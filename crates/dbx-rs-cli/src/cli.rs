use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::future::Future;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use dbx_rs_config::{MAX_QUERY_BYTES, load_effective_config};
use dbx_rs_control::{
    AdHocQuery, ControlError, ControlService, QueryTestLimitOverrides, QueryTestRequest,
};
use dbx_rs_secure_store::{
    AuthoritySigner, DeploymentIdentity, DeploymentImportPolicy, DeploymentImportResult,
    SecretStore, embedded_deployment_authority, read_limited, seal_deployment_secret,
};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

const MAX_DEPLOYMENT_SECRET_BYTES: u64 = 16 * 1024;
const MAX_DEPLOYMENT_ENVELOPE_BYTES: u64 = 128 * 1024;

const HELP: &str = "dbx-rs - dbx-rs administration and diagnostics\n\
\n\
Usage:\n\
  dbx-rs config validate [--splunk-home PATH] [--app-home PATH]\n\
  dbx-rs input validate NAME [--splunk-home PATH] [--app-home PATH]\n\
  dbx-rs input probe NAME [--splunk-home PATH] [--app-home PATH]\n\
  dbx-rs query test NAME --query-stdin [LIMITS] [LOCATIONS]\n\
  dbx-rs query test NAME --query-file PATH [LIMITS] [LOCATIONS]\n\
  dbx-rs deployment authority show\n\
  dbx-rs deployment recipient init [LOCATIONS]\n\
  dbx-rs deployment recipient show [LOCATIONS]\n\
  dbx-rs deployment secret seal NAME --stdin --revision N --recipient ID ...\n\
      --authority-key PATH --output PATH\n\
  dbx-rs deployment secret import PATH [--replace-existing] [LOCATIONS]\n\
  dbx-rs help\n\
  dbx-rs --version\n\
\n\
Commands:\n\
  config validate  Validate the effective generic and database input configuration\n\
  input validate   Validate one input, its query assets, TLS assets, and credential reference\n\
  input probe      Open and verify one configured database connection\n\
  query test       Run one bounded read-only query and return its rows to the caller\n\
  deployment       Enroll clients and manage signed encrypted deployment credentials\n\
  help             Print this help text\n\
\n\
Query options:\n\
  --query-stdin       Read SQL from standard input; SQL is never accepted in arguments\n\
  --query-file PATH   Read SQL from the input connector's app query directory\n\
  --max-rows N        Lower the configured and hard query-test row limit\n\
  --max-bytes N       Lower the configured and hard query-test byte limit\n\
  --timeout-secs N    Lower the configured and hard query-test timeout\n\
\n\
Location options:\n\
  --splunk-home PATH  Override SPLUNK_HOME\n\
  --app-home PATH     Override the TA-dbx-rs app directory\n\
  -h, --help          Print this help text\n\
  -V, --version       Print version information\n";

#[derive(Debug, Eq, PartialEq)]
enum Command {
    ValidateConfig(Locations),
    ValidateInput {
        name: String,
        locations: Locations,
    },
    ProbeInput {
        name: String,
        locations: Locations,
    },
    TestQuery {
        name: String,
        source: QueryArgument,
        limits: QueryTestLimitOverrides,
        locations: Locations,
    },
    ShowDeploymentAuthority,
    InitializeDeploymentRecipient(Locations),
    ShowDeploymentRecipient(Locations),
    SealDeploymentSecret {
        name: String,
        revision: u64,
        recipients: Vec<String>,
        authority_key: PathBuf,
        output: PathBuf,
    },
    ImportDeploymentSecret {
        envelope: PathBuf,
        replace_existing: bool,
        locations: Locations,
    },
    Help,
    Version,
}

#[derive(Debug, Eq, PartialEq)]
enum QueryArgument {
    Stdin,
    File(PathBuf),
}

#[derive(Debug, Default, Eq, PartialEq)]
struct Locations {
    app_home: Option<PathBuf>,
    splunk_home: Option<PathBuf>,
}

enum ExecutionError {
    Control(ControlError),
    Message(String),
}

impl From<ControlError> for ExecutionError {
    fn from(error: ControlError) -> Self {
        Self::Control(error)
    }
}

pub(crate) async fn run(
    args: impl IntoIterator<Item = OsString>,
    mut stdin: impl Read,
    mut stdout: impl Write,
    mut stderr: impl Write,
) -> u8 {
    let command = match parse(args) {
        Ok(command) => command,
        Err(message) => return write_usage_error(&mut stderr, &message),
    };
    match execute(command, &mut stdin, &mut stdout).await {
        Ok(code) => code,
        Err(ExecutionError::Control(error)) => {
            let _result = write_json(&mut stderr, &error);
            1
        }
        Err(ExecutionError::Message(message)) => {
            let output = format!("error: {message}\n");
            let _result = stderr.write_all(output.as_bytes());
            1
        }
    }
}

async fn execute(
    command: Command,
    stdin: &mut impl Read,
    stdout: &mut impl Write,
) -> Result<u8, ExecutionError> {
    match command {
        Command::Help => write_output(stdout, HELP.as_bytes()).map(|()| 0),
        Command::Version => write_output(
            stdout,
            format!("dbx-rs {}\n", env!("CARGO_PKG_VERSION")).as_bytes(),
        )
        .map(|()| 0),
        Command::ValidateConfig(locations) => {
            let (app_home, splunk_home) = resolve_locations(locations)?;
            let config = load_effective_config(&app_home, &splunk_home)
                .map_err(|error| ExecutionError::Message(error.to_string()))?;
            let enabled = config.inputs.iter().filter(|input| !input.disabled).count();
            let output = format!(
                "configuration_valid=true\ninputs_total={}\ninputs_enabled={enabled}\n",
                config.inputs.len()
            );
            write_output(stdout, output.as_bytes()).map(|()| 0)
        }
        Command::ValidateInput { name, locations } => {
            let service = load_service(locations)?;
            let response = service.validate_input(&name)?;
            let code = u8::from(!response.valid);
            write_json(stdout, &response)?;
            Ok(code)
        }
        Command::ProbeInput { name, locations } => {
            let service = load_service(locations)?;
            let cancellation = CancellationToken::new();
            let response = with_signal_cancellation(
                cancellation.clone(),
                service.probe_input(&name, cancellation),
            )
            .await?;
            write_json(stdout, &response)?;
            Ok(0)
        }
        Command::TestQuery {
            name,
            source,
            limits,
            locations,
        } => {
            let query = match source {
                QueryArgument::Stdin => read_inline_query(stdin)?,
                QueryArgument::File(path) => AdHocQuery::File { path },
            };
            let service = load_service(locations)?;
            let request = QueryTestRequest {
                input: name,
                query,
                limits,
            };
            let cancellation = CancellationToken::new();
            let response = with_signal_cancellation(
                cancellation.clone(),
                service.test_query(request, cancellation),
            )
            .await?;
            write_json(stdout, &response)?;
            Ok(0)
        }
        Command::ShowDeploymentAuthority => show_deployment_authority(stdout),
        Command::InitializeDeploymentRecipient(locations) => {
            initialize_deployment_recipient(locations, stdout)
        }
        Command::ShowDeploymentRecipient(locations) => show_deployment_recipient(locations, stdout),
        Command::SealDeploymentSecret {
            name,
            revision,
            recipients,
            authority_key,
            output,
        } => seal_deployment_secret_command(
            &name,
            revision,
            &recipients,
            &authority_key,
            &output,
            stdin,
            stdout,
        ),
        Command::ImportDeploymentSecret {
            envelope,
            replace_existing,
            locations,
        } => import_deployment_secret(&envelope, replace_existing, locations, stdout),
    }
}

fn show_deployment_authority(stdout: &mut impl Write) -> Result<u8, ExecutionError> {
    let authority = embedded_deployment_authority()
        .map_err(|error| ExecutionError::Message(error.to_string()))?;
    let output = format!(
        "deployment_authority_sha256={}\n",
        authority.fingerprint_hex()
    );
    write_output(stdout, output.as_bytes()).map(|()| 0)
}

fn initialize_deployment_recipient(
    locations: Locations,
    stdout: &mut impl Write,
) -> Result<u8, ExecutionError> {
    let config = load_config(locations)?;
    let identity =
        DeploymentIdentity::load_or_create(&config.generic.paths.deployment_identity_file)
            .map_err(|error| ExecutionError::Message(error.to_string()))?;
    write_deployment_recipient(&identity, stdout)
}

fn show_deployment_recipient(
    locations: Locations,
    stdout: &mut impl Write,
) -> Result<u8, ExecutionError> {
    let config = load_config(locations)?;
    let identity = DeploymentIdentity::load(&config.generic.paths.deployment_identity_file)
        .map_err(|error| ExecutionError::Message(error.to_string()))?;
    write_deployment_recipient(&identity, stdout)
}

fn write_deployment_recipient(
    identity: &DeploymentIdentity,
    stdout: &mut impl Write,
) -> Result<u8, ExecutionError> {
    let output = format!("deployment_recipient={}\n", identity.recipient());
    write_output(stdout, output.as_bytes()).map(|()| 0)
}

fn seal_deployment_secret_command(
    name: &str,
    revision: u64,
    recipients: &[String],
    authority_key: &Path,
    output_path: &Path,
    stdin: &mut impl Read,
    stdout: &mut impl Write,
) -> Result<u8, ExecutionError> {
    let authority = embedded_deployment_authority()
        .map_err(|error| ExecutionError::Message(error.to_string()))?;
    let signer = AuthoritySigner::load(authority_key, &authority)
        .map_err(|error| ExecutionError::Message(error.to_string()))?;
    let secret = read_bounded_secret(stdin)?;
    let mut envelope = seal_deployment_secret(name, revision, secret, recipients, &signer)
        .map_err(|error| ExecutionError::Message(error.to_string()))?;
    let write_result = write_new_envelope(output_path, &envelope);
    envelope.fill(0);
    write_result?;
    let output = format!("deployment_secret_sealed={name}\nrevision={revision}\n");
    write_output(stdout, output.as_bytes()).map(|()| 0)
}

fn load_config(locations: Locations) -> Result<dbx_rs_config::EffectiveConfig, ExecutionError> {
    let (app_home, splunk_home) = resolve_locations(locations)?;
    load_effective_config(&app_home, &splunk_home)
        .map_err(|error| ExecutionError::Message(error.to_string()))
}

fn import_deployment_secret(
    envelope_path: &Path,
    replace_existing: bool,
    locations: Locations,
    stdout: &mut impl Write,
) -> Result<u8, ExecutionError> {
    let config = load_config(locations)?;
    let envelope = read_limited(envelope_path, MAX_DEPLOYMENT_ENVELOPE_BYTES)
        .map_err(|error| ExecutionError::Message(error.to_string()))?;
    let identity = DeploymentIdentity::load(&config.generic.paths.deployment_identity_file)
        .map_err(|error| ExecutionError::Message(error.to_string()))?;
    let authority = embedded_deployment_authority()
        .map_err(|error| ExecutionError::Message(error.to_string()))?;
    let store = SecretStore::open(
        &config.generic.paths.master_key_file,
        &config.generic.paths.secret_dir,
    )
    .map_err(|error| ExecutionError::Message(error.to_string()))?;
    let policy = if replace_existing {
        DeploymentImportPolicy::ReplaceExisting
    } else {
        DeploymentImportPolicy::RequireAbsentOrMatching
    };
    let result = store
        .import_deployment_envelope(
            &envelope,
            &identity,
            &config.generic.paths.deployment_receipt_dir,
            &authority,
            policy,
        )
        .map_err(|error| ExecutionError::Message(error.to_string()))?;
    let output = match result {
        DeploymentImportResult::Imported { name, revision } => {
            format!("deployment_secret_imported={name}\nrevision={revision}\n")
        }
        DeploymentImportResult::AlreadyCurrent { name, revision } => {
            format!("deployment_secret_current={name}\nrevision={revision}\n")
        }
        DeploymentImportResult::Repaired { name, revision } => {
            format!("deployment_secret_repaired={name}\nrevision={revision}\n")
        }
        DeploymentImportResult::Stale {
            name,
            envelope_revision,
            current_revision,
        } => format!(
            "deployment_secret_stale={name}\nenvelope_revision={envelope_revision}\ncurrent_revision={current_revision}\n"
        ),
    };
    write_output(stdout, output.as_bytes()).map(|()| 0)
}

fn read_bounded_secret(stdin: &mut impl Read) -> Result<Vec<u8>, ExecutionError> {
    let mut secret = Vec::new();
    if stdin
        .take(MAX_DEPLOYMENT_SECRET_BYTES + 1)
        .read_to_end(&mut secret)
        .is_err()
    {
        secret.fill(0);
        return Err(ExecutionError::Message(
            "failed to read deployment secret from standard input".into(),
        ));
    }
    if secret.len() as u64 > MAX_DEPLOYMENT_SECRET_BYTES {
        secret.fill(0);
        return Err(ExecutionError::Message(
            "deployment secret from standard input exceeds the size limit".into(),
        ));
    }
    Ok(secret)
}

fn write_new_envelope(path: &Path, bytes: &[u8]) -> Result<(), ExecutionError> {
    if path.extension().and_then(|value| value.to_str()) != Some("dbxsecret") {
        return Err(ExecutionError::Message(
            "deployment envelope output must end in .dbxsecret".into(),
        ));
    }
    reject_output_symlinks(path)?;
    let parent = path.parent().ok_or_else(|| {
        ExecutionError::Message("deployment envelope output has no parent directory".into())
    })?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| {
        ExecutionError::Message("deployment envelope output directory is unavailable".into())
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ExecutionError::Message(
            "deployment envelope output directory is invalid".into(),
        ));
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    set_envelope_create_mode(&mut options);
    let mut file = options.open(path).map_err(|_| {
        ExecutionError::Message("failed to create deployment envelope output".into())
    })?;
    if file.write_all(bytes).is_err() || file.sync_all().is_err() {
        drop(file);
        let _ignored = fs::remove_file(path);
        return Err(ExecutionError::Message(
            "failed to persist deployment envelope output".into(),
        ));
    }
    Ok(())
}

fn reject_output_symlinks(path: &Path) -> Result<(), ExecutionError> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(ExecutionError::Message(
                    "deployment envelope output path contains a symbolic link".into(),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(ExecutionError::Message(
                    "failed to inspect deployment envelope output path".into(),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_envelope_create_mode(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.mode(0o644);
}

#[cfg(not(unix))]
fn set_envelope_create_mode(_options: &mut OpenOptions) {}

fn load_service(locations: Locations) -> Result<ControlService, ExecutionError> {
    let (app_home, splunk_home) = resolve_locations(locations)?;
    ControlService::load(&app_home, &splunk_home).map_err(Into::into)
}

async fn with_signal_cancellation<T>(
    cancellation: CancellationToken,
    operation: impl Future<Output = T>,
) -> T {
    let signal_cancellation = cancellation.clone();
    let signal_task = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal_cancellation.cancel();
        }
    });
    let result = operation.await;
    signal_task.abort();
    result
}

fn read_inline_query(stdin: &mut impl Read) -> Result<AdHocQuery, ExecutionError> {
    let mut bytes = Vec::new();
    stdin
        .take(MAX_QUERY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ExecutionError::Message("failed to read query from standard input".into()))?;
    if bytes.len() as u64 > MAX_QUERY_BYTES {
        bytes.fill(0);
        return Err(ExecutionError::Message(
            "query from standard input exceeds the size limit".into(),
        ));
    }
    match String::from_utf8(bytes) {
        Ok(sql) => Ok(AdHocQuery::Inline { sql }),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.fill(0);
            Err(ExecutionError::Message(
                "query from standard input must be valid UTF-8".into(),
            ))
        }
    }
}

fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command, String> {
    let args = args
        .into_iter()
        .map(|argument| {
            argument
                .into_string()
                .map_err(|_| "arguments must be valid UTF-8".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let Some(command) = args.first().map(String::as_str) else {
        return Ok(Command::Help);
    };
    match command {
        "help" | "-h" | "--help" => parse_no_arguments(&args, Command::Help),
        "-V" | "--version" => parse_no_arguments(&args, Command::Version),
        "config" => {
            require_subcommand(&args, "validate", "config")?;
            Ok(Command::ValidateConfig(parse_locations(&args[2..])?))
        }
        "input" => parse_input_command(&args),
        "query" => parse_query_command(&args),
        "deployment" => parse_deployment_command(&args),
        _ => Err(format!("unknown command '{command}'")),
    }
}

fn parse_deployment_command(args: &[String]) -> Result<Command, String> {
    match (args.get(1).map(String::as_str), args.get(2).map(String::as_str)) {
        (Some("authority"), Some("show")) => {
            if args.len() != 3 {
                return Err("deployment authority show does not accept arguments".into());
            }
            Ok(Command::ShowDeploymentAuthority)
        }
        (Some("recipient"), Some("init")) => Ok(Command::InitializeDeploymentRecipient(
            parse_locations(&args[3..])?,
        )),
        (Some("recipient"), Some("show")) => Ok(Command::ShowDeploymentRecipient(
            parse_locations(&args[3..])?,
        )),
        (Some("secret"), Some("seal")) => parse_deployment_seal(args),
        (Some("secret"), Some("import")) => parse_deployment_import(args),
        _ => Err(
            "deployment command requires authority show, recipient init/show, or secret seal/import"
                .into(),
        ),
    }
}

fn parse_deployment_seal(args: &[String]) -> Result<Command, String> {
    let name = required_name(args.get(3), "deployment secret seal")?;
    let mut revision = None;
    let mut recipients = Vec::new();
    let mut authority_key = None;
    let mut output = None;
    let mut stdin = false;
    let mut index = 4;
    while index < args.len() {
        match args[index].as_str() {
            "--stdin" => {
                if stdin {
                    return Err("--stdin cannot be repeated".into());
                }
                stdin = true;
                index += 1;
            }
            "--revision" => {
                set_number_option(&mut revision, args, index, "--revision")?;
                index += 2;
            }
            "--recipient" => {
                recipients.push(required_option_value(args, index, "--recipient")?.to_owned());
                index += 2;
            }
            "--authority-key" => {
                set_path_option(&mut authority_key, args, index, "--authority-key")?;
                index += 2;
            }
            "--output" => {
                set_path_option(&mut output, args, index, "--output")?;
                index += 2;
            }
            argument => return Err(format!("unknown argument '{argument}'")),
        }
    }
    if !stdin {
        return Err("deployment secret seal requires --stdin".into());
    }
    if recipients.is_empty() {
        return Err("deployment secret seal requires at least one --recipient".into());
    }
    Ok(Command::SealDeploymentSecret {
        name,
        revision: revision.ok_or_else(|| "--revision is required".to_owned())?,
        recipients,
        authority_key: authority_key.ok_or_else(|| "--authority-key is required".to_owned())?,
        output: output.ok_or_else(|| "--output is required".to_owned())?,
    })
}

fn parse_deployment_import(args: &[String]) -> Result<Command, String> {
    let envelope = args
        .get(3)
        .filter(|path| !path.is_empty() && !path.starts_with('-'))
        .map(PathBuf::from)
        .ok_or_else(|| "deployment secret import requires PATH".to_owned())?;
    let mut replace_existing = false;
    let mut locations = Locations::default();
    let mut index = 4;
    while index < args.len() {
        match args[index].as_str() {
            "--replace-existing" => {
                if replace_existing {
                    return Err("--replace-existing cannot be repeated".into());
                }
                replace_existing = true;
                index += 1;
            }
            "--app-home" => {
                set_path_option(&mut locations.app_home, args, index, "--app-home")?;
                index += 2;
            }
            "--splunk-home" => {
                set_path_option(&mut locations.splunk_home, args, index, "--splunk-home")?;
                index += 2;
            }
            argument => return Err(format!("unknown argument '{argument}'")),
        }
    }
    Ok(Command::ImportDeploymentSecret {
        envelope,
        replace_existing,
        locations,
    })
}

fn parse_input_command(args: &[String]) -> Result<Command, String> {
    let action = args
        .get(1)
        .ok_or_else(|| "input command requires 'validate' or 'probe'".to_owned())?;
    if !matches!(action.as_str(), "validate" | "probe") {
        return Err("input command requires 'validate' or 'probe'".into());
    }
    let name = required_name(args.get(2), "input")?;
    let locations = parse_locations(&args[3..])?;
    if action == "validate" {
        Ok(Command::ValidateInput { name, locations })
    } else {
        Ok(Command::ProbeInput { name, locations })
    }
}

fn parse_query_command(args: &[String]) -> Result<Command, String> {
    require_subcommand(args, "test", "query")?;
    let name = required_name(args.get(2), "query test")?;
    let mut source = None;
    let mut limits = QueryTestLimitOverrides::default();
    let mut locations = Locations::default();
    let mut index = 3;
    while index < args.len() {
        match args[index].as_str() {
            "--query-stdin" => {
                set_once(&mut source, QueryArgument::Stdin, "query source")?;
                index += 1;
            }
            "--query-file" => {
                let value = required_option_value(args, index, "--query-file")?;
                set_once(
                    &mut source,
                    QueryArgument::File(PathBuf::from(value)),
                    "query source",
                )?;
                index += 2;
            }
            "--max-rows" => {
                set_number_option(&mut limits.max_rows, args, index, "--max-rows")?;
                index += 2;
            }
            "--max-bytes" => {
                set_number_option(&mut limits.max_bytes, args, index, "--max-bytes")?;
                index += 2;
            }
            "--timeout-secs" => {
                set_number_option(&mut limits.timeout_secs, args, index, "--timeout-secs")?;
                index += 2;
            }
            "--app-home" => {
                set_path_option(&mut locations.app_home, args, index, "--app-home")?;
                index += 2;
            }
            "--splunk-home" => {
                set_path_option(&mut locations.splunk_home, args, index, "--splunk-home")?;
                index += 2;
            }
            argument => return Err(format!("unknown argument '{argument}'")),
        }
    }
    let source = source.ok_or_else(|| {
        "query test requires exactly one of --query-stdin or --query-file".to_owned()
    })?;
    Ok(Command::TestQuery {
        name,
        source,
        limits,
        locations,
    })
}

fn require_subcommand(args: &[String], expected: &str, command: &str) -> Result<(), String> {
    if args.get(1).map(String::as_str) != Some(expected) {
        return Err(format!("{command} command requires '{expected}'"));
    }
    Ok(())
}

fn required_name(value: Option<&String>, command: &str) -> Result<String, String> {
    value
        .filter(|name| !name.is_empty() && !name.starts_with('-'))
        .cloned()
        .ok_or_else(|| format!("{command} requires an input NAME"))
}

fn set_once<T>(slot: &mut Option<T>, value: T, label: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("{label} cannot be repeated"));
    }
    Ok(())
}

fn required_option_value<'a>(
    args: &'a [String],
    index: usize,
    label: &str,
) -> Result<&'a str, String> {
    args.get(index + 1)
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .ok_or_else(|| format!("{label} requires a value"))
}

fn set_number_option(
    slot: &mut Option<u64>,
    args: &[String],
    index: usize,
    label: &str,
) -> Result<(), String> {
    let value = required_option_value(args, index, label)?
        .parse::<u64>()
        .map_err(|_| format!("{label} requires an unsigned integer"))?;
    set_once(slot, value, label)
}

fn set_path_option(
    slot: &mut Option<PathBuf>,
    args: &[String],
    index: usize,
    label: &str,
) -> Result<(), String> {
    let value = PathBuf::from(required_option_value(args, index, label)?);
    set_once(slot, value, label)
}

fn parse_no_arguments(args: &[String], command: Command) -> Result<Command, String> {
    if args.len() != 1 {
        return Err("help and version do not accept arguments".into());
    }
    Ok(command)
}

fn parse_locations(args: &[String]) -> Result<Locations, String> {
    let mut locations = Locations::default();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--app-home" => {
                set_path_option(&mut locations.app_home, args, index, "--app-home")?;
            }
            "--splunk-home" => {
                set_path_option(&mut locations.splunk_home, args, index, "--splunk-home")?;
            }
            argument => return Err(format!("unknown argument '{argument}'")),
        }
        index += 2;
    }
    Ok(locations)
}

fn resolve_locations(locations: Locations) -> Result<(PathBuf, PathBuf), ExecutionError> {
    let app_home = locations
        .app_home
        .map_or_else(infer_app_home, Ok)
        .map_err(ExecutionError::Message)?;
    let splunk_home = locations
        .splunk_home
        .or_else(|| {
            std::env::var_os("SPLUNK_HOME")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        })
        .or_else(|| app_home.ancestors().nth(3).map(Path::to_path_buf))
        .ok_or_else(|| ExecutionError::Message("SPLUNK_HOME could not be resolved".into()))?;
    if !app_home.is_absolute()
        || !splunk_home.is_absolute()
        || has_parent_component(&app_home)
        || has_parent_component(&splunk_home)
    {
        return Err(ExecutionError::Message(
            "app and Splunk home paths must be absolute without parent traversal".into(),
        ));
    }
    Ok((app_home, splunk_home))
}

fn infer_app_home() -> Result<PathBuf, String> {
    let executable = std::env::current_exe()
        .map_err(|_| "failed to resolve the dbx-rs executable".to_owned())?;
    executable
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "app home could not be inferred from the dbx-rs executable".to_owned())
}

fn has_parent_component(path: &Path) -> bool {
    path.components()
        .any(|component| component == std::path::Component::ParentDir)
}

fn write_usage_error(stderr: &mut impl Write, message: &str) -> u8 {
    let output = format!("error: {message}\n\nFor more information, try 'dbx-rs help'.\n");
    if stderr.write_all(output.as_bytes()).is_ok() {
        2
    } else {
        1
    }
}

fn write_json(writer: &mut impl Write, value: &impl Serialize) -> Result<(), ExecutionError> {
    serde_json::to_writer(&mut *writer, value)
        .map_err(|_| ExecutionError::Message("failed to write JSON command output".into()))?;
    writer
        .write_all(b"\n")
        .map_err(|_| ExecutionError::Message("failed to write command output".into()))
}

fn write_output(writer: &mut impl Write, output: &[u8]) -> Result<(), ExecutionError> {
    writer
        .write_all(output)
        .map_err(|_| ExecutionError::Message("failed to write command output".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn invoke(arguments: &[&str], stdin: &[u8]) -> (u8, String, String) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(
            arguments.iter().map(OsString::from),
            stdin,
            &mut stdout,
            &mut stderr,
        )
        .await;
        (
            code,
            String::from_utf8(stdout).expect("stdout must be UTF-8"),
            String::from_utf8(stderr).expect("stderr must be UTF-8"),
        )
    }

    #[tokio::test]
    async fn help_lists_control_operations() {
        let (code, stdout, stderr) = invoke(&["help"], b"").await;

        assert_eq!(code, 0);
        assert!(stdout.contains("input validate"));
        assert!(stdout.contains("input probe"));
        assert!(stdout.contains("query test"));
        assert!(stdout.contains("deployment secret seal"));
        assert!(stderr.is_empty());
    }

    #[tokio::test]
    async fn version_flag_prints_package_version() {
        let (code, stdout, stderr) = invoke(&["--version"], b"").await;

        assert_eq!(code, 0);
        assert_eq!(stdout, format!("dbx-rs {}\n", env!("CARGO_PKG_VERSION")));
        assert!(stderr.is_empty());
    }

    #[test]
    fn config_validate_locations_are_typed() {
        let command = parse(
            [
                "config",
                "validate",
                "--splunk-home",
                "/opt/splunk",
                "--app-home",
                "/opt/splunk/etc/apps/TA-dbx-rs",
            ]
            .map(OsString::from),
        )
        .expect("command must parse");

        assert_eq!(
            command,
            Command::ValidateConfig(Locations {
                app_home: Some(PathBuf::from("/opt/splunk/etc/apps/TA-dbx-rs")),
                splunk_home: Some(PathBuf::from("/opt/splunk")),
            })
        );
    }

    #[test]
    fn query_test_accepts_only_source_markers_in_arguments() {
        let command = parse(
            [
                "query",
                "test",
                "warehouse",
                "--query-stdin",
                "--max-rows",
                "5",
            ]
            .map(OsString::from),
        )
        .expect("command must parse");

        assert_eq!(
            command,
            Command::TestQuery {
                name: "warehouse".into(),
                source: QueryArgument::Stdin,
                limits: QueryTestLimitOverrides {
                    max_rows: Some(5),
                    ..QueryTestLimitOverrides::default()
                },
                locations: Locations::default(),
            }
        );

        let error =
            parse(["query", "test", "warehouse", "--query", "SELECT 1"].map(OsString::from))
                .expect_err("SQL arguments must be rejected");
        assert!(error.contains("unknown argument '--query'"));
    }

    #[tokio::test]
    async fn query_test_requires_exactly_one_source() {
        let (missing_code, _, missing_error) = invoke(&["query", "test", "warehouse"], b"").await;
        let (duplicate_code, _, duplicate_error) = invoke(
            &[
                "query",
                "test",
                "warehouse",
                "--query-stdin",
                "--query-file",
                "/tmp/query.sql",
            ],
            b"SELECT 1",
        )
        .await;

        assert_eq!(missing_code, 2);
        assert!(missing_error.contains("exactly one"));
        assert_eq!(duplicate_code, 2);
        assert!(duplicate_error.contains("cannot be repeated"));
    }

    #[tokio::test]
    async fn unknown_input_subcommand_is_a_usage_error() {
        let (code, stdout, stderr) = invoke(&["input", "rewrite", "warehouse"], b"").await;

        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("requires 'validate' or 'probe'"));
    }

    #[test]
    fn deployment_seal_requires_stdin_and_accepts_repeated_recipients() {
        let command = parse(
            [
                "deployment",
                "secret",
                "seal",
                "warehouse",
                "--stdin",
                "--revision",
                "7",
                "--recipient",
                "first",
                "--recipient",
                "second",
                "--authority-key",
                "/secure/authority.pk8",
                "--output",
                "/deployment/warehouse.dbxsecret",
            ]
            .map(OsString::from),
        )
        .expect("deployment seal must parse");

        assert_eq!(
            command,
            Command::SealDeploymentSecret {
                name: "warehouse".into(),
                revision: 7,
                recipients: vec!["first".into(), "second".into()],
                authority_key: PathBuf::from("/secure/authority.pk8"),
                output: PathBuf::from("/deployment/warehouse.dbxsecret"),
            }
        );

        let error = parse(
            [
                "deployment",
                "secret",
                "seal",
                "warehouse",
                "--password",
                "exposed",
            ]
            .map(OsString::from),
        )
        .expect_err("secret arguments must be rejected");
        assert!(error.contains("unknown argument '--password'"));
    }
}
