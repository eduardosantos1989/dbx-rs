use std::ffi::OsString;
use std::future::Future;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use dbx_rs_config::{MAX_QUERY_BYTES, load_effective_config};
use dbx_rs_control::{
    AdHocQuery, ControlError, ControlService, QueryTestLimitOverrides, QueryTestRequest,
};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

const HELP: &str = "dbx-rs - dbx-rs administration and diagnostics\n\
\n\
Usage:\n\
  dbx-rs config validate [--splunk-home PATH] [--app-home PATH]\n\
  dbx-rs input validate NAME [--splunk-home PATH] [--app-home PATH]\n\
  dbx-rs input probe NAME [--splunk-home PATH] [--app-home PATH]\n\
  dbx-rs query test NAME --query-stdin [LIMITS] [LOCATIONS]\n\
  dbx-rs query test NAME --query-file PATH [LIMITS] [LOCATIONS]\n\
  dbx-rs help\n\
  dbx-rs --version\n\
\n\
Commands:\n\
  config validate  Validate the effective generic and database input configuration\n\
  input validate   Validate one input, its query assets, TLS assets, and credential reference\n\
  input probe      Open and verify one configured database connection\n\
  query test       Run one bounded read-only query and return its rows to the caller\n\
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
    }
}

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
        _ => Err(format!("unknown command '{command}'")),
    }
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
}
