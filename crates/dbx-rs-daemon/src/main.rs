#![forbid(unsafe_code)]

mod error;
mod hec;
mod identity;
mod lifecycle;
mod operational;
mod prepared;
mod rising;
mod rising_metadata;
mod runtime;
mod splunk;
mod worker;

use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use dbx_rs_config::load_effective_config;
use dbx_rs_secure_store::SecretStore;

use crate::error::DaemonError;

const HELP: &str = "dbx-rs-daemon - Splunk-supervised database collection\n\
\n\
Usage:\n\
  dbx-rs-daemon run [--splunk-home PATH] [--app-home PATH]\n\
  dbx-rs-daemon bootstrap [--splunk-home PATH] [--app-home PATH]\n\
  dbx-rs-daemon secret set NAME --stdin [--splunk-home PATH] [--app-home PATH]\n\
  dbx-rs-daemon --version\n\
\n\
Commands:\n\
  run        Run one singleton daemon under splunkd supervision\n\
  bootstrap  Generate local identity and reconcile managed HEC configuration\n\
  secret     Store a database credential encrypted for this installation\n";

const MAX_STDIN_SECRET_BYTES: u64 = 16 * 1024;
const STARTUP_RETRY_BACKOFF: Duration = Duration::from_secs(5);

#[derive(Debug, Eq, PartialEq)]
enum Action {
    Run,
    Bootstrap,
    SetSecret { name: String },
    Help,
    Version,
}

#[derive(Debug, Eq, PartialEq)]
struct Command {
    action: Action,
    app_home: Option<PathBuf>,
    splunk_home: Option<PathBuf>,
}

#[derive(Clone)]
struct Locations {
    app_home: PathBuf,
    splunk_home: PathBuf,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    let command = match parse(std::env::args_os().skip(1)) {
        Ok(command) => command,
        Err(message) => {
            eprintln!("error: {message}\n\n{HELP}");
            return ExitCode::from(2);
        }
    };
    let is_run = command.action == Action::Run;
    match execute(command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            if is_run {
                tokio::time::sleep(STARTUP_RETRY_BACKOFF).await;
            }
            ExitCode::FAILURE
        }
    }
}

async fn execute(command: Command) -> Result<(), DaemonError> {
    match command.action {
        Action::Help => {
            print!("{HELP}");
            Ok(())
        }
        Action::Version => {
            println!("dbx-rs-daemon {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        action => {
            let locations = resolve_locations(command.app_home, command.splunk_home)?;
            let config = load_effective_config(&locations.app_home, &locations.splunk_home)
                .map_err(|error| DaemonError::from_config(&error))?;
            match action {
                Action::Run => {
                    runtime::run(&locations.app_home, &locations.splunk_home, config).await
                }
                Action::Bootstrap => {
                    let result = runtime::bootstrap(&config, &locations.splunk_home)?;
                    println!("splunk_inputs_changed={}", result.splunk_inputs_changed);
                    println!("certificate_created={}", result.certificate_created);
                    println!(
                        "splunk_restart_required={}",
                        result.splunk_inputs_changed || result.certificate_created
                    );
                    Ok(())
                }
                Action::SetSecret { name } => {
                    let store = SecretStore::open(
                        &config.generic.paths.master_key_file,
                        &config.generic.paths.secret_dir,
                    )?;
                    store.set(&name, read_secret_stdin()?)?;
                    println!("secret_stored={name}");
                    Ok(())
                }
                Action::Help | Action::Version => unreachable!("handled above"),
            }
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
    let Some(action) = args.first().map(String::as_str) else {
        return Ok(Command {
            action: Action::Help,
            app_home: None,
            splunk_home: None,
        });
    };
    if matches!(action, "help" | "-h" | "--help") {
        return parse_no_options(&args, Action::Help);
    }
    if matches!(action, "-V" | "--version") {
        return parse_no_options(&args, Action::Version);
    }

    let (action, option_start) = match action {
        "run" => (Action::Run, 1),
        "bootstrap" => (Action::Bootstrap, 1),
        "secret" => {
            if args.get(1).map(String::as_str) != Some("set") {
                return Err("secret command requires 'set'".into());
            }
            let name = args
                .get(2)
                .filter(|name| !name.starts_with('-'))
                .ok_or_else(|| "secret set requires NAME".to_owned())?
                .clone();
            if args.get(3).map(String::as_str) != Some("--stdin") {
                return Err("secret set requires --stdin".into());
            }
            (Action::SetSecret { name }, 4)
        }
        _ => return Err(format!("unknown command '{action}'")),
    };
    let (app_home, splunk_home) = parse_locations(&args[option_start..])?;
    Ok(Command {
        action,
        app_home,
        splunk_home,
    })
}

fn parse_no_options(args: &[String], action: Action) -> Result<Command, String> {
    if args.len() != 1 {
        return Err("help and version do not accept arguments".into());
    }
    Ok(Command {
        action,
        app_home: None,
        splunk_home: None,
    })
}

fn parse_locations(args: &[String]) -> Result<(Option<PathBuf>, Option<PathBuf>), String> {
    let mut app_home = None;
    let mut splunk_home = None;
    let mut index = 0;
    while index < args.len() {
        let (slot, label) = match args[index].as_str() {
            "--app-home" => (&mut app_home, "--app-home"),
            "--splunk-home" => (&mut splunk_home, "--splunk-home"),
            argument => return Err(format!("unknown argument '{argument}'")),
        };
        if slot.is_some() {
            return Err(format!("{label} cannot be repeated"));
        }
        let value = args
            .get(index + 1)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("{label} requires a path"))?;
        *slot = Some(PathBuf::from(value));
        index += 2;
    }
    Ok((app_home, splunk_home))
}

fn resolve_locations(
    app_home: Option<PathBuf>,
    splunk_home: Option<PathBuf>,
) -> Result<Locations, DaemonError> {
    let app_home = match app_home {
        Some(path) => path,
        None => infer_app_home()?,
    };
    let splunk_home = splunk_home
        .or_else(|| std::env::var_os("SPLUNK_HOME").map(PathBuf::from))
        .or_else(|| app_home.ancestors().nth(3).map(Path::to_path_buf))
        .ok_or_else(|| {
            DaemonError::new(
                "DBX-RS-CLI-0001",
                "configuration",
                "location_resolution",
                "SPLUNK_HOME could not be resolved",
                false,
                true,
            )
        })?;
    if !app_home.is_absolute() || !splunk_home.is_absolute() {
        return Err(DaemonError::new(
            "DBX-RS-CLI-0002",
            "configuration",
            "location_resolution",
            "app and Splunk home paths must be absolute",
            false,
            true,
        ));
    }
    Ok(Locations {
        app_home,
        splunk_home,
    })
}

fn infer_app_home() -> Result<PathBuf, DaemonError> {
    let executable = std::env::current_exe().map_err(|error| {
        DaemonError::io(
            "DBX-RS-CLI-0003",
            "location_resolution",
            "failed to resolve the daemon executable",
            &error,
        )
    })?;
    executable
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            DaemonError::new(
                "DBX-RS-CLI-0004",
                "configuration",
                "location_resolution",
                "app home could not be inferred from the daemon executable",
                false,
                true,
            )
        })
}

fn read_secret_stdin() -> Result<Vec<u8>, DaemonError> {
    let mut secret = Vec::new();
    std::io::stdin()
        .take(MAX_STDIN_SECRET_BYTES + 1)
        .read_to_end(&mut secret)
        .map_err(|error| {
            DaemonError::io(
                "DBX-RS-CLI-0005",
                "secret_input",
                "failed to read a secret from standard input",
                &error,
            )
        })?;
    if secret.len() as u64 > MAX_STDIN_SECRET_BYTES {
        secret.fill(0);
        return Err(DaemonError::new(
            "DBX-RS-CLI-0006",
            "configuration",
            "secret_input",
            "secret from standard input exceeds the size limit",
            false,
            true,
        ));
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_locations_are_explicitly_parsed() {
        let command = parse(
            [
                "run",
                "--splunk-home",
                "/opt/splunk",
                "--app-home",
                "/opt/splunk/etc/apps/TA-dbx-rs",
            ]
            .map(OsString::from),
        )
        .expect("command must parse");

        assert_eq!(command.action, Action::Run);
        assert_eq!(command.splunk_home, Some(PathBuf::from("/opt/splunk")));
    }

    #[test]
    fn secret_requires_stdin_marker() {
        let error = parse(["secret", "set", "warehouse"].map(OsString::from))
            .expect_err("missing stdin marker must fail");

        assert!(error.contains("--stdin"));
    }

    #[test]
    fn unknown_option_fails_closed() {
        let error = parse(["run", "--token", "secret"].map(OsString::from))
            .expect_err("unknown option must fail");

        assert!(error.contains("unknown argument"));
    }
}
