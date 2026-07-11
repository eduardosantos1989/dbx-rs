use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

use dbx_rs_config::load_effective_config;

const HELP: &str = "dbx-rs - dbx-rs administration and diagnostics\n\
\n\
Usage:\n\
  dbx-rs config validate [--splunk-home PATH] [--app-home PATH]\n\
  dbx-rs help\n\
  dbx-rs --version\n\
\n\
Commands:\n\
  config validate  Validate the effective generic and database input configuration\n\
  help             Print this help text\n\
\n\
Options:\n\
  --splunk-home PATH  Override SPLUNK_HOME\n\
  --app-home PATH     Override the TA-dbx-rs app directory\n\
  -h, --help          Print this help text\n\
  -V, --version       Print version information\n";

#[derive(Debug, Eq, PartialEq)]
enum Command {
    ValidateConfig(Locations),
    Help,
    Version,
}

#[derive(Debug, Default, Eq, PartialEq)]
struct Locations {
    app_home: Option<PathBuf>,
    splunk_home: Option<PathBuf>,
}

pub(crate) fn run(
    args: impl IntoIterator<Item = OsString>,
    mut stdout: impl Write,
    mut stderr: impl Write,
) -> u8 {
    let command = match parse(args) {
        Ok(command) => command,
        Err(message) => return write_usage_error(&mut stderr, &message),
    };
    match execute(command, &mut stdout) {
        Ok(()) => 0,
        Err(message) => {
            let output = format!("error: {message}\n");
            let _result = stderr.write_all(output.as_bytes());
            1
        }
    }
}

fn execute(command: Command, stdout: &mut impl Write) -> Result<(), String> {
    match command {
        Command::Help => write_output(stdout, HELP.as_bytes()),
        Command::Version => write_output(
            stdout,
            format!("dbx-rs {}\n", env!("CARGO_PKG_VERSION")).as_bytes(),
        ),
        Command::ValidateConfig(locations) => {
            let (app_home, splunk_home) = resolve_locations(locations)?;
            let config = load_effective_config(&app_home, &splunk_home)
                .map_err(|error| error.to_string())?;
            let enabled = config.inputs.iter().filter(|input| !input.disabled).count();
            let output = format!(
                "configuration_valid=true\ninputs_total={}\ninputs_enabled={enabled}\n",
                config.inputs.len()
            );
            write_output(stdout, output.as_bytes())
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
            if args.get(1).map(String::as_str) != Some("validate") {
                return Err("config command requires 'validate'".into());
            }
            Ok(Command::ValidateConfig(parse_locations(&args[2..])?))
        }
        _ => Err(format!("unknown command '{command}'")),
    }
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
        let (slot, label) = match args[index].as_str() {
            "--app-home" => (&mut locations.app_home, "--app-home"),
            "--splunk-home" => (&mut locations.splunk_home, "--splunk-home"),
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
    Ok(locations)
}

fn resolve_locations(locations: Locations) -> Result<(PathBuf, PathBuf), String> {
    let app_home = locations.app_home.map_or_else(infer_app_home, Ok)?;
    let splunk_home = locations
        .splunk_home
        .or_else(|| {
            std::env::var_os("SPLUNK_HOME")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        })
        .or_else(|| app_home.ancestors().nth(3).map(Path::to_path_buf))
        .ok_or_else(|| "SPLUNK_HOME could not be resolved".to_owned())?;
    if !app_home.is_absolute()
        || !splunk_home.is_absolute()
        || has_parent_component(&app_home)
        || has_parent_component(&splunk_home)
    {
        return Err("app and Splunk home paths must be absolute without parent traversal".into());
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

fn write_output(writer: &mut impl Write, output: &[u8]) -> Result<(), String> {
    writer
        .write_all(output)
        .map_err(|_| "failed to write command output".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invoke(arguments: &[&str]) -> (u8, String, String) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(
            arguments.iter().map(OsString::from),
            &mut stdout,
            &mut stderr,
        );
        (
            code,
            String::from_utf8(stdout).expect("stdout must be UTF-8"),
            String::from_utf8(stderr).expect("stderr must be UTF-8"),
        )
    }

    #[test]
    fn help_lists_config_validation() {
        let (code, stdout, stderr) = invoke(&["help"]);

        assert_eq!(code, 0);
        assert!(stdout.contains("config validate"));
        assert!(stderr.is_empty());
    }

    #[test]
    fn version_flag_prints_package_version() {
        let (code, stdout, stderr) = invoke(&["--version"]);

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
    fn unknown_config_subcommand_is_a_usage_error() {
        let (code, stdout, stderr) = invoke(&["config", "rewrite"]);

        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("requires 'validate'"));
    }
}
