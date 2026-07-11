use std::ffi::OsString;
use std::io::Write;

const HELP: &str = "dbx-rs - Splunk-native database collection without a JVM\n\
\n\
Usage:\n\
  dbx-rs help\n\
  dbx-rs --version\n\
\n\
Commands:\n\
  help       Print this help text\n\
\n\
Options:\n\
  -h, --help       Print this help text\n\
  -V, --version    Print version information\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Command {
    Help,
    Version,
}

#[derive(Debug, Eq, PartialEq)]
enum ParseError {
    UnexpectedArgument(String),
    UnknownArgument(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedArgument(argument) => {
                write!(formatter, "unexpected argument '{argument}'")
            }
            Self::UnknownArgument(argument) => write!(formatter, "unknown argument '{argument}'"),
        }
    }
}

fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command, ParseError> {
    let mut args = args.into_iter();
    let Some(argument) = args.next() else {
        return Ok(Command::Help);
    };

    let command = match argument.to_str() {
        Some("help" | "-h" | "--help") => Command::Help,
        Some("-V" | "--version") => Command::Version,
        _ => {
            return Err(ParseError::UnknownArgument(
                argument.to_string_lossy().into_owned(),
            ));
        }
    };

    if let Some(argument) = args.next() {
        return Err(ParseError::UnexpectedArgument(
            argument.to_string_lossy().into_owned(),
        ));
    }

    Ok(command)
}

pub(crate) fn run(
    args: impl IntoIterator<Item = OsString>,
    mut stdout: impl Write,
    mut stderr: impl Write,
) -> u8 {
    match parse(args) {
        Ok(Command::Help) => write_output(&mut stdout, HELP.as_bytes()),
        Ok(Command::Version) => {
            let version = format!("dbx-rs {}\n", env!("CARGO_PKG_VERSION"));
            write_output(&mut stdout, version.as_bytes())
        }
        Err(error) => {
            let message = format!("error: {error}\n\nFor more information, try 'dbx-rs help'.\n");
            if stderr.write_all(message.as_bytes()).is_ok() {
                2
            } else {
                1
            }
        }
    }
}

fn write_output(writer: &mut impl Write, output: &[u8]) -> u8 {
    u8::from(writer.write_all(output).is_err())
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
    fn help_command_prints_usage() {
        let (code, stdout, stderr) = invoke(&["help"]);

        assert_eq!(code, 0);
        assert!(stdout.contains("Usage:"));
        assert!(stdout.contains("dbx-rs --version"));
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
    fn no_arguments_prints_help() {
        let (code, stdout, stderr) = invoke(&[]);

        assert_eq!(code, 0);
        assert_eq!(stdout, HELP);
        assert!(stderr.is_empty());
    }

    #[test]
    fn unknown_argument_is_a_usage_error() {
        let (code, stdout, stderr) = invoke(&["--scheme"]);

        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("unknown argument '--scheme'"));
        assert!(stderr.contains("dbx-rs help"));
    }
}
