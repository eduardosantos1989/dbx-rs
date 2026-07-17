use std::ffi::OsString;
use std::path::PathBuf;

use crate::app::{self, BuildOptions, PlatformSelection};
use crate::authority;
use crate::{BuilderError, BuilderResult};

pub(crate) const HELP: &str = "dbx-rs-app-builder - build signed cross-platform Splunk apps\n\
\n\
Usage:\n\
  dbx-rs-app-builder authority init --output DIR [--common-name NAME]\n\
  dbx-rs-app-builder build --authority-dir DIR [OPTIONS]\n\
  dbx-rs-app-builder help\n\
  dbx-rs-app-builder --version\n\
\n\
Build options:\n\
  --output-dir DIR       Output directory (default: dist)\n\
  --template-dir DIR     Splunk app template (default: packaging/splunk/TA-dbx-rs)\n\
  --platform VALUE      all, linux, or windows (default: all)\n\
  --config-dir DIR      Shared app-local configuration copied into local/\n\
  --linux-overlay DIR   Linux-only app overlay\n\
  --windows-overlay DIR Windows-only app overlay\n\
  --target-dir DIR       Cargo target directory (default: target)\n\
  --no-archive           Build app directories without .spl archives\n\
\n\
The authority private key remains in DIR and is never copied into an app.\n";

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Command {
    InitializeAuthority {
        output: PathBuf,
        common_name: String,
    },
    Build(BuildOptions),
    Help,
    Version,
}

pub(crate) fn parse(args: impl IntoIterator<Item = OsString>) -> BuilderResult<Command> {
    let args = args
        .into_iter()
        .map(|argument| {
            argument
                .into_string()
                .map_err(|_| BuilderError::new("arguments must be valid UTF-8"))
        })
        .collect::<BuilderResult<Vec<_>>>()?;
    let Some(command) = args.first().map(String::as_str) else {
        return Ok(Command::Help);
    };
    match command {
        "help" | "-h" | "--help" => parse_no_arguments(&args, Command::Help),
        "-V" | "--version" => parse_no_arguments(&args, Command::Version),
        "authority" => parse_authority(&args),
        "build" => parse_build(&args),
        _ => Err(BuilderError::new(format!("unknown command '{command}'"))),
    }
}

pub(crate) fn execute(command: Command) -> BuilderResult<()> {
    match command {
        Command::Help => {
            print!("{HELP}");
            Ok(())
        }
        Command::Version => {
            println!("dbx-rs-app-builder {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::InitializeAuthority {
            output,
            common_name,
        } => {
            let material = authority::initialize(&output, &common_name)?;
            println!("authority_directory={}", material.directory.display());
            println!("authority_sha256={}", material.authority.fingerprint_hex());
            Ok(())
        }
        Command::Build(options) => {
            let outputs = app::build(&options)?;
            for output in outputs {
                println!("app_directory={}", output.app_directory.display());
                if let Some(archive) = output.archive {
                    println!("app_archive={}", archive.display());
                }
            }
            Ok(())
        }
    }
}

fn parse_authority(args: &[String]) -> BuilderResult<Command> {
    if args.get(1).map(String::as_str) != Some("init") {
        return Err(BuilderError::new("authority command requires 'init'"));
    }
    let mut output = None;
    let mut common_name = None;
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--output" => {
                set_path_option(&mut output, args, index, "--output")?;
                index += 2;
            }
            "--common-name" => {
                set_string_option(&mut common_name, args, index, "--common-name")?;
                index += 2;
            }
            argument => return Err(BuilderError::new(format!("unknown argument '{argument}'"))),
        }
    }
    Ok(Command::InitializeAuthority {
        output: output.ok_or_else(|| BuilderError::new("--output is required"))?,
        common_name: common_name.unwrap_or_else(|| "dbx-rs deployment authority".into()),
    })
}

fn parse_build(args: &[String]) -> BuilderResult<Command> {
    let mut authority_dir = None;
    let mut output_dir = None;
    let mut template_dir = None;
    let mut target_dir = None;
    let mut config_dir = None;
    let mut linux_overlay = None;
    let mut windows_overlay = None;
    let mut platform = None;
    let mut archive = true;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--authority-dir" => {
                set_path_option(&mut authority_dir, args, index, "--authority-dir")?;
                index += 2;
            }
            "--output-dir" => {
                set_path_option(&mut output_dir, args, index, "--output-dir")?;
                index += 2;
            }
            "--template-dir" => {
                set_path_option(&mut template_dir, args, index, "--template-dir")?;
                index += 2;
            }
            "--target-dir" => {
                set_path_option(&mut target_dir, args, index, "--target-dir")?;
                index += 2;
            }
            "--config-dir" => {
                set_path_option(&mut config_dir, args, index, "--config-dir")?;
                index += 2;
            }
            "--linux-overlay" => {
                set_path_option(&mut linux_overlay, args, index, "--linux-overlay")?;
                index += 2;
            }
            "--windows-overlay" => {
                set_path_option(&mut windows_overlay, args, index, "--windows-overlay")?;
                index += 2;
            }
            "--platform" => {
                let value = required_value(args, index, "--platform")?;
                let selected = PlatformSelection::parse(value)?;
                set_once(&mut platform, selected, "--platform")?;
                index += 2;
            }
            "--no-archive" => {
                if !archive {
                    return Err(BuilderError::new("--no-archive cannot be repeated"));
                }
                archive = false;
                index += 1;
            }
            argument => return Err(BuilderError::new(format!("unknown argument '{argument}'"))),
        }
    }
    Ok(Command::Build(BuildOptions {
        authority_dir: authority_dir
            .ok_or_else(|| BuilderError::new("--authority-dir is required"))?,
        output_dir: output_dir.unwrap_or_else(|| PathBuf::from("dist")),
        template_dir,
        target_dir,
        config_dir,
        linux_overlay,
        windows_overlay,
        platforms: platform.unwrap_or(PlatformSelection::All),
        archive,
    }))
}

fn parse_no_arguments(args: &[String], command: Command) -> BuilderResult<Command> {
    if args.len() != 1 {
        return Err(BuilderError::new(
            "help and version do not accept arguments",
        ));
    }
    Ok(command)
}

fn required_value<'a>(args: &'a [String], index: usize, label: &str) -> BuilderResult<&'a str> {
    args.get(index + 1)
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .ok_or_else(|| BuilderError::new(format!("{label} requires a value")))
}

fn set_path_option(
    slot: &mut Option<PathBuf>,
    args: &[String],
    index: usize,
    label: &str,
) -> BuilderResult<()> {
    set_once(
        slot,
        PathBuf::from(required_value(args, index, label)?),
        label,
    )
}

fn set_string_option(
    slot: &mut Option<String>,
    args: &[String],
    index: usize,
    label: &str,
) -> BuilderResult<()> {
    set_once(slot, required_value(args, index, label)?.to_owned(), label)
}

fn set_once<T>(slot: &mut Option<T>, value: T, label: &str) -> BuilderResult<()> {
    if slot.replace(value).is_some() {
        return Err(BuilderError::new(format!("{label} cannot be repeated")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_requires_external_authority_directory() {
        let error = parse(["build"].map(OsString::from)).expect_err("authority must be required");

        assert!(error.to_string().contains("--authority-dir"));
    }

    #[test]
    fn build_parses_platform_overlays_without_credentials() {
        let command = parse(
            [
                "build",
                "--authority-dir",
                "/keys",
                "--platform",
                "windows",
                "--config-dir",
                "/config",
                "--windows-overlay",
                "/overlay",
            ]
            .map(OsString::from),
        )
        .expect("build command must parse");

        let Command::Build(options) = command else {
            panic!("command must be build");
        };
        assert_eq!(options.platforms, PlatformSelection::Windows);
        assert_eq!(options.config_dir, Some(PathBuf::from("/config")));
        assert_eq!(options.windows_overlay, Some(PathBuf::from("/overlay")));
    }
}
