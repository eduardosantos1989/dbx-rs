#![forbid(unsafe_code)]

mod cli;

use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(cli::run(
        std::env::args_os().skip(1),
        std::io::stdout(),
        std::io::stderr(),
    ))
}
