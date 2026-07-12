#![forbid(unsafe_code)]

mod cli;

use std::process::ExitCode;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    ExitCode::from(
        cli::run(
            std::env::args_os().skip(1),
            std::io::stdin(),
            std::io::stdout(),
            std::io::stderr(),
        )
        .await,
    )
}
