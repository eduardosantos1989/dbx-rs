#![forbid(unsafe_code)]

mod app;
mod authority;
mod cli;

use std::process::ExitCode;

pub(crate) type BuilderResult<T> = Result<T, BuilderError>;

#[derive(Debug)]
pub(crate) struct BuilderError(String);

impl BuilderError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for BuilderError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for BuilderError {}

fn main() -> ExitCode {
    let command = match cli::parse(std::env::args_os().skip(1)) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("error: {error}\n\n{}", cli::HELP);
            return ExitCode::from(2);
        }
    };
    match cli::execute(command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
