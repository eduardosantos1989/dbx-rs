use std::io;

use dbx_rs_config::ConfigError;

#[derive(Debug)]
pub struct DaemonError {
    code: &'static str,
    class: &'static str,
    stage: &'static str,
    message: &'static str,
    retryable: bool,
    configuration_error: bool,
    io_kind: Option<io::ErrorKind>,
}

impl DaemonError {
    pub const fn new(
        code: &'static str,
        class: &'static str,
        stage: &'static str,
        message: &'static str,
        retryable: bool,
        configuration_error: bool,
    ) -> Self {
        Self {
            code,
            class,
            stage,
            message,
            retryable,
            configuration_error,
            io_kind: None,
        }
    }

    pub fn io(
        code: &'static str,
        stage: &'static str,
        message: &'static str,
        error: &io::Error,
    ) -> Self {
        Self {
            code,
            class: "io",
            stage,
            message,
            retryable: false,
            configuration_error: false,
            io_kind: Some(error.kind()),
        }
    }

    pub const fn from_config(error: &ConfigError) -> Self {
        Self {
            code: error.code(),
            class: "configuration",
            stage: "configuration",
            message: "dbx-rs configuration is invalid",
            retryable: false,
            configuration_error: true,
            io_kind: None,
        }
    }

    pub const fn code(&self) -> &'static str {
        self.code
    }

    pub const fn class(&self) -> &'static str {
        self.class
    }

    pub const fn stage(&self) -> &'static str {
        self.stage
    }

    pub const fn retryable(&self) -> bool {
        self.retryable
    }

    pub const fn configuration_error(&self) -> bool {
        self.configuration_error
    }
}

impl std::fmt::Display for DaemonError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "error[{}] {} during {}",
            self.code, self.message, self.stage
        )?;
        if let Some(kind) = self.io_kind {
            write!(formatter, " ({kind:?})")?;
        }
        Ok(())
    }
}

impl std::error::Error for DaemonError {}
