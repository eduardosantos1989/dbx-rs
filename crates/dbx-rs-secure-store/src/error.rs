use std::io;

#[derive(Debug)]
pub struct SecureStoreError {
    code: &'static str,
    class: &'static str,
    stage: &'static str,
    message: &'static str,
    retryable: bool,
    configuration_error: bool,
    io_kind: Option<io::ErrorKind>,
}

impl SecureStoreError {
    pub(crate) const fn new(
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

    pub(crate) fn io(
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

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn class(&self) -> &'static str {
        self.class
    }

    #[must_use]
    pub const fn stage(&self) -> &'static str {
        self.stage
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }

    #[must_use]
    pub const fn retryable(&self) -> bool {
        self.retryable
    }

    #[must_use]
    pub const fn configuration_error(&self) -> bool {
        self.configuration_error
    }

    #[must_use]
    pub const fn io_kind(&self) -> Option<io::ErrorKind> {
        self.io_kind
    }
}

impl std::fmt::Display for SecureStoreError {
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

impl std::error::Error for SecureStoreError {}
