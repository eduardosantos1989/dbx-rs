use std::io;

#[derive(Debug)]
pub struct SpoolError {
    code: &'static str,
    stage: &'static str,
    message: &'static str,
    io_kind: Option<io::ErrorKind>,
}

impl SpoolError {
    pub(crate) const fn new(
        code: &'static str,
        stage: &'static str,
        message: &'static str,
    ) -> Self {
        Self {
            code,
            stage,
            message,
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
            stage,
            message,
            io_kind: Some(error.kind()),
        }
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn stage(&self) -> &'static str {
        self.stage
    }

    #[must_use]
    pub const fn io_kind(&self) -> Option<io::ErrorKind> {
        self.io_kind
    }
}

impl std::fmt::Display for SpoolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "spool error[{}] {} during {}",
            self.code, self.message, self.stage
        )?;
        if let Some(kind) = self.io_kind {
            write!(formatter, " ({kind:?})")?;
        }
        Ok(())
    }
}

impl std::error::Error for SpoolError {}

impl From<dbx_rs_secure_store::SecureStoreError> for SpoolError {
    fn from(error: dbx_rs_secure_store::SecureStoreError) -> Self {
        Self {
            code: "DBX-RS-SPOOL-0001",
            stage: "protected_storage",
            message: "protected storage operation failed",
            io_kind: error.io_kind(),
        }
    }
}
