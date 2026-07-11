use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    Configuration,
    Dns,
    Tcp,
    Tls,
    Authentication,
    Protocol,
    Query,
    Conversion,
    Timeout,
    Cancelled,
    Internal,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConnectorError {
    code: String,
    class: ErrorClass,
    message: String,
    sql_state: Option<String>,
    retryable: bool,
    configuration_error: bool,
}

impl ConnectorError {
    pub fn new(
        code: impl Into<String>,
        class: ErrorClass,
        message: impl Into<String>,
        retryable: bool,
        configuration_error: bool,
    ) -> Self {
        Self {
            code: code.into(),
            class,
            message: message.into(),
            sql_state: None,
            retryable,
            configuration_error,
        }
    }

    pub fn cancelled(code: impl Into<String>) -> Self {
        Self::new(
            code,
            ErrorClass::Cancelled,
            "operation cancelled",
            true,
            false,
        )
    }

    #[must_use]
    pub fn with_sql_state(mut self, sql_state: impl Into<String>) -> Self {
        self.sql_state = Some(sql_state.into());
        self
    }

    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    #[must_use]
    pub const fn class(&self) -> ErrorClass {
        self.class
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub fn sql_state(&self) -> Option<&str> {
        self.sql_state.as_deref()
    }

    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        self.retryable
    }

    #[must_use]
    pub const fn is_configuration_error(&self) -> bool {
        self.configuration_error
    }
}

impl std::fmt::Display for ConnectorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ConnectorError {}
