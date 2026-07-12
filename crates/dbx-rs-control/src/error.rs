use dbx_rs_config::ConfigError;
use dbx_rs_connector_sdk::{ConnectorError, ErrorClass};
use dbx_rs_secure_store::SecureStoreError;
use serde::{Deserialize, Serialize};

use crate::service::CONTROL_SCHEMA_VERSION;

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
struct ControlErrorBody {
    schema_version: u16,
    operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    input: Option<String>,
    code: String,
    class: String,
    stage: String,
    message: String,
    retryable: bool,
    configuration_error: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    sql_state: Option<String>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ControlError {
    body: Box<ControlErrorBody>,
}

impl ControlError {
    pub(crate) fn new(
        code: impl Into<String>,
        class: impl Into<String>,
        stage: impl Into<String>,
        message: impl Into<String>,
        retryable: bool,
        configuration_error: bool,
    ) -> Self {
        Self {
            body: Box::new(ControlErrorBody {
                schema_version: CONTROL_SCHEMA_VERSION,
                operation: "control".into(),
                request_id: None,
                input: None,
                code: code.into(),
                class: class.into(),
                stage: stage.into(),
                message: message.into(),
                retryable,
                configuration_error,
                sql_state: None,
            }),
        }
    }

    pub(crate) fn from_config(error: &ConfigError) -> Self {
        Self::new(
            error.code(),
            "configuration",
            "configuration",
            "dbx-rs configuration is invalid",
            false,
            true,
        )
        .with_operation("config_load")
    }

    pub(crate) fn from_secure(error: &SecureStoreError) -> Self {
        Self::new(
            error.code(),
            error.class(),
            error.stage(),
            error.message(),
            error.retryable(),
            error.configuration_error(),
        )
    }

    pub(crate) fn from_connector(error: &ConnectorError) -> Self {
        let mut control = Self::new(
            error.code(),
            error_class_name(error.class()),
            error_stage(error.class()),
            error.message(),
            error.is_retryable(),
            error.is_configuration_error(),
        );
        control.body.sql_state = error.sql_state().map(str::to_owned);
        control
    }

    #[must_use]
    pub(crate) fn with_context(mut self, operation: &str, request_id: &str, input: &str) -> Self {
        operation.clone_into(&mut self.body.operation);
        self.body.request_id = Some(request_id.to_owned());
        self.body.input = Some(input.to_owned());
        self
    }

    #[must_use]
    pub(crate) fn with_operation(mut self, operation: &str) -> Self {
        operation.clone_into(&mut self.body.operation);
        self
    }

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.body.schema_version
    }

    #[must_use]
    pub fn operation(&self) -> &str {
        &self.body.operation
    }

    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        self.body.request_id.as_deref()
    }

    #[must_use]
    pub fn input(&self) -> Option<&str> {
        self.body.input.as_deref()
    }

    #[must_use]
    pub fn code(&self) -> &str {
        &self.body.code
    }

    #[must_use]
    pub fn class(&self) -> &str {
        &self.body.class
    }

    #[must_use]
    pub fn stage(&self) -> &str {
        &self.body.stage
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.body.message
    }

    #[must_use]
    pub const fn retryable(&self) -> bool {
        self.body.retryable
    }

    #[must_use]
    pub const fn configuration_error(&self) -> bool {
        self.body.configuration_error
    }

    #[must_use]
    pub fn sql_state(&self) -> Option<&str> {
        self.body.sql_state.as_deref()
    }
}

impl std::fmt::Debug for ControlError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControlError")
            .field("schema_version", &self.body.schema_version)
            .field("operation", &self.body.operation)
            .field("request_id", &self.body.request_id)
            .field("input", &self.body.input)
            .field("code", &self.body.code)
            .field("class", &self.body.class)
            .field("stage", &self.body.stage)
            .field("retryable", &self.body.retryable)
            .field("configuration_error", &self.body.configuration_error)
            .field("sql_state", &self.body.sql_state)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "error[{}] {} during {}",
            self.body.code, self.body.message, self.body.stage
        )
    }
}

impl std::error::Error for ControlError {}

pub(crate) const fn error_class_name(class: ErrorClass) -> &'static str {
    match class {
        ErrorClass::Configuration => "configuration",
        ErrorClass::Dns => "dns",
        ErrorClass::Tcp => "tcp",
        ErrorClass::Tls => "tls",
        ErrorClass::Authentication => "authentication",
        ErrorClass::Protocol => "protocol",
        ErrorClass::Query => "query",
        ErrorClass::Conversion => "conversion",
        ErrorClass::Timeout => "timeout",
        ErrorClass::Cancelled => "cancelled",
        ErrorClass::Internal => "internal",
    }
}

pub(crate) const fn error_stage(class: ErrorClass) -> &'static str {
    match class {
        ErrorClass::Configuration => "configuration",
        ErrorClass::Dns => "dns",
        ErrorClass::Tcp => "tcp_connect",
        ErrorClass::Tls => "tls_handshake",
        ErrorClass::Authentication => "authentication",
        ErrorClass::Protocol => "protocol",
        ErrorClass::Query => "query",
        ErrorClass::Conversion => "conversion",
        ErrorClass::Timeout => "timeout",
        ErrorClass::Cancelled => "cancellation",
        ErrorClass::Internal => "internal",
    }
}
