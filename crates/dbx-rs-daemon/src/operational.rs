use std::time::Instant;

use dbx_rs_connector_sdk::{ConnectorError, ErrorClass};
use dbx_rs_telemetry::{
    NdjsonTelemetry, OperationContext, OperationFailure, OperationLimits, OperationMetrics,
};

use crate::error::DaemonError;

pub struct OperationTracker {
    telemetry: NdjsonTelemetry,
    context: OperationContext,
    started: Instant,
}

impl OperationTracker {
    pub fn start(
        telemetry: &NdjsonTelemetry,
        connector: &str,
        operation: &str,
        request_id: &str,
        tls_mode: &str,
        input: Option<&str>,
        limits: OperationLimits,
    ) -> Result<Self, DaemonError> {
        let mut context = OperationContext::new(
            "dbx_rs_daemon",
            connector,
            operation,
            request_id,
            env!("CARGO_PKG_VERSION"),
            tls_mode,
        )
        .map_err(|_| telemetry_error("telemetry_context"))?;
        if let Some(input) = input {
            context = context
                .with_input(input)
                .map_err(|_| telemetry_error("telemetry_context"))?;
        }
        telemetry
            .operation_started(&context, limits)
            .map_err(|_| telemetry_error("telemetry_start"))?;
        Ok(Self {
            telemetry: telemetry.clone(),
            context,
            started: Instant::now(),
        })
    }

    pub fn succeeded(self, metrics: OperationMetrics) -> Result<(), DaemonError> {
        self.telemetry
            .operation_succeeded(&self.context, self.started.elapsed(), metrics)
            .map_err(|_| telemetry_error("telemetry_success"))
    }

    pub fn failed_daemon(&self, error: &DaemonError) {
        let failure = OperationFailure::new(
            error.code(),
            error.class(),
            error.stage(),
            error.retryable(),
            error.configuration_error(),
            None::<String>,
        );
        if let Ok(failure) = failure {
            let _ignored =
                self.telemetry
                    .operation_failed(&self.context, self.started.elapsed(), &failure);
        }
    }

    pub fn failed_connector(&self, error: &ConnectorError) {
        let failure = OperationFailure::new(
            error.code(),
            error_class_name(error.class()),
            error_stage(error.class()),
            error.is_retryable(),
            error.is_configuration_error(),
            error.sql_state(),
        );
        if let Ok(failure) = failure {
            let _ignored =
                self.telemetry
                    .operation_failed(&self.context, self.started.elapsed(), &failure);
        }
    }
}

const fn telemetry_error(stage: &'static str) -> DaemonError {
    DaemonError::new(
        "DBX-RS-TRACE-0001",
        "io",
        stage,
        "operational telemetry failed",
        true,
        false,
    )
}

const fn error_class_name(class: ErrorClass) -> &'static str {
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

const fn error_stage(class: ErrorClass) -> &'static str {
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
