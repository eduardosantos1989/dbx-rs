use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsMode {
    Disable,
    Require,
    VerifyCa,
    #[default]
    VerifyFull,
}

impl std::fmt::Display for TlsMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Disable => "disable",
            Self::Require => "require",
            Self::VerifyCa => "verify-ca",
            Self::VerifyFull => "verify-full",
        };
        formatter.write_str(value)
    }
}

impl std::str::FromStr for TlsMode {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "disable" => Ok(Self::Disable),
            "require" => Ok(Self::Require),
            "verify-ca" => Ok(Self::VerifyCa),
            "verify-full" => Ok(Self::VerifyFull),
            _ => Err("expected disable, require, verify-ca, or verify-full"),
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConnectionConfig {
    pub connector_id: String,
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub tls_mode: TlsMode,
    pub tls_server_name: Option<String>,
    pub tls_ca_pem: Option<Vec<u8>>,
    pub connect_timeout: Duration,
    pub probe_timeout: Duration,
}

impl std::fmt::Debug for ConnectionConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectionConfig")
            .field("connector_id", &self.connector_id)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("database", &self.database)
            .field("username", &self.username)
            .field("tls_mode", &self.tls_mode)
            .field("tls_server_name", &self.tls_server_name)
            .field(
                "tls_ca_pem",
                &self.tls_ca_pem.as_ref().map(|_| "[CONFIGURED]"),
            )
            .field("connect_timeout", &self.connect_timeout)
            .field("probe_timeout", &self.probe_timeout)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationSeverity {
    Warning,
    Error,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ValidationIssue {
    pub code: String,
    pub field: String,
    pub message: String,
    pub severity: ValidationSeverity,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ValidationReport {
    pub issues: Vec<ValidationIssue>,
}

impl ValidationReport {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self
            .issues
            .iter()
            .any(|issue| issue.severity == ValidationSeverity::Error)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProbeReport {
    pub connector_id: String,
    pub database_product: String,
    pub server_version: String,
    pub server_version_number: Option<u32>,
    pub endpoint: String,
    pub tls_mode: TlsMode,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CollectionResult {
    pub request_id: String,
    pub rows_read: u64,
    pub bytes_read: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_mode_defaults_to_verified_full() {
        assert_eq!(TlsMode::default(), TlsMode::VerifyFull);
    }

    #[test]
    fn validation_report_rejects_error_issues() {
        let report = ValidationReport {
            issues: vec![ValidationIssue {
                code: "TEST-001".into(),
                field: "host".into(),
                message: "host is required".into(),
                severity: ValidationSeverity::Error,
            }],
        };

        assert!(!report.is_valid());
    }

    #[test]
    fn connection_debug_does_not_emit_ca_contents() {
        let config = ConnectionConfig {
            connector_id: "test".into(),
            host: "localhost".into(),
            port: 1,
            database: "test".into(),
            username: "reader".into(),
            tls_mode: TlsMode::VerifyFull,
            tls_server_name: None,
            tls_ca_pem: Some(b"private certificate material".to_vec()),
            connect_timeout: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(1),
        };
        let debug = format!("{config:?}");

        assert!(debug.contains("[CONFIGURED]"));
        assert!(!debug.contains("private certificate material"));
    }
}
