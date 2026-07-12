use std::path::PathBuf;

use dbx_rs_connector_sdk::{TlsMode, ValidationIssue};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum AdHocQuery {
    Inline { sql: String },
    File { path: PathBuf },
}

impl std::fmt::Debug for AdHocQuery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inline { .. } => formatter.write_str("Inline([REDACTED])"),
            Self::File { .. } => formatter.write_str("File([CONFIGURED])"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueryTestLimitOverrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_rows: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueryTestLimits {
    pub max_rows: u64,
    pub max_bytes: u64,
    pub timeout_secs: u64,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueryTestRequest {
    pub input: String,
    pub query: AdHocQuery,
    #[serde(default)]
    pub limits: QueryTestLimitOverrides,
}

impl std::fmt::Debug for QueryTestRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QueryTestRequest")
            .field("input", &self.input)
            .field("query", &self.query)
            .field("limits", &self.limits)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InputValidationResponse {
    pub schema_version: u16,
    pub request_id: String,
    pub input: String,
    pub connector: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct InputProbeResponse {
    pub schema_version: u16,
    pub request_id: String,
    pub input: String,
    pub connector: String,
    pub database_product: String,
    pub server_version: String,
    pub server_version_number: Option<u32>,
    pub endpoint: String,
    pub tls_mode: TlsMode,
}

impl std::fmt::Debug for InputProbeResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InputProbeResponse")
            .field("schema_version", &self.schema_version)
            .field("request_id", &self.request_id)
            .field("input", &self.input)
            .field("connector", &self.connector)
            .field("database_product", &self.database_product)
            .field("server_version", &self.server_version)
            .field("server_version_number", &self.server_version_number)
            .field("endpoint", &"[REDACTED]")
            .field("tls_mode", &self.tls_mode)
            .finish()
    }
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
pub struct QueryTestResponse {
    pub schema_version: u16,
    pub request_id: String,
    pub input: String,
    pub connector: String,
    pub limits: QueryTestLimits,
    pub rows_read: u64,
    pub bytes_read: u64,
    pub rows: Vec<Value>,
}

impl std::fmt::Debug for QueryTestResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QueryTestResponse")
            .field("schema_version", &self.schema_version)
            .field("request_id", &self.request_id)
            .field("input", &self.input)
            .field("connector", &self.connector)
            .field("limits", &self.limits)
            .field("rows_read", &self.rows_read)
            .field("bytes_read", &self.bytes_read)
            .field("rows", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_request_debug_redacts_inline_sql() {
        let request = QueryTestRequest {
            input: "warehouse".into(),
            query: AdHocQuery::Inline {
                sql: "SELECT private_value FROM private_table".into(),
            },
            limits: QueryTestLimitOverrides::default(),
        };
        let debug = format!("{request:?}");

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("private_value"));
        assert!(!debug.contains("private_table"));
    }

    #[test]
    fn query_response_debug_redacts_rows() {
        let response = QueryTestResponse {
            schema_version: 1,
            request_id: "request".into(),
            input: "warehouse".into(),
            connector: "postgres".into(),
            limits: QueryTestLimits {
                max_rows: 1,
                max_bytes: 1024,
                timeout_secs: 1,
            },
            rows_read: 1,
            bytes_read: 20,
            rows: vec![serde_json::json!({"private_value": "secret row"})],
        };
        let debug = format!("{response:?}");

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("private_value"));
        assert!(!debug.contains("secret row"));
    }
}
