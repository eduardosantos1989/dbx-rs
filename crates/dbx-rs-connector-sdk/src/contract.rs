use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{
    ConnectionConfig, ConnectorError, ProbeReport, ResolvedSecret, TimestampIdCursorRequest,
    TimestampIdCursorSpec, ValidationReport,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }
}

pub const CONNECTOR_CONTRACT_VERSION: ProtocolVersion = ProtocolVersion::new(1, 2);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorCapability {
    ValidateConfiguration,
    ProbeConnection,
    PrepareQuery,
    ExecuteQuery,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationMethod {
    Password,
    ClientCertificate,
    Kerberos,
    OperatingSystem,
    Token,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorSupportTier {
    #[default]
    NativeCertified,
    ExperimentalNative,
    ManagedCompatibility,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConnectorDescriptor {
    pub contract_version: ProtocolVersion,
    pub connector_id: String,
    pub connector_version: String,
    pub database_families: Vec<String>,
    pub capabilities: Vec<ConnectorCapability>,
    pub authentication_methods: Vec<AuthenticationMethod>,
    pub build_id: String,
    #[serde(default)]
    pub support_tier: ConnectorSupportTier,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    Boolean,
    Int8,
    Int16,
    Int32,
    Int64,
    UInt32,
    Float32,
    Float64,
    Utf8,
    Binary,
    Uuid,
    Json,
    Decimal128 { precision: u8, scale: i8 },
    Date32,
    Time64Microsecond,
    TimestampMicrosecond,
    TimestampMicrosecondUtc,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct FieldDescriptor {
    pub name: String,
    pub field_type: FieldType,
    pub nullable: bool,
    pub source_type: String,
}

impl std::fmt::Debug for FieldDescriptor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FieldDescriptor")
            .field("name", &"[REDACTED]")
            .field("field_type", &self.field_type)
            .field("nullable", &self.nullable)
            .field("source_type", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuerySchema {
    pub fields: Vec<FieldDescriptor>,
}

impl std::fmt::Debug for QuerySchema {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QuerySchema")
            .field("field_count", &self.fields.len())
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct QueryText(String);

impl QueryText {
    #[must_use]
    pub fn new(query: impl Into<String>) -> Self {
        Self(query.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for QueryText {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("QueryText([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionLimits {
    pub max_rows: u64,
    pub max_batch_rows: u32,
    pub max_batch_bytes: u64,
    pub max_total_ipc_bytes: u64,
    pub timeout: Duration,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ValidationRequest {
    pub connection: ConnectionConfig,
    pub query: Option<QueryText>,
    pub max_rows: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<TimestampIdCursorSpec>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProbeRequest {
    pub request_id: String,
    pub connection: ConnectionConfig,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrepareRequest {
    pub request_id: String,
    pub connection: ConnectionConfig,
    pub query: QueryText,
    pub max_rows: u64,
    pub timeout: Duration,
    #[serde(default)]
    pub cursor: Option<TimestampIdCursorRequest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreparedQuery {
    pub request_id: String,
    pub connector_id: String,
    pub schema: QuerySchema,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecuteRequest {
    pub request_id: String,
    pub connection: ConnectionConfig,
    pub query: QueryText,
    pub limits: ExecutionLimits,
    pub expected_schema: Option<QuerySchema>,
    #[serde(default)]
    pub cursor: Option<TimestampIdCursorRequest>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArrowIpcBatch {
    pub request_id: String,
    pub sequence: u64,
    pub row_count: u64,
    pub schema: QuerySchema,
    pub ipc_bytes: Vec<u8>,
}

impl std::fmt::Debug for ArrowIpcBatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ArrowIpcBatch")
            .field("request_id", &self.request_id)
            .field("sequence", &self.sequence)
            .field("row_count", &self.row_count)
            .field("schema", &self.schema)
            .field("ipc_byte_count", &self.ipc_bytes.len())
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionResult {
    pub request_id: String,
    pub rows_read: u64,
    pub batches_emitted: u64,
    pub ipc_bytes_emitted: u64,
    pub truncated: bool,
    pub schema: QuerySchema,
}

pub type ConnectorFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ConnectorError>> + Send + 'a>>;

pub trait Connector: Send + Sync {
    fn descriptor(&self) -> ConnectorDescriptor;

    fn validate(&self, request: &ValidationRequest) -> ValidationReport;

    fn probe<'a>(
        &'a self,
        request: ProbeRequest,
        secret: &'a ResolvedSecret,
        cancellation: CancellationToken,
    ) -> ConnectorFuture<'a, ProbeReport>;

    fn prepare<'a>(
        &'a self,
        request: PrepareRequest,
        secret: &'a ResolvedSecret,
        cancellation: CancellationToken,
    ) -> ConnectorFuture<'a, PreparedQuery>;

    fn execute<'a>(
        &'a self,
        request: ExecuteRequest,
        secret: &'a ResolvedSecret,
        batch_tx: mpsc::Sender<ArrowIpcBatch>,
        cancellation: CancellationToken,
    ) -> ConnectorFuture<'a, ExecutionResult>;
}

pub trait ConnectorProvider: Send + Sync {
    /// Resolves a connector by its stable connector identifier.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when the identifier is not registered.
    fn connector(&self, connector_id: &str) -> Result<Arc<dyn Connector>, ConnectorError>;

    fn descriptors(&self) -> Vec<ConnectorDescriptor>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connection() -> ConnectionConfig {
        ConnectionConfig {
            connector_id: "postgres".into(),
            host: "localhost".into(),
            port: 5432,
            database: "inventory".into(),
            username: "reader".into(),
            tls_mode: crate::TlsMode::VerifyFull,
            tls_server_name: None,
            tls_ca_pem: None,
            connect_timeout: Duration::from_secs(5),
            probe_timeout: Duration::from_secs(5),
        }
    }

    fn schema() -> QuerySchema {
        QuerySchema {
            fields: vec![FieldDescriptor {
                name: "customer_secret".into(),
                field_type: FieldType::Utf8,
                nullable: false,
                source_type: "private_type_name".into(),
            }],
        }
    }

    #[test]
    fn protocol_version_remains_one_two() {
        assert_eq!(CONNECTOR_CONTRACT_VERSION, ProtocolVersion::new(1, 2));
    }

    #[test]
    fn legacy_descriptor_defaults_to_native_certified() {
        let descriptor: ConnectorDescriptor = serde_json::from_str(
            r#"{
                "contract_version":{"major":1,"minor":2},
                "connector_id":"postgres",
                "connector_version":"0.1.0",
                "database_families":["postgresql"],
                "capabilities":["validate_configuration"],
                "authentication_methods":["password"],
                "build_id":"legacy"
            }"#,
        )
        .expect("contract 1.2 descriptor should deserialize");

        assert_eq!(
            descriptor.support_tier,
            ConnectorSupportTier::NativeCertified
        );
    }

    #[test]
    fn contract_requests_round_trip_through_serde() {
        let request = ExecuteRequest {
            request_id: "request-1".into(),
            connection: connection(),
            query: QueryText::new("select sensitive_column from private_table"),
            limits: ExecutionLimits {
                max_rows: 100,
                max_batch_rows: 25,
                max_batch_bytes: 64 * 1024,
                max_total_ipc_bytes: 1024 * 1024,
                timeout: Duration::from_secs(30),
            },
            expected_schema: Some(schema()),
            cursor: None,
        };

        let encoded = serde_json::to_vec(&request).expect("request should serialize");
        let decoded: ExecuteRequest =
            serde_json::from_slice(&encoded).expect("request should deserialize");

        assert_eq!(decoded, request);
        assert_eq!(decoded.query.as_str(), request.query.as_str());

        let mut legacy = serde_json::to_value(&request).expect("request should become JSON");
        legacy
            .as_object_mut()
            .expect("request JSON must be an object")
            .remove("cursor");
        let legacy: ExecuteRequest =
            serde_json::from_value(legacy).expect("contract 1.0 request should deserialize");
        assert_eq!(legacy.cursor, None);

        let validation = ValidationRequest {
            connection: connection(),
            query: Some(QueryText::new(
                "select updated_at, private_id from private_table",
            )),
            max_rows: Some(100),
            cursor: Some(TimestampIdCursorSpec {
                timestamp_field: "updated_at".into(),
                id_field: "private_id".into(),
                overlap: Duration::from_secs(1),
                null_policy: crate::CursorNullPolicy::Reject,
            }),
        };
        let encoded = serde_json::to_vec(&validation).expect("validation should serialize");
        let decoded: ValidationRequest =
            serde_json::from_slice(&encoded).expect("validation should deserialize");
        assert_eq!(decoded, validation);
        let mut legacy = serde_json::to_value(&validation).expect("validation should become JSON");
        legacy
            .as_object_mut()
            .expect("validation JSON must be an object")
            .remove("cursor");
        let legacy: ValidationRequest =
            serde_json::from_value(legacy).expect("legacy validation should deserialize");
        assert_eq!(legacy.cursor, None);

        let batch = ArrowIpcBatch {
            request_id: "request-1".into(),
            sequence: 2,
            row_count: 25,
            schema: schema(),
            ipc_bytes: vec![0, 1, 2, 255],
        };
        let encoded = serde_json::to_vec(&batch).expect("batch should serialize");
        let decoded: ArrowIpcBatch =
            serde_json::from_slice(&encoded).expect("batch should deserialize");

        assert_eq!(decoded, batch);
    }

    #[test]
    fn debug_output_redacts_query_schema_details_and_ipc_payload() {
        let query = QueryText::new("select sensitive_column from private_table");
        let query_debug = format!("{query:?}");
        assert_eq!(query_debug, "QueryText([REDACTED])");
        assert!(!query_debug.contains("sensitive_column"));

        let request = ExecuteRequest {
            request_id: "request-1".into(),
            connection: connection(),
            query,
            limits: ExecutionLimits {
                max_rows: 1,
                max_batch_rows: 1,
                max_batch_bytes: 1024,
                max_total_ipc_bytes: 1024,
                timeout: Duration::from_secs(1),
            },
            expected_schema: Some(schema()),
            cursor: None,
        };
        let request_debug = format!("{request:?}");
        assert!(!request_debug.contains("sensitive_column"));
        assert!(!request_debug.contains("customer_secret"));

        let schema = schema();
        let schema_debug = format!("{schema:?}");
        assert!(schema_debug.contains("field_count: 1"));
        assert!(!schema_debug.contains("customer_secret"));
        assert!(!schema_debug.contains("private_type_name"));

        let batch = ArrowIpcBatch {
            request_id: "request-1".into(),
            sequence: 0,
            row_count: 1,
            schema,
            ipc_bytes: b"private ipc payload".to_vec(),
        };
        let batch_debug = format!("{batch:?}");
        assert!(batch_debug.contains("ipc_byte_count: 19"));
        assert!(!batch_debug.contains("private ipc payload"));
        assert!(!batch_debug.contains("customer_secret"));
    }

    #[test]
    fn connector_traits_are_object_safe() {
        fn accepts_connector(_: Option<&dyn Connector>) {}
        fn accepts_provider(_: Option<&dyn ConnectorProvider>) {}

        accepts_connector(None);
        accepts_provider(None);
    }
}
