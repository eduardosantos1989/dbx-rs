#![forbid(unsafe_code)]

mod contract;
mod cursor;
mod error;
mod model;
mod secret;

pub use contract::{
    ArrowIpcBatch, AuthenticationMethod, CONNECTOR_CONTRACT_VERSION, Connector,
    ConnectorCapability, ConnectorDescriptor, ConnectorFuture, ConnectorProvider,
    ConnectorSupportTier, ExecuteRequest, ExecutionLimits, ExecutionResult, FieldDescriptor,
    FieldType, PrepareRequest, PreparedQuery, ProbeRequest, ProtocolVersion, QuerySchema,
    QueryText, ValidationRequest,
};
pub use cursor::{
    CursorContractError, CursorNullPolicy, TIMESTAMP_ID_CURSOR_CANONICAL_BYTES,
    TIMESTAMP_ID_CURSOR_FORMAT_VERSION, TimestampIdCursor, TimestampIdCursorBound,
    TimestampIdCursorRequest, TimestampIdCursorSpec,
};
pub use error::{ConnectorError, ErrorClass};
pub use model::{
    CollectionResult, ConnectionConfig, ProbeReport, TlsMode, ValidationIssue, ValidationReport,
    ValidationSeverity,
};
pub use secret::ResolvedSecret;
