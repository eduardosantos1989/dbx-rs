#![forbid(unsafe_code)]

mod error;
mod model;
mod secret;

pub use error::{ConnectorError, ErrorClass};
pub use model::{
    CollectionResult, ConnectionConfig, ProbeReport, TlsMode, ValidationIssue, ValidationReport,
    ValidationSeverity,
};
pub use secret::ResolvedSecret;
