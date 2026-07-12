#![forbid(unsafe_code)]

mod dto;
mod error;
mod service;

pub use dto::{
    AdHocQuery, InputProbeResponse, InputValidationResponse, QueryTestLimitOverrides,
    QueryTestLimits, QueryTestRequest, QueryTestResponse,
};
pub use error::ControlError;
pub use service::{
    CONTROL_SCHEMA_VERSION, ControlService, MAX_CONTROL_PROBE_TIMEOUT_SECS, MAX_QUERY_TEST_BYTES,
    MAX_QUERY_TEST_ROWS, MAX_QUERY_TEST_TIMEOUT_SECS,
};
