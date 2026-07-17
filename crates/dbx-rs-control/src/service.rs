use std::fs;
use std::future::Future;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use dbx_rs_config::{
    CollectionMode, EffectiveConfig, InputConfig, MAX_QUERY_BYTES, MAX_TLS_CA_BYTES, QuerySource,
    load_effective_config,
};
use dbx_rs_connector_sdk::{
    ConnectionConfig, CursorNullPolicy, ProbeRequest, QueryText, TimestampIdCursorSpec, TlsMode,
    ValidationIssue, ValidationRequest, ValidationSeverity,
};
use dbx_rs_native_connectors::{JsonCollectionRequest, JsonRow, NativeConnectorProvider};
use dbx_rs_secure_store::{SecretStore, read_limited};
use dbx_rs_telemetry::{
    NdjsonTelemetry, OperationContext, OperationFailure, OperationLimits, OperationMetrics,
    TelemetryConfig,
};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::dto::{
    AdHocQuery, InputProbeResponse, InputValidationResponse, QueryTestLimitOverrides,
    QueryTestLimits, QueryTestRequest, QueryTestResponse,
};
use crate::error::ControlError;

pub const CONTROL_SCHEMA_VERSION: u16 = 1;
pub const MAX_QUERY_TEST_ROWS: u64 = 100;
pub const MAX_QUERY_TEST_BYTES: u64 = 1_000_000;
pub const MAX_QUERY_TEST_TIMEOUT_SECS: u64 = 30;
pub const MAX_CONTROL_PROBE_TIMEOUT_SECS: u64 = 30;

const ROW_CHANNEL_CAPACITY: usize = 16;
const CONTROL_CANCELLATION_GRACE: Duration = Duration::from_secs(1);

pub struct ControlService {
    app_home: PathBuf,
    config: EffectiveConfig,
    connectors: NativeConnectorProvider,
    telemetry: NdjsonTelemetry,
}

impl ControlService {
    /// Loads effective app configuration without creating credentials or app-local files.
    ///
    /// # Errors
    ///
    /// Returns a redacted control error when configuration or telemetry settings are invalid.
    pub fn load(app_home: &Path, splunk_home: &Path) -> Result<Self, ControlError> {
        let config = load_effective_config(app_home, splunk_home)
            .map_err(|error| ControlError::from_config(&error))?;
        let telemetry = NdjsonTelemetry::new(
            TelemetryConfig::new(&config.generic.paths.log_file).with_rotation(
                config.generic.logging.max_file_bytes,
                config.generic.logging.backup_count,
            ),
        )
        .map_err(|_| telemetry_error("telemetry_initialize").with_operation("control_load"))?;
        Ok(Self {
            app_home: app_home.to_path_buf(),
            config,
            connectors: NativeConnectorProvider::new(),
            telemetry,
        })
    }

    /// Validates one configured input, its referenced assets, and its protected secret.
    ///
    /// # Errors
    ///
    /// Returns a redacted control error when the input is unknown or telemetry cannot be written.
    pub fn validate_input(&self, name: &str) -> Result<InputValidationResponse, ControlError> {
        let request_id = request_id()
            .map_err(|error| error.with_context("input_validate", "request-unavailable", name))?;
        let input = self
            .input(name)
            .map_err(|error| error.with_context("input_validate", &request_id, name))?
            .clone();
        let tracker = ControlTracker::start(
            &self.telemetry,
            &input.connector,
            "input_validate",
            &request_id,
            &input.tls_mode,
            &input.name,
            OperationLimits::default(),
        )?;
        let response = self.validate_input_inner(&input, &request_id);
        tracker.succeeded(OperationMetrics::probe(None))?;
        Ok(response)
    }

    /// Probes the database connection configured by one named input.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for missing assets/secrets or a classified connector failure.
    pub async fn probe_input(
        &self,
        name: &str,
        cancellation: CancellationToken,
    ) -> Result<InputProbeResponse, ControlError> {
        let request_id = request_id()
            .map_err(|error| error.with_context("input_probe", "request-unavailable", name))?;
        let input = self
            .input(name)
            .map_err(|error| error.with_context("input_probe", &request_id, name))?
            .clone();
        let tracker = ControlTracker::start(
            &self.telemetry,
            &input.connector,
            "input_probe",
            &request_id,
            &input.tls_mode,
            &input.name,
            OperationLimits::default()
                .with_connect_timeout(input.connect_timeout)
                .with_operation_timeout(Duration::from_secs(MAX_CONTROL_PROBE_TIMEOUT_SECS)),
        )?;
        let operation_cancellation = cancellation.child_token();
        let operation =
            Box::pin(self.probe_input_inner(&input, &request_id, operation_cancellation.clone()));
        let result = run_with_hard_timeout(
            Duration::from_secs(MAX_CONTROL_PROBE_TIMEOUT_SECS),
            operation_cancellation,
            operation,
        )
        .await;
        match result {
            Ok(response) => {
                tracker.succeeded(OperationMetrics::probe(response.server_version_number))?;
                Ok(response)
            }
            Err(error) => {
                let error = error.with_context("input_probe", &request_id, &input.name);
                tracker.failed(&error);
                Err(error)
            }
        }
    }

    /// Executes one explicitly requested, bounded, read-only query test.
    ///
    /// Row payloads are returned only in the response and are never sent to operational telemetry.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for invalid limits/assets/secrets or a classified connector failure.
    pub async fn test_query(
        &self,
        request: QueryTestRequest,
        cancellation: CancellationToken,
    ) -> Result<QueryTestResponse, ControlError> {
        let request_id = request_id().map_err(|error| {
            error.with_context("query_test", "request-unavailable", &request.input)
        })?;
        let input = self
            .input(&request.input)
            .map_err(|error| error.with_context("query_test", &request_id, &request.input))?
            .clone();
        let caps = query_test_caps(&input);
        let limits = resolve_limits(&input, request.limits);
        let telemetry_limits = limits.as_ref().copied().unwrap_or(caps);
        let tracker = ControlTracker::start(
            &self.telemetry,
            &input.connector,
            "query_test",
            &request_id,
            &input.tls_mode,
            &input.name,
            OperationLimits::default()
                .with_max_rows(telemetry_limits.max_rows)
                .with_max_bytes(telemetry_limits.max_bytes)
                .with_connect_timeout(input.connect_timeout)
                .with_operation_timeout(Duration::from_secs(telemetry_limits.timeout_secs)),
        )?;
        let limits = match limits {
            Ok(limits) => limits,
            Err(error) => {
                let error = error.with_context("query_test", &request_id, &input.name);
                tracker.failed(&error);
                return Err(error);
            }
        };
        let operation_cancellation = cancellation.child_token();
        let operation = Box::pin(self.test_query_inner(
            &input,
            request,
            limits,
            &request_id,
            operation_cancellation.clone(),
        ));
        let result = run_with_hard_timeout(
            Duration::from_secs(limits.timeout_secs),
            operation_cancellation,
            operation,
        )
        .await;
        match result {
            Ok(response) => {
                tracker.succeeded(OperationMetrics::collection(
                    response.rows_read,
                    response.bytes_read,
                    false,
                ))?;
                Ok(response)
            }
            Err(error) => {
                let error = error.with_context("query_test", &request_id, &input.name);
                tracker.failed(&error);
                Err(error)
            }
        }
    }

    fn validate_input_inner(
        &self,
        input: &InputConfig,
        request_id: &str,
    ) -> InputValidationResponse {
        let mut issues = Vec::new();
        let query = load_configured_query(input);
        let cursor = match &input.mode {
            CollectionMode::Batch => None,
            CollectionMode::Rising(rising) => Some(TimestampIdCursorSpec {
                timestamp_field: rising.timestamp_field.clone(),
                id_field: rising.id_field.clone(),
                overlap: rising.overlap,
                null_policy: CursorNullPolicy::Reject,
            }),
        };
        match Self::connection_config(input) {
            Ok(connection) => match self.connectors.validate(&ValidationRequest {
                connection,
                query: query
                    .as_ref()
                    .ok()
                    .map(|query| QueryText::new(query.clone())),
                max_rows: Some(input.max_rows),
                cursor,
            }) {
                Ok(report) => issues.extend(report.issues),
                Err(error) => {
                    let error = ControlError::from_connector(&error);
                    issues.push(issue_from_error(
                        &error,
                        "connector",
                        "configured connector is unavailable",
                    ));
                }
            },
            Err(error) => issues.push(issue_from_error(
                &error,
                "tls_ca_file",
                "configured database TLS material could not be loaded",
            )),
        }

        match query {
            Ok(_) => {}
            Err(error) => issues.push(issue_from_error(
                &error,
                "query",
                "configured database query could not be loaded",
            )),
        }

        if let Err(error) = self.resolve_secret(input) {
            issues.push(issue_from_error(
                &error,
                "secret_ref",
                "configured protected secret could not be resolved",
            ));
        }

        InputValidationResponse {
            schema_version: CONTROL_SCHEMA_VERSION,
            request_id: request_id.to_owned(),
            input: input.name.clone(),
            connector: input.connector.clone(),
            valid: issues.is_empty(),
            issues,
        }
    }

    async fn probe_input_inner(
        &self,
        input: &InputConfig,
        request_id: &str,
        cancellation: CancellationToken,
    ) -> Result<InputProbeResponse, ControlError> {
        let connection = Self::connection_config(input)?;
        let secret = self.resolve_secret(input)?;
        let report = self
            .connectors
            .probe(
                ProbeRequest {
                    request_id: request_id.to_owned(),
                    connection,
                },
                &secret,
                cancellation,
            )
            .await
            .map_err(|error| ControlError::from_connector(&error))?;
        Ok(InputProbeResponse {
            schema_version: CONTROL_SCHEMA_VERSION,
            request_id: request_id.to_owned(),
            input: input.name.clone(),
            connector: report.connector_id,
            database_product: report.database_product,
            server_version: report.server_version,
            server_version_number: report.server_version_number,
            endpoint: report.endpoint,
            tls_mode: report.tls_mode,
        })
    }

    async fn test_query_inner(
        &self,
        input: &InputConfig,
        request: QueryTestRequest,
        limits: QueryTestLimits,
        request_id: &str,
        cancellation: CancellationToken,
    ) -> Result<QueryTestResponse, ControlError> {
        let query = self.load_ad_hoc_query(input, request.query)?;
        let connection = Self::connection_config(input)?;
        let secret = self.resolve_secret(input)?;
        let connector_request = JsonCollectionRequest {
            request_id: request_id.to_owned(),
            connection,
            query: QueryText::new(query),
            max_rows: limits.max_rows,
            max_bytes: limits.max_bytes,
            timeout: Duration::from_secs(limits.timeout_secs),
            cursor: None,
        };
        let (line_tx, line_rx) = mpsc::channel(ROW_CHANNEL_CAPACITY);
        let collect =
            self.connectors
                .collect_json_rows(connector_request, &secret, line_tx, cancellation);
        let receive = receive_rows(line_rx, limits.max_rows, limits.max_bytes);
        let (collection, rows) = tokio::join!(collect, receive);
        let rows = rows?;
        let collection = collection.map_err(|error| ControlError::from_connector(&error))?;
        if collection.rows_read != rows.values.len() as u64
            || collection.bytes_read != rows.bytes_read
        {
            return Err(ControlError::new(
                "DBX-RS-CONTROL-0008",
                "internal",
                "query_result",
                "query-test result accounting did not match the response",
                false,
                false,
            ));
        }
        Ok(QueryTestResponse {
            schema_version: CONTROL_SCHEMA_VERSION,
            request_id: request_id.to_owned(),
            input: input.name.clone(),
            connector: input.connector.clone(),
            limits,
            rows_read: collection.rows_read,
            bytes_read: collection.bytes_read,
            rows: rows.values,
        })
    }

    fn input(&self, name: &str) -> Result<&InputConfig, ControlError> {
        self.config
            .inputs
            .iter()
            .find(|input| input.name == name)
            .ok_or_else(|| {
                ControlError::new(
                    "DBX-RS-CONTROL-0001",
                    "configuration",
                    "input_lookup",
                    "configured input was not found",
                    false,
                    true,
                )
                .with_operation("input_lookup")
            })
    }

    fn connection_config(input: &InputConfig) -> Result<ConnectionConfig, ControlError> {
        let tls_ca_pem = input
            .tls_ca_file
            .as_deref()
            .map(|path| read_limited(path, MAX_TLS_CA_BYTES))
            .transpose()
            .map_err(|error| ControlError::from_secure(&error))?;
        let tls_mode = input.tls_mode.parse::<TlsMode>().map_err(|_| {
            ControlError::new(
                "DBX-RS-CONTROL-0002",
                "configuration",
                "connection_config",
                "input TLS mode is invalid",
                false,
                true,
            )
        })?;
        Ok(ConnectionConfig {
            connector_id: input.connector.clone(),
            host: input.host.clone(),
            port: input.port,
            database: input.database.clone(),
            username: input.username.clone(),
            tls_mode,
            tls_server_name: input.tls_server_name.clone(),
            tls_ca_pem,
            connect_timeout: input.connect_timeout,
            probe_timeout: input.probe_timeout,
        })
    }

    fn resolve_secret(
        &self,
        input: &InputConfig,
    ) -> Result<dbx_rs_connector_sdk::ResolvedSecret, ControlError> {
        let store = SecretStore::open_existing(
            &self.config.generic.paths.master_key_file,
            &self.config.generic.paths.secret_dir,
        )
        .map_err(|error| ControlError::from_secure(&error))?;
        store
            .resolve(&input.secret_ref)
            .map_err(|error| ControlError::from_secure(&error))
    }

    fn load_ad_hoc_query(
        &self,
        input: &InputConfig,
        query: AdHocQuery,
    ) -> Result<String, ControlError> {
        match query {
            AdHocQuery::Inline { sql } => {
                if sql.len() as u64 > MAX_QUERY_BYTES {
                    return Err(ControlError::new(
                        "DBX-RS-CONTROL-0003",
                        "configuration",
                        "query_input",
                        "inline query exceeds the size limit",
                        false,
                        true,
                    ));
                }
                Ok(sql)
            }
            AdHocQuery::File { path } => {
                let root = self
                    .app_home
                    .join("queries")
                    .join(query_namespace(&input.connector));
                let path = approved_query_file(&root, &path)?;
                query_from_bytes(
                    read_limited(&path, MAX_QUERY_BYTES)
                        .map_err(|error| ControlError::from_secure(&error))?,
                )
            }
        }
    }
}

fn load_configured_query(input: &InputConfig) -> Result<String, ControlError> {
    match &input.query {
        QuerySource::Inline(query) => Ok(query.clone()),
        QuerySource::File(path) => query_from_bytes(
            read_limited(path, MAX_QUERY_BYTES)
                .map_err(|error| ControlError::from_secure(&error))?,
        ),
    }
}

fn query_from_bytes(bytes: Vec<u8>) -> Result<String, ControlError> {
    match String::from_utf8(bytes) {
        Ok(query) => Ok(query),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.fill(0);
            Err(ControlError::new(
                "DBX-RS-CONTROL-0005",
                "configuration",
                "query_input",
                "query file is not valid UTF-8",
                false,
                true,
            ))
        }
    }
}

fn approved_query_file(root: &Path, path: &Path) -> Result<PathBuf, ControlError> {
    if !path.is_absolute() || has_parent_component(path) || path == root || !path.starts_with(root)
    {
        return Err(query_file_outside_root());
    }
    let canonical_root = fs::canonicalize(root).map_err(|_| query_file_unavailable())?;
    let canonical_path = fs::canonicalize(path).map_err(|_| query_file_unavailable())?;
    if canonical_path == canonical_root || !canonical_path.starts_with(canonical_root) {
        return Err(query_file_outside_root());
    }
    Ok(path.to_path_buf())
}

fn query_file_outside_root() -> ControlError {
    ControlError::new(
        "DBX-RS-CONTROL-0004",
        "configuration",
        "query_input",
        "query-test file must remain in the connector query directory",
        false,
        true,
    )
}

fn query_file_unavailable() -> ControlError {
    ControlError::new(
        "DBX-RS-CONTROL-0011",
        "configuration",
        "query_input",
        "query-test file could not be resolved",
        false,
        true,
    )
}

fn control_operation_timeout() -> ControlError {
    ControlError::new(
        "DBX-RS-CONTROL-0014",
        "timeout",
        "operation_timeout",
        "control operation exceeded its hard timeout",
        true,
        false,
    )
}

async fn run_with_hard_timeout<T, F>(
    hard_timeout: Duration,
    cancellation: CancellationToken,
    operation: F,
) -> Result<T, ControlError>
where
    F: Future<Output = Result<T, ControlError>>,
{
    run_with_hard_timeout_and_grace(
        hard_timeout,
        CONTROL_CANCELLATION_GRACE,
        cancellation,
        operation,
    )
    .await
}

async fn run_with_hard_timeout_and_grace<T, F>(
    hard_timeout: Duration,
    cancellation_grace: Duration,
    cancellation: CancellationToken,
    operation: F,
) -> Result<T, ControlError>
where
    F: Future<Output = Result<T, ControlError>>,
{
    tokio::pin!(operation);
    // Time out a pinned borrow so cancellation cleanup can still poll the owned operation.
    if let Ok(result) = timeout(hard_timeout, &mut operation).await {
        return result;
    }

    cancellation.cancel();
    let _cleanup_result = timeout(cancellation_grace, &mut operation).await;
    Err(control_operation_timeout())
}

fn query_test_caps(input: &InputConfig) -> QueryTestLimits {
    QueryTestLimits {
        max_rows: input.max_rows.min(MAX_QUERY_TEST_ROWS),
        max_bytes: input.max_bytes.min(MAX_QUERY_TEST_BYTES),
        timeout_secs: input
            .query_timeout
            .as_secs()
            .min(MAX_QUERY_TEST_TIMEOUT_SECS),
    }
}

fn resolve_limits(
    input: &InputConfig,
    overrides: QueryTestLimitOverrides,
) -> Result<QueryTestLimits, ControlError> {
    let caps = query_test_caps(input);
    Ok(QueryTestLimits {
        max_rows: resolve_limit(overrides.max_rows, caps.max_rows, "max_rows")?,
        max_bytes: resolve_limit(overrides.max_bytes, caps.max_bytes, "max_bytes")?,
        timeout_secs: resolve_limit(overrides.timeout_secs, caps.timeout_secs, "timeout_secs")?,
    })
}

fn resolve_limit(value: Option<u64>, cap: u64, field: &str) -> Result<u64, ControlError> {
    match value {
        None => Ok(cap),
        Some(value) if (1..=cap).contains(&value) => Ok(value),
        Some(_) => Err(ControlError::new(
            "DBX-RS-CONTROL-0006",
            "configuration",
            "query_limits",
            format!("query-test {field} is outside the permitted range"),
            false,
            true,
        )),
    }
}

async fn receive_rows(
    mut receiver: mpsc::Receiver<JsonRow>,
    max_rows: u64,
    max_bytes: u64,
) -> Result<ReceivedRows, ControlError> {
    let capacity = usize::try_from(max_rows).map_err(|_| {
        ControlError::new(
            "DBX-RS-CONTROL-0007",
            "internal",
            "query_result",
            "query-test row limit is invalid for this platform",
            false,
            false,
        )
    })?;
    let mut rows = Vec::with_capacity(capacity);
    let mut bytes_read = 0_u64;
    while let Some(line) = receiver.recv().await {
        let (line, _cursor) = line.into_parts();
        if rows.len() >= capacity {
            return Err(ControlError::new(
                "DBX-RS-CONTROL-0012",
                "query",
                "query_result",
                "query-test response exceeded the row limit",
                false,
                false,
            ));
        }
        let next_bytes = bytes_read.saturating_add(line.len() as u64 + 1);
        if next_bytes > max_bytes {
            return Err(ControlError::new(
                "DBX-RS-CONTROL-0013",
                "query",
                "query_result",
                "query-test response exceeded the byte limit",
                false,
                false,
            ));
        }
        let row = serde_json::from_slice(&line).map_err(|_| {
            ControlError::new(
                "DBX-RS-CONTROL-0009",
                "conversion",
                "query_result",
                "connector returned invalid JSON row data",
                false,
                false,
            )
        })?;
        rows.push(row);
        bytes_read = next_bytes;
    }
    Ok(ReceivedRows {
        values: rows,
        bytes_read,
    })
}

struct ReceivedRows {
    values: Vec<serde_json::Value>,
    bytes_read: u64,
}

fn issue_from_error(error: &ControlError, field: &str, message: &str) -> ValidationIssue {
    ValidationIssue {
        code: error.code().to_owned(),
        field: field.to_owned(),
        message: message.to_owned(),
        severity: ValidationSeverity::Error,
    }
}

fn query_namespace(connector: &str) -> &'static str {
    match connector {
        "mariadb" => "mariadb",
        "mssql" => "mssql",
        "mysql" => "mysql",
        "oracle" => "oracle",
        "postgres" => "psql",
        _ => "unsupported",
    }
}

fn has_parent_component(path: &Path) -> bool {
    path.components()
        .any(|component| component == Component::ParentDir)
}

fn request_id() -> Result<String, ControlError> {
    let mut random = [0_u8; 16];
    SystemRandom::new().fill(&mut random).map_err(|_| {
        ControlError::new(
            "DBX-RS-CONTROL-0010",
            "internal",
            "request_id",
            "secure request ID generation failed",
            false,
            false,
        )
    })?;
    random[6] = (random[6] & 0x0f) | 0x40;
    random[8] = (random[8] & 0x3f) | 0x80;
    Ok(format!(
        "{}-{}-{}-{}-{}",
        hex(&random[0..4]),
        hex(&random[4..6]),
        hex(&random[6..8]),
        hex(&random[8..10]),
        hex(&random[10..16])
    ))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

struct ControlTracker {
    telemetry: NdjsonTelemetry,
    context: OperationContext,
    started: Instant,
    operation: String,
    request_id: String,
    input: String,
}

impl ControlTracker {
    #[allow(clippy::too_many_arguments)]
    fn start(
        telemetry: &NdjsonTelemetry,
        connector: &str,
        operation: &str,
        request_id: &str,
        tls_mode: &str,
        input: &str,
        limits: OperationLimits,
    ) -> Result<Self, ControlError> {
        let context = OperationContext::new(
            "dbx_rs_control",
            connector,
            operation,
            request_id,
            env!("CARGO_PKG_VERSION"),
            tls_mode,
        )
        .and_then(|context| context.with_input(input))
        .map_err(|_| {
            telemetry_error("telemetry_context").with_context(operation, request_id, input)
        })?;
        telemetry.operation_started(&context, limits).map_err(|_| {
            telemetry_error("telemetry_start").with_context(operation, request_id, input)
        })?;
        Ok(Self {
            telemetry: telemetry.clone(),
            context,
            started: Instant::now(),
            operation: operation.to_owned(),
            request_id: request_id.to_owned(),
            input: input.to_owned(),
        })
    }

    fn succeeded(self, metrics: OperationMetrics) -> Result<(), ControlError> {
        self.telemetry
            .operation_succeeded(&self.context, self.started.elapsed(), metrics)
            .map_err(|_| {
                telemetry_error("telemetry_success").with_context(
                    &self.operation,
                    &self.request_id,
                    &self.input,
                )
            })
    }

    fn failed(&self, error: &ControlError) {
        let failure = OperationFailure::new(
            error.code(),
            error.class(),
            error.stage(),
            error.retryable(),
            error.configuration_error(),
            error.sql_state(),
        );
        if let Ok(failure) = failure {
            let _ignored =
                self.telemetry
                    .operation_failed(&self.context, self.started.elapsed(), &failure);
        }
    }
}

fn telemetry_error(stage: &'static str) -> ControlError {
    ControlError::new(
        "DBX-RS-CONTROL-TRACE-0001",
        "io",
        stage,
        "control operation telemetry failed",
        true,
        false,
    )
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use super::*;

    struct DropMarker(Arc<AtomicBool>);

    impl Drop for DropMarker {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn input() -> InputConfig {
        InputConfig {
            name: "warehouse".into(),
            disabled: false,
            mode: dbx_rs_config::CollectionMode::Batch,
            connector: "postgres".into(),
            interval: Duration::from_mins(1),
            host: "database.example".into(),
            port: 5432,
            database: "telemetry".into(),
            username: "reader".into(),
            secret_ref: "local:warehouse".into(),
            tls_mode: "disable".into(),
            tls_server_name: None,
            tls_ca_file: None,
            query: QuerySource::Inline("SELECT 1".into()),
            connect_timeout: Duration::from_secs(10),
            probe_timeout: Duration::from_secs(10),
            max_rows: 1_000,
            max_bytes: 2_000_000,
            query_timeout: Duration::from_mins(1),
            index: "main".into(),
            sourcetype: "dbx_rs:database:row".into(),
            source: "dbx_rs:test".into(),
        }
    }

    #[test]
    fn query_test_caps_are_the_minimum_of_input_and_control_limits() {
        assert_eq!(
            query_test_caps(&input()),
            QueryTestLimits {
                max_rows: MAX_QUERY_TEST_ROWS,
                max_bytes: MAX_QUERY_TEST_BYTES,
                timeout_secs: MAX_QUERY_TEST_TIMEOUT_SECS,
            }
        );
    }

    #[test]
    fn query_test_overrides_can_only_lower_effective_limits() {
        let limits = resolve_limits(
            &input(),
            QueryTestLimitOverrides {
                max_rows: Some(5),
                max_bytes: Some(4_096),
                timeout_secs: Some(2),
            },
        )
        .expect("lower limits must be accepted");

        assert_eq!(limits.max_rows, 5);
        assert_eq!(limits.max_bytes, 4_096);
        assert_eq!(limits.timeout_secs, 2);
    }

    #[tokio::test]
    async fn response_receiver_enforces_row_limit_independently() {
        let (sender, receiver) = mpsc::channel(2);
        sender
            .send(JsonRow::new(b"{\"row\":1}".to_vec(), None))
            .await
            .expect("send");
        sender
            .send(JsonRow::new(b"{\"row\":2}".to_vec(), None))
            .await
            .expect("send");
        drop(sender);

        let error = receive_rows(receiver, 1, 1_024)
            .await
            .err()
            .expect("second row must exceed the limit");

        assert_eq!(error.code(), "DBX-RS-CONTROL-0012");
    }

    #[tokio::test]
    async fn response_receiver_enforces_byte_limit_independently() {
        let (sender, receiver) = mpsc::channel(1);
        sender
            .send(JsonRow::new(b"{}".to_vec(), None))
            .await
            .expect("send");
        drop(sender);

        let error = receive_rows(receiver, 1, 2)
            .await
            .err()
            .expect("JSON line plus delimiter must exceed the limit");

        assert_eq!(error.code(), "DBX-RS-CONTROL-0013");
    }

    #[tokio::test]
    async fn hard_timeout_cancels_and_awaits_operation_cleanup() {
        let cancellation = CancellationToken::new();
        let operation_cancellation = cancellation.clone();
        let cancellation_observed = Arc::new(AtomicBool::new(false));
        let operation_observed = Arc::clone(&cancellation_observed);
        let operation = async move {
            operation_cancellation.cancelled().await;
            operation_observed.store(true, Ordering::SeqCst);
            Ok::<(), ControlError>(())
        };

        let error = run_with_hard_timeout_and_grace(
            Duration::from_millis(5),
            Duration::from_millis(100),
            cancellation,
            operation,
        )
        .await
        .expect_err("the hard deadline must remain the primary result");

        assert_eq!(error.code(), "DBX-RS-CONTROL-0014");
        assert!(cancellation_observed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn unresponsive_operation_is_dropped_after_cancellation_grace() {
        let cancellation = CancellationToken::new();
        let cancellation_state = cancellation.clone();
        let operation_dropped = Arc::new(AtomicBool::new(false));
        let marker = DropMarker(Arc::clone(&operation_dropped));
        let operation = async move {
            let _marker = marker;
            std::future::pending::<Result<(), ControlError>>().await
        };

        let error = run_with_hard_timeout_and_grace(
            Duration::from_millis(5),
            Duration::from_millis(5),
            cancellation,
            operation,
        )
        .await
        .expect_err("an unresponsive operation must time out");

        assert_eq!(error.code(), "DBX-RS-CONTROL-0014");
        assert!(cancellation_state.is_cancelled());
        assert!(operation_dropped.load(Ordering::SeqCst));
    }
}
