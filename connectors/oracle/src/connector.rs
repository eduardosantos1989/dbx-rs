use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use dbx_rs_connector_sdk::{
    ArrowIpcBatch, AuthenticationMethod, CONNECTOR_CONTRACT_VERSION, ConnectionConfig, Connector,
    ConnectorCapability, ConnectorDescriptor, ConnectorError, ConnectorFuture,
    ConnectorSupportTier, ErrorClass, ExecuteRequest, ExecutionResult, PrepareRequest,
    PreparedQuery, ProbeReport, ProbeRequest, ResolvedSecret, TlsMode, ValidationIssue,
    ValidationReport, ValidationRequest, ValidationSeverity,
};
use oracle_rs::TlsConfig;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

mod driver;
mod sql;
mod typed;

use driver::{DriverLimits, OracleDriver, OracleSession, RealOracleDriver};
use sql::normalize_query;

pub struct OracleConnector {
    driver: Arc<dyn OracleDriver>,
}

impl OracleConnector {
    pub const CONNECTOR_ID: &'static str = "oracle";
    pub(super) const MAX_COLLECTION_ROWS: u64 = 100_000;
    pub(super) const MAX_OPERATION_TIMEOUT: Duration = Duration::from_hours(24);
    pub(super) const MAX_QUERY_BYTES: usize = 1024 * 1024;
    pub(super) const MAX_TLS_CA_BYTES: usize = 1024 * 1024;
    pub(super) const MAX_REQUEST_ID_BYTES: usize = 256;
    pub(super) const MAX_SECRET_BYTES: usize = 1024;
    const MAX_SERVICE_BYTES: usize = 1024;
    const MAX_USERNAME_BYTES: usize = 1024;

    #[must_use]
    pub fn new() -> Self {
        Self {
            driver: Arc::new(RealOracleDriver),
        }
    }

    #[must_use]
    pub fn descriptor(&self) -> ConnectorDescriptor {
        ConnectorDescriptor {
            contract_version: CONNECTOR_CONTRACT_VERSION,
            connector_id: Self::CONNECTOR_ID.into(),
            connector_version: env!("CARGO_PKG_VERSION").into(),
            database_families: vec!["oracle".into()],
            capabilities: vec![
                ConnectorCapability::ValidateConfiguration,
                ConnectorCapability::ProbeConnection,
                ConnectorCapability::PrepareQuery,
                ConnectorCapability::ExecuteQuery,
            ],
            authentication_methods: vec![AuthenticationMethod::Password],
            build_id: format!("{}-{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
            support_tier: ConnectorSupportTier::ExperimentalNative,
        }
    }

    #[must_use]
    pub fn validate_connection(config: &ConnectionConfig) -> ValidationReport {
        let mut issues = Vec::new();
        Self::validate_endpoint_and_identity(config, &mut issues);
        issues.extend(timeout_issue(
            config.connect_timeout,
            "connect_timeout",
            "DBX-RS-ORA-CFG-0006",
            "DBX-RS-ORA-CFG-0012",
        ));
        issues.extend(timeout_issue(
            config.probe_timeout,
            "probe_timeout",
            "DBX-RS-ORA-CFG-0007",
            "DBX-RS-ORA-CFG-0013",
        ));
        Self::validate_tls(config, &mut issues);
        ValidationReport { issues }
    }

    fn validate_endpoint_and_identity(
        config: &ConnectionConfig,
        issues: &mut Vec<ValidationIssue>,
    ) {
        if config.connector_id != Self::CONNECTOR_ID {
            issues.push(validation_error(
                "DBX-RS-ORA-CFG-0001",
                "connector_id",
                "connector_id must be oracle",
            ));
        }
        if config.host.trim().is_empty() {
            issues.push(validation_error(
                "DBX-RS-ORA-CFG-0002",
                "host",
                "host is required",
            ));
        } else if !valid_tls_server_name(&config.host) {
            issues.push(validation_error(
                "DBX-RS-ORA-CFG-0044",
                "host",
                "host must be a valid bounded DNS name or IP address",
            ));
        }
        if config.port == 0 {
            issues.push(validation_error(
                "DBX-RS-ORA-CFG-0003",
                "port",
                "port must be greater than zero",
            ));
        }
        if config.database.trim().is_empty() {
            issues.push(validation_error(
                "DBX-RS-ORA-CFG-0004",
                "database",
                "database must contain an Oracle service name",
            ));
        } else if !valid_descriptor_value(&config.database, Self::MAX_SERVICE_BYTES) {
            issues.push(validation_error(
                "DBX-RS-ORA-CFG-0045",
                "database",
                "Oracle service name contains unsupported or unbounded text",
            ));
        }
        if config.username.trim().is_empty() {
            issues.push(validation_error(
                "DBX-RS-ORA-CFG-0005",
                "username",
                "username is required",
            ));
        } else if config.username.len() > Self::MAX_USERNAME_BYTES
            || config.username.chars().any(char::is_control)
        {
            issues.push(validation_error(
                "DBX-RS-ORA-CFG-0046",
                "username",
                "Oracle username contains unsupported or unbounded text",
            ));
        }
    }

    fn validate_tls(config: &ConnectionConfig, issues: &mut Vec<ValidationIssue>) {
        match config.tls_mode {
            TlsMode::Disable => {
                if config.tls_server_name.is_some() || config.tls_ca_pem.is_some() {
                    issues.push(validation_error(
                        "DBX-RS-ORA-CFG-0009",
                        "tls_mode",
                        "TLS server name and CA settings require tls_mode=verify-full",
                    ));
                }
            }
            TlsMode::VerifyFull => {
                let server_name = config
                    .tls_server_name
                    .as_deref()
                    .unwrap_or(config.host.as_str());
                if server_name.trim().is_empty() || !valid_tls_server_name(server_name) {
                    issues.push(validation_error(
                        "DBX-RS-ORA-CFG-0010",
                        if config.tls_server_name.is_some() {
                            "tls_server_name"
                        } else {
                            "host"
                        },
                        "TLS server name must be a valid DNS name or IP address",
                    ));
                }
                if let Some(pem) = config.tls_ca_pem.as_deref() {
                    if pem.len() > Self::MAX_TLS_CA_BYTES {
                        issues.push(validation_error(
                            "DBX-RS-ORA-CFG-0047",
                            "tls_ca_pem",
                            "TLS CA data exceeds the connector hard limit",
                        ));
                    } else if !valid_ca_pem(pem) {
                        issues.push(validation_error(
                            "DBX-RS-ORA-CFG-0011",
                            "tls_ca_pem",
                            "TLS CA data must contain at least one usable PEM certificate",
                        ));
                    }
                }
            }
            TlsMode::Require | TlsMode::VerifyCa => {
                issues.push(validation_error(
                    "DBX-RS-ORA-CFG-0008",
                    "tls_mode",
                    "Oracle TLS modes without hostname verification are unsupported",
                ));
            }
        }
    }

    /// Validates one bounded Oracle read query without opening a connection.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when the query is not one bounded `SELECT`/`WITH` statement.
    pub fn validate_query(query: &str, max_rows: u64) -> Result<(), ConnectorError> {
        normalize_query(query, max_rows).map(|_| ())
    }

    async fn probe_inner(
        &self,
        request: ProbeRequest,
        secret: &ResolvedSecret,
        cancellation: CancellationToken,
    ) -> Result<ProbeReport, ConnectorError> {
        if !valid_request_id(&request.request_id) {
            return Err(configuration_error(
                "DBX-RS-ORA-CFG-0040",
                "Oracle probe request ID is invalid or exceeds its hard limit",
            ));
        }
        Self::validate_operation(&request.connection, secret)?;
        let max_value_bytes = default_max_value_bytes()?;
        let session = self
            .connect_session(
                &request.connection,
                secret,
                DriverLimits {
                    max_rows_per_response: 1,
                    max_value_bytes,
                },
                &cancellation,
            )
            .await?;
        let operation = session.server_info();
        let result = run_session_operation(
            Arc::clone(&session),
            request.connection.probe_timeout,
            &cancellation,
            operation,
            "DBX-RS-ORA-CANCELLED-0002",
            "DBX-RS-ORA-PROBE-0001",
            "Oracle probe timed out",
        )
        .await;
        session.abort().await;
        let info = result?;
        Ok(ProbeReport {
            connector_id: Self::CONNECTOR_ID.into(),
            database_product: "Oracle Database".into(),
            server_version: if info.version.is_empty() {
                "unknown".into()
            } else {
                info.version
            },
            server_version_number: None,
            endpoint: format!(
                "{}:{}/{}",
                request.connection.host, request.connection.port, request.connection.database
            ),
            tls_mode: request.connection.tls_mode,
        })
    }

    async fn prepare_inner(
        &self,
        request: PrepareRequest,
        secret: &ResolvedSecret,
        cancellation: CancellationToken,
    ) -> Result<PreparedQuery, ConnectorError> {
        Self::validate_operation(&request.connection, secret)?;
        typed::validate_prepare_request(&request)?;
        let normalized = normalize_query(request.query.as_str(), request.max_rows)?;
        let max_value_bytes = default_max_value_bytes()?;
        let session = self
            .connect_session(
                &request.connection,
                secret,
                DriverLimits {
                    max_rows_per_response: 1,
                    max_value_bytes,
                },
                &cancellation,
            )
            .await?;
        let operation = typed::prepare_schema(session.as_ref(), &normalized.sql);
        let result = run_session_operation(
            Arc::clone(&session),
            request.timeout,
            &cancellation,
            operation,
            "DBX-RS-ORA-CANCELLED-0020",
            "DBX-RS-ORA-QUERY-0020",
            "Oracle prepare timed out",
        )
        .await;
        session.abort().await;
        Ok(PreparedQuery {
            request_id: request.request_id,
            connector_id: Self::CONNECTOR_ID.into(),
            schema: result?,
        })
    }

    async fn execute_inner(
        &self,
        request: ExecuteRequest,
        secret: &ResolvedSecret,
        batch_tx: mpsc::Sender<ArrowIpcBatch>,
        cancellation: CancellationToken,
    ) -> Result<ExecutionResult, ConnectorError> {
        Self::validate_operation(&request.connection, secret)?;
        typed::validate_execute_request(&request)?;
        let normalized = normalize_query(request.query.as_str(), request.limits.max_rows)?;
        let max_value_bytes = usize::try_from(request.limits.max_batch_bytes).map_err(|_| {
            configuration_error(
                "DBX-RS-ORA-CFG-0028",
                "Oracle batch IPC byte limit is invalid for this platform",
            )
        })?;
        let session = self
            .connect_session(
                &request.connection,
                secret,
                DriverLimits {
                    max_rows_per_response: request.limits.max_batch_rows as usize,
                    max_value_bytes,
                },
                &cancellation,
            )
            .await?;
        let timeout = request.limits.timeout;
        let operation = typed::execute_query(session.as_ref(), request, normalized.sql, batch_tx);
        let result = run_session_operation(
            Arc::clone(&session),
            timeout,
            &cancellation,
            operation,
            "DBX-RS-ORA-CANCELLED-0021",
            "DBX-RS-ORA-QUERY-0021",
            "Oracle query timed out",
        )
        .await;
        session.abort().await;
        result
    }

    fn validate_operation(
        config: &ConnectionConfig,
        secret: &ResolvedSecret,
    ) -> Result<(), ConnectorError> {
        let report = Self::validate_connection(config);
        if !report.is_valid() {
            return Err(ConnectorError::new(
                report
                    .issues
                    .first()
                    .map_or("DBX-RS-ORA-CFG-0099", |issue| issue.code.as_str()),
                ErrorClass::Configuration,
                "Oracle connection configuration is invalid",
                false,
                true,
            ));
        }
        if secret.is_empty() {
            return Err(configuration_error(
                "DBX-RS-ORA-AUTH-0001",
                "Oracle password is empty",
            ));
        }
        if secret.expose_secret().len() > Self::MAX_SECRET_BYTES {
            return Err(configuration_error(
                "DBX-RS-ORA-CFG-0043",
                "Oracle password exceeds the connector hard limit",
            ));
        }
        Ok(())
    }

    async fn connect_session(
        &self,
        config: &ConnectionConfig,
        secret: &ResolvedSecret,
        limits: DriverLimits,
        cancellation: &CancellationToken,
    ) -> Result<Arc<dyn OracleSession>, ConnectorError> {
        let mut connection = self.driver.connect(config, secret, limits);
        let mut deadline = Box::pin(tokio::time::sleep(config.connect_timeout));
        let outcome = tokio::select! {
            () = cancellation.cancelled() => ConnectOutcome::Cancelled,
            () = &mut deadline => ConnectOutcome::TimedOut,
            result = &mut connection => ConnectOutcome::Completed(result),
        };
        drop(connection);
        match outcome {
            ConnectOutcome::Completed(result) => result,
            ConnectOutcome::Cancelled => {
                Err(ConnectorError::cancelled("DBX-RS-ORA-CANCELLED-0001"))
            }
            ConnectOutcome::TimedOut => Err(ConnectorError::new(
                "DBX-RS-ORA-CONNECT-0004",
                ErrorClass::Timeout,
                "Oracle connection or authentication timed out",
                true,
                false,
            )),
        }
    }
}

impl Default for OracleConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl Connector for OracleConnector {
    fn descriptor(&self) -> ConnectorDescriptor {
        OracleConnector::descriptor(self)
    }

    fn validate(&self, request: &ValidationRequest) -> ValidationReport {
        let mut report = Self::validate_connection(&request.connection);
        if request.cursor.is_some() {
            report.issues.push(validation_error(
                "DBX-RS-ORA-CFG-0030",
                "cursor",
                "Oracle cursor collection is not enabled for the experimental connector",
            ));
        }
        if let Some(query) = request.query.as_ref() {
            match request.max_rows {
                Some(max_rows) => {
                    if let Err(error) = Self::validate_query(query.as_str(), max_rows) {
                        report.issues.push(ValidationIssue {
                            code: error.code().to_owned(),
                            field: "query".into(),
                            message: "configured Oracle query is invalid".into(),
                            severity: ValidationSeverity::Error,
                        });
                    }
                }
                None => report.issues.push(validation_error(
                    "DBX-RS-ORA-CFG-0041",
                    "max_rows",
                    "max_rows is required when an Oracle query is validated",
                )),
            }
        }
        report
    }

    fn probe<'a>(
        &'a self,
        request: ProbeRequest,
        secret: &'a ResolvedSecret,
        cancellation: CancellationToken,
    ) -> ConnectorFuture<'a, ProbeReport> {
        Box::pin(self.probe_inner(request, secret, cancellation))
    }

    fn prepare<'a>(
        &'a self,
        request: PrepareRequest,
        secret: &'a ResolvedSecret,
        cancellation: CancellationToken,
    ) -> ConnectorFuture<'a, PreparedQuery> {
        Box::pin(self.prepare_inner(request, secret, cancellation))
    }

    fn execute<'a>(
        &'a self,
        request: ExecuteRequest,
        secret: &'a ResolvedSecret,
        batch_tx: mpsc::Sender<ArrowIpcBatch>,
        cancellation: CancellationToken,
    ) -> ConnectorFuture<'a, ExecutionResult> {
        Box::pin(self.execute_inner(request, secret, batch_tx, cancellation))
    }
}

enum ConnectOutcome {
    Completed(Result<Arc<dyn OracleSession>, ConnectorError>),
    Cancelled,
    TimedOut,
}

enum SessionOutcome<T> {
    Completed(Result<T, ConnectorError>),
    Cancelled,
    TimedOut,
}

#[allow(clippy::too_many_arguments)]
async fn run_session_operation<T, F>(
    session: Arc<dyn OracleSession>,
    timeout: Duration,
    cancellation: &CancellationToken,
    operation: F,
    cancellation_code: &'static str,
    timeout_code: &'static str,
    timeout_message: &'static str,
) -> Result<T, ConnectorError>
where
    F: Future<Output = Result<T, ConnectorError>> + Send,
{
    let mut operation = Box::pin(operation);
    let mut deadline = Box::pin(tokio::time::sleep(timeout));
    let outcome = tokio::select! {
        () = cancellation.cancelled() => SessionOutcome::Cancelled,
        () = &mut deadline => SessionOutcome::TimedOut,
        result = &mut operation => SessionOutcome::Completed(result),
    };
    drop(operation);
    match outcome {
        SessionOutcome::Completed(result) => result,
        SessionOutcome::Cancelled => {
            session.abort().await;
            Err(ConnectorError::cancelled(cancellation_code))
        }
        SessionOutcome::TimedOut => {
            session.abort().await;
            Err(ConnectorError::new(
                timeout_code,
                ErrorClass::Timeout,
                timeout_message,
                true,
                false,
            ))
        }
    }
}

fn valid_ca_pem(pem: &[u8]) -> bool {
    TlsConfig::new()
        .with_ca_pem(pem.to_vec())
        .build_client_config()
        .is_ok()
}

fn valid_tls_server_name(server_name: &str) -> bool {
    TlsConfig::new()
        .with_server_name(server_name)
        .build_client_config()
        .is_ok()
}

fn valid_descriptor_value(value: &str, maximum_bytes: usize) -> bool {
    value.len() <= maximum_bytes
        && value.trim() == value
        && value.chars().all(|character| {
            !character.is_control()
                && !character.is_whitespace()
                && !matches!(character, '(' | ')' | '=')
        })
}

pub(super) fn valid_request_id(request_id: &str) -> bool {
    !request_id.trim().is_empty()
        && request_id.len() <= OracleConnector::MAX_REQUEST_ID_BYTES
        && !request_id.chars().any(char::is_control)
}

fn timeout_issue(
    timeout: Duration,
    field: &str,
    zero_code: &str,
    hard_limit_code: &str,
) -> Option<ValidationIssue> {
    if timeout.is_zero() {
        Some(validation_error(
            zero_code,
            field,
            "timeout must be greater than zero",
        ))
    } else if timeout > OracleConnector::MAX_OPERATION_TIMEOUT {
        Some(validation_error(
            hard_limit_code,
            field,
            "timeout exceeds the connector hard limit",
        ))
    } else {
        None
    }
}

fn validation_error(code: &str, field: &str, message: &str) -> ValidationIssue {
    ValidationIssue {
        code: code.into(),
        field: field.into(),
        message: message.into(),
        severity: ValidationSeverity::Error,
    }
}

fn configuration_error(code: &'static str, message: &'static str) -> ConnectorError {
    ConnectorError::new(code, ErrorClass::Configuration, message, false, true)
}

fn default_max_value_bytes() -> Result<usize, ConnectorError> {
    usize::try_from(typed::MAX_BATCH_IPC_BYTES).map_err(|_| {
        configuration_error(
            "DBX-RS-ORA-CFG-0028",
            "Oracle batch IPC byte limit is invalid for this platform",
        )
    })
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};

    use dbx_rs_connector_sdk::{ExecutionLimits, QueryText};
    use tokio::sync::Mutex;

    use super::driver::{
        DriverFuture, NativeColumn, NativeKind, NativePage, NativeServerInfo, NativeValue,
    };
    use super::*;

    struct FakeDriver {
        session: Arc<FakeSession>,
    }

    struct HangingDriver {
        dropped: Arc<AtomicBool>,
    }

    struct ConnectGuard(Arc<AtomicBool>);

    impl Drop for ConnectGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    impl OracleDriver for HangingDriver {
        fn connect<'a>(
            &'a self,
            _config: &'a ConnectionConfig,
            _secret: &'a ResolvedSecret,
            _limits: DriverLimits,
        ) -> DriverFuture<'a, Arc<dyn OracleSession>> {
            let dropped = Arc::clone(&self.dropped);
            Box::pin(async move {
                let _guard = ConnectGuard(dropped);
                std::future::pending().await
            })
        }
    }

    impl OracleDriver for FakeDriver {
        fn connect<'a>(
            &'a self,
            _config: &'a ConnectionConfig,
            _secret: &'a ResolvedSecret,
            _limits: DriverLimits,
        ) -> DriverFuture<'a, Arc<dyn OracleSession>> {
            let session: Arc<dyn OracleSession> = self.session.clone();
            Box::pin(async move { Ok(session) })
        }
    }

    struct FakeSession {
        columns: Vec<NativeColumn>,
        pages: Mutex<VecDeque<NativePage>>,
        hang_describe: bool,
        fail_read_only: bool,
        read_only_started: AtomicBool,
        operation_active: AtomicBool,
        abort_after_drop: AtomicBool,
        aborted: AtomicBool,
    }

    struct OperationGuard<'a>(&'a AtomicBool);

    impl Drop for OperationGuard<'_> {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }

    impl OracleSession for FakeSession {
        fn server_info(&self) -> DriverFuture<'_, NativeServerInfo> {
            Box::pin(async {
                Ok(NativeServerInfo {
                    version: "19.0.0.0.0".into(),
                })
            })
        }

        fn begin_read_only(&self) -> DriverFuture<'_, ()> {
            Box::pin(async move {
                if self.fail_read_only {
                    return Err(ConnectorError::new(
                        "TEST-READ-ONLY-FAILED",
                        ErrorClass::Query,
                        "fake Oracle read-only transaction failed",
                        false,
                        false,
                    ));
                }
                self.read_only_started.store(true, Ordering::SeqCst);
                Ok(())
            })
        }

        fn describe<'a>(&'a self, _sql: &'a str) -> DriverFuture<'a, Vec<NativeColumn>> {
            Box::pin(async move {
                if self.hang_describe {
                    self.operation_active.store(true, Ordering::SeqCst);
                    let _guard = OperationGuard(&self.operation_active);
                    std::future::pending::<()>().await;
                }
                Ok(self.columns.clone())
            })
        }

        fn query<'a>(&'a self, _sql: &'a str, _fetch_size: u32) -> DriverFuture<'a, NativePage> {
            Box::pin(async move {
                if !self.read_only_started.load(Ordering::SeqCst) {
                    return Err(ConnectorError::new(
                        "TEST-NOT-READ-ONLY",
                        ErrorClass::Internal,
                        "fake Oracle query was not protected by a read-only transaction",
                        false,
                        false,
                    ));
                }
                self.pages.lock().await.pop_front().ok_or_else(|| {
                    ConnectorError::new(
                        "TEST-NO-PAGE",
                        ErrorClass::Internal,
                        "missing fake page",
                        false,
                        false,
                    )
                })
            })
        }

        fn fetch_more(&self, _cursor_id: u16, _fetch_size: u32) -> DriverFuture<'_, NativePage> {
            self.query("", 1)
        }

        fn abort(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            Box::pin(async move {
                self.abort_after_drop.store(
                    !self.operation_active.load(Ordering::SeqCst),
                    Ordering::SeqCst,
                );
                self.aborted.store(true, Ordering::SeqCst);
            })
        }
    }

    fn config(tls_mode: TlsMode) -> ConnectionConfig {
        ConnectionConfig {
            connector_id: OracleConnector::CONNECTOR_ID.into(),
            host: "oracle.example".into(),
            port: 1521,
            database: "ORCLPDB1".into(),
            username: "reader".into(),
            tls_mode,
            tls_server_name: None,
            tls_ca_pem: None,
            connect_timeout: Duration::from_secs(5),
            probe_timeout: Duration::from_secs(5),
        }
    }

    fn number_column() -> NativeColumn {
        NativeColumn {
            name: "VALUE".into(),
            kind: NativeKind::Number {
                precision: 10,
                scale: 0,
            },
            nullable: false,
            source_type: "NUMBER(10,0)".into(),
        }
    }

    fn page(columns: &[NativeColumn], values: std::ops::Range<u64>, more: bool) -> NativePage {
        NativePage {
            columns: columns.to_vec(),
            rows: values
                .map(|value| vec![NativeValue::Number(value.to_string())])
                .collect(),
            has_more_rows: more,
            cursor_id: u16::from(more) * 7,
        }
    }

    fn connector(session: Arc<FakeSession>) -> OracleConnector {
        OracleConnector {
            driver: Arc::new(FakeDriver { session }),
        }
    }

    fn hanging_connector() -> (OracleConnector, Arc<AtomicBool>) {
        let dropped = Arc::new(AtomicBool::new(false));
        (
            OracleConnector {
                driver: Arc::new(HangingDriver {
                    dropped: Arc::clone(&dropped),
                }),
            },
            dropped,
        )
    }

    #[test]
    fn descriptor_marks_oracle_as_experimental_native() {
        let descriptor = OracleConnector::new().descriptor();
        assert_eq!(
            descriptor.support_tier,
            ConnectorSupportTier::ExperimentalNative
        );
        assert_eq!(descriptor.connector_id, "oracle");
    }

    #[test]
    fn weak_tls_modes_fail_closed() {
        let report = OracleConnector::validate_connection(&config(TlsMode::Require));
        assert!(!report.is_valid());
        assert_eq!(report.issues[0].code, "DBX-RS-ORA-CFG-0008");
    }

    #[test]
    fn malformed_custom_ca_fails_validation() {
        let mut connection = config(TlsMode::VerifyFull);
        connection.tls_ca_pem = Some(b"not a certificate".to_vec());

        let report = OracleConnector::validate_connection(&connection);

        assert!(!report.is_valid());
        assert_eq!(report.issues[0].code, "DBX-RS-ORA-CFG-0011");
    }

    #[test]
    fn invalid_tls_server_name_fails_validation() {
        let mut connection = config(TlsMode::VerifyFull);
        connection.tls_server_name = Some("invalid server name".into());

        let report = OracleConnector::validate_connection(&connection);

        assert!(!report.is_valid());
        assert_eq!(report.issues[0].code, "DBX-RS-ORA-CFG-0010");
    }

    #[test]
    fn connection_text_and_ca_inputs_have_connector_owned_bounds() {
        let mut invalid_host = config(TlsMode::Disable);
        invalid_host.host = "invalid host".into();
        let report = OracleConnector::validate_connection(&invalid_host);
        assert_eq!(report.issues[0].code, "DBX-RS-ORA-CFG-0044");

        let mut injected_service = config(TlsMode::Disable);
        injected_service.database = "ORCL)(DESCRIPTION=(ADDRESS=private))".into();
        let report = OracleConnector::validate_connection(&injected_service);
        assert_eq!(report.issues[0].code, "DBX-RS-ORA-CFG-0045");

        let mut oversized_username = config(TlsMode::Disable);
        oversized_username.username = "u".repeat(OracleConnector::MAX_USERNAME_BYTES + 1);
        let report = OracleConnector::validate_connection(&oversized_username);
        assert_eq!(report.issues[0].code, "DBX-RS-ORA-CFG-0046");

        let mut oversized_ca = config(TlsMode::VerifyFull);
        oversized_ca.tls_ca_pem = Some(vec![b'A'; OracleConnector::MAX_TLS_CA_BYTES + 1]);
        let report = OracleConnector::validate_connection(&oversized_ca);
        assert_eq!(report.issues[0].code, "DBX-RS-ORA-CFG-0047");
    }

    #[test]
    fn query_secret_and_request_id_limits_fail_before_driver_access() {
        let oversized_query = "Q".repeat(OracleConnector::MAX_QUERY_BYTES + 1);
        assert_eq!(
            OracleConnector::validate_query(&oversized_query, 1)
                .unwrap_err()
                .code(),
            "DBX-RS-ORA-CFG-0042"
        );

        let oversized_secret =
            ResolvedSecret::new(vec![b'S'; OracleConnector::MAX_SECRET_BYTES + 1]);
        assert_eq!(
            OracleConnector::validate_operation(&config(TlsMode::Disable), &oversized_secret)
                .unwrap_err()
                .code(),
            "DBX-RS-ORA-CFG-0043"
        );

        assert!(!valid_request_id(
            &"r".repeat(OracleConnector::MAX_REQUEST_ID_BYTES + 1)
        ));
        assert!(!valid_request_id("request\nprivate"));
    }

    #[tokio::test]
    async fn connection_authentication_uses_the_connect_timeout() {
        let (connector, dropped) = hanging_connector();
        let mut connection = config(TlsMode::Disable);
        connection.connect_timeout = Duration::from_millis(10);
        connection.probe_timeout = Duration::from_secs(5);
        let secret = ResolvedSecret::new(b"secret".to_vec());
        let operation = connector.probe_inner(
            ProbeRequest {
                request_id: "probe-connect-timeout".into(),
                connection,
            },
            &secret,
            CancellationToken::new(),
        );

        let error = tokio::time::timeout(Duration::from_millis(250), operation)
            .await
            .expect("connect timeout must bound authentication")
            .unwrap_err();

        assert_eq!(error.class(), ErrorClass::Timeout);
        assert_eq!(error.code(), "DBX-RS-ORA-CONNECT-0004");
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn cancellation_drops_in_flight_connection_authentication() {
        let (connector, dropped) = hanging_connector();
        let cancellation = CancellationToken::new();
        let cancel = cancellation.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            cancel.cancel();
        });
        let secret = ResolvedSecret::new(b"secret".to_vec());
        let operation = connector.probe_inner(
            ProbeRequest {
                request_id: "probe-connect-cancel".into(),
                connection: config(TlsMode::Disable),
            },
            &secret,
            cancellation,
        );

        let error = tokio::time::timeout(Duration::from_millis(250), operation)
            .await
            .expect("cancellation must interrupt connection authentication")
            .unwrap_err();

        assert_eq!(error.class(), ErrorClass::Cancelled);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn execution_fetches_more_than_one_hundred_rows_in_bounded_pages() {
        let columns = vec![number_column()];
        let session = Arc::new(FakeSession {
            columns: columns.clone(),
            pages: Mutex::new(VecDeque::from([
                page(&columns, 0..64, true),
                page(&columns, 64..128, true),
                page(&columns, 128..151, false),
            ])),
            hang_describe: false,
            fail_read_only: false,
            read_only_started: AtomicBool::new(false),
            operation_active: AtomicBool::new(false),
            abort_after_drop: AtomicBool::new(false),
            aborted: AtomicBool::new(false),
        });
        let connector = connector(Arc::clone(&session));
        let request = ExecuteRequest {
            request_id: "execute-1".into(),
            connection: config(TlsMode::Disable),
            query: QueryText::new("SELECT level AS value FROM dual CONNECT BY level <= 151"),
            limits: ExecutionLimits {
                max_rows: 150,
                max_batch_rows: 64,
                max_batch_bytes: 64 * 1024,
                max_total_ipc_bytes: 1024 * 1024,
                timeout: Duration::from_secs(5),
            },
            expected_schema: None,
            cursor: None,
        };
        let (batch_tx, mut batch_rx) = mpsc::channel(4);
        let result = connector
            .execute_inner(
                request,
                &ResolvedSecret::new(b"secret".to_vec()),
                batch_tx,
                CancellationToken::new(),
            )
            .await
            .unwrap();

        assert_eq!(result.rows_read, 150);
        assert_eq!(result.batches_emitted, 3);
        assert!(result.truncated);
        assert!(session.read_only_started.load(Ordering::SeqCst));
        let mut batch_rows = 0;
        while let Ok(batch) = batch_rx.try_recv() {
            batch_rows += batch.row_count;
        }
        assert_eq!(batch_rows, 150);
        assert!(session.aborted.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn read_only_transaction_failure_prevents_query_and_aborts() {
        let columns = vec![number_column()];
        let session = Arc::new(FakeSession {
            columns: columns.clone(),
            pages: Mutex::new(VecDeque::from([page(&columns, 0..1, false)])),
            hang_describe: false,
            fail_read_only: true,
            read_only_started: AtomicBool::new(false),
            operation_active: AtomicBool::new(false),
            abort_after_drop: AtomicBool::new(false),
            aborted: AtomicBool::new(false),
        });
        let connector = connector(Arc::clone(&session));
        let request = ExecuteRequest {
            request_id: "execute-read-only-failure".into(),
            connection: config(TlsMode::Disable),
            query: QueryText::new("SELECT value FROM source"),
            limits: ExecutionLimits {
                max_rows: 1,
                max_batch_rows: 1,
                max_batch_bytes: 64 * 1024,
                max_total_ipc_bytes: 1024 * 1024,
                timeout: Duration::from_secs(5),
            },
            expected_schema: None,
            cursor: None,
        };
        let (batch_tx, _batch_rx) = mpsc::channel(1);

        let error = connector
            .execute_inner(
                request,
                &ResolvedSecret::new(b"secret".to_vec()),
                batch_tx,
                CancellationToken::new(),
            )
            .await
            .unwrap_err();

        assert_eq!(error.code(), "TEST-READ-ONLY-FAILED");
        assert!(!session.read_only_started.load(Ordering::SeqCst));
        assert_eq!(session.pages.lock().await.len(), 1);
        assert!(session.aborted.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn empty_continuation_page_fails_closed_and_aborts() {
        let columns = vec![number_column()];
        let session = Arc::new(FakeSession {
            columns: columns.clone(),
            pages: Mutex::new(VecDeque::from([NativePage {
                columns,
                rows: Vec::new(),
                has_more_rows: true,
                cursor_id: 7,
            }])),
            hang_describe: false,
            fail_read_only: false,
            read_only_started: AtomicBool::new(false),
            operation_active: AtomicBool::new(false),
            abort_after_drop: AtomicBool::new(false),
            aborted: AtomicBool::new(false),
        });
        let connector = connector(Arc::clone(&session));
        let request = ExecuteRequest {
            request_id: "execute-empty-continuation".into(),
            connection: config(TlsMode::Disable),
            query: QueryText::new("SELECT value FROM source"),
            limits: ExecutionLimits {
                max_rows: 10,
                max_batch_rows: 2,
                max_batch_bytes: 64 * 1024,
                max_total_ipc_bytes: 1024 * 1024,
                timeout: Duration::from_secs(5),
            },
            expected_schema: None,
            cursor: None,
        };
        let (batch_tx, _batch_rx) = mpsc::channel(1);

        let error = connector
            .execute_inner(
                request,
                &ResolvedSecret::new(b"secret".to_vec()),
                batch_tx,
                CancellationToken::new(),
            )
            .await
            .unwrap_err();

        assert_eq!(error.code(), "DBX-RS-ORA-PROTOCOL-0010");
        assert_eq!(error.class(), ErrorClass::Protocol);
        assert!(session.aborted.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn missing_continuation_cursor_fails_closed_and_aborts() {
        let columns = vec![number_column()];
        let session = Arc::new(FakeSession {
            columns: columns.clone(),
            pages: Mutex::new(VecDeque::from([NativePage {
                columns,
                rows: vec![vec![NativeValue::Number("1".into())]],
                has_more_rows: true,
                cursor_id: 0,
            }])),
            hang_describe: false,
            fail_read_only: false,
            read_only_started: AtomicBool::new(false),
            operation_active: AtomicBool::new(false),
            abort_after_drop: AtomicBool::new(false),
            aborted: AtomicBool::new(false),
        });
        let connector = connector(Arc::clone(&session));
        let request = ExecuteRequest {
            request_id: "execute-missing-cursor".into(),
            connection: config(TlsMode::Disable),
            query: QueryText::new("SELECT value FROM source"),
            limits: ExecutionLimits {
                max_rows: 10,
                max_batch_rows: 2,
                max_batch_bytes: 64 * 1024,
                max_total_ipc_bytes: 1024 * 1024,
                timeout: Duration::from_secs(5),
            },
            expected_schema: None,
            cursor: None,
        };
        let (batch_tx, _batch_rx) = mpsc::channel(1);

        let error = connector
            .execute_inner(
                request,
                &ResolvedSecret::new(b"secret".to_vec()),
                batch_tx,
                CancellationToken::new(),
            )
            .await
            .unwrap_err();

        assert_eq!(error.code(), "DBX-RS-ORA-PROTOCOL-0011");
        assert_eq!(error.class(), ErrorClass::Protocol);
        assert!(session.aborted.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn cancellation_interrupts_blocked_batch_delivery_and_aborts() {
        let columns = vec![number_column()];
        let session = Arc::new(FakeSession {
            columns: columns.clone(),
            pages: Mutex::new(VecDeque::from([page(&columns, 0..2, false)])),
            hang_describe: false,
            fail_read_only: false,
            read_only_started: AtomicBool::new(false),
            operation_active: AtomicBool::new(false),
            abort_after_drop: AtomicBool::new(false),
            aborted: AtomicBool::new(false),
        });
        let connector = connector(Arc::clone(&session));
        let cancellation = CancellationToken::new();
        let cancel = cancellation.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            cancel.cancel();
        });
        let request = ExecuteRequest {
            request_id: "execute-blocked-delivery".into(),
            connection: config(TlsMode::Disable),
            query: QueryText::new("SELECT value FROM source"),
            limits: ExecutionLimits {
                max_rows: 2,
                max_batch_rows: 1,
                max_batch_bytes: 64 * 1024,
                max_total_ipc_bytes: 1024 * 1024,
                timeout: Duration::from_secs(5),
            },
            expected_schema: None,
            cursor: None,
        };
        let (batch_tx, mut batch_rx) = mpsc::channel(1);

        let error = tokio::time::timeout(
            Duration::from_millis(250),
            connector.execute_inner(
                request,
                &ResolvedSecret::new(b"secret".to_vec()),
                batch_tx,
                cancellation,
            ),
        )
        .await
        .expect("cancellation must interrupt blocked delivery")
        .unwrap_err();

        assert_eq!(error.class(), ErrorClass::Cancelled);
        assert_eq!(batch_rx.try_recv().unwrap().row_count, 1);
        assert!(batch_rx.try_recv().is_err());
        assert!(session.aborted.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn cancellation_drops_the_operation_then_aborts_the_connection() {
        let session = Arc::new(FakeSession {
            columns: vec![number_column()],
            pages: Mutex::new(VecDeque::new()),
            hang_describe: true,
            fail_read_only: false,
            read_only_started: AtomicBool::new(false),
            operation_active: AtomicBool::new(false),
            abort_after_drop: AtomicBool::new(false),
            aborted: AtomicBool::new(false),
        });
        let connector = connector(Arc::clone(&session));
        let cancellation = CancellationToken::new();
        let cancel = cancellation.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            cancel.cancel();
        });
        let request = PrepareRequest {
            request_id: "prepare-1".into(),
            connection: config(TlsMode::Disable),
            query: QueryText::new("SELECT 1 AS value FROM dual"),
            max_rows: 1,
            timeout: Duration::from_secs(5),
            cursor: None,
        };
        let error = connector
            .prepare_inner(
                request,
                &ResolvedSecret::new(b"secret".to_vec()),
                cancellation,
            )
            .await
            .unwrap_err();

        assert_eq!(error.class(), ErrorClass::Cancelled);
        assert!(session.aborted.load(Ordering::SeqCst));
        assert!(session.abort_after_drop.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn timeout_drops_the_operation_then_aborts_the_connection() {
        let session = Arc::new(FakeSession {
            columns: vec![number_column()],
            pages: Mutex::new(VecDeque::new()),
            hang_describe: true,
            fail_read_only: false,
            read_only_started: AtomicBool::new(false),
            operation_active: AtomicBool::new(false),
            abort_after_drop: AtomicBool::new(false),
            aborted: AtomicBool::new(false),
        });
        let connector = connector(Arc::clone(&session));
        let request = PrepareRequest {
            request_id: "prepare-timeout".into(),
            connection: config(TlsMode::Disable),
            query: QueryText::new("SELECT 1 AS value FROM dual"),
            max_rows: 1,
            timeout: Duration::from_millis(10),
            cursor: None,
        };
        let error = connector
            .prepare_inner(
                request,
                &ResolvedSecret::new(b"secret".to_vec()),
                CancellationToken::new(),
            )
            .await
            .unwrap_err();

        assert_eq!(error.class(), ErrorClass::Timeout);
        assert!(session.aborted.load(Ordering::SeqCst));
        assert!(session.abort_after_drop.load(Ordering::SeqCst));
    }
}
