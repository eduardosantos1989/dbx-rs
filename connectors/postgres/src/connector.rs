use std::{net::SocketAddr, sync::Arc, time::Duration};

use dbx_rs_connector_sdk::{
    AuthenticationMethod, CONNECTOR_CONTRACT_VERSION, ConnectionConfig, Connector,
    ConnectorCapability, ConnectorDescriptor, ConnectorError, ConnectorFuture, ErrorClass,
    ExecuteRequest, ExecutionResult, PrepareRequest, PreparedQuery, ProbeReport, ProbeRequest,
    ResolvedSecret, TimestampIdCursorBound, TimestampIdCursorRequest, TlsMode, ValidationIssue,
    ValidationReport, ValidationRequest, ValidationSeverity,
};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, pem::PemObject},
};
use tokio::net::{TcpStream, lookup_host};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};
use tokio_postgres::{Client, NoTls, config::SslMode, tls::MakeTlsConnect};
use tokio_postgres_rustls::MakeRustlsConnect;
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};

mod typed;

pub struct PostgresConnector;

impl PostgresConnector {
    pub const CONNECTOR_ID: &'static str = "postgres";
    const MAX_COLLECTION_ROWS: u64 = 100_000;
    pub(super) const MAX_OPERATION_TIMEOUT: Duration = Duration::from_hours(24);

    #[must_use]
    pub fn descriptor(&self) -> ConnectorDescriptor {
        ConnectorDescriptor {
            contract_version: CONNECTOR_CONTRACT_VERSION,
            connector_id: Self::CONNECTOR_ID.into(),
            connector_version: env!("CARGO_PKG_VERSION").into(),
            database_families: vec!["postgresql".into()],
            capabilities: vec![
                ConnectorCapability::ValidateConfiguration,
                ConnectorCapability::ProbeConnection,
                ConnectorCapability::PrepareQuery,
                ConnectorCapability::ExecuteQuery,
            ],
            authentication_methods: vec![AuthenticationMethod::Password],
            build_id: format!("{}-{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        }
    }

    /// Validates connectivity and returns the `PostgreSQL` product and version.
    ///
    /// # Errors
    ///
    /// Returns a classified connector error when configuration, resolution, connection, TLS,
    /// authentication, cancellation, or the probe query fails.
    pub async fn probe(
        &self,
        config: &ConnectionConfig,
        secret: &ResolvedSecret,
        cancellation: CancellationToken,
    ) -> Result<ProbeReport, ConnectorError> {
        let report = Self::validate_connection(config);
        if !report.is_valid() {
            return Err(Self::invalid_configuration(&report));
        }
        if secret.is_empty() {
            return Err(ConnectorError::new(
                "DBX-RS-PG-AUTH-0001",
                ErrorClass::Configuration,
                "PostgreSQL password is empty",
                false,
                true,
            ));
        }

        Self::authenticate_and_probe(config, secret, &cancellation).await
    }

    /// Prepares a bounded query and returns its connector-neutral schema.
    ///
    /// # Errors
    ///
    /// Returns a classified error for invalid configuration, connection, query, schema,
    /// cancellation, or timeout failures.
    pub async fn prepare(
        &self,
        request: PrepareRequest,
        secret: &ResolvedSecret,
        cancellation: CancellationToken,
    ) -> Result<PreparedQuery, ConnectorError> {
        typed::prepare(request, secret, cancellation).await
    }

    /// Executes a bounded query and emits self-contained Arrow IPC batches.
    ///
    /// # Errors
    ///
    /// Returns a classified error for invalid configuration, connection, query, conversion,
    /// limits, cancellation, output closure, or timeout failures.
    pub async fn execute(
        &self,
        request: ExecuteRequest,
        secret: &ResolvedSecret,
        batch_tx: mpsc::Sender<dbx_rs_connector_sdk::ArrowIpcBatch>,
        cancellation: CancellationToken,
    ) -> Result<ExecutionResult, ConnectorError> {
        typed::execute(request, secret, batch_tx, cancellation).await
    }

    /// Validates a `PostgreSQL` connection description without opening a network connection.
    #[must_use]
    pub fn validate_connection(config: &ConnectionConfig) -> ValidationReport {
        let mut issues = Vec::new();

        if config.connector_id != Self::CONNECTOR_ID {
            issues.push(validation_error(
                "DBX-RS-PG-CFG-0001",
                "connector_id",
                "connector_id must be postgres",
            ));
        }
        if config.host.trim().is_empty() {
            issues.push(validation_error(
                "DBX-RS-PG-CFG-0002",
                "host",
                "host is required",
            ));
        }
        if config.port == 0 {
            issues.push(validation_error(
                "DBX-RS-PG-CFG-0003",
                "port",
                "port must be greater than zero",
            ));
        }
        if config.database.trim().is_empty() {
            issues.push(validation_error(
                "DBX-RS-PG-CFG-0004",
                "database",
                "database is required",
            ));
        }
        if config.username.trim().is_empty() {
            issues.push(validation_error(
                "DBX-RS-PG-CFG-0005",
                "username",
                "username is required",
            ));
        }
        issues.extend(timeout_issue(
            config.connect_timeout,
            "connect_timeout",
            "DBX-RS-PG-CFG-0006",
            "DBX-RS-PG-CFG-0012",
        ));
        issues.extend(timeout_issue(
            config.probe_timeout,
            "probe_timeout",
            "DBX-RS-PG-CFG-0007",
            "DBX-RS-PG-CFG-0013",
        ));
        match config.tls_mode {
            TlsMode::Disable => {
                if config.tls_server_name.is_some() || config.tls_ca_pem.is_some() {
                    issues.push(validation_error(
                        "DBX-RS-PG-CFG-0009",
                        "tls_mode",
                        "TLS server name and CA settings require tls_mode=verify-full",
                    ));
                }
            }
            TlsMode::VerifyFull => {
                if config
                    .tls_server_name
                    .as_ref()
                    .is_some_and(|name| name.trim().is_empty())
                {
                    issues.push(validation_error(
                        "DBX-RS-PG-CFG-0010",
                        "tls_server_name",
                        "TLS server name must not be empty",
                    ));
                }
                if config
                    .tls_ca_pem
                    .as_deref()
                    .is_some_and(|pem| !valid_ca_pem(pem))
                {
                    issues.push(validation_error(
                        "DBX-RS-PG-CFG-0011",
                        "tls_ca_pem",
                        "TLS CA data must contain at least one valid PEM certificate",
                    ));
                }
            }
            TlsMode::Require | TlsMode::VerifyCa => {
                issues.push(validation_error(
                    "DBX-RS-PG-CFG-0008",
                    "tls_mode",
                    "tls_mode=require and verify-ca are unsupported because they do not verify the server hostname",
                ));
            }
        }

        ValidationReport { issues }
    }

    /// Validates one bounded read query without opening a network connection.
    ///
    /// # Errors
    ///
    /// Returns a classified configuration error when the query is empty, contains multiple
    /// statements, is not a `SELECT`/`WITH` query, or has an invalid row limit.
    pub fn validate_query(query: &str, max_rows: u64) -> Result<(), ConnectorError> {
        normalize_read_query(query, max_rows).map(|_| ())
    }

    fn invalid_configuration(report: &ValidationReport) -> ConnectorError {
        let first_code = report
            .issues
            .first()
            .map_or("DBX-RS-PG-CFG-0099", |issue| issue.code.as_str());
        ConnectorError::new(
            first_code,
            ErrorClass::Configuration,
            "PostgreSQL connection configuration is invalid",
            false,
            true,
        )
    }

    fn validate_operation(
        config: &ConnectionConfig,
        secret: &ResolvedSecret,
    ) -> Result<(), ConnectorError> {
        let report = Self::validate_connection(config);
        if !report.is_valid() {
            return Err(Self::invalid_configuration(&report));
        }
        if secret.is_empty() {
            return Err(ConnectorError::new(
                "DBX-RS-PG-AUTH-0001",
                ErrorClass::Configuration,
                "PostgreSQL password is empty",
                false,
                true,
            ));
        }
        Ok(())
    }

    async fn resolve(
        config: &ConnectionConfig,
        cancellation: &CancellationToken,
    ) -> Result<Vec<SocketAddr>, ConnectorError> {
        let resolution = tokio::select! {
            () = cancellation.cancelled() => {
                return Err(ConnectorError::cancelled("DBX-RS-PG-CANCELLED-0001"));
            }
            result = timeout(
                config.connect_timeout,
                lookup_host((config.host.as_str(), config.port)),
            ) => result,
        };

        let addresses = resolution
            .map_err(|_| {
                ConnectorError::new(
                    "DBX-RS-PG-DNS-0001",
                    ErrorClass::Timeout,
                    "PostgreSQL host resolution timed out",
                    true,
                    false,
                )
            })?
            .map_err(|_| {
                ConnectorError::new(
                    "DBX-RS-PG-DNS-0002",
                    ErrorClass::Dns,
                    "PostgreSQL host resolution failed",
                    true,
                    false,
                )
            })?
            .collect::<Vec<_>>();

        if addresses.is_empty() {
            return Err(ConnectorError::new(
                "DBX-RS-PG-DNS-0003",
                ErrorClass::Dns,
                "PostgreSQL host did not resolve to an address",
                true,
                false,
            ));
        }

        Ok(addresses)
    }

    async fn connect_tcp(
        config: &ConnectionConfig,
        addresses: Vec<SocketAddr>,
        cancellation: &CancellationToken,
    ) -> Result<(TcpStream, SocketAddr), ConnectorError> {
        let deadline = Instant::now()
            .checked_add(config.connect_timeout)
            .ok_or_else(|| {
                ConnectorError::new(
                    "DBX-RS-PG-CFG-0018",
                    ErrorClass::Configuration,
                    "PostgreSQL connection timeout cannot be represented",
                    false,
                    true,
                )
            })?;

        for address in addresses {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }

            let connection = tokio::select! {
                () = cancellation.cancelled() => {
                    return Err(ConnectorError::cancelled("DBX-RS-PG-CANCELLED-0002"));
                }
                result = timeout(remaining, TcpStream::connect(address)) => result,
            };

            if let Ok(Ok(stream)) = connection {
                stream.set_nodelay(true).map_err(|_| {
                    ConnectorError::new(
                        "DBX-RS-PG-TCP-0002",
                        ErrorClass::Tcp,
                        "failed to configure the PostgreSQL TCP connection",
                        true,
                        false,
                    )
                })?;
                return Ok((stream, address));
            }
        }

        Err(ConnectorError::new(
            "DBX-RS-PG-TCP-0001",
            ErrorClass::Tcp,
            "could not connect to any resolved PostgreSQL address",
            true,
            false,
        ))
    }

    async fn authenticate_and_probe(
        config: &ConnectionConfig,
        secret: &ResolvedSecret,
        cancellation: &CancellationToken,
    ) -> Result<ProbeReport, ConnectorError> {
        let (client, connection_task, endpoint) =
            Self::open_client(config, secret, "dbx-rs/postgres-probe", cancellation).await?;
        let query = client.query_one(
            "SELECT current_setting('server_version'), current_setting('server_version_num')::int4, version()",
            &[],
        );
        let query_result = tokio::select! {
            () = cancellation.cancelled() => {
                connection_task.abort();
                return Err(ConnectorError::cancelled("DBX-RS-PG-CANCELLED-0004"));
            }
            result = timeout(config.probe_timeout, query) => result,
        };

        let row = query_result
            .map_err(|_| {
                ConnectorError::new(
                    "DBX-RS-PG-QUERY-0002",
                    ErrorClass::Timeout,
                    "PostgreSQL probe query timed out",
                    true,
                    false,
                )
            })?
            .map_err(|error| classify_query_error(&error))?;

        let server_version = row.try_get::<_, String>(0).map_err(|_| {
            ConnectorError::new(
                "DBX-RS-PG-CONVERT-0001",
                ErrorClass::Conversion,
                "PostgreSQL returned an invalid server version",
                false,
                false,
            )
        })?;
        let server_version_number = row.try_get::<_, i32>(1).map_err(|_| {
            ConnectorError::new(
                "DBX-RS-PG-CONVERT-0002",
                ErrorClass::Conversion,
                "PostgreSQL returned an invalid numeric server version",
                false,
                false,
            )
        })?;
        let banner = row.try_get::<_, String>(2).map_err(|_| {
            ConnectorError::new(
                "DBX-RS-PG-CONVERT-0003",
                ErrorClass::Conversion,
                "PostgreSQL returned an invalid product identity",
                false,
                false,
            )
        })?;

        drop(client);
        connection_task.abort();

        Ok(ProbeReport {
            connector_id: Self::CONNECTOR_ID.into(),
            database_product: if banner.starts_with("PostgreSQL ") {
                "PostgreSQL".into()
            } else {
                "PostgreSQL-compatible".into()
            },
            server_version,
            server_version_number: u32::try_from(server_version_number).ok(),
            endpoint: endpoint.to_string(),
            tls_mode: config.tls_mode,
        })
    }

    async fn open_client(
        config: &ConnectionConfig,
        secret: &ResolvedSecret,
        application_name: &str,
        cancellation: &CancellationToken,
    ) -> Result<(Client, AbortOnDropHandle<()>, SocketAddr), ConnectorError> {
        let addresses = Self::resolve(config, cancellation).await?;
        let (stream, endpoint) = Self::connect_tcp(config, addresses, cancellation).await?;
        let mut postgres_config = tokio_postgres::Config::new();
        let tls_server_name = config
            .tls_server_name
            .as_deref()
            .unwrap_or(config.host.as_str());
        postgres_config
            .host(tls_server_name)
            .user(&config.username)
            .password(secret.expose_secret())
            .dbname(&config.database)
            .application_name(application_name);
        let (client, connection_task) =
            Self::establish_client(config, postgres_config, stream, cancellation).await?;
        Ok((client, AbortOnDropHandle::new(connection_task), endpoint))
    }

    async fn establish_client(
        config: &ConnectionConfig,
        mut postgres_config: tokio_postgres::Config,
        stream: TcpStream,
        cancellation: &CancellationToken,
    ) -> Result<(Client, JoinHandle<()>), ConnectorError> {
        match config.tls_mode {
            TlsMode::Disable => {
                postgres_config.ssl_mode(SslMode::Disable);
                let handshake = tokio::select! {
                    () = cancellation.cancelled() => {
                        return Err(ConnectorError::cancelled("DBX-RS-PG-CANCELLED-0003"));
                    }
                    result = timeout(
                        config.probe_timeout,
                        postgres_config.connect_raw(stream, NoTls),
                    ) => result,
                };
                let (client, connection) = handshake
                    .map_err(|_| handshake_timeout(config.tls_mode))?
                    .map_err(|error| classify_handshake_error(&error, config.tls_mode))?;
                let task = tokio::spawn(async move {
                    let _result = connection.await;
                });
                Ok((client, task))
            }
            TlsMode::VerifyFull => {
                postgres_config.ssl_mode(SslMode::Require);
                let mut tls = build_tls_connector(config)?;
                let tls_server_name = config
                    .tls_server_name
                    .as_deref()
                    .unwrap_or(config.host.as_str());
                let tls = <MakeRustlsConnect as MakeTlsConnect<TcpStream>>::make_tls_connect(
                    &mut tls,
                    tls_server_name,
                )
                .map_err(|_| {
                    ConnectorError::new(
                        "DBX-RS-PG-TLS-0006",
                        ErrorClass::Internal,
                        "failed to initialize PostgreSQL TLS server verification",
                        false,
                        false,
                    )
                })?;
                let handshake = tokio::select! {
                    () = cancellation.cancelled() => {
                        return Err(ConnectorError::cancelled("DBX-RS-PG-CANCELLED-0003"));
                    }
                    result = timeout(
                        config.probe_timeout,
                        postgres_config.connect_raw(stream, tls),
                    ) => result,
                };
                let (client, connection) = handshake
                    .map_err(|_| handshake_timeout(config.tls_mode))?
                    .map_err(|error| classify_handshake_error(&error, config.tls_mode))?;
                let task = tokio::spawn(async move {
                    let _result = connection.await;
                });
                Ok((client, task))
            }
            TlsMode::Require | TlsMode::VerifyCa => Err(ConnectorError::new(
                "DBX-RS-PG-CFG-0008",
                ErrorClass::Configuration,
                "PostgreSQL TLS mode is not supported",
                false,
                true,
            )),
        }
    }
}

impl Connector for PostgresConnector {
    fn descriptor(&self) -> ConnectorDescriptor {
        PostgresConnector::descriptor(self)
    }

    fn validate(&self, request: &ValidationRequest) -> ValidationReport {
        let mut report = Self::validate_connection(&request.connection);
        if let Some(query) = &request.query {
            match request.max_rows {
                Some(max_rows) => {
                    if let Err(error) = Self::validate_query(query.as_str(), max_rows) {
                        report.issues.push(ValidationIssue {
                            code: error.code().to_owned(),
                            field: "query".into(),
                            message: "configured PostgreSQL query is invalid".into(),
                            severity: ValidationSeverity::Error,
                        });
                    }
                }
                None => report.issues.push(validation_error(
                    "DBX-RS-PG-CFG-0019",
                    "max_rows",
                    "max_rows is required when a query is validated",
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
        Box::pin(async move {
            if request.request_id.trim().is_empty() {
                return Err(ConnectorError::new(
                    "DBX-RS-PG-CFG-0030",
                    ErrorClass::Configuration,
                    "probe request ID is required",
                    false,
                    true,
                ));
            }
            PostgresConnector::probe(self, &request.connection, secret, cancellation).await
        })
    }

    fn prepare<'a>(
        &'a self,
        request: PrepareRequest,
        secret: &'a ResolvedSecret,
        cancellation: CancellationToken,
    ) -> ConnectorFuture<'a, PreparedQuery> {
        Box::pin(PostgresConnector::prepare(
            self,
            request,
            secret,
            cancellation,
        ))
    }

    fn execute<'a>(
        &'a self,
        request: ExecuteRequest,
        secret: &'a ResolvedSecret,
        batch_tx: mpsc::Sender<dbx_rs_connector_sdk::ArrowIpcBatch>,
        cancellation: CancellationToken,
    ) -> ConnectorFuture<'a, ExecutionResult> {
        Box::pin(PostgresConnector::execute(
            self,
            request,
            secret,
            batch_tx,
            cancellation,
        ))
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
    } else if timeout > PostgresConnector::MAX_OPERATION_TIMEOUT {
        Some(validation_error(
            hard_limit_code,
            field,
            "timeout exceeds the connector hard limit",
        ))
    } else {
        None
    }
}

fn valid_ca_pem(pem: &[u8]) -> bool {
    parse_ca_certificates(pem).is_ok_and(|certificates| !certificates.is_empty())
}

fn parse_ca_certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, ConnectorError> {
    CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            ConnectorError::new(
                "DBX-RS-PG-TLS-0001",
                ErrorClass::Configuration,
                "failed to parse PostgreSQL TLS CA certificates",
                false,
                true,
            )
        })
}

fn build_tls_connector(config: &ConnectionConfig) -> Result<MakeRustlsConnect, ConnectorError> {
    let mut roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    if let Some(pem) = config.tls_ca_pem.as_deref() {
        let certificates = parse_ca_certificates(pem)?;
        let (added, ignored) = roots.add_parsable_certificates(certificates);
        if added == 0 || ignored != 0 {
            return Err(ConnectorError::new(
                "DBX-RS-PG-TLS-0002",
                ErrorClass::Configuration,
                "PostgreSQL TLS CA data contains an unusable certificate",
                false,
                true,
            ));
        }
    }

    let client_config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|_| {
                ConnectorError::new(
                    "DBX-RS-PG-TLS-0003",
                    ErrorClass::Internal,
                    "failed to initialize the PostgreSQL TLS protocol configuration",
                    false,
                    false,
                )
            })?
            .with_root_certificates(roots)
            .with_no_client_auth();

    Ok(MakeRustlsConnect::new(client_config))
}

fn handshake_timeout(tls_mode: TlsMode) -> ConnectorError {
    let (code, message) = if tls_mode == TlsMode::VerifyFull {
        (
            "DBX-RS-PG-TLS-0004",
            "PostgreSQL TLS negotiation or authentication timed out",
        )
    } else {
        ("DBX-RS-PG-AUTH-0002", "PostgreSQL authentication timed out")
    };
    ConnectorError::new(code, ErrorClass::Timeout, message, true, false)
}

fn classify_handshake_error(error: &tokio_postgres::Error, tls_mode: TlsMode) -> ConnectorError {
    if let Some(database_error) = error.as_db_error() {
        let sql_state = database_error.code().code();
        let class = error_class_for_sql_state(sql_state);
        let (code, message, retryable) = if class == ErrorClass::Authentication {
            (
                "DBX-RS-PG-AUTH-0003",
                "PostgreSQL authentication failed",
                false,
            )
        } else {
            (
                "DBX-RS-PG-PROTOCOL-0001",
                "PostgreSQL connection negotiation failed",
                sql_state.starts_with("08"),
            )
        };
        return ConnectorError::new(code, class, message, retryable, false)
            .with_sql_state(sql_state);
    }

    if tls_mode == TlsMode::VerifyFull {
        ConnectorError::new(
            "DBX-RS-PG-TLS-0005",
            ErrorClass::Tls,
            "PostgreSQL TLS verification or negotiation failed",
            false,
            false,
        )
    } else {
        ConnectorError::new(
            "DBX-RS-PG-PROTOCOL-0002",
            ErrorClass::Protocol,
            "PostgreSQL connection negotiation failed",
            true,
            false,
        )
    }
}

fn classify_query_error(error: &tokio_postgres::Error) -> ConnectorError {
    if let Some(database_error) = error.as_db_error() {
        let sql_state = database_error.code().code();
        return ConnectorError::new(
            "DBX-RS-PG-QUERY-0001",
            error_class_for_sql_state(sql_state),
            "PostgreSQL query failed",
            sql_state.starts_with("08"),
            false,
        )
        .with_sql_state(sql_state);
    }

    ConnectorError::new(
        "DBX-RS-PG-QUERY-0003",
        ErrorClass::Query,
        "PostgreSQL query failed",
        true,
        false,
    )
}

struct NormalizedTypedQuery {
    base: String,
    sql: String,
    cursor_bound: Option<TimestampIdCursorBound>,
}

fn normalize_typed_query(
    query: &str,
    max_rows: u64,
    cursor: Option<&TimestampIdCursorRequest>,
) -> Result<NormalizedTypedQuery, ConnectorError> {
    let base = normalize_read_query(query, max_rows)?;
    let fetch_rows = max_rows.saturating_add(1);
    let Some(cursor) = cursor else {
        return Ok(NormalizedTypedQuery {
            sql: format!("SELECT * FROM ({base}) AS dbx_rs_row LIMIT {fetch_rows}"),
            base,
            cursor_bound: None,
        });
    };

    let cursor_bound = cursor.effective_bound().map_err(|_| {
        ConnectorError::new(
            "DBX-RS-PG-CFG-0046",
            ErrorClass::Configuration,
            "PostgreSQL cursor specification or bound is invalid",
            false,
            true,
        )
    })?;
    if cursor.spec.timestamp_field.contains('\0') || cursor.spec.id_field.contains('\0') {
        return Err(ConnectorError::new(
            "DBX-RS-PG-CFG-0046",
            ErrorClass::Configuration,
            "PostgreSQL cursor specification or bound is invalid",
            false,
            true,
        ));
    }

    let timestamp_field = quote_postgres_identifier(&cursor.spec.timestamp_field);
    let id_field = quote_postgres_identifier(&cursor.spec.id_field);
    let predicate = cursor_bound.map_or_else(String::new, |bound| {
        let operator = if bound.inclusive { ">=" } else { ">" };
        format!(
            " WHERE (dbx_rs_row.{timestamp_field} IS NULL OR dbx_rs_row.{id_field} IS NULL OR (dbx_rs_row.{timestamp_field}, dbx_rs_row.{id_field}) {operator} ($1, $2))"
        )
    });
    let sql = format!(
        "SELECT * FROM ({base}) AS dbx_rs_row{predicate} ORDER BY dbx_rs_row.{timestamp_field} ASC NULLS FIRST, dbx_rs_row.{id_field} ASC NULLS FIRST LIMIT {fetch_rows}"
    );
    Ok(NormalizedTypedQuery {
        base,
        sql,
        cursor_bound,
    })
}

fn quote_postgres_identifier(identifier: &str) -> String {
    let mut quoted = String::with_capacity(identifier.len().saturating_add(2));
    quoted.push('"');
    for character in identifier.chars() {
        if character == '"' {
            quoted.push('"');
        }
        quoted.push(character);
    }
    quoted.push('"');
    quoted
}

fn normalize_read_query(query: &str, max_rows: u64) -> Result<String, ConnectorError> {
    if !(1..=PostgresConnector::MAX_COLLECTION_ROWS).contains(&max_rows) {
        return Err(ConnectorError::new(
            "DBX-RS-PG-CFG-0014",
            ErrorClass::Configuration,
            format!(
                "collection max_rows must be between 1 and {}",
                PostgresConnector::MAX_COLLECTION_ROWS
            ),
            false,
            true,
        ));
    }

    let query = query.trim();
    if query.is_empty() || query.contains('\0') {
        return Err(ConnectorError::new(
            "DBX-RS-PG-CFG-0015",
            ErrorClass::Configuration,
            "collection query must be non-empty text",
            false,
            true,
        ));
    }
    let query = query.strip_suffix(';').map_or(query, str::trim_end);
    if query.is_empty() || query.ends_with(';') {
        return Err(ConnectorError::new(
            "DBX-RS-PG-CFG-0016",
            ErrorClass::Configuration,
            "collection query must contain one statement",
            false,
            true,
        ));
    }

    let keyword_end = query
        .find(|character: char| !character.is_ascii_alphabetic())
        .unwrap_or(query.len());
    let keyword = &query[..keyword_end];
    if !keyword.eq_ignore_ascii_case("select") && !keyword.eq_ignore_ascii_case("with") {
        return Err(ConnectorError::new(
            "DBX-RS-PG-CFG-0017",
            ErrorClass::Configuration,
            "collection query must start with SELECT or WITH",
            false,
            true,
        ));
    }

    Ok(query.to_owned())
}

fn error_class_for_sql_state(sql_state: &str) -> ErrorClass {
    if sql_state.starts_with("28") {
        ErrorClass::Authentication
    } else if sql_state.starts_with("08") {
        ErrorClass::Protocol
    } else {
        ErrorClass::Query
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use dbx_rs_connector_sdk::{
        CursorNullPolicy, TimestampIdCursor, TimestampIdCursorRequest, TimestampIdCursorSpec,
    };

    use super::*;

    fn config(tls_mode: TlsMode) -> ConnectionConfig {
        ConnectionConfig {
            connector_id: PostgresConnector::CONNECTOR_ID.into(),
            host: "database.example".into(),
            port: 5432,
            database: "events".into(),
            username: "reader".into(),
            tls_mode,
            tls_server_name: None,
            tls_ca_pem: None,
            connect_timeout: Duration::from_secs(10),
            probe_timeout: Duration::from_secs(10),
        }
    }

    #[test]
    fn explicit_disabled_tls_is_valid_for_lab_probe() {
        let report = PostgresConnector::validate_connection(&config(TlsMode::Disable));

        assert!(report.is_valid());
    }

    #[test]
    fn verified_tls_is_valid() {
        let report = PostgresConnector::validate_connection(&config(TlsMode::VerifyFull));

        assert!(report.is_valid());
    }

    #[test]
    fn weaker_tls_mode_fails_closed() {
        let report = PostgresConnector::validate_connection(&config(TlsMode::Require));

        assert!(!report.is_valid());
        assert_eq!(report.issues[0].code, "DBX-RS-PG-CFG-0008");
    }

    #[test]
    fn malformed_custom_ca_is_rejected() {
        let mut config = config(TlsMode::VerifyFull);
        config.tls_ca_pem = Some(b"not a PEM certificate".to_vec());

        let report = PostgresConnector::validate_connection(&config);

        assert!(!report.is_valid());
        assert_eq!(report.issues[0].code, "DBX-RS-PG-CFG-0011");
    }

    #[test]
    fn connection_timeouts_above_the_hard_limit_are_rejected() {
        let mut config = config(TlsMode::VerifyFull);
        config.connect_timeout = PostgresConnector::MAX_OPERATION_TIMEOUT + Duration::from_secs(1);
        config.probe_timeout = PostgresConnector::MAX_OPERATION_TIMEOUT + Duration::from_secs(1);

        let report = PostgresConnector::validate_connection(&config);

        assert_eq!(report.issues.len(), 2);
        assert_eq!(report.issues[0].code, "DBX-RS-PG-CFG-0012");
        assert_eq!(report.issues[1].code, "DBX-RS-PG-CFG-0013");
    }

    #[test]
    fn authentication_sql_state_is_classified_without_message_matching() {
        assert_eq!(
            error_class_for_sql_state("28P01"),
            ErrorClass::Authentication
        );
    }

    #[test]
    fn typed_query_is_wrapped_with_hard_row_limit_and_truncation_probe() {
        let query = normalize_typed_query(" SELECT 1 AS value;\n", 25, None)
            .expect("read query must be accepted");

        assert_eq!(
            query.sql,
            "SELECT * FROM (SELECT 1 AS value) AS dbx_rs_row LIMIT 26"
        );
        assert_eq!(query.base, "SELECT 1 AS value");
        assert!(query.cursor_bound.is_none());
    }

    fn cursor_request(
        timestamp_field: &str,
        id_field: &str,
        overlap: Duration,
        committed: Option<TimestampIdCursor>,
    ) -> TimestampIdCursorRequest {
        TimestampIdCursorRequest {
            spec: TimestampIdCursorSpec {
                timestamp_field: timestamp_field.into(),
                id_field: id_field.into(),
                overlap,
                null_policy: CursorNullPolicy::Reject,
            },
            committed,
            resume_after: None,
        }
    }

    #[test]
    fn cursor_query_quotes_output_aliases_and_binds_an_exclusive_tuple() {
        let cursor = cursor_request(
            "updated\"at",
            "row id",
            Duration::ZERO,
            Some(TimestampIdCursor::new(1_234_567_890, 9_876_543_210)),
        );

        let query = normalize_typed_query("SELECT * FROM events", 10, Some(&cursor))
            .expect("cursor query must be accepted");

        assert_eq!(
            query.sql,
            "SELECT * FROM (SELECT * FROM events) AS dbx_rs_row WHERE (dbx_rs_row.\"updated\"\"at\" IS NULL OR dbx_rs_row.\"row id\" IS NULL OR (dbx_rs_row.\"updated\"\"at\", dbx_rs_row.\"row id\") > ($1, $2)) ORDER BY dbx_rs_row.\"updated\"\"at\" ASC NULLS FIRST, dbx_rs_row.\"row id\" ASC NULLS FIRST LIMIT 11"
        );
        assert!(!query.sql.contains("1234567890"));
        assert!(!query.sql.contains("9876543210"));
        assert!(query.cursor_bound.is_some_and(|bound| !bound.inclusive));
    }

    #[test]
    fn overlap_cursor_uses_an_inclusive_native_parameter_predicate() {
        let cursor = cursor_request(
            "updated_at",
            "id",
            Duration::from_secs(2),
            Some(TimestampIdCursor::new(10_000_000, 77)),
        );

        let query = normalize_typed_query("SELECT updated_at, id FROM events", 5, Some(&cursor))
            .expect("overlap cursor query must be accepted");

        assert!(query.sql.contains(") >= ($1, $2)"));
        assert!(
            query.sql.contains(
                "WHERE (dbx_rs_row.\"updated_at\" IS NULL OR dbx_rs_row.\"id\" IS NULL OR"
            )
        );
        assert!(!query.sql.contains("10000000"));
        assert!(query.cursor_bound.is_some_and(|bound| bound.inclusive));
    }

    #[test]
    fn cursor_without_committed_state_orders_without_parameters() {
        let cursor = cursor_request("updated_at", "id", Duration::ZERO, None);

        let query = normalize_typed_query("SELECT updated_at, id FROM events", 5, Some(&cursor))
            .expect("initial cursor query must be accepted");

        assert!(!query.sql.contains(" WHERE "));
        assert!(!query.sql.contains("$1"));
        assert!(
            query
                .sql
                .contains("ORDER BY dbx_rs_row.\"updated_at\" ASC NULLS FIRST")
        );
        assert!(query.cursor_bound.is_none());
    }

    #[test]
    fn invalid_cursor_specification_fails_before_sql_construction() {
        let cursor = cursor_request("same", "same", Duration::ZERO, None);

        let error = normalize_typed_query("SELECT 1", 5, Some(&cursor))
            .err()
            .expect("duplicate cursor fields must fail");

        assert_eq!(error.code(), "DBX-RS-PG-CFG-0046");
    }

    #[test]
    fn collection_query_rejects_non_read_statement() {
        let error = normalize_read_query("DELETE FROM events", 25)
            .expect_err("write query must be rejected");

        assert_eq!(error.code(), "DBX-RS-PG-CFG-0017");
    }

    #[test]
    fn collection_query_rejects_out_of_range_limit() {
        let error = normalize_read_query("SELECT 1", PostgresConnector::MAX_COLLECTION_ROWS + 1)
            .expect_err("oversized limit must be rejected");

        assert_eq!(error.code(), "DBX-RS-PG-CFG-0014");
    }
}
