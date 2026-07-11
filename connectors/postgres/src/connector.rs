use std::{net::SocketAddr, sync::Arc, time::Duration};

use dbx_rs_connector_sdk::{
    CollectionResult, ConnectionConfig, ConnectorError, ErrorClass, ProbeReport, ResolvedSecret,
    TlsMode, ValidationIssue, ValidationReport, ValidationSeverity,
};
use futures_util::TryStreamExt;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, pem::PemObject},
};
use tokio::net::{TcpStream, lookup_host};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};
use tokio_postgres::{Client, NoTls, config::SslMode, tls::MakeTlsConnect, types::ToSql};
use tokio_postgres_rustls::MakeRustlsConnect;
use tokio_util::sync::CancellationToken;

pub struct PostgresConnector;

pub struct JsonCollectionRequest {
    pub request_id: String,
    pub query: String,
    pub max_rows: u64,
    pub max_bytes: u64,
    pub timeout: Duration,
}

impl PostgresConnector {
    pub const CONNECTOR_ID: &'static str = "postgres";
    const MAX_JSON_COLLECTION_ROWS: u64 = 100_000;
    const MAX_JSON_COLLECTION_BYTES: u64 = 1024 * 1024 * 1024;

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
        let report = Self::validation_report(config);
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

    fn validation_report(config: &ConnectionConfig) -> ValidationReport {
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
        if config.connect_timeout.is_zero() {
            issues.push(validation_error(
                "DBX-RS-PG-CFG-0006",
                "connect_timeout",
                "connect_timeout must be greater than zero",
            ));
        }
        if config.probe_timeout.is_zero() {
            issues.push(validation_error(
                "DBX-RS-PG-CFG-0007",
                "probe_timeout",
                "probe_timeout must be greater than zero",
            ));
        }
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
        let deadline = Instant::now() + config.connect_timeout;

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
    ) -> Result<(Client, JoinHandle<()>, SocketAddr), ConnectorError> {
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
        Ok((client, connection_task, endpoint))
    }

    /// Streams a bounded read query as one UTF-8 JSON object per channel message.
    ///
    /// # Errors
    ///
    /// Returns a classified connector error when configuration, connection, query execution,
    /// conversion, cancellation, timeout, or output delivery fails.
    pub async fn collect_json_lines(
        &self,
        config: &ConnectionConfig,
        secret: &ResolvedSecret,
        request: JsonCollectionRequest,
        line_tx: mpsc::Sender<Vec<u8>>,
        cancellation: CancellationToken,
    ) -> Result<CollectionResult, ConnectorError> {
        let report = Self::validation_report(config);
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
        validate_collection_request(&request)?;
        let query = normalize_collection_query(&request.query, request.max_rows)?;
        let JsonCollectionRequest {
            request_id,
            max_bytes,
            timeout: collection_timeout,
            ..
        } = request;
        let (client, connection_task, _endpoint) =
            Self::open_client(config, secret, "dbx-rs/postgres-collection", &cancellation).await?;

        let collect = async {
            let (rows_read, bytes_read) =
                stream_json_lines(&client, &query, max_bytes, line_tx).await?;

            Ok(CollectionResult {
                request_id,
                rows_read,
                bytes_read,
            })
        };

        let result = tokio::select! {
            () = cancellation.cancelled() => {
                Err(ConnectorError::cancelled("DBX-RS-PG-CANCELLED-0010"))
            }
            result = timeout(collection_timeout, collect) => {
                result.map_err(|_| ConnectorError::new(
                    "DBX-RS-PG-QUERY-0010",
                    ErrorClass::Timeout,
                    "PostgreSQL collection timed out",
                    true,
                    false,
                ))?
            }
        };
        drop(client);
        connection_task.abort();
        result
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

fn validate_collection_request(request: &JsonCollectionRequest) -> Result<(), ConnectorError> {
    if request.request_id.trim().is_empty() {
        return Err(ConnectorError::new(
            "DBX-RS-PG-CFG-0012",
            ErrorClass::Configuration,
            "collection request ID is required",
            false,
            true,
        ));
    }
    if request.timeout.is_zero() {
        return Err(ConnectorError::new(
            "DBX-RS-PG-CFG-0013",
            ErrorClass::Configuration,
            "collection timeout must be greater than zero",
            false,
            true,
        ));
    }
    if !(1..=PostgresConnector::MAX_JSON_COLLECTION_BYTES).contains(&request.max_bytes) {
        return Err(ConnectorError::new(
            "DBX-RS-PG-CFG-0018",
            ErrorClass::Configuration,
            format!(
                "collection max_bytes must be between 1 and {}",
                PostgresConnector::MAX_JSON_COLLECTION_BYTES
            ),
            false,
            true,
        ));
    }
    Ok(())
}

async fn stream_json_lines(
    client: &Client,
    query: &str,
    max_bytes: u64,
    line_tx: mpsc::Sender<Vec<u8>>,
) -> Result<(u64, u64), ConnectorError> {
    client
        .batch_execute("BEGIN TRANSACTION READ ONLY")
        .await
        .map_err(|error| classify_query_error(&error))?;

    let parameters = std::iter::empty::<&(dyn ToSql + Sync)>();
    let (rows_read, bytes_read) = {
        let rows = client
            .query_raw(query, parameters)
            .await
            .map_err(|error| classify_query_error(&error))?;
        tokio::pin!(rows);

        let mut rows_read = 0_u64;
        let mut bytes_read = 0_u64;
        while let Some(row) = rows
            .try_next()
            .await
            .map_err(|error| classify_query_error(&error))?
        {
            let json = row.try_get::<_, String>(0).map_err(|_| {
                ConnectorError::new(
                    "DBX-RS-PG-CONVERT-0010",
                    ErrorClass::Conversion,
                    "PostgreSQL returned an invalid JSON row",
                    false,
                    false,
                )
            })?;
            let line = json.into_bytes();
            let next_bytes = bytes_read.saturating_add(line.len() as u64 + 1);
            if next_bytes > max_bytes {
                return Err(ConnectorError::new(
                    "DBX-RS-PG-LIMIT-0001",
                    ErrorClass::Query,
                    "PostgreSQL collection exceeded the configured byte limit",
                    false,
                    false,
                ));
            }
            bytes_read = next_bytes;
            rows_read = rows_read.saturating_add(1);
            line_tx.send(line).await.map_err(|_| {
                ConnectorError::new(
                    "DBX-RS-PG-OUTPUT-0001",
                    ErrorClass::Internal,
                    "JSON row receiver closed",
                    false,
                    false,
                )
            })?;
        }
        (rows_read, bytes_read)
    };

    client
        .batch_execute("COMMIT")
        .await
        .map_err(|error| classify_query_error(&error))?;
    Ok((rows_read, bytes_read))
}

fn validation_error(code: &str, field: &str, message: &str) -> ValidationIssue {
    ValidationIssue {
        code: code.into(),
        field: field.into(),
        message: message.into(),
        severity: ValidationSeverity::Error,
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

fn normalize_collection_query(query: &str, max_rows: u64) -> Result<String, ConnectorError> {
    if !(1..=PostgresConnector::MAX_JSON_COLLECTION_ROWS).contains(&max_rows) {
        return Err(ConnectorError::new(
            "DBX-RS-PG-CFG-0014",
            ErrorClass::Configuration,
            format!(
                "collection max_rows must be between 1 and {}",
                PostgresConnector::MAX_JSON_COLLECTION_ROWS
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

    Ok(format!(
        "SELECT row_to_json(dbx_rs_row)::text FROM ({query}) AS dbx_rs_row LIMIT {max_rows}"
    ))
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
        let report = PostgresConnector::validation_report(&config(TlsMode::Disable));

        assert!(report.is_valid());
    }

    #[test]
    fn verified_tls_is_valid() {
        let report = PostgresConnector::validation_report(&config(TlsMode::VerifyFull));

        assert!(report.is_valid());
    }

    #[test]
    fn weaker_tls_mode_fails_closed() {
        let report = PostgresConnector::validation_report(&config(TlsMode::Require));

        assert!(!report.is_valid());
        assert_eq!(report.issues[0].code, "DBX-RS-PG-CFG-0008");
    }

    #[test]
    fn malformed_custom_ca_is_rejected() {
        let mut config = config(TlsMode::VerifyFull);
        config.tls_ca_pem = Some(b"not a PEM certificate".to_vec());

        let report = PostgresConnector::validation_report(&config);

        assert!(!report.is_valid());
        assert_eq!(report.issues[0].code, "DBX-RS-PG-CFG-0011");
    }

    #[test]
    fn authentication_sql_state_is_classified_without_message_matching() {
        assert_eq!(
            error_class_for_sql_state("28P01"),
            ErrorClass::Authentication
        );
    }

    #[test]
    fn collection_query_is_wrapped_with_hard_row_limit() {
        let query = normalize_collection_query(" SELECT 1 AS value;\n", 25)
            .expect("read query must be accepted");

        assert_eq!(
            query,
            "SELECT row_to_json(dbx_rs_row)::text FROM (SELECT 1 AS value) AS dbx_rs_row LIMIT 25"
        );
    }

    #[test]
    fn collection_query_rejects_non_read_statement() {
        let error = normalize_collection_query("DELETE FROM events", 25)
            .expect_err("write query must be rejected");

        assert_eq!(error.code(), "DBX-RS-PG-CFG-0017");
    }

    #[test]
    fn collection_query_rejects_out_of_range_limit() {
        let error =
            normalize_collection_query("SELECT 1", PostgresConnector::MAX_JSON_COLLECTION_ROWS + 1)
                .expect_err("oversized limit must be rejected");

        assert_eq!(error.code(), "DBX-RS-PG-CFG-0014");
    }

    #[test]
    fn collection_request_rejects_out_of_range_byte_limit() {
        let request = JsonCollectionRequest {
            request_id: "test-request".into(),
            query: "SELECT 1".into(),
            max_rows: 1,
            max_bytes: PostgresConnector::MAX_JSON_COLLECTION_BYTES + 1,
            timeout: Duration::from_secs(1),
        };

        let error = validate_collection_request(&request)
            .expect_err("oversized byte limit must be rejected");

        assert_eq!(error.code(), "DBX-RS-PG-CFG-0018");
    }
}
