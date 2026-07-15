use std::{collections::BTreeSet, net::SocketAddr, time::Duration};

use dbx_rs_connector_sdk::{
    ArrowIpcBatch, AuthenticationMethod, CONNECTOR_CONTRACT_VERSION, ConnectionConfig, Connector,
    ConnectorCapability, ConnectorDescriptor, ConnectorError, ConnectorFuture,
    ConnectorSupportTier, ErrorClass, ExecuteRequest, ExecutionResult, PrepareRequest,
    PreparedQuery, ProbeReport, ProbeRequest, ResolvedSecret, TlsMode, ValidationIssue,
    ValidationReport, ValidationRequest, ValidationSeverity,
};
use mysql_async::{
    Conn, DriverError, Error as MySqlError, IoError, OptsBuilder, Row, ServerError, SslOpts, Value,
    prelude::Queryable,
};
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use tokio::{net::lookup_host, sync::mpsc, time::Instant};
use tokio_util::sync::CancellationToken;

mod sql;
mod typed;

const UNSUPPORTED_PRODUCT_MARKERS: &[&str] = &[
    "aurora",
    "memsql",
    "oceanbase",
    "polardb",
    "percona",
    "singlestore",
    "tidb",
    "vitess",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DatabaseProduct {
    MySql,
    MariaDb,
}

impl DatabaseProduct {
    const fn connector_id(self) -> &'static str {
        match self {
            Self::MySql => MySqlConnector::CONNECTOR_ID,
            Self::MariaDb => MariaDbConnector::CONNECTOR_ID,
        }
    }

    const fn family(self) -> &'static str {
        match self {
            Self::MySql => "mysql",
            Self::MariaDb => "mariadb",
        }
    }

    const fn display_name(self) -> &'static str {
        match self {
            Self::MySql => "MySQL",
            Self::MariaDb => "MariaDB",
        }
    }
}

pub(super) struct MySqlFamilyConnector;

impl MySqlFamilyConnector {
    pub(super) const MAX_COLLECTION_ROWS: u64 = 100_000;
    pub(super) const MAX_OPERATION_TIMEOUT: Duration = Duration::from_hours(24);
    pub(super) const MAX_QUERY_BYTES: usize = 1024 * 1024;
    pub(super) const MAX_TLS_CA_BYTES: usize = 1024 * 1024;
    pub(super) const MAX_REQUEST_ID_BYTES: usize = 256;
    pub(super) const MAX_CURSOR_FIELD_BYTES: usize = 63;
    const MAX_SECRET_BYTES: usize = 1024;
    const MAX_HOST_BYTES: usize = 253;
    const MAX_DATABASE_BYTES: usize = 1024;
    const MAX_USERNAME_BYTES: usize = 1024;
    const MAX_SERVER_TEXT_BYTES: usize = 4096;
    pub(super) const MAX_WIRE_PACKET_BYTES: usize = 1024 * 1024 + 64 * 1024;

    fn descriptor(product: DatabaseProduct) -> ConnectorDescriptor {
        ConnectorDescriptor {
            contract_version: CONNECTOR_CONTRACT_VERSION,
            connector_id: product.connector_id().into(),
            connector_version: env!("CARGO_PKG_VERSION").into(),
            database_families: vec![product.family().into()],
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

    fn validate_connection(
        product: DatabaseProduct,
        config: &ConnectionConfig,
    ) -> ValidationReport {
        let mut issues = Vec::new();
        if config.connector_id != product.connector_id() {
            issues.push(validation_error(
                "DBX-RS-MY-CFG-0001",
                "connector_id",
                "connector_id does not match the selected MySQL-family product",
            ));
        }
        if config.host.trim().is_empty() {
            issues.push(validation_error(
                "DBX-RS-MY-CFG-0002",
                "host",
                "host is required",
            ));
        } else if config.host.len() > Self::MAX_HOST_BYTES || !valid_server_name(&config.host) {
            issues.push(validation_error(
                "DBX-RS-MY-CFG-0044",
                "host",
                "host must be a valid bounded DNS name or IP address",
            ));
        }
        if config.port == 0 {
            issues.push(validation_error(
                "DBX-RS-MY-CFG-0003",
                "port",
                "port must be greater than zero",
            ));
        }
        if !valid_bounded_text(&config.database, Self::MAX_DATABASE_BYTES) {
            issues.push(validation_error(
                "DBX-RS-MY-CFG-0004",
                "database",
                "database is required and must contain bounded non-control text",
            ));
        }
        if !valid_bounded_text(&config.username, Self::MAX_USERNAME_BYTES) {
            issues.push(validation_error(
                "DBX-RS-MY-CFG-0005",
                "username",
                "username is required and must contain bounded non-control text",
            ));
        }
        issues.extend(timeout_issue(
            config.connect_timeout,
            "connect_timeout",
            "DBX-RS-MY-CFG-0006",
            "DBX-RS-MY-CFG-0012",
        ));
        issues.extend(timeout_issue(
            config.probe_timeout,
            "probe_timeout",
            "DBX-RS-MY-CFG-0007",
            "DBX-RS-MY-CFG-0013",
        ));
        validate_tls(config, &mut issues);
        ValidationReport { issues }
    }

    fn validate_operation(
        product: DatabaseProduct,
        config: &ConnectionConfig,
        secret: &ResolvedSecret,
    ) -> Result<(), ConnectorError> {
        let report = Self::validate_connection(product, config);
        if !report.is_valid() {
            return Err(ConnectorError::new(
                report
                    .issues
                    .first()
                    .map_or("DBX-RS-MY-CFG-0099", |issue| issue.code.as_str()),
                ErrorClass::Configuration,
                "MySQL-family connection configuration is invalid",
                false,
                true,
            ));
        }
        if secret.is_empty() {
            return Err(configuration_error(
                "DBX-RS-MY-AUTH-0001",
                "MySQL-family password is empty",
            ));
        }
        if secret.expose_secret().len() > Self::MAX_SECRET_BYTES {
            return Err(configuration_error(
                "DBX-RS-MY-CFG-0052",
                "MySQL-family password exceeds the connector hard limit",
            ));
        }
        if std::str::from_utf8(secret.expose_secret()).is_err() {
            return Err(configuration_error(
                "DBX-RS-MY-CFG-0051",
                "MySQL-family password must be valid UTF-8 for the native driver",
            ));
        }
        Ok(())
    }

    fn validate(product: DatabaseProduct, request: &ValidationRequest) -> ValidationReport {
        let mut report = Self::validate_connection(product, &request.connection);
        if let Some(query) = request.query.as_ref() {
            match request.max_rows {
                Some(max_rows) => {
                    let cursor = request.cursor.as_ref().map(|spec| {
                        dbx_rs_connector_sdk::TimestampIdCursorRequest {
                            spec: spec.clone(),
                            committed: None,
                            resume_after: None,
                        }
                    });
                    if let Err(error) =
                        sql::normalize_query(query.as_str(), max_rows, cursor.as_ref())
                    {
                        report.issues.push(ValidationIssue {
                            code: error.code().into(),
                            field: "query".into(),
                            message: "configured MySQL-family query is invalid".into(),
                            severity: ValidationSeverity::Error,
                        });
                    }
                }
                None => report.issues.push(validation_error(
                    "DBX-RS-MY-CFG-0029",
                    "max_rows",
                    "query validation requires max_rows",
                )),
            }
        } else if request.cursor.is_some() {
            report.issues.push(validation_error(
                "DBX-RS-MY-CFG-0030",
                "cursor",
                "cursor validation requires a query",
            ));
        }
        report
    }

    async fn probe(
        product: DatabaseProduct,
        request: ProbeRequest,
        secret: &ResolvedSecret,
        cancellation: CancellationToken,
    ) -> Result<ProbeReport, ConnectorError> {
        if !valid_request_id(&request.request_id) {
            return Err(configuration_error(
                "DBX-RS-MY-CFG-0053",
                "MySQL-family probe request ID is invalid or exceeds its hard limit",
            ));
        }
        Self::validate_operation(product, &request.connection, secret)?;
        let operation = open_session(
            product,
            &request.connection,
            secret,
            Self::MAX_WIRE_PACKET_BYTES,
            &cancellation,
        );
        let session = tokio::select! {
            () = cancellation.cancelled() => {
                return Err(ConnectorError::cancelled("DBX-RS-MY-CANCELLED-0002"));
            }
            result = tokio::time::timeout(request.connection.probe_timeout, operation) => {
                result.map_err(|_| ConnectorError::new(
                    "DBX-RS-MY-PROBE-0001",
                    ErrorClass::Timeout,
                    "MySQL-family probe timed out",
                    true,
                    false,
                ))??
            }
        };
        Ok(ProbeReport {
            connector_id: product.connector_id().into(),
            database_product: product.display_name().into(),
            server_version: session.server.version,
            server_version_number: pack_server_version(session.server.version_tuple),
            endpoint: session.endpoint.to_string(),
            tls_mode: request.connection.tls_mode,
        })
    }

    async fn prepare(
        product: DatabaseProduct,
        request: PrepareRequest,
        secret: &ResolvedSecret,
        cancellation: CancellationToken,
    ) -> Result<PreparedQuery, ConnectorError> {
        Self::validate_operation(product, &request.connection, secret)?;
        typed::prepare(product, request, secret, cancellation).await
    }

    async fn execute(
        product: DatabaseProduct,
        request: ExecuteRequest,
        secret: &ResolvedSecret,
        batch_tx: mpsc::Sender<ArrowIpcBatch>,
        cancellation: CancellationToken,
    ) -> Result<ExecutionResult, ConnectorError> {
        Self::validate_operation(product, &request.connection, secret)?;
        typed::execute(product, request, secret, batch_tx, cancellation).await
    }
}

pub struct MySqlConnector;

impl MySqlConnector {
    pub const CONNECTOR_ID: &'static str = "mysql";

    #[must_use]
    pub fn descriptor(&self) -> ConnectorDescriptor {
        MySqlFamilyConnector::descriptor(DatabaseProduct::MySql)
    }
}

impl Connector for MySqlConnector {
    fn descriptor(&self) -> ConnectorDescriptor {
        self.descriptor()
    }

    fn validate(&self, request: &ValidationRequest) -> ValidationReport {
        MySqlFamilyConnector::validate(DatabaseProduct::MySql, request)
    }

    fn probe<'a>(
        &'a self,
        request: ProbeRequest,
        secret: &'a ResolvedSecret,
        cancellation: CancellationToken,
    ) -> ConnectorFuture<'a, ProbeReport> {
        Box::pin(MySqlFamilyConnector::probe(
            DatabaseProduct::MySql,
            request,
            secret,
            cancellation,
        ))
    }

    fn prepare<'a>(
        &'a self,
        request: PrepareRequest,
        secret: &'a ResolvedSecret,
        cancellation: CancellationToken,
    ) -> ConnectorFuture<'a, PreparedQuery> {
        Box::pin(MySqlFamilyConnector::prepare(
            DatabaseProduct::MySql,
            request,
            secret,
            cancellation,
        ))
    }

    fn execute<'a>(
        &'a self,
        request: ExecuteRequest,
        secret: &'a ResolvedSecret,
        batch_tx: mpsc::Sender<ArrowIpcBatch>,
        cancellation: CancellationToken,
    ) -> ConnectorFuture<'a, ExecutionResult> {
        Box::pin(MySqlFamilyConnector::execute(
            DatabaseProduct::MySql,
            request,
            secret,
            batch_tx,
            cancellation,
        ))
    }
}

pub struct MariaDbConnector;

impl MariaDbConnector {
    pub const CONNECTOR_ID: &'static str = "mariadb";

    #[must_use]
    pub fn descriptor(&self) -> ConnectorDescriptor {
        MySqlFamilyConnector::descriptor(DatabaseProduct::MariaDb)
    }
}

impl Connector for MariaDbConnector {
    fn descriptor(&self) -> ConnectorDescriptor {
        self.descriptor()
    }

    fn validate(&self, request: &ValidationRequest) -> ValidationReport {
        MySqlFamilyConnector::validate(DatabaseProduct::MariaDb, request)
    }

    fn probe<'a>(
        &'a self,
        request: ProbeRequest,
        secret: &'a ResolvedSecret,
        cancellation: CancellationToken,
    ) -> ConnectorFuture<'a, ProbeReport> {
        Box::pin(MySqlFamilyConnector::probe(
            DatabaseProduct::MariaDb,
            request,
            secret,
            cancellation,
        ))
    }

    fn prepare<'a>(
        &'a self,
        request: PrepareRequest,
        secret: &'a ResolvedSecret,
        cancellation: CancellationToken,
    ) -> ConnectorFuture<'a, PreparedQuery> {
        Box::pin(MySqlFamilyConnector::prepare(
            DatabaseProduct::MariaDb,
            request,
            secret,
            cancellation,
        ))
    }

    fn execute<'a>(
        &'a self,
        request: ExecuteRequest,
        secret: &'a ResolvedSecret,
        batch_tx: mpsc::Sender<ArrowIpcBatch>,
        cancellation: CancellationToken,
    ) -> ConnectorFuture<'a, ExecutionResult> {
        Box::pin(MySqlFamilyConnector::execute(
            DatabaseProduct::MariaDb,
            request,
            secret,
            batch_tx,
            cancellation,
        ))
    }
}

pub(super) struct ConnectedSession {
    pub conn: Conn,
    server: ServerInfo,
    endpoint: SocketAddr,
}

struct ServerInfo {
    version: String,
    version_tuple: (u16, u16, u16),
}

pub(super) async fn open_session(
    product: DatabaseProduct,
    config: &ConnectionConfig,
    secret: &ResolvedSecret,
    max_packet_bytes: usize,
    cancellation: &CancellationToken,
) -> Result<ConnectedSession, ConnectorError> {
    let deadline = Instant::now()
        .checked_add(config.connect_timeout)
        .ok_or_else(|| {
            configuration_error(
                "DBX-RS-MY-CFG-0054",
                "MySQL-family connection timeout cannot be represented",
            )
        })?;
    let addresses = resolve(config, cancellation, deadline).await?;
    let mut last_tcp_error = None;

    for endpoint in addresses {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let connect = connect_endpoint(product, config, secret, endpoint, max_packet_bytes);
        let result = tokio::select! {
            () = cancellation.cancelled() => {
                return Err(ConnectorError::cancelled("DBX-RS-MY-CANCELLED-0001"));
            }
            result = tokio::time::timeout(remaining, connect) => result,
        };
        match result {
            Ok(Ok(session)) => return Ok(session),
            Ok(Err(error)) if error.class() == ErrorClass::Tcp => last_tcp_error = Some(error),
            Ok(Err(error)) => return Err(error),
            Err(_) => break,
        }
    }

    Err(last_tcp_error.unwrap_or_else(|| {
        ConnectorError::new(
            "DBX-RS-MY-CONNECT-0001",
            ErrorClass::Timeout,
            "MySQL-family connection or authentication timed out",
            true,
            false,
        )
    }))
}

async fn resolve(
    config: &ConnectionConfig,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<Vec<SocketAddr>, ConnectorError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(ConnectorError::new(
            "DBX-RS-MY-DNS-0001",
            ErrorClass::Timeout,
            "MySQL-family host resolution timed out",
            true,
            false,
        ));
    }
    let resolution = tokio::select! {
        () = cancellation.cancelled() => {
            return Err(ConnectorError::cancelled("DBX-RS-MY-CANCELLED-0001"));
        }
        result = tokio::time::timeout(
            remaining,
            lookup_host((config.host.as_str(), config.port)),
        ) => result,
    };
    let addresses = resolution
        .map_err(|_| {
            ConnectorError::new(
                "DBX-RS-MY-DNS-0001",
                ErrorClass::Timeout,
                "MySQL-family host resolution timed out",
                true,
                false,
            )
        })?
        .map_err(|_| {
            ConnectorError::new(
                "DBX-RS-MY-DNS-0002",
                ErrorClass::Dns,
                "MySQL-family host resolution failed",
                true,
                false,
            )
        })?
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(ConnectorError::new(
            "DBX-RS-MY-DNS-0003",
            ErrorClass::Dns,
            "MySQL-family host did not resolve to an address",
            true,
            false,
        ));
    }
    Ok(addresses)
}

async fn connect_endpoint(
    product: DatabaseProduct,
    config: &ConnectionConfig,
    secret: &ResolvedSecret,
    endpoint: SocketAddr,
    max_packet_bytes: usize,
) -> Result<ConnectedSession, ConnectorError> {
    let ssl_opts = match config.tls_mode {
        TlsMode::Disable => None,
        TlsMode::VerifyFull => {
            let mut ssl = SslOpts::default();
            if let Some(ca) = config.tls_ca_pem.clone() {
                ssl = ssl
                    .with_root_certs(vec![ca.into()])
                    .with_disable_built_in_roots(true);
            }
            if let Some(server_name) = config.tls_server_name.clone() {
                ssl = ssl.with_danger_tls_hostname_override(Some(server_name));
            }
            Some(ssl)
        }
        TlsMode::Require | TlsMode::VerifyCa => {
            return Err(configuration_error(
                "DBX-RS-MY-CFG-0008",
                "MySQL-family TLS mode is unsupported",
            ));
        }
    };
    let opts = OptsBuilder::default()
        .ip_or_hostname(config.host.clone())
        .resolved_ips(Some(vec![endpoint.ip()]))
        .tcp_port(config.port)
        .user(Some(config.username.clone()))
        .pass(Some(
            std::str::from_utf8(secret.expose_secret())
                .map_err(|_| {
                    configuration_error(
                        "DBX-RS-MY-CFG-0051",
                        "MySQL-family password must be valid UTF-8 for the native driver",
                    )
                })?
                .to_owned(),
        ))
        .db_name(Some(config.database.clone()))
        .prefer_socket(false)
        .stmt_cache_size(Some(8))
        .max_allowed_packet(Some(max_packet_bytes))
        .ssl_opts(ssl_opts);
    let mut conn = Conn::new(opts)
        .await
        .map_err(|error| classify_connect_error(&error, config.tls_mode))?;
    let version_tuple = conn.server_version();
    let server = configure_session(product, &mut conn, version_tuple).await?;
    Ok(ConnectedSession {
        conn,
        server,
        endpoint,
    })
}

async fn configure_session(
    product: DatabaseProduct,
    conn: &mut Conn,
    version_tuple: (u16, u16, u16),
) -> Result<ServerInfo, ConnectorError> {
    conn.query_drop("SET NAMES utf8mb4")
        .await
        .map_err(|error| classify_query_error(&error))?;
    conn.query_drop("SET SESSION time_zone = '+00:00'")
        .await
        .map_err(|error| classify_query_error(&error))?;
    conn.query_drop(
        "SET SESSION sql_mode = CONCAT_WS(',', NULLIF(@@SESSION.sql_mode, ''), 'NO_BACKSLASH_ESCAPES')",
    )
    .await
    .map_err(|error| classify_query_error(&error))?;
    let row = conn
        .query_first::<Row, _>(
            "SELECT VERSION(), @@version_comment, @@character_set_client, @@character_set_connection, @@character_set_results, @@time_zone, @@SESSION.sql_mode",
        )
        .await
        .map_err(|error| classify_query_error(&error))?
        .ok_or_else(|| protocol_error("DBX-RS-MY-PROTOCOL-0004", "MySQL-family server identity query returned no row"))?;
    let values = row.unwrap();
    if values.len() != 7 {
        return Err(protocol_error(
            "DBX-RS-MY-PROTOCOL-0005",
            "MySQL-family server identity query returned an invalid shape",
        ));
    }
    let version = strict_server_text(&values[0])?;
    let version_comment = strict_server_text(&values[1])?;
    let detected = detect_product(&version, &version_comment).ok_or_else(|| {
        configuration_error(
            "DBX-RS-MY-PRODUCT-0001",
            "server is not an identified MySQL or MariaDB product",
        )
    })?;
    if detected != product {
        return Err(configuration_error(
            "DBX-RS-MY-PRODUCT-0002",
            "server product does not match the configured connector",
        ));
    }
    for value in &values[2..5] {
        if !strict_server_text(value)?.eq_ignore_ascii_case("utf8mb4") {
            return Err(protocol_error(
                "DBX-RS-MY-PROTOCOL-0006",
                "MySQL-family session did not negotiate UTF8MB4",
            ));
        }
    }
    if strict_server_text(&values[5])? != "+00:00" {
        return Err(protocol_error(
            "DBX-RS-MY-PROTOCOL-0007",
            "MySQL-family session did not retain the UTC time zone",
        ));
    }
    if !strict_server_text(&values[6])?
        .split(',')
        .any(|mode| mode.eq_ignore_ascii_case("NO_BACKSLASH_ESCAPES"))
    {
        return Err(protocol_error(
            "DBX-RS-MY-PROTOCOL-0009",
            "MySQL-family session did not retain the required SQL mode",
        ));
    }
    Ok(ServerInfo {
        version,
        version_tuple,
    })
}

fn strict_server_text(value: &Value) -> Result<String, ConnectorError> {
    let Value::Bytes(bytes) = value else {
        return Err(protocol_error(
            "DBX-RS-MY-PROTOCOL-0008",
            "MySQL-family server identity contained an invalid value",
        ));
    };
    if bytes.is_empty() || bytes.len() > MySqlFamilyConnector::MAX_SERVER_TEXT_BYTES {
        return Err(protocol_error(
            "DBX-RS-MY-PROTOCOL-0008",
            "MySQL-family server identity contained an invalid value",
        ));
    }
    std::str::from_utf8(bytes).map(str::to_owned).map_err(|_| {
        protocol_error(
            "DBX-RS-MY-PROTOCOL-0008",
            "MySQL-family server identity contained malformed text",
        )
    })
}

fn detect_product(version: &str, comment: &str) -> Option<DatabaseProduct> {
    let version = version.to_ascii_lowercase();
    let comment = comment.to_ascii_lowercase();
    if UNSUPPORTED_PRODUCT_MARKERS
        .iter()
        .any(|marker| version.contains(marker) || comment.contains(marker))
    {
        return None;
    }
    if version.contains("mariadb") || comment.contains("mariadb") {
        return Some(DatabaseProduct::MariaDb);
    }
    (version.contains("mysql") || comment.contains("mysql")).then_some(DatabaseProduct::MySql)
}

fn pack_server_version(version: (u16, u16, u16)) -> Option<u32> {
    u32::from(version.0)
        .checked_mul(1_000_000)?
        .checked_add(u32::from(version.1).checked_mul(1_000)?)?
        .checked_add(u32::from(version.2))
}

fn validate_tls(config: &ConnectionConfig, issues: &mut Vec<ValidationIssue>) {
    match config.tls_mode {
        TlsMode::Disable => {
            if config.tls_server_name.is_some() || config.tls_ca_pem.is_some() {
                issues.push(validation_error(
                    "DBX-RS-MY-CFG-0009",
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
            if server_name.trim().is_empty() || !valid_server_name(server_name) {
                issues.push(validation_error(
                    "DBX-RS-MY-CFG-0010",
                    if config.tls_server_name.is_some() {
                        "tls_server_name"
                    } else {
                        "host"
                    },
                    "TLS server name must be a valid DNS name or IP address",
                ));
            }
            if let Some(pem) = config.tls_ca_pem.as_deref() {
                if pem.len() > MySqlFamilyConnector::MAX_TLS_CA_BYTES {
                    issues.push(validation_error(
                        "DBX-RS-MY-CFG-0055",
                        "tls_ca_pem",
                        "TLS CA data exceeds the connector hard limit",
                    ));
                } else if !valid_ca_pem(pem) {
                    issues.push(validation_error(
                        "DBX-RS-MY-CFG-0011",
                        "tls_ca_pem",
                        "TLS CA data must contain at least one usable PEM certificate",
                    ));
                }
            }
        }
        TlsMode::Require | TlsMode::VerifyCa => issues.push(validation_error(
            "DBX-RS-MY-CFG-0008",
            "tls_mode",
            "MySQL-family TLS modes without hostname verification are unsupported",
        )),
    }
}

fn valid_server_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MySqlFamilyConnector::MAX_HOST_BYTES
        && ServerName::try_from(name.to_owned()).is_ok()
}

fn valid_ca_pem(pem: &[u8]) -> bool {
    let mut count = 0_usize;
    for certificate in CertificateDer::pem_slice_iter(pem) {
        if certificate.is_err() {
            return false;
        }
        count += 1;
    }
    count > 0
}

fn valid_bounded_text(value: &str, max_bytes: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

fn valid_request_id(request_id: &str) -> bool {
    !request_id.trim().is_empty()
        && request_id.len() <= MySqlFamilyConnector::MAX_REQUEST_ID_BYTES
        && !request_id.chars().any(char::is_control)
}

fn timeout_issue(
    timeout: Duration,
    field: &'static str,
    zero_code: &'static str,
    maximum_code: &'static str,
) -> Vec<ValidationIssue> {
    if timeout.is_zero() {
        vec![validation_error(
            zero_code,
            field,
            "timeout must be greater than zero",
        )]
    } else if timeout > MySqlFamilyConnector::MAX_OPERATION_TIMEOUT {
        vec![validation_error(
            maximum_code,
            field,
            "timeout exceeds the connector hard limit",
        )]
    } else {
        Vec::new()
    }
}

fn validation_error(
    code: &'static str,
    field: &'static str,
    message: &'static str,
) -> ValidationIssue {
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

fn protocol_error(code: &'static str, message: &'static str) -> ConnectorError {
    ConnectorError::new(code, ErrorClass::Protocol, message, false, false)
}

fn classify_connect_error(error: &MySqlError, tls_mode: TlsMode) -> ConnectorError {
    match error {
        MySqlError::Server(server) if is_authentication_error(server) => ConnectorError::new(
            "DBX-RS-MY-AUTH-0002",
            ErrorClass::Authentication,
            "MySQL-family authentication failed",
            false,
            false,
        )
        .with_sql_state(server.state.clone()),
        MySqlError::Server(server) => ConnectorError::new(
            "DBX-RS-MY-PROTOCOL-0001",
            error_class_for_sql_state(&server.state),
            "MySQL-family connection negotiation failed",
            server.state.starts_with("08"),
            false,
        )
        .with_sql_state(server.state.clone()),
        MySqlError::Io(IoError::Tls(_)) => ConnectorError::new(
            "DBX-RS-MY-TLS-0001",
            ErrorClass::Tls,
            "MySQL-family TLS verification or negotiation failed",
            false,
            false,
        ),
        MySqlError::Io(IoError::Io(_)) => ConnectorError::new(
            "DBX-RS-MY-TCP-0001",
            ErrorClass::Tcp,
            "MySQL-family TCP connection failed",
            true,
            false,
        ),
        MySqlError::Driver(DriverError::NoClientSslFlagFromServer)
            if tls_mode == TlsMode::VerifyFull =>
        {
            ConnectorError::new(
                "DBX-RS-MY-TLS-0002",
                ErrorClass::Tls,
                "MySQL-family server does not support required TLS",
                false,
                false,
            )
        }
        MySqlError::Driver(
            DriverError::UnknownAuthPlugin { .. }
            | DriverError::MysqlOldPasswordDisabled
            | DriverError::CleartextPluginDisabled,
        ) => ConnectorError::new(
            "DBX-RS-MY-AUTH-0003",
            ErrorClass::Authentication,
            "MySQL-family authentication method is unsupported",
            false,
            false,
        ),
        _ => ConnectorError::new(
            "DBX-RS-MY-PROTOCOL-0002",
            ErrorClass::Protocol,
            "MySQL-family connection negotiation failed",
            true,
            false,
        ),
    }
}

pub(super) fn classify_query_error(error: &MySqlError) -> ConnectorError {
    match error {
        MySqlError::Server(server) => ConnectorError::new(
            "DBX-RS-MY-QUERY-0001",
            error_class_for_sql_state(&server.state),
            "MySQL-family query failed",
            server.state.starts_with("08") || matches!(server.code, 1205 | 1213),
            false,
        )
        .with_sql_state(server.state.clone()),
        MySqlError::Io(IoError::Tls(_)) => ConnectorError::new(
            "DBX-RS-MY-TLS-0003",
            ErrorClass::Tls,
            "MySQL-family TLS connection failed during query execution",
            true,
            false,
        ),
        MySqlError::Io(IoError::Io(_)) => ConnectorError::new(
            "DBX-RS-MY-TCP-0002",
            ErrorClass::Tcp,
            "MySQL-family TCP connection failed during query execution",
            true,
            false,
        ),
        _ => ConnectorError::new(
            "DBX-RS-MY-QUERY-0002",
            ErrorClass::Protocol,
            "MySQL-family query failed",
            true,
            false,
        ),
    }
}

fn is_authentication_error(error: &ServerError) -> bool {
    error.state.starts_with("28") || matches!(error.code, 1044 | 1045 | 1698)
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

    use dbx_rs_connector_sdk::{ConnectionConfig, QueryText, TlsMode, ValidationRequest};

    use super::*;

    fn config(connector_id: &str, tls_mode: TlsMode) -> ConnectionConfig {
        ConnectionConfig {
            connector_id: connector_id.into(),
            host: "database.example".into(),
            port: 3306,
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
    fn descriptors_keep_mysql_and_mariadb_distinct_and_experimental() {
        let mysql = MySqlConnector.descriptor();
        let mariadb = MariaDbConnector.descriptor();

        assert_eq!(mysql.connector_id, "mysql");
        assert_eq!(mysql.database_families, ["mysql"]);
        assert_eq!(mariadb.connector_id, "mariadb");
        assert_eq!(mariadb.database_families, ["mariadb"]);
        assert_eq!(mysql.support_tier, ConnectorSupportTier::ExperimentalNative);
        assert_eq!(
            mariadb.support_tier,
            ConnectorSupportTier::ExperimentalNative
        );
    }

    #[test]
    fn connector_id_and_weaker_tls_modes_fail_closed() {
        let mismatch = MySqlFamilyConnector::validate_connection(
            DatabaseProduct::MariaDb,
            &config("mysql", TlsMode::VerifyFull),
        );
        assert_eq!(mismatch.issues[0].code, "DBX-RS-MY-CFG-0001");

        let weak = MySqlFamilyConnector::validate_connection(
            DatabaseProduct::MySql,
            &config("mysql", TlsMode::Require),
        );
        assert!(
            weak.issues
                .iter()
                .any(|issue| issue.code == "DBX-RS-MY-CFG-0008")
        );
    }

    #[test]
    fn malformed_ca_and_unbounded_identity_fields_are_rejected() {
        let mut invalid = config("mysql", TlsMode::VerifyFull);
        invalid.tls_ca_pem = Some(b"not a certificate".to_vec());
        invalid.username = "x".repeat(MySqlFamilyConnector::MAX_USERNAME_BYTES + 1);

        let report = MySqlFamilyConnector::validate_connection(DatabaseProduct::MySql, &invalid);

        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.code == "DBX-RS-MY-CFG-0011")
        );
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.code == "DBX-RS-MY-CFG-0005")
        );
    }

    #[test]
    fn product_detection_rejects_cross_product_and_unidentified_forks() {
        assert_eq!(
            detect_product("8.4.0", "MySQL Community Server - GPL"),
            Some(DatabaseProduct::MySql)
        );
        assert_eq!(
            detect_product("10.11.8-MariaDB", "mariadb.org binary distribution"),
            Some(DatabaseProduct::MariaDb)
        );
        assert_eq!(detect_product("8.0.36-28", "Percona Server (GPL)"), None);
        assert_eq!(detect_product("8.0.11-TiDB", "TiDB Server"), None);
        assert_eq!(
            detect_product("8.0.mysql_aurora.3.08.2", "MySQL Community Server"),
            None
        );
        assert_eq!(detect_product("8.0.36", "Source distribution"), None);
    }

    #[test]
    fn server_errors_are_classified_without_forwarding_details() {
        let error = MySqlError::Server(ServerError {
            code: 1045,
            state: "28000".into(),
            message: "access denied for secret-user with secret-password".into(),
        });
        let classified = classify_connect_error(&error, TlsMode::VerifyFull);

        assert_eq!(classified.class(), ErrorClass::Authentication);
        assert!(!classified.to_string().contains("secret-user"));
        assert!(!classified.to_string().contains("secret-password"));
    }

    #[test]
    fn validation_applies_cursor_query_semantics_offline() {
        let connector = MySqlConnector;
        let request = ValidationRequest {
            connection: config("mysql", TlsMode::Disable),
            query: Some(QueryText::new("SELECT * FROM sample LIMIT 1")),
            max_rows: Some(10),
            cursor: Some(dbx_rs_connector_sdk::TimestampIdCursorSpec {
                timestamp_field: "updated_at".into(),
                id_field: "id".into(),
                overlap: Duration::ZERO,
                null_policy: dbx_rs_connector_sdk::CursorNullPolicy::Reject,
            }),
        };

        let report = connector.validate(&request);

        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.code == "DBX-RS-MY-CFG-0050")
        );
    }

    #[test]
    fn server_versions_pack_without_cross_product_assumptions() {
        assert_eq!(pack_server_version((8, 4, 1)), Some(8_004_001));
        assert_eq!(pack_server_version((11, 7, 2)), Some(11_007_002));
    }
}
