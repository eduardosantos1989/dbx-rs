use std::{collections::BTreeSet, net::SocketAddr, time::Duration};

use dbx_rs_connector_sdk::{
    ArrowIpcBatch, AuthenticationMethod, CONNECTOR_CONTRACT_VERSION, ConnectionConfig, Connector,
    ConnectorCapability, ConnectorDescriptor, ConnectorError, ConnectorFuture,
    ConnectorSupportTier, ErrorClass, ExecuteRequest, ExecutionResult, PrepareRequest,
    PreparedQuery, ProbeReport, ProbeRequest, ResolvedSecret, TlsMode, ValidationIssue,
    ValidationReport, ValidationRequest, ValidationSeverity,
};
use mssql_client::{
    ApplicationIntent, Client, Config, Credentials, Error as MssqlError, Ready, RedirectConfig,
    RetryPolicy, TimeoutConfig, TlsConfig,
};
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use tokio::{net::lookup_host, sync::mpsc, time::Instant};
use tokio_util::sync::CancellationToken;

mod sql;
mod typed;

pub struct MssqlConnector;

impl MssqlConnector {
    pub const CONNECTOR_ID: &'static str = "mssql";
    pub(super) const MAX_COLLECTION_ROWS: u64 = 100_000;
    pub(super) const MAX_OPERATION_TIMEOUT: Duration = Duration::from_hours(24);
    pub(super) const MAX_QUERY_BYTES: usize = 1024 * 1024;
    pub(super) const MAX_TLS_CA_BYTES: usize = 1024 * 1024;
    pub(super) const MAX_REQUEST_ID_BYTES: usize = 256;
    pub(super) const MAX_CURSOR_FIELD_BYTES: usize = 128;
    const MAX_SECRET_BYTES: usize = 1024;
    const MAX_HOST_BYTES: usize = 253;
    const MAX_TDS_TEXT_UNITS: usize = 128;
    const MAX_SERVER_TEXT_BYTES: usize = 4096;
    const MAX_WIRE_MESSAGE_BYTES: usize = 2 * 1024 * 1024;

    #[must_use]
    pub fn descriptor(&self) -> ConnectorDescriptor {
        ConnectorDescriptor {
            contract_version: CONNECTOR_CONTRACT_VERSION,
            connector_id: Self::CONNECTOR_ID.into(),
            connector_version: env!("CARGO_PKG_VERSION").into(),
            database_families: vec!["microsoft_sql_server".into()],
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

    fn validate_connection(config: &ConnectionConfig) -> ValidationReport {
        let mut issues = Vec::new();
        if config.connector_id != Self::CONNECTOR_ID {
            issues.push(validation_error(
                "DBX-RS-MS-CFG-0001",
                "connector_id",
                "connector_id does not select the SQL Server connector",
            ));
        }
        if config.host.trim().is_empty() {
            issues.push(validation_error(
                "DBX-RS-MS-CFG-0002",
                "host",
                "host is required",
            ));
        } else if config.host.len() > Self::MAX_HOST_BYTES || !valid_server_name(&config.host) {
            issues.push(validation_error(
                "DBX-RS-MS-CFG-0044",
                "host",
                "host must be a valid bounded DNS name or IP address",
            ));
        }
        if config.port == 0 {
            issues.push(validation_error(
                "DBX-RS-MS-CFG-0003",
                "port",
                "port must be greater than zero",
            ));
        }
        if !valid_tds_text(&config.database) {
            issues.push(validation_error(
                "DBX-RS-MS-CFG-0004",
                "database",
                "database is required and exceeds the SQL Server identifier envelope",
            ));
        }
        if !valid_tds_text(&config.username) {
            issues.push(validation_error(
                "DBX-RS-MS-CFG-0005",
                "username",
                "username is required and exceeds the SQL Server login envelope",
            ));
        }
        issues.extend(timeout_issue(
            config.connect_timeout,
            "connect_timeout",
            "DBX-RS-MS-CFG-0006",
            "DBX-RS-MS-CFG-0012",
        ));
        issues.extend(timeout_issue(
            config.probe_timeout,
            "probe_timeout",
            "DBX-RS-MS-CFG-0007",
            "DBX-RS-MS-CFG-0013",
        ));
        validate_tls(config, &mut issues);
        ValidationReport { issues }
    }

    pub(super) fn validate_operation(
        config: &ConnectionConfig,
        secret: &ResolvedSecret,
    ) -> Result<(), ConnectorError> {
        let report = Self::validate_connection(config);
        if !report.is_valid() {
            return Err(ConnectorError::new(
                report
                    .issues
                    .first()
                    .map_or("DBX-RS-MS-CFG-0099", |issue| issue.code.as_str()),
                ErrorClass::Configuration,
                "SQL Server connection configuration is invalid",
                false,
                true,
            ));
        }
        if secret.is_empty() {
            return Err(configuration_error(
                "DBX-RS-MS-AUTH-0001",
                "SQL Server password is empty",
            ));
        }
        if secret.expose_secret().len() > Self::MAX_SECRET_BYTES {
            return Err(configuration_error(
                "DBX-RS-MS-CFG-0052",
                "SQL Server password exceeds the connector hard limit",
            ));
        }
        let password = std::str::from_utf8(secret.expose_secret()).map_err(|_| {
            configuration_error(
                "DBX-RS-MS-CFG-0051",
                "SQL Server password must be valid UTF-8 for the native driver",
            )
        })?;
        if password.encode_utf16().count() > Self::MAX_TDS_TEXT_UNITS {
            return Err(configuration_error(
                "DBX-RS-MS-CFG-0052",
                "SQL Server password exceeds the SQL login envelope",
            ));
        }
        Ok(())
    }

    fn validate(request: &ValidationRequest) -> ValidationReport {
        let mut report = Self::validate_connection(&request.connection);
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
                            message: "configured SQL Server query is invalid".into(),
                            severity: ValidationSeverity::Error,
                        });
                    }
                }
                None => report.issues.push(validation_error(
                    "DBX-RS-MS-CFG-0029",
                    "max_rows",
                    "query validation requires max_rows",
                )),
            }
        } else if request.cursor.is_some() {
            report.issues.push(validation_error(
                "DBX-RS-MS-CFG-0030",
                "cursor",
                "cursor validation requires a query",
            ));
        }
        report
    }

    async fn probe_inner(
        request: ProbeRequest,
        secret: &ResolvedSecret,
        cancellation: CancellationToken,
    ) -> Result<ProbeReport, ConnectorError> {
        if !valid_request_id(&request.request_id) {
            return Err(configuration_error(
                "DBX-RS-MS-CFG-0053",
                "SQL Server probe request ID is invalid or exceeds its hard limit",
            ));
        }
        Self::validate_operation(&request.connection, secret)?;
        let session = open_session(
            &request.connection,
            secret,
            request.connection.probe_timeout,
            Self::MAX_WIRE_MESSAGE_BYTES,
            &cancellation,
        )
        .await?;
        Ok(ProbeReport {
            connector_id: Self::CONNECTOR_ID.into(),
            database_product: "Microsoft SQL Server".into(),
            server_version: session.server.version,
            server_version_number: pack_server_version(session.server.version_tuple),
            endpoint: session.endpoint.to_string(),
            tls_mode: request.connection.tls_mode,
        })
    }
}

impl Connector for MssqlConnector {
    fn descriptor(&self) -> ConnectorDescriptor {
        self.descriptor()
    }

    fn validate(&self, request: &ValidationRequest) -> ValidationReport {
        Self::validate(request)
    }

    fn probe<'a>(
        &'a self,
        request: ProbeRequest,
        secret: &'a ResolvedSecret,
        cancellation: CancellationToken,
    ) -> ConnectorFuture<'a, ProbeReport> {
        Box::pin(Self::probe_inner(request, secret, cancellation))
    }

    fn prepare<'a>(
        &'a self,
        request: PrepareRequest,
        secret: &'a ResolvedSecret,
        cancellation: CancellationToken,
    ) -> ConnectorFuture<'a, PreparedQuery> {
        Box::pin(typed::prepare(request, secret, cancellation))
    }

    fn execute<'a>(
        &'a self,
        request: ExecuteRequest,
        secret: &'a ResolvedSecret,
        batch_tx: mpsc::Sender<ArrowIpcBatch>,
        cancellation: CancellationToken,
    ) -> ConnectorFuture<'a, ExecutionResult> {
        Box::pin(typed::execute(request, secret, batch_tx, cancellation))
    }
}

pub(super) struct ConnectedSession {
    pub client: Client<Ready>,
    server: ServerInfo,
    endpoint: SocketAddr,
}

struct ServerInfo {
    version: String,
    version_tuple: (u16, u16, u16),
}

pub(super) async fn open_session(
    config: &ConnectionConfig,
    secret: &ResolvedSecret,
    command_timeout: Duration,
    max_response_bytes: usize,
    cancellation: &CancellationToken,
) -> Result<ConnectedSession, ConnectorError> {
    let deadline = Instant::now()
        .checked_add(config.connect_timeout)
        .ok_or_else(|| {
            configuration_error(
                "DBX-RS-MS-CFG-0054",
                "SQL Server connection timeout cannot be represented",
            )
        })?;
    let addresses = resolve(config, cancellation, deadline).await?;
    let mut last_tcp_error = None;

    for endpoint in addresses {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let driver_config = driver_config(
            config,
            secret,
            endpoint,
            remaining,
            command_timeout,
            max_response_bytes,
        )?;
        let result = tokio::select! {
            () = cancellation.cancelled() => {
                return Err(ConnectorError::cancelled("DBX-RS-MS-CANCELLED-0001"));
            }
            result = tokio::time::timeout(remaining, Client::connect(driver_config)) => result,
        };
        match result {
            Ok(Ok(mut client)) => {
                let server = identify_server(&mut client, config, cancellation).await?;
                return Ok(ConnectedSession {
                    client,
                    server,
                    endpoint,
                });
            }
            Ok(Err(error)) => {
                let error = classify_connect_error(&error, config.tls_mode);
                if error.class() == ErrorClass::Tcp {
                    last_tcp_error = Some(error);
                } else {
                    return Err(error);
                }
            }
            Err(_) => break,
        }
    }

    Err(last_tcp_error.unwrap_or_else(|| {
        ConnectorError::new(
            "DBX-RS-MS-CONNECT-0001",
            ErrorClass::Timeout,
            "SQL Server connection or authentication timed out",
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
            "DBX-RS-MS-DNS-0001",
            ErrorClass::Timeout,
            "SQL Server host resolution timed out",
            true,
            false,
        ));
    }
    let resolution = tokio::select! {
        () = cancellation.cancelled() => {
            return Err(ConnectorError::cancelled("DBX-RS-MS-CANCELLED-0001"));
        }
        result = tokio::time::timeout(
            remaining,
            lookup_host((config.host.as_str(), config.port)),
        ) => result,
    };
    let addresses = resolution
        .map_err(|_| {
            ConnectorError::new(
                "DBX-RS-MS-DNS-0001",
                ErrorClass::Timeout,
                "SQL Server host resolution timed out",
                true,
                false,
            )
        })?
        .map_err(|_| {
            ConnectorError::new(
                "DBX-RS-MS-DNS-0002",
                ErrorClass::Dns,
                "SQL Server host resolution failed",
                true,
                false,
            )
        })?
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(ConnectorError::new(
            "DBX-RS-MS-DNS-0003",
            ErrorClass::Dns,
            "SQL Server host did not resolve to an address",
            true,
            false,
        ));
    }
    Ok(addresses)
}

fn driver_config(
    connection: &ConnectionConfig,
    secret: &ResolvedSecret,
    endpoint: SocketAddr,
    connect_timeout: Duration,
    command_timeout: Duration,
    max_response_bytes: usize,
) -> Result<Config, ConnectorError> {
    let password = std::str::from_utf8(secret.expose_secret()).map_err(|_| {
        configuration_error(
            "DBX-RS-MS-CFG-0051",
            "SQL Server password must be valid UTF-8 for the native driver",
        )
    })?;
    let mut config = Config::new();
    config.host = endpoint.ip().to_string();
    config.port = endpoint.port();
    config.database = Some(connection.database.clone());
    config.credentials = Credentials::sql_server(connection.username.clone(), password.to_owned());
    config.application_name = "dbx-rs/mssql".into();
    config.connect_timeout = connect_timeout;
    config.command_timeout = command_timeout;
    config.max_response_size = max_response_bytes;
    config.packet_size = 8192;
    config.strict_mode = false;
    config.trust_server_certificate = false;
    config.instance = None;
    config.mars = false;
    config.redirect = RedirectConfig::no_follow();
    config.retry = RetryPolicy::no_retry();
    config.timeouts = TimeoutConfig::new()
        .connect_timeout(connect_timeout)
        .tls_timeout(connect_timeout)
        .login_timeout(connect_timeout)
        .command_timeout(command_timeout)
        .no_keepalive();
    config.application_intent = ApplicationIntent::ReadOnly;
    config.workstation_id = Some("dbx-rs".into());
    config.language = Some("us_english".into());
    config.multi_subnet_failover = false;
    config.send_string_parameters_as_unicode = true;
    config.statement_cache = false;
    match connection.tls_mode {
        TlsMode::Disable => {
            config.encrypt = false;
            config.no_tls = true;
        }
        TlsMode::VerifyFull => {
            config.encrypt = true;
            config.no_tls = false;
            let server_name = connection
                .tls_server_name
                .as_deref()
                .unwrap_or(connection.host.as_str());
            let mut tls = TlsConfig::new().with_server_name(server_name);
            if let Some(pem) = connection.tls_ca_pem.as_deref() {
                tls = tls.with_root_certificates(parse_ca_pem(pem)?);
            }
            config.tls = tls;
        }
        TlsMode::Require | TlsMode::VerifyCa => {
            return Err(configuration_error(
                "DBX-RS-MS-CFG-0008",
                "SQL Server TLS mode is unsupported",
            ));
        }
    }
    Ok(config)
}

async fn identify_server(
    client: &mut Client<Ready>,
    config: &ConnectionConfig,
    cancellation: &CancellationToken,
) -> Result<ServerInfo, ConnectorError> {
    const IDENTITY_QUERY: &str = "SELECT CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductVersion')) AS [product_version], CONVERT(nvarchar(128), SERVERPROPERTY(N'Edition')) AS [edition], CONVERT(int, SERVERPROPERTY(N'EngineEdition')) AS [engine_edition], CONVERT(nvarchar(128), DB_NAME()) AS [database_name]";
    let operation = async {
        let mut rows = client
            .query_stream(IDENTITY_QUERY, &[])
            .await
            .map_err(|error| classify_query_error(&error))?;
        let row = rows
            .try_next()
            .await
            .map_err(|error| classify_query_error(&error))?
            .ok_or_else(|| {
                protocol_error(
                    "DBX-RS-MS-PROTOCOL-0004",
                    "SQL Server identity query returned no row",
                )
            })?;
        if rows
            .try_next()
            .await
            .map_err(|error| classify_query_error(&error))?
            .is_some()
        {
            return Err(protocol_error(
                "DBX-RS-MS-PROTOCOL-0005",
                "SQL Server identity query returned an invalid shape",
            ));
        }
        let version = strict_server_text(&row, 0)?;
        let _edition = strict_server_text(&row, 1)?;
        let engine_edition = row
            .try_get::<i32>(2)
            .map_err(|_| {
                protocol_error(
                    "DBX-RS-MS-PROTOCOL-0006",
                    "SQL Server identity contained an invalid engine edition",
                )
            })?
            .ok_or_else(|| {
                protocol_error(
                    "DBX-RS-MS-PROTOCOL-0006",
                    "SQL Server identity contained an invalid engine edition",
                )
            })?;
        let database = strict_server_text(&row, 3)?;
        if !matches!(engine_edition, 2..=4) {
            return Err(configuration_error(
                "DBX-RS-MS-PRODUCT-0001",
                "server is outside the supported standalone SQL Server product boundary",
            ));
        }
        if !database.eq_ignore_ascii_case(&config.database) {
            return Err(configuration_error(
                "DBX-RS-MS-PRODUCT-0002",
                "SQL Server session did not select the configured database",
            ));
        }
        let version_tuple = parse_server_version(&version)?;
        Ok(ServerInfo {
            version,
            version_tuple,
        })
    };
    tokio::select! {
        () = cancellation.cancelled() => {
            Err(ConnectorError::cancelled("DBX-RS-MS-CANCELLED-0002"))
        }
        result = operation => result,
    }
}

fn strict_server_text(row: &mssql_client::Row, index: usize) -> Result<String, ConnectorError> {
    let value = row
        .try_get::<String>(index)
        .map_err(|_| {
            protocol_error(
                "DBX-RS-MS-PROTOCOL-0007",
                "SQL Server identity contained malformed text",
            )
        })?
        .ok_or_else(|| {
            protocol_error(
                "DBX-RS-MS-PROTOCOL-0007",
                "SQL Server identity contained invalid text",
            )
        })?;
    if value.is_empty() || value.len() > MssqlConnector::MAX_SERVER_TEXT_BYTES {
        return Err(protocol_error(
            "DBX-RS-MS-PROTOCOL-0007",
            "SQL Server identity contained invalid text",
        ));
    }
    Ok(value)
}

fn parse_server_version(version: &str) -> Result<(u16, u16, u16), ConnectorError> {
    let mut components = version.split('.');
    let parse = |value: Option<&str>| {
        value
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| {
                protocol_error(
                    "DBX-RS-MS-PROTOCOL-0008",
                    "SQL Server reported an invalid product version",
                )
            })
    };
    let parsed = (
        parse(components.next())?,
        parse(components.next())?,
        parse(components.next())?,
    );
    let _revision = parse(components.next())?;
    if components.next().is_some() {
        return Err(protocol_error(
            "DBX-RS-MS-PROTOCOL-0008",
            "SQL Server reported an invalid product version",
        ));
    }
    Ok(parsed)
}

fn pack_server_version(version: (u16, u16, u16)) -> Option<u32> {
    u32::from(version.0)
        .checked_mul(1_000_000)?
        .checked_add(u32::from(version.1).checked_mul(10_000)?)?
        .checked_add(u32::from(version.2))
}

fn validate_tls(config: &ConnectionConfig, issues: &mut Vec<ValidationIssue>) {
    match config.tls_mode {
        TlsMode::Disable => {
            if config.tls_server_name.is_some() || config.tls_ca_pem.is_some() {
                issues.push(validation_error(
                    "DBX-RS-MS-CFG-0009",
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
            if !valid_server_name(server_name) {
                issues.push(validation_error(
                    "DBX-RS-MS-CFG-0010",
                    if config.tls_server_name.is_some() {
                        "tls_server_name"
                    } else {
                        "host"
                    },
                    "TLS server name must be a valid DNS name or IP address",
                ));
            }
            if let Some(pem) = config.tls_ca_pem.as_deref() {
                if pem.len() > MssqlConnector::MAX_TLS_CA_BYTES {
                    issues.push(validation_error(
                        "DBX-RS-MS-CFG-0055",
                        "tls_ca_pem",
                        "TLS CA data exceeds the connector hard limit",
                    ));
                } else if parse_ca_pem(pem).is_err() {
                    issues.push(validation_error(
                        "DBX-RS-MS-CFG-0011",
                        "tls_ca_pem",
                        "TLS CA data must contain at least one usable PEM certificate",
                    ));
                }
            }
        }
        TlsMode::Require | TlsMode::VerifyCa => issues.push(validation_error(
            "DBX-RS-MS-CFG-0008",
            "tls_mode",
            "SQL Server TLS modes without hostname verification are unsupported",
        )),
    }
}

fn valid_server_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MssqlConnector::MAX_HOST_BYTES
        && ServerName::try_from(name.to_owned()).is_ok()
}

fn parse_ca_pem(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, ConnectorError> {
    let certificates = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            configuration_error(
                "DBX-RS-MS-CFG-0011",
                "TLS CA data must contain usable PEM certificates",
            )
        })?;
    if certificates.is_empty() {
        return Err(configuration_error(
            "DBX-RS-MS-CFG-0011",
            "TLS CA data must contain usable PEM certificates",
        ));
    }
    Ok(certificates)
}

fn valid_tds_text(value: &str) -> bool {
    !value.trim().is_empty()
        && value.encode_utf16().count() <= MssqlConnector::MAX_TDS_TEXT_UNITS
        && !value.chars().any(char::is_control)
}

fn valid_request_id(request_id: &str) -> bool {
    !request_id.trim().is_empty()
        && request_id.len() <= MssqlConnector::MAX_REQUEST_ID_BYTES
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
    } else if timeout > MssqlConnector::MAX_OPERATION_TIMEOUT {
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

fn classify_connect_error(error: &MssqlError, tls_mode: TlsMode) -> ConnectorError {
    match error {
        MssqlError::Authentication(_) => authentication_error(),
        MssqlError::Server { number, .. } if is_authentication_error(*number) => {
            authentication_error()
        }
        MssqlError::Tls(_) => ConnectorError::new(
            "DBX-RS-MS-TLS-0001",
            ErrorClass::Tls,
            "SQL Server TLS verification or negotiation failed",
            false,
            false,
        ),
        MssqlError::TlsTimeout { .. } => ConnectorError::new(
            "DBX-RS-MS-TLS-0002",
            ErrorClass::Tls,
            "SQL Server TLS negotiation timed out",
            true,
            false,
        ),
        MssqlError::ConnectTimeout { .. } | MssqlError::LoginTimeout { .. } => ConnectorError::new(
            "DBX-RS-MS-CONNECT-0001",
            ErrorClass::Timeout,
            "SQL Server connection or authentication timed out",
            true,
            false,
        ),
        MssqlError::Io(_) | MssqlError::Connection(_) | MssqlError::ConnectionClosed => {
            ConnectorError::new(
                "DBX-RS-MS-TCP-0001",
                ErrorClass::Tcp,
                "SQL Server TCP connection failed",
                true,
                false,
            )
        }
        MssqlError::Config(_) if tls_mode == TlsMode::Disable => ConnectorError::new(
            "DBX-RS-MS-TLS-0003",
            ErrorClass::Tls,
            "SQL Server requires TLS but the connection explicitly disables it",
            false,
            false,
        ),
        MssqlError::Server { .. }
        | MssqlError::ProtocolError(_)
        | MssqlError::Protocol(_)
        | MssqlError::Codec(_)
        | MssqlError::Routing { .. }
        | MssqlError::TooManyRedirects { .. } => ConnectorError::new(
            "DBX-RS-MS-PROTOCOL-0001",
            ErrorClass::Protocol,
            "SQL Server connection negotiation failed",
            error.is_transient(),
            false,
        ),
        _ => ConnectorError::new(
            "DBX-RS-MS-PROTOCOL-0002",
            ErrorClass::Protocol,
            "SQL Server connection negotiation failed",
            error.is_transient(),
            false,
        ),
    }
}

pub(super) fn classify_query_error(error: &MssqlError) -> ConnectorError {
    match error {
        MssqlError::Server { number, .. } if is_authentication_error(*number) => {
            authentication_error()
        }
        MssqlError::Server { .. } | MssqlError::Query(_) => ConnectorError::new(
            "DBX-RS-MS-QUERY-0001",
            ErrorClass::Query,
            "SQL Server query failed",
            error.is_transient(),
            false,
        ),
        MssqlError::CommandTimeout => ConnectorError::new(
            "DBX-RS-MS-QUERY-0002",
            ErrorClass::Timeout,
            "SQL Server query timed out",
            true,
            false,
        ),
        MssqlError::Cancelled | MssqlError::Cancel(_) => {
            ConnectorError::cancelled("DBX-RS-MS-CANCELLED-0022")
        }
        MssqlError::Tls(_) | MssqlError::TlsTimeout { .. } => ConnectorError::new(
            "DBX-RS-MS-TLS-0004",
            ErrorClass::Tls,
            "SQL Server TLS connection failed during query execution",
            true,
            false,
        ),
        MssqlError::Io(_) | MssqlError::Connection(_) | MssqlError::ConnectionClosed => {
            ConnectorError::new(
                "DBX-RS-MS-TCP-0002",
                ErrorClass::Tcp,
                "SQL Server TCP connection failed during query execution",
                true,
                false,
            )
        }
        MssqlError::Type(_) => ConnectorError::new(
            "DBX-RS-MS-CONVERT-0001",
            ErrorClass::Conversion,
            "SQL Server value could not be converted without loss",
            false,
            false,
        ),
        MssqlError::ResponseTooLarge { .. } => ConnectorError::new(
            "DBX-RS-MS-LIMIT-0001",
            ErrorClass::Query,
            "SQL Server response exceeded the connector wire limit",
            false,
            false,
        ),
        MssqlError::ProtocolError(_) | MssqlError::Protocol(_) | MssqlError::Codec(_) => {
            ConnectorError::new(
                "DBX-RS-MS-PROTOCOL-0003",
                ErrorClass::Protocol,
                "SQL Server query response violated the protocol contract",
                true,
                false,
            )
        }
        _ => ConnectorError::new(
            "DBX-RS-MS-QUERY-0003",
            ErrorClass::Protocol,
            "SQL Server query failed",
            error.is_transient(),
            false,
        ),
    }
}

fn authentication_error() -> ConnectorError {
    ConnectorError::new(
        "DBX-RS-MS-AUTH-0002",
        ErrorClass::Authentication,
        "SQL Server authentication failed",
        false,
        false,
    )
}

const fn is_authentication_error(number: i32) -> bool {
    matches!(number, 4060 | 18_450 | 18_452 | 18_456)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use dbx_rs_connector_sdk::{ConnectorSupportTier, QueryText};

    use super::*;

    fn config(tls_mode: TlsMode) -> ConnectionConfig {
        ConnectionConfig {
            connector_id: MssqlConnector::CONNECTOR_ID.into(),
            host: "database.example".into(),
            port: 1433,
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
    fn descriptor_is_explicitly_experimental_and_password_only() {
        let descriptor = MssqlConnector.descriptor();

        assert_eq!(descriptor.connector_id, "mssql");
        assert_eq!(descriptor.database_families, ["microsoft_sql_server"]);
        assert_eq!(
            descriptor.support_tier,
            ConnectorSupportTier::ExperimentalNative
        );
        assert_eq!(
            descriptor.authentication_methods,
            [AuthenticationMethod::Password]
        );
    }

    #[test]
    fn connector_id_and_weaker_tls_modes_fail_closed() {
        let mut mismatch = config(TlsMode::VerifyFull);
        mismatch.connector_id = "postgres".into();
        assert_eq!(
            MssqlConnector::validate_connection(&mismatch).issues[0].code,
            "DBX-RS-MS-CFG-0001"
        );

        for mode in [TlsMode::Require, TlsMode::VerifyCa] {
            let report = MssqlConnector::validate_connection(&config(mode));
            assert!(
                report
                    .issues
                    .iter()
                    .any(|issue| issue.code == "DBX-RS-MS-CFG-0008")
            );
        }
    }

    #[test]
    fn plaintext_rejects_stale_tls_material() {
        let mut connection = config(TlsMode::Disable);
        connection.tls_server_name = Some("database.example".into());

        let report = MssqlConnector::validate_connection(&connection);

        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.code == "DBX-RS-MS-CFG-0009")
        );
    }

    #[test]
    fn validation_checks_query_before_network_access() {
        let report = MssqlConnector.validate(&ValidationRequest {
            connection: config(TlsMode::Disable),
            query: Some(QueryText::new("DELETE FROM events")),
            max_rows: Some(10),
            cursor: None,
        });

        assert!(report.issues.iter().any(|issue| issue.field == "query"));
    }

    #[test]
    fn server_errors_are_redacted_and_classified() {
        let error = MssqlError::Server {
            number: 208,
            class: 16,
            state: 1,
            message: "Invalid object name 'private_table'".into(),
            server: Some("private-server".into()),
            procedure: None,
            line: 1,
        };
        let classified = classify_query_error(&error);
        let rendered = format!("{classified:?}");

        assert_eq!(classified.class(), ErrorClass::Query);
        assert!(!rendered.contains("private_table"));
        assert!(!rendered.contains("private-server"));
    }

    #[test]
    fn product_version_is_parsed_and_packed_without_truncating_build() {
        let version = parse_server_version("16.0.4265.3").expect("version should parse");

        assert_eq!(version, (16, 0, 4265));
        assert_eq!(pack_server_version(version), Some(16_004_265));
        assert!(parse_server_version("16.0.4265").is_err());
        assert!(parse_server_version("16.0.4265.invalid").is_err());
    }
}
