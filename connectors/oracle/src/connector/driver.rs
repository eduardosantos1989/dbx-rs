use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use dbx_rs_connector_sdk::{ConnectionConfig, ConnectorError, ErrorClass, ResolvedSecret, TlsMode};
use oracle_rs::{
    ColumnInfo, Config, Connection, OracleType, QueryResult, Row, TlsConfig, Value,
    ValueDecodePolicy, WireLimits,
};
use tokio::sync::Mutex;

pub(super) type DriverFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ConnectorError>> + Send + 'a>>;

#[derive(Clone, Copy)]
pub(super) struct DriverLimits {
    pub max_rows_per_response: usize,
    pub max_value_bytes: usize,
}

pub(super) trait OracleDriver: Send + Sync {
    fn connect<'a>(
        &'a self,
        config: &'a ConnectionConfig,
        secret: &'a ResolvedSecret,
        limits: DriverLimits,
    ) -> DriverFuture<'a, Arc<dyn OracleSession>>;
}

pub(super) trait OracleSession: Send + Sync {
    fn server_info(&self) -> DriverFuture<'_, NativeServerInfo>;
    fn begin_read_only(&self) -> DriverFuture<'_, ()>;
    fn describe<'a>(&'a self, sql: &'a str) -> DriverFuture<'a, Vec<NativeColumn>>;
    fn query<'a>(&'a self, sql: &'a str, fetch_size: u32) -> DriverFuture<'a, NativePage>;
    fn fetch_more(&self, cursor_id: u16, fetch_size: u32) -> DriverFuture<'_, NativePage>;
    fn abort(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct NativeServerInfo {
    pub version: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NativeKind {
    Number { precision: i16, scale: i16 },
    Date,
    Timestamp { fractional_precision: i16 },
    TimestampWithTimeZone,
    TimestampWithLocalTimeZone,
    Text,
    Binary,
    LongText,
    LongBinary,
    Lob,
    Unsupported,
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct NativeColumn {
    pub name: String,
    pub kind: NativeKind,
    pub nullable: bool,
    pub source_type: String,
}

#[derive(Clone, Eq, PartialEq)]
pub(super) enum NativeValue {
    Null,
    Number(String),
    Date {
        year: i32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    },
    Timestamp {
        year: i32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        microsecond: u32,
    },
    Text(String),
    Binary(Vec<u8>),
}

pub(super) type NativeRow = Vec<NativeValue>;

pub(super) struct NativePage {
    pub columns: Vec<NativeColumn>,
    pub rows: Vec<NativeRow>,
    pub has_more_rows: bool,
    pub cursor_id: u16,
}

pub(super) struct RealOracleDriver;

impl OracleDriver for RealOracleDriver {
    fn connect<'a>(
        &'a self,
        config: &'a ConnectionConfig,
        secret: &'a ResolvedSecret,
        limits: DriverLimits,
    ) -> DriverFuture<'a, Arc<dyn OracleSession>> {
        Box::pin(async move {
            let native = build_native_config(config, secret, limits)?;

            let connection = Connection::connect_with_config(native)
                .await
                .map_err(|error| classify_error(&error))?;
            Ok(Arc::new(RealOracleSession {
                connection,
                query_state: Mutex::new(QueryState::default()),
            }) as Arc<dyn OracleSession>)
        })
    }
}

fn build_native_config(
    config: &ConnectionConfig,
    secret: &ResolvedSecret,
    limits: DriverLimits,
) -> Result<Config, ConnectorError> {
    let wire_limits = WireLimits {
        max_packet_bytes: 1024 * 1024,
        max_response_bytes: 2 * 1024 * 1024,
        max_rows_per_response: limits.max_rows_per_response,
        max_columns: 1024,
        max_value_bytes: limits.max_value_bytes,
    };
    let mut native = Config::new(
        config.host.clone(),
        config.port,
        config.database.clone(),
        config.username.clone(),
        String::new(),
    )
    .connect_timeout(config.connect_timeout)
    .stmtcachesize(0)
    .wire_limits(wire_limits)
    .value_decode_policy(ValueDecodePolicy::CoreScalar);
    native.set_password_bytes(secret.expose_secret().to_vec());

    match config.tls_mode {
        TlsMode::Disable => {}
        TlsMode::VerifyFull => {
            let server_name = config
                .tls_server_name
                .as_deref()
                .unwrap_or(config.host.as_str());
            let mut tls = TlsConfig::new().with_server_name(server_name);
            if let Some(ca_pem) = config.tls_ca_pem.as_ref() {
                tls = tls.with_ca_pem(ca_pem.clone());
            }
            native = native.tls_config(tls);
        }
        TlsMode::Require | TlsMode::VerifyCa => {
            return Err(configuration_error(
                "DBX-RS-ORA-CFG-0008",
                "Oracle TLS mode is not supported",
            ));
        }
    }

    Ok(native)
}

struct RealOracleSession {
    connection: Connection,
    query_state: Mutex<QueryState>,
}

#[derive(Clone, Default)]
struct QueryState {
    columns: Vec<ColumnInfo>,
    previous_row: Option<Row>,
}

impl QueryState {
    fn replace_from(&mut self, result: &QueryResult) {
        self.columns.clone_from(&result.columns);
        self.previous_row = result.rows.last().cloned();
    }
}

impl OracleSession for RealOracleSession {
    fn server_info(&self) -> DriverFuture<'_, NativeServerInfo> {
        Box::pin(async move {
            let info = self.connection.server_info().await;
            Ok(NativeServerInfo {
                version: info.version,
            })
        })
    }

    fn begin_read_only(&self) -> DriverFuture<'_, ()> {
        Box::pin(async move {
            self.connection
                .execute("SET TRANSACTION READ ONLY", &[])
                .await
                .map(|_| ())
                .map_err(|error| classify_error(&error))
        })
    }

    fn describe<'a>(&'a self, sql: &'a str) -> DriverFuture<'a, Vec<NativeColumn>> {
        Box::pin(async move {
            self.connection
                .describe(sql)
                .await
                .map(|columns| columns.iter().map(native_column).collect())
                .map_err(|error| classify_error(&error))
        })
    }

    fn query<'a>(&'a self, sql: &'a str, fetch_size: u32) -> DriverFuture<'a, NativePage> {
        Box::pin(async move {
            let result = self
                .connection
                .query_with_fetch_size(sql, &[], fetch_size)
                .await
                .map_err(|error| classify_error(&error))?;
            let page = native_page(&result)?;
            self.query_state.lock().await.replace_from(&result);
            Ok(page)
        })
    }

    fn fetch_more(&self, cursor_id: u16, fetch_size: u32) -> DriverFuture<'_, NativePage> {
        Box::pin(async move {
            let state = self.query_state.lock().await.clone();
            if state.columns.is_empty() {
                return Err(protocol_error(
                    "DBX-RS-ORA-PROTOCOL-0002",
                    "Oracle fetch metadata is unavailable",
                ));
            }
            let result = self
                .connection
                .fetch_more_with_previous_row(
                    cursor_id,
                    &state.columns,
                    state.previous_row.as_ref(),
                    fetch_size,
                )
                .await
                .map_err(|error| classify_error(&error))?;
            let page = native_page(&result)?;
            self.query_state.lock().await.replace_from(&result);
            Ok(page)
        })
    }

    fn abort(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(self.connection.abort())
    }
}

fn native_page(result: &QueryResult) -> Result<NativePage, ConnectorError> {
    let columns = result.columns.iter().map(native_column).collect::<Vec<_>>();
    let rows = result
        .rows
        .iter()
        .map(|row| native_row(row.values(), &columns))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(NativePage {
        columns,
        rows,
        has_more_rows: result.has_more_rows,
        cursor_id: result.cursor_id,
    })
}

fn native_column(column: &ColumnInfo) -> NativeColumn {
    if column.is_json || column.is_oson {
        return NativeColumn {
            name: column.name.clone(),
            kind: NativeKind::Unsupported,
            nullable: column.nullable,
            source_type: "JSON".to_owned(),
        };
    }
    if column.vector_dimensions.is_some() || column.vector_format.is_some() {
        return NativeColumn {
            name: column.name.clone(),
            kind: NativeKind::Unsupported,
            nullable: column.nullable,
            source_type: "VECTOR".to_owned(),
        };
    }

    let (kind, source_type) = match column.oracle_type {
        OracleType::Number => (
            NativeKind::Number {
                precision: column.precision,
                scale: column.scale,
            },
            format!("NUMBER({},{})", column.precision, column.scale),
        ),
        OracleType::Date => (NativeKind::Date, "DATE".to_owned()),
        OracleType::Timestamp => (
            NativeKind::Timestamp {
                fractional_precision: column.scale,
            },
            format!("TIMESTAMP({})", column.scale),
        ),
        OracleType::TimestampTz => (
            NativeKind::TimestampWithTimeZone,
            "TIMESTAMP WITH TIME ZONE".to_owned(),
        ),
        OracleType::TimestampLtz => (
            NativeKind::TimestampWithLocalTimeZone,
            "TIMESTAMP WITH LOCAL TIME ZONE".to_owned(),
        ),
        OracleType::Varchar => (
            NativeKind::Text,
            if column.csfrm == 2 {
                "NVARCHAR2".to_owned()
            } else {
                "VARCHAR2".to_owned()
            },
        ),
        OracleType::Char => (
            NativeKind::Text,
            if column.csfrm == 2 {
                "NCHAR".to_owned()
            } else {
                "CHAR".to_owned()
            },
        ),
        OracleType::Raw => (NativeKind::Binary, "RAW".to_owned()),
        OracleType::Long => (NativeKind::LongText, "LONG".to_owned()),
        OracleType::LongRaw => (NativeKind::LongBinary, "LONG RAW".to_owned()),
        OracleType::Clob => (
            NativeKind::Lob,
            if column.csfrm == 2 {
                "NCLOB".to_owned()
            } else {
                "CLOB".to_owned()
            },
        ),
        OracleType::Blob => (NativeKind::Lob, "BLOB".to_owned()),
        OracleType::Bfile => (NativeKind::Lob, "BFILE".to_owned()),
        other => (NativeKind::Unsupported, format!("{other:?}")),
    };
    NativeColumn {
        name: column.name.clone(),
        kind,
        nullable: column.nullable,
        source_type,
    }
}

fn native_row(values: &[Value], columns: &[NativeColumn]) -> Result<NativeRow, ConnectorError> {
    if values.len() != columns.len() {
        return Err(protocol_error(
            "DBX-RS-ORA-PROTOCOL-0003",
            "Oracle row width does not match its metadata",
        ));
    }
    values
        .iter()
        .zip(columns)
        .map(|(value, column)| native_value(value, column.kind))
        .collect()
}

fn native_value(value: &Value, kind: NativeKind) -> Result<NativeValue, ConnectorError> {
    let converted = match value {
        Value::Null => NativeValue::Null,
        Value::String(value) if matches!(kind, NativeKind::Number { .. }) => {
            NativeValue::Number(value.clone())
        }
        Value::Number(value) if matches!(kind, NativeKind::Number { .. }) => {
            NativeValue::Number(value.value.clone())
        }
        Value::Integer(value) if matches!(kind, NativeKind::Number { .. }) => {
            NativeValue::Number(value.to_string())
        }
        Value::String(value) if kind == NativeKind::Text => NativeValue::Text(value.clone()),
        Value::Bytes(value) if kind == NativeKind::Binary => NativeValue::Binary(value.clone()),
        Value::Date(value) if kind == NativeKind::Date => NativeValue::Date {
            year: value.year,
            month: value.month,
            day: value.day,
            hour: value.hour,
            minute: value.minute,
            second: value.second,
        },
        Value::Timestamp(value) if matches!(kind, NativeKind::Timestamp { .. }) => {
            NativeValue::Timestamp {
                year: value.year,
                month: value.month,
                day: value.day,
                hour: value.hour,
                minute: value.minute,
                second: value.second,
                microsecond: value.microsecond,
            }
        }
        _ => {
            return Err(ConnectorError::new(
                "DBX-RS-ORA-CONVERT-0001",
                ErrorClass::Conversion,
                "Oracle value does not match its declared lossless type",
                false,
                false,
            ));
        }
    };
    Ok(converted)
}

struct ErrorClassification {
    code: &'static str,
    class: ErrorClass,
    message: &'static str,
    retryable: bool,
    user_actionable: bool,
}

impl ErrorClassification {
    const fn new(
        code: &'static str,
        class: ErrorClass,
        message: &'static str,
        retryable: bool,
        user_actionable: bool,
    ) -> Self {
        Self {
            code,
            class,
            message,
            retryable,
            user_actionable,
        }
    }

    fn into_error(self) -> ConnectorError {
        ConnectorError::new(
            self.code,
            self.class,
            self.message,
            self.retryable,
            self.user_actionable,
        )
    }
}

const AUTHENTICATION_FAILED: ErrorClassification = ErrorClassification::new(
    "DBX-RS-ORA-AUTH-0002",
    ErrorClass::Authentication,
    "Oracle authentication failed",
    false,
    false,
);
const AUTHENTICATION_UNSUPPORTED: ErrorClassification = ErrorClassification::new(
    "DBX-RS-ORA-AUTH-0003",
    ErrorClass::Authentication,
    "Oracle authentication verifier is unsupported",
    false,
    false,
);
const CONNECTION_TIMEOUT: ErrorClassification = ErrorClassification::new(
    "DBX-RS-ORA-CONNECT-0002",
    ErrorClass::Timeout,
    "Oracle connection timed out",
    true,
    false,
);
const SERVICE_UNAVAILABLE: ErrorClassification = ErrorClassification::new(
    "DBX-RS-ORA-CONNECT-0003",
    ErrorClass::Configuration,
    "Oracle service is unavailable",
    false,
    true,
);
const TLS_VERIFICATION_FAILED: ErrorClassification = ErrorClassification::new(
    "DBX-RS-ORA-TLS-0002",
    ErrorClass::Tls,
    "Oracle TLS verification failed",
    false,
    false,
);
const DNS_FAILED: ErrorClassification = ErrorClassification::new(
    "DBX-RS-ORA-DNS-0001",
    ErrorClass::Dns,
    "Oracle host resolution failed",
    true,
    false,
);
const TLS_FAILED: ErrorClassification = ErrorClassification::new(
    "DBX-RS-ORA-TLS-0001",
    ErrorClass::Tls,
    "Oracle TLS handshake or verification failed",
    false,
    false,
);
const TCP_FAILED: ErrorClassification = ErrorClassification::new(
    "DBX-RS-ORA-CONNECT-0001",
    ErrorClass::Tcp,
    "Oracle connection failed",
    true,
    false,
);
const PROTOCOL_FAILED: ErrorClassification = ErrorClassification::new(
    "DBX-RS-ORA-PROTOCOL-0001",
    ErrorClass::Protocol,
    "Oracle protocol exchange failed",
    true,
    false,
);
const RESPONSE_LIMIT_EXCEEDED: ErrorClassification = ErrorClassification::new(
    "DBX-RS-ORA-LIMIT-0001",
    ErrorClass::Query,
    "Oracle response exceeded a configured limit",
    false,
    false,
);
const CONVERSION_FAILED: ErrorClassification = ErrorClassification::new(
    "DBX-RS-ORA-CONVERT-0002",
    ErrorClass::Conversion,
    "Oracle value could not be converted without loss",
    false,
    false,
);
const UNSUPPORTED_CONNECTION_FEATURE: ErrorClassification = ErrorClassification::new(
    "DBX-RS-ORA-CFG-0098",
    ErrorClass::Configuration,
    "Oracle requested an unsupported connection feature",
    false,
    true,
);
const QUERY_FAILED: ErrorClassification = ErrorClassification::new(
    "DBX-RS-ORA-QUERY-0001",
    ErrorClass::Query,
    "Oracle query failed",
    false,
    false,
);
const INTERNAL_FAILURE: ErrorClassification = ErrorClassification::new(
    "DBX-RS-ORA-INTERNAL-0001",
    ErrorClass::Internal,
    "Oracle driver failed internally",
    false,
    false,
);

fn classify_error(error: &oracle_rs::Error) -> ConnectorError {
    use oracle_rs::Error;

    let classification = match error {
        Error::InvalidCredentials
        | Error::AuthenticationFailed(_)
        | Error::OracleError {
            code: 1017 | 28000, ..
        } => AUTHENTICATION_FAILED,
        Error::UnsupportedVerifierType(_) => AUTHENTICATION_UNSUPPORTED,
        Error::ConnectionTimeout(_) => CONNECTION_TIMEOUT,
        Error::InvalidServiceName { .. } | Error::InvalidSid { .. } => SERVICE_UNAVAILABLE,
        Error::OracleError { code: 29024, .. } => TLS_VERIFICATION_FAILED,
        Error::Dns => DNS_FAILED,
        Error::Tls => TLS_FAILED,
        Error::Io(_)
        | Error::ConnectionRefused { .. }
        | Error::ConnectionClosed
        | Error::ConnectionClosedByServer(_)
        | Error::ConnectionRedirected { .. }
        | Error::ConnectionRedirect(_) => TCP_FAILED,
        Error::InvalidPacketType(_)
        | Error::InvalidMessageType(_)
        | Error::PacketTooShort { .. }
        | Error::UnexpectedPacketType { .. }
        | Error::ProtocolVersionNotSupported(_, _)
        | Error::Protocol(_)
        | Error::ProtocolError(_)
        | Error::BufferUnderflow { .. }
        | Error::IncompleteResponse
        | Error::InvalidLengthIndicator(_)
        | Error::ConnectionNotReady => PROTOCOL_FAILED,
        Error::LimitExceeded | Error::InvalidLimits | Error::BufferOverflow { .. } => {
            RESPONSE_LIMIT_EXCEEDED
        }
        Error::DataConversionError(_)
        | Error::InvalidDataType(_)
        | Error::InvalidOracleType(_)
        | Error::UnexpectedNull => CONVERSION_FAILED,
        Error::InvalidConnectionString(_)
        | Error::FeatureNotSupported(_)
        | Error::NativeNetworkEncryptionRequired => UNSUPPORTED_CONNECTION_FEATURE,
        Error::CursorClosed
        | Error::InvalidCursor(_)
        | Error::OracleError { .. }
        | Error::SqlError(_)
        | Error::NoDataFound
        | Error::ServerError { .. } => QUERY_FAILED,
        Error::Internal(_) => INTERNAL_FAILURE,
    };

    classification.into_error()
}

fn configuration_error(code: &'static str, message: &'static str) -> ConnectorError {
    ConnectorError::new(code, ErrorClass::Configuration, message, false, true)
}

fn protocol_error(code: &'static str, message: &'static str) -> ConnectorError {
    ConnectorError::new(code, ErrorClass::Protocol, message, true, false)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn connection_config() -> ConnectionConfig {
        ConnectionConfig {
            connector_id: "oracle".into(),
            host: "oracle.example".into(),
            port: 1521,
            database: "ORCLPDB1".into(),
            username: "reader".into(),
            tls_mode: TlsMode::Disable,
            tls_server_name: None,
            tls_ca_pem: None,
            connect_timeout: Duration::from_secs(5),
            probe_timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn native_driver_enables_core_scalar_value_decoding() {
        let native = build_native_config(
            &connection_config(),
            &ResolvedSecret::new(b"secret".to_vec()),
            DriverLimits {
                max_rows_per_response: 17,
                max_value_bytes: 4096,
            },
        )
        .unwrap();

        assert_eq!(native.value_decode_policy, ValueDecodePolicy::CoreScalar);
        assert_eq!(native.wire_limits.max_rows_per_response, 17);
        assert_eq!(native.wire_limits.max_value_bytes, 4096);
    }

    #[test]
    fn query_state_carries_only_the_last_wire_row() {
        let columns = vec![ColumnInfo::new("VALUE", OracleType::Varchar)];
        let result = QueryResult {
            columns: columns.clone(),
            rows: vec![
                Row::new(vec![Value::String("first".into())]),
                Row::new(vec![Value::String("last".into())]),
            ],
            rows_affected: 2,
            has_more_rows: true,
            cursor_id: 7,
            response_packet_count: 1,
        };
        let mut state = QueryState::default();

        state.replace_from(&result);

        assert_eq!(state.columns.len(), 1);
        assert!(matches!(
            state.previous_row.as_ref().and_then(|row| row.get(0)),
            Some(Value::String(value)) if value == "last"
        ));
    }

    #[test]
    fn national_character_metadata_stays_distinct() {
        let mut column = ColumnInfo::new("VALUE", OracleType::Varchar);
        column.csfrm = 2;
        column.nullable = false;

        let mapped = native_column(&column);

        assert_eq!(mapped.kind, NativeKind::Text);
        assert_eq!(mapped.source_type, "NVARCHAR2");
        assert!(!mapped.nullable);
    }

    #[test]
    fn semantic_complex_metadata_never_falls_back_to_scalar_types() {
        let mut json = ColumnInfo::new("VALUE", OracleType::Varchar);
        json.is_json = true;
        assert_eq!(native_column(&json).kind, NativeKind::Unsupported);

        let mut vector = ColumnInfo::new("VALUE", OracleType::Raw);
        vector.vector_dimensions = Some(3);
        assert_eq!(native_column(&vector).kind, NativeKind::Unsupported);
    }

    #[test]
    fn driver_errors_are_classified_without_forwarding_details() {
        let authentication = classify_error(&oracle_rs::Error::AuthenticationFailed(
            "private detail".into(),
        ));
        assert_eq!(authentication.class(), ErrorClass::Authentication);
        assert!(!authentication.message().contains("private detail"));

        let protocol = classify_error(&oracle_rs::Error::BufferUnderflow {
            needed: 1,
            available: 0,
        });
        assert_eq!(protocol.class(), ErrorClass::Protocol);

        let dns = classify_error(&oracle_rs::Error::Dns);
        assert_eq!(dns.class(), ErrorClass::Dns);

        let tcp = classify_error(&oracle_rs::Error::Io(std::io::Error::other(
            "private tcp detail",
        )));
        assert_eq!(tcp.class(), ErrorClass::Tcp);
        assert!(!tcp.message().contains("private tcp detail"));

        let query = classify_error(&oracle_rs::Error::OracleError {
            code: 942,
            message: "private query detail".into(),
        });
        assert_eq!(query.class(), ErrorClass::Query);
        assert!(!query.message().contains("private query detail"));

        let tls = classify_error(&oracle_rs::Error::Tls);
        assert_eq!(tls.class(), ErrorClass::Tls);
        assert_eq!(tls.message(), "Oracle TLS handshake or verification failed");
    }
}
