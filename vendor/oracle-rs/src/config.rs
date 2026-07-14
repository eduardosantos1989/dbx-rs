//! Connection configuration and connection string parsing
//!
//! Supports Oracle EZConnect format:
//! - `host:port/service_name`
//! - `host/service_name`
//! - `host:port:sid`
//!
//! And TNS-style connect descriptors.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use crate::constants::charset;
use crate::error::{Error, Result};
use crate::transport::TlsConfig;

/// Default Oracle port
pub const DEFAULT_PORT: u16 = 1521;

/// Default SDU size
pub const DEFAULT_SDU: u32 = 8192;

/// Default statement cache size (matches python-oracledb default)
pub const DEFAULT_STMTCACHESIZE: usize = 20;

/// Conservative defaults for one bounded TNS operation.
pub const DEFAULT_MAX_PACKET_BYTES: usize = 1024 * 1024;
/// Maximum accumulated response bytes for one database round trip.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
/// Maximum rows decoded from one response page.
pub const DEFAULT_MAX_ROWS_PER_RESPONSE: usize = 1024;
/// Maximum columns accepted from server metadata.
pub const DEFAULT_MAX_COLUMNS: usize = 1024;
/// Maximum bytes accepted for one decoded scalar value.
pub const DEFAULT_MAX_VALUE_BYTES: usize = 1024 * 1024;

/// Allocation and cardinality limits applied by the TNS decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireLimits {
    /// Maximum size of one TNS packet, including its header.
    pub max_packet_bytes: usize,
    /// Maximum combined payload for one request/response exchange.
    pub max_response_bytes: usize,
    /// Maximum rows decoded from one response page.
    pub max_rows_per_response: usize,
    /// Maximum columns accepted from describe metadata.
    pub max_columns: usize,
    /// Maximum bytes accepted for one scalar value.
    pub max_value_bytes: usize,
}

impl Default for WireLimits {
    fn default() -> Self {
        Self {
            max_packet_bytes: DEFAULT_MAX_PACKET_BYTES,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_rows_per_response: DEFAULT_MAX_ROWS_PER_RESPONSE,
            max_columns: DEFAULT_MAX_COLUMNS,
            max_value_bytes: DEFAULT_MAX_VALUE_BYTES,
        }
    }
}

impl WireLimits {
    pub(crate) fn validate(self) -> Result<()> {
        if self.max_packet_bytes < crate::constants::PACKET_HEADER_SIZE
            || self.max_response_bytes < 2
            || self.max_rows_per_response == 0
            || self.max_columns == 0
            || self.max_value_bytes == 0
            || self.max_packet_bytes > self.max_response_bytes
        {
            return Err(Error::InvalidLimits);
        }
        Ok(())
    }
}

/// Policy controlling which query values may be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ValueDecodePolicy {
    /// Decode every value type implemented by the driver.
    #[default]
    All,
    /// Decode only NUMBER, DATE, unzoned TIMESTAMP, text, and RAW values.
    CoreScalar,
}

/// Service identification method
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceMethod {
    /// Connect using service name
    ServiceName(String),
    /// Connect using SID (legacy)
    Sid(String),
}

impl ServiceMethod {
    /// Get the service name if this is a ServiceName variant
    pub fn service_name(&self) -> Option<&str> {
        match self {
            ServiceMethod::ServiceName(s) => Some(s),
            ServiceMethod::Sid(_) => None,
        }
    }

    /// Get the SID if this is a Sid variant
    pub fn sid(&self) -> Option<&str> {
        match self {
            ServiceMethod::ServiceName(_) => None,
            ServiceMethod::Sid(s) => Some(s),
        }
    }
}

/// TLS mode for connections
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsMode {
    /// No TLS (plain TCP)
    #[default]
    Disable,
    /// Require TLS (TCPS)
    Require,
}

/// Connection configuration for Oracle databases.
///
/// This struct holds all the parameters needed to establish a connection to an
/// Oracle database, including host, port, credentials, TLS settings, and more.
///
/// # Examples
///
/// ## Basic connection
///
/// ```rust
/// use oracle_rs::Config;
///
/// let config = Config::new("localhost", 1521, "FREEPDB1", "user", "password");
/// ```
///
/// ## TLS connection with system certificates
///
/// ```rust,no_run
/// use oracle_rs::Config;
///
/// let config = Config::new("hostname", 2484, "service", "user", "password")
///     .with_tls()
///     .expect("TLS configuration failed");
/// ```
///
/// ## TLS connection with Oracle wallet
///
/// ```rust,ignore
/// use oracle_rs::Config;
///
/// let config = Config::new("hostname", 2484, "service", "user", "password")
///     .with_wallet("/path/to/wallet", Some("wallet_password"))
///     .expect("Wallet configuration failed");
/// ```
///
/// ## With custom options
///
/// ```rust
/// use oracle_rs::Config;
/// use std::time::Duration;
///
/// let config = Config::new("localhost", 1521, "FREEPDB1", "user", "password")
///     .connect_timeout(Duration::from_secs(30))
///     .stmtcachesize(50);
/// ```
#[derive(Clone)]
pub struct Config {
    /// Host to connect to
    pub host: String,
    /// Port to connect to
    pub port: u16,
    /// Service name or SID
    pub service: ServiceMethod,
    /// Username for authentication
    pub username: String,
    /// Password for authentication (stored temporarily)
    password: Vec<u8>,
    /// TLS mode
    pub tls_mode: TlsMode,
    /// TLS configuration (certificates, wallet, etc.)
    pub tls_config: Option<TlsConfig>,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// SDU (Session Data Unit) size
    pub sdu: u32,
    /// Client charset ID
    pub charset_id: u16,
    /// National charset ID
    pub ncharset_id: u16,
    /// Statement cache size (0 = disabled)
    pub stmtcachesize: usize,
    /// Bounds enforced while reading and decoding TNS responses.
    pub wire_limits: WireLimits,
    /// Type policy applied before query value decoding.
    pub value_decode_policy: ValueDecodePolicy,
}

impl fmt::Debug for Config {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Config")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("service", &self.service)
            .field("username", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .field("tls_mode", &self.tls_mode)
            .field("tls_config", &self.tls_config)
            .field("connect_timeout", &self.connect_timeout)
            .field("sdu", &self.sdu)
            .field("charset_id", &self.charset_id)
            .field("ncharset_id", &self.ncharset_id)
            .field("stmtcachesize", &self.stmtcachesize)
            .field("wire_limits", &self.wire_limits)
            .field("value_decode_policy", &self.value_decode_policy)
            .finish()
    }
}

impl Config {
    /// Create a new configuration with service name
    pub fn new(
        host: impl Into<String>,
        port: u16,
        service_name: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            service: ServiceMethod::ServiceName(service_name.into()),
            username: username.into(),
            password: password.into().into_bytes(),
            tls_mode: TlsMode::Disable,
            tls_config: None,
            connect_timeout: Duration::from_secs(10),
            sdu: DEFAULT_SDU,
            charset_id: charset::UTF8,
            ncharset_id: charset::UTF16,
            stmtcachesize: DEFAULT_STMTCACHESIZE,
            wire_limits: WireLimits::default(),
            value_decode_policy: ValueDecodePolicy::All,
        }
    }

    /// Create a new configuration with SID
    pub fn with_sid(
        host: impl Into<String>,
        port: u16,
        sid: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            service: ServiceMethod::Sid(sid.into()),
            username: username.into(),
            password: password.into().into_bytes(),
            tls_mode: TlsMode::Disable,
            tls_config: None,
            connect_timeout: Duration::from_secs(10),
            sdu: DEFAULT_SDU,
            charset_id: charset::UTF8,
            ncharset_id: charset::UTF16,
            stmtcachesize: DEFAULT_STMTCACHESIZE,
            wire_limits: WireLimits::default(),
            value_decode_policy: ValueDecodePolicy::All,
        }
    }

    /// Set TLS mode
    pub fn tls(mut self, mode: TlsMode) -> Self {
        self.tls_mode = mode;
        self
    }

    /// Set TLS configuration
    pub fn tls_config(mut self, config: TlsConfig) -> Self {
        self.tls_config = Some(config);
        self.tls_mode = TlsMode::Require;
        self
    }

    /// Check if TLS is enabled
    pub fn is_tls_enabled(&self) -> bool {
        self.tls_mode == TlsMode::Require
    }

    /// Enable TLS with system root certificates.
    ///
    /// This configures the connection to use TLS (TCPS protocol) with the
    /// system's trusted root certificate store for server verification.
    ///
    /// # Example
    ///
    /// ```rust
    /// use oracle_rs::Config;
    ///
    /// let config = Config::new("hostname", 2484, "service", "user", "password")
    ///     .with_tls()
    ///     .expect("TLS configuration failed");
    /// ```
    pub fn with_tls(mut self) -> Result<Self> {
        let tls_config = TlsConfig::new();
        // Validate that TLS config can be built
        tls_config.build_client_config()?;
        self.tls_config = Some(tls_config);
        self.tls_mode = TlsMode::Require;
        Ok(self)
    }

    /// Enable TLS with an Oracle wallet.
    ///
    /// Oracle wallets (ewallet.p12 or ewallet.pem files) contain certificates
    /// and keys for secure connections. This is the standard way to configure
    /// TLS for Oracle Cloud and enterprise deployments.
    ///
    /// # Arguments
    ///
    /// * `wallet_path` - Path to the wallet directory containing ewallet.pem
    /// * `wallet_password` - Optional password for encrypted wallets
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use oracle_rs::Config;
    ///
    /// let config = Config::new("hostname", 2484, "service", "user", "password")
    ///     .with_wallet("/path/to/wallet", Some("wallet_password"))
    ///     .expect("Wallet configuration failed");
    /// ```
    pub fn with_wallet(
        mut self,
        wallet_path: impl Into<String>,
        wallet_password: Option<&str>,
    ) -> Result<Self> {
        let tls_config = TlsConfig::new()
            .with_wallet(wallet_path, wallet_password.map(|s| s.to_string()));
        // Validate that TLS config can be built
        tls_config.build_client_config()?;
        self.tls_config = Some(tls_config);
        self.tls_mode = TlsMode::Require;
        Ok(self)
    }

    /// Configure DRCP (Database Resident Connection Pooling).
    ///
    /// DRCP allows the database server to maintain a pool of connections that
    /// can be shared across multiple client processes, reducing server resource
    /// usage.
    ///
    /// # Arguments
    ///
    /// * `connection_class` - Name identifying this class of connections
    /// * `purity` - Either "self" (dedicated) or "new" (can share with others)
    ///
    /// # Example
    ///
    /// ```rust
    /// use oracle_rs::Config;
    ///
    /// let config = Config::new("hostname", 1521, "service", "user", "password")
    ///     .with_drcp("my_app", "self");
    /// ```
    pub fn with_drcp(self, _connection_class: &str, _purity: &str) -> Self {
        // TODO: Implement DRCP configuration storage
        // For now, DRCP is handled at connection time via the connect descriptor
        self
    }

    /// Set the statement cache size.
    ///
    /// Statement caching improves performance by reusing parsed SQL statements.
    /// Set to 0 to disable caching.
    ///
    /// Default is 20 (matches python-oracledb default).
    ///
    /// # Example
    ///
    /// ```rust
    /// use oracle_rs::Config;
    ///
    /// let config = Config::new("localhost", 1521, "FREEPDB1", "user", "password")
    ///     .with_statement_cache_size(100);
    /// ```
    pub fn with_statement_cache_size(mut self, size: usize) -> Self {
        self.stmtcachesize = size;
        self
    }

    /// Set connection timeout
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set SDU size
    pub fn sdu(mut self, sdu: u32) -> Self {
        self.sdu = sdu;
        self
    }

    /// Set statement cache size
    ///
    /// Set to 0 to disable statement caching.
    /// Default is 20 (matches python-oracledb default).
    pub fn stmtcachesize(mut self, size: usize) -> Self {
        self.stmtcachesize = size;
        self
    }

    /// Set allocation and cardinality limits for TNS response decoding.
    pub fn wire_limits(mut self, limits: WireLimits) -> Self {
        self.wire_limits = limits;
        self
    }

    /// Set the query value decoding policy.
    ///
    /// Describe metadata remains available so callers can reject unsupported
    /// columns before execution. A disallowed query response value fails before
    /// any part of that value is consumed.
    pub fn value_decode_policy(mut self, policy: ValueDecodePolicy) -> Self {
        self.value_decode_policy = policy;
        self
    }

    /// Get the password (for authentication)
    pub(crate) fn password(&self) -> &[u8] {
        &self.password
    }

    /// Set the password
    pub fn set_password(&mut self, password: impl Into<String>) {
        self.clear_password();
        self.password = password.into().into_bytes();
    }

    /// Replace the password with raw bytes so callers do not need a lossy string conversion.
    pub fn set_password_bytes(&mut self, password: impl Into<Vec<u8>>) {
        self.clear_password();
        self.password = password.into();
    }

    pub(crate) fn clear_password(&mut self) {
        self.password.fill(0);
        self.password.clear();
    }

    /// Set the username
    pub fn set_username(&mut self, username: impl Into<String>) {
        self.username = username.into();
    }

    /// Build a TNS connect descriptor string
    pub fn build_connect_string(&self) -> String {
        let mut parts = Vec::new();

        // Address
        let protocol = match self.tls_mode {
            TlsMode::Disable => "TCP",
            TlsMode::Require => "TCPS",
        };
        parts.push(format!(
            "(ADDRESS=(PROTOCOL={})(HOST={})(PORT={}))",
            protocol, self.host, self.port
        ));

        // Connect data
        let service_part = match &self.service {
            ServiceMethod::ServiceName(name) => format!("(SERVICE_NAME={})", name),
            ServiceMethod::Sid(sid) => format!("(SID={})", sid),
        };
        parts.push(format!("(CONNECT_DATA={})", service_part));

        format!("(DESCRIPTION={})", parts.join(""))
    }

    /// Get the socket address string
    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            port: DEFAULT_PORT,
            service: ServiceMethod::ServiceName("FREEPDB1".to_string()),
            username: String::new(),
            password: Vec::new(),
            tls_mode: TlsMode::Disable,
            tls_config: None,
            connect_timeout: Duration::from_secs(10),
            sdu: DEFAULT_SDU,
            charset_id: charset::UTF8,
            ncharset_id: charset::UTF16,
            stmtcachesize: DEFAULT_STMTCACHESIZE,
            wire_limits: WireLimits::default(),
            value_decode_policy: ValueDecodePolicy::All,
        }
    }
}

impl Drop for Config {
    fn drop(&mut self) {
        self.clear_password();
    }
}

/// Parse an EZConnect-style connection string
///
/// Formats supported:
/// - `host:port/service_name`
/// - `host/service_name`
/// - `host:port:sid`
/// - `//host:port/service_name` (with optional leading slashes)
impl FromStr for Config {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();

        // Strip leading slashes if present
        let s = s.trim_start_matches('/');

        if s.is_empty() {
            return Err(Error::InvalidConnectionString(
                "empty connection string".to_string(),
            ));
        }

        // Check for TNS descriptor format
        if s.starts_with('(') {
            return Err(Error::InvalidConnectionString(
                "TNS descriptor format not yet supported, use EZConnect format".to_string(),
            ));
        }

        // Parse EZConnect format
        // Format: [//]host[:port][/service_name] or host:port:sid

        let mut config = Config::default();

        // Check for service_name format (contains /)
        if let Some(slash_pos) = s.find('/') {
            let host_port = &s[..slash_pos];
            let service_name = &s[slash_pos + 1..];

            if service_name.is_empty() {
                return Err(Error::InvalidConnectionString(
                    "missing service name after /".to_string(),
                ));
            }

            config.service = ServiceMethod::ServiceName(service_name.to_string());

            // Parse host:port
            if let Some(colon_pos) = host_port.find(':') {
                config.host = host_port[..colon_pos].to_string();
                config.port = host_port[colon_pos + 1..]
                    .parse()
                    .map_err(|_| Error::InvalidConnectionString("invalid port number".to_string()))?;
            } else {
                config.host = host_port.to_string();
                config.port = DEFAULT_PORT;
            }
        } else {
            // Check for SID format (host:port:sid)
            let parts: Vec<&str> = s.split(':').collect();

            match parts.len() {
                1 => {
                    // Just host, use defaults
                    config.host = parts[0].to_string();
                }
                2 => {
                    // host:port
                    config.host = parts[0].to_string();
                    config.port = parts[1]
                        .parse()
                        .map_err(|_| Error::InvalidConnectionString("invalid port number".to_string()))?;
                }
                3 => {
                    // host:port:sid
                    config.host = parts[0].to_string();
                    config.port = parts[1]
                        .parse()
                        .map_err(|_| Error::InvalidConnectionString("invalid port number".to_string()))?;
                    config.service = ServiceMethod::Sid(parts[2].to_string());
                }
                _ => {
                    return Err(Error::InvalidConnectionString(
                        "too many colons in connection string".to_string(),
                    ));
                }
            }
        }

        if config.host.is_empty() {
            return Err(Error::InvalidConnectionString(
                "missing host".to_string(),
            ));
        }

        Ok(config)
    }
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.service {
            ServiceMethod::ServiceName(name) => {
                write!(f, "{}:{}/{}", self.host, self.port, name)
            }
            ServiceMethod::Sid(sid) => {
                write!(f, "{}:{}:{}", self.host, self.port, sid)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_password_and_username() {
        let config = Config::new("localhost", 1521, "service", "private-user", "private-pass");
        let debug = format!("{config:?}");

        assert!(!debug.contains("private-user"));
        assert!(!debug.contains("private-pass"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn invalid_wire_limits_fail_closed() {
        let limits = WireLimits {
            max_packet_bytes: DEFAULT_MAX_RESPONSE_BYTES + 1,
            ..WireLimits::default()
        };

        assert!(matches!(limits.validate(), Err(Error::InvalidLimits)));
    }

    #[test]
    fn core_scalar_value_decoding_is_opt_in() {
        assert_eq!(Config::default().value_decode_policy, ValueDecodePolicy::All);
        assert_eq!(
            Config::default()
                .value_decode_policy(ValueDecodePolicy::CoreScalar)
                .value_decode_policy,
            ValueDecodePolicy::CoreScalar
        );
    }

    #[test]
    fn test_parse_ezconnect_full() {
        let config: Config = "myhost:1522/myservice".parse().unwrap();
        assert_eq!(config.host, "myhost");
        assert_eq!(config.port, 1522);
        assert_eq!(
            config.service,
            ServiceMethod::ServiceName("myservice".to_string())
        );
    }

    #[test]
    fn test_parse_ezconnect_default_port() {
        let config: Config = "myhost/myservice".parse().unwrap();
        assert_eq!(config.host, "myhost");
        assert_eq!(config.port, DEFAULT_PORT);
        assert_eq!(
            config.service,
            ServiceMethod::ServiceName("myservice".to_string())
        );
    }

    #[test]
    fn test_parse_ezconnect_with_slashes() {
        let config: Config = "//myhost:1522/myservice".parse().unwrap();
        assert_eq!(config.host, "myhost");
        assert_eq!(config.port, 1522);
    }

    #[test]
    fn test_parse_ezconnect_sid_format() {
        let config: Config = "myhost:1522:ORCL".parse().unwrap();
        assert_eq!(config.host, "myhost");
        assert_eq!(config.port, 1522);
        assert_eq!(config.service, ServiceMethod::Sid("ORCL".to_string()));
    }

    #[test]
    fn test_parse_host_only() {
        let config: Config = "myhost".parse().unwrap();
        assert_eq!(config.host, "myhost");
        assert_eq!(config.port, DEFAULT_PORT);
    }

    #[test]
    fn test_parse_host_port() {
        let config: Config = "myhost:1522".parse().unwrap();
        assert_eq!(config.host, "myhost");
        assert_eq!(config.port, 1522);
    }

    #[test]
    fn test_parse_empty() {
        let result: Result<Config> = "".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_port() {
        let result: Result<Config> = "myhost:notaport/service".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_build_connect_string() {
        let config = Config::new("myhost", 1522, "myservice", "user", "pass");
        let connect_str = config.build_connect_string();
        assert!(connect_str.contains("(HOST=myhost)"));
        assert!(connect_str.contains("(PORT=1522)"));
        assert!(connect_str.contains("(SERVICE_NAME=myservice)"));
        assert!(connect_str.contains("(PROTOCOL=TCP)"));
    }

    #[test]
    fn test_build_connect_string_sid() {
        let config = Config::with_sid("myhost", 1522, "ORCL", "user", "pass");
        let connect_str = config.build_connect_string();
        assert!(connect_str.contains("(SID=ORCL)"));
    }

    #[test]
    fn test_config_display() {
        let config = Config::new("myhost", 1522, "myservice", "user", "pass");
        assert_eq!(config.to_string(), "myhost:1522/myservice");

        let config_sid = Config::with_sid("myhost", 1522, "ORCL", "user", "pass");
        assert_eq!(config_sid.to_string(), "myhost:1522:ORCL");
    }

    #[test]
    fn test_config_builder_pattern() {
        let config = Config::new("host", 1521, "svc", "user", "pass")
            .tls(TlsMode::Require)
            .connect_timeout(Duration::from_secs(30))
            .sdu(16384);

        assert_eq!(config.tls_mode, TlsMode::Require);
        assert_eq!(config.connect_timeout, Duration::from_secs(30));
        assert_eq!(config.sdu, 16384);
    }
}
