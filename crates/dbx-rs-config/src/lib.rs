#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::time::Duration;

use configparser::ini::Ini;

const HARD_LOG_FILE_BYTES: u64 = 10_000_000;
const HARD_HEC_EVENT_BYTES: u64 = 10_000_000;
const HARD_HEC_BATCH_BYTES: u64 = 10_000_000;
const HARD_INPUT_ROWS: u64 = 100_000;
const HARD_INPUT_BYTES: u64 = 1024 * 1024 * 1024;
const HARD_SPOOL_SEGMENT_BYTES: u64 = 1024 * 1024 * 1024;
const HARD_SPOOL_INPUT_BYTES: u64 = 100 * 1024 * 1024 * 1024;
const HARD_SPOOL_TOTAL_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const HARD_INTERVAL_SECONDS: u64 = 365 * 24 * 60 * 60;
const HARD_OPERATION_SECONDS: u64 = 24 * 60 * 60;
const SPOOL_EVENT_OVERHEAD_BYTES: u64 = 1_024;
const SPOOL_FORMAT_OVERHEAD_BYTES: u64 = 4_096;

pub const MAX_QUERY_BYTES: u64 = 1024 * 1024;
pub const MAX_TLS_CA_BYTES: u64 = 1024 * 1024;

const GENERIC_FILE: &str = "dbxrs_generic.conf";
const INPUTS_FILE: &str = "dbxrs_inputs.conf";
const MAX_LABEL_BYTES: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveConfig {
    pub generic: GenericConfig,
    pub inputs: Vec<InputConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenericConfig {
    pub paths: PathsConfig,
    pub logging: LoggingConfig,
    pub daemon: DaemonConfig,
    pub spool: SpoolConfig,
    pub hec: HecConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathsConfig {
    pub log_file: PathBuf,
    pub splunkd_pid_file: PathBuf,
    pub instance_lock_file: PathBuf,
    pub master_key_file: PathBuf,
    pub secret_dir: PathBuf,
    pub hec_token_file: PathBuf,
    pub hec_server_pem_file: PathBuf,
    pub hec_ca_file: PathBuf,
    pub spool_key_file: PathBuf,
    pub state_dir: PathBuf,
    pub spool_dir: PathBuf,
    pub managed_inputs_file: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoggingConfig {
    pub max_file_bytes: u64,
    pub backup_count: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaemonConfig {
    pub poll_interval: Duration,
    pub shutdown_grace: Duration,
    pub configuration_reload: Duration,
    pub max_workers: WorkerLimit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpoolConfig {
    pub segment_max_bytes: u64,
    pub input_max_bytes: u64,
    pub total_max_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerLimit {
    Auto,
    Fixed(NonZeroUsize),
}

impl WorkerLimit {
    #[must_use]
    pub fn effective(self, available_parallelism: NonZeroUsize) -> NonZeroUsize {
        match self {
            Self::Auto => available_parallelism,
            Self::Fixed(configured) => configured.min(available_parallelism),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HecConfig {
    pub state: HecState,
    pub input_management: HecInputManagement,
    pub url: String,
    pub input_name: String,
    pub listen_port: u16,
    pub accept_from: String,
    pub tls_verification: TlsVerification,
    pub timeout: Duration,
    pub batch_max_events: usize,
    pub batch_max_bytes: u64,
    pub max_event_bytes: u64,
    pub index: String,
    pub sourcetype: String,
    pub source: String,
    pub acknowledgment: IndexerAcknowledgment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HecState {
    Enabled,
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HecInputManagement {
    Managed,
    External,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsVerification {
    Full,
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IndexerAcknowledgment {
    Enabled,
    Disabled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputConfig {
    pub name: String,
    pub disabled: bool,
    pub connector: String,
    pub interval: Duration,
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub secret_ref: String,
    pub tls_mode: String,
    pub tls_server_name: Option<String>,
    pub tls_ca_file: Option<PathBuf>,
    pub query: QuerySource,
    pub connect_timeout: Duration,
    pub probe_timeout: Duration,
    pub max_rows: u64,
    pub max_bytes: u64,
    pub query_timeout: Duration,
    pub index: String,
    pub sourcetype: String,
    pub source: String,
}

#[derive(Clone, Eq, PartialEq)]
pub enum QuerySource {
    File(PathBuf),
    Inline(String),
}

impl std::fmt::Debug for QuerySource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(_) => formatter.write_str("File([CONFIGURED])"),
            Self::Inline(_) => formatter.write_str("Inline([REDACTED])"),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ConfigError {
    code: &'static str,
    field: &'static str,
}

impl ConfigError {
    const fn new(code: &'static str, field: &'static str) -> Self {
        Self { code, field }
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn field(&self) -> &'static str {
        self.field
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "configuration error[{}] in {}",
            self.code, self.field
        )
    }
}

impl std::error::Error for ConfigError {}

/// Loads packaged defaults and app-local overrides for both dbx-rs configuration files.
///
/// # Errors
///
/// Returns a redacted configuration error when a file cannot be read or parsed, a required value
/// is absent, an unknown setting is present, or a typed constraint is violated.
pub fn load_effective_config(
    app_home: &Path,
    splunk_home: &Path,
) -> Result<EffectiveConfig, ConfigError> {
    let generic = load_layered(app_home, GENERIC_FILE)?;
    validate_generic_keys(&generic)?;
    let generic = parse_generic(&generic, splunk_home)?;

    let inputs = load_layered(app_home, INPUTS_FILE)?;
    let inputs = parse_inputs(&inputs, app_home, splunk_home, &generic)?;
    if generic.hec.state == HecState::Disabled && inputs.iter().any(|input| !input.disabled) {
        return Err(ConfigError::new("DBX-RS-CFG-0039", "hec.enabled"));
    }
    Ok(EffectiveConfig { generic, inputs })
}

fn load_layered(app_home: &Path, file_name: &'static str) -> Result<Ini, ConfigError> {
    let mut ini = Ini::new_cs();
    let default_path = app_home.join("default").join(file_name);
    ini.load(&default_path)
        .map_err(|_| ConfigError::new("DBX-RS-CFG-0001", file_name))?;
    let local_path = app_home.join("local").join(file_name);
    if local_path.exists() {
        ini.load_and_append(&local_path)
            .map_err(|_| ConfigError::new("DBX-RS-CFG-0002", file_name))?;
    }
    Ok(ini)
}

fn validate_generic_keys(ini: &Ini) -> Result<(), ConfigError> {
    const SECTIONS: &[(&str, &[&str])] = &[
        (
            "paths",
            &[
                "log_file",
                "splunkd_pid_file",
                "instance_lock_file",
                "master_key_file",
                "secret_dir",
                "hec_token_file",
                "hec_server_pem_file",
                "hec_ca_file",
                "spool_key_file",
                "state_dir",
                "spool_dir",
                "managed_inputs_file",
            ],
        ),
        ("logging", &["max_file_bytes", "backup_count"]),
        (
            "daemon",
            &[
                "poll_interval_ms",
                "shutdown_grace_secs",
                "configuration_reload_secs",
                "max_workers",
            ],
        ),
        (
            "spool",
            &["segment_max_bytes", "input_max_bytes", "total_max_bytes"],
        ),
        (
            "hec",
            &[
                "enabled",
                "manage_input",
                "url",
                "input_name",
                "listen_port",
                "accept_from",
                "verify_tls",
                "timeout_secs",
                "batch_max_events",
                "batch_max_bytes",
                "max_event_bytes",
                "index",
                "sourcetype",
                "source",
                "use_ack",
            ],
        ),
    ];

    let allowed_sections = SECTIONS
        .iter()
        .map(|(section, _)| *section)
        .collect::<HashSet<_>>();
    for (section, values) in ini.get_map_ref() {
        if !allowed_sections.contains(section.as_str()) {
            return Err(ConfigError::new("DBX-RS-CFG-0003", "section"));
        }
        let allowed_keys = SECTIONS
            .iter()
            .find_map(|(candidate, keys)| (*candidate == section).then_some(*keys))
            .ok_or_else(|| ConfigError::new("DBX-RS-CFG-0003", "section"))?;
        if values
            .keys()
            .any(|key| !allowed_keys.contains(&key.as_str()))
        {
            return Err(ConfigError::new("DBX-RS-CFG-0004", "setting"));
        }
    }
    Ok(())
}

fn parse_generic(ini: &Ini, splunk_home: &Path) -> Result<GenericConfig, ConfigError> {
    let paths = PathsConfig {
        log_file: required_var_path(ini, "paths", "log_file", splunk_home)?,
        splunkd_pid_file: required_var_path(ini, "paths", "splunkd_pid_file", splunk_home)?,
        instance_lock_file: required_runtime_path(ini, "paths", "instance_lock_file", splunk_home)?,
        master_key_file: required_var_path(ini, "paths", "master_key_file", splunk_home)?,
        secret_dir: required_var_path(ini, "paths", "secret_dir", splunk_home)?,
        hec_token_file: required_var_path(ini, "paths", "hec_token_file", splunk_home)?,
        hec_server_pem_file: required_var_path(ini, "paths", "hec_server_pem_file", splunk_home)?,
        hec_ca_file: required_var_path(ini, "paths", "hec_ca_file", splunk_home)?,
        spool_key_file: required_var_path(ini, "paths", "spool_key_file", splunk_home)?,
        state_dir: required_var_path(ini, "paths", "state_dir", splunk_home)?,
        spool_dir: required_var_path(ini, "paths", "spool_dir", splunk_home)?,
        managed_inputs_file: required_path(ini, "paths", "managed_inputs_file", splunk_home)?,
    };

    let max_file_bytes = required_u64(ini, "logging", "max_file_bytes")?;
    if !(4_096..=HARD_LOG_FILE_BYTES).contains(&max_file_bytes) {
        return Err(ConfigError::new(
            "DBX-RS-CFG-0005",
            "logging.max_file_bytes",
        ));
    }
    let backup_count = required_u8(ini, "logging", "backup_count")?;
    if backup_count > 20 {
        return Err(ConfigError::new("DBX-RS-CFG-0006", "logging.backup_count"));
    }
    let logging = LoggingConfig {
        max_file_bytes,
        backup_count,
    };

    let poll_interval_ms = required_u64(ini, "daemon", "poll_interval_ms")?;
    if !(100..=60_000).contains(&poll_interval_ms) {
        return Err(ConfigError::new(
            "DBX-RS-CFG-0007",
            "daemon.poll_interval_ms",
        ));
    }
    let max_workers = parse_worker_limit(&required(ini, "daemon", "max_workers")?)?;
    let shutdown_grace_secs = required_u64(ini, "daemon", "shutdown_grace_secs")?;
    if !(1..=300).contains(&shutdown_grace_secs) {
        return Err(ConfigError::new(
            "DBX-RS-CFG-0036",
            "daemon.shutdown_grace_secs",
        ));
    }
    let configuration_reload_secs = required_u64(ini, "daemon", "configuration_reload_secs")?;
    if !(1..=3_600).contains(&configuration_reload_secs) {
        return Err(ConfigError::new(
            "DBX-RS-CFG-0037",
            "daemon.configuration_reload_secs",
        ));
    }
    let daemon = DaemonConfig {
        poll_interval: Duration::from_millis(poll_interval_ms),
        shutdown_grace: Duration::from_secs(shutdown_grace_secs),
        configuration_reload: Duration::from_secs(configuration_reload_secs),
        max_workers,
    };

    let segment_max_bytes = required_u64(ini, "spool", "segment_max_bytes")?;
    if !(4_096..=HARD_SPOOL_SEGMENT_BYTES).contains(&segment_max_bytes) {
        return Err(ConfigError::new(
            "DBX-RS-CFG-0050",
            "spool.segment_max_bytes",
        ));
    }
    let input_max_bytes = required_u64(ini, "spool", "input_max_bytes")?;
    if input_max_bytes < segment_max_bytes || input_max_bytes > HARD_SPOOL_INPUT_BYTES {
        return Err(ConfigError::new("DBX-RS-CFG-0051", "spool.input_max_bytes"));
    }
    let total_max_bytes = required_u64(ini, "spool", "total_max_bytes")?;
    if total_max_bytes < input_max_bytes || total_max_bytes > HARD_SPOOL_TOTAL_BYTES {
        return Err(ConfigError::new("DBX-RS-CFG-0052", "spool.total_max_bytes"));
    }
    let spool = SpoolConfig {
        segment_max_bytes,
        input_max_bytes,
        total_max_bytes,
    };

    let hec = parse_hec(ini)?;
    Ok(GenericConfig {
        paths,
        logging,
        daemon,
        spool,
        hec,
    })
}

fn parse_hec(ini: &Ini) -> Result<HecConfig, ConfigError> {
    let enabled = required_bool(ini, "hec", "enabled")?;
    let url = required(ini, "hec", "url")?;
    if enabled
        && (!url.starts_with("https://")
            || url.contains('@')
            || !url.ends_with("/services/collector/event"))
    {
        return Err(ConfigError::new("DBX-RS-CFG-0008", "hec.url"));
    }
    let input_name = required_label(ini, "hec", "input_name")?;
    let listen_port = required_u16(ini, "hec", "listen_port")?;
    let accept_from = required(ini, "hec", "accept_from")?;
    if accept_from.len() > 512
        || !accept_from.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b':' | b'/' | b',' | b'!' | b' ' | b'-')
        })
    {
        return Err(ConfigError::new("DBX-RS-CFG-0041", "hec.accept_from"));
    }
    let batch_max_events = required_usize(ini, "hec", "batch_max_events")?;
    if batch_max_events == 0 || batch_max_events > 10_000 {
        return Err(ConfigError::new("DBX-RS-CFG-0009", "hec.batch_max_events"));
    }
    let batch_max_bytes = required_u64(ini, "hec", "batch_max_bytes")?;
    if !(1..=HARD_HEC_BATCH_BYTES).contains(&batch_max_bytes) {
        return Err(ConfigError::new("DBX-RS-CFG-0010", "hec.batch_max_bytes"));
    }
    let max_event_bytes = required_u64(ini, "hec", "max_event_bytes")?;
    if !(1..=HARD_HEC_EVENT_BYTES).contains(&max_event_bytes) || max_event_bytes > batch_max_bytes {
        return Err(ConfigError::new("DBX-RS-CFG-0011", "hec.max_event_bytes"));
    }
    let timeout_secs = required_u64(ini, "hec", "timeout_secs")?;
    if !(1..=HARD_OPERATION_SECONDS).contains(&timeout_secs) {
        return Err(ConfigError::new("DBX-RS-CFG-0034", "hec.timeout_secs"));
    }
    let timeout = Duration::from_secs(timeout_secs);
    let verify_tls = required_bool(ini, "hec", "verify_tls")?;
    if !verify_tls
        && !url.starts_with("https://localhost:")
        && !url.starts_with("https://127.0.0.1:")
        && !url.starts_with("https://[::1]:")
    {
        return Err(ConfigError::new("DBX-RS-CFG-0035", "hec.verify_tls"));
    }
    Ok(HecConfig {
        state: if enabled {
            HecState::Enabled
        } else {
            HecState::Disabled
        },
        input_management: if required_bool(ini, "hec", "manage_input")? {
            HecInputManagement::Managed
        } else {
            HecInputManagement::External
        },
        url,
        input_name,
        listen_port,
        accept_from,
        tls_verification: if verify_tls {
            TlsVerification::Full
        } else {
            TlsVerification::Disabled
        },
        timeout,
        batch_max_events,
        batch_max_bytes,
        max_event_bytes,
        index: required_label(ini, "hec", "index")?,
        sourcetype: required_label(ini, "hec", "sourcetype")?,
        source: required_label(ini, "hec", "source")?,
        acknowledgment: if required_bool(ini, "hec", "use_ack")? {
            IndexerAcknowledgment::Enabled
        } else {
            IndexerAcknowledgment::Disabled
        },
    })
}

fn parse_inputs(
    ini: &Ini,
    app_home: &Path,
    splunk_home: &Path,
    generic: &GenericConfig,
) -> Result<Vec<InputConfig>, ConfigError> {
    const ALLOWED: &[&str] = &[
        "disabled",
        "connector",
        "interval_secs",
        "host",
        "port",
        "database",
        "username",
        "secret_ref",
        "tls_mode",
        "tls_server_name",
        "tls_ca_file",
        "query",
        "query_file",
        "connect_timeout_secs",
        "probe_timeout_secs",
        "max_rows",
        "max_bytes",
        "query_timeout_secs",
        "index",
        "sourcetype",
        "source",
    ];
    let mut inputs = Vec::new();
    for (name, values) in ini.get_map_ref() {
        validate_label(name, "input.name")?;
        if values.keys().any(|key| {
            matches!(
                key.as_str(),
                "password" | "secret" | "token" | "connection_string"
            )
        }) {
            return Err(ConfigError::new("DBX-RS-CFG-0013", "input.secret"));
        }
        if values.keys().any(|key| !ALLOWED.contains(&key.as_str())) {
            return Err(ConfigError::new("DBX-RS-CFG-0012", "input.setting"));
        }
        inputs.push(parse_input(ini, name, app_home, splunk_home, generic)?);
    }
    inputs.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(inputs)
}

fn parse_input(
    ini: &Ini,
    name: &str,
    app_home: &Path,
    splunk_home: &Path,
    generic: &GenericConfig,
) -> Result<InputConfig, ConfigError> {
    let connector = required_label(ini, name, "connector")?;
    if connector != "postgres" {
        return Err(ConfigError::new("DBX-RS-CFG-0014", "input.connector"));
    }
    let max_rows = required_u64(ini, name, "max_rows")?;
    if !(1..=HARD_INPUT_ROWS).contains(&max_rows) {
        return Err(ConfigError::new("DBX-RS-CFG-0015", "input.max_rows"));
    }
    let max_bytes = required_u64(ini, name, "max_bytes")?;
    if !(1..=HARD_INPUT_BYTES).contains(&max_bytes) {
        return Err(ConfigError::new("DBX-RS-CFG-0016", "input.max_bytes"));
    }
    let required_segment_bytes = max_rows
        .checked_mul(SPOOL_EVENT_OVERHEAD_BYTES)
        .and_then(|overhead| overhead.checked_add(max_bytes))
        .and_then(|bytes| bytes.checked_add(SPOOL_FORMAT_OVERHEAD_BYTES))
        .ok_or_else(|| ConfigError::new("DBX-RS-CFG-0053", "input.spool_bound"))?;
    if required_segment_bytes > generic.spool.segment_max_bytes {
        return Err(ConfigError::new("DBX-RS-CFG-0053", "input.spool_bound"));
    }
    let interval_secs = required_u64(ini, name, "interval_secs")?;
    if !(1..=HARD_INTERVAL_SECONDS).contains(&interval_secs) {
        return Err(ConfigError::new("DBX-RS-CFG-0019", "input.interval_secs"));
    }
    let secret_ref = required(ini, name, "secret_ref")?;
    if !secret_ref
        .strip_prefix("local:")
        .is_some_and(valid_label_value)
    {
        return Err(ConfigError::new("DBX-RS-CFG-0020", "input.secret_ref"));
    }
    let tls_mode = required(ini, name, "tls_mode")?;
    if !matches!(tls_mode.as_str(), "disable" | "verify-full") {
        return Err(ConfigError::new("DBX-RS-CFG-0021", "input.tls_mode"));
    }
    let port = required_u16(ini, name, "port")?;
    if port == 0 {
        return Err(ConfigError::new("DBX-RS-CFG-0022", "input.port"));
    }

    let connect_timeout = required_nonzero_duration(ini, name, "connect_timeout_secs")?;
    let probe_timeout = required_nonzero_duration(ini, name, "probe_timeout_secs")?;
    let query_timeout = required_nonzero_duration(ini, name, "query_timeout_secs")?;

    Ok(InputConfig {
        name: name.into(),
        disabled: required_bool(ini, name, "disabled")?,
        connector: connector.clone(),
        interval: Duration::from_secs(interval_secs),
        host: required_nonempty(ini, name, "host")?,
        port,
        database: required_nonempty(ini, name, "database")?,
        username: required_nonempty(ini, name, "username")?,
        secret_ref,
        tls_mode,
        tls_server_name: optional(ini, name, "tls_server_name"),
        tls_ca_file: optional_asset_path(
            ini,
            name,
            "tls_ca_file",
            splunk_home,
            &app_home.join("certs").join(query_namespace(&connector)),
            "DBX-RS-CFG-0049",
        )?,
        query: parse_query_source(ini, name, app_home, splunk_home, &connector)?,
        connect_timeout,
        probe_timeout,
        max_rows,
        max_bytes,
        query_timeout,
        index: optional_label(ini, name, "index")?.unwrap_or_else(|| generic.hec.index.clone()),
        sourcetype: optional_label(ini, name, "sourcetype")?
            .unwrap_or_else(|| generic.hec.sourcetype.clone()),
        source: optional_label(ini, name, "source")?.unwrap_or_else(|| generic.hec.source.clone()),
    })
}

fn parse_query_source(
    ini: &Ini,
    section: &str,
    app_home: &Path,
    splunk_home: &Path,
    connector: &str,
) -> Result<QuerySource, ConfigError> {
    let inline = optional(ini, section, "query").filter(|value| !value.is_empty());
    let file = optional_asset_path(
        ini,
        section,
        "query_file",
        splunk_home,
        &app_home.join("queries").join(query_namespace(connector)),
        "DBX-RS-CFG-0048",
    )?;
    match (inline, file) {
        (Some(_), Some(_)) => Err(ConfigError::new("DBX-RS-CFG-0046", "input.query")),
        (None, None) => Err(ConfigError::new("DBX-RS-CFG-0045", "input.query")),
        (Some(query), None) => {
            if query.len() as u64 > MAX_QUERY_BYTES || query.contains('\0') {
                return Err(ConfigError::new("DBX-RS-CFG-0047", "input.query"));
            }
            Ok(QuerySource::Inline(query))
        }
        (None, Some(path)) => Ok(QuerySource::File(path)),
    }
}

fn query_namespace(connector: &str) -> &'static str {
    match connector {
        "postgres" => "psql",
        _ => "unsupported",
    }
}

fn parse_worker_limit(value: &str) -> Result<WorkerLimit, ConfigError> {
    if value == "auto" {
        return Ok(WorkerLimit::Auto);
    }
    value
        .parse::<usize>()
        .ok()
        .and_then(NonZeroUsize::new)
        .map(WorkerLimit::Fixed)
        .ok_or_else(|| ConfigError::new("DBX-RS-CFG-0023", "daemon.max_workers"))
}

fn required(ini: &Ini, section: &str, key: &'static str) -> Result<String, ConfigError> {
    optional(ini, section, key)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ConfigError::new("DBX-RS-CFG-0024", key))
}

fn optional(ini: &Ini, section: &str, key: &str) -> Option<String> {
    ini.get(section, key).map(|value| value.trim().to_owned())
}

fn required_nonempty(ini: &Ini, section: &str, key: &'static str) -> Result<String, ConfigError> {
    let value = required(ini, section, key)?;
    if value.len() > 512 || value.chars().any(char::is_control) {
        return Err(ConfigError::new("DBX-RS-CFG-0025", key));
    }
    Ok(value)
}

fn required_label(ini: &Ini, section: &str, key: &'static str) -> Result<String, ConfigError> {
    let value = required(ini, section, key)?;
    validate_label(&value, key)?;
    Ok(value)
}

fn optional_label(
    ini: &Ini,
    section: &str,
    key: &'static str,
) -> Result<Option<String>, ConfigError> {
    optional(ini, section, key)
        .map(|value| {
            validate_label(&value, key)?;
            Ok(value)
        })
        .transpose()
}

fn validate_label(value: &str, field: &'static str) -> Result<(), ConfigError> {
    if !valid_label_value(value) {
        return Err(ConfigError::new("DBX-RS-CFG-0026", field));
    }
    Ok(())
}

fn valid_label_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LABEL_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'+')
        })
}

fn required_bool(ini: &Ini, section: &str, key: &'static str) -> Result<bool, ConfigError> {
    match required(ini, section, key)?.to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" | "on" => Ok(true),
        "false" | "no" | "0" | "off" => Ok(false),
        _ => Err(ConfigError::new("DBX-RS-CFG-0027", key)),
    }
}

fn required_u64(ini: &Ini, section: &str, key: &'static str) -> Result<u64, ConfigError> {
    required(ini, section, key)?
        .parse()
        .map_err(|_| ConfigError::new("DBX-RS-CFG-0028", key))
}

fn required_u16(ini: &Ini, section: &str, key: &'static str) -> Result<u16, ConfigError> {
    required(ini, section, key)?
        .parse()
        .map_err(|_| ConfigError::new("DBX-RS-CFG-0029", key))
}

fn required_u8(ini: &Ini, section: &str, key: &'static str) -> Result<u8, ConfigError> {
    required(ini, section, key)?
        .parse()
        .map_err(|_| ConfigError::new("DBX-RS-CFG-0030", key))
}

fn required_usize(ini: &Ini, section: &str, key: &'static str) -> Result<usize, ConfigError> {
    required(ini, section, key)?
        .parse()
        .map_err(|_| ConfigError::new("DBX-RS-CFG-0031", key))
}

fn required_nonzero_duration(
    ini: &Ini,
    section: &str,
    key: &'static str,
) -> Result<Duration, ConfigError> {
    let seconds = required_u64(ini, section, key)?;
    if !(1..=HARD_OPERATION_SECONDS).contains(&seconds) {
        return Err(ConfigError::new("DBX-RS-CFG-0038", key));
    }
    Ok(Duration::from_secs(seconds))
}

fn required_path(
    ini: &Ini,
    section: &str,
    key: &'static str,
    splunk_home: &Path,
) -> Result<PathBuf, ConfigError> {
    expand_path(&required(ini, section, key)?, splunk_home, key)
}

fn required_var_path(
    ini: &Ini,
    section: &str,
    key: &'static str,
    splunk_home: &Path,
) -> Result<PathBuf, ConfigError> {
    let path = required_path(ini, section, key, splunk_home)?;
    if !path.starts_with(splunk_home.join("var")) {
        return Err(ConfigError::new("DBX-RS-CFG-0043", key));
    }
    Ok(path)
}

fn required_runtime_path(
    ini: &Ini,
    section: &str,
    key: &'static str,
    splunk_home: &Path,
) -> Result<PathBuf, ConfigError> {
    let path = required_path(ini, section, key, splunk_home)?;
    let runtime_root = splunk_home.join("var/run/splunk/dbx-rs");
    if path == runtime_root || !path.starts_with(runtime_root) {
        return Err(ConfigError::new("DBX-RS-CFG-0044", key));
    }
    Ok(path)
}

fn optional_path(
    ini: &Ini,
    section: &str,
    key: &'static str,
    splunk_home: &Path,
) -> Result<Option<PathBuf>, ConfigError> {
    optional(ini, section, key)
        .filter(|value| !value.is_empty())
        .map(|value| expand_path(&value, splunk_home, key))
        .transpose()
}

fn optional_asset_path(
    ini: &Ini,
    section: &str,
    key: &'static str,
    splunk_home: &Path,
    asset_root: &Path,
    error_code: &'static str,
) -> Result<Option<PathBuf>, ConfigError> {
    let path = optional_path(ini, section, key, splunk_home)?;
    if path
        .as_ref()
        .is_some_and(|path| path == asset_root || !path.starts_with(asset_root))
    {
        return Err(ConfigError::new(error_code, key));
    }
    Ok(path)
}

fn expand_path(
    value: &str,
    splunk_home: &Path,
    field: &'static str,
) -> Result<PathBuf, ConfigError> {
    let path = if value == "$SPLUNK_HOME" {
        splunk_home.to_path_buf()
    } else if let Some(relative) = value.strip_prefix("$SPLUNK_HOME/") {
        splunk_home.join(relative)
    } else {
        PathBuf::from(value)
    };
    if path
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        return Err(ConfigError::new("DBX-RS-CFG-0032", field));
    }
    if !path.is_absolute() {
        return Err(ConfigError::new("DBX-RS-CFG-0033", field));
    }
    if !path.starts_with(splunk_home) {
        return Err(ConfigError::new("DBX-RS-CFG-0042", field));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    fn fixture() -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "dbx-rs-config-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let app = root.join("etc/apps/TA-dbx-rs");
        fs::create_dir_all(app.join("default")).expect("default directory must be created");
        fs::create_dir_all(app.join("local")).expect("local directory must be created");
        fs::write(app.join("default").join(GENERIC_FILE), generic_config())
            .expect("generic fixture must be written");
        fs::write(app.join("default").join(INPUTS_FILE), input_config())
            .expect("input fixture must be written");
        (root, app)
    }

    fn generic_config() -> &'static str {
        r"[paths]
log_file = $SPLUNK_HOME/var/log/splunk/dbx-trace.log
splunkd_pid_file = $SPLUNK_HOME/var/run/splunk/splunkd.pid
instance_lock_file = $SPLUNK_HOME/var/run/splunk/dbx-rs/daemon.lock
master_key_file = $SPLUNK_HOME/var/lib/splunk/dbx-rs/credentials/master.key
secret_dir = $SPLUNK_HOME/var/lib/splunk/dbx-rs/credentials/secrets
hec_token_file = $SPLUNK_HOME/var/lib/splunk/dbx-rs/hec/token
hec_server_pem_file = $SPLUNK_HOME/var/lib/splunk/dbx-rs/hec/server.pem
hec_ca_file = $SPLUNK_HOME/var/lib/splunk/dbx-rs/hec/ca.pem
spool_key_file = $SPLUNK_HOME/var/lib/splunk/dbx-rs/durable/spool.key
state_dir = $SPLUNK_HOME/var/lib/splunk/dbx-rs/state
spool_dir = $SPLUNK_HOME/var/lib/splunk/dbx-rs/spool
managed_inputs_file = $SPLUNK_HOME/etc/apps/TA-dbx-rs/local/inputs.conf

[logging]
max_file_bytes = 10000000
backup_count = 2

[daemon]
poll_interval_ms = 1000
shutdown_grace_secs = 30
configuration_reload_secs = 5
max_workers = auto

[spool]
segment_max_bytes = 10000000
input_max_bytes = 100000000
total_max_bytes = 1000000000

[hec]
enabled = true
manage_input = true
url = https://localhost:8088/services/collector/event
input_name = dbx_rs
listen_port = 8088
accept_from = 127.0.0.1,::1
verify_tls = true
timeout_secs = 10
batch_max_events = 500
batch_max_bytes = 1000000
max_event_bytes = 1000000
index = dbx_rs_test
sourcetype = dbx_rs:database:row
source = dbx_rs:daemon
use_ack = false
"
    }

    fn input_config() -> &'static str {
        r"[heartbeat]
disabled = false
connector = postgres
interval_secs = 60
host = database.example
port = 5432
database = events
username = reader
secret_ref = local:heartbeat
tls_mode = verify-full
tls_server_name = database.example
tls_ca_file = $SPLUNK_HOME/etc/apps/TA-dbx-rs/certs/psql/database-ca.pem
query_file = $SPLUNK_HOME/etc/apps/TA-dbx-rs/queries/psql/heartbeat.sql
connect_timeout_secs = 10
probe_timeout_secs = 10
max_rows = 1000
max_bytes = 1048576
query_timeout_secs = 30
index = dbx_rs_test
sourcetype = dbx_rs:postgres:heartbeat
source = dbx_rs:heartbeat
"
    }

    #[test]
    fn loads_typed_defaults_and_local_override() {
        let (root, app) = fixture();
        fs::write(
            app.join("local").join(GENERIC_FILE),
            "[daemon]\nmax_workers = 16\n",
        )
        .expect("override must be written");

        let effective = load_effective_config(&app, &root).expect("config must load");
        assert_eq!(effective.inputs.len(), 1);
        assert_eq!(effective.inputs[0].connector, "postgres");
        assert!(matches!(&effective.inputs[0].query, QuerySource::File(_)));
        assert_eq!(
            effective.generic.logging.max_file_bytes,
            HARD_LOG_FILE_BYTES
        );
        assert_eq!(
            effective
                .generic
                .daemon
                .max_workers
                .effective(NonZeroUsize::new(4).expect("four is nonzero"))
                .get(),
            4
        );
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn rejects_log_size_above_hard_limit() {
        let (root, app) = fixture();
        fs::write(
            app.join("local").join(GENERIC_FILE),
            "[logging]\nmax_file_bytes = 10000001\n",
        )
        .expect("override must be written");

        let error = load_effective_config(&app, &root).expect_err("oversized log must fail");
        assert_eq!(error.code(), "DBX-RS-CFG-0005");
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn loads_bounded_spool_paths_and_quotas() {
        let (root, app) = fixture();

        let effective = load_effective_config(&app, &root).expect("config must load");

        assert_eq!(
            effective.generic.paths.spool_dir,
            root.join("var/lib/splunk/dbx-rs/spool")
        );
        assert_eq!(effective.generic.spool.segment_max_bytes, 10_000_000);
        assert_eq!(effective.generic.spool.input_max_bytes, 100_000_000);
        assert_eq!(effective.generic.spool.total_max_bytes, 1_000_000_000);
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn rejects_inverted_spool_quota_hierarchy() {
        let (root, app) = fixture();
        fs::write(
            app.join("local").join(GENERIC_FILE),
            "[spool]\ninput_max_bytes = 9999999\n",
        )
        .expect("override must be written");

        let error =
            load_effective_config(&app, &root).expect_err("inverted spool quotas must fail");

        assert_eq!(error.code(), "DBX-RS-CFG-0051");
        assert_eq!(error.field(), "spool.input_max_bytes");
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn rejects_input_that_cannot_fit_one_atomic_spool_segment() {
        let (root, app) = fixture();
        let oversized = input_config().replace("max_rows = 1000", "max_rows = 10000");
        fs::write(app.join("default").join(INPUTS_FILE), oversized)
            .expect("oversized input fixture must be written");

        let error = load_effective_config(&app, &root)
            .expect_err("input exceeding its atomic segment must fail");

        assert_eq!(error.code(), "DBX-RS-CFG-0053");
        assert_eq!(error.field(), "input.spool_bound");
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn accepts_exact_atomic_spool_bound_and_rejects_one_byte_less() {
        let (root, app) = fixture();
        let exact = 1_048_576 + (1_000 * SPOOL_EVENT_OVERHEAD_BYTES) + SPOOL_FORMAT_OVERHEAD_BYTES;
        fs::write(
            app.join("local").join(GENERIC_FILE),
            format!("[spool]\nsegment_max_bytes = {exact}\n"),
        )
        .expect("exact spool override must be written");

        load_effective_config(&app, &root).expect("exact spool bound must load");

        fs::write(
            app.join("local").join(GENERIC_FILE),
            format!("[spool]\nsegment_max_bytes = {}\n", exact - 1),
        )
        .expect("undersized spool override must be written");
        let error = load_effective_config(&app, &root)
            .expect_err("one byte below the spool bound must fail");
        assert_eq!(error.code(), "DBX-RS-CFG-0053");
        assert_eq!(error.field(), "input.spool_bound");
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn rejects_invalid_per_input_hec_metadata_labels() {
        for (field, value) in [
            ("index", String::new()),
            ("sourcetype", "a".repeat(MAX_LABEL_BYTES + 1)),
            ("source", "invalid\u{7f}label".to_owned()),
        ] {
            let (root, app) = fixture();
            let original = format!(
                "{field} = {}",
                match field {
                    "index" => "dbx_rs_test",
                    "sourcetype" => "dbx_rs:postgres:heartbeat",
                    "source" => "dbx_rs:heartbeat",
                    _ => unreachable!("test field is fixed"),
                }
            );
            let invalid = input_config().replace(&original, &format!("{field} = {value}"));
            fs::write(app.join("default").join(INPUTS_FILE), invalid)
                .expect("invalid metadata fixture must be written");

            let error = load_effective_config(&app, &root)
                .expect_err("invalid per-input HEC metadata must fail");
            assert_eq!(error.code(), "DBX-RS-CFG-0026");
            assert_eq!(error.field(), field);
            fs::remove_dir_all(root).expect("fixture must be removed");
        }
    }

    #[test]
    fn rejects_spool_path_outside_splunk_var() {
        let (root, app) = fixture();
        fs::write(
            app.join("local").join(GENERIC_FILE),
            "[paths]\nspool_dir = $SPLUNK_HOME/etc/apps/TA-dbx-rs/spool\n",
        )
        .expect("override must be written");

        let error = load_effective_config(&app, &root).expect_err("app-local spool must fail");

        assert_eq!(error.code(), "DBX-RS-CFG-0043");
        assert_eq!(error.field(), "spool_dir");
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn rejects_plaintext_password_setting() {
        let (root, app) = fixture();
        let unsafe_input = input_config().replace(
            "secret_ref = local:heartbeat",
            "password = exposed\nsecret_ref = local:heartbeat",
        );
        fs::write(app.join("default").join(INPUTS_FILE), unsafe_input)
            .expect("unsafe fixture must be written");

        let error = load_effective_config(&app, &root).expect_err("plaintext password must fail");
        assert_eq!(error.code(), "DBX-RS-CFG-0013");
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn rejects_obsolete_output_setting() {
        let (root, app) = fixture();
        let obsolete = input_config().replace(
            "source = dbx_rs:heartbeat",
            "source = dbx_rs:heartbeat\noutput = hec",
        );
        fs::write(app.join("default").join(INPUTS_FILE), obsolete)
            .expect("obsolete fixture must be written");

        let error = load_effective_config(&app, &root).expect_err("obsolete setting must fail");
        assert_eq!(error.code(), "DBX-RS-CFG-0012");
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn rejects_input_timeout_above_the_connector_hard_limit() {
        let (root, app) = fixture();
        let oversized =
            input_config().replace("query_timeout_secs = 30", "query_timeout_secs = 86401");
        fs::write(app.join("default").join(INPUTS_FILE), oversized)
            .expect("input fixture must be written");

        let error = load_effective_config(&app, &root).expect_err("oversized timeout must fail");

        assert_eq!(error.code(), "DBX-RS-CFG-0038");
        assert_eq!(error.field(), "query_timeout_secs");
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn rejects_unrepresentable_scheduler_and_hec_durations() {
        let (root, app) = fixture();
        let oversized_interval = input_config().replace(
            "interval_secs = 60",
            &format!("interval_secs = {}", HARD_INTERVAL_SECONDS + 1),
        );
        fs::write(app.join("default").join(INPUTS_FILE), oversized_interval)
            .expect("interval fixture must be written");
        let error = load_effective_config(&app, &root)
            .expect_err("oversized scheduling interval must fail");
        assert_eq!(error.code(), "DBX-RS-CFG-0019");
        assert_eq!(error.field(), "input.interval_secs");
        fs::remove_dir_all(root).expect("fixture must be removed");

        let (root, app) = fixture();
        fs::write(
            app.join("local").join(GENERIC_FILE),
            format!("[hec]\ntimeout_secs = {}\n", HARD_OPERATION_SECONDS + 1),
        )
        .expect("HEC timeout fixture must be written");
        let error =
            load_effective_config(&app, &root).expect_err("oversized HEC timeout must fail");
        assert_eq!(error.code(), "DBX-RS-CFG-0034");
        assert_eq!(error.field(), "hec.timeout_secs");
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn rejects_generated_paths_outside_splunk_var() {
        let (root, app) = fixture();
        fs::write(
            app.join("local").join(GENERIC_FILE),
            "[paths]\nlog_file = $SPLUNK_HOME/etc/apps/TA-dbx-rs/local/dbx-trace.log\n",
        )
        .expect("override must be written");

        let error = load_effective_config(&app, &root).expect_err("app-local log must fail");
        assert_eq!(error.code(), "DBX-RS-CFG-0043");
        assert_eq!(error.field(), "log_file");
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn rejects_lock_outside_private_runtime_directory() {
        let (root, app) = fixture();
        fs::write(
            app.join("local").join(GENERIC_FILE),
            "[paths]\ninstance_lock_file = $SPLUNK_HOME/var/run/splunk/dbx-rs.lock\n",
        )
        .expect("override must be written");

        let error =
            load_effective_config(&app, &root).expect_err("shared runtime lock path must fail");
        assert_eq!(error.code(), "DBX-RS-CFG-0044");
        assert_eq!(error.field(), "instance_lock_file");
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn rejects_input_files_outside_splunk_home() {
        let (root, app) = fixture();
        let external_query = input_config().replace(
            "query_file = $SPLUNK_HOME/etc/apps/TA-dbx-rs/queries/psql/heartbeat.sql",
            "query_file = /tmp/heartbeat.sql",
        );
        fs::write(app.join("default").join(INPUTS_FILE), external_query)
            .expect("input fixture must be written");

        let error = load_effective_config(&app, &root).expect_err("external query must fail");
        assert_eq!(error.code(), "DBX-RS-CFG-0042");
        assert_eq!(error.field(), "query_file");
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn accepts_inline_query_and_redacts_its_debug_output() {
        let (root, app) = fixture();
        let inline = input_config().replace(
            "query_file = $SPLUNK_HOME/etc/apps/TA-dbx-rs/queries/psql/heartbeat.sql",
            "query = SELECT 42 AS private_value",
        );
        fs::write(app.join("default").join(INPUTS_FILE), inline)
            .expect("inline fixture must be written");

        let effective = load_effective_config(&app, &root).expect("inline query must load");
        assert_eq!(
            effective.inputs[0].query,
            QuerySource::Inline("SELECT 42 AS private_value".into())
        );
        let debug = format!("{:?}", effective.inputs[0].query);
        assert_eq!(debug, "Inline([REDACTED])");
        assert!(!debug.contains("private_value"));
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn rejects_ambiguous_query_sources() {
        let (root, app) = fixture();
        let ambiguous = input_config().replace(
            "query_file = $SPLUNK_HOME/etc/apps/TA-dbx-rs/queries/psql/heartbeat.sql",
            "query = SELECT 1\nquery_file = $SPLUNK_HOME/etc/apps/TA-dbx-rs/queries/psql/heartbeat.sql",
        );
        fs::write(app.join("default").join(INPUTS_FILE), ambiguous)
            .expect("ambiguous fixture must be written");

        let error = load_effective_config(&app, &root).expect_err("ambiguous query must fail");
        assert_eq!(error.code(), "DBX-RS-CFG-0046");
        assert_eq!(error.field(), "input.query");
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn rejects_missing_query_source() {
        let (root, app) = fixture();
        let missing = input_config().replace(
            "query_file = $SPLUNK_HOME/etc/apps/TA-dbx-rs/queries/psql/heartbeat.sql\n",
            "",
        );
        fs::write(app.join("default").join(INPUTS_FILE), missing)
            .expect("missing-query fixture must be written");

        let error = load_effective_config(&app, &root).expect_err("missing query must fail");
        assert_eq!(error.code(), "DBX-RS-CFG-0045");
        assert_eq!(error.field(), "input.query");
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn rejects_query_and_ca_files_in_local() {
        let (root, app) = fixture();
        let local_query = input_config().replace(
            "query_file = $SPLUNK_HOME/etc/apps/TA-dbx-rs/queries/psql/heartbeat.sql",
            "query_file = $SPLUNK_HOME/etc/apps/TA-dbx-rs/local/heartbeat.sql",
        );
        fs::write(app.join("default").join(INPUTS_FILE), local_query)
            .expect("local query fixture must be written");
        let query_error =
            load_effective_config(&app, &root).expect_err("local query path must fail");
        assert_eq!(query_error.code(), "DBX-RS-CFG-0048");
        assert_eq!(query_error.field(), "query_file");

        let local_ca = input_config().replace(
            "tls_ca_file = $SPLUNK_HOME/etc/apps/TA-dbx-rs/certs/psql/database-ca.pem",
            "tls_ca_file = $SPLUNK_HOME/etc/apps/TA-dbx-rs/local/database-ca.pem",
        );
        fs::write(app.join("default").join(INPUTS_FILE), local_ca)
            .expect("local CA fixture must be written");
        let ca_error = load_effective_config(&app, &root).expect_err("local CA path must fail");
        assert_eq!(ca_error.code(), "DBX-RS-CFG-0049");
        assert_eq!(ca_error.field(), "tls_ca_file");
        fs::remove_dir_all(root).expect("fixture must be removed");
    }
}
