//! Immutable, redacted input preparation for daemon workers.
//!
//! File-backed query and database CA assets are resolved before a worker is spawned. Fingerprints
//! intentionally exclude file paths and secret values. Batch identity is derived from the stanza
//! name, while rising identity is derived from its explicit immutable UUID.

use std::fmt;
use std::time::Duration;

use dbx_rs_config::{
    CollectionMode, HecConfig, HecInputManagement, HecState, IndexerAcknowledgment, InputConfig,
    MAX_QUERY_BYTES, MAX_TLS_CA_BYTES, QuerySource, TlsVerification,
};
use dbx_rs_connector_sdk::{
    CONNECTOR_CONTRACT_VERSION, ConnectionConfig, CursorNullPolicy, QueryText,
    TIMESTAMP_ID_CURSOR_FORMAT_VERSION, TimestampIdCursorSpec, TlsMode,
};
use dbx_rs_secure_store::read_limited;
use ring::digest::{Context, SHA256};

use crate::error::DaemonError;

/// Version of the canonical fingerprint input encodings in this module.
pub const PREPARED_FINGERPRINT_VERSION: u16 = 1;

const INPUT_ID_DOMAIN: &[u8] = b"dbx-rs/batch-input-id/v1\0";
const QUERY_FINGERPRINT_DOMAIN: &[u8] = b"dbx-rs/query-fingerprint/v1\0";
const LINEAGE_FINGERPRINT_DOMAIN: &[u8] = b"dbx-rs/lineage-fingerprint/v1\0";
const REVISION_FINGERPRINT_DOMAIN: &[u8] = b"dbx-rs/revision-fingerprint/v1\0";
const RISING_INPUT_KEY_DOMAIN: &[u8] = b"dbx-rs/rising-input-key/v1\0";
const RISING_LINEAGE_FINGERPRINT_DOMAIN: &[u8] = b"dbx-rs/rising-source-lineage-fingerprint/v1\0";
const RISING_CURSOR_FINGERPRINT_DOMAIN: &[u8] = b"dbx-rs/rising-cursor-identity-fingerprint/v1\0";
const RISING_REVISION_FINGERPRINT_DOMAIN: &[u8] = b"dbx-rs/rising-revision-fingerprint/v1\0";

/// Stable opaque 32-byte spool identity for a prepared input.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct BatchInputId([u8; 32]);

impl BatchInputId {
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for BatchInputId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BatchInputId([REDACTED])")
    }
}

/// Opaque SHA-256 fingerprint with a versioned, domain-separated input encoding.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ConfigurationFingerprint([u8; 32]);

impl ConfigurationFingerprint {
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for ConfigurationFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConfigurationFingerprint([REDACTED])")
    }
}

/// State identity and cursor contract for a rising input.
#[derive(Clone, Eq, PartialEq)]
pub struct PreparedRising {
    pub state_input_id: [u8; 16],
    pub cursor_spec: TimestampIdCursorSpec,
    pub cursor_identity_fingerprint: ConfigurationFingerprint,
}

impl fmt::Debug for PreparedRising {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedRising")
            .field("state_input_id", &"[REDACTED]")
            .field("cursor_spec", &"[REDACTED]")
            .field("cursor_identity_fingerprint", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedSchedule {
    pub disabled: bool,
    pub interval: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedLimits {
    pub max_rows: u64,
    pub max_bytes: u64,
    pub query_timeout: Duration,
}

#[derive(Clone, Eq, PartialEq)]
pub struct PreparedOutput {
    pub index: String,
    pub sourcetype: String,
    pub source: String,
}

impl fmt::Debug for PreparedOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedOutput")
            .field("index", &"[REDACTED]")
            .field("sourcetype", &"[REDACTED]")
            .field("source", &"[REDACTED]")
            .finish()
    }
}

/// One immutable set of already-resolved worker inputs.
#[derive(Clone, Eq, PartialEq)]
pub struct PreparedInput {
    pub input_id: BatchInputId,
    pub rising: Option<PreparedRising>,
    pub name: String,
    pub connector: String,
    pub secret_ref: String,
    pub connection: ConnectionConfig,
    pub query: QueryText,
    pub schedule: PreparedSchedule,
    pub limits: PreparedLimits,
    pub output: PreparedOutput,
    pub query_fingerprint: ConfigurationFingerprint,
    pub lineage_fingerprint: ConfigurationFingerprint,
    pub revision_fingerprint: ConfigurationFingerprint,
}

struct PreparedIdentity {
    input_id: BatchInputId,
    rising: Option<PreparedRising>,
    lineage_fingerprint: ConfigurationFingerprint,
}

impl fmt::Debug for PreparedInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedInput")
            .field("input_id", &"[REDACTED]")
            .field("rising", &self.rising)
            .field("name", &self.name)
            .field("connector", &self.connector)
            .field("secret_ref", &"[REDACTED]")
            .field("connection", &"[REDACTED]")
            .field("query", &"[REDACTED]")
            .field("schedule", &self.schedule)
            .field("limits", &self.limits)
            .field("output", &self.output)
            .field("query_fingerprint", &"[REDACTED]")
            .field("lineage_fingerprint", &"[REDACTED]")
            .field("revision_fingerprint", &"[REDACTED]")
            .finish()
    }
}

/// Resolves all worker file dependencies and computes stable input fingerprints.
///
/// Secret values are deliberately not accepted by this API. The returned secret reference is
/// resolved only inside the worker immediately before connector use.
///
/// # Errors
///
/// Returns a redacted error when the configured query or CA cannot be read within its bound, the
/// query is not UTF-8, TLS or cursor configuration is invalid, or a canonical fingerprint field
/// is too large.
pub fn prepare_input(input: &InputConfig, hec: &HecConfig) -> Result<PreparedInput, DaemonError> {
    let query = resolve_query(&input.query)?;
    let tls_ca_pem = input
        .tls_ca_file
        .as_deref()
        .map(|path| {
            read_limited(path, MAX_TLS_CA_BYTES).map_err(|_| {
                preparation_error(
                    "DBX-RS-PREP-0003",
                    "tls_ca_input",
                    "configured database CA file could not be read",
                )
            })
        })
        .transpose()?;
    let tls_mode = input.tls_mode.parse::<TlsMode>().map_err(|_| {
        preparation_error(
            "DBX-RS-PREP-0004",
            "tls_configuration",
            "configured database TLS mode is invalid",
        )
    })?;
    let connection = ConnectionConfig {
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
    };
    let query_fingerprint = query_fingerprint(&input.connector, query.as_bytes())?;
    let PreparedIdentity {
        input_id,
        rising,
        lineage_fingerprint,
    } = prepare_identity(input, query_fingerprint)?;
    let operational_revision_fingerprint = revision_fingerprint(
        lineage_fingerprint,
        input,
        hec,
        connection.tls_mode,
        connection.tls_ca_pem.as_deref(),
    )?;
    let revision_fingerprint = match &rising {
        Some(rising) => rising_revision_fingerprint(
            operational_revision_fingerprint,
            rising.cursor_identity_fingerprint,
            rising.cursor_spec.overlap,
        ),
        None => operational_revision_fingerprint,
    };

    Ok(PreparedInput {
        input_id,
        rising,
        name: input.name.clone(),
        connector: input.connector.clone(),
        secret_ref: input.secret_ref.clone(),
        connection,
        query: QueryText::new(query),
        schedule: PreparedSchedule {
            disabled: input.disabled,
            interval: input.interval,
        },
        limits: PreparedLimits {
            max_rows: input.max_rows,
            max_bytes: input.max_bytes,
            query_timeout: input.query_timeout,
        },
        output: PreparedOutput {
            index: input.index.clone(),
            sourcetype: input.sourcetype.clone(),
            source: input.source.clone(),
        },
        query_fingerprint,
        lineage_fingerprint,
        revision_fingerprint,
    })
}

fn prepare_identity(
    input: &InputConfig,
    query_fingerprint: ConfigurationFingerprint,
) -> Result<PreparedIdentity, DaemonError> {
    if input.connector == "oracle" && matches!(&input.mode, CollectionMode::Rising(_)) {
        return Err(preparation_error(
            "DBX-RS-PREP-0007",
            "cursor_configuration",
            "Oracle rising collection is not supported",
        ));
    }
    match &input.mode {
        CollectionMode::Batch => {
            let input_id = batch_input_id(&input.name)?;
            let lineage_fingerprint =
                batch_lineage_fingerprint(input_id, input, query_fingerprint)?;
            Ok(PreparedIdentity {
                input_id,
                rising: None,
                lineage_fingerprint,
            })
        }
        CollectionMode::Rising(configured) => {
            let state_input_id = configured.input_id.into_bytes();
            let input_id = rising_input_key(state_input_id);
            let cursor_spec = TimestampIdCursorSpec {
                timestamp_field: configured.timestamp_field.clone(),
                id_field: configured.id_field.clone(),
                overlap: configured.overlap,
                null_policy: CursorNullPolicy::Reject,
            };
            cursor_spec.validate().map_err(|_| {
                preparation_error(
                    "DBX-RS-PREP-0006",
                    "cursor_configuration",
                    "configured rising cursor is invalid",
                )
            })?;
            let cursor_identity_fingerprint = cursor_identity_fingerprint(&cursor_spec)?;
            let lineage_fingerprint =
                rising_lineage_fingerprint(state_input_id, input, query_fingerprint)?;
            Ok(PreparedIdentity {
                input_id,
                rising: Some(PreparedRising {
                    state_input_id,
                    cursor_spec,
                    cursor_identity_fingerprint,
                }),
                lineage_fingerprint,
            })
        }
    }
}

fn resolve_query(source: &QuerySource) -> Result<String, DaemonError> {
    match source {
        QuerySource::Inline(query) => Ok(query.clone()),
        QuerySource::File(path) => {
            let bytes = read_limited(path, MAX_QUERY_BYTES).map_err(|_| {
                preparation_error(
                    "DBX-RS-PREP-0001",
                    "query_input",
                    "configured query file could not be read",
                )
            })?;
            String::from_utf8(bytes).map_err(|error| {
                let mut bytes = error.into_bytes();
                bytes.fill(0);
                preparation_error(
                    "DBX-RS-PREP-0002",
                    "query_input",
                    "configured query file is not valid UTF-8",
                )
            })
        }
    }
}

fn batch_input_id(name: &str) -> Result<BatchInputId, DaemonError> {
    let mut encoder = FingerprintEncoder::new(INPUT_ID_DOMAIN);
    encoder.bytes(1, name.as_bytes())?;
    Ok(BatchInputId(encoder.finish()))
}

fn rising_input_key(state_input_id: [u8; 16]) -> BatchInputId {
    let mut encoder = FingerprintEncoder::new(RISING_INPUT_KEY_DOMAIN);
    encoder.u16(1, PREPARED_FINGERPRINT_VERSION);
    encoder.fixed_bytes_16(2, &state_input_id);
    BatchInputId(encoder.finish())
}

fn query_fingerprint(
    connector: &str,
    query: &[u8],
) -> Result<ConfigurationFingerprint, DaemonError> {
    let mut encoder = FingerprintEncoder::new(QUERY_FINGERPRINT_DOMAIN);
    encoder.u16(1, PREPARED_FINGERPRINT_VERSION);
    encoder.bytes(2, connector.as_bytes())?;
    encoder.u16(3, CONNECTOR_CONTRACT_VERSION.major);
    encoder.u16(4, CONNECTOR_CONTRACT_VERSION.minor);
    encoder.bytes(5, query)?;
    Ok(ConfigurationFingerprint(encoder.finish()))
}

fn batch_lineage_fingerprint(
    input_id: BatchInputId,
    input: &InputConfig,
    query_fingerprint: ConfigurationFingerprint,
) -> Result<ConfigurationFingerprint, DaemonError> {
    let mut encoder = FingerprintEncoder::new(LINEAGE_FINGERPRINT_DOMAIN);
    encoder.u16(1, PREPARED_FINGERPRINT_VERSION);
    encoder.fixed_bytes(2, &input_id.into_bytes());
    encoder.bytes(3, input.host.as_bytes())?;
    encoder.u16(4, input.port);
    encoder.bytes(5, input.database.as_bytes())?;
    encoder.bytes(6, input.username.as_bytes())?;
    encoder.fixed_bytes(7, &query_fingerprint.into_bytes());
    Ok(ConfigurationFingerprint(encoder.finish()))
}

fn rising_lineage_fingerprint(
    state_input_id: [u8; 16],
    input: &InputConfig,
    query_fingerprint: ConfigurationFingerprint,
) -> Result<ConfigurationFingerprint, DaemonError> {
    let mut encoder = FingerprintEncoder::new(RISING_LINEAGE_FINGERPRINT_DOMAIN);
    encoder.u16(1, PREPARED_FINGERPRINT_VERSION);
    encoder.fixed_bytes_16(2, &state_input_id);
    encoder.bytes(3, input.connector.as_bytes())?;
    encoder.u16(4, CONNECTOR_CONTRACT_VERSION.major);
    encoder.u16(5, CONNECTOR_CONTRACT_VERSION.minor);
    encoder.bytes(6, input.host.as_bytes())?;
    encoder.u16(7, input.port);
    encoder.bytes(8, input.database.as_bytes())?;
    encoder.bytes(9, input.username.as_bytes())?;
    encoder.fixed_bytes(10, &query_fingerprint.into_bytes());
    Ok(ConfigurationFingerprint(encoder.finish()))
}

fn cursor_identity_fingerprint(
    cursor_spec: &TimestampIdCursorSpec,
) -> Result<ConfigurationFingerprint, DaemonError> {
    let mut encoder = FingerprintEncoder::new(RISING_CURSOR_FINGERPRINT_DOMAIN);
    encoder.u16(1, PREPARED_FINGERPRINT_VERSION);
    encoder.u16(2, CONNECTOR_CONTRACT_VERSION.major);
    encoder.u16(3, CONNECTOR_CONTRACT_VERSION.minor);
    encoder.u16(4, TIMESTAMP_ID_CURSOR_FORMAT_VERSION);
    encoder.bytes(5, cursor_spec.timestamp_field.as_bytes())?;
    encoder.bytes(6, cursor_spec.id_field.as_bytes())?;
    encoder.u8(7, cursor_null_policy_tag(cursor_spec.null_policy));
    Ok(ConfigurationFingerprint(encoder.finish()))
}

fn rising_revision_fingerprint(
    operational_revision: ConfigurationFingerprint,
    cursor_identity: ConfigurationFingerprint,
    overlap: Duration,
) -> ConfigurationFingerprint {
    let mut encoder = FingerprintEncoder::new(RISING_REVISION_FINGERPRINT_DOMAIN);
    encoder.u16(1, PREPARED_FINGERPRINT_VERSION);
    encoder.fixed_bytes(2, &operational_revision.into_bytes());
    encoder.u8(3, 1);
    encoder.fixed_bytes(4, &cursor_identity.into_bytes());
    encoder.duration(5, overlap);
    ConfigurationFingerprint(encoder.finish())
}

fn revision_fingerprint(
    lineage: ConfigurationFingerprint,
    input: &InputConfig,
    hec: &HecConfig,
    tls_mode: TlsMode,
    tls_ca_pem: Option<&[u8]>,
) -> Result<ConfigurationFingerprint, DaemonError> {
    let mut encoder = FingerprintEncoder::new(REVISION_FINGERPRINT_DOMAIN);
    encoder.u16(1, PREPARED_FINGERPRINT_VERSION);
    encoder.fixed_bytes(2, &lineage.into_bytes());
    encoder.bytes(3, input.secret_ref.as_bytes())?;
    encoder.u8(4, tls_mode_tag(tls_mode));
    encoder.optional_bytes(5, input.tls_server_name.as_deref().map(str::as_bytes))?;
    encoder.optional_digest(6, tls_ca_pem);
    encoder.duration(7, input.connect_timeout);
    encoder.duration(8, input.probe_timeout);
    encoder.duration(9, input.query_timeout);
    encoder.duration(10, input.interval);
    encoder.boolean(11, input.disabled);
    encoder.u64(12, input.max_rows);
    encoder.u64(13, input.max_bytes);
    encoder.bytes(14, input.index.as_bytes())?;
    encoder.bytes(15, input.sourcetype.as_bytes())?;
    encoder.bytes(16, input.source.as_bytes())?;
    encoder.u8(17, hec_state_tag(hec.state));
    encoder.bytes(18, hec.url.as_bytes())?;
    encoder.u8(19, hec_management_tag(hec.input_management));
    encoder.bytes(20, hec.input_name.as_bytes())?;
    encoder.u16(21, hec.listen_port);
    encoder.bytes(22, hec.accept_from.as_bytes())?;
    encoder.u8(23, tls_verification_tag(hec.tls_verification));
    encoder.duration(24, hec.timeout);
    encoder.usize(25, hec.batch_max_events)?;
    encoder.u64(26, hec.batch_max_bytes);
    encoder.u64(27, hec.max_event_bytes);
    encoder.u8(28, acknowledgment_tag(hec.acknowledgment));
    Ok(ConfigurationFingerprint(encoder.finish()))
}

const fn tls_mode_tag(mode: TlsMode) -> u8 {
    match mode {
        TlsMode::Disable => 0,
        TlsMode::Require => 1,
        TlsMode::VerifyCa => 2,
        TlsMode::VerifyFull => 3,
    }
}

const fn hec_state_tag(state: HecState) -> u8 {
    match state {
        HecState::Enabled => 1,
        HecState::Disabled => 0,
    }
}

const fn hec_management_tag(management: HecInputManagement) -> u8 {
    match management {
        HecInputManagement::Managed => 1,
        HecInputManagement::External => 0,
    }
}

const fn tls_verification_tag(verification: TlsVerification) -> u8 {
    match verification {
        TlsVerification::Full => 1,
        TlsVerification::Disabled => 0,
    }
}

const fn acknowledgment_tag(acknowledgment: IndexerAcknowledgment) -> u8 {
    match acknowledgment {
        IndexerAcknowledgment::Enabled => 1,
        IndexerAcknowledgment::Disabled => 0,
    }
}

const fn cursor_null_policy_tag(policy: CursorNullPolicy) -> u8 {
    match policy {
        CursorNullPolicy::Reject => 0,
    }
}

struct FingerprintEncoder {
    context: Context,
}

impl FingerprintEncoder {
    fn new(domain: &[u8]) -> Self {
        let mut context = Context::new(&SHA256);
        context.update(domain);
        Self { context }
    }

    fn boolean(&mut self, tag: u8, value: bool) {
        self.u8(tag, u8::from(value));
    }

    fn u8(&mut self, tag: u8, value: u8) {
        self.context.update(&[tag, value]);
    }

    fn u16(&mut self, tag: u8, value: u16) {
        self.context.update(&[tag]);
        self.context.update(&value.to_be_bytes());
    }

    fn u64(&mut self, tag: u8, value: u64) {
        self.context.update(&[tag]);
        self.context.update(&value.to_be_bytes());
    }

    fn usize(&mut self, tag: u8, value: usize) -> Result<(), DaemonError> {
        let value = u64::try_from(value).map_err(|_| fingerprint_size_error())?;
        self.u64(tag, value);
        Ok(())
    }

    fn duration(&mut self, tag: u8, value: Duration) {
        self.context.update(&[tag]);
        self.context.update(&value.as_secs().to_be_bytes());
        self.context.update(&value.subsec_nanos().to_be_bytes());
    }

    fn bytes(&mut self, tag: u8, value: &[u8]) -> Result<(), DaemonError> {
        let length = u32::try_from(value.len()).map_err(|_| fingerprint_size_error())?;
        self.context.update(&[tag]);
        self.context.update(&length.to_be_bytes());
        self.context.update(value);
        Ok(())
    }

    fn fixed_bytes(&mut self, tag: u8, value: &[u8; 32]) {
        self.context.update(&[tag]);
        self.context.update(value);
    }

    fn fixed_bytes_16(&mut self, tag: u8, value: &[u8; 16]) {
        self.context.update(&[tag]);
        self.context.update(value);
    }

    fn optional_bytes(&mut self, tag: u8, value: Option<&[u8]>) -> Result<(), DaemonError> {
        match value {
            Some(value) => {
                self.context.update(&[tag, 1]);
                let length = u32::try_from(value.len()).map_err(|_| fingerprint_size_error())?;
                self.context.update(&length.to_be_bytes());
                self.context.update(value);
            }
            None => self.context.update(&[tag, 0]),
        }
        Ok(())
    }

    fn optional_digest(&mut self, tag: u8, value: Option<&[u8]>) {
        match value {
            Some(value) => {
                self.context.update(&[tag, 1]);
                self.context
                    .update(ring::digest::digest(&SHA256, value).as_ref());
            }
            None => self.context.update(&[tag, 0]),
        }
    }

    fn finish(self) -> [u8; 32] {
        let mut output = [0_u8; 32];
        output.copy_from_slice(self.context.finish().as_ref());
        output
    }
}

const fn preparation_error(
    code: &'static str,
    stage: &'static str,
    message: &'static str,
) -> DaemonError {
    DaemonError::new(code, "configuration", stage, message, false, true)
}

const fn fingerprint_size_error() -> DaemonError {
    DaemonError::new(
        "DBX-RS-PREP-0005",
        "internal",
        "input_fingerprint",
        "prepared input field exceeds the canonical fingerprint limit",
        false,
        false,
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use dbx_rs_config::{HecInputManagement, load_effective_config};

    use super::*;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "dbx-rs-prepared-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("test directory must be created");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.0);
        }
    }

    fn input(query: QuerySource, ca_file: Option<PathBuf>) -> InputConfig {
        InputConfig {
            name: "orders".into(),
            disabled: false,
            mode: CollectionMode::Batch,
            connector: "postgres".into(),
            interval: Duration::from_mins(1),
            host: "private-db.example".into(),
            port: 5432,
            database: "private_database".into(),
            username: "private_user".into(),
            secret_ref: "local:private-secret".into(),
            tls_mode: "verify-full".into(),
            tls_server_name: Some("private-db.example".into()),
            tls_ca_file: ca_file,
            query,
            connect_timeout: Duration::from_secs(10),
            probe_timeout: Duration::from_secs(10),
            max_rows: 1_000,
            max_bytes: 1_000_000,
            query_timeout: Duration::from_secs(30),
            index: "private_index".into(),
            sourcetype: "private:sourcetype".into(),
            source: "private:source".into(),
        }
    }

    fn hec() -> HecConfig {
        HecConfig {
            state: HecState::Enabled,
            input_management: HecInputManagement::Managed,
            url: "https://private-hec.example/services/collector/event".into(),
            input_name: "dbx_rs".into(),
            listen_port: 8088,
            accept_from: "127.0.0.1".into(),
            tls_verification: TlsVerification::Full,
            timeout: Duration::from_secs(15),
            batch_max_events: 250,
            batch_max_bytes: 1_000_000,
            max_event_bytes: 900_000,
            index: "unused_default".into(),
            sourcetype: "unused:default".into(),
            source: "unused:default".into(),
            acknowledgment: IndexerAcknowledgment::Enabled,
        }
    }

    fn write(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("test asset must be written");
    }

    fn parsed_input(mode_settings: &str) -> (InputConfig, HecConfig) {
        let directory = TestDirectory::new();
        let app_home = directory.0.join("app");
        let splunk_home = directory.0.join("splunk");
        fs::create_dir_all(app_home.join("default"))
            .expect("default configuration directory must be created");
        fs::create_dir_all(app_home.join("local"))
            .expect("local configuration directory must be created");
        write(
            &app_home.join("default/dbxrs_generic.conf"),
            include_bytes!("../../../packaging/splunk/TA-dbx-rs/default/dbxrs_generic.conf"),
        );
        let configured = format!(
            r"[orders]
disabled = false
{mode_settings}
connector = postgres
interval_secs = 60
host = private-db.example
port = 5432
database = private_database
username = private_user
secret_ref = local:private-secret
tls_mode = disable
query = SELECT private_column FROM private_table
connect_timeout_secs = 10
probe_timeout_secs = 10
max_rows = 1000
max_bytes = 1000000
query_timeout_secs = 30
index = private_index
sourcetype = private:sourcetype
source = private:source
"
        );
        write(
            &app_home.join("default/dbxrs_inputs.conf"),
            configured.as_bytes(),
        );

        let mut effective =
            load_effective_config(&app_home, &splunk_home).expect("test configuration must load");
        (effective.inputs.remove(0), effective.generic.hec)
    }

    fn parsed_rising_input() -> (InputConfig, HecConfig) {
        parsed_input(
            "mode = rising\ninput_id = 123e4567-e89b-12d3-a456-426614174000\n\
             cursor_timestamp_field = private_updated_at\ncursor_id_field = private_row_id\n\
             cursor_overlap_secs = 10",
        )
    }

    #[test]
    fn identical_inline_and_file_queries_have_identical_fingerprints() {
        let directory = TestDirectory::new();
        let query_path = directory.0.join("query.sql");
        let sql = "SELECT id FROM private_table";
        write(&query_path, sql.as_bytes());

        let from_file = prepare_input(&input(QuerySource::File(query_path), None), &hec())
            .expect("file query must prepare");
        let inline = prepare_input(&input(QuerySource::Inline(sql.into()), None), &hec())
            .expect("inline query must prepare");

        assert_eq!(from_file.query_fingerprint, inline.query_fingerprint);
        assert_eq!(from_file.lineage_fingerprint, inline.lineage_fingerprint);
        assert_eq!(from_file.revision_fingerprint, inline.revision_fingerprint);
    }

    #[test]
    fn changing_query_bytes_at_the_same_path_changes_lineage() {
        let directory = TestDirectory::new();
        let query_path = directory.0.join("query.sql");
        write(&query_path, b"SELECT 1 AS value");
        let before = prepare_input(&input(QuerySource::File(query_path.clone()), None), &hec())
            .expect("first query must prepare");

        write(&query_path, b"SELECT 2 AS value");
        let after = prepare_input(&input(QuerySource::File(query_path), None), &hec())
            .expect("replacement query must prepare");

        assert_ne!(before.query_fingerprint, after.query_fingerprint);
        assert_ne!(before.lineage_fingerprint, after.lineage_fingerprint);
        assert_ne!(before.revision_fingerprint, after.revision_fingerprint);
        assert_eq!(before.query.as_str(), "SELECT 1 AS value");
        assert_eq!(after.query.as_str(), "SELECT 2 AS value");
    }

    #[test]
    fn ca_output_limits_and_secret_reference_only_change_revision() {
        let directory = TestDirectory::new();
        let first_ca = directory.0.join("first.pem");
        let second_ca = directory.0.join("second.pem");
        write(&first_ca, b"first CA bytes");
        write(&second_ca, b"second CA bytes");
        let base_input = input(QuerySource::Inline("SELECT 1".into()), Some(first_ca));
        let base = prepare_input(&base_input, &hec()).expect("base input must prepare");

        let mut changed_input = base_input;
        changed_input.tls_ca_file = Some(second_ca);
        changed_input.index = "another_private_index".into();
        changed_input.max_rows += 1;
        changed_input.secret_ref = "local:rotated-reference".into();
        let changed = prepare_input(&changed_input, &hec()).expect("changed input must prepare");

        assert_eq!(base.query_fingerprint, changed.query_fingerprint);
        assert_eq!(base.lineage_fingerprint, changed.lineage_fingerprint);
        assert_ne!(base.revision_fingerprint, changed.revision_fingerprint);
    }

    #[test]
    fn hec_delivery_change_only_changes_revision() {
        let configured = input(QuerySource::Inline("SELECT 1".into()), None);
        let base_hec = hec();
        let base = prepare_input(&configured, &base_hec).expect("base input must prepare");
        let mut changed_hec = base_hec;
        changed_hec.batch_max_events += 1;
        let changed = prepare_input(&configured, &changed_hec).expect("changed input must prepare");

        assert_eq!(base.query_fingerprint, changed.query_fingerprint);
        assert_eq!(base.lineage_fingerprint, changed.lineage_fingerprint);
        assert_ne!(base.revision_fingerprint, changed.revision_fingerprint);
    }

    #[test]
    fn rising_revision_binds_delivery_transport_and_event_limit() {
        let (configured, base_hec) = parsed_rising_input();
        let base = prepare_input(&configured, &base_hec).expect("base rising input must prepare");
        let mut changed_hec = base_hec.clone();
        changed_hec.url = "https://replacement-hec.example/services/collector/event".into();
        changed_hec.batch_max_events += 1;
        changed_hec.acknowledgment = IndexerAcknowledgment::Disabled;
        let transport_changed =
            prepare_input(&configured, &changed_hec).expect("transport change must prepare");

        assert_ne!(
            base.revision_fingerprint,
            transport_changed.revision_fingerprint
        );

        changed_hec.max_event_bytes += 1;
        let event_limit_changed =
            prepare_input(&configured, &changed_hec).expect("event-limit change must prepare");
        assert_ne!(
            base.revision_fingerprint,
            event_limit_changed.revision_fingerprint
        );
    }

    #[test]
    fn batch_identity_is_stable_and_name_scoped() {
        let first = prepare_input(&input(QuerySource::Inline("SELECT 1".into()), None), &hec())
            .expect("first input must prepare");
        let second = prepare_input(&input(QuerySource::Inline("SELECT 1".into()), None), &hec())
            .expect("same input must prepare");
        let mut renamed = input(QuerySource::Inline("SELECT 1".into()), None);
        renamed.name = "renamed-orders".into();
        let renamed = prepare_input(&renamed, &hec()).expect("renamed input must prepare");

        assert_eq!(first.input_id, second.input_id);
        assert_ne!(first.input_id, renamed.input_id);
    }

    #[test]
    fn implicit_and_explicit_batch_modes_prepare_identically() {
        let (implicit, implicit_hec) = parsed_input("");
        let (explicit, explicit_hec) = parsed_input("mode = batch");

        assert_eq!(implicit, explicit);
        assert_eq!(implicit_hec, explicit_hec);
        let implicit =
            prepare_input(&implicit, &implicit_hec).expect("implicit batch input must prepare");
        let explicit =
            prepare_input(&explicit, &explicit_hec).expect("explicit batch input must prepare");

        assert_eq!(implicit, explicit);
        assert!(implicit.rising.is_none());
    }

    #[test]
    fn oracle_batch_prepares_without_cursor_state() {
        let mut configured = input(QuerySource::Inline("SELECT 1 FROM DUAL".into()), None);
        configured.connector = "oracle".into();
        configured.port = 1521;
        configured.database = "ORCLPDB1".into();

        let prepared = prepare_input(&configured, &hec()).expect("Oracle batch must prepare");

        assert_eq!(prepared.connector, "oracle");
        assert_eq!(prepared.connection.connector_id, "oracle");
        assert!(prepared.rising.is_none());
    }

    #[test]
    fn oracle_rising_fails_closed_during_daemon_preparation() {
        let (mut configured, hec) = parsed_rising_input();
        configured.connector = "oracle".into();

        let error = prepare_input(&configured, &hec)
            .expect_err("Oracle rising must not create prepared cursor state");

        assert_eq!(error.code(), "DBX-RS-PREP-0007");
        assert_eq!(error.stage(), "cursor_configuration");
        assert!(error.configuration_error());
    }

    #[test]
    fn batch_v1_identity_and_fingerprints_have_stable_vectors() {
        let prepared = prepare_input(&input(QuerySource::Inline("SELECT 1".into()), None), &hec())
            .expect("batch input must prepare");

        assert_eq!(
            (
                prepared.input_id.into_bytes(),
                prepared.query_fingerprint.into_bytes(),
                prepared.lineage_fingerprint.into_bytes(),
                prepared.revision_fingerprint.into_bytes(),
            ),
            (
                [
                    0x8d, 0x31, 0xd4, 0x90, 0x73, 0x23, 0xa0, 0x0d, 0xc5, 0x04, 0x01, 0x2b, 0xc7,
                    0x93, 0x54, 0x38, 0xe7, 0x6d, 0xa6, 0xd7, 0x51, 0x00, 0x91, 0x5e, 0x75, 0x89,
                    0x25, 0xcd, 0xa1, 0xd9, 0x25, 0xfd,
                ],
                [
                    0x6a, 0x19, 0x39, 0x89, 0x72, 0x45, 0xf9, 0x9b, 0xae, 0x4f, 0x59, 0x80, 0xae,
                    0xc6, 0x30, 0x42, 0x9f, 0x32, 0x71, 0xbd, 0xb1, 0xf6, 0x76, 0x2d, 0x46, 0x05,
                    0x95, 0xd6, 0x6e, 0x25, 0x91, 0x59,
                ],
                [
                    0x5d, 0x79, 0x73, 0x26, 0xb7, 0xbb, 0x9a, 0x44, 0x50, 0xb2, 0x73, 0x5e, 0x8a,
                    0xc2, 0x79, 0x3f, 0xbe, 0x58, 0x27, 0x9b, 0xef, 0xd1, 0xdd, 0x9e, 0xe3, 0xdb,
                    0x32, 0x0a, 0xeb, 0xfa, 0x77, 0x2f,
                ],
                [
                    0xaa, 0x84, 0xd1, 0xde, 0x6b, 0x84, 0x77, 0xec, 0x68, 0xd8, 0xbe, 0xf2, 0x95,
                    0x01, 0x71, 0xa2, 0x9c, 0x3a, 0x7d, 0xfc, 0xfd, 0xa5, 0xbf, 0x2e, 0xc7, 0xaf,
                    0xd0, 0x25, 0x5f, 0x38, 0x28, 0x11,
                ],
            )
        );
    }

    #[test]
    fn rising_identity_and_fingerprints_are_stable_across_stanza_rename() {
        let (configured, hec) = parsed_rising_input();
        let first = prepare_input(&configured, &hec).expect("rising input must prepare");
        let mut renamed = configured;
        renamed.name = "private-renamed-orders".into();
        let renamed = prepare_input(&renamed, &hec).expect("renamed rising input must prepare");

        assert_eq!(first.input_id, renamed.input_id);
        assert_eq!(first.rising, renamed.rising);
        assert_eq!(first.query_fingerprint, renamed.query_fingerprint);
        assert_eq!(first.lineage_fingerprint, renamed.lineage_fingerprint);
        assert_eq!(first.revision_fingerprint, renamed.revision_fingerprint);
    }

    #[test]
    fn rising_overlap_only_changes_revision_identity() {
        let (configured, hec) = parsed_rising_input();
        let base = prepare_input(&configured, &hec).expect("rising input must prepare");
        let mut changed = configured;
        let CollectionMode::Rising(rising) = &mut changed.mode else {
            panic!("test input must be rising");
        };
        rising.overlap += Duration::from_secs(1);
        let changed = prepare_input(&changed, &hec).expect("changed rising input must prepare");

        assert_eq!(base.input_id, changed.input_id);
        assert_eq!(base.lineage_fingerprint, changed.lineage_fingerprint);
        assert_eq!(
            base.rising
                .as_ref()
                .expect("base must be rising")
                .cursor_identity_fingerprint,
            changed
                .rising
                .as_ref()
                .expect("changed input must be rising")
                .cursor_identity_fingerprint
        );
        assert_ne!(base.revision_fingerprint, changed.revision_fingerprint);
    }

    #[test]
    fn rising_source_and_query_changes_change_lineage() {
        let (configured, hec) = parsed_rising_input();
        let base = prepare_input(&configured, &hec).expect("rising input must prepare");

        let mut changed_source = configured.clone();
        changed_source.host = "different-private-db.example".into();
        let changed_source =
            prepare_input(&changed_source, &hec).expect("source change must prepare");

        let mut changed_query = configured;
        changed_query.query = QuerySource::Inline("SELECT private_other FROM private_table".into());
        let changed_query = prepare_input(&changed_query, &hec).expect("query change must prepare");

        assert_ne!(base.lineage_fingerprint, changed_source.lineage_fingerprint);
        assert_ne!(base.lineage_fingerprint, changed_query.lineage_fingerprint);
        assert_ne!(base.query_fingerprint, changed_query.query_fingerprint);
    }

    #[test]
    fn rising_cursor_alias_change_only_changes_cursor_and_revision_identity() {
        let (configured, hec) = parsed_rising_input();
        let base = prepare_input(&configured, &hec).expect("rising input must prepare");
        let mut changed = configured;
        let CollectionMode::Rising(rising) = &mut changed.mode else {
            panic!("test input must be rising");
        };
        rising.timestamp_field = "private_changed_at".into();
        let changed = prepare_input(&changed, &hec).expect("cursor change must prepare");

        assert_eq!(base.input_id, changed.input_id);
        assert_eq!(base.lineage_fingerprint, changed.lineage_fingerprint);
        assert_ne!(
            base.rising
                .as_ref()
                .expect("base must be rising")
                .cursor_identity_fingerprint,
            changed
                .rising
                .as_ref()
                .expect("changed input must be rising")
                .cursor_identity_fingerprint
        );
        assert_ne!(base.revision_fingerprint, changed.revision_fingerprint);
    }

    #[test]
    fn rising_debug_redacts_state_identity_and_cursor_aliases() {
        let (configured, hec) = parsed_rising_input();
        let prepared = prepare_input(&configured, &hec).expect("rising input must prepare");
        let rising = prepared.rising.as_ref().expect("input must be rising");
        let debug = format!("{prepared:?}");

        assert!(!debug.contains("private_updated_at"));
        assert!(!debug.contains("private_row_id"));
        assert!(!debug.contains("123e4567"));
        assert!(!debug.contains(&format!("{:?}", rising.state_input_id)));
        assert!(!debug.contains(&format!("{:?}", prepared.input_id.into_bytes())));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn debug_redacts_resolved_and_fingerprint_material() {
        let sql = "SELECT private_column FROM private_table";
        let prepared = prepare_input(&input(QuerySource::Inline(sql.into()), None), &hec())
            .expect("input must prepare");
        let debug = format!("{prepared:?}");

        for private in [
            sql,
            "private-db.example",
            "private_database",
            "private_user",
            "local:private-secret",
            "private_index",
            "private:sourcetype",
            "private:source",
        ] {
            assert!(!debug.contains(private), "debug leaked a private field");
        }
        assert!(!debug.contains(&format!("{:?}", prepared.query_fingerprint.into_bytes())));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn invalid_utf8_query_has_stable_redacted_error() {
        let directory = TestDirectory::new();
        let query_path = directory.0.join("query.sql");
        write(&query_path, &[0xff]);

        let error = prepare_input(&input(QuerySource::File(query_path), None), &hec())
            .expect_err("invalid UTF-8 must fail");

        assert_eq!(error.code(), "DBX-RS-PREP-0002");
        assert_eq!(error.stage(), "query_input");
        assert!(error.configuration_error());
    }
}
