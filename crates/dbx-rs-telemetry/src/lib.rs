#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

pub const SCHEMA_VERSION: u16 = 2;
pub const HARD_MAX_FILE_BYTES: u64 = 10_000_000;
pub const DEFAULT_MAX_FILE_BYTES: u64 = HARD_MAX_FILE_BYTES;
pub const DEFAULT_BACKUP_COUNT: u8 = 2;

const MIN_FILE_BYTES: u64 = 4_096;
const MAX_BACKUP_COUNT: u8 = 20;
const MAX_DIMENSION_BYTES: usize = 128;

#[derive(Clone)]
pub struct TelemetryConfig {
    path: PathBuf,
    max_file_bytes: u64,
    backup_count: u8,
}

impl TelemetryConfig {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            backup_count: DEFAULT_BACKUP_COUNT,
        }
    }

    #[must_use]
    pub const fn with_rotation(mut self, max_file_bytes: u64, backup_count: u8) -> Self {
        self.max_file_bytes = max_file_bytes;
        self.backup_count = backup_count;
        self
    }
}

#[derive(Clone)]
pub struct OperationContext {
    component: String,
    connector: String,
    operation: String,
    request_id: String,
    version: String,
    tls_mode: String,
    input: Option<String>,
}

impl OperationContext {
    /// Creates safe, bounded dimensions for one connector operation.
    ///
    /// # Errors
    ///
    /// Returns an error when a dimension is empty, too long, or contains characters outside the
    /// operational label character set.
    pub fn new(
        component: impl Into<String>,
        connector: impl Into<String>,
        operation: impl Into<String>,
        request_id: impl Into<String>,
        version: impl Into<String>,
        tls_mode: impl Into<String>,
    ) -> Result<Self, TelemetryError> {
        let context = Self {
            component: component.into(),
            connector: connector.into(),
            operation: operation.into(),
            request_id: request_id.into(),
            version: version.into(),
            tls_mode: tls_mode.into(),
            input: None,
        };
        for value in [
            &context.component,
            &context.connector,
            &context.operation,
            &context.request_id,
            &context.version,
            &context.tls_mode,
        ] {
            validate_dimension(value)?;
        }
        Ok(context)
    }

    /// Adds a safe Splunk input stanza name to this operation.
    ///
    /// # Errors
    ///
    /// Returns an error when the input name is empty, too long, or contains characters outside
    /// the operational label character set.
    pub fn with_input(mut self, input: impl Into<String>) -> Result<Self, TelemetryError> {
        let input = input.into();
        validate_dimension(&input)?;
        self.input = Some(input);
        Ok(self)
    }
}

#[derive(Clone, Copy, Default)]
pub struct OperationLimits {
    max_rows: Option<u64>,
    max_bytes: Option<u64>,
    connect_timeout_ms: Option<u64>,
    operation_timeout_ms: Option<u64>,
}

impl OperationLimits {
    #[must_use]
    pub const fn with_max_rows(mut self, max_rows: u64) -> Self {
        self.max_rows = Some(max_rows);
        self
    }

    #[must_use]
    pub const fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = Some(max_bytes);
        self
    }

    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout_ms = Some(duration_millis(timeout));
        self
    }

    #[must_use]
    pub fn with_operation_timeout(mut self, timeout: Duration) -> Self {
        self.operation_timeout_ms = Some(duration_millis(timeout));
        self
    }
}

#[derive(Clone, Copy, Default)]
pub struct OperationMetrics {
    rows: Option<u64>,
    bytes: Option<u64>,
    output_published: Option<bool>,
    server_version_number: Option<u32>,
}

impl OperationMetrics {
    #[must_use]
    pub const fn collection(rows: u64, bytes: u64, output_published: bool) -> Self {
        Self {
            rows: Some(rows),
            bytes: Some(bytes),
            output_published: Some(output_published),
            server_version_number: None,
        }
    }

    #[must_use]
    pub const fn probe(server_version_number: Option<u32>) -> Self {
        Self {
            rows: None,
            bytes: None,
            output_published: None,
            server_version_number,
        }
    }
}

pub struct OperationFailure {
    code: String,
    class: String,
    stage: String,
    retryable: bool,
    configuration_error: bool,
    sql_state: Option<String>,
}

impl OperationFailure {
    /// Creates a redacted failure record from stable classifications only.
    ///
    /// # Errors
    ///
    /// Returns an error when a classification is empty, too long, or contains characters outside
    /// the operational label character set.
    pub fn new(
        code: impl Into<String>,
        class: impl Into<String>,
        stage: impl Into<String>,
        retryable: bool,
        configuration_error: bool,
        sql_state: Option<impl Into<String>>,
    ) -> Result<Self, TelemetryError> {
        let failure = Self {
            code: code.into(),
            class: class.into(),
            stage: stage.into(),
            retryable,
            configuration_error,
            sql_state: sql_state.map(Into::into),
        };
        validate_dimension(&failure.code)?;
        validate_dimension(&failure.class)?;
        validate_dimension(&failure.stage)?;
        if let Some(sql_state) = &failure.sql_state {
            validate_dimension(sql_state)?;
        }
        Ok(failure)
    }
}

#[derive(Clone)]
pub struct NdjsonTelemetry {
    config: TelemetryConfig,
}

impl NdjsonTelemetry {
    /// Creates an NDJSON telemetry writer with bounded rotation.
    ///
    /// # Errors
    ///
    /// Returns an error when the path or rotation limits are invalid. The parent directory must
    /// already exist and is checked when the first event is written.
    pub fn new(config: TelemetryConfig) -> Result<Self, TelemetryError> {
        if config.path.file_name().is_none() {
            return Err(TelemetryError::configuration(
                "telemetry path has no file name",
            ));
        }
        if config.max_file_bytes < MIN_FILE_BYTES {
            return Err(TelemetryError::configuration(
                "telemetry rotation size is below the minimum",
            ));
        }
        if config.max_file_bytes > HARD_MAX_FILE_BYTES {
            return Err(TelemetryError::configuration(
                "telemetry rotation size exceeds the hard maximum",
            ));
        }
        if config.backup_count > MAX_BACKUP_COUNT {
            return Err(TelemetryError::configuration(
                "telemetry backup count exceeds the maximum",
            ));
        }
        Ok(Self { config })
    }

    /// Writes an `operation_started` record.
    ///
    /// # Errors
    ///
    /// Returns an error when time, serialization, locking, rotation, or file output fails.
    pub fn operation_started(
        &self,
        context: &OperationContext,
        limits: OperationLimits,
    ) -> Result<(), TelemetryError> {
        self.write_event(Record::started(context, limits))
    }

    /// Writes an `operation_succeeded` record with counters and duration.
    ///
    /// # Errors
    ///
    /// Returns an error when time, serialization, locking, rotation, or file output fails.
    pub fn operation_succeeded(
        &self,
        context: &OperationContext,
        duration: Duration,
        metrics: OperationMetrics,
    ) -> Result<(), TelemetryError> {
        self.write_event(Record::succeeded(context, duration, metrics))
    }

    /// Writes an `operation_failed` record without a vendor message or user data.
    ///
    /// # Errors
    ///
    /// Returns an error when time, serialization, locking, rotation, or file output fails.
    pub fn operation_failed(
        &self,
        context: &OperationContext,
        duration: Duration,
        failure: &OperationFailure,
    ) -> Result<(), TelemetryError> {
        self.write_event(Record::failed(context, duration, failure))
    }

    fn write_event(&self, mut event: Record<'_>) -> Result<(), TelemetryError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TelemetryError::clock())?;
        event.timestamp_epoch = timestamp.as_secs_f64();
        event.timestamp_epoch_ms = duration_millis(timestamp);

        let mut line = serde_json::to_vec(&event).map_err(|_| TelemetryError::serialization())?;
        line.push(b'\n');
        if line.len() as u64 > self.config.max_file_bytes {
            return Err(TelemetryError::configuration(
                "telemetry record exceeds the rotation size",
            ));
        }

        let lock_path = lock_path(&self.config.path)?;
        let lock_file = open_lock_file(&lock_path)?;
        lock_file
            .lock()
            .map_err(|error| TelemetryError::io("lock", error.kind()))?;
        rotate_if_needed(&self.config, line.len() as u64)?;
        let mut output = open_append_file(&self.config.path)?;
        output
            .write_all(&line)
            .map_err(|error| TelemetryError::io("write", error.kind()))?;
        output
            .sync_data()
            .map_err(|error| TelemetryError::io("synchronize", error.kind()))?;
        Ok(())
    }
}

#[derive(Serialize)]
struct Record<'a> {
    timestamp_epoch: f64,
    timestamp_epoch_ms: u64,
    schema_version: u16,
    level: &'static str,
    event: &'static str,
    status: &'static str,
    component: &'a str,
    connector: &'a str,
    operation: &'a str,
    request_id: &'a str,
    version: &'a str,
    tls_mode: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    input: Option<&'a str>,
    pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_rows: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    connect_timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation_timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rows: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rows_per_second: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_per_second: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_published: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    server_version_number: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_class: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_stage: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retryable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    configuration_error: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sql_state: Option<&'a str>,
}

impl<'a> Record<'a> {
    fn base(
        context: &'a OperationContext,
        level: &'static str,
        event: &'static str,
        status: &'static str,
    ) -> Self {
        Self {
            timestamp_epoch: 0.0,
            timestamp_epoch_ms: 0,
            schema_version: SCHEMA_VERSION,
            level,
            event,
            status,
            component: &context.component,
            connector: &context.connector,
            operation: &context.operation,
            request_id: &context.request_id,
            version: &context.version,
            tls_mode: &context.tls_mode,
            input: context.input.as_deref(),
            pid: std::process::id(),
            duration_ms: None,
            max_rows: None,
            max_bytes: None,
            connect_timeout_ms: None,
            operation_timeout_ms: None,
            rows: None,
            bytes: None,
            rows_per_second: None,
            bytes_per_second: None,
            output_published: None,
            server_version_number: None,
            error_code: None,
            error_class: None,
            error_stage: None,
            retryable: None,
            configuration_error: None,
            sql_state: None,
        }
    }

    fn started(context: &'a OperationContext, limits: OperationLimits) -> Self {
        let mut event = Self::base(context, "info", "operation_started", "started");
        event.max_rows = limits.max_rows;
        event.max_bytes = limits.max_bytes;
        event.connect_timeout_ms = limits.connect_timeout_ms;
        event.operation_timeout_ms = limits.operation_timeout_ms;
        event
    }

    fn succeeded(
        context: &'a OperationContext,
        duration: Duration,
        metrics: OperationMetrics,
    ) -> Self {
        let mut event = Self::base(context, "info", "operation_succeeded", "succeeded");
        event.duration_ms = Some(duration_millis(duration));
        event.rows = metrics.rows;
        event.bytes = metrics.bytes;
        event.output_published = metrics.output_published;
        event.server_version_number = metrics.server_version_number;
        event.rows_per_second = metrics
            .rows
            .and_then(|rows| rate_per_second(rows, duration));
        event.bytes_per_second = metrics
            .bytes
            .and_then(|bytes| rate_per_second(bytes, duration));
        event
    }

    fn failed(
        context: &'a OperationContext,
        duration: Duration,
        failure: &'a OperationFailure,
    ) -> Self {
        let mut event = Self::base(context, "error", "operation_failed", "failed");
        event.duration_ms = Some(duration_millis(duration));
        event.error_code = Some(&failure.code);
        event.error_class = Some(&failure.class);
        event.error_stage = Some(&failure.stage);
        event.retryable = Some(failure.retryable);
        event.configuration_error = Some(failure.configuration_error);
        event.sql_state = failure.sql_state.as_deref();
        event
    }
}

#[derive(Debug)]
pub struct TelemetryError {
    category: &'static str,
    operation: &'static str,
    io_kind: Option<io::ErrorKind>,
}

impl TelemetryError {
    const fn configuration(operation: &'static str) -> Self {
        Self {
            category: "configuration",
            operation,
            io_kind: None,
        }
    }

    const fn clock() -> Self {
        Self {
            category: "clock",
            operation: "read epoch timestamp",
            io_kind: None,
        }
    }

    const fn serialization() -> Self {
        Self {
            category: "serialization",
            operation: "encode NDJSON record",
            io_kind: None,
        }
    }

    const fn io(operation: &'static str, io_kind: io::ErrorKind) -> Self {
        Self {
            category: "io",
            operation,
            io_kind: Some(io_kind),
        }
    }
}

impl std::fmt::Display for TelemetryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "operational telemetry {} failed: {}",
            self.category, self.operation
        )?;
        if let Some(kind) = self.io_kind {
            write!(formatter, " ({kind:?})")?;
        }
        Ok(())
    }
}

impl std::error::Error for TelemetryError {}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn rate_per_second(value: u64, duration: Duration) -> Option<u64> {
    let nanoseconds = duration.as_nanos();
    if nanoseconds == 0 {
        return None;
    }
    let rate = u128::from(value).saturating_mul(1_000_000_000) / nanoseconds;
    Some(u64::try_from(rate).unwrap_or(u64::MAX))
}

fn validate_dimension(value: &str) -> Result<(), TelemetryError> {
    if value.is_empty()
        || value.len() > MAX_DIMENSION_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'+')
        })
    {
        return Err(TelemetryError::configuration(
            "telemetry dimension is invalid",
        ));
    }
    Ok(())
}

fn lock_path(path: &Path) -> Result<PathBuf, TelemetryError> {
    let parent = path
        .parent()
        .ok_or_else(|| TelemetryError::configuration("telemetry path has no parent directory"))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| TelemetryError::configuration("telemetry path has no file name"))?;
    let mut lock_name = OsString::from(".");
    lock_name.push(file_name);
    lock_name.push(".lock");
    Ok(parent.join(lock_name))
}

fn rotated_path(path: &Path, index: u8) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(format!(".{index}"));
    PathBuf::from(value)
}

fn open_lock_file(path: &Path) -> Result<File, TelemetryError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    set_private_mode(&mut options);
    options
        .open(path)
        .map_err(|error| TelemetryError::io("open lock file", error.kind()))
}

fn open_append_file(path: &Path) -> Result<File, TelemetryError> {
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    set_private_mode(&mut options);
    options
        .open(path)
        .map_err(|error| TelemetryError::io("open output file", error.kind()))
}

#[cfg(unix)]
fn set_private_mode(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_private_mode(_options: &mut OpenOptions) {}

fn rotate_if_needed(config: &TelemetryConfig, incoming_bytes: u64) -> Result<(), TelemetryError> {
    let current_bytes = match std::fs::metadata(&config.path) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
        Err(error) => return Err(TelemetryError::io("inspect output file", error.kind())),
    };
    if current_bytes == 0 || current_bytes.saturating_add(incoming_bytes) <= config.max_file_bytes {
        return Ok(());
    }

    if config.backup_count == 0 {
        remove_if_exists(&config.path)?;
        return Ok(());
    }

    for index in (1..=config.backup_count).rev() {
        let source = if index == 1 {
            config.path.clone()
        } else {
            rotated_path(&config.path, index - 1)
        };
        let target = rotated_path(&config.path, index);
        remove_if_exists(&target)?;
        rename_if_exists(&source, &target)?;
    }
    Ok(())
}

fn remove_if_exists(path: &Path) -> Result<(), TelemetryError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(TelemetryError::io("remove rotated file", error.kind())),
    }
}

fn rename_if_exists(source: &Path, target: &Path) -> Result<(), TelemetryError> {
    match std::fs::rename(source, target) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(TelemetryError::io("rotate output file", error.kind())),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    use serde_json::Value;

    use super::*;

    static NEXT_TEST_FILE: AtomicU64 = AtomicU64::new(0);

    fn test_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "dbx-rs-telemetry-{label}-{}-{}.log",
            std::process::id(),
            NEXT_TEST_FILE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn context(request_id: &str) -> OperationContext {
        OperationContext::new(
            "postgres_connector_cli",
            "postgres",
            "collect",
            request_id,
            "0.1.0",
            "verify-full",
        )
        .expect("test context must be valid")
    }

    fn cleanup(path: &Path, backups: u8) {
        let _result = std::fs::remove_file(path);
        let _result = std::fs::remove_file(lock_path(path).expect("test path must have a lock"));
        for index in 1..=backups {
            let _result = std::fs::remove_file(rotated_path(path, index));
        }
    }

    #[test]
    fn lifecycle_records_are_valid_ndjson_with_epoch_metrics() {
        let path = test_path("lifecycle");
        let telemetry = NdjsonTelemetry::new(TelemetryConfig::new(&path))
            .expect("telemetry config must be valid");
        let context = context("request-1");
        telemetry
            .operation_started(
                &context,
                OperationLimits::default()
                    .with_max_rows(10)
                    .with_max_bytes(1_024)
                    .with_connect_timeout(Duration::from_secs(5))
                    .with_operation_timeout(Duration::from_secs(30)),
            )
            .expect("start event must be written");
        telemetry
            .operation_succeeded(
                &context,
                Duration::from_millis(250),
                OperationMetrics::collection(10, 500, true),
            )
            .expect("success event must be written");

        let lines = std::fs::read_to_string(&path).expect("telemetry file must be readable");
        let events = lines
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("line must be valid JSON"))
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["schema_version"], SCHEMA_VERSION);
        assert!(events[0]["timestamp_epoch"].is_number());
        assert!(events[0]["timestamp_epoch_ms"].is_number());
        assert_eq!(events[0]["event"], "operation_started");
        assert_eq!(events[1]["event"], "operation_succeeded");
        assert_eq!(events[1]["rows"], 10);
        assert_eq!(events[1]["bytes"], 500);
        assert_eq!(events[1]["output_published"], true);
        for forbidden in [
            "query",
            "password",
            "host",
            "database",
            "username",
            "output_path",
        ] {
            assert!(events.iter().all(|event| event.get(forbidden).is_none()));
        }
        cleanup(&path, DEFAULT_BACKUP_COUNT);
    }

    #[test]
    fn input_dimension_is_safe_and_optional() {
        let path = test_path("input-dimension");
        let telemetry = NdjsonTelemetry::new(TelemetryConfig::new(&path))
            .expect("telemetry config must be valid");
        let input_context = context("request-input")
            .with_input("warehouse_ro")
            .expect("input name must be accepted");
        telemetry
            .operation_started(&input_context, OperationLimits::default())
            .expect("event must be written");

        let event: Value = serde_json::from_str(
            std::fs::read_to_string(&path)
                .expect("telemetry file must be readable")
                .trim(),
        )
        .expect("record must be valid JSON");
        assert_eq!(event["input"], "warehouse_ro");
        assert!(
            context("request-invalid")
                .with_input("unsafe/input")
                .is_err()
        );
        cleanup(&path, DEFAULT_BACKUP_COUNT);
    }

    #[test]
    fn failure_record_contains_only_stable_classification() {
        let path = test_path("failure");
        let telemetry = NdjsonTelemetry::new(TelemetryConfig::new(&path))
            .expect("telemetry config must be valid");
        let context = context("request-2");
        let failure = OperationFailure::new(
            "DBX-RS-PG-AUTH-0003",
            "authentication",
            "probe",
            false,
            false,
            Some("28P01"),
        )
        .expect("failure classification must be valid");
        telemetry
            .operation_failed(&context, Duration::from_millis(20), &failure)
            .expect("failure event must be written");

        let event: Value = serde_json::from_str(
            std::fs::read_to_string(&path)
                .expect("telemetry file must be readable")
                .trim(),
        )
        .expect("record must be valid JSON");
        assert_eq!(event["level"], "error");
        assert_eq!(event["error_code"], "DBX-RS-PG-AUTH-0003");
        assert_eq!(event["error_class"], "authentication");
        assert_eq!(event["sql_state"], "28P01");
        assert!(event.get("message").is_none());
        cleanup(&path, DEFAULT_BACKUP_COUNT);
    }

    #[test]
    fn bounded_rotation_retains_configured_backups() {
        let path = test_path("rotation");
        let backup_count = 2;
        let telemetry = NdjsonTelemetry::new(
            TelemetryConfig::new(&path).with_rotation(MIN_FILE_BYTES, backup_count),
        )
        .expect("telemetry config must be valid");
        for index in 0..80 {
            telemetry
                .operation_started(
                    &context(&format!("request-{index}")),
                    OperationLimits::default(),
                )
                .expect("event must be written");
        }

        assert!(path.exists());
        assert!(rotated_path(&path, 1).exists());
        assert!(rotated_path(&path, 2).exists());
        assert!(!rotated_path(&path, 3).exists());
        for candidate in [&path, &rotated_path(&path, 1), &rotated_path(&path, 2)] {
            let contents = std::fs::read_to_string(candidate).expect("log must be readable");
            assert!(
                contents
                    .lines()
                    .all(|line| serde_json::from_str::<Value>(line).is_ok())
            );
        }
        cleanup(&path, backup_count);
    }

    #[test]
    fn concurrent_writers_preserve_one_json_object_per_line() {
        let path = test_path("concurrent");
        let telemetry = Arc::new(
            NdjsonTelemetry::new(
                TelemetryConfig::new(&path).with_rotation(1_000_000, DEFAULT_BACKUP_COUNT),
            )
            .expect("telemetry config must be valid"),
        );
        let writers = (0..4)
            .map(|writer| {
                let telemetry = Arc::clone(&telemetry);
                thread::spawn(move || {
                    for event in 0..25 {
                        telemetry
                            .operation_started(
                                &context(&format!("writer-{writer}-event-{event}")),
                                OperationLimits::default(),
                            )
                            .expect("concurrent write must succeed");
                    }
                })
            })
            .collect::<Vec<_>>();
        for writer in writers {
            writer.join().expect("writer thread must join");
        }

        let contents = std::fs::read_to_string(&path).expect("telemetry file must be readable");
        assert_eq!(contents.lines().count(), 100);
        assert!(
            contents
                .lines()
                .all(|line| serde_json::from_str::<Value>(line).is_ok())
        );
        cleanup(&path, DEFAULT_BACKUP_COUNT);
    }

    #[test]
    fn rotation_size_cannot_exceed_hard_limit() {
        let path = test_path("hard-limit");
        let result = NdjsonTelemetry::new(
            TelemetryConfig::new(&path).with_rotation(HARD_MAX_FILE_BYTES + 1, 1),
        );

        assert!(result.is_err());
        cleanup(&path, 1);
    }
}
