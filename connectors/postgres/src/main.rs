#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dbx_rs_connector_postgres::PostgresConnector;
use dbx_rs_connector_sdk::{
    ConnectionConfig, ConnectorError, ErrorClass, ProbeReport, ResolvedSecret, TlsMode,
};
use dbx_rs_telemetry::{
    DEFAULT_BACKUP_COUNT, DEFAULT_MAX_FILE_BYTES, NdjsonTelemetry, OperationContext,
    OperationFailure, OperationLimits, OperationMetrics, TelemetryConfig,
};
use tokio_util::sync::CancellationToken;

const HELP: &str = "dbx-rs-connector-postgres - native PostgreSQL diagnostics\n\
\n\
Usage:\n\
  dbx-rs-connector-postgres probe --host HOST --database DATABASE --username USER \\\n      --password-stdin [--port PORT] [--tls-mode MODE]\n\
\n\
Commands:\n\
  probe                         Validate connectivity and identify PostgreSQL\n\
\n\
Connection options:\n\
  --host HOST                   PostgreSQL hostname or address\n\
  --port PORT                   PostgreSQL port (default: 5432)\n\
  --database DATABASE           PostgreSQL database\n\
  --username USER               PostgreSQL user\n\
  --password-stdin              Read the password from standard input\n\
  --tls-mode MODE               disable, require, verify-ca, or verify-full\n\
                                (default: verify-full)\n\
  --tls-server-name NAME        Override the verified TLS server name\n\
  --tls-ca-file PATH            Add PEM CA certificates to bundled public roots\n\
  --connect-timeout-secs N      DNS and TCP timeout (default: 10)\n\
  --probe-timeout-secs N        Authentication and probe timeout (default: 10)\n\
  --splunk-home PATH            Splunk installation root (normally inferred)\n\
  --trace-log PATH              Operational NDJSON log (default: Splunk dbx-trace.log)\n\
  --trace-max-bytes N           Rotate trace file at N bytes (default/max: 10000000)\n\
  --trace-backups N             Rotated trace files to retain (default: 2)\n\
\n\
  -h, --help                    Print this help text\n";

const MAX_FILE_BYTES: u64 = 1024 * 1024;
const TELEMETRY_COMPONENT: &str = "postgres_connector_cli";

struct ConnectionOptions {
    host: String,
    port: u16,
    database: String,
    username: String,
    tls_mode: TlsMode,
    tls_server_name: Option<String>,
    tls_ca_pem: Option<Vec<u8>>,
    connect_timeout: Duration,
    probe_timeout: Duration,
}

struct ProbeOptions {
    connection: ConnectionOptions,
    telemetry: TelemetryOptions,
}

struct TelemetryOptions {
    path: PathBuf,
    max_file_bytes: u64,
    backup_count: u8,
}

enum Command {
    Help,
    Probe(ProbeOptions),
}

struct RawOptions {
    host: Option<String>,
    port: u16,
    database: Option<String>,
    username: Option<String>,
    tls_mode: TlsMode,
    tls_server_name: Option<String>,
    tls_ca_file: Option<PathBuf>,
    connect_timeout: Duration,
    probe_timeout: Duration,
    password_stdin: bool,
    splunk_home: Option<PathBuf>,
    trace_log: Option<PathBuf>,
    trace_max_bytes: u64,
    trace_backups: u8,
}

impl Default for RawOptions {
    fn default() -> Self {
        Self {
            host: None,
            port: 5432,
            database: None,
            username: None,
            tls_mode: TlsMode::VerifyFull,
            tls_server_name: None,
            tls_ca_file: None,
            connect_timeout: Duration::from_secs(10),
            probe_timeout: Duration::from_secs(10),
            password_stdin: false,
            splunk_home: None,
            trace_log: None,
            trace_max_bytes: DEFAULT_MAX_FILE_BYTES,
            trace_backups: DEFAULT_BACKUP_COUNT,
        }
    }
}

struct OperationTracker {
    telemetry: NdjsonTelemetry,
    context: OperationContext,
    started: Instant,
}

impl OperationTracker {
    fn start(
        options: &TelemetryOptions,
        request_id: &str,
        tls_mode: TlsMode,
        limits: OperationLimits,
    ) -> Result<Self, String> {
        let telemetry = NdjsonTelemetry::new(
            TelemetryConfig::new(&options.path)
                .with_rotation(options.max_file_bytes, options.backup_count),
        )
        .map_err(|error| error.to_string())?;
        let context = OperationContext::new(
            TELEMETRY_COMPONENT,
            PostgresConnector::CONNECTOR_ID,
            "probe",
            request_id,
            env!("CARGO_PKG_VERSION"),
            tls_mode.to_string(),
        )
        .map_err(|error| error.to_string())?;
        telemetry
            .operation_started(&context, limits)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            telemetry,
            context,
            started: Instant::now(),
        })
    }

    fn succeeded(&self, metrics: OperationMetrics) {
        if let Err(error) =
            self.telemetry
                .operation_succeeded(&self.context, self.started.elapsed(), metrics)
        {
            eprintln!("warning: {error}");
        }
    }

    fn failed(&self, failure: &CommandFailure) {
        let classification = OperationFailure::new(
            &failure.code,
            failure.class,
            failure.stage,
            failure.retryable,
            failure.configuration_error,
            failure.sql_state.clone(),
        );
        match classification {
            Ok(classification) => {
                if let Err(error) = self.telemetry.operation_failed(
                    &self.context,
                    self.started.elapsed(),
                    &classification,
                ) {
                    eprintln!("warning: {error}");
                }
            }
            Err(error) => eprintln!("warning: {error}"),
        }
    }
}

struct CommandFailure {
    message: String,
    code: String,
    class: &'static str,
    stage: &'static str,
    retryable: bool,
    configuration_error: bool,
    sql_state: Option<String>,
}

impl CommandFailure {
    fn local(code: &'static str, stage: &'static str, message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: code.into(),
            class: "configuration",
            stage,
            retryable: false,
            configuration_error: true,
            sql_state: None,
        }
    }

    fn connector(error: &ConnectorError) -> Self {
        Self {
            message: format_connector_error(error),
            code: error.code().into(),
            class: error_class_name(error.class()),
            stage: error_stage(error.class()),
            retryable: error.is_retryable(),
            configuration_error: error.is_configuration_error(),
            sql_state: error.sql_state().map(str::to_owned),
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}

async fn run() -> Result<(), String> {
    match parse(std::env::args_os().skip(1))? {
        Command::Help => {
            print!("{HELP}");
            Ok(())
        }
        Command::Probe(options) => execute_probe(options).await,
    }
}

async fn execute_probe(options: ProbeOptions) -> Result<(), String> {
    let request_id = request_id();
    let limits = OperationLimits::default()
        .with_connect_timeout(options.connection.connect_timeout)
        .with_operation_timeout(options.connection.probe_timeout);
    let tracker = OperationTracker::start(
        &options.telemetry,
        &request_id,
        options.connection.tls_mode,
        limits,
    )?;
    match execute_probe_inner(options.connection).await {
        Ok(report) => {
            tracker.succeeded(OperationMetrics::probe(report.server_version_number));
            print_probe_report(&report);
            Ok(())
        }
        Err(failure) => {
            tracker.failed(&failure);
            Err(failure.message)
        }
    }
}

async fn execute_probe_inner(options: ConnectionOptions) -> Result<ProbeReport, CommandFailure> {
    let secret = read_secret_from_stdin().map_err(|message| {
        CommandFailure::local("DBX-RS-PG-CLI-0001", "credential_input", message)
    })?;
    PostgresConnector
        .probe(
            &connection_config(options),
            &secret,
            CancellationToken::new(),
        )
        .await
        .map_err(|error| CommandFailure::connector(&error))
}

fn print_probe_report(report: &ProbeReport) {
    println!("connector={}", report.connector_id);
    println!("database_product={}", report.database_product);
    println!("server_version={}", report.server_version);
    if let Some(version_number) = report.server_version_number {
        println!("server_version_number={version_number}");
    }
    println!("endpoint={}", report.endpoint);
    println!("tls_mode={}", report.tls_mode);
}

fn connection_config(options: ConnectionOptions) -> ConnectionConfig {
    ConnectionConfig {
        connector_id: PostgresConnector::CONNECTOR_ID.into(),
        host: options.host,
        port: options.port,
        database: options.database,
        username: options.username,
        tls_mode: options.tls_mode,
        tls_server_name: options.tls_server_name,
        tls_ca_pem: options.tls_ca_pem,
        connect_timeout: options.connect_timeout,
        probe_timeout: options.probe_timeout,
    }
}

fn format_connector_error(error: &ConnectorError) -> String {
    format!(
        "error[{}] {:?}: {}",
        error.code(),
        error.class(),
        error.message()
    )
}

const fn error_class_name(class: ErrorClass) -> &'static str {
    match class {
        ErrorClass::Configuration => "configuration",
        ErrorClass::Dns => "dns",
        ErrorClass::Tcp => "tcp",
        ErrorClass::Tls => "tls",
        ErrorClass::Authentication => "authentication",
        ErrorClass::Protocol => "protocol",
        ErrorClass::Query => "query",
        ErrorClass::Conversion => "conversion",
        ErrorClass::Timeout => "timeout",
        ErrorClass::Cancelled => "cancelled",
        ErrorClass::Internal => "internal",
    }
}

const fn error_stage(class: ErrorClass) -> &'static str {
    match class {
        ErrorClass::Configuration => "configuration",
        ErrorClass::Dns => "dns",
        ErrorClass::Tcp => "tcp_connect",
        ErrorClass::Tls => "tls_handshake",
        ErrorClass::Authentication => "authentication",
        ErrorClass::Protocol => "protocol",
        ErrorClass::Query => "query",
        ErrorClass::Conversion => "conversion",
        ErrorClass::Timeout => "timeout",
        ErrorClass::Cancelled => "cancellation",
        ErrorClass::Internal => "internal",
    }
}

fn request_id() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!("cli-{}-{timestamp}", std::process::id())
}

fn read_secret_from_stdin() -> Result<ResolvedSecret, String> {
    const MAX_SECRET_BYTES: u64 = 16 * 1024;
    let mut bytes = Vec::new();
    let read_result = std::io::stdin()
        .take(MAX_SECRET_BYTES + 1)
        .read_to_end(&mut bytes);
    if read_result.is_err() {
        bytes.fill(0);
        return Err("failed to read password from standard input".into());
    }
    if bytes.len() as u64 > MAX_SECRET_BYTES {
        bytes.fill(0);
        return Err("password from standard input exceeds the size limit".into());
    }
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Err("password from standard input is empty".into());
    }
    Ok(ResolvedSecret::new(bytes))
}

fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command, String> {
    let mut args = args
        .into_iter()
        .map(|argument| {
            argument
                .into_string()
                .map_err(|_| "arguments must be valid UTF-8".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter();

    let Some(command) = args.next() else {
        return Ok(Command::Help);
    };
    if matches!(command.as_str(), "help" | "-h" | "--help") {
        return Ok(Command::Help);
    }
    if command != "probe" {
        return Err(format!("unknown command '{command}'\n\n{HELP}"));
    }

    let Some(raw) = parse_options(args)? else {
        return Ok(Command::Help);
    };
    finish_command(raw)
}

fn parse_options(mut args: impl Iterator<Item = String>) -> Result<Option<RawOptions>, String> {
    let mut raw = RawOptions::default();
    while let Some(argument) = args.next() {
        if matches!(argument.as_str(), "-h" | "--help") {
            return Ok(None);
        }
        parse_option(&mut raw, &argument, &mut args)?;
    }
    Ok(Some(raw))
}

fn parse_option(
    raw: &mut RawOptions,
    argument: &str,
    args: &mut impl Iterator<Item = String>,
) -> Result<(), String> {
    match argument {
        "--host" => raw.host = Some(next_value(args, argument)?),
        "--port" => raw.port = parse_value(&next_value(args, argument)?, argument)?,
        "--database" => raw.database = Some(next_value(args, argument)?),
        "--username" => raw.username = Some(next_value(args, argument)?),
        "--password-stdin" => raw.password_stdin = true,
        "--tls-mode" => {
            raw.tls_mode = next_value(args, argument)?
                .parse()
                .map_err(|message| format!("invalid --tls-mode: {message}"))?;
        }
        "--tls-server-name" => raw.tls_server_name = Some(next_value(args, argument)?),
        "--tls-ca-file" => raw.tls_ca_file = Some(PathBuf::from(next_value(args, argument)?)),
        "--connect-timeout-secs" => {
            raw.connect_timeout =
                Duration::from_secs(parse_value(&next_value(args, argument)?, argument)?);
        }
        "--probe-timeout-secs" => {
            raw.probe_timeout =
                Duration::from_secs(parse_value(&next_value(args, argument)?, argument)?);
        }
        "--splunk-home" => {
            raw.splunk_home = Some(PathBuf::from(next_value(args, argument)?));
        }
        "--trace-log" => raw.trace_log = Some(PathBuf::from(next_value(args, argument)?)),
        "--trace-max-bytes" => {
            raw.trace_max_bytes = parse_value(&next_value(args, argument)?, argument)?;
        }
        "--trace-backups" => {
            raw.trace_backups = parse_value(&next_value(args, argument)?, argument)?;
        }
        _ => return Err(format!("unknown argument '{argument}'")),
    }
    Ok(())
}

fn finish_command(raw: RawOptions) -> Result<Command, String> {
    if !raw.password_stdin {
        return Err("--password-stdin is required".into());
    }

    let tls_ca_pem = raw
        .tls_ca_file
        .map(|path| read_limited_file(&path, "TLS CA", MAX_FILE_BYTES))
        .transpose()?;
    let connection = ConnectionOptions {
        host: raw.host.ok_or("--host is required")?,
        port: raw.port,
        database: raw.database.ok_or("--database is required")?,
        username: raw.username.ok_or("--username is required")?,
        tls_mode: raw.tls_mode,
        tls_server_name: raw.tls_server_name,
        tls_ca_pem,
        connect_timeout: raw.connect_timeout,
        probe_timeout: raw.probe_timeout,
    };
    let splunk_home = resolve_splunk_home(raw.splunk_home.as_deref())?;
    let telemetry = TelemetryOptions {
        path: resolve_trace_log_path(raw.trace_log.as_deref(), &splunk_home)?,
        max_file_bytes: raw.trace_max_bytes,
        backup_count: raw.trace_backups,
    };
    Ok(Command::Probe(ProbeOptions {
        connection,
        telemetry,
    }))
}

fn resolve_splunk_home(configured: Option<&Path>) -> Result<PathBuf, String> {
    let home = configured
        .map(Path::to_path_buf)
        .or_else(|| {
            std::env::var_os("SPLUNK_HOME")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        })
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .as_deref()
                .and_then(infer_splunk_home)
        })
        .ok_or_else(|| {
            "Splunk home could not be resolved; pass --splunk-home or set SPLUNK_HOME".to_owned()
        })?;
    if !home.is_absolute() || has_parent_component(&home) {
        return Err("Splunk home must be an absolute path without parent traversal".into());
    }
    Ok(home)
}

fn infer_splunk_home(executable: &Path) -> Option<PathBuf> {
    let bin = executable.parent()?;
    let app = bin.parent()?;
    let apps = app.parent()?;
    let etc = apps.parent()?;
    if bin.file_name()? != "bin" || apps.file_name()? != "apps" || etc.file_name()? != "etc" {
        return None;
    }
    etc.parent().map(Path::to_path_buf)
}

fn resolve_trace_log_path(
    configured: Option<&Path>,
    splunk_home: &Path,
) -> Result<PathBuf, String> {
    let splunk_var = splunk_home.join("var");
    let path = configured.map_or_else(
        || splunk_var.join("log").join("splunk").join("dbx-trace.log"),
        Path::to_path_buf,
    );
    if !path.is_absolute() || has_parent_component(&path) || !path.starts_with(&splunk_var) {
        return Err("operational trace log must be an absolute path under SPLUNK_HOME/var".into());
    }
    Ok(path)
}

fn has_parent_component(path: &Path) -> bool {
    path.components()
        .any(|component| component == std::path::Component::ParentDir)
}

fn read_limited_file(path: &Path, label: &str, max_bytes: u64) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|_| format!("failed to open {label} file"))?;
    let mut bytes = Vec::new();
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| format!("failed to read {label} file"))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!("{label} file exceeds the size limit"));
    }
    Ok(bytes)
}

fn next_value(args: &mut impl Iterator<Item = String>, option: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{option} requires a value"))
}

fn parse_value<T>(value: &str, option: &str) -> Result<T, String>
where
    T: std::str::FromStr,
{
    value
        .parse()
        .map_err(|_| format!("{option} has an invalid value"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_lists_only_the_probe_command() {
        assert!(HELP.contains("\\\n      --password-stdin"));
        assert!(!HELP.contains("collect"));
    }

    #[test]
    fn probe_defaults_to_verified_tls() {
        let command = parse(
            [
                "probe",
                "--host",
                "db.example",
                "--database",
                "events",
                "--username",
                "reader",
                "--password-stdin",
                "--splunk-home",
                "/tmp/dbx-rs-splunk-test",
            ]
            .map(OsString::from),
        )
        .expect("arguments must parse");

        let Command::Probe(options) = command else {
            panic!("expected probe command");
        };
        assert_eq!(options.connection.tls_mode, TlsMode::VerifyFull);
    }

    #[test]
    fn trace_rotation_options_are_parsed() {
        let command = parse(
            [
                "probe",
                "--host",
                "db.example",
                "--database",
                "events",
                "--username",
                "reader",
                "--password-stdin",
                "--trace-log",
                "/tmp/dbx-rs-splunk-test/var/log/splunk/dbx-test-trace.log",
                "--splunk-home",
                "/tmp/dbx-rs-splunk-test",
                "--trace-max-bytes",
                "8192",
                "--trace-backups",
                "2",
            ]
            .map(OsString::from),
        )
        .expect("arguments must parse");

        let Command::Probe(options) = command else {
            panic!("expected probe command");
        };
        assert_eq!(
            options.telemetry.path,
            Path::new("/tmp/dbx-rs-splunk-test/var/log/splunk/dbx-test-trace.log")
        );
        assert_eq!(options.telemetry.max_file_bytes, 8_192);
        assert_eq!(options.telemetry.backup_count, 2);
    }

    #[test]
    fn obsolete_collect_command_is_rejected() {
        let error = parse(["collect"].map(OsString::from))
            .err()
            .expect("removed command must fail");

        assert!(error.contains("unknown command 'collect'"));
    }

    #[test]
    fn trace_log_outside_splunk_var_is_rejected() {
        let error = parse(
            [
                "probe",
                "--host",
                "db.example",
                "--database",
                "events",
                "--username",
                "reader",
                "--password-stdin",
                "--splunk-home",
                "/tmp/dbx-rs-splunk-test",
                "--trace-log",
                "/tmp/dbx-trace.log",
            ]
            .map(OsString::from),
        )
        .err()
        .expect("external trace path must fail");

        assert!(error.contains("under SPLUNK_HOME/var"));
    }

    #[test]
    fn password_must_come_from_stdin() {
        let error = parse(
            [
                "probe",
                "--host",
                "db.example",
                "--database",
                "events",
                "--username",
                "reader",
            ]
            .map(OsString::from),
        )
        .err()
        .expect("missing password source must fail");

        assert_eq!(error, "--password-stdin is required");
    }
}
