use std::env;
use std::fs;
use std::io::Cursor;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arrow_array::{
    Array, BinaryArray, Decimal128Array, RecordBatch, StringArray, TimestampMicrosecondArray,
};
use arrow_ipc::reader::StreamReader;
use chrono::NaiveDate;
use dbx_rs_connector_oracle::OracleConnector;
use dbx_rs_connector_sdk::{
    ArrowIpcBatch, ConnectionConfig, Connector, ConnectorError, ErrorClass, ExecuteRequest,
    ExecutionLimits, ExecutionResult, PrepareRequest, ProbeRequest, QueryText, ResolvedSecret,
    TlsMode,
};
use oracle_rs::{Config, Connection, QueryResult, TlsConfig, WireLimits};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

const MAX_BATCH_BYTES: u64 = 1024 * 1024;
const MAX_TOTAL_IPC_BYTES: u64 = 8 * 1024 * 1024;

fn required(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} is required for the ignored live test"))
}

fn optional_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .map_or(Ok(default), |value| value.parse::<u64>())
        .unwrap_or_else(|_| panic!("{name} must be an unsigned integer"))
}

fn live_connection() -> ConnectionConfig {
    let tls_mode = env::var("DBX_RS_LIVE_ORACLE_TLS_MODE")
        .unwrap_or_else(|_| "disable".into())
        .parse::<TlsMode>()
        .expect("DBX_RS_LIVE_ORACLE_TLS_MODE must be a supported TLS mode");
    let tls_ca_pem = env::var("DBX_RS_LIVE_ORACLE_CA_FILE")
        .ok()
        .map(|path| fs::read(path).expect("live Oracle CA file must be readable"));

    ConnectionConfig {
        connector_id: "oracle".into(),
        host: required("DBX_RS_LIVE_ORACLE_HOST"),
        port: env::var("DBX_RS_LIVE_ORACLE_PORT")
            .map_or(Ok(1521), |port| port.parse::<u16>())
            .expect("DBX_RS_LIVE_ORACLE_PORT must be a valid port"),
        database: required("DBX_RS_LIVE_ORACLE_SERVICE"),
        username: required("DBX_RS_LIVE_ORACLE_USERNAME"),
        tls_mode,
        tls_server_name: env::var("DBX_RS_LIVE_ORACLE_TLS_SERVER_NAME").ok(),
        tls_ca_pem,
        connect_timeout: Duration::from_secs(10),
        probe_timeout: Duration::from_secs(10),
    }
}

fn live_secret() -> ResolvedSecret {
    ResolvedSecret::new(required("DBX_RS_LIVE_ORACLE_PASSWORD").into_bytes())
}

fn execution_request(
    request_id: &str,
    connection: ConnectionConfig,
    query: String,
    max_rows: u64,
    max_batch_rows: u32,
    timeout: Duration,
) -> ExecuteRequest {
    ExecuteRequest {
        request_id: request_id.into(),
        connection,
        query: QueryText::new(query),
        limits: ExecutionLimits {
            max_rows,
            max_batch_rows,
            max_batch_bytes: MAX_BATCH_BYTES,
            max_total_ipc_bytes: MAX_TOTAL_IPC_BYTES,
            timeout,
        },
        expected_schema: None,
        cursor: None,
    }
}

async fn execute_live(
    request: ExecuteRequest,
    cancellation: CancellationToken,
) -> Result<(ExecutionResult, Vec<ArrowIpcBatch>), ConnectorError> {
    let connector = OracleConnector::new();
    let secret = live_secret();
    let (batch_tx, mut batch_rx) = mpsc::channel(8);
    let execute = connector.execute(request, &secret, batch_tx, cancellation);
    let receive = async move {
        let mut batches = Vec::new();
        while let Some(batch) = batch_rx.recv().await {
            batches.push(batch);
        }
        batches
    };
    let (result, batches) = tokio::join!(execute, receive);
    result.map(|result| (result, batches))
}

fn decode_batch(batch: &ArrowIpcBatch) -> RecordBatch {
    let mut reader = StreamReader::try_new(Cursor::new(batch.ipc_bytes.as_slice()), None)
        .expect("live Oracle IPC stream must decode");
    let decoded = reader
        .next()
        .expect("live Oracle IPC stream must contain one batch")
        .expect("live Oracle IPC batch must decode");
    assert!(
        reader.next().is_none(),
        "IPC envelope must contain one batch"
    );
    decoded
}

fn decimal_value(batch: &ArrowIpcBatch) -> i128 {
    let decoded = decode_batch(batch);
    decoded
        .column(0)
        .as_any()
        .downcast_ref::<Decimal128Array>()
        .expect("live cleanup result must be Decimal128")
        .value(0)
}

fn native_config(config: &ConnectionConfig, secret: &ResolvedSecret) -> Config {
    let mut native = Config::new(
        config.host.clone(),
        config.port,
        config.database.clone(),
        config.username.clone(),
        String::new(),
    )
    .connect_timeout(config.connect_timeout)
    .stmtcachesize(0)
    .wire_limits(WireLimits {
        max_packet_bytes: 1024 * 1024,
        max_response_bytes: 2 * 1024 * 1024,
        max_rows_per_response: 20_000,
        max_columns: 16,
        max_value_bytes: 1024 * 1024,
    });
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
            panic!("live Oracle tests reject TLS modes without hostname verification");
        }
    }
    native
}

async fn fetch_all_pages(connection: &Connection, mut page: QueryResult) -> (usize, usize, bool) {
    let columns = page.columns.clone();
    let mut row_count = 0_usize;
    let mut page_count = 0_usize;
    let mut saw_multi_packet_response = false;

    loop {
        row_count += page.rows.len();
        page_count += 1;
        saw_multi_packet_response |= page.response_packet_count > 1;
        if !page.has_more_rows {
            break;
        }
        assert_ne!(page.cursor_id, 0, "continuation must include a cursor ID");
        assert!(page_count < 16, "live continuation exceeded its page bound");
        page = connection
            .fetch_more(page.cursor_id, &columns, 20_000)
            .await
            .expect("live Oracle continuation must succeed");
    }

    (row_count, page_count, saw_multi_packet_response)
}

fn render_marker_template(name: &str, marker: &str) -> String {
    let template = required(name);
    assert_eq!(
        template.matches("{marker}").count(),
        1,
        "live cleanup templates must contain exactly one marker placeholder"
    );
    template.replace("{marker}", marker)
}

#[tokio::test]
#[ignore = "requires an explicitly configured Oracle 19c sandbox"]
async fn oracle_19c_probe_and_one_row_query_pass() {
    let connection = live_connection();
    let connector = OracleConnector::new();
    let secret = live_secret();
    let report = connector
        .probe(
            ProbeRequest {
                request_id: "live-oracle-19c-probe".into(),
                connection: connection.clone(),
            },
            &secret,
            CancellationToken::new(),
        )
        .await
        .expect("live Oracle probe must succeed");
    let expected_version =
        env::var("DBX_RS_LIVE_ORACLE_VERSION_PREFIX").unwrap_or_else(|_| "19".into());
    assert!(
        report.server_version.starts_with(&expected_version),
        "live Oracle server version does not match the configured prefix"
    );

    let request = execution_request(
        "live-oracle-one-row",
        connection,
        "SELECT CAST(1 AS NUMBER(1,0)) AS value FROM DUAL".into(),
        1,
        1,
        Duration::from_secs(20),
    );
    let (result, batches) = execute_live(request, CancellationToken::new())
        .await
        .expect("live Oracle one-row query must succeed");
    assert_eq!(result.rows_read, 1);
    assert!(!result.truncated);
    assert_eq!(batches.len(), 1);
    assert_eq!(decimal_value(&batches[0]), 1);
}

#[tokio::test]
#[ignore = "requires an explicitly configured Oracle sandbox"]
async fn large_query_uses_multiple_packets_and_continues_beyond_one_hundred_rows() {
    let config = live_connection();
    assert!(
        OracleConnector::validate_connection(&config).is_valid(),
        "live Oracle connection configuration must validate"
    );
    let secret = live_secret();
    let connection = Connection::connect_with_config(native_config(&config, &secret))
        .await
        .expect("live native Oracle connection must succeed");
    let query = "SELECT \
        CAST(1000000000000000000000000000000000000 + level AS NUMBER(38,0)) AS value_a, \
        CAST(9000000000000000000000000000000000000 - level AS NUMBER(38,0)) AS value_b \
        FROM DUAL CONNECT BY level <= 20001";
    let first_page = connection
        .query_with_fetch_size(query, &[], 20_000)
        .await
        .expect("live multi-packet Oracle query must succeed");
    let (row_count, page_count, saw_multi_packet_response) =
        fetch_all_pages(&connection, first_page).await;
    connection.abort().await;

    assert_eq!(row_count, 20_001);
    assert!(page_count >= 2, "live result must require continuation");
    assert!(
        saw_multi_packet_response,
        "live result must contain an observed multi-packet TNS response"
    );

    let request = execution_request(
        "live-oracle-large-connector-query",
        config,
        query.into(),
        20_001,
        256,
        Duration::from_mins(1),
    );
    let (result, batches) = execute_live(request, CancellationToken::new())
        .await
        .expect("live Oracle connector continuation must succeed");
    assert_eq!(result.rows_read, 20_001);
    assert!(!result.truncated);
    assert_eq!(result.batches_emitted, batches.len() as u64);
    assert!(batches.len() > 1, "connector result must span batches");
    assert_eq!(
        batches.iter().map(|batch| batch.row_count).sum::<u64>(),
        20_001
    );
    for (sequence, batch) in batches.iter().enumerate() {
        assert_eq!(batch.sequence, sequence as u64);
    }

    let first = decode_batch(&batches[0]);
    let last = decode_batch(batches.last().unwrap());
    let first_values = first
        .column(0)
        .as_any()
        .downcast_ref::<Decimal128Array>()
        .unwrap();
    let last_values = last
        .column(0)
        .as_any()
        .downcast_ref::<Decimal128Array>()
        .unwrap();
    assert_eq!(first_values.value(0), 10_i128.pow(36) + 1);
    assert_eq!(
        last_values.value(last_values.len() - 1),
        10_i128.pow(36) + 20_001
    );
}

#[tokio::test]
#[ignore = "requires an explicitly configured verified-TLS Oracle sandbox"]
async fn core_type_corpus_round_trips_over_verified_tls() {
    let connection = live_connection();
    assert_eq!(
        connection.tls_mode,
        TlsMode::VerifyFull,
        "core live corpus requires verify-full TLS"
    );
    let query = "SELECT \
        CAST(-1234567890123456.7890 AS NUMBER(20,4)) AS decimal_value, \
        DATE '1970-01-01' AS date_value, \
        CAST(TIMESTAMP '2024-02-29 23:59:58.654321' AS TIMESTAMP(6)) AS timestamp_value, \
        CAST(UNISTR('national-\\20AC') AS NVARCHAR2(32)) AS national_value, \
        HEXTORAW('00FF07') AS binary_value, \
        CAST(NULL AS VARCHAR2(8)) AS null_value \
        FROM DUAL";
    let request = execution_request(
        "live-oracle-core-types",
        connection,
        query.into(),
        1,
        1,
        Duration::from_secs(20),
    );
    let (result, batches) = execute_live(request, CancellationToken::new())
        .await
        .expect("live Oracle core type corpus must succeed");
    assert_eq!(result.rows_read, 1);
    assert_eq!(batches.len(), 1);
    let decoded = decode_batch(&batches[0]);
    assert_eq!(decoded.num_columns(), 6);

    let decimal = decoded
        .column(0)
        .as_any()
        .downcast_ref::<Decimal128Array>()
        .unwrap();
    assert_eq!(decimal.value(0), -12_345_678_901_234_567_890_i128);
    let date = decoded
        .column(1)
        .as_any()
        .downcast_ref::<TimestampMicrosecondArray>()
        .unwrap();
    assert_eq!(date.value(0), 0);
    let timestamp = decoded
        .column(2)
        .as_any()
        .downcast_ref::<TimestampMicrosecondArray>()
        .unwrap();
    let expected_timestamp = NaiveDate::from_ymd_opt(2024, 2, 29)
        .unwrap()
        .and_hms_micro_opt(23, 59, 58, 654_321)
        .unwrap()
        .and_utc()
        .timestamp_micros();
    assert_eq!(timestamp.value(0), expected_timestamp);
    let text = decoded
        .column(3)
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(text.value(0), "national-\u{20ac}");
    let binary = decoded
        .column(4)
        .as_any()
        .downcast_ref::<BinaryArray>()
        .unwrap();
    assert_eq!(binary.value(0), [0, 0xff, 7]);
    let null = decoded
        .column(5)
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert!(null.is_null(0));
}

#[tokio::test]
#[ignore = "requires an explicitly configured verified-TLS Oracle sandbox"]
async fn wrong_tls_server_name_fails_verification() {
    let mut connection = live_connection();
    assert_eq!(
        connection.tls_mode,
        TlsMode::VerifyFull,
        "negative live TLS test requires verify-full TLS"
    );
    connection.tls_server_name = Some("dbx-rs-invalid.invalid".into());
    let connector = OracleConnector::new();
    let secret = live_secret();
    let error = connector
        .probe(
            ProbeRequest {
                request_id: "live-oracle-tls-negative".into(),
                connection,
            },
            &secret,
            CancellationToken::new(),
        )
        .await
        .expect_err("wrong Oracle TLS name must fail");

    assert_eq!(error.class(), ErrorClass::Tls);
    assert_eq!(error.code(), "DBX-RS-ORA-TLS-0001");
}

#[tokio::test]
#[ignore = "requires dedicated invalid credentials on an explicitly configured Oracle sandbox"]
async fn invalid_dedicated_credentials_are_classified_and_redacted() {
    let mut connection = live_connection();
    let invalid_username = required("DBX_RS_LIVE_ORACLE_INVALID_USERNAME");
    let invalid_password = required("DBX_RS_LIVE_ORACLE_INVALID_PASSWORD");
    assert!(
        invalid_username.len() >= 12 && invalid_password.len() >= 12,
        "invalid credential markers must be distinctive for redaction assertions"
    );
    connection.username.clone_from(&invalid_username);
    let secret = ResolvedSecret::new(invalid_password.as_bytes().to_vec());
    let connector = OracleConnector::new();
    let error = connector
        .probe(
            ProbeRequest {
                request_id: "live-oracle-invalid-auth".into(),
                connection,
            },
            &secret,
            CancellationToken::new(),
        )
        .await
        .expect_err("dedicated invalid Oracle credentials must fail");

    assert_eq!(error.class(), ErrorClass::Authentication);
    assert_eq!(error.code(), "DBX-RS-ORA-AUTH-0002");
    let diagnostic = format!("{error:?} {error}");
    assert!(!diagnostic.contains(&invalid_username));
    assert!(!diagnostic.contains(&invalid_password));
}

#[tokio::test]
#[ignore = "requires an explicitly configured Oracle sandbox"]
async fn unsupported_live_types_fail_closed_during_prepare() {
    let connection = live_connection();
    let connector = OracleConnector::new();
    let secret = live_secret();
    let cases = [
        (
            "SELECT TO_CLOB('x') AS value FROM DUAL",
            "DBX-RS-ORA-CONVERT-0013",
        ),
        (
            "SELECT SYSTIMESTAMP AS value FROM DUAL",
            "DBX-RS-ORA-CONVERT-0012",
        ),
        (
            "SELECT CAST(TIMESTAMP '2024-01-01 00:00:00.123456789' AS TIMESTAMP(9)) AS value FROM DUAL",
            "DBX-RS-ORA-CONVERT-0011",
        ),
    ];

    for (index, (query, expected_code)) in cases.into_iter().enumerate() {
        let error = connector
            .prepare(
                PrepareRequest {
                    request_id: format!("live-oracle-unsupported-{index}"),
                    connection: connection.clone(),
                    query: QueryText::new(query),
                    max_rows: 1,
                    timeout: Duration::from_secs(20),
                    cursor: None,
                },
                &secret,
                CancellationToken::new(),
            )
            .await
            .expect_err("unsupported live Oracle type must fail prepare");
        assert_eq!(error.class(), ErrorClass::Conversion);
        assert_eq!(error.code(), expected_code);
    }
}

#[tokio::test]
#[ignore = "requires configured long-query and server-cleanup Oracle fixtures"]
async fn cancellation_removes_the_matching_server_operation() {
    let marker = format!(
        "DBXRSORACANCEL{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time must follow the Unix epoch")
            .as_nanos()
    );
    let long_query = render_marker_template("DBX_RS_LIVE_ORACLE_LONG_QUERY_TEMPLATE", &marker);
    let cleanup_query =
        render_marker_template("DBX_RS_LIVE_ORACLE_CLEANUP_QUERY_TEMPLATE", &marker);
    let cancellation = CancellationToken::new();
    let cancel = cancellation.clone();
    let cancel_after =
        Duration::from_millis(optional_u64("DBX_RS_LIVE_ORACLE_CANCEL_AFTER_MS", 250));
    tokio::spawn(async move {
        tokio::time::sleep(cancel_after).await;
        cancel.cancel();
    });
    let request = execution_request(
        "live-oracle-cancel-cleanup",
        live_connection(),
        long_query,
        1,
        1,
        Duration::from_secs(30),
    );
    let error = execute_live(request, cancellation)
        .await
        .expect_err("live Oracle operation must be cancelled");
    assert_eq!(error.class(), ErrorClass::Cancelled);

    let deadline = Instant::now()
        + Duration::from_secs(optional_u64("DBX_RS_LIVE_ORACLE_CLEANUP_TIMEOUT_SECS", 10));
    loop {
        let request = execution_request(
            "live-oracle-cleanup-observer",
            live_connection(),
            cleanup_query.clone(),
            1,
            1,
            Duration::from_secs(20),
        );
        let (_, batches) = execute_live(request, CancellationToken::new())
            .await
            .expect("live Oracle cleanup observer query must succeed");
        assert_eq!(batches.len(), 1);
        if decimal_value(&batches[0]) == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "cancelled Oracle operation remained active past the cleanup deadline"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
