use std::{env, fs, io::Cursor, sync::Arc, time::Duration};

use arrow_array::{Array, Decimal128Array, Int64Array, RecordBatch, TimestampMicrosecondArray};
use arrow_ipc::reader::StreamReader;
use dbx_rs_connector_mssql::MssqlConnector;
use dbx_rs_connector_sdk::{
    ArrowIpcBatch, ConnectionConfig, Connector, ConnectorError, CursorNullPolicy, ErrorClass,
    ExecuteRequest, ExecutionLimits, ExecutionResult, FieldType, ProbeRequest, QueryText,
    ResolvedSecret, TimestampIdCursor, TimestampIdCursorRequest, TimestampIdCursorSpec, TlsMode,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const MAX_BATCH_BYTES: u64 = 1024 * 1024;
const MAX_TOTAL_IPC_BYTES: u64 = 8 * 1024 * 1024;

fn required(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} is required for the ignored live test"))
}

fn live_connection() -> ConnectionConfig {
    let tls_mode = env::var("DBX_RS_LIVE_MSSQL_TLS_MODE")
        .unwrap_or_else(|_| "verify-full".into())
        .parse::<TlsMode>()
        .expect("DBX_RS_LIVE_MSSQL_TLS_MODE must be a supported TLS mode");
    let tls_ca_pem = env::var("DBX_RS_LIVE_MSSQL_CA_FILE")
        .ok()
        .map(|path| fs::read(path).expect("DBX_RS_LIVE_MSSQL_CA_FILE must be readable"));

    ConnectionConfig {
        connector_id: MssqlConnector::CONNECTOR_ID.into(),
        host: required("DBX_RS_LIVE_MSSQL_HOST"),
        port: env::var("DBX_RS_LIVE_MSSQL_PORT")
            .map_or(Ok(1433), |port| port.parse::<u16>())
            .expect("DBX_RS_LIVE_MSSQL_PORT must be a valid port"),
        database: required("DBX_RS_LIVE_MSSQL_DATABASE"),
        username: required("DBX_RS_LIVE_MSSQL_USERNAME"),
        tls_mode,
        tls_server_name: env::var("DBX_RS_LIVE_MSSQL_TLS_SERVER_NAME").ok(),
        tls_ca_pem,
        connect_timeout: Duration::from_secs(10),
        probe_timeout: Duration::from_secs(10),
    }
}

fn live_secret() -> ResolvedSecret {
    ResolvedSecret::new(required("DBX_RS_LIVE_MSSQL_PASSWORD").into_bytes())
}

fn execution_request(
    request_id: &str,
    query: &str,
    max_rows: u64,
    max_batch_rows: u32,
    max_batch_bytes: u64,
    timeout: Duration,
    cursor: Option<TimestampIdCursorRequest>,
) -> ExecuteRequest {
    ExecuteRequest {
        request_id: request_id.into(),
        connection: live_connection(),
        query: QueryText::new(query),
        limits: ExecutionLimits {
            max_rows,
            max_batch_rows,
            max_batch_bytes,
            max_total_ipc_bytes: MAX_TOTAL_IPC_BYTES,
            timeout,
        },
        expected_schema: None,
        cursor,
    }
}

async fn execute_live(
    request: ExecuteRequest,
    cancellation: CancellationToken,
) -> Result<(ExecutionResult, Vec<ArrowIpcBatch>), ConnectorError> {
    let connector: Arc<dyn Connector> = Arc::new(MssqlConnector);
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

fn decode_batches(batches: &[ArrowIpcBatch]) -> Vec<RecordBatch> {
    batches
        .iter()
        .map(|batch| {
            let mut reader = StreamReader::try_new(Cursor::new(batch.ipc_bytes.as_slice()), None)
                .expect("live SQL Server IPC stream must decode");
            let decoded = reader
                .next()
                .expect("live SQL Server IPC stream must contain one batch")
                .expect("live SQL Server IPC batch must decode");
            assert!(
                reader.next().is_none(),
                "IPC envelope must contain one batch"
            );
            decoded
        })
        .collect()
}

fn cursor_request(
    committed: Option<TimestampIdCursor>,
    overlap: Duration,
) -> TimestampIdCursorRequest {
    TimestampIdCursorRequest {
        spec: TimestampIdCursorSpec {
            timestamp_field: "dbx_cursor_time".into(),
            id_field: "dbx_cursor_id".into(),
            overlap,
            null_policy: CursorNullPolicy::Reject,
        },
        committed,
        resume_after: None,
    }
}

fn cursor_rows(batches: &[ArrowIpcBatch]) -> Vec<TimestampIdCursor> {
    let decoded = decode_batches(batches);
    let schema = decoded
        .first()
        .expect("cursor execution must return a batch")
        .schema();
    let timestamp_index = schema
        .index_of("dbx_cursor_time")
        .expect("cursor timestamp must exist");
    let id_index = schema
        .index_of("dbx_cursor_id")
        .expect("cursor ID must exist");
    let mut cursors = Vec::new();
    for batch in decoded {
        let timestamps = batch
            .column(timestamp_index)
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .expect("cursor timestamp must use microsecond storage");
        let identifiers = batch
            .column(id_index)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("cursor ID must use signed 64-bit storage");
        for row in 0..batch.num_rows() {
            assert!(!timestamps.is_null(row));
            assert!(!identifiers.is_null(row));
            cursors.push(TimestampIdCursor::new(
                timestamps.value(row),
                identifiers.value(row),
            ));
        }
    }
    cursors
}

#[tokio::test]
#[ignore = "requires an authorized live SQL Server"]
async fn probe_identity_authentication_and_tls_name() {
    let connector = MssqlConnector;
    let connection = live_connection();
    let secret = live_secret();
    let report = connector
        .probe(
            ProbeRequest {
                request_id: "live-mssql-probe".into(),
                connection: connection.clone(),
            },
            &secret,
            CancellationToken::new(),
        )
        .await
        .expect("live SQL Server probe must succeed");

    assert_eq!(report.connector_id, "mssql");
    assert_eq!(report.database_product, "Microsoft SQL Server");
    assert!(
        report
            .server_version
            .starts_with(&required("DBX_RS_LIVE_MSSQL_VERSION_PREFIX"))
    );

    let mut invalid_password = secret.expose_secret().to_vec();
    invalid_password.extend_from_slice(b"-intentionally-invalid");
    let error = connector
        .probe(
            ProbeRequest {
                request_id: "live-mssql-invalid-auth".into(),
                connection: connection.clone(),
            },
            &ResolvedSecret::new(invalid_password),
            CancellationToken::new(),
        )
        .await
        .expect_err("invalid credentials must fail");
    assert_eq!(error.class(), ErrorClass::Authentication);
    assert!(!format!("{error:?}").contains(&required("DBX_RS_LIVE_MSSQL_PASSWORD")));

    if connection.tls_mode == TlsMode::VerifyFull {
        let mut wrong_name = connection;
        wrong_name.tls_server_name = Some("dbx-rs-wrong-name.invalid".into());
        let error = connector
            .probe(
                ProbeRequest {
                    request_id: "live-mssql-wrong-tls-name".into(),
                    connection: wrong_name,
                },
                &secret,
                CancellationToken::new(),
            )
            .await
            .expect_err("wrong TLS server name must fail");
        assert_eq!(error.class(), ErrorClass::Tls);
    }
}

#[tokio::test]
#[ignore = "requires an authorized live SQL Server"]
async fn exact_types_streaming_and_truncation() {
    const TYPES: &str = "SELECT CAST(1 AS bit) AS bit_value, CAST(255 AS tinyint) AS tiny_value, CAST(-32768 AS smallint) AS small_value, CAST(-2147483648 AS int) AS int_value, CAST(-9223372036854775807 AS bigint) AS big_value, CAST(1.25 AS real) AS real_value, CAST(-1.5 AS float) AS float_value, CAST(-12345678901234567890123456789012.345678 AS decimal(38,6)) AS exact_decimal, CAST(922337203685477.5807 AS money) AS money_value, CAST(-214748.3648 AS smallmoney) AS smallmoney_value, CAST('2026-07-17' AS date) AS date_value, CAST('23:59:59.123456' AS time(6)) AS time_value, CAST('2026-07-17T12:34:56.123456' AS datetime2(6)) AS datetime2_value, CAST('2026-07-17T12:34:56.997' AS datetime) AS datetime_value, CAST('2026-07-17T12:34:56.1234567+05:30' AS datetimeoffset(7)) AS offset_value, CAST('00112233-4455-6677-8899-aabbccddeeff' AS uniqueidentifier) AS uuid_value, CAST(N'Unicode text' AS nvarchar(100)) AS text_value, CAST(0x00ff10 AS varbinary(16)) AS binary_value, CAST(N'<root value=\"1\" />' AS xml) AS xml_value";
    const SEQUENCE: &str = "SELECT CONVERT(bigint, ROW_NUMBER() OVER (ORDER BY a.object_id, b.object_id)) AS n FROM sys.all_objects AS a CROSS JOIN sys.all_objects AS b";
    let request = execution_request(
        "live-mssql-exact-types",
        TYPES,
        10,
        10,
        MAX_BATCH_BYTES,
        Duration::from_secs(20),
        None,
    );
    let (result, batches) = execute_live(request, CancellationToken::new())
        .await
        .expect("exact type query must succeed");
    let expected = [
        FieldType::Boolean,
        FieldType::Int16,
        FieldType::Int16,
        FieldType::Int32,
        FieldType::Int64,
        FieldType::Float32,
        FieldType::Float64,
        FieldType::Decimal128 {
            precision: 38,
            scale: 6,
        },
        FieldType::Decimal128 {
            precision: 19,
            scale: 4,
        },
        FieldType::Decimal128 {
            precision: 10,
            scale: 4,
        },
        FieldType::Date32,
        FieldType::Time64Microsecond,
        FieldType::TimestampMicrosecond,
        FieldType::Utf8,
        FieldType::Utf8,
        FieldType::Uuid,
        FieldType::Utf8,
        FieldType::Binary,
        FieldType::Utf8,
    ];
    assert_eq!(result.rows_read, 1);
    assert_eq!(result.schema.fields.len(), expected.len());
    for (field, expected) in result.schema.fields.iter().zip(expected) {
        assert_eq!(field.field_type, expected);
    }
    let decoded = decode_batches(&batches);
    let decimal = decoded[0]
        .column(7)
        .as_any()
        .downcast_ref::<Decimal128Array>()
        .expect("decimal must use Decimal128");
    assert_eq!(
        decimal.value(0),
        -12_345_678_901_234_567_890_123_456_789_012_345_678
    );
    let money = decoded[0]
        .column(8)
        .as_any()
        .downcast_ref::<Decimal128Array>()
        .expect("money must use Decimal128");
    let smallmoney = decoded[0]
        .column(9)
        .as_any()
        .downcast_ref::<Decimal128Array>()
        .expect("smallmoney must use Decimal128");
    assert_eq!(money.value(0), 9_223_372_036_854_775_807);
    assert_eq!(smallmoney.value(0), -2_147_483_648);

    let request = execution_request(
        "live-mssql-multi-batch",
        SEQUENCE,
        300,
        64,
        MAX_BATCH_BYTES,
        Duration::from_secs(20),
        None,
    );
    let (result, batches) = execute_live(request, CancellationToken::new())
        .await
        .expect("multi-batch query must succeed");
    assert_eq!(result.rows_read, 300);
    assert!(result.truncated);
    assert!(result.batches_emitted >= 5);
    assert_eq!(batches.len() as u64, result.batches_emitted);
}

#[tokio::test]
#[ignore = "requires the dbx_rs_mssql_events live fixture"]
async fn rising_continuation_and_overlap_are_ordered() {
    const QUERY: &str = "SELECT updated_at AS dbx_cursor_time, event_id AS dbx_cursor_id, payload FROM dbo.dbx_rs_mssql_events";
    let request = execution_request(
        "live-mssql-rising-first",
        QUERY,
        2,
        2,
        MAX_BATCH_BYTES,
        Duration::from_secs(20),
        Some(cursor_request(None, Duration::ZERO)),
    );
    let (first, batches) = execute_live(request, CancellationToken::new())
        .await
        .expect("first rising page must succeed");
    let first_rows = cursor_rows(&batches);
    assert_eq!(first_rows.len(), 2);
    assert!(first.truncated);
    assert_eq!(
        first_rows[0].timestamp_epoch_micros,
        first_rows[1].timestamp_epoch_micros
    );
    assert!(first_rows[0].id < first_rows[1].id);

    let committed = *first_rows.last().expect("first page has a cursor");
    let request = execution_request(
        "live-mssql-rising-resume",
        QUERY,
        10,
        10,
        MAX_BATCH_BYTES,
        Duration::from_secs(20),
        Some(cursor_request(Some(committed), Duration::ZERO)),
    );
    let (_second, batches) = execute_live(request, CancellationToken::new())
        .await
        .expect("second rising page must succeed");
    let resumed = cursor_rows(&batches);
    assert!(
        resumed
            .first()
            .is_some_and(|cursor| cursor.position_cmp(&committed).is_gt())
    );

    let request = execution_request(
        "live-mssql-rising-overlap",
        QUERY,
        10,
        10,
        MAX_BATCH_BYTES,
        Duration::from_secs(20),
        Some(cursor_request(Some(committed), Duration::from_secs(1))),
    );
    let (_overlap, batches) = execute_live(request, CancellationToken::new())
        .await
        .expect("overlap rising page must succeed");
    let overlapped = cursor_rows(&batches);
    assert!(overlapped.iter().any(|cursor| cursor == &committed));
}

#[tokio::test]
#[ignore = "requires an authorized live SQL Server"]
async fn unsupported_type_timeout_cancellation_and_output_limit_fail_closed() {
    const EXPENSIVE: &str = "SELECT CONVERT(bigint, CHECKSUM(NEWID())) AS value FROM sys.all_objects AS a CROSS JOIN sys.all_objects AS b CROSS JOIN sys.all_objects AS c";

    let request = execution_request(
        "live-mssql-variant",
        "SELECT CAST(1 AS sql_variant) AS unsupported",
        10,
        10,
        MAX_BATCH_BYTES,
        Duration::from_secs(20),
        None,
    );
    let error = execute_live(request, CancellationToken::new())
        .await
        .expect_err("sql_variant must fail");
    assert_eq!(error.class(), ErrorClass::Conversion);

    let request = execution_request(
        "live-mssql-output-limit",
        "SELECT CAST(N'bounded-output' AS nvarchar(100)) AS value",
        10,
        10,
        128,
        Duration::from_secs(20),
        None,
    );
    let error = execute_live(request, CancellationToken::new())
        .await
        .expect_err("tiny IPC limit must fail");
    assert_eq!(error.code(), "DBX-RS-MS-LIMIT-0020");

    let request = execution_request(
        "live-mssql-timeout",
        EXPENSIVE,
        100_000,
        256,
        MAX_BATCH_BYTES,
        Duration::from_millis(1),
        None,
    );
    let error = execute_live(request, CancellationToken::new())
        .await
        .expect_err("short timeout must fail");
    assert_eq!(error.class(), ErrorClass::Timeout);

    let cancellation = CancellationToken::new();
    let cancel_after_start = cancellation.clone();
    let request = execution_request(
        "live-mssql-cancel",
        EXPENSIVE,
        100_000,
        256,
        MAX_BATCH_BYTES,
        Duration::from_secs(20),
        None,
    );
    let cancel = async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        cancel_after_start.cancel();
    };
    let execute = execute_live(request, cancellation);
    let (result, ()) = tokio::join!(execute, cancel);
    let error = result.expect_err("cancelled query must fail");
    assert_eq!(error.class(), ErrorClass::Cancelled);
}
