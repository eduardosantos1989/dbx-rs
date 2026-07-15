use std::{env, fs, io::Cursor, sync::Arc, time::Duration};

use arrow_array::{Array, Int64Array, RecordBatch, TimestampMicrosecondArray};
use arrow_ipc::reader::StreamReader;
use dbx_rs_connector_mysql::{MariaDbConnector, MySqlConnector};
use dbx_rs_connector_sdk::{
    ArrowIpcBatch, ConnectionConfig, Connector, ConnectorError, CursorNullPolicy, ErrorClass,
    ExecuteRequest, ExecutionLimits, ExecutionResult, FieldType, ProbeRequest, QueryText,
    ResolvedSecret, TimestampIdCursor, TimestampIdCursorRequest, TimestampIdCursorSpec, TlsMode,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const MAX_BATCH_BYTES: u64 = 1024 * 1024;
const MAX_TOTAL_IPC_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Copy)]
enum Family {
    MySql,
    MariaDb,
}

impl Family {
    const fn connector_id(self) -> &'static str {
        match self {
            Self::MySql => "mysql",
            Self::MariaDb => "mariadb",
        }
    }

    const fn product_name(self) -> &'static str {
        match self {
            Self::MySql => "MySQL",
            Self::MariaDb => "MariaDB",
        }
    }

    const fn environment_prefix(self) -> &'static str {
        match self {
            Self::MySql => "DBX_RS_LIVE_MYSQL",
            Self::MariaDb => "DBX_RS_LIVE_MARIADB",
        }
    }

    const fn other(self) -> Self {
        match self {
            Self::MySql => Self::MariaDb,
            Self::MariaDb => Self::MySql,
        }
    }

    fn connector(self) -> Arc<dyn Connector> {
        match self {
            Self::MySql => Arc::new(MySqlConnector),
            Self::MariaDb => Arc::new(MariaDbConnector),
        }
    }
}

fn environment_name(family: Family, suffix: &str) -> String {
    format!("{}_{suffix}", family.environment_prefix())
}

fn required(family: Family, suffix: &str) -> String {
    let name = environment_name(family, suffix);
    env::var(&name).unwrap_or_else(|_| panic!("{name} is required for the ignored live test"))
}

fn live_connection(family: Family) -> ConnectionConfig {
    let tls_mode_name = environment_name(family, "TLS_MODE");
    let tls_mode = env::var(&tls_mode_name)
        .unwrap_or_else(|_| "verify-full".into())
        .parse::<TlsMode>()
        .unwrap_or_else(|_| panic!("{tls_mode_name} must be a supported TLS mode"));
    let ca_name = environment_name(family, "CA_FILE");
    let tls_ca_pem = env::var(&ca_name)
        .ok()
        .map(|path| fs::read(path).unwrap_or_else(|_| panic!("{ca_name} must be readable")));
    let port_name = environment_name(family, "PORT");

    ConnectionConfig {
        connector_id: family.connector_id().into(),
        host: required(family, "HOST"),
        port: env::var(&port_name)
            .map_or(Ok(3306), |port| port.parse::<u16>())
            .unwrap_or_else(|_| panic!("{port_name} must be a valid port")),
        database: required(family, "DATABASE"),
        username: required(family, "USERNAME"),
        tls_mode,
        tls_server_name: env::var(environment_name(family, "TLS_SERVER_NAME")).ok(),
        tls_ca_pem,
        connect_timeout: Duration::from_secs(10),
        probe_timeout: Duration::from_secs(10),
    }
}

fn live_secret(family: Family) -> ResolvedSecret {
    ResolvedSecret::new(required(family, "PASSWORD").into_bytes())
}

fn execution_request(
    family: Family,
    request_id: &str,
    query: String,
    max_rows: u64,
    max_batch_rows: u32,
    timeout: Duration,
    cursor: Option<TimestampIdCursorRequest>,
) -> ExecuteRequest {
    ExecuteRequest {
        request_id: request_id.into(),
        connection: live_connection(family),
        query: QueryText::new(query),
        limits: ExecutionLimits {
            max_rows,
            max_batch_rows,
            max_batch_bytes: MAX_BATCH_BYTES,
            max_total_ipc_bytes: MAX_TOTAL_IPC_BYTES,
            timeout,
        },
        expected_schema: None,
        cursor,
    }
}

async fn execute_live(
    family: Family,
    request: ExecuteRequest,
    cancellation: CancellationToken,
) -> Result<(ExecutionResult, Vec<ArrowIpcBatch>), ConnectorError> {
    let connector = family.connector();
    let secret = live_secret(family);
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
                .expect("live MySQL-family IPC stream must decode");
            let decoded = reader
                .next()
                .expect("live MySQL-family IPC stream must contain one batch")
                .expect("live MySQL-family IPC batch must decode");
            assert!(
                reader.next().is_none(),
                "IPC envelope must contain one batch"
            );
            decoded
        })
        .collect()
}

fn cursor_rows(
    batches: &[ArrowIpcBatch],
    timestamp_field: &str,
    id_field: &str,
) -> Vec<TimestampIdCursor> {
    let decoded = decode_batches(batches);
    let schema = decoded
        .first()
        .expect("cursor execution must return at least one batch")
        .schema();
    let timestamp_index = schema
        .index_of(timestamp_field)
        .expect("cursor timestamp field must exist");
    let id_index = schema
        .index_of(id_field)
        .expect("cursor ID field must exist");
    let mut cursors = Vec::new();

    for batch in decoded {
        let timestamps = batch
            .column(timestamp_index)
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .expect("cursor timestamp must use microsecond Arrow storage");
        let identifiers = batch
            .column(id_index)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("cursor ID must use signed 64-bit Arrow storage");
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

async fn probe_product_and_failure_boundaries(family: Family) {
    let connection = live_connection(family);
    let secret = live_secret(family);
    let connector = family.connector();
    let report = connector
        .probe(
            ProbeRequest {
                request_id: format!("live-{}-probe", family.connector_id()),
                connection: connection.clone(),
            },
            &secret,
            CancellationToken::new(),
        )
        .await
        .expect("live MySQL-family probe must succeed");

    assert_eq!(report.connector_id, family.connector_id());
    assert_eq!(report.database_product, family.product_name());
    let expected_version = required(family, "VERSION_PREFIX");
    assert!(report.server_version.starts_with(&expected_version));

    let other = family.other();
    let mut mismatch = connection.clone();
    mismatch.connector_id = other.connector_id().into();
    let mismatch_error = other
        .connector()
        .probe(
            ProbeRequest {
                request_id: format!("live-{}-product-mismatch", family.connector_id()),
                connection: mismatch,
            },
            &secret,
            CancellationToken::new(),
        )
        .await
        .expect_err("cross-product connector selection must fail");
    assert_eq!(mismatch_error.code(), "DBX-RS-MY-PRODUCT-0002");
    assert_eq!(mismatch_error.class(), ErrorClass::Configuration);

    let mut invalid_password = secret.expose_secret().to_vec();
    invalid_password.extend_from_slice(b"-intentionally-invalid");
    let invalid_secret = ResolvedSecret::new(invalid_password);
    let authentication_error = connector
        .probe(
            ProbeRequest {
                request_id: format!("live-{}-invalid-auth", family.connector_id()),
                connection,
            },
            &invalid_secret,
            CancellationToken::new(),
        )
        .await
        .expect_err("invalid MySQL-family credentials must fail");
    assert_eq!(authentication_error.class(), ErrorClass::Authentication);
    assert!(!format!("{authentication_error:?}").contains(&required(family, "PASSWORD")));
}

async fn verified_tls_rejects_wrong_name(family: Family) {
    let mut connection = live_connection(family);
    assert_eq!(
        connection.tls_mode,
        TlsMode::VerifyFull,
        "wrong-name live gate requires verified-full TLS"
    );
    connection.tls_server_name = Some("dbx-rs-wrong-name.invalid".into());
    let error = family
        .connector()
        .probe(
            ProbeRequest {
                request_id: format!("live-{}-wrong-tls-name", family.connector_id()),
                connection,
            },
            &live_secret(family),
            CancellationToken::new(),
        )
        .await
        .expect_err("wrong TLS server name must fail");

    assert_eq!(error.class(), ErrorClass::Tls);
    assert_eq!(error.code(), "DBX-RS-MY-TLS-0001");
}

async fn exact_types_and_multi_batch_streaming(family: Family) {
    // The configured query must expose one or more rows with these aliases and native declarations.
    let type_query = required(family, "TYPE_QUERY");
    let request = execution_request(
        family,
        &format!("live-{}-exact-types", family.connector_id()),
        type_query,
        100,
        16,
        Duration::from_secs(20),
        None,
    );
    let (result, batches) = execute_live(family, request, CancellationToken::new())
        .await
        .expect("live exact-type query must succeed");
    let mut expected = vec![
        ("bit_value", FieldType::Boolean),
        ("signed_tiny", FieldType::Int8),
        ("signed_small", FieldType::Int16),
        ("signed_int", FieldType::Int32),
        ("signed_big", FieldType::Int64),
        ("unsigned_int", FieldType::UInt32),
        (
            "unsigned_big",
            FieldType::Decimal128 {
                precision: 20,
                scale: 0,
            },
        ),
        ("float_value", FieldType::Float32),
        ("double_value", FieldType::Float64),
        (
            "exact_decimal",
            FieldType::Decimal128 {
                precision: 38,
                scale: 6,
            },
        ),
        ("date_value", FieldType::Date32),
        ("datetime_value", FieldType::TimestampMicrosecond),
        ("timestamp_value", FieldType::TimestampMicrosecondUtc),
        ("text_value", FieldType::Utf8),
        ("binary_value", FieldType::Binary),
    ];
    expected.push((
        "json_value",
        match family {
            Family::MySql => FieldType::Json,
            Family::MariaDb => FieldType::Utf8,
        },
    ));

    assert!(result.rows_read > 0);
    assert_eq!(result.schema.fields.len(), expected.len());
    for (field, (name, field_type)) in result.schema.fields.iter().zip(expected) {
        assert_eq!(field.name, name);
        assert_eq!(field.field_type, field_type);
    }
    let decoded_rows = decode_batches(&batches)
        .iter()
        .map(RecordBatch::num_rows)
        .sum::<usize>();
    assert_eq!(decoded_rows as u64, result.rows_read);

    let sequence_query = "WITH RECURSIVE dbx_sequence(n) AS (SELECT CAST(1 AS SIGNED) UNION ALL SELECT n + 1 FROM dbx_sequence WHERE n < 300) SELECT n FROM dbx_sequence";
    let request = execution_request(
        family,
        &format!("live-{}-multi-batch", family.connector_id()),
        sequence_query.into(),
        300,
        64,
        Duration::from_secs(20),
        None,
    );
    let (result, batches) = execute_live(family, request, CancellationToken::new())
        .await
        .expect("live multi-batch query must succeed");

    assert_eq!(result.rows_read, 300);
    assert!(!result.truncated);
    assert!(batches.len() >= 5);
}

async fn rising_equal_timestamp_and_resume(family: Family) {
    let query = required(family, "RISING_QUERY");
    let spec = TimestampIdCursorSpec {
        timestamp_field: "updated_at".into(),
        id_field: "id".into(),
        overlap: Duration::ZERO,
        null_policy: CursorNullPolicy::Reject,
    };
    let first_request = TimestampIdCursorRequest {
        spec: spec.clone(),
        committed: None,
        resume_after: None,
    };
    let request = execution_request(
        family,
        &format!("live-{}-rising-first", family.connector_id()),
        query.clone(),
        2,
        1,
        Duration::from_secs(20),
        Some(first_request),
    );
    let (first_result, first_batches) = execute_live(family, request, CancellationToken::new())
        .await
        .expect("first live rising page must succeed");
    let first = cursor_rows(&first_batches, "updated_at", "id");

    assert_eq!(first.len(), 2);
    assert!(first_result.truncated);
    assert_eq!(
        first[0].timestamp_epoch_micros, first[1].timestamp_epoch_micros,
        "live fixture must start with an equal-timestamp pair"
    );
    assert!(first[1].id > first[0].id);

    let resume = first[1];
    let request = execution_request(
        family,
        &format!("live-{}-rising-resume", family.connector_id()),
        query,
        100,
        16,
        Duration::from_secs(20),
        Some(TimestampIdCursorRequest {
            spec,
            committed: None,
            resume_after: Some(resume),
        }),
    );
    let (_result, resumed_batches) = execute_live(family, request, CancellationToken::new())
        .await
        .expect("resumed live rising page must succeed");
    let resumed = cursor_rows(&resumed_batches, "updated_at", "id");

    assert!(!resumed.is_empty(), "live fixture must contain a third row");
    assert!(
        resumed
            .iter()
            .all(|cursor| cursor.position_cmp(&resume).is_gt())
    );

    let overlap_spec = TimestampIdCursorSpec {
        timestamp_field: "updated_at".into(),
        id_field: "id".into(),
        overlap: Duration::from_secs(1),
        null_policy: CursorNullPolicy::Reject,
    };
    let request = execution_request(
        family,
        &format!("live-{}-rising-overlap", family.connector_id()),
        required(family, "RISING_QUERY"),
        100,
        16,
        Duration::from_secs(20),
        Some(TimestampIdCursorRequest {
            spec: overlap_spec,
            committed: Some(resume),
            resume_after: None,
        }),
    );
    let (_result, overlap_batches) = execute_live(family, request, CancellationToken::new())
        .await
        .expect("live rising overlap page must succeed");
    let overlap = cursor_rows(&overlap_batches, "updated_at", "id");

    assert!(overlap.contains(&first[0]));
    assert!(overlap.contains(&resume));
}

async fn unsupported_type_and_cancellation(family: Family) {
    let request = execution_request(
        family,
        &format!("live-{}-unsupported-time", family.connector_id()),
        "SELECT CAST('01:02:03' AS TIME) AS unsupported_time".into(),
        1,
        1,
        Duration::from_secs(20),
        None,
    );
    let error = execute_live(family, request, CancellationToken::new())
        .await
        .expect_err("TIME output must fail closed");
    assert_eq!(error.class(), ErrorClass::Conversion);
    assert_eq!(error.code(), "DBX-RS-MY-CONVERT-0020");

    let cancellation = CancellationToken::new();
    let operation_cancellation = cancellation.clone();
    let request = execution_request(
        family,
        &format!("live-{}-cancellation", family.connector_id()),
        "SELECT SLEEP(30) AS slept".into(),
        1,
        1,
        Duration::from_secs(40),
        None,
    );
    let operation =
        tokio::spawn(async move { execute_live(family, request, operation_cancellation).await });
    tokio::time::sleep(Duration::from_millis(500)).await;
    cancellation.cancel();
    let error = tokio::time::timeout(Duration::from_secs(5), operation)
        .await
        .expect("cancelled live operation must clean up promptly")
        .expect("cancelled live operation task must not panic")
        .expect_err("cancelled live operation must return an error");

    assert_eq!(error.class(), ErrorClass::Cancelled);
}

async fn output_limit_and_timeout_fail_closed(family: Family) {
    let mut request = execution_request(
        family,
        &format!("live-{}-oversized-output", family.connector_id()),
        "SELECT REPEAT('x', 131072) AS oversized_text".into(),
        1,
        1,
        Duration::from_secs(20),
        None,
    );
    request.limits.max_batch_bytes = 100_000;
    let error = execute_live(family, request, CancellationToken::new())
        .await
        .expect_err("oversized live output must fail closed");
    assert_eq!(error.class(), ErrorClass::Query);
    assert_eq!(error.code(), "DBX-RS-MY-LIMIT-0020");

    let request = execution_request(
        family,
        &format!("live-{}-timeout", family.connector_id()),
        "SELECT SLEEP(30) AS slept".into(),
        1,
        1,
        Duration::from_millis(200),
        None,
    );
    let error = execute_live(family, request, CancellationToken::new())
        .await
        .expect_err("timed-out live query must fail closed");

    assert_eq!(error.class(), ErrorClass::Timeout);
    assert_eq!(error.code(), "DBX-RS-MY-QUERY-0021");
}

async fn stored_zero_date_fails_closed(family: Family) {
    // The configured fixture query must return at least one native zero DATE/DATETIME value.
    let request = execution_request(
        family,
        &format!("live-{}-zero-date", family.connector_id()),
        required(family, "ZERO_DATE_QUERY"),
        10,
        10,
        Duration::from_secs(20),
        None,
    );
    let error = execute_live(family, request, CancellationToken::new())
        .await
        .expect_err("stored zero date must fail closed");

    assert_eq!(error.class(), ErrorClass::Conversion);
    assert_eq!(error.code(), "DBX-RS-MY-CONVERT-0038");
}

macro_rules! product_live_tests {
    ($module:ident, $family:expr, $reason:literal) => {
        mod $module {
            use super::*;

            #[tokio::test]
            #[ignore = $reason]
            async fn probe_product_and_failure_boundaries_pass() {
                probe_product_and_failure_boundaries($family).await;
            }

            #[tokio::test]
            #[ignore = $reason]
            async fn verified_tls_wrong_name_fails() {
                verified_tls_rejects_wrong_name($family).await;
            }

            #[tokio::test]
            #[ignore = $reason]
            async fn exact_types_and_multi_batch_streaming_pass() {
                exact_types_and_multi_batch_streaming($family).await;
            }

            #[tokio::test]
            #[ignore = $reason]
            async fn rising_equal_timestamp_and_resume_pass() {
                rising_equal_timestamp_and_resume($family).await;
            }

            #[tokio::test]
            #[ignore = $reason]
            async fn unsupported_type_and_cancellation_pass() {
                unsupported_type_and_cancellation($family).await;
            }

            #[tokio::test]
            #[ignore = $reason]
            async fn output_limit_and_timeout_boundaries_pass() {
                output_limit_and_timeout_fail_closed($family).await;
            }

            #[tokio::test]
            #[ignore = $reason]
            async fn stored_zero_date_policy_pass() {
                stored_zero_date_fails_closed($family).await;
            }
        }
    };
}

product_live_tests!(
    mysql,
    Family::MySql,
    "requires an explicitly configured MySQL sandbox"
);
product_live_tests!(
    mariadb,
    Family::MariaDb,
    "requires an explicitly configured MariaDB sandbox"
);
