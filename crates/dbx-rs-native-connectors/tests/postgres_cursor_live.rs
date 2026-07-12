use std::{env, fs, time::Duration};

use dbx_rs_connector_sdk::{
    ConnectionConfig, CursorNullPolicy, QueryText, ResolvedSecret, TimestampIdCursor,
    TimestampIdCursorRequest, TimestampIdCursorSpec, TlsMode,
};
use dbx_rs_native_connectors::{JsonCollectionRequest, NativeConnectorProvider};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

fn required(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} is required for the ignored live test"))
}

fn live_connection() -> ConnectionConfig {
    let tls_mode = env::var("DBX_RS_LIVE_PG_TLS_MODE")
        .unwrap_or_else(|_| "disable".into())
        .parse::<TlsMode>()
        .expect("DBX_RS_LIVE_PG_TLS_MODE must be a supported TLS mode");
    let tls_ca_pem = env::var("DBX_RS_LIVE_PG_CA_FILE")
        .ok()
        .map(|path| fs::read(path).expect("live PostgreSQL CA file must be readable"));

    ConnectionConfig {
        connector_id: "postgres".into(),
        host: required("DBX_RS_LIVE_PG_HOST"),
        port: env::var("DBX_RS_LIVE_PG_PORT")
            .map_or(Ok(5432), |port| port.parse::<u16>())
            .expect("DBX_RS_LIVE_PG_PORT must be a valid port"),
        database: required("DBX_RS_LIVE_PG_DATABASE"),
        username: required("DBX_RS_LIVE_PG_USERNAME"),
        tls_mode,
        tls_server_name: env::var("DBX_RS_LIVE_PG_TLS_SERVER_NAME").ok(),
        tls_ca_pem,
        connect_timeout: Duration::from_secs(10),
        probe_timeout: Duration::from_secs(10),
    }
}

#[tokio::test]
#[ignore = "requires an explicitly configured PostgreSQL sandbox"]
async fn timestamp_id_cursor_does_not_skip_equal_timestamp_rows() {
    let provider = NativeConnectorProvider::new();
    let secret = ResolvedSecret::new(required("DBX_RS_LIVE_PG_PASSWORD").into_bytes());
    let request = JsonCollectionRequest {
        request_id: "live-cursor-equal-timestamp".into(),
        connection: live_connection(),
        query: QueryText::new(
            "SELECT updated_at, id FROM (VALUES \
             ('2024-01-01T00:00:00Z'::timestamptz, 1::bigint), \
             ('2024-01-01T00:00:00Z'::timestamptz, 2::bigint), \
             ('2024-01-01T00:00:00Z'::timestamptz, 3::bigint)) \
             AS source_rows(updated_at, id)",
        ),
        max_rows: 10,
        max_bytes: 16 * 1024,
        timeout: Duration::from_secs(20),
        cursor: Some(TimestampIdCursorRequest {
            spec: TimestampIdCursorSpec {
                timestamp_field: "updated_at".into(),
                id_field: "id".into(),
                overlap: Duration::ZERO,
                null_policy: CursorNullPolicy::Reject,
            },
            committed: Some(TimestampIdCursor::new(1_704_067_200_000_000, 1)),
            resume_after: None,
        }),
    };
    let (line_tx, mut line_rx) = mpsc::channel(4);
    let collect = provider.collect_json_rows(request, &secret, line_tx, CancellationToken::new());
    let receive = async move {
        let mut lines = Vec::new();
        while let Some(line) = line_rx.recv().await {
            lines.push(line);
        }
        lines
    };
    let (result, lines) = tokio::join!(collect, receive);
    let result = result.expect("live cursor collection must succeed");

    assert_eq!(result.rows_read, 2);
    assert_eq!(lines.len(), 2);
    assert!(!result.truncated);
    assert_eq!(
        result.checkpoint_candidate,
        Some(TimestampIdCursor::new(1_704_067_200_000_000, 3))
    );
}

#[tokio::test]
#[ignore = "requires an explicitly configured PostgreSQL sandbox"]
async fn overlap_includes_the_exact_timestamp_and_minimum_identifier_boundary() {
    let provider = NativeConnectorProvider::new();
    let secret = ResolvedSecret::new(required("DBX_RS_LIVE_PG_PASSWORD").into_bytes());
    let committed = TimestampIdCursor::new(1_704_067_201_000_000, 5);
    let request = JsonCollectionRequest {
        request_id: "live-cursor-overlap-boundary".into(),
        connection: live_connection(),
        query: QueryText::new(
            "SELECT updated_at, id FROM (VALUES \
             ('2024-01-01T00:00:00Z'::timestamptz, (-9223372036854775807 - 1)::bigint), \
             ('2024-01-01T00:00:00Z'::timestamptz, 0::bigint), \
             ('2024-01-01T00:00:01Z'::timestamptz, 5::bigint)) \
             AS source_rows(updated_at, id)",
        ),
        max_rows: 10,
        max_bytes: 16 * 1024,
        timeout: Duration::from_secs(20),
        cursor: Some(TimestampIdCursorRequest {
            spec: TimestampIdCursorSpec {
                timestamp_field: "updated_at".into(),
                id_field: "id".into(),
                overlap: Duration::from_secs(1),
                null_policy: CursorNullPolicy::Reject,
            },
            committed: Some(committed),
            resume_after: None,
        }),
    };
    let (line_tx, mut line_rx) = mpsc::channel(4);
    let collect = provider.collect_json_rows(request, &secret, line_tx, CancellationToken::new());
    let receive = async move {
        let mut count = 0_usize;
        while line_rx.recv().await.is_some() {
            count += 1;
        }
        count
    };
    let (result, row_count) = tokio::join!(collect, receive);
    let result = result.expect("live overlap collection must succeed");

    assert_eq!(row_count, 3);
    assert_eq!(result.rows_read, 3);
    assert!(!result.truncated);
    assert_eq!(result.checkpoint_candidate, Some(committed));
}

#[tokio::test]
#[ignore = "requires an explicitly configured PostgreSQL sandbox"]
async fn scan_resume_is_exclusive_and_does_not_reapply_overlap() {
    let provider = NativeConnectorProvider::new();
    let secret = ResolvedSecret::new(required("DBX_RS_LIVE_PG_PASSWORD").into_bytes());
    let committed = TimestampIdCursor::new(1_704_067_201_000_000, 5);
    let resume_after = TimestampIdCursor::new(1_704_067_200_000_000, 0);
    let request = JsonCollectionRequest {
        request_id: "live-cursor-scan-resume".into(),
        connection: live_connection(),
        query: QueryText::new(
            "SELECT updated_at, id FROM (VALUES \
             ('2024-01-01T00:00:00Z'::timestamptz, (-9223372036854775807 - 1)::bigint), \
             ('2024-01-01T00:00:00Z'::timestamptz, 0::bigint), \
             ('2024-01-01T00:00:00Z'::timestamptz, 1::bigint), \
             ('2024-01-01T00:00:01Z'::timestamptz, 5::bigint)) \
             AS source_rows(updated_at, id)",
        ),
        max_rows: 10,
        max_bytes: 16 * 1024,
        timeout: Duration::from_secs(20),
        cursor: Some(TimestampIdCursorRequest {
            spec: TimestampIdCursorSpec {
                timestamp_field: "updated_at".into(),
                id_field: "id".into(),
                overlap: Duration::from_secs(1),
                null_policy: CursorNullPolicy::Reject,
            },
            committed: Some(committed),
            resume_after: Some(resume_after),
        }),
    };
    let (line_tx, mut line_rx) = mpsc::channel(4);
    let collect = provider.collect_json_rows(request, &secret, line_tx, CancellationToken::new());
    let receive = async move {
        let mut lines = Vec::new();
        while let Some(line) = line_rx.recv().await {
            lines.push(line);
        }
        lines
    };
    let (result, lines) = tokio::join!(collect, receive);
    let result = result.expect("live scan continuation must succeed");

    assert_eq!(result.rows_read, 2);
    let ids = lines
        .iter()
        .map(|line| {
            serde_json::from_slice::<serde_json::Value>(line.as_bytes())
                .expect("live row must be JSON")["id"]
                .as_i64()
                .expect("live row ID must be signed 64-bit")
        })
        .collect::<Vec<_>>();
    assert_eq!(ids, [1, 5]);
    assert_eq!(result.checkpoint_candidate, Some(committed));
    assert!(!result.truncated);
}

#[tokio::test]
#[ignore = "requires an explicitly configured PostgreSQL sandbox"]
async fn committed_cursor_rejects_null_rows_instead_of_filtering_them() {
    let provider = NativeConnectorProvider::new();
    let secret = ResolvedSecret::new(required("DBX_RS_LIVE_PG_PASSWORD").into_bytes());
    let request = JsonCollectionRequest {
        request_id: "live-cursor-null-reject".into(),
        connection: live_connection(),
        query: QueryText::new(
            "SELECT updated_at, id FROM (VALUES \
             (NULL::timestamptz, 0::bigint), \
             ('2024-01-01T00:00:00Z'::timestamptz, 2::bigint)) \
             AS source_rows(updated_at, id)",
        ),
        max_rows: 10,
        max_bytes: 16 * 1024,
        timeout: Duration::from_secs(20),
        cursor: Some(TimestampIdCursorRequest {
            spec: TimestampIdCursorSpec {
                timestamp_field: "updated_at".into(),
                id_field: "id".into(),
                overlap: Duration::ZERO,
                null_policy: CursorNullPolicy::Reject,
            },
            committed: Some(TimestampIdCursor::new(1_704_067_200_000_000, 1)),
            resume_after: None,
        }),
    };
    let (line_tx, mut line_rx) = mpsc::channel(4);
    let collect = provider.collect_json_rows(request, &secret, line_tx, CancellationToken::new());
    let receive = async move {
        let mut count = 0_usize;
        while line_rx.recv().await.is_some() {
            count += 1;
        }
        count
    };
    let (result, row_count) = tokio::join!(collect, receive);

    assert!(result.is_err(), "NULL cursor row must fail collection");
    assert_eq!(row_count, 0, "NULLS FIRST must fail before row output");
}

#[tokio::test]
#[ignore = "requires an explicitly configured PostgreSQL sandbox"]
async fn duplicate_tuple_in_truncation_probe_fails_instead_of_being_skipped() {
    let provider = NativeConnectorProvider::new();
    let secret = ResolvedSecret::new(required("DBX_RS_LIVE_PG_PASSWORD").into_bytes());
    let request = JsonCollectionRequest {
        request_id: "live-cursor-duplicate-probe".into(),
        connection: live_connection(),
        query: QueryText::new(
            "SELECT updated_at, id FROM (VALUES \
             ('2024-01-01T00:00:00Z'::timestamptz, 1::bigint), \
             ('2024-01-01T00:00:00Z'::timestamptz, 1::bigint)) \
             AS source_rows(updated_at, id)",
        ),
        max_rows: 1,
        max_bytes: 16 * 1024,
        timeout: Duration::from_secs(20),
        cursor: Some(TimestampIdCursorRequest {
            spec: TimestampIdCursorSpec {
                timestamp_field: "updated_at".into(),
                id_field: "id".into(),
                overlap: Duration::ZERO,
                null_policy: CursorNullPolicy::Reject,
            },
            committed: None,
            resume_after: None,
        }),
    };
    let (line_tx, mut line_rx) = mpsc::channel(2);
    let collect = provider.collect_json_rows(request, &secret, line_tx, CancellationToken::new());
    let receive = async move {
        let mut count = 0_usize;
        while line_rx.recv().await.is_some() {
            count += 1;
        }
        count
    };
    let (result, row_count) = tokio::join!(collect, receive);

    assert!(
        result.is_err(),
        "duplicate truncation probe must fail collection"
    );
    assert!(row_count <= 1, "the probe row must never be emitted");
}
