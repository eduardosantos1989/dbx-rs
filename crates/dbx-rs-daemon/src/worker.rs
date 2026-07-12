use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dbx_rs_connector_sdk::{CollectionResult, ConnectorError};
use dbx_rs_native_connectors::{JsonCollectionRequest, NativeConnectorProvider};
use dbx_rs_secure_store::{SecretStore, SecureStoreError};
use dbx_rs_spool::{
    BatchId, Fingerprint, InputKey, ReadySegment, SegmentHeader, SegmentWriter, Spool,
};
use dbx_rs_telemetry::{NdjsonTelemetry, OperationLimits, OperationMetrics};
use ring::digest::{Context, SHA256};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::error::DaemonError;
use crate::hec::{EventMetadata, HecClient};
use crate::identity::{generate_uuid, generate_uuid_bytes};
use crate::operational::OperationTracker;
use crate::prepared::PreparedInput;

const ROW_CHANNEL_CAPACITY: usize = 64;
const EVENT_ID_DOMAIN: &[u8] = b"dbx-rs/hec-event-id/v1\0";

#[derive(Clone, Copy)]
pub struct DeliveryLimits {
    pub max_events: usize,
    pub max_bytes: u64,
}

pub type ReplayFences = BTreeMap<InputKey, Fingerprint>;

pub enum WorkerError {
    Daemon(DaemonError),
    Connector(ConnectorError),
}

#[derive(Clone)]
pub struct WorkerServices {
    pub spool: Spool,
    pub hec: HecClient,
    pub connectors: Arc<NativeConnectorProvider>,
    pub secrets: Arc<SecretStore>,
    pub telemetry: NdjsonTelemetry,
}

impl From<DaemonError> for WorkerError {
    fn from(error: DaemonError) -> Self {
        Self::Daemon(error)
    }
}

impl From<SecureStoreError> for WorkerError {
    fn from(error: SecureStoreError) -> Self {
        Self::Daemon(error.into())
    }
}

pub async fn run_input(
    input: PreparedInput,
    configuration_generation: u64,
    services: WorkerServices,
    cancellation: CancellationToken,
) -> Result<(), WorkerError> {
    let request_id = generate_uuid()?;
    let tls_mode = input.connection.tls_mode.to_string();
    let tracker = OperationTracker::start(
        &services.telemetry,
        &input.connector,
        "collect_spool",
        &request_id,
        &tls_mode,
        Some(&input.name),
        OperationLimits::default()
            .with_max_rows(input.limits.max_rows)
            .with_max_bytes(input.limits.max_bytes)
            .with_connect_timeout(input.connection.connect_timeout)
            .with_operation_timeout(input.limits.query_timeout),
    )?;
    let result = run_input_inner(
        &input,
        configuration_generation,
        &services,
        &request_id,
        cancellation,
    )
    .await;
    match result {
        Ok(collection) => {
            tracker
                .succeeded(OperationMetrics::collection(
                    collection.rows_read,
                    collection.bytes_read,
                    false,
                ))
                .map_err(WorkerError::Daemon)?;
            Ok(())
        }
        Err(WorkerError::Daemon(error)) => {
            tracker.failed_daemon(&error);
            Err(WorkerError::Daemon(error))
        }
        Err(WorkerError::Connector(error)) => {
            tracker.failed_connector(&error);
            Err(WorkerError::Connector(error))
        }
    }
}

async fn run_input_inner(
    input: &PreparedInput,
    configuration_generation: u64,
    services: &WorkerServices,
    request_id: &str,
    cancellation: CancellationToken,
) -> Result<CollectionResult, WorkerError> {
    let created_epoch_millis = epoch_millis()?;
    let input_key = InputKey::new(input.input_id.into_bytes());
    let batch_id = BatchId::new(generate_uuid_bytes()?);
    let header = SegmentHeader {
        input_key,
        configuration_fingerprint: Fingerprint::new(input.revision_fingerprint.into_bytes()),
        configuration_generation,
        batch_id,
        batch_sequence: created_epoch_millis,
        segment_sequence: 1,
        created_epoch_millis,
    };
    let writer = services
        .spool
        .begin_segment(header)
        .map_err(DaemonError::from)?;
    let secret = services.secrets.resolve(&input.secret_ref)?;
    let request = JsonCollectionRequest {
        request_id: request_id.to_owned(),
        connection: input.connection.clone(),
        query: input.query.clone(),
        max_rows: input.limits.max_rows,
        max_bytes: input.limits.max_bytes,
        timeout: input.limits.query_timeout,
        cursor: None,
    };
    let metadata = EventMetadata {
        index: input.output.index.clone(),
        sourcetype: input.output.sourcetype.clone(),
        source: input.output.source.clone(),
    };
    let (line_tx, line_rx) = mpsc::channel(ROW_CHANNEL_CAPACITY);
    let spooling = spool_rows(
        line_rx,
        writer,
        services.hec.clone(),
        metadata,
        input_key,
        batch_id,
    );
    let collection =
        services
            .connectors
            .collect_json_lines(request, &secret, line_tx, cancellation);
    let (collection, spooled) = tokio::join!(collection, spooling);
    let (collection, _ready) = finalize_spooled_collection(collection, spooled)?;
    Ok(collection)
}

fn finalize_spooled_collection(
    collection: Result<CollectionResult, ConnectorError>,
    spooled: Result<(SegmentWriter, u64), WorkerError>,
) -> Result<(CollectionResult, ReadySegment), WorkerError> {
    let (writer, spooled_rows) = spooled?;
    let collection = match collection {
        Ok(collection) => collection,
        Err(error) => {
            let _ignored = writer.abort();
            return Err(WorkerError::Connector(error));
        }
    };
    if collection.rows_read != spooled_rows {
        let _ignored = writer.abort();
        return Err(accounting_error().into());
    }
    let ready = writer.seal().map_err(DaemonError::from)?;
    if ready.summary().event_count != collection.rows_read {
        return Err(accounting_error().into());
    }
    Ok((collection, ready))
}

async fn spool_rows(
    mut line_rx: mpsc::Receiver<Vec<u8>>,
    mut writer: SegmentWriter,
    hec: HecClient,
    metadata: EventMetadata,
    input_key: InputKey,
    batch_id: BatchId,
) -> Result<(SegmentWriter, u64), WorkerError> {
    let mut rows = 0_u64;
    while let Some(line) = line_rx.recv().await {
        let ordinal = rows.checked_add(1).ok_or_else(accounting_error)?;
        let event_id = deterministic_event_id(input_key, batch_id, ordinal);
        let event = hec.encode_event(line, &metadata, &event_id)?;
        writer.append_event(&event).map_err(DaemonError::from)?;
        rows = ordinal;
    }
    Ok((writer, rows))
}

fn deterministic_event_id(input_key: InputKey, batch_id: BatchId, ordinal: u64) -> String {
    let mut context = Context::new(&SHA256);
    context.update(EVENT_ID_DOMAIN);
    context.update(&input_key.into_bytes());
    context.update(&batch_id.into_bytes());
    context.update(&ordinal.to_be_bytes());
    encode_lower_hex(context.finish().as_ref())
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

pub async fn drain_ready_segments(
    spool: Spool,
    hec: Option<HecClient>,
    limits: DeliveryLimits,
    replay_fences: ReplayFences,
) -> Result<u64, DaemonError> {
    tokio::task::spawn_blocking(move || {
        drain_ready_segments_sync(&spool, hec.as_ref(), limits, &replay_fences)
    })
    .await
    .map_err(|_| delivery_task_error())?
}

fn drain_ready_segments_sync(
    spool: &Spool,
    hec: Option<&HecClient>,
    limits: DeliveryLimits,
    replay_fences: &ReplayFences,
) -> Result<u64, DaemonError> {
    let delivered = spool.list_delivered()?;
    let ready = spool.list_ready()?;
    validate_replay_fences(&ready, replay_fences)?;

    for delivered in delivered {
        spool.compact_delivered(&delivered)?;
    }
    if ready.is_empty() {
        return Ok(0);
    }
    let hec = hec.ok_or_else(delivery_unavailable)?;
    let mut delivered_rows = 0_u64;
    for ready in ready {
        delivered_rows = delivered_rows
            .checked_add(deliver_ready_segment_sync(spool, &ready, hec, limits)?)
            .ok_or_else(accounting_error)?;
    }
    Ok(delivered_rows)
}

fn validate_replay_fences(
    ready: &[ReadySegment],
    replay_fences: &ReplayFences,
) -> Result<(), DaemonError> {
    for segment in ready {
        let header = segment.header();
        let Some(active_fingerprint) = replay_fences.get(&header.input_key) else {
            return Err(replay_input_missing());
        };
        if *active_fingerprint != header.configuration_fingerprint {
            return Err(replay_fingerprint_mismatch());
        }
    }
    Ok(())
}

fn deliver_ready_segment_sync(
    spool: &Spool,
    ready: &ReadySegment,
    hec: &HecClient,
    limits: DeliveryLimits,
) -> Result<u64, DaemonError> {
    let mut batch = Vec::new();
    let mut batch_events = 0_usize;
    let mut delivered_rows = 0_u64;
    for event in spool.reader(ready)? {
        let event = event?;
        if event.len() as u64 > limits.max_bytes {
            return Err(DaemonError::new(
                "DBX-RS-WORKER-0005",
                "configuration",
                "hec_delivery",
                "spooled event exceeds the configured HEC batch limit",
                false,
                true,
            ));
        }
        let separator_bytes = usize::from(!batch.is_empty());
        let next_bytes = batch
            .len()
            .saturating_add(separator_bytes)
            .saturating_add(event.len());
        if batch_events == limits.max_events || next_bytes as u64 > limits.max_bytes {
            hec.send_batch(&batch)?;
            delivered_rows = delivered_rows
                .checked_add(batch_events as u64)
                .ok_or_else(accounting_error)?;
            batch.clear();
            batch_events = 0;
        }
        if !batch.is_empty() {
            batch.push(b'\n');
        }
        batch.extend_from_slice(&event);
        batch_events += 1;
    }
    if !batch.is_empty() {
        hec.send_batch(&batch)?;
        delivered_rows = delivered_rows
            .checked_add(batch_events as u64)
            .ok_or_else(accounting_error)?;
    }
    if delivered_rows != ready.summary().event_count {
        return Err(accounting_error());
    }
    let delivered = spool.mark_delivered(ready)?;
    spool.compact_delivered(&delivered)?;
    Ok(delivered_rows)
}

fn epoch_millis() -> Result<u64, DaemonError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
        DaemonError::new(
            "DBX-RS-WORKER-0006",
            "internal",
            "clock",
            "system clock is before the Unix epoch",
            false,
            false,
        )
    })?;
    u64::try_from(duration.as_millis()).map_err(|_| {
        DaemonError::new(
            "DBX-RS-WORKER-0007",
            "internal",
            "clock",
            "epoch timestamp cannot be represented",
            false,
            false,
        )
    })
}

const fn accounting_error() -> DaemonError {
    DaemonError::new(
        "DBX-RS-WORKER-0003",
        "internal",
        "spool_accounting",
        "collection and durable spool accounting did not match",
        true,
        false,
    )
}

const fn delivery_task_error() -> DaemonError {
    DaemonError::new(
        "DBX-RS-WORKER-0004",
        "internal",
        "hec_delivery",
        "durable HEC delivery task failed",
        true,
        false,
    )
}

const fn replay_input_missing() -> DaemonError {
    DaemonError::new(
        "DBX-RS-WORKER-0008",
        "configuration",
        "spool_replay_fence",
        "spooled data has no active input configuration",
        false,
        true,
    )
}

const fn replay_fingerprint_mismatch() -> DaemonError {
    DaemonError::new(
        "DBX-RS-WORKER-0009",
        "configuration",
        "spool_replay_fence",
        "spooled data belongs to a different input configuration revision",
        false,
        true,
    )
}

const fn delivery_unavailable() -> DaemonError {
    DaemonError::new(
        "DBX-RS-WORKER-0010",
        "configuration",
        "spool_replay",
        "spooled data cannot be delivered while HEC output is disabled",
        false,
        true,
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use dbx_rs_config::{
        HecConfig, HecInputManagement, HecState, IndexerAcknowledgment, TlsVerification,
    };
    use dbx_rs_spool::{SpoolKey, SpoolLimits};

    use super::*;
    use crate::identity::{HecToken, ensure_hec_certificate};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "dbx-rs-worker-spool-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).expect("test root must be created");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.0);
        }
    }

    fn open_spool(root: &TestDirectory) -> Spool {
        let key = SpoolKey::load_or_create(&root.0.join("durable/spool.key"))
            .expect("spool key must open");
        let limits = SpoolLimits::new(4_096, 8_192, 16_384).expect("limits must work");
        Spool::open(&root.0.join("spool"), key, limits).expect("spool must open")
    }

    fn header() -> SegmentHeader {
        SegmentHeader {
            input_key: InputKey::new([0x11; 32]),
            configuration_fingerprint: Fingerprint::new([0x22; 32]),
            configuration_generation: 1,
            batch_id: BatchId::new([0x33; 16]),
            batch_sequence: 1,
            segment_sequence: 1,
            created_epoch_millis: 1,
        }
    }

    fn collection(rows: u64, bytes: u64) -> CollectionResult {
        CollectionResult {
            request_id: "request-1".into(),
            rows_read: rows,
            bytes_read: bytes,
            truncated: false,
            checkpoint_candidate: None,
            scan_resume: None,
        }
    }

    fn hec(root: &TestDirectory) -> HecClient {
        let token = HecToken::load_or_create(&root.0.join("identity/hec.token"))
            .expect("HEC token must open");
        let server = root.0.join("identity/hec-server.pem");
        let ca = root.0.join("identity/hec-ca.pem");
        ensure_hec_certificate(&server, &ca).expect("HEC certificate must open");
        let config = HecConfig {
            state: HecState::Enabled,
            input_management: HecInputManagement::Managed,
            url: "https://localhost:8088/services/collector/event".into(),
            input_name: "dbx_rs".into(),
            listen_port: 8088,
            accept_from: "127.0.0.1".into(),
            tls_verification: TlsVerification::Full,
            timeout: Duration::from_secs(1),
            batch_max_events: 10,
            batch_max_bytes: 4_096,
            max_event_bytes: 2_048,
            index: "test".into(),
            sourcetype: "test".into(),
            source: "test".into(),
            acknowledgment: IndexerAcknowledgment::Enabled,
        };
        HecClient::new(&config, &token, &ca).expect("HEC client must initialize")
    }

    #[test]
    fn epoch_batch_sequence_is_representable() {
        assert!(epoch_millis().expect("current epoch must work") > 0);
    }

    #[test]
    fn event_identity_is_stable_and_row_scoped() {
        let input = InputKey::new([0x11; 32]);
        let batch = BatchId::new([0x22; 16]);

        let first = deterministic_event_id(input, batch, 1);

        assert_eq!(first, deterministic_event_id(input, batch, 1));
        assert_ne!(first, deterministic_event_id(input, batch, 2));
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn collection_failure_aborts_without_publishing_ready_data() {
        let root = TestDirectory::new();
        let spool = open_spool(&root);
        let writer = spool.begin_segment(header()).expect("writer must begin");

        let result = finalize_spooled_collection(
            Err(ConnectorError::cancelled("TEST-CANCELLED")),
            Ok((writer, 0)),
        );

        assert!(matches!(result, Err(WorkerError::Connector(_))));
        assert!(spool.list_ready().expect("inventory must work").is_empty());
        assert_eq!(spool.usage().stored_bytes(), 0);
        assert_eq!(spool.usage().reserved_bytes(), 0);
    }

    #[test]
    fn successful_collection_stops_at_a_ready_segment() {
        let root = TestDirectory::new();
        let spool = open_spool(&root);
        let mut writer = spool.begin_segment(header()).expect("writer must begin");
        writer
            .append_event(br#"{"event":{"value":1}}"#)
            .expect("event must append");

        let Ok((_collection, ready)) =
            finalize_spooled_collection(Ok(collection(1, 11)), Ok((writer, 1)))
        else {
            panic!("successful collection must seal");
        };
        drop(ready);

        assert_eq!(spool.list_ready().expect("ready inventory").len(), 1);
        assert!(
            spool
                .list_delivered()
                .expect("delivered inventory")
                .is_empty()
        );
    }

    #[test]
    fn replay_requires_an_exact_active_revision_fence() {
        let root = TestDirectory::new();
        let spool = open_spool(&root);
        let expected = header();
        let mut writer = spool.begin_segment(expected).expect("writer must begin");
        writer
            .append_event(br#"{"event":{"value":1}}"#)
            .expect("event must append");
        writer.seal().expect("segment must seal");
        let ready = spool.list_ready().expect("ready inventory");

        let missing = validate_replay_fences(&ready, &ReplayFences::new())
            .expect_err("missing active input must block replay");
        assert_eq!(missing.code(), "DBX-RS-WORKER-0008");

        let mismatched = ReplayFences::from([(expected.input_key, Fingerprint::new([0x44; 32]))]);
        let mismatch = validate_replay_fences(&ready, &mismatched)
            .expect_err("changed input revision must block replay");
        assert_eq!(mismatch.code(), "DBX-RS-WORKER-0009");

        let matching =
            ReplayFences::from([(expected.input_key, expected.configuration_fingerprint)]);
        validate_replay_fences(&ready, &matching).expect("exact fence must permit replay");
        let unavailable = drain_ready_segments_sync(
            &spool,
            None,
            DeliveryLimits {
                max_events: 10,
                max_bytes: 4_096,
            },
            &matching,
        )
        .expect_err("disabled HEC must retain ready data");
        assert_eq!(unavailable.code(), "DBX-RS-WORKER-0010");
        assert_eq!(spool.list_ready().expect("ready must remain").len(), 1);
    }

    #[test]
    fn delivery_failure_retains_a_restart_replayable_ready_segment() {
        let root = TestDirectory::new();
        let spool = open_spool(&root);
        let mut writer = spool.begin_segment(header()).expect("writer must begin");
        writer
            .append_event(br#"{"event":{"value":1}}"#)
            .expect("event must append");
        let result = finalize_spooled_collection(Ok(collection(1, 11)), Ok((writer, 1)));
        let Ok((_collection, ready)) = result else {
            panic!("successful collection must seal");
        };

        let error = deliver_ready_segment_sync(
            &spool,
            &ready,
            &hec(&root),
            DeliveryLimits {
                max_events: 1,
                max_bytes: 1,
            },
        )
        .expect_err("bounded delivery failure must retain the segment");

        assert_eq!(error.code(), "DBX-RS-WORKER-0005");
        assert_eq!(spool.list_ready().expect("ready must remain").len(), 1);
        drop(ready);
        drop(spool);

        let reopened = open_spool(&root);
        assert_eq!(
            reopened
                .list_ready()
                .expect("restart inventory must authenticate")
                .len(),
            1
        );
        assert!(
            reopened
                .list_delivered()
                .expect("delivered inventory must work")
                .is_empty()
        );
    }
}
