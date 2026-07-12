use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dbx_rs_checkpoint::AttemptId;
use dbx_rs_connector_sdk::{
    CollectionResult, ConnectorError, TimestampIdCursor, TimestampIdCursorRequest,
    TimestampIdCursorSpec,
};
use dbx_rs_native_connectors::{JsonCollectionRequest, JsonRow, NativeConnectorProvider};
use dbx_rs_secure_store::{SecretStore, SecureStoreError};
use dbx_rs_spool::{
    BatchId, DeliveredSegment, Fingerprint, InputKey, ReadySegment, SegmentHeader, SegmentWriter,
    Spool,
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
use crate::rising_metadata::{RisingRecoveryMetadata, rising_request_fingerprint};

const ROW_CHANNEL_CAPACITY: usize = 64;
const EVENT_ID_DOMAIN: &[u8] = b"dbx-rs/hec-event-id/v1\0";
const RISING_EVENT_ID_DOMAIN: &[u8] = b"dbx-rs/hec-rising-event-id/v1\0";

#[derive(Clone, Copy)]
pub struct DeliveryLimits {
    pub max_events: usize,
    pub max_bytes: u64,
}

pub type ReplayFences = BTreeMap<InputKey, Fingerprint>;

#[derive(Clone)]
pub enum CollectionRun {
    Batch {
        configuration_generation: u64,
    },
    Rising {
        configuration_generation: u64,
        checkpoint_generation: u64,
        attempt_id: AttemptId,
        page: u64,
        cursor: TimestampIdCursorRequest,
    },
}

pub enum WorkerCompletion {
    Batch(CollectionResult),
    RisingSealed(CollectionResult),
    RisingEmpty(CollectionResult),
}

impl WorkerCompletion {
    const fn collection(&self) -> &CollectionResult {
        match self {
            Self::Batch(collection)
            | Self::RisingSealed(collection)
            | Self::RisingEmpty(collection) => collection,
        }
    }
}

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
    run: CollectionRun,
    services: WorkerServices,
    cancellation: CancellationToken,
) -> Result<WorkerCompletion, WorkerError> {
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
    let result = run_input_inner(&input, run, &services, &request_id, cancellation).await;
    match result {
        Ok(completion) => {
            let collection = completion.collection();
            tracker
                .succeeded(OperationMetrics::collection(
                    collection.rows_read,
                    collection.bytes_read,
                    false,
                ))
                .map_err(WorkerError::Daemon)?;
            Ok(completion)
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
    run: CollectionRun,
    services: &WorkerServices,
    request_id: &str,
    cancellation: CancellationToken,
) -> Result<WorkerCompletion, WorkerError> {
    validate_collection_run(
        input.rising.as_ref().map(|rising| &rising.cursor_spec),
        &run,
    )?;
    let created_epoch_millis = epoch_millis()?;
    let input_key = InputKey::new(input.input_id.into_bytes());
    let (configuration_generation, batch_id, batch_sequence, segment_sequence, cursor) = match run {
        CollectionRun::Batch {
            configuration_generation,
        } => (
            configuration_generation,
            BatchId::new(generate_uuid_bytes()?),
            created_epoch_millis,
            1,
            None,
        ),
        CollectionRun::Rising {
            configuration_generation,
            checkpoint_generation,
            attempt_id,
            page,
            cursor,
        } => (
            configuration_generation,
            BatchId::new(attempt_id.into_bytes()),
            checkpoint_generation,
            page,
            Some(cursor),
        ),
    };
    let header = SegmentHeader {
        input_key,
        configuration_fingerprint: Fingerprint::new(input.revision_fingerprint.into_bytes()),
        configuration_generation,
        batch_id,
        batch_sequence,
        segment_sequence,
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
        cursor: cursor.clone(),
    };
    let metadata = EventMetadata {
        index: input.output.index.clone(),
        sourcetype: input.output.sourcetype.clone(),
        source: input.output.source.clone(),
    };
    let (line_tx, line_rx) = mpsc::channel(ROW_CHANNEL_CAPACITY);
    let event_identity = match &cursor {
        Some(_) => {
            let rising = input
                .rising
                .as_ref()
                .ok_or_else(|| WorkerError::Daemon(collection_run_error()))?;
            EventIdentity::Rising {
                input_key,
                lineage_fingerprint: input.lineage_fingerprint.into_bytes(),
                cursor_identity_fingerprint: rising.cursor_identity_fingerprint.into_bytes(),
            }
        }
        None => EventIdentity::Batch {
            input_key,
            batch_id,
        },
    };
    let spooling = spool_rows(
        line_rx,
        writer,
        services.hec.clone(),
        metadata,
        event_identity,
    );
    let collection = services
        .connectors
        .collect_json_rows(request, &secret, line_tx, cancellation);
    let (collection, spooled) = tokio::join!(collection, spooling);
    let recovery_request = match (cursor.as_ref(), input.rising.as_ref()) {
        (Some(cursor), Some(rising)) => Some(rising_request_fingerprint(
            rising.cursor_identity_fingerprint.into_bytes(),
            cursor,
        )),
        (None, None) => None,
        (None, Some(_)) | (Some(_), None) => return Err(collection_run_error().into()),
    };
    finalize_spooled_collection(collection, spooled, recovery_request)
}

fn validate_collection_run(
    prepared_cursor: Option<&TimestampIdCursorSpec>,
    run: &CollectionRun,
) -> Result<(), WorkerError> {
    match (prepared_cursor, run) {
        (
            None,
            CollectionRun::Batch {
                configuration_generation,
            },
        ) if *configuration_generation > 0 => Ok(()),
        (
            Some(prepared),
            CollectionRun::Rising {
                configuration_generation,
                attempt_id,
                page,
                cursor,
                ..
            },
        ) if *configuration_generation > 0
            && *page > 0
            && attempt_id.into_bytes().iter().any(|byte| *byte != 0)
            && cursor.spec == *prepared
            && cursor.effective_bound().is_ok() =>
        {
            Ok(())
        }
        _ => Err(collection_run_error().into()),
    }
}

fn finalize_spooled_collection(
    collection: Result<CollectionResult, ConnectorError>,
    spooled: Result<(SegmentWriter, u64), WorkerError>,
    recovery_request: Option<[u8; 32]>,
) -> Result<WorkerCompletion, WorkerError> {
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
    if let Some(request_fingerprint) = recovery_request
        && collection.rows_read == 0
    {
        RisingRecoveryMetadata::new(
            collection.rows_read,
            collection.truncated,
            request_fingerprint,
            collection.checkpoint_candidate,
            collection.scan_resume,
        )
        .map_err(rising_metadata_error)?;
        writer.abort().map_err(DaemonError::from)?;
        return Ok(WorkerCompletion::RisingEmpty(collection));
    }
    let ready = if let Some(request_fingerprint) = recovery_request {
        let metadata = RisingRecoveryMetadata::new(
            collection.rows_read,
            collection.truncated,
            request_fingerprint,
            collection.checkpoint_candidate,
            collection.scan_resume,
        )
        .and_then(RisingRecoveryMetadata::encode)
        .map_err(rising_metadata_error)?;
        writer
            .seal_with_recovery_metadata(metadata)
            .map_err(DaemonError::from)?
    } else {
        writer.seal().map_err(DaemonError::from)?
    };
    if ready.summary().event_count != collection.rows_read {
        return Err(accounting_error().into());
    }
    if recovery_request.is_some() {
        Ok(WorkerCompletion::RisingSealed(collection))
    } else {
        Ok(WorkerCompletion::Batch(collection))
    }
}

#[derive(Clone, Copy)]
enum EventIdentity {
    Batch {
        input_key: InputKey,
        batch_id: BatchId,
    },
    Rising {
        input_key: InputKey,
        lineage_fingerprint: [u8; 32],
        cursor_identity_fingerprint: [u8; 32],
    },
}

async fn spool_rows(
    mut line_rx: mpsc::Receiver<JsonRow>,
    mut writer: SegmentWriter,
    hec: HecClient,
    metadata: EventMetadata,
    identity: EventIdentity,
) -> Result<(SegmentWriter, u64), WorkerError> {
    let mut rows = 0_u64;
    while let Some(row) = line_rx.recv().await {
        let ordinal = rows.checked_add(1).ok_or_else(accounting_error)?;
        let (line, cursor) = row.into_parts();
        let event_id = match (identity, cursor) {
            (
                EventIdentity::Batch {
                    input_key,
                    batch_id,
                },
                None,
            ) => deterministic_event_id(input_key, batch_id, ordinal),
            (
                EventIdentity::Rising {
                    input_key,
                    lineage_fingerprint,
                    cursor_identity_fingerprint,
                },
                Some(cursor),
            ) => deterministic_rising_event_id(
                input_key,
                lineage_fingerprint,
                cursor_identity_fingerprint,
                cursor,
            ),
            (EventIdentity::Batch { .. }, Some(_)) | (EventIdentity::Rising { .. }, None) => {
                return Err(cursor_accounting_error().into());
            }
        };
        let event = hec.encode_event(line, &metadata, &event_id)?;
        writer.append_event(&event).map_err(DaemonError::from)?;
        rows = ordinal;
    }
    Ok((writer, rows))
}

fn deterministic_rising_event_id(
    input_key: InputKey,
    lineage_fingerprint: [u8; 32],
    cursor_identity_fingerprint: [u8; 32],
    cursor: TimestampIdCursor,
) -> String {
    let mut context = Context::new(&SHA256);
    context.update(RISING_EVENT_ID_DOMAIN);
    context.update(&input_key.into_bytes());
    context.update(&lineage_fingerprint);
    context.update(&cursor_identity_fingerprint);
    context.update(&cursor.to_canonical_bytes());
    encode_lower_hex(context.finish().as_ref())
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
    rising_inputs: BTreeSet<InputKey>,
    cancellation: CancellationToken,
) -> Result<u64, DaemonError> {
    tokio::task::spawn_blocking(move || {
        drain_ready_segments_sync(
            &spool,
            hec.as_ref(),
            limits,
            &replay_fences,
            &rising_inputs,
            &cancellation,
        )
    })
    .await
    .map_err(|_| delivery_task_error())?
}

fn drain_ready_segments_sync(
    spool: &Spool,
    hec: Option<&HecClient>,
    limits: DeliveryLimits,
    replay_fences: &ReplayFences,
    rising_inputs: &BTreeSet<InputKey>,
    cancellation: &CancellationToken,
) -> Result<u64, DaemonError> {
    let delivered = spool.list_delivered()?;
    let ready = spool.list_ready()?;
    validate_replay_fences(&ready, replay_fences, rising_inputs)?;

    for delivered in delivered {
        if rising_inputs.contains(&delivered.header().input_key) {
            continue;
        }
        if !delivered.recovery_metadata().as_bytes().is_empty() {
            return Err(replay_input_missing());
        }
        // Batch delivery is already acknowledged at this boundary. Its current configuration is
        // irrelevant to safe compaction, including after input removal or revision changes.
        spool.compact_delivered(&delivered)?;
    }
    let ready = ready
        .into_iter()
        .filter(|segment| replay_fences.contains_key(&segment.header().input_key))
        .collect::<Vec<_>>();
    if ready.is_empty() {
        return Ok(0);
    }
    let hec = hec.ok_or_else(delivery_unavailable)?;
    let mut delivered_rows = 0_u64;
    for ready in ready {
        ensure_delivery_active(cancellation)?;
        let rows = ready.summary().event_count;
        let delivered = deliver_ready_segment_sync(spool, &ready, hec, limits, cancellation)?;
        spool.compact_delivered(&delivered)?;
        delivered_rows = delivered_rows
            .checked_add(rows)
            .ok_or_else(accounting_error)?;
    }
    Ok(delivered_rows)
}

fn validate_replay_fences(
    ready: &[ReadySegment],
    replay_fences: &ReplayFences,
    rising_inputs: &BTreeSet<InputKey>,
) -> Result<(), DaemonError> {
    for segment in ready {
        validate_replay_header(segment.header(), replay_fences, rising_inputs)?;
    }
    Ok(())
}

fn validate_replay_header(
    header: &SegmentHeader,
    replay_fences: &ReplayFences,
    rising_inputs: &BTreeSet<InputKey>,
) -> Result<(), DaemonError> {
    if let Some(active_fingerprint) = replay_fences.get(&header.input_key) {
        if *active_fingerprint != header.configuration_fingerprint {
            return Err(replay_fingerprint_mismatch());
        }
        return Ok(());
    }
    if rising_inputs.contains(&header.input_key) {
        return Ok(());
    }
    Err(replay_input_missing())
}

pub(crate) fn deliver_ready_segment_sync(
    spool: &Spool,
    ready: &ReadySegment,
    hec: &HecClient,
    limits: DeliveryLimits,
    cancellation: &CancellationToken,
) -> Result<DeliveredSegment, DaemonError> {
    let mut batch = Vec::new();
    let mut batch_events = 0_usize;
    let mut delivered_rows = 0_u64;
    for event in spool.reader(ready)? {
        ensure_delivery_active(cancellation)?;
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
            ensure_delivery_active(cancellation)?;
            hec.send_batch(&batch)?;
            ensure_delivery_active(cancellation)?;
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
        ensure_delivery_active(cancellation)?;
        hec.send_batch(&batch)?;
        ensure_delivery_active(cancellation)?;
        delivered_rows = delivered_rows
            .checked_add(batch_events as u64)
            .ok_or_else(accounting_error)?;
    }
    if delivered_rows != ready.summary().event_count {
        return Err(accounting_error());
    }
    ensure_delivery_active(cancellation)?;
    spool.mark_delivered(ready).map_err(DaemonError::from)
}

fn ensure_delivery_active(cancellation: &CancellationToken) -> Result<(), DaemonError> {
    if cancellation.is_cancelled() {
        Err(delivery_cancelled())
    } else {
        Ok(())
    }
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

const fn rising_metadata_error(error: crate::rising_metadata::RisingMetadataError) -> WorkerError {
    WorkerError::Daemon(DaemonError::new(
        error.code(),
        "storage",
        "rising_recovery_metadata",
        "rising recovery metadata is invalid",
        false,
        false,
    ))
}

const fn cursor_accounting_error() -> DaemonError {
    DaemonError::new(
        "DBX-RS-WORKER-0011",
        "internal",
        "cursor_accounting",
        "materialized row cursor did not match the collection mode",
        false,
        false,
    )
}

const fn collection_run_error() -> DaemonError {
    DaemonError::new(
        "DBX-RS-WORKER-0012",
        "internal",
        "collection_fence",
        "worker collection mode does not match its prepared durable fence",
        false,
        false,
    )
}

const fn delivery_cancelled() -> DaemonError {
    DaemonError::new(
        "DBX-RS-WORKER-0013",
        "cancelled",
        "hec_delivery",
        "durable HEC delivery was cancelled",
        true,
        false,
    )
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

        assert_eq!(
            first,
            "16164b3573c39e6b6f5d8bec98e1fba00a512d8db0ca7c6a043f926137b5f5f6"
        );
        assert_eq!(first, deterministic_event_id(input, batch, 1));
        assert_ne!(first, deterministic_event_id(input, batch, 2));
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    fn cursor_request() -> TimestampIdCursorRequest {
        TimestampIdCursorRequest {
            spec: TimestampIdCursorSpec {
                timestamp_field: "updated_at".into(),
                id_field: "id".into(),
                overlap: Duration::ZERO,
                null_policy: dbx_rs_connector_sdk::CursorNullPolicy::Reject,
            },
            committed: None,
            resume_after: None,
        }
    }

    #[test]
    fn collection_run_must_match_prepared_mode_cursor_and_fence() {
        let request = cursor_request();
        let batch = CollectionRun::Batch {
            configuration_generation: 1,
        };
        let rising = CollectionRun::Rising {
            configuration_generation: 1,
            checkpoint_generation: 0,
            attempt_id: AttemptId::new([0x11; 16]),
            page: 1,
            cursor: request.clone(),
        };

        assert!(validate_collection_run(None, &batch).is_ok());
        assert!(
            validate_collection_run(
                None,
                &CollectionRun::Batch {
                    configuration_generation: 0,
                }
            )
            .is_err()
        );
        assert!(validate_collection_run(Some(&request.spec), &rising).is_ok());
        assert!(validate_collection_run(None, &rising).is_err());
        assert!(validate_collection_run(Some(&request.spec), &batch).is_err());

        let mut wrong_spec = request.spec.clone();
        wrong_spec.id_field = "other_id".into();
        assert!(validate_collection_run(Some(&wrong_spec), &rising).is_err());

        let invalid_page = CollectionRun::Rising {
            configuration_generation: 1,
            checkpoint_generation: 0,
            attempt_id: AttemptId::new([0x11; 16]),
            page: 0,
            cursor: request.clone(),
        };
        assert!(validate_collection_run(Some(&request.spec), &invalid_page).is_err());
        let zero_generation = CollectionRun::Rising {
            configuration_generation: 0,
            checkpoint_generation: 0,
            attempt_id: AttemptId::new([0x11; 16]),
            page: 1,
            cursor: request.clone(),
        };
        assert!(validate_collection_run(Some(&request.spec), &zero_generation).is_err());
        let nil_attempt = CollectionRun::Rising {
            configuration_generation: 1,
            checkpoint_generation: 0,
            attempt_id: AttemptId::new([0; 16]),
            page: 1,
            cursor: request.clone(),
        };
        assert!(validate_collection_run(Some(&request.spec), &nil_attempt).is_err());

        let mut invalid_resume = request.clone();
        invalid_resume.committed = Some(TimestampIdCursor::new(100, 0));
        invalid_resume.resume_after = Some(TimestampIdCursor::new(99, 0));
        let invalid_bound = CollectionRun::Rising {
            configuration_generation: 1,
            checkpoint_generation: 0,
            attempt_id: AttemptId::new([0x11; 16]),
            page: 1,
            cursor: invalid_resume,
        };
        assert!(validate_collection_run(Some(&request.spec), &invalid_bound).is_err());
    }

    #[test]
    fn rising_event_identity_is_stable_across_attempts_and_page_boundaries() {
        let input = InputKey::new([0x11; 32]);
        let lineage = [0x22; 32];
        let cursor_identity = [0x33; 32];
        let cursor = TimestampIdCursor::new(1_720_000_000_000_000, 42);

        let first = deterministic_rising_event_id(input, lineage, cursor_identity, cursor);

        assert_eq!(
            first,
            deterministic_rising_event_id(input, lineage, cursor_identity, cursor)
        );
        assert_ne!(
            first,
            deterministic_rising_event_id(
                input,
                lineage,
                cursor_identity,
                TimestampIdCursor::new(1_720_000_000_000_000, 43)
            )
        );
        assert_ne!(
            first,
            deterministic_rising_event_id(input, [0x44; 32], cursor_identity, cursor)
        );
        assert_ne!(
            first,
            deterministic_rising_event_id(input, lineage, [0x55; 32], cursor)
        );
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn collection_failure_aborts_without_publishing_ready_data() {
        let root = TestDirectory::new();
        let spool = open_spool(&root);
        let writer = spool.begin_segment(header()).expect("writer must begin");

        let result = finalize_spooled_collection(
            Err(ConnectorError::cancelled("TEST-CANCELLED")),
            Ok((writer, 0)),
            None,
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

        let Ok(WorkerCompletion::Batch(_collection)) =
            finalize_spooled_collection(Ok(collection(1, 11)), Ok((writer, 1)), None)
        else {
            panic!("successful collection must seal");
        };

        assert_eq!(spool.list_ready().expect("ready inventory").len(), 1);
        assert!(
            spool
                .list_delivered()
                .expect("delivered inventory")
                .is_empty()
        );
    }

    #[test]
    fn rising_collection_seals_authenticated_recovery_metadata() {
        let root = TestDirectory::new();
        let spool = open_spool(&root);
        let mut writer = spool.begin_segment(header()).expect("writer must begin");
        writer
            .append_event(br#"{"event":{"value":1}}"#)
            .expect("event must append");
        let cursor = TimestampIdCursor::new(10, 1);
        let mut result = collection(1, 11);
        result.truncated = true;
        result.checkpoint_candidate = Some(cursor);
        result.scan_resume = Some(cursor);

        let Ok(completion) =
            finalize_spooled_collection(Ok(result), Ok((writer, 1)), Some([0x66; 32]))
        else {
            panic!("rising page must seal");
        };

        assert!(matches!(completion, WorkerCompletion::RisingSealed(_)));
        let ready = spool.list_ready().expect("ready inventory");
        assert_eq!(ready.len(), 1);
        let metadata = RisingRecoveryMetadata::decode(ready[0].recovery_metadata())
            .expect("metadata must authenticate and decode");
        assert_eq!(metadata.rows(), 1);
        assert!(metadata.truncated());
        assert_eq!(metadata.checkpoint_candidate(), Some(cursor));
        assert_eq!(metadata.scan_resume(), Some(cursor));
    }

    #[test]
    fn empty_rising_collection_aborts_without_publishing_a_segment() {
        let root = TestDirectory::new();
        let spool = open_spool(&root);
        let writer = spool.begin_segment(header()).expect("writer must begin");

        let Ok(completion) =
            finalize_spooled_collection(Ok(collection(0, 0)), Ok((writer, 0)), Some([0x66; 32]))
        else {
            panic!("empty rising page must complete");
        };

        assert!(matches!(completion, WorkerCompletion::RisingEmpty(_)));
        assert!(spool.list_ready().expect("ready inventory").is_empty());
        assert_eq!(spool.usage().stored_bytes(), 0);
        assert_eq!(spool.usage().reserved_bytes(), 0);
    }

    #[test]
    fn invalid_rising_cursor_accounting_aborts_the_open_segment() {
        let root = TestDirectory::new();
        let spool = open_spool(&root);
        let mut writer = spool.begin_segment(header()).expect("writer must begin");
        writer
            .append_event(br#"{"event":{"value":1}}"#)
            .expect("event must append");

        let error =
            finalize_spooled_collection(Ok(collection(1, 11)), Ok((writer, 1)), Some([0x66; 32]))
                .err()
                .expect("missing cursor facts must fail");

        assert!(matches!(error, WorkerError::Daemon(_)));
        assert!(spool.list_ready().expect("ready inventory").is_empty());
        assert_eq!(spool.usage().reserved_bytes(), 0);
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

        let rising = BTreeSet::new();
        let missing = validate_replay_fences(&ready, &ReplayFences::new(), &rising)
            .expect_err("missing active input must block replay");
        assert_eq!(missing.code(), "DBX-RS-WORKER-0008");

        let mismatched = ReplayFences::from([(expected.input_key, Fingerprint::new([0x44; 32]))]);
        let mismatch = validate_replay_fences(&ready, &mismatched, &rising)
            .expect_err("changed input revision must block replay");
        assert_eq!(mismatch.code(), "DBX-RS-WORKER-0009");

        let matching =
            ReplayFences::from([(expected.input_key, expected.configuration_fingerprint)]);
        validate_replay_fences(&ready, &matching, &rising).expect("exact fence must permit replay");
        let unavailable = drain_ready_segments_sync(
            &spool,
            None,
            DeliveryLimits {
                max_events: 10,
                max_bytes: 4_096,
            },
            &matching,
            &rising,
            &CancellationToken::new(),
        )
        .expect_err("disabled HEC must retain ready data");
        assert_eq!(unavailable.code(), "DBX-RS-WORKER-0010");
        assert_eq!(spool.list_ready().expect("ready must remain").len(), 1);
    }

    #[test]
    fn acknowledged_batch_compacts_after_input_removal() {
        let root = TestDirectory::new();
        let spool = open_spool(&root);
        let mut writer = spool.begin_segment(header()).expect("writer must begin");
        writer
            .append_event(br#"{"event":{"value":1}}"#)
            .expect("event must append");
        writer.seal().expect("segment must seal");
        let ready = spool
            .list_ready()
            .expect("ready inventory")
            .pop()
            .expect("one ready segment");
        spool
            .mark_delivered(&ready)
            .expect("delivery transition must work");

        let delivered_rows = drain_ready_segments_sync(
            &spool,
            None,
            DeliveryLimits {
                max_events: 10,
                max_bytes: 4_096,
            },
            &ReplayFences::new(),
            &BTreeSet::new(),
            &CancellationToken::new(),
        )
        .expect("an acknowledged batch must compact without an active input");

        assert_eq!(delivered_rows, 0);
        assert!(spool.list_delivered().expect("inventory").is_empty());
    }

    #[test]
    fn delivery_failure_retains_a_restart_replayable_ready_segment() {
        let root = TestDirectory::new();
        let spool = open_spool(&root);
        let mut writer = spool.begin_segment(header()).expect("writer must begin");
        writer
            .append_event(br#"{"event":{"value":1}}"#)
            .expect("event must append");
        let result = finalize_spooled_collection(Ok(collection(1, 11)), Ok((writer, 1)), None);
        let Ok(WorkerCompletion::Batch(_collection)) = result else {
            panic!("successful collection must seal");
        };
        let ready = spool
            .list_ready()
            .expect("ready inventory")
            .pop()
            .expect("one ready segment");

        let error = deliver_ready_segment_sync(
            &spool,
            &ready,
            &hec(&root),
            DeliveryLimits {
                max_events: 1,
                max_bytes: 1,
            },
            &CancellationToken::new(),
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

    #[test]
    fn cancelled_delivery_retains_ready_data_without_contacting_hec() {
        let root = TestDirectory::new();
        let spool = open_spool(&root);
        let mut writer = spool.begin_segment(header()).expect("writer must begin");
        writer
            .append_event(br#"{"event":{"value":1}}"#)
            .expect("event must append");
        writer.seal().expect("segment must seal");
        let ready = spool
            .list_ready()
            .expect("ready inventory")
            .pop()
            .expect("one ready segment");
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let error = deliver_ready_segment_sync(
            &spool,
            &ready,
            &hec(&root),
            DeliveryLimits {
                max_events: 10,
                max_bytes: 4_096,
            },
            &cancellation,
        )
        .expect_err("cancelled delivery must retain ready data");

        assert_eq!(error.code(), "DBX-RS-WORKER-0013");
        assert_eq!(spool.list_ready().expect("ready must remain").len(), 1);
        assert!(spool.list_delivered().expect("inventory").is_empty());
    }
}
