use std::sync::Arc;

use dbx_rs_config::InputConfig;
use dbx_rs_connector_postgres::{JsonCollectionRequest, PostgresConnector};
use dbx_rs_connector_sdk::{CollectionResult, ConnectionConfig, ConnectorError, TlsMode};
use dbx_rs_telemetry::{NdjsonTelemetry, OperationLimits, OperationMetrics};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::error::DaemonError;
use crate::hec::{EventMetadata, HecClient};
use crate::identity::generate_uuid;
use crate::operational::OperationTracker;
use crate::secrets::SecretStore;
use crate::secure_fs::read_limited;

const QUERY_FILE_MAX_BYTES: u64 = 1024 * 1024;
const TLS_CA_MAX_BYTES: u64 = 1024 * 1024;
const ROW_CHANNEL_CAPACITY: usize = 64;

pub enum WorkerError {
    Daemon(DaemonError),
    Connector(ConnectorError),
}

impl From<DaemonError> for WorkerError {
    fn from(error: DaemonError) -> Self {
        Self::Daemon(error)
    }
}

pub async fn run_input(
    input: InputConfig,
    hec: HecClient,
    secrets: Arc<SecretStore>,
    telemetry: NdjsonTelemetry,
    batch_max_events: usize,
    batch_max_bytes: u64,
    cancellation: CancellationToken,
) -> Result<(), WorkerError> {
    let request_id = generate_uuid()?;
    let tracker = OperationTracker::start(
        &telemetry,
        "postgres",
        "collect_hec",
        &request_id,
        &input.tls_mode,
        Some(&input.name),
        OperationLimits::default()
            .with_max_rows(input.max_rows)
            .with_max_bytes(input.max_bytes)
            .with_connect_timeout(input.connect_timeout)
            .with_operation_timeout(input.query_timeout),
    )?;
    let result = run_input_inner(
        &input,
        hec,
        &secrets,
        &request_id,
        batch_max_events,
        batch_max_bytes,
        cancellation,
    )
    .await;
    match result {
        Ok(collection) => {
            tracker
                .succeeded(OperationMetrics::collection(
                    collection.rows_read,
                    collection.bytes_read,
                    true,
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
    input: &InputConfig,
    hec: HecClient,
    secrets: &SecretStore,
    request_id: &str,
    batch_max_events: usize,
    batch_max_bytes: u64,
    cancellation: CancellationToken,
) -> Result<CollectionResult, WorkerError> {
    let query = String::from_utf8(read_limited(&input.query_file, QUERY_FILE_MAX_BYTES)?).map_err(
        |_| {
            DaemonError::new(
                "DBX-RS-WORKER-0001",
                "configuration",
                "query_input",
                "query file is not valid UTF-8",
                false,
                true,
            )
        },
    )?;
    let tls_ca_pem = input
        .tls_ca_file
        .as_deref()
        .map(|path| read_limited(path, TLS_CA_MAX_BYTES))
        .transpose()?;
    let tls_mode = input.tls_mode.parse::<TlsMode>().map_err(|_| {
        DaemonError::new(
            "DBX-RS-WORKER-0002",
            "configuration",
            "connection_config",
            "input TLS mode is invalid",
            false,
            true,
        )
    })?;
    let connection = ConnectionConfig {
        connector_id: PostgresConnector::CONNECTOR_ID.into(),
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
    let secret = secrets.resolve(&input.secret_ref)?;
    let request = JsonCollectionRequest {
        request_id: request_id.to_owned(),
        query,
        max_rows: input.max_rows,
        max_bytes: input.max_bytes,
        timeout: input.query_timeout,
    };
    let metadata = EventMetadata {
        index: input.index.clone(),
        sourcetype: input.sourcetype.clone(),
        source: input.source.clone(),
    };
    let (line_tx, line_rx) = mpsc::channel(ROW_CHANNEL_CAPACITY);
    let delivery = deliver_rows(line_rx, hec, metadata, batch_max_events, batch_max_bytes);
    let connector = PostgresConnector;
    let collection =
        connector.collect_json_lines(&connection, &secret, request, line_tx, cancellation);
    let (collection, delivery) = tokio::join!(collection, delivery);
    let collection = collection.map_err(WorkerError::Connector)?;
    let delivered_rows = delivery?;
    if collection.rows_read != delivered_rows {
        return Err(DaemonError::new(
            "DBX-RS-WORKER-0003",
            "internal",
            "hec_delivery",
            "HEC delivery accounting did not match collection accounting",
            true,
            false,
        )
        .into());
    }
    Ok(collection)
}

async fn deliver_rows(
    mut line_rx: mpsc::Receiver<Vec<u8>>,
    hec: HecClient,
    metadata: EventMetadata,
    max_events: usize,
    max_bytes: u64,
) -> Result<u64, WorkerError> {
    let mut batch = Vec::new();
    let mut batch_events = 0_usize;
    let mut delivered_rows = 0_u64;
    while let Some(line) = line_rx.recv().await {
        let event = hec.encode_event(line, &metadata)?;
        let separator_bytes = usize::from(!batch.is_empty());
        let next_bytes = batch
            .len()
            .saturating_add(separator_bytes)
            .saturating_add(event.len());
        if batch_events == max_events || next_bytes as u64 > max_bytes {
            send_batch(hec.clone(), std::mem::take(&mut batch)).await?;
            delivered_rows = delivered_rows.saturating_add(batch_events as u64);
            batch_events = 0;
        }
        if !batch.is_empty() {
            batch.push(b'\n');
        }
        batch.extend_from_slice(&event);
        batch_events += 1;
    }
    if !batch.is_empty() {
        send_batch(hec, batch).await?;
        delivered_rows = delivered_rows.saturating_add(batch_events as u64);
    }
    Ok(delivered_rows)
}

async fn send_batch(hec: HecClient, body: Vec<u8>) -> Result<(), WorkerError> {
    tokio::task::spawn_blocking(move || hec.send_batch(&body))
        .await
        .map_err(|_| {
            DaemonError::new(
                "DBX-RS-WORKER-0004",
                "internal",
                "hec_delivery",
                "HEC delivery task failed",
                true,
                false,
            )
        })?
        .map_err(WorkerError::Daemon)
}
