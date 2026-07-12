#![forbid(unsafe_code)]

use std::{cmp::Ordering, collections::HashSet, io::Cursor, sync::Arc, time::Duration};

use arrow_array::{
    Array, BinaryArray, BooleanArray, Date32Array, Decimal128Array, Float32Array, Float64Array,
    Int8Array, Int16Array, Int32Array, Int64Array, RecordBatch, StringArray,
    Time64MicrosecondArray, TimestampMicrosecondArray, UInt32Array,
    temporal_conversions::{date32_to_datetime, time64us_to_time, timestamp_us_to_datetime},
};
use arrow_ipc::reader::StreamReader;
use arrow_schema::{DataType, Schema, TimeUnit};
use dbx_rs_connector_postgres::PostgresConnector;
use dbx_rs_connector_sdk::{
    ArrowIpcBatch, CollectionResult, Connector, ConnectorDescriptor, ConnectorError,
    ConnectorProvider, ErrorClass, ExecuteRequest, ExecutionLimits, ExecutionResult,
    FieldDescriptor, FieldType, PrepareRequest, PreparedQuery, ProbeReport, ProbeRequest,
    QuerySchema, QueryText, ResolvedSecret, TimestampIdCursor, TimestampIdCursorBound,
    TimestampIdCursorRequest, ValidationReport, ValidationRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep_until, timeout as tokio_timeout};
use tokio_util::sync::CancellationToken;

const IPC_CHANNEL_CAPACITY: usize = 2;
const MAX_BATCH_ROWS: u32 = 256;
const MAX_FIXED_BATCH_VALUE_BYTES: u64 = 256 * 1024;
const MAX_BATCH_BYTES: u64 = 1024 * 1024;
const MAX_TOTAL_IPC_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const IPC_FRAME_OVERHEAD_BYTES: u64 = 64 * 1024;
const CLEANUP_GRACE: Duration = Duration::from_secs(1);
const MAX_COLLECTION_TIMEOUT: Duration = Duration::from_hours(24);
const IPC_END_MARKER: [u8; 8] = [0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0];

/// Registry for Native Certified connectors linked into this process.
#[derive(Clone)]
pub struct NativeConnectorProvider {
    postgres: Arc<PostgresConnector>,
}

/// Compatibility name for call sites that describe this component as a registry.
pub type NativeConnectorRegistry = NativeConnectorProvider;

impl NativeConnectorProvider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            postgres: Arc::new(PostgresConnector),
        }
    }

    /// Resolves a connector by ID.
    ///
    /// # Errors
    ///
    /// Returns a stable configuration error when the connector ID is not registered.
    pub fn connector(&self, connector_id: &str) -> Result<Arc<dyn Connector>, ConnectorError> {
        <Self as ConnectorProvider>::connector(self, connector_id)
    }

    #[must_use]
    pub fn descriptors(&self) -> Vec<ConnectorDescriptor> {
        <Self as ConnectorProvider>::descriptors(self)
    }

    /// Dispatches configuration and query validation to the selected connector.
    ///
    /// # Errors
    ///
    /// Returns a stable configuration error when the connector ID is not registered.
    pub fn validate(
        &self,
        request: &ValidationRequest,
    ) -> Result<ValidationReport, ConnectorError> {
        self.connector(&request.connection.connector_id)
            .map(|connector| connector.validate(request))
    }

    /// Dispatches a live connection probe to the selected connector.
    ///
    /// # Errors
    ///
    /// Returns a connector error from lookup or probe execution.
    pub async fn probe(
        &self,
        request: ProbeRequest,
        secret: &ResolvedSecret,
        cancellation: CancellationToken,
    ) -> Result<ProbeReport, ConnectorError> {
        let connector = self.connector(&request.connection.connector_id)?;
        connector.probe(request, secret, cancellation).await
    }

    /// Dispatches query preparation to the selected connector.
    ///
    /// # Errors
    ///
    /// Returns a connector error from lookup or preparation.
    pub async fn prepare(
        &self,
        request: PrepareRequest,
        secret: &ResolvedSecret,
        cancellation: CancellationToken,
    ) -> Result<PreparedQuery, ConnectorError> {
        let connector = self.connector(&request.connection.connector_id)?;
        connector.prepare(request, secret, cancellation).await
    }

    /// Dispatches typed query execution to the selected connector.
    ///
    /// # Errors
    ///
    /// Returns a connector error from lookup or execution.
    pub async fn execute(
        &self,
        request: ExecuteRequest,
        secret: &ResolvedSecret,
        batch_tx: mpsc::Sender<ArrowIpcBatch>,
        cancellation: CancellationToken,
    ) -> Result<ExecutionResult, ConnectorError> {
        let connector = self.connector(&request.connection.connector_id)?;
        connector
            .execute(request, secret, batch_tx, cancellation)
            .await
    }

    /// Executes a typed query and materializes compact NDJSON objects for host delivery.
    ///
    /// The returned byte count includes the newline delimiter for every emitted object. Channel
    /// messages contain the object bytes without the delimiter, matching the host delivery API.
    ///
    /// # Errors
    ///
    /// Returns a connector error for invalid limits, connector failures, malformed Arrow IPC,
    /// schema or counter mismatches, lossy conversion, output-limit violations, or a closed output
    /// channel. A materialization or output error takes precedence over the secondary error caused
    /// when the connector observes the closed IPC receiver.
    pub async fn collect_json_rows(
        &self,
        request: JsonCollectionRequest,
        secret: &ResolvedSecret,
        row_tx: mpsc::Sender<JsonRow>,
        cancellation: CancellationToken,
    ) -> Result<CollectionResult, ConnectorError> {
        validate_collection_request(&request)?;
        let connector = self.connector(&request.connection.connector_id)?;
        collect_json_rows_with_connector(connector, request, secret, row_tx, cancellation).await
    }
}

async fn collect_json_rows_with_connector(
    connector: Arc<dyn Connector>,
    request: JsonCollectionRequest,
    secret: &ResolvedSecret,
    row_tx: mpsc::Sender<JsonRow>,
    cancellation: CancellationToken,
) -> Result<CollectionResult, ConnectorError> {
    let operation_cancellation = cancellation.child_token();
    let deadline = Instant::now().checked_add(request.timeout).ok_or_else(|| {
        configuration_error(
            "DBX-RS-NATIVE-CFG-0006",
            "collection timeout cannot be represented",
        )
    })?;
    let operation = collect_json_rows_inner(
        connector,
        request,
        secret,
        row_tx,
        deadline,
        operation_cancellation.clone(),
    );
    tokio::pin!(operation);
    let deadline_elapsed = sleep_until(deadline);
    tokio::pin!(deadline_elapsed);

    tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            operation_cancellation.cancel();
            let _cleanup = tokio_timeout(CLEANUP_GRACE, &mut operation).await;
            Err(ConnectorError::cancelled("DBX-RS-NATIVE-CANCELLED-0003"))
        }
        () = &mut deadline_elapsed => {
            operation_cancellation.cancel();
            let _cleanup = tokio_timeout(CLEANUP_GRACE, &mut operation).await;
            Err(operation_timeout())
        }
        result = &mut operation => result,
    }
}

async fn collect_json_rows_inner(
    connector: Arc<dyn Connector>,
    request: JsonCollectionRequest,
    secret: &ResolvedSecret,
    row_tx: mpsc::Sender<JsonRow>,
    deadline: Instant,
    cancellation: CancellationToken,
) -> Result<CollectionResult, ConnectorError> {
    let prepared = connector
        .prepare(
            PrepareRequest {
                request_id: request.request_id.clone(),
                connection: request.connection.clone(),
                query: request.query.clone(),
                max_rows: request.max_rows,
                timeout: remaining_timeout(deadline)?,
                cursor: request.cursor.clone(),
            },
            secret,
            cancellation.child_token(),
        )
        .await?;
    validate_prepared(&request, &prepared)?;

    let limits = execution_limits(&request, &prepared.schema, remaining_timeout(deadline)?)?;
    let execute_request = ExecuteRequest {
        request_id: request.request_id.clone(),
        connection: request.connection.clone(),
        query: request.query.clone(),
        limits,
        expected_schema: Some(prepared.schema.clone()),
        cursor: request.cursor.clone(),
    };
    let (batch_tx, batch_rx) = mpsc::channel(IPC_CHANNEL_CAPACITY);
    let execution_cancellation = cancellation.child_token();
    let execute = connector.execute(
        execute_request,
        secret,
        batch_tx,
        execution_cancellation.clone(),
    );
    let materialize = materialize_batches(
        batch_rx,
        row_tx,
        MaterializationOptions {
            request_id: request.request_id.clone(),
            expected_schema: prepared.schema,
            limits,
            max_output_bytes: request.max_bytes,
            cursor: request.cursor.clone(),
            cancellation: cancellation.child_token(),
        },
    );
    tokio::pin!(execute);
    tokio::pin!(materialize);

    let (execution_result, materialization_result) = tokio::select! {
        result = &mut execute => {
            let materialization_result = (&mut materialize).await;
            (result, materialization_result)
        }
        materialization_result = &mut materialize => {
            if materialization_result.is_err() {
                execution_cancellation.cancel();
            }
            let execution_result = (&mut execute).await;
            (execution_result, materialization_result)
        }
    };

    let materialized = match materialization_result {
        Ok(materialized) => materialized,
        Err(error) => return Err(error),
    };
    let executed = execution_result?;
    validate_execution_result(&request.request_id, &executed, &materialized)?;
    validate_scan_progress(request.cursor.as_ref(), &executed, &materialized)?;

    Ok(CollectionResult {
        request_id: request.request_id,
        rows_read: materialized.rows,
        bytes_read: materialized.ndjson_bytes,
        truncated: executed.truncated,
        checkpoint_candidate: materialized.checkpoint_candidate,
        scan_resume: materialized.scan_resume,
    })
}

impl Default for NativeConnectorProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectorProvider for NativeConnectorProvider {
    fn connector(&self, connector_id: &str) -> Result<Arc<dyn Connector>, ConnectorError> {
        match connector_id {
            PostgresConnector::CONNECTOR_ID => Ok(self.postgres.clone()),
            _ => Err(error(
                "DBX-RS-NATIVE-CONNECTOR-0001",
                ErrorClass::Configuration,
                "connector ID is not registered",
                true,
            )),
        }
    }

    fn descriptors(&self) -> Vec<ConnectorDescriptor> {
        vec![self.postgres.descriptor()]
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct JsonCollectionRequest {
    pub request_id: String,
    pub connection: dbx_rs_connector_sdk::ConnectionConfig,
    pub query: QueryText,
    pub max_rows: u64,
    pub max_bytes: u64,
    pub timeout: Duration,
    #[serde(default)]
    pub cursor: Option<TimestampIdCursorRequest>,
}

/// One materialized NDJSON row and its validated connector-neutral cursor tuple, when configured.
#[derive(Clone, Eq, PartialEq)]
pub struct JsonRow {
    bytes: Vec<u8>,
    cursor: Option<TimestampIdCursor>,
}

impl JsonRow {
    #[must_use]
    pub fn new(bytes: Vec<u8>, cursor: Option<TimestampIdCursor>) -> Self {
        Self { bytes, cursor }
    }

    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, Option<TimestampIdCursor>) {
        (self.bytes, self.cursor)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn cursor(&self) -> Option<TimestampIdCursor> {
        self.cursor
    }
}

impl std::fmt::Debug for JsonRow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JsonRow")
            .field("bytes", &"[REDACTED]")
            .field("cursor", &self.cursor.as_ref().map(|_| "[CONFIGURED]"))
            .finish()
    }
}

impl std::fmt::Debug for JsonCollectionRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JsonCollectionRequest")
            .field("request_id", &self.request_id)
            .field("connector_id", &self.connection.connector_id)
            .field("connection", &"[REDACTED]")
            .field("query", &"[REDACTED]")
            .field("max_rows", &self.max_rows)
            .field("max_bytes", &self.max_bytes)
            .field("timeout", &self.timeout)
            .field("cursor", &self.cursor.as_ref().map(|_| "[CONFIGURED]"))
            .finish()
    }
}

struct CursorTracker {
    timestamp_index: usize,
    id_index: usize,
    lower_bound: Option<TimestampIdCursorBound>,
    committed: Option<TimestampIdCursor>,
    last_emitted: Option<TimestampIdCursor>,
    candidate: Option<TimestampIdCursor>,
}

impl CursorTracker {
    fn new(
        cursor: Option<&TimestampIdCursorRequest>,
        schema: &QuerySchema,
    ) -> Result<Option<Self>, ConnectorError> {
        let Some(cursor) = cursor else {
            return Ok(None);
        };
        cursor.spec.validate().map_err(|_| {
            configuration_error("DBX-RS-NATIVE-CURSOR-0001", "cursor definition is invalid")
        })?;
        let lower_bound = cursor.effective_bound().map_err(|_| {
            configuration_error(
                "DBX-RS-NATIVE-CURSOR-0002",
                "effective cursor bound cannot be represented",
            )
        })?;
        let timestamp_index = schema
            .fields
            .iter()
            .position(|field| field.name == cursor.spec.timestamp_field)
            .ok_or_else(|| {
                configuration_error(
                    "DBX-RS-NATIVE-CURSOR-0003",
                    "cursor timestamp field is missing from query output",
                )
            })?;
        let id_index = schema
            .fields
            .iter()
            .position(|field| field.name == cursor.spec.id_field)
            .ok_or_else(|| {
                configuration_error(
                    "DBX-RS-NATIVE-CURSOR-0004",
                    "cursor identifier field is missing from query output",
                )
            })?;
        if schema.fields[timestamp_index].field_type != FieldType::TimestampMicrosecondUtc {
            return Err(configuration_error(
                "DBX-RS-NATIVE-CURSOR-0005",
                "cursor timestamp field must be a UTC microsecond timestamp",
            ));
        }
        if schema.fields[id_index].field_type != FieldType::Int64 {
            return Err(configuration_error(
                "DBX-RS-NATIVE-CURSOR-0006",
                "cursor identifier field must be a signed 64-bit integer",
            ));
        }

        Ok(Some(Self {
            timestamp_index,
            id_index,
            lower_bound,
            committed: cursor.committed,
            last_emitted: None,
            candidate: None,
        }))
    }

    fn validate_row(
        &self,
        batch: &RecordBatch,
        row: usize,
    ) -> Result<TimestampIdCursor, ConnectorError> {
        let timestamp_array = batch.columns()[self.timestamp_index]
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .ok_or_else(|| {
                protocol_error(
                    "DBX-RS-NATIVE-CURSOR-0007",
                    "cursor timestamp Arrow array did not match its schema",
                )
            })?;
        let id_array = batch.columns()[self.id_index]
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or_else(|| {
                protocol_error(
                    "DBX-RS-NATIVE-CURSOR-0008",
                    "cursor identifier Arrow array did not match its schema",
                )
            })?;
        if timestamp_array.is_null(row) || id_array.is_null(row) {
            return Err(conversion_error(
                "DBX-RS-NATIVE-CURSOR-0009",
                "cursor fields cannot contain null values",
            ));
        }
        let value = TimestampIdCursor::new(timestamp_array.value(row), id_array.value(row));
        if self.lower_bound.is_some_and(|bound| {
            matches!(
                value.position_cmp(&bound.value),
                Ordering::Less | Ordering::Equal if !bound.inclusive
            ) || (bound.inclusive && value.position_cmp(&bound.value) == Ordering::Less)
        }) {
            return Err(protocol_error(
                "DBX-RS-NATIVE-CURSOR-0010",
                "query returned a cursor tuple outside its lower bound",
            ));
        }
        if self
            .last_emitted
            .is_some_and(|previous| value.position_cmp(&previous) != Ordering::Greater)
        {
            return Err(protocol_error(
                "DBX-RS-NATIVE-CURSOR-0011",
                "query output cursor tuples were not strictly increasing",
            ));
        }
        Ok(value)
    }

    fn record_emitted(&mut self, value: TimestampIdCursor) {
        self.last_emitted = Some(value);
        let value = self
            .committed
            .filter(|committed| committed.position_cmp(&value) == Ordering::Greater)
            .unwrap_or(value);
        self.candidate = Some(
            self.candidate
                .filter(|candidate| candidate.position_cmp(&value) == Ordering::Greater)
                .unwrap_or(value),
        );
    }

    const fn candidate(&self) -> Option<TimestampIdCursor> {
        self.candidate
    }

    const fn scan_resume(&self) -> Option<TimestampIdCursor> {
        self.last_emitted
    }
}

#[derive(Debug)]
struct MaterializedResult {
    rows: u64,
    ndjson_bytes: u64,
    batches: u64,
    ipc_bytes: u64,
    schema: QuerySchema,
    checkpoint_candidate: Option<TimestampIdCursor>,
    scan_resume: Option<TimestampIdCursor>,
}

struct MaterializationOptions {
    request_id: String,
    expected_schema: QuerySchema,
    limits: ExecutionLimits,
    max_output_bytes: u64,
    cursor: Option<TimestampIdCursorRequest>,
    cancellation: CancellationToken,
}

async fn materialize_batches(
    mut batch_rx: mpsc::Receiver<ArrowIpcBatch>,
    row_tx: mpsc::Sender<JsonRow>,
    options: MaterializationOptions,
) -> Result<MaterializedResult, ConnectorError> {
    let MaterializationOptions {
        request_id,
        expected_schema,
        limits,
        max_output_bytes,
        cursor,
        cancellation,
    } = options;
    reject_duplicate_fields(&expected_schema)?;
    let mut cursor_tracker = CursorTracker::new(cursor.as_ref(), &expected_schema)?;
    let mut result = MaterializedResult {
        rows: 0,
        ndjson_bytes: 0,
        batches: 0,
        ipc_bytes: 0,
        schema: expected_schema.clone(),
        checkpoint_candidate: None,
        scan_resume: None,
    };
    let mut expected_sequence = 0_u64;
    let context = MaterializationContext {
        request_id: &request_id,
        expected_schema: &expected_schema,
        limits,
        max_output_bytes,
        row_tx: &row_tx,
        cancellation: &cancellation,
    };

    loop {
        let envelope = tokio::select! {
            () = cancellation.cancelled() => {
                return Err(ConnectorError::cancelled("DBX-RS-NATIVE-CANCELLED-0001"));
            }
            envelope = batch_rx.recv() => envelope,
        };
        let Some(envelope) = envelope else {
            break;
        };
        materialize_envelope(
            &envelope,
            expected_sequence,
            &mut result,
            cursor_tracker.as_mut(),
            &context,
        )
        .await?;
        expected_sequence = expected_sequence.checked_add(1).ok_or_else(|| {
            conversion_error(
                "DBX-RS-NATIVE-IPC-0006",
                "Arrow IPC batch sequence overflowed",
            )
        })?;
    }

    if let Some(tracker) = cursor_tracker {
        result.checkpoint_candidate = tracker.candidate();
        result.scan_resume = tracker.scan_resume();
    }
    Ok(result)
}

struct MaterializationContext<'a> {
    request_id: &'a str,
    expected_schema: &'a QuerySchema,
    limits: ExecutionLimits,
    max_output_bytes: u64,
    row_tx: &'a mpsc::Sender<JsonRow>,
    cancellation: &'a CancellationToken,
}

async fn materialize_envelope(
    envelope: &ArrowIpcBatch,
    expected_sequence: u64,
    result: &mut MaterializedResult,
    mut cursor_tracker: Option<&mut CursorTracker>,
    context: &MaterializationContext<'_>,
) -> Result<(), ConnectorError> {
    validate_envelope(
        envelope,
        context.request_id,
        expected_sequence,
        context.expected_schema,
        result,
        &context.limits,
    )?;
    let ipc_byte_count = u64::try_from(envelope.ipc_bytes.len()).map_err(|_| {
        conversion_error(
            "DBX-RS-NATIVE-LIMIT-0004",
            "Arrow IPC batch byte count overflowed",
        )
    })?;
    let next_ipc_bytes = result
        .ipc_bytes
        .checked_add(ipc_byte_count)
        .ok_or_else(|| {
            conversion_error(
                "DBX-RS-NATIVE-LIMIT-0004",
                "Arrow IPC total byte count overflowed",
            )
        })?;
    if next_ipc_bytes > context.limits.max_total_ipc_bytes {
        return Err(limit_error(
            "DBX-RS-NATIVE-LIMIT-0005",
            "Arrow IPC exceeded the hard total byte limit",
        ));
    }

    let decoded = decode_one_batch(&envelope.ipc_bytes, &envelope.schema)?;
    let decoded_rows = u64::try_from(decoded.num_rows()).map_err(|_| {
        conversion_error(
            "DBX-RS-NATIVE-IPC-0004",
            "Arrow record batch row count overflowed",
        )
    })?;
    if decoded_rows != envelope.row_count {
        return Err(protocol_error(
            "DBX-RS-NATIVE-IPC-0005",
            "Arrow IPC row count did not match its envelope",
        ));
    }
    let next_rows = result.rows.checked_add(decoded_rows).ok_or_else(|| {
        conversion_error("DBX-RS-NATIVE-LIMIT-0001", "NDJSON row count overflowed")
    })?;
    if next_rows > context.limits.max_rows {
        return Err(limit_error(
            "DBX-RS-NATIVE-LIMIT-0002",
            "query output exceeded the configured row limit",
        ));
    }

    for row in 0..decoded.num_rows() {
        let cursor = cursor_tracker
            .as_deref()
            .map(|tracker| tracker.validate_row(&decoded, row))
            .transpose()?;
        materialize_and_send_row(&decoded, &envelope.schema, row, cursor, result, context).await?;
        if let (Some(tracker), Some(cursor)) = (cursor_tracker.as_deref_mut(), cursor) {
            tracker.record_emitted(cursor);
        }
    }
    result.batches = result.batches.checked_add(1).ok_or_else(|| {
        conversion_error(
            "DBX-RS-NATIVE-LIMIT-0006",
            "Arrow IPC batch count overflowed",
        )
    })?;
    result.ipc_bytes = next_ipc_bytes;
    Ok(())
}

async fn materialize_and_send_row(
    batch: &RecordBatch,
    schema: &QuerySchema,
    row: usize,
    cursor: Option<TimestampIdCursor>,
    result: &mut MaterializedResult,
    context: &MaterializationContext<'_>,
) -> Result<(), ConnectorError> {
    let line = materialize_row(batch, schema, row)?;
    let line_bytes = u64::try_from(line.len()).map_err(|_| {
        conversion_error(
            "DBX-RS-NATIVE-LIMIT-0003",
            "NDJSON line byte count overflowed",
        )
    })?;
    let line_with_delimiter = line_bytes.checked_add(1).ok_or_else(|| {
        conversion_error(
            "DBX-RS-NATIVE-LIMIT-0003",
            "NDJSON line byte count overflowed",
        )
    })?;
    let next_bytes = result
        .ndjson_bytes
        .checked_add(line_with_delimiter)
        .ok_or_else(|| {
            conversion_error(
                "DBX-RS-NATIVE-LIMIT-0003",
                "NDJSON total byte count overflowed",
            )
        })?;
    if next_bytes > context.max_output_bytes {
        return Err(limit_error(
            "DBX-RS-NATIVE-LIMIT-0003",
            "query output exceeded the configured NDJSON byte limit",
        ));
    }
    tokio::select! {
        () = context.cancellation.cancelled() => {
            return Err(ConnectorError::cancelled("DBX-RS-NATIVE-CANCELLED-0002"));
        }
        send = context.row_tx.send(JsonRow::new(line, cursor)) => {
            send.map_err(|_| {
                error(
                    "DBX-RS-NATIVE-OUTPUT-0001",
                    ErrorClass::Internal,
                    "NDJSON row receiver closed",
                    false,
                )
            })?;
        }
    }
    result.ndjson_bytes = next_bytes;
    result.rows = result.rows.checked_add(1).ok_or_else(|| {
        conversion_error("DBX-RS-NATIVE-LIMIT-0001", "NDJSON row count overflowed")
    })?;
    Ok(())
}

fn validate_collection_request(request: &JsonCollectionRequest) -> Result<(), ConnectorError> {
    if request.request_id.trim().is_empty() {
        return Err(configuration_error(
            "DBX-RS-NATIVE-CFG-0001",
            "collection request ID is required",
        ));
    }
    if request.max_rows == 0 {
        return Err(configuration_error(
            "DBX-RS-NATIVE-CFG-0002",
            "collection row limit must be greater than zero",
        ));
    }
    if request.max_bytes == 0 {
        return Err(configuration_error(
            "DBX-RS-NATIVE-CFG-0003",
            "collection NDJSON byte limit must be greater than zero",
        ));
    }
    if request.timeout.is_zero() {
        return Err(configuration_error(
            "DBX-RS-NATIVE-CFG-0004",
            "collection timeout must be greater than zero",
        ));
    }
    if request.timeout > MAX_COLLECTION_TIMEOUT {
        return Err(configuration_error(
            "DBX-RS-NATIVE-CFG-0006",
            "collection timeout exceeds the native hard limit",
        ));
    }
    if let Some(cursor) = &request.cursor {
        cursor.spec.validate().map_err(|_| {
            configuration_error("DBX-RS-NATIVE-CURSOR-0001", "cursor definition is invalid")
        })?;
        cursor.effective_bound().map_err(|_| {
            configuration_error(
                "DBX-RS-NATIVE-CURSOR-0002",
                "effective cursor bound cannot be represented",
            )
        })?;
    }
    Ok(())
}

fn execution_limits(
    request: &JsonCollectionRequest,
    schema: &QuerySchema,
    timeout: Duration,
) -> Result<ExecutionLimits, ConnectorError> {
    let max_batch_rows = max_batch_rows(request.max_rows, schema)?;
    let batch_count = request.max_rows.div_ceil(u64::from(max_batch_rows));
    let total_overhead = batch_count.saturating_mul(IPC_FRAME_OVERHEAD_BYTES);
    let max_total_ipc_bytes = request
        .max_bytes
        .saturating_add(total_overhead)
        .min(MAX_TOTAL_IPC_BYTES);
    let max_batch_bytes = request
        .max_bytes
        .saturating_add(IPC_FRAME_OVERHEAD_BYTES)
        .min(MAX_BATCH_BYTES)
        .min(max_total_ipc_bytes);

    Ok(ExecutionLimits {
        max_rows: request.max_rows,
        max_batch_rows,
        max_batch_bytes,
        max_total_ipc_bytes,
        timeout,
    })
}

// Variable-width database rows remain individually bounded until the connector can inspect their
// encoded IPC size. Fixed-width rows may batch within a conservative aggregate value budget.
fn max_batch_rows(max_rows: u64, schema: &QuerySchema) -> Result<u32, ConnectorError> {
    let fixed_row_bytes = schema.fields.iter().try_fold(0_u64, |total, field| {
        field_width(&field.field_type).map(|width| total.saturating_add(width))
    });
    let schema_cap = fixed_row_bytes.map_or(1, |row_bytes| {
        MAX_FIXED_BATCH_VALUE_BYTES
            .checked_div(row_bytes.max(1))
            .unwrap_or(1)
            .clamp(1, u64::from(MAX_BATCH_ROWS))
    });
    u32::try_from(max_rows.min(schema_cap)).map_err(|_| {
        configuration_error(
            "DBX-RS-NATIVE-CFG-0005",
            "collection row limit is invalid for this platform",
        )
    })
}

const fn field_width(field_type: &FieldType) -> Option<u64> {
    match field_type {
        FieldType::Boolean | FieldType::Int8 => Some(1),
        FieldType::Int16 => Some(2),
        FieldType::Int32 | FieldType::UInt32 | FieldType::Float32 | FieldType::Date32 => Some(4),
        FieldType::Int64
        | FieldType::Float64
        | FieldType::Time64Microsecond
        | FieldType::TimestampMicrosecond
        | FieldType::TimestampMicrosecondUtc => Some(8),
        FieldType::Decimal128 { .. } => Some(16),
        FieldType::Utf8 | FieldType::Binary | FieldType::Uuid | FieldType::Json => None,
    }
}

fn remaining_timeout(deadline: Instant) -> Result<Duration, ConnectorError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(operation_timeout());
    }
    Ok(remaining)
}

fn validate_prepared(
    request: &JsonCollectionRequest,
    prepared: &PreparedQuery,
) -> Result<(), ConnectorError> {
    if prepared.request_id != request.request_id
        || prepared.connector_id != request.connection.connector_id
    {
        return Err(protocol_error(
            "DBX-RS-NATIVE-PROTOCOL-0001",
            "prepared query identity did not match its request",
        ));
    }
    reject_duplicate_fields(&prepared.schema)?;
    CursorTracker::new(request.cursor.as_ref(), &prepared.schema).map(|_| ())
}

fn validate_envelope(
    envelope: &ArrowIpcBatch,
    request_id: &str,
    expected_sequence: u64,
    expected_schema: &QuerySchema,
    current: &MaterializedResult,
    limits: &ExecutionLimits,
) -> Result<(), ConnectorError> {
    if envelope.request_id != request_id {
        return Err(protocol_error(
            "DBX-RS-NATIVE-IPC-0001",
            "Arrow IPC request ID did not match execution",
        ));
    }
    if envelope.sequence != expected_sequence {
        return Err(protocol_error(
            "DBX-RS-NATIVE-IPC-0002",
            "Arrow IPC batch sequence was not contiguous",
        ));
    }
    if &envelope.schema != expected_schema || &current.schema != expected_schema {
        return Err(protocol_error(
            "DBX-RS-NATIVE-SCHEMA-0001",
            "Arrow IPC schema changed during execution",
        ));
    }
    let ipc_bytes = u64::try_from(envelope.ipc_bytes.len()).map_err(|_| {
        conversion_error(
            "DBX-RS-NATIVE-LIMIT-0004",
            "Arrow IPC batch byte count overflowed",
        )
    })?;
    if ipc_bytes > limits.max_batch_bytes {
        return Err(limit_error(
            "DBX-RS-NATIVE-LIMIT-0004",
            "Arrow IPC batch exceeded the hard byte limit",
        ));
    }
    if envelope.row_count > u64::from(limits.max_batch_rows) {
        return Err(limit_error(
            "DBX-RS-NATIVE-LIMIT-0007",
            "Arrow IPC batch exceeded the hard row limit",
        ));
    }
    Ok(())
}

fn decode_one_batch(
    ipc_bytes: &[u8],
    query_schema: &QuerySchema,
) -> Result<RecordBatch, ConnectorError> {
    if !ipc_bytes.ends_with(&IPC_END_MARKER) {
        return Err(protocol_error(
            "DBX-RS-NATIVE-IPC-0003",
            "Arrow IPC stream is missing its end marker",
        ));
    }
    let mut reader = StreamReader::try_new(Cursor::new(ipc_bytes), None).map_err(|_| {
        protocol_error(
            "DBX-RS-NATIVE-IPC-0003",
            "Arrow IPC stream could not be decoded",
        )
    })?;
    validate_arrow_schema(query_schema, reader.schema().as_ref())?;
    let batch = reader
        .next()
        .transpose()
        .map_err(|_| {
            protocol_error(
                "DBX-RS-NATIVE-IPC-0003",
                "Arrow IPC record batch could not be decoded",
            )
        })?
        .ok_or_else(|| {
            protocol_error(
                "DBX-RS-NATIVE-IPC-0003",
                "Arrow IPC stream did not contain a record batch",
            )
        })?;
    match reader.next().transpose() {
        Ok(None) => {}
        Ok(Some(_)) => Err(protocol_error(
            "DBX-RS-NATIVE-IPC-0003",
            "Arrow IPC stream contained more than one record batch",
        ))?,
        Err(_) => {
            return Err(protocol_error(
                "DBX-RS-NATIVE-IPC-0003",
                "Arrow IPC stream contained malformed trailing data",
            ));
        }
    }
    let encoded_len = u64::try_from(ipc_bytes.len()).map_err(|_| {
        protocol_error(
            "DBX-RS-NATIVE-IPC-0003",
            "Arrow IPC stream length could not be represented",
        )
    })?;
    if reader.get_ref().position() != encoded_len {
        return Err(protocol_error(
            "DBX-RS-NATIVE-IPC-0003",
            "Arrow IPC stream contained bytes after its end marker",
        ));
    }
    Ok(batch)
}

fn reject_duplicate_fields(schema: &QuerySchema) -> Result<(), ConnectorError> {
    let mut names = HashSet::with_capacity(schema.fields.len());
    if schema
        .fields
        .iter()
        .any(|field| !names.insert(field.name.as_str()))
    {
        return Err(conversion_error(
            "DBX-RS-NATIVE-SCHEMA-0002",
            "query output contains duplicate field names",
        ));
    }
    Ok(())
}

fn validate_arrow_schema(
    query_schema: &QuerySchema,
    arrow_schema: &Schema,
) -> Result<(), ConnectorError> {
    reject_duplicate_fields(query_schema)?;
    let mut arrow_names = HashSet::with_capacity(arrow_schema.fields().len());
    if arrow_schema
        .fields()
        .iter()
        .any(|field| !arrow_names.insert(field.name().as_str()))
    {
        return Err(conversion_error(
            "DBX-RS-NATIVE-SCHEMA-0002",
            "Arrow IPC contains duplicate field names",
        ));
    }
    if query_schema.fields.len() != arrow_schema.fields().len() {
        return Err(protocol_error(
            "DBX-RS-NATIVE-SCHEMA-0003",
            "Arrow IPC field count did not match the declared schema",
        ));
    }
    for (declared, arrow) in query_schema.fields.iter().zip(arrow_schema.fields()) {
        if declared.name != *arrow.name()
            || declared.nullable != arrow.is_nullable()
            || !arrow_type_matches(&declared.field_type, arrow.data_type())
        {
            return Err(protocol_error(
                "DBX-RS-NATIVE-SCHEMA-0004",
                "Arrow IPC field did not match the declared schema",
            ));
        }
    }
    Ok(())
}

fn arrow_type_matches(field_type: &FieldType, data_type: &DataType) -> bool {
    match field_type {
        FieldType::Boolean => data_type == &DataType::Boolean,
        FieldType::Int8 => data_type == &DataType::Int8,
        FieldType::Int16 => data_type == &DataType::Int16,
        FieldType::Int32 => data_type == &DataType::Int32,
        FieldType::Int64 => data_type == &DataType::Int64,
        FieldType::UInt32 => data_type == &DataType::UInt32,
        FieldType::Float32 => data_type == &DataType::Float32,
        FieldType::Float64 => data_type == &DataType::Float64,
        FieldType::Utf8 | FieldType::Uuid | FieldType::Json => data_type == &DataType::Utf8,
        FieldType::Binary => data_type == &DataType::Binary,
        FieldType::Decimal128 { precision, scale } => {
            data_type == &DataType::Decimal128(*precision, *scale)
        }
        FieldType::Date32 => data_type == &DataType::Date32,
        FieldType::Time64Microsecond => data_type == &DataType::Time64(TimeUnit::Microsecond),
        FieldType::TimestampMicrosecond => {
            data_type == &DataType::Timestamp(TimeUnit::Microsecond, None)
        }
        FieldType::TimestampMicrosecondUtc => {
            data_type == &DataType::Timestamp(TimeUnit::Microsecond, Some(Arc::<str>::from("UTC")))
        }
    }
}

fn materialize_row(
    batch: &RecordBatch,
    schema: &QuerySchema,
    row: usize,
) -> Result<Vec<u8>, ConnectorError> {
    let mut output = Vec::new();
    output.push(b'{');
    for (index, field) in schema.fields.iter().enumerate() {
        if index != 0 {
            output.push(b',');
        }
        write_json(&mut output, &field.name)?;
        output.push(b':');
        write_field_value(&mut output, batch.column(index).as_ref(), field, row)?;
    }
    output.push(b'}');
    Ok(output)
}

fn write_field_value(
    output: &mut Vec<u8>,
    array: &dyn Array,
    field: &FieldDescriptor,
    row: usize,
) -> Result<(), ConnectorError> {
    if array.is_null(row) {
        output.extend_from_slice(b"null");
        return Ok(());
    }

    match field.field_type {
        FieldType::Boolean => {
            write_array_value::<BooleanArray, _>(array, row, |a, r| write_json(output, &a.value(r)))
        }
        FieldType::Int8 => {
            write_array_value::<Int8Array, _>(array, row, |a, r| write_json(output, &a.value(r)))
        }
        FieldType::Int16 => {
            write_array_value::<Int16Array, _>(array, row, |a, r| write_json(output, &a.value(r)))
        }
        FieldType::Int32 => {
            write_array_value::<Int32Array, _>(array, row, |a, r| write_json(output, &a.value(r)))
        }
        FieldType::Int64 => {
            write_array_value::<Int64Array, _>(array, row, |a, r| write_json(output, &a.value(r)))
        }
        FieldType::UInt32 => {
            write_array_value::<UInt32Array, _>(array, row, |a, r| write_json(output, &a.value(r)))
        }
        FieldType::Float32 => write_array_value::<Float32Array, _>(array, row, |a, r| {
            write_finite_float(output, f64::from(a.value(r)))
        }),
        FieldType::Float64 => write_array_value::<Float64Array, _>(array, row, |a, r| {
            write_finite_float(output, a.value(r))
        }),
        FieldType::Utf8 | FieldType::Uuid => {
            write_array_value::<StringArray, _>(array, row, |a, r| write_json(output, a.value(r)))
        }
        FieldType::Binary => write_array_value::<BinaryArray, _>(array, row, |a, r| {
            write_json(output, &postgres_binary(a.value(r)))
        }),
        FieldType::Json => write_array_value::<StringArray, _>(array, row, |a, r| {
            let raw = RawValue::from_string(a.value(r).to_owned()).map_err(|_| {
                conversion_error(
                    "DBX-RS-NATIVE-CONVERT-0003",
                    "JSON field contained an invalid JSON value",
                )
            })?;
            output.extend_from_slice(raw.get().as_bytes());
            Ok(())
        }),
        FieldType::Decimal128 { scale, .. } => {
            write_array_value::<Decimal128Array, _>(array, row, |a, r| {
                write_json(output, &format_decimal(a.value(r), scale))
            })
        }
        FieldType::Date32 => write_array_value::<Date32Array, _>(array, row, |a, r| {
            let date = date32_to_datetime(a.value(r)).ok_or_else(temporal_overflow)?;
            write_json(output, &date.format("%Y-%m-%d").to_string())
        }),
        FieldType::Time64Microsecond => {
            write_array_value::<Time64MicrosecondArray, _>(array, row, |a, r| {
                let time = time64us_to_time(a.value(r)).ok_or_else(temporal_overflow)?;
                write_json(output, &time.format("%H:%M:%S%.6f").to_string())
            })
        }
        FieldType::TimestampMicrosecond => {
            write_array_value::<TimestampMicrosecondArray, _>(array, row, |a, r| {
                let timestamp =
                    timestamp_us_to_datetime(a.value(r)).ok_or_else(temporal_overflow)?;
                write_json(
                    output,
                    &timestamp.format("%Y-%m-%dT%H:%M:%S%.6f").to_string(),
                )
            })
        }
        FieldType::TimestampMicrosecondUtc => {
            write_array_value::<TimestampMicrosecondArray, _>(array, row, |a, r| {
                let timestamp =
                    timestamp_us_to_datetime(a.value(r)).ok_or_else(temporal_overflow)?;
                write_json(
                    output,
                    &format!("{}Z", timestamp.format("%Y-%m-%dT%H:%M:%S%.6f")),
                )
            })
        }
    }
}

fn write_array_value<A, F>(array: &dyn Array, row: usize, writer: F) -> Result<(), ConnectorError>
where
    A: Array + 'static,
    F: FnOnce(&A, usize) -> Result<(), ConnectorError>,
{
    let typed = array.as_any().downcast_ref::<A>().ok_or_else(|| {
        protocol_error(
            "DBX-RS-NATIVE-SCHEMA-0005",
            "Arrow array type did not match its declared field",
        )
    })?;
    writer(typed, row)
}

fn write_json<T: ?Sized + Serialize>(
    output: &mut Vec<u8>,
    value: &T,
) -> Result<(), ConnectorError> {
    serde_json::to_writer(output, value).map_err(|_| {
        conversion_error(
            "DBX-RS-NATIVE-CONVERT-0001",
            "field could not be encoded as JSON",
        )
    })
}

fn write_finite_float(output: &mut Vec<u8>, value: f64) -> Result<(), ConnectorError> {
    if !value.is_finite() {
        return Err(conversion_error(
            "DBX-RS-NATIVE-CONVERT-0002",
            "non-finite floating-point values cannot be encoded as JSON",
        ));
    }
    write_json(output, &value)
}

fn postgres_binary(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(2 + bytes.len().saturating_mul(2));
    encoded.push('\\');
    encoded.push('x');
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn format_decimal(value: i128, scale: i8) -> String {
    use std::cmp::Ordering;

    let negative = value.is_negative();
    let digits = value.unsigned_abs().to_string();
    let mut formatted = match scale.cmp(&0) {
        Ordering::Greater => {
            let scale = usize::try_from(scale).unwrap_or_default();
            if digits.len() <= scale {
                let mut value = String::with_capacity(scale.saturating_add(2));
                value.push_str("0.");
                value.extend(std::iter::repeat_n('0', scale - digits.len()));
                value.push_str(&digits);
                value
            } else {
                let split = digits.len() - scale;
                format!("{}.{}", &digits[..split], &digits[split..])
            }
        }
        Ordering::Less => {
            let zeros = usize::from(scale.unsigned_abs());
            let mut value = String::with_capacity(digits.len().saturating_add(zeros));
            value.push_str(&digits);
            value.extend(std::iter::repeat_n('0', zeros));
            value
        }
        Ordering::Equal => digits,
    };
    if negative {
        formatted.insert(0, '-');
    }
    formatted
}

fn validate_execution_result(
    request_id: &str,
    executed: &ExecutionResult,
    materialized: &MaterializedResult,
) -> Result<(), ConnectorError> {
    if executed.request_id != request_id
        || executed.rows_read != materialized.rows
        || executed.batches_emitted != materialized.batches
        || executed.ipc_bytes_emitted != materialized.ipc_bytes
        || executed.schema != materialized.schema
    {
        return Err(protocol_error(
            "DBX-RS-NATIVE-PROTOCOL-0002",
            "connector execution result did not match emitted Arrow IPC",
        ));
    }
    Ok(())
}

fn validate_scan_progress(
    cursor: Option<&TimestampIdCursorRequest>,
    executed: &ExecutionResult,
    materialized: &MaterializedResult,
) -> Result<(), ConnectorError> {
    let Some(cursor) = cursor else {
        return Ok(());
    };
    if executed.truncated && materialized.scan_resume.is_none() {
        return Err(limit_error(
            "DBX-RS-NATIVE-CURSOR-0012",
            "truncated cursor page did not produce a scan resume position",
        ));
    }
    if let (Some(previous), Some(resume)) = (cursor.resume_after, materialized.scan_resume)
        && resume.position_cmp(&previous) != Ordering::Greater
    {
        return Err(protocol_error(
            "DBX-RS-NATIVE-CURSOR-0013",
            "cursor page did not advance beyond its scan resume position",
        ));
    }
    Ok(())
}

fn temporal_overflow() -> ConnectorError {
    conversion_error(
        "DBX-RS-NATIVE-CONVERT-0004",
        "temporal field was outside the supported range",
    )
}

fn configuration_error(code: &'static str, message: &'static str) -> ConnectorError {
    error(code, ErrorClass::Configuration, message, true)
}

fn protocol_error(code: &'static str, message: &'static str) -> ConnectorError {
    error(code, ErrorClass::Protocol, message, false)
}

fn conversion_error(code: &'static str, message: &'static str) -> ConnectorError {
    error(code, ErrorClass::Conversion, message, false)
}

fn limit_error(code: &'static str, message: &'static str) -> ConnectorError {
    error(code, ErrorClass::Query, message, false)
}

fn operation_timeout() -> ConnectorError {
    ConnectorError::new(
        "DBX-RS-NATIVE-TIMEOUT-0001",
        ErrorClass::Timeout,
        "native connector collection exceeded its end-to-end timeout",
        true,
        false,
    )
}

fn error(
    code: &'static str,
    class: ErrorClass,
    message: &'static str,
    configuration_error: bool,
) -> ConnectorError {
    ConnectorError::new(code, class, message, false, configuration_error)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use super::*;
    use arrow_array::{
        BinaryArray, BooleanArray, Date32Array, Decimal128Array, Int64Array, StringArray,
        Time64MicrosecondArray, TimestampMicrosecondArray,
    };
    use arrow_ipc::writer::StreamWriter;
    use arrow_schema::Field;
    use dbx_rs_connector_sdk::{
        CONNECTOR_CONTRACT_VERSION, ConnectionConfig, ConnectorFuture, CursorNullPolicy,
        FieldDescriptor, TimestampIdCursorSpec, TlsMode,
    };

    fn connection() -> ConnectionConfig {
        ConnectionConfig {
            connector_id: "postgres".into(),
            host: "private-db.example".into(),
            port: 5432,
            database: "private_database".into(),
            username: "private_user".into(),
            tls_mode: TlsMode::VerifyFull,
            tls_server_name: None,
            tls_ca_pem: None,
            connect_timeout: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(1),
        }
    }

    fn descriptor(name: &str, field_type: FieldType, nullable: bool) -> FieldDescriptor {
        FieldDescriptor {
            name: name.into(),
            field_type,
            nullable,
            source_type: "test".into(),
        }
    }

    fn materialization_limits(max_rows: u64) -> ExecutionLimits {
        ExecutionLimits {
            max_rows,
            max_batch_rows: MAX_BATCH_ROWS,
            max_batch_bytes: MAX_BATCH_BYTES,
            max_total_ipc_bytes: MAX_TOTAL_IPC_BYTES,
            timeout: Duration::from_secs(1),
        }
    }

    fn materialization_options(
        schema: QuerySchema,
        max_rows: u64,
        max_output_bytes: u64,
        cursor: Option<TimestampIdCursorRequest>,
        cancellation: CancellationToken,
    ) -> MaterializationOptions {
        MaterializationOptions {
            request_id: "request-1".into(),
            expected_schema: schema,
            limits: materialization_limits(max_rows),
            max_output_bytes,
            cursor,
            cancellation,
        }
    }

    fn collection_request(
        max_rows: u64,
        max_bytes: u64,
        timeout: Duration,
    ) -> JsonCollectionRequest {
        JsonCollectionRequest {
            request_id: "request-1".into(),
            connection: connection(),
            query: QueryText::new("SELECT 1"),
            max_rows,
            max_bytes,
            timeout,
            cursor: None,
        }
    }

    fn cursor_request(
        committed: Option<TimestampIdCursor>,
        overlap: Duration,
    ) -> TimestampIdCursorRequest {
        TimestampIdCursorRequest {
            spec: TimestampIdCursorSpec {
                timestamp_field: "updated_at".into(),
                id_field: "id".into(),
                overlap,
                null_policy: CursorNullPolicy::Reject,
            },
            committed,
            resume_after: None,
        }
    }

    fn cursor_schema() -> QuerySchema {
        QuerySchema {
            fields: vec![
                descriptor("updated_at", FieldType::TimestampMicrosecondUtc, true),
                descriptor("id", FieldType::Int64, true),
            ],
        }
    }

    fn cursor_batch(timestamps: Vec<Option<i64>>, ids: Vec<Option<i64>>) -> RecordBatch {
        RecordBatch::try_new(
            Arc::new(Schema::new(vec![
                Field::new(
                    "updated_at",
                    DataType::Timestamp(TimeUnit::Microsecond, Some(Arc::<str>::from("UTC"))),
                    true,
                ),
                Field::new("id", DataType::Int64, true),
            ])),
            vec![
                Arc::new(TimestampMicrosecondArray::from(timestamps).with_timezone("UTC")),
                Arc::new(Int64Array::from(ids)),
            ],
        )
        .expect("cursor batch must be valid")
    }

    struct TimeoutConnector {
        prepare_delay: Duration,
        execute_timeout_millis: AtomicU64,
        cleanup_observed: AtomicBool,
    }

    impl TimeoutConnector {
        fn new(prepare_delay: Duration) -> Self {
            Self {
                prepare_delay,
                execute_timeout_millis: AtomicU64::new(0),
                cleanup_observed: AtomicBool::new(false),
            }
        }
    }

    impl Connector for TimeoutConnector {
        fn descriptor(&self) -> ConnectorDescriptor {
            ConnectorDescriptor {
                contract_version: CONNECTOR_CONTRACT_VERSION,
                connector_id: "postgres".into(),
                connector_version: "test".into(),
                database_families: Vec::new(),
                capabilities: Vec::new(),
                authentication_methods: Vec::new(),
                build_id: "test".into(),
            }
        }

        fn validate(&self, _request: &ValidationRequest) -> ValidationReport {
            ValidationReport::default()
        }

        fn probe<'a>(
            &'a self,
            _request: ProbeRequest,
            _secret: &'a ResolvedSecret,
            _cancellation: CancellationToken,
        ) -> ConnectorFuture<'a, ProbeReport> {
            Box::pin(async {
                Err(configuration_error(
                    "DBX-RS-NATIVE-TEST-0001",
                    "probe is not implemented by the timeout test connector",
                ))
            })
        }

        fn prepare<'a>(
            &'a self,
            request: PrepareRequest,
            _secret: &'a ResolvedSecret,
            cancellation: CancellationToken,
        ) -> ConnectorFuture<'a, PreparedQuery> {
            Box::pin(async move {
                tokio::select! {
                    () = cancellation.cancelled() => {
                        Err(ConnectorError::cancelled("DBX-RS-NATIVE-TEST-CANCELLED-0001"))
                    }
                    () = tokio::time::sleep(self.prepare_delay) => {
                        Ok(PreparedQuery {
                            request_id: request.request_id,
                            connector_id: request.connection.connector_id,
                            schema: QuerySchema::default(),
                        })
                    }
                }
            })
        }

        fn execute<'a>(
            &'a self,
            request: ExecuteRequest,
            _secret: &'a ResolvedSecret,
            _batch_tx: mpsc::Sender<ArrowIpcBatch>,
            cancellation: CancellationToken,
        ) -> ConnectorFuture<'a, ExecutionResult> {
            self.execute_timeout_millis.store(
                u64::try_from(request.limits.timeout.as_millis()).unwrap_or(u64::MAX),
                Ordering::SeqCst,
            );
            Box::pin(async move {
                cancellation.cancelled().await;
                self.cleanup_observed.store(true, Ordering::SeqCst);
                Err(ConnectorError::cancelled(
                    "DBX-RS-NATIVE-TEST-CANCELLED-0002",
                ))
            })
        }
    }

    fn encode_batch(batch: &RecordBatch) -> Vec<u8> {
        let mut encoded = Vec::new();
        let mut writer = StreamWriter::try_new(&mut encoded, batch.schema_ref())
            .expect("stream writer must initialize");
        writer.write(batch).expect("batch must encode");
        writer.finish().expect("stream must finish");
        drop(writer);
        encoded
    }

    #[test]
    fn request_debug_redacts_connection_and_query() {
        let request = JsonCollectionRequest {
            request_id: "request-1".into(),
            connection: connection(),
            query: QueryText::new("select private_value from secret_table"),
            max_rows: 10,
            max_bytes: 1_000,
            timeout: Duration::from_secs(1),
            cursor: None,
        };

        let debug = format!("{request:?}");
        assert!(debug.contains("request-1"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("private_value"));
        assert!(!debug.contains("private-db"));
        assert!(!debug.contains("private_database"));
        assert!(!debug.contains("private_user"));
    }

    #[test]
    fn request_debug_redacts_cursor_fields_and_values() {
        let mut request = collection_request(10, 1_000, Duration::from_secs(1));
        request.cursor = Some(cursor_request(
            Some(TimestampIdCursor::new(1_234_567, 987_654)),
            Duration::from_secs(1),
        ));

        let debug = format!("{request:?}");

        assert!(debug.contains("[CONFIGURED]"));
        assert!(!debug.contains("updated_at"));
        assert!(!debug.contains("1234567"));
        assert!(!debug.contains("987654"));
    }

    #[test]
    fn cursor_tracker_accepts_equal_timestamps_with_increasing_ids() {
        let schema = cursor_schema();
        let request = cursor_request(Some(TimestampIdCursor::new(10, 1)), Duration::ZERO);
        let mut tracker = CursorTracker::new(Some(&request), &schema)
            .expect("cursor must validate")
            .expect("cursor tracker must exist");
        let batch = cursor_batch(
            vec![Some(10), Some(10), Some(11)],
            vec![Some(2), Some(3), Some(i64::MIN)],
        );

        for row in 0..batch.num_rows() {
            let value = tracker
                .validate_row(&batch, row)
                .expect("strict tuple must validate");
            tracker.record_emitted(value);
        }

        assert_eq!(
            tracker.candidate(),
            Some(TimestampIdCursor::new(11, i64::MIN))
        );
    }

    #[test]
    fn cursor_tracker_rejects_null_duplicate_and_regressing_tuples() {
        let schema = cursor_schema();
        let request = cursor_request(None, Duration::ZERO);
        let mut tracker = CursorTracker::new(Some(&request), &schema)
            .expect("cursor must validate")
            .expect("cursor tracker must exist");
        let null_batch = cursor_batch(vec![None], vec![Some(1)]);
        assert_eq!(
            tracker
                .validate_row(&null_batch, 0)
                .expect_err("null cursor must fail")
                .code(),
            "DBX-RS-NATIVE-CURSOR-0009"
        );

        let ordered = cursor_batch(vec![Some(10)], vec![Some(2)]);
        let first = tracker
            .validate_row(&ordered, 0)
            .expect("first cursor must validate");
        tracker.record_emitted(first);
        let duplicate = cursor_batch(vec![Some(10)], vec![Some(2)]);
        assert_eq!(
            tracker
                .validate_row(&duplicate, 0)
                .expect_err("duplicate cursor must fail")
                .code(),
            "DBX-RS-NATIVE-CURSOR-0011"
        );
        let regression = cursor_batch(vec![Some(9)], vec![Some(999)]);
        assert_eq!(
            tracker
                .validate_row(&regression, 0)
                .expect_err("regressing cursor must fail")
                .code(),
            "DBX-RS-NATIVE-CURSOR-0011"
        );
    }

    #[test]
    fn cursor_tracker_enforces_schema_and_exact_overlap_boundary() {
        let mut schema = cursor_schema();
        schema.fields[0].field_type = FieldType::TimestampMicrosecond;
        let request = cursor_request(None, Duration::ZERO);
        assert_eq!(
            CursorTracker::new(Some(&request), &schema)
                .err()
                .expect("local timestamp cursor must fail")
                .code(),
            "DBX-RS-NATIVE-CURSOR-0005"
        );

        let schema = cursor_schema();
        let request = cursor_request(
            Some(TimestampIdCursor::new(1_000_000, 50)),
            Duration::from_secs(1),
        );
        let tracker = CursorTracker::new(Some(&request), &schema)
            .expect("overlap cursor must validate")
            .expect("cursor tracker must exist");
        let boundary = cursor_batch(vec![Some(0)], vec![Some(i64::MIN)]);

        assert_eq!(
            tracker
                .validate_row(&boundary, 0)
                .expect("inclusive overlap boundary must not skip minimum ID"),
            TimestampIdCursor::new(0, i64::MIN)
        );
    }

    #[test]
    fn execution_limits_follow_output_limits_and_bound_variable_rows() {
        let variable_schema = QuerySchema {
            fields: vec![descriptor("value", FieldType::Utf8, false)],
        };
        let small_request = collection_request(10, 100, Duration::from_secs(30));
        let small = execution_limits(&small_request, &variable_schema, Duration::from_secs(20))
            .expect("valid limits must be derived");

        assert_eq!(small.max_rows, 10);
        assert_eq!(small.max_batch_rows, 1);
        assert_eq!(small.max_batch_bytes, 100 + IPC_FRAME_OVERHEAD_BYTES);
        assert_eq!(
            small.max_total_ipc_bytes,
            100 + 10 * IPC_FRAME_OVERHEAD_BYTES
        );
        assert_eq!(small.timeout, Duration::from_secs(20));

        let fixed_schema = QuerySchema {
            fields: vec![descriptor("value", FieldType::Int64, false)],
        };
        let large = execution_limits(
            &collection_request(100_000, 1024 * 1024 * 1024, Duration::from_secs(30)),
            &fixed_schema,
            Duration::from_secs(1),
        )
        .expect("hard-capped limits must be derived");
        assert_eq!(large.max_batch_rows, MAX_BATCH_ROWS);
        assert_eq!(large.max_batch_bytes, MAX_BATCH_BYTES);
        assert_eq!(
            large.max_total_ipc_bytes,
            1024 * 1024 * 1024
                + 100_000_u64.div_ceil(u64::from(MAX_BATCH_ROWS)) * IPC_FRAME_OVERHEAD_BYTES
        );
        assert!(large.max_total_ipc_bytes < MAX_TOTAL_IPC_BYTES);
    }

    #[test]
    fn collection_timeout_above_the_hard_limit_is_rejected() {
        let request = collection_request(1, 1024, MAX_COLLECTION_TIMEOUT + Duration::from_secs(1));

        let error = validate_collection_request(&request).expect_err("timeout must be bounded");

        assert_eq!(error.code(), "DBX-RS-NATIVE-CFG-0006");
    }

    #[test]
    fn decimal_and_binary_formatting_is_exact() {
        assert_eq!(format_decimal(1_234, 2), "12.34");
        assert_eq!(format_decimal(-1, 2), "-0.01");
        assert_eq!(format_decimal(12, -2), "1200");
        assert_eq!(format_decimal(i128::MIN, 0), i128::MIN.to_string());
        assert_eq!(postgres_binary(&[0, 0xaf, 0xff]), "\\x00afff");
    }

    #[test]
    fn decode_and_materialize_preserves_logical_types_and_nulls() {
        let fields = vec![
            descriptor("ok", FieldType::Boolean, true),
            descriptor("count", FieldType::Int64, false),
            descriptor("label", FieldType::Utf8, false),
            descriptor("data", FieldType::Binary, false),
            descriptor("document", FieldType::Json, false),
            descriptor(
                "amount",
                FieldType::Decimal128 {
                    precision: 10,
                    scale: 2,
                },
                false,
            ),
            descriptor("day", FieldType::Date32, false),
            descriptor("clock", FieldType::Time64Microsecond, false),
            descriptor("local_time", FieldType::TimestampMicrosecond, false),
            descriptor("utc_time", FieldType::TimestampMicrosecondUtc, false),
        ];
        let schema = QuerySchema { fields };
        let arrow_schema = Arc::new(Schema::new(vec![
            Field::new("ok", DataType::Boolean, true),
            Field::new("count", DataType::Int64, false),
            Field::new("label", DataType::Utf8, false),
            Field::new("data", DataType::Binary, false),
            Field::new("document", DataType::Utf8, false),
            Field::new("amount", DataType::Decimal128(10, 2), false),
            Field::new("day", DataType::Date32, false),
            Field::new("clock", DataType::Time64(TimeUnit::Microsecond), false),
            Field::new(
                "local_time",
                DataType::Timestamp(TimeUnit::Microsecond, None),
                false,
            ),
            Field::new(
                "utc_time",
                DataType::Timestamp(TimeUnit::Microsecond, Some(Arc::from("UTC"))),
                false,
            ),
        ]));
        let batch = RecordBatch::try_new(
            arrow_schema,
            vec![
                Arc::new(BooleanArray::from(vec![None])),
                Arc::new(Int64Array::from(vec![42])),
                Arc::new(StringArray::from(vec!["quoted \"label\""])),
                Arc::new(BinaryArray::from(vec![&b"\0\xaf"[..]])),
                Arc::new(StringArray::from(vec![r#"{"nested":true}"#])),
                Arc::new(
                    Decimal128Array::from(vec![1_234])
                        .with_precision_and_scale(10, 2)
                        .expect("decimal metadata must be valid"),
                ),
                Arc::new(Date32Array::from(vec![0])),
                Arc::new(Time64MicrosecondArray::from(vec![1_234_567])),
                Arc::new(TimestampMicrosecondArray::from(vec![0])),
                Arc::new(TimestampMicrosecondArray::from(vec![0]).with_timezone("UTC")),
            ],
        )
        .expect("test batch must be valid");
        let encoded = encode_batch(&batch);
        let decoded = decode_one_batch(&encoded, &schema).expect("IPC must decode");
        let line = materialize_row(&decoded, &schema, 0).expect("row must materialize");

        assert_eq!(
            String::from_utf8(line).expect("JSON output must be UTF-8"),
            r#"{"ok":null,"count":42,"label":"quoted \"label\"","data":"\\x00af","document":{"nested":true},"amount":"12.34","day":"1970-01-01","clock":"00:00:01.234567","local_time":"1970-01-01T00:00:00.000000","utc_time":"1970-01-01T00:00:00.000000Z"}"#
        );
    }

    #[test]
    fn malformed_json_and_non_finite_floats_fail_closed() {
        let json_schema = QuerySchema {
            fields: vec![descriptor("document", FieldType::Json, false)],
        };
        let json_batch = RecordBatch::try_new(
            Arc::new(Schema::new(vec![Field::new(
                "document",
                DataType::Utf8,
                false,
            )])),
            vec![Arc::new(StringArray::from(vec!["not-json"]))],
        )
        .expect("test batch must be valid");
        let json_error =
            materialize_row(&json_batch, &json_schema, 0).expect_err("invalid JSON must fail");
        assert_eq!(json_error.code(), "DBX-RS-NATIVE-CONVERT-0003");

        let float_schema = QuerySchema {
            fields: vec![descriptor("value", FieldType::Float64, false)],
        };
        let float_batch = RecordBatch::try_new(
            Arc::new(Schema::new(vec![Field::new(
                "value",
                DataType::Float64,
                false,
            )])),
            vec![Arc::new(Float64Array::from(vec![f64::NAN]))],
        )
        .expect("test batch must be valid");
        let float_error = materialize_row(&float_batch, &float_schema, 0)
            .expect_err("non-finite float must fail");
        assert_eq!(float_error.code(), "DBX-RS-NATIVE-CONVERT-0002");
    }

    #[test]
    fn duplicate_fields_and_multiple_batches_are_rejected() {
        let duplicate = QuerySchema {
            fields: vec![
                descriptor("same", FieldType::Int64, false),
                descriptor("same", FieldType::Int64, false),
            ],
        };
        assert_eq!(
            reject_duplicate_fields(&duplicate)
                .expect_err("duplicate fields must fail")
                .code(),
            "DBX-RS-NATIVE-SCHEMA-0002"
        );

        let schema = QuerySchema {
            fields: vec![descriptor("value", FieldType::Int64, false)],
        };
        let batch = RecordBatch::try_new(
            Arc::new(Schema::new(vec![Field::new(
                "value",
                DataType::Int64,
                false,
            )])),
            vec![Arc::new(Int64Array::from(vec![1]))],
        )
        .expect("test batch must be valid");
        let mut encoded = Vec::new();
        let mut writer = StreamWriter::try_new(&mut encoded, batch.schema_ref())
            .expect("stream writer must initialize");
        writer.write(&batch).expect("first batch must encode");
        writer.write(&batch).expect("second batch must encode");
        writer.finish().expect("stream must finish");
        drop(writer);

        assert_eq!(
            decode_one_batch(&encoded, &schema)
                .expect_err("multiple batches must fail")
                .code(),
            "DBX-RS-NATIVE-IPC-0003"
        );
    }

    #[test]
    fn ipc_bytes_after_the_consumed_end_marker_are_rejected() {
        let schema = QuerySchema {
            fields: vec![descriptor("value", FieldType::Int64, false)],
        };
        let batch = RecordBatch::try_new(
            Arc::new(Schema::new(vec![Field::new(
                "value",
                DataType::Int64,
                false,
            )])),
            vec![Arc::new(Int64Array::from(vec![1]))],
        )
        .expect("test batch must be valid");
        let mut encoded = encode_batch(&batch);
        encoded.extend_from_slice(b"unconsumed trailing bytes");
        encoded.extend_from_slice(&IPC_END_MARKER);

        let error = decode_one_batch(&encoded, &schema)
            .expect_err("bytes after the consumed stream must fail");
        assert_eq!(error.code(), "DBX-RS-NATIVE-IPC-0003");
    }

    #[tokio::test]
    async fn materializer_counts_newlines_and_honors_output_limit() {
        let schema = QuerySchema {
            fields: vec![descriptor("value", FieldType::Int64, false)],
        };
        let batch = RecordBatch::try_new(
            Arc::new(Schema::new(vec![Field::new(
                "value",
                DataType::Int64,
                false,
            )])),
            vec![Arc::new(Int64Array::from(vec![1]))],
        )
        .expect("test batch must be valid");
        let encoded = encode_batch(&batch);
        let envelope = ArrowIpcBatch {
            request_id: "request-1".into(),
            sequence: 0,
            row_count: 1,
            schema: schema.clone(),
            ipc_bytes: encoded,
        };
        let (batch_tx, batch_rx) = mpsc::channel(1);
        let (line_tx, mut line_rx) = mpsc::channel(1);
        batch_tx.send(envelope).await.expect("batch must send");
        drop(batch_tx);

        let result = materialize_batches(
            batch_rx,
            line_tx,
            materialization_options(schema, 1, 12, None, CancellationToken::new()),
        )
        .await
        .expect("batch must materialize");
        assert_eq!(result.rows, 1);
        assert_eq!(result.ndjson_bytes, 12);
        assert_eq!(
            line_rx.recv().await.map(JsonRow::into_parts),
            Some((br#"{"value":1}"#.to_vec(), None))
        );
    }

    #[tokio::test]
    async fn materializer_returns_candidate_only_after_rows_are_emitted() {
        let schema = cursor_schema();
        let batch = cursor_batch(
            vec![Some(10), Some(10), Some(11)],
            vec![Some(2), Some(3), Some(-1)],
        );
        let envelope = ArrowIpcBatch {
            request_id: "request-1".into(),
            sequence: 0,
            row_count: 3,
            schema: schema.clone(),
            ipc_bytes: encode_batch(&batch),
        };
        let (batch_tx, batch_rx) = mpsc::channel(1);
        let (line_tx, mut line_rx) = mpsc::channel(3);
        batch_tx.send(envelope).await.expect("batch must send");
        drop(batch_tx);

        let result = materialize_batches(
            batch_rx,
            line_tx,
            materialization_options(
                schema,
                3,
                1024,
                Some(cursor_request(
                    Some(TimestampIdCursor::new(10, 1)),
                    Duration::ZERO,
                )),
                CancellationToken::new(),
            ),
        )
        .await
        .expect("cursor batch must materialize");

        assert_eq!(result.rows, 3);
        assert_eq!(
            result.checkpoint_candidate,
            Some(TimestampIdCursor::new(11, -1))
        );
        assert_eq!(result.scan_resume, Some(TimestampIdCursor::new(11, -1)));
        assert_eq!(
            line_rx.recv().await.and_then(|row| row.cursor()),
            Some(TimestampIdCursor::new(10, 2))
        );
        assert_eq!(
            line_rx.recv().await.and_then(|row| row.cursor()),
            Some(TimestampIdCursor::new(10, 3))
        );
        assert_eq!(
            line_rx.recv().await.and_then(|row| row.cursor()),
            Some(TimestampIdCursor::new(11, -1))
        );
    }

    #[test]
    fn overlap_scan_resume_continues_exclusively_without_reapplying_overlap() {
        let schema = cursor_schema();
        let committed = TimestampIdCursor::new(10, 5);
        let mut first = CursorTracker::new(
            Some(&cursor_request(Some(committed), Duration::from_secs(1))),
            &schema,
        )
        .expect("cursor must validate")
        .expect("cursor tracker must exist");
        let first_batch = cursor_batch(vec![Some(9), Some(9)], vec![Some(1), Some(2)]);
        for row in 0..first_batch.num_rows() {
            let value = first
                .validate_row(&first_batch, row)
                .expect("overlap tuple must validate");
            first.record_emitted(value);
        }
        let resume = first.scan_resume().expect("first page must have a resume");
        assert_eq!(first.candidate(), Some(committed));

        let mut request = cursor_request(Some(committed), Duration::from_secs(1));
        request.resume_after = Some(resume);
        let continuation = CursorTracker::new(Some(&request), &schema)
            .expect("continuation must validate")
            .expect("cursor tracker must exist");
        let replayed = cursor_batch(vec![Some(9)], vec![Some(2)]);
        assert_eq!(
            continuation
                .validate_row(&replayed, 0)
                .expect_err("resume tuple itself must be excluded")
                .code(),
            "DBX-RS-NATIVE-CURSOR-0010"
        );
        let next = cursor_batch(vec![Some(9)], vec![Some(3)]);
        continuation
            .validate_row(&next, 0)
            .expect("strictly later overlap tuple must continue the scan");
    }

    #[tokio::test]
    async fn materializer_observes_cancellation_while_waiting_for_a_batch() {
        let schema = QuerySchema::default();
        let (_batch_tx, batch_rx) = mpsc::channel(1);
        let (line_tx, _line_rx) = mpsc::channel(1);
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let error = materialize_batches(
            batch_rx,
            line_tx,
            materialization_options(schema, 1, 1, None, cancellation),
        )
        .await
        .expect_err("cancelled materialization must fail");

        assert_eq!(error.code(), "DBX-RS-NATIVE-CANCELLED-0001");
        assert_eq!(error.class(), ErrorClass::Cancelled);
    }

    #[tokio::test(start_paused = true)]
    async fn prepare_and_execute_share_one_timeout_and_cleanup_on_expiry() {
        let connector = Arc::new(TimeoutConnector::new(Duration::from_secs(30)));
        let request = collection_request(1, 1024, Duration::from_secs(50));
        let (line_tx, _line_rx) = mpsc::channel(1);

        let error = collect_json_rows_with_connector(
            connector.clone(),
            request,
            &ResolvedSecret::new(b"test-only".to_vec()),
            line_tx,
            CancellationToken::new(),
        )
        .await
        .expect_err("the shared deadline must expire during execute");

        assert_eq!(error.code(), "DBX-RS-NATIVE-TIMEOUT-0001");
        assert_eq!(error.class(), ErrorClass::Timeout);
        let execute_timeout = connector.execute_timeout_millis.load(Ordering::SeqCst);
        assert!(execute_timeout > 0);
        assert!(execute_timeout < 50_000);
        assert!(connector.cleanup_observed.load(Ordering::SeqCst));
    }

    #[test]
    fn bounded_connector_result_may_report_truncation() {
        let schema = QuerySchema::default();
        let executed = ExecutionResult {
            request_id: "request-1".into(),
            rows_read: 1,
            batches_emitted: 1,
            ipc_bytes_emitted: 128,
            truncated: true,
            schema: schema.clone(),
        };
        let materialized = MaterializedResult {
            rows: 1,
            ndjson_bytes: 3,
            batches: 1,
            ipc_bytes: 128,
            schema,
            checkpoint_candidate: None,
            scan_resume: None,
        };

        validate_execution_result("request-1", &executed, &materialized)
            .expect("truncation is a valid bounded result");
    }

    #[test]
    fn truncated_overlap_page_persists_a_distinct_scan_resume() {
        let schema = cursor_schema();
        let committed = TimestampIdCursor::new(10, 5);
        let cursor = cursor_request(Some(committed), Duration::from_secs(1));
        let executed = ExecutionResult {
            request_id: "request-1".into(),
            rows_read: 1,
            batches_emitted: 1,
            ipc_bytes_emitted: 128,
            truncated: true,
            schema: schema.clone(),
        };
        let materialized = MaterializedResult {
            rows: 1,
            ndjson_bytes: 3,
            batches: 1,
            ipc_bytes: 128,
            schema,
            checkpoint_candidate: Some(committed),
            scan_resume: Some(TimestampIdCursor::new(9, 99)),
        };

        validate_scan_progress(Some(&cursor), &executed, &materialized)
            .expect("a sealed page can resume even before the committed cursor");
    }

    #[test]
    fn unknown_connector_has_stable_error() {
        let error = NativeConnectorProvider::new()
            .connector("unknown")
            .err()
            .expect("unknown connector must fail");

        assert_eq!(error.code(), "DBX-RS-NATIVE-CONNECTOR-0001");
        assert_eq!(error.class(), ErrorClass::Configuration);
        assert!(error.is_configuration_error());
        assert!(!error.message().contains("unknown"));
    }
}
