use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::Write as _;
use std::io::{self, Write};
use std::sync::Arc;

use arrow_array::{
    ArrayRef, BinaryArray, BooleanArray, Date32Array, Decimal128Array, Float32Array, Float64Array,
    Int8Array, Int16Array, Int32Array, Int64Array, RecordBatch, StringArray,
    Time64MicrosecondArray, TimestampMicrosecondArray, UInt32Array,
};
use arrow_ipc::writer::StreamWriter;
use arrow_schema::{DataType, Field, Schema, SchemaRef, TimeUnit};
use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, NaiveTime, Timelike, Utc};
use dbx_rs_connector_sdk::{
    ArrowIpcBatch, ConnectorError, ErrorClass, ExecuteRequest, ExecutionResult, FieldDescriptor,
    FieldType, PrepareRequest, PreparedQuery, QuerySchema, TimestampIdCursor,
    TimestampIdCursorBound, TimestampIdCursorSpec,
};
use futures_util::TryStreamExt;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_postgres::types::{FromSql, ToSql, Type};
use tokio_postgres::{Client, Row, Statement};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{NormalizedTypedQuery, PostgresConnector, classify_query_error, normalize_typed_query};

const NUMERIC_POSITIVE: u16 = 0x0000;
const NUMERIC_NEGATIVE: u16 = 0x4000;
const NUMERIC_NAN: u16 = 0xC000;
const NUMERIC_POSITIVE_INFINITY: u16 = 0xD000;
const NUMERIC_NEGATIVE_INFINITY: u16 = 0xF000;
const NUMERIC_DISPLAY_SCALE_MASK: u16 = 0x3FFF;
const POSTGRES_TYPE_MODIFIER_HEADER_BYTES: i32 = 4;
const MAX_TYPED_BATCH_ROWS: u32 = 256;
const MAX_FIXED_BATCH_VALUE_BYTES: u64 = 256 * 1024;
const MAX_TYPED_BATCH_IPC_BYTES: u64 = 1024 * 1024;
const MAX_TYPED_TOTAL_IPC_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Clone)]
struct ColumnPlan {
    field: FieldDescriptor,
    arrow_type: DataType,
    value_type: ValueType,
}

#[derive(Clone, Copy)]
enum ValueType {
    Boolean,
    Int8,
    Int16,
    Int32,
    Int64,
    UInt32,
    Float32,
    Float64,
    Utf8,
    Binary,
    Uuid,
    Json,
    Decimal128 { precision: u8, scale: i8 },
    Date32,
    Time64Microsecond,
    TimestampMicrosecond,
    TimestampMicrosecondUtc,
}

struct PostgresCursorParameters {
    timestamp: DateTime<Utc>,
    id: i64,
}

#[derive(Clone, Copy)]
struct CursorProjection {
    timestamp_index: usize,
    id_index: usize,
}

pub(super) async fn prepare(
    request: PrepareRequest,
    secret: &dbx_rs_connector_sdk::ResolvedSecret,
    cancellation: CancellationToken,
) -> Result<PreparedQuery, ConnectorError> {
    PostgresConnector::validate_operation(&request.connection, secret)?;
    validate_prepare_request(&request)?;
    let query = normalize_typed_query(
        request.query.as_str(),
        request.max_rows,
        request.cursor.as_ref(),
    )?;
    let _cursor_parameters = postgres_cursor_parameters(query.cursor_bound)?;
    let (client, connection_task, _endpoint) = PostgresConnector::open_client(
        &request.connection,
        secret,
        "dbx-rs/postgres-prepare",
        &cancellation,
    )
    .await?;
    let operation = async {
        begin_read_only(&client, request.timeout).await?;
        let (_statement, schema, _arrow_schema, _plans, _cursor_projection) =
            prepare_typed_statement(
                &client,
                &query,
                request.cursor.as_ref().map(|cursor| &cursor.spec),
            )
            .await?;
        client
            .batch_execute("COMMIT")
            .await
            .map_err(|error| classify_query_error(&error))?;
        Ok(PreparedQuery {
            request_id: request.request_id,
            connector_id: PostgresConnector::CONNECTOR_ID.into(),
            schema,
        })
    };
    let result = tokio::select! {
        () = cancellation.cancelled() => {
            Err(ConnectorError::cancelled("DBX-RS-PG-CANCELLED-0020"))
        }
        result = timeout(request.timeout, operation) => {
            result.map_err(|_| operation_timeout("DBX-RS-PG-QUERY-0020", "PostgreSQL prepare timed out"))?
        }
    };
    drop(client);
    drop(connection_task);
    result
}

pub(super) async fn execute(
    request: ExecuteRequest,
    secret: &dbx_rs_connector_sdk::ResolvedSecret,
    batch_tx: mpsc::Sender<ArrowIpcBatch>,
    cancellation: CancellationToken,
) -> Result<ExecutionResult, ConnectorError> {
    PostgresConnector::validate_operation(&request.connection, secret)?;
    validate_execute_request(&request)?;
    let query = normalize_typed_query(
        request.query.as_str(),
        request.limits.max_rows,
        request.cursor.as_ref(),
    )?;
    let (client, connection_task, _endpoint) = PostgresConnector::open_client(
        &request.connection,
        secret,
        "dbx-rs/postgres-execute",
        &cancellation,
    )
    .await?;
    let operation_timeout_duration = request.limits.timeout;
    let operation = execute_query(&client, query, request, batch_tx);
    let result = tokio::select! {
        () = cancellation.cancelled() => {
            Err(ConnectorError::cancelled("DBX-RS-PG-CANCELLED-0021"))
        }
        result = timeout(operation_timeout_duration, operation) => {
            result.map_err(|_| operation_timeout("DBX-RS-PG-QUERY-0021", "PostgreSQL typed query timed out"))?
        }
    };
    drop(client);
    drop(connection_task);
    result
}

async fn execute_query(
    client: &Client,
    query: NormalizedTypedQuery,
    request: ExecuteRequest,
    batch_tx: mpsc::Sender<ArrowIpcBatch>,
) -> Result<ExecutionResult, ConnectorError> {
    begin_read_only(client, request.limits.timeout).await?;
    let cursor_parameters = postgres_cursor_parameters(query.cursor_bound)?;
    let (statement, query_schema, arrow_schema, plans, cursor_projection) =
        prepare_typed_statement(
            client,
            &query,
            request.cursor.as_ref().map(|cursor| &cursor.spec),
        )
        .await?;
    if request
        .expected_schema
        .as_ref()
        .is_some_and(|expected| expected != &query_schema)
    {
        return Err(conversion_error(
            "DBX-RS-PG-SCHEMA-0001",
            "PostgreSQL query schema changed before execution",
        ));
    }

    let rows = if let Some(parameters) = cursor_parameters.as_ref() {
        let parameters: [&(dyn ToSql + Sync); 2] = [&parameters.timestamp, &parameters.id];
        client
            .query_raw(&statement, parameters)
            .await
            .map_err(|error| classify_query_error(&error))?
    } else {
        client
            .query_raw(&statement, std::iter::empty::<&(dyn ToSql + Sync)>())
            .await
            .map_err(|error| classify_query_error(&error))?
    };
    tokio::pin!(rows);

    let batch_capacity = effective_batch_capacity(&request, &query_schema)?;
    let mut pending = Vec::with_capacity(batch_capacity);
    let mut rows_read = 0_u64;
    let mut sequence = 0_u64;
    let mut ipc_bytes_emitted = 0_u64;
    let mut truncated = false;
    let mut previous_cursor = None;

    while let Some(row) = rows
        .try_next()
        .await
        .map_err(|error| classify_query_error(&error))?
    {
        if let Some(projection) = cursor_projection {
            let cursor = projected_cursor(&row, projection)?;
            observe_cursor_order(&mut previous_cursor, cursor)?;
        }
        if rows_read == request.limits.max_rows {
            truncated = true;
            break;
        }
        pending.push(row);
        rows_read = rows_read.saturating_add(1);
        if pending.len() == batch_capacity {
            let emitted = emit_batch(
                &request,
                sequence,
                &query_schema,
                &arrow_schema,
                &plans,
                &pending,
                ipc_bytes_emitted,
                &batch_tx,
            )
            .await?;
            ipc_bytes_emitted = ipc_bytes_emitted.saturating_add(emitted);
            sequence = sequence.saturating_add(1);
            pending.clear();
        }
    }
    if !pending.is_empty() {
        let emitted = emit_batch(
            &request,
            sequence,
            &query_schema,
            &arrow_schema,
            &plans,
            &pending,
            ipc_bytes_emitted,
            &batch_tx,
        )
        .await?;
        ipc_bytes_emitted = ipc_bytes_emitted.saturating_add(emitted);
        sequence = sequence.saturating_add(1);
    }

    client
        .batch_execute("COMMIT")
        .await
        .map_err(|error| classify_query_error(&error))?;
    Ok(ExecutionResult {
        request_id: request.request_id,
        rows_read,
        batches_emitted: sequence,
        ipc_bytes_emitted,
        truncated,
        schema: query_schema,
    })
}

async fn prepare_typed_statement(
    client: &Client,
    query: &NormalizedTypedQuery,
    cursor_spec: Option<&TimestampIdCursorSpec>,
) -> Result<
    (
        Statement,
        QuerySchema,
        SchemaRef,
        Vec<ColumnPlan>,
        Option<CursorProjection>,
    ),
    ConnectorError,
> {
    let base_statement = client
        .prepare(&query.base)
        .await
        .map_err(|error| classify_query_error(&error))?;
    validate_base_parameters(base_statement.params())?;
    let (base_schema, _base_arrow_schema, _base_plans) = plan_columns(&base_statement)?;
    let cursor_projection = cursor_spec
        .map(|cursor_spec| validate_cursor_schema(&base_schema, cursor_spec))
        .transpose()?;

    let parameter_types = if query.cursor_bound.is_some() {
        vec![Type::TIMESTAMPTZ, Type::INT8]
    } else {
        Vec::new()
    };
    let statement = client
        .prepare_typed(&query.sql, &parameter_types)
        .await
        .map_err(|error| classify_query_error(&error))?;
    validate_cursor_parameters(statement.params(), query.cursor_bound.is_some())?;
    let (query_schema, arrow_schema, plans) = plan_columns(&statement)?;
    if query_schema != base_schema {
        return Err(conversion_error(
            "DBX-RS-PG-SCHEMA-0005",
            "PostgreSQL cursor wrapper changed the query output schema",
        ));
    }
    Ok((
        statement,
        query_schema,
        arrow_schema,
        plans,
        cursor_projection,
    ))
}

fn validate_base_parameters(parameters: &[Type]) -> Result<(), ConnectorError> {
    if !parameters.is_empty() {
        return Err(configuration_error(
            "DBX-RS-PG-CFG-0048",
            "PostgreSQL base queries cannot contain parameters",
        ));
    }
    Ok(())
}

fn validate_cursor_parameters(parameters: &[Type], has_bound: bool) -> Result<(), ConnectorError> {
    let valid = if has_bound {
        parameters == [Type::TIMESTAMPTZ, Type::INT8]
    } else {
        parameters.is_empty()
    };
    if !valid {
        return Err(conversion_error(
            "DBX-RS-PG-SCHEMA-0006",
            "PostgreSQL cursor parameter metadata did not match the typed bound",
        ));
    }
    Ok(())
}

fn validate_cursor_schema(
    schema: &QuerySchema,
    spec: &TimestampIdCursorSpec,
) -> Result<CursorProjection, ConnectorError> {
    let timestamp_fields = schema
        .fields
        .iter()
        .enumerate()
        .filter(|(_, field)| field.name == spec.timestamp_field)
        .collect::<Vec<_>>();
    let id_fields = schema
        .fields
        .iter()
        .enumerate()
        .filter(|(_, field)| field.name == spec.id_field)
        .collect::<Vec<_>>();
    if timestamp_fields.len() != 1
        || id_fields.len() != 1
        || timestamp_fields[0].1.field_type != FieldType::TimestampMicrosecondUtc
        || id_fields[0].1.field_type != FieldType::Int64
    {
        return Err(configuration_error(
            "DBX-RS-PG-CFG-0049",
            "PostgreSQL cursor requires unique TIMESTAMPTZ and BIGINT output fields",
        ));
    }
    Ok(CursorProjection {
        timestamp_index: timestamp_fields[0].0,
        id_index: id_fields[0].0,
    })
}

fn projected_cursor(
    row: &Row,
    projection: CursorProjection,
) -> Result<TimestampIdCursor, ConnectorError> {
    let timestamp = get_value::<DateTime<Utc>>(row, projection.timestamp_index)?;
    let id = get_value::<i64>(row, projection.id_index)?;
    cursor_from_native_values(timestamp, id)
}

fn cursor_from_native_values(
    timestamp: Option<DateTime<Utc>>,
    id: Option<i64>,
) -> Result<TimestampIdCursor, ConnectorError> {
    let (Some(timestamp), Some(id)) = (timestamp, id) else {
        return Err(conversion_error(
            "DBX-RS-PG-CONVERT-0035",
            "PostgreSQL cursor output contains a null value",
        ));
    };
    Ok(TimestampIdCursor::new(timestamp.timestamp_micros(), id))
}

fn observe_cursor_order(
    previous: &mut Option<TimestampIdCursor>,
    current: TimestampIdCursor,
) -> Result<(), ConnectorError> {
    if previous
        .as_ref()
        .is_some_and(|previous| current.position_cmp(previous) != Ordering::Greater)
    {
        return Err(conversion_error(
            "DBX-RS-PG-CONVERT-0036",
            "PostgreSQL cursor output is not strictly increasing",
        ));
    }
    *previous = Some(current);
    Ok(())
}

fn postgres_cursor_parameters(
    bound: Option<TimestampIdCursorBound>,
) -> Result<Option<PostgresCursorParameters>, ConnectorError> {
    bound
        .map(|bound| {
            let timestamp =
                DateTime::<Utc>::from_timestamp_micros(bound.value.timestamp_epoch_micros)
                    .ok_or_else(|| {
                        configuration_error(
                            "DBX-RS-PG-CFG-0047",
                            "PostgreSQL cursor timestamp is outside the supported range",
                        )
                    })?;
            Ok(PostgresCursorParameters {
                timestamp,
                id: bound.value.id,
            })
        })
        .transpose()
}

fn effective_batch_capacity(
    request: &ExecuteRequest,
    schema: &QuerySchema,
) -> Result<usize, ConnectorError> {
    let fixed_row_bytes = schema.fields.iter().try_fold(0_u64, |total, field| {
        field_width(&field.field_type).map(|width| total.saturating_add(width))
    });
    let schema_cap = fixed_row_bytes.map_or(1, |row_bytes| {
        MAX_FIXED_BATCH_VALUE_BYTES
            .checked_div(row_bytes.max(1))
            .unwrap_or(1)
            .clamp(1, u64::from(MAX_TYPED_BATCH_ROWS))
    });
    let batch_rows = u64::from(request.limits.max_batch_rows)
        .min(request.limits.max_rows)
        .min(schema_cap);
    usize::try_from(batch_rows).map_err(|_| {
        configuration_error(
            "DBX-RS-PG-CFG-0028",
            "typed query batch row limit is invalid for this platform",
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

#[allow(clippy::too_many_arguments)]
async fn emit_batch(
    request: &ExecuteRequest,
    sequence: u64,
    query_schema: &QuerySchema,
    arrow_schema: &SchemaRef,
    plans: &[ColumnPlan],
    rows: &[Row],
    total_ipc_bytes: u64,
    batch_tx: &mpsc::Sender<ArrowIpcBatch>,
) -> Result<u64, ConnectorError> {
    let batch = rows_to_batch(rows, plans, Arc::clone(arrow_schema))?;
    let ipc_bytes = encode_batch(&batch, request.limits.max_batch_bytes)?;
    let encoded_bytes = ipc_bytes.len() as u64;
    if total_ipc_bytes.saturating_add(encoded_bytes) > request.limits.max_total_ipc_bytes {
        return Err(ConnectorError::new(
            "DBX-RS-PG-LIMIT-0021",
            ErrorClass::Query,
            "PostgreSQL typed query exceeded the total IPC byte limit",
            false,
            false,
        ));
    }
    let frame = ArrowIpcBatch {
        request_id: request.request_id.clone(),
        sequence,
        row_count: batch.num_rows() as u64,
        schema: query_schema.clone(),
        ipc_bytes,
    };
    batch_tx.send(frame).await.map_err(|_| {
        ConnectorError::new(
            "DBX-RS-PG-OUTPUT-0020",
            ErrorClass::Internal,
            "Arrow IPC batch receiver closed",
            false,
            false,
        )
    })?;
    Ok(encoded_bytes)
}

fn validate_prepare_request(request: &PrepareRequest) -> Result<(), ConnectorError> {
    if request.request_id.trim().is_empty() {
        return Err(configuration_error(
            "DBX-RS-PG-CFG-0020",
            "prepare request ID is required",
        ));
    }
    if request.timeout.is_zero() {
        return Err(configuration_error(
            "DBX-RS-PG-CFG-0021",
            "prepare timeout must be greater than zero",
        ));
    }
    if request.timeout > PostgresConnector::MAX_OPERATION_TIMEOUT {
        return Err(configuration_error(
            "DBX-RS-PG-CFG-0044",
            "prepare timeout exceeds the connector hard limit",
        ));
    }
    Ok(())
}

fn validate_execute_request(request: &ExecuteRequest) -> Result<(), ConnectorError> {
    if request.request_id.trim().is_empty() {
        return Err(configuration_error(
            "DBX-RS-PG-CFG-0022",
            "execute request ID is required",
        ));
    }
    if request.limits.timeout.is_zero() {
        return Err(configuration_error(
            "DBX-RS-PG-CFG-0023",
            "typed query timeout must be greater than zero",
        ));
    }
    if request.limits.timeout > PostgresConnector::MAX_OPERATION_TIMEOUT {
        return Err(configuration_error(
            "DBX-RS-PG-CFG-0045",
            "typed query timeout exceeds the connector hard limit",
        ));
    }
    if request.limits.max_batch_rows == 0 {
        return Err(configuration_error(
            "DBX-RS-PG-CFG-0024",
            "typed query batch row limit must be greater than zero",
        ));
    }
    if request.limits.max_batch_bytes == 0 {
        return Err(configuration_error(
            "DBX-RS-PG-CFG-0025",
            "typed query batch byte limit must be greater than zero",
        ));
    }
    if request.limits.max_total_ipc_bytes == 0 {
        return Err(configuration_error(
            "DBX-RS-PG-CFG-0026",
            "typed query total IPC byte limit must be greater than zero",
        ));
    }
    if request.limits.max_batch_rows > MAX_TYPED_BATCH_ROWS {
        return Err(configuration_error(
            "DBX-RS-PG-CFG-0040",
            "typed query batch row limit exceeds the connector hard limit",
        ));
    }
    if request.limits.max_batch_bytes > MAX_TYPED_BATCH_IPC_BYTES {
        return Err(configuration_error(
            "DBX-RS-PG-CFG-0041",
            "typed query batch IPC byte limit exceeds the connector hard limit",
        ));
    }
    if request.limits.max_total_ipc_bytes > MAX_TYPED_TOTAL_IPC_BYTES {
        return Err(configuration_error(
            "DBX-RS-PG-CFG-0042",
            "typed query total IPC byte limit exceeds the connector hard limit",
        ));
    }
    if request.limits.max_batch_bytes > request.limits.max_total_ipc_bytes {
        return Err(configuration_error(
            "DBX-RS-PG-CFG-0043",
            "typed query batch IPC byte limit exceeds its total IPC byte limit",
        ));
    }
    Ok(())
}

async fn begin_read_only(
    client: &Client,
    operation_timeout: std::time::Duration,
) -> Result<(), ConnectorError> {
    client
        .batch_execute("BEGIN TRANSACTION READ ONLY")
        .await
        .map_err(|error| classify_query_error(&error))?;
    let millis = operation_timeout.as_millis().clamp(1, i32::MAX as u128);
    client
        .batch_execute(&format!("SET LOCAL statement_timeout = {millis}"))
        .await
        .map_err(|error| classify_query_error(&error))
}

fn plan_columns(
    statement: &Statement,
) -> Result<(QuerySchema, SchemaRef, Vec<ColumnPlan>), ConnectorError> {
    ensure_nonempty_schema(statement.columns().len())?;
    let mut names = BTreeSet::new();
    let mut plans = Vec::with_capacity(statement.columns().len());
    for column in statement.columns() {
        if !names.insert(column.name()) {
            return Err(conversion_error(
                "DBX-RS-PG-SCHEMA-0002",
                "PostgreSQL query returned duplicate column names",
            ));
        }
        plans.push(plan_column(column)?);
    }
    let query_schema = QuerySchema {
        fields: plans.iter().map(|plan| plan.field.clone()).collect(),
    };
    let fields = plans
        .iter()
        .map(|plan| Field::new(&plan.field.name, plan.arrow_type.clone(), true))
        .collect::<Vec<_>>();
    Ok((query_schema, Arc::new(Schema::new(fields)), plans))
}

fn ensure_nonempty_schema(column_count: usize) -> Result<(), ConnectorError> {
    if column_count == 0 {
        return Err(conversion_error(
            "DBX-RS-PG-SCHEMA-0003",
            "PostgreSQL query returned no columns",
        ));
    }
    Ok(())
}

fn plan_column(column: &tokio_postgres::Column) -> Result<ColumnPlan, ConnectorError> {
    let source_type = column.type_().name().to_owned();
    let (field_type, arrow_type, value_type) =
        type_mapping(column.type_(), column.type_modifier())?;
    Ok(ColumnPlan {
        field: FieldDescriptor {
            name: column.name().to_owned(),
            field_type,
            nullable: true,
            source_type,
        },
        arrow_type,
        value_type,
    })
}

fn type_mapping(
    pg_type: &Type,
    type_modifier: i32,
) -> Result<(FieldType, DataType, ValueType), ConnectorError> {
    let mapping = if *pg_type == Type::BOOL {
        (FieldType::Boolean, DataType::Boolean, ValueType::Boolean)
    } else if *pg_type == Type::CHAR {
        (FieldType::Int8, DataType::Int8, ValueType::Int8)
    } else if *pg_type == Type::INT2 {
        (FieldType::Int16, DataType::Int16, ValueType::Int16)
    } else if *pg_type == Type::INT4 {
        (FieldType::Int32, DataType::Int32, ValueType::Int32)
    } else if *pg_type == Type::INT8 {
        (FieldType::Int64, DataType::Int64, ValueType::Int64)
    } else if *pg_type == Type::OID {
        (FieldType::UInt32, DataType::UInt32, ValueType::UInt32)
    } else if *pg_type == Type::FLOAT4 {
        (FieldType::Float32, DataType::Float32, ValueType::Float32)
    } else if *pg_type == Type::FLOAT8 {
        (FieldType::Float64, DataType::Float64, ValueType::Float64)
    } else if matches!(
        *pg_type,
        Type::TEXT | Type::VARCHAR | Type::BPCHAR | Type::NAME | Type::UNKNOWN
    ) {
        (FieldType::Utf8, DataType::Utf8, ValueType::Utf8)
    } else if *pg_type == Type::BYTEA {
        (FieldType::Binary, DataType::Binary, ValueType::Binary)
    } else if *pg_type == Type::UUID {
        (FieldType::Uuid, DataType::Utf8, ValueType::Uuid)
    } else if matches!(*pg_type, Type::JSON | Type::JSONB) {
        (FieldType::Json, DataType::Utf8, ValueType::Json)
    } else if *pg_type == Type::NUMERIC {
        let (precision, scale) = decode_numeric_type_modifier(type_modifier)?;
        (
            FieldType::Decimal128 { precision, scale },
            DataType::Decimal128(precision, scale),
            ValueType::Decimal128 { precision, scale },
        )
    } else if *pg_type == Type::DATE {
        (FieldType::Date32, DataType::Date32, ValueType::Date32)
    } else if *pg_type == Type::TIME {
        (
            FieldType::Time64Microsecond,
            DataType::Time64(TimeUnit::Microsecond),
            ValueType::Time64Microsecond,
        )
    } else if *pg_type == Type::TIMESTAMP {
        (
            FieldType::TimestampMicrosecond,
            DataType::Timestamp(TimeUnit::Microsecond, None),
            ValueType::TimestampMicrosecond,
        )
    } else if *pg_type == Type::TIMESTAMPTZ {
        (
            FieldType::TimestampMicrosecondUtc,
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            ValueType::TimestampMicrosecondUtc,
        )
    } else {
        return Err(conversion_error(
            "DBX-RS-PG-CONVERT-0020",
            "PostgreSQL query output contains an unsupported type",
        ));
    };
    Ok(mapping)
}

fn rows_to_batch(
    rows: &[Row],
    plans: &[ColumnPlan],
    schema: SchemaRef,
) -> Result<RecordBatch, ConnectorError> {
    let arrays = plans
        .iter()
        .enumerate()
        .map(|(index, plan)| column_array(rows, index, plan.value_type))
        .collect::<Result<Vec<_>, _>>()?;
    RecordBatch::try_new(schema, arrays).map_err(|_| {
        conversion_error(
            "DBX-RS-PG-CONVERT-0021",
            "failed to construct PostgreSQL Arrow record batch",
        )
    })
}

#[allow(clippy::too_many_lines)]
fn column_array(
    rows: &[Row],
    index: usize,
    value_type: ValueType,
) -> Result<ArrayRef, ConnectorError> {
    macro_rules! primitive_array {
        ($rust_type:ty, $array_type:ty) => {{
            let values = rows
                .iter()
                .map(|row| get_value::<$rust_type>(row, index))
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(<$array_type>::from(values)) as ArrayRef
        }};
    }
    let array = match value_type {
        ValueType::Boolean => primitive_array!(bool, BooleanArray),
        ValueType::Int8 => primitive_array!(i8, Int8Array),
        ValueType::Int16 => primitive_array!(i16, Int16Array),
        ValueType::Int32 => primitive_array!(i32, Int32Array),
        ValueType::Int64 => primitive_array!(i64, Int64Array),
        ValueType::UInt32 => primitive_array!(u32, UInt32Array),
        ValueType::Float32 => {
            let values = rows
                .iter()
                .map(|row| get_finite::<f32>(row, index))
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(Float32Array::from(values))
        }
        ValueType::Float64 => {
            let values = rows
                .iter()
                .map(|row| get_finite::<f64>(row, index))
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(Float64Array::from(values))
        }
        ValueType::Utf8 => primitive_array!(String, StringArray),
        ValueType::Binary => {
            let values = rows
                .iter()
                .map(|row| get_value::<Vec<u8>>(row, index))
                .collect::<Result<Vec<_>, _>>()?;
            let borrowed = values.iter().map(Option::as_deref).collect::<Vec<_>>();
            Arc::new(BinaryArray::from(borrowed))
        }
        ValueType::Uuid => {
            let values = rows
                .iter()
                .map(|row| {
                    get_value::<Uuid>(row, index).map(|value| value.map(|value| value.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(StringArray::from(values))
        }
        ValueType::Json => {
            let values = rows
                .iter()
                .map(|row| get_value::<PgJson>(row, index).map(|value| value.map(|value| value.0)))
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(StringArray::from(values))
        }
        ValueType::Decimal128 { precision, scale } => {
            let values = rows
                .iter()
                .map(|row| {
                    get_value::<PgNumeric>(row, index)?
                        .map(|value| value.to_i128(precision, scale))
                        .transpose()
                })
                .collect::<Result<Vec<_>, _>>()?;
            let array = Decimal128Array::from(values)
                .with_precision_and_scale(precision, scale)
                .map_err(|_| {
                    conversion_error(
                        "DBX-RS-PG-CONVERT-0022",
                        "PostgreSQL decimal exceeds its declared precision",
                    )
                })?;
            Arc::new(array)
        }
        ValueType::Date32 => {
            let values = rows
                .iter()
                .map(|row| {
                    get_value::<NaiveDate>(row, index)
                        .map(|value| value.map(|value| value.num_days_from_ce() - 719_163))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(Date32Array::from(values))
        }
        ValueType::Time64Microsecond => {
            let values = rows
                .iter()
                .map(|row| {
                    get_value::<NaiveTime>(row, index).map(|value| {
                        value.map(|value| {
                            i64::from(value.num_seconds_from_midnight()) * 1_000_000
                                + i64::from(value.nanosecond() / 1_000)
                        })
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(Time64MicrosecondArray::from(values))
        }
        ValueType::TimestampMicrosecond => {
            let values = rows
                .iter()
                .map(|row| {
                    get_value::<NaiveDateTime>(row, index)
                        .map(|value| value.map(|value| value.and_utc().timestamp_micros()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(TimestampMicrosecondArray::from(values))
        }
        ValueType::TimestampMicrosecondUtc => {
            let values = rows
                .iter()
                .map(|row| {
                    get_value::<DateTime<Utc>>(row, index)
                        .map(|value| value.map(|value| value.timestamp_micros()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(TimestampMicrosecondArray::from(values).with_timezone("UTC"))
        }
    };
    Ok(array)
}

fn get_value<'a, T>(row: &'a Row, index: usize) -> Result<Option<T>, ConnectorError>
where
    T: FromSql<'a>,
{
    row.try_get::<_, Option<T>>(index).map_err(|_| {
        conversion_error(
            "DBX-RS-PG-CONVERT-0023",
            "PostgreSQL value could not be converted without loss",
        )
    })
}

trait Finite: Sized + Copy {
    fn is_finite(self) -> bool;
}

impl Finite for f32 {
    fn is_finite(self) -> bool {
        self.is_finite()
    }
}

impl Finite for f64 {
    fn is_finite(self) -> bool {
        self.is_finite()
    }
}

fn get_finite<'a, T>(row: &'a Row, index: usize) -> Result<Option<T>, ConnectorError>
where
    T: FromSql<'a> + Finite,
{
    let value = get_value::<T>(row, index)?;
    if value.is_some_and(|value| !value.is_finite()) {
        return Err(conversion_error(
            "DBX-RS-PG-CONVERT-0024",
            "non-finite PostgreSQL floating-point values require an explicit text cast",
        ));
    }
    Ok(value)
}

fn encode_batch(batch: &RecordBatch, max_bytes: u64) -> Result<Vec<u8>, ConnectorError> {
    let max_bytes = usize::try_from(max_bytes).map_err(|_| {
        configuration_error(
            "DBX-RS-PG-CFG-0027",
            "typed query batch byte limit is invalid for this platform",
        )
    })?;
    let mut output = BoundedWriter::new(max_bytes);
    let result = (|| {
        let mut writer = StreamWriter::try_new(&mut output, batch.schema().as_ref())?;
        writer.write(batch)?;
        writer.finish()
    })();
    result.map_err(|_| {
        ConnectorError::new(
            "DBX-RS-PG-LIMIT-0020",
            ErrorClass::Query,
            "PostgreSQL Arrow IPC batch exceeded its byte limit",
            false,
            false,
        )
    })?;
    Ok(output.into_inner())
}

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("Arrow IPC batch limit exceeded"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct PgJson(String);

impl<'a> FromSql<'a> for PgJson {
    fn from_sql(ty: &Type, raw: &'a [u8]) -> Result<Self, Box<dyn Error + Sync + Send>> {
        let json = if *ty == Type::JSONB {
            match raw.split_first() {
                Some((1, json)) => json,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid JSONB version",
                    )
                    .into());
                }
            }
        } else {
            raw
        };
        let json = std::str::from_utf8(json)?;
        let _validated: &serde_json::value::RawValue = serde_json::from_str(json)?;
        Ok(Self(json.to_owned()))
    }

    fn accepts(ty: &Type) -> bool {
        matches!(*ty, Type::JSON | Type::JSONB)
    }
}

struct PgNumeric {
    weight: i16,
    sign: u16,
    display_scale: u16,
    digits: Vec<u16>,
}

impl PgNumeric {
    fn to_i128(&self, precision: u8, scale: i8) -> Result<i128, ConnectorError> {
        if !matches!(self.sign, NUMERIC_POSITIVE | NUMERIC_NEGATIVE) {
            return Err(conversion_error(
                "DBX-RS-PG-CONVERT-0025",
                "non-finite PostgreSQL numeric values require an explicit text cast",
            ));
        }
        let scale = u16::try_from(scale).map_err(|_| {
            conversion_error(
                "DBX-RS-PG-CONVERT-0026",
                "negative-scale PostgreSQL numeric values are unsupported",
            )
        })?;
        if self.display_scale != scale {
            return Err(conversion_error(
                "DBX-RS-PG-CONVERT-0027",
                "PostgreSQL numeric scale does not match its declared schema",
            ));
        }
        let mut digits = self.decimal_digits(scale)?;
        let significant_digits = digits.trim_start_matches('0').len();
        if significant_digits > usize::from(precision) {
            return Err(conversion_error(
                "DBX-RS-PG-CONVERT-0028",
                "PostgreSQL numeric value exceeds its declared precision",
            ));
        }
        if digits.is_empty() {
            digits.push('0');
        }
        let mut value = 0_i128;
        for digit in digits.bytes() {
            value = value
                .checked_mul(10)
                .and_then(|value| value.checked_add(i128::from(digit - b'0')))
                .ok_or_else(|| {
                    conversion_error(
                        "DBX-RS-PG-CONVERT-0029",
                        "PostgreSQL numeric value exceeds Decimal128 range",
                    )
                })?;
        }
        if self.sign == NUMERIC_NEGATIVE && value != 0 {
            value = value.checked_neg().ok_or_else(|| {
                conversion_error(
                    "DBX-RS-PG-CONVERT-0029",
                    "PostgreSQL numeric value exceeds Decimal128 range",
                )
            })?;
        }
        Ok(value)
    }

    fn decimal_digits(&self, scale: u16) -> Result<String, ConnectorError> {
        let mut output = String::new();
        if self.weight >= 0 {
            for power in (0..=self.weight).rev() {
                let digit = self.digit_at_power(power);
                if power == self.weight {
                    output.push_str(&digit.to_string());
                } else {
                    write!(&mut output, "{digit:04}").map_err(|_| {
                        conversion_error(
                            "DBX-RS-PG-CONVERT-0030",
                            "PostgreSQL numeric scale is invalid",
                        )
                    })?;
                }
            }
        } else {
            output.push('0');
        }
        let fractional_groups = usize::from(scale).div_ceil(4);
        for group in 0..fractional_groups {
            let power = (-1_i16)
                .checked_sub(i16::try_from(group).map_err(|_| {
                    conversion_error(
                        "DBX-RS-PG-CONVERT-0030",
                        "PostgreSQL numeric scale is invalid",
                    )
                })?)
                .ok_or_else(|| {
                    conversion_error(
                        "DBX-RS-PG-CONVERT-0030",
                        "PostgreSQL numeric scale is invalid",
                    )
                })?;
            write!(&mut output, "{:04}", self.digit_at_power(power)).map_err(|_| {
                conversion_error(
                    "DBX-RS-PG-CONVERT-0030",
                    "PostgreSQL numeric scale is invalid",
                )
            })?;
        }
        let integer_digits = if self.weight >= 0 {
            let first = self.digit_at_power(self.weight).to_string().len();
            first + usize::try_from(self.weight).unwrap_or(0) * 4
        } else {
            1
        };
        output.truncate(integer_digits + usize::from(scale));
        Ok(output)
    }

    fn digit_at_power(&self, power: i16) -> u16 {
        let index = i32::from(self.weight) - i32::from(power);
        usize::try_from(index)
            .ok()
            .and_then(|index| self.digits.get(index).copied())
            .unwrap_or(0)
    }
}

impl<'a> FromSql<'a> for PgNumeric {
    fn from_sql(_ty: &Type, raw: &'a [u8]) -> Result<Self, Box<dyn Error + Sync + Send>> {
        if raw.len() < 8 || !raw.len().is_multiple_of(2) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid numeric binary length",
            )
            .into());
        }
        let word = |offset: usize| u16::from_be_bytes([raw[offset], raw[offset + 1]]);
        let digit_count = usize::from(word(0));
        if raw.len() != 8 + digit_count * 2 {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "invalid numeric digit count").into(),
            );
        }
        let weight = i16::from_be_bytes([raw[2], raw[3]]);
        let sign = word(4);
        if !matches!(
            sign,
            NUMERIC_POSITIVE
                | NUMERIC_NEGATIVE
                | NUMERIC_NAN
                | NUMERIC_POSITIVE_INFINITY
                | NUMERIC_NEGATIVE_INFINITY
        ) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid numeric sign").into());
        }
        let display_scale = word(6);
        if display_scale & NUMERIC_DISPLAY_SCALE_MASK != display_scale {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid numeric scale").into());
        }
        let mut digits = Vec::with_capacity(digit_count);
        for offset in (8..raw.len()).step_by(2) {
            let digit = word(offset);
            if digit > 9_999 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid numeric base-10000 digit",
                )
                .into());
            }
            digits.push(digit);
        }
        Ok(Self {
            weight,
            sign,
            display_scale,
            digits,
        })
    }

    fn accepts(ty: &Type) -> bool {
        *ty == Type::NUMERIC
    }
}

fn decode_numeric_type_modifier(type_modifier: i32) -> Result<(u8, i8), ConnectorError> {
    if type_modifier < POSTGRES_TYPE_MODIFIER_HEADER_BYTES {
        return Err(conversion_error(
            "DBX-RS-PG-CONVERT-0031",
            "unconstrained PostgreSQL numeric output requires an explicit bounded decimal or text cast",
        ));
    }
    let modifier = type_modifier - POSTGRES_TYPE_MODIFIER_HEADER_BYTES;
    let precision = u8::try_from((modifier >> 16) & 0xffff).map_err(|_| {
        conversion_error(
            "DBX-RS-PG-CONVERT-0032",
            "PostgreSQL numeric precision exceeds Decimal128",
        )
    })?;
    let raw_scale = modifier & 0x7ff;
    let scale = (raw_scale ^ 0x400) - 0x400;
    let scale = i8::try_from(scale).map_err(|_| {
        conversion_error(
            "DBX-RS-PG-CONVERT-0033",
            "PostgreSQL numeric scale is outside the supported range",
        )
    })?;
    if precision == 0 || precision > 38 || scale < 0 || i16::from(scale) > i16::from(precision) {
        return Err(conversion_error(
            "DBX-RS-PG-CONVERT-0034",
            "PostgreSQL numeric declaration is outside Decimal128 precision and scale limits",
        ));
    }
    Ok((precision, scale))
}

fn configuration_error(code: &'static str, message: &'static str) -> ConnectorError {
    ConnectorError::new(code, ErrorClass::Configuration, message, false, true)
}

fn conversion_error(code: &'static str, message: &'static str) -> ConnectorError {
    ConnectorError::new(code, ErrorClass::Conversion, message, false, false)
}

fn operation_timeout(code: &'static str, message: &'static str) -> ConnectorError {
    ConnectorError::new(code, ErrorClass::Timeout, message, true, false)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use dbx_rs_connector_sdk::{
        ConnectionConfig, CursorNullPolicy, ExecutionLimits, QueryText, TimestampIdCursor, TlsMode,
    };

    use super::*;

    fn execute_request() -> ExecuteRequest {
        ExecuteRequest {
            request_id: "request-1".into(),
            connection: ConnectionConfig {
                connector_id: PostgresConnector::CONNECTOR_ID.into(),
                host: "localhost".into(),
                port: 5432,
                database: "database".into(),
                username: "reader".into(),
                tls_mode: TlsMode::Disable,
                tls_server_name: None,
                tls_ca_pem: None,
                connect_timeout: Duration::from_secs(1),
                probe_timeout: Duration::from_secs(1),
            },
            query: QueryText::new("SELECT 1"),
            limits: ExecutionLimits {
                max_rows: 100,
                max_batch_rows: MAX_TYPED_BATCH_ROWS,
                max_batch_bytes: MAX_TYPED_BATCH_IPC_BYTES,
                max_total_ipc_bytes: MAX_TYPED_TOTAL_IPC_BYTES,
                timeout: Duration::from_secs(1),
            },
            expected_schema: None,
            cursor: None,
        }
    }

    fn parse_numeric(raw: &[u8]) -> Result<PgNumeric, Box<dyn Error + Sync + Send + '_>> {
        PgNumeric::from_sql(&Type::NUMERIC, raw)
    }

    #[test]
    fn numeric_type_modifier_decodes_precision_and_scale() {
        let modifier = POSTGRES_TYPE_MODIFIER_HEADER_BYTES + (10 << 16) + 4;

        assert_eq!(decode_numeric_type_modifier(modifier), Ok((10, 4)));
    }

    #[test]
    fn unconstrained_numeric_fails_closed() {
        let error = decode_numeric_type_modifier(-1).expect_err("unbounded numeric must fail");

        assert_eq!(error.code(), "DBX-RS-PG-CONVERT-0031");
    }

    #[test]
    fn postgresql_15_extended_numeric_scales_fail_closed() {
        let negative_scale = POSTGRES_TYPE_MODIFIER_HEADER_BYTES + (2 << 16) + 0x7fd;
        let error = decode_numeric_type_modifier(negative_scale)
            .expect_err("negative-scale numeric is outside contract v1");
        assert_eq!(error.code(), "DBX-RS-PG-CONVERT-0034");

        let scale_above_precision = POSTGRES_TYPE_MODIFIER_HEADER_BYTES + (3 << 16) + 5;
        let error = decode_numeric_type_modifier(scale_above_precision)
            .expect_err("scale above precision is outside contract v1");
        assert_eq!(error.code(), "DBX-RS-PG-CONVERT-0034");
    }

    #[test]
    fn execute_limits_reject_values_above_connector_hard_caps() {
        let mut request = execute_request();
        request.limits.max_batch_rows = MAX_TYPED_BATCH_ROWS + 1;
        let error = validate_execute_request(&request).expect_err("batch rows must be bounded");
        assert_eq!(error.code(), "DBX-RS-PG-CFG-0040");

        let mut request = execute_request();
        request.limits.max_batch_bytes = MAX_TYPED_BATCH_IPC_BYTES + 1;
        let error = validate_execute_request(&request).expect_err("batch bytes must be bounded");
        assert_eq!(error.code(), "DBX-RS-PG-CFG-0041");

        let mut request = execute_request();
        request.limits.max_total_ipc_bytes = MAX_TYPED_TOTAL_IPC_BYTES + 1;
        let error = validate_execute_request(&request).expect_err("total bytes must be bounded");
        assert_eq!(error.code(), "DBX-RS-PG-CFG-0042");

        let mut request = execute_request();
        request.limits.timeout = PostgresConnector::MAX_OPERATION_TIMEOUT + Duration::from_secs(1);
        let error = validate_execute_request(&request).expect_err("timeout must be bounded");
        assert_eq!(error.code(), "DBX-RS-PG-CFG-0045");
    }

    #[test]
    fn execute_limits_reject_batch_bytes_above_total_bytes() {
        let mut request = execute_request();
        request.limits.max_total_ipc_bytes = request.limits.max_batch_bytes - 1;

        let error = validate_execute_request(&request).expect_err("batch must fit total limit");

        assert_eq!(error.code(), "DBX-RS-PG-CFG-0043");
    }

    #[test]
    fn effective_batch_capacity_applies_row_and_schema_limits() {
        let mut request = execute_request();
        request.limits.max_rows = 1;
        let fixed_schema = QuerySchema {
            fields: vec![FieldDescriptor {
                name: "value".into(),
                field_type: FieldType::Int64,
                nullable: true,
                source_type: "int8".into(),
            }],
        };

        assert_eq!(effective_batch_capacity(&request, &fixed_schema), Ok(1));

        request.limits.max_rows = 100;
        let variable_schema = QuerySchema {
            fields: vec![FieldDescriptor {
                name: "value".into(),
                field_type: FieldType::Utf8,
                nullable: true,
                source_type: "text".into(),
            }],
        };

        assert_eq!(effective_batch_capacity(&request, &variable_schema), Ok(1));
    }

    #[test]
    fn zero_column_schema_fails_closed() {
        assert!(ensure_nonempty_schema(1).is_ok());

        let error = ensure_nonempty_schema(0).expect_err("zero-column schema must fail");

        assert_eq!(error.code(), "DBX-RS-PG-SCHEMA-0003");
    }

    fn cursor_spec() -> TimestampIdCursorSpec {
        TimestampIdCursorSpec {
            timestamp_field: "updated_at".into(),
            id_field: "id".into(),
            overlap: Duration::ZERO,
            null_policy: CursorNullPolicy::Reject,
        }
    }

    fn cursor_schema(timestamp_type: FieldType, id_type: FieldType) -> QuerySchema {
        QuerySchema {
            fields: vec![
                FieldDescriptor {
                    name: "updated_at".into(),
                    field_type: timestamp_type,
                    nullable: true,
                    source_type: "timestamp with time zone".into(),
                },
                FieldDescriptor {
                    name: "id".into(),
                    field_type: id_type,
                    nullable: true,
                    source_type: "int8".into(),
                },
            ],
        }
    }

    #[test]
    fn cursor_schema_requires_timestamptz_and_bigint_fields() {
        let spec = cursor_spec();
        let projection = validate_cursor_schema(
            &cursor_schema(FieldType::TimestampMicrosecondUtc, FieldType::Int64),
            &spec,
        )
        .expect("supported cursor schema must resolve");
        assert_eq!(projection.timestamp_index, 0);
        assert_eq!(projection.id_index, 1);

        for schema in [
            cursor_schema(FieldType::TimestampMicrosecond, FieldType::Int64),
            cursor_schema(FieldType::TimestampMicrosecondUtc, FieldType::Int32),
            QuerySchema {
                fields: vec![FieldDescriptor {
                    name: "id".into(),
                    field_type: FieldType::Int64,
                    nullable: true,
                    source_type: "int8".into(),
                }],
            },
        ] {
            let error = validate_cursor_schema(&schema, &spec)
                .err()
                .expect("unsupported or absent cursor fields must fail");
            assert_eq!(error.code(), "DBX-RS-PG-CFG-0049");
        }
    }

    #[test]
    fn cursor_native_values_reject_nulls_without_exposing_values() {
        let timestamp = DateTime::<Utc>::from_timestamp_micros(10)
            .expect("test timestamp must be representable");

        for result in [
            cursor_from_native_values(None, Some(1)),
            cursor_from_native_values(Some(timestamp), None),
        ] {
            let error = result.expect_err("null cursor values must fail");
            assert_eq!(error.code(), "DBX-RS-PG-CONVERT-0035");
            assert!(!error.to_string().contains("updated_at"));
        }
    }

    #[test]
    fn cursor_tuple_order_is_strict_across_equal_timestamps() {
        let mut previous = None;
        observe_cursor_order(&mut previous, TimestampIdCursor::new(10, 1))
            .expect("first cursor must be accepted");
        observe_cursor_order(&mut previous, TimestampIdCursor::new(10, 2))
            .expect("larger tie-breaker must be accepted");
        observe_cursor_order(&mut previous, TimestampIdCursor::new(11, i64::MIN))
            .expect("later timestamp must be accepted");

        let duplicate = observe_cursor_order(&mut previous, TimestampIdCursor::new(11, i64::MIN))
            .expect_err("duplicate tuple must fail");
        assert_eq!(duplicate.code(), "DBX-RS-PG-CONVERT-0036");

        let mut previous = Some(TimestampIdCursor::new(20, 5));
        let decreasing = observe_cursor_order(&mut previous, TimestampIdCursor::new(20, 4))
            .expect_err("decreasing tuple must fail");
        assert_eq!(decreasing.code(), "DBX-RS-PG-CONVERT-0036");
    }

    #[test]
    fn base_and_cursor_parameter_metadata_are_exact() {
        assert!(validate_base_parameters(&[]).is_ok());
        let error = validate_base_parameters(&[Type::INT8])
            .expect_err("base query parameters must be rejected");
        assert_eq!(error.code(), "DBX-RS-PG-CFG-0048");

        assert!(validate_cursor_parameters(&[], false).is_ok());
        assert!(validate_cursor_parameters(&[Type::TIMESTAMPTZ, Type::INT8], true).is_ok());
        for parameters in [
            vec![Type::TIMESTAMP, Type::INT8],
            vec![Type::TIMESTAMPTZ, Type::INT4],
            vec![Type::TIMESTAMPTZ],
        ] {
            let error = validate_cursor_parameters(&parameters, true)
                .expect_err("cursor parameter metadata must match exactly");
            assert_eq!(error.code(), "DBX-RS-PG-SCHEMA-0006");
        }
    }

    #[test]
    fn cursor_bound_converts_to_checked_native_values() {
        assert!(
            postgres_cursor_parameters(None)
                .expect("unbounded cursor must be valid")
                .is_none()
        );
        let parameters = postgres_cursor_parameters(Some(TimestampIdCursorBound {
            value: TimestampIdCursor::new(1_234_567, -42),
            inclusive: false,
        }))
        .expect("representable cursor must convert")
        .expect("bound must produce parameters");
        assert_eq!(parameters.timestamp.timestamp_micros(), 1_234_567);
        assert_eq!(parameters.id, -42);

        let error = postgres_cursor_parameters(Some(TimestampIdCursorBound {
            value: TimestampIdCursor::new(i64::MAX, 0),
            inclusive: false,
        }))
        .err()
        .expect("out-of-range chrono cursor must fail");
        assert_eq!(error.code(), "DBX-RS-PG-CFG-0047");
    }

    #[test]
    fn numeric_binary_preserves_declared_trailing_zero_scale() {
        let numeric = PgNumeric {
            weight: 0,
            sign: NUMERIC_POSITIVE,
            display_scale: 4,
            digits: vec![1, 2_300],
        };

        assert_eq!(numeric.to_i128(10, 4), Ok(12_300));
    }

    #[test]
    fn negative_fractional_numeric_is_exact() {
        let numeric = PgNumeric {
            weight: -1,
            sign: NUMERIC_NEGATIVE,
            display_scale: 4,
            digits: vec![1_234],
        };

        assert_eq!(numeric.to_i128(10, 4), Ok(-1_234));
    }

    #[test]
    fn numeric_wire_frames_preserve_zero_and_base_10000_groups() {
        let zero = parse_numeric(&[0, 0, 0, 0, 0, 0, 0, 4]).expect("zero should parse");
        assert_eq!(zero.to_i128(10, 4), Ok(0));

        let fractional = parse_numeric(&[0, 1, 0xff, 0xfe, 0, 0, 0, 8, 0x04, 0xd2])
            .expect("fraction should parse");
        assert_eq!(fractional.to_i128(10, 8), Ok(1_234));

        let negative = parse_numeric(&[0, 1, 0xff, 0xff, 0x40, 0, 0, 4, 0x04, 0xd2])
            .expect("negative fraction should parse");
        assert_eq!(negative.to_i128(10, 4), Ok(-1_234));

        let trailing_groups = parse_numeric(&[0, 1, 0, 2, 0, 0, 0, 0, 0, 1])
            .expect("integer with omitted trailing groups should parse");
        assert_eq!(trailing_groups.to_i128(12, 0), Ok(100_000_000));
    }

    #[test]
    fn numeric_wire_frame_preserves_decimal128_precision_boundary() {
        let mut raw = vec![0, 10, 0, 9, 0, 0, 0, 0, 0, 99];
        for _ in 0..9 {
            raw.extend_from_slice(&9_999_u16.to_be_bytes());
        }
        let numeric = parse_numeric(&raw).expect("38-digit numeric should parse");
        let expected = "9".repeat(38).parse::<i128>().expect("i128 boundary");

        assert_eq!(numeric.to_i128(38, 0), Ok(expected));
    }

    #[test]
    fn numeric_wire_parser_rejects_malformed_frames() {
        let malformed: &[&[u8]] = &[
            &[0; 7],
            &[0; 9],
            &[0, 1, 0, 0, 0, 0, 0, 0],
            &[0, 0, 0, 0, 0x12, 0x34, 0, 0],
            &[0, 0, 0, 0, 0, 0, 0x40, 0],
            &[0, 1, 0, 0, 0, 0, 0, 0, 0x27, 0x10],
        ];

        for raw in malformed {
            assert!(parse_numeric(raw).is_err(), "frame should be rejected");
        }
    }

    #[test]
    fn numeric_wire_special_values_parse_but_fail_decimal_conversion() {
        for sign in [
            NUMERIC_NAN,
            NUMERIC_POSITIVE_INFINITY,
            NUMERIC_NEGATIVE_INFINITY,
        ] {
            let [sign_high, sign_low] = sign.to_be_bytes();
            let numeric = parse_numeric(&[0, 0, 0, 0, sign_high, sign_low, 0, 0])
                .expect("known special numeric should parse");

            let error = numeric
                .to_i128(10, 0)
                .expect_err("special numeric must not become Decimal128");
            assert_eq!(error.code(), "DBX-RS-PG-CONVERT-0025");
        }
    }

    #[test]
    fn bounded_writer_never_grows_past_limit() {
        let mut writer = BoundedWriter::new(3);
        writer.write_all(b"abc").expect("write within limit");

        assert!(writer.write_all(b"d").is_err());
        assert_eq!(writer.into_inner(), b"abc");
    }
}
