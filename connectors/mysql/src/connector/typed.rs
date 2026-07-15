use std::{
    cmp::Ordering,
    collections::BTreeSet,
    io::{self, Write},
    sync::Arc,
};

use arrow_array::{
    ArrayRef, BinaryArray, BooleanArray, Date32Array, Decimal128Array, Float32Array, Float64Array,
    Int8Array, Int16Array, Int32Array, Int64Array, RecordBatch, StringArray,
    TimestampMicrosecondArray, UInt32Array,
};
use arrow_ipc::writer::StreamWriter;
use arrow_schema::{DataType, Field, Schema, SchemaRef, TimeUnit};
use chrono::{DateTime, Datelike, NaiveDate, Timelike, Utc};
use dbx_rs_connector_sdk::{
    ArrowIpcBatch, ConnectorError, ErrorClass, ExecuteRequest, ExecutionResult, FieldDescriptor,
    FieldType, PrepareRequest, PreparedQuery, QuerySchema, TimestampIdCursor,
    TimestampIdCursorBound, TimestampIdCursorSpec,
};
use futures_util::TryStreamExt;
use mysql_async::{
    Column, Params, Row, Statement, Transaction, TxOpts, Value,
    consts::{ColumnFlags, ColumnType},
    prelude::Queryable,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::{
    DatabaseProduct, MySqlFamilyConnector, classify_query_error, open_session,
    sql::{NormalizedQuery, normalize_query},
};

const BINARY_CHARACTER_SET: u16 = 63;
const MAX_TYPED_BATCH_ROWS: u32 = 256;
const MAX_QUERY_COLUMNS: usize = 1024;
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
    Json,
    Decimal128 {
        precision: u8,
        scale: i8,
        unsigned: bool,
    },
    Date32,
    TimestampMicrosecond,
    TimestampMicrosecondUtc,
}

#[derive(Clone, Copy)]
struct CursorProjection {
    timestamp_index: usize,
    id_index: usize,
}

pub(super) async fn prepare(
    product: DatabaseProduct,
    request: PrepareRequest,
    secret: &dbx_rs_connector_sdk::ResolvedSecret,
    cancellation: CancellationToken,
) -> Result<PreparedQuery, ConnectorError> {
    validate_prepare_request(&request)?;
    let query = normalize_query(
        request.query.as_str(),
        request.max_rows,
        request.cursor.as_ref(),
    )?;
    let mut session = open_session(
        product,
        &request.connection,
        secret,
        MySqlFamilyConnector::MAX_WIRE_PACKET_BYTES,
        &cancellation,
    )
    .await?;
    let operation = prepare_schema(
        &mut session.conn,
        &query,
        request.cursor.as_ref().map(|cursor| &cursor.spec),
    );
    let schema = tokio::select! {
        () = cancellation.cancelled() => {
            Err(ConnectorError::cancelled("DBX-RS-MY-CANCELLED-0020"))
        }
        result = tokio::time::timeout(request.timeout, operation) => {
            result.map_err(|_| operation_timeout(
                "DBX-RS-MY-QUERY-0020",
                "MySQL-family prepare timed out",
            ))?
        }
    }?;
    Ok(PreparedQuery {
        request_id: request.request_id,
        connector_id: product.connector_id().into(),
        schema,
    })
}

pub(super) async fn execute(
    product: DatabaseProduct,
    request: ExecuteRequest,
    secret: &dbx_rs_connector_sdk::ResolvedSecret,
    batch_tx: mpsc::Sender<ArrowIpcBatch>,
    cancellation: CancellationToken,
) -> Result<ExecutionResult, ConnectorError> {
    validate_execute_request(&request)?;
    let query = normalize_query(
        request.query.as_str(),
        request.limits.max_rows,
        request.cursor.as_ref(),
    )?;
    let max_packet_bytes = usize::try_from(request.limits.max_batch_bytes)
        .unwrap_or(MySqlFamilyConnector::MAX_WIRE_PACKET_BYTES)
        .saturating_add(64 * 1024)
        .min(MySqlFamilyConnector::MAX_WIRE_PACKET_BYTES);
    let mut session = open_session(
        product,
        &request.connection,
        secret,
        max_packet_bytes,
        &cancellation,
    )
    .await?;
    let timeout = request.limits.timeout;
    let operation = execute_query(&mut session.conn, query, request, batch_tx);
    tokio::select! {
        () = cancellation.cancelled() => {
            Err(ConnectorError::cancelled("DBX-RS-MY-CANCELLED-0021"))
        }
        result = tokio::time::timeout(timeout, operation) => {
            result.map_err(|_| operation_timeout(
                "DBX-RS-MY-QUERY-0021",
                "MySQL-family query timed out",
            ))?
        }
    }
}

async fn prepare_schema(
    conn: &mut mysql_async::Conn,
    query: &NormalizedQuery,
    cursor_spec: Option<&TimestampIdCursorSpec>,
) -> Result<QuerySchema, ConnectorError> {
    let mut options = TxOpts::new();
    options.with_readonly(true);
    let mut transaction = conn
        .start_transaction(options)
        .await
        .map_err(|error| classify_query_error(&error))?;
    let (_statement, schema, _arrow_schema, _plans, _projection) =
        prepare_typed_statement(&mut transaction, query, cursor_spec).await?;
    transaction
        .commit()
        .await
        .map_err(|error| classify_query_error(&error))?;
    Ok(schema)
}

#[allow(clippy::too_many_lines)]
async fn execute_query(
    conn: &mut mysql_async::Conn,
    query: NormalizedQuery,
    request: ExecuteRequest,
    batch_tx: mpsc::Sender<ArrowIpcBatch>,
) -> Result<ExecutionResult, ConnectorError> {
    let mut options = TxOpts::new();
    options.with_readonly(true);
    let mut transaction = conn
        .start_transaction(options)
        .await
        .map_err(|error| classify_query_error(&error))?;
    let (statement, query_schema, arrow_schema, plans, cursor_projection) =
        prepare_typed_statement(
            &mut transaction,
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
            "DBX-RS-MY-SCHEMA-0001",
            "MySQL-family query schema changed before execution",
        ));
    }

    let parameters = query_parameters(query.cursor_bound, request.limits.max_rows)?;
    let result = transaction
        .exec_iter(statement, Params::Positional(parameters))
        .await
        .map_err(|error| classify_query_error(&error))?;
    let mut rows = result
        .stream_and_drop::<Row>()
        .await
        .map_err(|error| classify_query_error(&error))?
        .ok_or_else(|| {
            conversion_error(
                "DBX-RS-MY-SCHEMA-0007",
                "MySQL-family query returned no result set",
            )
        })?;

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
    drop(rows);

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

    transaction
        .commit()
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
    transaction: &mut Transaction<'_>,
    query: &NormalizedQuery,
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
    let base_statement = transaction
        .prep(&query.base)
        .await
        .map_err(|error| classify_query_error(&error))?;
    if base_statement.num_params() != 0 {
        return Err(configuration_error(
            "DBX-RS-MY-CFG-0048",
            "MySQL-family base queries cannot contain parameters",
        ));
    }
    let base_columns = base_statement.columns();
    let (base_schema, _base_arrow_schema, _base_plans) = plan_columns(&base_columns)?;
    let cursor_projection = cursor_spec
        .map(|spec| validate_cursor_schema(&base_schema, spec))
        .transpose()?;

    let statement = transaction
        .prep(&query.sql)
        .await
        .map_err(|error| classify_query_error(&error))?;
    let expected_parameters = if query.cursor_bound.is_some() { 3 } else { 1 };
    if usize::from(statement.num_params()) != expected_parameters {
        return Err(conversion_error(
            "DBX-RS-MY-SCHEMA-0006",
            "MySQL-family cursor parameter metadata did not match the typed bound",
        ));
    }
    let columns = statement.columns();
    let (query_schema, arrow_schema, plans) = plan_columns(&columns)?;
    if query_schema != base_schema {
        return Err(conversion_error(
            "DBX-RS-MY-SCHEMA-0005",
            "MySQL-family query wrapper changed the output schema",
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

fn validate_cursor_schema(
    schema: &QuerySchema,
    spec: &TimestampIdCursorSpec,
) -> Result<CursorProjection, ConnectorError> {
    let timestamps = schema
        .fields
        .iter()
        .enumerate()
        .filter(|(_, field)| field.name == spec.timestamp_field)
        .collect::<Vec<_>>();
    let identifiers = schema
        .fields
        .iter()
        .enumerate()
        .filter(|(_, field)| field.name == spec.id_field)
        .collect::<Vec<_>>();
    if timestamps.len() != 1
        || identifiers.len() != 1
        || timestamps[0].1.field_type != FieldType::TimestampMicrosecondUtc
        || identifiers[0].1.field_type != FieldType::Int64
    {
        return Err(configuration_error(
            "DBX-RS-MY-CFG-0049",
            "MySQL-family cursor requires unique TIMESTAMP and signed BIGINT output fields",
        ));
    }
    Ok(CursorProjection {
        timestamp_index: timestamps[0].0,
        id_index: identifiers[0].0,
    })
}

fn query_parameters(
    bound: Option<TimestampIdCursorBound>,
    max_rows: u64,
) -> Result<Vec<Value>, ConnectorError> {
    let fetch_rows = max_rows.checked_add(1).ok_or_else(|| {
        configuration_error(
            "DBX-RS-MY-CFG-0014",
            "collection max_rows is outside the MySQL-family hard limit",
        )
    })?;
    let mut parameters = Vec::with_capacity(if bound.is_some() { 3 } else { 1 });
    if let Some(bound) = bound {
        parameters.push(cursor_timestamp_parameter(
            bound.value.timestamp_epoch_micros,
        )?);
        parameters.push(Value::Int(bound.value.id));
    }
    parameters.push(Value::UInt(fetch_rows));
    Ok(parameters)
}

fn cursor_timestamp_parameter(epoch_micros: i64) -> Result<Value, ConnectorError> {
    let timestamp = DateTime::<Utc>::from_timestamp_micros(epoch_micros).ok_or_else(|| {
        configuration_error(
            "DBX-RS-MY-CFG-0047",
            "MySQL-family cursor timestamp is outside the supported range",
        )
    })?;
    let year = timestamp.year();
    if !(1000..=9999).contains(&year) {
        return Err(configuration_error(
            "DBX-RS-MY-CFG-0047",
            "MySQL-family cursor timestamp is outside the supported range",
        ));
    }
    let year = u16::try_from(year).map_err(|_| {
        configuration_error(
            "DBX-RS-MY-CFG-0047",
            "MySQL-family cursor timestamp is outside the supported range",
        )
    })?;
    let component = |value| {
        u8::try_from(value).map_err(|_| {
            configuration_error(
                "DBX-RS-MY-CFG-0047",
                "MySQL-family cursor timestamp is outside the supported range",
            )
        })
    };
    Ok(Value::Date(
        year,
        component(timestamp.month())?,
        component(timestamp.day())?,
        component(timestamp.hour())?,
        component(timestamp.minute())?,
        component(timestamp.second())?,
        timestamp.timestamp_subsec_micros(),
    ))
}

fn projected_cursor(
    row: &Row,
    projection: CursorProjection,
) -> Result<TimestampIdCursor, ConnectorError> {
    let timestamp = cell(row, projection.timestamp_index)?
        .map(timestamp_micros)
        .transpose()?;
    let id = cell(row, projection.id_index)?
        .map(signed_i64)
        .transpose()?;
    let (Some(timestamp), Some(id)) = (timestamp, id) else {
        return Err(conversion_error(
            "DBX-RS-MY-CONVERT-0035",
            "MySQL-family cursor output contains a null value",
        ));
    };
    Ok(TimestampIdCursor::new(timestamp, id))
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
            "DBX-RS-MY-CONVERT-0036",
            "MySQL-family cursor output is not strictly increasing",
        ));
    }
    *previous = Some(current);
    Ok(())
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
    let rows = u64::from(request.limits.max_batch_rows)
        .min(request.limits.max_rows)
        .min(schema_cap);
    usize::try_from(rows).map_err(|_| {
        configuration_error(
            "DBX-RS-MY-CFG-0028",
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
            "DBX-RS-MY-LIMIT-0021",
            ErrorClass::Query,
            "MySQL-family typed query exceeded the total IPC byte limit",
            false,
            false,
        ));
    }
    batch_tx
        .send(ArrowIpcBatch {
            request_id: request.request_id.clone(),
            sequence,
            row_count: batch.num_rows() as u64,
            schema: query_schema.clone(),
            ipc_bytes,
        })
        .await
        .map_err(|_| {
            ConnectorError::new(
                "DBX-RS-MY-OUTPUT-0020",
                ErrorClass::Internal,
                "Arrow IPC batch receiver closed",
                false,
                false,
            )
        })?;
    Ok(encoded_bytes)
}

fn plan_columns(
    columns: &[Column],
) -> Result<(QuerySchema, SchemaRef, Vec<ColumnPlan>), ConnectorError> {
    if columns.is_empty() {
        return Err(conversion_error(
            "DBX-RS-MY-SCHEMA-0003",
            "MySQL-family query returned no columns",
        ));
    }
    if columns.len() > MAX_QUERY_COLUMNS {
        return Err(conversion_error(
            "DBX-RS-MY-SCHEMA-0008",
            "MySQL-family query returned too many columns",
        ));
    }
    let mut names = BTreeSet::new();
    let mut plans = Vec::with_capacity(columns.len());
    for column in columns {
        let name = std::str::from_utf8(column.name_ref()).map_err(|_| {
            conversion_error(
                "DBX-RS-MY-SCHEMA-0004",
                "MySQL-family column name contained malformed UTF-8",
            )
        })?;
        if name.is_empty() || !names.insert(name.to_owned()) {
            return Err(conversion_error(
                "DBX-RS-MY-SCHEMA-0002",
                "MySQL-family query returned empty or duplicate column names",
            ));
        }
        plans.push(plan_column(column, name)?);
    }
    let query_schema = QuerySchema {
        fields: plans.iter().map(|plan| plan.field.clone()).collect(),
    };
    let fields = plans
        .iter()
        .map(|plan| {
            Field::new(
                &plan.field.name,
                plan.arrow_type.clone(),
                plan.field.nullable,
            )
        })
        .collect::<Vec<_>>();
    Ok((query_schema, Arc::new(Schema::new(fields)), plans))
}

#[allow(clippy::too_many_lines)]
fn plan_column(column: &Column, name: &str) -> Result<ColumnPlan, ConnectorError> {
    let flags = column.flags();
    let unsigned = flags.contains(ColumnFlags::UNSIGNED_FLAG);
    // BINARY_FLAG also marks text that uses a `_bin` collation, including MariaDB's JSON alias.
    let binary = column.character_set() == BINARY_CHARACTER_SET;
    let (field_type, arrow_type, value_type, source_type) = match column.column_type() {
        ColumnType::MYSQL_TYPE_TINY if unsigned => (
            FieldType::UInt32,
            DataType::UInt32,
            ValueType::UInt32,
            "TINYINT UNSIGNED".into(),
        ),
        ColumnType::MYSQL_TYPE_TINY => (
            FieldType::Int8,
            DataType::Int8,
            ValueType::Int8,
            "TINYINT".into(),
        ),
        ColumnType::MYSQL_TYPE_SHORT if unsigned => (
            FieldType::UInt32,
            DataType::UInt32,
            ValueType::UInt32,
            "SMALLINT UNSIGNED".into(),
        ),
        ColumnType::MYSQL_TYPE_SHORT => (
            FieldType::Int16,
            DataType::Int16,
            ValueType::Int16,
            "SMALLINT".into(),
        ),
        ColumnType::MYSQL_TYPE_INT24 if unsigned => (
            FieldType::UInt32,
            DataType::UInt32,
            ValueType::UInt32,
            "MEDIUMINT UNSIGNED".into(),
        ),
        ColumnType::MYSQL_TYPE_INT24 => (
            FieldType::Int32,
            DataType::Int32,
            ValueType::Int32,
            "MEDIUMINT".into(),
        ),
        ColumnType::MYSQL_TYPE_LONG if unsigned => (
            FieldType::UInt32,
            DataType::UInt32,
            ValueType::UInt32,
            "INT UNSIGNED".into(),
        ),
        ColumnType::MYSQL_TYPE_LONG => (
            FieldType::Int32,
            DataType::Int32,
            ValueType::Int32,
            "INT".into(),
        ),
        ColumnType::MYSQL_TYPE_LONGLONG if unsigned => (
            FieldType::Decimal128 {
                precision: 20,
                scale: 0,
            },
            DataType::Decimal128(20, 0),
            ValueType::Decimal128 {
                precision: 20,
                scale: 0,
                unsigned: true,
            },
            "BIGINT UNSIGNED".into(),
        ),
        ColumnType::MYSQL_TYPE_LONGLONG => (
            FieldType::Int64,
            DataType::Int64,
            ValueType::Int64,
            "BIGINT".into(),
        ),
        ColumnType::MYSQL_TYPE_YEAR => (
            FieldType::UInt32,
            DataType::UInt32,
            ValueType::UInt32,
            "YEAR".into(),
        ),
        ColumnType::MYSQL_TYPE_FLOAT => (
            FieldType::Float32,
            DataType::Float32,
            ValueType::Float32,
            "FLOAT".into(),
        ),
        ColumnType::MYSQL_TYPE_DOUBLE => (
            FieldType::Float64,
            DataType::Float64,
            ValueType::Float64,
            "DOUBLE".into(),
        ),
        ColumnType::MYSQL_TYPE_DECIMAL | ColumnType::MYSQL_TYPE_NEWDECIMAL => {
            let (precision, scale) = decimal_shape(column)?;
            (
                FieldType::Decimal128 { precision, scale },
                DataType::Decimal128(precision, scale),
                ValueType::Decimal128 {
                    precision,
                    scale,
                    unsigned,
                },
                format!(
                    "DECIMAL({precision},{scale}){}",
                    if unsigned { " UNSIGNED" } else { "" }
                ),
            )
        }
        ColumnType::MYSQL_TYPE_BIT if column.column_length() == 1 => (
            FieldType::Boolean,
            DataType::Boolean,
            ValueType::Boolean,
            "BIT(1)".into(),
        ),
        ColumnType::MYSQL_TYPE_BIT if (2..=64).contains(&column.column_length()) => (
            FieldType::Binary,
            DataType::Binary,
            ValueType::Binary,
            format!("BIT({})", column.column_length()),
        ),
        ColumnType::MYSQL_TYPE_DATE | ColumnType::MYSQL_TYPE_NEWDATE => (
            FieldType::Date32,
            DataType::Date32,
            ValueType::Date32,
            "DATE".into(),
        ),
        ColumnType::MYSQL_TYPE_DATETIME | ColumnType::MYSQL_TYPE_DATETIME2 => (
            FieldType::TimestampMicrosecond,
            DataType::Timestamp(TimeUnit::Microsecond, None),
            ValueType::TimestampMicrosecond,
            "DATETIME".into(),
        ),
        ColumnType::MYSQL_TYPE_TIMESTAMP | ColumnType::MYSQL_TYPE_TIMESTAMP2 => (
            FieldType::TimestampMicrosecondUtc,
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            ValueType::TimestampMicrosecondUtc,
            "TIMESTAMP".into(),
        ),
        ColumnType::MYSQL_TYPE_JSON => (
            FieldType::Json,
            DataType::Utf8,
            ValueType::Json,
            "JSON".into(),
        ),
        ColumnType::MYSQL_TYPE_VARCHAR
        | ColumnType::MYSQL_TYPE_VAR_STRING
        | ColumnType::MYSQL_TYPE_STRING
        | ColumnType::MYSQL_TYPE_TINY_BLOB
        | ColumnType::MYSQL_TYPE_MEDIUM_BLOB
        | ColumnType::MYSQL_TYPE_LONG_BLOB
        | ColumnType::MYSQL_TYPE_BLOB
            if binary =>
        {
            (
                FieldType::Binary,
                DataType::Binary,
                ValueType::Binary,
                "BINARY".into(),
            )
        }
        ColumnType::MYSQL_TYPE_VARCHAR
        | ColumnType::MYSQL_TYPE_VAR_STRING
        | ColumnType::MYSQL_TYPE_STRING
        | ColumnType::MYSQL_TYPE_TINY_BLOB
        | ColumnType::MYSQL_TYPE_MEDIUM_BLOB
        | ColumnType::MYSQL_TYPE_LONG_BLOB
        | ColumnType::MYSQL_TYPE_BLOB
        | ColumnType::MYSQL_TYPE_ENUM
        | ColumnType::MYSQL_TYPE_SET => (
            FieldType::Utf8,
            DataType::Utf8,
            ValueType::Utf8,
            "TEXT".into(),
        ),
        _ => {
            return Err(conversion_error(
                "DBX-RS-MY-CONVERT-0020",
                "MySQL-family query output contains an unsupported type",
            ));
        }
    };
    Ok(ColumnPlan {
        field: FieldDescriptor {
            name: name.into(),
            field_type,
            nullable: !flags.contains(ColumnFlags::NOT_NULL_FLAG),
            source_type,
        },
        arrow_type,
        value_type,
    })
}

fn decimal_shape(column: &Column) -> Result<(u8, i8), ConnectorError> {
    let scale = column.decimals();
    if scale > 38 {
        return Err(decimal_declaration_error());
    }
    let overhead =
        u32::from(scale > 0) + u32::from(!column.flags().contains(ColumnFlags::UNSIGNED_FLAG));
    let precision = column
        .column_length()
        .checked_sub(overhead)
        .and_then(|value| u8::try_from(value).ok())
        .ok_or_else(decimal_declaration_error)?;
    if precision == 0 || precision > 38 || scale > precision {
        return Err(decimal_declaration_error());
    }
    let scale = i8::try_from(scale).map_err(|_| decimal_declaration_error())?;
    Ok((precision, scale))
}

fn decimal_declaration_error() -> ConnectorError {
    conversion_error(
        "DBX-RS-MY-CONVERT-0034",
        "MySQL-family decimal declaration is outside Decimal128 precision and scale limits",
    )
}

fn rows_to_batch(
    rows: &[Row],
    plans: &[ColumnPlan],
    schema: SchemaRef,
) -> Result<RecordBatch, ConnectorError> {
    let arrays = plans
        .iter()
        .enumerate()
        .map(|(index, plan)| column_array(rows, index, plan))
        .collect::<Result<Vec<_>, _>>()?;
    RecordBatch::try_new(schema, arrays).map_err(|_| {
        conversion_error(
            "DBX-RS-MY-CONVERT-0021",
            "failed to construct MySQL-family Arrow record batch",
        )
    })
}

#[allow(clippy::too_many_lines)]
fn column_array(rows: &[Row], index: usize, plan: &ColumnPlan) -> Result<ArrayRef, ConnectorError> {
    macro_rules! primitive_array {
        ($converter:expr, $array_type:ty) => {{
            let values = rows
                .iter()
                .map(|row| optional_value(row, index, plan, $converter))
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(<$array_type>::from(values)) as ArrayRef
        }};
    }
    let array = match plan.value_type {
        ValueType::Boolean => primitive_array!(boolean_value, BooleanArray),
        ValueType::Int8 => primitive_array!(signed_i8, Int8Array),
        ValueType::Int16 => primitive_array!(signed_i16, Int16Array),
        ValueType::Int32 => primitive_array!(signed_i32, Int32Array),
        ValueType::Int64 => primitive_array!(signed_i64, Int64Array),
        ValueType::UInt32 => primitive_array!(unsigned_u32, UInt32Array),
        ValueType::Float32 => primitive_array!(finite_f32, Float32Array),
        ValueType::Float64 => primitive_array!(finite_f64, Float64Array),
        ValueType::Utf8 => {
            let values = rows
                .iter()
                .map(|row| optional_value(row, index, plan, strict_utf8))
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(StringArray::from(values))
        }
        ValueType::Binary => {
            let values = rows
                .iter()
                .map(|row| optional_value(row, index, plan, binary_value))
                .collect::<Result<Vec<_>, _>>()?;
            let borrowed = values.iter().map(Option::as_deref).collect::<Vec<_>>();
            Arc::new(BinaryArray::from(borrowed))
        }
        ValueType::Json => {
            let values = rows
                .iter()
                .map(|row| optional_value(row, index, plan, json_value))
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(StringArray::from(values))
        }
        ValueType::Decimal128 {
            precision,
            scale,
            unsigned,
        } => {
            let values = rows
                .iter()
                .map(|row| {
                    optional_value(row, index, plan, |value| {
                        decimal_value(value, precision, scale, unsigned)
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let array = Decimal128Array::from(values)
                .with_precision_and_scale(precision, scale)
                .map_err(|_| {
                    conversion_error(
                        "DBX-RS-MY-CONVERT-0022",
                        "MySQL-family decimal exceeds its declared precision",
                    )
                })?;
            Arc::new(array)
        }
        ValueType::Date32 => primitive_array!(date32_value, Date32Array),
        ValueType::TimestampMicrosecond => {
            primitive_array!(timestamp_micros, TimestampMicrosecondArray)
        }
        ValueType::TimestampMicrosecondUtc => {
            let values = rows
                .iter()
                .map(|row| optional_value(row, index, plan, timestamp_micros))
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(TimestampMicrosecondArray::from(values).with_timezone("UTC"))
        }
    };
    Ok(array)
}

fn optional_value<T, F>(
    row: &Row,
    index: usize,
    plan: &ColumnPlan,
    converter: F,
) -> Result<Option<T>, ConnectorError>
where
    F: Fn(&Value) -> Result<T, ConnectorError>,
{
    match cell(row, index)? {
        Some(value) => converter(value).map(Some),
        None if plan.field.nullable => Ok(None),
        None => Err(conversion_error(
            "DBX-RS-MY-CONVERT-0037",
            "MySQL-family row contradicted non-nullable metadata",
        )),
    }
}

fn cell(row: &Row, index: usize) -> Result<Option<&Value>, ConnectorError> {
    match row.as_ref(index) {
        Some(Value::NULL) => Ok(None),
        Some(value) => Ok(Some(value)),
        None => Err(conversion_error(
            "DBX-RS-MY-CONVERT-0023",
            "MySQL-family row did not match its declared schema",
        )),
    }
}

fn boolean_value(value: &Value) -> Result<bool, ConnectorError> {
    match value {
        Value::Bytes(bytes) if bytes.as_slice() == [0] => Ok(false),
        Value::Bytes(bytes) if bytes.as_slice() == [1] => Ok(true),
        _ => Err(value_conversion_error()),
    }
}

fn signed_i8(value: &Value) -> Result<i8, ConnectorError> {
    i8::try_from(signed_i64(value)?).map_err(|_| value_conversion_error())
}

fn signed_i16(value: &Value) -> Result<i16, ConnectorError> {
    i16::try_from(signed_i64(value)?).map_err(|_| value_conversion_error())
}

fn signed_i32(value: &Value) -> Result<i32, ConnectorError> {
    i32::try_from(signed_i64(value)?).map_err(|_| value_conversion_error())
}

fn signed_i64(value: &Value) -> Result<i64, ConnectorError> {
    match value {
        Value::Int(value) => Ok(*value),
        _ => Err(value_conversion_error()),
    }
}

fn unsigned_u32(value: &Value) -> Result<u32, ConnectorError> {
    match value {
        Value::UInt(value) => u32::try_from(*value).map_err(|_| value_conversion_error()),
        Value::Int(value) if *value >= 0 => {
            u32::try_from(*value).map_err(|_| value_conversion_error())
        }
        _ => Err(value_conversion_error()),
    }
}

fn finite_f32(value: &Value) -> Result<f32, ConnectorError> {
    let Value::Float(value) = value else {
        return Err(value_conversion_error());
    };
    if !value.is_finite() {
        return Err(non_finite_error());
    }
    Ok(*value)
}

fn finite_f64(value: &Value) -> Result<f64, ConnectorError> {
    let Value::Double(value) = value else {
        return Err(value_conversion_error());
    };
    if !value.is_finite() {
        return Err(non_finite_error());
    }
    Ok(*value)
}

fn strict_utf8(value: &Value) -> Result<String, ConnectorError> {
    let Value::Bytes(bytes) = value else {
        return Err(value_conversion_error());
    };
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| value_conversion_error())
}

fn binary_value(value: &Value) -> Result<Vec<u8>, ConnectorError> {
    match value {
        Value::Bytes(bytes) => Ok(bytes.clone()),
        _ => Err(value_conversion_error()),
    }
}

fn json_value(value: &Value) -> Result<String, ConnectorError> {
    let json = strict_utf8(value)?;
    let _raw: &serde_json::value::RawValue =
        serde_json::from_str(&json).map_err(|_| value_conversion_error())?;
    Ok(json)
}

fn decimal_value(
    value: &Value,
    precision: u8,
    scale: i8,
    unsigned: bool,
) -> Result<i128, ConnectorError> {
    if let Value::UInt(value) = value
        && scale == 0
        && precision == 20
        && unsigned
    {
        return Ok(i128::from(*value));
    }
    let Value::Bytes(bytes) = value else {
        return Err(value_conversion_error());
    };
    parse_decimal(bytes, precision, scale, unsigned)
}

fn parse_decimal(
    bytes: &[u8],
    precision: u8,
    scale: i8,
    unsigned: bool,
) -> Result<i128, ConnectorError> {
    let text = std::str::from_utf8(bytes).map_err(|_| value_conversion_error())?;
    let (negative, digits) = text
        .strip_prefix('-')
        .map_or((false, text), |digits| (true, digits));
    if digits.is_empty() || (unsigned && negative) {
        return Err(value_conversion_error());
    }
    let scale = usize::try_from(scale).map_err(|_| value_conversion_error())?;
    let (integer, fraction) = digits.split_once('.').map_or((digits, ""), |parts| parts);
    if integer.is_empty()
        || integer.bytes().any(|byte| !byte.is_ascii_digit())
        || fraction.bytes().any(|byte| !byte.is_ascii_digit())
        || fraction.len() != scale
        || (scale == 0 && digits.contains('.'))
        || (integer.len() > 1 && integer.starts_with('0'))
    {
        return Err(value_conversion_error());
    }
    let all_digits = format!("{integer}{fraction}");
    let integer_digits = usize::from(integer != "0") * integer.len();
    if integer_digits.saturating_add(fraction.len()) > usize::from(precision) {
        return Err(value_conversion_error());
    }
    let mut parsed = 0_i128;
    for digit in all_digits.bytes() {
        parsed = parsed
            .checked_mul(10)
            .and_then(|value| value.checked_add(i128::from(digit - b'0')))
            .ok_or_else(value_conversion_error)?;
    }
    if negative && parsed != 0 {
        parsed = parsed.checked_neg().ok_or_else(value_conversion_error)?;
    }
    Ok(parsed)
}

fn date32_value(value: &Value) -> Result<i32, ConnectorError> {
    let Value::Date(year, month, day, hour, minute, second, micros) = value else {
        return Err(value_conversion_error());
    };
    if *hour != 0 || *minute != 0 || *second != 0 || *micros != 0 {
        return Err(value_conversion_error());
    }
    let date = valid_date(*year, *month, *day)?;
    Ok(date.num_days_from_ce() - 719_163)
}

fn timestamp_micros(value: &Value) -> Result<i64, ConnectorError> {
    let Value::Date(year, month, day, hour, minute, second, micros) = value else {
        return Err(value_conversion_error());
    };
    let date = valid_date(*year, *month, *day)?;
    let timestamp = date
        .and_hms_micro_opt(
            u32::from(*hour),
            u32::from(*minute),
            u32::from(*second),
            *micros,
        )
        .ok_or_else(value_conversion_error)?;
    Ok(timestamp.and_utc().timestamp_micros())
}

fn valid_date(year: u16, month: u8, day: u8) -> Result<NaiveDate, ConnectorError> {
    if year == 0 || month == 0 || day == 0 {
        return Err(conversion_error(
            "DBX-RS-MY-CONVERT-0038",
            "zero or incomplete MySQL-family dates are unsupported",
        ));
    }
    NaiveDate::from_ymd_opt(i32::from(year), u32::from(month), u32::from(day))
        .ok_or_else(value_conversion_error)
}

fn value_conversion_error() -> ConnectorError {
    conversion_error(
        "DBX-RS-MY-CONVERT-0024",
        "MySQL-family value could not be converted without loss",
    )
}

fn non_finite_error() -> ConnectorError {
    conversion_error(
        "DBX-RS-MY-CONVERT-0025",
        "non-finite MySQL-family floating-point values require an explicit text cast",
    )
}

fn encode_batch(batch: &RecordBatch, max_bytes: u64) -> Result<Vec<u8>, ConnectorError> {
    let max_bytes = usize::try_from(max_bytes).map_err(|_| {
        configuration_error(
            "DBX-RS-MY-CFG-0027",
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
            "DBX-RS-MY-LIMIT-0020",
            ErrorClass::Query,
            "MySQL-family Arrow IPC batch exceeded its byte limit",
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

pub(super) fn validate_prepare_request(request: &PrepareRequest) -> Result<(), ConnectorError> {
    if request.request_id.trim().is_empty()
        || request.request_id.len() > MySqlFamilyConnector::MAX_REQUEST_ID_BYTES
        || request.request_id.chars().any(char::is_control)
    {
        return Err(configuration_error(
            "DBX-RS-MY-CFG-0057",
            "prepare request ID is invalid or exceeds its hard limit",
        ));
    }
    if request.timeout.is_zero() {
        return Err(configuration_error(
            "DBX-RS-MY-CFG-0058",
            "prepare timeout must be greater than zero",
        ));
    }
    if request.timeout > MySqlFamilyConnector::MAX_OPERATION_TIMEOUT {
        return Err(configuration_error(
            "DBX-RS-MY-CFG-0045",
            "prepare timeout exceeds the connector hard limit",
        ));
    }
    Ok(())
}

pub(super) fn validate_execute_request(request: &ExecuteRequest) -> Result<(), ConnectorError> {
    if request.request_id.trim().is_empty()
        || request.request_id.len() > MySqlFamilyConnector::MAX_REQUEST_ID_BYTES
        || request.request_id.chars().any(char::is_control)
    {
        return Err(configuration_error(
            "DBX-RS-MY-CFG-0059",
            "execute request ID is invalid or exceeds its hard limit",
        ));
    }
    if request.limits.timeout.is_zero() {
        return Err(configuration_error(
            "DBX-RS-MY-CFG-0060",
            "typed query timeout must be greater than zero",
        ));
    }
    if request.limits.timeout > MySqlFamilyConnector::MAX_OPERATION_TIMEOUT {
        return Err(configuration_error(
            "DBX-RS-MY-CFG-0045",
            "typed query timeout exceeds the connector hard limit",
        ));
    }
    if request.limits.max_batch_rows == 0 {
        return Err(configuration_error(
            "DBX-RS-MY-CFG-0024",
            "typed query batch row limit must be greater than zero",
        ));
    }
    if request.limits.max_batch_bytes == 0 {
        return Err(configuration_error(
            "DBX-RS-MY-CFG-0025",
            "typed query batch byte limit must be greater than zero",
        ));
    }
    if request.limits.max_total_ipc_bytes == 0 {
        return Err(configuration_error(
            "DBX-RS-MY-CFG-0026",
            "typed query total IPC byte limit must be greater than zero",
        ));
    }
    if request.limits.max_batch_rows > MAX_TYPED_BATCH_ROWS {
        return Err(configuration_error(
            "DBX-RS-MY-CFG-0061",
            "typed query batch row limit exceeds the connector hard limit",
        ));
    }
    if request.limits.max_batch_bytes > MAX_TYPED_BATCH_IPC_BYTES {
        return Err(configuration_error(
            "DBX-RS-MY-CFG-0062",
            "typed query batch IPC byte limit exceeds the connector hard limit",
        ));
    }
    if request.limits.max_total_ipc_bytes > MAX_TYPED_TOTAL_IPC_BYTES {
        return Err(configuration_error(
            "DBX-RS-MY-CFG-0042",
            "typed query total IPC byte limit exceeds the connector hard limit",
        ));
    }
    if request.limits.max_batch_bytes > request.limits.max_total_ipc_bytes {
        return Err(configuration_error(
            "DBX-RS-MY-CFG-0043",
            "typed query batch IPC byte limit exceeds its total IPC byte limit",
        ));
    }
    Ok(())
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
        ConnectionConfig, CursorNullPolicy, ExecutionLimits, QueryText, TimestampIdCursorSpec,
        TlsMode,
    };

    use super::*;

    fn column(column_type: ColumnType, name: &str) -> Column {
        Column::new(column_type).with_name(name.as_bytes())
    }

    fn execute_request() -> ExecuteRequest {
        ExecuteRequest {
            request_id: "request-1".into(),
            connection: ConnectionConfig {
                connector_id: "mysql".into(),
                host: "localhost".into(),
                port: 3306,
                database: "events".into(),
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

    #[test]
    fn signed_and_unsigned_integer_metadata_map_without_loss() {
        let signed = plan_column(&column(ColumnType::MYSQL_TYPE_LONGLONG, "signed"), "signed")
            .expect("signed BIGINT should map");
        let unsigned_column = column(ColumnType::MYSQL_TYPE_LONGLONG, "unsigned")
            .with_flags(ColumnFlags::UNSIGNED_FLAG);
        let unsigned =
            plan_column(&unsigned_column, "unsigned").expect("unsigned BIGINT should map");

        assert_eq!(signed.field.field_type, FieldType::Int64);
        assert_eq!(
            unsigned.field.field_type,
            FieldType::Decimal128 {
                precision: 20,
                scale: 0
            }
        );
        assert_eq!(
            decimal_value(&Value::UInt(u64::MAX), 20, 0, true),
            Ok(i128::from(u64::MAX))
        );
    }

    #[test]
    fn decimal_metadata_and_values_preserve_declared_scale() {
        let decimal = column(ColumnType::MYSQL_TYPE_NEWDECIMAL, "amount")
            .with_column_length(12)
            .with_decimals(2);
        let plan = plan_column(&decimal, "amount").expect("DECIMAL(10,2) should map");
        let all_fractional = column(ColumnType::MYSQL_TYPE_NEWDECIMAL, "ratio")
            .with_column_length(4)
            .with_decimals(2);
        let all_fractional_plan =
            plan_column(&all_fractional, "ratio").expect("DECIMAL(2,2) should map");

        assert_eq!(
            plan.field.field_type,
            FieldType::Decimal128 {
                precision: 10,
                scale: 2
            }
        );
        assert_eq!(
            all_fractional_plan.field.field_type,
            FieldType::Decimal128 {
                precision: 2,
                scale: 2
            }
        );
        assert_eq!(
            parse_decimal(b"-12345678.90", 10, 2, false),
            Ok(-1_234_567_890)
        );
        assert_eq!(parse_decimal(b"0.12", 2, 2, false), Ok(12));
        assert_eq!(parse_decimal(b"0.01", 2, 2, false), Ok(1));
        assert!(parse_decimal(b"00.12", 2, 2, false).is_err());
        assert!(parse_decimal(b"1.2", 10, 2, false).is_err());
        assert!(parse_decimal(b"-1.00", 10, 2, true).is_err());
    }

    #[test]
    fn decimal_declarations_over_decimal128_fail_closed() {
        let too_wide = column(ColumnType::MYSQL_TYPE_NEWDECIMAL, "wide")
            .with_column_length(42)
            .with_decimals(2);
        let error = plan_column(&too_wide, "wide")
            .err()
            .expect("wide decimal must fail");

        assert_eq!(error.code(), "DBX-RS-MY-CONVERT-0034");
    }

    #[test]
    fn result_column_count_is_hard_bounded() {
        let columns = (0..=MAX_QUERY_COLUMNS)
            .map(|index| column(ColumnType::MYSQL_TYPE_LONG, &format!("column_{index}")))
            .collect::<Vec<_>>();

        let error = plan_columns(&columns)
            .err()
            .expect("oversized result schema must fail");

        assert_eq!(error.code(), "DBX-RS-MY-SCHEMA-0008");
    }

    #[test]
    fn binary_charset_distinguishes_bytes_from_bin_collated_text_and_json() {
        let binary =
            column(ColumnType::MYSQL_TYPE_BLOB, "payload").with_character_set(BINARY_CHARACTER_SET);
        let text = column(ColumnType::MYSQL_TYPE_BLOB, "message")
            .with_character_set(255)
            .with_flags(ColumnFlags::BINARY_FLAG);
        let json = column(ColumnType::MYSQL_TYPE_JSON, "document")
            .with_character_set(BINARY_CHARACTER_SET)
            .with_flags(ColumnFlags::BINARY_FLAG);

        assert_eq!(
            plan_column(&binary, "payload")
                .expect("binary should map")
                .field
                .field_type,
            FieldType::Binary
        );
        assert_eq!(
            plan_column(&text, "message")
                .expect("text should map")
                .field
                .field_type,
            FieldType::Utf8
        );
        assert_eq!(
            plan_column(&json, "document")
                .expect("native MySQL JSON should map")
                .field
                .field_type,
            FieldType::Json
        );
    }

    #[test]
    fn exact_temporal_conversion_rejects_zero_and_invalid_dates() {
        assert!(date32_value(&Value::Date(0, 0, 0, 0, 0, 0, 0)).is_err());
        assert!(timestamp_micros(&Value::Date(2024, 2, 30, 0, 0, 0, 0)).is_err());
        assert_eq!(
            timestamp_micros(&Value::Date(1970, 1, 1, 0, 0, 0, 1)),
            Ok(1)
        );
    }

    #[test]
    fn json_and_floats_fail_closed_on_invalid_values() {
        assert_eq!(
            json_value(&Value::Bytes(br#"{"id":9007199254740993}"#.to_vec())),
            Ok(r#"{"id":9007199254740993}"#.into())
        );
        assert!(json_value(&Value::Bytes(b"{invalid".to_vec())).is_err());
        assert!(finite_f64(&Value::Double(f64::INFINITY)).is_err());
    }

    #[test]
    fn cursor_schema_requires_timestamp_and_signed_bigint() {
        let spec = TimestampIdCursorSpec {
            timestamp_field: "updated_at".into(),
            id_field: "id".into(),
            overlap: Duration::ZERO,
            null_policy: CursorNullPolicy::Reject,
        };
        let schema = QuerySchema {
            fields: vec![
                FieldDescriptor {
                    name: "updated_at".into(),
                    field_type: FieldType::TimestampMicrosecondUtc,
                    nullable: false,
                    source_type: "TIMESTAMP".into(),
                },
                FieldDescriptor {
                    name: "id".into(),
                    field_type: FieldType::Int64,
                    nullable: false,
                    source_type: "BIGINT".into(),
                },
            ],
        };

        assert!(validate_cursor_schema(&schema, &spec).is_ok());
        let mut unsigned = schema;
        unsigned.fields[1].field_type = FieldType::Decimal128 {
            precision: 20,
            scale: 0,
        };
        assert!(validate_cursor_schema(&unsigned, &spec).is_err());
    }

    #[test]
    fn query_parameters_use_binary_values_and_n_plus_one_limit() {
        let parameters = query_parameters(
            Some(TimestampIdCursorBound {
                value: TimestampIdCursor::new(1, -7),
                inclusive: false,
            }),
            10,
        )
        .expect("cursor parameters should convert");

        assert!(matches!(parameters[0], Value::Date(..)));
        assert_eq!(parameters[1], Value::Int(-7));
        assert_eq!(parameters[2], Value::UInt(11));
    }

    #[test]
    fn cursor_parameters_reject_dates_outside_the_server_envelope() {
        let year_999 = NaiveDate::from_ymd_opt(999, 12, 31)
            .expect("test date must exist")
            .and_hms_opt(23, 59, 59)
            .expect("test time must exist")
            .and_utc()
            .timestamp_micros();

        let error = cursor_timestamp_parameter(year_999)
            .expect_err("pre-MySQL-range cursor timestamp must fail");

        assert_eq!(error.code(), "DBX-RS-MY-CFG-0047");
    }

    #[test]
    fn execute_limits_apply_connector_hard_caps() {
        let mut request = execute_request();
        request.limits.max_batch_rows += 1;
        assert_eq!(
            validate_execute_request(&request)
                .expect_err("row cap should fail")
                .code(),
            "DBX-RS-MY-CFG-0061"
        );

        let mut request = execute_request();
        request.limits.max_batch_bytes += 1;
        assert_eq!(
            validate_execute_request(&request)
                .expect_err("byte cap should fail")
                .code(),
            "DBX-RS-MY-CFG-0062"
        );
    }

    #[test]
    fn unsupported_time_and_geometry_types_fail_closed() {
        for column_type in [
            ColumnType::MYSQL_TYPE_TIME,
            ColumnType::MYSQL_TYPE_GEOMETRY,
            ColumnType::MYSQL_TYPE_VECTOR,
        ] {
            let column = column(column_type, "unsupported");
            assert!(plan_column(&column, "unsupported").is_err());
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
