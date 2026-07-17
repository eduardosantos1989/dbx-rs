use std::{
    cmp::Ordering,
    collections::BTreeSet,
    fmt::Write as _,
    io::{self, Write},
    sync::Arc,
    time::Duration,
};

use arrow_array::{
    ArrayRef, BinaryArray, BooleanArray, Date32Array, Decimal128Array, Float32Array, Float64Array,
    Int16Array, Int32Array, Int64Array, RecordBatch, StringArray, Time64MicrosecondArray,
    TimestampMicrosecondArray,
};
use arrow_ipc::writer::StreamWriter;
use arrow_schema::{DataType, Field, Schema, SchemaRef, TimeUnit};
use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, NaiveTime, Timelike, Utc};
use dbx_rs_connector_sdk::{
    ArrowIpcBatch, ConnectorError, ErrorClass, ExecuteRequest, ExecutionResult, FieldDescriptor,
    FieldType, PrepareRequest, PreparedQuery, QuerySchema, TimestampIdCursor,
    TimestampIdCursorBound, TimestampIdCursorSpec,
};
use mssql_client::{Column, FromSql, Row, ToSql};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{
    MssqlConnector, classify_query_error, open_session,
    sql::{NormalizedQuery, normalize_query, quote_identifier},
};

const MAX_TYPED_BATCH_ROWS: u32 = 256;
const MAX_QUERY_COLUMNS: usize = 256;
const MAX_FIELD_NAME_BYTES: usize = 512;
const MAX_VALUE_BYTES: usize = 1024 * 1024;
const MAX_FIXED_BATCH_VALUE_BYTES: u64 = 256 * 1024;
const MAX_TYPED_BATCH_IPC_BYTES: u64 = 1024 * 1024;
const MAX_TYPED_TOTAL_IPC_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const CANCELLATION_GRACE: Duration = Duration::from_secs(5);
const DESCRIBE_TEMPORAL_METADATA_SQL: &str = "SELECT [column_ordinal], [name], [scale] FROM sys.dm_exec_describe_first_result_set(@P1, NULL, 0) WHERE [is_hidden] = 0 ORDER BY [column_ordinal]";

#[derive(Clone, Debug)]
struct ColumnPlan {
    field: FieldDescriptor,
    arrow_type: DataType,
    value_type: ValueType,
    projection: String,
}

#[derive(Clone, Copy, Debug)]
enum ValueType {
    Boolean,
    Int16,
    Int32,
    Int64,
    Float32,
    Float64,
    Utf8,
    Binary,
    Uuid,
    Decimal128 { precision: u8, scale: i8 },
    Date32,
    Time64Microsecond,
    TimestampMicrosecond,
    TimestampMicrosecondUtc,
}

#[derive(Clone, Copy)]
struct CursorProjection {
    timestamp_index: usize,
    id_index: usize,
}

struct QueryParameters {
    timestamp: Option<NaiveDateTime>,
    id: Option<i64>,
    fetch_rows: i32,
}

struct DescribedColumn {
    ordinal: usize,
    name: String,
    scale: Option<u8>,
}

pub(super) async fn prepare(
    request: PrepareRequest,
    secret: &dbx_rs_connector_sdk::ResolvedSecret,
    cancellation: CancellationToken,
) -> Result<PreparedQuery, ConnectorError> {
    MssqlConnector::validate_operation(&request.connection, secret)?;
    validate_prepare_request(&request)?;
    let query = normalize_query(
        request.query.as_str(),
        request.max_rows,
        request.cursor.as_ref(),
    )?;
    let mut session = open_session(
        &request.connection,
        secret,
        request.timeout,
        MssqlConnector::MAX_WIRE_MESSAGE_BYTES,
        &cancellation,
    )
    .await?;
    let cancel_handle = session.client.cancel_handle();
    let operation = prepare_schema(
        &mut session.client,
        &query,
        request.cursor.as_ref().map(|cursor| &cursor.spec),
    );
    tokio::pin!(operation);
    let deadline = tokio::time::sleep(request.timeout);
    tokio::pin!(deadline);
    let schema = tokio::select! {
        biased;
        result = &mut operation => result,
        () = cancellation.cancelled() => {
            let _ = cancel_handle.cancel().await;
            let _ = tokio::time::timeout(CANCELLATION_GRACE, &mut operation).await;
            Err(ConnectorError::cancelled("DBX-RS-MS-CANCELLED-0020"))
        }
        () = &mut deadline => {
            let _ = cancel_handle.cancel().await;
            let _ = tokio::time::timeout(CANCELLATION_GRACE, &mut operation).await;
            Err(operation_timeout(
                "DBX-RS-MS-QUERY-0020",
                "SQL Server prepare timed out",
            ))
        }
    }?;
    Ok(PreparedQuery {
        request_id: request.request_id,
        connector_id: MssqlConnector::CONNECTOR_ID.into(),
        schema,
    })
}

pub(super) async fn execute(
    request: ExecuteRequest,
    secret: &dbx_rs_connector_sdk::ResolvedSecret,
    batch_tx: mpsc::Sender<ArrowIpcBatch>,
    cancellation: CancellationToken,
) -> Result<ExecutionResult, ConnectorError> {
    MssqlConnector::validate_operation(&request.connection, secret)?;
    validate_execute_request(&request)?;
    let query = normalize_query(
        request.query.as_str(),
        request.limits.max_rows,
        request.cursor.as_ref(),
    )?;
    let mut session = open_session(
        &request.connection,
        secret,
        request.limits.timeout,
        MssqlConnector::MAX_WIRE_MESSAGE_BYTES,
        &cancellation,
    )
    .await?;
    let cancel_handle = session.client.cancel_handle();
    let timeout = request.limits.timeout;
    let operation = execute_query(&mut session.client, query, request, batch_tx);
    tokio::pin!(operation);
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    tokio::select! {
        biased;
        result = &mut operation => result,
        () = cancellation.cancelled() => {
            let _ = cancel_handle.cancel().await;
            let _ = tokio::time::timeout(CANCELLATION_GRACE, &mut operation).await;
            Err(ConnectorError::cancelled("DBX-RS-MS-CANCELLED-0021"))
        }
        () = &mut deadline => {
            let _ = cancel_handle.cancel().await;
            let _ = tokio::time::timeout(CANCELLATION_GRACE, &mut operation).await;
            Err(operation_timeout(
                "DBX-RS-MS-QUERY-0021",
                "SQL Server typed query timed out",
            ))
        }
    }
}

async fn prepare_schema(
    client: &mut mssql_client::Client<mssql_client::Ready>,
    query: &NormalizedQuery,
    cursor_spec: Option<&TimestampIdCursorSpec>,
) -> Result<QuerySchema, ConnectorError> {
    let (schema, _arrow_schema, _plans, _cursor_projection) =
        discover_query(client, query, cursor_spec).await?;
    Ok(schema)
}

#[allow(clippy::too_many_lines)]
async fn execute_query(
    client: &mut mssql_client::Client<mssql_client::Ready>,
    query: NormalizedQuery,
    request: ExecuteRequest,
    batch_tx: mpsc::Sender<ArrowIpcBatch>,
) -> Result<ExecutionResult, ConnectorError> {
    let (query_schema, arrow_schema, plans, cursor_projection) = discover_query(
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
            "DBX-RS-MS-SCHEMA-0001",
            "SQL Server query schema changed before execution",
        ));
    }

    let projection = projection_sql(&plans);
    let sql = query.execution_sql(&projection, request.cursor.as_ref());
    let parameters = query_parameters(query.cursor_bound, request.limits.max_rows)?;
    let mut rows = if let (Some(timestamp), Some(id)) = (parameters.timestamp, parameters.id) {
        let params: [&(dyn ToSql + Sync); 3] = [&timestamp, &id, &parameters.fetch_rows];
        client
            .query_stream(&sql, &params)
            .await
            .map_err(|error| classify_query_error(&error))?
    } else {
        let params: [&(dyn ToSql + Sync); 1] = [&parameters.fetch_rows];
        client
            .query_stream(&sql, &params)
            .await
            .map_err(|error| classify_query_error(&error))?
    };
    validate_projected_columns(rows.columns(), &plans)?;

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
            if rows
                .try_next()
                .await
                .map_err(|error| classify_query_error(&error))?
                .is_some()
            {
                return Err(protocol_error(
                    "DBX-RS-MS-PROTOCOL-0020",
                    "SQL Server returned more rows than the bound TOP request",
                ));
            }
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

    Ok(ExecutionResult {
        request_id: request.request_id,
        rows_read,
        batches_emitted: sequence,
        ipc_bytes_emitted,
        truncated,
        schema: query_schema,
    })
}

async fn discover_query(
    client: &mut mssql_client::Client<mssql_client::Ready>,
    query: &NormalizedQuery,
    cursor_spec: Option<&TimestampIdCursorSpec>,
) -> Result<
    (
        QuerySchema,
        SchemaRef,
        Vec<ColumnPlan>,
        Option<CursorProjection>,
    ),
    ConnectorError,
> {
    let metadata_sql = query.metadata_sql();
    let mut metadata = client
        .query_stream(&metadata_sql, &[])
        .await
        .map_err(|error| classify_query_error(&error))?;
    let mut source_columns = metadata.columns().to_vec();
    if metadata
        .try_next()
        .await
        .map_err(|error| classify_query_error(&error))?
        .is_some()
    {
        return Err(protocol_error(
            "DBX-RS-MS-PROTOCOL-0021",
            "SQL Server metadata query unexpectedly returned rows",
        ));
    }
    drop(metadata);

    hydrate_temporal_metadata(client, &metadata_sql, &mut source_columns).await?;

    let (query_schema, arrow_schema, plans) = plan_columns(&source_columns, cursor_spec)?;
    let cursor_projection = cursor_spec
        .map(|spec| validate_cursor_schema(&query_schema, spec))
        .transpose()?;
    let projection = projection_sql(&plans);
    let projected_sql = query.projected_metadata_sql(&projection);
    let mut projected = client
        .query_stream(&projected_sql, &[])
        .await
        .map_err(|error| classify_query_error(&error))?;
    validate_projected_columns(projected.columns(), &plans)?;
    if projected
        .try_next()
        .await
        .map_err(|error| classify_query_error(&error))?
        .is_some()
    {
        return Err(protocol_error(
            "DBX-RS-MS-PROTOCOL-0022",
            "SQL Server projected metadata query unexpectedly returned rows",
        ));
    }
    Ok((query_schema, arrow_schema, plans, cursor_projection))
}

async fn hydrate_temporal_metadata(
    client: &mut mssql_client::Client<mssql_client::Ready>,
    metadata_sql: &str,
    columns: &mut [Column],
) -> Result<(), ConnectorError> {
    if !columns.iter().any(is_temporal_column) {
        return Ok(());
    }

    let metadata_sql = metadata_sql.to_owned();
    let params: [&(dyn ToSql + Sync); 1] = [&metadata_sql];
    let mut rows = client
        .query_stream(DESCRIBE_TEMPORAL_METADATA_SQL, &params)
        .await
        .map_err(|error| classify_query_error(&error))?;
    let mut described = Vec::with_capacity(columns.len());
    while let Some(row) = rows
        .try_next()
        .await
        .map_err(|error| classify_query_error(&error))?
    {
        let ordinal = row
            .try_get::<i32>(0)
            .map_err(|_| temporal_metadata_error())?
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(temporal_metadata_error)?;
        let name = row
            .try_get::<String>(1)
            .map_err(|_| temporal_metadata_error())?
            .ok_or_else(temporal_metadata_error)?;
        let scale = row
            .try_get::<u8>(2)
            .map_err(|_| temporal_metadata_error())?;
        described.push(DescribedColumn {
            ordinal,
            name,
            scale,
        });
    }
    merge_temporal_metadata(columns, &described)
}

fn merge_temporal_metadata(
    columns: &mut [Column],
    described: &[DescribedColumn],
) -> Result<(), ConnectorError> {
    if columns.len() != described.len() {
        return Err(temporal_metadata_error());
    }
    for (index, (column, described)) in columns.iter_mut().zip(described).enumerate() {
        if described.ordinal != index + 1 || described.name != column.name {
            return Err(temporal_metadata_error());
        }
        if is_temporal_column(column) {
            column.scale = Some(described.scale.ok_or_else(temporal_metadata_error)?);
        }
    }
    Ok(())
}

fn is_temporal_column(column: &Column) -> bool {
    matches!(
        column.type_name.as_str(),
        "Time" | "DateTime2" | "DateTimeOffset"
    )
}

fn projection_sql(plans: &[ColumnPlan]) -> String {
    plans
        .iter()
        .map(|plan| plan.projection.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

fn validate_projected_columns(
    columns: &[Column],
    plans: &[ColumnPlan],
) -> Result<(), ConnectorError> {
    if columns.len() != plans.len()
        || columns
            .iter()
            .zip(plans)
            .any(|(column, plan)| column.name != plan.field.name)
    {
        return Err(conversion_error(
            "DBX-RS-MS-SCHEMA-0005",
            "SQL Server query wrapper changed the output schema",
        ));
    }
    Ok(())
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
            "DBX-RS-MS-CFG-0056",
            "SQL Server cursor requires unique UTC datetime2(0..6) and signed bigint fields",
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
) -> Result<QueryParameters, ConnectorError> {
    let fetch_rows = max_rows.checked_add(1).ok_or_else(|| {
        configuration_error(
            "DBX-RS-MS-CFG-0014",
            "collection max_rows is outside the SQL Server hard limit",
        )
    })?;
    let fetch_rows = i32::try_from(fetch_rows).map_err(|_| {
        configuration_error(
            "DBX-RS-MS-CFG-0014",
            "collection max_rows is outside the SQL Server hard limit",
        )
    })?;
    let (timestamp, id) = bound.map_or(Ok((None, None)), |bound| {
        cursor_timestamp_parameter(bound.value.timestamp_epoch_micros)
            .map(|timestamp| (Some(timestamp), Some(bound.value.id)))
    })?;
    Ok(QueryParameters {
        timestamp,
        id,
        fetch_rows,
    })
}

fn cursor_timestamp_parameter(epoch_micros: i64) -> Result<NaiveDateTime, ConnectorError> {
    let timestamp = DateTime::<Utc>::from_timestamp_micros(epoch_micros).ok_or_else(|| {
        configuration_error(
            "DBX-RS-MS-CFG-0057",
            "SQL Server cursor timestamp is outside the supported range",
        )
    })?;
    if !(1..=9999).contains(&timestamp.year()) {
        return Err(configuration_error(
            "DBX-RS-MS-CFG-0057",
            "SQL Server cursor timestamp is outside the supported range",
        ));
    }
    Ok(timestamp.naive_utc())
}

fn projected_cursor(
    row: &Row,
    projection: CursorProjection,
) -> Result<TimestampIdCursor, ConnectorError> {
    let timestamp = required_value::<NaiveDateTime>(row, projection.timestamp_index)?;
    let id = required_value::<i64>(row, projection.id_index)?;
    let timestamp = exact_timestamp_micros(timestamp)?;
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
            "DBX-RS-MS-CONVERT-0036",
            "SQL Server cursor output is not strictly increasing",
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
            "DBX-RS-MS-CFG-0028",
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
            "DBX-RS-MS-LIMIT-0021",
            ErrorClass::Query,
            "SQL Server typed query exceeded the total IPC byte limit",
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
                "DBX-RS-MS-OUTPUT-0020",
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
    cursor_spec: Option<&TimestampIdCursorSpec>,
) -> Result<(QuerySchema, SchemaRef, Vec<ColumnPlan>), ConnectorError> {
    if columns.is_empty() {
        return Err(conversion_error(
            "DBX-RS-MS-SCHEMA-0003",
            "SQL Server query returned no columns",
        ));
    }
    if columns.len() > MAX_QUERY_COLUMNS {
        return Err(conversion_error(
            "DBX-RS-MS-SCHEMA-0008",
            "SQL Server query returned too many columns",
        ));
    }
    let mut names = BTreeSet::new();
    let mut plans = Vec::with_capacity(columns.len());
    for column in columns {
        let name = column.name.as_str();
        if name.is_empty()
            || name.len() > MAX_FIELD_NAME_BYTES
            || name.encode_utf16().count() > 128
            || name.chars().any(char::is_control)
            || !names.insert(name.to_owned())
        {
            return Err(conversion_error(
                "DBX-RS-MS-SCHEMA-0002",
                "SQL Server query returned invalid or duplicate column names",
            ));
        }
        let cursor_timestamp = cursor_spec.is_some_and(|spec| spec.timestamp_field == name);
        plans.push(plan_column(column, cursor_timestamp)?);
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
fn plan_column(column: &Column, cursor_timestamp: bool) -> Result<ColumnPlan, ConnectorError> {
    let name = column.name.as_str();
    let direct = direct_projection(name);
    let (field_type, arrow_type, value_type, source_type, projection) =
        match column.type_name.as_str() {
            "Bit" | "BitN" => (
                FieldType::Boolean,
                DataType::Boolean,
                ValueType::Boolean,
                "BIT".into(),
                direct,
            ),
            "Int1" => (
                FieldType::Int16,
                DataType::Int16,
                ValueType::Int16,
                "TINYINT".into(),
                direct,
            ),
            "Int2" => (
                FieldType::Int16,
                DataType::Int16,
                ValueType::Int16,
                "SMALLINT".into(),
                direct,
            ),
            "Int4" => (
                FieldType::Int32,
                DataType::Int32,
                ValueType::Int32,
                "INT".into(),
                direct,
            ),
            "Int8" => (
                FieldType::Int64,
                DataType::Int64,
                ValueType::Int64,
                "BIGINT".into(),
                direct,
            ),
            "IntN" => integer_n_plan(column, direct)?,
            "Float4" => (
                FieldType::Float32,
                DataType::Float32,
                ValueType::Float32,
                "REAL".into(),
                direct,
            ),
            "Float8" => (
                FieldType::Float64,
                DataType::Float64,
                ValueType::Float64,
                "FLOAT(53)".into(),
                direct,
            ),
            "FloatN" => float_n_plan(column, direct)?,
            "Decimal" | "DecimalN" | "Numeric" | "NumericN" => {
                let (precision, scale) = decimal_shape(column)?;
                (
                    FieldType::Decimal128 { precision, scale },
                    DataType::Decimal128(precision, scale),
                    ValueType::Decimal128 { precision, scale },
                    format!("DECIMAL({precision},{scale})"),
                    decimal_projection(name),
                )
            }
            "Money" => money_plan(name, 19, "MONEY"),
            "Money4" => money_plan(name, 10, "SMALLMONEY"),
            "MoneyN" => match column.max_length {
                Some(4) => money_plan(name, 10, "SMALLMONEY"),
                Some(8) => money_plan(name, 19, "MONEY"),
                _ => return Err(unsupported_type_error()),
            },
            "Guid" => (
                FieldType::Uuid,
                DataType::Utf8,
                ValueType::Uuid,
                "UNIQUEIDENTIFIER".into(),
                direct,
            ),
            "Date" => (
                FieldType::Date32,
                DataType::Date32,
                ValueType::Date32,
                "DATE".into(),
                direct,
            ),
            "Time" => {
                let scale = temporal_scale(column, "TIME")?;
                (
                    FieldType::Time64Microsecond,
                    DataType::Time64(TimeUnit::Microsecond),
                    ValueType::Time64Microsecond,
                    format!("TIME({scale})"),
                    direct,
                )
            }
            "DateTime2" => {
                let scale = temporal_scale(column, "DATETIME2")?;
                if cursor_timestamp {
                    (
                        FieldType::TimestampMicrosecondUtc,
                        DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                        ValueType::TimestampMicrosecondUtc,
                        format!("DATETIME2({scale}) UTC-CURSOR"),
                        direct,
                    )
                } else {
                    (
                        FieldType::TimestampMicrosecond,
                        DataType::Timestamp(TimeUnit::Microsecond, None),
                        ValueType::TimestampMicrosecond,
                        format!("DATETIME2({scale})"),
                        direct,
                    )
                }
            }
            "DateTimeOffset" => {
                let scale = column.scale.ok_or_else(temporal_declaration_error)?;
                if scale > 7 {
                    return Err(temporal_declaration_error());
                }
                (
                    FieldType::Utf8,
                    DataType::Utf8,
                    ValueType::Utf8,
                    format!("DATETIMEOFFSET({scale})"),
                    datetimeoffset_projection(name),
                )
            }
            "DateTime" | "DateTime4" | "DateTimeN" => (
                FieldType::Utf8,
                DataType::Utf8,
                ValueType::Utf8,
                legacy_datetime_source(column)?,
                legacy_datetime_projection(name),
            ),
            "Char" | "VarChar" | "BigChar" | "BigVarChar" | "Text" | "NChar" | "NVarChar"
            | "NText" => (
                FieldType::Utf8,
                DataType::Utf8,
                ValueType::Utf8,
                text_source_type(column)?,
                text_projection(name),
            ),
            "Binary" | "VarBinary" | "BigBinary" | "BigVarBinary" | "Image" => (
                FieldType::Binary,
                DataType::Binary,
                ValueType::Binary,
                binary_source_type(column),
                binary_projection(name),
            ),
            "Xml" => (
                FieldType::Utf8,
                DataType::Utf8,
                ValueType::Utf8,
                "XML".into(),
                text_projection(name),
            ),
            _ => return Err(unsupported_type_error()),
        };
    Ok(ColumnPlan {
        field: FieldDescriptor {
            name: name.into(),
            field_type,
            nullable: column.nullable,
            source_type,
        },
        arrow_type,
        value_type,
        projection,
    })
}

type PlanTuple = (FieldType, DataType, ValueType, String, String);

fn integer_n_plan(column: &Column, projection: String) -> Result<PlanTuple, ConnectorError> {
    match column.max_length {
        Some(1) => Ok((
            FieldType::Int16,
            DataType::Int16,
            ValueType::Int16,
            "TINYINT".into(),
            projection,
        )),
        Some(2) => Ok((
            FieldType::Int16,
            DataType::Int16,
            ValueType::Int16,
            "SMALLINT".into(),
            projection,
        )),
        Some(4) => Ok((
            FieldType::Int32,
            DataType::Int32,
            ValueType::Int32,
            "INT".into(),
            projection,
        )),
        Some(8) => Ok((
            FieldType::Int64,
            DataType::Int64,
            ValueType::Int64,
            "BIGINT".into(),
            projection,
        )),
        _ => Err(unsupported_type_error()),
    }
}

fn float_n_plan(column: &Column, projection: String) -> Result<PlanTuple, ConnectorError> {
    match column.max_length {
        Some(4) => Ok((
            FieldType::Float32,
            DataType::Float32,
            ValueType::Float32,
            "REAL".into(),
            projection,
        )),
        Some(8) => Ok((
            FieldType::Float64,
            DataType::Float64,
            ValueType::Float64,
            "FLOAT(53)".into(),
            projection,
        )),
        _ => Err(unsupported_type_error()),
    }
}

fn money_plan(name: &str, precision: u8, source_type: &str) -> PlanTuple {
    (
        FieldType::Decimal128 {
            precision,
            scale: 4,
        },
        DataType::Decimal128(precision, 4),
        ValueType::Decimal128 {
            precision,
            scale: 4,
        },
        source_type.into(),
        money_projection(name),
    )
}

fn decimal_shape(column: &Column) -> Result<(u8, i8), ConnectorError> {
    let precision = column.precision.ok_or_else(decimal_declaration_error)?;
    let scale = column.scale.ok_or_else(decimal_declaration_error)?;
    if precision == 0 || precision > 38 || scale > precision {
        return Err(decimal_declaration_error());
    }
    let scale = i8::try_from(scale).map_err(|_| decimal_declaration_error())?;
    Ok((precision, scale))
}

fn temporal_scale(column: &Column, _source: &str) -> Result<u8, ConnectorError> {
    let scale = column.scale.ok_or_else(temporal_declaration_error)?;
    if scale > 6 {
        return Err(temporal_declaration_error());
    }
    Ok(scale)
}

fn legacy_datetime_source(column: &Column) -> Result<String, ConnectorError> {
    match column.type_name.as_str() {
        "DateTime" => Ok("DATETIME".into()),
        "DateTime4" => Ok("SMALLDATETIME".into()),
        "DateTimeN" => match column.max_length {
            Some(4) => Ok("SMALLDATETIME".into()),
            Some(8) => Ok("DATETIME".into()),
            _ => Err(unsupported_type_error()),
        },
        _ => Err(unsupported_type_error()),
    }
}

fn text_source_type(column: &Column) -> Result<String, ConnectorError> {
    let base = match column.type_name.as_str() {
        "Char" | "BigChar" => "CHAR",
        "VarChar" | "BigVarChar" => "VARCHAR",
        "NChar" => "NCHAR",
        "NVarChar" => "NVARCHAR",
        "Text" => "TEXT",
        "NText" => "NTEXT",
        _ => return Err(unsupported_type_error()),
    };
    let mut source = if matches!(base, "TEXT" | "NTEXT") {
        base.to_owned()
    } else {
        let length = column.max_length.ok_or_else(unsupported_type_error)?;
        let length = if length == u32::from(u16::MAX) {
            "MAX".into()
        } else if matches!(base, "NCHAR" | "NVARCHAR") {
            if !length.is_multiple_of(2) {
                return Err(unsupported_type_error());
            }
            (length / 2).to_string()
        } else {
            length.to_string()
        };
        format!("{base}({length})")
    };
    if let Some(collation) = column.collation {
        let _ = write!(
            source,
            " COLLATION({},{})",
            collation.lcid, collation.sort_id
        );
    }
    Ok(source)
}

fn binary_source_type(column: &Column) -> String {
    let base = match column.type_name.as_str() {
        "VarBinary" | "BigVarBinary" => "VARBINARY",
        "Image" => return "IMAGE".into(),
        _ => "BINARY",
    };
    column.max_length.map_or_else(
        || base.into(),
        |length| {
            if length == u32::from(u16::MAX) {
                format!("{base}(MAX)")
            } else {
                format!("{base}({length})")
            }
        },
    )
}

fn qualified_column(name: &str) -> String {
    format!("[dbx_rs_row].{}", quote_identifier(name))
}

fn direct_projection(name: &str) -> String {
    format!("{} AS {}", qualified_column(name), quote_identifier(name))
}

fn decimal_projection(name: &str) -> String {
    format!(
        "CONVERT(nvarchar(50), {}) AS {}",
        qualified_column(name),
        quote_identifier(name)
    )
}

fn money_projection(name: &str) -> String {
    format!(
        "CONVERT(nvarchar(50), {}, 2) AS {}",
        qualified_column(name),
        quote_identifier(name)
    )
}

fn legacy_datetime_projection(name: &str) -> String {
    format!(
        "CONVERT(nvarchar(23), {}, 121) AS {}",
        qualified_column(name),
        quote_identifier(name)
    )
}

fn datetimeoffset_projection(name: &str) -> String {
    format!(
        "CONVERT(nvarchar(40), {}, 127) AS {}",
        qualified_column(name),
        quote_identifier(name)
    )
}

fn text_projection(name: &str) -> String {
    let column = qualified_column(name);
    let converted = format!("CONVERT(nvarchar(max), {column})");
    format!(
        "CASE WHEN {column} IS NULL OR DATALENGTH({converted}) <= {MAX_VALUE_BYTES} THEN {converted} ELSE CONVERT(nvarchar(max), CONVERT(int, CONCAT(N'dbx_rs_value_', DATALENGTH({converted})))) END AS {}",
        quote_identifier(name)
    )
}

fn binary_projection(name: &str) -> String {
    let column = qualified_column(name);
    format!(
        "CASE WHEN {column} IS NULL OR DATALENGTH({column}) <= {MAX_VALUE_BYTES} THEN CONVERT(varbinary(max), {column}) ELSE CONVERT(varbinary(max), CONVERT(int, CONCAT(N'dbx_rs_value_', DATALENGTH({column})))) END AS {}",
        quote_identifier(name)
    )
}

fn decimal_declaration_error() -> ConnectorError {
    conversion_error(
        "DBX-RS-MS-CONVERT-0034",
        "SQL Server decimal declaration is outside Decimal128 precision and scale limits",
    )
}

fn temporal_declaration_error() -> ConnectorError {
    conversion_error(
        "DBX-RS-MS-CONVERT-0035",
        "SQL Server temporal declaration exceeds exact microsecond precision",
    )
}

fn temporal_metadata_error() -> ConnectorError {
    protocol_error(
        "DBX-RS-MS-PROTOCOL-0024",
        "SQL Server temporal metadata was incomplete or inconsistent",
    )
}

fn unsupported_type_error() -> ConnectorError {
    conversion_error(
        "DBX-RS-MS-CONVERT-0020",
        "SQL Server query output contains an unsupported type",
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
            "DBX-RS-MS-CONVERT-0021",
            "failed to construct SQL Server Arrow record batch",
        )
    })
}

#[allow(clippy::too_many_lines)]
fn column_array(rows: &[Row], index: usize, plan: &ColumnPlan) -> Result<ArrayRef, ConnectorError> {
    macro_rules! primitive_array {
        ($rust_type:ty, $array_type:ty) => {{
            let values = rows
                .iter()
                .map(|row| optional_value::<$rust_type>(row, index, plan))
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(<$array_type>::from(values)) as ArrayRef
        }};
    }
    let array = match plan.value_type {
        ValueType::Boolean => primitive_array!(bool, BooleanArray),
        ValueType::Int16 if plan.field.source_type == "TINYINT" => {
            let values = rows
                .iter()
                .map(|row| optional_value::<u8>(row, index, plan).map(|value| value.map(i16::from)))
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(Int16Array::from(values))
        }
        ValueType::Int16 => primitive_array!(i16, Int16Array),
        ValueType::Int32 => primitive_array!(i32, Int32Array),
        ValueType::Int64 => primitive_array!(i64, Int64Array),
        ValueType::Float32 => {
            let values = rows
                .iter()
                .map(|row| finite_value::<f32>(row, index, plan))
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(Float32Array::from(values))
        }
        ValueType::Float64 => {
            let values = rows
                .iter()
                .map(|row| finite_value::<f64>(row, index, plan))
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(Float64Array::from(values))
        }
        ValueType::Utf8 => {
            let values = rows
                .iter()
                .map(|row| bounded_string(row, index, plan))
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(StringArray::from(values))
        }
        ValueType::Binary => {
            let values = rows
                .iter()
                .map(|row| bounded_binary(row, index, plan))
                .collect::<Result<Vec<_>, _>>()?;
            let borrowed = values.iter().map(Option::as_deref).collect::<Vec<_>>();
            Arc::new(BinaryArray::from(borrowed))
        }
        ValueType::Uuid => {
            let values = rows
                .iter()
                .map(|row| {
                    optional_value::<Uuid>(row, index, plan)
                        .map(|value| value.map(|value| value.hyphenated().to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(StringArray::from(values))
        }
        ValueType::Decimal128 { precision, scale } => {
            let values = rows
                .iter()
                .map(|row| {
                    bounded_string(row, index, plan)?
                        .map(|value| parse_decimal(&value, precision, scale))
                        .transpose()
                })
                .collect::<Result<Vec<_>, _>>()?;
            let array = Decimal128Array::from(values)
                .with_precision_and_scale(precision, scale)
                .map_err(|_| {
                    conversion_error(
                        "DBX-RS-MS-CONVERT-0022",
                        "SQL Server decimal exceeds its declared precision",
                    )
                })?;
            Arc::new(array)
        }
        ValueType::Date32 => {
            let values = rows
                .iter()
                .map(|row| {
                    optional_value::<NaiveDate>(row, index, plan)
                        .map(|value| value.map(|value| value.num_days_from_ce() - 719_163))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(Date32Array::from(values))
        }
        ValueType::Time64Microsecond => {
            let values = rows
                .iter()
                .map(|row| {
                    optional_value::<NaiveTime>(row, index, plan)?
                        .map(exact_time_micros)
                        .transpose()
                })
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(Time64MicrosecondArray::from(values))
        }
        ValueType::TimestampMicrosecond => {
            let values = rows
                .iter()
                .map(|row| {
                    optional_value::<NaiveDateTime>(row, index, plan)?
                        .map(exact_timestamp_micros)
                        .transpose()
                })
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(TimestampMicrosecondArray::from(values))
        }
        ValueType::TimestampMicrosecondUtc => {
            let values = rows
                .iter()
                .map(|row| {
                    optional_value::<NaiveDateTime>(row, index, plan)?
                        .map(exact_timestamp_micros)
                        .transpose()
                })
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(TimestampMicrosecondArray::from(values).with_timezone("UTC"))
        }
    };
    Ok(array)
}

fn optional_value<T: FromSql>(
    row: &Row,
    index: usize,
    plan: &ColumnPlan,
) -> Result<Option<T>, ConnectorError> {
    if index >= row.len() {
        return Err(value_conversion_error());
    }
    if row.is_null(index) {
        if plan.field.nullable {
            return Ok(None);
        }
        return Err(conversion_error(
            "DBX-RS-MS-CONVERT-0037",
            "SQL Server row contradicted non-nullable metadata",
        ));
    }
    row.get::<T>(index)
        .map(Some)
        .map_err(|_| value_conversion_error())
}

fn required_value<T: FromSql>(row: &Row, index: usize) -> Result<T, ConnectorError> {
    if index >= row.len() || row.is_null(index) {
        return Err(conversion_error(
            "DBX-RS-MS-CONVERT-0038",
            "SQL Server cursor output contains a null or missing value",
        ));
    }
    row.get::<T>(index).map_err(|_| value_conversion_error())
}

trait Finite: Copy {
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

fn finite_value<T: FromSql + Finite>(
    row: &Row,
    index: usize,
    plan: &ColumnPlan,
) -> Result<Option<T>, ConnectorError> {
    let value = optional_value::<T>(row, index, plan)?;
    if value.is_some_and(|value| !value.is_finite()) {
        return Err(conversion_error(
            "DBX-RS-MS-CONVERT-0025",
            "non-finite SQL Server floating-point values require an explicit text cast",
        ));
    }
    Ok(value)
}

fn bounded_string(
    row: &Row,
    index: usize,
    plan: &ColumnPlan,
) -> Result<Option<String>, ConnectorError> {
    let value = optional_value::<String>(row, index, plan)?;
    if value
        .as_ref()
        .is_some_and(|value| value.len() > MAX_VALUE_BYTES)
    {
        return Err(value_size_error());
    }
    Ok(value)
}

fn bounded_binary(
    row: &Row,
    index: usize,
    plan: &ColumnPlan,
) -> Result<Option<Vec<u8>>, ConnectorError> {
    let value = optional_value::<Vec<u8>>(row, index, plan)?;
    if value
        .as_ref()
        .is_some_and(|value| value.len() > MAX_VALUE_BYTES)
    {
        return Err(value_size_error());
    }
    Ok(value)
}

fn parse_decimal(value: &str, precision: u8, scale: i8) -> Result<i128, ConnectorError> {
    let scale = usize::try_from(scale).map_err(|_| value_conversion_error())?;
    let (negative, unsigned) = value
        .strip_prefix('-')
        .map_or((false, value), |value| (true, value));
    if unsigned.is_empty() || unsigned.starts_with('+') {
        return Err(value_conversion_error());
    }
    let (integer, fractional) = if scale == 0 {
        if unsigned.contains('.') {
            return Err(value_conversion_error());
        }
        (unsigned, "")
    } else {
        let (integer, fractional) = unsigned
            .split_once('.')
            .ok_or_else(value_conversion_error)?;
        if fractional.contains('.') || fractional.len() != scale {
            return Err(value_conversion_error());
        }
        (integer, fractional)
    };
    if integer.is_empty()
        || (integer.len() > 1 && integer.starts_with('0'))
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(value_conversion_error());
    }
    let integer_digits = if integer == "0" { 0 } else { integer.len() };
    let represented_digits = if scale == 0 && integer == "0" {
        1
    } else {
        integer_digits.saturating_add(fractional.len())
    };
    if represented_digits > usize::from(precision) {
        return Err(value_conversion_error());
    }
    let mut unscaled = String::with_capacity(integer.len().saturating_add(fractional.len()));
    unscaled.push_str(integer);
    unscaled.push_str(fractional);
    let unscaled = unscaled
        .parse::<i128>()
        .map_err(|_| value_conversion_error())?;
    if negative {
        unscaled.checked_neg().ok_or_else(value_conversion_error)
    } else {
        Ok(unscaled)
    }
}

fn exact_time_micros(value: NaiveTime) -> Result<i64, ConnectorError> {
    if !value.nanosecond().is_multiple_of(1_000) {
        return Err(value_conversion_error());
    }
    Ok(i64::from(value.num_seconds_from_midnight()) * 1_000_000
        + i64::from(value.nanosecond() / 1_000))
}

fn exact_timestamp_micros(value: NaiveDateTime) -> Result<i64, ConnectorError> {
    if !value.nanosecond().is_multiple_of(1_000) {
        return Err(value_conversion_error());
    }
    Ok(value.and_utc().timestamp_micros())
}

fn value_conversion_error() -> ConnectorError {
    conversion_error(
        "DBX-RS-MS-CONVERT-0024",
        "SQL Server value could not be converted without loss",
    )
}

fn value_size_error() -> ConnectorError {
    conversion_error(
        "DBX-RS-MS-CONVERT-0026",
        "SQL Server value exceeded the connector per-value byte limit",
    )
}

fn encode_batch(batch: &RecordBatch, max_bytes: u64) -> Result<Vec<u8>, ConnectorError> {
    let max_bytes = usize::try_from(max_bytes).map_err(|_| {
        configuration_error(
            "DBX-RS-MS-CFG-0027",
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
            "DBX-RS-MS-LIMIT-0020",
            ErrorClass::Query,
            "SQL Server Arrow IPC batch exceeded its byte limit",
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

fn validate_prepare_request(request: &PrepareRequest) -> Result<(), ConnectorError> {
    if request.request_id.trim().is_empty()
        || request.request_id.len() > MssqlConnector::MAX_REQUEST_ID_BYTES
        || request.request_id.chars().any(char::is_control)
    {
        return Err(configuration_error(
            "DBX-RS-MS-CFG-0058",
            "prepare request ID is invalid or exceeds its hard limit",
        ));
    }
    if request.timeout.is_zero() {
        return Err(configuration_error(
            "DBX-RS-MS-CFG-0059",
            "prepare timeout must be greater than zero",
        ));
    }
    if request.timeout > MssqlConnector::MAX_OPERATION_TIMEOUT {
        return Err(configuration_error(
            "DBX-RS-MS-CFG-0045",
            "prepare timeout exceeds the connector hard limit",
        ));
    }
    Ok(())
}

fn validate_execute_request(request: &ExecuteRequest) -> Result<(), ConnectorError> {
    if request.request_id.trim().is_empty()
        || request.request_id.len() > MssqlConnector::MAX_REQUEST_ID_BYTES
        || request.request_id.chars().any(char::is_control)
    {
        return Err(configuration_error(
            "DBX-RS-MS-CFG-0060",
            "execute request ID is invalid or exceeds its hard limit",
        ));
    }
    if request.limits.timeout.is_zero() {
        return Err(configuration_error(
            "DBX-RS-MS-CFG-0061",
            "typed query timeout must be greater than zero",
        ));
    }
    if request.limits.timeout > MssqlConnector::MAX_OPERATION_TIMEOUT {
        return Err(configuration_error(
            "DBX-RS-MS-CFG-0045",
            "typed query timeout exceeds the connector hard limit",
        ));
    }
    if request.limits.max_batch_rows == 0 {
        return Err(configuration_error(
            "DBX-RS-MS-CFG-0024",
            "typed query batch row limit must be greater than zero",
        ));
    }
    if request.limits.max_batch_bytes == 0 {
        return Err(configuration_error(
            "DBX-RS-MS-CFG-0025",
            "typed query batch byte limit must be greater than zero",
        ));
    }
    if request.limits.max_total_ipc_bytes == 0 {
        return Err(configuration_error(
            "DBX-RS-MS-CFG-0026",
            "typed query total IPC byte limit must be greater than zero",
        ));
    }
    if request.limits.max_batch_rows > MAX_TYPED_BATCH_ROWS {
        return Err(configuration_error(
            "DBX-RS-MS-CFG-0062",
            "typed query batch row limit exceeds the connector hard limit",
        ));
    }
    if request.limits.max_batch_bytes > MAX_TYPED_BATCH_IPC_BYTES {
        return Err(configuration_error(
            "DBX-RS-MS-CFG-0063",
            "typed query batch IPC byte limit exceeds the connector hard limit",
        ));
    }
    if request.limits.max_total_ipc_bytes > MAX_TYPED_TOTAL_IPC_BYTES {
        return Err(configuration_error(
            "DBX-RS-MS-CFG-0042",
            "typed query total IPC byte limit exceeds the connector hard limit",
        ));
    }
    if request.limits.max_batch_bytes > request.limits.max_total_ipc_bytes {
        return Err(configuration_error(
            "DBX-RS-MS-CFG-0043",
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

fn protocol_error(code: &'static str, message: &'static str) -> ConnectorError {
    ConnectorError::new(code, ErrorClass::Protocol, message, false, false)
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
    use mssql_client::SqlValue;

    use super::*;

    fn column(type_name: &str, name: &str) -> Column {
        Column::new(name, 0, type_name)
    }

    fn execute_request() -> ExecuteRequest {
        ExecuteRequest {
            request_id: "request-1".into(),
            connection: ConnectionConfig {
                connector_id: MssqlConnector::CONNECTOR_ID.into(),
                host: "localhost".into(),
                port: 1433,
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
    fn integer_metadata_uses_exact_signed_widths() {
        let tiny = plan_column(&column("Int1", "tiny"), false).expect("tinyint should map");
        let bigint = plan_column(&column("IntN", "big").with_max_length(8), false)
            .expect("nullable bigint should map");

        assert_eq!(tiny.field.field_type, FieldType::Int16);
        assert_eq!(bigint.field.field_type, FieldType::Int64);
        assert_eq!(bigint.field.source_type, "BIGINT");
    }

    #[test]
    fn decimal_metadata_and_canonical_values_preserve_scale() {
        let decimal = column("DecimalN", "amount").with_precision_scale(38, 6);
        let plan = plan_column(&decimal, false).expect("decimal should map");
        let money = plan_column(&column("Money", "money"), false).expect("money should map");

        assert_eq!(
            plan.field.field_type,
            FieldType::Decimal128 {
                precision: 38,
                scale: 6
            }
        );
        assert_eq!(
            parse_decimal("-12345678901234567890123456789012.345678", 38, 6),
            Ok(-12_345_678_901_234_567_890_123_456_789_012_345_678)
        );
        assert_eq!(parse_decimal("0.12", 2, 2), Ok(12));
        assert!(parse_decimal("1.2", 10, 2).is_err());
        assert!(parse_decimal("00.12", 10, 2).is_err());
        assert!(money.projection.contains(", 2)"));
    }

    #[test]
    fn datetime2_is_naive_unless_selected_as_the_utc_cursor() {
        let datetime = column("DateTime2", "updated_at").with_precision_scale(27, 6);
        let batch = plan_column(&datetime, false).expect("batch datetime2 should map");
        let cursor = plan_column(&datetime, true).expect("cursor datetime2 should map");

        assert_eq!(batch.field.field_type, FieldType::TimestampMicrosecond);
        assert_eq!(cursor.field.field_type, FieldType::TimestampMicrosecondUtc);
        assert!(cursor.field.source_type.contains("UTC-CURSOR"));
    }

    #[test]
    fn described_temporal_scale_is_merged_by_exact_ordinal_and_name() {
        let mut columns = [
            column("DateTime2", "updated_at"),
            column("Int8", "event_id"),
        ];
        let described = [
            DescribedColumn {
                ordinal: 1,
                name: "updated_at".into(),
                scale: Some(6),
            },
            DescribedColumn {
                ordinal: 2,
                name: "event_id".into(),
                scale: None,
            },
        ];

        merge_temporal_metadata(&mut columns, &described).expect("metadata should reconcile");
        assert_eq!(columns[0].scale, Some(6));
        assert_eq!(columns[1].scale, None);

        let mismatched = [DescribedColumn {
            ordinal: 1,
            name: "wrong".into(),
            scale: Some(6),
        }];
        let error = merge_temporal_metadata(&mut columns[..1], &mismatched)
            .expect_err("name mismatch must fail closed");
        assert_eq!(error.code(), "DBX-RS-MS-PROTOCOL-0024");
    }

    #[test]
    fn scale_seven_temporal_values_fail_closed() {
        for type_name in ["Time", "DateTime2"] {
            let column = column(type_name, "too_precise").with_precision_scale(27, 7);
            let error = plan_column(&column, false).expect_err("scale seven must fail");

            assert_eq!(error.code(), "DBX-RS-MS-CONVERT-0035");
        }
    }

    #[test]
    fn text_and_binary_projection_enforce_server_side_guards() {
        let text = plan_column(
            &column("NVarChar", "message").with_max_length(u32::from(u16::MAX)),
            false,
        )
        .expect("nvarchar max should map");
        let binary = plan_column(
            &column("BigVarBinary", "payload").with_max_length(u32::from(u16::MAX)),
            false,
        )
        .expect("varbinary max should map");

        assert!(text.projection.contains("DATALENGTH"));
        assert!(text.projection.contains(&MAX_VALUE_BYTES.to_string()));
        assert!(binary.projection.contains("DATALENGTH"));
    }

    #[test]
    fn unsupported_variant_and_udt_fail_closed() {
        for type_name in ["Variant", "Udt", "Null"] {
            assert!(plan_column(&column(type_name, "unsupported"), false).is_err());
        }
    }

    #[test]
    fn result_schema_is_bounded_and_duplicate_free() {
        let columns = (0..=MAX_QUERY_COLUMNS)
            .map(|index| column("Int4", &format!("column_{index}")))
            .collect::<Vec<_>>();
        assert_eq!(
            plan_columns(&columns, None)
                .expect_err("oversized schema must fail")
                .code(),
            "DBX-RS-MS-SCHEMA-0008"
        );

        let duplicate = [column("Int4", "same"), column("Int4", "same")];
        assert_eq!(
            plan_columns(&duplicate, None)
                .expect_err("duplicate names must fail")
                .code(),
            "DBX-RS-MS-SCHEMA-0002"
        );
    }

    #[test]
    fn cursor_schema_requires_datetime2_and_bigint() {
        let spec = TimestampIdCursorSpec {
            timestamp_field: "updated_at".into(),
            id_field: "id".into(),
            overlap: Duration::ZERO,
            null_policy: CursorNullPolicy::Reject,
        };
        let columns = [
            column("DateTime2", "updated_at").with_precision_scale(27, 6),
            column("Int8", "id"),
        ];
        let (schema, _, _) = plan_columns(&columns, Some(&spec)).expect("cursor schema should map");

        assert!(validate_cursor_schema(&schema, &spec).is_ok());
    }

    #[test]
    fn query_parameters_use_n_plus_one_and_exact_datetime2() {
        let parameters = query_parameters(
            Some(TimestampIdCursorBound {
                value: TimestampIdCursor::new(1, -7),
                inclusive: false,
            }),
            10,
        )
        .expect("cursor parameters should convert");

        assert_eq!(
            parameters
                .timestamp
                .map(|value| value.and_utc().timestamp_micros()),
            Some(1)
        );
        assert_eq!(parameters.id, Some(-7));
        assert_eq!(parameters.fetch_rows, 11);
    }

    #[test]
    fn row_conversion_rejects_nonfinite_values_and_oversized_text() {
        let float_plan = plan_column(&column("Float8", "value"), false).expect("float should map");
        let float_row = Row::from_values(
            vec![column("Float8", "value")],
            vec![SqlValue::Double(f64::INFINITY)],
        );
        assert!(finite_value::<f64>(&float_row, 0, &float_plan).is_err());

        let text_plan = plan_column(
            &column("NVarChar", "value").with_max_length(u32::from(u16::MAX)),
            false,
        )
        .expect("text should map");
        let text_row = Row::from_values(
            vec![column("NVarChar", "value")],
            vec![SqlValue::String("x".repeat(MAX_VALUE_BYTES + 1))],
        );
        assert!(bounded_string(&text_row, 0, &text_plan).is_err());
    }

    #[test]
    fn execute_limits_apply_connector_hard_caps() {
        let mut request = execute_request();
        request.limits.max_batch_rows += 1;
        assert_eq!(
            validate_execute_request(&request)
                .expect_err("row cap should fail")
                .code(),
            "DBX-RS-MS-CFG-0062"
        );

        let mut request = execute_request();
        request.limits.max_batch_bytes += 1;
        assert_eq!(
            validate_execute_request(&request)
                .expect_err("byte cap should fail")
                .code(),
            "DBX-RS-MS-CFG-0063"
        );
    }

    #[test]
    fn bounded_writer_never_grows_past_limit() {
        let mut writer = BoundedWriter::new(3);
        writer.write_all(b"abc").expect("write within limit");
        assert!(writer.write_all(b"d").is_err());
        assert_eq!(writer.into_inner(), b"abc");
    }
}
