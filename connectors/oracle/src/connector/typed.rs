use std::collections::BTreeSet;
use std::io::{self, Write};
use std::sync::Arc;

use arrow_array::{
    ArrayRef, BinaryArray, Decimal128Array, RecordBatch, StringArray, TimestampMicrosecondArray,
};
use arrow_ipc::writer::StreamWriter;
use arrow_schema::{DataType, Field, Schema, SchemaRef, TimeUnit};
use chrono::NaiveDate;
use dbx_rs_connector_sdk::{
    ArrowIpcBatch, ConnectorError, ErrorClass, ExecuteRequest, ExecutionResult, FieldDescriptor,
    FieldType, PrepareRequest, QuerySchema,
};
use tokio::sync::mpsc;

use super::driver::{NativeColumn, NativeKind, NativePage, NativeRow, NativeValue, OracleSession};
use super::{OracleConnector, valid_request_id};

pub(super) const MAX_BATCH_ROWS: u32 = 256;
pub(super) const MAX_BATCH_IPC_BYTES: u64 = 1024 * 1024;
pub(super) const MAX_TOTAL_IPC_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Clone)]
struct ColumnPlan {
    field: FieldDescriptor,
    arrow_type: DataType,
    value_type: ValueType,
}

#[derive(Clone, Copy)]
enum ValueType {
    Decimal128 { precision: u8, scale: i8 },
    TimestampMicrosecond,
    Utf8,
    Binary,
}

struct PlannedSchema {
    query_schema: QuerySchema,
    arrow_schema: SchemaRef,
    columns: Vec<ColumnPlan>,
}

pub(super) fn validate_prepare_request(request: &PrepareRequest) -> Result<(), ConnectorError> {
    if !valid_request_id(&request.request_id) {
        return Err(configuration_error(
            "DBX-RS-ORA-CFG-0020",
            "Oracle prepare request ID is invalid or exceeds its hard limit",
        ));
    }
    if request.timeout.is_zero() {
        return Err(configuration_error(
            "DBX-RS-ORA-CFG-0021",
            "Oracle prepare timeout must be greater than zero",
        ));
    }
    if request.timeout > OracleConnector::MAX_OPERATION_TIMEOUT {
        return Err(configuration_error(
            "DBX-RS-ORA-CFG-0029",
            "Oracle prepare timeout exceeds the connector hard limit",
        ));
    }
    if request.cursor.is_some() {
        return Err(configuration_error(
            "DBX-RS-ORA-CFG-0030",
            "Oracle cursor collection is not enabled for the experimental connector",
        ));
    }
    Ok(())
}

pub(super) fn validate_execute_request(request: &ExecuteRequest) -> Result<(), ConnectorError> {
    if !valid_request_id(&request.request_id) {
        return Err(configuration_error(
            "DBX-RS-ORA-CFG-0022",
            "Oracle execute request ID is invalid or exceeds its hard limit",
        ));
    }
    if request.limits.timeout.is_zero() {
        return Err(configuration_error(
            "DBX-RS-ORA-CFG-0023",
            "Oracle query timeout must be greater than zero",
        ));
    }
    if request.limits.timeout > OracleConnector::MAX_OPERATION_TIMEOUT {
        return Err(configuration_error(
            "DBX-RS-ORA-CFG-0031",
            "Oracle query timeout exceeds the connector hard limit",
        ));
    }
    if request.limits.max_batch_rows == 0 {
        return Err(configuration_error(
            "DBX-RS-ORA-CFG-0024",
            "Oracle batch row limit must be greater than zero",
        ));
    }
    if request.limits.max_batch_rows > MAX_BATCH_ROWS {
        return Err(configuration_error(
            "DBX-RS-ORA-CFG-0032",
            "Oracle batch row limit exceeds the connector hard limit",
        ));
    }
    if request.limits.max_batch_bytes == 0 {
        return Err(configuration_error(
            "DBX-RS-ORA-CFG-0025",
            "Oracle batch IPC byte limit must be greater than zero",
        ));
    }
    if request.limits.max_batch_bytes > MAX_BATCH_IPC_BYTES {
        return Err(configuration_error(
            "DBX-RS-ORA-CFG-0033",
            "Oracle batch IPC byte limit exceeds the connector hard limit",
        ));
    }
    if request.limits.max_total_ipc_bytes == 0 {
        return Err(configuration_error(
            "DBX-RS-ORA-CFG-0026",
            "Oracle total IPC byte limit must be greater than zero",
        ));
    }
    if request.limits.max_total_ipc_bytes > MAX_TOTAL_IPC_BYTES {
        return Err(configuration_error(
            "DBX-RS-ORA-CFG-0034",
            "Oracle total IPC byte limit exceeds the connector hard limit",
        ));
    }
    if request.limits.max_batch_bytes > request.limits.max_total_ipc_bytes {
        return Err(configuration_error(
            "DBX-RS-ORA-CFG-0027",
            "Oracle batch IPC byte limit exceeds its total IPC byte limit",
        ));
    }
    if request.cursor.is_some() {
        return Err(configuration_error(
            "DBX-RS-ORA-CFG-0030",
            "Oracle cursor collection is not enabled for the experimental connector",
        ));
    }
    Ok(())
}

pub(super) async fn prepare_schema(
    session: &dyn OracleSession,
    sql: &str,
) -> Result<QuerySchema, ConnectorError> {
    let columns = session.describe(sql).await?;
    Ok(plan_columns(&columns)?.query_schema)
}

pub(super) async fn execute_query(
    session: &dyn OracleSession,
    request: ExecuteRequest,
    sql: String,
    batch_tx: mpsc::Sender<ArrowIpcBatch>,
) -> Result<ExecutionResult, ConnectorError> {
    session.begin_read_only().await?;
    let described_columns = session.describe(&sql).await?;
    let plan = plan_columns(&described_columns)?;
    if request
        .expected_schema
        .as_ref()
        .is_some_and(|expected| expected != &plan.query_schema)
    {
        return Err(conversion_error(
            "DBX-RS-ORA-SCHEMA-0001",
            "Oracle query schema changed before execution",
        ));
    }

    let batch_capacity = effective_batch_capacity(&request, &plan)?;
    let fetch_size = u32::try_from(batch_capacity).map_err(|_| {
        configuration_error(
            "DBX-RS-ORA-CFG-0028",
            "Oracle fetch row limit is invalid for this platform",
        )
    })?;
    let mut page = session.query(&sql, fetch_size).await?;
    let mut pending = Vec::with_capacity(batch_capacity);
    let mut rows_read = 0_u64;
    let mut batches_emitted = 0_u64;
    let mut ipc_bytes_emitted = 0_u64;
    let mut truncated = false;

    loop {
        validate_page_metadata(&page, &described_columns)?;
        if page.rows.is_empty() && page.has_more_rows {
            return Err(protocol_error(
                "DBX-RS-ORA-PROTOCOL-0010",
                "Oracle returned an empty continuation page",
            ));
        }

        for row in page.rows.drain(..) {
            if rows_read == request.limits.max_rows {
                truncated = true;
                break;
            }
            pending.push(row);
            rows_read = rows_read.saturating_add(1);
            if pending.len() == batch_capacity {
                let emitted = emit_batch(
                    &request,
                    batches_emitted,
                    &plan,
                    &pending,
                    ipc_bytes_emitted,
                    &batch_tx,
                )
                .await?;
                ipc_bytes_emitted = ipc_bytes_emitted.saturating_add(emitted);
                batches_emitted = batches_emitted.saturating_add(1);
                pending.clear();
            }
        }
        if truncated || !page.has_more_rows {
            break;
        }
        if page.cursor_id == 0 {
            return Err(protocol_error(
                "DBX-RS-ORA-PROTOCOL-0011",
                "Oracle continuation page omitted its cursor ID",
            ));
        }
        page = session.fetch_more(page.cursor_id, fetch_size).await?;
    }

    if !pending.is_empty() {
        let emitted = emit_batch(
            &request,
            batches_emitted,
            &plan,
            &pending,
            ipc_bytes_emitted,
            &batch_tx,
        )
        .await?;
        ipc_bytes_emitted = ipc_bytes_emitted.saturating_add(emitted);
        batches_emitted = batches_emitted.saturating_add(1);
    }

    Ok(ExecutionResult {
        request_id: request.request_id,
        rows_read,
        batches_emitted,
        ipc_bytes_emitted,
        truncated,
        schema: plan.query_schema,
    })
}

fn validate_page_metadata(
    page: &NativePage,
    described_columns: &[NativeColumn],
) -> Result<(), ConnectorError> {
    if page.columns != described_columns {
        return Err(conversion_error(
            "DBX-RS-ORA-SCHEMA-0002",
            "Oracle query metadata differs from its describe metadata",
        ));
    }
    Ok(())
}

fn plan_columns(columns: &[NativeColumn]) -> Result<PlannedSchema, ConnectorError> {
    if columns.is_empty() {
        return Err(conversion_error(
            "DBX-RS-ORA-SCHEMA-0003",
            "Oracle query returned no columns",
        ));
    }
    let mut names = BTreeSet::new();
    let mut plans = Vec::with_capacity(columns.len());
    for column in columns {
        if !names.insert(column.name.to_ascii_uppercase()) {
            return Err(conversion_error(
                "DBX-RS-ORA-SCHEMA-0004",
                "Oracle query returned duplicate column names",
            ));
        }
        plans.push(plan_column(column)?);
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
    Ok(PlannedSchema {
        query_schema,
        arrow_schema: Arc::new(Schema::new(fields)),
        columns: plans,
    })
}

fn plan_column(column: &NativeColumn) -> Result<ColumnPlan, ConnectorError> {
    let (field_type, arrow_type, value_type) = match column.kind {
        NativeKind::Number { precision, scale }
            if (1..=38).contains(&precision) && (0..=precision).contains(&scale) =>
        {
            let precision = u8::try_from(precision).map_err(|_| invalid_number_schema())?;
            let scale = i8::try_from(scale).map_err(|_| invalid_number_schema())?;
            (
                FieldType::Decimal128 { precision, scale },
                DataType::Decimal128(precision, scale),
                ValueType::Decimal128 { precision, scale },
            )
        }
        NativeKind::Number { .. } => return Err(invalid_number_schema()),
        NativeKind::Date => (
            FieldType::TimestampMicrosecond,
            DataType::Timestamp(TimeUnit::Microsecond, None),
            ValueType::TimestampMicrosecond,
        ),
        NativeKind::Timestamp {
            fractional_precision,
        } if (0..=6).contains(&fractional_precision) => (
            FieldType::TimestampMicrosecond,
            DataType::Timestamp(TimeUnit::Microsecond, None),
            ValueType::TimestampMicrosecond,
        ),
        NativeKind::Timestamp { .. } => {
            return Err(conversion_error(
                "DBX-RS-ORA-CONVERT-0011",
                "Oracle timestamp precision exceeds microsecond fidelity",
            ));
        }
        NativeKind::Text => (FieldType::Utf8, DataType::Utf8, ValueType::Utf8),
        NativeKind::Binary => (FieldType::Binary, DataType::Binary, ValueType::Binary),
        NativeKind::TimestampWithTimeZone | NativeKind::TimestampWithLocalTimeZone => {
            return Err(conversion_error(
                "DBX-RS-ORA-CONVERT-0012",
                "Oracle zoned timestamps require an explicit lossless policy",
            ));
        }
        NativeKind::LongText | NativeKind::LongBinary | NativeKind::Lob => {
            return Err(conversion_error(
                "DBX-RS-ORA-CONVERT-0013",
                "Oracle LONG and LOB output is disabled until bounded locator reads are verified",
            ));
        }
        NativeKind::Unsupported => {
            return Err(conversion_error(
                "DBX-RS-ORA-CONVERT-0014",
                "Oracle query output contains an unsupported type",
            ));
        }
    };

    Ok(ColumnPlan {
        field: FieldDescriptor {
            name: column.name.clone(),
            field_type,
            nullable: column.nullable,
            source_type: column.source_type.clone(),
        },
        arrow_type,
        value_type,
    })
}

fn invalid_number_schema() -> ConnectorError {
    conversion_error(
        "DBX-RS-ORA-CONVERT-0010",
        "Oracle NUMBER requires declared precision 1..38 and nonnegative scale",
    )
}

fn effective_batch_capacity(
    request: &ExecuteRequest,
    plan: &PlannedSchema,
) -> Result<usize, ConnectorError> {
    let fixed_row_bytes = plan.columns.iter().try_fold(0_u64, |total, column| {
        field_width(column.value_type).map(|width| total.saturating_add(width))
    });
    let schema_cap = fixed_row_bytes.map_or(1, |row_bytes| {
        request
            .limits
            .max_batch_bytes
            .checked_div(row_bytes.max(1))
            .unwrap_or(1)
            .max(1)
    });
    let rows = u64::from(request.limits.max_batch_rows)
        .min(request.limits.max_rows)
        .min(schema_cap)
        .max(1);
    usize::try_from(rows).map_err(|_| {
        configuration_error(
            "DBX-RS-ORA-CFG-0028",
            "Oracle batch row limit is invalid for this platform",
        )
    })
}

const fn field_width(value_type: ValueType) -> Option<u64> {
    match value_type {
        ValueType::Decimal128 { .. } => Some(16),
        ValueType::TimestampMicrosecond => Some(8),
        ValueType::Utf8 | ValueType::Binary => None,
    }
}

async fn emit_batch(
    request: &ExecuteRequest,
    sequence: u64,
    plan: &PlannedSchema,
    rows: &[NativeRow],
    total_ipc_bytes: u64,
    batch_tx: &mpsc::Sender<ArrowIpcBatch>,
) -> Result<u64, ConnectorError> {
    let batch = rows_to_batch(rows, plan)?;
    let ipc_bytes = encode_batch(&batch, request.limits.max_batch_bytes)?;
    let encoded_bytes = ipc_bytes.len() as u64;
    if total_ipc_bytes.saturating_add(encoded_bytes) > request.limits.max_total_ipc_bytes {
        return Err(ConnectorError::new(
            "DBX-RS-ORA-LIMIT-0021",
            ErrorClass::Query,
            "Oracle query exceeded the total IPC byte limit",
            false,
            false,
        ));
    }
    batch_tx
        .send(ArrowIpcBatch {
            request_id: request.request_id.clone(),
            sequence,
            row_count: batch.num_rows() as u64,
            schema: plan.query_schema.clone(),
            ipc_bytes,
        })
        .await
        .map_err(|_| {
            ConnectorError::new(
                "DBX-RS-ORA-OUTPUT-0020",
                ErrorClass::Internal,
                "Arrow IPC batch receiver closed",
                false,
                false,
            )
        })?;
    Ok(encoded_bytes)
}

fn rows_to_batch(rows: &[NativeRow], plan: &PlannedSchema) -> Result<RecordBatch, ConnectorError> {
    validate_rows(rows, plan)?;
    let arrays = plan
        .columns
        .iter()
        .enumerate()
        .map(|(index, column)| column_array(rows, index, column.value_type))
        .collect::<Result<Vec<_>, _>>()?;
    RecordBatch::try_new(Arc::clone(&plan.arrow_schema), arrays).map_err(|_| {
        conversion_error(
            "DBX-RS-ORA-CONVERT-0020",
            "failed to construct Oracle Arrow record batch",
        )
    })
}

fn validate_rows(rows: &[NativeRow], plan: &PlannedSchema) -> Result<(), ConnectorError> {
    for row in rows {
        if row.len() != plan.columns.len() {
            return Err(value_mismatch());
        }
        if row
            .iter()
            .zip(&plan.columns)
            .any(|(value, column)| matches!(value, NativeValue::Null) && !column.field.nullable)
        {
            return Err(conversion_error(
                "DBX-RS-ORA-CONVERT-0025",
                "Oracle returned NULL for a non-nullable result column",
            ));
        }
    }
    Ok(())
}

fn column_array(
    rows: &[NativeRow],
    index: usize,
    value_type: ValueType,
) -> Result<ArrayRef, ConnectorError> {
    let array = match value_type {
        ValueType::Decimal128 { precision, scale } => {
            let values = rows
                .iter()
                .map(|row| match value_at(row, index)? {
                    NativeValue::Null => Ok(None),
                    NativeValue::Number(value) => {
                        decimal_to_i128(value, precision, scale).map(Some)
                    }
                    _ => Err(value_mismatch()),
                })
                .collect::<Result<Vec<_>, _>>()?;
            let decimal = Decimal128Array::from(values)
                .with_precision_and_scale(precision, scale)
                .map_err(|_| {
                    conversion_error(
                        "DBX-RS-ORA-CONVERT-0021",
                        "Oracle NUMBER exceeds its declared precision",
                    )
                })?;
            Arc::new(decimal) as ArrayRef
        }
        ValueType::TimestampMicrosecond => {
            let values = rows
                .iter()
                .map(|row| match value_at(row, index)? {
                    NativeValue::Null => Ok(None),
                    NativeValue::Date {
                        year,
                        month,
                        day,
                        hour,
                        minute,
                        second,
                    } => {
                        timestamp_micros(*year, *month, *day, *hour, *minute, *second, 0).map(Some)
                    }
                    NativeValue::Timestamp {
                        year,
                        month,
                        day,
                        hour,
                        minute,
                        second,
                        microsecond,
                    } => {
                        timestamp_micros(*year, *month, *day, *hour, *minute, *second, *microsecond)
                            .map(Some)
                    }
                    _ => Err(value_mismatch()),
                })
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(TimestampMicrosecondArray::from(values)) as ArrayRef
        }
        ValueType::Utf8 => {
            let values = rows
                .iter()
                .map(|row| match value_at(row, index)? {
                    NativeValue::Null => Ok(None),
                    NativeValue::Text(value) => Ok(Some(value.clone())),
                    _ => Err(value_mismatch()),
                })
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(StringArray::from(values)) as ArrayRef
        }
        ValueType::Binary => {
            let values = rows
                .iter()
                .map(|row| match value_at(row, index)? {
                    NativeValue::Null => Ok(None),
                    NativeValue::Binary(value) => Ok(Some(value.as_slice())),
                    _ => Err(value_mismatch()),
                })
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(BinaryArray::from(values)) as ArrayRef
        }
    };
    Ok(array)
}

fn value_at(row: &NativeRow, index: usize) -> Result<&NativeValue, ConnectorError> {
    row.get(index).ok_or_else(value_mismatch)
}

fn value_mismatch() -> ConnectorError {
    conversion_error(
        "DBX-RS-ORA-CONVERT-0022",
        "Oracle value does not match its planned Arrow type",
    )
}

fn timestamp_micros(
    year: i32,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    microsecond: u32,
) -> Result<i64, ConnectorError> {
    if year <= 0 {
        return Err(conversion_error(
            "DBX-RS-ORA-CONVERT-0023",
            "Oracle BC dates require an explicit lossless calendar policy",
        ));
    }
    let value = NaiveDate::from_ymd_opt(year, u32::from(month), u32::from(day))
        .and_then(|date| {
            date.and_hms_micro_opt(
                u32::from(hour),
                u32::from(minute),
                u32::from(second),
                microsecond,
            )
        })
        .ok_or_else(|| {
            conversion_error(
                "DBX-RS-ORA-CONVERT-0023",
                "Oracle date or timestamp is outside the supported range",
            )
        })?;
    Ok(value.and_utc().timestamp_micros())
}

fn decimal_to_i128(value: &str, precision: u8, scale: i8) -> Result<i128, ConnectorError> {
    let scale = usize::try_from(scale).map_err(|_| invalid_decimal_value())?;
    if value.is_empty() || value.trim() != value {
        return Err(invalid_decimal_value());
    }
    let (negative, unsigned) = value
        .strip_prefix('-')
        .map_or((false, value), |unsigned| (true, unsigned));
    let mut parts = unsigned.split('.');
    let integer = parts.next().unwrap_or_default();
    let fractional = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || integer.is_empty()
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
        || fractional.len() > scale
    {
        return Err(invalid_decimal_value());
    }

    let mut digits = String::with_capacity(integer.len().saturating_add(scale));
    digits.push_str(integer);
    digits.push_str(fractional);
    digits.extend(std::iter::repeat_n('0', scale - fractional.len()));
    let significant_digits = digits.trim_start_matches('0').len();
    if significant_digits > usize::from(precision) {
        return Err(conversion_error(
            "DBX-RS-ORA-CONVERT-0021",
            "Oracle NUMBER exceeds its declared precision",
        ));
    }

    let mut parsed = 0_i128;
    for digit in digits.bytes() {
        parsed = parsed
            .checked_mul(10)
            .and_then(|current| current.checked_add(i128::from(digit - b'0')))
            .ok_or_else(invalid_decimal_value)?;
    }
    if negative && parsed != 0 {
        parsed = parsed.checked_neg().ok_or_else(invalid_decimal_value)?;
    }
    Ok(parsed)
}

fn invalid_decimal_value() -> ConnectorError {
    conversion_error(
        "DBX-RS-ORA-CONVERT-0024",
        "Oracle NUMBER could not be represented exactly as Decimal128",
    )
}

fn encode_batch(batch: &RecordBatch, max_bytes: u64) -> Result<Vec<u8>, ConnectorError> {
    let max_bytes = usize::try_from(max_bytes).map_err(|_| {
        configuration_error(
            "DBX-RS-ORA-CFG-0028",
            "Oracle batch IPC byte limit is invalid for this platform",
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
            "DBX-RS-ORA-LIMIT-0020",
            ErrorClass::Query,
            "Oracle Arrow IPC batch exceeded its byte limit",
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

fn configuration_error(code: &'static str, message: &'static str) -> ConnectorError {
    ConnectorError::new(code, ErrorClass::Configuration, message, false, true)
}

fn conversion_error(code: &'static str, message: &'static str) -> ConnectorError {
    ConnectorError::new(code, ErrorClass::Conversion, message, false, false)
}

fn protocol_error(code: &'static str, message: &'static str) -> ConnectorError {
    ConnectorError::new(code, ErrorClass::Protocol, message, true, false)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use arrow_array::Array;
    use arrow_ipc::reader::StreamReader;

    use super::*;

    fn column(kind: NativeKind) -> NativeColumn {
        NativeColumn {
            name: "VALUE".into(),
            kind,
            nullable: true,
            source_type: "test".into(),
        }
    }

    #[test]
    fn number_requires_bounded_lossless_decimal_metadata() {
        let valid = plan_column(&column(NativeKind::Number {
            precision: 38,
            scale: 6,
        }))
        .unwrap();
        assert_eq!(
            valid.field.field_type,
            FieldType::Decimal128 {
                precision: 38,
                scale: 6
            }
        );

        for kind in [
            NativeKind::Number {
                precision: 0,
                scale: 0,
            },
            NativeKind::Number {
                precision: 10,
                scale: -1,
            },
            NativeKind::Number {
                precision: 39,
                scale: 0,
            },
        ] {
            assert_eq!(
                plan_column(&column(kind))
                    .err()
                    .expect("invalid NUMBER metadata must fail")
                    .code(),
                "DBX-RS-ORA-CONVERT-0010"
            );
        }
    }

    #[test]
    fn decimal_conversion_is_exact_and_precision_checked() {
        assert_eq!(decimal_to_i128("123.45", 5, 2).unwrap(), 12_345);
        assert_eq!(decimal_to_i128("-0.01", 5, 2).unwrap(), -1);
        assert_eq!(decimal_to_i128("0", 5, 2).unwrap(), 0);
        assert!(decimal_to_i128("1.234", 5, 2).is_err());
        assert!(decimal_to_i128("1000", 3, 0).is_err());
        assert!(decimal_to_i128("1e2", 3, 0).is_err());
    }

    #[test]
    fn lossy_or_unbounded_types_fail_closed() {
        assert_eq!(
            plan_column(&column(NativeKind::Timestamp {
                fractional_precision: 7,
            }))
            .err()
            .expect("sub-microsecond timestamps must fail")
            .code(),
            "DBX-RS-ORA-CONVERT-0011"
        );

        for kind in [
            NativeKind::TimestampWithTimeZone,
            NativeKind::TimestampWithLocalTimeZone,
        ] {
            assert_eq!(
                plan_column(&column(kind))
                    .err()
                    .expect("zoned timestamps must fail")
                    .code(),
                "DBX-RS-ORA-CONVERT-0012"
            );
        }
        for kind in [
            NativeKind::LongText,
            NativeKind::LongBinary,
            NativeKind::Lob,
        ] {
            assert_eq!(
                plan_column(&column(kind))
                    .err()
                    .expect("unbounded Oracle values must fail")
                    .code(),
                "DBX-RS-ORA-CONVERT-0013"
            );
        }
    }

    #[test]
    fn date_and_timestamp_conversion_reject_invalid_components() {
        assert_eq!(timestamp_micros(1970, 1, 1, 0, 0, 0, 1).unwrap(), 1);
        assert!(timestamp_micros(0, 1, 1, 0, 0, 0, 0).is_err());
        assert!(timestamp_micros(-100, 1, 1, 0, 0, 0, 0).is_err());
        assert!(timestamp_micros(2024, 2, 30, 0, 0, 0, 0).is_err());
        assert!(timestamp_micros(2024, 1, 1, 0, 0, 0, 1_000_000).is_err());
    }

    #[test]
    fn nulls_are_preserved_for_every_supported_arrow_family() {
        let columns = vec![
            column(NativeKind::Number {
                precision: 10,
                scale: 2,
            }),
            column(NativeKind::Date),
            column(NativeKind::Timestamp {
                fractional_precision: 6,
            }),
            column(NativeKind::Text),
            column(NativeKind::Binary),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, mut column)| {
            column.name = format!("VALUE_{index}");
            column
        })
        .collect::<Vec<_>>();
        let plan = plan_columns(&columns).unwrap();
        let batch = rows_to_batch(&[vec![NativeValue::Null; columns.len()]], &plan).unwrap();

        assert_eq!(batch.num_rows(), 1);
        assert!(batch.columns().iter().all(|array| array.null_count() == 1));
    }

    #[test]
    fn core_type_batch_round_trips_through_arrow_ipc_exactly() {
        let columns = vec![
            column(NativeKind::Number {
                precision: 20,
                scale: 4,
            }),
            column(NativeKind::Date),
            column(NativeKind::Timestamp {
                fractional_precision: 6,
            }),
            column(NativeKind::Text),
            column(NativeKind::Binary),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, mut column)| {
            column.name = format!("VALUE_{index}");
            column
        })
        .collect::<Vec<_>>();
        let plan = plan_columns(&columns).unwrap();
        let timestamp = timestamp_micros(2024, 2, 29, 23, 59, 58, 654_321).unwrap();
        let batch = rows_to_batch(
            &[
                vec![
                    NativeValue::Number("-1234567890123456.7890".into()),
                    NativeValue::Date {
                        year: 1970,
                        month: 1,
                        day: 1,
                        hour: 0,
                        minute: 0,
                        second: 0,
                    },
                    NativeValue::Timestamp {
                        year: 2024,
                        month: 2,
                        day: 29,
                        hour: 23,
                        minute: 59,
                        second: 58,
                        microsecond: 654_321,
                    },
                    NativeValue::Text("national-\u{20ac}".into()),
                    NativeValue::Binary(vec![0, 0xff, 7]),
                ],
                vec![NativeValue::Null; columns.len()],
            ],
            &plan,
        )
        .unwrap();
        let ipc = encode_batch(&batch, MAX_BATCH_IPC_BYTES).unwrap();
        let decoded = StreamReader::try_new(Cursor::new(ipc), None)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();

        let decimal = decoded
            .column(0)
            .as_any()
            .downcast_ref::<Decimal128Array>()
            .unwrap();
        assert_eq!(decimal.value(0), -12_345_678_901_234_567_890_i128);
        assert!(decimal.is_null(1));

        let date = decoded
            .column(1)
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(date.value(0), 0);
        assert!(date.is_null(1));

        let timestamp_array = decoded
            .column(2)
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(timestamp_array.value(0), timestamp);
        assert!(timestamp_array.is_null(1));

        let text = decoded
            .column(3)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(text.value(0), "national-\u{20ac}");
        assert!(text.is_null(1));

        let binary = decoded
            .column(4)
            .as_any()
            .downcast_ref::<BinaryArray>()
            .unwrap();
        assert_eq!(binary.value(0), [0, 0xff, 7]);
        assert!(binary.is_null(1));
    }

    #[test]
    fn null_in_non_nullable_column_fails_closed() {
        let mut number = column(NativeKind::Number {
            precision: 10,
            scale: 0,
        });
        number.nullable = false;
        let plan = plan_columns(&[number]).unwrap();

        let error = rows_to_batch(&[vec![NativeValue::Null]], &plan).unwrap_err();

        assert_eq!(error.code(), "DBX-RS-ORA-CONVERT-0025");
    }

    #[test]
    fn row_width_must_match_described_columns() {
        let plan = plan_columns(&[column(NativeKind::Text)]).unwrap();

        let error = rows_to_batch(
            &[vec![
                NativeValue::Text("first".into()),
                NativeValue::Text("extra".into()),
            ]],
            &plan,
        )
        .unwrap_err();

        assert_eq!(error.code(), "DBX-RS-ORA-CONVERT-0022");
    }
}
