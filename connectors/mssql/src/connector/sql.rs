use dbx_rs_connector_sdk::{
    ConnectorError, ErrorClass, TimestampIdCursorBound, TimestampIdCursorRequest,
};

use super::MssqlConnector;

const RESERVED_CTE: &str = "dbx_rs_base";
const REJECTED_TOKENS: &[&str] = &[
    "alter",
    "backup",
    "bulk",
    "checkpoint",
    "create",
    "dbcc",
    "delete",
    "deny",
    "drop",
    "dump",
    "execute",
    "exec",
    "grant",
    "holdlock",
    "insert",
    "into",
    "kill",
    "merge",
    "next",
    "openrowset",
    "openquery",
    "opendatasource",
    "openxml",
    "reconfigure",
    "restore",
    "revert",
    "revoke",
    "set",
    "shutdown",
    "tablockx",
    "truncate",
    "update",
    "updlock",
    "use",
    "waitfor",
    "writetext",
    "xlock",
];

#[derive(Clone, Debug)]
struct Token {
    text: String,
    start: usize,
    depth: usize,
}

pub(super) struct NormalizedQuery {
    pub cursor_bound: Option<TimestampIdCursorBound>,
    cte_prefix: Option<String>,
    main_select: String,
}

impl NormalizedQuery {
    pub(super) fn metadata_sql(&self) -> String {
        self.wrap("SELECT TOP (0) * FROM [dbx_rs_base] AS [dbx_rs_row]")
    }

    pub(super) fn projected_metadata_sql(&self, projection: &str) -> String {
        self.wrap(&format!(
            "SELECT TOP (0) {projection} FROM [dbx_rs_base] AS [dbx_rs_row]"
        ))
    }

    pub(super) fn execution_sql(
        &self,
        projection: &str,
        cursor: Option<&TimestampIdCursorRequest>,
    ) -> String {
        let Some(cursor) = cursor else {
            return self.wrap(&format!(
                "SELECT TOP (@P1) {projection} FROM [dbx_rs_base] AS [dbx_rs_row]"
            ));
        };

        let timestamp = qualified_identifier(&cursor.spec.timestamp_field);
        let id = qualified_identifier(&cursor.spec.id_field);
        let (predicate, page_parameter) = self.cursor_bound.map_or_else(
            || (String::new(), "@P1"),
            |bound| {
                let id_operator = if bound.inclusive { ">=" } else { ">" };
                (
                    format!(
                        " WHERE ({timestamp} IS NULL OR {id} IS NULL OR {timestamp} > @P1 OR ({timestamp} = @P1 AND {id} {id_operator} @P2))"
                    ),
                    "@P3",
                )
            },
        );
        let order = format!(
            " ORDER BY CASE WHEN {timestamp} IS NULL THEN 0 ELSE 1 END, {timestamp}, CASE WHEN {id} IS NULL THEN 0 ELSE 1 END, {id}"
        );
        self.wrap(&format!(
            "SELECT TOP ({page_parameter}) {projection} FROM [dbx_rs_base] AS [dbx_rs_row]{predicate}{order}"
        ))
    }

    fn wrap(&self, outer: &str) -> String {
        self.cte_prefix.as_ref().map_or_else(
            || format!("WITH [dbx_rs_base] AS (\n{}\n)\n{outer}", self.main_select),
            |prefix| {
                format!(
                    "{prefix}\n, [dbx_rs_base] AS (\n{}\n)\n{outer}",
                    self.main_select
                )
            },
        )
    }

    #[cfg(test)]
    fn base(&self) -> &str {
        &self.main_select
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn normalize_query(
    query: &str,
    max_rows: u64,
    cursor: Option<&TimestampIdCursorRequest>,
) -> Result<NormalizedQuery, ConnectorError> {
    if !(1..=MssqlConnector::MAX_COLLECTION_ROWS).contains(&max_rows) {
        return Err(configuration_error(
            "DBX-RS-MS-CFG-0014",
            "collection max_rows is outside the SQL Server hard limit",
        ));
    }
    if query.len() > MssqlConnector::MAX_QUERY_BYTES {
        return Err(configuration_error(
            "DBX-RS-MS-CFG-0041",
            "SQL Server query exceeds the connector hard limit",
        ));
    }

    let query = query.trim();
    if query.is_empty() || query.contains('\0') {
        return Err(configuration_error(
            "DBX-RS-MS-CFG-0015",
            "collection query must be non-empty text",
        ));
    }
    let query = query.strip_suffix(';').map_or(query, str::trim_end);
    if query.is_empty() {
        return Err(configuration_error(
            "DBX-RS-MS-CFG-0016",
            "collection query must contain one statement",
        ));
    }

    let tokens = scan_sql(query)?;
    reject_unsafe_query(&tokens)?;
    let first = tokens.first().ok_or_else(|| {
        configuration_error(
            "DBX-RS-MS-CFG-0017",
            "collection query must start with SELECT or WITH",
        )
    })?;
    if !first.text.eq_ignore_ascii_case("select") && !first.text.eq_ignore_ascii_case("with") {
        return Err(configuration_error(
            "DBX-RS-MS-CFG-0017",
            "collection query must start with SELECT or WITH",
        ));
    }
    if tokens
        .iter()
        .any(|token| token.text.eq_ignore_ascii_case(RESERVED_CTE))
    {
        return Err(configuration_error(
            "DBX-RS-MS-CFG-0048",
            "SQL Server base query uses a connector-reserved identifier",
        ));
    }
    if tokens.iter().any(|token| {
        token.depth == 0
            && ["order", "offset", "fetch", "option", "for", "top"]
                .iter()
                .any(|word| token.text.eq_ignore_ascii_case(word))
    }) {
        return Err(configuration_error(
            "DBX-RS-MS-CFG-0050",
            "SQL Server base query cannot own outer pagination, ordering, or query options",
        ));
    }

    let (cte_prefix, main_select) = if first.text.eq_ignore_ascii_case("select") {
        (None, query.to_owned())
    } else {
        let main = tokens
            .iter()
            .skip(1)
            .find(|token| token.depth == 0 && token.text.eq_ignore_ascii_case("select"))
            .ok_or_else(|| {
                configuration_error(
                    "DBX-RS-MS-CFG-0049",
                    "SQL Server WITH query must end in one top-level SELECT",
                )
            })?;
        let prefix = query[..main.start].trim_end();
        if prefix.is_empty() {
            return Err(configuration_error(
                "DBX-RS-MS-CFG-0049",
                "SQL Server WITH query is malformed",
            ));
        }
        (Some(prefix.to_owned()), query[main.start..].to_owned())
    };

    let cursor_bound = cursor
        .map(TimestampIdCursorRequest::effective_bound)
        .transpose()
        .map_err(|_| {
            configuration_error(
                "DBX-RS-MS-CFG-0046",
                "SQL Server cursor specification or bound is invalid",
            )
        })?
        .flatten();
    if let Some(cursor) = cursor
        && (!valid_cursor_field(&cursor.spec.timestamp_field)
            || !valid_cursor_field(&cursor.spec.id_field))
    {
        return Err(configuration_error(
            "DBX-RS-MS-CFG-0046",
            "SQL Server cursor specification or bound is invalid",
        ));
    }

    Ok(NormalizedQuery {
        cursor_bound,
        cte_prefix,
        main_select,
    })
}

fn reject_unsafe_query(tokens: &[Token]) -> Result<(), ConnectorError> {
    if tokens.iter().any(|token| {
        REJECTED_TOKENS
            .iter()
            .any(|word| token.text.eq_ignore_ascii_case(word))
    }) {
        return Err(configuration_error(
            "DBX-RS-MS-CFG-0018",
            "collection query contains a write, execution, lock, or external-access form",
        ));
    }
    Ok(())
}

fn scan_sql(query: &str) -> Result<Vec<Token>, ConnectorError> {
    let bytes = query.as_bytes();
    let mut position = 0_usize;
    let mut depth = 0_usize;
    let mut tokens = Vec::new();
    while position < bytes.len() {
        match bytes[position] {
            b'\'' | b'"' => position = skip_quoted(bytes, position, bytes[position])?,
            b'[' => position = skip_bracket_identifier(bytes, position)?,
            b'-' if bytes.get(position + 1) == Some(&b'-') => {
                position = skip_line_comment(bytes, position + 2);
            }
            b'/' if bytes.get(position + 1) == Some(&b'*') => {
                position = skip_block_comment(bytes, position + 2)?;
            }
            b';' => {
                return Err(configuration_error(
                    "DBX-RS-MS-CFG-0016",
                    "collection query must contain one statement",
                ));
            }
            b'@' => {
                return Err(configuration_error(
                    "DBX-RS-MS-CFG-0047",
                    "SQL Server base queries cannot contain variables or parameters",
                ));
            }
            b'(' => {
                depth = depth.checked_add(1).ok_or_else(|| {
                    configuration_error(
                        "DBX-RS-MS-CFG-0020",
                        "SQL Server query nesting exceeds its supported envelope",
                    )
                })?;
                position += 1;
            }
            b')' => {
                depth = depth.checked_sub(1).ok_or_else(|| {
                    configuration_error(
                        "DBX-RS-MS-CFG-0020",
                        "SQL Server query contains unbalanced parentheses",
                    )
                })?;
                position += 1;
            }
            byte if is_identifier_start(byte) => {
                let start = position;
                position += 1;
                while position < bytes.len() && is_identifier_continue(bytes[position]) {
                    position += 1;
                }
                let text = std::str::from_utf8(&bytes[start..position]).map_err(|_| {
                    configuration_error(
                        "DBX-RS-MS-CFG-0020",
                        "SQL Server query contains malformed identifier text",
                    )
                })?;
                tokens.push(Token {
                    text: text.to_owned(),
                    start,
                    depth,
                });
            }
            _ => position += 1,
        }
    }
    if depth != 0 {
        return Err(configuration_error(
            "DBX-RS-MS-CFG-0020",
            "SQL Server query contains unbalanced parentheses",
        ));
    }
    Ok(tokens)
}

fn skip_quoted(bytes: &[u8], start: usize, quote: u8) -> Result<usize, ConnectorError> {
    let mut position = start + 1;
    while position < bytes.len() {
        if bytes[position] == quote {
            if bytes.get(position + 1) == Some(&quote) {
                position += 2;
            } else {
                return Ok(position + 1);
            }
        } else {
            position += 1;
        }
    }
    Err(configuration_error(
        "DBX-RS-MS-CFG-0021",
        "SQL Server query contains an unterminated quoted value",
    ))
}

fn skip_bracket_identifier(bytes: &[u8], start: usize) -> Result<usize, ConnectorError> {
    let mut position = start + 1;
    while position < bytes.len() {
        if bytes[position] == b']' {
            if bytes.get(position + 1) == Some(&b']') {
                position += 2;
            } else {
                return Ok(position + 1);
            }
        } else {
            position += 1;
        }
    }
    Err(configuration_error(
        "DBX-RS-MS-CFG-0021",
        "SQL Server query contains an unterminated bracketed identifier",
    ))
}

fn skip_line_comment(bytes: &[u8], start: usize) -> usize {
    bytes[start..]
        .iter()
        .position(|byte| matches!(byte, b'\n' | b'\r'))
        .map_or(bytes.len(), |offset| start + offset + 1)
}

fn skip_block_comment(bytes: &[u8], start: usize) -> Result<usize, ConnectorError> {
    let mut position = start;
    let mut nesting = 1_usize;
    while position + 1 < bytes.len() {
        if bytes[position] == b'/' && bytes[position + 1] == b'*' {
            nesting = nesting.checked_add(1).ok_or_else(|| {
                configuration_error(
                    "DBX-RS-MS-CFG-0022",
                    "SQL Server comment nesting exceeds its supported envelope",
                )
            })?;
            position += 2;
        } else if bytes[position] == b'*' && bytes[position + 1] == b'/' {
            nesting -= 1;
            position += 2;
            if nesting == 0 {
                return Ok(position);
            }
        } else {
            position += 1;
        }
    }
    Err(configuration_error(
        "DBX-RS-MS-CFG-0022",
        "SQL Server query contains an unterminated comment",
    ))
}

const fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'#')
}

const fn is_identifier_continue(byte: u8) -> bool {
    is_identifier_start(byte) || byte.is_ascii_digit() || matches!(byte, b'$')
}

pub(super) fn quote_identifier(identifier: &str) -> String {
    let mut quoted = String::with_capacity(identifier.len().saturating_add(2));
    quoted.push('[');
    for character in identifier.chars() {
        if character == ']' {
            quoted.push(']');
        }
        quoted.push(character);
    }
    quoted.push(']');
    quoted
}

fn qualified_identifier(identifier: &str) -> String {
    format!("[dbx_rs_row].{}", quote_identifier(identifier))
}

fn valid_cursor_field(field: &str) -> bool {
    !field.is_empty()
        && field.len() <= MssqlConnector::MAX_CURSOR_FIELD_BYTES
        && field.encode_utf16().count() <= 128
        && !field.chars().any(char::is_control)
}

fn configuration_error(code: &'static str, message: &'static str) -> ConnectorError {
    ConnectorError::new(code, ErrorClass::Configuration, message, false, true)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use dbx_rs_connector_sdk::{
        CursorNullPolicy, TimestampIdCursor, TimestampIdCursorRequest, TimestampIdCursorSpec,
    };

    use super::*;

    fn cursor() -> TimestampIdCursorRequest {
        TimestampIdCursorRequest {
            spec: TimestampIdCursorSpec {
                timestamp_field: "updated]at".into(),
                id_field: "id".into(),
                overlap: Duration::ZERO,
                null_policy: CursorNullPolicy::Reject,
            },
            committed: Some(TimestampIdCursor::new(1_000_000, 7)),
            resume_after: None,
        }
    }

    #[test]
    fn select_query_is_wrapped_with_host_top() {
        let query = normalize_query(" SELECT value FROM sample; ", 10, None)
            .expect("read query should normalize");

        assert_eq!(query.base(), "SELECT value FROM sample");
        assert!(query.metadata_sql().starts_with("WITH [dbx_rs_base]"));
        assert!(query.execution_sql("*", None).contains("TOP (@P1)"));
    }

    #[test]
    fn cte_query_appends_the_connector_cte() {
        let query = normalize_query(
            "WITH source AS (SELECT 1 AS value) SELECT value FROM source",
            10,
            None,
        )
        .expect("CTE query should normalize");
        let sql = query.execution_sql("*", None);

        assert!(sql.starts_with("WITH source AS"));
        assert!(sql.contains(", [dbx_rs_base] AS ("));
        assert!(sql.contains("SELECT value FROM source"));
    }

    #[test]
    fn cursor_query_quotes_fields_and_binds_tuple() {
        let request = cursor();
        let query = normalize_query("SELECT * FROM sample", 10, Some(&request))
            .expect("cursor query should normalize");
        let sql = query.execution_sql("*", Some(&request));

        assert!(sql.contains("[dbx_rs_row].[updated]]at]"));
        assert!(sql.contains("[dbx_rs_row].[id] > @P2"));
        assert!(sql.contains("TOP (@P3)"));
        assert!(query.cursor_bound.is_some());
    }

    #[test]
    fn overlap_cursor_uses_an_inclusive_id_boundary() {
        let mut request = cursor();
        request.spec.overlap = Duration::from_secs(1);
        let query = normalize_query("SELECT * FROM sample", 10, Some(&request))
            .expect("overlap cursor should normalize");

        assert!(
            query
                .execution_sql("*", Some(&request))
                .contains("[dbx_rs_row].[id] >= @P2")
        );
    }

    #[test]
    fn lexical_literals_identifiers_and_comments_are_masked() {
        for query in [
            "SELECT 'update; @P1' AS value",
            "SELECT [drop] FROM sample",
            "SELECT \"set\" FROM sample",
            "SELECT 1 /* outer /* delete */ still outer */",
            "SELECT 1 -- insert; @P1\n",
        ] {
            normalize_query(query, 10, None).expect("masked text should be ignored");
        }
    }

    #[test]
    fn unsafe_and_ambiguous_forms_fail_closed() {
        let rejected = [
            "UPDATE sample SET value = 1",
            "WITH source AS (SELECT 1) DELETE FROM sample",
            "SELECT 1; SELECT 2",
            "SELECT @P1",
            "SELECT 1 INTO target",
            "SELECT * FROM OPENROWSET(BULK 'x', SINGLE_BLOB) AS source",
            "SELECT NEXT VALUE FOR event_sequence",
            "SELECT * FROM sample WITH (UPDLOCK)",
            "SELECT TOP (1) * FROM sample",
            "SELECT * FROM sample ORDER BY id",
            "SELECT * FROM sample OPTION (MAXDOP 1)",
            "SELECT 'unterminated",
            "SELECT 1 /* unterminated",
            "SELECT (1",
            "SELECT 1)",
        ];

        for query in rejected {
            assert!(
                normalize_query(query, 10, None).is_err(),
                "query should fail: {query}"
            );
        }
    }

    #[test]
    fn reserved_identifier_is_rejected_only_when_executable() {
        assert!(normalize_query("SELECT * FROM dbx_rs_base", 10, None).is_err());
        normalize_query("SELECT 'dbx_rs_base' AS value", 10, None)
            .expect("literal should not collide with reserved CTE");
    }
}
