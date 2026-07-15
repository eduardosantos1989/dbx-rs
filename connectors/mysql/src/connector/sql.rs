use dbx_rs_connector_sdk::{
    ConnectorError, ErrorClass, TimestampIdCursorBound, TimestampIdCursorRequest,
};

use super::MySqlFamilyConnector;

const REJECTED_TOKENS: &[&str] = &[
    "alter",
    "analyze",
    "call",
    "create",
    "delete",
    "do",
    "drop",
    "dumpfile",
    "execute",
    "get_lock",
    "grant",
    "handler",
    "insert",
    "into",
    "load",
    "load_file",
    "lock",
    "next",
    "nextval",
    "outfile",
    "procedure",
    "release_lock",
    "release_all_locks",
    "rename",
    "replace",
    "reset",
    "revoke",
    "set",
    "setval",
    "share",
    "spider_bg_direct_sql",
    "spider_copy_tables",
    "spider_direct_sql",
    "sys_eval",
    "sys_exec",
    "truncate",
    "unlock",
    "update",
];

pub(super) struct NormalizedQuery {
    pub base: String,
    pub sql: String,
    pub cursor_bound: Option<TimestampIdCursorBound>,
}

pub(super) fn normalize_query(
    query: &str,
    max_rows: u64,
    cursor: Option<&TimestampIdCursorRequest>,
) -> Result<NormalizedQuery, ConnectorError> {
    let base = normalize_read_query(query, max_rows)?;
    let tokens = scan_sql(&base)?;
    reject_unsafe_tokens(&base, &tokens)?;
    let Some(cursor) = cursor else {
        return Ok(NormalizedQuery {
            sql: format!("SELECT * FROM ({base}) AS dbx_rs_row LIMIT ?"),
            base,
            cursor_bound: None,
        });
    };

    if tokens
        .iter()
        .any(|token| token.eq_ignore_ascii_case("limit") || token.eq_ignore_ascii_case("offset"))
    {
        return Err(configuration_error(
            "DBX-RS-MY-CFG-0050",
            "MySQL-family cursor base query must not contain LIMIT or OFFSET",
        ));
    }

    let cursor_bound = cursor.effective_bound().map_err(|_| {
        configuration_error(
            "DBX-RS-MY-CFG-0046",
            "MySQL-family cursor specification or bound is invalid",
        )
    })?;
    if !valid_cursor_field(&cursor.spec.timestamp_field)
        || !valid_cursor_field(&cursor.spec.id_field)
    {
        return Err(configuration_error(
            "DBX-RS-MY-CFG-0046",
            "MySQL-family cursor specification or bound is invalid",
        ));
    }

    let timestamp_field = quote_identifier(&cursor.spec.timestamp_field);
    let id_field = quote_identifier(&cursor.spec.id_field);
    let predicate = cursor_bound.map_or_else(String::new, |bound| {
        let operator = if bound.inclusive { ">=" } else { ">" };
        format!(
            " WHERE (dbx_rs_row.{timestamp_field} IS NULL OR dbx_rs_row.{id_field} IS NULL OR (dbx_rs_row.{timestamp_field}, dbx_rs_row.{id_field}) {operator} (?, ?))"
        )
    });
    let sql = format!(
        "SELECT * FROM ({base}) AS dbx_rs_row{predicate} ORDER BY (dbx_rs_row.{timestamp_field} IS NOT NULL) ASC, dbx_rs_row.{timestamp_field} ASC, (dbx_rs_row.{id_field} IS NOT NULL) ASC, dbx_rs_row.{id_field} ASC LIMIT ?"
    );

    Ok(NormalizedQuery {
        base,
        sql,
        cursor_bound,
    })
}

fn normalize_read_query(query: &str, max_rows: u64) -> Result<String, ConnectorError> {
    if !(1..=MySqlFamilyConnector::MAX_COLLECTION_ROWS).contains(&max_rows) {
        return Err(configuration_error(
            "DBX-RS-MY-CFG-0014",
            "collection max_rows is outside the MySQL-family hard limit",
        ));
    }
    if query.len() > MySqlFamilyConnector::MAX_QUERY_BYTES {
        return Err(configuration_error(
            "DBX-RS-MY-CFG-0041",
            "MySQL-family query exceeds the connector hard limit",
        ));
    }

    let query = query.trim();
    if query.is_empty() || query.contains('\0') {
        return Err(configuration_error(
            "DBX-RS-MY-CFG-0015",
            "collection query must be non-empty text",
        ));
    }
    let query = query.strip_suffix(';').map_or(query, str::trim_end);
    if query.is_empty() {
        return Err(configuration_error(
            "DBX-RS-MY-CFG-0016",
            "collection query must contain one statement",
        ));
    }
    Ok(query.to_owned())
}

fn reject_unsafe_tokens(query: &str, tokens: &[String]) -> Result<(), ConnectorError> {
    let Some(first) = tokens.first() else {
        return Err(configuration_error(
            "DBX-RS-MY-CFG-0017",
            "collection query must start with SELECT or WITH",
        ));
    };
    if !first.eq_ignore_ascii_case("select") && !first.eq_ignore_ascii_case("with") {
        return Err(configuration_error(
            "DBX-RS-MY-CFG-0017",
            "collection query must start with SELECT or WITH",
        ));
    }

    if tokens.iter().any(|token| {
        REJECTED_TOKENS
            .iter()
            .any(|word| token.eq_ignore_ascii_case(word))
    }) || query.as_bytes().windows(2).any(|window| window == b":=")
    {
        return Err(configuration_error(
            "DBX-RS-MY-CFG-0018",
            "collection query contains a write, lock, assignment, or external-output form",
        ));
    }
    Ok(())
}

fn scan_sql(query: &str) -> Result<Vec<String>, ConnectorError> {
    let bytes = query.as_bytes();
    let mut position = 0_usize;
    let mut tokens = Vec::new();
    while position < bytes.len() {
        match bytes[position] {
            b'\'' | b'"' | b'`' => {
                position = skip_quoted(bytes, position, bytes[position])?;
            }
            b'#' => position = skip_line_comment(bytes, position + 1),
            b'-' if bytes.get(position + 1) == Some(&b'-')
                && bytes.get(position + 2).is_none_or(u8::is_ascii_whitespace) =>
            {
                position = skip_line_comment(bytes, position + 2);
            }
            b'/' if bytes.get(position + 1) == Some(&b'*') => {
                if matches!(bytes.get(position + 2), Some(b'!' | b'+')) {
                    return Err(configuration_error(
                        "DBX-RS-MY-CFG-0019",
                        "executable MySQL-family comments are unsupported",
                    ));
                }
                position = skip_block_comment(bytes, position + 2)?;
            }
            b';' => {
                return Err(configuration_error(
                    "DBX-RS-MY-CFG-0016",
                    "collection query must contain one statement",
                ));
            }
            b'?' => {
                return Err(configuration_error(
                    "DBX-RS-MY-CFG-0048",
                    "MySQL-family base queries cannot contain parameters",
                ));
            }
            byte if is_identifier_start(byte) => {
                let start = position;
                position += 1;
                while position < bytes.len() && is_identifier_continue(bytes[position]) {
                    position += 1;
                }
                let token = std::str::from_utf8(&bytes[start..position]).map_err(|_| {
                    configuration_error(
                        "DBX-RS-MY-CFG-0020",
                        "MySQL-family query contains malformed identifier text",
                    )
                })?;
                tokens.push(token.to_owned());
            }
            _ => position += 1,
        }
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
        "DBX-RS-MY-CFG-0021",
        "MySQL-family query contains an unterminated quoted value",
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
    while position + 1 < bytes.len() {
        if bytes[position] == b'*' && bytes[position + 1] == b'/' {
            return Ok(position + 2);
        }
        position += 1;
    }
    Err(configuration_error(
        "DBX-RS-MY-CFG-0022",
        "MySQL-family query contains an unterminated comment",
    ))
}

const fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

const fn is_identifier_continue(byte: u8) -> bool {
    is_identifier_start(byte) || byte.is_ascii_digit() || byte == b'$'
}

fn quote_identifier(identifier: &str) -> String {
    let mut quoted = String::with_capacity(identifier.len().saturating_add(2));
    quoted.push('`');
    for character in identifier.chars() {
        if character == '`' {
            quoted.push('`');
        }
        quoted.push(character);
    }
    quoted.push('`');
    quoted
}

fn valid_cursor_field(field: &str) -> bool {
    field.len() <= MySqlFamilyConnector::MAX_CURSOR_FIELD_BYTES
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
                timestamp_field: "updated`at".into(),
                id_field: "id".into(),
                overlap: Duration::ZERO,
                null_policy: CursorNullPolicy::Reject,
            },
            committed: Some(TimestampIdCursor::new(1_000_000, 7)),
            resume_after: None,
        }
    }

    #[test]
    fn batch_query_is_wrapped_with_a_bound_parameter() {
        let normalized = normalize_query(" SELECT value FROM sample; ", 10, None)
            .expect("read query should normalize");

        assert_eq!(normalized.base, "SELECT value FROM sample");
        assert_eq!(
            normalized.sql,
            "SELECT * FROM (SELECT value FROM sample) AS dbx_rs_row LIMIT ?"
        );
    }

    #[test]
    fn shipped_mysql_and_mariadb_queries_pass_offline_validation() {
        for query in [
            include_str!("../../../../packaging/splunk/TA-dbx-rs/queries/mysql/example.sql"),
            include_str!("../../../../packaging/splunk/TA-dbx-rs/queries/mariadb/example.sql"),
        ] {
            normalize_query(query, 10, None).expect("shipped query example must remain valid");
        }
    }

    #[test]
    fn cursor_query_quotes_fields_and_uses_native_parameters() {
        let normalized = normalize_query("SELECT * FROM sample", 10, Some(&cursor()))
            .expect("cursor query should normalize");

        assert!(normalized.sql.contains("dbx_rs_row.`updated``at`"));
        assert!(normalized.sql.contains(") > (?, ?)"));
        assert!(normalized.sql.ends_with("LIMIT ?"));
        assert!(normalized.cursor_bound.is_some());
    }

    #[test]
    fn lexical_literals_and_comments_do_not_trigger_write_rejection() {
        for query in [
            "SELECT 'update; ?' AS value",
            "SELECT \"into\" AS value",
            "SELECT `set` FROM sample",
            "SELECT 1 /* update; ? */",
            "SELECT 1 # delete; ?\n",
            "SELECT 1 -- insert; ?\n",
        ] {
            normalize_query(query, 10, None).expect("quoted or commented text should be ignored");
        }
    }

    #[test]
    fn unsafe_and_ambiguous_query_forms_fail_closed() {
        let rejected = [
            "UPDATE sample SET value = 1",
            "WITH cte AS (SELECT 1) DELETE FROM sample",
            "SELECT 1; SELECT 2",
            "SELECT ?",
            "SELECT 1 INTO OUTFILE '/tmp/x'",
            "SELECT LOAD_FILE('/etc/passwd')",
            "SELECT @x := 1",
            "SELECT GET_LOCK('x', 1)",
            "SELECT RELEASE_ALL_LOCKS()",
            "SELECT NEXT VALUE FOR event_sequence",
            "SELECT event_sequence.NEXTVAL",
            "SELECT SETVAL(event_sequence, 42)",
            "SELECT SPIDER_DIRECT_SQL('UPDATE remote_table SET value = 1')",
            "SELECT sys_exec('touch /tmp/dbx-rs')",
            "SELECT * FROM sample FOR SHARE",
            "SELECT 1 FOR UPDATE",
            "SELECT 1 /*! SQL_NO_CACHE */",
            "SELECT 1 /*+ MAX_EXECUTION_TIME(1) */",
            "SELECT 'masked\\'; UPDATE sample SET value = 1",
            "SELECT 'unterminated",
            "SELECT 1 /* unterminated",
        ];

        for query in rejected {
            assert!(
                normalize_query(query, 10, None).is_err(),
                "query should fail: {query}"
            );
        }
    }

    #[test]
    fn cursor_queries_reject_user_pagination_only_when_executable() {
        for query in [
            "SELECT * FROM sample LIMIT 1",
            "SELECT * FROM sample OFFSET 1",
        ] {
            let error = normalize_query(query, 10, Some(&cursor()))
                .err()
                .expect("cursor pagination should fail");
            assert_eq!(error.code(), "DBX-RS-MY-CFG-0050");
        }

        normalize_query("SELECT 'limit offset' AS value", 10, Some(&cursor()))
            .expect("literal pagination words should be ignored");
    }

    #[test]
    fn cursor_fields_are_bounded_before_sql_construction() {
        for timestamp_field in [
            "x".repeat(MySqlFamilyConnector::MAX_CURSOR_FIELD_BYTES + 1),
            "updated\nat".into(),
        ] {
            let mut request = cursor();
            request.spec.timestamp_field = timestamp_field;

            let error = normalize_query("SELECT * FROM sample", 10, Some(&request))
                .err()
                .expect("invalid cursor fields must fail before query construction");

            assert_eq!(error.code(), "DBX-RS-MY-CFG-0046");
        }
    }
}
