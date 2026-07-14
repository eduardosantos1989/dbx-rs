use dbx_rs_connector_sdk::{ConnectorError, ErrorClass};

use super::OracleConnector;

pub(super) struct NormalizedQuery {
    pub sql: String,
}

pub(super) fn normalize_query(
    query: &str,
    max_rows: u64,
) -> Result<NormalizedQuery, ConnectorError> {
    if !(1..=OracleConnector::MAX_COLLECTION_ROWS).contains(&max_rows) {
        return Err(configuration_error(
            "DBX-RS-ORA-CFG-0014",
            "Oracle max_rows is outside the connector hard limit",
        ));
    }

    if query.len() > OracleConnector::MAX_QUERY_BYTES {
        return Err(configuration_error(
            "DBX-RS-ORA-CFG-0042",
            "Oracle query exceeds the connector hard limit",
        ));
    }

    let query = query.trim();
    if query.is_empty() || query.contains('\0') {
        return Err(configuration_error(
            "DBX-RS-ORA-CFG-0015",
            "Oracle query must be non-empty text",
        ));
    }

    let scan = scan_executable_text(query)?;
    if scan.has_bind {
        return Err(configuration_error(
            "DBX-RS-ORA-CFG-0018",
            "Oracle collection queries cannot contain bind parameters",
        ));
    }
    let base = match scan.semicolon {
        None => query,
        Some(position) if query[position + 1..].trim().is_empty() => query[..position].trim_end(),
        Some(_) => {
            return Err(configuration_error(
                "DBX-RS-ORA-CFG-0016",
                "Oracle collection query must contain one statement",
            ));
        }
    };
    if base.is_empty() {
        return Err(configuration_error(
            "DBX-RS-ORA-CFG-0016",
            "Oracle collection query must contain one statement",
        ));
    }

    let keyword = first_keyword(base).ok_or_else(|| {
        configuration_error(
            "DBX-RS-ORA-CFG-0017",
            "Oracle collection query must start with SELECT or WITH",
        )
    })?;
    if !keyword.eq_ignore_ascii_case("select") && !keyword.eq_ignore_ascii_case("with") {
        return Err(configuration_error(
            "DBX-RS-ORA-CFG-0017",
            "Oracle collection query must start with SELECT or WITH",
        ));
    }

    let fetch_rows = max_rows.checked_add(1).ok_or_else(|| {
        configuration_error(
            "DBX-RS-ORA-CFG-0014",
            "Oracle max_rows is outside the connector hard limit",
        )
    })?;
    Ok(NormalizedQuery {
        sql: format!("SELECT * FROM ({base}) dbx_rs_row FETCH FIRST {fetch_rows} ROWS ONLY"),
    })
}

struct QueryScan {
    semicolon: Option<usize>,
    has_bind: bool,
}

fn scan_executable_text(query: &str) -> Result<QueryScan, ConnectorError> {
    let bytes = query.as_bytes();
    let mut position = 0;
    let mut semicolon = None;
    let mut has_bind = false;

    while position < bytes.len() {
        match bytes[position] {
            b'\'' => {
                position = skip_doubled_quote(bytes, position, b'\'').ok_or_else(syntax_error)?;
            }
            b'"' => {
                position = skip_doubled_quote(bytes, position, b'"').ok_or_else(syntax_error)?;
            }
            b'q' | b'Q' if bytes.get(position + 1) == Some(&b'\'') => {
                position = skip_q_quote(bytes, position).ok_or_else(syntax_error)?;
            }
            b'-' if bytes.get(position + 1) == Some(&b'-') => {
                position = skip_line_comment(bytes, position + 2);
            }
            b'/' if bytes.get(position + 1) == Some(&b'*') => {
                position = skip_block_comment(bytes, position + 2).ok_or_else(syntax_error)?;
            }
            b';' => {
                if semicolon.replace(position).is_some() {
                    return Err(configuration_error(
                        "DBX-RS-ORA-CFG-0016",
                        "Oracle collection query must contain one statement",
                    ));
                }
                position += 1;
            }
            b':' => {
                has_bind = true;
                position += 1;
            }
            _ => position += 1,
        }
    }

    Ok(QueryScan {
        semicolon,
        has_bind,
    })
}

fn first_keyword(query: &str) -> Option<&str> {
    let bytes = query.as_bytes();
    let mut position = 0;
    loop {
        while bytes.get(position).is_some_and(u8::is_ascii_whitespace) {
            position += 1;
        }
        if bytes.get(position..position + 2) == Some(b"--") {
            position = skip_line_comment(bytes, position + 2);
            continue;
        }
        if bytes.get(position..position + 2) == Some(b"/*") {
            position = skip_block_comment(bytes, position + 2)?;
            continue;
        }
        break;
    }

    let start = position;
    while bytes.get(position).is_some_and(u8::is_ascii_alphabetic) {
        position += 1;
    }
    (position > start).then(|| &query[start..position])
}

fn skip_doubled_quote(bytes: &[u8], start: usize, quote: u8) -> Option<usize> {
    let mut position = start + 1;
    while position < bytes.len() {
        if bytes[position] == quote {
            if bytes.get(position + 1) == Some(&quote) {
                position += 2;
            } else {
                return Some(position + 1);
            }
        } else {
            position += 1;
        }
    }
    None
}

fn skip_q_quote(bytes: &[u8], start: usize) -> Option<usize> {
    let delimiter = *bytes.get(start + 2)?;
    let closing = match delimiter {
        b'[' => b']',
        b'{' => b'}',
        b'(' => b')',
        b'<' => b'>',
        other => other,
    };
    let mut position = start + 3;
    while position + 1 < bytes.len() {
        if bytes[position] == closing && bytes[position + 1] == b'\'' {
            return Some(position + 2);
        }
        position += 1;
    }
    None
}

fn skip_line_comment(bytes: &[u8], mut position: usize) -> usize {
    while position < bytes.len() && !matches!(bytes[position], b'\n' | b'\r') {
        position += 1;
    }
    position
}

fn skip_block_comment(bytes: &[u8], mut position: usize) -> Option<usize> {
    let mut depth = 1_u32;
    while position + 1 < bytes.len() {
        match (bytes[position], bytes[position + 1]) {
            (b'/', b'*') => {
                depth = depth.checked_add(1)?;
                position += 2;
            }
            (b'*', b'/') => {
                depth -= 1;
                position += 2;
                if depth == 0 {
                    return Some(position);
                }
            }
            _ => position += 1,
        }
    }
    None
}

fn syntax_error() -> ConnectorError {
    configuration_error(
        "DBX-RS-ORA-CFG-0019",
        "Oracle query contains unterminated quoted text or a comment",
    )
}

fn configuration_error(code: &'static str, message: &'static str) -> ConnectorError {
    ConnectorError::new(code, ErrorClass::Configuration, message, false, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_query_with_a_hard_truncation_probe() {
        let query = normalize_query(" SELECT 1 AS value FROM DUAL; ", 25).unwrap();
        assert_eq!(
            query.sql,
            "SELECT * FROM (SELECT 1 AS value FROM DUAL) dbx_rs_row FETCH FIRST 26 ROWS ONLY"
        );
    }

    #[test]
    fn rejects_multiple_statements_and_bind_parameters() {
        assert_eq!(
            normalize_query("SELECT 1 FROM DUAL; DELETE FROM audit", 1)
                .err()
                .expect("multiple statements must fail")
                .code(),
            "DBX-RS-ORA-CFG-0016"
        );
        assert_eq!(
            normalize_query("SELECT :password FROM DUAL", 1)
                .err()
                .expect("bind parameters must fail")
                .code(),
            "DBX-RS-ORA-CFG-0018"
        );
    }

    #[test]
    fn ignores_delimiters_inside_oracle_quoted_text_and_comments() {
        let query = normalize_query(
            "/* SELECT :ignored */ SELECT q'[semi; :bind]' AS value FROM DUAL -- ; :ignored",
            1,
        )
        .unwrap();
        assert!(query.sql.contains("q'[semi; :bind]'"));
    }

    #[test]
    fn rejects_unterminated_non_executable_text() {
        assert_eq!(
            normalize_query("SELECT 'secret FROM DUAL", 1)
                .err()
                .expect("unterminated quoted text must fail")
                .code(),
            "DBX-RS-ORA-CFG-0019"
        );
    }
}
