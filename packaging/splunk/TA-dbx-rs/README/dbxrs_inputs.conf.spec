[<input_name>]
disabled = <boolean>
* Disables this database input when true.

mode = batch | rising
* Optional collection mode. Omitted mode defaults to batch for existing stanzas.
* Rising mode is supported by PostgreSQL, MySQL, and MariaDB. Oracle is batch-only. Batch stanzas
  must not configure any rising-only settings below.
* A rising scan collects, seals, reconciles, and delivers one bounded page at a time. Every
  non-empty page is an authenticated durable spool segment before HEC delivery can begin. Startup
  reconciles sealed-page recovery metadata before replay or another page is collected.
* A rising checkpoint advances only after every page in the scan crosses the configured HEC
  delivery boundary. Delivery is at-least-once, so an uncertain HEC response or acknowledgment can
  replay an envelope that Splunk already accepted.

input_id = <canonical lowercase UUID>
* Required only for rising mode. This immutable, non-nil 16-byte identity owns durable cursor state.
* Generate a unique UUID for each rising stanza. UUIDs must be unique across enabled and disabled
  stanzas. Renaming a stanza does not replace this identity.
* Never change or reuse an input_id for a different logical source. Administrative identity
  migration and checkpoint reset are not implemented in this release.
* Changing the source connection, base query, cursor output aliases, or versioned cursor contract is
  also an identity change and fails closed. Keep those fields unchanged until a reviewed
  administrative migration workflow is available.

cursor_timestamp_field = <query output field>
cursor_id_field = <query output field>
* Required only for rising mode. The configured query must expose these distinct exact output
  aliases once. PostgreSQL requires non-NULL TIMESTAMPTZ and BIGINT; MySQL and MariaDB require
  non-NULL TIMESTAMP and signed BIGINT. Names are limited to 63 UTF-8 bytes and cannot contain
  control characters.
* The timestamp-plus-ID tuple must uniquely identify each source row. NULL cursor values, duplicate
  tuples, and ordering regressions fail the page without advancing the checkpoint.
* The configured query is a parameter-free SELECT or WITH base query. dbx-rs owns the outer cursor
  predicate, native parameter binding, lexicographic timestamp-then-ID ordering, and page limit.
* A rising base query must not contain its own LIMIT, OFFSET, or FETCH clause. Connector preparation
  rejects these clauses because they could hide rows from the outer cursor scan. No alternate
  ordering or null policy is currently configurable.

cursor_overlap_secs = <non-negative integer>
* Optional only for rising mode. Defaults to 0. Valid range: 0 through 31536000 seconds.
* Nonzero overlap deliberately rereads the configured committed time window. The same source
  lineage and cursor tuple retains the same stable dbxrs_event_id across overlap rereads, page
  boundaries, retries, and restarts; overlap does not invent a distinct event identity.
* Changing only the overlap preserves source-lineage and cursor identity but creates a new
  operational revision. That revision activates only while the input has no active attempt and no
  retained spool data; otherwise configuration activation fails closed.
* Splunk can still receive the same identity more than once under at-least-once delivery when a HEC
  acceptance or acknowledgment outcome is uncertain. Use dbxrs_event_id for downstream dedupe.

connector = postgres | oracle | mysql | mariadb
* Native connector identifier. PostgreSQL is Native Certified. Oracle, MySQL, and MariaDB are
  Experimental Native. Oracle supports batch mode only; MySQL and MariaDB have offline-tested batch
  and rising implementations but still require separate live product certification.

interval_secs = <positive integer>
* Delay from one completed collection to the next run.
* A stanza never overlaps with its own previous run.
* Valid range: 1 through 31536000 seconds.

host = <hostname or address>
port = <positive integer>
database = <database name>
username = <database user>
* Database connection identity. These values are not written to operational logs.

secret_ref = local:<name>
* Reference created with: dbx-rs-daemon secret set <name> --stdin
* Plaintext password, secret, token, and connection_string settings are rejected.

tls_mode = verify-full | disable
* verify-full is the secure default. disable must be explicit for isolated labs.

tls_server_name = <DNS name>
* Optional verified server name for TLS.

tls_ca_file = <absolute path>
* Optional PEM CA bundle. Supports an initial $SPLUNK_HOME/ path component.
* Certificate files must resolve below the selected product root: certs/psql, certs/oracle,
  certs/mysql, or certs/mariadb.

query_file = <absolute path>
* UTF-8 SELECT or WITH query file. SQL is not written to operational logs.
* Query files must resolve below the selected product root: queries/psql, queries/oracle,
  queries/mysql, or queries/mariadb.

query = <SQL text>
* Inline SELECT or WITH query for short definitions.
* Configure exactly one of query_file or query. SQL is not written to operational logs.

connect_timeout_secs = <positive integer>
probe_timeout_secs = <positive integer>
query_timeout_secs = <positive integer>
* Valid range: 1 through 86400 seconds.

max_rows = <positive integer>
* Hard maximum: 100000 rows per batch run or rising query page.

max_bytes = <positive integer>
* Together with max_rows, must fit the configured atomic spool segment including bounded envelope
  and encryption overhead. Raise spool.segment_max_bytes or lower these input limits if validation
  reports input.spool_bound.
* Hard maximum: 1073741824 unencoded row bytes per batch run or rising query page.
* PostgreSQL bytea retains its existing lowercase \\x-prefixed hexadecimal JSON string. Oracle RAW
  and MySQL-family binary values are emitted losslessly as lowercase hex:-prefixed JSON strings.

index = <label>
sourcetype = <label>
source = <label>
* Optional HEC metadata. Omitted values inherit the generic HEC defaults.
* Labels are limited to 128 ASCII letters, digits, and - _ . : / + characters.
