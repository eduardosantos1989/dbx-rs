[<input_name>]
disabled = <boolean>
* Disables this database input when true.

connector = postgres
* Native connector identifier. PostgreSQL is currently implemented.

interval_secs = <positive integer>
* Delay from one completed collection to the next run.
* A stanza never overlaps with its own previous run.

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
* PostgreSQL certificate files must resolve below the app's certs/psql directory.

query_file = <absolute path>
* UTF-8 SELECT or WITH query file. SQL is not written to operational logs.
* PostgreSQL query files must resolve below the app's queries/psql directory.

query = <SQL text>
* Inline SELECT or WITH query for short definitions.
* Configure exactly one of query_file or query. SQL is not written to operational logs.

connect_timeout_secs = <positive integer>
probe_timeout_secs = <positive integer>
query_timeout_secs = <positive integer>
* Valid range: 1 through 86400 seconds.

max_rows = <positive integer>
* Hard maximum: 100000 rows per run.

max_bytes = <positive integer>
* Hard maximum: 1073741824 unencoded row bytes per run.

index = <label>
sourcetype = <label>
source = <label>
* Optional HEC metadata. Omitted values inherit the generic HEC defaults.
