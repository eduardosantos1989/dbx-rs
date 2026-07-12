# TA-dbx-rs

This Splunk app runs `dbx-rs-daemon` as one continuously supervised scripted input. Splunk starts
the process directly with `interval = 0`; the daemon holds an installation lock and exits when the
captured splunkd PID and process-start identity changes. Splunk then owns restart behavior. Database
workers can run concurrently across input stanzas, but each stanza is non-overlapping and total
worker concurrency is capped at available CPU parallelism.

## Configuration

`default/dbxrs_generic.conf` contains paths, operational log rotation, daemon scheduling limits,
encrypted spool quotas, and HEC transport settings. Put overrides in `local/dbxrs_generic.conf`.

`default/dbxrs_inputs.conf` is intentionally empty. Put database stanzas in
`local/dbxrs_inputs.conf`; see `README/dbxrs_inputs.conf.example` and the `.conf.spec` files. A
stanza references a credential by `local:<name>`. Plaintext password, secret, token, and connection
string settings are rejected.

Put PostgreSQL query files in `queries/psql/` and PostgreSQL CA bundles in `certs/psql/`. Input
stanzas may instead use `query = ...` for short inline SQL, but `query` and `query_file` are mutually
exclusive. The daemon reads these assets but does not create or rewrite them. Installation-specific
query and certificate files are ignored by the public source tree and must be supplied by an
approved package, deployment server, deployer, or future UI workflow.

Validate the effective layered configuration without starting the daemon:

```bash
$SPLUNK_HOME/etc/apps/TA-dbx-rs/bin/dbx-rs config validate
```

Validate one named input and its existing query, TLS, and protected credential assets without
opening a database connection:

```bash
$SPLUNK_HOME/etc/apps/TA-dbx-rs/bin/dbx-rs input validate example_postgres
```

Probe the configured database endpoint through the same connector and TLS path used by collection:

```bash
$SPLUNK_HOME/etc/apps/TA-dbx-rs/bin/dbx-rs input probe example_postgres
```

Run a bounded read-only query test from standard input, keeping SQL out of process arguments and
shell history:

```bash
printf '%s\n' 'SELECT current_database() AS database_name' | \
  $SPLUNK_HOME/etc/apps/TA-dbx-rs/bin/dbx-rs \
  query test example_postgres --query-stdin --max-rows 1
```

An approved file already deployed under the connector asset directory is also accepted:

```bash
$SPLUNK_HOME/etc/apps/TA-dbx-rs/bin/dbx-rs \
  query test example_postgres \
  --query-file "$SPLUNK_HOME/etc/apps/TA-dbx-rs/queries/psql/health.sql"
```

Control-operation responses are compact JSON. An invalid named input returns its validation report
and exit status 1; operation failures are JSON on standard error. Query tests accept one
`SELECT`/`WITH` statement, execute inside a read-only transaction, and are capped at 100 rows,
1,000,000 bytes, and 30 seconds. The named input's configured limits can lower those caps, and CLI
limit options can lower them further but cannot raise them. Result rows are emitted only in the
explicit command response; SQL and row payloads are not written to operational telemetry.
The 30-second query-test deadline covers validation, asset/credential loading, connection setup,
execution, and response conversion. Connection probes have a separate 30-second end-to-end cap.

Store a credential without placing it in process arguments, environment variables, or config:

```bash
printf '%s' 'database-password' | \
  $SPLUNK_HOME/etc/apps/TA-dbx-rs/bin/dbx-rs-daemon secret set example_postgres --stdin
```

The command generates a 256-bit installation key on first use and writes authenticated encrypted
secret files with owner-only permissions under `$SPLUNK_HOME/var/lib/splunk/dbx-rs/credentials`.
The key is generated locally and is not embedded in the binary. Back up the master key and
encrypted secret directory together; losing the key makes the secrets unrecoverable.

Transient daemon files live under `$SPLUNK_HOME/var/run/splunk/dbx-rs`; persistent generated state
and identity live under `$SPLUNK_HOME/var/lib/splunk/dbx-rs`. The encrypted spool, its separate
installation key, and checkpoint repository also live below that persistent Splunk `var` tree.
Generated path settings are rejected unless they resolve under `$SPLUNK_HOME/var`. The daemon does
not generate files under `local/` except the managed HEC `inputs.conf` that Splunk itself requires
in the configuration layer. Back up the spool key together with retained spool files; losing that
key makes those segments intentionally unreadable.

## HEC bootstrap

With `manage_input = true`, bootstrap generates one stable UUID token, a private local CA, and a
localhost server certificate. It reconciles only `[http]` and the configured `[http://name]` stanza
in `local/inputs.conf`; unrelated stanzas remain present. Splunk requires that managed configuration
file in the app configuration tree. The token and certificate material instead remain under
`$SPLUNK_HOME/var/lib/splunk/dbx-rs/hec` and must never be published.

Database trust certificates under `certs/` are deployable input assets and are separate from this
generated HEC server identity.

Run bootstrap after installing the app and before the first Splunk restart:

```bash
$SPLUNK_HOME/etc/apps/TA-dbx-rs/bin/dbx-rs-daemon bootstrap
```

If `splunk_restart_required=true`, restart Splunk so its HEC listener loads the generated certificate
and token. Subsequent daemon starts reuse the same identity and reconciliation is idempotent. Set
`manage_input = false` only when an operator provisions matching token and CA files externally.

## Operational telemetry

Daemon, config-reload, connector, HEC-delivery, and administrative control operations append one
NDJSON object per lifecycle event to `$SPLUNK_HOME/var/log/splunk/dbx-trace.log`. The
`dbx_rs:trace:json` sourcetype sends these events to `_internal` and uses numeric `timestamp_epoch`
as event time.

Schema version 2 includes status, request ID, component, connector, operation, safe input-stanza
name, TLS mode, duration, configured limits, row and byte counters, throughput, publish state, and
stable failure classifications. It contains no fields for SQL, credentials, tokens, bound values,
row payloads, hostnames, database names, usernames, or file paths.

Every active or rotated trace file has a hard 10,000,000-byte maximum. Two backups are retained by
default, so the three trace data files use at most 30,000,000 bytes in total. A larger configured size
is rejected. Cross-process writes and rotation use a small separate lock file, and complete records
are synced.

Schema version 2 adds the optional `input` field. Roll back ingestion by restoring the prior props
and monitor stanzas, then restarting Splunk. Roll back emission by deploying the previous binary;
the trace has no checkpoint or data-delivery role.

## Delivery boundary

HEC is the default daemon output. Before a query starts, the daemon reserves one complete segment
against per-input and global quotas. Final HEC envelopes stream into independently authenticated
encrypted frames. The footer and file are synchronized before the segment is atomically renamed
from `.open` to `.ready`; only then can delivery begin. Connector failure aborts the unsealed file.
Quota exhaustion stops new queries and never deletes ready data.

Each delivery cycle submits a bounded HEC request once and leaves the exact segment ready on any
failure. Startup authenticates and replays ready segments before scheduling more database work.
With indexer acknowledgment enabled, a segment becomes delivered only after all requests are
acknowledged. Without it, HTTP acceptance is the configured weaker boundary. A crash or lost
response after Splunk accepted data but before the local lifecycle rename can replay the same event,
so this is durable at-least-once delivery rather than universal exactly-once delivery. Every frozen
HEC envelope carries a stable `dbxrs_event_id` field derived from opaque input, batch, and row
identities so downstream searches can identify replay duplicates without changing the database row.

The connector and native adapter implement a typed timestamp-plus-ID cursor and return an
uncommitted checkpoint candidate plus a distinct scan-resume cursor for bounded overlap pages. The
versioned checkpoint repository can persist delivery-gated cursor and scan state with atomic
revision fencing and explicit backup restore, but scheduled rising inputs do not use it yet. The
current scheduler remains batch-only; no persistent database cursor advances. Do not configure a
batch query that depends on rising semantics until that final coordinator integration is released.

The spool and checkpoint formats are persistent. To roll back, stop the daemon and preserve the
complete spool root, spool key, and `state_dir`. A binary that does not understand format v1 must
not touch those files. Restore a format-v1-capable binary with the matching state and key, then
validate both inventories before collection resumes; deleting retained data is not a rollback
procedure. Upgrade preflight also validates that each input's row and byte limits fit one complete
configured spool segment; lower those limits or raise the bounded segment limit before restarting.

## Query-path upgrade and rollback

Before upgrading an existing input, move its PostgreSQL query file from `local/` to `queries/psql/`
and its database CA bundle from `local/` to `certs/psql/`, preserving ownership and permissions, then
update both paths in `local/dbxrs_inputs.conf`. To roll back to a binary that permits the older
layout, move the files back and restore the prior paths. A configuration that uses inline `query`
must first be converted to a query file because older binaries do not recognize that setting.
