# TA-dbx-rs

This Splunk app runs `dbx-rs-daemon` as one continuously supervised scripted input. Splunk starts
the process directly with `interval = 0`; the daemon holds an installation lock and exits when the
captured splunkd PID and process-start identity changes. Splunk then owns restart behavior. Database
workers can run concurrently across input stanzas, but each stanza is non-overlapping and total
worker concurrency is capped at available CPU parallelism.

## Configuration

`default/dbxrs_generic.conf` contains paths, operational log rotation, daemon scheduling limits,
and HEC transport settings. Put overrides in `local/dbxrs_generic.conf`.

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
and identity live under `$SPLUNK_HOME/var/lib/splunk/dbx-rs`. A future durable delivery spool must
also live under Splunk's `var` tree when implemented. Generated path settings are rejected unless
they resolve under `$SPLUNK_HOME/var`. The daemon does not generate files under `local/` except the
managed HEC `inputs.conf` that Splunk itself requires in the configuration layer.

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

Daemon, config-reload, connector, and HEC-delivery operations append one NDJSON object per lifecycle
event to `$SPLUNK_HOME/var/log/splunk/dbx-trace.log`. The `dbx_rs:trace:json` sourcetype sends these
events to `_internal` and uses numeric `timestamp_epoch` as event time.

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

HEC is the default daemon output. Batches are bounded, retried three times with short backoff, and
can wait for indexer acknowledgment. Database rows are streamed through a bounded channel, so slow
HEC applies backpressure instead of allowing unbounded memory growth.

The durable disk spool and database checkpoints are not implemented yet. A failure after an earlier
batch was accepted can replay those rows on the next query, and a changing source query can still
have gaps without a cursor protocol. Do not treat this slice as production end-to-end at-least-once
collection until spool and checkpoint state machines are added.

## Query-path upgrade and rollback

Before upgrading an existing input, move its PostgreSQL query file from `local/` to `queries/psql/`
and its database CA bundle from `local/` to `certs/psql/`, preserving ownership and permissions, then
update both paths in `local/dbxrs_inputs.conf`. To roll back to a binary that permits the older
layout, move the files back and restore the prior paths. A configuration that uses inline `query`
must first be converted to a query file because older binaries do not recognize that setting.
