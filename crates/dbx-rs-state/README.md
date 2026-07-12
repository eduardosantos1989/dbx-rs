# dbx-rs durable state

This crate stores delivery-gated checkpoint state beneath a caller-provided private state root. It
keeps the transition rules in `dbx-rs-checkpoint` and adds a bounded scan-resume model, a versioned
checksummed envelope, atomic replacement, one previous envelope, and compare-and-swap fencing. An
owner-only filesystem lock serializes writers opened through independent store handles.

For Splunk deployments the state root is
`$SPLUNK_HOME/var/lib/splunk/dbx-rs/state`. Per-input directories use an opaque SHA-256 key rather
than a configured name. Directories are owner-only and envelope files are mode `0600` on Unix.
The daemon, not this crate, owns the owner-only fixed
`$SPLUNK_HOME/var/lib/splunk/dbx-rs/state-root.binding` marker that binds an installation to its
exact configured state root.

At startup, the daemon uses a non-creating identity inventory to validate every persisted input
owner and rejects detached owners that are absent from the effective configuration. It then
preflights each configured identity and durable configuration revision before any HEC setup or
reconciliation side effect.

The version 1 envelope is limited to 1 MiB and currently carries durable payload format 2. The
payload contains cursor, retained sealed-segment, compacted-prefix row/sequence counters, and
monotonic delivered-prefix metadata but no SQL,
credentials, tokens, arbitrary query parameters, row payloads, or spool event data. Cursor values
are redacted from diagnostics. The checksum detects damage; it is not an authentication mechanism.
Spool event records require their own authenticated encryption format.

Every active checkpoint attempt must have a matching active scan. Ordinary compare-and-swap writes
accept only an exact checkpoint coordinator transition, append-only logical scan progress, one
standalone delivery-receipt advance of exactly one sequence number, or exact pruning of an already
receipted and spool-compacted reference prefix into cumulative sequence and row counters. These
transitions cannot be combined. Delivery confirmation requires a complete scan, a full receipt
prefix, and coordinator row counts that match retained plus compacted scan rows; commit requires the
same complete receipt before the active attempt and scan can be cleared. Prefix pruning bounds state
size without resetting the exclusive resume cursor during long scans.

Ordinary writes cannot change source-lineage or cursor identity, activate another configuration,
drop an unreceipted segment reference, alter compacted row accounting, rewind a resume cursor,
regress, skip, or overrun delivery receipts, or fabricate a committed cursor. Configuration
activation is a separate operation: it requires no active attempt, advances the durable
configuration generation, and derives a new coordinator fence from the fingerprint and generation.
Reusing an earlier fingerprint therefore cannot revive a stale attempt. Source-lineage or cursor
identity changes require an explicit administrative migration policy outside this storage API. The
daemon does not yet provide that migration or checkpoint-reset workflow, so operators must not
change an established input ID, source lineage, or cursor identity.

An unsupported envelope or payload version is never overwritten automatically. Corrupt state also
fails closed. Restoring `checkpoint.dbx.prev` is the explicit regression operation and writes a new
store revision. Before configuration activation, identity migration, backup restore, or binary
rollback, operators must stop the affected input and reconcile and preserve both its checkpoint and
spool files. Payload format 2 is not readable by binaries that only understand payload format 1.
Such a binary must not create, rewrite, compact, or delete either data set. Rollback means restoring
a format-compatible binary and the matched state, spool, and spool key backup. Draining spool data
does not downgrade a payload-format-2 checkpoint; rollback to a payload-v1-only binary requires a
matched pre-v2 backup. Deleting retained state or spool data is not rollback.
