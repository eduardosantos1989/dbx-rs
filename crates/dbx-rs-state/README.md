# dbx-rs durable state

This crate stores delivery-gated checkpoint state beneath a caller-provided private state root. It
keeps the transition rules in `dbx-rs-checkpoint` and adds a bounded scan-resume model, a versioned
checksummed envelope, atomic replacement, one previous envelope, and compare-and-swap fencing. An
owner-only filesystem lock serializes writers opened through independent store handles.

For Splunk deployments the state root is
`$SPLUNK_HOME/var/lib/splunk/dbx-rs/state`. Per-input directories use an opaque SHA-256 key rather
than a configured name. Directories are owner-only and envelope files are mode `0600` on Unix.

The version 1 envelope is limited to 1 MiB. It contains cursor and progress metadata but no SQL,
credentials, tokens, arbitrary query parameters, row payloads, or spool event data. Cursor values
are redacted from diagnostics. The checksum detects damage; it is not an authentication mechanism.
Spool event records require their own authenticated encryption format.

Ordinary compare-and-swap writes accept only an exact checkpoint coordinator transition or
append-only sealed scan progress. They cannot change query/cursor identity, activate another
configuration, drop sealed segment references, rewind a resume cursor, or fabricate a committed
cursor. Configuration activation is a separate operation: it requires no active attempt, advances
the durable configuration generation, and derives a new coordinator fence from the fingerprint and
generation. Reusing an earlier fingerprint therefore cannot revive a stale attempt. Query or cursor
identity changes require an explicit administrative migration policy outside this storage API.

An unsupported envelope or payload version is never overwritten automatically. Corrupt state also
fails closed. Restoring `checkpoint.dbx.prev` is the explicit regression operation and writes a new
store revision. Before configuration activation, identity migration, backup restore, or binary
rollback, operators must stop the affected input and reconcile and preserve both its checkpoint and
spool files. A binary that does not understand format version 1 must not create, rewrite, compact, or
delete either data set. Rollback means restoring a format-compatible binary and the matched state,
spool, and spool key backup; deleting retained state or spool data is not rollback.
