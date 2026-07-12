# dbx-rs spool

This crate owns the encrypted durable event-segment format used before Splunk delivery. It is
host-owned and connector-neutral. Event records are exact final delivery envelopes supplied by the
caller; the crate does not inspect or log their contents.

## Formats v1 and v2

Each segment contains a fixed plaintext prefix with magic, format version, key identifier, random
salt, and opaque segment identifier. HKDF-SHA256 derives a unique segment key from a separate local
spool master key. The encrypted header, every event, and the footer are independently authenticated
with ChaCha20-Poly1305 using monotonically sequenced nonces and frame metadata as additional
authenticated data.

New segments use format v2. After all event frames, v2 writes exactly one authenticated opaque
recovery-metadata frame followed by the footer. Metadata is limited to 128 bytes; `seal()` writes an
empty metadata frame, while `seal_with_recovery_metadata(...)` writes caller-supplied bytes. The
encoder reserves the maximum metadata frame and footer before accepting events, so sealing cannot
exceed the segment limit. Format-v1 segments remain readable and expose empty recovery metadata.

The footer binds the event count, plaintext byte count, and a length-delimited SHA-256 event-stream
digest. Ready and delivered handles expose a domain-separated reference digest that additionally
binds the format version, segment identifier, complete header, footer summary, event-stream digest,
and recovery metadata. A complete segment is synchronized before an atomic `.open` to `.ready`
rename, followed by parent-directory synchronization. `.ready` files are immutable. Delivery
changes only the lifecycle extension to `.delivered`; deletion requires explicit compaction.

Directories are owner-only and generated files are mode `0600` on Unix. Existing symbolic links in
the spool or key path ancestry are rejected before access. Input directories and segment names use
opaque lowercase hexadecimal identities. Startup moves incomplete `.open` files to private
quarantine. It never promotes them, deletes ready data, or infers delivery.

## Operational impact

- Segment, per-input, and global quotas are hard. A full configured segment is reserved before a
  database query can start.
- Quarantined files count toward quota until an operator follows a reviewed cleanup procedure.
- An unsupported version, wrong key, unsafe path, or corrupt ready/delivered segment blocks
  inventory instead of skipping data.
- Declared frame lengths are bounded by both the remaining file and the segment format budget before
  memory is allocated.
- Recovery metadata is opaque. Callers must use a versioned encoding and must not include
  credentials, row payloads, or unredacted SQL. A coordinator may include the minimum cursor values
  required for exact recovery only because the complete metadata frame is encrypted and
  authenticated; those values must remain redacted from diagnostics.
- Deploying this release changes newly sealed segments from format v1 to format v2. Inventory and
  delivery remain compatible with existing v1 segments.
- The master key is installation-specific and must be backed up with the spool. Losing it makes
  retained segments intentionally unreadable.

## Rollback

Stop the daemon before rolling back. A v1-only binary rejects v2 segments and must not be started
while any v2 `.ready`, `.delivered`, or incomplete segment remains in the spool. Preserve the
complete spool root and master key and use a v2-capable binary to drain every v2 segment before
restoring a v1-only release. Retaining a v2 segment requires continuing to use a v2-capable binary.
The v2 reader can validate both v1 and v2 inventory. Spool draining does not downgrade a separate
durable checkpoint, and destructive cleanup is never an automatic rollback action.
