# dbx-rs spool

This crate owns the encrypted durable event-segment format used before Splunk delivery. It is
host-owned and connector-neutral. Event records are exact final delivery envelopes supplied by the
caller; the crate does not inspect or log their contents.

## Format v1

Each segment contains a fixed plaintext prefix with magic, format version, key identifier, random
salt, and opaque segment identifier. HKDF-SHA256 derives a unique segment key from a separate local
spool master key. The encrypted header, every event, and the footer are independently authenticated
with ChaCha20-Poly1305 using monotonically sequenced nonces and frame metadata as additional
authenticated data.

The footer binds the event count, plaintext byte count, and a length-delimited SHA-256 stream
digest. A complete segment is synchronized before an atomic `.open` to `.ready` rename, followed
by parent-directory synchronization. `.ready` files are immutable. Delivery changes only the
lifecycle extension to `.delivered`; deletion requires explicit compaction.

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
- The master key is installation-specific and must be backed up with the spool. Losing it makes
  retained segments intentionally unreadable.

## Rollback

Stop the daemon before rolling back. A binary that does not understand format v1 must not touch the
spool. Preserve the complete spool root and master key, restore the format-v1-capable binary, and
allow it to validate inventory before collection resumes. Destructive cleanup is never an automatic
rollback action.
