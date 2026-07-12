# dbx-rs checkpoint state

This crate contains the serializable, in-memory state machine that gates cursor advancement on a
matching collection result and delivery confirmation. Collection and delivery progress are
independent, so either side may finish first.

The serialized `Snapshot` is a versioned state-transfer DTO only. It is **not yet a durable
persistent format**. This crate performs no filesystem I/O and defines no state directory,
atomic-write protocol, corruption policy, or rollback procedure. Those persistent-format concerns
must be specified and reviewed before snapshots are stored on disk.
