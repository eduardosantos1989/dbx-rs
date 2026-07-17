# dbx-rs

`dbx-rs` is an open-source, Splunk-native database collection engine written in Rust. Its target
architecture runs as a self-contained Splunk-supervised daemon with standalone connector
diagnostics and an administrative CLI, requires no JVM, and requires no separately installed
database driver for certified native connectors.

## Status

The project is at an early vertical-slice stage. The PostgreSQL connector validates configuration,
probes with verified Rustls TLS, prepares typed schemas, and streams bounded self-contained Arrow
IPC batches through connector contract v1.2. The connector can bind a certified
`TIMESTAMPTZ`-plus-`BIGINT` cursor through native PostgreSQL parameters and enforce deterministic
outer ordering. A connector-neutral native registry validates cursor schema, nulls, strict tuple
ordering, overlap bounds, and checkpoint candidates directly from Arrow before materializing
explicit-null NDJSON for the current HEC delivery adapter. Unsupported or lossy PostgreSQL
conversions fail closed. A singleton daemon is supervised as a continuous Splunk
scripted input, loads typed layered configuration, keeps database credentials in an
installation-specific authenticated encrypted store, and sends CPU-bounded non-overlapping input
runs through a quota-bounded encrypted spool before verified local HEC delivery. Complete segments
are authenticated, synchronized, and atomically sealed before network output; incomplete segments
are quarantined on startup and ready segments are replayed in stable order. Each frozen HEC
envelope includes a deterministic event identity for downstream replay deduplication. It can
generate and reconcile a stable local HEC token and certificate without Splunk management
credentials. Daemon and connector operations emit versioned, redacted NDJSON lifecycle metrics
with epoch timestamps to Splunk's `dbx-trace.log`.

Oracle is registered as an Experimental Native batch connector. Distinct MySQL and MariaDB
Experimental Native connectors implement product detection, verified Rustls TLS, prepared typed
Arrow streaming, and `TIMESTAMP`-plus-signed-`BIGINT` rising queries through a shared native
protocol crate. Microsoft SQL Server is registered as a separate Experimental Native batch/rising
connector using Rustls and TDS directly, with exact decimal/money conversion and a
`DATETIME2(0..6)`-plus-`BIGINT` cursor. Unsupported, lossy, cross-product, and unsafe query forms
fail closed. These connectors remain Experimental Native pending broader compatibility evidence.

The `dbx-rs` administrative CLI now exposes typed JSON operations for validating one named input,
probing its configured connector, and running a tightly bounded read-only query test.
Inline test SQL is read only from standard input, while file tests are restricted to the app's
connector-specific query directory. These operations share serializable service DTOs intended for
a future authenticated REST layer; no REST listener is currently exposed. The connector contract is
currently an in-process boundary. The framed worker transport remains a later implementation step.

A serializable checkpoint coordinator models independent collection and delivery completion,
stale-generation fencing, replay recovery, and delivery-gated cursor commit. The scheduled daemon
supports batch stanzas for every registered connector and rising stanzas for PostgreSQL, SQL
Server, MySQL, and MariaDB with an immutable input UUID and typed timestamp-plus-integer cursor. Every active rising
attempt has a durable scan, and each non-empty page is authenticated and sealed in the spool before
its reference is appended to the scan. Startup reconciliation can adopt a sealed page, resume
collection, persist one sequential delivery receipt at a time, compact receipted segments, and
finish an empty final page without inventing a cursor.

A rising checkpoint advances only after collection is complete, every sealed page has crossed the
configured HEC boundary, the complete delivery-receipt prefix is durable, and the coordinator has
confirmed delivery. Delivery remains at-least-once: batch or rising envelopes can be replayed after
an uncertain HTTP or indexer-acknowledgment result. Stable event identities support downstream
deduplication without changing that delivery contract. Detailed planning material is maintained
privately until reviewed for public release.

The first product objective is a PostgreSQL input under the Splunk-supervised daemon with durable,
at-least-once collection and a composite rising cursor. Reliability and explicit delivery semantics
take priority over connector count.

## Linux compatibility

The required deployment target includes legacy Linux x86-64 hosts that use glibc 2.10 or newer.
The product will ship a static-musl Linux binary so its own runtime does not require a newer glibc;
the normal Rust GNU target requires glibc 2.17 or newer. Kernel, CPU, Splunk, and database support
remain separate compatibility dimensions and will be certified with recorded tests rather than
assumed from the glibc version.

## Principles

- No Java runtime, JDBC, or Java task server.
- No external driver installation for Native Certified connectors.
- No silent checkpoint advancement, TLS downgrade, or lossy type conversion.
- No universal exactly-once claim; replay duplicates are possible after uncertain delivery.
- No secrets, bound values, or row payloads in logs.
- No unsafe Rust without an isolated crate and an approved architecture decision record.

## Build

Install Rust through `rustup`. The repository pins its toolchain in `rust-toolchain.toml`.

```bash
cargo build --workspace
cargo run -p dbx-rs-cli -- --version
cargo run -p dbx-rs-daemon -- --version
cargo run -p dbx-rs-connector-postgres -- --help
```

Run the complete bootstrap checks with:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo deny check
```

`cargo-deny` is a separate development tool. Install the pinned CI version with:

```bash
cargo install cargo-deny --version 0.20.2 --locked
```

## Contributing

Read `AGENTS.md` and `CONTRIBUTING.md` before making changes. Foundational architecture changes
require maintainer review; private ADRs and repository memory are not public contribution
artifacts.

## Security

See `SECURITY.md` for vulnerability reporting guidance. Do not include credentials, tokens,
connection strings, row data, or other sensitive material in an issue or support artifact.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE`.
