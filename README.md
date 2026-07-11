# dbx-rs

`dbx-rs` is an open-source, Splunk-native database collection engine written in Rust. Its target
architecture runs as a self-contained Splunk-supervised daemon with standalone connector
diagnostics, requires no JVM, and requires no separately installed database driver for certified
native connectors.

## Status

The project is at an early vertical-slice stage. The PostgreSQL connector validates configuration,
probes with verified Rustls TLS, and streams bounded JSON rows. A singleton daemon is supervised as a
continuous Splunk scripted input, loads typed layered configuration, keeps database credentials in
an installation-specific authenticated encrypted store, and sends CPU-bounded non-overlapping input
runs to verified local HEC. It can generate and reconcile a stable local HEC token and certificate
without Splunk management credentials. Daemon and connector operations emit versioned, redacted
NDJSON lifecycle metrics with epoch timestamps to Splunk's `dbx-trace.log`.

Durable spool recovery and database checkpoint protocols are not implemented yet. HEC ACK confirms
individual accepted batches, but the current end-to-end path must not be described as production
at-least-once collection until those state machines exist. Detailed planning and operational
material is maintained privately until it has been reviewed for public release.

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
