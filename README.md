# dbx-rs

`dbx-rs` is an open-source, Splunk-native database collection engine written in Rust. Its target
architecture runs as a self-contained Splunk modular input or standalone collector, requires no
JVM, and requires no separately installed database driver for certified native connectors.

## Status

The project is at repository bootstrap. The current executable only exposes version and help
output; it does not yet connect to databases or Splunk. The design baseline is documented in
[`docs/dbx-rs-ideation-and-engineering-plan.md`](docs/dbx-rs-ideation-and-engineering-plan.md).

The first product objective is a PostgreSQL modular input with durable, at-least-once collection
and a composite rising cursor. Reliability and explicit delivery semantics take priority over
connector count.

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
cargo run -p dbx-rs-cli -- help
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
must be recorded as ADRs, and meaningful work must update the repository memory under
`docs/memory/`.

## Security

See `SECURITY.md` for vulnerability reporting guidance. Do not include credentials, tokens,
connection strings, row data, or other sensitive material in an issue or support artifact.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE`.
