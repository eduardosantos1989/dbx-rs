# Contributing to dbx-rs

## Before starting

1. Read `AGENTS.md` and the relevant design sections or ADRs.
2. Read the repository memory under `docs/memory/`.
3. Select one small issue or acceptance criterion.
4. Create or update a session log under `docs/memory/sessions/`.

Do not combine a foundational architecture change with unrelated feature work. Record an ADR
before changing an accepted architecture decision.

## Development setup

The pinned Rust toolchain is installed automatically by `rustup` when Cargo runs in this
repository. Install the dependency policy tool separately:

```bash
cargo install cargo-deny --version 0.20.2 --locked
```

## Required checks

Run these commands before submitting a change:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo deny check
```

Add integration, recovery, fuzz, compatibility, or security tests when the changed behavior calls
for them. Never put live credentials or production data in tests, fixtures, snapshots, logs, or
issue reports.

## Change documentation

Document:

- Behavior and operational impact.
- Security considerations.
- Evidence from tests or reproductions.
- Upgrade and rollback behavior for configuration or persistent-format changes.
- Known limitations and unverified hypotheses.

Use precise support-tier and delivery language. A connector is not Native Certified without its
required compatibility evidence, and collection is not universally exactly-once.

