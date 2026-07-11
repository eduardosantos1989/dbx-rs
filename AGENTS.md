# dbx-rs agent rules

These rules apply to the entire repository. A more specific `AGENTS.md` may add local rules for
its directory, but it must not weaken these requirements.

## Required workflow

- Read the nearest `AGENTS.md` before changing files.
- Read `docs/memory/current-state.md`, `docs/memory/known-failures.md`, and
  `docs/memory/open-questions.md` before implementation.
- Read the relevant plan under `docs/memory/plans/active/` when one exists.
- Create or update a session file under `docs/memory/sessions/` for every meaningful task.
- Keep facts, evidence, and hypotheses distinct.
- Never state a root cause without evidence.
- Record what worked, what failed, commands executed, and the next recommended step.
- Prefer concise structured notes over long prose.

Every session file must include:

- Objective
- Starting context
- Relevant files
- Actions taken
- Commands executed
- Observations
- Evidence
- What worked
- What failed
- Hypotheses
- Next steps

## Architecture invariants

- Preserve the zero-JVM architecture. Do not introduce Java, JDBC, or a Java fallback.
- Do not add a system database-driver dependency to a Native Certified connector.
- Do not expose third-party database crate types outside a connector crate.
- Keep connector APIs serializable and independent of host-global state.
- Do not advance checkpoints before the configured delivery boundary.
- Describe delivery as at-least-once; do not claim universal exactly-once behavior.
- Do not log credentials, tokens, bound values, row payloads, or unredacted SQL by default.
- Do not silently weaken TLS or perform lossy type conversion.
- Do not add unsafe Rust outside an isolated crate approved by an ADR.
- Document operational impact and rollback for every persistent-format change.

## Engineering expectations

- Keep changes small and aligned with the active issue.
- Use workspace dependency inheritance.
- Add tests for behavior and every state-machine transition or recovery path introduced.
- Update an ADR when changing a foundational architecture decision.
- Run the relevant checks before declaring work complete:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo deny check
```

