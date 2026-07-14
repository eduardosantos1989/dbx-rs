# dbx-rs oracle-rs fork

This directory starts from the crates.io `oracle-rs` 0.1.7 archive with SHA-256:

```text
5c9ca364b441f92b717658c62e85207158b30285deb01811ccd923017f61612e
```

The upstream project is <https://github.com/stiang/oracle-rs> and remains licensed under MIT or
Apache-2.0. The unmodified upstream license files are retained in this directory.

The dbx-rs patch series is intentionally limited to the experimental native feasibility gates:

- Rust 1.97, matching the dbx-rs workspace toolchain;
- Ring-only Rustls configuration;
- current RustCrypto authentication dependencies and rustls-pki-types PEM parsing;
- bounded TNS packet, response-packet count, server banner, row, column, and value handling,
  including cumulative scalar admission before an oversized TTC chunk payload is read or copied,
  bounded allocation-free skips, correct outer-plus-inner TTC framing for metadata values, and a
  connector-selectable core-scalar policy that rejects every other query value before decoding;
- retained JSON/OSON UDS flags and vector metadata so semantic complex types cannot masquerade as
  supported scalar wire values;
- version-gated TTC request tokens for execute, authentication, fetch, LOB, and simple functions,
  including connection-sequenced fetch requests and fail-closed response-token validation;
- negotiated field-version parsing for query, DML, batch, PL/SQL, and marker-reset error
  completions, including Oracle 19c responses that omit 20c-only fields;
- Oracle-version-aware response parsing, strict server-version derivation, and multi-packet
  query/fetch continuation, including bounded row-header duplicate bit vectors and explicit
  previous-row continuity across fetch pages;
- Oracle authentication completion, bounded server-side piggyback decoding, and database-version
  extraction for negotiated 19c-era field layouts;
- CONNECT packet parity plus TCPS handling for Oracle's pre-ACCEPT TLS RESEND transition, which
  rebuilds verified TLS on the retained TCP socket before replaying CONNECT;
- explicit DNS/TCP failure separation and negotiated AL32UTF8/AL16UTF16 enforcement;
- immediate connection termination for timeout and cancellation cleanup;
- strict non-lossy protocol, authentication, and wire-type decoding, including canonical Oracle
  NUMBER length/digits and exact DATE/TIMESTAMP components without sub-microsecond truncation;
- stable TLS failure classification and redacted configuration/diagnostic behavior;
- APIs needed by the isolated dbx-rs connector without exposing fork types across that connector.

The isolated connector starts execution with `SET TRANSACTION READ ONLY` and includes ignored,
environment-gated live tests for Oracle 19c probe/query, direct packet observation plus connector-
level continuation through 20,001 rows, exact core types over verified TLS, negative TLS and
authentication, unsupported-type rejection, and cancellation cleanup. On 2026-07-14, all seven
tests passed serially against the authorized Oracle 19.3 sandbox. This authorizes narrow
Experimental Native product integration; it is not certification evidence for other Oracle
versions or configurations.

Encrypted Oracle wallet keys are outside this constrained fork and fail closed instead of falling
back to unauthenticated client TLS. The dbx-rs connector exposes password authentication with
either verified TCPS or explicitly disabled TLS; it does not expose wallet or client-certificate
configuration.

## Ownership and update policy

dbx-rs accepts ownership of this pinned fork for the Experimental Native Oracle connector under
these constraints:

- preserve the crates.io archive hash above and record the exact upstream tag or commit considered
  for every update;
- review upstream releases and RustSec advisories for direct and transitive dependencies during
  each dependency-maintenance cycle and before every release containing Oracle support;
- keep dbx-rs changes as reviewable protocol, bounds, transport, and connector-enablement patches;
  every behavior change requires a focused regression and redacted evidence;
- rebase in a dedicated change, compare the complete source and dependency diff, rerun fork,
  connector, workspace, live 19c, static-musl, ELF, license, deny, secret, and unsafe-code gates;
- do not silently replace the fork with OCI, ODPI-C, a system client, JDBC, or a JVM fallback;
- treat Oracle 23ai field-version-18 token behavior as synthetic until its dedicated live gate
  passes, and keep the support tier Experimental Native until an approved compatibility matrix is
  complete.

Rollback from a fork update means restoring the previously checksummed source and lock resolution,
rerunning the same gates, disabling Oracle stanzas during runtime rollback, and preserving ready
spool segments until they are deliberately drained or retained.

This fork is not evidence of Oracle certification. On 2026-07-14, the exact all-features static-musl
CLI and daemon passed ELF inspection, scheduled Oracle-to-Splunk HEC ACK delivery, and retained-ready
restart replay. Repeat those artifact and durability gates for every release containing this fork.
