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
- explicit DNS/TCP failure separation and negotiated AL32UTF8/AL16UTF16 enforcement;
- immediate connection termination for timeout and cancellation cleanup;
- strict non-lossy protocol, authentication, and wire-type decoding, including canonical Oracle
  NUMBER length/digits and exact DATE/TIMESTAMP components without sub-microsecond truncation;
- stable TLS failure classification and redacted configuration/diagnostic behavior;
- APIs needed by the isolated dbx-rs connector without exposing fork types across that connector.

The isolated connector starts execution with `SET TRANSACTION READ ONLY` and includes ignored,
environment-gated live tests for Oracle 19c probe/query, direct packet observation plus connector-
level continuation through 20,001 rows, exact core types over verified TLS, negative TLS and
authentication, unsupported-type rejection, and cancellation cleanup. Compiling those fixtures is
offline evidence; they must run against an authorized sandbox before any certification or
integration decision.

Encrypted Oracle wallet keys are outside this constrained fork and fail closed instead of falling
back to unauthenticated client TLS. The dbx-rs connector exposes password authentication with
either verified TCPS or explicitly disabled TLS; it does not expose wallet or client-certificate
configuration.

This fork is not evidence of Oracle certification. Live Oracle 19c query, continuation,
cancellation-cleanup, TLS, type-corpus, and compatibility tests plus inspection of the eventual
shipped static-musl artifact remain mandatory before registry, daemon, configuration, or packaging
integration.
