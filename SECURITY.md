# Security policy

## Supported versions

`dbx-rs` is in initial development and has no production release. Security fixes are currently
made on the default development branch only.

## Reporting a vulnerability

Use the repository host's private vulnerability reporting feature when it is available. If no
private channel is configured, contact a maintainer privately before opening a public report. Do
not include exploit details or sensitive data in a public issue.

Include only the minimum evidence needed to reproduce the issue:

- Affected revision or release.
- Operating system and architecture.
- Relevant deployment mode.
- Reproduction steps using synthetic data.
- Observed impact.

Remove credentials, tokens, session keys, connection strings, SQL parameter values, row payloads,
certificates, and private hostnames from all reports and attachments.

## Security baseline

The project must not silently weaken TLS, expose secrets in logs, advance checkpoints before the
configured delivery boundary, or perform silent lossy type conversion. Java and JDBC fallbacks
are outside the supported architecture.

