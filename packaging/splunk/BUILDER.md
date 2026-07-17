# Cross-platform Splunk app builder

The builder compiles and packages separate deployment apps for Linux x86-64 and Windows x86-64.
Linux uses a static-musl target. Windows uses the MSVC target and `cargo-xwin` when the builder runs
on a non-Windows host.

## Prerequisites

Install the pinned Rust toolchain and both standard-library targets. On a non-Windows build host,
install `cargo-xwin` as well.

```bash
rustup target add x86_64-unknown-linux-musl x86_64-pc-windows-msvc --toolchain 1.97.0
cargo install cargo-xwin --locked
```

Generate a deployment authority once in a protected directory outside the repository and outside
every app. Back up this directory. Losing its private key prevents future credential updates.

```bash
packaging/splunk/build-apps.sh authority init \
  --output /secure/dbx-rs-deployment-authority
```

Build both apps and deterministic `.spl` archives:

```bash
packaging/splunk/build-apps.sh build \
  --authority-dir /secure/dbx-rs-deployment-authority \
  --output-dir dist
```

Use `--config-dir` for shared files copied into each app's `local/` directory. Use
`--linux-overlay` and `--windows-overlay` for platform-specific files. The builder validates the
effective configuration, rejects symlinks and plaintext credential assignments, verifies that only
the public authority is embedded, authenticates every `.dbxsecret` against that authority, and
writes `dbx-rs-build-manifest.json` with per-file SHA-256 digests.

## Deployment Server mapping

Place the two app directories under `$SPLUNK_HOME/etc/deployment-apps` on the Deployment Server.
The following application-level machine filters prevent cross-platform delivery:

```ini
[serverClass:dbx-rs-platforms]
whitelist.0 = *

[serverClass:dbx-rs-platforms:app:TA-dbx-rs-linux-x86_64]
whitelist.0 = *
machineTypesFilter = linux-x86_64
stateOnClient = enabled
restartSplunkd = true

[serverClass:dbx-rs-platforms:app:TA-dbx-rs-windows-x86_64]
whitelist.0 = *
machineTypesFilter = windows-*
stateOnClient = enabled
restartSplunkd = true
```

Reload the Deployment Server after installing apps or editing `serverclass.conf`:

```bash
$SPLUNK_HOME/bin/splunk reload deploy-server
```

## Encrypted credentials

On each client, initialize or show its public recipient. The private identity remains under that
client's Splunk `var` tree.

```bash
$APP_HOME/bin/dbx-rs deployment recipient init
```

On the protected build or Deployment Server administration host, seal a credential to one or more
enrolled recipients. The credential is read only from standard input. The authority key path and
recipient IDs are not secret values.

```bash
read -r -s DB_PASSWORD
printf '%s' "$DB_PASSWORD" | \
  $APP_HOME/bin/dbx-rs deployment secret seal warehouse \
    --stdin \
    --revision 1 \
    --recipient 'dbxrs-hpke-x25519-v1:...' \
    --authority-key /secure/dbx-rs-deployment-authority/deployment-authority-key.pk8 \
    --output "$APP_HOME/deployment-secrets/warehouse.dbxsecret"
unset DB_PASSWORD
```

Only the signed `.dbxsecret` envelope is distributed. The daemon authenticates and imports the
greatest revision before workers start and on configuration reload. Reusing the same revision with
different content is rejected; lower revisions are stale. Splunk KV is not used.
