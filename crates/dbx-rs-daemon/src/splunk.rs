use std::collections::BTreeSet;
use std::path::Path;

use configparser::ini::Ini;
use dbx_rs_config::{HecConfig, HecInputManagement, HecState, IndexerAcknowledgment, InputConfig};

use crate::error::DaemonError;
use crate::identity::HecToken;
use crate::secure_fs::{atomic_write, read_limited};

const MAX_INPUTS_CONF_BYTES: u64 = 1024 * 1024;

pub fn reconcile_managed_hec(
    config: &HecConfig,
    inputs: &[InputConfig],
    token: &HecToken,
    server_pem_file: &Path,
    managed_inputs_file: &Path,
) -> Result<bool, DaemonError> {
    if config.input_management == HecInputManagement::External {
        return Ok(false);
    }

    let mut ini = Ini::new_cs();
    if managed_inputs_file.exists() {
        let bytes = read_limited(managed_inputs_file, MAX_INPUTS_CONF_BYTES)?;
        let text = String::from_utf8(bytes).map_err(|_| {
            DaemonError::new(
                "DBX-RS-SPLUNK-0001",
                "configuration",
                "inputs_read",
                "managed Splunk inputs file is not valid UTF-8",
                false,
                true,
            )
        })?;
        ini.read(text).map_err(|_| {
            DaemonError::new(
                "DBX-RS-SPLUNK-0002",
                "configuration",
                "inputs_parse",
                "managed Splunk inputs file is invalid",
                false,
                true,
            )
        })?;
    }

    let mut changed = false;
    if config.state == HecState::Enabled {
        changed |= set(&mut ini, "http", "disabled", "0");
        changed |= set(&mut ini, "http", "port", &config.listen_port.to_string());
        changed |= set(&mut ini, "http", "enableSSL", "1");
        changed |= set(&mut ini, "http", "acceptFrom", &config.accept_from);
        changed |= set(&mut ini, "http", "maxEventSize", "10MB");
        let server_pem = server_pem_file.to_str().ok_or_else(|| {
            DaemonError::new(
                "DBX-RS-SPLUNK-0003",
                "configuration",
                "inputs_reconcile",
                "HEC certificate path is not valid UTF-8",
                false,
                true,
            )
        })?;
        changed |= set(&mut ini, "http", "serverCert", server_pem);
    }

    let stanza = format!("http://{}", config.input_name);
    changed |= set(
        &mut ini,
        &stanza,
        "disabled",
        if config.state == HecState::Enabled {
            "0"
        } else {
            "1"
        },
    );
    changed |= set(&mut ini, &stanza, "token", token.as_str());
    changed |= set(&mut ini, &stanza, "description", "dbx-rs managed HEC input");
    changed |= set(&mut ini, &stanza, "index", &config.index);
    changed |= set(
        &mut ini,
        &stanza,
        "indexes",
        &allowed_indexes(config, inputs),
    );
    changed |= set(&mut ini, &stanza, "sourcetype", &config.sourcetype);
    changed |= set(&mut ini, &stanza, "queueSize", "1MB");
    changed |= set(&mut ini, &stanza, "connection_host", "none");
    changed |= set(
        &mut ini,
        &stanza,
        "useACK",
        if config.acknowledgment == IndexerAcknowledgment::Enabled {
            "true"
        } else {
            "false"
        },
    );

    if changed || !managed_inputs_file.exists() {
        atomic_write(managed_inputs_file, ini.writes().as_bytes(), 0o600)?;
        return Ok(true);
    }
    Ok(false)
}

fn allowed_indexes(config: &HecConfig, inputs: &[InputConfig]) -> String {
    let mut indexes = BTreeSet::from([config.index.as_str()]);
    indexes.extend(
        inputs
            .iter()
            .filter(|input| !input.disabled)
            .map(|input| input.index.as_str()),
    );
    indexes.into_iter().collect::<Vec<_>>().join(",")
}

fn set(ini: &mut Ini, section: &str, key: &str, value: &str) -> bool {
    if ini.get(section, key).as_deref() == Some(value) {
        return false;
    }
    ini.setstr(section, key, Some(value));
    true
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use dbx_rs_config::{HecState, TlsVerification};

    use super::*;

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "dbx-rs-splunk-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn config() -> HecConfig {
        HecConfig {
            state: HecState::Enabled,
            input_management: HecInputManagement::Managed,
            url: "https://localhost:8088/services/collector/event".into(),
            input_name: "dbx_rs".into(),
            listen_port: 8088,
            accept_from: "127.0.0.1,::1".into(),
            tls_verification: TlsVerification::Full,
            timeout: Duration::from_secs(10),
            batch_max_events: 500,
            batch_max_bytes: 1_000_000,
            max_event_bytes: 1_000_000,
            index: "dbx_rs_test".into(),
            sourcetype: "dbx_rs:database:row".into(),
            source: "dbx_rs:daemon".into(),
            acknowledgment: IndexerAcknowledgment::Disabled,
        }
    }

    #[test]
    fn reconciliation_preserves_unrelated_stanzas_and_is_idempotent() {
        let root = test_dir();
        let inputs_file = root.join("inputs.conf");
        fs::create_dir_all(&root).expect("fixture directory must be created");
        fs::write(
            &inputs_file,
            "[monitor:///var/log/example]\ndisabled = false\nindex = main\n",
        )
        .expect("fixture inputs must be written");
        let token =
            HecToken::load_or_create(&root.join("hec.token")).expect("token must be created");

        assert!(
            reconcile_managed_hec(
                &config(),
                &[],
                &token,
                &root.join("hec-server.pem"),
                &inputs_file,
            )
            .expect("reconciliation must succeed")
        );
        assert!(
            fs::read_to_string(&inputs_file)
                .expect("inputs must be readable")
                .contains("monitor:///var/log/example")
        );
        assert!(
            !reconcile_managed_hec(
                &config(),
                &[],
                &token,
                &root.join("hec-server.pem"),
                &inputs_file,
            )
            .expect("second reconciliation must succeed")
        );
        fs::remove_dir_all(root).expect("fixture must be removed");
    }
}
