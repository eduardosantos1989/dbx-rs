use std::collections::BTreeMap;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dbx_rs_config::{HecConfig, IndexerAcknowledgment, TlsVerification};
use dbx_rs_secure_store::read_limited;
use http::HeaderValue;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use ureq::tls::{Certificate, RootCerts, TlsConfig};

use crate::error::DaemonError;
use crate::identity::{HecToken, generate_uuid};

const MAX_HEC_RESPONSE_BYTES: u64 = 4 * 1024;
const ACK_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone)]
pub struct HecClient {
    inner: Arc<HecClientInner>,
}

struct HecClientInner {
    agent: ureq::Agent,
    event_url: String,
    ack_url: String,
    authorization: HeaderValue,
    request_channel: HeaderValue,
    use_ack: bool,
    timeout: Duration,
    max_event_bytes: u64,
    max_batch_bytes: u64,
}

#[derive(Clone)]
pub struct EventMetadata {
    pub index: String,
    pub sourcetype: String,
    pub source: String,
}

impl HecClient {
    pub fn new(
        config: &HecConfig,
        token: &HecToken,
        ca_file: &std::path::Path,
    ) -> Result<Self, DaemonError> {
        let tls_config = match config.tls_verification {
            TlsVerification::Full => {
                let ca_pem = read_limited(ca_file, 64 * 1024)?;
                let certificate = Certificate::from_pem(&ca_pem).map_err(|_| {
                    DaemonError::new(
                        "DBX-RS-HEC-0001",
                        "configuration",
                        "hec_tls",
                        "HEC trust certificate is invalid",
                        false,
                        true,
                    )
                })?;
                TlsConfig::builder()
                    .root_certs(RootCerts::new_with_certs(&[certificate]))
                    .build()
            }
            TlsVerification::Disabled => TlsConfig::builder().disable_verification(true).build(),
        };
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(config.timeout))
            .tls_config(tls_config)
            .build()
            .new_agent();

        let mut authorization_bytes = b"Splunk ".to_vec();
        authorization_bytes.extend_from_slice(token.as_str().as_bytes());
        let authorization = HeaderValue::from_bytes(&authorization_bytes).map_err(|_| {
            DaemonError::new(
                "DBX-RS-HEC-0002",
                "configuration",
                "hec_authentication",
                "HEC authorization value is invalid",
                false,
                true,
            )
        })?;
        authorization_bytes.fill(0);
        let request_channel = HeaderValue::from_str(&generate_uuid()?).map_err(|_| {
            DaemonError::new(
                "DBX-RS-HEC-0003",
                "internal",
                "hec_channel",
                "HEC request channel generation failed",
                false,
                false,
            )
        })?;
        let ack_url = config
            .url
            .strip_suffix("/event")
            .map(|prefix| format!("{prefix}/ack"))
            .ok_or_else(|| {
                DaemonError::new(
                    "DBX-RS-HEC-0004",
                    "configuration",
                    "hec_url",
                    "HEC event URL cannot be mapped to the ACK endpoint",
                    false,
                    true,
                )
            })?;

        Ok(Self {
            inner: Arc::new(HecClientInner {
                agent,
                event_url: config.url.clone(),
                ack_url,
                authorization,
                request_channel,
                use_ack: config.acknowledgment == IndexerAcknowledgment::Enabled,
                timeout: config.timeout,
                max_event_bytes: config.max_event_bytes,
                max_batch_bytes: config.batch_max_bytes,
            }),
        })
    }

    pub fn encode_event(
        &self,
        line: Vec<u8>,
        metadata: &EventMetadata,
        event_id: &str,
    ) -> Result<Vec<u8>, DaemonError> {
        let event = String::from_utf8(line).map_err(|_| {
            DaemonError::new(
                "DBX-RS-HEC-0005",
                "conversion",
                "hec_encode",
                "database event is not valid UTF-8",
                false,
                false,
            )
        })?;
        let event = RawValue::from_string(event).map_err(|_| {
            DaemonError::new(
                "DBX-RS-HEC-0006",
                "conversion",
                "hec_encode",
                "database event is not valid JSON",
                false,
                false,
            )
        })?;
        let envelope = EventEnvelope {
            time: epoch_seconds()?,
            index: &metadata.index,
            sourcetype: &metadata.sourcetype,
            source: &metadata.source,
            fields: EventFields {
                dbxrs_event_id: event_id,
            },
            event: &event,
        };
        let encoded = serde_json::to_vec(&envelope).map_err(|_| {
            DaemonError::new(
                "DBX-RS-HEC-0007",
                "internal",
                "hec_encode",
                "HEC event serialization failed",
                false,
                false,
            )
        })?;
        if encoded.len() as u64 > self.inner.max_event_bytes {
            return Err(DaemonError::new(
                "DBX-RS-HEC-0008",
                "configuration",
                "hec_encode",
                "HEC event exceeds the configured hard event limit",
                false,
                true,
            ));
        }
        Ok(encoded)
    }

    pub fn send_batch(&self, body: &[u8]) -> Result<(), DaemonError> {
        if body.is_empty() || body.len() as u64 > self.inner.max_batch_bytes {
            return Err(DaemonError::new(
                "DBX-RS-HEC-0009",
                "configuration",
                "hec_send",
                "HEC batch is empty or exceeds its configured hard limit",
                false,
                true,
            ));
        }

        self.send_once(body)
    }

    fn send_once(&self, body: &[u8]) -> Result<(), DaemonError> {
        let mut response = self
            .inner
            .agent
            .post(&self.inner.event_url)
            .header("Authorization", self.inner.authorization.clone())
            .header(
                "X-Splunk-Request-Channel",
                self.inner.request_channel.clone(),
            )
            .content_type("application/json")
            .send(body)
            .map_err(|_| hec_transport_error("hec_send"))?;
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_HEC_RESPONSE_BYTES)
            .read_to_vec()
            .map_err(|_| hec_transport_error("hec_response"))?;
        let response: HecResponse = serde_json::from_slice(&body).map_err(|_| {
            DaemonError::new(
                "DBX-RS-HEC-0010",
                "protocol",
                "hec_response",
                "HEC returned an invalid response",
                true,
                false,
            )
        })?;
        if response.code != 0 {
            return Err(DaemonError::new(
                "DBX-RS-HEC-0011",
                "protocol",
                "hec_response",
                "HEC rejected an event batch",
                true,
                false,
            ));
        }
        if self.inner.use_ack {
            let ack_id = response.ack_id.ok_or_else(|| {
                DaemonError::new(
                    "DBX-RS-HEC-0012",
                    "protocol",
                    "hec_ack",
                    "HEC ACK mode did not return an acknowledgment ID",
                    true,
                    false,
                )
            })?;
            self.wait_for_ack(ack_id)?;
        }
        Ok(())
    }

    fn wait_for_ack(&self, ack_id: u64) -> Result<(), DaemonError> {
        let deadline = Instant::now() + self.inner.timeout;
        let request = serde_json::to_vec(&AckRequest { acks: [ack_id] }).map_err(|_| {
            DaemonError::new(
                "DBX-RS-HEC-0013",
                "internal",
                "hec_ack",
                "HEC ACK request serialization failed",
                false,
                false,
            )
        })?;
        let ack_key = ack_id.to_string();
        while Instant::now() < deadline {
            let mut response = self
                .inner
                .agent
                .post(&self.inner.ack_url)
                .header("Authorization", self.inner.authorization.clone())
                .header(
                    "X-Splunk-Request-Channel",
                    self.inner.request_channel.clone(),
                )
                .content_type("application/json")
                .send(&request)
                .map_err(|_| hec_transport_error("hec_ack"))?;
            let body = response
                .body_mut()
                .with_config()
                .limit(MAX_HEC_RESPONSE_BYTES)
                .read_to_vec()
                .map_err(|_| hec_transport_error("hec_ack"))?;
            let response: AckResponse = serde_json::from_slice(&body).map_err(|_| {
                DaemonError::new(
                    "DBX-RS-HEC-0014",
                    "protocol",
                    "hec_ack",
                    "HEC returned an invalid ACK response",
                    true,
                    false,
                )
            })?;
            if response.acks.get(&ack_key).copied().unwrap_or(false) {
                return Ok(());
            }
            thread::sleep(ACK_POLL_INTERVAL);
        }
        Err(DaemonError::new(
            "DBX-RS-HEC-0015",
            "timeout",
            "hec_ack",
            "HEC indexer acknowledgment timed out",
            true,
            false,
        ))
    }
}

#[derive(Serialize)]
struct EventEnvelope<'a> {
    time: f64,
    index: &'a str,
    sourcetype: &'a str,
    source: &'a str,
    fields: EventFields<'a>,
    event: &'a RawValue,
}

#[derive(Serialize)]
struct EventFields<'a> {
    dbxrs_event_id: &'a str,
}

#[derive(Deserialize)]
struct HecResponse {
    code: u32,
    #[serde(default, rename = "ackId")]
    ack_id: Option<u64>,
}

#[derive(Serialize)]
struct AckRequest {
    acks: [u64; 1],
}

#[derive(Deserialize)]
struct AckResponse {
    acks: BTreeMap<String, bool>,
}

fn epoch_seconds() -> Result<f64, DaemonError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .map_err(|_| {
            DaemonError::new(
                "DBX-RS-HEC-0016",
                "internal",
                "clock",
                "system clock is before the Unix epoch",
                false,
                false,
            )
        })
}

const fn hec_transport_error(stage: &'static str) -> DaemonError {
    DaemonError::new(
        "DBX-RS-HEC-0017",
        "transport",
        stage,
        "HEC transport failed",
        true,
        false,
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use dbx_rs_config::{HecInputManagement, HecState};

    use super::*;

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    fn fixture() -> (std::path::PathBuf, HecConfig, HecToken) {
        let root = std::env::temp_dir().join(format!(
            "dbx-rs-hec-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let token =
            HecToken::load_or_create(&root.join("hec.token")).expect("token must be generated");
        crate::identity::ensure_hec_certificate(
            &root.join("hec-server.pem"),
            &root.join("hec-ca.pem"),
        )
        .expect("certificate must be generated");
        let config = HecConfig {
            state: HecState::Enabled,
            input_management: HecInputManagement::Managed,
            url: "https://localhost:8088/services/collector/event".into(),
            input_name: "dbx_rs".into(),
            listen_port: 8088,
            accept_from: "127.0.0.1,::1".into(),
            tls_verification: TlsVerification::Full,
            timeout: Duration::from_secs(1),
            batch_max_events: 10,
            batch_max_bytes: 4096,
            max_event_bytes: 2048,
            index: "dbx_rs_test".into(),
            sourcetype: "dbx_rs:database:row".into(),
            source: "dbx_rs:daemon".into(),
            acknowledgment: IndexerAcknowledgment::Disabled,
        };
        (root, config, token)
    }

    #[test]
    fn event_envelope_preserves_structured_json_and_metadata() {
        let (root, config, token) = fixture();
        let client = HecClient::new(&config, &token, &root.join("hec-ca.pem"))
            .expect("client must initialize");
        let encoded = client
            .encode_event(
                br#"{"value":42}"#.to_vec(),
                &EventMetadata {
                    index: "dbx_rs_test".into(),
                    sourcetype: "dbx_rs:postgres:test".into(),
                    source: "dbx_rs:test".into(),
                },
                "stable-event-id",
            )
            .expect("event must encode");
        let value: serde_json::Value =
            serde_json::from_slice(&encoded).expect("envelope must be JSON");

        assert_eq!(value["event"]["value"], 42);
        assert_eq!(value["index"], "dbx_rs_test");
        assert_eq!(value["fields"]["dbxrs_event_id"], "stable-event-id");
        assert!(value["time"].as_f64().is_some_and(|time| time > 0.0));
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn invalid_database_json_is_rejected_before_transport() {
        let (root, config, token) = fixture();
        let client = HecClient::new(&config, &token, &root.join("hec-ca.pem"))
            .expect("client must initialize");
        let error = client
            .encode_event(
                b"not-json".to_vec(),
                &EventMetadata {
                    index: "dbx_rs_test".into(),
                    sourcetype: "dbx_rs:postgres:test".into(),
                    source: "dbx_rs:test".into(),
                },
                "stable-event-id",
            )
            .expect_err("invalid JSON must fail");

        assert_eq!(error.code(), "DBX-RS-HEC-0006");
        fs::remove_dir_all(root).expect("fixture must be removed");
    }
}
