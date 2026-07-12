use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use dbx_rs_control::{AdHocQuery, ControlService, QueryTestLimitOverrides, QueryTestRequest};
use dbx_rs_secure_store::SecretStore;
use tokio_util::sync::CancellationToken;

const QUERY_MARKER: &str = "control-private-query-marker";
const SECRET_MARKER: &str = "control-private-secret-marker";

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    splunk_home: PathBuf,
    app_home: PathBuf,
}

impl Fixture {
    fn new(secret_name: Option<&str>) -> Self {
        let splunk_home = std::env::temp_dir().join(format!(
            "dbx-rs-control-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let app_home = splunk_home.join("etc/apps/TA-dbx-rs");
        for path in [
            app_home.join("default"),
            app_home.join("local"),
            app_home.join("queries/psql"),
            splunk_home.join("var/log/splunk"),
            splunk_home.join("var/run/splunk/dbx-rs"),
        ] {
            fs::create_dir_all(path).expect("fixture directory must be created");
        }
        fs::write(
            app_home.join("default/dbxrs_generic.conf"),
            generic_config(),
        )
        .expect("generic configuration must be written");
        fs::write(
            app_home.join("default/dbxrs_inputs.conf"),
            input_config(secret_name.unwrap_or("missing")),
        )
        .expect("input configuration must be written");

        let store = SecretStore::open(
            &splunk_home.join("var/lib/splunk/dbx-rs/credentials/master.key"),
            &splunk_home.join("var/lib/splunk/dbx-rs/credentials/secrets"),
        )
        .expect("secret store must be created");
        if let Some(name) = secret_name {
            store
                .set(name, SECRET_MARKER.as_bytes().to_vec())
                .expect("fixture secret must be stored");
        }

        Self {
            splunk_home,
            app_home,
        }
    }

    fn service(&self) -> ControlService {
        ControlService::load(&self.app_home, &self.splunk_home).expect("control service must load")
    }

    fn trace(&self) -> String {
        fs::read_to_string(self.splunk_home.join("var/log/splunk/dbx-trace.log"))
            .expect("trace must be readable")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.splunk_home).expect("fixture must be removed");
    }
}

#[test]
fn named_validation_checks_assets_and_existing_secret_without_disclosure() {
    let fixture = Fixture::new(Some("warehouse"));
    let response = fixture
        .service()
        .validate_input("warehouse")
        .expect("validation operation must complete");

    assert!(response.valid);
    assert!(response.issues.is_empty());
    let trace = fixture.trace();
    assert!(trace.contains("\"component\":\"dbx_rs_control\""));
    assert!(trace.contains("\"operation\":\"input_validate\""));
    assert!(!trace.contains(QUERY_MARKER));
    assert!(!trace.contains(SECRET_MARKER));
}

#[test]
fn missing_secret_is_a_validation_issue_and_is_not_created() {
    let fixture = Fixture::new(None);
    let secret_file = fixture
        .splunk_home
        .join("var/lib/splunk/dbx-rs/credentials/secrets/missing.secret");
    let response = fixture
        .service()
        .validate_input("warehouse")
        .expect("validation operation must complete");

    assert!(!response.valid);
    assert!(
        response
            .issues
            .iter()
            .any(|issue| issue.field == "secret_ref")
    );
    assert!(!secret_file.exists());
}

#[tokio::test]
async fn query_test_rejects_write_sql_before_network_access_and_redacts_trace() {
    let fixture = Fixture::new(Some("warehouse"));
    let error = fixture
        .service()
        .test_query(
            QueryTestRequest {
                input: "warehouse".into(),
                query: AdHocQuery::Inline {
                    sql: "DELETE FROM control-private-query-marker".into(),
                },
                limits: QueryTestLimitOverrides::default(),
            },
            CancellationToken::new(),
        )
        .await
        .expect_err("write SQL must be rejected");

    assert_eq!(error.code(), "DBX-RS-PG-CFG-0017");
    assert_eq!(error.operation(), "query_test");
    assert_eq!(error.input(), Some("warehouse"));
    let wire = serde_json::to_value(&error).expect("error must serialize");
    assert_eq!(wire["code"], "DBX-RS-PG-CFG-0017");
    assert!(wire.get("body").is_none());
    let trace = fixture.trace();
    assert!(trace.contains("\"status\":\"failed\""));
    assert!(!trace.contains(QUERY_MARKER));
    assert!(!trace.contains(SECRET_MARKER));
}

#[tokio::test]
async fn query_test_rejects_limits_above_the_effective_cap() {
    let fixture = Fixture::new(Some("warehouse"));
    let error = fixture
        .service()
        .test_query(
            QueryTestRequest {
                input: "warehouse".into(),
                query: AdHocQuery::Inline {
                    sql: "SELECT 1".into(),
                },
                limits: QueryTestLimitOverrides {
                    max_rows: Some(101),
                    ..QueryTestLimitOverrides::default()
                },
            },
            CancellationToken::new(),
        )
        .await
        .expect_err("hard-cap violation must be rejected");

    assert_eq!(error.code(), "DBX-RS-CONTROL-0006");
    assert!(error.configuration_error());
}

#[tokio::test]
async fn query_file_must_be_inside_the_connector_asset_root() {
    let fixture = Fixture::new(Some("warehouse"));
    let outside = fixture.splunk_home.join("outside.sql");
    fs::write(&outside, "SELECT 1").expect("outside query must be written");
    let error = fixture
        .service()
        .test_query(query_file_request(outside), CancellationToken::new())
        .await
        .expect_err("outside query file must be rejected");

    assert_eq!(error.code(), "DBX-RS-CONTROL-0004");
}

#[cfg(unix)]
#[tokio::test]
async fn query_file_parent_symlink_cannot_escape_the_asset_root() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new(Some("warehouse"));
    let outside = fixture.splunk_home.join("outside");
    fs::create_dir_all(&outside).expect("outside directory must be created");
    fs::write(outside.join("query.sql"), "SELECT 1").expect("outside query must be written");
    let link = fixture.app_home.join("queries/psql/escape");
    symlink(&outside, &link).expect("escape symlink must be created");
    let error = fixture
        .service()
        .test_query(
            query_file_request(link.join("query.sql")),
            CancellationToken::new(),
        )
        .await
        .expect_err("query path through escaping parent symlink must be rejected");

    assert_eq!(error.code(), "DBX-RS-CONTROL-0004");
}

fn query_file_request(path: PathBuf) -> QueryTestRequest {
    QueryTestRequest {
        input: "warehouse".into(),
        query: AdHocQuery::File { path },
        limits: QueryTestLimitOverrides::default(),
    }
}

fn generic_config() -> &'static str {
    r"[paths]
log_file = $SPLUNK_HOME/var/log/splunk/dbx-trace.log
splunkd_pid_file = $SPLUNK_HOME/var/run/splunk/splunkd.pid
instance_lock_file = $SPLUNK_HOME/var/run/splunk/dbx-rs/daemon.lock
master_key_file = $SPLUNK_HOME/var/lib/splunk/dbx-rs/credentials/master.key
secret_dir = $SPLUNK_HOME/var/lib/splunk/dbx-rs/credentials/secrets
hec_token_file = $SPLUNK_HOME/var/lib/splunk/dbx-rs/hec/token
hec_server_pem_file = $SPLUNK_HOME/var/lib/splunk/dbx-rs/hec/server.pem
hec_ca_file = $SPLUNK_HOME/var/lib/splunk/dbx-rs/hec/ca.pem
spool_key_file = $SPLUNK_HOME/var/lib/splunk/dbx-rs/durable/spool.key
state_dir = $SPLUNK_HOME/var/lib/splunk/dbx-rs/state
spool_dir = $SPLUNK_HOME/var/lib/splunk/dbx-rs/spool
managed_inputs_file = $SPLUNK_HOME/etc/apps/TA-dbx-rs/local/inputs.conf

[logging]
max_file_bytes = 10000000
backup_count = 2

[daemon]
poll_interval_ms = 1000
shutdown_grace_secs = 30
configuration_reload_secs = 5
max_workers = auto

[spool]
segment_max_bytes = 10000000
input_max_bytes = 100000000
total_max_bytes = 1000000000

[hec]
enabled = true
manage_input = false
url = https://localhost:8088/services/collector/event
input_name = dbx_rs
listen_port = 8088
accept_from = 127.0.0.1,::1
verify_tls = true
timeout_secs = 15
batch_max_events = 250
batch_max_bytes = 1000000
max_event_bytes = 900000
index = dbx_rs_test
sourcetype = dbx_rs:database:row
source = dbx_rs:daemon
use_ack = false
"
}

fn input_config(secret_name: &str) -> String {
    format!(
        r"[warehouse]
disabled = false
connector = postgres
interval_secs = 60
host = database.invalid
port = 5432
database = telemetry
username = reader
secret_ref = local:{secret_name}
tls_mode = disable
query = SELECT '{QUERY_MARKER}' AS marker
connect_timeout_secs = 1
probe_timeout_secs = 1
max_rows = 1000
max_bytes = 2000000
query_timeout_secs = 60
index = dbx_rs_test
sourcetype = dbx_rs:database:row
source = dbx_rs:test
"
    )
}
