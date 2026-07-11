[paths]
log_file = <absolute path>
* NDJSON operational trace file.
* The daemon rejects a logging limit above 10000000 bytes per file.
* All generated path settings must resolve under $SPLUNK_HOME/var.

splunkd_pid_file = <absolute path>
* splunkd PID file whose first process entry owns this daemon lifecycle.

instance_lock_file = <absolute path>
* Process lock that prevents concurrent daemon instances.
* Must resolve below $SPLUNK_HOME/var/run/splunk/dbx-rs.

master_key_file = <absolute path>
* Installation-specific credential-encryption key. Never distribute this file.

secret_dir = <absolute path>
* Directory containing authenticated encrypted database credentials.

hec_token_file = <absolute path>
* Protected local copy of the generated or externally provisioned HEC token.

hec_server_pem_file = <absolute path>
* Managed localhost HEC certificate chain and private key.

hec_ca_file = <absolute path>
* CA certificate used by the daemon to verify managed localhost HEC.

managed_inputs_file = <absolute path>
* Splunk inputs.conf file updated when manage_input is true.
* This Splunk-discovered configuration file is the only generated default outside var.
* Every configured path must resolve inside $SPLUNK_HOME; parent traversal is rejected.

[logging]
max_file_bytes = <integer>
* Active NDJSON trace size in bytes.
* Valid range: 4096 through 10000000. The maximum is a hard limit.

backup_count = <integer>
* Number of rotated trace files retained.
* Valid range: 0 through 20.

[daemon]
poll_interval_ms = <integer>
* Lifecycle and scheduler poll interval in milliseconds.
* Valid range: 100 through 60000.

shutdown_grace_secs = <integer>
* Time allowed for active workers to stop after splunkd changes or signals shutdown.
* Valid range: 1 through 300.

configuration_reload_secs = <integer>
* Interval for layered default and local configuration reload.
* Valid range: 1 through 3600.

max_workers = auto | <positive integer>
* Maximum concurrent database workers.
* The daemon always caps this value at available CPU parallelism.

[hec]
enabled = <boolean>
* Enables HEC as the daemon output.

manage_input = <boolean>
* Generates a stable UUID token and reconciles the managed HEC stanzas when true.
* When false, hec_token_file and hec_ca_file must be provisioned externally.

url = <HTTPS URL>
* HEC event endpoint ending in /services/collector/event.

input_name = <label>
* Managed [http://name] stanza suffix.

listen_port = <positive integer>
* Port used by managed local HEC.

accept_from = <IP or CIDR list>
* Splunk HEC client allowlist written to [http]/acceptFrom.
* The packaged default permits only IPv4 and IPv6 loopback clients.

verify_tls = <boolean>
* Verifies HEC TLS against hec_ca_file when true.
* Disabling verification is accepted only for a loopback URL.

timeout_secs = <positive integer>
* Global HEC request and indexer-acknowledgment timeout.

batch_max_events = <positive integer>
* Maximum events in one HEC request. Valid maximum: 10000.

batch_max_bytes = <positive integer>
* Maximum encoded HEC request body. Hard maximum: 10000000 bytes.

max_event_bytes = <positive integer>
* Maximum encoded HEC event. Hard maximum: 10000000 bytes and no larger than batch_max_bytes.

index = <label>
* Default HEC index.

sourcetype = <label>
* Default HEC sourcetype.

source = <label>
* Default HEC source.

use_ack = <boolean>
* Waits for Splunk indexer acknowledgment before declaring a batch delivered.
