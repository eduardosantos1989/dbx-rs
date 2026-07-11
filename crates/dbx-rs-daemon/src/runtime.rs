use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use dbx_rs_config::{
    EffectiveConfig, HecInputManagement, HecState, InputConfig, load_effective_config,
};
use dbx_rs_telemetry::{NdjsonTelemetry, OperationLimits, OperationMetrics, TelemetryConfig};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::error::DaemonError;
use crate::hec::HecClient;
use crate::identity::{HecToken, ensure_hec_certificate, generate_uuid};
use crate::lifecycle::{InstanceGuard, SplunkdIdentity, shutdown_signal};
use crate::operational::OperationTracker;
use crate::secrets::SecretStore;
use crate::splunk::reconcile_managed_hec;
use crate::worker::run_input;

pub struct BootstrapResult {
    pub splunk_inputs_changed: bool,
    pub certificate_created: bool,
}

struct PreparedRuntime {
    secrets: Arc<SecretStore>,
    hec: Option<HecClient>,
    result: BootstrapResult,
}

pub fn bootstrap(config: &EffectiveConfig) -> Result<BootstrapResult, DaemonError> {
    let _guard = InstanceGuard::acquire(&config.generic.paths.instance_lock_file)?;
    prepare_runtime(config).map(|prepared| prepared.result)
}

pub async fn run(
    app_home: &Path,
    splunk_home: &Path,
    mut config: EffectiveConfig,
) -> Result<(), DaemonError> {
    ensure_log_parent(&config.generic.paths.log_file)?;
    let telemetry = NdjsonTelemetry::new(
        TelemetryConfig::new(&config.generic.paths.log_file).with_rotation(
            config.generic.logging.max_file_bytes,
            config.generic.logging.backup_count,
        ),
    )
    .map_err(|_| trace_error())?;
    let run_id = generate_uuid()?;
    let tracker = OperationTracker::start(
        &telemetry,
        "host",
        "daemon_run",
        &run_id,
        "local",
        None,
        OperationLimits::default(),
    )?;
    let result = run_inner(app_home, splunk_home, &mut config, telemetry).await;
    match result {
        Ok(()) => tracker.succeeded(OperationMetrics::probe(None)),
        Err(error) => {
            tracker.failed_daemon(&error);
            Err(error)
        }
    }
}

async fn run_inner(
    app_home: &Path,
    splunk_home: &Path,
    config: &mut EffectiveConfig,
    telemetry: NdjsonTelemetry,
) -> Result<(), DaemonError> {
    let _guard = InstanceGuard::acquire(&config.generic.paths.instance_lock_file)?;
    let splunkd = SplunkdIdentity::capture(&config.generic.paths.splunkd_pid_file)?;
    let prepared = prepare_runtime(config)?;
    let secrets = prepared.secrets;
    let mut hec = prepared.hec;
    let available_parallelism = std::thread::available_parallelism().map_err(|error| {
        DaemonError::io(
            "DBX-RS-RUN-0001",
            "worker_capacity",
            "failed to determine available CPU parallelism",
            &error,
        )
    })?;
    let cancellation = CancellationToken::new();
    let mut schedule = ScheduleState::new(&config.inputs, Instant::now());
    let mut tasks = BTreeMap::<String, JoinHandle<()>>::new();
    let mut next_reload = Instant::now() + config.generic.daemon.configuration_reload;
    let mut signal = Box::pin(shutdown_signal());
    let mut signal_error = None;

    loop {
        finish_workers(&mut tasks, &mut schedule, config).await;
        if !splunkd.is_current() {
            break;
        }

        let now = Instant::now();
        if now >= next_reload {
            if let Some((new_config, new_hec)) =
                reload_configuration(app_home, splunk_home, config, &telemetry)
            {
                *config = new_config;
                hec = new_hec;
                schedule.sync(&config.inputs, now);
            }
            next_reload = now + config.generic.daemon.configuration_reload;
        }

        let capacity = config
            .generic
            .daemon
            .max_workers
            .effective(available_parallelism)
            .get();
        if let Some(client) = &hec {
            for input in schedule.take_due(&config.inputs, now, capacity) {
                let name = input.name.clone();
                let worker_client = client.clone();
                let worker_secrets = Arc::clone(&secrets);
                let worker_telemetry = telemetry.clone();
                let worker_cancellation = cancellation.child_token();
                let batch_max_events = config.generic.hec.batch_max_events;
                let batch_max_bytes = config.generic.hec.batch_max_bytes;
                let task = tokio::spawn(async move {
                    let _result = run_input(
                        input,
                        worker_client,
                        worker_secrets,
                        worker_telemetry,
                        batch_max_events,
                        batch_max_bytes,
                        worker_cancellation,
                    )
                    .await;
                });
                tasks.insert(name, task);
            }
        }

        tokio::select! {
            result = &mut signal => {
                if let Err(error) = result {
                    signal_error = Some(error);
                }
                break;
            }
            () = tokio::time::sleep(config.generic.daemon.poll_interval) => {}
        }
    }

    cancellation.cancel();
    stop_workers(tasks, config.generic.daemon.shutdown_grace).await;
    if let Some(error) = signal_error {
        return Err(error);
    }
    Ok(())
}

fn prepare_runtime(config: &EffectiveConfig) -> Result<PreparedRuntime, DaemonError> {
    let secrets = Arc::new(SecretStore::open(
        &config.generic.paths.master_key_file,
        &config.generic.paths.secret_dir,
    )?);
    let (hec, result) = prepare_hec(config)?;
    Ok(PreparedRuntime {
        secrets,
        hec,
        result,
    })
}

fn prepare_hec(
    config: &EffectiveConfig,
) -> Result<(Option<HecClient>, BootstrapResult), DaemonError> {
    let managed = config.generic.hec.input_management == HecInputManagement::Managed;
    let enabled = config.generic.hec.state == HecState::Enabled;
    let certificate_created = if managed && enabled {
        ensure_hec_certificate(
            &config.generic.paths.hec_server_pem_file,
            &config.generic.paths.hec_ca_file,
        )?
    } else {
        false
    };
    let token = if managed {
        Some(HecToken::load_or_create(
            &config.generic.paths.hec_token_file,
        )?)
    } else if enabled {
        Some(HecToken::load(&config.generic.paths.hec_token_file)?)
    } else {
        None
    };
    let splunk_inputs_changed = if managed {
        reconcile_managed_hec(
            &config.generic.hec,
            &config.inputs,
            token.as_ref().ok_or_else(|| {
                DaemonError::new(
                    "DBX-RS-RUN-0007",
                    "configuration",
                    "hec_prepare",
                    "managed HEC output has no token",
                    false,
                    true,
                )
            })?,
            &config.generic.paths.hec_server_pem_file,
            &config.generic.paths.managed_inputs_file,
        )?
    } else {
        false
    };
    let hec = if enabled {
        Some(HecClient::new(
            &config.generic.hec,
            token.as_ref().ok_or_else(|| {
                DaemonError::new(
                    "DBX-RS-RUN-0002",
                    "configuration",
                    "hec_prepare",
                    "enabled HEC output has no token",
                    false,
                    true,
                )
            })?,
            &config.generic.paths.hec_ca_file,
        )?)
    } else {
        None
    };
    Ok((
        hec,
        BootstrapResult {
            splunk_inputs_changed,
            certificate_created,
        },
    ))
}

fn reload_configuration(
    app_home: &Path,
    splunk_home: &Path,
    current: &EffectiveConfig,
    telemetry: &NdjsonTelemetry,
) -> Option<(EffectiveConfig, Option<HecClient>)> {
    let candidate = match load_effective_config(app_home, splunk_home) {
        Ok(candidate) => candidate,
        Err(error) => {
            log_reload_failure(telemetry, &DaemonError::from_config(&error));
            return None;
        }
    };
    if candidate == *current {
        return None;
    }
    if candidate.generic.paths != current.generic.paths
        || candidate.generic.logging != current.generic.logging
    {
        log_reload_failure(
            telemetry,
            &DaemonError::new(
                "DBX-RS-RUN-0003",
                "configuration",
                "config_reload",
                "path and logging changes require a daemon restart",
                false,
                true,
            ),
        );
        return None;
    }
    match prepare_hec(&candidate) {
        Ok((hec, _result)) => {
            log_reload_success(telemetry);
            Some((candidate, hec))
        }
        Err(error) => {
            log_reload_failure(telemetry, &error);
            None
        }
    }
}

fn log_reload_success(telemetry: &NdjsonTelemetry) {
    if let Ok(request_id) = generate_uuid()
        && let Ok(tracker) = OperationTracker::start(
            telemetry,
            "host",
            "config_reload",
            &request_id,
            "local",
            None,
            OperationLimits::default(),
        )
    {
        let _ignored = tracker.succeeded(OperationMetrics::probe(None));
    }
}

fn log_reload_failure(telemetry: &NdjsonTelemetry, error: &DaemonError) {
    if let Ok(request_id) = generate_uuid()
        && let Ok(tracker) = OperationTracker::start(
            telemetry,
            "host",
            "config_reload",
            &request_id,
            "local",
            None,
            OperationLimits::default(),
        )
    {
        tracker.failed_daemon(error);
    }
}

async fn finish_workers(
    tasks: &mut BTreeMap<String, JoinHandle<()>>,
    schedule: &mut ScheduleState,
    config: &EffectiveConfig,
) {
    let finished = tasks
        .iter()
        .filter_map(|(name, task)| task.is_finished().then_some(name.clone()))
        .collect::<Vec<_>>();
    for name in finished {
        if let Some(task) = tasks.remove(&name) {
            let _result = task.await;
        }
        let interval = config
            .inputs
            .iter()
            .find(|input| input.name == name)
            .map(|input| input.interval);
        schedule.complete(&name, Instant::now(), interval);
    }
}

async fn stop_workers(tasks: BTreeMap<String, JoinHandle<()>>, grace: std::time::Duration) {
    let deadline = tokio::time::Instant::now() + grace;
    for (_name, mut task) in tasks {
        if tokio::time::timeout_at(deadline, &mut task).await.is_err() {
            task.abort();
        }
    }
}

fn ensure_log_parent(path: &Path) -> Result<(), DaemonError> {
    let parent = path.parent().ok_or_else(|| {
        DaemonError::new(
            "DBX-RS-RUN-0004",
            "configuration",
            "trace_initialize",
            "trace log path has no parent directory",
            false,
            true,
        )
    })?;
    std::fs::create_dir_all(parent).map_err(|error| {
        DaemonError::io(
            "DBX-RS-RUN-0005",
            "trace_initialize",
            "failed to create the trace log directory",
            &error,
        )
    })
}

const fn trace_error() -> DaemonError {
    DaemonError::new(
        "DBX-RS-RUN-0006",
        "configuration",
        "trace_initialize",
        "operational telemetry configuration is invalid",
        false,
        true,
    )
}

struct ScheduleState {
    next_due: BTreeMap<String, Instant>,
    running: BTreeSet<String>,
}

impl ScheduleState {
    fn new(inputs: &[InputConfig], now: Instant) -> Self {
        let mut state = Self {
            next_due: BTreeMap::new(),
            running: BTreeSet::new(),
        };
        state.sync(inputs, now);
        state
    }

    fn sync(&mut self, inputs: &[InputConfig], now: Instant) {
        let enabled = inputs
            .iter()
            .filter(|input| !input.disabled)
            .map(|input| input.name.as_str())
            .collect::<BTreeSet<_>>();
        self.next_due
            .retain(|name, _due| enabled.contains(name.as_str()));
        for name in enabled {
            self.next_due.entry(name.to_owned()).or_insert(now);
        }
    }

    fn take_due(
        &mut self,
        inputs: &[InputConfig],
        now: Instant,
        capacity: usize,
    ) -> Vec<InputConfig> {
        let available = capacity.saturating_sub(self.running.len());
        let due = inputs
            .iter()
            .filter(|input| !input.disabled)
            .filter(|input| !self.running.contains(&input.name))
            .filter(|input| {
                self.next_due
                    .get(&input.name)
                    .is_some_and(|due| *due <= now)
            })
            .take(available)
            .cloned()
            .collect::<Vec<_>>();
        self.running
            .extend(due.iter().map(|input| input.name.clone()));
        due
    }

    fn complete(&mut self, name: &str, now: Instant, interval: Option<std::time::Duration>) {
        self.running.remove(name);
        if let Some(interval) = interval {
            self.next_due.insert(name.to_owned(), now + interval);
        } else {
            self.next_due.remove(name);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;
    use std::path::PathBuf;
    use std::time::Duration;

    use super::*;

    fn input(name: &str) -> InputConfig {
        InputConfig {
            name: name.into(),
            disabled: false,
            connector: "postgres".into(),
            interval: Duration::from_mins(1),
            host: "database.example".into(),
            port: 5432,
            database: "events".into(),
            username: "reader".into(),
            secret_ref: format!("local:{name}"),
            tls_mode: "verify-full".into(),
            tls_server_name: Some("database.example".into()),
            tls_ca_file: Some(PathBuf::from("/ca.pem")),
            query: dbx_rs_config::QuerySource::File(PathBuf::from("/query.sql")),
            connect_timeout: Duration::from_secs(10),
            probe_timeout: Duration::from_secs(10),
            max_rows: 100,
            max_bytes: 1024,
            query_timeout: Duration::from_secs(30),
            index: "dbx_rs_test".into(),
            sourcetype: "dbx_rs:postgres:test".into(),
            source: "dbx_rs:test".into(),
        }
    }

    #[test]
    fn scheduler_respects_capacity_and_prevents_input_overlap() {
        let now = Instant::now();
        let inputs = vec![input("a"), input("b"), input("c")];
        let mut schedule = ScheduleState::new(&inputs, now);

        let first = schedule.take_due(&inputs, now, 2);
        assert_eq!(first.len(), 2);
        assert!(schedule.take_due(&inputs, now, 2).is_empty());
        schedule.complete("a", now, Some(Duration::from_mins(1)));
        let second = schedule.take_due(&inputs, now, 2);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].name, "c");
    }

    #[test]
    fn configured_worker_count_is_hard_capped_by_cpu_count() {
        let configured =
            dbx_rs_config::WorkerLimit::Fixed(NonZeroUsize::new(16).expect("sixteen is nonzero"));
        let cpus = NonZeroUsize::new(4).expect("four is nonzero");

        assert_eq!(configured.effective(cpus).get(), 4);
    }
}
