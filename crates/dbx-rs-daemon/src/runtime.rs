use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use dbx_rs_config::{EffectiveConfig, HecInputManagement, HecState, load_effective_config};
use dbx_rs_native_connectors::NativeConnectorProvider;
use dbx_rs_secure_store::SecretStore;
use dbx_rs_spool::{Spool, SpoolKey, SpoolLimits};
use dbx_rs_telemetry::{NdjsonTelemetry, OperationLimits, OperationMetrics, TelemetryConfig};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::error::DaemonError;
use crate::hec::HecClient;
use crate::identity::{HecToken, ensure_hec_certificate, generate_uuid};
use crate::lifecycle::{InstanceGuard, SplunkdIdentity, shutdown_signal};
use crate::operational::OperationTracker;
use crate::prepared::{PreparedInput, prepare_input};
use crate::splunk::reconcile_managed_hec;
use crate::worker::{
    DeliveryLimits, ReplayFences, WorkerServices, drain_ready_segments, run_input,
};

pub struct BootstrapResult {
    pub splunk_inputs_changed: bool,
    pub certificate_created: bool,
}

struct PreparedRuntime {
    secrets: Arc<SecretStore>,
    hec: Option<HecClient>,
    result: BootstrapResult,
}

struct WorkerTask {
    cancellation: CancellationToken,
    interval: std::time::Duration,
    handle: JoinHandle<()>,
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
    let spool = open_spool(config)?;
    let mut prepared_inputs = prepare_enabled_inputs(config)?;
    let mut generations = ConfigurationGenerations::new(&prepared_inputs)?;
    let available_parallelism = available_parallelism()?;
    let cancellation = CancellationToken::new();
    let connectors = Arc::new(NativeConnectorProvider::new());
    let mut schedule = ScheduleState::new(&input_intervals(&prepared_inputs), Instant::now());
    let mut tasks = BTreeMap::<String, WorkerTask>::new();
    let mut next_reload = Instant::now() + config.generic.daemon.configuration_reload;
    let mut signal = Box::pin(shutdown_signal());
    let mut signal_error = None;

    loop {
        finish_workers(&mut tasks, &mut schedule).await;
        if !splunkd.is_current() {
            break;
        }

        let now = Instant::now();
        if now >= next_reload {
            if let Some((new_config, new_hec, new_inputs)) =
                reload_configuration(app_home, splunk_home, config, &prepared_inputs, &telemetry)
            {
                apply_reload(
                    (new_config, new_hec, new_inputs),
                    ReloadState {
                        config,
                        hec: &mut hec,
                        inputs: &mut prepared_inputs,
                        generations: &mut generations,
                        schedule: &mut schedule,
                        tasks: &mut tasks,
                    },
                    &spool,
                    &telemetry,
                    now,
                )
                .await?;
            }
            next_reload = now + config.generic.daemon.configuration_reload;
        }

        let backlog_drained = if tasks.is_empty() {
            Some(
                drain_spool_backlog(
                    &spool,
                    hec.as_ref(),
                    configured_delivery_limits(config),
                    &prepared_inputs,
                    &telemetry,
                )
                .await,
            )
        } else {
            None
        };
        let capacity = configured_worker_capacity(config, available_parallelism);
        if collection_wave_may_start(tasks.len(), backlog_drained)
            && let Some(client) = &hec
        {
            let services = WorkerServices {
                spool: spool.clone(),
                hec: client.clone(),
                connectors: Arc::clone(&connectors),
                secrets: Arc::clone(&secrets),
                telemetry: telemetry.clone(),
            };
            spawn_due_workers(
                &mut schedule,
                &prepared_inputs,
                &generations,
                capacity,
                &cancellation,
                &mut tasks,
                &services,
            )?;
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

fn configured_spool_limits(config: &EffectiveConfig) -> Result<SpoolLimits, DaemonError> {
    SpoolLimits::new(
        config.generic.spool.segment_max_bytes,
        config.generic.spool.input_max_bytes,
        config.generic.spool.total_max_bytes,
    )
    .map_err(DaemonError::from)
}

fn open_spool(config: &EffectiveConfig) -> Result<Spool, DaemonError> {
    let limits = configured_spool_limits(config)?;
    let key = SpoolKey::load_or_create(&config.generic.paths.spool_key_file)?;
    Spool::open(&config.generic.paths.spool_dir, key, limits).map_err(DaemonError::from)
}

fn available_parallelism() -> Result<std::num::NonZeroUsize, DaemonError> {
    std::thread::available_parallelism().map_err(|error| {
        DaemonError::io(
            "DBX-RS-RUN-0001",
            "worker_capacity",
            "failed to determine available CPU parallelism",
            &error,
        )
    })
}

fn configured_worker_capacity(
    config: &EffectiveConfig,
    available_parallelism: std::num::NonZeroUsize,
) -> usize {
    config
        .generic
        .daemon
        .max_workers
        .effective(available_parallelism)
        .get()
}

const fn configured_delivery_limits(config: &EffectiveConfig) -> DeliveryLimits {
    DeliveryLimits {
        max_events: config.generic.hec.batch_max_events,
        max_bytes: config.generic.hec.batch_max_bytes,
    }
}

fn prepare_enabled_inputs(
    config: &EffectiveConfig,
) -> Result<BTreeMap<String, PreparedInput>, DaemonError> {
    config
        .inputs
        .iter()
        .filter(|input| !input.disabled)
        .map(|input| {
            prepare_input(input, &config.generic.hec)
                .map(|prepared| (prepared.name.clone(), prepared))
        })
        .collect()
}

fn input_intervals(
    inputs: &BTreeMap<String, PreparedInput>,
) -> BTreeMap<String, std::time::Duration> {
    inputs
        .iter()
        .map(|(name, input)| (name.clone(), input.schedule.interval))
        .collect()
}

async fn drain_spool_backlog(
    spool: &Spool,
    hec: Option<&HecClient>,
    limits: DeliveryLimits,
    inputs: &BTreeMap<String, PreparedInput>,
    telemetry: &NdjsonTelemetry,
) -> bool {
    let pending = match spool.list_ready() {
        Ok(ready) => ready,
        Err(error) => {
            let error = DaemonError::from(error);
            log_background_failure(telemetry, "spool_replay", &error);
            return false;
        }
    };
    let pending_bytes = pending.iter().try_fold(0_u64, |total, segment| {
        total.checked_add(segment.summary().plaintext_bytes)
    });
    let Some(pending_bytes) = pending_bytes else {
        let error = replay_accounting_error();
        log_background_failure(telemetry, "spool_replay", &error);
        return false;
    };
    let tracker = if pending.is_empty() {
        None
    } else {
        let Ok(request_id) = generate_uuid() else {
            return false;
        };
        match OperationTracker::start(
            telemetry,
            "host",
            "spool_replay",
            &request_id,
            "local",
            None,
            OperationLimits::default().with_max_bytes(limits.max_bytes),
        ) {
            Ok(tracker) => Some(tracker),
            Err(_) => return false,
        }
    };

    match drain_ready_segments(spool.clone(), hec.cloned(), limits, replay_fences(inputs)).await {
        Ok(rows) => tracker.is_none_or(|tracker| {
            tracker
                .succeeded(OperationMetrics::collection(rows, pending_bytes, true))
                .is_ok()
        }),
        Err(error) => {
            if let Some(tracker) = &tracker {
                tracker.failed_daemon(&error);
            } else {
                log_background_failure(telemetry, "spool_replay", &error);
            }
            false
        }
    }
}

const fn replay_accounting_error() -> DaemonError {
    DaemonError::new(
        "DBX-RS-RUN-0009",
        "internal",
        "spool_replay",
        "durable replay accounting overflowed",
        false,
        false,
    )
}

fn replay_fences(inputs: &BTreeMap<String, PreparedInput>) -> ReplayFences {
    inputs
        .values()
        .map(|input| {
            (
                dbx_rs_spool::InputKey::new(input.input_id.into_bytes()),
                dbx_rs_spool::Fingerprint::new(input.revision_fingerprint.into_bytes()),
            )
        })
        .collect()
}

const fn collection_wave_may_start(active_workers: usize, backlog_drained: Option<bool>) -> bool {
    active_workers == 0 && matches!(backlog_drained, Some(true))
}

fn spawn_due_workers(
    schedule: &mut ScheduleState,
    inputs: &BTreeMap<String, PreparedInput>,
    generations: &ConfigurationGenerations,
    capacity: usize,
    cancellation: &CancellationToken,
    tasks: &mut BTreeMap<String, WorkerTask>,
    services: &WorkerServices,
) -> Result<(), DaemonError> {
    let intervals = input_intervals(inputs);
    for name in schedule.take_due(&intervals, Instant::now(), capacity) {
        let input = inputs
            .get(&name)
            .expect("scheduled prepared input must exist")
            .clone();
        let configuration_generation = generations.generation(&name)?;
        let worker_cancellation = cancellation.child_token();
        let task_cancellation = worker_cancellation.clone();
        let worker_services = WorkerServices::clone(services);
        let interval = input.schedule.interval;
        let handle = tokio::spawn(async move {
            let _result = run_input(
                input,
                configuration_generation,
                worker_services,
                worker_cancellation,
            )
            .await;
        });
        tasks.insert(
            name,
            WorkerTask {
                cancellation: task_cancellation,
                interval,
                handle,
            },
        );
    }
    Ok(())
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

struct ReloadState<'a> {
    config: &'a mut EffectiveConfig,
    hec: &'a mut Option<HecClient>,
    inputs: &'a mut BTreeMap<String, PreparedInput>,
    generations: &'a mut ConfigurationGenerations,
    schedule: &'a mut ScheduleState,
    tasks: &'a mut BTreeMap<String, WorkerTask>,
}

async fn apply_reload(
    candidate: (
        EffectiveConfig,
        Option<HecClient>,
        BTreeMap<String, PreparedInput>,
    ),
    state: ReloadState<'_>,
    spool: &Spool,
    telemetry: &NdjsonTelemetry,
    now: Instant,
) -> Result<(), DaemonError> {
    let (new_config, new_hec, new_inputs) = candidate;
    stop_workers_for_reload(
        state.tasks,
        state.schedule,
        state.config.generic.daemon.shutdown_grace,
    )
    .await;
    let old_delivery = configured_delivery_limits(state.config);
    if !drain_spool_backlog(
        spool,
        state.hec.as_ref(),
        old_delivery,
        state.inputs,
        telemetry,
    )
    .await
    {
        return Ok(());
    }

    state.generations.activate(&new_inputs)?;
    *state.config = new_config;
    *state.hec = new_hec;
    *state.inputs = new_inputs;
    state.schedule.sync(&input_intervals(state.inputs), now);
    log_reload_success(telemetry);
    Ok(())
}

fn reload_configuration(
    app_home: &Path,
    splunk_home: &Path,
    current: &EffectiveConfig,
    current_inputs: &BTreeMap<String, PreparedInput>,
    telemetry: &NdjsonTelemetry,
) -> Option<(
    EffectiveConfig,
    Option<HecClient>,
    BTreeMap<String, PreparedInput>,
)> {
    let candidate = match load_effective_config(app_home, splunk_home) {
        Ok(candidate) => candidate,
        Err(error) => {
            log_reload_failure(telemetry, &DaemonError::from_config(&error));
            return None;
        }
    };
    if candidate.generic.paths != current.generic.paths
        || candidate.generic.logging != current.generic.logging
        || candidate.generic.spool != current.generic.spool
    {
        log_reload_failure(
            telemetry,
            &DaemonError::new(
                "DBX-RS-RUN-0003",
                "configuration",
                "config_reload",
                "path, logging, and spool-limit changes require a daemon restart",
                false,
                true,
            ),
        );
        return None;
    }
    let candidate_inputs = match prepare_enabled_inputs(&candidate) {
        Ok(inputs) => inputs,
        Err(error) => {
            log_reload_failure(telemetry, &error);
            return None;
        }
    };
    if candidate == *current && candidate_inputs == *current_inputs {
        return None;
    }
    match prepare_hec(&candidate) {
        Ok((hec, _result)) => Some((candidate, hec, candidate_inputs)),
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
    log_background_failure(telemetry, "config_reload", error);
}

fn log_background_failure(
    telemetry: &NdjsonTelemetry,
    operation: &'static str,
    error: &DaemonError,
) {
    if let Ok(request_id) = generate_uuid()
        && let Ok(tracker) = OperationTracker::start(
            telemetry,
            "host",
            operation,
            &request_id,
            "local",
            None,
            OperationLimits::default(),
        )
    {
        tracker.failed_daemon(error);
    }
}

async fn finish_workers(tasks: &mut BTreeMap<String, WorkerTask>, schedule: &mut ScheduleState) {
    let finished = tasks
        .iter()
        .filter_map(|(name, task)| task.handle.is_finished().then_some(name.clone()))
        .collect::<Vec<_>>();
    for name in finished {
        if let Some(task) = tasks.remove(&name) {
            let interval = task.interval;
            let _result = task.handle.await;
            schedule.complete(&name, Instant::now(), Some(interval));
        }
    }
}

async fn stop_workers(tasks: BTreeMap<String, WorkerTask>, grace: std::time::Duration) {
    let deadline = tokio::time::Instant::now() + grace;
    for task in tasks.values() {
        task.cancellation.cancel();
    }
    for (_name, mut task) in tasks {
        if tokio::time::timeout_at(deadline, &mut task.handle)
            .await
            .is_err()
        {
            task.handle.abort();
            let _result = task.handle.await;
        }
    }
}

async fn stop_workers_for_reload(
    tasks: &mut BTreeMap<String, WorkerTask>,
    schedule: &mut ScheduleState,
    grace: std::time::Duration,
) {
    let owned = std::mem::take(tasks);
    stop_workers(owned, grace).await;
    schedule.release_all();
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
    fn new(inputs: &BTreeMap<String, std::time::Duration>, now: Instant) -> Self {
        let mut state = Self {
            next_due: BTreeMap::new(),
            running: BTreeSet::new(),
        };
        state.sync(inputs, now);
        state
    }

    fn sync(&mut self, inputs: &BTreeMap<String, std::time::Duration>, now: Instant) {
        let enabled = inputs.keys().map(String::as_str).collect::<BTreeSet<_>>();
        self.next_due
            .retain(|name, _due| enabled.contains(name.as_str()));
        for name in enabled {
            self.next_due.entry(name.to_owned()).or_insert(now);
        }
    }

    fn take_due(
        &mut self,
        inputs: &BTreeMap<String, std::time::Duration>,
        now: Instant,
        capacity: usize,
    ) -> Vec<String> {
        let available = capacity.saturating_sub(self.running.len());
        let due = inputs
            .keys()
            .filter(|name| !self.running.contains(*name))
            .filter(|name| self.next_due.get(*name).is_some_and(|due| *due <= now))
            .take(available)
            .cloned()
            .collect::<Vec<_>>();
        self.running.extend(due.iter().cloned());
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

    fn release_all(&mut self) {
        self.running.clear();
    }
}

#[derive(Default)]
struct ConfigurationGenerations {
    high_water: BTreeMap<String, u64>,
    active: BTreeMap<String, ([u8; 32], u64)>,
}

impl ConfigurationGenerations {
    fn new(inputs: &BTreeMap<String, PreparedInput>) -> Result<Self, DaemonError> {
        let mut generations = Self::default();
        generations.activate(inputs)?;
        Ok(generations)
    }

    fn activate(&mut self, inputs: &BTreeMap<String, PreparedInput>) -> Result<(), DaemonError> {
        let revisions = inputs
            .iter()
            .map(|(name, input)| (name.clone(), input.revision_fingerprint.into_bytes()))
            .collect();
        self.activate_revisions(revisions)
    }

    fn activate_revisions(
        &mut self,
        revisions: BTreeMap<String, [u8; 32]>,
    ) -> Result<(), DaemonError> {
        let mut next_active = BTreeMap::new();
        for (name, revision) in revisions {
            let generation = match self.active.get(&name) {
                Some((active_revision, generation)) if *active_revision == revision => *generation,
                _ => self
                    .high_water
                    .get(&name)
                    .copied()
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or_else(configuration_generation_error)?,
            };
            self.high_water.insert(name.clone(), generation);
            next_active.insert(name, (revision, generation));
        }
        self.active = next_active;
        Ok(())
    }

    fn generation(&self, name: &str) -> Result<u64, DaemonError> {
        self.active
            .get(name)
            .map(|(_revision, generation)| *generation)
            .ok_or_else(configuration_generation_error)
    }
}

const fn configuration_generation_error() -> DaemonError {
    DaemonError::new(
        "DBX-RS-RUN-0008",
        "internal",
        "configuration_generation",
        "input configuration generation is unavailable",
        false,
        false,
    )
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use super::*;

    fn inputs(names: &[&str]) -> BTreeMap<String, Duration> {
        names
            .iter()
            .map(|name| ((*name).to_owned(), Duration::from_mins(1)))
            .collect()
    }

    #[test]
    fn scheduler_respects_capacity_and_prevents_input_overlap() {
        let now = Instant::now();
        let inputs = inputs(&["a", "b", "c"]);
        let mut schedule = ScheduleState::new(&inputs, now);

        let first = schedule.take_due(&inputs, now, 2);
        assert_eq!(first.len(), 2);
        assert!(schedule.take_due(&inputs, now, 2).is_empty());
        schedule.complete("a", now, Some(Duration::from_mins(1)));
        let second = schedule.take_due(&inputs, now, 2);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0], "c");
    }

    #[test]
    fn configured_worker_count_is_hard_capped_by_cpu_count() {
        let configured =
            dbx_rs_config::WorkerLimit::Fixed(NonZeroUsize::new(16).expect("sixteen is nonzero"));
        let cpus = NonZeroUsize::new(4).expect("four is nonzero");

        assert_eq!(configured.effective(cpus).get(), 4);
    }

    #[test]
    fn collection_wave_requires_no_workers_and_a_drained_backlog() {
        assert!(collection_wave_may_start(0, Some(true)));
        assert!(!collection_wave_may_start(1, Some(true)));
        assert!(!collection_wave_may_start(0, Some(false)));
        assert!(!collection_wave_may_start(0, None));
    }

    #[tokio::test]
    async fn worker_shutdown_cancels_every_task_before_waiting() {
        let first = CancellationToken::new();
        let second = CancellationToken::new();
        let observed_peer_cancellation = Arc::new(AtomicBool::new(false));
        let first_wait = first.clone();
        let second_observed = second.clone();
        let observation = Arc::clone(&observed_peer_cancellation);
        let first_handle = tokio::spawn(async move {
            first_wait.cancelled().await;
            observation.store(second_observed.is_cancelled(), Ordering::SeqCst);
        });
        let second_wait = second.clone();
        let second_handle = tokio::spawn(async move {
            second_wait.cancelled().await;
        });
        let interval = Duration::from_secs(1);
        let tasks = BTreeMap::from([
            (
                "a".into(),
                WorkerTask {
                    cancellation: first,
                    interval,
                    handle: first_handle,
                },
            ),
            (
                "b".into(),
                WorkerTask {
                    cancellation: second,
                    interval,
                    handle: second_handle,
                },
            ),
        ]);

        stop_workers(tasks, Duration::from_secs(1)).await;

        assert!(observed_peer_cancellation.load(Ordering::SeqCst));
    }

    #[test]
    fn configuration_generation_rejects_aba_reuse() {
        let mut generations = ConfigurationGenerations::default();
        generations
            .activate_revisions(BTreeMap::from([("input".into(), [0x11; 32])]))
            .expect("first activation must work");
        assert_eq!(generations.generation("input").expect("active"), 1);

        generations
            .activate_revisions(BTreeMap::from([("input".into(), [0x22; 32])]))
            .expect("second activation must work");
        assert_eq!(generations.generation("input").expect("active"), 2);

        generations
            .activate_revisions(BTreeMap::from([("input".into(), [0x11; 32])]))
            .expect("third activation must work");
        assert_eq!(generations.generation("input").expect("active"), 3);
    }
}
