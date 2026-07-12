use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use dbx_rs_config::{EffectiveConfig, HecInputManagement, HecState, load_effective_config};
use dbx_rs_connector_sdk::{PrepareRequest, TimestampIdCursorRequest};
use dbx_rs_native_connectors::NativeConnectorProvider;
use dbx_rs_secure_store::{SecretStore, read_limited, write_new};
use dbx_rs_spool::{Spool, SpoolKey, SpoolLimits};
use dbx_rs_telemetry::{NdjsonTelemetry, OperationLimits, OperationMetrics, TelemetryConfig};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use ring::digest::{Context, SHA256};

use crate::error::DaemonError;
use crate::hec::HecClient;
use crate::identity::{HecToken, ensure_hec_certificate, generate_uuid};
use crate::lifecycle::{InstanceGuard, SplunkdIdentity, shutdown_signal};
use crate::operational::OperationTracker;
use crate::prepared::{PreparedInput, prepare_input};
use crate::rising::{
    RisingCoordinator, RisingPageContext, RisingReconcileOutcome, StartPageOutcome,
};
use crate::splunk::reconcile_managed_hec;
use crate::worker::{
    CollectionRun, DeliveryLimits, ReplayFences, WorkerCompletion, WorkerError, WorkerServices,
    deliver_ready_segment_sync, drain_ready_segments, run_input,
};

const STATE_ROOT_BINDING_RELATIVE_PATH: &str = "var/lib/splunk/dbx-rs/state-root.binding";
const STATE_ROOT_BINDING_MAGIC: &[u8; 16] = b"DBXRSSTATEPATH1\0";
const STATE_ROOT_BINDING_DOMAIN: &[u8] = b"dbx-rs/state-root-binding/v1\0";
const STATE_ROOT_BINDING_BYTES: usize = 48;
const STATE_ROOT_BINDING_BYTES_U64: u64 = 48;

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
    rising: Option<RisingPageContext>,
    handle: JoinHandle<Result<WorkerCompletion, WorkerError>>,
}

pub fn bootstrap(
    config: &EffectiveConfig,
    splunk_home: &Path,
) -> Result<BootstrapResult, DaemonError> {
    let _guard = InstanceGuard::acquire(&config.generic.paths.instance_lock_file)?;
    let _durable = preflight_durable_runtime(config, splunk_home)?;
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

// Keep the safety-critical reload, recovery, and collection ordering visible in one loop.
#[allow(clippy::too_many_lines)]
async fn run_inner(
    app_home: &Path,
    splunk_home: &Path,
    config: &mut EffectiveConfig,
    telemetry: NdjsonTelemetry,
) -> Result<(), DaemonError> {
    let _guard = InstanceGuard::acquire(&config.generic.paths.instance_lock_file)?;
    let splunkd = SplunkdIdentity::capture(&config.generic.paths.splunkd_pid_file)?;
    let (mut prepared_inputs, rising, spool) = preflight_durable_runtime(config, splunk_home)?;
    let prepared = prepare_runtime(config)?;
    let secrets = prepared.secrets;
    let mut hec = prepared.hec;
    let mut generations = ConfigurationGenerations::new(&prepared_inputs)?;
    let mut validated_rising = BTreeSet::<[u8; 16]>::new();
    let available_parallelism = available_parallelism()?;
    let cancellation = CancellationToken::new();
    let connectors = Arc::new(NativeConnectorProvider::new());
    let mut schedule = ScheduleState::new(&input_intervals(&prepared_inputs), Instant::now());
    let mut tasks = BTreeMap::<String, WorkerTask>::new();
    let mut next_reload = Instant::now() + config.generic.daemon.configuration_reload;
    let signal_cancellation = cancellation.clone();
    let mut signal = Some(tokio::spawn(async move {
        let result = shutdown_signal().await;
        signal_cancellation.cancel();
        result
    }));
    let mut signal_error = None;

    loop {
        finish_workers(
            &mut tasks,
            &mut schedule,
            &rising,
            &spool,
            &prepared_inputs,
            &telemetry,
        )
        .await;
        if !splunkd.is_current() {
            break;
        }

        let now = Instant::now();
        if now >= next_reload {
            if let Some((new_config, new_inputs)) =
                reload_configuration(app_home, splunk_home, config, &prepared_inputs, &telemetry)
            {
                apply_reload(
                    (new_config, new_inputs),
                    ReloadState {
                        config,
                        hec: &mut hec,
                        inputs: &mut prepared_inputs,
                        generations: &mut generations,
                        schedule: &mut schedule,
                        tasks: &mut tasks,
                        rising: &rising,
                        validated_rising: &mut validated_rising,
                        cancellation: &cancellation,
                    },
                    &spool,
                    &telemetry,
                    now,
                )
                .await?;
            }
            next_reload = now + config.generic.daemon.configuration_reload;
        }

        let backlog_drained = reconcile_and_drain_backlogs(
            BacklogContext {
                rising: &rising,
                spool: &spool,
                hec: hec.as_ref(),
                delivery_limits: configured_delivery_limits(config),
                inputs: &prepared_inputs,
                telemetry: &telemetry,
                cancellation: &cancellation,
            },
            &mut schedule,
            !tasks.is_empty(),
            now,
        )
        .await;
        launch_collection_wave(
            CollectionWaveContext {
                backlog_drained,
                capacity: configured_worker_capacity(config, available_parallelism),
                hec: hec.as_ref(),
                spool: &spool,
                connectors: &connectors,
                secrets: &secrets,
                telemetry: &telemetry,
                inputs: &prepared_inputs,
                generations: &generations,
                rising: &rising,
                cancellation: &cancellation,
            },
            &mut schedule,
            &mut validated_rising,
            &mut tasks,
        )
        .await;

        let signal_task = signal.as_mut().expect("signal task must remain active");
        tokio::select! {
            result = signal_task => {
                signal = None;
                signal_error = signal_failure(result);
                break;
            }
            () = tokio::time::sleep(config.generic.daemon.poll_interval) => {}
        }
    }

    cancellation.cancel();
    stop_workers(tasks, config.generic.daemon.shutdown_grace).await;
    if let Some(signal) = signal {
        signal.abort();
        let _ignored = signal.await;
    }
    if let Some(error) = signal_error {
        return Err(error);
    }
    Ok(())
}

fn preflight_durable_runtime(
    config: &EffectiveConfig,
    splunk_home: &Path,
) -> Result<(BTreeMap<String, PreparedInput>, RisingCoordinator, Spool), DaemonError> {
    bind_state_root(splunk_home, &config.generic.paths.state_dir)?;
    let prepared_inputs = prepare_inputs(config)?;
    let rising = RisingCoordinator::open(&config.generic.paths.state_dir)?;
    let spool = open_spool(config)?;
    rising.preflight_startup(&prepared_inputs, &spool)?;
    Ok((prepared_inputs, rising, spool))
}

fn signal_failure(
    result: Result<Result<(), DaemonError>, tokio::task::JoinError>,
) -> Option<DaemonError> {
    match result {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(error),
        Err(_) => Some(DaemonError::new(
            "DBX-RS-RUN-0016",
            "internal",
            "signal_handler",
            "shutdown signal task did not complete",
            false,
            false,
        )),
    }
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

fn prepare_inputs(
    config: &EffectiveConfig,
) -> Result<BTreeMap<String, PreparedInput>, DaemonError> {
    config
        .inputs
        .iter()
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
        .filter(|(_name, input)| !input.schedule.disabled)
        .map(|(name, input)| (name.clone(), input.schedule.interval))
        .collect()
}

fn runnable_intervals(
    inputs: &BTreeMap<String, PreparedInput>,
    needs_collection: &BTreeSet<String>,
) -> BTreeMap<String, std::time::Duration> {
    inputs
        .iter()
        .filter(|(name, input)| {
            !input.schedule.disabled || needs_collection.contains(name.as_str())
        })
        .map(|(name, input)| (name.clone(), input.schedule.interval))
        .collect()
}

struct RisingBacklogSummary {
    needs_collection: BTreeSet<String>,
    committed: BTreeSet<String>,
}

async fn reconcile_rising_backlog(
    coordinator: &RisingCoordinator,
    spool: &Spool,
    hec: Option<&HecClient>,
    limits: DeliveryLimits,
    inputs: &BTreeMap<String, PreparedInput>,
    telemetry: &NdjsonTelemetry,
    cancellation: &CancellationToken,
) -> Result<RisingBacklogSummary, ()> {
    let coordinator = coordinator.clone();
    let spool = spool.clone();
    let hec = hec.cloned();
    let inputs = inputs.clone();
    let telemetry = telemetry.clone();
    let task_telemetry = telemetry.clone();
    let cancellation = cancellation.clone();
    tokio::task::spawn_blocking(move || {
        reconcile_rising_backlog_sync(
            &coordinator,
            &spool,
            hec.as_ref(),
            limits,
            &inputs,
            &task_telemetry,
            &cancellation,
        )
    })
    .await
    .map_err(|_| {
        log_background_failure(
            &telemetry,
            "rising_reconcile",
            &rising_reconcile_task_error(),
        );
    })?
}

fn reconcile_rising_backlog_sync(
    coordinator: &RisingCoordinator,
    spool: &Spool,
    hec: Option<&HecClient>,
    limits: DeliveryLimits,
    inputs: &BTreeMap<String, PreparedInput>,
    telemetry: &NdjsonTelemetry,
    cancellation: &CancellationToken,
) -> Result<RisingBacklogSummary, ()> {
    let mut summary = RisingBacklogSummary {
        needs_collection: BTreeSet::new(),
        committed: BTreeSet::new(),
    };
    for (name, input) in inputs
        .iter()
        .filter(|(_name, input)| input.rising.is_some())
    {
        let mut delivery_failure_logged = false;
        let result = coordinator.reconcile(input, spool, |ready| {
            let client = hec.ok_or_else(rising_delivery_unavailable)?;
            match deliver_rising_segment(
                spool,
                ready,
                client,
                limits,
                input,
                telemetry,
                cancellation,
            ) {
                Ok(delivered) => Ok(delivered),
                Err(error) => {
                    delivery_failure_logged = true;
                    Err(error)
                }
            }
        });
        match result {
            Ok(RisingReconcileOutcome::Idle { .. }) => {}
            Ok(RisingReconcileOutcome::NeedsCollection { .. }) => {
                summary.needs_collection.insert(name.clone());
            }
            Ok(RisingReconcileOutcome::Committed { .. }) => {
                summary.committed.insert(name.clone());
            }
            Err(error) => {
                if !delivery_failure_logged {
                    log_background_input_failure(
                        telemetry,
                        &input.connector,
                        "rising_reconcile",
                        name,
                        &error,
                    );
                }
                return Err(());
            }
        }
    }
    Ok(summary)
}

fn deliver_rising_segment(
    spool: &Spool,
    ready: &dbx_rs_spool::ReadySegment,
    hec: &HecClient,
    limits: DeliveryLimits,
    input: &PreparedInput,
    telemetry: &NdjsonTelemetry,
    cancellation: &CancellationToken,
) -> Result<dbx_rs_spool::DeliveredSegment, DaemonError> {
    let request_id = generate_uuid()?;
    let tracker = OperationTracker::start(
        telemetry,
        &input.connector,
        "spool_replay",
        &request_id,
        "local",
        Some(&input.name),
        OperationLimits::default().with_max_bytes(limits.max_bytes),
    )?;
    let rows = ready.summary().event_count;
    let bytes = ready.summary().plaintext_bytes;
    match deliver_ready_segment_sync(spool, ready, hec, limits, cancellation) {
        Ok(delivered) => {
            tracker.succeeded(OperationMetrics::collection(rows, bytes, true))?;
            Ok(delivered)
        }
        Err(error) => {
            tracker.failed_daemon(&error);
            Err(error)
        }
    }
}

const fn rising_reconcile_task_error() -> DaemonError {
    DaemonError::new(
        "DBX-RS-RUN-0014",
        "internal",
        "rising_reconcile",
        "rising recovery task did not complete",
        true,
        false,
    )
}

const fn rising_delivery_unavailable() -> DaemonError {
    DaemonError::new(
        "DBX-RS-RUN-0010",
        "configuration",
        "rising_delivery",
        "rising spool data cannot be delivered while HEC output is disabled",
        false,
        true,
    )
}

async fn drain_spool_backlog(
    spool: &Spool,
    hec: Option<&HecClient>,
    limits: DeliveryLimits,
    inputs: &BTreeMap<String, PreparedInput>,
    telemetry: &NdjsonTelemetry,
    cancellation: &CancellationToken,
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

    match drain_ready_segments(
        spool.clone(),
        hec.cloned(),
        limits,
        replay_fences(inputs),
        rising_input_keys(inputs),
        cancellation.clone(),
    )
    .await
    {
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
        .filter(|input| input.rising.is_none())
        .map(|input| {
            (
                dbx_rs_spool::InputKey::new(input.input_id.into_bytes()),
                dbx_rs_spool::Fingerprint::new(input.revision_fingerprint.into_bytes()),
            )
        })
        .collect()
}

fn rising_input_keys(inputs: &BTreeMap<String, PreparedInput>) -> BTreeSet<dbx_rs_spool::InputKey> {
    inputs
        .values()
        .filter(|input| input.rising.is_some())
        .map(|input| dbx_rs_spool::InputKey::new(input.input_id.into_bytes()))
        .collect()
}

const fn collection_wave_may_start(active_workers: usize, backlog_drained: Option<bool>) -> bool {
    active_workers == 0 && matches!(backlog_drained, Some(true))
}

struct BacklogContext<'a> {
    rising: &'a RisingCoordinator,
    spool: &'a Spool,
    hec: Option<&'a HecClient>,
    delivery_limits: DeliveryLimits,
    inputs: &'a BTreeMap<String, PreparedInput>,
    telemetry: &'a NdjsonTelemetry,
    cancellation: &'a CancellationToken,
}

async fn reconcile_and_drain_backlogs(
    context: BacklogContext<'_>,
    schedule: &mut ScheduleState,
    workers_active: bool,
    now: Instant,
) -> Option<bool> {
    if workers_active {
        return None;
    }
    let Ok(summary) = reconcile_rising_backlog(
        context.rising,
        context.spool,
        context.hec,
        context.delivery_limits,
        context.inputs,
        context.telemetry,
        context.cancellation,
    )
    .await
    else {
        return Some(false);
    };
    for name in &summary.committed {
        let input = context
            .inputs
            .get(name)
            .expect("committed rising input must remain prepared");
        schedule.complete(
            name,
            now,
            (!input.schedule.disabled).then_some(input.schedule.interval),
        );
    }
    schedule.sync(
        &runnable_intervals(context.inputs, &summary.needs_collection),
        now,
    );
    Some(
        drain_spool_backlog(
            context.spool,
            context.hec,
            context.delivery_limits,
            context.inputs,
            context.telemetry,
            context.cancellation,
        )
        .await,
    )
}

struct WorkerLaunchContext<'a> {
    inputs: &'a BTreeMap<String, PreparedInput>,
    generations: &'a ConfigurationGenerations,
    rising: &'a RisingCoordinator,
    cancellation: &'a CancellationToken,
    services: &'a WorkerServices,
}

struct CollectionWaveContext<'a> {
    backlog_drained: Option<bool>,
    capacity: usize,
    hec: Option<&'a HecClient>,
    spool: &'a Spool,
    connectors: &'a Arc<NativeConnectorProvider>,
    secrets: &'a Arc<SecretStore>,
    telemetry: &'a NdjsonTelemetry,
    inputs: &'a BTreeMap<String, PreparedInput>,
    generations: &'a ConfigurationGenerations,
    rising: &'a RisingCoordinator,
    cancellation: &'a CancellationToken,
}

async fn launch_collection_wave(
    context: CollectionWaveContext<'_>,
    schedule: &mut ScheduleState,
    validated_rising: &mut BTreeSet<[u8; 16]>,
    tasks: &mut BTreeMap<String, WorkerTask>,
) {
    if context.cancellation.is_cancelled()
        || !collection_wave_may_start(tasks.len(), context.backlog_drained)
    {
        return;
    }
    let Some(hec) = context.hec else {
        return;
    };
    let services = WorkerServices {
        spool: context.spool.clone(),
        hec: hec.clone(),
        connectors: Arc::clone(context.connectors),
        secrets: Arc::clone(context.secrets),
        telemetry: context.telemetry.clone(),
    };
    spawn_due_workers(
        schedule,
        validated_rising,
        context.capacity,
        tasks,
        WorkerLaunchContext {
            inputs: context.inputs,
            generations: context.generations,
            rising: context.rising,
            cancellation: context.cancellation,
            services: &services,
        },
    )
    .await;
}

async fn spawn_due_workers(
    schedule: &mut ScheduleState,
    validated_rising: &mut BTreeSet<[u8; 16]>,
    capacity: usize,
    tasks: &mut BTreeMap<String, WorkerTask>,
    context: WorkerLaunchContext<'_>,
) {
    for name in schedule.take_due(Instant::now(), capacity) {
        let input = context
            .inputs
            .get(&name)
            .expect("scheduled prepared input must exist")
            .clone();
        let interval = input.schedule.interval;
        let (run, rising_context) = if let Some(prepared_rising) = &input.rising {
            if !validated_rising.contains(&prepared_rising.state_input_id) {
                if let Err(error) =
                    prepare_rising_contract(&input, context.services, context.cancellation).await
                {
                    log_background_failure(&context.services.telemetry, "rising_prepare", &error);
                    schedule.complete(&name, Instant::now(), Some(interval));
                    continue;
                }
                validated_rising.insert(prepared_rising.state_input_id);
            }
            let page_context = match context
                .rising
                .start_or_resume_page(&input, &context.services.spool)
            {
                Ok(StartPageOutcome::Ready(page_context)) => *page_context,
                Ok(StartPageOutcome::AwaitingReconcile) => {
                    schedule.complete(&name, Instant::now(), Some(std::time::Duration::ZERO));
                    continue;
                }
                Err(error) => {
                    log_background_failure(&context.services.telemetry, "rising_start", &error);
                    schedule.complete(&name, Instant::now(), Some(interval));
                    continue;
                }
            };
            (
                CollectionRun::Rising {
                    configuration_generation: page_context.configuration_generation,
                    checkpoint_generation: page_context.checkpoint_generation,
                    attempt_id: page_context.attempt_id,
                    page: page_context.page,
                    cursor: page_context.cursor_request.clone(),
                },
                Some(page_context),
            )
        } else {
            let configuration_generation = match context.generations.generation(&name) {
                Ok(generation) => generation,
                Err(error) => {
                    log_background_failure(&context.services.telemetry, "batch_start", &error);
                    schedule.complete(&name, Instant::now(), Some(interval));
                    continue;
                }
            };
            (
                CollectionRun::Batch {
                    configuration_generation,
                },
                None,
            )
        };
        let worker_cancellation = context.cancellation.child_token();
        let task_cancellation = worker_cancellation.clone();
        let worker_services = WorkerServices::clone(context.services);
        let handle = tokio::spawn(run_input(input, run, worker_services, worker_cancellation));
        tasks.insert(
            name,
            WorkerTask {
                cancellation: task_cancellation,
                interval,
                rising: rising_context,
                handle,
            },
        );
    }
}

async fn prepare_rising_contract(
    input: &PreparedInput,
    services: &WorkerServices,
    cancellation: &CancellationToken,
) -> Result<(), DaemonError> {
    let rising = input.rising.as_ref().ok_or_else(rising_prepare_error)?;
    let request_id = generate_uuid()?;
    let secret = services.secrets.resolve(&input.secret_ref)?;
    services
        .connectors
        .prepare(
            PrepareRequest {
                request_id,
                connection: input.connection.clone(),
                query: input.query.clone(),
                max_rows: input.limits.max_rows,
                timeout: input.limits.query_timeout,
                cursor: Some(TimestampIdCursorRequest {
                    spec: rising.cursor_spec.clone(),
                    committed: None,
                    resume_after: None,
                }),
            },
            &secret,
            cancellation.child_token(),
        )
        .await
        .map(|_prepared| ())
        .map_err(|_error| rising_prepare_error())
}

const fn rising_prepare_error() -> DaemonError {
    DaemonError::new(
        "DBX-RS-RUN-0012",
        "connector",
        "rising_prepare",
        "rising query and cursor contract could not be prepared",
        true,
        false,
    )
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
    rising: &'a RisingCoordinator,
    validated_rising: &'a mut BTreeSet<[u8; 16]>,
    cancellation: &'a CancellationToken,
}

async fn apply_reload(
    candidate: (EffectiveConfig, BTreeMap<String, PreparedInput>),
    state: ReloadState<'_>,
    spool: &Spool,
    telemetry: &NdjsonTelemetry,
    now: Instant,
) -> Result<(), DaemonError> {
    let (new_config, new_inputs) = candidate;
    if let Err(error) = validate_reload_input_identities(state.inputs, &new_inputs) {
        log_reload_failure(telemetry, &error);
        return Ok(());
    }
    if let Err(error) = state.rising.validate_configured_identities(&new_inputs) {
        log_reload_failure(telemetry, &error);
        return Ok(());
    }
    for input in new_inputs.values().filter(|input| input.rising.is_some()) {
        if let Err(error) = state.rising.validate_candidate_identity(input) {
            log_reload_failure(telemetry, &error);
            return Ok(());
        }
    }
    stop_workers_for_reload(
        state.tasks,
        state.schedule,
        state.config.generic.daemon.shutdown_grace,
    )
    .await;
    let old_delivery = configured_delivery_limits(state.config);
    let Ok(rising_backlog) = reconcile_rising_backlog(
        state.rising,
        spool,
        state.hec.as_ref(),
        old_delivery,
        state.inputs,
        telemetry,
        state.cancellation,
    )
    .await
    else {
        return Ok(());
    };
    if !rising_backlog.needs_collection.is_empty() {
        log_reload_failure(telemetry, &reload_active_rising_error());
        return Ok(());
    }
    if !drain_spool_backlog(
        spool,
        state.hec.as_ref(),
        old_delivery,
        state.inputs,
        telemetry,
        state.cancellation,
    )
    .await
    {
        return Ok(());
    }

    let mut new_generations = state.generations.clone();
    new_generations.activate(&new_inputs)?;
    let new_hec = match prepare_hec(&new_config) {
        Ok((hec, _bootstrap)) => hec,
        Err(error) => {
            log_reload_failure(telemetry, &error);
            return Ok(());
        }
    };
    *state.config = new_config;
    *state.hec = new_hec;
    *state.inputs = new_inputs;
    *state.generations = new_generations;
    state.validated_rising.clear();
    state.schedule.sync(
        &runnable_intervals(state.inputs, &rising_backlog.needs_collection),
        now,
    );
    log_reload_success(telemetry);
    Ok(())
}

fn validate_reload_input_identities(
    current: &BTreeMap<String, PreparedInput>,
    candidate: &BTreeMap<String, PreparedInput>,
) -> Result<(), DaemonError> {
    for (name, current_input) in current {
        let Some(candidate_input) = candidate.get(name) else {
            continue;
        };
        let current_identity = current_input
            .rising
            .as_ref()
            .map(|rising| rising.state_input_id);
        let candidate_identity = candidate_input
            .rising
            .as_ref()
            .map(|rising| rising.state_input_id);
        if current_identity != candidate_identity {
            return Err(reload_input_identity_error());
        }
    }
    Ok(())
}

const fn reload_input_identity_error() -> DaemonError {
    DaemonError::new(
        "DBX-RS-RUN-0018",
        "configuration",
        "config_reload",
        "collection mode and rising identity changes require explicit migration",
        false,
        true,
    )
}

const fn reload_active_rising_error() -> DaemonError {
    DaemonError::new(
        "DBX-RS-RUN-0011",
        "configuration",
        "config_reload",
        "configuration reload is blocked until the active rising scan completes",
        true,
        true,
    )
}

fn reload_configuration(
    app_home: &Path,
    splunk_home: &Path,
    current: &EffectiveConfig,
    current_inputs: &BTreeMap<String, PreparedInput>,
    telemetry: &NdjsonTelemetry,
) -> Option<(EffectiveConfig, BTreeMap<String, PreparedInput>)> {
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
    if candidate.generic.hec != current.generic.hec && candidate.inputs != current.inputs {
        log_reload_failure(telemetry, &combined_hec_input_reload_error());
        return None;
    }
    let candidate_inputs = match prepare_inputs(&candidate) {
        Ok(inputs) => inputs,
        Err(error) => {
            log_reload_failure(telemetry, &error);
            return None;
        }
    };
    if candidate == *current && candidate_inputs == *current_inputs {
        return None;
    }
    Some((candidate, candidate_inputs))
}

const fn combined_hec_input_reload_error() -> DaemonError {
    DaemonError::new(
        "DBX-RS-RUN-0015",
        "configuration",
        "config_reload",
        "HEC and database input changes must be activated in separate reloads",
        false,
        true,
    )
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

fn log_background_input_failure(
    telemetry: &NdjsonTelemetry,
    connector: &str,
    operation: &'static str,
    input: &str,
    error: &DaemonError,
) {
    if let Ok(request_id) = generate_uuid()
        && let Ok(tracker) = OperationTracker::start(
            telemetry,
            connector,
            operation,
            &request_id,
            "local",
            Some(input),
            OperationLimits::default(),
        )
    {
        tracker.failed_daemon(error);
    }
}

async fn finish_workers(
    tasks: &mut BTreeMap<String, WorkerTask>,
    schedule: &mut ScheduleState,
    rising: &RisingCoordinator,
    spool: &Spool,
    inputs: &BTreeMap<String, PreparedInput>,
    telemetry: &NdjsonTelemetry,
) {
    let finished = tasks
        .iter()
        .filter_map(|(name, task)| task.handle.is_finished().then_some(name.clone()))
        .collect::<Vec<_>>();
    for name in finished {
        if let Some(task) = tasks.remove(&name) {
            let interval = task.interval;
            let result = task.handle.await;
            let rising_success = match (task.rising.as_ref(), result) {
                (None, Ok(Ok(WorkerCompletion::Batch(_collection)))) => false,
                (
                    None,
                    Ok(Ok(WorkerCompletion::RisingSealed(_) | WorkerCompletion::RisingEmpty(_))),
                )
                | (Some(_), Ok(Ok(WorkerCompletion::Batch(_)))) => {
                    log_background_failure(telemetry, "worker_finish", &worker_result_error());
                    false
                }
                (Some(_context), Ok(Ok(WorkerCompletion::RisingSealed(_collection)))) => true,
                (Some(context), Ok(Ok(WorkerCompletion::RisingEmpty(collection)))) => {
                    let input = inputs
                        .get(&name)
                        .expect("finished rising input must remain prepared");
                    match rising.record_empty_completion(input, context, &collection, spool) {
                        Ok(()) => true,
                        Err(error) => {
                            log_background_failure(telemetry, "rising_empty", &error);
                            false
                        }
                    }
                }
                (_, Ok(Err(_))) => false,
                (_, Err(_)) => {
                    let error = worker_join_error();
                    if let Some(input) = inputs.get(&name) {
                        log_background_input_failure(
                            telemetry,
                            &input.connector,
                            "worker_finish",
                            &name,
                            &error,
                        );
                    } else {
                        log_background_failure(telemetry, "worker_finish", &error);
                    }
                    false
                }
            };
            if task.rising.is_some() && rising_success {
                schedule.complete(&name, Instant::now(), None);
            } else {
                schedule.complete(&name, Instant::now(), Some(interval));
            }
        }
    }
}

const fn worker_result_error() -> DaemonError {
    DaemonError::new(
        "DBX-RS-RUN-0013",
        "internal",
        "worker_finish",
        "worker completion did not match its scheduled collection mode",
        false,
        false,
    )
}

const fn worker_join_error() -> DaemonError {
    DaemonError::new(
        "DBX-RS-RUN-0017",
        "internal",
        "worker_finish",
        "worker task did not complete normally",
        false,
        false,
    )
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

fn bind_state_root(splunk_home: &Path, state_root: &Path) -> Result<(), DaemonError> {
    let binding_path = splunk_home.join(STATE_ROOT_BINDING_RELATIVE_PATH);
    let expected = state_root_binding(state_root)?;
    match fs::symlink_metadata(&binding_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len() != STATE_ROOT_BINDING_BYTES_U64
                || binding_permissions_are_broad(&metadata)
            {
                return Err(state_root_binding_error());
            }
            let actual = read_limited(&binding_path, STATE_ROOT_BINDING_BYTES_U64)?;
            if actual != expected {
                return Err(state_root_binding_error());
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_new(&binding_path, &expected, 0o600)?;
            Ok(())
        }
        Err(error) => Err(DaemonError::io(
            "DBX-RS-RUN-0019",
            "state_root_binding",
            "failed to inspect the durable state-root binding",
            &error,
        )),
    }
}

fn state_root_binding(state_root: &Path) -> Result<Vec<u8>, DaemonError> {
    let path = state_root.to_str().ok_or_else(state_root_binding_error)?;
    let mut context = Context::new(&SHA256);
    context.update(STATE_ROOT_BINDING_DOMAIN);
    context.update(path.as_bytes());
    let mut binding = Vec::with_capacity(STATE_ROOT_BINDING_BYTES);
    binding.extend_from_slice(STATE_ROOT_BINDING_MAGIC);
    binding.extend_from_slice(context.finish().as_ref());
    Ok(binding)
}

#[cfg(unix)]
fn binding_permissions_are_broad(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o077 != 0
}

#[cfg(not(unix))]
const fn binding_permissions_are_broad(_metadata: &fs::Metadata) -> bool {
    false
}

const fn state_root_binding_error() -> DaemonError {
    DaemonError::new(
        "DBX-RS-RUN-0019",
        "configuration",
        "state_root_binding",
        "durable state root does not match the installation binding",
        false,
        true,
    )
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

    fn take_due(&mut self, now: Instant, capacity: usize) -> Vec<String> {
        let available = capacity.saturating_sub(self.running.len());
        let mut due = self
            .next_due
            .iter()
            .filter(|(name, due)| !self.running.contains(*name) && **due <= now)
            .map(|(name, due)| (name.clone(), *due))
            .collect::<Vec<_>>();
        due.sort_unstable_by(|(left_name, left_due), (right_name, right_due)| {
            left_due
                .cmp(right_due)
                .then_with(|| left_name.cmp(right_name))
        });
        let due = due
            .into_iter()
            .take(available)
            .map(|(name, _due)| name)
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

#[derive(Clone, Default)]
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
            .filter(|(_name, input)| input.rising.is_none())
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
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Duration;

    use dbx_rs_config::{
        CollectionMode, HecConfig, IndexerAcknowledgment, InputConfig, QuerySource, TlsVerification,
    };
    use dbx_rs_connector_sdk::{CursorNullPolicy, TimestampIdCursorSpec};

    use super::*;

    static NEXT_RUNTIME_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn runtime_directory(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "dbx-rs-runtime-{label}-{}-{}",
            std::process::id(),
            NEXT_RUNTIME_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ))
    }
    use crate::prepared::PreparedRising;

    fn inputs(names: &[&str]) -> BTreeMap<String, Duration> {
        names
            .iter()
            .map(|name| ((*name).to_owned(), Duration::from_mins(1)))
            .collect()
    }

    fn prepared_input(name: &str, rising_identity: Option<[u8; 16]>) -> PreparedInput {
        let configured = InputConfig {
            name: name.into(),
            disabled: false,
            mode: CollectionMode::Batch,
            connector: "postgres".into(),
            interval: Duration::from_mins(1),
            host: "database.example".into(),
            port: 5432,
            database: "database".into(),
            username: "dbx_reader".into(),
            secret_ref: "local:database".into(),
            tls_mode: "disable".into(),
            tls_server_name: None,
            tls_ca_file: None,
            query: QuerySource::Inline("SELECT 1 AS value".into()),
            connect_timeout: Duration::from_secs(10),
            probe_timeout: Duration::from_secs(10),
            max_rows: 100,
            max_bytes: 65_536,
            query_timeout: Duration::from_secs(30),
            index: "dbx_rs_test".into(),
            sourcetype: "dbx_rs:test".into(),
            source: "dbx_rs:test".into(),
        };
        let hec = HecConfig {
            state: HecState::Disabled,
            input_management: HecInputManagement::External,
            url: "https://localhost:8088/services/collector/event".into(),
            input_name: "dbx_rs".into(),
            listen_port: 8088,
            accept_from: "127.0.0.1,::1".into(),
            tls_verification: TlsVerification::Full,
            timeout: Duration::from_secs(15),
            batch_max_events: 250,
            batch_max_bytes: 1_000_000,
            max_event_bytes: 900_000,
            index: "dbx_rs_test".into(),
            sourcetype: "dbx_rs:database:row".into(),
            source: "dbx_rs:daemon".into(),
            acknowledgment: IndexerAcknowledgment::Enabled,
        };
        let mut prepared = prepare_input(&configured, &hec).expect("test input must prepare");
        if let Some(state_input_id) = rising_identity {
            prepared.rising = Some(PreparedRising {
                state_input_id,
                cursor_spec: TimestampIdCursorSpec {
                    timestamp_field: "dbx_cursor_time".into(),
                    id_field: "dbx_cursor_id".into(),
                    overlap: Duration::ZERO,
                    null_policy: CursorNullPolicy::Reject,
                },
                cursor_identity_fingerprint: prepared.revision_fingerprint,
            });
        }
        prepared
    }

    fn prepared_inputs(input: PreparedInput) -> BTreeMap<String, PreparedInput> {
        BTreeMap::from([(input.name.clone(), input)])
    }

    #[test]
    fn scheduler_respects_capacity_and_prevents_input_overlap() {
        let now = Instant::now();
        let inputs = inputs(&["a", "b", "c"]);
        let mut schedule = ScheduleState::new(&inputs, now);

        let first = schedule.take_due(now, 2);
        assert_eq!(first.len(), 2);
        assert!(schedule.take_due(now, 2).is_empty());
        schedule.complete("a", now, Some(Duration::from_mins(1)));
        let second = schedule.take_due(now, 2);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0], "c");
    }

    #[test]
    fn scheduler_runs_older_due_input_before_immediate_rising_continuation() {
        let first_due = Instant::now();
        let later = first_due + Duration::from_secs(1);
        let intervals = inputs(&["a_truncated", "z_waiting"]);
        let mut schedule = ScheduleState::new(&intervals, first_due);

        assert_eq!(schedule.take_due(first_due, 1), ["a_truncated"]);
        schedule.complete("a_truncated", later, None);
        schedule.sync(&intervals, later);

        assert_eq!(schedule.take_due(later, 1), ["z_waiting"]);
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

    #[test]
    fn state_root_binding_is_stable_and_rejects_relocation() {
        let splunk_home = runtime_directory("state-root-binding");
        let state_root = splunk_home.join("var/lib/splunk/dbx-rs/state");
        bind_state_root(&splunk_home, &state_root).expect("first root must bind");
        let binding_path = splunk_home.join(STATE_ROOT_BINDING_RELATIVE_PATH);
        let original = fs::read(&binding_path).expect("binding must be readable");
        assert_eq!(original.len(), STATE_ROOT_BINDING_BYTES);
        bind_state_root(&splunk_home, &state_root).expect("same root must remain valid");

        let error = bind_state_root(
            &splunk_home,
            &splunk_home.join("var/lib/splunk/dbx-rs/replacement-state"),
        )
        .expect_err("state-root relocation must fail closed");
        assert_eq!(error.code(), "DBX-RS-RUN-0019");
        assert_eq!(
            fs::read(&binding_path).expect("failed relocation must preserve binding"),
            original
        );
        fs::remove_dir_all(splunk_home).expect("fixture must be removed");
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
            Err(WorkerError::Daemon(worker_result_error()))
        });
        let second_wait = second.clone();
        let second_handle = tokio::spawn(async move {
            second_wait.cancelled().await;
            Err(WorkerError::Daemon(worker_result_error()))
        });
        let interval = Duration::from_secs(1);
        let tasks = BTreeMap::from([
            (
                "a".into(),
                WorkerTask {
                    cancellation: first,
                    interval,
                    rising: None,
                    handle: first_handle,
                },
            ),
            (
                "b".into(),
                WorkerTask {
                    cancellation: second,
                    interval,
                    rising: None,
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

    #[test]
    fn reload_preserves_same_stanza_rising_identity() {
        let identity = [0x11; 16];
        let current = prepared_inputs(prepared_input("heartbeat", Some(identity)));
        let candidate = prepared_inputs(prepared_input("heartbeat", Some(identity)));

        validate_reload_input_identities(&current, &candidate)
            .expect("an unchanged rising identity must remain reloadable");
    }

    #[test]
    fn reload_rejects_same_stanza_rising_identity_replacement() {
        let current = prepared_inputs(prepared_input("heartbeat", Some([0x11; 16])));
        let candidate = prepared_inputs(prepared_input("heartbeat", Some([0x22; 16])));

        let error = validate_reload_input_identities(&current, &candidate)
            .expect_err("a same-stanza rising identity replacement must fail closed");

        assert_eq!(error.code(), "DBX-RS-RUN-0018");
        assert_eq!(error.stage(), "config_reload");
        assert!(error.configuration_error());
    }

    #[test]
    fn reload_rejects_same_stanza_collection_mode_changes() {
        for (current_identity, candidate_identity) in
            [(None, Some([0x11; 16])), (Some([0x11; 16]), None)]
        {
            let current = prepared_inputs(prepared_input("heartbeat", current_identity));
            let candidate = prepared_inputs(prepared_input("heartbeat", candidate_identity));

            let error = validate_reload_input_identities(&current, &candidate)
                .expect_err("a same-stanza collection-mode change must fail closed");

            assert_eq!(error.code(), "DBX-RS-RUN-0018");
        }
    }

    #[test]
    fn reload_allows_rising_stanza_rename_with_the_same_identity() {
        let identity = [0x11; 16];
        let current = prepared_inputs(prepared_input("old_name", Some(identity)));
        let candidate = prepared_inputs(prepared_input("new_name", Some(identity)));

        validate_reload_input_identities(&current, &candidate)
            .expect("the explicit rising identity must survive a stanza rename");
    }
}
