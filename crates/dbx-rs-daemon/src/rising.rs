//! Durable orchestration for scheduled timestamp-plus-ID rising inputs.
//!
//! This module is the sole daemon owner of rising checkpoint mutations. A non-empty page is
//! sealed before it is referenced by state, delivery receipts are persisted before compaction,
//! and the committed cursor advances only after every referenced page is durably delivered.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use dbx_rs_checkpoint::{
    AttemptFence, AttemptId, CollectionState, CommitOutcome, DeliveryState, Snapshot,
};
use dbx_rs_connector_sdk::{CollectionResult, TimestampIdCursor, TimestampIdCursorRequest};
use dbx_rs_spool::{
    BatchId, DeliveredSegment, Fingerprint as SpoolFingerprint, InputKey, ReadySegment,
    SegmentHeader, Spool,
};
use dbx_rs_state::{
    ActiveScan, DurableInputState, FileCheckpointStore, Fingerprint as StateFingerprint, InputId,
    LoadResult, MAX_SEGMENTS_PER_SCAN, SegmentRef, StateKey, StoredState, configuration_fence_id,
};

use crate::error::DaemonError;
use crate::identity::generate_uuid_bytes;
use crate::prepared::{PreparedInput, PreparedRising};
use crate::rising_metadata::{
    RisingMetadataError, RisingRecoveryMetadata, rising_request_fingerprint,
};

const INITIAL_CONFIGURATION_GENERATION: u64 = 1;
const INITIAL_CHECKPOINT_GENERATION: u64 = 0;
const ATTEMPT_ID_GENERATION_LIMIT: usize = 16;

/// Durable state and recovery owner for scheduled rising inputs.
#[derive(Clone)]
pub(crate) struct RisingCoordinator {
    store: Arc<FileCheckpointStore>,
}

impl std::fmt::Debug for RisingCoordinator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RisingCoordinator")
            .field("store", &self.store)
            .finish()
    }
}

/// Immutable worker fence for exactly one rising page.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RisingPageContext {
    pub configuration_generation: u64,
    pub checkpoint_generation: u64,
    pub attempt_id: AttemptId,
    pub page: u64,
    pub cursor_request: TimestampIdCursorRequest,
    input_key: InputKey,
    configuration_fingerprint: SpoolFingerprint,
}

impl RisingPageContext {
    /// Builds the exact durable spool header for this page.
    #[must_use]
    #[cfg(test)]
    pub(crate) const fn segment_header(&self, created_epoch_millis: u64) -> SegmentHeader {
        SegmentHeader {
            input_key: self.input_key,
            configuration_fingerprint: self.configuration_fingerprint,
            configuration_generation: self.configuration_generation,
            batch_id: BatchId::new(self.attempt_id.into_bytes()),
            batch_sequence: self.checkpoint_generation,
            segment_sequence: self.page,
            created_epoch_millis,
        }
    }
}

impl std::fmt::Debug for RisingPageContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RisingPageContext")
            .field("configuration_generation", &self.configuration_generation)
            .field("checkpoint_generation", &self.checkpoint_generation)
            .field("attempt_id", &self.attempt_id)
            .field("page", &self.page)
            .field("cursor_request", &self.cursor_request)
            .field("input_key", &"[REDACTED]")
            .field("configuration_fingerprint", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum StartPageOutcome {
    Ready(Box<RisingPageContext>),
    AwaitingReconcile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RisingReconcileOutcome {
    Idle {
        checkpoint_generation: u64,
    },
    NeedsCollection {
        checkpoint_generation: u64,
        next_page: u64,
    },
    Committed {
        checkpoint_generation: u64,
        cursor_advanced: bool,
    },
}

/// Redacted state summary used by runtime scheduling and tests.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct RisingStateStatus {
    pub configuration_generation: u64,
    pub checkpoint_generation: u64,
    pub committed: Option<TimestampIdCursor>,
    pub active: bool,
    pub next_page: Option<u64>,
    pub delivered_through_sequence: u64,
}

impl std::fmt::Debug for RisingStateStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RisingStateStatus")
            .field("configuration_generation", &self.configuration_generation)
            .field("checkpoint_generation", &self.checkpoint_generation)
            .field("committed", &self.committed.map(|_| "[CONFIGURED]"))
            .field("active", &self.active)
            .field("next_page", &self.next_page)
            .field(
                "delivered_through_sequence",
                &self.delivered_through_sequence,
            )
            .finish()
    }
}

impl RisingCoordinator {
    /// Opens the non-creating checkpoint store at an absolute private path.
    ///
    /// # Errors
    ///
    /// Returns a redacted storage error when the state root is unsafe or cannot be inspected.
    pub(crate) fn open(path: &Path) -> Result<Self, DaemonError> {
        FileCheckpointStore::open(path)
            .map(|store| Self {
                store: Arc::new(store),
            })
            .map_err(state_store_error)
    }

    /// Verifies that every persisted checkpoint owner remains present in effective configuration.
    ///
    /// New rising identities are permitted, and stanza names do not participate in ownership. A
    /// persisted identity cannot be removed or replaced until an explicit administrative
    /// retirement or migration boundary exists.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid stored state or a detached persisted identity.
    pub(crate) fn validate_configured_identities(
        &self,
        inputs: &BTreeMap<String, PreparedInput>,
    ) -> Result<(), DaemonError> {
        let configured = inputs
            .values()
            .filter_map(|input| input.rising.as_ref())
            .map(|rising| rising.state_input_id)
            .collect::<BTreeSet<_>>();
        let persisted = self.store.input_ids().map_err(state_store_error)?;
        if persisted
            .iter()
            .any(|identity| !configured.contains(&identity.into_bytes()))
        {
            return Err(detached_identity_error());
        }
        Ok(())
    }

    /// Validates and, when idle, activates every existing configured checkpoint before startup
    /// performs delivery-side effects.
    ///
    /// Missing state remains non-creating. Retained spool data without state and any active work
    /// fenced to a different prepared revision fail closed.
    ///
    /// # Errors
    ///
    /// Returns an error for detached identities, invalid state/spool inventory, immutable identity
    /// changes, or a revision change blocked by durable work.
    pub(crate) fn preflight_startup(
        &self,
        inputs: &BTreeMap<String, PreparedInput>,
        spool: &Spool,
    ) -> Result<(), DaemonError> {
        self.validate_configured_identities(inputs)?;
        for input in inputs.values().filter(|input| input.rising.is_some()) {
            let rising = require_rising(input)?;
            match self
                .store
                .load(state_key(rising))
                .map_err(state_store_error)?
            {
                LoadResult::Missing => {
                    if input_spool_is_nonempty(input, spool)? {
                        return Err(inventory_error(
                            "durable rising state is missing while retained spool data exists",
                        ));
                    }
                }
                LoadResult::Current(_) => {
                    self.ensure_input(input, spool)?;
                }
            }
        }
        Ok(())
    }

    /// Creates state for a new rising identity or validates/activates its prepared configuration.
    ///
    /// A source-lineage or cursor-identity change always fails closed. A non-identity revision may
    /// activate only while no attempt or spool data exists for this input.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-rising input, unsafe/corrupt state or spool data, an immutable
    /// identity change, or a revision activation blocked by retained work.
    pub(crate) fn ensure_input(
        &self,
        input: &PreparedInput,
        spool: &Spool,
    ) -> Result<RisingStateStatus, DaemonError> {
        let rising = require_rising(input)?;
        let key = state_key(rising);
        let state = match self.store.load(key).map_err(state_store_error)? {
            LoadResult::Missing => {
                if input_spool_is_nonempty(input, spool)? {
                    return Err(inventory_error(
                        "durable rising state is missing while retained spool data exists",
                    ));
                }
                self.store
                    .create(key, &initial_state(input, rising))
                    .map_err(state_store_error)?
            }
            LoadResult::Current(state) => {
                let mut state = *state;
                validate_prepared_identity(&state.value, input, rising)?;
                let prepared_revision = state_fingerprint(input.revision_fingerprint.into_bytes());
                if state.value.configuration_fingerprint != prepared_revision {
                    if state.value.active_scan.is_some()
                        || state.value.coordinator.active_attempt.is_some()
                        || input_spool_is_nonempty(input, spool)?
                    {
                        return Err(configuration_activation_error());
                    }
                    state = self
                        .store
                        .activate_configuration(key, state.token, prepared_revision)
                        .map_err(state_store_error)?;
                }
                state
            }
        };
        Ok(status(&state.value))
    }

    /// Returns the current validated state summary without creating or activating state.
    ///
    /// # Errors
    ///
    /// Returns an error when state is missing, corrupt, or inconsistent with the prepared input.
    #[cfg(test)]
    pub(crate) fn status(&self, input: &PreparedInput) -> Result<RisingStateStatus, DaemonError> {
        let rising = require_rising(input)?;
        let state = self.load_current(input, rising)?;
        Ok(status(&state.value))
    }

    /// Validates a reload candidate's immutable identities without creating or changing state.
    ///
    /// A missing state is valid for preflight. Operational revision differences are deliberately
    /// ignored here and are activated only after old work is quiesced and reconciled.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid state or a source-lineage/cursor-identity change.
    pub(crate) fn validate_candidate_identity(
        &self,
        input: &PreparedInput,
    ) -> Result<(), DaemonError> {
        let rising = require_rising(input)?;
        match self
            .store
            .load(state_key(rising))
            .map_err(state_store_error)?
        {
            LoadResult::Missing => Ok(()),
            LoadResult::Current(state) => validate_prepared_identity(&state.value, input, rising),
        }
    }

    /// Starts a durable attempt or returns the next restart-safe page context.
    ///
    /// Retained ready/delivered work must be reconciled first. This prevents a worker from
    /// collecting a duplicate page while a seal-before-state or delivery crash is pending.
    ///
    /// # Errors
    ///
    /// Returns an error for state/spool corruption, stale ownership, invalid cursor bounds, or
    /// failed durable transitions.
    pub(crate) fn start_or_resume_page(
        &self,
        input: &PreparedInput,
        spool: &Spool,
    ) -> Result<StartPageOutcome, DaemonError> {
        self.ensure_input(input, spool)?;
        let rising = require_rising(input)?;
        let key = state_key(rising);
        let mut stored = self.load_current(input, rising)?;
        let inventory = InputInventory::load(input, spool)?;
        let plan = validate_inventory(&stored.value, input, &inventory)?;
        if !plan.is_clean_for_collection() {
            return Ok(StartPageOutcome::AwaitingReconcile);
        }

        if stored.value.coordinator.active_attempt.is_none() {
            let attempt_id = fresh_attempt_id(&stored.value)?;
            let fence = AttemptFence::new(
                attempt_id,
                stored.value.coordinator.configuration_id,
                stored.value.coordinator.generation,
            );
            let mut next = stored.value.clone();
            next.coordinator
                .start_attempt(fence)
                .map_err(checkpoint_error)?;
            next.active_scan = Some(ActiveScan {
                attempt_id,
                base_committed: next.coordinator.committed,
                resume_after: None,
                maximum_candidate: None,
                compacted_through_sequence: 0,
                compacted_rows: 0,
                next_page: 1,
                complete: false,
                segments: Vec::new(),
                delivered_through_sequence: 0,
            });
            stored = self
                .store
                .compare_exchange(key, stored.token, &next)
                .map_err(state_store_error)?;
        }

        let active = stored
            .value
            .coordinator
            .active_attempt
            .as_ref()
            .ok_or_else(checkpoint_invariant_error)?;
        let scan = stored
            .value
            .active_scan
            .as_ref()
            .ok_or_else(checkpoint_invariant_error)?;
        if scan.complete
            || active.collection != CollectionState::InProgress
            || active.delivery != DeliveryState::InProgress
            || scan.delivered_through_sequence != segment_count(scan)?
        {
            return Ok(StartPageOutcome::AwaitingReconcile);
        }

        let cursor_request = TimestampIdCursorRequest {
            spec: rising.cursor_spec.clone(),
            committed: stored.value.coordinator.committed,
            resume_after: scan.resume_after,
        };
        cursor_request
            .effective_bound()
            .map_err(|_| cursor_request_error())?;
        Ok(StartPageOutcome::Ready(Box::new(RisingPageContext {
            configuration_generation: stored.value.configuration_generation,
            checkpoint_generation: stored.value.coordinator.generation,
            attempt_id: active.fence.attempt_id,
            page: scan.next_page,
            cursor_request,
            input_key: spool_input_key(input),
            configuration_fingerprint: spool_fingerprint(input.revision_fingerprint.into_bytes()),
        })))
    }

    /// Records a successful empty final page without creating a spool segment.
    ///
    /// # Errors
    ///
    /// Returns an error for non-empty/inconsistent collection facts, a stale page fence, retained
    /// unreconciled spool work, or a failed durable transition.
    pub(crate) fn record_empty_completion(
        &self,
        input: &PreparedInput,
        context: &RisingPageContext,
        collection: &CollectionResult,
        spool: &Spool,
    ) -> Result<(), DaemonError> {
        if collection.rows_read != 0
            || collection.truncated
            || collection.checkpoint_candidate.is_some()
            || collection.scan_resume.is_some()
        {
            return Err(empty_completion_error());
        }
        self.ensure_input(input, spool)?;
        let rising = require_rising(input)?;
        let key = state_key(rising);
        let stored = self.load_current(input, rising)?;
        validate_page_context(&stored.value, input, rising, context)?;
        let inventory = InputInventory::load(input, spool)?;
        let plan = validate_inventory(&stored.value, input, &inventory)?;
        if !plan.is_clean_for_collection() {
            return Err(inventory_error(
                "empty rising completion conflicts with retained spool work",
            ));
        }

        let mut next = stored.value.clone();
        let fence = active_fence(&next)?;
        let (rows, candidate) = {
            let scan = next
                .active_scan
                .as_mut()
                .ok_or_else(checkpoint_invariant_error)?;
            if scan.complete || scan.next_page != context.page {
                return Err(page_context_error());
            }
            scan.complete = true;
            (sealed_rows(scan)?, scan.maximum_candidate)
        };
        next.coordinator
            .collection_completed(fence, rows, candidate)
            .map_err(checkpoint_error)?;
        self.store
            .compare_exchange(key, stored.token, &next)
            .map_err(state_store_error)?;
        Ok(())
    }

    /// Reconciles sealed pages, durable delivery receipts, compaction, and final commit.
    ///
    /// The callback must send and receive the configured sink acknowledgment before atomically
    /// marking the supplied ready segment delivered. Returning an error leaves the ready/delivered
    /// lifecycle recoverable on the next call.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid state/spool relationships, a delivery callback failure, a
    /// compaction failure, or a rejected durable state-machine transition.
    pub(crate) fn reconcile<F>(
        &self,
        input: &PreparedInput,
        spool: &Spool,
        mut deliver: F,
    ) -> Result<RisingReconcileOutcome, DaemonError>
    where
        F: FnMut(&ReadySegment) -> Result<DeliveredSegment, DaemonError>,
    {
        let rising = require_rising(input)?;
        let key = state_key(rising);
        if matches!(
            self.store.load(key).map_err(state_store_error)?,
            LoadResult::Missing
        ) {
            if input_spool_is_nonempty(input, spool)? {
                return Err(inventory_error(
                    "durable rising state is missing while retained spool data exists",
                ));
            }
            return Ok(RisingReconcileOutcome::Idle {
                checkpoint_generation: INITIAL_CHECKPOINT_GENERATION,
            });
        }
        self.ensure_input(input, spool)?;
        let mut stored = self.load_current(input, rising)?;
        if stored.value.active_scan.is_none() {
            let inventory = InputInventory::load(input, spool)?;
            validate_inventory(&stored.value, input, &inventory)?;
            return Ok(RisingReconcileOutcome::Idle {
                checkpoint_generation: stored.value.coordinator.generation,
            });
        }

        let inventory = InputInventory::load(input, spool)?;
        let plan = validate_inventory(&stored.value, input, &inventory)?;
        stored = self.reconcile_delivery_prefix(key, stored, input, spool, plan, &mut deliver)?;
        self.finish_reconciled_scan(key, stored)
    }

    fn reconcile_delivery_prefix<F>(
        &self,
        key: StateKey,
        mut stored: StoredState,
        input: &PreparedInput,
        spool: &Spool,
        mut plan: InventoryPlan,
        deliver: &mut F,
    ) -> Result<StoredState, DaemonError>
    where
        F: FnMut(&ReadySegment) -> Result<DeliveredSegment, DaemonError>,
    {
        for delivered in plan.receipted_delivered.drain(..) {
            spool.compact_delivered(&delivered)?;
        }
        stored = self.prune_compacted_prefix(key, stored)?;

        if let Some(orphan) = plan.orphan.take() {
            let next = adopt_orphan(&stored.value, input, &orphan)?;
            stored = self
                .store
                .compare_exchange(key, stored.token, &next)
                .map_err(state_store_error)?;
            let sequence = segment_count(
                stored
                    .value
                    .active_scan
                    .as_ref()
                    .ok_or_else(checkpoint_invariant_error)?,
            )?;
            plan.pending.insert(sequence, LocatedSegment::Ready(orphan));
        }

        loop {
            let scan = stored
                .value
                .active_scan
                .as_ref()
                .ok_or_else(checkpoint_invariant_error)?;
            let next_sequence = scan
                .delivered_through_sequence
                .checked_add(1)
                .ok_or_else(checkpoint_invariant_error)?;
            if next_sequence > segment_count(scan)? {
                break;
            }
            let located = plan
                .pending
                .remove(&next_sequence)
                .ok_or_else(|| inventory_error("a referenced rising segment is missing"))?;
            let delivered = match located {
                LocatedSegment::Ready(ready) => {
                    let delivered = deliver(&ready)?;
                    validate_delivered_for_reference(
                        &stored.value,
                        input,
                        next_sequence,
                        &delivered,
                    )?;
                    delivered
                }
                LocatedSegment::Delivered(delivered) => delivered,
            };

            let mut next = stored.value.clone();
            next.active_scan
                .as_mut()
                .ok_or_else(checkpoint_invariant_error)?
                .delivered_through_sequence = next_sequence;
            stored = self
                .store
                .compare_exchange(key, stored.token, &next)
                .map_err(state_store_error)?;
            spool.compact_delivered(&delivered)?;
            stored = self.prune_compacted_prefix(key, stored)?;
        }

        Ok(stored)
    }

    fn prune_compacted_prefix(
        &self,
        key: StateKey,
        stored: StoredState,
    ) -> Result<StoredState, DaemonError> {
        let scan = stored
            .value
            .active_scan
            .as_ref()
            .ok_or_else(checkpoint_invariant_error)?;
        let removable = scan
            .segments
            .iter()
            .take_while(|reference| reference.sequence() <= scan.delivered_through_sequence)
            .count();
        if removable == 0 {
            return Ok(stored);
        }
        let removed_rows =
            scan.segments[..removable]
                .iter()
                .try_fold(0_u64, |rows, reference| {
                    rows.checked_add(reference.rows())
                        .ok_or_else(checkpoint_invariant_error)
                })?;
        let compacted_through_sequence = scan.segments[removable - 1].sequence();
        let mut next = stored.value.clone();
        let next_scan = next
            .active_scan
            .as_mut()
            .ok_or_else(checkpoint_invariant_error)?;
        next_scan.compacted_through_sequence = compacted_through_sequence;
        next_scan.compacted_rows = next_scan
            .compacted_rows
            .checked_add(removed_rows)
            .ok_or_else(checkpoint_invariant_error)?;
        next_scan.segments.drain(..removable);
        self.store
            .compare_exchange(key, stored.token, &next)
            .map_err(state_store_error)
    }

    fn finish_reconciled_scan(
        &self,
        key: StateKey,
        mut stored: StoredState,
    ) -> Result<RisingReconcileOutcome, DaemonError> {
        let scan = stored
            .value
            .active_scan
            .as_ref()
            .ok_or_else(checkpoint_invariant_error)?;
        if !scan.complete {
            return Ok(RisingReconcileOutcome::NeedsCollection {
                checkpoint_generation: stored.value.coordinator.generation,
                next_page: scan.next_page,
            });
        }
        if scan.delivered_through_sequence != segment_count(scan)? {
            return Err(inventory_error(
                "completed rising scan has an incomplete delivery prefix",
            ));
        }

        let fence = active_fence(&stored.value)?;
        let rows = sealed_rows(scan)?;
        match stored
            .value
            .coordinator
            .active_attempt
            .as_ref()
            .ok_or_else(checkpoint_invariant_error)?
            .delivery
        {
            DeliveryState::InProgress => {
                let mut next = stored.value.clone();
                next.coordinator
                    .delivery_confirmed(fence, rows)
                    .map_err(checkpoint_error)?;
                stored = self
                    .store
                    .compare_exchange(key, stored.token, &next)
                    .map_err(state_store_error)?;
            }
            DeliveryState::Confirmed {
                rows: delivered_rows,
            } if delivered_rows == rows => {}
            DeliveryState::Confirmed { .. } | DeliveryState::Failed | DeliveryState::Uncertain => {
                return Err(checkpoint_invariant_error());
            }
        }

        let mut next = stored.value.clone();
        let commit = next.coordinator.commit(fence).map_err(checkpoint_error)?;
        next.active_scan = None;
        let committed = self
            .store
            .compare_exchange(key, stored.token, &next)
            .map_err(state_store_error)?;
        let (checkpoint_generation, cursor_advanced) = match commit {
            CommitOutcome::Committed {
                generation,
                cursor_advanced,
            } => (generation, cursor_advanced),
            CommitOutcome::AlreadyCommitted { .. } => return Err(checkpoint_invariant_error()),
        };
        if committed.value.coordinator.generation != checkpoint_generation {
            return Err(checkpoint_invariant_error());
        }
        Ok(RisingReconcileOutcome::Committed {
            checkpoint_generation,
            cursor_advanced,
        })
    }

    fn load_current(
        &self,
        input: &PreparedInput,
        rising: &PreparedRising,
    ) -> Result<StoredState, DaemonError> {
        match self
            .store
            .load(state_key(rising))
            .map_err(state_store_error)?
        {
            LoadResult::Missing => Err(missing_state_error()),
            LoadResult::Current(state) => {
                validate_prepared_identity(&state.value, input, rising)?;
                if state.value.configuration_fingerprint
                    != state_fingerprint(input.revision_fingerprint.into_bytes())
                {
                    return Err(configuration_activation_error());
                }
                Ok(*state)
            }
        }
    }
}

fn initial_state(input: &PreparedInput, rising: &PreparedRising) -> DurableInputState {
    let configuration_fingerprint = state_fingerprint(input.revision_fingerprint.into_bytes());
    DurableInputState::new(
        InputId::new(rising.state_input_id),
        state_fingerprint(input.lineage_fingerprint.into_bytes()),
        state_fingerprint(rising.cursor_identity_fingerprint.into_bytes()),
        configuration_fingerprint,
        INITIAL_CONFIGURATION_GENERATION,
        Snapshot::new(
            configuration_fence_id(configuration_fingerprint, INITIAL_CONFIGURATION_GENERATION),
            INITIAL_CHECKPOINT_GENERATION,
            None,
        ),
        None,
    )
}

fn validate_prepared_identity(
    state: &DurableInputState,
    input: &PreparedInput,
    rising: &PreparedRising,
) -> Result<(), DaemonError> {
    if state.input_id != InputId::new(rising.state_input_id)
        || state.source_lineage_fingerprint
            != state_fingerprint(input.lineage_fingerprint.into_bytes())
        || state.cursor_identity_fingerprint
            != state_fingerprint(rising.cursor_identity_fingerprint.into_bytes())
    {
        return Err(identity_migration_error());
    }
    Ok(())
}

fn validate_page_context(
    state: &DurableInputState,
    input: &PreparedInput,
    rising: &PreparedRising,
    context: &RisingPageContext,
) -> Result<(), DaemonError> {
    let active = state
        .coordinator
        .active_attempt
        .as_ref()
        .ok_or_else(page_context_error)?;
    let scan = state.active_scan.as_ref().ok_or_else(page_context_error)?;
    let expected_cursor = TimestampIdCursorRequest {
        spec: rising.cursor_spec.clone(),
        committed: state.coordinator.committed,
        resume_after: scan.resume_after,
    };
    if context.input_key != spool_input_key(input)
        || context.configuration_fingerprint
            != spool_fingerprint(input.revision_fingerprint.into_bytes())
        || context.configuration_generation != state.configuration_generation
        || context.checkpoint_generation != state.coordinator.generation
        || context.attempt_id != active.fence.attempt_id
        || context.page != scan.next_page
        || context.cursor_request != expected_cursor
    {
        return Err(page_context_error());
    }
    Ok(())
}

fn adopt_orphan(
    state: &DurableInputState,
    input: &PreparedInput,
    orphan: &ReadySegment,
) -> Result<DurableInputState, DaemonError> {
    let mut next = state.clone();
    let metadata = validate_common_segment(&next, input, SegmentView::Ready(orphan))?;
    if metadata.request_fingerprint() != expected_request_fingerprint(&next, input)? {
        return Err(inventory_error(
            "sealed rising page does not match the durable cursor request",
        ));
    }
    let fence = active_fence(&next)?;
    let (rows, candidate, complete) = {
        let scan = next
            .active_scan
            .as_mut()
            .ok_or_else(checkpoint_invariant_error)?;
        if scan.complete
            || orphan.header().segment_sequence != scan.next_page
            || metadata.rows() == 0
            || metadata.rows() != orphan.summary().event_count
        {
            return Err(inventory_error(
                "sealed rising page does not match the active scan",
            ));
        }
        let sequence = segment_count(scan)?
            .checked_add(1)
            .ok_or_else(checkpoint_invariant_error)?;
        if sequence != scan.next_page || scan.segments.len() >= MAX_SEGMENTS_PER_SCAN {
            return Err(inventory_error(
                "sealed rising page exceeds the active scan bounds",
            ));
        }
        scan.segments.push(SegmentRef::new(
            orphan.segment_id().into_bytes(),
            sequence,
            scan.next_page,
            metadata.rows(),
            orphan.reference_digest(),
        ));
        scan.resume_after = metadata.scan_resume();
        scan.maximum_candidate = metadata.checkpoint_candidate();
        scan.next_page = scan
            .next_page
            .checked_add(1)
            .ok_or_else(checkpoint_invariant_error)?;
        scan.complete = !metadata.truncated();
        (sealed_rows(scan)?, scan.maximum_candidate, scan.complete)
    };
    if complete {
        next.coordinator
            .collection_completed(fence, rows, candidate)
            .map_err(checkpoint_error)?;
    }
    Ok(next)
}

fn expected_request_fingerprint(
    state: &DurableInputState,
    input: &PreparedInput,
) -> Result<[u8; 32], DaemonError> {
    let rising = require_rising(input)?;
    let scan = state
        .active_scan
        .as_ref()
        .ok_or_else(checkpoint_invariant_error)?;
    let request = TimestampIdCursorRequest {
        spec: rising.cursor_spec.clone(),
        committed: state.coordinator.committed,
        resume_after: scan.resume_after,
    };
    Ok(rising_request_fingerprint(
        rising.cursor_identity_fingerprint.into_bytes(),
        &request,
    ))
}

fn validate_delivered_for_reference(
    state: &DurableInputState,
    input: &PreparedInput,
    sequence: u64,
    delivered: &DeliveredSegment,
) -> Result<(), DaemonError> {
    let scan = state
        .active_scan
        .as_ref()
        .ok_or_else(checkpoint_invariant_error)?;
    let reference = scan
        .segments
        .iter()
        .find(|reference| reference.sequence() == sequence)
        .ok_or_else(checkpoint_invariant_error)?;
    validate_reference(
        state,
        input,
        scan,
        reference,
        SegmentView::Delivered(delivered),
    )
}

struct InputInventory {
    ready: Vec<ReadySegment>,
    delivered: Vec<DeliveredSegment>,
}

impl InputInventory {
    fn load(input: &PreparedInput, spool: &Spool) -> Result<Self, DaemonError> {
        let key = spool_input_key(input);
        let ready = spool
            .list_ready()?
            .into_iter()
            .filter(|segment| segment.header().input_key == key)
            .collect();
        let delivered = spool
            .list_delivered()?
            .into_iter()
            .filter(|segment| segment.header().input_key == key)
            .collect();
        Ok(Self { ready, delivered })
    }
}

enum LocatedSegment {
    Ready(ReadySegment),
    Delivered(DeliveredSegment),
}

impl LocatedSegment {
    const fn view(&self) -> SegmentView<'_> {
        match self {
            Self::Ready(segment) => SegmentView::Ready(segment),
            Self::Delivered(segment) => SegmentView::Delivered(segment),
        }
    }
}

#[derive(Clone, Copy)]
enum SegmentView<'a> {
    Ready(&'a ReadySegment),
    Delivered(&'a DeliveredSegment),
}

impl<'a> SegmentView<'a> {
    const fn header_ref(self) -> &'a SegmentHeader {
        match self {
            Self::Ready(segment) => segment.header(),
            Self::Delivered(segment) => segment.header(),
        }
    }

    const fn segment_id(self) -> [u8; 16] {
        match self {
            Self::Ready(segment) => segment.segment_id().into_bytes(),
            Self::Delivered(segment) => segment.segment_id().into_bytes(),
        }
    }

    const fn event_count(self) -> u64 {
        match self {
            Self::Ready(segment) => segment.summary().event_count,
            Self::Delivered(segment) => segment.summary().event_count,
        }
    }

    fn reference_digest(self) -> [u8; 32] {
        match self {
            Self::Ready(segment) => segment.reference_digest(),
            Self::Delivered(segment) => segment.reference_digest(),
        }
    }

    fn metadata(self) -> Result<RisingRecoveryMetadata, DaemonError> {
        let metadata = match self {
            Self::Ready(segment) => segment.recovery_metadata(),
            Self::Delivered(segment) => segment.recovery_metadata(),
        };
        RisingRecoveryMetadata::decode(metadata).map_err(rising_metadata_error)
    }
}

struct InventoryPlan {
    orphan: Option<ReadySegment>,
    pending: BTreeMap<u64, LocatedSegment>,
    receipted_delivered: Vec<DeliveredSegment>,
}

impl InventoryPlan {
    fn is_clean_for_collection(&self) -> bool {
        self.orphan.is_none() && self.pending.is_empty() && self.receipted_delivered.is_empty()
    }
}

fn validate_inventory(
    state: &DurableInputState,
    input: &PreparedInput,
    inventory: &InputInventory,
) -> Result<InventoryPlan, DaemonError> {
    let mut by_id = index_inventory(state, input, inventory)?;
    let Some(scan) = &state.active_scan else {
        if by_id.is_empty() {
            return Ok(InventoryPlan {
                orphan: None,
                pending: BTreeMap::new(),
                receipted_delivered: Vec::new(),
            });
        }
        return Err(inventory_error(
            "retained rising spool data has no active durable scan",
        ));
    };

    let mut pending = BTreeMap::new();
    let mut receipted_delivered = Vec::new();
    for reference in &scan.segments {
        let located = by_id.remove(&reference.segment_id());
        match (
            reference.sequence() <= scan.delivered_through_sequence,
            located,
        ) {
            (true, None) => {}
            (true, Some(LocatedSegment::Delivered(delivered))) => {
                validate_reference(
                    state,
                    input,
                    scan,
                    reference,
                    SegmentView::Delivered(&delivered),
                )?;
                receipted_delivered.push(delivered);
            }
            (true, Some(LocatedSegment::Ready(_))) => {
                return Err(inventory_error(
                    "a receipted rising segment is still in ready state",
                ));
            }
            (false, None) => {
                return Err(inventory_error("a referenced rising segment is missing"));
            }
            (false, Some(located)) => {
                validate_reference(state, input, scan, reference, located.view())?;
                if pending.insert(reference.sequence(), located).is_some() {
                    return Err(inventory_error("duplicate rising segment sequence"));
                }
            }
        }
    }

    let orphan = adoptable_orphan(scan, by_id)?;
    Ok(InventoryPlan {
        orphan,
        pending,
        receipted_delivered,
    })
}

fn index_inventory(
    state: &DurableInputState,
    input: &PreparedInput,
    inventory: &InputInventory,
) -> Result<BTreeMap<[u8; 16], LocatedSegment>, DaemonError> {
    let mut by_id = BTreeMap::<[u8; 16], LocatedSegment>::new();
    for ready in &inventory.ready {
        validate_common_segment(state, input, SegmentView::Ready(ready))?;
        if by_id
            .insert(
                ready.segment_id().into_bytes(),
                LocatedSegment::Ready(ready.clone()),
            )
            .is_some()
        {
            return Err(inventory_error("duplicate rising spool segment identity"));
        }
    }
    for delivered in &inventory.delivered {
        validate_common_segment(state, input, SegmentView::Delivered(delivered))?;
        if by_id
            .insert(
                delivered.segment_id().into_bytes(),
                LocatedSegment::Delivered(delivered.clone()),
            )
            .is_some()
        {
            return Err(inventory_error("duplicate rising spool segment identity"));
        }
    }
    Ok(by_id)
}

fn adoptable_orphan(
    scan: &ActiveScan,
    mut by_id: BTreeMap<[u8; 16], LocatedSegment>,
) -> Result<Option<ReadySegment>, DaemonError> {
    Ok(match by_id.len() {
        0 => None,
        1 => {
            let (_, located) = by_id.pop_first().ok_or_else(checkpoint_invariant_error)?;
            match located {
                LocatedSegment::Ready(ready)
                    if !scan.complete
                        && ready.header().segment_sequence == scan.next_page
                        && ready.summary().event_count > 0 =>
                {
                    Some(ready)
                }
                LocatedSegment::Ready(_) | LocatedSegment::Delivered(_) => {
                    return Err(inventory_error(
                        "unreferenced rising spool data is not an adoptable next ready page",
                    ));
                }
            }
        }
        _ => {
            return Err(inventory_error(
                "multiple unreferenced rising spool segments are retained",
            ));
        }
    })
}

fn validate_common_segment(
    state: &DurableInputState,
    input: &PreparedInput,
    segment: SegmentView<'_>,
) -> Result<RisingRecoveryMetadata, DaemonError> {
    let active = state
        .coordinator
        .active_attempt
        .as_ref()
        .ok_or_else(|| inventory_error("rising spool data has no active checkpoint attempt"))?;
    let header = segment.header_ref();
    if header.input_key != spool_input_key(input)
        || header.configuration_fingerprint
            != spool_fingerprint(input.revision_fingerprint.into_bytes())
        || header.configuration_generation != state.configuration_generation
        || header.batch_id != BatchId::new(active.fence.attempt_id.into_bytes())
        || header.batch_sequence != state.coordinator.generation
        || header.segment_sequence == 0
    {
        return Err(inventory_error(
            "rising spool segment is outside the active durable fence",
        ));
    }
    let metadata = segment.metadata()?;
    if metadata.rows() != segment.event_count() || metadata.rows() == 0 {
        return Err(inventory_error(
            "rising spool metadata does not match the authenticated footer",
        ));
    }
    Ok(metadata)
}

fn validate_reference(
    state: &DurableInputState,
    input: &PreparedInput,
    scan: &ActiveScan,
    reference: &SegmentRef,
    segment: SegmentView<'_>,
) -> Result<(), DaemonError> {
    let metadata = validate_common_segment(state, input, segment)?;
    if reference.sequence() != reference.page()
        || segment.header_ref().segment_sequence != reference.page()
        || segment.segment_id() != reference.segment_id()
        || segment.event_count() != reference.rows()
        || segment.reference_digest() != reference.digest()
    {
        return Err(inventory_error(
            "rising spool segment does not match its durable reference",
        ));
    }
    let last_sequence = segment_count(scan)?;
    // A completed scan may end with an empty page, so its last retained segment can still carry
    // `truncated=true`. Every earlier page, and the last page of an incomplete scan, must be
    // truncated; a non-truncated page can only be the final retained page of a complete scan.
    let must_be_truncated = reference.sequence() < last_sequence || !scan.complete;
    if must_be_truncated && !metadata.truncated() {
        return Err(inventory_error(
            "rising spool page termination does not match durable scan state",
        ));
    }
    Ok(())
}

fn input_spool_is_nonempty(input: &PreparedInput, spool: &Spool) -> Result<bool, DaemonError> {
    let key = spool_input_key(input);
    let usage = spool.usage();
    if usage.input_stored_bytes(key) != 0 || usage.input_reserved_bytes(key) != 0 {
        return Ok(true);
    }
    let inventory = InputInventory::load(input, spool)?;
    Ok(!inventory.ready.is_empty() || !inventory.delivered.is_empty())
}

fn require_rising(input: &PreparedInput) -> Result<&PreparedRising, DaemonError> {
    input.rising.as_ref().ok_or_else(|| {
        DaemonError::new(
            "DBX-RS-RISING-0001",
            "configuration",
            "rising_configuration",
            "scheduled input is not configured for rising collection",
            false,
            true,
        )
    })
}

fn status(state: &DurableInputState) -> RisingStateStatus {
    RisingStateStatus {
        configuration_generation: state.configuration_generation,
        checkpoint_generation: state.coordinator.generation,
        committed: state.coordinator.committed,
        active: state.coordinator.active_attempt.is_some(),
        next_page: state.active_scan.as_ref().map(|scan| scan.next_page),
        delivered_through_sequence: state
            .active_scan
            .as_ref()
            .map_or(0, |scan| scan.delivered_through_sequence),
    }
}

fn state_key(rising: &PreparedRising) -> StateKey {
    StateKey::for_input(InputId::new(rising.state_input_id))
}

const fn state_fingerprint(bytes: [u8; 32]) -> StateFingerprint {
    StateFingerprint::new(bytes)
}

const fn spool_fingerprint(bytes: [u8; 32]) -> SpoolFingerprint {
    SpoolFingerprint::new(bytes)
}

fn spool_input_key(input: &PreparedInput) -> InputKey {
    InputKey::new(input.input_id.into_bytes())
}

fn active_fence(state: &DurableInputState) -> Result<AttemptFence, DaemonError> {
    state
        .coordinator
        .active_attempt
        .as_ref()
        .map(|active| active.fence)
        .ok_or_else(checkpoint_invariant_error)
}

fn fresh_attempt_id(state: &DurableInputState) -> Result<AttemptId, DaemonError> {
    let previous = state
        .coordinator
        .last_committed_attempt
        .map(|attempt| attempt.fence.attempt_id);
    for _ in 0..ATTEMPT_ID_GENERATION_LIMIT {
        let candidate = AttemptId::new(generate_uuid_bytes()?);
        if Some(candidate) != previous {
            return Ok(candidate);
        }
    }
    Err(DaemonError::new(
        "DBX-RS-RISING-0002",
        "internal",
        "attempt_identity",
        "failed to generate a distinct rising attempt identity",
        false,
        false,
    ))
}

fn sealed_rows(scan: &ActiveScan) -> Result<u64, DaemonError> {
    scan.segments
        .iter()
        .try_fold(scan.compacted_rows, |rows, segment| {
            rows.checked_add(segment.rows())
                .ok_or_else(checkpoint_invariant_error)
        })
}

fn segment_count(scan: &ActiveScan) -> Result<u64, DaemonError> {
    let retained = u64::try_from(scan.segments.len()).map_err(|_| checkpoint_invariant_error())?;
    scan.compacted_through_sequence
        .checked_add(retained)
        .ok_or_else(checkpoint_invariant_error)
}

fn rising_metadata_error(error: RisingMetadataError) -> DaemonError {
    DaemonError::new(
        error.code(),
        "storage",
        "rising_recovery",
        "authenticated rising recovery metadata is invalid",
        false,
        false,
    )
}

fn state_store_error(_error: dbx_rs_state::StateStoreError) -> DaemonError {
    DaemonError::new(
        "DBX-RS-RISING-0003",
        "storage",
        "checkpoint_state",
        "durable rising checkpoint operation failed",
        false,
        false,
    )
}

fn checkpoint_error(_error: dbx_rs_checkpoint::CheckpointError) -> DaemonError {
    checkpoint_invariant_error()
}

const fn checkpoint_invariant_error() -> DaemonError {
    DaemonError::new(
        "DBX-RS-RISING-0004",
        "storage",
        "checkpoint_transition",
        "durable rising checkpoint invariants are inconsistent",
        false,
        false,
    )
}

const fn missing_state_error() -> DaemonError {
    DaemonError::new(
        "DBX-RS-RISING-0005",
        "storage",
        "checkpoint_state",
        "durable rising checkpoint state is missing",
        false,
        false,
    )
}

const fn identity_migration_error() -> DaemonError {
    DaemonError::new(
        "DBX-RS-RISING-0006",
        "configuration",
        "rising_identity",
        "rising source or cursor identity requires explicit migration",
        false,
        true,
    )
}

const fn configuration_activation_error() -> DaemonError {
    DaemonError::new(
        "DBX-RS-RISING-0007",
        "configuration",
        "configuration_activation",
        "rising configuration activation is blocked by durable work",
        false,
        true,
    )
}

const fn inventory_error(message: &'static str) -> DaemonError {
    DaemonError::new(
        "DBX-RS-RISING-0008",
        "storage",
        "spool_recovery",
        message,
        false,
        false,
    )
}

const fn page_context_error() -> DaemonError {
    DaemonError::new(
        "DBX-RS-RISING-0009",
        "storage",
        "page_fence",
        "rising page completion has a stale durable fence",
        false,
        false,
    )
}

const fn cursor_request_error() -> DaemonError {
    DaemonError::new(
        "DBX-RS-RISING-0010",
        "configuration",
        "cursor_bound",
        "rising cursor lower bound cannot be represented",
        false,
        true,
    )
}

const fn empty_completion_error() -> DaemonError {
    DaemonError::new(
        "DBX-RS-RISING-0011",
        "internal",
        "collection_accounting",
        "rising empty completion has inconsistent collection facts",
        false,
        false,
    )
}

const fn detached_identity_error() -> DaemonError {
    DaemonError::new(
        "DBX-RS-RISING-0012",
        "configuration",
        "rising_identity",
        "persisted rising checkpoint identity is not configured",
        false,
        true,
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use dbx_rs_config::load_effective_config;
    use dbx_rs_spool::{Fingerprint as SpoolFingerprint, SpoolKey, SpoolLimits};

    use super::*;
    use crate::prepared::prepare_input;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        app_home: PathBuf,
        splunk_home: PathBuf,
        input: PreparedInput,
        spool: Spool,
        coordinator: RisingCoordinator,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "dbx-rs-rising-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            let app_home = root.join("app");
            let splunk_home = root.join("splunk");
            fs::create_dir_all(app_home.join("default"))
                .expect("default configuration directory must exist");
            fs::write(
                app_home.join("default/dbxrs_generic.conf"),
                include_bytes!("../../../packaging/splunk/TA-dbx-rs/default/dbxrs_generic.conf"),
            )
            .expect("generic configuration must be written");
            write_input_configuration(&app_home, "SELECT updated_at, row_id FROM source_table");
            let input = load_prepared(&app_home, &splunk_home);

            let key = SpoolKey::load_or_create(&root.join("durable/spool.key"))
                .expect("spool key must open");
            let limits = SpoolLimits::new(16 * 1024, 128 * 1024, 512 * 1024)
                .expect("spool limits must be valid");
            let spool =
                Spool::open(&root.join("durable/spool"), key, limits).expect("spool must open");
            let coordinator = RisingCoordinator::open(&root.join("durable/state"))
                .expect("coordinator must open");
            Self {
                root,
                app_home,
                splunk_home,
                input,
                spool,
                coordinator,
            }
        }

        fn page(&self) -> RisingPageContext {
            match self
                .coordinator
                .start_or_resume_page(&self.input, &self.spool)
                .expect("page scheduling must succeed")
            {
                StartPageOutcome::Ready(context) => *context,
                StartPageOutcome::AwaitingReconcile => {
                    panic!("fixture unexpectedly requires reconciliation")
                }
            }
        }

        fn reopen_coordinator(&self) -> RisingCoordinator {
            RisingCoordinator::open(&self.root.join("durable/state"))
                .expect("coordinator must reopen")
        }

        fn modified_query_input(&self) -> PreparedInput {
            write_input_configuration(
                &self.app_home,
                "SELECT updated_at, row_id FROM replacement_table",
            );
            load_prepared(&self.app_home, &self.splunk_home)
        }

        fn revised_operational_input(&self) -> PreparedInput {
            self.operational_input_with_byte_decrement(1)
        }

        fn operational_input_with_byte_decrement(&self, decrement: u64) -> PreparedInput {
            let effective = load_effective_config(&self.app_home, &self.splunk_home)
                .expect("configuration must load");
            let mut input = effective.inputs[0].clone();
            input.max_bytes = input
                .max_bytes
                .checked_sub(decrement)
                .expect("fixture byte limit must remain positive");
            prepare_input(&input, &effective.generic.hec).expect("revised input must prepare")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.root);
        }
    }

    fn write_input_configuration(app_home: &Path, query: &str) {
        let configured = format!(
            r"[orders]
disabled = false
mode = rising
input_id = 123e4567-e89b-12d3-a456-426614174000
cursor_timestamp_field = updated_at
cursor_id_field = row_id
cursor_overlap_secs = 0
connector = postgres
interval_secs = 60
host = db.example.invalid
port = 5432
database = reporting
username = reader
secret_ref = local:reporting
tls_mode = disable
query = {query}
connect_timeout_secs = 10
probe_timeout_secs = 10
max_rows = 1000
max_bytes = 1000000
query_timeout_secs = 30
index = dbx_test
sourcetype = dbx:test
source = dbx:test
"
        );
        fs::write(
            app_home.join("default/dbxrs_inputs.conf"),
            configured.as_bytes(),
        )
        .expect("input configuration must be written");
    }

    fn load_prepared(app_home: &Path, splunk_home: &Path) -> PreparedInput {
        let effective =
            load_effective_config(app_home, splunk_home).expect("configuration must load");
        prepare_input(&effective.inputs[0], &effective.generic.hec)
            .expect("rising input must prepare")
    }

    fn cursor(timestamp: i64, id: i64) -> TimestampIdCursor {
        TimestampIdCursor::new(timestamp, id)
    }

    fn seal_page(
        spool: &Spool,
        input: &PreparedInput,
        context: &RisingPageContext,
        rows: u64,
        truncated: bool,
        candidate: TimestampIdCursor,
    ) -> ReadySegment {
        let rising = input.rising.as_ref().expect("input must be rising");
        let request_fingerprint = rising_request_fingerprint(
            rising.cursor_identity_fingerprint.into_bytes(),
            &context.cursor_request,
        );
        let metadata = RisingRecoveryMetadata::new(
            rows,
            truncated,
            request_fingerprint,
            Some(candidate),
            Some(candidate),
        )
        .and_then(RisingRecoveryMetadata::encode)
        .expect("recovery metadata must encode");
        let mut writer = spool
            .begin_segment(context.segment_header(1_720_000_000_123))
            .expect("segment must begin");
        for row in 0..rows {
            writer
                .append_event(format!("event-{row}").as_bytes())
                .expect("event must append");
        }
        writer
            .seal_with_recovery_metadata(metadata)
            .expect("segment must seal")
    }

    fn empty_collection() -> CollectionResult {
        CollectionResult {
            request_id: "test-request".into(),
            rows_read: 0,
            bytes_read: 0,
            truncated: false,
            checkpoint_candidate: None,
            scan_resume: None,
        }
    }

    fn injected_delivery_error() -> DaemonError {
        DaemonError::new(
            "DBX-RS-TEST-RISING-0001",
            "delivery",
            "test_delivery",
            "injected delivery failure",
            true,
            false,
        )
    }

    fn mark_delivered(
        spool: &Spool,
        ready: &ReadySegment,
    ) -> Result<DeliveredSegment, DaemonError> {
        spool.mark_delivered(ready).map_err(DaemonError::from)
    }

    #[test]
    fn reconcile_missing_state_is_a_non_creating_idle_preflight() {
        let fixture = Fixture::new();

        assert_eq!(
            fixture
                .coordinator
                .reconcile(&fixture.input, &fixture.spool, |_| {
                    panic!("missing state cannot deliver")
                })
                .expect("missing state must be idle"),
            RisingReconcileOutcome::Idle {
                checkpoint_generation: 0
            }
        );
        assert_eq!(
            fixture
                .coordinator
                .status(&fixture.input)
                .expect_err("preflight must not create state")
                .code(),
            "DBX-RS-RISING-0005"
        );
    }

    #[test]
    fn candidate_identity_preflight_ignores_revision_without_activating_it() {
        let fixture = Fixture::new();
        fixture
            .coordinator
            .ensure_input(&fixture.input, &fixture.spool)
            .expect("initial state must be created");
        let revised = fixture.revised_operational_input();
        assert_eq!(
            revised.lineage_fingerprint,
            fixture.input.lineage_fingerprint
        );
        assert_ne!(
            revised.revision_fingerprint,
            fixture.input.revision_fingerprint
        );

        fixture
            .coordinator
            .validate_candidate_identity(&revised)
            .expect("revision-only candidate must pass identity preflight");
        assert_eq!(
            fixture
                .coordinator
                .status(&fixture.input)
                .expect("preflight must leave old revision active")
                .configuration_generation,
            1
        );
        assert_eq!(
            fixture
                .coordinator
                .ensure_input(&revised, &fixture.spool)
                .expect("idle revision must activate")
                .configuration_generation,
            2
        );
    }

    #[test]
    fn persisted_identity_must_remain_configured_across_restart() {
        let fixture = Fixture::new();
        fixture
            .coordinator
            .ensure_input(&fixture.input, &fixture.spool)
            .expect("initial state must be created");
        let configured = BTreeMap::from([(fixture.input.name.clone(), fixture.input.clone())]);
        fixture
            .reopen_coordinator()
            .validate_configured_identities(&configured)
            .expect("same persisted identity must remain valid");

        let mut renamed = fixture.input.clone();
        renamed.name = "renamed-orders".into();
        fixture
            .reopen_coordinator()
            .validate_configured_identities(&BTreeMap::from([(renamed.name.clone(), renamed)]))
            .expect("stanza rename must preserve UUID ownership");

        let error = fixture
            .reopen_coordinator()
            .validate_configured_identities(&BTreeMap::new())
            .expect_err("detached persisted identity must fail closed");
        assert_eq!(error.code(), "DBX-RS-RISING-0012");
        assert!(error.configuration_error());
    }

    #[test]
    fn startup_preflight_activates_idle_revision_and_blocks_active_revision() {
        let fixture = Fixture::new();
        fixture
            .coordinator
            .ensure_input(&fixture.input, &fixture.spool)
            .expect("initial state must be created");
        let revised = fixture.revised_operational_input();
        fixture
            .reopen_coordinator()
            .preflight_startup(
                &BTreeMap::from([(revised.name.clone(), revised.clone())]),
                &fixture.spool,
            )
            .expect("idle revision must activate before delivery setup");
        assert_eq!(
            fixture
                .reopen_coordinator()
                .status(&revised)
                .expect("activated state must load")
                .configuration_generation,
            2
        );

        fixture
            .reopen_coordinator()
            .start_or_resume_page(&revised, &fixture.spool)
            .expect("active scan must start");
        let changed_again = fixture.operational_input_with_byte_decrement(2);
        let error = fixture
            .reopen_coordinator()
            .preflight_startup(
                &BTreeMap::from([(changed_again.name.clone(), changed_again)]),
                &fixture.spool,
            )
            .expect_err("active revision replacement must fail before HEC setup");
        assert_eq!(error.code(), "DBX-RS-RISING-0007");
    }

    #[test]
    fn seal_before_state_reference_is_adopted_delivered_and_committed() {
        let fixture = Fixture::new();
        let context = fixture.page();
        let candidate = cursor(1_000_000, 11);
        seal_page(
            &fixture.spool,
            &fixture.input,
            &context,
            2,
            false,
            candidate,
        );

        assert_eq!(
            fixture
                .coordinator
                .start_or_resume_page(&fixture.input, &fixture.spool)
                .expect("sealed orphan must be recognized"),
            StartPageOutcome::AwaitingReconcile
        );
        let error = fixture
            .coordinator
            .reconcile(&fixture.input, &fixture.spool, |_| {
                Err(injected_delivery_error())
            })
            .expect_err("injected delivery must stop after adoption");
        assert_eq!(error.code(), "DBX-RS-TEST-RISING-0001");
        let adopted = fixture
            .coordinator
            .status(&fixture.input)
            .expect("adopted state must load");
        assert!(adopted.active);
        assert_eq!(adopted.next_page, Some(2));
        assert_eq!(adopted.delivered_through_sequence, 0);

        let restarted = fixture.reopen_coordinator();
        let outcome = restarted
            .reconcile(&fixture.input, &fixture.spool, |ready| {
                mark_delivered(&fixture.spool, ready)
            })
            .expect("restarted reconciliation must commit");
        assert_eq!(
            outcome,
            RisingReconcileOutcome::Committed {
                checkpoint_generation: 1,
                cursor_advanced: true
            }
        );
        let committed = restarted
            .status(&fixture.input)
            .expect("committed state must load");
        assert_eq!(committed.committed, Some(candidate));
        assert!(!committed.active);
        assert!(
            fixture
                .spool
                .list_ready()
                .expect("ready inventory")
                .is_empty()
        );
        assert!(
            fixture
                .spool
                .list_delivered()
                .expect("delivered inventory")
                .is_empty()
        );
    }

    #[test]
    fn delivered_without_receipt_recovers_without_resending() {
        let fixture = Fixture::new();
        let context = fixture.page();
        seal_page(
            &fixture.spool,
            &fixture.input,
            &context,
            1,
            false,
            cursor(2_000_000, 21),
        );

        fixture
            .coordinator
            .reconcile(&fixture.input, &fixture.spool, |ready| {
                let _delivered = mark_delivered(&fixture.spool, ready)?;
                Err(injected_delivery_error())
            })
            .expect_err("crash after mark-delivered must be injected");
        assert_eq!(
            fixture
                .coordinator
                .status(&fixture.input)
                .expect("state must load")
                .delivered_through_sequence,
            0
        );
        assert!(
            fixture
                .spool
                .list_ready()
                .expect("ready inventory")
                .is_empty()
        );
        assert_eq!(
            fixture
                .spool
                .list_delivered()
                .expect("delivered inventory")
                .len(),
            1
        );

        let restarted = fixture.reopen_coordinator();
        let outcome = restarted
            .reconcile(&fixture.input, &fixture.spool, |_| {
                panic!("delivered segment must not be resent")
            })
            .expect("delivered lifecycle must recover");
        assert!(matches!(
            outcome,
            RisingReconcileOutcome::Committed {
                checkpoint_generation: 1,
                ..
            }
        ));
        assert!(
            fixture
                .spool
                .list_delivered()
                .expect("delivered inventory")
                .is_empty()
        );
    }

    #[test]
    fn persisted_receipt_is_compacted_before_final_commit() {
        let fixture = Fixture::new();
        let context = fixture.page();
        seal_page(
            &fixture.spool,
            &fixture.input,
            &context,
            1,
            false,
            cursor(3_000_000, 31),
        );
        fixture
            .coordinator
            .reconcile(&fixture.input, &fixture.spool, |_| {
                Err(injected_delivery_error())
            })
            .expect_err("first reconciliation only adopts");
        let ready = fixture
            .spool
            .list_ready()
            .expect("ready inventory")
            .pop()
            .expect("adopted ready segment must exist");
        fixture
            .spool
            .mark_delivered(&ready)
            .expect("segment must be marked delivered");

        let rising = require_rising(&fixture.input).expect("input must be rising");
        let key = state_key(rising);
        let current = match fixture
            .coordinator
            .store
            .load(key)
            .expect("state must load")
        {
            LoadResult::Current(state) => *state,
            LoadResult::Missing => panic!("state must exist"),
        };
        let mut receipted = current.value.clone();
        receipted
            .active_scan
            .as_mut()
            .expect("scan must exist")
            .delivered_through_sequence = 1;
        fixture
            .coordinator
            .store
            .compare_exchange(key, current.token, &receipted)
            .expect("receipt must persist independently");

        let outcome = fixture
            .reopen_coordinator()
            .reconcile(&fixture.input, &fixture.spool, |_| {
                panic!("receipted segment must not be resent")
            })
            .expect("receipt recovery must compact and commit");
        assert!(matches!(outcome, RisingReconcileOutcome::Committed { .. }));
        assert!(
            fixture
                .spool
                .list_delivered()
                .expect("delivered inventory")
                .is_empty()
        );
    }

    #[test]
    fn truncated_page_continues_and_final_page_commits_maximum_candidate() {
        let fixture = Fixture::new();
        let first = fixture.page();
        let first_candidate = cursor(4_000_000, 41);
        seal_page(
            &fixture.spool,
            &fixture.input,
            &first,
            2,
            true,
            first_candidate,
        );
        assert_eq!(
            fixture
                .coordinator
                .reconcile(&fixture.input, &fixture.spool, |ready| {
                    mark_delivered(&fixture.spool, ready)
                })
                .expect("first page must reconcile"),
            RisingReconcileOutcome::NeedsCollection {
                checkpoint_generation: 0,
                next_page: 2
            }
        );
        let rising = require_rising(&fixture.input).expect("input must be rising");
        let stored = fixture
            .coordinator
            .load_current(&fixture.input, rising)
            .expect("continued scan must load");
        let scan = stored
            .value
            .active_scan
            .as_ref()
            .expect("scan remains active");
        assert_eq!(scan.compacted_through_sequence, 1);
        assert_eq!(scan.compacted_rows, 2);
        assert!(scan.segments.is_empty());
        let second = fixture.page();
        assert_eq!(second.page, 2);
        assert_eq!(second.cursor_request.resume_after, Some(first_candidate));
        assert_eq!(second.cursor_request.committed, None);

        let final_candidate = cursor(4_000_001, 42);
        seal_page(
            &fixture.spool,
            &fixture.input,
            &second,
            1,
            false,
            final_candidate,
        );
        assert_eq!(
            fixture
                .coordinator
                .reconcile(&fixture.input, &fixture.spool, |ready| {
                    mark_delivered(&fixture.spool, ready)
                })
                .expect("final page must reconcile"),
            RisingReconcileOutcome::Committed {
                checkpoint_generation: 1,
                cursor_advanced: true
            }
        );
        assert_eq!(
            fixture
                .coordinator
                .status(&fixture.input)
                .expect("state must load")
                .committed,
            Some(final_candidate)
        );
    }

    #[test]
    fn compacted_scan_continues_beyond_the_retained_segment_limit() {
        let fixture = Fixture::new();
        let rising = require_rising(&fixture.input).expect("input must be rising");
        let key = state_key(rising);
        let boundary = u64::try_from(MAX_SEGMENTS_PER_SCAN).expect("segment limit must fit in u64");
        let boundary_candidate = cursor(4_500_000, i64::try_from(boundary).expect("limit fits"));
        let mut seeded = initial_state(&fixture.input, rising);
        let fence = AttemptFence::new(
            AttemptId::new([0xa5; 16]),
            seeded.coordinator.configuration_id,
            seeded.coordinator.generation,
        );
        seeded
            .coordinator
            .start_attempt(fence)
            .expect("seeded attempt must start");
        seeded.active_scan = Some(ActiveScan {
            attempt_id: fence.attempt_id,
            base_committed: None,
            resume_after: Some(boundary_candidate),
            maximum_candidate: Some(boundary_candidate),
            compacted_through_sequence: boundary,
            compacted_rows: boundary,
            next_page: boundary.checked_add(1).expect("page must advance"),
            complete: false,
            segments: Vec::new(),
            delivered_through_sequence: boundary,
        });
        fixture
            .coordinator
            .store
            .create(key, &seeded)
            .expect("compacted boundary state must persist");

        let context = fixture.page();
        assert_eq!(context.page, boundary + 1);
        assert_eq!(
            context.cursor_request.resume_after,
            Some(boundary_candidate)
        );
        let next_candidate = cursor(4_500_001, i64::try_from(boundary + 1).expect("limit fits"));
        seal_page(
            &fixture.spool,
            &fixture.input,
            &context,
            1,
            true,
            next_candidate,
        );

        assert_eq!(
            fixture
                .coordinator
                .reconcile(&fixture.input, &fixture.spool, |ready| {
                    mark_delivered(&fixture.spool, ready)
                })
                .expect("page beyond the retained-reference limit must reconcile"),
            RisingReconcileOutcome::NeedsCollection {
                checkpoint_generation: 0,
                next_page: boundary + 2,
            }
        );
        let stored = fixture
            .coordinator
            .load_current(&fixture.input, rising)
            .expect("compacted scan must load");
        let scan = stored
            .value
            .active_scan
            .as_ref()
            .expect("scan remains active");
        assert_eq!(scan.compacted_through_sequence, boundary + 1);
        assert_eq!(scan.compacted_rows, boundary + 1);
        assert!(scan.segments.is_empty());
        assert_eq!(scan.resume_after, Some(next_candidate));
        let restarted = fixture.reopen_coordinator();
        let resumed = match restarted
            .start_or_resume_page(&fixture.input, &fixture.spool)
            .expect("compacted scan must resume after restart")
        {
            StartPageOutcome::Ready(context) => *context,
            StartPageOutcome::AwaitingReconcile => {
                panic!("fully compacted scan must be ready for collection")
            }
        };
        assert_eq!(resumed.page, boundary + 2);
        assert_eq!(resumed.cursor_request.resume_after, Some(next_candidate));
    }

    #[test]
    fn empty_final_page_commits_without_a_segment() {
        let fixture = Fixture::new();
        let context = fixture.page();
        fixture
            .coordinator
            .record_empty_completion(
                &fixture.input,
                &context,
                &empty_collection(),
                &fixture.spool,
            )
            .expect("empty collection must persist");

        assert_eq!(
            fixture
                .coordinator
                .reconcile(&fixture.input, &fixture.spool, |_| {
                    panic!("empty collection has no delivery")
                })
                .expect("empty collection must commit"),
            RisingReconcileOutcome::Committed {
                checkpoint_generation: 1,
                cursor_advanced: false
            }
        );
        let state = fixture
            .coordinator
            .status(&fixture.input)
            .expect("state must load");
        assert_eq!(state.committed, None);
        assert!(!state.active);
    }

    #[test]
    fn completed_scan_accepts_truncated_last_segment_after_empty_tail_page() {
        let fixture = Fixture::new();
        let first = fixture.page();
        let candidate = cursor(5_000_000, 51);
        seal_page(&fixture.spool, &fixture.input, &first, 1, true, candidate);
        fixture
            .coordinator
            .reconcile(&fixture.input, &fixture.spool, |ready| {
                mark_delivered(&fixture.spool, ready)
            })
            .expect("truncated page must reconcile");
        let empty = fixture.page();
        fixture
            .coordinator
            .record_empty_completion(&fixture.input, &empty, &empty_collection(), &fixture.spool)
            .expect("empty tail page must complete scan");

        assert_eq!(
            fixture
                .coordinator
                .reconcile(&fixture.input, &fixture.spool, |_| {
                    panic!("already receipted page must not be resent")
                })
                .expect("empty tail scan must commit"),
            RisingReconcileOutcome::Committed {
                checkpoint_generation: 1,
                cursor_advanced: true
            }
        );
        assert_eq!(
            fixture
                .coordinator
                .status(&fixture.input)
                .expect("state must load")
                .committed,
            Some(candidate)
        );
    }

    #[test]
    fn orphan_with_a_different_cursor_request_is_rejected() {
        let fixture = Fixture::new();
        let context = fixture.page();
        let rising = fixture.input.rising.as_ref().expect("input must be rising");
        let mut different_request = context.cursor_request.clone();
        different_request.resume_after = Some(cursor(7_000_000, 70));
        let candidate = cursor(8_000_000, 80);
        let metadata = RisingRecoveryMetadata::new(
            1,
            false,
            rising_request_fingerprint(
                rising.cursor_identity_fingerprint.into_bytes(),
                &different_request,
            ),
            Some(candidate),
            Some(candidate),
        )
        .and_then(RisingRecoveryMetadata::encode)
        .expect("metadata must encode");
        let mut writer = fixture
            .spool
            .begin_segment(context.segment_header(1_720_000_000_123))
            .expect("segment must begin");
        writer.append_event(b"event").expect("event must append");
        writer
            .seal_with_recovery_metadata(metadata)
            .expect("segment must seal");

        let error = fixture
            .coordinator
            .reconcile(&fixture.input, &fixture.spool, |_| {
                panic!("mismatched request must not deliver")
            })
            .expect_err("mismatched request must block adoption");

        assert_eq!(error.code(), "DBX-RS-RISING-0008");
        assert_eq!(
            fixture
                .coordinator
                .status(&fixture.input)
                .expect("state must remain readable")
                .next_page,
            Some(1)
        );
    }

    #[test]
    fn stale_segment_fence_and_changed_lineage_fail_closed() {
        let fixture = Fixture::new();
        let context = fixture.page();
        let mut stale_header = context.segment_header(1_720_000_000_123);
        stale_header.configuration_fingerprint = SpoolFingerprint::new([0xff; 32]);
        let rising = fixture.input.rising.as_ref().expect("input must be rising");
        let metadata = RisingRecoveryMetadata::new(
            1,
            false,
            rising_request_fingerprint(
                rising.cursor_identity_fingerprint.into_bytes(),
                &context.cursor_request,
            ),
            Some(cursor(6_000_000, 61)),
            Some(cursor(6_000_000, 61)),
        )
        .and_then(RisingRecoveryMetadata::encode)
        .expect("metadata must encode");
        let mut writer = fixture
            .spool
            .begin_segment(stale_header)
            .expect("stale segment must begin");
        writer.append_event(b"event").expect("event must append");
        writer
            .seal_with_recovery_metadata(metadata)
            .expect("stale segment must seal");
        assert_eq!(
            fixture
                .coordinator
                .reconcile(&fixture.input, &fixture.spool, |_| {
                    panic!("stale segment must not deliver")
                })
                .expect_err("stale segment must block")
                .code(),
            "DBX-RS-RISING-0008"
        );

        let changed = fixture.modified_query_input();
        assert_eq!(
            fixture
                .coordinator
                .ensure_input(&changed, &fixture.spool)
                .expect_err("lineage change must require migration")
                .code(),
            "DBX-RS-RISING-0006"
        );
    }
}
