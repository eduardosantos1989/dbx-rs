//! Serializable, in-memory checkpoint coordination.
//!
//! A cursor is committed only after collection completes and delivery is confirmed for the same
//! attempt, configuration, generation, and row count. Collection and delivery are orthogonal and
//! may finish in either order. Failed, uncertain, incomplete, stale, or inconsistent attempts do
//! not advance the committed cursor.
//!
//! [`Snapshot`] serialization is intended for state transfer and restart tests. It is not a
//! durable persistent format yet. This crate performs no filesystem I/O and specifies no on-disk
//! layout, atomic replacement protocol, corruption policy, or rollback behavior.

#![forbid(unsafe_code)]

use std::{cmp::Ordering, fmt};

use dbx_rs_connector_sdk::TimestampIdCursor;
use serde::{Deserialize, Serialize};

/// The only snapshot representation understood by this crate.
pub const SNAPSHOT_FORMAT_VERSION: u16 = 1;

/// An opaque identifier generated for one collection and delivery attempt.
#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AttemptId([u8; 16]);

impl AttemptId {
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn into_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Debug for AttemptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AttemptId([REDACTED])")
    }
}

/// Fences an attempt to one configuration and checkpoint generation.
#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttemptFence {
    pub attempt_id: AttemptId,
    pub configuration_id: [u8; 32],
    pub generation: u64,
}

impl AttemptFence {
    #[must_use]
    pub const fn new(attempt_id: AttemptId, configuration_id: [u8; 32], generation: u64) -> Self {
        Self {
            attempt_id,
            configuration_id,
            generation,
        }
    }
}

impl fmt::Debug for AttemptFence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttemptFence")
            .field("attempt_id", &self.attempt_id)
            .field("configuration_id", &"[REDACTED]")
            .field("generation", &self.generation)
            .finish()
    }
}

/// Collection-side progress for an active attempt.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum CollectionState {
    InProgress,
    Completed {
        rows: u64,
        candidate: Option<TimestampIdCursor>,
    },
    Failed,
}

impl fmt::Debug for CollectionState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InProgress => formatter.write_str("InProgress"),
            Self::Completed { rows, candidate } => formatter
                .debug_struct("Completed")
                .field("rows", rows)
                .field("candidate", &candidate.as_ref().map(|_| "[CONFIGURED]"))
                .finish(),
            Self::Failed => formatter.write_str("Failed"),
        }
    }
}

/// Delivery-side progress for an active attempt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum DeliveryState {
    InProgress,
    Confirmed { rows: u64 },
    Failed,
    Uncertain,
}

/// One active collection/delivery attempt.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActiveAttempt {
    pub fence: AttemptFence,
    pub collection: CollectionState,
    pub delivery: DeliveryState,
}

impl fmt::Debug for ActiveAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActiveAttempt")
            .field("fence", &self.fence)
            .field("collection", &self.collection)
            .field("delivery", &self.delivery)
            .finish()
    }
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommittedAttempt {
    pub fence: AttemptFence,
    pub resulting_generation: u64,
}

impl fmt::Debug for CommittedAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommittedAttempt")
            .field("fence", &self.fence)
            .field("resulting_generation", &self.resulting_generation)
            .finish()
    }
}

/// Complete checkpoint coordinator state.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct Snapshot {
    pub format_version: u16,
    pub configuration_id: [u8; 32],
    pub generation: u64,
    pub committed: Option<TimestampIdCursor>,
    pub active_attempt: Option<ActiveAttempt>,
    pub last_committed_attempt: Option<CommittedAttempt>,
}

impl Snapshot {
    #[must_use]
    pub const fn new(
        configuration_id: [u8; 32],
        generation: u64,
        committed: Option<TimestampIdCursor>,
    ) -> Self {
        Self {
            format_version: SNAPSHOT_FORMAT_VERSION,
            configuration_id,
            generation,
            committed,
            active_attempt: None,
            last_committed_attempt: None,
        }
    }

    /// Checks the structural invariants required before any transition.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported version, inconsistent attempt fencing, an impossible
    /// committed-attempt marker, or an invalid collection candidate.
    pub fn validate(&self) -> Result<(), CheckpointError> {
        if self.format_version != SNAPSHOT_FORMAT_VERSION {
            return Err(CheckpointError::UnsupportedSnapshotVersion);
        }

        if let Some(active) = &self.active_attempt {
            if active.fence.configuration_id != self.configuration_id
                || active.fence.generation != self.generation
            {
                return Err(CheckpointError::InvalidSnapshot);
            }
            if let CollectionState::Completed { rows, candidate } = active.collection {
                validate_candidate(self.committed, rows, candidate)?;
            }
        }

        if let Some(last) = self.last_committed_attempt {
            let Some(expected_generation) = last.fence.generation.checked_add(1) else {
                return Err(CheckpointError::InvalidSnapshot);
            };
            if last.fence.configuration_id != self.configuration_id
                || expected_generation != last.resulting_generation
                || last.resulting_generation != self.generation
            {
                return Err(CheckpointError::InvalidSnapshot);
            }
        }

        Ok(())
    }

    /// Starts a new attempt at the snapshot's current fence.
    ///
    /// # Errors
    ///
    /// Returns an error for stale fencing, invalid snapshot state, or a different active attempt.
    pub fn start_attempt(&mut self, fence: AttemptFence) -> Result<StartOutcome, CheckpointError> {
        self.validate()?;
        self.require_current_context(fence)?;
        match &self.active_attempt {
            Some(active) if active.fence.attempt_id == fence.attempt_id => {
                Ok(StartOutcome::AlreadyActive)
            }
            Some(_) => Err(CheckpointError::ActiveAttemptExists),
            None => {
                self.active_attempt = Some(ActiveAttempt {
                    fence,
                    collection: CollectionState::InProgress,
                    delivery: DeliveryState::InProgress,
                });
                Ok(StartOutcome::Started)
            }
        }
    }

    /// Records a completed collection without committing its candidate.
    ///
    /// # Errors
    ///
    /// Returns an error for stale fencing, invalid candidate semantics, or a conflicting terminal
    /// collection state.
    pub fn collection_completed(
        &mut self,
        fence: AttemptFence,
        rows: u64,
        candidate: Option<TimestampIdCursor>,
    ) -> Result<RecordOutcome, CheckpointError> {
        self.validate()?;
        self.require_active_fence(fence)?;
        validate_candidate(self.committed, rows, candidate)?;

        let active = self
            .active_attempt
            .as_mut()
            .ok_or(CheckpointError::InvalidSnapshot)?;
        match &active.collection {
            CollectionState::InProgress => {
                active.collection = CollectionState::Completed { rows, candidate };
                Ok(RecordOutcome::Recorded)
            }
            CollectionState::Completed {
                rows: recorded_rows,
                candidate: recorded_candidate,
            } if *recorded_rows == rows && *recorded_candidate == candidate => {
                Ok(RecordOutcome::Unchanged)
            }
            CollectionState::Completed { .. } | CollectionState::Failed => {
                Err(CheckpointError::ConflictingCollectionState)
            }
        }
    }

    /// Marks collection as failed. A failed collection can never commit.
    ///
    /// # Errors
    ///
    /// Returns an error for stale fencing or a conflicting completed collection.
    pub fn collection_failed(
        &mut self,
        fence: AttemptFence,
    ) -> Result<RecordOutcome, CheckpointError> {
        self.validate()?;
        self.require_active_fence(fence)?;

        let active = self
            .active_attempt
            .as_mut()
            .ok_or(CheckpointError::InvalidSnapshot)?;
        match active.collection {
            CollectionState::InProgress => {
                active.collection = CollectionState::Failed;
                Ok(RecordOutcome::Recorded)
            }
            CollectionState::Failed => Ok(RecordOutcome::Unchanged),
            CollectionState::Completed { .. } => Err(CheckpointError::ConflictingCollectionState),
        }
    }

    /// Records delivery confirmation without committing a cursor.
    ///
    /// # Errors
    ///
    /// Returns an error for stale fencing or a conflicting terminal delivery state.
    pub fn delivery_confirmed(
        &mut self,
        fence: AttemptFence,
        rows: u64,
    ) -> Result<RecordOutcome, CheckpointError> {
        self.validate()?;
        self.require_active_fence(fence)?;

        let active = self
            .active_attempt
            .as_mut()
            .ok_or(CheckpointError::InvalidSnapshot)?;
        match active.delivery {
            DeliveryState::InProgress => {
                active.delivery = DeliveryState::Confirmed { rows };
                Ok(RecordOutcome::Recorded)
            }
            DeliveryState::Confirmed {
                rows: recorded_rows,
            } if recorded_rows == rows => Ok(RecordOutcome::Unchanged),
            DeliveryState::Confirmed { .. } | DeliveryState::Failed | DeliveryState::Uncertain => {
                Err(CheckpointError::ConflictingDeliveryState)
            }
        }
    }

    /// Marks delivery as failed. A failed delivery can never commit.
    ///
    /// # Errors
    ///
    /// Returns an error for stale fencing or a conflicting terminal delivery state.
    pub fn delivery_failed(
        &mut self,
        fence: AttemptFence,
    ) -> Result<RecordOutcome, CheckpointError> {
        self.record_delivery_terminal(fence, DeliveryState::Failed)
    }

    /// Marks delivery as uncertain. An uncertain delivery can never commit.
    ///
    /// # Errors
    ///
    /// Returns an error for stale fencing or a conflicting terminal delivery state.
    pub fn delivery_uncertain(
        &mut self,
        fence: AttemptFence,
    ) -> Result<RecordOutcome, CheckpointError> {
        self.record_delivery_terminal(fence, DeliveryState::Uncertain)
    }

    /// Commits a ready attempt, or reports that the same commit was already applied.
    ///
    /// # Errors
    ///
    /// Returns an error unless collection and delivery succeeded under the exact same fence and
    /// reported the same row count. Failed, uncertain, and incomplete states remain unchanged.
    pub fn commit(&mut self, fence: AttemptFence) -> Result<CommitOutcome, CheckpointError> {
        self.validate()?;

        if self
            .last_committed_attempt
            .is_some_and(|last| last.fence == fence)
        {
            return Ok(CommitOutcome::AlreadyCommitted {
                generation: self.generation,
            });
        }

        self.require_active_fence(fence)?;
        let active = self
            .active_attempt
            .as_ref()
            .ok_or(CheckpointError::InvalidSnapshot)?;
        let (collection_rows, candidate) = match active.collection {
            CollectionState::InProgress => return Err(CheckpointError::CollectionInProgress),
            CollectionState::Completed { rows, candidate } => (rows, candidate),
            CollectionState::Failed => return Err(CheckpointError::CollectionFailed),
        };
        let delivery_rows = match active.delivery {
            DeliveryState::InProgress => return Err(CheckpointError::DeliveryInProgress),
            DeliveryState::Confirmed { rows } => rows,
            DeliveryState::Failed => return Err(CheckpointError::DeliveryFailed),
            DeliveryState::Uncertain => return Err(CheckpointError::DeliveryUncertain),
        };
        if collection_rows != delivery_rows {
            return Err(CheckpointError::RowCountMismatch);
        }

        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(CheckpointError::GenerationOverflow)?;
        let cursor_advanced = match (self.committed, candidate) {
            (Some(committed), Some(candidate)) => {
                candidate.position_cmp(&committed) == Ordering::Greater
            }
            (None, Some(_)) => true,
            (_, None) => false,
        };
        if let Some(candidate) = candidate {
            self.committed = Some(candidate);
        }
        self.generation = next_generation;
        self.active_attempt = None;
        self.last_committed_attempt = Some(CommittedAttempt {
            fence,
            resulting_generation: next_generation,
        });

        Ok(CommitOutcome::Committed {
            generation: next_generation,
            cursor_advanced,
        })
    }

    /// Applies the safe restart action for the current serialized phase.
    ///
    /// A fully confirmed matching attempt is committed. Every other active attempt is discarded
    /// for replay from the existing committed cursor. The caller-provided configuration and
    /// generation fence prevent recovery under stale ownership.
    ///
    /// # Errors
    ///
    /// Returns an error for stale ownership or invalid snapshot state. No cursor is changed on
    /// error.
    pub fn recover(
        &mut self,
        configuration_id: [u8; 32],
        generation: u64,
    ) -> Result<RecoveryAction, CheckpointError> {
        self.validate()?;
        self.require_snapshot_context(configuration_id, generation)?;

        let Some(active) = self.active_attempt.as_ref() else {
            return Ok(RecoveryAction::StartNewAttempt);
        };
        let fence = active.fence;
        let action = recovery_disposition(active);

        match action {
            RecoveryDisposition::Commit => match self.commit(fence)? {
                CommitOutcome::Committed {
                    generation,
                    cursor_advanced,
                } => Ok(RecoveryAction::Committed {
                    attempt_id: fence.attempt_id,
                    generation,
                    cursor_advanced,
                }),
                CommitOutcome::AlreadyCommitted { .. } => {
                    unreachable!("an active attempt cannot already be committed")
                }
            },
            RecoveryDisposition::Replay(reason) => {
                self.active_attempt = None;
                Ok(RecoveryAction::ReplayFromCommitted {
                    attempt_id: fence.attempt_id,
                    reason,
                })
            }
        }
    }

    fn record_delivery_terminal(
        &mut self,
        fence: AttemptFence,
        terminal: DeliveryState,
    ) -> Result<RecordOutcome, CheckpointError> {
        self.validate()?;
        self.require_active_fence(fence)?;

        let active = self
            .active_attempt
            .as_mut()
            .ok_or(CheckpointError::InvalidSnapshot)?;
        match active.delivery {
            DeliveryState::InProgress => {
                active.delivery = terminal;
                Ok(RecordOutcome::Recorded)
            }
            current if current == terminal => Ok(RecordOutcome::Unchanged),
            DeliveryState::Confirmed { .. } | DeliveryState::Failed | DeliveryState::Uncertain => {
                Err(CheckpointError::ConflictingDeliveryState)
            }
        }
    }

    fn require_snapshot_context(
        &self,
        configuration_id: [u8; 32],
        generation: u64,
    ) -> Result<(), CheckpointError> {
        if configuration_id != self.configuration_id {
            return Err(CheckpointError::ConfigurationMismatch);
        }
        if generation != self.generation {
            return Err(CheckpointError::GenerationMismatch);
        }
        Ok(())
    }

    fn require_current_context(&self, fence: AttemptFence) -> Result<(), CheckpointError> {
        self.require_snapshot_context(fence.configuration_id, fence.generation)
    }

    fn require_active_fence(&self, fence: AttemptFence) -> Result<(), CheckpointError> {
        self.require_current_context(fence)?;
        let active = self
            .active_attempt
            .as_ref()
            .ok_or(CheckpointError::NoActiveAttempt)?;
        if active.fence.attempt_id != fence.attempt_id {
            return Err(CheckpointError::AttemptMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for Snapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Snapshot")
            .field("format_version", &self.format_version)
            .field("configuration_id", &"[REDACTED]")
            .field("generation", &self.generation)
            .field(
                "committed",
                &self.committed.as_ref().map(|_| "[CONFIGURED]"),
            )
            .field("active_attempt", &self.active_attempt)
            .field("last_committed_attempt", &self.last_committed_attempt)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StartOutcome {
    Started,
    AlreadyActive,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordOutcome {
    Recorded,
    Unchanged,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum CommitOutcome {
    Committed {
        generation: u64,
        cursor_advanced: bool,
    },
    AlreadyCommitted {
        generation: u64,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayReason {
    CollectionInProgress,
    DeliveryInProgress,
    CollectionFailed,
    DeliveryFailed,
    DeliveryUncertain,
    RowCountMismatch,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "action")]
pub enum RecoveryAction {
    StartNewAttempt,
    ReplayFromCommitted {
        attempt_id: AttemptId,
        reason: ReplayReason,
    },
    Committed {
        attempt_id: AttemptId,
        generation: u64,
        cursor_advanced: bool,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointError {
    UnsupportedSnapshotVersion,
    InvalidSnapshot,
    ConfigurationMismatch,
    GenerationMismatch,
    AttemptMismatch,
    ActiveAttemptExists,
    NoActiveAttempt,
    MissingCandidate,
    CandidateForEmptyCollection,
    CandidateRegression,
    ConflictingCollectionState,
    ConflictingDeliveryState,
    CollectionInProgress,
    CollectionFailed,
    DeliveryInProgress,
    DeliveryFailed,
    DeliveryUncertain,
    RowCountMismatch,
    GenerationOverflow,
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsupportedSnapshotVersion => "checkpoint snapshot version is unsupported",
            Self::InvalidSnapshot => "checkpoint snapshot invariants are invalid",
            Self::ConfigurationMismatch => "checkpoint configuration fence is stale",
            Self::GenerationMismatch => "checkpoint generation fence is stale",
            Self::AttemptMismatch => "checkpoint attempt identifier is stale",
            Self::ActiveAttemptExists => "a different checkpoint attempt is already active",
            Self::NoActiveAttempt => "there is no active checkpoint attempt",
            Self::MissingCandidate => "a non-empty collection requires a cursor candidate",
            Self::CandidateForEmptyCollection => {
                "an empty collection must not provide a cursor candidate"
            }
            Self::CandidateRegression => "the cursor candidate regresses committed state",
            Self::ConflictingCollectionState => {
                "collection already has a conflicting terminal state"
            }
            Self::ConflictingDeliveryState => "delivery already has a conflicting terminal state",
            Self::CollectionInProgress => "collection has not completed",
            Self::CollectionFailed => "collection failed",
            Self::DeliveryInProgress => "delivery has not been confirmed",
            Self::DeliveryFailed => "delivery failed",
            Self::DeliveryUncertain => "delivery result is uncertain",
            Self::RowCountMismatch => "collection and delivery row counts differ",
            Self::GenerationOverflow => "checkpoint generation is exhausted",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CheckpointError {}

#[derive(Clone, Copy)]
enum RecoveryDisposition {
    Commit,
    Replay(ReplayReason),
}

fn recovery_disposition(active: &ActiveAttempt) -> RecoveryDisposition {
    match (&active.collection, active.delivery) {
        (CollectionState::Failed, _) => RecoveryDisposition::Replay(ReplayReason::CollectionFailed),
        (_, DeliveryState::Failed) => RecoveryDisposition::Replay(ReplayReason::DeliveryFailed),
        (_, DeliveryState::Uncertain) => {
            RecoveryDisposition::Replay(ReplayReason::DeliveryUncertain)
        }
        (CollectionState::InProgress, _) => {
            RecoveryDisposition::Replay(ReplayReason::CollectionInProgress)
        }
        (CollectionState::Completed { .. }, DeliveryState::InProgress) => {
            RecoveryDisposition::Replay(ReplayReason::DeliveryInProgress)
        }
        (
            CollectionState::Completed {
                rows: collection_rows,
                ..
            },
            DeliveryState::Confirmed {
                rows: delivery_rows,
            },
        ) if collection_rows != &delivery_rows => {
            RecoveryDisposition::Replay(ReplayReason::RowCountMismatch)
        }
        (CollectionState::Completed { .. }, DeliveryState::Confirmed { .. }) => {
            RecoveryDisposition::Commit
        }
    }
}

fn validate_candidate(
    committed: Option<TimestampIdCursor>,
    rows: u64,
    candidate: Option<TimestampIdCursor>,
) -> Result<(), CheckpointError> {
    if rows == 0 {
        return if candidate.is_none() {
            Ok(())
        } else {
            Err(CheckpointError::CandidateForEmptyCollection)
        };
    }

    let candidate = candidate.ok_or(CheckpointError::MissingCandidate)?;
    if committed.is_some_and(|committed| candidate.position_cmp(&committed) == Ordering::Less) {
        return Err(CheckpointError::CandidateRegression);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIGURATION: [u8; 32] = [0x31; 32];
    const OTHER_CONFIGURATION: [u8; 32] = [0x42; 32];
    const START_GENERATION: u64 = 7;
    const COMMITTED: TimestampIdCursor = TimestampIdCursor::new(1_000, 10);
    const CANDIDATE: TimestampIdCursor = TimestampIdCursor::new(1_001, 11);

    fn attempt(byte: u8, generation: u64) -> AttemptFence {
        AttemptFence::new(AttemptId::new([byte; 16]), CONFIGURATION, generation)
    }

    fn active_snapshot() -> (Snapshot, AttemptFence) {
        let mut snapshot = Snapshot::new(CONFIGURATION, START_GENERATION, Some(COMMITTED));
        let fence = attempt(0x11, START_GENERATION);
        assert_eq!(snapshot.start_attempt(fence), Ok(StartOutcome::Started));
        (snapshot, fence)
    }

    fn round_trip(snapshot: &Snapshot) -> Snapshot {
        let bytes = serde_json::to_vec(snapshot).expect("snapshot serializes");
        serde_json::from_slice(&bytes).expect("snapshot deserializes")
    }

    #[test]
    fn collection_and_delivery_may_finish_in_either_order() {
        for delivery_first in [false, true] {
            let (mut snapshot, fence) = active_snapshot();
            if delivery_first {
                assert_eq!(
                    snapshot.delivery_confirmed(fence, 2),
                    Ok(RecordOutcome::Recorded)
                );
                assert_eq!(
                    snapshot.collection_completed(fence, 2, Some(CANDIDATE)),
                    Ok(RecordOutcome::Recorded)
                );
            } else {
                assert_eq!(
                    snapshot.collection_completed(fence, 2, Some(CANDIDATE)),
                    Ok(RecordOutcome::Recorded)
                );
                assert_eq!(
                    snapshot.delivery_confirmed(fence, 2),
                    Ok(RecordOutcome::Recorded)
                );
            }

            assert_eq!(snapshot.committed, Some(COMMITTED));
            assert_eq!(
                snapshot.commit(fence),
                Ok(CommitOutcome::Committed {
                    generation: START_GENERATION + 1,
                    cursor_advanced: true,
                })
            );
            assert_eq!(snapshot.committed, Some(CANDIDATE));
            assert!(snapshot.active_attempt.is_none());
        }
    }

    #[test]
    fn commit_is_idempotent_after_the_attempt_is_cleared() {
        let (mut snapshot, fence) = active_snapshot();
        snapshot
            .collection_completed(fence, 1, Some(CANDIDATE))
            .expect("collection completes");
        snapshot
            .delivery_confirmed(fence, 1)
            .expect("delivery confirms");

        snapshot.commit(fence).expect("first commit succeeds");
        let after_first_commit = snapshot.clone();
        assert_eq!(
            snapshot.commit(fence),
            Ok(CommitOutcome::AlreadyCommitted {
                generation: START_GENERATION + 1,
            })
        );
        assert_eq!(snapshot, after_first_commit);
    }

    #[test]
    fn incomplete_failed_and_uncertain_attempts_never_advance() {
        let cases = [
            (CollectionState::InProgress, DeliveryState::InProgress),
            (
                CollectionState::Failed,
                DeliveryState::Confirmed { rows: 1 },
            ),
            (
                CollectionState::Completed {
                    rows: 1,
                    candidate: Some(CANDIDATE),
                },
                DeliveryState::Failed,
            ),
            (
                CollectionState::Completed {
                    rows: 1,
                    candidate: Some(CANDIDATE),
                },
                DeliveryState::Uncertain,
            ),
        ];

        for (collection, delivery) in cases {
            let (mut snapshot, fence) = active_snapshot();
            let active = snapshot.active_attempt.as_mut().expect("attempt is active");
            active.collection = collection;
            active.delivery = delivery;
            assert!(snapshot.commit(fence).is_err());
            assert_eq!(snapshot.committed, Some(COMMITTED));
            assert_eq!(snapshot.generation, START_GENERATION);
            assert!(snapshot.active_attempt.is_some());
        }
    }

    #[test]
    fn stale_attempt_generation_and_configuration_are_rejected() {
        let (mut snapshot, fence) = active_snapshot();

        let wrong_attempt = attempt(0x22, START_GENERATION);
        assert_eq!(
            snapshot.delivery_confirmed(wrong_attempt, 1),
            Err(CheckpointError::AttemptMismatch)
        );

        let stale_generation = attempt(0x11, START_GENERATION - 1);
        assert_eq!(
            snapshot.delivery_confirmed(stale_generation, 1),
            Err(CheckpointError::GenerationMismatch)
        );

        let wrong_configuration =
            AttemptFence::new(fence.attempt_id, OTHER_CONFIGURATION, START_GENERATION);
        assert_eq!(
            snapshot.delivery_confirmed(wrong_configuration, 1),
            Err(CheckpointError::ConfigurationMismatch)
        );
        assert_eq!(snapshot.committed, Some(COMMITTED));
    }

    #[test]
    fn candidate_regression_and_missing_candidate_fail_closed() {
        let (mut snapshot, fence) = active_snapshot();
        assert_eq!(
            snapshot.collection_completed(fence, 1, Some(TimestampIdCursor::new(999, i64::MAX)),),
            Err(CheckpointError::CandidateRegression)
        );
        assert_eq!(
            snapshot.collection_completed(fence, 1, None),
            Err(CheckpointError::MissingCandidate)
        );
        assert_eq!(snapshot.committed, Some(COMMITTED));
        assert_eq!(snapshot.generation, START_GENERATION);
    }

    #[test]
    fn equal_candidate_is_valid_for_overlap_replay() {
        let (mut snapshot, fence) = active_snapshot();
        snapshot
            .collection_completed(fence, 3, Some(COMMITTED))
            .expect("replayed rows may end at the committed tuple");
        snapshot
            .delivery_confirmed(fence, 3)
            .expect("delivery confirms");

        assert_eq!(
            snapshot.commit(fence),
            Ok(CommitOutcome::Committed {
                generation: START_GENERATION + 1,
                cursor_advanced: false,
            })
        );
        assert_eq!(snapshot.committed, Some(COMMITTED));
    }

    #[test]
    fn empty_result_commits_without_moving_the_cursor() {
        let (mut snapshot, fence) = active_snapshot();
        snapshot
            .collection_completed(fence, 0, None)
            .expect("empty collection completes");
        snapshot
            .delivery_confirmed(fence, 0)
            .expect("empty delivery confirms");

        assert_eq!(
            snapshot.commit(fence),
            Ok(CommitOutcome::Committed {
                generation: START_GENERATION + 1,
                cursor_advanced: false,
            })
        );
        assert_eq!(snapshot.committed, Some(COMMITTED));
        assert_eq!(snapshot.generation, START_GENERATION + 1);
    }

    #[test]
    fn empty_result_rejects_a_candidate() {
        let (mut snapshot, fence) = active_snapshot();
        assert_eq!(
            snapshot.collection_completed(fence, 0, Some(CANDIDATE)),
            Err(CheckpointError::CandidateForEmptyCollection)
        );
    }

    #[test]
    fn row_mismatch_cannot_commit() {
        let (mut snapshot, fence) = active_snapshot();
        snapshot
            .collection_completed(fence, 2, Some(CANDIDATE))
            .expect("collection completes");
        snapshot
            .delivery_confirmed(fence, 1)
            .expect("delivery records independently");

        assert_eq!(
            snapshot.commit(fence),
            Err(CheckpointError::RowCountMismatch)
        );
        assert_eq!(snapshot.committed, Some(COMMITTED));
        assert_eq!(snapshot.generation, START_GENERATION);
    }

    #[test]
    fn restart_without_an_attempt_starts_fresh() {
        let snapshot = Snapshot::new(CONFIGURATION, START_GENERATION, Some(COMMITTED));
        let mut restored = round_trip(&snapshot);

        assert_eq!(
            restored.recover(CONFIGURATION, START_GENERATION),
            Ok(RecoveryAction::StartNewAttempt)
        );
        assert_eq!(restored, snapshot);
    }

    #[test]
    fn restart_replays_each_incomplete_or_terminal_phase_without_advancing() {
        let phases = [
            (
                CollectionState::InProgress,
                DeliveryState::InProgress,
                ReplayReason::CollectionInProgress,
            ),
            (
                CollectionState::Completed {
                    rows: 1,
                    candidate: Some(CANDIDATE),
                },
                DeliveryState::InProgress,
                ReplayReason::DeliveryInProgress,
            ),
            (
                CollectionState::InProgress,
                DeliveryState::Confirmed { rows: 1 },
                ReplayReason::CollectionInProgress,
            ),
            (
                CollectionState::Failed,
                DeliveryState::InProgress,
                ReplayReason::CollectionFailed,
            ),
            (
                CollectionState::Completed {
                    rows: 1,
                    candidate: Some(CANDIDATE),
                },
                DeliveryState::Failed,
                ReplayReason::DeliveryFailed,
            ),
            (
                CollectionState::Completed {
                    rows: 1,
                    candidate: Some(CANDIDATE),
                },
                DeliveryState::Uncertain,
                ReplayReason::DeliveryUncertain,
            ),
        ];

        for (collection, delivery, reason) in phases {
            let (snapshot, fence) = active_snapshot();
            let mut restored = round_trip(&Snapshot {
                active_attempt: Some(ActiveAttempt {
                    fence,
                    collection,
                    delivery,
                }),
                ..snapshot
            });

            assert_eq!(
                restored.recover(CONFIGURATION, START_GENERATION),
                Ok(RecoveryAction::ReplayFromCommitted {
                    attempt_id: fence.attempt_id,
                    reason,
                })
            );
            assert_eq!(restored.committed, Some(COMMITTED));
            assert_eq!(restored.generation, START_GENERATION);
            assert!(restored.active_attempt.is_none());
        }
    }

    #[test]
    fn restart_commits_a_ready_attempt_in_both_completion_orders() {
        for delivery_first in [false, true] {
            let (mut snapshot, fence) = active_snapshot();
            if delivery_first {
                snapshot
                    .delivery_confirmed(fence, 1)
                    .expect("delivery confirms first");
                snapshot
                    .collection_completed(fence, 1, Some(CANDIDATE))
                    .expect("collection completes second");
            } else {
                snapshot
                    .collection_completed(fence, 1, Some(CANDIDATE))
                    .expect("collection completes first");
                snapshot
                    .delivery_confirmed(fence, 1)
                    .expect("delivery confirms second");
            }
            let mut restored = round_trip(&snapshot);

            assert_eq!(
                restored.recover(CONFIGURATION, START_GENERATION),
                Ok(RecoveryAction::Committed {
                    attempt_id: fence.attempt_id,
                    generation: START_GENERATION + 1,
                    cursor_advanced: true,
                })
            );
            assert_eq!(restored.committed, Some(CANDIDATE));
            assert_eq!(restored.generation, START_GENERATION + 1);
            assert!(restored.active_attempt.is_none());
        }
    }

    #[test]
    fn restart_discards_row_count_mismatch() {
        let (mut snapshot, fence) = active_snapshot();
        snapshot
            .collection_completed(fence, 2, Some(CANDIDATE))
            .expect("collection completes");
        snapshot
            .delivery_confirmed(fence, 1)
            .expect("delivery records independently");
        let mut restored = round_trip(&snapshot);

        assert_eq!(
            restored.recover(CONFIGURATION, START_GENERATION),
            Ok(RecoveryAction::ReplayFromCommitted {
                attempt_id: fence.attempt_id,
                reason: ReplayReason::RowCountMismatch,
            })
        );
        assert_eq!(restored.committed, Some(COMMITTED));
        assert_eq!(restored.generation, START_GENERATION);
        assert!(restored.active_attempt.is_none());
    }

    #[test]
    fn restart_rejects_stale_configuration_and_generation() {
        let (snapshot, _) = active_snapshot();

        let mut wrong_configuration = round_trip(&snapshot);
        assert_eq!(
            wrong_configuration.recover(OTHER_CONFIGURATION, START_GENERATION),
            Err(CheckpointError::ConfigurationMismatch)
        );
        assert_eq!(wrong_configuration, snapshot);

        let mut stale_generation = round_trip(&snapshot);
        assert_eq!(
            stale_generation.recover(CONFIGURATION, START_GENERATION - 1),
            Err(CheckpointError::GenerationMismatch)
        );
        assert_eq!(stale_generation, snapshot);
    }

    #[test]
    fn deserialized_candidate_regression_is_rejected_before_recovery() {
        let (snapshot, fence) = active_snapshot();
        let corrupted = Snapshot {
            active_attempt: Some(ActiveAttempt {
                fence,
                collection: CollectionState::Completed {
                    rows: 1,
                    candidate: Some(TimestampIdCursor::new(999, i64::MAX)),
                },
                delivery: DeliveryState::Confirmed { rows: 1 },
            }),
            ..snapshot
        };
        let mut restored = round_trip(&corrupted);

        assert_eq!(
            restored.recover(CONFIGURATION, START_GENERATION),
            Err(CheckpointError::CandidateRegression)
        );
        assert_eq!(restored.committed, Some(COMMITTED));
        assert_eq!(restored.generation, START_GENERATION);
    }

    #[test]
    fn debug_output_redacts_configuration_cursor_and_attempt_values() {
        let (mut snapshot, fence) = active_snapshot();
        snapshot
            .collection_completed(fence, 1, Some(CANDIDATE))
            .expect("collection completes");
        let debug = format!("{snapshot:?}");

        assert!(!debug.contains("1000"));
        assert!(!debug.contains("1001"));
        assert!(!debug.contains("31, 31"));
        assert!(!debug.contains("17, 17"));
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("[CONFIGURED]"));
    }

    #[test]
    fn unsupported_version_and_invalid_embedded_fence_fail_closed() {
        let mut unsupported = Snapshot::new(CONFIGURATION, START_GENERATION, Some(COMMITTED));
        unsupported.format_version += 1;
        assert_eq!(
            unsupported.validate(),
            Err(CheckpointError::UnsupportedSnapshotVersion)
        );

        let (mut invalid, _) = active_snapshot();
        invalid
            .active_attempt
            .as_mut()
            .expect("active")
            .fence
            .generation -= 1;
        assert_eq!(invalid.validate(), Err(CheckpointError::InvalidSnapshot));
    }
}
