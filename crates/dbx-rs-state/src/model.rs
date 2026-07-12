use std::cmp::Ordering;
use std::collections::HashSet;
use std::fmt;

use dbx_rs_checkpoint::{AttemptId, CollectionState, SNAPSHOT_FORMAT_VERSION, Snapshot};
use dbx_rs_connector_sdk::TimestampIdCursor;
use ring::digest::{Context, SHA256};
use serde::{Deserialize, Serialize};

pub const DURABLE_STATE_FORMAT_VERSION: u16 = 1;
pub const MAX_SEGMENTS_PER_SCAN: usize = 4_096;

const STATE_KEY_DOMAIN: &[u8] = b"dbx-rs-state-key-v1\0";
const CONFIGURATION_FENCE_DOMAIN: &[u8] = b"dbx-rs-configuration-fence-v1\0";

#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct InputId([u8; 16]);

impl InputId {
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn into_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Debug for InputId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InputId([REDACTED])")
    }
}

#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Fingerprint([REDACTED])")
    }
}

/// Derives the checkpoint coordinator fence for one persisted configuration incarnation.
///
/// The monotonic generation is included so returning to an earlier configuration fingerprint does
/// not make attempts created by that earlier incarnation current again.
#[must_use]
pub fn configuration_fence_id(
    configuration_fingerprint: Fingerprint,
    configuration_generation: u64,
) -> [u8; 32] {
    let mut context = Context::new(&SHA256);
    context.update(CONFIGURATION_FENCE_DOMAIN);
    context.update(&configuration_fingerprint.into_bytes());
    context.update(&configuration_generation.to_be_bytes());
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(context.finish().as_ref());
    bytes
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct StateKey([u8; 32]);

impl StateKey {
    #[must_use]
    pub fn for_input(input_id: InputId) -> Self {
        let mut context = Context::new(&SHA256);
        context.update(STATE_KEY_DOMAIN);
        context.update(&input_id.into_bytes());
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(context.finish().as_ref());
        Self(bytes)
    }

    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    pub(crate) fn directory_name(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut value = String::with_capacity(64);
        for byte in self.0 {
            value.push(char::from(HEX[usize::from(byte >> 4)]));
            value.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        value
    }
}

impl fmt::Debug for StateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StateKey([REDACTED])")
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct SegmentRef {
    segment_id: [u8; 16],
    sequence: u64,
    page: u64,
    rows: u64,
    digest: [u8; 32],
}

impl SegmentRef {
    #[must_use]
    pub const fn new(
        segment_id: [u8; 16],
        sequence: u64,
        page: u64,
        rows: u64,
        digest: [u8; 32],
    ) -> Self {
        Self {
            segment_id,
            sequence,
            page,
            rows,
            digest,
        }
    }

    #[must_use]
    pub const fn segment_id(&self) -> [u8; 16] {
        self.segment_id
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn page(&self) -> u64 {
        self.page
    }

    #[must_use]
    pub const fn rows(&self) -> u64 {
        self.rows
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

impl fmt::Debug for SegmentRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SegmentRef")
            .field("segment_id", &"[REDACTED]")
            .field("sequence", &self.sequence)
            .field("page", &self.page)
            .field("rows", &self.rows)
            .field("digest", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActiveScan {
    pub attempt_id: AttemptId,
    pub base_committed: Option<TimestampIdCursor>,
    pub resume_after: Option<TimestampIdCursor>,
    pub maximum_candidate: Option<TimestampIdCursor>,
    pub next_page: u64,
    pub complete: bool,
    pub segments: Vec<SegmentRef>,
}

impl fmt::Debug for ActiveScan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActiveScan")
            .field("attempt_id", &self.attempt_id)
            .field(
                "base_committed",
                &self.base_committed.as_ref().map(|_| "[CONFIGURED]"),
            )
            .field(
                "resume_after",
                &self.resume_after.as_ref().map(|_| "[CONFIGURED]"),
            )
            .field(
                "maximum_candidate",
                &self.maximum_candidate.as_ref().map(|_| "[CONFIGURED]"),
            )
            .field("next_page", &self.next_page)
            .field("complete", &self.complete)
            .field("segments", &self.segments)
            .finish()
    }
}

impl ActiveScan {
    fn validate(&self, snapshot: &Snapshot) -> Result<(), StateValidationError> {
        let active = snapshot
            .active_attempt
            .as_ref()
            .ok_or(StateValidationError::ScanWithoutActiveAttempt)?;
        if active.fence.attempt_id != self.attempt_id {
            return Err(StateValidationError::ScanAttemptMismatch);
        }
        if self.base_committed != snapshot.committed {
            return Err(StateValidationError::ScanBaseMismatch);
        }
        if self.next_page == 0 {
            return Err(StateValidationError::InvalidNextPage);
        }
        if self.segments.len() > MAX_SEGMENTS_PER_SCAN {
            return Err(StateValidationError::TooManySegments);
        }
        if self.segments.is_empty() {
            if self.resume_after.is_some() || self.maximum_candidate.is_some() {
                return Err(StateValidationError::UnexpectedScanCursor);
            }
        } else if self.resume_after.is_none() {
            return Err(StateValidationError::MissingResumeCursor);
        }
        if let (Some(maximum), Some(resume)) = (self.maximum_candidate, self.resume_after)
            && maximum.position_cmp(&resume) == Ordering::Less
        {
            return Err(StateValidationError::CandidateBehindResume);
        }
        if let (Some(committed), Some(maximum)) = (self.base_committed, self.maximum_candidate)
            && maximum.position_cmp(&committed) == Ordering::Less
        {
            return Err(StateValidationError::CandidateRegression);
        }

        let mut ids = HashSet::with_capacity(self.segments.len());
        let mut expected_sequence = 1_u64;
        let mut expected_page = 0_u64;
        let mut sealed_rows = 0_u64;
        for segment in &self.segments {
            if segment.sequence == 0
                || segment.page == 0
                || segment.page >= self.next_page
                || segment.sequence != expected_sequence
                || !(segment.page == expected_page || segment.page == expected_page + 1)
                || segment.rows == 0
            {
                return Err(StateValidationError::InvalidSegmentOrder);
            }
            if !ids.insert(segment.segment_id) {
                return Err(StateValidationError::DuplicateSegment);
            }
            sealed_rows = sealed_rows
                .checked_add(segment.rows)
                .ok_or(StateValidationError::RowCountOverflow)?;
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(StateValidationError::InvalidSegmentOrder)?;
            expected_page = segment.page;
        }
        if !self.segments.is_empty() && expected_page + 1 != self.next_page {
            return Err(StateValidationError::InvalidSegmentOrder);
        }
        if sealed_rows > 0 && self.maximum_candidate.is_none() {
            return Err(StateValidationError::MissingMaximumCandidate);
        }

        match &active.collection {
            CollectionState::Completed { rows, candidate } => {
                if !self.complete
                    || *rows != sealed_rows
                    || *candidate != self.maximum_candidate
                    || (*rows > 0 && self.resume_after.is_none())
                {
                    return Err(StateValidationError::ScanCompletionMismatch);
                }
            }
            CollectionState::InProgress | CollectionState::Failed if self.complete => {
                return Err(StateValidationError::ScanCompletionMismatch);
            }
            CollectionState::InProgress | CollectionState::Failed => {}
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct DurableInputState {
    pub format_version: u16,
    pub input_id: InputId,
    pub query_fingerprint: Fingerprint,
    pub cursor_identity_fingerprint: Fingerprint,
    pub configuration_fingerprint: Fingerprint,
    pub configuration_generation: u64,
    pub coordinator: Snapshot,
    pub active_scan: Option<ActiveScan>,
}

impl DurableInputState {
    #[must_use]
    pub const fn new(
        input_id: InputId,
        query_fingerprint: Fingerprint,
        cursor_identity_fingerprint: Fingerprint,
        configuration_fingerprint: Fingerprint,
        configuration_generation: u64,
        coordinator: Snapshot,
        active_scan: Option<ActiveScan>,
    ) -> Self {
        Self {
            format_version: DURABLE_STATE_FORMAT_VERSION,
            input_id,
            query_fingerprint,
            cursor_identity_fingerprint,
            configuration_fingerprint,
            configuration_generation,
            coordinator,
            active_scan,
        }
    }

    /// Validates the persistent state and its coordinator/scan relationships.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported format or inconsistent fencing, cursor, page, segment,
    /// or collection state.
    pub fn validate(&self) -> Result<(), StateValidationError> {
        if self.format_version != DURABLE_STATE_FORMAT_VERSION {
            return Err(StateValidationError::UnsupportedStateVersion);
        }
        if self.configuration_generation == 0 {
            return Err(StateValidationError::InvalidConfigurationGeneration);
        }
        if self.coordinator.format_version != SNAPSHOT_FORMAT_VERSION {
            return Err(StateValidationError::UnsupportedCoordinatorVersion);
        }
        self.coordinator
            .validate()
            .map_err(|_| StateValidationError::InvalidCoordinator)?;
        let expected_fence = configuration_fence_id(
            self.configuration_fingerprint,
            self.configuration_generation,
        );
        if self.coordinator.configuration_id != expected_fence {
            return Err(StateValidationError::ConfigurationFenceMismatch);
        }
        if let Some(scan) = &self.active_scan {
            scan.validate(&self.coordinator)?;
        }
        Ok(())
    }
}

impl fmt::Debug for DurableInputState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableInputState")
            .field("format_version", &self.format_version)
            .field("input_id", &self.input_id)
            .field("query_fingerprint", &self.query_fingerprint)
            .field(
                "cursor_identity_fingerprint",
                &self.cursor_identity_fingerprint,
            )
            .field("configuration_fingerprint", &self.configuration_fingerprint)
            .field("configuration_generation", &self.configuration_generation)
            .field("coordinator", &self.coordinator)
            .field("active_scan", &self.active_scan)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateValidationError {
    UnsupportedStateVersion,
    UnsupportedCoordinatorVersion,
    InvalidConfigurationGeneration,
    InvalidCoordinator,
    ConfigurationFenceMismatch,
    ScanWithoutActiveAttempt,
    ScanAttemptMismatch,
    ScanBaseMismatch,
    InvalidNextPage,
    TooManySegments,
    MissingResumeCursor,
    UnexpectedScanCursor,
    MissingMaximumCandidate,
    CandidateBehindResume,
    CandidateRegression,
    InvalidSegmentOrder,
    DuplicateSegment,
    RowCountOverflow,
    ScanCompletionMismatch,
}

impl fmt::Display for StateValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsupportedStateVersion => "durable state version is unsupported",
            Self::UnsupportedCoordinatorVersion => "checkpoint coordinator version is unsupported",
            Self::InvalidConfigurationGeneration => "configuration generation is invalid",
            Self::InvalidCoordinator => "checkpoint coordinator state is invalid",
            Self::ConfigurationFenceMismatch => "configuration fingerprint fence is inconsistent",
            Self::ScanWithoutActiveAttempt => "scan has no active checkpoint attempt",
            Self::ScanAttemptMismatch => "scan attempt fence is inconsistent",
            Self::ScanBaseMismatch => "scan base does not match the committed cursor",
            Self::InvalidNextPage => "scan page state is invalid",
            Self::TooManySegments => "scan segment count exceeds the hard limit",
            Self::MissingResumeCursor => "sealed scan progress requires a resume cursor",
            Self::UnexpectedScanCursor => "scan cursors require sealed progress",
            Self::MissingMaximumCandidate => {
                "non-empty sealed scan progress requires a maximum candidate"
            }
            Self::CandidateBehindResume => "scan candidate is behind its resume cursor",
            Self::CandidateRegression => "scan candidate regresses the committed cursor",
            Self::InvalidSegmentOrder => "scan segments are not in canonical order",
            Self::DuplicateSegment => "scan contains a duplicate segment",
            Self::RowCountOverflow => "scan row accounting overflowed",
            Self::ScanCompletionMismatch => "scan and collection completion are inconsistent",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for StateValidationError {}

#[cfg(test)]
mod tests {
    use dbx_rs_checkpoint::{AttemptFence, StartOutcome};

    use super::*;

    const CONFIGURATION: [u8; 32] = [0x31; 32];

    fn configuration_fingerprint() -> Fingerprint {
        Fingerprint::new(CONFIGURATION)
    }

    fn configuration_fence() -> [u8; 32] {
        configuration_fence_id(configuration_fingerprint(), 1)
    }

    fn state() -> DurableInputState {
        DurableInputState::new(
            InputId::new([0x11; 16]),
            Fingerprint::new([0x22; 32]),
            Fingerprint::new([0x23; 32]),
            configuration_fingerprint(),
            1,
            Snapshot::new(
                configuration_fence(),
                7,
                Some(TimestampIdCursor::new(1_000, 10)),
            ),
            None,
        )
    }

    #[test]
    fn identifiers_and_debug_output_are_redacted() {
        let state = state();
        let debug = format!("{state:?}");
        assert!(!debug.contains("11111111"));
        assert!(!debug.contains("22222222"));
        assert!(debug.contains("[REDACTED]"));
        assert_eq!(
            StateKey::for_input(state.input_id).directory_name().len(),
            64
        );
    }

    #[test]
    fn configuration_fence_changes_for_every_generation() {
        let fingerprint = configuration_fingerprint();
        assert_eq!(
            configuration_fence_id(fingerprint, 1),
            configuration_fence_id(fingerprint, 1)
        );
        assert_ne!(
            configuration_fence_id(fingerprint, 1),
            configuration_fence_id(fingerprint, 2)
        );
    }

    #[test]
    fn scan_must_match_active_attempt_and_completed_accounting() {
        let mut state = state();
        let fence = AttemptFence::new(
            AttemptId::new([0x44; 16]),
            configuration_fence(),
            state.coordinator.generation,
        );
        assert_eq!(
            state.coordinator.start_attempt(fence),
            Ok(StartOutcome::Started)
        );
        let candidate = TimestampIdCursor::new(1_001, 11);
        state.active_scan = Some(ActiveScan {
            attempt_id: fence.attempt_id,
            base_committed: state.coordinator.committed,
            resume_after: Some(candidate),
            maximum_candidate: Some(candidate),
            next_page: 2,
            complete: false,
            segments: vec![SegmentRef::new([0x51; 16], 1, 1, 1, [0x61; 32])],
        });
        assert_eq!(state.validate(), Ok(()));

        state
            .coordinator
            .collection_completed(fence, 1, Some(candidate))
            .expect("collection completion must be accepted");
        assert_eq!(
            state.validate(),
            Err(StateValidationError::ScanCompletionMismatch)
        );
        state.active_scan.as_mut().expect("scan exists").complete = true;
        assert_eq!(state.validate(), Ok(()));
    }

    #[test]
    fn scan_rejects_duplicate_or_out_of_order_segments() {
        let mut state = state();
        let fence = AttemptFence::new(
            AttemptId::new([0x44; 16]),
            configuration_fence(),
            state.coordinator.generation,
        );
        state
            .coordinator
            .start_attempt(fence)
            .expect("attempt starts");
        let candidate = TimestampIdCursor::new(1_001, 11);
        let segment = SegmentRef::new([0x51; 16], 1, 1, 1, [0x61; 32]);
        state.active_scan = Some(ActiveScan {
            attempt_id: fence.attempt_id,
            base_committed: state.coordinator.committed,
            resume_after: Some(candidate),
            maximum_candidate: Some(candidate),
            next_page: 2,
            complete: false,
            segments: vec![segment.clone(), segment],
        });
        assert!(matches!(
            state.validate(),
            Err(StateValidationError::InvalidSegmentOrder | StateValidationError::DuplicateSegment)
        ));
    }
}
