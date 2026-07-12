use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{BatchId, Fingerprint, InputKey, SpoolError};

pub const MIN_SEGMENT_BYTES: u64 = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpoolLimits {
    pub(crate) segment: u64,
    pub(crate) input: u64,
    pub(crate) global: u64,
}

impl SpoolLimits {
    /// Constructs relationally checked spool limits.
    ///
    /// # Errors
    ///
    /// Returns an error for a segment too small to contain the format or for limits that are not
    /// monotonically ordered.
    pub const fn new(
        segment_max_bytes: u64,
        input_max_bytes: u64,
        global_max_bytes: u64,
    ) -> Result<Self, SpoolError> {
        if segment_max_bytes < MIN_SEGMENT_BYTES
            || segment_max_bytes > input_max_bytes
            || input_max_bytes > global_max_bytes
        {
            return Err(SpoolError::new(
                "DBX-RS-SPOOL-LIMIT-0001",
                "limit_validate",
                "spool limits are invalid",
            ));
        }
        Ok(Self {
            segment: segment_max_bytes,
            input: input_max_bytes,
            global: global_max_bytes,
        })
    }

    #[must_use]
    pub const fn segment_max_bytes(self) -> u64 {
        self.segment
    }

    #[must_use]
    pub const fn input_max_bytes(self) -> u64 {
        self.input
    }

    #[must_use]
    pub const fn global_max_bytes(self) -> u64 {
        self.global
    }
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub struct SegmentHeader {
    pub input_key: InputKey,
    pub configuration_fingerprint: Fingerprint,
    pub configuration_generation: u64,
    pub batch_id: BatchId,
    pub batch_sequence: u64,
    pub segment_sequence: u64,
    pub created_epoch_millis: u64,
}

impl std::fmt::Debug for SegmentHeader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SegmentHeader")
            .field("input_key", &self.input_key)
            .field("configuration_fingerprint", &self.configuration_fingerprint)
            .field("configuration_generation", &self.configuration_generation)
            .field("batch_id", &self.batch_id)
            .field("batch_sequence", &self.batch_sequence)
            .field("segment_sequence", &self.segment_sequence)
            .field("created_epoch_millis", &self.created_epoch_millis)
            .finish()
    }
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub struct SegmentSummary {
    pub event_count: u64,
    pub plaintext_bytes: u64,
    #[serde(skip)]
    pub(crate) stream_digest: [u8; 32],
}

impl std::fmt::Debug for SegmentSummary {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SegmentSummary")
            .field("event_count", &self.event_count)
            .field("plaintext_bytes", &self.plaintext_bytes)
            .field("stream_digest", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SpoolUsage {
    stored: u64,
    reserved: u64,
    stored_by_input: BTreeMap<InputKey, u64>,
    reserved_by_input: BTreeMap<InputKey, u64>,
}

impl SpoolUsage {
    #[must_use]
    pub const fn stored_bytes(&self) -> u64 {
        self.stored
    }

    #[must_use]
    pub const fn reserved_bytes(&self) -> u64 {
        self.reserved
    }

    #[must_use]
    pub fn input_stored_bytes(&self, input_key: InputKey) -> u64 {
        self.stored_by_input.get(&input_key).copied().unwrap_or(0)
    }

    #[must_use]
    pub fn input_reserved_bytes(&self, input_key: InputKey) -> u64 {
        self.reserved_by_input.get(&input_key).copied().unwrap_or(0)
    }

    pub(crate) fn from_parts(
        stored_bytes: u64,
        reserved_bytes: u64,
        per_input_stored_bytes: BTreeMap<InputKey, u64>,
        per_input_reserved_bytes: BTreeMap<InputKey, u64>,
    ) -> Self {
        Self {
            stored: stored_bytes,
            reserved: reserved_bytes,
            stored_by_input: per_input_stored_bytes,
            reserved_by_input: per_input_reserved_bytes,
        }
    }
}
