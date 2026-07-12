use std::{cmp::Ordering, fmt, time::Duration};

use serde::{Deserialize, Serialize};

pub const TIMESTAMP_ID_CURSOR_FORMAT_VERSION: u16 = 1;
pub const TIMESTAMP_ID_CURSOR_CANONICAL_BYTES: usize = 18;

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub struct TimestampIdCursor {
    pub timestamp_epoch_micros: i64,
    pub id: i64,
}

impl TimestampIdCursor {
    #[must_use]
    pub const fn new(timestamp_epoch_micros: i64, id: i64) -> Self {
        Self {
            timestamp_epoch_micros,
            id,
        }
    }

    #[must_use]
    pub fn position_cmp(&self, other: &Self) -> Ordering {
        match self
            .timestamp_epoch_micros
            .cmp(&other.timestamp_epoch_micros)
        {
            Ordering::Equal => self.id.cmp(&other.id),
            ordering => ordering,
        }
    }

    #[must_use]
    pub fn to_canonical_bytes(self) -> [u8; TIMESTAMP_ID_CURSOR_CANONICAL_BYTES] {
        let mut bytes = [0_u8; TIMESTAMP_ID_CURSOR_CANONICAL_BYTES];
        bytes[..2].copy_from_slice(&TIMESTAMP_ID_CURSOR_FORMAT_VERSION.to_be_bytes());
        bytes[2..10].copy_from_slice(&self.timestamp_epoch_micros.to_be_bytes());
        bytes[10..].copy_from_slice(&self.id.to_be_bytes());
        bytes
    }

    /// Decodes the stable cursor representation.
    ///
    /// # Errors
    ///
    /// Returns an error when the byte length or format version is unsupported.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CursorContractError> {
        let bytes: &[u8; TIMESTAMP_ID_CURSOR_CANONICAL_BYTES] = bytes
            .try_into()
            .map_err(|_| CursorContractError::InvalidCanonicalLength)?;
        let version = u16::from_be_bytes([bytes[0], bytes[1]]);
        if version != TIMESTAMP_ID_CURSOR_FORMAT_VERSION {
            return Err(CursorContractError::UnsupportedFormatVersion);
        }

        let mut timestamp_bytes = [0_u8; 8];
        timestamp_bytes.copy_from_slice(&bytes[2..10]);
        let timestamp_epoch_micros = i64::from_be_bytes(timestamp_bytes);
        let mut id_bytes = [0_u8; 8];
        id_bytes.copy_from_slice(&bytes[10..]);
        let id = i64::from_be_bytes(id_bytes);
        Ok(Self::new(timestamp_epoch_micros, id))
    }
}

impl fmt::Debug for TimestampIdCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TimestampIdCursor([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CursorNullPolicy {
    #[default]
    Reject,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct TimestampIdCursorSpec {
    pub timestamp_field: String,
    pub id_field: String,
    #[serde(default)]
    pub overlap: Duration,
    #[serde(default)]
    pub null_policy: CursorNullPolicy,
}

impl TimestampIdCursorSpec {
    /// Validates the connector-neutral cursor definition.
    ///
    /// # Errors
    ///
    /// Returns an error when either output field is empty or both names are identical.
    pub fn validate(&self) -> Result<(), CursorContractError> {
        if self.timestamp_field.trim().is_empty() || self.id_field.trim().is_empty() {
            return Err(CursorContractError::EmptyFieldName);
        }
        if self.timestamp_field == self.id_field {
            return Err(CursorContractError::DuplicateFieldName);
        }
        if !self.overlap.subsec_nanos().is_multiple_of(1_000) {
            return Err(CursorContractError::OverlapPrecisionLoss);
        }
        i64::try_from(self.overlap.as_micros())
            .map_err(|_| CursorContractError::OverlapOutOfRange)?;
        Ok(())
    }
}

impl fmt::Debug for TimestampIdCursorSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TimestampIdCursorSpec")
            .field("timestamp_field", &"[REDACTED]")
            .field("id_field", &"[REDACTED]")
            .field("overlap", &self.overlap)
            .field("null_policy", &self.null_policy)
            .finish()
    }
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub struct TimestampIdCursorBound {
    pub value: TimestampIdCursor,
    pub inclusive: bool,
}

impl fmt::Debug for TimestampIdCursorBound {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TimestampIdCursorBound")
            .field("value", &"[REDACTED]")
            .field("inclusive", &self.inclusive)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct TimestampIdCursorRequest {
    pub spec: TimestampIdCursorSpec,
    pub committed: Option<TimestampIdCursor>,
    #[serde(default)]
    pub resume_after: Option<TimestampIdCursor>,
}

impl TimestampIdCursorRequest {
    /// Computes the lower query bound without advancing the committed cursor.
    ///
    /// Zero overlap resumes exclusively after the committed tuple. Nonzero overlap rewinds the
    /// timestamp and uses the minimum signed identifier as an inclusive bound.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid definition, an overlap outside signed-microsecond range, or
    /// timestamp subtraction underflow.
    pub fn effective_bound(&self) -> Result<Option<TimestampIdCursorBound>, CursorContractError> {
        self.spec.validate()?;
        if let Some(resume_after) = self.resume_after {
            let initial = self.initial_bound()?;
            if initial
                .is_some_and(|bound| resume_after.position_cmp(&bound.value) == Ordering::Less)
            {
                return Err(CursorContractError::ResumeBeforeInitialBound);
            }
            return Ok(Some(TimestampIdCursorBound {
                value: resume_after,
                inclusive: false,
            }));
        }
        self.initial_bound()
    }

    fn initial_bound(&self) -> Result<Option<TimestampIdCursorBound>, CursorContractError> {
        let Some(committed) = self.committed else {
            return Ok(None);
        };
        if self.spec.overlap.is_zero() {
            return Ok(Some(TimestampIdCursorBound {
                value: committed,
                inclusive: false,
            }));
        }

        let overlap_micros = i64::try_from(self.spec.overlap.as_micros())
            .map_err(|_| CursorContractError::OverlapOutOfRange)?;
        let timestamp_epoch_micros = committed
            .timestamp_epoch_micros
            .checked_sub(overlap_micros)
            .ok_or(CursorContractError::TimestampUnderflow)?;
        Ok(Some(TimestampIdCursorBound {
            value: TimestampIdCursor::new(timestamp_epoch_micros, i64::MIN),
            inclusive: true,
        }))
    }
}

impl fmt::Debug for TimestampIdCursorRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TimestampIdCursorRequest")
            .field("spec", &self.spec)
            .field(
                "committed",
                &self.committed.as_ref().map(|_| "[CONFIGURED]"),
            )
            .field(
                "resume_after",
                &self.resume_after.as_ref().map(|_| "[CONFIGURED]"),
            )
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CursorContractError {
    EmptyFieldName,
    DuplicateFieldName,
    OverlapOutOfRange,
    OverlapPrecisionLoss,
    TimestampUnderflow,
    ResumeBeforeInitialBound,
    InvalidCanonicalLength,
    UnsupportedFormatVersion,
}

impl fmt::Display for CursorContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyFieldName => "cursor field names must be non-empty",
            Self::DuplicateFieldName => "cursor field names must be distinct",
            Self::OverlapOutOfRange => "cursor overlap is outside the supported range",
            Self::OverlapPrecisionLoss => {
                "cursor overlap must use whole microseconds without precision loss"
            }
            Self::TimestampUnderflow => "cursor overlap underflowed the timestamp",
            Self::ResumeBeforeInitialBound => {
                "scan resume cursor precedes the initial collection bound"
            }
            Self::InvalidCanonicalLength => "canonical cursor byte length is invalid",
            Self::UnsupportedFormatVersion => "canonical cursor format version is unsupported",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CursorContractError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(overlap: Duration) -> TimestampIdCursorRequest {
        TimestampIdCursorRequest {
            spec: TimestampIdCursorSpec {
                timestamp_field: "updated_at".into(),
                id_field: "id".into(),
                overlap,
                null_policy: CursorNullPolicy::Reject,
            },
            committed: Some(TimestampIdCursor::new(1_000_000, 42)),
            resume_after: None,
        }
    }

    #[test]
    fn canonical_bytes_are_versioned_and_stable() {
        let cursor = TimestampIdCursor::new(-1, i64::MIN);
        assert_eq!(
            cursor.to_canonical_bytes(),
            [
                0, 1, 255, 255, 255, 255, 255, 255, 255, 255, 128, 0, 0, 0, 0, 0, 0, 0,
            ]
        );
        assert_eq!(
            TimestampIdCursor::from_canonical_bytes(&cursor.to_canonical_bytes()),
            Ok(cursor)
        );
    }

    #[test]
    fn cursor_order_uses_timestamp_then_identifier() {
        let first = TimestampIdCursor::new(10, 1);
        let same_timestamp = TimestampIdCursor::new(10, 2);
        let later_timestamp = TimestampIdCursor::new(11, i64::MIN);

        assert_eq!(first.position_cmp(&same_timestamp), Ordering::Less);
        assert_eq!(
            same_timestamp.position_cmp(&later_timestamp),
            Ordering::Less
        );
    }

    #[test]
    fn zero_overlap_is_exclusive_and_nonzero_overlap_is_inclusive() {
        let exact = request(Duration::ZERO)
            .effective_bound()
            .expect("zero overlap must work")
            .expect("committed cursor has a bound");
        assert_eq!(exact.value, TimestampIdCursor::new(1_000_000, 42));
        assert!(!exact.inclusive);

        let replay = request(Duration::from_micros(10))
            .effective_bound()
            .expect("overlap must work")
            .expect("committed cursor has a bound");
        assert_eq!(replay.value, TimestampIdCursor::new(999_990, i64::MIN));
        assert!(replay.inclusive);
    }

    #[test]
    fn overlap_underflow_fails_closed() {
        let mut request = request(Duration::from_micros(1));
        request.committed = Some(TimestampIdCursor::new(i64::MIN, 0));

        assert_eq!(
            request.effective_bound(),
            Err(CursorContractError::TimestampUnderflow)
        );
    }

    #[test]
    fn sub_microsecond_overlap_fails_closed() {
        let request = request(Duration::from_nanos(1));

        assert_eq!(
            request.effective_bound(),
            Err(CursorContractError::OverlapPrecisionLoss)
        );
    }

    #[test]
    fn invalid_overlap_is_rejected_before_the_initial_run() {
        let mut request = request(Duration::from_nanos(1));
        request.committed = None;

        assert_eq!(
            request.effective_bound(),
            Err(CursorContractError::OverlapPrecisionLoss)
        );

        request.spec.overlap = Duration::from_secs(u64::MAX);
        assert_eq!(
            request.effective_bound(),
            Err(CursorContractError::OverlapOutOfRange)
        );
    }

    #[test]
    fn debug_output_redacts_fields_and_values() {
        let request = request(Duration::from_secs(1));
        let debug = format!("{request:?}");

        assert!(!debug.contains("updated_at"));
        assert!(!debug.contains("1000000"));
        assert!(!debug.contains("42"));
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("[CONFIGURED]"));
    }

    #[test]
    fn scan_resume_is_exclusive_and_disables_overlap_reapplication() {
        let mut request = request(Duration::from_micros(10));
        request.resume_after = Some(TimestampIdCursor::new(999_995, 7));

        let bound = request
            .effective_bound()
            .expect("resume must work")
            .expect("resume has a bound");

        assert_eq!(bound.value, TimestampIdCursor::new(999_995, 7));
        assert!(!bound.inclusive);
    }

    #[test]
    fn scan_resume_cannot_regress_before_the_initial_overlap_bound() {
        let mut request = request(Duration::from_micros(10));
        request.resume_after = Some(TimestampIdCursor::new(999_989, i64::MAX));

        assert_eq!(
            request.effective_bound(),
            Err(CursorContractError::ResumeBeforeInitialBound)
        );
    }
}
