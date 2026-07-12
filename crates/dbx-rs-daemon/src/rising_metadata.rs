use std::{cmp::Ordering, fmt};

use dbx_rs_connector_sdk::{
    TIMESTAMP_ID_CURSOR_CANONICAL_BYTES, TimestampIdCursor, TimestampIdCursorRequest,
};
use dbx_rs_spool::{MAX_RECOVERY_METADATA_BYTES, RecoveryMetadata};
use ring::digest::{Context, SHA256};

const FORMAT_VERSION: u16 = 2;
const FLAG_TRUNCATED: u8 = 1 << 0;
const FLAG_CHECKPOINT_CANDIDATE: u8 = 1 << 1;
const FLAG_SCAN_RESUME: u8 = 1 << 2;
const SUPPORTED_FLAGS: u8 = FLAG_TRUNCATED | FLAG_CHECKPOINT_CANDIDATE | FLAG_SCAN_RESUME;

const VERSION_OFFSET: usize = 0;
const FLAGS_OFFSET: usize = 2;
const RESERVED_OFFSET: usize = 3;
const ROWS_OFFSET: usize = 4;
const REQUEST_FINGERPRINT_OFFSET: usize = 12;
const CHECKPOINT_CANDIDATE_OFFSET: usize = REQUEST_FINGERPRINT_OFFSET + 32;
const SCAN_RESUME_OFFSET: usize = CHECKPOINT_CANDIDATE_OFFSET + TIMESTAMP_ID_CURSOR_CANONICAL_BYTES;
const ENCODED_BYTES: usize = SCAN_RESUME_OFFSET + TIMESTAMP_ID_CURSOR_CANONICAL_BYTES;
const REQUEST_FINGERPRINT_DOMAIN: &[u8] = b"dbx-rs/rising-request-fingerprint/v1\0";

const _: () = assert!(ENCODED_BYTES <= MAX_RECOVERY_METADATA_BYTES);

/// Authenticated recovery facts needed to adopt a sealed rising page after a restart.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct RisingRecoveryMetadata {
    rows: u64,
    truncated: bool,
    request_fingerprint: [u8; 32],
    checkpoint_candidate: Option<TimestampIdCursor>,
    scan_resume: Option<TimestampIdCursor>,
}

impl RisingRecoveryMetadata {
    /// Constructs semantically valid recovery metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when the request fingerprint is the reserved all-zero value, cursor
    /// presence does not match the row count, a truncated page has no resume cursor, or the
    /// checkpoint candidate precedes the scan-resume cursor.
    pub(crate) fn new(
        rows: u64,
        truncated: bool,
        request_fingerprint: [u8; 32],
        checkpoint_candidate: Option<TimestampIdCursor>,
        scan_resume: Option<TimestampIdCursor>,
    ) -> Result<Self, RisingMetadataError> {
        let metadata = Self {
            rows,
            truncated,
            request_fingerprint,
            checkpoint_candidate,
            scan_resume,
        };
        metadata.validate()?;
        Ok(metadata)
    }

    #[must_use]
    pub(crate) const fn rows(self) -> u64 {
        self.rows
    }

    #[must_use]
    pub(crate) const fn truncated(self) -> bool {
        self.truncated
    }

    #[must_use]
    pub(crate) const fn request_fingerprint(self) -> [u8; 32] {
        self.request_fingerprint
    }

    #[must_use]
    pub(crate) const fn checkpoint_candidate(self) -> Option<TimestampIdCursor> {
        self.checkpoint_candidate
    }

    #[must_use]
    pub(crate) const fn scan_resume(self) -> Option<TimestampIdCursor> {
        self.scan_resume
    }

    /// Encodes this value into the bounded opaque spool representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the spool's hard metadata limit becomes smaller than this codec's fixed
    /// representation.
    pub(crate) fn encode(self) -> Result<RecoveryMetadata, RisingMetadataError> {
        let mut bytes = [0_u8; ENCODED_BYTES];
        bytes[VERSION_OFFSET..FLAGS_OFFSET].copy_from_slice(&FORMAT_VERSION.to_be_bytes());

        let mut flags = 0_u8;
        if self.truncated {
            flags |= FLAG_TRUNCATED;
        }
        if let Some(candidate) = self.checkpoint_candidate {
            flags |= FLAG_CHECKPOINT_CANDIDATE;
            bytes[CHECKPOINT_CANDIDATE_OFFSET..SCAN_RESUME_OFFSET]
                .copy_from_slice(&candidate.to_canonical_bytes());
        }
        if let Some(resume) = self.scan_resume {
            flags |= FLAG_SCAN_RESUME;
            bytes[SCAN_RESUME_OFFSET..].copy_from_slice(&resume.to_canonical_bytes());
        }
        bytes[FLAGS_OFFSET] = flags;
        bytes[ROWS_OFFSET..REQUEST_FINGERPRINT_OFFSET].copy_from_slice(&self.rows.to_be_bytes());
        bytes[REQUEST_FINGERPRINT_OFFSET..CHECKPOINT_CANDIDATE_OFFSET]
            .copy_from_slice(&self.request_fingerprint);

        RecoveryMetadata::new(bytes)
            .map_err(|_| RisingMetadataError::new(RisingMetadataErrorKind::SpoolMetadataLimit))
    }

    /// Decodes and validates authenticated spool recovery metadata.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-canonical encoding, unsupported format or cursor version, or
    /// invalid row/cursor semantics.
    pub(crate) fn decode(metadata: &RecoveryMetadata) -> Result<Self, RisingMetadataError> {
        let bytes: &[u8; ENCODED_BYTES] = metadata
            .as_bytes()
            .try_into()
            .map_err(|_| RisingMetadataError::new(RisingMetadataErrorKind::InvalidLength))?;

        let version = u16::from_be_bytes([bytes[VERSION_OFFSET], bytes[VERSION_OFFSET + 1]]);
        if version != FORMAT_VERSION {
            return Err(RisingMetadataError::new(
                RisingMetadataErrorKind::UnsupportedVersion,
            ));
        }

        let flags = bytes[FLAGS_OFFSET];
        if flags & !SUPPORTED_FLAGS != 0 {
            return Err(RisingMetadataError::new(
                RisingMetadataErrorKind::UnsupportedFlags,
            ));
        }
        if bytes[RESERVED_OFFSET] != 0 {
            return Err(RisingMetadataError::new(
                RisingMetadataErrorKind::NonCanonicalReservedByte,
            ));
        }

        let mut rows = [0_u8; 8];
        rows.copy_from_slice(&bytes[ROWS_OFFSET..REQUEST_FINGERPRINT_OFFSET]);
        let mut request_fingerprint = [0_u8; 32];
        request_fingerprint
            .copy_from_slice(&bytes[REQUEST_FINGERPRINT_OFFSET..CHECKPOINT_CANDIDATE_OFFSET]);

        let checkpoint_candidate = decode_cursor_slot(
            &bytes[CHECKPOINT_CANDIDATE_OFFSET..SCAN_RESUME_OFFSET],
            flags & FLAG_CHECKPOINT_CANDIDATE != 0,
        )?;
        let scan_resume =
            decode_cursor_slot(&bytes[SCAN_RESUME_OFFSET..], flags & FLAG_SCAN_RESUME != 0)?;

        Self::new(
            u64::from_be_bytes(rows),
            flags & FLAG_TRUNCATED != 0,
            request_fingerprint,
            checkpoint_candidate,
            scan_resume,
        )
    }

    fn validate(&self) -> Result<(), RisingMetadataError> {
        if self.request_fingerprint.iter().all(|byte| *byte == 0) {
            return Err(RisingMetadataError::new(
                RisingMetadataErrorKind::InvalidRequestFingerprint,
            ));
        }
        if self.rows == 0 {
            if self.truncated || self.checkpoint_candidate.is_some() || self.scan_resume.is_some() {
                return Err(RisingMetadataError::new(
                    RisingMetadataErrorKind::InvalidSemantics,
                ));
            }
            return Ok(());
        }

        let (Some(candidate), Some(resume)) = (self.checkpoint_candidate, self.scan_resume) else {
            return Err(RisingMetadataError::new(
                RisingMetadataErrorKind::InvalidSemantics,
            ));
        };
        if candidate.position_cmp(&resume) == Ordering::Less {
            return Err(RisingMetadataError::new(
                RisingMetadataErrorKind::InvalidSemantics,
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for RisingRecoveryMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RisingRecoveryMetadata")
            .field("rows", &self.rows)
            .field("truncated", &self.truncated)
            .field("request_fingerprint", &"[REDACTED]")
            .field(
                "checkpoint_candidate",
                &self.checkpoint_candidate.map(|_| "[CONFIGURED]"),
            )
            .field("scan_resume", &self.scan_resume.map(|_| "[CONFIGURED]"))
            .finish()
    }
}

/// Hashes the cursor identity and exact durable lower-bound request using a versioned preimage.
///
/// Optional cursor slots are encoded as a one-byte presence tag followed by canonical cursor bytes
/// when present. Changing this layout requires a new fingerprint domain and metadata format.
#[must_use]
pub(crate) fn rising_request_fingerprint(
    cursor_identity_fingerprint: [u8; 32],
    request: &TimestampIdCursorRequest,
) -> [u8; 32] {
    let mut context = Context::new(&SHA256);
    context.update(REQUEST_FINGERPRINT_DOMAIN);
    context.update(&cursor_identity_fingerprint);
    update_optional_cursor(&mut context, request.committed);
    update_optional_cursor(&mut context, request.resume_after);
    let mut fingerprint = [0_u8; 32];
    fingerprint.copy_from_slice(context.finish().as_ref());
    fingerprint
}

fn update_optional_cursor(context: &mut Context, cursor: Option<TimestampIdCursor>) {
    match cursor {
        Some(cursor) => {
            context.update(&[1]);
            context.update(&cursor.to_canonical_bytes());
        }
        None => context.update(&[0]),
    }
}

fn decode_cursor_slot(
    bytes: &[u8],
    present: bool,
) -> Result<Option<TimestampIdCursor>, RisingMetadataError> {
    if !present {
        if bytes.iter().any(|byte| *byte != 0) {
            return Err(RisingMetadataError::new(
                RisingMetadataErrorKind::NonCanonicalAbsentCursor,
            ));
        }
        return Ok(None);
    }

    TimestampIdCursor::from_canonical_bytes(bytes)
        .map(Some)
        .map_err(|_| RisingMetadataError::new(RisingMetadataErrorKind::InvalidCursor))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RisingMetadataErrorKind {
    InvalidLength,
    UnsupportedVersion,
    UnsupportedFlags,
    NonCanonicalReservedByte,
    NonCanonicalAbsentCursor,
    InvalidCursor,
    InvalidSemantics,
    SpoolMetadataLimit,
    InvalidRequestFingerprint,
}

/// Redacted failure returned by the rising recovery metadata codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RisingMetadataError {
    kind: RisingMetadataErrorKind,
}

impl RisingMetadataError {
    const fn new(kind: RisingMetadataErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub(crate) const fn code(self) -> &'static str {
        match self.kind {
            RisingMetadataErrorKind::InvalidLength => "DBX-RS-DAEMON-RISING-METADATA-0001",
            RisingMetadataErrorKind::UnsupportedVersion => "DBX-RS-DAEMON-RISING-METADATA-0002",
            RisingMetadataErrorKind::UnsupportedFlags => "DBX-RS-DAEMON-RISING-METADATA-0003",
            RisingMetadataErrorKind::NonCanonicalReservedByte => {
                "DBX-RS-DAEMON-RISING-METADATA-0004"
            }
            RisingMetadataErrorKind::NonCanonicalAbsentCursor => {
                "DBX-RS-DAEMON-RISING-METADATA-0005"
            }
            RisingMetadataErrorKind::InvalidCursor => "DBX-RS-DAEMON-RISING-METADATA-0006",
            RisingMetadataErrorKind::InvalidSemantics => "DBX-RS-DAEMON-RISING-METADATA-0007",
            RisingMetadataErrorKind::SpoolMetadataLimit => "DBX-RS-DAEMON-RISING-METADATA-0008",
            RisingMetadataErrorKind::InvalidRequestFingerprint => {
                "DBX-RS-DAEMON-RISING-METADATA-0009"
            }
        }
    }

    const fn message(self) -> &'static str {
        match self.kind {
            RisingMetadataErrorKind::InvalidLength => "rising recovery metadata length is invalid",
            RisingMetadataErrorKind::UnsupportedVersion => {
                "rising recovery metadata version is unsupported"
            }
            RisingMetadataErrorKind::UnsupportedFlags => {
                "rising recovery metadata flags are unsupported"
            }
            RisingMetadataErrorKind::NonCanonicalReservedByte => {
                "rising recovery metadata reserved byte is nonzero"
            }
            RisingMetadataErrorKind::NonCanonicalAbsentCursor => {
                "rising recovery metadata has bytes for an absent cursor"
            }
            RisingMetadataErrorKind::InvalidCursor => {
                "rising recovery metadata contains an invalid cursor"
            }
            RisingMetadataErrorKind::InvalidSemantics => {
                "rising recovery metadata semantics are invalid"
            }
            RisingMetadataErrorKind::SpoolMetadataLimit => {
                "rising recovery metadata exceeds the spool hard limit"
            }
            RisingMetadataErrorKind::InvalidRequestFingerprint => {
                "rising recovery request fingerprint is invalid"
            }
        }
    }
}

impl fmt::Display for RisingMetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "error[{}] {}", self.code(), self.message())
    }
}

impl std::error::Error for RisingMetadataError {}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_REQUEST_FINGERPRINT: [u8; 32] = [0x44; 32];

    fn cursor(timestamp: i64, id: i64) -> TimestampIdCursor {
        TimestampIdCursor::new(timestamp, id)
    }

    fn nonempty(truncated: bool) -> RisingRecoveryMetadata {
        RisingRecoveryMetadata::new(
            7,
            truncated,
            TEST_REQUEST_FINGERPRINT,
            Some(cursor(1_234_567, 88)),
            Some(cursor(1_234_567, 88)),
        )
        .expect("fixture must be valid")
    }

    fn encoded_bytes(metadata: RisingRecoveryMetadata) -> Vec<u8> {
        metadata.encode().expect("fixture must encode").into_bytes()
    }

    fn decode_bytes(bytes: &[u8]) -> Result<RisingRecoveryMetadata, RisingMetadataError> {
        let metadata =
            RecoveryMetadata::new(bytes).expect("test metadata must fit the spool bound");
        RisingRecoveryMetadata::decode(&metadata)
    }

    fn assert_error_code(
        result: Result<RisingRecoveryMetadata, RisingMetadataError>,
        code: &'static str,
    ) {
        assert_eq!(result.expect_err("metadata must fail").code(), code);
    }

    #[test]
    fn fixed_encoding_is_bounded_and_stable() {
        let bytes = encoded_bytes(nonempty(true));

        assert_eq!(
            bytes,
            [
                0x00, 0x02, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x44, 0x44,
                0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
                0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
                0x44, 0x44, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0xd6, 0x87, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12,
                0xd6, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58,
            ]
        );
        assert_eq!(bytes.len(), 80);
        assert!(bytes.len() <= MAX_RECOVERY_METADATA_BYTES);
        assert_eq!(&bytes[..2], &FORMAT_VERSION.to_be_bytes());
        assert_eq!(
            bytes[FLAGS_OFFSET],
            FLAG_TRUNCATED | FLAG_CHECKPOINT_CANDIDATE | FLAG_SCAN_RESUME
        );
        assert_eq!(bytes[RESERVED_OFFSET], 0);
        assert_eq!(
            &bytes[ROWS_OFFSET..REQUEST_FINGERPRINT_OFFSET],
            &7_u64.to_be_bytes()
        );
        assert_eq!(
            &bytes[REQUEST_FINGERPRINT_OFFSET..CHECKPOINT_CANDIDATE_OFFSET],
            &TEST_REQUEST_FINGERPRINT
        );
    }

    #[test]
    fn empty_and_populated_values_round_trip() {
        let values = [
            RisingRecoveryMetadata::new(0, false, TEST_REQUEST_FINGERPRINT, None, None)
                .expect("empty must be valid"),
            nonempty(false),
            nonempty(true),
            RisingRecoveryMetadata::new(
                u64::MAX,
                false,
                TEST_REQUEST_FINGERPRINT,
                Some(cursor(i64::MAX, i64::MAX)),
                Some(cursor(i64::MIN, i64::MIN)),
            )
            .expect("ordered extremes must be valid"),
        ];

        for value in values {
            let encoded = value.encode().expect("value must encode");
            assert_eq!(RisingRecoveryMetadata::decode(&encoded), Ok(value));
        }
    }

    #[test]
    fn accessors_return_recovery_facts() {
        let metadata = nonempty(true);

        assert_eq!(metadata.rows(), 7);
        assert!(metadata.truncated());
        assert_eq!(metadata.request_fingerprint(), TEST_REQUEST_FINGERPRINT);
        assert_eq!(metadata.checkpoint_candidate(), Some(cursor(1_234_567, 88)));
        assert_eq!(metadata.scan_resume(), Some(cursor(1_234_567, 88)));
    }

    #[test]
    fn debug_output_redacts_cursor_values() {
        let debug = format!("{:?}", nonempty(true));

        assert!(debug.contains("checkpoint_candidate: Some(\"[CONFIGURED]\")"));
        assert!(debug.contains("scan_resume: Some(\"[CONFIGURED]\")"));
        assert!(!debug.contains("1234567"));
        assert!(!debug.contains("88"));
    }

    #[test]
    fn decoder_rejects_short_and_long_encodings() {
        let bytes = encoded_bytes(nonempty(false));

        assert_error_code(
            decode_bytes(&bytes[..bytes.len() - 1]),
            "DBX-RS-DAEMON-RISING-METADATA-0001",
        );
        let mut long = bytes;
        long.push(0);
        assert_error_code(decode_bytes(&long), "DBX-RS-DAEMON-RISING-METADATA-0001");
    }

    #[test]
    fn decoder_rejects_unsupported_outer_version() {
        let mut bytes = encoded_bytes(nonempty(false));
        bytes[VERSION_OFFSET..FLAGS_OFFSET].copy_from_slice(&3_u16.to_be_bytes());

        assert_error_code(decode_bytes(&bytes), "DBX-RS-DAEMON-RISING-METADATA-0002");
    }

    #[test]
    fn decoder_rejects_unknown_flags_and_nonzero_reserved_byte() {
        let mut flags = encoded_bytes(nonempty(false));
        flags[FLAGS_OFFSET] |= 1 << 7;
        assert_error_code(decode_bytes(&flags), "DBX-RS-DAEMON-RISING-METADATA-0003");

        let mut reserved = encoded_bytes(nonempty(false));
        reserved[RESERVED_OFFSET] = 1;
        assert_error_code(
            decode_bytes(&reserved),
            "DBX-RS-DAEMON-RISING-METADATA-0004",
        );
    }

    #[test]
    fn decoder_rejects_bytes_in_absent_cursor_slots() {
        let empty = RisingRecoveryMetadata::new(0, false, TEST_REQUEST_FINGERPRINT, None, None)
            .expect("empty must be valid");

        for offset in [CHECKPOINT_CANDIDATE_OFFSET, SCAN_RESUME_OFFSET] {
            let mut bytes = encoded_bytes(empty);
            bytes[offset] = 1;
            assert_error_code(decode_bytes(&bytes), "DBX-RS-DAEMON-RISING-METADATA-0005");
        }
    }

    #[test]
    fn decoder_rejects_unsupported_cursor_versions_in_each_slot() {
        for offset in [CHECKPOINT_CANDIDATE_OFFSET, SCAN_RESUME_OFFSET] {
            let mut bytes = encoded_bytes(nonempty(false));
            bytes[offset..offset + 2].copy_from_slice(&2_u16.to_be_bytes());
            assert_error_code(decode_bytes(&bytes), "DBX-RS-DAEMON-RISING-METADATA-0006");
        }
    }

    #[test]
    fn zero_rows_rejects_every_nonempty_shape() {
        let cases = [
            (true, None, None),
            (false, Some(cursor(1, 1)), None),
            (false, None, Some(cursor(1, 1))),
            (false, Some(cursor(1, 1)), Some(cursor(1, 1))),
        ];

        for (truncated, candidate, resume) in cases {
            assert_error_code(
                RisingRecoveryMetadata::new(
                    0,
                    truncated,
                    TEST_REQUEST_FINGERPRINT,
                    candidate,
                    resume,
                ),
                "DBX-RS-DAEMON-RISING-METADATA-0007",
            );
        }
    }

    #[test]
    fn positive_rows_require_both_cursors_for_final_and_truncated_pages() {
        for truncated in [false, true] {
            for (candidate, resume) in [
                (None, None),
                (Some(cursor(1, 1)), None),
                (None, Some(cursor(1, 1))),
            ] {
                assert_error_code(
                    RisingRecoveryMetadata::new(
                        1,
                        truncated,
                        TEST_REQUEST_FINGERPRINT,
                        candidate,
                        resume,
                    ),
                    "DBX-RS-DAEMON-RISING-METADATA-0007",
                );
            }
        }
    }

    #[test]
    fn candidate_must_not_precede_scan_resume() {
        assert_error_code(
            RisingRecoveryMetadata::new(
                1,
                false,
                TEST_REQUEST_FINGERPRINT,
                Some(cursor(100, 8)),
                Some(cursor(100, 9)),
            ),
            "DBX-RS-DAEMON-RISING-METADATA-0007",
        );

        for candidate in [cursor(100, 9), cursor(101, i64::MIN)] {
            assert!(
                RisingRecoveryMetadata::new(
                    1,
                    false,
                    TEST_REQUEST_FINGERPRINT,
                    Some(candidate),
                    Some(cursor(100, 9)),
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn decoder_applies_semantic_validation_to_authenticated_bytes() {
        let mut zero_rows_truncated = encoded_bytes(
            RisingRecoveryMetadata::new(0, false, TEST_REQUEST_FINGERPRINT, None, None)
                .expect("empty must be valid"),
        );
        zero_rows_truncated[FLAGS_OFFSET] = FLAG_TRUNCATED;
        assert_error_code(
            decode_bytes(&zero_rows_truncated),
            "DBX-RS-DAEMON-RISING-METADATA-0007",
        );

        let mut missing_resume = encoded_bytes(nonempty(true));
        missing_resume[FLAGS_OFFSET] &= !FLAG_SCAN_RESUME;
        missing_resume[SCAN_RESUME_OFFSET..].fill(0);
        assert_error_code(
            decode_bytes(&missing_resume),
            "DBX-RS-DAEMON-RISING-METADATA-0007",
        );

        let mut candidate_behind = encoded_bytes(nonempty(false));
        candidate_behind[CHECKPOINT_CANDIDATE_OFFSET..SCAN_RESUME_OFFSET]
            .copy_from_slice(&cursor(1_234_567, 87).to_canonical_bytes());
        assert_error_code(
            decode_bytes(&candidate_behind),
            "DBX-RS-DAEMON-RISING-METADATA-0007",
        );
    }

    #[test]
    fn request_fingerprint_binds_cursor_identity_committed_and_resume_positions() {
        let request = TimestampIdCursorRequest {
            spec: dbx_rs_connector_sdk::TimestampIdCursorSpec {
                timestamp_field: "updated_at".into(),
                id_field: "id".into(),
                overlap: std::time::Duration::ZERO,
                null_policy: dbx_rs_connector_sdk::CursorNullPolicy::Reject,
            },
            committed: Some(cursor(100, 1)),
            resume_after: Some(cursor(101, 2)),
        };
        let fingerprint = rising_request_fingerprint([0x11; 32], &request);

        assert_eq!(
            fingerprint,
            [
                0xe1, 0x71, 0x78, 0xb2, 0xfb, 0x85, 0x17, 0x52, 0x0b, 0xaa, 0xb6, 0x82, 0x1e, 0x76,
                0x94, 0x03, 0x30, 0x10, 0xd2, 0x37, 0x7e, 0xdd, 0xe4, 0x2a, 0x40, 0x8d, 0xa1, 0xbc,
                0xe7, 0x6c, 0x4b, 0x87,
            ]
        );
        assert_eq!(
            fingerprint,
            rising_request_fingerprint([0x11; 32], &request)
        );
        assert_ne!(
            fingerprint,
            rising_request_fingerprint([0x22; 32], &request)
        );
        let mut changed_committed = request.clone();
        changed_committed.committed = Some(cursor(100, 2));
        assert_ne!(
            fingerprint,
            rising_request_fingerprint([0x11; 32], &changed_committed)
        );
        let mut changed_resume = request;
        changed_resume.resume_after = Some(cursor(101, 3));
        assert_ne!(
            fingerprint,
            rising_request_fingerprint([0x11; 32], &changed_resume)
        );
    }

    #[test]
    fn all_zero_request_fingerprint_is_rejected() {
        assert_error_code(
            RisingRecoveryMetadata::new(0, false, [0; 32], None, None),
            "DBX-RS-DAEMON-RISING-METADATA-0009",
        );
    }

    #[test]
    fn errors_are_stable_and_redacted() {
        let error = RisingRecoveryMetadata::new(
            1,
            false,
            TEST_REQUEST_FINGERPRINT,
            Some(cursor(9_876_543_210, 1_234_567_890)),
            Some(cursor(9_876_543_211, 1_234_567_890)),
        )
        .expect_err("candidate regression must fail");

        assert_eq!(error.code(), "DBX-RS-DAEMON-RISING-METADATA-0007");
        let display = error.to_string();
        let debug = format!("{error:?}");
        for sensitive in ["9876543210", "9876543211", "1234567890"] {
            assert!(!display.contains(sensitive));
            assert!(!debug.contains(sensitive));
        }
    }
}
