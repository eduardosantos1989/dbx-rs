use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use dbx_rs_secure_store::ensure_private_dir;
use ring::digest::{Context, SHA256};
use ring::rand::{SecureRandom, SystemRandom};

use crate::error::SpoolError;
use crate::format::{FORMAT_VERSION, SegmentDecoder, SegmentEncoder};
use crate::identity::{InputKey, SegmentId, decode_hex, encode_hex};
use crate::key::SpoolKey;
use crate::model::{RecoveryMetadata, SegmentHeader, SegmentSummary, SpoolLimits, SpoolUsage};

const SEGMENTS_DIRECTORY: &str = "segments";
const QUARANTINE_DIRECTORY: &str = "quarantine";
const OPEN_EXTENSION: &str = "open";
const READY_EXTENSION: &str = "ready";
const DELIVERED_EXTENSION: &str = "delivered";
const QUARANTINE_EXTENSION: &str = "quarantine";
const SEGMENT_ID_ATTEMPTS: usize = 16;
const REFERENCE_DIGEST_DOMAIN: &[u8] = b"dbx-rs/spool-segment-reference/v1\0";

#[derive(Clone)]
pub struct Spool {
    inner: Arc<SpoolInner>,
}

struct SpoolInner {
    segments: PathBuf,
    key: SpoolKey,
    limits: SpoolLimits,
    accounting: Mutex<Accounting>,
    recovered_open_segments: u64,
}

#[derive(Default)]
struct Accounting {
    stored: u64,
    reserved: u64,
    stored_by_input: BTreeMap<InputKey, u64>,
    reserved_by_input: BTreeMap<InputKey, u64>,
}

impl Spool {
    /// Opens a private spool, quarantines incomplete open segments, validates durable segments,
    /// and rebuilds byte accounting from disk.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe paths, malformed files, unsupported or unauthenticated ready
    /// segments, accounting overflow, or filesystem failures. Corrupt durable data is never
    /// deleted automatically.
    pub fn open(root: &Path, key: SpoolKey, limits: SpoolLimits) -> Result<Self, SpoolError> {
        ensure_private_directory(root)?;
        let segments = root.join(SEGMENTS_DIRECTORY);
        let quarantine = root.join(QUARANTINE_DIRECTORY);
        ensure_private_directory(&segments)?;
        ensure_private_directory(&quarantine)?;
        let recovered_open_segments = recover_open_segments(&segments, &quarantine)?;
        let accounting = scan_accounting(&segments, &quarantine, &key, limits)?;
        Ok(Self {
            inner: Arc::new(SpoolInner {
                segments,
                key,
                limits,
                accounting: Mutex::new(accounting),
                recovered_open_segments,
            }),
        })
    }

    /// Reserves one complete configured segment before creating its owner-only `.open` file.
    ///
    /// # Errors
    ///
    /// Returns an error before file creation when the input or global quota cannot reserve a full
    /// segment, or when safe file creation and initial synchronization fail.
    pub fn begin_segment(&self, header: SegmentHeader) -> Result<SegmentWriter, SpoolError> {
        self.reserve(header.input_key)?;
        match self.begin_reserved_segment(header) {
            Ok(writer) => Ok(writer),
            Err(error) => {
                self.release_reservation(header.input_key);
                Err(error)
            }
        }
    }

    #[must_use]
    pub fn usage(&self) -> SpoolUsage {
        let accounting = lock_accounting(&self.inner.accounting);
        SpoolUsage::from_parts(
            accounting.stored,
            accounting.reserved,
            accounting.stored_by_input.clone(),
            accounting.reserved_by_input.clone(),
        )
    }

    #[must_use]
    pub fn limits(&self) -> SpoolLimits {
        self.inner.limits
    }

    #[must_use]
    pub fn recovered_open_segments(&self) -> u64 {
        self.inner.recovered_open_segments
    }

    /// Returns all ready segments after fully authenticating and validating them.
    ///
    /// Ordering is stable by input, batch sequence, batch ID, segment sequence, and segment ID.
    ///
    /// # Errors
    ///
    /// Returns a blocking error if any ready segment is unsafe, corrupt, truncated, unsupported,
    /// belongs to another key or input directory, or exceeds its configured limit.
    pub fn list_ready(&self) -> Result<Vec<ReadySegment>, SpoolError> {
        let mut ready = self.scan_lifecycle(READY_EXTENSION)?;
        ready.sort_by_key(sort_key);
        Ok(ready)
    }

    /// Returns all delivered segments after fully authenticating and validating them.
    ///
    /// # Errors
    ///
    /// Returns a blocking error under the same conditions as [`Self::list_ready`].
    pub fn list_delivered(&self) -> Result<Vec<DeliveredSegment>, SpoolError> {
        let mut delivered = self
            .scan_lifecycle(DELIVERED_EXTENSION)?
            .into_iter()
            .map(DeliveredSegment::from_ready)
            .collect::<Vec<_>>();
        delivered.sort_by_key(|segment| sort_key(&segment.as_ready()));
        Ok(delivered)
    }

    /// Opens a streaming reader for one immutable ready segment.
    ///
    /// # Errors
    ///
    /// Returns an error if the handle does not belong to this spool or the segment cannot be safely
    /// opened and authenticated.
    pub fn reader(&self, segment: &ReadySegment) -> Result<SegmentReader, SpoolError> {
        self.validate_owned_path(&segment.path, READY_EXTENSION)?;
        let file = open_private_file(&segment.path)?;
        let decoder = SegmentDecoder::open(file, &self.inner.key, self.inner.limits.segment)?;
        if decoder.segment_id() != segment.segment_id
            || decoder.header != segment.header
            || decoder.format_version() != segment.format_version
        {
            return Err(identity_mismatch());
        }
        Ok(SegmentReader {
            decoder,
            expected_summary: segment.summary,
            expected_recovery_metadata: segment.recovery_metadata.clone(),
            terminal_error: false,
        })
    }

    /// Atomically transitions a fully validated ready segment to delivered state.
    ///
    /// # Errors
    ///
    /// Returns an error if validation, rename, or directory synchronization fails. Byte accounting
    /// is unchanged by the lifecycle transition.
    pub fn mark_delivered(&self, segment: &ReadySegment) -> Result<DeliveredSegment, SpoolError> {
        self.validate_ready_handle(segment)?;
        let delivered_path = segment.path.with_extension(DELIVERED_EXTENSION);
        if delivered_path.exists() {
            return Err(SpoolError::new(
                "DBX-RS-SPOOL-LIFECYCLE-0001",
                "mark_delivered",
                "delivered spool destination already exists",
            ));
        }
        fs::rename(&segment.path, &delivered_path).map_err(|error| {
            SpoolError::io(
                "DBX-RS-SPOOL-LIFECYCLE-0002",
                "mark_delivered",
                "failed to mark a spool segment delivered",
                &error,
            )
        })?;
        sync_directory(
            delivered_path.parent().ok_or_else(invalid_path)?,
            "mark_delivered",
        )?;
        Ok(DeliveredSegment {
            path: delivered_path,
            header: segment.header,
            segment_id: segment.segment_id,
            summary: segment.summary,
            format_version: segment.format_version,
            recovery_metadata: segment.recovery_metadata.clone(),
            byte_len: segment.byte_len,
        })
    }

    /// Explicitly deletes one fully validated delivered segment and releases its stored quota.
    ///
    /// Ready, open, and quarantined segments are never compacted by this method.
    ///
    /// # Errors
    ///
    /// Returns an error if the handle is stale, validation fails, deletion or synchronization
    /// fails, or internal accounting is inconsistent.
    pub fn compact_delivered(&self, segment: &DeliveredSegment) -> Result<(), SpoolError> {
        self.validate_delivered_handle(segment)?;
        fs::remove_file(&segment.path).map_err(|error| {
            SpoolError::io(
                "DBX-RS-SPOOL-LIFECYCLE-0003",
                "compact_delivered",
                "failed to compact a delivered spool segment",
                &error,
            )
        })?;
        sync_directory(
            segment.path.parent().ok_or_else(invalid_path)?,
            "compact_delivered",
        )?;
        self.remove_stored(segment.header.input_key, segment.byte_len)
    }

    fn begin_reserved_segment(&self, header: SegmentHeader) -> Result<SegmentWriter, SpoolError> {
        let input_directory = self.input_directory(header.input_key);
        ensure_private_directory(&input_directory)?;
        let random = SystemRandom::new();
        let mut last_collision = false;
        for _ in 0..SEGMENT_ID_ATTEMPTS {
            let mut segment_bytes = [0_u8; 16];
            let mut salt = [0_u8; 32];
            random.fill(&mut segment_bytes).map_err(|_| {
                SpoolError::new(
                    "DBX-RS-SPOOL-CRYPTO-0006",
                    "segment_create",
                    "secure segment identity generation failed",
                )
            })?;
            random.fill(&mut salt).map_err(|_| {
                SpoolError::new(
                    "DBX-RS-SPOOL-CRYPTO-0007",
                    "segment_create",
                    "secure segment salt generation failed",
                )
            })?;
            let segment_id = SegmentId::new(segment_bytes);
            let open_path = input_directory.join(format!(
                "{}.{}",
                encode_hex(segment_id.as_bytes()),
                OPEN_EXTENSION
            ));
            let file = match create_private_file(&open_path) {
                Ok(file) => file,
                Err(error) if error.io_kind() == Some(std::io::ErrorKind::AlreadyExists) => {
                    last_collision = true;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let encoder = match SegmentEncoder::start(
                file,
                &self.inner.key,
                salt,
                segment_id,
                header,
                self.inner.limits.segment,
            ) {
                Ok(encoder) => encoder,
                Err(error) => {
                    let _ignored = fs::remove_file(&open_path);
                    return Err(error);
                }
            };
            return Ok(SegmentWriter {
                spool: self.clone(),
                encoder: Some(encoder),
                open_path,
                header,
                segment_id,
                reservation_active: true,
                published: false,
            });
        }
        Err(SpoolError::new(
            "DBX-RS-SPOOL-LIFECYCLE-0004",
            "segment_create",
            if last_collision {
                "could not allocate a unique spool segment"
            } else {
                "spool segment creation failed"
            },
        ))
    }

    fn reserve(&self, input_key: InputKey) -> Result<(), SpoolError> {
        let bytes = self.inner.limits.segment;
        let mut accounting = lock_accounting(&self.inner.accounting);
        let input_stored = accounting
            .stored_by_input
            .get(&input_key)
            .copied()
            .unwrap_or(0);
        let input_reserved = accounting
            .reserved_by_input
            .get(&input_key)
            .copied()
            .unwrap_or(0);
        let next_input = input_stored
            .checked_add(input_reserved)
            .and_then(|usage| usage.checked_add(bytes))
            .ok_or_else(quota_overflow)?;
        if next_input > self.inner.limits.input {
            return Err(SpoolError::new(
                "DBX-RS-SPOOL-QUOTA-0001",
                "quota_reserve",
                "input spool quota is full",
            ));
        }
        let next_global = accounting
            .stored
            .checked_add(accounting.reserved)
            .and_then(|usage| usage.checked_add(bytes))
            .ok_or_else(quota_overflow)?;
        if next_global > self.inner.limits.global {
            return Err(SpoolError::new(
                "DBX-RS-SPOOL-QUOTA-0002",
                "quota_reserve",
                "global spool quota is full",
            ));
        }
        accounting.reserved = accounting
            .reserved
            .checked_add(bytes)
            .ok_or_else(quota_overflow)?;
        let reserved = accounting.reserved_by_input.entry(input_key).or_default();
        *reserved = reserved.checked_add(bytes).ok_or_else(quota_overflow)?;
        Ok(())
    }

    fn release_reservation(&self, input_key: InputKey) {
        let bytes = self.inner.limits.segment;
        let mut accounting = lock_accounting(&self.inner.accounting);
        accounting.reserved = accounting.reserved.saturating_sub(bytes);
        decrement_entry(&mut accounting.reserved_by_input, input_key, bytes);
    }

    fn publish_reservation(
        &self,
        input_key: InputKey,
        actual_bytes: u64,
    ) -> Result<(), SpoolError> {
        let reserved_bytes = self.inner.limits.segment;
        if actual_bytes > reserved_bytes {
            return Err(SpoolError::new(
                "DBX-RS-SPOOL-QUOTA-0004",
                "quota_publish",
                "sealed spool segment exceeded its reservation",
            ));
        }
        let mut accounting = lock_accounting(&self.inner.accounting);
        if accounting.reserved < reserved_bytes
            || accounting
                .reserved_by_input
                .get(&input_key)
                .copied()
                .unwrap_or(0)
                < reserved_bytes
        {
            return Err(SpoolError::new(
                "DBX-RS-SPOOL-QUOTA-0005",
                "quota_publish",
                "spool reservation accounting is inconsistent",
            ));
        }
        let next_stored = accounting
            .stored
            .checked_add(actual_bytes)
            .ok_or_else(quota_overflow)?;
        let next_input_stored = accounting
            .stored_by_input
            .get(&input_key)
            .copied()
            .unwrap_or(0)
            .checked_add(actual_bytes)
            .ok_or_else(quota_overflow)?;
        accounting.reserved -= reserved_bytes;
        decrement_entry(&mut accounting.reserved_by_input, input_key, reserved_bytes);
        accounting.stored = next_stored;
        accounting
            .stored_by_input
            .insert(input_key, next_input_stored);
        Ok(())
    }

    fn remove_stored(&self, input_key: InputKey, bytes: u64) -> Result<(), SpoolError> {
        let mut accounting = lock_accounting(&self.inner.accounting);
        if accounting.stored < bytes
            || accounting
                .stored_by_input
                .get(&input_key)
                .copied()
                .unwrap_or(0)
                < bytes
        {
            return Err(SpoolError::new(
                "DBX-RS-SPOOL-QUOTA-0005",
                "quota_compact",
                "spool reservation accounting is inconsistent",
            ));
        }
        accounting.stored -= bytes;
        decrement_entry(&mut accounting.stored_by_input, input_key, bytes);
        Ok(())
    }

    fn input_directory(&self, input_key: InputKey) -> PathBuf {
        self.inner.segments.join(encode_hex(input_key.as_bytes()))
    }

    fn scan_lifecycle(&self, extension: &str) -> Result<Vec<ReadySegment>, SpoolError> {
        let mut segments = Vec::new();
        for input_entry in read_directory(&self.inner.segments, "inventory_scan")? {
            let input_entry = input_entry.map_err(|error| directory_read_error(&error))?;
            let input_key = validate_input_directory(&input_entry.path())?;
            for file_entry in read_directory(&input_entry.path(), "inventory_scan")? {
                let file_entry = file_entry.map_err(|error| directory_read_error(&error))?;
                let path = file_entry.path();
                let (segment_id, state) = parse_segment_name(&path)?;
                if state != extension {
                    continue;
                }
                let inspected = inspect_segment(&path, &self.inner.key, self.inner.limits.segment)?;
                if inspected.header.input_key != input_key || inspected.segment_id != segment_id {
                    return Err(identity_mismatch());
                }
                segments.push(ReadySegment {
                    path,
                    header: inspected.header,
                    segment_id,
                    summary: inspected.summary,
                    format_version: inspected.format_version,
                    recovery_metadata: inspected.recovery_metadata,
                    byte_len: inspected.byte_len,
                });
            }
        }
        Ok(segments)
    }

    fn validate_owned_path(&self, path: &Path, extension: &str) -> Result<(), SpoolError> {
        let parent = path.parent().ok_or_else(invalid_path)?;
        let input_parent = parent.parent().ok_or_else(invalid_path)?;
        if input_parent != self.inner.segments
            || path.extension().and_then(|value| value.to_str()) != Some(extension)
        {
            return Err(invalid_path());
        }
        let input_key = validate_input_directory(parent)?;
        let (_, parsed_extension) = parse_segment_name(path)?;
        if parsed_extension != extension || parent != self.input_directory(input_key) {
            return Err(invalid_path());
        }
        Ok(())
    }

    fn validate_ready_handle(&self, segment: &ReadySegment) -> Result<(), SpoolError> {
        self.validate_owned_path(&segment.path, READY_EXTENSION)?;
        let inspected = inspect_segment(&segment.path, &self.inner.key, self.inner.limits.segment)?;
        if inspected.header != segment.header
            || inspected.segment_id != segment.segment_id
            || inspected.summary != segment.summary
            || inspected.format_version != segment.format_version
            || inspected.recovery_metadata != segment.recovery_metadata
            || inspected.byte_len != segment.byte_len
        {
            return Err(identity_mismatch());
        }
        Ok(())
    }

    fn validate_delivered_handle(&self, segment: &DeliveredSegment) -> Result<(), SpoolError> {
        self.validate_owned_path(&segment.path, DELIVERED_EXTENSION)?;
        let inspected = inspect_segment(&segment.path, &self.inner.key, self.inner.limits.segment)?;
        if inspected.header != segment.header
            || inspected.segment_id != segment.segment_id
            || inspected.summary != segment.summary
            || inspected.format_version != segment.format_version
            || inspected.recovery_metadata != segment.recovery_metadata
            || inspected.byte_len != segment.byte_len
        {
            return Err(identity_mismatch());
        }
        Ok(())
    }
}

impl std::fmt::Debug for Spool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Spool")
            .field("root", &"[CONFIGURED]")
            .field("key", &"[REDACTED]")
            .field("limits", &self.inner.limits)
            .finish_non_exhaustive()
    }
}

pub struct SegmentWriter {
    spool: Spool,
    encoder: Option<SegmentEncoder>,
    open_path: PathBuf,
    header: SegmentHeader,
    segment_id: SegmentId,
    reservation_active: bool,
    published: bool,
}

impl SegmentWriter {
    /// Appends one exact final event envelope as an independently authenticated frame.
    ///
    /// # Errors
    ///
    /// Returns an error without writing a partial frame if the event cannot fit while preserving
    /// footer space. I/O or encryption failures leave the segment unready.
    pub fn append_event(&mut self, event: &[u8]) -> Result<(), SpoolError> {
        self.encoder
            .as_mut()
            .ok_or_else(writer_closed)?
            .append_event(event)
    }

    /// Writes and synchronizes the authenticated footer, atomically publishes `.ready`, and
    /// converts the full reservation to actual stored bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if footer creation, synchronization, publication, parent synchronization,
    /// or accounting fails. A successfully renamed ready segment is never deleted on a later
    /// synchronization error and will be recovered by inventory scanning.
    pub fn seal(self) -> Result<ReadySegment, SpoolError> {
        self.seal_with_recovery_metadata(RecoveryMetadata::empty())
    }

    /// Seals the segment with one bounded, authenticated opaque recovery value.
    ///
    /// The metadata frame is written after every event and immediately before the footer. The
    /// encoder reserves enough space for the maximum metadata value before accepting any event.
    ///
    /// # Errors
    ///
    /// Returns an error under the same conditions as [`Self::seal`].
    pub fn seal_with_recovery_metadata(
        mut self,
        recovery_metadata: RecoveryMetadata,
    ) -> Result<ReadySegment, SpoolError> {
        let encoder = self.encoder.take().ok_or_else(writer_closed)?;
        let (file, summary, byte_len) = encoder.finish(&recovery_metadata)?;
        drop(file);
        let ready_path = self.open_path.with_extension(READY_EXTENSION);
        if ready_path.exists() {
            return Err(SpoolError::new(
                "DBX-RS-SPOOL-LIFECYCLE-0005",
                "segment_seal",
                "ready spool destination already exists",
            ));
        }
        fs::rename(&self.open_path, &ready_path).map_err(|error| {
            SpoolError::io(
                "DBX-RS-SPOOL-LIFECYCLE-0006",
                "segment_seal",
                "failed to publish a ready spool segment",
                &error,
            )
        })?;
        self.published = true;
        if let Err(error) = self
            .spool
            .publish_reservation(self.header.input_key, byte_len)
        {
            // Keep the full reservation charged. Startup inventory will rebuild exact accounting.
            self.reservation_active = false;
            return Err(error);
        }
        self.reservation_active = false;
        sync_directory(
            ready_path.parent().ok_or_else(invalid_path)?,
            "segment_seal",
        )?;
        Ok(ReadySegment {
            path: ready_path,
            header: self.header,
            segment_id: self.segment_id,
            summary,
            format_version: FORMAT_VERSION,
            recovery_metadata,
            byte_len,
        })
    }

    /// Explicitly abandons an unsealed segment and releases its reservation.
    ///
    /// # Errors
    ///
    /// Returns an error if the open file cannot be removed or its parent synchronized.
    pub fn abort(mut self) -> Result<(), SpoolError> {
        self.encoder.take();
        remove_if_present(&self.open_path)?;
        sync_directory(
            self.open_path.parent().ok_or_else(invalid_path)?,
            "segment_abort",
        )?;
        if self.reservation_active {
            self.spool.release_reservation(self.header.input_key);
            self.reservation_active = false;
        }
        Ok(())
    }
}

impl std::fmt::Debug for SegmentWriter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SegmentWriter")
            .field("header", &self.header)
            .field("segment_id", &self.segment_id)
            .field("path", &"[CONFIGURED]")
            .finish_non_exhaustive()
    }
}

impl Drop for SegmentWriter {
    fn drop(&mut self) {
        self.encoder.take();
        if !self.published {
            let _ignored = fs::remove_file(&self.open_path);
        }
        if self.reservation_active {
            self.spool.release_reservation(self.header.input_key);
            self.reservation_active = false;
        }
    }
}

#[derive(Clone)]
pub struct ReadySegment {
    path: PathBuf,
    header: SegmentHeader,
    segment_id: SegmentId,
    summary: SegmentSummary,
    format_version: u16,
    recovery_metadata: RecoveryMetadata,
    byte_len: u64,
}

impl ReadySegment {
    #[must_use]
    pub const fn header(&self) -> &SegmentHeader {
        &self.header
    }

    #[must_use]
    pub const fn segment_id(&self) -> SegmentId {
        self.segment_id
    }

    #[must_use]
    pub const fn summary(&self) -> SegmentSummary {
        self.summary
    }

    #[must_use]
    pub fn recovery_metadata(&self) -> &RecoveryMetadata {
        &self.recovery_metadata
    }

    /// Returns the state-reference digest for the complete authenticated segment identity.
    #[must_use]
    pub fn reference_digest(&self) -> [u8; 32] {
        segment_reference_digest(
            self.format_version,
            self.segment_id,
            &self.header,
            self.summary,
            &self.recovery_metadata,
        )
    }

    #[must_use]
    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }
}

impl std::fmt::Debug for ReadySegment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReadySegment")
            .field("header", &self.header)
            .field("segment_id", &self.segment_id)
            .field("summary", &self.summary)
            .field("byte_len", &self.byte_len)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct DeliveredSegment {
    path: PathBuf,
    header: SegmentHeader,
    segment_id: SegmentId,
    summary: SegmentSummary,
    format_version: u16,
    recovery_metadata: RecoveryMetadata,
    byte_len: u64,
}

impl DeliveredSegment {
    #[must_use]
    pub const fn header(&self) -> &SegmentHeader {
        &self.header
    }

    #[must_use]
    pub const fn segment_id(&self) -> SegmentId {
        self.segment_id
    }

    #[must_use]
    pub const fn summary(&self) -> SegmentSummary {
        self.summary
    }

    #[must_use]
    pub fn recovery_metadata(&self) -> &RecoveryMetadata {
        &self.recovery_metadata
    }

    /// Returns the same state-reference digest exposed by the corresponding ready segment.
    #[must_use]
    pub fn reference_digest(&self) -> [u8; 32] {
        segment_reference_digest(
            self.format_version,
            self.segment_id,
            &self.header,
            self.summary,
            &self.recovery_metadata,
        )
    }

    #[must_use]
    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }

    fn from_ready(segment: ReadySegment) -> Self {
        Self {
            path: segment.path,
            header: segment.header,
            segment_id: segment.segment_id,
            summary: segment.summary,
            format_version: segment.format_version,
            recovery_metadata: segment.recovery_metadata,
            byte_len: segment.byte_len,
        }
    }

    fn as_ready(&self) -> ReadySegment {
        ReadySegment {
            path: self.path.clone(),
            header: self.header,
            segment_id: self.segment_id,
            summary: self.summary,
            format_version: self.format_version,
            recovery_metadata: self.recovery_metadata.clone(),
            byte_len: self.byte_len,
        }
    }
}

impl std::fmt::Debug for DeliveredSegment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeliveredSegment")
            .field("header", &self.header)
            .field("segment_id", &self.segment_id)
            .field("summary", &self.summary)
            .field("byte_len", &self.byte_len)
            .finish_non_exhaustive()
    }
}

pub struct SegmentReader {
    decoder: SegmentDecoder,
    expected_summary: SegmentSummary,
    expected_recovery_metadata: RecoveryMetadata,
    terminal_error: bool,
}

impl Iterator for SegmentReader {
    type Item = Result<Vec<u8>, SpoolError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.terminal_error {
            return None;
        }
        match self.decoder.next_event() {
            Ok(Some(event)) => Some(Ok(event)),
            Ok(None) => {
                if self.decoder.summary() == Some(self.expected_summary)
                    && self.decoder.recovery_metadata() == Some(&self.expected_recovery_metadata)
                {
                    None
                } else {
                    self.terminal_error = true;
                    Some(Err(SpoolError::new(
                        "DBX-RS-SPOOL-FORMAT-0022",
                        "footer_validate",
                        "spool footer changed after inventory validation",
                    )))
                }
            }
            Err(error) => {
                self.terminal_error = true;
                Some(Err(error))
            }
        }
    }
}

struct InspectedSegment {
    header: SegmentHeader,
    segment_id: SegmentId,
    summary: SegmentSummary,
    format_version: u16,
    recovery_metadata: RecoveryMetadata,
    byte_len: u64,
}

fn inspect_segment(
    path: &Path,
    key: &SpoolKey,
    limit: u64,
) -> Result<InspectedSegment, SpoolError> {
    let file = open_private_file(path)?;
    let byte_len = file
        .metadata()
        .map_err(|error| {
            SpoolError::io(
                "DBX-RS-SPOOL-PATH-0001",
                "file_inspect",
                "failed to inspect a spool file",
                &error,
            )
        })?
        .len();
    let mut decoder = SegmentDecoder::open(file, key, limit)?;
    while decoder.next_event()?.is_some() {}
    let summary = decoder.summary().ok_or_else(|| {
        SpoolError::new(
            "DBX-RS-SPOOL-FORMAT-0023",
            "footer_validate",
            "spool segment has no authenticated footer",
        )
    })?;
    let recovery_metadata = decoder.recovery_metadata().cloned().ok_or_else(|| {
        SpoolError::new(
            "DBX-RS-SPOOL-FORMAT-0025",
            "recovery_metadata",
            "spool segment has no recovery metadata",
        )
    })?;
    Ok(InspectedSegment {
        header: decoder.header,
        segment_id: decoder.segment_id(),
        summary,
        format_version: decoder.format_version(),
        recovery_metadata,
        byte_len,
    })
}

fn scan_accounting(
    segments_root: &Path,
    quarantine_root: &Path,
    key: &SpoolKey,
    limits: SpoolLimits,
) -> Result<Accounting, SpoolError> {
    let mut accounting = Accounting::default();
    for input_entry in read_directory(segments_root, "inventory_scan")? {
        let input_entry = input_entry.map_err(|error| directory_read_error(&error))?;
        let input_key = validate_input_directory(&input_entry.path())?;
        for file_entry in read_directory(&input_entry.path(), "inventory_scan")? {
            let file_entry = file_entry.map_err(|error| directory_read_error(&error))?;
            let path = file_entry.path();
            let (segment_id, extension) = parse_segment_name(&path)?;
            if !matches!(extension, READY_EXTENSION | DELIVERED_EXTENSION) {
                return Err(invalid_path());
            }
            let inspected = inspect_segment(&path, key, limits.segment)?;
            if inspected.header.input_key != input_key || inspected.segment_id != segment_id {
                return Err(identity_mismatch());
            }
            add_stored(&mut accounting, input_key, inspected.byte_len)?;
        }
    }
    for input_entry in read_directory(quarantine_root, "quarantine_scan")? {
        let input_entry = input_entry.map_err(|error| directory_read_error(&error))?;
        let input_key = validate_input_directory(&input_entry.path())?;
        for file_entry in read_directory(&input_entry.path(), "quarantine_scan")? {
            let file_entry = file_entry.map_err(|error| directory_read_error(&error))?;
            let path = file_entry.path();
            let (_, extension) = parse_segment_name(&path)?;
            if extension != QUARANTINE_EXTENSION {
                return Err(invalid_path());
            }
            let metadata = validate_private_file(&path)?;
            add_stored(&mut accounting, input_key, metadata.len())?;
        }
    }
    Ok(accounting)
}

fn recover_open_segments(segments_root: &Path, quarantine_root: &Path) -> Result<u64, SpoolError> {
    let mut recovered = 0_u64;
    for input_entry in read_directory(segments_root, "startup_recovery")? {
        let input_entry = input_entry.map_err(|error| directory_read_error(&error))?;
        let input_key = validate_input_directory(&input_entry.path())?;
        for file_entry in read_directory(&input_entry.path(), "startup_recovery")? {
            let file_entry = file_entry.map_err(|error| directory_read_error(&error))?;
            let path = file_entry.path();
            let (segment_id, extension) = parse_segment_name(&path)?;
            if extension != OPEN_EXTENSION {
                continue;
            }
            validate_private_file(&path)?;
            let destination_directory = quarantine_root.join(encode_hex(input_key.as_bytes()));
            ensure_private_directory(&destination_directory)?;
            let destination = destination_directory.join(format!(
                "{}.{}",
                encode_hex(segment_id.as_bytes()),
                QUARANTINE_EXTENSION
            ));
            if destination.exists() {
                return Err(SpoolError::new(
                    "DBX-RS-SPOOL-RECOVERY-0001",
                    "startup_recovery",
                    "quarantine destination already exists",
                ));
            }
            fs::rename(&path, &destination).map_err(|error| {
                SpoolError::io(
                    "DBX-RS-SPOOL-RECOVERY-0002",
                    "startup_recovery",
                    "failed to quarantine an incomplete spool segment",
                    &error,
                )
            })?;
            sync_directory(&input_entry.path(), "startup_recovery")?;
            sync_directory(&destination_directory, "startup_recovery")?;
            recovered = recovered.checked_add(1).ok_or_else(|| {
                SpoolError::new(
                    "DBX-RS-SPOOL-RECOVERY-0003",
                    "startup_recovery",
                    "recovered spool segment count overflowed",
                )
            })?;
        }
    }
    Ok(recovered)
}

fn add_stored(
    accounting: &mut Accounting,
    input_key: InputKey,
    bytes: u64,
) -> Result<(), SpoolError> {
    accounting.stored = accounting
        .stored
        .checked_add(bytes)
        .ok_or_else(quota_overflow)?;
    let input_bytes = accounting.stored_by_input.entry(input_key).or_default();
    *input_bytes = input_bytes.checked_add(bytes).ok_or_else(quota_overflow)?;
    Ok(())
}

fn decrement_entry(values: &mut BTreeMap<InputKey, u64>, key: InputKey, bytes: u64) {
    if let Some(value) = values.get_mut(&key) {
        *value = value.saturating_sub(bytes);
        if *value == 0 {
            values.remove(&key);
        }
    }
}

fn segment_reference_digest(
    format_version: u16,
    segment_id: SegmentId,
    header: &SegmentHeader,
    summary: SegmentSummary,
    recovery_metadata: &RecoveryMetadata,
) -> [u8; 32] {
    let mut context = Context::new(&SHA256);
    context.update(REFERENCE_DIGEST_DOMAIN);
    context.update(&format_version.to_be_bytes());
    context.update(segment_id.as_bytes());
    context.update(header.input_key.as_bytes());
    context.update(header.configuration_fingerprint.as_bytes());
    context.update(&header.configuration_generation.to_be_bytes());
    context.update(header.batch_id.as_bytes());
    context.update(&header.batch_sequence.to_be_bytes());
    context.update(&header.segment_sequence.to_be_bytes());
    context.update(&header.created_epoch_millis.to_be_bytes());
    context.update(&summary.event_count.to_be_bytes());
    context.update(&summary.plaintext_bytes.to_be_bytes());
    context.update(&summary.stream_digest);
    context.update(&(recovery_metadata.as_bytes().len() as u64).to_be_bytes());
    context.update(recovery_metadata.as_bytes());
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(context.finish().as_ref());
    digest
}

fn sort_key(segment: &ReadySegment) -> (InputKey, u64, crate::BatchId, u64, SegmentId) {
    (
        segment.header.input_key,
        segment.header.batch_sequence,
        segment.header.batch_id,
        segment.header.segment_sequence,
        segment.segment_id,
    )
}

fn ensure_private_directory(path: &Path) -> Result<(), SpoolError> {
    reject_existing_ancestor_symlinks(path)?;
    if path.exists() {
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            SpoolError::io(
                "DBX-RS-SPOOL-PATH-0002",
                "directory_validate",
                "failed to inspect a spool directory",
                &error,
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(SpoolError::new(
                "DBX-RS-SPOOL-PATH-0003",
                "directory_validate",
                "spool directory has an unsafe type",
            ));
        }
    }
    ensure_private_dir(path)?;
    validate_private_directory(path)
}

fn validate_input_directory(path: &Path) -> Result<InputKey, SpoolError> {
    validate_private_directory(path)?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(invalid_path)?;
    decode_hex::<32>(name)
        .map(InputKey::new)
        .ok_or_else(invalid_path)
}

fn validate_private_directory(path: &Path) -> Result<(), SpoolError> {
    reject_existing_ancestor_symlinks(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        SpoolError::io(
            "DBX-RS-SPOOL-PATH-0002",
            "directory_validate",
            "failed to inspect a spool directory",
            &error,
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SpoolError::new(
            "DBX-RS-SPOOL-PATH-0003",
            "directory_validate",
            "spool directory has an unsafe type",
        ));
    }
    validate_directory_mode(&metadata)
}

fn validate_private_file(path: &Path) -> Result<fs::Metadata, SpoolError> {
    reject_existing_ancestor_symlinks(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        SpoolError::io(
            "DBX-RS-SPOOL-PATH-0001",
            "file_validate",
            "failed to inspect a spool file",
            &error,
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SpoolError::new(
            "DBX-RS-SPOOL-PATH-0004",
            "file_validate",
            "spool file has an unsafe type",
        ));
    }
    validate_file_mode(&metadata)?;
    Ok(metadata)
}

fn open_private_file(path: &Path) -> Result<File, SpoolError> {
    validate_private_file(path)?;
    File::open(path).map_err(|error| {
        SpoolError::io(
            "DBX-RS-SPOOL-PATH-0005",
            "file_open",
            "failed to open a spool file",
            &error,
        )
    })
}

fn create_private_file(path: &Path) -> Result<File, SpoolError> {
    reject_existing_ancestor_symlinks(path)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    set_create_mode(&mut options);
    let file = options.open(path).map_err(|error| {
        SpoolError::io(
            "DBX-RS-SPOOL-PATH-0006",
            "file_create",
            "failed to create an open spool file",
            &error,
        )
    })?;
    set_file_mode(path)?;
    Ok(file)
}

fn parse_segment_name(path: &Path) -> Result<(SegmentId, &str), SpoolError> {
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(invalid_path)?;
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .ok_or_else(invalid_path)?;
    let segment_id = decode_hex::<16>(stem)
        .map(SegmentId::new)
        .ok_or_else(invalid_path)?;
    Ok((segment_id, extension))
}

fn read_directory(path: &Path, stage: &'static str) -> Result<fs::ReadDir, SpoolError> {
    validate_private_directory(path)?;
    fs::read_dir(path).map_err(|error| {
        SpoolError::io(
            "DBX-RS-SPOOL-PATH-0007",
            stage,
            "failed to read a spool directory",
            &error,
        )
    })
}

fn sync_directory(path: &Path, stage: &'static str) -> Result<(), SpoolError> {
    validate_private_directory(path)?;
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            SpoolError::io(
                "DBX-RS-SPOOL-PATH-0008",
                stage,
                "failed to synchronize a spool directory",
                &error,
            )
        })
}

fn remove_if_present(path: &Path) -> Result<(), SpoolError> {
    reject_existing_ancestor_symlinks(path)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(SpoolError::io(
            "DBX-RS-SPOOL-LIFECYCLE-0007",
            "segment_abort",
            "failed to remove an open spool segment",
            &error,
        )),
    }
}

pub(crate) fn reject_existing_ancestor_symlinks(path: &Path) -> Result<(), SpoolError> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(SpoolError::new(
                    "DBX-RS-SPOOL-PATH-0003",
                    "path_validate",
                    "spool path contains a symbolic link",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(SpoolError::io(
                    "DBX-RS-SPOOL-PATH-0002",
                    "path_validate",
                    "failed to inspect a spool path",
                    &error,
                ));
            }
        }
    }
    Ok(())
}

fn lock_accounting(accounting: &Mutex<Accounting>) -> MutexGuard<'_, Accounting> {
    accounting
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn directory_read_error(error: &std::io::Error) -> SpoolError {
    SpoolError::io(
        "DBX-RS-SPOOL-PATH-0009",
        "directory_read",
        "failed to inspect a spool directory entry",
        error,
    )
}

const fn quota_overflow() -> SpoolError {
    SpoolError::new(
        "DBX-RS-SPOOL-QUOTA-0003",
        "quota_accounting",
        "spool quota accounting overflowed",
    )
}

const fn identity_mismatch() -> SpoolError {
    SpoolError::new(
        "DBX-RS-SPOOL-FORMAT-0024",
        "identity_validate",
        "spool segment identity is inconsistent",
    )
}

const fn invalid_path() -> SpoolError {
    SpoolError::new(
        "DBX-RS-SPOOL-PATH-0010",
        "path_validate",
        "spool path or name is invalid",
    )
}

const fn writer_closed() -> SpoolError {
    SpoolError::new(
        "DBX-RS-SPOOL-LIFECYCLE-0008",
        "writer_state",
        "spool segment writer is closed",
    )
}

#[cfg(unix)]
fn set_create_mode(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_create_mode(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn set_file_mode(path: &Path) -> Result<(), SpoolError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| {
        SpoolError::io(
            "DBX-RS-SPOOL-PATH-0011",
            "file_permissions",
            "failed to protect spool file permissions",
            &error,
        )
    })
}

#[cfg(not(unix))]
fn set_file_mode(_path: &Path) -> Result<(), SpoolError> {
    Ok(())
}

#[cfg(unix)]
fn validate_directory_mode(metadata: &fs::Metadata) -> Result<(), SpoolError> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(SpoolError::new(
            "DBX-RS-SPOOL-PATH-0012",
            "directory_permissions",
            "spool directory permissions are too broad",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_directory_mode(_metadata: &fs::Metadata) -> Result<(), SpoolError> {
    Ok(())
}

#[cfg(unix)]
fn validate_file_mode(metadata: &fs::Metadata) -> Result<(), SpoolError> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(SpoolError::new(
            "DBX-RS-SPOOL-PATH-0013",
            "file_permissions",
            "spool file permissions are too broad",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_file_mode(_metadata: &fs::Metadata) -> Result<(), SpoolError> {
    Ok(())
}

#[cfg(test)]
mod tests;
