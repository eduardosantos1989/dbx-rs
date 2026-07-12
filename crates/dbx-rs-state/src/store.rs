use std::cmp::Ordering;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use dbx_rs_checkpoint::{CollectionState, DeliveryState, Snapshot};
use dbx_rs_secure_store::{SecureStoreError, atomic_write, ensure_private_dir, read_limited};
use ring::digest::{Context, SHA256};

use crate::model::{
    ActiveScan, DurableInputState, Fingerprint, StateKey, StateValidationError,
    configuration_fence_id,
};

pub const DURABLE_ENVELOPE_VERSION: u16 = 1;
pub const MAX_ENVELOPE_BYTES: u64 = 1_048_576;

const MAGIC: &[u8; 8] = b"DBXRSCP\0";
const JSON_CODEC: u16 = 1;
const HEADER_BYTES: usize = 56;
const CHECKSUM_START: usize = 24;
const CHECKSUM_END: usize = 56;
const CHECKSUM_DOMAIN: &[u8] = b"dbx-rs-checkpoint-envelope-v1\0";
const CURRENT_FILE: &str = "checkpoint.dbx";
const PREVIOUS_FILE: &str = "checkpoint.dbx.prev";
const WRITER_LOCK_FILE: &str = ".checkpoint-writer.lock";

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct StateToken {
    pub revision: u64,
    pub digest: [u8; 32],
}

impl fmt::Debug for StateToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StateToken")
            .field("revision", &self.revision)
            .field("digest", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct StoredState {
    pub value: DurableInputState,
    pub token: StateToken,
}

impl fmt::Debug for StoredState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredState")
            .field("value", &self.value)
            .field("token", &self.token)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum LoadResult {
    Missing,
    Current(Box<StoredState>),
}

impl fmt::Debug for LoadResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => formatter.write_str("Missing"),
            Self::Current(state) => formatter.debug_tuple("Current").field(state).finish(),
        }
    }
}

pub struct FileCheckpointStore {
    root: PathBuf,
    writer: Mutex<()>,
}

struct WriterFileLock(File);

impl Drop for WriterFileLock {
    fn drop(&mut self) {
        let _ignored = File::unlock(&self.0);
    }
}

impl fmt::Debug for FileCheckpointStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileCheckpointStore")
            .field("root", &"[CONFIGURED]")
            .finish_non_exhaustive()
    }
}

impl FileCheckpointStore {
    /// Opens a non-creating store rooted at an absolute, non-symlink path.
    ///
    /// # Errors
    ///
    /// Returns an error when the root is relative or an existing state directory is a symlink,
    /// has the wrong type, or is accessible by group/other users on Unix.
    pub fn open(root: &Path) -> Result<Self, StateStoreError> {
        if !root.is_absolute() {
            return Err(StateStoreError::InvalidRoot);
        }
        validate_directory_if_exists(root)?;
        validate_directory_if_exists(&root.join("inputs"))?;
        if let Some(metadata) = inspect_file(&root.join(WRITER_LOCK_FILE))? {
            validate_private_file_mode(&metadata)?;
        }
        Ok(Self {
            root: root.to_path_buf(),
            writer: Mutex::new(()),
        })
    }

    /// Loads one current envelope without creating directories.
    ///
    /// # Errors
    ///
    /// Returns an error for filesystem, permission, envelope, checksum, payload, or state invariant
    /// failures. Corrupt and unsupported files are left untouched.
    pub fn load(&self, key: StateKey) -> Result<LoadResult, StateStoreError> {
        let _guard = self
            .writer
            .lock()
            .map_err(|_| StateStoreError::LockPoisoned)?;
        self.load_unlocked(key)
    }

    /// Creates revision one for a previously missing input.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid state/key relationships, existing state or backup files, or a
    /// failure to create and synchronize the private state path.
    pub fn create(
        &self,
        key: StateKey,
        value: &DurableInputState,
    ) -> Result<StoredState, StateStoreError> {
        validate_key(key, value)?;
        value.validate().map_err(map_validation_error)?;
        let envelope = encode_envelope(value, 1)?;
        let stored = decode_envelope(&envelope)?;
        let _guard = self
            .writer
            .lock()
            .map_err(|_| StateStoreError::LockPoisoned)?;
        let _file_lock = self.acquire_writer_lock()?;
        self.ensure_input_directory(key)?;
        if read_envelope(&self.current_path(key))?.is_some() {
            return Err(StateStoreError::AlreadyExists);
        }
        if inspect_file(&self.previous_path(key))?.is_some() {
            return Err(StateStoreError::OrphanedBackup);
        }
        atomic_write(&self.current_path(key), &envelope, 0o600)?;
        Ok(stored)
    }

    /// Persists one ordinary checkpoint state-machine or append-only scan-progress transition.
    ///
    /// The exact current envelope is first published as `checkpoint.dbx.prev`. Store revision is
    /// incremented for every successful replacement, independently of checkpoint generation.
    /// Configuration activation, identity migration, recovery rewind, and rollback are not ordinary
    /// transitions and are rejected by this method.
    ///
    /// # Errors
    ///
    /// Returns an error for missing/corrupt current state, a stale token, an invalid transition,
    /// revision overflow, or a synchronized write failure.
    pub fn compare_exchange(
        &self,
        key: StateKey,
        expected: StateToken,
        value: &DurableInputState,
    ) -> Result<StoredState, StateStoreError> {
        validate_key(key, value)?;
        value.validate().map_err(map_validation_error)?;
        let _guard = self
            .writer
            .lock()
            .map_err(|_| StateStoreError::LockPoisoned)?;
        let _file_lock = self.acquire_writer_lock()?;
        let (current_bytes, current) = self
            .read_current_unlocked(key)?
            .ok_or(StateStoreError::MissingCurrent)?;
        verify_expected(current.token, expected)?;
        validate_transition(&current.value, value)?;
        self.replace_current_unlocked(key, &current_bytes, &current, value)
    }

    /// Activates a new non-lineage configuration fingerprint at the next durable generation.
    ///
    /// Query and cursor identity are deliberately preserved by this API. Changing either identity
    /// requires a separate administrative migration policy that this store does not infer. The
    /// caller must first stop the input and reconcile every retained spool segment for it.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, an unchanged fingerprint, active work, generation overflow,
    /// or a synchronized write failure.
    pub fn activate_configuration(
        &self,
        key: StateKey,
        expected: StateToken,
        configuration_fingerprint: Fingerprint,
    ) -> Result<StoredState, StateStoreError> {
        let _guard = self
            .writer
            .lock()
            .map_err(|_| StateStoreError::LockPoisoned)?;
        let _file_lock = self.acquire_writer_lock()?;
        let (current_bytes, current) = self
            .read_current_unlocked(key)?
            .ok_or(StateStoreError::MissingCurrent)?;
        verify_expected(current.token, expected)?;
        if current.value.configuration_fingerprint == configuration_fingerprint {
            return Err(StateStoreError::ConfigurationUnchanged);
        }
        if current.value.active_scan.is_some() || current.value.coordinator.active_attempt.is_some()
        {
            return Err(StateStoreError::ConfigurationActivationBlocked);
        }

        let mut next = current.value.clone();
        next.configuration_generation = next
            .configuration_generation
            .checked_add(1)
            .ok_or(StateStoreError::ConfigurationGenerationOverflow)?;
        next.configuration_fingerprint = configuration_fingerprint;
        let fence = configuration_fence_id(
            next.configuration_fingerprint,
            next.configuration_generation,
        );
        next.coordinator = Snapshot::new(
            fence,
            current.value.coordinator.generation,
            current.value.coordinator.committed,
        );
        next.validate().map_err(map_validation_error)?;

        self.replace_current_unlocked(key, &current_bytes, &current, &next)
    }

    /// Explicitly restores the previous payload as a new current store revision.
    ///
    /// The former current envelope becomes the next `.prev`, allowing the restore itself to be
    /// reversed. Cursor/configuration generations may move backward only through this explicit API.
    ///
    /// # Errors
    ///
    /// Returns an error for stale current state, a missing or invalid previous envelope, invalid
    /// input identity, revision overflow, or a synchronized write failure.
    pub fn restore_previous(
        &self,
        key: StateKey,
        expected: StateToken,
    ) -> Result<StoredState, StateStoreError> {
        let _guard = self
            .writer
            .lock()
            .map_err(|_| StateStoreError::LockPoisoned)?;
        let _file_lock = self.acquire_writer_lock()?;
        let (current_bytes, current) = self
            .read_current_unlocked(key)?
            .ok_or(StateStoreError::MissingCurrent)?;
        verify_expected(current.token, expected)?;
        let (_previous_bytes, previous) =
            read_envelope(&self.previous_path(key))?.ok_or(StateStoreError::MissingBackup)?;
        validate_key(key, &previous.value)?;
        let next_revision = current
            .token
            .revision
            .checked_add(1)
            .ok_or(StateStoreError::RevisionOverflow)?;
        let restored_bytes = encode_envelope(&previous.value, next_revision)?;
        let restored = decode_envelope(&restored_bytes)?;

        atomic_write(&self.previous_path(key), &current_bytes, 0o600)?;
        atomic_write(&self.current_path(key), &restored_bytes, 0o600)?;
        Ok(restored)
    }

    fn replace_current_unlocked(
        &self,
        key: StateKey,
        current_bytes: &[u8],
        current: &StoredState,
        value: &DurableInputState,
    ) -> Result<StoredState, StateStoreError> {
        let next_revision = current
            .token
            .revision
            .checked_add(1)
            .ok_or(StateStoreError::RevisionOverflow)?;
        let next_bytes = encode_envelope(value, next_revision)?;
        let next = decode_envelope(&next_bytes)?;

        atomic_write(&self.previous_path(key), current_bytes, 0o600)?;
        atomic_write(&self.current_path(key), &next_bytes, 0o600)?;
        Ok(next)
    }

    fn acquire_writer_lock(&self) -> Result<WriterFileLock, StateStoreError> {
        ensure_directory(&self.root)?;
        let path = self.root.join(WRITER_LOCK_FILE);
        if inspect_file(&path)?.is_none() {
            match dbx_rs_secure_store::write_new(&path, b"", 0o600) {
                Ok(()) => {}
                Err(error) if error.io_kind() == Some(std::io::ErrorKind::AlreadyExists) => {}
                Err(error) => return Err(error.into()),
            }
        }
        let metadata = inspect_file(&path)?.ok_or(StateStoreError::Filesystem)?;
        validate_private_file_mode(&metadata)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|_| StateStoreError::Filesystem)?;
        let metadata = file.metadata().map_err(|_| StateStoreError::Filesystem)?;
        if !metadata.is_file() {
            return Err(StateStoreError::InvalidPathType);
        }
        validate_private_file_mode(&metadata)?;
        File::lock(&file).map_err(|_| StateStoreError::WriterLockUnavailable)?;
        Ok(WriterFileLock(file))
    }

    fn load_unlocked(&self, key: StateKey) -> Result<LoadResult, StateStoreError> {
        match self.read_current_unlocked(key)? {
            Some((_bytes, state)) => Ok(LoadResult::Current(Box::new(state))),
            None => Ok(LoadResult::Missing),
        }
    }

    fn read_current_unlocked(
        &self,
        key: StateKey,
    ) -> Result<Option<(Vec<u8>, StoredState)>, StateStoreError> {
        self.validate_input_directories(key)?;
        let value = read_envelope(&self.current_path(key))?;
        if let Some((_bytes, state)) = &value {
            validate_key(key, &state.value)?;
        }
        Ok(value)
    }

    fn validate_input_directories(&self, key: StateKey) -> Result<(), StateStoreError> {
        validate_directory_if_exists(&self.root)?;
        validate_directory_if_exists(&self.root.join("inputs"))?;
        validate_directory_if_exists(&self.input_directory(key))
    }

    fn ensure_input_directory(&self, key: StateKey) -> Result<(), StateStoreError> {
        ensure_directory(&self.root)?;
        let inputs = self.root.join("inputs");
        ensure_directory(&inputs)?;
        ensure_directory(&self.input_directory(key))
    }

    fn input_directory(&self, key: StateKey) -> PathBuf {
        self.root.join("inputs").join(key.directory_name())
    }

    fn current_path(&self, key: StateKey) -> PathBuf {
        self.input_directory(key).join(CURRENT_FILE)
    }

    fn previous_path(&self, key: StateKey) -> PathBuf {
        self.input_directory(key).join(PREVIOUS_FILE)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateStoreError {
    InvalidRoot,
    PathSymlink,
    InvalidPathType,
    InvalidPermissions,
    Filesystem,
    LockPoisoned,
    WriterLockUnavailable,
    AlreadyExists,
    OrphanedBackup,
    MissingCurrent,
    MissingBackup,
    StateKeyMismatch,
    EnvelopeTooLarge,
    EnvelopeTruncated,
    InvalidMagic,
    UnsupportedEnvelopeVersion,
    UnsupportedCodec,
    InvalidRevision,
    InvalidEnvelopeLength,
    TrailingData,
    ChecksumMismatch,
    InvalidPayload,
    UnsupportedStateVersion,
    InvalidState(StateValidationError),
    StaleRevision,
    StaleDigest,
    RevisionOverflow,
    NoStateChange,
    IdentityMigrationRequired,
    ConfigurationActivationRequired,
    ConfigurationActivationBlocked,
    ConfigurationUnchanged,
    ConfigurationGenerationOverflow,
    InvalidCheckpointTransition,
    ScanProgressRegression,
    ConfigurationGenerationRegression,
    CheckpointGenerationRegression,
}

impl fmt::Display for StateStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidRoot => "state root is invalid",
            Self::PathSymlink => "state path must not be a symbolic link",
            Self::InvalidPathType => "state path has an invalid file type",
            Self::InvalidPermissions => "state path permissions are too broad",
            Self::Filesystem => "state filesystem operation failed",
            Self::LockPoisoned => "state writer lock is unavailable",
            Self::WriterLockUnavailable => "state filesystem writer lock is unavailable",
            Self::AlreadyExists => "checkpoint state already exists",
            Self::OrphanedBackup => "checkpoint backup exists without current state",
            Self::MissingCurrent => "current checkpoint state is missing",
            Self::MissingBackup => "previous checkpoint state is missing",
            Self::StateKeyMismatch => "checkpoint state identity does not match its key",
            Self::EnvelopeTooLarge => "checkpoint envelope exceeds the hard size limit",
            Self::EnvelopeTruncated => "checkpoint envelope is truncated",
            Self::InvalidMagic => "checkpoint envelope magic is invalid",
            Self::UnsupportedEnvelopeVersion => "checkpoint envelope version is unsupported",
            Self::UnsupportedCodec => "checkpoint envelope codec is unsupported",
            Self::InvalidRevision => "checkpoint store revision is invalid",
            Self::InvalidEnvelopeLength => "checkpoint envelope length is invalid",
            Self::TrailingData => "checkpoint envelope has trailing data",
            Self::ChecksumMismatch => "checkpoint envelope checksum does not match",
            Self::InvalidPayload => "checkpoint payload is invalid",
            Self::UnsupportedStateVersion => "checkpoint payload version is unsupported",
            Self::InvalidState(_) => "checkpoint payload invariants are invalid",
            Self::StaleRevision => "checkpoint store revision is stale",
            Self::StaleDigest => "checkpoint store digest is stale",
            Self::RevisionOverflow => "checkpoint store revision is exhausted",
            Self::NoStateChange => "checkpoint state transition does not change durable state",
            Self::IdentityMigrationRequired => {
                "query or cursor identity change requires explicit migration"
            }
            Self::ConfigurationActivationRequired => {
                "configuration change requires explicit activation"
            }
            Self::ConfigurationActivationBlocked => {
                "configuration activation is blocked by active work"
            }
            Self::ConfigurationUnchanged => "configuration fingerprint is already active",
            Self::ConfigurationGenerationOverflow => "configuration generation is exhausted",
            Self::InvalidCheckpointTransition => {
                "checkpoint transition was not produced by the coordinator state machine"
            }
            Self::ScanProgressRegression => "checkpoint scan progress is not append-only",
            Self::ConfigurationGenerationRegression => {
                "checkpoint configuration generation regresses durable state"
            }
            Self::CheckpointGenerationRegression => "checkpoint generation regresses durable state",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for StateStoreError {}

impl From<SecureStoreError> for StateStoreError {
    fn from(_error: SecureStoreError) -> Self {
        Self::Filesystem
    }
}

fn validate_key(key: StateKey, value: &DurableInputState) -> Result<(), StateStoreError> {
    if StateKey::for_input(value.input_id) != key {
        return Err(StateStoreError::StateKeyMismatch);
    }
    Ok(())
}

fn validate_transition(
    current: &DurableInputState,
    next: &DurableInputState,
) -> Result<(), StateStoreError> {
    if current.input_id != next.input_id {
        return Err(StateStoreError::StateKeyMismatch);
    }
    if current.query_fingerprint != next.query_fingerprint
        || current.cursor_identity_fingerprint != next.cursor_identity_fingerprint
    {
        return Err(StateStoreError::IdentityMigrationRequired);
    }
    if next.configuration_generation < current.configuration_generation {
        return Err(StateStoreError::ConfigurationGenerationRegression);
    }
    if current.configuration_fingerprint != next.configuration_fingerprint
        || current.configuration_generation != next.configuration_generation
    {
        return Err(StateStoreError::ConfigurationActivationRequired);
    }
    if next.coordinator.generation < current.coordinator.generation {
        return Err(StateStoreError::CheckpointGenerationRegression);
    }
    let transition = classify_checkpoint_transition(&current.coordinator, &next.coordinator)?;
    validate_scan_transition(current, next, transition)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CheckpointTransition {
    Unchanged,
    StartAttempt,
    CollectionCompleted,
    CollectionFailed,
    DeliveryChanged,
    Commit,
}

fn classify_checkpoint_transition(
    current: &Snapshot,
    next: &Snapshot,
) -> Result<CheckpointTransition, StateStoreError> {
    if current == next {
        return Ok(CheckpointTransition::Unchanged);
    }

    if let Some(active) = &next.active_attempt {
        if snapshot_after(current, next, |snapshot| {
            snapshot.start_attempt(active.fence)
        }) {
            return Ok(CheckpointTransition::StartAttempt);
        }
        match &active.collection {
            CollectionState::Completed { rows, candidate }
                if snapshot_after(current, next, |snapshot| {
                    snapshot.collection_completed(active.fence, *rows, *candidate)
                }) =>
            {
                return Ok(CheckpointTransition::CollectionCompleted);
            }
            CollectionState::Failed
                if snapshot_after(current, next, |snapshot| {
                    snapshot.collection_failed(active.fence)
                }) =>
            {
                return Ok(CheckpointTransition::CollectionFailed);
            }
            CollectionState::InProgress
            | CollectionState::Completed { .. }
            | CollectionState::Failed => {}
        }
        match active.delivery {
            DeliveryState::Confirmed { rows }
                if snapshot_after(current, next, |snapshot| {
                    snapshot.delivery_confirmed(active.fence, rows)
                }) =>
            {
                return Ok(CheckpointTransition::DeliveryChanged);
            }
            DeliveryState::Failed
                if snapshot_after(current, next, |snapshot| {
                    snapshot.delivery_failed(active.fence)
                }) =>
            {
                return Ok(CheckpointTransition::DeliveryChanged);
            }
            DeliveryState::Uncertain
                if snapshot_after(current, next, |snapshot| {
                    snapshot.delivery_uncertain(active.fence)
                }) =>
            {
                return Ok(CheckpointTransition::DeliveryChanged);
            }
            DeliveryState::InProgress
            | DeliveryState::Confirmed { .. }
            | DeliveryState::Failed
            | DeliveryState::Uncertain => {}
        }
    }

    if let Some(active) = &current.active_attempt
        && snapshot_after(current, next, |snapshot| snapshot.commit(active.fence))
    {
        return Ok(CheckpointTransition::Commit);
    }

    Err(StateStoreError::InvalidCheckpointTransition)
}

fn snapshot_after<T, E>(
    current: &Snapshot,
    next: &Snapshot,
    transition: impl FnOnce(&mut Snapshot) -> Result<T, E>,
) -> bool {
    let mut candidate = current.clone();
    transition(&mut candidate).is_ok() && candidate == *next
}

fn validate_scan_transition(
    current: &DurableInputState,
    next: &DurableInputState,
    transition: CheckpointTransition,
) -> Result<(), StateStoreError> {
    match transition {
        CheckpointTransition::Unchanged => {
            let active = current
                .coordinator
                .active_attempt
                .as_ref()
                .ok_or(StateStoreError::NoStateChange)?;
            if active.collection != CollectionState::InProgress {
                return Err(StateStoreError::InvalidCheckpointTransition);
            }
            match (&current.active_scan, &next.active_scan) {
                (None, Some(scan)) => validate_initial_scan(scan),
                (Some(current), Some(next)) => validate_scan_append(current, next, false),
                (None, None) => Err(StateStoreError::NoStateChange),
                (Some(_), None) => Err(StateStoreError::ScanProgressRegression),
            }
        }
        CheckpointTransition::StartAttempt => {
            if current.active_scan.is_some() {
                return Err(StateStoreError::ScanProgressRegression);
            }
            next.active_scan
                .as_ref()
                .map_or(Ok(()), validate_initial_scan)
        }
        CheckpointTransition::CollectionCompleted => {
            match (&current.active_scan, &next.active_scan) {
                (None, None) => Ok(()),
                (Some(current), Some(next)) => validate_scan_append(current, next, true),
                (None, Some(_)) | (Some(_), None) => Err(StateStoreError::ScanProgressRegression),
            }
        }
        CheckpointTransition::CollectionFailed | CheckpointTransition::DeliveryChanged => {
            if current.active_scan == next.active_scan {
                Ok(())
            } else {
                Err(StateStoreError::ScanProgressRegression)
            }
        }
        CheckpointTransition::Commit => {
            if next.active_scan.is_none() {
                Ok(())
            } else {
                Err(StateStoreError::ScanProgressRegression)
            }
        }
    }
}

fn validate_initial_scan(scan: &ActiveScan) -> Result<(), StateStoreError> {
    if scan.next_page == 1
        && !scan.complete
        && scan.segments.is_empty()
        && scan.resume_after.is_none()
        && scan.maximum_candidate.is_none()
    {
        Ok(())
    } else {
        Err(StateStoreError::ScanProgressRegression)
    }
}

fn validate_scan_append(
    current: &ActiveScan,
    next: &ActiveScan,
    completes_collection: bool,
) -> Result<(), StateStoreError> {
    if current.attempt_id != next.attempt_id
        || current.base_committed != next.base_committed
        || current.complete
        || next.complete != completes_collection
        || next.next_page < current.next_page
        || !next.segments.starts_with(&current.segments)
    {
        return Err(StateStoreError::ScanProgressRegression);
    }

    let appended = next.segments.len() > current.segments.len();
    if !appended {
        if next.next_page != current.next_page
            || next.resume_after != current.resume_after
            || next.maximum_candidate != current.maximum_candidate
        {
            return Err(StateStoreError::ScanProgressRegression);
        }
        return if completes_collection {
            Ok(())
        } else {
            Err(StateStoreError::NoStateChange)
        };
    }

    if !cursor_strictly_advances(current.resume_after, next.resume_after)
        || cursor_regresses(current.maximum_candidate, next.maximum_candidate)
    {
        return Err(StateStoreError::ScanProgressRegression);
    }
    Ok(())
}

fn cursor_strictly_advances(
    current: Option<dbx_rs_connector_sdk::TimestampIdCursor>,
    next: Option<dbx_rs_connector_sdk::TimestampIdCursor>,
) -> bool {
    match (current, next) {
        (None, Some(_)) => true,
        (Some(current), Some(next)) => next.position_cmp(&current) == Ordering::Greater,
        (None | Some(_), None) => false,
    }
}

fn cursor_regresses(
    current: Option<dbx_rs_connector_sdk::TimestampIdCursor>,
    next: Option<dbx_rs_connector_sdk::TimestampIdCursor>,
) -> bool {
    match (current, next) {
        (Some(current), Some(next)) => next.position_cmp(&current) == Ordering::Less,
        (Some(_), None) => true,
        (None, None | Some(_)) => false,
    }
}

fn verify_expected(current: StateToken, expected: StateToken) -> Result<(), StateStoreError> {
    if current.revision != expected.revision {
        return Err(StateStoreError::StaleRevision);
    }
    if current.digest != expected.digest {
        return Err(StateStoreError::StaleDigest);
    }
    Ok(())
}

fn encode_envelope(value: &DurableInputState, revision: u64) -> Result<Vec<u8>, StateStoreError> {
    value.validate().map_err(map_validation_error)?;
    let payload = serde_json::to_vec(value).map_err(|_| StateStoreError::InvalidPayload)?;
    encode_payload(&payload, revision)
}

fn encode_payload(payload: &[u8], revision: u64) -> Result<Vec<u8>, StateStoreError> {
    if revision == 0 {
        return Err(StateStoreError::InvalidRevision);
    }
    let total = HEADER_BYTES
        .checked_add(payload.len())
        .ok_or(StateStoreError::EnvelopeTooLarge)?;
    if u64::try_from(total).map_or(true, |total| total > MAX_ENVELOPE_BYTES) {
        return Err(StateStoreError::EnvelopeTooLarge);
    }
    let payload_len =
        u32::try_from(payload.len()).map_err(|_| StateStoreError::EnvelopeTooLarge)?;
    let mut bytes = vec![0_u8; total];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&DURABLE_ENVELOPE_VERSION.to_be_bytes());
    bytes[10..12].copy_from_slice(&JSON_CODEC.to_be_bytes());
    bytes[12..16].copy_from_slice(&payload_len.to_be_bytes());
    bytes[16..24].copy_from_slice(&revision.to_be_bytes());
    bytes[HEADER_BYTES..].copy_from_slice(payload);
    let checksum = envelope_checksum(&bytes[..CHECKSUM_START], payload);
    bytes[CHECKSUM_START..CHECKSUM_END].copy_from_slice(&checksum);
    Ok(bytes)
}

fn decode_envelope(bytes: &[u8]) -> Result<StoredState, StateStoreError> {
    if u64::try_from(bytes.len()).map_or(true, |length| length > MAX_ENVELOPE_BYTES) {
        return Err(StateStoreError::EnvelopeTooLarge);
    }
    if bytes.len() < HEADER_BYTES {
        return Err(StateStoreError::EnvelopeTruncated);
    }
    if &bytes[..8] != MAGIC {
        return Err(StateStoreError::InvalidMagic);
    }
    let envelope_version = u16::from_be_bytes([bytes[8], bytes[9]]);
    if envelope_version != DURABLE_ENVELOPE_VERSION {
        return Err(StateStoreError::UnsupportedEnvelopeVersion);
    }
    let codec = u16::from_be_bytes([bytes[10], bytes[11]]);
    if codec != JSON_CODEC {
        return Err(StateStoreError::UnsupportedCodec);
    }
    let payload_length = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let payload_length =
        usize::try_from(payload_length).map_err(|_| StateStoreError::InvalidEnvelopeLength)?;
    let expected_length = HEADER_BYTES
        .checked_add(payload_length)
        .ok_or(StateStoreError::InvalidEnvelopeLength)?;
    match bytes.len().cmp(&expected_length) {
        std::cmp::Ordering::Less => return Err(StateStoreError::EnvelopeTruncated),
        std::cmp::Ordering::Greater => return Err(StateStoreError::TrailingData),
        std::cmp::Ordering::Equal => {}
    }
    let mut revision_bytes = [0_u8; 8];
    revision_bytes.copy_from_slice(&bytes[16..24]);
    let revision = u64::from_be_bytes(revision_bytes);
    if revision == 0 {
        return Err(StateStoreError::InvalidRevision);
    }
    let payload = &bytes[HEADER_BYTES..];
    let calculated = envelope_checksum(&bytes[..CHECKSUM_START], payload);
    let mut stored_digest = [0_u8; 32];
    stored_digest.copy_from_slice(&bytes[CHECKSUM_START..CHECKSUM_END]);
    if calculated != stored_digest {
        return Err(StateStoreError::ChecksumMismatch);
    }
    let value = serde_json::from_slice::<DurableInputState>(payload)
        .map_err(|_| StateStoreError::InvalidPayload)?;
    value.validate().map_err(map_validation_error)?;
    Ok(StoredState {
        value,
        token: StateToken {
            revision,
            digest: stored_digest,
        },
    })
}

fn envelope_checksum(prefix: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut context = Context::new(&SHA256);
    context.update(CHECKSUM_DOMAIN);
    context.update(prefix);
    context.update(payload);
    let mut checksum = [0_u8; 32];
    checksum.copy_from_slice(context.finish().as_ref());
    checksum
}

fn map_validation_error(error: StateValidationError) -> StateStoreError {
    if matches!(
        error,
        StateValidationError::UnsupportedStateVersion
            | StateValidationError::UnsupportedCoordinatorVersion
    ) {
        StateStoreError::UnsupportedStateVersion
    } else {
        StateStoreError::InvalidState(error)
    }
}

fn read_envelope(path: &Path) -> Result<Option<(Vec<u8>, StoredState)>, StateStoreError> {
    let Some(metadata) = inspect_file(path)? else {
        return Ok(None);
    };
    if metadata.len() > MAX_ENVELOPE_BYTES {
        return Err(StateStoreError::EnvelopeTooLarge);
    }
    validate_private_file_mode(&metadata)?;
    let bytes = read_limited(path, MAX_ENVELOPE_BYTES)?;
    let state = decode_envelope(&bytes)?;
    Ok(Some((bytes, state)))
}

fn inspect_file(path: &Path) -> Result<Option<fs::Metadata>, StateStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(StateStoreError::PathSymlink);
            }
            if !metadata.is_file() {
                return Err(StateStoreError::InvalidPathType);
            }
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(StateStoreError::Filesystem),
    }
}

fn ensure_directory(path: &Path) -> Result<(), StateStoreError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_directory_if_exists(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ensure_private_dir(path)?;
            validate_directory_if_exists(path)
        }
        Err(_) => Err(StateStoreError::Filesystem),
    }
}

fn validate_directory_if_exists(path: &Path) -> Result<(), StateStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(StateStoreError::PathSymlink);
            }
            if !metadata.is_dir() {
                return Err(StateStoreError::InvalidPathType);
            }
            validate_private_directory_mode(&metadata)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(StateStoreError::Filesystem),
    }
}

#[cfg(unix)]
fn validate_private_directory_mode(metadata: &fs::Metadata) -> Result<(), StateStoreError> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(StateStoreError::InvalidPermissions);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_directory_mode(_metadata: &fs::Metadata) -> Result<(), StateStoreError> {
    Ok(())
}

#[cfg(unix)]
fn validate_private_file_mode(metadata: &fs::Metadata) -> Result<(), StateStoreError> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(StateStoreError::InvalidPermissions);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_file_mode(_metadata: &fs::Metadata) -> Result<(), StateStoreError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    use dbx_rs_checkpoint::{AttemptFence, AttemptId, Snapshot};
    use dbx_rs_connector_sdk::TimestampIdCursor;

    use crate::model::DURABLE_STATE_FORMAT_VERSION;
    use crate::{Fingerprint, InputId, configuration_fence_id};

    use super::*;

    const CONFIGURATION: [u8; 32] = [0x31; 32];
    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    fn root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "dbx-rs-state-{label}-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn configuration_fingerprint() -> Fingerprint {
        Fingerprint::new(CONFIGURATION)
    }

    fn configuration_fence() -> [u8; 32] {
        configuration_fence_id(configuration_fingerprint(), 1)
    }

    fn state() -> DurableInputState {
        DurableInputState::new(
            InputId::new([0x11; 16]),
            Fingerprint::new([0x21; 32]),
            Fingerprint::new([0x22; 32]),
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

    fn next_state(byte: u8) -> DurableInputState {
        let mut value = state();
        let fence = AttemptFence::new(
            AttemptId::new([byte; 16]),
            value.coordinator.configuration_id,
            value.coordinator.generation,
        );
        value
            .coordinator
            .start_attempt(fence)
            .expect("test attempt must start");
        value
    }

    fn store(label: &str) -> (PathBuf, FileCheckpointStore, StateKey) {
        let root = root(label);
        let store = FileCheckpointStore::open(&root).expect("store must open");
        let key = StateKey::for_input(state().input_id);
        (root, store, key)
    }

    #[test]
    fn envelope_round_trip_and_header_are_stable() {
        let state = state();
        let first = encode_envelope(&state, 9).expect("envelope encodes");
        let second = encode_envelope(&state, 9).expect("envelope encodes deterministically");
        assert_eq!(first, second);
        assert_eq!(&first[..8], MAGIC);
        assert_eq!(&first[8..10], &DURABLE_ENVELOPE_VERSION.to_be_bytes());
        assert_eq!(&first[10..12], &JSON_CODEC.to_be_bytes());
        assert_eq!(&first[16..24], &9_u64.to_be_bytes());
        let decoded = decode_envelope(&first).expect("envelope decodes");
        assert_eq!(decoded.value, state);
        assert_eq!(decoded.token.revision, 9);
        assert_eq!(&first[24..56], decoded.token.digest.as_slice());
    }

    #[test]
    fn every_prefix_truncation_is_rejected() {
        let bytes = encode_envelope(&state(), 1).expect("envelope encodes");
        for length in 0..bytes.len() {
            assert_eq!(
                decode_envelope(&bytes[..length]),
                Err(StateStoreError::EnvelopeTruncated),
                "prefix length {length} must fail as truncated"
            );
        }
    }

    #[test]
    fn tamper_trailing_and_oversize_are_rejected() {
        let bytes = encode_envelope(&state(), 1).expect("envelope encodes");

        let mut payload_tamper = bytes.clone();
        let last = payload_tamper.len() - 1;
        payload_tamper[last] ^= 1;
        assert_eq!(
            decode_envelope(&payload_tamper),
            Err(StateStoreError::ChecksumMismatch)
        );

        let mut checksum_tamper = bytes.clone();
        checksum_tamper[24] ^= 1;
        assert_eq!(
            decode_envelope(&checksum_tamper),
            Err(StateStoreError::ChecksumMismatch)
        );

        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            decode_envelope(&trailing),
            Err(StateStoreError::TrailingData)
        );
        assert_eq!(
            decode_envelope(&vec![0; usize::try_from(MAX_ENVELOPE_BYTES).unwrap() + 1]),
            Err(StateStoreError::EnvelopeTooLarge)
        );
    }

    #[test]
    fn unsupported_envelope_codec_and_payload_versions_are_distinct() {
        let mut envelope = encode_envelope(&state(), 1).expect("envelope encodes");
        envelope[8..10].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            decode_envelope(&envelope),
            Err(StateStoreError::UnsupportedEnvelopeVersion)
        );

        let mut envelope = encode_envelope(&state(), 1).expect("envelope encodes");
        envelope[10..12].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            decode_envelope(&envelope),
            Err(StateStoreError::UnsupportedCodec)
        );

        let mut future = state();
        future.format_version = DURABLE_STATE_FORMAT_VERSION + 1;
        let payload = serde_json::to_vec(&future).expect("future state serializes");
        let envelope = encode_payload(&payload, 1).expect("raw envelope encodes");
        assert_eq!(
            decode_envelope(&envelope),
            Err(StateStoreError::UnsupportedStateVersion)
        );

        let mut future = state();
        future.coordinator.format_version += 1;
        let payload = serde_json::to_vec(&future).expect("future coordinator serializes");
        let envelope = encode_payload(&payload, 1).expect("raw envelope encodes");
        assert_eq!(
            decode_envelope(&envelope),
            Err(StateStoreError::UnsupportedStateVersion)
        );
    }

    #[test]
    fn invalid_magic_payload_and_zero_revision_are_rejected() {
        let mut magic = encode_envelope(&state(), 1).expect("envelope encodes");
        magic[0] ^= 1;
        assert_eq!(decode_envelope(&magic), Err(StateStoreError::InvalidMagic));

        let invalid_payload = encode_payload(b"{", 1).expect("raw payload envelope encodes");
        assert_eq!(
            decode_envelope(&invalid_payload),
            Err(StateStoreError::InvalidPayload)
        );

        let mut zero_revision = encode_envelope(&state(), 1).expect("envelope encodes");
        zero_revision[16..24].fill(0);
        let checksum = envelope_checksum(
            &zero_revision[..CHECKSUM_START],
            &zero_revision[HEADER_BYTES..],
        );
        zero_revision[CHECKSUM_START..CHECKSUM_END].copy_from_slice(&checksum);
        assert_eq!(
            decode_envelope(&zero_revision),
            Err(StateStoreError::InvalidRevision)
        );
    }

    #[test]
    fn create_load_and_compare_exchange_use_revision_and_digest() {
        let (root, store, key) = store("cas");
        assert_eq!(store.load(key), Ok(LoadResult::Missing));
        let created = store.create(key, &state()).expect("state must be created");
        assert_eq!(created.token.revision, 1);
        assert_eq!(
            store.load(key),
            Ok(LoadResult::Current(Box::new(created.clone())))
        );

        let mut stale_digest = created.token;
        stale_digest.digest[0] ^= 1;
        assert_eq!(
            store.compare_exchange(key, stale_digest, &next_state(0x41)),
            Err(StateStoreError::StaleDigest)
        );
        let mut stale_revision = created.token;
        stale_revision.revision = 0;
        assert_eq!(
            store.compare_exchange(key, stale_revision, &next_state(0x41)),
            Err(StateStoreError::StaleRevision)
        );

        let next = store
            .compare_exchange(key, created.token, &next_state(0x41))
            .expect("matching CAS must succeed");
        assert_eq!(next.token.revision, 2);
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn previous_state_is_restored_as_a_new_revision() {
        let (root, store, key) = store("restore");
        let original_value = state();
        let original = store
            .create(key, &original_value)
            .expect("state must be created");
        let changed = store
            .compare_exchange(key, original.token, &next_state(0x41))
            .expect("state must advance");
        let restored = store
            .restore_previous(key, changed.token)
            .expect("previous state must restore");
        assert_eq!(restored.token.revision, 3);
        assert_eq!(restored.value, original_value);

        let undone = store
            .restore_previous(key, restored.token)
            .expect("restore must itself be reversible");
        assert_eq!(undone.token.revision, 4);
        assert_eq!(undone.value, changed.value);
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn corrupt_previous_state_does_not_change_current() {
        let (root, store, key) = store("corrupt-previous");
        let original = store.create(key, &state()).expect("state must be created");
        let changed = store
            .compare_exchange(key, original.token, &next_state(0x41))
            .expect("state must advance");
        let previous_path = store.previous_path(key);
        let mut previous = fs::read(&previous_path).expect("previous envelope must be readable");
        let last = previous.len() - 1;
        previous[last] ^= 1;
        fs::write(previous_path, previous).expect("previous envelope must be corrupted");

        assert_eq!(
            store.restore_previous(key, changed.token),
            Err(StateStoreError::ChecksumMismatch)
        );
        assert_eq!(store.load(key), Ok(LoadResult::Current(Box::new(changed))));
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn ordinary_cas_rejects_fabricated_commit_and_identity_changes() {
        let (root, store, key) = store("ordinary-transition");
        let initial = store.create(key, &state()).expect("state must be created");

        let mut fabricated = state();
        fabricated.coordinator = Snapshot::new(
            configuration_fence(),
            fabricated.coordinator.generation + 1,
            Some(TimestampIdCursor::new(9_999, 99)),
        );
        assert_eq!(
            store.compare_exchange(key, initial.token, &fabricated),
            Err(StateStoreError::InvalidCheckpointTransition)
        );

        let mut changed_query = state();
        changed_query.query_fingerprint = Fingerprint::new([0x71; 32]);
        assert_eq!(
            store.compare_exchange(key, initial.token, &changed_query),
            Err(StateStoreError::IdentityMigrationRequired)
        );

        let mut changed_cursor = state();
        changed_cursor.cursor_identity_fingerprint = Fingerprint::new([0x72; 32]);
        assert_eq!(
            store.compare_exchange(key, initial.token, &changed_cursor),
            Err(StateStoreError::IdentityMigrationRequired)
        );
        assert_eq!(store.load(key), Ok(LoadResult::Current(Box::new(initial))));
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn configuration_activation_fences_aba_and_generic_cas() {
        let (root, store, key) = store("configuration-activation");
        let initial = store.create(key, &state()).expect("state must be created");
        let stale_fence = AttemptFence::new(
            AttemptId::new([0x91; 16]),
            initial.value.coordinator.configuration_id,
            initial.value.coordinator.generation,
        );
        let configuration_b = Fingerprint::new([0x81; 32]);

        let mut generic_change = state();
        generic_change.configuration_generation = 2;
        generic_change.configuration_fingerprint = configuration_b;
        generic_change.coordinator = Snapshot::new(
            configuration_fence_id(configuration_b, 2),
            generic_change.coordinator.generation,
            generic_change.coordinator.committed,
        );
        assert_eq!(
            store.compare_exchange(key, initial.token, &generic_change),
            Err(StateStoreError::ConfigurationActivationRequired)
        );

        let activated_b = store
            .activate_configuration(key, initial.token, configuration_b)
            .expect("configuration B must activate");
        assert_eq!(activated_b.value.configuration_generation, 2);
        let activated_a = store
            .activate_configuration(key, activated_b.token, configuration_fingerprint())
            .expect("configuration A must reactivate");
        assert_eq!(activated_a.value.configuration_generation, 3);
        assert_ne!(
            activated_a.value.coordinator.configuration_id,
            stale_fence.configuration_id
        );
        assert!(
            activated_a
                .value
                .coordinator
                .clone()
                .start_attempt(stale_fence)
                .is_err()
        );
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn scan_progress_is_append_only_and_exact_commit_is_accepted() {
        let (root, store, key) = store("scan-progress");
        let initial = store.create(key, &state()).expect("state must be created");
        let mut started = state();
        let fence = AttemptFence::new(
            AttemptId::new([0x41; 16]),
            started.coordinator.configuration_id,
            started.coordinator.generation,
        );
        started
            .coordinator
            .start_attempt(fence)
            .expect("attempt must start");
        started.active_scan = Some(ActiveScan {
            attempt_id: fence.attempt_id,
            base_committed: started.coordinator.committed,
            resume_after: None,
            maximum_candidate: None,
            next_page: 1,
            complete: false,
            segments: Vec::new(),
        });
        let started = store
            .compare_exchange(key, initial.token, &started)
            .expect("attempt and empty scan must persist");

        let first_candidate = TimestampIdCursor::new(1_001, 11);
        let mut first_page = started.value.clone();
        first_page.active_scan = Some(ActiveScan {
            attempt_id: fence.attempt_id,
            base_committed: first_page.coordinator.committed,
            resume_after: Some(first_candidate),
            maximum_candidate: Some(first_candidate),
            next_page: 2,
            complete: false,
            segments: vec![crate::SegmentRef::new([0x51; 16], 1, 1, 1, [0x61; 32])],
        });
        let first_page = store
            .compare_exchange(key, started.token, &first_page)
            .expect("first sealed page must append");

        let mut dropped = first_page.value.clone();
        dropped.active_scan = None;
        assert_eq!(
            store.compare_exchange(key, first_page.token, &dropped),
            Err(StateStoreError::ScanProgressRegression)
        );

        let mut regressed = first_page.value.clone();
        regressed
            .active_scan
            .as_mut()
            .expect("scan exists")
            .resume_after = Some(TimestampIdCursor::new(1_000, 10));
        assert_eq!(
            store.compare_exchange(key, first_page.token, &regressed),
            Err(StateStoreError::ScanProgressRegression)
        );

        let second_candidate = TimestampIdCursor::new(1_002, 12);
        let mut completed = first_page.value.clone();
        let scan = completed.active_scan.as_mut().expect("scan exists");
        scan.resume_after = Some(second_candidate);
        scan.maximum_candidate = Some(second_candidate);
        scan.next_page = 3;
        scan.complete = true;
        scan.segments
            .push(crate::SegmentRef::new([0x52; 16], 2, 2, 1, [0x62; 32]));
        completed
            .coordinator
            .collection_completed(fence, 2, Some(second_candidate))
            .expect("collection must complete");
        let completed = store
            .compare_exchange(key, first_page.token, &completed)
            .expect("completed scan must persist");

        let mut delivered = completed.value.clone();
        delivered
            .coordinator
            .delivery_confirmed(fence, 2)
            .expect("delivery must confirm");
        let delivered = store
            .compare_exchange(key, completed.token, &delivered)
            .expect("delivery state must persist");
        let mut committed = delivered.value.clone();
        committed
            .coordinator
            .commit(fence)
            .expect("checkpoint must commit");
        committed.active_scan = None;
        let committed = store
            .compare_exchange(key, delivered.token, &committed)
            .expect("exact coordinator commit must persist");
        assert_eq!(
            committed.value.coordinator.committed,
            Some(second_candidate)
        );
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn exactly_one_independent_store_compare_exchange_succeeds() {
        let root = root("concurrent");
        let first_store = FileCheckpointStore::open(&root).expect("first store must open");
        let key = StateKey::for_input(state().input_id);
        let created = first_store
            .create(key, &state())
            .expect("state must be created");
        let second_store = FileCheckpointStore::open(&root).expect("second store must open");
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for (byte, store) in [(0x41, first_store), (0x42, second_store)] {
            let barrier = Arc::clone(&barrier);
            let token = created.token;
            handles.push(thread::spawn(move || {
                barrier.wait();
                store.compare_exchange(key, token, &next_state(byte))
            }));
        }
        barrier.wait();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().expect("writer must not panic"))
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(StateStoreError::StaleRevision)))
                .count(),
            1
        );
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn persisted_oversize_is_rejected_before_reading() {
        let (root, store, key) = store("oversize");
        store.create(key, &state()).expect("state must be created");
        fs::write(
            store.current_path(key),
            vec![0; usize::try_from(MAX_ENVELOPE_BYTES).unwrap() + 1],
        )
        .expect("oversize fixture must be written");
        assert_eq!(store.load(key), Err(StateStoreError::EnvelopeTooLarge));
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn tampered_current_state_fails_closed_without_rewrite() {
        let (root, store, key) = store("tampered-current");
        store.create(key, &state()).expect("state must be created");
        let current = store.current_path(key);
        let mut tampered = fs::read(&current).expect("current envelope must be readable");
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        fs::write(&current, &tampered).expect("current envelope must be corrupted");

        assert_eq!(store.load(key), Err(StateStoreError::ChecksumMismatch));
        assert_eq!(
            fs::read(&current).expect("corrupt envelope remains readable"),
            tampered
        );
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[cfg(unix)]
    #[test]
    fn directories_and_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let (root, store, key) = store("modes");
        let created = store.create(key, &state()).expect("state must be created");
        store
            .compare_exchange(key, created.token, &next_state(0x41))
            .expect("state must advance");
        for directory in [&root, &root.join("inputs"), &store.input_directory(key)] {
            let mode = fs::metadata(directory)
                .expect("directory metadata exists")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700);
        }
        for file in [
            store.current_path(key),
            store.previous_path(key),
            root.join(WRITER_LOCK_FILE),
        ] {
            let mode = fs::metadata(file)
                .expect("file metadata exists")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_root_and_current_file_are_rejected() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let target = root("symlink-target");
        fs::create_dir(&target).expect("target directory must be created");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700))
            .expect("target mode must be private");
        let link = root("symlink-root");
        symlink(&target, &link).expect("root symlink must be created");
        assert!(matches!(
            FileCheckpointStore::open(&link),
            Err(StateStoreError::PathSymlink)
        ));
        fs::remove_file(&link).expect("root symlink must be removed");
        fs::remove_dir(&target).expect("target directory must be removed");

        let (root, store, key) = store("symlink-current");
        store.create(key, &state()).expect("state must be created");
        let current = store.current_path(key);
        let target = store.input_directory(key).join("target");
        fs::rename(&current, &target).expect("current must move to target");
        symlink(&target, &current).expect("current symlink must be created");
        assert_eq!(store.load(key), Err(StateStoreError::PathSymlink));
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[cfg(unix)]
    #[test]
    fn invalid_root_and_current_file_types_are_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let root_file = root("root-file");
        fs::write(&root_file, b"not a directory").expect("root fixture must be written");
        fs::set_permissions(&root_file, fs::Permissions::from_mode(0o600))
            .expect("root fixture mode must be private");
        assert!(matches!(
            FileCheckpointStore::open(&root_file),
            Err(StateStoreError::InvalidPathType)
        ));
        fs::remove_file(root_file).expect("root fixture must be removed");

        let (root, store, key) = store("current-directory");
        store.create(key, &state()).expect("state must be created");
        let current = store.current_path(key);
        fs::remove_file(&current).expect("current file must be removed");
        fs::create_dir(&current).expect("current directory fixture must be created");
        assert_eq!(store.load(key), Err(StateStoreError::InvalidPathType));
        fs::remove_dir_all(root).expect("fixture must be removed");
    }
}
