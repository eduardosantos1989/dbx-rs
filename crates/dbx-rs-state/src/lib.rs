//! Durable, bounded checkpoint state storage.

#![forbid(unsafe_code)]

mod model;
mod store;

pub use model::{
    ActiveScan, DurableInputState, Fingerprint, InputId, MAX_SEGMENTS_PER_SCAN, SegmentRef,
    StateKey, StateValidationError, configuration_fence_id,
};
pub use store::{
    DURABLE_ENVELOPE_VERSION, FileCheckpointStore, LoadResult, MAX_ENVELOPE_BYTES, StateStoreError,
    StateToken, StoredState,
};
