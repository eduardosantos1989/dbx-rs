//! Encrypted, bounded, crash-recoverable event spool primitives.
//!
//! One exact final event envelope is stored in each independently authenticated frame. A segment
//! becomes deliverable only after its authenticated footer is synchronized and the file is
//! atomically renamed from `.open` to `.ready`. Quota is reserved before collection begins;
//! ready data is never deleted automatically.

#![forbid(unsafe_code)]

mod error;
mod format;
mod identity;
mod key;
mod model;
mod spool;

pub use error::SpoolError;
pub use identity::{BatchId, Fingerprint, InputKey, SegmentId};
pub use key::SpoolKey;
pub use model::{MIN_SEGMENT_BYTES, SegmentHeader, SegmentSummary, SpoolLimits, SpoolUsage};
pub use spool::{DeliveredSegment, ReadySegment, SegmentReader, SegmentWriter, Spool};
