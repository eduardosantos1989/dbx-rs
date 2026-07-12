#![forbid(unsafe_code)]

mod error;
mod fs;
mod store;

pub use error::SecureStoreError;
pub use fs::{atomic_write, ensure_private_dir, read_limited, write_new};
pub use store::SecretStore;
