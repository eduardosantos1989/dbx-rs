use std::path::Path;

use dbx_rs_secure_store::{read_limited, write_new};
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};

use crate::error::SpoolError;
use crate::spool::reject_existing_ancestor_symlinks;

pub(crate) const KEY_BYTES: usize = 32;
pub(crate) const KEY_ID_BYTES: usize = 16;

pub struct SpoolKey {
    pub(crate) bytes: [u8; KEY_BYTES],
    pub(crate) id: [u8; KEY_ID_BYTES],
}

impl SpoolKey {
    /// Loads an existing spool master key or creates a new owner-only key.
    ///
    /// # Errors
    ///
    /// Returns an error if secure randomness, protected file creation, permissions, or key loading
    /// fails. Existing malformed or broadly permissioned keys fail closed.
    pub fn load_or_create(path: &Path) -> Result<Self, SpoolError> {
        reject_existing_ancestor_symlinks(path)?;
        let bytes = if path.exists() {
            load_key(path)?
        } else {
            create_key(path)?
        };
        let key_digest = digest(&SHA256, &bytes);
        let mut id = [0_u8; KEY_ID_BYTES];
        id.copy_from_slice(&key_digest.as_ref()[..KEY_ID_BYTES]);
        Ok(Self { bytes, id })
    }
}

impl std::fmt::Debug for SpoolKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SpoolKey([REDACTED])")
    }
}

impl Drop for SpoolKey {
    fn drop(&mut self) {
        self.bytes.fill(0);
        self.id.fill(0);
    }
}

fn create_key(path: &Path) -> Result<[u8; KEY_BYTES], SpoolError> {
    let mut key = [0_u8; KEY_BYTES];
    SystemRandom::new().fill(&mut key).map_err(|_| {
        SpoolError::new(
            "DBX-RS-SPOOL-KEY-0001",
            "key_create",
            "secure spool key generation failed",
        )
    })?;
    match write_new(path, &key, 0o600) {
        Ok(()) => Ok(key),
        Err(_) if path.exists() => {
            key.fill(0);
            load_key(path)
        }
        Err(error) => {
            key.fill(0);
            Err(error.into())
        }
    }
}

fn load_key(path: &Path) -> Result<[u8; KEY_BYTES], SpoolError> {
    validate_key_permissions(path)?;
    let mut stored = read_limited(path, KEY_BYTES as u64)?;
    if stored.len() != KEY_BYTES {
        stored.fill(0);
        return Err(SpoolError::new(
            "DBX-RS-SPOOL-KEY-0002",
            "key_load",
            "stored spool key has an invalid size",
        ));
    }
    let mut key = [0_u8; KEY_BYTES];
    key.copy_from_slice(&stored);
    stored.fill(0);
    Ok(key)
}

#[cfg(unix)]
fn validate_key_permissions(path: &Path) -> Result<(), SpoolError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        SpoolError::io(
            "DBX-RS-SPOOL-KEY-0003",
            "key_permissions",
            "failed to inspect the spool key",
            &error,
        )
    })?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(SpoolError::new(
            "DBX-RS-SPOOL-KEY-0004",
            "key_permissions",
            "spool key permissions are too broad",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_key_permissions(_path: &Path) -> Result<(), SpoolError> {
    Ok(())
}
