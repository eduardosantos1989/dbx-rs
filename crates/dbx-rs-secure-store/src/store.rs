use std::path::{Path, PathBuf};

use dbx_rs_connector_sdk::ResolvedSecret;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use subtle::ConstantTimeEq;

use crate::error::SecureStoreError;
use crate::fs::{
    atomic_write, ensure_private_dir, read_private_limited, validate_private_dir, write_new,
};

const MASTER_KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const MAGIC: &[u8; 8] = b"DBXRSSEC";
const VERSION: u8 = 1;
const MAX_SECRET_BYTES: usize = 16 * 1024;
const MAX_SECRET_FILE_BYTES: u64 = (MAX_SECRET_BYTES + 64) as u64;

pub struct SecretStore {
    key: [u8; MASTER_KEY_BYTES],
    directory: PathBuf,
}

impl SecretStore {
    /// Opens a writable store, creating its directory and master key when absent.
    ///
    /// # Errors
    ///
    /// Returns an error when private storage cannot be created, protected, or read.
    pub fn open(master_key_file: &Path, directory: &Path) -> Result<Self, SecureStoreError> {
        ensure_private_dir(directory)?;
        let key = if master_key_file.exists() {
            load_master_key(master_key_file)?
        } else {
            create_master_key(master_key_file)?
        };
        Ok(Self {
            key,
            directory: directory.to_path_buf(),
        })
    }

    /// Opens an existing store without creating or modifying files or directories.
    ///
    /// # Errors
    ///
    /// Returns an error when the private directory or master key is missing, insecure, or invalid.
    pub fn open_existing(
        master_key_file: &Path,
        directory: &Path,
    ) -> Result<Self, SecureStoreError> {
        validate_private_dir(directory)?;
        let key = load_master_key(master_key_file)?;
        Ok(Self {
            key,
            directory: directory.to_path_buf(),
        })
    }

    /// Encrypts and atomically stores one named local secret.
    ///
    /// # Errors
    ///
    /// Returns an error when the name or value is invalid, encryption fails, or the protected file
    /// cannot be written.
    pub fn set(&self, name: &str, mut secret: Vec<u8>) -> Result<(), SecureStoreError> {
        validate_name(name)?;
        trim_line_endings(&mut secret);
        if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
            secret.fill(0);
            return Err(SecureStoreError::new(
                "DBX-RS-SECRET-0001",
                "configuration",
                "secret_input",
                "secret is empty or exceeds the size limit",
                false,
                true,
            ));
        }

        let mut nonce_bytes = [0_u8; NONCE_BYTES];
        SystemRandom::new().fill(&mut nonce_bytes).map_err(|_| {
            secret.fill(0);
            SecureStoreError::new(
                "DBX-RS-SECRET-0002",
                "internal",
                "secret_encrypt",
                "secure random generation failed",
                false,
                false,
            )
        })?;
        let key = encryption_key(&self.key)?;
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(aad(name)),
            &mut secret,
        )
        .map_err(|_| {
            secret.fill(0);
            SecureStoreError::new(
                "DBX-RS-SECRET-0003",
                "internal",
                "secret_encrypt",
                "secret encryption failed",
                false,
                false,
            )
        })?;

        let mut protected = Vec::with_capacity(MAGIC.len() + 1 + NONCE_BYTES + secret.len());
        protected.extend_from_slice(MAGIC);
        protected.push(VERSION);
        protected.extend_from_slice(&nonce_bytes);
        protected.append(&mut secret);
        let result = atomic_write(&self.secret_path(name), &protected, 0o600);
        protected.fill(0);
        result
    }

    /// Authenticates and decrypts one `local:<name>` secret reference.
    ///
    /// # Errors
    ///
    /// Returns an error when the reference or protected file is invalid, missing, oversized, or
    /// cannot be authenticated and decrypted.
    pub fn resolve(&self, reference: &str) -> Result<ResolvedSecret, SecureStoreError> {
        let name = reference.strip_prefix("local:").ok_or_else(|| {
            SecureStoreError::new(
                "DBX-RS-SECRET-0004",
                "configuration",
                "secret_resolve",
                "secret reference is not a local protected reference",
                false,
                true,
            )
        })?;
        validate_name(name)?;
        let mut protected = read_private_limited(&self.secret_path(name), MAX_SECRET_FILE_BYTES)?;
        let prefix_bytes = MAGIC.len() + 1 + NONCE_BYTES;
        if protected.len() <= prefix_bytes + aead::CHACHA20_POLY1305.tag_len()
            || &protected[..MAGIC.len()] != MAGIC
            || protected[MAGIC.len()] != VERSION
        {
            protected.fill(0);
            return Err(invalid_secret_file());
        }
        let mut nonce_bytes = [0_u8; NONCE_BYTES];
        nonce_bytes.copy_from_slice(&protected[MAGIC.len() + 1..prefix_bytes]);
        let mut encrypted = protected.split_off(prefix_bytes);
        protected.fill(0);
        let key = encryption_key(&self.key)?;
        let secret_len = if let Ok(plaintext) = key.open_in_place(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(aad(name)),
            &mut encrypted,
        ) {
            plaintext.len()
        } else {
            encrypted.fill(0);
            return Err(invalid_secret_file());
        };
        encrypted.truncate(secret_len);
        if encrypted.is_empty() || encrypted.len() > MAX_SECRET_BYTES {
            encrypted.fill(0);
            return Err(invalid_secret_file());
        }
        Ok(ResolvedSecret::new(encrypted))
    }

    pub(crate) fn secret_path(&self, name: &str) -> PathBuf {
        self.directory.join(format!("{name}.secret"))
    }

    pub(crate) const fn key(&self) -> &[u8; MASTER_KEY_BYTES] {
        &self.key
    }

    pub(crate) fn secret_matches(
        &self,
        name: &str,
        expected: &[u8],
    ) -> Result<bool, SecureStoreError> {
        let path = self.secret_path(name);
        if !path.exists() {
            return Ok(false);
        }
        let resolved = self.resolve(&format!("local:{name}"))?;
        Ok(resolved.expose_secret().len() == expected.len()
            && bool::from(resolved.expose_secret().ct_eq(expected)))
    }
}

impl Drop for SecretStore {
    fn drop(&mut self) {
        self.key.fill(0);
    }
}

fn create_master_key(path: &Path) -> Result<[u8; MASTER_KEY_BYTES], SecureStoreError> {
    let mut key = [0_u8; MASTER_KEY_BYTES];
    SystemRandom::new().fill(&mut key).map_err(|_| {
        SecureStoreError::new(
            "DBX-RS-SECRET-0005",
            "internal",
            "master_key_create",
            "secure random generation failed",
            false,
            false,
        )
    })?;
    match write_new(path, &key, 0o600) {
        Ok(()) => Ok(key),
        Err(_) if path.exists() => {
            key.fill(0);
            load_master_key(path)
        }
        Err(error) => {
            key.fill(0);
            Err(error)
        }
    }
}

fn load_master_key(path: &Path) -> Result<[u8; MASTER_KEY_BYTES], SecureStoreError> {
    let mut bytes = read_private_limited(path, MASTER_KEY_BYTES as u64)?;
    if bytes.len() != MASTER_KEY_BYTES {
        bytes.fill(0);
        return Err(SecureStoreError::new(
            "DBX-RS-SECRET-0006",
            "configuration",
            "master_key_load",
            "stored master key has an invalid size",
            false,
            true,
        ));
    }
    let mut key = [0_u8; MASTER_KEY_BYTES];
    key.copy_from_slice(&bytes);
    bytes.fill(0);
    Ok(key)
}

pub(crate) fn encryption_key(
    bytes: &[u8; MASTER_KEY_BYTES],
) -> Result<LessSafeKey, SecureStoreError> {
    UnboundKey::new(&aead::CHACHA20_POLY1305, bytes)
        .map(LessSafeKey::new)
        .map_err(|_| {
            SecureStoreError::new(
                "DBX-RS-SECRET-0007",
                "internal",
                "secret_crypto",
                "secret encryption key initialization failed",
                false,
                false,
            )
        })
}

fn aad(name: &str) -> Vec<u8> {
    let mut aad = b"dbx-rs-local-secret-v1\0".to_vec();
    aad.extend_from_slice(name.as_bytes());
    aad
}

pub(crate) fn validate_name(name: &str) -> Result<(), SecureStoreError> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(SecureStoreError::new(
            "DBX-RS-SECRET-0008",
            "configuration",
            "secret_name",
            "secret name is invalid",
            false,
            true,
        ));
    }
    Ok(())
}

pub(crate) fn trim_line_endings(bytes: &mut Vec<u8>) {
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
}

const fn invalid_secret_file() -> SecureStoreError {
    SecureStoreError::new(
        "DBX-RS-SECRET-0009",
        "configuration",
        "secret_decrypt",
        "protected secret file is invalid or cannot be authenticated",
        false,
        true,
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "dbx-rs-secrets-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn protected_secret_round_trips_without_plaintext_on_disk() {
        let root = test_dir();
        let store = SecretStore::open(&root.join("master.key"), &root.join("secrets"))
            .expect("store must open");
        store
            .set("warehouse", b"not-for-storage-in-cleartext\n".to_vec())
            .expect("secret must be stored");

        let on_disk = fs::read(root.join("secrets/warehouse.secret"))
            .expect("protected secret must be readable");
        assert!(
            !on_disk
                .windows(b"not-for-storage-in-cleartext".len())
                .any(|window| window == b"not-for-storage-in-cleartext")
        );
        let resolved = store
            .resolve("local:warehouse")
            .expect("secret must resolve");
        assert_eq!(resolved.expose_secret(), b"not-for-storage-in-cleartext");
        drop(resolved);
        drop(store);
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn existing_store_opens_and_resolves_without_rewriting_material() {
        let root = test_dir();
        let key_path = root.join("master.key");
        let secret_dir = root.join("secrets");
        let store = SecretStore::open(&key_path, &secret_dir).expect("store must open");
        store
            .set("warehouse", b"existing-secret".to_vec())
            .expect("secret must be stored");
        drop(store);
        let key_before = fs::read(&key_path).expect("key must be readable");
        let secret_before =
            fs::read(secret_dir.join("warehouse.secret")).expect("secret must be readable");

        let existing =
            SecretStore::open_existing(&key_path, &secret_dir).expect("existing store must open");
        let resolved = existing
            .resolve("local:warehouse")
            .expect("existing secret must resolve");

        assert_eq!(resolved.expose_secret(), b"existing-secret");
        assert_eq!(fs::read(&key_path).expect("key must remain"), key_before);
        assert_eq!(
            fs::read(secret_dir.join("warehouse.secret")).expect("secret must remain"),
            secret_before
        );
        drop(resolved);
        drop(existing);
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn existing_store_does_not_create_missing_material() {
        let root = test_dir();
        let error = SecretStore::open_existing(&root.join("master.key"), &root.join("secrets"))
            .err()
            .expect("missing store must fail closed");

        assert_eq!(error.code(), "DBX-RS-FS-0018");
        assert!(!root.exists());
    }

    #[test]
    fn secret_name_is_bound_into_authentication() {
        let root = test_dir();
        let store = SecretStore::open(&root.join("master.key"), &root.join("secrets"))
            .expect("store must open");
        store
            .set("source", b"secret-value".to_vec())
            .expect("secret must be stored");
        fs::copy(
            root.join("secrets/source.secret"),
            root.join("secrets/other.secret"),
        )
        .expect("ciphertext must be copied");

        let error = store
            .resolve("local:other")
            .expect_err("renamed ciphertext must not decrypt");
        assert_eq!(error.code(), "DBX-RS-SECRET-0009");
        drop(store);
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[cfg(unix)]
    #[test]
    fn master_key_and_secret_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let root = test_dir();
        let store = SecretStore::open(&root.join("master.key"), &root.join("secrets"))
            .expect("store must open");
        store
            .set("source", b"secret-value".to_vec())
            .expect("secret must be stored");

        let key_mode = fs::metadata(root.join("master.key"))
            .expect("key metadata must exist")
            .permissions()
            .mode()
            & 0o777;
        let secret_mode = fs::metadata(root.join("secrets/source.secret"))
            .expect("secret metadata must exist")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(key_mode, 0o600);
        assert_eq!(secret_mode, 0o600);
        drop(store);
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[cfg(unix)]
    #[test]
    fn nested_symlink_ancestors_are_rejected() {
        use std::os::unix::fs::symlink;

        let root = test_dir();
        let redirected = root.with_extension("redirected");
        fs::create_dir_all(&root).expect("fixture root must be created");
        fs::create_dir_all(&redirected).expect("redirect target must be created");
        symlink(&redirected, root.join("nested")).expect("nested symlink must be created");

        let error = SecretStore::open(
            &root.join("nested/master.key"),
            &root.join("nested/secrets"),
        )
        .err()
        .expect("nested symlink must fail closed");

        assert_eq!(error.code(), "DBX-RS-FS-0014");
        assert!(!redirected.join("master.key").exists());
        assert!(!redirected.join("secrets").exists());
        fs::remove_dir_all(root).expect("fixture must be removed");
        fs::remove_dir_all(redirected).expect("redirect target must be removed");
    }
}
