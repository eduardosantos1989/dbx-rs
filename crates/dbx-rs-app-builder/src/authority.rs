use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use dbx_rs_secure_store::{AuthoritySigner, DeploymentAuthority, read_limited, write_new};
use rcgen::{CertificateParams, DnType, KeyPair, KeyUsagePurpose, PKCS_ED25519};
use serde::{Deserialize, Serialize};

use crate::{BuilderError, BuilderResult};

pub(crate) const PRIVATE_KEY_FILE: &str = "deployment-authority-key.pk8";
pub(crate) const CERTIFICATE_DER_FILE: &str = "deployment-authority.der";
pub(crate) const CERTIFICATE_PEM_FILE: &str = "deployment-authority.pem";
pub(crate) const PUBLIC_KEY_FILE: &str = "deployment-authority.pub";
const METADATA_FILE: &str = "authority.json";
const MAX_CERTIFICATE_BYTES: u64 = 16 * 1024;
const MAX_PUBLIC_KEY_BYTES: u64 = 32;
const MAX_METADATA_BYTES: u64 = 4 * 1024;

static NEXT_STAGING_DIRECTORY: AtomicU64 = AtomicU64::new(0);

pub(crate) struct AuthorityMaterial {
    pub(crate) directory: PathBuf,
    pub(crate) private_key_file: PathBuf,
    pub(crate) certificate_der_file: PathBuf,
    pub(crate) public_key_file: PathBuf,
    pub(crate) authority: DeploymentAuthority,
}

#[derive(Deserialize, Serialize)]
struct AuthorityMetadata {
    schema_version: u8,
    algorithm: String,
    certificate_sha256: String,
    certificate_der_file: String,
    certificate_pem_file: String,
    private_key_file: String,
    public_key_file: String,
}

pub(crate) fn initialize(directory: &Path, common_name: &str) -> BuilderResult<AuthorityMaterial> {
    validate_common_name(common_name)?;
    let directory = absolute_path(directory)?;
    if directory.exists() {
        return Err(BuilderError::new(
            "authority output directory already exists",
        ));
    }
    let parent = directory
        .parent()
        .ok_or_else(|| BuilderError::new("authority output directory has no parent"))?;
    fs::create_dir_all(parent)
        .map_err(|_| BuilderError::new("failed to create authority output parent"))?;
    reject_symlink_ancestors(parent)?;

    let sequence = NEXT_STAGING_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let staging = parent.join(format!(
        ".dbx-rs-authority.{}.{sequence}.tmp",
        std::process::id()
    ));
    if staging.exists() {
        return Err(BuilderError::new(
            "authority staging directory already exists",
        ));
    }

    let result = initialize_staged(&staging, common_name).and_then(|()| {
        fs::rename(&staging, &directory)
            .map_err(|_| BuilderError::new("failed to publish authority directory"))
    });
    if result.is_err() {
        let _ignored = fs::remove_dir_all(&staging);
    }
    result?;
    load(&directory)
}

pub(crate) fn load(directory: &Path) -> BuilderResult<AuthorityMaterial> {
    let directory = directory
        .canonicalize()
        .map_err(|_| BuilderError::new("authority directory is unavailable"))?;
    let metadata = fs::symlink_metadata(&directory)
        .map_err(|_| BuilderError::new("failed to inspect authority directory"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BuilderError::new("authority directory is invalid"));
    }

    let private_key_file = directory.join(PRIVATE_KEY_FILE);
    let certificate_der_file = directory.join(CERTIFICATE_DER_FILE);
    let public_key_file = directory.join(PUBLIC_KEY_FILE);
    let certificate = read_limited(&certificate_der_file, MAX_CERTIFICATE_BYTES)
        .map_err(|error| BuilderError::new(error.to_string()))?;
    let public_key = read_limited(&public_key_file, MAX_PUBLIC_KEY_BYTES)
        .map_err(|error| BuilderError::new(error.to_string()))?;
    let authority = DeploymentAuthority::from_parts(&certificate, &public_key)
        .map_err(|error| BuilderError::new(error.to_string()))?;
    AuthoritySigner::load(&private_key_file, &authority)
        .map_err(|error| BuilderError::new(error.to_string()))?;
    validate_metadata(&directory, &authority)?;

    Ok(AuthorityMaterial {
        directory,
        private_key_file,
        certificate_der_file,
        public_key_file,
        authority,
    })
}

fn initialize_staged(staging: &Path, common_name: &str) -> BuilderResult<()> {
    let key_pair = KeyPair::generate_for(&PKCS_ED25519)
        .map_err(|_| BuilderError::new("failed to generate deployment authority key"))?;
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    let certificate = params
        .self_signed(&key_pair)
        .map_err(|_| BuilderError::new("failed to generate deployment authority certificate"))?;
    let certificate_der = certificate.der().as_ref();
    let public_key = key_pair.public_key_raw();
    let authority = DeploymentAuthority::from_parts(certificate_der, public_key)
        .map_err(|error| BuilderError::new(error.to_string()))?;
    AuthoritySigner::from_pkcs8(key_pair.serialized_der(), &authority)
        .map_err(|error| BuilderError::new(error.to_string()))?;

    let mut private_key = key_pair.serialize_der();
    let writes = (|| {
        write_new(&staging.join(PRIVATE_KEY_FILE), &private_key, 0o600)
            .map_err(|error| BuilderError::new(error.to_string()))?;
        write_new(&staging.join(CERTIFICATE_DER_FILE), certificate_der, 0o600)
            .map_err(|error| BuilderError::new(error.to_string()))?;
        write_new(
            &staging.join(CERTIFICATE_PEM_FILE),
            certificate.pem().as_bytes(),
            0o600,
        )
        .map_err(|error| BuilderError::new(error.to_string()))?;
        write_new(&staging.join(PUBLIC_KEY_FILE), public_key, 0o600)
            .map_err(|error| BuilderError::new(error.to_string()))?;
        let metadata = AuthorityMetadata {
            schema_version: 1,
            algorithm: "Ed25519".into(),
            certificate_sha256: authority.fingerprint_hex(),
            certificate_der_file: CERTIFICATE_DER_FILE.into(),
            certificate_pem_file: CERTIFICATE_PEM_FILE.into(),
            private_key_file: PRIVATE_KEY_FILE.into(),
            public_key_file: PUBLIC_KEY_FILE.into(),
        };
        let encoded = serde_json::to_vec_pretty(&metadata)
            .map_err(|_| BuilderError::new("failed to encode authority metadata"))?;
        write_new(&staging.join(METADATA_FILE), &encoded, 0o600)
            .map_err(|error| BuilderError::new(error.to_string()))
    })();
    private_key.fill(0);
    writes
}

fn validate_metadata(directory: &Path, authority: &DeploymentAuthority) -> BuilderResult<()> {
    let encoded = read_limited(&directory.join(METADATA_FILE), MAX_METADATA_BYTES)
        .map_err(|error| BuilderError::new(error.to_string()))?;
    let metadata = serde_json::from_slice::<AuthorityMetadata>(&encoded)
        .map_err(|_| BuilderError::new("authority metadata is invalid"))?;
    if metadata.schema_version != 1
        || metadata.algorithm != "Ed25519"
        || metadata.certificate_sha256 != authority.fingerprint_hex()
        || metadata.certificate_der_file != CERTIFICATE_DER_FILE
        || metadata.certificate_pem_file != CERTIFICATE_PEM_FILE
        || metadata.private_key_file != PRIVATE_KEY_FILE
        || metadata.public_key_file != PUBLIC_KEY_FILE
        || !directory.join(CERTIFICATE_PEM_FILE).is_file()
    {
        return Err(BuilderError::new(
            "authority metadata does not match its files",
        ));
    }
    Ok(())
}

fn validate_common_name(common_name: &str) -> BuilderResult<()> {
    if common_name.is_empty()
        || common_name.len() > 128
        || common_name.chars().any(char::is_control)
    {
        return Err(BuilderError::new("authority common name is invalid"));
    }
    Ok(())
}

fn absolute_path(path: &Path) -> BuilderResult<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|current| current.join(path))
            .map_err(|_| BuilderError::new("failed to resolve current directory"))
    }
}

fn reject_symlink_ancestors(path: &Path) -> BuilderResult<()> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(BuilderError::new("authority path contains a symbolic link"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(BuilderError::new("failed to inspect authority path")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_name_is_bounded_and_single_line() {
        assert!(validate_common_name("dbx-rs deployment").is_ok());
        assert!(validate_common_name("").is_err());
        assert!(validate_common_name("invalid\nname").is_err());
        assert!(validate_common_name(&"x".repeat(129)).is_err());
    }
}
