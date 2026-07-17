use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use hpke::aead::ChaCha20Poly1305 as HpkeChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{
    Deserializable, Kem as HpkeKem, OpModeR, OpModeS, Serializable, setup_receiver, setup_sender,
};
use ring::aead::{self, Aad, Nonce};
use ring::digest::{Context, SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use x509_cert::Certificate;
use x509_cert::der::asn1::ObjectIdentifier;
use x509_cert::der::{Decode, Encode};

use crate::error::SecureStoreError;
use crate::fs::{atomic_write, ensure_private_dir, read_limited, read_private_limited, write_new};
use crate::store::{SecretStore, encryption_key, trim_line_endings, validate_name};

const EMBEDDED_CERTIFICATE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/deployment-authority.der"));
const EMBEDDED_PUBLIC_KEY: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/deployment-authority.pub"));

const PUBLIC_KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const NONCE_BYTES: usize = 12;
const DIGEST_BYTES: usize = 32;
const MAX_CERTIFICATE_BYTES: usize = 16 * 1024;
const MAX_PRIVATE_KEY_BYTES: u64 = 4 * 1024;
const MAX_RECIPIENTS: usize = 256;
const MAX_SECRET_BYTES: usize = 16 * 1024;
const MAX_SECRET_NAME_BYTES: usize = 128;
const MAX_ENVELOPE_BYTES: u64 = 128 * 1024;
const MAX_DEPLOYMENT_FILES: usize = 1_024;

type DeploymentKem = X25519HkdfSha256;
type DeploymentPublicKey = <DeploymentKem as HpkeKem>::PublicKey;
type DeploymentPrivateKey = <DeploymentKem as HpkeKem>::PrivateKey;
type DeploymentEncappedKey = <DeploymentKem as HpkeKem>::EncappedKey;

const IDENTITY_MAGIC: &[u8; 8] = b"DBXRSIDN";
const IDENTITY_VERSION: u8 = 1;
const IDENTITY_KEY_BYTES: usize = 32;
const IDENTITY_FILE_BYTES: usize = IDENTITY_MAGIC.len() + 1 + IDENTITY_KEY_BYTES;
const RECIPIENT_PREFIX: &str = "dbxrs-hpke-x25519-v1:";
const RECIPIENT_HEX_BYTES: usize = PUBLIC_KEY_BYTES * 2;
const RECIPIENT_STRING_BYTES: usize = RECIPIENT_PREFIX.len() + RECIPIENT_HEX_BYTES;

const ENVELOPE_MAGIC: &[u8; 8] = b"DBXRSDPL";
const ENVELOPE_VERSION: u8 = 1;
const CONTENT_KEY_BYTES: usize = 32;
const CONTENT_TAG_BYTES: usize = 16;
const RECIPIENT_ID_BYTES: usize = 32;
const HPKE_ENCAPPED_KEY_BYTES: usize = 32;
const HPKE_WRAPPED_KEY_BYTES: usize = CONTENT_KEY_BYTES + CONTENT_TAG_BYTES;
const RECIPIENT_ENTRY_BYTES: usize =
    RECIPIENT_ID_BYTES + HPKE_ENCAPPED_KEY_BYTES + HPKE_WRAPPED_KEY_BYTES;
const ENVELOPE_HEADER_BYTES: usize = ENVELOPE_MAGIC.len() + 1 + 2 + NONCE_BYTES + 4;
const SIGNATURE_DOMAIN: &[u8] = b"dbx-rs/deployment-envelope/v1\0";
const HPKE_INFO: &[u8] = b"dbx-rs/deployment-hpke-wrap/v1\0";
const HPKE_AAD_DOMAIN: &[u8] = b"dbx-rs/deployment-hpke-recipient/v1\0";
const CONTENT_AAD_DOMAIN: &[u8] = b"dbx-rs/deployment-content/v1\0";

const PAYLOAD_MAGIC: &[u8; 8] = b"DBXRSPAY";
const PAYLOAD_VERSION: u8 = 1;
const PAYLOAD_HEADER_BYTES: usize = PAYLOAD_MAGIC.len() + 1 + 8 + 2 + 4;
const MAX_PAYLOAD_BYTES: usize = PAYLOAD_HEADER_BYTES + MAX_SECRET_NAME_BYTES + MAX_SECRET_BYTES;

const RECEIPT_MAGIC: &[u8; 8] = b"DBXRSRCP";
const RECEIPT_VERSION: u8 = 1;
const RECEIPT_PLAINTEXT_BYTES: usize = 8 + DIGEST_BYTES;
const RECEIPT_FILE_BYTES: usize =
    RECEIPT_MAGIC.len() + 1 + NONCE_BYTES + RECEIPT_PLAINTEXT_BYTES + 16;
const RECEIPT_AAD_DOMAIN: &[u8] = b"dbx-rs/deployment-receipt/v1\0";
const WRITER_LOCK_FILE: &str = ".writer.lock";

/// Public deployment authority embedded in a release binary.
#[derive(Clone)]
pub struct DeploymentAuthority {
    certificate_der: Vec<u8>,
    public_key: [u8; PUBLIC_KEY_BYTES],
    fingerprint: [u8; DIGEST_BYTES],
}

impl DeploymentAuthority {
    /// Creates a verifier from one DER certificate and its matching raw Ed25519 public key.
    ///
    /// The app builder is responsible for generating both values from one key pair. Runtime
    /// signature verification uses the raw key; the certificate is retained as the release's
    /// public identity and fingerprint input.
    ///
    /// # Errors
    ///
    /// Returns an error when either public value has an invalid size or representation.
    pub fn from_parts(certificate_der: &[u8], public_key: &[u8]) -> Result<Self, SecureStoreError> {
        if certificate_der.is_empty()
            || certificate_der.len() > MAX_CERTIFICATE_BYTES
            || public_key.len() != PUBLIC_KEY_BYTES
            || public_key.iter().all(|byte| *byte == 0)
        {
            return Err(authority_invalid());
        }
        validate_authority_certificate(certificate_der, public_key)?;
        let mut key = [0_u8; PUBLIC_KEY_BYTES];
        key.copy_from_slice(public_key);
        let mut fingerprint = [0_u8; DIGEST_BYTES];
        fingerprint.copy_from_slice(digest(&SHA256, certificate_der).as_ref());
        Ok(Self {
            certificate_der: certificate_der.to_vec(),
            public_key: key,
            fingerprint,
        })
    }

    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    #[must_use]
    pub const fn public_key(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.public_key
    }

    #[must_use]
    pub fn fingerprint_hex(&self) -> String {
        lowercase_hex(&self.fingerprint)
    }
}

fn validate_authority_certificate(
    certificate_der: &[u8],
    public_key: &[u8],
) -> Result<(), SecureStoreError> {
    const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

    let certificate = Certificate::from_der(certificate_der).map_err(|_| authority_invalid())?;
    let subject_public_key = certificate
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(authority_invalid)?;
    let signature = certificate
        .signature
        .as_bytes()
        .ok_or_else(authority_invalid)?;
    if certificate.tbs_certificate.issuer != certificate.tbs_certificate.subject
        || certificate.signature_algorithm.oid != ED25519_OID
        || certificate.signature_algorithm.parameters.is_some()
        || certificate.tbs_certificate.signature.oid != ED25519_OID
        || certificate.tbs_certificate.signature.parameters.is_some()
        || certificate
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .oid
            != ED25519_OID
        || certificate
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .parameters
            .is_some()
        || subject_public_key != public_key
    {
        return Err(authority_invalid());
    }
    let signed = certificate
        .tbs_certificate
        .to_der()
        .map_err(|_| authority_invalid())?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&signed, signature)
        .map_err(|_| authority_invalid())
}

impl std::fmt::Debug for DeploymentAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeploymentAuthority")
            .field("certificate", &"[PUBLIC EMBEDDED]")
            .field("fingerprint", &self.fingerprint_hex())
            .finish()
    }
}

/// Returns whether this binary was built with a deployment authority.
#[must_use]
pub const fn deployment_authority_configured() -> bool {
    !EMBEDDED_CERTIFICATE.is_empty() && !EMBEDDED_PUBLIC_KEY.is_empty()
}

/// Loads the public deployment authority embedded by the app builder.
///
/// # Errors
///
/// Returns an error when this is an ordinary development build without an embedded authority or
/// when the embedded public material is invalid.
pub fn embedded_deployment_authority() -> Result<DeploymentAuthority, SecureStoreError> {
    if !deployment_authority_configured() {
        return Err(SecureStoreError::new(
            "DBX-RS-DEPLOY-0001",
            "configuration",
            "deployment_authority",
            "this binary has no embedded deployment authority",
            false,
            true,
        ));
    }
    DeploymentAuthority::from_parts(EMBEDDED_CERTIFICATE, EMBEDDED_PUBLIC_KEY)
}

/// Ed25519 deployment authority signer loaded from an external private key.
pub struct AuthoritySigner(Ed25519KeyPair);

impl AuthoritySigner {
    /// Loads an owner-protected PKCS#8 key and proves that it matches the selected authority.
    ///
    /// # Errors
    ///
    /// Returns an error when the key cannot be read, parsed, or matched to the embedded public key.
    pub fn load(
        private_key_file: &Path,
        authority: &DeploymentAuthority,
    ) -> Result<Self, SecureStoreError> {
        let mut bytes = read_private_limited(private_key_file, MAX_PRIVATE_KEY_BYTES)?;
        let signer = Self::from_pkcs8(&bytes, authority);
        bytes.fill(0);
        signer
    }

    /// Creates a signer from PKCS#8 bytes and proves that it matches the selected authority.
    ///
    /// # Errors
    ///
    /// Returns an error when the key is invalid or does not match the authority.
    pub fn from_pkcs8(
        private_key: &[u8],
        authority: &DeploymentAuthority,
    ) -> Result<Self, SecureStoreError> {
        let key_pair = Ed25519KeyPair::from_pkcs8(private_key).map_err(|_| signer_invalid())?;
        if key_pair.public_key().as_ref() != authority.public_key() {
            return Err(signer_invalid());
        }
        Ok(Self(key_pair))
    }

    fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_BYTES] {
        let signature = self.0.sign(message);
        let mut bytes = [0_u8; SIGNATURE_BYTES];
        bytes.copy_from_slice(signature.as_ref());
        bytes
    }
}

/// Installation-specific HPKE identity used to unwrap Deployment Server credentials.
pub struct DeploymentIdentity(DeploymentPrivateKey);

impl DeploymentIdentity {
    /// Generates a new installation identity.
    #[must_use]
    pub fn generate() -> Self {
        let (private_key, _) = DeploymentKem::gen_keypair();
        Self(private_key)
    }

    /// Loads an existing owner-protected identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the file is missing, insecure, malformed, or oversized.
    pub fn load(path: &Path) -> Result<Self, SecureStoreError> {
        let mut bytes = read_private_limited(path, IDENTITY_FILE_BYTES as u64)?;
        if bytes.len() != IDENTITY_FILE_BYTES
            || &bytes[..IDENTITY_MAGIC.len()] != IDENTITY_MAGIC
            || bytes[IDENTITY_MAGIC.len()] != IDENTITY_VERSION
        {
            bytes.fill(0);
            return Err(identity_invalid());
        }
        let identity = DeploymentPrivateKey::from_bytes(&bytes[IDENTITY_MAGIC.len() + 1..])
            .map(Self)
            .map_err(|_| identity_invalid());
        bytes.fill(0);
        identity
    }

    /// Loads or atomically creates one installation identity.
    ///
    /// # Errors
    ///
    /// Returns an error when protected storage cannot be created or an existing identity is
    /// invalid.
    pub fn load_or_create(path: &Path) -> Result<Self, SecureStoreError> {
        if path.exists() {
            return Self::load(path);
        }
        let identity = Self::generate();
        let mut private_key = identity.0.to_bytes();
        let mut bytes = Vec::with_capacity(IDENTITY_FILE_BYTES);
        bytes.extend_from_slice(IDENTITY_MAGIC);
        bytes.push(IDENTITY_VERSION);
        bytes.extend_from_slice(private_key.as_slice());
        private_key.fill(0);
        let result = write_new(path, &bytes, 0o600);
        bytes.fill(0);
        match result {
            Ok(()) => Ok(identity),
            Err(error) if error.io_kind() == Some(std::io::ErrorKind::AlreadyExists) => {
                Self::load(path)
            }
            Err(error) => Err(error),
        }
    }

    /// Returns the public recipient string that may be enrolled on Deployment Server.
    #[must_use]
    pub fn recipient(&self) -> String {
        let public_key = DeploymentKem::sk_to_pk(&self.0);
        let public_key_bytes = deployment_public_key_bytes(&public_key);
        format!("{RECIPIENT_PREFIX}{}", lowercase_hex(&public_key_bytes))
    }
}

impl std::fmt::Debug for DeploymentIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DeploymentIdentity([REDACTED])")
    }
}

/// Policy for the first signed import when a same-name local secret already exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeploymentImportPolicy {
    RequireAbsentOrMatching,
    ReplaceExisting,
}

/// Result of reconciling one signed credential envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeploymentImportResult {
    Imported {
        name: String,
        revision: u64,
    },
    AlreadyCurrent {
        name: String,
        revision: u64,
    },
    Repaired {
        name: String,
        revision: u64,
    },
    Stale {
        name: String,
        envelope_revision: u64,
        current_revision: u64,
    },
}

/// Aggregate result of a daemon deployment-directory reconciliation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeploymentReconcileSummary {
    pub files: usize,
    pub imported: usize,
    pub already_current: usize,
    pub repaired: usize,
    pub stale: usize,
}

/// Encrypts and signs one credential for one or more enrolled client recipients.
///
/// The secret is accepted only through the caller's byte buffer; command-line integration reads it
/// from standard input. Line endings are removed consistently with local secret entry.
///
/// # Errors
///
/// Returns an error for invalid names, revisions, secret sizes, recipients, encryption, or signing
/// state.
pub fn seal_deployment_secret(
    name: &str,
    revision: u64,
    mut secret: Vec<u8>,
    recipient_strings: &[String],
    signer: &AuthoritySigner,
) -> Result<Vec<u8>, SecureStoreError> {
    validate_name(name)?;
    trim_line_endings(&mut secret);
    if revision == 0 || secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
        secret.fill(0);
        return Err(deployment_input_invalid());
    }
    let recipients = parse_recipients(recipient_strings)?;

    let name_len = u16::try_from(name.len()).map_err(|_| deployment_input_invalid())?;
    let secret_len = u32::try_from(secret.len()).map_err(|_| deployment_input_invalid())?;
    let mut payload = Vec::with_capacity(PAYLOAD_HEADER_BYTES + name.len() + secret.len());
    payload.extend_from_slice(PAYLOAD_MAGIC);
    payload.push(PAYLOAD_VERSION);
    payload.extend_from_slice(&revision.to_be_bytes());
    payload.extend_from_slice(&name_len.to_be_bytes());
    payload.extend_from_slice(&secret_len.to_be_bytes());
    payload.extend_from_slice(name.as_bytes());
    payload.extend_from_slice(&secret);
    secret.fill(0);

    let encrypted = encrypt_payload(&payload, &recipients);
    payload.fill(0);
    let mut envelope = encrypted?;
    let final_len = envelope
        .len()
        .checked_add(SIGNATURE_BYTES)
        .ok_or_else(envelope_invalid)?;
    if final_len as u64 > MAX_ENVELOPE_BYTES {
        return Err(envelope_invalid());
    }

    let signature = signer.sign(&signature_message(&envelope));
    envelope.extend_from_slice(&signature);
    Ok(envelope)
}

/// Verifies the structure and deployment-authority signature of an encrypted envelope.
///
/// This check intentionally does not decrypt the payload and therefore needs no client identity.
/// It is used by the app builder to reject malformed or unauthorized `.dbxsecret` files before
/// packaging them.
///
/// # Errors
///
/// Returns an error when the envelope is malformed, has duplicate recipient entries, or was not
/// signed by the selected deployment authority.
pub fn verify_deployment_envelope(
    envelope: &[u8],
    authority: &DeploymentAuthority,
) -> Result<(), SecureStoreError> {
    verify_deployment_envelope_layout(envelope, authority).map(|_layout| ())
}

impl SecretStore {
    /// Imports one signed deployment envelope into this installation's local secret store.
    ///
    /// # Errors
    ///
    /// Returns an error when authorization, decryption, local state, or receipt persistence fails.
    pub fn import_deployment_envelope(
        &self,
        envelope: &[u8],
        identity: &DeploymentIdentity,
        receipt_dir: &Path,
        authority: &DeploymentAuthority,
        policy: DeploymentImportPolicy,
    ) -> Result<DeploymentImportResult, SecureStoreError> {
        let deployed = open_deployment_envelope(envelope, identity, authority)?;
        let _lock = ImportFileLock::acquire(receipt_dir)?;
        import_deployed_secret(self, receipt_dir, &deployed, policy)
    }
}

/// Reconciles all signed credential envelopes in one fixed app directory.
///
/// Every envelope is authenticated and decrypted before any local secret changes. For each secret
/// name, only the greatest revision is imported; conflicting envelopes at the same revision fail
/// closed.
///
/// # Errors
///
/// Returns an error for an invalid directory entry, excessive file count, missing identity,
/// unauthorized envelope, revision conflict, or protected-storage failure.
pub fn reconcile_deployment_directory(
    store: &SecretStore,
    envelope_dir: &Path,
    identity_file: &Path,
    receipt_dir: &Path,
    authority: &DeploymentAuthority,
) -> Result<DeploymentReconcileSummary, SecureStoreError> {
    let envelope_files = deployment_envelope_files(envelope_dir)?;
    if envelope_files.is_empty() {
        return Ok(DeploymentReconcileSummary::default());
    }
    reconcile_deployment_files(
        store,
        &envelope_files,
        identity_file,
        receipt_dir,
        authority,
    )
}

/// Reconciles signed credentials using this binary's embedded public authority.
///
/// An absent or empty envelope directory is a no-op, including for development builds that do not
/// contain a deployment authority.
///
/// # Errors
///
/// Returns an error when deployed files are invalid, this binary lacks the required authority, or
/// an authenticated credential cannot be safely imported.
pub fn reconcile_embedded_deployment_directory(
    store: &SecretStore,
    envelope_dir: &Path,
    identity_file: &Path,
    receipt_dir: &Path,
) -> Result<DeploymentReconcileSummary, SecureStoreError> {
    let envelope_files = deployment_envelope_files(envelope_dir)?;
    if envelope_files.is_empty() {
        return Ok(DeploymentReconcileSummary::default());
    }
    let authority = embedded_deployment_authority()?;
    reconcile_deployment_files(
        store,
        &envelope_files,
        identity_file,
        receipt_dir,
        &authority,
    )
}

fn reconcile_deployment_files(
    store: &SecretStore,
    envelope_files: &[PathBuf],
    identity_file: &Path,
    receipt_dir: &Path,
    authority: &DeploymentAuthority,
) -> Result<DeploymentReconcileSummary, SecureStoreError> {
    let identity = DeploymentIdentity::load(identity_file)?;
    let mut selected = BTreeMap::<String, DeployedSecret>::new();
    let mut stale = 0_usize;
    for path in envelope_files {
        let bytes = read_limited(path, MAX_ENVELOPE_BYTES)?;
        let deployed = open_deployment_envelope(&bytes, &identity, authority)?;
        match selected.entry(deployed.name.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(deployed);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let current = entry.get();
                match current.revision.cmp(&deployed.revision) {
                    std::cmp::Ordering::Equal => {
                        if current.envelope_digest != deployed.envelope_digest {
                            return Err(revision_conflict());
                        }
                        stale = stale.saturating_add(1);
                    }
                    std::cmp::Ordering::Less => {
                        entry.insert(deployed);
                        stale = stale.saturating_add(1);
                    }
                    std::cmp::Ordering::Greater => {
                        stale = stale.saturating_add(1);
                    }
                }
            }
        }
    }

    let _lock = ImportFileLock::acquire(receipt_dir)?;
    let mut summary = DeploymentReconcileSummary {
        files: envelope_files.len(),
        stale,
        ..DeploymentReconcileSummary::default()
    };
    for deployed in selected.into_values() {
        match import_deployed_secret(
            store,
            receipt_dir,
            &deployed,
            DeploymentImportPolicy::RequireAbsentOrMatching,
        )? {
            DeploymentImportResult::Imported { .. } => summary.imported += 1,
            DeploymentImportResult::AlreadyCurrent { .. } => summary.already_current += 1,
            DeploymentImportResult::Repaired { .. } => summary.repaired += 1,
            DeploymentImportResult::Stale { .. } => summary.stale += 1,
        }
    }
    Ok(summary)
}

fn parse_recipients(
    recipient_strings: &[String],
) -> Result<Vec<DeploymentPublicKey>, SecureStoreError> {
    if recipient_strings.is_empty() || recipient_strings.len() > MAX_RECIPIENTS {
        return Err(recipient_invalid());
    }
    let mut canonical = BTreeSet::<[u8; PUBLIC_KEY_BYTES]>::new();
    let mut recipients = Vec::with_capacity(recipient_strings.len());
    for value in recipient_strings {
        if value.len() != RECIPIENT_STRING_BYTES || value.trim() != value {
            return Err(recipient_invalid());
        }
        let encoded = value
            .strip_prefix(RECIPIENT_PREFIX)
            .ok_or_else(recipient_invalid)?;
        let public_key_bytes = decode_lowercase_hex_32(encoded).ok_or_else(recipient_invalid)?;
        if public_key_bytes.iter().all(|byte| *byte == 0) || !canonical.insert(public_key_bytes) {
            return Err(recipient_invalid());
        }
        let public_key =
            DeploymentPublicKey::from_bytes(&public_key_bytes).map_err(|_| recipient_invalid())?;
        recipients.push(public_key);
    }
    Ok(recipients)
}

fn encrypt_payload(
    payload: &[u8],
    recipients: &[DeploymentPublicKey],
) -> Result<Vec<u8>, SecureStoreError> {
    let recipient_count = u16::try_from(recipients.len()).map_err(|_| recipient_invalid())?;
    let content_ciphertext_len = payload
        .len()
        .checked_add(CONTENT_TAG_BYTES)
        .ok_or_else(deployment_encrypt_error)?;
    let content_ciphertext_len_u32 =
        u32::try_from(content_ciphertext_len).map_err(|_| deployment_encrypt_error())?;
    let table_len = recipients
        .len()
        .checked_mul(RECIPIENT_ENTRY_BYTES)
        .ok_or_else(deployment_encrypt_error)?;
    let unsigned_len = ENVELOPE_HEADER_BYTES
        .checked_add(table_len)
        .and_then(|length| length.checked_add(content_ciphertext_len))
        .ok_or_else(deployment_encrypt_error)?;
    if unsigned_len
        .checked_add(SIGNATURE_BYTES)
        .is_none_or(|length| length as u64 > MAX_ENVELOPE_BYTES)
    {
        return Err(envelope_invalid());
    }

    let mut content_key = [0_u8; CONTENT_KEY_BYTES];
    let mut nonce = [0_u8; NONCE_BYTES];
    let rng = SystemRandom::new();
    if rng.fill(&mut content_key).is_err() || rng.fill(&mut nonce).is_err() {
        content_key.fill(0);
        return Err(deployment_encrypt_error());
    }
    let result = encrypt_payload_with_key(
        payload,
        recipients,
        recipient_count,
        content_ciphertext_len_u32,
        nonce,
        &content_key,
        unsigned_len,
    );
    content_key.fill(0);
    result
}

#[allow(clippy::too_many_arguments)]
fn encrypt_payload_with_key(
    payload: &[u8],
    recipients: &[DeploymentPublicKey],
    recipient_count: u16,
    content_ciphertext_len: u32,
    nonce: [u8; NONCE_BYTES],
    content_key: &[u8; CONTENT_KEY_BYTES],
    unsigned_len: usize,
) -> Result<Vec<u8>, SecureStoreError> {
    let mut recipient_table = Vec::with_capacity(recipients.len() * RECIPIENT_ENTRY_BYTES);
    for recipient in recipients {
        let public_key_bytes = deployment_public_key_bytes(recipient);
        let recipient_id = deployment_recipient_id(&public_key_bytes);
        let (encapped_key, mut sender) = setup_sender::<
            HpkeChaCha20Poly1305,
            HkdfSha256,
            DeploymentKem,
        >(&OpModeS::Base, recipient, HPKE_INFO)
        .map_err(|_| deployment_encrypt_error())?;
        let wrapped_key = sender
            .seal(content_key, &hpke_aad(&recipient_id))
            .map_err(|_| deployment_encrypt_error())?;
        let encapped_key = encapped_key.to_bytes();
        if encapped_key.len() != HPKE_ENCAPPED_KEY_BYTES
            || wrapped_key.len() != HPKE_WRAPPED_KEY_BYTES
        {
            return Err(deployment_encrypt_error());
        }
        recipient_table.extend_from_slice(&recipient_id);
        recipient_table.extend_from_slice(encapped_key.as_slice());
        recipient_table.extend_from_slice(&wrapped_key);
    }

    let mut envelope = Vec::with_capacity(unsigned_len);
    envelope.extend_from_slice(ENVELOPE_MAGIC);
    envelope.push(ENVELOPE_VERSION);
    envelope.extend_from_slice(&recipient_count.to_be_bytes());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&content_ciphertext_len.to_be_bytes());
    envelope.extend_from_slice(&recipient_table);

    let mut ciphertext = payload.to_vec();
    let key = encryption_key(content_key).map_err(|_| deployment_encrypt_error())?;
    let aad = content_aad(&envelope);
    if key
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut ciphertext,
        )
        .is_err()
    {
        ciphertext.fill(0);
        return Err(deployment_encrypt_error());
    }
    envelope.append(&mut ciphertext);
    Ok(envelope)
}

struct DeployedSecret {
    name: String,
    revision: u64,
    secret: Vec<u8>,
    envelope_digest: [u8; DIGEST_BYTES],
}

impl Drop for DeployedSecret {
    fn drop(&mut self) {
        self.secret.fill(0);
    }
}

fn open_deployment_envelope(
    envelope: &[u8],
    identity: &DeploymentIdentity,
    authority: &DeploymentAuthority,
) -> Result<DeployedSecret, SecureStoreError> {
    let layout = verify_deployment_envelope_layout(envelope, authority)?;
    let mut content_key = unwrap_content_key(envelope, identity, layout.recipient_count)?;
    let plaintext_result = decrypt_payload(
        &envelope[..layout.content_start],
        &envelope[layout.content_start..layout.unsigned_len],
        layout.nonce,
        &content_key,
    );
    content_key.fill(0);
    let plaintext = plaintext_result?;
    let mut deployed = parse_payload(plaintext)?;
    deployed
        .envelope_digest
        .copy_from_slice(digest(&SHA256, envelope).as_ref());
    Ok(deployed)
}

fn verify_deployment_envelope_layout(
    envelope: &[u8],
    authority: &DeploymentAuthority,
) -> Result<EnvelopeLayout, SecureStoreError> {
    let layout = parse_envelope_layout(envelope)?;
    let signature = &envelope[layout.unsigned_len..];
    UnparsedPublicKey::new(&ED25519, authority.public_key())
        .verify(
            &signature_message(&envelope[..layout.unsigned_len]),
            signature,
        )
        .map_err(|_| signature_invalid())?;
    validate_recipient_entries(envelope, layout.recipient_count)?;
    Ok(layout)
}

#[derive(Clone, Copy)]
struct EnvelopeLayout {
    recipient_count: usize,
    nonce: [u8; NONCE_BYTES],
    content_start: usize,
    unsigned_len: usize,
}

fn parse_envelope_layout(envelope: &[u8]) -> Result<EnvelopeLayout, SecureStoreError> {
    if envelope.len()
        < ENVELOPE_HEADER_BYTES + RECIPIENT_ENTRY_BYTES + CONTENT_TAG_BYTES + SIGNATURE_BYTES
        || envelope.len() as u64 > MAX_ENVELOPE_BYTES
        || &envelope[..ENVELOPE_MAGIC.len()] != ENVELOPE_MAGIC
        || envelope[ENVELOPE_MAGIC.len()] != ENVELOPE_VERSION
    {
        return Err(envelope_invalid());
    }

    let recipient_count_start = ENVELOPE_MAGIC.len() + 1;
    let nonce_start = recipient_count_start + 2;
    let content_length_start = nonce_start + NONCE_BYTES;
    let recipient_count = u16::from_be_bytes([
        envelope[recipient_count_start],
        envelope[recipient_count_start + 1],
    ]) as usize;
    let mut nonce = [0_u8; NONCE_BYTES];
    nonce.copy_from_slice(&envelope[nonce_start..content_length_start]);
    let content_ciphertext_len = u32::from_be_bytes([
        envelope[content_length_start],
        envelope[content_length_start + 1],
        envelope[content_length_start + 2],
        envelope[content_length_start + 3],
    ]) as usize;
    if recipient_count == 0
        || recipient_count > MAX_RECIPIENTS
        || content_ciphertext_len <= CONTENT_TAG_BYTES
        || content_ciphertext_len > MAX_PAYLOAD_BYTES + CONTENT_TAG_BYTES
    {
        return Err(envelope_invalid());
    }
    let recipient_table_len = recipient_count
        .checked_mul(RECIPIENT_ENTRY_BYTES)
        .ok_or_else(envelope_invalid)?;
    let content_start = ENVELOPE_HEADER_BYTES
        .checked_add(recipient_table_len)
        .ok_or_else(envelope_invalid)?;
    let unsigned_len = content_start
        .checked_add(content_ciphertext_len)
        .ok_or_else(envelope_invalid)?;
    let expected_len = unsigned_len
        .checked_add(SIGNATURE_BYTES)
        .ok_or_else(envelope_invalid)?;
    if expected_len != envelope.len() {
        return Err(envelope_invalid());
    }
    Ok(EnvelopeLayout {
        recipient_count,
        nonce,
        content_start,
        unsigned_len,
    })
}

fn validate_recipient_entries(
    envelope: &[u8],
    recipient_count: usize,
) -> Result<(), SecureStoreError> {
    let mut seen_recipient_ids = BTreeSet::new();
    for index in 0..recipient_count {
        let entry_start = ENVELOPE_HEADER_BYTES + index * RECIPIENT_ENTRY_BYTES;
        let encapped_start = entry_start + RECIPIENT_ID_BYTES;
        let wrapped_start = encapped_start + HPKE_ENCAPPED_KEY_BYTES;
        let mut recipient_id = [0_u8; RECIPIENT_ID_BYTES];
        recipient_id.copy_from_slice(&envelope[entry_start..encapped_start]);
        if !seen_recipient_ids.insert(recipient_id)
            || DeploymentEncappedKey::from_bytes(&envelope[encapped_start..wrapped_start]).is_err()
        {
            return Err(envelope_invalid());
        }
    }
    Ok(())
}

fn unwrap_content_key(
    envelope: &[u8],
    identity: &DeploymentIdentity,
    recipient_count: usize,
) -> Result<[u8; CONTENT_KEY_BYTES], SecureStoreError> {
    let identity_public_key = DeploymentKem::sk_to_pk(&identity.0);
    let identity_public_bytes = deployment_public_key_bytes(&identity_public_key);
    let identity_recipient_id = deployment_recipient_id(&identity_public_bytes);
    let mut seen_recipient_ids = BTreeSet::new();
    let mut matching_entry = None;
    for index in 0..recipient_count {
        let entry_start = ENVELOPE_HEADER_BYTES + index * RECIPIENT_ENTRY_BYTES;
        let mut recipient_id = [0_u8; RECIPIENT_ID_BYTES];
        recipient_id.copy_from_slice(&envelope[entry_start..entry_start + RECIPIENT_ID_BYTES]);
        if !seen_recipient_ids.insert(recipient_id) {
            return Err(envelope_invalid());
        }
        if recipient_id == identity_recipient_id {
            matching_entry = Some(entry_start);
        }
    }
    let entry_start = matching_entry.ok_or_else(decrypt_invalid)?;
    let encapped_start = entry_start + RECIPIENT_ID_BYTES;
    let wrapped_start = encapped_start + HPKE_ENCAPPED_KEY_BYTES;
    let encapped_key = DeploymentEncappedKey::from_bytes(&envelope[encapped_start..wrapped_start])
        .map_err(|_| decrypt_invalid())?;
    let wrapped_end = wrapped_start + HPKE_WRAPPED_KEY_BYTES;
    let mut receiver = setup_receiver::<HpkeChaCha20Poly1305, HkdfSha256, DeploymentKem>(
        &OpModeR::Base,
        &identity.0,
        &encapped_key,
        HPKE_INFO,
    )
    .map_err(|_| decrypt_invalid())?;
    let mut unwrapped_key = receiver
        .open(
            &envelope[wrapped_start..wrapped_end],
            &hpke_aad(&identity_recipient_id),
        )
        .map_err(|_| decrypt_invalid())?;
    if unwrapped_key.len() != CONTENT_KEY_BYTES {
        unwrapped_key.fill(0);
        return Err(decrypt_invalid());
    }
    let mut content_key = [0_u8; CONTENT_KEY_BYTES];
    content_key.copy_from_slice(&unwrapped_key);
    unwrapped_key.fill(0);
    Ok(content_key)
}

fn decrypt_payload(
    envelope_prefix: &[u8],
    content_ciphertext: &[u8],
    nonce: [u8; NONCE_BYTES],
    content_key: &[u8; CONTENT_KEY_BYTES],
) -> Result<Vec<u8>, SecureStoreError> {
    let mut plaintext = content_ciphertext.to_vec();
    let key = encryption_key(content_key).map_err(|_| decrypt_invalid())?;
    let aad = content_aad(envelope_prefix);
    let plaintext_len = if let Ok(value) = key.open_in_place(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad),
        &mut plaintext,
    ) {
        value.len()
    } else {
        plaintext.fill(0);
        return Err(decrypt_invalid());
    };
    plaintext.truncate(plaintext_len);
    if plaintext.is_empty() || plaintext.len() > MAX_PAYLOAD_BYTES {
        plaintext.fill(0);
        return Err(payload_invalid());
    }
    Ok(plaintext)
}

fn parse_payload(mut plaintext: Vec<u8>) -> Result<DeployedSecret, SecureStoreError> {
    let invalid = plaintext.len() < PAYLOAD_HEADER_BYTES
        || &plaintext[..PAYLOAD_MAGIC.len()] != PAYLOAD_MAGIC
        || plaintext[PAYLOAD_MAGIC.len()] != PAYLOAD_VERSION;
    if invalid {
        plaintext.fill(0);
        return Err(payload_invalid());
    }
    let revision_start = PAYLOAD_MAGIC.len() + 1;
    let name_length_start = revision_start + 8;
    let secret_length_start = name_length_start + 2;
    let mut revision_bytes = [0_u8; 8];
    revision_bytes.copy_from_slice(&plaintext[revision_start..name_length_start]);
    let revision = u64::from_be_bytes(revision_bytes);
    let name_len = u16::from_be_bytes([
        plaintext[name_length_start],
        plaintext[name_length_start + 1],
    ]) as usize;
    let secret_len = u32::from_be_bytes([
        plaintext[secret_length_start],
        plaintext[secret_length_start + 1],
        plaintext[secret_length_start + 2],
        plaintext[secret_length_start + 3],
    ]) as usize;
    let Some(name_end) = PAYLOAD_HEADER_BYTES.checked_add(name_len) else {
        plaintext.fill(0);
        return Err(payload_invalid());
    };
    let Some(expected_len) = name_end.checked_add(secret_len) else {
        plaintext.fill(0);
        return Err(payload_invalid());
    };
    if revision == 0
        || name_len == 0
        || name_len > MAX_SECRET_NAME_BYTES
        || secret_len == 0
        || secret_len > MAX_SECRET_BYTES
        || expected_len != plaintext.len()
    {
        plaintext.fill(0);
        return Err(payload_invalid());
    }
    let name = if let Ok(value) = std::str::from_utf8(&plaintext[PAYLOAD_HEADER_BYTES..name_end]) {
        value.to_owned()
    } else {
        plaintext.fill(0);
        return Err(payload_invalid());
    };
    if validate_name(&name).is_err() {
        plaintext.fill(0);
        return Err(payload_invalid());
    }
    let secret = plaintext.split_off(name_end);
    plaintext.fill(0);
    Ok(DeployedSecret {
        name,
        revision,
        secret,
        envelope_digest: [0_u8; DIGEST_BYTES],
    })
}

fn signature_message(unsigned_envelope: &[u8]) -> Vec<u8> {
    let mut context = Context::new(&SHA256);
    context.update(SIGNATURE_DOMAIN);
    context.update(unsigned_envelope);
    context.finish().as_ref().to_vec()
}

#[derive(Clone, Copy)]
struct Receipt {
    revision: u64,
    envelope_digest: [u8; DIGEST_BYTES],
}

fn import_deployed_secret(
    store: &SecretStore,
    receipt_dir: &Path,
    deployed: &DeployedSecret,
    policy: DeploymentImportPolicy,
) -> Result<DeploymentImportResult, SecureStoreError> {
    let name = deployed.name.clone();
    if let Some(receipt) = load_receipt(store, receipt_dir, &name)? {
        if deployed.revision < receipt.revision {
            return Ok(DeploymentImportResult::Stale {
                name,
                envelope_revision: deployed.revision,
                current_revision: receipt.revision,
            });
        }
        if deployed.revision == receipt.revision {
            if deployed.envelope_digest != receipt.envelope_digest {
                return Err(revision_conflict());
            }
            if store.secret_path(&name).exists() {
                if !store.secret_matches(&name, &deployed.secret)? {
                    return Err(local_secret_conflict());
                }
                return Ok(DeploymentImportResult::AlreadyCurrent {
                    name,
                    revision: deployed.revision,
                });
            }
            store.set(&name, deployed.secret.clone())?;
            return Ok(DeploymentImportResult::Repaired {
                name,
                revision: deployed.revision,
            });
        }
    } else if store.secret_path(&name).exists() {
        if store.secret_matches(&name, &deployed.secret)? {
            store_receipt(
                store,
                receipt_dir,
                &name,
                deployed.revision,
                deployed.envelope_digest,
            )?;
            return Ok(DeploymentImportResult::Repaired {
                name,
                revision: deployed.revision,
            });
        }
        if policy == DeploymentImportPolicy::RequireAbsentOrMatching {
            return Err(local_secret_conflict());
        }
    }

    store.set(&name, deployed.secret.clone())?;
    store_receipt(
        store,
        receipt_dir,
        &name,
        deployed.revision,
        deployed.envelope_digest,
    )?;
    Ok(DeploymentImportResult::Imported {
        name,
        revision: deployed.revision,
    })
}

fn load_receipt(
    store: &SecretStore,
    receipt_dir: &Path,
    name: &str,
) -> Result<Option<Receipt>, SecureStoreError> {
    let path = receipt_path(receipt_dir, name);
    if !path.exists() {
        return Ok(None);
    }
    let mut protected = read_private_limited(&path, RECEIPT_FILE_BYTES as u64)?;
    let prefix_len = RECEIPT_MAGIC.len() + 1 + NONCE_BYTES;
    if protected.len() != RECEIPT_FILE_BYTES
        || &protected[..RECEIPT_MAGIC.len()] != RECEIPT_MAGIC
        || protected[RECEIPT_MAGIC.len()] != RECEIPT_VERSION
    {
        protected.fill(0);
        return Err(receipt_invalid());
    }
    let mut nonce = [0_u8; NONCE_BYTES];
    nonce.copy_from_slice(&protected[RECEIPT_MAGIC.len() + 1..prefix_len]);
    let mut ciphertext = protected.split_off(prefix_len);
    protected.fill(0);
    let key = encryption_key(store.key())?;
    let plaintext_len = if let Ok(plaintext) = key.open_in_place(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(receipt_aad(name)),
        &mut ciphertext,
    ) {
        plaintext.len()
    } else {
        ciphertext.fill(0);
        return Err(receipt_invalid());
    };
    ciphertext.truncate(plaintext_len);
    if ciphertext.len() != RECEIPT_PLAINTEXT_BYTES {
        ciphertext.fill(0);
        return Err(receipt_invalid());
    }
    let revision = u64::from_be_bytes(ciphertext[..8].try_into().map_err(|_| receipt_invalid())?);
    let mut envelope_digest = [0_u8; DIGEST_BYTES];
    envelope_digest.copy_from_slice(&ciphertext[8..]);
    ciphertext.fill(0);
    if revision == 0 {
        return Err(receipt_invalid());
    }
    Ok(Some(Receipt {
        revision,
        envelope_digest,
    }))
}

fn store_receipt(
    store: &SecretStore,
    receipt_dir: &Path,
    name: &str,
    revision: u64,
    envelope_digest: [u8; DIGEST_BYTES],
) -> Result<(), SecureStoreError> {
    let mut plaintext = Vec::with_capacity(RECEIPT_PLAINTEXT_BYTES + aead::MAX_TAG_LEN);
    plaintext.extend_from_slice(&revision.to_be_bytes());
    plaintext.extend_from_slice(&envelope_digest);
    let mut nonce = [0_u8; NONCE_BYTES];
    SystemRandom::new().fill(&mut nonce).map_err(|_| {
        plaintext.fill(0);
        receipt_crypto_error()
    })?;
    let key = encryption_key(store.key())?;
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(receipt_aad(name)),
        &mut plaintext,
    )
    .map_err(|_| {
        plaintext.fill(0);
        receipt_crypto_error()
    })?;
    let mut protected = Vec::with_capacity(RECEIPT_FILE_BYTES);
    protected.extend_from_slice(RECEIPT_MAGIC);
    protected.push(RECEIPT_VERSION);
    protected.extend_from_slice(&nonce);
    protected.append(&mut plaintext);
    let result = atomic_write(&receipt_path(receipt_dir, name), &protected, 0o600);
    protected.fill(0);
    result
}

fn receipt_aad(name: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(RECEIPT_AAD_DOMAIN.len() + name.len());
    aad.extend_from_slice(RECEIPT_AAD_DOMAIN);
    aad.extend_from_slice(name.as_bytes());
    aad
}

fn receipt_path(directory: &Path, name: &str) -> PathBuf {
    directory.join(format!("{name}.receipt"))
}

fn deployment_envelope_files(directory: &Path) -> Result<Vec<PathBuf>, SecureStoreError> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(deployment_directory_invalid());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(SecureStoreError::io(
                "DBX-RS-DEPLOY-0017",
                "deployment_scan",
                "failed to inspect the deployment credential directory",
                &error,
            ));
        }
    }
    let entries = fs::read_dir(directory).map_err(|error| {
        SecureStoreError::io(
            "DBX-RS-DEPLOY-0017",
            "deployment_scan",
            "failed to inspect the deployment credential directory",
            &error,
        )
    })?;
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            SecureStoreError::io(
                "DBX-RS-DEPLOY-0017",
                "deployment_scan",
                "failed to inspect a deployment credential entry",
                &error,
            )
        })?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("dbxsecret") {
            continue;
        }
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            SecureStoreError::io(
                "DBX-RS-DEPLOY-0017",
                "deployment_scan",
                "failed to inspect a deployment credential entry",
                &error,
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(deployment_directory_invalid());
        }
        files.push(path);
        if files.len() > MAX_DEPLOYMENT_FILES {
            return Err(deployment_directory_invalid());
        }
    }
    files.sort();
    Ok(files)
}

struct ImportFileLock(File);

impl ImportFileLock {
    fn acquire(directory: &Path) -> Result<Self, SecureStoreError> {
        ensure_private_dir(directory)?;
        let path = directory.join(WRITER_LOCK_FILE);
        if !path.exists() {
            match write_new(&path, b"", 0o600) {
                Ok(()) => {}
                Err(error) if error.io_kind() == Some(std::io::ErrorKind::AlreadyExists) => {}
                Err(error) => return Err(error),
            }
        }
        let _validated = read_private_limited(&path, 0)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|error| {
                SecureStoreError::io(
                    "DBX-RS-DEPLOY-0018",
                    "deployment_lock",
                    "failed to open the deployment credential lock",
                    &error,
                )
            })?;
        File::lock(&file).map_err(|error| {
            SecureStoreError::io(
                "DBX-RS-DEPLOY-0018",
                "deployment_lock",
                "failed to acquire the deployment credential lock",
                &error,
            )
        })?;
        Ok(Self(file))
    }
}

impl Drop for ImportFileLock {
    fn drop(&mut self) {
        let _ignored = File::unlock(&self.0);
    }
}

fn deployment_public_key_bytes(public_key: &DeploymentPublicKey) -> [u8; PUBLIC_KEY_BYTES] {
    let encoded = public_key.to_bytes();
    let mut bytes = [0_u8; PUBLIC_KEY_BYTES];
    bytes.copy_from_slice(encoded.as_slice());
    bytes
}

fn deployment_recipient_id(public_key: &[u8; PUBLIC_KEY_BYTES]) -> [u8; RECIPIENT_ID_BYTES] {
    let mut identifier = [0_u8; RECIPIENT_ID_BYTES];
    identifier.copy_from_slice(digest(&SHA256, public_key).as_ref());
    identifier
}

fn hpke_aad(recipient_id: &[u8; RECIPIENT_ID_BYTES]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HPKE_AAD_DOMAIN.len() + recipient_id.len());
    aad.extend_from_slice(HPKE_AAD_DOMAIN);
    aad.extend_from_slice(recipient_id);
    aad
}

fn content_aad(envelope_prefix: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CONTENT_AAD_DOMAIN.len() + envelope_prefix.len());
    aad.extend_from_slice(CONTENT_AAD_DOMAIN);
    aad.extend_from_slice(envelope_prefix);
    aad
}

fn decode_lowercase_hex_32(value: &str) -> Option<[u8; PUBLIC_KEY_BYTES]> {
    if value.len() != RECIPIENT_HEX_BYTES || !value.is_ascii() {
        return None;
    }
    let encoded = value.as_bytes();
    let mut decoded = [0_u8; PUBLIC_KEY_BYTES];
    for (index, byte) in decoded.iter_mut().enumerate() {
        let high = lowercase_hex_value(encoded[index * 2])?;
        let low = lowercase_hex_value(encoded[index * 2 + 1])?;
        *byte = (high << 4) | low;
    }
    Some(decoded)
}

const fn lowercase_hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

const fn authority_invalid() -> SecureStoreError {
    SecureStoreError::new(
        "DBX-RS-DEPLOY-0002",
        "configuration",
        "deployment_authority",
        "deployment authority public material is invalid",
        false,
        true,
    )
}

const fn signer_invalid() -> SecureStoreError {
    SecureStoreError::new(
        "DBX-RS-DEPLOY-0003",
        "configuration",
        "deployment_signer",
        "deployment authority private key is invalid or does not match this binary",
        false,
        true,
    )
}

const fn recipient_invalid() -> SecureStoreError {
    SecureStoreError::new(
        "DBX-RS-DEPLOY-0004",
        "configuration",
        "deployment_recipient",
        "deployment recipient set is invalid",
        false,
        true,
    )
}

const fn deployment_input_invalid() -> SecureStoreError {
    SecureStoreError::new(
        "DBX-RS-DEPLOY-0005",
        "configuration",
        "deployment_secret",
        "deployment secret name, revision, or value is invalid",
        false,
        true,
    )
}

const fn deployment_encrypt_error() -> SecureStoreError {
    SecureStoreError::new(
        "DBX-RS-DEPLOY-0006",
        "internal",
        "deployment_encrypt",
        "deployment secret encryption failed",
        false,
        false,
    )
}

const fn envelope_invalid() -> SecureStoreError {
    SecureStoreError::new(
        "DBX-RS-DEPLOY-0007",
        "configuration",
        "deployment_envelope",
        "deployment credential envelope is invalid",
        false,
        true,
    )
}

const fn signature_invalid() -> SecureStoreError {
    SecureStoreError::new(
        "DBX-RS-DEPLOY-0008",
        "configuration",
        "deployment_signature",
        "deployment credential signature is invalid",
        false,
        true,
    )
}

const fn decrypt_invalid() -> SecureStoreError {
    SecureStoreError::new(
        "DBX-RS-DEPLOY-0009",
        "configuration",
        "deployment_decrypt",
        "deployment credential cannot be decrypted by this installation",
        false,
        true,
    )
}

const fn payload_invalid() -> SecureStoreError {
    SecureStoreError::new(
        "DBX-RS-DEPLOY-0010",
        "configuration",
        "deployment_payload",
        "decrypted deployment credential payload is invalid",
        false,
        true,
    )
}

const fn identity_invalid() -> SecureStoreError {
    SecureStoreError::new(
        "DBX-RS-DEPLOY-0011",
        "configuration",
        "deployment_identity",
        "installation deployment identity is invalid",
        false,
        true,
    )
}

const fn receipt_invalid() -> SecureStoreError {
    SecureStoreError::new(
        "DBX-RS-DEPLOY-0012",
        "configuration",
        "deployment_receipt",
        "deployment credential receipt is invalid or cannot be authenticated",
        false,
        true,
    )
}

const fn receipt_crypto_error() -> SecureStoreError {
    SecureStoreError::new(
        "DBX-RS-DEPLOY-0013",
        "internal",
        "deployment_receipt",
        "deployment credential receipt encryption failed",
        false,
        false,
    )
}

const fn revision_conflict() -> SecureStoreError {
    SecureStoreError::new(
        "DBX-RS-DEPLOY-0014",
        "configuration",
        "deployment_revision",
        "deployment credential revision conflicts with authenticated state",
        false,
        true,
    )
}

const fn local_secret_conflict() -> SecureStoreError {
    SecureStoreError::new(
        "DBX-RS-DEPLOY-0015",
        "configuration",
        "deployment_import",
        "deployment credential conflicts with an unmanaged local secret",
        false,
        true,
    )
}

const fn deployment_directory_invalid() -> SecureStoreError {
    SecureStoreError::new(
        "DBX-RS-DEPLOY-0016",
        "configuration",
        "deployment_scan",
        "deployment credential directory contains an invalid entry or too many envelopes",
        false,
        true,
    )
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use rcgen::{CertificateParams, DnType, KeyPair as RcgenKeyPair, PKCS_ED25519};

    use super::*;

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    fn fixture() -> (PathBuf, SecretStore, DeploymentIdentity) {
        let root = std::env::temp_dir().join(format!(
            "dbx-rs-deployment-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let store = SecretStore::open(&root.join("master.key"), &root.join("secrets"))
            .expect("secret store must open");
        (root, store, DeploymentIdentity::generate())
    }

    fn authority() -> (DeploymentAuthority, AuthoritySigner) {
        let key_pair = RcgenKeyPair::generate_for(&PKCS_ED25519).expect("test key must generate");
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "dbx-rs test deployment authority");
        let certificate = params
            .self_signed(&key_pair)
            .expect("test certificate must generate");
        let authority =
            DeploymentAuthority::from_parts(certificate.der().as_ref(), key_pair.public_key_raw())
                .expect("test authority must load");
        let signer = AuthoritySigner::from_pkcs8(key_pair.serialized_der(), &authority)
            .expect("test signer must load");
        (authority, signer)
    }

    fn envelope(
        identity: &DeploymentIdentity,
        signer: &AuthoritySigner,
        revision: u64,
        value: &[u8],
    ) -> Vec<u8> {
        seal_deployment_secret(
            "warehouse",
            revision,
            value.to_vec(),
            &[identity.recipient()],
            signer,
        )
        .expect("envelope must seal")
    }

    #[test]
    fn installation_identity_round_trips_and_is_stable() {
        let (root, _store, _) = fixture();
        let identity_file = root.join("deployment/identity");
        let created =
            DeploymentIdentity::load_or_create(&identity_file).expect("identity must be created");
        let loaded = DeploymentIdentity::load(&identity_file).expect("identity must be loadable");

        assert_eq!(created.recipient(), loaded.recipient());
        assert!(created.recipient().starts_with(RECIPIENT_PREFIX));
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn deployment_authority_rejects_mismatched_and_tampered_certificates() {
        let key_pair = RcgenKeyPair::generate_for(&PKCS_ED25519).expect("test key must generate");
        let wrong_key_pair =
            RcgenKeyPair::generate_for(&PKCS_ED25519).expect("wrong test key must generate");
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "dbx-rs test deployment authority");
        let certificate = params
            .self_signed(&key_pair)
            .expect("test certificate must generate");

        let mismatch = DeploymentAuthority::from_parts(
            certificate.der().as_ref(),
            wrong_key_pair.public_key_raw(),
        )
        .expect_err("certificate and raw public key must match");
        assert_eq!(mismatch.code(), "DBX-RS-DEPLOY-0002");

        let mut tampered = certificate.der().as_ref().to_vec();
        let signature_byte = tampered
            .last_mut()
            .expect("certificate must include a signature");
        *signature_byte ^= 0x01;
        let tamper = DeploymentAuthority::from_parts(&tampered, key_pair.public_key_raw())
            .expect_err("certificate signature tampering must fail");
        assert_eq!(tamper.code(), "DBX-RS-DEPLOY-0002");
    }

    #[test]
    fn empty_embedded_reconciliation_needs_no_authority_or_identity() {
        let (root, store, _) = fixture();
        let summary = reconcile_embedded_deployment_directory(
            &store,
            &root.join("deployment-secrets"),
            &root.join("missing-identity"),
            &root.join("receipts"),
        )
        .expect("empty directory must be a no-op");

        assert_eq!(summary, DeploymentReconcileSummary::default());
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn signed_multi_recipient_envelope_imports_without_plaintext() {
        let (root, store, first) = fixture();
        let second = DeploymentIdentity::generate();
        let (authority, signer) = authority();
        let marker = b"deployment-only-password";
        let sealed = seal_deployment_secret(
            "warehouse",
            1,
            marker.to_vec(),
            &[first.recipient(), second.recipient()],
            &signer,
        )
        .expect("envelope must seal");

        assert!(!sealed.windows(marker.len()).any(|window| window == marker));
        verify_deployment_envelope(&sealed, &authority)
            .expect("builder-style signature verification must pass");

        let mut duplicate_recipient = sealed.clone();
        let first_recipient_id = duplicate_recipient
            [ENVELOPE_HEADER_BYTES..ENVELOPE_HEADER_BYTES + RECIPIENT_ID_BYTES]
            .to_vec();
        let second_recipient_start = ENVELOPE_HEADER_BYTES + RECIPIENT_ENTRY_BYTES;
        duplicate_recipient[second_recipient_start..second_recipient_start + RECIPIENT_ID_BYTES]
            .copy_from_slice(&first_recipient_id);
        let unsigned_len = duplicate_recipient.len() - SIGNATURE_BYTES;
        let replacement_signature =
            signer.sign(&signature_message(&duplicate_recipient[..unsigned_len]));
        duplicate_recipient[unsigned_len..].copy_from_slice(&replacement_signature);
        let duplicate_error = verify_deployment_envelope(&duplicate_recipient, &authority)
            .expect_err("duplicate recipient entries must fail");
        assert_eq!(duplicate_error.code(), "DBX-RS-DEPLOY-0007");

        let result = store
            .import_deployment_envelope(
                &sealed,
                &second,
                &root.join("receipts"),
                &authority,
                DeploymentImportPolicy::RequireAbsentOrMatching,
            )
            .expect("second recipient must import");
        assert_eq!(
            result,
            DeploymentImportResult::Imported {
                name: "warehouse".into(),
                revision: 1,
            }
        );
        assert_eq!(
            store
                .resolve("local:warehouse")
                .expect("secret must resolve")
                .expose_secret(),
            marker
        );
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn tamper_wrong_identity_and_wrong_signer_fail_closed() {
        let (root, store, identity) = fixture();
        let wrong_identity = DeploymentIdentity::generate();
        let (trusted_authority, signer) = authority();
        let (wrong_authority, _) = authority();
        let sealed = envelope(&identity, &signer, 1, b"secret");

        let wrong_identity_error = store
            .import_deployment_envelope(
                &sealed,
                &wrong_identity,
                &root.join("receipts"),
                &trusted_authority,
                DeploymentImportPolicy::RequireAbsentOrMatching,
            )
            .expect_err("wrong identity must fail");
        assert_eq!(wrong_identity_error.code(), "DBX-RS-DEPLOY-0009");

        let wrong_signer_error = store
            .import_deployment_envelope(
                &sealed,
                &identity,
                &root.join("receipts"),
                &wrong_authority,
                DeploymentImportPolicy::RequireAbsentOrMatching,
            )
            .expect_err("wrong authority must fail");
        assert_eq!(wrong_signer_error.code(), "DBX-RS-DEPLOY-0008");

        let mut tampered = sealed;
        tampered[ENVELOPE_HEADER_BYTES + 1] ^= 0x80;
        let tamper_error = store
            .import_deployment_envelope(
                &tampered,
                &identity,
                &root.join("receipts"),
                &trusted_authority,
                DeploymentImportPolicy::RequireAbsentOrMatching,
            )
            .expect_err("tamper must fail");
        assert_eq!(tamper_error.code(), "DBX-RS-DEPLOY-0008");
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn revisions_are_idempotent_monotonic_and_conflict_checked() {
        let (root, store, identity) = fixture();
        let (authority, signer) = authority();
        let receipt_dir = root.join("receipts");
        let first = envelope(&identity, &signer, 7, b"first");
        let next = envelope(&identity, &signer, 8, b"next");
        let conflict = envelope(&identity, &signer, 8, b"different");

        assert!(matches!(
            store
                .import_deployment_envelope(
                    &first,
                    &identity,
                    &receipt_dir,
                    &authority,
                    DeploymentImportPolicy::RequireAbsentOrMatching,
                )
                .expect("first import must pass"),
            DeploymentImportResult::Imported { revision: 7, .. }
        ));
        assert!(matches!(
            store
                .import_deployment_envelope(
                    &first,
                    &identity,
                    &receipt_dir,
                    &authority,
                    DeploymentImportPolicy::RequireAbsentOrMatching,
                )
                .expect("repeat must pass"),
            DeploymentImportResult::AlreadyCurrent { revision: 7, .. }
        ));
        assert!(matches!(
            store
                .import_deployment_envelope(
                    &next,
                    &identity,
                    &receipt_dir,
                    &authority,
                    DeploymentImportPolicy::RequireAbsentOrMatching,
                )
                .expect("higher revision must pass"),
            DeploymentImportResult::Imported { revision: 8, .. }
        ));
        assert!(matches!(
            store
                .import_deployment_envelope(
                    &first,
                    &identity,
                    &receipt_dir,
                    &authority,
                    DeploymentImportPolicy::RequireAbsentOrMatching,
                )
                .expect("lower revision must be classified"),
            DeploymentImportResult::Stale {
                envelope_revision: 7,
                current_revision: 8,
                ..
            }
        ));
        let conflict_error = store
            .import_deployment_envelope(
                &conflict,
                &identity,
                &receipt_dir,
                &authority,
                DeploymentImportPolicy::RequireAbsentOrMatching,
            )
            .expect_err("same revision conflict must fail");
        assert_eq!(conflict_error.code(), "DBX-RS-DEPLOY-0014");
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn first_import_does_not_replace_a_different_unmanaged_secret_without_policy() {
        let (root, store, identity) = fixture();
        let (authority, signer) = authority();
        store
            .set("warehouse", b"local".to_vec())
            .expect("local secret must store");
        let sealed = envelope(&identity, &signer, 1, b"deployed");

        let error = store
            .import_deployment_envelope(
                &sealed,
                &identity,
                &root.join("receipts"),
                &authority,
                DeploymentImportPolicy::RequireAbsentOrMatching,
            )
            .expect_err("automatic import must not replace unmanaged state");
        assert_eq!(error.code(), "DBX-RS-DEPLOY-0015");
        assert!(matches!(
            store
                .import_deployment_envelope(
                    &sealed,
                    &identity,
                    &root.join("receipts"),
                    &authority,
                    DeploymentImportPolicy::ReplaceExisting,
                )
                .expect("explicit replacement must pass"),
            DeploymentImportResult::Imported { revision: 1, .. }
        ));
        fs::remove_dir_all(root).expect("fixture must be removed");
    }
}
