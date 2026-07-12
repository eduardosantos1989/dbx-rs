use std::path::Path;

use dbx_rs_secure_store::{read_limited, write_new};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, date_time_ymd,
};
use ring::rand::{SecureRandom, SystemRandom};

use crate::error::DaemonError;

const TOKEN_BYTES: usize = 36;
const MAX_PEM_BYTES: u64 = 64 * 1024;

pub struct HecToken {
    bytes: Vec<u8>,
}

impl HecToken {
    pub fn load(path: &Path) -> Result<Self, DaemonError> {
        Self::from_bytes(read_limited(path, 128)?)
    }

    pub fn load_or_create(path: &Path) -> Result<Self, DaemonError> {
        if path.exists() {
            return Self::load(path);
        }

        let token = generate_uuid()?;
        match write_new(path, token.as_bytes(), 0o600) {
            Ok(()) => Self::from_bytes(token.into_bytes()),
            Err(_) if path.exists() => Self::load(path),
            Err(error) => Err(error.into()),
        }
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes).expect("validated HEC token must remain UTF-8")
    }
}

impl Drop for HecToken {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

pub(crate) fn generate_uuid() -> Result<String, DaemonError> {
    let random = generate_uuid_bytes()?;
    Ok(format!(
        "{}-{}-{}-{}-{}",
        hex(&random[0..4]),
        hex(&random[4..6]),
        hex(&random[6..8]),
        hex(&random[8..10]),
        hex(&random[10..16])
    ))
}

pub(crate) fn generate_uuid_bytes() -> Result<[u8; 16], DaemonError> {
    let mut random = [0_u8; 16];
    SystemRandom::new().fill(&mut random).map_err(|_| {
        DaemonError::new(
            "DBX-RS-ID-0001",
            "internal",
            "random_generation",
            "secure random generation failed",
            false,
            false,
        )
    })?;
    random[6] = (random[6] & 0x0f) | 0x40;
    random[8] = (random[8] & 0x3f) | 0x80;
    Ok(random)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

impl HecToken {
    fn from_bytes(mut bytes: Vec<u8>) -> Result<Self, DaemonError> {
        while matches!(bytes.last(), Some(b'\n' | b'\r')) {
            bytes.pop();
        }
        if bytes.len() != TOKEN_BYTES || !valid_uuid(&bytes) {
            bytes.fill(0);
            return Err(DaemonError::new(
                "DBX-RS-ID-0002",
                "configuration",
                "token_validate",
                "stored HEC token is invalid",
                false,
                true,
            ));
        }
        Ok(Self { bytes })
    }
}

fn valid_uuid(value: &[u8]) -> bool {
    value.iter().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) {
            *byte == b'-'
        } else {
            byte.is_ascii_hexdigit()
        }
    })
}

pub fn ensure_hec_certificate(server_path: &Path, ca_path: &Path) -> Result<bool, DaemonError> {
    match (server_path.exists(), ca_path.exists()) {
        (true, true) => {
            validate_pem(&read_limited(server_path, MAX_PEM_BYTES)?, true)?;
            validate_pem(&read_limited(ca_path, MAX_PEM_BYTES)?, false)?;
            Ok(false)
        }
        (false, false) => {
            let (server_pem, ca_pem) = generate_hec_certificate()?;
            write_new(ca_path, ca_pem.as_bytes(), 0o644)?;
            if let Err(error) = write_new(server_path, server_pem.as_bytes(), 0o600) {
                let _ignored = std::fs::remove_file(ca_path);
                return Err(error.into());
            }
            Ok(true)
        }
        _ => Err(DaemonError::new(
            "DBX-RS-ID-0003",
            "configuration",
            "certificate_validate",
            "HEC certificate installation is incomplete",
            false,
            true,
        )),
    }
}

fn generate_hec_certificate() -> Result<(String, String), DaemonError> {
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "dbx-rs local HEC CA");
    set_legacy_safe_validity(&mut ca_params);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate().map_err(|_| certificate_error())?;
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).map_err(|_| certificate_error())?;

    let mut server_params = CertificateParams::new(vec![
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
        "::1".to_owned(),
    ])
    .map_err(|_| certificate_error())?;
    server_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    set_legacy_safe_validity(&mut server_params);
    server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate().map_err(|_| certificate_error())?;
    let server_cert = server_params
        .signed_by(&server_key, &ca)
        .map_err(|_| certificate_error())?;
    let ca_pem = ca.pem();
    let server_pem = format!(
        "{}{}{}",
        server_cert.pem(),
        server_key.serialize_pem(),
        ca_pem
    );
    Ok((server_pem, ca_pem))
}

fn set_legacy_safe_validity(params: &mut CertificateParams) {
    params.not_before = date_time_ymd(2020, 1, 1);
    params.not_after = date_time_ymd(2037, 12, 31);
}

const fn certificate_error() -> DaemonError {
    DaemonError::new(
        "DBX-RS-ID-0004",
        "internal",
        "certificate_generation",
        "HEC certificate generation failed",
        false,
        false,
    )
}

fn validate_pem(bytes: &[u8], requires_key: bool) -> Result<(), DaemonError> {
    let has_certificate = bytes
        .windows(b"-----BEGIN CERTIFICATE-----".len())
        .any(|window| window == b"-----BEGIN CERTIFICATE-----");
    let has_key = bytes
        .windows(b"-----BEGIN PRIVATE KEY-----".len())
        .any(|window| window == b"-----BEGIN PRIVATE KEY-----");
    if !has_certificate || (requires_key && !has_key) {
        return Err(DaemonError::new(
            "DBX-RS-ID-0005",
            "configuration",
            "certificate_validate",
            "stored HEC certificate material is invalid",
            false,
            true,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "dbx-rs-identity-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn generated_token_is_stable_and_uuid_shaped() {
        let root = test_dir();
        let path = root.join("hec.token");
        let first = HecToken::load_or_create(&path).expect("token must be created");
        let first_value = first.as_str().to_owned();
        drop(first);
        let second = HecToken::load_or_create(&path).expect("token must be reloaded");

        assert_eq!(second.as_str(), first_value);
        assert!(valid_uuid(second.as_str().as_bytes()));
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn generated_certificate_contains_leaf_key_and_ca() {
        let root = test_dir();
        let server = root.join("hec-server.pem");
        let ca = root.join("hec-ca.pem");

        assert!(ensure_hec_certificate(&server, &ca).expect("certificate must be generated"));
        assert!(!ensure_hec_certificate(&server, &ca).expect("certificate must be stable"));
        validate_pem(
            &fs::read(&server).expect("server PEM must be readable"),
            true,
        )
        .expect("server PEM must validate");
        validate_pem(&fs::read(&ca).expect("CA PEM must be readable"), false)
            .expect("CA PEM must validate");
        fs::remove_dir_all(root).expect("fixture must be removed");
    }
}
