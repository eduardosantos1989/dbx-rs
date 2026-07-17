use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const CERT_ENV: &str = "DBX_RS_DEPLOYMENT_AUTHORITY_CERT_DER";
const PUBLIC_KEY_ENV: &str = "DBX_RS_DEPLOYMENT_AUTHORITY_PUBLIC_KEY";
const MAX_CERT_BYTES: usize = 16 * 1024;
const PUBLIC_KEY_BYTES: usize = 32;

fn main() {
    println!("cargo:rerun-if-env-changed={CERT_ENV}");
    println!("cargo:rerun-if-env-changed={PUBLIC_KEY_ENV}");

    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be available"));
    let cert = configured_path(CERT_ENV);
    let public_key = configured_path(PUBLIC_KEY_ENV);
    match (cert, public_key) {
        (None, None) => {
            fs::write(output.join("deployment-authority.der"), [])
                .expect("empty authority certificate must be written");
            fs::write(output.join("deployment-authority.pub"), [])
                .expect("empty authority key must be written");
        }
        (Some(cert), Some(public_key)) => {
            copy_checked(
                &cert,
                &output.join("deployment-authority.der"),
                MAX_CERT_BYTES,
            );
            copy_checked(
                &public_key,
                &output.join("deployment-authority.pub"),
                PUBLIC_KEY_BYTES,
            );
            let key_len = fs::metadata(&public_key)
                .expect("deployment authority public key metadata must be readable")
                .len();
            assert_eq!(
                key_len, PUBLIC_KEY_BYTES as u64,
                "deployment authority public key must contain exactly 32 bytes"
            );
        }
        _ => panic!("both deployment authority environment variables must be set together"),
    }
}

fn configured_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn copy_checked(source: &Path, destination: &Path, max_bytes: usize) {
    println!("cargo:rerun-if-changed={}", source.display());
    let metadata = fs::metadata(source).expect("deployment authority file must be readable");
    assert!(
        metadata.is_file(),
        "deployment authority path must be a file"
    );
    assert!(
        metadata.len() > 0 && metadata.len() <= max_bytes as u64,
        "deployment authority file has an invalid size"
    );
    fs::copy(source, destination).expect("deployment authority file must be copied");
}
