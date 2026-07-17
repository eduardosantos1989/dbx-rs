#![forbid(unsafe_code)]

mod deployment;
mod error;
mod fs;
mod store;

pub use deployment::{
    AuthoritySigner, DeploymentAuthority, DeploymentIdentity, DeploymentImportPolicy,
    DeploymentImportResult, DeploymentReconcileSummary, deployment_authority_configured,
    embedded_deployment_authority, reconcile_deployment_directory,
    reconcile_embedded_deployment_directory, seal_deployment_secret, verify_deployment_envelope,
};
pub use error::SecureStoreError;
pub use fs::{atomic_write, ensure_private_dir, read_limited, read_private_limited, write_new};
pub use store::SecretStore;
