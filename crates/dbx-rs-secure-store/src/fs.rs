use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::SecureStoreError;

static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);

/// Creates a private directory tree and applies owner-only permissions.
///
/// # Errors
///
/// Returns an error when the directory cannot be created or protected.
pub fn ensure_private_dir(path: &Path) -> Result<(), SecureStoreError> {
    reject_existing_ancestor_symlinks(path)?;
    fs::create_dir_all(path).map_err(|error| {
        SecureStoreError::io(
            "DBX-RS-FS-0001",
            "directory_create",
            "failed to create a private directory",
            &error,
        )
    })?;
    reject_existing_ancestor_symlinks(path)?;
    set_mode(path, 0o700)
}

pub(crate) fn validate_private_dir(path: &Path) -> Result<(), SecureStoreError> {
    reject_existing_ancestor_symlinks(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        SecureStoreError::io(
            "DBX-RS-FS-0018",
            "directory_validate",
            "failed to inspect a private directory",
            &error,
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SecureStoreError::new(
            "DBX-RS-FS-0019",
            "configuration",
            "directory_validate",
            "private directory has an invalid type",
            false,
            true,
        ));
    }
    validate_private_mode(path, &metadata)
}

/// Reads one regular, non-symlink file up to a fixed byte limit.
///
/// # Errors
///
/// Returns an error when the path is a symlink, is not a regular file, exceeds the limit, or
/// cannot be inspected or read.
pub fn read_limited(path: &Path, max_bytes: u64) -> Result<Vec<u8>, SecureStoreError> {
    read_limited_inner(path, max_bytes, false)
}

/// Reads one owner-protected regular file up to a fixed byte limit.
///
/// On Unix, group or other permission bits are rejected. On Windows, inherited access is removed
/// and the running account is granted full control before the file is read.
///
/// # Errors
///
/// Returns an error when the file is not regular, is a symlink, is too large, has insecure
/// permissions, or cannot be inspected or read.
pub fn read_private_limited(path: &Path, max_bytes: u64) -> Result<Vec<u8>, SecureStoreError> {
    read_limited_inner(path, max_bytes, true)
}

fn read_limited_inner(
    path: &Path,
    max_bytes: u64,
    require_private: bool,
) -> Result<Vec<u8>, SecureStoreError> {
    reject_existing_ancestor_symlinks(path)?;
    let file = File::open(path).map_err(|error| {
        SecureStoreError::io(
            "DBX-RS-FS-0002",
            "file_open",
            "failed to open a protected file",
            &error,
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        SecureStoreError::io(
            "DBX-RS-FS-0003",
            "file_metadata",
            "failed to inspect a protected file",
            &error,
        )
    })?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return Err(SecureStoreError::new(
            "DBX-RS-FS-0004",
            "configuration",
            "file_validate",
            "protected file has an invalid type or size",
            false,
            true,
        ));
    }
    if require_private {
        validate_private_file_mode(path, &metadata)?;
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| {
        SecureStoreError::new(
            "DBX-RS-FS-0017",
            "configuration",
            "file_validate",
            "protected file is too large for this platform",
            false,
            true,
        )
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            SecureStoreError::io(
                "DBX-RS-FS-0005",
                "file_read",
                "failed to read a protected file",
                &error,
            )
        })?;
    if bytes.len() as u64 > max_bytes {
        bytes.fill(0);
        return Err(SecureStoreError::new(
            "DBX-RS-FS-0004",
            "configuration",
            "file_validate",
            "protected file has an invalid type or size",
            false,
            true,
        ));
    }
    Ok(bytes)
}

/// Creates and synchronizes a new protected file without replacing an existing path.
///
/// # Errors
///
/// Returns an error when the parent cannot be protected or the file cannot be created, written,
/// permissioned, or synchronized.
pub fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), SecureStoreError> {
    let parent = path.parent().ok_or_else(|| {
        SecureStoreError::new(
            "DBX-RS-FS-0006",
            "configuration",
            "file_create",
            "protected file has no parent directory",
            false,
            true,
        )
    })?;
    ensure_private_dir(parent)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    set_create_mode(&mut options, mode);
    let mut file = options.open(path).map_err(|error| {
        SecureStoreError::io(
            "DBX-RS-FS-0007",
            "file_create",
            "failed to create a protected file",
            &error,
        )
    })?;
    write_and_sync(&mut file, bytes)?;
    set_mode(path, mode)?;
    sync_parent(parent)
}

/// Atomically replaces a protected file through a synchronized sibling staging file.
///
/// # Errors
///
/// Returns an error when the parent cannot be protected or the staging file cannot be created,
/// written, synchronized, permissioned, or published.
pub fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), SecureStoreError> {
    let parent = path.parent().ok_or_else(|| {
        SecureStoreError::new(
            "DBX-RS-FS-0006",
            "configuration",
            "file_write",
            "protected file has no parent directory",
            false,
            true,
        )
    })?;
    ensure_private_dir(parent)?;
    let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            SecureStoreError::new(
                "DBX-RS-FS-0008",
                "configuration",
                "file_write",
                "protected file name is invalid",
                false,
                true,
            )
        })?;
    let temp = parent.join(format!(
        ".{file_name}.{}.{sequence}.tmp",
        std::process::id()
    ));

    let write_result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        set_create_mode(&mut options, mode);
        let mut file = options.open(&temp).map_err(|error| {
            SecureStoreError::io(
                "DBX-RS-FS-0009",
                "file_write",
                "failed to create an atomic staging file",
                &error,
            )
        })?;
        write_and_sync(&mut file, bytes)?;
        set_mode(&temp, mode)?;
        fs::rename(&temp, path).map_err(|error| {
            SecureStoreError::io(
                "DBX-RS-FS-0010",
                "file_publish",
                "failed to publish an atomic file",
                &error,
            )
        })?;
        sync_parent(parent)
    })();

    if write_result.is_err() {
        let _ignored = fs::remove_file(&temp);
    }
    write_result
}

fn write_and_sync(file: &mut File, bytes: &[u8]) -> Result<(), SecureStoreError> {
    file.write_all(bytes).map_err(|error| {
        SecureStoreError::io(
            "DBX-RS-FS-0011",
            "file_write",
            "failed to write a protected file",
            &error,
        )
    })?;
    file.sync_all().map_err(|error| {
        SecureStoreError::io(
            "DBX-RS-FS-0012",
            "file_sync",
            "failed to synchronize a protected file",
            &error,
        )
    })
}

fn reject_existing_ancestor_symlinks(path: &Path) -> Result<(), SecureStoreError> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(SecureStoreError::new(
                    "DBX-RS-FS-0014",
                    "configuration",
                    "path_validate",
                    "protected paths must not contain symbolic links",
                    false,
                    true,
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(SecureStoreError::io(
                    "DBX-RS-FS-0013",
                    "path_validate",
                    "failed to inspect a protected path",
                    &error,
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_create_mode(options: &mut OpenOptions, mode: u32) {
    use std::os::unix::fs::OpenOptionsExt;

    options.mode(mode);
}

#[cfg(all(not(unix), not(windows)))]
fn set_create_mode(_options: &mut OpenOptions, _mode: u32) {}

#[cfg(windows)]
fn set_create_mode(_options: &mut OpenOptions, _mode: u32) {}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), SecureStoreError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|error| {
        SecureStoreError::io(
            "DBX-RS-FS-0015",
            "permissions",
            "failed to protect file permissions",
            &error,
        )
    })
}

#[cfg(windows)]
fn set_mode(path: &Path, _mode: u32) -> Result<(), SecureStoreError> {
    protect_windows_path(path, path.is_dir())
}

#[cfg(all(not(unix), not(windows)))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), SecureStoreError> {
    Err(unsupported_permissions())
}

#[cfg(unix)]
fn validate_private_mode(_path: &Path, metadata: &fs::Metadata) -> Result<(), SecureStoreError> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(SecureStoreError::new(
            "DBX-RS-FS-0020",
            "configuration",
            "permissions",
            "private directory permissions are too broad",
            false,
            true,
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn validate_private_mode(path: &Path, _metadata: &fs::Metadata) -> Result<(), SecureStoreError> {
    protect_windows_path(path, true)
}

#[cfg(all(not(unix), not(windows)))]
fn validate_private_mode(_path: &Path, _metadata: &fs::Metadata) -> Result<(), SecureStoreError> {
    Err(unsupported_permissions())
}

#[cfg(unix)]
fn validate_private_file_mode(
    _path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), SecureStoreError> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(SecureStoreError::new(
            "DBX-RS-FS-0021",
            "configuration",
            "permissions",
            "private file permissions are too broad",
            false,
            true,
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn validate_private_file_mode(
    path: &Path,
    _metadata: &fs::Metadata,
) -> Result<(), SecureStoreError> {
    protect_windows_path(path, false)
}

#[cfg(all(not(unix), not(windows)))]
fn validate_private_file_mode(
    _path: &Path,
    _metadata: &fs::Metadata,
) -> Result<(), SecureStoreError> {
    Err(unsupported_permissions())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), SecureStoreError> {
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|error| {
            SecureStoreError::io(
                "DBX-RS-FS-0016",
                "directory_sync",
                "failed to synchronize a protected directory",
                &error,
            )
        })
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), SecureStoreError> {
    Ok(())
}

#[cfg(windows)]
fn protect_windows_path(path: &Path, directory: bool) -> Result<(), SecureStoreError> {
    use std::process::{Command, Stdio};

    let output = Command::new("whoami").output().map_err(|error| {
        SecureStoreError::io(
            "DBX-RS-FS-0022",
            "permissions",
            "failed to identify the Windows service account",
            &error,
        )
    })?;
    if !output.status.success() || output.stdout.len() > 512 {
        return Err(windows_permissions_error());
    }
    let account = String::from_utf8(output.stdout).map_err(|_| windows_permissions_error())?;
    let account = account.trim_matches(['\r', '\n']);
    if account.is_empty()
        || account.len() > 256
        || account.chars().any(|character| character.is_control())
    {
        return Err(windows_permissions_error());
    }
    let grant = if directory {
        format!("{account}:(OI)(CI)F")
    } else {
        format!("{account}:F")
    };
    let status = Command::new("icacls")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(grant)
        .arg("/Q")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| {
            SecureStoreError::io(
                "DBX-RS-FS-0023",
                "permissions",
                "failed to apply Windows private-path permissions",
                &error,
            )
        })?;
    if !status.success() {
        return Err(windows_permissions_error());
    }
    Ok(())
}

#[cfg(windows)]
const fn windows_permissions_error() -> SecureStoreError {
    SecureStoreError::new(
        "DBX-RS-FS-0024",
        "configuration",
        "permissions",
        "Windows private-path permissions could not be enforced",
        false,
        true,
    )
}

#[cfg(all(not(unix), not(windows)))]
const fn unsupported_permissions() -> SecureStoreError {
    SecureStoreError::new(
        "DBX-RS-FS-0025",
        "configuration",
        "permissions",
        "private-path permissions are unsupported on this platform",
        false,
        true,
    )
}
