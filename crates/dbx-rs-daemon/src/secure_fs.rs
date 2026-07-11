use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::DaemonError;

static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);

pub fn ensure_private_dir(path: &Path) -> Result<(), DaemonError> {
    fs::create_dir_all(path).map_err(|error| {
        DaemonError::io(
            "DBX-RS-FS-0001",
            "directory_create",
            "failed to create a private directory",
            &error,
        )
    })?;
    set_mode(path, 0o700)
}

pub fn read_limited(path: &Path, max_bytes: u64) -> Result<Vec<u8>, DaemonError> {
    reject_symlink(path)?;
    let file = File::open(path).map_err(|error| {
        DaemonError::io(
            "DBX-RS-FS-0002",
            "file_open",
            "failed to open a protected file",
            &error,
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        DaemonError::io(
            "DBX-RS-FS-0003",
            "file_metadata",
            "failed to inspect a protected file",
            &error,
        )
    })?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return Err(DaemonError::new(
            "DBX-RS-FS-0004",
            "configuration",
            "file_validate",
            "protected file has an invalid type or size",
            false,
            true,
        ));
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| {
        DaemonError::new(
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
            DaemonError::io(
                "DBX-RS-FS-0005",
                "file_read",
                "failed to read a protected file",
                &error,
            )
        })?;
    if bytes.len() as u64 > max_bytes {
        bytes.fill(0);
        return Err(DaemonError::new(
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

pub fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), DaemonError> {
    let parent = path.parent().ok_or_else(|| {
        DaemonError::new(
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
        DaemonError::io(
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

pub fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), DaemonError> {
    let parent = path.parent().ok_or_else(|| {
        DaemonError::new(
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
            DaemonError::new(
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
            DaemonError::io(
                "DBX-RS-FS-0009",
                "file_write",
                "failed to create an atomic staging file",
                &error,
            )
        })?;
        write_and_sync(&mut file, bytes)?;
        set_mode(&temp, mode)?;
        fs::rename(&temp, path).map_err(|error| {
            DaemonError::io(
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

fn write_and_sync(file: &mut File, bytes: &[u8]) -> Result<(), DaemonError> {
    file.write_all(bytes).map_err(|error| {
        DaemonError::io(
            "DBX-RS-FS-0011",
            "file_write",
            "failed to write a protected file",
            &error,
        )
    })?;
    file.sync_all().map_err(|error| {
        DaemonError::io(
            "DBX-RS-FS-0012",
            "file_sync",
            "failed to synchronize a protected file",
            &error,
        )
    })
}

fn reject_symlink(path: &Path) -> Result<(), DaemonError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        DaemonError::io(
            "DBX-RS-FS-0013",
            "file_metadata",
            "failed to inspect a protected path",
            &error,
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(DaemonError::new(
            "DBX-RS-FS-0014",
            "configuration",
            "file_validate",
            "protected file must not be a symbolic link",
            false,
            true,
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn set_create_mode(options: &mut OpenOptions, mode: u32) {
    use std::os::unix::fs::OpenOptionsExt;

    options.mode(mode);
}

#[cfg(not(unix))]
fn set_create_mode(_options: &mut OpenOptions, _mode: u32) {}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), DaemonError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|error| {
        DaemonError::io(
            "DBX-RS-FS-0015",
            "permissions",
            "failed to protect file permissions",
            &error,
        )
    })
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), DaemonError> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), DaemonError> {
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|error| {
            DaemonError::io(
                "DBX-RS-FS-0016",
                "directory_sync",
                "failed to synchronize a protected directory",
                &error,
            )
        })
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), DaemonError> {
    Ok(())
}
