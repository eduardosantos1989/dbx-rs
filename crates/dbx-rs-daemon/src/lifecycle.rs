use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::DaemonError;
use crate::secure_fs::{ensure_private_dir, read_limited};

#[derive(Debug)]
pub struct InstanceGuard {
    _file: File,
}

impl InstanceGuard {
    pub fn acquire(path: &Path) -> Result<Self, DaemonError> {
        let parent = path.parent().ok_or_else(|| {
            DaemonError::new(
                "DBX-RS-LIFE-0001",
                "configuration",
                "instance_lock",
                "instance lock path has no parent directory",
                false,
                true,
            )
        })?;
        ensure_private_dir(parent)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        set_private_mode(&mut options);
        let mut file = options.open(path).map_err(|error| {
            DaemonError::io(
                "DBX-RS-LIFE-0003",
                "instance_lock",
                "failed to open the instance lock",
                &error,
            )
        })?;
        file.try_lock().map_err(|_| {
            DaemonError::new(
                "DBX-RS-LIFE-0004",
                "configuration",
                "instance_lock",
                "another dbx-rs daemon instance already owns the lock",
                true,
                false,
            )
        })?;
        file.set_len(0).map_err(|error| {
            DaemonError::io(
                "DBX-RS-LIFE-0005",
                "instance_lock",
                "failed to update the instance lock",
                &error,
            )
        })?;
        file.seek(SeekFrom::Start(0)).map_err(|error| {
            DaemonError::io(
                "DBX-RS-LIFE-0006",
                "instance_lock",
                "failed to seek the instance lock",
                &error,
            )
        })?;
        writeln!(file, "{}", std::process::id()).map_err(|error| {
            DaemonError::io(
                "DBX-RS-LIFE-0007",
                "instance_lock",
                "failed to record the daemon process ID",
                &error,
            )
        })?;
        file.sync_data().map_err(|error| {
            DaemonError::io(
                "DBX-RS-LIFE-0008",
                "instance_lock",
                "failed to synchronize the instance lock",
                &error,
            )
        })?;
        Ok(Self { _file: file })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SplunkdIdentity {
    pid_file: PathBuf,
    pid: u32,
    process_start: Option<u64>,
}

impl SplunkdIdentity {
    pub fn capture(pid_file: &Path) -> Result<Self, DaemonError> {
        let pid = read_pid(pid_file)?;
        let process_start = process_start(pid)?;
        Ok(Self {
            pid_file: pid_file.to_path_buf(),
            pid,
            process_start,
        })
    }

    pub fn is_current(&self) -> bool {
        Self::capture(&self.pid_file).is_ok_and(|current| current == *self)
    }
}

fn read_pid(path: &Path) -> Result<u32, DaemonError> {
    let bytes = read_limited(path, 4_096)?;
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| invalid_pid())?
        .split_ascii_whitespace()
        .next()
        .ok_or_else(invalid_pid)?;
    let pid = value.parse::<u32>().map_err(|_| invalid_pid())?;
    if pid == 0 {
        return Err(invalid_pid());
    }
    Ok(pid)
}

const fn invalid_pid() -> DaemonError {
    DaemonError::new(
        "DBX-RS-LIFE-0009",
        "configuration",
        "splunkd_pid",
        "splunkd PID file is invalid",
        true,
        true,
    )
}

#[cfg(unix)]
fn process_start(pid: u32) -> Result<Option<u64>, DaemonError> {
    let process_stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|error| {
        DaemonError::io(
            "DBX-RS-LIFE-0010",
            "splunkd_process",
            "splunkd process is not available",
            &error,
        )
    })?;
    let close = process_stat.rfind(')').ok_or_else(|| {
        DaemonError::new(
            "DBX-RS-LIFE-0011",
            "protocol",
            "splunkd_process",
            "process identity data is invalid",
            true,
            false,
        )
    })?;
    let process_start_ticks = process_stat[close + 1..]
        .split_whitespace()
        .nth(19)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| {
            DaemonError::new(
                "DBX-RS-LIFE-0011",
                "protocol",
                "splunkd_process",
                "process identity data is invalid",
                true,
                false,
            )
        })?;
    Ok(Some(process_start_ticks))
}

#[cfg(not(unix))]
fn process_start(_pid: u32) -> Result<Option<u64>, DaemonError> {
    Ok(None)
}

pub async fn shutdown_signal() -> Result<(), DaemonError> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate = signal(SignalKind::terminate()).map_err(|_| signal_error())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.map_err(|_| signal_error()),
            value = terminate.recv() => value.map_or_else(|| Err(signal_error()), |()| Ok(())),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.map_err(|_| signal_error())
    }
}

const fn signal_error() -> DaemonError {
    DaemonError::new(
        "DBX-RS-LIFE-0012",
        "internal",
        "signal_handler",
        "failed to install or receive a shutdown signal",
        false,
        false,
    )
}

#[cfg(unix)]
fn set_private_mode(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_private_mode(_options: &mut OpenOptions) {}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    fn test_file(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "dbx-rs-lifecycle-{label}-{}-{}",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn singleton_lock_rejects_a_second_owner() {
        let root = test_file("lock");
        let path = root.join("daemon.lock");
        let first = InstanceGuard::acquire(&path).expect("first owner must acquire lock");
        let error = InstanceGuard::acquire(&path).expect_err("second owner must be rejected");

        assert_eq!(error.code(), "DBX-RS-LIFE-0004");
        drop(first);
        fs::remove_dir_all(root).expect("fixture must be removed");
    }

    #[test]
    fn pid_identity_detects_file_change() {
        let path = test_file("pid");
        fs::write(&path, format!("{}\n", std::process::id())).expect("PID fixture must be written");
        let identity = SplunkdIdentity::capture(&path).expect("identity must be captured");
        assert!(identity.is_current());
        fs::write(&path, "1\n").expect("PID fixture must change");
        assert!(!identity.is_current());
        fs::remove_file(path).expect("fixture must be removed");
    }
}
