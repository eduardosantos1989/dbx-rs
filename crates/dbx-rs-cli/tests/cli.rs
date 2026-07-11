#![forbid(unsafe_code)]

use std::process::{Command, Output};

fn dbx_rs(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_dbx-rs"))
        .args(arguments)
        .output()
        .expect("dbx-rs must execute")
}

#[test]
fn version_flag_reports_binary_name_and_version() {
    let output = dbx_rs(&["--version"]);

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout must be UTF-8"),
        format!("dbx-rs {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn help_command_reports_usage() {
    let output = dbx_rs(&["help"]);
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");

    assert!(output.status.success());
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("dbx-rs help"));
    assert!(output.stderr.is_empty());
}
