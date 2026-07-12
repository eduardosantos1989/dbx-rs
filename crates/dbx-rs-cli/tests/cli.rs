#![forbid(unsafe_code)]

use std::path::PathBuf;
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
fn packaged_defaults_validate() {
    let app_home = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../packaging/splunk/TA-dbx-rs")
        .canonicalize()
        .expect("packaged app must exist");
    let splunk_home = std::env::temp_dir().join("dbx-rs-cli-validation-home");
    let output = dbx_rs(&[
        "config",
        "validate",
        "--app-home",
        app_home.to_str().expect("app path must be UTF-8"),
        "--splunk-home",
        splunk_home.to_str().expect("Splunk path must be UTF-8"),
    ]);
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");

    assert!(output.status.success());
    assert!(stdout.contains("configuration_valid=true"));
    assert!(stdout.contains("inputs_total=0"));
    assert!(output.stderr.is_empty());
}

#[test]
fn named_control_errors_are_structured_json() {
    let app_home = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../packaging/splunk/TA-dbx-rs")
        .canonicalize()
        .expect("packaged app must exist");
    let splunk_home = std::env::temp_dir().join("dbx-rs-cli-control-home");
    let output = dbx_rs(&[
        "input",
        "validate",
        "missing_input",
        "--app-home",
        app_home.to_str().expect("app path must be UTF-8"),
        "--splunk-home",
        splunk_home.to_str().expect("Splunk path must be UTF-8"),
    ]);
    let error: serde_json::Value =
        serde_json::from_slice(&output.stderr).expect("stderr must contain one JSON error");

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(error["operation"], "input_validate");
    assert_eq!(error["input"], "missing_input");
    assert_eq!(error["code"], "DBX-RS-CONTROL-0001");
}
