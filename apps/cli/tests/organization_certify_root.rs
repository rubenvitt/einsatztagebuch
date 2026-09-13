//! Installed CLI process witnesses which never reach user key access.
#[path = "support/mod.rs"]
mod support;
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_einsatzarchiv"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn certify_root_missing_state_or_unsupported_lease_refuses_without_beginning() {
    let directory = support::temp_dir("certify-root-cli-missing");
    let anchor = directory.path().join("new-anchor.etb");
    let result = run(&[
        "--trust-anchor",
        anchor.to_str().unwrap(),
        "organization",
        "certify-root",
        "--initial-registry-version",
        "7",
    ]);
    // Explicit step 2 cannot use init's legacy unleased platform fallback.
    let expected = if cfg!(any(
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        all(
            target_os = "linux",
            target_env = "gnu",
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )) {
        12
    } else {
        20
    };
    assert_eq!(
        result.status.code(),
        Some(expected),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stdout.is_empty());
    assert!(!anchor.try_exists().unwrap());
    let mut state = anchor.as_os_str().to_os_string();
    state.push(".bootstrap-state");
    assert!(!std::path::PathBuf::from(state).try_exists().unwrap());
}

#[test]
fn certify_root_requires_explicit_version_and_rejects_foreign_switches() {
    let prefix = ["--trust-anchor", "anchor", "organization", "certify-root"];
    for tail in [
        vec![],
        vec!["--initial-registry-version"],
        vec!["--initial-registry-version", "18446744073709551616"],
        vec!["--initial-registry-version", "NaN"],
        vec![
            "--initial-registry-version",
            "7",
            "--initial-registry-version",
            "7",
        ],
        vec!["--initial-registry-version", "7", "--key", "secret"],
        vec![
            "--initial-registry-version",
            "7",
            "--operator-config",
            "config",
        ],
        vec!["--initial-registry-version", "7", "--output", "elsewhere"],
    ] {
        let mut args = prefix.to_vec();
        args.extend(tail);
        let result = run(&args);
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
    }
    for (command, positional) in [("organization", "init"), ("verify", "archive")] {
        let result = run(&[
            "--trust-anchor",
            "anchor",
            command,
            positional,
            "--initial-registry-version",
            "7",
        ]);
        assert_eq!(result.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&result.stderr).contains("--initial-registry-version"));
    }
}

#[test]
fn certify_root_json_and_occupied_anchor_refuse_before_state_or_provider_effects() {
    let directory = support::temp_dir("certify-root-cli-output");
    let anchor = directory.path().join("future.etb");
    let args = [
        "--trust-anchor",
        anchor.to_str().unwrap(),
        "organization",
        "certify-root",
        "--initial-registry-version",
        "0",
    ];
    let mut json = args.to_vec();
    json.extend(["--format", "json"]);
    let result = run(&json);
    assert_eq!(result.status.code(), Some(21));
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("organization certify-root"));
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    std::fs::write(&anchor, b"existing independent anchor").unwrap();
    let result = run(&args);
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    assert_eq!(
        std::fs::read(&anchor).unwrap(),
        b"existing independent anchor"
    );
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn certify_root_help_exposes_explicit_scope_without_changing_init() {
    let result = run(&[]);
    assert_eq!(result.status.code(), Some(2));
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(text.contains("einsatzarchiv --trust-anchor <new-file> organization certify-root --initial-registry-version <u64>"));
    assert!(text.contains("organization init begins or resumes the ceremony"));
}
