//! Die Operator-Kommandos akzeptieren keine Ersatzidentität oder Schlüsseldatei.

mod support;

use std::{fs, process::Command};

fn run(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_einsatzarchiv"))
        .args(arguments)
        .output()
        .expect("CLI starts")
}

#[test]
fn operator_actions_without_native_providers_refuse_without_mutating_local_files() {
    let directory = support::temp_dir("operator-provider-boundary");
    let anchor = directory.path().join("external-anchor.etb");
    let original = b"the existing independently supplied anchor";
    fs::write(&anchor, original).unwrap();
    for action in ["provision", "verify-session", "revoke"] {
        let output = run(&[
            "--trust-anchor",
            anchor.to_str().unwrap(),
            "operator",
            action,
        ]);
        assert_eq!(output.status.code(), Some(21), "action {action}");
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("EA-OPERATOR-NATIVE-PROVIDER-UNAVAILABLE"));
        assert!(!stderr.contains(anchor.to_str().unwrap()));
        assert_eq!(fs::read(&anchor).unwrap(), original);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}

#[test]
fn missing_provider_does_not_create_an_anchor_or_a_profile() {
    let directory = support::temp_dir("operator-no-profile");
    let anchor = directory.path().join("absent-anchor.etb");
    let output = run(&[
        "--trust-anchor",
        anchor.to_str().unwrap(),
        "operator",
        "provision",
    ]);
    assert_eq!(output.status.code(), Some(21));
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn each_operator_action_requires_an_external_anchor_argument() {
    for action in ["provision", "verify-session", "revoke"] {
        let output = run(&["operator", action]);
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("--trust-anchor"));
    }
}

#[test]
fn operator_actions_reject_free_identity_text_and_key_or_output_paths() {
    for extra in [
        vec!["freely-entered-person"],
        vec!["--key", "instance-key-file"],
        vec!["--output", "plaintext-profile"],
        vec!["--include-runtime-metadata"],
        vec!["--report-signing-key", "signer"],
    ] {
        for action in ["provision", "verify-session", "revoke"] {
            let mut arguments = vec!["--trust-anchor", "anchor", "operator", action];
            arguments.extend(extra.iter().copied());
            let output = run(&arguments);
            assert_eq!(output.status.code(), Some(2), "{arguments:?}");
            assert!(output.stdout.is_empty());
        }
    }
}

#[test]
fn operator_subcommands_are_closed() {
    for arguments in [
        vec!["--trust-anchor", "anchor", "operator"],
        vec!["--trust-anchor", "anchor", "operator", "restore"],
        vec!["--trust-anchor", "anchor", "operator", "login-as"],
    ] {
        assert_eq!(run(&arguments).status.code(), Some(2));
    }
}

#[test]
fn invalid_subcommands_report_command_specific_choices() {
    for (command, action, expected_diagnostic) in [
        (
            "organization",
            "iniit",
            "einsatzarchiv: unknown organization subcommand iniit; expected init",
        ),
        (
            "operator",
            "restore",
            "einsatzarchiv: unknown operator subcommand restore; expected provision, verify-session or revoke",
        ),
    ] {
        let output = run(&["--trust-anchor", "anchor", command, action]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(stderr.lines().next(), Some(expected_diagnostic));
    }
}

#[test]
fn json_format_cannot_turn_an_unavailable_action_into_success() {
    let output = run(&[
        "--trust-anchor",
        "anchor",
        "--format",
        "json",
        "operator",
        "verify-session",
    ]);
    assert_eq!(output.status.code(), Some(21));
    assert!(output.stdout.is_empty());
}
