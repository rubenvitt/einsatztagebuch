use std::{
    collections::BTreeSet,
    env, fs, io,
    path::{Path, PathBuf},
    process::{self, Command},
};

#[derive(Debug, PartialEq, Eq)]
struct FuzzSettings {
    nightly: String,
    cargo_fuzz: String,
}

#[derive(Debug, PartialEq, Eq)]
struct FuzzArgs {
    smoke_seconds: u64,
    target: Option<String>,
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn verify_quick_commands() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        ("cargo", vec!["fmt", "--all", "--check"]),
        (
            "cargo",
            vec![
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--locked",
                "--",
                "-D",
                "warnings",
            ],
        ),
        (
            "cargo",
            vec!["test", "--workspace", "--all-targets", "--locked"],
        ),
    ]
}

fn parse_fuzz_settings(input: &str) -> Result<FuzzSettings, String> {
    let document: toml::Value = input
        .parse()
        .map_err(|error| format!("invalid fuzz toolchain TOML: {error}"))?;
    let nightly = document
        .get("nightly")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| "missing nightly pin".to_owned())?;
    if !is_dated_nightly(nightly) {
        return Err("nightly must be an exact nightly-YYYY-MM-DD pin".to_owned());
    }
    let cargo_fuzz = document
        .get("cargo-fuzz")
        .and_then(toml::Value::as_str)
        .filter(|version| !version.is_empty())
        .ok_or_else(|| "missing cargo-fuzz pin".to_owned())?;

    Ok(FuzzSettings {
        nightly: nightly.to_owned(),
        cargo_fuzz: cargo_fuzz.to_owned(),
    })
}

fn is_dated_nightly(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 18
        && value.starts_with("nightly-")
        && bytes[12] == b'-'
        && bytes[15] == b'-'
        && bytes[8..12].iter().all(u8::is_ascii_digit)
        && bytes[13..15].iter().all(u8::is_ascii_digit)
        && bytes[16..18].iter().all(u8::is_ascii_digit)
}

fn parse_fuzz_args<I, S>(args: I) -> Result<FuzzArgs, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut smoke_seconds = 60;
    let mut target = None;
    let mut args = args.into_iter();
    while let Some(argument) = args.next() {
        match argument.as_ref() {
            "--smoke-seconds" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--smoke-seconds requires a value".to_owned())?;
                smoke_seconds = value
                    .as_ref()
                    .parse()
                    .map_err(|_| "--smoke-seconds must be a positive integer".to_owned())?;
                if smoke_seconds == 0 {
                    return Err("--smoke-seconds must be greater than zero".to_owned());
                }
            }
            "--target" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--target requires a value".to_owned())?;
                if value.as_ref().is_empty() {
                    return Err("--target must not be empty".to_owned());
                }
                target = Some(value.as_ref().to_owned());
            }
            unknown => return Err(format!("unknown test-fuzz argument: {unknown}")),
        }
    }

    Ok(FuzzArgs {
        smoke_seconds,
        target,
    })
}

fn parse_fuzz_targets(input: &str) -> Result<Vec<String>, String> {
    let document: toml::Value = input
        .parse()
        .map_err(|error| format!("invalid fuzz manifest: {error}"))?;
    let bins = document
        .get("bin")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| "fuzz manifest declares no [[bin]] targets".to_owned())?;
    let mut unique = BTreeSet::new();
    for bin in bins {
        let name = bin
            .get("name")
            .and_then(toml::Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| "fuzz target is missing a name".to_owned())?;
        if !unique.insert(name.to_owned()) {
            return Err(format!("duplicate fuzz target: {name}"));
        }
    }
    if unique.is_empty() {
        return Err("fuzz manifest declares no targets".to_owned());
    }
    Ok(unique.into_iter().collect())
}

fn fuzz_command_args(nightly: &str, target: &str, smoke_seconds: u64) -> Vec<String> {
    vec![
        format!("+{nightly}"),
        "fuzz".to_owned(),
        "run".to_owned(),
        "--fuzz-dir".to_owned(),
        "fuzz".to_owned(),
        target.to_owned(),
        "--".to_owned(),
        format!("-max_total_time={smoke_seconds}"),
    ]
}

fn fuzz_lock_validation_args() -> Vec<&'static str> {
    vec![
        "metadata",
        "--manifest-path",
        "fuzz/Cargo.toml",
        "--locked",
        "--format-version",
        "1",
        "--no-deps",
    ]
}

fn run_process(root: &Path, program: &str, args: &[impl AsRef<std::ffi::OsStr>]) -> io::Result<()> {
    let status = Command::new(program)
        .args(args)
        .current_dir(root)
        .status()?;
    if !status.success() {
        process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

fn run_fuzz(root: &Path, args: impl IntoIterator<Item = String>) -> Result<(), String> {
    let settings_path = root.join(".cargo/fuzz-toolchain.toml");
    let settings = parse_fuzz_settings(
        &fs::read_to_string(&settings_path)
            .map_err(|error| format!("failed to read {}: {error}", settings_path.display()))?,
    )?;
    let args = parse_fuzz_args(args)?;
    let fuzz_manifest = root.join("fuzz/Cargo.toml");
    let fuzz_lock = root.join("fuzz/Cargo.lock");
    if !fuzz_lock.is_file() {
        return Err(format!(
            "missing committed fuzz lockfile: {}",
            fuzz_lock.display()
        ));
    }
    run_process(root, "cargo", &fuzz_lock_validation_args())
        .map_err(|error| format!("failed to validate the fuzz lockfile: {error}"))?;
    let available_targets = parse_fuzz_targets(
        &fs::read_to_string(&fuzz_manifest)
            .map_err(|error| format!("failed to read {}: {error}", fuzz_manifest.display()))?,
    )?;
    let targets = if let Some(target) = args.target {
        if !available_targets.contains(&target) {
            return Err(format!("unknown fuzz target: {target}"));
        }
        vec![target]
    } else {
        available_targets
    };

    let version_output = Command::new("cargo")
        .args([
            format!("+{}", settings.nightly),
            "fuzz".to_owned(),
            "--version".to_owned(),
        ])
        .current_dir(root)
        .output()
        .map_err(|error| format!("failed to invoke pinned cargo-fuzz: {error}"))?;
    if !version_output.status.success() {
        return Err("pinned cargo-fuzz invocation failed".to_owned());
    }
    let installed_version = String::from_utf8_lossy(&version_output.stdout);
    let expected_version = format!("cargo-fuzz {}", settings.cargo_fuzz);
    if installed_version.trim() != expected_version {
        return Err(format!(
            "cargo-fuzz version mismatch: expected {expected_version}, got {}",
            installed_version.trim()
        ));
    }

    for target in targets {
        let command_args = fuzz_command_args(&settings.nightly, &target, args.smoke_seconds);
        run_process(root, "cargo", &command_args)
            .map_err(|error| format!("failed to invoke cargo-fuzz: {error}"))?;
    }
    Ok(())
}

fn run_workspace_tests(root: &Path) -> io::Result<()> {
    run_process(
        root,
        "cargo",
        &["test", "--workspace", "--all-targets", "--locked"],
    )
}

fn validate_cddl_document(name: &str, input: &str) -> Result<(), String> {
    cddl::parser::cddl_from_str(input, false)
        .map(|_| ())
        .map_err(|error| format!("invalid CDDL {name}: {error}"))
}

fn compile_json_schema(name: &str, input: &str) -> Result<jsonschema::Validator, String> {
    let schema: serde_json::Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid JSON schema {name}: {error}"))?;
    jsonschema::meta::validate(&schema)
        .map_err(|error| format!("invalid JSON schema {name}: {error}"))?;
    require_closed_object_schemas(name, &schema, "#")?;
    jsonschema::validator_for(&schema)
        .map_err(|error| format!("failed to compile JSON schema {name}: {error}"))
}

fn validate_json_schema_document(name: &str, input: &str) -> Result<(), String> {
    compile_json_schema(name, input).map(|_| ())
}

fn validate_addendum_review(input: &str) -> Result<(), String> {
    let normalized = input
        .replace('*', "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for requirement in [
        "normativ für v0.1",
        "darf kein dort bereits festgelegtes Feld",
        "vor Task 3 akzeptiert",
    ] {
        if !normalized.contains(requirement) {
            return Err(format!("wire-format addendum is missing: {requirement}"));
        }
    }
    let table = input
        .split_once("## Feld-zu-Design-Review")
        .map(|(_, remainder)| remainder)
        .and_then(|remainder| remainder.split_once("**Review-Ergebnis:**"))
        .map(|(table, _)| table)
        .ok_or_else(|| "wire-format addendum review table is missing".to_owned())?;
    let mut reviewed_rows = 0;
    for line in table.lines().filter(|line| line.trim().starts_with('|')) {
        let cells = line
            .split('|')
            .map(str::trim)
            .filter(|cell| !cell.is_empty())
            .collect::<Vec<_>>();
        if cells.len() != 3 || cells[0] == "Artefakt / Felder" || cells[0].starts_with("---") {
            continue;
        }
        reviewed_rows += 1;
        if cells[2] != "bestätigt" {
            return Err(format!("unresolved review row: {line}"));
        }
    }
    if reviewed_rows == 0 {
        return Err("wire-format addendum review table has no field mappings".to_owned());
    }
    if !normalized.contains("Review-Ergebnis: keine ungelöste Zeile und kein Widerspruch") {
        return Err("wire-format addendum lacks a resolved review result".to_owned());
    }
    Ok(())
}

fn require_closed_object_schemas(
    name: &str,
    value: &serde_json::Value,
    location: &str,
) -> Result<(), String> {
    match value {
        serde_json::Value::Object(object) => {
            if object.get("type").and_then(serde_json::Value::as_str) == Some("object")
                && object.get("additionalProperties") != Some(&serde_json::Value::Bool(false))
            {
                return Err(format!(
                    "JSON schema {name} object at {location} must set additionalProperties to false"
                ));
            }
            for (key, child) in object {
                require_closed_object_schemas(name, child, &format!("{location}/{key}"))?;
            }
        }
        serde_json::Value::Array(array) => {
            for (index, child) in array.iter().enumerate() {
                require_closed_object_schemas(name, child, &format!("{location}/{index}"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_schemas(root: &Path) -> Result<(), String> {
    let archive_paths = [
        "schemas/archive/v1/archive.cddl",
        "schemas/archive/v1/trust.cddl",
        "schemas/archive/v1/evidence.cddl",
    ];
    let mut archive_bundle = String::new();
    for relative in archive_paths {
        let path = root.join(relative);
        let input = fs::read_to_string(&path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        validate_cddl_document(relative, &input)?;
        archive_bundle.push_str(&input);
        archive_bundle.push('\n');
    }
    validate_cddl_document("combined archive CDDL", &archive_bundle)?;

    let audit_path = "schemas/reports/v1/local-audit.cddl";
    let audit = fs::read_to_string(root.join(audit_path))
        .map_err(|error| format!("failed to read {audit_path}: {error}"))?;
    validate_cddl_document(audit_path, &audit)?;

    for relative in [
        "schemas/reports/v1/verification-report.schema.json",
        "schemas/reports/v1/key-inventory.schema.json",
    ] {
        let path = root.join(relative);
        let input = fs::read_to_string(&path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        validate_json_schema_document(relative, &input)?;
    }
    let addendum_path =
        root.join("docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-wire-format-addendum.md");
    let addendum = fs::read_to_string(&addendum_path)
        .map_err(|error| format!("failed to read {}: {error}", addendum_path.display()))?;
    validate_addendum_review(&addendum)?;
    println!("validated 4 CDDL and 2 JSON schemas");
    Ok(())
}

fn run() -> Result<(), String> {
    let root = workspace_root();
    let mut args = env::args().skip(1);
    let gate = args
        .next()
        .ok_or_else(|| "usage: xtask <gate> [gate options]".to_owned())?;
    match gate.as_str() {
        "verify-quick" => {
            for (program, command_args) in verify_quick_commands() {
                run_process(&root, program, &command_args)
                    .map_err(|error| format!("failed to invoke {program}: {error}"))?;
            }
            Ok(())
        }
        "test-core" | "test-golden" | "test-property" | "test-recovery" => {
            if args.next().is_some() {
                return Err(format!("{gate} does not accept arguments"));
            }
            run_workspace_tests(&root)
                .map_err(|error| format!("failed to invoke workspace tests: {error}"))
        }
        "test-fuzz" => run_fuzz(&root, args),
        "validate-schemas" => {
            if args.next().is_some() {
                return Err("validate-schemas does not accept arguments".to_owned());
            }
            validate_schemas(&root)
        }
        _ => Err(format!("unknown gate: {gate}")),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("xtask: {error}");
        process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn schema_validation_rejects_malformed_cddl() {
        let error = super::validate_cddl_document("broken.cddl", "root = [")
            .expect_err("malformed CDDL must fail closed");

        assert!(error.contains("broken.cddl"));
    }

    #[test]
    fn schema_validation_rejects_malformed_json_schema() {
        let error = super::validate_json_schema_document("broken.schema.json", "{")
            .expect_err("malformed JSON Schema must fail closed");

        assert!(error.contains("broken.schema.json"));
    }

    #[test]
    fn report_schema_rejects_an_unknown_property() {
        let schema = r#"{
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {"schemaId": {"const": "example/v1"}},
            "required": ["schemaId"],
            "additionalProperties": false
        }"#;
        let instance = serde_json::json!({"schemaId": "example/v1", "unknown": true});

        let validator = super::compile_json_schema("example.schema.json", schema).unwrap();
        assert!(!validator.is_valid(&instance));
    }

    #[test]
    fn addendum_review_rejects_an_unresolved_mapping_row() {
        let addendum = r#"normativ für v0.1
darf kein dort bereits festgelegtes Feld überschreiben
vor Task 3 akzeptiert
## Feld-zu-Design-Review
| Artefakt / Felder | Designquelle | Status |
|---|---|---|
| checkpoint | §15.2 | ungelöst |
**Review-Ergebnis:** keine ungelöste Zeile
"#;

        let error = super::validate_addendum_review(addendum)
            .expect_err("unresolved review rows must fail closed");
        assert!(error.contains("unresolved review row"));
    }

    #[test]
    fn verify_quick_uses_the_required_locked_commands() {
        assert_eq!(
            super::verify_quick_commands(),
            vec![
                ("cargo", vec!["fmt", "--all", "--check"]),
                (
                    "cargo",
                    vec![
                        "clippy",
                        "--workspace",
                        "--all-targets",
                        "--all-features",
                        "--locked",
                        "--",
                        "-D",
                        "warnings",
                    ],
                ),
                (
                    "cargo",
                    vec!["test", "--workspace", "--all-targets", "--locked"],
                ),
            ]
        );
    }

    #[test]
    fn fuzz_settings_require_exact_committed_pins() {
        let settings = super::parse_fuzz_settings(
            r#"nightly = "nightly-2026-08-13"
cargo-fuzz = "0.13.2"
"#,
        )
        .unwrap();

        assert_eq!(settings.nightly, "nightly-2026-08-13");
        assert_eq!(settings.cargo_fuzz, "0.13.2");
    }

    #[test]
    fn fuzz_settings_reject_an_ambient_nightly_name() {
        let error = super::parse_fuzz_settings(
            r#"nightly = "nightly"
cargo-fuzz = "0.13.2"
"#,
        )
        .unwrap_err();

        assert_eq!(error, "nightly must be an exact nightly-YYYY-MM-DD pin");
    }

    #[test]
    fn fuzz_arguments_accept_caller_selected_target_and_duration() {
        let args =
            super::parse_fuzz_args(["--smoke-seconds", "30", "--target", "cbor_object"]).unwrap();

        assert_eq!(args.smoke_seconds, 30);
        assert_eq!(args.target.as_deref(), Some("cbor_object"));
    }

    #[test]
    fn fuzz_arguments_default_to_the_stage_gate_duration_and_all_targets() {
        let args = super::parse_fuzz_args(std::iter::empty::<&str>()).unwrap();

        assert_eq!(args.smoke_seconds, 60);
        assert_eq!(args.target, None);
    }

    #[test]
    fn fuzz_arguments_reject_a_zero_duration() {
        let error = super::parse_fuzz_args(["--smoke-seconds", "0"]).unwrap_err();

        assert_eq!(error, "--smoke-seconds must be greater than zero");
    }

    #[test]
    fn fuzz_manifest_lists_every_declared_target() {
        let targets = super::parse_fuzz_targets(
            r#"[[bin]]
name = "cbor_object"
path = "fuzz_targets/cbor_object.rs"

[[bin]]
name = "signed_object"
path = "fuzz_targets/signed_object.rs"
"#,
        )
        .unwrap();

        assert_eq!(targets, vec!["cbor_object", "signed_object"]);
    }

    #[test]
    fn fuzz_command_uses_the_committed_nightly_and_fuzz_directory() {
        assert_eq!(
            super::fuzz_command_args("nightly-2026-08-13", "cbor_object", 30),
            vec![
                "+nightly-2026-08-13",
                "fuzz",
                "run",
                "--fuzz-dir",
                "fuzz",
                "cbor_object",
                "--",
                "-max_total_time=30",
            ]
        );
    }

    #[test]
    fn fuzz_lock_validation_is_locked_and_targets_the_fuzz_manifest() {
        assert_eq!(
            super::fuzz_lock_validation_args(),
            vec![
                "metadata",
                "--manifest-path",
                "fuzz/Cargo.toml",
                "--locked",
                "--format-version",
                "1",
                "--no-deps",
            ]
        );
    }
}
