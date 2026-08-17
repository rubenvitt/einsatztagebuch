use std::{
    collections::BTreeSet,
    env, fs,
    io::{self, Read},
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
        // Belegt ausschliesslich UEBERSETZBARKEIT fuer wasm32-unknown-unknown, nicht
        // Lauffaehigkeit. Der Laufzeitnachweis nach
        // docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md §14.1
        // (wasm-bindgen-Schicht, getrandom/wasm_js in einer echten JS-Umgebung, eine
        // HPKE-Entkapselung, eine Signaturpruefung gegen einen Testvektor) steht aus.
        //
        // Positivliste, nicht --workspace: xtask zieht jsonschema/cddl und
        // std::process::Command und ist nicht wasm-tauglich. Nicht --all-targets:
        // das zoege Dev-Dependencies und Integrationstests in den wasm-Graph.
        // Jede neue Bibliotheks-Crate MUSS hier oder in WASM32_EXEMPT_CRATES
        // stehen; tools/xtask/tests/workspace.rs erzwingt genau eine Zuordnung
        // je Mitglied unter crates/.
        (
            "cargo",
            vec![
                "check",
                "--target",
                "wasm32-unknown-unknown",
                "--locked",
                "-p",
                "ea-types",
                "-p",
                "ea-cbor",
                "-p",
                "ea-crypto",
                "-p",
                "ea-format",
                "-p",
                "ea-schema",
                "-p",
                "ea-time",
                "-p",
                "ea-trust",
                "-p",
                "ea-archive",
                "-p",
                "ea-chain",
                "-p",
                "ea-verify",
            ],
        ),
    ]
}

/// Library crates deliberately kept off the wasm32 positive list.
///
/// Each entry carries the crate name and the reason it cannot or need not
/// compile for `wasm32-unknown-unknown`.
/// `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §9
/// makes the verification pipeline shared browser code, and that pipeline ends
/// at `ea-verify`. A crate that reaches past it into the host operating system
/// is not shared browser code and belongs here instead.
///
/// Read as TEXT by `tools/xtask/tests/workspace.rs`, which requires exactly one
/// classification — positive list or justified exception — for every member
/// under `crates/`. That test is the only consumer, hence `dead_code`.
#[allow(dead_code)]
const WASM32_EXEMPT_CRATES: [(&str, &str); 2] = [
    (
        "ea-recovery",
        "carries the filesystem-backed archive source, plaintext handling and \
         restrictive target permissions on top of `std::fs`, so it is not shared \
         browser code: `web-reader-design.md` §9 makes only the verification \
         pipeline shared Rust, and that pipeline ends at `ea-verify`, which stays \
         on the positive list. `apps/cli` depends on this crate, never the other \
         way round.",
    ),
    (
        "ea-testkit",
        "owns the deterministic vector file and manifest emission over `std::fs` \
         and is therefore host-side generator code, not shared browser code: \
         `web-reader-design.md` §9 makes only the verification pipeline shared \
         Rust, and that pipeline ends at `ea-verify`, which stays on the positive \
         list. Test targets depend on this crate, never the other way round.",
    ),
];

/// Reports when the running compiler is not the one `rust-toolchain.toml` pins.
///
/// `RUSTUP_TOOLCHAIN` takes precedence over `rust-toolchain.toml` in full,
/// including its `targets` declaration, and rustup rewrites the variable to the
/// resolved toolchain for every process it spawns — so the variable's mere
/// presence proves nothing. Comparing the resolved toolchain against the pinned
/// channel is the only check that survives that rewriting.
///
/// A run under a different compiler is not evidence about the pinned toolchain.
/// The gate still runs: choosing another toolchain deliberately is legitimate.
/// It must not do so silently.
fn toolchain_mismatch_warning(pinned_channel: &str, active_toolchain: &str) -> Option<String> {
    let pinned = pinned_channel.trim();
    let active = active_toolchain.trim();
    if pinned.is_empty() || active.is_empty() || active.starts_with(pinned) {
        return None;
    }
    Some(format!(
        "warning: active toolchain {active} is not the pinned channel {pinned} from \
         rust-toolchain.toml, whose targets declaration is therefore ignored as well. \
         This run is not a valid pinned-toolchain proof. Unset RUSTUP_TOOLCHAIN \
         (`env -u RUSTUP_TOOLCHAIN ...`) to verify against the pin."
    ))
}

/// Reads the pinned channel out of `rust-toolchain.toml`.
fn pinned_toolchain_channel(root: &Path) -> Option<String> {
    let document: toml::Value = fs::read_to_string(root.join("rust-toolchain.toml"))
        .ok()?
        .parse()
        .ok()?;
    document
        .get("toolchain")?
        .get("channel")?
        .as_str()
        .map(str::to_owned)
}

/// Resolves the toolchain that actually runs, independent of who set the variable.
fn active_toolchain() -> Option<String> {
    let output = Command::new("rustup")
        .args(["show", "active-toolchain"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .map(str::to_owned)
}

/// Fails fast when the active toolchain cannot build the wasm32 gate command.
///
/// `targets` in `rust-toolchain.toml` is ignored entirely once `RUSTUP_TOOLCHAIN`
/// is set in the environment, so the declaration alone does not guarantee the
/// target is present. Without this check the user meets `can't find crate for
/// 'core'` instead of an actionable message.
///
/// Note that `rustup target list --installed` reports the targets of whichever
/// toolchain is active, so under an override it answers for the overriding
/// toolchain. That is why [`toolchain_mismatch_warning`] runs alongside it: this
/// check alone would pass while the pin is being ignored.
fn ensure_wasm32_target_available() -> Result<(), String> {
    let Ok(output) = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
    else {
        return Ok(());
    };
    if !output.status.success() {
        return Ok(());
    }
    if String::from_utf8_lossy(&output.stdout).contains("wasm32-unknown-unknown") {
        return Ok(());
    }
    Err(String::from(
        "wasm32-unknown-unknown is not installed for the active toolchain. \
         Run `rustup target add wasm32-unknown-unknown`. \
         Note: RUSTUP_TOOLCHAIN in the environment overrides rust-toolchain.toml, \
         including its targets declaration.",
    ))
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
    cddl::pest_bridge::cddl_from_pest_str_checked(input)
        .map(|_| ())
        .map_err(|error| format!("invalid CDDL {name}: {error}"))
}

fn validate_cddl_syntax(name: &str, input: &str) -> Result<(), String> {
    cddl::parser::cddl_from_str(input, false)
        .map(|_| ())
        .map_err(|error| format!("invalid CDDL {name}: {error}"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JsonSchemaProfile {
    DeterministicReport,
    PayloadProjection,
}

fn json_schema_profile(relative: &str) -> Result<JsonSchemaProfile, String> {
    if relative.starts_with("schemas/reports/") {
        Ok(JsonSchemaProfile::DeterministicReport)
    } else if relative.starts_with("schemas/payload/") {
        Ok(JsonSchemaProfile::PayloadProjection)
    } else {
        Err(format!("JSON schema {relative} has no declared profile"))
    }
}

fn compile_json_schema_for_profile(
    name: &str,
    input: &str,
    profile: JsonSchemaProfile,
) -> Result<jsonschema::Validator, String> {
    let schema: serde_json::Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid JSON schema {name}: {error}"))?;
    jsonschema::meta::validate(&schema)
        .map_err(|error| format!("invalid JSON schema {name}: {error}"))?;
    require_closed_object_schemas(name, &schema, "#")?;
    if profile == JsonSchemaProfile::DeterministicReport {
        require_canonical_array_contracts(name, &schema, "#")?;
    }
    jsonschema::validator_for(&schema)
        .map_err(|error| format!("failed to compile JSON schema {name}: {error}"))
}

#[cfg(test)]
fn compile_json_schema(name: &str, input: &str) -> Result<jsonschema::Validator, String> {
    compile_json_schema_for_profile(name, input, JsonSchemaProfile::DeterministicReport)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum CanonicalValue {
    Bytes(Vec<u8>),
    Uint(u64),
}

#[derive(Clone, Debug)]
struct CanonicalKeyPart<'a> {
    path: &'a str,
    encoding: &'a str,
}

fn canonical_key_parts<'a>(
    name: &str,
    schema: &'a serde_json::Value,
) -> Result<Vec<CanonicalKeyPart<'a>>, String> {
    let parts = schema
        .get("x-ea-sort-key")
        .and_then(serde_json::Value::as_array)
        .filter(|parts| !parts.is_empty())
        .ok_or_else(|| format!("array schema {name} lacks x-ea-sort-key"))?;
    parts
        .iter()
        .map(|part| {
            let path = part
                .get("path")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| format!("array schema {name} has an invalid sort-key path"))?;
            let encoding = part
                .get("encoding")
                .and_then(serde_json::Value::as_str)
                .filter(|encoding| matches!(*encoding, "hex-bytes" | "utf8" | "uint"))
                .ok_or_else(|| format!("array schema {name} has an invalid sort-key encoding"))?;
            Ok(CanonicalKeyPart { path, encoding })
        })
        .collect()
}

fn decode_lower_hex(name: &str, value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{name} canonical hex key must be lowercase and even-length"
        ));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => unreachable!(),
            };
            Ok((digit(pair[0]) << 4) | digit(pair[1]))
        })
        .collect()
}

fn canonical_value(
    name: &str,
    item: &serde_json::Value,
    part: &CanonicalKeyPart<'_>,
) -> Result<CanonicalValue, String> {
    let value = if part.path == "$" {
        item
    } else {
        item.get(part.path)
            .ok_or_else(|| format!("{name} item lacks canonical key {}", part.path))?
    };
    match part.encoding {
        "hex-bytes" => value
            .as_str()
            .ok_or_else(|| format!("{name} key {} must be a string", part.path))
            .and_then(|value| decode_lower_hex(name, value))
            .map(CanonicalValue::Bytes),
        "utf8" => value
            .as_str()
            .ok_or_else(|| format!("{name} key {} must be a string", part.path))
            .map(|value| CanonicalValue::Bytes(value.as_bytes().to_vec())),
        "uint" => value
            .as_u64()
            .ok_or_else(|| format!("{name} key {} must be an unsigned integer", part.path))
            .map(CanonicalValue::Uint),
        _ => unreachable!(),
    }
}

fn validate_canonical_array(
    name: &str,
    schema: &serde_json::Value,
    values: &[serde_json::Value],
) -> Result<(), String> {
    let parts = canonical_key_parts(name, schema)?;
    let unique_paths = schema
        .get("x-ea-unique-key")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("array schema {name} lacks x-ea-unique-key"))?
        .iter()
        .map(|path| {
            path.as_str()
                .ok_or_else(|| format!("array schema {name} has an invalid unique-key path"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let sort_paths = parts.iter().map(|part| part.path).collect::<Vec<_>>();
    if unique_paths != sort_paths {
        return Err(format!(
            "array schema {name} unique key must equal its complete stable sort key"
        ));
    }
    if schema.get("uniqueItems") != Some(&serde_json::Value::Bool(true)) {
        return Err(format!("array schema {name} must set uniqueItems to true"));
    }

    let keys = values
        .iter()
        .map(|item| {
            parts
                .iter()
                .map(|part| canonical_value(name, item, part))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    for pair in keys.windows(2) {
        if pair[0] == pair[1] {
            return Err(format!("{name} contains a duplicate key"));
        }
        if pair[0] > pair[1] {
            return Err(format!("{name} is not sorted by its stable key"));
        }
    }
    Ok(())
}

fn require_canonical_array_contracts(
    name: &str,
    value: &serde_json::Value,
    location: &str,
) -> Result<(), String> {
    match value {
        serde_json::Value::Object(object) => {
            if object.get("type").and_then(serde_json::Value::as_str) == Some("array") {
                canonical_key_parts(&format!("{name} {location}"), value)?;
                validate_canonical_array(&format!("{name} {location}"), value, &[])?;
            }
            for (key, child) in object {
                require_canonical_array_contracts(name, child, &format!("{location}/{key}"))?;
            }
        }
        serde_json::Value::Array(array) => {
            for (index, child) in array.iter().enumerate() {
                require_canonical_array_contracts(name, child, &format!("{location}/{index}"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_json_schema_document_for_profile(
    name: &str,
    input: &str,
    profile: JsonSchemaProfile,
) -> Result<(), String> {
    compile_json_schema_for_profile(name, input, profile).map(|_| ())
}

#[cfg(test)]
fn validate_json_schema_document(name: &str, input: &str) -> Result<(), String> {
    validate_json_schema_document_for_profile(name, input, JsonSchemaProfile::DeterministicReport)
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

fn decode_lower_hex_vector(relative: &str, input: &str) -> Result<Vec<u8>, String> {
    let hex = input
        .strip_suffix('\n')
        .ok_or_else(|| format!("payload vector {relative} must end in exactly one newline"))?;
    if hex.is_empty()
        || !hex.len().is_multiple_of(2)
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "payload vector {relative} must contain nonempty lowercase hexadecimal octets"
        ));
    }
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => Ok(byte - b'0'),
                b'a'..=b'f' => Ok(byte - b'a' + 10),
                _ => Err(format!("payload vector {relative} contains invalid hex")),
            };
            Ok((digit(pair[0])? << 4) | digit(pair[1])?)
        })
        .collect()
}

const MAX_PLAINTEXT_BYTES_V1: usize = 1_048_576;
const MAX_PAYLOAD_VECTOR_TEXT_BYTES_V1: usize = 2 * MAX_PLAINTEXT_BYTES_V1 + 1;

fn validate_payload_vector_file(
    path: &Path,
    relative: &str,
    root: &str,
    cddl: &str,
) -> Result<(), String> {
    let file =
        fs::File::open(path).map_err(|error| format!("failed to read {relative}: {error}"))?;
    let mut source = Vec::with_capacity(MAX_PAYLOAD_VECTOR_TEXT_BYTES_V1 + 1);
    file.take((MAX_PAYLOAD_VECTOR_TEXT_BYTES_V1 + 1) as u64)
        .read_to_end(&mut source)
        .map_err(|error| format!("failed to read {relative}: {error}"))?;
    if source.len() > MAX_PAYLOAD_VECTOR_TEXT_BYTES_V1 {
        return Err(format!(
            "payload vector {relative} exceeds MAX_PAYLOAD_VECTOR_TEXT_BYTES_V1 = {MAX_PAYLOAD_VECTOR_TEXT_BYTES_V1}"
        ));
    }
    let input = std::str::from_utf8(&source)
        .map_err(|error| format!("payload vector {relative} is not UTF-8: {error}"))?;
    let bytes = decode_lower_hex_vector(relative, input)?;
    if bytes.len() > MAX_PLAINTEXT_BYTES_V1 {
        return Err(format!(
            "payload vector {relative} exceeds MAX_PLAINTEXT_BYTES_V1"
        ));
    }
    ea_cbor::validate(&bytes, ea_cbor::ParserLimits::V1)
        .map_err(|error| format!("payload vector {relative} is not canonical: {error}"))?;
    cddl_cat::validate_cbor_bytes(root, cddl, &bytes)
        .map_err(|error| format!("payload vector {relative} violates {root}: {error:?}"))
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
        validate_cddl_syntax(relative, &input)?;
        archive_bundle.push_str(&input);
        archive_bundle.push('\n');
    }
    validate_cddl_document("combined archive CDDL", &archive_bundle)?;

    let protocol_path = "schemas/protocol/v1/signed-protocol.cddl";
    let protocol = fs::read_to_string(root.join(protocol_path))
        .map_err(|error| format!("failed to read {protocol_path}: {error}"))?;
    validate_cddl_document(protocol_path, &protocol)?;

    let identity_path = "schemas/identity/v1/os-account.cddl";
    let identity = fs::read_to_string(root.join(identity_path))
        .map_err(|error| format!("failed to read {identity_path}: {error}"))?;
    validate_cddl_document(identity_path, &identity)?;

    let audit_path = "schemas/reports/v1/local-audit.cddl";
    let audit = fs::read_to_string(root.join(audit_path))
        .map_err(|error| format!("failed to read {audit_path}: {error}"))?;
    validate_cddl_document(audit_path, &audit)?;

    let payload_path = "schemas/payload/v1/payload.cddl";
    let payload = fs::read_to_string(root.join(payload_path))
        .map_err(|error| format!("failed to read {payload_path}: {error}"))?;
    validate_cddl_document(payload_path, &payload)?;
    for (file, cddl_root) in [
        ("genesis.hex", "genesis-payload-v1"),
        ("incident.hex", "incident-payload-v1"),
        ("amendment.hex", "amendment-payload-v1"),
        ("key-transition.hex", "key-transition-payload-v1"),
        (
            "destruction-evidence.hex",
            "destruction-evidence-payload-v1",
        ),
    ] {
        let relative = format!("vectors/format/payload-v1/{file}");
        validate_payload_vector_file(&root.join(&relative), &relative, cddl_root, &payload)?;
    }

    for relative in [
        "schemas/reports/v1/verification-report.schema.json",
        "schemas/reports/v1/key-inventory.schema.json",
        "schemas/payload/v1/genesis.schema.json",
        "schemas/payload/v1/incident.schema.json",
        "schemas/payload/v1/amendment.schema.json",
        "schemas/payload/v1/key-transition.schema.json",
        "schemas/payload/v1/destruction-evidence.schema.json",
    ] {
        let path = root.join(relative);
        let input = fs::read_to_string(&path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        validate_json_schema_document_for_profile(
            relative,
            &input,
            json_schema_profile(relative)?,
        )?;
    }
    let compatibility_path = "schemas/compatibility-matrix.json";
    let compatibility = fs::read_to_string(root.join(compatibility_path))
        .map_err(|error| format!("failed to read {compatibility_path}: {error}"))?;
    serde_json::from_str::<serde_json::Value>(&compatibility)
        .map_err(|error| format!("invalid compatibility matrix: {error}"))?;
    let expected_compatibility = ea_schema::SchemaRegistry::v1().compatibility_matrix_json();
    if compatibility != expected_compatibility {
        return Err("compatibility matrix differs from the ea-schema registry".to_owned());
    }
    let addendum_path =
        root.join("docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-wire-format-addendum.md");
    let addendum = fs::read_to_string(&addendum_path)
        .map_err(|error| format!("failed to read {}: {error}", addendum_path.display()))?;
    validate_addendum_review(&addendum)?;
    println!("validated 7 CDDL, 7 JSON schemas, 5 payload vectors, and compatibility matrix");
    Ok(())
}

/// Die Vektorfamilien, die der Stufe-1-Gate verlangt — lexikografisch sortiert,
/// damit Bericht und Fehlerzeile byteidentisch reproduzierbar sind.
const STAGE_ONE_VECTOR_FAMILIES: [&str; 6] = [
    "crypto", "evidence", "format", "grants", "receipts", "trust",
];

/// Die primaeren Abnahmekriterien der Stufe 1 nach
/// `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md`.
///
/// Der Bericht nennt sie. Die BELEGPFLICHT — jede dieser Zahlen braucht eine
/// vollstaendige Ledger-Zeile im Status `implemented` oder `integrated` — wird
/// erst scharf geschaltet, wenn die Vektorfamilien und Property-Tests
/// existieren. Wuerde sie hier greifen, koennte das Ledger nur mit erfundenen
/// Testnamen gruen werden.
const STAGE_ONE_PRIMARY_ACCEPTANCE_CRITERIA: [u32; 10] = [4, 5, 6, 9, 14, 16, 17, 20, 38, 51];

/// Das maschinell pruefbare Requirement-Ledger, relativ zur Gate-Wurzel.
const REQUIREMENT_LEDGER_PATH: &str = "docs/traceability/v0.1-requirements.csv";

/// Die aufzaehlbare Quelle der Pflichtzeilenmenge, relativ zur Gate-Wurzel.
const DESIGN_DOCUMENT_PATH: &str = "docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md";

/// Das Fuzz-Manifest, relativ zur Gate-Wurzel.
const FUZZ_MANIFEST_PATH: &str = "fuzz/Cargo.toml";

/// Die fuenf Fuzz-Flaechen aus `design.md` §22.1 und das Ziel, das jede
/// abdeckt — Flaechen in der Reihenfolge des Entwurfstexts, damit Bericht und
/// Fehlerzeile byteidentisch reproduzierbar sind.
///
/// Vier Ziele decken fuenf Flaechen: `object_bounds` traegt Objektgrenzen und
/// Ressourcenlimits gemeinsam, weil beide am selben Objektrahmen gemessen
/// werden. Die sechs Familienrohgrenzen, die globale Objektgrenze sowie die
/// Wert- und Arbeitsgrenzen aus Global Constraint Zeile 30 des Stufe-1-Plans
/// stehen dort als Uebersetzungszeit-Assertions.
const STAGE_ONE_FUZZ_SURFACES: [(&str, &str); 5] = [
    ("cbor", "cbor_object"),
    ("cose", "cose_sign1"),
    ("hpke", "hpke_grant"),
    ("object-bounds", "object_bounds"),
    ("resource-limits", "object_bounds"),
];

/// Der Spaltenvertrag des Ledgers. Spaetere Stufen ergaenzen nur Zeilen.
const LEDGER_COLUMNS: [&str; 9] = [
    "requirement_id",
    "version",
    "source",
    "title",
    "primary_acceptance_criterion",
    "related_acceptance_criteria",
    "evidence",
    "stage",
    "status",
];

/// Die Spalten, die eine Zeile vollstaendig machen — das `is_complete()`
/// dieses Ledgers.
const LEDGER_REQUIRED_COLUMNS: [&str; 4] = ["source", "title", "evidence", "status"];

/// Das erlaubte Statusvokabular, lexikografisch fuer eine stabile Fehlerzeile.
const LEDGER_STATUSES: [&str; 3] = ["implemented", "integrated", "planned"];

/// Die drei unnummerierten Gates aus `design.md` §21, §22 und §25.
const UNNUMBERED_GATE_IDENTIFIERS: [&str; 3] = ["GATE-21", "GATE-22", "GATE-25"];

/// Eine Ledger-Zeile, reduziert auf die gepruefte Teilmenge des Spaltenvertrags.
#[derive(Debug)]
struct LedgerRow {
    requirement_id: String,
    primary_acceptance_criterion: String,
    values: Vec<String>,
}

/// Schneidet den Abschnitt zwischen zwei Ueberschriften heraus.
///
/// Die Grenze ist zwingend: `design.md` §24 beginnt mit einer nummerierten
/// Liste, die sonst als Abnahmekriterien zaehlen wuerde, und §27.2 fuehrt
/// weitere `FR-`-Zeilen, die keine funktionale Pflichtzeile sind.
fn section_between<'a>(text: &'a str, start: &str, end: &str) -> Result<&'a str, String> {
    let start_at = text.find(start).ok_or_else(|| {
        format!(
            "the design document must contain the heading {}",
            start.trim()
        )
    })?;
    let tail = &text[start_at + start.len()..];
    let end_at = tail.find(end).ok_or_else(|| {
        format!(
            "the design document must contain the heading {}",
            end.trim()
        )
    })?;
    Ok(&tail[..end_at])
}

/// Leitet die Pflichtzeilenmenge aus aufzaehlbaren Quellen ab.
///
/// Keine handgepflegte Liste: die funktionalen Anforderungen kommen aus der
/// Tabelle in §27.1, die Abnahmekriterien aus der nummerierten Liste in §23 —
/// dort auf zwei Stellen aufgefuellt, damit die lexikografische Sortierung des
/// Ledgers der numerischen entspricht — und die drei unnummerierten Gates aus
/// einer festen Pseudo-Identifikatormenge.
fn required_requirement_identifiers(design: &str) -> Result<BTreeSet<String>, String> {
    let mut identifiers = BTreeSet::new();

    let acceptance = section_between(
        design,
        "\n## 23. Abnahmekriterien\n",
        "\n## 24. Interne Lieferstufen\n",
    )?;
    let mut numbers = Vec::new();
    for line in acceptance.lines() {
        let digits: String = line.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() || !line[digits.len()..].starts_with(". ") {
            continue;
        }
        let number = digits
            .parse::<u32>()
            .map_err(|error| format!("unreadable acceptance criterion number {digits}: {error}"))?;
        numbers.push(number);
    }
    if numbers.is_empty() {
        return Err("design.md section 23 must enumerate acceptance criteria".to_owned());
    }
    for (index, number) in numbers.iter().enumerate() {
        let expected = u32::try_from(index + 1).unwrap_or(u32::MAX);
        if *number != expected {
            return Err(format!(
                "design.md section 23 must number its acceptance criteria consecutively; \
                 expected {expected}, found {number}"
            ));
        }
        identifiers.insert(format!("AK-{number:02}"));
    }

    let functional = section_between(
        design,
        "\n### 27.1 Funktionale Anforderungen\n",
        "\n### 27.2 Nichtfunktionale Anforderungen\n",
    )?;
    let mut functional_count = 0_usize;
    for line in functional.lines() {
        let Some(rest) = line.strip_prefix("| FR-") else {
            continue;
        };
        let number = rest.split('|').next().unwrap_or_default().trim();
        if number.is_empty() {
            return Err("design.md section 27.1 carries a nameless FR row".to_owned());
        }
        identifiers.insert(format!("FR-{number}"));
        functional_count += 1;
    }
    if functional_count == 0 {
        return Err("design.md section 27.1 must enumerate functional requirements".to_owned());
    }

    for gate in UNNUMBERED_GATE_IDENTIFIERS {
        identifiers.insert(gate.to_owned());
    }
    Ok(identifiers)
}

/// Zerlegt eine Ledger-Zeile in ihre Felder.
///
/// Jedes Feld MUSS in Anfuehrungszeichen stehen; ein doppeltes
/// Anfuehrungszeichen im Feld wird verdoppelt. Damit kann kein Trennzeichen im
/// Freitext eine Spalte verschieben und die Formalpruefung still bestehen.
fn parse_ledger_fields(line: &str) -> Result<Vec<String>, String> {
    let mut fields = Vec::new();
    let mut characters = line.chars();
    loop {
        if characters.next() != Some('"') {
            return Err("every field must be enclosed in double quotes".to_owned());
        }
        let mut field = String::new();
        loop {
            match characters.next() {
                Some('"') => {
                    let mut lookahead = characters.clone();
                    if lookahead.next() == Some('"') {
                        characters = lookahead;
                        field.push('"');
                    } else {
                        break;
                    }
                }
                Some(character) => field.push(character),
                None => return Err("unterminated quoted field".to_owned()),
            }
        }
        fields.push(field);
        match characters.next() {
            None => return Ok(fields),
            Some(',') => {}
            Some(character) => {
                return Err(format!(
                    "unexpected character {character} after a quoted field"
                ));
            }
        }
    }
}

/// Prueft Wohlgeformtheit und Zeilenvollstaendigkeit des Ledgers.
fn parse_requirement_ledger(text: &str) -> Result<Vec<LedgerRow>, String> {
    if text.contains('\r') {
        return Err("the requirement ledger must use LF line endings".to_owned());
    }
    let mut lines = text.split('\n');
    let header = lines
        .next()
        .ok_or_else(|| "the requirement ledger must carry exactly one header line".to_owned())?;
    let header_fields = parse_ledger_fields(header)
        .map_err(|error| format!("requirement ledger line 1: {error}"))?;
    if header_fields != LEDGER_COLUMNS {
        return Err(format!(
            "the requirement ledger header must declare {}",
            LEDGER_COLUMNS.join(", ")
        ));
    }

    let mut rows = Vec::new();
    let mut problems = Vec::new();
    let mut blanks = 0_usize;
    for (index, line) in lines.enumerate() {
        let number = index + 2;
        // Genau EINE leere Zeile ist zulaessig: der Rest hinter dem
        // abschliessenden Zeilenvorschub. Jede weitere ist eine echte Leerzeile.
        if line.is_empty() {
            blanks += 1;
            if blanks > 1 {
                return Err("the requirement ledger must not carry blank lines".to_owned());
            }
            continue;
        }
        if blanks > 0 {
            return Err("the requirement ledger must not carry blank lines".to_owned());
        }
        let values = match parse_ledger_fields(line) {
            Ok(values) => values,
            Err(error) => {
                problems.push(format!("line {number}: {error}"));
                continue;
            }
        };
        if values.len() != LEDGER_COLUMNS.len() {
            problems.push(format!(
                "line {number}: expected {} columns, found {}",
                LEDGER_COLUMNS.len(),
                values.len()
            ));
            continue;
        }
        let requirement_id = values[0].clone();
        if requirement_id.is_empty() {
            problems.push(format!("line {number}: requirement_id must not be empty"));
            continue;
        }
        for column in LEDGER_REQUIRED_COLUMNS {
            let at = LEDGER_COLUMNS
                .iter()
                .position(|declared| *declared == column)
                .unwrap_or_default();
            if values[at].trim().is_empty() {
                problems.push(format!("{requirement_id}: {column} must not be empty"));
            }
        }
        let status = values[8].clone();
        if !status.is_empty() && !LEDGER_STATUSES.contains(&status.as_str()) {
            problems.push(format!(
                "{requirement_id}: status {status} is outside the vocabulary {}",
                LEDGER_STATUSES.join(", ")
            ));
        }
        let primary_acceptance_criterion = values[4].clone();
        if !primary_acceptance_criterion.is_empty() {
            match primary_acceptance_criterion.parse::<u32>() {
                Ok(criterion) if (1..=54).contains(&criterion) => {}
                _ => problems.push(format!(
                    "{requirement_id}: primary_acceptance_criterion \
                     {primary_acceptance_criterion} must be a number from 1 to 54 or empty"
                )),
            }
        }
        rows.push(LedgerRow {
            requirement_id,
            primary_acceptance_criterion,
            values,
        });
    }
    if !text.ends_with('\n') {
        problems.push("the requirement ledger must end with a line feed".to_owned());
    }
    if !problems.is_empty() {
        return Err(format!(
            "incomplete requirement ledger rows: {}",
            problems.join("; ")
        ));
    }
    for pair in rows.windows(2) {
        if pair[0].requirement_id > pair[1].requirement_id {
            return Err(format!(
                "the requirement ledger must be sorted by requirement_id; {} precedes {}",
                pair[0].requirement_id, pair[1].requirement_id
            ));
        }
    }
    Ok(rows)
}

/// Liest das Ledger von der Gate-Wurzel.
///
/// Eine fehlende Datei ist ein LEERES Ledger, kein IO-Fehler: der Gate soll die
/// unbelegten Identifikatoren einzeln nennen, nicht bloss melden, dass er nichts
/// gefunden hat.
fn read_requirement_ledger(path: &Path) -> Result<Vec<LedgerRow>, String> {
    match fs::read_to_string(path) {
        Ok(text) => {
            parse_requirement_ledger(&text).map_err(|error| format!("{}: {error}", path.display()))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(format!("failed to read {}: {error}", path.display())),
    }
}

/// Wurzel des Stufengates: `EA_STAGE_GATE_ROOT`, sonst der Arbeitsbaum.
///
/// Der Override ist der Test-Seam. Ohne ihn liefe jeder Test gegen den echten
/// Arbeitsbaum und wuerde invertieren, sobald ein spaeterer Task eine
/// Vektorfamilie nachliefert. Die Kommandozeile bleibt `stage-gate <stage>`;
/// die Wurzel ist kein Positionsargument, weil ueberzaehlige Argumente ein
/// Fehler sind.
fn stage_gate_root(root: &Path) -> PathBuf {
    env::var_os("EA_STAGE_GATE_ROOT").map_or_else(|| root.to_path_buf(), PathBuf::from)
}

/// Wahr, wenn die Familie ein lesbares Manifest traegt.
///
/// Eine Familie darf ihre Vektoren versionieren: `vectors/crypto/suite-1/` ist
/// die Suite-1-Fassung der Primitivvektoren, und eine spaetere Suite kaeme
/// daneben zu liegen, nicht an ihre Stelle. Eine Version darf sich ausserdem in
/// Teilmengen gliedern: `vectors/format/v1/` traegt `valid/` und `invalid/` mit
/// je einem eigenen Manifest, weil die Positiv- und die Negativvektoren
/// verschiedene Erzeuger haben. Der Gate sucht deshalb bis
/// `vectors/<familie>/<version>/<teilmenge>/manifest.json`.
///
/// Ein blosses Verzeichnis genuegt weiterhin nicht: `vectors/format/payload-v1/`
/// existiert im Bestand OHNE Manifest und wird von `validate-schemas` getrieben.
fn family_carries_a_manifest(vectors: &Path, family: &str) -> bool {
    /// Familienverzeichnis, Version, Teilmenge — tiefer sucht der Gate nicht.
    const MAX_DEPTH: u32 = 3;

    directory_carries_a_manifest(&vectors.join(family), MAX_DEPTH)
}

/// Wahr, wenn unter `directory` innerhalb von `depth` Ebenen ein lesbares
/// `manifest.json` liegt.
fn directory_carries_a_manifest(directory: &Path, depth: u32) -> bool {
    if depth == 0 {
        return false;
    }
    if fs::read(directory.join("manifest.json")).is_ok() {
        return true;
    }
    let Ok(children) = fs::read_dir(directory) else {
        return false;
    };
    children
        .filter_map(Result::ok)
        .any(|child| directory_carries_a_manifest(&child.path(), depth - 1))
}

/// Liest die im Fuzz-Manifest deklarierten Ziele und prueft, dass sie jede der
/// fuenf Flaechen aus `design.md` §22.1 abdecken.
///
/// Der Gate prueft die DEKLARATION, nicht den Lauf: ob ein Ziel Funde liefert,
/// entscheidet `xtask test-fuzz`. Fehlt eine Flaeche, nennt die Fehlerzeile sie
/// und das erwartete Ziel — die Flaechen laufen in Entwurfsreihenfolge, also
/// meldet der Gate stets die erste Luecke.
fn stage_one_fuzz_targets(gate_root: &Path) -> Result<Vec<String>, String> {
    let manifest_path = gate_root.join(FUZZ_MANIFEST_PATH);
    let declared = parse_fuzz_targets(
        &fs::read_to_string(&manifest_path)
            .map_err(|error| format!("failed to read {}: {error}", manifest_path.display()))?,
    )?;
    for (surface, target) in STAGE_ONE_FUZZ_SURFACES {
        if !declared.iter().any(|name| name == target) {
            return Err(format!(
                "missing fuzz target for surface {surface}: {target} is not declared in {}",
                manifest_path.display()
            ));
        }
    }
    Ok(declared)
}

/// Prueft die Stufe-1-Vektorfamilien und schreibt den Bericht nach stdout.
///
/// Eine Familie zaehlt erst als vorhanden, wenn [`family_carries_a_manifest`]
/// unter ihr ein lesbares `manifest.json` findet. Ein blosses Verzeichnis
/// genuegt nicht: `vectors/format/payload-v1/` existiert im Bestand ohne
/// Manifest und wird von `validate-schemas` getrieben.
///
/// Danach prueft der Gate das Requirement-Ledger: formale Wohlgeformtheit,
/// Zeilenvollstaendigkeit und Abdeckung der aus `design.md` abgeleiteten
/// Pflichtzeilenmenge. `evidenced_acceptance_criteria` zeigt, welche primaeren
/// Abnahmekriterien bereits belegt sind; die Belegpflicht selbst wird erst
/// scharf geschaltet, wenn Vektoren und Property-Tests existieren.
///
/// Zuletzt prueft der Gate die Fuzz-Flaechen aus `design.md` §22.1 gegen die im
/// Fuzz-Manifest deklarierten Ziele.
///
/// Das Berichtsschema ist stabil und wird von spaeteren Stufen erweitert, nie
/// umbenannt. `rows` nennt die `requirement_id` jeder Ledger-Zeile in
/// Dateireihenfolge; `fuzz_targets` nennt die deklarierten Ziele lexikografisch
/// und `fuzz_surfaces` die Zuordnung Flaeche zu Ziel in Entwurfsreihenfolge.
fn run_stage_gate(root: &Path, stage: u32) -> Result<(), String> {
    if stage != 1 {
        return Err(format!(
            "stage-gate is only defined for stage 1 so far, not {stage}"
        ));
    }
    let vectors = stage_gate_root(root).join("vectors");
    let mut present = Vec::new();
    let mut missing = Vec::new();
    for family in STAGE_ONE_VECTOR_FAMILIES {
        if family_carries_a_manifest(&vectors, family) {
            present.push(family);
        } else {
            missing.push(family);
        }
    }
    if !missing.is_empty() {
        return Err(format!(
            "stage 1 vector families without a readable manifest under {}: {}",
            vectors.display(),
            missing.join(", ")
        ));
    }
    let gate_root = stage_gate_root(root);
    let design_path = gate_root.join(DESIGN_DOCUMENT_PATH);
    let design = fs::read_to_string(&design_path)
        .map_err(|error| format!("failed to read {}: {error}", design_path.display()))?;
    let required = required_requirement_identifiers(&design)?;
    let ledger_path = gate_root.join(REQUIREMENT_LEDGER_PATH);
    let rows = read_requirement_ledger(&ledger_path)?;
    let covered = rows
        .iter()
        .map(|row| row.requirement_id.clone())
        .collect::<BTreeSet<_>>();
    let uncovered = required
        .difference(&covered)
        .cloned()
        .collect::<Vec<String>>();
    if !uncovered.is_empty() {
        return Err(format!(
            "the requirement ledger {} does not cover: {}",
            ledger_path.display(),
            uncovered.join(", ")
        ));
    }
    let fuzz_targets = stage_one_fuzz_targets(&gate_root)?;
    let fuzz_surfaces = STAGE_ONE_FUZZ_SURFACES
        .iter()
        .map(|(surface, target)| serde_json::json!({ "surface": surface, "target": target }))
        .collect::<Vec<_>>();
    let row_identifiers = rows
        .iter()
        .map(|row| row.requirement_id.clone())
        .collect::<Vec<_>>();
    let evidenced = rows
        .iter()
        .filter(|row| {
            matches!(row.values[8].as_str(), "implemented" | "integrated")
                && !row.primary_acceptance_criterion.is_empty()
        })
        .filter_map(|row| row.primary_acceptance_criterion.parse::<u32>().ok())
        .collect::<BTreeSet<_>>();
    let report = serde_json::json!({
        "stage": stage,
        "vector_families": present,
        "primary_acceptance_criteria": STAGE_ONE_PRIMARY_ACCEPTANCE_CRITERIA,
        "evidenced_acceptance_criteria": evidenced,
        "rows": row_identifiers,
        "fuzz_targets": fuzz_targets,
        "fuzz_surfaces": fuzz_surfaces,
    });
    println!(
        "{}",
        serde_json::to_string(&report)
            .map_err(|error| format!("failed to render the stage gate report: {error}"))?
    );
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
            if let (Some(pinned), Some(active)) =
                (pinned_toolchain_channel(&root), active_toolchain())
                && let Some(warning) = toolchain_mismatch_warning(&pinned, &active)
            {
                eprintln!("{warning}");
            }
            ensure_wasm32_target_available()?;
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
        "stage-gate" => {
            let stage = args
                .next()
                .ok_or_else(|| "usage: xtask stage-gate <stage>".to_owned())?;
            if args.next().is_some() {
                return Err("stage-gate accepts exactly one stage argument".to_owned());
            }
            let stage = stage
                .parse::<u32>()
                .map_err(|error| format!("stage-gate stage must be a number: {stage}: {error}"))?;
            run_stage_gate(&root, stage)
        }
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
    /// Pinnt den Ableiter gegen den ECHTEN Entwurf.
    ///
    /// `tools/xtask/tests/stage_gate.rs` treibt den Gate gegen ein synthetisches
    /// Fixture, damit die Fehlerzustaende ueber die Taskkette stabil bleiben.
    /// Ohne diesen Test bliebe unbemerkt, wenn der Ableiter am gemessenen
    /// Bestand — 69 `FR-`-Zeilen in §27.1, 54 Abnahmekriterien in §23 — vorbei
    /// parst und die Pflichtzeilenmenge still schrumpft.
    #[test]
    fn the_required_identifier_set_is_derived_from_the_design_document() {
        let path = super::workspace_root().join(super::DESIGN_DOCUMENT_PATH);
        let design = std::fs::read_to_string(&path).expect("the design document must be readable");
        let identifiers = super::required_requirement_identifiers(&design)
            .expect("the design document must enumerate requirement identifiers");

        let functional = identifiers
            .iter()
            .filter(|identifier| identifier.starts_with("FR-"))
            .count();
        let acceptance = identifiers
            .iter()
            .filter(|identifier| identifier.starts_with("AK-"))
            .count();
        assert_eq!(
            functional, 69,
            "design.md section 27.1 enumerates 69 functional requirements"
        );
        assert_eq!(
            acceptance, 54,
            "design.md section 23 enumerates 54 acceptance criteria"
        );
        assert!(identifiers.contains("FR-001"));
        assert!(identifiers.contains("AK-01"));
        assert!(identifiers.contains("AK-54"));
        for gate in super::UNNUMBERED_GATE_IDENTIFIERS {
            assert!(identifiers.contains(gate));
        }
        assert_eq!(identifiers.len(), 69 + 54 + 3);
    }

    #[test]
    fn the_requirement_ledger_rejects_a_field_without_quotes() {
        let error = super::parse_ledger_fields("AK-01,v1").expect_err("quoting is mandatory");

        assert!(error.contains("double quotes"), "{error}");
    }

    /// Genau ein abschliessender Zeilenvorschub, keine Leerzeile.
    ///
    /// Ohne diese Grenze bliebe eine Leerzeile am Dateiende unbemerkt, weil sie
    /// weder eine Spalte verschiebt noch einen Identifikator entfernt — und der
    /// Diff einer spaeteren Stufe wuerde sie stillschweigend mitschleppen.
    #[test]
    fn the_requirement_ledger_rejects_a_trailing_blank_line() {
        let header = super::LEDGER_COLUMNS
            .iter()
            .map(|column| format!("\"{column}\""))
            .collect::<Vec<_>>()
            .join(",");
        let row = "\"AK-01\",\"v1\",\"design.md\",\"Titel\",\"1\",\"\",\"gate\",\"1\",\"planned\"";
        let text = format!("{header}\n{row}\n");
        super::parse_requirement_ledger(&text).expect("a well formed ledger must parse");

        let error = super::parse_requirement_ledger(&format!("{text}\n"))
            .expect_err("a trailing blank line must fail closed");

        assert!(error.contains("blank lines"), "{error}");
    }

    #[test]
    fn schema_validation_rejects_malformed_cddl() {
        let error = super::validate_cddl_document("broken.cddl", "root = [")
            .expect_err("malformed CDDL must fail closed");

        assert!(error.contains("broken.cddl"));
    }

    /// Eine versionierte Vektorfamilie zaehlt, ein leeres Verzeichnis nicht.
    ///
    /// `vectors/crypto/suite-1/manifest.json` ist die erste Familie, die ihre
    /// Vektoren versioniert. Ohne diese Erweiterung meldete der Gate `crypto`
    /// weiterhin als fehlend, obwohl das Manifest existiert — und mit einer
    /// blossen Verzeichnispruefung zaehlte `vectors/format/payload-v1/`
    /// faelschlich mit, das im Bestand kein Manifest traegt.
    #[test]
    fn a_versioned_vector_family_directory_satisfies_the_stage_gate() {
        struct TempDir(std::path::PathBuf);

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = TempDir(std::env::temp_dir().join(format!(
            "einsatzarchiv-vector-family-{}-{nonce}",
            std::process::id()
        )));
        let vectors = directory.0.join("vectors");
        std::fs::create_dir_all(vectors.join("versioned/suite-1")).unwrap();
        std::fs::write(
            vectors.join("versioned/suite-1/manifest.json"),
            "{\"family\":\"versioned\"}\n",
        )
        .unwrap();
        std::fs::create_dir_all(vectors.join("flat")).unwrap();
        std::fs::write(
            vectors.join("flat/manifest.json"),
            "{\"family\":\"flat\"}\n",
        )
        .unwrap();
        std::fs::create_dir_all(vectors.join("bare/payload-v1")).unwrap();

        assert!(super::family_carries_a_manifest(&vectors, "versioned"));
        assert!(super::family_carries_a_manifest(&vectors, "flat"));
        assert!(
            !super::family_carries_a_manifest(&vectors, "bare"),
            "a version directory without manifest.json must not satisfy the gate"
        );
        assert!(!super::family_carries_a_manifest(&vectors, "absent"));
    }

    #[test]
    fn schema_validation_rejects_an_undefined_cddl_reference() {
        let error = super::validate_cddl_document("undefined.cddl", "root = missing-rule")
            .expect_err("undefined CDDL references must fail closed");

        assert!(error.contains("missing-rule"));
    }

    #[test]
    fn payload_vector_file_reader_caps_source_before_hex_decode() {
        const MAX_PLAINTEXT_BYTES_V1: usize = 1_048_576;
        const MAX_TEXT_BYTES_V1: usize = 2 * MAX_PLAINTEXT_BYTES_V1 + 1;

        struct TempDir(std::path::PathBuf);

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = TempDir(std::env::temp_dir().join(format!(
            "einsatzarchiv-payload-vector-cap-{}-{nonce}",
            std::process::id()
        )));
        std::fs::create_dir(&directory.0).unwrap();

        // A canonical CBOR byte string with a five-byte header and 1,048,571
        // content bytes occupies exactly MAX_PLAINTEXT_BYTES_V1 bytes.
        let mut cbor = vec![0x5a, 0x00, 0x0f, 0xff, 0xfb];
        cbor.resize(MAX_PLAINTEXT_BYTES_V1, 0);
        let mut source = Vec::with_capacity(MAX_TEXT_BYTES_V1);
        for byte in cbor {
            source.push(b"0123456789abcdef"[(byte >> 4) as usize]);
            source.push(b"0123456789abcdef"[(byte & 0x0f) as usize]);
        }
        source.push(b'\n');
        assert_eq!(source.len(), MAX_TEXT_BYTES_V1);

        let exact_path = directory.0.join("exact.hex");
        std::fs::write(&exact_path, &source).unwrap();
        super::validate_payload_vector_file(
            &exact_path,
            "exact.hex",
            "payload-test-v1",
            "payload-test-v1 = bstr",
        )
        .expect("the exact maximum lowercase-hex source plus one LF must validate");

        source.pop();
        source.push(b'0');
        source.push(b'\n');
        assert_eq!(source.len(), MAX_TEXT_BYTES_V1 + 1);
        let over_path = directory.0.join("over.hex");
        std::fs::write(&over_path, &source).unwrap();
        let error = super::validate_payload_vector_file(
            &over_path,
            "over.hex",
            "payload-test-v1",
            "payload-test-v1 = bstr",
        )
        .expect_err("one extra source character must fail before hex decoding");
        assert_eq!(
            error,
            "payload vector over.hex exceeds MAX_PAYLOAD_VECTOR_TEXT_BYTES_V1 = 2097153"
        );
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
    fn payload_projection_accepts_an_ordered_array_without_report_sort_extensions() {
        let schema = r#"{
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "personnel": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {"displayName": {"type": "string"}},
                        "required": ["displayName"],
                        "additionalProperties": false
                    }
                }
            },
            "required": ["personnel"],
            "additionalProperties": false
        }"#;
        let instance = serde_json::json!({
            "personnel": [
                {"displayName": "Zulu"},
                {"displayName": "Alpha"}
            ]
        });

        let validator = super::compile_json_schema_for_profile(
            "payload-projection.schema.json",
            schema,
            super::JsonSchemaProfile::PayloadProjection,
        )
        .expect("payload projection arrays preserve authoring order without report extensions");
        assert!(validator.is_valid(&instance));

        let report_error = super::compile_json_schema_for_profile(
            "deterministic-report.schema.json",
            schema,
            super::JsonSchemaProfile::DeterministicReport,
        )
        .expect_err("the same array must still fail the deterministic-report profile");
        assert!(report_error.contains("lacks x-ea-sort-key"));
    }

    #[test]
    fn checked_in_incident_projection_is_closed_and_preserves_authoring_order() {
        let schema = include_str!("../../../schemas/payload/v1/incident.schema.json");
        let validator = super::compile_json_schema_for_profile(
            "schemas/payload/v1/incident.schema.json",
            schema,
            super::JsonSchemaProfile::PayloadProjection,
        )
        .unwrap();
        let valid = serde_json::json!({
            "recordType": "incident",
            "recordId": "0112131415167018801a1b1c1d1e1f20",
            "schemaId": "ea.incident",
            "schemaVersion": 1,
            "finalizedAtDevice": 1798763400000_i64,
            "timezone": "America/New_York",
            "operator": {
                "organizationId": "10101010101010101010101010101010",
                "operatorSubjectId": "20202020202020202020202020202020",
                "displayName": "Erika Beispiel",
                "functionLabel": "Einsatzleitung",
                "salt": "3030303030303030303030303030303030303030303030303030303030303030",
                "operatorBindingObjectHash": "4040404040404040404040404040404040404040404040404040404040404040"
            },
            "source": {
                "kind": "native",
                "sourceId": "writer-native",
                "sourceFormatVersion": 1
            },
            "registryVersion": 7,
            "extensionData": [],
            "body": {
                "humanIncidentNumber": "2026-0001",
                "occurredAt": {"start": 1798763400000_i64, "end": null},
                "keyword": {"kind": "freeText", "text": "Brand"},
                "location": {"kind": "freeText", "freeText": "Hauptstraße", "coordinates": null},
                "personnel": [
                    {"kind": "adHoc", "displayName": "Zulu", "roleOrFunction": null},
                    {"kind": "adHoc", "displayName": "Alpha", "roleOrFunction": null}
                ],
                "personnelEmptyReason": null,
                "vehicles": [],
                "vehiclesEmptyReason": "Keine Fahrzeuge",
                "patientCountStatus": "known",
                "patientCount": 0,
                "notes": null,
                "externalOrganizations": []
            }
        });
        assert!(validator.is_valid(&valid));

        let mut unknown_nested = valid;
        unknown_nested["operator"]["rawIdentifier"] = serde_json::json!("secret");
        assert!(!validator.is_valid(&unknown_nested));
    }

    #[test]
    fn payload_integer_schemas_declare_exact_wire_bounds() {
        let schemas = [
            (
                "genesis",
                include_str!("../../../schemas/payload/v1/genesis.schema.json"),
            ),
            (
                "incident",
                include_str!("../../../schemas/payload/v1/incident.schema.json"),
            ),
            (
                "amendment",
                include_str!("../../../schemas/payload/v1/amendment.schema.json"),
            ),
            (
                "key-transition",
                include_str!("../../../schemas/payload/v1/key-transition.schema.json"),
            ),
            (
                "destruction-evidence",
                include_str!("../../../schemas/payload/v1/destruction-evidence.schema.json"),
            ),
        ];
        let mut issues = Vec::new();
        for (name, source) in schemas {
            let schema: serde_json::Value = serde_json::from_str(source).unwrap();
            collect_integer_bound_issues(name, "#", &schema, &mut issues);
        }
        assert!(
            issues.is_empty(),
            "every payload integer must declare its exact wire bounds:\n{}",
            issues.join("\n")
        );
    }

    #[test]
    fn checked_in_integer_bounds_accept_limits_and_reject_adjacent_values() {
        let genesis: serde_json::Value = serde_json::from_str(include_str!(
            "../../../schemas/payload/v1/genesis.schema.json"
        ))
        .unwrap();
        let incident: serde_json::Value = serde_json::from_str(include_str!(
            "../../../schemas/payload/v1/incident.schema.json"
        ))
        .unwrap();
        let destruction: serde_json::Value = serde_json::from_str(include_str!(
            "../../../schemas/payload/v1/destruction-evidence.schema.json"
        ))
        .unwrap();

        assert_integer_boundaries(
            "common finalizedAtDevice",
            &genesis["properties"]["finalizedAtDevice"],
            &["-9223372036854775808", "9223372036854775807"],
            &["-9223372036854775809", "9223372036854775808"],
        );
        assert_integer_boundaries(
            "common registryVersion",
            &genesis["properties"]["registryVersion"],
            &["0", "18446744073709551615"],
            &["-1", "18446744073709551616"],
        );
        assert_integer_boundaries(
            "nested Incident occurredAt.start",
            &incident["$defs"]["body"]["properties"]["occurredAt"]["properties"]["start"],
            &["-9223372036854775808", "9223372036854775807"],
            &["-9223372036854775809", "9223372036854775808"],
        );
        assert_integer_boundaries(
            "nested Destruction resultCode",
            &destruction["properties"]["body"]["properties"]["executionResults"]["items"]["properties"]
                ["resultCode"],
            &["0", "18446744073709551615"],
            &["-1", "18446744073709551616"],
        );
    }

    #[test]
    fn payload_source_ids_allow_kind_spellings_and_empty_text() {
        let schemas = [
            include_str!("../../../schemas/payload/v1/genesis.schema.json"),
            include_str!("../../../schemas/payload/v1/incident.schema.json"),
            include_str!("../../../schemas/payload/v1/amendment.schema.json"),
            include_str!("../../../schemas/payload/v1/key-transition.schema.json"),
            include_str!("../../../schemas/payload/v1/destruction-evidence.schema.json"),
        ];
        for source in schemas {
            let schema: serde_json::Value = serde_json::from_str(source).unwrap();
            let validator =
                jsonschema::validator_for(&schema["$defs"]["source"]["properties"]["sourceId"])
                    .unwrap();
            for allowed in ["writer-native", "legacyImport", "legacy-access-import"] {
                assert!(
                    validator.is_valid(&serde_json::Value::String(allowed.to_owned())),
                    "sourceId must not reserve kind spelling {allowed}"
                );
            }
            assert!(validator.is_valid(&serde_json::Value::String(String::new())));
        }
    }

    fn collect_integer_bound_issues(
        schema_name: &str,
        path: &str,
        value: &serde_json::Value,
        issues: &mut Vec<String>,
    ) {
        let declares_integer = match value.get("type") {
            Some(serde_json::Value::String(kind)) => kind == "integer",
            Some(serde_json::Value::Array(kinds)) => {
                kinds.iter().any(|kind| kind.as_str() == Some("integer"))
            }
            _ => false,
        };
        if declares_integer {
            let minimum = value.get("minimum").and_then(serde_json::Value::as_number);
            let maximum = value.get("maximum").and_then(serde_json::Value::as_number);
            let expected = expected_integer_bounds(path);
            match (minimum, maximum) {
                (Some(minimum), Some(maximum))
                    if !minimum.is_f64()
                        && !maximum.is_f64()
                        && (minimum.to_string(), maximum.to_string()) == expected => {}
                _ => issues.push(format!(
                    "{schema_name}{path}: expected {}..={}, got {}..={}",
                    expected.0,
                    expected.1,
                    minimum.map_or_else(|| "missing".to_owned(), ToString::to_string),
                    maximum.map_or_else(|| "missing".to_owned(), ToString::to_string),
                )),
            }
        }
        match value {
            serde_json::Value::Object(entries) => {
                for (key, child) in entries {
                    collect_integer_bound_issues(
                        schema_name,
                        &format!("{path}/{key}"),
                        child,
                        issues,
                    );
                }
            }
            serde_json::Value::Array(entries) => {
                for (index, child) in entries.iter().enumerate() {
                    collect_integer_bound_issues(
                        schema_name,
                        &format!("{path}/{index}"),
                        child,
                        issues,
                    );
                }
            }
            _ => {}
        }
    }

    fn expected_integer_bounds(path: &str) -> (String, String) {
        let field = path.rsplit('/').next().unwrap();
        match field {
            "finalizedAtDevice" | "changedAt" | "start" | "end" => (
                "-9223372036854775808".to_owned(),
                "9223372036854775807".to_owned(),
            ),
            "latE7" => ("-900000000".to_owned(), "900000000".to_owned()),
            "lonE7" => ("-1800000000".to_owned(), "1800000000".to_owned()),
            "patientCount" => ("0".to_owned(), "4294967295".to_owned()),
            _ => ("0".to_owned(), "18446744073709551615".to_owned()),
        }
    }

    fn assert_integer_boundaries(
        name: &str,
        schema: &serde_json::Value,
        accepted: &[&str],
        rejected: &[&str],
    ) {
        let validator = jsonschema::validator_for(schema).unwrap();
        for literal in accepted {
            let value = exact_integer(literal);
            assert!(validator.is_valid(&value), "{name} must accept {literal}");
        }
        for literal in rejected {
            let value = exact_integer(literal);
            assert!(
                !validator.is_valid(&value),
                "{name} must reject adjacent value {literal}"
            );
        }
    }

    fn exact_integer(literal: &str) -> serde_json::Value {
        let value: serde_json::Value = serde_json::from_str(literal).unwrap();
        let number = value.as_number().unwrap();
        assert_eq!(
            number.to_string(),
            literal,
            "integer literal must stay exact"
        );
        assert!(!number.is_f64(), "integer literal must not become a float");
        value
    }

    #[test]
    fn schema_array_contracts_reject_unsorted_and_duplicate_keys() {
        let verification: serde_json::Value = serde_json::from_str(include_str!(
            "../../../schemas/reports/v1/verification-report.schema.json"
        ))
        .unwrap();
        let inventory: serde_json::Value = serde_json::from_str(include_str!(
            "../../../schemas/reports/v1/key-inventory.schema.json"
        ))
        .unwrap();
        let families = [
            (
                "registryVersions",
                &verification["properties"]["registryVersions"],
                serde_json::json!([1, 2]),
                serde_json::json!([2, 1]),
                serde_json::json!([1, 1]),
            ),
            (
                "objectResults",
                &verification["properties"]["objectResults"],
                serde_json::json!([{"objectHash": "00"}, {"objectHash": "01"}]),
                serde_json::json!([{"objectHash": "01"}, {"objectHash": "00"}]),
                serde_json::json!([
                    {"objectHash": "00", "result": "valid"},
                    {"objectHash": "00", "result": "authorizedDestroyed"}
                ]),
            ),
            (
                "authorizedDestructions",
                &verification["properties"]["authorizedDestructions"],
                serde_json::json!([{"destructionId": "00"}, {"destructionId": "01"}]),
                serde_json::json!([{"destructionId": "01"}, {"destructionId": "00"}]),
                serde_json::json!([
                    {"destructionId": "00", "state": "requested"},
                    {"destructionId": "00", "state": "completeManagedScope"}
                ]),
            ),
            (
                "gaps",
                &verification["properties"]["gaps"],
                serde_json::json!([
                    {"chainId": "00", "fromSequence": 1},
                    {"chainId": "00", "fromSequence": 2}
                ]),
                serde_json::json!([
                    {"chainId": "00", "fromSequence": 2},
                    {"chainId": "00", "fromSequence": 1}
                ]),
                serde_json::json!([
                    {"chainId": "00", "fromSequence": 1, "throughSequence": 2},
                    {"chainId": "00", "fromSequence": 1, "throughSequence": 3}
                ]),
            ),
            (
                "errors",
                &verification["$defs"]["sortedErrors"],
                serde_json::json!([
                    {"objectHash": "00", "code": "a"},
                    {"objectHash": "00", "code": "b"}
                ]),
                serde_json::json!([
                    {"objectHash": "00", "code": "b"},
                    {"objectHash": "00", "code": "a"}
                ]),
                serde_json::json!([
                    {"objectHash": "00", "code": "a", "detail": 1},
                    {"objectHash": "00", "code": "a", "detail": 2}
                ]),
            ),
            (
                "publicKeyThumbprints",
                &verification["properties"]["publicKeyThumbprints"],
                serde_json::json!(["00", "01"]),
                serde_json::json!(["01", "00"]),
                serde_json::json!(["00", "00"]),
            ),
            (
                "media",
                &inventory["properties"]["media"],
                serde_json::json!([{"mediumId": "a"}, {"mediumId": "b"}]),
                serde_json::json!([{"mediumId": "b"}, {"mediumId": "a"}]),
                serde_json::json!([
                    {"mediumId": "a", "keyRole": "root"},
                    {"mediumId": "a", "keyRole": "writer"}
                ]),
            ),
        ];

        for (name, schema, sorted, unsorted, duplicate) in families {
            super::validate_canonical_array(name, schema, sorted.as_array().unwrap()).unwrap();
            let unsorted_error =
                super::validate_canonical_array(name, schema, unsorted.as_array().unwrap())
                    .expect_err("unsorted input must fail closed");
            assert!(
                unsorted_error.contains("not sorted"),
                "{name}: {unsorted_error}"
            );
            let duplicate_error =
                super::validate_canonical_array(name, schema, duplicate.as_array().unwrap())
                    .expect_err("duplicate sort keys must fail closed");
            assert!(
                duplicate_error.contains("duplicate key"),
                "{name}: {duplicate_error}"
            );
        }
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
                (
                    "cargo",
                    vec![
                        "check",
                        "--target",
                        "wasm32-unknown-unknown",
                        "--locked",
                        "-p",
                        "ea-types",
                        "-p",
                        "ea-cbor",
                        "-p",
                        "ea-crypto",
                        "-p",
                        "ea-format",
                        "-p",
                        "ea-schema",
                        "-p",
                        "ea-time",
                        "-p",
                        "ea-trust",
                        "-p",
                        "ea-archive",
                        "-p",
                        "ea-chain",
                        "-p",
                        "ea-verify",
                    ],
                ),
            ]
        );
    }

    #[test]
    fn toolchain_mismatch_voids_the_pinned_verification_run() {
        // rustup rewrites RUSTUP_TOOLCHAIN to the resolved toolchain for every
        // process it spawns, so the pinned run also carries the variable. Only the
        // comparison against the pinned channel distinguishes the two cases.
        assert_eq!(
            super::toolchain_mismatch_warning("1.95.0", "1.95.0-aarch64-apple-darwin"),
            None
        );
        assert_eq!(super::toolchain_mismatch_warning("1.95.0", "1.95.0"), None);
        assert_eq!(super::toolchain_mismatch_warning("", "1.97.1"), None);
        assert_eq!(super::toolchain_mismatch_warning("1.95.0", ""), None);

        let warning = super::toolchain_mismatch_warning("1.95.0", "1.97.1-aarch64-apple-darwin")
            .expect("a differing active toolchain must be reported");
        assert!(warning.contains("1.97.1-aarch64-apple-darwin"));
        assert!(warning.contains("1.95.0"));
        assert!(warning.contains("rust-toolchain.toml"));
        assert!(warning.contains("not a valid pinned-toolchain proof"));
    }

    #[test]
    fn pinned_channel_is_read_from_the_committed_toolchain_file() {
        let root = super::workspace_root();
        assert_eq!(
            super::pinned_toolchain_channel(&root).as_deref(),
            Some("1.95.0")
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
