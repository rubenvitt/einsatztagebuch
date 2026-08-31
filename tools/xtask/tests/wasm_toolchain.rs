// tools/xtask/tests/wasm_toolchain.rs — die drei Orte, an denen dieselbe
// wasm-bindgen-Fassung steht, muessen zeichengleich sein. Der Spike hat genau
// diesen Bruch gemessen: ein frei aufgeloestes Lockfile lief auf 0.2.127,
// waehrend die CLI 0.2.126 war, und `wasm-bindgen` bricht dann mit einem
// Schema-Mismatch ab statt mit einer Codeaussage.
//
// Ein EIGENES Testziel und kein Anhang an `integration_services.rs`: die
// beiden pruefen verschiedene Vorbedingungen und muessen einzeln fahrbar
// bleiben. `run_gate` wird dabei in der Gestalt uebernommen, die
// `tools/xtask/tests/integration_services.rs` bereits fuehrt — ein
// Integrationstestziel kann keine Hilfsfunktion eines anderen Ziels sehen,
// die Wiederholung ist eine Sprachgrenze und keine Duplikation einer
// Entscheidung.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use toml::Value;

/// Reads the workspace root the way `tools/xtask/tests/adr_gate.rs` does.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Ruft das gebaute `xtask`-Binaer und trennt Erfolg von Fehlermeldung.
///
/// `main` schreibt jeden Fehler als `xtask: {error}` nach stderr und beendet
/// sich mit 2; das Praefix wird hier abgeschnitten, damit der Test den
/// Wortlaut der Fehlermeldung selbst pruefen kann.
fn run_gate<const N: usize>(args: [&str; N]) -> Result<String, String> {
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .output()
        .expect("xtask must start");
    let stdout = String::from_utf8(output.stdout).expect("xtask stdout must be UTF-8");
    if output.status.success() {
        return Ok(stdout);
    }
    let stderr = String::from_utf8(output.stderr).expect("xtask stderr must be UTF-8");
    Err(stderr
        .lines()
        .find_map(|line| line.strip_prefix("xtask: "))
        .unwrap_or_else(|| panic!("xtask must report its failure on stderr: {stderr}"))
        .to_owned())
}

/// Liest die von Cargo AUFGELOESTE Fassung eines Pakets aus `Cargo.lock`.
fn locked_version(root: &Path, name: &str) -> String {
    let lock: Value = fs::read_to_string(root.join("Cargo.lock"))
        .expect("Cargo.lock must be readable")
        .parse()
        .expect("Cargo.lock must be valid TOML");
    lock["package"]
        .as_array()
        .expect("Cargo.lock must declare [[package]] entries")
        .iter()
        .find(|package| package["name"].as_str() == Some(name))
        .and_then(|package| package["version"].as_str())
        .unwrap_or_else(|| panic!("Cargo.lock must lock {name}; it is not a resolved dependency"))
        .to_owned()
}

/// Liest den exakten Pin eines geteilten Workspace-Abhaengigkeit, mit dem
/// fuehrenden `=` abgeschnitten, damit er direkt gegen [`locked_version`]
/// verglichen werden kann.
fn shared_dependency_pin(root: &Path, name: &str) -> String {
    let manifest: Value = fs::read_to_string(root.join("Cargo.toml"))
        .expect("Cargo.toml must be readable")
        .parse()
        .expect("Cargo.toml must be valid TOML");
    let dependencies = manifest["workspace"]["dependencies"]
        .as_table()
        .expect("Cargo.toml must declare [workspace.dependencies]");
    let version = dependencies
        .get(name)
        .unwrap_or_else(|| panic!("{name} must be a shared workspace dependency"))
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{name} must carry an explicit version in [workspace.dependencies]"));
    version
        .strip_prefix('=')
        .unwrap_or_else(|| panic!("{name} must be pinned exactly (= prefix), found {version}"))
        .to_owned()
}

/// Liest den Werkzeugpin eines `cargo:`-Backends aus `mise.toml`.
fn mise_cargo_tool_pin(root: &Path, tool: &str) -> String {
    let manifest: Value = fs::read_to_string(root.join("mise.toml"))
        .expect("mise.toml must be readable")
        .parse()
        .expect("mise.toml must be valid TOML");
    let tools = manifest["tools"]
        .as_table()
        .expect("mise.toml must carry a [tools] table");
    tools
        .get(&format!("cargo:{tool}"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("mise.toml must pin cargo:{tool}"))
        .to_owned()
}

/// Liest den Quelltext von `tools/xtask/src/main.rs`.
///
/// `build_wasm_builds_without_inherited_rustflags` prueft eine SOURCE-Aussage
/// (`env_remove("RUSTFLAGS")`) und keine Laufzeitaussage: das Verhalten selbst
/// ist unbeobachtbar, solange `crates/ea-reader-wasm` nicht existiert.
fn build_wasm_command_source() -> String {
    fs::read_to_string(workspace_root().join("tools/xtask/src/main.rs"))
        .expect("tools/xtask/src/main.rs must be readable")
}

#[test]
fn the_wasm_bindgen_cli_pin_equals_the_locked_crate_version() {
    let root = workspace_root();
    let locked = locked_version(&root, "wasm-bindgen");
    assert_eq!(
        locked,
        shared_dependency_pin(&root, "wasm-bindgen"),
        "Cargo.lock and [workspace.dependencies] must agree on wasm-bindgen"
    );
    assert_eq!(
        locked,
        mise_cargo_tool_pin(&root, "wasm-bindgen-cli"),
        "mise.toml must pin wasm-bindgen-cli to the locked wasm-bindgen version"
    );
}

#[test]
fn build_wasm_rejects_every_argument_and_reports_the_missing_bridge_crate() {
    assert_eq!(
        run_gate(["build-wasm", "reader"]).unwrap_err(),
        "build-wasm does not accept arguments"
    );
    assert_eq!(run_gate(["build-wasmm"]).unwrap_err(), "unknown gate: build-wasmm");
    // Solange `crates/ea-reader-wasm/Cargo.toml` fehlt, meldet der Vorlauf das
    // FEHLENDE ARTEFAKT mit einer Anweisung statt einen cargo-Fehler
    // durchzureichen. Kein Ueberspringen ueber eine Umgebungsvariable.
    assert!(
        run_gate(["build-wasm"])
            .unwrap_err()
            .contains("crates/ea-reader-wasm"),
        "build-wasm must name the missing bridge crate"
    );
}

#[test]
fn build_wasm_builds_without_inherited_rustflags() {
    // getrandom 0.4.3 waehlt sein wasm-Backend ueber das Cargo-Feature
    // `wasm_js`; ein geerbtes `--cfg getrandom_backend=...` aus 0.3 wuerde das
    // Feature ueberstimmen. Der Bau laeuft deshalb mit entferntem RUSTFLAGS.
    assert!(
        build_wasm_command_source().contains("env_remove(\"RUSTFLAGS\")"),
        "build-wasm must strip RUSTFLAGS before it invokes cargo"
    );
}
