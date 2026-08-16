use std::{collections::BTreeSet, fs, process::Command};
use toml::Value;

#[test]
fn workspace_declares_exact_planned_members_and_shared_dependencies() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    assert!(root.join("Cargo.lock").is_file());
    assert!(root.join("pnpm-lock.yaml").is_file());
    let root_manifest: Value = fs::read_to_string(root.join("Cargo.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let member_array = root_manifest["workspace"]["members"].as_array().unwrap();
    assert_eq!(
        member_array.len(),
        12,
        "workspace members must not be duplicated or omitted"
    );
    let members = member_array
        .iter()
        .map(|member| member.as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        members,
        BTreeSet::from([
            "tools/xtask",
            "tests/ea-system-tests",
            "crates/ea-types",
            "crates/ea-cbor",
            "crates/ea-crypto",
            "crates/ea-format",
            "crates/ea-schema",
            "crates/ea-time",
            "crates/ea-trust",
            "crates/ea-archive",
            "crates/ea-chain",
            "crates/ea-verify",
        ])
    );
    let workspace_dependencies = root_manifest["workspace"]["dependencies"]
        .as_table()
        .unwrap();
    assert!(
        !workspace_dependencies.is_empty(),
        "workspace.dependencies must contain shared dependencies"
    );
    for (dependency, path) in [
        ("ea-time", "crates/ea-time"),
        ("ea-trust", "crates/ea-trust"),
    ] {
        assert_eq!(
            workspace_dependencies
                .get(dependency)
                .and_then(Value::as_table)
                .and_then(|spec| spec.get("path"))
                .and_then(Value::as_str),
            Some(path),
            "{dependency} must be a local workspace dependency"
        );
    }
    for member in [
        "tools/xtask",
        "tests/ea-system-tests",
        "crates/ea-types",
        "crates/ea-cbor",
        "crates/ea-crypto",
        "crates/ea-format",
        "crates/ea-schema",
        "crates/ea-time",
        "crates/ea-trust",
        "crates/ea-archive",
        "crates/ea-chain",
        "crates/ea-verify",
    ] {
        let manifest: Value = fs::read_to_string(root.join(member).join("Cargo.toml"))
            .unwrap()
            .parse()
            .unwrap();
        let mut member_dependency_references = 0;
        for table_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
            if let Some(dependencies) = manifest.get(table_name).and_then(Value::as_table) {
                for (name, dependency) in dependencies {
                    member_dependency_references += 1;
                    assert!(
                        workspace_dependencies.contains_key(name),
                        "{member} {table_name} dependency {name} is not shared at workspace scope"
                    );
                    assert_eq!(
                        dependency
                            .as_table()
                            .and_then(|spec| spec.get("workspace"))
                            .and_then(Value::as_bool),
                        Some(true),
                        "{member} {table_name} dependency {name} must use workspace = true"
                    );
                }
            }
        }
        if member != "crates/ea-types" {
            assert!(
                member_dependency_references > 0,
                "{member} must reference at least one shared workspace dependency"
            );
        }
    }
    assert!(
        Command::new("cargo")
            .args(["metadata", "--locked", "--no-deps"])
            .current_dir(root)
            .status()
            .unwrap()
            .success()
    );
}

/// Collects every double-quoted literal of `text`, in order of appearance.
///
/// The regions this test slices out of `tools/xtask/src/main.rs` contain no
/// escaped quotes and no raw strings, so alternating on `"` is exact.
fn quoted_literals(text: &str) -> Vec<&str> {
    let parts: Vec<&str> = text.split('"').collect();
    assert!(
        !parts.len().is_multiple_of(2),
        "unbalanced string literals in the sliced region"
    );
    parts.into_iter().skip(1).step_by(2).collect()
}

/// Pins that the wasm32 gate classifies every library crate, and that the
/// Stage 1 plan prints the same positive list.
///
/// `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §9
/// makes the verification pipeline shared Rust code that runs in the browser
/// and §10 makes `wasm32-unknown-unknown` a binding gate target. A comment
/// asking future authors to extend the positive list is not enforceable; this
/// assertion is. Every member under `crates/` must be either on the positive
/// list or on the justified exception list, never on both and never on
/// neither.
#[test]
fn every_crates_member_is_classified_for_the_wasm32_gate() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let root_manifest: Value = fs::read_to_string(root.join("Cargo.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let library_members = root_manifest["workspace"]["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|member| member.as_str().unwrap())
        .filter(|member| member.starts_with("crates/"))
        .collect::<BTreeSet<_>>();
    assert!(
        !library_members.is_empty(),
        "the workspace must declare library crates under crates/"
    );

    let main_rs = fs::read_to_string(root.join("tools/xtask/src/main.rs")).unwrap();

    // Positivliste: die -p-Namen des wasm32-Blocks in verify_quick_commands().
    // Anker ist das ZITIERTE Ziel, nicht das Wort — der erklaerende Kommentar
    // darueber nennt wasm32-unknown-unknown ebenfalls.
    let target_literal = "\"wasm32-unknown-unknown\"";
    let target_at = main_rs
        .find(target_literal)
        .expect("verify_quick_commands() must run a wasm32-unknown-unknown check");
    let block_end = target_at
        + main_rs[target_at..]
            .find(']')
            .expect("the wasm32 argument vector must be closed");
    let block_literals = quoted_literals(&main_rs[target_at..block_end]);
    let mut positive_list = BTreeSet::new();
    let mut literals = block_literals.iter();
    while let Some(literal) = literals.next() {
        if *literal == "-p" {
            let name = literals
                .next()
                .expect("every -p in the wasm32 block must name a package");
            assert!(
                positive_list.insert(*name),
                "{name} is listed twice on the wasm32 positive list"
            );
        }
    }

    // Ausnahmeliste: Paare aus Crate-Name und Begruendung. Fehlt die Konstante,
    // ist die Liste leer — dann muss jedes Mitglied auf der Positivliste stehen.
    let mut exempt_list = BTreeSet::new();
    if let Some(exempt_at) = main_rs.find("WASM32_EXEMPT_CRATES") {
        let tail = &main_rs[exempt_at..];
        let body_at = tail
            .find("= [")
            .expect("WASM32_EXEMPT_CRATES must be initialised with an array literal");
        let body_end = body_at
            + tail[body_at..]
                .find("];")
                .expect("WASM32_EXEMPT_CRATES must be terminated with `];`");
        let entries = quoted_literals(&tail[body_at..body_end]);
        assert!(
            entries.len().is_multiple_of(2),
            "every WASM32_EXEMPT_CRATES entry must carry a crate name and a justification"
        );
        for entry in entries.chunks(2) {
            let (name, justification) = (entry[0], entry[1]);
            assert!(
                !justification.trim().is_empty(),
                "the WASM32_EXEMPT_CRATES entry for {name} must state a justification"
            );
            assert!(
                exempt_list.insert(name),
                "{name} is listed twice on the wasm32 exception list"
            );
        }
    }

    let mut member_names = BTreeSet::new();
    for member in &library_members {
        let name = member.strip_prefix("crates/").unwrap();
        member_names.insert(name);
        let on_positive_list = positive_list.contains(name);
        let on_exempt_list = exempt_list.contains(name);
        assert!(
            on_positive_list || on_exempt_list,
            "{member} is neither on the wasm32 positive list nor on the justified \
             exception list in tools/xtask/src/main.rs"
        );
        assert!(
            !(on_positive_list && on_exempt_list),
            "{member} is on both the wasm32 positive list and the exception list in \
             tools/xtask/src/main.rs; exactly one classification is allowed"
        );
    }
    for classified in positive_list.iter().chain(exempt_list.iter()) {
        assert!(
            member_names.contains(classified),
            "the wasm32 classification in tools/xtask/src/main.rs names {classified}, \
             which is not a workspace member under crates/"
        );
    }

    // G2: die Kommandozeile in Task 11 Step 4 des Stage-1-Plans nennt genau die
    // Positivliste.
    let stage_one = fs::read_to_string(
        root.join("docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md"),
    )
    .unwrap();
    let gate_line = stage_one
        .lines()
        .find(|line| {
            line.trim_start()
                .starts_with("cargo check --target wasm32-unknown-unknown --locked")
        })
        .expect("stage 1 plan Task 11 Step 4 must print the wasm32 gate command");
    let mut planned = BTreeSet::new();
    let mut tokens = gate_line.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "-p" {
            planned.insert(
                tokens
                    .next()
                    .expect("every -p in the plan command must name a package"),
            );
        }
    }
    assert_eq!(
        planned, positive_list,
        "stage 1 plan Task 11 Step 4 must run the wasm32 check over exactly the \
         positive list of tools/xtask/src/main.rs"
    );
}

#[test]
fn rust_toolchain_declares_the_wasm32_target() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let toolchain: Value = fs::read_to_string(root.join("rust-toolchain.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let targets = toolchain["toolchain"]["targets"]
        .as_array()
        .expect("rust-toolchain.toml must declare targets so a fresh checkout provisions wasm32");
    assert!(
        targets
            .iter()
            .any(|target| target.as_str() == Some("wasm32-unknown-unknown")),
        "wasm32-unknown-unknown must be provisioned by the pinned toolchain"
    );
}

#[test]
fn workspace_getrandom_enables_the_wasm_js_feature() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest: Value = fs::read_to_string(root.join("Cargo.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let getrandom = &manifest["workspace"]["dependencies"]["getrandom"];
    assert_eq!(getrandom["version"].as_str(), Some("=0.4.3"));
    let features = getrandom["features"]
        .as_array()
        .expect("getrandom must declare features so wasm32 resolves a backend");
    assert!(
        features.iter().any(|f| f.as_str() == Some("wasm_js")),
        "getrandom must enable wasm_js; getrandom 0.4.3 needs no --cfg getrandom_backend"
    );
}
