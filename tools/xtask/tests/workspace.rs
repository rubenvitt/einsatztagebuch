use std::{collections::BTreeSet, fs, process::Command};
use toml::Value;

/// The workspace members, maintained as a set rather than as a count.
///
/// Every task that adds a member appends its path here and nowhere else: the
/// duplicate check, the comparison against `Cargo.toml` and the dependency walk
/// all read this list, so no task has to know how many members the workspace
/// has. A member added to one of the two files and forgotten in the other still
/// fails loudly.
const WORKSPACE_MEMBERS: &[&str] = &[
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
    "crates/ea-archive-fs",
    "crates/ea-chain",
    "crates/ea-verify",
    "crates/ea-reader",
    "crates/ea-reader-wasm",
    "crates/ea-recovery",
    "crates/ea-testkit",
    "crates/ea-key-provider",
    "crates/ea-operator",
    "crates/ea-local-store",
    "crates/ea-audit",
    "crates/ea-draft",
    "crates/ea-writer",
    "crates/ea-ui-contracts",
    "crates/ea-sync-protocol",
    "crates/ea-sync-server",
    "crates/ea-sync-client",
    "apps/server",
    "apps/cli",
    "apps/desktop/src-tauri",
];

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
    let members = member_array
        .iter()
        .map(|member| member.as_str().unwrap())
        .collect::<BTreeSet<_>>();
    let expected_members = WORKSPACE_MEMBERS.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(
        WORKSPACE_MEMBERS.len(),
        expected_members.len(),
        "WORKSPACE_MEMBERS must not list a member twice"
    );
    assert_eq!(
        member_array.len(),
        WORKSPACE_MEMBERS.len(),
        "workspace members must not be duplicated or omitted"
    );
    assert_eq!(members, expected_members);
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
    for &member in WORKSPACE_MEMBERS {
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
    // Lockfile-Vorschritt: --locked beweist, dass Cargo.lock zum Manifest passt.
    // Ein neues Mitglied oder eine neue Fremdabhaengigkeit schreibt Cargo.lock
    // neu, deshalb laeuft in dem Task, der sie eintraegt, GENAU EIN Kommando
    // ohne --locked: `cargo metadata --format-version 1`. Alle weiteren
    // Kommandos dieses Tasks tragen wieder --locked.
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

    // Ausnahmeliste: Paare aus Crate-Name und Begruendung, gelesen aus der
    // Deklaration selbst. Der Anker verlangt die Slice-Form: eine Liste mit
    // fester Arity zwingt jeden Task, der eine Ausnahme ergaenzt, zu einer
    // Zahlenaenderung, und genau die soll niemand mehr anfassen muessen.
    //
    // Der Positivlisten-Anker daruber ist das ERSTE zitierte
    // "wasm32-unknown-unknown" von main.rs und MUSS das in
    // verify_quick_commands() bleiben: ensure_wasm32_target_available() traegt
    // dasselbe Literal ein zweites Mal, in seiner Zielpruefung wie in seiner
    // rustup-Meldung. Bewusst ohne Zeilennummern, damit die Angabe nicht
    // abdriften kann.
    const EXEMPT_DECLARATION: &str = "const WASM32_EXEMPT_CRATES: &[(&str, &str)] = &[";
    let declaration_at = main_rs.find(EXEMPT_DECLARATION).expect(
        "tools/xtask/src/main.rs must declare WASM32_EXEMPT_CRATES as a slice literal so that a \
         new exception needs no arity edit",
    );
    let body_at = declaration_at + EXEMPT_DECLARATION.len();
    let body_end = body_at
        + main_rs[body_at..]
            .find("];")
            .expect("WASM32_EXEMPT_CRATES must be terminated with `];`");
    let entries = quoted_literals(&main_rs[body_at..body_end]);
    assert!(
        !entries.is_empty(),
        "WASM32_EXEMPT_CRATES must list at least one justified exception"
    );
    let mut exempt_list = BTreeSet::new();
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
fn rust_toolchain_declares_wasm32_and_no_release_target() {
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
    for release_target in [
        "x86_64-pc-windows-msvc",
        "x86_64-unknown-linux-gnu",
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
    ] {
        assert!(
            !targets
                .iter()
                .any(|target| target.as_str() == Some(release_target)),
            "{release_target} carries the signed min/max release proof of Stage 7. This stage \
             proves buildability for the host target only, so the pinned toolchain must not \
             provision it and no task may run a cross-target check against it."
        );
    }
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

/// Pins that every shared dependency is exact.
///
/// `docs/adr/0001-toolchain-and-cryptography-dependencies.md:15` states that all
/// version requirements in `[workspace.dependencies]` are exact; `deny.toml:6`
/// denies wildcards but no gate invokes cargo-deny. An entry may omit a version
/// only when it is a path member of this workspace, so a `git` or registry entry
/// cannot slip through the hole between the two shapes.
#[test]
fn every_workspace_dependency_is_pinned_exactly() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest: Value = fs::read_to_string(root.join("Cargo.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let dependencies = manifest["workspace"]["dependencies"].as_table().unwrap();
    for (name, entry) in dependencies {
        let requirement = match entry {
            Value::String(requirement) => Some(requirement.as_str()),
            Value::Table(spec) => spec.get("version").and_then(Value::as_str),
            _ => panic!("workspace dependency {name} must be a version string or a table"),
        };
        match requirement {
            Some(requirement) => assert!(
                requirement.starts_with('='),
                "workspace dependency {name} must pin an exact version (=x.y.z), found \
                 {requirement}"
            ),
            None => assert!(
                entry
                    .as_table()
                    .is_some_and(|spec| spec.contains_key("path")),
                "workspace dependency {name} declares no version; only path members of this \
                 workspace may do that"
            ),
        }
    }
}

#[test]
fn workspace_serde_is_pinned_with_derive() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest: Value = fs::read_to_string(root.join("Cargo.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let serde = &manifest["workspace"]["dependencies"]["serde"];
    assert_eq!(serde["version"].as_str(), Some("=1.0.229"));
    let features = serde["features"]
        .as_array()
        .expect("serde must declare features so members inherit the derive macro");
    assert!(
        features
            .iter()
            .any(|feature| feature.as_str() == Some("derive")),
        "serde must enable derive; the desktop DTO surface has no other source for it"
    );
}

/// Pins the release exclusion of the `ea-archive-fs` test surface.
///
/// `test-support` is a DEFAULT feature for a Cargo reason: an integration test
/// cannot enable a feature of its own crate, and the usual way out — a
/// self dev-dependency — would rewrite `Cargo.lock`. The residual risk is not
/// the readers but the three MUTATING methods: `overwrite_for_test` bypasses
/// create-if-absent and `remove_for_test` deletes archive bytes, so in a
/// default build both are `pub`. Two things therefore have to hold, and this
/// test pins both: the manifest names the three methods as a release exclusion
/// together with the `--no-default-features` release build, and no
/// `*_for_test` method sits in the crate OUTSIDE the feature gate.
#[test]
fn ea_archive_fs_names_its_mutating_test_surface_as_a_release_exclusion() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest_text = fs::read_to_string(root.join("crates/ea-archive-fs/Cargo.toml")).unwrap();
    let manifest: Value = manifest_text.parse().unwrap();
    assert_eq!(
        manifest["features"]["default"].as_array().map(|d| d.len()),
        Some(1),
        "test-support stays the single default feature; a second one would widen the release \
         surface silently"
    );
    assert_eq!(
        manifest["features"]["default"][0].as_str(),
        Some("test-support")
    );
    const MUTATORS: [&str; 3] = [
        "overwrite_for_test",
        "materialize_for_test",
        "remove_for_test",
    ];
    for mutator in MUTATORS {
        assert!(
            manifest_text.contains(mutator),
            "{mutator} mutates archive bytes and must be named in the manifest as a release \
             exclusion, so a Stage 7 release build cannot forget it"
        );
    }
    assert!(
        manifest_text.contains("--no-default-features"),
        "the manifest must state that the Stage 7 release build drops the default feature"
    );

    let source = fs::read_to_string(root.join("crates/ea-archive-fs/src/local_path.rs")).unwrap();
    let gate = source
        .find("#[cfg(any(test, feature = \"test-support\"))]")
        .expect("the observation surface must live behind the test-support gate");
    for method in MUTATORS {
        let declaration = format!("pub fn {method}(");
        let at = source
            .find(&declaration)
            .unwrap_or_else(|| panic!("{method} must exist; it is named in the manifest"));
        assert!(
            at > gate,
            "{method} must be declared behind the test-support gate, never in the unconditional \
             surface of a release build"
        );
    }
    for (index, _) in source.match_indices("pub fn ") {
        let tail = &source[index..];
        let name_end = tail.find('(').expect("a declaration carries parentheses");
        if tail[..name_end].contains("_for_test") {
            assert!(
                index > gate,
                "every *_for_test method must sit behind the gate: {}",
                &tail[..name_end]
            );
        }
    }
}

/// Pins that NO non-test edge carries the `ea-archive-fs` test surface — read
/// off the RESOLVED feature graph and not off manifest prose.
///
/// The neighbouring test pins the manifest text and the position of the three
/// mutating methods behind the `cfg`. Both held while the surface was still in
/// the host: `test-support` is a DEFAULT feature, `apps/desktop/src-tauri`
/// inherited it, and `overwrite_for_test` (bypasses create-if-absent),
/// `materialize_for_test` and `remove_for_test` (deletes archive bytes) were
/// therefore `pub` in the shipped binary. The promise rested on "nobody calls
/// them" instead of on "they are not there".
///
/// Three assertions, and the third is the one that cannot be satisfied by
/// prose:
///
/// 1. the SHARED workspace edge disables the default features (Cargo rejects
///    `default-features = false` next to `workspace = true` at the member, so
///    the switch has to sit here — and here it is fail-closed: a new member
///    inherits no test surface),
/// 2. no `[dependencies]` or `[build-dependencies]` entry of any member asks
///    for `test-support` — only `[dev-dependencies]` may,
/// 3. `cargo tree -e features` resolves the host's graph WITHOUT the feature.
///
/// Assertion 3 carries its own positive control: an empty tree, a failed
/// command or a mistyped package name would all be free of `test-support` and
/// would otherwise pass.
#[test]
fn no_non_test_edge_carries_the_ea_archive_fs_test_surface() {
    const CRATE: &str = "ea-archive-fs";
    const SURFACE: &str = "test-support";
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");

    let root_manifest: Value = fs::read_to_string(root.join("Cargo.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let shared = root_manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(|dependencies| dependencies.get(CRATE))
        .unwrap_or_else(|| panic!("the workspace must declare the shared {CRATE} edge"));
    assert_eq!(
        shared.get("default-features").and_then(Value::as_bool),
        Some(false),
        "the shared {CRATE} edge must disable its default features; otherwise every member \
         inherits the three mutating test methods"
    );

    let mut dev_edges = 0_usize;
    for member in WORKSPACE_MEMBERS {
        let manifest: Value = fs::read_to_string(root.join(member).join("Cargo.toml"))
            .unwrap()
            .parse()
            .unwrap();
        for table in ["dependencies", "build-dependencies", "dev-dependencies"] {
            let Some(edge) = manifest.get(table).and_then(|deps| deps.get(CRATE)) else {
                continue;
            };
            let asks_for_the_surface =
                edge.get("features")
                    .and_then(Value::as_array)
                    .is_some_and(|features| {
                        features
                            .iter()
                            .any(|feature| feature.as_str() == Some(SURFACE))
                    });
            if table == "dev-dependencies" {
                if asks_for_the_surface {
                    dev_edges += 1;
                }
                continue;
            }
            assert!(
                !asks_for_the_surface,
                "{member} {table} re-enables {CRATE}/{SURFACE}; the three mutating methods would \
                 be back in a non-test build"
            );
        }
    }
    assert!(
        dev_edges > 0,
        "no dev edge asks for {CRATE}/{SURFACE} any more — then this test proves nothing about a \
         surface that is still reachable elsewhere"
    );

    // Der aufgeloeste Baum des WIRTS. `-e features` zeigt die Merkmalskanten,
    // `-i` dreht ihn auf die Verbraucher von `ea-archive-fs`.
    let resolved = Command::new("cargo")
        .args([
            "tree",
            "--locked",
            "-p",
            "ea-desktop",
            "-e",
            "features",
            "-i",
            CRATE,
        ])
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(
        resolved.status.success(),
        "cargo tree must resolve the host graph: {}",
        String::from_utf8_lossy(&resolved.stderr)
    );
    let tree = String::from_utf8(resolved.stdout).unwrap();
    // Positivkontrolle: der Baum enthaelt die Kante, die geprueft werden soll.
    // Ohne sie waere die Abwesenheit des Merkmals kein Befund.
    for consumer in ["ea-desktop", "ea-writer", "ea-ui-contracts"] {
        assert!(
            tree.contains(consumer),
            "{consumer} must appear as a consumer of {CRATE} in the resolved tree; without the \
             edge the assertion below cannot fail:\n{tree}"
        );
    }
    assert!(
        !tree.contains(SURFACE),
        "the resolved feature graph of the host must not contain {CRATE}/{SURFACE}:\n{tree}"
    );
}
