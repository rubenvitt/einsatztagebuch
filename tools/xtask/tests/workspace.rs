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
    "crates/ea-index",
    "crates/ea-schema",
    "crates/ea-time",
    "crates/ea-trust",
    "crates/ea-archive",
    "crates/ea-archive-fs",
    "crates/ea-chain",
    "crates/ea-demo-world",
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
    "crates/ea-destruction",
    "crates/ea-writer",
    "crates/ea-ui-contracts",
    "crates/ea-sync-protocol",
    "crates/ea-sync-server",
    "crates/ea-sync-client",
    "crates/ea-admin",
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

/// Every dependency table of one member manifest whose kind is in `kinds`,
/// labelled for failure messages — the top-level tables AND their
/// platform-specific twins under `[target.'cfg(..)'.<kind>]`.
///
/// Die Plattformtabellen gehören dazu, weil Cargo sie beim Bau für die
/// passende Zielplattform genauso auflöst wie die allgemeinen: eine Kante in
/// `[target.'cfg(windows)'.dependencies]` landet im Windows-Build, und Windows
/// ist Auslieferungsplattform. `crates/ea-admin/Cargo.toml` nutzt solche
/// Tabellen bereits; eine Prüfung nur der drei allgemeinen Tabellen sähe eine
/// dort eingeschmuggelte Testfläche nicht.
fn dependency_tables<'a>(manifest: &'a Value, kinds: &[&str]) -> Vec<(String, &'a toml::Table)> {
    let mut tables = Vec::new();
    for kind in kinds {
        if let Some(table) = manifest.get(*kind).and_then(Value::as_table) {
            tables.push(((*kind).to_owned(), table));
        }
    }
    if let Some(platforms) = manifest.get("target").and_then(Value::as_table) {
        for (platform, section) in platforms {
            for kind in kinds {
                if let Some(table) = section.get(*kind).and_then(Value::as_table) {
                    tables.push((format!("[target.'{platform}'.{kind}]"), table));
                }
            }
        }
    }
    tables
}

/// Whether a dependency entry asks for `feature` by name.
fn edge_asks_for(edge: &Value, feature: &str) -> bool {
    edge.get("features")
        .and_then(Value::as_array)
        .is_some_and(|features| features.iter().any(|entry| entry.as_str() == Some(feature)))
}

/// The workspace members that are a production build ON THEIR OWN: every
/// member with a `bin`, `cdylib` or `staticlib` target, read from
/// `cargo metadata` and not from a hand-kept list.
///
/// Die Regel folgt einer Eigenschaft und keiner Namensliste: nur ein solches
/// Ziel wird selbst ausgeliefert (Server- und CLI-Binärdatei, der Tauri-Wirt
/// als Binärdatei, das wasm-Modul als `cdylib`). Ein reines `lib`-Mitglied
/// erreicht einen Build nur über einen dieser Wirte und ist damit über dessen
/// Graphen mitgeprüft; ein Paket nur aus `lib`- und `test`-Zielen wie
/// `tests/ea-system-tests` fällt so von selbst heraus, `example`-Ziele zählen
/// nicht. `publish = false` taugt als Unterscheidung nicht — JEDES Mitglied
/// dieses Arbeitsbereichs trägt es. `tools/xtask` bleibt als Binärdatei
/// bewusst drin: es liefert zwar nichts aus, aber sein Graph kostet einen
/// Aufruf von Zehntelsekunden, und eine Ausnahme per Name wäre genau die
/// Liste, die ein neuer Wirt nicht kennen würde.
fn production_hosts(root: &std::path::Path) -> Vec<String> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps", "--locked"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "cargo metadata must describe the workspace: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let members: BTreeSet<&str> = metadata["workspace_members"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    let mut hosts = Vec::new();
    for package in metadata["packages"].as_array().unwrap() {
        if !members.contains(package["id"].as_str().unwrap()) {
            continue;
        }
        let ships = package["targets"].as_array().unwrap().iter().any(|target| {
            target["kind"]
                .as_array()
                .unwrap()
                .iter()
                .any(|kind| matches!(kind.as_str(), Some("bin" | "cdylib" | "staticlib")))
        });
        if ships {
            hosts.push(package["name"].as_str().unwrap().to_owned());
        }
    }
    hosts.sort();
    // Untergrenze gegen eine leere oder verstümmelte Ableitung: fiele die
    // Liste leer aus, bestünde jede Prüfung über sie hinweg ohne Befund. Die
    // Namen hier sind Beispiele, die dabei sein MÜSSEN, nicht der Umfang.
    for known in [
        "einsatzarchiv-cli",
        "ea-desktop",
        "einsatzarchiv-server",
        "ea-reader-wasm",
    ] {
        assert!(
            hosts.iter().any(|host| host == known),
            "{known} ships a bin or cdylib and must be derived as a production host: {hosts:?}"
        );
    }
    hosts
}

/// Runs `cargo tree --locked <arguments>` in the workspace root and returns
/// its output; a failing command fails the test instead of yielding an empty
/// (and therefore clean-looking) tree.
fn cargo_tree(root: &std::path::Path, arguments: &[&str]) -> String {
    let mut full = vec!["tree", "--locked"];
    full.extend_from_slice(arguments);
    let resolved = Command::new("cargo")
        .args(&full)
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        resolved.status.success(),
        "cargo {} must resolve: {}",
        full.join(" "),
        String::from_utf8_lossy(&resolved.stderr)
    );
    String::from_utf8(resolved.stdout).unwrap()
}

/// Asserts that no derived production host resolves `<krate>/<surface>` in its
/// normal (`no-dev`) feature graph on ANY platform (`--target all`).
///
/// Der volle Baum und nicht `-i <krate>`: ein Wirt, der die Crate gar nicht
/// zieht, ließe `cargo tree -i` mit „did not match any packages" scheitern,
/// und dieser Wirt ist gerade der, über den eine neue Kante hereinkäme. Die
/// Positivkontrolle pro Wirt ist deshalb, dass der Baum mit dem Wirt selbst
/// beginnt — ein vertippter Name oder eine leere Ausgabe scheitert daran. Im
/// Fehlerfall zeigt der invertierte Baum den Weg zur Fläche.
fn assert_no_host_resolves(root: &std::path::Path, krate: &str, surface: &str) {
    let surface_node = format!("{krate} feature \"{surface}\"");
    for host in production_hosts(root) {
        let shipped = cargo_tree(
            root,
            &["-p", &host, "-e", "no-dev,features", "--target", "all"],
        );
        assert!(
            shipped.starts_with(&format!("{host} v")),
            "the resolved tree of {host} must start with {host} itself:\n{shipped}"
        );
        if shipped.contains(&surface_node) {
            let path = cargo_tree(
                root,
                &[
                    "-p",
                    &host,
                    "-e",
                    "no-dev,features",
                    "--target",
                    "all",
                    "-i",
                    krate,
                ],
            );
            panic!(
                "the production host {host} resolves {krate}/{surface} through a normal edge on \
                 some platform:\n{path}"
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
        for (table, dependencies) in dependency_tables(
            &manifest,
            &["dependencies", "build-dependencies", "dev-dependencies"],
        ) {
            let Some(edge) = dependencies.get(CRATE) else {
                continue;
            };
            let asks_for_the_surface = edge_asks_for(edge, SURFACE);
            if table.trim_end_matches(']').ends_with("dev-dependencies") {
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
    // `-i` dreht ihn auf die Verbraucher von `ea-archive-fs`. `no-dev` nimmt
    // die eigenen `[dev-dependencies]` des Wirts heraus: Zusicherung 2 erlaubt
    // genau diese Kanten, und seit der Wirt Testziele mit echtem Writer hat,
    // fordert er das Merkmal dort selbst an. `--target all` löst die Kanten
    // ALLER Zielplattformen auf, nicht nur die des Rechners, auf dem der Test
    // läuft.
    let resolve = |edges: &str| {
        cargo_tree(
            &root,
            &[
                "-p",
                "ea-desktop",
                "-e",
                edges,
                "--target",
                "all",
                "-i",
                CRATE,
            ],
        )
    };
    let tree = resolve("no-dev,features");
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
    // Zweite Positivkontrolle: mit den Dev-Kanten erscheint das Merkmal. Sonst
    // saegte `no-dev` nur die Sicht ab und die Abwesenheit oben saegte nichts.
    let with_dev = resolve("features");
    assert!(
        with_dev.contains(SURFACE),
        "the host's own dev edges must make {CRATE}/{SURFACE} visible; otherwise its absence \
         above says nothing about the feature and only something about the command:\n{with_dev}"
    );
    // Und nicht nur `ea-desktop`: jeder abgeleitete Produktionswirt. Die
    // Positivkontrollen oben belegen, dass der Befehl die Fläche sehen kann.
    assert_no_host_resolves(&root, CRATE, SURFACE);
}

/// Pins that NO non-test edge carries the `ea-reader` test surface — the same
/// construction as `no_non_test_edge_carries_the_ea_archive_fs_test_surface`
/// above, for the second crate that ships one.
///
/// It exists as a SECOND test and not as a second call of the first, because
/// the first hard-wires `const CRATE: &str = "ea-archive-fs"` and one of its
/// assertions does not carry over: `ea-archive-fs` has dev edges that ask for
/// the feature by name, `ea-reader` has none — its own integration tests get it
/// through the crate's own default. Copying `dev_edges > 0` would fail on the
/// first run.
///
/// The stake is the same and it is browser-facing:
/// `SealedVaultV1::flip_one_wrapped_key_byte_for_test` corrupts a wrapped vault
/// key, `SealedVaultV1::replace_sealed_anchor_bytes_for_test` unseals the vault
/// body, swaps the pinned anchor bytes and re-seals. Without the switch on the
/// shared edge, both sit in `crates/ea-reader-wasm` and therefore in the
/// shipped wasm module — an exported surface that damages ciphertext on demand.
///
/// Four assertions. The last pair replaces the `dev_edges` positive control of
/// the neighbouring test: the same `cargo tree` invocation runs a SECOND time
/// with `-F ea-reader/test-support` and must then CONTAIN the feature. That is
/// what makes the absence in the first tree a finding instead of an artefact of
/// an empty tree, a mistyped package name or a failed command.
#[test]
fn no_non_test_edge_carries_the_ea_reader_test_surface() {
    const CRATE: &str = "ea-reader";
    const SURFACE: &str = "test-support";
    const HOST: &str = "ea-reader-wasm";
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
        "the shared {CRATE} edge must disable its default features; otherwise {HOST} — and with \
         it the shipped wasm module — inherits the two ciphertext-damaging test methods"
    );

    for member in WORKSPACE_MEMBERS {
        let manifest: Value = fs::read_to_string(root.join(member).join("Cargo.toml"))
            .unwrap()
            .parse()
            .unwrap();
        for (table, dependencies) in
            dependency_tables(&manifest, &["dependencies", "build-dependencies"])
        {
            let Some(edge) = dependencies.get(CRATE) else {
                continue;
            };
            assert!(
                !edge_asks_for(edge, SURFACE),
                "{member} {table} re-enables {CRATE}/{SURFACE}; the two damaging methods would be \
                 back in a non-test build"
            );
        }
    }

    // Der aufgelöste Baum des BROWSER-Wirts, einmal ohne und einmal mit dem
    // Merkmal, über ALLE Zielplattformen. Der zweite Lauf ist die
    // Positivkontrolle des ersten.
    let resolve = |extra: &[&str]| {
        let mut arguments = vec!["-p", HOST, "-e", "features", "--target", "all", "-i", CRATE];
        arguments.extend_from_slice(extra);
        cargo_tree(&root, &arguments)
    };

    let shipped = resolve(&[]);
    assert!(
        shipped.contains(HOST),
        "{HOST} must appear as a consumer of {CRATE} in the resolved tree; without the edge the \
         assertion below cannot fail:\n{shipped}"
    );
    assert!(
        !shipped.contains(SURFACE),
        "the resolved feature graph of {HOST} must not contain {CRATE}/{SURFACE}:\n{shipped}"
    );
    let forced = resolve(&["-F", "ea-reader/test-support"]);
    assert!(
        forced.contains(SURFACE),
        "forcing {CRATE}/{SURFACE} must make it appear; otherwise its absence above says nothing \
         about the feature and only something about the command:\n{forced}"
    );
    // Der Browser-Wirt ist nicht der einzige Verbraucher: `ea-ui-contracts`
    // und über sie der Desktop-Wirt ziehen `ea-reader` ebenfalls. Geprüft wird
    // deshalb jeder abgeleitete Produktionswirt, ohne Dev-Kanten.
    assert_no_host_resolves(&root, CRATE, SURFACE);

    // Und dieselbe Manifest- und `cfg`-Zusicherung wie beim Nachbarn: der
    // Schalter an der Wurzelkante wirkt nur, solange `test-support` das EINZIGE
    // Default-Merkmal ist und beide Methoden hinter dem Tor stehen.
    let manifest_text = fs::read_to_string(root.join("crates/ea-reader/Cargo.toml")).unwrap();
    let manifest: Value = manifest_text.parse().unwrap();
    assert_eq!(
        manifest["features"]["default"].as_array().map(Vec::len),
        Some(1),
        "test-support stays the single default feature of {CRATE}; a second one would widen the \
         release surface silently"
    );
    assert_eq!(
        manifest["features"]["default"][0].as_str(),
        Some(SURFACE),
        "the one default feature of {CRATE} must be {SURFACE} itself"
    );
    const DAMAGERS: [&str; 2] = [
        "flip_one_wrapped_key_byte_for_test",
        "replace_sealed_anchor_bytes_for_test",
    ];
    for damager in DAMAGERS {
        assert!(
            manifest_text.contains(damager),
            "{damager} damages ciphertext and must be named in the manifest as a release \
             exclusion, so a release build cannot forget it"
        );
    }
    for source_path in [
        "crates/ea-reader/src/vault.rs",
        "crates/ea-reader/src/envelope.rs",
    ] {
        let source = fs::read_to_string(root.join(source_path)).unwrap();
        let Some(gate) = source.find("#[cfg(any(test, feature = \"test-support\"))]") else {
            continue;
        };
        for (index, _) in source.match_indices("fn ") {
            let tail = &source[index..];
            let name_end = tail.find('(').expect("a declaration carries parentheses");
            if tail[..name_end].contains("_for_test") {
                assert!(
                    index > gate,
                    "every *_for_test declaration in {source_path} must sit behind the gate: {}",
                    &tail[..name_end]
                );
            }
        }
    }
}

/// Pins that NO production build carries the `ea-admin` test surface — the
/// third member of the family of `no_non_test_edge_carries_the_ea_archive_fs_test_surface`
/// and `no_non_test_edge_carries_the_ea_reader_test_surface`, and the check the
/// stage 5 gate report (`docs/traceability/stage-5-gate.md`, section 4,
/// „Testflaeche ueber `desktop-fixture`") asks for.
///
/// The stake: `ea-admin/test-support` switches on fixture constructors
/// (`RecoveryTestObservation`, `verify_fresh_machine_recovery_test`,
/// `RecoveryTestFreshness::for_testing`) that production entry points never
/// consult. They reach a build through ONE normal edge:
/// `einsatzarchiv-cli/desktop-fixture` → `dep:ea-desktop` with
/// `features = ["test-support"]` → `ea-desktop/test-support` →
/// `ea-admin/test-support`. That edge is optional and sits in a FEATURE table,
/// so a scan of the dependency tables — the construction of both neighbours —
/// is blind to it. Only the resolved graph sees it.
///
/// Two assertions of the neighbours do not carry over, and each divergence is
/// deliberate:
///
/// - the shared workspace edge is NOT `default-features = false`: `ea-admin`
///   declares no `default` at all, so the switch would guard nothing. The
///   fail-closed analogue is that no `default` of `ea-admin` — and no
///   `default` of any member, followed transitively through its own feature
///   table — ever reaches `ea-admin/test-support`;
/// - `dev_edges > 0` of the archive-fs test is replaced by two resolved
///   positive controls on the CLI, see below.
///
/// The production hosts are DERIVED, not listed: every member with a `bin`,
/// `cdylib` or `staticlib` target (`production_hosts`). A hand-kept list of
/// today's two consumers (`einsatzarchiv-cli`, `ea-desktop`) missed a host
/// that starts consuming `ea-admin` tomorrow — for instance
/// `einsatzarchiv-server` through a feature of `ea-ui-contracts`. Every host
/// resolves with `-e no-dev,features --target all`: the normal edges of EVERY
/// platform, not only of the machine running the test, because Windows is a
/// delivery platform and `[target.'cfg(..)'.dependencies]` tables are resolved
/// only for their platform. The manifest side reads those tables too.
///
/// The positive controls make the absence a finding: the two hosts that
/// consume `ea-admin` today must name themselves as its normal consumers, the
/// CLI with `--features desktop-fixture` MUST show `ea-admin feature
/// "test-support"` (the one normal edge the check exists for), and the CLI
/// with its own dev edges (`-e features`) MUST show it too — all with the same
/// `--target all` as the check itself.
#[test]
fn no_production_build_carries_the_ea_admin_test_surface() {
    const CRATE: &str = "ea-admin";
    const SURFACE: &str = "test-support";
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let surface_edge = format!("{CRATE}/{SURFACE}");
    let surface_node = format!("{CRATE} feature \"{SURFACE}\"");

    // Manifestseite, Teil 1: `ea-admin` selbst schaltet die Flaeche nie per
    // Vorgabe ein.
    let admin: Value = fs::read_to_string(root.join("crates/ea-admin/Cargo.toml"))
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        admin
            .get("features")
            .and_then(|features| features.get(SURFACE))
            .is_some(),
        "{CRATE} must still declare {SURFACE}; otherwise this test guards a feature that no \
         longer exists"
    );
    let admin_default = admin
        .get("features")
        .and_then(|features| features.get("default"))
        .and_then(Value::as_array)
        .map(|default| default.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    assert!(
        !admin_default.contains(&SURFACE),
        "{CRATE} must not enable {SURFACE} by default; every consumer would inherit the \
         fixture constructors"
    );

    // Manifestseite, Teil 2: kein Mitglied erreicht die Flaeche aus seinem
    // `default` heraus — transitiv ueber die eigene Merkmalstabelle — und keine
    // normale oder Build-Kante fordert sie an. Nur `[dev-dependencies]` duerfen.
    for member in WORKSPACE_MEMBERS {
        let manifest: Value = fs::read_to_string(root.join(member).join("Cargo.toml"))
            .unwrap()
            .parse()
            .unwrap();
        for (table, dependencies) in
            dependency_tables(&manifest, &["dependencies", "build-dependencies"])
        {
            let Some(edge) = dependencies.get(CRATE) else {
                continue;
            };
            assert!(
                !edge_asks_for(edge, SURFACE),
                "{member} {table} re-enables {surface_edge}; the fixture constructors would be \
                 in a non-test build"
            );
        }
        let Some(features) = manifest.get("features").and_then(Value::as_table) else {
            continue;
        };
        let mut pending = vec!["default".to_owned()];
        let mut reached = BTreeSet::new();
        while let Some(feature) = pending.pop() {
            if !reached.insert(feature.clone()) {
                continue;
            }
            let Some(expansion) = features.get(&feature).and_then(Value::as_array) else {
                continue;
            };
            for entry in expansion.iter().filter_map(Value::as_str) {
                assert!(
                    entry != surface_edge && entry != format!("{CRATE}?/{SURFACE}"),
                    "{member} reaches {surface_edge} from its default features (via \
                     `{feature}`); a plain build of {member} would carry the fixture \
                     constructors"
                );
                if !entry.contains('/') && !entry.starts_with("dep:") {
                    pending.push(entry.to_owned());
                }
            }
        }
    }

    // Graphseite: der aufgelöste Merkmalsgraph JEDES abgeleiteten
    // Produktionswirts, ohne Dev-Kanten und über alle Zielplattformen.
    assert_no_host_resolves(&root, CRATE, SURFACE);

    // Positivkontrollen, alle mit derselben Befehlsform wie die Prüfung oben.
    let resolve = |host: &str, edges: &str, extra: &[&str]| {
        let mut arguments = vec!["-p", host, "-e", edges, "--target", "all", "-i", CRATE];
        arguments.extend_from_slice(extra);
        cargo_tree(&root, &arguments)
    };
    // Die beiden Wirte, die `ea-admin` heute über eine normale Kante ziehen,
    // müssen sich als Verbraucher nennen. Sonst prüfte die Schleife oben nur
    // Wirte, deren Graph `ea-admin` gar nicht enthält.
    for consumer in ["einsatzarchiv-cli", "ea-desktop"] {
        let shipped = resolve(consumer, "no-dev,features", &[]);
        assert!(
            shipped.contains(&format!("{consumer} v")) && shipped.contains("ea-admin feature"),
            "{consumer} must appear as a normal consumer of {CRATE} in the resolved tree; \
             without the edge the host check above cannot fail:\n{shipped}"
        );
    }

    // Erste Positivkontrolle: genau die eine normale Kante, für die dieser
    // Test existiert. Mit `desktop-fixture` MUSS die Fläche erscheinen, sonst
    // sähe der Test die Kante gar nicht und wäre blind — einmal im vollen Baum,
    // den die Wirtsprüfung liest, und einmal im invertierten mit dem Weg.
    let fixture_full = cargo_tree(
        &root,
        &[
            "-p",
            "einsatzarchiv-cli",
            "-e",
            "no-dev,features",
            "--target",
            "all",
            "--features",
            "desktop-fixture",
        ],
    );
    assert!(
        fixture_full.contains(&surface_node),
        "the full tree of einsatzarchiv-cli --features desktop-fixture must contain \
         {surface_node}; otherwise the host check above reads a tree in which the surface can \
         never show"
    );
    let fixture = resolve(
        "einsatzarchiv-cli",
        "no-dev,features",
        &["--features", "desktop-fixture"],
    );
    assert!(
        fixture.contains(&surface_node) && fixture.contains("ea-desktop feature \"test-support\""),
        "einsatzarchiv-cli --features desktop-fixture must make {surface_edge} visible through \
         ea-desktop/test-support; otherwise the absence above says nothing about the feature \
         and only something about the command:\n{fixture}"
    );
    // Zweite Positivkontrolle, wie beim archive-fs-Test: mit den Dev-Kanten des
    // CLI erscheint die Fläche ebenfalls. Sonst sägte `no-dev` nur die Sicht ab.
    let with_dev = resolve("einsatzarchiv-cli", "features", &[]);
    assert!(
        with_dev.contains(&surface_node),
        "the CLI's own dev edges must make {surface_edge} visible; otherwise `no-dev` above \
         only narrowed the view:\n{with_dev}"
    );
}
