// crates/ea-reader-wasm/tests/bridge_boundary.rs
//
// WIRTSZEUGE, und der cfg-Kopf sagt es. Ohne ihn zoege der Browserlauf
// `cargo test --locked -p ea-reader-wasm --target wasm32-unknown-unknown`
// dieses Ziel mit, uebersetzte es fuer wasm32 und uebergaebe es dem
// `wasm-bindgen-test-runner` — der findet in einem Ziel ohne
// `#[wasm_bindgen_test]` keinen einzigen Fall. Das Spiegelbild WIRD ueber
// `crates/ea-reader-wasm/tests/opfs_browser.rs` stehen und aus dem umgekehrten
// Grund `#![cfg(target_arch = "wasm32")]` tragen; die Datei gibt es heute noch
// nicht, sie entsteht mit der Aufgabe „`apps/web`, die wasm-bindgen-Bruecke,
// der OPFS-Bytespeicher und der Laufzeitnachweis im Gate".
#![cfg(not(target_arch = "wasm32"))]

use std::{
    fs,
    path::{Path, PathBuf},
};

use ea_reader::{GATE_ORDER_V1, ReaderMode};
use ea_reader_wasm::bridge_echo;

/// Sammelt JEDE `.rs`-Datei unter `directory`, REKURSIV.
///
/// Rekursiv und nicht flach, und das ist keine Vorsorge, sondern die
/// Voraussetzung dafuer, dass der Zeuge weiter misst, was sein Name sagt: ein
/// `fs::read_dir` ueber `src/` allein saehe `src/bridge/opfs.rs` NICHT, und
/// `assert!(exports > 0)` bliebe an `lib.rs` trotzdem gruen. Der Zeuge meldete
/// dann nichts und schwiege dabei laut. Nach der Messung im Doc-Kommentar
/// unten ist er die einzige Instanz, die ein fehlendes cfg faengt; er darf
/// keinen Winkel dieser Crate auslassen. Angelegt, solange die Crate EINE
/// Quelle hat und es nichts kostet.
fn collect_rust_sources(directory: &Path, into: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(directory).unwrap_or_else(|error| {
        panic!(
            "{} must be a readable directory: {error}",
            directory.display()
        )
    });
    for entry in entries {
        let path = entry.expect("readable directory entry").path();
        if path.is_dir() {
            collect_rust_sources(&path, into);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            into.push(path);
        }
    }
}

/// Der Rundlauf in BEIDE Richtungen: ein Argument geht hinein, ein anderer
/// Wert kommt heraus. Ein Export, der nur einen Rueckgabewert liefert, belegt
/// nicht, dass Argumente die Grenze ueberhaupt erreichen — genau die Luecke,
/// die `echo_from_js` im Spike `spikes/wasm-runtime-proof/src/lib.rs` schliesst.
#[test]
fn the_bridge_returns_what_its_caller_hands_it() {
    assert_eq!(bridge_echo("Datei-Modus"), "ea-reader-wasm: Datei-Modus");
    assert_ne!(bridge_echo("a"), bridge_echo("b"));
}

/// Das wasm-Ziel wird in diesem Task NICHT ausgefuehrt. Belegbar ist hier
/// deshalb nur die LAGE des Exports, und die wird als Text gelesen — dieselbe
/// Bauform, mit der `every_crates_member_is_classified_for_the_wasm32_gate`
/// den wasm32-Block aus `tools/xtask/src/main.rs` liest.
///
/// # Die verlangte Bauform ist das cfg AM ITEM
///
/// Das `#[cfg(target_arch = "wasm32")]` steht unmittelbar ueber dem Attribut
/// jeder einzelnen Ausfuhr, nicht am umschliessenden `mod`. Ein Modultor waere
/// fuer die Uebersetzung gleichwertig — ein weggetortes Modul uebersetzt gar
/// nichts, die Ausfuhr laege also auch dann nicht in der Wirtsbibliothek —,
/// fuer diesen Zeugen aber unsichtbar: er liest Text und folgt keinem `mod`.
/// Die Regel ist deshalb die engere von beiden — je Ausfuhr ein cfg —, und die
/// Fehlermeldung unten haelt die zwei Faelle auseinander.
///
/// Die Messung im naechsten Abschnitt betrifft AUSSCHLIESSLICH den anderen
/// Fall, das GANZ fehlende cfg. Ueber das Modultor sagt sie nichts, und sie
/// muss es auch nicht: dort ist der Befund kein Uebersetzungsschaden, sondern
/// eine Bauform, die dieser Zeuge nicht lesen kann.
///
/// # Dieser Zeuge ist die EINZIGE Instanz, und das ist GEMESSEN
///
/// Der Stufe-4-Plan nahm an, eine Ausfuhr ohne ihr cfg falle ohnehin am
/// Wirtsbau auf — „spaeter und unklarer", aber sie falle. Das ist falsch.
/// Gemessen in der Aufgabe „wasm32-Reichweite" mit entferntem
/// `#[cfg(target_arch = "wasm32")]` ueber `bridge_echo_js` und sonst
/// unveraendertem Baum: `cargo build --locked -p ea-reader-wasm --lib`,
/// `cargo test --locked -p ea-reader-wasm --all-targets --no-run` und
/// `cargo clippy --locked -p ea-reader-wasm --all-targets --all-features --
/// -D warnings` enden ALLE DREI mit 0 und ohne eine einzige Diagnose;
/// `wasm-bindgen 0.2.126` uebersetzt sein Attribut auf einem Nicht-wasm-Ziel
/// klaglos, sogar unter `#![forbid(unsafe_code)]`. Nur dieser Zeuge fiel
/// (Exitcode 101).
///
/// Es gibt also KEIN zweites Netz. Fuer die neun Bruecken-Module, die nach
/// diesem Task entstehen — `bridge.rs`, `opfs_worker.rs`, `vault_bridge.rs`,
/// `webauthn.rs`, `fetch.rs`, `file_access.rs`, `visibility.rs`,
/// `export_bridge.rs`, `view.rs` —, heisst das: der Compiler warnt NICHT mit. Ein GANZ vergessenes cfg faellt
/// hier oder gar nicht, und die Ausfuhr wandert unbemerkt in die
/// Wirtsbibliothek.
#[test]
fn every_wasm_bindgen_export_sits_behind_the_wasm32_cfg() {
    // Der Zeuge laeuft ueber JEDE Quelle der Bruecke — rekursiv, siehe
    // `collect_rust_sources` — und ueber BEIDE
    // Schreibweisen des Attributs. Neun spaetere Module — `bridge.rs`,
    // `opfs_worker.rs`, `vault_bridge.rs`, `webauthn.rs`, `fetch.rs`,
    // `file_access.rs`, `visibility.rs`, `export_bridge.rs`, `view.rs` —
    // legen Ausfuhren an, und
    // sie schreiben `#[wasm_bindgen(js_name = …)]` nach einem
    // `use wasm_bindgen::prelude::*;`. Ein Zeuge, der nur `src/lib.rs` liest
    // und nur die voll qualifizierte Form kennt, saehe keine davon.
    let mut sources: Vec<PathBuf> = Vec::new();
    collect_rust_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut sources,
    );
    sources.sort();
    assert!(
        !sources.is_empty(),
        "the bridge must carry at least one source file"
    );

    let mut exports = 0_usize;
    for path in &sources {
        // Die qualifizierte Form wird auf die kurze zurueckgefuehrt, damit
        // GENAU EIN Muster gesucht wird und keine Schreibweise durchrutscht.
        // Jede andere Form (etwa `cfg_attr`) wird vorher rot (DRK-321, M3).
        let raw = fs::read_to_string(path).expect("bridge sources must be readable");
        assert_only_recognized_wasm_bindgen_forms(&raw, path);
        let source = raw.replace("#[wasm_bindgen::prelude::wasm_bindgen", "#[wasm_bindgen");
        for (index, _) in source.match_indices("#[wasm_bindgen") {
            // `#[wasm_bindgen_test]` ist kein Export und wird nicht gezaehlt.
            if source[index..].starts_with("#[wasm_bindgen_test") {
                continue;
            }
            exports += 1;
            assert!(
                source[..index]
                    .trim_end()
                    .ends_with("#[cfg(target_arch = \"wasm32\")]"),
                "every wasm_bindgen export must carry `#[cfg(target_arch = \"wasm32\")]` on \
                 the ITEM ITSELF, on the line directly above the attribute. Two different \
                 mistakes land here, and they have different consequences. (1) NO cfg at \
                 all: the export is then compiled into the HOST library as well, and NOTHING \
                 ELSE reports it — on exactly that mutation `cargo build --lib`, \
                 `cargo test --all-targets --no-run` and \
                 `cargo clippy --all-targets -- -D warnings` were all measured to end with 0, \
                 so for that case this witness is the only instance that catches it. (2) A \
                 cfg on the enclosing `mod` instead: that COMPILES correctly and puts nothing \
                 into the host library, but it does not satisfy this witness, which reads \
                 text and cannot follow a `mod`. The per-item cfg is the required shape, \
                 deliberately the narrower of the two. Offending file: {}",
                path.display()
            );
        }
    }
    assert!(exports > 0, "the bridge must export at least once");
}

/// `ea-reader` traegt in diesem Task KEINE Rechnung. Was hier steht, sind
/// WERTPINS und keine Struktursicherungen, und das gehoert dazugesagt.
///
/// `assert_eq!(GATE_ORDER_V1, ea_verify::GATE_ORDER_V1)` vergleicht DURCH den
/// Re-Export hindurch und ist heute tautologisch: die zwei Namen bezeichnen
/// dasselbe Element. Eine handkopierte Liste gleichen Inhalts bliebe hier
/// gruen. Dass es keine zweite Liste GIBT, sagt das `pub use` in
/// `crates/ea-reader/src/lib.rs` und nicht dieser Test; die Zusicherung faengt
/// erst dann etwas, wenn `ea-reader` je eine eigene Konstante deklarierte —
/// dann misst sie deren Inhaltsgleichheit.
///
/// `ReaderMode::ALL.len()` pinnt ebenso einen WERT und keine Vollstaendigkeit.
/// Die Geschlossenheit erzwingt der erschoepfende `match` in
/// `ReaderMode::code`; aufgeschrieben und gemessen ist das an
/// `crates/ea-reader/src/mode.rs`.
#[test]
fn the_reader_crate_reexports_the_gate_order_instead_of_redeclaring_it() {
    assert_eq!(GATE_ORDER_V1, ea_verify::GATE_ORDER_V1);
    assert_eq!(ReaderMode::ALL.len(), 2);
    assert_eq!(ReaderMode::Server.code(), "server");
    assert_eq!(ReaderMode::File.code(), "file");
}

/// Was eine Ausfuhr der Bruecke dem Web-Reader an Faehigkeit gibt. Die Liste
/// ist geschlossen: eine neue Faehigkeit ist eine Entscheidung und kein Nebenbei.
/// Es gibt bewusst KEINE Faehigkeit „Zustandsuebergang", „Autorisierung" oder
/// „Vernichtung starten/fortsetzen/abbrechen" (Web-Reader-Design §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Capability {
    Diagnostics,
    Runtime,
    Storage,
    BundleTrust,
    View,
    Enrollment,
    Vault,
    Session,
    FileMode,
    Sync,
    Export,
    /// Nur der eigene Cache und Index (Web-Reader-Design §3).
    ReplicaCacheRemoval,
    /// Nur die eigene, jobgebundene Loeschattestierung (Web-Reader-Design §3).
    ReplicaAttestation,
    /// Die zwei Escrow-Zeremonien des Readers (Escrow-Profil §5–§7, DRK-460
    /// Ruling Q3): das Paket aus dem eigenen KEM und der fluechtige
    /// Transport-Schluessel. Eigene Faehigkeit, damit eine Zeremonie mit
    /// fremdem Schluesselmaterial nicht unter `Enrollment` oder `Vault`
    /// verschwindet.
    ReaderKeyEscrow,
}

/// Jede `#[wasm_bindgen]`-Ausfuhr von `ea-reader-wasm` mit ihrer Faehigkeit,
/// nach `js_name` sortiert. Eine neue Ausfuhr wird erst gruen, wenn sie hier
/// mit Faehigkeit eingetragen ist; eine entfernte, wenn ihre Zeile geht.
const WASM_EXPORTS: &[(&str, Capability)] = &[
    ("blobGet", Capability::Storage),
    ("blobPut", Capability::Storage),
    ("bridgeEcho", Capability::Diagnostics),
    ("enrollmentBegin", Capability::Enrollment),
    ("enrollmentBeginRestored", Capability::Enrollment),
    ("enrollmentConfirmFingerprints", Capability::Enrollment),
    ("enrollmentFingerprints", Capability::Enrollment),
    ("enrollmentFinish", Capability::Enrollment),
    ("enrollmentFinishRestored", Capability::Enrollment),
    ("enrollmentRegisterAuthenticator", Capability::Enrollment),
    ("evaluateBundleCandidate", Capability::BundleTrust),
    ("fileModeBeginDirectory", Capability::FileMode),
    ("fileModeBundleExtension", Capability::FileMode),
    ("fileModeDirectoryUnavailable", Capability::FileMode),
    ("fileModeOpenBundle", Capability::FileMode),
    ("fileModeOpenDirectory", Capability::FileMode),
    ("fileModePushBlob", Capability::FileMode),
    ("readerAmendmentThread", Capability::View),
    ("readerDestructionApply", Capability::ReplicaCacheRemoval),
    (
        "readerDestructionApplyDelivery",
        Capability::ReplicaCacheRemoval,
    ),
    ("readerDestructionAttest", Capability::ReplicaAttestation),
    (
        "readerDestructionAttestation",
        Capability::ReplicaAttestation,
    ),
    ("readerDestructionReceipt", Capability::ReplicaCacheRemoval),
    ("readerEntryView", Capability::View),
    ("readerExportOne", Capability::Export),
    ("readerKeyEscrowSealPackage", Capability::ReaderKeyEscrow),
    ("readerKeyEscrowTransportAbort", Capability::ReaderKeyEscrow),
    ("readerKeyEscrowTransportBegin", Capability::ReaderKeyEscrow),
    ("readerKeyEscrowTransportOpen", Capability::ReaderKeyEscrow),
    ("readerNoteActivity", Capability::Session),
    ("readerNoteVisibility", Capability::Session),
    ("readerRegistrationRequest", Capability::Enrollment),
    ("readerRuntimeWitness", Capability::Runtime),
    ("readerSearch", Capability::View),
    ("readerSessionLock", Capability::Session),
    ("readerSessionStateAt", Capability::Session),
    ("readerStandClose", Capability::View),
    ("readerStandView", Capability::View),
    ("readerSyncAcceptBatch", Capability::Sync),
    ("readerSyncNextRequest", Capability::Sync),
    ("readerTechnicalView", Capability::View),
    ("readerTrustAge", Capability::BundleTrust),
    ("readerVaultSeal", Capability::Vault),
    ("readerVaultUnlock", Capability::Vault),
];

/// DRK-321 (Fixrunde, M3): jedes Vorkommen des Bezeichners `wasm_bindgen`
/// ausserhalb von Kommentarzeilen muss eine der zwei Formen sein, die die
/// Scanner lesen koennen:
/// - `#[wasm_bindgen` als Attribut direkt hinter `#[` (die Exportform), oder
/// - ein Pfadanfang `wasm_bindgen::…`, der selbst nicht hinter `::` steht
///   (`use wasm_bindgen::prelude::*;`, `wasm_bindgen::JsValue`).
///
/// Damit wird jede andere Form rot, statt still am Scan vorbeizugehen:
/// `#[cfg_attr(…, wasm_bindgen(js_name = …))]`, ein Alias
/// `use wasm_bindgen::prelude::wasm_bindgen as wb;` oder `use wasm_bindgen as w;`,
/// `extern crate wasm_bindgen`. `wasm_bindgen_test` und `wasm_bindgen_futures`
/// sind andere Bezeichner und zaehlen nicht.
fn unrecognized_wasm_bindgen_forms(source: &str) -> Vec<String> {
    let code: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .map(|line| format!("{line}\n"))
        .collect();
    let code = code.replace("#[wasm_bindgen::prelude::wasm_bindgen", "#[wasm_bindgen");
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut findings = Vec::new();
    for (index, token) in code.match_indices("wasm_bindgen") {
        let before = &code[..index];
        let after = &code[index + token.len()..];
        if before.chars().next_back().is_some_and(ident) || after.chars().next().is_some_and(ident)
        {
            continue;
        }
        let attribute = before.ends_with("#[");
        let path_root = after.starts_with("::") && !before.ends_with("::");
        if !(attribute || path_root) {
            let line_start = before.rfind('\n').map_or(0, |i| i + 1);
            let line_end = after
                .find('\n')
                .map_or(code.len(), |i| index + token.len() + i);
            findings.push(code[line_start..line_end].trim().to_owned());
        }
    }
    findings
}

fn assert_only_recognized_wasm_bindgen_forms(source: &str, path: &Path) {
    let findings = unrecognized_wasm_bindgen_forms(source);
    assert!(
        findings.is_empty(),
        "wasm_bindgen appears in a form the export scanners cannot read (cfg_attr, \
         alias, extern crate, ...). Write exports as \
         `#[cfg(target_arch = \"wasm32\")]` + `#[wasm_bindgen(js_name = \"...\")]`. \
         {}: {findings:?}",
        path.display()
    );
}

#[test]
fn the_wasm_bindgen_form_scanner_rejects_hidden_exports() {
    assert!(
        unrecognized_wasm_bindgen_forms(
            "use wasm_bindgen::prelude::*;\nuse wasm_bindgen_futures::JsFuture;\n\
             // #[cfg_attr(x, wasm_bindgen)]\n#[wasm_bindgen(js_name = \"a\")]\n\
             fn a(v: wasm_bindgen::JsValue) {}\n#[wasm_bindgen_test]\nfn t() {}\n"
        )
        .is_empty()
    );
    for hidden in [
        "#[cfg_attr(target_arch = \"wasm32\", wasm_bindgen(js_name = \"x\"))]",
        "#[cfg_attr(target_arch = \"wasm32\", wasm_bindgen::prelude::wasm_bindgen)]",
        "use wasm_bindgen::prelude::wasm_bindgen as wb;",
        "use wasm_bindgen as w;",
        "extern crate wasm_bindgen;",
        "#[ wasm_bindgen(js_name = \"x\")]",
    ] {
        assert_eq!(
            unrecognized_wasm_bindgen_forms(hidden).len(),
            1,
            "must be flagged: {hidden}"
        );
    }
}

/// Liest jede `#[wasm_bindgen(...)]`-Ausfuhr der Crate und gibt ihren
/// `js_name` zurueck. Eine Ausfuhr OHNE `js_name` ist ein Fehler: sonst
/// entstuende ein Export am Namensscan vorbei.
fn wasm_export_names() -> Vec<(String, PathBuf)> {
    let mut sources: Vec<PathBuf> = Vec::new();
    collect_rust_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut sources,
    );
    sources.sort();
    let mut names = Vec::new();
    for path in sources {
        let raw = fs::read_to_string(&path).expect("bridge sources must be readable");
        assert_only_recognized_wasm_bindgen_forms(&raw, &path);
        let source = raw.replace("#[wasm_bindgen::prelude::wasm_bindgen", "#[wasm_bindgen");
        for (index, _) in source.match_indices("#[wasm_bindgen") {
            if source[index..].starts_with("#[wasm_bindgen_test") {
                continue;
            }
            let attribute = &source[index..index + source[index..].find(']').unwrap()];
            let name = attribute
                .split_once("js_name")
                .and_then(|(_, rest)| rest.trim_start().strip_prefix('='))
                .map(|rest| {
                    rest.trim_start()
                        .trim_start_matches('"')
                        .split(|c: char| c == '"' || c == ',' || c == ')' || c.is_whitespace())
                        .next()
                        .unwrap_or_default()
                        .to_owned()
                })
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| {
                    panic!(
                        "every wasm_bindgen export must name itself with `js_name`, so the \
                         capability allowlist sees it: `{attribute}]` in {}",
                        path.display()
                    )
                });
            names.push((name, path.clone()));
        }
    }
    names
}

/// DRK-321: die Reader-Grenze wird nach FAEHIGKEITEN geprueft, nicht nach
/// Woertern. Die Menge der WASM-Ausfuhren ist genau `WASM_EXPORTS`, in beide
/// Richtungen, und nur die Replikenfaehigkeiten beruehren die Vernichtung.
#[test]
fn wasm_exports_match_the_capability_allowlist() {
    use std::collections::{BTreeMap, BTreeSet};
    let found = wasm_export_names();
    let mut seen = BTreeSet::new();
    for (name, path) in &found {
        assert!(
            seen.insert(name.as_str()),
            "duplicate wasm export `{name}` in {}",
            path.display()
        );
    }
    let allowed: BTreeMap<&str, Capability> = WASM_EXPORTS.iter().copied().collect();
    assert_eq!(
        allowed.len(),
        WASM_EXPORTS.len(),
        "the allowlist names every export once"
    );
    let unlisted: Vec<_> = found
        .iter()
        .filter(|(name, _)| !allowed.contains_key(name.as_str()))
        .map(|(name, path)| format!("{name} ({})", path.display()))
        .collect();
    assert!(
        unlisted.is_empty(),
        "new wasm exports need a capability entry in WASM_EXPORTS: {unlisted:?}"
    );
    let stale: Vec<_> = allowed
        .keys()
        .filter(|name| !seen.contains(*name))
        .collect();
    assert!(
        stale.is_empty(),
        "WASM_EXPORTS lists exports that no longer exist: {stale:?}"
    );
    let replica = |wanted: Capability| -> BTreeSet<&str> {
        WASM_EXPORTS
            .iter()
            .filter(|(_, capability)| *capability == wanted)
            .map(|(name, _)| *name)
            .collect()
    };
    assert_eq!(
        replica(Capability::ReplicaAttestation),
        BTreeSet::from(["readerDestructionAttest", "readerDestructionAttestation"])
    );
    assert_eq!(
        replica(Capability::ReplicaCacheRemoval),
        BTreeSet::from([
            "readerDestructionApply",
            "readerDestructionApplyDelivery",
            "readerDestructionReceipt",
        ])
    );
    for (name, capability) in WASM_EXPORTS {
        let lower = name.to_ascii_lowercase();
        assert!(
            !lower.contains("destruction")
                || matches!(
                    capability,
                    Capability::ReplicaCacheRemoval | Capability::ReplicaAttestation
                ),
            "`{name}` touches destruction outside the two replica capabilities"
        );
    }
}
