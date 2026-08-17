//! Die Berichtssignatur: eine BEGRUENDETE VERWEIGERUNG, keine Ersatzloesung.
//!
//! # Was hier gemessen wird
//!
//! Zweierlei, und beides ist eine Aussage ueber eine NICHT stattgefundene
//! Kryptografie:
//!
//! 1. `--report-signing-key` wird von der Grammatik ANGENOMMEN und vom Lauf mit
//!    [`ea_recovery::ExitCode::Unsupported`] (21) abgewiesen. Die Meldung nennt
//!    woertlich, welches Element der Suite v1 fehlt. Geschrieben wird NICHTS —
//!    ein halb erzeugtes Ziel waere schlimmer als keins.
//! 2. Ohne den Schalter traegt das Dokument `reportHash` und ausdruecklich
//!    KEINEN `reportSignature`. Ein leeres oder null-Glied waere eine Behauptung
//!    ueber eine Pruefung, die es nicht gibt.
//!
//! # WARUM VERWEIGERT WIRD
//!
//! Eine abgesetzte COSE-Sign1-Signatur ueber `reportHash` ist mit dem heutigen
//! `ea-crypto` nicht erzeugbar, und `ea-crypto` ist geschlossen:
//! `ContentType` (`crates/ea-crypto/src/cose.rs:25`) kennt keinen
//! Verifikationsbericht und weist jeden fremden Wert ab (`:97`); `sign_normal`
//! sperrt die Umwidmung vorhandener Digest-Typen ausdruecklich (`:332`);
//! `CoseSigner::sign` ist privat (`:567`); `SignerRole` (`:816`) kennt keine
//! Berichtsrolle und `CertificateCapability` (`:1543`) keine Berichtsfaehigkeit
//! — die PRUEFSEITE fehlt also ebenso. `design.md`:1781 macht die Signatur
//! bedingt („sofern eine autorisierte Signaturrolle verfuegbar ist"); in Suite
//! v1 existiert keine, und der gehashte unsignierte Bericht IST damit das
//! normkonforme Ergebnis. Die volle Begruendung steht in
//! `docs/adr/0001-toolchain-and-cryptography-dependencies.md`.
//!
//! # DIE UHR IST HIER KEIN PARAMETER
//!
//! Wie in `apps/cli/tests/determinism.rs`: die CLI kennt genau eine Uhr, und
//! jeder Bestand stammt deshalb aus der `live_clock_*`-Familie.

#[path = "support/mod.rs"]
mod support;

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use serde_json::Value;

use support::{LiveArchive, live_clock_archive, materialize, temp_dir};

/// Das gepinnte Berichtsschema, zur Uebersetzungszeit eingebettet.
const REPORT_SCHEMA_V1: &str =
    include_str!("../../../schemas/reports/v1/verification-report.schema.json");

/// Ein auf die Platte gelegter Bestand samt Ankerdatei und Zielverzeichnis.
///
/// Anker und Ziel liegen in EIGENEN Verzeichnissen: eine Ankerdatei oder eine
/// Berichtsdatei unter der Archivwurzel wuerde mitgelesen und als Beiwerk
/// gezaehlt.
struct Laid {
    archive: support::TempDir,
    anchor: support::TempDir,
    output: support::TempDir,
}

impl Laid {
    fn anchor_path(&self) -> String {
        path_argument(&self.anchor.path().join("anchor.bin"))
    }

    /// Ein noch NICHT existierender Zielpfad unter dem Zielverzeichnis.
    fn output_path(&self, name: &str) -> PathBuf {
        self.output.path().join(name)
    }
}

/// Ein vom Testrahmen selbst gebildeter Pfad als Argumentzeichenkette.
fn path_argument(path: &Path) -> String {
    path.to_str()
        .expect("der vom Testrahmen selbst gebildete Pfad ist UTF-8")
        .to_owned()
}

/// Legt `built` samt Anker ab und oeffnet ein leeres Zielverzeichnis.
fn lay_out(tag: &str, built: &LiveArchive) -> Laid {
    let archive = temp_dir(&format!("{tag}-archive"));
    materialize(&built.fixture, archive.path());
    let anchor = temp_dir(&format!("{tag}-anchor"));
    fs::write(anchor.path().join("anchor.bin"), &built.anchor_bytes)
        .expect("die Ankerdatei muss schreibbar sein");
    let output = temp_dir(&format!("{tag}-output"));
    Laid {
        archive,
        anchor,
        output,
    }
}

/// Startet das Werkzeug mit `tokens` und liefert seinen vollstaendigen Ausgang.
fn run(tokens: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_einsatzarchiv"))
        .args(tokens)
        .output()
        .expect("das Testbinary muss startbar sein")
}

/// Der Exitcode eines Laufs.
fn code_of(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("der Prozess muss regulaer enden")
}

/// Die Anzahl der Eintraege eines Verzeichnisses.
fn entry_count(directory: &Path) -> usize {
    fs::read_dir(directory)
        .expect("das Zielverzeichnis muss lesbar sein")
        .count()
}

/// Ein ausdruecklich benannter Signierschluessel endet mit 21 — und schreibt nichts.
///
/// Der Wert des Schalters ist ein PFADFOERMIGES Argument, das gar nicht
/// existieren muss: die Verweigerung steht VOR jedem Lesen und vor jedem
/// Schreiben. Genau das ist der Punkt — es wird nicht erst gearbeitet und dann
/// abgebrochen.
///
/// Gemessen wird nicht nur die Abwesenheit der Zieldatei, sondern die LEERE des
/// ganzen Zielverzeichnisses. Ein `!exists()` allein waere schwach: die Datei
/// hat auch vorher nicht existiert.
#[test]
fn an_explicit_report_signing_key_is_refused_with_a_named_reason() {
    let built = live_clock_archive();
    let laid = lay_out("report-signing-refusal", &built);

    let anchor = laid.anchor_path();
    let archive = path_argument(laid.archive.path());
    let target = laid.output_path("bericht.json");
    let target_argument = path_argument(&target);
    let signer = path_argument(&laid.anchor.path().join("report-signer.key"));

    let output = run(&[
        "--trust-anchor",
        &anchor,
        "report",
        &archive,
        "--output",
        &target_argument,
        "--report-signing-key",
        &signer,
    ]);

    assert_eq!(
        code_of(&output),
        21,
        "exit code; stderr war: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8(output.stderr).expect("die Meldung ist UTF-8");
    assert!(
        stderr.contains("ea.verification-report/v1"),
        "die Meldung muss den fehlenden Inhaltstyp WOERTLICH nennen, war: {stderr}"
    );
    assert!(
        stderr.contains("contentType"),
        "die Meldung muss benennen, WELCHES Element fehlt, war: {stderr}"
    );

    assert!(
        !target.exists(),
        "ein verweigerter Lauf darf keine Zieldatei anlegen"
    );
    assert_eq!(
        entry_count(laid.output.path()),
        0,
        "ein verweigerter Lauf darf im Zielverzeichnis NICHTS hinterlassen"
    );
    assert!(
        output.stdout.is_empty(),
        "ein verweigerter Lauf sagt nichts auf stdout"
    );
}

/// Ohne den Schalter: `reportHash` steht, `reportSignature` steht NICHT.
///
/// Die positive Haelfte (`reportHash` ist da) macht die negative erst
/// aussagekraeftig — sonst waere die Zusicherung auch ueber einer leeren Datei
/// wahr. Gemessen wird beides am Dokument selbst und zusaetzlich am
/// geschlossenen Schema.
#[test]
fn an_unsigned_report_carries_no_signature_member() {
    let built = live_clock_archive();
    let laid = lay_out("unsigned-report", &built);

    let anchor = laid.anchor_path();
    let archive = path_argument(laid.archive.path());
    let target = laid.output_path("bericht.json");
    let target_argument = path_argument(&target);

    let output = run(&[
        "--trust-anchor",
        &anchor,
        "report",
        &archive,
        "--output",
        &target_argument,
    ]);
    assert_eq!(
        code_of(&output),
        0,
        "der Lauf ohne Schalter muss durchgehen; stderr war: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let document = String::from_utf8(fs::read(&target).expect("der Bericht muss lesbar sein"))
        .expect("das Berichtsdokument ist UTF-8");

    assert!(
        !document.contains("reportSignature"),
        "ein unsignierter Bericht traegt das Glied GAR NICHT — auch nicht leer: {document}"
    );
    let parsed: Value = serde_json::from_str(&document).expect("das Dokument ist JSON");
    assert!(
        parsed.get("reportSignature").is_none(),
        "auch der geparste Baum darf das Glied nicht kennen"
    );
    assert!(
        parsed
            .get("reportHash")
            .and_then(Value::as_str)
            .is_some_and(|hash| hash.len() == 64),
        "der Bericht ist GEHASHT — sonst waere die Aussage ueber die Signatur leer"
    );

    let schema: Value =
        serde_json::from_str(REPORT_SCHEMA_V1).expect("das gepinnte Schema ist JSON");
    let validator = jsonschema::validator_for(&schema).expect("das gepinnte Schema uebersetzt");
    let errors: Vec<String> = validator
        .iter_errors(&parsed)
        .map(|error| format!("{} an {}", error, error.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "das unsignierte Dokument verletzt das gepinnte Schema: {errors:?}"
    );
}
