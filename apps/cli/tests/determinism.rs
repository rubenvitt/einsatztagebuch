//! Der Bericht als DATEI: dieselben Eingaben, dieselben Bytes.
//!
//! # Was dieses Target misst
//!
//! `apps/cli/tests/exit_codes.rs` misst die Berichtsausgabe auf stdout. HIER
//! wird gemessen, was `report --output` in eine DATEI legt: Byteidentitaet ueber
//! mehrere Laeufe, die Unabhaengigkeit von der Dateireihenfolge des Bestands,
//! die Unberuehrtheit von `reportHash` durch Laufzeitmetadaten, die
//! Schemagueltigkeit BEIDER Dokumentformen und die Zielregeln.
//!
//! # DIE UHR IST HIER KEIN PARAMETER
//!
//! Die CLI kennt genau eine, `SystemTime::now()`. Jeder Bestand stammt deshalb
//! aus der `live_clock_*`-Familie; die geerbten Bestaende sind unter der echten
//! Uhr stumm. Die Begruendung steht in `apps/cli/tests/support/mod.rs`.
//!
//! # EIN BESTAND, MEHRERE LAEUFE
//!
//! `ea_crypto::hpke_seal` zieht je Aufruf ein frisches ephemeres
//! Schluesselpaar. Zwei Aufrufe von `live_clock_archive()` liefern deshalb
//! verschiedene Grantbytes. Wer Byteidentitaet misst, materialisiert EINEN
//! Bestand und laesst ihn mehrfach laufen — er baut ihn nicht mehrfach.

#[path = "support/mod.rs"]
mod support;

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use ea_recovery::{RuntimeMetadataV1, emit_report_document, verify_directory};
use ea_trust::decode_trust_anchor;
use ea_verify::VerificationReportV1;
use serde_json::Value;

use support::{LiveArchive, live_clock, live_clock_archive, materialize, temp_dir};

/// Das gepinnte Berichtsschema, zur Uebersetzungszeit eingebettet.
///
/// `include_str!` und kein Lesen zur Laufzeit: `schemas/` ist geschlossen, und
/// der Nachweis soll gegen GENAU die Datei laufen, gegen die dieser Bau
/// uebersetzt wurde.
const REPORT_SCHEMA_V1: &str =
    include_str!("../../../schemas/reports/v1/verification-report.schema.json");

/// Ein auf die Platte gelegter Bestand samt Ankerdatei und Zielverzeichnis.
///
/// Der Anker liegt in einem EIGENEN Verzeichnis und niemals im Bestand: eine
/// Ankerdatei unter der Archivwurzel wuerde mitgelesen und als Beiwerk
/// gezaehlt. Das Zielverzeichnis liegt aus demselben Grund getrennt — eine
/// Berichtsdatei im Bestand veraenderte den Bestand, ueber den sie berichtet.
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

/// Laesst `report` gegen `laid` laufen und liefert den Exitcode.
///
/// AUSDRUECKLICH OHNE `--format`: die Vorgabe ist `text`, und die Zieldatei
/// traegt trotzdem das kanonische Berichtsdokument. Der Schalter waehlt die
/// Form der stdout-Ausgabe und nicht die des Berichts — waere es anders, gaebe
/// es zwei Dateiformen unter einem Namen und keine Byteidentitaet zu messen.
fn run_report(laid: &Laid, archive: &Path, output: &Path) -> i32 {
    let anchor = laid.anchor_path();
    let archive = path_argument(archive);
    let output = path_argument(output);
    code_of(&run(&[
        "--trust-anchor",
        &anchor,
        "report",
        &archive,
        "--output",
        &output,
    ]))
}

/// Laesst `report` MIT `--format <format>` laufen.
///
/// `--format` ist ein GLOBALER Schalter: `args.rs` schraenkt ihn auf kein
/// Kommando ein, also nimmt `report` ihn an. Er darf die Zieldatei trotzdem
/// nicht beruehren — gemessen und nicht behauptet.
fn run_report_with_format(laid: &Laid, format: &str, output: &Path) -> i32 {
    let anchor = laid.anchor_path();
    let archive = path_argument(laid.archive.path());
    let output = path_argument(output);
    code_of(&run(&[
        "--trust-anchor",
        &anchor,
        "--format",
        format,
        "report",
        &archive,
        "--output",
        &output,
    ]))
}

/// Laesst `report` MIT `--include-runtime-metadata` laufen.
fn run_report_with_runtime_metadata(laid: &Laid, output: &Path) -> i32 {
    let anchor = laid.anchor_path();
    let archive = path_argument(laid.archive.path());
    let output = path_argument(output);
    code_of(&run(&[
        "--trust-anchor",
        &anchor,
        "--include-runtime-metadata",
        "report",
        &archive,
        "--output",
        &output,
    ]))
}

/// Der Bericht desselben Bestands, gerechnet OHNE Prozessstart.
///
/// Die Uhr ist dieselbe wie im Prozess — beide liegen im Registrierungsfenster
/// der `live_clock_*`-Familie, und der Bericht traegt kein einziges aus der Uhr
/// abgeleitetes Feld.
fn report_of(laid: &Laid) -> VerificationReportV1 {
    let anchor_bytes =
        fs::read(laid.anchor.path().join("anchor.bin")).expect("die Ankerdatei muss lesbar sein");
    let anchor = decode_trust_anchor(&anchor_bytes).expect("der Anker muss dekodieren");
    verify_directory(laid.archive.path(), &anchor, live_clock(), None)
        .expect("der Bestand muss berichten")
}

/// Liest ein geschriebenes Dokument als Zeichenkette.
fn document_at(path: &Path) -> String {
    String::from_utf8(fs::read(path).expect("der Bericht muss lesbar sein"))
        .expect("das Berichtsdokument ist UTF-8")
}

/// Prueft ein Dokument gegen `schemas/reports/v1/verification-report.schema.json`.
fn assert_valid_against_schema(document: &str, label: &str) {
    let parsed: Value = serde_json::from_str(document)
        .unwrap_or_else(|error| panic!("{label} muss parsbare JSON sein: {error}: {document}"));
    let schema: Value =
        serde_json::from_str(REPORT_SCHEMA_V1).expect("das gepinnte Schema ist JSON");
    let validator = jsonschema::validator_for(&schema).expect("das gepinnte Schema uebersetzt");
    let errors: Vec<String> = validator
        .iter_errors(&parsed)
        .map(|error| format!("{} an {}", error, error.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "{label} verletzt das gepinnte Schema: {errors:?}"
    );
}

/// DER KERN DIESES TASKS: derselbe Bestand, dieselben Berichtsbytes.
///
/// Drei Laeufe, und der dritte ist der eigentliche Beweis: er laeuft ueber
/// denselben Bestand, der unter VERTAUSCHTEN Pfaden materialisiert wurde.
/// Pfade klassifizieren im Einsatzarchiv nie — sie sind ein HINWEIS, und
/// klassifiziert wird am 9-Byte-Praefix. Ein Bericht, der sich mit der
/// Dateireihenfolge aenderte, haette also eine Ordnung aus dem Dateisystem
/// uebernommen, statt sie selbst zu setzen.
#[test]
fn report_is_byte_identical_without_runtime_metadata() {
    let built = live_clock_archive();
    let laid = lay_out("determinism", &built);

    let first = laid.output_path("first.json");
    assert_eq!(
        run_report(&laid, laid.archive.path(), &first),
        0,
        "erster Lauf"
    );
    let second = laid.output_path("second.json");
    assert_eq!(
        run_report(&laid, laid.archive.path(), &second),
        0,
        "zweiter Lauf"
    );

    let first_bytes = fs::read(&first).expect("der erste Bericht muss lesbar sein");
    let second_bytes = fs::read(&second).expect("der zweite Bericht muss lesbar sein");
    assert_eq!(
        first_bytes, second_bytes,
        "zwei Laeufe ueber denselben Bestand muessen dieselben Bytes schreiben"
    );

    // Der dritte Lauf: derselbe Bestand unter vertauschten Pfadhinweisen.
    let shuffled_fixture = built.fixture.randomized_paths();
    let hints = |fixture: &support::verify_support::archive_support::ArchiveFixture| {
        fixture
            .blobs()
            .iter()
            .map(|(hint, _)| hint.clone())
            .collect::<Vec<_>>()
    };
    // OHNE diesen Waechter waere der dritte Lauf still aussagelos, sobald
    // `randomized_paths` je zur Identitaet degenerierte.
    assert_ne!(
        hints(&built.fixture),
        hints(&shuffled_fixture),
        "der dritte Lauf muss eine ANDERE Dateireihenfolge vorfinden"
    );
    let shuffled = temp_dir("determinism-shuffled");
    materialize(&shuffled_fixture, shuffled.path());

    let third = laid.output_path("third.json");
    assert_eq!(
        run_report(&laid, shuffled.path(), &third),
        0,
        "dritter Lauf"
    );
    assert_eq!(
        fs::read(&third).expect("der dritte Bericht muss lesbar sein"),
        first_bytes,
        "der Pfadhinweis ist ein Hinweis: er darf den Bericht nicht veraendern"
    );

    // Der vierte Lauf: DERSELBE Bestand, aber mit `--format json`. Der Schalter
    // wird global geparst und von `report` angenommen; die Zieldatei traegt
    // trotzdem dieselben Bytes. Ohne diesen Lauf stuende die Aussage nur als
    // Satz in `apps/cli/src/commands/report.rs` — und ein spaeter eingebautes
    // `match` ueber `Format` braeche keinen einzigen Test.
    for format in ["text", "json"] {
        let target = laid.output_path(&format!("format-{format}.json"));
        assert_eq!(
            run_report_with_format(&laid, format, &target),
            0,
            "Lauf mit --format {format}"
        );
        assert_eq!(
            fs::read(&target).expect("der Bericht muss lesbar sein"),
            first_bytes,
            "--format waehlt die Bildschirmform und NICHT die Form der Berichtsdatei"
        );
    }
}

/// `reportHash` haengt NICHT an den Laufzeitmetadaten.
///
/// Sein Urbild ist das Dokument OHNE `reportHash`, `reportSignature` und
/// `runtimeMetadata` (`crates/ea-verify/src/report.rs::canonical_hash_preimage`).
/// Waere es anders, koennte derselbe Bestand je nach Schalter zwei
/// verschiedene Hashes tragen — und der Hash haette aufgehoert, den Bestand zu
/// benennen.
///
/// Gemessen wird zusaetzlich die STAERKERE Aussage: die beiden Dokumente
/// unterscheiden sich AUSSCHLIESSLICH um das angehaengte Glied. Ein Vergleich
/// nur der Hashes uebersaehe, wenn `--include-runtime-metadata` nebenbei ein
/// anderes Feld veraenderte.
#[test]
fn report_hash_is_unaffected_by_runtime_metadata() {
    let built = live_clock_archive();
    let laid = lay_out("runtime-metadata", &built);

    let plain_path = laid.output_path("plain.json");
    assert_eq!(
        run_report(&laid, laid.archive.path(), &plain_path),
        0,
        "Lauf ohne Metadaten"
    );
    let with_path = laid.output_path("with-metadata.json");
    assert_eq!(
        run_report_with_runtime_metadata(&laid, &with_path),
        0,
        "Lauf mit Metadaten"
    );

    let plain = document_at(&plain_path);
    let with_metadata = document_at(&with_path);
    assert_ne!(
        plain, with_metadata,
        "mit dem Schalter muss ein Glied hinzukommen"
    );

    let plain_body = plain
        .strip_suffix("\n}")
        .expect("das kanonische Dokument endet auf der schliessenden Klammer");
    let tail = with_metadata
        .strip_prefix(plain_body)
        .unwrap_or_else(|| panic!("das Dokument mit Metadaten muss auf {plain_body} aufbauen"));
    assert!(
        tail.starts_with(",\n  \"runtimeMetadata\": {\n") && tail.ends_with("\n}"),
        "angehaengt werden darf GENAU das runtimeMetadata-Glied, war: {tail}"
    );

    let plain_value: Value = serde_json::from_str(&plain).expect("das Dokument ist JSON");
    let with_value: Value = serde_json::from_str(&with_metadata).expect("das Dokument ist JSON");
    assert_eq!(
        plain_value["reportHash"], with_value["reportHash"],
        "der reportHash darf sich nicht bewegen"
    );

    // Und er ist der GERECHNETE, nicht irgendeiner: derselbe Bestand ohne
    // Prozessstart traegt denselben Wert.
    let report = report_of(&laid);
    let expected = report
        .report_hash()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(plain_value["reportHash"], Value::String(expected));

    // Die vier Glieder stehen vollstaendig und in Schema-Property-Reihenfolge.
    let runtime = &with_value["runtimeMetadata"];
    assert!(
        runtime["generatedAt"].is_i64()
            && runtime["hostName"].is_string()
            && runtime["inputPath"].is_string()
            && runtime["runtimeMs"].is_u64(),
        "runtimeMetadata muss alle vier Glieder tragen, war: {runtime}"
    );
    assert_eq!(
        runtime["inputPath"],
        Value::String(path_argument(laid.archive.path())),
        "inputPath ist der Pfad, WIE IHN DER AUFRUFER eingegeben hat"
    );
}

/// BEIDE Dokumentformen sind schemagueltig — auch mit feindlichen Zeichenketten.
///
/// # Warum hier ein DRITTES Dokument entsteht
///
/// Die beiden Laeufe oben belegen den Escaper NICHT: `HOSTNAME` ist auf darwin
/// meist ungesetzt (dann steht dort `unknown`), und ein Temporaerpfad enthaelt
/// weder `"` noch `\` noch ein Steuerzeichen. Jede Zusicherung ueber sie liefe
/// ueber ein Dokument, in dem [`emit_report_document`]s Escaper ein
/// Nichtstuer war — vakuum-wahr. Das dritte Dokument entsteht deshalb im
/// Prozess und traegt in `hostName` und `inputPath` genau die drei Klassen, die
/// maskiert werden muessen.
///
/// Gemessen wird der RUECKWEG: `serde_json` liest die Zeichenketten wieder aus
/// und muss die urspruenglichen Werte liefern. Das ist die eine Probe, die eine
/// falsche Maskierung nicht bestehen kann.
#[test]
fn both_document_shapes_validate_against_the_closed_schema() {
    let built = live_clock_archive();
    let laid = lay_out("schema-proof", &built);

    let plain_path = laid.output_path("plain.json");
    assert_eq!(run_report(&laid, laid.archive.path(), &plain_path), 0);
    let with_path = laid.output_path("with-metadata.json");
    assert_eq!(run_report_with_runtime_metadata(&laid, &with_path), 0);

    assert_valid_against_schema(&document_at(&plain_path), "das Dokument ohne Metadaten");
    assert_valid_against_schema(&document_at(&with_path), "das Dokument mit Metadaten");

    let hostile_host = "reco\"very\\host\u{1}";
    let hostile_path = "C:\\Einsatz\\\"archiv\"\n";
    let hostile = emit_report_document(
        &report_of(&laid),
        Some(&RuntimeMetadataV1 {
            generated_at: 1_786_938_024_364,
            host_name: hostile_host.to_owned(),
            input_path: hostile_path.to_owned(),
            runtime_ms: 7,
        }),
    )
    .expect("der Emitter muss auch freie Zeichenketten schreiben");

    assert_valid_against_schema(&hostile, "das Dokument mit feindlichen Zeichenketten");
    let parsed: Value = serde_json::from_str(&hostile).expect("das Dokument ist JSON");
    assert_eq!(
        parsed["runtimeMetadata"]["hostName"],
        Value::String(hostile_host.to_owned()),
        "der Rueckweg muss GENAU den Ausgangswert liefern"
    );
    assert_eq!(
        parsed["runtimeMetadata"]["inputPath"],
        Value::String(hostile_path.to_owned())
    );
    // Und die Bytes selbst, damit nicht nur der Rueckweg, sondern auch die FORM
    // gepinnt ist.
    assert!(
        hostile.contains(r#""hostName": "reco\"very\\host\u0001""#)
            && hostile.contains(r#""inputPath": "C:\\Einsatz\\\"archiv\"\u000a""#),
        "die Maskierung muss byteweise stehen, war: {hostile}"
    );
}

/// Eine EXISTIERENDE Zieldatei beendet den Lauf mit 2 — und bleibt unberuehrt.
///
/// Ein Wiederherstellungswerkzeug, das ein vorhandenes Ziel ueberschriebe,
/// vernichtete unter Umstaenden genau das, was jemand retten wollte. Der Code
/// ist 2 und nicht 20: es ist nichts gescheitert, sondern der Aufruf nennt ein
/// Ziel, das nicht frei ist.
#[test]
fn report_refuses_an_existing_output_file() {
    let built = live_clock_archive();
    let laid = lay_out("occupied-output", &built);

    let occupied = laid.output_path("bericht.json");
    let previous = b"dies ist ein fremder Inhalt, der bleiben muss";
    fs::write(&occupied, previous).expect("die Zieldatei muss anlegbar sein");

    assert_eq!(
        run_report(&laid, laid.archive.path(), &occupied),
        2,
        "ein belegtes Ziel ist ein Konfigurationsfehler"
    );
    assert_eq!(
        fs::read(&occupied).expect("die Zieldatei muss lesbar bleiben"),
        previous,
        "die vorhandene Datei darf nicht angetastet werden"
    );
}

/// Die Zieldatei gehoert dem Eigentuemer allein.
///
/// Ein Bericht nennt Objekthashes, Kettenkoepfe und Abdruecke eines Bestands.
/// Auf einem geteilten Rechner ist das nichts, was jeder mitlesen soll.
#[cfg(unix)]
#[test]
fn report_writes_its_target_with_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt as _;

    let built = live_clock_archive();
    let laid = lay_out("output-mode", &built);

    let target = laid.output_path("bericht.json");
    assert_eq!(run_report(&laid, laid.archive.path(), &target), 0);

    let mode = fs::metadata(&target)
        .expect("die Zieldatei muss existieren")
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o777,
        0o600,
        "die Zieldatei muss 0600 tragen, war: {:o}",
        mode & 0o777
    );
}
