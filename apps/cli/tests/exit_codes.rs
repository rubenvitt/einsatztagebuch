//! `verify` und `list` von Ende zu Ende, gemessen am echten Prozess.
//!
//! # Was dieses Target misst — und was nicht
//!
//! `crates/ea-recovery/tests/exit_codes.rs` misst die ABLEITUNG: welcher
//! Berichtszustand auf welche Zeile der Norm faellt, ohne Prozessstart und mit
//! der Uhr als Parameter. HIER wird gemessen, was den PROZESS verlaesst: der
//! Exitcode, die Bytes auf stdout, der Strom, auf dem eine Meldung erscheint.
//! Beides ist noetig — eine Ableitung ohne Prozess sagt nichts ueber den
//! Exitcode, ein Exitcode ohne Ableitung nichts darueber, warum er kam.
//!
//! # DIE UHR IST HIER KEIN PARAMETER
//!
//! Die CLI kennt genau eine, `SystemTime::now()`. Jeder Bestand, der hier einen
//! BEFUND belegt, stammt deshalb aus der `live_clock_*`-Familie; die geerbten
//! Bestaende sind unter der echten Uhr stumm. Die eine Ausnahme —
//! `complete_valid_archive` — steht hier ausdruecklich als GEGENFALL und ist in
//! [`an_inherited_archive_at_the_real_clock_fails_with_fifteen`] begruendet.
//!
//! # EIN CODE IST AUS `verify` UND `list` NICHT ERREICHBAR
//!
//! - `Key` (14) verlangt einen Entschluesselungsfehler, und der entsteht nur,
//!   wenn ein Empfaengerschluessel im Lauf steht. `--key` gehoert nach
//!   `apps/cli/src/args.rs` AUSSCHLIESSLICH zu `decrypt`; `verify` und `list`
//!   entkapseln nichts. Gemessen und gepinnt in
//!   [`a_foreign_encapsulation_stays_invisible_without_a_recipient_key`].
//!
//! # `Evidence` (13) IST ERREICHBAR — ungemessen ist nicht dasselbe wie
//! unerreichbar
//!
//! Hier stand, Code 13 verlange `VerifyOptions::with_evidence_requirement`, das
//! `ea_recovery::verify_directory` nicht durchreicht. DAS IST FALSCH, und die
//! Begruendung ist an zwei Stellen im Code nachlesbar widerlegt:
//! `run_evidence_gate` legt `TokenNotBound` und `RenewalInputUnknown` in
//! `evidenceErrors` ab, BEVOR es ohne Forderung zurueckkehrt
//! (`crates/ea-verify/src/evidence.rs:157`), und Regel 4 der Ableitung fragt
//! allein, ob `evidenceErrors` leer ist — nach der Forderung fragt sie nicht
//! (`crates/ea-recovery/src/exit.rs:111`). Ein schlichtes `verify` ueber einen
//! Bestand mit einem `.ecp`, dessen archiviertes `rfc3161Response` nicht zum
//! `3161-ctt`-Header seines COSE-Objekts passt, endet deshalb mit 13.
//!
//! UNGEMESSEN bleibt der Pfad aus einem Grund der Fixture-Kette und nicht der
//! Norm: keine Fixture dieser Kette baut ein `.ecp` mit RFC-3161-Anteilen. Der
//! eingefrorene Vektor, der es koennte —
//! `timestamp/rejected-replaced-ctt-header`, gepinnt in
//! `tests/ea-system-tests/tests/conformance_golden_vectors.rs:3149` — liegt in
//! einer Testcrate ohne `ea-recovery` im Graphen, und `ea-testkit` steht
//! umgekehrt nicht in den Dev-Dependencies dieser Kette. Wer den Fall messen
//! will, verdrahtet zuerst das eine oder das andere; er darf sich nur nicht
//! darauf verlassen, dass der Code hier nicht hinkommt.

#[path = "support/mod.rs"]
mod support;

use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

use ea_format::EIP_PREFIX_V1;
use ea_recovery::{load_trust_anchor, verify_directory};
use ea_trust::decode_trust_anchor;
use ea_types::ChainSequence;
use ea_verify::VerificationReportV1;

use support::{
    LiveArchive, live_clock, live_clock_archive, live_clock_archive_with_a_missing_middle_entry,
    live_clock_archive_with_foreign_encapsulation,
    live_clock_archive_with_mutated_writer_signature, live_clock_archive_without_trust_objects,
    materialize, temp_dir,
    verify_support::{archive_support::trust_support, complete_valid_archive},
};

/// Ein auf die Platte gelegter Bestand samt seiner Ankerdatei.
///
/// Der Anker liegt in einem EIGENEN Verzeichnis und niemals im Bestand: eine
/// Ankerdatei unter der Archivwurzel wuerde von
/// `ea_recovery::FsArchiveSource::open` mitgelesen und als Beiwerk gezaehlt —
/// der Bestand saehe je nach Testaufbau anders aus. `design.md`:1765 verlangt
/// ohnehin, dass der Anker VON AUSSEN kommt; hier wird das auch raeumlich wahr.
struct Laid {
    archive: support::TempDir,
    anchor: support::TempDir,
}

impl Laid {
    /// Der Pfad der Archivwurzel als Argument.
    fn archive_path(&self) -> String {
        path_argument(self.archive.path())
    }

    /// Der Pfad der Ankerdatei als Argument.
    fn anchor_path(&self) -> String {
        path_argument(&self.anchor.path().join("anchor.bin"))
    }
}

/// Ein vom Testrahmen selbst gebildeter Pfad als Argumentzeichenkette.
fn path_argument(path: &Path) -> String {
    path.to_str()
        .expect("der vom Testrahmen selbst gebildete Pfad ist UTF-8")
        .to_owned()
}

/// Legt `fixture` und `anchor_bytes` ab.
fn lay_out(tag: &str, built: &LiveArchive) -> Laid {
    lay_out_with_anchor(tag, built, &built.anchor_bytes)
}

/// Wie [`lay_out`], aber mit einem FREMDEN oder verstuemmelten Anker.
fn lay_out_with_anchor(tag: &str, built: &LiveArchive, anchor_bytes: &[u8]) -> Laid {
    let archive = temp_dir(&format!("{tag}-archive"));
    materialize(&built.fixture, archive.path());
    let anchor = temp_dir(&format!("{tag}-anchor"));
    fs::write(anchor.path().join("anchor.bin"), anchor_bytes)
        .expect("die Ankerdatei muss schreibbar sein");
    Laid { archive, anchor }
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

/// Startet `command` gegen `laid` und liefert Exitcode und stdout.
fn run_command(command: &str, laid: &Laid, format: &str) -> (i32, Vec<u8>) {
    let anchor = laid.anchor_path();
    let archive = laid.archive_path();
    let output = run(&[
        "--trust-anchor",
        &anchor,
        "--format",
        format,
        command,
        &archive,
    ]);
    (code_of(&output), output.stdout)
}

/// Der Bericht desselben Bestands, gerechnet OHNE Prozessstart.
///
/// Die Uhr ist hier dieselbe wie im Prozess — beide liegen im
/// Registrierungsfenster der `live_clock_*`-Familie, und der Bericht traegt
/// kein einziges aus der Uhr abgeleitetes Feld. Deshalb ist der Vergleich
/// beider Wege eine Aussage ueber den Kommandopfad und nicht ueber die Zeit.
fn report_of(laid: &Laid) -> VerificationReportV1 {
    let anchor_bytes =
        fs::read(laid.anchor.path().join("anchor.bin")).expect("die Ankerdatei muss lesbar sein");
    let anchor = decode_trust_anchor(&anchor_bytes).expect("der Anker muss dekodieren");
    verify_directory(laid.archive.path(), &anchor, live_clock(), None)
        .expect("der Bestand muss berichten")
}

// ===========================================================================
// Der Angriff mit einem fremden Anker
// ===========================================================================

/// DER KERN DES TASKS: ein in sich stimmiger FREMDER Anker endet mit 12.
///
/// Der BESTAND bleibt unveraendert und vollstaendig gueltig — er verifiziert
/// gegen seinen eigenen Anker mit Code 0, und genau das misst
/// [`a_live_archive_verifies_with_zero`]. Ausgetauscht wird allein der Anker.
///
/// # Woher der fremde Anker stammt, und was daran gemessen wurde
///
/// `trust_support::RegistryLineBuilder::with_first_admin_revoked_from(Some(1))`
/// baut dieselbe Linienform mit einem abweichenden ersten Admin-Zertifikat und
/// einer abweichenden Bindung. GEMESSEN (Sonde gegen `ea-recovery`, danach
/// entfernt): die 384 Ankerbytes unterscheiden sich, und zwar bereits in der
/// `chainId` — `2ff560f2…` gegen `b5c2ab24…`. Die Bytes sind also NICHT
/// dieselben, und der Test steht nicht auf einer Tautologie.
///
/// GEMESSEN wurde ebenso der WEG: derselbe Bestand liefert gegen diesen Anker
/// `publicKeyThumbprints = 0`, `objectResults = 0`, `isFullyVerified = false`
/// und KEINEN einzigen Format-, Quarantaene- oder Signaturbefund. Es scheitert
/// also nicht die Dekodierung des Ankers, sondern Gate `trust` traegt nicht,
/// die Pipeline endet FAIL-CLOSED, und Regel 3 der Ableitung greift. Beide Wege
/// muessen auf 12 fuehren; dieser Fall dokumentiert, dass hier der zweite
/// gemessen wurde. Den ersten misst
/// [`an_undecodable_anchor_fails_with_twelve`].
#[test]
fn a_foreign_but_self_consistent_anchor_fails_with_twelve() {
    let built = live_clock_archive();
    let foreign_line = trust_support::RegistryLineBuilder::with_first_admin_revoked_from(Some(
        ChainSequence::new(1),
    ));
    let foreign_anchor_bytes = foreign_line.exact_anchor_bytes().to_vec();
    assert_ne!(
        foreign_anchor_bytes, built.anchor_bytes,
        "ein fremder Anker, der dieselben Bytes traegt, waere keiner"
    );

    let laid = lay_out_with_anchor("foreign-anchor", &built, &foreign_anchor_bytes);
    let (code, _) = run_command("verify", &laid, "text");
    assert_eq!(code, 12, "exit code");

    // Der Weg, nicht nur das Ergebnis: der fremde Anker DEKODIERT — er ist in
    // sich stimmig —, und trotzdem sagt der Lauf ueber kein Objekt etwas.
    let report = report_of(&laid);
    assert_eq!(
        report.public_key_thumbprints().len(),
        0,
        "der fremde Anker traegt keine einzige gelungene Signaturpruefung"
    );
    assert_eq!(
        report.object_results().len(),
        0,
        "ueber kein Objekt darf gegen einen fremden Anker etwas ausgesagt werden"
    );
    assert_eq!(
        report.quarantined_objects().len() + report.signature_errors().len(),
        0,
        "der Bestand ist unversehrt; es faellt der Anker, nicht ein Objekt"
    );
}

/// Eine FEHLENDE Ankerdatei ist ein Dateisystemfehler (20).
#[test]
fn a_missing_anchor_file_fails_with_twenty() {
    let built = live_clock_archive();
    let laid = lay_out("absent-anchor", &built);
    let archive = laid.archive_path();
    let absent = path_argument(&laid.anchor.path().join("gibt-es-nicht.bin"));

    let output = run(&["--trust-anchor", &absent, "verify", &archive]);

    assert_eq!(code_of(&output), 20, "exit code");
    assert!(
        output.stdout.is_empty(),
        "ohne Bericht gibt es keine Nutzausgabe, war: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// Ein Anker mit einem gekippten Byte endet mit 12 — auf dem ANDEREN Weg.
///
/// GEMESSEN (dieselbe Sonde): von den 384 Ankerbytes brechen die Offsets 0 bis
/// 350 die Dekodierung; die verbleibenden 32 sind der letzte Hashwert des
/// Ankers und ueberstehen ein Kippen. Gekippt wird deshalb Offset 0, und der
/// gemessene Weg ist ausdruecklich der ERSTE: `decode_trust_anchor` scheitert
/// mit `EA-TRUST-ANCHOR-SHAPE`, es entsteht GAR KEIN Bericht, und der Code
/// stammt aus `exit_code_for_error` statt aus `exit_code_for`.
#[test]
fn an_undecodable_anchor_fails_with_twelve() {
    let built = live_clock_archive();
    let mut mutated = built.anchor_bytes.clone();
    mutated[0] ^= 0x01;
    let laid = lay_out_with_anchor("mutated-anchor", &built, &mutated);

    let (code, stdout) = run_command("verify", &laid, "text");
    assert_eq!(code, 12, "exit code");
    assert!(
        stdout.is_empty(),
        "ohne Bericht gibt es keine Nutzausgabe, war: {}",
        String::from_utf8_lossy(&stdout)
    );

    // Der Weg wird BENANNT und nicht erschlossen: die Dekodierung faellt.
    let Err(error) = load_trust_anchor(&laid.anchor.path().join("anchor.bin")) else {
        panic!("ein Anker mit gekipptem Byte darf nicht dekodieren");
    };
    assert!(
        matches!(error, ea_recovery::RecoveryError::TrustAnchor(_)),
        "gemessen werden muss der Ankerbefund, nicht ein Dateisystemfehler: {error:?}"
    );
}

// ===========================================================================
// Der Bestand selbst
// ===========================================================================

/// Ein fehlendes Wurzelverzeichnis ist ein Dateisystemfehler (20).
#[test]
fn a_missing_archive_directory_fails_with_twenty() {
    let built = live_clock_archive();
    let laid = lay_out("absent-archive", &built);
    let anchor = laid.anchor_path();
    let absent = path_argument(&laid.archive.path().join("gibt-es-nicht"));

    let output = run(&["--trust-anchor", &anchor, "verify", &absent]);
    assert_eq!(code_of(&output), 20, "exit code");
}

/// Ein Archivpfad, der auf eine DATEI zeigt, ebenso.
///
/// Eine Datei ist kein Bestand. Ihn dennoch zu lesen — etwa als einzigen Blob —
/// hiesse, aus einem Bedienfehler stillschweigend einen Bestand zu erfinden.
#[test]
fn an_archive_path_that_is_a_file_fails_with_twenty() {
    let built = live_clock_archive();
    let laid = lay_out("file-archive", &built);
    let anchor = laid.anchor_path();
    let file = laid.archive.path().join("nicht-verzeichnis.bin");
    fs::write(&file, b"kein Verzeichnis").expect("die Datei muss schreibbar sein");
    let file = path_argument(&file);

    let output = run(&["--trust-anchor", &anchor, "verify", &file]);
    assert_eq!(code_of(&output), 20, "exit code");
}

/// Ein LEERES Verzeichnis mit gueltigem Anker endet mit 12.
///
/// Ohne Trust-Objekte traegt Gate `trust` nicht, und der Lauf endet
/// fail-closed. Ausdruecklich NICHT 0: ein Werkzeug, das ueber ein leeres
/// Verzeichnis Erfolg meldete, bestaetigte einen Bestand, den es nicht gibt.
#[test]
fn an_empty_directory_fails_with_twelve() {
    let built = live_clock_archive();
    let archive = temp_dir("empty-archive");
    let anchor = temp_dir("empty-anchor");
    fs::write(anchor.path().join("anchor.bin"), &built.anchor_bytes)
        .expect("die Ankerdatei muss schreibbar sein");
    let laid = Laid { archive, anchor };

    let (code, _) = run_command("verify", &laid, "text");
    assert_eq!(code, 12, "exit code");
}

/// Derselbe Befund, wenn die Trust-Objekte fehlen, der Bestand aber steht.
#[test]
fn an_archive_without_trust_objects_fails_with_twelve() {
    let built = live_clock_archive_without_trust_objects();
    let laid = lay_out("no-trust", &built);

    let (code, _) = run_command("verify", &laid, "text");
    assert_eq!(code, 12, "exit code");
}

/// Der Erfolgspfad: 0, und der Bericht auf stdout traegt den GERECHNETEN
/// `reportHash`.
///
/// Die zweite Haelfte ist die eigentliche Aussage. Ein Exitcode 0 allein sagte
/// nur, dass niemand widersprochen hat; der `reportHash` bindet die Ausgabe an
/// genau den Bericht, den dieselbe Fassade ohne Prozessstart bildet.
#[test]
fn a_live_archive_verifies_with_zero() {
    let built = live_clock_archive();
    let laid = lay_out("verify-success", &built);

    let (code, stdout) = run_command("verify", &laid, "json");
    assert_eq!(code, 0, "exit code");

    let report = report_of(&laid);
    let expected = report
        .to_canonical_json()
        .expect("der Bericht muss kanonisch schreibbar sein");
    assert_eq!(
        String::from_utf8_lossy(&stdout),
        expected,
        "die JSON-Ausgabe muss GENAU das kanonische Berichtsdokument sein"
    );
    assert!(
        expected.contains(&hex::encode(report.report_hash().as_bytes())),
        "das Dokument muss den gerechneten reportHash tragen"
    );
}

/// Die beiden unter der echten Uhr erreichbaren Befundcodes: 10 und 11.
///
/// Beide Bestaende stammen aus der `live_clock_*`-Familie und tragen je GENAU
/// EINEN Befund — gemessen in `crates/ea-recovery/tests/live_clock.rs`. Ein
/// zweiter Befund lenkte den Bestand still auf einen kleineren Code um und
/// machte ihn als Beleg wertlos.
#[test]
fn every_reachable_live_finding_maps_to_its_normative_exit_code() {
    let built = live_clock_archive_with_mutated_writer_signature();
    let laid = lay_out("live-integrity", &built);
    let (code, _) = run_command("verify", &laid, "text");
    assert_eq!(code, 10, "ein Signaturbefund ist Integrity");

    let built = live_clock_archive_with_a_missing_middle_entry();
    let laid = lay_out("live-chain", &built);
    let (code, _) = run_command("verify", &laid, "text");
    assert_eq!(code, 11, "eine Kettenluecke ist Chain");
}

/// Ein Bestand mit FREMDER Kapselung bleibt unter `verify` unsichtbar.
///
/// KEIN Versaeumnis, sondern die Grenze dieses Kommandos: `verify` bekommt
/// keinen Empfaengerschluessel — `--key` gehoert nach `apps/cli/src/args.rs`
/// ausschliesslich zu `decrypt` —, also findet gar keine Entkapselung statt,
/// `decryptionErrors` bleibt leer, und Regel 5 der Ableitung greift nie. Code
/// 14 entsteht deshalb AUSSCHLIESSLICH im Kommandopfad von `decrypt`.
///
/// Der Bestand ist ansonsten lupenrein: drei Eintraege, keine Luecke, keine
/// gefallene Signatur. Deshalb 0.
#[test]
fn a_foreign_encapsulation_stays_invisible_without_a_recipient_key() {
    let built = live_clock_archive_with_foreign_encapsulation();
    let laid = lay_out("live-key", &built);

    let (code, _) = run_command("verify", &laid, "text");
    assert_eq!(
        code, 0,
        "ohne Empfaengerschluessel wird nichts entkapselt, also gibt es keinen Befund"
    );

    let report = report_of(&laid);
    assert_eq!(
        report.decryption_errors().len(),
        0,
        "ohne Schluessel entsteht kein Entschluesselungsfehler"
    );
}

/// Der GEGENFALL zu Code 15: geprueft und dennoch stumm.
///
/// Hier steht ABSICHTLICH ein geerbter Bestand, und zwar genau deshalb, weil er
/// unter der echten Uhr degeneriert: seine Registrierungskoepfe sind samtlich
/// veraltet, `isFullyVerified` bleibt wahr, und ueber den einen geparsten
/// Eintrag wird NICHTS ausgesagt. Ohne Regel 6 der Ableitung meldete die CLI
/// genau hier Erfolg ueber einen Bestand, ueber den sie nichts gesagt hat.
///
/// Das ist der einzige Ort in `apps/cli`, an dem ein geerbter Bestand vorkommt,
/// und er ist kein Erfolgspfad, sondern dessen Gegenprobe.
#[test]
fn an_inherited_archive_at_the_real_clock_fails_with_fifteen() {
    let built = complete_valid_archive();
    let archive = temp_dir("inherited-archive");
    materialize(&built.fixture, archive.path());
    let anchor = temp_dir("inherited-anchor");
    fs::write(anchor.path().join("anchor.bin"), &built.anchor_bytes)
        .expect("die Ankerdatei muss schreibbar sein");
    let laid = Laid { archive, anchor };

    let (code, _) = run_command("verify", &laid, "text");
    assert_eq!(code, 15, "exit code");

    let report = report_of(&laid);
    assert!(
        report.is_fully_verified()
            && report.object_results().len() == 0
            && report.entry_package_count() == 1,
        "der geerbte Bestand ist unter der echten Uhr geprueft und dennoch stumm"
    );
}

// ===========================================================================
// Die Ausgabeform
// ===========================================================================

/// `verify --format text` ist eine GESCHLOSSENE Zeilenfolge.
///
/// Verglichen wird die GANZE Ausgabe und nicht ein `contains`: nur so faellt
/// eine zusaetzliche Zeile auf. Genau darum geht es — eine Uhrzeit, ein
/// Hostpfad oder eine Laufzeit in der Textausgabe waere der Schleichweg an
/// `--include-runtime-metadata` vorbei, und der Bericht verlaengerte sich still
/// um ein nichtdeterministisches Feld.
///
/// Die Reihenfolge der Fehlerarrays ist die des Berichtsdokuments
/// (`crates/ea-verify/src/report.rs::write_document`) und nicht eine zweite,
/// eigene: es soll genau EINE Ordnungsautoritaet geben.
#[test]
fn the_text_output_is_a_closed_line_sequence() {
    let built = live_clock_archive();
    let laid = lay_out("text-form", &built);

    let (code, stdout) = run_command("verify", &laid, "text");
    assert_eq!(code, 0, "exit code");

    let report = report_of(&laid);
    let expected = format!(
        "archiveObjectCount {}\n\
         entryPackageCount {}\n\
         destroyedEntryCount {}\n\
         nonObjectFileCount {}\n\
         chainHead.sequence {}\n\
         chainHead.entryHash {}\n\
         gaps {}\n\
         formatErrors {}\n\
         quarantinedObjects {}\n\
         signatureErrors {}\n\
         evidenceErrors {}\n\
         decryptionErrors {}\n\
         reportHash {}\n",
        report.archive_object_count(),
        report.entry_package_count(),
        report.destroyed_entry_count(),
        report.non_object_file_count(),
        report.chain_head().sequence().get(),
        hex::encode(report.chain_head().entry_hash().as_bytes()),
        report.gaps().len(),
        report.format_errors().len(),
        report.quarantined_objects().len(),
        report.signature_errors().len(),
        report.evidence_errors().len(),
        report.decryption_errors().len(),
        hex::encode(report.report_hash().as_bytes()),
    );
    assert_eq!(String::from_utf8_lossy(&stdout), expected);

    // Die Form allein genuegt nicht: waeren alle Werte null, pruefte der
    // Vergleich oben nur sich selbst. Diese drei Zahlen sind die Eigenschaften
    // GENAU dieses Bestands und stehen woertlich.
    assert!(
        expected.contains("entryPackageCount 1\n")
            && expected.contains("nonObjectFileCount 2\n")
            && expected.contains("destroyedEntryCount 0\n"),
        "der Live-Bestand traegt einen Eintrag und zwei Nicht-Objekt-Dateien: {expected}"
    );
}

/// `list --format text` gibt je Objektergebnis eine Zeile aus.
#[test]
fn the_listing_prints_one_line_per_object_result() {
    let built = live_clock_archive();
    let laid = lay_out("list-form", &built);

    let (code, stdout) = run_command("list", &laid, "text");
    assert_eq!(code, 0, "exit code");

    let report = report_of(&laid);
    let mut expected = String::new();
    for result in report.object_results() {
        expected.push_str(&format!(
            "{} {} {} {}\n",
            hex::encode(result.object_hash().as_bytes()),
            result.object_type().code(),
            result.result().as_str(),
            result.server_confirmation().as_str(),
        ));
    }
    for quarantined in report.quarantined_objects() {
        expected.push_str(&format!(
            "{} {}\n",
            hex::encode(quarantined.object_hash().as_bytes()),
            quarantined.reason().as_str(),
        ));
    }
    assert_eq!(String::from_utf8_lossy(&stdout), expected);
    assert_eq!(
        expected.lines().count(),
        1,
        "der Live-Bestand traegt genau ein Objektergebnis: {expected}"
    );
}

/// Ein isoliertes Objekt bekommt seine eigene Zeile MIT Grund.
///
/// # Warum der Bestand hier EIGENS praepariert wird
///
/// GEMESSEN: `live_clock_archive_with_mutated_writer_signature()` isoliert kein
/// Objekt — es liefert `signatureErrors = 1` bei `quarantinedObjects = 0`. Ein
/// Test ueber diesem Bestand liefe mit einer LEEREN Schleife durch und bewiese
/// nichts ueber Quarantaenezeilen. Eingeschleust wird deshalb ein Blob mit
/// gueltigem Praefix und unlesbarem Rumpf: das erzeugt PAARWEISE einen
/// `formatError` und einen Quarantaeneeintrag `malformed` — derselbe Griff, den
/// `crates/ea-recovery/tests/exit_codes.rs::the_smallest_specific_code_wins`
/// benutzt.
#[test]
fn the_listing_names_every_quarantined_object_with_its_reason() {
    let mut built = live_clock_archive();
    let mut malformed = EIP_PREFIX_V1.to_vec();
    malformed.extend_from_slice(b"nicht dekodierbar");
    built
        .fixture
        .push_exact_bytes("entries/000000000099_broken.eip", malformed);
    let laid = lay_out("list-quarantine", &built);

    let (code, stdout) = run_command("list", &laid, "text");
    assert_eq!(
        code, 10,
        "ein isolierter Bestand meldet weiterhin seinen Befund"
    );

    let report = report_of(&laid);
    assert_eq!(
        report.quarantined_objects().len(),
        1,
        "ohne isoliertes Objekt pruefte die Schleife unten nichts"
    );
    let rendered = String::from_utf8_lossy(&stdout);
    assert_eq!(
        rendered.lines().count(),
        report.object_results().len() + report.quarantined_objects().len(),
        "jede Zeile gehoert genau einem Objekt: {rendered}"
    );
    for quarantined in report.quarantined_objects() {
        let line = format!(
            "{} {}",
            hex::encode(quarantined.object_hash().as_bytes()),
            quarantined.reason().as_str()
        );
        assert!(
            rendered.lines().any(|rendered_line| rendered_line == line),
            "die Zeile {line} muss in der Auflistung stehen: {rendered}"
        );
    }
}

/// `verify --format json` und `list --format json` schreiben BYTEGLEICH.
///
/// EIN materialisierter Bestand, ZWEI Laeufe. Zweimal gebaut waere der Bestand
/// nicht derselbe: `ea_crypto::hpke_seal` zieht je Aufruf ein frisches
/// ephemeres Schluesselpaar, die Grantbytes unterschieden sich, und der Test
/// fiele aus einem Grund, der mit der Ausgabeform nichts zu tun hat.
#[test]
fn verify_and_list_emit_byte_identical_json() {
    let built = live_clock_archive();
    let laid = lay_out("json-identity", &built);

    let (verify_code, verify_stdout) = run_command("verify", &laid, "json");
    let (list_code, list_stdout) = run_command("list", &laid, "json");

    assert_eq!(verify_code, 0, "verify exit code");
    assert_eq!(list_code, 0, "list exit code");
    assert_eq!(
        verify_stdout, list_stdout,
        "beide Kommandos schreiben GENAU das Berichtsdokument"
    );
}

/// Das JSON-Dokument endet OHNE Zeilenumbruch.
///
/// `crates/ea-verify/src/json.rs:20-23` friert diese Form ein. Ein
/// abschliessender Umbruch waere ein zusaetzliches Byte und braeche jede
/// Byteidentitaetsaussage ueber den Bericht.
#[test]
fn the_json_document_carries_no_trailing_newline() {
    let built = live_clock_archive();
    let laid = lay_out("json-trailer", &built);

    let (_, stdout) = run_command("verify", &laid, "json");

    assert_eq!(
        stdout.last().copied(),
        Some(b'}'),
        "das Dokument muss auf der schliessenden Klammer enden, war: {:?}",
        String::from_utf8_lossy(&stdout)
            .chars()
            .rev()
            .take(4)
            .collect::<String>()
    );
}

/// Auch ein Bestand MIT Befund wird berichtet.
///
/// Ein Werkzeug, das bei einem Befund schwiege, zwaenge den Betreiber, den
/// Exitcode zu raten. Der Bericht ist die Diagnose; der Exitcode nur ihre
/// Zusammenfassung.
#[test]
fn a_failing_archive_still_writes_its_report() {
    let built = live_clock_archive_with_a_missing_middle_entry();
    let laid = lay_out("failing-report", &built);

    let (code, stdout) = run_command("verify", &laid, "json");
    assert_eq!(code, 11, "exit code");

    let report = report_of(&laid);
    assert_eq!(
        String::from_utf8_lossy(&stdout),
        report
            .to_canonical_json()
            .expect("der Bericht muss kanonisch schreibbar sein"),
        "auch ein Bestand mit Befund liefert sein vollstaendiges Dokument"
    );
}
