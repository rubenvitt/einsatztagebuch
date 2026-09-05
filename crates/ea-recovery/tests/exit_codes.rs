//! Die normative Exitcodetabelle aus `design.md`:1802-1815, Zeile fuer Zeile.
//!
//! # Warum jeder Fall SEINE ZAEHLER mitpinnt
//!
//! [`exit_code_for`] prueft in AUFSTEIGENDER Codereihenfolge und nimmt den
//! ERSTEN Treffer. Ein Bestand, der unbemerkt einen ZWEITEN Befund traegt,
//! landet damit still auf einem kleineren Code und belegt nicht mehr, wofuer er
//! hier steht. Jeder Fall assertiert deshalb neben dem Code auch die Zaehler,
//! aus denen er entsteht — der Beleg ist das Zaehlerbild, der Code nur sein
//! Ergebnis.
//!
//! # Warum die Berichte aus echten Bestaenden kommen
//!
//! [`VerificationReportV1`] laesst sich ausserhalb von `ea-verify` NICHT
//! bauen: `empty()` und jedes Feld sind `pub(crate)`. Es gibt hier also keinen
//! synthetischen Berichtspfad; jeder Fall materialisiert einen Bestand und
//! laesst ihn durch [`verify_directory`] laufen.
//!
//! # ZWEI UHREN, UND SIE GEHOEREN VERSCHIEDENEN FAMILIEN
//!
//! In DIESEM Target ist die Uhr ein Parameter von [`verify_directory`], und nur
//! deshalb duerfen hier die GEERBTEN Bestaende aus
//! `crates/ea-verify/tests/support` unter [`FIXTURE_OS_WALL_CLOCK_V1`] stehen.
//! Unter `apps/cli` ist das ausgeschlossen: dort gibt es nur
//! `SystemTime::now()`, und unter ihr degenerieren die geerbten Koepfe zu einer
//! leeren Aussage. Die `live_clock_*`-Familie ist dort die einzige zulaessige.
//!
//! # EIN CODE IST HIER NICHT ERREICHBAR, UND DAS IST KEIN VERSAEUMNIS
//!
//! `Unsupported` (21) gehoert zur abgesetzten Berichtssignatur, die aus
//! Task 10 herausgenommen wurde.
//!
//! # `Usage` (2) IST ERREICHBAR — nur nie aus einem BERICHT
//!
//! Er ist eine AUFRUFFORM und kein Befund; aus einem BERICHT entsteht er nie.
//! Aus einem LAUF entsteht er in der ZIELPRUEFUNG dieser Crate: wenn das Ziel
//! eines schreibenden Kommandos bereits belegt ist — gemessen in
//! [`an_occupied_output_is_a_usage_error_and_leaves_the_file_untouched`] — und
//! wenn der genannte Zielpfad ein SYMLINK ist, gemessen in
//! `a_symlinked_output_is_a_usage_error_on_both_paths_and_spares_the_foreign_directory`.
//! Die uebrige Aufrufform prueft der Argumentparser der CLI.
//!
//! # `Evidence` (13) GEHOERT NICHT IN DIESE LISTE
//!
//! Hier stand, Code 13 verlange `VerifyOptions::with_evidence_requirement`, das
//! die feste Signatur von [`verify_directory`] nicht durchreicht. Das ist
//! FALSCH: `run_evidence_gate` fuellt `evidenceErrors` mit `TokenNotBound` und
//! `RenewalInputUnknown`, BEVOR es ohne Forderung zurueckkehrt
//! (`crates/ea-verify/src/evidence.rs:157`), und Regel 4 fragt allein nach
//! einem nicht leeren `evidenceErrors` (`crates/ea-recovery/src/exit.rs:111`).
//! Die Forderung entscheidet nur ueber `Missing` und `Overdue`, nicht ueber die
//! Bindungsbefunde.
//!
//! Ungemessen bleibt der Pfad, weil keine Fixture dieser Kette ein `.ecp` mit
//! RFC-3161-Anteilen baut — nicht, weil der Code ihn nicht erreicht. Die
//! Begruendung steht ausfuehrlich in `apps/cli/tests/exit_codes.rs`.
//!
//! # WAS [`every_finding_maps_to_its_normative_exit_code`] ZUSAGT
//!
//! Jeden GEMESSENEN Befund auf genau seine Zeile der Norm — und ausdruecklich
//! nicht die Vollstaendigkeit der Codemenge. `Evidence` (13) ist nach dem
//! Abschnitt oben erreichbar und steht trotzdem nicht in diesem Test, weil
//! keine Fixture dieser Kette seinen Pfad baut. Der NAME bleibt, weil
//! `docs/traceability/stage-1-gate.md`:31 ihn als Beleg fuer AK 20 fuehrt;
//! seine Reichweite steht hier. Geschlossen ueber die Menge ist allein
//! [`every_exit_code_carries_its_normative_number`] — und der pinnt die
//! ZAHLEN, nicht die Erreichbarkeit.

#[path = "support/mod.rs"]
mod support;

use std::{fs, path::Path};

use ea_crypto::HpkeRecipientPrivateKey;
use ea_format::EIP_PREFIX_V1;
use ea_recovery::{
    ExitCode, RecoveryError, exit_code_for, exit_code_for_error, load_trust_anchor,
    output_directory_is_free, prepare_output_directory, verify_directory, write_report_document,
};
use ea_trust::TrustAnchorV1;
use ea_types::{KeyThumbprint, UnixMillis};
use ea_verify::VerificationReportV1;

use support::{
    live_clock, live_clock_archive, live_clock_archive_without_trust_objects, materialize,
    temp_dir,
    verify_support::{
        DESTRUCTION_STATE_IN_PROGRESS_V1, DESTRUCTION_STATE_PENDING_BACKUP_EXPIRY_V1,
        DESTRUCTION_STATE_REQUESTED_V1, DestructionSpec, FIXTURE_OS_WALL_CLOCK_V1,
        IsolationDefectV1, archive_support::ArchiveFixture, archive_with_a_missing_middle_entry,
        complete_recipient_key_thumbprint, complete_recipient_private_key, complete_valid_archive,
        destruction_archive, isolation_archive,
    },
};

/// Die Uhr, unter der die GEERBTEN Bestaende ihre Aussage tragen.
fn fixture_clock() -> UnixMillis {
    UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1)
}

/// Materialisiert `fixture` und laesst den Bestand durch die Fassade laufen.
///
/// Ueber das DATEISYSTEM und nicht ueber `verify_archive`: gemessen wird die
/// Fassade, die die CLI spaeter benutzt, samt ihrem Weg durch
/// [`ea_recovery::FsArchiveSource`].
fn report_of(
    tag: &str,
    fixture: &ArchiveFixture,
    anchor: &TrustAnchorV1,
    now: UnixMillis,
    recipient: Option<(KeyThumbprint, &HpkeRecipientPrivateKey)>,
) -> VerificationReportV1 {
    let root = temp_dir(tag);
    materialize(fixture, root.path());
    verify_directory(root.path(), anchor, now, recipient).expect("der Bestand muss berichten")
}

/// Der Kern des Tasks: jeder Befund landet auf genau seiner Zeile der Norm.
#[test]
fn every_finding_maps_to_its_normative_exit_code() {
    // ------------------------------------------------------------ 0 -------
    // Ein Bestand, ueber dessen einzigen Eintrag tatsaechlich etwas ausgesagt
    // wurde. `objectResults == entryPackageCount` ist die Bedingung, ohne die
    // Regel 6 zuschluege — genau das trennt Erfolg von einer leeren Aussage.
    let built = live_clock_archive();
    let report = report_of(
        "exit-success",
        &built.fixture,
        &built.anchor(),
        live_clock(),
        None,
    );
    assert!(
        report.is_fully_verified()
            && report.object_results().len() == 1
            && report.entry_package_count() == 1
            && report.destroyed_entry_count() == 0
            && report.authorized_destructions().len() == 0,
        "der Erfolgspfad muss ueber jeden geparsten Eintrag etwas ausgesagt haben"
    );
    assert_eq!(exit_code_for(&report), ExitCode::Success);

    // ----------------------------------------------------------- 10 -------
    // Ein verkipptes Byte in der Schreibersignatur. Der Bestand traegt
    // ZUSAETZLICH eine Luecke — der isolierte Eintrag fehlt der Kette —, und
    // genau deshalb belegt er die Vorrangregel mit: 10 vor 11.
    let built = isolation_archive(IsolationDefectV1::MutatedWriterSignature);
    let report = report_of(
        "exit-integrity",
        &built.fixture,
        &built.anchor(),
        fixture_clock(),
        None,
    );
    assert!(
        report.signature_errors().len() == 1 && report.format_errors().len() == 0,
        "der Befund ist eine gefallene Signaturpruefung"
    );
    assert_eq!(exit_code_for(&report), ExitCode::Integrity);

    // ----------------------------------------------------------- 11 -------
    // Ein fehlender mittlerer Eintrag. KEIN Format-, Quarantaene- oder
    // Signaturbefund — sonst schluege Regel 1 zuerst zu und dieser Fall bewiese
    // nichts ueber Regel 2.
    let built = archive_with_a_missing_middle_entry();
    let report = report_of(
        "exit-chain",
        &built.fixture,
        &built.anchor(),
        fixture_clock(),
        None,
    );
    assert!(
        report.gaps().len() == 2
            && report.format_errors().len() == 0
            && report.quarantined_objects().len() == 0
            && report.signature_errors().len() == 0,
        "eine Luecke ist der EINZIGE Befund dieses Bestands"
    );
    assert_eq!(exit_code_for(&report), ExitCode::Chain);

    // ----------------------------------------------------------- 12 -------
    let built = live_clock_archive_without_trust_objects();
    let report = report_of(
        "exit-trust",
        &built.fixture,
        &built.anchor(),
        live_clock(),
        None,
    );
    assert!(
        report.public_key_thumbprints().len() == 0 && report.quarantined_objects().len() == 0,
        "ohne Registrierungslinie ist keine Signaturpruefung gelungen"
    );
    assert_eq!(exit_code_for(&report), ExitCode::Trust);

    // ----------------------------------------------------------- 14 -------
    // Der Empfaengerschluessel MUSS gesetzt sein. Ohne ihn findet gar keine
    // Entkapselung statt, `decryptionErrors` bliebe leer, und der Bestand
    // liefe auf 15 statt auf 14.
    let private_key = complete_recipient_private_key();
    let built = isolation_archive(IsolationDefectV1::ForeignEncapsulation);
    let report = report_of(
        "exit-key",
        &built.fixture,
        &built.anchor(),
        fixture_clock(),
        Some((complete_recipient_key_thumbprint(), &private_key)),
    );
    assert!(
        report.decryption_errors().len() == 1
            && report.signature_errors().len() == 0
            && report.gaps().len() == 0
            && report.evidence_errors().len() == 0,
        "eine gescheiterte Entkapselung ist der EINZIGE Befund dieses Bestands"
    );
    assert_eq!(exit_code_for(&report), ExitCode::Key);

    // ----------------------------------------------------------- 15 (a) ---
    // DIE WICHTIGSTE ZEILE: vollstaendig geprueft, und ueber den einen
    // geparsten Eintrag ist NICHTS ausgesagt. Der geerbte Bestand unter der
    // ECHTEN Uhr ist genau dieser Fall — `is_fully_verified()` bleibt wahr,
    // `objectResults` ist leer. Ohne Regel 6 meldete die CLI hier Erfolg.
    let built = complete_valid_archive();
    let report = report_of(
        "exit-incomplete-empty",
        &built.fixture,
        &built.anchor(),
        live_clock(),
        None,
    );
    assert!(
        report.is_fully_verified()
            && report.object_results().len() == 0
            && report.entry_package_count() == 1
            && report.public_key_thumbprints().len() == 1,
        "der geerbte Bestand ist unter der echten Uhr geprueft und dennoch stumm"
    );
    assert_eq!(exit_code_for(&report), ExitCode::Incomplete);

    // ----------------------------------------------------------- 15 (b) ---
    // Der zweite Weg auf dieselbe Zeile: „teilweise vernichtet". Der Bestand
    // ist ohne Befund, traegt aber einen autorisierten Vernichtungsvorgang.
    let built = destruction_archive(&[DestructionSpec::new(
        0x51,
        &[
            DESTRUCTION_STATE_REQUESTED_V1,
            DESTRUCTION_STATE_IN_PROGRESS_V1,
            DESTRUCTION_STATE_PENDING_BACKUP_EXPIRY_V1,
        ],
    )]);
    let report = report_of(
        "exit-incomplete-destroyed",
        &built.fixture,
        &built.anchor(),
        fixture_clock(),
        None,
    );
    assert!(
        report.is_fully_verified() && report.authorized_destructions().len() == 1,
        "ein lupenreiner Vorgang ist kein Befund, aber eine Vernichtung"
    );
    assert_eq!(exit_code_for(&report), ExitCode::Incomplete);

    // ----------------------------------------------------------- 20 -------
    // Ein Wurzelverzeichnis, das es nicht gibt. Das ist KEIN Bericht: es
    // entsteht gar keiner, und der Code kommt aus `exit_code_for_error`.
    let absent = temp_dir("exit-io");
    let missing = absent.path().join("gibt-es-nicht");
    let error = verify_directory(&missing, &built.anchor(), fixture_clock(), None)
        .expect_err("ein fehlendes Wurzelverzeichnis kann keinen Bericht erzeugen");
    assert!(
        matches!(error, RecoveryError::Io(_)),
        "ein fehlendes Verzeichnis ist ein Dateisystemfehler, gemessen {error:?}"
    );
    assert_eq!(exit_code_for_error(&error), ExitCode::Io);
}

/// Bei mehreren Befunden gewinnt der KLEINSTE spezifische Code — und der
/// Bericht behaelt trotzdem ALLE Befunde.
///
/// Die zweite Haelfte ist die eigentliche Aussage. Ein Exitcode ist eine
/// Zusammenfassung fuer einen Prozessaufrufer; er darf die Diagnose nicht
/// beschneiden.
#[test]
fn the_smallest_specific_code_wins() {
    let mut built = archive_with_a_missing_middle_entry();
    let anchor = built.anchor();
    // Praefix vorhanden, Parser scheitert: das erzeugt PAARWEISE einen
    // `formatError` und einen Quarantaeneeintrag `malformed` — Regel 1.
    let mut malformed = EIP_PREFIX_V1.to_vec();
    malformed.extend_from_slice(b"nicht dekodierbar");
    built
        .fixture
        .push_exact_bytes("entries/000000000099_broken.eip", malformed);

    let report = report_of(
        "exit-smallest",
        &built.fixture,
        &anchor,
        fixture_clock(),
        None,
    );

    assert!(
        report.format_errors().len() == 1 && report.quarantined_objects().len() == 1,
        "der eingeschleuste Blob muss als Formatbefund erscheinen"
    );
    assert!(
        report.gaps().len() == 2,
        "die Luecke des Bestands bleibt vollstaendig im Bericht stehen, gemessen {}",
        report.gaps().len()
    );
    assert_eq!(
        exit_code_for(&report),
        ExitCode::Integrity,
        "10 schlaegt 11, weil die Regeln in aufsteigender Codereihenfolge greifen"
    );
}

/// Regel 3 ist genau der Fail-Closed-Ausstieg an Gate `trust`, nicht weniger
/// und nicht mehr.
///
/// BELEG UND NICHT BEHAUPTUNG: `pipeline_completed` ist nicht oeffentlich
/// lesbar. Sichtbar ist die Aequivalenz daran, dass ein Lauf ohne
/// Vertrauenskette ALLE sechs Fehlerarrays leer laesst und `is_fully_verified()`
/// dennoch falsch ist — waehrend jeder Lauf mit Kette mindestens den
/// Wurzelabdruck traegt.
#[test]
fn an_empty_thumbprint_set_is_exactly_the_fail_closed_trust_exit() {
    let built = live_clock_archive_without_trust_objects();
    let report = report_of(
        "exit-trust-equivalence",
        &built.fixture,
        &built.anchor(),
        live_clock(),
        None,
    );

    assert!(
        report.format_errors().len() == 0
            && report.quarantined_objects().len() == 0
            && report.signature_errors().len() == 0
            && report.evidence_errors().len() == 0
            && report.decryption_errors().len() == 0
            && report.gaps().len() == 0,
        "der Fail-Closed-Ausstieg erzeugt KEINEN Befund ueber ein Objekt"
    );
    assert!(
        !report.is_fully_verified(),
        "ein Lauf ohne Vertrauenskette ist nicht vollstaendig verifiziert"
    );
    assert!(
        report.public_key_thumbprints().len() == 0,
        "und er hat keine einzige Signaturpruefung getragen"
    );
    assert_eq!(exit_code_for(&report), ExitCode::Trust);

    // Der Gegenbeweis: derselbe Aufbau MIT Linie traegt Abdruecke und faellt
    // deshalb nie auf Regel 3.
    let with_line = live_clock_archive();
    let report = report_of(
        "exit-trust-contrast",
        &with_line.fixture,
        &with_line.anchor(),
        live_clock(),
        None,
    );
    assert!(
        report.public_key_thumbprints().len() == 2,
        "ein Lauf mit Kette traegt mindestens den Wurzelabdruck"
    );
    assert_eq!(exit_code_for(&report), ExitCode::Success);
}

/// Ein Anker, der sich nicht dekodieren laesst, ist ein TRUST-Befund (12) und
/// ausdruecklich kein Aufruffehler (2).
///
/// `design.md`:1782 laesst dazu keinen Spielraum: „Jede Abweichung endet mit
/// Exitcode 12."
#[test]
fn an_undecodable_trust_anchor_is_a_trust_error() {
    let root = temp_dir("anchor-garbage");
    let path = root.path().join("anchor.bin");
    fs::write(&path, b"kein Trust Anchor").expect("die Ankerdatei muss schreibbar sein");

    // `let Err(..) else` und nicht `expect_err`: `TrustAnchorV1` leitet
    // ABSICHTLICH kein `Debug` ab — ein Anker ist Vertrauensmaterial und darf
    // nicht beilaeufig in eine Ausgabe geraten.
    let Err(error) = load_trust_anchor(&path) else {
        panic!("dieser Anker darf nicht dekodieren");
    };
    assert!(
        matches!(error, RecoveryError::TrustAnchor(_)),
        "eine gescheiterte Dekodierung ist ein Ankerbefund, gemessen {error:?}"
    );
    assert_eq!(exit_code_for_error(&error), ExitCode::Trust);

    // Die neue Variante faellt nicht aus der Global Constraint heraus: auch sie
    // nennt in keiner Darstellung einen Hostpfad.
    let host_path = path.display().to_string();
    for rendered in [format!("{error}"), format!("{error:?}")] {
        assert!(
            !rendered.contains(&host_path) && !rendered.contains("anchor.bin"),
            "die Fehlerdarstellung nennt einen Hostpfad: {rendered}"
        );
    }
}

/// DIE ZAHLEN SIND DER VERTRAG, nicht die Namen.
///
/// Jede andere Zusicherung dieses Targets vergleicht Variante gegen Variante.
/// Ohne diesen Fall liesse sich `Integrity = 10` zu `= 11` aendern, ohne dass
/// irgendein Test des Workspace bricht — die normative Tabelle aus
/// `design.md`:1802-1815 haette dann keinen einzigen Messpunkt.
///
/// Zugleich der einzige Fall, der [`ExitCode::as_i32`] ueberhaupt anfasst. Das
/// ist der Wert, der spaeter durch `process::exit` den Prozess verlaesst; er
/// darf nicht ungemessen dorthin gelangen.
#[test]
fn every_exit_code_carries_its_normative_number() {
    assert_eq!(
        [
            ExitCode::Success.as_i32(),
            ExitCode::Usage.as_i32(),
            ExitCode::Integrity.as_i32(),
            ExitCode::Chain.as_i32(),
            ExitCode::Trust.as_i32(),
            ExitCode::Evidence.as_i32(),
            ExitCode::Key.as_i32(),
            ExitCode::Incomplete.as_i32(),
            ExitCode::Io.as_i32(),
            ExitCode::Unsupported.as_i32(),
        ],
        [0, 2, 10, 11, 12, 13, 14, 15, 20, 21],
        "die Exitcodes muessen exakt der Tabelle aus design.md:1802-1815 entsprechen"
    );
}

/// Eine NICHT LESBARE Ankerdatei ist dagegen ein Dateisystemfehler (20).
///
/// Die Trennung ist der Gegenstand: 20 sagt „ich konnte nicht nachsehen", 12
/// sagt „ich habe nachgesehen und es passt nicht". Beides zu einem Code zu
/// verschmelzen naehme dem Betreiber die Unterscheidung zwischen einem
/// vergessenen Recovery-Medium und einem untergeschobenen Anker.
#[test]
fn an_unreadable_trust_anchor_file_is_an_io_error() {
    let root = temp_dir("anchor-absent");
    let path = root.path().join("gibt-es-nicht.bin");
    assert!(!Path::new(&path).exists(), "die Datei darf es nicht geben");

    let Err(error) = load_trust_anchor(&path) else {
        panic!("eine fehlende Datei kann keinen Anker geben");
    };
    assert!(
        matches!(error, RecoveryError::Io(_)),
        "eine fehlende Datei ist ein Dateisystemfehler, gemessen {error:?}"
    );
    assert_eq!(exit_code_for_error(&error), ExitCode::Io);
}

/// Ein lesbarer, gueltiger Anker kommt unveraendert durch.
///
/// Ohne diesen Fall bewiesen die beiden Fehlerpfade nur, dass
/// [`load_trust_anchor`] IRGENDWAS ablehnt.
#[test]
fn a_valid_trust_anchor_file_loads_into_the_same_anchor() {
    let built = live_clock_archive();
    let root = temp_dir("anchor-valid");
    let path = root.path().join("anchor.bin");
    fs::write(&path, &built.anchor_bytes).expect("die Ankerdatei muss schreibbar sein");

    let loaded = load_trust_anchor(&path).expect("der Fixture-Anker muss laden");
    assert!(
        loaded.chain_id() == built.anchor().chain_id()
            && loaded.root_key_thumbprint() == built.anchor().root_key_thumbprint(),
        "der geladene Anker muss derselbe sein wie der des Bestands"
    );
}

/// Ein BELEGTES Ziel endet mit 2, und die vorhandene Datei bleibt unberuehrt.
///
/// # Warum das hier steht und nicht nur in `apps/cli`
///
/// Die Zielregeln und die Rechtevergabe wohnen in dieser Crate, damit sie an
/// genau EINER Stelle stehen und OHNE Prozessstart messbar sind. `decrypt` und
/// `export` erben sie unveraendert; ein Nachweis, der einen Prozess braeuchte,
/// muesste je Kommando wiederholt werden.
///
/// Gemessen wird beides: dass ein belegtes Ziel ein KONFIGURATIONSFEHLER ist
/// (2) und kein Dateisystemfehler (20), und dass ein
/// Wiederherstellungswerkzeug die vorgefundene Datei nicht antastet — sie
/// koennte genau das sein, was jemand retten wollte.
#[test]
fn an_occupied_output_is_a_usage_error_and_leaves_the_file_untouched() {
    let root = temp_dir("occupied-output");
    let occupied = root.path().join("bericht.json");
    let previous = b"ein fremder Inhalt, der bleiben muss";
    fs::write(&occupied, previous).expect("die Zieldatei muss anlegbar sein");

    let Err(error) = write_report_document("{}", &occupied) else {
        panic!("ein belegtes Ziel darf nicht beschrieben werden");
    };
    assert!(
        matches!(error, RecoveryError::OutputExists),
        "ein belegtes Ziel ist kein Dateisystemfehler, gemessen {error:?}"
    );
    assert_eq!(exit_code_for_error(&error), ExitCode::Usage);
    assert_eq!(
        fs::read(&occupied).expect("die Zieldatei muss lesbar bleiben"),
        previous,
        "die vorgefundene Datei darf nicht angetastet werden"
    );

    // Die neue Variante faellt nicht aus der Global Constraint heraus: auch sie
    // nennt in keiner Darstellung einen Hostpfad.
    let host_path = occupied.display().to_string();
    for rendered in [format!("{error}"), format!("{error:?}")] {
        assert!(
            !rendered.contains(&host_path) && !rendered.contains("bericht.json"),
            "die Fehlerdarstellung nennt einen Hostpfad: {rendered}"
        );
    }

    // Der Gegenfall: ein FREIES Ziel entsteht, traegt genau die uebergebenen
    // Bytes und gehoert unter unix dem Eigentuemer allein. Ohne ihn bewiese der
    // Fall oben nur, dass dieser Schreiber IRGENDWAS ablehnt.
    let fresh = root.path().join("frisch.json");
    write_report_document("{}", &fresh).expect("ein freies Ziel muss beschreibbar sein");
    assert_eq!(
        fs::read(&fresh).expect("das neue Ziel muss lesbar sein"),
        b"{}",
        "geschrieben wird genau das uebergebene Dokument"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mode = fs::metadata(&fresh)
            .expect("das neue Ziel muss existieren")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            ea_recovery::OUTPUT_FILE_MODE_V1,
            "das neue Ziel muss 0600 tragen, war: {:o}",
            mode & 0o777
        );
    }
}

/// EIN SYMLINK IST KEIN ZIEL, sondern ein Verweis auf eines.
///
/// Gemessen werden BEIDE Wege, denn beide muessen dasselbe sagen:
/// [`output_directory_is_free`] raet vor der Verifikation, und
/// [`prepare_output_directory`] legt danach an. Sagte nur der zweite ab, endete
/// ein `decrypt` auf einen verlinkten Pfad mit dem spezifischeren Code des
/// naechsten Abbruchgrundes statt mit der 2 — `design.md`:1815 verlangt aber
/// den kleinsten zutreffenden spezifischen Code, und genau dafuer steht die
/// Vorpruefung ueberhaupt.
///
/// Und gemessen wird nicht nur der Code: das VERLINKTE Verzeichnis behaelt
/// seine Rechte. Ohne die Pruefung folgten `read_dir` und `set_permissions`
/// beide dem Link, verengten ein FREMDES Verzeichnis auf 0700 und legten den
/// Klartext ausserhalb des genannten Pfades ab.
#[cfg(unix)]
#[test]
fn a_symlinked_output_is_a_usage_error_on_both_paths_and_spares_the_foreign_directory() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let root = temp_dir("symlinked-output");
    let foreign = root.path().join("fremd");
    fs::create_dir(&foreign).expect("das fremde Verzeichnis muss anlegbar sein");
    fs::set_permissions(&foreign, fs::Permissions::from_mode(0o755))
        .expect("das fremde Verzeichnis muss seine Rechte tragen");
    let link = root.path().join("ziel");
    symlink(&foreign, &link).expect("der Symlink muss anlegbar sein");

    // ZUERST DER RATENDE WEG: er veraendert nichts und traegt den Vorrang der 2.
    let Err(guessed) = output_directory_is_free(&link) else {
        panic!("ein Symlink ist kein freies Ziel");
    };
    assert!(
        matches!(guessed, RecoveryError::OutputExists),
        "ein verlinktes Ziel ist kein Dateisystemfehler, gemessen {guessed:?}"
    );
    assert_eq!(exit_code_for_error(&guessed), ExitCode::Usage);

    // DANN DER SCHREIBENDE: er ist die Sperre und muss dasselbe sagen.
    let Err(prepared) = prepare_output_directory(&link) else {
        panic!("ein Symlink ist kein anlegbares Ziel");
    };
    assert!(
        matches!(prepared, RecoveryError::OutputExists),
        "ein verlinktes Ziel ist kein Dateisystemfehler, gemessen {prepared:?}"
    );
    assert_eq!(exit_code_for_error(&prepared), ExitCode::Usage);

    // Das fremde Verzeichnis bleibt, wie es war — Rechte wie Inhalt.
    let mode = fs::metadata(&foreign)
        .expect("das fremde Verzeichnis muss existieren")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o755,
        "die Rechte des verlinkten Verzeichnisses duerfen nicht verengt werden, war: {mode:o}"
    );
    assert_eq!(
        fs::read_dir(&foreign)
            .expect("das fremde Verzeichnis muss lesbar bleiben")
            .count(),
        0,
        "in das verlinkte Verzeichnis darf nichts geschrieben werden"
    );

    // Und der Link selbst ist weder ersetzt noch aufgeloest worden.
    assert!(
        fs::symlink_metadata(&link)
            .expect("der Symlink muss liegen bleiben")
            .is_symlink(),
        "der genannte Pfad darf nicht durch ein Verzeichnis ersetzt werden"
    );
}
