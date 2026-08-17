//! Die Ausgabeform des Werkzeugs.
//!
//! # Zwei Stroeme, und sie werden nicht vermischt
//!
//! FEHLERMELDUNGEN gehen nach stderr, NUTZAUSGABEN nach stdout. Wer die
//! Berichtsausgabe in eine Datei umlenkt, darf darin keine Meldung finden; wer
//! nach der Grammatik fragt, bekommt eine Nutzausgabe und keinen Fehlertext.
//! Deshalb ist [`UsageError::NoArguments`] der einzige Aufruffall, der nach
//! stdout schreibt.
//!
//! # Was eine Meldung NIE enthaelt
//!
//! Den Inhalt einer Datei und jeden Hostpfad, den der Aufrufer nicht selbst
//! eingegeben hat. Ein von ihm eingegebener Pfad darf zurueckkommen — er
//! stammt aus der Eingabezeile und nicht aus dem Bestand. [`RecoveryError`]
//! zeigt ohnehin nur seinen stabilen Code an; ein Hostpfad kann von dort gar
//! nicht erst hierher gelangen.
//!
//! # WAS EINE AUSGABE NIE ENTHAELT
//!
//! Eine Uhrzeit, einen Hostpfad und jede Laufzeitangabe — in der TEXTFORM
//! genauso wie im Berichtsdokument. Die Regel ist dieselbe und aus demselben
//! Grund: nichtdeterministische Felder entstehen ausschliesslich ueber
//! `--include-runtime-metadata`, und eine Textausgabe, die eine Uhrzeit
//! mitschriebe, waere der Schleichweg daran vorbei. Gemessen wird das nicht
//! ueber ein `contains`, sondern indem
//! `apps/cli/tests/exit_codes.rs::the_text_output_is_a_closed_line_sequence`
//! die GANZE Ausgabe vergleicht: eine zusaetzliche Zeile faellt nur so auf.
//!
//! # Warum `list` kein eigenes JSON hat
//!
//! `schemas/` ist geschlossen, es gibt kein Schema fuer eine Auflistung, und
//! `objectResults` IST die Liste. Eine erfundene `ea.archive-listing/v1` waere
//! eine Schemaaenderung durch die Hintertuer. `list --format json` und
//! `verify --format json` schreiben deshalb BEIDE genau das Dokument
//! `ea.verification-report/v1` — byteweise dasselbe.

use std::io::{self, Write};

use ea_recovery::RecoveryError;
use ea_verify::VerificationReportV1;

use crate::args::UsageError;

/// Die geschlossene Grammatik, Zeile fuer Zeile.
///
/// Genau fuenf Zeilen, weil es genau fuenf Kommandos gibt. Der Text ist Teil
/// des beobachtbaren Verhaltens und wird als solcher gemessen.
const GRAMMAR_V1: [&str; 5] = [
    "einsatzarchiv --trust-anchor <file> verify  <archive-path>",
    "einsatzarchiv --trust-anchor <file> list    <archive-path>",
    "einsatzarchiv --trust-anchor <file> decrypt <archive-path> --key <key-source> --output <target>",
    "einsatzarchiv --trust-anchor <file> report  <archive-path> --output <report-file>",
    "einsatzarchiv --trust-anchor <file> export  <archive-or-server> --output <new-target>",
];

/// Druckt die Grammatik auf stdout.
///
/// `println!` und ausdruecklich kein gepufferter Schreiber: der Aufrufer
/// beendet den Prozess unmittelbar danach, und ein Puffer, der dabei nicht
/// mehr geleert wird, machte die Ausgabe von der Zeitplanung abhaengig.
pub fn print_grammar() {
    for line in GRAMMAR_V1 {
        println!("{line}");
    }
}

/// Druckt einen Aufruffehler auf stderr.
///
/// Das Praefix benennt das Werkzeug, damit die Zeile in einem Protokoll
/// zuzuordnen ist, in dem mehrere Prozesse schreiben.
pub fn print_usage_error(error: &UsageError) {
    eprintln!("einsatzarchiv: {error}");
}

/// Druckt einen Laufzeitfehler auf stderr.
///
/// Angezeigt wird der STABILE Fehlercode und nichts weiter — `RecoveryError`
/// traegt bewusst weder Pfad noch Bytes. Ein Test darf auf den Code
/// assertieren; ein Betreiber soll daran erkennen, was gescheitert ist.
pub fn print_recovery_error(error: &RecoveryError) {
    eprintln!("einsatzarchiv: {error}");
}

/// Schreibt `bytes` als Kleinbuchstaben-Hex.
///
/// Von Hand und nicht ueber `hex`: die Kiste ist eine DEV-Dependency dieses
/// Pakets und gehoert nicht in den Auslieferungsgraphen eines
/// Wiederherstellungswerkzeugs. Die Form ist dieselbe, die
/// `crates/ea-verify/src/json.rs` fuer das Berichtsdokument erzwingt.
fn write_hex(out: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    for byte in bytes {
        write!(out, "{byte:02x}")?;
    }
    Ok(())
}

/// Schreibt den Bericht als geschlossene Zeilenfolge auf stdout.
///
/// # Die Reihenfolge ist GELIEHEN, nicht erfunden
///
/// Erst die vier Zaehler und der Kettenkopf, dann JE FEHLERARRAY seine Anzahl
/// in der Gliederreihenfolge des Berichtsdokuments
/// (`crates/ea-verify/src/report.rs::write_document`: `gaps`, `formatErrors`,
/// `quarantinedObjects`, `signatureErrors`, `evidenceErrors`,
/// `decryptionErrors`), zuletzt `reportHash`. Eine zweite, eigene Ordnung
/// haette keinen Nutzen und einen Preis: sie muesste getrennt gepflegt werden
/// und wuerde still auseinanderlaufen.
///
/// # Errors
///
/// [`RecoveryError::Io`], wenn stdout nicht schreibbar ist — etwa, weil der
/// Empfaenger der Pipe bereits beendet wurde.
pub fn print_report_text(report: &VerificationReportV1) -> Result<(), RecoveryError> {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    writeln!(out, "archiveObjectCount {}", report.archive_object_count())?;
    writeln!(out, "entryPackageCount {}", report.entry_package_count())?;
    writeln!(
        out,
        "destroyedEntryCount {}",
        report.destroyed_entry_count()
    )?;
    writeln!(out, "nonObjectFileCount {}", report.non_object_file_count())?;
    writeln!(
        out,
        "chainHead.sequence {}",
        report.chain_head().sequence().get()
    )?;
    write!(out, "chainHead.entryHash ")?;
    write_hex(&mut out, report.chain_head().entry_hash().as_bytes())?;
    writeln!(out)?;

    writeln!(out, "gaps {}", report.gaps().len())?;
    writeln!(out, "formatErrors {}", report.format_errors().len())?;
    writeln!(
        out,
        "quarantinedObjects {}",
        report.quarantined_objects().len()
    )?;
    writeln!(out, "signatureErrors {}", report.signature_errors().len())?;
    writeln!(out, "evidenceErrors {}", report.evidence_errors().len())?;
    writeln!(out, "decryptionErrors {}", report.decryption_errors().len())?;

    write!(out, "reportHash ")?;
    write_hex(&mut out, report.report_hash().as_bytes())?;
    writeln!(out)?;

    out.flush()?;
    Ok(())
}

/// Schreibt die Auflistung als Zeilenfolge auf stdout.
///
/// Je Objektergebnis eine Zeile `<objectHash> <objectType> <result>
/// <serverConfirmation>`, danach je isoliertem Objekt eine Zeile
/// `<objectHash> <reason>`. Beide Folgen stehen in der ORDNUNG DES BERICHTS —
/// aufsteigend nach `objectHash` —, weil sie unmittelbar aus dessen
/// `BTreeMap`s stammen und hier nichts umsortiert wird.
///
/// `objectType` erscheint als ZAHL und nicht als Name: das Berichtsschema
/// fuehrt `objectResult.objectType` als Typbyte 1..6, und `schemas/` ist
/// geschlossen. Ein hier erfundener Name waere ein zweites, ungeprueftes
/// Vokabular ueber derselben Sache.
///
/// # Errors
///
/// Wie [`print_report_text`].
pub fn print_listing_text(report: &VerificationReportV1) -> Result<(), RecoveryError> {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for result in report.object_results() {
        write_hex(&mut out, result.object_hash().as_bytes())?;
        writeln!(
            out,
            " {} {} {}",
            result.object_type().code(),
            result.result().as_str(),
            result.server_confirmation().as_str()
        )?;
    }
    for quarantined in report.quarantined_objects() {
        write_hex(&mut out, quarantined.object_hash().as_bytes())?;
        writeln!(out, " {}", quarantined.reason().as_str())?;
    }

    out.flush()?;
    Ok(())
}

/// Schreibt das kanonische Berichtsdokument auf stdout.
///
/// OHNE abschliessenden Zeilenumbruch. `crates/ea-verify/src/json.rs:20-23`
/// friert diese Form ein; ein Umbruch waere ein zusaetzliches Byte und braeche
/// die Byteidentitaet, auf der jede spaetere Aussage ueber den Bericht steht.
///
/// # Errors
///
/// [`RecoveryError::Verify`], falls der Bericht je eine Zeichenkette ausser der
/// Reihe truege — das ist ein Integritaetsbefund und kein Schreibfehler.
/// [`RecoveryError::Io`], wenn stdout nicht schreibbar ist.
pub fn print_report_json(report: &VerificationReportV1) -> Result<(), RecoveryError> {
    let document = report.to_canonical_json()?;
    let stdout = io::stdout();
    let mut out = stdout.lock();
    out.write_all(document.as_bytes())?;
    out.flush()?;
    Ok(())
}
