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
//! stammt aus der Eingabezeile und nicht aus dem Bestand.
//!
//! # Warum hier (noch) nichts weiter steht
//!
//! `Format::Text` schreibt zeilenweise stabile Schluessel-Wert-Paare ohne
//! Uhrzeit und ohne Hostpfad; `Format::Json` schreibt fuer `verify` und `list`
//! GENAU das Berichtsdokument `ea.verification-report/v1`. Beides braucht einen
//! Bericht, und den erzeugt erst der ausgefuellte Kommandopfad. Ein
//! Emitter ohne Aufrufer waere unter `-D warnings` toter Code und, schlimmer,
//! eine ungepruefte Form.
//!
//! Die JSON-Entscheidung steht dabei schon fest und ist keine Bequemlichkeit:
//! `schemas/` ist geschlossen, es gibt kein Schema fuer eine Auflistung, und
//! `objectResults` IST die Liste. Eine erfundene `ea.archive-listing/v1` waere
//! eine Schemaaenderung durch die Hintertuer.

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
