//! Die Exitcodetabelle aus `design.md`:1783-1795, verbatim.
//!
//! # „Der kleinste zutreffende spezifische Code"
//!
//! Die Norm sagt: „Bei mehreren Fehlern gilt deterministisch der kleinste
//! spezifische Fehlercode; vollstaendige Details stehen weiterhin in der
//! strukturierten Ausgabe." [`exit_code_for`] setzt das um, indem es in
//! AUFSTEIGENDER Codereihenfolge prueft und den ERSTEN Treffer liefert. Die
//! Auswahl ist die Pruefreihenfolge — sie ist ausdruecklich NICHT ein
//! `min()` ueber die zutreffenden Codes: [`ExitCode::Success`] ist mit 0
//! numerisch der kleinste Wert der Aufzaehlung und zugleich der AUFFANGFALL.
//! Ein `min()` kehrte die Tabelle damit still um.
//!
//! Der Bericht bleibt davon unberuehrt. Ein Exitcode ist eine Zusammenfassung
//! fuer einen Prozessaufrufer und beschneidet die Diagnose nicht.

use ea_archive::ArchiveError;
use ea_verify::{VerificationReportV1, VerifyError};

use crate::RecoveryError;

/// Die stabilen Prozess-Exitcodes des Wiederherstellungswerkzeugs.
///
/// `#[repr(i32)]`, weil genau diese Zahlen den Prozess verlassen; die
/// Diskriminanten sind der Vertrag, nicht die Namen.
///
/// [`Ord`] ist abgeleitet, weil die Werte eine Ordnung HABEN — nicht, damit
/// irgendwo ein Minimum gebildet wird. Siehe die Modulnotiz.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ExitCode {
    /// Vollstaendig erfolgreich.
    Success = 0,
    /// Aufruf- oder Konfigurationsfehler.
    ///
    /// Entsteht NIE aus einem Bericht — eine Aufrufform ist kein Befund ueber
    /// einen Bestand —, sondern an genau zwei Stellen: im Argumentparser der
    /// CLI und bei der Zielpruefung eines schreibenden Kommandos
    /// ([`RecoveryError::OutputExists`]). Beide sagen dasselbe: so, wie dieser
    /// Lauf aufgerufen wurde, wird er nicht ausgefuehrt; am Bestand liegt es
    /// nicht.
    Usage = 2,
    /// Format-, Hash- oder Signaturfehler.
    Integrity = 10,
    /// Kettenluecke, Fork oder Rollback.
    Chain = 11,
    /// Trust-, Registry- oder Autorisierungsfehler.
    Trust = 12,
    /// Evidence ungueltig oder richtlinienwidrig ueberfaellig.
    Evidence = 13,
    /// Schluessel fehlt oder Entschluesselung fehlgeschlagen.
    Key = 14,
    /// Vollstaendig geprueft, aber fachlich unvollstaendig oder teilweise
    /// vernichtet.
    Incomplete = 15,
    /// I/O-, Speicher- oder Transportfehler.
    Io = 20,
    /// Nicht unterstuetzte Format-, Suite-, Plattform- oder
    /// Providerfaehigkeit.
    Unsupported = 21,
}

impl ExitCode {
    /// Der Zahlwert, wie ihn der Prozess zurueckgibt.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

/// Leitet den Exitcode aus einem VOLLSTAENDIG gebildeten Bericht ab.
///
/// REINE FUNKTION ueber den Bericht, und nichts weiter. Ein Kommando, das
/// zusaetzliche Abbruchgruende kennt — `decrypt` etwa, das ohne einen einzigen
/// eigenen Grant nie Erfolg melden darf —, bildet die in SEINEM Pfad und nicht
/// hier. Diese Funktion soll fuer denselben Bericht immer dasselbe sagen.
#[must_use]
pub fn exit_code_for(report: &VerificationReportV1) -> ExitCode {
    // 1 — „Format-, Hash- oder Signaturfehler". Alle drei Arrays zusammen,
    // weil die Norm sie in EINER Zeile fuehrt. `formatErrors` und
    // `quarantinedObjects` sind bei `malformed` paarweise, treten aber
    // ausdruecklich auch einzeln auf (`duplicate`, `unattributable`).
    if report.format_errors().len() != 0
        || report.quarantined_objects().len() != 0
        || report.signature_errors().len() != 0
    {
        return ExitCode::Integrity;
    }

    // 2 — „Kettenluecke, Fork oder Rollback". Eine unerklaerte Luecke faellt
    // HIERHIN und ausdruecklich nicht auf 15: Code 15 setzt ein VOLLSTAENDIG
    // geprueftes Ergebnis voraus, und eine Luecke senkt
    // `is_fully_verified()`.
    if report.gaps().len() != 0 {
        return ExitCode::Chain;
    }

    // 3 — „Trust-, Registry- oder Autorisierungsfehler". Ein leerer
    // Abdrucksatz ist der einzige OEFFENTLICH LESBARE Diskriminator des
    // Fail-Closed-Ausstiegs an Gate `trust`: `pipeline_completed` ist
    // `pub(crate)`. Die Aequivalenz ist exakt und nicht bloss ausreichend —
    // `crates/ea-verify/src/archive.rs:302` ist der EINZIGE vorzeitige
    // Ausstieg der Pipeline, und er liegt VOR dem ersten Insert an `:314`.
    // Jeder weitere Insert (`:379`, `:598`, `:659`, `:793`,
    // `destruction.rs:261`) liegt dahinter. Gemessen wird die Aequivalenz in
    // `tests/exit_codes.rs::an_empty_thumbprint_set_is_exactly_the_fail_closed_trust_exit`.
    if report.public_key_thumbprints().len() == 0 {
        return ExitCode::Trust;
    }

    // 4 — „Evidence ungueltig oder richtlinienwidrig ueberfaellig".
    if report.evidence_errors().len() != 0 {
        return ExitCode::Evidence;
    }

    // 5 — „Schluessel fehlt oder Entschluesselung fehlgeschlagen".
    if report.decryption_errors().len() != 0 {
        return ExitCode::Key;
    }

    // Hinter Schritt 5 sind alle sechs Fehlerarrays leer, also gilt
    // `is_fully_verified() == pipeline_completed`. Schritt 3 hat den einzigen
    // Zustand mit `pipeline_completed == false` bereits abgefangen — der Wert
    // MUSS hier wahr sein. Das haelt der `debug_assert` fest, damit ein
    // spaeterer Zustand, der beides unterlaeuft, nicht still durch Regel 6
    // hindurch auf 0 faellt, sondern im Test laut wird.
    debug_assert!(
        report.is_fully_verified(),
        "hinter Regel 5 kann nur noch der Fail-Closed-Ausstieg unvollstaendig sein, \
         und den faengt Regel 3 ab"
    );

    // 6 — „vollstaendig geprueft, aber fachlich unvollstaendig oder teilweise
    // vernichtet". DIE WICHTIGSTE ZEILE: gemessen liefert ein Bestand, dessen
    // Registrierungskoepfe zur Laufuhr saemtlich veraltet sind,
    // `is_fully_verified() == true` bei NULL Objektergebnissen ueber einem
    // geparsten Eintrag. Ohne diese Zeile meldete das Werkzeug Erfolg ueber
    // einen Bestand, ueber den es nichts ausgesagt hat.
    //
    // Verglichen wird gegen `entry_package_count() + destroyed_entry_count()`,
    // weil beide Objektarten ein Ergebnis tragen koennen; ein autorisierter
    // Vernichtungsvorgang ist der zweite Weg auf dieselbe Zeile
    // („teilweise vernichtet").
    if report.is_fully_verified()
        && (report.object_results().len()
            < report.entry_package_count() + report.destroyed_entry_count()
            || report.authorized_destructions().len() != 0)
    {
        return ExitCode::Incomplete;
    }

    // 7 — sonst.
    ExitCode::Success
}

/// Leitet den Exitcode aus einem Lauf ab, der GAR KEINEN Bericht bilden konnte.
///
/// Scharf getrennt von [`exit_code_for`]: dort urteilt ein Bericht ueber einen
/// Bestand, hier ist kein Urteil zustande gekommen.
#[must_use]
pub const fn exit_code_for_error(error: &RecoveryError) -> ExitCode {
    match error {
        // Das Dateisystem konnte einen Schritt nicht ausfuehren.
        RecoveryError::Io(_) => ExitCode::Io,
        // Der Bestand sprengt eine FORMATSCHRANKE. Das ist kein Transport-,
        // sondern ein Formatbefund, und deshalb 10 und nicht 20 — genau wie
        // die beiden Schranken des Inventars unten.
        RecoveryError::ArchiveTooLarge => ExitCode::Integrity,
        // `design.md`:1765: „Jede Abweichung endet mit Exitcode 12."
        RecoveryError::TrustAnchor(_) => ExitCode::Trust,
        // Ein belegtes Ziel ist ein KONFIGURATIONSFEHLER und kein
        // Dateisystemfehler: geschrieben wurde nichts, gefunden wurde nichts,
        // und der Lauf ist mit einem anderen `--output` unveraendert
        // wiederholbar. Die Begruendung steht an `RecoveryError::OutputExists`.
        RecoveryError::OutputExists => ExitCode::Usage,
        // Ebenfalls eine Aussage ueber den AUFRUF und nicht ueber den Bestand:
        // die benannte Datei traegt kein Schluesselmaterial dieser Form. Die
        // Begruendung, warum das 2 und nicht 14 ist, steht an
        // `RecoveryError::KeySource`.
        RecoveryError::KeySource => ExitCode::Usage,
        // „Schluessel fehlt": der vorgelegte Schluessel oeffnet diesen Bestand
        // nicht. Der EINZIGE Abbruchgrund dieser Aufzaehlung, der aus einem
        // vollstaendig gebildeten und makellosen Bericht entsteht — siehe die
        // Notiz an `exit_code_for`.
        RecoveryError::NoOwnGrant => ExitCode::Key,
        // „Entschluesselung fehlgeschlagen", die zweite Haelfte derselben
        // Zeile der Norm.
        RecoveryError::Decryption => ExitCode::Key,
        // „Nicht unterstuetzte Plattformfaehigkeit". Kein Dateisystemfehler:
        // es ist nichts misslungen, es ist etwas nicht vorhanden.
        RecoveryError::RestrictivePermissionsUnsupported => ExitCode::Unsupported,
        // Dieselbe Zeile der Norm, andere Haelfte: eine nicht unterstuetzte
        // PROVIDERFAEHIGKEIT. Stage 1 kennt keine Serverquelle, und eine Quelle,
        // die kein Verzeichnis ist, wird deshalb nicht ersatzweise als eine
        // gelesen. Ausdruecklich nicht 20 — es ist nichts misslungen.
        RecoveryError::UnsupportedSource => ExitCode::Unsupported,
        RecoveryError::Verify(error) => match error {
            VerifyError::Archive(error) => match error {
                ArchiveError::Unavailable => ExitCode::Io,
                ArchiveError::BlobLimit | ArchiveError::TotalByteLimit => ExitCode::Integrity,
                // `ArchiveError` ist `#[non_exhaustive]`. Eine kuenftige
                // Variante bekommt hier NICHT still einen Befundcode
                // untergeschoben: dieses Bauwerk kennt sie nicht, und genau
                // das sagt 21.
                _ => ExitCode::Unsupported,
            },
            // Der Berichtsschreiber fand eine Zeichenkette ausser der Reihe.
            // Das kann nur eintreten, wenn unkontrollierter Text in den
            // Bericht gelangt waere — ein Integritaetsbefund.
            VerifyError::NonCanonicalReport => ExitCode::Integrity,
            // Wie oben: `VerifyError` ist `#[non_exhaustive]`.
            _ => ExitCode::Unsupported,
        },
        // KEIN Auffangarm fuer `RecoveryError` selbst: die Aufzaehlung wohnt in
        // DIESER Crate, `#[non_exhaustive]` bindet sie hier also nicht. Ohne
        // Auffangarm bricht eine neue Variante genau hier den Bau, statt still
        // einen Code zu erben.
    }
}
