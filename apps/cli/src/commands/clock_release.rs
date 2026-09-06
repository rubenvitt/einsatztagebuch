//! Kommando `clock-release apply`.
//!
//! Verbraucht eine BEREITS AUSGESTELLTE Uhrfreigabe und waehlt den Kopf unter
//! ihr neu.
//!
//! # Warum es kein `issue` gibt
//!
//! `ea_admin::clock_release::ClockReleaseService::issue` verlangt einen
//! `ea_trust::RegistryCandidate` in seiner Signatur, und dieses Paket fuehrt
//! keine produktive Kante zu `ea-trust` (`apps/cli/Cargo.toml`). Die Grammatik
//! fuehrt den Schritt deshalb NICHT auf: sie nennt, was das Werkzeug kann.
//!
//! Der Ausweg ist bewusst KEINE Kante und keine Nachbildung. Ein Kommando, das
//! eine Freigabe ausstellte, ohne den Zeitzustand zu kennen, waere eine zweite
//! Uhr und damit genau das, was der Umsetzungsplan verbietet.
//!
//! # Die drei Verfuegbarkeiten werden ERFRAGT
//!
//! `ea_admin::operator_runtime::OperatorRuntime::clock_release_availability`
//! ist der schmale Zugang, der dafuer gebaut wurde: die Bedienerlaufzeit haelt
//! den Zustandsspeicher ohnehin, liest ihn INNERHALB von `ea-admin` und gibt
//! nach aussen nur das Drei-Varianten-Enum
//! [`ea_admin::clock_release::ClockReleaseAvailability`] heraus. Kein Typ aus
//! `ea-trust` oder `ea-time` ueberquert dabei die Paketgrenze, und dieses
//! Modul rechnet die Lage nicht mehr aus Fehlerarmen zurueck.
//!
//! Die Frage steht VOR dem Dreischritt. Der Grund ist nicht Bequemlichkeit:
//! gefragt wird nach dem Zustand, in dem der Betreiber die Freigabe vorgelegt
//! hat, und ein Fehlschlag des Dreischritts aendert ihn nicht — er schreibt
//! nichts. Ueber Annahme oder Abweisung entscheidet weiterhin allein der Kern;
//! die erfragte Verfuegbarkeit traegt AUSSCHLIESSLICH den Bedienhinweis.
//!
//! # Die Freigabebytes werden DURCHGEREICHT
//!
//! Sie werden nicht dekodiert und nichts aus ihnen wird angezeigt. Der
//! signierte Kontext bindet eine Zufalls-Nonce
//! (`ea_format::ClockReleaseContextV1`); die Quittung dieses Kommandos ist
//! deshalb eine feste Zeile ohne jeden Platzhalter.

use std::{fs::File, io::Read as _, path::Path};

use ea_admin::{
    clock_release::{ClockReleaseAvailability, ClockReleaseWorkflowError, apply_clock_release},
    operator_runtime::{OperatorRuntime, OperatorRuntimeConfig, OperatorRuntimeError},
};
use ea_recovery::ExitCode;
use ea_types::UnixMillis;

use crate::{args::Invocation, output};

/// Die Obergrenze einer Freigabedatei.
///
/// Eine signierte `local-audit-event-v1`-Zeile ist einige hundert Byte gross.
/// Die Grenze ist nicht knapp gewaehlt, sondern grosszuegig — ihr Zweck ist
/// allein, dass eine irrtuemlich benannte Datei nicht in den Speicher gelesen
/// wird. Dieselbe Bauart wie das Konfigurationslimit in
/// `ea_admin::operator_runtime`.
const RELEASE_FILE_LIMIT: usize = 64 * 1024;

/// Fuehrt `clock-release apply` aus.
///
/// `now` kommt als PARAMETER aus `main`; dieser Pfad holt keine Uhr.
pub fn run(
    invocation: &Invocation,
    config_path: &Path,
    release_path: &Path,
    now: UnixMillis,
) -> ExitCode {
    // 1 — die Freigabebytes ZUERST. Eine fehlende Datei ist ein Befund ueber
    // die Eingabe und kein Befund ueber einen Bestand; sie soll den Lauf
    // beenden, bevor ein Archiv geoeffnet und eine Bedienerlaufzeit gebunden
    // wird.
    let release = match read_release(release_path) {
        Ok(release) => release,
        Err(error) => {
            output::print_operator_error(&error);
            return error.exit_code();
        }
    };

    match apply(invocation, config_path, &release, now) {
        Ok(code) => code,
        Err(ApplyError::Runtime(error)) => {
            output::print_operator_error(&error);
            error.exit_code()
        }
        Err(ApplyError::Workflow(error, availability)) => {
            output::print_clock_release_error(&error);
            // Der Unterschied, den der Umsetzungsplan verlangt: „es wird gar
            // keine Freigabe angeboten" ist eine ANDERE Lage als „eine
            // Freigabe wurde angeboten und abgewiesen". Fehlt die Antwort,
            // bleibt die Zeile WEG — ein geratener Wert waere genau der
            // Rueckschluss, den diese Fassung beseitigt.
            if let Some(availability) = availability {
                output::print_clock_release_availability(availability);
            }
            exit_code_for(&error)
        }
    }
}

/// Der Fehlschlag EINES der beiden Schritte — Laufzeit oder Freigabe.
enum ApplyError {
    Runtime(OperatorRuntimeError),
    /// Der Fehlschlag der Freigabe, samt der ERFRAGTEN Verfuegbarkeit.
    ///
    /// `None` heisst genau eine Sache: die Verfuegbarkeit selbst war nicht zu
    /// erfragen — dann scheiterte schon die Frage, und der Fehler DIESER Frage
    /// ist es, der gemeldet wird.
    Workflow(ClockReleaseWorkflowError, Option<ClockReleaseAvailability>),
}

impl From<OperatorRuntimeError> for ApplyError {
    fn from(error: OperatorRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<ClockReleaseWorkflowError> for ApplyError {
    /// Der Weg, den NUR die gescheiterte FRAGE nimmt.
    ///
    /// Der gescheiterte Dreischritt traegt seine Antwort selbst bei und baut
    /// die Variante deshalb ausdruecklich.
    fn from(error: ClockReleaseWorkflowError) -> Self {
        Self::Workflow(error, None)
    }
}

/// Oeffnet die Laufzeit und laesst `ea-admin` den Dreischritt fuehren.
fn apply(
    invocation: &Invocation,
    config_path: &Path,
    release: &[u8],
    now: UnixMillis,
) -> Result<ExitCode, ApplyError> {
    let config = OperatorRuntimeConfig::load(config_path)?;
    let mut runtime = OperatorRuntime::open(config, &invocation.anchor, now, false)?;
    // 2 — die Verfuegbarkeit ERFRAGEN, bevor der Dreischritt laeuft. `open`
    // hat die Laufzeit soeben auf Frische geprueft, und der Dreischritt
    // schreibt bei einem Fehlschlag nichts: die Antwort beschreibt damit genau
    // den Zustand, in dem die vorgelegte Freigabe beurteilt wird.
    let availability = runtime.clock_release_availability(now)?;
    let proposed_sequence = runtime.next_sequence();

    let outcome = {
        // Zeitblock und Kopfauswahl gehoeren zu EINEM Speicherzugriff;
        // `trust_and_store` gibt beide Haelften in einem Zug heraus, damit
        // dazwischen nichts geschrieben werden kann.
        let (trust, store) = runtime.trust_and_store();
        // Ohne frisch verifizierte Zeitquellen: dieses Werkzeug holt keine
        // Quittung und keinen Checkpoint. Die unabhaengige Referenz stammt
        // damit ausschliesslich aus dem persistierten Zustand — was der
        // ehrliche Stand ist und keine Verkuerzung.
        apply_clock_release(store, trust, proposed_sequence, now, &[], release)
    };
    outcome.map_err(|error| ApplyError::Workflow(error, Some(availability)))?;

    runtime.ensure_current()?;
    output::print_clock_release_applied(invocation.format)?;
    Ok(ExitCode::Success)
}

/// Liest die Freigabebytes UNVERAENDERT und begrenzt.
fn read_release(path: &Path) -> Result<Vec<u8>, OperatorRuntimeError> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| OperatorRuntimeError::Io)?
        .take(RELEASE_FILE_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| OperatorRuntimeError::Io)?;
    if bytes.len() > RELEASE_FILE_LIMIT {
        return Err(OperatorRuntimeError::Io);
    }
    Ok(bytes)
}

/// Ordnet einen Freigabefehler der normativen Exitcodetabelle zu.
///
/// Die Auditgrenze ist ein Schreib- und Speicherbefund und faellt auf 20;
/// alles uebrige — Zweck, Bindung, Zeitversatz, Wiedereinspielung, Ablauf,
/// Kopfauswahl — ist ein Befund ueber die Vertrauenslage und faellt auf 12.
/// Der Auffangarm ist Pflicht: [`ClockReleaseWorkflowError`] ist
/// `#[non_exhaustive]`.
fn exit_code_for(error: &ClockReleaseWorkflowError) -> ExitCode {
    match error {
        ClockReleaseWorkflowError::Audit(_) => ExitCode::Io,
        _ => ExitCode::Trust,
    }
}
