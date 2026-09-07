//! Kommando `writer-transition prepare|activate`.
//!
//! Bereitet den Uebergang vom laufenden auf einen freigegebenen Writer vor
//! und plant — nach der Wurzelzeremonie — das Aenderung-3-Ereignis, das ihn
//! wirksam macht.
//!
//! # Was dieser Pfad NICHT tut
//!
//! Er parst keinen Antrag, rechnet keine Sequenz, dekodiert kein Objekt und
//! entscheidet keinen Schritt. Den Antrag liest `ea-admin`
//! (`ea_admin::writer_transition::WriterTransitionRequest::load`), die
//! Vorbereitung prueft `WriterTransitionService::prepare` gegen den
//! gewaehlten Kopf, die Aktivierung haelt `WriterTransitionService::activate`
//! gegen die veroeffentlichten Bytes, und das Ereignis baut die Fabrik
//! (`ea_admin::registry::RegistryEventFactory`). Dieses Modul ruft, liest
//! ab, druckt und ordnet einen Exitcode zu — dieselbe Arbeitsteilung wie bei
//! `registry revocation-plan`.
//!
//! # Der Autorisierungshash: Platzhalter VOR der Zeremonie, echt DANACH
//!
//! `WriterTransitionService::prepare` bildet die Nutzlast ueber den EINEN
//! Kodierer `TrustPayloadV1::writer_transition(fields, authorization_hash)`.
//! Der echte Hash ist der der erteilten Administrationsautorisierung, und
//! die wird in der Wurzelzeremonie erteilt: ihr Beweiszustand
//! (`ea_trust::VerifiedAdminAuthorizationIntent`) entsteht nur dort, aus den
//! Offline-Schluesselquellen der Wurzel und dem zweiten Kanal, und ein
//! CLI-Prozess haelt ihn nicht — die Zeremonie ist Host-Arbeit, wie in Task 4.
//!
//! Die Antragsdatei darf den Hash deshalb NENNEN
//! (`admin_authorization_object_hash`, optional;
//! `ea_admin::writer_transition::LoadedWriterTransitionRequest`):
//!
//! - `prepare` OHNE Hash — der Antrag vor der Zeremonie — ruft den Dienst mit
//!   `ObjectHash::from(Hash32::ZERO)`, genau wie
//!   `ea_admin::policy::plan_initial_policy` die Policy-Form mit diesem
//!   Platzhalter prueft, bevor eine Autorisierung erteilt ist. Jede Pruefung
//!   von `prepare` — laufender Writer, freigegebener Writer, Sequenz,
//!   Grammatik der Felder — ist vom Hash unabhaengig.
//! - `prepare` MIT Hash bildet GENAU die Nutzlast, die die Zeremonie
//!   signiert. Die Ausgabe sagt in einer festen Zeile, welche der beiden
//!   Lagen vorliegt — zwei Texte, keine Variante.
//! - `activate` VERLANGT den Hash. Es bereitet mit demselben Antrag erneut
//!   vor (`PreparedWriterTransition` ist absichtlich nicht serialisierbar)
//!   und vergleicht die veroeffentlichten Bytes mit der Nutzlast als GANZES,
//!   einschliesslich des Hashes (`exact_digest_input`). Mit dem Platzhalter
//!   hielten die Bytes niemals dagegen; ein Antrag ohne Hash ist deshalb an
//!   diesem Kommando ein Aufruffehler (Exitcode 2, benannt in
//!   `crate::output::print_missing_authorization_hash_refusal`) und wird
//!   abgewiesen, BEVOR die Bedienerdatei gelesen und ein Archiv geoeffnet
//!   wird — dieselbe Bauart wie die Ablehnung einer Bedienerdatei ohne
//!   `target_certificate_hash` in `crate::commands::registry`. Nicht
//!   `EA-TRANSITION-REQUEST-SHAPE`: die Datei ist in Form, `prepare` nimmt
//!   sie; ihr fehlt ein Feld, das dieses eine Kommando braucht.
//!
//! # Das Fenster kommt HALB von aussen
//!
//! `--valid-through` und `--not-after` sind Entscheidungen des Betreibers.
//! `effective_from_sequence` ist keine: sie folgt aus dem abgeglichenen
//! Kettenkopf des Antrags, und `activate` weist jedes Fenster ab, das woanders
//! beginnt. Das Fenster wird deshalb aus `prepared.effective_from_sequence()`
//! und den beiden Schaltern zusammengesetzt — dieselbe Bauart wie in
//! `crate::commands::registry`, mit einer Zahl weniger.

use std::{fs::File, io::Read as _, path::Path};

use ea_admin::{
    RegistryWindow,
    operator_runtime::{OperatorRuntime, OperatorRuntimeConfig, OperatorRuntimeError},
    registry::{RegistryEventFactory, RegistryWorkflowError},
    writer_transition::{
        WriterTransitionError, WriterTransitionRequest, WriterTransitionRequestError,
        WriterTransitionService,
    },
};
use ea_recovery::ExitCode;
use ea_types::{ChainSequence, Hash32, ObjectHash, UnixMillis};

use crate::{
    args::Invocation,
    output::{self, WriterTransitionActivateView, WriterTransitionPrepareView},
};

/// Die Obergrenze einer Objektdatei.
///
/// Ein `writerTransition`-Objekt ist einige hundert Byte gross. Die Grenze
/// ist grosszuegig; ihr Zweck ist allein, dass eine irrtuemlich benannte
/// Datei nicht in den Speicher gelesen wird — dieselbe Bauart wie
/// `RELEASE_FILE_LIMIT` in `crate::commands::clock_release`.
const TRANSITION_OBJECT_FILE_LIMIT: usize = 64 * 1024;

/// Der Platzhalter fuer den Hash der Administrationsautorisierung.
///
/// Siehe die Modulbeschreibung: derselbe Wert, mit dem
/// `ea_admin::policy::plan_initial_policy` die Form prueft.
fn placeholder_authorization_hash() -> ObjectHash {
    ObjectHash::from(Hash32::ZERO)
}

/// Fuehrt `writer-transition prepare` aus.
///
/// `now` kommt als PARAMETER aus `main`; dieser Pfad holt keine Uhr.
pub fn prepare(
    invocation: &Invocation,
    config_path: &Path,
    request_path: &Path,
    now: UnixMillis,
) -> ExitCode {
    // 1 — der Antrag ZUERST, vor der Bedienerdatei und vor jedem Bestand.
    // Eine Datei, die keinen Antrag ergibt, ist ein Befund ueber die Eingabe
    // und kein Befund ueber ein Archiv; sie beendet den Lauf, bevor eines
    // geoeffnet wird.
    let loaded = match WriterTransitionRequest::load(request_path) {
        Ok(loaded) => loaded,
        Err(error) => {
            output::print_writer_transition_request_error(&error);
            return exit_code_for_request(&error);
        }
    };
    let request = loaded.request;
    // Der echte Hash, wenn der Antrag ihn nennt; sonst der Platzhalter.
    let authorization = loaded
        .admin_authorization_object_hash
        .unwrap_or_else(placeholder_authorization_hash);
    let result = run(invocation, config_path, now, |runtime| {
        let service = WriterTransitionService::new(runtime.head());
        let prepared = service.prepare(&request, authorization)?;
        let fields = prepared.fields();
        let head = runtime.head();
        // Alle Angaben werden ABGELESEN: die Felder von der Vorbereitung,
        // Version und Hash vom Kopf, Kettenkopf und Autorisierung vom Antrag.
        let view = WriterTransitionPrepareView {
            organization_id: fields.organization_id,
            chain_id: fields.chain_id,
            old_writer_certificate_hash: fields.old_writer_certificate_hash,
            new_writer_certificate_hash: fields.new_writer_certificate_hash,
            trusted_head_chain_sequence: request.trusted_head.chain_sequence,
            trusted_head_entry_hash: fields.previous_entry_hash,
            effective_from_sequence: prepared.effective_from_sequence(),
            reason_code: fields.reason_code,
            registry_version: head.registry_version(),
            registry_head_hash: head.registry_head_hash(),
            admin_authorization_object_hash: loaded.admin_authorization_object_hash,
        };
        Ok(Report::Prepare(view))
    });
    finish(invocation, result)
}

/// Fuehrt `writer-transition activate` aus.
///
/// `now` kommt als PARAMETER aus `main`; dieser Pfad holt keine Uhr.
pub fn activate(
    invocation: &Invocation,
    config_path: &Path,
    request_path: &Path,
    transition_object_path: &Path,
    valid_through_sequence: ChainSequence,
    not_after: UnixMillis,
    now: UnixMillis,
) -> ExitCode {
    // 1 — der Antrag und die Objektbytes ZUERST, aus demselben Grund wie bei
    // `prepare`. Die Bytes werden UNVERAENDERT durchgereicht.
    let loaded = match WriterTransitionRequest::load(request_path) {
        Ok(loaded) => loaded,
        Err(error) => {
            output::print_writer_transition_request_error(&error);
            return exit_code_for_request(&error);
        }
    };
    let request = loaded.request;
    // Ohne den echten Hash gibt es nichts, wogegen die Bytes halten koennten
    // (Modulbeschreibung). Ein Aufruffehler, VOR der Bedienerdatei.
    let Some(authorization) = loaded.admin_authorization_object_hash else {
        output::print_missing_authorization_hash_refusal();
        return ExitCode::Usage;
    };
    let transition_object = match read_transition_object(transition_object_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            output::print_operator_error(&error);
            return error.exit_code();
        }
    };
    let result = run(invocation, config_path, now, |runtime| {
        let service = WriterTransitionService::new(runtime.head());
        let prepared = service.prepare(&request, authorization)?;
        let audit = runtime.audit_service();
        let events = RegistryEventFactory::new(runtime.head(), &audit, runtime.local_device());
        // Das Fenster beginnt an der Wirksamkeitssequenz des Antrags — die
        // einzige Stelle, an der der Dienst es annimmt.
        let window = RegistryWindow {
            effective_from_sequence: prepared.effective_from_sequence(),
            valid_through_sequence,
            not_after,
        };
        let activated = service.activate(&prepared, &transition_object, &events, window)?;
        let event = activated.event();
        let view = WriterTransitionActivateView {
            registry_version: event.registry_version,
            previous_registry_hash: event.previous_registry_hash,
            effective_from_sequence: event.effective_from_sequence,
            valid_through_sequence: event.valid_through_sequence,
            issued_at: event.issued_at,
            not_before: event.not_before,
            not_after: event.not_after,
            transition_object_hash: activated.transition_object_hash(),
        };
        Ok(Report::Activate(view))
    });
    finish(invocation, result)
}

/// Die abgelesene Sicht EINES der beiden Unterkommandos.
enum Report {
    Prepare(WriterTransitionPrepareView),
    Activate(WriterTransitionActivateView),
}

/// Der Fehlschlag EINES der Schritte — Laufzeit oder Uebergang.
///
/// Dieselbe Bauart wie `PlanError` in `crate::commands::registry`: zwei
/// Herkuenfte, die ihre Codes behalten, damit der Leser erfaehrt, WELCHE
/// Schicht gesprochen hat. Der Antrag steht nicht darin: seine Fehler
/// entstehen VOR diesem Typ und enden den Lauf, bevor er gebaut wird.
enum RunError {
    Runtime(OperatorRuntimeError),
    Transition(WriterTransitionError),
}

impl From<OperatorRuntimeError> for RunError {
    fn from(error: OperatorRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<WriterTransitionError> for RunError {
    fn from(error: WriterTransitionError) -> Self {
        Self::Transition(error)
    }
}

/// Laedt die Bedienerdatei, oeffnet die Laufzeit und laesst `step` gegen den
/// gewaehlten Kopf arbeiten.
///
/// `step` bekommt die Laufzeit als Referenz und nicht den Kopf allein: die
/// Aktivierung braucht neben dem Kopf den Auditdienst und die lokale
/// Geraeteidentitaet fuer die Ereignisfabrik.
fn run(
    invocation: &Invocation,
    config_path: &Path,
    now: UnixMillis,
    step: impl FnOnce(&OperatorRuntime) -> Result<Report, RunError>,
) -> Result<Report, RunError> {
    // 2 — die Bedienerdatei. Ihre Fehler tragen ihre eigene Zuordnung
    // (`OperatorRuntimeError::exit_code`): eine unlesbare Datei ist 20, eine
    // Datei ohne Form ist 2.
    let config = OperatorRuntimeConfig::load(config_path)?;
    // 3 — der gepruefte Bestand und sein gewaehlter Kopf. `initialize` ist
    // ausdruecklich `false`: dieses Kommando richtet keinen Bediener ein.
    let runtime = OperatorRuntime::open(config, &invocation.anchor, now, false)?;
    // 4 — der Schritt.
    let report = step(&runtime)?;
    // 5 — der gewaehlte Kopf muss den ganzen Lauf ueber tragen. Eine Ausgabe
    // ueber einen inzwischen abgelaufenen Kopf waere eine Aussage ueber einen
    // Stand, den es nicht mehr gibt.
    runtime.ensure_current()?;
    Ok(report)
}

/// Druckt das Ergebnis oder den Fehler und ordnet den Exitcode zu.
fn finish(invocation: &Invocation, result: Result<Report, RunError>) -> ExitCode {
    let printed = match result {
        Ok(Report::Prepare(view)) => {
            output::print_writer_transition_prepare_report(&view, invocation.format)
        }
        Ok(Report::Activate(view)) => {
            output::print_writer_transition_activate_report(&view, invocation.format)
        }
        Err(RunError::Runtime(error)) => {
            output::print_operator_error(&error);
            return error.exit_code();
        }
        Err(RunError::Transition(error)) => {
            output::print_writer_transition_error(&error);
            return exit_code_for(&error);
        }
    };
    match printed {
        Ok(()) => ExitCode::Success,
        Err(error) => {
            output::print_operator_error(&error);
            error.exit_code()
        }
    }
}

/// Liest die Objektbytes UNVERAENDERT und begrenzt.
///
/// Dieselbe Bauart wie `read_release` in `crate::commands::clock_release`,
/// mit demselben Code: eine fehlende oder zu grosse Datei ist
/// `EA-OPERATOR-IO` und faellt auf 20.
fn read_transition_object(path: &Path) -> Result<Vec<u8>, OperatorRuntimeError> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| OperatorRuntimeError::Io)?
        .take(TRANSITION_OBJECT_FILE_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| OperatorRuntimeError::Io)?;
    if bytes.len() > TRANSITION_OBJECT_FILE_LIMIT {
        return Err(OperatorRuntimeError::Io);
    }
    Ok(bytes)
}

/// Ordnet einen Antragsfehler der normativen Exitcodetabelle zu.
///
/// Dieselbe Richtung wie die der Bedienerdatei in
/// `ea_admin::operator_runtime::OperatorRuntimeError::exit_code`, an der
/// sich `crate::commands::registry` bereits misst: eine Datei, die nicht zu
/// lesen ist, ist ein I/O-Befund (`EA-OPERATOR-IO` → 20); eine Datei, die
/// lesbar ist, aber keine Form hat, ist ein Aufruffehler
/// (`EA-OPERATOR-CONFIG` → 2) — am Bestand liegt es nicht, es wurde kein
/// Byte eines Archivs gelesen, und mit einer Datei in Form ist der Lauf
/// unveraendert wiederholbar. Der Auffangarm ist Pflicht:
/// [`WriterTransitionRequestError`] ist `#[non_exhaustive]`, und ein neuer
/// Arm dort ist ein Befund ueber die Eingabe, also konservativ 2.
fn exit_code_for_request(error: &WriterTransitionRequestError) -> ExitCode {
    match error {
        WriterTransitionRequestError::Unreadable => ExitCode::Io,
        _ => ExitCode::Usage,
    }
}

/// Ordnet einen Uebergangsfehler der normativen Exitcodetabelle zu.
///
/// Die Tabelle ist eine Zusage des PROZESSES und wohnt deshalb hier und nicht
/// in `ea-admin` — dieselbe Richtung wie in `crate::commands::registry`, und
/// dieselbe Regel: ein Formfehler ist ein Befund ueber BYTES und faellt auf
/// 10; ein durchgereichter Registrierungsbefund faellt, wie dort, mit seiner
/// Formhaelfte auf 10 und sonst auf 12; alles uebrige — laufender Writer,
/// freigegebener Writer, Sequenz, Objekt, Fenster — ist ein Befund ueber die
/// Vertrauenslage und faellt auf 12. Beide Auffangarme sind Pflicht:
/// [`WriterTransitionError`] und [`RegistryWorkflowError`] sind
/// `#[non_exhaustive]`, und ein neuer Arm soll konservativ auf 12 fallen.
fn exit_code_for(error: &WriterTransitionError) -> ExitCode {
    match error {
        WriterTransitionError::Format(_)
        | WriterTransitionError::Registry(RegistryWorkflowError::Format(_)) => ExitCode::Integrity,
        _ => ExitCode::Trust,
    }
}
