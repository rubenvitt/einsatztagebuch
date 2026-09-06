//! Kommando `registry revocation-plan`.
//!
//! Bereitet die Registrierungsaenderung 1 fuer ein am gewaehlten Kopf aktives
//! Ziel vor und berichtet ihre REICHWEITE.
//!
//! # Was dieser Pfad NICHT tut
//!
//! Er parst keine Registrierung, rechnet keine Sequenz und entscheidet keinen
//! Schritt. Die Zielart wird aus dem Bestand HERGELEITET
//! (`ea_admin::revocation::classify_revocation_target`), das Ereignis baut die
//! Fabrik (`ea_admin::registry::RegistryEventFactory`), und die Reichweite
//! gibt `ea_admin::revocation::RevocationEffect` heraus. Dieses Modul ruft,
//! liest ab, druckt und ordnet einen Exitcode zu — dieselbe Arbeitsteilung wie
//! bei `organization init` und `operator`.
//!
//! # Warum es PLAN heisst und nicht `revoke`
//!
//! `plan_revocation` liefert `RegistryEventFieldsV1` — die vorbereiteten
//! Felder. Wirksam wird die Aenderung erst, wenn die Wurzel sie signiert und
//! der Kopf uebergeht; die dafuer noetigen Offline-Schluesselquellen kann ein
//! CLI-Prozess so wenig herbeireden wie bei `organization init`
//! (`ea_key_provider::SecretPurpose` kennt keinen Wurzelzweck). Ein Kommando
//! namens `revoke` verspraeche einen Vollzug, den dieser Lauf nicht hat.
//!
//! # Warum das Ziel in der BEDIENERDATEI steht und nicht in der Aufrufzeile
//!
//! Ein Objekthash ist 32 Byte Hex, und dieses Paket hat keinen Hex-Dekodierer:
//! `hex` steht nur in `[dev-dependencies]`, und `ea-admin` gibt seinen eigenen
//! (`operator_runtime::parse_hash`) nicht heraus. Die oeffentliche
//! Bedienerdatei fuehrt mit `target_certificate_hash` bereits ein
//! GEPRUEFTES Zielfeld, das `ea-admin` selbst dekodiert. Es hier zu lesen
//! bringt keinen zweiten Parser in den Kommandopfad. Dass das Feld heute
//! zusaetzlich den Autoritaetsbetrieb bedient, ist eine Ueberladung und im
//! Abschlussbericht dieser Scheibe vermerkt.
//!
//! # Das Fenster kommt VON AUSSEN
//!
//! `--effective-from`, `--valid-through` und `--not-after` sind Entscheidungen
//! des Betreibers. Sie werden unveraendert in [`RegistryWindow`] gelegt; ob
//! sie zum Lease und zur Registrierungsalterung des gewaehlten Kopfes passen,
//! prueft `OperatorBindingService::registry_event` und nicht dieses Modul.

use std::path::Path;

use ea_admin::{
    RegistryWindow,
    operator_runtime::{OperatorRuntime, OperatorRuntimeConfig, OperatorRuntimeError},
    registry::{RegistryEventFactory, RegistryWorkflowError},
    revocation::plan_revocation,
};
use ea_recovery::ExitCode;
use ea_types::{ChainSequence, ObjectHash, UnixMillis};

use crate::{
    args::Invocation,
    output::{self, RevocationPlanView},
};

/// Fuehrt `registry revocation-plan` aus.
///
/// `now` kommt als PARAMETER aus `main`; dieser Pfad holt keine Uhr.
pub fn run(
    invocation: &Invocation,
    config_path: &Path,
    effective_from_sequence: ChainSequence,
    valid_through_sequence: ChainSequence,
    not_after: UnixMillis,
    now: UnixMillis,
) -> ExitCode {
    // 1 — die Bedienerdatei und ihr Ziel, VOR jedem Bestand. Eine Datei ohne
    // Ziel ist ein Aufruffehler und kein Befund: es wurde kein Byte eines
    // Archivs gelesen, und der Lauf ist mit einem benannten Ziel unveraendert
    // wiederholbar.
    let config = match OperatorRuntimeConfig::load(config_path) {
        Ok(config) => config,
        Err(error) => {
            output::print_operator_error(&error);
            return error.exit_code();
        }
    };
    let Some(target) = config.target_certificate_hash else {
        output::print_missing_revocation_target_refusal();
        return ExitCode::Usage;
    };
    // Ein Zertifikatshash IST ein Objekthash; `ea-types` fuehrt heute nur die
    // Richtung `ObjectHash -> CertificateHash` und den Weg ueber die 32 Byte
    // zurueck. Die Umwandlung kann nicht scheitern — `as_bytes` gibt genau
    // `[u8; 32]` —, und wenn sie es doch taete, waere der Typ veraendert
    // worden und muesste laut werden.
    let object_hash = ObjectHash::try_from(target.as_bytes().as_slice())
        .expect("ein Zertifikatshash ist 32 Byte lang");

    let result = plan(invocation, config, object_hash, now, || RegistryWindow {
        effective_from_sequence,
        valid_through_sequence,
        not_after,
    });
    match result {
        Ok(code) => code,
        Err(PlanError::Runtime(error)) => {
            output::print_operator_error(&error);
            error.exit_code()
        }
        Err(PlanError::Workflow(error)) => {
            output::print_registry_workflow_error(&error);
            exit_code_for(&error)
        }
    }
}

/// Der Fehlschlag EINES der beiden Schritte — Laufzeit oder Ablauf.
///
/// Zwei Herkuenfte, die ihre Codes behalten: die Laufzeit bringt ihre eigene
/// Zuordnung mit ([`OperatorRuntimeError::exit_code`]), der Ablauf bekommt sie
/// hier ([`exit_code_for`]). Sie zu einem Typ zu verschmelzen naehme dem Leser
/// die Auskunft, WELCHE Schicht gesprochen hat.
enum PlanError {
    Runtime(OperatorRuntimeError),
    Workflow(RegistryWorkflowError),
}

impl From<OperatorRuntimeError> for PlanError {
    fn from(error: OperatorRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<RegistryWorkflowError> for PlanError {
    fn from(error: RegistryWorkflowError) -> Self {
        Self::Workflow(error)
    }
}

/// Oeffnet die Laufzeit, plant die Aenderung 1 und druckt ihre Reichweite.
///
/// `window` kommt als Abschluss und nicht als Wert, damit die drei Zahlen erst
/// hinter dem Oeffnen der Laufzeit zusammengesetzt werden — vorher gibt es
/// keinen Kopf, gegen den sie etwas bedeuteten.
fn plan(
    invocation: &Invocation,
    config: OperatorRuntimeConfig,
    object_hash: ObjectHash,
    now: UnixMillis,
    window: impl FnOnce() -> RegistryWindow,
) -> Result<ExitCode, PlanError> {
    // 2 — der gepruefte Bestand und sein gewaehlter Kopf. `initialize` ist
    // ausdruecklich `false`: dieses Kommando richtet keinen Bediener ein.
    let runtime = OperatorRuntime::open(config, &invocation.anchor, now, false)?;
    let audit = runtime.audit_service();
    let events = RegistryEventFactory::new(runtime.head(), &audit, runtime.local_device());

    // 3 — die Planung. Zielart, Fensterpruefung und Reichweite liegen
    // vollstaendig in `ea-admin`.
    let (event, effect) = plan_revocation(&events, window(), object_hash)?;

    // 4 — der gewaehlte Kopf muss den ganzen Lauf ueber tragen. Eine Ausgabe
    // ueber einen inzwischen abgelaufenen Kopf waere eine Aussage ueber einen
    // Stand, den es nicht mehr gibt.
    runtime.ensure_current()?;

    // 5 — die Reichweite wird ABGELESEN und nicht behauptet: alle vier
    // Angaben stammen aus `RevocationEffect`, keine aus diesem Modul.
    output::print_revocation_plan_report(
        &RevocationPlanView {
            target_class: effect.target_class(),
            registry_version: event.registry_version,
            stops_new_grants_from: effect.stops_new_grants_from(),
            valid_through_sequence: event.valid_through_sequence,
            recalls_issued_grants: effect.recalls_issued_grants(),
            recalls_decrypted_plaintext: effect.recalls_decrypted_plaintext(),
        },
        invocation.format,
    )?;
    Ok(ExitCode::Success)
}

/// Ordnet einen Ablauffehler der normativen Exitcodetabelle zu.
///
/// Die Tabelle ist eine Zusage des PROZESSES und wohnt deshalb hier und nicht
/// in `ea-admin` — dieselbe Richtung, die `apps/cli/Cargo.toml` fuer die
/// Zeremonie beschreibt.
///
/// Ein Formfehler ist ein Befund ueber BYTES und faellt auf 10; alles uebrige
/// ist ein Befund ueber die Vertrauenslage — Zielart, Zertifikatslebenszyklus,
/// Fenster, Lease — und faellt auf 12. Der Auffangarm ist Pflicht:
/// [`RegistryWorkflowError`] ist `#[non_exhaustive]`, und ein neuer Arm dort
/// soll diesen Pfad nicht brechen, sondern konservativ auf 12 fallen.
fn exit_code_for(error: &RegistryWorkflowError) -> ExitCode {
    match error {
        RegistryWorkflowError::Format(_) => ExitCode::Integrity,
        _ => ExitCode::Trust,
    }
}
