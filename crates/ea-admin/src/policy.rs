//! Die initiale Policy und ihr Lease.
//!
//! # Warum der Antrag KEIN `Default` hat
//!
//! Der Plan verlangt, dass die initiale Policy Profil, Registrierungsalter,
//! Zeitversatz, Verhalten bei veraltetem Kopf, Sequenz-Lease, Evidenzfenster,
//! Leserinaktivitaet und -historie, Archivprofile, Backup und Restore,
//! Aufbewahrung und Vernichtung, Freitext sowie Suiten und Formate
//! AUSDRUECKLICH festlegt. Ein Vorgabewert waere genau das Gegenteil: eine
//! Dimension, die niemand entschieden hat, die aber trotzdem gilt.
//! [`InitialPolicyRequest`] hat deshalb ausschliesslich Pflichtfelder und
//! keinen `Default`; wer eine Dimension vergisst, kommt nicht am Uebersetzer
//! vorbei.
//!
//! # Warum das Lease NICHT im Policy-Objekt steht
//!
//! `PolicyFieldsV1` traegt `effectiveFromSequence`, aber keine Obergrenze
//! (`crates/ea-format/src/etb.rs:216-236`). Das Sequenz-Lease lebt im
//! Registrierungsereignis (`effectiveFromSequence`/`validThroughSequence`).
//! Der Plan zaehlt es trotzdem zu dem, was die initiale Policy festlegt —
//! also reist es hier als [`RegistryWindow`] neben dem Policy-Koerper mit,
//! statt als erfundenes Feld IN ihm.

use ea_format::{FreeTextPolicyFieldsV1, PolicyFieldsV1, RetentionPolicyFieldsV1, TrustPayloadV1};
use ea_types::{ChainSequence, Hash32, ObjectHash, OrganizationId, UnixMillis};

use crate::{RegistryWindow, registry::RegistryWorkflowError};

/// Jede Dimension, die die initiale Policy festlegt — Pflichtfeld fuer
/// Pflichtfeld.
///
/// Die Feldnamen folgen [`PolicyFieldsV1`]; `policy_version` und
/// `previous_policy_object_hash` fehlen absichtlich, weil sie fuer die
/// INITIALE Policy keine Wahl sind (siehe [`initial_policy_plan`]).
#[derive(Clone)]
pub struct InitialPolicyRequest {
    pub organization_id: OrganizationId,
    /// Die Sequenz, ab der die Policy gilt — zugleich die Untergrenze des
    /// Lease von Kopf 1.
    pub effective_from_sequence: ChainSequence,
    /// Die Obergrenze des Sequenz-Lease von Kopf 1.
    pub lease_valid_through_sequence: ChainSequence,
    /// Die Zeitgrenze von Kopf 1.
    pub not_after: UnixMillis,
    /// Betriebsprofil, 0..1 (`crates/ea-format/src/etb.rs:1725-1727`).
    pub operating_profile: u8,
    pub max_registry_age_ms: u64,
    pub max_future_clock_skew_ms: u64,
    /// Verhalten bei veraltetem Registrierungskopf, 0..1.
    pub registry_expiry_behavior: u8,
    pub evidence_max_delay_ms: u64,
    pub reader_inactivity_ms: u64,
    pub reader_trust_refresh_ms: u64,
    pub reader_history_access_allowed: bool,
    /// Die zugelassenen Archivprofile. Leer hiesse: kein Profil zugelassen und
    /// damit auch das Netzwerkfehlerverhalten nicht festgelegt.
    pub allowed_archive_profile_hashes: Vec<Hash32>,
    pub backup_frequency_ms: u64,
    pub restore_test_interval_ms: u64,
    pub retention_policy: RetentionPolicyFieldsV1,
    pub free_text_policy: FreeTextPolicyFieldsV1,
    pub allowed_crypto_suite_ids: Vec<String>,
    pub allowed_format_versions: Vec<u64>,
}

/// Die initiale Policy zusammen mit dem Lease, das Kopf 1 fuer sie fuehrt.
#[derive(Clone)]
pub struct InitialPolicyPlan {
    /// Der Policy-Koerper. Version 1, ohne Vorgaengerin.
    pub policy: PolicyFieldsV1,
    /// Das Fenster von Kopf 1 — Sequenz-Lease und Zeitgrenze.
    pub window: RegistryWindow,
}

impl InitialPolicyPlan {
    /// Die Aenderung, unter der Kopf 1 diese Policy traegt: Aktion 2.
    ///
    /// Der Objekthash entsteht erst, wenn die Wurzel die Policy signiert hat;
    /// er kann deshalb nicht schon im Plan stehen.
    #[must_use]
    pub const fn action(policy_object_hash: ObjectHash) -> crate::registry::RegistryActionV1 {
        crate::registry::RegistryActionV1::PolicyChange { policy_object_hash }
    }
}

/// Baut die initiale Policy und das Lease von Kopf 1.
///
/// Die Form der Felder prueft [`TrustPayloadV1::policy`]; hier wird nichts
/// davon nachgerechnet.
///
/// # Was diese Pruefung dem Formpruefer VORAUS hat
///
/// Zwei verschiedene Dinge, und nur eines davon ist „sonst ungeprueft":
///
/// * Die drei LEEREN Listen wuerde auch [`TrustPayloadV1::policy`] abweisen —
///   gemessen, jede fuer sich, mit `EA-FORMAT-SHAPE`. Der Gewinn hier ist
///   nicht, dass es ueberhaupt auffaellt, sondern WANN und ALS WAS: der
///   Aufrufer erfaehrt es, bevor ein Policy-Koerper entsteht, und er erfaehrt
///   „eine Dimension ist offen" statt „die Form stimmt nicht". Die Bedienung
///   der initialen Policy kann daraus eine Frage an den Menschen machen, aus
///   einem Formfehler nicht.
/// * Die Lease-Beziehung prueft tatsaechlich SONST NIEMAND: das Lease steht im
///   Registrierungsereignis und nicht im Policy-Koerper (siehe den Modulkopf),
///   also sieht der Formpruefer es gar nicht. Ohne diesen Arm liefe ein Lease,
///   das vor seiner Wirksamkeitssequenz endet, ohne Befund durch.
///
/// # Errors
///
/// `EA-WORKFLOW-POLICY-INCOMPLETE`, wenn Archivprofile, Suiten oder Formate
/// leer sind oder das Lease vor seiner Wirksamkeitssequenz endet. Formfehler
/// der Felder behalten ihren `EA-FORMAT-`-Code.
pub fn initial_policy_plan(
    request: InitialPolicyRequest,
) -> Result<InitialPolicyPlan, RegistryWorkflowError> {
    if request.allowed_archive_profile_hashes.is_empty()
        || request.allowed_crypto_suite_ids.is_empty()
        || request.allowed_format_versions.is_empty()
        || request.lease_valid_through_sequence < request.effective_from_sequence
    {
        return Err(RegistryWorkflowError::PolicyIncomplete);
    }

    let policy = PolicyFieldsV1 {
        organization_id: request.organization_id,
        // Die initiale Policy IST die erste; beides ist keine Wahl des
        // Aufrufers, sondern folgt daraus, dass es keine Vorgaengerin gibt.
        policy_version: 1,
        previous_policy_object_hash: None,
        operating_profile: request.operating_profile,
        max_registry_age_ms: request.max_registry_age_ms,
        max_future_clock_skew_ms: request.max_future_clock_skew_ms,
        registry_expiry_behavior: request.registry_expiry_behavior,
        evidence_max_delay_ms: request.evidence_max_delay_ms,
        reader_inactivity_ms: request.reader_inactivity_ms,
        reader_trust_refresh_ms: request.reader_trust_refresh_ms,
        reader_history_access_allowed: request.reader_history_access_allowed,
        allowed_archive_profile_hashes: request.allowed_archive_profile_hashes,
        backup_frequency_ms: request.backup_frequency_ms,
        restore_test_interval_ms: request.restore_test_interval_ms,
        retention_policy: request.retention_policy,
        free_text_policy: request.free_text_policy,
        allowed_crypto_suite_ids: request.allowed_crypto_suite_ids,
        allowed_format_versions: request.allowed_format_versions,
        effective_from_sequence: request.effective_from_sequence,
    };

    // Der EINE Formpruefer. Die Autorisierung ist zum Planzeitpunkt noch nicht
    // erteilt; ihr Hash tritt beim Signieren an diese Stelle.
    TrustPayloadV1::policy(policy.clone(), ObjectHash::from(Hash32::ZERO))?;

    Ok(InitialPolicyPlan {
        policy,
        window: RegistryWindow {
            effective_from_sequence: request.effective_from_sequence,
            valid_through_sequence: request.lease_valid_through_sequence,
            not_after: request.not_after,
        },
    })
}
