//! Aufnahme EINES `.etb` in den Katalog einer Organisation.
//!
//! # Wozu es das braucht
//!
//! Ein Registrierungskopf laesst sich nur pruefen, wenn die Objekte, die er
//! nennt — seine Autorisierung, seine Policy, das Zertifikat, das er aktiviert
//! — schon im Katalog liegen (`registry.rs`, `verify_bound_authorization` und
//! jeder `prepare_effect`-Arm enden sonst mit
//! [`RegistryError::ActivationMissing`](crate::RegistryError)). Wer Objekte
//! einzeln entgegennimmt, braucht deshalb eine Antwort auf die Frage: „Darf
//! dieses eine Objekt in den Katalog, BEVOR ein Kopf es nennt?“
//!
//! # Was Aufnahme heisst — und was nicht
//!
//! Aufnahme ist KEINE Autoritaet. Ein aufgenommenes Objekt aktiviert kein
//! Zertifikat, hebt keine Policy und verschiebt keinen Kopf; es liegt im
//! Katalog und wartet darauf, dass ein Kopfuebergang es benennt. Autoritaet
//! entsteht ausschliesslich dort — in `select_registry_head` — und dort laeuft
//! die VOLLE Paarpruefung.
//!
//! Aufnahme beantwortet genau drei Fragen, und zwar mit den Bausteinen, die
//! `ea-trust` ohnehin fuehrt:
//!
//! 1. Sind die exakten Bytes ein `.etb` dieser Organisation?
//! 2. Traegt es die Unterschrift eines Signierers, der fuer SEINE Objektart im
//!    aktuellen Abschluss zustaendig ist?
//! 3. Liegt der Zeitpunkt im Gueltigkeitsfenster, das es selbst nennt?
//!
//! # Warum das Paar nicht in einem Zug geht
//!
//! Ein Zielobjekt und seine Autorisierung referenzieren EINANDER: die
//! Wurzelsignatur des Ziels deckt ueber
//! `VerificationContext::root_trust_digest` die exakten Autorisierungsbytes ab,
//! und die Autorisierung nennt den Kernhash des Ziels. Keins von beiden kann
//! zuerst vollstaendig geprueft werden. Die Reihenfolge der Aufnahme ist
//! deshalb festgelegt: erst die Autorisierung — zielfrei gegen den
//! unterschreibenden Administrator —, dann das Ziel, dessen Wurzelsignatur die
//! nun vorliegende Autorisierung abdeckt.
//!
//! # Die Wiedereinspielsperre bleibt beim Kopf
//!
//! [`verify_admin_authorization`] verbraucht `authorizationId` und `nonce`.
//! Die Aufnahme darf das NICHT tun: sonst waere die Autorisierung nach ihrer
//! eigenen Aufnahme verbraucht und der Kopfuebergang, der sie braucht,
//! scheiterte mit `EA-TRUST-AUTH-REPLAY`. Die Aufnahme fuehrt deshalb eine
//! eigene, weggeworfene Sperre. Der Schutz sitzt unveraendert dort, wo aus der
//! Autorisierung Wirkung wird.

use ea_format::{DecodedTrustPayloadV1, ParsedArchiveObject, TrustSubtypeV1};
use ea_types::{ChainSequence, ObjectHash, OrganizationId, UnixMillis};

use crate::{
    SelectedRegistryHead, TrustError, VerifiedTrust,
    admin_authorization::{
        AdminAuthorizationReplay, verify_admin_authorization, verify_authorization_signer,
    },
    resolver::PreviousHeadState,
};

/// Prueft EIN exaktes `.etb` fuer die Aufnahme in den Katalog.
///
/// `head` ist der aktuell gewaehlte Registrierungskopf, oder `None`, solange
/// die Organisation noch keinen hat — dann gilt der aus dem Anker bewiesene
/// Bootstrap-Stand. Beide Staende tragen dieselben Bausteine; der Unterschied
/// ist, welche Zertifikate aktiv sind.
///
/// `exact_object_bytes` MUSS bereits im Katalog liegen, aus dem `trust`
/// entstanden ist: der Aufrufer reicht das Objekt seiner
/// [`crate::TrustObjectSource`] bei, bevor er `verify_trust` ruft. Sonst
/// antwortet die Pruefung mit [`TrustError::Source`].
///
/// # Errors
///
/// [`TrustError::ActionMismatch`] fuer eine Objektart, ueber die diese Stufe
/// nichts beweisen kann, sowie jeden Befund der geteilten Pruefung.
pub fn verify_catalogue_admission(
    trust: &VerifiedTrust,
    head: Option<&SelectedRegistryHead>,
    exact_object_bytes: &[u8],
    now: UnixMillis,
    at_sequence: ChainSequence,
) -> Result<TrustSubtypeV1, TrustError> {
    let state = head.map_or_else(
        || trust.previous_head(),
        SelectedRegistryHead::candidate_state,
    );
    let object_hash = ea_crypto::object_hash(exact_object_bytes);
    let ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(exact_object_bytes).map_err(|_| TrustError::Source)?
    else {
        return Err(TrustError::ActionMismatch);
    };
    let object = parsed.value();
    let subtype = object.subtype();
    if state.catalog_object(object_hash).is_none() {
        return Err(TrustError::Source);
    }

    match object.decoded_payload().map_err(|_| TrustError::Source)? {
        // Die Autorisierung: zielfrei gegen den unterschreibenden
        // Administrator, plus ihr eigenes Zeitfenster.
        DecodedTrustPayloadV1::OrganizationAdminAuthorization(fields) => {
            require_organization(state, fields.organization_id)?;
            if fields.registry_version != state.registry_version
                || fields.registry_head_hash != state.registry_head_hash
            {
                return Err(TrustError::ActionMismatch);
            }
            verify_authorization_signer(state, object, &fields, at_sequence)?;
            if now < fields.issued_at {
                return Err(TrustError::AuthNotYetValid);
            }
            if now > fields.expires_at {
                return Err(TrustError::AuthExpired);
            }
        }
        // Die autorisierten Ziele: die VOLLE Paarpruefung, denn ihre
        // Autorisierung liegt jetzt vor. Die Sperre ist eine eigene und
        // weggeworfene — verbraucht wird beim Kopfuebergang.
        DecodedTrustPayloadV1::AuthorizedRoot(core) => {
            require_organization(state, core.fields().organization_id)?;
            admit_authorized_target(
                state,
                core.authorization_object_hash(),
                object_hash,
                now,
                at_sequence,
            )?;
        }
        DecodedTrustPayloadV1::AuthorizedDevice(core) => {
            require_organization(state, core.fields().organization_id)?;
            admit_authorized_target(
                state,
                core.authorization_object_hash(),
                object_hash,
                now,
                at_sequence,
            )?;
        }
        DecodedTrustPayloadV1::AuthorizedOperatorBinding(core) => {
            require_organization(state, core.fields().organization_id)?;
            admit_authorized_target(
                state,
                core.authorization_object_hash(),
                object_hash,
                now,
                at_sequence,
            )?;
        }
        DecodedTrustPayloadV1::Policy(core) => {
            admit_authorized_target(
                state,
                core.authorization_object_hash(),
                object_hash,
                now,
                at_sequence,
            )?;
        }
        DecodedTrustPayloadV1::WriterTransition(core) => {
            require_organization(state, core.fields().organization_id)?;
            admit_authorized_target(
                state,
                core.authorization_object_hash(),
                object_hash,
                now,
                at_sequence,
            )?;
        }
        // Die Bootstrap-Arten nennt der Anker selbst, und `verify_trust` hat
        // sie deshalb schon bewiesen — sonst waere `trust` nicht entstanden.
        DecodedTrustPayloadV1::InitialRoot(fields) => {
            require_organization(state, fields.organization_id)?;
        }
        DecodedTrustPayloadV1::InitialAdminDevice(fields) => {
            require_organization(state, fields.organization_id)?;
        }
        DecodedTrustPayloadV1::InitialAdminOperatorBinding(fields) => {
            require_organization(state, fields.organization_id)?;
        }
        // Der Kopf selbst wird NICHT aufgenommen: er ist der Uebergang, und
        // ueber ihn entscheidet `select_registry_head`.
        DecodedTrustPayloadV1::RegistryEvent(_) => return Err(TrustError::ActionMismatch),
        // Vernichtung und Grant-Autorisierung gehoeren nicht in den
        // Registrierungsabschluss: `ea-trust` fuehrt fuer sie heute keine
        // Signiererregel, und eine hier zu erfinden waere genau die zweite
        // Umsetzung, die es nicht geben darf.
        DecodedTrustPayloadV1::GrantAuthorization(_)
        | DecodedTrustPayloadV1::DestructionAuthorization(_)
        | DecodedTrustPayloadV1::DestructionTransition(_)
        | DecodedTrustPayloadV1::DeletionAttestation(_) => {
            return Err(TrustError::ActionMismatch);
        }
    }
    Ok(subtype)
}

/// Die aktiven Zertifikate, solange die Organisation noch keinen Kopf hat.
///
/// Sie sind die vom ANKER benannten Administratorzertifikate, und
/// `verify_trust` hat sie ueber `require_exact_anchor_sets` bereits bewiesen —
/// ein zusaetzliches oder abweichendes waere gar nicht bis hierher gekommen.
/// Ohne diesen Zugriff koennte eine frische Organisation ihren ersten
/// Registrierungskopf nie einreichen: dazu braucht es eine Capability, und die
/// steht in genau diesen Zertifikaten.
///
/// Nach dem ersten Kopf gilt [`SelectedRegistryHead::active_certificates`];
/// diese Funktion ist ausdruecklich der Stand DAVOR.
pub fn bootstrap_active_certificates(
    trust: &VerifiedTrust,
    at_sequence: ChainSequence,
) -> impl Iterator<
    Item = (
        ea_types::CertificateHash,
        &ea_format::DeviceCertificateFieldsV1,
    ),
> {
    trust
        .previous_head()
        .active_certificates(at_sequence)
        .map(|(hash, certificate)| (hash, &certificate.fields))
}

fn admit_authorized_target(
    state: &PreviousHeadState,
    authorization_object_hash: ObjectHash,
    object_hash: ObjectHash,
    now: UnixMillis,
    at_sequence: ChainSequence,
) -> Result<(), TrustError> {
    let mut replay = AdminAuthorizationReplay::default();
    verify_admin_authorization(
        state,
        authorization_object_hash,
        object_hash,
        now,
        at_sequence,
        &mut replay,
    )
    .map(|_| ())
}

fn require_organization(
    state: &PreviousHeadState,
    organization_id: OrganizationId,
) -> Result<(), TrustError> {
    if organization_id == state.root.fields.organization_id {
        Ok(())
    } else {
        Err(TrustError::ActionMismatch)
    }
}
