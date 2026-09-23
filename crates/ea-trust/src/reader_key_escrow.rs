//! Der Trust-Kern des Reader-Key-Escrows (v1.1-Profil §3.1).
//!
//! # Eine Regel je Familie
//!
//! Dieses Modul trägt genau EIN privates Prädikat je Familie. Alle Aufrufer —
//! die native Zeremonie, die Familien-Admission des Servers, der Bestand für
//! Reader und Prüfung — laufen durch dieselben Prädikate und erhalten
//! Beweistypen mit Accessoren. Kein Aufrufer vergleicht Felder selbst.
//!
//! # Die Publikationsfreigabe
//!
//! Genau eine Signatur des benannten aktiven `OrganizationAdmin`-Zertifikats
//! mit `organizationAdminApprove`, gepaart mit der benannten aktiven nativen
//! Bedienerbindung desselben Autoritätssubjekts — dieselbe Regel wie die der
//! Administrationsautorisierung ([`crate::admin_authorization`]), nur über den
//! Kontext der Freigabe. Organisation, Kopf und Sequenz kommen aus der
//! gewählten geprüften Registry, nie aus Nutzlastbehauptungen. Abgelaufen ist
//! `now > expires-at` (Entscheidung 10); die Höchstdauer von 300 000 ms prüft
//! der Codec.

use ea_crypto::VerificationContext;
use ea_format::{
    DecodedTrustPayloadV1, ParsedArchiveObject, ReaderKeyEscrowApprovalCoreV1, TrustObjectV1,
};
use ea_types::{ChainSequence, ObjectHash, RegistryVersion, SubjectId, UnixMillis};

use crate::{
    AdminAuthorizationReplayKey, SelectedRegistryHead, TrustError, TrustStateStore, VerifiedTrust,
    admin_authorization::{AdminSignerClaim, consume_replay_keys, verify_admin_signer_claim},
    resolver::PreviousHeadState,
};

/// Wie die `authorization-sequence` einer Autorisierung an den Zustand
/// gebunden ist, gegen den sie geprüft wird.
#[derive(Clone, Copy)]
pub(crate) enum SequenceRule {
    /// Gleich der vorgeschlagenen Sequenz des gewählten Kopfes — die frische
    /// Zeremonie, nach dem Vorbild `verify_grant_authorization`.
    Exact(ChainSequence),
}

/// Gegen welche Zeit das Gültigkeitsfenster gemessen wird.
#[derive(Clone, Copy)]
pub(crate) enum WindowRule {
    /// `t < issued-at` ist noch nicht gültig, `t > expires-at` abgelaufen;
    /// `t == expires-at` ist gültig (Entscheidung 10).
    At(UnixMillis),
}

/// Eine Publikationsfreigabe, die [`approval_rule`] bestanden hat.
///
/// Nur in diesem Modul konstruierbar:
///
/// ```compile_fail
/// let _ = ea_trust::VerifiedReaderKeyEscrowApproval { inner: panic!() };
/// ```
pub struct VerifiedReaderKeyEscrowApproval {
    inner: ApprovalInner,
}

struct ApprovalInner {
    exact_bytes: Vec<u8>,
    object_hash: ObjectHash,
    fields: ReaderKeyEscrowApprovalCoreV1,
    signer_authority_subject_id: SubjectId,
    replay_keys: [AdminAuthorizationReplayKey; 2],
    verified_registry_version: RegistryVersion,
    verified_registry_head_hash: ObjectHash,
}

impl VerifiedReaderKeyEscrowApproval {
    /// Die Version des Kopfes, GEGEN den geprüft wurde.
    #[must_use]
    pub const fn verified_registry_version(&self) -> RegistryVersion {
        self.inner.verified_registry_version
    }

    /// Der Hash des Kopfes, GEGEN den geprüft wurde.
    #[must_use]
    pub const fn verified_registry_head_hash(&self) -> ObjectHash {
        self.inner.verified_registry_head_hash
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.inner.exact_bytes
    }

    #[must_use]
    pub const fn object_hash(&self) -> ObjectHash {
        self.inner.object_hash
    }

    #[must_use]
    pub const fn fields(&self) -> &ReaderKeyEscrowApprovalCoreV1 {
        &self.inner.fields
    }

    #[must_use]
    pub const fn signer_authority_subject_id(&self) -> SubjectId {
        self.inner.signer_authority_subject_id
    }

    /// Die beiden Sperrzeilen der Freigabe, `authorization-id` zuerst, dann
    /// `nonce` — im selben Namensraum wie jede Administrationsautorisierung.
    #[must_use]
    pub const fn replay_keys(&self) -> &[AdminAuthorizationReplayKey; 2] {
        &self.inner.replay_keys
    }
}

/// Prüft eine FRISCHE Publikationsfreigabe in der Zeremonie (Profil §5
/// Schritt 4).
///
/// Die Bytes müssen NICHT im Katalog liegen: die Freigabe entsteht in der
/// Zeremonie und wird erst mit dem Escrow veröffentlicht. Kopf, Sequenz und
/// Organisation kommen aus `head`: die Freigabe muss genau an diesen Kopf und
/// an seine vorgeschlagene Sequenz gebunden sein, und `now` muss in ihrem
/// Fenster liegen.
///
/// Die Einmal-Nutzung sitzt NICHT hier: verbraucht wird über
/// [`consume_reader_key_escrow_approval`].
///
/// # Errors
///
/// [`TrustError::Source`] für Bytes, die keine Publikationsfreigabe sind,
/// [`TrustError::ActionMismatch`] für fremde Organisation, fremden Kopf oder
/// fremde Sequenz, jeden Befund der Signiererregel
/// ([`TrustError::Signature`], [`TrustError::SignerInactive`],
/// [`TrustError::SubjectMismatch`]) sowie [`TrustError::AuthNotYetValid`] und
/// [`TrustError::AuthExpired`].
pub fn verify_reader_key_escrow_approval(
    trust: &VerifiedTrust,
    head: &SelectedRegistryHead,
    exact_approval_bytes: &[u8],
    now: UnixMillis,
) -> Result<VerifiedReaderKeyEscrowApproval, TrustError> {
    let (object_hash, object, fields) = decode_approval(exact_approval_bytes)?;
    let state = head.candidate_state();
    if fields.organization_id != trust.organization_id() {
        return Err(TrustError::ActionMismatch);
    }
    let signer_authority_subject_id = approval_rule(
        state,
        &object,
        &fields,
        SequenceRule::Exact(head.proposed_sequence()),
        WindowRule::At(now),
    )?;
    Ok(VerifiedReaderKeyEscrowApproval {
        inner: ApprovalInner {
            exact_bytes: exact_approval_bytes.to_vec(),
            object_hash,
            replay_keys: AdminAuthorizationReplayKey::pair_from_verified_escrow_approval(&fields),
            fields,
            signer_authority_subject_id,
            verified_registry_version: head.registry_version(),
            verified_registry_head_hash: head.registry_head_hash(),
        },
    })
}

/// Verbraucht eine geprüfte Publikationsfreigabe EIN Mal, organisationsweit
/// und laufübergreifend: beide Zeilen im bestehenden zweidimensionalen
/// Einmal-Speicher, `authorization-id` zuerst.
///
/// # Errors
///
/// [`TrustError::AuthReplay`], wenn die `authorization-id` ODER die `nonce`
/// schon verbraucht ist — auch durch eine Administrationsautorisierung oder
/// eine Öffnungsautorisierung (geteilter Namensraum). Sonst jeden Befund der
/// Ablage, insbesondere [`TrustError::StateUnavailable`] für einen Speicher,
/// der die Sperre nicht führt.
pub fn consume_reader_key_escrow_approval(
    store: &mut dyn TrustStateStore,
    approval: &VerifiedReaderKeyEscrowApproval,
) -> Result<(), TrustError> {
    consume_replay_keys(store, approval.replay_keys())
}

/// Dekodiert exakte Bytes als Publikationsfreigabe.
pub(crate) fn decode_approval(
    exact_bytes: &[u8],
) -> Result<(ObjectHash, TrustObjectV1, ReaderKeyEscrowApprovalCoreV1), TrustError> {
    let ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(exact_bytes).map_err(|_| TrustError::Source)?
    else {
        return Err(TrustError::Source);
    };
    let DecodedTrustPayloadV1::ReaderKeyEscrowApproval(fields) = parsed
        .value()
        .decoded_payload()
        .map_err(|_| TrustError::Source)?
    else {
        return Err(TrustError::Source);
    };
    Ok((parsed.object_hash(), parsed.value().clone(), fields))
}

/// Die EINE Regel der Publikationsfreigabe.
///
/// `state` ist der Zustand, an dessen Kopf die Freigabe gebunden sein muss —
/// der gewählte Kopf in Zeremonie und Aufnahme, der exakt nachgespielte
/// Pin-Zustand in der Historie. Die Reihenfolge der Befunde:
///
/// 1. Organisation (`ActionMismatch`);
/// 2. Kopf gleich dem Zustand (`ActionMismatch`);
/// 3. Sequenz nach `sequence` (`ActionMismatch`);
/// 4. Signierer über die geteilte Administrator-Regel zur
///    `authorization-sequence`;
/// 5. Fenster nach `window`.
pub(crate) fn approval_rule(
    state: &PreviousHeadState,
    object: &TrustObjectV1,
    fields: &ReaderKeyEscrowApprovalCoreV1,
    sequence: SequenceRule,
    window: WindowRule,
) -> Result<SubjectId, TrustError> {
    if fields.organization_id != state.root.fields.organization_id {
        return Err(TrustError::ActionMismatch);
    }
    if fields.registry_version != state.registry_version
        || fields.registry_head_hash != state.registry_head_hash
    {
        return Err(TrustError::ActionMismatch);
    }
    let authorization_sequence = ChainSequence::new(fields.authorization_sequence);
    require_sequence(state, authorization_sequence, sequence)?;
    let signer = verify_admin_signer_claim(
        state,
        object,
        &AdminSignerClaim {
            organization_id: fields.organization_id,
            admin_certificate_hash: fields.admin_certificate_object_hash,
            admin_key_thumbprint: fields.admin_key_thumbprint,
            admin_operator_binding_object_hash: fields.admin_operator_binding_object_hash,
        },
        VerificationContext::reader_key_escrow_approval_trust_digest,
        authorization_sequence,
    )?;
    require_window(fields.issued_at, fields.expires_at, window)?;
    Ok(signer)
}

pub(crate) fn require_sequence(
    state: &PreviousHeadState,
    authorization_sequence: ChainSequence,
    rule: SequenceRule,
) -> Result<(), TrustError> {
    let _ = state;
    let bound = match rule {
        SequenceRule::Exact(expected) => authorization_sequence == expected,
    };
    if bound {
        Ok(())
    } else {
        Err(TrustError::ActionMismatch)
    }
}

pub(crate) fn require_window(
    issued_at: UnixMillis,
    expires_at: UnixMillis,
    rule: WindowRule,
) -> Result<(), TrustError> {
    let WindowRule::At(use_time) = rule;
    if use_time < issued_at {
        return Err(TrustError::AuthNotYetValid);
    }
    if use_time > expires_at {
        return Err(TrustError::AuthExpired);
    }
    Ok(())
}
