//! Die Öffnungsautorisierung des Reader-Key-Escrows,
//! `readerKeyEscrowRecoveryAuthorization` (v1.1-Profil §3.1 und §6).
//!
//! Nach dem Vorbild von [`crate::grant_authorization`]: mindestens zwei
//! Signaturen von `KeyApprover`-Zertifikaten mit `historicalGrantApprove`
//! (Entscheidung 8 — keine achte Capability), gezählt über
//! [`crate::distinct_authority_subjects`]. Zwei Zertifikate EINER Person sind
//! eine Person und erfüllen die Schwelle nicht; gezählt wird deshalb NIE über
//! Zertifikatshashes. Kopf, Sequenz und Organisation kommen aus der gewählten
//! geprüften Registry. Abgelaufen ist `now > expires-at`; die Höchstdauer von
//! 900 000 ms prüft der Codec. Alle Zielfelder müssen zu EINEM voll
//! geprüften, gültigen Escrow passen, und der Ziel-Transport-Schlüssel wird
//! geprüft, BEVOR der Recovery-Provider angesprochen wird.

use ea_crypto::{
    CanonicalPublicCoseKey, HpkeRecipientPublicKey, VerificationContext, parse_cose_sign1,
};
use ea_format::{
    DecodedTrustPayloadV1, ParsedArchiveObject, ReaderKeyEscrowRecoveryAuthorizationCoreV1,
    ReaderKeyEscrowRestoreContextV1, TrustObjectV1,
};
use ea_types::{ChainSequence, ObjectHash, UnixMillis};

use crate::{
    AdminAuthorizationReplayKey, SelectedRegistryHead, TrustError, TrustStateStore, VerifiedTrust,
    admin_authorization::consume_replay_keys,
    distinct_authority_subjects,
    reader_key_escrow::{
        ReaderKeyEscrowHead, ReaderKeyEscrowStanding, SequenceRule, VerifiedReaderKeyEscrow,
        VerifiedReaderKeyEscrowSet, WindowRule, require_sequence, require_window,
        verify_reader_key_escrows,
    },
    resolver::{PreviousHeadResolver, PreviousHeadState},
};

/// Wie viele UNTERSCHIEDLICHE Personen eine Öffnung autorisieren müssen.
///
/// Dieselbe Zahl wie [`crate::REQUIRED_DISTINCT_GRANT_APPROVERS_V1`], aber
/// eine eigene Konstante: die beiden Vorgänge dürfen sich künftig trennen.
pub const REQUIRED_DISTINCT_ESCROW_RECOVERY_APPROVERS_V1: usize = 2;

/// Eine Öffnungsautorisierung, die ihre Regel gegen ein im gewählten Kopf
/// GÜLTIGES Escrow bestanden hat.
///
/// Nur in diesem Modul konstruierbar:
///
/// ```compile_fail
/// let _ = ea_trust::VerifiedReaderKeyEscrowRecoveryAuthorization { inner: panic!() };
/// ```
pub struct VerifiedReaderKeyEscrowRecoveryAuthorization {
    inner: RecoveryInner,
}

struct RecoveryInner {
    exact_bytes: Vec<u8>,
    object_hash: ObjectHash,
    fields: ReaderKeyEscrowRecoveryAuthorizationCoreV1,
    escrow: VerifiedReaderKeyEscrow,
    replay_keys: [AdminAuthorizationReplayKey; 2],
}

impl VerifiedReaderKeyEscrowRecoveryAuthorization {
    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.inner.exact_bytes
    }

    #[must_use]
    pub const fn object_hash(&self) -> ObjectHash {
        self.inner.object_hash
    }

    #[must_use]
    pub const fn fields(&self) -> &ReaderKeyEscrowRecoveryAuthorizationCoreV1 {
        &self.inner.fields
    }

    /// Das EINE voll geprüfte, im gewählten Kopf gültige Escrow, zu dem alle
    /// Zielfelder passen.
    #[must_use]
    pub const fn escrow(&self) -> &VerifiedReaderKeyEscrow {
        &self.inner.escrow
    }

    /// Der HPKE-Kontext der Öffnungsantwort, aus der GEPRÜFTEN Autorisierung.
    #[must_use]
    pub fn restore_context(&self) -> ReaderKeyEscrowRestoreContextV1 {
        ReaderKeyEscrowRestoreContextV1::from_recovery_authorization(
            &self.inner.fields,
            self.inner.object_hash,
        )
    }

    /// Die beiden Sperrzeilen, `authorization-id` zuerst — im selben
    /// Namensraum wie Administrationsautorisierung und Freigabe.
    #[must_use]
    pub const fn replay_keys(&self) -> &[AdminAuthorizationReplayKey; 2] {
        &self.inner.replay_keys
    }

    /// Profil §3.1: der tatsächliche Ziel-Transport-Schlüssel MUSS
    /// kanonisches X25519 sein und dem autorisierten Abdruck gleichen —
    /// BEVOR der Recovery-Provider angesprochen wird. Der zurückgegebene Typ
    /// ist der Nachweis dafür.
    ///
    /// # Errors
    ///
    /// [`TrustError::ActionMismatch`] für einen nicht kanonischen Schlüssel
    /// oder einen anderen Abdruck.
    pub fn require_target_transport_key(
        &self,
        x25519_public: [u8; 32],
    ) -> Result<AuthorizedEscrowTransportKey, TrustError> {
        HpkeRecipientPublicKey::from_bytes(x25519_public)
            .map_err(|_| TrustError::ActionMismatch)?;
        let key = CanonicalPublicCoseKey::x25519(x25519_public)
            .map_err(|_| TrustError::ActionMismatch)?;
        if key.thumbprint() != self.inner.fields.target_transport_key_thumbprint {
            return Err(TrustError::ActionMismatch);
        }
        Ok(AuthorizedEscrowTransportKey { key })
    }
}

/// Ein Ziel-Transport-Schlüssel, der gegen die geprüfte
/// Öffnungsautorisierung bestanden hat.
///
/// Nur über
/// [`VerifiedReaderKeyEscrowRecoveryAuthorization::require_target_transport_key`]
/// erhältlich:
///
/// ```compile_fail
/// let key = ea_crypto::CanonicalPublicCoseKey::x25519([9; 32]).unwrap();
/// let _ = ea_trust::AuthorizedEscrowTransportKey { key };
/// ```
///
/// ```compile_fail
/// let key = ea_crypto::CanonicalPublicCoseKey::x25519([9; 32]).unwrap();
/// let _: ea_trust::AuthorizedEscrowTransportKey = key.into();
/// ```
pub struct AuthorizedEscrowTransportKey {
    key: CanonicalPublicCoseKey,
}

impl AuthorizedEscrowTransportKey {
    #[must_use]
    pub const fn public_key(&self) -> &CanonicalPublicCoseKey {
        &self.key
    }
}

/// Prüft eine Öffnungsautorisierung in Zeremonie B und im Reader.
///
/// Kopf und Sequenz müssen GENAU der gewählte Kopf und seine vorgeschlagene
/// Sequenz sein (Vorbild `verify_grant_authorization`, Ruling Q1); `now`
/// muss im Fenster liegen. Die Bytes müssen nicht im Katalog liegen.
///
/// Die Einmal-Nutzung sitzt NICHT hier: verbraucht wird über
/// [`consume_reader_key_escrow_recovery_authorization`].
///
/// # Errors
///
/// [`TrustError::Source`] für Bytes, die keine Öffnungsautorisierung sind,
/// oder ein Escrow, das nicht im Bestand liegt;
/// [`TrustError::ActionMismatch`] für fremde Organisation, fremden Kopf,
/// fremde Sequenz und jede Abweichung eines Zielfelds;
/// [`TrustError::AuthNotYetValid`] / [`TrustError::AuthExpired`];
/// [`TrustError::Signature`], wenn eine Signatur nicht trägt oder die
/// Totalordnung verletzt; [`TrustError::ApproversInsufficient`] für weniger
/// als zwei Personen; [`TrustError::EscrowInactive`] für ein Escrow, das im
/// gewählten Kopf nicht gültig ist; sowie jeden Befund des Bestands.
pub fn verify_reader_key_escrow_recovery_authorization(
    trust: &VerifiedTrust,
    head: &SelectedRegistryHead,
    exact_authorization_bytes: &[u8],
    now: UnixMillis,
) -> Result<VerifiedReaderKeyEscrowRecoveryAuthorization, TrustError> {
    verify_against_head(
        trust,
        head,
        exact_authorization_bytes,
        SequenceRule::Exact(head.proposed_sequence()),
        now,
    )
}

/// Dieselbe Regel für die Familien-Admission: die Sequenz liegt nur im
/// Lease des gewählten Kopfes, wie bei der Aufnahme einer
/// `grantAuthorization`.
pub(crate) fn verify_recovery_for_admission(
    trust: &VerifiedTrust,
    head: &SelectedRegistryHead,
    exact_authorization_bytes: &[u8],
    now: UnixMillis,
) -> Result<VerifiedReaderKeyEscrowRecoveryAuthorization, TrustError> {
    verify_against_head(
        trust,
        head,
        exact_authorization_bytes,
        SequenceRule::Lease,
        now,
    )
}

fn verify_against_head(
    trust: &VerifiedTrust,
    head: &SelectedRegistryHead,
    exact_authorization_bytes: &[u8],
    sequence: SequenceRule,
    now: UnixMillis,
) -> Result<VerifiedReaderKeyEscrowRecoveryAuthorization, TrustError> {
    let ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(exact_authorization_bytes)
            .map_err(|_| TrustError::Source)?
    else {
        return Err(TrustError::Source);
    };
    let DecodedTrustPayloadV1::ReaderKeyEscrowRecoveryAuthorization(fields) = parsed
        .value()
        .decoded_payload()
        .map_err(|_| TrustError::Source)?
    else {
        return Err(TrustError::Source);
    };
    let state = head.candidate_state();
    recovery_signers_rule(
        trust,
        state,
        parsed.value(),
        &fields,
        sequence,
        WindowRule::At(now),
    )?;
    let escrows = verify_reader_key_escrows(trust, ReaderKeyEscrowHead::Selected(head))?;
    let escrow = recovery_target_rule(&fields, &escrows, true)?.clone();
    Ok(VerifiedReaderKeyEscrowRecoveryAuthorization {
        inner: RecoveryInner {
            exact_bytes: exact_authorization_bytes.to_vec(),
            object_hash: parsed.object_hash(),
            replay_keys: AdminAuthorizationReplayKey::pair_from_verified_escrow_recovery(&fields),
            fields,
            escrow,
        },
    })
}

/// Verbraucht eine geprüfte Öffnungsautorisierung EIN Mal, organisationsweit
/// und laufübergreifend: beide Zeilen im bestehenden zweidimensionalen
/// Einmal-Speicher, `authorization-id` zuerst (Profil §6 Schritt 4).
///
/// # Errors
///
/// [`TrustError::AuthReplay`], wenn `authorization-id` ODER `nonce` schon
/// verbraucht ist — auch durch eine andere Familie desselben Namensraums.
/// Sonst jeden Befund der Ablage.
pub fn consume_reader_key_escrow_recovery_authorization(
    store: &mut dyn TrustStateStore,
    authorization: &VerifiedReaderKeyEscrowRecoveryAuthorization,
) -> Result<(), TrustError> {
    consume_replay_keys(store, authorization.replay_keys())
}

/// Organisation, Kopf, Sequenz, Fenster und Personen — alles, was die
/// Autorisierung selbst betrifft.
pub(crate) fn recovery_signers_rule(
    trust: &VerifiedTrust,
    state: &PreviousHeadState,
    object: &TrustObjectV1,
    fields: &ReaderKeyEscrowRecoveryAuthorizationCoreV1,
    sequence: SequenceRule,
    window: WindowRule,
) -> Result<(), TrustError> {
    if fields.organization_id != trust.organization_id()
        || fields.organization_id != state.root.fields.organization_id
    {
        return Err(TrustError::ActionMismatch);
    }
    if fields.registry_version != state.registry_version
        || fields.registry_head_hash != state.registry_head_hash
    {
        return Err(TrustError::ActionMismatch);
    }
    require_sequence(
        state,
        ChainSequence::new(fields.authorization_sequence),
        sequence,
    )?;
    require_window(fields.issued_at, fields.expires_at, window)?;
    require_total_order(object.signatures())?;
    let persons = distinct_authority_subjects(
        object.signatures(),
        object.exact_digest_input(),
        &PreviousHeadResolver::new(state),
        VerificationContext::reader_key_escrow_recovery_approval_trust_digest,
    )
    .map_err(|_| TrustError::Signature)?;
    if persons < REQUIRED_DISTINCT_ESCROW_RECOVERY_APPROVERS_V1 {
        return Err(TrustError::ApproversInsufficient);
    }
    Ok(())
}

/// Die bestehende Totalordnungs- und Duplikatsregel mehrfach signierter
/// Objekte: streng aufsteigend nach Zertifikatshash.
fn require_total_order(signatures: &[Vec<u8>]) -> Result<(), TrustError> {
    let mut previous = None;
    for signature in signatures {
        let certificate_hash = parse_cose_sign1(signature, &[])
            .map_err(|_| TrustError::Signature)?
            .certificate_hash()
            .ok_or(TrustError::Signature)?;
        if previous.is_some_and(|previous| previous >= certificate_hash) {
            return Err(TrustError::Signature);
        }
        previous = Some(certificate_hash);
    }
    Ok(())
}

/// Alle Zielfelder passen zu EINEM Escrow des Bestands. `require_valid`
/// verlangt, dass es im gewählten Kopf gültig ist (Ruling F4); in der
/// Historie ist ein später widerrufenes Escrow normale Vergangenheit.
pub(crate) fn recovery_target_rule<'s>(
    fields: &ReaderKeyEscrowRecoveryAuthorizationCoreV1,
    escrows: &'s VerifiedReaderKeyEscrowSet,
    require_valid: bool,
) -> Result<&'s VerifiedReaderKeyEscrow, TrustError> {
    let escrow = escrows
        .get(fields.escrow_object_hash)
        .ok_or(TrustError::Source)?;
    if require_valid && escrow.standing() != ReaderKeyEscrowStanding::Valid {
        return Err(TrustError::EscrowInactive);
    }
    let core = escrow.core();
    if fields.organization_id != core.organization_id
        || fields.reader_certificate_object_hash != core.reader_certificate_object_hash
        || fields.reader_subject_id != core.reader_subject_id
        || fields.enrollment_registry_version != core.enrollment_registry_version
        || fields.enrollment_registry_head_hash != core.enrollment_registry_head_hash
    {
        return Err(TrustError::ActionMismatch);
    }
    Ok(escrow)
}
