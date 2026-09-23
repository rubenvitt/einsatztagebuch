//! Die drei Trust-Familien des Reader-Key-Escrows und ihre HPKE-Kontexte.
//!
//! Vertrag: `docs/superpowers/specs/2026-09-08-einsatzarchiv-reader-key-escrow-profile.md`
//! §3 (Gestalt) und §4 (Kontexte), Grammatik in `schemas/archive/v1/trust.cddl`.
//! Alle drei Familien sind DIREKTE Familien nach dem Vorbild der
//! Bundle-Freigabe: kein zulässiges `target-trust-subtype`, kein Arm in
//! `registry-change-v1`, kein Gegenstand des Registrierungsabschlusses.
//!
//! Dieses Modul ist reiner Codec. Es prüft Syntax und Feldrelationen, die
//! ohne Registry entscheidbar sind (Arität, Längen, Version, `purpose`,
//! Höchstdauer). Signaturen, Freigabebindung, Enrollment-Bindung und
//! Eindeutigkeit prüft der Trust-Kern.
//!
//! Die Feldreihenfolge aller Kerne und Kontexte ist mit den Vektoren unter
//! `vectors/reader-key-escrow/v1/`, `vectors/reader-key-escrow-approval/v1/`
//! und `vectors/reader-key-escrow-recovery/v1/` EINGEFROREN.

use ea_crypto::{
    READER_KEY_ESCROW_APPROVAL_MAX_LIFETIME_MS,
    READER_KEY_ESCROW_RECOVERY_AUTHORIZATION_MAX_LIFETIME_MS,
    reader_key_escrow_lifetime_is_admissible,
};
use ea_types::{
    AuthorizationId, CertificateHash, ChainSequence, Hash32, KeyThumbprint, ObjectHash,
    OrganizationId, RegistryVersion, SubjectId, UnixMillis,
};
use minicbor::{Decoder, Encoder};

use crate::{
    FormatError,
    etb::{decode_authorized_parts, expect_version, typed_bytes},
    object::{bytes_exact, expect_array_length, expect_empty_array, finish},
};

/// Das Suite-Literal im HPKE-Kontext der Escrow-Kapselung (Profil §4).
///
/// Ein CBOR-Feld des Kontexts, keine Hash-Domäne: `info` und AAD entstehen in
/// der Hausform `hpke_info(cbor)`/`hpke_aad(cbor)`. Eingefroren in der
/// Vektorfamilie `reader-key-escrow/v1` (Ruling R1b).
pub const READER_KEY_ESCROW_SUITE_ID: &str = "EINSATZARCHIV-READER-KEY-ESCROW-1";

/// Das Suite-Literal im HPKE-Kontext der Öffnungsantwort (Profil §4).
pub const READER_KEY_ESCROW_RESTORE_SUITE_ID: &str = "EINSATZARCHIV-READER-KEY-ESCROW-RESTORE-1";

/// Der einzige Operationscode der Öffnung: Ersatz aller verlorenen
/// Reader-Authenticators. Ein breiterer Code existiert nicht.
const RECOVERY_PURPOSE_REPLACE_LOST_AUTHENTICATORS: u64 = 0;

/// Der Kern eines Escrows, `reader-key-escrow-core-v1` (14 Positionen).
///
/// `reader_subject_id` ist die Person, an die das Escrow das
/// Reader-Zertifikat bindet (Profil §1.1). Sie ist ausdrücklich NICHT die
/// `authoritySubjectId` eines Signiererzertifikats: dieselbe Typgestalt
/// (`SubjectId`, 16 Byte), aber ein anderer Begriff, und kein Prüfweg darf die
/// beiden gegeneinander tauschen.
#[derive(Clone, Eq, PartialEq)]
pub struct ReaderKeyEscrowCoreV1 {
    pub organization_id: OrganizationId,
    pub reader_certificate_object_hash: CertificateHash,
    pub reader_subject_id: SubjectId,
    pub enrollment_registry_version: RegistryVersion,
    pub enrollment_registry_head_hash: Hash32,
    pub enrollment_sequence: ChainSequence,
    pub recovery_certificate_object_hash: CertificateHash,
    pub recovery_kem_key_thumbprint: KeyThumbprint,
    /// Der HPKE-Kapselungswert, 32 Byte.
    pub encapsulated_key: [u8; 32],
    /// Der versiegelte Reader-KEM-Schlüssel: 32 Byte Schlüssel plus 16 Byte
    /// AEAD-Tag.
    pub encrypted_reader_kem_key: [u8; 48],
    pub issued_at: UnixMillis,
    pub root_key_thumbprint: KeyThumbprint,
}

/// Die dekodierte Escrow-Nutzlast `[core, approval-object-hash]`.
///
/// Bewusst NICHT [`crate::AuthorizedTrustCoreV1`]: dessen
/// `authorization_object_hash()` gäbe den Freigabehash als
/// Admin-Autorisierung aus. Das zweite Element nennt die Publikationsfreigabe
/// dieses Profils.
#[derive(Clone, Eq, PartialEq)]
pub struct ReaderKeyEscrowPayloadV1 {
    core: ReaderKeyEscrowCoreV1,
    approval_object_hash: ObjectHash,
    exact_core: Vec<u8>,
}

impl ReaderKeyEscrowPayloadV1 {
    #[must_use]
    pub const fn core(&self) -> &ReaderKeyEscrowCoreV1 {
        &self.core
    }

    /// Der Objekthash der Publikationsfreigabe, die dieses Escrow bindet.
    #[must_use]
    pub const fn approval_object_hash(&self) -> ObjectHash {
        self.approval_object_hash
    }

    /// Die EXAKTEN Bytes des Cores, wie sie in der Nutzlast stehen.
    ///
    /// Urbild von `escrow-core-hash`. Bei der Prüfung wird nie reserialisiert
    /// (Profil §4).
    #[must_use]
    pub fn exact_core(&self) -> &[u8] {
        &self.exact_core
    }
}

/// Der Kern der Publikationsfreigabe, `reader-key-escrow-approval-core-v1`
/// (16 Positionen).
#[derive(Clone, Eq, PartialEq)]
pub struct ReaderKeyEscrowApprovalCoreV1 {
    pub authorization_id: AuthorizationId,
    pub organization_id: OrganizationId,
    pub registry_version: RegistryVersion,
    pub registry_head_hash: Hash32,
    pub authorization_sequence: u64,
    pub admin_key_thumbprint: KeyThumbprint,
    pub admin_certificate_object_hash: CertificateHash,
    pub admin_operator_binding_object_hash: ObjectHash,
    /// Der Hash über den exakten Escrow-Core, nicht über die Nutzlast.
    pub escrow_core_hash: Hash32,
    pub reader_certificate_object_hash: CertificateHash,
    /// Siehe [`ReaderKeyEscrowCoreV1::reader_subject_id`].
    pub reader_subject_id: SubjectId,
    pub issued_at: UnixMillis,
    pub expires_at: UnixMillis,
    pub nonce: [u8; 32],
}

/// Der Kern der Öffnungsautorisierung,
/// `reader-key-escrow-recovery-authorization-core-v1` (17 Positionen).
///
/// `purpose` trägt kein Feld: der einzige zulässige Wert `0` wird beim
/// Kodieren geschrieben und beim Dekodieren verlangt.
#[derive(Clone, Eq, PartialEq)]
pub struct ReaderKeyEscrowRecoveryAuthorizationCoreV1 {
    pub authorization_id: AuthorizationId,
    pub organization_id: OrganizationId,
    pub registry_version: RegistryVersion,
    pub registry_head_hash: Hash32,
    pub authorization_sequence: u64,
    pub escrow_object_hash: ObjectHash,
    pub reader_certificate_object_hash: CertificateHash,
    /// Siehe [`ReaderKeyEscrowCoreV1::reader_subject_id`].
    pub reader_subject_id: SubjectId,
    pub enrollment_registry_version: RegistryVersion,
    pub enrollment_registry_head_hash: Hash32,
    pub target_transport_key_thumbprint: KeyThumbprint,
    pub issued_at: UnixMillis,
    pub expires_at: UnixMillis,
    pub nonce: [u8; 32],
}

/// Der HPKE-Kontext der Escrow-Kapselung, `reader-key-escrow-hpke-context-v1`.
///
/// Er wird NICHT übertragen, sondern aus dem geprüften Core abgeleitet
/// ([`Self::from_escrow_core`]) und als `hpke_info(encode())` und
/// `hpke_aad(encode())` verwendet. `enrollment-sequence` steht im Core, nicht
/// im Kontext — so will es das Profil (§4), und der Core ist wurzelsigniert.
#[derive(Clone, Eq, PartialEq)]
pub struct ReaderKeyEscrowHpkeContextV1 {
    pub organization_id: OrganizationId,
    pub reader_certificate_object_hash: CertificateHash,
    pub reader_subject_id: SubjectId,
    pub enrollment_registry_version: RegistryVersion,
    pub enrollment_registry_head_hash: Hash32,
    pub recovery_certificate_object_hash: CertificateHash,
    pub recovery_kem_key_thumbprint: KeyThumbprint,
}

impl ReaderKeyEscrowHpkeContextV1 {
    /// Die sieben Kontextfelder aus dem Core.
    #[must_use]
    pub fn from_escrow_core(core: &ReaderKeyEscrowCoreV1) -> Self {
        Self {
            organization_id: core.organization_id,
            reader_certificate_object_hash: core.reader_certificate_object_hash,
            reader_subject_id: core.reader_subject_id,
            enrollment_registry_version: core.enrollment_registry_version,
            enrollment_registry_head_hash: core.enrollment_registry_head_hash,
            recovery_certificate_object_hash: core.recovery_certificate_object_hash,
            recovery_kem_key_thumbprint: core.recovery_kem_key_thumbprint,
        }
    }

    /// Das deterministische CBOR: sieben Felder hinter der Version, das
    /// Suite-Literal und der leere Extension-Slot.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut exact = Vec::with_capacity(256);
        Encoder::new(&mut exact)
            .array(10)
            .and_then(|encoder| encoder.u8(1))
            .and_then(|encoder| encoder.bytes(self.organization_id.as_bytes()))
            .and_then(|encoder| encoder.bytes(self.reader_certificate_object_hash.as_bytes()))
            .and_then(|encoder| encoder.bytes(self.reader_subject_id.as_bytes()))
            .and_then(|encoder| encoder.u64(self.enrollment_registry_version.get()))
            .and_then(|encoder| encoder.bytes(self.enrollment_registry_head_hash.as_bytes()))
            .and_then(|encoder| encoder.bytes(self.recovery_certificate_object_hash.as_bytes()))
            .and_then(|encoder| encoder.bytes(self.recovery_kem_key_thumbprint.as_bytes()))
            .and_then(|encoder| encoder.str(READER_KEY_ESCROW_SUITE_ID))
            .and_then(|encoder| encoder.array(0))
            .expect("encoding a fixed context into a vector cannot fail");
        exact
    }
}

/// Der HPKE-Kontext der Öffnungsantwort, `reader-key-escrow-restore-context-v1`.
///
/// Abgeleitet aus der geprüften Öffnungsautorisierung und ihrem Objekthash
/// ([`Self::from_recovery_authorization`]).
#[derive(Clone, Eq, PartialEq)]
pub struct ReaderKeyEscrowRestoreContextV1 {
    pub organization_id: OrganizationId,
    pub authorization_object_hash: ObjectHash,
    pub escrow_object_hash: ObjectHash,
    pub reader_certificate_object_hash: CertificateHash,
    pub reader_subject_id: SubjectId,
    pub target_transport_key_thumbprint: KeyThumbprint,
}

impl ReaderKeyEscrowRestoreContextV1 {
    /// Die sechs Kontextfelder aus der Autorisierung und ihrem Objekthash.
    #[must_use]
    pub fn from_recovery_authorization(
        core: &ReaderKeyEscrowRecoveryAuthorizationCoreV1,
        authorization_object_hash: ObjectHash,
    ) -> Self {
        Self {
            organization_id: core.organization_id,
            authorization_object_hash,
            escrow_object_hash: core.escrow_object_hash,
            reader_certificate_object_hash: core.reader_certificate_object_hash,
            reader_subject_id: core.reader_subject_id,
            target_transport_key_thumbprint: core.target_transport_key_thumbprint,
        }
    }

    /// Das deterministische CBOR: sechs Felder hinter der Version, das
    /// Suite-Literal und der leere Extension-Slot.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut exact = Vec::with_capacity(256);
        Encoder::new(&mut exact)
            .array(9)
            .and_then(|encoder| encoder.u8(1))
            .and_then(|encoder| encoder.bytes(self.organization_id.as_bytes()))
            .and_then(|encoder| encoder.bytes(self.authorization_object_hash.as_bytes()))
            .and_then(|encoder| encoder.bytes(self.escrow_object_hash.as_bytes()))
            .and_then(|encoder| encoder.bytes(self.reader_certificate_object_hash.as_bytes()))
            .and_then(|encoder| encoder.bytes(self.reader_subject_id.as_bytes()))
            .and_then(|encoder| encoder.bytes(self.target_transport_key_thumbprint.as_bytes()))
            .and_then(|encoder| encoder.str(READER_KEY_ESCROW_RESTORE_SUITE_ID))
            .and_then(|encoder| encoder.array(0))
            .expect("encoding a fixed context into a vector cannot fail");
        exact
    }
}

fn lifetime(issued: i64, expires: i64, max: i64) -> Result<(), FormatError> {
    if reader_key_escrow_lifetime_is_admissible(issued, expires, max) {
        Ok(())
    } else {
        Err(FormatError::Shape)
    }
}

pub(crate) fn encode_reader_key_escrow_core(
    core: &ReaderKeyEscrowCoreV1,
) -> Result<Vec<u8>, FormatError> {
    let mut exact = Vec::with_capacity(384);
    Encoder::new(&mut exact)
        .array(14)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(core.organization_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(core.reader_certificate_object_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(core.reader_subject_id.as_bytes()))
        .and_then(|encoder| encoder.u64(core.enrollment_registry_version.get()))
        .and_then(|encoder| encoder.bytes(core.enrollment_registry_head_hash.as_bytes()))
        .and_then(|encoder| encoder.u64(core.enrollment_sequence.get()))
        .and_then(|encoder| encoder.bytes(core.recovery_certificate_object_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(core.recovery_kem_key_thumbprint.as_bytes()))
        .and_then(|encoder| encoder.bytes(&core.encapsulated_key))
        .and_then(|encoder| encoder.bytes(&core.encrypted_reader_kem_key))
        .and_then(|encoder| encoder.i64(core.issued_at.get()))
        .and_then(|encoder| encoder.bytes(core.root_key_thumbprint.as_bytes()))
        .and_then(|encoder| encoder.array(0))
        .map_err(|_| FormatError::Shape)?;
    Ok(exact)
}

/// Die Nutzlast `[core, approval-object-hash]` um den EXAKTEN Core.
pub(crate) fn encode_reader_key_escrow_payload(
    exact_core: &[u8],
    approval_object_hash: ObjectHash,
) -> Result<Vec<u8>, FormatError> {
    let mut exact = Vec::with_capacity(exact_core.len().saturating_add(40));
    Encoder::new(&mut exact)
        .array(2)
        .map_err(|_| FormatError::Shape)?;
    exact.extend_from_slice(exact_core);
    Encoder::new(&mut exact)
        .bytes(approval_object_hash.as_bytes())
        .map_err(|_| FormatError::Shape)?;
    Ok(exact)
}

pub(crate) fn encode_reader_key_escrow_approval(
    core: &ReaderKeyEscrowApprovalCoreV1,
) -> Result<Vec<u8>, FormatError> {
    lifetime(
        core.issued_at.get(),
        core.expires_at.get(),
        READER_KEY_ESCROW_APPROVAL_MAX_LIFETIME_MS,
    )?;
    let mut exact = Vec::with_capacity(512);
    Encoder::new(&mut exact)
        .array(16)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(core.authorization_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(core.organization_id.as_bytes()))
        .and_then(|encoder| encoder.u64(core.registry_version.get()))
        .and_then(|encoder| encoder.bytes(core.registry_head_hash.as_bytes()))
        .and_then(|encoder| encoder.u64(core.authorization_sequence))
        .and_then(|encoder| encoder.bytes(core.admin_key_thumbprint.as_bytes()))
        .and_then(|encoder| encoder.bytes(core.admin_certificate_object_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(core.admin_operator_binding_object_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(core.escrow_core_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(core.reader_certificate_object_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(core.reader_subject_id.as_bytes()))
        .and_then(|encoder| encoder.i64(core.issued_at.get()))
        .and_then(|encoder| encoder.i64(core.expires_at.get()))
        .and_then(|encoder| encoder.bytes(&core.nonce))
        .and_then(|encoder| encoder.array(0))
        .map_err(|_| FormatError::Shape)?;
    Ok(exact)
}

pub(crate) fn encode_reader_key_escrow_recovery_authorization(
    core: &ReaderKeyEscrowRecoveryAuthorizationCoreV1,
) -> Result<Vec<u8>, FormatError> {
    lifetime(
        core.issued_at.get(),
        core.expires_at.get(),
        READER_KEY_ESCROW_RECOVERY_AUTHORIZATION_MAX_LIFETIME_MS,
    )?;
    let mut exact = Vec::with_capacity(512);
    Encoder::new(&mut exact)
        .array(17)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(core.authorization_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(core.organization_id.as_bytes()))
        .and_then(|encoder| encoder.u64(core.registry_version.get()))
        .and_then(|encoder| encoder.bytes(core.registry_head_hash.as_bytes()))
        .and_then(|encoder| encoder.u64(core.authorization_sequence))
        .and_then(|encoder| encoder.bytes(core.escrow_object_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(core.reader_certificate_object_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(core.reader_subject_id.as_bytes()))
        .and_then(|encoder| encoder.u64(core.enrollment_registry_version.get()))
        .and_then(|encoder| encoder.bytes(core.enrollment_registry_head_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(core.target_transport_key_thumbprint.as_bytes()))
        .and_then(|encoder| encoder.u64(RECOVERY_PURPOSE_REPLACE_LOST_AUTHENTICATORS))
        .and_then(|encoder| encoder.i64(core.issued_at.get()))
        .and_then(|encoder| encoder.i64(core.expires_at.get()))
        .and_then(|encoder| encoder.bytes(&core.nonce))
        .and_then(|encoder| encoder.array(0))
        .map_err(|_| FormatError::Shape)?;
    Ok(exact)
}

pub(crate) fn decode_reader_key_escrow_core(
    input: &[u8],
) -> Result<ReaderKeyEscrowCoreV1, FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 14)?;
    expect_version(&mut decoder)?;
    let organization_id = typed_bytes(&mut decoder, 16)?;
    let reader_certificate_object_hash = typed_bytes(&mut decoder, 32)?;
    let reader_subject_id = typed_bytes(&mut decoder, 16)?;
    let enrollment_registry_version =
        RegistryVersion::new(decoder.u64().map_err(|_| FormatError::Shape)?);
    let enrollment_registry_head_hash = typed_bytes(&mut decoder, 32)?;
    let enrollment_sequence = ChainSequence::new(decoder.u64().map_err(|_| FormatError::Shape)?);
    let recovery_certificate_object_hash = typed_bytes(&mut decoder, 32)?;
    let recovery_kem_key_thumbprint = typed_bytes(&mut decoder, 32)?;
    let encapsulated_key = fixed_bytes(&mut decoder)?;
    let encrypted_reader_kem_key = fixed_bytes(&mut decoder)?;
    let issued_at = UnixMillis::new(decoder.i64().map_err(|_| FormatError::Shape)?);
    let root_key_thumbprint = typed_bytes(&mut decoder, 32)?;
    expect_empty_array(&mut decoder)?;
    finish(&decoder, input)?;
    Ok(ReaderKeyEscrowCoreV1 {
        organization_id,
        reader_certificate_object_hash,
        reader_subject_id,
        enrollment_registry_version,
        enrollment_registry_head_hash,
        enrollment_sequence,
        recovery_certificate_object_hash,
        recovery_kem_key_thumbprint,
        encapsulated_key,
        encrypted_reader_kem_key,
        issued_at,
        root_key_thumbprint,
    })
}

/// Die Nutzlast `[core, approval-object-hash]`. Die Zweiergestalt teilt sie
/// mit `authorized-trust-payload-v1`, deshalb trägt derselbe Zerleger — die
/// BEDEUTUNG des zweiten Elements ist eine andere.
pub(crate) fn decode_reader_key_escrow_payload(
    input: &[u8],
) -> Result<ReaderKeyEscrowPayloadV1, FormatError> {
    let parts = decode_authorized_parts(input)?;
    let core = decode_reader_key_escrow_core(parts.exact_core)?;
    Ok(ReaderKeyEscrowPayloadV1 {
        core,
        approval_object_hash: parts.authorization_object_hash,
        exact_core: parts.exact_core.to_vec(),
    })
}

pub(crate) fn decode_reader_key_escrow_approval(
    input: &[u8],
) -> Result<ReaderKeyEscrowApprovalCoreV1, FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 16)?;
    expect_version(&mut decoder)?;
    let authorization_id = typed_bytes(&mut decoder, 16)?;
    let organization_id = typed_bytes(&mut decoder, 16)?;
    let registry_version = RegistryVersion::new(decoder.u64().map_err(|_| FormatError::Shape)?);
    let registry_head_hash = typed_bytes(&mut decoder, 32)?;
    let authorization_sequence = decoder.u64().map_err(|_| FormatError::Shape)?;
    let admin_key_thumbprint = typed_bytes(&mut decoder, 32)?;
    let admin_certificate_object_hash = typed_bytes(&mut decoder, 32)?;
    let admin_operator_binding_object_hash = typed_bytes(&mut decoder, 32)?;
    let escrow_core_hash = typed_bytes(&mut decoder, 32)?;
    let reader_certificate_object_hash = typed_bytes(&mut decoder, 32)?;
    let reader_subject_id = typed_bytes(&mut decoder, 16)?;
    let issued = decoder.i64().map_err(|_| FormatError::Shape)?;
    let expires = decoder.i64().map_err(|_| FormatError::Shape)?;
    lifetime(issued, expires, READER_KEY_ESCROW_APPROVAL_MAX_LIFETIME_MS)?;
    let nonce = fixed_bytes(&mut decoder)?;
    expect_empty_array(&mut decoder)?;
    finish(&decoder, input)?;
    Ok(ReaderKeyEscrowApprovalCoreV1 {
        authorization_id,
        organization_id,
        registry_version,
        registry_head_hash,
        authorization_sequence,
        admin_key_thumbprint,
        admin_certificate_object_hash,
        admin_operator_binding_object_hash,
        escrow_core_hash,
        reader_certificate_object_hash,
        reader_subject_id,
        issued_at: UnixMillis::new(issued),
        expires_at: UnixMillis::new(expires),
        nonce,
    })
}

pub(crate) fn decode_reader_key_escrow_recovery_authorization(
    input: &[u8],
) -> Result<ReaderKeyEscrowRecoveryAuthorizationCoreV1, FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 17)?;
    expect_version(&mut decoder)?;
    let authorization_id = typed_bytes(&mut decoder, 16)?;
    let organization_id = typed_bytes(&mut decoder, 16)?;
    let registry_version = RegistryVersion::new(decoder.u64().map_err(|_| FormatError::Shape)?);
    let registry_head_hash = typed_bytes(&mut decoder, 32)?;
    let authorization_sequence = decoder.u64().map_err(|_| FormatError::Shape)?;
    let escrow_object_hash = typed_bytes(&mut decoder, 32)?;
    let reader_certificate_object_hash = typed_bytes(&mut decoder, 32)?;
    let reader_subject_id = typed_bytes(&mut decoder, 16)?;
    let enrollment_registry_version =
        RegistryVersion::new(decoder.u64().map_err(|_| FormatError::Shape)?);
    let enrollment_registry_head_hash = typed_bytes(&mut decoder, 32)?;
    let target_transport_key_thumbprint = typed_bytes(&mut decoder, 32)?;
    // Analog zum Grant-Zweck: ein unbekannter Operationscode ist ein
    // Etikettenfehler, keine Gestaltfrage.
    if decoder.u64().map_err(|_| FormatError::Shape)?
        != RECOVERY_PURPOSE_REPLACE_LOST_AUTHENTICATORS
    {
        return Err(FormatError::TagMismatch);
    }
    let issued = decoder.i64().map_err(|_| FormatError::Shape)?;
    let expires = decoder.i64().map_err(|_| FormatError::Shape)?;
    lifetime(
        issued,
        expires,
        READER_KEY_ESCROW_RECOVERY_AUTHORIZATION_MAX_LIFETIME_MS,
    )?;
    let nonce = fixed_bytes(&mut decoder)?;
    expect_empty_array(&mut decoder)?;
    finish(&decoder, input)?;
    Ok(ReaderKeyEscrowRecoveryAuthorizationCoreV1 {
        authorization_id,
        organization_id,
        registry_version,
        registry_head_hash,
        authorization_sequence,
        escrow_object_hash,
        reader_certificate_object_hash,
        reader_subject_id,
        enrollment_registry_version,
        enrollment_registry_head_hash,
        target_transport_key_thumbprint,
        issued_at: UnixMillis::new(issued),
        expires_at: UnixMillis::new(expires),
        nonce,
    })
}

fn fixed_bytes<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], FormatError> {
    bytes_exact(decoder, N)?
        .try_into()
        .map_err(|_| FormatError::Shape)
}
