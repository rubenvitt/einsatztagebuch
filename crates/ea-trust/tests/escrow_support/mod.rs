//! Registry-Linie und Objekte für die Zeugen des Reader-Key-Escrows.
//!
//! Additiv neben `support/mod.rs`: jenes Modul binden über zehn Pakete per
//! `#[path]` ein, und es darf keine Kante zu `ea-testkit` ziehen. Dieses hier
//! nutzt die Fixture-Bauer aus `ea_testkit::reader_key_escrow_fixture` — EINE
//! Kodierung — und wird nur von den Escrow-Zeugen eingebunden. Die native
//! Zeremonie kann es ebenso per `#[path]` einbinden.
//!
//! Die einbindende Testdatei MUSS `mod support;` und
//! `#[path = "../../ea-verify/src/state.rs"] mod state;` deklarieren.
#![allow(dead_code)]

use ea_crypto::{CanonicalPublicCoseKey, HpkeRecipientPrivateKey, SecretBytes, object_hash};
use ea_format::{
    CertificateKindV1, ReaderKeyEscrowApprovalCoreV1, ReaderKeyEscrowCoreV1,
    ReaderKeyEscrowRecoveryAuthorizationCoreV1,
};
use ea_testkit::reader_key_escrow_fixture::{
    FixtureTrustSigner, escrow_with_approval, seal_reader_kem_key_for_escrow,
    signed_reader_key_escrow_approval, signed_reader_key_escrow_recovery_authorization,
};
use ea_trust::{
    RegistrySelectionOutcome, SelectedRegistryHead, VerifiedTrust, decode_trust_anchor,
    load_trust_state, prepare_local_time, select_registry_head, verify_registry_candidate,
    verify_trust,
};
use ea_types::{
    AuthorizationId, CertificateHash, ChainSequence, Hash32, KeyThumbprint, ObjectHash,
    RegistryVersion, SubjectId, UnixMillis,
};

use crate::{
    state,
    support::{self, ActionSpec, BuiltHead, HeadOptions, RegistryLineBuilder},
};

pub const READER_KEM_SEED: [u8; 32] = [0xb1; 32];
pub const SECOND_READER_KEM_SEED: [u8; 32] = [0xb2; 32];
pub const RECOVERY_KEM_SEED: [u8; 32] = [0xb3; 32];
pub const TRANSPORT_KEM_SEED: [u8; 32] = [0xb4; 32];

/// Die Uhr der Kopfwahl. Liegt im Fenster jedes Fixture-Kopfes.
pub const SELECTION_NOW: UnixMillis = UnixMillis::new(800);

pub fn x25519_public(seed: [u8; 32]) -> [u8; 32] {
    *HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(seed))
        .unwrap()
        .public_key()
        .as_bytes()
}

pub fn x25519_key(seed: [u8; 32]) -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::x25519(x25519_public(seed)).unwrap()
}

pub fn certificate_of(object: ObjectHash) -> CertificateHash {
    CertificateHash::from(object)
}

pub fn hash32_of(object: ObjectHash) -> Hash32 {
    Hash32::try_from(object.as_bytes().as_slice()).unwrap()
}

pub fn subject(fill: u8) -> SubjectId {
    SubjectId::try_from([fill; 16].as_slice()).unwrap()
}

/// Der Registry-Zustand, in dem ein Reader-Zertifikat aktiv wurde.
#[derive(Clone, Copy)]
pub struct Enrollment {
    pub certificate: CertificateHash,
    pub version: RegistryVersion,
    pub head_hash: Hash32,
    pub sequence: ChainSequence,
    pub head: BuiltHead,
}

impl Enrollment {
    fn from_head(head: BuiltHead) -> Self {
        Self {
            certificate: certificate_of(head.direct_object_hash.unwrap()),
            version: head.version,
            head_hash: hash32_of(head.object_hash),
            sequence: head.effective_from,
            head,
        }
    }
}

/// Eine Linie mit Policy, Recovery-Empfänger, zwei Key Approvern und einem
/// Reader — in dieser Reihenfolge, damit der Recovery-Empfänger zum
/// Enrollment des Readers schon aktiv ist.
pub struct EscrowLine {
    pub line: RegistryLineBuilder,
    pub recovery: CertificateHash,
    pub approvers: Vec<CertificateHash>,
    pub reader: Enrollment,
}

#[derive(Clone, Copy, Default)]
pub struct EscrowLineOptions {
    /// Beide Key Approver tragen dasselbe Autoritätssubjekt: EINE Person
    /// unter zwei Zertifikaten.
    pub same_approver_person: bool,
    /// Der erste Key Approver trägt kein `historicalGrantApprove`.
    pub approver_without_capability: bool,
}

pub fn escrow_line(options: EscrowLineOptions) -> EscrowLine {
    let mut line = RegistryLineBuilder::new();
    push_filler(&mut line);
    let recovery = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::RecoveryRecipient,
            marker: 0x61,
            effective_from: None,
        },
        HeadOptions {
            kem_public_key_override: Some(x25519_key(RECOVERY_KEM_SEED)),
            ..HeadOptions::default()
        },
    );
    let mut approvers = Vec::new();
    for (index, marker) in [0x71_u8, 0x72].into_iter().enumerate() {
        let head = line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::KeyApprover,
                marker,
                effective_from: None,
            },
            HeadOptions {
                authority_subject_id_override: options.same_approver_person.then(|| subject(0x71)),
                certificate_capabilities_override: (options.approver_without_capability
                    && index == 0)
                    .then(Vec::new),
                ..HeadOptions::default()
            },
        );
        approvers.push(certificate_of(head.direct_object_hash.unwrap()));
    }
    let reader = push_reader(&mut line, 0x81, READER_KEM_SEED);
    EscrowLine {
        line,
        recovery: certificate_of(recovery.direct_object_hash.unwrap()),
        approvers,
        reader,
    }
}

/// Aktiviert ein weiteres Reader-Zertifikat mit eigenem KEM und eigener
/// Gerätekennung.
pub fn push_reader(line: &mut RegistryLineBuilder, marker: u8, kem_seed: [u8; 32]) -> Enrollment {
    Enrollment::from_head(line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Reader,
            marker,
            effective_from: None,
        },
        HeadOptions {
            kem_public_key_override: Some(x25519_key(kem_seed)),
            ..HeadOptions::default()
        },
    ))
}

/// Ein Kopf ohne Bezug zum Escrow: eine neue Policy-Version.
pub fn push_filler(line: &mut RegistryLineBuilder) -> BuiltHead {
    line.push(
        ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        HeadOptions::default(),
    )
}

/// Widerruft ein Nicht-Administrator-Zertifikat.
pub fn push_revocation(line: &mut RegistryLineBuilder, certificate: CertificateHash) -> BuiltHead {
    line.push(
        ActionSpec::Revoke {
            target_kind: 0,
            object_hash: ObjectHash::try_from(certificate.as_bytes().as_slice()).unwrap(),
        },
        HeadOptions::default(),
    )
}

/// Der zweite Bootstrap-Administrator: das einzige Administratorgeheimnis,
/// das `support` herausgibt.
pub fn admin(line: &RegistryLineBuilder) -> FixtureTrustSigner {
    FixtureTrustSigner {
        seed: support::second_admin_signing_secret(),
        certificate_hash: certificate_of(line.second_bootstrap_admin_hash()),
    }
}

pub fn root(line: &RegistryLineBuilder) -> FixtureTrustSigner {
    FixtureTrustSigner {
        seed: support::root_signing_secret(),
        certificate_hash: certificate_of(line.current_root_hash()),
    }
}

/// Ein Key Approver dieser Linie. Alle Gerätezertifikate der Linie tragen
/// denselben Signaturschlüssel (`support::device_signing_secret`).
pub fn approver(certificate: CertificateHash) -> FixtureTrustSigner {
    FixtureTrustSigner {
        seed: support::device_signing_secret(),
        certificate_hash: certificate,
    }
}

/// Der Kopf, gegen den eine Autorisierung gebunden wird.
#[derive(Clone, Copy)]
pub struct Basis {
    pub version: RegistryVersion,
    pub head_hash: Hash32,
    pub sequence: u64,
}

impl Basis {
    pub fn of(head: &BuiltHead, sequence: u64) -> Self {
        Self {
            version: head.version,
            head_hash: hash32_of(head.object_hash),
            sequence,
        }
    }

    pub fn of_selected(head: &SelectedRegistryHead) -> Self {
        Self {
            version: head.registry_version(),
            head_hash: hash32_of(head.registry_head_hash()),
            sequence: head.proposed_sequence().get(),
        }
    }
}

/// Die Freigabefelder ohne die drei Bindungsfelder, die
/// [`escrow_with_approval`] aus dem Core setzt.
pub fn approval_core(
    line: &RegistryLineBuilder,
    basis: Basis,
    window: (u64, u64),
    id: u8,
) -> ReaderKeyEscrowApprovalCoreV1 {
    ReaderKeyEscrowApprovalCoreV1 {
        authorization_id: AuthorizationId::try_from([id; 16].as_slice()).unwrap(),
        organization_id: support::organization(),
        registry_version: basis.version,
        registry_head_hash: basis.head_hash,
        authorization_sequence: basis.sequence,
        admin_key_thumbprint: support::device_signing_key(support::second_admin_signing_secret())
            .thumbprint(),
        admin_certificate_object_hash: certificate_of(line.second_bootstrap_admin_hash()),
        admin_operator_binding_object_hash: line.second_bootstrap_admin_binding_hash(),
        escrow_core_hash: Hash32::ZERO,
        reader_certificate_object_hash: CertificateHash::try_from([0; 32].as_slice()).unwrap(),
        reader_subject_id: subject(0),
        issued_at: millis(window.0),
        expires_at: millis(window.1),
        nonce: [id.wrapping_add(0x40); 32],
    }
}

pub fn signed_approval(
    line: &RegistryLineBuilder,
    core: &ReaderKeyEscrowApprovalCoreV1,
) -> Vec<u8> {
    signed_reader_key_escrow_approval(core, &admin(line))
}

/// Ein Escrow-Core mit echtem Chiffrat des Reader-KEM an den
/// Recovery-Empfänger.
pub fn escrow_core(
    escrow: &EscrowLine,
    enrollment: &Enrollment,
    reader_kem_seed: [u8; 32],
    reader_subject: SubjectId,
    issued_at: u64,
) -> ReaderKeyEscrowCoreV1 {
    let mut core = ReaderKeyEscrowCoreV1 {
        organization_id: support::organization(),
        reader_certificate_object_hash: enrollment.certificate,
        reader_subject_id: reader_subject,
        enrollment_registry_version: enrollment.version,
        enrollment_registry_head_hash: enrollment.head_hash,
        enrollment_sequence: enrollment.sequence,
        recovery_certificate_object_hash: escrow.recovery,
        recovery_kem_key_thumbprint: x25519_key(RECOVERY_KEM_SEED).thumbprint(),
        encapsulated_key: [0; 32],
        encrypted_reader_kem_key: [0; 48],
        issued_at: millis(issued_at),
        root_key_thumbprint: support::device_signing_key(support::root_signing_secret())
            .thumbprint(),
    };
    let (encapsulated_key, encrypted) = seal_reader_kem_key_for_escrow(
        &SecretBytes::new(reader_kem_seed),
        x25519_public(RECOVERY_KEM_SEED),
        &core,
    )
    .unwrap();
    core.encapsulated_key = encapsulated_key;
    core.encrypted_reader_kem_key = encrypted;
    core
}

/// Freigabe und Escrow, konsistent gebunden, beide im Katalog abgelegt.
/// Zurück kommen die Objekthashes `(freigabe, escrow)`.
pub fn publish_escrow(
    escrow: &mut EscrowLine,
    core: &ReaderKeyEscrowCoreV1,
    approval: &ReaderKeyEscrowApprovalCoreV1,
) -> (ObjectHash, ObjectHash) {
    let (approval_bytes, escrow_bytes) =
        escrow_with_approval(core, approval, &admin(&escrow.line), &root(&escrow.line));
    let hashes = (object_hash(&approval_bytes), object_hash(&escrow_bytes));
    escrow.line.add_object(approval_bytes);
    escrow.line.add_object(escrow_bytes);
    hashes
}

/// Die Bytes `(freigabe, escrow)` ohne Ablage im Katalog.
pub fn escrow_bytes(
    escrow: &EscrowLine,
    core: &ReaderKeyEscrowCoreV1,
    approval: &ReaderKeyEscrowApprovalCoreV1,
) -> (Vec<u8>, Vec<u8>) {
    escrow_with_approval(core, approval, &admin(&escrow.line), &root(&escrow.line))
}

pub fn recovery_core(
    escrow_object_hash: ObjectHash,
    escrow_core: &ReaderKeyEscrowCoreV1,
    basis: Basis,
    window: (u64, u64),
    id: u8,
) -> ReaderKeyEscrowRecoveryAuthorizationCoreV1 {
    ReaderKeyEscrowRecoveryAuthorizationCoreV1 {
        authorization_id: AuthorizationId::try_from([id; 16].as_slice()).unwrap(),
        organization_id: support::organization(),
        registry_version: basis.version,
        registry_head_hash: basis.head_hash,
        authorization_sequence: basis.sequence,
        escrow_object_hash,
        reader_certificate_object_hash: escrow_core.reader_certificate_object_hash,
        reader_subject_id: escrow_core.reader_subject_id,
        enrollment_registry_version: escrow_core.enrollment_registry_version,
        enrollment_registry_head_hash: escrow_core.enrollment_registry_head_hash,
        target_transport_key_thumbprint: transport_thumbprint(),
        issued_at: millis(window.0),
        expires_at: millis(window.1),
        nonce: [id.wrapping_add(0x40); 32],
    }
}

pub fn transport_thumbprint() -> KeyThumbprint {
    x25519_key(TRANSPORT_KEM_SEED).thumbprint()
}

pub fn signed_recovery(
    core: &ReaderKeyEscrowRecoveryAuthorizationCoreV1,
    approvers: &[CertificateHash],
) -> Vec<u8> {
    let signers: Vec<_> = approvers.iter().copied().map(approver).collect();
    signed_reader_key_escrow_recovery_authorization(core, &signers)
}

pub const fn millis(value: u64) -> UnixMillis {
    UnixMillis::new(value as i64)
}

/// Wählt den Kopf, dessen Lease `sequence` enthält, und gibt den
/// `VerifiedTrust` DESSELBEN Durchlaufs mit heraus.
pub fn select(line: &RegistryLineBuilder, sequence: u64) -> (VerifiedTrust, SelectedRegistryHead) {
    let anchor = decode_trust_anchor(line.exact_anchor_bytes()).unwrap();
    let key = state::verification_state_key(anchor.organization_id());
    let mut store = state::EphemeralTrustStateStore::new(key, SELECTION_NOW);
    let sequence = ChainSequence::new(sequence);
    loop {
        let snapshot = load_trust_state(&mut store, key).unwrap();
        let trust = verify_trust(&anchor, &line.source(), snapshot).unwrap();
        let candidate = verify_registry_candidate(&trust, sequence).unwrap();
        let time = prepare_local_time(&mut store, &candidate, SELECTION_NOW, &[]).unwrap();
        match select_registry_head(candidate, time, None).unwrap() {
            RegistrySelectionOutcome::Selected(head) => return (trust, head),
            RegistrySelectionOutcome::Advanced(_) => {}
            RegistrySelectionOutcome::PendingFuture(_) => panic!("unexpected future head"),
        }
    }
}

/// Die letzte Sequenz im Lease des letzten Kopfes der Linie.
pub fn tip_sequence(line: &RegistryLineBuilder) -> u64 {
    line.heads().last().unwrap().effective_from.get()
}
