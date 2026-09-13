//! Real historical fixture: the Reader is enrolled after the immutable Entry.
use super::*;
use ea_crypto::{hpke_aad, hpke_info, hpke_seal};
use ea_format::{GrantAuthorizationFieldsV1, TrustObjectV1, TrustPayloadV1};
use ea_trust::{
    RegistrySelectionOutcome, SelectedRegistryHead, load_trust_state, prepare_local_time,
    select_registry_head, verify_registry_candidate, verify_trust,
};
use ea_types::AuthorizationId;

pub struct HistoricalFixture {
    pub fixture: ArchiveFixture,
    pub line: trust_support::RegistryLineBuilder,
    pub anchor: TrustAnchorV1,
    pub entry_hash: EntryHash,
    pub entry_bytes: Vec<u8>,
    pub original_bytes: Vec<u8>,
    pub recipient_certificate: Vec<u8>,
    pub recipient_certificate_hash: CertificateHash,
    pub operator_binding: ObjectHash,
    pub hga_certificate: CertificateHash,
    pub approvers: [CertificateHash; 2],
    pub head: trust_support::BuiltHead,
}
pub fn fixture(plaintext: &[u8]) -> HistoricalFixture {
    fixture_with_payload(|_, _| plaintext.to_vec())
}
pub fn fixture_with_payload(
    payload: impl FnOnce(RegistryVersion, ObjectHash) -> Vec<u8>,
) -> HistoricalFixture {
    fixture_with_host_options(payload, None)
}
pub struct HostOptions {
    pub not_after: i64,
    pub max_age: u64,
    pub instance: [u8; 32],
    pub account_hash: Hash32,
    pub commitment: Hash32,
}
pub fn fixture_with_host_options(
    payload: impl FnOnce(RegistryVersion, ObjectHash) -> Vec<u8>,
    host: Option<HostOptions>,
) -> HistoricalFixture {
    fixture_with_options(payload, host, None, None, true)
}
pub fn fixture_with_expired_original_head(
    payload: impl FnOnce(RegistryVersion, ObjectHash) -> Vec<u8>,
) -> HistoricalFixture {
    fixture_with_options(payload, None, Some(500), None, true)
}
pub fn fixture_with_writer_signer(plaintext: &[u8], signer: &CoseSigner) -> HistoricalFixture {
    fixture_with_options(|_, _| plaintext.to_vec(), None, None, Some(signer), true)
}
pub fn fixture_with_host_options_and_no_server(
    payload: impl FnOnce(RegistryVersion, ObjectHash) -> Vec<u8>,
    host: Option<HostOptions>,
) -> HistoricalFixture {
    fixture_with_options(payload, host, None, None, false)
}
fn fixture_with_options(
    payload: impl FnOnce(RegistryVersion, ObjectHash) -> Vec<u8>,
    host: Option<HostOptions>,
    original_not_after: Option<i64>,
    writer_signer: Option<&CoseSigner>,
    include_server: bool,
) -> HistoricalFixture {
    let usable_not_after = host.as_ref().map_or(10_000, |h| h.not_after);
    let mut line = trust_support::RegistryLineBuilder::new();
    let before = || trust_support::HeadOptions {
        effective_from: Some(0),
        valid_through: Some(0),
        not_after: UnixMillis::new(500),
        policy_max_registry_age_ms_override: host.as_ref().map(|h| h.max_age),
        ..Default::default()
    };
    line.push(policy_action(), before());
    let mut certificates = Vec::new();
    for (kind, marker) in [
        (CertificateKindV1::RecoveryRecipient, 0x51),
        (CertificateKindV1::HistoricalGrantAuthority, 0x52),
        (CertificateKindV1::KeyApprover, 0x53),
        (CertificateKindV1::KeyApprover, 0x54),
        (CertificateKindV1::Writer, 0x55),
        (CertificateKindV1::ServerReceipt, 0x57),
    ] {
        if kind == CertificateKindV1::ServerReceipt && !include_server {
            continue;
        }
        let head = line.push(
            trust_support::ActionSpec::Device {
                kind,
                marker,
                effective_from: Some(0),
            },
            trust_support::HeadOptions {
                not_after: UnixMillis::new(500),
                signing_public_key_override: if kind == CertificateKindV1::Writer {
                    writer_signer.map(|s| s.public_key().unwrap())
                } else {
                    None
                },
                kem_public_key_override: (kind == CertificateKindV1::RecoveryRecipient).then(
                    || {
                        ea_crypto::CanonicalPublicCoseKey::x25519(
                            *complete_recipient_private_key().public_key().as_bytes(),
                        )
                        .unwrap()
                    },
                ),
                ..before()
            },
        );
        certificates.push(CertificateHash::from(head.direct_object_hash.unwrap()));
    }
    let writer_head = line.push(
        trust_support::ActionSpec::OperatorBinding {
            certificate_hash: ObjectHash::try_from(certificates[4].as_bytes().as_slice()).unwrap(),
            role: ea_format::OperatorRoleV1::Writer,
            marker: 0x20,
            effective_from: Some(0),
        },
        trust_support::HeadOptions {
            binding_operator_profile_commitment_override: Some(
                ea_crypto::operator_profile_commitment(
                    trust_support::organization(),
                    ea_types::OperatorSubjectId::try_from(&[0x20; 16][..]).unwrap(),
                    "Erika Beispiel",
                    "Einsatzleitung",
                    &[0x30; 32],
                ),
            ),
            not_after: UnixMillis::new(original_not_after.unwrap_or(usable_not_after)),
            ..before()
        },
    );
    let plaintext = payload(writer_head.version, writer_head.direct_object_hash.unwrap());
    let anchor = decode_trust_anchor(line.exact_anchor_bytes()).unwrap();
    let plan = complete_grant_plan_hash(complete_recipient_key_thumbprint(), certificates[0]);
    let default_signer = writer_device_signer();
    let signer = writer_signer.unwrap_or(&default_signer);
    let entry = build_complete_entry_signed_by(
        HeadRefV1::of(&writer_head),
        certificates[4],
        signer,
        None,
        anchor.chain_id(),
        plan,
        0,
        None,
        &plaintext,
    );
    let entry_hash = entry.entry_hash();
    let entry_bytes = encode_entry_package(&entry).unwrap().into_vec();
    let original_bytes = complete_grant_bytes_issued_by(
        HeadRefV1::of(&writer_head),
        certificates[4],
        signer.public_key().unwrap().thumbprint(),
        signer,
        anchor.chain_id(),
        entry_hash,
        0,
        GrantPurposeV1::Recovery,
        complete_recipient_key_thumbprint(),
        certificates[0],
        &complete_recipient_private_key().public_key(),
    );
    let head = line.push(
        trust_support::ActionSpec::Device {
            kind: CertificateKindV1::Reader,
            marker: 0x56,
            effective_from: Some(1),
        },
        trust_support::HeadOptions {
            effective_from: Some(1),
            valid_through: Some(100),
            not_after: UnixMillis::new(usable_not_after),
            kem_public_key_override: Some(
                ea_crypto::CanonicalPublicCoseKey::x25519(
                    *other_recipient_private_key().public_key().as_bytes(),
                )
                .unwrap(),
            ),
            ..Default::default()
        },
    );
    let recipient_certificate = line
        .exact_object_bytes(head.direct_object_hash.unwrap())
        .to_vec();
    let recipient_certificate_hash = CertificateHash::from(head.direct_object_hash.unwrap());
    let admin_hash = line.second_bootstrap_admin_hash();
    let instance = ea_crypto::CoseSigner::from_secret(SecretBytes::new(
        host.as_ref().map_or([0x61; 32], |h| h.instance),
    ))
    .public_key()
    .unwrap();
    let head = line.push(
        trust_support::ActionSpec::OperatorBinding {
            certificate_hash: admin_hash,
            role: ea_format::OperatorRoleV1::OrganizationAdmin,
            marker: 0x42,
            effective_from: Some(1),
        },
        trust_support::HeadOptions {
            effective_from: Some(1),
            valid_through: Some(100),
            not_after: UnixMillis::new(usable_not_after),
            binding_operator_profile_commitment_override: host.as_ref().map(|h| h.commitment),
            binding_os_account_hash_override: host.as_ref().map(|h| h.account_hash),
            binding_instance_key_thumbprint_override: Some(instance.thumbprint()),
            ..Default::default()
        },
    );
    let operator_binding = head.direct_object_hash.unwrap();
    let mut fixture = ArchiveFixture::new();
    push_trust_objects(&mut fixture, &line);
    fixture.push_exact_bytes("entries/000000000000_entry.eip", entry_bytes.clone());
    fixture.push_exact_bytes("grants/000000000000_original.eag", original_bytes.clone());
    HistoricalFixture {
        fixture,
        line,
        anchor,
        entry_hash,
        entry_bytes,
        original_bytes,
        recipient_certificate,
        recipient_certificate_hash,
        operator_binding,
        hga_certificate: certificates[1],
        approvers: [certificates[2], certificates[3]],
        head,
    }
}
impl HistoricalFixture {
    pub fn authorization(&self, expires: i64) -> Vec<u8> {
        self.authorization_changed(expires, |_| {})
    }
    pub fn authorization_changed(
        &self,
        expires: i64,
        change: impl FnOnce(&mut GrantAuthorizationFieldsV1),
    ) -> Vec<u8> {
        let mut fields = GrantAuthorizationFieldsV1 {
            authorization_id: AuthorizationId::try_from(&[0x81; 16][..]).unwrap(),
            organization_id: self.anchor.organization_id(),
            registry_version: self.head.version,
            registry_head_hash: Hash32::try_from(self.head.object_hash.as_bytes().as_slice())
                .unwrap(),
            authorization_sequence: 1,
            entry_hashes: vec![self.entry_hash],
            recipient_key_thumbprint: other_recipient_key_thumbprint(),
            recipient_certificate_hash: self.recipient_certificate_hash,
            expires_at: UnixMillis::new(expires),
        };
        change(&mut fields);
        let payload = TrustPayloadV1::grant_authorization(fields).unwrap();
        let signer = trust_support::authorized_device_signer();
        let signatures = self
            .approvers
            .iter()
            .map(|cert| {
                signer
                    .sign_historical_grant_approval_digest(*cert, payload.exact_digest_input())
                    .unwrap()
            })
            .collect();
        ea_format::encode_trust(&TrustObjectV1::new(payload, signatures).unwrap())
            .unwrap()
            .into_vec()
    }
    pub fn selected(&self, sequence: u64, now: i64, floor: i64) -> SelectedRegistryHead {
        let key = ea_verify_state::verification_state_key(self.anchor.organization_id());
        let mut store = ea_verify_state::EphemeralTrustStateStore::new(key, UnixMillis::new(floor));
        loop {
            let snapshot = load_trust_state(&mut store, key).unwrap();
            let trust = verify_trust(&self.anchor, &self.line.source(), snapshot).unwrap();
            let candidate =
                verify_registry_candidate(&trust, ChainSequence::new(sequence)).unwrap();
            let candidate_version = candidate.registry_version();
            let time =
                prepare_local_time(&mut store, &candidate, UnixMillis::new(now), &[]).unwrap();
            match select_registry_head(candidate, time, None).unwrap() {
                RegistrySelectionOutcome::Selected(head)
                    if (sequence == 0
                        && candidate_version.get() == self.head.version.get() - 2)
                        || candidate_version == self.head.version =>
                {
                    return head;
                }
                RegistrySelectionOutcome::Selected(_) | RegistrySelectionOutcome::Advanced(_) => {}
                _ => panic!("unexpected future"),
            }
        }
    }
}
#[path = "../../src/state.rs"]
#[allow(dead_code)]
mod ea_verify_state;

pub fn with_grant(plaintext: &[u8], expires: i64) -> HistoricalFixture {
    install_grant(fixture(plaintext), expires)
}
pub fn install_grant(mut fixture: HistoricalFixture, expires: i64) -> HistoricalFixture {
    let authorization = fixture.authorization(expires);
    let signer = trust_support::authorized_device_signer();
    let fields = |encapsulated_key, wrapped_cek| GrantBodyFieldsV1 {
        organization_id: fixture.anchor.organization_id(),
        chain_id: fixture.anchor.chain_id(),
        entry_hash: fixture.entry_hash,
        kind: GrantKindV1::Historical,
        purpose: GrantPurposeV1::Reader,
        recipient_key_thumbprint: super::other_recipient_key_thumbprint(),
        recipient_certificate_hash: fixture.recipient_certificate_hash,
        issuer_key_thumbprint: trust_support::authorized_device_signing_key_thumbprint(),
        issuer_certificate_hash: fixture.hga_certificate,
        registry_version: fixture.head.version,
        registry_head_hash: Hash32::try_from(fixture.head.object_hash.as_bytes().as_slice())
            .unwrap(),
        created_at_device: UnixMillis::new(800),
        original_recovery_grant_object_hash: Some(object_hash(&fixture.original_bytes)),
        grant_authorization_object_hash: Some(object_hash(&authorization)),
        encapsulated_key,
        wrapped_cek,
    };
    let draft = GrantBodyV1::new(fields([0; 32], [0; 48])).unwrap();
    let context = draft.exact_grant_context().unwrap();
    // The fixture CEK for sequence zero is [0x3c; 32].
    let sealed = hpke_seal(
        &super::other_recipient_private_key().public_key(),
        &SecretBytes::new([0x3c; 32]),
        &hpke_info(context),
        &hpke_aad(context),
    )
    .unwrap();
    let body = GrantBodyV1::new(fields(*sealed.encapsulated_key(), *sealed.wrapped_cek())).unwrap();
    let signature = signer.sign_historical_grant(body.exact_bytes()).unwrap();
    let grant = encode_grant(&GrantV1::new(body, signature).unwrap()).unwrap();
    fixture
        .fixture
        .push_exact_bytes("trust/grant-authorization.etb", authorization);
    fixture.fixture.push_object("grants/historical.eag", grant);
    fixture
}

pub fn signed_receipt(f: &HistoricalFixture, at: i64) -> Vec<u8> {
    use ea_format::{DecodedTrustPayloadV1, ParsedArchiveObject, decode_exact_object};
    let ParsedArchiveObject::Entry(e) = decode_exact_object(&f.entry_bytes).unwrap() else {
        panic!()
    };
    let m = e.value().manifest().fields();
    let inv = ea_archive::ArchiveInventory::build(&f.fixture).unwrap();
    let cert = inv
        .trust()
        .iter()
        .find_map(|p| match p.value().decoded_payload().unwrap() {
            DecodedTrustPayloadV1::AuthorizedDevice(fields)
                if fields.fields().certificate_kind == CertificateKindV1::ServerReceipt =>
            {
                Some(CertificateHash::from(p.object_hash()))
            }
            _ => None,
        })
        .unwrap();
    let head = inv
        .trust()
        .iter()
        .find(|p| p.object_hash().as_bytes() == &m.registry_head_hash)
        .unwrap();
    let DecodedTrustPayloadV1::RegistryEvent(event) = head.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    let core = ReceiptCoreV1::new(ReceiptCoreFieldsV1 {
        organization_id: f.anchor.organization_id(),
        chain_id: m.chain_id,
        chain_sequence: m.chain_sequence,
        entry_hash: f.entry_hash,
        entry_object_hash: object_hash(&f.entry_bytes),
        previous_entry_hash: m.previous_entry_hash,
        registry_version: m.registry_version,
        registry_head_hash: Hash32::try_from(m.registry_head_hash.as_slice()).unwrap(),
        policy_object_hash: event.fields().policy_object_hash,
        initial_grant_plan_hash: Hash32::try_from(m.initial_grant_plan_hash.as_slice()).unwrap(),
        initial_grant_object_hashes: vec![object_hash(&f.original_bytes)],
        accepted_at_server: UnixMillis::new(at),
        evidence_due_at: None,
        server_key_thumbprint: trust_support::authorized_device_signing_key_thumbprint(),
        server_certificate_hash: cert,
    })
    .unwrap();
    let sig = trust_support::authorized_device_signer()
        .sign_receipt(core.exact_bytes())
        .unwrap();
    encode_receipt(&ReceiptV1::new(core, sig).unwrap())
        .unwrap()
        .into_vec()
}
