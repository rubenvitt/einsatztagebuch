//! Real immutable entries before and after an actual Recovery key rotation.
use super::support::verify_support::{
    self as fixture, archive_support::trust_support, historical::HistoricalFixture,
};
use ea_crypto::{CoseSigner, SecretBytes};
use ea_format::*;
use ea_schema::*;
use ea_types::*;

pub struct KemEpoch {
    pub old_certificate: CertificateHash,
    pub new_certificate: CertificateHash,
    pub entry_hash: EntryHash,
    pub entry_bytes: Vec<u8>,
    pub grant_bytes: Vec<u8>,
}

pub fn append_kem_epoch(
    f: &mut HistoricalFixture,
    mut writer_binding: ObjectHash,
    rotate_writer: bool,
    live_limits: Option<(i64, u64)>,
) -> KemEpoch {
    let selected = f.selected(1, 800, 800);
    let old_certificate = selected
        .active_certificates()
        .find(|(_, fields)| fields.certificate_kind == CertificateKindV1::RecoveryRecipient)
        .unwrap()
        .0;
    let mut writer = selected
        .active_certificates()
        .find(|(_, fields)| fields.certificate_kind == CertificateKindV1::Writer)
        .unwrap()
        .0;
    let (not_after, valid_through) = live_limits.unwrap_or((10_000, 100));
    let options = || trust_support::HeadOptions {
        effective_from: Some(1),
        valid_through: Some(valid_through),
        not_after: UnixMillis::new(not_after),
        ..Default::default()
    };
    f.line.push(
        trust_support::ActionSpec::Revoke {
            target_kind: 0,
            object_hash: ObjectHash::try_from(old_certificate.as_bytes().as_slice()).unwrap(),
        },
        options(),
    );
    let recipient = fixture::other_recipient_private_key();
    let public =
        ea_crypto::CanonicalPublicCoseKey::x25519(*recipient.public_key().as_bytes()).unwrap();
    assert!(public.thumbprint() != fixture::complete_recipient_key_thumbprint());
    f.head = f.line.push(
        trust_support::ActionSpec::Device {
            kind: CertificateKindV1::RecoveryRecipient,
            marker: 0x78,
            effective_from: Some(1),
        },
        trust_support::HeadOptions {
            kem_public_key_override: Some(public.clone()),
            ..options()
        },
    );
    let new_certificate = CertificateHash::from(f.head.direct_object_hash.unwrap());
    let signer = CoseSigner::from_secret(SecretBytes::new(if rotate_writer {
        [0x88; 32]
    } else {
        trust_support::device_signing_secret()
    }));
    let mut transition = None;
    if rotate_writer {
        let old_writer = writer;
        let new = f.line.push(
            trust_support::ActionSpec::Device {
                kind: CertificateKindV1::Writer,
                marker: 0x79,
                effective_from: Some(1),
            },
            trust_support::HeadOptions {
                signing_public_key_override: Some(signer.public_key().unwrap()),
                ..options()
            },
        );
        writer = CertificateHash::from(new.direct_object_hash.unwrap());
        let binding = f.line.push(
            trust_support::ActionSpec::OperatorBinding {
                certificate_hash: new.direct_object_hash.unwrap(),
                role: OperatorRoleV1::Writer,
                marker: 0x20,
                effective_from: Some(1),
            },
            trust_support::HeadOptions {
                binding_operator_profile_commitment_override: Some(
                    ea_crypto::operator_profile_commitment(
                        trust_support::organization(),
                        OperatorSubjectId::try_from(&[0x20; 16][..]).unwrap(),
                        "Erika Beispiel",
                        "Einsatzleitung",
                        &[0x30; 32],
                    ),
                ),
                ..options()
            },
        );
        writer_binding = binding.direct_object_hash.unwrap();
        f.head = f.line.push(
            trust_support::ActionSpec::WriterTransition {
                old_writer: ObjectHash::try_from(old_writer.as_bytes().as_slice()).unwrap(),
                new_writer: ObjectHash::try_from(writer.as_bytes().as_slice()).unwrap(),
                effective_from: Some(1),
            },
            trust_support::HeadOptions {
                writer_transition_previous_entry_hash: Some(f.entry_hash),
                ..options()
            },
        );
        transition = f.head.direct_object_hash;
        assert!(old_writer != writer);
    }
    let plan = fixture::complete_grant_plan_hash(public.thumbprint(), new_certificate);
    let mut record = [2; 16];
    record[6] = 0x70;
    record[8] = 0x80;
    let mut original = [1; 16];
    original[6] = 0x70;
    original[8] = 0x80;
    let header = CommonHeaderV1::new(
        RecordId::try_from(record.as_slice()).unwrap(),
        UnixMillis::new(0),
        "Europe/Berlin",
        OperatorSnapshotV1::new(
            trust_support::organization(),
            OperatorSubjectId::try_from(&[0x20; 16][..]).unwrap(),
            "Erika Beispiel",
            "Einsatzleitung",
            [0x30; 32],
            writer_binding,
        )
        .unwrap(),
        NativeSourceV1::new("recovery-fixture", 1).unwrap(),
        f.head.version,
    )
    .unwrap();
    let payload = encode_payload(&PayloadV1::Amendment(
        AmendmentV1::new(
            header,
            "1970-0001",
            RecordId::try_from(original.as_slice()).unwrap(),
            f.entry_hash,
            ChainSequence::new(0),
            "T9 separate schema epoch",
            vec![AmendmentChangeV1::new("keyword", "T9 corrected sample").unwrap()],
        )
        .unwrap(),
    ))
    .unwrap();
    let entry = fixture::build_complete_entry_signed_by(
        fixture::HeadRefV1::of(&f.head),
        writer,
        &signer,
        transition,
        f.anchor.chain_id(),
        plan,
        1,
        Some(f.entry_hash),
        &payload,
    );
    let entry_hash = entry.entry_hash();
    let entry_bytes = encode_entry_package(&entry).unwrap().into_vec();
    let grant_bytes = fixture::complete_grant_bytes_issued_by(
        fixture::HeadRefV1::of(&f.head),
        writer,
        signer.public_key().unwrap().thumbprint(),
        &signer,
        f.anchor.chain_id(),
        entry_hash,
        1,
        GrantPurposeV1::Recovery,
        public.thumbprint(),
        new_certificate,
        &recipient.public_key(),
    );
    KemEpoch {
        old_certificate,
        new_certificate,
        entry_hash,
        entry_bytes,
        grant_bytes,
    }
}
