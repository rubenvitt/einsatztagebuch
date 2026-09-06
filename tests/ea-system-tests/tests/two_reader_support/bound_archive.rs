//! Adds distinct recipients to the Reader's signed, activated operator fixture.
//! Only the grant plan changes: the payload and its authenticated registry line
//! retain the canonical operator profile commitment used by the real Reader.

use std::sync::OnceLock;

use ea_archive::ArchiveInventory;
use ea_crypto::{SecretBytes, SecretVec, aead_seal, hpke_aad, hpke_info, hpke_seal, object_hash};
use ea_format::{
    EntryPackageV1, GrantBodyFieldsV1, GrantBodyV1, GrantKindV1, GrantPlanItemV1, GrantPlanV1,
    GrantV1, ManifestCoreV1, SignedManifestV1, encode_entry_package, encode_grant,
};
use ea_types::Hash32;

use super::operator_fixture::{self, Defect};
use super::verify_support::{
    self, CompleteArchive, PlannedRecipientV1, archive_support::ArchiveFixture,
};

fn profile_fixture() -> &'static (CompleteArchive, Vec<Vec<u8>>) {
    static FIXTURE: OnceLock<(CompleteArchive, Vec<Vec<u8>>)> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        operator_fixture::archive_with_payloads(
            &[&operator_fixture::genesis_plaintext()],
            Defect::None,
        )
    })
}

pub(super) fn genesis_plaintext() -> &'static [u8] {
    &profile_fixture().1[0]
}

pub(super) fn for_recipients(recipients: &[PlannedRecipientV1]) -> CompleteArchive {
    let base = &profile_fixture().0;
    let plaintext = genesis_plaintext();
    let inventory = ArchiveInventory::build(&base.fixture).unwrap();
    assert_eq!(inventory.entries().len(), 1);
    let plan = GrantPlanV1::new(
        recipients
            .iter()
            .map(|recipient| {
                GrantPlanItemV1::new(
                    recipient.key_thumbprint,
                    recipient.certificate_hash,
                    recipient.purpose,
                )
            })
            .collect(),
    )
    .unwrap();
    let mut fields = inventory.entries()[0].value().manifest().fields().clone();
    fields.initial_grant_plan_hash = *plan.hash().as_bytes();
    // Public, deterministic test material. Separate plans use separate nonces;
    // neither this key nor the fixture represents production secret storage.
    let cek = SecretBytes::new([0x6c; 32]);
    fields.nonce.copy_from_slice(&plan.hash().as_bytes()[..12]);
    let manifest = ManifestCoreV1::new(
        fields.clone(),
        &vec![0; plaintext.len() + ea_crypto::AEAD_OVERHEAD],
    )
    .unwrap();
    let ciphertext = aead_seal(
        &cek,
        &SecretBytes::new(fields.nonce),
        SecretVec::new(plaintext.to_vec()),
        &ea_crypto::payload_aad(manifest.exact_bytes()),
    )
    .unwrap();
    let signed = SignedManifestV1::new(manifest, &ciphertext).unwrap();
    let signature = verify_support::writer_device_signer()
        .sign_record(signed.exact_bytes())
        .unwrap();
    let entry = EntryPackageV1::new(signed, ciphertext, signature).unwrap();
    let entry_bytes = encode_entry_package(&entry).unwrap().into_vec();
    let entry_object_hashes = vec![object_hash(&entry_bytes)];

    let mut fixture = ArchiveFixture::new();
    // Keep the exact trust objects (including the activated operator binding),
    // replacing the base fixture's entry and single-recipient grant entirely.
    for (path_hint, bytes) in base.fixture.blobs() {
        let hash = object_hash(bytes);
        if !base.entry_object_hashes.contains(&hash) && !base.grant_object_hashes.contains(&hash) {
            fixture.push_exact_bytes(path_hint, bytes.clone());
        }
    }
    fixture.push_exact_bytes("entries/0.eip", entry_bytes);
    let mut grant_object_hashes = Vec::new();
    for (index, recipient) in recipients.iter().enumerate() {
        let grant_fields = |encapsulated_key, wrapped_cek| GrantBodyFieldsV1 {
            organization_id: fields.organization_id,
            chain_id: fields.chain_id,
            entry_hash: entry.entry_hash(),
            kind: GrantKindV1::Initial,
            purpose: recipient.purpose,
            recipient_key_thumbprint: recipient.key_thumbprint,
            recipient_certificate_hash: recipient.certificate_hash,
            issuer_key_thumbprint: verify_support::writer_device_key_thumbprint(),
            issuer_certificate_hash: fields.writer_certificate_hash,
            registry_version: fields.registry_version,
            registry_head_hash: Hash32::try_from(fields.registry_head_hash.as_slice()).unwrap(),
            created_at_device: super::OS_WALL_CLOCK,
            original_recovery_grant_object_hash: None,
            grant_authorization_object_hash: None,
            encapsulated_key,
            wrapped_cek,
        };
        let draft = GrantBodyV1::new(grant_fields([0; 32], [0; 48])).unwrap();
        let context = draft.exact_grant_context().unwrap();
        let sealed = hpke_seal(
            &recipient.public_key,
            &cek,
            &hpke_info(context),
            &hpke_aad(context),
        )
        .unwrap();
        let body = GrantBodyV1::new(grant_fields(
            *sealed.encapsulated_key(),
            *sealed.wrapped_cek(),
        ))
        .unwrap();
        let signature = verify_support::writer_device_signer()
            .sign_initial_grant(body.exact_bytes())
            .unwrap();
        let bytes = encode_grant(&GrantV1::new(body, signature).unwrap())
            .unwrap()
            .into_vec();
        grant_object_hashes.push(object_hash(&bytes));
        fixture.push_exact_bytes(&format!("grants/{index}.eag"), bytes);
    }
    CompleteArchive {
        fixture,
        anchor_bytes: base.anchor_bytes.clone(),
        entry_object_hashes,
        grant_object_hashes,
    }
}
