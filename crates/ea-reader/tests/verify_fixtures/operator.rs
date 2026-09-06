//! Signed Reader archives whose payload operator is backed by an activated binding.
//! Fixture construction uses the production schema, format and crypto codecs.

use ea_archive::ArchiveInventory;
use ea_crypto::{SecretBytes, SecretVec, aead_seal, object_hash, operator_profile_digest};
use ea_format::{
    CertificateKindV1, EntryPackageV1, GrantBodyFieldsV1, GrantBodyV1, GrantKindV1,
    GrantPlanItemV1, GrantPlanV1, GrantPurposeV1, GrantV1, ManifestCoreFieldsV1, ManifestCoreV1,
    OperatorRoleV1, SignedManifestV1, encode_entry_package, encode_grant,
};
use ea_trust::TrustObjectSource;
use ea_types::{CertificateHash, ChainSequence, Hash32, ObjectHash, UnixMillis};
use minicbor::{Decoder, Encoder};

use super::verify_support::archive_support::trust_support::{
    self, ActionSpec, HeadOptions, RegistryLineBuilder,
};
use super::verify_support::{self, CompleteArchive, archive_support::ArchiveFixture};

#[derive(Clone, Copy, Debug, Default)]
pub enum Defect {
    #[default]
    None,
    Salt,
    Name,
    Function,
    Subject,
    Organization,
    UnknownBinding,
    BorrowedBinding,
    ReaderBinding,
    HeaderRegistry,
    ManifestHead,
    NotYetEffective,
    RevokedAtEntry,
    LaterRevocation,
}

const NAME: &str = "Erika Beispiel";
const FUNCTION: &str = "Einsatzleitung";
const SUBJECT: [u8; 16] = [0x20; 16];
const SALT: [u8; 32] = [0x30; 32];

/// Profile shared by the signed binding and its encoded payload snapshots.
/// The registry fixture represents subjects as sixteen copies of one marker.
#[derive(Clone, Copy)]
pub struct Profile<'a> {
    pub subject_marker: u8,
    pub display_name: &'a str,
    pub function_label: &'a str,
    pub salt: [u8; 32],
}

impl Default for Profile<'_> {
    fn default() -> Self {
        Self {
            subject_marker: SUBJECT[0],
            display_name: NAME,
            function_label: FUNCTION,
            salt: SALT,
        }
    }
}

/// An independent fixture encoding of the five specification inputs. The
/// production Reader must use the shared ea-crypto field helper instead.
fn commitment(profile: Profile<'_>) -> Hash32 {
    let mut e = Encoder::new(Vec::new());
    e.array(5)
        .unwrap()
        .bytes(trust_support::organization().as_bytes())
        .unwrap()
        .bytes(&[profile.subject_marker; 16])
        .unwrap()
        .str(profile.display_name)
        .unwrap()
        .str(profile.function_label)
        .unwrap()
        .bytes(&profile.salt)
        .unwrap();
    operator_profile_digest(&e.into_writer())
}

fn options(not_after: i64) -> HeadOptions {
    HeadOptions {
        effective_from: Some(0),
        valid_through: Some(100),
        not_after: UnixMillis::new(not_after),
        ..HeadOptions::default()
    }
}

pub fn archive(plaintexts: &[&[u8]], defect: Defect) -> CompleteArchive {
    archive_with_payloads(plaintexts, defect).0
}

pub fn archive_with_payloads(
    plaintexts: &[&[u8]],
    defect: Defect,
) -> (CompleteArchive, Vec<Vec<u8>>) {
    archive_with_profile(plaintexts, defect, Profile::default())
}

/// Builds and activates a real binding for the supplied profile, returning
/// the exact bound plaintexts that were encrypted into the archive. This lets
/// privacy fixtures retain their own name/function markers and salt/subject.
pub fn archive_with_profile(
    plaintexts: &[&[u8]],
    defect: Defect,
    profile: Profile<'_>,
) -> (CompleteArchive, Vec<Vec<u8>>) {
    let mut line = RegistryLineBuilder::new();
    let chain_id = ea_trust::decode_trust_anchor(line.exact_anchor_bytes())
        .unwrap()
        .chain_id();
    line.push(
        ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: Some(0),
        },
        options(500),
    );
    let writer_head = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x11,
            effective_from: Some(0),
        },
        options(if matches!(defect, Defect::NotYetEffective) {
            10_000
        } else {
            600
        }),
    );
    let writer = writer_head.direct_object_hash.unwrap();
    let binding_certificate = if matches!(defect, Defect::ReaderBinding) {
        line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::Reader,
                marker: 0x12,
                effective_from: Some(0),
            },
            options(650),
        )
        .direct_object_hash
        .unwrap()
    } else {
        writer
    };
    let borrowed = matches!(defect, Defect::BorrowedBinding);
    let binding_head = line.push(
        ActionSpec::OperatorBinding {
            certificate_hash: binding_certificate,
            role: if matches!(defect, Defect::ReaderBinding) {
                OperatorRoleV1::Reader
            } else {
                OperatorRoleV1::Writer
            },
            marker: profile.subject_marker,
            effective_from: Some(if matches!(defect, Defect::NotYetEffective) {
                1
            } else {
                0
            }),
        },
        HeadOptions {
            binding_operator_profile_commitment_override: Some(commitment(profile)),
            effective_from: Some(if matches!(defect, Defect::NotYetEffective) {
                1
            } else {
                0
            }),
            revoked_from_sequence: matches!(defect, Defect::RevokedAtEntry)
                .then_some(ChainSequence::new(1)),
            ..options(if borrowed { 700 } else { 10_000 })
        },
    );
    let own_binding = binding_head.direct_object_hash.unwrap();
    let (head, binding) = if borrowed {
        let h = line.push(
            ActionSpec::OperatorBinding {
                certificate_hash: writer,
                role: OperatorRoleV1::Writer,
                marker: profile.subject_marker.wrapping_add(1),
                effective_from: Some(0),
            },
            HeadOptions {
                // A valid Root signature does not excuse a commitment belonging to
                // another subject. This catches a digest-only identity check.
                binding_operator_profile_commitment_override: Some(commitment(profile)),
                ..options(10_000)
            },
        );
        (h, h.direct_object_hash.unwrap())
    } else if matches!(defect, Defect::NotYetEffective) {
        (writer_head, own_binding)
    } else {
        (binding_head, own_binding)
    };
    if matches!(defect, Defect::LaterRevocation) {
        line.push(
            ActionSpec::Revoke {
                target_kind: 1,
                object_hash: own_binding,
            },
            HeadOptions {
                effective_from: Some(50),
                ..options(10_000)
            },
        );
    }
    let mut fixture = ArchiveFixture::new();
    let source = line.source();
    source
        .visit_trust_object_hashes(&mut |hash| {
            fixture.push_exact_bytes(
                &format!("trust/{}.etb", hex::encode(hash.as_bytes())),
                source.read_exact_trust_object(hash)?.unwrap().to_vec(),
            );
            Ok(())
        })
        .unwrap();
    let recipient = verify_support::complete_recipient_key_thumbprint();
    let recipient_certificate = verify_support::complete_recipient_certificate_hash();
    let plan = GrantPlanV1::new(vec![GrantPlanItemV1::new(
        recipient,
        recipient_certificate,
        GrantPurposeV1::Recovery,
    )])
    .unwrap();
    let mut previous = None;
    let mut entry_object_hashes = Vec::new();
    let mut grant_object_hashes = Vec::new();
    let mut bound_plaintexts = Vec::new();
    for (index, plaintext) in plaintexts.iter().enumerate() {
        let sequence = u64::try_from(index).unwrap();
        let plaintext =
            bound_plaintext_with_profile(plaintext, binding, head.version.get(), defect, profile);
        bound_plaintexts.push(plaintext.clone());
        let mut cek_bytes = [0x3c; 32];
        cek_bytes[..8].copy_from_slice(&sequence.to_be_bytes());
        let cek = SecretBytes::new(cek_bytes);
        let mut nonce = [0x5e; 12];
        nonce[..8].copy_from_slice(&sequence.to_be_bytes());
        let manifest_fields = ManifestCoreFieldsV1 {
            organization_id: trust_support::organization(),
            chain_id,
            chain_sequence: ChainSequence::new(sequence),
            previous_entry_hash: previous,
            writer_certificate_hash: CertificateHash::from(writer),
            writer_transition_event_hash: None,
            registry_version: head.version,
            registry_head_hash: if matches!(defect, Defect::ManifestHead) {
                [0x99; 32]
            } else {
                *head.object_hash.as_bytes()
            },
            initial_grant_plan_hash: *plan.hash().as_bytes(),
            nonce,
        };
        let manifest = ManifestCoreV1::new(
            manifest_fields,
            &vec![0; plaintext.len() + ea_crypto::AEAD_OVERHEAD],
        )
        .unwrap();
        let ciphertext = aead_seal(
            &cek,
            &SecretBytes::new(nonce),
            SecretVec::new(plaintext),
            &ea_crypto::payload_aad(manifest.exact_bytes()),
        )
        .unwrap();
        let signed = SignedManifestV1::new(manifest, &ciphertext).unwrap();
        let signature = verify_support::writer_device_signer()
            .sign_record(signed.exact_bytes())
            .unwrap();
        let entry = EntryPackageV1::new(signed, ciphertext, signature).unwrap();
        let entry_bytes = encode_entry_package(&entry).unwrap().into_vec();
        entry_object_hashes.push(object_hash(&entry_bytes));
        fixture.push_exact_bytes(&format!("entries/{index}.eip"), entry_bytes);
        let fields = |encapsulated_key, wrapped_cek| GrantBodyFieldsV1 {
            organization_id: trust_support::organization(),
            chain_id,
            entry_hash: entry.entry_hash(),
            kind: GrantKindV1::Initial,
            purpose: GrantPurposeV1::Recovery,
            recipient_key_thumbprint: recipient,
            recipient_certificate_hash: recipient_certificate,
            issuer_key_thumbprint: verify_support::writer_device_key_thumbprint(),
            issuer_certificate_hash: CertificateHash::from(writer),
            registry_version: head.version,
            registry_head_hash: Hash32::try_from(head.object_hash.as_bytes().as_slice()).unwrap(),
            created_at_device: UnixMillis::new(verify_support::FIXTURE_OS_WALL_CLOCK_V1),
            original_recovery_grant_object_hash: None,
            grant_authorization_object_hash: None,
            encapsulated_key,
            wrapped_cek,
        };
        let draft = GrantBodyV1::new(fields([0; 32], [0; 48])).unwrap();
        let context = draft.exact_grant_context().unwrap();
        let sealed = ea_crypto::hpke_seal(
            &verify_support::complete_recipient_private_key().public_key(),
            &cek,
            &ea_crypto::hpke_info(context),
            &ea_crypto::hpke_aad(context),
        )
        .unwrap();
        let body =
            GrantBodyV1::new(fields(*sealed.encapsulated_key(), *sealed.wrapped_cek())).unwrap();
        let signature = verify_support::writer_device_signer()
            .sign_initial_grant(body.exact_bytes())
            .unwrap();
        let bytes = encode_grant(&GrantV1::new(body, signature).unwrap())
            .unwrap()
            .into_vec();
        grant_object_hashes.push(object_hash(&bytes));
        fixture.push_exact_bytes(&format!("grants/{index}.eag"), bytes);
        previous = Some(entry.entry_hash());
    }
    (
        CompleteArchive {
            fixture,
            anchor_bytes: line.exact_anchor_bytes().to_vec(),
            entry_object_hashes,
            grant_object_hashes,
        },
        bound_plaintexts,
    )
}

/// Replaces only the operator and registry-version slots of a schema-valid
/// fixture. Other bytes, including amendment references, remain unchanged.
pub fn bound_plaintext(
    bytes: &[u8],
    binding: ObjectHash,
    registry_version: u64,
    defect: Defect,
) -> Vec<u8> {
    bound_plaintext_with_profile(bytes, binding, registry_version, defect, Profile::default())
}

fn bound_plaintext_with_profile(
    bytes: &[u8],
    binding: ObjectHash,
    registry_version: u64,
    defect: Defect,
    profile: Profile<'_>,
) -> Vec<u8> {
    let schemas = ea_schema::SchemaRegistry::v1();
    if !schemas.schemas().iter().any(|s| {
        schemas
            .validate(s.schema_id(), s.schema_version(), bytes)
            .is_ok()
    }) {
        return bytes.to_vec();
    }
    let mut d = Decoder::new(bytes);
    assert_eq!(d.array().unwrap(), Some(11));
    for _ in 0..6 {
        d.skip().unwrap();
    }
    let operator_start = d.position();
    d.skip().unwrap();
    let operator_end = d.position();
    d.skip().unwrap();
    let registry_start = d.position();
    d.skip().unwrap();
    let registry_end = d.position();
    let mut operator = Encoder::new(Vec::new());
    let organization = if matches!(defect, Defect::Organization) {
        [0x99; 16]
    } else {
        *trust_support::organization().as_bytes()
    };
    operator
        .array(6)
        .unwrap()
        .bytes(&organization)
        .unwrap()
        .bytes(&if matches!(defect, Defect::Subject) {
            [profile.subject_marker.wrapping_add(1); 16]
        } else {
            [profile.subject_marker; 16]
        })
        .unwrap()
        .str(if matches!(defect, Defect::Name) {
            "Mallory CANARY"
        } else {
            profile.display_name
        })
        .unwrap()
        .str(if matches!(defect, Defect::Function) {
            "Fremde Funktion CANARY"
        } else {
            profile.function_label
        })
        .unwrap()
        .bytes(&if matches!(defect, Defect::Salt) {
            profile.salt.map(|byte| byte.wrapping_add(1))
        } else {
            profile.salt
        })
        .unwrap()
        .bytes(if matches!(defect, Defect::UnknownBinding) {
            &[0x99; 32]
        } else {
            binding.as_bytes()
        })
        .unwrap();
    let mut out = bytes[..operator_start].to_vec();
    out.extend(operator.into_writer());
    out.extend_from_slice(&bytes[operator_end..registry_start]);
    Encoder::new(&mut out)
        .u64(if matches!(defect, Defect::HeaderRegistry) {
            registry_version + 1
        } else {
            registry_version
        })
        .unwrap();
    out.extend_from_slice(&bytes[registry_end..]);
    let mut genesis = Decoder::new(&out);
    genesis.array().unwrap();
    if genesis.str().unwrap() == "genesis" {
        for _ in 1..10 {
            genesis.skip().unwrap();
        }
        genesis.array().unwrap();
        assert_eq!(genesis.bytes().unwrap().len(), 16);
        let end = genesis.position();
        out[end - 16..end].copy_from_slice(&organization);
    }
    assert!(schemas.schemas().iter().any(|s| {
        schemas
            .validate(s.schema_id(), s.schema_version(), &out)
            .is_ok()
    }));
    out
}

pub fn genesis_plaintext() -> Vec<u8> {
    hex::decode(include_str!("../../../../vectors/format/payload-v1/genesis.hex").trim()).unwrap()
}

pub fn entry_hash(source: &ArchiveFixture) -> ea_types::EntryHash {
    ArchiveInventory::build(source)
        .unwrap()
        .entries()
        .iter()
        .max_by_key(|entry| entry.value().manifest().fields().chain_sequence)
        .unwrap()
        .value()
        .entry_hash()
}
