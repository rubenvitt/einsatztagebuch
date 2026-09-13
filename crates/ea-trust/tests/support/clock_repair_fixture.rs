//! Shared exact Registry/Receipt fixture; no free authority or time proof.
#![allow(dead_code)]
use super::support::{self, ActionSpec, HeadOptions, Pin, RegistryLineBuilder};
use ea_crypto::{CanonicalPublicCoseKey, CoseSigner, SecretBytes, object_hash};
use ea_format::{CertificateKindV1, OperatorRoleV1};
use ea_time::TrustedTimeState;
use ea_trust::*;
use ea_types::*;
use ed25519_dalek::SigningKey;

pub const NAME: &str = "Clock fixture";
pub const FUNCTION: &str = "Administration";
pub const SALT: [u8; 32] = [0x35; 32];
pub const INSTANCE: [u8; 32] = [0x68; 32];
pub const NOW: i64 = 800;
pub const END: i64 = 10_000_000;
pub fn subject() -> OperatorSubjectId {
    OperatorSubjectId::try_from(&[0x42; 16][..]).unwrap()
}
pub fn device() -> DeviceId {
    DeviceId::try_from(&[0x52; 16][..]).unwrap()
}
pub fn instance_public() -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::ed25519(SigningKey::from_bytes(&INSTANCE).verifying_key().to_bytes())
        .unwrap()
}
pub fn account_hash() -> Hash32 {
    ea_crypto::linux_os_account_binding_hash(
        support::organization(),
        device(),
        b"1234567890abcdef1234567890abcdef\n",
        1000,
    )
    .unwrap()
}
pub fn signing_public() -> CanonicalPublicCoseKey {
    CoseSigner::from_secret(SecretBytes::new(support::second_admin_signing_secret()))
        .public_key()
        .unwrap()
}
pub struct Fixture {
    pub line: RegistryLineBuilder,
    pub authority: ClockRepairRegistryAuthority,
    pub certificate: CertificateHash,
    pub binding: ObjectHash,
}
pub fn fixture() -> Fixture {
    let mut line = RegistryLineBuilder::new();
    let options = || HeadOptions {
        not_after: UnixMillis::new(END),
        effective_from: Some(1),
        valid_through: Some(99),
        policy_max_registry_age_ms_override: Some(20_000_000),
        policy_max_future_clock_skew_ms_override: Some(50),
        ..HeadOptions::default()
    };
    line.push(
        ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        options(),
    );
    let server = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::ServerReceipt,
            marker: 0x66,
            effective_from: Some(1),
        },
        options(),
    );
    let certificate = CertificateHash::from(line.second_bootstrap_admin_hash());
    let binding = line.push(
        ActionSpec::OperatorBinding {
            certificate_hash: line.second_bootstrap_admin_hash(),
            role: OperatorRoleV1::OrganizationAdmin,
            marker: 0x42,
            effective_from: Some(1),
        },
        HeadOptions {
            binding_operator_profile_commitment_override: Some(
                ea_crypto::operator_profile_commitment(
                    support::organization(),
                    subject(),
                    NAME,
                    FUNCTION,
                    &SALT,
                ),
            ),
            binding_os_account_hash_override: Some(account_hash()),
            binding_instance_key_thumbprint_override: Some(instance_public().thumbprint()),
            ..options()
        },
    );
    let binding_hash = binding.direct_object_hash.unwrap();
    let key = TrustStateKey {
        organization_id: support::organization(),
        device_id: device(),
    };
    let mut store = Store {
        key,
        revision: 17,
        time: TrustedTimeState::initial(UnixMillis::new(700)),
        pin: RegistryHeadPin::new(binding.version, binding.object_hash),
    };
    let trust = line.verified_with_time_and_key(Pin::Head(2), store.time.clone(), key);
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(25)).unwrap();
    let signer = CoseSigner::from_secret(SecretBytes::new(support::device_signing_secret()));
    let core = ea_format::ReceiptCoreV1::new(ea_format::ReceiptCoreFieldsV1 {
        organization_id: key.organization_id,
        chain_id: trust.chain_id(),
        chain_sequence: ChainSequence::new(25),
        entry_hash: EntryHash::from(support::hash32(0x61)),
        entry_object_hash: object_hash(b"clock fixture original"),
        previous_entry_hash: Some(EntryHash::from(support::hash32(0x60))),
        registry_version: binding.version,
        registry_head_hash: Hash32::try_from(binding.object_hash.as_bytes().as_slice()).unwrap(),
        policy_object_hash: line.current_policy_hash().unwrap(),
        initial_grant_plan_hash: support::hash32(0x63),
        initial_grant_object_hashes: vec![object_hash(b"clock fixture grant")],
        accepted_at_server: UnixMillis::new(700),
        evidence_due_at: None,
        server_key_thumbprint: signer.public_key().unwrap().thumbprint(),
        server_certificate_hash: CertificateHash::from(server.direct_object_hash.unwrap()),
    })
    .unwrap();
    let signature = signer.sign_receipt(core.exact_bytes()).unwrap();
    let bytes =
        ea_format::encode_receipt(&ea_format::ReceiptV1::new(core, signature).unwrap()).unwrap();
    let ea_format::ParsedArchiveObject::Receipt(receipt) =
        ea_format::decode_exact_object(bytes.as_bytes()).unwrap()
    else {
        panic!()
    };
    let source = verify_receipt_time(candidate.preexisting_authority().unwrap(), &receipt).unwrap();
    let block =
        prepare_local_time(&mut store, &candidate, UnixMillis::new(NOW), &[source]).unwrap();
    let authority =
        verify_clock_repair_authority(&candidate, &block, certificate, binding_hash).unwrap();
    drop(block);
    Fixture {
        line,
        authority,
        certificate,
        binding: binding_hash,
    }
}
struct Store {
    key: TrustStateKey,
    revision: u64,
    time: TrustedTimeState,
    pin: RegistryHeadPin,
}
impl TrustStateStore for Store {
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        if self.key != key {
            return Err(StateStoreError::Conflict);
        }
        Ok(PersistedTrustRecord::new(
            self.revision,
            self.time.clone(),
            Some(self.pin),
        ))
    }
    fn commit_independent_time(
        &mut self,
        key: TrustStateKey,
        revision: u64,
        commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        if key != self.key || revision != self.revision {
            return Err(StateStoreError::Conflict);
        }
        self.revision += 1;
        self.time = commit.next_trusted_time().clone();
        self.load(key)
    }
    fn clock_release_consumed(
        &mut self,
        _: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        Ok(false)
    }
    fn commit_registry_selection(
        &mut self,
        _: TrustStateKey,
        _: u64,
        _: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }
}
