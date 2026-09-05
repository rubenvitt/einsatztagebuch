//! Lifecycle contracts at simulated native ports, with real trust selection
//! and Ed25519 presence verification on every host (including macOS).
//!
//! Sharing the existing test module keeps its registry/store/signing fixtures
//! in one place within the owned files. Its session tests also run in this target.

#[path = "session_contract.rs"]
mod session_contract;

use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

use ea_crypto::{
    CanonicalPublicCoseKey, CoseSigner, SecretBytes, authorized_trust_digest, object_hash,
};
use ea_format::{
    CertificateKindV1, OperatorBindingFieldsV1, OperatorRoleV1,
    OrganizationAdminAuthorizationFieldsV1, RegistryChangeV1, TrustObjectV1, TrustPayloadV1,
    TrustSubtypeV1, encode_trust,
};
use ea_operator::{
    BoundOperator, OperatorAuthenticator, OperatorError, OperatorSessionProof, OsAccountInputs,
    OsAccountProvider, ReauthPurpose, verify_current_session,
};
use ea_trust::SelectedRegistryHead;
use ea_types::{
    AuthorizationId, CertificateHash, ChainSequence, DeviceId, Hash32, ObjectHash,
    OperatorSubjectId, OrganizationId, UnixMillis,
};
use session_contract::{
    INSTANCE_SECRET, OTHER_INSTANCE_SECRET,
    fixtures::{self, FakeAuthenticator},
    support::{self, ActionSpec, ChangeOverride, HeadOptions, RegistryLineBuilder},
};

fn fresh_proof(head: &SelectedRegistryHead, purpose: ReauthPurpose) -> OperatorSessionProof {
    FakeAuthenticator::new(fixtures::binding(head))
        .reauthenticate(fixtures::valid_account(), purpose)
        .unwrap()
}

fn verify(
    head: &SelectedRegistryHead,
    proof: &OperatorSessionProof,
    account: &dyn OsAccountProvider,
) -> Result<(), OperatorError> {
    verify_current_session(
        head,
        CertificateHash::from(fixtures::writer_certificate_object_hash()),
        OperatorRoleV1::Writer,
        proof,
        ReauthPurpose::Finalize,
        account,
    )
}

#[test]
fn current_session_requires_the_expected_role_and_device_certificate() {
    let head = fixtures::selected_registry_head();
    let proof = fresh_proof(&head, ReauthPurpose::Finalize);
    let account = fixtures::valid_account();
    assert!(verify(&head, &proof, account.as_ref()).is_ok());

    for wrong_role in [OperatorRoleV1::Reader, OperatorRoleV1::OrganizationAdmin] {
        assert_eq!(
            verify_current_session(
                &head,
                CertificateHash::from(fixtures::writer_certificate_object_hash()),
                wrong_role,
                &proof,
                ReauthPurpose::Finalize,
                account.as_ref(),
            )
            .unwrap_err()
            .code(),
            "EA-OPERATOR-ROLE-MISMATCH"
        );
    }

    // Another real, active certificate of this very registry.
    let (line, _, _) = fixtures::build_line();
    let other_certificate = CertificateHash::from(line.bootstrap_admin_hash());
    assert!(head.active_certificate_fields(other_certificate).is_some());
    assert_eq!(
        verify_current_session(
            &head,
            other_certificate,
            OperatorRoleV1::Writer,
            &proof,
            ReauthPurpose::Finalize,
            account.as_ref(),
        )
        .unwrap_err()
        .code(),
        "EA-OPERATOR-DEVICE-MISMATCH"
    );
}

#[test]
fn each_signed_purpose_is_accepted_only_for_that_purpose() {
    let head = fixtures::selected_registry_head();
    let account = fixtures::valid_account();
    for signed_purpose in ReauthPurpose::ALL {
        let proof = fresh_proof(&head, signed_purpose);
        for expected_purpose in ReauthPurpose::ALL {
            let result = verify_current_session(
                &head,
                CertificateHash::from(fixtures::writer_certificate_object_hash()),
                OperatorRoleV1::Writer,
                &proof,
                expected_purpose,
                account.as_ref(),
            );
            if signed_purpose == expected_purpose {
                assert!(result.is_ok(), "{}", signed_purpose.label());
            } else {
                assert_eq!(result.unwrap_err().code(), "EA-OPERATOR-PROOF-MISMATCH");
            }
        }
    }
}

#[test]
fn verification_does_not_extend_expiry_and_rejects_future_and_locked_proofs() {
    let head = fixtures::selected_registry_head();
    let proof = fresh_proof(&head, ReauthPurpose::Finalize);
    let account = fixtures::valid_account();
    for (delta_ms, accepted) in [
        (-1, false),
        (0, true),
        (299_999, true),
        (300_000, false),
        (300_001, false),
    ] {
        let current = fixtures::selected_registry_head_at(fixtures::FIXTURE_NOW_MS + delta_ms);
        let result = verify(&current, &proof, account.as_ref());
        if accepted {
            assert!(result.is_ok(), "delta={delta_ms}");
        } else {
            assert_eq!(result.unwrap_err().code(), "EA-OPERATOR-PROOF-MISMATCH");
        }
    }
    let locked = proof.invalidate_on_lock();
    assert_eq!(
        verify(&head, &locked, account.as_ref()).unwrap_err().code(),
        "EA-OPERATOR-PROOF-MISMATCH"
    );
}

#[test]
fn an_already_signed_proof_does_not_replace_current_account_and_key_checks() {
    let head = fixtures::selected_registry_head();
    let proof = fresh_proof(&head, ReauthPurpose::Finalize);
    for (account, expected) in [
        (fixtures::wrong_account(), "EA-OPERATOR-ACCOUNT-MISMATCH"),
        (
            fixtures::missing_instance_key(),
            "EA-OPERATOR-INSTANCE-KEY-MISSING",
        ),
        (
            fixtures::wrong_instance_key(),
            "EA-OPERATOR-INSTANCE-KEY-MISMATCH",
        ),
    ] {
        assert_eq!(
            verify(&head, &proof, account.as_ref()).unwrap_err().code(),
            expected
        );
    }
}

fn revoke(line: &mut RegistryLineBuilder, target_kind: u8, object_hash: ObjectHash) {
    line.push(
        ActionSpec::Revoke {
            target_kind,
            object_hash,
        },
        fixtures::head_options(101, 200),
    );
}

#[test]
fn a_current_head_revocation_rejects_the_same_still_fresh_proof() {
    for target_kind in [0, 1] {
        let (mut line, binding_hash, certificate_hash) =
            fixtures::build_line_for(CertificateKindV1::Reader, OperatorRoleV1::Reader, 0x63);
        let before = fixtures::select_head_of(&line, fixtures::FIXTURE_NOW_MS);
        let proof = FakeAuthenticator::new(BoundOperator::resolve(&before, binding_hash).unwrap())
            .reauthenticate(fixtures::valid_account(), ReauthPurpose::PlaintextExport)
            .unwrap();
        let account = fixtures::valid_account();
        let check = |head: &SelectedRegistryHead| {
            verify_current_session(
                head,
                CertificateHash::from(certificate_hash),
                OperatorRoleV1::Reader,
                &proof,
                ReauthPurpose::PlaintextExport,
                account.as_ref(),
            )
        };
        assert!(check(&before).is_ok());

        revoke(
            &mut line,
            target_kind,
            if target_kind == 0 {
                certificate_hash
            } else {
                binding_hash
            },
        );
        let after = fixtures::select_head_at_sequence(&line, fixtures::FIXTURE_NOW_MS + 1, 101);
        assert!(proof.is_valid_for(
            ReauthPurpose::PlaintextExport,
            after.preexisting_effective_now()
        ));
        assert_eq!(
            check(&after).unwrap_err().code(),
            "EA-OPERATOR-BINDING-NOT-ACTIVE"
        );
        assert_eq!(
            after
                .active_certificate_fields(CertificateHash::from(certificate_hash))
                .is_some(),
            target_kind == 1,
            "binding-only revocation leaves the certificate active"
        );
    }
}

#[test]
fn a_proof_cannot_select_another_active_binding_on_a_different_device() {
    let original = fixtures::selected_registry_head();
    let proof = fresh_proof(&original, ReauthPurpose::Finalize);
    let (line, binding_hash, certificate_hash) =
        fixtures::build_line_for(CertificateKindV1::Writer, OperatorRoleV1::Writer, 0x62);
    let current = fixtures::select_head_of(&line, fixtures::FIXTURE_NOW_MS);
    assert!(BoundOperator::resolve(&current, binding_hash).is_ok());
    assert_eq!(
        verify_current_session(
            &current,
            CertificateHash::from(certificate_hash),
            OperatorRoleV1::Writer,
            &proof,
            ReauthPurpose::Finalize,
            fixtures::valid_account().as_ref(),
        )
        .unwrap_err()
        .code(),
        "EA-OPERATOR-BINDING-NOT-ACTIVE"
    );
}

#[test]
fn reader_and_admin_roles_are_checked_against_the_resolved_binding() {
    for (kind, role, purpose) in [
        (
            CertificateKindV1::Reader,
            OperatorRoleV1::Reader,
            ReauthPurpose::PlaintextExport,
        ),
        (
            CertificateKindV1::OrganizationAdmin,
            OperatorRoleV1::OrganizationAdmin,
            ReauthPurpose::AdminRootCeremony,
        ),
    ] {
        let (line, binding_hash, certificate_hash) = fixtures::build_line_for(kind, role, 0x63);
        let head = fixtures::select_head_of(&line, fixtures::FIXTURE_NOW_MS);
        let proof = FakeAuthenticator::new(BoundOperator::resolve(&head, binding_hash).unwrap())
            .reauthenticate(fixtures::valid_account(), purpose)
            .unwrap();
        assert!(
            verify_current_session(
                &head,
                CertificateHash::from(certificate_hash),
                role,
                &proof,
                purpose,
                fixtures::valid_account().as_ref(),
            )
            .is_ok()
        );
        assert_eq!(
            verify_current_session(
                &head,
                CertificateHash::from(certificate_hash),
                OperatorRoleV1::Writer,
                &proof,
                purpose,
                fixtures::valid_account().as_ref(),
            )
            .unwrap_err()
            .code(),
            "EA-OPERATOR-ROLE-MISMATCH"
        );
    }
}

#[test]
fn another_active_certificate_for_the_same_device_cannot_substitute_for_the_bound_one() {
    let (mut line, binding_hash, certificate_hash) =
        fixtures::build_line_for(CertificateKindV1::Reader, OperatorRoleV1::Reader, 0x63);
    let before = fixtures::select_head_of(&line, fixtures::FIXTURE_NOW_MS);
    let proof = FakeAuthenticator::new(BoundOperator::resolve(&before, binding_hash).unwrap())
        .reauthenticate(fixtures::valid_account(), ReauthPurpose::PlaintextExport)
        .unwrap();
    let second = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Reader,
            marker: 0x63,
            effective_from: None,
        },
        fixtures::head_options(101, 200),
    );
    let after = fixtures::select_head_at_sequence(&line, fixtures::FIXTURE_NOW_MS + 1, 110);
    let original = CertificateHash::from(certificate_hash);
    let replacement = CertificateHash::from(second.direct_object_hash.unwrap());
    assert!(original != replacement);
    assert!(
        after.active_certificate_fields(original).unwrap().device_id
            == after
                .active_certificate_fields(replacement)
                .unwrap()
                .device_id
    );
    assert!(
        verify_current_session(
            &after,
            original,
            OperatorRoleV1::Reader,
            &proof,
            ReauthPurpose::PlaintextExport,
            fixtures::valid_account().as_ref()
        )
        .is_ok()
    );
    assert_eq!(
        verify_current_session(
            &after,
            replacement,
            OperatorRoleV1::Reader,
            &proof,
            ReauthPurpose::PlaintextExport,
            fixtures::valid_account().as_ref()
        )
        .unwrap_err()
        .code(),
        "EA-OPERATOR-DEVICE-MISMATCH"
    );
}

#[derive(Clone)]
struct SimulatedAccount {
    inputs: Rc<RefCell<OsAccountInputs>>,
    instance_secret: Rc<Cell<Option<[u8; 32]>>>,
}

impl SimulatedAccount {
    fn new(inputs: OsAccountInputs) -> Self {
        Self {
            inputs: Rc::new(RefCell::new(inputs)),
            instance_secret: Rc::new(Cell::new(Some(INSTANCE_SECRET))),
        }
    }
}

impl OsAccountProvider for SimulatedAccount {
    fn os_account_binding_hash(
        &self,
        organization: OrganizationId,
        device: DeviceId,
    ) -> Result<Hash32, OperatorError> {
        self.inputs.borrow().binding_hash(organization, device)
    }

    fn operator_instance_public_key(
        &self,
    ) -> Result<Option<CanonicalPublicCoseKey>, OperatorError> {
        Ok(self.instance_secret.get().map(fixtures::public_key))
    }
}

fn platform_inputs(platform: &str, uid: u32) -> OsAccountInputs {
    match platform {
        "Windows" => {
            let subs = vec![21, 1, 2, 3, uid];
            let mut sid = vec![1, 5, 0, 0, 0, 0, 0, 5];
            for sub in &subs {
                sid.extend_from_slice(&sub.to_le_bytes());
            }
            ea_operator::windows::account_inputs(sid, [0, 0, 0, 0, 0, 5], subs)
        }
        "macOS" => ea_operator::macos::account_inputs(
            vec!["f81d4fae-7dec-11d0-a765-00a0c91e6bf6".to_owned()],
            vec![uid.to_string()],
            uid,
        ),
        "Linux" => {
            ea_operator::linux::account_inputs(b"0123456789abcdef0123456789abcdef\n".to_vec(), uid)
        }
        _ => panic!("unknown test platform"),
    }
}

// These are the public test-vector secrets used by the shared registry builder,
// not OS keys. Only this small additional binding is built here: the existing
// fixture's account hash is synthetic and has no OS-account preimage.
fn head_for_account(
    account: &dyn OsAccountProvider,
) -> (SelectedRegistryHead, ObjectHash, CertificateHash) {
    let (mut line, _, certificate_object_hash) = fixtures::build_line();
    let base = fixtures::select_head_of(&line, fixtures::FIXTURE_NOW_MS);
    let certificate_hash = CertificateHash::from(certificate_object_hash);
    let device = base
        .active_certificate_fields(certificate_hash)
        .unwrap()
        .device_id;
    let fields = OperatorBindingFieldsV1 {
        organization_id: support::organization(),
        operator_subject_id: OperatorSubjectId::try_from(&[0x74; 16][..]).unwrap(),
        operator_profile_commitment: support::hash32(0x75),
        device_certificate_hash: certificate_hash,
        operator_role: OperatorRoleV1::Writer,
        os_account_binding_hash: account
            .os_account_binding_hash(support::organization(), device)
            .unwrap(),
        operator_instance_key_thumbprint: fixtures::public_key(INSTANCE_SECRET).thumbprint(),
        effective_from_sequence: ChainSequence::new(101),
        revoked_from_sequence: None,
    };
    let provisional =
        TrustPayloadV1::authorized_operator_binding(fields.clone(), ObjectHash::from(Hash32::ZERO))
            .unwrap();
    let mut decoder = minicbor::Decoder::new(provisional.exact_payload());
    assert_eq!(decoder.array().unwrap(), Some(2));
    let start = decoder.position();
    decoder.skip().unwrap();
    let core = &provisional.exact_payload()[start..decoder.position()];
    let mut authorized_input = Vec::new();
    minicbor::Encoder::new(&mut authorized_input)
        .array(2)
        .unwrap()
        .str("operatorBinding")
        .unwrap();
    authorized_input.extend_from_slice(core);

    let admin = CoseSigner::from_secret(SecretBytes::new([
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e,
        0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8,
        0xa6, 0xfb,
    ]));
    let authorization =
        TrustPayloadV1::organization_admin_authorization(OrganizationAdminAuthorizationFieldsV1 {
            authorization_id: AuthorizationId::try_from(&[0xe1; 16][..]).unwrap(),
            organization_id: support::organization(),
            registry_version: base.registry_version(),
            registry_head_hash: Hash32::try_from(base.registry_head_hash().as_bytes().as_slice())
                .unwrap(),
            admin_key_thumbprint: base
                .active_certificate_fields(CertificateHash::from(line.bootstrap_admin_hash()))
                .unwrap()
                .signing_key_thumbprint
                .unwrap(),
            admin_certificate_hash: CertificateHash::from(line.bootstrap_admin_hash()),
            admin_operator_binding_object_hash: line.bootstrap_admin_binding_hash(),
            action_code: 4,
            target_trust_subtype: TrustSubtypeV1::OperatorBinding,
            authorized_trust_core_hash: authorized_trust_digest(&authorized_input),
            issued_at: UnixMillis::new(100),
            expires_at: UnixMillis::new(1_100),
            nonce: [0xe2; 32],
        })
        .unwrap();
    let signature = admin
        .sign_organization_admin_trust_digest(authorization.exact_digest_input())
        .unwrap();
    let authorization_bytes =
        encode_trust(&TrustObjectV1::new(authorization, vec![signature]).unwrap())
            .unwrap()
            .into_vec();
    let binding =
        TrustPayloadV1::authorized_operator_binding(fields, object_hash(&authorization_bytes))
            .unwrap();
    let root = CoseSigner::from_secret(SecretBytes::new([
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ]));
    let signature = root
        .sign_root_trust_digest(
            CertificateHash::from(line.current_root_hash()),
            binding.exact_digest_input(),
            Some(&authorization_bytes),
        )
        .unwrap();
    let binding_bytes = encode_trust(&TrustObjectV1::new(binding, vec![signature]).unwrap())
        .unwrap()
        .into_vec();
    let binding_hash = object_hash(&binding_bytes);
    line.add_object(authorization_bytes);
    line.add_object(binding_bytes);
    line.push(
        ActionSpec::OperatorBinding {
            certificate_hash: certificate_object_hash,
            role: OperatorRoleV1::Writer,
            marker: 0x76,
            effective_from: None,
        },
        HeadOptions {
            change_override: ChangeOverride::Raw(RegistryChangeV1::OperatorBinding {
                object_hash: binding_hash,
            }),
            omit_direct_object: true,
            omit_direct_authorization: true,
            ..fixtures::head_options(101, 200)
        },
    );
    (
        fixtures::select_head_at_sequence(&line, fixtures::FIXTURE_NOW_MS, 110),
        binding_hash,
        certificate_hash,
    )
}

#[test]
fn recreated_accounts_same_uid_reused_home_and_restored_profiles_require_a_new_binding() {
    // All three simulations run on every host. On Linux both machine-id and UID
    // remain byte-for-byte identical; only the per-installation key disappears
    // with the Secret-Service collection, or is replaced on account recreation.
    for platform in ["Windows", "macOS", "Linux"] {
        let account = SimulatedAccount::new(platform_inputs(platform, 1001));
        let (head, binding_hash, certificate_hash) = head_for_account(&account);
        let auth = FakeAuthenticator::new(BoundOperator::resolve(&head, binding_hash).unwrap());
        let proof = auth
            .reauthenticate(Box::new(account.clone()), ReauthPurpose::Finalize)
            .unwrap();
        let check = || {
            verify_current_session(
                &head,
                certificate_hash,
                OperatorRoleV1::Writer,
                &proof,
                ReauthPurpose::Finalize,
                &account,
            )
        };
        assert!(check().is_ok(), "{platform}: original account");

        account.instance_secret.set(None);
        assert_eq!(
            check().unwrap_err().code(),
            "EA-OPERATOR-INSTANCE-KEY-MISSING",
            "{platform}: lost key / restored profile"
        );
        account.instance_secret.set(Some(OTHER_INSTANCE_SECRET));
        assert_eq!(
            check().unwrap_err().code(),
            "EA-OPERATOR-INSTANCE-KEY-MISMATCH",
            "{platform}: recreated account"
        );
        assert_eq!(
            auth.reauthenticate(Box::new(account.clone()), ReauthPurpose::Finalize)
                .unwrap_err()
                .code(),
            "EA-OPERATOR-INSTANCE-KEY-MISMATCH"
        );
    }
}

#[test]
fn a_changed_native_account_is_rejected_even_with_the_original_instance_key() {
    for platform in ["Windows", "macOS", "Linux"] {
        let account = SimulatedAccount::new(platform_inputs(platform, 1001));
        let (head, binding_hash, certificate_hash) = head_for_account(&account);
        let proof = FakeAuthenticator::new(BoundOperator::resolve(&head, binding_hash).unwrap())
            .reauthenticate(Box::new(account.clone()), ReauthPurpose::Finalize)
            .unwrap();
        account.inputs.replace(platform_inputs(platform, 1002));
        assert_eq!(
            verify_current_session(
                &head,
                certificate_hash,
                OperatorRoleV1::Writer,
                &proof,
                ReauthPurpose::Finalize,
                &account
            )
            .unwrap_err()
            .code(),
            "EA-OPERATOR-ACCOUNT-MISMATCH",
            "{platform}"
        );
    }
}
