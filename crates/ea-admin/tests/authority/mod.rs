use super::*;
use crate::operator_exchange::{ExchangeSigner, PendingExchange};
use ea_format::{CertificateKindV1, KeyProtectionProfileV1};
use ea_key_provider::{InMemoryKeyProvider, KeyProvider, SecretPurpose};
use ea_trust::{
    RegistrySelectionOutcome, load_trust_state, prepare_local_time, select_registry_head,
    verify_registry_candidate, verify_trust,
};
use ea_types::UnixMillis;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

use support::trust_support as fixtures;

#[path = "../support/operator_lifecycle.rs"]
mod lifecycle;
mod recovery;
mod routing;
use crate::test_support as support;

struct Signing(SigningKey);
impl ExchangeSigner for Signing {
    fn sign(&self, input: &[u8]) -> Result<[u8; 64], ExchangeError> {
        Ok(self.0.sign(input).to_bytes())
    }
}

fn database() -> (Arc<EncryptedDatabase>, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "ea-authority-test-{}-{}",
        std::process::id(),
        hex::encode(random())
    ));
    std::fs::create_dir(&dir).unwrap();
    let provider = InMemoryKeyProvider::new_for_test([0x61; 32]);
    let key = provider
        .generate(
            SecretPurpose::LocalDatabaseKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    (
        Arc::new(EncryptedDatabase::open(&dir.join("authority.sqlite"), &provider, &key).unwrap()),
        dir,
    )
}
fn random() -> [u8; 16] {
    let mut b = [0; 16];
    getrandom::fill(&mut b).unwrap();
    b
}

#[test]
fn a_completed_encrypted_reply_is_replayed_exactly_and_pending_is_never_reauthorized() {
    let (database, directory) = database();
    let device = Signing(SigningKey::from_bytes(&[0x12; 32]));
    let pending = PendingExchange::new(json!({"op":"identity"}), &device).unwrap();
    let bytes = pending.request_bytes();
    assert!(begin_request(&database, bytes).unwrap().is_none());
    assert!(matches!(
        begin_request(&database, bytes),
        Err(AuthorityError::Uncertain)
    ));
    let public = CanonicalPublicCoseKey::ed25519(device.0.verifying_key().to_bytes()).unwrap();
    let verified = VerifiedExchangeRequest::verify(bytes, &public).unwrap();
    let signer = Signing(SigningKey::from_bytes(
        &fixtures::second_admin_signing_secret(),
    ));
    let reply = verified.reply(json!({"display_name":"Private Authority Person", "profile_commitment_salt":hex::encode([0x5d;32])}), &signer).unwrap();
    assert!(
        !reply
            .windows(b"Private Authority Person".len())
            .any(|w| w == b"Private Authority Person")
    );
    finish_request(&database, bytes, &reply).unwrap();
    drop(database);
    let provider = InMemoryKeyProvider::new_for_test([0x61; 32]);
    let key = provider
        .generate(
            SecretPurpose::LocalDatabaseKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    let database = Arc::new(
        EncryptedDatabase::open_existing(&directory.join("authority.sqlite"), &provider, &key)
            .unwrap(),
    );
    assert_eq!(begin_request(&database, bytes).unwrap().unwrap(), reply);
    let admin_public =
        CanonicalPublicCoseKey::ed25519(signer.0.verifying_key().to_bytes()).unwrap();
    assert_eq!(
        pending.open_reply(&reply, &admin_public).unwrap()["display_name"],
        "Private Authority Person"
    );
    drop(database);
    std::fs::remove_dir_all(directory).unwrap();
}

fn fixture() -> (
    fixtures::RegistryLineBuilder,
    SelectedRegistryHead,
    CertificateHash,
    Arc<EncryptedDatabase>,
    std::path::PathBuf,
) {
    let mut line = fixtures::RegistryLineBuilder::new();
    line.push(
        fixtures::ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        fixtures::HeadOptions::default(),
    );
    let cert = line
        .push(
            fixtures::ActionSpec::Device {
                kind: CertificateKindV1::Writer,
                marker: 0x61,
                effective_from: None,
            },
            fixtures::HeadOptions::default(),
        )
        .direct_object_hash
        .unwrap();
    let (database, directory) = database();
    let head = select(&line, &database);
    (line, head, CertificateHash::from(cert), database, directory)
}

fn select(
    line: &fixtures::RegistryLineBuilder,
    database: &Arc<EncryptedDatabase>,
) -> SelectedRegistryHead {
    let anchor = ea_trust::decode_trust_anchor(line.exact_anchor_bytes()).unwrap();
    let key = fixtures::state_key();
    let mut store = crate::operator_trust_store::OperatorTrustStateStore::open(
        database.clone(),
        key,
        anchor.chain_id(),
        anchor.trust_anchor_hash(),
        UnixMillis::new(0),
    )
    .unwrap();
    let sequence = line.heads().last().unwrap().effective_from;
    loop {
        let trust = verify_trust(
            &anchor,
            &line.source(),
            load_trust_state(&mut store, key).unwrap(),
        )
        .unwrap();
        let pin = trust.pinned_head().copied();
        let candidate = verify_registry_candidate(&trust, sequence).unwrap();
        let time = prepare_local_time(&mut store, &candidate, UnixMillis::new(1000), &[]).unwrap();
        if let RegistrySelectionOutcome::Selected(h) =
            select_registry_head(candidate, time, None).unwrap()
            && pin.is_some_and(|pin| pin.registry_head_hash() == h.registry_head_hash())
        {
            return h;
        }
    }
}

#[test]
fn only_the_pinned_active_source_and_exact_registry_context_can_request_authority() {
    let (line, head, certificate, database, directory) = fixture();
    let admin = CertificateHash::from(line.bootstrap_admin_hash());
    let binding = line.bootstrap_admin_binding_hash();
    let body = json!({"op":"describe-admin","args":{},"context":{
        "organization_id":hex::encode(head.root_certificate_fields().organization_id.as_bytes()),
        "chain_id":hex::encode(head.chain_id().as_bytes()),"registry_head_hash":hex::encode(head.registry_head_hash().as_bytes()),
        "registry_version":head.registry_version().get(),"sequence":head.proposed_sequence().get(),
        "device_certificate_hash":hex::encode(certificate.as_bytes()),"admin_certificate_hash":hex::encode(admin.as_bytes()),
        "admin_binding_object_hash":hex::encode(binding.as_bytes())}});
    let signing = Signing(SigningKey::from_bytes(&fixtures::device_signing_secret()));
    let request = PendingExchange::new(body.clone(), &signing).unwrap();
    assert!(verify_request(request.request_bytes(), &head, certificate, admin, binding).is_ok());
    let foreign = Signing(SigningKey::from_bytes(&[0x44; 32]));
    let request = PendingExchange::new(body.clone(), &foreign).unwrap();
    assert!(verify_request(request.request_bytes(), &head, certificate, admin, binding).is_err());
    for field in [
        "organization_id",
        "chain_id",
        "registry_head_hash",
        "device_certificate_hash",
        "admin_certificate_hash",
        "admin_binding_object_hash",
    ] {
        let mut wrong = body.clone();
        wrong["context"][field] = json!("00".repeat(if field.ends_with("_id") { 16 } else { 32 }));
        let request = PendingExchange::new(wrong, &signing).unwrap();
        assert!(
            verify_request(request.request_bytes(), &head, certificate, admin, binding).is_err(),
            "{field}"
        );
    }
    for field in ["registry_version", "sequence"] {
        let mut wrong = body.clone();
        wrong["context"][field] = json!(0);
        let request = PendingExchange::new(wrong, &signing).unwrap();
        assert!(
            verify_request(request.request_bytes(), &head, certificate, admin, binding).is_err(),
            "{field}"
        );
    }
    drop(database);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn the_authority_accepts_operator_targets_but_never_root_rotation_or_policy_digests() {
    let mut line = fixtures::RegistryLineBuilder::new();
    let (_, binding) = line.prepare_unsigned(
        fixtures::ActionSpec::OperatorBinding {
            certificate_hash: line.bootstrap_admin_hash(),
            role: ea_format::OperatorRoleV1::OrganizationAdmin,
            marker: 0x72,
            effective_from: None,
        },
        fixtures::HeadOptions::default(),
    );
    assert!(supported_target(binding.exact_digest_input()).is_ok());
    let (_, policy) = line.prepare_unsigned(
        fixtures::ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        fixtures::HeadOptions::default(),
    );
    assert!(supported_target(policy.exact_digest_input()).is_err());
    assert!(supported_target(&[0; 32]).is_err());
}

#[test]
fn salted_commitment_must_match_the_unexpired_authority_attestation_and_its_target() {
    let (mut line, head, certificate, database, directory) = fixture();
    let subject = OperatorSubjectId::try_from(&[0x72; 16][..]).unwrap();
    let salt = [0x5d; 32];
    let commitment = ea_crypto::operator_profile_commitment(
        fixtures::organization(),
        subject,
        "Externally Verified",
        "Incident Command",
        &salt,
    );
    let (_, payload) = line.prepare_unsigned(
        fixtures::ActionSpec::OperatorBinding {
            certificate_hash: ObjectHash::try_from(certificate.as_bytes().as_slice()).unwrap(),
            role: OperatorRoleV1::Writer,
            marker: 0x72,
            effective_from: None,
        },
        fixtures::HeadOptions {
            binding_operator_profile_commitment_override: Some(commitment),
            ..fixtures::HeadOptions::default()
        },
    );
    let DecodedTrustPayloadV1::AuthorizedOperatorBinding(binding) =
        payload.decoded_payload().unwrap()
    else {
        panic!("binding");
    };
    let fields = binding.fields();
    assert!(
        verify_attested_profile(
            &database,
            &head,
            certificate,
            fields,
            None,
            UnixMillis::new(1000)
        )
        .is_err()
    );
    database.execute("INSERT INTO operator_authority_identity VALUES (?1,?2,?3,?4,'writer','Externally Verified','Incident Command',?5,NULL,1000)", &[
        blob(certificate.as_bytes()),blob(head.registry_head_hash().as_bytes()),blob(fixtures::organization().as_bytes()),blob(subject.as_bytes()),blob(&salt),
    ]).unwrap();
    assert!(
        verify_attested_profile(
            &database,
            &head,
            certificate,
            fields,
            None,
            UnixMillis::new(1000)
        )
        .is_ok()
    );
    for current in [999, 1000 + MAX_INACTIVITY_MS] {
        assert!(
            verify_attested_profile(
                &database,
                &head,
                certificate,
                fields,
                None,
                UnixMillis::new(current)
            )
            .is_err()
        );
    }
    assert!(
        verify_attested_profile(
            &database,
            &head,
            certificate,
            fields,
            Some(fixtures::object_hash_marker(0x11)),
            UnixMillis::new(1000)
        )
        .is_err()
    );
    for index in 0..5 {
        let mut wrong = fields.clone();
        match index {
            0 => wrong.operator_subject_id = OperatorSubjectId::try_from(&[0x73; 16][..]).unwrap(),
            1 => {
                wrong.organization_id = ea_types::OrganizationId::try_from(&[0x73; 16][..]).unwrap()
            }
            2 => wrong.device_certificate_hash = CertificateHash::from(line.bootstrap_admin_hash()),
            3 => wrong.operator_role = OperatorRoleV1::Reader,
            _ => wrong.operator_profile_commitment = fixtures::hash32(0x73),
        }
        assert!(
            verify_attested_profile(
                &database,
                &head,
                certificate,
                &wrong,
                None,
                UnixMillis::new(1000)
            )
            .is_err()
        );
    }
    database
        .execute(
            "UPDATE operator_authority_identity SET profile_commitment_salt=?1",
            &[blob(&[0x5e; 32])],
        )
        .unwrap();
    assert!(
        verify_attested_profile(
            &database,
            &head,
            certificate,
            fields,
            None,
            UnixMillis::new(1000)
        )
        .is_err()
    );
    database.execute("UPDATE operator_authority_identity SET profile_commitment_salt=?1,display_name='Unverified Replacement'", &[blob(&salt)]).unwrap();
    assert!(
        verify_attested_profile(
            &database,
            &head,
            certificate,
            fields,
            None,
            UnixMillis::new(1000)
        )
        .is_err()
    );
    drop(database);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn previous_identity_comes_from_actual_active_and_revoked_bindings_even_without_a_profile() {
    let (mut line, _, certificate, database, directory) = fixture();
    let binding = line
        .push(
            fixtures::ActionSpec::OperatorBinding {
                certificate_hash: ObjectHash::try_from(certificate.as_bytes().as_slice()).unwrap(),
                role: OperatorRoleV1::Writer,
                marker: 0x72,
                effective_from: None,
            },
            fixtures::HeadOptions::default(),
        )
        .direct_object_hash
        .unwrap();
    let subject = OperatorSubjectId::try_from(&[0x72; 16][..]).unwrap();
    let head = select(&line, &database);
    assert!(
        previous_binding(
            &head,
            [binding],
            subject,
            OperatorRoleV1::Writer,
            certificate
        )
        .is_err()
    );
    line.push(
        fixtures::ActionSpec::Revoke {
            target_kind: 1,
            object_hash: binding,
        },
        fixtures::HeadOptions::default(),
    );
    let head = select(&line, &database);
    assert!(
        previous_binding(
            &head,
            [binding],
            subject,
            OperatorRoleV1::Writer,
            certificate
        )
        .unwrap()
            == Some(binding)
    );
    let catalog_only = line.add_prepared(fixtures::ActionSpec::OperatorBinding {
        certificate_hash: ObjectHash::try_from(certificate.as_bytes().as_slice()).unwrap(),
        role: OperatorRoleV1::Writer,
        marker: 0x72,
        effective_from: None,
    });
    let head = select(&line, &database);
    assert!(
        previous_binding(
            &head,
            [binding, catalog_only],
            subject,
            OperatorRoleV1::Writer,
            certificate,
        )
        .unwrap()
            == Some(binding)
    );
    assert!(
        database
            .query_row("SELECT * FROM operator_profile", &[])
            .unwrap()
            .is_none()
    );
    drop(database);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn presence_is_limited_to_the_bound_admin_ceremony_and_actual_current_time() {
    let (line, head, _, database, directory) = fixture();
    let certificate = CertificateHash::from(line.bootstrap_admin_hash());
    let binding = line.bootstrap_admin_binding_hash();
    let admin = head.active_certificate_fields(certificate).unwrap();
    let label = ReauthPurpose::AdminRootCeremony.label();
    let mut challenge = REAUTH_CHALLENGE_DOMAIN.to_vec();
    challenge.push(label.len() as u8);
    challenge.extend_from_slice(label.as_bytes());
    let offset = challenge.len();
    challenge.extend_from_slice(admin.organization_id.as_bytes());
    challenge.extend_from_slice(admin.device_id.as_bytes());
    challenge.extend_from_slice(binding.as_bytes());
    challenge.extend_from_slice(&[0x4a; 32]);
    challenge.extend_from_slice(&1000i64.to_be_bytes());
    challenge.extend_from_slice(&(1000 + MAX_INACTIVITY_MS).to_be_bytes());
    assert!(
        check_presence_challenge(
            &head,
            certificate,
            binding,
            &challenge,
            UnixMillis::new(1000)
        )
        .is_ok()
    );
    for at in [
        0,
        REAUTH_CHALLENGE_DOMAIN.len() + 1,
        offset,
        offset + 16,
        offset + 32,
    ] {
        let mut wrong = challenge.clone();
        wrong[at] ^= 1;
        assert!(
            check_presence_challenge(&head, certificate, binding, &wrong, UnixMillis::new(1000))
                .is_err()
        );
    }
    for current in [999, 1000 + MAX_INACTIVITY_MS] {
        assert!(
            check_presence_challenge(
                &head,
                certificate,
                binding,
                &challenge,
                UnixMillis::new(current)
            )
            .is_err()
        );
    }
    challenge.push(0);
    assert!(
        check_presence_challenge(
            &head,
            certificate,
            binding,
            &challenge,
            UnixMillis::new(1000)
        )
        .is_err()
    );
    drop(database);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn identity_fields_and_salt_are_not_accepted_from_public_request_arguments() {
    let identity = json!({"organization_id":"21".repeat(16),"device_id":"61".repeat(16),"challenge":"42".repeat(32),"role":"writer","previous_subject_id":null,"previous_binding_object_hash":null});
    assert!(args::<IdentityArgs>(&identity).is_ok());
    for field in [
        "display_name",
        "function_label",
        "operator_subject_id",
        "profile_commitment_salt",
        "os_display_name",
    ] {
        let mut forged = identity.clone();
        forged[field] = json!("attacker chosen");
        assert!(args::<IdentityArgs>(&forged).is_err());
    }
    assert!(
        args::<AuthorizeArgs>(
            &json!({"target_payload":"00","profile_commitment_salt":"55".repeat(32)})
        )
        .is_err()
    );
}

#[test]
fn audit_core_keeps_bound_identity_and_freshness_when_target_opened_before_authority() {
    use ea_format::{
        GenericAuditContextV1, LocalAuditActionV1, LocalAuditEventCoreFieldsV1,
        LocalAuditOutcomeV1, encode_local_audit_core,
    };
    let (line, head, _, database, directory) = fixture();
    let admin = CertificateHash::from(line.bootstrap_admin_hash());
    let binding = line.bootstrap_admin_binding_hash();
    let fields = head.active_certificate_fields(admin).unwrap();
    let core_fields = |index| LocalAuditEventCoreFieldsV1 {
        event_id: ea_types::EventId::try_from(&[0x44; 16][..]).unwrap(),
        organization_id: if index == 1 {
            ea_types::OrganizationId::try_from(&[0x55; 16][..]).unwrap()
        } else {
            fields.organization_id
        },
        device_id: if index == 2 {
            ea_types::DeviceId::try_from(&[0x55; 16][..]).unwrap()
        } else {
            fields.device_id
        },
        operator_binding_object_hash: if index == 3 || index == 6 {
            None
        } else {
            Some(binding)
        },
        signer_certificate_object_hash: if index == 4 {
            line.second_bootstrap_admin_hash()
        } else {
            line.bootstrap_admin_hash()
        },
        action: if index == 6 {
            LocalAuditActionV1::AdminRootCeremony(ea_format::AdminRootContextV1::new(
                binding, binding, 4,
            ))
        } else if index == 5 {
            LocalAuditActionV1::RecoveryTest(GenericAuditContextV1::new(Some(binding)))
        } else {
            LocalAuditActionV1::Login(GenericAuditContextV1::new(Some(binding)))
        },
        outcome: LocalAuditOutcomeV1::Completed,
        effective_now: UnixMillis::new(900),
        nonce: [0x44; 32],
    };
    let good = encode_local_audit_core(&core_fields(0)).unwrap();
    assert!(audit_event(&good, &head, admin, binding, UnixMillis::new(1000)).is_ok());
    for index in 1..=6 {
        let core = encode_local_audit_core(&core_fields(index)).unwrap();
        assert!(audit_event(&core, &head, admin, binding, UnixMillis::new(1000)).is_err());
    }
    assert!(audit_event(&good, &head, admin, binding, UnixMillis::new(899)).is_err());
    assert!(
        audit_event(
            &good,
            &head,
            admin,
            binding,
            UnixMillis::new(900 + MAX_INACTIVITY_MS)
        )
        .is_err()
    );
    assert!(audit_event(&[0; 32], &head, admin, binding, UnixMillis::new(1000)).is_err());
    drop(database);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn later_requests_are_discovered_without_repeating_handled_requests() {
    let (_, directory) = database();
    let mut handled = std::collections::BTreeSet::new();
    assert!(request_paths(&directory, &handled).unwrap().is_empty());
    let first = directory.join("request-first.json");
    let second = directory.join("request-second.json");
    std::fs::write(&first, b"first signed request").unwrap();
    assert_eq!(
        request_paths(&directory, &handled).unwrap(),
        std::slice::from_ref(&first)
    );
    handled.insert(first);
    std::fs::write(&second, b"second signed request").unwrap();
    assert_eq!(request_paths(&directory, &handled).unwrap(), [second]);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn outer_envelope_reencoding_cannot_mint_another_authorization_replay_identity() {
    let signer = Signing(SigningKey::from_bytes(&fixtures::device_signing_secret()));
    let public = CanonicalPublicCoseKey::ed25519(signer.0.verifying_key().to_bytes()).unwrap();
    let pending =
        PendingExchange::new(json!({"op":"authorize-target","args":{}}), &signer).unwrap();
    let original = VerifiedExchangeRequest::verify(pending.request_bytes(), &public).unwrap();
    let mut envelope: Value = serde_json::from_slice(pending.request_bytes()).unwrap();
    for index in 0..2 {
        if index == 1 {
            envelope["body"] = json!(envelope["body"].as_str().unwrap().to_uppercase());
        }
        let alternate = serde_json::to_vec_pretty(&envelope).unwrap();
        if let Ok(replayed) = VerifiedExchangeRequest::verify(&alternate, &public) {
            assert_eq!(
                replayed.request_id(),
                original.request_id(),
                "same authenticated request cannot receive fresh authorization ID/nonce by changing unsigned outer spelling"
            );
        }
    }
}

fn select_durable(
    source: &dyn ea_trust::TrustObjectSource,
    anchor: &ea_trust::TrustAnchorV1,
    store: &mut crate::operator_trust_store::OperatorTrustStateStore,
    key: ea_trust::TrustStateKey,
    sequence: u64,
) -> SelectedRegistryHead {
    for _ in 0..20 {
        let trust = verify_trust(anchor, source, load_trust_state(store, key).unwrap()).unwrap();
        let candidate =
            verify_registry_candidate(&trust, ea_types::ChainSequence::new(sequence)).unwrap();
        let time = prepare_local_time(store, &candidate, UnixMillis::new(1000), &[]).unwrap();
        match select_registry_head(candidate, time, None).unwrap() {
            RegistrySelectionOutcome::Selected(head) => return head,
            RegistrySelectionOutcome::Advanced(_) => {}
            RegistrySelectionOutcome::PendingFuture(_) => panic!("unexpected future"),
        }
    }
    panic!("selected head required")
}

fn request_for(
    head: &SelectedRegistryHead,
    target: CertificateHash,
    admin: CertificateHash,
    binding: ObjectHash,
    args: Value,
) -> PendingExchange {
    PendingExchange::new(json!({"op":"authorize-target", "args":args, "context":{
        "organization_id":hex::encode(head.root_certificate_fields().organization_id.as_bytes()),
        "chain_id":hex::encode(head.chain_id().as_bytes()),
        "registry_head_hash":hex::encode(head.registry_head_hash().as_bytes()),
        "registry_version":head.registry_version().get(), "sequence":head.proposed_sequence().get(),
        "device_certificate_hash":hex::encode(target.as_bytes()),
        "admin_certificate_hash":hex::encode(admin.as_bytes()),
        "admin_binding_object_hash":hex::encode(binding.as_bytes())
    }}), &Signing(SigningKey::from_bytes(&fixtures::device_signing_secret()))).unwrap()
}

#[test]
fn authority_lifecycle_issues_binding_activation_revocation_to_an_independent_store() {
    use ea_trust::TrustStateStore;
    use ea_types::{ChainSequence, RegistryVersion};
    use support::trust_support as t;
    let mut line = t::RegistryLineBuilder::new();
    let options = |from, through| t::HeadOptions {
        effective_from: Some(from),
        valid_through: Some(through),
        not_after: UnixMillis::new(10_000_000),
        ..t::HeadOptions::default()
    };
    line.push(
        t::ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        options(1, 10),
    );
    let target = CertificateHash::from(
        line.push(
            t::ActionSpec::Device {
                kind: CertificateKindV1::Writer,
                marker: 0x61,
                effective_from: None,
            },
            options(11, 20),
        )
        .direct_object_hash
        .unwrap(),
    );
    let administrator = lifecycle::RecoveryAdmin::enroll(&mut line);
    let target_database = lifecycle::database("authority-target");
    let authority_database = &administrator.database.database;
    let anchor = ea_trust::decode_trust_anchor(line.exact_anchor_bytes()).unwrap();
    let authority_key = ea_trust::TrustStateKey {
        organization_id: anchor.organization_id(),
        device_id: ea_types::DeviceId::try_from(&[0x42; 16][..]).unwrap(),
    };
    let target_key = ea_trust::TrustStateKey {
        organization_id: anchor.organization_id(),
        device_id: ea_types::DeviceId::try_from(&[0x61; 16][..]).unwrap(),
    };
    let mut authority_store = crate::operator_trust_store::OperatorTrustStateStore::open(
        authority_database.clone(),
        authority_key,
        anchor.chain_id(),
        anchor.trust_anchor_hash(),
        UnixMillis::new(0),
    )
    .unwrap();
    let mut target_store = crate::operator_trust_store::OperatorTrustStateStore::open(
        target_database.database.clone(),
        target_key,
        anchor.chain_id(),
        anchor.trust_anchor_hash(),
        UnixMillis::new(0),
    )
    .unwrap();
    let head = select_durable(
        &line.source(),
        &anchor,
        &mut authority_store,
        authority_key,
        21,
    );
    let target_head = select_durable(&line.source(), &anchor, &mut target_store, target_key, 21);
    assert_eq!(
        head.registry_head_hash().as_bytes(),
        target_head.registry_head_hash().as_bytes()
    );
    let subject = OperatorSubjectId::try_from(&[0x72; 16][..]).unwrap();
    let salt = [0x5d; 32];
    authority_database.execute("INSERT INTO operator_authority_identity VALUES (?1,?2,?3,?4,'writer','Externally Verified','Incident Command',?5,NULL,1000)", &[
        blob(target.as_bytes()),blob(head.registry_head_hash().as_bytes()),blob(anchor.organization_id().as_bytes()),blob(subject.as_bytes()),blob(&salt),
    ]).unwrap();
    let fields = ea_format::OperatorBindingFieldsV1 {
        organization_id: anchor.organization_id(),
        operator_subject_id: subject,
        operator_profile_commitment: ea_crypto::operator_profile_commitment(
            anchor.organization_id(),
            subject,
            "Externally Verified",
            "Incident Command",
            &salt,
        ),
        device_certificate_hash: target,
        operator_role: OperatorRoleV1::Writer,
        os_account_binding_hash: t::hash32(0x73),
        operator_instance_key_thumbprint: lifecycle::key([0x47; 32]).thumbprint(),
        effective_from_sequence: ChainSequence::new(101),
        revoked_from_sequence: None,
    };
    let mut targets = vec![OperatorTrustTarget::Binding(fields)];
    let admin_provider = Arc::new(support::FixtureKeyProvider::second_admin());
    let root_provider = Arc::new(support::FixtureKeyProvider::root());
    let exchange_signer = Signing(SigningKey::from_bytes(&t::second_admin_signing_secret()));
    let exchange_public =
        CanonicalPublicCoseKey::ed25519(exchange_signer.0.verifying_key().to_bytes()).unwrap();
    let mut current_head = head;
    let mut relevant: Vec<Vec<u8>> = Vec::new();
    let mut binding = ObjectHash::from(Hash32::ZERO);
    let exchange_directory = support::temp_dir("authority-retained-media");
    let mut retained_replies = std::collections::BTreeMap::new();
    for stage in 0..3 {
        let (authorization, signed_target, all) = {
            let source = line.source();
            let admin_audit = administrator.audit(&current_head);
            let authenticator = administrator.authenticator(&current_head);
            let session = administrator
                .service(&current_head, admin_audit.service())
                .verify_session(administrator.login(&authenticator))
                .unwrap();
            let core = AuthorityCore {
                database: authority_database,
                store: &authority_store,
                source: &source,
                anchor: &anchor,
                state_key: authority_key,
                head: &current_head,
                admin_certificate: administrator.certificate,
                admin_binding: administrator.binding,
                admin_handle: admin_provider.handle(),
                admin_provider: admin_provider.clone(),
                root_handle: root_provider.handle(),
                root_provider: root_provider.clone(),
                current: &|| Ok(UnixMillis::new(1000)),
                reply_signer: &exchange_signer,
            };
            let payload = targets[stage]
                .payload(ObjectHash::from(Hash32::ZERO))
                .unwrap();
            let pending = request_for(
                &current_head,
                target,
                administrator.certificate,
                administrator.binding,
                json!({"target_payload":hex::encode(payload.exact_digest_input()),"relevant_objects":relevant.iter().map(hex::encode).collect::<Vec<_>>()}),
            );
            let path = exchange_directory
                .path()
                .join(format!("request-{}.json", pending.request_id()));
            write_exchange_file(&path, pending.request_bytes()).unwrap();
            let mut incoming = None;
            for path in request_paths(exchange_directory.path(), &Default::default()).unwrap() {
                let file = prepare_request_file(
                    authority_database,
                    &current_head,
                    target,
                    administrator.certificate,
                    administrator.binding,
                    &path,
                )
                .expect("retained completed files must allow discovery of the new current request");
                if let Some(reply) = &file.cached {
                    assert_eq!(reply, &retained_replies[&file.request.request_id()]);
                } else {
                    assert_eq!(file.request.request_id(), pending.request_id());
                    assert!(incoming.replace(file).is_none());
                }
            }
            let PreparedRequestFile {
                request: verified,
                payload: request,
                ..
            } = incoming.expect("current request must reach authorization");
            if stage == 0 {
                for trigger in [
                    "CREATE TRIGGER injected_crash BEFORE INSERT ON operator_admin_replay WHEN NEW.dimension=1 BEGIN SELECT RAISE(ABORT,'simulated interruption'); END",
                    "CREATE TRIGGER injected_crash BEFORE INSERT ON local_audit_event BEGIN SELECT RAISE(ABORT,'simulated interruption'); END",
                    "CREATE TRIGGER injected_crash BEFORE INSERT ON operator_authority_target BEGIN SELECT RAISE(ABORT,'simulated interruption'); END",
                    "CREATE TRIGGER injected_crash BEFORE UPDATE OF reply_bytes ON operator_authority_request BEGIN SELECT RAISE(ABORT,'simulated interruption'); END",
                ] {
                    authority_database.execute(trigger, &[]).unwrap();
                    assert!(
                        core.authorize(
                            target,
                            &verified,
                            args(&request.args).unwrap(),
                            session.proof()
                        )
                        .is_err()
                    );
                    assert_eq!(
                        authority_database
                            .query_row("SELECT COUNT(*) FROM operator_admin_replay", &[])
                            .unwrap()
                            .unwrap()
                            .integer(0)
                            .unwrap(),
                        0,
                        "interruption must roll back BOTH replay dimensions"
                    );
                    assert_eq!(
                        authority_database
                            .query_row("SELECT COUNT(*) FROM local_audit_event", &[])
                            .unwrap()
                            .unwrap()
                            .integer(0)
                            .unwrap(),
                        0,
                        "interruption must roll back the audit"
                    );
                    assert_eq!(
                        authority_database
                            .query_row("SELECT COUNT(*) FROM operator_authority_target", &[])
                            .unwrap()
                            .unwrap()
                            .integer(0)
                            .unwrap(),
                        0,
                        "interruption must roll back publication"
                    );
                    assert_eq!(authority_database.query_row("SELECT state FROM operator_authority_request WHERE request_hash=?1",&[blob(&fixed::<32>(&verified.request_id()).unwrap())]).unwrap().unwrap().integer(0).unwrap(),0);
                    let reopened =
                        lifecycle::reopen_database(administrator.database.directory.path());
                    assert!(
                        !reopened
                            .query_row("SELECT root_signature FROM operator_authority_staged", &[])
                            .unwrap()
                            .unwrap()
                            .blob(0)
                            .unwrap()
                            .is_empty(),
                        "exact public Root signature must survive reopen"
                    );
                    assert_eq!(root_provider.signatures_produced(), 1);
                    authority_database
                        .execute("DROP TRIGGER injected_crash", &[])
                        .unwrap();
                }
            }
            if stage == 0 {
                let nonce = fixed::<32>(&verified.request_id()).unwrap();
                authority_database.execute("INSERT INTO operator_admin_replay(organization_id,dimension,replay_value) VALUES(?1,1,?2)",&[blob(anchor.organization_id().as_bytes()),blob(&nonce)]).unwrap();
                let denied = core.authorize(
                    target,
                    &verified,
                    args(&request.args).unwrap(),
                    session.proof(),
                );
                assert!(
                    matches!(
                        denied,
                        Err(AuthorityError::Admin(AdminError::Trust(
                            ea_trust::TrustError::AuthReplay
                        )))
                    ),
                    "a foreign consumed nonce must never be reported fresh"
                );
                assert_eq!(
                    authority_database
                        .query_row(
                            "SELECT COUNT(*) FROM operator_admin_replay WHERE dimension=0",
                            &[]
                        )
                        .unwrap()
                        .unwrap()
                        .integer(0)
                        .unwrap(),
                    0
                );
                assert_eq!(
                    authority_database
                        .query_row(
                            "SELECT COUNT(*) FROM operator_admin_replay WHERE dimension=1",
                            &[]
                        )
                        .unwrap()
                        .unwrap()
                        .integer(0)
                        .unwrap(),
                    1
                );
                assert_eq!(
                    authority_database
                        .query_row("SELECT COUNT(*) FROM local_audit_event", &[])
                        .unwrap()
                        .unwrap()
                        .integer(0)
                        .unwrap(),
                    0
                );
                // Remove only the test-injected foreign collision before the
                // independent race scenario; production exposes no reset API.
                authority_database.execute("DELETE FROM operator_admin_replay WHERE organization_id=?1 AND dimension=1 AND replay_value=?2",&[blob(anchor.organization_id().as_bytes()),blob(&nonce)]).unwrap();
            }
            let encrypted = if stage == 0 {
                struct SimultaneousReply<'a> {
                    barrier: Arc<(std::sync::Mutex<usize>, std::sync::Condvar)>,
                    signer: &'a Signing,
                }
                impl ExchangeSigner for SimultaneousReply<'_> {
                    fn sign(&self, input: &[u8]) -> Result<[u8; 64], ExchangeError> {
                        let (lock, changed) = self.barrier.as_ref();
                        let mut count = lock.lock().unwrap();
                        *count += 1;
                        changed.notify_all();
                        let (count, _) = changed
                            .wait_timeout_while(count, std::time::Duration::from_secs(5), |count| {
                                *count < 2
                            })
                            .unwrap();
                        if *count < 2 {
                            return Err(ExchangeError::Timeout);
                        }
                        self.signer.sign(input)
                    }
                }
                let barrier = Arc::new((std::sync::Mutex::new(0), std::sync::Condvar::new()));
                let results = std::thread::scope(|scope| {
                    let mut workers = Vec::new();
                    for _ in 0..2 {
                        let source_line = line.clone();
                        let directory = administrator.database.directory.path();
                        let anchor = &anchor;
                        let admin_provider = admin_provider.clone();
                        let root_provider = root_provider.clone();
                        let proof = session.proof();
                        let shared_head = &current_head;
                        let request_bytes = pending.request_bytes().to_vec();
                        let signer = SimultaneousReply {
                            barrier: barrier.clone(),
                            signer: &exchange_signer,
                        };
                        let admin_certificate = administrator.certificate;
                        let admin_binding = administrator.binding;
                        workers.push(scope.spawn(move || {
                            let reopened = lifecycle::reopen_database(directory);
                            let store = crate::operator_trust_store::OperatorTrustStateStore::open(
                                reopened.clone(),
                                authority_key,
                                anchor.chain_id(),
                                anchor.trust_anchor_hash(),
                                UnixMillis::new(0),
                            )
                            .unwrap();
                            let source = source_line.source();
                            let head = shared_head;
                            let (verified, request) = verify_request(
                                &request_bytes,
                                head,
                                target,
                                admin_certificate,
                                admin_binding,
                            )
                            .unwrap();
                            let core = AuthorityCore {
                                database: &reopened,
                                store: &store,
                                source: &source,
                                anchor,
                                state_key: authority_key,
                                head,
                                admin_certificate,
                                admin_binding,
                                admin_handle: admin_provider.handle(),
                                admin_provider,
                                root_handle: root_provider.handle(),
                                root_provider,
                                current: &|| Ok(UnixMillis::new(1000)),
                                reply_signer: &signer,
                            };
                            for _ in 0..5 {
                                match core.authorize(
                                    target,
                                    &verified,
                                    args(&request.args).unwrap(),
                                    proof,
                                ) {
                                    Err(error) if error.code() == "EA-TRUST-STATE-CONFLICT" => {
                                        continue;
                                    }
                                    result => return result.is_ok(),
                                }
                            }
                            false
                        }));
                    }
                    workers
                        .into_iter()
                        .map(|worker| worker.join().unwrap())
                        .collect::<Vec<_>>()
                });
                assert_eq!(
                    results.into_iter().filter(|ok| *ok).count(),
                    1,
                    "two independent connections must publish exactly once"
                );
                assert_eq!(
                    root_provider.signatures_produced(),
                    1,
                    "both resumptions must use the staged Root signature"
                );
                begin_request(authority_database, pending.request_bytes())
                    .unwrap()
                    .unwrap()
            } else {
                core.authorize(
                    target,
                    &verified,
                    args(&request.args).unwrap(),
                    session.proof(),
                )
                .unwrap()
            };
            let response = pending.open_reply(&encrypted, &exchange_public).unwrap();
            retained_replies.insert(pending.request_id(), encrypted.clone());
            let authorization = bytes(response["authorization"].as_str().unwrap()).unwrap();
            let signed_target = bytes(response["target"].as_str().unwrap()).unwrap();
            if stage == 0 || stage == 2 {
                use ea_format::{
                    BindingLifecycleContextV1, LocalAuditActionV1, LocalAuditOutcomeV1,
                };
                let new = (stage == 0).then(|| object_hash(&signed_target));
                let old = (stage == 2).then_some(binding);
                let sequence = if stage == 0 { 101 } else { 201 };
                for variant in 0..8 {
                    let header = if variant == 7 {
                        None
                    } else if variant == 2 {
                        Some(ObjectHash::from(Hash32::ZERO))
                    } else if stage == 0 && variant == 0 {
                        // operator_host::host_audit uses an authenticated
                        // device without claiming an operator session.
                        None
                    } else {
                        Some(administrator.binding)
                    };
                    let context = BindingLifecycleContextV1::new(
                        if variant == 5 {
                            Some(administrator.binding)
                        } else {
                            old
                        },
                        if variant == 4 {
                            Some(ObjectHash::from(Hash32::ZERO))
                        } else if variant == 6 {
                            None
                        } else {
                            new
                        },
                        ChainSequence::new(sequence + u64::from(variant == 3)),
                    );
                    let fields = ea_format::LocalAuditEventCoreFieldsV1 {
                        event_id: ea_types::EventId::try_from(&[0x35; 16][..]).unwrap(),
                        organization_id: anchor.organization_id(),
                        device_id: current_head
                            .active_certificate_fields(administrator.certificate)
                            .unwrap()
                            .device_id,
                        operator_binding_object_hash: header,
                        signer_certificate_object_hash: ObjectHash::try_from(
                            administrator.certificate.as_bytes().as_slice(),
                        )
                        .unwrap(),
                        action: if stage == 0 {
                            LocalAuditActionV1::BindingChange(context)
                        } else {
                            LocalAuditActionV1::Revocation(context)
                        },
                        outcome: LocalAuditOutcomeV1::Completed,
                        effective_now: UnixMillis::new(1000),
                        nonce: [0x35; 32],
                    };
                    let exact_core = ea_format::encode_local_audit_core(&fields).unwrap();
                    if variant == 0 {
                        audit_event(
                            &exact_core,
                            &current_head,
                            administrator.certificate,
                            administrator.binding,
                            UnixMillis::new(1000),
                        )
                        .expect("host action must survive the typed header guard");
                    }
                    let checked = audit_event(
                        &exact_core,
                        &current_head,
                        administrator.certificate,
                        administrator.binding,
                        UnixMillis::new(1000),
                    )
                    .and_then(|event| {
                        verify_audit_scope(
                            authority_database,
                            &current_head,
                            target,
                            administrator.binding,
                            &event,
                        )
                    });
                    let allowed = variant <= 1
                        || (stage == 2 && variant == 6)
                        || (stage == 0 && variant == 7);
                    assert_eq!(
                        checked.is_ok(),
                        allowed,
                        "stage {stage} lifecycle audit variant {variant}"
                    );
                }
                if stage == 0 {
                    let ea_format::ParsedArchiveObject::Trust(original) =
                        ea_format::decode_exact_object(&signed_target).unwrap()
                    else {
                        panic!("signed binding")
                    };
                    let mut signature = original.value().signatures()[0].clone();
                    *signature.last_mut().unwrap() ^= 1;
                    let forged = ea_format::encode_trust(
                        &ea_format::TrustObjectV1::new(
                            exact_audit_trust(&signed_target).unwrap(),
                            vec![signature],
                        )
                        .unwrap(),
                    )
                    .unwrap();
                    let forged_hash = object_hash(forged.as_bytes());
                    authority_database.execute("INSERT INTO operator_authority_target SELECT ?1,authorization_hash,request_hash,target_certificate_hash,authorization,?2,action_code FROM operator_authority_target WHERE target_hash=?3", &[blob(forged_hash.as_bytes()),blob(forged.as_bytes()),blob(object_hash(&signed_target).as_bytes())]).unwrap();
                    let audit_fields = ea_format::LocalAuditEventCoreFieldsV1 {
                        event_id: ea_types::EventId::try_from(&[0x36; 16][..]).unwrap(),
                        organization_id: anchor.organization_id(),
                        device_id: current_head
                            .active_certificate_fields(administrator.certificate)
                            .unwrap()
                            .device_id,
                        operator_binding_object_hash: None,
                        signer_certificate_object_hash: ObjectHash::try_from(
                            administrator.certificate.as_bytes().as_slice(),
                        )
                        .unwrap(),
                        action: LocalAuditActionV1::BindingChange(BindingLifecycleContextV1::new(
                            None,
                            Some(forged_hash),
                            ChainSequence::new(101),
                        )),
                        outcome: LocalAuditOutcomeV1::Completed,
                        effective_now: UnixMillis::new(1000),
                        nonce: [0x36; 32],
                    };
                    let encoded = ea_format::encode_local_audit_core(&audit_fields).unwrap();
                    let audit = audit_event(
                        &encoded,
                        &current_head,
                        administrator.certificate,
                        administrator.binding,
                        UnixMillis::new(1000),
                    )
                    .unwrap();
                    assert!(
                        verify_audit_scope(
                            authority_database,
                            &current_head,
                            target,
                            administrator.binding,
                            &audit
                        )
                        .is_err(),
                        "cache row metadata cannot replace actual Root signature verification"
                    );
                    authority_database
                        .execute(
                            "DELETE FROM operator_authority_target WHERE target_hash=?1",
                            &[blob(forged_hash.as_bytes())],
                        )
                        .unwrap();
                }
            }
            assert_eq!(
                begin_request(authority_database, pending.request_bytes())
                    .unwrap()
                    .unwrap(),
                encrypted
            );
            assert_eq!(
                bytes(
                    pending.open_reply(&encrypted, &exchange_public).unwrap()["target"]
                        .as_str()
                        .unwrap()
                )
                .unwrap(),
                signed_target
            );
            if stage == 1 {
                let audit_fields = ea_format::LocalAuditEventCoreFieldsV1 {
                    event_id: ea_types::EventId::try_from(&[0x34; 16][..]).unwrap(),
                    organization_id: anchor.organization_id(),
                    device_id: current_head
                        .active_certificate_fields(administrator.certificate)
                        .unwrap()
                        .device_id,
                    operator_binding_object_hash: Some(administrator.binding),
                    signer_certificate_object_hash: ObjectHash::try_from(
                        administrator.certificate.as_bytes().as_slice(),
                    )
                    .unwrap(),
                    action: ea_format::LocalAuditActionV1::BindingChange(
                        ea_format::BindingLifecycleContextV1::new(
                            None,
                            Some(object_hash(&signed_target)),
                            ChainSequence::new(101),
                        ),
                    ),
                    outcome: ea_format::LocalAuditOutcomeV1::Completed,
                    effective_now: UnixMillis::new(1000),
                    nonce: [0x34; 32],
                };
                let audit_core = ea_format::encode_local_audit_core(&audit_fields).unwrap();
                let audit = audit_event(
                    &audit_core,
                    &current_head,
                    administrator.certificate,
                    administrator.binding,
                    UnixMillis::new(1000),
                )
                .unwrap();
                assert!(
                    verify_audit_scope(
                        authority_database,
                        &current_head,
                        target,
                        administrator.binding,
                        &audit
                    )
                    .is_err(),
                    "a signed Registry target must not become an operator binding in a proxy audit"
                );
            }
            // The target performs its own catalogue/head selection and durable replay
            // consumption; authority consumption must not poison the target's store.
            let mut all = relevant.clone();
            all.push(authorization.clone());
            all.push(signed_target.clone());
            let target_source = crate::operator_remote::ObjectOverlay::new(&source, &all);
            let target_trust = verify_trust(
                &anchor,
                &target_source,
                load_trust_state(&mut target_store, target_key).unwrap(),
            )
            .unwrap();
            let candidate =
                verify_registry_candidate(&target_trust, current_head.proposed_sequence()).unwrap();
            let time =
                prepare_local_time(&mut target_store, &candidate, UnixMillis::new(1000), &[])
                    .unwrap();
            let RegistrySelectionOutcome::Selected(verified_head) =
                select_registry_head(candidate, time, None).unwrap()
            else {
                panic!("target head")
            };
            assert_eq!(
                verified_head.registry_head_hash().as_bytes(),
                current_head.registry_head_hash().as_bytes()
            );
            let proof = ea_trust::verify_authorized_trust_target(
                &target_trust,
                Some(&verified_head),
                &signed_target,
                UnixMillis::new(1000),
                current_head.proposed_sequence(),
            )
            .unwrap();
            ea_trust::consume_admin_authorization(&mut target_store, &proof).unwrap();
            assert!(ea_trust::consume_admin_authorization(&mut target_store, &proof).is_err());
            assert!(ea_trust::consume_admin_authorization(&mut authority_store, &proof).is_err());
            (authorization, signed_target, all)
        };
        if stage == 0 {
            binding = object_hash(&signed_target);
            relevant = vec![authorization, signed_target];
        } else {
            for bytes in &all {
                line.add_object(bytes.clone());
            }
            current_head = select_durable(
                &line.source(),
                &anchor,
                &mut authority_store,
                authority_key,
                if stage == 1 { 101 } else { 201 },
            );
            let target_head = select_durable(
                &line.source(),
                &anchor,
                &mut target_store,
                target_key,
                if stage == 1 { 101 } else { 201 },
            );
            assert_eq!(
                current_head.registry_head_hash().as_bytes(),
                target_head.registry_head_hash().as_bytes()
            );
            if stage == 1 {
                assert!(
                    target_head
                        .active_operator_binding_fields(binding)
                        .is_some()
                );
            } else {
                assert!(
                    target_head
                        .active_operator_binding_fields(binding)
                        .is_none()
                );
                assert!(
                    target_head
                        .revoked_operator_binding_fields(binding)
                        .is_some()
                );
            }
            relevant.clear();
        }
        // Reopen the encrypted authority store after each transition while
        // retaining EVERY exchange file, including requests for earlier heads.
        let reopened = lifecycle::reopen_database(administrator.database.directory.path());
        reopened.execute("PRAGMA query_only=ON", &[]).unwrap();
        let paths = request_paths(exchange_directory.path(), &Default::default()).unwrap();
        assert_eq!(paths.len(), stage + 1);
        for path in paths {
            let request = prepare_request_file(
                &reopened,
                &current_head,
                target,
                administrator.certificate,
                administrator.binding,
                &path,
            )
            .expect("completed old-head files must not interrupt the later directory run");
            let cached = request
                .cached
                .expect("completed request cannot become a new mutation");
            assert_eq!(&cached, &retained_replies[&request.request.request_id()]);
            publish_reply_file(
                exchange_directory.path(),
                &request.request.request_id(),
                &cached,
            )
            .unwrap();
        }
        if stage < 2 {
            targets.push(OperatorTrustTarget::Registry(
                ea_format::RegistryEventFieldsV1 {
                    organization_id: anchor.organization_id(),
                    registry_version: RegistryVersion::new(
                        current_head.registry_version().get() + 1,
                    ),
                    previous_registry_hash: Some(
                        Hash32::try_from(current_head.registry_head_hash().as_bytes().as_slice())
                            .unwrap(),
                    ),
                    effective_from_sequence: ChainSequence::new(if stage == 0 { 101 } else { 201 }),
                    valid_through_sequence: ChainSequence::new(if stage == 0 { 200 } else { 300 }),
                    issued_at: UnixMillis::new(1000),
                    not_before: UnixMillis::new(1000),
                    not_after: UnixMillis::new(10_000_000),
                    policy_object_hash: current_head.policy_object_hash(),
                    change: if stage == 0 {
                        RegistryChangeV1::OperatorBinding {
                            object_hash: binding,
                        }
                    } else {
                        RegistryChangeV1::Target {
                            target_kind: 1,
                            object_hash: binding,
                        }
                    },
                    root_key_thumbprint: current_head.root_certificate_fields().root_key_thumbprint,
                },
            ));
        }
    }
    assert_eq!(root_provider.signatures_produced(), 3);
    assert_eq!(
        authority_database
            .query_row("SELECT COUNT(*) FROM operator_authority_target", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        3
    );
    assert_eq!(
        authority_database
            .query_row("SELECT COUNT(*) FROM local_audit_event", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        3
    );
    assert!(
        target_database
            .database
            .query_row("SELECT singleton FROM operator_profile", &[])
            .unwrap()
            .is_none()
    );
    // Both persisted stores remain readable with independent device keys.
    authority_store.load(authority_key).unwrap();
    target_store.load(target_key).unwrap();
}

#[test]
#[cfg(unix)]
fn private_console_drains_rejected_line_and_refuses_input_after_shared_deadline() {
    use std::{
        io::Cursor,
        time::{Duration, Instant},
    };
    let mut long = Cursor::new(b"overlong secret\nnext\n".to_vec());
    assert!(read_private_line(&mut long, 4, Instant::now() + Duration::from_secs(1)).is_err());
    assert_eq!(
        long.position(),
        b"overlong secret\n".len() as u64,
        "rejected private input must not remain queued when terminal mode is restored"
    );
    let mut expired = Cursor::new(b"secret\n".to_vec());
    assert!(
        read_private_line(&mut expired, 64, Instant::now()).is_err(),
        "expired shared prompt must not accept another line"
    );
    assert_eq!(expired.position(), 0);
}

#[test]
fn the_same_person_on_another_device_is_not_a_replacement_of_this_devices_binding() {
    let mut line = fixtures::RegistryLineBuilder::new();
    line.push(
        fixtures::ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        fixtures::HeadOptions::default(),
    );
    let first = CertificateHash::from(
        line.push(
            fixtures::ActionSpec::Device {
                kind: CertificateKindV1::Reader,
                marker: 0x61,
                effective_from: None,
            },
            fixtures::HeadOptions::default(),
        )
        .direct_object_hash
        .unwrap(),
    );
    let second = CertificateHash::from(
        line.push(
            fixtures::ActionSpec::Device {
                kind: CertificateKindV1::Reader,
                marker: 0x62,
                effective_from: None,
            },
            fixtures::HeadOptions {
                signing_public_key_override: Some(lifecycle::key([0x69; 32])),
                kem_public_key_override: Some(CanonicalPublicCoseKey::x25519([0x66; 32]).unwrap()),
                ..fixtures::HeadOptions::default()
            },
        )
        .direct_object_hash
        .unwrap(),
    );
    let binding = line
        .push(
            fixtures::ActionSpec::OperatorBinding {
                certificate_hash: ObjectHash::try_from(first.as_bytes().as_slice()).unwrap(),
                role: OperatorRoleV1::Reader,
                marker: 0x72,
                effective_from: None,
            },
            fixtures::HeadOptions::default(),
        )
        .direct_object_hash
        .unwrap();
    let (database, directory) = database();
    let subject = OperatorSubjectId::try_from(&[0x72; 16][..]).unwrap();
    let head = select(&line, &database);
    assert!(head.active_certificate_fields(first).is_some());
    assert!(head.active_certificate_fields(second).is_some());
    assert!(previous_binding(&head, [binding], subject, OperatorRoleV1::Reader, first).is_err());
    assert!(
        previous_binding(&head, [binding], subject, OperatorRoleV1::Reader, second)
            .unwrap()
            .is_none(),
        "an active binding on another device cannot prevent enrollment here"
    );
    line.push(
        fixtures::ActionSpec::Revoke {
            target_kind: 1,
            object_hash: binding,
        },
        fixtures::HeadOptions::default(),
    );
    let head = select(&line, &database);
    assert!(
        previous_binding(&head, [binding], subject, OperatorRoleV1::Reader, first).unwrap()
            == Some(binding)
    );
    assert!(
        previous_binding(&head, [binding], subject, OperatorRoleV1::Reader, second)
            .unwrap()
            .is_none(),
        "a revoked binding on another device is not a predecessor here"
    );
    drop(database);
    std::fs::remove_dir_all(directory).unwrap();
}
