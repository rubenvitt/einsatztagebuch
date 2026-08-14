use ea_crypto::{entry_hash, object_hash, record_digest};
use ea_format::{
    CertificateKindV1, CheckpointCoreFieldsV1, CheckpointCoreV1, DestroyedEntryStubV1,
    DeviceCertificateFieldsV1, EAG_PREFIX_V1, ECP_PREFIX_V1, EDS_PREFIX_V1, EIP_PREFIX_V1,
    ESR_MAX_RAW_BYTES_V1, ESR_PREFIX_V1, ETB_PREFIX_V1, EvidenceObjectV1, GrantBodyFieldsV1,
    GrantBodyV1, GrantKindV1, GrantPurposeV1, GrantV1, KeyProtectionProfileV1,
    OrganizationAdminAuthorizationFieldsV1, Parsed, ParsedArchiveObject, ReceiptCoreFieldsV1,
    ReceiptCoreV1, ReceiptV1, TrustObjectV1, TrustPayloadV1, TrustSubtypeV1, decode_exact_object,
    encode_destroyed_entry_stub, encode_entry_package, encode_evidence, encode_grant,
    encode_receipt, encode_trust,
};
use ea_types::{ChainSequence, ObjectHash, RegistryVersion, UnixMillis};

mod support;

#[test]
fn every_family_has_the_exact_nine_byte_prefix_and_positional_shape() {
    let fixtures = support::all_valid_objects();
    let expected = [
        [0x85, 0x44, b'E', b'A', b'1', 0, 1, 1, 0x80],
        [0x85, 0x44, b'E', b'A', b'1', 0, 2, 1, 0x80],
        [0x85, 0x44, b'E', b'A', b'1', 0, 3, 1, 0x80],
        [0x85, 0x44, b'E', b'A', b'1', 0, 4, 1, 0x80],
        [0x85, 0x44, b'E', b'A', b'1', 0, 5, 1, 0x80],
        [0x85, 0x44, b'E', b'A', b'1', 0, 6, 1, 0x80],
    ];
    assert_eq!(
        [
            EIP_PREFIX_V1,
            EAG_PREFIX_V1,
            ESR_PREFIX_V1,
            ECP_PREFIX_V1,
            ETB_PREFIX_V1,
            EDS_PREFIX_V1,
        ],
        expected
    );

    for ((bytes, expected_prefix), expected_tag) in fixtures.iter().zip(expected).zip(1_u8..=6) {
        assert_eq!(&bytes[..9], expected_prefix);
        assert_eq!(support::top_level_type(bytes), expected_tag);
        let parsed = decode_exact_object(bytes).unwrap();
        let reencoded = match parsed {
            ParsedArchiveObject::Entry(value) => {
                assert_exact(&value, bytes);
                encode_entry_package(value.value()).unwrap()
            }
            ParsedArchiveObject::Grant(value) => {
                assert_exact(&value, bytes);
                encode_grant(value.value()).unwrap()
            }
            ParsedArchiveObject::Receipt(value) => {
                assert_exact(&value, bytes);
                encode_receipt(value.value()).unwrap()
            }
            ParsedArchiveObject::Evidence(value) => {
                assert_exact(&value, bytes);
                encode_evidence(value.value()).unwrap()
            }
            ParsedArchiveObject::Trust(value) => {
                assert_exact(&value, bytes);
                encode_trust(value.value()).unwrap()
            }
            ParsedArchiveObject::Destroyed(value) => {
                assert_exact(&value, bytes);
                encode_destroyed_entry_stub(value.value()).unwrap()
            }
        };
        assert_eq!(reencoded.as_bytes(), bytes);
    }
}

fn assert_exact<T>(parsed: &Parsed<T>, input: &[u8]) {
    assert_eq!(parsed.exact_bytes().as_bytes(), input);
    assert_eq!(
        parsed.object_hash().as_bytes(),
        object_hash(input).as_bytes()
    );
}

#[test]
fn public_typed_construction_paths_encode_five_new_non_entry_objects() {
    let signer = support::signer();
    let signer_thumbprint = support::signer_thumbprint();
    let certificate_hash = support::certificate(3);

    let grant_body = GrantBodyV1::new(GrantBodyFieldsV1 {
        organization_id: support::organization(1),
        chain_id: support::chain(2),
        entry_hash: support::entry_hash(3),
        kind: GrantKindV1::Initial,
        purpose: GrantPurposeV1::Reader,
        recipient_key_thumbprint: support::key_thumbprint(4),
        recipient_certificate_hash: support::certificate(5),
        issuer_key_thumbprint: signer_thumbprint,
        issuer_certificate_hash: certificate_hash,
        registry_version: RegistryVersion::new(6),
        registry_head_hash: support::typed_hash(7),
        created_at_device: UnixMillis::new(8),
        original_recovery_grant_object_hash: None,
        grant_authorization_object_hash: None,
        encapsulated_key: [9; 32],
        wrapped_cek: [10; 48],
    })
    .unwrap();
    let grant_signature = signer.sign_initial_grant(grant_body.exact_bytes()).unwrap();
    let grant = GrantV1::new(grant_body, grant_signature).unwrap();
    let grant_bytes = encode_grant(&grant).unwrap().into_vec();

    let receipt_core = ReceiptCoreV1::new(ReceiptCoreFieldsV1 {
        organization_id: support::organization(1),
        chain_id: support::chain(2),
        chain_sequence: ChainSequence::new(0),
        entry_hash: support::entry_hash(3),
        entry_object_hash: support::typed_object_hash(4),
        previous_entry_hash: None,
        registry_version: RegistryVersion::new(5),
        registry_head_hash: support::typed_hash(6),
        policy_object_hash: support::typed_object_hash(7),
        initial_grant_plan_hash: support::typed_hash(8),
        initial_grant_object_hashes: vec![support::typed_object_hash(9)],
        accepted_at_server: UnixMillis::new(10),
        evidence_due_at: None,
        server_key_thumbprint: signer_thumbprint,
        server_certificate_hash: certificate_hash,
    })
    .unwrap();
    let receipt_signature = signer.sign_receipt(receipt_core.exact_bytes()).unwrap();
    let receipt = ReceiptV1::new(receipt_core, receipt_signature).unwrap();
    let receipt_bytes = encode_receipt(&receipt).unwrap().into_vec();

    let checkpoint_core = CheckpointCoreV1::new(CheckpointCoreFieldsV1 {
        organization_id: support::organization(1),
        chain_id: support::chain(2),
        covered_from_sequence: ChainSequence::new(0),
        covered_through_sequence: ChainSequence::new(0),
        head_entry_hash: support::entry_hash(3),
        registry_head_hash: support::typed_hash(4),
        issued_at_server: UnixMillis::new(5),
        previous_evidence_hash: None,
    })
    .unwrap();
    let checkpoint_signature = signer
        .sign_checkpoint(certificate_hash, checkpoint_core.exact_bytes())
        .unwrap();
    let evidence = EvidenceObjectV1::standard(checkpoint_core, checkpoint_signature).unwrap();
    let evidence_bytes = encode_evidence(&evidence).unwrap().into_vec();

    let trust_payload =
        TrustPayloadV1::organization_admin_authorization(OrganizationAdminAuthorizationFieldsV1 {
            authorization_id: support::authorization_id(1),
            organization_id: support::organization(2),
            registry_version: RegistryVersion::new(3),
            registry_head_hash: support::typed_hash(4),
            admin_key_thumbprint: signer_thumbprint,
            admin_certificate_hash: certificate_hash,
            admin_operator_binding_object_hash: support::typed_object_hash(5),
            action_code: 0,
            target_trust_subtype: TrustSubtypeV1::DeviceCertificate,
            authorized_trust_core_hash: support::typed_hash(6),
            issued_at: UnixMillis::new(7),
            expires_at: UnixMillis::new(8),
            nonce: [9; 32],
        })
        .unwrap();
    let trust_signature = signer
        .sign_organization_admin_trust_digest(trust_payload.exact_digest_input())
        .unwrap();
    let trust = TrustObjectV1::new(trust_payload, vec![trust_signature]).unwrap();
    let trust_bytes = encode_trust(&trust).unwrap().into_vec();

    let eip = support::valid_eip(vec![0x5a; 16]);
    let entry = match decode_exact_object(&eip).unwrap() {
        ParsedArchiveObject::Entry(value) => value,
        _ => unreachable!(),
    };
    let destroyed = DestroyedEntryStubV1::new(
        entry.value().signed_manifest().clone(),
        entry.value().writer_signature().to_vec(),
        object_hash(&eip),
        support::destruction_id(10),
        support::typed_object_hash(11),
    )
    .unwrap();
    let destroyed_bytes = encode_destroyed_entry_stub(&destroyed).unwrap().into_vec();

    for (bytes, expected_type) in [
        (grant_bytes, 2),
        (receipt_bytes, 3),
        (evidence_bytes, 4),
        (trust_bytes, 5),
        (destroyed_bytes, 6),
    ] {
        assert_eq!(support::top_level_type(&bytes), expected_type);
        assert!(decode_exact_object(&bytes).is_ok());
    }
}

#[test]
fn public_encoder_rejects_a_typed_object_above_its_family_raw_cap() {
    let accepted = receipt_with_grant_hash_count(1_911);
    let accepted = encode_receipt(&accepted).unwrap();
    assert_eq!(accepted.as_bytes().len(), ESR_MAX_RAW_BYTES_V1);
    assert!(decode_exact_object(accepted.as_bytes()).is_ok());

    let rejected = receipt_with_grant_hash_count(1_912);
    let error = encode_receipt(&rejected)
        .err()
        .expect("an encoder must not emit an object its decoder rejects at the family cap");
    assert_eq!(error.code(), "EA-FORMAT-ESR-RAW-LIMIT");
}

#[test]
fn public_encoders_apply_the_decoders_structural_cbor_budgets() {
    let oversized_item = support::constructed_timestamp_with_response_length(1_048_593);
    assert_eq!(
        encode_evidence(&oversized_item).err().unwrap().code(),
        "EA-CBOR-ITEM-LIMIT"
    );

    let oversized_container = support::constructed_policy_with_format_version_count(10_001);
    assert_eq!(
        encode_trust(&oversized_container).err().unwrap().code(),
        "EA-CBOR-CONTAINER-LIMIT"
    );
}

fn receipt_with_grant_hash_count(count: u32) -> ReceiptV1 {
    let signer = support::signer();
    let certificate_hash = support::certificate(3);
    let initial_grant_object_hashes = (0_u32..count)
        .map(|value| {
            let mut bytes = [0; 32];
            bytes[28..].copy_from_slice(&value.to_be_bytes());
            ObjectHash::try_from(bytes.as_slice()).unwrap()
        })
        .collect();
    let core = ReceiptCoreV1::new(ReceiptCoreFieldsV1 {
        organization_id: support::organization(1),
        chain_id: support::chain(2),
        chain_sequence: ChainSequence::new(0),
        entry_hash: support::entry_hash(3),
        entry_object_hash: support::typed_object_hash(4),
        previous_entry_hash: None,
        registry_version: RegistryVersion::new(u64::MAX),
        registry_head_hash: support::typed_hash(6),
        policy_object_hash: support::typed_object_hash(7),
        initial_grant_plan_hash: support::typed_hash(8),
        initial_grant_object_hashes,
        accepted_at_server: UnixMillis::new(24),
        evidence_due_at: None,
        server_key_thumbprint: support::signer_thumbprint(),
        server_certificate_hash: certificate_hash,
    })
    .unwrap();
    let signature = signer.sign_receipt(core.exact_bytes()).unwrap();
    ReceiptV1::new(core, signature).unwrap()
}

#[test]
fn decoder_preserves_exact_input_and_hashes_it_without_reserialization() {
    let bytes = support::valid_eip(vec![0x5a; 17]);
    let parsed = match decode_exact_object(&bytes).unwrap() {
        ParsedArchiveObject::Entry(parsed) => parsed,
        _ => panic!("fixture must decode as entry"),
    };

    assert_eq!(parsed.exact_bytes().as_bytes(), bytes);
    assert_eq!(
        parsed.object_hash().as_bytes(),
        object_hash(&bytes).as_bytes()
    );
    assert_eq!(parsed.value().manifest().ciphertext_length(), 17);
    assert_eq!(parsed.value().ciphertext(), &[0x5a; 17]);

    let signed_manifest = parsed.value().signed_manifest().exact_bytes();
    let expected_entry_hash = entry_hash(
        record_digest(signed_manifest),
        parsed.value().writer_signature(),
    );
    assert_eq!(
        parsed.value().entry_hash().as_bytes(),
        expected_entry_hash.as_bytes()
    );

    let mut alternate = bytes.clone();
    alternate.push(0x00);
    assert_ne!(
        object_hash(&alternate).as_bytes(),
        parsed.object_hash().as_bytes()
    );
}

#[test]
fn encoder_derives_manifest_ciphertext_length_from_the_exact_bstr() {
    let encoded = support::valid_eip(vec![0x33; 17]);
    assert_eq!(support::manifest_ciphertext_length(&encoded), 17);
    assert_eq!(support::exact_ciphertext_bstr(&encoded).len(), 17);
}

#[test]
fn ciphertext_boundaries_are_exact_and_checked_before_encoding() {
    assert_eq!(
        support::manifest_for_ciphertext(&[0; 15])
            .err()
            .unwrap()
            .code(),
        "EA-FORMAT-CIPHERTEXT-LENGTH"
    );
    let maximum = support::valid_eip(vec![0x7a; 1_048_592]);
    let parsed = decode_exact_object(&maximum).unwrap();
    assert!(matches!(parsed, ParsedArchiveObject::Entry(_)));
    assert_eq!(
        support::manifest_for_ciphertext(&vec![0; 1_048_593])
            .err()
            .unwrap()
            .code(),
        "EA-FORMAT-CIPHERTEXT-LENGTH"
    );
}

#[test]
fn exact_ciphertext_hash_and_signed_manifest_digest_bind_the_body() {
    assert_eq!(
        decode_exact_object(&support::eip_with_same_length_ciphertext_tamper())
            .unwrap_err()
            .code(),
        "EA-FORMAT-SHAPE"
    );
    assert_eq!(
        decode_exact_object(&support::eip_with_stale_signed_manifest_signature())
            .unwrap_err()
            .code(),
        "EA-FORMAT-COSE"
    );
}

#[test]
fn cose_content_type_and_writer_certificate_hash_correlate_locally() {
    assert_eq!(
        decode_exact_object(&support::eip_with_wrong_cose_content_type())
            .unwrap_err()
            .code(),
        "EA-FORMAT-COSE"
    );
    assert_eq!(
        decode_exact_object(&support::eip_with_wrong_cose_certificate_hash())
            .unwrap_err()
            .code(),
        "EA-FORMAT-COSE"
    );
}

#[test]
fn predecessor_nullability_correlates_with_genesis_sequence() {
    for invalid in [
        support::eip_with_sequence_and_predecessor(0, Some([0x90; 32])),
        support::eip_with_sequence_and_predecessor(1, None),
    ] {
        assert_eq!(
            decode_exact_object(&invalid).unwrap_err().code(),
            "EA-FORMAT-SHAPE"
        );
    }
}

#[test]
fn opaque_signature_authenticity_is_deferred_but_exact_cose_changes_entry_hash() {
    let first = support::valid_eip(vec![0x66; 16]);
    let second = support::eip_with_different_opaque_signature(&first);
    let first = match decode_exact_object(&first).unwrap() {
        ParsedArchiveObject::Entry(value) => value,
        _ => unreachable!(),
    };
    let second = match decode_exact_object(&second).unwrap() {
        ParsedArchiveObject::Entry(value) => value,
        _ => unreachable!(),
    };
    assert_ne!(
        first.value().writer_signature(),
        second.value().writer_signature()
    );
    assert_ne!(
        first.value().entry_hash().as_bytes(),
        second.value().entry_hash().as_bytes()
    );
    for parsed in [&first, &second] {
        let expected = entry_hash(
            record_digest(parsed.value().signed_manifest().exact_bytes()),
            parsed.value().writer_signature(),
        );
        assert_eq!(parsed.value().entry_hash().as_bytes(), expected.as_bytes());
    }
}

#[test]
fn manifest_ciphertext_length_mismatch_is_rejected_in_both_directions() {
    for mismatch in [
        support::eip_with_declared_and_actual_ciphertext_lengths(16, 17),
        support::eip_with_declared_and_actual_ciphertext_lengths(18, 17),
    ] {
        assert_eq!(
            decode_exact_object(&mismatch).unwrap_err().code(),
            "EA-FORMAT-CIPHERTEXT-LENGTH"
        );
    }
}

#[test]
fn tag_version_and_critical_extensions_are_correlated_and_closed() {
    let tag_mismatch = support::eip_with_manifest_object_type(2);
    assert_eq!(
        decode_exact_object(&tag_mismatch).unwrap_err().code(),
        "EA-FORMAT-TAG-MISMATCH"
    );

    let mut unknown_version = support::valid_eip(vec![0; 16]);
    unknown_version[7] = 2;
    assert_eq!(
        decode_exact_object(&unknown_version).unwrap_err().code(),
        "EA-FORMAT-UNKNOWN-VERSION"
    );

    let nonempty_outer = support::replace_outer_extensions(&support::valid_eip(vec![0; 16]));
    assert_eq!(
        decode_exact_object(&nonempty_outer).unwrap_err().code(),
        "EA-FORMAT-CRITICAL-EXTENSION"
    );

    let nonempty_manifest = support::eip_with_nonempty_manifest_extensions();
    assert_eq!(
        decode_exact_object(&nonempty_manifest).unwrap_err().code(),
        "EA-FORMAT-CRITICAL-EXTENSION"
    );
}

#[test]
fn receipt_core_is_nonempty_bytewise_sorted_unique_and_typed() {
    let parsed = match decode_exact_object(&support::valid_esr()).unwrap() {
        ParsedArchiveObject::Receipt(value) => value,
        _ => unreachable!(),
    };
    assert_eq!(parsed.value().core().chain_sequence().get(), 0);
    assert_eq!(
        parsed.value().core().initial_grant_object_hashes()[0].as_bytes(),
        &[0x08; 32]
    );

    for (invalid, code) in support::invalid_receipt_grant_hash_lists() {
        assert_eq!(decode_exact_object(&invalid).unwrap_err().code(), code);
    }
}

#[test]
fn receipt_digest_content_type_and_server_headers_bind_the_exact_core() {
    for invalid in support::invalid_receipt_cose_bindings() {
        assert_eq!(
            decode_exact_object(&invalid).unwrap_err().code(),
            "EA-FORMAT-COSE"
        );
    }
}

#[test]
fn all_evidence_variants_have_their_exact_local_positional_shapes() {
    for (bytes, expected_kind) in [
        (
            support::valid_ecp(),
            ea_format::EvidenceKindV1::StandardCheckpoint,
        ),
        (
            support::valid_timestamp_ecp(),
            ea_format::EvidenceKindV1::Timestamp,
        ),
        (
            support::valid_renewal_ecp(),
            ea_format::EvidenceKindV1::Renewal,
        ),
    ] {
        let parsed = match decode_exact_object(&bytes).unwrap() {
            ParsedArchiveObject::Evidence(value) => value,
            _ => unreachable!(),
        };
        assert_eq!(parsed.value().kind(), expected_kind);
        assert_exact(&parsed, &bytes);
    }

    for (invalid, code) in support::invalid_evidence_structural_cases() {
        assert_eq!(decode_exact_object(&invalid).unwrap_err().code(), code);
    }
}

#[test]
fn every_evidence_variant_has_a_typed_public_construction_path() {
    let objects = support::constructed_evidence_objects();
    assert_eq!(objects.len(), 3);
    for (expected_kind, object) in objects {
        let bytes = encode_evidence(&object).unwrap();
        let decoded = match decode_exact_object(bytes.as_bytes()).unwrap() {
            ParsedArchiveObject::Evidence(value) => value,
            _ => unreachable!(),
        };
        assert_eq!(decoded.value().kind(), expected_kind);
        assert_eq!(decoded.exact_bytes().as_bytes(), bytes.as_bytes());
    }
}

#[test]
fn evidence_ctt_presence_correlates_with_standard_timestamp_and_renewal() {
    for (invalid, code) in support::evidence_ctt_correlation_cases() {
        assert_eq!(decode_exact_object(&invalid).unwrap_err().code(), code);
    }
}

#[test]
fn every_trust_subtype_has_its_exact_local_positional_shape() {
    let fixtures = support::valid_etb_objects();
    assert_eq!(fixtures.len(), 11);
    for (expected_subtype, bytes) in fixtures {
        let parsed = match decode_exact_object(&bytes).unwrap() {
            ParsedArchiveObject::Trust(value) => value,
            _ => unreachable!(),
        };
        assert_eq!(parsed.value().subtype(), expected_subtype);
        assert_exact(&parsed, &bytes);
    }
}

#[test]
fn device_certificate_v1_production_bytes_match_pinned_literal() {
    let payload = TrustPayloadV1::initial_admin_device_certificate(DeviceCertificateFieldsV1 {
        organization_id: support::organization(1),
        device_id: support::device_id(2),
        certificate_kind: CertificateKindV1::OrganizationAdmin,
        signing_public_cose_key: Some(vec![0xa1, 0x01]),
        kem_public_cose_key: None,
        signing_key_thumbprint: Some(support::key_thumbprint(3)),
        kem_key_thumbprint: None,
        capabilities: vec!["decrypt".into(), "sign".into()],
        key_protection_profile: KeyProtectionProfileV1::OsWrapped,
        effective_from_sequence: ChainSequence::new(0),
        revoked_from_sequence: None,
        authority_subject_id: Some(support::subject_id(2)),
    })
    .unwrap();
    let trust = support::constructed_normal_trust(payload, 1);
    let encoded = encode_trust(&trust).unwrap();
    let pinned_core = hex::decode(
        "8e01500101010101010101010101010101010150020202020202020202020202020202020242a101f658200303030303030303030303030303030303030303030303030303030303030303f6826764656372797074647369676e0000f6500202020202020202020202020202020280",
    )
    .unwrap();

    assert_eq!(
        support::exact_device_certificate_payload(encoded.as_bytes()),
        pinned_core.as_slice()
    );

    let decoded = match decode_exact_object(encoded.as_bytes()).unwrap() {
        ParsedArchiveObject::Trust(value) => value,
        _ => unreachable!(),
    };
    assert_eq!(decoded.value().subtype(), TrustSubtypeV1::DeviceCertificate);
    assert_eq!(
        encode_trust(decoded.value()).unwrap().as_bytes(),
        encoded.as_bytes()
    );
}

#[test]
fn every_trust_wire_form_has_a_typed_public_construction_path() {
    let objects = support::constructed_trust_objects();
    assert_eq!(objects.len(), 14);
    for (expected_subtype, object) in objects {
        let bytes = encode_trust(&object).unwrap();
        let decoded = match decode_exact_object(bytes.as_bytes()).unwrap() {
            ParsedArchiveObject::Trust(value) => value,
            _ => unreachable!(),
        };
        assert_eq!(decoded.value().subtype(), expected_subtype);
        assert_eq!(decoded.exact_bytes().as_bytes(), bytes.as_bytes());
    }
}

#[test]
fn root_device_and_operator_accept_their_distinct_authorized_forms() {
    for (expected_subtype, bytes) in support::valid_authorized_root_device_and_operator_objects() {
        let parsed = match decode_exact_object(&bytes).unwrap() {
            ParsedArchiveObject::Trust(value) => value,
            _ => unreachable!(),
        };
        assert_eq!(parsed.value().subtype(), expected_subtype);
        assert_exact(&parsed, &bytes);
    }
}

#[test]
fn trust_direct_authorized_wrappers_and_signature_cardinalities_are_local() {
    for invalid in support::invalid_trust_wrapper_and_cardinality_cases() {
        assert_eq!(
            decode_exact_object(&invalid).unwrap_err().code(),
            "EA-FORMAT-SHAPE"
        );
    }
}

#[test]
fn trust_lists_and_destruction_target_tuples_are_sorted_and_unique() {
    for (invalid, code) in support::invalid_trust_sorted_and_target_cases() {
        assert_eq!(decode_exact_object(&invalid).unwrap_err().code(), code);
    }
}

#[test]
fn trust_cose_content_type_is_local_but_signature_authenticity_is_deferred() {
    assert_eq!(
        decode_exact_object(&support::trust_with_wrong_content_type())
            .unwrap_err()
            .code(),
        "EA-FORMAT-COSE"
    );

    let original = support::valid_etb_objects().remove(3).1;
    let changed = support::trust_with_different_opaque_signature(&original);
    assert!(matches!(
        decode_exact_object(&original).unwrap(),
        ParsedArchiveObject::Trust(_)
    ));
    assert!(matches!(
        decode_exact_object(&changed).unwrap(),
        ParsedArchiveObject::Trust(_)
    ));
}

#[test]
fn certificate_hashless_trust_profile_is_exclusive_to_direct_initial_root() {
    let (initial_root, non_root_with_initial_root_profile) =
        support::trust_profile_correlation_cases();

    let root = match decode_exact_object(&initial_root).unwrap() {
        ParsedArchiveObject::Trust(value) => value,
        _ => unreachable!(),
    };
    assert_eq!(
        root.value().subtype(),
        ea_format::TrustSubtypeV1::RootCertificate
    );
    assert_eq!(root.value().signatures().len(), 1);
    assert!(
        ea_crypto::parse_cose_sign1(&root.value().signatures()[0], &[])
            .unwrap()
            .certificate_hash()
            .is_none()
    );

    for invalid in [
        support::direct_initial_root_with_normal_trust_profile(),
        non_root_with_initial_root_profile,
    ] {
        assert_eq!(
            decode_exact_object(&invalid).unwrap_err().code(),
            "EA-FORMAT-COSE"
        );
    }
}

#[test]
fn exact_cose_bytes_are_preserved_in_entry_and_destroyed_stub_hashes() {
    let eip = support::valid_eip(vec![0x44; 16]);
    let entry = match decode_exact_object(&eip).unwrap() {
        ParsedArchiveObject::Entry(value) => value,
        _ => panic!("fixture must decode as entry"),
    };
    let eds = support::valid_eds_from_entry(entry.value(), &eip);
    let destroyed = match decode_exact_object(&eds).unwrap() {
        ParsedArchiveObject::Destroyed(value) => value,
        _ => panic!("fixture must decode as destroyed stub"),
    };
    assert_eq!(
        destroyed.value().writer_signature(),
        entry.value().writer_signature()
    );
    assert_eq!(
        destroyed.value().entry_hash().as_bytes(),
        entry.value().entry_hash().as_bytes()
    );
}

#[test]
fn destroyed_stub_recomputes_entry_hash_and_duplicates_ciphertext_hash_exactly() {
    for invalid in [
        support::eds_with_stale_entry_hash_after_signature_mutation(),
        support::eds_with_mismatched_carried_entry_hash(),
        support::eds_with_mismatched_duplicate_ciphertext_hash(),
    ] {
        assert_eq!(
            decode_exact_object(&invalid).unwrap_err().code(),
            "EA-FORMAT-SHAPE"
        );
    }
}

#[test]
fn destroyed_stub_writer_cose_binds_payload_content_type_and_certificate() {
    for invalid in support::invalid_eds_cose_bindings() {
        assert_eq!(
            decode_exact_object(&invalid).unwrap_err().code(),
            "EA-FORMAT-COSE"
        );
    }
}
