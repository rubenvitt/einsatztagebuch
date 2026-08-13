use ea_crypto::{
    CoseSigner, GRANT_SUITE_ID, SUITE_ID, SecretBytes, SuiteV1, authorized_trust_digest,
    bootstrap_anchor_hash, ciphertext_digest, entry_hash, grant_digest, grant_plan_digest,
    hpke_aad, hpke_info, object_hash, operator_profile_digest, payload_aad, receipt_digest,
    record_digest, recovery_test_digest, renewal_input_digest, trust_anchor_hash, trust_digest,
};
use ea_types::{CertificateHash, Hash32, KeyThumbprint};

const WRITER_COSE_HEX: &str = "d284589aa50132028303046f63657274696669636174654861736803782b6170706c69636174696f6e2f766e642e65696e7361747a6172636869762e7265636f72642d646967657374045820be5de2f4bcdc383add3fc9827d345f1a37c6a06026b38696fb3229c003b35f496f6365727469666963617465486173685820d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeefa05820404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f5840a1163c544a30406de46b5c3ce22c3ff0fd2ad5b0d698d44b2a3f3b1b47fbadebf202109dfebe2ec5a7e942102aab6f95ccb28d970fb3803869969912e7005200";

fn production_domain_outputs(input: &[u8]) -> [[u8; 32]; 12] {
    [
        *ciphertext_digest(input).as_bytes(),
        *record_digest(input).as_bytes(),
        *object_hash(input).as_bytes(),
        *grant_plan_digest(input).as_bytes(),
        *grant_digest(input).as_bytes(),
        *receipt_digest(input).as_bytes(),
        *trust_digest(input).as_bytes(),
        *authorized_trust_digest(input).as_bytes(),
        *renewal_input_digest(input).as_bytes(),
        *bootstrap_anchor_hash(input).as_bytes(),
        *trust_anchor_hash(input).as_bytes(),
        *operator_profile_digest(input).as_bytes(),
    ]
}

#[test]
fn suite_ids_and_domain_compositions_are_closed() {
    assert_eq!(SuiteV1::SUITE_ID, SUITE_ID);
    assert_eq!(SuiteV1::GRANT_SUITE_ID, GRANT_SUITE_ID);
    assert_eq!(SUITE_ID, "EINSATZARCHIV-SUITE-1");
    assert_eq!(GRANT_SUITE_ID, "EINSATZARCHIV-HPKE-1");

    let input = hex::decode("8101").unwrap();
    let expected = [
        (
            b"EINSATZARCHIV-CIPHERTEXT-v1".as_slice(),
            "45494e5341545a4152434849562d434950484552544558542d7631",
            "8101",
            "45494e5341545a4152434849562d434950484552544558542d76318101",
            "d1f5d1dded1e767e0de068ed366d7e676d98330438631645bfa1fe4b0ec4028a",
        ),
        (
            b"EINSATZARCHIV-RECORD-v1".as_slice(),
            "45494e5341545a4152434849562d5245434f52442d7631",
            "8101",
            "45494e5341545a4152434849562d5245434f52442d76318101",
            "f218a12559e7055e2c4c46a16d51f87f4f199d61829ad5f1f1613826aa2060f8",
        ),
        (
            b"EINSATZARCHIV-OBJECT-v1".as_slice(),
            "45494e5341545a4152434849562d4f424a4543542d7631",
            "8101",
            "45494e5341545a4152434849562d4f424a4543542d76318101",
            "8ce7cae429b9810b475372f528a6cfbaaefe6632e5daa96cf7d11533c6839c7e",
        ),
        (
            b"EINSATZARCHIV-GRANT-PLAN-v1".as_slice(),
            "45494e5341545a4152434849562d4752414e542d504c414e2d7631",
            "8101",
            "45494e5341545a4152434849562d4752414e542d504c414e2d76318101",
            "5969433b30e1f972379b2d142ae992f05ca5c8c9855c3efc511c7556f8fa7bed",
        ),
        (
            b"EINSATZARCHIV-GRANT-v1".as_slice(),
            "45494e5341545a4152434849562d4752414e542d7631",
            "8101",
            "45494e5341545a4152434849562d4752414e542d76318101",
            "806e5c7ca77f9fa413c432be0e0e022b08b1b716df9a3fbd4f2cea57f78d8381",
        ),
        (
            b"EINSATZARCHIV-RECEIPT-v1".as_slice(),
            "45494e5341545a4152434849562d524543454950542d7631",
            "8101",
            "45494e5341545a4152434849562d524543454950542d76318101",
            "901c614a65150d2a1c7f95198f0a21c4045a15a8f7dc973fb72c81329a4202cc",
        ),
        (
            b"EINSATZARCHIV-TRUST-OBJECT-v1".as_slice(),
            "45494e5341545a4152434849562d54525553542d4f424a4543542d7631",
            "8101",
            "45494e5341545a4152434849562d54525553542d4f424a4543542d76318101",
            "63b90701c5867550f2d772fa45c6d5154f610174734611e525caf91d658026bf",
        ),
        (
            b"EINSATZARCHIV-ADMIN-AUTHORIZED-TRUST-v1".as_slice(),
            "45494e5341545a4152434849562d41444d494e2d415554484f52495a45442d54525553542d7631",
            "8101",
            "45494e5341545a4152434849562d41444d494e2d415554484f52495a45442d54525553542d76318101",
            "6db46d2082a03b13f5426f0ce4deef70da023b34a70ffbe848ea10e6ad6e5648",
        ),
        (
            b"EINSATZARCHIV-EVIDENCE-RENEWAL-INPUT-v1".as_slice(),
            "45494e5341545a4152434849562d45564944454e43452d52454e4557414c2d494e5055542d7631",
            "8101",
            "45494e5341545a4152434849562d45564944454e43452d52454e4557414c2d494e5055542d76318101",
            "fb89aaf73cef5037135c6f76a8743c3ed50f8969f391c96c87f351eefa3c5897",
        ),
        (
            b"EINSATZARCHIV-TRUST-ANCHOR-PRE-v1".as_slice(),
            "45494e5341545a4152434849562d54525553542d414e43484f522d5052452d7631",
            "8101",
            "45494e5341545a4152434849562d54525553542d414e43484f522d5052452d76318101",
            "db7bb044527b8779069b2b003baa064bedf1d597f32fb0272d188f99c440ef5b",
        ),
        (
            b"EINSATZARCHIV-TRUST-ANCHOR-v1".as_slice(),
            "45494e5341545a4152434849562d54525553542d414e43484f522d7631",
            "8101",
            "45494e5341545a4152434849562d54525553542d414e43484f522d76318101",
            "9dac731f953e0768c85844c808aac6e89a65f933801707560182ba1bbde53fb6",
        ),
        (
            b"EINSATZARCHIV-OPERATOR-PROFILE-v1".as_slice(),
            "45494e5341545a4152434849562d4f50455241544f522d50524f46494c452d7631",
            "8101",
            "45494e5341545a4152434849562d4f50455241544f522d50524f46494c452d76318101",
            "60bd39012e33d7ea1504a73b6ce78052923faaa99cc5c65db0c95d064e6abeec",
        ),
    ];
    for (index, (domain, domain_hex, context_hex, complete_preimage_hex, expected_output_hex)) in
        expected.into_iter().enumerate()
    {
        assert_eq!(hex::encode(domain), domain_hex);
        assert_eq!(hex::encode(&input), context_hex);
        assert_eq!(
            hex::decode(complete_preimage_hex).unwrap(),
            [domain, input.as_slice()].concat()
        );
        assert_eq!(
            hex::encode(production_domain_outputs(&input)[index]),
            expected_output_hex
        );
    }

    assert_eq!(
        hex::encode(record_digest(b"known answer input").as_bytes()),
        "bd22d085eac876e0ff43481f554a754010e1543accc876f0b33bc66e8acdb94d"
    );
    assert_eq!(
        hex::encode(object_hash(b"known answer input").as_bytes()),
        "b4d5d9a05190e4b9914c0587995e8d7c50b0a0b91c029631b18bf01a57315609"
    );
    assert_ne!(
        record_digest(b"same bytes").as_bytes(),
        object_hash(b"same bytes").as_bytes()
    );
}

#[test]
fn aad_and_hpke_contexts_pin_domain_bytes_and_order() {
    let context = hex::decode("8101").unwrap();
    assert_eq!(
        hex::encode(payload_aad(&context)),
        "45494e5341545a4152434849562d4141442d76318101"
    );
    assert_eq!(
        hex::encode(hpke_info(&context)),
        "45494e5341545a4152434849562d48504b452d494e464f2d76318101"
    );
    assert_eq!(
        hex::encode(hpke_aad(&context)),
        "45494e5341545a4152434849562d48504b452d4141442d76318101"
    );
}

#[test]
fn package_and_recovery_constructions_match_independent_known_answers() {
    let record_digest = Hash32::try_from(
        hex::decode("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let writer_cose = hex::decode(WRITER_COSE_HEX).unwrap();
    let package_preimage = hex::decode(concat!(
        "45494e5341545a4152434849562d5041434b4147452d7631",
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
        "d284589aa50132028303046f63657274696669636174654861736803782b6170706c69636174696f6e2f766e642e65696e7361747a6172636869762e7265636f72642d646967657374045820be5de2f4bcdc383add3fc9827d345f1a37c6a06026b38696fb3229c003b35f496f6365727469666963617465486173685820d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeefa05820404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f5840a1163c544a30406de46b5c3ce22c3ff0fd2ad5b0d698d44b2a3f3b1b47fbadebf202109dfebe2ec5a7e942102aab6f95ccb28d970fb3803869969912e7005200"
    ))
    .unwrap();
    assert_eq!(
        package_preimage,
        [
            b"EINSATZARCHIV-PACKAGE-v1".as_slice(),
            record_digest.as_bytes(),
            writer_cose.as_slice(),
        ]
        .concat()
    );
    assert_eq!(
        hex::encode(entry_hash(record_digest, &writer_cose).as_bytes()),
        "213150700fc1cd0cb07cf66c53563f479f1b1f96683ba1e0e1bde0adc69e7351"
    );

    let challenge = SecretBytes::new(std::array::from_fn(|index| 0x90 + index as u8));
    let thumbprint = KeyThumbprint::try_from(
        hex::decode("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf")
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let recovery_context = hex::decode("83015820909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf5820b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf").unwrap();
    let recovery_preimage = hex::decode("45494e5341545a4152434849562d5245434f564552592d544553542d763183015820909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf5820b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf").unwrap();
    assert_eq!(
        recovery_preimage,
        [
            b"EINSATZARCHIV-RECOVERY-TEST-v1".as_slice(),
            recovery_context.as_slice(),
        ]
        .concat()
    );
    assert_eq!(
        hex::encode(recovery_test_digest(challenge, thumbprint).as_bytes()),
        "35b317aa12d1c912a517e97146d7caa6648b80e43af3460bab1b8b65c0484b05"
    );
}

#[test]
fn recovery_signing_accepts_only_a_challenge_not_a_productive_digest() {
    let signer = CoseSigner::from_secret(SecretBytes::new([0x42; 32]));
    let certificate_hash = CertificateHash::try_from([0x51; 32].as_slice()).unwrap();
    let signed = signer
        .sign_recovery_test(certificate_hash, SecretBytes::new([0xa5; 32]))
        .unwrap();
    assert_eq!(
        ea_crypto::parse_cose_sign1(&signed, &[]).unwrap().payload(),
        recovery_test_digest(
            SecretBytes::new([0xa5; 32]),
            ea_crypto::CanonicalPublicCoseKey::ed25519(
                hex::decode("2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12")
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
            .unwrap()
            .thumbprint(),
        )
        .as_bytes()
    );
}

#[test]
fn every_production_construction_is_input_mutation_sensitive() {
    let cbor = hex::decode("8101").unwrap();
    let original_outputs = production_domain_outputs(&cbor);
    for byte_index in 0..cbor.len() {
        let mut mutation = cbor.clone();
        mutation[byte_index] ^= 1;
        for (construction_index, (original, changed)) in original_outputs
            .iter()
            .zip(production_domain_outputs(&mutation))
            .enumerate()
        {
            assert_ne!(
                original, &changed,
                "construction {construction_index} ignored input byte {byte_index}"
            );
        }
    }

    let aad = payload_aad(&cbor);
    let info = hpke_info(&cbor);
    let hpke_bound_aad = hpke_aad(&cbor);
    for index in 0..cbor.len() {
        let mut mutation = cbor.clone();
        mutation[index] ^= 1;
        assert_ne!(payload_aad(&mutation), aad);
        assert_ne!(hpke_info(&mutation), info);
        assert_ne!(hpke_aad(&mutation), hpke_bound_aad);
    }

    let base_record_digest = Hash32::try_from([0x40; 32].as_slice()).unwrap();
    let writer_cose = hex::decode(WRITER_COSE_HEX).unwrap();
    let original_entry_hash = entry_hash(base_record_digest, &writer_cose);
    for byte_index in 0..writer_cose.len() {
        let mut mutation = writer_cose.clone();
        mutation[byte_index] ^= 1;
        assert_ne!(
            entry_hash(base_record_digest, &mutation).as_bytes(),
            original_entry_hash.as_bytes()
        );
    }
    for byte_index in 0..32 {
        let mut mutation = [0x40; 32];
        mutation[byte_index] ^= 1;
        let mutation = Hash32::try_from(mutation.as_slice()).unwrap();
        assert_ne!(
            entry_hash(mutation, &writer_cose).as_bytes(),
            original_entry_hash.as_bytes()
        );
    }

    let challenge: [u8; 32] = std::array::from_fn(|index| 0x90 + index as u8);
    let thumbprint: [u8; 32] = std::array::from_fn(|index| 0xb0 + index as u8);
    let original_recovery = recovery_test_digest(
        SecretBytes::new(challenge),
        KeyThumbprint::try_from(thumbprint.as_slice()).unwrap(),
    );
    for byte_index in 0..32 {
        let mut challenge_mutation = challenge;
        challenge_mutation[byte_index] ^= 1;
        assert_ne!(
            recovery_test_digest(
                SecretBytes::new(challenge_mutation),
                KeyThumbprint::try_from(thumbprint.as_slice()).unwrap(),
            )
            .as_bytes(),
            original_recovery.as_bytes()
        );

        let mut thumbprint_mutation = thumbprint;
        thumbprint_mutation[byte_index] ^= 1;
        assert_ne!(
            recovery_test_digest(
                SecretBytes::new(challenge),
                KeyThumbprint::try_from(thumbprint_mutation.as_slice()).unwrap(),
            )
            .as_bytes(),
            original_recovery.as_bytes()
        );
    }
}
