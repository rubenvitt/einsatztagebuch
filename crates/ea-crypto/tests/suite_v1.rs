use ea_crypto::{
    CoseSigner, SecretBytes, StreamingObjectHasher, entry_hash, object_hash, recovery_test_digest,
};
use ea_types::{CertificateHash, Hash32, KeyThumbprint};

const WRITER_COSE_HEX: &str = "d284589aa50132028303046f63657274696669636174654861736803782b6170706c69636174696f6e2f766e642e65696e7361747a6172636869762e7265636f72642d646967657374045820be5de2f4bcdc383add3fc9827d345f1a37c6a06026b38696fb3229c003b35f496f6365727469666963617465486173685820d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeefa05820404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f5840a1163c544a30406de46b5c3ce22c3ff0fd2ad5b0d698d44b2a3f3b1b47fbadebf202109dfebe2ec5a7e942102aab6f95ccb28d970fb3803869969912e7005200";

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
fn package_and_recovery_constructions_are_field_mutation_sensitive() {
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

/// Der stueckweise Objekthash ist bitgleich zum einteiligen.
///
/// Der Sync-Server hasht Objektbytes waehrend des Stroms, ohne den vollen
/// Koerper zu halten (`design.md` §13.3, Schritt 1). Diese Gleichheit ist die
/// Bedingung dafuer, dass der so gebildete Hash derselbe content-addressed
/// Schluessel ist wie der, den jeder andere Aufrufer mit `object_hash` rechnet
/// — waere sie verletzt, laege dasselbe Objekt unter zwei Schluesseln.
#[test]
fn the_streaming_object_hasher_matches_the_one_shot_object_hash() {
    let payload: Vec<u8> = (0..4096_u32).map(|index| (index % 251) as u8).collect();

    // Jede Stueckelung, die es geben kann: eine, die genau aufgeht, eine mit
    // Rest, eine mit einem einzigen Byte je Stueck und der leere Fall.
    for chunk_size in [1_usize, 7, 512, 4096] {
        let mut hasher = StreamingObjectHasher::new();
        for chunk in payload.chunks(chunk_size) {
            hasher.update(chunk);
        }
        assert_eq!(
            hasher.finish().as_bytes(),
            object_hash(&payload).as_bytes(),
            "chunking at {chunk_size} bytes must not change the object hash"
        );
    }

    let empty = StreamingObjectHasher::new();
    assert_eq!(empty.finish().as_bytes(), object_hash(&[]).as_bytes());

    // Positivkontrolle: ein geaenderter Koerper ergibt einen anderen Hash, also
    // misst der Vergleich oben ueberhaupt etwas.
    let mut different = payload.clone();
    different[0] ^= 1;
    let mut hasher = StreamingObjectHasher::new();
    hasher.update(&different);
    assert_ne!(hasher.finish().as_bytes(), object_hash(&payload).as_bytes());
}
