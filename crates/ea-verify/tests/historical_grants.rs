mod support;
use ea_types::UnixMillis;
use ea_verify::{VerifyOptions, verify_archive};

#[test]
fn a_new_reader_opens_the_old_entry_at_the_exact_expiry_boundary() {
    let f = support::historical::with_grant(support::COMPLETE_PLAINTEXT_V1, 800);
    let key = support::other_recipient_private_key();
    let report = verify_archive(
        &f.fixture,
        &f.anchor,
        VerifyOptions::new(UnixMillis::new(800))
            .with_recipient(support::other_recipient_key_thumbprint(), &key),
    )
    .unwrap();
    assert!(report.is_fully_verified(), "{report:?}");
    assert!(report.public_key_thumbprints().any(|k| k
        == support::archive_support::trust_support::authorized_device_signing_key_thumbprint()));
    // A wrong recipient secret must now reach HPKE and be reported, not be ignored as missing.
    let wrong = support::complete_recipient_private_key();
    let wrong_report = verify_archive(
        &f.fixture,
        &f.anchor,
        VerifyOptions::new(UnixMillis::new(800))
            .with_recipient(support::other_recipient_key_thumbprint(), &wrong),
    )
    .unwrap();
    assert_eq!(wrong_report.decryption_errors().len(), 1);
}

#[test]
fn replaying_the_exact_historical_bytes_after_expiry_is_rejected() {
    let f = support::historical::with_grant(support::COMPLETE_PLAINTEXT_V1, 800);
    let key = support::other_recipient_private_key();
    let report = verify_archive(
        &f.fixture,
        &f.anchor,
        VerifyOptions::new(UnixMillis::new(801))
            .with_recipient(support::other_recipient_key_thumbprint(), &key),
    )
    .unwrap();
    assert!(
        report
            .signature_errors()
            .any(|e| e.code() == "EA-GRANT-EXPIRED")
    );
}

#[test]
fn a_forged_lower_hash_historical_candidate_cannot_hide_a_valid_grant() {
    let mut f = support::historical::with_grant(support::COMPLETE_PLAINTEXT_V1, 800);
    let valid = f
        .fixture
        .blobs()
        .iter()
        .find(|(name, _)| name == "grants/historical.eag")
        .unwrap()
        .1
        .clone();
    let valid_hash = ea_crypto::object_hash(&valid);
    let forged = (0u8..=255)
        .find_map(|marker| {
            let mut bytes = valid.clone();
            let n = bytes.len();
            bytes[n - 1] = marker;
            (bytes != valid && ea_crypto::object_hash(&bytes) < valid_hash).then_some(bytes)
        })
        .expect("lower hash forgery");
    f.fixture.push_exact_bytes("grants/forged.eag", forged);
    let key = support::other_recipient_private_key();
    let report = verify_archive(
        &f.fixture,
        &f.anchor,
        VerifyOptions::new(UnixMillis::new(800))
            .with_recipient(support::other_recipient_key_thumbprint(), &key),
    )
    .unwrap();
    assert!(report.is_fully_verified(), "{report:?}");
    assert!(report.recipient_grants().next().unwrap().1 == valid_hash);
}

#[test]
fn an_initial_recovery_grant_remains_readable_after_its_registry_lease_expires() {
    let f = support::historical::fixture_with_expired_original_head(|_, _| {
        support::COMPLETE_PLAINTEXT_V1.to_vec()
    });
    let key = support::complete_recipient_private_key();
    let report = verify_archive(
        &f.fixture,
        &f.anchor,
        VerifyOptions::new(UnixMillis::new(800))
            .with_recipient(support::complete_recipient_key_thumbprint(), &key),
    )
    .unwrap();
    assert_eq!(report.recipient_grants().count(), 1);
    assert!(report.is_fully_verified(), "{report:?}");
}

#[test]
fn the_authorization_expiry_not_its_old_registry_lease_limits_archived_opening() {
    let f = support::historical::with_grant(support::COMPLETE_PLAINTEXT_V1, 20_000);
    let key = support::other_recipient_private_key();
    let report = verify_archive(
        &f.fixture,
        &f.anchor,
        VerifyOptions::new(UnixMillis::new(10_001))
            .with_recipient(support::other_recipient_key_thumbprint(), &key),
    )
    .unwrap();
    assert_eq!(report.recipient_grants().count(), 1);
    assert!(report.is_fully_verified(), "{report:?}");
    let expired = verify_archive(
        &f.fixture,
        &f.anchor,
        VerifyOptions::new(UnixMillis::new(20_001))
            .with_recipient(support::other_recipient_key_thumbprint(), &key),
    )
    .unwrap();
    assert!(
        expired
            .signature_errors()
            .any(|e| e.code() == "EA-GRANT-EXPIRED")
    );
}
