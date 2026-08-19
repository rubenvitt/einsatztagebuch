//! Die Rollentrennung des Writers als uebersetzte Produktinvariante.
//!
//! Auf einem Writer existiert kein privater Reader-, Recovery-, Historical-
//! Grant-Authority- oder Key-Approver-Schluessel. `WriterKeyProfile::validate`
//! ist die negative Haelfte dieser Zusage und kann nur ablehnen;
//! `WriterKeyProfile::validate_local` ist die positive Haelfte.

use ea_crypto::CertificateCapability;
use ea_format::KeyProtectionProfileV1;
use ea_key_provider::{
    InMemoryKeyProvider, KeyProvider, KeyPurpose, SecretPurpose, WriterKeyProfile,
    require_claimed_protection_profile,
};

#[test]
fn writer_profile_rejects_forbidden_private_key_purposes() {
    for purpose in [
        KeyPurpose::ReaderKem,
        KeyPurpose::RecoveryKem,
        KeyPurpose::HistoricalGrantAuthority,
        KeyPurpose::KeyApprover,
    ] {
        assert!(WriterKeyProfile::validate(&[purpose]).is_err());
    }
}

#[test]
fn writer_profile_admits_only_the_four_local_purposes() {
    assert!(
        WriterKeyProfile::validate_local(&[
            SecretPurpose::WriterSigningKey,
            SecretPurpose::OperatorInstanceKey,
            SecretPurpose::DraftDek,
            SecretPurpose::LocalDatabaseKey,
        ])
        .is_ok()
    );
}

#[test]
fn a_claimed_hardware_profile_never_falls_back_silently() {
    let provider = InMemoryKeyProvider::new_for_test([9; 32]);
    let handle = provider
        .generate(
            SecretPurpose::OperatorInstanceKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    let reached = provider.reached_protection_profile(&handle).unwrap();
    assert_eq!(reached, KeyProtectionProfileV1::OsWrapped);
    assert_eq!(
        require_claimed_protection_profile(reached, KeyProtectionProfileV1::HardwareNonExportable)
            .unwrap_err()
            .code(),
        "EA-KEY-PROTECTION-PROFILE-MISMATCH"
    );
}

#[test]
fn an_equal_and_stage_two_reachable_protection_profile_passes() {
    for profile in [
        KeyProtectionProfileV1::OsWrapped,
        KeyProtectionProfileV1::HardwareNonExportable,
    ] {
        assert!(require_claimed_protection_profile(profile, profile).is_ok());
    }
}

#[test]
fn a_protection_profile_outside_stage_two_is_refused_even_when_it_matches() {
    for profile in [
        KeyProtectionProfileV1::OfflineEncryptedContainer,
        KeyProtectionProfileV1::Pkcs11,
        KeyProtectionProfileV1::ServerSecretStoreOrHsm,
    ] {
        assert_eq!(
            require_claimed_protection_profile(profile, profile)
                .unwrap_err()
                .code(),
            "EA-KEY-PROTECTION-PROFILE-UNSUPPORTED"
        );
    }
}

#[test]
fn a_writer_certificate_capability_is_decided_against_the_parsed_allowlist() {
    assert_eq!(
        WriterKeyProfile::validate_capabilities(&[String::from("initialGrant")]).unwrap(),
        vec![CertificateCapability::InitialGrant]
    );
    assert!(
        WriterKeyProfile::validate_capabilities(&[])
            .unwrap()
            .is_empty()
    );

    // Kein Stufe-1-Literal: die Aufzaehlung von ea-crypto weist es zurueck,
    // diese Crate fuehrt keine zweite Allowlist.
    assert_eq!(
        WriterKeyProfile::validate_capabilities(&[String::from("initialgrant")])
            .unwrap_err()
            .code(),
        "EA-KEY-UNKNOWN-CAPABILITY"
    );

    // Ein bekanntes Literal, das einem Writer nicht zusteht.
    for capability in [
        "historicalGrant",
        "organizationAdminApprove",
        "historicalGrantApprove",
        "destructionApprove",
        "serverReceipt",
        "deletionAttest",
    ] {
        assert_eq!(
            WriterKeyProfile::validate_capabilities(&[String::from(capability)])
                .unwrap_err()
                .code(),
            "EA-KEY-FORBIDDEN-CAPABILITY"
        );
    }
}

#[test]
fn the_default_feature_set_omits_the_in_memory_provider() {
    let manifest: toml::Value = toml::from_str(include_str!("../Cargo.toml")).unwrap();
    let default = manifest["features"].get("default");
    assert!(
        default.is_none()
            || !default
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .any(|feature| feature.as_str() == Some("test-support")),
        "test-support must never be a default feature"
    );

    // Die zweite Tuer, und warum sie zu ist. Diese Crate haengt als
    // DEV-Abhaengigkeit von sich selbst ab, um `test-support` fuer die eigenen
    // Testziele einzuschalten — das Testkommando des Workspace laeuft ohne
    // `--all-features`. Derselbe Eintrag unter `[dependencies]` schaltete das
    // Feature im Bibliotheksgraphen ein; dagegen steht keine Zusicherung hier,
    // sondern Cargo selbst: es weist ihn mit `cyclic package dependency:
    // package ea-key-provider depends on itself` zurueck, nachgeprueft. Was
    // hier steht, ist der Grund fuer den Dev-Eintrag — wer ihn entfernt, soll
    // diesen Satz lesen und nicht einen Uebersetzungsfehler anderswo.
    assert!(
        manifest["dev-dependencies"]["ea-key-provider"]["features"]
            .as_array()
            .unwrap()
            .iter()
            .any(|feature| feature.as_str() == Some("test-support")),
        "the dev-dependency on itself is what enables test-support in the gate"
    );
}
