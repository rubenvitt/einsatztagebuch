//! Die Rollentrennung des Writers als uebersetzte Produktinvariante.
//!
//! Auf einem Writer existiert kein privater Reader-, Recovery-, Historical-
//! Grant-Authority- oder Key-Approver-Schluessel. `WriterKeyProfile::validate`
//! ist die negative Haelfte dieser Zusage und kann nur ablehnen;
//! `WriterKeyProfile::validate_local` ist die positive Haelfte.
//!
//! # Wo diese Zusage WIRKLICH haengt, und was diese Datei dazu beitraegt
//!
//! Am TYP. `SecretPurpose` und `KeyPurpose` sind disjunkt, es gibt keine
//! Umwandlung zwischen ihnen, und ein fremder Zweck ist kein Argument von
//! `validate_local` — deshalb kann `validate_local` nur `Ok` liefern, und
//! deshalb ist eine Zusicherung ueber `is_ok()` KEIN Zeuge: sie kann fuer keine
//! uebersetzende Aenderung fehlschlagen. Hier stand genau so eine, und sie
//! trug den Namen der Invariante.
//!
//! Belegt wird der Typteil compilezeitlich, von den vier
//! `compile_fail`-Doctests im Wurzelmodul von `ea_key_provider` — zwei von
//! ihnen (kein `From`, kein fremder Zweck als Argument) gehoeren genau dieser
//! Zusage. Sie laufen unter
//! `cargo test --locked -p ea-key-provider --features test-support --doc` und
//! AUSDRUECKLICH nicht unter dem `--all-targets`-Lauf des Workspace, der
//! Doctests ausschliesst (`crates/ea-key-provider/src/lib.rs` nennt beides).
//!
//! Was diese Datei beitraegt, ist der Teil, den der `--all-targets`-Lauf
//! UEBERSETZT: der Vollstaendigkeitspin unten. Ein fuenfter lokaler Zweck
//! bricht ihn — auch dann, wenn `validate_local` gleichzeitig mit einem
//! Platzhalterarm beruhigt wird. Und die negative Haelfte ist ohnehin
//! laufzeitmessbar: sie kann ablehnen, also wird sie mit ihrem Code gemessen.

use std::collections::HashSet;

use ea_crypto::CertificateCapability;
use ea_format::KeyProtectionProfileV1;
use ea_key_provider::{
    InMemoryKeyProvider, KeyProvider, KeyPurpose, KeystoreProvider, SecretPurpose,
    WriterKeyProfile, require_claimed_protection_profile,
};

/// Die vier fremden Zwecke sind FREMD — einzeln, gemeinsam, und die leere
/// Liste ist der dokumentierte Grenzfall.
///
/// Gemessen wird der CODE und nicht `is_err()`: `validate` hat genau einen
/// Ablehnungsgrund, und ein anderer Code an dieser Stelle waere eine andere
/// Aussage.
#[test]
fn writer_profile_rejects_forbidden_private_key_purposes() {
    let all = [
        KeyPurpose::ReaderKem,
        KeyPurpose::RecoveryKem,
        KeyPurpose::HistoricalGrantAuthority,
        KeyPurpose::KeyApprover,
    ];
    for purpose in all {
        assert_eq!(
            WriterKeyProfile::validate(&[purpose]).unwrap_err().code(),
            "EA-KEY-FORBIDDEN-PURPOSE"
        );
    }
    // Alle vier zugleich, und nicht nur je einer: eine Implementierung, die
    // nur das erste Element ansieht, faellt hier nicht auf — eine, die eine
    // MEHRELEMENTIGE Liste durchliesse, sehr wohl.
    assert_eq!(
        WriterKeyProfile::validate(&all).unwrap_err().code(),
        "EA-KEY-FORBIDDEN-PURPOSE"
    );
    // Der dokumentierte Grenzfall: nichts zu beanstanden ist kein Fehler.
    // Ohne ihn koennte `validate` bedingungslos ablehnen und waere gruen.
    assert!(WriterKeyProfile::validate(&[]).is_ok());
}

/// Der Vollstaendigkeitspin der lokalen Zwecke: eine Kette OHNE
/// Platzhalterarm.
///
/// Ein fuenfter [`SecretPurpose`] bricht die Uebersetzung DIESES Testziels und
/// erzwingt damit eine Entscheidung — und zwar auch dann, wenn jemand
/// `WriterKeyProfile::validate_local` gleichzeitig mit `_ => {}` beruhigt.
/// Genau diese Aenderung, das stille Zulassen eines fuenften Zwecks, konnte die
/// frueher hier stehende `is_ok()`-Zusicherung nicht bemerken.
///
/// MEHR sagt der Pin nicht. Dass ein FREMDER Zweck hier ueberhaupt nicht
/// einsetzbar ist, gehoert dem Typ und ist von den `compile_fail`-Doctests des
/// Wurzelmoduls belegt, nicht von dieser Datei.
const fn purpose_after(purpose: SecretPurpose) -> Option<SecretPurpose> {
    match purpose {
        SecretPurpose::WriterSigningKey => Some(SecretPurpose::OperatorInstanceKey),
        SecretPurpose::OperatorInstanceKey => Some(SecretPurpose::DraftDek),
        SecretPurpose::DraftDek => Some(SecretPurpose::LocalDatabaseKey),
        SecretPurpose::LocalDatabaseKey => None,
    }
}

/// Die lokalen Zwecke, ABGELAUFEN und nicht abgeschrieben.
///
/// Der Lauf endet auch bei einer Kette, die sich SCHLIESST: das erste
/// wiederkehrende Glied wird angehaengt und der Lauf gebrochen, damit die
/// Zusicherung im Test es BERICHTET, statt dass dieser Aufruf haengt.
fn every_local_purpose() -> Vec<SecretPurpose> {
    let mut all = vec![SecretPurpose::WriterSigningKey];
    while let Some(next) = purpose_after(*all.last().expect("die Kette beginnt mit einem Glied")) {
        let repeated = all.contains(&next);
        all.push(next);
        if repeated {
            break;
        }
    }
    all
}

#[test]
fn the_local_purposes_are_pinned_and_every_one_of_them_is_admitted() {
    let all = every_local_purpose();
    // Die Kette laeuft geradeaus und schliesst sich nicht: kein Zweck kommt
    // zweimal. Ohne diese Zeile waere `LocalDatabaseKey => Some(DraftDek)` eine
    // Liste, die dieselben vier Zwecke mehrfach fuehrt, und die Zaehlung
    // darunter waere gruen zu machen, indem man Glieder wiederholt.
    assert_eq!(
        all.iter().copied().collect::<HashSet<_>>().len(),
        all.len(),
        "die Kette fuehrt jeden Zweck genau einmal"
    );
    // Die Zahl steht hier, damit ein fuenfter Zweck AUCH dann auffaellt, wenn
    // ihn jemand ordentlich in die Kette einhaengt: dann ist die Frage, ob er
    // ein lokaler Zweck eines Writers sein DARF, und diese Zeile stellt sie.
    assert_eq!(
        all.len(),
        4,
        "vier lokale Zwecke, ein fuenfter ist eine Entscheidung"
    );
    assert!(WriterKeyProfile::validate_local(&all).is_ok());
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
        require_claimed_protection_profile(
            handle.keystore_provider(),
            reached,
            KeyProtectionProfileV1::HardwareNonExportable
        )
        .unwrap_err()
        .code(),
        "EA-KEY-PROTECTION-PROFILE-MISMATCH"
    );
}

#[test]
fn an_equal_os_wrapped_profile_passes_for_every_provider() {
    for provider in [
        KeystoreProvider::OperatingSystem,
        KeystoreProvider::InMemory,
    ] {
        assert!(
            require_claimed_protection_profile(
                provider,
                KeyProtectionProfileV1::OsWrapped,
                KeyProtectionProfileV1::OsWrapped
            )
            .is_ok()
        );
    }
}

#[test]
fn a_hardware_claim_needs_an_explicitly_supported_provider_even_when_it_matches() {
    // Die dritte Klausel der Zusage. Stufe 2 kennt heute KEINEN Provider, der
    // nicht-exportierbares Hardwarematerial erreicht — ein uebereinstimmender
    // Hardware-Anspruch besteht deshalb bei keinem Provider, statt
    // durchzugehen, weil ihm niemand widerspricht.
    for provider in [
        KeystoreProvider::OperatingSystem,
        KeystoreProvider::InMemory,
    ] {
        assert_eq!(
            require_claimed_protection_profile(
                provider,
                KeyProtectionProfileV1::HardwareNonExportable,
                KeyProtectionProfileV1::HardwareNonExportable
            )
            .unwrap_err()
            .code(),
            "EA-KEY-PROTECTION-PROFILE-UNREACHABLE"
        );
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
            require_claimed_protection_profile(KeystoreProvider::OperatingSystem, profile, profile)
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
