//! Die Autorisierungsmatrix an der Grenze des Zeremoniendienstes.
//!
//! Die Zusage lautet: NUR das Paar aus einem Wurzel-signierten Ziel und seiner
//! Administrationsautorisierung kommt in die Signierseite. Jede Haelfte allein
//! scheitert, ein fremder Kernhash scheitert, ein fremder Aktionscode
//! scheitert — und ein Nachweis, der einem anderen Zweck dient oder entwertet
//! ist, kommt gar nicht erst bis zur Sperre.

mod support;

use ea_admin::AdminError;
use ea_crypto::object_hash;
use ea_operator::ReauthPurpose;
use ea_trust::{TrustError, verify_authorized_trust_target};
use ea_types::{ChainSequence, UnixMillis};

use support::{
    AuditHarness, FixtureKeyProvider, PersistentStore, ReplayTable, ceremony_line,
    ceremony_service, operator_proof, selected_head, trust_support, verified,
};

use std::sync::{Arc, Mutex};

use trust_support::{ActionSpec, HeadOptions, Pin, RegistryLineBuilder};

const USE_TIME: UnixMillis = UnixMillis::new(support::FIXTURE_NOW_MS);

fn expect_trust_code(error: TrustError, expected: &str) {
    assert_eq!(error.code(), expected);
    assert_eq!(error.to_string(), expected);
    assert_eq!(format!("{error:?}"), expected);
}

fn expect_admin_code(error: AdminError, expected: &str) {
    assert_eq!(error.code(), expected);
    assert_eq!(error.to_string(), expected);
    assert_eq!(format!("{error:?}"), expected);
}

#[test]
fn the_valid_pair_publishes_the_exact_authorized_target() {
    let ceremony = ceremony_line();
    let trust = verified(&ceremony.line);
    let head = selected_head(&ceremony.line);
    let authorization = verify_authorized_trust_target(
        &trust,
        None,
        ceremony
            .line
            .exact_object_bytes(ceremony.target_object_hash),
        USE_TIME,
        ChainSequence::new(support::TARGET_SEQUENCE),
    )
    .expect("das Wurzel-signierte Ziel und seine Autorisierung verifizieren");

    let provider = FixtureKeyProvider::root();
    let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
    let service = ceremony_service(&head, &provider, &audit, &ceremony);
    let proof = operator_proof(
        &head,
        ceremony.binding_object_hash,
        ReauthPurpose::AdminRootCeremony,
    );
    let table = Arc::new(Mutex::new(ReplayTable::default()));
    let mut store = PersistentStore::open(&table);

    let published = service
        .publish_authorized_target(
            &authorization,
            ceremony.target_payload,
            ceremony
                .line
                .exact_object_bytes(authorization.authorization_object_hash()),
            &mut store,
            &proof,
        )
        .expect("die Zeremonie gibt das autorisierte Ziel heraus");

    assert!(
        object_hash(published.as_bytes()) == ceremony.target_object_hash,
        "die herausgegebenen Bytes SIND das autorisierte Ziel"
    );
}

#[test]
fn a_root_signed_object_without_an_admin_authorization_is_no_authorized_target() {
    let ceremony = ceremony_line();
    let trust = verified(&ceremony.line);
    // Das Bootstrap-Administratorzertifikat: Wurzel-signiert, aber ohne jede
    // Administrationsautorisierung — die Root-only-Haelfte des Paares.
    let root_only = ceremony
        .line
        .exact_object_bytes(ceremony.line.bootstrap_admin_hash())
        .to_vec();

    let error = verify_authorized_trust_target(
        &trust,
        None,
        &root_only,
        USE_TIME,
        ChainSequence::new(support::TARGET_SEQUENCE),
    )
    .err()
    .expect("eine Wurzelsignatur allein autorisiert keine Aenderung");
    expect_trust_code(error, "EA-TRUST-ACTION-MISMATCH");
}

#[test]
fn an_admin_authorization_alone_is_no_authorized_target() {
    let ceremony = ceremony_line();
    let trust = verified(&ceremony.line);
    let authorization = verify_authorized_trust_target(
        &trust,
        None,
        ceremony
            .line
            .exact_object_bytes(ceremony.target_object_hash),
        USE_TIME,
        ChainSequence::new(support::TARGET_SEQUENCE),
    )
    .expect("das gueltige Paar verifiziert");
    // Die Admin-only-Haelfte: das Autorisierungsobjekt selbst, Admin-signiert
    // und ohne Wurzelsignatur.
    let admin_only = ceremony
        .line
        .exact_object_bytes(authorization.authorization_object_hash())
        .to_vec();

    let error = verify_authorized_trust_target(
        &trust,
        None,
        &admin_only,
        USE_TIME,
        ChainSequence::new(support::TARGET_SEQUENCE),
    )
    .err()
    .expect("eine Administrationsautorisierung ist kein autorisiertes Ziel");
    expect_trust_code(error, "EA-TRUST-ACTION-MISMATCH");
}

#[test]
fn an_authorization_for_another_action_is_refused() {
    let mut line = RegistryLineBuilder::new();
    let head = line.push(
        ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        HeadOptions {
            direct_authorization_action: Some(6),
            ..HeadOptions::default()
        },
    );
    let target = head
        .direct_object_hash
        .expect("ein Policy-Uebergang traegt ein direktes Ziel");
    let trust = line.verified(Pin::None);

    let error = verify_authorized_trust_target(
        &trust,
        None,
        line.exact_object_bytes(target),
        UnixMillis::new(100),
        head.effective_from,
    )
    .err()
    .expect("eine Wurzelrotationsautorisierung autorisiert keine Policy");
    expect_trust_code(error, "EA-TRUST-ACTION-MISMATCH");
}

#[test]
fn a_payload_whose_core_is_not_the_authorized_one_never_reaches_the_key_port() {
    let ceremony = ceremony_line();
    let trust = verified(&ceremony.line);
    let head = selected_head(&ceremony.line);
    let authorization = verify_authorized_trust_target(
        &trust,
        None,
        ceremony
            .line
            .exact_object_bytes(ceremony.target_object_hash),
        USE_TIME,
        ChainSequence::new(support::TARGET_SEQUENCE),
    )
    .expect("das gueltige Paar verifiziert");

    // Die Nutzlast EINER ANDEREN Linie: derselbe Subtyp, ein anderer Kern.
    let stranger = ceremony_stranger_payload();

    let provider = FixtureKeyProvider::root();
    let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
    let service = ceremony_service(&head, &provider, &audit, &ceremony);
    let proof = operator_proof(
        &head,
        ceremony.binding_object_hash,
        ReauthPurpose::AdminRootCeremony,
    );
    let table = Arc::new(Mutex::new(ReplayTable::default()));
    let mut store = PersistentStore::open(&table);

    let error = service
        .publish_authorized_target(
            &authorization,
            stranger,
            ceremony
                .line
                .exact_object_bytes(authorization.authorization_object_hash()),
            &mut store,
            &proof,
        )
        .err()
        .expect("eine Nutzlast, die diese Autorisierung nicht nennt, wird nicht signiert");
    expect_admin_code(error, "EA-CRYPTO-INVALID-PROTOCOL-CORE");
    assert!(
        audit.booked().is_empty(),
        "ein Abbruch vor der Signatur bucht keine Zeile"
    );
}

/// Die Nutzlast einer FREMDEN Linie mit demselben Subtyp.
fn ceremony_stranger_payload() -> ea_format::TrustPayloadV1 {
    let mut line = RegistryLineBuilder::new();
    let (_, payload) = line.push_returning_direct_payload(
        ActionSpec::Policy {
            policy_version: Some(42),
            previous_policy_hash: None,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    payload.expect("ein Policy-Uebergang traegt ein direktes Ziel")
}

#[test]
fn a_proof_for_another_purpose_is_refused_before_the_lock_is_touched() {
    let ceremony = ceremony_line();
    let trust = verified(&ceremony.line);
    let head = selected_head(&ceremony.line);
    let authorization = verify_authorized_trust_target(
        &trust,
        None,
        ceremony
            .line
            .exact_object_bytes(ceremony.target_object_hash),
        USE_TIME,
        ChainSequence::new(support::TARGET_SEQUENCE),
    )
    .expect("das gueltige Paar verifiziert");

    let provider = FixtureKeyProvider::root();
    let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
    let service = ceremony_service(&head, &provider, &audit, &ceremony);
    // Ein Nachweis fuer den ABSCHLUSS — der falsche Zweck fuer eine Zeremonie.
    let proof = operator_proof(&head, ceremony.binding_object_hash, ReauthPurpose::Finalize);
    let table = Arc::new(Mutex::new(ReplayTable::default()));
    let mut store = PersistentStore::open(&table);

    let error = service
        .publish_authorized_target(
            &authorization,
            ceremony.target_payload,
            ceremony
                .line
                .exact_object_bytes(authorization.authorization_object_hash()),
            &mut store,
            &proof,
        )
        .err()
        .expect("ein zweckfremder Nachweis autorisiert keine Zeremonie");
    expect_admin_code(error, "EA-CEREMONY-REAUTH-MISMATCH");
    assert!(
        table
            .lock()
            .expect("die Tabelle der Fixture ist nicht vergiftet")
            .is_empty(),
        "ein abgewiesener Nachweis verbraucht die Autorisierung NICHT"
    );
}

#[test]
fn a_proof_invalidated_by_the_lock_screen_is_refused() {
    let ceremony = ceremony_line();
    let trust = verified(&ceremony.line);
    let head = selected_head(&ceremony.line);
    let authorization = verify_authorized_trust_target(
        &trust,
        None,
        ceremony
            .line
            .exact_object_bytes(ceremony.target_object_hash),
        USE_TIME,
        ChainSequence::new(support::TARGET_SEQUENCE),
    )
    .expect("das gueltige Paar verifiziert");

    let provider = FixtureKeyProvider::root();
    let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
    let service = ceremony_service(&head, &provider, &audit, &ceremony);
    let proof = operator_proof(
        &head,
        ceremony.binding_object_hash,
        ReauthPurpose::AdminRootCeremony,
    )
    .invalidate_on_lock();
    let table = Arc::new(Mutex::new(ReplayTable::default()));
    let mut store = PersistentStore::open(&table);

    let error = service
        .publish_authorized_target(
            &authorization,
            ceremony.target_payload,
            ceremony
                .line
                .exact_object_bytes(authorization.authorization_object_hash()),
            &mut store,
            &proof,
        )
        .err()
        .expect("ein entwerteter Nachweis autorisiert keine Zeremonie");
    expect_admin_code(error, "EA-CEREMONY-REAUTH-MISMATCH");
}

#[test]
fn an_authorization_object_that_is_not_the_proven_one_is_refused() {
    let ceremony = ceremony_line();
    let trust = verified(&ceremony.line);
    let head = selected_head(&ceremony.line);
    let authorization = verify_authorized_trust_target(
        &trust,
        None,
        ceremony
            .line
            .exact_object_bytes(ceremony.target_object_hash),
        USE_TIME,
        ChainSequence::new(support::TARGET_SEQUENCE),
    )
    .expect("das gueltige Paar verifiziert");

    let provider = FixtureKeyProvider::root();
    let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
    let service = ceremony_service(&head, &provider, &audit, &ceremony);
    let proof = operator_proof(
        &head,
        ceremony.binding_object_hash,
        ReauthPurpose::AdminRootCeremony,
    );
    let table = Arc::new(Mutex::new(ReplayTable::default()));
    let mut store = PersistentStore::open(&table);
    // EIN Byte anders: der Beweiszustand nennt einen anderen Objekthash.
    let mut stranger = ceremony
        .line
        .exact_object_bytes(authorization.authorization_object_hash())
        .to_vec();
    let last = stranger.len() - 1;
    stranger[last] ^= 1;

    let error = service
        .publish_authorized_target(
            &authorization,
            ceremony.target_payload,
            &stranger,
            &mut store,
            &proof,
        )
        .err()
        .expect("der Beweiszustand nennt seine Autorisierung selbst");
    expect_admin_code(error, "EA-CEREMONY-AUTHORIZATION-MISMATCH");
}

#[test]
fn a_foreign_root_key_cannot_publish_the_authorized_target() {
    let ceremony = ceremony_line();
    let trust = verified(&ceremony.line);
    let head = selected_head(&ceremony.line);
    let authorization = verify_authorized_trust_target(
        &trust,
        None,
        ceremony
            .line
            .exact_object_bytes(ceremony.target_object_hash),
        USE_TIME,
        ChainSequence::new(support::TARGET_SEQUENCE),
    )
    .expect("das gueltige Paar verifiziert");

    // Derselbe Port, ein FREMDER Schluessel: die Bytes, die entstuenden, waeren
    // nicht das Ziel, ueber das der Beweiszustand spricht.
    let provider = FixtureKeyProvider::foreign();
    let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
    let service = ceremony_service(&head, &provider, &audit, &ceremony);
    let proof = operator_proof(
        &head,
        ceremony.binding_object_hash,
        ReauthPurpose::AdminRootCeremony,
    );
    let table = Arc::new(Mutex::new(ReplayTable::default()));
    let mut store = PersistentStore::open(&table);

    let error = service
        .publish_authorized_target(
            &authorization,
            ceremony.target_payload,
            ceremony
                .line
                .exact_object_bytes(authorization.authorization_object_hash()),
            &mut store,
            &proof,
        )
        .err()
        .expect("ein fremder Wurzelschluessel erzeugt nicht das autorisierte Ziel");
    expect_admin_code(error, "EA-CEREMONY-TARGET-MISMATCH");
    assert!(
        audit.booked().is_empty(),
        "ein Ziel, das der Beweiszustand nicht nennt, wird nicht auditiert"
    );
}
