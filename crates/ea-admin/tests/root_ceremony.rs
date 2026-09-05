//! Die Reihenfolge des Zeremoniendienstes IST seine Zusicherung.
//!
//! Verbrauchen, signieren, kodieren, auditieren — und erst dann herausgeben.
//! Diese Zeugen messen die Reihenfolge an ihren Wirkungen: eine zweite
//! Veroeffentlichung derselben Autorisierung scheitert LAUFUEBERGREIFEND, und
//! ein gescheitertes Audit haelt die Zielbytes zurueck und hinterlaesst eine
//! Zeile mit dem Ausgang `failed`.

mod support;

use std::sync::{Arc, Mutex};

use ea_admin::AdminError;
use ea_crypto::object_hash;
use ea_format::{LocalAuditActionV1, LocalAuditOutcomeV1, decode_local_audit_event};
use ea_operator::ReauthPurpose;
use ea_trust::{VerifiedAdminAuthorization, verify_authorized_trust_target};
use ea_types::{ChainSequence, UnixMillis};

use support::{
    AuditHarness, CeremonyLine, FixtureKeyProvider, PersistentStore, ReplayTable,
    StoreWithoutReplayLock, ceremony_line, ceremony_service, operator_proof, selected_head,
    verified,
};

const USE_TIME: UnixMillis = UnixMillis::new(support::FIXTURE_NOW_MS);

fn expect_admin_code(error: AdminError, expected: &str) {
    assert_eq!(error.code(), expected);
    assert_eq!(error.to_string(), expected);
    assert_eq!(format!("{error:?}"), expected);
}

/// Ein Lauf: eigener Bestand, eigener Beweiszustand, eigener Dienst.
fn prove(ceremony: &CeremonyLine) -> VerifiedAdminAuthorization {
    let trust = verified(&ceremony.line);
    verify_authorized_trust_target(
        &trust,
        None,
        ceremony
            .line
            .exact_object_bytes(ceremony.target_object_hash),
        USE_TIME,
        ChainSequence::new(support::TARGET_SEQUENCE),
    )
    .expect("das Wurzel-signierte Ziel und seine Autorisierung verifizieren")
}

#[test]
fn the_ceremony_books_the_admin_root_ceremony_row_before_it_hands_out_the_bytes() {
    let ceremony = ceremony_line();
    let head = selected_head(&ceremony.line);
    let authorization = prove(&ceremony);
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

    let authorization_object_hash = authorization.authorization_object_hash();
    let published = service
        .publish_authorized_target(
            &authorization,
            ceremony.target_payload,
            ceremony.line.exact_object_bytes(authorization_object_hash),
            &mut store,
            &proof,
        )
        .expect("die Zeremonie gelingt");

    let booked = audit.booked();
    assert_eq!(booked.len(), 1, "genau EINE Zeile je Veroeffentlichung");
    let event = decode_local_audit_event(&booked[0]).expect("die gebuchte Zeile ist wohlgeformt");
    let LocalAuditActionV1::AdminRootCeremony(context) = event.action() else {
        panic!("die Zeremonie schreibt die adminRootCeremony-Zeile");
    };
    assert!(context.authorization_object_hash() == authorization_object_hash);
    assert!(context.target_object_hash() == ceremony.target_object_hash);
    assert_eq!(
        context.action_code(),
        2,
        "der Aktionscode ist der der Administrationsautorisierung — Policy"
    );
    assert_eq!(event.outcome(), LocalAuditOutcomeV1::Completed);
    assert!(
        event.operator_binding_object_hash() == Some(ceremony.binding_object_hash),
        "die pseudonyme Bindung liegt eine Ebene hoeher, im Kern"
    );
    assert!(object_hash(published.as_bytes()) == ceremony.target_object_hash);
}

#[test]
fn the_second_publication_of_the_same_authorization_is_refused_across_runs() {
    let table = Arc::new(Mutex::new(ReplayTable::default()));

    {
        // Erster Lauf.
        let ceremony = ceremony_line();
        let head = selected_head(&ceremony.line);
        let authorization = prove(&ceremony);
        let provider = FixtureKeyProvider::root();
        let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
        let service = ceremony_service(&head, &provider, &audit, &ceremony);
        let proof = operator_proof(
            &head,
            ceremony.binding_object_hash,
            ReauthPurpose::AdminRootCeremony,
        );
        let mut store = PersistentStore::open(&table);
        let authorization_object_hash = authorization.authorization_object_hash();
        service
            .publish_authorized_target(
                &authorization,
                ceremony.target_payload,
                ceremony.line.exact_object_bytes(authorization_object_hash),
                &mut store,
                &proof,
            )
            .expect("die erste Veroeffentlichung gelingt");
    }

    // Zweiter Lauf: frischer Bestand, frischer Beweiszustand, frischer
    // Speicherwert — DASSELBE Backing. Die Pruefung selbst gelingt erneut, weil
    // das prozesslokale Set leer ist; genau deshalb muss der Speicher sperren.
    let ceremony = ceremony_line();
    let head = selected_head(&ceremony.line);
    let replayed = prove(&ceremony);
    let provider = FixtureKeyProvider::root();
    let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
    let service = ceremony_service(&head, &provider, &audit, &ceremony);
    let proof = operator_proof(
        &head,
        ceremony.binding_object_hash,
        ReauthPurpose::AdminRootCeremony,
    );
    let mut store = PersistentStore::open(&table);
    let authorization_object_hash = replayed.authorization_object_hash();

    let error = service
        .publish_authorized_target(
            &replayed,
            ceremony.target_payload,
            ceremony.line.exact_object_bytes(authorization_object_hash),
            &mut store,
            &proof,
        )
        .err()
        .expect("die laufuebergreifende Sperre weist die zweite Nutzung ab");
    expect_admin_code(error, "EA-TRUST-AUTH-REPLAY");
    assert!(
        audit.booked().is_empty(),
        "eine abgewiesene Wiedereinspielung schreibt keine Zeremonienzeile"
    );
}

#[test]
fn a_store_without_the_replay_lock_fails_closed() {
    let ceremony = ceremony_line();
    let head = selected_head(&ceremony.line);
    let authorization = prove(&ceremony);
    let provider = FixtureKeyProvider::root();
    let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
    let service = ceremony_service(&head, &provider, &audit, &ceremony);
    let proof = operator_proof(
        &head,
        ceremony.binding_object_hash,
        ReauthPurpose::AdminRootCeremony,
    );
    let mut store = StoreWithoutReplayLock;
    let authorization_object_hash = authorization.authorization_object_hash();

    let error = service
        .publish_authorized_target(
            &authorization,
            ceremony.target_payload,
            ceremony.line.exact_object_bytes(authorization_object_hash),
            &mut store,
            &proof,
        )
        .err()
        .expect("ein Speicher ohne Sperre darf nicht 'frisch' antworten");
    expect_admin_code(error, "EA-TRUST-STATE-UNAVAILABLE");
}

#[test]
fn a_failing_audit_withholds_the_target_bytes_and_books_a_failed_row() {
    let ceremony = ceremony_line();
    let head = selected_head(&ceremony.line);
    let authorization = prove(&ceremony);
    let provider = FixtureKeyProvider::root();
    // Der ERSTE Anhaengevorgang scheitert — die Zeile mit dem Ausgang
    // `completed`. Der zweite gelingt und ist danach ablesbar.
    let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 1);
    let service = ceremony_service(&head, &provider, &audit, &ceremony);
    let proof = operator_proof(
        &head,
        ceremony.binding_object_hash,
        ReauthPurpose::AdminRootCeremony,
    );
    let table = Arc::new(Mutex::new(ReplayTable::default()));
    let mut store = PersistentStore::open(&table);
    let authorization_object_hash = authorization.authorization_object_hash();

    let error = service
        .publish_authorized_target(
            &authorization,
            ceremony.target_payload,
            ceremony.line.exact_object_bytes(authorization_object_hash),
            &mut store,
            &proof,
        )
        .err()
        .expect("scheitert das Audit, kommen die Zielbytes NICHT heraus");
    expect_admin_code(error, "EA-CEREMONY-AUDIT-FAILED");

    let booked = audit.booked();
    assert_eq!(booked.len(), 1, "die Ruecknahmezeile ist gebucht");
    let event = decode_local_audit_event(&booked[0]).expect("die gebuchte Zeile ist wohlgeformt");
    let LocalAuditActionV1::AdminRootCeremony(context) = event.action() else {
        panic!("auch die Ruecknahme ist eine adminRootCeremony-Zeile");
    };
    assert!(context.target_object_hash() == ceremony.target_object_hash);
    assert_eq!(event.outcome(), LocalAuditOutcomeV1::Failed);
}
