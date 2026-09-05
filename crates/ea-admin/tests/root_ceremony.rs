//! Die Reihenfolge des Zeremoniendienstes IST seine Zusicherung.
//!
//! Pruefen, signieren, kodieren — DANN verbrauchen, auditieren und erst dann
//! herausgeben. Diese Zeugen messen die Reihenfolge an ihren Wirkungen: eine
//! zweite Veroeffentlichung derselben Autorisierung scheitert
//! LAUFUEBERGREIFEND und in BEIDEN Sperrdimensionen, ein gescheitertes Audit
//! haelt die Zielbytes zurueck und hinterlaesst eine Zeile mit dem Ausgang
//! `failed`, und der Aktionscode der Zeile ist der, den die Autorisierung
//! wirklich traegt.

mod support;

use std::sync::{Arc, Mutex};

use ea_admin::AdminError;
use ea_crypto::{VerificationContext, object_hash};
use ea_format::{
    CertificateKindV1, DecodedTrustPayloadV1, LocalAuditActionV1, LocalAuditOutcomeV1,
    OperatorRoleV1, ParsedArchiveObject, decode_exact_object, decode_local_audit_event,
};
use ea_operator::ReauthPurpose;
use ea_trust::verify_intended_trust_target;
use ea_types::{CertificateHash, ChainSequence, UnixMillis};

use support::{
    AuditHarness, FixtureKeyProvider, PersistentStore, ReplayTable, StoreWithoutReplayLock,
    ceremony_line, ceremony_proof, ceremony_service, selected_head, trust_support,
};
use trust_support::{ActionSpec, HeadOptions, Pin, RegistryLineBuilder};

fn expect_admin_code(error: AdminError, expected: &str) {
    assert_eq!(error.code(), expected);
    assert_eq!(error.to_string(), expected);
    assert_eq!(format!("{error:?}"), expected);
}

#[test]
fn the_ceremony_books_the_admin_root_ceremony_row_before_it_hands_out_the_bytes() {
    let ceremony = ceremony_line();
    let head = selected_head(&ceremony.line);
    let intent = ceremony.intent(&head);
    let provider = FixtureKeyProvider::root();
    let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
    let service = ceremony_service(&head, &provider, &audit, &ceremony);
    let proof = ceremony_proof(&ceremony, &head, ReauthPurpose::AdminRootCeremony);
    let table = Arc::new(Mutex::new(ReplayTable::default()));
    let mut store = PersistentStore::open(&table);

    let authorization_object_hash = ceremony.authorization_object_hash;
    let authorization_bytes = ceremony.authorization_bytes().to_vec();
    let published = service
        .publish_authorized_target(
            &intent,
            ceremony.target_payload,
            &authorization_bytes,
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
    assert!(
        context.target_object_hash() == object_hash(published.as_bytes()),
        "die Zeile nennt genau das Objekt, das herausgegeben wurde"
    );
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
}

#[test]
fn the_second_publication_of_the_same_authorization_is_refused_across_runs() {
    let table = Arc::new(Mutex::new(ReplayTable::default()));

    {
        // Erster Lauf.
        let ceremony = ceremony_line();
        let head = selected_head(&ceremony.line);
        let intent = ceremony.intent(&head);
        let provider = FixtureKeyProvider::root();
        let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
        let service = ceremony_service(&head, &provider, &audit, &ceremony);
        let proof = ceremony_proof(&ceremony, &head, ReauthPurpose::AdminRootCeremony);
        let mut store = PersistentStore::open(&table);
        let authorization_bytes = ceremony.authorization_bytes().to_vec();
        service
            .publish_authorized_target(
                &intent,
                ceremony.target_payload,
                &authorization_bytes,
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
    let replayed = ceremony.intent(&head);
    let provider = FixtureKeyProvider::root();
    let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
    let service = ceremony_service(&head, &provider, &audit, &ceremony);
    let proof = ceremony_proof(&ceremony, &head, ReauthPurpose::AdminRootCeremony);
    let mut store = PersistentStore::open(&table);
    let authorization_bytes = ceremony.authorization_bytes().to_vec();

    let error = service
        .publish_authorized_target(
            &replayed,
            ceremony.target_payload,
            &authorization_bytes,
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
fn the_lock_holds_both_dimensions_of_the_authorization() {
    let ceremony = ceremony_line();
    let head = selected_head(&ceremony.line);
    let intent = ceremony.intent(&head);
    let provider = FixtureKeyProvider::root();
    let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
    let service = ceremony_service(&head, &provider, &audit, &ceremony);
    let proof = ceremony_proof(&ceremony, &head, ReauthPurpose::AdminRootCeremony);
    let table = Arc::new(Mutex::new(ReplayTable::default()));
    let mut store = PersistentStore::open(&table);
    let authorization_bytes = ceremony.authorization_bytes().to_vec();

    service
        .publish_authorized_target(
            &intent,
            ceremony.target_payload,
            &authorization_bytes,
            &mut store,
            &proof,
        )
        .expect("die Veroeffentlichung gelingt");

    // ZWEI Sperrzeilen, nicht eine: `authorizationId` und `nonce` sind je fuer
    // sich organisationsweit einmalig. Eine gemeinsame Zeile aus beiden waere
    // schwaecher — eine zweite Autorisierung mit derselben Nonce und einer
    // anderen Kennung kaeme durch.
    assert_eq!(
        table
            .lock()
            .expect("die Tabelle der Fixture ist nicht vergiftet")
            .len(),
        2,
        "eine Autorisierung setzt beide Sperrdimensionen"
    );
}

#[test]
fn a_store_without_the_replay_lock_fails_closed() {
    let ceremony = ceremony_line();
    let head = selected_head(&ceremony.line);
    let intent = ceremony.intent(&head);
    let provider = FixtureKeyProvider::root();
    let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
    let service = ceremony_service(&head, &provider, &audit, &ceremony);
    let proof = ceremony_proof(&ceremony, &head, ReauthPurpose::AdminRootCeremony);
    let mut store = StoreWithoutReplayLock;
    let authorization_bytes = ceremony.authorization_bytes().to_vec();

    let error = service
        .publish_authorized_target(
            &intent,
            ceremony.target_payload,
            &authorization_bytes,
            &mut store,
            &proof,
        )
        .err()
        .expect("ein Speicher ohne Sperre darf nicht 'frisch' antworten");
    expect_admin_code(error, "EA-TRUST-STATE-UNAVAILABLE");
    assert!(
        audit.booked().is_empty(),
        "ohne Verbrauch keine Zeremonienzeile"
    );
}

#[test]
fn a_failing_audit_withholds_the_target_bytes_and_books_a_failed_row() {
    let ceremony = ceremony_line();
    let head = selected_head(&ceremony.line);
    let intent = ceremony.intent(&head);
    let provider = FixtureKeyProvider::root();
    // Der ERSTE Anhaengevorgang scheitert — die Zeile mit dem Ausgang
    // `completed`. Der zweite gelingt und ist danach ablesbar.
    let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 1);
    let service = ceremony_service(&head, &provider, &audit, &ceremony);
    let proof = ceremony_proof(&ceremony, &head, ReauthPurpose::AdminRootCeremony);
    let table = Arc::new(Mutex::new(ReplayTable::default()));
    let mut store = PersistentStore::open(&table);
    let authorization_bytes = ceremony.authorization_bytes().to_vec();

    let error = service
        .publish_authorized_target(
            &intent,
            ceremony.target_payload,
            &authorization_bytes,
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
    assert!(context.authorization_object_hash() == ceremony.authorization_object_hash);
    assert_eq!(event.outcome(), LocalAuditOutcomeV1::Failed);
    // Der Verbrauch liegt VOR dem Audit; ein Abbruch hier ist der EINZIGE, der
    // verbraucht — und er schweigt nicht.
    assert!(
        !table
            .lock()
            .expect("die Tabelle der Fixture ist nicht vergiftet")
            .is_empty()
    );
}

/// Die fuenf Aktionscodes, die als DIREKTES Ziel einer Zeremonie ueberhaupt
/// erreichbar sind, samt der Objektart, die sie tragen.
///
/// Code 1 — Widerruf — fehlt, und zwar nicht aus Nachlaessigkeit: eine
/// Widerrufung hat kein direktes Ziel (`ActionSpec::has_direct_target` ist
/// dafuer falsch), sie lebt ausschliesslich in der Aenderung des
/// Registrierungsereignisses. Es gibt also keine Nutzlast, die ein
/// Zeremoniendienst dafuer unterschreiben koennte.
///
/// Code 3 — Writer-Uebergang — fehlt aus demselben Grund NICHT, sondern weil
/// er zwei bereits aktive Writer-Zertifikate nennt; die braeuchten zwei
/// Uebergaenge, und dann laege die Autorisierung nicht mehr auf
/// Registrierung null. Der Zeuge misst die UEBEREINSTIMMUNG DER LESER, und
/// die haengt nicht an der Objektart.
fn reachable_action_specs(line: &RegistryLineBuilder) -> Vec<(u64, ActionSpec)> {
    vec![
        (
            0,
            ActionSpec::Device {
                kind: CertificateKindV1::Writer,
                marker: 0x51,
                effective_from: None,
            },
        ),
        (
            2,
            ActionSpec::Policy {
                policy_version: None,
                previous_policy_hash: None,
                effective_from: None,
            },
        ),
        (
            4,
            ActionSpec::OperatorBinding {
                // Das Bootstrap-Administratorzertifikat: ein Objekt, das es auf
                // Registrierung null schon gibt. Ein frisch gepushtes
                // Zertifikat ruecke die Linie vor, und die Autorisierung laege
                // dann nicht mehr auf dem Stand, gegen den dieser Zeuge prueft.
                certificate_hash: line.bootstrap_admin_hash(),
                role: OperatorRoleV1::OrganizationAdmin,
                marker: 0x52,
                effective_from: None,
            },
        ),
        (
            5,
            ActionSpec::AdminIssue {
                marker: 0x54,
                effective_from: None,
            },
        ),
        (
            6,
            ActionSpec::RootRotate {
                previous_root_hash: Some(line.current_root_hash()),
                effective_version: None,
            },
        ),
    ]
}

/// Der Aktionscode der Auditzeile ist der, den die geschlossene Aktionstabelle
/// FORDERT — fuer jede Objektart, die eine Zeremonie unterschreiben kann.
///
/// Drei Leser stehen ueber denselben Bytes: `ea-format` (den `ea-trust` und
/// diese Crate benutzen), `ea-crypto` an der Signaturgrenze, und die
/// geschlossene Aktionstabelle, die `ea-trust` gegen den gelesenen Wert
/// stellt. Divergierten sie, naennte eine ausgelieferte
/// `adminRootCeremony`-Zeile eine andere Aktion als die, die zugelassen wurde.
#[test]
fn every_reachable_action_code_reaches_the_audit_line_unchanged() {
    for (expected_code, action) in reachable_action_specs(&RegistryLineBuilder::new()) {
        let mut line = RegistryLineBuilder::new();
        let root_certificate_hash = CertificateHash::from(line.current_root_hash());
        let (authorization_object_hash, payload) =
            line.prepare_unsigned(action, HeadOptions::default());
        let trust = line.verified(Pin::None);

        // 1. `ea-trust` stellt den gelesenen Aktionscode gegen
        //    `descriptor.required_action` aus der geschlossenen Tabelle.
        //    Gelingt der Beweis, IST der gelesene Wert der geforderte.
        let intent = verify_intended_trust_target(
            &trust,
            None,
            &payload,
            UnixMillis::new(100),
            ChainSequence::new(1),
        )
        .unwrap_or_else(|error| {
            panic!("Aktionscode {expected_code}: der Beweis muss tragen, nicht {error:?}")
        });
        assert!(intent.target_trust_subtype() == payload.subtype());

        // 2. `ea-crypto` liest denselben Wert an der Signaturgrenze und stellt
        //    ihn gegen `admin_action_permits_target`.
        VerificationContext::root_trust_digest(
            payload.exact_digest_input(),
            root_certificate_hash,
            Some(line.exact_object_bytes(authorization_object_hash)),
        )
        .unwrap_or_else(|error| {
            panic!("Aktionscode {expected_code}: die Signaturgrenze muss tragen, nicht {error:?}")
        });

        // 3. Der Leser der Auditzeile — `ea_format::decode_exact_object`,
        //    derselbe, den `ea_admin::admin_action_code` fuehrt.
        let ParsedArchiveObject::Trust(parsed) =
            decode_exact_object(line.exact_object_bytes(authorization_object_hash))
                .expect("die Autorisierung ist ein wohlgeformtes Objekt")
        else {
            panic!("die Autorisierung ist ein Trust-Objekt");
        };
        let DecodedTrustPayloadV1::OrganizationAdminAuthorization(fields) = parsed
            .value()
            .decoded_payload()
            .expect("die Autorisierung ist wohlgeformt")
        else {
            panic!("die Autorisierung ist eine Administrationsautorisierung");
        };
        assert_eq!(
            u64::from(fields.action_code),
            expected_code,
            "der Leser der Auditzeile und die geschlossene Aktionstabelle muessen \
             denselben Aktionscode nennen"
        );
    }
}
