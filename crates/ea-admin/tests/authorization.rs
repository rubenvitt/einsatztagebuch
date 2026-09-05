//! Die Autorisierungsmatrix an der Grenze des Zeremoniendienstes.
//!
//! Die Zusage lautet: NUR ein Ziel, dessen Autorisierung gegen DIESEN Kopf
//! bewiesen ist, kommt in die Signierseite — und nur unter dem Nachweis DER
//! Bedienerin, fuer die der Dienst handelt. Jede Haelfte des Paares allein
//! scheitert, ein fremder Kernhash scheitert, ein fremder Aktionscode
//! scheitert, ein Beweis aus einem anderen Registrierungsstand scheitert.
//!
//! Jeder abweisende Zeuge prueft zusaetzlich, dass die Sperrtabelle danach
//! LEER ist. Das ist die Zeugenschaft ueber die Reihenfolge: wer den Verbrauch
//! vor eine dieser Pruefungen zoege, machte sie rot.

mod support;

use std::sync::{Arc, Mutex};

use ea_admin::AdminError;
use ea_crypto::object_hash;
use ea_format::{CertificateKindV1, OperatorRoleV1, ParsedArchiveObject, decode_exact_object};
use ea_operator::ReauthPurpose;
use ea_trust::{TrustError, verify_authorized_trust_target, verify_intended_trust_target};
use ea_types::{CertificateHash, ChainSequence, UnixMillis};

use support::{
    AFTER_REVOCATION_SEQUENCE, AuditHarness, EARLIER_HEAD, EARLIER_SEQUENCE, FixtureKeyProvider,
    LAST_HEAD, PROPOSED_SEQUENCE, PersistentStore, ReplayTable, ceremony_line, ceremony_proof,
    ceremony_service, ceremony_service_for, ceremony_service_under_root, second_operator_proof,
    selected_head, selected_head_at, trust_support, verified,
};
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

fn assert_untouched(table: &Arc<Mutex<ReplayTable>>) {
    assert!(
        table
            .lock()
            .expect("die Tabelle der Fixture ist nicht vergiftet")
            .is_empty(),
        "eine abgewiesene Zeremonie verbraucht die Autorisierung NICHT"
    );
}

#[test]
fn the_valid_pair_publishes_a_target_that_did_not_exist_before() {
    let ceremony = ceremony_line();
    let head = selected_head(&ceremony.line);
    let intent = ceremony.intent(&head);

    let trust = verified(&ceremony.line);
    let provider = FixtureKeyProvider::root();
    let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
    let service = ceremony_service(&head, &provider, &audit, &ceremony);
    let proof = ceremony_proof(&ceremony, &head, ReauthPurpose::AdminRootCeremony);
    let table = Arc::new(Mutex::new(ReplayTable::default()));
    let mut store = PersistentStore::open(&table);

    let expected_digest_input = ceremony.target_payload.exact_digest_input().to_vec();
    let authorization_bytes = ceremony.authorization_bytes().to_vec();
    let published = service
        .publish_authorized_target(
            &intent,
            ceremony.target_payload,
            &authorization_bytes,
            &mut store,
            &proof,
        )
        .expect("die Zeremonie gibt das autorisierte Ziel heraus");

    let ParsedArchiveObject::Trust(parsed) = decode_exact_object(published.as_bytes())
        .expect("die herausgegebenen Bytes sind ein wohlgeformtes Trust-Objekt")
    else {
        panic!("die Zeremonie gibt ein Trust-Objekt heraus");
    };
    assert_eq!(
        parsed.value().exact_digest_input(),
        expected_digest_input.as_slice(),
        "das veroeffentlichte Objekt traegt genau die beabsichtigte Nutzlast"
    );
    assert_eq!(
        parsed.value().signatures().len(),
        1,
        "genau EINE Wurzelsignatur"
    );
    // Der Beleg, dass die Zeremonie ein Objekt ERZEUGT hat, das es vorher
    // nicht gab: die Laufzeitrichtung findet zu genau diesen OBJEKTBYTES kein
    // Katalogobjekt. Ueber die Nutzlastbytes gemessen waere die Aussage leer —
    // Nutzlastbytes sind nie Objektbytes, der Aufruf meldete
    // `EA-TRUST-SOURCE` auch fuer ein laengst veroeffentlichtes Ziel.
    let absent = verify_authorized_trust_target(
        &trust,
        Some(&head),
        published.as_bytes(),
        USE_TIME,
        ChainSequence::new(PROPOSED_SEQUENCE),
    )
    .err()
    .expect("das erzeugte Objekt lag in diesem Bestand nicht");
    expect_trust_code(absent, "EA-TRUST-SOURCE");
    assert!(
        !table
            .lock()
            .expect("die Tabelle der Fixture ist nicht vergiftet")
            .is_empty(),
        "die gelungene Veroeffentlichung hat die Autorisierung verbraucht"
    );
}

#[test]
fn a_root_signed_object_without_an_admin_authorization_is_no_authorized_target() {
    let ceremony = ceremony_line();
    let trust = verified(&ceremony.line);
    let head = selected_head(&ceremony.line);
    // Das Bootstrap-Administratorzertifikat: Wurzel-signiert, aber ohne jede
    // Administrationsautorisierung — die Root-only-Haelfte des Paares.
    let root_only = ceremony
        .line
        .exact_object_bytes(ceremony.line.bootstrap_admin_hash())
        .to_vec();

    let error = verify_authorized_trust_target(
        &trust,
        Some(&head),
        &root_only,
        USE_TIME,
        ChainSequence::new(PROPOSED_SEQUENCE),
    )
    .err()
    .expect("eine Wurzelsignatur allein autorisiert keine Aenderung");
    expect_trust_code(error, "EA-TRUST-ACTION-MISMATCH");
}

#[test]
fn an_admin_authorization_alone_is_no_authorized_target() {
    let ceremony = ceremony_line();
    let trust = verified(&ceremony.line);
    let head = selected_head(&ceremony.line);
    // Die Admin-only-Haelfte: das Autorisierungsobjekt selbst, Admin-signiert
    // und ohne Wurzelsignatur.
    let admin_only = ceremony.authorization_bytes().to_vec();

    let error = verify_authorized_trust_target(
        &trust,
        Some(&head),
        &admin_only,
        USE_TIME,
        ChainSequence::new(PROPOSED_SEQUENCE),
    )
    .err()
    .expect("eine Administrationsautorisierung ist kein autorisiertes Ziel");
    expect_trust_code(error, "EA-TRUST-ACTION-MISMATCH");
}

#[test]
fn an_authorization_for_another_action_is_refused() {
    let mut line = RegistryLineBuilder::new();
    let (_, payload) = line.prepare_unsigned(
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
    let trust = line.verified(Pin::None);

    let error = verify_intended_trust_target(
        &trust,
        None,
        &payload,
        UnixMillis::new(100),
        ChainSequence::new(1),
    )
    .err()
    .expect("eine Wurzelrotationsautorisierung autorisiert keine Policy");
    expect_trust_code(error, "EA-TRUST-ACTION-MISMATCH");
}

#[test]
fn a_payload_whose_core_is_not_the_authorized_one_never_reaches_the_key_port() {
    let ceremony = ceremony_line();
    let head = selected_head(&ceremony.line);
    let intent = ceremony.intent(&head);

    // Die Nutzlast EINER ANDEREN Linie: derselbe Subtyp, ein anderer Kern.
    let stranger = stranger_policy_payload();

    let provider = FixtureKeyProvider::root();
    let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
    let service = ceremony_service(&head, &provider, &audit, &ceremony);
    let proof = ceremony_proof(&ceremony, &head, ReauthPurpose::AdminRootCeremony);
    let table = Arc::new(Mutex::new(ReplayTable::default()));
    let mut store = PersistentStore::open(&table);

    let error = service
        .publish_authorized_target(
            &intent,
            stranger,
            ceremony.authorization_bytes(),
            &mut store,
            &proof,
        )
        .err()
        .expect("eine Nutzlast, die diese Autorisierung nicht deckt, wird nicht signiert");
    expect_admin_code(error, "EA-CRYPTO-INVALID-PROTOCOL-CORE");
    assert_eq!(
        provider.signatures_produced(),
        0,
        "der Schluesselport wurde gar nicht erst gefragt"
    );
    assert!(
        audit.booked().is_empty(),
        "ein Abbruch vor der Signatur bucht keine Zeile"
    );
    assert_untouched(&table);
}

/// Die Nutzlast einer FREMDEN Linie mit demselben Subtyp.
fn stranger_policy_payload() -> ea_format::TrustPayloadV1 {
    let mut line = RegistryLineBuilder::new();
    let (_, payload) = line.prepare_unsigned(
        ActionSpec::Policy {
            policy_version: Some(42),
            previous_policy_hash: None,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    payload
}

#[test]
fn a_payload_of_another_subtype_is_refused_against_the_proven_intent() {
    let ceremony = ceremony_line();
    let head = selected_head(&ceremony.line);
    let intent = ceremony.intent(&head);

    // Eine Bedienerbindung statt einer Policy — ein anderer Subtyp, und der
    // Beweiszustand nennt seinen eigenen.
    let mut stranger_line = RegistryLineBuilder::new();
    let writer = stranger_line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x61,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    let (_, stranger) = stranger_line.prepare_unsigned(
        ActionSpec::OperatorBinding {
            certificate_hash: writer
                .direct_object_hash
                .expect("das Writer-Zertifikat ist ein direktes Ziel"),
            role: OperatorRoleV1::Writer,
            marker: 0x77,
            effective_from: None,
        },
        HeadOptions::default(),
    );

    let provider = FixtureKeyProvider::root();
    let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
    let service = ceremony_service(&head, &provider, &audit, &ceremony);
    let proof = ceremony_proof(&ceremony, &head, ReauthPurpose::AdminRootCeremony);
    let table = Arc::new(Mutex::new(ReplayTable::default()));
    let mut store = PersistentStore::open(&table);

    let error = service
        .publish_authorized_target(
            &intent,
            stranger,
            ceremony.authorization_bytes(),
            &mut store,
            &proof,
        )
        .err()
        .expect("der Beweiszustand deckt genau EINEN Subtyp");
    expect_admin_code(error, "EA-CEREMONY-TARGET-MISMATCH");
    assert_eq!(provider.signatures_produced(), 0);
    assert_untouched(&table);
}

#[test]
fn a_proof_for_another_purpose_is_refused_before_the_lock_is_touched() {
    let ceremony = ceremony_line();
    let head = selected_head(&ceremony.line);
    let intent = ceremony.intent(&head);

    let provider = FixtureKeyProvider::root();
    let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
    let service = ceremony_service(&head, &provider, &audit, &ceremony);
    // Ein Nachweis fuer den ABSCHLUSS — der falsche Zweck fuer eine Zeremonie.
    let proof = ceremony_proof(&ceremony, &head, ReauthPurpose::Finalize);
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
        .expect("ein zweckfremder Nachweis autorisiert keine Zeremonie");
    expect_admin_code(error, "EA-CEREMONY-REAUTH-MISMATCH");
    assert_untouched(&table);
}

#[test]
fn a_proof_invalidated_by_the_lock_screen_is_refused() {
    let ceremony = ceremony_line();
    let head = selected_head(&ceremony.line);
    let intent = ceremony.intent(&head);

    let provider = FixtureKeyProvider::root();
    let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
    let service = ceremony_service(&head, &provider, &audit, &ceremony);
    let proof =
        ceremony_proof(&ceremony, &head, ReauthPurpose::AdminRootCeremony).invalidate_on_lock();
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
        .expect("ein entwerteter Nachweis autorisiert keine Zeremonie");
    expect_admin_code(error, "EA-CEREMONY-REAUTH-MISMATCH");
    assert_untouched(&table);
}

#[test]
fn the_proof_of_another_bound_operator_of_the_same_organization_is_refused() {
    let ceremony = ceremony_line();
    let head = selected_head(&ceremony.line);
    let intent = ceremony.intent(&head);

    let provider = FixtureKeyProvider::root();
    let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
    let service = ceremony_service(&head, &provider, &audit, &ceremony);
    // FRISCH, richtiger Zweck, am Kopf AKTIVE Bindung — nur eben eine andere
    // Bedienerin. Ohne den Bindungsvergleich veroeffentlichte sie das
    // Wurzelziel, und die Auditzeile rechnete es ihr zu.
    let stranger = second_operator_proof(&ceremony, &head, ReauthPurpose::AdminRootCeremony);
    assert!(
        head.active_operator_binding_fields(ceremony.second_binding_object_hash)
            .is_some(),
        "die zweite Bindung ist an dieser Sequenz wirklich aktiv"
    );
    let table = Arc::new(Mutex::new(ReplayTable::default()));
    let mut store = PersistentStore::open(&table);

    let authorization_bytes = ceremony.authorization_bytes().to_vec();
    let error = service
        .publish_authorized_target(
            &intent,
            ceremony.target_payload,
            &authorization_bytes,
            &mut store,
            &stranger,
        )
        .err()
        .expect("der Dienst handelt fuer GENAU EINE Bindung");
    expect_admin_code(error, "EA-CEREMONY-BINDING-MISMATCH");
    assert!(audit.booked().is_empty());
    assert_untouched(&table);
}

#[test]
fn a_proof_whose_binding_the_head_has_revoked_is_refused() {
    let ceremony = ceremony_line();
    // Der Nachweis entsteht an einer Sequenz VOR dem Widerruf …
    let issuing_head = selected_head(&ceremony.line);
    let proof = second_operator_proof(&ceremony, &issuing_head, ReauthPurpose::AdminRootCeremony);

    // … und wird an einer Sequenz DAHINTER vorgelegt: derselbe Kopf, dieselbe
    // Zeit, aber die Bindung ist dort widerrufen.
    let head = selected_head_at(&ceremony.line, LAST_HEAD, AFTER_REVOCATION_SEQUENCE);
    assert!(
        head.active_operator_binding_fields(ceremony.second_binding_object_hash)
            .is_none(),
        "die zweite Bindung ist hinter ihrem Widerruf nicht mehr aktiv"
    );
    let intent = ceremony.intent(&head);

    let provider = FixtureKeyProvider::root();
    let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
    let service = ceremony_service_for(
        &head,
        &provider,
        &audit,
        &ceremony,
        ceremony.second_binding_object_hash,
    );
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
        .expect("eine widerrufene Bindung handelt nicht mehr");
    expect_admin_code(error, "EA-CEREMONY-BINDING-INACTIVE");
    assert!(audit.booked().is_empty());
    assert_untouched(&table);
}

#[test]
fn a_proof_state_of_another_registry_head_is_refused() {
    let ceremony = ceremony_line();
    // Der Beweiszustand gegen den AKTUELLEN Kopf …
    let proving_head = selected_head(&ceremony.line);
    let intent = ceremony.intent(&proving_head);

    // … und ein Dienst, der gegen den VORHERIGEN handelt. Zeit,
    // Bedienerbindung, Wurzelzertifikat und Auditdienst kaemen von dort.
    let head = selected_head_at(&ceremony.line, EARLIER_HEAD, EARLIER_SEQUENCE);
    assert!(
        head.registry_version() != proving_head.registry_version(),
        "die beiden Koepfe tragen wirklich verschiedene Registrierungsfassungen"
    );
    let provider = FixtureKeyProvider::root();
    let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
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
        .expect("ein Beweis aus einem anderen Registrierungsstand wirkt hier nicht");
    expect_admin_code(error, "EA-CEREMONY-HEAD-MISMATCH");
    assert_eq!(provider.signatures_produced(), 0);
    assert!(audit.booked().is_empty());
    assert_untouched(&table);
}

#[test]
fn an_authorization_object_that_is_not_the_proven_one_is_refused() {
    let ceremony = ceremony_line();
    let head = selected_head(&ceremony.line);
    let intent = ceremony.intent(&head);

    let provider = FixtureKeyProvider::root();
    let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
    let service = ceremony_service(&head, &provider, &audit, &ceremony);
    let proof = ceremony_proof(&ceremony, &head, ReauthPurpose::AdminRootCeremony);
    let table = Arc::new(Mutex::new(ReplayTable::default()));
    let mut store = PersistentStore::open(&table);
    // EIN Byte anders: der Beweiszustand nennt einen anderen Objekthash.
    let mut stranger = ceremony.authorization_bytes().to_vec();
    let last = stranger.len() - 1;
    stranger[last] ^= 1;
    assert!(object_hash(&stranger) != intent.authorization_object_hash());

    let error = service
        .publish_authorized_target(
            &intent,
            ceremony.target_payload,
            &stranger,
            &mut store,
            &proof,
        )
        .err()
        .expect("der Beweiszustand nennt seine Autorisierung selbst");
    expect_admin_code(error, "EA-CEREMONY-AUTHORIZATION-MISMATCH");
    assert_eq!(provider.signatures_produced(), 0);
    assert_untouched(&table);
}

#[test]
fn a_foreign_root_key_cannot_publish_and_leaves_no_completed_row() {
    let ceremony = ceremony_line();
    let head = selected_head(&ceremony.line);
    let intent = ceremony.intent(&head);

    // Derselbe Port, ein FREMDER Schluessel. Der Kopfuebergang wiese das
    // fertige Objekt spaeter ab — aber bis dahin waere eine von zwei
    // Administratoren ausgestellte Einmal-Autorisierung verbrannt und eine
    // `completed`-Auditzeile ueber eine Vollendung gebucht, die keine ist.
    let provider = FixtureKeyProvider::foreign();
    let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
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
        .expect("ein fremder Wurzelschluessel veroeffentlicht nicht");
    expect_admin_code(error, "EA-CEREMONY-ROOT-SIGNATURE-MISMATCH");
    assert_eq!(
        provider.signatures_produced(),
        1,
        "der Port wurde gefragt — und seine Antwort wurde zurueckgelesen"
    );
    assert!(
        audit.booked().is_empty(),
        "keine Zeile ueber eine Vollendung, die keine ist"
    );
    assert_untouched(&table);
}

#[test]
fn a_certificate_hash_that_is_not_the_heads_root_is_refused() {
    let ceremony = ceremony_line();
    let head = selected_head(&ceremony.line);
    let intent = ceremony.intent(&head);

    let provider = FixtureKeyProvider::root();
    let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
    // Ein echtes, aktives Zertifikat der Linie — nur eben nicht die Wurzel.
    let service = ceremony_service_under_root(
        &head,
        &provider,
        &audit,
        &ceremony,
        CertificateHash::from(ceremony.writer_certificate_object_hash),
    );
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
        .expect("der Dienst signiert nur unter der Wurzelurkunde SEINES Kopfes");
    expect_admin_code(error, "EA-CEREMONY-ROOT-CERTIFICATE-MISMATCH");
    assert!(audit.booked().is_empty());
    assert_untouched(&table);
}

#[test]
fn a_provider_that_claims_the_root_thumbprint_but_signs_with_another_key_is_refused() {
    let ceremony = ceremony_line();
    let head = selected_head(&ceremony.line);
    let intent = ceremony.intent(&head);

    // Der geschuetzte Kopf NENNT den Abdruck der Wurzel; unterschrieben hat
    // ein anderer Schluessel. `CoseSign1Bytes::compose` liest seine Bytes nur
    // gegen `parse_cose_sign1` zurueck, und das prueft keine Signatur — ein
    // reiner Abdruckvergleich faellt auf diesen Provider herein.
    let provider = FixtureKeyProvider::impersonating_root();
    let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
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
        .expect("ein behaupteter Abdruck ist keine Wurzelsignatur");
    expect_admin_code(error, "EA-CEREMONY-ROOT-SIGNATURE-MISMATCH");
    assert!(audit.booked().is_empty());
    assert_untouched(&table);
}
