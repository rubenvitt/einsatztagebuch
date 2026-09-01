//! Die Kardinalitaet aus `web-reader-design.md` §6.3, die
//! Envelope-Konstruktion aus §6.2 und die REIHENFOLGE der drei Endpunktaufrufe
//! aus §6.4.1.
//!
//! # Die Reihenfolge ist die Zusage, nicht die Anzahl
//!
//! `finish` legt erst beide WebAuthn-Credentials beim Sync-Server an, laedt
//! danach GENAU EINEN versiegelten Tresor hoch und schreibt erst dann lokal.
//! Die Reihenfolge ist fail-closed: ein lokal geschriebener Tresor ohne
//! serverseitige Kopie ueberstuende kein geraeumtes Browserprofil, und §6.4
//! verlangt genau, dass dieser Fall ohne Administrationsvorgang geloest wird.
//! Deshalb steht sie hier als GANZE Liste und nicht als drei Einzelproben —
//! drei Anwesenheitspruefungen blieben gruen, wenn der Upload vor die
//! Registrierungen rutschte.
//!
//! # `.err().expect(..)` und nicht `.unwrap_err()`
//!
//! `Result::unwrap_err` ist auf `T: Debug` beschraenkt, und drei OK-Typen
//! dieser Aufgabe haben keins: `&AuthenticatorRecordV1` (er haelt eine
//! `SecretBytes<32>`), `EnrolledReaderV1` und `FingerprintConfirmationV1`, das
//! es ausdruecklich nicht bekommt. Dieselbe Schreibweise steht aus demselben
//! Grund schon in `crates/ea-reader/tests/vault_envelope.rs`. Wo der OK-Typ ein
//! `Debug` HAT — `UnlockedVault` mit seiner handgeschriebenen Ausgabe —, bleibt
//! `.unwrap_err()` stehen.

mod fixtures;

use ea_crypto::SecretBytes;
use ea_reader::{
    EnrollmentCallV1, EnrollmentEndpointError, InMemoryEnrollmentEndpoints,
    InMemoryReaderBlobStore, ReaderBlobStore, ReaderEnrollment, recover_and_unlock_vault,
};
use ea_sync_protocol::HttpMethod;

#[test]
fn a_single_authenticator_is_a_refusal_and_writes_no_blob() {
    let mut store = InMemoryReaderBlobStore::new();
    let mut endpoints = InMemoryEnrollmentEndpoints::new();
    let mut enrollment = ReaderEnrollment::begin(
        &store,
        fixtures::organization(),
        fixtures::subject(),
        fixtures::pinned_anchor(),
        fixtures::bundle_fingerprint(),
    )
    .unwrap();
    enrollment
        .register_authenticator(fixtures::attested(1))
        .unwrap();
    let shown = enrollment.fingerprints();
    let confirmation = enrollment
        .confirm_fingerprints(
            &shown.key_fingerprint_hex(),
            &shown.bundle_fingerprint_hex(),
        )
        .unwrap();
    let refused = enrollment
        .finish(
            confirmation,
            fixtures::request_context(),
            &mut endpoints,
            &mut store,
        )
        .err()
        .expect("ein einzelner Authenticator ist eine Weigerung");
    assert_eq!(refused.code(), "EA-READER-ENROLLMENT-SINGLE-AUTHENTICATOR");
    assert!(
        store.keys().unwrap().is_empty(),
        "a refused enrollment must leave no vault blob behind"
    );
    assert!(
        endpoints.calls().is_empty(),
        "a refused enrollment must not reach a single endpoint"
    );
}

/// Die Weigerung, die den Ausschluss ueber die LEBENSDAUER EINES ENROLLMENTS
/// hinaus traegt.
///
/// `excludeCredentials` speist sich aus dem Zustand EINES laufenden
/// `ReaderEnrollment`, und der beginnt mit einem leeren Satz. `/enrollment` ist
/// aber eine gewoehnliche, anfahrbare Route, und die Flaeche ruft `begin` bei
/// jeder Montage; `user.id` ist dabei stets dieselbe pseudonyme `subjectId`.
/// Ein ZWEITER Besuch nach einem abgeschlossenen Enrollment schickte also
/// wieder `excludeCredentials: []` — und ein einziger Klick auf „Authenticator
/// registrieren" ersetzte auf demselben Plattform-Authenticator den Passkey des
/// bereits versiegelten UND hochgeladenen Tresors. Derselbe Defekt, nur gegen
/// einen lebenden Tresor statt gegen einen halb gebauten.
///
/// Gemessen werden hier drei Dinge und nicht eines: auf einem FRISCHEN Geraet
/// beginnt ein Enrollment, auf einem Geraet MIT Tresor ist der Anlauf eine
/// Weigerung unter einem eigenen Code, und die Weigerung laesst den lokalen
/// Bytespeicher BYTEGLEICH stehen. Der dritte Punkt ist der, ohne den der Zeuge
/// auch dann gruen bliebe, wenn `begin` den vorhandenen Tresor ueberschriebe und
/// erst danach abbraeche.
#[test]
fn begin_refuses_on_a_device_that_already_carries_a_sealed_vault() {
    let mut store = InMemoryReaderBlobStore::new();
    let mut endpoints = InMemoryEnrollmentEndpoints::new();

    // Auf einem frischen Geraet ist `begin` ein Erfolg — sonst maesse die
    // Weigerung unten nichts als eine Funktion, die immer faellt.
    ReaderEnrollment::begin(
        &store,
        fixtures::organization(),
        fixtures::subject(),
        fixtures::pinned_anchor(),
        fixtures::bundle_fingerprint(),
    )
    .expect("ein Geraet ohne Tresor beginnt ein Enrollment");

    let enrolled = fixtures::two_authenticator_enrollment_into(&mut endpoints, &mut store);
    let keys_before = store.keys().unwrap();
    assert_eq!(keys_before, vec![enrolled.blob_key().clone()]);
    let sealed_before = store.get(enrolled.blob_key()).unwrap().unwrap();

    // `.err().expect(..)` und nicht `.unwrap_err()`: der OK-Typ ist
    // `ReaderEnrollment`, und der traegt kein `Debug`.
    let refused = ReaderEnrollment::begin(
        &store,
        fixtures::organization(),
        fixtures::subject(),
        fixtures::pinned_anchor(),
        fixtures::bundle_fingerprint(),
    )
    .err()
    .expect("ein Geraet mit versiegeltem Tresor beginnt kein zweites Enrollment");
    assert_eq!(refused.code(), "EA-READER-ENROLLMENT-VAULT-PRESENT");

    assert_eq!(
        store.keys().unwrap(),
        keys_before,
        "eine abgewiesene Wiederaufnahme legt keinen zweiten Blob an"
    );
    assert_eq!(
        store.get(enrolled.blob_key()).unwrap().unwrap(),
        sealed_before,
        "und sie ruehrt den vorhandenen Tresor nicht an"
    );
    assert!(
        endpoints.calls().len() == 3,
        "und sie erreicht keinen weiteren Endpunkt"
    );
}

#[test]
fn finish_calls_three_endpoints_in_order_and_only_then_writes_locally() {
    let mut store = InMemoryReaderBlobStore::new();
    let mut endpoints = InMemoryEnrollmentEndpoints::new();
    let enrolled = fixtures::two_authenticator_enrollment_into(&mut endpoints, &mut store);
    // Die Reihenfolge IST die Zusage, deshalb steht sie als ganze Liste da und
    // nicht als drei Einzelproben.
    assert_eq!(
        endpoints.calls(),
        &[
            EnrollmentCallV1 {
                method: HttpMethod::Post,
                target_uri: "/v1/webauthn-credentials".to_owned(),
                signed: true
            },
            EnrollmentCallV1 {
                method: HttpMethod::Post,
                target_uri: "/v1/webauthn-credentials".to_owned(),
                signed: true
            },
            EnrollmentCallV1 {
                method: HttpMethod::Put,
                target_uri: "/v1/vault-blobs".to_owned(),
                signed: true
            },
        ]
    );
    assert_eq!(store.keys().unwrap(), vec![enrolled.blob_key().clone()]);
}

#[test]
fn a_failing_upload_leaves_nothing_written_at_all() {
    let mut store = InMemoryReaderBlobStore::new();
    let mut endpoints = InMemoryEnrollmentEndpoints::new();
    // Der DRITTE Aufruf ist das `PUT /v1/vault-blobs`; er faellt, nachdem beide
    // Credentials schon angelegt sind. Genau dieser Zeitpunkt ist der Punkt,
    // an dem ein nicht fail-closed gebautes `finish` lokal schriebe.
    endpoints.fail_call(3, EnrollmentEndpointError::Status(503));
    let enrollment = fixtures::enrollment_with_two_authenticators();
    let shown = enrollment.fingerprints();
    let confirmation = enrollment
        .confirm_fingerprints(
            &shown.key_fingerprint_hex(),
            &shown.bundle_fingerprint_hex(),
        )
        .unwrap();
    let refused = enrollment
        .finish(
            confirmation,
            fixtures::request_context(),
            &mut endpoints,
            &mut store,
        )
        .err()
        .expect("ein gefallener Upload ist eine Weigerung");
    assert_eq!(refused.code(), "EA-READER-ENROLLMENT-ENDPOINT-STATUS");
    assert!(store.keys().unwrap().is_empty());
}

#[test]
fn each_authenticator_yields_one_envelope_over_the_same_vault_key() {
    let mut store = InMemoryReaderBlobStore::new();
    let mut endpoints = InMemoryEnrollmentEndpoints::new();
    let enrolled = fixtures::two_authenticator_enrollment_into(&mut endpoints, &mut store);
    assert_eq!(enrolled.envelopes().len(), 2);
    let first = enrolled.unlock_with(&fixtures::authenticator(1)).unwrap();
    let second = enrolled.unlock_with(&fixtures::authenticator(2)).unwrap();
    // Ueber `as_bytes()`, weil `KeyThumbprint` und `Hash32` kein `Debug`
    // ableiten (`crates/ea-types/src/ids.rs`, `hash_newtype!`) — dieselbe
    // Schreibweise wie in `crates/ea-reader/tests/vault_envelope.rs`.
    assert_eq!(
        first.kem_key_thumbprint().as_bytes(),
        second.kem_key_thumbprint().as_bytes()
    );
    assert_eq!(
        first.pinned_anchor().trust_anchor_hash().as_bytes(),
        fixtures::pinned_anchor().trust_anchor_hash().as_bytes()
    );
}

#[test]
fn the_prf_output_is_never_the_wrapping_key_and_deleting_one_passkey_keeps_the_vault_open() {
    let mut store = InMemoryReaderBlobStore::new();
    let mut endpoints = InMemoryEnrollmentEndpoints::new();
    let enrolled = fixtures::two_authenticator_enrollment_into(&mut endpoints, &mut store);
    // Die ROHE PRF-Ausgabe DIREKT als Wrapping-Schluessel vorgelegt. `unwrap_err`
    // scheidet aus: sein Ok-Typ ist `SecretBytes<CEK_SIZE>`, und `SecretBytes`
    // traegt bewusst kein `Debug`.
    let refused = enrolled.envelopes()[0]
        .unwrap(&SecretBytes::new(fixtures::prf_output(1)))
        .err()
        .expect("die rohe PRF-Ausgabe ist nicht der Wrapping-Schluessel");
    assert_eq!(refused.code(), "EA-CRYPTO-AEAD-OPEN");
    // `without_authenticator` reicht auf `SealedVaultV1::without_credential`
    // durch — und das gibt ein `Result` zurueck, weil das Entfernen des LETZTEN
    // Entsperrweges `EA-READER-VAULT-NO-AUTHENTICATOR` ist.
    let surviving = enrolled
        .without_authenticator(fixtures::credential_id(1))
        .unwrap();
    assert_eq!(surviving.envelopes().len(), 1);
    assert!(surviving.unlock_with(&fixtures::authenticator(2)).is_ok());
    let closed = surviving
        .unlock_with(&fixtures::authenticator(1))
        .unwrap_err();
    assert_eq!(closed.code(), "EA-READER-VAULT-NO-ENVELOPE");
}

#[test]
fn a_duplicate_credential_id_does_not_count_twice() {
    let store = InMemoryReaderBlobStore::new();
    let mut enrollment = ReaderEnrollment::begin(
        &store,
        fixtures::organization(),
        fixtures::subject(),
        fixtures::pinned_anchor(),
        fixtures::bundle_fingerprint(),
    )
    .unwrap();
    enrollment
        .register_authenticator(fixtures::attested(1))
        .unwrap();
    let refused = enrollment
        .register_authenticator(fixtures::attested(1))
        .err()
        .expect("dieselbe credentialId zaehlt kein zweites Mal");
    assert_eq!(
        refused.code(),
        "EA-READER-ENROLLMENT-DUPLICATE-AUTHENTICATOR"
    );
    assert_eq!(enrollment.registered_authenticator_count(), 1);
}

/// Die WIRTSHAELFTE des Ausschlusses: was die Bruecke herausgibt, ist genau der
/// Satz der bisher aufgenommenen Kennungen — nicht mehr und nicht weniger.
///
/// Mehr waere ein Ausschluss auf ein Geraet, das dieses Enrollment gar nicht
/// haelt; weniger ist die Luecke, um die es geht: eine fehlende Kennung laesst
/// die naechste `navigator.credentials.create`-Zeremonie auf dasselbe Geraet
/// laufen, und dort ERSETZT sie den vorhandenen Passkey, statt einen zweiten
/// anzulegen. Die Browserhaelfte misst
/// `a second ceremony on the same authenticator is refused instead of silently
/// replacing the first passkey` in `apps/web/tests/e2e/enrollment.spec.ts`;
/// dieser Zeuge hier misst, dass sie ueberhaupt etwas auszuschliessen bekommt.
///
/// Die Reihenfolge steht mit in der Zusicherung, weil die Liste als GANZE
/// verglichen wird — dieselbe Bauform wie bei den drei Endpunktaufrufen oben:
/// zwei Anwesenheitspruefungen blieben gruen, wo ein Umbau den Satz vertauscht
/// oder halbiert.
#[test]
fn the_registered_credential_ids_are_exactly_the_ones_the_next_ceremony_must_exclude() {
    let store = InMemoryReaderBlobStore::new();
    let mut enrollment = ReaderEnrollment::begin(
        &store,
        fixtures::organization(),
        fixtures::subject(),
        fixtures::pinned_anchor(),
        fixtures::bundle_fingerprint(),
    )
    .unwrap();
    // VOR der ersten Zeremonie ist der Satz leer — und nicht etwa nicht
    // vorhanden. Genau diesen Wert bekommt `enrollmentBegin` heraus.
    assert!(enrollment.registered_credential_ids().is_empty());

    enrollment
        .register_authenticator(fixtures::attested(1))
        .unwrap();
    assert_eq!(
        enrollment.registered_credential_ids(),
        vec![fixtures::credential_id(1).as_slice()]
    );

    enrollment
        .register_authenticator(fixtures::attested(2))
        .unwrap();
    assert_eq!(
        enrollment.registered_credential_ids(),
        vec![
            fixtures::credential_id(1).as_slice(),
            fixtures::credential_id(2).as_slice()
        ]
    );

    // Eine ABGEWIESENE Aufnahme darf den Satz nicht anfassen: ein Eintrag, den
    // das Enrollment nicht haelt, schloesse ein Geraet aus, das noch gebraucht
    // wird.
    let refused = enrollment
        .register_authenticator(fixtures::attested_with_short_credential_id())
        .err()
        .expect("acht Byte liegen unter MIN_WEBAUTHN_CREDENTIAL_ID_BYTES_V1");
    assert_eq!(refused.code(), "EA-READER-ENROLLMENT-CREDENTIAL-ID-LENGTH");
    assert_eq!(
        enrollment.registered_credential_ids(),
        vec![
            fixtures::credential_id(1).as_slice(),
            fixtures::credential_id(2).as_slice()
        ]
    );
    assert_eq!(
        enrollment.registered_credential_ids().len(),
        enrollment.registered_authenticator_count()
    );
}

#[test]
fn a_credential_id_below_the_protocol_minimum_is_refused_here_and_not_at_the_endpoint() {
    let store = InMemoryReaderBlobStore::new();
    let mut enrollment = ReaderEnrollment::begin(
        &store,
        fixtures::organization(),
        fixtures::subject(),
        fixtures::pinned_anchor(),
        fixtures::bundle_fingerprint(),
    )
    .unwrap();
    let refused = enrollment
        .register_authenticator(fixtures::attested_with_short_credential_id())
        .err()
        .expect("acht Byte liegen unter MIN_WEBAUTHN_CREDENTIAL_ID_BYTES_V1");
    assert_eq!(refused.code(), "EA-READER-ENROLLMENT-CREDENTIAL-ID-LENGTH");
    assert_eq!(enrollment.registered_authenticator_count(), 0);
}

#[test]
fn the_cross_device_qr_flow_is_not_an_unlock_path() {
    let store = InMemoryReaderBlobStore::new();
    let mut enrollment = ReaderEnrollment::begin(
        &store,
        fixtures::organization(),
        fixtures::subject(),
        fixtures::pinned_anchor(),
        fixtures::bundle_fingerprint(),
    )
    .unwrap();
    let refused = enrollment
        .register_authenticator(fixtures::cross_device_attested())
        .err()
        .expect("der QR-Flow ist kein Entsperrpfad");
    assert_eq!(refused.code(), "EA-READER-ENROLLMENT-TRANSPORT-REFUSED");
}

#[test]
fn the_retrieval_carries_no_signature_and_exactly_one_ciphertext_opens() {
    let mut store = InMemoryReaderBlobStore::new();
    let mut enrolling = InMemoryEnrollmentEndpoints::new();
    let enrolled = fixtures::two_authenticator_enrollment_into(&mut enrolling, &mut store);
    let stored = store.get(enrolled.blob_key()).unwrap().unwrap();
    // Acht Chiffrate, wie `MAX_VAULT_BLOBS_PER_SUBJECT_V1` sie zulaesst, und
    // GENAU EINES gehoert diesem Reader. Die sieben anderen sind Rauschen.
    // Ein FRISCHES Doppel, damit `calls()` nur den Abruf zeigt und nicht die
    // drei Aufrufe, mit denen das Enrollment vorher fertig wurde.
    let mut endpoints = InMemoryEnrollmentEndpoints::new();
    endpoints.answer_retrieval_with(fixtures::seven_foreign_ciphertexts_and(stored));
    let unlocked = recover_and_unlock_vault(
        &fixtures::retrieval_request(),
        &fixtures::authenticator(2),
        &mut endpoints,
    )
    .unwrap();
    assert_eq!(
        unlocked.pinned_anchor().trust_anchor_hash().as_bytes(),
        fixtures::pinned_anchor().trust_anchor_hash().as_bytes()
    );
    assert_eq!(
        endpoints.calls(),
        &[EnrollmentCallV1 {
            method: HttpMethod::Post,
            target_uri: "/v1/vault-blobs/retrievals".to_owned(),
            signed: false,
        }]
    );
}

#[test]
fn a_reader_without_an_envelope_in_any_ciphertext_gets_no_vault_for_credential() {
    let mut store = InMemoryReaderBlobStore::new();
    let mut enrolling = InMemoryEnrollmentEndpoints::new();
    let enrolled = fixtures::two_authenticator_enrollment_into(&mut enrolling, &mut store);
    let stored = store.get(enrolled.blob_key()).unwrap().unwrap();
    let mut endpoints = InMemoryEnrollmentEndpoints::new();
    endpoints.answer_retrieval_with(fixtures::seven_foreign_ciphertexts_and(stored));
    // Derselbe Antwortsatz, aber ein dritter Authenticator, fuer den in KEINEM
    // der acht Chiffrate ein Envelope liegt. Der Unterschied zu
    // `EA-READER-VAULT-NO-ENVELOPE` ist die Reichweite: dort scheitert EIN
    // bekannter Tresor, hier scheitert der ganze Abruf.
    let refused = recover_and_unlock_vault(
        &fixtures::retrieval_request(),
        &fixtures::authenticator(3),
        &mut endpoints,
    )
    .unwrap_err();
    assert_eq!(refused.code(), "EA-READER-ENROLLMENT-NO-VAULT");
    assert_eq!(endpoints.calls().len(), 1);
}
