//! Das nicht ueberspringbare Fingerprint-Gate aus `web-reader-design.md` §4.3.
//!
//! Die Zusicherung ist nicht „es gibt eine Pruefung", sondern „es gibt keinen
//! Weg daran vorbei": `finish` nimmt eine `FingerprintConfirmationV1`, und
//! dieser Typ ist AUSSCHLIESSLICH aus `ReaderEnrollment::confirm_fingerprints`
//! mit uebereinstimmenden Werten konstruierbar — dieselbe Bauform, mit der
//! `VerifiedEncryptedEntry` spaeter den HPKE-Entkapseler bewacht. Deshalb misst
//! `the_confirmation_has_no_construction_path_outside_a_match` eine ABWESENHEIT
//! im Quelltext und nicht ein Ergebnis zur Laufzeit: eine zweite
//! Konstruktionsstelle waere zur Laufzeit von keiner Zusicherung zu sehen.

mod fixtures;

use ea_reader::{
    DeviceTrustStateV1, InMemoryEnrollmentEndpoints, InMemoryReaderBlobStore, ReaderEnrollment,
};

#[test]
fn a_diverging_fingerprint_aborts_the_enrollment() {
    let enrollment = fixtures::enrollment_with_two_authenticators();
    let shown = enrollment.fingerprints();
    // Beide Seiten sind HEXZEICHENKETTEN, und das ist die entschiedene Form:
    // die ANGEZEIGTEN Werte sind typisiert (`KeyThumbprint`, `Hash32`), die
    // ERWARTETEN kommen aus einer Tastatur.
    let wrong_bundle = fixtures::flip_one_hex_digit(&shown.bundle_fingerprint_hex());
    // `.err().expect(…)` und nicht `.unwrap_err()`: der OK-Typ ist
    // `FingerprintConfirmationV1`, und der traegt bewusst kein `Debug`.
    let refused = enrollment
        .confirm_fingerprints(&shown.key_fingerprint_hex(), &wrong_bundle)
        .err()
        .expect("ein abweichender Bundle-Fingerprint bestaetigt nichts");
    assert_eq!(refused.code(), "EA-READER-ENROLLMENT-FINGERPRINT-MISMATCH");
    let wrong_key = fixtures::flip_one_hex_digit(&shown.key_fingerprint_hex());
    let refused_key = enrollment
        .confirm_fingerprints(&wrong_key, &shown.bundle_fingerprint_hex())
        .err()
        .expect("ein abweichender Schluessel-Fingerprint bestaetigt nichts");
    assert_eq!(
        refused_key.code(),
        "EA-READER-ENROLLMENT-FINGERPRINT-MISMATCH"
    );
    let malformed = enrollment
        .confirm_fingerprints("nicht hexadezimal", &shown.bundle_fingerprint_hex())
        .err()
        .expect("eine nicht-hexadezimale Eingabe bestaetigt nichts");
    assert_eq!(
        malformed.code(),
        "EA-READER-ENROLLMENT-FINGERPRINT-ENCODING"
    );
}

#[test]
fn the_shown_values_are_the_kem_thumbprint_and_the_bundle_hash() {
    let enrollment = fixtures::enrollment_with_two_authenticators();
    let shown = enrollment.fingerprints();
    assert_eq!(
        shown.bundle_fingerprint().as_bytes(),
        fixtures::bundle_fingerprint().as_bytes()
    );
    assert_eq!(
        shown.key_fingerprint_hex(),
        hex::encode(shown.key_fingerprint().as_bytes())
    );
    assert_eq!(shown.key_fingerprint_hex().len(), 64);
}

#[test]
fn the_confirmation_has_no_construction_path_outside_a_match() {
    // Der Beweis ist die ABWESENHEIT einer Konstruktion, nicht ihr Ergebnis.
    // Die Arithmetik steht ausgeschrieben da, weil eine nackte Zahl hier nicht
    // pruefbar waere: die DEKLARATION enthaelt dieselbe Zeichenfolge wie eine
    // Konstruktion, und ein `impl`-Kopf ebenfalls.
    let source = include_str!("../src/enrollment.rs");
    assert_eq!(
        source
            .matches("pub struct FingerprintConfirmationV1 {")
            .count(),
        1,
        "genau eine Deklaration"
    );
    assert_eq!(
        source.matches("FingerprintConfirmationV1 {").count(),
        2,
        "die Deklaration und GENAU EIN Strukturausdruck in confirm_fingerprints"
    );
    assert_eq!(
        source.matches("impl FingerprintConfirmationV1").count(),
        0,
        "kein inhaerenter impl-Block: er koennte eine zweite Konstruktionsstelle \
         hinter einer assoziierten Funktion verstecken, und sein Kopf zaehlte \
         oben mit"
    );
    assert!(!source.contains("pub fn skip"), "no skip path may exist");
    assert!(!source.contains("Default for FingerprintConfirmationV1"));
    assert!(!source.contains("Clone for FingerprintConfirmationV1"));
    assert!(
        !source.contains("AnchorUnpinned"),
        "der fehlende Anker ist im Typ ausgeschlossen und braucht keinen Laufzeitfall"
    );
}

#[test]
fn the_gate_fires_on_every_first_call_without_a_pinned_trust_store() {
    let mut store = InMemoryReaderBlobStore::new();
    let mut endpoints = InMemoryEnrollmentEndpoints::new();
    let known = ReaderEnrollment::device_state(&store).unwrap();
    assert!(matches!(known, DeviceTrustStateV1::NoPinnedAnchor));
    assert!(ReaderEnrollment::fingerprint_gate_required(&known));
    let enrolled = fixtures::two_authenticator_enrollment_into(&mut endpoints, &mut store);
    let after = ReaderEnrollment::device_state(&store).unwrap();
    assert!(matches!(after, DeviceTrustStateV1::Pinned));
    assert!(!ReaderEnrollment::fingerprint_gate_required(&after));
    drop(enrolled);
}
