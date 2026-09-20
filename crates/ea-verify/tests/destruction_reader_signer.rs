//! Web-Reader-Design §3 im Offline-Pruefer: kein Zustandsuebergang von einem
//! Reader-Geraet.
//!
//! `ea-destruction` und `ea-reader` verweigern diesen Uebergang seit DRK-321
//! oertlich (`crates/ea-destruction/tests/transitions.rs`:231-310). Dieselben
//! Bytes duerfen im Bericht keine ANDERE Antwort bekommen; der Befund ist
//! deshalb ein Eintrag in `signatureErrors` und kein Widerspruch — die
//! Signatur traegt hier nicht, also nimmt das Ereignis an der Kettenauswertung
//! GAR NICHT teil (`crates/ea-verify/src/destruction.rs`:15-22).
//!
//! VERGLICHEN WIRD UEBER HEXZEICHENKETTEN: `ObjectHash` und `DestructionId`
//! tragen bewusst kein `Debug`, und ein `assert!` ohne Gegenueberstellung
//! zeigte im Fehlerfall nicht, WAS statt des Erwarteten kam.

#[path = "support/mod.rs"]
mod support;

use ea_types::UnixMillis;
use ea_verify::{VerificationReportV1, VerifyOptions, verify_archive};

/// Der Code, den ein Reader-signierter Uebergang traegt.
const READER_DEVICE_SIGNER_CODE_V1: &str = "EA-VERIFY-DESTRUCTION-READER-DEVICE-SIGNER";

/// Der Zustand `requested` als `destruction-state-v1`-Code.
const REQUESTED_V1: u8 = 0;

fn verified(
    reader_revoked: bool,
) -> (
    support::destruction_v12::ReaderSignerFixture,
    VerificationReportV1,
) {
    let fixture = support::destruction_v12::reader_signer_fixture(reader_revoked);
    let report = verify_archive(
        &fixture.source,
        &fixture.anchor,
        VerifyOptions::new(UnixMillis::new(support::FIXTURE_OS_WALL_CLOCK_V1)),
    )
    .expect("der Bericht muss entstehen");
    (fixture, report)
}

fn findings(report: &VerificationReportV1) -> Vec<(String, &'static str)> {
    report
        .signature_errors()
        .map(|error| (hex::encode(error.object_hash().as_bytes()), error.code()))
        .collect()
}

/// Der Befund entsteht, und zwar GENAU EINMAL und GENAU UEBER DEM
/// Uebergangsobjekt.
#[test]
fn a_transition_signed_on_a_reader_device_is_one_signature_finding() {
    let (fixture, report) = verified(false);
    assert_eq!(
        findings(&report),
        vec![(
            hex::encode(fixture.reader_event_object_hash.as_bytes()),
            READER_DEVICE_SIGNER_CODE_V1
        )],
    );
}

/// Die Positivkontrolle: dieselbe Struktur, dasselbe Zertifikatsmuster, nur
/// ohne Reader-Zertifikat auf dem Signierergeraet — befundfrei und im Zustand.
#[test]
fn the_same_transition_without_a_reader_certificate_stays_finding_free() {
    let (fixture, report) = verified(false);
    let control = hex::encode(fixture.control_event_object_hash.as_bytes());
    assert!(
        findings(&report).iter().all(|(hash, _)| hash != &control),
        "die Positivkontrolle darf keinen Befund tragen",
    );
    let states: Vec<_> = report
        .authorized_destructions()
        .map(|entry| {
            (
                hex::encode(entry.destruction_id().as_bytes()),
                entry.state().code(),
            )
        })
        .collect();
    assert_eq!(
        states,
        vec![(
            hex::encode(fixture.control_destruction_id.as_bytes()),
            REQUESTED_V1
        )],
        "nur die Kontrolle erreicht die Kettenauswertung",
    );
    assert!(
        !states
            .iter()
            .any(|(id, _)| id == &hex::encode(fixture.reader_destruction_id.as_bytes())),
        "der Reader-signierte Vorgang bekommt gar keinen Zustand",
    );
}

/// Ein WIDERRUFENES Reader-Zertifikat zaehlt ebenso: der Widerruf macht aus
/// einem Reader-Geraet keinen Uebergangssignierer (so haelt es DRK-321).
#[test]
fn a_revoked_reader_certificate_still_marks_its_device_as_a_reader() {
    let (fixture, report) = verified(true);
    assert_eq!(
        findings(&report),
        vec![(
            hex::encode(fixture.reader_event_object_hash.as_bytes()),
            READER_DEVICE_SIGNER_CODE_V1
        )],
    );
    assert_eq!(report.authorized_destructions().len(), 1);
}

/// Der Befund bleibt ein SIGNATURBEFUND: keine Quarantaene, und der Bericht
/// ist nicht vollstaendig verifiziert.
#[test]
fn the_reader_signed_transition_is_no_quarantined_object() {
    let (fixture, report) = verified(false);
    assert!(!report.is_fully_verified());
    let reader = hex::encode(fixture.reader_event_object_hash.as_bytes());
    assert!(
        !report
            .quarantined_objects()
            .any(|object| hex::encode(object.object_hash().as_bytes()) == reader),
        "ein Signaturbefund ist kein Widerspruch",
    );
}
