//! Die Gates `evidence` und `recipient-grant` und die Entkapselung dahinter.
//!
//! DIE ENTKAPSELUNG IST KEIN GATE (`design.md` §14.1, :1586). Sie folgt auf das
//! neunte, sie wird protokolliert, und keine Verifikationsentscheidung haengt
//! an ihr. Diese Datei misst deshalb vier Dinge, die genau diese Grenze
//! ziehen:
//!
//! 1. Ein vollstaendig gueltiger Bestand MIT Empfaengerschluessel protokolliert
//!    die neun Gates und danach `hpke-open`, meldet keinen einzigen Befund und
//!    ist vollstaendig verifiziert.
//! 2. Geforderte, aber ueberfaellige Evidence erzeugt GENAU EINEN
//!    `evidenceErrors`-Eintrag.
//! 3. Ein falscher Empfaengerschluessel erzeugt GENAU EINEN
//!    `decryptionErrors`-Eintrag. Ein mutiertes Ciphertextbyte kaeme dafuer
//!    nicht in Frage: es faellt bereits an Gate `manifest-signature`, weil der
//!    Ciphertexthash im signierten Manifest steht.
//! 4. Ein fehlender EIGENER Grant ist KEIN Mangel: der Eintrag bleibt
//!    `valid`, es wird nichts entschluesselt, und es entsteht ausdruecklich
//!    KEIN `decryptionErrors`-Eintrag (`design.md`:1595).
//!
//! Kein Test dieser Datei schreibt einen Gate-Bezeichner als Literal:
//! `GATE_ORDER_V1` ist die einzige Quelle.

#[path = "support/mod.rs"]
mod support;

use ea_types::UnixMillis;
use ea_verify::{
    DECAPSULATION_EVENT_V1, EvidenceGateErrorV1, EvidenceRequirementV1, GATE_ORDER_V1,
    ObjectErrorV1, RecordingObserver, VerificationReportV1, VerifyOptions, verify_archive,
    verify_archive_observed,
};

use support::{
    CheckpointSpec, CompleteArchive, FIXTURE_OS_WALL_CLOCK_V1, ReceiptArchiveSpec,
    archive_without_the_own_grant, complete_recipient_private_key, complete_valid_archive,
    other_recipient_private_key, receipt_archive,
};

fn clock() -> UnixMillis {
    UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1)
}

/// Die Erwartung an ein vollstaendiges Protokoll: neun Gates, dann `hpke-open`.
fn expected_full_protocol() -> Vec<&'static str> {
    let mut expected = GATE_ORDER_V1.to_vec();
    expected.push(DECAPSULATION_EVENT_V1);
    expected
}

fn verify(archive: &CompleteArchive, options: VerifyOptions<'_>) -> VerificationReportV1 {
    verify_archive(&archive.fixture, &archive.anchor(), options)
        .expect("ein Befund ueber ein Objekt ist nie ein Fehler des Laufs")
}

/// Der Kern dieses Tasks: die letzten beiden Gates laufen, und erst danach
/// wird entkapselt.
#[test]
fn evidence_and_recipient_grant_run_before_a_decapsulation_that_is_no_gate() {
    let archive = complete_valid_archive();
    let recipient = complete_recipient_private_key();
    let mut observer = RecordingObserver::new();

    let report = verify_archive_observed(
        &archive.fixture,
        &archive.anchor(),
        VerifyOptions::new(clock())
            .with_recipient(support::complete_recipient_key_thumbprint(), &recipient),
        &mut observer,
    )
    .expect("der lueckenfreie Bestand traegt");

    assert_eq!(
        observer.events(),
        expected_full_protocol().as_slice(),
        "gate events"
    );
    assert_eq!(report.format_errors().len(), 0);
    assert_eq!(report.quarantined_objects().len(), 0);
    assert_eq!(report.signature_errors().len(), 0);
    assert_eq!(report.evidence_errors().len(), 0);
    assert_eq!(report.decryption_errors().len(), 0);
    assert_eq!(report.gaps().len(), 0);
    assert!(
        report.is_fully_verified(),
        "ein vollstaendig gueltiger Bestand ist vollstaendig verifiziert"
    );
}

/// Geforderte, aber ueberfaellige Evidence: GENAU EIN `evidenceErrors`-Eintrag.
///
/// Die Frist steht im SIGNIERTEN `evidence-due-at` der Quittung
/// (`design.md`:1677) und beginnt nirgendwo sonst. Der Befund traegt deshalb
/// den Objekthash der QUITTUNG: sie ist das Objekt, das die Frist behauptet,
/// und der Eintrag selbst bleibt gueltig.
#[test]
fn required_evidence_that_is_overdue_yields_exactly_one_evidence_error() {
    let overdue = FIXTURE_OS_WALL_CLOCK_V1 - 1;
    let archive = receipt_archive(
        ReceiptArchiveSpec::bare()
            .with_receipts()
            .with_checkpoint(CheckpointSpec::None)
            .with_evidence_due_at(overdue),
    );

    let report = verify_archive(
        &archive.fixture,
        &archive.anchor(),
        VerifyOptions::new(clock()).with_evidence_requirement(EvidenceRequirementV1::Required),
    )
    .expect("ein Befund ueber ein Objekt ist nie ein Fehler des Laufs");

    // GENAU EIN BEFUND JE UEBERFAELLIGER QUITTUNG — nicht einer pro Bestand
    // und nicht zwei pro Quittung. Der Bestand traegt zwei bestaetigte
    // Quittungen, also zwei Befunde, und jeder gehoert zu genau einer von
    // ihnen.
    assert_eq!(
        report.evidence_errors().len(),
        archive.receipt_object_hashes.len(),
        "genau ein Befund je ueberfaelliger Quittung"
    );
    for receipt_object_hash in &archive.receipt_object_hashes {
        let matching: Vec<&ObjectErrorV1> = report
            .evidence_errors()
            .filter(|error| error.object_hash() == *receipt_object_hash)
            .collect();
        assert_eq!(matching.len(), 1, "genau ein Befund zu dieser Quittung");
        assert_eq!(
            matching[0].code(),
            EvidenceGateErrorV1::Overdue.code(),
            "eine abgelaufene Frist ist ueberfaellig, nicht bloss ausstehend"
        );
    }
    assert!(!report.is_fully_verified());
}

/// Dieselbe Frist OHNE Forderung ist kein Mangel.
#[test]
fn an_unrequested_evidence_deadline_is_no_finding() {
    let overdue = FIXTURE_OS_WALL_CLOCK_V1 - 1;
    let archive = receipt_archive(
        ReceiptArchiveSpec::bare()
            .with_receipts()
            .with_evidence_due_at(overdue),
    );

    let report = verify_archive(
        &archive.fixture,
        &archive.anchor(),
        VerifyOptions::new(clock()),
    )
    .expect("ein Befund ueber ein Objekt ist nie ein Fehler des Laufs");

    assert_eq!(report.evidence_errors().len(), 0);
}

/// Ein falscher Empfaengerschluessel: GENAU EIN `decryptionErrors`-Eintrag.
#[test]
fn a_wrong_recipient_key_yields_exactly_one_decryption_error() {
    let archive = complete_valid_archive();
    let wrong = other_recipient_private_key();

    let report = verify(
        &archive,
        VerifyOptions::new(clock())
            .with_recipient(support::complete_recipient_key_thumbprint(), &wrong),
    );

    assert_eq!(report.decryption_errors().len(), 1);
    assert!(
        report
            .decryption_errors()
            .next()
            .expect("ein Befund")
            .object_hash()
            == archive.grant_object_hash,
        "der Befund traegt den Grant, an dem die Entkapselung scheiterte"
    );
    assert_eq!(
        report.object_results().len(),
        1,
        "der Eintrag bleibt ein Ergebnis; der Befund liegt auf dem Grant"
    );
    assert!(!report.is_fully_verified());
}

/// Ohne Empfaengerschluessel wird nichts versucht — und nichts abgewertet.
#[test]
fn without_a_recipient_key_nothing_is_opened_and_nothing_is_lowered() {
    let archive = complete_valid_archive();
    let mut observer = RecordingObserver::new();

    let report = verify_archive_observed(
        &archive.fixture,
        &archive.anchor(),
        VerifyOptions::new(clock()),
        &mut observer,
    )
    .expect("der lueckenfreie Bestand traegt");

    assert_eq!(observer.events(), GATE_ORDER_V1.as_slice());
    assert!(
        !observer.events().contains(&DECAPSULATION_EVENT_V1),
        "ohne Schluessel wird nicht entkapselt, also auch nichts protokolliert"
    );
    assert_eq!(report.decryption_errors().len(), 0);
    assert!(
        report.is_fully_verified(),
        "ein fehlender Empfaengerschluessel ist kein Mangel des Bestands"
    );
}

/// Fehlender EIGENER Grant: `valid`, keine Entschluesselung, kein Befund.
#[test]
fn a_missing_own_grant_keeps_the_entry_valid_without_any_decryption_error() {
    let archive = archive_without_the_own_grant();
    let recipient = complete_recipient_private_key();
    let mut observer = RecordingObserver::new();

    let report = verify_archive_observed(
        &archive.fixture,
        &archive.anchor(),
        VerifyOptions::new(clock())
            .with_recipient(support::complete_recipient_key_thumbprint(), &recipient),
        &mut observer,
    )
    .expect("der Bestand traegt auch ohne eigenen Grant");

    assert_eq!(report.object_results().len(), 1);
    assert!(
        report
            .object_results()
            .next()
            .expect("ein Ergebnis")
            .object_hash()
            == archive.entry_object_hash,
        "das Ergebnis gehoert zu dem einen Eintrag des Bestands"
    );
    assert_eq!(
        report.decryption_errors().len(),
        0,
        "ein fehlender Grant ist kein Entschluesselungsfehler"
    );
    assert_eq!(report.signature_errors().len(), 0);
    assert!(
        !observer.events().contains(&DECAPSULATION_EVENT_V1),
        "ohne eigenen Grant wird nichts geoeffnet"
    );
    assert!(
        report.is_fully_verified(),
        "der Zustand `fehlender Grant` senkt die Verifikation nicht"
    );
}
