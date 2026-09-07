//! Die Transitionsregel aus `design.md`:669 an Gate `manifest-signature`.
//!
//! Stufe 5, Task 5: bis hierher isolierte `ea-verify` JEDEN Eintrag mit
//! gesetztem `writerTransitionEventHash`, weil `ea-trust` den wirksamen
//! Uebergang nicht herausgab. Jetzt gibt `SelectedRegistryHead` ihn heraus,
//! und an die Stelle der Pauschalabweisung tritt die Regel:
//!
//! - kein Hash und kein an dieser Sequenz wirksamer Uebergang: traegt;
//! - Hash UND Uebergang: traegt genau dann, wenn der Hash der Objekthash des
//!   Uebergangs ist, der Eintrag den `previous_entry_hash` des Uebergangs
//!   bindet und sein Schreiber der neue Writer ist;
//! - Hash ohne Uebergang (zusaetzlich) und Uebergang ohne Hash (fehlend):
//!   traegt nicht.
//!
//! Ein fallender Anspruch ist ein Trust-Fehler DES OBJEKTS und nie ein `Err`
//! des Laufs: der Eintrag wird als `unattributable` isoliert — genau wie ein
//! Eintrag, dessen Schreiber sich nicht aufloest —, wird kein Kettenknoten
//! und senkt `is_fully_verified()`. Die uebrigen Eintraege behalten ihr
//! Ergebnis.
//!
//! JEDER MUTANT LOESCHT GENAU EINE BEDINGUNG. Wer aus der Regel den
//! Hashvergleich streicht, faellt an `WrongClaim`; wer die Vorgaengerbindung
//! streicht, an `ForeignPredecessor`; wer die Fallunterscheidung fehlend /
//! zusaetzlich streicht, an `MissingClaim` beziehungsweise `AdditionalClaim`.
//! Der zurueckgespielte alte Writer faellt schon davor, an der Aufloesung des
//! laufenden Writers — der Test pinnt genau diesen Befund.

#[path = "support/mod.rs"]
mod support;

use ea_archive::QuarantineReason;
use ea_types::{ObjectHash, UnixMillis};
use ea_verify::{ObjectResultKindV1, VerificationReportV1, VerifyOptions, verify_archive};

use support::{
    FIXTURE_OS_WALL_CLOCK_V1, TRANSITION_EFFECTIVE_FROM_V1, TRANSITION_ENTRY_COUNT_V1,
    TRANSITION_LAST_OLD_WRITER_SEQUENCE_V1, TRANSITION_TRAILING_SEQUENCE_V1,
    WriterTransitionArchive, WriterTransitionDefectV1, second_writer_device_key_thumbprint,
    writer_device_key_thumbprint, writer_transition_archive,
};

fn clock() -> UnixMillis {
    UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1)
}

/// Verifiziert OHNE eigenen Empfaengerschluessel, und das ist eine Grenze
/// des Standes, keine Nachlaessigkeit: Gate `recipient-grant` waehlt seinen
/// Kopf in EINER Runde ueber den zuletzt gepinnten (`select_pinned_head`,
/// `crates/ea-verify/src/archive.rs`), und ein gepinnter Kopf geht nie
/// zurueck. Ein Bestand ueber MEHRERE Leases — und ein Uebergang ist einer —
/// bekaeme fuer die Grants unter den fruehen Koepfen deshalb
/// `EA-VERIFY-GRANT-HEAD-UNAVAILABLE`; die bestehenden mehrkoepfigen Fixtures
/// geben den fruehen Eintraegen aus demselben Grund keinen eigenen Grant.
/// Die Transitionsregel haengt an keinem Grant; `is_fully_verified()` sinkt
/// durch einen nicht uebergebenen Schluessel nicht (`design.md`:1595).
fn verify(archive: &WriterTransitionArchive) -> VerificationReportV1 {
    verify_archive(
        &archive.fixture,
        &archive.anchor(),
        VerifyOptions::new(clock()),
    )
    .expect("ein Uebergangsbestand muss berichten — ein Befund ist nie ein Err des Laufs")
}

#[test]
fn an_exactly_claimed_transition_verifies_completely_with_both_writers() {
    let archive = writer_transition_archive(WriterTransitionDefectV1::None);
    let report = verify(&archive);

    assert_eq!(
        report.quarantined_objects().len(),
        0,
        "kein isoliertes Objekt"
    );
    assert_eq!(report.signature_errors().len(), 0);
    assert_eq!(report.gaps().len(), 0, "der Uebergang reisst keine Luecke");

    // JEDER Eintrag ist ein Kettenknoten und indiziert — auch der, der den
    // Transitionshash traegt, und der danach.
    assert_eq!(
        report.object_results().len(),
        usize::try_from(TRANSITION_ENTRY_COUNT_V1).expect("passt in usize")
    );
    for object_hash in &archive.entry_object_hashes {
        assert!(
            report.object_results().any(|result| {
                result.object_hash() == *object_hash && result.result() == ObjectResultKindV1::Valid
            }),
            "jeder Eintrag des Uebergangsbestands ist gueltig"
        );
    }
    assert_eq!(
        report.chain_head().sequence().get(),
        TRANSITION_TRAILING_SEQUENCE_V1,
        "der verifizierte Kopf steht auf dem zweiten Eintrag des neuen Writers"
    );

    // `publicKeyThumbprints` ist Nachweis des GEPRUEFTEN: beide Writer haben
    // Signaturen getragen, beide stehen darin.
    let thumbprints: Vec<_> = report.public_key_thumbprints().collect();
    assert!(
        thumbprints.contains(&writer_device_key_thumbprint()),
        "der alte Writer hat die Eintraege 0..=N getragen"
    );
    assert!(
        thumbprints.contains(&second_writer_device_key_thumbprint()),
        "der neue Writer hat die Eintraege N+1 und N+2 getragen"
    );
    assert!(
        archive.old_writer_certificate_hash != archive.new_writer_certificate_hash,
        "zwei Writer, zwei Zertifikate"
    );

    assert!(report.is_fully_verified());
}

/// Genau EIN Objekt ist isoliert, und zwar `broken` als `unattributable`;
/// alle uebrigen Eintraege behalten ihr Ergebnis; der Bestand ist nicht
/// vollstaendig verifiziert.
fn assert_exactly_one_unattributable(
    archive: &WriterTransitionArchive,
    report: &VerificationReportV1,
    broken: ObjectHash,
    expected_head_sequence: u64,
) {
    let quarantined: Vec<_> = report.quarantined_objects().collect();
    assert_eq!(quarantined.len(), 1, "genau ein isoliertes Objekt");
    assert!(
        quarantined[0].object_hash() == broken,
        "isoliert ist der Eintrag, dessen Anspruch nicht traegt"
    );
    assert_eq!(
        quarantined[0].reason(),
        QuarantineReason::Unattributable,
        "ein fallender Transitionsanspruch ist ein Zuordnungsmangel, kein Widerspruch"
    );
    assert_eq!(
        report.signature_errors().len(),
        0,
        "die Signatur traegt; es ist der Anspruch, der nicht traegt"
    );
    assert!(
        report
            .object_results()
            .all(|result| result.object_hash() != broken),
        "ein isoliertes Objekt wird nicht indiziert"
    );
    for object_hash in archive
        .entry_object_hashes
        .iter()
        .filter(|hash| **hash != broken)
    {
        assert!(
            report.object_results().any(|result| {
                result.object_hash() == *object_hash && result.result() == ObjectResultKindV1::Valid
            }),
            "die uebrigen Eintraege behalten ihr Ergebnis"
        );
    }
    assert_eq!(
        report.chain_head().sequence().get(),
        expected_head_sequence,
        "der verifizierte Kopf endet vor dem isolierten Eintrag"
    );
    assert!(
        !report.is_fully_verified(),
        "ein isolierter Befund darf den Bestand nie als vollstaendig verifiziert zeigen"
    );
}

#[test]
fn a_first_new_writer_entry_without_the_hash_is_unattributable() {
    let archive = writer_transition_archive(WriterTransitionDefectV1::MissingClaim);
    let report = verify(&archive);
    assert_exactly_one_unattributable(
        &archive,
        &report,
        archive.entry_object_hash_at(TRANSITION_EFFECTIVE_FROM_V1),
        TRANSITION_LAST_OLD_WRITER_SEQUENCE_V1,
    );
}

#[test]
fn a_second_new_writer_entry_carrying_the_hash_is_unattributable() {
    let archive = writer_transition_archive(WriterTransitionDefectV1::AdditionalClaim);
    let report = verify(&archive);
    assert_exactly_one_unattributable(
        &archive,
        &report,
        archive.entry_object_hash_at(TRANSITION_TRAILING_SEQUENCE_V1),
        TRANSITION_EFFECTIVE_FROM_V1,
    );
}

#[test]
fn a_first_new_writer_entry_naming_another_object_is_unattributable() {
    let archive = writer_transition_archive(WriterTransitionDefectV1::WrongClaim);
    let report = verify(&archive);
    assert_exactly_one_unattributable(
        &archive,
        &report,
        archive.entry_object_hash_at(TRANSITION_EFFECTIVE_FROM_V1),
        TRANSITION_LAST_OLD_WRITER_SEQUENCE_V1,
    );
}

#[test]
fn a_transition_naming_another_predecessor_leaves_the_first_entry_unattributable() {
    let archive = writer_transition_archive(WriterTransitionDefectV1::ForeignPredecessor);
    let report = verify(&archive);
    assert_exactly_one_unattributable(
        &archive,
        &report,
        archive.entry_object_hash_at(TRANSITION_EFFECTIVE_FROM_V1),
        TRANSITION_LAST_OLD_WRITER_SEQUENCE_V1,
    );
}

#[test]
fn a_restored_old_writer_at_the_transition_sequence_is_unattributable() {
    let archive = writer_transition_archive(WriterTransitionDefectV1::RestoredOldWriter);
    let report = verify(&archive);
    assert_exactly_one_unattributable(
        &archive,
        &report,
        archive.entry_object_hash_at(TRANSITION_EFFECTIVE_FROM_V1),
        TRANSITION_LAST_OLD_WRITER_SEQUENCE_V1,
    );
    // Der alte Writer hat die fruehen Eintraege getragen und steht deshalb in
    // `publicKeyThumbprints`; sein Eintrag auf `N + 1` hat KEINE Pruefung
    // getragen, denn er ist nicht der laufende Writer des Uebergangskopfes.
    let thumbprints: Vec<_> = report.public_key_thumbprints().collect();
    assert!(thumbprints.contains(&writer_device_key_thumbprint()));
    assert!(thumbprints.contains(&second_writer_device_key_thumbprint()));
}
