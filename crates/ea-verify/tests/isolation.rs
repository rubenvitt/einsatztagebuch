//! Isolation EINES defekten Objekts neben gueltigen — und die Grenzen davon.
//!
//! `design.md`:1585/1593 verlangt beides zugleich: ein unbekanntes, ungueltiges
//! oder unvollstaendiges Objekt wird ISOLIERT — nicht indiziert, nicht als
//! normaler Einsatz geoeffnet — und bleibt trotzdem im Bericht SICHTBAR. Und
//! fail-closed bleibt unberuehrt: ein isoliertes Objekt darf NIEMALS dazu
//! fuehren, dass der Bestand als vollstaendig verifiziert dargestellt wird.
//!
//! Bis hierher belegt jeder Test genau EINEN Befund an genau EINEM Objekt.
//! Diese Datei misst, was daneben steht: dass die uebrigen Objekte ihr Ergebnis
//! BEHALTEN. Ein `Err` des Laufs kaeme dafuer nicht in Frage — es vernichtete
//! die Aussage ueber alle uebrigen Objekte —, und deshalb wird in jedem
//! Unterfall auf `Ok` bestanden.
//!
//! # Die drei Pflicht-Fehlerarrays, je ein Defekt neben zwei Unversehrten
//!
//! - `signatureErrors`: der mittlere von drei Eintraegen traegt ein verkipptes
//!   Byte in der Schreibersignatur.
//! - `evidenceErrors`: eine von drei Quittungen behauptet eine Frist, zu der
//!   keine Evidence vorliegt, und die Frist ist abgelaufen.
//! - `decryptionErrors`: einer von drei Grants ist auf einen FREMDEN Schluessel
//!   gekapselt, sodass allein `hpke_open` scheitert.
//!
//! DAS DEFEKTE OBJEKT IST NICHT IMMER EIN EINTRAG, und das ist keine
//! Nachlaessigkeit dieser Datei, sondern die Regel des Berichts. Ein Befund von
//! Gate `evidence` traegt die QUITTUNG, ein Befund der Entkapselung den GRANT
//! (`crates/ea-verify/src/evidence.rs:181-184`,
//! `crates/ea-verify/src/recipient.rs:53-58`); der zugehoerige EINTRAG bleibt
//! gueltig und behaelt sein Ergebnis. In diesen beiden Unterfaellen stehen
//! deshalb DREI Ergebnisse im Bericht und nicht zwei — die beiden unbeteiligten
//! Eintraege und der betroffene. Jeder Unterfall pinnt seine Zahl selbst, damit
//! die Asymmetrie ausgesprochen ist statt versteckt.
//!
//! # Zwei Zustaende, die NIE ein Mangel sind
//!
//! `notServerConfirmed` (`design.md`:1591) und ein nicht uebergebener
//! Empfaengerschluessel (`design.md`:1595) senken
//! `is_fully_verified()` ausdruecklich nicht. Umgekehrt senkt JEDER
//! Quarantaeneeintrag ihn — auch der harmloseste, `duplicate`.
//!
//! # Dateinamen-Unabhaengigkeit
//!
//! Klassifiziert wird am 9-Byte-Exact-Object-Praefix, nie am Pfad. Derselbe
//! Bestand unter vertauschten Hinweisen und in umgekehrter Reihenfolge muss
//! deshalb denselben Kettenkopf UND byteidentische kanonische JSON-Bytes
//! liefern. Das ist zugleich der schaerfste Determinismusnachweis dieser
//! Crate: eine Streuordnung auf dem Emit-Pfad faellt hier auf.

#[path = "support/mod.rs"]
mod support;

use ea_archive::QuarantineReason;
use ea_types::{ObjectHash, UnixMillis};
use ea_verify::{
    DECAPSULATION_EVENT_V1, DecryptionErrorV1, EvidenceGateErrorV1, EvidenceRequirementV1,
    ManifestSignatureErrorV1, ObjectResultKindV1, RecordingObserver, ServerConfirmationV1,
    VerificationReportV1, VerifyOptions, verify_archive, verify_archive_observed,
};

use support::{
    FIXTURE_OS_WALL_CLOCK_V1, ISOLATION_DEFECT_INDEX_V1, ISOLATION_DEFECT_SEQUENCE_V1,
    ISOLATION_ENTRY_COUNT_V1, IsolationDefectV1, RECEIPT_PRE_ENTRY_GAP_THROUGH_V1,
    archive_support::ArchiveFixture, complete_recipient_key_thumbprint,
    complete_recipient_private_key, isolation_archive, receipt_archive_with_one_deadline,
};

fn clock() -> UnixMillis {
    UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1)
}

/// Die drei Pflicht-Fehlerarrays des Berichts, als Auswahl.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ErrorArrayV1 {
    Signature,
    Evidence,
    Decryption,
}

impl ErrorArrayV1 {
    const ALL: [Self; 3] = [Self::Signature, Self::Evidence, Self::Decryption];

    const fn name(self) -> &'static str {
        match self {
            Self::Signature => "signatureErrors",
            Self::Evidence => "evidenceErrors",
            Self::Decryption => "decryptionErrors",
        }
    }

    /// Die Eintraege dieses Arrays als Paare aus Objekthash und Code.
    fn entries(self, report: &VerificationReportV1) -> Vec<(ObjectHash, &'static str)> {
        let errors: Box<dyn Iterator<Item = _>> = match self {
            Self::Signature => Box::new(report.signature_errors()),
            Self::Evidence => Box::new(report.evidence_errors()),
            Self::Decryption => Box::new(report.decryption_errors()),
        };
        errors
            .map(|error| (error.object_hash(), error.code()))
            .collect()
    }
}

/// Die gemeinsame Behauptung aller drei Unterfaelle.
///
/// Sie steht an EINER Stelle, weil sie in allen dreien dieselbe ist: GENAU EIN
/// Befund im erwarteten Array, NULL in den beiden anderen, das defekte Objekt
/// ohne Ergebnis, und der Bestand ausdruecklich nicht vollstaendig verifiziert.
///
/// `expected_valid` sind die Objekte, die dieser Unterfall mit `valid` im
/// Bericht erwartet — in (a) die zwei unbeteiligten Eintraege, in (b) und (c)
/// ALLE DREI: dort traegt die Quittung beziehungsweise der Grant den Befund,
/// und der zugehoerige Eintrag bleibt selbst gueltig. Die Pruefung ist eine
/// Teilmengenaussage; ihre Gegenrichtung liefert `expected_results`, das die
/// Gesamtzahl der Ergebnisse pinnt.
fn assert_isolated(
    report: &VerificationReportV1,
    array: ErrorArrayV1,
    broken: ObjectHash,
    code: &'static str,
    expected_valid: &[ObjectHash],
    expected_results: usize,
) {
    for candidate in ErrorArrayV1::ALL {
        let entries = candidate.entries(report);
        if candidate == array {
            assert_eq!(entries.len(), 1, "genau ein Befund in {}", candidate.name());
            assert!(
                entries[0].0 == broken,
                "der Befund in {} traegt das defekte Objekt",
                candidate.name()
            );
            assert_eq!(entries[0].1, code, "der Code in {}", candidate.name());
        } else {
            assert_eq!(
                entries.len(),
                0,
                "kein Befund in {} — ein Objekt erscheint in genau einem Array",
                candidate.name()
            );
        }
    }

    // ZUERST die Aussage, um die es geht: die unbeteiligten Objekte BEHALTEN
    // ihr Ergebnis. Ein Lauf, der wegen des einen Defekts die uebrigen
    // Ergebnisse verloere, faellt genau hier.
    let valid: Vec<ObjectHash> = report
        .object_results()
        .filter(|result| result.result() == ObjectResultKindV1::Valid)
        .map(|result| result.object_hash())
        .collect();
    assert_eq!(
        expected_valid
            .iter()
            .filter(|hash| valid.contains(hash))
            .count(),
        expected_valid.len(),
        "valid object results beside the broken one"
    );
    assert_eq!(
        report.object_results().len(),
        expected_results,
        "die Zahl der Objektergebnisse neben dem defekten Objekt"
    );
    assert!(
        report
            .object_results()
            .all(|result| result.object_hash() != broken),
        "ein isoliertes Objekt wird nicht indiziert und bekommt kein Ergebnis"
    );
    assert!(
        !report.is_fully_verified(),
        "ein isolierter Befund darf den Bestand nie als vollstaendig verifiziert zeigen"
    );
}

/// Der Kern dieses Tasks: ein Defekt, drei Arrays, und die uebrigen Objekte
/// behalten ihr Ergebnis.
#[test]
fn one_broken_object_among_two_valid_ones_lands_in_exactly_one_error_array() {
    a_mutated_writer_signature_lands_only_in_signature_errors();
    an_overdue_deadline_lands_only_in_evidence_errors();
    a_foreign_encapsulation_lands_only_in_decryption_errors();
}

/// (a) Ein verkipptes Byte in der Schreibersignatur des MITTLEREN Eintrags.
///
/// Der Eintrag faellt an Gate `manifest-signature`, wird deshalb KEIN
/// Kettenknoten und hinterlaesst an seiner Sequenz eine LUECKE. Das ist der
/// wahre Befund und wird hier mitgerechnet statt weggeschwiegen: `ea-chain`
/// vergleicht Vorgaengerbindungen nur zwischen unmittelbar benachbarten
/// Sequenzen, ein fehlender Knoten in der Mitte ist deshalb eine Luecke und kein
/// Bruch — die beiden Nachbarn bleiben unstrittig.
fn a_mutated_writer_signature_lands_only_in_signature_errors() {
    let archive = isolation_archive(IsolationDefectV1::MutatedWriterSignature);
    let recipient = complete_recipient_private_key();
    let report = verify_archive(
        &archive.fixture,
        &archive.anchor(),
        VerifyOptions::new(clock()).with_recipient(complete_recipient_key_thumbprint(), &recipient),
    )
    .expect("ein Befund ueber EIN Objekt ist nie ein Fehler des Laufs");

    let broken = archive.entry_object_hashes[ISOLATION_DEFECT_INDEX_V1];
    let intact: Vec<ObjectHash> = archive
        .entry_object_hashes
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != ISOLATION_DEFECT_INDEX_V1)
        .map(|(_, hash)| *hash)
        .collect();
    assert_eq!(intact.len(), 2, "zwei unversehrte Eintraege daneben");

    assert_isolated(
        &report,
        ErrorArrayV1::Signature,
        broken,
        ManifestSignatureErrorV1::SignatureInvalid.code(),
        &intact,
        intact.len(),
    );
    assert_eq!(
        report.quarantined_objects().len(),
        0,
        "ein Signaturbefund isoliert nicht zusaetzlich"
    );
    assert_eq!(report.gaps().len(), 1, "genau eine Luecke");
    let gap = report.gaps().next().expect("eine Luecke");
    assert_eq!(gap.from_sequence().get(), ISOLATION_DEFECT_SEQUENCE_V1);
    assert_eq!(gap.through_sequence().get(), ISOLATION_DEFECT_SEQUENCE_V1);
}

/// (b) Geforderte, aber ueberfaellige Evidence an GENAU EINER von drei
/// Quittungen.
///
/// Der Befund traegt die QUITTUNG: sie ist das Objekt, das die Frist behauptet.
/// Alle drei Eintraege bleiben gueltig und bestaetigt — deshalb stehen hier drei
/// Ergebnisse im Bericht.
fn an_overdue_deadline_lands_only_in_evidence_errors() {
    // ECHTE FRISTLAGE: `accepted-at-server` (800) < faellig (900) <
    // `effectiveNow` (1800). Eine Quittung, deren Ende vor ihrem eigenen Beginn
    // laege, koennte kein Server je signieren.
    let due_at = FIXTURE_OS_WALL_CLOCK_V1 + 100;
    let after_the_deadline = UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1 + 1000);
    let archive = receipt_archive_with_one_deadline(due_at);

    let report = verify_archive(
        &archive.fixture,
        &archive.anchor(),
        VerifyOptions::new(after_the_deadline)
            .with_evidence_requirement(EvidenceRequirementV1::Required),
    )
    .expect("ein Befund ueber EIN Objekt ist nie ein Fehler des Laufs");

    let broken = archive.receipt_object_hashes[ISOLATION_DEFECT_INDEX_V1];
    assert_isolated(
        &report,
        ErrorArrayV1::Evidence,
        broken,
        EvidenceGateErrorV1::Overdue.code(),
        &archive.entry_object_hashes,
        archive.entry_object_hashes.len(),
    );
    assert!(
        report
            .object_results()
            .all(|result| result.server_confirmation() == ServerConfirmationV1::ServerConfirmed),
        "alle drei Quittungen tragen; nur eine behauptet zusaetzlich eine Frist"
    );
    assert_eq!(
        report.quarantined_objects().len(),
        0,
        "eine ueberfaellige Frist isoliert kein Objekt"
    );
    // Die Vorlauf-Luecke der Quittungslinie: die drei Koepfe verbrauchen die
    // Faecher null und eins, bevor das Schreiberzertifikat aktiv ist.
    assert_eq!(report.gaps().len(), 1);
    let gap = report.gaps().next().expect("eine Luecke");
    assert_eq!(gap.from_sequence().get(), 0);
    assert_eq!(
        gap.through_sequence().get(),
        RECEIPT_PRE_ENTRY_GAP_THROUGH_V1
    );
}

/// (c) Einer von drei Grants ist auf einen FREMDEN Schluessel gekapselt.
///
/// Der Fehlschlag entsteht AUSSCHLIESSLICH in der Entkapselung. Der Grant nennt
/// weiterhin den eigenen Abdruck und dasselbe Empfaengerzertifikat — beides geht
/// in den Planhash ein —, und der Ciphertext bleibt unangetastet: eine Mutation
/// dort faellt bereits an Gate `manifest-signature`, weil der Ciphertexthash im
/// signierten Manifest steht, und der Unterfall fiele auf (a) zurueck.
fn a_foreign_encapsulation_lands_only_in_decryption_errors() {
    let archive = isolation_archive(IsolationDefectV1::ForeignEncapsulation);
    let recipient = complete_recipient_private_key();
    let mut observer = RecordingObserver::new();
    let report = verify_archive_observed(
        &archive.fixture,
        &archive.anchor(),
        VerifyOptions::new(clock()).with_recipient(complete_recipient_key_thumbprint(), &recipient),
        &mut observer,
    )
    .expect("ein Befund ueber EIN Objekt ist nie ein Fehler des Laufs");

    // NEBEN DEM FEHLSCHLAG STEHT EIN ERFOLG. `hpke-open` wird ausschliesslich
    // protokolliert, wenn mindestens eine Entkapselung GELUNGEN ist
    // (`crates/ea-verify/src/recipient.rs:231-245`) — der eine untaugliche Grant
    // hat den Schritt also nicht insgesamt gekippt.
    //
    // MEHR IST VON HIER AUS NICHT ZU MESSEN, und das ist keine Luecke des Tests,
    // sondern Absicht des Berichts: eine GELUNGENE Entkapselung hinterlaesst
    // darin nichts. Der Klartext gehoert nie in einen Bericht, und das Ereignis
    // benennt den Schritt der Pipeline, nicht die Zahl der geoeffneten Objekte.
    assert!(
        observer.events().contains(&DECAPSULATION_EVENT_V1),
        "ein nicht zu oeffnender Grant haelt die Entkapselung als Schritt nicht auf"
    );

    let broken = archive.grant_object_hashes[ISOLATION_DEFECT_INDEX_V1];
    assert_isolated(
        &report,
        ErrorArrayV1::Decryption,
        broken,
        DecryptionErrorV1::CekUnwrapFailed.code(),
        &archive.entry_object_hashes,
        archive.entry_object_hashes.len(),
    );
    assert_eq!(
        report.gaps().len(),
        0,
        "ein nicht zu oeffnender Grant reisst keine Luecke in die Kette"
    );
    assert_eq!(report.quarantined_objects().len(), 0);
}

/// Die Pfadhinweise eines Bestands, in seiner Reihenfolge.
fn hints(fixture: &ArchiveFixture) -> Vec<String> {
    fixture
        .blobs()
        .iter()
        .map(|(hint, _)| hint.clone())
        .collect()
}

/// Die Bytesequenzen eines Bestands als geordnete Multimenge.
fn sorted_bytes(fixture: &ArchiveFixture) -> Vec<Vec<u8>> {
    let mut bytes: Vec<Vec<u8>> = fixture
        .blobs()
        .iter()
        .map(|(_, bytes)| bytes.clone())
        .collect();
    bytes.sort_unstable();
    bytes
}

/// Derselbe Bestand unter anderen Pfaden ist derselbe Bericht.
///
/// Der Fall `renamed_objects_rebuild_the_same_chain` des Stage-1-Plans. Geprueft
/// wird nicht nur der Kettenkopf, sondern die GANZEN kanonischen Bytes: eine
/// Streuordnung irgendwo auf dem Emit-Pfad faellt hier auf, in einer Aussage
/// ueber den Kopf allein nicht.
#[test]
fn renamed_objects_rebuild_the_same_chain() {
    for defect in [
        IsolationDefectV1::None,
        IsolationDefectV1::MutatedWriterSignature,
        IsolationDefectV1::ForeignEncapsulation,
        IsolationDefectV1::DuplicateEntry,
    ] {
        let archive = isolation_archive(defect);
        let recipient = complete_recipient_private_key();
        let options = VerifyOptions::new(clock())
            .with_recipient(complete_recipient_key_thumbprint(), &recipient);

        let canonical_paths: &ArchiveFixture = &archive.fixture;
        let randomized_paths: ArchiveFixture = archive.fixture.randomized_paths();
        // DER VERGLEICH MUSS ETWAS ZU VERGLEICHEN HABEN. Ohne diese beiden
        // Waechter waere der Test still aussagelos, sobald `randomized_paths`
        // je zur Identitaet wuerde: die Hinweise MUESSEN sich unterscheiden, die
        // Bytes als Multimenge NICHT.
        assert_ne!(
            hints(canonical_paths),
            hints(&randomized_paths),
            "die Umbenennung muss die Hinweise wirklich vertauschen"
        );
        assert_eq!(
            sorted_bytes(canonical_paths),
            sorted_bytes(&randomized_paths),
            "die Umbenennung darf keine Bytesequenz veraendern"
        );

        let expected = verify_archive(canonical_paths, &archive.anchor(), options)
            .expect("der Bestand traegt");
        let actual = verify_archive(&randomized_paths, &archive.anchor(), options)
            .expect("derselbe Bestand traegt auch unter anderen Hinweisen");

        assert!(
            expected.chain_head() == actual.chain_head(),
            "derselbe Kettenkopf bei {defect:?}"
        );
        assert_eq!(
            expected
                .to_canonical_json()
                .expect("der Bericht muss kanonisch schreiben"),
            actual
                .to_canonical_json()
                .expect("der Bericht muss kanonisch schreiben"),
            "byteidentische kanonische JSON-Bytes bei {defect:?}"
        );
    }
}

/// Zwei Zustaende, die `is_fully_verified()` NIE senken.
///
/// Der lueckenfreie Bestand traegt keine Quittung — jedes Ergebnis ist damit
/// `notServerConfirmed` —, und der Lauf bekommt keinen Empfaengerschluessel.
/// Beides ist kein Mangel, und beides zusammen ergibt trotzdem einen
/// vollstaendig verifizierten Bestand.
#[test]
fn a_missing_receipt_and_a_missing_recipient_key_are_no_defect() {
    let archive = isolation_archive(IsolationDefectV1::None);

    let report = verify_archive(
        &archive.fixture,
        &archive.anchor(),
        VerifyOptions::new(clock()),
    )
    .expect("der lueckenfreie Bestand traegt");

    assert_eq!(
        report.object_results().len(),
        usize::try_from(ISOLATION_ENTRY_COUNT_V1).expect("drei Eintraege"),
    );
    assert!(
        report
            .object_results()
            .all(|result| result.server_confirmation() == ServerConfirmationV1::NotServerConfirmed),
        "ohne Quittung ist jedes Ergebnis notServerConfirmed"
    );
    assert_eq!(report.decryption_errors().len(), 0);
    assert!(
        report.is_fully_verified(),
        "notServerConfirmed und ein fehlender Empfaengerschluessel sind kein Mangel"
    );
}

/// Umgekehrt: JEDER Quarantaeneeintrag senkt `is_fully_verified()`, auch der
/// harmloseste.
///
/// Eine zweite, bytegleiche Kopie desselben Eintrags ist kein Angriff und kein
/// Verlust — sie ist bloss doppelt. Fail-closed heisst trotzdem: der Bestand
/// gilt nicht als vollstaendig verifiziert, das doppelte Objekt bekommt KEIN
/// Ergebnis, und die uebrigen behalten ihres.
#[test]
fn even_a_duplicate_lowers_full_verification() {
    let archive = isolation_archive(IsolationDefectV1::DuplicateEntry);
    let recipient = complete_recipient_private_key();

    let report = verify_archive(
        &archive.fixture,
        &archive.anchor(),
        VerifyOptions::new(clock()).with_recipient(complete_recipient_key_thumbprint(), &recipient),
    )
    .expect("ein Duplikat ist nie ein Fehler des Laufs");

    let duplicated = archive.entry_object_hashes[ISOLATION_DEFECT_INDEX_V1];
    assert_eq!(report.quarantined_objects().len(), 1);
    let quarantined = report.quarantined_objects().next().expect("ein Eintrag");
    assert!(quarantined.object_hash() == duplicated);
    assert_eq!(quarantined.reason(), QuarantineReason::Duplicate);

    assert_eq!(report.signature_errors().len(), 0);
    assert_eq!(report.evidence_errors().len(), 0);
    assert_eq!(report.decryption_errors().len(), 0);
    assert_eq!(
        report.object_results().len(),
        2,
        "das isolierte Objekt bekommt kein Ergebnis, die beiden anderen behalten ihres"
    );
    assert!(
        report
            .object_results()
            .all(|result| result.object_hash() != duplicated),
        "ein Objekt erscheint entweder in objectResults oder in einem Quarantaenearray"
    );
    assert!(
        !report.is_fully_verified(),
        "auch ein blosses Duplikat senkt die vollstaendige Verifikation"
    );
}
