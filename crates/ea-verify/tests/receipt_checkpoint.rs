//! Gate `receipt`: Serverquittungen, Checkpoints und der Stummel.
//!
//! Gate `receipt` umfasst nach `design.md` §14.1 Schritt 7 (:1581) die
//! Serverquittung UND die Checkpoints, sofern vorhanden. Checkpoints gehoeren
//! ausdruecklich NICHT zu Gate `evidence`; Gate 8 ist auf Evidence-Objekte und
//! Zeitstempel begrenzt. Die Verwechslung liegt nahe, weil beide in
//! `crates/ea-format/src/ecp.rs` wohnen — deshalb steht sie hier und im Code
//! benannt.
//!
//! DREI MESSUNGEN, DIE DIESES TARGET GEGEN DEN URSPRUENGLICHEN ZUSCHNITT
//! VERSCHIEBEN. Sie sind gemessen und nicht abgeleitet; wer sie „wegrepariert",
//! macht den Test unwahr:
//!
//! 1. `is_fully_verified()` kann in diesem Stand fuer KEINEN Bestand wahr sein.
//!    `pipeline_completed` bleibt bis Task 17 falsch, und jeder Bestand dieser
//!    Fixtures traegt die Vorlauf-Luecke `0..=1`
//!    (`support::RECEIPT_PRE_ENTRY_GAP_THROUGH_V1`). Statt eines Bool, das
//!    ohnehin nur `false == false` behauptete, prueft dieses Target die
//!    STAERKERE Aussage: der Bestand ohne Quittung gibt in allen sechs
//!    Mangelfeldern EXAKT dasselbe Bild ab wie der mit Quittung. Genau das
//!    heisst „`notServerConfirmed` ist kein Mangel" (`design.md`:1591) — und
//!    genau das faengt den echten Fehlerfall, dass eine fehlende Quittung
//!    stillschweigend einen Eintrag in ein Mangelfeld legt.
//! 2. Ein `.eds` kann in diesem Stand NICHT `authorizedDestroyed` werden. Der
//!    Stummel benennt eine `destructionAuthorization`; deren Aufloesung ist von
//!    `ea-verify` aus nicht erreichbar — `ea-trust` exportiert dafuer keine
//!    Pruefung, `TrustCatalog` ist `pub(crate)`, und `catalog::load` prueft
//!    ueberhaupt keine Signatur. Die vollstaendige Messung steht bei
//!    `place_in_chain` in `crates/ea-verify/src/archive.rs`.
//!    Der Task nennt selbst die Gegenregel — „ein Stub ohne vollstaendige
//!    Pruefkette bleibt eine Luecke" (`design.md`:1597) —, und genau die wird
//!    hier gemessen.
//! 3. Der Bestand braucht DREI Registrierungskoepfe (Policy, Serverzertifikat,
//!    Schreiberzertifikat), weil ein Kopf genau einen Uebergang traegt und
//!    `VerificationContext::receipt` ein Zertifikat mit der Capability
//!    `serverReceipt` verlangt. Daher die Vorlauf-Luecke `0..=1`.

#[path = "support/mod.rs"]
mod support;

use ea_archive::QuarantineReason;
use ea_chain::RollbackAssessment;
use ea_types::UnixMillis;
use ea_verify::{
    ObjectResultKindV1, ServerConfirmationV1, VerificationReportV1, VerifyOptions, verify_archive,
};

use support::{
    CHECKPOINT_PROVEN_GAP_FROM_V1, CHECKPOINT_TRUNCATED_THROUGH_V1, CheckpointSpec,
    DESTROYED_STUB_SEQUENCE_V1, FIXTURE_OS_WALL_CLOCK_V1, GENESIS_GAP_SEQUENCE_V1,
    RECEIPT_HEAD_SEQUENCE_V1, RECEIPT_PRE_ENTRY_GAP_THROUGH_V1, ReceiptArchiveSpec,
    receipt_archive,
};

fn options() -> VerifyOptions<'static> {
    VerifyOptions::new(UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1))
}

/// Die Luecke, die JEDER Bestand dieses Moduls traegt.
fn pre_entry_gap(report: &VerificationReportV1) -> bool {
    report.gaps().any(|gap| {
        gap.from_sequence().get() == GENESIS_GAP_SEQUENCE_V1
            && gap.through_sequence().get() == RECEIPT_PRE_ENTRY_GAP_THROUGH_V1
    })
}

/// Die Groessen der sechs Mangelfelder, die `is_fully_verified()` speisen.
#[derive(Debug, Eq, PartialEq)]
struct DefectCounts {
    format_errors: usize,
    quarantined: usize,
    signature_errors: usize,
    evidence_errors: usize,
    decryption_errors: usize,
    gaps: usize,
}

fn defects(report: &VerificationReportV1) -> DefectCounts {
    DefectCounts {
        format_errors: report.format_errors().len(),
        quarantined: report.quarantined_objects().len(),
        signature_errors: report.signature_errors().len(),
        evidence_errors: report.evidence_errors().len(),
        decryption_errors: report.decryption_errors().len(),
        gaps: report.gaps().len(),
    }
}

/// UMBENANNT GEGENUEBER DEM AUFTRAG, und zwar bewusst. Der Auftrag nannte
/// diesen Test
/// `receipts_confirm_checkpoints_bound_rollback_and_a_stub_is_authorized_destroyed`.
/// Der letzte Namensteil behauptet ein Ergebnis, das dieser Stand nicht
/// erreichen kann und das der Rumpf deshalb widerlegt (Messung 2 im Modulkopf).
/// Ein Testname, der das Gegenteil seines Rumpfes behauptet, ist derselbe
/// Fehler wie eine Pruefung, die wie eine aussieht, ohne eine zu sein.
#[test]
fn receipts_confirm_checkpoints_bound_rollback_and_a_stub_stays_a_gap() {
    // ---------------------------------------------------------------- 1 ----
    // MIT QUITTUNG: beide Eintraege sind gueltig UND serverbestaetigt.
    let built = receipt_archive(ReceiptArchiveSpec::bare().with_receipts());
    let anchor = built.anchor();
    let confirmed = verify_archive(&built.fixture, &anchor, options())
        .expect("der Bestand mit Quittungen muss berichten");

    let results: Vec<_> = confirmed.object_results().collect();
    assert_eq!(
        results.len(),
        built.entry_object_hashes.len(),
        "jeder unstrittige Eintrag bekommt genau ein Objektergebnis"
    );
    for expected in &built.entry_object_hashes {
        let result = results
            .iter()
            .find(|result| result.object_hash() == *expected)
            .expect("zu jedem Eintrag muss ein Objektergebnis gehoeren");
        assert_eq!(
            result.result(),
            ObjectResultKindV1::Valid,
            "ein vollstaendig geprueftes Eintragspaket ist gueltig"
        );
        assert_eq!(
            result.server_confirmation(),
            ServerConfirmationV1::ServerConfirmed,
            "server confirmation"
        );
    }
    // Der Abdruck, der die Pruefungen GETRAGEN hat. Er ist in dieser Linie fuer
    // Schreiber und Server derselbe — die Registrierungslinie stellt jedes
    // Geraetezertifikat auf denselben Schluessel aus, die Rolle kommt vom
    // ZERTIFIKAT. Der Nachweis ist deshalb hier keine Unterscheidung zwischen
    // beiden, sondern die Aussage, dass ueberhaupt gegen einen geprueft wurde.
    assert!(
        confirmed
            .public_key_thumbprints()
            .any(|thumbprint| thumbprint == support::writer_device_key_thumbprint()),
        "eine erfolgreiche Signaturpruefung legt ihren Abdruck in den Nachweis"
    );

    // ---------------------------------------------------------------- 2 ----
    // OHNE QUITTUNG: derselbe Bestand, dieselben Maengel, nur unbestaetigt.
    let bare = receipt_archive(ReceiptArchiveSpec::bare());
    let bare_anchor = bare.anchor();
    let unconfirmed = verify_archive(&bare.fixture, &bare_anchor, options())
        .expect("der Bestand ohne Quittungen muss berichten");

    let bare_results: Vec<_> = unconfirmed.object_results().collect();
    assert_eq!(
        bare_results.len(),
        bare.entry_object_hashes.len(),
        "eine fehlende Quittung nimmt keinem Eintrag sein Ergebnis"
    );
    for result in &bare_results {
        assert_eq!(
            result.result(),
            ObjectResultKindV1::Valid,
            "ohne Quittung bleibt der Eintrag GUELTIG"
        );
        assert_eq!(
            result.server_confirmation(),
            ServerConfirmationV1::NotServerConfirmed,
            "server confirmation"
        );
    }
    // DIE EIGENTLICHE AUSSAGE: `notServerConfirmed` ist kein Mangel. Die beiden
    // Bestaende unterscheiden sich in KEINEM der sechs Felder, die
    // `is_fully_verified()` speisen — nur in der Bestaetigungsdimension.
    assert_eq!(
        defects(&unconfirmed),
        defects(&confirmed),
        "eine fehlende Quittung darf in keinem Mangelfeld einen Eintrag erzeugen"
    );
    assert_eq!(
        unconfirmed.is_fully_verified(),
        confirmed.is_fully_verified(),
        "eine fehlende Quittung senkt das Gesamturteil nicht"
    );

    // ---------------------------------------------------------------- 3 ----
    // OHNE CHECKPOINT: NICHT PRUEFBAR — und ausdruecklich nicht „kein Rollback".
    assert_eq!(
        *unconfirmed.rollback_assessment(),
        RollbackAssessment::NotAssessable,
        "ohne `.ecp` ist ueber Rollback NICHTS gesagt"
    );
    assert_eq!(
        *confirmed.rollback_assessment(),
        RollbackAssessment::NotAssessable
    );

    // ---------------------------------------------------------------- 4 ----
    // CHECKPOINT UEBER DEM KOPF: eine BEWIESENE Luecke, kein Widerspruch.
    let built = receipt_archive(
        ReceiptArchiveSpec::bare()
            .with_receipts()
            .with_checkpoint(CheckpointSpec::Truncated),
    );
    let anchor = built.anchor();
    let truncated = verify_archive(&built.fixture, &anchor, options())
        .expect("der abgeschnittene Bestand muss berichten");

    assert!(
        matches!(
            truncated.rollback_assessment(),
            RollbackAssessment::Rollback(_)
        ),
        "ein Checkpoint oberhalb des Kopfes ist ein Rueckbaubefund"
    );
    let proven: Vec<_> = truncated
        .gaps()
        .filter(|gap| gap.from_sequence().get() == CHECKPOINT_PROVEN_GAP_FROM_V1)
        .collect();
    assert_eq!(proven.len(), 1, "genau eine bewiesene Luecke");
    assert_eq!(
        proven[0].through_sequence().get(),
        CHECKPOINT_TRUNCATED_THROUGH_V1,
        "die Luecke reicht bis zur bezeugten Sequenz"
    );
    assert!(
        proven[0].chain_id() == anchor.chain_id(),
        "die Kettenkennung stammt IMMER aus dem Anker"
    );
    assert!(pre_entry_gap(&truncated), "die Vorlauf-Luecke bleibt");
    assert_eq!(
        truncated.quarantined_objects().len(),
        0,
        "eine bewiesene Luecke isoliert kein Objekt — es fehlt ja gerade"
    );

    // ---------------------------------------------------------------- 5 ----
    // CHECKPOINT MIT ANDEREM KOPFHASH: GENAU EIN Widerspruch, keine Luecke.
    let built = receipt_archive(
        ReceiptArchiveSpec::bare()
            .with_receipts()
            .with_checkpoint(CheckpointSpec::HeadMismatch),
    );
    let anchor = built.anchor();
    let conflicting = verify_archive(&built.fixture, &anchor, options())
        .expect("der widersprechende Bestand muss berichten");

    let isolated: Vec<_> = conflicting.quarantined_objects().collect();
    assert_eq!(isolated.len(), 1, "genau ein isoliertes Objekt");
    assert_eq!(
        isolated[0].reason(),
        QuarantineReason::Conflicting,
        "ein Kopfwiderspruch ist ein WIDERSPRUCH, kein Zuordnungsmangel"
    );
    assert!(
        isolated[0].object_hash() == built.entry_object_hashes[1],
        "isoliert wird der Eintrag, dem der Checkpoint widerspricht"
    );
    assert_eq!(
        conflicting
            .gaps()
            .filter(|gap| gap.from_sequence().get() > RECEIPT_PRE_ENTRY_GAP_THROUGH_V1)
            .count(),
        0,
        "eine Kopfabweichung beweist KEINE Luecke"
    );
    // OHNE DIESE ZEILE waere der Fall still aussagelos: haette der Checkpoint
    // sich nicht als Serveraussage nachweisen lassen, entstuende gar kein
    // `CheckpointClaim`, `assess_rollback` liefe auf `NotAssessable` — und der
    // Widerspruch oben faende nie statt. Der Befund stuende dann hier.
    assert_eq!(
        conflicting.signature_errors().len(),
        0,
        "der Checkpoint muss sich als Serveraussage nachweisen lassen"
    );
    // Ein Objekt erscheint ENTWEDER in `objectResults` ODER in genau einem
    // Fehler-/Quarantaenearray, niemals in beidem.
    assert!(
        conflicting
            .object_results()
            .all(|result| result.object_hash() != built.entry_object_hashes[1]),
        "ein isoliertes Objekt bekommt kein Objektergebnis"
    );

    // ---------------------------------------------------------------- 6 ----
    // DER STUMMEL. ABWEICHUNG, GEMESSEN: `authorizedDestroyed` ist in diesem
    // Stand unerreichbar, weil die `destructionAuthorization` des Stummels von
    // `ea-verify` aus nicht aufloesbar ist — `ea-trust` exportiert dafuer keine
    // Pruefung, `TrustCatalog` ist `pub(crate)`, und blosse Inventarmitglied-
    // schaft ist KEINE Autorisierung. Fail-closed heisst dann: der Stummel wird
    // kein Kettenknoten, und das fehlende `.eip` erscheint als Luecke
    // (`design.md`:1597). Eine Entschluesselung findet ohnehin nicht statt.
    let built = receipt_archive(ReceiptArchiveSpec::bare().with_destroyed_stub());
    let anchor = built.anchor();
    let stubbed = verify_archive(&built.fixture, &anchor, options())
        .expect("der Bestand mit Stummel muss berichten");

    assert_eq!(
        stubbed.destroyed_entry_count(),
        1,
        "der Stummel wird gezaehlt — ein Zaehler ist keine Sachaussage"
    );
    assert_eq!(
        stubbed.authorized_destructions().len(),
        0,
        "ohne aufloesbare Autorisierung wird KEIN Vernichtungsvorgang behauptet"
    );
    let stub_hash = built
        .destroyed_stub_object_hash
        .expect("das Fixture legt einen Stummel ab");
    assert!(
        stubbed
            .object_results()
            .all(|result| result.object_hash() != stub_hash),
        "ein Stummel ohne vollstaendige Pruefkette bekommt kein Objektergebnis"
    );
    assert!(
        stubbed.gaps().any(|gap| {
            gap.from_sequence().get() == DESTROYED_STUB_SEQUENCE_V1
                && gap.through_sequence().get() == DESTROYED_STUB_SEQUENCE_V1
        }),
        "das fehlende `.eip` des Stummels erscheint als Luecke"
    );
    // Der Stummel ist eine LUECKE und sonst nichts: er erzeugt weder einen
    // Signatur- noch einen Format- noch einen Quarantaenebefund, und schon gar
    // keinen Entschluesselungsversuch.
    assert_eq!(
        defects(&stubbed),
        DefectCounts {
            format_errors: 0,
            quarantined: 0,
            signature_errors: 0,
            evidence_errors: 0,
            decryption_errors: 0,
            // Die Vorlauf-Luecke `0..=1` und das Fach des Stummels.
            gaps: 2,
        },
        "ein Stummel ohne Autorisierung ist eine Luecke und kein weiterer Mangel"
    );
    assert_eq!(
        stubbed.chain_head().sequence().get(),
        RECEIPT_HEAD_SEQUENCE_V1,
        "der Kopf bleibt der letzte unstrittige Eintrag"
    );
}
