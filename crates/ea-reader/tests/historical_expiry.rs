//! Der historische Grant, der bis Stufe 5 NICHTS hinterlaesst, und die zwei
//! Ausgaenge von `decrypt_verified`, die der Reader heute erreichen kann.

#[path = "verify_fixtures/mod.rs"]
mod verify_fixtures;

use ea_reader::{
    DECAPSULATION_EVENT_V1, ReaderMode, ReaderVerifier, RecordingObserver, SchemaRegistry,
    SilentObserver, VerificationStatus, decrypt_verified,
};

use verify_fixtures::fixtures;

/// Die Zahl der Grants, die `complete_archive_with_a_forged_historical_grant()`
/// auf den Genesis-Eintrag ablegt.
///
/// ZWEI, und darin lag der Irrtum des frueheren Plantexts: der Bestand ist der
/// vollstaendige PLUS einem gefaelschten historischen Grant, und der initiale
/// eigene Grant bleibt liegen.
const GRANTS_ON_THE_GENESIS_ENTRY_V1: usize = 2;

// Ein gefaelschter historischer Grant hinterlaesst NICHTS — und das ist eine
// staerkere Aussage als „er wird abgewiesen": `own_grant` filtert auf
// `GrantKindV1::Initial` und SIEHT ihn nie. Der `GrantKindV1::Historical`-Arm
// in `verify_own_grant` traegt woertlich den Quelltextkommentar „UNERREICHBAR
// DURCH KONSTRUKTION"; ueber die Pipeline ist
// `EA-VERIFY-GRANT-AUTHORIZATION-UNVERIFIABLE` gar nicht erreichbar.
//
// GEMESSEN und gegen den frueheren Plantext korrigiert: der Eintrag ist
// deshalb `Verified` und NICHT `MissingGrant`. Er traegt seinen eigenen
// initialen Grant weiterhin, und die Entkapselung dahinter laeuft.
#[test]
fn a_forged_historical_grant_leaves_no_trace_at_all() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let source = fixtures::archive_with_a_forged_historical_grant();
    let mut observer = RecordingObserver::new();
    let classification = ReaderVerifier::new(ReaderMode::Server, fixtures::EFFECTIVE_NOW)
        .classify(source, &vault, &mut observer)
        .expect("der Bestand muss klassifizieren");
    let entry_hash = fixtures::entry_hash(source);
    let state = classification
        .state_of(entry_hash)
        .expect("der Eintrag bleibt sichtbar");

    // ANTI-LEERLAUF: der gefaelschte Grant liegt WIRKLICH im Bestand. Ohne
    // diese Zeile waere jede Abwesenheitszusage darunter auch ueber dem
    // unveraenderten Bestand gruen.
    assert_eq!(
        classification.inventory().grants().len(),
        GRANTS_ON_THE_GENESIS_ENTRY_V1,
    );

    // KEIN Code, KEIN Befund, KEIN Unterschied.
    assert_eq!(state.verification(), VerificationStatus::Verified);
    assert_eq!(state.detail_code(), None);
    assert_eq!(classification.report().decryption_errors().len(), 0);
    assert_eq!(classification.report().signature_errors().len(), 0);
    assert!(classification.report().is_fully_verified());

    // Und das Protokoll ist woertlich dasselbe wie ueber dem Bestand OHNE den
    // gefaelschten Grant.
    let mut untouched = RecordingObserver::new();
    ReaderVerifier::new(ReaderMode::Server, fixtures::EFFECTIVE_NOW)
        .classify(fixtures::complete_archive(), &vault, &mut untouched)
        .expect("der unveraenderte Bestand muss klassifizieren");
    assert_eq!(observer.events(), untouched.events());
}

// Ein Zeuge gilt fuer den Lauf, in dem er entstand, weil Gate
// `recipient-grant` seine Nutzungsfrist gegen genau diesen `effectiveNow`
// gemessen hat. Die Pruefung ist EXAKT und ohne Toleranz — eine Toleranz waere
// eine zweite, schwaechere Frist neben der des Registrierungskopfes.
#[test]
fn a_witness_from_an_earlier_run_is_refused() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let source = fixtures::complete_archive();
    let first = fixtures::classify_at(source, &vault, fixtures::EFFECTIVE_NOW);
    let entry_hash = fixtures::entry_hash(source);
    let entry = first
        .verified_entry(entry_hash)
        .expect("der Bestand traegt einen Zeugen");
    let grant = first
        .verified_grant(entry_hash)
        .expect("und einen eigenen Grant");
    let refused = decrypt_verified(
        entry,
        grant,
        &vault,
        &SchemaRegistry::v1(),
        fixtures::LATER_EFFECTIVE_NOW,
        &mut SilentObserver,
    )
    .expect_err("ein Zeuge gilt fuer den Lauf, in dem er entstand");
    assert_eq!(refused.code(), "EA-READER-WITNESS-STALE");
}

// Der Erfolgspfad der KRYPTORECHNUNG, bis zur Schemabestimmung.
//
// Der Lauf faehrt `decrypt_verified` VOLLSTAENDIG durch die HPKE-Entkapselung
// und die AEAD-Oeffnung und endet erwartungsgemaess an der Schemabestimmung:
// der Klartext von `complete_valid_archive()` ist
// `b"einsatzarchiv-fixture-payload"`, und darauf traegt keine der fuenf
// Bestimmungen. GENAU DIESER AUSGANG beweist, dass die aus `open_entry`
// nachgebaute Rechnung stimmt — waere sie falsch, fiele der Lauf FRUEHER mit
// `EA-VERIFY-DECRYPT-CEK-UNWRAP-FAILED` oder
// `EA-VERIFY-DECRYPT-PAYLOAD-OPEN-FAILED`.
#[test]
fn the_hpke_and_aead_computation_runs_in_full_before_the_schema_is_determined() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let source = fixtures::complete_archive();
    let classification = fixtures::classify(source, &vault);
    let entry_hash = fixtures::entry_hash(source);
    let entry = classification
        .verified_entry(entry_hash)
        .expect("der Bestand traegt einen Zeugen");
    let grant = classification
        .verified_grant(entry_hash)
        .expect("und einen eigenen Grant");
    let mut observer = RecordingObserver::new();
    let refused = decrypt_verified(
        entry,
        grant,
        &vault,
        &SchemaRegistry::v1(),
        fixtures::EFFECTIVE_NOW,
        &mut observer,
    )
    .expect_err("der Fixture-Klartext traegt keine Schemakennung");
    assert_eq!(refused.code(), "EA-READER-SCHEMA-UNSUPPORTED");
    // Ein FRISCHER Beobachter sieht genau ein Ereignis und kein Gate-Praefix:
    // die Entkapselung des Readers ist kein zehntes Gate.
    assert_eq!(observer.events(), [DECAPSULATION_EVENT_V1]);
}
