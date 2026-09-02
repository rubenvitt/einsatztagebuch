//! Der historische Grant, der bis Stufe 5 NICHTS hinterlaesst, und die drei
//! Ausgaenge von `decrypt_verified`, die der Reader heute erreichen kann: der
//! veraltete Zeuge, die Schemabestimmung, die nichts traegt, und der VOLLE
//! Erfolg ueber einem schemagueltigen Klartext.

#[path = "verify_fixtures/mod.rs"]
mod verify_fixtures;

use ea_format::GrantKindV1;
use ea_reader::{
    DECAPSULATION_EVENT_V1, PayloadV1, ReaderMode, ReaderVerifier, RecordingObserver,
    SchemaRegistry, SilentObserver, VerificationStatus, decrypt_verified,
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
//
// WELCHER Grant der Zeuge ist, entscheidet sich an der Reihenfolge: der
// gefaelschte liegt unter dem kleineren Objekthash und steht in
// `inventory.grants()` VOR dem initialen. Liesse `own_grant` den Artfilter
// fallen, bliebe jede Zusicherung oben gruen — und der Zeuge truege die
// Faelschung. Deshalb faehrt dieser Test das Paar durch `decrypt_verified`:
// nur der initiale Grant entkapselt bis zur Schemabestimmung
// (`EA-READER-SCHEMA-UNSUPPORTED`); die Faelschung kapselt auf nichts und
// fiele frueher, mit `EA-VERIFY-DECRYPT-CEK-UNWRAP-FAILED`.
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

    // ANTI-LEERLAUF fuer die Ordnung: die Faelschung steht VOR dem initialen
    // Grant, sonst maesse die Entkapselung unten den Artfilter gar nicht.
    let initial = classification
        .inventory()
        .grants()
        .iter()
        .find(|grant| grant.value().grant_body().fields().kind == GrantKindV1::Initial)
        .expect("der initiale eigene Grant liegt weiterhin im Bestand");
    assert!(fixtures::forged_historical_grant_object_hash() < initial.object_hash());
    assert!(
        classification.inventory().grants()[0].object_hash()
            == fixtures::forged_historical_grant_object_hash()
    );

    // Der Zeuge ist der INITIALE Grant: das Paar entkapselt bis zur
    // Schemabestimmung.
    let entry = classification
        .verified_entry(entry_hash)
        .expect("der Eintrag traegt einen Zeugen");
    let grant = classification
        .verified_grant(entry_hash)
        .expect("und einen eigenen Grant");
    let refused = decrypt_verified(
        entry,
        grant,
        &vault,
        &SchemaRegistry::v1(),
        fixtures::EFFECTIVE_NOW,
        &mut SilentObserver,
    )
    .expect_err("der Fixture-Klartext traegt keine Schemakennung");
    assert_eq!(refused.code(), "EA-READER-SCHEMA-UNSUPPORTED");
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

// Der ZWEITE Zeuge des Erfolgspfads: der volle Weg bis `with_plaintext`,
// `with_payload`, `source_schema` und `target_schema`.
//
// Der erste Zeuge oben beweist die Kryptorechnung und endet an der
// Schemabestimmung; er sagt NICHTS darueber, was `VerifiedDecryptedRecord`
// danach herausgibt. Ohne diesen Lauf waeren die acht Zugriffe eine
// unbefahrene Flaeche, und jede spaetere Aufgabe baute auf einer Signatur, die
// nie einen Wert getragen hat. Der Bestand ist DERSELBE Bau wie
// `complete_archive()`, nur mit dem eingefrorenen Genesis-Vektor als
// Klartext — und der Zeuge misst gegen den Vektor und nicht gegen etwas, das
// der Reader selbst erzeugt hat.
#[test]
fn a_genesis_plaintext_is_opened_in_full_and_never_escapes_the_record() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let source = fixtures::complete_archive_with_a_genesis_plaintext();
    let classification = fixtures::classify(source, &vault);
    let entry_hash = fixtures::entry_hash(source);
    let state = classification
        .state_of(entry_hash)
        .expect("der Eintrag bleibt sichtbar");
    assert_eq!(state.verification(), VerificationStatus::Verified);
    let entry = classification
        .verified_entry(entry_hash)
        .expect("der Bestand traegt einen Zeugen");
    let grant = classification
        .verified_grant(entry_hash)
        .expect("und einen eigenen Grant");

    let mut observer = RecordingObserver::new();
    let record = decrypt_verified(
        entry,
        grant,
        &vault,
        &SchemaRegistry::v1(),
        fixtures::EFFECTIVE_NOW,
        &mut observer,
    )
    .expect("der Genesis-Klartext traegt die erste Schemabestimmung");
    // Genau EINE Entkapselung, und kein Gate-Praefix — auch im Erfolgsfall.
    assert_eq!(observer.events(), [DECAPSULATION_EVENT_V1]);

    // Die Herkunftsspalten sind die des Zeugen und nicht neu erfunden.
    assert!(record.entry_hash() == entry.entry_hash());
    assert_eq!(record.chain_sequence(), entry.chain_sequence());
    assert!(record.object_hash() == entry.object_hash());
    assert_eq!(record.minted_at(), fixtures::EFFECTIVE_NOW);

    // Die Bestimmung ist die des Vektors — UNABHAENGIG vom Record ermittelt,
    // ueber dieselbe Probe, die `decrypt_verified` faehrt, und ohne die
    // Kennung als Literal ein zweites Mal zu schreiben. In v1 ist die
    // Ableitung die Identitaet: Quelle und Ziel sind dasselbe Paar.
    let registry = SchemaRegistry::v1();
    let mut determined = registry.schemas().iter().filter(|descriptor| {
        registry
            .validate(
                descriptor.schema_id(),
                descriptor.schema_version(),
                fixtures::genesis_plaintext(),
            )
            .is_ok()
    });
    let descriptor = determined
        .next()
        .expect("der Vektor traegt genau eine Bestimmung");
    assert!(determined.next().is_none());
    let expected_schema = (descriptor.schema_id(), descriptor.schema_version());
    assert_eq!(record.source_schema(), expected_schema);
    assert_eq!(record.target_schema(), expected_schema);

    // Die Bytes sind der Vektor, BYTEGLEICH — kein Rest, kein Praefix.
    assert!(record.with_plaintext(|bytes| bytes == fixtures::genesis_plaintext()));
    // Und die geparste Nutzlast ist die Genesis-Variante, dekodiert innerhalb
    // der Ausleihe; `Debug` gibt keinen ihrer Werte heraus.
    record.with_payload(|payload| {
        let PayloadV1::Genesis(genesis) = payload else {
            panic!("der Genesis-Vektor dekodiert zur Genesis-Variante");
        };
        let timezone = genesis.header().timezone();
        assert!(!timezone.is_empty());
        assert!(!format!("{record:?}").contains(timezone));
    });
    assert!(record.with_plaintext(|bytes| !format!("{record:?}").contains(&hex::encode(bytes))));
}
