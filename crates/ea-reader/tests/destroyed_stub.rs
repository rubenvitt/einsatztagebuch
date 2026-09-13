//! Der `.eds`-Stummel: zwei Ausgaenge, zwei Dimensionen, und in keinem der
//! beiden ein Weg an den HPKE-Entkapseler.

#[path = "verify_fixtures/mod.rs"]
mod verify_fixtures;

use ea_format::DecodedTrustPayloadV1;
use ea_reader::{
    ChainSequence, DECAPSULATION_EVENT_V1, EntryStatus, ReaderClassification, ReaderMode,
    ReaderVerifier, RecordingObserver, VerificationStatus,
};
use ea_types::{DestructionId, ObjectHash};

use verify_fixtures::{fixtures, verify_support};

// These older archives have valid approval/events but no normal encrypted
// Writer Evidence binding the Stub. Every Stub remains an unexplained gap;
// the other four actual entries still reach HPKE.
#[test]
fn a_stub_reaches_no_decapsulation_in_either_outcome() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    for (label, source, entry_state) in [
        (
            "Autorisierung ohne gebundene Writer-Evidence",
            fixtures::stub_with_resolvable_authorization(),
            EntryStatus::UnexplainedGap,
        ),
        (
            "ungeklaerte Luecke: Kennung zeigt auf nichts",
            fixtures::stub_without_resolvable_authorization(),
            EntryStatus::UnexplainedGap,
        ),
        (
            "ungeklaerte Luecke: gefaelschter Autorisierungshash",
            fixtures::stub_naming_a_forged_authorization_hash(),
            EntryStatus::UnexplainedGap,
        ),
        (
            "ungeklaerte Luecke: Autorisierung nennt einen anderen Eintrag",
            fixtures::stub_of_an_authorization_targeting_another_entry(),
            EntryStatus::UnexplainedGap,
        ),
    ] {
        let mut observer = RecordingObserver::new();
        let classification = ReaderVerifier::new(ReaderMode::Server, fixtures::EFFECTIVE_NOW)
            .classify(source, &vault, &mut observer)
            .expect("der Berichtsbestand muss klassifizieren");
        let key = fixtures::stub_entry_hash(source);

        // ANTI-LEERLAUF: der Lauf FAEHRT durch die Entkapselung.
        assert!(
            observer.events().contains(&DECAPSULATION_EVENT_V1),
            "{label}"
        );

        let stub_object_hash = classification.inventory().destroyed()[0].object_hash();
        assert!(
            classification
                .report()
                .object_results()
                .all(|result| result.object_hash() != stub_object_hash),
            "{label}: ein `.eds` bekommt kein objectResult"
        );
        assert!(
            classification.inventory().grants().iter().all(|grant| grant
                .value()
                .grant_body()
                .fields()
                .entry_hash
                != key),
            "{label}: kein Grant nennt den entryHash des Stummels"
        );
        assert!(classification.verified_entry(key).is_none(), "{label}");
        assert!(classification.verified_grant(key).is_none(), "{label}");

        let state = classification
            .state_of(key)
            .expect("der Stummel traegt entryHash und Sequenz selbst");
        assert_eq!(state.entry_state(), entry_state, "{label}");
        // These fixtures have no complete Stub Evidence, hence no result.
        assert_eq!(state.verification(), VerificationStatus::Gap, "{label}");
        assert_eq!(
            state.sequence(),
            ChainSequence::new(verify_support::REPORT_DESTROYED_STUB_SEQUENCE_V1),
            "{label}"
        );
    }
}

// Authorization/transition/target joins are independently visible, but they
// never substitute for the later authenticated encrypted Stub binding.
#[test]
fn the_authorization_graph_alone_cannot_supply_stub_evidence() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let resolvable = fixtures::classify(fixtures::stub_with_resolvable_authorization(), &vault);
    let (authorized_id, authorized_hash) = the_one_authorized_destruction(&resolvable);
    assert!(
        links_of(&resolvable) == [true, true, true],
        "die Kette schliesst sich"
    );

    for (label, source, links) in [
        (
            "Kennung zeigt auf nichts",
            fixtures::stub_without_resolvable_authorization(),
            [false, false, true],
        ),
        (
            "gefaelschter Autorisierungshash",
            fixtures::stub_naming_a_forged_authorization_hash(),
            [true, false, true],
        ),
        (
            "Autorisierung nennt einen anderen Eintrag",
            fixtures::stub_of_an_authorization_targeting_another_entry(),
            [true, true, false],
        ),
    ] {
        let classification = fixtures::classify(source, &vault);
        // Derselbe Vorgang, in jedem Bestand, unter derselben Kennung.
        let (id, hash) = the_one_authorized_destruction(&classification);
        assert!(id == authorized_id, "{label}");
        // Der Bestand mit dem fremden Ziel traegt eine ANDERE Autorisierung;
        // die uebrigen dieselbe.
        assert!((hash == authorized_hash) == links[2], "{label}");
        // Der Bericht traegt ueber KEINEN von ihnen einen zusaetzlichen Befund:
        // die Faelschung ist fuer `ea-verify` unsichtbar, und genau deshalb
        // muss der Reader die Kette selbst ziehen.
        assert_eq!(
            public_finding_counts(&classification),
            public_finding_counts(&resolvable),
            "{label}"
        );
        assert_eq!(links_of(&classification), links, "{label}");
    }
}

/// Kennung und Autorisierungshash des EINEN Vorgangs eines Berichtsbestands.
fn the_one_authorized_destruction(
    classification: &ReaderClassification,
) -> (DestructionId, ObjectHash) {
    let mut destructions = classification.report().authorized_destructions();
    let destruction = destructions.next().expect("der Vorgang liegt im Bestand");
    assert!(destructions.next().is_none(), "genau ein Vorgang");
    (
        destruction.destruction_id(),
        destruction.authorization_object_hash(),
    )
}

/// Die drei Glieder der Pruefkette des EINEN Stummels, einzeln gemessen.
///
/// `[Kennung trifft, Hash trifft, Autorisierung nennt den Stummel-Eintrag]`.
/// Das dritte Glied wird gegen die Autorisierung gemessen, die der BERICHT
/// fuehrt, nicht gegen die, die der Stummel nennt — sonst waere es bei einem
/// gefaelschten Hash gar nicht messbar.
fn links_of(classification: &ReaderClassification) -> [bool; 3] {
    let (authorized_id, authorized_hash) = the_one_authorized_destruction(classification);
    let stub = classification.inventory().destroyed()[0].value();
    let sequence = stub.signed_manifest().manifest().fields().chain_sequence;
    let authorization = classification
        .inventory()
        .trust()
        .iter()
        .find(|object| object.object_hash() == authorized_hash)
        .expect("die Autorisierung des Vorgangs liegt im Bestand");
    let Ok(DecodedTrustPayloadV1::DestructionAuthorization(fields)) =
        authorization.value().decoded_payload()
    else {
        panic!("der Bericht fuehrt eine Vernichtungsautorisierung");
    };
    [
        stub.destruction_id() == authorized_id,
        stub.destruction_authorization_object_hash() == authorized_hash,
        fields.targets.iter().any(|target| {
            target.entry_hash() == stub.entry_hash().as_bytes()
                && target.chain_sequence() == sequence.get()
        }),
    ]
}

/// Die Befundzaehler des Berichts, die ein Stummel ueberhaupt beruehren
/// koennte.
fn public_finding_counts(classification: &ReaderClassification) -> [usize; 5] {
    let report = classification.report();
    [
        report.object_results().count(),
        report.format_errors().count(),
        report.quarantined_objects().count(),
        report.signature_errors().count(),
        report.gaps().count(),
    ]
}
