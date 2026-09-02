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

// GEMESSEN und gegen den frueheren Plantext korrigiert: dieser Bestand
// ERREICHT die Entkapselung. Vier seiner Eintraege tragen einen eigenen Grant
// auf den Abdruck des Tresors, `claim_own_grants` oeffnet sie, und das
// archivweite Protokoll enthaelt `hpke-open`. Eine Zusicherung auf die
// ABWESENHEIT des Ereignisses waere hier also rot gewesen — und ueber einem
// Bestand ohne eigene Grants waere sie gruen gewesen, ohne etwas zu messen.
//
// Was der Stummel wirklich zusagt, ist enger und staerker: er wird nie ein
// Kettenknoten, bekommt kein `objectResult`, kein Grant nennt seinen
// `entryHash`, und `claim_own_grants` laeuft ausschliesslich ueber platzierte
// Eintraege MIT `objectResult`. Der Typzusage nach heisst das: fuer einen
// Stummel ist `decrypt_verified` gar nicht erst formulierbar.
#[test]
fn a_stub_reaches_no_decapsulation_in_either_outcome() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    for (label, source, entry_state) in [
        (
            "autorisiert vernichtet",
            fixtures::stub_with_resolvable_authorization(),
            EntryStatus::AuthorizedDestroyed,
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
        // BEIDE Dimensionen bleiben getrennt (design.md §17.4): auch der
        // autorisiert vernichtete Stummel hat KEIN objectResult und steht in
        // einem gaps-Intervall, ist in der Verifikationsdimension also `Gap`.
        assert_eq!(state.verification(), VerificationStatus::Gap, "{label}");
        assert_eq!(
            state.sequence(),
            ChainSequence::new(verify_support::REPORT_DESTROYED_STUB_SEQUENCE_V1),
            "{label}"
        );
    }
}

// Die PRUEFKETTE, aus der `autorisiert vernichtet` ueberhaupt erst entsteht.
//
// `ObjectResultKindV1::AuthorizedDestroyed` ist ein TOTER Zweig —
// `confirm_entries` ist der einzige Erzeuger von `objectResults` und setzt
// ausnahmslos `Valid`. Der Zustand kommt deshalb aus drei Gliedern: die
// `destructionId` des Stummels gegen `authorized_destructions()`, sein
// `destructionAuthorizationObjectHash` gegen den Hash, den die Transitionen
// authentifiziert haben, und der Eintrag des Stummels gegen die `targets` der
// Autorisierung. Dieser Zeuge haelt fest, dass ALLE VIER Bestaende denselben
// Vorgang fuehren, der Bericht ueber keinen von ihnen einen zusaetzlichen
// Befund traegt — und dass jeder der drei Luecken-Bestaende GENAU EIN Glied
// bricht. Ein Join, der ein Glied auslaesst, laesst also mindestens einen von
// ihnen als `autorisiert vernichtet` durch; das misst
// `a_stub_reaches_no_decapsulation_in_either_outcome`.
#[test]
fn the_authorized_destruction_is_reached_only_through_the_full_chain() {
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
