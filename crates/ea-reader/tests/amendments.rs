//! Nachtragsreferenzen und die Original/Nachtrag-Projektion.
//!
//! Der Faden VERBINDET und ERSETZT NICHT. Was diese Zeugen messen, ist genau
//! diese Trennung: ein Nachtrag tritt bei, wenn alle vier Referenzen auf das
//! VERIFIZIERTE Original zeigen; weicht eine ab, wird er ein PRUEFPROBLEM und
//! keine Luecke; und das Original behaelt in jedem dieser Faelle seine Bytes,
//! seinen Eintragshash und seine Sichtbarkeit. `web-reader-design.md` §12 und
//! die Produktinvariante „amendment-only corrections" lassen dazu keinen
//! zweiten Weg zu.
//!
//! # Die Eingaben sind ECHTE Zeugen
//!
//! Jeder Datensatz dieser Laeufe kommt aus `decrypt_verified` ueber einem
//! lueckenlosen, vollstaendig verifizierten Bestand — dem Bau, den
//! `amendment_fixtures/fixtures.rs` beschreibt. `ReaderEntryThread::build`
//! nimmt ausschliesslich [`VerifiedDecryptedRecord`], und dieser Typ ist
//! nirgendwo sonst konstruierbar; die Reihenfolge „Verifikation vor
//! Entschluesselung" steht damit schon in den Typen und nicht erst in einem
//! Kommentar.
//!
//! # Zwei Abweichungen vom Testrumpf des Plans, beide erzwungen
//!
//! 1. `EntryHash` und `RecordId` entstehen aus `hash_newtype!`/`id_newtype!`
//!    in `crates/ea-types/src/ids.rs` und leiten KEIN `Debug` ab. `assert_eq!`
//!    und `assert_ne!` verlangen es und uebersetzen darauf gar nicht erst;
//!    jeder Vergleich dieser beiden Typen — und der von [`CorrectionReference`],
//!    die beide traegt — laeuft deshalb ueber `assert!(a == b)`. Dieselbe
//!    Begruendung schreibt `verify_fixtures/fixtures.rs` bereits aus.
//! 2. `Result::unwrap_err` verlangt `Debug` auf dem ERFOLGSTYP.
//!    `ReaderEntryThread` ist ein opaker Wert ohne `Debug`, und ein `Debug`
//!    darauf gaebe es nur um den Preis, die Klartexte seiner Datensaetze
//!    ausgabefaehig zu machen — genau das, was `WR-082` verbietet. Der
//!    Fehlschlag des untauglichen Originals wird deshalb ueber ein
//!    `let ... else` gepflueckt.

#[path = "amendment_fixtures/mod.rs"]
mod amendment_fixtures;

use ea_reader::{
    AmendmentJoinErrorV1, ChainSequence, CorrectionReference, PayloadV1, ReaderEntryThread,
    RejectedAmendment, VerificationStatus,
};

use amendment_fixtures::fixtures;

#[test]
fn amendments_join_without_replacing_the_original() {
    let thread = ReaderEntryThread::build(
        fixtures::original(),
        vec![fixtures::amendment_b(), fixtures::amendment_a()],
    )
    .expect("ein Einsatz ist ein taugliches Original");

    thread.original().with_payload(|payload| {
        let PayloadV1::Incident(incident) = payload else {
            panic!("the original of a thread is an incident record")
        };
        assert!(incident.header().record_id() == fixtures::original_record_id());
        assert_eq!(incident.human_incident_number(), "2026-0001");
    });
    // Sortiert nach Kettensequenz, nicht nach Eingabereihenfolge: `amendment_b`
    // steht vorn und traegt die HOEHERE Sequenz.
    assert_eq!(
        thread
            .amendments()
            .iter()
            .map(|a| a.chain_sequence())
            .collect::<Vec<_>>(),
        vec![ChainSequence::new(7), ChainSequence::new(9)]
    );
    // Das Original bleibt vollstaendig sichtbar: dieselben Bytes, derselbe
    // Eintragshash, kein Kennzeichen `ueberholt` und keine Verdeckung.
    thread
        .original()
        .with_plaintext(|bytes| assert_eq!(bytes, fixtures::original_plaintext()));
    assert!(thread.original().entry_hash() == fixtures::original_entry_hash());
    for amendment in thread.amendments() {
        assert!(amendment.entry_hash() != thread.original().entry_hash());
        assert!(amendment.with_payload(|payload| matches!(payload, PayloadV1::Amendment(_))));
        assert!(amendment.with_plaintext(|bytes| !bytes.is_empty()));
    }

    // Die Korrekturreferenz ist klartextfrei und traegt GENAU drei Felder. Das
    // erschoepfende Strukturliteral ist die Zusicherung: ein viertes Feld
    // uebersetzt hier nicht mehr, und die Einsatznummer waere genau dieses
    // vierte Feld.
    assert!(
        thread.correction_reference()
            == CorrectionReference {
                original_record_id: fixtures::original_record_id(),
                original_sequence: ChainSequence::new(4),
                original_entry_hash: fixtures::original_entry_hash(),
            }
    );
}

#[test]
fn a_mismatched_reference_stays_a_verification_problem_instead_of_joining() {
    for (candidate, reason) in [
        (
            fixtures::amendment_with_foreign_record_id(),
            AmendmentJoinErrorV1::OriginalRecordIdMismatch,
        ),
        (
            fixtures::amendment_with_flipped_entry_hash(),
            AmendmentJoinErrorV1::OriginalEntryHashMismatch,
        ),
        (
            fixtures::amendment_with_wrong_sequence(),
            AmendmentJoinErrorV1::OriginalSequenceMismatch,
        ),
        (
            fixtures::amendment_with_other_incident_number(),
            AmendmentJoinErrorV1::IncidentNumberMismatch,
        ),
        (
            fixtures::an_incident_record(),
            AmendmentJoinErrorV1::NotAnAmendment,
        ),
    ] {
        let candidate_entry_hash = candidate.entry_hash();
        let candidate_sequence = candidate.chain_sequence();
        let thread = ReaderEntryThread::build(fixtures::original(), vec![candidate])
            .expect("ein einzelner kaputter Nachtrag nimmt den Faden nicht");
        assert!(
            thread.amendments().is_empty(),
            "{reason:?} must not join the thread"
        );
        assert_eq!(thread.rejected().len(), 1);
        assert_eq!(thread.rejected()[0].reason, reason);
        // Ein abgewiesener Nachtrag ist ein PRUEFPROBLEM, kein leerer Einsatz und
        // keine Luecke: er behaelt seinen Eintragshash und seinen Status.
        assert_eq!(thread.rejected()[0].status, VerificationStatus::Invalid);
        // Und er behaelt seine ADRESSE: `RejectedAmendment` traegt genau die
        // beiden Spalten, unter denen die Oberflaeche ihn wiederfindet. Ein
        // Objekt ohne Adresse waere von einem fehlenden nicht zu unterscheiden
        // — und genau das ist der Unterschied zwischen Pruefproblem und Luecke.
        let rejected: &RejectedAmendment = &thread.rejected()[0];
        assert!(rejected.entry_hash == candidate_entry_hash);
        assert_eq!(rejected.chain_sequence, candidate_sequence);
        // Und er aendert am Original nichts.
        assert!(thread.original().entry_hash() == fixtures::original_entry_hash());
        // Auch nicht an dessen Bytes und dessen Sichtbarkeit: der Faden zeigt
        // den Einsatz weiterhin als Einsatz, mit derselben Einsatznummer.
        thread
            .original()
            .with_plaintext(|bytes| assert_eq!(bytes, fixtures::original_plaintext()));
        thread.original().with_payload(|payload| {
            let PayloadV1::Incident(incident) = payload else {
                panic!("a rejected amendment never turns the original into something else")
            };
            assert_eq!(incident.human_incident_number(), "2026-0001");
        });
    }
}

#[test]
fn the_thread_refuses_an_original_that_is_not_an_incident_and_a_duplicate_sequence() {
    let Err(refused) = ReaderEntryThread::build(fixtures::a_genesis_record(), Vec::new()) else {
        panic!("ein Genesis-Datensatz traegt keine Einsatznummer und ist kein Original")
    };
    assert_eq!(refused, AmendmentJoinErrorV1::NotAnIncident);
    // Zwei Nachtraege auf DERSELBEN Kettensequenz. Welcher von beiden bleibt,
    // darf nicht die Eingabereihenfolge entscheiden: bei gleicher Sequenz
    // traegt die Ordnung nur noch der zweite Schluessel, der Eintragshash, und
    // die Zusage des Plans lautet „der erste in Sequenzordnung bleibt". Ein
    // Zeuge, der nur `amendments().len() == 1` und den Grund misst, bestuende
    // auch gegen eine Projektion, die die Eingabe durchreicht — deshalb stehen
    // hier BEIDE Adressen fest, bevor die Datensaetze in den Faden wandern.
    let first = fixtures::amendment_a();
    let second = fixtures::amendment_a_again_at_the_same_sequence();
    assert_eq!(first.chain_sequence(), second.chain_sequence());
    let (kept, dropped) = if first.entry_hash() < second.entry_hash() {
        (first.entry_hash(), second.entry_hash())
    } else {
        (second.entry_hash(), first.entry_hash())
    };

    let thread = ReaderEntryThread::build(fixtures::original(), vec![first, second])
        .expect("ein Einsatz ist ein taugliches Original");
    assert_eq!(thread.amendments().len(), 1);
    assert!(thread.amendments()[0].entry_hash() == kept);
    assert_eq!(thread.rejected().len(), 1);
    assert_eq!(
        thread.rejected()[0].reason,
        AmendmentJoinErrorV1::DuplicateSequence
    );
    assert!(thread.rejected()[0].entry_hash == dropped);
    assert_eq!(thread.rejected()[0].status, VerificationStatus::Invalid);

    // Und in der Gegenrichtung faellt dieselbe Entscheidung.
    let reversed = ReaderEntryThread::build(
        fixtures::original(),
        vec![
            fixtures::amendment_a_again_at_the_same_sequence(),
            fixtures::amendment_a(),
        ],
    )
    .expect("dieselben Datensaetze in der Gegenrichtung");
    assert!(reversed.amendments()[0].entry_hash() == kept);
    assert!(reversed.rejected()[0].entry_hash == dropped);

    // Und auch dieser Fall nimmt dem Original nichts. Der Plan sagt den
    // Rueckhalt fuer JEDEN Abweisungsfall zu, und die doppelte Sequenz ist der
    // einzige, in dem die Abweisung nicht aus der Referenz des Kandidaten
    // folgt, sondern aus einem Widerspruch ZWISCHEN zwei Kandidaten - genau
    // der Fall, in dem eine Projektion in Versuchung geraete, den Faden neu zu
    // rechnen.
    assert!(thread.original().entry_hash() == fixtures::original_entry_hash());
    thread
        .original()
        .with_plaintext(|bytes| assert_eq!(bytes, fixtures::original_plaintext()));
    thread.original().with_payload(|payload| {
        let PayloadV1::Incident(incident) = payload else {
            panic!("a duplicate amendment never turns the original into something else")
        };
        assert_eq!(incident.human_incident_number(), "2026-0001");
    });
}

/// Die Eingabereihenfolge erreicht die Ausgabe NICHT.
///
/// Der erste Zeuge faehrt `[b, a]` und misst die Sortierung gegen eine feste
/// Erwartung; das allein sagt noch nicht, dass `[a, b]` dasselbe liefert.
/// Dieser Lauf haelt deshalb ZWEI Faeden derselben Datensaetze in beiden
/// Richtungen gegeneinander: Eintragshashe, Sequenzen, Abweisungen und die
/// Korrekturreferenz muessen Wert fuer Wert uebereinstimmen. Er deckt den
/// KOLLISIONSFREIEN Fall ab; den Gleichstand auf EINER Sequenz misst
/// `the_thread_refuses_an_original_that_is_not_an_incident_and_a_duplicate_sequence`,
/// der dieselben zwei Richtungen ueber die Zwillinge faehrt.
///
/// Der Abrufweg entscheidet die Eingabereihenfolge — Cache, Sync-Batch und
/// Dateimodus liefern in verschiedenen Ordnungen —, und eine Anzeige, die
/// davon abhaengt, waere fuer denselben Bestand zweimal verschieden.
///
/// # ANTI-LEERLAUF
///
/// Die Laengenzusicherung steht gegen die feste ZWEI und nicht gegen die
/// jeweils andere Ausgabe: zwei LEERE Faeden stimmen ebenfalls Wert fuer Wert
/// ueberein, und die Schleife darunter liefe dann null Mal. Eine Projektion,
/// die jeden Kandidaten still verwuerfe, bestuende diesen Zeugen sonst —
/// GEMESSEN, nicht vermutet.
#[test]
fn the_input_order_of_the_amendments_never_reaches_the_output() {
    let forward = ReaderEntryThread::build(
        fixtures::original(),
        vec![fixtures::amendment_a(), fixtures::amendment_b()],
    )
    .expect("ein Einsatz ist ein taugliches Original");
    let reversed = ReaderEntryThread::build(
        fixtures::original(),
        vec![fixtures::amendment_b(), fixtures::amendment_a()],
    )
    .expect("dieselben Datensaetze in der Gegenrichtung");

    assert_eq!(forward.amendments().len(), 2);
    assert_eq!(reversed.amendments().len(), 2);
    for (left, right) in forward.amendments().iter().zip(reversed.amendments()) {
        assert!(left.entry_hash() == right.entry_hash());
        assert_eq!(left.chain_sequence(), right.chain_sequence());
        assert!(left.with_plaintext(|bytes| right.with_plaintext(|other| bytes == other)));
    }
    assert!(forward.rejected().is_empty());
    assert!(reversed.rejected().is_empty());
    assert!(forward.correction_reference() == reversed.correction_reference());
    assert!(forward.original().entry_hash() == reversed.original().entry_hash());
}
