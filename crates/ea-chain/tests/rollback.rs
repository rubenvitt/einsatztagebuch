//! Rollback ist NUR gegen Checkpoint-Aussagen pruefbar.
//!
//! Ohne eine signierte Serveraussage ueber einen frueheren Kopf gibt es keine
//! Referenz, gegen die ein Rueckbau erkennbar waere. Fuer ein Archiv ohne `.ecp`
//! muss das Ergebnis deshalb ausdruecklich NICHT PRUEFBAR sein — niemals
//! "kein Rollback". Der Test deckt alle Ausgaenge in einem Fall ab, samt der
//! beiden Wege, auf denen ein Bestand die bezeugte Sequenz verfehlt.

use ea_chain::{
    ChainNode, ChainNodeKind, CheckpointClaim, RollbackAssessment, RollbackFinding,
    assess_rollback, build_chain,
};
use ea_types::{CertificateHash, ChainId, ChainSequence, EntryHash, ObjectHash};

fn chain_id(seed: u8) -> ChainId {
    ChainId::try_from([seed; 16].as_slice()).expect("chain id from 16 bytes")
}

fn entry_hash(seed: u8) -> EntryHash {
    EntryHash::try_from([seed; 32].as_slice()).expect("entry hash from 32 bytes")
}

fn object_hash(seed: u8) -> ObjectHash {
    ObjectHash::try_from([seed; 32].as_slice()).expect("object hash from 32 bytes")
}

fn node(chain: ChainId, sequence: u64, previous: Option<u8>, entry: u8, object: u8) -> ChainNode {
    ChainNode {
        chain_id: chain,
        chain_sequence: ChainSequence::new(sequence),
        previous_entry_hash: previous.map(entry_hash),
        entry_hash: entry_hash(entry),
        object_hash: object_hash(object),
        writer_certificate_hash: CertificateHash::try_from([200_u8; 32].as_slice())
            .expect("certificate hash from 32 bytes"),
        writer_transition_event_hash: None,
        kind: ChainNodeKind::EntryPackage,
    }
}

fn claim(
    chain: ChainId,
    from: u64,
    through: u64,
    head_entry: u8,
    checkpoint_object: u8,
) -> CheckpointClaim {
    CheckpointClaim {
        chain_id: chain,
        covered_from_sequence: ChainSequence::new(from),
        covered_through_sequence: ChainSequence::new(through),
        head_entry_hash: entry_hash(head_entry),
        checkpoint_object_hash: object_hash(checkpoint_object),
    }
}

#[test]
fn an_archive_without_checkpoints_cannot_assess_rollback_at_all() {
    let chain = chain_id(1);
    let nodes = [
        node(chain, 0, None, 10, 20),
        node(chain, 1, Some(10), 11, 21),
        node(chain, 2, Some(11), 12, 22),
        node(chain, 3, Some(12), 13, 23),
    ];
    let verified = build_chain(chain, &nodes).expect("intact four node chain");
    assert_eq!(
        verified
            .verified_head()
            .expect("verified head of an intact chain")
            .chain_sequence(),
        ChainSequence::new(3),
        "{verified:?}"
    );

    // Ausgang 1: keine Checkpoint-Aussage, also keine Referenz. Die Kette ist
    // makellos — trotzdem darf hier NIE "kein Rollback" behauptet werden.
    assert_eq!(
        assess_rollback(&verified, &[]),
        RollbackAssessment::NotAssessable,
        "{verified:?}"
    );

    // Ausgang 2: eine Aussage ueber eine FREMDE Kette ist keine Aussage ueber
    // diese. Nach der Filterung bleibt nichts uebrig — wieder nicht pruefbar.
    let foreign = claim(chain_id(2), 0, 5, 99, 60);
    assert_eq!(
        assess_rollback(&verified, &[foreign]),
        RollbackAssessment::NotAssessable,
        "{verified:?}"
    );

    // Ausgang 3: Der Server hat Sequenz 5 nachweislich gesehen, der Bestand
    // reicht nur bis 3. Das ist eine BEWIESENE Luecke 4..=5.
    let truncating = claim(chain, 0, 5, 99, 61);
    let truncated = assess_rollback(&verified, &[foreign, truncating]);
    let RollbackAssessment::Rollback(findings) = &truncated else {
        panic!("checkpoint above the verified head is a rollback: {truncated:?}");
    };
    assert_eq!(findings.len(), 1, "{truncated:?}");
    assert_eq!(
        findings[0],
        RollbackFinding::TruncatedBelowCheckpoint {
            covered_through_sequence: ChainSequence::new(5),
            verified_head_sequence: Some(ChainSequence::new(3)),
            checkpoint_object_hash: object_hash(61),
        },
        "{truncated:?}"
    );
    assert_eq!(
        findings[0].proven_missing_sequences(),
        Some((ChainSequence::new(4), ChainSequence::new(5))),
        "{truncated:?}"
    );

    // Ausgang 4: Die bezeugte Sequenz existiert, traegt aber einen anderen
    // Kopf-Eintragshash. Das strittige Objekt ist benennbar.
    let mismatching = claim(chain, 0, 3, 88, 62);
    let mismatch = assess_rollback(&verified, &[mismatching]);
    let RollbackAssessment::Rollback(findings) = &mismatch else {
        panic!("a differing head entry hash is a rollback: {mismatch:?}");
    };
    assert_eq!(findings.len(), 1, "{mismatch:?}");
    assert_eq!(
        findings[0],
        RollbackFinding::HeadEntryHashMismatch {
            sequence: ChainSequence::new(3),
            checkpoint_head_entry_hash: entry_hash(88),
            chain_entry_hash: entry_hash(13),
            checkpoint_object_hash: object_hash(62),
            conflicting_object_hash: object_hash(23),
        },
        "{mismatch:?}"
    );
    assert_eq!(
        findings[0].proven_missing_sequences(),
        None,
        "eine Kopfabweichung beweist keine Luecke: {mismatch:?}"
    );

    // Ausgang 5: passende Aussage. Erst hier — und nur nach einem positiven
    // Abgleich gegen einen Knoten des verifizierten Praefixes — ist
    // "kein Rollback" zulaessig.
    let matching = claim(chain, 0, 3, 13, 63);
    assert_eq!(
        assess_rollback(&verified, &[matching]),
        RollbackAssessment::Consistent,
        "{verified:?}"
    );

    // Die Ausgaenge sind unterscheidbar: Truncation und Kopfabweichung sind
    // nicht derselbe Befund.
    assert_ne!(truncated, mismatch);

    // Der vollstaendig geleerte Bestand: kein Knoten, also kein `head()` und
    // kein verifizierter Kopf. Genau deshalb merkt sich `VerifiedChain` die
    // gepruefte Kette selbst — ohne das waere die Aussage keiner Kette
    // zuzuordnen und die Totalloeschung waere "nicht pruefbar" statt Rollback.
    let emptied = build_chain(chain, &[]).expect("an empty chain is a valid input");
    assert_eq!(emptied.verified_head(), None, "{emptied:?}");
    let erased = assess_rollback(&emptied, &[foreign, claim(chain, 0, 5, 99, 64)]);
    let RollbackAssessment::Rollback(findings) = &erased else {
        panic!("a checkpoint over an emptied archive is a rollback: {erased:?}");
    };
    assert_eq!(findings.len(), 1, "{erased:?}");
    assert_eq!(
        findings[0],
        RollbackFinding::TruncatedBelowCheckpoint {
            covered_through_sequence: ChainSequence::new(5),
            verified_head_sequence: None,
            checkpoint_object_hash: object_hash(64),
        },
        "{erased:?}"
    );
    assert_eq!(
        findings[0].proven_missing_sequences(),
        Some((ChainSequence::new(0), ChainSequence::new(5))),
        "ohne verifizierten Kopf beginnt die bewiesene Luecke bei 0: {erased:?}"
    );

    // Unten abgeschnittener Bestand: die bezeugte Sequenz 1 fehlt, obwohl der
    // verifizierte Kopf mit 3 DARUEBER liegt. Die Zahlenpruefung allein wuerde
    // hier auf `Consistent` durchfallen; erst der fehlgeschlagene Knotenzugriff
    // macht den Rueckbau sichtbar.
    let beheaded = build_chain(
        chain,
        &[
            node(chain, 2, Some(11), 12, 22),
            node(chain, 3, Some(12), 13, 23),
        ],
    )
    .expect("a chain starting above genesis is a valid input");
    assert_eq!(
        beheaded
            .verified_head()
            .expect("verified head above the missing prefix")
            .chain_sequence(),
        ChainSequence::new(3),
        "{beheaded:?}"
    );
    let bottom = assess_rollback(&beheaded, &[claim(chain, 0, 1, 11, 65)]);
    let RollbackAssessment::Rollback(findings) = &bottom else {
        panic!("a checkpoint over a removed prefix is a rollback: {bottom:?}");
    };
    assert_eq!(findings.len(), 1, "{bottom:?}");
    assert_eq!(
        findings[0],
        RollbackFinding::TruncatedBelowCheckpoint {
            covered_through_sequence: ChainSequence::new(1),
            verified_head_sequence: Some(ChainSequence::new(3)),
            checkpoint_object_hash: object_hash(65),
        },
        "{bottom:?}"
    );
    assert_eq!(
        findings[0].proven_missing_sequences(),
        None,
        "unterhalb des Kopfes folgt kein Intervall, die Luecke steht in gaps: {bottom:?}"
    );
}
