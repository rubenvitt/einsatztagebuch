//! Wertbasierte Kernpruefung der Kettenverkettung.
//!
//! Der Test kennt weder Fixtures noch Signaturen: `ea-chain` arbeitet
//! ausschliesslich auf `ChainNode`-Werten. Fehler werden ueber
//! `ChainError::code()` assertiert, nie ueber ihre Formatierung.

use ea_chain::{ChainError, ChainNode, ChainNodeKind, build_chain};
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

fn certificate_hash(seed: u8) -> CertificateHash {
    CertificateHash::try_from([seed; 32].as_slice()).expect("certificate hash from 32 bytes")
}

fn node(
    chain: ChainId,
    sequence: u64,
    previous: Option<u8>,
    entry: u8,
    object: u8,
    kind: ChainNodeKind,
) -> ChainNode {
    ChainNode {
        chain_id: chain,
        chain_sequence: ChainSequence::new(sequence),
        previous_entry_hash: previous.map(entry_hash),
        entry_hash: entry_hash(entry),
        object_hash: object_hash(object),
        writer_certificate_hash: certificate_hash(200),
        writer_transition_event_hash: None,
        kind,
    }
}

#[test]
fn genesis_is_sequence_zero_and_each_successor_binds_its_predecessor() {
    let chain = chain_id(1);
    let genesis = node(chain, 0, None, 10, 20, ChainNodeKind::EntryPackage);
    let second = node(chain, 1, Some(10), 11, 21, ChainNodeKind::EntryPackage);
    let third = ChainNode {
        writer_transition_event_hash: Some(object_hash(70)),
        ..node(chain, 2, Some(11), 12, 22, ChainNodeKind::DestroyedStub)
    };

    // Gueltige Dreierkette: Eingabereihenfolge ist gleichgueltig, die
    // Ausgabereihenfolge ist deterministisch nach (Sequenz, entry_hash).
    let verified = build_chain(chain, &[third, genesis, second]).expect("valid three node chain");
    assert_eq!(verified.nodes(), [genesis, second, third].as_slice());
    assert!(verified.breaks().is_empty(), "{verified:?}");

    let head = verified.head().expect("head of a non-empty chain");
    assert_eq!(head.chain_id().as_bytes(), chain.as_bytes());
    assert_eq!(head.chain_sequence(), ChainSequence::new(2));
    assert_eq!(head.entry_hash().as_bytes(), entry_hash(12).as_bytes());

    let verified_head = verified
        .verified_head()
        .expect("verified head of an intact chain");
    assert_eq!(verified_head.chain_sequence(), ChainSequence::new(2));
    assert_eq!(
        verified_head.entry_hash().as_bytes(),
        entry_hash(12).as_bytes()
    );

    // Genesis mit Vorgaengerhash ist ein Eingabefehler des Aufrufers.
    let bound_genesis = node(chain, 0, Some(9), 10, 20, ChainNodeKind::EntryPackage);
    assert_eq!(
        build_chain(chain, &[bound_genesis])
            .expect_err("genesis must not carry a previous entry hash")
            .code(),
        "EA-CHAIN-GENESIS-BINDING"
    );

    // Sequenz > 0 ohne Vorgaengerhash ebenso.
    let unbound_successor = node(chain, 1, None, 11, 21, ChainNodeKind::EntryPackage);
    assert_eq!(
        build_chain(chain, &[genesis, unbound_successor])
            .expect_err("a successor must carry a previous entry hash")
            .code(),
        "EA-CHAIN-GENESIS-BINDING"
    );

    // Ein Knoten aus einer fremden Kette ebenso.
    assert_eq!(
        build_chain(chain_id(2), &[genesis])
            .expect_err("nodes of a foreign chain are rejected")
            .code(),
        "EA-CHAIN-FOREIGN-CHAIN-ID"
    );

    // Ein Vorgaengerhash-Bruch bei Sequenz 2 ist dagegen ein BEFUND ueber den
    // Bestand: Ok mit Diagnose, kein Err.
    let broken_third = node(chain, 2, Some(99), 12, 22, ChainNodeKind::EntryPackage);
    let broken = build_chain(chain, &[genesis, second, broken_third])
        .expect("a break is a finding, not Err");
    assert_eq!(broken.breaks().len(), 1, "{broken:?}");

    let chain_break = &broken.breaks()[0];
    assert_eq!(chain_break.sequence(), ChainSequence::new(2));
    assert_eq!(
        chain_break.expected_previous_entry_hash().as_bytes(),
        entry_hash(11).as_bytes()
    );
    assert_eq!(
        chain_break.actual_previous_entry_hash().as_bytes(),
        entry_hash(99).as_bytes()
    );
    assert_eq!(
        chain_break.object_hash().as_bytes(),
        object_hash(22).as_bytes()
    );

    // head() bleibt die hoechste gesehene Sequenz, verified_head() haelt vor
    // der ersten gebrochenen Sequenz an.
    assert_eq!(
        broken.head().expect("head").chain_sequence(),
        ChainSequence::new(2)
    );
    let broken_verified_head = broken
        .verified_head()
        .expect("verified head before the break");
    assert_eq!(broken_verified_head.chain_sequence(), ChainSequence::new(1));
    assert_eq!(
        broken_verified_head.entry_hash().as_bytes(),
        entry_hash(11).as_bytes()
    );

    // Der Sortierschluessel ist total: zwei Knoten mit gleicher Sequenz und
    // gleichem Eintragshash trennt der object_hash, sodass die Reihenfolge
    // nicht von der Eingabereihenfolge abhaengt.
    let twin_low = node(chain, 1, Some(10), 11, 21, ChainNodeKind::EntryPackage);
    let twin_high = node(chain, 1, Some(10), 11, 22, ChainNodeKind::DestroyedStub);
    let one_way = build_chain(chain, &[genesis, twin_low, twin_high]).expect("tied nodes");
    let other_way = build_chain(chain, &[twin_high, twin_low, genesis]).expect("tied nodes");
    assert_eq!(one_way.nodes(), other_way.nodes());
    assert_eq!(one_way.nodes(), [genesis, twin_low, twin_high].as_slice());

    // Der dritte stabile Code gehoert zum Vertrag, auch ohne Fixture in
    // Grenzgroesse.
    assert_eq!(ChainError::NodeLimit.code(), "EA-CHAIN-NODE-LIMIT");
}
