//! Wertbasierte Kernpruefung der Kettenverkettung.
//!
//! Der Test kennt weder Fixtures noch Signaturen: `ea-chain` arbeitet
//! ausschliesslich auf `ChainNode`-Werten. Fehler werden ueber
//! `ChainError::code()` assertiert, nie ueber ihre Formatierung.

use ea_chain::{ChainError, ChainForkForm, ChainNode, ChainNodeKind, build_chain};
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

#[test]
fn missing_sequences_collapse_into_maximal_intervals_and_a_stub_fills_its_own() {
    let chain = chain_id(1);

    // 1. Fehlen 3, 4 und 5, ist das GENAU EIN Intervall 3..=5, nicht drei.
    //    Oberhalb der hoechsten gesehenen Sequenz gibt es keine Luecke, weil
    //    ueber nicht existierende Fortsetzungen keine Aussage moeglich ist.
    let with_hole = build_chain(
        chain,
        &[
            node(chain, 0, None, 10, 20, ChainNodeKind::EntryPackage),
            node(chain, 1, Some(10), 11, 21, ChainNodeKind::EntryPackage),
            node(chain, 2, Some(11), 12, 22, ChainNodeKind::EntryPackage),
            node(chain, 6, Some(15), 16, 26, ChainNodeKind::EntryPackage),
            node(chain, 7, Some(16), 17, 27, ChainNodeKind::EntryPackage),
        ],
    )
    .expect("a gap is a finding, not Err");
    assert!(with_hole.breaks().is_empty(), "{with_hole:?}");
    assert_eq!(with_hole.gaps().len(), 1, "{with_hole:?}");
    assert_eq!(
        with_hole.gaps()[0].chain_id().as_bytes(),
        chain.as_bytes(),
        "{with_hole:?}"
    );
    assert_eq!(
        with_hole.gaps()[0].from_sequence(),
        ChainSequence::new(3),
        "{with_hole:?}"
    );
    assert_eq!(
        with_hole.gaps()[0].through_sequence(),
        ChainSequence::new(5),
        "{with_hole:?}"
    );
    assert!(!with_hole.is_fully_verified(), "{with_hole:?}");

    // 2. Fehlt Genesis bei vorhandener Sequenz 1, ist das ein ChainGap 0..=0.
    //    Ein Bruch ist das nicht — die Vorgaengerbindung aller vorhandenen
    //    Knoten geht auf —, aber verifiziert ist die Kette dennoch nicht.
    let without_genesis = build_chain(
        chain,
        &[
            node(chain, 1, Some(10), 11, 21, ChainNodeKind::EntryPackage),
            node(chain, 2, Some(11), 12, 22, ChainNodeKind::EntryPackage),
        ],
    )
    .expect("a missing genesis is a finding, not Err");
    assert!(without_genesis.breaks().is_empty(), "{without_genesis:?}");
    assert_eq!(without_genesis.gaps().len(), 1, "{without_genesis:?}");
    assert_eq!(
        without_genesis.gaps()[0].from_sequence(),
        ChainSequence::new(0),
        "{without_genesis:?}"
    );
    assert_eq!(
        without_genesis.gaps()[0].through_sequence(),
        ChainSequence::new(0),
        "{without_genesis:?}"
    );
    assert!(!without_genesis.is_fully_verified(), "{without_genesis:?}");

    // 3. Ein DestroyedStub BESETZT seine Sequenz vollstaendig: er ist kein
    //    Loch, sondern ein Kettenglied mit derselben Kettenidentitaet. Er
    //    bindet seinen Vorgaenger wie ein Eintragspaket und wird vom
    //    Nachfolger genauso gebunden.
    let with_stub = build_chain(
        chain,
        &[
            node(chain, 0, None, 10, 20, ChainNodeKind::EntryPackage),
            node(chain, 1, Some(10), 11, 21, ChainNodeKind::EntryPackage),
            node(chain, 2, Some(11), 12, 22, ChainNodeKind::DestroyedStub),
            node(chain, 3, Some(12), 13, 23, ChainNodeKind::EntryPackage),
        ],
    )
    .expect("a stub chain is a valid chain");
    assert!(with_stub.gaps().is_empty(), "{with_stub:?}");
    assert!(with_stub.breaks().is_empty(), "{with_stub:?}");
    assert!(with_stub.is_fully_verified(), "{with_stub:?}");
    assert_eq!(
        with_stub
            .verified_head()
            .expect("verified head of an intact chain")
            .chain_sequence(),
        ChainSequence::new(3),
        "{with_stub:?}"
    );

    // 4. Zwei Knoten auf derselben Sequenz sind kein Loch. Der zweite besetzt
    //    dieselbe, bereits besetzte Sequenz — er darf keine Luecke erzeugen.
    let twins = build_chain(
        chain,
        &[
            node(chain, 0, None, 10, 20, ChainNodeKind::EntryPackage),
            node(chain, 1, Some(10), 11, 21, ChainNodeKind::EntryPackage),
            node(chain, 1, Some(10), 11, 22, ChainNodeKind::DestroyedStub),
        ],
    )
    .expect("tied nodes");
    assert!(twins.gaps().is_empty(), "{twins:?}");

    // 5. ChainSequence ist u64. Ein Knoten bei u64::MAX darf weder panisch
    //    werden noch ueberlaufen: unterhalb liegt genau ein Intervall, und
    //    oberhalb gibt es keine Fortsetzung, ueber die etwas auszusagen waere.
    let at_ceiling = build_chain(
        chain,
        &[node(
            chain,
            u64::MAX,
            Some(30),
            31,
            32,
            ChainNodeKind::EntryPackage,
        )],
    )
    .expect("a node at u64::MAX is a finding, not a panic");
    assert_eq!(at_ceiling.gaps().len(), 1, "{at_ceiling:?}");
    assert_eq!(
        at_ceiling.gaps()[0].from_sequence(),
        ChainSequence::new(0),
        "{at_ceiling:?}"
    );
    assert_eq!(
        at_ceiling.gaps()[0].through_sequence(),
        ChainSequence::new(u64::MAX - 1),
        "{at_ceiling:?}"
    );

    // Und ein lueckenloses Paar direkt unter der Decke ebenso wenig.
    let below_ceiling = build_chain(
        chain,
        &[
            node(
                chain,
                u64::MAX - 1,
                Some(30),
                31,
                32,
                ChainNodeKind::EntryPackage,
            ),
            node(
                chain,
                u64::MAX,
                Some(31),
                33,
                34,
                ChainNodeKind::EntryPackage,
            ),
        ],
    )
    .expect("a pair at the ceiling is a finding, not a panic");
    assert_eq!(below_ceiling.gaps().len(), 1, "{below_ceiling:?}");
    assert_eq!(
        below_ceiling.gaps()[0].through_sequence(),
        ChainSequence::new(u64::MAX - 2),
        "{below_ceiling:?}"
    );
    assert!(below_ceiling.breaks().is_empty(), "{below_ceiling:?}");

    // Zwei Knoten auf u64::MAX: der Cursor kann nicht weiterzaehlen und darf
    // deshalb weder ueberlaufen noch dieselbe Luecke ein zweites Mal melden.
    let twins_at_ceiling = build_chain(
        chain,
        &[
            node(
                chain,
                u64::MAX,
                Some(30),
                31,
                32,
                ChainNodeKind::EntryPackage,
            ),
            node(
                chain,
                u64::MAX,
                Some(30),
                31,
                33,
                ChainNodeKind::DestroyedStub,
            ),
        ],
    )
    .expect("tied nodes at the ceiling are a finding, not a panic");
    assert_eq!(twins_at_ceiling.gaps().len(), 1, "{twins_at_ceiling:?}");
    assert_eq!(
        twins_at_ceiling.gaps()[0].through_sequence(),
        ChainSequence::new(u64::MAX - 1),
        "{twins_at_ceiling:?}"
    );
}

#[test]
fn both_collision_forms_yield_a_fork_and_stop_the_verified_head() {
    let chain = chain_id(1);

    // Eine lueckenlose Kette 0..4 als Boden beider Haelften.
    let base = [
        node(chain, 0, None, 10, 20, ChainNodeKind::EntryPackage),
        node(chain, 1, Some(10), 11, 21, ChainNodeKind::EntryPackage),
        node(chain, 2, Some(11), 12, 22, ChainNodeKind::EntryPackage),
        node(chain, 3, Some(12), 13, 23, ChainNodeKind::EntryPackage),
        node(chain, 4, Some(13), 14, 24, ChainNodeKind::EntryPackage),
    ];

    // 1. SequenceCollision: ein zweites Kind desselben Vorgaengers besetzt
    //    Sequenz 2. Ein Fork ist ein BEFUND ueber den Bestand, kein Err — ein
    //    Err koennte das unstrittige Praefix nicht mitfuehren.
    let mut sequence_input = base.to_vec();
    sequence_input.push(node(
        chain,
        2,
        Some(11),
        40,
        40,
        ChainNodeKind::EntryPackage,
    ));
    let forked = build_chain(chain, &sequence_input).expect("a fork is a finding, not Err");

    assert_eq!(forked.forks().len(), 1, "{forked:?}");
    let fork = &forked.forks()[0];
    assert_eq!(fork.form(), ChainForkForm::SequenceCollision, "{forked:?}");
    assert_eq!(fork.chain_id().as_bytes(), chain.as_bytes(), "{forked:?}");
    assert_eq!(fork.sequence(), ChainSequence::new(2), "{forked:?}");
    assert_eq!(
        fork.competing_entry_hashes()[0].as_bytes(),
        entry_hash(12).as_bytes(),
        "{forked:?}"
    );
    assert_eq!(
        fork.competing_entry_hashes()[1].as_bytes(),
        entry_hash(40).as_bytes(),
        "{forked:?}"
    );
    assert_eq!(
        fork.competing_object_hashes()[0].as_bytes(),
        object_hash(22).as_bytes(),
        "{forked:?}"
    );
    assert_eq!(
        fork.competing_object_hashes()[1].as_bytes(),
        object_hash(40).as_bytes(),
        "{forked:?}"
    );

    // Der Fork erzeugt KEINEN Bruch: Sequenz 3 bindet mit entry_hash(12) einen
    // real vorhandenen Vorgaenger. Ein Phantombruch waere kein Schoenheitsfehler,
    // sondern quarantaeniert in Task 16 das unschuldige Objekt der Sequenz 3.
    assert!(forked.breaks().is_empty(), "{forked:?}");
    assert!(forked.gaps().is_empty(), "{forked:?}");

    // head() bleibt die hoechste gesehene Sequenz, verified_head() haelt vor
    // der Forksequenz an.
    assert_eq!(
        forked.head().expect("head").chain_sequence(),
        ChainSequence::new(4),
        "{forked:?}"
    );
    let verified_head = forked
        .verified_head()
        .expect("verified head before the fork");
    assert_eq!(
        verified_head.chain_sequence(),
        ChainSequence::new(1),
        "{forked:?}"
    );
    assert_eq!(
        verified_head.entry_hash().as_bytes(),
        entry_hash(11).as_bytes(),
        "{forked:?}"
    );
    assert!(!forked.is_fully_verified(), "{forked:?}");

    // Die Eingabereihenfolge aendert den Befund nicht — in voller Wertgleichheit
    // belegt, nicht nur in der Anzahl.
    let mut reversed = sequence_input.clone();
    reversed.reverse();
    assert_eq!(
        build_chain(chain, &reversed).expect("a fork is a finding, not Err"),
        forked
    );

    // 2. PredecessorCollision: zwei Knoten VERSCHIEDENER Sequenz beanspruchen
    //    denselben Vorgaenger. Die Erkennung haengt am Vorgaengerhash, nicht an
    //    der Sequenz.
    let mut predecessor_input = base.to_vec();
    predecessor_input.push(node(
        chain,
        5,
        Some(13),
        15,
        35,
        ChainNodeKind::EntryPackage,
    ));
    let branched = build_chain(chain, &predecessor_input).expect("a fork is a finding, not Err");

    assert_eq!(branched.forks().len(), 1, "{branched:?}");
    let branch = &branched.forks()[0];
    assert_eq!(
        branch.form(),
        ChainForkForm::PredecessorCollision,
        "{branched:?}"
    );
    // Die Forksequenz ist die kleinere der beiden strittigen Sequenzen: dort
    // wird die Kettenidentitaet zum ersten Mal mehrdeutig.
    assert_eq!(branch.sequence(), ChainSequence::new(4), "{branched:?}");
    assert_eq!(
        branch.competing_entry_hashes()[0].as_bytes(),
        entry_hash(14).as_bytes(),
        "{branched:?}"
    );
    assert_eq!(
        branch.competing_entry_hashes()[1].as_bytes(),
        entry_hash(15).as_bytes(),
        "{branched:?}"
    );
    assert_eq!(
        branch.competing_object_hashes()[0].as_bytes(),
        object_hash(24).as_bytes(),
        "{branched:?}"
    );
    assert_eq!(
        branch.competing_object_hashes()[1].as_bytes(),
        object_hash(35).as_bytes(),
        "{branched:?}"
    );

    // Der Knoten auf Sequenz 5 bindet entry_hash(13) statt des Kopfes von
    // Sequenz 4 — das ist ein echter Bruch, kein Phantom.
    assert_eq!(branched.breaks().len(), 1, "{branched:?}");
    assert_eq!(
        branched.breaks()[0].sequence(),
        ChainSequence::new(5),
        "{branched:?}"
    );

    assert_eq!(
        branched.head().expect("head").chain_sequence(),
        ChainSequence::new(5),
        "{branched:?}"
    );
    assert_eq!(
        branched
            .verified_head()
            .expect("verified head before the fork")
            .chain_sequence(),
        ChainSequence::new(3),
        "{branched:?}"
    );
    assert!(!branched.is_fully_verified(), "{branched:?}");

    let mut reversed_branch = predecessor_input.clone();
    reversed_branch.reverse();
    assert_eq!(
        build_chain(chain, &reversed_branch).expect("a fork is a finding, not Err"),
        branched
    );

    // 3. Ein Fork auf der niedrigsten Sequenz laesst gar kein unstrittiges
    //    Praefix uebrig: verified_head() ist dann None, nicht der Forkknoten.
    let split_genesis = build_chain(
        chain,
        &[
            node(chain, 0, None, 10, 20, ChainNodeKind::EntryPackage),
            node(chain, 0, None, 50, 50, ChainNodeKind::EntryPackage),
        ],
    )
    .expect("a fork is a finding, not Err");
    assert_eq!(split_genesis.forks().len(), 1, "{split_genesis:?}");
    assert!(split_genesis.verified_head().is_none(), "{split_genesis:?}");
    assert_eq!(
        split_genesis.head().expect("head").chain_sequence(),
        ChainSequence::new(0),
        "{split_genesis:?}"
    );

    // 4. Bytegleiche Knoten sind eine Dublette, kein Fork: sie werden vor der
    //    Analyse dedupliziert. Die Quarantaene dafuer entsteht in ea-archive.
    let duplicated = build_chain(
        chain,
        &[base[0], base[1], base[2], base[1], base[0], base[2]],
    )
    .expect("a duplicate is not a fork");
    assert!(duplicated.forks().is_empty(), "{duplicated:?}");
    assert_eq!(duplicated.nodes().len(), 3, "{duplicated:?}");
    assert!(duplicated.is_fully_verified(), "{duplicated:?}");
}
