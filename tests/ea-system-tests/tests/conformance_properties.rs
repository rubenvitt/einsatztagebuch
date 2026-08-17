//! Eigenschaftstests fuer deterministische Kodierung, Kettenbildung und
//! Parser, dazu Cross-Version und Kompatibilitaet.
//!
//! Deckt die Punkte vier, fuenf und sechs aus `design.md` §22.1 ab:
//! `Cross-Version-Tests fuer Format und Schema`,
//! `Kompatibilitaetstests fuer historische Pflichtfeldregeln, abgeleitete
//! Altansichten, unbekannte Schemata und parallele alte/neue Krypto-Suites`
//! und `Property-Tests fuer deterministische Kodierung, Kettenbildung und
//! Parser`.
//!
//! # Kein Property-Framework
//!
//! Der Workspace fuehrt kein `proptest` und kein `quickcheck`, und es kommt
//! keines dazu. Die Eigenschaften laufen stattdessen ueber ein
//! EINGEFRORENES Eingabekorpus: ein fest verdrahteter Seed
//! ([`ea_testkit::PROPERTY_CORPUS_SEED`]), ein reproduzierbarer PRNG aus
//! SHA-256 im Zaehlermodus und ein per Manifest festgehaltener Umfang. Ein
//! Fehlschlag ist damit aus dem Seed allein wiederherstellbar — was ein
//! zufaellig geseedetes Framework gerade nicht leistet.
//!
//! # Was diese Datei NICHT belegt
//!
//! ENDLOSSCHLEIFEN werden nicht durch eine Zeitschranke ausgeschlossen. Der
//! Beleg ist, dass dieser Test terminiert: der Umfang ist eingefroren, jede
//! Mutation laeuft genau einmal durch `decode_exact_object`, und ein
//! nichtterminierender Parser liesse den Testlauf haengen statt gruen zu
//! melden. Eine eigene Thread- und Timeout-Maschinerie wuerde dieselbe Aussage
//! treffen und zusaetzlich eine Flakiness-Quelle einbauen.
//!
//! EIN LEERER SCHEINEINTRAG ist auf den hier geprueften Ebenen strukturell
//! ausgeschlossen und wird nicht zusaetzlich behauptet:
//! [`ea_format::decode_exact_object`] und [`ea_schema::SchemaRegistry`] geben
//! entweder ein gebundenes Objekt oder einen benannten Fehler zurueck. Es gibt
//! keine dritte Variante, in die ein leerer Eintrag passte. Die
//! BERICHTSseitige Aussage zu AK 17 — dass ein abgelehntes Objekt im
//! Verifikationsbericht als Quarantaene und nicht als leerer Eintrag
//! erscheint — gehoert zu `ea-verify` und steht dort.
//!
//! LUECKE UND BRUCH sind in `ea-chain` BEFUNDE im `Ok`-Zweig, keine
//! `Err`-Werte. `ChainError` beschreibt ausschliesslich unzulaessige Eingaben
//! (`crates/ea-chain/src/error.rs`). Die Eigenschaft prueft deshalb
//! [`ea_chain::VerifiedChain::gaps`], [`ea_chain::VerifiedChain::breaks`] und
//! [`ea_chain::VerifiedChain::is_fully_verified`], nicht `Result::is_err`.

use std::collections::BTreeSet;

use ea_cbor::ParserLimits;
use ea_chain::{ChainNode, ChainNodeKind, build_chain};
use ea_format::{
    EAG_MAX_RAW_BYTES_V1, ECP_MAX_RAW_BYTES_V1, EDS_MAX_RAW_BYTES_V1, EIP_MAX_RAW_BYTES_V1,
    ESR_MAX_RAW_BYTES_V1, ETB_MAX_RAW_BYTES_V1, ParsedArchiveObject, decode_exact_object,
    encode_destroyed_entry_stub, encode_entry_package, encode_evidence, encode_grant,
    encode_receipt, encode_trust,
};
use ea_schema::{
    CommonHeaderV1, GenesisV1, NativeSourceV1, OperatorSnapshotV1, PayloadV1, SCHEMA_VERSION_V1,
    SUITE_ID_V1, SchemaRegistry, encode_payload,
};
use ea_types::{
    CertificateHash, ChainId, ChainSequence, EntryHash, Hash32, Id16, ObjectHash,
    OperatorSubjectId, OrganizationId, RecordId, RegistryVersion, UnixMillis,
};

/// Die Werte aus Global Constraint Zeile 30 des Stage-1-Plans, ABGESCHRIEBEN
/// aus dem Plantext und nicht aus `ea-cbor`.
///
/// Wuerden sie aus der Kiste importiert, pruefte die Eigenschaft die Kiste
/// gegen sich selbst und eine Absenkung der Grenzen bliebe unbemerkt.
const GLOBAL_CONSTRAINT_MAX_DEPTH: usize = 16;
const GLOBAL_CONSTRAINT_MAX_CONTAINER_ITEMS: usize = 10_000;
const GLOBAL_CONSTRAINT_MAX_TOTAL_ITEMS: usize = 10_000;
const GLOBAL_CONSTRAINT_MAX_TEXT_OR_BYTES: usize = 1_048_592;

/// Die sechs Familien mit ihrer Rohgrenze aus Global Constraint Zeile 30.
const FAMILY_RAW_LIMITS: [(&str, usize); 6] = [
    ("eip", 2_097_152),
    ("eag", 65_536),
    ("esr", 65_536),
    ("ecp", 4_194_304),
    ("etb", 4_194_304),
    ("eds", 262_144),
];

/// Die sechs Eigenschaften ueber dem eingefrorenen Korpus.
#[test]
fn deterministic_encoding_chain_and_parser_properties_hold() {
    let corpus = ea_testkit::property_corpus();

    check_the_corpus_is_frozen(&corpus);
    check_roundtrip_determinism(&corpus);
    check_canonicity(&corpus);
    check_encoding_injectivity(&corpus);
    check_chain_formation(&corpus);
    check_parser_robustness(&corpus);
    check_cross_version_and_compatibility(&corpus);
}

/// Zwei Laeufe desselben Erzeugers liefern dasselbe Korpus.
#[test]
fn the_corpus_is_reproducible_from_its_frozen_seed() {
    let first = ea_testkit::property_corpus();
    let second = ea_testkit::property_corpus();

    assert_eq!(
        first.manifest_json(),
        second.manifest_json(),
        "the corpus generator must be deterministic"
    );
    assert_eq!(first.seed, ea_testkit::PROPERTY_CORPUS_SEED);
    assert_eq!(second.seed, ea_testkit::PROPERTY_CORPUS_SEED);
}

// ---------------------------------------------------------------------------
// Eigenschaft 0: der Umfang ist eingefroren
// ---------------------------------------------------------------------------

/// Ohne diese Schranken bestuende jede folgende Eigenschaft ueber einem leeren
/// Korpus trivial.
fn check_the_corpus_is_frozen(corpus: &ea_testkit::PropertyCorpus) {
    assert_eq!(corpus.seed, ea_testkit::PROPERTY_CORPUS_SEED);
    assert_eq!(corpus.cases.len(), ea_testkit::PROPERTY_CORPUS_CASE_COUNT);
    assert_eq!(corpus.chain.len(), ea_testkit::PROPERTY_CORPUS_CHAIN_LENGTH);
    assert_eq!(
        corpus.field_deltas.len(),
        ea_testkit::PROPERTY_CORPUS_FIELD_DELTA_COUNT
    );
    assert_eq!(
        corpus.mutations.len(),
        ea_testkit::PROPERTY_CORPUS_MUTATION_COUNT
    );
    assert_eq!(
        corpus.cross_version.len(),
        ea_testkit::PROPERTY_CORPUS_CROSS_VERSION_COUNT
    );
    assert_eq!(
        ea_testkit::sha256_hex(corpus.manifest_json().as_bytes()),
        ea_testkit::PROPERTY_CORPUS_MANIFEST_SHA256,
        "the corpus manifest is frozen; a changed generator must change this constant deliberately"
    );

    // Jede der sechs Familien kommt vor. Ein Korpus, der nur `.eip` enthielte,
    // koennte alle folgenden Eigenschaften bestehen, ohne die Formatebene
    // abzudecken.
    let families = corpus
        .cases
        .iter()
        .map(|case| case.family)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        families,
        FAMILY_RAW_LIMITS
            .iter()
            .map(|(family, _)| *family)
            .collect::<BTreeSet<_>>(),
    );
}

// ---------------------------------------------------------------------------
// Eigenschaft 1: Roundtrip-Determinismus
// ---------------------------------------------------------------------------

/// `encode(decode(bytes)) == bytes`, byteidentisch, fuer jedes Korpusobjekt.
fn check_roundtrip_determinism(corpus: &ea_testkit::PropertyCorpus) {
    for case in &corpus.cases {
        let parsed = decode_exact_object(&case.bytes)
            .unwrap_or_else(|error| panic!("{} must parse: {}", case.name, error.code()));
        assert_eq!(
            reencode(&parsed),
            case.bytes,
            "{} must re-encode byte-identically",
            case.name
        );
        // Der Parser haelt die Eingabebytes exakt fest; eine Abweichung hier
        // waere eine stille Umkodierung im Parser selbst.
        assert_eq!(exact_bytes(&parsed), case.bytes, "{}", case.name);
    }
    for node in &corpus.chain {
        let parsed = decode_exact_object(&node.bytes)
            .unwrap_or_else(|error| panic!("a chain node must parse: {}", error.code()));
        assert_eq!(reencode(&parsed), node.bytes);
    }
}

// ---------------------------------------------------------------------------
// Eigenschaft 2: Kanonizitaet
// ---------------------------------------------------------------------------

/// Kein erzeugtes Objekt verletzt `ea_cbor::validate(..., ParserLimits::V1)`,
/// und keines uebersteigt die Rohgrenze seiner Familie.
fn check_canonicity(corpus: &ea_testkit::PropertyCorpus) {
    // Die Grenzen selbst stehen in Global Constraint Zeile 30. Wandern sie,
    // faellt diese Eigenschaft, bevor sie ueber einem gelockerten Parser
    // trivial gruen wird.
    assert_eq!(ParserLimits::V1.max_depth, GLOBAL_CONSTRAINT_MAX_DEPTH);
    assert_eq!(
        ParserLimits::V1.max_container_items,
        GLOBAL_CONSTRAINT_MAX_CONTAINER_ITEMS
    );
    assert_eq!(
        ParserLimits::V1.max_total_items,
        GLOBAL_CONSTRAINT_MAX_TOTAL_ITEMS
    );
    assert_eq!(
        ParserLimits::V1.max_text_or_bytes,
        GLOBAL_CONSTRAINT_MAX_TEXT_OR_BYTES
    );
    assert_eq!(
        family_raw_limits_from_source(),
        FAMILY_RAW_LIMITS.map(|(_, limit)| limit),
        "the six family raw limits are fixed by Global Constraint line 30"
    );

    for case in &corpus.cases {
        ea_cbor::validate(&case.bytes, ParserLimits::V1)
            .unwrap_or_else(|error| panic!("{} is not canonical: {}", case.name, error.code()));
        let limit = FAMILY_RAW_LIMITS
            .iter()
            .find(|(family, _)| *family == case.family)
            .map(|(_, limit)| *limit)
            .expect("every case belongs to one of the six families");
        assert!(
            case.bytes.len() <= limit,
            "{} exceeds the raw limit of its family",
            case.name
        );
    }
}

// ---------------------------------------------------------------------------
// Eigenschaft 3: Kodierungs-Injektivitaet
// ---------------------------------------------------------------------------

/// Zwei verschiedene Feldbelegungen erzeugen nie dieselben Bytes.
///
/// Die tragende Haelfte sind die EINFELD-Differenzpaare: zwei Belegungen, die
/// sich in GENAU einem Feld unterscheiden, muessen verschiedene Objektbytes
/// erzeugen. Ein Feld, das der Kodierer stillschweigend nicht schreibt, faellt
/// genau hier auf — waehrend ein Korpus, das alle Felder gleichzeitig
/// variiert, nur belegte, dass 32 Zufallsbytes nicht kollidieren.
fn check_encoding_injectivity(corpus: &ea_testkit::PropertyCorpus) {
    for delta in &corpus.field_deltas {
        assert_ne!(
            delta.base_bytes, delta.changed_bytes,
            "changing only {} must change the object bytes",
            delta.field
        );
        decode_exact_object(&delta.base_bytes)
            .unwrap_or_else(|error| panic!("the delta base must parse: {}", error.code()));
        decode_exact_object(&delta.changed_bytes).unwrap_or_else(|error| {
            panic!("the {} delta must parse: {}", delta.field, error.code())
        });
    }

    // Jedes variierte Feld kommt genau einmal vor: eine Dublette waere ein
    // Feld, dessen Differenzpaar fehlt, ohne dass die Zahl auffiele.
    let fields = corpus
        .field_deltas
        .iter()
        .map(|delta| delta.field)
        .collect::<BTreeSet<_>>();
    assert_eq!(fields.len(), corpus.field_deltas.len());

    // Und global: kein Objektbytestring des Korpus kommt zweimal vor.
    let distinct = corpus
        .cases
        .iter()
        .map(|case| case.bytes.as_slice())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        distinct.len(),
        corpus.cases.len(),
        "two different assignments produced identical bytes"
    );
}

// ---------------------------------------------------------------------------
// Eigenschaft 4: Kettenbildung
// ---------------------------------------------------------------------------

/// Jede committed Sequenz steigt exakt um eins und bindet den Hash des
/// direkten Vorgaengers.
fn check_chain_formation(corpus: &ea_testkit::PropertyCorpus) {
    let nodes = chain_nodes(corpus);
    let chain_id = ChainId::try_from(corpus.chain[0].chain_id.as_slice()).expect("16 bytes");

    // Die Zusage des Korpus, bevor `ea-chain` ueberhaupt laeuft.
    for (index, node) in corpus.chain.iter().enumerate() {
        assert_eq!(node.chain_sequence, index as u64);
        match index.checked_sub(1) {
            None => assert_eq!(node.previous_entry_hash, None),
            Some(previous) => assert_eq!(
                node.previous_entry_hash,
                Some(corpus.chain[previous].entry_hash),
                "sequence {index} must bind its direct predecessor"
            ),
        }
    }

    let verified = build_chain(chain_id, &nodes).expect("the frozen chain is a valid input");
    assert!(verified.is_fully_verified(), "{verified:?}");
    assert!(verified.gaps().is_empty());
    assert!(verified.breaks().is_empty());
    assert!(verified.forks().is_empty());
    let head = verified.head().expect("a non-empty chain has a head");
    assert_eq!(head.chain_sequence().get(), (nodes.len() - 1) as u64);

    // Die Eingabereihenfolge darf das Ergebnis nicht bewegen: `build_chain`
    // sortiert und dedupliziert bewusst ohne `HashMap`.
    let mut reversed = nodes.clone();
    reversed.reverse();
    let from_reversed = build_chain(chain_id, &reversed).expect("the same nodes remain valid");
    assert_eq!(format!("{verified:?}"), format!("{from_reversed:?}"));

    // Ein entferntes mittleres Objekt erzeugt eine LUECKE — als Befund im
    // `Ok`-Zweig, siehe Moduldoku.
    let removed = nodes.len() / 2;
    let mut with_gap = nodes.clone();
    let dropped = with_gap.remove(removed);
    let gapped = build_chain(chain_id, &with_gap).expect("a shorter node list stays valid input");
    assert!(!gapped.is_fully_verified());
    let gap = gapped
        .gaps()
        .iter()
        .find(|gap| gap.from_sequence() == dropped.chain_sequence)
        .unwrap_or_else(|| panic!("removing sequence {removed} must open a gap: {gapped:?}"));
    assert_eq!(gap.through_sequence(), dropped.chain_sequence);

    // Zwei vertauschte Objekte erzeugen eine ABLEHNUNG. Das blosse Umsortieren
    // der Eingabe kann es nicht sein — `build_chain` sortiert selbst, und der
    // Test oben misst genau das. Vertauscht werden die Eintragshashes zweier
    // Knoten: danach bindet der Nachfolger einen Vorgaenger, der an dieser
    // Stelle nicht mehr steht.
    let mut swapped = nodes.clone();
    let (left, right) = (0, swapped.len() - 1);
    let carried = swapped[left].entry_hash;
    swapped[left].entry_hash = swapped[right].entry_hash;
    swapped[right].entry_hash = carried;
    let broken = build_chain(chain_id, &swapped).expect("swapped nodes stay valid input");
    assert!(!broken.is_fully_verified(), "{broken:?}");
    assert!(
        !broken.breaks().is_empty(),
        "swapping two entry hashes must break the predecessor binding: {broken:?}"
    );
}

/// Die Kettenknoten des Korpus als `ea-chain`-Werte.
fn chain_nodes(corpus: &ea_testkit::PropertyCorpus) -> Vec<ChainNode> {
    corpus
        .chain
        .iter()
        .map(|node| ChainNode {
            chain_id: ChainId::try_from(node.chain_id.as_slice()).expect("16 bytes"),
            chain_sequence: ChainSequence::new(node.chain_sequence),
            previous_entry_hash: node
                .previous_entry_hash
                .map(|hash| EntryHash::from(Hash32::try_from(hash.as_slice()).expect("32 bytes"))),
            entry_hash: EntryHash::from(
                Hash32::try_from(node.entry_hash.as_slice()).expect("32 bytes"),
            ),
            object_hash: ObjectHash::from(
                Hash32::try_from(node.object_hash.as_slice()).expect("32 bytes"),
            ),
            writer_certificate_hash: CertificateHash::try_from(
                node.writer_certificate_hash.as_slice(),
            )
            .expect("32 bytes"),
            writer_transition_event_hash: None,
            kind: ChainNodeKind::EntryPackage,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Eigenschaft 5: Parser-Robustheit
// ---------------------------------------------------------------------------

/// Kein Eingabebytestring, auch kein mutierter, fuehrt zu Panic oder zu einer
/// Ueberschreitung der Grenzen aus Global Constraint Zeile 30. Ergebnis ist
/// stets `Ok` oder ein BENANNTER `Err`.
fn check_parser_robustness(corpus: &ea_testkit::PropertyCorpus) {
    let mut rejected = 0_usize;
    for mutation in &corpus.mutations {
        // `ea_cbor::validate` steht vor `ea-format` und muss dieselbe Zusage
        // halten: Ergebnis, kein Absturz.
        let _ = ea_cbor::validate(&mutation.bytes, ParserLimits::V1);

        match decode_exact_object(&mutation.bytes) {
            Ok(parsed) => {
                // Ein Mutant, der durchkommt, MUSS wieder byteidentisch
                // kodieren. Sonst haette der Parser stillschweigend etwas
                // anderes gelesen, als dasteht.
                assert_eq!(reencode(&parsed), mutation.bytes, "{}", mutation.name);
            }
            Err(error) => {
                rejected += 1;
                let code = error.code();
                assert!(
                    code.starts_with("EA-"),
                    "{} was rejected without a named code: {code}",
                    mutation.name
                );
                assert!(!code.contains(' '), "{} code {code}", mutation.name);
            }
        }
        assert!(
            mutation.bytes.len() <= 4_194_304,
            "{} exceeds MAX_ARCHIVE_OBJECT_BYTES_V1",
            mutation.name
        );
    }

    // Ohne diese Schranke koennte ein Parser, der ALLES annimmt, die
    // Eigenschaft leer bestehen.
    assert!(
        rejected * 2 >= corpus.mutations.len(),
        "only {rejected} of {} mutations were rejected; the mutation set does not bite",
        corpus.mutations.len()
    );
}

// ---------------------------------------------------------------------------
// Eigenschaft 6: Cross-Version und Kompatibilitaet
// ---------------------------------------------------------------------------

/// AK 17: ein alter Leser lehnt Unbekanntes ab, ohne einen leeren
/// Scheineintrag zu erzeugen.
fn check_cross_version_and_compatibility(corpus: &ea_testkit::PropertyCorpus) {
    // Formatebene: unbekannte Objektversion, kritische Erweiterung, fremdes
    // Objekttyp-Tag.
    for case in &corpus.cross_version {
        let error = decode_exact_object(&case.bytes)
            .err()
            .unwrap_or_else(|| panic!("{} must be refused", case.name));
        assert_eq!(error.code(), case.expected_error_code, "{}", case.name);
    }

    let registry = SchemaRegistry::v1();
    let payload = frozen_genesis_payload();

    // Abgeleitete Altansicht: v1 leitet identisch ab, und die Quellbytes
    // bleiben exakt erhalten.
    let view = registry
        .derive_view("ea.genesis", SCHEMA_VERSION_V1, &payload)
        .expect("the frozen genesis payload derives its own view");
    assert_eq!(view.source_schema_id(), "ea.genesis");
    assert_eq!(view.target_schema_id(), "ea.genesis");
    assert_eq!(view.source_schema_version(), SCHEMA_VERSION_V1);
    assert_eq!(view.target_schema_version(), SCHEMA_VERSION_V1);
    assert_eq!(view.exact_source_bytes(), payload.as_slice());

    // Unbekanntes Schema und unbekannte Schemaversion: benannter Fehler, kein
    // `Ok`. Es gibt keine dritte Variante, in die ein leerer Eintrag passte.
    for (schema_id, version) in [
        ("ea.unknown-record", SCHEMA_VERSION_V1),
        ("ea.genesis", SCHEMA_VERSION_V1 + 1),
    ] {
        let error = registry
            .validate(schema_id, version, &payload)
            .err()
            .unwrap_or_else(|| panic!("{schema_id}/{version} must be refused"));
        assert_eq!(error.code(), "EA-SCHEMA-UNSUPPORTED");
        let error = registry
            .derive_view(schema_id, version, &payload)
            .err()
            .unwrap_or_else(|| panic!("{schema_id}/{version} must be refused"));
        assert_eq!(error.code(), "EA-SCHEMA-UNSUPPORTED");
    }

    // Parallele alte/neue Krypto-Suites: die bekannte Suite passiert, jede
    // andere faellt.
    registry
        .require_suite(SUITE_ID_V1)
        .expect("the v1 suite is supported");
    let error = registry
        .require_suite("EINSATZARCHIV-SUITE-2")
        .expect_err("a future suite must be refused by a v1 reader");
    assert_eq!(error.code(), "EA-SCHEMA-UNSUPPORTED-SUITE");

    // Historische Pflichtfeldregeln. Der Nutzinhalt ist WOHLGEFORMTES,
    // kanonisches CBOR und trotzdem unvollstaendig: der Datensatz fuehrt fuenf
    // statt sechs Felder. Genau das trennt die Feldregel vom CBOR-Parser — ein
    // abgeschnittener Bytestring wuerde schon davor scheitern und belegte die
    // Regel nicht.
    let missing_field = genesis_without_its_last_mandatory_field(&payload);
    ea_cbor::validate(&missing_field, ParserLimits::V1)
        .expect("the shortened record is still canonical CBOR");
    let error = registry
        .validate("ea.genesis", SCHEMA_VERSION_V1, &missing_field)
        .expect_err("a record missing a mandatory field must be refused");
    assert_eq!(error.code(), "EA-SCHEMA-SHAPE");

    // Und der Nutzinhalt eines ANDEREN Datensatztyps erfuellt die
    // Pflichtfeldregeln von `ea.incident` nicht.
    let error = registry
        .validate("ea.incident", SCHEMA_VERSION_V1, &payload)
        .expect_err("a genesis payload does not satisfy the incident rules");
    assert_eq!(error.code(), "EA-SCHEMA-RECORD-TYPE");

    // Abgeschnittene Bytes sind eine ANDERE Aussage: sie treffen den
    // CBOR-Parser, nicht die Feldregeln. Beide Ebenen lehnen benannt ab, und
    // der Test haelt auseinander, welche gerade antwortet.
    for truncated in truncations_of(&payload) {
        let error = registry
            .validate("ea.genesis", SCHEMA_VERSION_V1, &truncated)
            .expect_err("a truncated payload must be refused");
        assert_eq!(error.code(), "EA-CBOR-INVALID");
    }

    // Die Formatebene bleibt davon unberuehrt: die gueltigen Korpusobjekte
    // werden weiterhin angenommen. Eine Cross-Version-Pruefung, die alles
    // ablehnte, waere wertlos.
    for case in &corpus.cases {
        assert!(decode_exact_object(&case.bytes).is_ok(), "{}", case.name);
    }
}

/// Ein deterministischer, gueltiger `ea.genesis`-Nutzinhalt.
fn frozen_genesis_payload() -> Vec<u8> {
    let header = CommonHeaderV1::new(
        RecordId::from(
            Id16::try_from(
                [
                    0x01, 0x93, 0x0e, 0x1b, 0x2c, 0x40, 0x74, 0x11, 0x8f, 0x22, 0x33, 0x44, 0x55,
                    0x66, 0x77, 0x88,
                ]
                .as_slice(),
            )
            .expect("16 bytes"),
        ),
        UnixMillis::new(1_700_000_000_000),
        "Europe/Berlin",
        OperatorSnapshotV1::new(
            OrganizationId::try_from([0x30_u8; 16].as_slice()).expect("16 bytes"),
            OperatorSubjectId::from(Id16::try_from([0x31_u8; 16].as_slice()).expect("16 bytes")),
            "Eigenschaft",
            "Eigenschaft",
            [0x32; 32],
            ObjectHash::from(Hash32::try_from([0x33_u8; 32].as_slice()).expect("32 bytes")),
        )
        .expect("the frozen operator snapshot is well formed"),
        NativeSourceV1::new("property", 1).expect("the frozen source is well formed"),
        RegistryVersion::new(1),
    )
    .expect("the frozen common header is well formed");
    let genesis = GenesisV1::new(
        header,
        OrganizationId::try_from([0x30_u8; 16].as_slice()).expect("16 bytes"),
        ChainId::try_from([0x34_u8; 16].as_slice()).expect("16 bytes"),
        ObjectHash::from(Hash32::try_from([0x35_u8; 32].as_slice()).expect("32 bytes")),
        1,
        ObjectHash::from(Hash32::try_from([0x36_u8; 32].as_slice()).expect("32 bytes")),
    )
    .expect("the frozen genesis record is well formed");
    encode_payload(&PayloadV1::Genesis(genesis)).expect("encoding the frozen genesis cannot fail")
}

/// Die Laenge des `genesis`-Teilarrays in Bytes, EINSCHLIESSLICH seines
/// Kopfbytes.
///
/// Abgeleitet aus `crates/ea-schema/src/encode.rs::encode_genesis`: ein
/// Array-Kopf `0x86`, dann `bytes(16)` und `bytes(16)` zu je 17 Byte,
/// `bytes(32)` zu 34 Byte, die Zahl 1 zu einem Byte, die 21 Zeichen lange
/// Suite-Kennung zu 22 Byte und `bytes(32)` zu 34 Byte — zusammen 126.
const GENESIS_TAIL_BYTES: usize = 126;

/// Die Laenge des letzten `genesis`-Feldes, `initialPolicyObjectHash`.
const GENESIS_LAST_FIELD_BYTES: usize = 34;

/// Derselbe Datensatz mit FUENF statt sechs Feldern.
///
/// Das Ergebnis ist kanonisches CBOR und trotzdem regelwidrig: genau der Fall,
/// den eine Pflichtfeldregel abfangen MUSS und ein CBOR-Parser nicht sieht.
///
/// Die Bytearithmetik ist gemessen, nicht geraten — das Kopfbyte wird vor dem
/// Schnitt geprueft. Wandert das Genesis-Layout, faellt diese Zusicherung
/// laut, statt den Schnitt still an die falsche Stelle zu legen.
fn genesis_without_its_last_mandatory_field(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() > GENESIS_TAIL_BYTES);
    let header = payload.len() - GENESIS_TAIL_BYTES;
    assert_eq!(
        payload[header], 0x86,
        "the genesis record is a six element array"
    );
    let mut shortened = payload[..payload.len() - GENESIS_LAST_FIELD_BYTES].to_vec();
    shortened[header] = 0x85;
    shortened
}

/// Zwei Kuerzungen: die letzte Haelfte und alles bis auf ein Byte.
///
/// Beide treffen den CBOR-Parser, nicht die Feldregeln; siehe die Aufrufstelle.
fn truncations_of(payload: &[u8]) -> Vec<Vec<u8>> {
    vec![payload[..payload.len() / 2].to_vec(), payload[..1].to_vec()]
}

// ---------------------------------------------------------------------------
// Familienunabhaengige Helfer
// ---------------------------------------------------------------------------

/// Kodiert ein geparstes Objekt mit dem Kodierer seiner Familie neu.
fn reencode(parsed: &ParsedArchiveObject) -> Vec<u8> {
    match parsed {
        ParsedArchiveObject::Entry(value) => encode_entry_package(value.value()),
        ParsedArchiveObject::Grant(value) => encode_grant(value.value()),
        ParsedArchiveObject::Receipt(value) => encode_receipt(value.value()),
        ParsedArchiveObject::Evidence(value) => encode_evidence(value.value()),
        ParsedArchiveObject::Trust(value) => encode_trust(value.value()),
        ParsedArchiveObject::Destroyed(value) => encode_destroyed_entry_stub(value.value()),
    }
    .expect("re-encoding a parsed object cannot fail")
    .into_vec()
}

/// Die exakten Bytes, die der Parser festgehalten hat.
fn exact_bytes(parsed: &ParsedArchiveObject) -> Vec<u8> {
    match parsed {
        ParsedArchiveObject::Entry(value) => value.exact_bytes().as_bytes().to_vec(),
        ParsedArchiveObject::Grant(value) => value.exact_bytes().as_bytes().to_vec(),
        ParsedArchiveObject::Receipt(value) => value.exact_bytes().as_bytes().to_vec(),
        ParsedArchiveObject::Evidence(value) => value.exact_bytes().as_bytes().to_vec(),
        ParsedArchiveObject::Trust(value) => value.exact_bytes().as_bytes().to_vec(),
        ParsedArchiveObject::Destroyed(value) => value.exact_bytes().as_bytes().to_vec(),
    }
}

/// Die sechs Rohgrenzen, wie `ea-format` sie fuehrt.
fn family_raw_limits_from_source() -> [usize; 6] {
    [
        EIP_MAX_RAW_BYTES_V1,
        EAG_MAX_RAW_BYTES_V1,
        ESR_MAX_RAW_BYTES_V1,
        ECP_MAX_RAW_BYTES_V1,
        ETB_MAX_RAW_BYTES_V1,
        EDS_MAX_RAW_BYTES_V1,
    ]
}
