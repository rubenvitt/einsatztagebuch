//! Der kanonische Verifikationsbericht gegen sein gepinntes JSON-Schema.
//!
//! Der Schemanachweis liegt BEWUSST hier und nicht in `ea-verify`: `jsonschema`
//! zoege `getrandom 0.3.4` in den wasm-Graphen, und `ea-verify` steht auf der
//! wasm32-Positivliste von `tools/xtask/src/main.rs`. `ea-verify` schreibt
//! deshalb einen eigenen kanonischen JSON-Writer; hier wird belegt, dass dessen
//! Ausgabe das Schema erfuellt.

/// Die Archivfixtures, per `#[path]` eingebunden statt ueber eine optionale
/// Dependency.
///
/// EINGEBUNDEN WIRD DAS `ea-verify`-MODUL, nicht das von `ea-archive`: es
/// bindet jenes seinerseits als `archive_support` ein und liefert darueber
/// hinaus die Vernichtungsfixtures. Ohne sie liesse sich `authorizedDestructions`
/// nur LEER gegen das Schema pruefen — und genau dort liegt der Fallstrick, dass
/// `destructionId` 32 und ein Objekthash 64 Hex-Zeichen hat.
#[path = "../../../crates/ea-verify/tests/support/mod.rs"]
mod support;

use ea_archive::ArchiveSource;
use ea_crypto::{object_hash, verification_report_hash};
use ea_format::CertificateKindV1;
use ea_trust::{TrustAnchorV1, TrustObjectSource, decode_trust_anchor};
use ea_types::UnixMillis;

use ea_archive::QuarantineReason;
use ea_types::ObjectHash;
use ea_verify::{
    DECAPSULATION_EVENT_V1, DestructionStateV1, GATE_ORDER_V1, RecordingObserver,
    ServerConfirmationV1, VerificationReportV1, VerifyOptions, verify_archive,
    verify_archive_observed,
};
use serde_json::Value;

use support::{
    DESTRUCTION_STATE_COMPLETE_MANAGED_SCOPE_V1, DESTRUCTION_STATE_IN_PROGRESS_V1,
    DESTRUCTION_STATE_REQUESTED_V1, DestructionSpec, FIXTURE_OS_WALL_CLOCK_V1,
    REPORT_DESTROYED_STUB_SEQUENCE_V1, REPORT_DUPLICATE_SEQUENCE_V1, REPORT_EARLY_SEQUENCE_V1,
    REPORT_FORK_SEQUENCE_V1, REPORT_GAP_FROM_V1, REPORT_GAP_THROUGH_V1, REPORT_HEAD_SEQUENCE_V1,
    REPORT_RECEIPTED_SEQUENCES_V1, REPORT_TRAILING_SEQUENCE_V1, REPORT_UNCONFIRMED_SEQUENCE_V1,
    archive_support::{
        ArchiveFixture, FIXTURE_TIME_FLOOR_V1, MUTATED_EIP_FORMAT_ERROR_CODE_V1,
        eip_with_one_mutated_body_byte,
        trust_support::{ActionSpec, HeadOptions, RegistryLineBuilder},
    },
    complete_recipient_key_thumbprint, complete_recipient_private_key, complete_report_archive,
    destruction_archive,
};

/// Das gepinnte Berichtsschema, zur Uebersetzungszeit eingebettet.
///
/// `include_str!` statt `std::fs`: der Pfad ist relativ zu dieser Datei und
/// damit unabhaengig vom Arbeitsverzeichnis des Testlaufs.
const REPORT_SCHEMA_V1: &str =
    include_str!("../../../schemas/reports/v1/verification-report.schema.json");

/// Der Nullhash des Sentinels: 64 Nullen.
const ZERO_HASH_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Ein Bestand, der AUSSCHLIESSLICH die Vertrauensablage und ein Stueck
/// Beiwerk traegt.
///
/// Bewusst ohne Eintraege, Stummel und Quittungen: damit sind
/// `quarantinedObjects` und `formatErrors` durch Konstruktion leer — die
/// Trust-Objekte einer Registrierungslinie sind paarweise verschieden, erheben
/// keinen Anspruch auf ein Sequenzfach und bestaetigen keinen Eintrag.
struct TrustOnlyArchive {
    fixture: ArchiveFixture,
    anchor_bytes: Vec<u8>,
    trust_object_count: usize,
    non_object_count: usize,
}

impl TrustOnlyArchive {
    fn build() -> Self {
        let mut line = RegistryLineBuilder::new();
        line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::Writer,
                marker: 0x11,
                effective_from: None,
            },
            HeadOptions::default(),
        );

        let source = line.source();
        let mut hashes = Vec::new();
        source
            .visit_trust_object_hashes(&mut |hash| {
                hashes.push(hash);
                Ok(())
            })
            .expect("the fixture trust line must enumerate");

        let mut fixture = ArchiveFixture::new();
        let mut trust_object_count = 0;
        for hash in hashes {
            let bytes = source
                .read_exact_trust_object(hash)
                .expect("the fixture trust line must read")
                .expect("an enumerated trust object must be readable");
            fixture.push_exact_bytes(
                &format!(
                    "{}{}.etb",
                    ea_archive::REGISTRY_EVENTS_DIR_V1,
                    hex::encode(hash.as_bytes())
                ),
                bytes.to_vec(),
            );
            trust_object_count += 1;
        }
        fixture.push_non_object(ea_archive::README_FORMAT_FILE_V1, b"Einsatzarchiv v1\n");

        Self {
            fixture,
            anchor_bytes: line.exact_anchor_bytes().to_vec(),
            trust_object_count,
            non_object_count: 1,
        }
    }

    fn anchor(&self) -> TrustAnchorV1 {
        decode_trust_anchor(&self.anchor_bytes).expect("the fixture anchor must decode")
    }
}

/// Die Verifikationsoptionen der Fixtures.
///
/// Die Uhr ist ein PFLICHTPARAMETER und wird nie hergeleitet: ohne uebergebene
/// Uhr kann die Pipeline keinen Registrierungskopf auswaehlen.
fn options() -> VerifyOptions<'static> {
    VerifyOptions::new(UnixMillis::new(FIXTURE_TIME_FLOOR_V1))
}

fn run(source: &dyn ArchiveSource, anchor: &TrustAnchorV1) -> VerificationReportV1 {
    verify_archive(source, anchor, options()).expect("the fixture archive must report")
}

fn parse(json: &str) -> Value {
    serde_json::from_str(json).expect("the canonical writer must emit parsable JSON")
}

/// Prueft die JSON gegen `schemas/reports/v1/verification-report.schema.json`.
fn assert_valid_against_schema(document: &Value) {
    let schema: Value = serde_json::from_str(REPORT_SCHEMA_V1).expect("the pinned schema is JSON");
    let validator = jsonschema::validator_for(&schema).expect("the pinned schema compiles");
    let errors: Vec<String> = validator
        .iter_errors(document)
        .map(|error| format!("{} at {}", error, error.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "the canonical report violates the pinned schema: {errors:?}"
    );
}

#[test]
fn a_trust_only_archive_report_validates_against_the_pinned_schema() {
    let built = TrustOnlyArchive::build();
    let anchor = built.anchor();
    let report = run(&built.fixture, &anchor);

    // Die Zaehlerinvariante aus design.md 11.4: jede gelieferte Bytesequenz
    // faellt in genau eine der beiden Zaehlklassen.
    assert_eq!(report.archive_object_count(), built.trust_object_count);
    assert_eq!(report.non_object_file_count(), built.non_object_count);
    assert_eq!(
        report.archive_object_count() + report.non_object_file_count(),
        built.fixture.len()
    );
    assert_eq!(report.entry_package_count(), 0);
    assert_eq!(report.destroyed_entry_count(), 0);

    // K2: die Kettenidentitaet stammt IMMER aus dem Anker, nie aus dem Bestand.
    // `ea-types` leitet fuer Kennungs- und Hashtypen kein `Debug` ab; deshalb
    // hier `assert!` mit eigener Meldung statt `assert_eq!`.
    assert!(
        report.chain_head().chain_id() == anchor.chain_id(),
        "die Kettenkennung des Berichts stammt IMMER aus dem Anker"
    );
    assert_eq!(report.chain_head().sequence().get(), 0);
    assert_eq!(
        report.chain_head().entry_hash().as_bytes(),
        &[0_u8; 32],
        "ohne rekonstruierte Kette gilt das Sentinel, nie genesis_entry_hash()"
    );
    assert_ne!(
        report.chain_head().entry_hash().as_bytes(),
        anchor.genesis_entry_hash().as_bytes(),
        "das Sentinel darf keinen verifizierten Genesis-Eintrag behaupten"
    );

    let json = report
        .to_canonical_json()
        .expect("the canonical writer must emit");
    let document = parse(&json);
    assert_valid_against_schema(&document);

    assert_eq!(document["schemaId"], "ea.verification-report/v1");
    assert_eq!(
        document["chainHead"]["chainId"],
        Value::String(hex::encode(anchor.chain_id().as_bytes()))
    );
    assert_eq!(document["chainHead"]["sequence"].as_u64(), Some(0));
    assert_eq!(document["chainHead"]["entryHash"], ZERO_HASH_HEX);
    assert_eq!(
        document["archiveObjectCount"].as_u64(),
        Some(built.trust_object_count as u64)
    );
    assert_eq!(
        document["nonObjectFileCount"].as_u64(),
        Some(built.non_object_count as u64)
    );
    for empty in [
        "registryVersions",
        "objectResults",
        "authorizedDestructions",
        "gaps",
        "formatErrors",
        "quarantinedObjects",
        "signatureErrors",
        "evidenceErrors",
        "decryptionErrors",
    ] {
        assert_eq!(
            document[empty].as_array().map(Vec::len),
            Some(0),
            "{empty} must be empty over an archive that carries nothing but its trust store"
        );
    }

    // NICHT LEER, und das ist die eine Sachaussage, die dieser Bestand traegt:
    // Gate `trust` hat die Registrierungslinie GEGEN die Wurzel des Ankers
    // geprueft und sie getragen. `publicKeyThumbprints` ist Nachweis des
    // Geprueften, also steht genau dieser eine Abdruck darin — kein
    // Geraetezertifikat der Linie, denn keines hat in diesem Lauf eine
    // Signatur getragen.
    assert_eq!(
        document["publicKeyThumbprints"],
        Value::Array(vec![Value::String(hex::encode(
            anchor.root_key_thumbprint().as_bytes()
        ))]),
        "publicKeyThumbprints carries exactly the root the trust gate verified against"
    );
    assert!(
        document.get("reportSignature").is_none() && document.get("runtimeMetadata").is_none(),
        "Phase B emits neither a report signature nor runtime metadata"
    );

    // reportHash = SHA-256 ueber die kanonischen Bytes OHNE reportHash,
    // reportSignature und runtimeMetadata.
    let preimage = report
        .canonical_hash_preimage()
        .expect("the canonical writer must emit the preimage");
    assert!(
        !preimage.contains("reportHash"),
        "the preimage must exclude its own hash"
    );
    assert!(
        report.report_hash() == verification_report_hash(preimage.as_bytes()),
        "reportHash muss SHA-256 ueber genau dieses Urbild sein"
    );
    assert_eq!(
        document["reportHash"],
        Value::String(hex::encode(report.report_hash().as_bytes()))
    );

    // Dieselben Bytes zweimal: byteidentische JSON.
    let again = run(&built.fixture, &anchor)
        .to_canonical_json()
        .expect("the canonical writer must emit");
    assert_eq!(json, again);

    // Die schaerfere Fassung derselben Aussage: DIESELBEN Bytes unter
    // vertauschten Pfadhinweisen und in umgekehrter Reihenfolge. Ein zweiter
    // Lauf ueber die unveraenderte Reihenfolge koennte eine Einfuegeordnung
    // nicht von einer kanonischen unterscheiden — dieser hier kann es.
    let shuffled = run(&built.fixture.randomized_paths(), &anchor)
        .to_canonical_json()
        .expect("the canonical writer must emit");
    assert_eq!(json, shuffled);

    // SEIT DIE PIPELINE VOLLSTAENDIG LAEUFT ist dieser Bestand vollstaendig
    // verifiziert — und zwar LEER-WAHR: er traegt ausser Trust-Objekten nichts,
    // also gibt es nichts, was unverifiziert bleiben koennte. Kein
    // `formatError`, kein isoliertes Objekt, keine Luecke; `build_chain` bildet
    // ueber null Knoten kein Intervall.
    //
    // Die Aussage ist damit „an diesem Bestand ist nichts zu beanstanden", nicht
    // „hier wurde ein Eintrag geprueft". Wer letzteres wissen will, liest
    // `objectResults` — und das Array ist hier leer.
    assert!(
        report.is_fully_verified(),
        "ein Bestand ohne jeden Befund ist vollstaendig verifiziert, sobald die Pipeline durchlief"
    );
    assert_eq!(
        report.object_results().len(),
        0,
        "vollstaendig verifiziert heisst hier: es gab nichts zu beanstanden, nicht: es wurde ein \
         Eintrag geprueft"
    );
}

#[test]
fn a_malformed_object_pairs_a_format_error_with_a_quarantine_entry() {
    let mut built = TrustOnlyArchive::build();
    let mutated = eip_with_one_mutated_body_byte();
    let mutated_hash = object_hash(&mutated);
    built
        .fixture
        .push_exact_bytes("entries/000000000001_entry.eip", mutated.clone());
    let anchor = built.anchor();
    let report = run(&built.fixture, &anchor);

    assert_eq!(
        report.archive_object_count(),
        built.trust_object_count + 1,
        "die verkippten Bytes tragen weiterhin ein Exact-Object-Praefix"
    );
    assert_eq!(report.entry_package_count(), 0);

    let json = report
        .to_canonical_json()
        .expect("the canonical writer must emit");
    let document = parse(&json);
    assert_valid_against_schema(&document);

    let expected_hash = Value::String(hex::encode(mutated_hash.as_bytes()));
    let format_errors = document["formatErrors"].as_array().expect("array");
    assert_eq!(format_errors.len(), 1);
    assert_eq!(format_errors[0]["objectHash"], expected_hash);
    assert_eq!(
        format_errors[0]["code"],
        Value::String(MUTATED_EIP_FORMAT_ERROR_CODE_V1.to_owned())
    );

    let quarantined = document["quarantinedObjects"].as_array().expect("array");
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0]["objectHash"], expected_hash);
    assert_eq!(quarantined[0]["reason"], "malformed");

    assert_eq!(document["objectResults"].as_array().map(Vec::len), Some(0));
    assert!(!report.is_fully_verified());

    // Auch mit Befunden haengt die Ausgabe nicht an der Reihenfolge des
    // Bestands: dieselben Bytes unter vertauschten Hinweisen und rueckwaerts.
    let shuffled = run(&built.fixture.randomized_paths(), &anchor)
        .to_canonical_json()
        .expect("the canonical writer must emit");
    assert_eq!(json, shuffled);
}

/// Ein Bericht MIT Vernichtungsvorgaengen gegen dasselbe Schema.
///
/// DIE EIGENTLICHE AUSSAGE ist eine Laengenaussage: `destructionId` folgt dem
/// `uuid`-Muster `^[0-9a-f]{32}$`, `authorizationObjectHash` dem `hash`-Muster
/// `^[0-9a-f]{64}$`. Beide entstehen aus `Id16` beziehungsweise `Hash32`, und
/// beide laufen durch DENSELBEN Hexschreiber. Verwechselte er sie, validierte
/// der Bericht nur zufaellig — deshalb wird hier nicht die Laenge nachgezaehlt,
/// sondern das Schema selbst befragt.
#[test]
fn a_report_with_destructions_validates_against_the_pinned_schema() {
    let built = destruction_archive(&[
        DestructionSpec::new(0x91, &[DESTRUCTION_STATE_REQUESTED_V1]),
        DestructionSpec::new(
            0x92,
            &[
                DESTRUCTION_STATE_REQUESTED_V1,
                DESTRUCTION_STATE_IN_PROGRESS_V1,
                DESTRUCTION_STATE_COMPLETE_MANAGED_SCOPE_V1,
            ],
        )
        .with_attestation(),
    ]);
    let anchor = built.anchor();
    let report = verify_archive(
        &built.fixture,
        &anchor,
        VerifyOptions::new(UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1)),
    )
    .expect("the fixture archive must report");

    let json = report
        .to_canonical_json()
        .expect("the canonical writer must emit");
    let document = parse(&json);
    assert_valid_against_schema(&document);

    let destructions = document["authorizedDestructions"]
        .as_array()
        .expect("array");
    assert_eq!(destructions.len(), 2);
    assert_eq!(
        destructions[0]["destructionId"],
        Value::String(hex::encode(built.destructions[0].destruction_id.as_bytes()))
    );
    assert_eq!(destructions[0]["state"], "requested");
    assert_eq!(
        destructions[1]["authorizationObjectHash"],
        Value::String(hex::encode(
            built.destructions[1].authorization_object_hash.as_bytes()
        ))
    );
    assert_eq!(destructions[1]["state"], "completeManagedScope");
    assert_eq!(
        destructions[0]["destructionId"].as_str().map(str::len),
        Some(32),
        "a destructionId is sixteen bytes, a hash is thirty-two"
    );
    assert_eq!(
        destructions[1]["authorizationObjectHash"]
            .as_str()
            .map(str::len),
        Some(64)
    );

    // Auch mit Vorgaengen haengt die Ausgabe nicht an der Reihenfolge des
    // Bestands: dieselben Bytes unter vertauschten Hinweisen und rueckwaerts.
    let shuffled = verify_archive(
        &built.fixture.randomized_paths(),
        &anchor,
        VerifyOptions::new(UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1)),
    )
    .expect("the fixture archive must report")
    .to_canonical_json()
    .expect("the canonical writer must emit");
    assert_eq!(json, shuffled);
}

/// Die siebzehn Pflichtfelder, die der Bestand tatsaechlich FUELLT.
///
/// `signatureErrors`, `evidenceErrors` und `decryptionErrors` fehlen hier
/// bewusst: der Gesamtbestand traegt seine Maengel dort, wo sie hingehoeren —
/// unlesbare Bytes in `formatErrors`, isolierte Objekte in
/// `quarantinedObjects`, das fehlende `.eip` in `gaps`. Ein Bestand, der
/// zusaetzlich eine kaputte Signatur, eine ueberfaellige Frist UND einen
/// falschen Empfaengerschluessel traegt, misst nicht mehr, sondern weniger:
/// jeder dieser Faelle hat sein eigenes Fixture, und in einem Bestand mit
/// achtzehn Befunden liesse sich keiner davon mehr einem Objekt zuordnen.
const REPORT_FILLED_ARRAY_FIELDS_V1: [&str; 7] = [
    "registryVersions",
    "objectResults",
    "authorizedDestructions",
    "gaps",
    "formatErrors",
    "quarantinedObjects",
    "publicKeyThumbprints",
];

/// Die Ordnungsregeln EINES Arrays, so wie sein Schema sie erklaert.
struct ArrayRuleV1 {
    /// Der Name des Berichtsfelds.
    name: String,
    /// Die Teile des `x-ea-sort-key`, je Pfad und Kodierung.
    sort: Vec<(String, String)>,
    /// Die Pfade des `x-ea-unique-key`.
    unique: Vec<String>,
}

/// Der Sortier- beziehungsweise Eindeutigkeitsschluessel jedes Arrays, so wie
/// das Schema ihn erklaert.
fn schema_array_rules(schema: &Value) -> Vec<ArrayRuleV1> {
    let defs = &schema["$defs"];
    let mut rules = Vec::new();
    for (name, property) in schema["properties"]
        .as_object()
        .expect("das Schema traegt Eigenschaften")
    {
        // `signatureErrors` und seine Geschwister zeigen per `$ref` auf
        // `#/$defs/sortedErrors`. Aufgeloest wird hier, statt die Regeln zu
        // wiederholen — sonst pruefte der Test seine eigene Abschrift.
        let resolved = match property["$ref"].as_str() {
            Some(reference) => {
                let key = reference
                    .strip_prefix("#/$defs/")
                    .expect("ein Schemaverweis zeigt in $defs");
                &defs[key]
            }
            None => property,
        };
        let Some(sort_key) = resolved["x-ea-sort-key"].as_array() else {
            continue;
        };
        let sort = sort_key
            .iter()
            .map(|part| {
                (
                    part["path"].as_str().expect("ein Pfad").to_owned(),
                    part["encoding"]
                        .as_str()
                        .expect("eine Kodierung")
                        .to_owned(),
                )
            })
            .collect();
        let unique = resolved["x-ea-unique-key"]
            .as_array()
            .expect("ein sortiertes Array traegt einen Eindeutigkeitsschluessel")
            .iter()
            .map(|path| path.as_str().expect("ein Pfad").to_owned())
            .collect();
        rules.push(ArrayRuleV1 {
            name: name.clone(),
            sort,
            unique,
        });
    }
    rules
}

/// Der Vergleichswert eines Schluesselteils: Bytes, damit `uint`, `hex-bytes`
/// und `utf8` unter derselben Ordnung vergleichbar sind.
fn sort_key_part(element: &Value, path: &str, encoding: &str) -> Vec<u8> {
    let value = if path == "$" { element } else { &element[path] };
    match encoding {
        // Feste Breite, damit die Bytefolge dieselbe Ordnung traegt wie die Zahl.
        "uint" => value
            .as_u64()
            .expect("ein uint-Schluessel ist eine Zahl")
            .to_be_bytes()
            .to_vec(),
        "hex-bytes" => hex::decode(
            value
                .as_str()
                .expect("ein hex-Schluessel ist eine Zeichenkette"),
        )
        .expect("ein hex-Schluessel ist hexadezimal"),
        "utf8" => value
            .as_str()
            .expect("ein utf8-Schluessel ist eine Zeichenkette")
            .as_bytes()
            .to_vec(),
        other => panic!("unbekannte Schluesselkodierung {other}"),
    }
}

/// Prueft JEDES sortierte Array des Dokuments gegen die Regeln SEINES Schemas.
fn assert_sorted_and_unique(schema: &Value, document: &Value) {
    for rule in schema_array_rules(schema) {
        let ArrayRuleV1 { name, sort, unique } = rule;
        let array = document[&name]
            .as_array()
            .unwrap_or_else(|| panic!("{name} muss ein Array sein"));
        let keys: Vec<Vec<Vec<u8>>> = array
            .iter()
            .map(|element| {
                sort.iter()
                    .map(|(path, encoding)| sort_key_part(element, path, encoding))
                    .collect()
            })
            .collect();
        for pair in keys.windows(2) {
            assert!(
                pair[0] < pair[1],
                "{name} ist nicht streng aufsteigend nach seinem x-ea-sort-key sortiert"
            );
        }
        let mut unique_keys: Vec<Vec<&Value>> = array
            .iter()
            .map(|element| {
                unique
                    .iter()
                    .map(|path| if path == "$" { element } else { &element[path] })
                    .collect()
            })
            .collect();
        let total = unique_keys.len();
        unique_keys.sort_by_key(|key| {
            key.iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
        });
        unique_keys.dedup();
        assert_eq!(
            unique_keys.len(),
            total,
            "{name} traegt zwei Elemente mit demselben x-ea-unique-key"
        );
    }
}

/// EIN Bestand, der jedes Pflichtfeld des Berichts fuellt.
///
/// Er traegt Eintraege ueber ZWEI Registrierungsversionen, einen `.eds` mit
/// seiner Luecke, einen Vernichtungsvorgang mit Ereigniskette und
/// Loeschbestaetigung, ein isoliertes unlesbares Objekt, eine Dublette, einen
/// Widerspruch, ein Nicht-Archivobjekt, Quittungen fuer EINEN TEIL der
/// Eintraege, einen Checkpoint als Evidence-Objekt mit Serverzeitstempel und
/// einen Empfaengerschluessel, mit dem tatsaechlich entkapselt wird.
#[test]
fn a_complete_archive_report_fills_every_required_field_and_stays_byte_identical() {
    let built = complete_report_archive();
    let anchor = built.anchor();
    let recipient = complete_recipient_private_key();
    let options = VerifyOptions::new(UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1))
        .with_recipient(complete_recipient_key_thumbprint(), &recipient);

    let mut observer = RecordingObserver::new();
    let report = verify_archive_observed(&built.fixture, &anchor, options, &mut observer)
        .expect("der Gesamtbestand muss berichten");

    // Das Protokoll eines Bestands mit gueltigen Eintraegen: die NEUN Gates in
    // der Reihenfolge von GATE_ORDER_V1, danach — und als kein Gate — die
    // Entkapselung.
    let mut expected: Vec<&str> = GATE_ORDER_V1.to_vec();
    expected.push(DECAPSULATION_EVENT_V1);
    assert_eq!(observer.events(), expected.as_slice());

    let json = report
        .to_canonical_json()
        .expect("der kanonische Schreiber muss ausgeben");
    let document = parse(&json);
    let schema: Value =
        serde_json::from_str(REPORT_SCHEMA_V1).expect("das gepinnte Schema ist JSON");
    assert_valid_against_schema(&document);

    // Alle siebzehn Pflichtfelder liegen vor — die Liste stammt aus dem SCHEMA
    // und wird hier nicht abgeschrieben.
    let required: Vec<&str> = schema["required"]
        .as_array()
        .expect("das Schema nennt seine Pflichtfelder")
        .iter()
        .map(|name| name.as_str().expect("ein Feldname"))
        .collect();
    assert_eq!(required.len(), 17);
    for name in &required {
        assert!(
            document.get(*name).is_some(),
            "das Pflichtfeld {name} fehlt im Bericht"
        );
    }
    for name in REPORT_FILLED_ARRAY_FIELDS_V1 {
        assert_eq!(
            document[name].as_array().map(Vec::len).unwrap_or(0).min(1),
            1,
            "report json is missing a non-empty {name}"
        );
    }
    assert_sorted_and_unique(&schema, &document);

    // Die Zaehlinvariante aus design.md 11.4.
    assert_eq!(
        report.archive_object_count() + report.non_object_file_count(),
        built.fixture.len()
    );
    assert_eq!(report.non_object_file_count(), built.non_object_count);
    assert_eq!(report.destroyed_entry_count(), 1);
    assert_eq!(
        report.entry_package_count(),
        built.valid_entry_object_hashes.len() + 1 + built.conflicting_object_hashes.len(),
        "gezaehlt werden ALLE nach objectHash eindeutigen `.eip`, unabhaengig vom Gate-Ausgang"
    );

    // ZWEI Registrierungsversionen, und beide stammen aus Objekten, die Gate
    // manifest-signature BESTANDEN haben.
    let versions: Vec<_> = report.registry_versions().collect();
    assert_eq!(versions.len(), 2);
    assert!(versions[0] == built.early_registry_version);
    assert!(versions[1] == built.late_registry_version);

    // chainHead: die Kettenkennung IMMER aus dem Anker, die Sequenz aus dem
    // verifizierten Praefix — und ausdruecklich nicht das Sentinel.
    assert!(report.chain_head().chain_id() == anchor.chain_id());
    assert_eq!(
        report.chain_head().sequence().get(),
        REPORT_HEAD_SEQUENCE_V1
    );
    assert_ne!(report.chain_head().entry_hash().as_bytes(), &[0_u8; 32]);
    assert_eq!(
        document["chainHead"]["entryHash"].as_str().map(str::len),
        Some(64)
    );
    assert_ne!(document["chainHead"]["entryHash"], ZERO_HASH_HEX);

    // Die eine Luecke: das fehlende `.eip` unter dem Stummel.
    let gaps: Vec<_> = report.gaps().collect();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].from_sequence().get(), REPORT_GAP_FROM_V1);
    assert_eq!(gaps[0].through_sequence().get(), REPORT_GAP_THROUGH_V1);
    assert_eq!(
        gaps[0].from_sequence().get(),
        REPORT_DESTROYED_STUB_SEQUENCE_V1,
        "die Luecke liegt genau dort, wo der Stummel das `.eip` ersetzt"
    );

    // DER ZUSCHNITT, den dieser Test voraussetzt, wird an der MESSUNG geprueft
    // und nicht zwischen Konstanten behauptet: jeder Befund liegt oberhalb des
    // verifizierten Kopfes. Ruecke einer davon ins Praefix, endete der Kopf
    // davor, und mehrere Aussagen unten wuerden still etwas anderes messen.
    let verified_head = report.chain_head().sequence().get();
    for (name, sequence) in [
        ("der Stummel", REPORT_DESTROYED_STUB_SEQUENCE_V1),
        ("der Nachfolger der Luecke", REPORT_TRAILING_SEQUENCE_V1),
        ("die Dublette", REPORT_DUPLICATE_SEQUENCE_V1),
        ("der Widerspruch", REPORT_FORK_SEQUENCE_V1),
    ] {
        assert!(
            verified_head < sequence,
            "{name} muss oberhalb des verifizierten Kopfes liegen"
        );
    }
    assert!(
        verified_head > REPORT_EARLY_SEQUENCE_V1,
        "der verifizierte Kopf muss ueber die Lease des fruehen Kopfes hinausreichen,          sonst zeigt der Bestand keine zwei Registrierungsversionen im Praefix"
    );
    assert!(
        !REPORT_RECEIPTED_SEQUENCES_V1.contains(&verified_head),
        "die Sequenz des Kopfes traegt bewusst keine Quittung: `notServerConfirmed`          muss auch am Kopf sichtbar sein"
    );
    assert_eq!(verified_head, REPORT_UNCONFIRMED_SEQUENCE_V1);

    // Ein Objekt erscheint ENTWEDER in objectResults ODER in genau einem
    // Fehler-/Quarantaenearray, niemals in beidem.
    let results: Vec<_> = report
        .object_results()
        .map(|result| result.object_hash())
        .collect();
    assert_eq!(results.len(), built.valid_entry_object_hashes.len());
    for object_hash in &built.valid_entry_object_hashes {
        assert!(
            results.iter().any(|result| result == object_hash),
            "jeder unversehrte Eintrag traegt genau ein Ergebnis"
        );
    }
    let mut isolated: Vec<_> = report
        .quarantined_objects()
        .map(|entry| (entry.object_hash(), entry.reason()))
        .collect();
    isolated.sort_by_key(|(hash, _)| *hash);
    assert_eq!(isolated.len(), 4);
    for object_hash in results {
        assert!(
            !isolated
                .iter()
                .any(|(isolated, _)| *isolated == object_hash),
            "ein Objekt mit Ergebnis darf nicht zugleich isoliert sein"
        );
    }
    let reason_of = |wanted: ObjectHash| {
        isolated
            .iter()
            .find(|(hash, _)| *hash == wanted)
            .map(|(_, reason)| *reason)
    };
    assert_eq!(
        reason_of(built.malformed_object_hash),
        Some(QuarantineReason::Malformed)
    );
    assert_eq!(
        reason_of(built.duplicate_object_hash),
        Some(QuarantineReason::Duplicate)
    );
    for object_hash in &built.conflicting_object_hashes {
        assert_eq!(reason_of(*object_hash), Some(QuarantineReason::Conflicting));
    }
    // PAARWEISE: die unlesbaren Bytes tragen zugleich einen formatError.
    let format_errors: Vec<_> = report.format_errors().collect();
    assert_eq!(format_errors.len(), 1);
    assert!(format_errors[0].object_hash() == built.malformed_object_hash);

    // Quittungen fuer EINEN TEIL der Eintraege — und `notServerConfirmed` ist
    // kein Mangel.
    //
    // GEPRUEFT WIRD DIE MENGE, nicht ihre Groesse: eine blosse Zahl bliebe
    // richtig, wenn eine Fixture-Aenderung die Quittung auf einen ANDEREN
    // Eintrag schoebe, und der Test waere still aussagelos.
    let mut confirmed: Vec<ObjectHash> = report
        .object_results()
        .filter(|result| result.server_confirmation() == ServerConfirmationV1::ServerConfirmed)
        .map(|result| result.object_hash())
        .collect();
    confirmed.sort_unstable();
    let mut expected_confirmed = built.confirmed_entry_object_hashes.clone();
    expected_confirmed.sort_unstable();
    assert!(
        confirmed == expected_confirmed,
        "bestaetigt sind GENAU die Eintraege, zu denen eine Quittung im Bestand liegt"
    );
    assert!(
        confirmed.len() < report.object_results().len(),
        "der Bestand muss auch einen unbestaetigten Eintrag tragen, sonst zeigt er \
         `notServerConfirmed` gar nicht"
    );

    // Der Vernichtungsvorgang mit seiner Ereigniskette.
    let destructions: Vec<_> = report.authorized_destructions().collect();
    assert_eq!(destructions.len(), built.destructions.len());
    assert!(
        destructions[0].destruction_id() == built.destructions[0].destruction_id,
        "der Vorgang des Berichts ist der des Bestands"
    );
    assert_eq!(
        destructions[0].state(),
        DestructionStateV1::CompleteManagedScope
    );

    // Der Empfaengerschluessel hat tatsaechlich geoeffnet: kein
    // Entschluesselungsbefund, und das Protokoll traegt `hpke-open`.
    assert_eq!(report.decryption_errors().len(), 0);
    assert_eq!(report.evidence_errors().len(), 0);
    assert_eq!(report.signature_errors().len(), 0);

    // Der Bestand traegt Befunde — er ist deshalb NICHT vollstaendig
    // verifiziert. Das ist die Aussage, nicht ein Mangel des Tests.
    assert!(!report.is_fully_verified());

    // reportHash = SHA-256 ueber die kanonischen Bytes OHNE reportHash,
    // reportSignature und runtimeMetadata.
    let preimage = report
        .canonical_hash_preimage()
        .expect("der kanonische Schreiber muss das Urbild ausgeben");
    assert!(!preimage.contains("reportHash"));
    assert!(!preimage.contains("reportSignature"));
    assert!(!preimage.contains("runtimeMetadata"));
    assert!(report.report_hash() == verification_report_hash(preimage.as_bytes()));
    assert_eq!(
        document["reportHash"],
        Value::String(hex::encode(report.report_hash().as_bytes()))
    );

    // Zwei Laeufe, byteidentisch — und derselbe Bestand unter vertauschten
    // Pfadhinweisen ebenfalls.
    let again = verify_archive(&built.fixture, &anchor, options)
        .expect("der Gesamtbestand muss berichten")
        .to_canonical_json()
        .expect("der kanonische Schreiber muss ausgeben");
    assert_eq!(json, again);

    // DER VERGLEICH MUSS ETWAS ZU VERGLEICHEN HABEN. Ohne diese beiden Waechter
    // waere die Aussage still aussagelos, sobald `randomized_paths` je zur
    // Identitaet wuerde: die Hinweise MUESSEN sich unterscheiden, die Bytes als
    // Multimenge NICHT. Dieselbe Absicherung wie in
    // `crates/ea-verify/tests/isolation.rs`.
    let randomized = built.fixture.randomized_paths();
    let hints = |fixture: &ArchiveFixture| -> Vec<String> {
        fixture
            .blobs()
            .iter()
            .map(|(hint, _)| hint.clone())
            .collect()
    };
    let sorted_bytes = |fixture: &ArchiveFixture| -> Vec<Vec<u8>> {
        let mut bytes: Vec<Vec<u8>> = fixture
            .blobs()
            .iter()
            .map(|(_, blob)| blob.clone())
            .collect();
        bytes.sort_unstable();
        bytes
    };
    assert_ne!(
        hints(&built.fixture),
        hints(&randomized),
        "die Umbenennung muss die Hinweise wirklich vertauschen"
    );
    assert_eq!(
        sorted_bytes(&built.fixture),
        sorted_bytes(&randomized),
        "die Umbenennung darf keine Bytesequenz veraendern"
    );

    let shuffled = verify_archive(&randomized, &anchor, options)
        .expect("der Gesamtbestand muss auch unter anderen Hinweisen berichten")
        .to_canonical_json()
        .expect("der kanonische Schreiber muss ausgeben");
    assert_eq!(json, shuffled);
}
