//! Der kanonische Verifikationsbericht gegen sein gepinntes JSON-Schema.
//!
//! Der Schemanachweis liegt BEWUSST hier und nicht in `ea-verify`: `jsonschema`
//! zoege `getrandom 0.3.4` in den wasm-Graphen, und `ea-verify` steht auf der
//! wasm32-Positivliste von `tools/xtask/src/main.rs`. `ea-verify` schreibt
//! deshalb einen eigenen kanonischen JSON-Writer; hier wird belegt, dass dessen
//! Ausgabe das Schema erfuellt.

/// Die Archivfixtures, per `#[path]` eingebunden statt ueber eine optionale
/// Dependency. Bindet seinerseits die Trust- und Formatfixtures ein.
#[path = "../../../crates/ea-archive/tests/support/mod.rs"]
mod support;

use ea_archive::ArchiveSource;
use ea_crypto::{object_hash, verification_report_hash};
use ea_format::CertificateKindV1;
use ea_trust::{TrustAnchorV1, TrustObjectSource, decode_trust_anchor};
use ea_types::UnixMillis;
use ea_verify::{VerificationReportV1, VerifyOptions, verify_archive};
use serde_json::Value;

use support::{
    ArchiveFixture, FIXTURE_TIME_FLOOR_V1, MUTATED_EIP_FORMAT_ERROR_CODE_V1,
    eip_with_one_mutated_body_byte,
    trust_support::{ActionSpec, HeadOptions, RegistryLineBuilder},
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
        "publicKeyThumbprints",
    ] {
        assert_eq!(
            document[empty].as_array().map(Vec::len),
            Some(0),
            "{empty} must be empty while only the format gate has run"
        );
    }
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
