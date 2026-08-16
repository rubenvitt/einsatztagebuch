#[path = "support/mod.rs"]
mod support;

use ea_archive::{ArchiveBlob, ArchiveError, ArchiveInventory, ArchiveSource, QuarantineReason};
use ea_crypto::object_hash;
use ea_format::{
    EntryPackageV1, ParsedArchiveObject, ReceiptCoreFieldsV1, ReceiptCoreV1, ReceiptV1,
    decode_exact_object, encode_receipt,
};
use ea_types::{ChainSequence, ObjectHash, RegistryVersion, UnixMillis};
use support::{
    ArchiveFixture, MUTATED_EIP_FORMAT_ERROR_CODE_V1, canonical_archive,
    eip_with_one_mutated_body_byte, format_support, signed_entry_package,
};

/// Ein Objekthash als Hex.
///
/// `ea-types` leitet fuer Hashtypen kein `Debug` ab; verglichen wird deshalb
/// die Hexdarstellung, die im Fehlerfall auch lesbar ist.
fn hex(hash: ObjectHash) -> String {
    ::hex::encode(hash.as_bytes())
}

/// Passt `code` auf `^EA-[A-Z0-9-]+$` aus
/// `schemas/reports/v1/verification-report.schema.json`?
///
/// Von Hand geprueft statt mit einer Regex-Crate: das Muster ist geschlossen
/// und `ea-archive` zieht dafuer keine Abhaengigkeit.
fn matches_report_error_code_pattern(code: &str) -> bool {
    let Some(rest) = code.strip_prefix("EA-") else {
        return false;
    };
    !rest.is_empty()
        && rest.chars().all(|character| {
            character.is_ascii_uppercase() || character.is_ascii_digit() || character == '-'
        })
}

/// Ein Bestand, der dieselbe Bytesequenz `count`-mal liefert, ohne sie
/// `count`-mal abzulegen.
///
/// Nur so lassen sich [`ea_archive::MAX_ARCHIVE_BLOBS_V1`] und
/// [`ea_archive::MAX_TOTAL_ARCHIVE_BYTES_V1`] pruefen, ohne den Speicher eines
/// Bestands dieser Groesse zu belegen.
struct RepeatingSource<'a> {
    count: usize,
    path_hint: &'a str,
    bytes: &'a [u8],
}

impl ArchiveSource for RepeatingSource<'_> {
    fn visit_blobs(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        for _ in 0..self.count {
            visitor(ArchiveBlob::new(self.path_hint, self.bytes))?;
        }
        Ok(())
    }
}

/// Die drei Inventarklassen aus `design.md` §11.4 entstehen am 9-Byte-Exact-
/// Object-Praefix, nie am Dateinamen.
///
/// Ein gueltiges `.eip` unter `README-FORMAT.txt` ist ein Archivobjekt; eine
/// Textdatei unter `entries/` ist keines und zaehlt nur in
/// `nonObjectFileCount`. Traegt eine Bytesequenz das Praefix und scheitert
/// dennoch am Parser, entstehen PAARWEISE ein `formatError` und ein
/// Quarantaeneeintrag mit Grund `malformed` — beide ueber denselben
/// Objekthash, der auch fuer nicht parsbare Bytes berechenbar ist.
#[test]
fn the_prefix_decides_the_inventory_class_not_the_file_name() {
    let (_, eip) = signed_entry_package();
    let malformed = eip_with_one_mutated_body_byte();

    let mut fixture = ArchiveFixture::new();
    // Ein gueltiges Objekt unter dem Beiwerk-Pfad: bleibt ein Archivobjekt.
    fixture.push_exact_bytes(ea_archive::README_FORMAT_FILE_V1, eip.clone());
    // Klartext unter entries/: bleibt Beiwerk.
    fixture.push_non_object(
        &format!("{}notiz.txt", ea_archive::ENTRIES_DIR_V1),
        b"kein Archivobjekt, nur Text\n",
    );
    // Dieselben unlesbaren Bytes zweimal, unter verschiedenen Hinweisen: die
    // Zaehlung sieht zwei Bytesequenzen, die Befundlisten genau einen Befund.
    fixture.push_exact_bytes(
        &format!("{}kaputt.eip", ea_archive::ENTRIES_DIR_V1),
        malformed.clone(),
    );
    fixture.push_exact_bytes(
        &format!("{}kaputt-noch-einmal.bin", ea_archive::FORMAT_DIR_V1),
        malformed.clone(),
    );

    let inventory = ArchiveInventory::build(&fixture).expect("an in-memory source must complete");

    // Klasse 1: Bytes MIT Praefix.
    assert_eq!(
        inventory.archive_object_count(),
        3,
        "archiveObjectCount counts byte sequences with the prefix, parsed or not"
    );
    assert_eq!(inventory.entries().len(), 1);
    assert_eq!(
        hex(inventory.entries()[0].object_hash()),
        hex(object_hash(&eip))
    );
    assert!(inventory.grants().is_empty());
    assert!(inventory.receipts().is_empty());
    assert!(inventory.evidence().is_empty());
    assert!(inventory.trust().is_empty());
    assert!(inventory.destroyed().is_empty());

    // Klasse 2: Bytes OHNE Praefix.
    assert_eq!(
        inventory.non_object_file_count(),
        1,
        "plain text under entries/ is not an archive object"
    );

    // Klasse 3: Praefix vorhanden, Parser gescheitert — paarweise.
    let malformed_hash = object_hash(&malformed);
    assert_eq!(
        inventory.format_errors().len(),
        1,
        "identical malformed bytes are one finding, not two"
    );
    assert_eq!(
        hex(inventory.format_errors()[0].object_hash()),
        hex(malformed_hash)
    );
    assert_eq!(
        inventory.format_errors()[0].code(),
        MUTATED_EIP_FORMAT_ERROR_CODE_V1
    );
    assert!(
        inventory.format_errors()[0]
            .code()
            .starts_with("EA-FORMAT-"),
        "a parse failure carries a FormatError::code()"
    );
    assert!(matches_report_error_code_pattern(
        inventory.format_errors()[0].code()
    ));

    assert_eq!(inventory.quarantined().len(), 1);
    assert_eq!(
        inventory.quarantined()[0].reason(),
        QuarantineReason::Malformed
    );
    assert_eq!(
        hex(inventory.quarantined()[0].object_hash()),
        hex(malformed_hash)
    );

    // Die Kopplung ist die Invariante: jeder Malformed-Eintrag hat genau einen
    // formatError ueber demselben Objekthash.
    let malformed_quarantined: Vec<_> = inventory
        .quarantined()
        .iter()
        .filter(|entry| entry.reason() == QuarantineReason::Malformed)
        .map(|entry| hex(entry.object_hash()))
        .collect();
    let format_error_hashes: Vec<_> = inventory
        .format_errors()
        .iter()
        .map(|entry| hex(entry.object_hash()))
        .collect();
    assert_eq!(malformed_quarantined, format_error_hashes);

    // Ein Objekt erscheint ENTWEDER im Inventar ODER in der Quarantaene.
    assert!(
        inventory
            .entries()
            .iter()
            .all(|entry| entry.object_hash() != malformed_hash),
        "a quarantined object never appears among the parsed objects"
    );

    // Die Zaehlinvariante aus §11.4.
    assert_eq!(
        inventory.archive_object_count() + inventory.non_object_file_count(),
        fixture.len(),
        "every delivered byte sequence falls into exactly one of the two counts"
    );
}

/// Der kanonische Bestand fuellt alle sechs Objektfamilien und erzeugt keinen
/// einzigen Befund.
#[test]
fn the_canonical_archive_inventories_every_object_family() {
    let built = canonical_archive();
    let inventory =
        ArchiveInventory::build(&built.fixture).expect("an in-memory source must complete");

    assert_eq!(inventory.entries().len(), 1);
    assert_eq!(inventory.grants().len(), 1);
    assert_eq!(inventory.receipts().len(), 1);
    assert_eq!(inventory.evidence().len(), 1);
    assert_eq!(inventory.destroyed().len(), 1);
    assert_eq!(inventory.trust().len(), built.trust_object_count);

    assert!(inventory.quarantined().is_empty());
    assert!(inventory.format_errors().is_empty());
    assert_eq!(inventory.non_object_file_count(), built.non_object_count);
    assert_eq!(
        inventory.archive_object_count() + inventory.non_object_file_count(),
        built.fixture.len()
    );

    // Der Trust Anchor ist NIE Teil der Klassifikation: er kommt als Parameter.
    let anchor_hash = object_hash(&built.anchor_bytes);
    assert!(
        inventory
            .trust()
            .iter()
            .all(|object| object.object_hash() != anchor_hash)
    );

    // Umbenennen aendert am Inventar nichts.
    let renamed = ArchiveInventory::build(&built.fixture.randomized_paths())
        .expect("an in-memory source must complete");
    assert_eq!(renamed.entries().len(), inventory.entries().len());
    assert_eq!(
        renamed.non_object_file_count(),
        inventory.non_object_file_count()
    );
    assert_eq!(
        renamed.archive_object_count(),
        inventory.archive_object_count()
    );
}

/// Die Schranken liefern `Err`, nie eine Panik — und brechen ab, ohne den Rest
/// zu lesen.
#[test]
fn exceeding_the_archive_limits_yields_an_error_instead_of_a_panic() {
    let at_the_blob_limit = RepeatingSource {
        count: ea_archive::MAX_ARCHIVE_BLOBS_V1,
        path_hint: "beiwerk.bin",
        bytes: b"x",
    };
    let inventory = ArchiveInventory::build(&at_the_blob_limit)
        .expect("exactly MAX_ARCHIVE_BLOBS_V1 blobs must still be inventoried");
    assert_eq!(
        inventory.non_object_file_count(),
        ea_archive::MAX_ARCHIVE_BLOBS_V1
    );

    let over_the_blob_limit = RepeatingSource {
        count: ea_archive::MAX_ARCHIVE_BLOBS_V1 + 1,
        path_hint: "beiwerk.bin",
        bytes: b"x",
    };
    assert_eq!(
        ArchiveInventory::build(&over_the_blob_limit).err(),
        Some(ArchiveError::BlobLimit)
    );

    // 2049 MiB uebersteigen MAX_TOTAL_ARCHIVE_BYTES_V1 (2 GiB) — aus einer
    // einzigen Belegung von 1 MiB.
    const MIB: usize = 1024 * 1024;
    let chunk = vec![0_u8; MIB];
    let over_the_byte_limit = RepeatingSource {
        count: ea_archive::MAX_TOTAL_ARCHIVE_BYTES_V1 / MIB + 1,
        path_hint: "grosses-beiwerk.bin",
        bytes: &chunk,
    };
    assert_eq!(
        ArchiveInventory::build(&over_the_byte_limit).err(),
        Some(ArchiveError::TotalByteLimit)
    );
}

/// Derselbe Bestand, rueckwaerts durchlaufen.
///
/// Die Befunde duerfen nicht davon abhaengen, in welcher Reihenfolge der Port
/// die Bytes liefert. Deterministisch umgedreht statt zufaellig gemischt, damit
/// ein Fehlschlag reproduzierbar ist.
struct ReversedSource<'a>(&'a ArchiveFixture);

impl ArchiveSource for ReversedSource<'_> {
    fn visit_blobs(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        for (path_hint, bytes) in self.0.blobs().iter().rev() {
            visitor(ArchiveBlob::new(path_hint, bytes))?;
        }
        Ok(())
    }
}

/// Die Quarantaenebefunde als lesbare Paare `(Objekthash-Hex, Grund)`.
fn findings(inventory: &ArchiveInventory) -> Vec<(String, QuarantineReason)> {
    inventory
        .quarantined()
        .iter()
        .map(|entry| (hex(entry.object_hash()), entry.reason()))
        .collect()
}

/// Der `EntryPackageV1` hinter fertigen `.eip`-Bytes.
///
/// Der Wert wird gebraucht, um daraus ein `.eds` zu bauen; gelesen wird er ueber
/// denselben Parser, den auch das Inventar benutzt.
fn parsed_entry(eip: &[u8]) -> EntryPackageV1 {
    match decode_exact_object(eip).expect("the fixture entry package must parse") {
        ParsedArchiveObject::Entry(value) => value.value().clone(),
        other => panic!("expected an entry package, got {other:?}"),
    }
}

/// Ein gueltiges `.esr` auf `entry_object_hash = hash32(4)`, unterschieden
/// allein durch `accepted_at_server`.
///
/// Zwei so gebaute Quittungen sind VERSCHIEDENE Objekte (verschiedener
/// `object_hash`), die dieselbe Identitaet behaupten — genau der dritte
/// Konfliktfall. `server_key_thumbprint` MUSS der Daumenabdruck des
/// Fixture-Signierers sein, sonst weist `ReceiptV1::new` die Signatur zurueck.
fn rival_receipt(accepted_at_server: i64) -> Vec<u8> {
    let core = ReceiptCoreV1::new(ReceiptCoreFieldsV1 {
        organization_id: format_support::organization(1),
        chain_id: format_support::chain(2),
        chain_sequence: ChainSequence::new(0),
        entry_hash: format_support::entry_hash(3),
        entry_object_hash: format_support::typed_object_hash(4),
        previous_entry_hash: None,
        registry_version: RegistryVersion::new(4),
        registry_head_hash: format_support::typed_hash(5),
        policy_object_hash: format_support::typed_object_hash(6),
        initial_grant_plan_hash: format_support::typed_hash(7),
        initial_grant_object_hashes: vec![format_support::typed_object_hash(8)],
        accepted_at_server: UnixMillis::new(accepted_at_server),
        evidence_due_at: None,
        server_key_thumbprint: format_support::signer_thumbprint(),
        server_certificate_hash: format_support::certificate(3),
    })
    .expect("the fixture receipt core must encode");
    let signature = format_support::signer()
        .sign_receipt(core.exact_bytes())
        .expect("the fixture signer must sign the receipt");
    let receipt = ReceiptV1::new(core, signature).expect("the fixture receipt must assemble");
    encode_receipt(&receipt)
        .expect("the fixture receipt must encode")
        .into_vec()
}

/// Die beiden bestandsbezogenen Quarantaenegruende entstehen am `object_hash`,
/// nie am Dateinamen.
///
/// `duplicate`: bytegleiche Kopien unter mehreren Pfaden. Die erste bleibt das
/// inventarisierte Objekt; die Kopien erzeugen zusammen GENAU EINEN Eintrag,
/// weil `quarantinedObjects` im Bericht nach `objectHash` eindeutig ist.
///
/// `conflicting`: verschiedene Objekte, die dieselbe Identitaet behaupten. Dann
/// werden BEIDE isoliert — es wird nicht stillschweigend nach Reihenfolge
/// entschieden.
///
/// Ein `.eds` ist dabei NICHT automatisch mit dem `.eip` in Konflikt, das es
/// ersetzt: es traegt dessen `original_eip_object_hash` bewusst. Konflikt ist
/// nur, wenn zwei VERSCHIEDENE urspruengliche Eintraege fuer dieselbe Sequenz
/// Verifikationsanspruch erheben.
#[test]
fn identical_bytes_are_duplicates_and_rival_identities_are_conflicting() {
    let eag = format_support::valid_initial_eag();
    let eip_a = format_support::valid_eip(vec![0x55; 16]);
    let eip_b = format_support::valid_eip(vec![0x56; 16]);
    assert_ne!(
        hex(object_hash(&eip_a)),
        hex(object_hash(&eip_b)),
        "the two rivals must be different objects"
    );

    let mut fixture = ArchiveFixture::new();
    // Dieselbe Zusage dreimal, unter drei Pfaden: drei Bytesequenzen, ein
    // Befund.
    for index in 0..3 {
        fixture.push_exact_bytes(
            &format!("{}kopie-{index}.eag", ea_archive::GRANTS_DIR_V1),
            eag.clone(),
        );
    }
    // Zwei verschiedene Eintragspakete auf derselben chain_id und derselben
    // chain_sequence: eine Sequenzkollision.
    fixture.push_exact_bytes(
        &format!("{}000000000000_a.eip", ea_archive::ENTRIES_DIR_V1),
        eip_a.clone(),
    );
    fixture.push_exact_bytes(
        &format!("{}000000000000_b.eip", ea_archive::ENTRIES_DIR_V1),
        eip_b.clone(),
    );

    let inventory = ArchiveInventory::build(&fixture).expect("an in-memory source must complete");

    assert_eq!(inventory.quarantined().len(), 3, "quarantined objects");

    let mut expected = vec![
        (hex(object_hash(&eag)), QuarantineReason::Duplicate),
        (hex(object_hash(&eip_a)), QuarantineReason::Conflicting),
        (hex(object_hash(&eip_b)), QuarantineReason::Conflicting),
    ];
    expected.sort();
    assert_eq!(findings(&inventory), expected);

    // Die Zaehler zaehlen weiterhin Bytesequenzen, nicht Befunde.
    assert_eq!(
        inventory.archive_object_count(),
        5,
        "archive_object_count counts every byte sequence with the prefix"
    );
    assert_eq!(
        inventory.archive_object_count() + inventory.non_object_file_count(),
        fixture.len()
    );
    // Die Familien bleiben nach object_hash eindeutig: die Kopien fallen
    // zusammen, die Rivalen bleiben beide geparst.
    assert_eq!(inventory.grants().len(), 1);
    assert_eq!(inventory.entries().len(), 2);
    // Ein Konflikt erzeugt keinen formatError: die Bytes sind lesbar.
    assert!(inventory.format_errors().is_empty());

    // Die Eingabereihenfolge veraendert den Befund nicht.
    let reversed = ArchiveInventory::build(&ReversedSource(&fixture))
        .expect("an in-memory source must complete");
    assert_eq!(inventory.quarantined(), reversed.quarantined());
    assert_eq!(
        inventory.archive_object_count(),
        reversed.archive_object_count()
    );

    // Zweiter Konfliktfall: ein `.eip` und ein `.eds`, das fuer dieselbe
    // Sequenz einen ANDEREN urspruenglichen Eintrag beansprucht.
    let eds_b = format_support::valid_eds_from_entry(&parsed_entry(&eip_b), &eip_b);
    let mut rival_stub = ArchiveFixture::new();
    rival_stub.push_exact_bytes(
        &format!("{}000000000000_a.eip", ea_archive::ENTRIES_DIR_V1),
        eip_a.clone(),
    );
    rival_stub.push_exact_bytes(
        &format!("{}000000000000_b.eds", ea_archive::DESTROYED_ENTRIES_DIR_V1),
        eds_b.clone(),
    );
    let inventory =
        ArchiveInventory::build(&rival_stub).expect("an in-memory source must complete");
    let mut expected = vec![
        (hex(object_hash(&eip_a)), QuarantineReason::Conflicting),
        (hex(object_hash(&eds_b)), QuarantineReason::Conflicting),
    ];
    expected.sort();
    assert_eq!(
        findings(&inventory),
        expected,
        "both rivals are isolated, never only the later one"
    );
    let reversed = ArchiveInventory::build(&ReversedSource(&rival_stub))
        .expect("an in-memory source must complete");
    assert_eq!(inventory.quarantined(), reversed.quarantined());

    // ABGRENZUNG: dasselbe `.eds` NEBEN dem `.eip`, das es ersetzt, ist kein
    // Konflikt — es traegt dessen original_eip_object_hash bewusst.
    let mut replaced = ArchiveFixture::new();
    replaced.push_exact_bytes(
        &format!("{}000000000000_b.eip", ea_archive::ENTRIES_DIR_V1),
        eip_b.clone(),
    );
    replaced.push_exact_bytes(
        &format!("{}000000000000_b.eds", ea_archive::DESTROYED_ENTRIES_DIR_V1),
        eds_b.clone(),
    );
    let inventory = ArchiveInventory::build(&replaced).expect("an in-memory source must complete");
    assert!(
        inventory.quarantined().is_empty(),
        "a stub is not in conflict with the entry package it replaces: {:?}",
        inventory.quarantined()
    );

    // ABGRENZUNG: nur der Stub, ohne rivalisierendes `.eip`, ist der Normalfall
    // autorisiert vernichtet.
    let mut stub_only = ArchiveFixture::new();
    stub_only.push_exact_bytes(
        &format!("{}000000000000_b.eds", ea_archive::DESTROYED_ENTRIES_DIR_V1),
        eds_b.clone(),
    );
    let inventory = ArchiveInventory::build(&stub_only).expect("an in-memory source must complete");
    assert!(
        inventory.quarantined().is_empty(),
        "a lone stub is the authorized-destroyed normal case: {:?}",
        inventory.quarantined()
    );

    // Dritter Konfliktfall: zwei `.esr` auf demselben entry_object_hash mit
    // verschiedenen Bytes.
    let esr_early = rival_receipt(9);
    let esr_late = rival_receipt(10);
    assert_ne!(hex(object_hash(&esr_early)), hex(object_hash(&esr_late)));
    let mut rival_receipts = ArchiveFixture::new();
    rival_receipts.push_exact_bytes(
        &format!("{}frueh.esr", ea_archive::RECEIPTS_DIR_V1),
        esr_early.clone(),
    );
    rival_receipts.push_exact_bytes(
        &format!("{}spaet.esr", ea_archive::RECEIPTS_DIR_V1),
        esr_late.clone(),
    );
    let inventory =
        ArchiveInventory::build(&rival_receipts).expect("an in-memory source must complete");
    let mut expected = vec![
        (hex(object_hash(&esr_early)), QuarantineReason::Conflicting),
        (hex(object_hash(&esr_late)), QuarantineReason::Conflicting),
    ];
    expected.sort();
    assert_eq!(findings(&inventory), expected);
    let reversed = ArchiveInventory::build(&ReversedSource(&rival_receipts))
        .expect("an in-memory source must complete");
    assert_eq!(inventory.quarantined(), reversed.quarantined());

    // Vorrang: ein Objekt, das ZUGLEICH doppelt liegt und rivalisiert, traegt
    // `conflicting`. Der inhaltliche Widerspruch verdraengt die blosse
    // Wiederholung — es bleibt bei genau einem Grund je Objekthash.
    let mut duplicated_rival = ArchiveFixture::new();
    for index in 0..2 {
        duplicated_rival.push_exact_bytes(
            &format!("{}kopie-{index}_a.eip", ea_archive::ENTRIES_DIR_V1),
            eip_a.clone(),
        );
    }
    duplicated_rival.push_exact_bytes(
        &format!("{}000000000000_b.eip", ea_archive::ENTRIES_DIR_V1),
        eip_b.clone(),
    );
    let inventory =
        ArchiveInventory::build(&duplicated_rival).expect("an in-memory source must complete");
    let mut expected = vec![
        (hex(object_hash(&eip_a)), QuarantineReason::Conflicting),
        (hex(object_hash(&eip_b)), QuarantineReason::Conflicting),
    ];
    expected.sort();
    assert_eq!(
        findings(&inventory),
        expected,
        "conflicting outranks duplicate"
    );
    assert_eq!(inventory.archive_object_count(), 3);

    // Unlesbare Bytes bleiben `malformed`: der Grund mit dem gepinnten
    // formatError verdraengt den blossen Wiederholungsbefund.
    let malformed = eip_with_one_mutated_body_byte();
    let mut repeated_malformed = ArchiveFixture::new();
    for index in 0..2 {
        repeated_malformed.push_exact_bytes(&format!("kaputt-{index}.bin"), malformed.clone());
    }
    let inventory =
        ArchiveInventory::build(&repeated_malformed).expect("an in-memory source must complete");
    assert_eq!(
        findings(&inventory),
        vec![(hex(object_hash(&malformed)), QuarantineReason::Malformed)],
        "malformed outranks duplicate so the pairing with formatErrors holds"
    );
    assert_eq!(inventory.format_errors().len(), 1);
}

/// Die Quarantaenegruende sind die geschlossene Menge des Reportschemas.
#[test]
fn the_quarantine_reasons_are_the_closed_set_of_the_report_schema() {
    for (reason, literal) in [
        (QuarantineReason::Malformed, "malformed"),
        (QuarantineReason::Duplicate, "duplicate"),
        (QuarantineReason::Conflicting, "conflicting"),
        (QuarantineReason::Unattributable, "unattributable"),
    ] {
        assert_eq!(reason.as_str(), literal);
    }
}
