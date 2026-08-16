#[path = "support/mod.rs"]
mod support;

use ea_archive::{ArchiveBlob, ArchiveError, ArchiveInventory, ArchiveSource, QuarantineReason};
use ea_crypto::object_hash;
use ea_types::ObjectHash;
use support::{
    ArchiveFixture, MUTATED_EIP_FORMAT_ERROR_CODE_V1, canonical_archive,
    eip_with_one_mutated_body_byte, signed_entry_package,
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
