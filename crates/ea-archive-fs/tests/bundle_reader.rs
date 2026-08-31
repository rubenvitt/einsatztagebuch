//! Der Containerleser ist STRENG und nicht nachsichtig.
//!
//! Ein nachsichtiger Leser liesse ein manipuliertes Buendel eine andere
//! Bytemenge vorzeigen als die, die sein Index beschreibt. Deshalb ist jede
//! Strukturverletzung ein Fehler und niemals ein uebersprungener Eintrag.
//!
//! # Die Positivkontrolle steht VOR der Schleife
//!
//! Fuenf Mutationen, die alle nur `is_err()` behaupten, waeren auch dann gruen,
//! wenn der Leser JEDES Buendel abwiese — und der Rundlaufbeweis liegt in einem
//! ANDEREN Testziel (`bundle_export.rs`), das dieser Datei nichts belegt.
//! `the_unmutated_export_parses` und die je Arm gepinnte Fehlerart sind
//! deshalb keine Zutat, sondern die Voraussetzung dafuer, dass die fuenf
//! Negativfaelle etwas bedeuten.

mod support;

use ea_archive::{MAX_ARCHIVE_BLOBS_V1, MAX_TOTAL_ARCHIVE_BYTES_V1};
use ea_archive_fs::{
    ArchiveBundleSource, BUNDLE_HEADER_BYTES_V1, BUNDLE_MAGIC_V1, BundleError,
    FORMAT_PACKAGE_FILES_V1, open_archive_bundle, write_archive_bundle,
};

use support::{BundleHarness, path_hints_of};

/// Ein zerlegtes Buendel: der Index als Satzliste, die Nutzlast als Block.
///
/// Die Mutationen arbeiten auf DIESER Form und nicht auf rohen Byteoffsets:
/// ein Indexsatz ist variabel lang, und eine Vertauschung „irgendwo bei Byte
/// 90" traefe je nach Pfadlaenge etwas anderes.
struct Dissected {
    records: Vec<(String, u64, u64)>,
    payload: Vec<u8>,
}

impl Dissected {
    fn of(bytes: &[u8]) -> Self {
        assert_eq!(&bytes[..BUNDLE_MAGIC_V1.len()], &BUNDLE_MAGIC_V1);
        let count = u64::from_be_bytes(bytes[32..40].try_into().unwrap());
        let index_length =
            usize::try_from(u64::from_be_bytes(bytes[40..48].try_into().unwrap())).unwrap();
        let index = &bytes[BUNDLE_HEADER_BYTES_V1..BUNDLE_HEADER_BYTES_V1 + index_length];
        let mut records = Vec::new();
        let mut at = 0;
        while at < index.len() {
            let path_length =
                usize::from(u16::from_be_bytes(index[at..at + 2].try_into().unwrap()));
            at += 2;
            let path = String::from_utf8(index[at..at + path_length].to_vec()).unwrap();
            at += path_length;
            let offset = u64::from_be_bytes(index[at..at + 8].try_into().unwrap());
            at += 8;
            let length = u64::from_be_bytes(index[at..at + 8].try_into().unwrap());
            at += 8;
            records.push((path, offset, length));
        }
        assert_eq!(u64::try_from(records.len()).unwrap(), count);
        Self {
            records,
            payload: bytes[BUNDLE_HEADER_BYTES_V1 + index_length..].to_vec(),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut index = Vec::new();
        for (path, offset, length) in &self.records {
            index.extend_from_slice(&u16::try_from(path.len()).unwrap().to_be_bytes());
            index.extend_from_slice(path.as_bytes());
            index.extend_from_slice(&offset.to_be_bytes());
            index.extend_from_slice(&length.to_be_bytes());
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&BUNDLE_MAGIC_V1);
        bytes.extend_from_slice(&u64::try_from(self.records.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(&u64::try_from(index.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(&index);
        bytes.extend_from_slice(&self.payload);
        bytes
    }
}

/// `&mut Vec<u8>` und nicht `&mut [u8]`: alle sechs Mutationen teilen EINEN
/// Funktionszeigertyp, und drei von ihnen ersetzen den Puffer vollstaendig.
#[allow(
    clippy::ptr_arg,
    reason = "gemeinsamer Funktionszeigertyp der Mutationen"
)]
fn flip_first_magic_byte(bytes: &mut Vec<u8>) {
    bytes[0] ^= 0x01;
}

fn insert_one_padding_byte_between_two_blobs(bytes: &mut Vec<u8>) {
    let dissected = Dissected::of(bytes);
    assert!(
        dissected.records.len() >= 2,
        "die Fixture MUSS mindestens zwei Blobs tragen"
    );
    let first_length = usize::try_from(dissected.records[0].2).unwrap();
    let at = bytes.len() - dissected.payload.len() + first_length;
    bytes.insert(at, 0x00);
}

fn swap_two_index_entries(bytes: &mut Vec<u8>) {
    let mut dissected = Dissected::of(bytes);
    dissected.records.swap(0, 1);
    *bytes = dissected.encode();
}

fn duplicate_one_index_path(bytes: &mut Vec<u8>) {
    let mut dissected = Dissected::of(bytes);
    dissected.records[1].0 = dissected.records[0].0.clone();
    *bytes = dissected.encode();
}

/// Vertauscht die OFFSETS der ersten zwei Blobs, ohne eine Laenge zu aendern.
///
/// Die gefaehrlichste der sechs Mutationen und die einzige, die nur die
/// ZUSAMMENHANGSREGEL abweist: die Summe der Laengen bleibt gleich der
/// Nutzlastlaenge, die Adressen bleiben aufsteigend, und jeder Bereich liegt
/// innerhalb der Datei — nur zeigt jede der zwei Adressen jetzt auf die Bytes
/// der ANDEREN. Ein nachsichtiger Leser gaebe hier Archivbytes unter dem
/// falschen Pfad heraus.
fn swap_the_two_payload_offsets(bytes: &mut Vec<u8>) {
    let mut dissected = Dissected::of(bytes);
    let first = dissected.records[0].1;
    let second = dissected.records[1].1;
    dissected.records[0].1 = second;
    dissected.records[1].1 = first;
    *bytes = dissected.encode();
}

fn drop_the_last_payload_byte(bytes: &mut Vec<u8>) {
    bytes.pop();
}

#[test]
fn the_unmutated_export_parses() {
    let bytes = BundleHarness::finalized_archive().exported_bytes();
    let source = ArchiveBundleSource::from_bytes(bytes)
        .expect("das unveraenderte Buendel MUSS getragen werden");
    assert!(
        path_hints_of(&source).len() >= 2,
        "die Fixture MUSS mindestens zwei Blobs tragen, sonst messen die Mutationen nichts"
    );
}

#[test]
fn the_reader_rejects_a_wrong_magic_a_gap_and_an_unsorted_index() {
    for (name, mutate, expected) in [
        (
            "magic",
            flip_first_magic_byte as fn(&mut Vec<u8>),
            BundleError::Malformed,
        ),
        (
            "gap",
            insert_one_padding_byte_between_two_blobs,
            BundleError::Malformed,
        ),
        ("order", swap_two_index_entries, BundleError::Malformed),
        (
            "duplicate",
            duplicate_one_index_path,
            BundleError::Malformed,
        ),
        (
            "offsets",
            swap_the_two_payload_offsets,
            BundleError::Malformed,
        ),
        (
            "truncated",
            drop_the_last_payload_byte,
            BundleError::Malformed,
        ),
    ] {
        let mut bytes = BundleHarness::finalized_archive().exported_bytes();
        mutate(&mut bytes);
        let outcome = ArchiveBundleSource::from_bytes(bytes);
        assert!(outcome.is_err(), "{name} muss abgewiesen werden");
        assert_eq!(
            outcome.err(),
            Some(expected),
            "{name} muss GENAU diesen Befund tragen"
        );
    }
}

#[test]
fn the_reader_enforces_the_same_caps_as_the_directory_reader() {
    let bytes = BundleHarness::synthetic_index_claiming(MAX_ARCHIVE_BLOBS_V1 + 1);
    assert!(matches!(
        ArchiveBundleSource::from_bytes(bytes),
        Err(BundleError::BlobLimit)
    ));
}

/// Der ZWEITE Deckel, den der Verzeichnisleser fuehrt.
///
/// Ein Bestand von mehr als zwei Gibibyte laesst sich in einem Test nicht
/// herstellen; ein Index, der so viele Bytes BEHAUPTET, schon. Genau das ist
/// der Angriff: eine Laengenangabe, die den Puffer aufblaeht, bevor irgendetwas
/// gelesen wurde.
#[test]
fn the_reader_refuses_an_index_that_claims_more_bytes_than_the_cap() {
    let path = b"entries/000000000000000000000000000.eip";
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&BUNDLE_MAGIC_V1);
    bytes.extend_from_slice(&1_u64.to_be_bytes());
    bytes.extend_from_slice(&u64::try_from(2 + path.len() + 8 + 8).unwrap().to_be_bytes());
    bytes.extend_from_slice(&u16::try_from(path.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(path);
    bytes.extend_from_slice(&0_u64.to_be_bytes());
    bytes
        .extend_from_slice(&(u64::try_from(MAX_TOTAL_ARCHIVE_BYTES_V1).unwrap() + 1).to_be_bytes());

    assert!(matches!(
        ArchiveBundleSource::from_bytes(bytes),
        Err(BundleError::TotalByteLimit)
    ));
}

#[test]
fn the_bundle_carries_the_format_package_and_every_non_object_file() {
    // Ein Bestand, dem das Beiwerk FEHLT: nur so ist Schritt 1 des Exports von
    // seiner Abwesenheit unterscheidbar.
    let harness = BundleHarness::without_the_format_package();
    for (missing, _) in FORMAT_PACKAGE_FILES_V1 {
        assert!(
            !harness.backend().exists_for_test(missing),
            "{missing} darf VOR dem Export nicht liegen"
        );
    }
    write_archive_bundle(
        harness.backend(),
        harness.anchor(),
        harness.os_wall_clock(),
        &harness.bundle_path(),
    )
    .unwrap();
    let bundle = open_archive_bundle(&harness.bundle_path()).unwrap();
    let paths = path_hints_of(&bundle);
    for (expected, _) in FORMAT_PACKAGE_FILES_V1 {
        assert!(
            paths.iter().any(|path| path.as_str() == *expected),
            "{expected} fehlt im Buendel"
        );
    }
    assert!(paths.contains(&ea_archive::README_FORMAT_FILE_V1.to_owned()));
}

/// Die STABILEN Fehlercodes des Containers.
///
/// Fuenf der sechs Varianten sind in diesem Ziel und in `bundle_export.rs`
/// ueber den VARIANTENNAMEN erreicht — `BundleError` ist `PartialEq`, also
/// vergleichen jene Zusicherungen Werte und nie Zeichenketten. Der Fehlercode
/// ist aber eine eigene Zusage: er verlaesst die Crate, und ein Aufrufer
/// assertiert gegen ihn. Wanderte er, faende es keine dieser Zusicherungen.
///
/// `Io` steht mit dabei, obwohl kein Test seinen PFAD faehrt: der Vertrag
/// umfasst ihn, und den Code zu pinnen ist eine andere Aussage als das
/// Wirtdateisystem zu einer Ablehnung zu zwingen. Dieselbe Begruendung wie
/// `ChainError::NodeLimit` in `crates/ea-chain/tests/chain_core.rs`:149.
#[test]
fn every_bundle_error_keeps_its_stable_code() {
    assert_eq!(
        BundleError::SourceNotFullyVerified.code(),
        "EA-BUNDLE-SOURCE-NOT-FULLY-VERIFIED"
    );
    assert_eq!(
        BundleError::TargetOccupied.code(),
        "EA-BUNDLE-TARGET-OCCUPIED"
    );
    assert_eq!(BundleError::Malformed.code(), "EA-BUNDLE-MALFORMED");
    assert_eq!(BundleError::BlobLimit.code(), "EA-BUNDLE-BLOB-LIMIT");
    assert_eq!(
        BundleError::TotalByteLimit.code(),
        "EA-BUNDLE-TOTAL-BYTE-LIMIT"
    );
    assert_eq!(BundleError::Io.code(), "EA-BUNDLE-IO");
}
