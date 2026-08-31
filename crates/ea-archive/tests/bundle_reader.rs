//! Der Containerleser, gemessen OHNE Wirtsdateisystem.
//!
//! Dieses Ziel ist der Zeuge des Umzugs: es liegt in der Crate, die kein
//! `std::fs` beruehrt, und es baut seine Bytes von Hand. Die fuenf
//! Strukturmutationen bleiben in `crates/ea-archive-fs/tests/bundle_reader.rs`
//! — sie mutieren einen ECHTEN Export aus `write_archive_bundle`, und einen
//! Schreiber hat diese Crate nicht.

use ea_archive::{
    ArchiveBlob, ArchiveBundleSource, ArchiveSource, BUNDLE_HEADER_BYTES_V1, BUNDLE_MAGIC_V1,
    BundleError, MAX_ARCHIVE_BLOBS_V1,
};

/// Baut Containerbytes von Hand, nach dem Format der Moduldoku von
/// `crates/ea-archive/src/bundle.rs` und nach nichts sonst.
///
/// Von Hand, und das ist die Aussage: `encode_bundle` lebt in
/// `crates/ea-archive-fs` und ist von hier aus unerreichbar. Ein zweiter
/// Kodierer neben dem Leser waere ohnehin der schwaechere Zeuge — beide truegen
/// dieselbe Abweichung und blieben gruen.
///
/// Die Saetze werden in der uebergebenen Reihenfolge geschrieben, die Offsets
/// zusammenhaengend ab null. Die STRENG aufsteigende Sortierung der Adressen
/// bleibt damit eine Zusage des Aufrufers — genau wie beim Export, dessen
/// Adressen aus dem Verzeichnisdurchlauf kommen.
fn hand_built_container(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut index = Vec::new();
    let mut offset: u64 = 0;
    for (path, bytes) in entries {
        index.extend_from_slice(&u16::try_from(path.len()).unwrap().to_be_bytes());
        index.extend_from_slice(path.as_bytes());
        index.extend_from_slice(&offset.to_be_bytes());
        index.extend_from_slice(&u64::try_from(bytes.len()).unwrap().to_be_bytes());
        offset += u64::try_from(bytes.len()).unwrap();
    }

    let mut container = Vec::new();
    container.extend_from_slice(&BUNDLE_MAGIC_V1);
    container.extend_from_slice(&u64::try_from(entries.len()).unwrap().to_be_bytes());
    container.extend_from_slice(&u64::try_from(index.len()).unwrap().to_be_bytes());
    container.extend_from_slice(&index);
    for (_, bytes) in entries {
        container.extend_from_slice(bytes);
    }
    container
}

/// Positivkontrolle ZUERST — die Regel, die `crates/ea-archive-fs/tests/bundle_reader.rs`
/// in seinem Kopf schon aufschreibt: Negativfaelle, die nur `is_err()` behaupten,
/// waeren auch dann gruen, wenn der Leser jeden Container abwiese.
#[test]
fn a_hand_built_container_hands_out_its_blobs_without_touching_the_filesystem() {
    let bytes = hand_built_container(&[("trust/root.etb", b"AAAA"), ("trust/z.etb", b"BB")]);
    let bundle = ArchiveBundleSource::from_bytes(bytes).unwrap();
    let mut seen: Vec<(String, Vec<u8>)> = Vec::new();
    bundle
        .visit_blobs(&mut |blob: ArchiveBlob<'_>| {
            seen.push((blob.path_hint().to_owned(), blob.bytes().to_vec()));
            Ok(())
        })
        .unwrap();
    assert_eq!(
        seen.len(),
        2,
        "beide Blobs muessen herauskommen, nicht einer"
    );
    assert_eq!(seen[0].0, "trust/root.etb");
    assert_eq!(seen[1].1, b"BB".to_vec());
}

/// Die Blobzahl wird aus dem KOPF durchgesetzt, bevor ein Indexsatz angefasst
/// wird. Der Zeuge misst genau diese Reihenfolge: der Kopf luegt, der Index ist
/// leer, und der Befund muss trotzdem `BlobLimit` sein und nicht `Malformed`.
///
/// Verglichen wird ueber `.err()` und nicht ueber den ganzen `Result`:
/// [`ArchiveBundleSource`] traegt bewusst weder `Debug` noch `PartialEq` — der
/// Typ haelt den vollstaendigen Bestand im Speicher —, und `assert_eq!` ueber
/// dem `Result` verlangte beides. Dieselbe Form benutzt der Einheitentest des
/// Wirtsteils in `crates/ea-archive-fs/src/bundle.rs`.
#[test]
fn the_blob_count_is_refused_from_the_header_before_any_index_record() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&BUNDLE_MAGIC_V1);
    bytes.extend_from_slice(&(MAX_ARCHIVE_BLOBS_V1 as u64 + 1).to_be_bytes());
    bytes.extend_from_slice(&0u64.to_be_bytes());
    assert_eq!(bytes.len(), BUNDLE_HEADER_BYTES_V1);
    assert_eq!(
        ArchiveBundleSource::from_bytes(bytes).err(),
        Some(BundleError::BlobLimit)
    );
}

/// Die Fehlercodes reisen mit dem Typ. Sie sind Fehlercodes eines Containers
/// und keine Fehlercodes eines Dateisystems, und `EA-BUNDLE-IO` bleibt in der
/// Liste, obwohl diese Crate kein `std::fs` beruehrt: die Variante wird
/// ausschliesslich in `crates/ea-archive-fs` konstruiert, und eine zweite
/// Fehleraufzaehlung neben dieser waere der Weg, auf dem zwei Codes fuer
/// denselben Befund entstehen.
#[test]
fn every_bundle_error_code_survives_the_move() {
    for (error, code) in [
        (
            BundleError::SourceNotFullyVerified,
            "EA-BUNDLE-SOURCE-NOT-FULLY-VERIFIED",
        ),
        (BundleError::TargetOccupied, "EA-BUNDLE-TARGET-OCCUPIED"),
        (BundleError::Malformed, "EA-BUNDLE-MALFORMED"),
        (BundleError::BlobLimit, "EA-BUNDLE-BLOB-LIMIT"),
        (BundleError::TotalByteLimit, "EA-BUNDLE-TOTAL-BYTE-LIMIT"),
        (BundleError::Io, "EA-BUNDLE-IO"),
    ] {
        assert_eq!(error.code(), code);
    }
}
