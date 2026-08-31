//! Der Port auf OPAKE Bytes, und was er ueber sich selbst NICHT wissen darf.
//!
//! Der Speicher darf nie erfahren, was in einem Blob steht: jeder Aufrufer legt
//! Chiffrat ab und holt Chiffrat. `web-reader-design.md` §9 laesst
//! Kryptographie ausschliesslich in geteiltem Rust zu — ein typisierter Zugriff
//! hier waere eine ZWEITE Stelle, an der ueber Klartext entschieden wird.

use ea_reader::{InMemoryReaderBlobStore, ReaderBlobKey, ReaderBlobStore};

#[test]
fn the_blob_store_round_trips_opaque_bytes_and_lists_its_keys() {
    let mut store = InMemoryReaderBlobStore::new();
    let key = ReaderBlobKey::new("vault/envelope-0").expect("a bounded ASCII key");
    assert_eq!(store.get(&key).unwrap(), None);
    store.put(&key, b"\x00\xff\x00opaque").unwrap();
    assert_eq!(
        store.get(&key).unwrap().as_deref(),
        Some(&b"\x00\xff\x00opaque"[..])
    );
    assert_eq!(store.keys().unwrap(), vec![key.clone()]);
    store.delete(&key).unwrap();
    assert_eq!(store.get(&key).unwrap(), None);
}

#[test]
fn a_blob_key_is_a_bounded_ascii_path_and_never_a_traversal() {
    for rejected in [
        "",
        "../escape",
        "vault/../../etc",
        "vault/\u{00e9}",
        &"a".repeat(129),
    ] {
        assert!(
            ReaderBlobKey::new(rejected).is_err(),
            "{rejected} must be refused"
        );
    }
}

// Der Port kennt keine Struktur. Waere er typisiert, waere er eine zweite Stelle,
// an der ueber Klartext entschieden wird.
//
// Die Verbotsliste nennt die FACHLICHEN Typnamen und nicht das blosse Wort
// `Entry`: die Ablage des Doppels ist eine `BTreeMap`, und deren idiomatische
// Einfuegeform heisst `std::collections::btree_map::Entry`. Ein Verbot auf
// `Entry` faerbte den Zeugen an einem Namen der Standardbibliothek rot, der
// mit Opazitaet nichts zu tun hat — ein Fehlalarm, der die Zusicherung
// entwertet, weil die naechste Person sie abschaltet statt sie zu lesen.
#[test]
fn the_port_exposes_no_typed_accessor() {
    let source = include_str!("../src/blob_store.rs");
    for forbidden in [
        "EntryHash",
        "EntryPackage",
        "EntryStatus",
        "Grant",
        "TrustAnchor",
        "Cek",
        "plaintext",
    ] {
        assert!(
            !source.contains(forbidden),
            "blob_store.rs must stay opaque: {forbidden}"
        );
    }
}
