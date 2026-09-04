//! Die Blob-Runde und der Rebuild.
//!
//! Die Zusage ist staerker als „es geht wieder auf": derselbe Bestand unter
//! derselben Nonce MUSS den BYTEGLEICHEN Blob liefern, sonst ist der Rebuild
//! keine Rekonstruktion, sondern eine zweite Wahrheit.

mod fixtures;

use ea_crypto::{AEAD_NONCE_SIZE, CEK_SIZE, SecretBytes};
use ea_index::{
    INDEX_BLOB_HEADER_BYTES_V1, INDEX_BLOB_MAGIC_V1, INDEX_FORMAT_VERSION_V1, IndexBlobV1,
    InvertedIndexV1, ReaderQueryV1,
};

#[test]
fn the_blob_round_trips_through_chacha20poly1305_and_carries_no_plaintext() {
    let index = fixtures::index_over(&fixtures::three_records());
    let key = SecretBytes::new([0x33; CEK_SIZE]);
    let blob = IndexBlobV1::seal(&index, &key, &SecretBytes::new([0x07; AEAD_NONCE_SIZE])).unwrap();
    assert_eq!(
        &blob.bytes()[..INDEX_BLOB_MAGIC_V1.len()],
        &INDEX_BLOB_MAGIC_V1
    );
    for canary in [
        b"CANARY-PERSON".as_slice(),
        b"2026-0001".as_slice(),
        b"LF 10".as_slice(),
    ] {
        assert!(
            !fixtures::contains_subslice(blob.bytes(), canary),
            "no decrypted field value may appear in the sealed index blob"
        );
    }
    let reopened = IndexBlobV1::open(blob.bytes(), &key).unwrap();
    assert_eq!(reopened.indexed_packages(), index.indexed_packages());
    assert_eq!(
        reopened
            .search(&ReaderQueryV1::vehicle("LF 10"))
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        IndexBlobV1::open(blob.bytes(), &SecretBytes::new([0x34; CEK_SIZE]))
            .unwrap_err()
            .code(),
        "EA-CRYPTO-AEAD-OPEN"
    );
    let mut tampered = blob.bytes().to_vec();
    *tampered.last_mut().unwrap() ^= 0x01;
    assert_eq!(
        IndexBlobV1::open(&tampered, &key).unwrap_err().code(),
        "EA-CRYPTO-AEAD-OPEN"
    );
}

/// Der KOPF ist mitauthentisiert und nicht bloss vorangestellt.
///
/// Ohne den Kopf als AAD liesse sich ein aelterer Blob unter einer neuen
/// Formatversion zurueckspielen: dieselben Chiffratbytes, ein anderer Kopf, und
/// die Oeffnung gaebe nach. Beide Mutationen liegen AUSSERHALB des Chiffrats,
/// also faellt hier ausschliesslich die AAD-Bindung durch.
#[test]
fn the_plaintext_header_is_bound_into_the_ciphertext_as_aad() {
    let index = fixtures::index_over(&fixtures::three_records());
    let key = SecretBytes::new([0x33; CEK_SIZE]);
    let blob = IndexBlobV1::seal(&index, &key, &SecretBytes::new([0x07; AEAD_NONCE_SIZE])).unwrap();

    let mut wrong_version = blob.bytes().to_vec();
    wrong_version[INDEX_BLOB_MAGIC_V1.len() + 3] ^= 0x01;
    assert_eq!(
        IndexBlobV1::open(&wrong_version, &key).unwrap_err().code(),
        "EA-INDEX-BLOB-FORMAT",
        "eine fremde Formatversion faellt VOR der Oeffnung, an ihrer eigenen Zusicherung"
    );

    let mut wrong_nonce = blob.bytes().to_vec();
    wrong_nonce[INDEX_BLOB_HEADER_BYTES_V1 - 1] ^= 0x01;
    assert_eq!(
        IndexBlobV1::open(&wrong_nonce, &key).unwrap_err().code(),
        "EA-CRYPTO-AEAD-OPEN",
        "eine getauschte Nonce faellt an der AEAD-Bindung und nicht an einer Formzusicherung"
    );

    assert_eq!(INDEX_FORMAT_VERSION_V1, 1);
    assert_eq!(
        INDEX_BLOB_HEADER_BYTES_V1,
        INDEX_BLOB_MAGIC_V1.len() + 4 + AEAD_NONCE_SIZE
    );
}

/// Bytes, die den Kopf gar nicht tragen, fallen an der Form und nicht am Tag.
#[test]
fn bytes_that_are_not_an_index_blob_are_refused_before_any_key_touches_them() {
    let key = SecretBytes::new([0x33; CEK_SIZE]);
    for candidate in [
        Vec::new(),
        vec![0x00; INDEX_BLOB_HEADER_BYTES_V1 - 1],
        vec![0x00; INDEX_BLOB_HEADER_BYTES_V1 + 4],
    ] {
        assert_eq!(
            IndexBlobV1::open(&candidate, &key).unwrap_err().code(),
            "EA-INDEX-BLOB-FORMAT",
            "candidate of {} bytes",
            candidate.len()
        );
    }
}

#[test]
fn a_rebuild_from_the_exact_cached_bytes_is_byte_identical() {
    let records = fixtures::three_records();
    let key = SecretBytes::new([0x33; CEK_SIZE]);
    let nonce = SecretBytes::new([0x07; AEAD_NONCE_SIZE]);
    let first = IndexBlobV1::seal(&fixtures::index_over(&records), &key, &nonce).unwrap();
    let rebuilt = InvertedIndexV1::rebuild_from(records.iter().rev()).unwrap();
    let second = IndexBlobV1::seal(&rebuilt, &key, &nonce).unwrap();
    assert_eq!(
        first.bytes(),
        second.bytes(),
        "insertion order must not reach the sealed bytes; the index is a BTreeMap"
    );
}
