//! Die Blob-Runde und der Rebuild.
//!
//! Die Zusage ist staerker als „es geht wieder auf": derselbe Bestand unter
//! derselben Nonce MUSS den BYTEGLEICHEN Blob liefern, sonst ist der Rebuild
//! keine Rekonstruktion, sondern eine zweite Wahrheit.

mod fixtures;

use ea_crypto::{AEAD_NONCE_SIZE, CEK_SIZE, SecretBytes};
use ea_index::{
    INDEX_BLOB_HEADER_BYTES_V1, INDEX_BLOB_MAGIC_V1, INDEX_FORMAT_VERSION_V1,
    INDEX_PARSER_LIMITS_V1, IndexBlobV1, InvertedIndexV1, ReaderQueryV1,
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
    // BEIDE Formen, und das ist der Punkt: Termschluessel liegen im Koerper
    // KLEIN GEFALTET, die Einsatznummer in ihrer Anzeigeform. Ein Kanarienvogel
    // allein in Grossschreibung schlaege selbst dann nicht an, wenn der Koerper
    // unverschluesselt danebenlaege — gemessen am Klartextkoerper dieser
    // Kulisse, der `canary-person` und `lf 10` traegt und `CANARY-PERSON` und
    // `LF 10` nie.
    for canary in [
        b"CANARY-PERSON".as_slice(),
        b"canary-person".as_slice(),
        b"2026-0001".as_slice(),
        b"LF 10".as_slice(),
        b"lf 10".as_slice(),
        b"verkehrsunfall".as_slice(),
    ] {
        assert!(
            !fixtures::contains_subslice(blob.bytes(), canary),
            "no decrypted field value may appear in the sealed index blob: {}",
            String::from_utf8_lossy(canary)
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

/// Jede Kopfmutation faellt, und JEDE an ihrer eigenen Schicht.
///
/// Der Zeuge hiess frueher `the_plaintext_header_is_bound_into_the_ciphertext_as_aad`
/// und behauptete damit mehr, als er misst: GEMESSEN bleibt er gruen, wenn man
/// beiden `aead_*`-Aufrufen ein leeres AAD gibt. Das ist kein Fehler des
/// Codes, sondern eine Tatsache ueber den heutigen Kopf — Magic und
/// Formatversion prueft `IndexBlobV1::open` ausdruecklich VOR jeder Kryptografie,
/// und die Kopf-Nonce IST die AEAD-Nonce. Was er wirklich haelt, ist die
/// SCHICHTUNG: Formfehler fallen an der Form, Schluesselfehler an der
/// Kryptografie. Die AAD-Bindung selbst bezeugt
/// `the_header_is_passed_as_aad_and_a_body_sealed_without_it_never_opens`.
#[test]
fn every_header_mutation_is_refused_at_its_own_layer() {
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

/// Die AAD-Bindung, direkt bezeugt.
///
/// Der einzige Weg dahin fuehrt an `IndexBlobV1::seal` vorbei: die Kulisse
/// versiegelt denselben Koerper unter demselben Schluessel und derselben Nonce
/// einmal MIT und einmal OHNE den Kopf als AAD. Der erste geht auf — das ist
/// die Positivkontrolle, ohne die die zweite Zeile auch dann gruen bliebe, wenn
/// der handgebaute Blob aus einem ganz anderen Grund nicht traegt. Der zweite
/// DARF sich nicht oeffnen lassen; gaebe `open` ein leeres AAD weiter, oeffnete
/// er sich klaglos und lieferte einen leeren Bestand.
#[test]
fn the_header_is_passed_as_aad_and_a_body_sealed_without_it_never_opens() {
    let key = SecretBytes::new([0x33; CEK_SIZE]);
    let nonce = SecretBytes::new([0x07; AEAD_NONCE_SIZE]);
    let body = fixtures::hand_built_body(&[]);

    let bound = fixtures::hand_sealed_blob(&body, &key, &nonce, true);
    assert_eq!(
        IndexBlobV1::open(&bound, &key)
            .expect("mit gebundenem Kopf geht derselbe Weg auf")
            .indexed_packages(),
        0
    );

    let unbound = fixtures::hand_sealed_blob(&body, &key, &nonce, false);
    assert_eq!(
        IndexBlobV1::open(&unbound, &key).unwrap_err().code(),
        "EA-CRYPTO-AEAD-OPEN",
        "ein Chiffrat ohne den Kopf als AAD darf sich nicht oeffnen lassen"
    );
}

/// Ein Koerper, den dieser Kodierer nie schriebe, ist ein ARTEFAKTfehler.
///
/// Jede der fuenf Missbildungen ist wohlgeformtes, kanonisches,
/// grenzenkonformes CBOR — der Zeuge weist das je Fall NACH, indem er
/// `ea_cbor::validate` mit denselben Grenzen darueberlaufen laesst. Ein
/// `EA-CBOR-*` als Befund behauptete deshalb einen Fehler, den `ea-cbor` nie
/// erhoben hat.
#[test]
fn a_body_this_encoder_could_not_have_written_is_refused_as_a_blob_format() {
    let key = SecretBytes::new([0x33; CEK_SIZE]);
    let nonce = SecretBytes::new([0x07; AEAD_NONCE_SIZE]);

    let short_entry_hash = {
        let mut row = fixtures::HandBuiltRowV1::valid(1);
        row.entry_hash.truncate(31);
        vec![row]
    };
    let short_record_id = {
        let mut row = fixtures::HandBuiltRowV1::valid(1);
        row.record_id.truncate(15);
        vec![row]
    };
    let fourteen_positions = {
        let mut row = fixtures::HandBuiltRowV1::valid(1);
        row.positions = 14;
        vec![row]
    };
    let two_valued_option = {
        let mut row = fixtures::HandBuiltRowV1::valid(1);
        row.option_positions = 2;
        vec![row]
    };
    let duplicate_rows = vec![
        fixtures::HandBuiltRowV1::valid(1),
        fixtures::HandBuiltRowV1::valid(1),
    ];
    let descending_rows = vec![
        fixtures::HandBuiltRowV1::valid(2),
        fixtures::HandBuiltRowV1::valid(1),
    ];
    let unsorted_terms = {
        let mut row = fixtures::HandBuiltRowV1::valid(1);
        row.keyword_terms = vec!["brand".to_owned(), "arbeitsunfall".to_owned()];
        vec![row]
    };

    for (name, rows) in [
        ("31-byte entry hash", short_entry_hash),
        ("15-byte record id", short_record_id),
        ("fourteen positions", fourteen_positions),
        ("two-valued option container", two_valued_option),
        ("two rows under one entry hash", duplicate_rows),
        ("descending rows", descending_rows),
        ("descending terms", unsorted_terms),
    ] {
        let body = fixtures::hand_built_body(&rows);
        ea_cbor::validate(&body, INDEX_PARSER_LIMITS_V1).unwrap_or_else(|error| {
            panic!("{name} must be well-formed canonical CBOR, ea-cbor said {error}")
        });
        let blob = fixtures::hand_sealed_blob(&body, &key, &nonce, true);
        assert_eq!(
            IndexBlobV1::open(&blob, &key).unwrap_err().code(),
            "EA-INDEX-BLOB-FORMAT",
            "{name}"
        );
    }
}
