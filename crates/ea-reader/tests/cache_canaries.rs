//! Der Bytespeicher sieht NIE Klartext — vier Marker, je einer pro Feld.
//!
//! `ReaderObjectCache` und `ReaderEntryStateStore` liegen ueber dem opaken
//! Byteport `ReaderBlobStore` und leiten ihre Schluessel aus dem
//! Tresorschluessel ab. Der Zeuge
//! `exact_objects_and_entry_states_are_never_plaintext_in_the_blob_store`
//! liest anschliessend GENAU DAS, was ein Angreifer mit Zugriff auf OPFS
//! saehe: die Schluesselliste im Klartext und jeden Blobinhalt.
//!
//! # Warum fuenf Marker und nicht einer
//!
//! Ein Sammelmarker liesse offen, welches Feld geleckt hat. `b"missingGrant"`
//! ist das Schemaliteral, das `ea_types::VerificationStatus::code()` gemessen
//! ausgibt, und faende jede Serde- oder Debug-Darstellung des Zustands;
//! `b"fehlender Grant"` ist die Oberflaechenschreibweise aus `design.md`
//! §17.4 und faende eine vorgerenderte Ansicht. `CANARY-PERSON` steht fuer
//! einen fachlichen Inhalt, die vollstaendigen Objektbytes fuer den
//! unverschluesselt durchgereichten Blob. Dieselbe Regel — EIN Marker JE FELD
//! — setzt `tests/ea-system-tests/tests/privacy_canaries_writer.rs` bereits
//! durch.
//!
//! Der fuenfte Marker ist der EINTRAGSHASH als ROHBYTES, und er ist der
//! einzige, der ueberhaupt in einem Klartext-Eintragszustand vorkaeme.
//! `encode_entry_state` schreibt die drei Statusdimensionen als u8-Ordinale;
//! weder `missingGrant` noch `fehlender Grant` stuende also je in einem
//! `entry-state/<hex>`-Blob, auch wenn dieser vollstaendig unverschluesselt
//! abgelegt wuerde. Die vier Marker oben messen damit ausschliesslich die
//! CACHE-Seite. Was im CBOR-Koerper wirklich steht, sind Eintragshash,
//! Objekthash, Sequenz und drei Zahlen — und die ADRESSE traegt den
//! Eintragshash nur HEXADEZIMAL, sodass der Marker als Rohbytes den Blob und
//! nicht seinen Schluessel misst.
//!
//! # Der Adressraum ist hexadezimal, und das ist kein Geschmack
//!
//! `ReaderBlobStore::keys()` gibt die Schluessel im KLARTEXT heraus. Ein
//! fachlicher Bestandteil im Schluessel waere ein Leck, das keine Pruefung des
//! Blobinhalts faengt — deshalb `cache/<hex objectHash>` und
//! `entry-state/<hex entryHash>` und nichts sonst.
//!
//! # Die Positivkontrolle ist Teil der Aussage
//!
//! Ohne sie belegte der Zeuge nur, dass nichts gespeichert wurde. Erst das
//! Zurueckholen ueber den Tresor zeigt, dass der Marker WIRKLICH im System
//! war; und der zweite Tresor zeigt, dass die Bindung am Tresorschluessel
//! haengt und nicht am Speicher — fuer BEIDE Speicher, nicht nur fuer den
//! Cache. Ein Zustandsspeicher, der seinen Schluessel nicht aus dem Tresor
//! zoege, bliebe sonst unbemerkt.
//!
//! # Die Adresse ist ein AEAD-Zusatz und keine verglichene Zeichenkette
//!
//! `a_blob_moved_to_a_foreign_address_refuses` vertauscht zwei Cache-Blobs
//! unter Umgehung des Caches — ueber den rohen Byteport, so wie ein Angreifer
//! mit OPFS-Zugriff es taete — und verlangt fuer BEIDE Objekthashes
//! `EA-CRYPTO-AEAD-OPEN`. Ohne die Adresse im zusaetzlichen authentifizierten
//! Datum liefe derselbe Aufruf gemessen auf `Ok(Some(fremde Bytes))` hinaus:
//! ein vertauschter Blob entschluesselt fehlerfrei, er bedeutet nur etwas
//! anderes. Genau diese Verwechslung ist der Grund, warum `blob_aad` in
//! `crates/ea-reader/src/envelope.rs` die Adresse mitnimmt.

mod fixtures;

use ea_reader::{
    InMemoryReaderBlobStore, ReaderBlobKey, ReaderBlobStore, ReaderEntryStateStore,
    ReaderObjectCache,
};

#[test]
fn exact_objects_and_entry_states_are_never_plaintext_in_the_blob_store() {
    let mut store = InMemoryReaderBlobStore::default();
    let unlocked = fixtures::unlocked_vault();
    let cache = ReaderObjectCache::open(&unlocked);
    let states = ReaderEntryStateStore::open(&unlocked);

    let bytes = fixtures::entry_package_bytes_carrying(b"CANARY-PERSON");
    let object_hash = cache.put_exact_object(&mut store, &bytes).unwrap();
    states
        .put_entry_state(&mut store, &fixtures::missing_grant_state())
        .unwrap();

    for key in store.keys().unwrap() {
        let raw = store.get(&key).unwrap().unwrap();
        assert!(!ea_testkit::contains_canary(&raw, &bytes));
        assert!(!ea_testkit::contains_canary(&raw, b"CANARY-PERSON"));
        assert!(!ea_testkit::contains_canary(&raw, b"missingGrant"));
        assert!(!ea_testkit::contains_canary(&raw, b"fehlender Grant"));
        // Der einzige Marker, den ein KLARTEXT-Eintragszustand traegt: die
        // drei Statusdimensionen liegen als Ordinale vor, der Eintragshash
        // dagegen als Rohbytes. Die Adresse traegt ihn nur hexadezimal.
        assert!(!ea_testkit::contains_canary(
            &raw,
            fixtures::entry_hash().as_bytes()
        ));
    }

    // Positivkontrolle: der Marker war wirklich im System.
    assert_eq!(
        cache.get_exact_object(&store, object_hash).unwrap(),
        Some(bytes)
    );
    assert_eq!(
        states
            .get_entry_state(&store, fixtures::entry_hash())
            .unwrap(),
        Some(fixtures::missing_grant_state())
    );

    // Ein zweiter Tresor oeffnet denselben Speicher nicht — und zwar KEINEN
    // der beiden. Der Zustandsspeicher braucht seine eigene Probe: sein
    // Schluessel entsteht ueber einen anderen Info-Kontext, und eine Bindung,
    // die nur fuer den Cache gemessen ist, ist fuer ihn nicht gemessen.
    let second = fixtures::second_unlocked_vault();
    assert_eq!(
        ReaderEntryStateStore::open(&second)
            .get_entry_state(&store, fixtures::entry_hash())
            .unwrap_err()
            .code(),
        "EA-CRYPTO-AEAD-OPEN"
    );
    let other = ReaderObjectCache::open(&second);
    assert_eq!(
        other
            .get_exact_object(&store, object_hash)
            .unwrap_err()
            .code(),
        "EA-CRYPTO-AEAD-OPEN"
    );
}

/// Zwei vertauschte Blobs weigern sich BEIDE.
///
/// Der Tausch geht ueber den rohen Byteport und nicht ueber den Cache: genau
/// so saehe der Eingriff aus, gegen den die Adressbindung schuetzt. Ein
/// Speicher ohne diesen Zusatz gaebe hier zweimal `Ok(Some(..))` mit den Bytes
/// des jeweils anderen Objekts zurueck — kein Fehler, nur die falsche Antwort,
/// und das ist der schlimmere der beiden Ausgaenge.
#[test]
fn a_blob_moved_to_a_foreign_address_refuses() {
    let mut store = InMemoryReaderBlobStore::default();
    let unlocked = fixtures::unlocked_vault();
    let cache = ReaderObjectCache::open(&unlocked);

    let first_bytes = fixtures::entry_package_bytes_carrying(b"CANARY-ERSTER");
    let second_bytes = fixtures::entry_package_bytes_carrying(b"CANARY-ZWEITER");
    let first_hash = cache.put_exact_object(&mut store, &first_bytes).unwrap();
    let second_hash = cache.put_exact_object(&mut store, &second_bytes).unwrap();

    let first_key = cache_address(first_hash);
    let second_key = cache_address(second_hash);
    let first_blob = store.get(&first_key).unwrap().unwrap();
    let second_blob = store.get(&second_key).unwrap().unwrap();
    store.put(&first_key, &second_blob).unwrap();
    store.put(&second_key, &first_blob).unwrap();

    for hash in [first_hash, second_hash] {
        assert_eq!(
            cache.get_exact_object(&store, hash).unwrap_err().code(),
            "EA-CRYPTO-AEAD-OPEN"
        );
    }
}

/// Die Adresse eines gecachten Objekts, wie `crates/ea-reader/src/cache.rs`
/// sie bildet.
///
/// Sie wird hier NACHGEBAUT und nicht importiert: `cache_key` ist modulprivat,
/// und das soll es bleiben. Der Zeuge braucht die Adresse nur, um am Cache
/// VORBEI in den Byteport zu greifen — genau die Sicht, die ein Angreifer auf
/// OPFS hat.
fn cache_address(object_hash: ea_types::ObjectHash) -> ReaderBlobKey {
    ReaderBlobKey::new(&format!("cache/{}", hex::encode(object_hash.as_bytes())))
        .expect("eine hexadezimale Cacheadresse ist ein gueltiger Blobschluessel")
}
