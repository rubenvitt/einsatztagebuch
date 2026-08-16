#[path = "support/mod.rs"]
mod support;

use ea_archive::ArchiveInventory;
use ea_crypto::object_hash;
use ea_trust::{
    MAX_TRUST_OBJECTS_V1, TrustObjectSource, TrustSourceError, decode_trust_anchor, verify_trust,
};
use ea_types::ObjectHash;
use support::{
    VariedTrustObjectSource, canonical_archive, etb_with_one_mutated_subtype_byte,
    trust_object_bytes, unpinned_snapshot,
};

/// Ein Objekthash als Hex.
///
/// `ea-types` leitet fuer Hashtypen kein `Debug` ab; verglichen wird deshalb
/// die Hexdarstellung, die im Fehlerfall auch lesbar ist.
fn hex(hash: ObjectHash) -> String {
    ::hex::encode(hash.as_bytes())
}

fn hexes(hashes: &[ObjectHash]) -> Vec<String> {
    hashes.iter().copied().map(hex).collect()
}

/// Das Inventar IST der Trust-Port, und es haelt an, sobald der Besucher
/// abbricht.
///
/// `ArchiveSource` ist der breite Port ueber alle Archivbytes,
/// `ea_trust::TrustObjectSource` bleibt unveraendert der schmale,
/// archiv-agnostische Trust-Port. `ArchiveInventory` implementiert ihn selbst;
/// es wird nichts dupliziert und `ea-trust` erfaehrt nichts ueber Archivlayout.
///
/// Vier Zusicherungen stehen hier zugleich:
///
/// 1. KEIN ZWISCHEN-VEC. Der Besucher wird waehrend des Durchlaufs des
///    beschraenkten Trust-Index gerufen. Liefert er beim k-ten Hash `Err`,
///    haelt der Adapter VOR dem naechsten Element an — nachgewiesen ueber die
///    Aufrufzahl. Und ein Bestand knapp UEBER `MAX_TRUST_OBJECTS_V1` bricht,
///    bevor ein einziger Hash gesammelt wurde.
/// 2. SCHRANKEN UNVERAENDERT. `MAX_TRUST_OBJECTS_V1` wird importiert, nicht
///    neu definiert, und ein Ueberschreiten liefert `TrustSourceError`.
/// 3. NUR TRUST-OBJEKTE. Der Index traegt ausschliesslich erfolgreich geparste
///    Objekte des Typs 5. Verkippte, doppelte und Nicht-Archivbytes erscheinen
///    nicht — sonst kippte eine kaputte Datei die Trust-Verifikation, statt
///    isoliert zu bleiben.
/// 4. Die gelieferten `Arc<[u8]>` sind die exakten Originalbytes des Bestands.
///
/// Zuletzt der Nachweis am echten Verifizierer: `verify_trust` ueber das
/// Inventar liefert `Ok`, obwohl der Bestand daneben Beiwerk, ein Duplikat und
/// ein unlesbares `.etb` traegt.
#[test]
fn the_inventory_serves_the_trust_port_and_stops_at_the_first_visitor_error() {
    let built = canonical_archive();
    let trust_objects = trust_object_bytes(&built.fixture);
    assert!(
        trust_objects.len() >= 4,
        "the canonical registry line must carry several trust objects"
    );
    let malformed = etb_with_one_mutated_subtype_byte(&trust_objects[0]);

    let mut fixture = built.fixture.clone();
    // Dieselben Trust-Bytes ein zweites Mal, unter anderem Hinweis.
    fixture.push_exact_bytes("trust/authorizations/copy.etb", trust_objects[0].clone());
    // Ein `.etb`, das am Parser scheitert: Praefix vorhanden, Subtyp unbekannt.
    fixture.push_exact_bytes("trust/registry-events/broken.etb", malformed.clone());
    // Beiwerk unter einem Trust-Pfad. Klassifiziert wird am Praefix, nie am Pfad.
    fixture.push_non_object("trust/notes.txt", b"kein Archivobjekt\n");
    let inventory = ArchiveInventory::build(&fixture).expect("the fixture archive must inventory");

    // (3) Der Port zeigt genau die geparsten Typ-5-Objekte, aufsteigend und
    // ohne Wiederholung.
    let mut visited = Vec::new();
    inventory
        .visit_trust_object_hashes(&mut |hash| {
            visited.push(hash);
            Ok(())
        })
        .expect("the inventory must enumerate its trust objects");

    let mut expected: Vec<ObjectHash> = trust_objects
        .iter()
        .map(|bytes| object_hash(bytes))
        .collect();
    expected.sort_unstable();
    expected.dedup();
    assert_eq!(
        hexes(&visited),
        hexes(&expected),
        "the trust port shows exactly the parsed type-5 objects, ascending"
    );
    assert_eq!(
        visited.len(),
        trust_objects.len(),
        "the second copy of the same bytes must be enumerated once, not twice"
    );

    for (label, other) in [
        ("eip", &built.eip),
        ("eag", &built.eag),
        ("esr", &built.esr),
        ("ecp", &built.ecp),
        ("eds", &built.eds),
        ("malformed etb", &malformed),
    ] {
        assert!(
            !visited.contains(&object_hash(other)),
            "{label} must stay out of the narrow trust port"
        );
    }

    // (4) Jeder aufgezaehlte Hash ist lesbar und liefert die Originalbytes.
    for hash in &visited {
        let bytes = inventory
            .read_exact_trust_object(*hash)
            .expect("reading an enumerated trust object must not fail")
            .expect("every enumerated trust object must be readable");
        let original = trust_objects
            .iter()
            .find(|candidate| object_hash(candidate) == *hash)
            .expect("every enumerated hash belongs to a fixture trust object");
        assert!(
            &*bytes == original.as_slice(),
            "the port hands out the exact archive bytes, never a re-encoding: {}",
            hex(*hash)
        );
    }

    // Alles, was kein geparstes Trust-Objekt ist, ist dem Port unbekannt.
    for (label, absent) in [
        ("eip", object_hash(&built.eip)),
        ("malformed etb", object_hash(&malformed)),
        (
            "unknown hash",
            object_hash(b"weder im Bestand noch im Index"),
        ),
    ] {
        assert!(
            inventory
                .read_exact_trust_object(absent)
                .expect("an unknown hash is not an error")
                .is_none(),
            "{label} must not be readable through the trust port"
        );
    }

    // (1) Abbruch beim k-ten Hash, mit genau k Aufrufen und unveraendertem
    // Fehler: ein Adapter, der den Besucherfehler schluckt oder ersetzt, faellt
    // hier durch.
    let k = 2;
    assert!(k < visited.len(), "the abort must happen in the middle");
    let mut calls = 0_usize;
    let error = inventory
        .visit_trust_object_hashes(&mut |_| {
            calls += 1;
            if calls == k {
                Err(TrustSourceError::Unavailable)
            } else {
                Ok(())
            }
        })
        .expect_err("a visitor error must stop the walk and travel back out");
    assert_eq!(error.code(), "EA-TRUST-SOURCE");
    assert_eq!(
        calls, k,
        "the walk must stop before the next element instead of finishing a prebuilt vector"
    );

    // Der Nachweis am echten Verifizierer.
    let anchor = decode_trust_anchor(&built.anchor_bytes).expect("the fixture anchor must decode");
    let verified = verify_trust(&anchor, &inventory, unpinned_snapshot())
        .expect("the inventory must serve ea-trust as its object source");
    assert!(verified.chain_id() == anchor.chain_id());
    assert!(verified.organization_id() == anchor.organization_id());
    assert!(verified.pinned_head().is_none());

    // (2) Knapp ueber der Schranke: der Fehler faellt, BEVOR ein einziger Hash
    // gesammelt wird. Ein vorab gebauter Vec waere daran erkennbar.
    let over_limit =
        VariedTrustObjectSource::new(trust_objects[0].clone(), MAX_TRUST_OBJECTS_V1 + 1);
    let over_limit = ArchiveInventory::build(&over_limit)
        .expect("the archive limits are wider than the trust limits");
    assert_eq!(over_limit.trust().len(), MAX_TRUST_OBJECTS_V1 + 1);
    let mut calls = 0_usize;
    let error = over_limit
        .visit_trust_object_hashes(&mut |_| {
            calls += 1;
            Ok(())
        })
        .expect_err("more than MAX_TRUST_OBJECTS_V1 trust objects must fail closed");
    assert_eq!(error.code(), "EA-TRUST-SOURCE-COUNT-LIMIT");
    assert_eq!(
        calls, 0,
        "the count limit must be settled before any hash is handed out"
    );
}
