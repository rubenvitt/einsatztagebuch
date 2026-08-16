#[path = "support/mod.rs"]
mod support;

use ea_archive::{ArchiveBlob, ArchiveError, ArchiveSource};
use support::{ArchiveFixture, canonical_archive, has_exact_object_prefix};

/// Sammelt Hinweis und Bytes jedes besuchten Blobs in Besuchsreihenfolge.
fn walk(source: &dyn ArchiveSource) -> Vec<(String, Vec<u8>)> {
    let mut seen = Vec::new();
    source
        .visit_blobs(&mut |blob: ArchiveBlob<'_>| {
            seen.push((blob.path_hint().to_owned(), blob.bytes().to_vec()));
            Ok(())
        })
        .expect("an in-memory source must complete");
    seen
}

/// Der Port ist BREITER als `TrustObjectSource`: er liefert auch Beiwerk.
///
/// Ohne diese Breite liesse sich `nonObjectFileCount` gar nicht bilden, und
/// jedes normkonforme Archiv wuerde sein eigenes `README-FORMAT.txt`
/// isolieren (`design.md` §11.4).
#[test]
fn an_in_memory_source_visits_every_blob_exactly_once_including_non_objects() {
    let built = canonical_archive();
    let expected = built.fixture.blobs().to_vec();
    assert!(
        built.non_object_count > 0,
        "the fixture must carry beiwerk, otherwise the claim is vacuous"
    );

    let seen = walk(&built.fixture);

    // Jede gelieferte Bytesequenz genau einmal, in Ablagereihenfolge.
    assert_eq!(seen, expected, "every blob must be visited exactly once");
    assert_eq!(seen.len(), built.fixture.len());

    // Die Invariante aus §11.4: Objekte plus Beiwerk sind der ganze Bestand.
    let objects = seen
        .iter()
        .filter(|(_, bytes)| has_exact_object_prefix(bytes))
        .count();
    let non_objects = seen.len() - objects;
    assert_eq!(non_objects, built.non_object_count);
    assert_eq!(objects + non_objects, seen.len());

    // Beiwerk kommt wirklich mit — namentlich, nicht nur als Zahl.
    assert!(
        seen.iter()
            .any(|(path_hint, _)| path_hint == ea_archive::README_FORMAT_FILE_V1),
        "the walk must deliver README-FORMAT.txt, which carries no object prefix"
    );

    // Die fuenf signierten Familien liegen im Bestand, der Trust Anchor NICHT.
    for object in [&built.eip, &built.eag, &built.esr, &built.ecp, &built.eds] {
        assert!(
            seen.iter().any(|(_, bytes)| bytes == object),
            "every signed fixture object must be delivered by the port"
        );
    }
    assert!(
        !seen.iter().any(|(_, bytes)| *bytes == built.anchor_bytes),
        "the trust anchor is never part of the archive; it is passed as a parameter"
    );
}

/// Ein Fehler des Besuchers haelt den Durchlauf VOR dem naechsten Element an.
///
/// Genau darauf stuetzt sich das Inventar, wenn es `MAX_ARCHIVE_BLOBS_V1` und
/// `MAX_TOTAL_ARCHIVE_BYTES_V1` durchsetzt, ohne den Bestand vorher
/// vollstaendig zu lesen.
#[test]
fn a_visitor_error_stops_the_walk_before_the_next_blob() {
    let built = canonical_archive();
    let total = built.fixture.len();
    assert!(total > 2, "the fixture must be long enough to stop early");

    let mut visited = 0;
    let outcome = built.fixture.visit_blobs(&mut |_| {
        visited += 1;
        if visited == 2 {
            return Err(ArchiveError::BlobLimit);
        }
        Ok(())
    });

    assert_eq!(outcome, Err(ArchiveError::BlobLimit));
    assert_eq!(visited, 2, "the walk must not continue past the failure");
    assert_eq!(ArchiveError::BlobLimit.code(), "EA-ARCHIVE-BLOB-LIMIT");
    assert_eq!(
        format!("{}", ArchiveError::BlobLimit),
        "EA-ARCHIVE-BLOB-LIMIT"
    );
    assert_eq!(
        format!("{:?}", ArchiveError::BlobLimit),
        "EA-ARCHIVE-BLOB-LIMIT"
    );
}

/// Umbenennen aendert den Bestand nicht — Pfade sind Hinweise.
#[test]
fn renaming_every_blob_preserves_the_delivered_bytes() {
    let built = canonical_archive();
    let renamed = built.fixture.randomized_paths();

    let mut original_bytes: Vec<Vec<u8>> = walk(&built.fixture)
        .into_iter()
        .map(|(_, bytes)| bytes)
        .collect();
    let renamed_walk = walk(&renamed);
    let mut renamed_bytes: Vec<Vec<u8>> = renamed_walk
        .iter()
        .map(|(_, bytes)| bytes.clone())
        .collect();
    original_bytes.sort();
    renamed_bytes.sort();
    assert_eq!(
        original_bytes, renamed_bytes,
        "renaming must preserve the byte multiset exactly"
    );

    // Die Hinweise haben sich tatsaechlich VERSCHOBEN, nicht bloss die
    // Reihenfolge. Ein Vergleich der Hinweisfolgen wuerde schon durch das
    // Umdrehen erfuellt, auch wenn die Umbenennung selbst entartet waere —
    // und Task 19 stuetzt sich auf genau diese Umbenennung. Verglichen wird
    // deshalb die MENGE der Paare (Hinweis, Bytes): sie aendert sich nur,
    // wenn Bytes wirklich unter einem anderen Hinweis liegen.
    let original_pairs = walk(&built.fixture)
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let renamed_pairs = renamed_walk
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    assert_ne!(
        original_pairs, renamed_pairs,
        "randomized_paths must re-pair bytes with other hints, not merely reorder them"
    );

    // Die Hinweise selbst bleiben als Multimenge dieselben — es wird
    // umbenannt, nicht erfunden.
    let mut original_hints = walk(&built.fixture)
        .into_iter()
        .map(|(path_hint, _)| path_hint)
        .collect::<Vec<_>>();
    let mut renamed_hints = renamed_walk
        .iter()
        .map(|(path_hint, _)| path_hint.clone())
        .collect::<Vec<_>>();
    original_hints.sort();
    renamed_hints.sort();
    assert_eq!(original_hints, renamed_hints);

    // Ein gueltiges Objekt unter dem Beiwerk-Pfad bleibt ein Objekt: die
    // Klasse ist nicht durch Umbenennen waehlbar (§11.4).
    let mut renamed_fixture = ArchiveFixture::new();
    renamed_fixture.push_exact_bytes(ea_archive::README_FORMAT_FILE_V1, built.eip.clone());
    let seen = walk(&renamed_fixture);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, ea_archive::README_FORMAT_FILE_V1);
    assert!(has_exact_object_prefix(&seen[0].1));

    // Der leere Bestand ist der Randfall der Rotation.
    assert!(ArchiveFixture::new().randomized_paths().is_empty());
}

/// Der Pfadhinweis wird unveraendert durchgereicht, auch wenn er in keinem
/// Layoutpfad vorkommt.
#[test]
fn path_hints_are_passed_through_verbatim() {
    let (_, eip) = support::signed_entry_package();
    let mut fixture = ArchiveFixture::new();
    fixture.push_non_object("wo/auch/immer.txt", b"kein Objekt");
    fixture.push_exact_bytes("völlig/anderer ort.bin", eip.clone());

    let seen = walk(&fixture);
    assert_eq!(seen[0].0, "wo/auch/immer.txt");
    assert_eq!(seen[1].0, "völlig/anderer ort.bin");
    assert_eq!(seen[1].1, eip);
}

/// `LAYOUT_PATHS_V1` sammelt die Konstanten, die `design.md` §11.4 nennt.
#[test]
fn the_layout_constants_are_reachable_and_collected() {
    assert_eq!(ea_archive::LAYOUT_PATHS_V1.len(), 19);
    for path in ea_archive::LAYOUT_PATHS_V1 {
        assert!(!path.is_empty());
    }
    assert!(ea_archive::LAYOUT_PATHS_V1.contains(&ea_archive::TRUST_DIR_V1));
    assert!(ea_archive::LAYOUT_PATHS_V1.contains(&ea_archive::README_FORMAT_FILE_V1));
    // Die Schranken sind nicht enger als die des Trust-Teilbestands: der
    // Bestand ist dessen Obermenge. Als const-Block, damit ein Unterschreiten
    // schon die Uebersetzung bricht.
    const {
        assert!(ea_archive::MAX_ARCHIVE_BLOBS_V1 >= ea_trust::MAX_TRUST_OBJECTS_V1);
    }
    const {
        assert!(
            ea_archive::MAX_TOTAL_ARCHIVE_BYTES_V1 >= ea_trust::MAX_TOTAL_TRUST_OBJECT_BYTES_V1
        );
    }
}
