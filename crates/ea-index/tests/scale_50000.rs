//! Der GEMESSENE Zeuge der Schwelle.
//!
//! Er traegt `#[ignore]`, weil 50 000 Pakete kein Schnelllaufbudget sind, und
//! wird ausschliesslich ueber `cargo run --locked -p xtask -- index-scale 50000`
//! gefahren. Was er druckt, sind MESSWERTE und keine Zusicherungen: Blobgroesse,
//! Versiegelungs- und Entsperrdauer, Suchdauer und der Spitzenspeicher des
//! Testprozesses gehen als eine Zeile in den Stufe-4-Gate-Bericht.
//!
//! Er fasst AUSDRUECKLICH keinen Readertyp an — kein Cursor, kein
//! Objektmanifest, kein Bytespeicher. Was hier gemessen wird, ist der Index und
//! nur er; die dauerhafte Objektgrenze des Readers steht anderswo und ist im
//! Task-Abschnitt dieses Plans als Uebergabe benannt.

mod fixtures;

use std::time::Instant;

use ea_crypto::{AEAD_NONCE_SIZE, CEK_SIZE, SecretBytes};
use ea_index::{
    IndexBlobV1, IndexPressureV1, InvertedIndexV1, MONOLITHIC_INDEX_MAX_PACKAGES_V1, ReaderQueryV1,
};

#[test]
#[ignore = "run through `cargo run --locked -p xtask -- index-scale 50000`"]
fn fifty_thousand_packages_fit_the_monolithic_blob_and_report_their_cost() {
    assert_eq!(MONOLITHIC_INDEX_MAX_PACKAGES_V1, 50_000);
    let key = SecretBytes::new([0x33; CEK_SIZE]);
    let mut index = InvertedIndexV1::empty();
    let mut pressure = IndexPressureV1::Nominal;
    for package in 0..MONOLITHIC_INDEX_MAX_PACKAGES_V1 {
        pressure = index.upsert(&fixtures::synthetic_package(package)).unwrap();
    }
    assert_eq!(index.indexed_packages(), MONOLITHIC_INDEX_MAX_PACKAGES_V1);
    assert!(
        matches!(pressure, IndexPressureV1::SegmentationRequired { .. }),
        "the threshold package itself must raise the pre-authorized signal"
    );

    let sealed_at = Instant::now();
    let blob = IndexBlobV1::seal(&index, &key, &SecretBytes::new([0x07; AEAD_NONCE_SIZE])).unwrap();
    let seal_ms = sealed_at.elapsed().as_millis();
    let unlock_at = Instant::now();
    let reopened = IndexBlobV1::open(blob.bytes(), &key).unwrap();
    let unlock_ms = unlock_at.elapsed().as_millis();
    let search_at = Instant::now();
    let hits = reopened
        .search(&ReaderQueryV1::vehicle("LF 49999"))
        .unwrap();
    let search_us = search_at.elapsed().as_micros();
    assert_eq!(hits.len(), 1);

    // Gemessen, nicht behauptet. Die Zahlen gehen in den Stufe-4-Gate-Bericht.
    println!(
        "ea-index scale packages={} blob_bytes={} seal_ms={} unlock_ms={} search_us={} peak_rss_kib={}",
        MONOLITHIC_INDEX_MAX_PACKAGES_V1,
        blob.bytes().len(),
        seal_ms,
        unlock_ms,
        search_us,
        peak_resident_kib()
    );

    let beyond = index
        .upsert(&fixtures::synthetic_package(
            MONOLITHIC_INDEX_MAX_PACKAGES_V1,
        ))
        .unwrap();
    assert!(matches!(
        beyond,
        IndexPressureV1::SegmentationRequired {
            indexed_packages: 50_001
        }
    ));
    assert_eq!(
        index
            .search(&ReaderQueryV1::vehicle("LF 50000"))
            .unwrap()
            .len(),
        1,
        "past the threshold the index must still answer; the signal is not a refusal"
    );
}

/// Der Spitzenspeicher des Testprozesses in KiB, oder `0`, wo der Wirt ihn
/// nicht ausweist.
///
/// `VmHWM` aus `/proc/self/status` und keine Fremdcrate: der Wert wird
/// GEDRUCKT und nicht zugesichert, eine Kante allein fuer eine Protokollzeile
/// waere zu teuer. Auf einem Wirt ohne `/proc` steht `0` — sichtbar fehlend
/// statt still erfunden.
fn peak_resident_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("VmHWM:"))
                .and_then(|value| value.split_whitespace().next()?.parse::<u64>().ok())
        })
        .unwrap_or(0)
}
