//! Das Alter des Trust-Standes: die Rechnung und ihr Speicher.
//!
//! Der Fehlerpunkt, den diese Datei bezeugt, heisst `stale-trust-state`: ein
//! dauerhaft im Datei-Modus betriebenes Geraet sieht einen Widerruf erst beim
//! naechsten Bezug des Trust-Bestandes. Sichtbar gemacht wird das ueber das
//! ALTER — und ausdruecklich nicht ueber eine Sperre.

mod fixtures;

use ea_reader::{
    InMemoryReaderBlobStore, ReaderBlobStore, ReaderTrustStateStore, ReaderTrustStateV1,
    reader_trust_age_view,
};
use ea_types::{RegistryVersion, UnixMillis};

/// Ein Tag in Millisekunden — der Vorgabewert, den `ea-trust` fuer die Policy
/// fuehrt.
const ONE_DAY_MS: u64 = 86_400_000;

#[test]
fn an_unset_deadline_is_never_overdue() {
    // `schemas/archive/v1/trust.cddl` notiert `0 = unset` an genau diesem
    // Feld. Ohne diese Regel waere ein Bestand ab der ersten Millisekunde
    // ueberfaellig, und die Aufforderung verloere ihre Aussage.
    let view = reader_trust_age_view(UnixMillis::new(0), UnixMillis::new(i64::from(u32::MAX)), 0);

    assert!(view.trust_age_ms() > 0, "das Alter selbst wird gerechnet");
    assert_eq!(view.reader_trust_refresh_ms(), 0);
    assert!(!view.trust_refresh_overdue());
}

#[test]
fn an_exceeded_deadline_asks_for_a_refresh() {
    let view = reader_trust_age_view(
        UnixMillis::new(1_000),
        UnixMillis::new(1_000 + i64::try_from(ONE_DAY_MS).expect("ein Tag passt in i64") + 1),
        ONE_DAY_MS,
    );

    assert_eq!(view.trust_age_ms(), ONE_DAY_MS + 1);
    assert!(view.trust_refresh_overdue());
}

#[test]
fn an_age_exactly_at_the_deadline_is_not_yet_overdue() {
    let view = reader_trust_age_view(
        UnixMillis::new(1_000),
        UnixMillis::new(1_000 + i64::try_from(ONE_DAY_MS).expect("ein Tag passt in i64")),
        ONE_DAY_MS,
    );

    assert_eq!(view.trust_age_ms(), ONE_DAY_MS);
    assert!(!view.trust_refresh_overdue());
}

#[test]
fn a_clock_set_back_yields_no_negative_age() {
    // Eine zurueckgestellte Uhr ergibt Alter NULL und keine negative Zahl —
    // derselbe Boden, den die Finalisierungsvorschau des Writers zieht.
    let view = reader_trust_age_view(UnixMillis::new(9_000), UnixMillis::new(1_000), ONE_DAY_MS);

    assert_eq!(view.trust_age_ms(), 0);
    assert!(!view.trust_refresh_overdue());
}

#[test]
fn the_stored_trust_state_survives_a_round_trip() {
    let vault = fixtures::unlocked_vault();
    let store = ReaderTrustStateStore::open(&vault);
    let mut blobs = InMemoryReaderBlobStore::default();
    let written = ReaderTrustStateV1 {
        last_trust_refresh_at: UnixMillis::new(1_700_000_000_000),
        registry_version: RegistryVersion::new(6),
    };

    store
        .put_trust_state(&mut blobs, written)
        .expect("der Trust-Stand wird geschrieben");
    let read = store
        .get_trust_state(&blobs)
        .expect("der Trust-Stand wird gelesen")
        .expect("er wurde soeben geschrieben");

    assert_eq!(
        read.last_trust_refresh_at.get(),
        written.last_trust_refresh_at.get()
    );
    assert_eq!(read.registry_version.get(), written.registry_version.get());
}

#[test]
fn a_device_that_never_refreshed_carries_no_state_at_all() {
    // `None` ist NICHT dasselbe wie ein Alter von null: das eine heisst „nie
    // bezogen", das andere „gerade eben bezogen". Wer beides zusammenfaellen
    // liesse, zeigte einem Geraet im Datei-Modus einen frischen Bestand an,
    // den es nie hatte.
    let vault = fixtures::unlocked_vault();
    let store = ReaderTrustStateStore::open(&vault);
    let blobs = InMemoryReaderBlobStore::default();

    assert!(
        store
            .get_trust_state(&blobs)
            .expect("ein leerer Speicher ist kein Fehler")
            .is_none()
    );
}

#[test]
fn a_foreign_vault_cannot_open_the_trust_state() {
    // Die Bindung haengt am Tresorschluessel und nicht am Speicher.
    let vault = fixtures::unlocked_vault();
    let mut blobs = InMemoryReaderBlobStore::default();
    ReaderTrustStateStore::open(&vault)
        .put_trust_state(
            &mut blobs,
            ReaderTrustStateV1 {
                last_trust_refresh_at: UnixMillis::new(1_700_000_000_000),
                registry_version: RegistryVersion::new(6),
            },
        )
        .expect("der Trust-Stand wird geschrieben");

    let foreign = fixtures::second_unlocked_vault();
    assert!(
        ReaderTrustStateStore::open(&foreign)
            .get_trust_state(&blobs)
            .is_err(),
        "ein fremder Tresor oeffnet den Trust-Stand nicht"
    );
}

#[test]
fn the_blob_store_never_sees_the_refresh_timestamp_in_the_clear() {
    let vault = fixtures::unlocked_vault();
    let mut blobs = InMemoryReaderBlobStore::default();
    // Ein Zeitpunkt, dessen Big-Endian-Bytes als Marker taugen.
    let marker = 0x0102_0304_0506_0708_i64;
    ReaderTrustStateStore::open(&vault)
        .put_trust_state(
            &mut blobs,
            ReaderTrustStateV1 {
                last_trust_refresh_at: UnixMillis::new(marker),
                registry_version: RegistryVersion::new(6),
            },
        )
        .expect("der Trust-Stand wird geschrieben");

    let needle = marker.to_be_bytes();
    for key in blobs
        .keys()
        .expect("der Speicher gibt seine Schluessel heraus")
    {
        let blob = blobs
            .get(&key)
            .expect("der Speicher liest, was er selbst haelt")
            .expect("der soeben geschriebene Blob");
        assert!(
            !blob.windows(needle.len()).any(|window| window == needle),
            "der Zeitpunkt darf im Bytespeicher nie im Klartext liegen"
        );
    }
}
