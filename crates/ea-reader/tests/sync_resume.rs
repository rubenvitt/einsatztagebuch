//! Der Cursor bewegt sich NUR hinter jeder dauerhaften Wirkung — und ein
//! wiedereroeffneter Speicher belegt es.
//!
//! Jeder Zeuge dieser Datei misst denselben Satz aus zwei Richtungen: was der
//! Dienst im Arbeitsspeicher haelt, ist ohne Aussage, und was nach einem
//! Neuoeffnen des Bytespeichers dasteht, ist die ganze Aussage. Im Browser ist
//! das kein Gedankenspiel — ein Tab schliesst, ein Worker wird beendet, und
//! die Speicherbereinigung bricht einen OPFS-Schreibvorgang ab.

#[path = "sync_support/mod.rs"]
mod sync_support;

use ea_reader::{ConfirmedCursor, ReaderSyncFaultPoint, ReaderSyncService};
use sync_support::{ReaderSyncHarness, fixtures};

/// Jeder Abbruchpunkt einzeln, und nach jedem ein NEU GEOEFFNETER Speicher.
/// Der Wiederaufbau aus denselben Bytes ist die Aussage — ein Dienst, der
/// seinen Cursor im Prozessspeicher haelt, waere hier gruen und im Browser rot,
/// sobald ein Tab schliesst.
#[test]
fn the_cursor_moves_only_after_every_object_is_durable_and_the_chain_verifies() {
    for fault in ReaderSyncFaultPoint::ALL {
        let mut harness = ReaderSyncHarness::with_two_batches();
        let before = harness.confirmed_cursor();
        let _ = harness.pull_with_fault(fault);
        let reopened = harness.reopen_store();
        assert_eq!(
            reopened.confirmed_cursor(),
            before,
            "{} advanced the cursor across an interruption",
            fault.name()
        );
        reopened.pull().unwrap();
        assert_eq!(reopened.confirmed_head(), fixtures::batch_end_head());
    }
}

/// Wiederholen ist idempotent: derselbe Batch ein zweites Mal legt keine
/// zweiten Bytes ab und bewegt den Cursor nicht weiter.
#[test]
fn a_repeated_batch_writes_no_second_byte_and_moves_nothing() {
    let mut harness = ReaderSyncHarness::with_two_batches();
    let first = harness.pull().unwrap();
    let bytes_after_first = harness.blob_store_byte_count();
    let second = harness.pull_same_batch_again().unwrap();
    assert_eq!(first, second);
    assert_eq!(harness.blob_store_byte_count(), bytes_after_first);
}

/// Cacheverlust: der Speicher ist leer, der gepinnte Anchor ist es nicht. Der
/// Wiederaufbau laeuft ab Genesis und endet auf DEMSELBEN Kopf.
#[test]
fn a_lost_cache_rebuilds_from_genesis_to_the_same_head() {
    let mut harness = ReaderSyncHarness::with_two_batches();
    harness.pull().unwrap();
    let head = harness.confirmed_head();
    let rebuilt = harness.erase_blob_store().rebuild_from_genesis().unwrap();
    // `as_bytes()` auf BEIDEN Seiten, weil `ea-types` fuer seine Hash-Newtypes
    // ausdruecklich kein `Debug` ableitet und `assert_eq!` eines verlangt.
    // Dieselbe Schreibweise fuehrt
    // `crates/ea-archive-fs/tests/profile_migration.rs` fuer Profilhashes.
    assert_eq!(
        rebuilt.entry_hash().as_bytes(),
        head.entry_hash().as_bytes()
    );
    assert_eq!(rebuilt.sequence(), head.sequence());
}

/// Der ERSTE der zwei browser-eigenen Abbruchpunkte: ein Tab, der MITTEN im
/// Batch schliesst.
///
/// Modelliert als Fallenlassen des Dienstes zwischen `AfterFirstObjectWrite`
/// und `BeforeCursorPersist` — die Objektbytes sind dauerhaft, `confirm` ist
/// nie gelaufen. Auf dem Desktop gab es diesen Punkt nicht: dort endet ein
/// Prozess, hier endet ein Dokument, und der Bytespeicher ueberlebt beide
/// Male. Der Ausgang MUSS derselbe sein wie bei jedem anderen Abbruch.
#[test]
fn a_tab_that_closes_mid_batch_leaves_the_cursor_where_it_was() {
    let mut harness = ReaderSyncHarness::with_two_batches();
    let before: ConfirmedCursor = harness.confirmed_cursor();
    harness.accept_one_batch_and_drop_the_service().unwrap();
    let reopened = harness.reopen_store();
    assert_eq!(reopened.confirmed_cursor(), before);
    reopened.pull().unwrap();
    assert_eq!(reopened.confirmed_head(), fixtures::batch_end_head());
}

/// Der ZWEITE: ein OPFS-Schreibvorgang, den die Speicherbereinigung des
/// Browsers abbricht.
///
/// Modelliert als `ReaderBlobStore`-Doppel, das ab dem n-ten Byte
/// `QuotaExceeded` liefert. Der Dienst wird HIER unmittelbar gebaut und nicht
/// ueber die Kulisse gefahren: die Aussage ist, dass `accept_batch` an einem
/// Speicher scheitert, der mitten im Schreiben aufhoert, und dass der
/// Cursor DIESES Speichers danach unveraendert dasteht.
#[test]
fn an_opfs_write_the_browser_aborts_leaves_the_cursor_where_it_was() {
    let harness = ReaderSyncHarness::with_two_batches();
    let before = harness.confirmed_cursor();
    let service: ReaderSyncService<'_> = harness.service();
    let request = service.next_request(&before).unwrap();
    let response = harness.serve(&request);
    let mut quota = harness.blob_store_that_quits_after_one_object();
    assert_eq!(
        service
            .accept_batch(&mut quota, &before, &response)
            .unwrap_err()
            .code(),
        "EA-READER-STORE"
    );
    // Gelesen aus DEN Bytes, an denen der Abbruch geschah, und nicht aus dem
    // Dienst, der sie geschrieben hat.
    assert_eq!(harness.confirmed_cursor_in(&quota), before);
}
