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
/// Modelliert als `ReaderBlobStore`-Doppel, das ab dem n-ten Objekt
/// `QuotaExceeded` liefert.
///
/// # Warum die erste Seite VORHER vollstaendig durchlaeuft
///
/// Weil der Zeuge sonst nichts misst. Auf einem frischen Geraet steht der
/// Cursor auf Genesis, und ein Speicher, der gar nichts geschrieben hat, traegt
/// ebenfalls Genesis — die Zusicherung verglich Genesis mit Genesis und waere
/// auch gruen geblieben, wenn der Dienst faelschlich geschrieben haette (der
/// eine erlaubte Schreibvorgang war dann eben verbraucht). Erst eine Kulisse
/// MITTEN in der Lesestrecke — gecachte Objekte, ein Blaetterschein im Cursor —
/// macht die Frage „steht er noch dort" beantwortbar. Das [`assert_ne!`] gegen
/// Genesis haelt genau das fest, damit dieser Zeuge nicht ein zweites Mal
/// leerlaufen kann.
#[test]
fn an_opfs_write_the_browser_aborts_leaves_the_cursor_where_it_was() {
    let mut harness = ReaderSyncHarness::with_two_batches();
    let mid_run = harness.pull_one_page().unwrap();
    assert_ne!(
        mid_run,
        ConfirmedCursor::genesis(&fixtures::pinned_anchor()),
        "die erste Seite MUSS den Cursor bewegt haben, sonst misst dieser Zeuge nichts"
    );
    assert_eq!(harness.confirmed_cursor(), mid_run);

    let service: ReaderSyncService<'_> = harness.service();
    let request = service.next_request(&mid_run).unwrap();
    let response = harness.serve(&request);
    let mut quota = harness.blob_store_that_quits_after_one_object();
    assert_eq!(
        service
            .accept_batch(&mut quota, &mid_run, &response)
            .unwrap_err()
            .code(),
        "EA-READER-STORE"
    );
    // Gelesen aus DEN Bytes, an denen der Abbruch geschah, und nicht aus dem
    // Dienst, der sie geschrieben hat.
    assert_eq!(harness.confirmed_cursor_in(&quota), mid_run);

    // Und der naechste Lauf holt die abgebrochene Seite erneut.
    drop(service);
    harness.pull().unwrap();
    assert_eq!(harness.confirmed_head(), fixtures::batch_end_head());
}

/// Der Bestand, den die naechste Verifikation sieht, kommt aus RUST.
///
/// `OpfsBlobStore::open` verlangt die vollstaendige Schluesselmenge, bevor es
/// ein einziges synchrones Zugriffshandle oeffnet — wer sie nennt, bestimmt
/// damit, was `verify_archive_observed` ueberhaupt zu Gesicht bekommt. Eine
/// frueherere Fassung liess JavaScript sie nennen; das war fail-closed, aber
/// die Zustaendigkeit war falsch herum (`web-reader-design.md` §9).
///
/// Der Zeuge stellt die Menge deshalb gegen den Speicher, den der ERSTE
/// Vorlauf im Browser oeffnen kann — nur Cursor und Objektliste — und verlangt,
/// dass jede gecachte Adresse daraus wieder auftaucht.
#[test]
fn the_verified_holding_is_reconstructed_from_rusts_own_durable_manifest() {
    let harness = ReaderSyncHarness::with_two_batches();
    harness.pull().unwrap();

    let cached = harness.cached_blob_keys();
    assert!(
        cached.len() > 1,
        "die Kulisse muss mehrere Objekte gecacht haben, sonst misst dieser Zeuge nichts"
    );

    // Der Speicher des ersten Vorlaufs: NUR die zwei Zustandsadressen.
    let state_store = harness.sync_state_store();
    let service: ReaderSyncService<'_> = harness.service();
    let required: Vec<String> = service
        .required_blob_keys(&state_store, &fixtures::second_page())
        .unwrap()
        .iter()
        .map(|key| key.as_str().to_owned())
        .collect();

    for key in &cached {
        assert!(
            required.contains(key),
            "die dauerhafte Objektliste hat {key} nicht wiederhergestellt"
        );
    }
    assert!(required.contains(&"sync/cursor-v1".to_owned()));
    assert!(required.contains(&"sync/objects-v1".to_owned()));
}

/// Die Objektliste laeuft dem Cursor VORAUS und nie hinterher.
///
/// Die Richtung ist die Sicherheitsaussage: eine Liste, die ein Objekt nennt,
/// das nicht da ist, kostet einen leeren Blob und sonst nichts; eine Liste, der
/// ein vorhandenes Objekt fehlt, versteckt es vor der Verifikation. Nach einem
/// Abbruch VOR dem Cursorschreiben muss die Liste die Objekte des Batches
/// deshalb bereits fuehren.
#[test]
fn the_object_manifest_is_written_before_the_cursor_moves() {
    let mut harness = ReaderSyncHarness::with_two_batches();
    let before = harness.confirmed_cursor();
    let _ = harness.pull_with_fault(ReaderSyncFaultPoint::AfterCursorPersist);

    let reopened = harness.reopen_store();
    assert_eq!(reopened.confirmed_cursor(), before, "der Cursor steht");
    assert!(
        !reopened.cached_blob_keys().is_empty(),
        "die Objektbytes der abgebrochenen Seite sind dauerhaft"
    );

    let state_store = reopened.sync_state_store();
    let service: ReaderSyncService<'_> = reopened.service();
    let required: Vec<String> = service
        .required_blob_keys(&state_store, &fixtures::second_page())
        .unwrap()
        .iter()
        .map(|key| key.as_str().to_owned())
        .collect();
    for key in reopened.cached_blob_keys() {
        assert!(
            required.contains(&key),
            "{key} liegt im Speicher, steht aber nicht in der Objektliste"
        );
    }
}

/// Auch der Wiederaufbau MISST seinen Schreibvorgang, statt ihn anzuordnen.
///
/// `accept_batch` liest jedes Objekt zurueck, `confirm` liest den Cursor
/// zurueck — `rebuild_from_genesis` tat es nicht, und das war die eine
/// dauerhafte Wirkung dieser Crate ohne Probe. Ein Speicher, der den
/// Schreibvorgang quittiert und den Blob dann vergisst, liesse den Reader an
/// einen lokal verifizierten Aufsetzpunkt glauben, den er nicht mehr vorzeigen
/// kann. Das ist schlimmer als ein Fehlschlag: es ist ein Fehlschlag, der sich
/// als Erfolg ausgibt.
#[test]
fn a_rebuild_whose_write_does_not_stick_refuses_instead_of_claiming_a_checkpoint() {
    let harness = ReaderSyncHarness::with_two_batches();
    let mut forgetful = harness.blob_store_that_forgets_the_cursor();
    let service: ReaderSyncService<'_> = harness.service();
    assert_eq!(
        service
            .rebuild_from_genesis(&mut forgetful)
            .unwrap_err()
            .code(),
        "EA-READER-STORE"
    );
}
