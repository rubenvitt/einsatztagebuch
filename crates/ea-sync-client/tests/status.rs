//! Die REIHENFOLGE und der Zustand, den sie erzeugt.
//!
//! Zwei Zusagen von `design.md` §9.3 Schritt 12 und `design.md`:1584 stehen
//! hier ausfuehrbar: vor erfolgreicher Netzarchiv-Publikation findet kein
//! Serverupload statt, und `synchronisiert` verlangt eine lokal verifizierte
//! Quittung.

mod support;

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use ea_archive::{ArchiveBackend, ArchiveBackendError, ArchiveBlob, ArchiveError, ArchiveSource};
use ea_archive_fs::{LocalPathBackend, SyncStatus};
use ea_sync_client::SyncLocalArchiveV1;
use support::{SyncHarness, fixtures};

/// Wartet das Netzarchiv, bleibt der Server UNBERUEHRT.
///
/// Die Zusicherung `commit_calls() == 0` ist die tragende: sie misst nicht,
/// dass der Upload gescheitert waere, sondern dass er GAR NICHT VERSUCHT wurde.
/// Ein Upload, der erst an der Gegenstelle scheitert, haette die committeten
/// Bytes schon aus dem Haus gegeben.
#[tokio::test]
async fn controlled_network_publish_precedes_server_upload() {
    let mut harness = SyncHarness::controlled_network_disconnected().await;
    harness
        .push_pending()
        .await
        .expect("ein wartendes Netzarchiv ist ein ZUSTAND und kein Fehler");
    assert_eq!(
        harness.server.commit_calls(),
        0,
        "vor der Netzarchivpublikation darf KEIN Serverupload laufen"
    );
    assert_eq!(harness.status(), SyncStatus::UploadPending);
    assert_eq!(harness.detail(), "Netzarchiv wartet");
}

/// `synchronisiert` verlangt eine QUITTUNG, die die Verifikation bestanden hat.
#[tokio::test]
async fn synchronized_requires_locally_verified_receipt() {
    let mut harness = SyncHarness::new().await;
    harness.server.return_receipt(fixtures::bad_receipt());
    assert_eq!(
        harness
            .push_pending()
            .await
            .expect_err("eine unbestaetigte Quittung MUSS den Lauf anhalten")
            .code(),
        "EA-SYNC-RECEIPT-INVALID"
    );
    assert_ne!(harness.status(), SyncStatus::Synchronized);

    // Und der Bestand ist unberuehrt: die Quittung wird VOR dem Ablegen
    // geprueft, nicht danach. Ohne diese zweite Haelfte waere der Test auch
    // dann gruen, wenn die verworfene Quittung trotzdem auf der Platte laege.
    assert!(
        harness.local_receipt_paths().is_empty(),
        "eine verworfene Quittung darf den Bestand nicht erreichen"
    );
}

/// Ein LOKALES Profil laesst den Serverupload sofort laufen.
///
/// Die Gegenprobe zum ersten Zeugen: ohne sie waere `commit_calls() == 0` auch
/// dann gruen, wenn der Klient NIE einen Commit sendet.
#[tokio::test]
async fn a_local_profile_reaches_the_server_without_a_network_archive() {
    let mut harness = SyncHarness::new().await;
    harness.server.return_receipt(fixtures::bad_receipt());
    let _ = harness.push_pending().await;
    assert_eq!(
        harness.server.commit_calls(),
        1,
        "ohne Netzprofil geht der Eintrag unmittelbar auf die Leitung"
    );
    assert_eq!(
        harness.server.challenge_calls(),
        1,
        "jeder Commit holt sich VORHER eine frische Challenge"
    );
}

/// Die vier Zustaende bleiben vier, und die Ursache steht DANEBEN.
#[tokio::test]
async fn the_public_surface_stays_exactly_four_states() {
    assert_eq!(SyncStatus::ALL.len(), 4);
    let mut harness = SyncHarness::controlled_network_disconnected().await;
    let summary = harness.push_pending().await.expect("der Lauf muss tragen");
    assert!(SyncStatus::ALL.contains(&summary.status()));
    let cause = summary
        .detail_cause()
        .expect("ein wartendes Netzarchiv nennt seine Ursache");
    assert!(
        !SyncStatus::ALL
            .iter()
            .any(|status| status.label() == cause.label()),
        "die Detailursache ist niemals ein fuenfter Zustand"
    );
}

/// Eine FORMGUELTIGE, aber unpruefbare `.esr` im Bestand macht keinen Eintrag
/// erledigt.
///
/// Der gefaehrlichste Weg zu einem falschen `synchronisiert` fuehrt nicht ueber
/// die Leitung, sondern ueber die PLATTE: das Inventar klassifiziert am
/// Exact-Object-Praefix, und der Quittungsparser prueft Gestalt und Content
/// Type — aber weder die Serversignatur noch die fuenf Bindungen. Zaehlte die
/// Ableitung eine solche Datei als Bestaetigung, faende sie nichts mehr
/// anstehendes und meldete `synchronisiert`, ohne dass ein Server je etwas
/// gesehen hat.
#[tokio::test]
async fn a_format_valid_but_unverifiable_local_receipt_never_confirms_an_entry() {
    let mut harness = SyncHarness::new().await;
    let entry = harness
        .pending_entry()
        .await
        .expect("die Fixture traegt genau einen anstehenden Eintrag");
    harness.plant_unverifiable_local_receipt(&entry);

    // Die Datei liegt WIRKLICH da, und sie ist WIRKLICH eine Quittung: ohne
    // diese zwei Zusicherungen misst der Zeuge nur eine fehlende Datei.
    let planted = harness
        .local_receipt_bytes()
        .expect("die untergeschobene Quittung MUSS im Bestand liegen");
    assert!(
        matches!(
            ea_format::decode_exact_object(&planted),
            Ok(ea_format::ParsedArchiveObject::Receipt(_))
        ),
        "die untergeschobene Datei MUSS eine formgueltige Quittung sein"
    );

    let summary = harness.push_pending().await.expect("der Lauf muss tragen");
    assert_ne!(
        summary.status(),
        SyncStatus::Synchronized,
        "eine unpruefbare Quittung darf NIE synchronisiert melden"
    );
    assert_eq!(
        summary.outstanding(),
        1,
        "der Eintrag bleibt anstehend, solange keine GEPRUEFTE Quittung auf ihn zeigt"
    );
}

/// Der Commit geht an den Pfad des Endpunkts, mit der KETTE darin.
///
/// Der Regressionszeuge zu einem Befund der Selbstpruefung: die Ziel-URI trug
/// einmal den Eintragshash, wo die Kettenkennung hingehoert. Die Signatur deckt
/// `@target-uri` ab, also ist das keine stille Fehladressierung, sondern eine
/// Signatur ueber eine andere Ressource — und die Attrappe echote jeden Pfad,
/// also sah es niemand.
#[tokio::test]
async fn the_commit_goes_to_the_endpoint_path_of_this_chain() {
    let mut harness = SyncHarness::new().await;
    harness.server.return_receipt(fixtures::bad_receipt());
    let _ = harness.push_pending().await;

    let targets = harness.server.seen_targets();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0], harness.expected_commit_target());
    assert!(
        targets[0].starts_with("/v1/chains/") && targets[0].ends_with("/entry-commits"),
        "der Pfad ist der des Endpunkts: {}",
        targets[0]
    );
}

/// Eine Netzarchiv-Publikation, die GLEICHZEITIG einen fremden ausstehenden
/// Plan mitzieht, blockiert den Serverupload NICHT fälschlich.
///
/// EA-CNA-PUB-7 vereinigt einen neu angenommenen Plan mit einem bereits
/// ausstehenden — hier die vorher aufgeschobene Publikation eines FREMDEN
/// Vorgangs. `publish_to_network_archive` prüft danach BYTEGLEICHHEIT je
/// EIGENER Adresse und nicht über die GANZE Antwort: ohne diesen Zeugen hätte
/// ein Vergleich über die gesamte Liste den Eintrag fälschlich als
/// `Netzarchiv ausstehend` gemeldet, obwohl seine eigenen Objekte längst
/// angekommen sind.
#[tokio::test]
async fn a_publish_that_also_drains_an_unrelated_outstanding_plan_does_not_block_the_server_upload()
{
    let mut harness = SyncHarness::controlled_network_disconnected().await;
    harness.seed_outstanding_network_plan();

    harness
        .target
        .as_ref()
        .expect("die Fixture trägt ein Netzziel")
        .connect();
    let _ = harness.push_pending().await.expect("der Lauf muss tragen");

    // Der Server wurde TATSÄCHLICH versucht — unmöglich, hätte
    // `publish_to_network_archive` den Eintrag fälschlich als
    // `Netzarchiv ausstehend` gemeldet. `commit_calls` zählt VOR der
    // hinterlegten Antwort, die Zusicherung ist also unabhängig davon, ob der
    // Server selbst antwortet.
    assert_eq!(
        harness.server.commit_calls(),
        1,
        "die eigenen Objekte des Eintrags waren veröffentlicht — der Serverupload darf nicht blockieren"
    );
}

/// Der ueberschrittene Queuebound erreicht den oeffentlichen Zustand `Fehler`.
///
/// Die Kette ganz, an einer echten Warteschlange: das Profil laesst genau ein
/// Objekt zu, der Plan traegt mehr, und was am Ende dasteht, ist `Fehler` mit
/// `Queuegrenze erreicht` daneben. Vor Task 10 pinnte
/// `crates/ea-archive-fs/tests/publication_queue.rs` diesen Zustand direkt;
/// seit die Abbildung in `ea-sync-client` liegt, gehoert der Zeuge hierher.
#[tokio::test]
async fn an_exceeded_queue_bound_reaches_the_public_failed_state() {
    let mut harness = SyncHarness::controlled_network_with_a_single_object_bound().await;
    let summary = harness
        .push_pending()
        .await
        .expect("die Grenze ist ein ZUSTAND");
    assert_eq!(summary.status(), SyncStatus::Failed);
    assert_eq!(
        summary.detail_cause(),
        Some(ea_archive_fs::DetailCause::QueueLimitReached)
    );
    assert_eq!(
        harness.server.commit_calls(),
        0,
        "eine abgelehnte Netzarchivpublikation gibt den Serverupload NICHT frei"
    );
}

/// Der lokale Archivport eines Netzprofils in Testgestalt: seine committete
/// Quelle ist eine Vereinigung aus ZWEI Teilen — der Netzsicht und der
/// lokalen Komponente mit dem jüngsten Eintrag samt Grants (EA-CNA-SRC-2).
///
/// Die Quittungsablage bleibt der `LocalPathBackend` der Fixture; dieser
/// Zeuge erreicht sie nie, weil der Serverupload gar nicht beginnt.
struct TwoPartUnionArchive {
    backend: Arc<LocalPathBackend>,
    remote: Vec<(String, Vec<u8>)>,
    local: Vec<(String, Vec<u8>)>,
    visits: Arc<AtomicUsize>,
}

impl TwoPartUnionArchive {
    /// Die Fixture ohne Bytes: nur die Paarung zählt.
    fn empty(harness: &SyncHarness) -> Self {
        Self {
            backend: harness.writer().backend_handle(),
            remote: Vec::new(),
            local: Vec::new(),
            visits: Arc::new(AtomicUsize::new(0)),
        }
    }
}

/// Eine Besuchssicht der Vereinigung; erst die Netzsicht, dann die lokale
/// Komponente.
struct TwoPartUnionSource<'a> {
    archive: &'a TwoPartUnionArchive,
}

impl ArchiveSource for TwoPartUnionSource<'_> {
    fn visit_blobs(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        self.archive.visits.fetch_add(1, Ordering::SeqCst);
        for (path, bytes) in self.archive.remote.iter().chain(&self.archive.local) {
            visitor(ArchiveBlob::new(path, bytes))?;
        }
        Ok(())
    }
}

impl SyncLocalArchiveV1 for TwoPartUnionArchive {
    fn backend(&self) -> &dyn ArchiveBackend {
        self.backend.as_ref()
    }

    fn committed_source(&self) -> Result<Box<dyn ArchiveSource + '_>, ArchiveBackendError> {
        Ok(Box::new(TwoPartUnionSource { archive: self }))
    }

    fn requires_network_publication(&self) -> bool {
        true
    }
}

/// Liest die committete Quelle eines Netzprofils die VEREINIGUNG, wartet das
/// Netzarchiv, und bleibt der Server trotzdem unberührt (EA-CNA-PUB-5).
///
/// Der jüngste Eintrag liegt nur im lokalen Teil der Vereinigung. Dass er
/// anstehend erkannt und dann NICHT hochgeladen wird, misst beides: die
/// Warteschlange entsteht aus der Vereinigung, und vor der
/// Netzarchivpublikation sendet der Klient keinen Commit.
#[tokio::test]
async fn server_commit_is_not_sent_while_network_publication_is_deferred_for_a_union_source() {
    let mut harness = SyncHarness::controlled_network_disconnected().await;

    let mut committed = Vec::new();
    harness
        .writer()
        .backend()
        .as_archive_source()
        .visit_blobs(&mut |blob| {
            committed.push((blob.path_hint().to_owned(), blob.bytes().to_vec()));
            Ok(())
        })
        .expect("der committete Bestand der Fixture ist lesbar");
    let newest = committed
        .iter()
        .map(|(path, _)| path)
        .filter(|path| path.starts_with("entries/") && path.ends_with(".eip"))
        .max()
        .expect("die Fixture hat einen Eintrag committet")
        .clone();
    let hash = newest
        .trim_start_matches("entries/")
        .trim_end_matches(".eip")
        .split_once('_')
        .map(|(_, hash)| hash.to_owned())
        .expect("ein Eintragsname trägt Sequenz und Hash");
    let (local, remote): (Vec<_>, Vec<_>) = committed
        .into_iter()
        .partition(|(path, _)| *path == newest || path.starts_with(&format!("grants/{hash}_")));
    assert!(
        local.len() >= 2,
        "der lokale Teil trägt das `.eip` und mindestens einen Grant"
    );
    assert!(!remote.is_empty(), "der Netzteil trägt die übrige Kette");

    let visits = Arc::new(AtomicUsize::new(0));
    harness.use_local_archive(Arc::new(TwoPartUnionArchive {
        backend: harness.writer().backend_handle(),
        remote,
        local,
        visits: Arc::clone(&visits),
    }));

    harness
        .push_pending()
        .await
        .expect("ein wartendes Netzarchiv ist ein ZUSTAND und kein Fehler");
    assert!(
        visits.load(Ordering::SeqCst) > 0,
        "die Warteschlange entsteht aus der Vereinigung"
    );
    assert_eq!(
        harness.server.commit_calls(),
        0,
        "vor der Netzarchivpublikation darf KEIN Serverupload laufen"
    );
    assert_eq!(harness.status(), SyncStatus::UploadPending);
    assert_eq!(harness.detail(), "Netzarchiv wartet");
}

/// Ein Netzport ohne Netzarchiv-Warteschlange wird schon beim Aufbau
/// abgelehnt (EA-CNA-PUB-5): sonst übersprünge `push_pending` die
/// Netzpublikation und committete direkt beim Server.
#[tokio::test]
async fn a_network_port_without_a_network_queue_is_refused() {
    let mut harness = SyncHarness::new().await;
    let port = TwoPartUnionArchive::empty(&harness);
    harness.use_local_archive(Arc::new(port));
    let refused = harness
        .try_client()
        .err()
        .expect("ein ungepaarter Netzport darf keinen Klienten ergeben");
    assert_eq!(refused.code(), "EA-SYNC-CLIENT-NETWORK-UNPAIRED");
    assert_eq!(harness.server.commit_calls(), 0);
}
