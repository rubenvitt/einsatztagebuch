//! Die REIHENFOLGE und der Zustand, den sie erzeugt.
//!
//! Zwei Zusagen von `design.md` §9.3 Schritt 12 und `design.md`:1584 stehen
//! hier ausfuehrbar: vor erfolgreicher Netzarchiv-Publikation findet kein
//! Serverupload statt, und `synchronisiert` verlangt eine lokal verifizierte
//! Quittung.

mod support;

use ea_archive_fs::SyncStatus;
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
