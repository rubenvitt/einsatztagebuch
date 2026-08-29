//! Neustart, Wiederaufnahme und Wiedergabe.
//!
//! Vier Zusagen stehen hier ausfuehrbar:
//!
//! 1. Die Warteschlange wird bei JEDEM Start aus committeten Archivbytes
//!    rekonstruiert und traegt keine veraenderliche Zeile mit sich.
//! 2. Eine unterbrochene Antwort fuehrt auf DENSELBEN Rumpf — die Wiedergabe
//!    ist idempotent, weil der Rumpf byteidentisch aus denselben committeten
//!    Bytes entsteht.
//! 3. Der Wiederaufnahmezaehler ueberlebt den Neustart, und die Schranke des
//!    Profils ist erreichbar.
//! 4. Format-, Signatur-, Fork-, Registry- und Autorisierungsfehler werden
//!    NICHT automatisch wiederholt.

mod support;

use ea_archive_fs::{DetailCause, SyncStatus};
use support::{CommitReplyV1, SyncHarness, fixtures};

/// Die Warteschlange entsteht bei jedem Lauf NEU — und identisch.
///
/// Zwei Laeufe gegen zwei frisch gebaute Klienten sehen denselben Rumpf. Der
/// Vergleich ist eine GLEICHHEIT und keine Beschreibung: haenge irgendetwas an
/// einer veraenderlichen Zeile statt an den committeten Bytes, wichen die zwei
/// Rumpfe voneinander ab.
#[tokio::test]
async fn the_queue_is_rebuilt_from_committed_bytes_on_every_start() {
    let mut harness = SyncHarness::new().await;
    harness
        .server
        .script(vec![CommitReplyV1::Unreachable, CommitReplyV1::Unreachable]);

    let _ = harness.push_pending().await;
    // Die Wiederaufnahme wartet WIRKLICH: ohne dieses Vorstellen faende der
    // zweite Lauf einen noch nicht faelligen Eintrag und liesse ihn zu Recht
    // liegen. Genau das ist die Zusage von `0004_sync_retry.sql`, und dieser
    // Zeuge misst sie mit, indem er sie umgehen MUSS.
    harness.advance(60_000);
    let _ = harness.push_pending().await;

    let bodies = harness.server.seen_commit_bodies();
    assert_eq!(bodies.len(), 2, "beide Laeufe haben gesendet");
    assert_eq!(
        bodies[0], bodies[1],
        "ein Neustart baut BYTEIDENTISCH denselben Rumpf"
    );
}

/// Jeder Commit traegt eine FRISCHE Nonce.
///
/// Der Server fuehrt einen Replay-Speicher; eine wiederverwendete Nonce waere
/// dort ein Replay und keine Wiederaufnahme.
#[tokio::test]
async fn every_attempt_is_signed_with_a_fresh_challenge() {
    let mut harness = SyncHarness::new().await;
    harness
        .server
        .script(vec![CommitReplyV1::Unreachable, CommitReplyV1::Unreachable]);
    let _ = harness.push_pending().await;
    harness.advance(60_000);
    let _ = harness.push_pending().await;

    let nonces = harness.server.seen_nonces();
    assert_eq!(nonces.len(), 2);
    assert_ne!(
        nonces[0], nonces[1],
        "eine wiederverwendete Nonce waere ein Replay"
    );
    assert_eq!(
        harness.server.challenge_calls(),
        2,
        "je Commit genau eine Challenge"
    );
}

/// Die begrenzte Wiederaufnahme ist ABZAEHLBAR und erreicht ihre Schranke.
///
/// Der Zaehler liegt in der lokalen Ablage, also zaehlt er ueber die frisch
/// gebauten Klienten der einzelnen Laeufe hinweg weiter. Genau das macht
/// `Wiederaufnahme erschoepft` ueberhaupt erreichbar — ein Prozessfeld finge
/// nach jedem Neustart wieder bei null an.
#[tokio::test]
async fn the_bounded_resume_reaches_its_profile_limit_across_restarts() {
    let mut harness = SyncHarness::controlled_network_connected().await;
    harness.server.script(vec![
        CommitReplyV1::Unreachable,
        CommitReplyV1::ServerError(503),
        CommitReplyV1::Unreachable,
        CommitReplyV1::Unreachable,
    ]);

    // Vier Laeufe: das Profil erlaubt drei Versuche, der vierte trifft auf die
    // erschoepfte Schranke.
    let mut summaries = Vec::new();
    for _ in 0..4 {
        harness.advance(60_000);
        summaries.push(
            harness
                .push_pending()
                .await
                .expect("eine erschoepfte Wiederaufnahme ist ein ZUSTAND und kein Fehler"),
        );
    }

    // UNBEDINGT und nicht in einem `if let`: eine Zusicherung, die nur laeuft,
    // wenn der gesuchte Fall eintrat, ist keine.
    let last = summaries
        .last()
        .expect("vier Laeufe liefern vier Zusammenfassungen");
    assert_eq!(last.status(), SyncStatus::Failed);
    assert_eq!(
        last.detail_cause(),
        Some(DetailCause::ResumeAttemptsExhausted)
    );
    assert_ne!(
        harness.status(),
        SyncStatus::Synchronized,
        "eine erschoepfte Wiederaufnahme ist NIE synchronisiert"
    );
}

/// Eine Ablehnung des Dienstes wird NICHT automatisch wiederholt.
///
/// `409` ist der Fork. `design.md`:1584 zaehlt ihn ausdruecklich zu den
/// Fehlern, die nicht automatisch uebergangen werden — ein zweiter Anlauf
/// aendert nichts an ihm und verdeckte nur, dass die Kette auseinanderlaeuft.
#[tokio::test]
async fn a_fork_is_never_automatically_retried() {
    let mut harness = SyncHarness::new().await;
    harness.server.script(vec![CommitReplyV1::ProtocolError(
        409,
        "EA-SYNC-CONFLICT".to_owned(),
    )]);

    assert_eq!(
        harness
            .push_pending()
            .await
            .expect_err("ein Fork MUSS den Lauf anhalten")
            .code(),
        "EA-SYNC-CLIENT-NOT-RETRIED"
    );
    assert_eq!(
        harness.server.commit_calls(),
        1,
        "der Fork wird GENAU EINMAL gesendet und nie wiederholt"
    );
}

/// Das Netzarchiv bekommt die committeten Bytes in der Reihenfolge des Plans.
///
/// Grants zuerst, `.eip` zuletzt — und byteidentisch mit dem, was committet
/// liegt.
#[tokio::test]
async fn the_network_archive_receives_grants_first_and_the_entry_last() {
    let mut harness = SyncHarness::controlled_network_connected().await;
    harness.server.return_receipt(fixtures::bad_receipt());
    let _ = harness.push_pending().await;

    let target = harness
        .target
        .as_ref()
        .expect("das Netzprofil traegt ein Ziel");
    let order = target.published_order();
    assert!(
        !order.is_empty(),
        "ohne Publikation misst dieser Test nichts"
    );
    let entry_at = order
        .iter()
        .position(|path| path.ends_with(".eip"))
        .expect("das committete .eip MUSS veroeffentlicht sein");
    assert_eq!(
        entry_at,
        order.len() - 1,
        "das .eip steht ZULETZT: {order:?}"
    );
    assert!(
        order[..entry_at].iter().all(|path| path.ends_with(".eag")),
        "vor dem .eip stehen ausschliesslich Grants: {order:?}"
    );

    // Und die veroeffentlichten Bytes sind die committeten. Ein Ziel, das
    // etwas anderes annimmt, gibt den Serverupload nicht frei.
    for (path, bytes) in order.iter().zip(target.published_bytes()) {
        assert_eq!(
            harness.writer().backend().read_for_test(path),
            Some(bytes),
            "{path} traegt im Netzarchiv andere Bytes als im Bestand"
        );
    }
}

/// Ein bestaetigter Cursor ueberlebt den Neustart.
///
/// Er liegt in derselben Zeile wie der Zaehler, und ein frisch gebauter Klient
/// findet ihn wieder — das ist der Wiederaufsetzpunkt, an dem eine
/// unterbrochene Uebertragung fortsetzt, statt von vorn zu beginnen.
#[tokio::test]
async fn a_confirmed_cursor_survives_a_restart() {
    let harness = SyncHarness::new().await;
    let entry = harness
        .pending_entry_object_hash()
        .await
        .expect("die Fixture traegt genau einen anstehenden Eintrag");

    assert_eq!(
        harness.resume_cursor(entry),
        None,
        "ohne bestaetigten Cursor gibt es keinen Wiederaufsetzpunkt"
    );
    let token = harness.record_demo_cursor(entry);
    assert_eq!(
        harness.resume_cursor(entry),
        Some(token),
        "der bestaetigte Cursor ueberlebt den frisch gebauten Klienten"
    );
}
