//! Der Publikationsausgang, die vier normativen Sync-Zustaende und die
//! Detailursache DANEBEN.
//!
//! Seit Task 10 sagt die Warteschlange, WAS mit den Bytes geschah, und nicht
//! mehr, in welchem oeffentlichen Zustand der Eintrag ist; die Zusicherungen
//! unten sind auf `PublicationOutcomeV1` umgeschrieben. Die eine Zusicherung,
//! die dabei ZURUECKGENOMMEN wurde, fragte einen leeren Platz nach
//! `synchronisiert` — genau diese Verwechslung ist gefallen. Ihre Aussage
//! steht unveraendert weiter da: ein leerer Platz ist
//! [`PublicationOutcomeV1::NothingPending`].

mod support;

use ea_archive_fs::{DetailCause, PublicationOutcomeV1, SyncStatus};

#[test]
fn a_lost_network_capability_keeps_upload_pending_with_its_own_detail_cause() {
    let (_guard, _root) = support::temp_root("queue-pending");
    let queue = support::queue_with_disconnecting_adapter();
    let state = queue.publish(support::two_grants_and_one_entry()).unwrap();
    assert_eq!(state.outcome(), PublicationOutcomeV1::Deferred);
    assert_eq!(
        state.detail_cause(),
        Some(DetailCause::NetworkArchiveWaiting)
    );
    assert!(!state.fell_back_to_another_target());
}

#[test]
fn resumption_publishes_byte_identical_objects_in_the_same_order() {
    let (_guard, _root) = support::temp_root("queue-resume");
    let queue = support::queue_with_disconnecting_adapter();
    let planned = support::two_grants_and_one_entry();
    queue.publish(planned.clone()).unwrap();
    let resumed = queue.reconnect().resume().unwrap();
    assert_eq!(resumed.published_bytes(), planned.exact_bytes());
    assert_eq!(resumed.published_order(), planned.order());
    assert_eq!(resumed.outcome(), PublicationOutcomeV1::PublishedCompletely);
    assert_eq!(resumed.detail_cause(), None);
    assert!(!resumed.fell_back_to_another_target());
}

#[test]
fn a_hard_target_failure_keeps_the_whole_plan_pending() {
    let (_guard, _root) = support::temp_root("queue-hard-failure");
    let (queue, target) = support::queue_with_a_reconnected_but_failing_target();
    let planned = support::two_grants_and_one_entry();

    // Das Ziel ist ERREICHBAR und lehnt am zweiten Objekt hart ab. Der Fehler
    // wird gemeldet — und ist ausdruecklich NICHT die verlorene
    // Erreichbarkeit, sonst prueefte der Test den alten Pfad weiter.
    assert_eq!(
        queue.resume().unwrap_err().code(),
        "EA-ARCHIVE-FLUSH-FAILED"
    );
    assert_eq!(
        target.published_order().len(),
        1,
        "genau das erste Objekt kam durch"
    );

    // Der aufgeschobene Plan darf dabei NICHT verloren gehen: ein zweiter
    // `resume` faende sonst einen leeren Slot und meldete `synchronisiert`,
    // obwohl zwei Objekte nie ankamen.
    assert_eq!(
        queue.resume().unwrap_err().code(),
        "EA-ARCHIVE-FLUSH-FAILED",
        "der Plan MUSS aufgeschoben geblieben sein"
    );

    // Nach der Reparatur laeuft der GANZE Plan byteidentisch und in seiner
    // Reihenfolge zu Ende — auch das erste, schon veroeffentlichte Objekt
    // erscheint wieder, weil der ganze Plan aufbewahrt wurde.
    target.repair();
    let resumed = queue.resume().unwrap();
    assert_eq!(resumed.outcome(), PublicationOutcomeV1::PublishedCompletely);
    assert_eq!(resumed.published_bytes(), planned.exact_bytes());
    assert_eq!(resumed.published_order(), planned.order());
    assert_eq!(target.published_order(), planned.order());

    // Und jetzt, und erst jetzt, ist die Warteschlange leer.
    let empty = queue.resume().unwrap();
    assert_eq!(empty.outcome(), PublicationOutcomeV1::NothingPending);
    assert!(empty.published_order().is_empty());
}

#[test]
fn a_hard_target_failure_keeps_a_freshly_accepted_plan_pending() {
    let (_guard, _root) = support::temp_root("queue-publish-hard-failure");
    let (queue, target) = support::queue_on_a_connected_but_failing_target();
    let planned = support::two_grants_and_one_entry();

    // Der Weg ueber `publish`: das Ziel war NIE getrennt, der Plan kommt frisch
    // an und laeuft am zweiten Objekt in den Hartfehler. Auch dieser Plan ist
    // ANGENOMMEN und darf nicht verloren gehen — dieser Aufrufer entsteht in
    // Task 11.
    assert_eq!(
        queue.publish(planned.clone()).unwrap_err().code(),
        "EA-ARCHIVE-FLUSH-FAILED"
    );
    assert_eq!(
        target.published_order().len(),
        1,
        "genau das erste Objekt kam durch"
    );

    target.repair();
    let resumed = queue.resume().unwrap();
    assert_eq!(resumed.outcome(), PublicationOutcomeV1::PublishedCompletely);
    assert_eq!(resumed.published_bytes(), planned.exact_bytes());
    assert_eq!(resumed.published_order(), planned.order());
    assert_eq!(target.published_order(), planned.order());
}

#[test]
fn the_four_sync_states_carry_the_exact_normative_copy() {
    assert_eq!(
        SyncStatus::ALL
            .iter()
            .map(|status| status.label())
            .collect::<Vec<_>>(),
        vec![
            "lokal gesichert",
            "Upload ausstehend",
            "synchronisiert",
            "Fehler"
        ]
    );
    // Die Detailursache ist ein EIGENER Text und niemals ein fuenfter Zustand:
    // keine Beschriftung einer Ursache ist die Beschriftung eines Zustands.
    for cause in DetailCause::ALL {
        assert!(
            !SyncStatus::ALL
                .iter()
                .any(|status| status.label() == cause.label()),
            "{} darf kein Zustand sein",
            cause.label()
        );
    }
    assert_eq!(
        DetailCause::NetworkArchiveWaiting.label(),
        "Netzarchiv wartet"
    );
}

#[test]
fn a_queue_bound_that_is_exceeded_fails_instead_of_falling_back() {
    let (_guard, _root) = support::temp_root("queue-bound");
    let queue = support::queue_with_disconnecting_adapter();
    let state = queue
        .publish(support::planned_publication_beyond_the_queue_bound())
        .unwrap();
    assert_eq!(state.outcome(), PublicationOutcomeV1::QueueLimitReached);
    assert_eq!(state.detail_cause(), Some(DetailCause::QueueLimitReached));
    assert!(
        !state.fell_back_to_another_target(),
        "die Anwendung faellt NIEMALS still auf ein anderes Ziel zurueck"
    );
}
