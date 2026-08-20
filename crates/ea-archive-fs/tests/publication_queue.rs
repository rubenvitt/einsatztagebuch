//! Die vier normativen Sync-Zustaende und die Detailursache DANEBEN.

mod support;

use ea_archive_fs::{DetailCause, SyncStatus};

#[test]
fn a_lost_network_capability_keeps_upload_pending_with_its_own_detail_cause() {
    let (_guard, _root) = support::temp_root("queue-pending");
    let queue = support::queue_with_disconnecting_adapter();
    let state = queue.publish(support::two_grants_and_one_entry()).unwrap();
    assert_eq!(state.sync_status(), SyncStatus::UploadPending);
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
    assert_eq!(resumed.sync_status(), SyncStatus::Synchronized);
    assert_eq!(resumed.detail_cause(), None);
    assert!(!resumed.fell_back_to_another_target());
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
    assert_eq!(state.sync_status(), SyncStatus::Failed);
    assert_eq!(state.detail_cause(), Some(DetailCause::QueueLimitReached));
    assert!(
        !state.fell_back_to_another_target(),
        "die Anwendung faellt NIEMALS still auf ein anderes Ziel zurueck"
    );
}
