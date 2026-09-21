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

use ea_archive::{ArchivePath, GRANTS_DIR_V1};
use ea_archive_fs::{
    DetailCause, NetworkArchiveTargetV1, PlannedPublicationV1, PublicationOutcomeV1,
    PublicationQueue, PublicationTargetV1, SyncStatus,
};

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
        "EA-ARCHIVE-BYTE-CONFLICT"
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
        "EA-ARCHIVE-BYTE-CONFLICT",
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
        "EA-ARCHIVE-BYTE-CONFLICT"
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

#[test]
fn second_offline_publish_keeps_the_first_plan_and_resumes_both_in_order() {
    let (_guard, _root) = support::temp_root("queue-second-offline");
    let queue = support::queue_with_disconnecting_adapter();
    let first = support::two_grants_and_one_entry();
    let second = support::second_disjoint_plan();

    let first_state = queue.publish(first.clone()).unwrap();
    assert_eq!(first_state.outcome(), PublicationOutcomeV1::Deferred);

    // Der ZWEITE Plan trifft auf eine WEITERHIN getrennte Warteschlange: er
    // darf den ersten nicht verdrängen, sondern muss sich mit ihm
    // vereinigen — ausstehend zuerst, neu danach.
    let second_state = queue.publish(second.clone()).unwrap();
    assert_eq!(second_state.outcome(), PublicationOutcomeV1::Deferred);

    let resumed = queue.reconnect().resume().unwrap();
    let mut expected_order = first.order();
    expected_order.extend(second.order());
    let mut expected_bytes = first.exact_bytes();
    expected_bytes.extend(second.exact_bytes());

    assert_eq!(resumed.outcome(), PublicationOutcomeV1::PublishedCompletely);
    assert_eq!(resumed.published_order(), expected_order);
    assert_eq!(resumed.published_bytes(), expected_bytes);

    // Und danach ist die Warteschlange leer — kein Rest des ersten Plans.
    let empty = queue.resume().unwrap();
    assert_eq!(empty.outcome(), PublicationOutcomeV1::NothingPending);
}

#[test]
fn connected_publish_drains_an_outstanding_plan_before_the_new_one() {
    let (_guard, _root) = support::temp_root("queue-connected-drains-outstanding");
    let queue = support::queue_with_disconnecting_adapter();
    let first = support::two_grants_and_one_entry();
    let second = support::second_disjoint_plan();

    let deferred = queue.publish(first.clone()).unwrap();
    assert_eq!(deferred.outcome(), PublicationOutcomeV1::Deferred);

    // Das Ziel wird wieder erreichbar, BEVOR der zweite Plan ankommt: `publish`
    // muss den ausstehenden Plan zuerst mit dem neuen vereinigen und dann die
    // VOLLSTÄNDIGE Vereinigung in einem Zug abarbeiten — kein Verdrängen,
    // kein getrennter zweiter Lauf.
    let _ = queue.reconnect();
    let drained = queue.publish(second.clone()).unwrap();

    let mut expected_order = first.order();
    expected_order.extend(second.order());
    let mut expected_bytes = first.exact_bytes();
    expected_bytes.extend(second.exact_bytes());

    assert_eq!(drained.outcome(), PublicationOutcomeV1::PublishedCompletely);
    assert_eq!(drained.published_order(), expected_order);
    assert_eq!(drained.published_bytes(), expected_bytes);

    let empty = queue.resume().unwrap();
    assert_eq!(empty.outcome(), PublicationOutcomeV1::NothingPending);
}

#[test]
fn merge_with_conflicting_bytes_is_refused_and_keeps_the_pending_plan() {
    let (_guard, _root) = support::temp_root("queue-merge-conflict");
    let queue = support::queue_with_disconnecting_adapter();
    let first = support::two_grants_and_one_entry();
    let conflicting = support::plan_conflicting_with_two_grants_and_one_entry();

    let deferred = queue.publish(first.clone()).unwrap();
    assert_eq!(deferred.outcome(), PublicationOutcomeV1::Deferred);

    let error = queue.publish(conflicting).unwrap_err();
    assert_eq!(error.code(), "EA-ARCHIVE-BYTE-CONFLICT");

    // Der ausstehende Plan MUSS unverändert der erste sein: eine abgelehnte
    // Vereinigung darf ihn weder verlieren noch teilweise ersetzen.
    let resumed = queue.reconnect().resume().unwrap();
    assert_eq!(resumed.outcome(), PublicationOutcomeV1::PublishedCompletely);
    assert_eq!(resumed.published_order(), first.order());
    assert_eq!(resumed.published_bytes(), first.exact_bytes());
}

#[test]
fn merged_plan_over_the_queue_limit_is_refused_without_dropping_pending() {
    let (_guard, _root) = support::temp_root("queue-merge-over-bound");
    let queue = support::queue_with_disconnecting_adapter();
    let first = support::two_grants_and_one_entry();
    // 3 (erster Plan) + 62 (zweiter) = 65 > 64 (Profilgrenze der Fixture).
    let second = support::planned_grants(62, "bound-merge");

    let deferred = queue.publish(first.clone()).unwrap();
    assert_eq!(deferred.outcome(), PublicationOutcomeV1::Deferred);

    let over_bound = queue.publish(second).unwrap();
    assert_eq!(
        over_bound.outcome(),
        PublicationOutcomeV1::QueueLimitReached
    );
    assert_eq!(
        over_bound.detail_cause(),
        Some(DetailCause::QueueLimitReached)
    );

    // Abgelehnt wird nur die VEREINIGUNG: der zuvor angenommene erste Plan
    // bleibt vollständig in der Warteschlange.
    let resumed = queue.reconnect().resume().unwrap();
    assert_eq!(resumed.outcome(), PublicationOutcomeV1::PublishedCompletely);
    assert_eq!(resumed.published_order(), first.order());
    assert_eq!(resumed.published_bytes(), first.exact_bytes());
}

#[test]
fn derive_pending_orders_grants_before_their_entry_by_sequence() {
    let (_guard, root) = support::temp_root("derive-pending-order");
    let remote = support::open_remote(root.join("remote"));

    let entry_bytes = support::signed_entry_bytes();
    remote.materialize_for_test("entries/000000000001_x.eip", &entry_bytes);

    let grant_a = support::signed_grant_a().into_vec();
    let grant_b = support::signed_grant_b().into_vec();

    let local = support::FixedArchiveSource::new(vec![
        ("grants/000000000002_b.eag".to_owned(), grant_b.clone()),
        ("grants/000000000002_a.eag".to_owned(), grant_a.clone()),
        ("entries/000000000002_x.eip".to_owned(), entry_bytes.clone()),
        // Dieselbe Adresse UND dieselben Bytes wie am Netzziel: bereits
        // veröffentlicht, gehört nicht in den Plan.
        ("entries/000000000001_x.eip".to_owned(), entry_bytes.clone()),
        // KEIN Exact-Object-Präfix: Formatbeiwerk, kein
        // Publikationsgegenstand — muss aus dem Plan bleiben.
        ("format/beiwerk.txt".to_owned(), support::non_object_bytes()),
    ]);

    let plan = PlannedPublicationV1::derive_pending(&local, &remote).unwrap();

    assert_eq!(
        plan.order(),
        vec![
            "grants/000000000002_a.eag",
            "grants/000000000002_b.eag",
            "entries/000000000002_x.eip",
        ]
    );
    assert_eq!(plan.exact_bytes(), vec![grant_a, grant_b, entry_bytes]);
}

#[test]
fn derive_pending_refuses_differing_bytes_at_the_remote() {
    let (_guard, root) = support::temp_root("derive-pending-conflict");
    let remote = support::open_remote(root.join("remote"));

    let grant_a = support::signed_grant_a().into_vec();
    let grant_b = support::signed_grant_b().into_vec();
    remote.materialize_for_test("grants/000000000002_a.eag", &grant_a);

    // DIESELBE Adresse, ANDERE Bytes: das ist der Bytekonflikt.
    let local =
        support::FixedArchiveSource::new(vec![("grants/000000000002_a.eag".to_owned(), grant_b)]);

    match PlannedPublicationV1::derive_pending(&local, &remote) {
        Err(error) => assert_eq!(error.code(), "EA-ARCHIVE-BYTE-CONFLICT"),
        Ok(_) => panic!("derive_pending hätte einen Bytekonflikt melden müssen"),
    }
}

#[test]
fn derive_pending_surfaces_a_malformed_object_instead_of_silently_skipping_it() {
    let (_guard, root) = support::temp_root("derive-pending-malformed");
    let remote = support::open_remote(root.join("remote"));

    // Trägt das `.eag`-Präfix, parst aber NICHT vollständig: eine committete,
    // aber beschädigte Adresse. Sie MUSS als Fehler erscheinen — ansonsten
    // fiele sie still aus der Publikation, ohne dass je jemand es bemerkt.
    let local = support::FixedArchiveSource::new(vec![(
        "grants/000000000003_broken.eag".to_owned(),
        support::non_object_bytes_with_a_grant_prefix(),
    )]);

    match PlannedPublicationV1::derive_pending(&local, &remote) {
        Err(ea_archive::ArchiveBackendError::Format(_)) => {}
        Err(other) => panic!(
            "erwartet war ein Formfehler, gemeldet wurde {}",
            other.code()
        ),
        Ok(plan) => panic!(
            "derive_pending hätte das defekte Objekt melden müssen, lieferte aber {} Objekte",
            plan.len()
        ),
    }
}

#[test]
fn network_target_publishes_create_if_absent_and_verifies_readback() {
    let (_guard, root) = support::temp_root("network-target-publish");
    let network_root = root.join("network");
    std::fs::create_dir_all(&network_root).expect("die Netzwurzel der Fixture muss anlegbar sein");

    let target = NetworkArchiveTargetV1::new(
        network_root.clone(),
        support::controlled_network_profile(),
        support::policy_allowing_controlled_network(),
    )
    .expect("das Netzziel der Fixture muss entstehen");
    assert!(target.is_connected());

    let address = ArchivePath::in_dir(GRANTS_DIR_V1, "readback.eag").expect("gültige Adresse");
    let bytes = support::signed_grant_a().into_vec();
    target
        .publish_one(&address, &bytes)
        .expect("die Publikation muss gelingen");

    // Unabhängig NACHGELESEN — nicht über dasselbe Ziel, sondern über ein
    // frisches Backend derselben Wurzel: das belegt, dass die Bytes wirklich
    // am Netzziel liegen und nicht nur im gecachten Griff des Ziels.
    let verify = support::open_remote(network_root);
    assert_eq!(verify.read_for_test(address.as_str()), Some(bytes));
}

#[test]
fn network_target_reports_disconnected_when_root_is_missing_and_never_creates_it() {
    let (_guard, root) = support::temp_root("network-target-missing");
    let network_root = root.join("missing");

    let target = NetworkArchiveTargetV1::new(
        network_root.clone(),
        support::controlled_network_profile(),
        support::policy_allowing_controlled_network(),
    )
    .expect("das Netzziel der Fixture muss entstehen");

    assert!(!target.is_connected());
    assert!(
        !network_root.exists(),
        "open_existing legt die fehlende Wurzel NIE an"
    );
}

#[test]
fn queue_reports_upload_pending_when_the_network_root_disappears_and_resumes_after_it_returns() {
    let (_guard, root) = support::temp_root("network-target-root-loss");
    let network_root = root.join("network");
    std::fs::create_dir_all(&network_root).expect("die Netzwurzel der Fixture muss anlegbar sein");

    let target = NetworkArchiveTargetV1::new(
        network_root.clone(),
        support::controlled_network_profile(),
        support::policy_allowing_controlled_network(),
    )
    .expect("das Netzziel der Fixture muss entstehen");
    // Einmal ERFOLGREICH verbunden — belegt, dass der Verlust danach
    // wirklich ERKANNT wird und nicht bloß nie geprüft wurde.
    assert!(target.is_connected());

    let queue = PublicationQueue::new(
        Box::new(target),
        support::controlled_network_profile(),
        &support::policy_allowing_controlled_network(),
    )
    .expect("die Warteschlange der Fixture muss entstehen");
    let plan = support::two_grants_and_one_entry();

    // Das Netzlaufwerk verschwindet, BEVOR der Plan ankommt (EA-CNA-PUB-4).
    std::fs::remove_dir_all(&network_root).expect("die Netzwurzel muss entfernbar sein");

    let state = queue
        .publish(plan.clone())
        .expect("ein verlorenes Netzziel ist ein ZUSTAND und kein Fehler");
    assert_eq!(state.outcome(), PublicationOutcomeV1::Deferred);
    assert_eq!(
        state.detail_cause(),
        Some(DetailCause::NetworkArchiveWaiting)
    );

    // Die Wurzel kommt zurück — der aufgeschobene Plan läuft byteidentisch
    // zu Ende.
    std::fs::create_dir_all(&network_root).expect("die Netzwurzel muss wieder anlegbar sein");
    let resumed = queue.reconnect().resume().unwrap();
    assert_eq!(resumed.outcome(), PublicationOutcomeV1::PublishedCompletely);
    assert_eq!(resumed.published_bytes(), plan.exact_bytes());
    assert_eq!(resumed.published_order(), plan.order());
}

#[test]
fn two_threads_publishing_while_disconnected_both_survive_in_acceptance_order() {
    let (_guard, _root) = support::temp_root("queue-concurrent-publish");
    // Die künstliche Verzögerung weitet das Entscheidungsfenster von
    // `publish` (Vereinigung, Grenzprüfung, Verbindungsstatus) so weit, dass
    // zwei gleichzeitig gestartete Aufrufe es zuverlässig überlappen — ohne
    // auf eine günstige Verzahnung des Schedulers angewiesen zu sein.
    let queue = std::sync::Arc::new(support::queue_with_slow_disconnected_target(
        std::time::Duration::from_millis(20),
    ));
    let first = support::two_grants_and_one_entry();
    let second = support::second_disjoint_plan();

    // Ein Startschuss für beide Threads: sie treten die Entscheidung von
    // `publish` möglichst gleichzeitig an.
    let start = std::sync::Arc::new(std::sync::Barrier::new(2));

    let thread_first = {
        let queue = std::sync::Arc::clone(&queue);
        let plan = first.clone();
        let start = std::sync::Arc::clone(&start);
        std::thread::spawn(move || {
            start.wait();
            queue.publish(plan)
        })
    };
    let thread_second = {
        let queue = std::sync::Arc::clone(&queue);
        let plan = second.clone();
        let start = std::sync::Arc::clone(&start);
        std::thread::spawn(move || {
            start.wait();
            queue.publish(plan)
        })
    };

    let state_first = thread_first
        .join()
        .expect("Thread A darf nicht paniken")
        .expect("ein getrenntes Ziel ist ein ZUSTAND und kein Fehler");
    let state_second = thread_second
        .join()
        .expect("Thread B darf nicht paniken")
        .expect("ein getrenntes Ziel ist ein ZUSTAND und kein Fehler");
    assert_eq!(state_first.outcome(), PublicationOutcomeV1::Deferred);
    assert_eq!(state_second.outcome(), PublicationOutcomeV1::Deferred);

    let resumed = queue.reconnect().resume().unwrap();
    assert_eq!(resumed.outcome(), PublicationOutcomeV1::PublishedCompletely);

    // BEIDE Pläne müssen überleben — welcher zuerst durchkam, entscheidet der
    // Scheduler, aber niemals darf einer davon spurlos verschwinden. Die
    // Vereinigung hält jeden Plan als GANZES zusammen (siehe
    // `PublicationQueue::merge`), also ist die Reihenfolge eine der beiden
    // vollständigen Verkettungen.
    let mut forward = first.order();
    forward.extend(second.order());
    let mut backward = second.order();
    backward.extend(first.order());
    let order = resumed.published_order();
    assert!(
        order == forward || order == backward,
        "beide Pläne müssen vollständig und ungebrochen erscheinen: {order:?}"
    );
    assert_eq!(order.len(), first.order().len() + second.order().len());
}

#[test]
fn resume_waits_for_an_in_flight_connected_drain_instead_of_reporting_nothing_pending() {
    let (_guard, _root) = support::temp_root("queue-drain-blocks-resume");
    let arrived = std::sync::Arc::new(std::sync::Barrier::new(2));
    let release = std::sync::Arc::new(std::sync::Barrier::new(2));
    let plan = support::two_grants_and_one_entry();

    let (queue, _target) = support::queue_with_blocking_target(
        true,
        Some("grants/b.eag".to_owned()),
        std::sync::Arc::clone(&arrived),
        std::sync::Arc::clone(&release),
    );
    let queue = std::sync::Arc::new(queue);

    let publisher = {
        let queue = std::sync::Arc::clone(&queue);
        let plan = plan.clone();
        std::thread::spawn(move || queue.publish(plan))
    };

    // Warten, bis der Drain WIRKLICH mitten im zweiten Objekt hängt.
    arrived.wait();

    let resumer_done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let resumer = {
        let queue = std::sync::Arc::clone(&queue);
        let done = std::sync::Arc::clone(&resumer_done);
        std::thread::spawn(move || {
            let state = queue.resume();
            done.store(true, std::sync::atomic::Ordering::SeqCst);
            state
        })
    };

    // `resume` MUSS auf die Drain-Sperre warten: es darf in dieser kurzen
    // Beobachtungsspanne nicht fertig geworden sein, während der Drain noch
    // mitten im Plan hängt. Die eigentliche Garantie kommt vom Mutex selbst
    // (resume kann `drain_lock` nicht nehmen, solange `publisher` ihn hält)
    // — die Schlafzeit dient nur der Beobachtung.
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(
        !resumer_done.load(std::sync::atomic::Ordering::SeqCst),
        "resume() ist fertig, obwohl der Drain noch mitten im Plan hängt — es hat NICHT gewartet"
    );

    release.wait();

    let publish_state = publisher
        .join()
        .expect("Publisher-Thread darf nicht paniken")
        .expect("die Publikation muss gelingen");
    assert_eq!(
        publish_state.outcome(),
        PublicationOutcomeV1::PublishedCompletely
    );

    let resume_state = resumer
        .join()
        .expect("Resume-Thread darf nicht paniken")
        .expect("resume darf nicht fehlschlagen");
    assert_eq!(resume_state.outcome(), PublicationOutcomeV1::NothingPending);
}

#[test]
fn two_concurrent_connected_publishes_never_interleave_and_keep_the_global_order() {
    let (_guard, _root) = support::temp_root("queue-concurrent-connected-publish");
    let arrived = std::sync::Arc::new(std::sync::Barrier::new(2));
    let release = std::sync::Arc::new(std::sync::Barrier::new(2));
    let pending_plan = support::two_grants_and_one_entry();
    let plan_a = support::second_disjoint_plan();
    let plan_b = support::third_disjoint_plan();

    // Block auf der LETZTEN Adresse von `plan_a`: die Vereinigung
    // `pending_plan ⊎ plan_a` hat bis dahin schon alles Vorherige unblockiert
    // durchlaufen lassen.
    let block_on = plan_a
        .order()
        .last()
        .cloned()
        .expect("plan_a ist nicht leer");
    let (queue, target) = support::queue_with_blocking_target(
        false,
        Some(block_on),
        std::sync::Arc::clone(&arrived),
        std::sync::Arc::clone(&release),
    );

    // Der ausstehende Plan wird angenommen, WÄHREND das Ziel noch getrennt
    // ist — die "pending-first"-Hälfte der Zusage.
    let deferred = queue.publish(pending_plan.clone()).unwrap();
    assert_eq!(deferred.outcome(), PublicationOutcomeV1::Deferred);

    let queue = std::sync::Arc::new(queue);
    let _ = queue.reconnect();

    let thread_a = {
        let queue = std::sync::Arc::clone(&queue);
        let plan = plan_a.clone();
        std::thread::spawn(move || queue.publish(plan))
    };

    // Warten, bis A wirklich mitten im LETZTEN eigenen Objekt hängt — der
    // ausstehende Plan UND alle vorherigen Objekte von A sind zu diesem
    // Zeitpunkt schon durch.
    arrived.wait();
    let observed_before_b = target.published_order();

    // B versucht JETZT gleichzeitig zu publizieren. Ohne die Drain-Sperre
    // liefe B's eigener Drain PARALLEL zu A's und würde dessen Adressen
    // unterbrechen oder überholen.
    let thread_b = {
        let queue = std::sync::Arc::clone(&queue);
        let plan = plan_b.clone();
        std::thread::spawn(move || queue.publish(plan))
    };

    std::thread::sleep(std::time::Duration::from_millis(50));
    assert_eq!(
        target.published_order(),
        observed_before_b,
        "B darf WÄHREND A's Drain hängt noch KEIN einziges Objekt am Ziel abgelegt haben"
    );

    release.wait();

    let state_a = thread_a
        .join()
        .expect("Thread A darf nicht paniken")
        .expect("Publikation A muss gelingen");
    let state_b = thread_b
        .join()
        .expect("Thread B darf nicht paniken")
        .expect("Publikation B muss gelingen");

    assert_eq!(state_a.outcome(), PublicationOutcomeV1::PublishedCompletely);
    assert_eq!(state_b.outcome(), PublicationOutcomeV1::PublishedCompletely);

    let mut expected_order = pending_plan.order();
    expected_order.extend(plan_a.order());
    expected_order.extend(plan_b.order());
    assert_eq!(
        target.published_order(),
        expected_order,
        "die GESAMTE Ankunftsreihenfolge am Ziel muss ausstehend, dann A, dann B sein — nie verschachtelt"
    );
}

#[test]
fn a_write_failure_from_an_otherwise_reachable_target_is_treated_as_lost_connectivity() {
    let (_guard, _root) = support::temp_root("queue-io-write-failure");
    let (queue, target) = support::queue_with_an_unwritable_but_connected_target();
    let plan = support::two_grants_and_one_entry();

    let state = queue
        .publish(plan.clone())
        .expect("ein präsenter, aber unbeschreibbarer Mount ist ein ZUSTAND und kein Fehler");
    assert_eq!(state.outcome(), PublicationOutcomeV1::Deferred);
    assert_eq!(
        state.detail_cause(),
        Some(DetailCause::NetworkArchiveWaiting)
    );
    assert!(
        target.published_order().is_empty(),
        "vor der Reparatur darf am Ziel NICHTS angekommen sein"
    );

    target.repair();
    let resumed = queue.resume().unwrap();
    assert_eq!(resumed.outcome(), PublicationOutcomeV1::PublishedCompletely);
    assert_eq!(resumed.published_bytes(), plan.exact_bytes());
    assert_eq!(resumed.published_order(), plan.order());
}
