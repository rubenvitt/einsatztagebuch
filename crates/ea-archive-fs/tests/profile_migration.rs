//! Der auditierte Profilwechsel — und was bei jedem Fehler uebrig bleibt.

mod support;

use ea_archive_fs::MigrationFaultPoint;
use ea_format::{LocalAuditActionV1, decode_local_audit_event};

#[test]
fn migration_failure_leaves_only_the_old_profile_active() {
    let harness = support::migration_harness();
    let migrator = harness.migrator();
    let result = migrator
        .with_fault(MigrationFaultPoint::BeforePointerSwap)
        .run();
    assert!(result.is_err());
    assert_eq!(
        migrator.active_profile_hash().as_bytes(),
        support::source_profile_hash().as_bytes()
    );
    assert!(migrator.finalization_lock().is_available());
}

#[test]
fn every_fault_point_leaves_only_the_old_profile_active() {
    for point in support::all_fault_points() {
        let harness = support::migration_harness();
        let migrator = harness.migrator();
        let outcome = migrator.with_fault(*point).run();
        assert!(outcome.is_err(), "{point:?} MUSS die Migration abbrechen");
        assert_eq!(
            migrator.active_profile_hash().as_bytes(),
            support::source_profile_hash().as_bytes(),
            "{point:?} darf das Zielprofil nicht aktiv lassen"
        );
        assert!(
            migrator.finalization_lock().is_available(),
            "{point:?} muss die Finalisierungssperre wieder freigeben"
        );
    }
}

#[test]
fn a_fault_after_the_pointer_swap_rolls_the_pointer_back_to_a_higher_generation() {
    let harness = support::migration_harness();
    let migrator = harness.migrator();
    let previous_generation = migrator.previous_generation();
    assert!(
        migrator
            .with_fault(MigrationFaultPoint::AfterPointerSwap)
            .run()
            .is_err()
    );
    assert_eq!(
        migrator.active_profile_hash().as_bytes(),
        support::source_profile_hash().as_bytes()
    );
    // Der Rueckfall ist ein NEUER Zeiger und keine Wiederherstellung: die
    // Generation ist um ZWEI gestiegen — eins fuer den Wechsel, eins fuer die
    // Ruecknahme. Ein wiederholter Generationswert waere ein wiedereinspielbarer
    // Zeiger.
    assert_eq!(migrator.previous_generation(), previous_generation + 2);
}

#[test]
fn migration_requires_matching_reauth_and_audits_the_pointer_result() {
    let harness = support::migration_harness();
    let migrator = harness.migrator();
    assert_eq!(
        migrator
            .run_with(support::finalize_proof())
            .unwrap_err()
            .code(),
        "EA-ARCHIVE-REAUTH-MISMATCH"
    );
    let result = migrator
        .run_with(support::profile_migration_proof())
        .unwrap();
    let event = harness
        .audit()
        .signed_event(result.audit_event_id())
        .unwrap();
    let decoded = decode_local_audit_event(event.exact_bytes()).unwrap();
    let LocalAuditActionV1::ArchiveProfileMigration(context) = decoded.action() else {
        panic!("die gebuchte Zeile MUSS ein Profilwechsel sein");
    };
    assert_eq!(
        context.source_profile_hash().as_bytes(),
        support::source_profile_hash().as_bytes()
    );
    assert_eq!(
        context.target_profile_hash().as_bytes(),
        migrator.active_profile_hash().as_bytes()
    );
    assert_eq!(
        context.inventory_hash().as_bytes(),
        result.inventory_hash().as_bytes()
    );
    assert_eq!(
        context.active_pointer_hash().as_bytes(),
        result.active_pointer_hash().as_bytes()
    );
    assert!(harness.audit().is_flushed(result.audit_event_id()));
}

#[test]
fn a_target_profile_outside_the_effective_policy_is_refused_before_any_copy() {
    let harness = support::migration_harness_with_unlisted_target_profile();
    let migrator = harness.migrator();
    assert_eq!(
        migrator
            .run_with(support::profile_migration_proof())
            .unwrap_err()
            .code(),
        "EA-ARCHIVE-PROFILE-NOT-ALLOWED"
    );
    assert_eq!(migrator.staged_object_count(), 0);
}

#[test]
fn the_inventory_hash_is_equal_on_both_profiles_after_a_successful_switch() {
    let harness = support::migration_harness();
    let migrator = harness.migrator();
    let previous_generation = migrator.previous_generation();
    let result = migrator
        .run_with(support::profile_migration_proof())
        .unwrap();
    assert_eq!(
        result.source_inventory_hash().as_bytes(),
        result.target_inventory_hash().as_bytes()
    );
    assert_eq!(result.active_pointer_generation(), previous_generation + 1);
    assert!(
        result.source_remains_readable(),
        "das alte Profil bleibt lesbar und wird NIE automatisch geloescht"
    );
}

#[test]
fn every_durable_step_has_a_named_fault_point_before_and_after_it() {
    // Sieben dauerhafte Schritte, je ein Punkt davor und danach.
    assert_eq!(MigrationFaultPoint::ALL.len(), 14);
    let names = MigrationFaultPoint::ALL
        .iter()
        .map(|point| point.name())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        names.len(),
        MigrationFaultPoint::ALL.len(),
        "jeder Fehlerpunkt traegt einen eigenen Namen"
    );
    for point in MigrationFaultPoint::ALL {
        assert!(
            point.name().starts_with("before-") || point.name().starts_with("after-"),
            "{:?} muss sich einem dauerhaften Schritt zuordnen",
            point
        );
    }
}

#[test]
fn a_pending_old_profile_publication_stops_the_switch_before_the_inventory() {
    let harness = support::migration_harness_with_a_pending_publication();
    let migrator = harness.migrator();

    // Das Ziel der Warteschlange ist getrennt, die Publikation bleibt also
    // `Upload ausstehend`. Ein Wechsel, der sie zuruecklaesst, verliert genau
    // die Objekte, die noch nicht im Quellinventar stehen — und zwar unbemerkt,
    // weil Quell- und Zielinventar dann uebereinstimmen.
    assert_eq!(
        migrator
            .run_with(support::profile_migration_proof())
            .unwrap_err()
            .code(),
        "EA-ARCHIVE-PENDING-PUBLICATION"
    );
    assert_eq!(
        migrator.active_profile_hash().as_bytes(),
        support::source_profile_hash().as_bytes()
    );
    assert_eq!(
        migrator.staged_object_count(),
        0,
        "der Abbruch liegt VOR der Uebernahme"
    );
    assert!(migrator.finalization_lock().is_available());
}

#[test]
fn a_hard_target_failure_keeps_the_second_migration_attempt_fail_closed() {
    let harness = support::migration_harness_with_a_hard_failing_publication();

    // Das Ziel der Warteschlange ist ERREICHBAR und lehnt hart ab. Der erste
    // Versuch bricht damit vor dem Inventar ab.
    assert_eq!(
        harness
            .migrator()
            .run_with(support::profile_migration_proof())
            .unwrap_err()
            .code(),
        "EA-ARCHIVE-PENDING-PUBLICATION"
    );

    // Und der ZWEITE Versuch ebenso: verliert die Warteschlange ihren Plan am
    // Hartfehler, meldet ihr `resume` beim naechsten Mal `synchronisiert`, und
    // der Wechsel laeuft durch, ohne dass die geplanten Objekte je beim Ziel
    // angekommen sind. Genau diese stille Herabstufung darf es nicht geben.
    let second = harness.migrator();
    assert_eq!(
        second
            .run_with(support::profile_migration_proof())
            .unwrap_err()
            .code(),
        "EA-ARCHIVE-PENDING-PUBLICATION",
        "der Wiederholungsweg darf nicht fail-open werden"
    );
    assert_eq!(
        second.active_profile_hash().as_bytes(),
        support::source_profile_hash().as_bytes()
    );
    assert_eq!(
        second.staged_object_count(),
        0,
        "der Abbruch liegt VOR der Uebernahme"
    );
    assert!(second.finalization_lock().is_available());

    // Erst wenn das Ziel die Publikation wirklich annimmt, traegt der Wechsel —
    // und dann liegen alle drei geplanten Objekte beim Ziel.
    harness.repair_hard_failing_targets();
    let third = harness.migrator();
    third
        .run_with(support::profile_migration_proof())
        .expect("nach dem Beenden der Publikation MUSS der Wechsel tragen");
    assert_eq!(
        third.active_profile_hash().as_bytes(),
        support::target_profile_hash().as_bytes()
    );
    assert_eq!(
        harness.published_by_hard_failing_targets(),
        support::two_grants_and_one_entry().order()
    );
}

#[test]
fn a_finished_old_profile_publication_lets_the_switch_proceed() {
    let harness = support::migration_harness_with_a_pending_publication();
    // Wiederverbindung: die aufgeschobene Publikation laeuft byteidentisch zu
    // Ende, und ERST DANN traegt der Wechsel.
    harness.reconnect_pending_publications();
    let migrator = harness.migrator();
    let result = migrator
        .run_with(support::profile_migration_proof())
        .expect("nach dem Beenden der Publikation MUSS der Wechsel tragen");
    assert_eq!(
        migrator.active_profile_hash().as_bytes(),
        support::target_profile_hash().as_bytes()
    );
    assert_eq!(
        result.source_inventory_hash().as_bytes(),
        result.target_inventory_hash().as_bytes()
    );
}
