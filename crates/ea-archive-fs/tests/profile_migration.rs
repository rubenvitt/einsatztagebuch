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
        // Der CODE und nicht nur `is_err`. Ohne ihn waere die Schleife auch
        // dann gruen, wenn ein Fehlerpunkt aus einem GANZ ANDEREN Grund
        // abbraeche — etwa weil die Fixture ihr Ziel nicht mehr oeffnen kann.
        //
        // Dieselbe Fehlerart entsteht im selben Pfad noch an einer zweiten
        // Stelle: `generation.checked_add(1)`
        // (`crates/ea-archive-fs/src/profile_migration.rs:528`) meldet bei
        // einem Ueberlauf der Generationsachse ebenfalls `MigrationFault`. Die
        // Fixture beginnt bei Generation 0, also ist dieser Ausgang hier
        // ausgeschlossen und der gemessene Code dem EINGESPIELTEN Fehlerpunkt
        // zuzurechnen.
        let Err(error) = outcome else {
            panic!("{point:?} MUSS die Migration abbrechen");
        };
        assert_eq!(
            error.code(),
            "EA-ARCHIVE-MIGRATION-FAULT",
            "{point:?} muss GENAU den Fehlerpunktcode melden"
        );
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

/// Ein Ziel, das sich NICHT vollstaendig offline verifizieren laesst, wird nie
/// das aktive Profil.
///
/// Schritt 4 der Migration (`design.md` §11.5) verifiziert Quelle UND Ziel
/// gegen denselben Vertrauensanker, bevor der Zeiger umschaltet. Hier ist der
/// Anker fachfremd, also traegt schon `decode_trust_anchor`
/// (`crates/ea-archive-fs/src/profile_migration.rs:483-484`) nicht — und die
/// Migration bricht ab, OBWOHL die Stagingkopie in Schritt 3 bereits
/// durchgelaufen ist.
///
/// Genau darum steht die Nachpruefung dahinter: kopierte Bytes im Ziel sind
/// KEIN vollzogener Wechsel. Der Zeiger nennt weiter das Quellprofil, die
/// Zielwurzel traegt ueberhaupt keinen aktiven Zeiger, und die
/// Finalisierungssperre ist wieder frei.
#[test]
fn a_target_that_cannot_be_verified_offline_never_becomes_the_active_profile() {
    let harness = support::migration_harness();
    let audit = support::AuditHarness::new();
    let foreign_anchor = support::undecodable_anchor_bytes();
    let migrator = harness.migrator_with(&foreign_anchor, audit.service());

    let Err(error) = migrator.run() else {
        panic!("ein unlesbarer Vertrauensanker MUSS den Wechsel abbrechen");
    };
    assert_eq!(error.code(), "EA-ARCHIVE-VERIFICATION-FAILED");

    // Nichts ist dauerhaft geworden.
    assert_eq!(
        migrator.active_profile_hash().as_bytes(),
        support::source_profile_hash().as_bytes(),
        "das Quellprofil bleibt aktiv"
    );
    assert_eq!(
        migrator.previous_generation(),
        0,
        "ohne Umschaltung steigt die Generation nicht"
    );
    assert!(
        migrator.finalization_lock().is_available(),
        "die Finalisierungssperre ist wieder frei"
    );
    assert!(
        harness.target().active_profile_pointer_bytes().is_none(),
        "die Zielwurzel traegt keinen aktiven Profilzeiger"
    );

    // Die POSITIVKONTROLLE: dieselbe Fixture mit dem ECHTEN Anker vollzieht den
    // Wechsel. Ohne sie waere der Test auch dann gruen, wenn diese Fixture
    // ueberhaupt keinen Wechsel mehr hinbekaeme.
    let anchor = harness.anchor_bytes().to_vec();
    let honest = harness.migrator_with(&anchor, audit.service());
    assert!(
        honest.run().is_ok(),
        "mit dem echten Anker vollzieht dieselbe Fixture den Wechsel"
    );
}

/// Ein Ziel, dessen Bestand nach der Uebernahme NICHT der Quelle entspricht,
/// wird nie das aktive Profil.
///
/// Das Ziel traegt hier eine Datei, die die Quelle nicht kennt — der Rest einer
/// frueheren, abgebrochenen Uebernahme. Die Stagingkopie legt sie nicht an und
/// entfernt sie auch nicht: Create-if-absent ist idempotent, aber nicht
/// aufraeumend. Erst der Vergleich der beiden Verifikationsberichte in
/// Schritt 4 (`profile_migration.rs:497-503`) faellt darueber.
///
/// Gemessen wird nicht nur der Code, sondern auch, dass die fremde Datei den
/// Abbruch UEBERLEBT: die Migration raeumt im Ziel nichts weg, was sie nicht
/// selbst angelegt hat.
///
/// GRENZE DIESES ZEUGEN, ausgeschrieben, damit sie niemand fuer staerker haelt
/// als sie ist: derselbe Code entsteht im selben Pfad ein zweites Mal, sechs
/// Zeilen spaeter, aus dem Vergleich der beiden INVENTARhashes
/// (`profile_migration.rs:507-510`). Gemessen ist der ERSTE Vergleich — wird
/// seine Variante getauscht, wird dieser Test rot. Wird die Klausel dagegen
/// ganz entfernt, bleibt er GRUEN, weil der zweite Vergleich dieselbe
/// Abweichung faengt und denselben Code meldet. Das ist kein Mangel des
/// Zeugen, sondern eine Eigenschaft des Produktionscodes: Inventargleichheit
/// bedeutet gleiche Bytes an gleichen Pfaden und damit zwangslaeufig gleiche
/// Verifikationsberichte — der zweite Vergleich ist die staerkere Formulierung
/// desselben Waechters, und der erste ist nur der frueher greifende. Kein
/// Szenario kann die beiden trennen.
#[test]
fn a_target_whose_contents_diverge_from_the_source_never_becomes_the_active_profile() {
    const LEFTOVER: &str = "README-BETRIEB.txt";

    let harness = support::migration_harness();
    harness
        .target()
        .overwrite_for_test(LEFTOVER, b"uebrig aus einem frueheren Wechsel");
    let audit = support::AuditHarness::new();
    let anchor = harness.anchor_bytes().to_vec();
    let migrator = harness.migrator_with(&anchor, audit.service());

    let Err(error) = migrator.run() else {
        panic!("ein abweichender Zielbestand MUSS den Wechsel abbrechen");
    };
    assert_eq!(error.code(), "EA-ARCHIVE-INVENTORY-MISMATCH");

    assert_eq!(
        migrator.active_profile_hash().as_bytes(),
        support::source_profile_hash().as_bytes(),
        "das Quellprofil bleibt aktiv"
    );
    assert_eq!(migrator.previous_generation(), 0);
    assert!(migrator.finalization_lock().is_available());
    assert!(
        harness.target().active_profile_pointer_bytes().is_none(),
        "die Zielwurzel traegt keinen aktiven Profilzeiger"
    );
    assert!(
        harness.target().exists_for_test(LEFTOVER),
        "die fremde Datei bleibt liegen — der Wechsel raeumt fremde Bytes nicht weg"
    );
    assert!(
        !harness.source().exists_for_test(LEFTOVER),
        "und sie ist nie in die Quelle gewandert"
    );
}

/// Die signierte Auditzeile ist BEDINGUNG des Wechsels, nicht sein Nachklang.
///
/// Der Auditdienst signiert hier wirklich; nur seine Ablage nimmt nichts an.
/// Die Zeile wird NACH dem Zeigerwechsel gebucht, es ist also bereits eine
/// dauerhafte Wirkung eingetreten — und genau deshalb ist die Zusage hier keine
/// Rueckkehr per `?`, sondern eine RUECKNAHME: der Zeiger nennt danach wieder
/// das Quellprofil, und zwar bei der naechsthoeheren Generation, damit kein
/// Generationswert zweimal vorkommt.
///
/// Ohne diesen Zeugen bliebe der Ausgang unbewacht, an dem ein Wechsel
/// vollzogen und gleichzeitig unauditiert waere.
#[test]
fn an_unwritable_audit_line_rolls_the_pointer_back_to_the_source_profile() {
    let harness = support::migration_harness();
    let refusing = support::RefusingAuditHarness::new();
    let anchor = harness.anchor_bytes().to_vec();
    let migrator = harness.migrator_with(&anchor, refusing.service());
    let generation_before = migrator.previous_generation();

    let Err(error) = migrator.run() else {
        panic!("eine nicht buchbare Auditzeile MUSS den Wechsel abbrechen");
    };
    assert_eq!(error.code(), "EA-ARCHIVE-AUDIT-FAILED");

    assert_eq!(
        migrator.active_profile_hash().as_bytes(),
        support::source_profile_hash().as_bytes(),
        "nach der Ruecknahme ist wieder das Quellprofil aktiv"
    );
    // ZWEI Schritte: einer fuer die Umschaltung, einer fuer die Ruecknahme. Ein
    // wiederholter Generationswert waere ein wiedereinspielbarer Zeiger.
    assert_eq!(migrator.previous_generation(), generation_before + 2);
    assert!(
        migrator.finalization_lock().is_available(),
        "die Finalisierungssperre ist wieder frei"
    );

    // GENAU EIN aktiver Zeiger, gelesen AUS DER ABLAGE und nicht aus dem
    // Spiegel der abgebrochenen Instanz.
    let roots_with_a_pointer = [harness.source(), harness.target()]
        .into_iter()
        .filter(|backend| backend.active_profile_pointer_bytes().is_some())
        .count();
    assert_eq!(
        roots_with_a_pointer, 1,
        "genau eine Wurzel fuehrt einen aktiven Profilzeiger"
    );
}
