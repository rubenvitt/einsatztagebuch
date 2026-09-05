//! Die tragende Invariante der Ersteinrichtung: zwoelf Schritte, nur vorwaerts,
//! und der Produktivzustand erst nach dem Frischrechner-Recovery-Test.
//!
//! Die Spezifikation zaehlt den gefuehrten Prozess in `§12.1` ab
//! (`docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md:1336-1347`)
//! und schliesst ihn mit zwei normativen Saetzen: „Jede Aenderung eines bereits
//! in Schritt 4 festgeschriebenen Feldes bricht das Setup ab und beginnt mit
//! neuen Organisations-/Ketten-IDs" und „Ohne erfolgreichen Schritt 12 darf die
//! Organisation nicht in den Produktivzustand wechseln" (`:1349`).
//!
//! Beide Saetze sind hier Zeugen und keine Prosa. Der teuerste von ihnen ist
//! der sechste: ein VOLLSTAENDIG selbstkonsistenter finaler Anker einer FREMDEN
//! Zeremonie wird abgewiesen, weil er eine andere Vorstufe fortsetzt als die,
//! die diese Zeremonie in Schritt 4 auf ihren Medien festgeschrieben hat.
//!
//! Alles hier ist `#[test]` und synchron; diese Crate kennt kein Tokio.

mod support;

use std::{collections::BTreeSet, fs, path::PathBuf};

use ea_admin::{
    AdminError, AnchorMediumId, BootstrapCoordinator, BootstrapStep, FileBootstrapStore,
    ProductionState, confirm_pre_anchor_fingerprint,
};
use ea_trust::decode_trust_anchor;

use support::{
    BootstrapHarness, FIRST_MEDIUM, MediaStack, MemoryBootstrapStore, SECOND_MEDIUM,
    SequentialRandom, bootstrap_admin_pairs, changed_admin_pairs, fixture_root_material,
    trust_support,
};

/// Der Befund eines Laufs, dessen ERFOLGSWERT kein `Debug` traegt.
///
/// `expect_err` verlangt es; [`BootstrapCoordinator`] traegt es
/// ausdruecklich nicht — er haelt eine geliehene Ablage und einen Zustand, und
/// beides gehoert in keine Diagnosezeile.
fn expect_admin_error<T>(result: Result<T, AdminError>, expected: &str) {
    match result {
        Ok(_) => panic!("dieser Lauf muss mit {expected} scheitern"),
        Err(error) => expect_admin_code(error, expected),
    }
}

fn expect_admin_code(error: AdminError, expected: &str) {
    assert_eq!(error.code(), expected);
    assert_eq!(error.to_string(), expected);
    assert_eq!(format!("{error:?}"), expected);
}

// ---------------------------------------------------------------------------
// Schritt 12 und der Produktivzustand
// ---------------------------------------------------------------------------

/// Der Zeuge aus Schritt 1 des Plans.
#[test]
fn production_state_requires_all_twelve_steps_and_fresh_recovery() {
    let mut setup = BootstrapHarness::new();
    setup.complete_through_genesis().unwrap();
    assert_eq!(
        setup.production_state(),
        ProductionState::BlockedRecoveryTest
    );
    setup.run_fresh_machine_recovery().unwrap();
    assert_eq!(setup.production_state(), ProductionState::Ready);
}

#[test]
fn a_partial_recovery_test_never_becomes_a_successful_one() {
    let mut setup = BootstrapHarness::new();
    setup.complete_through_genesis().unwrap();
    let error = setup
        .run_fresh_machine_recovery_missing_one_medium()
        .expect_err("ein fehlendes Medium macht den GESAMTEN Test fehlgeschlagen");
    expect_admin_code(error, "EA-CEREMONY-RECOVERY-TEST-FAILED");
    assert_eq!(
        setup.production_state(),
        ProductionState::BlockedRecoveryTest
    );
}

#[test]
fn a_recovery_test_on_the_ceremony_machine_is_not_a_fresh_machine_test() {
    let mut setup = BootstrapHarness::new();
    setup.complete_through_genesis().unwrap();
    let error = setup
        .run_recovery_on_the_ceremony_machine()
        .expect_err("Schritt 12 verlangt einen FRISCHEN Rechner");
    expect_admin_code(error, "EA-CEREMONY-RECOVERY-TEST-SAME-MACHINE");
    assert_eq!(
        setup.production_state(),
        ProductionState::BlockedRecoveryTest
    );
}

// ---------------------------------------------------------------------------
// Nur vorwaerts
// ---------------------------------------------------------------------------

#[test]
fn a_restart_resumes_the_same_step_it_stopped_at() {
    let mut store = MemoryBootstrapStore::default();
    let mut random = SequentialRandom::default();
    let (organization, chain) = {
        let mut coordinator = BootstrapCoordinator::begin(&mut store, &mut random).unwrap();
        coordinator
            .generate_offline_root(fixture_root_material())
            .unwrap();
        assert_eq!(coordinator.step(), BootstrapStep::GenerateOfflineRoot);
        (coordinator.organization_id(), coordinator.chain_id())
    };

    let resumed = BootstrapCoordinator::resume(&mut store)
        .unwrap()
        .expect("eine begonnene Zeremonie laesst sich fortsetzen");
    assert_eq!(resumed.step(), BootstrapStep::GenerateOfflineRoot);
    assert_eq!(
        resumed.organization_id().as_bytes(),
        organization.as_bytes()
    );
    assert_eq!(resumed.chain_id().as_bytes(), chain.as_bytes());
    assert_eq!(
        resumed
            .re_enter(BootstrapStep::GenerateOfflineRoot)
            .unwrap(),
        BootstrapStep::GenerateOfflineRoot
    );
}

#[test]
fn a_ceremony_never_steps_backward() {
    let mut store = MemoryBootstrapStore::default();
    let mut random = SequentialRandom::default();
    let mut coordinator = BootstrapCoordinator::begin(&mut store, &mut random).unwrap();
    coordinator
        .generate_offline_root(fixture_root_material())
        .unwrap();
    let error = coordinator
        .re_enter(BootstrapStep::GenerateIds)
        .expect_err("ein bereits abgeschlossener Schritt wird nicht erneut betreten");
    expect_admin_code(error, "EA-CEREMONY-BOOTSTRAP-STEP-REGRESSION");
    assert_eq!(coordinator.step(), BootstrapStep::GenerateOfflineRoot);
}

#[test]
fn a_step_that_has_no_predecessor_yet_is_out_of_order() {
    let mut store = MemoryBootstrapStore::default();
    let mut random = SequentialRandom::default();
    let coordinator = BootstrapCoordinator::begin(&mut store, &mut random).unwrap();
    let error = coordinator
        .re_enter(BootstrapStep::PinPreAnchorOnMedia)
        .expect_err("Schritt 4 ist noch nicht erreicht");
    expect_admin_code(error, "EA-CEREMONY-BOOTSTRAP-STEP-OUT-OF-ORDER");
}

// ---------------------------------------------------------------------------
// Schritt 4: ohne bestaetigte Medien geht es nicht weiter
// ---------------------------------------------------------------------------

#[test]
fn an_unconfirmed_pre_anchor_blocks_every_step_after_the_fourth() {
    let mut store = MemoryBootstrapStore::default();
    let mut random = SequentialRandom::default();
    let mut coordinator = BootstrapCoordinator::begin(&mut store, &mut random).unwrap();
    coordinator
        .generate_offline_root(fixture_root_material())
        .unwrap();
    coordinator
        .create_admin_pairs(&bootstrap_admin_pairs())
        .unwrap();
    let error = coordinator
        .generate_recovery_and_hga_keys(support::recovery_kem_record(), support::hga_record())
        .expect_err("Schritt 5 verlangt die festgeschriebene Vorstufe");
    expect_admin_code(error, "EA-CEREMONY-PRE-ANCHOR-UNCONFIRMED");
}

#[test]
fn a_medium_that_reads_back_other_bytes_leaves_the_pre_anchor_unsealed() {
    let mut store = MemoryBootstrapStore::default();
    let mut random = SequentialRandom::default();
    let mut coordinator = BootstrapCoordinator::begin(&mut store, &mut random).unwrap();
    coordinator
        .generate_offline_root(fixture_root_material())
        .unwrap();
    let pre_fingerprint = coordinator
        .create_admin_pairs(&bootstrap_admin_pairs())
        .unwrap();
    let mut media = MediaStack::corrupting(&[SECOND_MEDIUM]);
    let confirmation = confirm_pre_anchor_fingerprint(
        coordinator.pre_anchor().expect("Schritt 3 hat sie gebaut"),
        pre_fingerprint,
    )
    .unwrap();
    let error = coordinator
        .pin_pre_anchor_on_media(&mut media, &[FIRST_MEDIUM, SECOND_MEDIUM], confirmation)
        .expect_err("ein Medium liest andere Bytes zurueck");
    expect_admin_code(error, "EA-CEREMONY-MEDIA-READBACK-MISMATCH");
    assert_eq!(coordinator.step(), BootstrapStep::CreateAdminPairs);
}

#[test]
fn one_medium_alone_cannot_seal_the_pre_anchor() {
    let mut store = MemoryBootstrapStore::default();
    let mut random = SequentialRandom::default();
    let mut coordinator = BootstrapCoordinator::begin(&mut store, &mut random).unwrap();
    coordinator
        .generate_offline_root(fixture_root_material())
        .unwrap();
    let pre_fingerprint = coordinator
        .create_admin_pairs(&bootstrap_admin_pairs())
        .unwrap();
    let mut media = MediaStack::default();
    let confirmation =
        confirm_pre_anchor_fingerprint(coordinator.pre_anchor().unwrap(), pre_fingerprint).unwrap();
    let error = coordinator
        .pin_pre_anchor_on_media(&mut media, &[FIRST_MEDIUM], confirmation)
        .expect_err("ein Datentraeger ist kein Bestand");
    expect_admin_code(error, "EA-CEREMONY-MEDIA-QUORUM-MISSING");
}

// ---------------------------------------------------------------------------
// Die Versiegelung: der Kern dieser Aufgabe
// ---------------------------------------------------------------------------

/// Ein FREMDER, in sich vollkommen stimmiger Anker.
///
/// [`decode_trust_anchor`] nimmt ihn an — er rechnet seine eigene Vorstufe
/// nach und findet nichts. Erst der Vergleich gegen die in Schritt 4
/// bestaetigte Vorstufe DIESER Zeremonie faengt ihn.
#[test]
fn a_self_consistent_foreign_archive_fails_at_this_ceremonys_anchor() {
    let mut setup = BootstrapHarness::new();
    setup.complete_through_root_signed_targets().unwrap();
    let foreign = trust_support::RegistryLineBuilder::new();
    assert!(
        decode_trust_anchor(foreign.exact_anchor_bytes()).is_ok(),
        "der fremde Anker ist in sich stimmig"
    );
    let error = setup
        .adopt_final_anchor(foreign.exact_anchor_bytes())
        .expect_err("er setzt eine ANDERE Vorstufe fort");
    expect_admin_code(error, "EA-ANCHOR-PRE-FIELD-CHANGED");
}

#[test]
fn changing_a_pre_anchor_field_after_the_seal_forces_new_organization_and_chain_ids() {
    let mut setup = BootstrapHarness::new();
    setup.complete_through_pre_anchor_seal().unwrap();
    let (aborted_organization, aborted_chain) = setup.current_ids();

    // `ea-types` gibt `Hash32` bewusst kein `Debug`; der Zeuge deutet den
    // Ausgang deshalb selbst statt ueber `expect_err`.
    let Err(error) = setup.rewrite_admin_pairs(&changed_admin_pairs()) else {
        panic!("ein festgeschriebenes Feld aendert sich nicht mehr");
    };
    expect_admin_code(error, "EA-ANCHOR-PRE-FIELD-CHANGED");

    setup.restart_with_new_ids().unwrap();
    let (fresh_organization, fresh_chain) = setup.current_ids();
    assert_ne!(
        fresh_organization.as_bytes(),
        aborted_organization.as_bytes(),
        "die neue Zeremonie traegt eine neue Organisations-ID"
    );
    assert_ne!(
        fresh_chain.as_bytes(),
        aborted_chain.as_bytes(),
        "die neue Zeremonie traegt eine neue Ketten-ID"
    );
    assert_eq!(setup.step(), BootstrapStep::GenerateIds);
}

#[test]
fn a_ceremony_that_was_not_aborted_cannot_be_restarted() {
    let mut setup = BootstrapHarness::new();
    setup.complete_through_pre_anchor_seal().unwrap();
    let error = setup
        .restart_with_new_ids()
        .expect_err("eine laufende Zeremonie faengt nicht einfach neu an");
    expect_admin_code(error, "EA-CEREMONY-BOOTSTRAP-STEP-REGRESSION");
}

// ---------------------------------------------------------------------------
// Was persistiert wird — und was nicht
// ---------------------------------------------------------------------------

#[test]
fn the_persisted_ceremony_state_carries_no_key_material() {
    let mut setup = BootstrapHarness::new();
    setup.complete_through_genesis().unwrap();
    let image = setup.persisted_image();
    assert!(!image.is_empty(), "die Zeremonie hat etwas persistiert");
    for secret in support::every_fixture_secret() {
        assert!(
            !image
                .windows(secret.len())
                .any(|window| window == secret.as_slice()),
            "der persistierte Zustand traegt Schluesselmaterial"
        );
    }
}

#[test]
fn the_persisted_ceremony_state_carries_the_public_anchor_bytes() {
    let mut setup = BootstrapHarness::new();
    setup.complete_through_genesis().unwrap();
    let image = setup.persisted_image();
    let pre = setup.sealed_pre_anchor_bytes();
    assert!(
        image
            .windows(pre.len())
            .any(|window| window == pre.as_slice()),
        "die exakten Vorstufenbytes gehoeren in den persistierten Zustand"
    );
}

// ---------------------------------------------------------------------------
// Das signierte Bootstrap-Transkript
// ---------------------------------------------------------------------------

#[test]
fn the_bootstrap_transcript_records_the_root_and_both_anchor_pinned_admin_pairs() {
    let mut setup = BootstrapHarness::new();
    setup.complete_through_genesis().unwrap();
    let transcript = setup.transcript();
    assert_eq!(
        transcript.root_certificate_object_hash().as_bytes(),
        fixture_root_material().certificate_object_hash.as_bytes()
    );
    assert_eq!(transcript.admin_pairs().len(), 2);
    assert!(
        !transcript.root_signature_bytes().is_empty(),
        "das Transkript ist Wurzel-signiert"
    );
}

// ---------------------------------------------------------------------------
// Die Medienkennung
// ---------------------------------------------------------------------------

#[test]
fn the_twelve_steps_are_ordered_and_complete() {
    let steps = BootstrapStep::ALL;
    assert_eq!(steps.len(), 12);
    for pair in steps.windows(2) {
        assert!(pair[0] < pair[1], "die Schritte sind aufsteigend geordnet");
    }
    assert_eq!(steps[0], BootstrapStep::GenerateIds);
    assert_eq!(steps[11], BootstrapStep::RunFreshMachineRecoveryTest);
    assert_eq!(AnchorMediumId::new([0x01; 16]), FIRST_MEDIUM);
}

// ---------------------------------------------------------------------------
// Die dateigestuetzte Ablage
// ---------------------------------------------------------------------------

/// Der Pfad, unter dem eine Zeremonie neben ihrem kuenftigen Anker liegt.
fn state_path(directory: &support::TempDir) -> PathBuf {
    directory.path().join("anchor.etb.bootstrap-state")
}

/// DER tragende Zeuge der Ablage: eine Zeremonie ueberlebt den Prozess.
///
/// Der erste Block endet, der Koordinator und die Ablage werden fallen
/// gelassen — es bleibt nichts als die Datei. Was danach fortsetzt, muss
/// dieselbe Zeremonie sein und nicht eine zweite daneben: `:1349` laesst neue
/// Kennungen ausschliesslich nach einem Abbruch zu.
#[test]
fn a_file_backed_ceremony_resumes_with_the_same_identifiers_after_the_process_ended() {
    let directory = support::temp_dir("resume");
    let path = state_path(&directory);

    let (organization, chain) = {
        let mut store = FileBootstrapStore::new(path.clone());
        let coordinator =
            BootstrapCoordinator::begin(&mut store, &mut SequentialRandom::default()).unwrap();
        assert_eq!(coordinator.step(), BootstrapStep::GenerateIds);
        (coordinator.organization_id(), coordinator.chain_id())
    };

    let mut store = FileBootstrapStore::new(path);
    let resumed = BootstrapCoordinator::resume(&mut store)
        .unwrap()
        .expect("die persistierte Zeremonie laesst sich fortsetzen");
    assert_eq!(resumed.step(), BootstrapStep::GenerateIds);
    assert_eq!(
        resumed.organization_id().as_bytes(),
        organization.as_bytes()
    );
    assert_eq!(resumed.chain_id().as_bytes(), chain.as_bytes());
    assert_eq!(
        resumed.production_state(),
        ProductionState::BlockedRecoveryTest
    );
}

/// Eine fehlende Datei ist KEINE Zeremonie und kein Fehlschlag.
#[test]
fn an_absent_state_file_is_no_ceremony_and_no_failure() {
    let directory = support::temp_dir("absent");
    let mut store = FileBootstrapStore::new(state_path(&directory));
    assert!(
        BootstrapCoordinator::resume(&mut store).unwrap().is_none(),
        "ohne Datei gibt es nichts fortzusetzen"
    );
}

/// Die Datei traegt GENAU das Abbild des Ports und kein Byte darueber hinaus.
#[test]
fn the_state_file_carries_exactly_the_persisted_image() {
    let directory = support::temp_dir("image");
    let path = state_path(&directory);
    let mut store = FileBootstrapStore::new(path.clone());
    let coordinator =
        BootstrapCoordinator::begin(&mut store, &mut SequentialRandom::default()).unwrap();
    assert_eq!(
        fs::read(&path).expect("die Zustandsdatei muss lesbar sein"),
        coordinator.state().persisted_image()
    );
}

/// Ein Abbild JENSEITS von Schritt 1 wird abgewiesen statt halb gelesen.
///
/// `BootstrapStateV1::persisted_image` ist bewusst verlustbehaftet: ein
/// [`ea_key_provider::KeyHandle`] gibt darin Anwendung, Kontoinstanz und Zweck
/// preis, aber weder seinen `KeystoreProvider` noch seine `KeyEntryPolicy`.
/// Ein Zustand mit Schluesselgriffen ist daraus also nicht wiederherstellbar —
/// und was nicht bytegetreu zurueckkommt, wird nicht geraten.
#[test]
fn a_state_image_beyond_the_first_step_is_refused_rather_than_half_read() {
    let mut memory = MemoryBootstrapStore::default();
    {
        let mut coordinator =
            BootstrapCoordinator::begin(&mut memory, &mut SequentialRandom::default()).unwrap();
        coordinator
            .generate_offline_root(fixture_root_material())
            .unwrap();
    }

    let directory = support::temp_dir("beyond");
    let path = state_path(&directory);
    fs::write(&path, memory.image()).expect("das Abbild muss schreibbar sein");

    let mut store = FileBootstrapStore::new(path);
    expect_admin_error(
        BootstrapCoordinator::resume(&mut store),
        "EA-CEREMONY-BOOTSTRAP-STATE-SHAPE",
    );
}

/// Eine abgeschnittene Datei ist kein halber Zustand, sondern keiner.
#[test]
fn a_truncated_state_file_is_refused() {
    let directory = support::temp_dir("truncated");
    let path = state_path(&directory);
    let mut store = FileBootstrapStore::new(path.clone());
    let image = BootstrapCoordinator::begin(&mut store, &mut SequentialRandom::default())
        .unwrap()
        .state()
        .persisted_image();
    fs::write(&path, &image[..image.len() / 2]).expect("das Abbild muss schreibbar sein");

    let mut store = FileBootstrapStore::new(path);
    expect_admin_error(
        BootstrapCoordinator::resume(&mut store),
        "EA-CEREMONY-BOOTSTRAP-STATE-SHAPE",
    );
}

/// Eine Ablage, die nicht antwortet, meldet den Befund IHRES Ports.
///
/// Kein Zustandsbefund: die Bytes wurden gar nicht erst gelesen, es ist also
/// nichts ueber ihre Gestalt gesagt.
#[test]
fn a_state_path_that_cannot_be_read_is_a_store_finding() {
    let directory = support::temp_dir("unreadable");
    let path = state_path(&directory);
    fs::create_dir(&path).expect("das Verzeichnis muss anlegbar sein");

    let mut store = FileBootstrapStore::new(path);
    expect_admin_error(
        BootstrapCoordinator::begin(&mut store, &mut SequentialRandom::default()),
        "EA-CEREMONY-BOOTSTRAP-STORE-UNAVAILABLE",
    );
}

// ---------------------------------------------------------------------------
// Der Name eines Schritts
// ---------------------------------------------------------------------------

/// Jeder Schritt nennt sich selbst, und keine zwei teilen einen Namen.
///
/// Der Name ist beobachtbares Aussenverhalten — `apps/cli` druckt ihn. Er
/// steht deshalb als Tabelle neben [`BootstrapStep::number`] und nicht als
/// abgeleitetes `Debug` in einer Oberflaeche, die ihn nachbaut.
#[test]
fn every_step_names_itself_and_no_two_share_a_name() {
    let mut names = BTreeSet::new();
    for (index, step) in BootstrapStep::ALL.into_iter().enumerate() {
        assert_eq!(usize::from(step.number()), index + 1);
        assert_eq!(step.name(), format!("{step:?}"));
        names.insert(step.name());
    }
    assert_eq!(names.len(), 12, "zwoelf Schritte, zwoelf Namen");
}
