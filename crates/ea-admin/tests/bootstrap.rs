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
    AdminError, AnchorMediumId, BootstrapCoordinator, BootstrapStep, BootstrapStore,
    FileBootstrapStore, OuterKeyRecordV1, ProductionState, confirm_pre_anchor_fingerprint,
};
use ea_crypto::{ContentType, object_hash, parse_cose_sign1};
use ea_trust::decode_trust_anchor;
use ea_types::CertificateHash;

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
        let mut coordinator =
            BootstrapCoordinator::begin(&mut store, &mut random, Some(support::ceremony_machine()))
                .unwrap();
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
    let mut coordinator =
        BootstrapCoordinator::begin(&mut store, &mut random, Some(support::ceremony_machine()))
            .unwrap();
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
    let coordinator =
        BootstrapCoordinator::begin(&mut store, &mut random, Some(support::ceremony_machine()))
            .unwrap();
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
    let mut coordinator =
        BootstrapCoordinator::begin(&mut store, &mut random, Some(support::ceremony_machine()))
            .unwrap();
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
    let mut coordinator =
        BootstrapCoordinator::begin(&mut store, &mut random, Some(support::ceremony_machine()))
            .unwrap();
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
    let mut coordinator =
        BootstrapCoordinator::begin(&mut store, &mut random, Some(support::ceremony_machine()))
            .unwrap();
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

    // „Wurzel-signiert" ist keine Aussage ueber die LAENGE der Signatur: ein
    // Port, der ein einzelnes `0x00` zurueckgaebe, bestuende ein
    // `!is_empty()`. Gemessen wird deshalb die Zuschreibung selbst — Inhalt,
    // Urkunde, Abdruck und Urbild der COSE.
    let parsed = parse_cose_sign1(transcript.root_signature_bytes(), &[])
        .expect("die Wurzelsignatur ist eine COSE_Sign1");
    assert!(parsed.content_type() == ContentType::TrustDigest);
    assert_eq!(
        parsed.payload(),
        object_hash(transcript.exact_bytes()).as_bytes(),
        "die Wurzel hat ueber GENAU die Transkriptbytes unterschrieben"
    );
    assert_eq!(
        parsed.key_thumbprint().as_bytes(),
        fixture_root_material().key_thumbprint.as_bytes()
    );
    // `ea-types` gibt `CertificateHash` bewusst kein `Debug`; der Zeuge
    // vergleicht deshalb selbst.
    assert!(
        parsed.certificate_hash()
            == Some(CertificateHash::from(
                fixture_root_material().certificate_object_hash
            )),
        "die COSE nennt die Wurzelurkunde dieser Zeremonie"
    );
}

/// Eine COSE, die die Wurzel NICHT unterschrieben hat, schliesst Schritt 11
/// nicht ab.
///
/// `FixtureKeyProvider::impersonating_root` nennt im geschuetzten Kopf den
/// Abdruck der Wurzel und unterschreibt mit einem fremden Schluessel — genau
/// der Fall, den ein reiner Abdruckvergleich nicht faengt.
/// [`ea_admin::RootCeremonyService`] prueft an dieser Stelle seit jeher beide
/// Haelften; das Transkript nahm bis dahin entgegen, was der Port lieferte.
#[test]
fn a_transcript_the_root_cannot_be_attributed_never_completes_step_eleven() {
    let mut setup = BootstrapHarness::new();
    let anchor_bytes = setup.prepare_final_anchor().unwrap();
    let provider = support::FixtureKeyProvider::impersonating_root();
    let error = setup
        .adopt_final_anchor_signed_by(&anchor_bytes, &provider)
        .expect_err("diese Bytes stammen nicht von der Wurzel");
    expect_admin_code(error, "EA-CEREMONY-ROOT-SIGNATURE-MISMATCH");
    assert_eq!(
        provider.signatures_produced(),
        1,
        "der Port wurde bemueht — der Befund faellt DANACH"
    );
    assert_eq!(setup.step(), BootstrapStep::RootSignBootstrapTargets);
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
        let coordinator = BootstrapCoordinator::begin(
            &mut store,
            &mut SequentialRandom::default(),
            Some(support::ceremony_machine()),
        )
        .unwrap();
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
    let coordinator = BootstrapCoordinator::begin(
        &mut store,
        &mut SequentialRandom::default(),
        Some(support::ceremony_machine()),
    )
    .unwrap();
    assert_eq!(
        fs::read(&path).expect("die Zustandsdatei muss lesbar sein"),
        coordinator.state().persisted_image()
    );
}

/// DER Zeuge der Zusage aus der Moduldokumentation: „Ein Neustart nimmt
/// denselben Schritt wieder auf" — auch einen SPAETEREN als den ersten.
///
/// Der erste Block treibt die Zeremonie bis Schritt 3, danach werden
/// Koordinator und Ablage fallen gelassen. Was bleibt, ist die Datei. Eine
/// Ablage, die Schritte 2 bis 12 zwar SCHREIBT, aber nur Schritt 1 zurueck
/// liest, machte aus jeder Zeremonie ab Schritt 2 eine Sackgasse: `resume`,
/// `resume_or_begin`, `begin` und `restart_with_new_ids` faenden dann alle
/// denselben unlesbaren Zustand vor.
#[test]
fn a_file_backed_ceremony_resumes_at_a_later_step_after_the_process_ended() {
    let directory = support::temp_dir("resume-late");
    let path = state_path(&directory);

    let (organization, chain) = {
        let mut store = FileBootstrapStore::new(path.clone());
        let mut coordinator = BootstrapCoordinator::begin(
            &mut store,
            &mut SequentialRandom::default(),
            Some(support::ceremony_machine()),
        )
        .unwrap();
        coordinator
            .generate_offline_root(fixture_root_material())
            .unwrap();
        coordinator
            .create_admin_pairs(&bootstrap_admin_pairs())
            .unwrap();
        (coordinator.organization_id(), coordinator.chain_id())
    };

    let mut store = FileBootstrapStore::new(path);
    let resumed = BootstrapCoordinator::resume(&mut store)
        .unwrap()
        .expect("die persistierte Zeremonie laesst sich fortsetzen");
    assert_eq!(resumed.step(), BootstrapStep::CreateAdminPairs);
    assert_eq!(
        resumed.organization_id().as_bytes(),
        organization.as_bytes()
    );
    assert_eq!(resumed.chain_id().as_bytes(), chain.as_bytes());
    assert_eq!(
        resumed
            .pre_anchor()
            .expect("Schritt 3 hat die Vorstufe gebaut")
            .exact_bytes(),
        resumed
            .state()
            .exact_pre_anchor_bytes()
            .expect("die Vorstufe steht im Abbild")
    );
}

/// Ein VERAENDERTES Abbild wird abgewiesen statt halb gelesen.
///
/// Die Pruefung ist keine Feldliste, sondern ein Zug: was gelesen wurde, wird
/// mit demselben [`ea_admin::BootstrapStateV1::persisted_image`] neu kodiert,
/// das es hervorgebracht hat, und muss bytegleich sein. Damit kann die
/// Pruefung nicht hinter das Abbild zurueckfallen.
#[test]
fn a_state_image_that_does_not_re_encode_is_refused() {
    let mut memory = MemoryBootstrapStore::default();
    {
        let mut coordinator = BootstrapCoordinator::begin(
            &mut memory,
            &mut SequentialRandom::default(),
            Some(support::ceremony_machine()),
        )
        .unwrap();
        coordinator
            .generate_offline_root(fixture_root_material())
            .unwrap();
    }

    // Zwei Veraenderungen, und sie fallen an verschiedenen Stellen: die erste
    // an einem Feld, das der Leser deutet, die zweite an einem, das er
    // ausdruecklich NICHT in den Zustand zurueckträgt — die
    // Anwendungskennung eines Schluesselgriffs. Nur der Byteabgleich sieht
    // sie.
    let tail_flipped = {
        let mut image = memory.image().to_vec();
        let last = image.len() - 1;
        image[last] ^= 0xff;
        image
    };
    let handle_renamed = {
        let mut image = memory.image().to_vec();
        let needle = b"de.einsatzarchiv.writer";
        let at = image
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("das Abbild nennt die Anwendungskennung des Griffs");
        image[at] = b'x';
        image
    };

    for (index, image) in [tail_flipped, handle_renamed].into_iter().enumerate() {
        let directory = support::temp_dir(&format!("tampered-{index}"));
        let path = state_path(&directory);
        fs::write(&path, &image).expect("das Abbild muss schreibbar sein");

        let mut store = FileBootstrapStore::new(path);
        expect_admin_error(
            BootstrapCoordinator::resume(&mut store),
            "EA-CEREMONY-BOOTSTRAP-STATE-SHAPE",
        );
    }
}

/// Die Ablage selbst faellt nicht auf einen frueheren Schritt zurueck.
///
/// „Nur vorwaerts" im Speicher des Koordinators ist eine Aussage ueber EINEN
/// Prozess. Der Zustand lebt aber in der Datei, und dorthin schreiben auch
/// zwei Koordinatoren nacheinander. Ein aelterer Schnappschuss, der ueber
/// einen neueren geschrieben wuerde, naehme der Zeremonie ihre Versiegelung —
/// und `:1349` liesse danach nur noch neue Kennungen zu.
#[test]
fn the_state_file_never_walks_the_persisted_step_backward() {
    let mut memory = MemoryBootstrapStore::default();
    let (earlier, later) = {
        let mut coordinator = BootstrapCoordinator::begin(
            &mut memory,
            &mut SequentialRandom::default(),
            Some(support::ceremony_machine()),
        )
        .unwrap();
        coordinator
            .generate_offline_root(fixture_root_material())
            .unwrap();
        let earlier = coordinator.state().clone();
        coordinator
            .create_admin_pairs(&bootstrap_admin_pairs())
            .unwrap();
        (earlier, coordinator.state().clone())
    };

    let directory = support::temp_dir("monotone");
    let path = state_path(&directory);
    let mut store = FileBootstrapStore::new(path.clone());
    store
        .store(&later)
        .expect("der spaetere Stand wird geschrieben");
    expect_admin_error(
        store.store(&earlier),
        "EA-CEREMONY-BOOTSTRAP-STEP-REGRESSION",
    );
    assert_eq!(
        fs::read(&path).expect("die Zustandsdatei muss lesbar sein"),
        later.persisted_image(),
        "die Datei traegt weiter den spaeteren Stand"
    );
}

/// Eine abgeschnittene Datei ist kein halber Zustand, sondern keiner.
#[test]
fn a_truncated_state_file_is_refused() {
    let directory = support::temp_dir("truncated");
    let path = state_path(&directory);
    let mut store = FileBootstrapStore::new(path.clone());
    let image = BootstrapCoordinator::begin(
        &mut store,
        &mut SequentialRandom::default(),
        Some(support::ceremony_machine()),
    )
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
        BootstrapCoordinator::begin(
            &mut store,
            &mut SequentialRandom::default(),
            Some(support::ceremony_machine()),
        ),
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

// ---------------------------------------------------------------------------
// Die Torwaechter — je einer je Schritt
// ---------------------------------------------------------------------------

/// Kein Schritt laeuft, bevor sein Vorgaenger abgeschlossen ist.
///
/// Tabellengetrieben und nicht elf Mal von Hand: `require_completed` steht in
/// zehn Schritten wortgleich, und ein Zeuge je Schritt haette zehn Kulissen
/// gebraucht. Gemessen wird gegen eine GERADE begonnene Zeremonie — dort fehlt
/// jedem Schritt ab dem dritten sein Vorgaenger.
#[test]
fn every_step_refuses_to_run_before_its_predecessor() {
    for step in BootstrapStep::ALL {
        if step <= BootstrapStep::GenerateOfflineRoot {
            // Schritt 1 ist mit dem Beginn abgeschlossen, Schritt 2 ist damit
            // an der Reihe. Ihr Torwaechter ist der Abbruch, siehe
            // `an_aborted_ceremony_refuses_every_step`.
            continue;
        }
        let mut store = MemoryBootstrapStore::default();
        let mut random = SequentialRandom::default();
        let mut coordinator =
            BootstrapCoordinator::begin(&mut store, &mut random, Some(support::ceremony_machine()))
                .unwrap();
        let error = support::invoke_step(&mut coordinator, step)
            .expect_err("ein Schritt ohne Vorgaenger laeuft nicht");
        assert_eq!(
            error.code(),
            "EA-CEREMONY-BOOTSTRAP-STEP-OUT-OF-ORDER",
            "Schritt {} ({}) laeuft ohne seinen Vorgaenger",
            step.number(),
            step.name()
        );
        assert_eq!(coordinator.step(), BootstrapStep::GenerateIds);
    }
}

/// Eine abgebrochene Zeremonie fuehrt keinen Schritt mehr aus.
#[test]
fn an_aborted_ceremony_refuses_every_step() {
    let mut setup = BootstrapHarness::new();
    setup.complete_through_pre_anchor_seal().unwrap();
    let Err(error) = setup.rewrite_admin_pairs(&changed_admin_pairs()) else {
        panic!("ein festgeschriebenes Feld aendert sich nicht mehr");
    };
    expect_admin_code(error, "EA-ANCHOR-PRE-FIELD-CHANGED");

    for step in BootstrapStep::ALL {
        if step == BootstrapStep::GenerateIds {
            continue;
        }
        let error = setup
            .invoke(step)
            .expect_err("eine abgebrochene Zeremonie fuehrt nichts mehr aus");
        assert_eq!(
            error.code(),
            "EA-ANCHOR-PRE-FIELD-CHANGED",
            "Schritt {} laeuft nach dem Abbruch",
            step.number()
        );
    }
}

/// Eine zweite Zeremonie neben einer persistierten waeren zwei Wahrheiten.
#[test]
fn a_second_ceremony_beside_a_persisted_one_is_refused() {
    let mut store = MemoryBootstrapStore::default();
    BootstrapCoordinator::begin(
        &mut store,
        &mut SequentialRandom::default(),
        Some(support::ceremony_machine()),
    )
    .unwrap();
    expect_admin_error(
        BootstrapCoordinator::begin(
            &mut store,
            &mut SequentialRandom::default(),
            Some(support::ceremony_machine()),
        ),
        "EA-CEREMONY-BOOTSTRAP-STEP-REGRESSION",
    );
}

/// Ein Neuanfang, der die ALTEN Kennungen noch einmal zieht, ist keiner.
#[test]
fn a_restart_that_draws_the_same_identifiers_is_refused() {
    let mut setup = BootstrapHarness::new();
    setup.complete_through_pre_anchor_seal().unwrap();
    let Err(error) = setup.rewrite_admin_pairs(&changed_admin_pairs()) else {
        panic!("ein festgeschriebenes Feld aendert sich nicht mehr");
    };
    expect_admin_code(error, "EA-ANCHOR-PRE-FIELD-CHANGED");
    let error = setup
        .restart_with_repeating_random()
        .expect_err("dieselben Kennungen sind keine neuen");
    expect_admin_code(error, "EA-LOCAL-CRYPTO-RNG");
}

// ---------------------------------------------------------------------------
// Die Mindestzahlen aus `:1338`, `:1341`, `:1342` und `:1343`
// ---------------------------------------------------------------------------

#[test]
fn a_single_admin_pair_is_no_quorum() {
    let mut store = MemoryBootstrapStore::default();
    let mut random = SequentialRandom::default();
    let mut coordinator =
        BootstrapCoordinator::begin(&mut store, &mut random, Some(support::ceremony_machine()))
            .unwrap();
    coordinator
        .generate_offline_root(fixture_root_material())
        .unwrap();
    let pairs = bootstrap_admin_pairs();
    expect_admin_error(
        coordinator.create_admin_pairs(&pairs[..1]),
        "EA-CEREMONY-BOOTSTRAP-QUORUM-MISSING",
    );
    assert_eq!(coordinator.step(), BootstrapStep::GenerateOfflineRoot);
}

/// Zwei Eintraege desselben Schluessels sind EIN Approver.
#[test]
fn two_entries_of_the_same_approver_are_one_approver() {
    let mut setup = BootstrapHarness::new();
    setup.complete_through_pre_anchor_seal().unwrap();
    setup.generate_recovery_and_hga_keys().unwrap();
    let approvers = support::approver_records();
    let error = setup
        .enroll_key_approvers(&[approvers[0].clone(), approvers[0].clone()])
        .expect_err("zwei Namen sind kein zweiter Schluessel");
    expect_admin_code(error, "EA-CEREMONY-BOOTSTRAP-QUORUM-MISSING");
}

/// Eine Sicherung auf EINEM Medium ist kein Bestand, und eine fehlende Klasse
/// ist keine vollstaendige Sicherung (`:1342`).
#[test]
fn a_backup_needs_all_four_classes_on_two_separate_media() {
    let one_medium = {
        let mut backups = support::ceremony_backups();
        backups[0].media.truncate(1);
        backups
    };
    let missing_class = {
        let mut backups = support::ceremony_backups();
        backups.pop();
        backups
    };
    for backups in [one_medium, missing_class] {
        let mut setup = BootstrapHarness::new();
        setup.complete_through_key_approvers().unwrap();
        let error = setup
            .verify_key_backups(&backups)
            .expect_err("`:1342` verlangt vier Klassen auf je zwei getrennten Medien");
        expect_admin_code(error, "EA-CEREMONY-BOOTSTRAP-QUORUM-MISSING");
    }
}

/// Schritt 8 ohne ein einziges Komponentenpaar hat nicht stattgefunden.
#[test]
fn no_component_binding_is_no_provisioning() {
    let mut setup = BootstrapHarness::new();
    setup.complete_through_key_backups().unwrap();
    let error = setup
        .provision_component_keys(&[])
        .expect_err("Schritt 8 provisioniert mindestens ein Konto");
    expect_admin_code(error, "EA-CEREMONY-BOOTSTRAP-QUORUM-MISSING");
}

// ---------------------------------------------------------------------------
// Der Rueckfall — in der Ablage und im Speicher
// ---------------------------------------------------------------------------

/// Ein Wurzelwechsel VOR der Versiegelung faellt nicht auf Schritt 2 zurueck.
///
/// Der Zeuge fuer die Regressionspruefung in `advance`: die Zeremonie steht
/// bei Schritt 3, und Schritt 2 noch einmal auszufuehren hiesse, den
/// persistierten Schritt rueckwaerts zu schreiben.
#[test]
fn a_root_change_before_the_seal_never_walks_the_step_backward() {
    let mut store = MemoryBootstrapStore::default();
    let mut random = SequentialRandom::default();
    let mut coordinator =
        BootstrapCoordinator::begin(&mut store, &mut random, Some(support::ceremony_machine()))
            .unwrap();
    coordinator
        .generate_offline_root(fixture_root_material())
        .unwrap();
    coordinator
        .create_admin_pairs(&bootstrap_admin_pairs())
        .unwrap();
    let error = coordinator
        .generate_offline_root(support::foreign_root_material())
        .expect_err("Schritt 2 laeuft nicht hinter Schritt 3");
    expect_admin_code(error, "EA-CEREMONY-BOOTSTRAP-STEP-REGRESSION");
    assert_eq!(coordinator.step(), BootstrapStep::CreateAdminPairs);
}

/// Eine Ablage, die zwischen zwei Lesevorgaengen verstummt, beendet den
/// Prozess nicht.
///
/// `resume_or_begin` ist der EINZIGE Weg von `apps/cli/src/commands/
/// organization.rs` in die Zeremonie. Ein `expect` darin machte aus einem
/// nebenlaeufigen Lauf oder einer von Hand geloeschten Zustandsdatei einen
/// Prozessabbruch — ein fail-closed gebautes Werkzeug haette dann keinen Code
/// mehr zu melden.
#[test]
fn a_store_that_stops_answering_between_two_loads_never_panics() {
    let mut memory = MemoryBootstrapStore::default();
    {
        let mut coordinator = BootstrapCoordinator::begin(
            &mut memory,
            &mut SequentialRandom::default(),
            Some(support::ceremony_machine()),
        )
        .unwrap();
        coordinator
            .generate_offline_root(fixture_root_material())
            .unwrap();
    }

    let mut store = support::StoreThatStopsAnswering::over(&memory);
    let coordinator = BootstrapCoordinator::resume_or_begin(
        &mut store,
        &mut SequentialRandom::default(),
        Some(support::ceremony_machine()),
    )
    .expect("eine Ablage, die einmal antwortet, reicht");
    assert_eq!(coordinator.step(), BootstrapStep::GenerateOfflineRoot);
}

// ---------------------------------------------------------------------------
// Der Abbruch aus `:1349` — fuer JEDES festgeschriebene Feld
// ---------------------------------------------------------------------------

/// Ein Wurzelwechsel NACH der Versiegelung bricht ab wie ein Paarwechsel.
///
/// `:1349` unterscheidet die Felder nicht: „Jede Aenderung eines bereits in
/// Schritt 4 festgeschriebenen Feldes bricht das Setup ab". Ein Pfad, der nur
/// abweist und nicht abbricht, liesse die Zeremonie in einem Zustand stehen,
/// aus dem `restart_with_new_ids` nicht mehr herausfuehrt.
#[test]
fn a_post_seal_root_change_aborts_the_ceremony_like_a_pair_change() {
    let mut setup = BootstrapHarness::new();
    setup.complete_through_pre_anchor_seal().unwrap();
    let (aborted_organization, aborted_chain) = setup.current_ids();

    let error = setup
        .rewrite_root()
        .expect_err("ein festgeschriebenes Feld aendert sich nicht mehr");
    expect_admin_code(error, "EA-ANCHOR-PRE-FIELD-CHANGED");

    setup
        .restart_with_new_ids()
        .expect("`:1349` nennt den Neuanfang als das Heilmittel");
    let (fresh_organization, fresh_chain) = setup.current_ids();
    assert_ne!(
        fresh_organization.as_bytes(),
        aborted_organization.as_bytes()
    );
    assert_ne!(fresh_chain.as_bytes(), aborted_chain.as_bytes());
}

// ---------------------------------------------------------------------------
// Schritt 12 gehoert DIESER Zeremonie
// ---------------------------------------------------------------------------

/// Ein vollstaendig in sich stimmiger Recovery-Test einer FREMDEN Organisation
/// erreicht den Produktivzustand nicht.
///
/// Der teuerste Zeuge dieses Schrittes, und der Gegenpol zu
/// `a_self_consistent_foreign_archive_fails_at_this_ceremonys_anchor`: die
/// Beobachtung ist in jedem ihrer fuenf Ausgaenge fehlerfrei — Medien
/// vollzaehlig, Abdruecke gleich, Testeintrag lesbar, Sample vollstaendig —,
/// und der genannte Anker ist selbstkonsistent. Er ist nur nicht der Anker,
/// den Schritt 11 dieser Zeremonie angenommen hat. Ohne diese Bindung
/// beglaubigte ein Recovery-Test irgendeines Bestandes die Freigabe
/// irgendeiner anderen Organisation.
#[test]
fn a_recovery_test_against_a_foreign_anchor_never_reaches_ready() {
    let mut setup = BootstrapHarness::new();
    setup.complete_through_genesis().unwrap();
    let foreign =
        decode_trust_anchor(trust_support::RegistryLineBuilder::new().exact_anchor_bytes())
            .expect("der fremde Anker ist in sich stimmig");

    let mut observation = setup.passing_observation(support::fresh_machine());
    observation.expected_trust_anchor_hash = foreign.trust_anchor_hash();
    observation.observed_trust_anchor_hash = foreign.trust_anchor_hash();

    let error = setup
        .record_recovery_observation(support::ceremony_machine(), &observation)
        .expect_err("der Test hat einen ANDEREN Anker geprueft");
    expect_admin_code(error, "EA-CEREMONY-RECOVERY-TEST-FAILED");
    assert_eq!(
        setup.production_state(),
        ProductionState::BlockedRecoveryTest
    );
}

/// Wer die Zeremonienmaschine als den frischen Rechner ausgibt, kommt damit
/// nicht durch.
///
/// `verify_fresh_machine_recovery_test` bekommt den Zeremonienrechner vom
/// AUFRUFER — und das ist die Partei, die den Produktivzustand will. Ein
/// falsch benannter Zeremonienrechner laesst dort jede Maschine als „frisch"
/// erscheinen. Der Koordinator vergleicht deshalb gegen den Rechner, den
/// Schritt 1 festgehalten hat.
#[test]
fn a_caller_that_misnames_the_ceremony_machine_never_reaches_ready() {
    let mut setup = BootstrapHarness::new();
    setup.complete_through_genesis().unwrap();
    let observation = setup.passing_observation(support::ceremony_machine());
    let error = setup
        .record_recovery_observation(support::fresh_machine(), &observation)
        .expect_err("der Test lief auf der Zeremonienmaschine");
    expect_admin_code(error, "EA-CEREMONY-RECOVERY-TEST-SAME-MACHINE");
    assert_eq!(
        setup.production_state(),
        ProductionState::BlockedRecoveryTest
    );
}

/// Ein Test, der nichts erwartet hat, hat nichts geprueft.
///
/// Ohne diesen Riegel bestuende der billigste aller Laeufe: null erwartete
/// Medien, null erwartete Sample-Eintraege — und alle Vergleiche gaengen
/// leer auf.
#[test]
fn an_observation_that_expected_nothing_is_not_a_passed_recovery_test() {
    let mut setup = BootstrapHarness::new();
    setup.complete_through_genesis().unwrap();

    // Beide Haelften einzeln: ein Lauf ohne erwartete Medien UND ein Lauf ohne
    // erwartetes Sample. Zusammen gemessen verdeckte die Medienhaelfte die
    // andere — die Medienzahl prueft der Koordinator ohnehin gegen Schritt 4,
    // das leere Sample dagegen kann nur das Urteil selbst sehen.
    let no_media = {
        let mut observation = setup.passing_observation(support::fresh_machine());
        observation.media_expected = 0;
        observation.media_present = 0;
        observation
    };
    let no_sample = {
        let mut observation = setup.passing_observation(support::fresh_machine());
        observation.sample_entries_expected = 0;
        observation.sample_entries_decrypted = 0;
        observation
    };
    for vacuous in [no_media, no_sample] {
        let error = setup
            .record_recovery_observation(support::ceremony_machine(), &vacuous)
            .expect_err("ein Lauf ohne Erwartung ist kein bestandener Lauf");
        expect_admin_code(error, "EA-CEREMONY-RECOVERY-TEST-FAILED");
    }
}

/// Ein Test, der weniger Medien erwartet hat, als Schritt 4 versiegelt hat,
/// hat den Bestand nicht geprueft.
#[test]
fn a_recovery_test_that_expected_fewer_media_than_the_ceremony_sealed_is_incomplete() {
    let mut setup = BootstrapHarness::new();
    setup.complete_through_genesis().unwrap();
    let thin = {
        let mut observation = setup.passing_observation(support::fresh_machine());
        observation.media_expected = 1;
        observation.media_present = 1;
        observation
    };
    let error = setup
        .record_recovery_observation(support::ceremony_machine(), &thin)
        .expect_err("Schritt 4 hat zwei Medien versiegelt");
    expect_admin_code(error, "EA-CEREMONY-RECOVERY-TEST-FAILED");
}

/// Eine Ablage, die nicht schreibt, gibt auch keine Freigabe.
#[test]
fn a_failing_store_never_reports_a_production_state_it_did_not_persist() {
    let mut setup = BootstrapHarness::new();
    setup.complete_through_genesis().unwrap();
    let (error, reported) = setup.run_recovery_against_a_failing_store();
    expect_admin_code(error, "EA-CEREMONY-BOOTSTRAP-STORE-UNAVAILABLE");
    assert_eq!(
        reported,
        ProductionState::BlockedRecoveryTest,
        "ein Koordinator meldet keinen Zustand, den seine Ablage nicht hat"
    );
}

// ---------------------------------------------------------------------------
// Schritt 11: die finalen Ankerbytes gehen auf DIESELBEN Medien
// ---------------------------------------------------------------------------

/// `:1346` verlangt die finalen Ankerbytes „auf beiden Medien".
#[test]
fn one_medium_alone_cannot_carry_the_final_anchor() {
    let mut setup = BootstrapHarness::new();
    let anchor_bytes = setup.prepare_final_anchor().unwrap();
    let error = setup
        .adopt_final_anchor_on(
            &anchor_bytes,
            &[FIRST_MEDIUM],
            support::fingerprint_of_bytes(&anchor_bytes),
        )
        .expect_err("ein Datentraeger ist kein Bestand");
    expect_admin_code(error, "EA-CEREMONY-MEDIA-QUORUM-MISSING");
}

/// Es muessen DIESELBEN Medien sein, die Schritt 4 versiegelt hat.
#[test]
fn a_medium_that_did_not_carry_the_pre_anchor_cannot_carry_the_final_anchor() {
    let mut setup = BootstrapHarness::new();
    let anchor_bytes = setup.prepare_final_anchor().unwrap();
    let error = setup
        .adopt_final_anchor_on(
            &anchor_bytes,
            &[FIRST_MEDIUM, AnchorMediumId::new([0x0e; 16])],
            support::fingerprint_of_bytes(&anchor_bytes),
        )
        .expect_err("`:1346` meint dieselben beiden Medien");
    expect_admin_code(error, "EA-CEREMONY-MEDIA-QUORUM-MISSING");
}

/// Festgeschrieben ist nur, was bytegleich wieder herauskommt.
#[test]
fn a_medium_that_reads_back_other_bytes_never_carries_the_final_anchor() {
    let mut setup = BootstrapHarness::new();
    let anchor_bytes = setup.prepare_final_anchor().unwrap();
    setup.corrupt_second_medium();
    let error = setup
        .adopt_final_anchor(&anchor_bytes)
        .expect_err("ein Medium liest andere Bytes zurueck");
    expect_admin_code(error, "EA-CEREMONY-MEDIA-READBACK-MISMATCH");
}

/// Der zweite Kanal muss ueber die FINALEN Bytes bestaetigt haben.
///
/// Der Fingerprint der Vorstufe ist der Wert, den Schritt 4 und Schritt 9
/// bestaetigen liessen — er deckt die finalen Ankerbytes nicht. `:1346`
/// verlangt ausdruecklich, dass „ihr voller Fingerprint erneut ueber den
/// zweiten Kanal bestaetigt" wird.
#[test]
fn the_pre_anchor_fingerprint_does_not_confirm_the_final_anchor() {
    let mut setup = BootstrapHarness::new();
    let anchor_bytes = setup.prepare_final_anchor().unwrap();
    let pre_fingerprint = support::fingerprint_of_bytes(&setup.sealed_pre_anchor_bytes());
    let error = setup
        .adopt_final_anchor_on(
            &anchor_bytes,
            &[FIRST_MEDIUM, SECOND_MEDIUM],
            pre_fingerprint,
        )
        .expect_err("der Fingerprint der Vorstufe deckt den finalen Anker nicht");
    expect_admin_code(error, "EA-CEREMONY-SECOND-CHANNEL-MISMATCH");
}

/// Der finale Anker wird ueber SEINE Domaene bestaetigt, nicht ueber die der
/// Vorstufe.
///
/// `:1769-1777` rechnet zwei Fingerprints ueber zwei Domaenen:
/// `bootstrapAnchorHash` ueber `EINSATZARCHIV-TRUST-ANCHOR-PRE-v1` und
/// `trustAnchorHash` ueber `EINSATZARCHIV-TRUST-ANCHOR-v1`. Schritt 11
/// bestaetigt den ZWEITEN — das ist der Wert, den `decode_trust_anchor` beim
/// Einlesen bildet und den ein Mensch am Telefon vorliest.
///
/// Ohne diesen Zeugen verlangte die Zeremonie einen Wert, den niemand
/// ausrechnet: `bootstrapAnchorHash` ueber die FINALEN Bytes gehoert zu keiner
/// Anzeige und zu keinem Dokument.
#[test]
fn the_final_anchor_is_confirmed_over_its_own_domain_and_not_the_pre_anchors() {
    let mut setup = BootstrapHarness::new();
    let anchor_bytes = setup.prepare_final_anchor().unwrap();

    let pre_domain_over_final_bytes = support::fingerprint_of_bytes(&anchor_bytes);
    let final_domain = support::final_fingerprint_of_bytes(&anchor_bytes);
    assert!(
        pre_domain_over_final_bytes.as_bytes() != final_domain.as_bytes(),
        "die zwei Domaenen trennen die zwei Ankerbilder ueberhaupt erst"
    );

    let error = setup
        .adopt_final_anchor_on(
            &anchor_bytes,
            &[FIRST_MEDIUM, SECOND_MEDIUM],
            pre_domain_over_final_bytes,
        )
        .expect_err("die Vorstufendomaene bestaetigt den finalen Anker nicht");
    expect_admin_code(error, "EA-CEREMONY-SECOND-CHANNEL-MISMATCH");

    let mut accepted = BootstrapHarness::new();
    let bytes = accepted.prepare_final_anchor().unwrap();
    accepted
        .adopt_final_anchor_on(
            &bytes,
            &[FIRST_MEDIUM, SECOND_MEDIUM],
            support::final_fingerprint_of_bytes(&bytes),
        )
        .expect("der Fingerprint aus `:1774-1777` bestaetigt ihn sehr wohl");
}

/// Der Anker muss GENAU den Genesis nennen, den diese Zeremonie gebunden hat.
#[test]
fn an_anchor_that_names_another_genesis_is_refused() {
    let mut setup = BootstrapHarness::new();
    let error = setup
        .adopt_anchor_of_another_genesis()
        .expect_err("ein anderer Genesis ist ein anderer Bestand");
    expect_admin_code(error, "EA-CEREMONY-GENESIS-CONTEXT-MISMATCH");
}

// ---------------------------------------------------------------------------
// Die Schritte 3, 5, 6, 7 und 10 binden an DIESE Zeremonie
// ---------------------------------------------------------------------------

/// `:1340` verlangt „getrennte" Schluessel — und getrennt heisst auch: nicht
/// die Wurzel.
#[test]
fn the_recovery_and_hga_keys_are_separate_keys_and_neither_is_the_root() {
    let root_thumbprint = fixture_root_material().key_thumbprint;
    let cases: [(OuterKeyRecordV1, OuterKeyRecordV1); 3] = [
        (
            support::recovery_kem_record(),
            support::recovery_kem_record(),
        ),
        (
            support::keyed_record(0x31, root_thumbprint),
            support::hga_record(),
        ),
        (
            support::recovery_kem_record(),
            support::keyed_record(0x32, root_thumbprint),
        ),
    ];
    for (recovery, hga) in cases {
        let mut setup = BootstrapHarness::new();
        setup.complete_through_pre_anchor_seal().unwrap();
        let error = setup
            .generate_recovery_and_hga_keys_from(recovery, hga)
            .expect_err("`:1340` verlangt getrennte Schluessel");
        expect_admin_code(error, "EA-CEREMONY-BOOTSTRAP-QUORUM-MISSING");
    }
}

/// Ein Approver ist nicht die Wurzel und nicht der Recovery-Schluessel.
#[test]
fn an_approver_is_not_one_of_the_ceremonys_own_keys() {
    let mut setup = BootstrapHarness::new();
    setup.complete_through_pre_anchor_seal().unwrap();
    setup.generate_recovery_and_hga_keys().unwrap();
    let approvers = support::approver_records();
    let error = setup
        .enroll_key_approvers(&[
            approvers[0].clone(),
            support::keyed_record(0x43, support::recovery_kem_record().key_thumbprint),
        ])
        .expect_err("ein Approver ist ein VIERTER Schluessel");
    expect_admin_code(error, "EA-CEREMONY-BOOTSTRAP-QUORUM-MISSING");
}

/// Eine Sicherung eines unbeteiligten Schluessels ist keine Sicherung DIESER
/// Zeremonie.
#[test]
fn a_backup_of_an_unrelated_key_is_not_a_backup_of_this_ceremony() {
    let mut setup = BootstrapHarness::new();
    setup.complete_through_key_approvers().unwrap();
    let mut backups = support::ceremony_backups();
    backups[0].key_thumbprint = support::unrelated_thumbprint();
    let error = setup
        .verify_key_backups(&backups)
        .expect_err("`:1342` meint die Schluessel DIESER Zeremonie");
    expect_admin_code(error, "EA-CEREMONY-BOOTSTRAP-QUORUM-MISSING");
}

/// Zwei Paare, die denselben Hash nennen, sind keine zwei Paare.
///
/// `:1780` verlangt eine Eins-zu-eins-Paarung von Admin-Zertifikat und
/// `operatorBinding`. Zwei Paare, die sich ein Zertifikat oder eine Bindung
/// teilen, koennen diese Paarung nicht tragen — und der Befund faellt hier, wo
/// die Zeremonie noch laeuft, statt beim ersten `verify_trust`, wenn die
/// Vorstufe laengst auf schreibgeschuetzten Medien steht.
#[test]
fn admin_pairs_that_repeat_a_hash_are_not_two_pairs() {
    for pairs in support::admin_pairs_sharing_a_hash() {
        let mut store = MemoryBootstrapStore::default();
        let mut random = SequentialRandom::default();
        let mut coordinator =
            BootstrapCoordinator::begin(&mut store, &mut random, Some(support::ceremony_machine()))
                .unwrap();
        coordinator
            .generate_offline_root(fixture_root_material())
            .unwrap();
        let Err(error) = coordinator.create_admin_pairs(&pairs) else {
            panic!("eine Paarung, die keine ist, wird nicht versiegelt");
        };
        expect_admin_code(error, "EA-CEREMONY-BOOTSTRAP-QUORUM-MISSING");
    }
}

/// Ein Bootstrap-Ziel einer ANDEREN Organisation gehoert nicht in diese
/// Zeremonie.
///
/// Schritt 10 reicht an [`ea_admin::RootCeremonyService`] durch und haelt den
/// entstandenen Objekthash fest. Ohne eine Bindung an die Kennungen dieser
/// Zeremonie hielte er auch fest, was eine FREMDE Organisation autorisiert
/// hat — und der `bootstrapTargets`-Teil des Transkripts spraeche danach ueber
/// zwei Organisationen.
#[test]
fn a_bootstrap_target_of_another_organization_is_refused() {
    let mut setup = BootstrapHarness::with_unrelated_identifiers();
    let error = setup
        .complete_through_root_signed_targets()
        .expect_err("die Autorisierung nennt eine andere Organisation");
    expect_admin_code(error, "EA-CEREMONY-BOOTSTRAP-CONTEXT-MISMATCH");
}
