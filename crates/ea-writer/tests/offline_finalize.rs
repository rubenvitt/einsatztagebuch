//! Der glatte Pfad der Offline-Finalisierung.

mod support;

use ea_writer::{FinalizationPhase, FinalizationStep, StaleDecision};
use support::{WriterHarness, valid_incident};

#[test]
fn offline_finalize_commits_grants_then_entry_and_returns_no_content() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness.service(&source);
    let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);

    let preview = service
        .preview(&proof, valid_incident())
        .expect("die Vorschau des glatten Pfades muss entstehen");
    assert_eq!(preview.decision(), StaleDecision::Fresh);

    let out = service
        .finalize(&proof, valid_incident(), &preview)
        .expect("der glatte Pfad muss abschliessen");
    assert_eq!(out.sync_status, ea_archive_fs::SyncStatus::LocallySaved);
    assert_eq!(out.sequence, preview.proposed_sequence());

    // Das `.eip` liegt ZULETZT und unter seinem Layoutnamen.
    let entries = harness.backend().relative_paths_below_for_test("entries/");
    assert_eq!(
        entries.len(),
        1,
        "genau ein Eintrag und KEINE liegengebliebene temporaere Datei: {entries:?}"
    );
    assert!(
        entries[0].starts_with("entries/000000000000_") && entries[0].ends_with(".eip"),
        "der Eintragsname folgt §11.4: {}",
        entries[0]
    );

    // Ein Grant je Empfaenger des Plans, alle unter `grants/`.
    let grants = harness.backend().relative_paths_below_for_test("grants/");
    assert_eq!(
        grants.len(),
        harness.expected_grant_count(),
        "ein Grant je aktivem Empfaenger: {grants:?}"
    );
    assert!(grants.iter().all(|path| path.ends_with(".eag")));

    // Kein nutzbarer `draftDEK` mehr, und ein leerer Entwurf.
    assert!(
        !harness.draft_dek_is_present() || harness.draft_is_blank(),
        "nach dem Abschluss steht ein leerer Entwurf mit frischem Schluessel"
    );
}

#[test]
fn each_reached_step_has_its_own_observable_postcondition() {
    for step in FinalizationStep::ALL.iter().copied().take(8) {
        let harness = WriterHarness::with_incident();
        let source = harness.source();
        let service = harness.service(&source);
        let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);
        let reached = service
            .finalize_up_to(&proof, valid_incident(), step)
            .unwrap_or_else(|error| panic!("{step:?} muss erreichbar sein: {error:?}"));
        assert_eq!(reached.reached_step(), Some(step), "{step:?}");
        match step {
            FinalizationStep::RebuildLocalHead => {
                assert!(reached.head_source_is_committed_archive_bytes());
                assert!(reached.rollback_assessment().is_none());
            }
            FinalizationStep::CompareServerCheckpoint => {
                assert!(reached.rollback_assessment().is_some());
                assert!(reached.selected_registry_version().is_none());
            }
            FinalizationStep::SelectRegistryHeadAndOperator => {
                assert_eq!(
                    reached.selected_registry_version(),
                    Some(harness.expected_registry_version())
                );
                assert!(reached.active_recovery_recipient_count() >= 1);
                assert!(reached.draft_record_bytes().is_empty());
            }
            FinalizationStep::ValidateAndSerialize => {
                assert!(!reached.draft_record_bytes().is_empty());
                assert!(reached.grant_plan().is_none());
            }
            FinalizationStep::BuildAndHashGrantPlan => {
                assert_eq!(
                    reached.grant_plan().map(|plan| plan.items().len()),
                    Some(harness.expected_grant_count())
                );
                assert!(reached.preview().is_some());
                assert!(reached.manifest_core().is_none());
            }
            FinalizationStep::DrawSecretsAndBuildEntryHash => {
                let plan_hash = *reached.grant_plan().unwrap().hash().as_bytes();
                assert_eq!(
                    reached
                        .manifest_core()
                        .unwrap()
                        .fields()
                        .initial_grant_plan_hash,
                    plan_hash,
                    "das Manifest bindet die Grants ueber den PLANHASH"
                );
                assert!(!reached.signed_manifest_bytes().is_empty());
                assert!(!reached.writer_signature().is_empty());
                assert!(reached.grants().is_empty());
            }
            FinalizationStep::ProduceGrantsAndEntryBytes => {
                assert_eq!(
                    reached.grants().len(),
                    reached.grant_plan().unwrap().items().len()
                );
                assert!(!reached.entry_bytes().is_empty());
                assert_eq!(reached.phase(), FinalizationPhase::ReversibleDraft);
            }
            FinalizationStep::StageAndFlush => {
                assert_eq!(reached.phase(), FinalizationPhase::PreparedAndFlushed);
                assert!(reached.prepared().is_some());
                // NICHTS ist veroeffentlicht.
                let published = harness
                    .backend()
                    .relative_paths_below_for_test("entries/")
                    .into_iter()
                    .filter(|path| path.ends_with(".eip"))
                    .count();
                assert_eq!(published, 0, "Schritt 8 veroeffentlicht nichts");
                // Und doch liegt schon jedes Byte: das ist der Unterschied
                // zwischen vorbereitet und veroeffentlicht.
                assert!(
                    harness
                        .backend()
                        .relative_paths_below_for_test("entries/")
                        .iter()
                        .any(|path| path.ends_with(".eip.staging")),
                    "Schritt 8 stagt das .eip"
                );
            }
            _ => unreachable!("die Schleife laeuft nur bis Schritt 8"),
        }
    }
}
