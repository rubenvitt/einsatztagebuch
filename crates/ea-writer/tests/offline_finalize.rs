//! Der glatte Pfad der Offline-Finalisierung.

mod support;

use ea_writer::{FinalizationFaultPoint, FinalizationPhase, FinalizationStep, StaleDecision};
use support::{WriterHarness, valid_incident};

#[test]
fn offline_finalize_commits_grants_then_entry_and_returns_no_content() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness.service(&source);
    let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);

    let preview = service
        .preview(&proof, valid_incident(), harness.observed_now())
        .expect("die Vorschau des glatten Pfades muss entstehen");
    assert_eq!(preview.decision(), StaleDecision::Fresh);

    let out = service
        .finalize(&proof, valid_incident(), &preview, harness.observed_now())
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

    // Kein Geheimnis dieses Schluesselspeichers oeffnet den Eintrag mehr.
    //
    // Die Zusicherung `!draft_dek_is_present() || draft_is_blank()` stand hier
    // vorher und KONNTE nicht fehlschlagen: Schritt 13 legt einen leeren
    // Entwurf an, also war die rechte Haelfte immer wahr. Gemessen wird jetzt
    // die Zusage selbst.
    assert!(harness.writer_keys_cannot_decrypt(out.entry_hash));
    assert!(harness.draft_is_blank());
}

/// Die Grants liegen VOR dem `.eip` — beobachtet und nicht gefolgert.
///
/// Der Zeuge ist der Abbruchpunkt: an
/// [`FinalizationFaultPoint::AfterGrantPublishBeforeEntryRename`] MUSS JEDER
/// Grant unter seinem Zielnamen liegen und das `.eip` NOCH NICHT. Der Endzustand
/// eines glatten Laufs kann das nicht sagen — dort liegt beides.
#[test]
fn every_grant_is_published_before_the_entry_is_renamed() {
    let mut harness = WriterHarness::with_incident();
    harness
        .finalize_with_fault(FinalizationFaultPoint::AfterGrantPublishBeforeEntryRename)
        .expect("der Abbruch zwischen Grants und Eintrag muss erreichbar sein");

    assert_eq!(
        harness.published_grant_paths().len(),
        harness.expected_grant_count(),
        "JEDER geplante Grant liegt veroeffentlicht: {:?}",
        harness.published_grant_paths()
    );
    assert!(
        harness.published_entry_paths().is_empty(),
        "das .eip ist noch NICHT veroeffentlicht: {:?}",
        harness.published_entry_paths()
    );

    // Und die Ordnung ist keine Sackgasse: die eigene vorbereitete Transaktion
    // vollendet sie.
    let source = harness.source();
    let service = harness.service(&source);
    service
        .recover_pending()
        .expect("die Wiederherstellung hinter der Grenze muss tragen");
    assert_eq!(harness.published_entry_paths().len(), 1);
}

#[test]
fn each_reached_step_has_its_own_observable_postcondition() {
    for step in FinalizationStep::ALL.iter().copied() {
        let harness = WriterHarness::with_incident();
        let source = harness.source();
        let service = harness.service(&source);
        let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);
        let reached = service
            .finalize_up_to(&proof, valid_incident(), harness.observed_now(), step)
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
                assert!(
                    harness.published_entry_paths().is_empty(),
                    "Schritt 8 veroeffentlicht nichts"
                );
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
            FinalizationStep::ZeroAndDeleteDraftKey => {
                assert_eq!(reached.phase(), FinalizationPhase::DraftKeyAbsent);
                assert!(
                    !harness.draft_dek_is_present(),
                    "die Grenze ist der GELOESCHTE draftDEK"
                );
                assert!(
                    harness.published_entry_paths().is_empty(),
                    "und vor Schritt 11 ist nichts committed"
                );
            }
            FinalizationStep::PublishGrants => {
                assert_eq!(reached.phase(), FinalizationPhase::GrantsPublished);
                assert_eq!(
                    harness.published_grant_paths().len(),
                    harness.expected_grant_count()
                );
                assert!(
                    harness.published_entry_paths().is_empty(),
                    "Schritt 10 veroeffentlicht die Grants und NICHT den Eintrag"
                );
            }
            FinalizationStep::PublishEntryLast => {
                assert_eq!(reached.phase(), FinalizationPhase::EntryCommitted);
                // `sync_status` gehoert zum Ergebnis, und ein Lauf, der hier
                // anhaelt, hat keines — Schritt 13 bildet es. Die
                // Nachbedingung von Schritt 11 ist der Commit-Marker selbst.
                assert_eq!(harness.published_entry_paths().len(), 1);
                assert!(reached.outcome().is_none());
            }
            FinalizationStep::PublishToNetworkArchive => {
                assert_eq!(reached.phase(), FinalizationPhase::NetworkArchivePublished);
                // Beim LOKALEN Profil ist Schritt 12 ohne Publikation
                // abgeschlossen; die Abschlussmarke liegt noch, weil erst
                // Schritt 13 sie loest.
                assert!(harness.prepared_marker_is_present());
            }
            FinalizationStep::ReconcileAndOpenBlankDraft => {
                assert_eq!(reached.phase(), FinalizationPhase::Reconciled);
                assert!(
                    !harness.prepared_marker_is_present(),
                    "Schritt 13 loest die Abschlussmarke"
                );
                assert_eq!(
                    harness.staged_object_count(),
                    0,
                    "und laesst keine Staging-Adresse zurueck"
                );
                assert!(harness.draft_is_blank());
                assert_eq!(
                    reached.outcome().map(|outcome| outcome.sync_status),
                    Some(ea_archive_fs::SyncStatus::LocallySaved)
                );
            }
        }
    }
}
