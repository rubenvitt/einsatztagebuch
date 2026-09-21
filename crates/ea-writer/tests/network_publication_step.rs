//! Schritt 12 (EA-CNA-PUB-8 (a)): ein angehängter Publikationsport wird genau
//! einmal NACH dem lokalen Commit des `.eip` gerufen, und sein Ausgang lässt
//! die Finalisierung nie scheitern.

mod support;

use std::sync::{Arc, Mutex};

use ea_archive_fs::{LocalPathBackend, PublicationOutcomeV1, SyncStatus};
use ea_operator::ReauthPurpose;
use ea_writer::{FinalizationFaultPoint, NetworkPublicationPortV1};
use support::{WriterHarness, valid_incident};

/// Was der Port im Augenblick seines Aufrufs am Bestand sah.
#[derive(Debug)]
struct Observation {
    entries: Vec<String>,
    grants: Vec<String>,
    staged: Vec<String>,
}

/// Ein Port, der beobachtet statt zu veröffentlichen, und `Deferred` meldet
/// — der Ausgang, den ein nicht erreichbares Netzziel liefert.
struct RecordingPort {
    backend: Arc<LocalPathBackend>,
    calls: Mutex<Vec<Observation>>,
}
impl RecordingPort {
    fn new(backend: Arc<LocalPathBackend>) -> Self {
        Self {
            backend,
            calls: Mutex::new(Vec::new()),
        }
    }
}
impl NetworkPublicationPortV1 for RecordingPort {
    fn publish_committed(&self) -> PublicationOutcomeV1 {
        let below = |directory: &str, suffix: &str| -> Vec<String> {
            self.backend
                .relative_paths_below_for_test(directory)
                .into_iter()
                .filter(|path| path.ends_with(suffix))
                .collect()
        };
        let mut staged = below("entries/", ".staging");
        staged.extend(below("grants/", ".staging"));
        self.calls.lock().unwrap().push(Observation {
            entries: below("entries/", ".eip"),
            grants: below("grants/", ".eag"),
            staged,
        });
        PublicationOutcomeV1::Deferred
    }
}

#[test]
fn step_twelve_calls_the_port_once_after_the_entry_commit_and_never_fails_finalization() {
    let harness = WriterHarness::with_incident();
    let port = RecordingPort::new(harness.backend_handle());
    let source = harness.source();
    let service = harness.service(&source).with_network_publication(&port);
    let proof = harness.proof_for(ReauthPurpose::Finalize);

    let preview = service
        .preview(&proof, valid_incident(), harness.observed_now())
        .unwrap();
    assert!(
        port.calls.lock().unwrap().is_empty(),
        "die Vorschau erreicht Schritt 12 nie"
    );
    let outcome = service
        .finalize(&proof, valid_incident(), &preview, harness.observed_now())
        .expect("ein aufgeschobenes Netzziel lässt die Finalisierung nicht scheitern");
    assert_eq!(
        outcome.sync_status,
        SyncStatus::LocallySaved,
        "der fachliche Abschluss ist nach Schritt 11 `lokal gesichert`"
    );

    let calls = port.calls.lock().unwrap();
    assert_eq!(calls.len(), 1, "genau ein Aufruf je Finalisierung");
    let seen = &calls[0];
    assert_eq!(
        seen.entries,
        harness.published_entry_paths(),
        "beim Aufruf ist das `.eip` bereits committed (nach Schritt 11)"
    );
    assert_eq!(seen.entries.len(), 1);
    assert_eq!(
        seen.grants.len(),
        harness.expected_grant_count(),
        "und jeder Grant davor"
    );
    assert!(
        seen.staged.is_empty(),
        "keine Staging-Adresse mehr: die Renames sind durch: {seen:?}"
    );
    assert!(harness.draft_is_blank());
}

#[test]
fn a_run_that_stops_before_step_twelve_never_calls_the_port() {
    let harness = WriterHarness::with_incident();
    let port = RecordingPort::new(harness.backend_handle());
    let source = harness.source();
    let service = harness.service(&source).with_network_publication(&port);
    let proof = harness.proof_for(ReauthPurpose::Finalize);
    service
        .finalize_interrupted_at(
            &proof,
            valid_incident(),
            harness.observed_now(),
            FinalizationFaultPoint::AfterEntryDirectoryFlush,
        )
        .unwrap();
    assert_eq!(harness.published_entry_paths().len(), 1);
    assert!(
        port.calls.lock().unwrap().is_empty(),
        "ein Abbruch nach Schritt 11 publiziert nicht"
    );
}
