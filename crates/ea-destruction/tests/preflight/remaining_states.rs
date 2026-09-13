//! Signed historical reducer probes only; no remote removal or native producer.
use super::*;

#[derive(Clone, Copy)]
pub(super) enum Probe {
    PendingMissingDuty,
    LateOriginal,
}

pub(super) struct Inputs<'a> {
    pub job: &'a VerifiedImportedPreflight,
    pub requested: &'a VerifiedDestructionEvent,
    pub started: &'a VerifiedDestructionEvent,
    pub writer: &'a VerifiedDeletionAttestation,
    pub reader_pending: &'a VerifiedDeletionAttestation,
    pub server: &'a VerifiedDeletionAttestation,
}

pub(super) fn run(
    probe: Probe,
    input: Inputs<'_>,
    claim: &impl Fn(DeletionAttestationFieldsV1) -> VerifiedDeletionAttestation,
    transition: &impl Fn(u8, u8, ObjectHash, i64, u8) -> VerifiedDestructionEvent,
) {
    let Inputs {
        job,
        requested,
        started,
        writer,
        reader_pending,
        server,
    } = input;
    match probe {
        Probe::PendingMissingDuty => {
            let pending = transition(1, 2, started.object_hash(), 1001, 0xa1);
            let events = [requested.clone(), started.clone(), pending];
            let complete_duties = [writer.clone(), reader_pending.clone(), server.clone()];
            let control = reconstruct_imported_history(job, &events, &complete_duties).unwrap();
            assert_eq!(control.state(), DestructionState::PendingBackupExpiry);
            assert_eq!(control.evidence().replicas().len(), 3);
            assert_eq!(
                reader_pending.fields().backup_expiry_at,
                Some(UnixMillis::new(2000))
            );
            assert_eq!(reader_pending.fields().executed_at, UnixMillis::new(1001));

            // The same fixed Server duty is immediately removable in the
            // positive control. Withholding its attestation does not turn it
            // into an immutable backup or remove it from the denominator.
            let missing = [writer.clone(), reader_pending.clone()];
            let projected = project_imported_evidence(job, &missing).unwrap();
            assert_eq!(projected.replicas().len(), 3);
            assert!(projected.replicas().iter().any(|(device, status)| {
                device.as_bytes() == &server.fields().replica_id
                    && *status == EvidenceReplicaStatus::Unreachable
            }));
            assert!(
                projected
                    .replicas()
                    .iter()
                    .any(|(_, status)| { *status == EvidenceReplicaStatus::PendingBackup })
            );
            assert!(!projected.all_managed_replicas_confirmed());
            assert!(
                reconstruct_imported_history(job, &events, &missing).is_err(),
                "1->2 needs every immediately removable duty, not only one pending backup"
            );
        }
        Probe::LateOriginal => {
            // Sign and verify the original once at its real historical claim
            // time. Delivery below supplies these exact retained bytes later;
            // no new execution time, signature, or object is manufactured.
            let mut fields = reader_pending.fields().clone();
            fields.result = 0;
            fields.backup_expiry_at = None;
            fields.executed_at = UnixMillis::new(1998);
            let retained = claim(fields);
            let exact = retained.exact_bytes().to_vec();
            let hash = retained.object_hash();
            let failed = transition(1, 4, started.object_hash(), 1999, 0xa2);
            let history = [requested.clone(), started.clone(), failed.clone()];
            let known_at_failure = [writer.clone(), server.clone()];
            let before_delivery =
                reconstruct_imported_history(job, &history, &known_at_failure).unwrap();
            assert_eq!(
                before_delivery.state(),
                DestructionState::IncompleteUnreachableReplica
            );
            assert_eq!(before_delivery.evidence().replicas().len(), 3);
            assert!(
                before_delivery
                    .evidence()
                    .replicas()
                    .iter()
                    .any(|(device, status)| {
                        device.as_bytes() == &retained.fields().replica_id
                            && *status == EvidenceReplicaStatus::Unreachable
                    })
            );

            let delivered = [writer.clone(), server.clone(), retained.clone()];
            assert_eq!(delivered[2].exact_bytes(), exact.as_slice());
            assert!(delivered[2].object_hash() == hash);
            assert!(delivered[2].fields().executed_at < failed.fields().executed_at);
            assert!(
                project_imported_evidence(job, &delivered)
                    .unwrap()
                    .all_managed_replicas_confirmed()
            );
            let resumed = transition(4, 1, failed.object_hash(), 2000, 0xa3);
            let mut resumed_history = history.to_vec();
            resumed_history.push(resumed.clone());
            let after_delivery = reconstruct_imported_history(job, &history, &delivered);
            let after_resume = reconstruct_imported_history(job, &resumed_history, &delivered);
            // Orthogonal control: another Server duty remains unreachable,
            // so state 4 remains justified even after late Reader delivery.
            // This isolates the 4->1 recovery test from state-4 admission.
            let writer_only = [writer.clone()];
            assert_eq!(
                reconstruct_imported_history(job, &history, &writer_only)
                    .unwrap()
                    .state(),
                DestructionState::IncompleteUnreachableReplica
            );
            let reader_arrived = [writer.clone(), retained.clone()];
            let partial_delivery =
                reconstruct_imported_history(job, &history, &reader_arrived).unwrap();
            assert_eq!(
                partial_delivery.state(),
                DestructionState::IncompleteUnreachableReplica
            );
            assert!(!partial_delivery.evidence().all_managed_replicas_confirmed());
            let partial_resume =
                reconstruct_imported_history(job, &resumed_history, &reader_arrived);
            eprintln!(
                "late-original historical-failure-accepted={} resumed-history-accepted={} remaining-server-failure-accepted=true remaining-server-resume-accepted={}",
                after_delivery.is_ok(),
                after_resume.is_ok(),
                partial_resume.is_ok()
            );
            assert!(
                after_delivery.is_ok(),
                "later delivery of an older exact success must not erase the valid conservative failure history"
            );
            assert_eq!(
                after_delivery.unwrap().state(),
                DestructionState::IncompleteUnreachableReplica
            );
            assert_eq!(after_resume.unwrap().state(), DestructionState::InProgress);
            let partial_resume = partial_resume.unwrap();
            assert_eq!(partial_resume.state(), DestructionState::InProgress);
            assert_eq!(partial_resume.evidence().replicas().len(), 3);
            assert!(
                partial_resume
                    .evidence()
                    .replicas()
                    .iter()
                    .any(|(device, status)| {
                        device.as_bytes() == &server.fields().replica_id
                            && *status == EvidenceReplicaStatus::Unreachable
                    })
            );
            assert!(!partial_resume.evidence().all_managed_replicas_confirmed());
            assert_original_targets(partial_resume.evidence(), job);
            resumed_history.push(transition(1, 3, resumed.object_hash(), 2000, 0xa7));
            assert!(reconstruct_imported_history(job, &resumed_history, &reader_arrived).is_err());
        }
    }
}

// Inspect the existing evidence payload conversion without signing or
// publishing it. A historical retry must preserve every target/stub binding.
pub(super) fn assert_original_targets(
    evidence: &VerifiedDestructionEvidence,
    job: &VerifiedImportedPreflight,
) {
    let mut record = [0x11; 16];
    record[6] = 0x70;
    record[8] = 0x80;
    let header = ea_schema::CommonHeaderV1::new(
        RecordId::try_from(record.as_slice()).unwrap(),
        UnixMillis::new(2000),
        "UTC",
        ea_schema::OperatorSnapshotV1::new(
            evidence.organization_id(),
            OperatorSubjectId::try_from(&[0x73; 16][..]).unwrap(),
            "Historical fixture",
            "Operator",
            [0x74; 32],
            ObjectHash::try_from(&[0x75; 32][..]).unwrap(),
        )
        .unwrap(),
        ea_schema::NativeSourceV1::new("historical-fixture", 1).unwrap(),
        RegistryVersion::new(1),
    )
    .unwrap();
    let payload = evidence.clone().into_payload(header).unwrap();
    assert_eq!(payload.targets().len(), job.targets().len());
    assert_eq!(payload.stub_bindings().len(), job.targets().len());
    for target in job.targets() {
        assert!(payload.targets().iter().any(|actual| {
            actual.entry_hash() == target.entry_hash()
                && actual.chain_sequence() == target.sequence()
        }));
        assert!(payload.stub_bindings().iter().any(|actual| {
            actual.entry_hash() == target.entry_hash()
                && actual.stub_object_hash() == ea_crypto::object_hash(target.exact_stub_bytes())
        }));
    }
}
