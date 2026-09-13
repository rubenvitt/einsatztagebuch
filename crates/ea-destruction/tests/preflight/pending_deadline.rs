//! Exact signed historical Pending events at and after retained expiry.
use super::*;

#[derive(Clone, Copy)]
pub(super) enum Probe {
    SingleExpired,
    ExpiredBesideFuture,
}

#[test]
fn historical_pending_refuses_at_and_after_backup_expiry_without_removal() {
    run_local_scenario_with_probes(None, false, None, None, Some(Probe::SingleExpired));
}

#[test]
fn historical_pending_future_other_deadline_cannot_hide_expired_duty() {
    run_local_scenario_with_probes(None, false, None, None, Some(Probe::ExpiredBesideFuture));
}

pub(super) fn run(
    probe: Probe,
    input: remaining_states::Inputs<'_>,
    transition: &impl Fn(u8, u8, ObjectHash, i64, u8) -> VerifiedDestructionEvent,
    server_claim: &impl Fn(DeletionAttestationFieldsV1) -> VerifiedDeletionAttestation,
    reader_claim: &impl Fn(DeletionAttestationFieldsV1) -> VerifiedDeletionAttestation,
) {
    let remaining_states::Inputs {
        job,
        requested,
        started,
        writer,
        reader_pending,
        server,
    } = input;
    assert_eq!(reader_pending.fields().executed_at, UnixMillis::new(1001));
    assert_eq!(
        reader_pending.fields().backup_expiry_at,
        Some(UnixMillis::new(2000))
    );
    assert_eq!(reader_pending.fields().result, 1);
    let server = match probe {
        Probe::SingleExpired => server.clone(),
        Probe::ExpiredBesideFuture => {
            let mut fields = server.fields().clone();
            fields.result = 1;
            fields.executed_at = UnixMillis::new(1001);
            fields.backup_expiry_at = Some(UnixMillis::new(3000));
            server_claim(fields)
        }
    };
    let claims = [writer.clone(), reader_pending.clone(), server];
    let evidence = project_imported_evidence(job, &claims).unwrap();
    assert_eq!(evidence.replicas().len(), 3);
    assert!(
        !evidence
            .replicas()
            .iter()
            .any(|(_, s)| *s == EvidenceReplicaStatus::Unreachable)
    );
    assert!(!evidence.all_managed_replicas_confirmed());
    let pending_count = evidence
        .replicas()
        .iter()
        .filter(|(_, s)| *s == EvidenceReplicaStatus::PendingBackup)
        .count();
    assert_eq!(
        pending_count,
        match probe {
            Probe::SingleExpired => 1,
            Probe::ExpiredBesideFuture => 2,
        }
    );

    let before_expiry = transition(1, 2, started.object_hash(), 1999, 0xb1);
    let before_events = [requested.clone(), started.clone(), before_expiry];
    assert_eq!(
        reconstruct_imported_history(job, &before_events, &claims)
            .unwrap()
            .state(),
        DestructionState::PendingBackupExpiry
    );

    // Both boundaries are actually reconstructed before the final assertion,
    // so an at-expiry failure cannot hide the after-expiry observation.
    let accepted = [2000, 2001].map(|time| {
        let candidate = transition(1, 2, started.object_hash(), time, 0xb2);
        assert!(
            claims
                .iter()
                .all(|c| c.fields().executed_at < candidate.fields().executed_at)
        );
        let events = [requested.clone(), started.clone(), candidate];
        reconstruct_imported_history(job, &events, &claims).is_ok()
    });
    eprintln!(
        "pending-deadline pending-count={pending_count} before-expiry-accepted=true at-expiry-accepted={} after-expiry-accepted={}",
        accepted[0], accepted[1]
    );
    assert!(
        accepted.iter().all(|accepted| !accepted),
        "expired Pending duty without successful removal cannot justify a new 1->2 event, even beside another future deadline"
    );

    // The historical maximum remains authoritative even if a newer claim
    // announces a shorter deadline. Input order must not alter that bound.
    let mut shorter = reader_pending.fields().clone();
    shorter.executed_at = UnixMillis::new(1100);
    shorter.backup_expiry_at = Some(UnixMillis::new(1500));
    let mut shortened_claims = claims.to_vec();
    shortened_claims.push(reader_claim(shorter));
    for _ in 0..2 {
        assert_eq!(
            reconstruct_imported_history(job, &before_events, &shortened_claims)
                .unwrap()
                .state(),
            DestructionState::PendingBackupExpiry
        );
        shortened_claims.reverse();
    }

    // A valid but later-executed claim cannot lend its longer deadline to the
    // already expired event under review, regardless of delivery array order.
    let mut later = reader_pending.fields().clone();
    later.executed_at = UnixMillis::new(2002);
    later.backup_expiry_at = Some(UnixMillis::new(4000));
    let mut later_claims = claims.to_vec();
    later_claims.push(reader_claim(later));
    let expired = transition(1, 2, started.object_hash(), 2001, 0xb3);
    let expired_events = [requested.clone(), started.clone(), expired];
    for _ in 0..2 {
        assert!(
            reconstruct_imported_history(job, &expired_events, &later_claims).is_err(),
            "future execution cannot extend an older Pending event's deadline"
        );
        later_claims.reverse();
    }
}
