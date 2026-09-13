mod support;
use ea_destruction::*;
use ea_format::{CertificateKindV1, OperatorRoleV1};
use ea_operator::ReauthPurpose;
use support::*;

#[test]
fn frozen_custody_survives_restart_and_new_known_reader_invalidates_old_denominator() {
    let mut f = RequestFixture::new();
    let head = f.f.head();
    let (auth, target) = f.authorization();
    let first = event(&f.f, &auth, event_fields(&f.f, &auth, 1, None, 0, None));
    let proof = f.proof(&head, ReauthPurpose::Destruction);
    let audit = f.audit(&head, false, false);
    let repository = SqliteDestructionRepository::new(f.database.clone());
    let service = DestructionRequestService {
        head: &head,
        certificate: f.certificate,
        role: OperatorRoleV1::Writer,
        account: &Account { matching: true },
        audit: &audit,
        repository: &repository,
    };
    let request = service.request(&auth, &first, &[target], &proof).unwrap();
    let resumed = service
        .resume(request.authorization(), &head, &proof)
        .unwrap();
    let custody = SqliteManagedCustody::new(f.database.clone());
    let frozen = custody.freeze(&resumed).unwrap();
    assert_eq!(frozen.known_replica_count(), 1);
    let exact = frozen.exact_bytes().to_vec();
    drop(custody);
    let reopened = SqliteManagedCustody::new(f.reopen());
    let loaded = reopened.freeze(&resumed).unwrap();
    assert_eq!(loaded.exact_bytes(), exact);
    reopened.require_unchanged(&loaded).unwrap();
    f.f.line.push(
        trust::ActionSpec::Device {
            kind: CertificateKindV1::Reader,
            marker: 0x7a,
            effective_from: None,
        },
        options(),
    );
    let current = selected(&f.f.line, NOW + 1);
    reopened.observe_registry(&current).unwrap();
    assert_eq!(
        reopened.require_unchanged(&loaded).err(),
        Some(DestructionError::SecurityConflict)
    );
    assert!(
        reopened.freeze(&resumed).is_err(),
        "same job cannot shrink or replace its frozen denominator"
    );
}

#[test]
fn revoked_historically_admitted_custodian_stays_in_durable_inventory() {
    let mut f = RequestFixture::new();
    let reader =
        f.f.line
            .push(
                trust::ActionSpec::Device {
                    kind: CertificateKindV1::Reader,
                    marker: 0x7a,
                    effective_from: None,
                },
                options(),
            )
            .direct_object_hash
            .unwrap();
    f.f.line.push(
        trust::ActionSpec::Revoke {
            target_kind: 0,
            object_hash: reader,
        },
        options(),
    );
    let head = f.f.head();
    assert!(
        head.active_certificate_fields(ea_types::CertificateHash::from(reader))
            .is_none()
    );
    let (auth, target) = f.authorization();
    let first = event(&f.f, &auth, event_fields(&f.f, &auth, 1, None, 0, None));
    let proof = f.proof(&head, ReauthPurpose::Destruction);
    let audit = f.audit(&head, false, false);
    let repository = SqliteDestructionRepository::new(f.database.clone());
    let service = DestructionRequestService {
        head: &head,
        certificate: f.certificate,
        role: OperatorRoleV1::Writer,
        account: &Account { matching: true },
        audit: &audit,
        repository: &repository,
    };
    let request = service.request(&auth, &first, &[target], &proof).unwrap();
    let resumed = service
        .resume(request.authorization(), &head, &proof)
        .unwrap();
    let custody = SqliteManagedCustody::new(f.database.clone());
    let frozen = custody.freeze(&resumed).unwrap();
    assert_eq!(frozen.known_replica_count(), 2);
    assert!(
        f.database
            .execute("DELETE FROM managed_custody", &[])
            .is_err()
    );
    assert!(
        f.database
            .execute(
                "UPDATE destruction_inventory SET exact_bytes=X\u{27}00\u{27}",
                &[]
            )
            .is_err()
    );
}
