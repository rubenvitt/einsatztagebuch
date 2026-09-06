use super::*;
use ea_audit::{AuditActorProof, TypedLocalAuditEvent};
use std::cell::{Cell, RefCell};

#[test]
fn prepared_audit_waits_for_the_enclosing_transaction_and_rolls_back_with_it() {
    let fixture = support::ceremony_line();
    let head = support::selected_head(&fixture.line);
    let proof = support::ceremony_proof(&fixture, &head, ReauthPurpose::AdminRootCeremony);
    let (database, directory) = database();
    let provider = Arc::new(support::FixtureKeyProvider::device());
    let service = ea_audit::SignedLocalAuditService::new(
        Arc::new(ea_audit::SqliteLocalAuditRepository::new(database.clone())),
        provider.clone(),
        provider.handle(),
        fixture.writer_certificate_object_hash,
        UnixMillis::new(1000),
    );
    let prepared = service
        .prepare_signed(
            AuditActorProof::OperatorSession(&proof),
            TypedLocalAuditEvent {
                action: ea_format::LocalAuditActionV1::Login(
                    ea_format::GenericAuditContextV1::new(Some(fixture.binding_object_hash)),
                ),
                outcome: ea_format::LocalAuditOutcomeV1::Accepted,
            },
        )
        .expect("preparation signs without booking");
    verify_prepared_audit(&prepared, &head, ea_crypto::SignerRole::Writer).unwrap();
    let foreign = Arc::new(support::FixtureKeyProvider::foreign());
    let wrong = ea_audit::SignedLocalAuditService::new(
        Arc::new(ea_audit::SqliteLocalAuditRepository::new(database.clone())),
        foreign.clone(),
        foreign.handle(),
        fixture.writer_certificate_object_hash,
        UnixMillis::new(1000),
    );
    let wrong = wrong
        .prepare_signed(
            AuditActorProof::OperatorSession(&proof),
            TypedLocalAuditEvent {
                action: ea_format::LocalAuditActionV1::Login(
                    ea_format::GenericAuditContextV1::new(Some(fixture.binding_object_hash)),
                ),
                outcome: ea_format::LocalAuditOutcomeV1::Accepted,
            },
        )
        .unwrap();
    assert!(
        verify_prepared_audit(&wrong, &head, ea_crypto::SignerRole::Writer).is_err(),
        "structurally valid foreign signature cannot enter atomic publication"
    );
    assert!(
        database
            .query_row("SELECT event_id FROM local_audit_event", &[])
            .unwrap()
            .is_none()
    );
    let rolled_back = database.transaction(|tx| {
        ea_audit::SqliteLocalAuditRepository::append_prepared_in(tx, &prepared)?;
        Err::<(), _>(ea_audit::AuditError::Encoding)
    });
    assert!(rolled_back.is_err());
    assert!(
        database
            .query_row("SELECT event_id FROM local_audit_event", &[])
            .unwrap()
            .is_none()
    );
    database
        .transaction(|tx| ea_audit::SqliteLocalAuditRepository::append_prepared_in(tx, &prepared))
        .unwrap();
    assert_eq!(
        database
            .query_row("SELECT exact_bytes FROM local_audit_event", &[])
            .unwrap()
            .unwrap()
            .blob(0)
            .unwrap(),
        prepared.exact_bytes()
    );
    drop(database);
    std::fs::remove_dir_all(directory).unwrap();
}

struct Publication {
    signature: RefCell<Option<Vec<u8>>>,
    committed: Cell<bool>,
    reject: bool,
}
impl crate::root_ceremony::DurableRootPublication for Publication {
    fn retained_signature(&self) -> Result<Option<Vec<u8>>, AdminError> {
        Ok(self.signature.borrow().clone())
    }
    fn stage_signature(&self, signature: &[u8]) -> Result<(), AdminError> {
        self.signature.replace(Some(signature.to_vec()));
        Ok(())
    }
    fn commit(
        &self,
        _: &ea_format::ExactObjectBytes,
        _: &[ea_trust::AdminAuthorizationReplayKey; 2],
        _: TypedLocalAuditEvent,
    ) -> Result<(), AdminError> {
        self.committed.set(true);
        if self.reject {
            Err(AdminError::AuditFailed)
        } else {
            Ok(())
        }
    }
}

#[test]
fn durable_root_retains_public_signature_but_withholds_target_after_callback_failure() {
    let fixture = support::ceremony_line();
    let head = support::selected_head(&fixture.line);
    let intent = fixture.intent(&head);
    let proof = support::ceremony_proof(&fixture, &head, ReauthPurpose::AdminRootCeremony);
    let provider = support::FixtureKeyProvider::root();
    let audit = support::AuditHarness::new(&head, fixture.writer_certificate_object_hash, 0);
    let service = support::ceremony_service(&head, &provider, &audit, &fixture);
    let mut publication = Publication {
        signature: RefCell::new(None),
        committed: Cell::new(false),
        reject: true,
    };
    assert!(
        service
            .publish_durably(
                &intent,
                fixture.target_payload(),
                fixture.authorization_bytes(),
                &proof,
                &publication
            )
            .is_err()
    );
    assert!(
        publication.committed.get(),
        "the durable callback must be reached after validation"
    );
    assert!(
        publication.signature.borrow().is_some(),
        "public Root signature must survive a failed commit"
    );
    publication.reject = false;
    let retained = publication.signature.borrow().clone().unwrap();
    let mut forged = retained.clone();
    *forged.last_mut().unwrap() ^= 1;
    publication.signature.replace(Some(forged));
    publication.committed.set(false);
    assert!(matches!(
        service.publish_durably(
            &intent,
            fixture.target_payload(),
            fixture.authorization_bytes(),
            &proof,
            &publication
        ),
        Err(AdminError::RootSignatureMismatch)
    ));
    assert!(
        !publication.committed.get(),
        "forged retained signature must never reach commit"
    );
    publication.signature.replace(Some(retained));
    let wrong = support::second_operator_proof(&fixture, &head, ReauthPurpose::AdminRootCeremony);
    assert!(matches!(
        service.publish_durably(
            &intent,
            fixture.target_payload(),
            fixture.authorization_bytes(),
            &wrong,
            &publication
        ),
        Err(AdminError::BindingMismatch)
    ));
    assert!(
        !publication.committed.get(),
        "retention cannot substitute another operator's presence"
    );
    let mut wrong = fixture.authorization_bytes().to_vec();
    wrong[0] ^= 1;
    assert!(matches!(
        service.publish_durably(
            &intent,
            fixture.target_payload(),
            &wrong,
            &proof,
            &publication
        ),
        Err(AdminError::AuthorizationMismatch)
    ));
    assert!(!publication.committed.get());

    let target = service
        .publish_durably(
            &intent,
            fixture.target_payload(),
            fixture.authorization_bytes(),
            &proof,
            &publication,
        )
        .unwrap();
    assert_eq!(
        provider.signatures_produced(),
        1,
        "resumption must not ask the Root for a new signature"
    );
    assert!(!target.as_bytes().is_empty());
}
