mod support;
use async_trait::async_trait;
use aws_sdk_s3::primitives::ByteStream;
use ea_format::ObjectTypeV1;
use ea_sync_server::destruction::{DestructionPorts, accept_destruction_request};
use ea_sync_server::*;
use ea_types::*;
use std::sync::Arc;

struct Ports {
    head: Arc<ea_trust::SelectedRegistryHead>,
}
impl ServerClock for Ports {
    fn now(&self) -> UnixMillis {
        UnixMillis::new(support::NOW)
    }
}
#[async_trait]
impl ChainHeadReader for Ports {
    async fn committed_chain_head(
        &self,
        _: OrganizationId,
        _: ChainId,
    ) -> Result<Option<ChainHeadStateV1>, RepositoryError> {
        Ok(Some(ChainHeadStateV1 {
            sequence: ChainSequence::new(self.head.proposed_sequence().get() - 1),
            entry_hash: EntryHash::try_from(&[0x82; 32][..]).unwrap(),
            accepted_at_server: UnixMillis::new(support::NOW),
        }))
    }
}
#[async_trait]
impl RegistryHeadDirectory for Ports {
    async fn select_current_admission(
        &self,
        _: OrganizationId,
        _: ChainSequence,
        now: UnixMillis,
    ) -> Result<Option<RegistryAdmissionV1>, AuthorityError> {
        Ok(Some(RegistryAdmissionV1 {
            head: self.head.clone(),
            fence: RegistryAdmissionFenceV1 {
                catalog_revision: 1,
                exact_anchor_bytes: vec![],
                selected_at: now,
                not_after: self.head.not_after(),
            },
        }))
    }
    async fn select_head_for_sequence(
        &self,
        organization: OrganizationId,
        sequence: ChainSequence,
        _: UnixMillis,
    ) -> Result<RegistryHeadSelectionV1, AuthorityError> {
        assert!(organization == self.head.policy_fields().organization_id);
        assert!(sequence == self.head.proposed_sequence());
        Ok(RegistryHeadSelectionV1::Selected(self.head.clone()))
    }
}
#[async_trait]
impl ObjectStore for Ports {
    // A successfully authorized call reaches this intentionally unavailable
    // external dependency; refused requests must return their own policy code.
    async fn stage_stream(
        &self,
        _: ObjectTypeV1,
        _: ByteStream,
        _: u64,
    ) -> Result<StagedObject, StoreError> {
        Err(StoreError::Unavailable)
    }
    async fn put_if_absent(&self, _: StagedObject) -> Result<StoredObject, StoreError> {
        panic!("unreachable")
    }
    async fn get_exact(&self, _: ObjectHash) -> Result<ByteStream, StoreError> {
        panic!("unreachable")
    }
    async fn get_exact_in(&self, _: ObjectTypeV1, _: ObjectHash) -> Result<ByteStream, StoreError> {
        panic!("unreachable")
    }
}
#[async_trait]
impl DestructionStore for Ports {
    async fn record_destruction_request(
        &self,
        _: DestructionRequestCommandV1,
        _: &dyn ServerClock,
    ) -> Result<AppendOutcome, RepositoryError> {
        panic!("unreachable")
    }
    async fn destruction_state(
        &self,
        _: OrganizationId,
        _: DestructionId,
    ) -> Result<Option<DestructionStateV1>, RepositoryError> {
        Ok(None)
    }
    async fn is_destruction_target(
        &self,
        _: OrganizationId,
        _: EntryHash,
    ) -> Result<bool, RepositoryError> {
        panic!("unreachable")
    }
}
async fn admit(f: &support::Fixture, bytes: &[u8]) -> String {
    let p = Ports {
        head: Arc::new(f.head()),
    };
    let ports = DestructionPorts {
        clock: &p,
        objects: &p,
        destructions: &p,
        heads: &p,
        chain_heads: &p,
    };
    accept_destruction_request(support::trust::organization(), bytes, &ports)
        .await
        .err()
        .unwrap()
        .code()
        .into()
}
#[tokio::test]
async fn server_enforces_both_documented_policy_conditions_before_storage() {
    for (enabled, document) in [(false, false), (false, true), (true, false)] {
        let f = support::Fixture::new(enabled, document, false);
        assert_eq!(
            admit(&f, &f.authorization()).await,
            "EA-DESTRUCTION-PRIVACY-GATE"
        );
    }
    let f = support::Fixture::new(true, true, false);
    assert_eq!(
        admit(&f, &f.authorization()).await,
        "EA-DESTRUCTION-DEPENDENCY-UNAVAILABLE"
    );
}
#[tokio::test]
async fn server_rejects_forged_head_hash_and_same_person_approvals() {
    let f = support::Fixture::new(true, true, false);
    let mut fields = f.fields();
    fields.registry_head_hash = Hash32::ZERO;
    assert_eq!(
        admit(&f, &f.sign(fields, f.approvers.to_vec())).await,
        "EA-DESTRUCTION-AUTHORIZATION-UNVERIFIABLE"
    );
    let f = support::Fixture::new(true, true, true);
    assert_eq!(
        admit(&f, &f.authorization()).await,
        "EA-DESTRUCTION-AUTHORIZATION-INSUFFICIENT"
    );
}

struct CatalogDirectory<'a> {
    line: &'a support::trust::RegistryLineBuilder,
    committed_server_head: ChainHeadStateV1,
}
impl CatalogDirectory<'_> {
    fn head_at(&self, sequence: ChainSequence) -> ea_trust::SelectedRegistryHead {
        let index = self
            .line
            .heads()
            .iter()
            .rposition(|h| h.effective_from <= sequence)
            .unwrap();
        support::try_selected_at(self.line, index, support::NOW).unwrap()
    }
}
#[async_trait]
impl RegistryHeadDirectory for CatalogDirectory<'_> {
    async fn select_current_admission(
        &self,
        _: OrganizationId,
        sequence: ChainSequence,
        now: UnixMillis,
    ) -> Result<Option<RegistryAdmissionV1>, AuthorityError> {
        let head = self.head_at(sequence);
        let fence = RegistryAdmissionFenceV1 {
            catalog_revision: 1,
            exact_anchor_bytes: self.line.exact_anchor_bytes().to_vec(),
            selected_at: now,
            not_after: head.not_after(),
        };
        Ok(Some(RegistryAdmissionV1 {
            head: Arc::new(head),
            fence,
        }))
    }
    async fn select_head_for_sequence(
        &self,
        _: OrganizationId,
        sequence: ChainSequence,
        _: UnixMillis,
    ) -> Result<RegistryHeadSelectionV1, AuthorityError> {
        Ok(RegistryHeadSelectionV1::Selected(Arc::new(
            self.head_at(sequence),
        )))
    }
}
#[async_trait]
impl ChainHeadReader for CatalogDirectory<'_> {
    async fn committed_chain_head(
        &self,
        _: OrganizationId,
        _: ChainId,
    ) -> Result<Option<ChainHeadStateV1>, RepositoryError> {
        Ok(Some(self.committed_server_head))
    }
}
#[tokio::test]
async fn current_server_progress_keeps_future_policy_inactive_but_enforces_effective_disablement() {
    let mut f = support::Fixture::new(true, true, false);
    let bytes = f.authorization();
    f.line.push(
        support::trust::ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        support::trust::HeadOptions {
            policy_destruction_enabled_override: Some(false),
            policy_eds_privacy_decision_document_hash_override: Some(None),
            ..support::options()
        },
    );
    for (next, expected) in [
        (301, "EA-DESTRUCTION-DEPENDENCY-UNAVAILABLE"),
        (401, "EA-DESTRUCTION-PRIVACY-GATE"),
    ] {
        let directory = CatalogDirectory {
            line: &f.line,
            committed_server_head: ChainHeadStateV1 {
                sequence: ChainSequence::new(next - 1),
                entry_hash: EntryHash::try_from(&[0x82; 32][..]).unwrap(),
                accepted_at_server: UnixMillis::new(support::NOW),
            },
        };
        let current = directory.head_at(ChainSequence::new(
            directory.committed_server_head.sequence.get() + 1,
        ));
        assert_eq!(
            current.policy_fields().retention_policy.destruction_enabled,
            next == 301
        );
        let p = Ports {
            head: Arc::new(directory.head_at(ChainSequence::new(301))),
        };
        let ports = DestructionPorts {
            clock: &p,
            objects: &p,
            destructions: &p,
            heads: &directory,
            chain_heads: &directory,
        };
        assert_eq!(
            accept_destruction_request(support::trust::organization(), &bytes, &ports)
                .await
                .err()
                .unwrap()
                .code(),
            expected
        );
    }
}
