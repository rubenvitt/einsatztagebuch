#[path = "support/operator_lifecycle.rs"]
mod lifecycle;
mod support;

use ea_admin::{
    AuthorizedOperatorIntent, OperatorAuthorizationPort, OperatorLifecycleError,
    OperatorMutationPorts, OperatorTrustTarget, RegistryWindow, RevokeOperatorRequest,
    RootCeremonyService,
    operator_exchange::{ExchangeError, ExchangeSigner, PendingExchange},
};
use ea_crypto::{CanonicalPublicCoseKey, object_hash};
use ea_local_store::EncryptedDatabase;
use ea_trust::SelectedRegistryHead;
use ea_types::{CertificateHash, Hash32, ObjectHash, UnixMillis};
use ed25519_dalek::{Signer, SigningKey};
use lifecycle::*;
use serde_json::json;
use std::sync::{Arc, Mutex};

struct Signing(SigningKey);
impl ExchangeSigner for Signing {
    fn sign(&self, input: &[u8]) -> Result<[u8; 64], ExchangeError> {
        Ok(self.0.sign(input).to_bytes())
    }
}
struct LostReply {
    database: Arc<EncryptedDatabase>,
    requests: Vec<Vec<u8>>,
    issued: Vec<i64>,
}
impl OperatorAuthorizationPort for LostReply {
    fn stage_signed_objects(&mut self, _: &[&[u8]]) -> Result<(), OperatorLifecycleError> {
        panic!("a lost reply cannot reach object staging")
    }
    fn authorize(
        &mut self,
        head: &SelectedRegistryHead,
        target: &OperatorTrustTarget,
    ) -> Result<AuthorizedOperatorIntent, OperatorLifecycleError> {
        let OperatorTrustTarget::Registry(event) = target else {
            panic!("expected Registry revocation")
        };
        self.issued.push(event.issued_at.get());
        let signing = Signing(SigningKey::from_bytes(&[0x29; 32]));
        let public = CanonicalPublicCoseKey::ed25519(signing.0.verifying_key().to_bytes()).unwrap();
        let payload = target.payload(ObjectHash::from(Hash32::ZERO)).unwrap();
        let pending = PendingExchange::load_or_create(
            &self.database,
            json!({"context": {
                "registry_head_hash": hex::encode(head.registry_head_hash().as_bytes()),
                "registry_version": head.registry_version().get(),
                "sequence": head.proposed_sequence().get()},
                "op": "authorize-target", "args": {
                    "target_payload": hex::encode(payload.exact_digest_input()),
                    "relevant_objects": []}}),
            &signing,
            &public,
        )
        .unwrap();
        self.requests.push(pending.request_bytes().to_vec());
        Err(OperatorLifecycleError::IdentityVerification)
    }
}
fn revoke(
    h: &Harness,
    head: &SelectedRegistryHead,
    lost: &mut LostReply,
    requested: RegistryWindow,
) -> OperatorLifecycleError {
    let audit = h.audit(head, 0);
    let root = support::FixtureKeyProvider::root();
    let ceremony = RootCeremonyService::new(
        head,
        &root,
        root.handle(),
        CertificateHash::from(head.root_certificate_object_hash()),
        audit.service(),
        h.binding,
    );
    let table = Arc::new(Mutex::new(support::ReplayTable::default()));
    let mut store = support::PersistentStore::open(&table);
    let presence = h.authenticator(head);
    let database = lost.database.clone();
    h.service(head, audit.service())
        .revoke(
            RevokeOperatorRequest {
                database: &database,
                binding_object_hash: h.binding,
                window: requested,
            },
            &mut OperatorMutationPorts {
                authorization: lost,
                ceremony: &ceremony,
                store: &mut store,
            },
            h.login(&presence),
        )
        .err()
        .unwrap()
}

#[test]
fn later_time_after_reopen_reuses_the_exact_pending_revocation_and_reply_key() {
    let h = Harness::new();
    let head = h.head();
    let db = database("revocation-lost-reply");
    let path = db.directory.path().to_owned();
    let mut lost = LostReply {
        database: db.database,
        requests: Vec::new(),
        issued: Vec::new(),
    };
    assert!(matches!(
        revoke(&h, &head, &mut lost, window(50, 100)),
        OperatorLifecycleError::IdentityVerification
    ));
    let key = lost
        .database
        .query_row(
            "SELECT reply_private_key FROM operator_pending_exchange",
            &[],
        )
        .unwrap()
        .unwrap()
        .blob(0)
        .unwrap()
        .to_vec();
    let first_hash = object_hash(&lost.requests[0]);
    drop(lost);
    let mut lost = LostReply {
        database: reopen_database(&path),
        requests: Vec::new(),
        issued: Vec::new(),
    };
    let later = selected_at(
        &h.line,
        h.line.exact_object_bytes(head.registry_head_hash()),
        head.proposed_sequence().get(),
        UnixMillis::new(1100),
    );
    assert!(matches!(
        revoke(&h, &later, &mut lost, window(50, 100)),
        OperatorLifecycleError::IdentityVerification
    ));
    assert_eq!(lost.issued, [1000]);
    assert!(object_hash(&lost.requests[0]) == first_hash);
    let row = lost
        .database
        .query_row(
            "SELECT COUNT(*),reply_private_key FROM operator_pending_exchange",
            &[],
        )
        .unwrap()
        .unwrap();
    assert_eq!(row.integer(0).unwrap(), 1);
    assert!(row.blob(1).unwrap() == key);
}

#[test]
fn a_changed_window_or_actor_does_not_replace_the_frozen_intent() {
    let h = Harness::new();
    let head = h.head();
    let db = database("revocation-frozen-context");
    let mut lost = LostReply {
        database: db.database,
        requests: Vec::new(),
        issued: Vec::new(),
    };
    assert!(matches!(
        revoke(&h, &head, &mut lost, window(50, 100)),
        OperatorLifecycleError::IdentityVerification
    ));
    assert!(matches!(
        revoke(&h, &head, &mut lost, window(51, 100)),
        OperatorLifecycleError::JournalConflict
    ));
    lost.database
        .execute(
            "UPDATE operator_revocation_intent SET admin_binding_hash=zeroblob(32)",
            &[],
        )
        .unwrap();
    assert!(matches!(
        revoke(&h, &head, &mut lost, window(50, 100)),
        OperatorLifecycleError::JournalConflict
    ));
    assert_eq!(lost.requests.len(), 1);
    assert_eq!(
        lost.database
            .query_row("SELECT COUNT(*) FROM operator_pending_exchange", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        1
    );
}
