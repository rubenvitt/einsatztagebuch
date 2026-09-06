//! Exercise the production SQLCipher adapter through verified trust commits.
mod support;

use std::{
    path::Path,
    process::{Command, Stdio},
    sync::{Arc, Barrier},
    thread,
    time::{Duration, Instant},
};

use ea_admin::operator_trust_store::OperatorTrustStateStore;
use ea_crypto::{CoseSigner, SecretBytes};
use ea_format::{
    CertificateKindV1, ClockReleaseContextV1, ClockReleaseJustificationV1, IndependentTimeKindV1,
    IndependentTimeReferenceV1, KeyProtectionProfileV1, LocalAuditActionV1,
    LocalAuditEventCoreFieldsV1, LocalAuditOutcomeV1, ParsedArchiveObject, ReceiptCoreFieldsV1,
    ReceiptCoreV1, ReceiptV1, decode_exact_object, encode_local_audit_core,
    encode_local_audit_event, encode_receipt,
};
use ea_key_provider::{InMemoryKeyProvider, KeyProvider, SecretPurpose};
use ea_local_store::{EncryptedDatabase, StoreValue};
use ea_time::TrustedTimeState;
use ea_trust::{
    AdminAuthorizationReplayKey, ClockReleaseReplayKey, IndependentTimeCommit,
    PersistedTrustRecord, RegistryCandidate, RegistryError, RegistrySelectionCommit,
    StateStoreError, TrustStateKey, TrustStateStore, VerifiedAdminAuthorization,
    VerifiedSignedTime, consume_admin_authorization, decode_trust_anchor, load_trust_state,
    prepare_local_time, select_registry_head, verify_authorized_trust_target, verify_clock_release,
    verify_receipt_time, verify_registry_candidate, verify_trust,
};
use ea_types::{CertificateHash, ChainId, DeviceId, EntryHash, EventId, Hash32, UnixMillis};
use support::trust_support::{self, ActionSpec, HeadOptions, Pin, RegistryLineBuilder};

fn state_key() -> TrustStateKey {
    TrustStateKey {
        organization_id: trust_support::organization(),
        device_id: DeviceId::try_from(&[0x52; 16][..]).unwrap(),
    }
}

fn database(directory: &Path) -> Arc<EncryptedDatabase> {
    let provider = InMemoryKeyProvider::new_for_test([0x61; 32]);
    let key = provider
        .generate(
            SecretPurpose::LocalDatabaseKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    Arc::new(EncryptedDatabase::open(&directory.join("trust.sqlite"), &provider, &key).unwrap())
}

fn open(database: Arc<EncryptedDatabase>, line: &RegistryLineBuilder) -> OperatorTrustStateStore {
    let anchor = decode_trust_anchor(line.exact_anchor_bytes()).unwrap();
    OperatorTrustStateStore::open(
        database,
        state_key(),
        anchor.chain_id(),
        anchor.trust_anchor_hash(),
        UnixMillis::new(100),
    )
    .unwrap()
}

fn policy() -> ActionSpec {
    ActionSpec::Policy {
        policy_version: None,
        previous_policy_hash: None,
        effective_from: None,
    }
}

fn line() -> RegistryLineBuilder {
    let mut line = RegistryLineBuilder::new();
    line.push(policy(), HeadOptions::default());
    line
}

fn candidate_for(store: &mut dyn TrustStateStore, line: &RegistryLineBuilder) -> RegistryCandidate {
    let anchor = decode_trust_anchor(line.exact_anchor_bytes()).unwrap();
    let snapshot = load_trust_state(store, state_key()).unwrap();
    let trust = verify_trust(&anchor, &line.source(), snapshot).unwrap();
    verify_registry_candidate(&trust, line.heads().last().unwrap().effective_from).unwrap()
}

fn select(
    store: &mut dyn TrustStateStore,
    line: &RegistryLineBuilder,
) -> Result<(), RegistryError> {
    let candidate = candidate_for(store, line);
    let time = prepare_local_time(store, &candidate, UnixMillis::new(1_000), &[]).unwrap();
    select_registry_head(candidate, time, None).map(|_| ())
}

// A boundary observer, not a storage mock: commits can only be built by ea-trust.
// This lets adversarial tests submit that same verified commit to real databases.
type SelectionHook<'a> = dyn FnMut(
        &mut OperatorTrustStateStore,
        TrustStateKey,
        u64,
        &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError>
    + 'a;
type TimeHook<'a> = dyn FnMut(
        &mut OperatorTrustStateStore,
        TrustStateKey,
        u64,
        &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError>
    + 'a;

struct Observe<'a> {
    store: &'a mut OperatorTrustStateStore,
    selection: &'a mut SelectionHook<'a>,
}

struct ObserveTime<'a> {
    store: &'a mut OperatorTrustStateStore,
    time: &'a mut TimeHook<'a>,
}

impl TrustStateStore for ObserveTime<'_> {
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        self.store.load(key)
    }
    fn commit_independent_time(
        &mut self,
        key: TrustStateKey,
        revision: u64,
        commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        (self.time)(self.store, key, revision, commit)
    }
    fn clock_release_consumed(
        &mut self,
        key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        self.store.clock_release_consumed(key)
    }
    fn commit_registry_selection(
        &mut self,
        key: TrustStateKey,
        revision: u64,
        commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        self.store.commit_registry_selection(key, revision, commit)
    }
}

impl TrustStateStore for Observe<'_> {
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        self.store.load(key)
    }
    fn commit_independent_time(
        &mut self,
        key: TrustStateKey,
        revision: u64,
        commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        self.store.commit_independent_time(key, revision, commit)
    }
    fn clock_release_consumed(
        &mut self,
        key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        self.store.clock_release_consumed(key)
    }
    fn admin_authorization_consumed(
        &mut self,
        key: &AdminAuthorizationReplayKey,
    ) -> Result<bool, StateStoreError> {
        self.store.admin_authorization_consumed(key)
    }
    fn commit_registry_selection(
        &mut self,
        key: TrustStateKey,
        revision: u64,
        commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        (self.selection)(self.store, key, revision, commit)
    }
}

fn authorization(id: u8, nonce: u8) -> VerifiedAdminAuthorization {
    let mut line = RegistryLineBuilder::new();
    let head = line.push(
        policy(),
        HeadOptions {
            direct_authorization_id: Some(id),
            direct_nonce: Some(nonce),
            ..HeadOptions::default()
        },
    );
    verify_authorized_trust_target(
        &line.verified(Pin::None),
        None,
        line.exact_object_bytes(head.direct_object_hash.unwrap()),
        UnixMillis::new(100),
        head.effective_from,
    )
    .unwrap()
}

#[test]
fn initialization_is_idempotent_and_rejects_a_different_chain_or_anchor() {
    let directory = support::temp_dir("trust-context");
    let db = database(directory.path());
    let line = line();
    let mut store = open(Arc::clone(&db), &line);
    select(&mut store, &line).unwrap();
    let anchor = decode_trust_anchor(line.exact_anchor_bytes()).unwrap();
    let mut reopened = OperatorTrustStateStore::open(
        Arc::clone(&db),
        state_key(),
        anchor.chain_id(),
        anchor.trust_anchor_hash(),
        UnixMillis::new(i64::MAX),
    )
    .unwrap();
    let record = reopened.load(state_key()).unwrap();
    assert_eq!(record.revision(), 1);
    assert_eq!(record.trusted_time().floor().get(), 100);
    assert!(record.pinned_head().unwrap().registry_head_hash() == line.heads()[0].object_hash);
    for (chain, hash) in [
        (
            ChainId::try_from(&[0x99; 16][..]).unwrap(),
            anchor.trust_anchor_hash(),
        ),
        (anchor.chain_id(), trust_support::hash32(0x99)),
    ] {
        assert!(matches!(
            OperatorTrustStateStore::open(
                Arc::clone(&db),
                state_key(),
                chain,
                hash,
                UnixMillis::new(0)
            ),
            Err(StateStoreError::Conflict)
        ));
    }
    assert_eq!(store.load(state_key()).unwrap().revision(), 1);
}

#[test]
fn pin_and_revision_survive_database_close_and_reopen() {
    let directory = support::temp_dir("trust-restart");
    let line = line();
    {
        let mut store = open(database(directory.path()), &line);
        select(&mut store, &line).unwrap();
    }
    let mut store = open(database(directory.path()), &line);
    let record = store.load(state_key()).unwrap();
    assert_eq!(record.revision(), 1);
    assert!(record.pinned_head().unwrap().registry_head_hash() == line.heads()[0].object_hash);
    // Affirming the same head is legal, but still consumes a revision.
    select(&mut store, &line).unwrap();
    assert_eq!(store.load(state_key()).unwrap().revision(), 2);
}

#[test]
fn two_connections_can_commit_a_revision_only_once() {
    let directory = support::temp_dir("trust-concurrent");
    let line = line();
    let mut first = open(database(directory.path()), &line);
    let mut second = open(database(directory.path()), &line);
    let mut hook =
        |first: &mut OperatorTrustStateStore, key, revision, commit: &RegistrySelectionCommit| {
            let barrier = Barrier::new(2);
            let (a, b) = thread::scope(|scope| {
                let a = scope.spawn(|| {
                    barrier.wait();
                    first.commit_registry_selection(key, revision, commit)
                });
                let b = scope.spawn(|| {
                    barrier.wait();
                    second.commit_registry_selection(key, revision, commit)
                });
                (a.join().unwrap(), b.join().unwrap())
            });
            let (winner, loser) = if a.is_ok() { (a, b) } else { (b, a) };
            assert!(matches!(loser, Err(StateStoreError::Conflict)));
            winner
        };
    select(
        &mut Observe {
            store: &mut first,
            selection: &mut hook,
        },
        &line,
    )
    .unwrap();
    assert_eq!(first.load(state_key()).unwrap().revision(), 1);
}

#[test]
fn simultaneous_initialization_does_not_overwrite_the_first_floor() {
    let directory = support::temp_dir("trust-initialize-race");
    let a = database(directory.path());
    let b = database(directory.path());
    let line = line();
    let anchor = decode_trust_anchor(line.exact_anchor_bytes()).unwrap();
    let barrier = Barrier::new(2);
    let open_at = |db, floor| {
        barrier.wait();
        let mut store = OperatorTrustStateStore::open(
            db,
            state_key(),
            anchor.chain_id(),
            anchor.trust_anchor_hash(),
            UnixMillis::new(floor),
        )
        .unwrap();
        let record = store.load(state_key()).unwrap();
        assert_eq!(record.revision(), 0);
        record.trusted_time().floor().get()
    };
    let (a, b) = thread::scope(|scope| {
        let a = scope.spawn(|| open_at(a, 100));
        let b = scope.spawn(|| open_at(b, 200));
        (a.join().unwrap(), b.join().unwrap())
    });
    assert_eq!(a, b);
    assert!([100, 200].contains(&a));
}

fn wait_for(path: &Path) {
    let start = Instant::now();
    while !path.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "process rendezvous timed out"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[ignore = "subprocess entry; invoked by separate_processes_observe_the_same_sql_cas"]
fn trust_store_process_worker() {
    let directory = std::env::var_os("EA_TRUST_STORE_PROCESS_DIR").unwrap();
    let directory = Path::new(&directory);
    let name = std::env::var("EA_TRUST_STORE_PROCESS_NAME").unwrap();
    let line = line();
    let mut store = open(database(directory), &line);
    let mut hook =
        |store: &mut OperatorTrustStateStore, key, revision, commit: &RegistrySelectionCommit| {
            std::fs::write(directory.join(format!("ready-{name}")), []).unwrap();
            wait_for(&directory.join("go"));
            store.commit_registry_selection(key, revision, commit)
        };
    let result = select(
        &mut Observe {
            store: &mut store,
            selection: &mut hook,
        },
        &line,
    );
    let result = result.map_or_else(|error| error.code(), |()| "committed");
    std::fs::write(directory.join(format!("result-{name}")), result).unwrap();
}

#[test]
fn separate_processes_observe_the_same_sql_cas() {
    let directory = support::temp_dir("trust-processes");
    drop(open(database(directory.path()), &line()));
    let children: Vec<_> = ["a", "b"]
        .into_iter()
        .map(|name| {
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "trust_store_process_worker",
                    "--ignored",
                    "--nocapture",
                ])
                .env("EA_TRUST_STORE_PROCESS_DIR", directory.path())
                .env("EA_TRUST_STORE_PROCESS_NAME", name)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    wait_for(&directory.path().join("ready-a"));
    wait_for(&directory.path().join("ready-b"));
    std::fs::write(directory.path().join("go"), []).unwrap();
    for child in children {
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let mut results: Vec<_> = ["a", "b"]
        .into_iter()
        .map(|name| {
            std::fs::read_to_string(directory.path().join(format!("result-{name}"))).unwrap()
        })
        .collect();
    results.sort();
    assert_eq!(results, ["EA-TRUST-STATE-CONFLICT", "committed"]);
    assert_eq!(
        open(database(directory.path()), &line())
            .load(state_key())
            .unwrap()
            .revision(),
        1
    );
}

#[test]
fn each_admin_replay_dimension_is_durable_and_organization_wide() {
    let directory = support::temp_dir("trust-admin-replay");
    let line = line();
    {
        let mut store = open(database(directory.path()), &line);
        consume_admin_authorization(&mut store, &authorization(0x51, 0x61)).unwrap();
    }
    let db = database(directory.path());
    let anchor = decode_trust_anchor(line.exact_anchor_bytes()).unwrap();
    let mut other_device = OperatorTrustStateStore::open(
        db,
        TrustStateKey {
            device_id: DeviceId::try_from(&[0x77; 16][..]).unwrap(),
            ..state_key()
        },
        anchor.chain_id(),
        anchor.trust_anchor_hash(),
        UnixMillis::new(100),
    )
    .unwrap();
    for proof in [authorization(0x51, 0x62), authorization(0x52, 0x61)] {
        assert_eq!(
            consume_admin_authorization(&mut other_device, &proof)
                .unwrap_err()
                .code(),
            "EA-TRUST-AUTH-REPLAY"
        );
    }
}

#[test]
fn concurrent_admin_consumers_cannot_both_consume_the_same_nonce() {
    let directory = support::temp_dir("trust-admin-concurrent");
    let line = line();
    let mut first = open(database(directory.path()), &line);
    let mut second = open(database(directory.path()), &line);
    let a = authorization(0x51, 0x61);
    let b = authorization(0x52, 0x61);
    let barrier = Barrier::new(2);
    let (a, b) = thread::scope(|scope| {
        let a = scope.spawn(|| {
            barrier.wait();
            consume_admin_authorization(&mut first, &a).map(|_| ())
        });
        let b = scope.spawn(|| {
            barrier.wait();
            consume_admin_authorization(&mut second, &b).map(|_| ())
        });
        (a.join().unwrap(), b.join().unwrap())
    });
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(a.err().or(b.err()).unwrap().code(), "EA-TRUST-AUTH-REPLAY");
}

#[test]
fn second_replay_write_failure_keeps_the_first_dimension_consumed_across_restart() {
    let directory = support::temp_dir("trust-replay-failure");
    let line = line();
    {
        let db = database(directory.path());
        let mut store = open(Arc::clone(&db), &line);
        db.execute("CREATE TRIGGER reject_nonce BEFORE INSERT ON operator_admin_replay WHEN NEW.dimension=1 BEGIN SELECT RAISE(ABORT, 'injected failure'); END", &[]).unwrap();
        assert_eq!(
            consume_admin_authorization(&mut store, &authorization(0x51, 0x61))
                .unwrap_err()
                .code(),
            "EA-TRUST-STATE-UNAVAILABLE"
        );
    }
    let db = database(directory.path());
    db.execute("DROP TRIGGER reject_nonce", &[]).unwrap();
    let mut store = open(db, &line);
    let proof = authorization(0x51, 0x61);
    assert_eq!(
        store.admin_authorization_consumed(&proof.replay_keys()[0]),
        Ok(true)
    );
    assert_eq!(
        store.admin_authorization_consumed(&proof.replay_keys()[1]),
        Ok(false)
    );
    assert_eq!(
        consume_admin_authorization(&mut store, &proof)
            .unwrap_err()
            .code(),
        "EA-TRUST-AUTH-REPLAY"
    );
}

#[test]
fn wrong_state_key_is_rejected_without_initializing_another_row() {
    let directory = support::temp_dir("trust-wrong-key");
    let mut store = open(database(directory.path()), &line());
    let mut wrong = state_key();
    wrong.device_id = DeviceId::try_from(&[0x55; 16][..]).unwrap();
    assert!(matches!(store.load(wrong), Err(StateStoreError::Conflict)));
}

#[test]
fn replay_consumption_rejects_foreign_organizations_and_database_failure() {
    let directory = support::temp_dir("trust-replay-fail-closed");
    let line = line();
    let db = database(directory.path());
    let anchor = decode_trust_anchor(line.exact_anchor_bytes()).unwrap();
    let mut key = state_key();
    key.organization_id = ea_types::OrganizationId::try_from(&[0x55; 16][..]).unwrap();
    let mut foreign = OperatorTrustStateStore::open(
        Arc::clone(&db),
        key,
        anchor.chain_id(),
        anchor.trust_anchor_hash(),
        UnixMillis::new(100),
    )
    .unwrap();
    let proof = authorization(0x51, 0x61);
    assert_eq!(
        foreign.admin_authorization_consumed(&proof.replay_keys()[0]),
        Err(StateStoreError::Conflict)
    );
    let mut store = open(Arc::clone(&db), &line);
    db.execute("DROP TABLE operator_admin_replay", &[]).unwrap();
    assert_eq!(
        store.admin_authorization_consumed(&proof.replay_keys()[0]),
        Err(StateStoreError::Unavailable)
    );
    db.execute("DELETE FROM operator_trust_state", &[]).unwrap();
    assert!(matches!(
        store.load(state_key()),
        Err(StateStoreError::Unavailable)
    ));
}

#[test]
fn malformed_persisted_records_fail_closed_on_load_and_reopen() {
    for (sql, error) in [
        (
            "UPDATE operator_trust_state SET revision=X'00'",
            StateStoreError::Unavailable,
        ),
        (
            "UPDATE operator_trust_state SET pin_version=X'0000000000000001'",
            StateStoreError::Unavailable,
        ),
        (
            "UPDATE operator_trust_state SET independent_time_ms=0",
            StateStoreError::Unavailable,
        ),
        (
            "UPDATE operator_trust_state SET independent_kind=3,independent_time_ms=100,independent_hash=zeroblob(32)",
            StateStoreError::Unavailable,
        ),
        (
            "UPDATE operator_trust_state SET independent_kind=0,independent_time_ms=101,independent_hash=zeroblob(32)",
            StateStoreError::MonotonicityViolation,
        ),
        (
            "UPDATE operator_trust_state SET independent_kind=0,independent_time_ms=100,independent_hash=X'00'",
            StateStoreError::Unavailable,
        ),
        (
            "UPDATE operator_trust_state SET pin_version=X'0000000000000001',pin_hash=X'00'",
            StateStoreError::Unavailable,
        ),
    ] {
        let directory = support::temp_dir("trust-corrupt");
        let db = database(directory.path());
        let line = line();
        let mut store = open(Arc::clone(&db), &line);
        db.execute("PRAGMA ignore_check_constraints=ON", &[])
            .unwrap();
        db.execute(sql, &[]).unwrap();
        assert!(
            matches!(store.load(state_key()), Err(actual) if actual == error),
            "{sql}"
        );
        let anchor = decode_trust_anchor(line.exact_anchor_bytes()).unwrap();
        assert!(
            matches!(OperatorTrustStateStore::open(Arc::clone(&db), state_key(), anchor.chain_id(), anchor.trust_anchor_hash(), UnixMillis::new(0)), Err(actual) if actual == error),
            "{sql}"
        );
    }
}

#[test]
fn floor_and_pin_regressions_are_rejected_at_the_persistence_boundary() {
    // The observer simulates a durable state that is newer than the commit's
    // contents at the same revision. Only the real adapter decides acceptance.
    for (tag, sql, params) in [
        (
            "floor",
            "UPDATE operator_trust_state SET floor_ms=1001",
            vec![],
        ),
        (
            "pin-version",
            "UPDATE operator_trust_state SET pin_version=?1,pin_hash=?2",
            vec![
                StoreValue::Blob(999_u64.to_be_bytes().to_vec()),
                StoreValue::Blob(vec![0x55; 32]),
            ],
        ),
        (
            "pin-fork",
            "UPDATE operator_trust_state SET pin_version=?1,pin_hash=?2",
            vec![
                StoreValue::Blob(1_u64.to_be_bytes().to_vec()),
                StoreValue::Blob(vec![0x55; 32]),
            ],
        ),
        (
            "reference-loss",
            "UPDATE operator_trust_state SET floor_ms=100,independent_kind=0,independent_hash=?1,independent_time_ms=99",
            vec![StoreValue::Blob(vec![0x55; 32])],
        ),
    ] {
        let directory = support::temp_dir(tag);
        let db = database(directory.path());
        let line = line();
        let mut store = open(Arc::clone(&db), &line);
        let mut called = false;
        let mut hook = |store: &mut OperatorTrustStateStore,
                        key,
                        revision,
                        commit: &RegistrySelectionCommit| {
            called = true;
            db.execute(sql, &params).unwrap();
            store.commit_registry_selection(key, revision, commit)
        };
        assert_eq!(
            select(
                &mut Observe {
                    store: &mut store,
                    selection: &mut hook
                },
                &line
            )
            .unwrap_err()
            .code(),
            "EA-TRUST-STATE-MONOTONICITY",
            "{tag}"
        );
        assert!(called);
        assert_eq!(store.load(state_key()).unwrap().revision(), 0);
    }
}

#[test]
fn revisions_support_full_u64_and_exhaustion_does_not_wrap() {
    let directory = support::temp_dir("trust-revision-range");
    let db = database(directory.path());
    let line = line();
    let mut store = open(Arc::clone(&db), &line);
    for revision in [u64::MAX - 1, u64::MAX] {
        db.execute(
            "UPDATE operator_trust_state SET revision=?1",
            &[StoreValue::Blob(revision.to_be_bytes().to_vec())],
        )
        .unwrap();
        let outcome = select(&mut store, &line);
        if revision == u64::MAX {
            assert_eq!(outcome.unwrap_err().code(), "EA-TRUST-STATE-MONOTONICITY");
        } else {
            outcome.unwrap();
        }
        assert_eq!(store.load(state_key()).unwrap().revision(), u64::MAX);
    }
}

fn receipt(
    line: &RegistryLineBuilder,
    candidate: &RegistryCandidate,
    time: i64,
) -> VerifiedSignedTime {
    let authority = line.heads()[1];
    let core = ReceiptCoreV1::new(ReceiptCoreFieldsV1 {
        organization_id: trust_support::organization(),
        chain_id: decode_trust_anchor(line.exact_anchor_bytes())
            .unwrap()
            .chain_id(),
        chain_sequence: authority.effective_from,
        entry_hash: EntryHash::from(trust_support::hash32(0x61)),
        entry_object_hash: trust_support::object_hash_marker(0x62),
        previous_entry_hash: Some(EntryHash::from(trust_support::hash32(0x60))),
        registry_version: authority.version,
        registry_head_hash: Hash32::try_from(authority.object_hash.as_bytes().as_slice()).unwrap(),
        policy_object_hash: line.current_policy_hash().unwrap(),
        initial_grant_plan_hash: trust_support::hash32(0x64),
        initial_grant_object_hashes: vec![trust_support::object_hash_marker(0x65)],
        accepted_at_server: UnixMillis::new(time),
        evidence_due_at: None,
        server_key_thumbprint: trust_support::authorized_device_signing_key_thumbprint(),
        server_certificate_hash: CertificateHash::from(authority.direct_object_hash.unwrap()),
    })
    .unwrap();
    let signature = trust_support::authorized_device_signer()
        .sign_receipt(core.exact_bytes())
        .unwrap();
    let bytes = encode_receipt(&ReceiptV1::new(core, signature).unwrap()).unwrap();
    let ParsedArchiveObject::Receipt(receipt) = decode_exact_object(bytes.as_bytes()).unwrap()
    else {
        panic!("receipt")
    };
    verify_receipt_time(candidate.preexisting_authority().unwrap(), &receipt).unwrap()
}

fn time_line(store: &mut OperatorTrustStateStore) -> RegistryLineBuilder {
    let mut line = line();
    select(store, &line).unwrap();
    line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::ServerReceipt,
            marker: 0x44,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    select(store, &line).unwrap();
    line
}

fn advance_time(store: &mut dyn TrustStateStore, line: &RegistryLineBuilder, time: i64) {
    let candidate = candidate_for(store, line);
    let source = receipt(line, &candidate, time);
    // Independent time persists before registry selection; dropping this block
    // must not discard it or change the current pin.
    drop(prepare_local_time(store, &candidate, UnixMillis::new(time), &[source]).unwrap());
}

#[test]
fn independently_verified_time_and_reference_survive_restart_without_changing_the_pin() {
    let directory = support::temp_dir("trust-time-restart");
    let line = {
        let mut store = open(database(directory.path()), &line());
        let line = time_line(&mut store);
        advance_time(&mut store, &line, 900);
        line
    };
    let mut store = open(database(directory.path()), &line);
    let record = store.load(state_key()).unwrap();
    assert_eq!(record.revision(), 3);
    assert_eq!(record.trusted_time().floor().get(), 900);
    assert_eq!(
        record
            .trusted_time()
            .independent_reference()
            .unwrap()
            .verified_time()
            .get(),
        900
    );
    assert!(record.pinned_head().unwrap().registry_head_hash() == line.heads()[1].object_hash);
    advance_time(&mut store, &line, 800);
    assert_eq!(store.load(state_key()).unwrap().revision(), 3);
}

#[test]
fn independent_time_cas_checks_preference_order_and_preserves_the_pin() {
    // Compare real Receipt commits against independently manipulated durable
    // records: equal timestamps must still honor source-kind/hash preference.
    for (kind, reference_time, hash, accepted) in [
        (0, 901, vec![0xff; 32], false),
        (0, 900, vec![0; 32], false),
        (0, 900, vec![0xff; 32], true),
        (1, 900, vec![0; 32], true),
        (2, 900, vec![0; 32], true),
        (0, 899, vec![0; 32], true),
    ] {
        let directory = support::temp_dir("trust-time-order");
        let db = database(directory.path());
        let mut store = open(Arc::clone(&db), &line());
        let line = time_line(&mut store);
        db.execute("UPDATE operator_trust_state SET floor_ms=1000", &[])
            .unwrap();
        let mut called = false;
        let mut hook = |store: &mut OperatorTrustStateStore,
                        key,
                        revision,
                        commit: &IndependentTimeCommit| {
            called = true;
            db.execute("UPDATE operator_trust_state SET independent_kind=?1,independent_time_ms=?2,independent_hash=?3",
                &[StoreValue::Integer(kind), StoreValue::Integer(reference_time), StoreValue::Blob(hash.clone())]).unwrap();
            let result = store.commit_independent_time(key, revision, commit);
            if accepted {
                let record = result.as_ref().map_err(|error| error.code()).unwrap();
                assert!(
                    record.pinned_head().unwrap().registry_head_hash()
                        == line.heads()[1].object_hash
                );
                let mut other = open(database(directory.path()), &line);
                assert!(matches!(
                    other.commit_independent_time(key, revision, commit),
                    Err(StateStoreError::Conflict)
                ));
            } else {
                assert!(matches!(
                    result,
                    Err(StateStoreError::MonotonicityViolation)
                ));
                assert_eq!(store.load(key).unwrap().revision(), revision);
            }
            result
        };
        let mut observed = ObserveTime {
            store: &mut store,
            time: &mut hook,
        };
        let candidate = candidate_for(&mut observed, &line);
        let source = receipt(&line, &candidate, 900);
        let result =
            prepare_local_time(&mut observed, &candidate, UnixMillis::new(1_000), &[source]);
        assert_eq!(result.is_ok(), accepted);
        drop(result);
        assert!(called);
    }
}

fn release_bytes(
    line: &RegistryLineBuilder,
    candidate: &RegistryCandidate,
    state: &TrustedTimeState,
) -> Vec<u8> {
    let reference = state.independent_reference().unwrap();
    let core = encode_local_audit_core(&LocalAuditEventCoreFieldsV1 {
        event_id: EventId::try_from(&[0x33; 16][..]).unwrap(),
        organization_id: trust_support::organization(),
        device_id: state_key().device_id,
        operator_binding_object_hash: Some(line.second_bootstrap_admin_binding_hash()),
        signer_certificate_object_hash: line.second_bootstrap_admin_hash(),
        action: LocalAuditActionV1::ClockSkewRelease(ClockReleaseContextV1::new(
            state.floor(),
            UnixMillis::new(1_000),
            37,
            candidate.registry_version(),
            candidate.registry_head_hash(),
            line.current_policy_hash().unwrap(),
            IndependentTimeReferenceV1::new(
                IndependentTimeKindV1::Receipt,
                reference.object_hash(),
                reference.verified_time(),
            ),
            ClockReleaseJustificationV1::PlatformTimeSourceRecovery,
            UnixMillis::new(990),
            UnixMillis::new(1_010),
        )),
        outcome: LocalAuditOutcomeV1::Accepted,
        effective_now: UnixMillis::new(1_000),
        nonce: [0x87; 32],
    })
    .unwrap();
    let signature = CoseSigner::from_secret(SecretBytes::new(
        trust_support::second_admin_signing_secret(),
    ))
    .sign_local_audit(&core)
    .unwrap();
    encode_local_audit_event(&core, &signature).unwrap()
}

#[test]
fn clock_replay_and_selection_commit_together_and_failed_sql_rolls_both_back() {
    let directory = support::temp_dir("trust-clock-replay");
    let mut line = RegistryLineBuilder::new();
    line.push(
        policy(),
        HeadOptions {
            policy_max_future_clock_skew_ms_override: Some(37),
            not_after: UnixMillis::new(200_000),
            ..HeadOptions::default()
        },
    );
    let db = database(directory.path());
    let mut store = open(Arc::clone(&db), &line);
    select(&mut store, &line).unwrap();
    line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::ServerReceipt,
            marker: 0x44,
            effective_from: None,
        },
        HeadOptions {
            not_after: UnixMillis::new(200_000),
            ..HeadOptions::default()
        },
    );
    select(&mut store, &line).unwrap();
    advance_time(&mut store, &line, 900);
    db.execute("CREATE TRIGGER reject_selection BEFORE UPDATE ON operator_trust_state BEGIN SELECT RAISE(ABORT, 'injected failure'); END", &[]).unwrap();
    let mut hook = |store: &mut OperatorTrustStateStore,
                    key,
                    revision,
                    commit: &RegistrySelectionCommit| {
        let replay = commit.replay_key().unwrap();
        assert_eq!(store.clock_release_consumed(replay), Ok(false));
        assert!(matches!(
            store.commit_registry_selection(key, revision + 1, commit),
            Err(StateStoreError::Conflict)
        ));
        db.execute("CREATE TRIGGER reject_clock_replay BEFORE INSERT ON operator_clock_release_replay BEGIN SELECT RAISE(ABORT, 'injected failure'); END", &[]).unwrap();
        assert!(matches!(
            store.commit_registry_selection(key, revision, commit),
            Err(StateStoreError::Unavailable)
        ));
        assert_eq!(store.load(key).unwrap().revision(), revision);
        assert_eq!(store.clock_release_consumed(replay), Ok(false));
        db.execute("DROP TRIGGER reject_clock_replay", &[]).unwrap();
        assert!(matches!(
            store.commit_registry_selection(key, revision, commit),
            Err(StateStoreError::Unavailable)
        ));
        assert_eq!(store.clock_release_consumed(replay), Ok(false));
        assert_eq!(store.load(key).unwrap().revision(), revision);
        db.execute("DROP TRIGGER reject_selection", &[]).unwrap();
        let record = store.commit_registry_selection(key, revision, commit)?;
        // A second independent connection sees both the committed row and replay.
        let mut reopened = open(database(directory.path()), &line);
        assert_eq!(reopened.clock_release_consumed(replay), Ok(true));
        assert_eq!(reopened.load(key).unwrap().revision(), revision + 1);
        assert!(matches!(
            reopened.commit_registry_selection(key, revision + 1, commit),
            Err(StateStoreError::ReplayAlreadyConsumed)
        ));
        Ok(record)
    };
    let mut observed = Observe {
        store: &mut store,
        selection: &mut hook,
    };
    let candidate = candidate_for(&mut observed, &line);
    let state = observed.load(state_key()).unwrap();
    let audit = release_bytes(&line, &candidate, state.trusted_time());
    let mut time =
        prepare_local_time(&mut observed, &candidate, UnixMillis::new(1_000), &[]).unwrap();
    let release = verify_clock_release(&candidate, &mut time, &audit).unwrap();
    select_registry_head(candidate, time, Some(release)).unwrap();
    drop(store);
    drop(db);
    let mut store = open(database(directory.path()), &line);
    let candidate = candidate_for(&mut store, &line);
    let mut time = prepare_local_time(&mut store, &candidate, UnixMillis::new(1_000), &[]).unwrap();
    assert_eq!(
        verify_clock_release(&candidate, &mut time, &audit)
            .err()
            .unwrap()
            .code(),
        "EA-TRUST-CLOCK-RELEASE-REPLAY"
    );
}
