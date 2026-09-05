//! Der oeffentliche, zielgebundene Einstieg und die LAUFUEBERGREIFENDE
//! Einmal-Sperre der Administrationsautorisierung.
//!
//! Die beiden Zusagen haengen zusammen: erst gibt eine oeffentliche Funktion
//! den geprueften Beweiszustand heraus, dann verbraucht ihn ein Speicher, der
//! einen Prozesslauf ueberlebt. Ein Zeuge, der nur ein prozesslokales `BTreeSet`
//! zweimal befragt, bezeugt genau das NICHT.

mod support;

use std::{cell::RefCell, rc::Rc};

use ea_trust::{
    AdminAuthorizationReplayKey, ClockReleaseReplayKey, IndependentTimeCommit,
    PersistedTrustRecord, RegistrySelectionCommit, StateStoreError, TrustError, TrustStateKey,
    TrustStateStore, consume_admin_authorization, verify_authorized_trust_target,
};
use ea_types::{ChainSequence, ObjectHash, UnixMillis};

use support::{ActionSpec, HeadOptions, Pin, RegistryLineBuilder};

/// Eine Zeile, wie sie in einer Tabelle laege. Der Primaerschluessel IST die
/// Sperre — genau wie bei `clock_release_replays`.
type ReplayRow = ([u8; 16], [u8; 16], [u8; 32]);

fn replay_row(key: &AdminAuthorizationReplayKey) -> ReplayRow {
    (
        *key.organization_id().as_bytes(),
        *key.authorization_id().as_bytes(),
        *key.nonce(),
    )
}

/// Der Speicher HINTER dem Speicherwert.
///
/// Er lebt ausserhalb jedes `PersistentStore` — so wie eine Tabelle ausserhalb
/// des Prozesses liegt, der sie beschreibt. Ein zweiter Lauf oeffnet einen
/// NEUEN `PersistentStore` ueber DIESES Backing.
#[derive(Default)]
struct ReplayTable(Vec<ReplayRow>);

struct PersistentStore {
    table: Rc<RefCell<ReplayTable>>,
}

impl PersistentStore {
    fn open(table: &Rc<RefCell<ReplayTable>>) -> Self {
        Self {
            table: Rc::clone(table),
        }
    }
}

impl TrustStateStore for PersistentStore {
    fn load(&mut self, _key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }

    fn commit_independent_time(
        &mut self,
        _key: TrustStateKey,
        _expected_revision: u64,
        _commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }

    fn clock_release_consumed(
        &mut self,
        _key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }

    fn commit_registry_selection(
        &mut self,
        _key: TrustStateKey,
        _expected_revision: u64,
        _commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }

    fn admin_authorization_consumed(
        &mut self,
        key: &AdminAuthorizationReplayKey,
    ) -> Result<bool, StateStoreError> {
        let mut table = self.table.borrow_mut();
        let row = replay_row(key);
        if table.0.contains(&row) {
            return Ok(true);
        }
        table.0.push(row);
        Ok(false)
    }
}

/// Ein Speicher, der die Sperre NICHT fuehrt — der heutige Regelfall unter den
/// Implementierern des Traits.
struct StoreWithoutReplayLock;

impl TrustStateStore for StoreWithoutReplayLock {
    fn load(&mut self, _key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }

    fn commit_independent_time(
        &mut self,
        _key: TrustStateKey,
        _expected_revision: u64,
        _commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }

    fn clock_release_consumed(
        &mut self,
        _key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }

    fn commit_registry_selection(
        &mut self,
        _key: TrustStateKey,
        _expected_revision: u64,
        _commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }
}

fn policy() -> ActionSpec {
    ActionSpec::Policy {
        policy_version: None,
        previous_policy_hash: None,
        effective_from: None,
    }
}

/// Der Bezugspunkt: `HeadOptions::default()` gibt `issued_at = 100`, und
/// `exact_authorization` setzt `expires_at = issued_at + 1_000`.
const USE_TIME: UnixMillis = UnixMillis::new(100);

fn authorized_policy_target() -> (RegistryLineBuilder, ObjectHash, ChainSequence) {
    let mut line = RegistryLineBuilder::new();
    let head = line.push(policy(), HeadOptions::default());
    (
        line,
        head.direct_object_hash
            .expect("a Policy transition carries a direct target"),
        head.effective_from,
    )
}

fn expect_code(error: TrustError, expected_code: &str) {
    assert_eq!(error.code(), expected_code);
    assert_eq!(error.to_string(), expected_code);
    assert_eq!(format!("{error:?}"), expected_code);
}

#[test]
fn the_public_entry_hands_out_the_proof_state_of_an_authorized_target() {
    let (line, target, at_sequence) = authorized_policy_target();
    let trust = line.verified(Pin::None);

    let proof = verify_authorized_trust_target(
        &trust,
        None,
        line.exact_object_bytes(target),
        USE_TIME,
        at_sequence,
    )
    .expect("the Root-signed target and its Admin authorization verify against Registry zero");

    assert!(proof.target_object_hash() == target);
    assert!(proof.authorization_object_hash() != target);
    assert_eq!(proof.previous_registry_version().get(), 0);
}

#[test]
fn an_authorization_is_organization_wide_single_use_across_runs() {
    let table = Rc::new(RefCell::new(ReplayTable::default()));
    let (line, target, at_sequence) = authorized_policy_target();

    {
        // Erster Lauf.
        let trust = line.verified(Pin::None);
        let proof = verify_authorized_trust_target(
            &trust,
            None,
            line.exact_object_bytes(target),
            USE_TIME,
            at_sequence,
        )
        .expect("the first use of the authorization verifies");
        let mut store = PersistentStore::open(&table);
        consume_admin_authorization(&mut store, &proof).expect("the first use consumes the lock");
    }

    // Zweiter Lauf: frischer Pruefzustand, frischer Speicherwert, DASSELBE
    // Backing. Die Pruefung selbst gelingt erneut — das prozesslokale Set ist
    // leer —, und genau deshalb muss der Speicher die Sperre tragen.
    let trust = line.verified(Pin::None);
    let replayed = verify_authorized_trust_target(
        &trust,
        None,
        line.exact_object_bytes(target),
        USE_TIME,
        at_sequence,
    )
    .expect("a fresh verification run cannot see the earlier process-local set");
    let mut store = PersistentStore::open(&table);
    let error = consume_admin_authorization(&mut store, &replayed)
        .expect_err("the persistent lock must refuse the second use");
    expect_code(error, "EA-TRUST-AUTH-REPLAY");
}

#[test]
fn a_store_without_the_replay_lock_fails_closed() {
    let (line, target, at_sequence) = authorized_policy_target();
    let trust = line.verified(Pin::None);
    let proof = verify_authorized_trust_target(
        &trust,
        None,
        line.exact_object_bytes(target),
        USE_TIME,
        at_sequence,
    )
    .expect("the target verifies");

    let mut store = StoreWithoutReplayLock;
    let error = consume_admin_authorization(&mut store, &proof)
        .expect_err("a store that does not carry the lock must not answer 'not consumed'");
    expect_code(error, "EA-TRUST-STATE-UNAVAILABLE");
}

#[test]
fn a_target_outside_the_catalogue_is_refused() {
    let (line, target, at_sequence) = authorized_policy_target();
    let trust = line.verified(Pin::None);
    let mut stranger = line.exact_object_bytes(target).to_vec();
    let last = stranger.len() - 1;
    stranger[last] ^= 1;

    let error = verify_authorized_trust_target(&trust, None, &stranger, USE_TIME, at_sequence)
        .err()
        .expect("bytes that no catalogue entry carries prove nothing");
    expect_code(error, "EA-TRUST-SOURCE");
}

#[test]
fn an_authorization_for_another_action_is_refused() {
    let mut line = RegistryLineBuilder::new();
    let head = line.push(
        policy(),
        HeadOptions {
            direct_authorization_action: Some(6),
            ..HeadOptions::default()
        },
    );
    let target = head
        .direct_object_hash
        .expect("a Policy transition carries a direct target");
    let trust = line.verified(Pin::None);

    let error = verify_authorized_trust_target(
        &trust,
        None,
        line.exact_object_bytes(target),
        USE_TIME,
        head.effective_from,
    )
    .err()
    .expect("a Root rotation authorization does not authorize a Policy");
    expect_code(error, "EA-TRUST-ACTION-MISMATCH");
}

#[test]
fn use_before_and_after_the_authorization_window_is_refused() {
    let (line, target, at_sequence) = authorized_policy_target();
    let trust = line.verified(Pin::None);

    let early = verify_authorized_trust_target(
        &trust,
        None,
        line.exact_object_bytes(target),
        UnixMillis::new(99),
        at_sequence,
    )
    .err()
    .expect("an authorization does not act before it was issued");
    expect_code(early, "EA-TRUST-AUTH-NOT-YET-VALID");

    let late = verify_authorized_trust_target(
        &trust,
        None,
        line.exact_object_bytes(target),
        UnixMillis::new(1_101),
        at_sequence,
    )
    .err()
    .expect("an authorization does not act after it expired");
    expect_code(late, "EA-TRUST-AUTH-EXPIRED");
}
