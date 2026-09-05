//! Der oeffentliche, zielgebundene Einstieg und die LAUFUEBERGREIFENDE
//! Einmal-Sperre der Administrationsautorisierung.
//!
//! Die beiden Zusagen haengen zusammen: erst gibt eine oeffentliche Funktion
//! den geprueften Beweiszustand heraus, dann verbraucht ihn ein Speicher, der
//! einen Prozesslauf ueberlebt. Ein Zeuge, der nur ein prozesslokales `BTreeSet`
//! zweimal befragt, bezeugt genau das NICHT.

mod support;

use std::{cell::RefCell, rc::Rc};

use ea_format::{TrustPayloadV1, TrustSubtypeV1};
use ea_time::TrustedTimeState;
use ea_trust::{
    AdminAuthorizationReplayDimension, AdminAuthorizationReplayKey, ClockReleaseReplayKey,
    IndependentTimeCommit, PersistedTrustRecord, RegistryHeadPin, RegistrySelectionCommit,
    RegistrySelectionOutcome, SelectedRegistryHead, StateStoreError, TrustError, TrustStateKey,
    TrustStateStore, consume_admin_authorization, consume_admin_authorization_intent,
    prepare_local_time, select_registry_head, verify_authorized_trust_target,
    verify_intended_trust_target, verify_registry_candidate,
};
use ea_types::{ChainSequence, ObjectHash, UnixMillis};

use support::{ActionSpec, HeadOptions, Pin, RegistryLineBuilder};

/// Eine Zeile, wie sie in einer Tabelle laege. Der Primaerschluessel IST die
/// Sperre — genau wie bei `clock_release_replays`. Die Dimension gehoert in den
/// Schluessel: eine `authorizationId` und eine `nonce` sind GETRENNT einmalig.
type ReplayRow = ([u8; 16], u8, Vec<u8>);

fn replay_row(key: &AdminAuthorizationReplayKey) -> ReplayRow {
    let (marker, value) = match key.dimension() {
        AdminAuthorizationReplayDimension::AuthorizationId(id) => (0_u8, id.as_bytes().to_vec()),
        AdminAuthorizationReplayDimension::Nonce(nonce) => (1_u8, nonce.to_vec()),
    };
    (*key.organization_id().as_bytes(), marker, value)
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

/// Ein Speicher, der den Primaerschluesselverstoss als FEHLER meldet statt als
/// `Ok(true)` — die naheliegende Form eines `INSERT … ON CONFLICT`, das den
/// Konflikt hochreicht.
struct StoreReportingConflictAsError;

impl TrustStateStore for StoreReportingConflictAsError {
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
        _key: &AdminAuthorizationReplayKey,
    ) -> Result<bool, StateStoreError> {
        Err(StateStoreError::ReplayAlreadyConsumed)
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
/// Die Sequenz, an der die Bootstrap-Administratoren aktiv sind.
const SEQUENCE: ChainSequence = ChainSequence::new(1);

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

/// Der Zeitpunkt, an dem die Kopfauswahl der Fixture steht: innerhalb von
/// `not_before = 90` und `not_after = 10_000` des ersten Kopfes.
const SELECTION_NOW: UnixMillis = UnixMillis::new(1_000);
/// Eine Sequenz innerhalb von `[effective_from = 1, valid_through = 100]`.
const SELECTION_SEQUENCE: ChainSequence = ChainSequence::new(30);

/// Ein Speicher, der die Kopfauswahl der Fixture traegt — mehr braucht die
/// Auswahl nicht.
struct SelectionStore {
    key: TrustStateKey,
    revision: u64,
    trusted_time: TrustedTimeState,
    pinned_head: RegistryHeadPin,
}

impl TrustStateStore for SelectionStore {
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        if key != self.key {
            return Err(StateStoreError::Conflict);
        }
        Ok(PersistedTrustRecord::new(
            self.revision,
            self.trusted_time.clone(),
            Some(self.pinned_head),
        ))
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
        Ok(false)
    }

    fn commit_registry_selection(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        if key != self.key || expected_revision != self.revision {
            return Err(StateStoreError::Conflict);
        }
        self.revision += 1;
        self.trusted_time = commit.next_trusted_time().clone();
        self.pinned_head = *commit.next_head();
        Ok(PersistedTrustRecord::new(
            self.revision,
            self.trusted_time.clone(),
            Some(self.pinned_head),
        ))
    }
}

/// Waehlt den letzten Kopf der Linie — der Stand, gegen den ein danach
/// vorbereitetes Ziel autorisiert ist.
fn selected_head(line: &RegistryLineBuilder) -> SelectedRegistryHead {
    let index = line.heads().len() - 1;
    let head = line.heads()[index];
    let key = support::state_key();
    let trusted_time = TrustedTimeState::initial(SELECTION_NOW);
    let trust = line.verified_with_record(Pin::Head(index), 17, trusted_time.clone(), key);
    let candidate = verify_registry_candidate(&trust, SELECTION_SEQUENCE)
        .expect("die Fixture muss ihren eigenen Kopf als Kandidaten tragen");
    let mut store = SelectionStore {
        key,
        revision: 17,
        trusted_time,
        pinned_head: RegistryHeadPin::new(head.version, head.object_hash),
    };
    let local_time = prepare_local_time(&mut store, &candidate, SELECTION_NOW, &[])
        .expect("die lokale Zeit der Fixture muss vorbereitbar sein");
    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(candidate, local_time, None).expect("die Auswahl muss gelingen")
    else {
        panic!("die Fixture muss ihren eigenen aktuellen Kopf waehlen");
    };
    selected
}

#[test]
fn the_head_argument_chooses_the_state_the_authorization_is_bound_to() {
    // Das Ziel wird NACH Kopf 1 vorbereitet, seine Autorisierung nennt also
    // Registrierung 1 und den Hash von Kopf 1 — nicht den Bootstrap-Stand.
    let mut line = RegistryLineBuilder::new();
    line.push(policy(), HeadOptions::default());
    let target = line.add_prepared(policy());
    let head = selected_head(&line);
    let trust = line.verified(Pin::None);

    let proof = verify_authorized_trust_target(
        &trust,
        Some(&head),
        line.exact_object_bytes(target),
        USE_TIME,
        SELECTION_SEQUENCE,
    )
    .expect("gegen den gewaehlten Kopf traegt die Autorisierung");
    assert_eq!(proof.previous_registry_version(), head.registry_version());

    // Derselbe Aufruf ohne den Kopf laeuft gegen den Bootstrap-Stand
    // (Registrierung 0) und MUSS scheitern. Ein Einstieg, der `head`
    // ignorierte, gaebe hier dieselbe Antwort wie oben.
    let error = verify_authorized_trust_target(
        &trust,
        None,
        line.exact_object_bytes(target),
        USE_TIME,
        SELECTION_SEQUENCE,
    )
    .err()
    .expect("der Bootstrap-Stand traegt eine an Kopf 1 gebundene Autorisierung nicht");
    expect_code(error, "EA-TRUST-ACTION-MISMATCH");
}

/// Zwei Linien, die sich AUSSCHLIESSLICH in `authorizationId` und `nonce` des
/// direkten Ziels unterscheiden — sonst Byte fuer Byte dieselbe Fixture.
fn line_with_authorization(id: u8, nonce: u8) -> (RegistryLineBuilder, ObjectHash, ChainSequence) {
    let mut line = RegistryLineBuilder::new();
    let head = line.push(
        policy(),
        HeadOptions {
            direct_authorization_id: Some(id),
            direct_nonce: Some(nonce),
            ..HeadOptions::default()
        },
    );
    (
        line,
        head.direct_object_hash
            .expect("a Policy transition carries a direct target"),
        head.effective_from,
    )
}

fn consume_line(table: &Rc<RefCell<ReplayTable>>, id: u8, nonce: u8) -> Result<(), TrustError> {
    let (line, target, at_sequence) = line_with_authorization(id, nonce);
    let trust = line.verified(Pin::None);
    let proof = verify_authorized_trust_target(
        &trust,
        None,
        line.exact_object_bytes(target),
        USE_TIME,
        at_sequence,
    )
    .expect("jede der beiden Autorisierungen ist fuer sich gueltig");
    let mut store = PersistentStore::open(table);
    consume_admin_authorization(&mut store, &proof)
}

#[test]
fn a_reused_nonce_under_a_fresh_authorization_id_is_refused() {
    let table = Rc::new(RefCell::new(ReplayTable::default()));
    consume_line(&table, 0x20, 0x60).expect("die erste Autorisierung verbraucht ihre beiden Werte");

    let error = consume_line(&table, 0x21, 0x60)
        .expect_err("dieselbe Nonce ist organisationsweit ein zweites Mal nicht nutzbar");
    expect_code(error, "EA-TRUST-AUTH-REPLAY");
}

#[test]
fn a_reused_authorization_id_under_a_fresh_nonce_is_refused() {
    let table = Rc::new(RefCell::new(ReplayTable::default()));
    consume_line(&table, 0x20, 0x60).expect("die erste Autorisierung verbraucht ihre beiden Werte");

    let error = consume_line(&table, 0x20, 0x61)
        .expect_err("dieselbe authorizationId ist organisationsweit ein zweites Mal nicht nutzbar");
    expect_code(error, "EA-TRUST-AUTH-REPLAY");
}

#[test]
fn two_authorizations_sharing_neither_value_both_pass() {
    let table = Rc::new(RefCell::new(ReplayTable::default()));
    consume_line(&table, 0x20, 0x60).expect("die erste Autorisierung verbraucht ihre beiden Werte");
    consume_line(&table, 0x21, 0x61)
        .expect("eine Autorisierung, die keinen Wert teilt, ist unberuehrt");
}

#[test]
fn a_store_that_reports_the_conflict_as_an_error_still_says_auth_replay() {
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

    let mut store = StoreReportingConflictAsError;
    let error = consume_admin_authorization(&mut store, &proof)
        .expect_err("ein Primaerschluesselverstoss ist eine Wiedereinspielung");
    // NICHT `EA-TRUST-CLOCK-RELEASE-REPLAY`: das waere die falsche Familie.
    expect_code(error, "EA-TRUST-AUTH-REPLAY");
}

// ---------------------------------------------------------------------------
// Die Spiegelhaelfte: die Zeit VOR der Wurzelsignatur.
// ---------------------------------------------------------------------------

/// Eine Autorisierung im Katalog, ein Ziel, das es noch nicht gibt.
fn intended_policy_target() -> (RegistryLineBuilder, TrustPayloadV1) {
    let mut line = RegistryLineBuilder::new();
    let (_, payload) = line.prepare_unsigned(policy(), HeadOptions::default());
    (line, payload)
}

#[test]
fn an_intended_target_verifies_before_it_is_signed_or_published() {
    let (line, payload) = intended_policy_target();
    let trust = line.verified(Pin::None);

    // Der Beleg, dass das Ziel WIRKLICH noch nicht existiert: die
    // Laufzeitrichtung findet zu diesen exakten Nutzlastbytes kein
    // Katalogobjekt.
    let runtime =
        verify_authorized_trust_target(&trust, None, payload.exact_payload(), USE_TIME, SEQUENCE)
            .err()
            .expect("ein unveroeffentlichtes Ziel ist kein Katalogobjekt");
    expect_code(runtime, "EA-TRUST-SOURCE");

    let intent = verify_intended_trust_target(&trust, None, &payload, USE_TIME, SEQUENCE)
        .expect("die Autorisierung deckt das beabsichtigte Ziel, auch ohne dessen Signatur");
    assert!(intent.target_trust_subtype() == payload.subtype());
    assert_eq!(intent.previous_registry_version().get(), 0);
}

#[test]
fn an_intended_target_of_another_object_kind_is_refused() {
    // Die Autorisierung sagt, sie decke eine WURZELURKUNDE; die beabsichtigte
    // Nutzlast ist eine Policy. Der `authorizedTrustCoreHash` wird ueber
    // `[targetTrustSubtype, authorizedTrustCore]` gebildet, ein anderer Subtyp
    // ist also ein anderer Kern.
    let mut line = RegistryLineBuilder::new();
    let (_, payload) = line.prepare_unsigned(
        policy(),
        HeadOptions {
            direct_authorization_subtype: Some(TrustSubtypeV1::RootCertificate),
            ..HeadOptions::default()
        },
    );
    let trust = line.verified(Pin::None);

    let error = verify_intended_trust_target(&trust, None, &payload, USE_TIME, SEQUENCE)
        .err()
        .expect("a payload that its authorization does not cover proves nothing");
    expect_code(error, "EA-TRUST-ACTION-MISMATCH");
}

#[test]
fn an_intended_target_for_another_action_is_refused() {
    let mut line = RegistryLineBuilder::new();
    let (_, payload) = line.prepare_unsigned(
        policy(),
        HeadOptions {
            direct_authorization_action: Some(6),
            ..HeadOptions::default()
        },
    );
    let trust = line.verified(Pin::None);

    let error = verify_intended_trust_target(&trust, None, &payload, USE_TIME, SEQUENCE)
        .err()
        .expect("a Root rotation authorization does not authorize a Policy");
    expect_code(error, "EA-TRUST-ACTION-MISMATCH");
}

#[test]
fn an_intended_target_outside_the_authorization_window_is_refused() {
    let (line, payload) = intended_policy_target();
    let trust = line.verified(Pin::None);

    let early = verify_intended_trust_target(&trust, None, &payload, UnixMillis::new(99), SEQUENCE)
        .err()
        .expect("an authorization does not act before it was issued");
    expect_code(early, "EA-TRUST-AUTH-NOT-YET-VALID");

    let late =
        verify_intended_trust_target(&trust, None, &payload, UnixMillis::new(1_101), SEQUENCE)
            .err()
            .expect("an authorization does not act after it expired");
    expect_code(late, "EA-TRUST-AUTH-EXPIRED");
}

#[test]
fn an_intent_carries_the_same_two_replay_dimensions_as_a_published_target() {
    let table = Rc::new(RefCell::new(ReplayTable::default()));
    let (line, payload) = intended_policy_target();
    let trust = line.verified(Pin::None);
    let intent = verify_intended_trust_target(&trust, None, &payload, USE_TIME, SEQUENCE)
        .expect("die Absicht traegt");

    let mut store = PersistentStore::open(&table);
    consume_admin_authorization_intent(&mut store, &intent).expect("der erste Verbrauch gelingt");

    // Zweiter Lauf, frischer Pruefzustand, dasselbe Backing.
    let trust = line.verified(Pin::None);
    let replayed = verify_intended_trust_target(&trust, None, &payload, USE_TIME, SEQUENCE)
        .expect("die Pruefung selbst sieht die fruehere Nutzung nicht");
    let mut store = PersistentStore::open(&table);
    let error = consume_admin_authorization_intent(&mut store, &replayed)
        .expect_err("die persistente Sperre weist die zweite Nutzung ab");
    expect_code(error, "EA-TRUST-AUTH-REPLAY");
}
