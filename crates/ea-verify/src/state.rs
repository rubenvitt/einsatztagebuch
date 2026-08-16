//! Der Zustandsspeicher EINES Verifikationslaufs — rein im Speicher.
//!
//! Eine Archivverifikation ist LESEND. Sie muss trotzdem einen
//! `ea_trust::TrustStateStore` bedienen, weil die Auswahl eines
//! Registrierungskopfes eine Zustandsuebergangsfunktion ist und nicht anders
//! erreichbar. Der Speicher dieses Moduls erfuellt deshalb den vollen Vertrag
//! — Compare-and-Set, streng monotone Revisionen, Wiedereinspielsperre — und
//! wird nach dem Lauf verworfen. Es bleibt kein persistenter Zustand zurueck.
//!
//! Kein `std::fs`, keine Uhr: der Zeitboden kommt als Parameter.

use ea_time::TrustedTimeState;
use ea_trust::{
    ClockReleaseReplayKey, IndependentTimeCommit, PersistedTrustRecord, RegistryHeadPin,
    RegistrySelectionCommit, StateStoreError, TrustStateKey, TrustStateStore,
};
use ea_types::{DeviceId, Id16, OrganizationId, UnixMillis};

/// Der Zustandsschluessel eines Verifikationslaufs.
///
/// Die Organisation stammt IMMER aus dem Trust Anchor: `ea_trust::verify_trust`
/// weist jeden Stand ab, dessen Organisation nicht die des Ankers ist, und der
/// Anker ist Parameter der Verifikation, nie Bestandsinhalt.
///
/// Die Geraetekennung ist das Nullid: eine lesende Verifikation hat kein
/// schreibendes Geraet, dessen Kennung sie fuehren koennte. Sie ist trotzdem
/// nicht weglassbar, weil `TrustStateKey` beides verlangt — und weil der
/// Speicher nach dem Lauf verworfen wird, kollidiert dieses Nullid mit keinem
/// echten Geraetestand.
#[must_use]
pub fn verification_state_key(organization_id: OrganizationId) -> TrustStateKey {
    TrustStateKey {
        organization_id,
        device_id: DeviceId::from(Id16::ZERO),
    }
}

/// Ein bereits verbrauchter Freigabenachweis.
///
/// `ClockReleaseReplayKey` gibt seine drei Bestandteile einzeln heraus und ist
/// selbst nicht vergleichbar; sie werden deshalb hier kopiert.
#[derive(Clone, Copy, Eq, PartialEq)]
struct ConsumedRelease {
    organization_id: OrganizationId,
    target_device_id: DeviceId,
    nonce: [u8; 32],
}

impl ConsumedRelease {
    fn from_key(key: &ClockReleaseReplayKey) -> Self {
        Self {
            organization_id: key.organization_id(),
            target_device_id: key.target_device_id(),
            nonce: *key.nonce(),
        }
    }
}

/// Der Zustandsspeicher eines Verifikationslaufs.
///
/// Startet aus einem LEEREN Stand: Revision null, kein gepinnter
/// Registrierungskopf, und als Zeitboden genau die uebergebene Uhr. Ein
/// leerer Stand ist die ehrliche Ausgangslage — ein Verifizierer kennt keine
/// Vorgeschichte, die er nicht selbst aus dem Bestand belegt hat.
pub struct EphemeralTrustStateStore {
    key: TrustStateKey,
    revision: u64,
    trusted_time: TrustedTimeState,
    pinned_head: Option<RegistryHeadPin>,
    consumed_releases: Vec<ConsumedRelease>,
}

impl EphemeralTrustStateStore {
    /// Ein leerer Stand ueber `key` mit `floor` als Zeitboden.
    #[must_use]
    pub fn new(key: TrustStateKey, floor: UnixMillis) -> Self {
        Self {
            key,
            revision: 0,
            trusted_time: TrustedTimeState::initial(floor),
            pinned_head: None,
            consumed_releases: Vec::new(),
        }
    }

    /// Der Schluessel, den dieser Speicher bedient. Jeder andere ist Konflikt.
    #[must_use]
    pub const fn key(&self) -> TrustStateKey {
        self.key
    }

    /// Die aktuelle Revision. Waechst mit jedem Commit um genau eins.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Der gegenwaertige Stand als Datensatz.
    fn record(&self) -> PersistedTrustRecord {
        PersistedTrustRecord::new(self.revision, self.trusted_time.clone(), self.pinned_head)
    }

    /// Prueft Schluessel und erwartete Revision — die Compare-and-Set-Haelfte.
    fn check_cas(&self, key: TrustStateKey, expected_revision: u64) -> Result<(), StateStoreError> {
        if key != self.key || expected_revision != self.revision {
            return Err(StateStoreError::Conflict);
        }
        Ok(())
    }

    /// Schreibt den naechsten Stand fort und vergibt die naechste Revision.
    ///
    /// Der Zeitboden darf dabei NIE sinken: ein rueckwaerts laufender Boden
    /// waere genau der Angriff, gegen den `ea-time` den Boden ueberhaupt
    /// fuehrt.
    fn advance(
        &mut self,
        next_trusted_time: &TrustedTimeState,
        next_pinned_head: Option<RegistryHeadPin>,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        if next_trusted_time.floor() < self.trusted_time.floor() {
            return Err(StateStoreError::MonotonicityViolation);
        }
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(StateStoreError::Unavailable)?;
        self.trusted_time = next_trusted_time.clone();
        self.pinned_head = next_pinned_head;
        Ok(self.record())
    }
}

/// Der volle Vertrag aus `crates/ea-trust/src/state.rs`, im Speicher.
impl TrustStateStore for EphemeralTrustStateStore {
    /// Liefert den gegenwaertigen Stand. Ein fremder Schluessel ist Konflikt.
    ///
    /// Bewusst nicht verbrauchend: `verify_trust` laeuft je Eintragssequenz
    /// erneut, und ein Speicher, der nur einmal laedt, waere schon beim
    /// zweiten Eintrag unbrauchbar.
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        self.check_cas(key, self.revision)?;
        Ok(self.record())
    }

    /// Schreibt eine unabhaengige Zeitquelle fort.
    fn commit_independent_time(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        self.check_cas(key, expected_revision)?;
        let pinned_head = self.pinned_head;
        self.advance(commit.next_trusted_time(), pinned_head)
    }

    /// War dieser Freigabenachweis in DIESEM Lauf schon einmal wirksam?
    ///
    /// Der Speicher lebt nur fuer einen Lauf; eine laufuebergreifende Sperre
    /// kann er ehrlicherweise nicht behaupten und behauptet sie nicht.
    fn clock_release_consumed(
        &mut self,
        key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        Ok(self
            .consumed_releases
            .contains(&ConsumedRelease::from_key(key)))
    }

    /// Pinnt den ausgewaehlten Registrierungskopf.
    fn commit_registry_selection(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        self.check_cas(key, expected_revision)?;
        // Die Kopfauswahl darf den Boden heben, aber niemals die unabhaengige
        // Referenz austauschen — die entsteht ausschliesslich aus signierten
        // Zeitquellen ueber `commit_independent_time`.
        if commit.next_trusted_time().independent_reference()
            != self.trusted_time.independent_reference()
        {
            return Err(StateStoreError::MonotonicityViolation);
        }
        let release = commit.replay_key().map(ConsumedRelease::from_key);
        if release
            .as_ref()
            .is_some_and(|candidate| self.consumed_releases.contains(candidate))
        {
            return Err(StateStoreError::ReplayAlreadyConsumed);
        }
        let next_head = *commit.next_head();
        let record = self.advance(commit.next_trusted_time(), Some(next_head))?;
        if let Some(release) = release {
            self.consumed_releases.push(release);
        }
        Ok(record)
    }
}
