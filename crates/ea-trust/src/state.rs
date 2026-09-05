use core::fmt;

use ea_format::{ClockReleaseAuditV1, OrganizationAdminAuthorizationFieldsV1};
use ea_time::TrustedTimeState;
use ea_types::{AuthorizationId, DeviceId, ObjectHash, OrganizationId, RegistryVersion};

use crate::TrustError;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TrustStateKey {
    pub organization_id: OrganizationId,
    pub device_id: DeviceId,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RegistryHeadPin {
    registry_version: RegistryVersion,
    registry_head_hash: ObjectHash,
}

impl RegistryHeadPin {
    #[must_use]
    pub const fn new(registry_version: RegistryVersion, registry_head_hash: ObjectHash) -> Self {
        Self {
            registry_version,
            registry_head_hash,
        }
    }

    #[must_use]
    pub const fn registry_version(&self) -> RegistryVersion {
        self.registry_version
    }

    #[must_use]
    pub const fn registry_head_hash(&self) -> ObjectHash {
        self.registry_head_hash
    }
}

pub struct PersistedTrustRecord {
    revision: u64,
    trusted_time: TrustedTimeState,
    pinned_head: Option<RegistryHeadPin>,
}

impl PersistedTrustRecord {
    #[must_use]
    pub const fn new(
        revision: u64,
        trusted_time: TrustedTimeState,
        pinned_head: Option<RegistryHeadPin>,
    ) -> Self {
        Self {
            revision,
            trusted_time,
            pinned_head,
        }
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn trusted_time(&self) -> &TrustedTimeState {
        &self.trusted_time
    }

    #[must_use]
    pub const fn pinned_head(&self) -> Option<&RegistryHeadPin> {
        self.pinned_head.as_ref()
    }
}

pub struct TrustStateSnapshot {
    key: TrustStateKey,
    record: PersistedTrustRecord,
}

impl TrustStateSnapshot {
    #[must_use]
    pub const fn key(&self) -> TrustStateKey {
        self.key
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.record.revision()
    }

    #[must_use]
    pub const fn trusted_time(&self) -> &TrustedTimeState {
        self.record.trusted_time()
    }

    #[must_use]
    pub const fn pinned_head(&self) -> Option<&RegistryHeadPin> {
        self.record.pinned_head()
    }
}

pub struct ClockReleaseReplayKey {
    organization_id: OrganizationId,
    target_device_id: DeviceId,
    nonce: [u8; 32],
}

impl ClockReleaseReplayKey {
    pub(crate) fn from_verified_audit(audit: &ClockReleaseAuditV1) -> Self {
        Self {
            organization_id: audit.organization_id(),
            target_device_id: audit.target_device_id(),
            nonce: *audit.nonce(),
        }
    }

    #[must_use]
    pub const fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }

    #[must_use]
    pub const fn target_device_id(&self) -> DeviceId {
        self.target_device_id
    }

    #[must_use]
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }
}

/// Die Dimension, in der ein Wert organisationsweit EINMAL nutzbar ist.
///
/// `design.md` §16.3 sagt „UUID **und** Nonce sind organisationsweit einmal
/// nutzbar" — zwei Aussagen, nicht eine. Ein Tripel aus beiden waere schwaecher
/// als das prozesslokale `AdminAuthorizationReplay`, das seit Stufe 1 zwei
/// getrennte Mengen fuehrt: zwei Autorisierungen mit derselben Nonce und
/// verschiedener `authorizationId` haetten verschiedene Tripel und kaemen beide
/// durch.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum AdminAuthorizationReplayDimension {
    AuthorizationId(AuthorizationId),
    Nonce([u8; 32]),
}

/// EINE organisationsweite, laufuebergreifende Sperrzeile einer
/// Administrationsautorisierung.
///
/// Eine Autorisierung liefert deren ZWEI — je eine Dimension. Der Schluessel
/// traegt die Dimension mit, weil eine Ablage sie unterscheiden muss: die
/// reservierte Tabelle `replay_nonces` (`0001_initial.sql:304-316`) hat den
/// Primaerschluessel `(organization_id, nonce)` und nimmt nur die
/// Nonce-Dimension auf; die `authorizationId`-Dimension braucht ihren eigenen
/// Geltungsbereich. Ein Speicher, der die Dimension wegwirft, verwechselt eine
/// 16-Byte-Kennung mit einer 32-Byte-Nonce.
///
/// Wie [`ClockReleaseReplayKey`] ist er NACHWEISEND und nicht frei baubar. Er
/// entsteht ausschliesslich in der geprueften Autorisierung und kommt ueber
/// [`VerifiedAdminAuthorization::replay_keys`](crate::VerifiedAdminAuthorization::replay_keys)
/// heraus. Ein Aufrufer, der ihn selbst zusammensetzen koennte, koennte eine
/// fremde Autorisierung als verbraucht markieren.
pub struct AdminAuthorizationReplayKey {
    organization_id: OrganizationId,
    dimension: AdminAuthorizationReplayDimension,
}

impl AdminAuthorizationReplayKey {
    /// Die BEIDEN Sperrzeilen einer geprueften Autorisierung.
    ///
    /// Die Reihenfolge ist festgelegt und bedeutsam: die `authorizationId`
    /// zuerst. Sie ist der Wert, den ein zweiter Versuch DERSELBEN
    /// Autorisierung teilt, also faellt der haeufigste Wiedereinspielversuch
    /// im ersten Zug, bevor irgendein Wert gesetzt wurde.
    pub(crate) const fn pair_from_verified_authorization(
        fields: &OrganizationAdminAuthorizationFieldsV1,
    ) -> [Self; 2] {
        [
            Self {
                organization_id: fields.organization_id,
                dimension: AdminAuthorizationReplayDimension::AuthorizationId(
                    fields.authorization_id,
                ),
            },
            Self {
                organization_id: fields.organization_id,
                dimension: AdminAuthorizationReplayDimension::Nonce(fields.nonce),
            },
        ]
    }

    #[must_use]
    pub const fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }

    #[must_use]
    pub const fn dimension(&self) -> AdminAuthorizationReplayDimension {
        self.dimension
    }
}

pub struct IndependentTimeCommit {
    next_trusted_time: TrustedTimeState,
}

impl IndependentTimeCommit {
    pub(crate) const fn new(next_trusted_time: TrustedTimeState) -> Self {
        Self { next_trusted_time }
    }

    #[must_use]
    pub const fn next_trusted_time(&self) -> &TrustedTimeState {
        &self.next_trusted_time
    }
}

pub struct RegistrySelectionCommit {
    next_trusted_time: TrustedTimeState,
    next_head: RegistryHeadPin,
    replay_key: Option<ClockReleaseReplayKey>,
}

impl RegistrySelectionCommit {
    pub(crate) const fn advance_head(
        next_trusted_time: TrustedTimeState,
        next_head: RegistryHeadPin,
        replay_key: Option<ClockReleaseReplayKey>,
    ) -> Self {
        Self {
            next_trusted_time,
            next_head,
            replay_key,
        }
    }

    pub(crate) const fn compare_and_affirm(
        trusted_time: TrustedTimeState,
        current_head: RegistryHeadPin,
        replay_key: Option<ClockReleaseReplayKey>,
    ) -> Self {
        Self {
            next_trusted_time: trusted_time,
            next_head: current_head,
            replay_key,
        }
    }

    #[must_use]
    pub const fn next_trusted_time(&self) -> &TrustedTimeState {
        &self.next_trusted_time
    }

    #[must_use]
    pub const fn next_head(&self) -> &RegistryHeadPin {
        &self.next_head
    }

    #[must_use]
    pub const fn replay_key(&self) -> Option<&ClockReleaseReplayKey> {
        self.replay_key.as_ref()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum StateStoreError {
    Conflict,
    ReplayAlreadyConsumed,
    MonotonicityViolation,
    Unavailable,
}

impl StateStoreError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Conflict => "EA-TRUST-STATE-CONFLICT",
            Self::ReplayAlreadyConsumed => "EA-TRUST-CLOCK-RELEASE-REPLAY",
            Self::MonotonicityViolation => "EA-TRUST-STATE-MONOTONICITY",
            Self::Unavailable => "EA-TRUST-STATE-UNAVAILABLE",
        }
    }
}

impl fmt::Display for StateStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for StateStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for StateStoreError {}

pub trait TrustStateStore {
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError>;

    fn commit_independent_time(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError>;

    fn clock_release_consumed(
        &mut self,
        key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError>;

    /// Verbraucht EINE Sperrzeile einer Administrationsautorisierung und
    /// meldet, ob sie SCHON verbraucht war.
    ///
    /// Anders als [`Self::clock_release_consumed`] ist dieser Port
    /// SCHREIBEND. Die Uhrfreigabe fragt nur; ihre Sperre wird eine Ebene
    /// hoeher in `commit_registry_selection` gesetzt, das ohnehin schreibt.
    /// Die Administrationsautorisierung hat keinen solchen Commit — sie wird
    /// oberhalb von `ea-trust` verbraucht —, also MUSS das Pruefen und das
    /// Setzen hier in einem Zug geschehen. Ein Speicher, der bloss liest,
    /// laesst zwei gleichzeitige Verbraucher durch; die Umsetzung ist ein
    /// Einfuegen, dessen Primaerschluessel die Sperre IST.
    ///
    /// Der Port ist EINDIMENSIONAL. Die Regel, dass eine Autorisierung ZWEI
    /// Zeilen setzt — `authorizationId` und `nonce` —, liegt in
    /// [`consume_admin_authorization`](crate::consume_admin_authorization) und
    /// damit in `ea-trust`; ein Speicher kann sie nicht vergessen. Die beiden
    /// Zuege sind nicht in EINER Transaktion, und das ist tragbar: jede Zeile
    /// fuer sich ist atomar, und ein Aufrufer, der die erste gewinnt und die
    /// zweite verliert, wird abgewiesen. Es gibt keinen Verlauf, in dem zwei
    /// Verbraucher derselben Nonce beide durchkommen — die Nonce-Zeile ist der
    /// Serialisierungspunkt.
    ///
    /// Die Vorgabe antwortet mit [`StateStoreError::Unavailable`] und NICHT
    /// mit `Ok(false)`. Ein Speicher, der die Sperre nicht fuehrt, weiss
    /// nicht, dass die Autorisierung frisch ist — er darf es also auch nicht
    /// behaupten. Das ist die einzige Vorgabe, die keine stille Luecke oeffnet.
    ///
    /// # Errors
    ///
    /// [`StateStoreError::Unavailable`], solange der Speicher die Sperre nicht
    /// fuehrt, sowie jeden Befund der Ablage.
    fn admin_authorization_consumed(
        &mut self,
        _key: &AdminAuthorizationReplayKey,
    ) -> Result<bool, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }

    fn commit_registry_selection(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError>;
}

pub fn load_trust_state(
    store: &mut dyn TrustStateStore,
    key: TrustStateKey,
) -> Result<TrustStateSnapshot, TrustError> {
    let record = store.load(key).map_err(map_store_error)?;
    if record
        .trusted_time()
        .independent_reference()
        .is_some_and(|reference| reference.verified_time() > record.trusted_time().floor())
    {
        return Err(TrustError::StateMonotonicity);
    }
    Ok(TrustStateSnapshot { key, record })
}

pub(crate) const fn map_store_error(error: StateStoreError) -> TrustError {
    match error {
        StateStoreError::Conflict => TrustError::StateConflict,
        StateStoreError::ReplayAlreadyConsumed => TrustError::ClockReleaseReplay,
        StateStoreError::MonotonicityViolation => TrustError::StateMonotonicity,
        StateStoreError::Unavailable => TrustError::StateUnavailable,
    }
}
