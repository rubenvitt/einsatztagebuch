//! Native local storage admission. Paths are not authority or evidence.
use crate::operator_runtime::{
    OperatorArchiveSnapshot, OperatorRuntime, OperatorRuntimeError,
    writer::InteractiveOperatorRuntime,
};
use ea_archive::{
    ArchiveBackend, ArchiveBackendError, ArchiveBackendProfileV1, ArchiveBlob, ArchiveError,
    ArchiveSource, BoundArchiveProfilePolicyV1, WriterLock,
};
use ea_archive_fs::{
    CapabilityTestVectorV1, ControlledNetworkBackend, ControlledNetworkLocalComponentV1,
    LocalCommitComponentV1, LocalPathBackend, SqlcipherArchiveBackend, SqliteCommitStore,
};
use ea_audit::{AuditActorProof, SqliteLocalAuditRepository, TypedLocalAuditEvent};
use ea_destruction::ObservedArchiveHoldingV1;
use ea_format::{
    ArchiveProfileMigrationContextV1, LocalAuditActionV1, LocalAuditOutcomeV1, OperatorRoleV1,
};
use ea_local_store::{EncryptedDatabase, StoreError, StoreTransaction, StoreValue};
use ea_operator::ReauthPurpose;
use ea_recovery::FsArchiveSource;
use ea_types::Hash32;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone)]
pub struct NativeArchiveConfig {
    pub profile: ArchiveBackendProfileV1,
    pub local_commit_database_path: Option<PathBuf>,
}
impl NativeArchiveConfig {
    /// Die Aufruferform: ein Netzprofil bindet die lokale Komponente in der
    /// eigenen Datenbank der Laufzeit, LocalPath trägt keinen Datenbankpfad.
    #[must_use]
    pub fn for_runtime_database(profile: ArchiveBackendProfileV1, database_path: &Path) -> Self {
        let local_commit_database_path =
            matches!(profile, ArchiveBackendProfileV1::ControlledNetworkPath(_))
                .then(|| database_path.to_owned());
        Self {
            profile,
            local_commit_database_path,
        }
    }
}

/// Errors retain the authority/backend boundary without disclosing host paths.
#[derive(Debug)]
pub enum NativeArchiveOpenError {
    Config,
    Runtime(OperatorRuntimeError),
    Backend(ArchiveBackendError),
    /// Registrierung durch eine andere Rolle als `OrganizationAdmin` oder
    /// `Writer` oder durch eine Authority-Konfiguration (EA-CNA-REG-1).
    Role,
    /// Abweichende vorhandene Registrierung oder Scope-Zeile (EA-CNA-REG-6).
    RegistrationConflict,
    /// Der Profilzeiger im Netzziel nennt ein anderes Profil (EA-CNA-REG-2(g)).
    PointerConflict,
    /// LocalPath-Konfiguration trotz Registrierung (EA-CNA-REG-10).
    ProfileMismatch,
    /// Auditzeile nicht vorbereitbar oder nicht schreibbar (EA-CNA-REG-4).
    Audit,
    /// Der Capability-Test des Netzziels belegt nicht alle Zusagen.
    Capability,
}
impl NativeArchiveOpenError {
    /// Stabiler Fehlercode ohne Hostpfad, Schlüssel oder Klartext.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Config => "EA-NATIVE-ARCHIVE-CONFIG",
            Self::Runtime(error) => error.code(),
            Self::Backend(error) => error.code(),
            Self::Role => "EA-NATIVE-ARCHIVE-ROLE",
            Self::RegistrationConflict => "EA-NATIVE-ARCHIVE-REGISTRATION-CONFLICT",
            Self::PointerConflict => "EA-NATIVE-ARCHIVE-POINTER-CONFLICT",
            Self::ProfileMismatch => "EA-NATIVE-ARCHIVE-PROFILE-MISMATCH",
            Self::Audit => "EA-NATIVE-ARCHIVE-AUDIT",
            Self::Capability => "EA-ARCHIVE-HEALTH-FILESYSTEM-SEMANTICS",
        }
    }
}
impl From<OperatorRuntimeError> for NativeArchiveOpenError {
    fn from(error: OperatorRuntimeError) -> Self {
        Self::Runtime(error)
    }
}
impl From<ArchiveBackendError> for NativeArchiveOpenError {
    fn from(error: ArchiveBackendError) -> Self {
        Self::Backend(error)
    }
}
impl From<StoreError> for NativeArchiveOpenError {
    fn from(_: StoreError) -> Self {
        Self::Backend(ArchiveBackendError::Io)
    }
}

/// Ergebnis einer Registrierung (EA-CNA-REG-6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeArchiveRegistrationOutcome {
    /// Scope-, Komponenten- und Auditzeile wurden in einer Transaktion gebucht.
    Registered,
    /// Die identische Zeile bestand schon; ohne Präsenz, Audit und Schreiben.
    AlreadyRegistered,
}

/// Registriert die lokale SQLCipher-Komponente eines Netzprofils einmal je
/// Anker (EA-CNA-REG-1 … REG-8) in der EIGENEN Datenbank der Runtime.
///
/// Registrieren darf eine Current-Runtime mit Rolle `OrganizationAdmin` oder
/// `Writer`: die frische Präsenz ist an die Profilzeile der eigenen Datenbank
/// gebunden, und die Autorität für das Profil liegt in der signierten Policy
/// des verifizierten Heads, nicht in der registrierenden Rolle.
///
/// Alle Vorbedingungen werden lesend und in der Reihenfolge von
/// EA-CNA-REG-2 geprüft, bevor eine frische Präsenz verlangt wird. Scope-,
/// Komponenten- und Auditzeile entstehen in genau einer Transaktion; der
/// aktive Profilzeiger wird höchstens gelesen, nie geschrieben. Danach öffnet
/// die Registrierung die Komponente über denselben Weg wie jeder spätere
/// Verbraucher.
///
/// # Errors
///
/// `Role` für eine andere Rolle oder eine Authority-Konfiguration; `Config` für eine unpassende Form;
/// `Backend` für Policy, fehlende Migrationen oder ein unerreichbares
/// Netzziel; `Capability`, `PointerConflict`, `RegistrationConflict` und
/// `Audit` wie in der Spezifikation; `Runtime` für Autorität und Präsenz.
pub fn register_network_component(
    runtime: &OperatorRuntime,
    config: NativeArchiveConfig,
) -> Result<
    (
        NativeArchiveRegistrationOutcome,
        NativeArchiveExistingComponent,
    ),
    NativeArchiveOpenError,
> {
    // REG-1: Current-Autorität und Rolle vor jeder Prüfung.
    runtime.ensure_current()?;
    require_registering_role(runtime.config().role, runtime.config().authority)?;
    let database = runtime.database();
    // REG-2(a): Netzprofil mit derselben SQLCipher-Datei wie die Runtime.
    let ArchiveBackendProfileV1::ControlledNetworkPath(profile) = &config.profile else {
        return Err(NativeArchiveOpenError::Config);
    };
    let configured_path = config
        .local_commit_database_path
        .as_ref()
        .ok_or(NativeArchiveOpenError::Config)?;
    let actual = std::fs::canonicalize(database.path()).map_err(|_| ArchiveBackendError::Io)?;
    let configured = std::fs::canonicalize(configured_path).map_err(|_| ArchiveBackendError::Io)?;
    if actual != configured {
        return Err(NativeArchiveOpenError::Config);
    }
    // REG-2(b): exakte Profilbytes und Grenzen, die in i64 passen.
    let exact_profile = ea_format::encode_archive_backend_profile_core(&config.profile.core()?)
        .map_err(ArchiveBackendError::Format)?;
    let profile_hash = ea_crypto::archive_profile_digest(&exact_profile);
    let limits = (
        i64::try_from(profile.queue_max_objects).map_err(|_| NativeArchiveOpenError::Config)?,
        i64::try_from(profile.queue_max_bytes).map_err(|_| NativeArchiveOpenError::Config)?,
    );
    if limits.0 <= 0 || limits.1 <= 0 {
        return Err(NativeArchiveOpenError::Config);
    }
    // REG-2(c): die gewählte Policy nennt genau diesen Profilhash.
    let policy = BoundArchiveProfilePolicyV1::from_policy(runtime.head().policy_fields());
    policy.require(profile_hash)?;
    // REG-2(d): Migrationen 16 und 26.
    if !database.has_migration(16)? || !database.has_migration(26)? {
        return Err(ArchiveBackendError::MissingLocalCommitComponent.into());
    }
    // REG-2(e/f): vorhandenes Netzziel ohne Anlegen der Wurzel, alle sieben
    // Capability-Zusagen belegt.
    let remote = LocalPathBackend::open_existing(
        runtime.config().archive_directory.clone(),
        config.profile.clone(),
        &policy,
    )?;
    let measured = remote.run_capability_test(&CapabilityTestVectorV1::new(
        &profile.capability_test_vector_id,
        b"EINSATZARCHIV-NATIVE-CAPABILITY-v1",
    )?)?;
    if !measured.all_proven() {
        return Err(NativeArchiveOpenError::Capability);
    }
    // REG-2(g): ein vorhandener Zeiger muss genau dieses Profil nennen.
    let pointer_hash = match remote.read_active_profile_pointer()? {
        None => Hash32::ZERO,
        Some(pointer) if pointer.active_profile_hash() != profile_hash => {
            return Err(NativeArchiveOpenError::PointerConflict);
        }
        Some(_) => ea_crypto::active_profile_pointer_digest(
            &remote
                .active_profile_pointer_bytes()
                .ok_or(ArchiveBackendError::Io)?,
        ),
    };
    // REG-2(h) und REG-6: nur lesen.
    let anchor = runtime.anchor().trust_anchor_hash();
    let namespace = ea_crypto::native_archive_component_namespace(anchor, profile_hash);
    let registration = Registration {
        anchor,
        profile_hash,
        namespace,
        exact_profile: &exact_profile,
        limits,
    };
    let existing =
        database.transaction::<_, NativeArchiveOpenError>(|tx| registration.existing(tx))?;
    if existing == Existing::Identical {
        let component = NativeArchiveExistingComponent::open_current(runtime, config)?;
        return Ok((
            NativeArchiveRegistrationOutcome::AlreadyRegistered,
            component,
        ));
    }
    // REG-3: frische Präsenz für genau diese Registrierung.
    let session = runtime.reauthenticate_for(ReauthPurpose::ArchiveProfileMigration)?;
    runtime.ensure_current()?;
    // REG-4: gleiche Quell- und Zielhashes kennzeichnen die Erstregistrierung.
    let inventory = ea_format::encode_archive_inventory_list(&remote.inventory()?)
        .map_err(ArchiveBackendError::Format)?;
    let context = ArchiveProfileMigrationContextV1::new(
        profile_hash,
        profile_hash,
        ea_crypto::archive_inventory_digest(&inventory),
        pointer_hash,
    );
    let audit = runtime
        .audit_service()
        .prepare_signed(
            AuditActorProof::OperatorSession(session.proof()),
            TypedLocalAuditEvent {
                action: LocalAuditActionV1::ArchiveProfileMigration(context),
                outcome: LocalAuditOutcomeV1::Accepted,
            },
        )
        .map_err(|_| NativeArchiveOpenError::Audit)?;
    // REG-5: Scope, Komponente und Audit in genau einer Transaktion; nie
    // `SqliteCommitStore::new`, das eine eigene Transaktion öffnete.
    runtime.ensure_current()?;
    database.transaction::<_, NativeArchiveOpenError>(|tx| {
        match registration.existing(tx)? {
            Existing::Absent { scope: false } => {
                tx.execute(
                    "INSERT INTO local_commit_scope(namespace,object_limit,byte_limit) VALUES(?1,?2,?3)",
                    &[
                        StoreValue::Blob(namespace.as_bytes().to_vec()),
                        StoreValue::Integer(limits.0),
                        StoreValue::Integer(limits.1),
                    ],
                )?;
            }
            Existing::Absent { scope: true } => {}
            // Eine zwischenzeitlich entstandene Zeile ist nicht diese Registrierung.
            Existing::Identical => return Err(NativeArchiveOpenError::RegistrationConflict),
        }
        tx.execute(
            "INSERT INTO native_archive_component(anchor_hash,profile_hash,namespace,exact_profile) VALUES(?1,?2,?3,?4)",
            &[
                StoreValue::Blob(anchor.as_bytes().to_vec()),
                StoreValue::Blob(profile_hash.as_bytes().to_vec()),
                StoreValue::Blob(namespace.as_bytes().to_vec()),
                StoreValue::Blob(exact_profile.clone()),
            ],
        )?;
        SqliteLocalAuditRepository::append_prepared_in(tx, &audit)
            .map_err(|_| NativeArchiveOpenError::Audit)
    })?;
    // REG-7: Messung über denselben Weg wie jeder spätere Verbraucher.
    let component = NativeArchiveExistingComponent::open_current(runtime, config)?;
    Ok((NativeArchiveRegistrationOutcome::Registered, component))
}

/// EA-CNA-REG-1: `OrganizationAdmin` oder `Writer` registrieren die eigene
/// Datenbank; jede andere Rolle und jede Authority-Konfiguration nie.
fn require_registering_role(
    role: OperatorRoleV1,
    authority: bool,
) -> Result<(), NativeArchiveOpenError> {
    if !authority
        && matches!(
            role,
            OperatorRoleV1::OrganizationAdmin | OperatorRoleV1::Writer
        )
    {
        Ok(())
    } else {
        Err(NativeArchiveOpenError::Role)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Existing {
    Identical,
    Absent { scope: bool },
}

struct Registration<'a> {
    anchor: Hash32,
    profile_hash: Hash32,
    namespace: Hash32,
    exact_profile: &'a [u8],
    limits: (i64, i64),
}
impl Registration<'_> {
    /// Liest die vorhandenen Zeilen für Anker und Namensraum, ohne zu schreiben.
    fn existing(&self, tx: &StoreTransaction<'_>) -> Result<Existing, NativeArchiveOpenError> {
        if let Some(row) = tx.query_row(
            "SELECT profile_hash,namespace,exact_profile FROM native_archive_component WHERE anchor_hash=?1",
            &[StoreValue::Blob(self.anchor.as_bytes().to_vec())],
        )? {
            if row.blob(0)? == self.profile_hash.as_bytes()
                && row.blob(1)? == self.namespace.as_bytes()
                && row.blob(2)? == self.exact_profile
            {
                return Ok(Existing::Identical);
            }
            return Err(NativeArchiveOpenError::RegistrationConflict);
        }
        match tx.query_row(
            "SELECT object_limit,byte_limit FROM local_commit_scope WHERE namespace=?1",
            &[StoreValue::Blob(self.namespace.as_bytes().to_vec())],
        )? {
            None => Ok(Existing::Absent { scope: false }),
            Some(scope) if (scope.integer(0)?, scope.integer(1)?) == self.limits => {
                Ok(Existing::Absent { scope: true })
            }
            Some(_) => Err(NativeArchiveOpenError::RegistrationConflict),
        }
    }
}

/// Besteht für den Anker eine Registrierung? Ohne Migration 26 gibt es keine.
fn anchor_registered(
    database: &EncryptedDatabase,
    anchor: Hash32,
) -> Result<bool, NativeArchiveOpenError> {
    if !database.has_migration(26)? {
        return Ok(false);
    }
    Ok(database
        .query_row(
            "SELECT 1 FROM native_archive_component WHERE anchor_hash=?1",
            &[StoreValue::Blob(anchor.as_bytes().to_vec())],
        )?
        .is_some())
}

/// EA-CNA-REG-10 für einen Writer, der seinen LocalPath-Bestand selbst
/// öffnet: Trägt der Anker eine Registrierung, wird ein registriertes
/// Netzziel nie als lokaler Pfad beschrieben. Liest nur die eigene
/// Datenbank, vor jeder Dateisystem-I/O am Archivverzeichnis.
///
/// # Errors
///
/// `ProfileMismatch` bei registriertem Anker; `Backend` für Datenbankfehler.
pub fn refuse_local_path_on_registered_anchor(
    runtime: &InteractiveOperatorRuntime,
) -> Result<(), NativeArchiveOpenError> {
    if anchor_registered(runtime.database(), runtime.anchor().trust_anchor_hash())? {
        return Err(NativeArchiveOpenError::ProfileMismatch);
    }
    Ok(())
}

/// Die Registrierung eines Ankers, wie der Start sie braucht (EA-CNA-SRC-1/2):
/// Namensraum und die beiden gepinnten Grenzen der lokalen Komponente.
///
/// Das Profil selbst wird nicht dekodiert. Der Start prüft bewusst keine
/// Policy (EA-CNA-SRC-2); was er braucht, bindet die Zeile über
/// `profile_hash = archive_profile_digest(exact_profile)` und den daraus
/// abgeleiteten Namensraum.
pub(crate) struct RegisteredNetworkComponent {
    pub(crate) namespace: Hash32,
    pub(crate) object_limit: u64,
    pub(crate) byte_limit: u64,
}

/// Liest die Registrierung für `anchor` in einer Transaktion, ohne zu
/// schreiben. Ohne Migration 26 gibt es keine Registrierung.
///
/// # Errors
///
/// `Store` für Datenbankfehler; `Archive`, wenn Profilhash, Namensraum oder
/// Scope-Zeile nicht zueinander passen.
pub(crate) fn registered_component(
    database: &Arc<EncryptedDatabase>,
    anchor: Hash32,
) -> Result<Option<RegisteredNetworkComponent>, OperatorRuntimeError> {
    if !database.has_migration(26)? {
        return Ok(None);
    }
    database.transaction::<_, OperatorRuntimeError>(|tx| {
        let Some(row) = tx.query_row(
            "SELECT profile_hash,namespace,exact_profile FROM native_archive_component WHERE anchor_hash=?1",
            &[StoreValue::Blob(anchor.as_bytes().to_vec())],
        )?
        else {
            return Ok(None);
        };
        let profile_hash = ea_crypto::archive_profile_digest(row.blob(2)?);
        let namespace = ea_crypto::native_archive_component_namespace(anchor, profile_hash);
        if row.blob(0)? != profile_hash.as_bytes() || row.blob(1)? != namespace.as_bytes() {
            return Err(OperatorRuntimeError::Archive);
        }
        let scope = tx
            .query_row(
                "SELECT object_limit,byte_limit FROM local_commit_scope WHERE namespace=?1",
                &[StoreValue::Blob(namespace.as_bytes().to_vec())],
            )?
            .ok_or(OperatorRuntimeError::Archive)?;
        let limit = |value: i64| {
            u64::try_from(value)
                .ok()
                .filter(|n| *n > 0)
                .ok_or(OperatorRuntimeError::Archive)
        };
        Ok(Some(RegisteredNetworkComponent {
            namespace,
            object_limit: limit(scope.integer(0)?)?,
            byte_limit: limit(scope.integer(1)?)?,
        }))
    })
}

/// An existing local storage handle, never an active-profile pointer, complete
/// archive source, signature authority or permission to publish to a target.
/// The measured network carrier remains private: reconnect requires a separate
/// activation-pointer contract which this type deliberately does not provide.
pub struct NativeArchiveExistingComponent {
    storage: ComponentStorage,
    profile: ArchiveBackendProfileV1,
    profile_hash: Hash32,
}

/// Die konkrete lokale Ablage; für ein Netzprofil zusätzlich der zugelassene
/// Träger des Netzziels, der selbst nie aufs Netz zugreift.
enum ComponentStorage {
    Local(LocalPathBackend),
    Network {
        backend: SqlcipherArchiveBackend,
        /// Kanonischer Pfad der eigenen SQLCipher-Datei: Ort der Verwahrung
        /// (EA-CNA-WRT-7).
        database_path: PathBuf,
        _component: ControlledNetworkLocalComponentV1,
    },
}
impl NativeArchiveExistingComponent {
    /// Uses actual Current readiness both before admission and before return.
    pub fn open_current(
        runtime: &OperatorRuntime,
        config: NativeArchiveConfig,
    ) -> Result<Self, NativeArchiveOpenError> {
        runtime.ensure_current()?;
        let opened = Self::open(
            runtime.database(),
            &runtime.config().archive_directory,
            runtime.anchor().trust_anchor_hash(),
            BoundArchiveProfilePolicyV1::from_policy(runtime.head().policy_fields()),
            config,
        )?;
        runtime.ensure_current()?;
        Ok(opened)
    }

    /// Preserves the Interactive runtime's Writer-only stale exception. This
    /// does not convert StaleWriter into general Current/admin authority.
    pub fn open_writer(
        runtime: &InteractiveOperatorRuntime,
        config: NativeArchiveConfig,
    ) -> Result<Self, NativeArchiveOpenError> {
        runtime.ensure_current()?;
        let opened = Self::open(
            runtime.database(),
            &runtime.config().archive_directory,
            runtime.anchor().trust_anchor_hash(),
            BoundArchiveProfilePolicyV1::from_policy(runtime.head().policy_fields()),
            config,
        )?;
        runtime.ensure_current()?;
        Ok(opened)
    }

    /// Only local storage primitives. Each later privileged operation still
    /// needs its own current authority; this handle grants none.
    pub fn local_backend(&self) -> &dyn ArchiveBackend {
        match &self.storage {
            ComponentStorage::Local(backend) => backend,
            ComponentStorage::Network { backend, .. } => backend,
        }
    }
    pub fn profile_hash(&self) -> Hash32 {
        self.profile_hash
    }
    /// Ist dies die lokale Komponente eines kontrollierten Netzprofils?
    #[must_use]
    pub fn is_network(&self) -> bool {
        matches!(self.storage, ComponentStorage::Network { .. })
    }
    /// Das SQLCipher-Backend eines Netzprofils; für LocalPath keines.
    #[must_use]
    pub fn sqlcipher_backend(&self) -> Option<&SqlcipherArchiveBackend> {
        match &self.storage {
            ComponentStorage::Local(_) => None,
            ComponentStorage::Network { backend, .. } => Some(backend),
        }
    }

    /// Misst die Capabilities, die ein Verbraucher vor seinem ersten Dienst
    /// verlangt, und liefert kein Teilergebnis.
    ///
    /// LocalPath: alle sieben Zusagen des Zielverzeichnisses. Netzprofil:
    /// die SQLCipher-Zusagen (EA-CNA-WRT-4) an der eigenen Datenbank und alle
    /// sieben Zusagen des vorhandenen Netzziels, dessen Wurzel nie angelegt
    /// wird.
    ///
    /// # Errors
    ///
    /// `Capability` für eine nicht belegte Zusage; `Backend` für Policy,
    /// Lock-Konkurrenz oder ein unerreichbares Ziel.
    pub fn require_capabilities(
        &self,
        archive_directory: &Path,
        policy: &BoundArchiveProfilePolicyV1,
    ) -> Result<(), NativeArchiveOpenError> {
        let vector = CapabilityTestVectorV1::new(
            match &self.profile {
                ArchiveBackendProfileV1::LocalPath(profile) => &profile.capability_test_vector_id,
                ArchiveBackendProfileV1::ControlledNetworkPath(profile) => {
                    &profile.capability_test_vector_id
                }
            },
            b"EINSATZARCHIV-NATIVE-CAPABILITY-v1",
        )?;
        let proven = match &self.storage {
            ComponentStorage::Local(backend) => backend.run_capability_test(&vector)?.all_proven(),
            ComponentStorage::Network { backend, .. } => {
                backend.run_capability_test()?.all_proven()
                    && LocalPathBackend::open_existing(
                        archive_directory.to_owned(),
                        self.profile.clone(),
                        policy,
                    )?
                    .run_capability_test(&vector)?
                    .all_proven()
            }
        };
        if proven {
            Ok(())
        } else {
            Err(NativeArchiveOpenError::Capability)
        }
    }

    fn open(
        database: &Arc<EncryptedDatabase>,
        archive_directory: &Path,
        anchor: Hash32,
        policy: BoundArchiveProfilePolicyV1,
        config: NativeArchiveConfig,
    ) -> Result<Self, NativeArchiveOpenError> {
        let network = matches!(
            &config.profile,
            ArchiveBackendProfileV1::ControlledNetworkPath(_)
        );
        if network != config.local_commit_database_path.is_some() {
            return Err(NativeArchiveOpenError::Config);
        }
        // EA-CNA-REG-10: ein registriertes Netzziel wird nie als lokaler Pfad
        // umetikettiert. Vor Policy und jeder Dateisystem-I/O, damit auch ein
        // nicht mehr erlaubtes LocalPath-Profil dieselbe Ablehnung erhält.
        if !network && anchor_registered(database, anchor)? {
            return Err(NativeArchiveOpenError::ProfileMismatch);
        }
        let exact_profile = ea_format::encode_archive_backend_profile_core(&config.profile.core()?)
            .map_err(ArchiveBackendError::Format)?;
        let profile_hash = ea_crypto::archive_profile_digest(&exact_profile);
        policy.require(profile_hash)?;
        let ArchiveBackendProfileV1::ControlledNetworkPath(profile) = &config.profile else {
            // Compatible LocalPath behavior: this may materialize local format
            // files after policy admission, as the existing backend does.
            let backend = LocalPathBackend::open(
                archive_directory.to_owned(),
                config.profile.clone(),
                &policy,
            )?;
            return Ok(Self {
                storage: ComponentStorage::Local(backend),
                profile: config.profile,
                profile_hash,
            });
        };
        let configured_path = config
            .local_commit_database_path
            .as_ref()
            .ok_or(NativeArchiveOpenError::Config)?;
        let actual = std::fs::canonicalize(database.path()).map_err(|_| ArchiveBackendError::Io)?;
        let configured =
            std::fs::canonicalize(configured_path).map_err(|_| ArchiveBackendError::Io)?;
        if actual != configured {
            return Err(NativeArchiveOpenError::Config);
        }
        let namespace = ea_crypto::native_archive_component_namespace(anchor, profile_hash);
        let objects = i64::try_from(profile.queue_max_objects)
            .map_err(|_| ArchiveBackendError::MissingLocalCommitComponent)?;
        let bytes = i64::try_from(profile.queue_max_bytes)
            .map_err(|_| ArchiveBackendError::MissingLocalCommitComponent)?;
        // This transaction only reads. Never register a scope/binding or infer
        // first-use authority from absence, even under the stale Writer entry.
        database.transaction::<_, NativeArchiveOpenError>(|tx| {
            let migration = tx.query_row("SELECT count(*) FROM schema_migration WHERE version IN (16,26)", &[])?
                .ok_or(StoreError::Shape)?;
            if migration.integer(0)? != 2 { return Err(ArchiveBackendError::MissingLocalCommitComponent.into()); }
            let row = tx.query_row("SELECT profile_hash,namespace,exact_profile FROM native_archive_component WHERE anchor_hash=?1",
                &[StoreValue::Blob(anchor.as_bytes().to_vec())])?
                .ok_or(ArchiveBackendError::MissingLocalCommitComponent)?;
            if row.blob(0)? != profile_hash.as_bytes() || row.blob(1)? != namespace.as_bytes() || row.blob(2)? != exact_profile {
                return Err(ArchiveBackendError::ByteConflict.into());
            }
            let scope = tx.query_row("SELECT object_limit,byte_limit FROM local_commit_scope WHERE namespace=?1",
                &[StoreValue::Blob(namespace.as_bytes().to_vec())])?
                .ok_or(ArchiveBackendError::MissingLocalCommitComponent)?;
            if scope.integer(0)? != objects || scope.integer(1)? != bytes {
                return Err(ArchiveBackendError::ByteConflict.into());
            }
            Ok(())
        })?;
        let measurement = SqliteCommitStore::open_existing(
            database.clone(),
            namespace,
            profile.queue_max_objects,
            profile.queue_max_bytes,
        )?;
        let store = SqliteCommitStore::open_existing(
            database.clone(),
            namespace,
            profile.queue_max_objects,
            profile.queue_max_bytes,
        )?;
        // Validate the actual backend's durability before measuring at rest.
        let backend = SqlcipherArchiveBackend::open(store)?;
        let component = ControlledNetworkBackend::open_local_component(
            archive_directory.to_owned(),
            Some(LocalCommitComponentV1::new(
                actual.clone(),
                Box::new(measurement),
            )),
            config.profile.clone(),
            &policy,
        )?;
        Ok(Self {
            storage: ComponentStorage::Network {
                backend,
                database_path: actual,
                _component: component,
            },
            profile: config.profile,
            profile_hash,
        })
    }
}

impl ObservedArchiveHoldingV1 for NativeArchiveExistingComponent {
    fn profile_hash(&self) -> Result<Hash32, ArchiveBackendError> {
        Ok(self.profile_hash)
    }
    fn acquire_writer_lock(&self) -> Result<WriterLock, ArchiveBackendError> {
        self.local_backend().acquire_writer_lock()
    }
    /// LocalPath: die kanonische Wurzel wie bisher; Netzprofil: der
    /// kanonische Datenbankpfad der lokalen Komponente, nie das Netzziel.
    fn canonical_location(&self) -> Result<PathBuf, ArchiveBackendError> {
        match &self.storage {
            ComponentStorage::Local(backend) => backend.canonical_location(),
            ComponentStorage::Network { database_path, .. } => Ok(database_path.clone()),
        }
    }
    fn visit_committed(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        match &self.storage {
            ComponentStorage::Local(backend) => backend.visit_committed(visitor),
            ComponentStorage::Network { backend, .. } => backend.visit_blobs(visitor),
        }
    }
    fn visit_staged(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        match &self.storage {
            ComponentStorage::Local(backend) => backend.visit_staged(visitor),
            ComponentStorage::Network { backend, .. } => backend.visit_managed_blobs(&mut |blob| {
                if ea_archive::is_staging_path(blob.path_hint()) {
                    visitor(blob)
                } else {
                    Ok(())
                }
            }),
        }
    }
}

/// Die Lesesicht des Netz-Writers (EA-CNA-WRT-5): die committete Netzsicht
/// des verifizierten Snapshots (live gelesen oder Grundlinie, EA-CNA-SRC-4)
/// vereinigt mit der LIVE gelesenen committeten lokalen Komponente, bei
/// jedem Besuch neu gebildet. So sieht Schritt 1 den Kettenkopf und die
/// Publikationsprüfung der Schritte 10/11 die eigenen lokalen Commits.
pub struct NetworkWriterSourceV1<'a> {
    baseline: &'a FsArchiveSource,
    local: &'a SqlcipherArchiveBackend,
}
impl ArchiveSource for NetworkWriterSourceV1<'_> {
    fn visit_blobs(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        // Ein Konflikt oder eine unvollständige Aufzählung verwirft die ganze
        // Vereinigung; es gibt keinen Vorrang einer Seite.
        self.baseline
            .committed_view()
            .with_exact_component(self.local)
            .map_err(|_| ArchiveError::Unavailable)?
            .visit_blobs(visitor)
    }
}

impl NativeArchiveExistingComponent {
    /// Die Lesequelle eines Netz-Writers über der Netzsicht von `snapshot`.
    ///
    /// # Errors
    ///
    /// `Config` für eine LocalPath-Komponente oder einen Snapshot ohne
    /// Netzsicht (also ohne Registrierung beim Öffnen).
    pub fn writer_source<'a>(
        &'a self,
        snapshot: &'a OperatorArchiveSnapshot,
    ) -> Result<NetworkWriterSourceV1<'a>, NativeArchiveOpenError> {
        let ComponentStorage::Network { backend, .. } = &self.storage else {
            return Err(NativeArchiveOpenError::Config);
        };
        let baseline = snapshot
            .remote_baseline()
            .ok_or(NativeArchiveOpenError::Config)?;
        Ok(NetworkWriterSourceV1 {
            baseline,
            local: backend,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_admits_admin_and_writer_and_refuses_every_other_role() {
        assert!(require_registering_role(OperatorRoleV1::OrganizationAdmin, false).is_ok());
        assert!(require_registering_role(OperatorRoleV1::Writer, false).is_ok());
        for refused in [
            require_registering_role(OperatorRoleV1::Reader, false),
            require_registering_role(OperatorRoleV1::OrganizationAdmin, true),
            require_registering_role(OperatorRoleV1::Writer, true),
        ] {
            assert!(matches!(refused, Err(NativeArchiveOpenError::Role)));
            assert_eq!(refused.unwrap_err().code(), "EA-NATIVE-ARCHIVE-ROLE");
        }
    }
}
