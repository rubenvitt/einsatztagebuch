//! Native local custody composition. Configuration selects existing resources;
//! signed catalog and job custody alone can prove absence of a registered server.
use super::destruction_transport::{
    NativeDestructionServerConfig, NativeDestructionServerTransport,
};
mod evidence;
use super::{CONFIG_ERROR, NativeDesktopRuntime, now, writer_config::WriterSettings};
use crate::commands::CommandError;
use crate::state::{DestructionAdministrationPort, RuntimeSessionPort};
use ea_admin::{
    destruction_runtime::{
        DestructionRuntime, NativeDestructionStatus, NativeEvidenceWriter, NativeLocalHolder,
    },
    operator_runtime::{OperatorRuntime, OperatorRuntimeConfig},
};
use ea_archive::{ArchiveBackendProfileV1, LocalPathProfileV1};
use ea_recovery::KeySourceSpec;
use ea_types::{CertificateHash, DestructionId, DeviceId, ObjectHash};
use ea_ui_contracts::{
    DestructionAdministrationView, DestructionPreflightView, DestructionProcessView,
    DestructionReplicaView, DestructionStateV1, DestructionTargetView,
};
use serde::Deserialize;
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

fn config_error() -> CommandError {
    CommandError::new(CONFIG_ERROR)
}
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn certificate(value: &str) -> Result<CertificateHash, CommandError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(config_error());
    }
    let bytes = value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| config_error())?, 16)
                .map_err(|_| config_error())
        })
        .collect::<Result<Vec<_>, _>>()?;
    CertificateHash::try_from(bytes.as_slice()).map_err(|_| config_error())
}

#[derive(Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u8,
    writer_operator_config: PathBuf,
    evidence_writer_config: Option<PathBuf>,
    component_certificate_hash: String,
    component_key_source: String,
    delivery: Delivery,
    #[serde(default)]
    servers: Vec<ServerConfig>,
    holders: Vec<Holder>,
}
#[derive(Clone, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum Delivery {
    NoRegisteredServer,
    AuthenticatedServer,
}
#[derive(Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct ServerConfig {
    device_id: String,
    address: std::net::SocketAddr,
    server_name: String,
    authority: String,
    ca_file: PathBuf,
    server_certificate_hash: String,
}
impl ServerConfig {
    fn native(&self, base: &Path) -> Result<NativeDestructionServerConfig, CommandError> {
        if self.device_id.len() != 32
            || !self
                .device_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.server_name.is_empty()
            || self.authority.is_empty()
            || self.ca_file.as_os_str().is_empty()
        {
            return Err(config_error());
        }
        let bytes = self
            .device_id
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| config_error())?, 16)
                    .map_err(|_| config_error())
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(NativeDestructionServerConfig {
            device_id: DeviceId::try_from(bytes.as_slice()).map_err(|_| config_error())?,
            address: self.address,
            server_name: self.server_name.clone(),
            authority: self.authority.clone(),
            ca_file: relative(base, self.ca_file.clone()),
            server_certificate: certificate(&self.server_certificate_hash)?,
        })
    }
}
#[derive(Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Holder {
    archive_directory: PathBuf,
    filesystem_row_id: String,
    capability_test_vector_id: String,
    custody_certificate_hash: String,
}
impl Config {
    fn parse(bytes: &[u8]) -> Result<Self, CommandError> {
        if bytes.len() > 65_536 {
            return Err(config_error());
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| config_error())?;
        if value.version != 1
            || value.writer_operator_config.as_os_str().is_empty()
            || value
                .evidence_writer_config
                .as_ref()
                .is_some_and(|path| path.as_os_str().is_empty())
            || value.holders.is_empty()
            || value.holders.len() > 256
        {
            return Err(config_error());
        }
        certificate(&value.component_certificate_hash)?;
        match value.delivery {
            Delivery::NoRegisteredServer if !value.servers.is_empty() => return Err(config_error()),
            Delivery::AuthenticatedServer
                if value.servers.is_empty() || value.servers.len() > 64 =>
            {
                return Err(config_error());
            }
            _ => {}
        }
        let mut devices = std::collections::BTreeSet::new();
        for server in &value.servers {
            if !devices.insert(server.native(Path::new("."))?.device_id) {
                return Err(config_error());
            }
        }
        // Only the existing encrypted container grammar is supported here.
        // A selected hardware provider is refused explicitly, never downgraded.
        match KeySourceSpec::parse(value.component_key_source.as_ref())
            .map_err(|_| config_error())?
        {
            KeySourceSpec::Container { .. } => {}
            KeySourceSpec::Pkcs11 { .. } => {
                return Err(CommandError::new(
                    "EA-DESTRUCTION-COMPONENT-PKCS11-UNAVAILABLE",
                ));
            }
            KeySourceSpec::File(_) => {
                return Err(CommandError::new("EA-DESTRUCTION-COMPONENT-CONTAINER"));
            }
        }
        for holder in &value.holders {
            certificate(&holder.custody_certificate_hash)?;
            if holder.archive_directory.as_os_str().is_empty()
                || holder.filesystem_row_id.is_empty()
                || holder.capability_test_vector_id.is_empty()
            {
                return Err(config_error());
            }
        }
        Ok(value)
    }
    fn evidence_settings(&self, base: &Path) -> Result<Option<WriterSettings>, CommandError> {
        self.evidence_writer_config
            .as_ref()
            .map(|path| WriterSettings::load(&relative(base, path.clone())))
            .transpose()
    }
    fn load(path: &Path) -> Result<Self, CommandError> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| config_error())?
            .take(65_537)
            .read_to_end(&mut bytes)
            .map_err(|_| config_error())?;
        Self::parse(&bytes)
    }
}
fn relative(base: &Path, path: PathBuf) -> PathBuf {
    if path.is_relative() {
        base.join(path)
    } else {
        path
    }
}

pub(super) struct DestructionResources {
    pub(super) runtime: DestructionRuntime,
    server_transport: Option<NativeDestructionServerTransport>,
    reopen: Option<ReopenSource>,
    evidence_settings: Option<WriterSettings>,
    evidence_writer: Option<NativeEvidenceWriter>,
    evidence_epoch: Option<u64>,
}

#[derive(Clone)]
enum CustodianProvider {
    Installed,
    #[cfg(feature = "test-support")]
    TestFixture(PathBuf),
}
struct ReopenSource {
    path: PathBuf,
    anchor: PathBuf,
    config: Config,
    evidence_settings: Option<WriterSettings>,
    controller: OperatorRuntimeConfig,
    writer: OperatorRuntimeConfig,
    provider: CustodianProvider,
}
fn same_operator_configuration(a: &OperatorRuntimeConfig, b: &OperatorRuntimeConfig) -> bool {
    a.archive_directory == b.archive_directory
        && a.database_path == b.database_path
        && a.device_certificate_hash == b.device_certificate_hash
        && a.binding_object_hash == b.binding_object_hash
        && a.role == b.role
        && a.purpose == b.purpose
        && a.admin_certificate_hash == b.admin_certificate_hash
        && a.admin_binding_object_hash == b.admin_binding_object_hash
        && a.ceremony_exchange_directory == b.ceremony_exchange_directory
        && a.authority == b.authority
        && a.target_certificate_hash == b.target_certificate_hash
}
impl DestructionResources {
    fn lock(&mut self) {
        self.runtime.lock();
        // Keep durable draft state, but never cache an irreversibly locked
        // adapter. The next explicit action obtains a fresh guarded instance;
        // an earlier preview cannot be revived by replacing its guard.
        if let Some(mut writer) = self.evidence_writer.take() {
            writer.lock();
        }
    }

    #[cfg(feature = "test-support")]
    pub(super) fn with_local_test_runtime(runtime: DestructionRuntime) -> Self {
        Self {
            runtime,
            server_transport: None,
            reopen: None,
            evidence_settings: None,
            evidence_writer: None,
            evidence_epoch: None,
        }
    }
    pub(super) fn open(
        path: &Path,
        controller: &OperatorRuntime,
        anchor: &Path,
    ) -> Result<Self, CommandError> {
        Self::open_using(
            path,
            controller,
            anchor,
            Some(CustodianProvider::Installed),
            |writer| {
                OperatorRuntime::open(writer, anchor, now()?, false)
                    .map_err(|error| CommandError::new(error.code()))
            },
        )
    }
    #[cfg(feature = "test-support")]
    pub(super) fn open_with_test_custodian(
        path: &Path,
        controller: &OperatorRuntime,
        anchor: &Path,
        native: Arc<ea_admin::native_provider::NativeOperatorProvider>,
    ) -> Result<Self, CommandError> {
        Self::open_using(path, controller, anchor, None, |writer| {
            OperatorRuntime::open_with_test_native(writer, anchor, now()?, false, native)
                .map_err(|error| CommandError::new(error.code()))
        })
    }
    #[cfg(feature = "test-support")]
    pub(super) fn open_with_test_custodian_path(
        path: &Path,
        controller: &OperatorRuntime,
        anchor: &Path,
        helper: &Path,
    ) -> Result<Self, CommandError> {
        Self::open_using(
            path,
            controller,
            anchor,
            Some(CustodianProvider::TestFixture(helper.to_owned())),
            |writer| {
                let native = ea_admin::native_provider::NativeOperatorProvider::open_test_fixture(
                    helper.to_owned(),
                    false,
                )
                .map_err(|error| CommandError::new(error.code()))?;
                OperatorRuntime::open_with_test_native(writer, anchor, now()?, false, native)
                    .map_err(|error| CommandError::new(error.code()))
            },
        )
    }
    fn open_using(
        path: &Path,
        controller: &OperatorRuntime,
        anchor: &Path,
        provider: Option<CustodianProvider>,
        open_custodian: impl FnOnce(OperatorRuntimeConfig) -> Result<OperatorRuntime, CommandError>,
    ) -> Result<Self, CommandError> {
        if controller.config().role != ea_format::OperatorRoleV1::OrganizationAdmin {
            return Err(config_error());
        }
        let config = Config::load(path)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        let writer =
            OperatorRuntimeConfig::load(&relative(base, config.writer_operator_config.clone()))
                .map_err(|error| CommandError::new(error.code()))?;
        let evidence_settings = config.evidence_settings(base)?;
        let reopen = provider.map(|provider| ReopenSource {
            path: path.to_owned(),
            anchor: anchor.to_owned(),
            config: config.clone(),
            evidence_settings: evidence_settings.clone(),
            controller: controller.config().clone(),
            writer: writer.clone(),
            provider,
        });
        let custodian = open_custodian(writer)?;
        let controller = controller
            .reopened_for_action()
            .map_err(|error| CommandError::new(error.code()))?;
        let mut resources = Self::compose(config, base, controller, custodian, evidence_settings)?;
        resources.reopen = reopen;
        Ok(resources)
    }
    /// Called only by the explicit custodian-login command. Configuration or
    /// identity changes require a new application launch, never a silent swap.
    fn reopened_for_custodian_login(
        &self,
        controller: &OperatorRuntime,
    ) -> Result<Self, CommandError> {
        let source = self
            .reopen
            .as_ref()
            .ok_or_else(|| CommandError::new("EA-DESKTOP-CUSTODIAN-LOGIN-UNAVAILABLE"))?;
        let current = Config::load(&source.path)?;
        let base = source.path.parent().unwrap_or_else(|| Path::new("."));
        let writer =
            OperatorRuntimeConfig::load(&relative(base, current.writer_operator_config.clone()))
                .map_err(|error| CommandError::new(error.code()))?;
        let evidence_settings = current.evidence_settings(base)?;
        if current != source.config
            || evidence_settings != source.evidence_settings
            || !same_operator_configuration(controller.config(), &source.controller)
            || !same_operator_configuration(&writer, &source.writer)
        {
            return Err(config_error());
        }
        // Use the just-checked in-memory configuration: a second file read
        // must not substitute resources between the comparison and opening.
        let custodian = match &source.provider {
            CustodianProvider::Installed => {
                OperatorRuntime::open(writer, &source.anchor, now()?, false)
            }
            #[cfg(feature = "test-support")]
            CustodianProvider::TestFixture(helper) => {
                let native = ea_admin::native_provider::NativeOperatorProvider::open_test_fixture(
                    helper.clone(),
                    false,
                )
                .map_err(|error| CommandError::new(error.code()))?;
                OperatorRuntime::open_with_test_native(
                    writer,
                    &source.anchor,
                    now()?,
                    false,
                    native,
                )
            }
        }
        .map_err(|error| CommandError::new(error.code()))?;
        let controller = controller
            .reopened_for_action()
            .map_err(|error| CommandError::new(error.code()))?;
        let mut resources = Self::compose(current, base, controller, custodian, evidence_settings)?;
        resources.reopen = Some(ReopenSource {
            path: source.path.clone(),
            anchor: source.anchor.clone(),
            config: source.config.clone(),
            evidence_settings: source.evidence_settings.clone(),
            controller: source.controller.clone(),
            writer: source.writer.clone(),
            provider: source.provider.clone(),
        });
        Ok(resources)
    }
    fn compose(
        config: Config,
        base: &Path,
        controller: OperatorRuntime,
        custodian: OperatorRuntime,
        evidence_settings: Option<WriterSettings>,
    ) -> Result<Self, CommandError> {
        let mut holders = Vec::new();
        for holder in config.holders {
            holders.push(
                NativeLocalHolder::open(
                    &custodian,
                    relative(base, holder.archive_directory),
                    ArchiveBackendProfileV1::LocalPath(LocalPathProfileV1 {
                        filesystem_row_id: holder.filesystem_row_id,
                        capability_test_vector_id: holder.capability_test_vector_id,
                    }),
                    certificate(&holder.custody_certificate_hash)?,
                )
                .map_err(|error| CommandError::new(error.code()))?,
            );
        }
        let KeySourceSpec::Container {
            path,
            passphrase_file,
        } = KeySourceSpec::parse(config.component_key_source.as_ref())
            .map_err(|_| config_error())?
        else {
            return Err(config_error());
        };
        let source = KeySourceSpec::Container {
            path: relative(base, path),
            passphrase_file: relative(base, passphrase_file),
        };
        let server_transport = match config.delivery {
            Delivery::NoRegisteredServer => None,
            Delivery::AuthenticatedServer => Some(
                NativeDestructionServerTransport::open(
                    config
                        .servers
                        .iter()
                        .map(|server| server.native(base))
                        .collect::<Result<Vec<_>, _>>()?,
                    &source,
                )
                .map_err(|error| CommandError::new(error.code()))?,
            ),
        };
        let runtime = DestructionRuntime::new(
            controller,
            custodian,
            holders,
            certificate(&config.component_certificate_hash)?,
            source,
        )
        .map_err(|error| CommandError::new(error.code()))?;
        Ok(Self {
            runtime,
            server_transport,
            reopen: None,
            evidence_settings,
            evidence_writer: None,
            evidence_epoch: None,
        })
    }
    pub(super) fn view(
        &mut self,
        mut process: Option<NativeDestructionStatus>,
    ) -> Result<DestructionAdministrationView, CommandError> {
        let administration = self
            .runtime
            .administration()
            .map_err(|error| CommandError::new(error.code()))?;
        if process.is_none() && administration.known_destruction_ids.len() == 1 {
            process = Some(
                self.runtime
                    .status(administration.known_destruction_ids[0])
                    .map_err(|error| CommandError::new(error.code()))?,
            );
        }
        if process.as_ref().is_some_and(|p| {
            p.policy_hash != administration.policy_hash
                || p.privacy_decision_enabled != administration.privacy_decision_enabled
                || !administration
                    .known_destruction_ids
                    .contains(&p.destruction_id)
        }) {
            return Err(CommandError::new("EA-DESTRUCTION-SECURITY-CONFLICT"));
        }
        Ok(DestructionAdministrationView {
            privacy_decision_enabled: administration.privacy_decision_enabled,
            policy_hash: hex(administration.policy_hash.as_bytes()),
            known_destruction_ids: administration
                .known_destruction_ids
                .iter()
                .map(|id| hex(id.as_bytes()))
                .collect(),
            process: process.map(project).transpose()?,
        })
    }
}

struct ExpectedEpoch {
    source: Arc<AtomicU64>,
    expected: u64,
}
impl ea_admin::destruction_runtime::DestructionHostGuard for ExpectedEpoch {
    fn require_open(&self) -> Result<(), ea_admin::destruction_runtime::NativeDestructionError> {
        if self.expected & 1 != 0 || self.source.load(Ordering::SeqCst) != self.expected {
            Err(ea_admin::destruction_runtime::NativeDestructionError::Session)
        } else {
            Ok(())
        }
    }
}
impl NativeDesktopRuntime {
    fn destruction_action<T>(
        &self,
        action: impl FnOnce(&mut DestructionResources) -> Result<T, CommandError>,
    ) -> Result<T, CommandError> {
        let epoch = self.session_epoch.load(Ordering::SeqCst);
        if epoch & 1 != 0
            || self.verified_role()? != Some(ea_format::OperatorRoleV1::OrganizationAdmin)
        {
            return Err(CommandError::new("EA-DESKTOP-ADMINISTRATION-FORBIDDEN"));
        }
        let mut resources = self
            .destruction
            .as_ref()
            .ok_or_else(|| CommandError::new("EA-DESKTOP-DESTRUCTION-UNAVAILABLE"))?
            .lock()
            .map_err(|_| CommandError::new("EA-DESKTOP-RUNTIME-LOCK"))?;
        if self.session_epoch.load(Ordering::SeqCst) != epoch {
            resources.lock();
            return Err(CommandError::new("EA-DESKTOP-SESSION-LOCKED"));
        }
        if resources.evidence_epoch != Some(epoch) {
            // Host re-login cannot revive a preview issued before a lock. The
            // encrypted draft binding survives; explicit preview/recovery reads it.
            resources.evidence_writer = None;
            resources.evidence_epoch = Some(epoch);
        }
        let guard: Arc<dyn ea_admin::destruction_runtime::DestructionHostGuard> =
            Arc::new(ExpectedEpoch {
                source: self.session_epoch.clone(),
                expected: epoch,
            });
        resources.runtime.set_host_guard(guard.clone());
        if let Some(writer) = resources.evidence_writer.as_mut() {
            writer.set_host_guard(guard);
        }
        let result = action(&mut resources);
        if self.session_epoch.load(Ordering::SeqCst) != epoch {
            resources.lock();
            return Err(CommandError::new("EA-DESKTOP-SESSION-LOCKED"));
        }
        if result.is_err() {
            resources.lock();
        }
        result
    }
}
impl DestructionAdministrationPort for NativeDesktopRuntime {
    fn export_reader_delivery(
        &self,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
        reader: DeviceId,
    ) -> Result<ea_ui_contracts::DestructionReaderDeliveryView, CommandError> {
        self.destruction_action(|resources| {
            let delivery = resources
                .runtime
                .export_reader_delivery(id, expected_preflight_hash, reader)
                .map_err(|error| CommandError::new(error.code()))?;
            Ok(ea_ui_contracts::DestructionReaderDeliveryView {
                destruction_id: hex(id.as_bytes()),
                job_hash: hex(delivery.job_hash().as_bytes()),
                reader_id: hex(delivery.reader_id().as_bytes()),
                exact_authorization: delivery.exact_authorization().to_vec(),
                exact_initiating_event: delivery.exact_initiating_event().to_vec(),
                exact_job_upload: delivery.exact_job_upload().to_vec(),
            })
        })
    }

    fn authenticate_custodian(
        &self,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
    ) -> Result<DestructionAdministrationView, CommandError> {
        if self.verified_role()? != Some(ea_format::OperatorRoleV1::OrganizationAdmin) {
            return Err(CommandError::new("EA-DESKTOP-ADMINISTRATION-FORBIDDEN"));
        }
        let epoch = self.session_epoch.load(Ordering::SeqCst);
        let controller = {
            let inner = self
                .inner
                .lock()
                .map_err(|_| CommandError::new("EA-DESKTOP-RUNTIME-LOCK"))?;
            inner
                .runtime
                .current()
                .ok_or_else(config_error)?
                .reopened_for_action()
                .map_err(|error| CommandError::new(error.code()))?
        };
        self.destruction_action(|resources| {
            let mut fresh = resources.reopened_for_custodian_login(&controller)?;
            fresh.runtime.set_host_guard(Arc::new(ExpectedEpoch {
                source: self.session_epoch.clone(),
                expected: epoch,
            }));
            fresh
                .runtime
                .unlock()
                .map_err(|error| CommandError::new(error.code()))?;
            let before = fresh
                .runtime
                .status(id)
                .map_err(|error| CommandError::new(error.code()))?;
            if before.destruction_id != id || before.preflight_hash != Some(expected_preflight_hash)
            {
                return Err(CommandError::new("EA-DESTRUCTION-SECURITY-CONFLICT"));
            }
            fresh
                .runtime
                .authenticate_custodian()
                .map_err(|error| CommandError::new(error.code()))?;
            // Writer presence was consumed only by its own login. Obtain a
            // separate Admin presence before returning the durable public view.
            fresh
                .runtime
                .unlock()
                .map_err(|error| CommandError::new(error.code()))?;
            let status = fresh
                .runtime
                .status(id)
                .map_err(|error| CommandError::new(error.code()))?;
            if status.destruction_id != id || status.preflight_hash != Some(expected_preflight_hash)
            {
                return Err(CommandError::new("EA-DESTRUCTION-SECURITY-CONFLICT"));
            }
            let view = fresh.view(Some(status))?;
            if self.session_epoch.load(Ordering::SeqCst) != epoch {
                return Err(CommandError::new("EA-DESKTOP-SESSION-LOCKED"));
            }
            *resources = fresh;
            Ok(view)
        })
    }
    fn synchronize(
        &self,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
    ) -> Result<DestructionAdministrationView, CommandError> {
        self.destruction_action(|resources| {
            let transport = resources
                .server_transport
                .as_mut()
                .ok_or_else(|| CommandError::new("EA-DESTRUCTION-TRANSPORT-UNAVAILABLE"))?;
            let status = transport
                .synchronize(&mut resources.runtime, id, expected_preflight_hash)
                .map_err(|error| CommandError::new(error.code()))?;
            resources.view(Some(status))
        })
    }
    fn read(
        &self,
        id: Option<DestructionId>,
    ) -> Result<DestructionAdministrationView, CommandError> {
        self.destruction_action(|resources| {
            resources
                .runtime
                .unlock()
                .map_err(|error| CommandError::new(error.code()))?;
            let status = id
                .map(|id| resources.runtime.status(id))
                .transpose()
                .map_err(|error| CommandError::new(error.code()))?;
            resources.view(status)
        })
    }
    fn prepare(&self, exact: &[u8]) -> Result<DestructionAdministrationView, CommandError> {
        self.destruction_action(|resources| {
            let status = resources
                .runtime
                .prepare(exact)
                .map_err(|error| CommandError::new(error.code()))?;
            resources.view(Some(status))
        })
    }
    fn start(
        &self,
        id: DestructionId,
        preflight: ObjectHash,
    ) -> Result<DestructionAdministrationView, CommandError> {
        self.destruction_action(|resources| {
            let status = if let Some(transport) = &mut resources.server_transport {
                transport
                    .start(&mut resources.runtime, id, preflight)
                    .map_err(|error| CommandError::new(error.code()))?
            } else {
                resources.runtime.start(
                    id,
                    preflight,
                    ea_admin::destruction_runtime::NativeDestructionDelivery::NoRegisteredServer,
                )
                .map_err(|error| CommandError::new(error.code()))?
            };
            resources.view(Some(status))
        })
    }
    fn import_progress(
        &self,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
        exact_etb_objects: &[Vec<u8>],
    ) -> Result<DestructionAdministrationView, CommandError> {
        self.destruction_action(|resources| {
            let status = resources
                .runtime
                .import_signed_progress(id, expected_preflight_hash, exact_etb_objects)
                .map_err(|error| CommandError::new(error.code()))?;
            resources.view(Some(status))
        })
    }
    fn resume(&self, id: DestructionId) -> Result<DestructionAdministrationView, CommandError> {
        self.destruction_action(|resources| {
            let status = if let Some(transport) = &mut resources.server_transport {
                transport
                    .resume(&mut resources.runtime, id)
                    .map_err(|error| CommandError::new(error.code()))?
            } else {
                let status = resources.runtime.resume_local(
                    id,
                    ea_admin::destruction_runtime::NativeDestructionDelivery::NoRegisteredServer,
                )
                .map_err(|error| CommandError::new(error.code()))?;
                if let Some(hash) = completion_job(&status) {
                    resources.runtime.complete_verified_progress(
                        id,
                        hash,
                        ea_admin::destruction_runtime::NativeDestructionDelivery::NoRegisteredServer,
                    )
                    .map_err(|error| CommandError::new(error.code()))?
                } else if let Some(hash) = pending_job(&status, now()?) {
                    resources.runtime.mark_pending_backup_progress(
                        id,
                        hash,
                        ea_admin::destruction_runtime::NativeDestructionDelivery::NoRegisteredServer,
                    )
                    .map_err(|error| CommandError::new(error.code()))?
                } else {
                    status
                }
            };
            resources.view(Some(status))
        })
    }
}
/// Routes only explicit Resume. This projection grants no authority: the native
/// service rechecks signed history, all deadlines, custody and actual archives.
pub(super) fn completion_job(status: &NativeDestructionStatus) -> Option<ObjectHash> {
    use ea_destruction::{DestructionState, EvidenceReplicaStatus};
    if !matches!(
        status.state,
        DestructionState::InProgress
            | DestructionState::PendingBackupExpiry
            | DestructionState::CompleteManagedScope
    ) || status.replicas.is_empty()
        || status.targets.is_empty()
        || status
            .targets
            .iter()
            .any(|target| target.stub_object_hash.is_none())
        || !status.replicas.iter().all(|replica| {
            matches!(
                (replica.result, replica.attestation_hash),
                (EvidenceReplicaStatus::Successful(success), Some(hash)) if success == hash
            )
        })
    {
        return None;
    }
    // A successful removal may retain an already elapsed backup deadline.
    // The verified replica result, not absence of that field, drives routing.
    status.preflight_hash
}
/// Routing only; the native service verifies every historical maximum and
/// repeats its fresh cutoff check after blocking native and archive operations.
pub(super) fn pending_job(
    status: &NativeDestructionStatus,
    observed_now: ea_types::UnixMillis,
) -> Option<ObjectHash> {
    use ea_destruction::{DestructionState, EvidenceReplicaStatus, ManagedReplicaKind};
    if !matches!(
        status.state,
        DestructionState::InProgress | DestructionState::PendingBackupExpiry
    ) || status.targets.is_empty()
        || status
            .targets
            .iter()
            .any(|target| target.stub_object_hash.is_none())
        || !status.replicas.iter().any(|replica| {
            replica.device_id == status.custodian_device_id
                && replica.kind == ManagedReplicaKind::Writer
                && matches!((replica.result, replica.attestation_hash),
                    (EvidenceReplicaStatus::Successful(success), Some(hash)) if success == hash)
        })
    {
        return None;
    }
    let mut pending = false;
    for replica in &status.replicas {
        match (replica.result, replica.attestation_hash) {
            (EvidenceReplicaStatus::Successful(success), Some(hash)) if success == hash => {}
            (EvidenceReplicaStatus::PendingBackup, Some(_))
                if matches!(
                    replica.kind,
                    ManagedReplicaKind::Reader | ManagedReplicaKind::SyncServer
                ) && replica
                    .backup_expiry_at
                    .is_some_and(|expiry| expiry > observed_now) =>
            {
                pending = true;
            }
            _ => return None,
        }
    }
    pending.then_some(status.preflight_hash).flatten()
}
fn project(value: NativeDestructionStatus) -> Result<DestructionProcessView, CommandError> {
    use ea_destruction::{DestructionState, EvidenceReplicaStatus, ManagedReplicaKind};
    let state = match value.state {
        DestructionState::Requested => DestructionStateV1::Requested,
        DestructionState::InProgress => DestructionStateV1::InProgress,
        DestructionState::PendingBackupExpiry => DestructionStateV1::PendingBackupExpiry,
        DestructionState::CompleteManagedScope => DestructionStateV1::CompleteManagedScope,
        DestructionState::IncompleteUnreachableReplica => {
            DestructionStateV1::IncompleteUnreachableReplica
        }
    };
    let replicas = value
        .replicas
        .into_iter()
        .map(|replica| {
            let result_code = match (replica.attestation_hash, replica.result) {
                (None, EvidenceReplicaStatus::Unreachable) => None,
                (Some(hash), EvidenceReplicaStatus::Successful(success)) if hash == success => {
                    Some(0)
                }
                (Some(_), EvidenceReplicaStatus::PendingBackup) => Some(1),
                (Some(_), EvidenceReplicaStatus::Unreachable) => Some(2),
                _ => return Err(config_error()),
            };
            Ok(DestructionReplicaView {
                device_id: hex(replica.device_id.as_bytes()),
                kind_code: match replica.kind {
                    ManagedReplicaKind::Writer => 0,
                    ManagedReplicaKind::Reader => 1,
                    ManagedReplicaKind::SyncServer => 2,
                },
                attestation_hash: replica.attestation_hash.map(|hash| hex(hash.as_bytes())),
                result_code,
                backup_expiry_at: replica.backup_expiry_at,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let preflight = match (value.preflight_hash, value.preflight_report_json) {
        (Some(hash), Some(report)) => Some(DestructionPreflightView {
            job_hash: hex(hash.as_bytes()),
            exact_canonical_report_json: report,
            known_replica_count: u32::try_from(replicas.len()).map_err(|_| config_error())?,
        }),
        (None, None) => None,
        _ => return Err(config_error()),
    };
    Ok(DestructionProcessView {
        destruction_id: hex(value.destruction_id.as_bytes()),
        authorization_object_hash: hex(value.authorization_hash.as_bytes()),
        state,
        scope_code: value.scope_code,
        legal_reason_code: value.legal_reason_code,
        controller_device_id: hex(value.controller_device_id.as_bytes()),
        custodian_device_id: hex(value.custodian_device_id.as_bytes()),
        approver_certificate_hashes: value
            .approver_certificate_hashes
            .iter()
            .map(|hash| hex(hash.as_bytes()))
            .collect(),
        targets: value
            .targets
            .into_iter()
            .map(|target| DestructionTargetView {
                entry_hash: hex(target.entry_hash.as_bytes()),
                chain_sequence: target.chain_sequence,
                stub_object_hash: target.stub_object_hash.map(|hash| hex(hash.as_bytes())),
            })
            .collect(),
        preflight,
        replicas,
        evidence_entry_hash: value.evidence_entry_hash.map(|hash| hex(hash.as_bytes())),
    })
}

#[cfg(test)]
mod tests {
    use super::Config;

    fn config() -> serde_json::Value {
        serde_json::json!({
            "version": 1,
            "writer_operator_config": "writer.json",
            "component_certificate_hash": "ab".repeat(32),
            "component_key_source": "container:component.eak;passphrase-file=component.pass",
            "delivery": "authenticated-server",
            "holders": [{
                "archive_directory": "archive",
                "filesystem_row_id": "apfs",
                "capability_test_vector_id": "local-v1",
                "custody_certificate_hash": "cd".repeat(32)
            }],
            "servers": [{
                "device_id": "12".repeat(16),
                "address": "127.0.0.1:9443",
                "server_name": "archive.example",
                "authority": "archive.example:9443",
                "ca_file": "server-ca.pem",
                "server_certificate_hash": "ef".repeat(32)
            }]
        })
    }

    #[test]
    fn authenticated_server_delivery_requires_explicit_native_endpoints() {
        let value = config();
        assert!(Config::parse(&serde_json::to_vec(&value).unwrap()).is_ok());
        for field in [
            "device_id",
            "address",
            "server_name",
            "authority",
            "ca_file",
            "server_certificate_hash",
        ] {
            let mut incomplete = value.clone();
            incomplete["servers"][0]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(
                Config::parse(&serde_json::to_vec(&incomplete).unwrap()).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn delivery_configuration_cannot_omit_duplicate_or_silently_ignore_servers() {
        let value = config();
        for count in [0, 2, 65] {
            let mut invalid = value.clone();
            invalid["servers"] = serde_json::Value::Array(vec![value["servers"][0].clone(); count]);
            assert!(Config::parse(&serde_json::to_vec(&invalid).unwrap()).is_err());
        }
        let mut local = value.clone();
        local["delivery"] = "no-registered-server".into();
        assert!(Config::parse(&serde_json::to_vec(&local).unwrap()).is_err());
        local.as_object_mut().unwrap().remove("servers");
        assert!(Config::parse(&serde_json::to_vec(&local).unwrap()).is_ok());
    }
}
