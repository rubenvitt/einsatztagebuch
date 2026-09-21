//! Public configuration and media routing. No input field can attest identity,
//! native presence, restoration, completeness or readiness.
use super::*;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Profile {
    #[serde(rename = "localPath", rename_all = "camelCase")]
    LocalPath {
        filesystem_row_id: String,
        capability_test_vector_id: String,
    },
    #[serde(rename = "controlledNetworkPath", rename_all = "camelCase")]
    ControlledNetworkPath {
        filesystem_row_id: String,
        protocol_id: String,
        server_product: String,
        server_version: String,
        mount_options: Vec<String>,
        failover_config_id: String,
        capability_test_vector_id: String,
        queue_max_objects: u64,
        queue_max_bytes: u64,
        resume_backoff_initial_ms: u64,
        resume_backoff_max_ms: u64,
        resume_max_attempts: u64,
    },
}
pub fn parse_recovery_archive_profile(
    exact: &[u8],
) -> Result<ArchiveBackendProfileV1, RecoveryRuntimeError> {
    if exact.len() > 65536 {
        return Err(RecoveryTestError::Source.into());
    }
    let parsed: Profile = serde_json::from_slice(exact).map_err(|_| RecoveryTestError::Source)?;
    let profile = match parsed {
        Profile::LocalPath {
            filesystem_row_id,
            capability_test_vector_id,
        } => ArchiveBackendProfileV1::LocalPath(ea_archive::LocalPathProfileV1 {
            filesystem_row_id,
            capability_test_vector_id,
        }),
        Profile::ControlledNetworkPath {
            filesystem_row_id,
            protocol_id,
            server_product,
            server_version,
            mount_options,
            failover_config_id,
            capability_test_vector_id,
            queue_max_objects,
            queue_max_bytes,
            resume_backoff_initial_ms,
            resume_backoff_max_ms,
            resume_max_attempts,
        } => {
            ArchiveBackendProfileV1::ControlledNetworkPath(ea_archive::ControlledNetworkProfileV1 {
                filesystem_row_id,
                protocol_id,
                server_product,
                server_version,
                mount_options,
                failover_config_id,
                capability_test_vector_id,
                queue_max_objects,
                queue_max_bytes,
                resume_backoff_initial_ms,
                resume_backoff_max_ms,
                resume_max_attempts,
            })
        }
    };
    profile.core()?;
    Ok(profile)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MediaDocument {
    schema_id: String,
    media: Vec<MediumSource>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MediumSource {
    medium_id: String,
    source: String,
}
pub fn parse_recovery_media_sources(
    exact: &[u8],
    inventory: &KeyInventory,
) -> Result<Vec<RecoveryTestMediumSource>, RecoveryRuntimeError> {
    if exact.len() > 1024 * 1024 {
        return Err(RecoveryTestError::Inventory.into());
    }
    let document: MediaDocument =
        serde_json::from_slice(exact).map_err(|_| RecoveryTestError::Inventory)?;
    if document.schema_id != "ea.recovery-media-sources/v1" {
        return Err(RecoveryTestError::Inventory.into());
    }
    let mut seen = std::collections::BTreeSet::new();
    document
        .media
        .into_iter()
        .map(|row| {
            let medium = inventory
                .media()
                .iter()
                .find(|m| m.id() == row.medium_id)
                .ok_or(RecoveryTestError::Inventory)?;
            if !seen.insert(medium.pseudonymous_id_hash()) {
                return Err(RecoveryTestError::Inventory.into());
            }
            let source = if let Some(slot) = row.source.strip_prefix("native:") {
                RecoveryMediumInput::NativeSigningSlot(match slot {
                    "admin-signing" => RecoveryNativeSigningSlot::Admin,
                    "writer-signing" => RecoveryNativeSigningSlot::Writer,
                    "root-signing" => RecoveryNativeSigningSlot::Root,
                    _ => return Err(RecoveryTestError::Key.into()),
                })
            } else {
                RecoveryMediumInput::Offline(
                    ea_recovery::KeySourceSpec::parse(std::ffi::OsStr::new(&row.source))
                        .map_err(|_| RecoveryTestError::Key)?,
                )
            };
            require_medium_source(medium, &source)?;
            Ok(RecoveryTestMediumSource {
                medium_id_hash: medium.pseudonymous_id_hash(),
                source,
            })
        })
        .collect()
}

/// A routing compatibility check can reject a declaration, never certify the
/// protection reached by a provider. Actual operation checks still follow.
pub(super) fn require_medium_source(
    medium: &ea_recovery::RecoveryMedium,
    source: &RecoveryMediumInput,
) -> Result<(), RecoveryTestError> {
    use ea_format::KeyProtectionProfileV1 as Protection;
    match (source, medium.protection()) {
        (
            RecoveryMediumInput::Offline(ea_recovery::KeySourceSpec::Container { .. }),
            Protection::OfflineEncryptedContainer,
        ) => Ok(()),
        (
            RecoveryMediumInput::Offline(ea_recovery::KeySourceSpec::Pkcs11 { .. }),
            Protection::Pkcs11,
        ) => Ok(()),
        (
            RecoveryMediumInput::Offline(ea_recovery::KeySourceSpec::Pkcs11 { .. }),
            Protection::HardwareNonExportable | Protection::ServerSecretStoreOrHsm,
        ) => Err(RecoveryTestError::Protection),
        (RecoveryMediumInput::NativeSigningSlot(slot), _) if slot.accepts(medium) => Ok(()),
        _ => Err(RecoveryTestError::Key),
    }
}

impl RecoveryTestRuntime {
    /// Deterministically selects an already existing original probe for each
    /// required Recovery epoch. capture_source authenticates every chosen pair.
    /// No key, grant or source identity is created by this selection.
    pub fn capture_inventory(
        &mut self,
        inventory: &KeyInventory,
        snapshot: &Path,
        passphrase: &SecretVec,
    ) -> Result<VerifiedRecoverySource, RecoveryRuntimeError> {
        self.runtime.ensure_current()?;
        // Dieselbe Quelle wie die Capture: ein Netzprofil ohne Export hat
        // keine vollständige Quelle und lehnt hier schon ab (EA-CNA-REC-3).
        let source = self.archive_source()?;
        let probe = ea_recovery::RecoveryArchiveProbe::verify(
            &source,
            self.runtime.anchor(),
            self.runtime.head().preexisting_effective_now().value(),
        )?;
        let probes = select_recovery_probes(inventory, &probe)?;
        self.capture_source(RecoverySourceCapture {
            inventory,
            probes,
            snapshot,
            passphrase,
        })
    }
    /// Wie [`Self::capture_inventory`] für ein Netzprofil: die Sonden werden
    /// erst nach dem Export aus der Vereinigung von Netzziel und
    /// zurückgelesenem Export gewählt, also auch aus lokal committeten, noch
    /// nicht publizierten Objekten (EA-CNA-REC-3).
    pub fn capture_inventory_with_component_export(
        &mut self,
        inventory: &KeyInventory,
        snapshot: &Path,
        passphrase: &SecretVec,
        component_export: &Path,
    ) -> Result<VerifiedRecoverySource, RecoveryRuntimeError> {
        self.runtime.ensure_current()?;
        self.capture_network(
            RecoverySourceCapture {
                inventory,
                probes: Vec::new(),
                snapshot,
                passphrase,
            },
            component_export,
            true,
        )
    }
}

/// Wählt je Recovery-Medium deterministisch das früheste vorhandene
/// Original-Paar aus Setup-Eintrag und Initial-Grant.
pub(super) fn select_recovery_probes(
    inventory: &KeyInventory,
    probe: &ea_recovery::RecoveryArchiveProbe,
) -> Result<Vec<RecoveryProbeBinding>, RecoveryRuntimeError> {
    let mut probes = Vec::new();
    for medium in inventory
        .media()
        .iter()
        .filter(|m| m.role() == ea_recovery::RecoveryKeyRole::RecoveryRecipient)
    {
        let mut candidates = Vec::new();
        for grant in probe.inventory().grants() {
            let g = grant.value().grant_body().fields();
            if g.kind != ea_format::GrantKindV1::Initial
                || g.purpose != ea_format::GrantPurposeV1::Recovery
                || g.recipient_certificate_hash != medium.certificate()
                || g.recipient_key_thumbprint != medium.expected_thumbprint()
            {
                continue;
            }
            if let Some(entry) = probe
                .inventory()
                .entries()
                .iter()
                .find(|e| e.value().entry_hash() == g.entry_hash)
            {
                candidates.push((
                    entry.value().manifest().fields().chain_sequence,
                    grant.object_hash(),
                    g.entry_hash,
                ));
            }
        }
        candidates.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let (_, grant, entry) = candidates.first().ok_or(RecoveryTestError::Incomplete)?;
        probes.push(RecoveryProbeBinding {
            medium_hash: *medium.pseudonymous_id_hash().as_bytes(),
            certificate_hash: *medium.certificate().as_bytes(),
            key_thumbprint: *medium.expected_thumbprint().as_bytes(),
            setup_entry_hash: *entry.as_bytes(),
            initial_grant_hash: *grant.as_bytes(),
        });
    }
    probes.sort_by_key(|p| p.medium_hash);
    Ok(probes)
}
