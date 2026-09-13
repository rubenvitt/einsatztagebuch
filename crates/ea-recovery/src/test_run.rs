//! Read-only cryptographic test kernel. Completion here still needs the native
//! runtime's current presence, exact restored source, signed audit and commit.
use crate::{
    FsArchiveSource, KeyInventory, RecoveryArchiveProbe, RecoveryKeyRole, RecoveryMedium,
    RecoverySigningBackup, RecoveryTestError, VerifiedRecoverySource,
};
use ea_crypto::{HpkeRecipient, object_hash};
use ea_trust::{SelectedRegistryHead, TrustAnchorV1};
use ea_types::{Hash32, ObjectHash};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct MediumResult {
    pub medium_id_hash: String,
    pub role: String,
    pub certificate_hash: String,
    pub expected_thumbprint: String,
    pub observed_thumbprint: String,
    pub test_kind: String,
    pub result: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct SampleResult {
    pub entry_hash: String,
    pub object_hash: String,
    pub grant_hash: String,
    pub sequence: u64,
    pub writer_certificate_hash: String,
    pub schema_id: String,
    pub schema_version: u64,
    pub suite_id: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct TestReport {
    pub schema_id: String,
    pub test_id: String,
    pub source_envelope_hash: String,
    pub source_machine: String,
    pub target_machine: String,
    pub target_installation: String,
    pub anchor_hash: String,
    pub archive_inventory_hash: String,
    pub tip_sequence: u64,
    pub tip_entry_hash: String,
    pub registry_version: u64,
    pub registry_head_hash: String,
    pub proposed_sequence: u64,
    pub effective_now: i64,
    pub release_version: String,
    pub schema_versions: Vec<String>,
    pub suite_versions: Vec<String>,
    pub media: Vec<MediumResult>,
    pub samples: Vec<SampleResult>,
    pub result: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}
pub enum RecoveryMediumCheck {
    Passed {
        observed: ea_types::KeyThumbprint,
    },
    Missing,
    Failed {
        observed: Option<ea_types::KeyThumbprint>,
        error: RecoveryTestError,
    },
}
pub struct RecoveryTestRun<'a> {
    run_id: [u8; 16],
    scope: &'a VerifiedRecoverySource,
    keys: &'a KeyInventory,
    head: &'a SelectedRegistryHead,
    anchor: &'a TrustAnchorV1,
    probe: RecoveryArchiveProbe<'a>,
    machine: ea_key_provider::MeasuredMachineIdentity,
    installation: Hash32,
    results: BTreeMap<ObjectHash, MediumResult>,
    samples: BTreeMap<ObjectHash, SampleResult>,
    full_archive: bool,
    failed: bool,
    failures: BTreeMap<ObjectHash, (RecoveryTestError, Option<ea_types::KeyThumbprint>)>,
}
pub enum RecoveryRunOutcome {
    Completed(CompletedRecoveryRun),
    Failed(FailedRecoveryRun),
}
pub struct FailedRecoveryRun {
    exact: Vec<u8>,
    machine: Hash32,
}
impl FailedRecoveryRun {
    pub fn exact_report(&self) -> &[u8] {
        &self.exact
    }
    pub fn machine_fingerprint(&self) -> Hash32 {
        self.machine
    }
}
pub struct CompletedRecoveryRun {
    exact: Vec<u8>,
    machine: Hash32,
}
impl CompletedRecoveryRun {
    pub fn exact_report(&self) -> &[u8] {
        &self.exact
    }
    pub fn machine_fingerprint(&self) -> Hash32 {
        self.machine
    }
    pub fn context_hash(&self) -> Hash32 {
        report_context(&self.exact)
    }
}
pub(crate) fn report_context(exact: &[u8]) -> Hash32 {
    let mut input = b"EINSATZARCHIV-RECOVERY-REPORT-CONTEXT-v1".to_vec();
    input.extend_from_slice(exact);
    Hash32::try_from(object_hash(&input).as_bytes().as_slice()).expect("hash width")
}
impl<'a> RecoveryTestRun<'a> {
    pub fn new(
        scope: &'a VerifiedRecoverySource,
        source: &'a FsArchiveSource,
        anchor: &'a TrustAnchorV1,
        keys: &'a KeyInventory,
        head: &'a SelectedRegistryHead,
        installation: Hash32,
    ) -> Result<Self, RecoveryTestError> {
        let f = scope.core().fields();
        if f.anchor_hash != *anchor.trust_anchor_hash().as_bytes()
            || f.inventory_hash != *keys.exact_hash().as_bytes()
            || f.archive_inventory_hash != crate::recovery_archive_inventory_hash(source)?
            || f.registry_version != head.registry_version().get()
            || f.registry_head != *head.registry_head_hash().as_bytes()
            || f.proposed_sequence != head.proposed_sequence().get()
            || head.preexisting_effective_now().value().get() < f.effective_now
            || installation == Hash32::ZERO
        {
            return Err(RecoveryTestError::Source);
        }
        let machine = ea_key_provider::measure_native_machine_identity()
            .map_err(|_| RecoveryTestError::Machine)?;
        if machine.fingerprint().as_bytes() == &f.source_machine {
            return Err(RecoveryTestError::Machine);
        }
        let probe =
            RecoveryArchiveProbe::verify(source, anchor, head.preexisting_effective_now().value())?;
        let mut run_id = [0; 16];
        getrandom::fill(&mut run_id).map_err(|_| RecoveryTestError::Entropy)?;
        Ok(Self {
            run_id,
            scope,
            keys,
            head,
            anchor,
            probe,
            machine,
            installation,
            results: BTreeMap::new(),
            samples: BTreeMap::new(),
            full_archive: false,
            failed: false,
            failures: BTreeMap::new(),
        })
    }
    pub fn run_id(&self) -> [u8; 16] {
        self.run_id
    }
    pub fn medium_check(&self, id: ObjectHash) -> Result<RecoveryMediumCheck, RecoveryTestError> {
        if !self
            .keys
            .media()
            .iter()
            .any(|m| m.pseudonymous_id_hash() == id)
        {
            return Err(RecoveryTestError::Inventory);
        }
        if let Some((error, observed)) = self.failures.get(&id) {
            return Ok(RecoveryMediumCheck::Failed {
                observed: *observed,
                error: *error,
            });
        }
        if let Some(result) = self.results.get(&id) {
            let observed =
                hex::decode(&result.observed_thumbprint).map_err(|_| RecoveryTestError::Source)?;
            return Ok(RecoveryMediumCheck::Passed {
                observed: ea_types::KeyThumbprint::try_from(observed.as_slice())
                    .map_err(|_| RecoveryTestError::Source)?,
            });
        }
        Ok(RecoveryMediumCheck::Missing)
    }
    fn medium(&self, id: ObjectHash) -> Result<&RecoveryMedium, RecoveryTestError> {
        if self.results.contains_key(&id) {
            return Err(RecoveryTestError::Inventory);
        }
        self.keys
            .media()
            .iter()
            .find(|m| m.pseudonymous_id_hash() == id)
            .ok_or(RecoveryTestError::Inventory)
    }
    pub fn test_signing(
        &mut self,
        id: ObjectHash,
        backup: &dyn RecoverySigningBackup,
    ) -> Result<(), RecoveryTestError> {
        let result = self.test_signing_inner(id, backup);
        if let Err(error) = result {
            let observed = backup.public_key().ok().map(|key| key.thumbprint());
            self.record_medium_failure(id, error, observed)?;
        }
        result
    }
    fn test_signing_inner(
        &mut self,
        id: ObjectHash,
        backup: &dyn RecoverySigningBackup,
    ) -> Result<(), RecoveryTestError> {
        let medium = self.medium(id)?;
        let proof = if (medium.role() == RecoveryKeyRole::Root
            && medium.certificate().as_bytes()
                == self.head.root_certificate_object_hash().as_bytes())
            || self
                .head
                .active_certificate_fields(medium.certificate())
                .is_some()
        {
            crate::verify_signing_backup(self.head, medium, backup)?
        } else {
            let past = crate::source_verification::historical_signing_authority(
                self.probe.inventory(),
                self.anchor,
                medium,
                self.head.registry_version(),
                self.head.preexisting_effective_now().value(),
            )
            .ok_or(RecoveryTestError::Role)?;
            crate::verify_historical_signing_backup(&past, medium, backup)?
        };
        let result = medium_result(medium, proof.key_thumbprint());
        self.results.insert(id, result);
        Ok(())
    }
    pub fn test_recovery(
        &mut self,
        id: ObjectHash,
        key: &dyn HpkeRecipient,
    ) -> Result<(), RecoveryTestError> {
        let result = self.test_recovery_inner(id, key);
        if let Err(error) = result {
            let observed = crate::recipient_key_thumbprint(key).ok();
            self.record_medium_failure(id, error, observed)?;
        }
        result
    }
    fn test_recovery_inner(
        &mut self,
        id: ObjectHash,
        key: &dyn HpkeRecipient,
    ) -> Result<(), RecoveryTestError> {
        let medium = self.medium(id)?;
        if medium.role() != RecoveryKeyRole::RecoveryRecipient {
            return Err(RecoveryTestError::Role);
        }
        let p = self
            .scope
            .core()
            .fields()
            .probes
            .iter()
            .find(|p| p.medium_hash == *id.as_bytes())
            .ok_or(RecoveryTestError::Incomplete)?;
        let tested = self.probe.test_recovery_medium(
            medium,
            ea_types::EntryHash::try_from(p.setup_entry_hash.as_slice())
                .map_err(|_| RecoveryTestError::Source)?,
            ObjectHash::try_from(p.initial_grant_hash.as_slice())
                .map_err(|_| RecoveryTestError::Source)?,
            key,
        )?;
        let result = medium_result(medium, medium.expected_thumbprint());
        self.full_archive |= tested.full_archive_verified();
        for s in tested.samples() {
            self.samples
                .entry(
                    ObjectHash::try_from(s.entry_hash().as_bytes().as_slice()).expect("hash width"),
                )
                .or_insert_with(|| SampleResult {
                    entry_hash: hex::encode(s.entry_hash().as_bytes()),
                    object_hash: hex::encode(s.object_hash().as_bytes()),
                    grant_hash: hex::encode(s.grant_hash().as_bytes()),
                    sequence: s.sequence().get(),
                    writer_certificate_hash: hex::encode(s.writer_certificate().as_bytes()),
                    schema_id: s.schema_id().to_owned(),
                    schema_version: s.schema_version(),
                    suite_id: s.suite_id().to_owned(),
                });
        }
        self.results.insert(id, result);
        Ok(())
    }
    fn require_complete(&self) -> Result<(), RecoveryTestError> {
        if self.failed
            || self.results.len() != self.keys.media().len()
            || !self.full_archive
            || self.samples.is_empty()
        {
            return Err(RecoveryTestError::Incomplete);
        }
        let mut required = BTreeSet::new();
        for entry in self.probe.inventory().entries() {
            required.insert(hex::encode(entry.value().entry_hash().as_bytes()));
        }
        if required
            .iter()
            .any(|entry| !self.samples.values().any(|s| &s.entry_hash == entry))
        {
            return Err(RecoveryTestError::Incomplete);
        }
        Ok(())
    }
    pub fn finish(self) -> Result<CompletedRecoveryRun, RecoveryTestError> {
        self.require_complete()?;
        self.into_report("complete", None)
    }
    pub fn finish_report(self) -> Result<RecoveryRunOutcome, RecoveryTestError> {
        if self.require_complete().is_ok() {
            self.finish().map(RecoveryRunOutcome::Completed)
        } else {
            self.finish_failed().map(RecoveryRunOutcome::Failed)
        }
    }

    /// Failure recording can never promote a medium or mint completion.
    pub fn record_medium_failure(
        &mut self,
        id: ObjectHash,
        error: RecoveryTestError,
        observed: Option<ea_types::KeyThumbprint>,
    ) -> Result<(), RecoveryTestError> {
        self.failed = true;
        if !self
            .keys
            .media()
            .iter()
            .any(|m| m.pseudonymous_id_hash() == id)
        {
            return Err(RecoveryTestError::Inventory);
        }
        self.failures.entry(id).or_insert((error, observed));
        Ok(())
    }

    /// Retains every expected medium, including missing and failed inputs.
    /// A successful run cannot be relabelled through this failure-only edge.
    pub fn finish_failed(mut self) -> Result<FailedRecoveryRun, RecoveryTestError> {
        if self.require_complete().is_ok() {
            return Err(RecoveryTestError::Incomplete);
        }
        for medium in self.keys.media() {
            let id = medium.pseudonymous_id_hash();
            if let Some((error, observed)) = self.failures.get(&id) {
                let mut result = medium_result(medium, medium.expected_thumbprint());
                result.observed_thumbprint =
                    observed.map_or_else(String::new, |key| hex::encode(key.as_bytes()));
                result.result = "failed".into();
                result.error_code = Some(error.code().into());
                self.results.insert(id, result);
            } else if let std::collections::btree_map::Entry::Vacant(entry) = self.results.entry(id)
            {
                let mut result = medium_result(medium, medium.expected_thumbprint());
                result.observed_thumbprint.clear();
                result.result = "missing".into();
                result.error_code = Some(RecoveryTestError::Incomplete.code().into());
                entry.insert(result);
            }
        }
        // Diagnostic failures make no sample-coverage claim.
        self.samples.clear();
        let report = self.into_report("failed", Some(RecoveryTestError::Incomplete))?;
        Ok(FailedRecoveryRun {
            exact: report.exact,
            machine: report.machine,
        })
    }

    fn into_report(
        self,
        overall: &str,
        error: Option<RecoveryTestError>,
    ) -> Result<CompletedRecoveryRun, RecoveryTestError> {
        if ea_key_provider::measure_native_machine_identity()
            .map_err(|_| RecoveryTestError::Machine)?
            != self.machine
        {
            return Err(RecoveryTestError::Machine);
        }
        let mut buckets = BTreeMap::new();
        for sample in self.samples.into_values() {
            let key = (
                sample.schema_id.clone(),
                sample.schema_version,
                sample.suite_id.clone(),
                sample.writer_certificate_hash.clone(),
            );
            let current = buckets.entry(key).or_insert(sample.clone());
            if sample.sequence < current.sequence {
                *current = sample;
            }
        }
        let f = self.scope.core().fields();
        let report = TestReport {
            schema_id: "ea.recovery-test/v1".into(),
            test_id: hex::encode(self.run_id),
            source_envelope_hash: hex::encode(self.scope.envelope_hash().as_bytes()),
            source_machine: hex::encode(f.source_machine),
            target_machine: hex::encode(self.machine.fingerprint().as_bytes()),
            target_installation: hex::encode(self.installation.as_bytes()),
            anchor_hash: hex::encode(f.anchor_hash),
            archive_inventory_hash: hex::encode(f.archive_inventory_hash),
            tip_sequence: f.tip_sequence,
            tip_entry_hash: hex::encode(f.tip_entry_hash),
            registry_version: self.head.registry_version().get(),
            registry_head_hash: hex::encode(self.head.registry_head_hash().as_bytes()),
            proposed_sequence: self.head.proposed_sequence().get(),
            effective_now: self.head.preexisting_effective_now().value().get(),
            release_version: env!("CARGO_PKG_VERSION").into(),
            schema_versions: ea_schema::SchemaRegistry::v1()
                .schemas()
                .iter()
                .map(|s| format!("{}/v{}", s.schema_id(), s.schema_version()))
                .collect(),
            suite_versions: vec![ea_schema::SUITE_ID_V1.into()],
            media: self.results.into_values().collect(),
            samples: buckets.into_values().collect(),
            result: overall.into(),
            error_code: error.map(|error| error.code().into()),
        };
        let exact = serde_json::to_vec(&report).map_err(|_| RecoveryTestError::Source)?;
        Ok(CompletedRecoveryRun {
            exact,
            machine: self.machine.fingerprint(),
        })
    }
}
fn medium_result(medium: &RecoveryMedium, observed: ea_types::KeyThumbprint) -> MediumResult {
    MediumResult {
        medium_id_hash: hex::encode(medium.pseudonymous_id_hash().as_bytes()),
        role: medium.role().label().into(),
        certificate_hash: hex::encode(medium.certificate().as_bytes()),
        expected_thumbprint: hex::encode(medium.expected_thumbprint().as_bytes()),
        observed_thumbprint: hex::encode(observed.as_bytes()),
        test_kind: match medium.test_kind() {
            crate::RecoveryTestKind::SignatureChallenge => "signatureChallenge",
            crate::RecoveryTestKind::RecoveryDecrypt => "recoveryDecrypt",
            crate::RecoveryTestKind::ProviderPresence => "providerPresence",
        }
        .into(),
        result: "passed".into(),
        error_code: None,
    }
}
