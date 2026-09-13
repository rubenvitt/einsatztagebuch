//! Operational documentation stays separate from native measurements.
use super::*;
use ea_crypto::{
    ContentType, GoLivePostureCore, GoLivePostureFields, VerificationContext, object_hash,
    verify_cose_sign1,
};
use ea_key_provider::{HostOsBuild, PostureCheck};
use ea_local_store::StoreValue;
use ea_types::{ChainId, OrganizationId};
use serde::{Deserialize, Serialize};

/// Hashes the exact public organizational evidence document, without retaining it.
pub fn evidence_reference_hash(exact: &[u8]) -> Result<ObjectHash, OperatorRuntimeError> {
    if exact.is_empty() || exact.len() > 1024 * 1024 {
        return Err(OperatorRuntimeError::Config);
    }
    Ok(object_hash(exact))
}

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct TargetWire {
    organization_id: String,
    chain_id: String,
    installation_id: String,
    account_hash: String,
    device_id: String,
    certificate_hash: String,
    binding_hash: String,
    os_family: u8,
    os_build_hash: String,
    unknown_mask: u8,
}
/// Public exchange claims. Import compares these against independent local facts.
pub struct PostureTargetContext(TargetWire);
impl PostureTargetContext {
    pub fn from_json(bytes: &[u8]) -> Result<Self, OperatorRuntimeError> {
        if bytes.len() > 4096 {
            return Err(denied());
        }
        let wire: TargetWire = serde_json::from_slice(bytes).map_err(|_| denied())?;
        if !(1..=3).contains(&wire.os_family) || !(1..=15).contains(&wire.unknown_mask) {
            return Err(denied());
        }
        Ok(Self(wire))
    }
    pub fn to_json(&self) -> Result<Vec<u8>, OperatorRuntimeError> {
        serde_json::to_vec(&self.0).map_err(|_| denied())
    }
}
/// Minted only after checking actual measurements and exact durable evidence.
pub struct VerifiedPostureAdmission<'a> {
    runtime: &'a OperatorRuntime,
    documented_mask: u8,
    document_hash: Option<ObjectHash>,
    reference_hash: Option<ObjectHash>,
    valid_until: Option<UnixMillis>,
}
impl VerifiedPostureAdmission<'_> {
    pub fn documented_unknown_mask(&self) -> u8 {
        self.documented_mask
    }
    pub fn document_hash(&self) -> Option<ObjectHash> {
        self.document_hash
    }
    pub fn evidence_reference_hash(&self) -> Option<ObjectHash> {
        self.reference_hash
    }
    pub fn valid_until(&self) -> Option<UnixMillis> {
        self.valid_until
    }
    pub(crate) fn current_documented_mask(&self, report: &DevicePostureReport) -> u8 {
        let Ok(current) = self.runtime.posture_admission_for_report() else {
            return 0;
        };
        if self.document_hash != current.document_hash
            || self.documented_mask != current.documented_mask
            || self.runtime.device_posture_report().ok().as_ref() != Some(report)
        {
            return 0;
        }
        current.documented_mask
    }
}
fn denied() -> OperatorRuntimeError {
    OperatorRuntimeError::Posture
}
fn unknown_mask(report: &DevicePostureReport) -> Result<u8, OperatorRuntimeError> {
    let mut mask = 0;
    for (index, requirement) in PostureRequirement::ALL.into_iter().enumerate() {
        match report.check(requirement) {
            PostureCheck::Fail { .. } => return Err(denied()),
            PostureCheck::Unknown { .. } => mask |= 1 << index,
            PostureCheck::Pass { .. } => {}
        }
    }
    Ok(mask)
}
fn bytes<const N: usize>(value: &str) -> Result<[u8; N], OperatorRuntimeError> {
    hex::decode(value)
        .map_err(|_| denied())?
        .try_into()
        .map_err(|_| denied())
}
fn envelope(core: &[u8], signature: &[u8]) -> Result<Vec<u8>, OperatorRuntimeError> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(2)
        .and_then(|e| e.bytes(core))
        .and_then(|e| e.bytes(signature))
        .map_err(|_| denied())?;
    Ok(e.into_writer())
}
fn parse_envelope(exact: &[u8]) -> Result<(GoLivePostureCore, Vec<u8>), OperatorRuntimeError> {
    if exact.len() > 8192 {
        return Err(denied());
    }
    let mut d = minicbor::Decoder::new(exact);
    if d.array().map_err(|_| denied())? != Some(2) {
        return Err(denied());
    }
    let core = d.bytes().map_err(|_| denied())?;
    let signature = d.bytes().map_err(|_| denied())?;
    if d.position() != exact.len() || envelope(core, signature)? != exact {
        return Err(denied());
    }
    Ok((
        GoLivePostureCore::from_exact(core).map_err(|_| denied())?,
        signature.to_vec(),
    ))
}
impl OperatorRuntime {
    fn measured_posture(&self) -> Result<(DevicePostureReport, u8), OperatorRuntimeError> {
        self.ensure_fresh_context()?;
        self.native.ensure_session_active()?;
        let report = self.device_posture_report()?;
        let mask = unknown_mask(&report)?;
        self.ensure_fresh_context()?;
        Ok((report, mask))
    }
    fn build_identity(&self) -> Result<HostOsBuild, OperatorRuntimeError> {
        let build = self.posture.os_build_identity().map_err(|_| denied())?;
        self.ensure_fresh_context()?;
        self.native.ensure_session_active()?;
        Ok(build)
    }
    fn target_wire(&self, mask: u8, build: HostOsBuild) -> TargetWire {
        TargetWire {
            organization_id: hex::encode(self.anchor().organization_id().as_bytes()),
            chain_id: hex::encode(self.head.chain_id().as_bytes()),
            installation_id: hex::encode(self.native.installation_id().as_bytes()),
            account_hash: hex::encode(self.account_hash.as_bytes()),
            device_id: hex::encode(self.device_id.as_bytes()),
            certificate_hash: hex::encode(self.config.device_certificate_hash.as_bytes()),
            binding_hash: hex::encode(self.config.binding_object_hash.as_bytes()),
            os_family: build.family(),
            os_build_hash: hex::encode(build.hash().as_bytes()),
            unknown_mask: mask,
        }
    }
    pub fn posture_target_context(&self) -> Result<PostureTargetContext, OperatorRuntimeError> {
        let (_, mask) = self.measured_posture()?;
        if mask == 0 {
            return Err(denied());
        }
        let build = self.build_identity()?;
        Ok(PostureTargetContext(self.target_wire(mask, build)))
    }
    /// Separate local rollback guard; this does not alter the signed trust floor.
    fn posture_now(&self, record: bool) -> Result<UnixMillis, OperatorRuntimeError> {
        self.ensure_fresh_context()?;
        let wall = fresh_wall_clock()?;
        let key = StoreValue::Blob(self.native.installation_id().as_bytes().to_vec());
        let observe =
            |tx: &ea_local_store::StoreTransaction<'_>| -> Result<(), OperatorRuntimeError> {
                if let Some(row) = tx.query_row(
                    "SELECT last_observed_wall FROM go_live_posture_clock WHERE installation_id=?1",
                    std::slice::from_ref(&key),
                )? && wall.get() < row.integer(0)?
                {
                    return Err(denied());
                }
                tx.execute("INSERT INTO go_live_posture_clock(installation_id,last_observed_wall) VALUES(?1,?2) ON CONFLICT(installation_id) DO UPDATE SET last_observed_wall=excluded.last_observed_wall",&[key.clone(),StoreValue::Integer(wall.get())])?;
                Ok(())
            };
        if record {
            self.database.transaction(observe)?;
        } else if let Some(row) = self.database.query_row(
            "SELECT last_observed_wall FROM go_live_posture_clock WHERE installation_id=?1",
            &[key],
        )? && wall.get() < row.integer(0)?
        {
            return Err(denied());
        }
        let elapsed = i64::try_from(self.opened.elapsed().as_millis()).map_err(|_| denied())?;
        let monotonic = self
            .head
            .preexisting_effective_now()
            .value()
            .get()
            .checked_add(elapsed)
            .ok_or_else(denied)?;
        Ok(UnixMillis::new(wall.get().max(monotonic)))
    }
    fn documentation_environment(&self) -> Result<(), OperatorRuntimeError> {
        self.measured_posture()?;
        self.build_identity()?;
        if self.config.role != OperatorRoleV1::OrganizationAdmin {
            return Err(denied());
        }
        Ok(())
    }
    fn check_document_context(
        &self,
        fields: &GoLivePostureFields,
        now: UnixMillis,
    ) -> Result<(), OperatorRuntimeError> {
        if fields.organization_id != self.anchor().organization_id()
            || fields.chain_id != self.head.chain_id()
            || fields.registry_version != self.head.registry_version()
            || fields.registry_head_hash != self.head.registry_head_hash()
            || fields.issued_sequence > self.head.proposed_sequence()
            || now < fields.issued_at
            || now >= fields.valid_until
            || fields.valid_until > self.head.not_after()
        {
            return Err(denied());
        }
        let certificate = self
            .head
            .active_certificate_fields(fields.issuer_certificate_hash)
            .ok_or_else(denied)?;
        if certificate.certificate_kind != CertificateKindV1::OrganizationAdmin {
            return Err(denied());
        }
        let issuer = self
            .head
            .active_operator_binding_fields(fields.issuer_binding_hash)
            .ok_or_else(denied)?;
        if issuer.device_certificate_hash != fields.issuer_certificate_hash
            || issuer.operator_role != OperatorRoleV1::OrganizationAdmin
        {
            return Err(denied());
        }
        let target = self
            .head
            .active_operator_binding_fields(fields.target_binding_hash)
            .ok_or_else(denied)?;
        let target_cert = self
            .head
            .active_certificate_fields(fields.target_certificate_hash)
            .ok_or_else(denied)?;
        if target.device_certificate_hash != fields.target_certificate_hash
            || target.os_account_binding_hash != fields.target_account_hash
            || target_cert.device_id != fields.target_device_id
        {
            return Err(denied());
        }
        Ok(())
    }
    pub fn issue_posture_document(
        &self,
        target: &PostureTargetContext,
        reference: ObjectHash,
        lifetime_ms: i64,
    ) -> Result<Vec<u8>, OperatorRuntimeError> {
        self.documentation_environment()?;
        if !(1..=ea_crypto::GO_LIVE_POSTURE_MAX_LIFETIME_MS).contains(&lifetime_ms) {
            return Err(denied());
        }
        let issued = self.posture_now(true)?;
        let until = UnixMillis::new(
            issued
                .get()
                .checked_add(lifetime_ms)
                .ok_or_else(denied)?
                .min(self.head.not_after().get()),
        );
        let t = &target.0;
        macro_rules! id {
            ($kind:ty,$value:expr,$n:expr) => {
                <$kind>::try_from(bytes::<$n>($value)?.as_slice()).map_err(|_| denied())?
            };
        }
        let core = GoLivePostureCore::new(GoLivePostureFields {
            organization_id: id!(OrganizationId, &t.organization_id, 16),
            chain_id: id!(ChainId, &t.chain_id, 16),
            target_installation_id: id!(Hash32, &t.installation_id, 32),
            target_account_hash: id!(Hash32, &t.account_hash, 32),
            target_device_id: id!(DeviceId, &t.device_id, 16),
            target_certificate_hash: id!(CertificateHash, &t.certificate_hash, 32),
            target_binding_hash: id!(ObjectHash, &t.binding_hash, 32),
            os_family: t.os_family,
            os_build_hash: id!(ObjectHash, &t.os_build_hash, 32),
            documented_unknown_mask: t.unknown_mask,
            evidence_reference_hash: reference,
            issuer_certificate_hash: self.config.device_certificate_hash,
            issuer_binding_hash: self.config.binding_object_hash,
            registry_version: self.head.registry_version(),
            registry_head_hash: self.head.registry_head_hash(),
            issued_sequence: self.head.proposed_sequence(),
            issued_at: issued,
            valid_until: until,
        })
        .map_err(|_| denied())?;
        self.check_document_context(core.fields(), issued)?;
        let audit = self.audit_service();
        let presence = DocumentationPresence(self);
        let service = OperatorBindingService::new(&self.head, &audit, self.local_device);
        let session = service.verify_session_for_context(
            VerifySessionRequest {
                database: &self.database,
                binding_object_hash: self.config.binding_object_hash,
                device_certificate_hash: self.config.device_certificate_hash,
                role: self.config.role,
                purpose: ReauthPurpose::GoLivePostureDocumentation,
                account: self.native.clone(),
                authenticator: &presence,
            },
            core.digest(),
        )?;
        if session.proof().context_hash() != Some(core.digest()) {
            return Err(denied());
        }
        self.documentation_environment()?;
        let signature = self.signer.sign(
            &self.signer.handle(SecretPurpose::WriterSigningKey),
            ContentType::GoLivePostureDigest,
            self.config.device_certificate_hash,
            core.digest().as_bytes(),
        )?;
        let context = VerificationContext::go_live_posture_document(core.exact_bytes())
            .map_err(|_| denied())?;
        verify_cose_sign1(signature.as_bytes(), &self.head, &context).map_err(|_| denied())?;
        self.documentation_environment()?;
        self.check_document_context(core.fields(), self.posture_now(true)?)?;
        let exact = envelope(core.exact_bytes(), signature.as_bytes())?;
        let hash = StoreValue::Blob(object_hash(&exact).as_bytes().to_vec());
        self.database.transaction(|tx| -> Result<(), OperatorRuntimeError> {
            tx.execute(
                "INSERT OR IGNORE INTO go_live_posture_issued(object_hash,exact_envelope) VALUES(?1,?2)",
                &[hash.clone(), StoreValue::Blob(exact.clone())],
            )?;
            let stored = tx.query_row(
                "SELECT exact_envelope FROM go_live_posture_issued WHERE object_hash=?1",
                std::slice::from_ref(&hash),
            )?.ok_or_else(denied)?;
            if stored.blob(0)? != exact {
                return Err(denied());
            }
            Ok(())
        })?;
        self.documentation_environment()?;
        let fresh = self.reopened_for_action()?;
        fresh.documentation_environment()?;
        self.ensure_same_authority_as(&fresh)?;
        ea_operator::verify_current_session(
            fresh.head(),
            self.config.device_certificate_hash,
            self.config.role,
            session.proof(),
            ReauthPurpose::GoLivePostureDocumentation,
            self.native.as_ref(),
        )?;
        self.native.record_verified_session(&session)?;
        Ok(exact)
    }
    fn verify_posture_document(
        &self,
        exact: &[u8],
        mask: u8,
        build: HostOsBuild,
        now: UnixMillis,
    ) -> Result<VerifiedPostureAdmission<'_>, OperatorRuntimeError> {
        let (core, signature) = parse_envelope(exact)?;
        let f = core.fields();
        self.check_document_context(f, now)?;
        if f.target_installation_id != self.native.installation_id()
            || f.target_account_hash != self.account_hash
            || f.target_device_id != self.device_id
            || f.target_certificate_hash != self.config.device_certificate_hash
            || f.target_binding_hash != self.config.binding_object_hash
            || f.os_family != build.family()
            || f.os_build_hash != build.hash()
            || mask & !f.documented_unknown_mask != 0
        {
            return Err(denied());
        }
        let context = VerificationContext::go_live_posture_document(core.exact_bytes())
            .map_err(|_| denied())?;
        verify_cose_sign1(&signature, &self.head, &context).map_err(|_| denied())?;
        Ok(VerifiedPostureAdmission {
            runtime: self,
            documented_mask: mask,
            document_hash: Some(object_hash(exact)),
            reference_hash: Some(f.evidence_reference_hash),
            valid_until: Some(f.valid_until),
        })
    }
    pub fn import_posture_document(&self, exact: &[u8]) -> Result<(), OperatorRuntimeError> {
        let (_, mask) = self.measured_posture()?;
        let build = self.build_identity()?;
        self.verify_posture_document(exact, mask, build, self.posture_now(true)?)?;
        let (core, _) = parse_envelope(exact)?;
        if core.fields().documented_unknown_mask != mask {
            return Err(denied());
        }
        let hash = object_hash(exact);
        self.database.transaction(|tx| -> Result<(), OperatorRuntimeError> {
            if let Some(row) = tx.query_row(
                "SELECT object_hash,issued_at,exact_envelope FROM go_live_posture_evidence WHERE singleton=0", &[],
            )? {
                if row.blob(0)? == hash.as_bytes() {
                    return if row.blob(2)? == exact { Ok(()) } else { Err(denied()) };
                }
                if row.integer(1)? >= core.fields().issued_at.get() {
                    return Err(denied());
                }
            }
            tx.execute(
                "INSERT INTO go_live_posture_evidence(singleton,object_hash,issued_at,exact_envelope) VALUES(0,?1,?2,?3) ON CONFLICT(singleton) DO UPDATE SET object_hash=excluded.object_hash,issued_at=excluded.issued_at,exact_envelope=excluded.exact_envelope",
                &[
                    StoreValue::Blob(hash.as_bytes().to_vec()),
                    StoreValue::Integer(core.fields().issued_at.get()),
                    StoreValue::Blob(exact.to_vec()),
                ],
            )?;
            Ok(())
        })?;
        self.posture_admission()?;
        Ok(())
    }
    pub fn posture_admission(&self) -> Result<VerifiedPostureAdmission<'_>, OperatorRuntimeError> {
        self.posture_admission_inner(true)
    }
    pub(super) fn posture_admission_for_report(
        &self,
    ) -> Result<VerifiedPostureAdmission<'_>, OperatorRuntimeError> {
        self.posture_admission_inner(false)
    }
    fn posture_admission_inner(
        &self,
        record: bool,
    ) -> Result<VerifiedPostureAdmission<'_>, OperatorRuntimeError> {
        let (_, mask) = self.measured_posture()?;
        if mask == 0 {
            return Ok(VerifiedPostureAdmission {
                runtime: self,
                documented_mask: 0,
                document_hash: None,
                reference_hash: None,
                valid_until: None,
            });
        }
        let build = self.build_identity()?;
        let row = self
            .database
            .query_row(
                "SELECT object_hash,exact_envelope FROM go_live_posture_evidence WHERE singleton=0",
                &[],
            )?
            .ok_or_else(denied)?;
        let exact = row.blob(1)?;
        if object_hash(exact).as_bytes() != row.blob(0)? {
            return Err(denied());
        }
        let admission =
            self.verify_posture_document(exact, mask, build, self.posture_now(record)?)?;
        self.ensure_fresh_context()?;
        Ok(admission)
    }
}
struct DocumentationPresence<'a>(&'a OperatorRuntime);
impl OperatorPresence for DocumentationPresence<'_> {
    fn prove_presence_and_sign(&self, challenge: &[u8]) -> Result<[u8; 64], OperatorError> {
        prove_with_deadline(self.0.native.as_ref(), challenge, || {
            self.0.documentation_environment()
        })
    }
}
