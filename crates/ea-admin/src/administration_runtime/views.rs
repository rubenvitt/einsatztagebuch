//! Read-only native admission. A view never grants signing authority.
use crate::{
    RegistryWindow,
    operator_runtime::{OperatorRuntime, OperatorRuntimeError},
    registry::{RegistryEventFactory, RegistryWorkflowError},
    revocation::{RevocationEffect, plan_revocation},
};
use ea_format::{OperatorRoleV1, PolicyFieldsV1};
use ea_trust::{EffectiveWriterTransitionV1, SelectedRegistryHead};
use ea_types::{CertificateHash, ObjectHash};

/// Borrowed from the same freshly reopened native runtime, without Root access.
pub struct AdministrationView<'a> {
    runtime: &'a OperatorRuntime,
}
impl AdministrationView<'_> {
    pub fn head(&self) -> &SelectedRegistryHead {
        self.runtime.head()
    }
    pub fn policy(&self) -> &PolicyFieldsV1 {
        self.head().policy_fields()
    }
    pub fn registry_age_ms(&self) -> u64 {
        let age = i128::from(self.head().preexisting_effective_now().value().get())
            - i128::from(self.head().issued_at().get());
        u64::try_from(age.max(0)).unwrap_or(u64::MAX)
    }
    pub fn current_writer(&self) -> Option<CertificateHash> {
        self.head().current_writer_certificate_hash()
    }
    pub fn transition(&self) -> Option<&EffectiveWriterTransitionV1> {
        self.head().effective_writer_transition()
    }
    pub fn revocation_effect(
        &self,
        target: ObjectHash,
    ) -> Result<RevocationEffect, RegistryWorkflowError> {
        let audit = self.runtime.audit_service();
        let factory = RegistryEventFactory::new(self.head(), &audit, self.runtime.local_device());
        let (_, effect) = plan_revocation(
            &factory,
            RegistryWindow {
                effective_from_sequence: self.runtime.next_sequence(),
                valid_through_sequence: self.head().valid_through_sequence(),
                not_after: self.head().not_after(),
            },
            target,
        )?;
        Ok(effect)
    }
}

/// Refreshes the actual archive, persistent pins/time and native account before
/// exposing administrative diagnostics. No caller-provided clock or ready flag.
pub fn current_view(
    runtime: &mut OperatorRuntime,
) -> Result<AdministrationView<'_>, OperatorRuntimeError> {
    if runtime.config().role != OperatorRoleV1::OrganizationAdmin || runtime.config().authority {
        return Err(OperatorRuntimeError::Config);
    }
    runtime.refresh_for_action()?;
    let binding = runtime
        .head()
        .active_operator_binding_fields(runtime.config().binding_object_hash)
        .filter(|binding| {
            binding.operator_role == OperatorRoleV1::OrganizationAdmin
                && binding.device_certificate_hash == runtime.config().device_certificate_hash
        })
        .ok_or(ea_operator::OperatorError::BindingNotActive)?;
    if binding.organization_id != runtime.anchor().organization_id() {
        return Err(OperatorRuntimeError::Config);
    }
    Ok(AdministrationView { runtime })
}
