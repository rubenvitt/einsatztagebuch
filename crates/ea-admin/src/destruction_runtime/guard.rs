//! Additional host invalidation composed with actual native authority checks.
use super::*;
use crate::operator_runtime::destruction_authority::HeldDestructionAuthority;
use ea_destruction::LocalActionAuthorityGuard;
use ea_local_store::StoreTransaction;
pub(super) struct RuntimeActionGuard<'a> {
    native: HeldDestructionAuthority<'a>,
    host: Option<&'a dyn DestructionHostGuard>,
}
impl DestructionRuntime {
    pub(super) fn action_guard(&self) -> Result<RuntimeActionGuard<'_>, Error> {
        self.check_host()?;
        let native = HeldDestructionAuthority::capture(&self.controller, &self.custodian)
            .map_err(|_| Error::Session)?;
        self.check_host()?;
        Ok(RuntimeActionGuard {
            native,
            host: self.host_guard.as_deref(),
        })
    }
    pub(super) fn action_guard_before(
        &self,
        cutoff: ea_types::UnixMillis,
    ) -> Result<RuntimeActionGuard<'_>, Error> {
        self.check_host()?;
        let native =
            HeldDestructionAuthority::capture_before(&self.controller, &self.custodian, cutoff)
                .map_err(|_| Error::Session)?;
        self.check_host()?;
        Ok(RuntimeActionGuard {
            native,
            host: self.host_guard.as_deref(),
        })
    }
}
impl RuntimeActionGuard<'_> {
    fn host(&self) -> Result<(), DestructionError> {
        self.host.map_or(Ok(()), |guard| {
            guard.require_open().map_err(|_| DestructionError::Operator)
        })
    }
}
impl LocalActionAuthorityGuard for RuntimeActionGuard<'_> {
    fn check_in(&mut self, tx: &StoreTransaction<'_>) -> Result<(), DestructionError> {
        self.host()?;
        self.native.check_in(tx)?;
        self.host()
    }
    fn check_before_effect(&mut self) -> Result<(), DestructionError> {
        self.host()?;
        self.native.check_before_effect()?;
        self.host()
    }
}
