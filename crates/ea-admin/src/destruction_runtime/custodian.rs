//! Explicit independent Writer login; never a destruction action proof.
use super::*;

impl DestructionRuntime {
    /// Authenticate the configured Writer custodian with its own native Finalize
    /// presence. The proof remains internal; subsequent administrative actions
    /// must authenticate separately. An invalidated native watch is not replaced.
    pub fn authenticate_custodian(&mut self) -> Result<(), NativeDestructionError> {
        // An independent Writer login cannot preserve or create Admin authority.
        self.session = None;
        self.refresh()?;
        let session = self
            .custodian
            .reauthenticate_for(ReauthPurpose::Finalize)
            .map_err(|_| Error::Session)?;
        self.check_host()?;
        // Use the actual post-dialog selection, not the previously held time.
        let fresh = self
            .custodian
            .reopened_for_action()
            .map_err(|_| Error::Session)?;
        fresh.ensure_current().map_err(|_| Error::Session)?;
        self.custodian
            .ensure_same_authority_as(&fresh)
            .map_err(|_| Error::Session)?;
        ea_operator::verify_current_session(
            fresh.head(),
            fresh.config().device_certificate_hash,
            OperatorRoleV1::Writer,
            session.proof(),
            ReauthPurpose::Finalize,
            fresh.native().as_ref(),
        )
        .map_err(|_| Error::Session)?;
        // Recheck both identities, exact persisted time/Registry bounds and host
        // refusal after blocking account verification. Nothing escapes as a proof.
        self.require_same_fresh_action()?;
        drop(session);
        Ok(())
    }
}
