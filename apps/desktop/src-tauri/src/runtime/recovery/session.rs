//! A private handoff of the same native Recovery proof, never a UI authority flag.
use super::{CommandError, Mailbox, error};
use ea_admin::recovery_test_runtime::{RecoverySessionObserver, RecoveryTestAbort};
use ea_operator::OperatorSessionProof;
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub(super) struct RoleSessionInbox {
    latest: Mutex<Option<(u64, Arc<OperatorSessionProof>)>>,
}
impl RoleSessionInbox {
    pub(super) fn for_epoch(
        &self,
        epoch: u64,
    ) -> Result<Option<Arc<OperatorSessionProof>>, CommandError> {
        let mut latest = self
            .latest
            .lock()
            .map_err(|_| error("EA-DESKTOP-RUNTIME-LOCK"))?;
        if latest
            .as_ref()
            .is_some_and(|(issued_epoch, _)| *issued_epoch != epoch || epoch & 1 != 0)
        {
            *latest = None;
        }
        Ok(latest.as_ref().map(|(_, proof)| proof.clone()))
    }
}

pub(super) struct SessionObserver {
    pub(super) epoch: u64,
    pub(super) mailbox: Arc<Mailbox>,
    pub(super) inbox: Arc<RoleSessionInbox>,
}
impl RecoverySessionObserver for SessionObserver {
    fn verified_session(
        &mut self,
        proof: Arc<OperatorSessionProof>,
    ) -> Result<(), RecoveryTestAbort> {
        self.mailbox.ensure_active()?;
        let mut latest = self.inbox.latest.lock().map_err(|_| RecoveryTestAbort)?;
        self.mailbox.ensure_active()?;
        let previous = latest.replace((self.epoch, proof));
        if let Err(error) = self.mailbox.ensure_active() {
            *latest = previous;
            return Err(error);
        }
        Ok(())
    }
}
