use super::mailbox::{Mailbox, MediumChoice};
use ea_admin::recovery_test_runtime::{
    RecoveryMediumInput, RecoveryMediumObservation, RecoveryMediumRequest, RecoveryMediumStatus,
    RecoveryTestAbort, RecoveryTestGuide, RecoveryTestMediumSource,
};
use ea_ui_contracts::{RecoveryMediumObservationView, RecoveryMediumRequestView};
use std::sync::Arc;

pub(super) struct DesktopGuide {
    pub mailbox: Arc<Mailbox>,
    pub media: Vec<RecoveryTestMediumSource>,
    pub pending: Option<RecoveryMediumRequestView>,
}
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
impl RecoveryTestGuide for DesktopGuide {
    fn request_medium(
        &mut self,
        request: &RecoveryMediumRequest,
    ) -> Result<Option<RecoveryMediumInput>, RecoveryTestAbort> {
        self.ensure_active()?;
        let view = RecoveryMediumRequestView {
            run_id: hex(&request.run_id()),
            request_id: hex(request.request_id().as_bytes()),
            medium_id_hash: hex(request.medium_id_hash().as_bytes()),
            index: u32::try_from(request.index()).map_err(|_| RecoveryTestAbort)?,
            total: u32::try_from(request.total()).map_err(|_| RecoveryTestAbort)?,
            role_code: request.role().label().into(),
            certificate_hash: hex(request.certificate().as_bytes()),
            expected_thumbprint: hex(request.expected_thumbprint().as_bytes()),
            protection_code: request.protection() as u64,
            test_kind_code: match request.test_kind() {
                ea_recovery::RecoveryTestKind::SignatureChallenge => "signatureChallenge",
                ea_recovery::RecoveryTestKind::RecoveryDecrypt => "recoveryDecrypt",
                ea_recovery::RecoveryTestKind::ProviderPresence => "providerPresence",
            }
            .into(),
        };
        self.pending = Some(view.clone());
        let choice = self.mailbox.request(view)?;
        self.ensure_active()?;
        if choice == MediumChoice::Missing {
            return Ok(None);
        }
        Ok(self
            .media
            .iter()
            .find(|row| row.medium_id_hash == request.medium_id_hash())
            .map(|row| match &row.source {
                RecoveryMediumInput::Offline(source) => {
                    RecoveryMediumInput::Offline(source.clone())
                }
                RecoveryMediumInput::NativeSigningSlot(slot) => {
                    RecoveryMediumInput::NativeSigningSlot(*slot)
                }
            }))
    }
    fn medium_result(
        &mut self,
        result: &RecoveryMediumObservation,
    ) -> Result<(), RecoveryTestAbort> {
        self.ensure_active()?;
        let request = self.pending.take().ok_or(RecoveryTestAbort)?;
        if request.run_id != hex(&result.run_id())
            || request.request_id != hex(result.request_id().as_bytes())
            || request.medium_id_hash != hex(result.medium_id_hash().as_bytes())
        {
            return Err(RecoveryTestAbort);
        }
        self.mailbox.observe(RecoveryMediumObservationView {
            request,
            result_code: match result.status() {
                RecoveryMediumStatus::Passed => 0,
                RecoveryMediumStatus::Missing => 1,
                RecoveryMediumStatus::Failed => 2,
            },
            observed_thumbprint: result
                .observed_thumbprint()
                .map(|value| hex(value.as_bytes())),
            error_code: result.error_code().map(str::to_owned),
        })
    }
    fn ensure_active(&self) -> Result<(), RecoveryTestAbort> {
        self.mailbox.ensure_active()
    }
}
