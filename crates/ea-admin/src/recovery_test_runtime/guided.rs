//! Public progress never contains medium names, provider locations or secrets.
use super::*;
use ea_recovery::{RecoveryKeyRole, RecoveryTestKind};
use ea_types::{CertificateHash, Hash32, KeyThumbprint};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryTestAbort;

pub struct RecoveryMediumRequest {
    pub(super) run_id: [u8; 16],
    pub(super) request_id: Hash32,
    pub(super) medium_id_hash: ObjectHash,
    pub(super) index: usize,
    pub(super) total: usize,
    pub(super) role: RecoveryKeyRole,
    pub(super) certificate: CertificateHash,
    pub(super) expected: KeyThumbprint,
    pub(super) protection: ea_format::KeyProtectionProfileV1,
    pub(super) test_kind: RecoveryTestKind,
}
impl RecoveryMediumRequest {
    pub fn run_id(&self) -> [u8; 16] {
        self.run_id
    }
    pub fn request_id(&self) -> Hash32 {
        self.request_id
    }
    pub fn medium_id_hash(&self) -> ObjectHash {
        self.medium_id_hash
    }
    /// One-based position in the exact expected inventory.
    pub fn index(&self) -> usize {
        self.index
    }
    pub fn total(&self) -> usize {
        self.total
    }
    pub fn role(&self) -> RecoveryKeyRole {
        self.role
    }
    pub fn certificate(&self) -> CertificateHash {
        self.certificate
    }
    pub fn expected_thumbprint(&self) -> KeyThumbprint {
        self.expected
    }
    pub fn protection(&self) -> ea_format::KeyProtectionProfileV1 {
        self.protection
    }
    pub fn test_kind(&self) -> RecoveryTestKind {
        self.test_kind
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryMediumStatus {
    Passed,
    Missing,
    Failed,
}
pub struct RecoveryMediumObservation {
    pub(super) run_id: [u8; 16],
    pub(super) request_id: Hash32,
    pub(super) medium_id_hash: ObjectHash,
    pub(super) status: RecoveryMediumStatus,
    pub(super) observed: Option<KeyThumbprint>,
    pub(super) error: Option<&'static str>,
}
impl RecoveryMediumObservation {
    pub fn run_id(&self) -> [u8; 16] {
        self.run_id
    }
    pub fn request_id(&self) -> Hash32 {
        self.request_id
    }
    pub fn medium_id_hash(&self) -> ObjectHash {
        self.medium_id_hash
    }
    pub fn status(&self) -> RecoveryMediumStatus {
        self.status
    }
    pub fn observed_thumbprint(&self) -> Option<KeyThumbprint> {
        self.observed
    }
    pub fn error_code(&self) -> Option<&'static str> {
        self.error
    }
}
pub trait RecoveryTestGuide {
    /// May wait for one input. Runtime holds no SQLCipher transaction here.
    fn request_medium(
        &mut self,
        request: &RecoveryMediumRequest,
    ) -> Result<Option<RecoveryMediumInput>, RecoveryTestAbort>;
    fn medium_result(
        &mut self,
        result: &RecoveryMediumObservation,
    ) -> Result<(), RecoveryTestAbort>;
    /// Pure, non-blocking, denial-only host epoch check. It cannot authorize an
    /// operation, open a key, wait for input, or enter the database.
    fn ensure_active(&self) -> Result<(), RecoveryTestAbort>;
}

/// Native host handoff of the same already verified and durably audited proof.
/// This is not progress data and must never be sent to the renderer. Observers
/// may deny a closed host epoch; they cannot mint or extend session authority.
/// Handoff must be short and must not wait for user input. The host rechecks
/// its epoch, native session and current purpose-specific authority on use.
pub trait RecoverySessionObserver {
    fn verified_session(
        &mut self,
        proof: std::sync::Arc<ea_operator::OperatorSessionProof>,
    ) -> Result<(), RecoveryTestAbort>;
}

pub(super) struct NoopSessionObserver;
impl RecoverySessionObserver for NoopSessionObserver {
    fn verified_session(
        &mut self,
        _: std::sync::Arc<ea_operator::OperatorSessionProof>,
    ) -> Result<(), RecoveryTestAbort> {
        Ok(())
    }
}
impl RecoveryMediumRequest {
    pub(super) fn new(
        run_id: [u8; 16],
        medium: &ea_recovery::RecoveryMedium,
        index: usize,
        total: usize,
    ) -> Self {
        let medium_id_hash = medium.pseudonymous_id_hash();
        let mut h = ea_crypto::StreamingObjectHasher::new();
        h.update(b"EINSATZARCHIV-RECOVERY-MEDIUM-REQUEST-v1");
        h.update(&run_id);
        h.update(medium_id_hash.as_bytes());
        Self {
            run_id,
            request_id: Hash32::try_from(h.finish().as_bytes().as_slice()).expect("hash width"),
            medium_id_hash,
            index,
            total,
            role: medium.role(),
            certificate: medium.certificate(),
            expected: medium.expected_thumbprint(),
            protection: medium.protection(),
            test_kind: medium.test_kind(),
        }
    }
}
impl RecoveryMediumObservation {
    pub(super) fn new(
        request: &RecoveryMediumRequest,
        check: ea_recovery::RecoveryMediumCheck,
    ) -> Self {
        let (status, observed, error) = match check {
            ea_recovery::RecoveryMediumCheck::Passed { observed } => {
                (RecoveryMediumStatus::Passed, Some(observed), None)
            }
            ea_recovery::RecoveryMediumCheck::Missing => (
                RecoveryMediumStatus::Missing,
                None,
                Some(RecoveryTestError::Incomplete.code()),
            ),
            ea_recovery::RecoveryMediumCheck::Failed { observed, error } => {
                (RecoveryMediumStatus::Failed, observed, Some(error.code()))
            }
        };
        Self {
            run_id: request.run_id,
            request_id: request.request_id,
            medium_id_hash: request.medium_id_hash,
            status,
            observed,
            error,
        }
    }
}
pub(super) struct BatchGuide<'a> {
    pub media: &'a [RecoveryTestMediumSource],
}
impl RecoveryTestGuide for BatchGuide<'_> {
    fn request_medium(
        &mut self,
        request: &RecoveryMediumRequest,
    ) -> Result<Option<RecoveryMediumInput>, RecoveryTestAbort> {
        Ok(self
            .media
            .iter()
            .find(|row| row.medium_id_hash == request.medium_id_hash)
            .map(|row| match &row.source {
                RecoveryMediumInput::Offline(source) => {
                    RecoveryMediumInput::Offline(source.clone())
                }
                RecoveryMediumInput::NativeSigningSlot(slot) => {
                    RecoveryMediumInput::NativeSigningSlot(*slot)
                }
            }))
    }
    fn medium_result(&mut self, _: &RecoveryMediumObservation) -> Result<(), RecoveryTestAbort> {
        Ok(())
    }
    fn ensure_active(&self) -> Result<(), RecoveryTestAbort> {
        Ok(())
    }
}
