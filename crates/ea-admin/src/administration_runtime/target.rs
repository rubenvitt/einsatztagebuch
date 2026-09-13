//! Closed, untrusted target description. Parsing does not authorize a ceremony.
use super::TrustCeremonyRoundV1;
use crate::TrustCeremonyKind;
use ea_format::{
    CertificateKindV1, DecodedTrustPayloadV1, DeviceCertificateFieldsV1, FormatError,
    PolicyFieldsV1, RegistryChangeV1, RegistryEventFieldsV1, TrustPayloadV1,
    WriterTransitionFieldsV1,
};
use ea_types::ObjectHash;

enum Fields {
    Device(DeviceCertificateFieldsV1),
    Policy(PolicyFieldsV1),
    Transition(WriterTransitionFieldsV1),
    Registry(RegistryEventFieldsV1),
}
pub struct UntrustedAdministrationTarget {
    fields: Fields,
}
impl UntrustedAdministrationTarget {
    pub fn parse(exact: &[u8]) -> Result<Self, FormatError> {
        let payload = TrustPayloadV1::from_exact_digest_input(exact)?;
        let fields = match payload.decoded_payload()? {
            DecodedTrustPayloadV1::AuthorizedDevice(core)
                if core.fields().certificate_kind != CertificateKindV1::OrganizationAdmin =>
            {
                Fields::Device(core.fields().clone())
            }
            DecodedTrustPayloadV1::Policy(core) => Fields::Policy(core.fields().clone()),
            DecodedTrustPayloadV1::WriterTransition(core) => {
                Fields::Transition(core.fields().clone())
            }
            DecodedTrustPayloadV1::RegistryEvent(core)
                if matches!(
                    core.fields().change,
                    RegistryChangeV1::Certificate { .. }
                        | RegistryChangeV1::Target { .. }
                        | RegistryChangeV1::Policy { .. }
                        | RegistryChangeV1::WriterTransition { .. }
                ) =>
            {
                Fields::Registry(core.fields().clone())
            }
            _ => return Err(FormatError::Shape),
        };
        Ok(Self { fields })
    }
    pub fn payload(&self, authorization: ObjectHash) -> Result<TrustPayloadV1, FormatError> {
        match &self.fields {
            Fields::Device(fields) => {
                TrustPayloadV1::authorized_device_certificate(fields.clone(), authorization)
            }
            Fields::Policy(fields) => TrustPayloadV1::policy(fields.clone(), authorization),
            Fields::Transition(fields) => {
                TrustPayloadV1::writer_transition(fields.clone(), authorization)
            }
            Fields::Registry(fields) => {
                TrustPayloadV1::registry_event(fields.clone(), authorization)
            }
        }
    }
    pub fn kind(&self) -> TrustCeremonyKind {
        match &self.fields {
            Fields::Device(_) => TrustCeremonyKind::DeviceApprove,
            Fields::Policy(_) => TrustCeremonyKind::PolicyChange,
            Fields::Transition(_) => TrustCeremonyKind::WriterTransition,
            Fields::Registry(fields) => match fields.change {
                RegistryChangeV1::Certificate { .. } => TrustCeremonyKind::DeviceApprove,
                RegistryChangeV1::Target { .. } => TrustCeremonyKind::DeviceRevoke,
                RegistryChangeV1::Policy { .. } => TrustCeremonyKind::PolicyChange,
                RegistryChangeV1::WriterTransition { .. } => TrustCeremonyKind::WriterTransition,
                _ => unreachable!("parser only accepts administration changes 0..3"),
            },
        }
    }
    pub fn round(&self) -> TrustCeremonyRoundV1 {
        if matches!(self.fields, Fields::Registry(_)) {
            TrustCeremonyRoundV1::ActivateRegistry
        } else {
            TrustCeremonyRoundV1::IssueTarget
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{ceremony_line, ceremony_line_for, trust_support::ActionSpec};
    use ea_format::OperatorRoleV1;
    use ea_types::{Hash32, ObjectHash};
    #[test]
    fn exact_policy_round_preserves_core_while_binding_only_the_selected_authorization() {
        let fixture = ceremony_line();
        let before = fixture.target_payload();
        let target = UntrustedAdministrationTarget::parse(before.exact_digest_input()).unwrap();
        assert_eq!(target.kind(), TrustCeremonyKind::PolicyChange);
        assert_eq!(target.round(), TrustCeremonyRoundV1::IssueTarget);
        let different = ObjectHash::from(Hash32::try_from(&[0x45; 32][..]).unwrap());
        let after = target.payload(different).unwrap();
        let DecodedTrustPayloadV1::Policy(before) = before.decoded_payload().unwrap() else {
            panic!()
        };
        let DecodedTrustPayloadV1::Policy(after) = after.decoded_payload().unwrap() else {
            panic!()
        };
        assert_eq!(before.exact_core(), after.exact_core());
        assert!(after.authorization_object_hash() == different);
    }
    #[test]
    fn generic_admin_parser_never_absorbs_the_separate_operator_binding_workflow() {
        let fixture = ceremony_line_for(&|writer, _| ActionSpec::OperatorBinding {
            certificate_hash: writer,
            role: OperatorRoleV1::Writer,
            marker: 0x32,
            effective_from: None,
        });
        assert!(
            UntrustedAdministrationTarget::parse(fixture.target_payload().exact_digest_input())
                .is_err()
        );
    }
}
