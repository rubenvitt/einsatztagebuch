use ea_crypto::CertificateCapability;
use ea_sync_protocol::{EndpointV1, HttpMethod};
#[test]
fn exact_signed_destruction_event_and_job_endpoints_are_additive() {
    for (path, code) in [
        ("/v1/destructions/{destructionId}/events", 18),
        ("/v1/destructions/{destructionId}/jobs", 19),
    ] {
        let endpoint = EndpointV1::ALL
            .into_iter()
            .find(|item| item.path_template() == path)
            .expect("the approved exact-byte destruction endpoint must be routed");
        assert_eq!(endpoint.code(), code);
        assert_eq!(endpoint.method(), HttpMethod::Post);
        assert_eq!(
            endpoint.required_capability(),
            Some(CertificateCapability::DeletionAttest)
        );
        assert_eq!(endpoint.success_status(), 202);
    }
    assert_eq!(EndpointV1::Destructions.code(), 16);
    assert_eq!(EndpointV1::DestructionStatus.code(), 17);
}
