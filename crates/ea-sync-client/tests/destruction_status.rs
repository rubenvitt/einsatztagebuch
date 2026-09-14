mod support;
use ea_sync_client::*;
use ea_sync_protocol::{DestructionStatusResponseV1, HttpMethod};
use ea_types::{DestructionId, ObjectHash};
use std::sync::{Arc, Mutex};
struct Server {
    challenge: Arc<support::FakeServer>,
    response: Mutex<TransportResponseV1>,
    seen: Mutex<Vec<TransportRequestV1>>,
}
#[async_trait]
impl SyncTransportV1 for Server {
    async fn send(
        &self,
        request: TransportRequestV1,
    ) -> Result<TransportResponseV1, TransportErrorV1> {
        if request.target == "/v1/auth/challenges" {
            return self.challenge.send(request).await;
        }
        self.seen.lock().unwrap().push(request);
        Ok(self.response.lock().unwrap().clone())
    }
}
#[tokio::test]
async fn fresh_signed_get_checks_exact_id_hash_and_http_success() {
    let harness = support::SyncHarness::new().await;
    let id = DestructionId::try_from(&[0x19; 16][..]).unwrap();
    let hash = ObjectHash::try_from(&[0x20; 32][..]).unwrap();
    let status = |id, hash| {
        DestructionStatusResponseV1::new(id, 0, hash, vec![], vec![])
            .unwrap()
            .exact_bytes()
            .to_vec()
    };
    let server = Arc::new(Server {
        challenge: harness.server.clone(),
        response: Mutex::new(TransportResponseV1 {
            status: 200,
            body: status(id, hash),
        }),
        seen: Mutex::new(Vec::new()),
    });
    let client = harness.client_with_transport(server.clone());
    let observed = client.destruction_status(id, hash).await.unwrap();
    assert!(observed.authorization_object_hash() == hash);
    client.destruction_status(id, hash).await.unwrap();
    {
        let requests = server.seen.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].method, HttpMethod::Get);
        assert_eq!(
            requests[0].target,
            "/v1/destructions/19191919191919191919191919191919"
        );
        assert!(requests[0].headers.iter().any(|(h, _)| *h == "signature"));
        assert_ne!(requests[0].nonce, requests[1].nonce);
    }
    server.response.lock().unwrap().body =
        status(id, ObjectHash::try_from(&[0x21; 32][..]).unwrap());
    assert!(client.destruction_status(id, hash).await.is_err());
    server.response.lock().unwrap().body =
        status(DestructionId::try_from(&[0x21; 16][..]).unwrap(), hash);
    assert!(client.destruction_status(id, hash).await.is_err());
    *server.response.lock().unwrap() = TransportResponseV1 {
        status: 409,
        body: status(id, hash),
    };
    assert!(client.destruction_status(id, hash).await.is_err());
}
