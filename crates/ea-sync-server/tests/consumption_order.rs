//! Die Reihenfolge des Einmalverbrauchs, gegen den Nachtrag gestellt.
//!
//! `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-sync-wire-addendum.md`
//! schreibt sie aus: „… Signatur, **Einmalverbrauch von Nonce und
//! Request-ID, zuletzt Organisationsbindung und Capability**“. Der Verbrauch
//! liegt also NACH der Signatur und VOR der Autorisierung.
//!
//! Dieser Fall steht als Einheitspruefung und nicht als HTTP-Fall, weil er
//! einen Aufrufer braucht, der freigegeben ist und trotzdem die geforderte
//! Capability nicht traegt. Die eingefrorenen Vektoren kennen nur
//! Zertifikate MIT `organizationAdminApprove`; ein solcher Aufrufer liesse
//! sich aus ihnen nicht bauen, ohne eingefrorene Bytes anzufassen. Hier
//! kommt er aus einem Verzeichnis-Doppel — und genau die Kante, an der die
//! Entscheidung faellt, wird gemessen.

use std::{
    future::Future,
    pin::pin,
    sync::Mutex,
    task::{Context, Poll, Waker},
};

use async_trait::async_trait;
use ea_crypto::{CertificateCapability, SecretBytes};
use ea_sync_protocol::{
    EndpointV1, RegisteredDevice, RequestParts, RequestSigner, SignatureParametersV1,
    SignedRequestV1, SyncProtocolError, body_digest, organization_tag,
};
use ea_sync_server::{
    AuthorityError, ChallengeSpendOutcome, ChallengeStore, DeviceAuthorityDirectory,
    RepositoryError, RequestIdStore, ServerClock,
    auth::{AuthPorts, AuthServiceError, authenticate, challenge_nonce_digest},
};
use ea_types::{CertificateHash, Hash32, KeyThumbprint, OrganizationId, UnixMillis};

/// Fuehrt eine Zukunft zu Ende, die NIE wartet.
///
/// Jeder Port dieses Testfalls antwortet sofort; die Zukunft kann deshalb
/// nicht `Pending` liefern. Ein `panic!` an dieser Stelle ist der ehrliche
/// Befund, falls doch — besser als eine stille Endlosschleife oder eine
/// Laufzeit, die diese Crate ausdruecklich nicht haelt.
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("every port of this test answers immediately"),
    }
}

struct FixedClock(UnixMillis);
impl ServerClock for FixedClock {
    fn now(&self) -> UnixMillis {
        self.0
    }
}

/// Ein Challenge-Speicher, der jeden Verbrauch AUFSCHREIBT.
#[derive(Default)]
struct RecordingChallenges {
    spent: Mutex<Vec<Hash32>>,
}

#[async_trait]
impl ChallengeStore for RecordingChallenges {
    async fn issue(
        &self,
        _organization_id: OrganizationId,
        _nonce_digest: Hash32,
        _rate_key_digest: Hash32,
        _issued_at: UnixMillis,
        _expires_at: UnixMillis,
    ) -> Result<(), RepositoryError> {
        Ok(())
    }

    async fn count_issued_since(
        &self,
        _rate_key_digest: Hash32,
        _since: UnixMillis,
    ) -> Result<u64, RepositoryError> {
        Ok(0)
    }

    async fn spend(
        &self,
        _organization_id: OrganizationId,
        nonce_digest: Hash32,
        _now: UnixMillis,
    ) -> Result<ChallengeSpendOutcome, RepositoryError> {
        let mut spent = self.spent.lock().expect("the test mutex is never poisoned");
        if spent.contains(&nonce_digest) {
            return Ok(ChallengeSpendOutcome::AlreadySpent);
        }
        spent.push(nonce_digest);
        Ok(ChallengeSpendOutcome::Spent)
    }
}

#[derive(Default)]
struct RecordingRequestIds {
    claimed: Mutex<Vec<[u8; 16]>>,
}

#[async_trait]
impl RequestIdStore for RecordingRequestIds {
    async fn claim(
        &self,
        _organization_id: OrganizationId,
        request_id: [u8; 16],
        _seen_at: UnixMillis,
        _expires_at: UnixMillis,
    ) -> Result<bool, RepositoryError> {
        let mut claimed = self
            .claimed
            .lock()
            .expect("the test mutex is never poisoned");
        if claimed.contains(&request_id) {
            return Ok(false);
        }
        claimed.push(request_id);
        Ok(true)
    }
}

/// Ein Verzeichnis, das GENAU EIN freigegebenes Geraet kennt.
struct OneDevice(RegisteredDevice);

#[async_trait]
impl DeviceAuthorityDirectory for OneDevice {
    async fn resolve(
        &self,
        _organization_id: OrganizationId,
        key_thumbprint: KeyThumbprint,
        _now: UnixMillis,
    ) -> Result<Option<RegisteredDevice>, AuthorityError> {
        Ok((self.0.key_thumbprint() == key_thumbprint).then(|| self.0.clone()))
    }
}

const AUTHORITY: &str = "sync.example.org";
const CALLER_SEED: [u8; 32] = [0x3a; 32];
const NONCE: [u8; 32] = [0x3b; 32];
const REQUEST_ID: [u8; 16] = [0x3c; 16];

fn organization() -> OrganizationId {
    OrganizationId::try_from(&[0x3d_u8; 16][..]).expect("16 bytes")
}

fn signed_trust_event_request(signer: &RequestSigner, body: &[u8]) -> SignedRequestV1 {
    let endpoint = EndpointV1::TrustEvents;
    let parts = RequestParts {
        method: endpoint.method(),
        authority: AUTHORITY.to_owned(),
        target_uri: format!("https://{AUTHORITY}{}", endpoint.path_template()),
        content_type: endpoint.request_media_type().map(ToOwned::to_owned),
        body_digest: Some(body_digest(body)),
        request_id: ea_sync_protocol::RequestIdV1::try_from(&REQUEST_ID[..])
            .expect("a request id is 16 bytes"),
    };
    let parameters = SignatureParametersV1::new(0, 300, NONCE, organization_tag(organization()));
    signer
        .sign(&parts, &parameters)
        .expect("signing the test request must succeed")
}

#[test]
fn a_capability_refusal_still_spends_the_challenge_and_the_request_id() {
    let signer = RequestSigner::from_secret(SecretBytes::new(CALLER_SEED));
    // Freigegeben, organisationsgebunden — und mit der FALSCHEN Capability.
    let device = RegisteredDevice::new(
        organization(),
        CertificateHash::try_from(&[0x3e_u8; 32][..]).expect("32 bytes"),
        signer.public_key(),
        vec![CertificateCapability::InitialGrant],
    );
    let directory = OneDevice(device);
    let challenges = RecordingChallenges::default();
    let request_ids = RecordingRequestIds::default();
    let clock = FixedClock(UnixMillis::new(1_000));
    let ports = AuthPorts {
        clock: &clock,
        challenges: &challenges,
        request_ids: &request_ids,
        directory: &directory,
    };

    let request = signed_trust_event_request(&signer, b"body");
    let refusal = block_on(authenticate(
        EndpointV1::TrustEvents,
        AUTHORITY,
        &request,
        &ports,
        None,
    ))
    .expect_err("a device without organizationAdminApprove must be refused");
    assert_eq!(
        refusal,
        AuthServiceError::Protocol(SyncProtocolError::CapabilityMissing)
    );
    assert_eq!(refusal.http_status(), 403);

    // DAS ist die Aussage: die Abweisung kam NACH dem Verbrauch.
    //
    // Verglichen wird ueber `==` und nicht ueber `assert_eq!`: die Kennungen
    // aus `ea-types` tragen bewusst KEIN `Debug`, damit kein Testbericht ihren
    // Wert druckt.
    assert!(
        challenges
            .spent
            .lock()
            .expect("the test mutex is never poisoned")
            .as_slice()
            == [challenge_nonce_digest(&NONCE)],
        "the addendum consumes the nonce before the capability decision"
    );
    assert_eq!(
        request_ids
            .claimed
            .lock()
            .expect("the test mutex is never poisoned")
            .as_slice(),
        &[REQUEST_ID],
        "the addendum consumes the request id before the capability decision"
    );

    // Und der Nachfasser mit denselben Einmalwerten kommt nicht weiter: er
    // scheitert jetzt am Verbrauch, nicht mehr an der Capability.
    let replay = block_on(authenticate(
        EndpointV1::TrustEvents,
        AUTHORITY,
        &request,
        &ports,
        None,
    ))
    .expect_err("the spent challenge must refuse the second probe");
    assert_eq!(replay, AuthServiceError::NonceReplay);
    assert_eq!(replay.code(), "EA-AUTH-NONCE-REPLAY");
}

/// Vor gueltiger Signatur wird NICHTS verbraucht.
#[test]
fn a_refusal_before_the_signature_spends_nothing() {
    let signer = RequestSigner::from_secret(SecretBytes::new(CALLER_SEED));
    // Das Verzeichnis kennt diesen Schluessel nicht: der Pruefer scheitert an
    // der Identitaet, also VOR der Signatur.
    let directory = OneDevice(RegisteredDevice::new(
        organization(),
        CertificateHash::try_from(&[0x3e_u8; 32][..]).expect("32 bytes"),
        RequestSigner::from_secret(SecretBytes::new([0x4f; 32])).public_key(),
        vec![CertificateCapability::OrganizationAdminApprove],
    ));
    let challenges = RecordingChallenges::default();
    let request_ids = RecordingRequestIds::default();
    let clock = FixedClock(UnixMillis::new(1_000));
    let ports = AuthPorts {
        clock: &clock,
        challenges: &challenges,
        request_ids: &request_ids,
        directory: &directory,
    };

    let request = signed_trust_event_request(&signer, b"body");
    let refusal = block_on(authenticate(
        EndpointV1::TrustEvents,
        AUTHORITY,
        &request,
        &ports,
        None,
    ))
    .expect_err("an unresolvable key must be refused");
    assert_eq!(
        refusal,
        AuthServiceError::Protocol(SyncProtocolError::KeyUnresolved)
    );
    assert!(
        challenges
            .spent
            .lock()
            .expect("the test mutex is never poisoned")
            .is_empty(),
        "a stranger must not be able to burn foreign one-time values"
    );
    assert!(
        request_ids
            .claimed
            .lock()
            .expect("the test mutex is never poisoned")
            .is_empty()
    );
}
