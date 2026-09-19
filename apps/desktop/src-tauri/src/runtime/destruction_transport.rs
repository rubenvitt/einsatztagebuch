//! Authenticated exact-byte server exchange for a separately admitted native controller.
use ea_admin::destruction_runtime::{
    DestructionRuntime, NativeDestructionError, NativeDestructionStatus,
};
use ea_recovery::KeySourceSpec;
use ea_types::{CertificateHash, DestructionId, DeviceId, ObjectHash};
use std::{net::SocketAddr, path::PathBuf};

/// Public host configuration, never renderer-provided network authority.
#[derive(Clone)]
pub struct NativeDestructionServerConfig {
    pub device_id: DeviceId,
    pub address: SocketAddr,
    pub server_name: String,
    pub authority: String,
    pub ca_file: PathBuf,
    pub server_certificate: CertificateHash,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeDestructionTransportError {
    Native(NativeDestructionError),
    Configuration,
    KeySource,
    Tls,
    Unavailable,
    ResponseLimit,
    Protocol,
    Binding,
    ReservationMissing,
    RemoteRefusal,
    CausalHistory,
}
impl NativeDestructionTransportError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Native(error) => error.code(),
            Self::Configuration => "EA-DESTRUCTION-TRANSPORT-CONFIG",
            Self::KeySource => "EA-DESTRUCTION-TRANSPORT-KEY-SOURCE",
            Self::Tls => "EA-DESTRUCTION-TRANSPORT-TLS",
            Self::Unavailable => "EA-DESTRUCTION-TRANSPORT-UNAVAILABLE",
            Self::ResponseLimit => "EA-DESTRUCTION-TRANSPORT-RESPONSE-LIMIT",
            Self::Protocol => "EA-DESTRUCTION-TRANSPORT-PROTOCOL",
            Self::Binding => "EA-DESTRUCTION-TRANSPORT-BINDING",
            Self::ReservationMissing => "EA-DESTRUCTION-SERVER-RESERVATION-MISSING",
            Self::RemoteRefusal => "EA-DESTRUCTION-TRANSPORT-REMOTE-REFUSAL",
            Self::CausalHistory => "EA-DESTRUCTION-TRANSPORT-HISTORY",
        }
    }
}
impl From<NativeDestructionError> for NativeDestructionTransportError {
    fn from(value: NativeDestructionError) -> Self {
        Self::Native(value)
    }
}

use ea_admin::destruction_runtime::{
    NativeDestructionDelivery, NativeDestructionExchange, ServerReservationPort,
};
use ea_recovery::{ContainedKeyKind, EncryptedKeyContainer, read_secret_file};
use ea_sync_client::{
    HyperTlsTransport, SyncTransportV1, TransportErrorV1, TransportRequestV1, TransportResponseV1,
};
use ea_sync_protocol::{
    ChallengeRequestV1, DestructionStatusResponseV1, EndpointV1, HttpMethod, RequestIdV1,
    RequestParts, RequestSigner, SignatureParametersV1, body_digest, organization_tag,
};
use ea_types::OrganizationId;
use rustls::pki_types::pem::PemObject as _;
use std::collections::{BTreeMap, BTreeSet};
type Error = NativeDestructionTransportError;

struct Server {
    config: NativeDestructionServerConfig,
    transport: HyperTlsTransport,
    challenge_transport: HyperTlsTransport,
}
/// Synchronous host adapter; async I/O stays inside the existing TLS transport.
/// Call from the native blocking worker, never a renderer or an async worker.
pub struct NativeDestructionServerTransport {
    servers: Vec<Server>,
    signer: RequestSigner,
}
impl NativeDestructionServerTransport {
    pub fn open(
        servers: Vec<NativeDestructionServerConfig>,
        component_source: &KeySourceSpec,
    ) -> Result<Self, Error> {
        if servers.is_empty() || servers.len() > 64 {
            return Err(Error::Configuration);
        }
        let mut identities = BTreeSet::new();
        let mut endpoints = Vec::new();
        for config in servers {
            validate_endpoint(&config)?;
            if !identities.insert(config.device_id) {
                return Err(Error::Configuration);
            }
            let meta =
                std::fs::symlink_metadata(&config.ca_file).map_err(|_| Error::Configuration)?;
            if !meta.is_file() || meta.len() == 0 || meta.len() > 1024 * 1024 {
                return Err(Error::Configuration);
            }
            let exact = std::fs::read(&config.ca_file).map_err(|_| Error::Configuration)?;
            let mut roots = rustls::RootCertStore::empty();
            for certificate in rustls::pki_types::CertificateDer::pem_slice_iter(&exact) {
                roots
                    .add(certificate.map_err(|_| Error::Tls)?)
                    .map_err(|_| Error::Tls)?;
            }
            if roots.is_empty() {
                return Err(Error::Tls);
            }
            let challenge_transport = HyperTlsTransport::new_bounded(
                config.address,
                config.server_name.clone(),
                roots.clone(),
                ea_sync_protocol::MAX_SMALL_BODY_BYTES_V1,
            )
            .map_err(|_| Error::Tls)?;
            let transport = HyperTlsTransport::new_bounded(
                config.address,
                config.server_name.clone(),
                roots,
                ea_sync_protocol::MAX_READER_PAGE_BYTES_V1,
            )
            .map_err(|_| Error::Tls)?;
            endpoints.push(Server {
                config,
                transport,
                challenge_transport,
            });
        }
        let KeySourceSpec::Container {
            path,
            passphrase_file,
        } = component_source
        else {
            // Raw files and PKCS sources without the required HTTP signing port
            // are explicit refusals, never a fallback or implicit key reuse.
            return Err(Error::KeySource);
        };
        let container = EncryptedKeyContainer::read_from(path).map_err(|_| Error::KeySource)?;
        let passphrase = read_secret_file(passphrase_file).map_err(|_| Error::KeySource)?;
        let secret = container
            .open(ContainedKeyKind::Signing, &passphrase)
            .map_err(|_| Error::KeySource)?;
        Ok(Self {
            servers: endpoints,
            signer: RequestSigner::from_secret(secret),
        })
    }
    /// Read all existing reservations through the native barrier, then persist
    /// native Start before any mutating remote request. Even an exact replay of
    /// a job or event can resume server-side physical execution.
    pub fn start(
        &mut self,
        native: &mut DestructionRuntime,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
    ) -> Result<NativeDestructionStatus, Error> {
        let context = native.prepare_server_exchange(id, expected_preflight_hash)?;
        self.admit(&context)?;
        // The barrier performs authenticated GETs only. No job/event POST may
        // precede durable native Start: the server may already have progressed
        // concurrently and execute again even when a POST is byte-identical.
        let mut barrier = Reservation {
            transport: self,
            context: &context,
            failure: None,
        };
        let outcome = native.start(
            id,
            expected_preflight_hash,
            NativeDestructionDelivery::AuthenticatedServer(&mut barrier),
        );
        if let Some(error) = barrier.failure {
            return Err(error);
        }
        outcome?;
        // Never transmit any mutation until both exact native audit copies are durable.
        let context = native.prepare_server_exchange(id, expected_preflight_hash)?;
        self.admit(&context)?;
        self.publish(&context)?;
        self.import(native, &context)
    }
    /// Explicitly resume real server execution and local holder cleanup. Missing
    /// readers/backups stay in the immutable denominator without a success claim.
    pub fn resume(
        &mut self,
        native: &mut DestructionRuntime,
        id: DestructionId,
    ) -> Result<NativeDestructionStatus, Error> {
        // Test-support is absent from production defaults. Explicit diagnostic
        // opt-in emits only fixed phase names and elapsed time, never arguments.
        #[cfg(feature = "test-support")]
        let diagnostic_started = (std::env::var_os("EA_TEST_NATIVE_RESUME_PHASES").as_deref()
            == Some(std::ffi::OsStr::new("1")))
        .then(std::time::Instant::now);
        macro_rules! phase {
            ($label:literal) => {
                #[cfg(feature = "test-support")]
                if let Some(started) = diagnostic_started {
                    eprintln!("native-resume phase {} {:?}", $label, started.elapsed());
                }
            };
        }
        phase!("unlock.begin");
        native.unlock()?;
        phase!("status.begin");
        let saved = native.status(id)?;
        let hash = saved.preflight_hash.ok_or(Error::Binding)?;
        if saved.state == ea_destruction::DestructionState::Requested {
            return Err(Error::CausalHistory);
        }
        phase!("prepare-1.begin");
        let context = native.prepare_server_exchange(id, hash)?;
        phase!("admit-1.begin");
        self.admit(&context)?;
        phase!("publish-1.begin");
        self.publish(&context)?;
        phase!("local.begin");
        let mut barrier = Reservation {
            transport: self,
            context: &context,
            failure: None,
        };
        let outcome = native.resume_local(
            id,
            NativeDestructionDelivery::AuthenticatedServer(&mut barrier),
        );
        if let Some(error) = barrier.failure {
            return Err(error);
        }
        outcome?;
        phase!("prepare-2.begin");
        let context = native.prepare_server_exchange(id, hash)?;
        phase!("admit-2.begin");
        self.admit(&context)?;
        phase!("publish-2.begin");
        self.publish(&context)?;
        phase!("import.begin");
        let mut status = self.import(native, &context)?;
        phase!("import.return");
        // Ruling G2 (19.09.2026): in state4 the server re-contact above is
        // chained into the native 4→1 retry, then continues like any Resume
        // below (1→3 or 1→2). The core decides and refuses a Reader case or an
        // open duty with its own code; never a silent no-op, never a loop.
        if let Some(hash) = super::destruction::retry_job(&status)? {
            phase!("retry.begin");
            status = self.resume_incomplete(native, id, hash)?;
            if super::destruction::retry_job(&status)?.is_some() {
                return Err(Error::CausalHistory);
            }
        }
        let (hash, pending) = if let Some(hash) = super::destruction::completion_job(&status) {
            (hash, false)
        } else if let Some(hash) = super::destruction::pending_job(
            &status,
            super::now().map_err(|_| Error::Configuration)?,
        ) {
            (hash, true)
        } else {
            // Resume never records state4 (Ruling 13.09.2026); only the
            // explicit, separately confirmed `mark_incomplete` does.
            return Ok(status);
        };
        // The imported status only selects the explicit native action. Obtain
        // a fresh authenticated reservation; never substitute NoRegisteredServer.
        if pending {
            phase!("pending.begin");
        } else {
            phase!("complete.begin");
        }
        let context = native.prepare_server_exchange(id, hash)?;
        self.admit(&context)?;
        let mut barrier = Reservation {
            transport: self,
            context: &context,
            failure: None,
        };
        let outcome = if pending {
            native.mark_pending_backup_progress(
                id,
                hash,
                NativeDestructionDelivery::AuthenticatedServer(&mut barrier),
            )
        } else {
            native.complete_verified_progress(
                id,
                hash,
                NativeDestructionDelivery::AuthenticatedServer(&mut barrier),
            )
        };
        if let Some(error) = barrier.failure {
            return Err(error);
        }
        outcome?;
        // Local commit is not a remote acknowledgement. Publish exact original
        // attestations/events, then import the actual current server response.
        if pending {
            phase!("pending.publish.begin");
        } else {
            phase!("complete.publish.begin");
        }
        let context = native.prepare_server_exchange(id, hash)?;
        self.admit(&context)?;
        self.publish(&context)?;
        let status = self.import(native, &context)?;
        if pending {
            phase!("pending.return");
        } else {
            phase!("complete.return");
        }
        Ok(status)
    }
    /// Native 4→1 retry for a server-bound state4, only chained from `resume`
    /// after its server re-contact and import. The retained 1/2→4 original is
    /// the last event of the freshly admitted exchange. The core reads the
    /// reservation per call before and after signing; publication follows the
    /// durable local commit, then the actual server reply is imported.
    fn resume_incomplete(
        &mut self,
        native: &mut DestructionRuntime,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
    ) -> Result<NativeDestructionStatus, Error> {
        let context = native.prepare_server_exchange(id, expected_preflight_hash)?;
        self.admit(&context)?;
        let retained = context
            .events()?
            .last()
            .map(|event| event.0)
            .ok_or(Error::CausalHistory)?;
        let mut barrier = Reservation {
            transport: self,
            context: &context,
            failure: None,
        };
        let outcome = native.resume_incomplete_progress(
            id,
            expected_preflight_hash,
            retained,
            NativeDestructionDelivery::AuthenticatedServer(&mut barrier),
        );
        if let Some(error) = barrier.failure {
            return Err(error);
        }
        outcome?;
        let context = native.prepare_server_exchange(id, expected_preflight_hash)?;
        self.admit(&context)?;
        self.publish(&context)?;
        self.import(native, &context)
    }
    /// The explicit, separately confirmed final action (Ruling 13.09.2026). The
    /// conservative Failure producer deliberately has no delivery port: missing
    /// timely confirmation must be recordable without a reachable server, so no
    /// reservation is simulated. Only local binding checks precede the durable
    /// commit; afterwards publish the exact originals and import the reply.
    pub fn mark_incomplete(
        &mut self,
        native: &mut DestructionRuntime,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
    ) -> Result<NativeDestructionStatus, Error> {
        {
            // No request: bind the configured servers, their certificates and
            // the component key to this job before the final event is signed.
            let context = native.prepare_server_exchange(id, expected_preflight_hash)?;
            self.admit(&context)?;
        }
        native.mark_incomplete_progress(id, expected_preflight_hash)?;
        let context = native.prepare_server_exchange(id, expected_preflight_hash)?;
        self.admit(&context)?;
        self.publish(&context)?;
        self.import(native, &context)
    }
    /// Read actual server claims and durably import verified exact ETB objects.
    /// This operation sends no event/job POST and cannot start remote execution.
    pub fn synchronize(
        &mut self,
        native: &mut DestructionRuntime,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
    ) -> Result<NativeDestructionStatus, Error> {
        let context = native.prepare_server_exchange(id, expected_preflight_hash)?;
        self.admit(&context)?;
        self.import(native, &context)
    }
    /// Read current authenticated reservations for an already started job. No job or event publication.
    pub fn project_writer_evidence(
        &mut self,
        native: &mut DestructionRuntime,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
    ) -> Result<ea_destruction::VerifiedDestructionEvidence, Error> {
        let context = native.prepare_server_exchange(id, expected_preflight_hash)?;
        self.admit(&context)?;
        let mut barrier = Reservation {
            transport: self,
            context: &context,
            failure: None,
        };
        let outcome = native.project_writer_evidence(
            id,
            NativeDestructionDelivery::AuthenticatedServer(&mut barrier),
        );
        if let Some(error) = barrier.failure {
            return Err(error);
        }
        Ok(outcome?)
    }
    fn admit(&self, context: &NativeDestructionExchange) -> Result<(), Error> {
        context.require_current()?;
        context.verify_component_key(&self.signer.public_key())?;
        let actual = self
            .servers
            .iter()
            .map(|s| s.config.device_id)
            .collect::<BTreeSet<_>>();
        let required = context
            .required_servers()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if actual != required {
            return Err(Error::Binding);
        }
        for server in &self.servers {
            context.verify_server(server.config.device_id, server.config.server_certificate)?;
        }
        context.require_current()?;
        Ok(())
    }
    fn call(
        &self,
        server: &Server,
        context: &NativeDestructionExchange,
        endpoint: EndpointV1,
        body: Option<&[u8]>,
    ) -> Result<DestructionStatusResponseV1, Error> {
        context.verify_server(server.config.device_id, server.config.server_certificate)?;
        let challenge = ChallengeRequestV1::new(context.organization_id());
        let response = send(
            &server.challenge_transport,
            TransportRequestV1 {
                method: HttpMethod::Post,
                target: "/v1/auth/challenges".into(),
                authority: server.config.authority.clone(),
                content_type: Some(ea_sync_protocol::STRUCTURED_MEDIA_TYPE_V1.into()),
                headers: vec![(
                    "content-type",
                    ea_sync_protocol::STRUCTURED_MEDIA_TYPE_V1.into(),
                )],
                body: challenge.exact_bytes().to_vec(),
                nonce: [0; 32],
            },
        )?;
        if response.status != EndpointV1::AuthChallenges.success_status() {
            return Err(Error::RemoteRefusal);
        }
        let (nonce, created, expires) = context.verify_challenge_window(
            server.config.device_id,
            server.config.server_certificate,
            &response.body,
        )?;
        let path = format!(
            "/v1/destructions/{}",
            hexadecimal(context.destruction_id().as_bytes())
        );
        let target = match endpoint {
            EndpointV1::DestructionStatus => path,
            EndpointV1::DestructionEvents => format!("{path}/events"),
            EndpointV1::DestructionJobs => format!("{path}/jobs"),
            _ => return Err(Error::Protocol),
        };
        let content_type = endpoint.request_media_type().map(str::to_owned);
        let parts = RequestParts {
            method: endpoint.method(),
            authority: server.config.authority.clone(),
            target_uri: format!("https://{}{target}", server.config.authority),
            content_type: content_type.clone(),
            body_digest: body.map(body_digest),
            request_id: RequestIdV1::try_from(&nonce[..16]).map_err(|_| Error::Protocol)?,
        };
        let parameters = SignatureParametersV1::new(
            created,
            expires,
            nonce,
            organization_tag(context.organization_id()),
        );
        let signed = self
            .signer
            .sign(&parts, &parameters)
            .map_err(|_| Error::Protocol)?;
        let mut headers = vec![
            (
                ea_sync_protocol::REQUEST_ID_HEADER_V1,
                signed.request_id().to_header_value(),
            ),
            ("signature-input", signed.signature_input_header()),
            ("signature", signed.signature_header()),
        ];
        if let Some(media) = &content_type {
            headers.push(("content-type", media.clone()));
        }
        if let Some(digest) = signed.content_digest_header() {
            headers.push(("content-digest", digest.to_owned()));
        }
        context.require_current()?;
        let response = send(
            &server.transport,
            TransportRequestV1 {
                method: endpoint.method(),
                target,
                authority: server.config.authority.clone(),
                content_type,
                headers,
                body: body.unwrap_or(&[]).to_vec(),
                nonce,
            },
        )?;
        if response.status == 404 && endpoint == EndpointV1::DestructionStatus {
            return Err(Error::ReservationMissing);
        }
        if response.status != endpoint.success_status() {
            return Err(Error::RemoteRefusal);
        }
        self.checked_status(context, &response.body)
    }
    fn status(
        &self,
        server: &Server,
        context: &NativeDestructionExchange,
    ) -> Result<DestructionStatusResponseV1, Error> {
        self.call(server, context, EndpointV1::DestructionStatus, None)
    }
    fn checked_status(
        &self,
        context: &NativeDestructionExchange,
        bytes: &[u8],
    ) -> Result<DestructionStatusResponseV1, Error> {
        let status = DestructionStatusResponseV1::decode(bytes).map_err(|_| Error::Protocol)?;
        context.progress_batches(&status)?;
        Ok(status)
    }
    fn publish(&self, context: &NativeDestructionExchange) -> Result<(), Error> {
        // All reservations must be real and bound before the first mutation.
        for server in &self.servers {
            self.status(server, context)?;
        }
        for server in &self.servers {
            let mut status = self.status(server, context)?;
            let events = context.events()?;
            let first = events.first().ok_or(Error::CausalHistory)?;
            self.post_event(server, context, &mut status, first)?;
            let response = self.call(
                server,
                context,
                EndpointV1::DestructionJobs,
                Some(context.exact_job()),
            )?;
            status = response;
            // Attestations may be relayed as their original exact signed bytes.
            // Post those before a later completion event whose reducer needs them.
            for (hash, exact) in context.attestations() {
                if status
                    .attestations()
                    .iter()
                    .any(|v| v.object_hash() == hash)
                {
                    continue;
                }
                let response =
                    self.call(server, context, EndpointV1::DestructionEvents, Some(exact))?;
                status = response;
                if !status
                    .attestations()
                    .iter()
                    .any(|v| v.object_hash() == hash)
                {
                    return Err(Error::CausalHistory);
                }
            }
            for event in events.iter().skip(1) {
                self.post_event(server, context, &mut status, event)?;
            }
        }
        context.require_current()?;
        Ok(())
    }
    fn post_event(
        &self,
        server: &Server,
        context: &NativeDestructionExchange,
        status: &mut DestructionStatusResponseV1,
        event: &(ObjectHash, CertificateHash, &[u8]),
    ) -> Result<(), Error> {
        if status
            .transitions()
            .iter()
            .any(|v| v.object_hash() == event.0)
        {
            return Ok(());
        }
        if event.1 != context.component_certificate() {
            return Err(Error::CausalHistory);
        }
        let response = self.call(
            server,
            context,
            EndpointV1::DestructionEvents,
            Some(event.2),
        )?;
        *status = response;
        if !status
            .transitions()
            .iter()
            .any(|v| v.object_hash() == event.0)
        {
            return Err(Error::CausalHistory);
        }
        Ok(())
    }
    fn import(
        &self,
        native: &mut DestructionRuntime,
        context: &NativeDestructionExchange,
    ) -> Result<NativeDestructionStatus, Error> {
        let mut transitions = BTreeMap::new();
        let mut attestations = BTreeMap::new();
        for server in &self.servers {
            let status = self.status(server, context)?;
            for record in status.transitions() {
                transitions.insert(record.object_hash(), record.clone());
            }
            for record in status.attestations() {
                attestations.insert(record.object_hash(), record.clone());
            }
        }
        let union = DestructionStatusResponseV1::new(
            context.destruction_id(),
            0,
            context.authorization_hash(),
            transitions.into_values().collect(),
            attestations.into_values().collect(),
        )
        .map_err(|_| Error::Protocol)?;
        let batches = context.progress_batches(&union)?;
        for batch in batches {
            context.require_current()?;
            native.import_signed_progress(context.destruction_id(), context.job_hash(), &batch)?;
        }
        context.require_current()?;
        native.unlock()?;
        Ok(native.status(context.destruction_id())?)
    }
}
struct Reservation<'a> {
    transport: &'a NativeDestructionServerTransport,
    context: &'a NativeDestructionExchange,
    failure: Option<Error>,
}
impl ServerReservationPort for Reservation<'_> {
    fn read_current_status(
        &mut self,
        organization: OrganizationId,
        destruction: DestructionId,
    ) -> Result<Vec<u8>, ea_destruction::DestructionError> {
        let result = (|| {
            if organization != self.context.organization_id()
                || destruction != self.context.destruction_id()
            {
                return Err(Error::Binding);
            }
            self.transport.admit(self.context)?;
            let mut exact = None;
            for server in &self.transport.servers {
                let status = self.transport.status(server, self.context)?;
                if exact.is_none() {
                    exact = Some(status.exact_bytes().to_vec());
                }
            }
            self.context.require_current()?;
            exact.ok_or(Error::Binding)
        })();
        result.map_err(|error| {
            self.failure = Some(error);
            ea_destruction::DestructionError::Target
        })
    }
}
fn send(
    transport: &HyperTlsTransport,
    request: TransportRequestV1,
) -> Result<TransportResponseV1, Error> {
    tauri::async_runtime::block_on(transport.send(request)).map_err(|error| match error {
        TransportErrorV1::Tls => Error::Tls,
        TransportErrorV1::ResponseTooLarge => Error::ResponseLimit,
        TransportErrorV1::Timeout | TransportErrorV1::Unreachable => Error::Unavailable,
    })
}
fn validate_endpoint(config: &NativeDestructionServerConfig) -> Result<(), Error> {
    let name = &config.server_name;
    if name.is_empty()
        || name.len() > 253
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
    {
        return Err(Error::Configuration);
    }
    let host = if name.contains(':') {
        format!("[{name}]")
    } else {
        name.clone()
    };
    let expected = format!("{host}:{}", config.address.port());
    if config.authority != expected && !(config.address.port() == 443 && config.authority == host) {
        return Err(Error::Configuration);
    }
    Ok(())
}
fn hexadecimal(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(HEX[usize::from(byte >> 4)] as char);
        text.push(HEX[usize::from(byte & 15)] as char);
    }
    text
}
