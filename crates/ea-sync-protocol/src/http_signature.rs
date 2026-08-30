//! RFC-9421-Signatur des Einsatzarchiv-Profils: Signierer, Pruefer und die
//! Signaturbasis, ueber die beide dasselbe sagen.
//!
//! Der Signierer laeuft OHNE Wirtsbetriebssystem: `created`, `expires`,
//! `nonce` und die Request-ID kommen als Parameter herein, weil der Leser im
//! Browser signiert und dort weder Uhr noch Zufallsquelle dieser Bibliothek
//! gehoeren (`web-reader-design.md` §6.6).
//!
//! Die Pruefreihenfolge ist ABSICHTLICH festgelegt und in [`RequestVerifier::verify`]
//! aufgeschrieben: erst die Form der Signatur, dann Ziel und Zeit, dann der
//! Digest, dann die Identitaet, dann die Signatur selbst, dann die
//! Einmalwerte, zuletzt die Autorisierung. Ein Einmalwert wird ERST verbraucht,
//! nachdem die Signatur gilt — sonst koennte ein Fremder fremde Nonces
//! aufbrauchen.

use core::fmt;

use ea_crypto::{CanonicalPublicCoseKey, CertificateCapability, SecretBytes};
use ea_types::{CertificateHash, KeyThumbprint, OrganizationId};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

use crate::{EndpointAuthentication, EndpointV1, SyncProtocolError};

/// Das Label, unter dem jede Signatur dieses Profils steht.
pub const SIGNATURE_LABEL_V1: &str = "ea1";

/// Der Header, der die global eindeutige Request-ID traegt.
pub const REQUEST_ID_HEADER_V1: &str = "ea-request-id";

/// `alg` des Profils. Ein anderer Wert wird fail-closed abgelehnt.
pub const SIGNATURE_ALGORITHM_V1: &str = "ed25519";

/// Das groesste zulaessige Gueltigkeitsfenster in Sekunden.
///
/// `design.md` §13.1: „Falsche Geraetezeit darf nicht durch ein unbegrenzt
/// grosses Replay-Fenster kompensiert werden.“ Fuenf Minuten sind die
/// Obergrenze, nicht die Voreinstellung eines Klienten.
pub const MAX_SIGNATURE_WINDOW_SECONDS_V1: i64 = 300;

/// Der Vorlauf, den der Pruefer einer FREMDEN Uhr zugesteht — in
/// Millisekunden.
///
/// RFC 9421 §3.2.1 ueberlaesst die „leeway" ausdruecklich dem Pruefer, und
/// ohne sie faellt ein Schreiber, dessen Uhr eine Sekunde vorgeht, mit JEDEM
/// signierten Request auf `401` — den der Klient als nicht automatisch
/// wiederholbar fuehrt. Eine Minute deckt die uebliche Drift einer
/// ungepflegten Geraeteuhr und bleibt weit unter dem Fenster von
/// [`MAX_SIGNATURE_WINDOW_SECONDS_V1`].
///
/// Sie gilt NUR nach vorn, und sie verlaengert nichts: `expires` bleibt
/// unveraendert die harte Grenze, und die Fensterbreite wird weiterhin gegen
/// [`MAX_SIGNATURE_WINDOW_SECONDS_V1`] gestellt.
pub const MAX_CLOCK_SKEW_MS_V1: i64 = 60_000;

/// Derselbe Vorlauf in der Einheit, in der `created` auf dem Draht steht.
///
/// Er steht als eigene Konstante da, weil `created` SEKUNDEN traegt und die
/// Millisekundenzahl gegen sie gestellt ein Fenster von siebzehn Stunden
/// waere — ein Einheitenfehler, den kein Zeuge mit plausiblen Werten faengt.
const MAX_CLOCK_SKEW_SECONDS_V1: i64 = MAX_CLOCK_SKEW_MS_V1 / 1_000;

/// SHA-256 ueber die uebertragenen Koerperbytes — das Urbild des
/// RFC-9530-`content-digest`.
#[must_use]
pub fn body_digest(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(body);
    hasher.finalize().into()
}

/// Das organisationsgebundene `tag` des Profils: die 32 Kleinbuchstaben-Hexziffern
/// der 16-Byte-`organizationId`. Es traegt keinen fachlichen Wert.
#[must_use]
pub fn organization_tag(organization_id: OrganizationId) -> String {
    hex::encode(organization_id.as_bytes())
}

/// Die HTTP-Methoden, die die v1-API kennt.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
}

impl HttpMethod {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
        }
    }
}

/// Die abgedeckten Komponenten des Einsatzarchiv-Profils.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SignatureComponent {
    Method,
    Authority,
    TargetUri,
    ContentType,
    ContentDigest,
    RequestId,
}

impl SignatureComponent {
    #[must_use]
    pub const fn identifier(self) -> &'static str {
        match self {
            Self::Method => "@method",
            Self::Authority => "@authority",
            Self::TargetUri => "@target-uri",
            Self::ContentType => "content-type",
            Self::ContentDigest => "content-digest",
            Self::RequestId => REQUEST_ID_HEADER_V1,
        }
    }

    fn parse(identifier: &str) -> Option<Self> {
        match identifier {
            "@method" => Some(Self::Method),
            "@authority" => Some(Self::Authority),
            "@target-uri" => Some(Self::TargetUri),
            "content-type" => Some(Self::ContentType),
            "content-digest" => Some(Self::ContentDigest),
            REQUEST_ID_HEADER_V1 => Some(Self::RequestId),
            _ => None,
        }
    }
}

/// Die global eindeutige Request-ID: 16 Byte, auf der Leitung 32 Hexziffern.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct RequestIdV1([u8; 16]);

impl RequestIdV1 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    #[must_use]
    pub fn to_header_value(self) -> String {
        hex::encode(self.0)
    }

    fn parse(value: &str) -> Option<Self> {
        let bytes = hex::decode(value).ok()?;
        if value.len() != 32 || value.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return None;
        }
        <[u8; 16]>::try_from(bytes.as_slice()).ok().map(Self)
    }
}

impl TryFrom<&[u8]> for RequestIdV1 {
    type Error = SyncProtocolError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        <[u8; 16]>::try_from(value)
            .map(Self)
            .map_err(|_| SyncProtocolError::FrameShape)
    }
}

impl fmt::Debug for RequestIdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "RequestIdV1({})", hex::encode(self.0))
    }
}

/// Die Signaturparameter, die der Aufrufer setzt.
#[derive(Clone, Eq, PartialEq)]
pub struct SignatureParametersV1 {
    created: i64,
    expires: i64,
    nonce: [u8; 32],
    tag: String,
}

impl SignatureParametersV1 {
    #[must_use]
    pub const fn new(created: i64, expires: i64, nonce: [u8; 32], tag: String) -> Self {
        Self {
            created,
            expires,
            nonce,
            tag,
        }
    }

    #[must_use]
    pub const fn created(&self) -> i64 {
        self.created
    }

    #[must_use]
    pub const fn expires(&self) -> i64 {
        self.expires
    }

    #[must_use]
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    #[must_use]
    pub fn tag(&self) -> &str {
        &self.tag
    }
}

impl fmt::Debug for SignatureParametersV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SignatureParametersV1(<bound>)")
    }
}

/// Die Bestandteile eines Requests, aus denen der Signierer die Basis baut.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestParts {
    pub method: HttpMethod,
    pub authority: String,
    pub target_uri: String,
    /// `Some`, sobald der Request einen Koerper traegt.
    pub content_type: Option<String>,
    /// SHA-256 ueber die gesendeten Koerperbytes.
    pub body_digest: Option<[u8; 32]>,
    pub request_id: RequestIdV1,
}

/// Ein Request, so wie der Transport ihn empfangen hat.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedRequestV1 {
    pub method: HttpMethod,
    pub authority: String,
    pub target_uri: String,
    pub content_type: Option<String>,
    /// Der `content-digest`-Header, unveraendert wie empfangen.
    pub content_digest: Option<String>,
    /// Der `ea-request-id`-Header, unveraendert wie empfangen.
    pub request_id: Option<String>,
    /// SHA-256, die der Transport ueber die empfangenen Bytes gebildet hat.
    /// Sie entsteht beim Streamen, damit kein Koerper vor der Pruefung im
    /// Speicher liegen muss.
    pub body_digest: Option<[u8; 32]>,
}

/// Ein empfangener oder gebauter Request samt seiner RFC-9421-Signatur.
#[derive(Clone, Eq, PartialEq)]
pub struct SignedRequestV1 {
    method: HttpMethod,
    authority: String,
    target_uri: String,
    content_type: Option<String>,
    content_digest: Option<String>,
    request_id: RequestIdV1,
    body_digest: Option<[u8; 32]>,
    covered: Vec<SignatureComponent>,
    parameters: SignatureParametersV1,
    key_thumbprint: KeyThumbprint,
    signature: [u8; 64],
}

impl SignedRequestV1 {
    /// Liest einen empfangenen Request mit seinen beiden Signaturheadern ein.
    pub fn parse(
        received: &ReceivedRequestV1,
        signature_input: &str,
        signature: &str,
    ) -> Result<Self, SyncProtocolError> {
        let (covered, parameters, key_thumbprint) = parse_signature_input(signature_input)?;
        let signature = parse_signature_header(signature)?;
        for component in &covered {
            let present = match component {
                SignatureComponent::Method
                | SignatureComponent::Authority
                | SignatureComponent::TargetUri => true,
                SignatureComponent::ContentType => received.content_type.is_some(),
                SignatureComponent::ContentDigest => received.content_digest.is_some(),
                SignatureComponent::RequestId => received.request_id.is_some(),
            };
            if !present {
                return Err(SyncProtocolError::SignatureCoverage);
            }
        }
        let request_id = received
            .request_id
            .as_deref()
            .ok_or(SyncProtocolError::SignatureCoverage)?;
        let request_id =
            RequestIdV1::parse(request_id).ok_or(SyncProtocolError::SignatureMalformed)?;
        Ok(Self {
            method: received.method,
            authority: received.authority.clone(),
            target_uri: received.target_uri.clone(),
            content_type: received.content_type.clone(),
            content_digest: received.content_digest.clone(),
            request_id,
            body_digest: received.body_digest,
            covered,
            parameters,
            key_thumbprint,
            signature,
        })
    }

    /// Der Request in der Form, in der ein Transport ihn wieder ausliefert.
    #[must_use]
    pub fn to_received(&self) -> ReceivedRequestV1 {
        ReceivedRequestV1 {
            method: self.method,
            authority: self.authority.clone(),
            target_uri: self.target_uri.clone(),
            content_type: self.content_type.clone(),
            content_digest: self.content_digest.clone(),
            request_id: Some(self.request_id.to_header_value()),
            body_digest: self.body_digest,
        }
    }

    /// Die Signaturbasis nach RFC 9421 §2.5: je abgedeckter Komponente eine
    /// Zeile, zuletzt `@signature-params` OHNE abschliessenden Zeilenumbruch.
    #[must_use]
    pub fn signature_base(&self) -> String {
        let mut base = String::with_capacity(512);
        for component in &self.covered {
            base.push('"');
            base.push_str(component.identifier());
            base.push_str("\": ");
            base.push_str(&self.component_value(*component));
            base.push('\n');
        }
        base.push_str("\"@signature-params\": ");
        base.push_str(&self.signature_parameters_value());
        base
    }

    /// Der Wert des `Signature-Input`-Headers.
    #[must_use]
    pub fn signature_input_header(&self) -> String {
        format!("{SIGNATURE_LABEL_V1}={}", self.signature_parameters_value())
    }

    /// Der Wert des `Signature`-Headers.
    #[must_use]
    pub fn signature_header(&self) -> String {
        format!("{SIGNATURE_LABEL_V1}=:{}:", base64_encode(&self.signature))
    }

    /// Der RFC-9530-`content-digest`-Header, sofern der Request einen Koerper
    /// traegt.
    #[must_use]
    pub fn content_digest_header(&self) -> Option<&str> {
        self.content_digest.as_deref()
    }

    #[must_use]
    pub const fn key_thumbprint(&self) -> KeyThumbprint {
        self.key_thumbprint
    }

    #[must_use]
    pub const fn parameters(&self) -> &SignatureParametersV1 {
        &self.parameters
    }

    #[must_use]
    pub const fn request_id(&self) -> RequestIdV1 {
        self.request_id
    }

    #[must_use]
    pub fn covered_components(&self) -> &[SignatureComponent] {
        &self.covered
    }

    fn component_value(&self, component: SignatureComponent) -> String {
        match component {
            SignatureComponent::Method => self.method.as_str().to_owned(),
            SignatureComponent::Authority => self.authority.clone(),
            SignatureComponent::TargetUri => self.target_uri.clone(),
            SignatureComponent::ContentType => self.content_type.clone().unwrap_or_default(),
            SignatureComponent::ContentDigest => self.content_digest.clone().unwrap_or_default(),
            SignatureComponent::RequestId => self.request_id.to_header_value(),
        }
    }

    /// `("…" "…");created=…;expires=…;nonce="…";keyid="…";alg="ed25519";tag="…"`
    fn signature_parameters_value(&self) -> String {
        let list = self
            .covered
            .iter()
            .map(|component| format!("\"{}\"", component.identifier()))
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            "({list});created={};expires={};nonce=\"{}\";keyid=\"{}\";alg=\"{SIGNATURE_ALGORITHM_V1}\";tag=\"{}\"",
            self.parameters.created,
            self.parameters.expires,
            hex::encode(self.parameters.nonce),
            hex::encode(self.key_thumbprint.as_bytes()),
            self.parameters.tag,
        )
    }
}

impl fmt::Debug for SignedRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SignedRequestV1(<bound>)")
    }
}

/// Die klientenseitige Haelfte des Profils.
///
/// Ohne Wirtsabhaengigkeit: der Schluessel kommt herein, die Zeit und die
/// Einmalwerte kommen herein, und nichts davon wird hier beschafft.
pub struct RequestSigner {
    key: SigningKey,
    public: CanonicalPublicCoseKey,
    key_thumbprint: KeyThumbprint,
}

impl RequestSigner {
    /// Der Signierer aus dem geheimen Ed25519-Skalar.
    ///
    /// # Panics
    ///
    /// Nie: ein Ed25519-Signaturschluessel erzeugt immer einen gueltigen
    /// oeffentlichen Punkt, und `CanonicalPublicCoseKey::ed25519` lehnt nur
    /// ungueltige oder schwache Punkte ab.
    #[must_use]
    pub fn from_secret(secret: SecretBytes<32>) -> Self {
        let key = secret.with_exposed(SigningKey::from_bytes);
        let public = CanonicalPublicCoseKey::ed25519(*key.verifying_key().as_bytes())
            .expect("an Ed25519 signing key always yields a valid public point");
        let key_thumbprint = public.thumbprint();
        Self {
            key,
            public,
            key_thumbprint,
        }
    }

    #[must_use]
    pub fn public_key(&self) -> CanonicalPublicCoseKey {
        self.public.clone()
    }

    #[must_use]
    pub const fn key_thumbprint(&self) -> KeyThumbprint {
        self.key_thumbprint
    }

    /// Signiert genau die Komponentenliste des Profils.
    pub fn sign(
        &self,
        parts: &RequestParts,
        parameters: &SignatureParametersV1,
    ) -> Result<SignedRequestV1, SyncProtocolError> {
        if parts.content_type.is_some() != parts.body_digest.is_some() {
            return Err(SyncProtocolError::ContentTypeMismatch);
        }
        let content_digest = parts
            .body_digest
            .map(|digest| content_digest_header(&digest));
        let mut covered = vec![
            SignatureComponent::Method,
            SignatureComponent::Authority,
            SignatureComponent::TargetUri,
        ];
        if parts.content_type.is_some() {
            covered.push(SignatureComponent::ContentType);
            covered.push(SignatureComponent::ContentDigest);
        }
        covered.push(SignatureComponent::RequestId);
        let mut request = SignedRequestV1 {
            method: parts.method,
            authority: parts.authority.clone(),
            target_uri: parts.target_uri.clone(),
            content_type: parts.content_type.clone(),
            content_digest,
            request_id: parts.request_id,
            body_digest: parts.body_digest,
            covered,
            parameters: parameters.clone(),
            key_thumbprint: self.key_thumbprint,
            signature: [0; 64],
        };
        request.signature = self
            .key
            .sign(request.signature_base().as_bytes())
            .to_bytes();
        Ok(request)
    }
}

impl fmt::Debug for RequestSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestSigner(<bound>)")
    }
}

/// Ein freigegebenes Geraet, wie der Server es kennt.
#[derive(Clone, Eq, PartialEq)]
pub struct RegisteredDevice {
    organization_id: OrganizationId,
    certificate_hash: CertificateHash,
    public_key: CanonicalPublicCoseKey,
    key_thumbprint: KeyThumbprint,
    capabilities: Vec<CertificateCapability>,
}

impl RegisteredDevice {
    #[must_use]
    pub fn new(
        organization_id: OrganizationId,
        certificate_hash: CertificateHash,
        public_key: CanonicalPublicCoseKey,
        capabilities: Vec<CertificateCapability>,
    ) -> Self {
        let key_thumbprint = public_key.thumbprint();
        Self {
            organization_id,
            certificate_hash,
            public_key,
            key_thumbprint,
            capabilities,
        }
    }

    #[must_use]
    pub const fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }

    #[must_use]
    pub const fn certificate_hash(&self) -> CertificateHash {
        self.certificate_hash
    }

    #[must_use]
    pub const fn key_thumbprint(&self) -> KeyThumbprint {
        self.key_thumbprint
    }

    #[must_use]
    pub fn capabilities(&self) -> &[CertificateCapability] {
        &self.capabilities
    }
}

impl fmt::Debug for RegisteredDevice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RegisteredDevice(<bound>)")
    }
}

/// Die Aufloesung von `keyid` auf ein freigegebenes Geraetezertifikat.
pub trait DeviceDirectory {
    fn lookup(&self, key_thumbprint: KeyThumbprint) -> Option<RegisteredDevice>;
}

/// Der Einmalspeicher fuer Nonces und Request-IDs.
///
/// Beide Methoden geben `true` zurueck, wenn der Wert VORHER unbenutzt war.
/// Getrennte Methoden statt eines gemeinsamen Speichers: nur so bleiben
/// `EA-HTTP-NONCE-REPLAY` und `EA-HTTP-REQUEST-ID-REPLAY` unterscheidbar.
pub trait ReplayStore {
    fn claim_nonce(&mut self, nonce: &[u8; 32]) -> bool;
    fn claim_request_id(&mut self, request_id: RequestIdV1) -> bool;
}

/// Das Ergebnis einer erfolgreichen Requestpruefung.
#[derive(Clone, Eq, PartialEq)]
pub enum AuthenticatedDevice {
    /// Ein freigegebenes Geraet mit Organisationsautoritaet.
    Certified {
        organization_id: OrganizationId,
        certificate_hash: CertificateHash,
        key_thumbprint: KeyThumbprint,
        capabilities: Vec<CertificateCapability>,
    },
    /// Der beantragte, noch nicht freigegebene Geraeteschluessel von
    /// `POST /v1/device-registrations`. Er traegt WEDER Zertifikatskette NOCH
    /// Capability NOCH Organisationsautoritaet.
    ProofOfPossession { requested_key: KeyThumbprint },
}

impl fmt::Debug for AuthenticatedDevice {
    /// Ohne Bezeichner und ohne Hash: ein Log oder ein Testbericht traegt
    /// hoechstens die ART der Identitaet, nie ihren Wert.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Certified { .. } => "AuthenticatedDevice::Certified(<bound>)",
            Self::ProofOfPossession { .. } => "AuthenticatedDevice::ProofOfPossession(<bound>)",
        })
    }
}

/// Die serverseitige Haelfte des Profils.
pub struct RequestVerifier<'a> {
    endpoint: EndpointV1,
    authority: &'a str,
    organization_id: OrganizationId,
    now_seconds: i64,
    directory: &'a dyn DeviceDirectory,
    requested_key: Option<CanonicalPublicCoseKey>,
}

impl<'a> RequestVerifier<'a> {
    #[must_use]
    pub fn new(
        endpoint: EndpointV1,
        authority: &'a str,
        organization_id: OrganizationId,
        now_seconds: i64,
        directory: &'a dyn DeviceDirectory,
    ) -> Self {
        Self {
            endpoint,
            authority,
            organization_id,
            now_seconds,
            directory,
            requested_key: None,
        }
    }

    /// Der beantragte Schluessel aus dem Koerper von
    /// `POST /v1/device-registrations`.
    ///
    /// Er MUSS von aussen kommen: ein `keyThumbprint` ist ein Hash und traegt
    /// den oeffentlichen Punkt nicht in sich. Ohne ihn scheitert die
    /// Registrierung mit `EA-HTTP-KEY-UNRESOLVED`, statt still zu bestehen.
    #[must_use]
    pub fn with_requested_key(mut self, requested_key: CanonicalPublicCoseKey) -> Self {
        self.requested_key = Some(requested_key);
        self
    }

    /// Prueft einen Request und liefert die Identitaet, gegen die geroutet
    /// werden darf.
    pub fn verify(
        &self,
        request: &SignedRequestV1,
        store: &mut dyn ReplayStore,
    ) -> Result<AuthenticatedDevice, SyncProtocolError> {
        self.check_coverage(request)?;
        self.check_target(request)?;
        self.check_window(request)?;
        self.check_content_digest(request)?;
        let key = self.resolve_key(request)?;
        key.public
            .verify_ed25519_strict(request.signature_base().as_bytes(), &request.signature)
            .map_err(|_| SyncProtocolError::SignatureInvalid)?;
        if !store.claim_nonce(request.parameters.nonce()) {
            return Err(SyncProtocolError::NonceReplay);
        }
        if !store.claim_request_id(request.request_id) {
            return Err(SyncProtocolError::RequestIdReplay);
        }
        match key.device {
            None => Ok(AuthenticatedDevice::ProofOfPossession {
                requested_key: request.key_thumbprint,
            }),
            Some(device) => {
                if device.organization_id != self.organization_id {
                    return Err(SyncProtocolError::OrganizationMismatch);
                }
                if let Some(required) = self.endpoint.required_capability()
                    && !device.capabilities.contains(&required)
                {
                    return Err(SyncProtocolError::CapabilityMissing);
                }
                Ok(AuthenticatedDevice::Certified {
                    organization_id: device.organization_id,
                    certificate_hash: device.certificate_hash,
                    key_thumbprint: device.key_thumbprint,
                    capabilities: device.capabilities,
                })
            }
        }
    }

    fn check_coverage(&self, request: &SignedRequestV1) -> Result<(), SyncProtocolError> {
        let mut seen = Vec::with_capacity(request.covered.len());
        for component in &request.covered {
            if seen.contains(component) {
                return Err(SyncProtocolError::SignatureDuplicateComponent);
            }
            seen.push(*component);
        }
        let mut required = vec![
            SignatureComponent::Method,
            SignatureComponent::Authority,
            SignatureComponent::TargetUri,
            SignatureComponent::RequestId,
        ];
        if self.endpoint.request_media_type().is_some() {
            required.push(SignatureComponent::ContentType);
            required.push(SignatureComponent::ContentDigest);
        }
        if required.iter().any(|component| !seen.contains(component)) {
            return Err(SyncProtocolError::SignatureCoverage);
        }
        Ok(())
    }

    fn check_target(&self, request: &SignedRequestV1) -> Result<(), SyncProtocolError> {
        if request.authority != self.authority {
            return Err(SyncProtocolError::AuthorityMismatch);
        }
        let expected_prefix = format!("https://{}", self.authority);
        let Some(path) = request.target_uri.strip_prefix(&expected_prefix) else {
            return Err(SyncProtocolError::TargetUriMismatch);
        };
        if request.method != self.endpoint.method() || !self.endpoint.matches_path(path) {
            return Err(SyncProtocolError::TargetUriMismatch);
        }
        if request.parameters.tag != organization_tag(self.organization_id) {
            return Err(SyncProtocolError::TagMismatch);
        }
        match (self.endpoint.request_media_type(), &request.content_type) {
            (Some(expected), Some(actual)) if expected == actual => Ok(()),
            (None, None) => Ok(()),
            _ => Err(SyncProtocolError::ContentTypeMismatch),
        }
    }

    fn check_window(&self, request: &SignedRequestV1) -> Result<(), SyncProtocolError> {
        let parameters = &request.parameters;
        if parameters.created >= parameters.expires
            || parameters
                .expires
                .checked_sub(parameters.created)
                .is_none_or(|window| window > MAX_SIGNATURE_WINDOW_SECONDS_V1)
        {
            return Err(SyncProtocolError::WindowInvalid);
        }
        if self.now_seconds > parameters.expires {
            return Err(SyncProtocolError::RequestExpired);
        }
        // Nach vorn mit Toleranz: eine leicht vorgehende Uhr ist ein
        // Betriebszustand und kein Angriff. Jenseits der Toleranz bleibt es
        // fail-closed.
        if self.now_seconds.saturating_add(MAX_CLOCK_SKEW_SECONDS_V1) < parameters.created {
            return Err(SyncProtocolError::WindowInvalid);
        }
        Ok(())
    }

    fn check_content_digest(&self, request: &SignedRequestV1) -> Result<(), SyncProtocolError> {
        if self.endpoint.request_media_type().is_none() {
            return Ok(());
        }
        let (Some(digest), Some(header)) = (request.body_digest, request.content_digest.as_deref())
        else {
            return Err(SyncProtocolError::ContentDigestMismatch);
        };
        if content_digest_header(&digest) == header {
            Ok(())
        } else {
            Err(SyncProtocolError::ContentDigestMismatch)
        }
    }

    fn resolve_key(&self, request: &SignedRequestV1) -> Result<ResolvedKey, SyncProtocolError> {
        if self.endpoint.authentication() == EndpointAuthentication::ProofOfPossession {
            let requested = self
                .requested_key
                .clone()
                .ok_or(SyncProtocolError::KeyUnresolved)?;
            if requested.thumbprint() != request.key_thumbprint {
                return Err(SyncProtocolError::KeyUnresolved);
            }
            return Ok(ResolvedKey {
                public: requested,
                device: None,
            });
        }
        let device = self
            .directory
            .lookup(request.key_thumbprint)
            .ok_or(SyncProtocolError::KeyUnresolved)?;
        Ok(ResolvedKey {
            public: device.public_key.clone(),
            device: Some(device),
        })
    }
}

impl fmt::Debug for RequestVerifier<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestVerifier(<bound>)")
    }
}

struct ResolvedKey {
    public: CanonicalPublicCoseKey,
    /// `None` genau auf dem Proof-of-Possession-Pfad.
    device: Option<RegisteredDevice>,
}

/// Der RFC-9530-Header ueber genau die uebertragenen Bytes.
///
/// Genau EIN Digest, genau `sha-256`, keine Parameter. Die Pruefung vergleicht
/// die ZEICHENKETTE gegen den neu gebildeten Wert; damit deckt sie exakt das
/// ab, was RFC 9421 signiert, und braucht keinen Base64-Dekodierer.
///
/// OEFFENTLICH, weil die Objektauslieferung des Servers denselben Header
/// bildet. Sie tat es einmal mit einem ZWEITEN, von Hand geschriebenen
/// Base64-Kodierer — zwei Umsetzungen derselben RFC-Abbildung, von denen eine
/// irgendwann die falsche gewesen waere.
#[must_use]
pub fn content_digest_header(digest: &[u8; 32]) -> String {
    format!("sha-256=:{}:", base64_encode(digest))
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64 nach RFC 4648 §4 mit Fuellzeichen.
///
/// Der Kodierer steht HIER und nicht in einer weiteren gepinnten
/// Fremdabhaengigkeit: RFC 9421 und RFC 9530 verlangen genau diese eine
/// Abbildung, sie ist vollstaendig durch die beiden RFCs bestimmt, und eine
/// zusaetzliche Pinnung haette einen ADR-Eintrag mit Veroeffentlichungsdatum,
/// MSRV und RustSec-Durchsicht verlangt, den dieser Task nicht belegen kann.
fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut buffer = [0u8; 3];
        buffer[..chunk.len()].copy_from_slice(chunk);
        let value = u32::from(buffer[0]) << 16 | u32::from(buffer[1]) << 8 | u32::from(buffer[2]);
        for index in 0..4 {
            if index <= chunk.len() {
                let position = (value >> (18 - 6 * index)) & 0x3f;
                out.push(char::from(BASE64_ALPHABET[position as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Base64 nach RFC 4648 §4 auf genau `N` Bytes.
///
/// Bewusst LAENGENFEST: die einzige Stelle, die dekodiert, ist die 64 Byte
/// lange Signatur. Eine falsche Eingabelaenge, ein Zeichen ausserhalb des
/// Alphabets oder ein nicht kanonisches letztes Quantum sind fail-closed.
fn base64_decode_exact<const N: usize>(input: &str) -> Option<[u8; N]> {
    if input.len() != N.div_ceil(3) * 4 {
        return None;
    }
    let symbols = input.as_bytes();
    let last_chunk = symbols.len() / 4 - 1;
    let mut out = Vec::with_capacity(N);
    for (chunk_index, chunk) in symbols.chunks(4).enumerate() {
        let padding = chunk.iter().filter(|symbol| **symbol == b'=').count();
        if padding > 0 && (chunk_index != last_chunk || padding > 2) {
            return None;
        }
        // Fuellzeichen stehen ausschliesslich am Ende des letzten Quantums.
        if chunk[4 - padding..].iter().any(|symbol| *symbol != b'=') {
            return None;
        }
        let mut value = 0u32;
        for (index, symbol) in chunk[..4 - padding].iter().enumerate() {
            let position = BASE64_ALPHABET.iter().position(|entry| entry == symbol)?;
            value |= (position as u32) << (18 - 6 * index);
        }
        // Kanonisch: die ungenutzten unteren Bits des letzten Quantums sind 0.
        if value & ((1u32 << (8 * padding)) - 1) != 0 {
            return None;
        }
        out.extend_from_slice(&value.to_be_bytes()[1..=3 - padding]);
    }
    <[u8; N]>::try_from(out.as_slice()).ok()
}

fn parse_signature_header(header: &str) -> Result<[u8; 64], SyncProtocolError> {
    let value = header
        .strip_prefix(&format!("{SIGNATURE_LABEL_V1}=:"))
        .and_then(|rest| rest.strip_suffix(':'))
        .ok_or(SyncProtocolError::SignatureMalformed)?;
    base64_decode_exact::<64>(value).ok_or(SyncProtocolError::SignatureMalformed)
}

type ParsedSignatureInput = (
    Vec<SignatureComponent>,
    SignatureParametersV1,
    KeyThumbprint,
);

fn parse_signature_input(header: &str) -> Result<ParsedSignatureInput, SyncProtocolError> {
    let rest = header
        .strip_prefix(&format!("{SIGNATURE_LABEL_V1}=("))
        .ok_or(SyncProtocolError::SignatureMalformed)?;
    let (list, parameters) = rest
        .split_once(')')
        .ok_or(SyncProtocolError::SignatureMalformed)?;
    let mut covered = Vec::new();
    if !list.is_empty() {
        for identifier in list.split(' ') {
            let identifier = identifier
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .ok_or(SyncProtocolError::SignatureMalformed)?;
            covered.push(
                SignatureComponent::parse(identifier)
                    .ok_or(SyncProtocolError::SignatureMalformed)?,
            );
        }
    }

    let mut created = None;
    let mut expires = None;
    let mut nonce = None;
    let mut key_thumbprint = None;
    let mut algorithm = None;
    let mut tag = None;
    for parameter in parameters.split(';').filter(|part| !part.is_empty()) {
        let (name, value) = parameter
            .split_once('=')
            .ok_or(SyncProtocolError::SignatureMalformed)?;
        let quoted = value
            .strip_prefix('"')
            .and_then(|inner| inner.strip_suffix('"'));
        match name {
            "created" => created = Some(parse_integer(value)?),
            "expires" => expires = Some(parse_integer(value)?),
            "nonce" => {
                nonce = Some(parse_fixed_hex::<32>(
                    quoted.ok_or(SyncProtocolError::SignatureMalformed)?,
                )?);
            }
            "keyid" => {
                let raw =
                    parse_fixed_hex::<32>(quoted.ok_or(SyncProtocolError::SignatureMalformed)?)?;
                key_thumbprint = Some(
                    KeyThumbprint::try_from(raw.as_slice())
                        .map_err(|_| SyncProtocolError::SignatureMalformed)?,
                );
            }
            "alg" => algorithm = quoted.map(str::to_owned),
            "tag" => tag = quoted.map(str::to_owned),
            _ => return Err(SyncProtocolError::SignatureMalformed),
        }
    }
    if algorithm.as_deref() != Some(SIGNATURE_ALGORITHM_V1) {
        return Err(SyncProtocolError::UnsupportedAlgorithm);
    }
    Ok((
        covered,
        SignatureParametersV1::new(
            created.ok_or(SyncProtocolError::SignatureMalformed)?,
            expires.ok_or(SyncProtocolError::SignatureMalformed)?,
            nonce.ok_or(SyncProtocolError::SignatureMalformed)?,
            tag.ok_or(SyncProtocolError::SignatureMalformed)?,
        ),
        key_thumbprint.ok_or(SyncProtocolError::SignatureMalformed)?,
    ))
}

fn parse_integer(value: &str) -> Result<i64, SyncProtocolError> {
    value
        .parse()
        .map_err(|_| SyncProtocolError::SignatureMalformed)
}

fn parse_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], SyncProtocolError> {
    if value.len() != N * 2 || value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(SyncProtocolError::SignatureMalformed);
    }
    let bytes = hex::decode(value).map_err(|_| SyncProtocolError::SignatureMalformed)?;
    <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| SyncProtocolError::SignatureMalformed)
}

#[cfg(test)]
mod tests {
    use super::{base64_decode_exact, base64_encode};

    #[test]
    fn base64_round_trips_and_rejects_every_malformed_input() {
        let value = [0x9au8; 32];
        let encoded = base64_encode(&value);
        assert_eq!(encoded.len(), 44);
        assert_eq!(base64_decode_exact::<32>(&encoded), Some(value));
        // Ein Zeichen ausserhalb des Alphabets.
        assert_eq!(
            base64_decode_exact::<32>(&format!("{}!", &encoded[..43])),
            None
        );
        // Eine falsche Laenge.
        assert_eq!(base64_decode_exact::<32>(&encoded[..40]), None);
        // Eine Eingabe, die zu einer anderen festen Laenge gehoert.
        assert_eq!(base64_decode_exact::<64>(&encoded), None);
        // Ein nicht kanonisches letztes Quantum: `Zh==` traegt gesetzte
        // Fuellbits, `Zg==` ist die kanonische Form derselben zwei Bytes.
        assert_eq!(base64_decode_exact::<1>("Zh=="), None);
        assert_eq!(base64_decode_exact::<1>("Zg=="), Some([b'f']));
    }

    #[test]
    fn base64_encodes_the_rfc_4648_test_vectors() {
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }
}
