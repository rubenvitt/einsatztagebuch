//! Die transportneutralen Dienste der Auth- und Webflaeche.
//!
//! Hier steht KEIN Axum und KEIN sqlx: der Dienst kennt nur die Ports aus
//! [`crate::ports`], die Rahmen aus `ea-sync-protocol` und die sechs
//! Protokollkerne aus `ea-crypto`. Ein eigener Kodierer existiert nicht — der
//! waere die zweite Quelle der Wahrheit, gegen die `challenge-response-v1`
//! irgendwann abdriftete.
//!
//! # Die Reihenfolge der Einmalwerte
//!
//! Der Sync-Wire-Nachtrag schreibt sie vollstaendig aus: „… Signatur,
//! **Einmalverbrauch von Nonce und Request-ID, zuletzt Organisationsbindung
//! und Capability**“. Der Verbrauch liegt also NACH der Signatur und VOR der
//! Autorisierung — beide Grenzen zaehlen.
//!
//! [`ea_sync_protocol::RequestVerifier`] haelt diese Reihenfolge intern
//! bereits ein, ruft seinen [`ea_sync_protocol::ReplayStore`] aber SYNCHRON,
//! waehrend die Einmalspeicher dieses Servers in PostgreSQL liegen. Der
//! Pruefer bekommt deshalb [`DeferredReplayStore`], der nichts verbraucht, und
//! [`authenticate`] holt den Verbrauch an der richtigen Stelle nach.
//!
//! „An der richtigen Stelle“ heisst konkret: verbraucht wird auch dann, wenn
//! der Pruefer mit `EA-HTTP-ORGANIZATION-MISMATCH` oder
//! `EA-HTTP-CAPABILITY-MISSING` endet. Das sind die EINZIGEN beiden Befunde,
//! die er nach gueltiger Signatur noch erheben kann
//! (`crates/ea-sync-protocol/src/http_signature.rs`, `verify`), also
//! reproduziert genau diese Menge die Reihenfolge des Nachtrags. Ohne sie
//! behielte ein Aufrufer, dem die Capability fehlt, seine Challenge und seine
//! Request-ID und koennte damit beliebig oft nachfassen.
//!
//! Der Vorrang bleibt dabei der des Nachtrags: reisst der Verbrauch, gewinnt
//! sein Befund (`EA-AUTH-NONCE-REPLAY`) ueber die spaetere
//! Autorisierungsabweisung.
//!
//! # Was die Registrierung NICHT tut
//!
//! `POST /v1/device-registrations` legt einen Antrag ab und sonst nichts. Kein
//! Zertifikat, keine Rolle, keine Capability, kein Trust-Objekt. Die Freigabe
//! entsteht ausschliesslich aus einem Root-signierten Trust-Objekt
//! (`design.md` §12), und dasselbe gilt fuer
//! `POST /v1/webauthn-credentials`: die Registrierung eines Credentials
//! entscheidet allein, wem der Server spaeter ein Chiffrat aushaendigt, das
//! ohne Authenticator wertlos ist (`web-reader-design.md` §6.4.1).

use core::fmt;

use ea_crypto::{ChallengeResponseCoreV1, CoseVerifier, DeviceRegistrationRequestCoreV1};
use ea_sync_protocol::{
    AuthenticatedDevice, ChallengeRequestV1, ChallengeResponseV1, DeviceDirectory,
    DeviceRegistrationRequestV1, EndpointAuthentication, EndpointV1, RegisteredDevice, ReplayStore,
    RequestIdV1, RequestVerifier, SignedRequestV1, SyncProtocolError,
    WebauthnCredentialRegistrationV1, body_digest, organization_tag,
};
use ea_types::{Hash32, KeyThumbprint, OrganizationId, UnixMillis};

use crate::{
    RepositoryError, ServerClock, ServerSigner,
    models::{
        CredentialRegistrationOutcome, PENDING_REGISTRATION_STATE_V1, PendingDeviceRequestV1,
        PendingRegistrationOutcome, WebauthnCredentialV1,
    },
    ports::{
        ChallengeSpendOutcome, ChallengeStore, DeviceAuthorityDirectory, DeviceRegistrationStore,
        RequestIdStore, WebauthnCredentialStore,
    },
};

/// Die Lebensdauer einer Challenge.
///
/// Sie ist bewusst kuerzer als das groesste Signaturfenster von 300 Sekunden:
/// die Nonce soll nicht laenger offen stehen als der Request, den sie deckt.
pub const CHALLENGE_LIFETIME_MILLIS_V1: i64 = 120_000;

/// Das Fenster der Ratenbegrenzung und die Zahl der Challenges darin.
///
/// Gezaehlt wird je AUFRUFER — ueber den verbindungsseitigen Zaehlschluessel,
/// den `apps/server` aus der Gegenstellenadresse bildet — und ausdruecklich
/// NICHT je Organisation. Die `organizationId` steht beim Challenge-Endpunkt
/// im unsignierten Koerper: eine Begrenzung darauf liesse jeden Fremden eine
/// Organisation mit ihrer eigenen, oeffentlich mitgereisten Kennung
/// aussperren, und weil jeder signierte Request eine frische Challenge
/// braucht, waere das der Totalausfall dieser Organisation.
///
/// Die Zahl ist deshalb auch keine Durchsatzdecke einer Organisation mehr:
/// sechshundert Challenges je Minute und Gegenstelle sind grosszuegig fuer ein
/// Geraet und eng genug, dass eine einzelne Quelle den Endpunkt nicht flutet.
pub const CHALLENGE_RATE_WINDOW_MILLIS_V1: i64 = 60_000;
pub const CHALLENGE_RATE_LIMIT_V1: u64 = 600;

/// Wie lange eine verbrauchte Request-ID gesperrt bleibt.
///
/// Genau das groesste Signaturfenster: laenger braucht es nicht, kuerzer
/// oeffnete ein Replay.
pub const REQUEST_ID_LIFETIME_MILLIS_V1: i64 = 300_000;

/// Jeder Befund der Dienstschicht ueber dem Protokollrahmen.
///
/// Er steht NEBEN [`SyncProtocolError`] und nicht darin: die Rahmenschicht
/// kennt keine Challenge-Ablage und keinen Registrierungsantrag. Jeder Arm
/// traegt einen stabilen Code und genau eine HTTP-Abbildung; kein Code und
/// keine Meldung traegt ein Fragment des gelieferten Koerpers.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum AuthServiceError {
    /// Zu dieser Nonce hat der Server nie eine Challenge ausgegeben.
    ChallengeUnknown,
    /// Die Challenge ist abgelaufen.
    ChallengeExpired,
    /// Die Challenge war schon verbraucht.
    NonceReplay,
    /// Die Request-ID war schon da.
    RequestIdReplay,
    /// Die Ratenbegrenzung des Challenge-Endpunkts.
    RateLimited,
    /// Fuer dieses Geraet liegt bereits ein ANDERER Antrag vor.
    RegistrationConflict,
    /// Diese `credentialId` gehoert bereits einer anderen `subjectId`.
    CredentialConflict,
    /// `keyid` benennt kein aktuell freigegebenes Geraet dieser Organisation.
    DeviceUnauthorized,
    /// Der persistente Vertrauenszustand hat sich unter dem Aufrufer bewegt.
    /// Wiederholbar, und ausdruecklich KEINE Aussage ueber seine Autoritaet.
    TrustStateConflict,
    /// Datenbank oder Object Store antworten nicht.
    DependencyUnavailable,
    /// Interner Fehler ohne fachliche Ursache.
    Internal,
    /// Ein durchgereichter Rahmen- oder Signaturbefund.
    Protocol(SyncProtocolError),
}

impl AuthServiceError {
    /// Jeder eigene Befund dieses Dienstes.
    pub const ALL: [Self; 11] = [
        Self::ChallengeUnknown,
        Self::ChallengeExpired,
        Self::NonceReplay,
        Self::RequestIdReplay,
        Self::RateLimited,
        Self::RegistrationConflict,
        Self::CredentialConflict,
        Self::DeviceUnauthorized,
        Self::TrustStateConflict,
        Self::DependencyUnavailable,
        Self::Internal,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ChallengeUnknown => "EA-AUTH-CHALLENGE-UNKNOWN",
            Self::ChallengeExpired => "EA-AUTH-CHALLENGE-EXPIRED",
            Self::NonceReplay => "EA-AUTH-NONCE-REPLAY",
            Self::RequestIdReplay => "EA-AUTH-REQUEST-ID-REPLAY",
            Self::RateLimited => "EA-AUTH-RATE-LIMITED",
            Self::RegistrationConflict => "EA-AUTH-REGISTRATION-CONFLICT",
            Self::CredentialConflict => "EA-AUTH-CREDENTIAL-CONFLICT",
            Self::DeviceUnauthorized => "EA-AUTH-DEVICE-UNAUTHORIZED",
            Self::TrustStateConflict => "EA-TRUST-STATE-CONFLICT",
            Self::DependencyUnavailable => "EA-AUTH-DEPENDENCY-UNAVAILABLE",
            Self::Internal => "EA-AUTH-INTERNAL",
            Self::Protocol(error) => error.code(),
        }
    }

    /// Die HTTP-Abbildung des Sync-Wire-Nachtrags, Zeile fuer Zeile.
    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            // „fehlende, ungueltige oder abgelaufene Signatur ODER CHALLENGE".
            Self::ChallengeUnknown
            | Self::ChallengeExpired
            | Self::NonceReplay
            | Self::RequestIdReplay
            | Self::DeviceUnauthorized => 401,
            Self::RegistrationConflict | Self::CredentialConflict => 409,
            Self::RateLimited => 429,
            Self::Internal => 500,
            // Wiederholbar: der Aufrufer hat ein Rennen verloren, nicht seine
            // Autoritaet.
            Self::TrustStateConflict | Self::DependencyUnavailable => 503,
            Self::Protocol(error) => error.http_status(),
        }
    }

    /// `retryable` gilt AUSSCHLIESSLICH fuer 429, 500 und 503.
    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(self.http_status(), 429 | 500 | 503)
    }
}

impl From<SyncProtocolError> for AuthServiceError {
    fn from(value: SyncProtocolError) -> Self {
        Self::Protocol(value)
    }
}

impl From<crate::ports::AuthorityError> for AuthServiceError {
    fn from(value: crate::ports::AuthorityError) -> Self {
        match value {
            crate::ports::AuthorityError::Unavailable => Self::DependencyUnavailable,
            crate::ports::AuthorityError::StateConflict => Self::TrustStateConflict,
        }
    }
}

impl From<RepositoryError> for AuthServiceError {
    fn from(value: RepositoryError) -> Self {
        match value {
            RepositoryError::RequestIdReplay => Self::RequestIdReplay,
            // Der Vorgaengerkonflikt der Checkpoint-Kette gehoert dem
            // Commit-Pfad; hier kann er nicht entstehen. Er bleibt trotzdem
            // ein eigener Arm, damit er nicht stillschweigend zu einem
            // Registrierungskonflikt wird.
            RepositoryError::CommitIdentityConflict
            | RepositoryError::HeadConflict
            | RepositoryError::CheckpointPredecessorConflict => Self::RegistrationConflict,
            RepositoryError::Unavailable => Self::DependencyUnavailable,
        }
    }
}

impl fmt::Display for AuthServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for AuthServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for AuthServiceError {}

/// Der Nonce-Digest, unter dem eine Challenge abgelegt wird.
///
/// SHA-256 ueber die 32 Byte der Nonce. Der Klartext der Nonce liegt damit
/// nirgends in der Datenbank, und ein Auslesen der Tabelle gibt keine gueltige
/// Nonce her.
#[must_use]
pub fn challenge_nonce_digest(nonce: &[u8; 32]) -> Hash32 {
    hash32(body_digest(nonce))
}

/// Der Zaehlschluessel der Ratenbegrenzung aus einer Gegenstellenadresse.
///
/// SHA-256 ueber die Adressbytes. Als DIGEST, damit keine Adresse im Klartext
/// in den Bestand kommt: sie ist eine technische Identitaet und trotzdem kein
/// Wert, den ein blinder Server aufheben muss.
#[must_use]
pub fn rate_key_digest(peer: &[u8]) -> Hash32 {
    hash32(body_digest(peer))
}

/// Ein blankes SHA-256-Ergebnis als [`Hash32`].
///
/// `Hash32` nimmt bewusst nur `&[u8]` entgegen, damit keine falsch lange
/// Bytefolge hineinrutscht. Hier ist die Laenge STATISCH 32, der Befund kann
/// also nicht eintreten. Ein stiller Nullhash waere an dieser Stelle das
/// Gefaehrlichste von allem: er machte zwei verschiedene Nonces gleich.
///
/// # Panics
///
/// Nie: `digest` ist ein `[u8; 32]`.
fn hash32(digest: [u8; 32]) -> Hash32 {
    Hash32::try_from(&digest[..]).expect("a SHA-256 digest is exactly 32 bytes")
}

/// Ein [`ReplayStore`], der NICHTS verbraucht.
///
/// Er ist kein Loch, sondern die Bruecke ueber eine Laufzeitgrenze: der Pruefer
/// ist synchron, die Einmalspeicher liegen in PostgreSQL. Der wirkliche
/// Verbrauch passiert in [`authenticate`] unmittelbar nachdem die Signatur
/// gilt — also genau dann, wann der Sync-Wire-Nachtrag ihn verlangt, und nicht
/// frueher. Wer diesen Typ ausserhalb von [`authenticate`] verwendet, hebt die
/// Einmaligkeit auf; deshalb ist er `pub(crate)`.
pub(crate) struct DeferredReplayStore;

impl ReplayStore for DeferredReplayStore {
    fn claim_nonce(&mut self, _nonce: &[u8; 32]) -> bool {
        true
    }

    fn claim_request_id(&mut self, _request_id: RequestIdV1) -> bool {
        true
    }
}

/// Ein einelementiges [`DeviceDirectory`] fuer genau den `keyid` dieses
/// Requests.
///
/// Der Pruefer schlaegt synchron nach, die Autoritaet kommt aber aus Datenbank
/// und Object Store. Also wird VORHER aufgeloest und ihm genau die eine
/// Antwort gereicht, die er braucht.
struct SingleDeviceDirectory(Option<RegisteredDevice>);

impl DeviceDirectory for SingleDeviceDirectory {
    fn lookup(&self, key_thumbprint: KeyThumbprint) -> Option<RegisteredDevice> {
        self.0
            .as_ref()
            .filter(|device| device.key_thumbprint() == key_thumbprint)
            .cloned()
    }
}

/// Die `organizationId`, an die die Signatur ihr `tag` bindet.
///
/// Sie kommt aus dem Request, nicht aus dem Server — der Pruefer braucht sie,
/// BEVOR er irgendetwas aufloesen kann. Die `tag`-Pruefung im Pruefer wird
/// dadurch tautologisch, und das ist Absicht: die wirkliche Bindung ist
/// `EA-HTTP-ORGANIZATION-MISMATCH` gegen die Organisation des aufgeloesten
/// Zertifikats. Wer die Tautologie spaeter „repariert", muss diese Bindung
/// woanders neu bauen.
pub fn requested_organization(
    request: &SignedRequestV1,
) -> Result<OrganizationId, AuthServiceError> {
    let tag = request.parameters().tag();
    let mut bytes = [0_u8; 16];
    hex::decode_to_slice(tag, &mut bytes).map_err(|_| SyncProtocolError::TagMismatch)?;
    let organization_id =
        OrganizationId::try_from(&bytes[..]).map_err(|_| SyncProtocolError::TagMismatch)?;
    if organization_tag(organization_id) != tag {
        return Err(SyncProtocolError::TagMismatch.into());
    }
    Ok(organization_id)
}

/// Alles, was ein authentisierter Request an den Handler weiterreicht.
pub struct AuthenticatedRequest {
    pub organization_id: OrganizationId,
    pub device: AuthenticatedDevice,
}

impl fmt::Debug for AuthenticatedRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "AuthenticatedRequest({:?})", self.device)
    }
}

/// Die Ports, die jede Authentisierung braucht.
pub struct AuthPorts<'a> {
    pub clock: &'a dyn ServerClock,
    pub challenges: &'a dyn ChallengeStore,
    pub request_ids: &'a dyn RequestIdStore,
    pub directory: &'a dyn DeviceAuthorityDirectory,
}

/// Prueft einen signierten `/v1`-Request vollstaendig und verbraucht seine
/// Einmalwerte.
///
/// Die Reihenfolge steht im Sync-Wire-Nachtrag und wird hier eingehalten:
/// Abdeckung, Ziel, Fenster, Digest, Identitaet, Signatur — und ERST DANN
/// Nonce und Request-ID. `requested_key` ist genau auf dem
/// Proof-of-Possession-Pfad gesetzt; ohne ihn scheitert der dort mit
/// `EA-HTTP-KEY-UNRESOLVED`.
pub async fn authenticate(
    endpoint: EndpointV1,
    authority: &str,
    request: &SignedRequestV1,
    ports: &AuthPorts<'_>,
    requested_key: Option<ea_crypto::CanonicalPublicCoseKey>,
) -> Result<AuthenticatedRequest, AuthServiceError> {
    let organization_id = requested_organization(request)?;
    let now = ports.clock.now();
    let now_seconds = now.get().div_euclid(1_000);

    // Auf dem Proof-of-Possession-Pfad wird NICHTS aufgeloest: der Antrag
    // traegt weder Zertifikatskette noch Capability noch
    // Organisationsautoritaet.
    let resolved = if endpoint.authentication() == EndpointAuthentication::ProofOfPossession {
        None
    } else {
        ports
            .directory
            .resolve(organization_id, request.key_thumbprint(), now)
            .await?
    };
    // Der Block ist keine Formsache: [`ea_sync_protocol::DeviceDirectory`]
    // traegt bewusst KEINE `Send`-Schranke — der Pruefer laeuft auch im
    // Browser, wo es keine Faeden gibt. Verzeichnis und Pruefer duerfen
    // deshalb nicht ueber ein `await` hinweg leben, sonst waere die Zukunft
    // dieses Dienstes nicht mehr `Send` und Axum koennte sie nicht fuehren.
    // Sie sterben also, bevor der erste Datenbankzugriff wartet.
    let outcome = {
        let directory = SingleDeviceDirectory(resolved);
        let mut verifier = RequestVerifier::new(
            endpoint,
            authority,
            organization_id,
            now_seconds,
            &directory,
        );
        if let Some(key) = requested_key {
            verifier = verifier.with_requested_key(key);
        }
        verifier.verify(request, &mut DeferredReplayStore)
    };

    // Verbraucht wird, sobald die Signatur GILT — auch wenn der Pruefer danach
    // noch die Organisationsbindung oder die Capability abweist. Alles davor
    // liegt vor der Signatur und darf nichts verbrauchen: sonst brauchte ein
    // Fremder fremde Nonces auf.
    if consumption_is_due(&outcome) {
        spend_challenge(ports, organization_id, request.parameters().nonce(), now).await?;
        if !ports
            .request_ids
            .claim(
                organization_id,
                *request.request_id().as_bytes(),
                now,
                UnixMillis::new(now.get().saturating_add(REQUEST_ID_LIFETIME_MILLIS_V1)),
            )
            .await?
        {
            return Err(AuthServiceError::RequestIdReplay);
        }
    }

    Ok(AuthenticatedRequest {
        organization_id,
        device: outcome?,
    })
}

/// Gilt die Signatur dieses Requests bereits?
///
/// `Ok` heisst ja. Die beiden Autorisierungsbefunde heissen ebenfalls ja: der
/// Pruefer erhebt sie AUSSCHLIESSLICH hinter der gueltigen Signatur. Jeder
/// andere Befund liegt davor, und davor wird nichts verbraucht.
const fn consumption_is_due(outcome: &Result<AuthenticatedDevice, SyncProtocolError>) -> bool {
    matches!(
        outcome,
        Ok(_)
            | Err(SyncProtocolError::OrganizationMismatch)
            | Err(SyncProtocolError::CapabilityMissing)
    )
}

/// Verbraucht die Challenge hinter einer Nonce — einmal und fail-closed.
pub async fn spend_challenge(
    ports: &AuthPorts<'_>,
    organization_id: OrganizationId,
    nonce: &[u8; 32],
    now: UnixMillis,
) -> Result<(), AuthServiceError> {
    match ports
        .challenges
        .spend(organization_id, challenge_nonce_digest(nonce), now)
        .await?
    {
        ChallengeSpendOutcome::Spent => Ok(()),
        ChallengeSpendOutcome::Unknown => Err(AuthServiceError::ChallengeUnknown),
        ChallengeSpendOutcome::Expired => Err(AuthServiceError::ChallengeExpired),
        ChallengeSpendOutcome::AlreadySpent => Err(AuthServiceError::NonceReplay),
    }
}

/// `POST /v1/auth/challenges` — ratenbegrenzt, unsigniert, einmal beschrieben.
///
/// Die Nonce kommt vom Aufrufer als PARAMETER: eine Zufallsquelle waere eine
/// Wirtsentscheidung, und `crates/` haelt keine. `apps/server` beschafft sie
/// aus dem CSPRNG des TLS-Anbieters (`rustls::crypto::…::secure_random`).
pub async fn issue_challenge(
    request: &ChallengeRequestV1,
    nonce: [u8; 32],
    rate_key_digest: Hash32,
    clock: &dyn ServerClock,
    challenges: &dyn ChallengeStore,
    signer: &dyn ServerSigner,
) -> Result<ChallengeResponseV1, AuthServiceError> {
    let organization_id = request.organization_id();
    let now = clock.now();
    let window_start = UnixMillis::new(now.get().saturating_sub(CHALLENGE_RATE_WINDOW_MILLIS_V1));
    if challenges
        .count_issued_since(rate_key_digest, window_start)
        .await?
        >= CHALLENGE_RATE_LIMIT_V1
    {
        return Err(AuthServiceError::RateLimited);
    }

    let expires_at = UnixMillis::new(now.get().saturating_add(CHALLENGE_LIFETIME_MILLIS_V1));
    challenges
        .issue(
            organization_id,
            challenge_nonce_digest(&nonce),
            rate_key_digest,
            now,
            expires_at,
        )
        .await?;

    let core = ChallengeResponseCoreV1 {
        organization_id,
        nonce,
        issued_at_server: now,
        expires_at,
        server_certificate_hash: signer.certificate_hash(),
    };
    let exact_core =
        ea_crypto::encode_challenge_response_core(&core).map_err(|_| AuthServiceError::Internal)?;
    let signature = signer
        .sign_challenge_response(&exact_core)
        .map_err(|_| AuthServiceError::Internal)?;
    ChallengeResponseV1::new(core, &signature).map_err(AuthServiceError::from)
}

/// `POST /v1/device-registrations` — der Antrag, und nichts weiter.
///
/// Der Aufrufer hat die Signatur bereits ueber [`authenticate`] gefuehrt und
/// dabei den beantragten Schluessel als Proof of Possession nachgewiesen. Hier
/// wird die SELBSTSIGNATUR des Koerpers gegen genau diesen Schluessel geprueft
/// und der Antrag abgelegt.
pub async fn register_device(
    body: &DeviceRegistrationRequestV1,
    device: &AuthenticatedDevice,
    organization_id: OrganizationId,
    clock: &dyn ServerClock,
    registrations: &dyn DeviceRegistrationStore,
) -> Result<PendingRegistrationOutcome, AuthServiceError> {
    let AuthenticatedDevice::ProofOfPossession { requested_key } = device else {
        // Ein zertifiziertes Geraet auf diesem Pfad waere ein Programmfehler:
        // `EndpointV1::DeviceRegistrations` ist Proof of Possession.
        return Err(AuthServiceError::Internal);
    };
    let core: &DeviceRegistrationRequestCoreV1 = body.core();
    if core.organization_id != organization_id {
        return Err(SyncProtocolError::OrganizationMismatch.into());
    }
    if core.signing_public_cose_key.thumbprint() != *requested_key {
        return Err(SyncProtocolError::KeyUnresolved.into());
    }
    let exact_core = ea_crypto::encode_device_registration_request_core(core)
        .map_err(|_| AuthServiceError::Internal)?;
    CoseVerifier::verify_enrollment_pop(
        wrapper_signature(body.exact_bytes(), &exact_core)?,
        &core.signing_public_cose_key,
        &exact_core,
    )
    .map_err(|_| SyncProtocolError::SignatureInvalid)?;

    let outcome = registrations
        .record_pending(PendingDeviceRequestV1 {
            organization_id,
            device_id: core.device_id,
            requested_key_thumbprint: *requested_key,
            request_object_hash: hash32(body_digest(body.exact_bytes())),
            received_at: clock.now(),
        })
        .await?;
    match outcome {
        PendingRegistrationOutcome::Conflict => Err(AuthServiceError::RegistrationConflict),
        accepted => Ok(accepted),
    }
}

/// Der Zustand, in dem ein angenommener Antrag liegt — immer `pending`.
#[must_use]
pub const fn pending_registration_state() -> &'static str {
    PENDING_REGISTRATION_STATE_V1
}

/// Die COSE-Sign1-Haelfte von `[core, #6.18(COSE-Sign1)]`.
///
/// Der Rahmen ist die Verkettung beider exakter Teile; die Signatur ist damit
/// genau der Rest hinter dem Kopfbyte und dem Core. Es wird NICHT neu
/// dekodiert: `DeviceRegistrationRequestV1::decode` hat den Rahmen bereits
/// gegen seine eigene Kodierung gestellt.
/// Die COSE-Haelfte eines `[core, #6.18(COSE-Sign1)]`-Koerpers.
///
/// Der Schnitt ist BEWIESEN und nicht geraten: die Huelle ist ein CBOR-Array
/// fester Laenge zwei, also genau ein Kopfbyte, gefolgt von den exakten
/// Kernbytes; alles danach ist die Signatur. `ea_sync_protocol` hat den Rahmen
/// beim Dekodieren bereits gegen genau diese Form gestellt.
///
/// `pub(crate)`, weil ZWEI Aufnahmepfade dieselbe Haelfte brauchen — der
/// Proof-of-Possession-Antrag und die Lesequittung. Zwei Kopien derselben
/// Rechnung waeren zwei Gelegenheiten, sie verschieden zu machen.
pub(crate) fn wrapper_signature<'a>(
    exact: &'a [u8],
    exact_core: &[u8],
) -> Result<&'a [u8], AuthServiceError> {
    exact
        .get(1_usize.saturating_add(exact_core.len())..)
        .ok_or(AuthServiceError::Internal)
}

/// `POST /v1/webauthn-credentials` — die technische Credentialtabelle, sonst
/// nichts.
///
/// Kein Trust-Objekt, keine Rolle, keine Capability, keine Geraeteautoritaet
/// (`web-reader-design.md` §6.4.1, :230-233).
///
/// # Die `subjectId` wird NICHT an den Aufrufer gebunden, und warum
///
/// Ein freigegebenes Geraet dieser Organisation darf hier jede `subjectId`
/// eintragen. Das ist eine FESTLEGUNG und kein Versehen, und sie steht hier
/// ausgeschrieben statt in einer Fussnote:
///
/// * Eine kryptographische Bindung gaebe es nur ueber ein Root-signiertes
///   Objekt, das `subjectId` und Geraet verknuepft. §6.4.1 sagt ausdruecklich,
///   dass diese Registrierung dem Server KEINE Autoritaet verleiht und Rollen,
///   Capabilities und Geraeteautoritaet unveraendert allein aus
///   Root-signierten Trust-Objekten stammen — und ein solches Objekt gibt es
///   in dieser Stufe nicht. [`RegisteredDevice`] traegt folgerichtig keine
///   `subjectId`; `authority_subject_id` steht nur an zwei Zertifikatsarten
///   und nicht an einem Geraet. Die Bindung waere also erfunden, nicht
///   abgeleitet.
/// * Was TRAEGT, traegt trotzdem: der Eindeutigkeitszwang
///   (`organizationId`, `credentialId`) haelt eine `credentialId` fuer immer
///   bei der `subjectId`, unter der sie zuerst eingetragen wurde. Eine
///   bestehende Zeile laesst sich nicht umhaengen, und ein zweiter Anspruch
///   auf dieselbe `credentialId` ist
///   [`AuthServiceError::CredentialConflict`].
/// * Das Restrisiko ist benannt: ein freigegebenes Geraet kann seinen EIGENEN
///   Authenticator unter einer fremden `subjectId` eintragen und danach deren
///   Chiffrate abholen. Diese Chiffrate sind ohne die PRF-Ausgabe genau jenes
///   fremden Authenticators wertlos (§6.2), und dasselbe Geraet hat als
///   freigegebenes Geraet ohnehin Zugang zur Leseflaeche. Der Blobabruf
///   verschafft ihm damit keine Faehigkeit, die es nicht schon haette.
/// * Die Decke je `subjectId`
///   ([`ea_sync_protocol::MAX_VAULT_BLOBS_PER_SUBJECT_V1`]) begrenzt, was ein
///   solches Geraet auf der Ablageseite anrichten kann.
///
/// Eine echte Bindung entsteht mit dem Root-signierten Reader-Zertifikat der
/// Stufe 4; dann ist sie ABGELEITET und nicht behauptet.
pub async fn register_webauthn_credential(
    registration: &WebauthnCredentialRegistrationV1,
    organization_id: OrganizationId,
    clock: &dyn ServerClock,
    credentials: &dyn WebauthnCredentialStore,
) -> Result<CredentialRegistrationOutcome, AuthServiceError> {
    let outcome = credentials
        .register(WebauthnCredentialV1 {
            organization_id,
            subject_id: registration.subject_id(),
            credential_id: registration.credential_id().to_vec(),
            credential_public_cose_key: registration.credential_public_cose_key().to_vec(),
            registered_at: clock.now(),
        })
        .await?;
    match outcome {
        CredentialRegistrationOutcome::Conflict => Err(AuthServiceError::CredentialConflict),
        accepted => Ok(accepted),
    }
}
