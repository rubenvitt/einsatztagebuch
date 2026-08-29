//! Die transportneutrale Vault-Blob-Flaeche (`web-reader-design.md` §6.4).
//!
//! Kein Axum, kein sqlx, kein CORS: der Dienst kennt die Ports aus
//! [`crate::ports`], die drei Rahmen aus `ea-sync-protocol` und den
//! Ed25519-Pruefer aus `ea-crypto`. Die Herausgabe haengt an einer VERIFIZIERTEN
//! WebAuthn-Assertion und ausdruecklich NICHT an einem
//! [`ea_sync_protocol::AuthenticatedDevice`]: auf diesem Pfad existiert
//! ueberhaupt keine Geraeteidentitaet — der Browser ist frisch, sein Vault
//! verschlossen und der Ed25519-Schluessel des Lesers damit unerreichbar
//! (`web-reader-design.md` :213-216).
//!
//! # Der Signaturalgorithmus: EdDSA ueber Ed25519, und nur der
//!
//! §6.4.1 nennt KEINEN Algorithmus, und die Feld-zu-Design-Review des
//! Sync-Wire-Nachtrags fuehrt zu `webauthn-credential-registration-v1` nur
//! `subject-id`, `credential-id` und `credential-public-cose-key`. Der
//! Arbeitsbereich hat dagegen genau EINE oeffentliche Schluesselform —
//! [`ea_crypto::CanonicalPublicCoseKey`] — und die Suite ist durchgehend
//! Ed25519 (`design.md` §13.1, `alg="ed25519"`). Der Server nimmt deshalb
//! ausschliesslich ein OKP-Ed25519-Credential an und prueft die Assertion mit
//! [`ea_crypto::CanonicalPublicCoseKey::verify_ed25519_strict`] — der
//! Signatur ueber `authenticatorData ‖ SHA-256(clientDataJSON)`, wie WebAuthn
//! Level 2 §6.3.3 sie definiert.
//!
//! Das ist eine FESTLEGUNG und keine Nebenwirkung: ES256 verlangte einen
//! P-256-Pruefer, den dieser Baum nicht enthaelt, und damit einen neuen
//! Wurzelpin unter dem Verfahren aus ADR 0004. Die kanonische Form dieses
//! Arbeitsbereichs ist ausserdem die DREIELEMENTIGE Karte
//! `{1: kty, -1: crv, -2: x}` OHNE `alg` (Label 3); der Web-Reader normalisiert
//! den `credentialPublicKey` seines Authenticators vor der Registrierung in
//! genau diese Form.
//!
//! # Warum die `clientDataJSON` gebaut und nicht gelesen wird
//!
//! ADR 0004 hat `json` an Axum abgeschaltet, damit neben dem deterministischen
//! CBOR kein zweiter, ungeprueter Dekodierweg in den Server fuehrt. Ein
//! JSON-Parser fuer dieses eine Feld holte ihn zurueck. Der Server
//! SERIALISIERT deshalb die erwartete `CollectedClientData` aus Challenge und
//! Bundle-Origin und vergleicht byteweise. Der Vergleich ist strenger als ein
//! Parser: er pinnt zugleich `type`, `origin` und `crossOrigin`.

use core::fmt;

use ea_crypto::CanonicalPublicCoseKey;
use ea_sync_protocol::{
    MAX_VAULT_BLOBS_PER_SUBJECT_V1, MIN_AUTHENTICATOR_DATA_BYTES_V1, SyncProtocolError,
    VaultBlobRetrievalRequestV1, VaultBlobRetrievalResponseV1, VaultBlobUploadV1, body_digest,
};
use ea_types::{Hash32, OrganizationId, SubjectId};

use crate::{
    RepositoryError, ServerClock,
    auth::challenge_nonce_digest,
    models::{ReaderVaultBlobV1, StoredWebauthnCredentialV1, VaultBlobOutcome},
    ports::{ChallengeSpendOutcome, ChallengeStore, VaultBlobStore, WebauthnCredentialStore},
};

/// Der Ersatzschluessel fuer den NICHT-Treffer.
///
/// Der kanonisch kodierte Ed25519-Basispunkt: ein gueltiger, nicht schwacher
/// Punkt. Er steht hier, damit ein unbekanntes Credential DIESELBE Rechnung
/// ausloest wie ein bekanntes — sonst unterschiede ein Angreifer die beiden
/// Faelle an der Arbeit, die der Server leistet, und genau das waere die
/// Enumerationsflaeche aus §6.4.1 (:228). Er entscheidet nie etwas: sobald das
/// Credential fehlt, steht die Annahme schon auf `false`.
const PLACEHOLDER_CREDENTIAL_PUBLIC_KEY_V1: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// Die Bitmaske des `User Present`-Flags in `authenticatorData`.
const AUTHENTICATOR_FLAG_USER_PRESENT_V1: u8 = 0x01;

/// Jeder Befund dieser Flaeche.
///
/// Es gibt GENAU EINEN Ablehnungscode fuer alles, was an der Assertion haengt:
/// unbekanntes Credential, fremde `subjectId`, falscher Origin, falsche
/// `rpIdHash`, fehlendes `UP`, nicht steigender Zaehler, verbrauchte Challenge,
/// nicht tragende Signatur. Sie zu unterscheiden hiesse, dem Aufrufer zu
/// sagen, WORAN er gescheitert ist — und das ist die Enumerationsflaeche, die
/// §6.4.1 verbietet.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum VaultServiceError {
    /// Die Assertion traegt nicht. Ein einziger Code fuer jeden Grund.
    AssertionInvalid,
    /// Diese `subjectId` haelt bereits so viele Blobs, wie sie halten darf.
    BlobLimit,
    /// Die Datenbank antwortet nicht.
    DependencyUnavailable,
    /// Interner Fehler ohne fachliche Ursache.
    Internal,
    /// Ein durchgereichter Rahmenbefund.
    Protocol(SyncProtocolError),
}

impl VaultServiceError {
    /// Jeder eigene Befund dieses Dienstes.
    pub const ALL: [Self; 4] = [
        Self::AssertionInvalid,
        Self::BlobLimit,
        Self::DependencyUnavailable,
        Self::Internal,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AssertionInvalid => "EA-WEBAUTHN-ASSERTION-INVALID",
            Self::BlobLimit => "EA-VAULT-BLOB-LIMIT",
            Self::DependencyUnavailable => "EA-VAULT-DEPENDENCY-UNAVAILABLE",
            Self::Internal => "EA-VAULT-INTERNAL",
            Self::Protocol(error) => error.code(),
        }
    }

    /// Die HTTP-Abbildung des Sync-Wire-Nachtrags.
    ///
    /// `401` und ausdruecklich KEIN `404` fuer eine unbekannte `subjectId`:
    /// die `404`-Zeile der Abbildung nennt unbekanntes Objekt, unbekannte
    /// Kette, unbekannten Eintrag und unbekannte Vernichtungs-ID — und keine
    /// `subjectId`.
    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::AssertionInvalid => 401,
            Self::BlobLimit => 413,
            Self::Internal => 500,
            Self::DependencyUnavailable => 503,
            Self::Protocol(error) => error.http_status(),
        }
    }

    /// `retryable` gilt AUSSCHLIESSLICH fuer 429, 500 und 503.
    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(self.http_status(), 429 | 500 | 503)
    }
}

impl From<SyncProtocolError> for VaultServiceError {
    fn from(value: SyncProtocolError) -> Self {
        Self::Protocol(value)
    }
}

impl From<RepositoryError> for VaultServiceError {
    fn from(value: RepositoryError) -> Self {
        match value {
            RepositoryError::Unavailable => Self::DependencyUnavailable,
            _ => Self::Internal,
        }
    }
}

impl fmt::Display for VaultServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for VaultServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for VaultServiceError {}

/// Die WebAuthn-Gegenstelle, gegen die eine Assertion gestellt wird.
///
/// Beides kommt aus der KONFIGURATION und nie aus dem Request: der Origin ist
/// derselbe getrennte Bundle-Origin, den die CORS-Positivliste fuehrt
/// (`web-reader-design.md` §4.1, :70-75), und die `rpId` ist sein Hostname.
/// Sie aus dem Request zu lesen hiesse, den Aufrufer die Erwartung setzen zu
/// lassen, gegen die er geprueft wird.
#[derive(Clone, Eq, PartialEq)]
pub struct WebauthnRelyingPartyV1 {
    origin: String,
    relying_party_id_hash: [u8; 32],
}

impl WebauthnRelyingPartyV1 {
    #[must_use]
    pub fn new(origin: String, relying_party_id: &str) -> Self {
        Self {
            origin,
            relying_party_id_hash: body_digest(relying_party_id.as_bytes()),
        }
    }

    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }
}

impl fmt::Debug for WebauthnRelyingPartyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WebauthnRelyingPartyV1(<bound>)")
    }
}

/// Die Ports der Vault-Blob-Flaeche.
pub struct VaultPorts<'a> {
    pub clock: &'a dyn ServerClock,
    pub challenges: &'a dyn ChallengeStore,
    pub credentials: &'a dyn WebauthnCredentialStore,
    pub blobs: &'a dyn VaultBlobStore,
}

/// `PUT /v1/vault-blobs` — create-if-absent, kein Update, kein Loeschpfad.
///
/// Der Blobhash wird GERECHNET und nicht behauptet: SHA-256 ueber die exakten
/// Chiffratbytes. Ein vom Aufrufer gelieferter Hash waere eine Adresse, die
/// nicht auf ihren Inhalt zeigen muss, und derselbe Schluessel truege dann
/// zwei verschiedene Bytefolgen.
///
/// Der Blob liegt AUSDRUECKLICH NICHT im Object Store unter
/// `<type>/<hex objectHash>`: dieser Namensraum gehoert den sechs
/// Archivobjektarten (`design.md` §13.4). Der Server legt Bytes ab, die er
/// nicht lesen kann, und kennt weder Vault-Key noch PRF-Ausgabe
/// (`web-reader-design.md` §6.4, :206-207).
///
/// Die `organizationId` kommt aus der GEPRUEFTEN RFC-9421-Identitaet des
/// Aufrufers und nicht aus dem Koerper: die `subjectId` darf der Aufrufer
/// waehlen, die Organisation nicht.
///
/// # Errors
///
/// [`VaultServiceError::BlobLimit`], wenn diese `subjectId` ihre Decke
/// erreicht hat; [`VaultServiceError::DependencyUnavailable`] bei einem
/// Datenbankausfall.
pub async fn store_vault_blob(
    upload: &VaultBlobUploadV1,
    organization_id: OrganizationId,
    clock: &dyn ServerClock,
    blobs: &dyn VaultBlobStore,
) -> Result<VaultBlobOutcome, VaultServiceError> {
    let blob = ReaderVaultBlobV1 {
        organization_id,
        subject_id: upload.subject_id(),
        blob_hash: hash32(body_digest(upload.ciphertext())),
        ciphertext: upload.ciphertext().to_vec(),
        stored_at: clock.now(),
    };
    match blobs.store(blob, blob_capacity()?).await? {
        VaultBlobOutcome::LimitReached => Err(VaultServiceError::BlobLimit),
        accepted => Ok(accepted),
    }
}

/// `POST /v1/vault-blobs/retrievals` — die Herausgabe gegen eine Assertion.
///
/// # Die konstante Form
///
/// Jeder Weg durch diese Funktion leistet DIESELBE Arbeit: eine Aufloesung,
/// ein Challenge-Verbrauch, ein Bytevergleich der `clientDataJSON`, eine
/// Pruefung der `authenticatorData`, ein Zaehlervergleich und eine
/// Signaturpruefung. Es gibt keinen fruehen Ausstieg, der ein unbekanntes
/// Credential von einem nicht tragenden unterscheidet — weder am Code, noch am
/// Status, noch an den Bytes, noch daran, ob die Challenge verbraucht wurde.
/// Bliebe die Challenge auf einem der beiden Wege stehen, unterschiede ein
/// Angreifer die Faelle daran, ob er seine Nonce wiederverwenden kann.
///
/// # Errors
///
/// [`VaultServiceError::AssertionInvalid`] fuer jeden Grund, aus dem die
/// Assertion nicht traegt; [`VaultServiceError::DependencyUnavailable`] bei
/// einem Datenbankausfall.
pub async fn release_vault_blobs(
    request: &VaultBlobRetrievalRequestV1,
    relying_party: &WebauthnRelyingPartyV1,
    ports: &VaultPorts<'_>,
) -> Result<VaultBlobRetrievalResponseV1, VaultServiceError> {
    let organization_id = request.organization_id();
    let now = ports.clock.now();

    let resolved = ports
        .credentials
        .resolve(organization_id, request.credential_id())
        .await?;
    // Der Verbrauch laeuft AUCH dann, wenn das Credential fehlt.
    let spend = ports
        .challenges
        .spend(
            organization_id,
            challenge_nonce_digest(request.challenge()),
            now,
        )
        .await?;

    let reference = resolved.clone().unwrap_or_else(placeholder_credential);
    let delivered_counter = signature_counter(request.authenticator_data());

    // `&=` und nicht `&&`: die Kette darf nicht abkuerzen, sonst haengt die
    // geleistete Arbeit am Grund der Ablehnung.
    let mut accepted = resolved.is_some();
    accepted &= matches!(spend, ChallengeSpendOutcome::Spent);
    accepted &= reference.subject_id == request.subject_id();
    accepted &= client_data_begins_with_required_members(
        request.client_data_json(),
        &expected_client_data_json(request.challenge(), relying_party.origin()),
    );
    accepted &= authenticator_data_binds(request.authenticator_data(), relying_party);
    accepted &= counter_advances(reference.signature_counter, delivered_counter);
    accepted &= assertion_signature_verifies(&reference, request);
    if !accepted {
        return Err(VaultServiceError::AssertionInvalid);
    }

    // Der Zaehler wird nur fortgeschrieben, wenn der Authenticator einen
    // fuehrt. Das bedingte `UPDATE` ist zugleich die Sperre: zwei Abrufe mit
    // derselben Assertion koennen nicht beide gewinnen.
    if delivered_counter > reference.signature_counter
        && !ports
            .credentials
            .advance_counter(
                organization_id,
                request.credential_id(),
                reference.signature_counter,
                delivered_counter,
            )
            .await?
    {
        return Err(VaultServiceError::AssertionInvalid);
    }

    let capacity = blob_capacity()?;
    let ciphertexts = ports
        .blobs
        .list_for_subject(organization_id, request.subject_id(), capacity)
        .await?;
    // Der Rahmenfehler wird zu `AssertionInvalid` und NICHT durchgereicht.
    // Nach der Decke in `store` und dem `limit` oben kann er nicht eintreten;
    // traete er doch ein, waere ein eigener Code an dieser Stelle genau die
    // Unterscheidbarkeit, die §6.4.1 (:228) verbietet — eine `subjectId` ueber
    // der Decke waere an ihrem Fehlercode erkennbar.
    VaultBlobRetrievalResponseV1::new(ciphertexts).map_err(|_| VaultServiceError::AssertionInvalid)
}

/// Die Decke je `subjectId` als `u64`.
///
/// # Errors
///
/// Nie auf einer Zielplattform dieses Servers: `usize` ist dort hoechstens
/// 64 Bit.
fn blob_capacity() -> Result<u64, VaultServiceError> {
    u64::try_from(MAX_VAULT_BLOBS_PER_SUBJECT_V1).map_err(|_| VaultServiceError::Internal)
}

/// Das Ersatzcredential des Nicht-Treffers.
fn placeholder_credential() -> StoredWebauthnCredentialV1 {
    StoredWebauthnCredentialV1 {
        subject_id: SubjectId::try_from(&[0_u8; 16][..])
            .unwrap_or_else(|_| unreachable!("a subject id is 16 bytes")),
        credential_public_cose_key: CanonicalPublicCoseKey::ed25519(
            PLACEHOLDER_CREDENTIAL_PUBLIC_KEY_V1,
        )
        .unwrap_or_else(|_| unreachable!("the Ed25519 base point is a usable public key"))
        .to_deterministic_cbor(),
        signature_counter: 0,
    }
}

/// Die PFLICHTGLIEDER der `CollectedClientData` in der Serialisierung von
/// WebAuthn Level 2 §5.8.1.1 — OHNE die schliessende Klammer.
///
/// Der Server BAUT sie und parst nichts. Damit sind `type`, `challenge`,
/// `origin` und `crossOrigin` in einem Zug gepinnt.
fn expected_client_data_json(challenge: &[u8; 32], origin: &str) -> Vec<u8> {
    let mut json = String::with_capacity(160);
    json.push_str("{\"type\":\"webauthn.get\",\"challenge\":\"");
    json.push_str(&base64url_no_pad(challenge));
    json.push_str("\",\"origin\":\"");
    json.push_str(origin);
    json.push_str("\",\"crossOrigin\":false");
    json.into_bytes()
}

/// Der Vergleich nach dem Limited Verification Algorithm, WebAuthn Level 2
/// §5.8.1.2.
///
/// Die Spezifikation verlangt AUSDRUECKLICH ein Praefix und keine
/// Bytegleichheit: §5.8.1.1 haengt hinter `crossOrigin` jedes weitere Glied an
/// („Other members …"), und Level 3 ergaenzt `topOrigin`. Ein Gleichheitstest
/// wiese einen regelkonformen Browser ab, der irgendetwas anhaengt — und weil
/// diese Flaeche fail-closed genau EINEN Fehlercode fuehrt, waere das ein
/// Endpunkt, der stumm gar nicht funktioniert.
///
/// Strenger als die Spezifikation an genau einer Stelle: hinter dem Praefix
/// MUSS `}` oder `,` stehen. Beides sind die einzigen Fortsetzungen, die
/// §5.8.1.1 erzeugt; ohne diese Zeile ginge auch ein angehaengtes `…falsex`
/// durch.
fn client_data_begins_with_required_members(delivered: &[u8], expected: &[u8]) -> bool {
    delivered.starts_with(expected) && matches!(delivered.get(expected.len()), Some(b'}' | b','))
}

/// Base64url ohne Fuellzeichen (RFC 4648 §5) — die Kodierung, in der WebAuthn
/// die Challenge in die `clientDataJSON` schreibt.
fn base64url_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    for chunk in bytes.chunks(3) {
        let mut buffer = [0_u8; 3];
        buffer[..chunk.len()].copy_from_slice(chunk);
        let value =
            (u32::from(buffer[0]) << 16) | (u32::from(buffer[1]) << 8) | u32::from(buffer[2]);
        for shift in 0..=chunk.len() {
            let index = usize::try_from((value >> (18 - 6 * shift)) & 0x3f).unwrap_or(0);
            out.push(char::from(ALPHABET[index]));
        }
    }
    out
}

/// Bindet die `authenticatorData` an diese Gegenstelle?
///
/// `rpIdHash` gegen die konfigurierte `rpId` und das `UP`-Flag. Ohne
/// `rpIdHash` waere eine Assertion, die ein Leser auf einer FREMDEN Seite
/// erzeugt hat, hier gueltig.
fn authenticator_data_binds(data: &[u8], relying_party: &WebauthnRelyingPartyV1) -> bool {
    data.len() >= MIN_AUTHENTICATOR_DATA_BYTES_V1
        && data.get(..32) == Some(&relying_party.relying_party_id_hash[..])
        && data
            .get(32)
            .is_some_and(|flags| flags & AUTHENTICATOR_FLAG_USER_PRESENT_V1 != 0)
}

/// Der `signCount` aus der `authenticatorData`, oder null.
///
/// Der Rahmen hat die Mindestlaenge bereits durchgesetzt; null ist deshalb
/// kein stiller Rueckfall, sondern der Wert, den ein Authenticator ohne
/// Zaehler liefert.
fn signature_counter(data: &[u8]) -> u32 {
    data.get(33..37)
        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
        .map_or(0, u32::from_be_bytes)
}

/// Steigt der Zaehler STRENG?
///
/// Mit der einen Ausnahme, die WebAuthn Level 2 §6.1.3 selbst benennt: sind
/// gespeicherter und gelieferter Wert BEIDE null, fuehrt der Authenticator
/// keinen Zaehler. Ohne diese Ausnahme koennte ein synchronisierter Passkey —
/// der Regelfall aus §6.4.1 — den Blob nie abholen, weil er dauerhaft null
/// meldet. Fuer jeden Authenticator, der einen Zaehler FUEHRT, gilt die
/// strenge Regel unveraendert, und ein geklonter Authenticator faellt daran
/// auf.
const fn counter_advances(stored: u32, delivered: u32) -> bool {
    if stored == 0 && delivered == 0 {
        return true;
    }
    delivered > stored
}

/// Traegt die Assertionssignatur gegen den gespeicherten Schluessel?
///
/// Signiert wird `authenticatorData ‖ SHA-256(clientDataJSON)` (WebAuthn
/// Level 2 §6.3.3). Ein Schluessel, der nicht in kanonischer OKP-Ed25519-Form
/// vorliegt, ist ein Nein und kein Ausfall: die Registrierung hat ihn bereits
/// in dieser Form angenommen, ein anderer Bestand waere ein Befund.
fn assertion_signature_verifies(
    credential: &StoredWebauthnCredentialV1,
    request: &VaultBlobRetrievalRequestV1,
) -> bool {
    let Ok(key) =
        CanonicalPublicCoseKey::from_deterministic_cbor(&credential.credential_public_cose_key)
    else {
        return false;
    };
    let mut message = Vec::with_capacity(request.authenticator_data().len().saturating_add(32));
    message.extend_from_slice(request.authenticator_data());
    message.extend_from_slice(&body_digest(request.client_data_json()));
    key.verify_ed25519_strict(&message, request.signature())
        .is_ok()
}

/// Ein blankes SHA-256-Ergebnis als [`Hash32`].
///
/// # Panics
///
/// Nie: `digest` ist ein `[u8; 32]`.
fn hash32(digest: [u8; 32]) -> Hash32 {
    Hash32::try_from(&digest[..]).expect("a SHA-256 digest is exactly 32 bytes")
}
