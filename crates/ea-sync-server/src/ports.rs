//! Die Ports, hinter denen die echten Serverdienste stehen.
//!
//! Die Crate haelt KEINE Tokio-Laufzeit: sie beschreibt nur die Kanten und ruft
//! die synchronen Kernbibliotheken direkt. Die Laufzeit lebt ausschliesslich in
//! `apps/server`, das diese Ports gegen PostgreSQL, den S3-kompatiblen Object
//! Store und den Serverschluessel implementiert.

use async_trait::async_trait;
use aws_sdk_s3::primitives::ByteStream;
use ea_crypto::CryptoError;
use ea_format::ObjectTypeV1;
use ea_sync_protocol::{TechnicalCursorSigner, TechnicalCursorVerifier};
use ea_types::{CertificateHash, ObjectHash};

use crate::models::{
    CommitDbCommand, CommittedDbState, RepositoryError, SecurityEventV1, StagedObject, StoreError,
    StoredObject,
};

/// Der content-addressed Object Store (`design.md` §13.3, §13.4).
#[async_trait]
pub trait ObjectStore: Send + Sync {
    /// Stromt den Koerper groessenbegrenzt in einen TEMPORAEREN Schluessel und
    /// hasht dabei mit.
    ///
    /// `limit` ist eine harte Decke: wird sie ueberschritten, endet der Aufruf
    /// mit [`StoreError::LimitExceeded`], OHNE den Rest des Stroms zu lesen.
    /// Der volle Koerper wird dabei nie im Speicher gehalten.
    async fn stage_stream(
        &self,
        kind: ObjectTypeV1,
        body: ByteStream,
        limit: u64,
    ) -> Result<StagedObject, StoreError>;

    /// Uebernimmt das gestagte Objekt content-addressed — put-if-absent.
    ///
    /// Liegen unter demselben Schluessel bereits ANDERE Bytes, ist das ein
    /// Security Event und der Aufruf endet mit [`StoreError::HashConflict`].
    /// Byteweise gleiche Bytes sind der zulaessige idempotente Fall.
    async fn put_if_absent(&self, staged: StagedObject) -> Result<StoredObject, StoreError>;

    /// Liefert die EXAKT archivierten Bytes zu diesem Hash
    /// (`design.md` §13.2, „Objektantworten liefern exakte archivierte Bytes“).
    async fn get_exact(&self, hash: ObjectHash) -> Result<ByteStream, StoreError>;
}

/// Die Aufloesung Hash zu Objektart.
///
/// [`ObjectStore::get_exact`] kennt nur den Hash, der Schluessel traegt aber
/// `<type>/<hex objectHash>`. Die Art steht im technischen Objektindex, also in
/// PostgreSQL — deshalb ist das ein eigener Port und keine sechsfache
/// Rateschleife ueber den Namensraum.
#[async_trait]
pub trait ObjectTypeDirectory: Send + Sync {
    async fn object_type_of(
        &self,
        hash: ObjectHash,
    ) -> Result<Option<ObjectTypeV1>, RepositoryError>;
}

/// Die gesperrte Kettenkopf-Transaktion (`design.md` §13.3, Schritte 4 bis 8).
#[async_trait]
pub trait CommitRepository: Send + Sync {
    async fn commit_locked_head(
        &self,
        command: CommitDbCommand,
    ) -> Result<CommittedDbState, RepositoryError>;
}

/// Die Append-only-Ablage der Security Events (`design.md` §13.4).
#[async_trait]
pub trait SecurityEventSink: Send + Sync {
    async fn record(&self, event: SecurityEventV1) -> Result<(), RepositoryError>;
}

/// Der eigene Ed25519-Schluessel des Servers.
///
/// SYNCHRON und ohne `#[async_trait]`, weil hier nichts wartet: es sind
/// Ed25519-Operationen ueber bereits vorliegende Bytes. Der Schluessel traegt
/// GENAU die drei Zwecke, die `design.md`:221 und der Sync-Wire-Nachtrag ihm
/// geben — Receipts, Checkpoints und den technischen Cursor —, und die
/// Zweckbindung laeuft ueber die Domaene, nicht ueber eine achte
/// `CertificateCapability`. Ein Reader-, Recovery-, HGA- oder
/// Approver-Privatschluessel liegt hier ausdruecklich NICHT.
pub trait ServerSigner: TechnicalCursorSigner + TechnicalCursorVerifier + Send + Sync {
    /// Das Serverzertifikat, unter dem signiert wird.
    fn certificate_hash(&self) -> CertificateHash;

    /// Die laufende Schluesselgeneration.
    ///
    /// Sie steigt bei jeder Rotation um eins. Ein technischer Cursor einer
    /// frueheren Generation oeffnet danach nicht mehr — das ist der Zweck der
    /// Rotation und kein Mangel.
    fn key_generation(&self) -> u32;

    fn sign_receipt(&self, exact_receipt_core: &[u8]) -> Result<Vec<u8>, CryptoError>;

    fn sign_checkpoint(&self, exact_checkpoint_core: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Die Serversignatur der Challenge-Antwort.
    ///
    /// `challenge-response-v1` ist `[core, #6.18(COSE-Sign1)]`
    /// (`schemas/protocol/v1/signed-protocol.cddl`:10-13), und der Server ist
    /// der Aussteller. Der VIERTE Zweck desselben Schluessels steht damit
    /// neben Receipt, Checkpoint und technischem Cursor, und er ist wie diese
    /// ueber den COSE-Content-Type gebunden — nicht ueber eine achte
    /// `CertificateCapability`.
    fn sign_challenge_response(&self, exact_challenge_core: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

/// Die UTC-Serverzeit.
///
/// Ein eigener Port, weil `design.md` §13.3 Schritt 5 `acceptedAtServer` aus
/// ihr bildet und ein Test diese Zeit setzen koennen muss, ohne die Uhr des
/// Rechners zu stellen.
pub trait ServerClock: Send + Sync {
    fn now(&self) -> ea_types::UnixMillis;
}

/// Wie eine ausgegebene Challenge auf ihren Verbrauch antwortet.
///
/// VIER Ausgaenge und nicht `bool`, weil der Fehlerkanal die drei
/// Verweigerungsgruende unterscheiden MUSS: eine nie ausgegebene Nonce ist ein
/// anderer Befund als eine abgelaufene und wieder ein anderer als eine bereits
/// verbrauchte. Ein `bool` zwaenge den Dienst, den Grund zu raten.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeSpendOutcome {
    /// Die Challenge war offen und ist jetzt verbraucht.
    Spent,
    /// Zu dieser Nonce gibt es keine ausgegebene Challenge.
    Unknown,
    /// Sie wurde ausgegeben, ist aber abgelaufen.
    Expired,
    /// Sie wurde bereits verbraucht.
    AlreadySpent,
}

/// Der Speicher der ausgegebenen Challenges (`design.md` §13.1).
///
/// Er wird EINMAL geschrieben — vom Challenge-Endpunkt — und von der
/// Geraeteregistrierung, der WebAuthn-Credential-Registrierung und dem
/// Vault-Blob-Abruf gelesen. Gespeichert wird ausschliesslich der DIGEST der
/// Nonce: der Server muss wiedererkennen, dass er sie ausgegeben hat, und
/// braucht sie dafuer nie im Klartext zurueck.
#[async_trait]
pub trait ChallengeStore: Send + Sync {
    async fn issue(
        &self,
        organization_id: ea_types::OrganizationId,
        nonce_digest: ea_types::Hash32,
        issued_at: ea_types::UnixMillis,
        expires_at: ea_types::UnixMillis,
    ) -> Result<(), RepositoryError>;

    /// Wie viele Challenges diese Organisation seit `since` bekommen hat.
    ///
    /// Die Ratenbegrenzung haengt an der `organizationId` und damit an einer
    /// NICHT-INHALTLICHEN technischen Identitaet; sie traegt nach dem
    /// Sync-Wire-Nachtrag keinen fachlichen Wert.
    async fn count_issued_since(
        &self,
        organization_id: ea_types::OrganizationId,
        since: ea_types::UnixMillis,
    ) -> Result<u64, RepositoryError>;

    /// Verbraucht die Challenge zu diesem Nonce-Digest — genau einmal.
    async fn spend(
        &self,
        organization_id: ea_types::OrganizationId,
        nonce_digest: ea_types::Hash32,
        now: ea_types::UnixMillis,
    ) -> Result<ChallengeSpendOutcome, RepositoryError>;
}

/// Der Einmalspeicher der Request-IDs (`design.md` §13.1).
///
/// Getrennt vom Challenge-Speicher, weil `EA-AUTH-NONCE-REPLAY` und
/// `EA-AUTH-REQUEST-ID-REPLAY` unterscheidbar bleiben muessen.
#[async_trait]
pub trait RequestIdStore: Send + Sync {
    /// `true`, wenn diese Request-ID VORHER unbenutzt war.
    async fn claim(
        &self,
        organization_id: ea_types::OrganizationId,
        request_id: [u8; 16],
        seen_at: ea_types::UnixMillis,
        expires_at: ea_types::UnixMillis,
    ) -> Result<bool, RepositoryError>;
}

/// Die Ablage der beantragten, noch NICHT freigegebenen Geraete.
///
/// Ein Eintrag hier verleiht keine Autoritaet — die kommt ausschliesslich aus
/// Root-signierten Trust-Objekten (`design.md` §12).
#[async_trait]
pub trait DeviceRegistrationStore: Send + Sync {
    async fn record_pending(
        &self,
        request: crate::models::PendingDeviceRequestV1,
    ) -> Result<crate::models::PendingRegistrationOutcome, RepositoryError>;
}

/// Die technische Credentialtabelle des Web-Readers
/// (`web-reader-design.md` §6.4.1).
///
/// Sie entscheidet allein, wem der Server ein Chiffrat aushaendigt, das ohne
/// Authenticator wertlos ist. Sie verleiht KEINE Rolle, KEINE Capability und
/// KEINE Geraeteautoritaet und legt kein Trust-Objekt an.
#[async_trait]
pub trait WebauthnCredentialStore: Send + Sync {
    async fn register(
        &self,
        credential: crate::models::WebauthnCredentialV1,
    ) -> Result<crate::models::CredentialRegistrationOutcome, RepositoryError>;
}

/// Der technische Index der Trust-Objekte einer Organisation.
///
/// Der Port INDIZIERT und BLAETTERT; er entscheidet nichts. Die Gueltigkeit
/// eines `.etb` stellt ausschliesslich die geteilte Pruefung aus `ea-trust`
/// fest, und die Leseantwort liefert exakte Objektbytes, keine aus Zeilen
/// zusammengesetzte Aussage (`design.md` §13.2).
#[async_trait]
pub trait TrustEventStore: Send + Sync {
    /// Traegt ein geprueftes `.etb` in EINER Transaktion in Objektindex,
    /// `trust_events` und — fuer ein `registryEvent` — die Registry-Linie ein.
    async fn index_event(
        &self,
        event: crate::models::TrustEventCommandV1,
    ) -> Result<crate::models::TrustIndexOutcome, RepositoryError>;

    /// Die Registry-Linie nach `after_version`, aufsteigend, hoechstens
    /// `limit` Saetze.
    async fn registry_line_after(
        &self,
        organization_id: ea_types::OrganizationId,
        after_version: ea_types::RegistryVersion,
        limit: usize,
    ) -> Result<Vec<crate::models::RegistryLineEntryV1>, RepositoryError>;
}

/// Die Aufloesung eines `keyid`-Thumbprints auf ein FREIGEGEBENES Geraet.
///
/// Der Port ist asynchron, weil die Antwort aus Datenbank UND Object Store
/// kommt; [`ea_sync_protocol::DeviceDirectory`] ist synchron, weil der Pruefer
/// selbst keine Laufzeit hat. Der Serverpfad loest deshalb VORHER auf und
/// reicht dem Pruefer ein einelementiges Verzeichnis.
///
/// WORAUS die Antwort entsteht, ist eine Sicherheitsaussage: ausschliesslich
/// aus der geteilten Trust-Pruefung ueber die Root-signierten Objekte der
/// Organisation. Es gibt keinen zweiten Weg, auf dem eine Zeile in
/// `role_intervals` oder `pending_device_requests` eine Capability verliehe.
#[async_trait]
pub trait DeviceAuthorityDirectory: Send + Sync {
    async fn resolve(
        &self,
        organization_id: ea_types::OrganizationId,
        key_thumbprint: ea_types::KeyThumbprint,
        now: ea_types::UnixMillis,
    ) -> Result<Option<ea_sync_protocol::RegisteredDevice>, RepositoryError>;
}
