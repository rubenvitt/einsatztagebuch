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
}

/// Die UTC-Serverzeit.
///
/// Ein eigener Port, weil `design.md` §13.3 Schritt 5 `acceptedAtServer` aus
/// ihr bildet und ein Test diese Zeit setzen koennen muss, ohne die Uhr des
/// Rechners zu stellen.
pub trait ServerClock: Send + Sync {
    fn now(&self) -> ea_types::UnixMillis;
}
