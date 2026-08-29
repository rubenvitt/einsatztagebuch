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
    ///
    /// Der Schluessel traegt `<type>/<hex objectHash>`, die Art kommt also aus
    /// dem technischen Objektindex. Das ist fuer eine LESEANTWORT richtig — sie
    /// liefert nur, was sichtbar ist.
    async fn get_exact(&self, hash: ObjectHash) -> Result<ByteStream, StoreError>;

    /// Dieselben Bytes, aber aus dem BENANNTEN Namensraum.
    ///
    /// Sie existiert fuer die Reconciliation, und der Grund ist ein Zirkel:
    /// [`Self::get_exact`] loest die Objektart ueber den Index auf, und eine
    /// unsichtbare Waise hat dort per Definition keine Zeile. Ueber jenen Weg
    /// waere sie unlesbar, und `design.md` §13.3 verlangt genau, dass sie
    /// gelesen und ERNEUT geprueft wird.
    ///
    /// Der Aufrufer kennt die Art, weil er einen Namensraum durchgeht — nicht,
    /// weil er sie behauptet: [`crate::reconcile::reconcile_object`] stellt die
    /// zurueckgegebenen Bytes anschliessend gegen ihre Adresse UND gegen die
    /// erwartete Art. Ein falsch benannter Namensraum liefert deshalb keine
    /// Uebernahme, sondern eine Quarantaene.
    async fn get_exact_in(
        &self,
        kind: ObjectTypeV1,
        hash: ObjectHash,
    ) -> Result<ByteStream, StoreError>;
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

    /// Derselbe Index, aber ORGANISATIONSGEBUNDEN und mit der Groesse.
    ///
    /// [`Self::object_type_of`] loest einen Hash organisationsFREI auf, und
    /// das ist fuer die Reconciliation richtig: sie geht den eigenen Bestand
    /// durch. Fuer `GET /v1/objects/{objectHash}` waere es eine Luecke — ein
    /// Aufrufer laese damit ein Objekt einer FREMDEN Organisation, und schon
    /// die Antwort „gibt es“ waere eine Aussage ueber deren Bestand. Der
    /// Leseweg fragt deshalb hier, und ein fremdes Objekt ist ihm unbekannt.
    ///
    /// Die Groesse kommt mit, weil die Objektantwort `Content-Length` traegt
    /// und sie sonst aus dem Strom gezaehlt werden muesste — also erst
    /// bekannt waere, wenn die Kopfzeilen laengst geschrieben sind.
    async fn indexed_object(
        &self,
        organization_id: ea_types::OrganizationId,
        hash: ObjectHash,
    ) -> Result<Option<crate::models::IndexedObjectV1>, RepositoryError>;
}

/// Die gesperrte Kettenkopf-Transaktion (`design.md` §13.3, Schritte 4 bis 8).
#[async_trait]
pub trait CommitRepository: Send + Sync {
    /// Der aktuelle Kettenkopf MIT seiner Annahmezeit — ohne Sperre.
    ///
    /// Schritt 5 bildet `acceptedAtServer` als Maximum aus Serverzeit und der
    /// Annahmezeit des DIREKTEN Vorgaengers, und die Quittung entsteht aus
    /// dieser Zahl. Beides passiert VOR [`Self::commit_locked_head`], das den
    /// fertigen Auftrag entgegennimmt; also braucht es diesen Lesezugriff.
    ///
    /// Er ist ausdruecklich NICHT die Entscheidung: bewegt sich der Kopf
    /// zwischen diesem Lesen und der Sperre, weist die Transaktion mit
    /// [`RepositoryError::HeadConflict`] ab. Der Lesezugriff beschleunigt die
    /// Bildung, er ersetzt sie nicht.
    async fn head_state(
        &self,
        organization_id: ea_types::OrganizationId,
        chain_id: ea_types::ChainId,
    ) -> Result<Option<crate::models::ChainHeadStateV1>, RepositoryError>;

    /// Der Kopf der CHECKPOINT-Kette dieser Kette — ohne Sperre.
    ///
    /// Er ist der Vorgaenger, den der naechste Standard-Checkpoint ueber
    /// `previous-evidence-hash` bindet. `None` heisst „diese Kette traegt
    /// noch keinen Checkpoint“, und das ist eine Antwort und kein Ausfall.
    ///
    /// Wie [`Self::head_state`] entscheidet dieser Lesezugriff NICHTS: die
    /// gesperrte Transaktion stellt den genannten Vorgaenger noch einmal
    /// gegen den tatsaechlichen Kopf und weist mit
    /// [`RepositoryError::CheckpointPredecessorConflict`] ab, wenn er sich
    /// dazwischen bewegt hat. Ohne diese zweite Pruefung koennte die
    /// Evidence-Kette sich gabeln.
    async fn checkpoint_head(
        &self,
        organization_id: ea_types::OrganizationId,
        chain_id: ea_types::ChainId,
    ) -> Result<Option<ObjectHash>, RepositoryError>;

    async fn commit_locked_head(
        &self,
        command: CommitDbCommand,
    ) -> Result<CommittedDbState, RepositoryError>;
}

/// Der technische Checkpoint-Index einer Organisation.
///
/// Ein eigener Port neben [`CommitRepository`], weil er eine andere Frage
/// stellt: jener SCHREIBT unter der Kettenkopfsperre, dieser BLAETTERT ueber
/// alle Ketten einer Organisation. `GET /v1/checkpoints` kennt keine Kette —
/// der Endpunkt traegt keine im Pfad, und ein technischer Cursor auf ihn
/// fuehrt deshalb `chainId = null`.
///
/// Der Port entscheidet nichts. Die Leseantwort liefert exakte Objektbytes,
/// und der Empfaenger prueft die Kette selbst (`design.md` §13.2: technische
/// Listen sind nicht autoritativ).
#[async_trait]
pub trait CheckpointDirectory: Send + Sync {
    /// Die Checkpoints nach `after_technical_index`, aufsteigend nach
    /// Blaetterposition, hoechstens `limit` Saetze.
    async fn checkpoints_after(
        &self,
        organization_id: ea_types::OrganizationId,
        after_technical_index: u64,
        limit: usize,
    ) -> Result<Vec<crate::models::CheckpointIndexEntryV1>, RepositoryError>;
}

/// Der zur EINTRAGSSEQUENZ gewaehlte Registry-Head.
///
/// Ein eigener Port neben [`DeviceAuthorityDirectory`], weil die beiden
/// verschiedene Fragen stellen. Jener loest einen Schluesselabdruck auf und
/// gibt ein Geraet heraus; dieser gibt den KOPF heraus, und zwar den fuer
/// GENAU DIESE Sequenz gewaehlten. Der Unterschied ist keine Formsache:
/// [`ea_trust::SelectedRegistryHead::active_certificates`] antwortet ueber die
/// vorgeschlagene Sequenz, mit der der Kopf gewaehlt wurde. Wer den Kopf der
/// Authentisierung wiederverwendete, bekaeme die zur Sequenz der
/// Trust-Endpunkte aktive Menge — und damit die falsche Empfaengermenge.
#[async_trait]
pub trait RegistryHeadDirectory: Send + Sync {
    /// Der hoechste dem Server bekannte anwendbare Kopf fuer diese Zeit und
    /// diese Sequenz (`design.md` §13.3, Schritt 5).
    async fn select_head_for_sequence(
        &self,
        organization_id: ea_types::OrganizationId,
        proposed_sequence: ea_types::ChainSequence,
        now: ea_types::UnixMillis,
    ) -> Result<RegistryHeadSelectionV1, AuthorityError>;
}

/// Wie die Kopfauswahl auf eine Sequenz antwortet.
///
/// DREI Ausgaenge und kein `Option`: „kein anwendbarer Kopf" und „der naechste
/// Kopf gilt erst spaeter" sind verschiedene Antworten mit verschiedenen
/// Status. Der zweite traegt die Version, die der Aufrufer zuerst holen muss,
/// und der Nachtrag fuehrt sie als `required-registry-version` im
/// Fehlerkoerper.
pub enum RegistryHeadSelectionV1 {
    /// `RegistrySelectionOutcome::Selected` — der operative Kopf.
    ///
    /// Als `Arc<dyn ActiveRegistryHeadV1>` und nicht als
    /// [`ea_trust::SelectedRegistryHead`], damit der Dienst gegen einen Port
    /// prueft statt gegen einen Typ, den nur `ea-trust` bauen kann. Die
    /// PRODUKTION reicht ausschliesslich den echten Kopf herein — die
    /// Implementierung fuer ihn steht in dieser Crate und leitet Feld fuer
    /// Feld weiter.
    Selected(std::sync::Arc<dyn ActiveRegistryHeadV1>),
    /// `RegistrySelectionOutcome::PendingFuture` — der naechste Kopf gilt
    /// erst spaeter. `409` mit `required-registry-version`.
    PendingFuture {
        required_registry_version: ea_types::RegistryVersion,
        required_registry_head_hash: ObjectHash,
    },
    /// Kein anwendbarer Kopf: kein Anker, keine Kopflinie, oder der vorhandene
    /// Kopf deckt diese Sequenz nicht. Das ist eine Antwort und kein Ausfall.
    NoApplicableHead,
}

/// Der gewaehlte Registry-Head, so wie der Commit-Pfad ihn liest.
///
/// Der Port beschreibt AUSSCHLIESSLICH Weiterleitungen an
/// [`ea_trust::SelectedRegistryHead`]; er trifft keine eigene Aussage und
/// leitet insbesondere keine Empfaengermenge aus Datenbankzeilen ab. Er
/// existiert, weil `SelectedRegistryHead` bewusst undurchsichtig ist und sich
/// ausserhalb von `ea-trust` nicht bauen laesst: ohne ihn koennte der
/// Commit-Dienst gegen keine Attrappe geprueft werden, und die Nebenlaeufigkeits-
/// und Ausfallmatrix brauchte fuer jeden Fall einen vollstaendigen
/// Vertrauensabschluss.
///
/// [`ea_crypto::SignerCertificateResolver`] ist Obertrait und keine Kopie:
/// [`ea_crypto::verify_cose_sign1`] loest den Signierer ueber genau diese
/// Kante auf, und `SelectedRegistryHead` implementiert sie bereits
/// (`crates/ea-trust/src/resolver.rs`:333).
pub trait ActiveRegistryHeadV1: ea_crypto::SignerCertificateResolver + Send + Sync {
    fn registry_version(&self) -> ea_types::RegistryVersion;
    fn registry_head_hash(&self) -> ObjectHash;
    /// Die Kettenkennung des Ankers — die Autoritaet fuer „in welche Kette
    /// schreibe ich hier".
    fn chain_id(&self) -> ea_types::ChainId;
    fn policy_object_hash(&self) -> ObjectHash;
    fn policy_fields(&self) -> &ea_format::PolicyFieldsV1;
    /// Jedes zur vorgeschlagenen Sequenz aktive Zertifikat, aufsteigend nach
    /// `CertificateHash`.
    ///
    /// Die EINZIGE Quelle der aktiven Empfaengermenge. Ein `Vec` und kein
    /// `impl Iterator`, weil der Port objektsicher bleiben muss.
    fn active_certificates(&self) -> Vec<(CertificateHash, &ea_format::DeviceCertificateFieldsV1)>;
}

/// Der echte Kopf ist die eine Produktionsimplementierung.
///
/// Jede Methode leitet unveraendert weiter; es gibt hier keine Zeile, die eine
/// eigene Aussage traefe.
impl ActiveRegistryHeadV1 for ea_trust::SelectedRegistryHead {
    fn registry_version(&self) -> ea_types::RegistryVersion {
        Self::registry_version(self)
    }

    fn registry_head_hash(&self) -> ObjectHash {
        Self::registry_head_hash(self)
    }

    fn chain_id(&self) -> ea_types::ChainId {
        Self::chain_id(self)
    }

    fn policy_object_hash(&self) -> ObjectHash {
        Self::policy_object_hash(self)
    }

    fn policy_fields(&self) -> &ea_format::PolicyFieldsV1 {
        Self::policy_fields(self)
    }

    fn active_certificates(&self) -> Vec<(CertificateHash, &ea_format::DeviceCertificateFieldsV1)> {
        Self::active_certificates(self).collect()
    }
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

    /// Der Abdruck des Schluessels, mit dem signiert wird.
    ///
    /// `receipt-core-v1` fuehrt ihn an einer Pflichtposition, und der Kern
    /// muss VOR der Signatur fertig sein — die Signatur laeuft ja ueber ihn.
    /// Er aus der fertigen Signatur zurueckzulesen waere ein Zirkel; also
    /// nennt ihn der Schluesselhalter, der ihn ohnehin kennt.
    fn key_thumbprint(&self) -> ea_types::KeyThumbprint;

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
        rate_key_digest: ea_types::Hash32,
        issued_at: ea_types::UnixMillis,
        expires_at: ea_types::UnixMillis,
    ) -> Result<(), RepositoryError>;

    /// Wie viele Challenges dieser AUFRUFER seit `since` bekommen hat.
    ///
    /// Gezaehlt wird ueber den verbindungsseitigen Zaehlschluessel und
    /// ausdruecklich NICHT ueber die `organizationId`: die kommt beim
    /// Challenge-Endpunkt aus dem unsignierten Koerper, und ein frei
    /// behaupteter Wert ist keine Identitaet. Ein Fremder koennte die
    /// Organisation sonst mit ihrer eigenen Kennung aussperren — und weil
    /// jeder signierte Request eine frische Challenge braucht, waere das ein
    /// Totalausfall dieser Organisation.
    async fn count_issued_since(
        &self,
        rate_key_digest: ea_types::Hash32,
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

    /// Loest ein Credential ueber den Eindeutigkeitszwang
    /// (`organizationId`, `credentialId`) auf.
    ///
    /// `None` heisst „unbekannt" und ist NICHT `404`: der Abrufpfad rechnet
    /// mit derselben Ersatzantwort weiter, damit ein unbekanntes Credential
    /// dieselbe Arbeit ausloest wie ein bekanntes (`web-reader-design.md`
    /// §6.4.1, :228).
    async fn resolve(
        &self,
        organization_id: ea_types::OrganizationId,
        credential_id: &[u8],
    ) -> Result<Option<crate::models::StoredWebauthnCredentialV1>, RepositoryError>;

    /// Schreibt den Signaturzaehler fort — Compare-and-Set.
    ///
    /// `true`, wenn die Zeile noch auf `from` stand. Ein `false` heisst, dass
    /// ein zweiter Abruf mit derselben Assertion schneller war; der Zaehler
    /// bleibt damit auch unter Nebenlaeufigkeit streng steigend.
    async fn advance_counter(
        &self,
        organization_id: ea_types::OrganizationId,
        credential_id: &[u8],
        from: u32,
        to: u32,
    ) -> Result<bool, RepositoryError>;
}

/// Die Ablage der gewrappten Reader-Vault-Blobs
/// (`web-reader-design.md` §6.4).
///
/// Sie ist AUSDRUECKLICH nicht der Object Store: dessen Namensraum
/// `<type>/<hex objectHash>` gehoert den sechs Archivobjektarten
/// (`design.md` §13.4). Hier liegen Bytes, die der Server nicht lesen kann und
/// zu denen er weder Vault-Key noch PRF-Ausgabe kennt.
#[async_trait]
pub trait VaultBlobStore: Send + Sync {
    /// Legt GENAU EIN Chiffrat ab: create-if-absent ueber
    /// (`organizationId`, `subjectId`, Blobhash), ohne Aenderungs- und ohne
    /// Loeschpfad.
    ///
    /// `max_per_subject` MUSS unter gegenseitigem Ausschluss durchgesetzt
    /// werden. Eine Zaehlung in derselben Anweisung reicht NICHT: unter
    /// `READ COMMITTED` liest die Unterabfrage einen Schnappschuss und nimmt
    /// keine Sperre, also kaemen zwei gleichzeitige Ablagen beide an einer
    /// Decke von sieben vorbei und landeten bei neun. Ein Bestand ueber der
    /// Decke waere nicht reparierbar — diese Stufe hat keinen Loeschpfad.
    async fn store(
        &self,
        blob: crate::models::ReaderVaultBlobV1,
        max_per_subject: u64,
    ) -> Result<crate::models::VaultBlobOutcome, RepositoryError>;

    /// Die Chiffrate GENAU EINER `subjectId` in GENAU EINER Organisation, in
    /// stabiler Reihenfolge und hoechstens `limit` Stueck.
    ///
    /// Die Grenze ist Tiefenverteidigung: die Decke steht bereits in
    /// [`Self::store`], und ein Bestand darueber koennte die Antwort sonst gar
    /// nicht mehr rahmen — was diese `subjectId` dauerhaft aussperrte.
    async fn list_for_subject(
        &self,
        organization_id: ea_types::OrganizationId,
        subject_id: ea_types::SubjectId,
        limit: u64,
    ) -> Result<Vec<Vec<u8>>, RepositoryError>;
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
    /// `Ok(None)` heisst „kein aktuell freigegebenes Geraet unter diesem
    /// Abdruck“ — und AUSSCHLIESSLICH das. Ein Ausfall und ein verlorenes
    /// Rennen sind eigene Befunde: sie als `None` auszugeben machte aus einer
    /// toten Datenbank ein „dein Schluessel ist unbekannt“, also aus einem
    /// wiederholbaren 503 ein endgueltiges 401.
    async fn resolve(
        &self,
        organization_id: ea_types::OrganizationId,
        key_thumbprint: ea_types::KeyThumbprint,
        now: ea_types::UnixMillis,
    ) -> Result<Option<ea_sync_protocol::RegisteredDevice>, AuthorityError>;
}

/// Warum die Autoritaetsaufloesung KEINE Antwort geben konnte.
///
/// „Kein freigegebenes Geraet“ steht bewusst NICHT darin: das ist eine
/// Antwort, kein Fehler, und es ist [`Option::None`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityError {
    /// Datenbank oder Object Store antworten nicht.
    Unavailable,
    /// Der persistente Vertrauenszustand hat sich unter dem Aufrufer bewegt.
    /// Wiederholbar — und ausdruecklich KEIN Autorisierungsbefund.
    StateConflict,
}

impl AuthorityError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "EA-AUTH-DEPENDENCY-UNAVAILABLE",
            Self::StateConflict => "EA-TRUST-STATE-CONFLICT",
        }
    }
}

/// Der technische Eintrags- und Grant-Index einer Kette.
///
/// Ein eigener Port neben [`CommitRepository`], weil er eine andere Frage
/// stellt: jener SCHREIBT unter der Kettenkopfsperre, dieser BLAETTERT. Er
/// entscheidet nichts — `design.md` §13.2 haelt fest, dass technische Listen
/// nicht autoritativ sind; die gelieferten Adressen loest der Dienst gegen den
/// Object Store auf, und die exakten Bytes prueft der Empfaenger selbst.
#[async_trait]
pub trait EntryDirectory: Send + Sync {
    /// Der Eintrag an GENAU dieser Sequenz dieser Kette.
    ///
    /// Er beantwortet die Bindung des Lesestapels: der Leser nennt
    /// `afterSequence` UND den zugehoerigen `afterEntryHash`, und beide
    /// muessen zusammenpassen. `Ok(None)` heisst „diese Kette traegt dort
    /// keinen Eintrag“ — eine Antwort, kein Ausfall.
    async fn entry_at(
        &self,
        organization_id: ea_types::OrganizationId,
        chain_id: ea_types::ChainId,
        sequence: ea_types::ChainSequence,
    ) -> Result<Option<crate::models::EntryIndexEntryV1>, RepositoryError>;

    /// Der Eintrag zu diesem `entryHash` — in DIESER Organisation.
    ///
    /// Die Organisation steht dabei, weil `entries.entry_hash` global
    /// eindeutig ist: ohne sie beantwortete ein Aufrufer die Frage „gibt es
    /// diesen Eintrag?“ ueber eine fremde Organisation hinweg.
    async fn entry_of(
        &self,
        organization_id: ea_types::OrganizationId,
        entry_hash: ea_types::EntryHash,
    ) -> Result<Option<crate::models::EntryIndexEntryV1>, RepositoryError>;

    /// Die Eintraege AB `from_sequence` — EINSCHLIESSLICH —, aufsteigend,
    /// hoechstens `limit`.
    ///
    /// EINSCHLIESSLICH und nicht „danach", und das ist eine Sicherheitsaussage
    /// und keine Geschmacksfrage: Sequenz NULL ist der Genesis-Eintrag
    /// (`ea_format`s `eip`-Pruefung erzwingt „ohne Vorgaenger genau dann, wenn
    /// Sequenz null"), und ein Leser ohne verifizierten Kopf fragt genau ab
    /// dort. Eine exklusive Grenze liesse den ersten Eintrag jeder Kette
    /// unerreichbar, und zwar OHNE Fehlermeldung — die Antwort waere ein
    /// plausibles `200`. Der Aufrufer, der nach einer bekannten Position
    /// weiterliest, uebergibt deshalb `position + 1`.
    async fn entries_from(
        &self,
        organization_id: ea_types::OrganizationId,
        chain_id: ea_types::ChainId,
        from_sequence: ea_types::ChainSequence,
        limit: usize,
    ) -> Result<Vec<crate::models::EntryIndexEntryV1>, RepositoryError>;

    /// Der aktuelle Kopf dieser Kette, oder `None` fuer eine unbekannte Kette.
    async fn chain_head(
        &self,
        organization_id: ea_types::OrganizationId,
        chain_id: ea_types::ChainId,
    ) -> Result<Option<crate::models::ChainHeadStateV1>, RepositoryError>;

    /// Der Eintrag und die Frist EINES Grants, ueber seine Adresse.
    ///
    /// Der Objektabruf kennt nur den Objekthash; ohne diese Aufloesung koennte
    /// er die beiden Auslieferungssperren gar nicht anwenden. `Ok(None)`
    /// heisst „dieses Objekt ist kein Grant dieser Organisation" — fuer jede
    /// andere Objektart ist das die richtige Antwort und kein Ausfall.
    async fn grant_delivery(
        &self,
        organization_id: ea_types::OrganizationId,
        object_hash: ObjectHash,
    ) -> Result<Option<crate::models::GrantDeliveryV1>, RepositoryError>;

    /// Die Grants dieses Eintrags, aufsteigend nach `objectHash`.
    async fn grants_of(
        &self,
        organization_id: ea_types::OrganizationId,
        entry_hash: ea_types::EntryHash,
    ) -> Result<Vec<crate::models::GrantIndexEntryV1>, RepositoryError>;

    /// Der Checkpoint, der GENAU diese Sequenz dieser Kette deckt.
    async fn checkpoint_covering(
        &self,
        organization_id: ea_types::OrganizationId,
        chain_id: ea_types::ChainId,
        covered_sequence: ea_types::ChainSequence,
    ) -> Result<Option<ObjectHash>, RepositoryError>;
}

/// Der Objektbestand einer Organisation, in Blaetterreihenfolge.
///
/// Er traegt den ARCHIVEXPORT und sonst nichts. Ein eigener Port neben
/// [`ObjectTypeDirectory`], weil der eine EINEN Hash aufloest und dieser den
/// gesamten Bestand durchgeht.
#[async_trait]
pub trait ArchiveExportDirectory: Send + Sync {
    async fn objects_after(
        &self,
        organization_id: ea_types::OrganizationId,
        after_technical_index: u64,
        limit: usize,
    ) -> Result<Vec<crate::models::ExportIndexEntryV1>, RepositoryError>;
}

/// Die Ablage der historischen Grants.
///
/// Sie schreibt AUSSCHLIESSLICH in `object_index` und `grants`. Sie beruehrt
/// weder `entries` noch `chain_heads` noch `receipts`: `design.md` §13.3 sagt
/// woertlich, der Endpunkt „veraendert weder `.eip`, initialen Grant-Plan noch
/// Kettenkopf“, und dieser Port hat kein Feld, mit dem er es koennte.
#[async_trait]
pub trait HistoricalGrantStore: Send + Sync {
    async fn record_historical_grant(
        &self,
        command: crate::models::HistoricalGrantCommandV1,
    ) -> Result<crate::models::AppendOutcome, RepositoryError>;
}

/// Die APPEND-ONLY-Ablage der Reader-Acknowledgements (`design.md` §13.4).
#[async_trait]
pub trait ReaderAckStore: Send + Sync {
    async fn record_reader_ack(
        &self,
        command: crate::models::ReaderAckCommandV1,
    ) -> Result<crate::models::AppendOutcome, RepositoryError>;
}

/// Die APPEND-ONLY-Ablage der Vernichtungsvorgaenge (`design.md` §16.3).
#[async_trait]
pub trait DestructionStore: Send + Sync {
    /// Nimmt eine gepruefte Mehr-Augen-Authorization an und legt den Vorgang
    /// im Zustand `requested` an — mit seinen Zielen, gegen die anschliessend
    /// jede Auslieferung und jeder Re-Grant gesperrt wird.
    async fn record_destruction_request(
        &self,
        command: crate::models::DestructionRequestCommandV1,
    ) -> Result<crate::models::AppendOutcome, RepositoryError>;

    /// Der gespeicherte Stand, oder `None` fuer eine unbekannte Kennung.
    async fn destruction_state(
        &self,
        organization_id: ea_types::OrganizationId,
        destruction_id: ea_types::DestructionId,
    ) -> Result<Option<crate::models::DestructionStateV1>, RepositoryError>;

    /// `true`, wenn fuer diesen Eintrag ein Vernichtungsvorgang laeuft.
    ///
    /// Das ist die serverseitige Sperre aus `design.md` §16.3, Schritt 2:
    /// „Neue Auslieferungen und historische Re-Grants fuer die Ziele
    /// serverseitig blockieren.“
    async fn is_destruction_target(
        &self,
        organization_id: ea_types::OrganizationId,
        entry_hash: ea_types::EntryHash,
    ) -> Result<bool, RepositoryError>;
}
