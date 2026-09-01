//! Der inkrementelle Lesestapel — und der Cursor, der sich erst DANACH bewegt.
//!
//! # Der Schnitt in drei Haelften ist die tragende Entscheidung
//!
//! [`ReaderSyncService::next_request`] gibt einen FERTIG signierten Request
//! heraus, [`ReaderSyncService::accept_batch`] nimmt die Antwortbytes zurueck,
//! [`ReaderSyncService::confirm`] schreibt den Cursor. Dazwischen liegt der
//! Browser mit seinem `fetch`, und genau dort liegt er auch physisch: in
//! `apps/web/src/sync/transport.ts`, das nichts tut, als die Bytes zu bewegen.
//!
//! Der Schnitt ist keine Bequemlichkeit. `crates/ea-sync-client` loest dieselbe
//! Aufgabe mit `#[async_trait] SyncTransportV1` ueber Tokio und steht deshalb
//! in `WASM32_EXEMPT_CRATES`; eine Kante von `ea-reader` dorthin waere eine
//! Kante von der Positivliste auf die Ausnahmeliste und fiele sofort. Und ein
//! async-Rust-Kern zoege eine zweite Laufzeit in das WASM-Modul, waehrend
//! `fetch` ohnehin ein Promise ist, das JavaScript besser abwartet als Rust.
//!
//! # Der Startkopf wird gegen den EIGENEN Cursor geprueft
//!
//! Nie gegen die Selbstauskunft der Antwort. `reader-batch-v1` traegt
//! `requested-after-sequence`, `requested-after-entry-hash` und
//! `start-head-entry-hash`, und alle drei muessen zum bestaetigten Cursor
//! passen — BEVOR ein einziges Objektbyte den Speicher erreicht. Ein Batch, der
//! nur mit SICH SELBST stimmig ist, ist an einem fremden Kopf angesetzt und
//! wird abgewiesen; `a_self_consistent_batch_at_a_foreign_head_is_still_refused`
//! misst genau diesen Unterschied.
//!
//! Die Zaehl- und Bytegrenzen des Rahmens (`MAX_READER_PAGE_OBJECTS_V1`,
//! `MAX_READER_PAGE_BYTES_V1`) setzt `ReaderBatchV1::decode` bereits durch; sie
//! werden hier nicht ein zweites Mal geschrieben.
//!
//! # Die Reihenfolge danach, und warum sie diese ist
//!
//! 1. Jedes `ObjectRecordV1` unter seinem `objectHash` in den verschluesselten
//!    Objektcache.
//! 2. Die Dauerhaftigkeit wird GEMESSEN und nicht angeordnet: der Port
//!    [`crate::ReaderBlobStore`] kennt kein `flush` — `OpfsBlobStore::put`
//!    flusht je Schreibvorgang —, also wird jeder angekuendigte Objekthash aus
//!    dem Speicher ZURUECKGELESEN. Fehlt einer, ist das
//!    `EA-READER-MISSING-OBJECT` und kein stiller Fortschritt.
//! 3. `verify_archive_observed` gegen den Vault-gepinnten `TrustAnchorV1` ueber
//!    den GESAMTEN lokalen Bestand, nicht nur ueber die neuen Bytes: eine Kette
//!    verifiziert an ihrem Kopf und nicht an einer Seite.
//! 4. Erst wenn nichts widerspricht, schreibt `confirm` den naechsten Cursor.
//!
//! Hier wird NICHTS entschluesselt. `VerifyOptions::new(os_wall_clock)` ohne
//! Empfaengerschluessel ist der Lauf, den dieser Task fuehrt; ein fehlender
//! eigener Grant ist dabei ausdruecklich KEIN Fehler, und seine Klassifikation
//! gehoert dem Task „Verifikation vor Entschlüsselung".
//!
//! # Ein Abbruch ist eine Aussage ueber den WIRT
//!
//! Deshalb traegt kein eingespielter Abbruchpunkt einen der vier
//! Abweisungscodes: die zwei Punkte um den Request herum melden
//! `EA-READER-TRANSPORT`, alle uebrigen `EA-READER-STORE`. Wer einen Abbruch
//! als Luecke oder Fork ausgaebe, machte aus einem geschlossenen Tab einen
//! Angriffsverdacht.

use ea_archive::QuarantineReason;
use ea_crypto::object_hash;
use ea_sync_protocol::{
    EndpointV1, REQUEST_ID_HEADER_V1, ReaderBatchV1, RequestIdV1, RequestParts, RequestSigner,
    SignatureParametersV1, organization_tag,
};
use ea_trust::TrustAnchorV1;
use ea_types::UnixMillis;
use ea_verify::{
    ChainHeadV1, SilentObserver, VerificationReportV1, VerifyOptions, verify_archive_observed,
};

use crate::batch::{ReaderCacheSourceV1, VerifiedSyncBatch};
use crate::blob_store::{ReaderBlobKey, ReaderBlobStore};
use crate::cache::{ReaderObjectCache, cache_key};
use crate::cursor::{
    ConfirmedCursor, READER_SYNC_CURSOR_BLOB_KEY_V1, READER_SYNC_OBJECTS_BLOB_KEY_V1,
    ReaderCursorStore,
};
use crate::http::ReaderRequestV1;
use crate::vault::{ReaderVaultError, UnlockedVault};

/// Die Gueltigkeitsspanne der Lesestapel-Anfrage, in Sekunden.
///
/// Sie liegt UNTER `ea_sync_protocol::MAX_SIGNATURE_WINDOW_SECONDS_V1` (300)
/// und wird nicht daraus abgeleitet: der Server nennt seine Obergrenze, der
/// Klient waehlt darunter. Dieselbe Regel und derselbe Wert wie
/// [`crate::ENROLLMENT_SIGNATURE_WINDOW_SECONDS_V1`]; eine eigene Konstante,
/// weil beide Spannen unabhaengig voneinander enger werden duerfen.
pub const READER_SYNC_SIGNATURE_WINDOW_SECONDS_V1: i64 = 60;

/// Die Unterschreitung steht als Zusicherung da und nicht als Absichtserklaerung
/// im Fliesstext: ein spaeter angehobener Klientenwert faellt beim UEBERSETZEN
/// und nicht erst an einem Server, der die Anfrage abweist.
const _: () = assert!(
    READER_SYNC_SIGNATURE_WINDOW_SECONDS_V1 < ea_sync_protocol::MAX_SIGNATURE_WINDOW_SECONDS_V1
);

/// Jeder Befund des Lesestapels.
///
/// ACHT Arme und ausdruecklich kein Sammelcode. Die ersten vier sind
/// Abweisungen mit je eigener Bedeutung: eine Luecke ist eine Aussage ueber den
/// BESTAND, ein Fork eine ueber den SERVER, ein fehlendes Objekt eine ueber die
/// ANTWORT, ein falscher Startkopf eine ueber die POSITION. Wer sie
/// zusammenfaltet, kann einen Verlust nicht mehr von einem Angriff
/// unterscheiden.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReaderSyncError {
    /// Der Batch bindet nicht den bestaetigten Cursor dieses Readers.
    StartHeadMismatch,
    /// Ein im Rahmen angekuendigtes Objekt liegt nicht im Cache.
    MissingObject,
    /// Die Kette verifiziert nicht bis zum Batchende.
    ChainGap,
    /// Zwei Ketten auf derselben Sequenz, oder ein Kopf, der einer schon
    /// bestaetigten Sequenz widerspricht.
    ChainFork,
    /// Die Antwortbytes sind kein `reader-batch-v1`, oder die Signatur liess
    /// sich nicht bilden.
    Protocol,
    /// Der Bytespeicher — oder der Tresor, der ihn aufschliesst — steht nicht
    /// zur Verfuegung.
    Store,
    /// Der Verifizierer konnte ueber den Bestand gar nichts sagen.
    Verification,
    /// Der Weg zum Server ist abgebrochen.
    Transport,
}

impl ReaderSyncError {
    /// Der stabile Code des Befunds.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::StartHeadMismatch => "EA-READER-START-HEAD-MISMATCH",
            Self::MissingObject => "EA-READER-MISSING-OBJECT",
            Self::ChainGap => "EA-READER-CHAIN-GAP",
            Self::ChainFork => "EA-READER-CHAIN-FORK",
            Self::Protocol => "EA-READER-PROTOCOL",
            Self::Store => "EA-READER-STORE",
            Self::Verification => "EA-READER-VERIFICATION",
            Self::Transport => "EA-READER-TRANSPORT",
        }
    }
}

impl core::fmt::Display for ReaderSyncError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ReaderSyncError {}

impl From<ReaderVaultError> for ReaderSyncError {
    /// Jeder Fehlschlag des Tresors oder seiner Speicher ist fuer den
    /// Lesestapel EINE Lage: der Speicher steht nicht zur Verfuegung. Die
    /// FEINERE Aussage bleibt am Ursprungstyp und geht nicht verloren — sie ist
    /// hier nur keine Aussage ueber den Batch.
    fn from(_: ReaderVaultError) -> Self {
        Self::Store
    }
}

/// Die zwoelf Abbruchpunkte eines Lesestapels, in Ablaufreihenfolge.
///
/// Gebaut wie `MigrationFaultPoint::ALL` in
/// `crates/ea-archive-fs/src/profile_migration.rs` (dort vierzehn) und aus
/// demselben Grund NICHT hinter einem Merkmalstor: die Liste behauptet, dass
/// jeder dieser Punkte im AUSGELIEFERTEN Ablauf erreichbar ist. Eine Liste, die
/// es nur unter einem Testfeature gaebe, pruefte ein anderes Programm als das,
/// das im Browser laeuft. Eingespielt wird ueber
/// [`ReaderSyncService::with_fault`], das den Dienst VERBRAUCHT — diese Crate
/// traegt nirgends innere Veraenderlichkeit, und ein Abbruchpunkt ist kein
/// Grund, damit anzufangen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReaderSyncFaultPoint {
    /// Vor dem Bilden und Signieren der Stapelanfrage.
    BeforeBatchRequest,
    /// Danach — der Request steht, hat den Wirt aber nie verlassen.
    AfterBatchRequest,
    /// Vor dem Vergleich des Startkopfs mit dem bestaetigten Cursor.
    BeforeStartHeadCheck,
    /// Danach.
    AfterStartHeadCheck,
    /// Vor dem ersten Objektbyte im verschluesselten Cache.
    BeforeObjectWrite,
    /// Nach dem ERSTEN und vor dem zweiten — der Tab, der mitten im Batch
    /// schliesst.
    AfterFirstObjectWrite,
    /// Vor der Rueckleseprobe, mit der die Dauerhaftigkeit gemessen wird.
    BeforeBlobStoreFlush,
    /// Danach: jedes angekuendigte Objekt ist aus dem Speicher zurueckgekommen.
    AfterBlobStoreFlush,
    /// Vor dem Verifikationslauf ueber den GESAMTEN lokalen Bestand.
    BeforeChainVerification,
    /// Danach — der Bericht liegt vor, der Cursor steht noch.
    AfterChainVerification,
    /// Vor dem Schreiben des naechsten Cursors.
    BeforeCursorPersist,
    /// Danach — und damit hinter der einzigen dauerhaften Wirkung von
    /// `confirm`. `confirm` NIMMT sie an dieser Stelle zurueck; die Begruendung
    /// steht dort.
    AfterCursorPersist,
}

impl ReaderSyncFaultPoint {
    /// Alle zwoelf Punkte, in Ablaufreihenfolge.
    pub const ALL: [Self; 12] = [
        Self::BeforeBatchRequest,
        Self::AfterBatchRequest,
        Self::BeforeStartHeadCheck,
        Self::AfterStartHeadCheck,
        Self::BeforeObjectWrite,
        Self::AfterFirstObjectWrite,
        Self::BeforeBlobStoreFlush,
        Self::AfterBlobStoreFlush,
        Self::BeforeChainVerification,
        Self::AfterChainVerification,
        Self::BeforeCursorPersist,
        Self::AfterCursorPersist,
    ];

    /// Der stabile Name des Punktes.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BeforeBatchRequest => "before-batch-request",
            Self::AfterBatchRequest => "after-batch-request",
            Self::BeforeStartHeadCheck => "before-start-head-check",
            Self::AfterStartHeadCheck => "after-start-head-check",
            Self::BeforeObjectWrite => "before-object-write",
            Self::AfterFirstObjectWrite => "after-first-object-write",
            Self::BeforeBlobStoreFlush => "before-blob-store-flush",
            Self::AfterBlobStoreFlush => "after-blob-store-flush",
            Self::BeforeChainVerification => "before-chain-verification",
            Self::AfterChainVerification => "after-chain-verification",
            Self::BeforeCursorPersist => "before-cursor-persist",
            Self::AfterCursorPersist => "after-cursor-persist",
        }
    }

    /// Der Befund, unter dem dieser Punkt abbricht.
    ///
    /// Ein Abbruch ist eine Aussage ueber den WIRT und nie ueber den Batch: die
    /// zwei Punkte um den Request herum unterbrechen den Netzweg, alle uebrigen
    /// den dauerhaften Speicherweg. Keiner traegt einen der vier
    /// Abweisungscodes.
    const fn interruption(self) -> ReaderSyncError {
        match self {
            Self::BeforeBatchRequest | Self::AfterBatchRequest => ReaderSyncError::Transport,
            _ => ReaderSyncError::Store,
        }
    }
}

/// Was eine ENTSPERRTE Sitzung dem Lesestapel mitbringt.
///
/// Fuenf Werte in EINEM Traeger, damit der gesperrte Zustand nicht als fuenf
/// unabhaengige `Option` darstellbar ist: entsperrt sind alle fuenf da,
/// gesperrt keiner, und ein Zwischenzustand existiert nicht. Vier davon nennt
/// die Aufgabe — Anker, Signierer, Cache und der Cursorspeicher —, die fuenfte
/// ist die Herkunft: sie gehoert zur Sitzung, weil `@authority` in der
/// Signaturbasis steht und ein Wechsel mitten in einer Lesestrecke jede
/// Signatur ungueltig machte.
struct ReaderSyncSession<'a> {
    anchor: &'a TrustAnchorV1,
    signer: RequestSigner,
    cache: ReaderObjectCache,
    cursors: ReaderCursorStore,
    authority: String,
}

/// Der inkrementelle Lesestapel EINER Sitzung.
///
/// Der Bytespeicher ist KEIN Feld: `ReaderBlobStore::put` braucht `&mut self`,
/// und ein gehaltener Speicher zwaenge den Dienst in die Lebensdauer eines
/// Wirts, den es im Browser nur innerhalb eines Worker-Zyklus gibt. Er tritt
/// deshalb je Aufruf ein — dieselbe Anordnung, die
/// [`crate::ReaderObjectCache::put_exact_object`],
/// [`crate::ReaderEntryStateStore::put_entry_state`] und
/// [`crate::ReaderTrustStateStore::put_trust_state`] in dieser Crate bereits
/// fuehren.
pub struct ReaderSyncService<'a> {
    session: Option<ReaderSyncSession<'a>>,
    os_wall_clock: UnixMillis,
    fault: Option<ReaderSyncFaultPoint>,
}

impl<'a> ReaderSyncService<'a> {
    /// Der Dienst einer ENTSPERRTEN Sitzung.
    ///
    /// Anker und Ed25519-Schluessel kommen AUSSCHLIESSLICH aus dem Tresor
    /// (`web-reader-design.md` §6.1); der Dienst beschafft weder das eine noch
    /// das andere. `authority` und die Uhr treten als Werte ein — auf
    /// `wasm32-unknown-unknown` gibt es fuer `SystemTime::now()` keinen Wirt,
    /// und eine hier erfundene Herkunft waere eine Behauptung ueber einen
    /// Server, den niemand konfiguriert hat.
    #[must_use]
    pub fn open(vault: &'a UnlockedVault, authority: String, os_wall_clock: UnixMillis) -> Self {
        // Der Signierer bekommt eine KOPIE des Skalars; das Original bleibt im
        // Tresor. Dieselbe Zeile fuehrt `ReaderEnrollment::finish`.
        let signer = RequestSigner::from_secret(
            vault
                .audit_signing_key()
                .with_exposed(|bytes| ea_crypto::SecretBytes::new(*bytes)),
        );
        Self {
            session: Some(ReaderSyncSession {
                anchor: vault.pinned_anchor(),
                signer,
                cache: ReaderObjectCache::open(vault),
                cursors: ReaderCursorStore::open(vault),
                authority,
            }),
            os_wall_clock,
            fault: None,
        }
    }

    /// Der Dienst eines GESPERRTEN Tresors.
    ///
    /// Er existiert, damit die Weigerung einen Ort hat: ohne ihn muesste der
    /// Aufrufer selbst entscheiden, was ein Sync im gesperrten Zustand tut, und
    /// die naheliegende Antwort — den Request trotzdem bilden und unsigniert
    /// senden — waere die falsche. `next_request` liefert
    /// `EA-READER-STORE`, und damit entsteht GAR KEINE Anfrage.
    #[must_use]
    pub const fn locked(os_wall_clock: UnixMillis) -> Self {
        Self {
            session: None,
            os_wall_clock,
            fault: None,
        }
    }

    /// Derselbe Dienst mit einem eingespielten Abbruchpunkt.
    ///
    /// VERBRAUCHEND und nicht `&self`: `ProfileMigrator::with_fault` kann sich
    /// eine `Mutex` leisten, weil es ohnehin eine haelt — diese Crate traegt
    /// nirgends innere Veraenderlichkeit, und ein Abbruchpunkt ist kein Grund,
    /// damit anzufangen.
    #[must_use]
    pub fn with_fault(mut self, point: ReaderSyncFaultPoint) -> Self {
        self.fault = Some(point);
        self
    }

    /// Der bestaetigte Cursor, GELESEN aus dem Bytespeicher.
    ///
    /// Ein Speicher ohne Cursorblob steht auf Genesis — das ist kein Fehler,
    /// sondern ein frisches Geraet. Ein Cursorblob fuer eine ANDERE Kette ist
    /// dagegen `EA-READER-STORE`: er kann nur aus einem fremden oder
    /// verfaelschten Speicher stammen, und stillschweigend auf Genesis
    /// zurueckzufallen hiesse, eine Uebernahme als Neuanfang auszugeben.
    ///
    /// # Errors
    /// `EA-READER-STORE`, wenn der Tresor gesperrt ist, der Blob nicht lesbar
    /// ist oder er eine fremde Kette nennt.
    pub fn confirmed_cursor(
        &self,
        store: &dyn ReaderBlobStore,
    ) -> Result<ConfirmedCursor, ReaderSyncError> {
        let session = self.session()?;
        let Some(cursor) = session.cursors.get_cursor(store)? else {
            return Ok(ConfirmedCursor::genesis(session.anchor));
        };
        if cursor.chain_id() != session.anchor.chain_id() {
            return Err(ReaderSyncError::Store);
        }
        Ok(cursor)
    }

    /// Die VOLLSTAENDIGE Schluesselmenge, die ein Speicher fuer diesen Batch
    /// offen haben MUSS: der Sync-Zustand, jede Adresse aus der dauerhaften
    /// Objektliste und jede, die der Rahmen neu belegt.
    ///
    /// # Warum das ein eigener Schritt ist
    ///
    /// Weil der Browser es erzwingt und nicht, weil es bequem waere:
    /// `OpfsBlobStore::open` (`crates/ea-reader-wasm/src/opfs_worker.rs`) ist
    /// der ASYNCHRONE Vorlauf, der jedes `FileSystemSyncAccessHandle` oeffnet,
    /// und danach ist der Speicher synchron — ein Schluessel, der beim Oeffnen
    /// nicht dabei war, laesst sich nachtraeglich nicht mehr aufschliessen. Der
    /// Aufrufer braucht die Menge also, BEVOR er den Speicher hat, den
    /// [`Self::accept_batch`] verlangt.
    ///
    /// Die Adressen entstehen HIER und nicht in der Bruecke: `cache/<hex
    /// objectHash>` ist die Abbildung von `crates/ea-reader/src/cache.rs`, und
    /// eine zweite Abschrift davon in JavaScript oder in `ea-reader-wasm` waere
    /// genau die Stelle, an der Schreiben und Oeffnen auseinanderliefen.
    /// # Der ansaessige Bestand kommt aus RUST und nie vom Wirt
    ///
    /// `state_store` ist ein Speicher, der NUR die zwei Adressen aus
    /// [`Self::sync_state_blob_keys`] offen hat; daraus wird die dauerhafte
    /// Objektliste gelesen. Frueher nahm diese Funktion die ansaessigen
    /// Schluessel als Argument entgegen, und im Browser fuellte JavaScript es:
    /// damit entschied der Wirt, welchen Bestand `verify_archive_observed`
    /// ueberhaupt zu sehen bekommt. Die Wirkung war fail-closed — ein
    /// ausgelassener Schluessel endet als Luecke oder Fork —, aber die
    /// Zustaendigkeit war falsch herum, und `web-reader-design.md` §9 laesst
    /// keine Sicherheitsentscheidung in TypeScript zu.
    ///
    /// # Errors
    /// `EA-READER-STORE` bei gesperrtem Tresor oder unlesbarer Objektliste,
    /// `EA-READER-PROTOCOL` fuer Bytes, die kein `reader-batch-v1` sind.
    pub fn required_blob_keys(
        &self,
        state_store: &dyn ReaderBlobStore,
        response_body: &[u8],
    ) -> Result<Vec<ReaderBlobKey>, ReaderSyncError> {
        let session = self.session()?;
        let batch = ReaderBatchV1::decode(response_body).map_err(|_| ReaderSyncError::Protocol)?;
        let mut keys = Self::sync_state_blob_keys()?;
        for hash in session.cursors.get_object_manifest(state_store)? {
            keys.push(cache_key(hash)?);
        }
        for record in batch.objects() {
            keys.push(cache_key(record.object_hash())?);
        }
        keys.sort_unstable();
        keys.dedup();
        Ok(keys)
    }

    /// Die zwei Adressen des dauerhaften Sync-Zustands: Cursor und Objektliste.
    ///
    /// Der ERSTE Vorlauf eines Browserlaufs oeffnet genau sie — mehr kann er
    /// nicht, weil erst die Objektliste sagt, was sonst noch zu oeffnen ist.
    /// Danach folgt der zweite Vorlauf ueber [`Self::required_blob_keys`].
    ///
    /// # Errors
    /// Die Codes des Bytespeichers; fuer zwei konstante Adressen unerreichbar,
    /// aber nicht wegdiskutiert.
    pub fn sync_state_blob_keys() -> Result<Vec<ReaderBlobKey>, ReaderSyncError> {
        Ok(vec![
            ReaderBlobKey::new(READER_SYNC_CURSOR_BLOB_KEY_V1).map_err(ReaderVaultError::from)?,
            ReaderBlobKey::new(READER_SYNC_OBJECTS_BLOB_KEY_V1).map_err(ReaderVaultError::from)?,
        ])
    }

    /// Der naechste Lesestapel-Request, FERTIG signiert.
    ///
    /// Der Pfad kommt aus `EndpointV1::ChainEntries::path_template()` und wird
    /// nicht als Literal ein zweites Mal geschrieben; dazu die Abfrageparameter
    /// `afterSequence`, `afterEntryHash` und — nur wenn einer vorliegt —
    /// `cursor`. Ein leeres `cursor=` waere eine ANDERE Anfrage als gar keins.
    ///
    /// # Errors
    /// `EA-READER-STORE` bei gesperrtem Tresor oder fehlender Entropie,
    /// `EA-READER-PROTOCOL`, wenn sich die Signatur nicht bilden laesst,
    /// `EA-READER-TRANSPORT` an den zwei Abbruchpunkten um den Request herum.
    pub fn next_request(
        &self,
        cursor: &ConfirmedCursor,
    ) -> Result<ReaderRequestV1, ReaderSyncError> {
        let session = self.session()?;
        self.fault_at(ReaderSyncFaultPoint::BeforeBatchRequest)?;
        let target = chain_entries_target(cursor);
        let request_id = RequestIdV1::try_from(&random_bytes::<16>()?[..])
            .map_err(|_| ReaderSyncError::Protocol)?;
        let parts = RequestParts {
            method: EndpointV1::ChainEntries.method(),
            authority: session.authority.clone(),
            target_uri: format!("https://{}{target}", session.authority),
            // KEIN Koerper, also deckt die Signatur weder `content-type` noch
            // `content-digest` ab — genau das, was
            // `EndpointV1::ChainEntries::request_media_type()` mit `None` sagt.
            content_type: None,
            body_digest: None,
            request_id,
        };
        let created = self.os_wall_clock.get().div_euclid(1_000);
        let parameters = SignatureParametersV1::new(
            created,
            created + READER_SYNC_SIGNATURE_WINDOW_SECONDS_V1,
            random_bytes::<32>()?,
            organization_tag(session.anchor.organization_id()),
        );
        let signed = session
            .signer
            .sign(&parts, &parameters)
            .map_err(|_| ReaderSyncError::Protocol)?;
        let request = ReaderRequestV1 {
            method: EndpointV1::ChainEntries.method(),
            authority: session.authority.clone(),
            target,
            headers: vec![
                (REQUEST_ID_HEADER_V1, request_id.to_header_value()),
                ("signature-input", signed.signature_input_header()),
                ("signature", signed.signature_header()),
            ],
            body: Vec::new(),
        };
        self.fault_at(ReaderSyncFaultPoint::AfterBatchRequest)?;
        Ok(request)
    }

    /// Nimmt die Antwortbytes an und gibt einen NACHWEIS heraus.
    ///
    /// Er schreibt Objektbytes und liest sie zurueck, er verifiziert die
    /// gesamte lokale Kette — und er bewegt den Cursor NICHT. Das tut
    /// [`Self::confirm`], und die Trennung ist der Grund, warum ein Abbruch
    /// zwischen beiden folgenlos ist.
    ///
    /// # Errors
    /// Die vier Abweisungen, dazu `EA-READER-PROTOCOL` fuer Bytes, die kein
    /// `reader-batch-v1` sind, `EA-READER-STORE` fuer den Bytespeicher und
    /// `EA-READER-VERIFICATION`, wenn der Verifizierer ueber den Bestand gar
    /// nichts sagen konnte.
    pub fn accept_batch(
        &self,
        store: &mut dyn ReaderBlobStore,
        cursor: &ConfirmedCursor,
        response_body: &[u8],
    ) -> Result<VerifiedSyncBatch, ReaderSyncError> {
        let session = self.session()?;
        self.fault_at(ReaderSyncFaultPoint::BeforeStartHeadCheck)?;
        let batch = ReaderBatchV1::decode(response_body).map_err(|_| ReaderSyncError::Protocol)?;
        if !binds_cursor(&batch, cursor) {
            return Err(ReaderSyncError::StartHeadMismatch);
        }
        self.fault_at(ReaderSyncFaultPoint::AfterStartHeadCheck)?;

        self.fault_at(ReaderSyncFaultPoint::BeforeObjectWrite)?;
        let mut object_hashes = Vec::with_capacity(batch.objects().len());
        for (index, record) in batch.objects().iter().enumerate() {
            // VOR dem Schreiben: Bytes, die ihre eigene Adresse nicht tragen,
            // landeten unter einer anderen — und das angekuendigte Objekt waere
            // danach im Cache abwesend. Der Cache bekommt sie deshalb gar nicht
            // erst zu sehen.
            if object_hash(record.exact_object_bytes()) != record.object_hash() {
                return Err(ReaderSyncError::MissingObject);
            }
            session
                .cache
                .put_exact_object(store, record.exact_object_bytes())?;
            object_hashes.push(record.object_hash());
            if index == 0 {
                self.fault_at(ReaderSyncFaultPoint::AfterFirstObjectWrite)?;
            }
        }

        self.fault_at(ReaderSyncFaultPoint::BeforeBlobStoreFlush)?;
        for hash in &object_hashes {
            if session.cache.get_exact_object(&*store, *hash)?.is_none() {
                return Err(ReaderSyncError::MissingObject);
            }
        }
        self.fault_at(ReaderSyncFaultPoint::AfterBlobStoreFlush)?;

        self.fault_at(ReaderSyncFaultPoint::BeforeChainVerification)?;
        let report = self.verify_local_archive(session, &*store)?;
        self.fault_at(ReaderSyncFaultPoint::AfterChainVerification)?;
        classify(&report, cursor, batch.covered_through_sequence())?;

        // Der Kopf, den der bestaetigte Cursor danach TRAEGT — und nicht
        // notwendig der, den der Bericht ausweist.
        //
        // Solange der Server einen Blaetterschein herausgibt, laeuft EINE
        // Lesestrecke weiter, und ihr Startkopf bleibt stehen:
        // `crates/ea-sync-server/src/reader_sync.rs` bindet den technischen
        // Cursor an GENAU den Startkopf, mit dem die Strecke begann, und
        // oeffnet ihn unter keinem anderen. Ein Reader, der zwischen zwei
        // Seiten seinen Startkopf nachzoege, bekaeme beim naechsten Blaettern
        // `EA-SYNC-CURSOR-INVALID` — gemessen am Geltungsbereich in
        // `TechnicalCursorScopeV1`. Der lokal weiter gerechnete Kopf geht dabei
        // nicht verloren: mit der letzten Seite faellt der Schein weg, und der
        // Cursor springt auf genau ihn.
        let confirmed_head = if batch.next_cursor().is_some() {
            ChainHeadV1::new(cursor.chain_id(), cursor.sequence(), cursor.entry_hash())
        } else {
            report.chain_head()
        };

        Ok(VerifiedSyncBatch::new(
            confirmed_head,
            batch.next_cursor().map(<[u8]>::to_vec),
            object_hashes,
            report,
        ))
    }

    /// Schreibt den naechsten Cursor — und NIMMT ihn zurueck, wenn das
    /// Zurueckschreiben nicht haelt.
    ///
    /// Die Ruecknahme ist die einzige Art, wie ein Punkt HINTER der dauerhaften
    /// Wirkung die Zusage „ein Abbruch laesst den Cursor stehen" noch einloesen
    /// kann; `ProfileMigrator` nimmt an `AfterPointerSwap` aus demselben Grund
    /// seinen Zeigertausch zurueck. Sie ist zugleich echter Produktionsweg und
    /// kein Testpfad: ein Speicher, der einen Schreibvorgang annimmt und den
    /// Blob danach nicht mehr herausgibt, hat den Cursor NICHT dauerhaft
    /// gemacht — und einen halb geschriebenen Cursor stehen zu lassen waere
    /// schlimmer, als gar keinen zu schreiben.
    ///
    /// # Errors
    /// `EA-READER-STORE` fuer jeden Fehlschlag des Bytespeichers und an den
    /// zwei Abbruchpunkten um den Schreibvorgang herum.
    pub fn confirm(
        &self,
        store: &mut dyn ReaderBlobStore,
        batch: VerifiedSyncBatch,
    ) -> Result<ConfirmedCursor, ReaderSyncError> {
        let session = self.session()?;
        self.fault_at(ReaderSyncFaultPoint::BeforeCursorPersist)?;
        let head = batch.head();
        let next = ConfirmedCursor::new(
            head.chain_id(),
            head.sequence(),
            head.entry_hash(),
            batch.next_cursor().map(<[u8]>::to_vec),
        );
        // Die Adressliste ZUERST und ausserhalb der Ruecknahme. Sie darf dem
        // Cursor vorauslaufen: nennt sie ein Objekt, das nicht da ist, liest
        // sich dessen Blob als abwesend und der Durchlauf ueberspringt ihn.
        // Umgekehrt waere es fail-closed, aber teuer — ein Objekt, das da ist
        // und nicht in der Liste steht, sieht die naechste Verifikation nicht.
        let mut cached = session.cursors.get_object_manifest(&*store)?;
        cached.extend_from_slice(batch.object_hashes());
        session.cursors.put_object_manifest(store, &cached)?;

        let previous = session.cursors.raw_blob(&*store)?;
        session.cursors.put_cursor(store, &next)?;
        match self.committed_cursor(session, &*store, &next) {
            Ok(()) => Ok(next),
            Err(error) => {
                session
                    .cursors
                    .restore_raw_blob(store, previous.as_deref())?;
                Err(error)
            }
        }
    }

    /// Setzt den Cursor auf den LOKAL verifizierten Stand zurueck.
    ///
    /// Nach einem Cacheverlust ist das Genesis; steht noch ein verifizierbarer
    /// Rest im Speicher, ist es dessen Kopf — „ab Genesis ODER ab einem lokal
    /// verifizierten Checkpoint". Der Blaetterschein faellt dabei IMMER weg: er
    /// gehoert zu einer Lesestrecke, die es nicht mehr gibt.
    ///
    /// Der Aufsetzpunkt wird SOFORT geschrieben. Ein Speicher, der Objektbytes
    /// verloren hat und weiterhin den alten Cursor traegt, behauptete einen
    /// verifizierten Stand, den er nicht mehr belegen kann.
    ///
    /// # Errors
    /// `EA-READER-STORE` und `EA-READER-VERIFICATION`.
    pub fn rebuild_from_genesis(
        &self,
        store: &mut dyn ReaderBlobStore,
    ) -> Result<ConfirmedCursor, ReaderSyncError> {
        let session = self.session()?;
        let report = self.verify_local_archive(session, &*store)?;
        let head = report.chain_head();
        let restart = if head.entry_hash() == ChainHeadV1::sentinel(head.chain_id()).entry_hash() {
            ConfirmedCursor::genesis(session.anchor)
        } else {
            ConfirmedCursor::new(
                session.anchor.chain_id(),
                head.sequence(),
                head.entry_hash(),
                None,
            )
        };
        // DIESELBE Rueckleseprobe wie in `confirm`, und aus demselben Grund:
        // ein Speicher, der einen Schreibvorgang annimmt und den Blob danach
        // nicht mehr herausgibt, hat den Aufsetzpunkt NICHT dauerhaft gemacht.
        // Ein Reader, der das nicht merkt, glaubte an einen lokal
        // verifizierten Checkpoint, den er nicht mehr vorzeigen kann. Der
        // Ruecknahmepfad ist hier derselbe wie dort.
        let previous = session.cursors.raw_blob(&*store)?;
        session.cursors.put_cursor(store, &restart)?;
        match self.committed_cursor(session, &*store, &restart) {
            Ok(()) => Ok(restart),
            Err(error) => {
                session
                    .cursors
                    .restore_raw_blob(store, previous.as_deref())?;
                Err(error)
            }
        }
    }

    /// Die entsperrte Sitzung — oder die Weigerung.
    fn session(&self) -> Result<&ReaderSyncSession<'a>, ReaderSyncError> {
        self.session.as_ref().ok_or(ReaderSyncError::Store)
    }

    /// Bricht ab, wenn `point` der eingespielte Abbruchpunkt ist.
    fn fault_at(&self, point: ReaderSyncFaultPoint) -> Result<(), ReaderSyncError> {
        if self.fault == Some(point) {
            return Err(point.interruption());
        }
        Ok(())
    }

    /// Ob der geschriebene Cursor auch zurueckkommt.
    fn committed_cursor(
        &self,
        session: &ReaderSyncSession<'a>,
        store: &dyn ReaderBlobStore,
        written: &ConfirmedCursor,
    ) -> Result<(), ReaderSyncError> {
        self.fault_at(ReaderSyncFaultPoint::AfterCursorPersist)?;
        match session.cursors.get_cursor(store)? {
            Some(read_back) if &read_back == written => Ok(()),
            _ => Err(ReaderSyncError::Store),
        }
    }

    /// Verifiziert den GESAMTEN lokalen Bestand gegen den gepinnten Anker.
    fn verify_local_archive(
        &self,
        session: &ReaderSyncSession<'a>,
        store: &dyn ReaderBlobStore,
    ) -> Result<VerificationReportV1, ReaderSyncError> {
        let source = ReaderCacheSourceV1::new(&session.cache, store);
        verify_archive_observed(
            &source,
            session.anchor,
            // OHNE Empfaengerschluessel: dieser Task entschluesselt nichts, und
            // ein fehlender eigener Grant ist hier kein Fehler.
            VerifyOptions::new(self.os_wall_clock),
            // Der Bericht ist gefragt, nicht das Gate-Protokoll.
            &mut SilentObserver,
        )
        .map_err(|_| ReaderSyncError::Verification)
    }
}

/// Ob der Batch GENAU diesen Cursor bindet.
///
/// Alle vier Positionen, und ausdruecklich nicht nur `start-head-entry-hash`:
/// die Selbstauskunft eines Batches ueber sich selbst ist immer stimmig.
fn binds_cursor(batch: &ReaderBatchV1, cursor: &ConfirmedCursor) -> bool {
    batch.chain_id() == cursor.chain_id()
        && batch.requested_after_sequence() == cursor.sequence().get()
        && batch.requested_after_entry_hash() == cursor.entry_hash()
        && batch.start_head_entry_hash() == cursor.entry_hash()
}

/// Der Pfad samt Abfragezeichenkette fuer `GET /v1/chains/{chainId}/entries`.
fn chain_entries_target(cursor: &ConfirmedCursor) -> String {
    let path = EndpointV1::ChainEntries
        .path_template()
        .replace("{chainId}", &hex::encode(cursor.chain_id().as_bytes()));
    let mut target = format!(
        "{path}?afterSequence={}&afterEntryHash={}",
        cursor.sequence().get(),
        hex::encode(cursor.entry_hash().as_bytes())
    );
    if let Some(token) = cursor.technical_cursor() {
        target.push_str("&cursor=");
        target.push_str(&hex::encode(token));
    }
    target
}

/// Der Bericht, gegen den bestaetigten Cursor und das Batchende gestellt.
///
/// Die Reihenfolge ist die der Schwere. Ein Fork ist eine Aussage ueber den
/// SERVER und muss vor jeder Luecke fallen: `ea-verify` traegt Fork und
/// Kettenbruch als `conflicting` in die Quarantaene ein und haelt den
/// verifizierten Kopf VOR der kleinsten strittigen Sequenz an — wer nur die
/// Kopfsequenz prueft, saehe genau dann eine Luecke, wo ein Angriff steht.
fn classify(
    report: &VerificationReportV1,
    cursor: &ConfirmedCursor,
    covered_through_sequence: u64,
) -> Result<(), ReaderSyncError> {
    if report
        .quarantined_objects()
        .any(|object| object.reason() == QuarantineReason::Conflicting)
    {
        return Err(ReaderSyncError::ChainFork);
    }
    let head = report.chain_head();
    // Auf einem Genesis-Cursor gibt es keine schon bestaetigte Sequenz, der ein
    // Kopf widersprechen koennte; der erste Eintrag auf Sequenz null waere sonst
    // selbst der Widerspruch.
    if !cursor.is_genesis()
        && (head.sequence().get() < cursor.sequence().get()
            || (head.sequence() == cursor.sequence() && head.entry_hash() != cursor.entry_hash()))
    {
        return Err(ReaderSyncError::ChainFork);
    }
    if report.gaps().len() != 0 {
        return Err(ReaderSyncError::ChainGap);
    }
    // MINDESTENS bis zum Batchende, nicht genau bis dorthin. Ein Kopf DARUEBER
    // ist kein Mangel, sondern der Normalfall eines Wiederholversuchs: der
    // Bestand traegt dann schon mehr, als die wiederholte Seite ankuendigt.
    // Ein Kopf DARUNTER ist die Ankuendigung ohne Deckung — der Server hat
    // eine Abdeckung behauptet, die die Kette nicht traegt.
    if head.sequence().get() < covered_through_sequence {
        return Err(ReaderSyncError::ChainGap);
    }
    Ok(())
}

/// `N` Byte frischer Entropie vom Wirt.
///
/// Genau der Weg, den `crates/ea-reader/src/enrollment.rs` und
/// `crates/ea-reader/src/vault.rs` bereits nehmen; ein zweites RNG entsteht
/// hier nicht.
fn random_bytes<const N: usize>() -> Result<[u8; N], ReaderSyncError> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|_| ReaderSyncError::Store)?;
    Ok(bytes)
}
