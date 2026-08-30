//! Der Klient: Reihenfolge, Signatur, Wiederaufnahme.
//!
//! # Die Reihenfolge ist die Zusage
//!
//! `design.md` §9.3 Schritt 12: bei einem kontrollierten Netzlaufwerkprofil
//! werden exakt dieselben committeten Bytes in gleicher Reihenfolge
//! veroeffentlicht — Grants zuerst, `.eip` zuletzt —, und „vor erfolgreicher
//! Netzarchiv-Publikation findet kein Sync-Server-Upload dieses Eintrags
//! statt". [`SyncClient::push_pending`] setzt das strukturell durch: der
//! Transport wird erst angefasst, NACHDEM das Netzarchiv die Bytes hat, und
//! die veroeffentlichten Bytes werden vorher gegen die committeten geprueft.
//!
//! # Jeder Request traegt eine FRISCHE Challenge
//!
//! Der Server fuehrt einen Nonce- und Request-ID-Speicher
//! (`crates/ea-sync-protocol/src/http_signature.rs`); eine wiederverwendete
//! Nonce ist dort ein Replay. Der Klient holt sie deshalb je Request neu und
//! bewahrt keine auf.
//!
//! # Was NICHT automatisch wiederholt wird
//!
//! `design.md`:1584: „Netzwerk- und 5xx-Fehler werden mit begrenztem
//! exponentiellem Backoff und Jitter erneut versucht. Format-, Signatur-,
//! Fork- und Autorisierungsfehler werden nicht automatisch uebergangen."
//! [`is_automatically_retried`] ist die ausfuehrbare Fassung des zweiten
//! Satzes, und sie entscheidet POSITIV: nur was ausdruecklich als
//! voruebergehend erkannt ist, wird wiederholt.

use std::sync::Arc;

use ea_archive::ArchiveBackend as _;
use ea_archive_fs::{LocalPathBackend, PlannedPublicationV1, PublicationQueue};
use ea_sync_protocol::{
    EntryCommitRequestV1, EntryCommitResponseV1, HttpMethod, RequestIdV1, RequestParts,
    RequestSigner, STRUCTURED_MEDIA_TYPE_V1, SignatureParametersV1, body_digest, organization_tag,
};
use ea_types::{ChainId, ObjectHash, OrganizationId, RetryConfig, UnixMillis};

use crate::{
    DetailCause, SyncClientError, SyncStatus,
    queue::{PendingStepV1, SyncQueueV1, step_of, sync_state_of},
    receipt::verify_receipt_against_archive,
    retry::{OsJitter, RetryStore},
};

/// Ein Request, wie der Transport ihn sieht.
///
/// Die SIGNATURKOPFZEILEN stehen fertig darin: sie entstehen im Klienten mit
/// dem echten [`RequestSigner`], und ein Transport, der sie selbst bilden
/// duerfte, waere eine zweite Auslegung desselben Profils.
#[derive(Clone, Debug)]
pub struct TransportRequestV1 {
    pub method: HttpMethod,
    /// Der Zielpfad, ohne Schema und Autoritaet.
    pub target: String,
    pub authority: String,
    pub content_type: Option<String>,
    /// Fertige Kopfzeilen, in der Reihenfolge, in der sie gesendet werden.
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
    /// Die Nonce dieser Signatur — HERAUSGEGEBEN, damit ein Zeuge sie messen
    /// kann. Sie steht ohnehin in `signature-input`; hier steht sie nur
    /// zerlegt daneben.
    pub nonce: [u8; 32],
}

/// Die Antwort, wie der Klient sie braucht.
#[derive(Clone, Debug)]
pub struct TransportResponseV1 {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Der Fehlschlag der LEITUNG — und nur er.
///
/// Eine Ablehnung mit Status ist KEIN Transportfehler: sie ist eine Antwort,
/// und ob sie wiederholt wird, entscheidet der Klient am Status und am
/// Fehlercode. Diese Aufzaehlung traegt deshalb ausschliesslich Faelle, in
/// denen gar keine Antwort entstanden ist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportErrorV1 {
    /// Die Gegenstelle war nicht erreichbar.
    Unreachable,
    /// Die Gegenstelle hat nicht rechtzeitig geantwortet.
    Timeout,
    /// Der TLS-Aufbau ist gescheitert. Fail-closed und ausdruecklich KEIN
    /// Grund, unverschluesselt zu wiederholen.
    Tls,
}

/// Die Transportnaht.
///
/// Objekt-sicher ueber `async-trait`, damit ein Testdoppel den echten Klienten
/// ersetzt, ohne dass der Klient davon etwas erfaehrt.
#[ea_sync_client_async_trait::async_trait]
pub trait SyncTransportV1: Send + Sync {
    /// Sendet GENAU EINEN Request und liest GENAU EINE Antwort.
    ///
    /// # Errors
    ///
    /// [`TransportErrorV1`], wenn keine Antwort entstanden ist.
    async fn send(
        &self,
        request: TransportRequestV1,
    ) -> Result<TransportResponseV1, TransportErrorV1>;
}

/// Was ein Lauf getan hat.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PushSummary {
    pushed: usize,
    outstanding: usize,
    status: SyncStatus,
    detail_cause: Option<DetailCause>,
}

impl PushSummary {
    /// Die Zahl der Eintraege, deren Quittung verifiziert und abgelegt ist.
    #[must_use]
    pub const fn pushed(&self) -> usize {
        self.pushed
    }

    /// Die Zahl der Eintraege, die weiter anstehen.
    #[must_use]
    pub const fn outstanding(&self) -> usize {
        self.outstanding
    }

    /// Der oeffentliche Zustand — einer der vier.
    #[must_use]
    pub const fn status(&self) -> SyncStatus {
        self.status
    }

    /// Die Detailursache DANEBEN, nie ein fuenfter Zustand.
    #[must_use]
    pub const fn detail_cause(&self) -> Option<DetailCause> {
        self.detail_cause
    }
}

/// Alles, was EIN Klient braucht.
///
/// Ein Datensatz statt zehn Stellungsargumenten: zwei Bytefolgen und zwei
/// Kennungen in Folge sind eine Verwechslung, die kein Typ bemerkt.
pub struct SyncClientConfigV1 {
    /// Der LOKALE committete Bestand. Die Warteschlange entsteht aus ihm, und
    /// die verifizierte Quittung wird in ihn gelegt.
    pub backend: Arc<LocalPathBackend>,
    /// Die exakten Ankerbytes DIESER Linie.
    pub anchor_bytes: Vec<u8>,
    /// Die Warteschlange des kontrollierten Netzprofils, sofern konfiguriert.
    pub network: Option<Arc<PublicationQueue>>,
    pub transport: Arc<dyn SyncTransportV1>,
    pub signer: Arc<RequestSigner>,
    pub organization_id: OrganizationId,
    /// Die Kette, auf die committet wird. Sie steht in der Ziel-URI, und die
    /// Signatur deckt `@target-uri` ab — ein falscher Wert ist deshalb keine
    /// stille Fehladressierung, sondern eine Signatur ueber eine andere
    /// Ressource.
    pub chain_id: ChainId,
    pub authority: String,
    pub database: Arc<ea_local_store::EncryptedDatabase>,
    /// Die Schranken des Profils. Sie kommen HEREIN und werden nicht hier
    /// erfunden: `ControlledNetworkProfileV1` fuehrt sie, und die Beschriftung
    /// der Ursache sagt „die Wiederaufnahmeversuche DES PROFILS".
    pub retry: RetryConfig,
    pub max_resume_attempts: u16,
    pub observed_now: UnixMillis,
}

/// Der Writer-Sync-Klient.
pub struct SyncClient {
    config: SyncClientConfigV1,
    retry_store: RetryStore,
}

impl SyncClient {
    /// Baut den Klienten.
    ///
    /// # Errors
    ///
    /// [`SyncClientError::RetryStateUnreadable`], wenn die lokale Ablage die
    /// Wiederaufnahmetabelle nicht fuehrt.
    pub fn new(config: SyncClientConfigV1) -> Result<Self, SyncClientError> {
        let retry_store = RetryStore::open(
            Arc::clone(&config.database),
            config.retry,
            config.max_resume_attempts,
        )?;
        Ok(Self {
            config,
            retry_store,
        })
    }

    /// Schiebt bis zu `limit` anstehende Eintraege.
    ///
    /// # Errors
    ///
    /// Jeder Ausgang von [`SyncClientError`]. Ein Fehlschlag laesst den
    /// Bestand unveraendert: die Quittung wird VOR dem Ablegen geprueft, und
    /// ein abgebrochener Lauf hat nichts geschrieben, was ein naechster nicht
    /// byteidentisch wiederholen koennte.
    pub async fn push_pending(&self, limit: usize) -> Result<PushSummary, SyncClientError> {
        let queue = self.derive_queue().await?;
        let mut pushed = 0_usize;
        let mut step: Option<PendingStepV1> = None;

        for entry in queue.pending().iter().take(limit) {
            // Die begrenzte Wiederaufnahme steht VOR der Leitung: ein Eintrag,
            // dessen naechster Versuch noch aussteht, wird nicht angefasst.
            let schedule = self.retry_store.load(entry.entry_object_hash())?;
            if schedule.failed_attempts >= self.config.max_resume_attempts {
                // Ein ZUSTAND und kein Fehler — dieselbe Unterscheidung, die
                // `PublicationQueue` fuer die verlorene Erreichbarkeit trifft.
                // Die Oberflaeche zeigt `Fehler` mit „Wiederaufnahme
                // erschoepft" daneben; ein `Err` an dieser Stelle liesse sie
                // stattdessen einen Kommandofehlschlag anzeigen und den
                // vierten Zustand nie erreichen.
                step = Some(PendingStepV1::ResumeExhausted);
                break;
            }
            if !schedule.is_due(self.config.observed_now) {
                // ABBRUCH und nicht Ueberspringen, und das ist dieselbe
                // Reihenfolgezusage wie drei Zeilen weiter unten: die Kette
                // wird in IHRER Reihenfolge hochgeladen, und
                // `SyncQueueV1::derive` sortiert die anstehenden Eintraege
                // genau dafuer aufsteigend nach Sequenz.
                //
                // Ein `continue` waere hier ein stiller Reihenfolgebruch mit
                // dauerhafter Folge: liegt Sequenz 7 nach einem
                // voruebergehenden Leitungsfehler auf ihrem Backoff, ginge
                // Sequenz 8 vor ihr auf die Leitung, der Dienst prueft die
                // Kettenposition und antwortet mit einem Fork — und ein Fork
                // wird zu Recht NICHT automatisch wiederholt. Aus einem
                // Netzaussetzer auf einem Eintrag waere eine harte Ablehnung
                // des naechsten geworden.
                step = Some(PendingStepV1::ServerUpload);
                break;
            }

            // Schritt 12, ERSTE Haelfte: das Netzarchiv. Solange es wartet,
            // wird der Transport nicht angefasst — und zwar fuer KEINEN
            // weiteren Eintrag, denn die Kette wird in ihrer Reihenfolge
            // hochgeladen.
            if let Some(waiting) = self.publish_to_network_archive(entry).await? {
                step = Some(waiting);
                break;
            }

            // Schritt 12, ZWEITE Haelfte: der Serverupload.
            match self.commit_one(entry).await? {
                CommitOutcomeV1::Confirmed => {
                    self.retry_store.clear(entry.entry_object_hash())?;
                    pushed += 1;
                }
                CommitOutcomeV1::Deferred => {
                    step = Some(PendingStepV1::ServerUpload);
                    break;
                }
                CommitOutcomeV1::Exhausted => {
                    step = Some(PendingStepV1::ResumeExhausted);
                    break;
                }
            }
        }

        let outstanding = queue.pending().len().saturating_sub(pushed);
        // Die BESTAETIGTEN sind die, die schon vor diesem Lauf eine gepruefte
        // Quittung trugen, PLUS die, die dieser Lauf bestaetigt hat. Ohne den
        // zweiten Summanden meldete ein Lauf, der genau den letzten
        // anstehenden Eintrag bestaetigt, `lokal gesichert` statt
        // `synchronisiert` — die Ableitung, die den Zuwachs saehe, lief vor
        // ihm.
        let confirmed = queue.confirmed().saturating_add(pushed);
        let (status, detail_cause) = sync_state_of(outstanding, confirmed, step);
        Ok(PushSummary {
            pushed,
            outstanding,
            status,
            detail_cause,
        })
    }

    /// Der zuletzt BESTAETIGTE technische Cursor dieses Eintrags.
    ///
    /// Er ueberlebt einen Neustart, weil er in der lokalen Ablage liegt: eine
    /// unterbrochene Uebertragung setzt an ihm wieder auf, statt von vorn zu
    /// beginnen und dabei denselben Eintrag ein zweites Mal zu senden.
    ///
    /// # Errors
    ///
    /// [`SyncClientError::RetryStateUnreadable`].
    pub fn resume_cursor(&self, entry: ObjectHash) -> Result<Option<Vec<u8>>, SyncClientError> {
        Ok(self.retry_store.load(entry)?.cursor)
    }

    /// Haelt einen BESTAETIGTEN Cursor fest.
    ///
    /// Er kommt als [`ea_sync_protocol::TechnicalCursorV1`] herein und nicht
    /// als rohe Bytes: der Cursor ist signiert und an seinen Geltungsbereich
    /// gebunden, und ein Aufrufer, der irgendwelche Bytes ablegen duerfte,
    /// koennte den Wiederaufsetzpunkt frei waehlen.
    ///
    /// # Errors
    ///
    /// [`SyncClientError::RetryStateUnreadable`].
    pub fn record_resume_cursor(
        &self,
        entry: ObjectHash,
        cursor: &ea_sync_protocol::TechnicalCursorV1,
    ) -> Result<(), SyncClientError> {
        self.retry_store
            .record_cursor(entry, cursor.token_bytes(), self.config.observed_now)
    }

    /// Leitet die Warteschlange aus dem committeten Bestand ab.
    ///
    /// Der Bestand liegt auf dem Wirtdateisystem, und `ea-archive-fs` ist
    /// SYNCHRON — deshalb `spawn_blocking` und nicht ein blockierender Aufruf
    /// im Laufzeitthread.
    async fn derive_queue(&self) -> Result<SyncQueueV1, SyncClientError> {
        let backend = Arc::clone(&self.config.backend);
        let anchor_bytes = self.config.anchor_bytes.clone();
        let observed_now = self.config.observed_now;
        blocking(move || {
            let anchor = ea_trust::decode_trust_anchor(&anchor_bytes)
                .map_err(|_| SyncClientError::Archive)?;
            SyncQueueV1::derive(&backend.as_archive_source(), &anchor, observed_now)
        })
        .await
    }

    /// Veroeffentlicht die committeten Bytes im Netzarchiv — Grants zuerst.
    ///
    /// Liefert [`Some`], wenn der Serverupload dieses Eintrags NICHT laufen
    /// darf.
    async fn publish_to_network_archive(
        &self,
        entry: &crate::PendingEntryV1,
    ) -> Result<Option<PendingStepV1>, SyncClientError> {
        let Some(network) = self.config.network.clone() else {
            return Ok(None);
        };
        let plan = entry.publication_plan();
        let expected: Vec<Vec<u8>> = plan.iter().map(|(_, bytes)| bytes.clone()).collect();

        let planned = {
            let mut objects = Vec::with_capacity(plan.len());
            for (path, bytes) in plan {
                objects.push((archive_path_of(&path)?, bytes));
            }
            PlannedPublicationV1::new(objects)
        };

        let state = blocking(move || match network.publish(planned) {
            Ok(state) => Ok(Ok(state)),
            // Ein Profil, das die wirksame Policy NICHT traegt, ist ein
            // ZUSTAND des Aufbaus und kein Abbruch des Laufs: die Oberflaeche
            // soll `Fehler` mit „Profil nicht freigegeben" zeigen und nicht
            // einen Archivfehler ohne Ursache.
            Err(ea_archive::ArchiveBackendError::ProfileNotAllowed) => {
                Ok(Err(PendingStepV1::ProfileNotAllowed))
            }
            Err(other) => Err(SyncClientError::from(other)),
        })
        .await?;
        let state = match state {
            Ok(state) => state,
            Err(step) => return Ok(Some(step)),
        };
        if let Some(step) = step_of(state.outcome()) {
            return Ok(Some(step));
        }

        // BYTEGLEICHHEIT, gemessen und nicht angenommen. Der Serverupload
        // haengt daran, dass im Netzarchiv genau die committeten Bytes liegen;
        // ein Ziel, das etwas anderes annimmt, darf den Upload nicht
        // freigeben.
        if state.published_bytes() != expected {
            return Ok(Some(PendingStepV1::NetworkArchive));
        }
        Ok(None)
    }

    /// Ein Commit gegen den Dienst, mit frischer Challenge und Signatur.
    async fn commit_one(
        &self,
        entry: &crate::PendingEntryV1,
    ) -> Result<CommitOutcomeV1, SyncClientError> {
        let request = EntryCommitRequestV1::new(
            entry.entry_bytes().to_vec(),
            entry.grant_plan()?,
            entry.grant_bytes().to_vec(),
        )?;

        let nonce = self.fresh_challenge().await?;
        // Der Pfad entsteht aus der VORLAGE des Endpunkts und nicht aus einer
        // hier zusammengesetzten Zeichenkette: `EndpointV1` besitzt die
        // Adressform, und eine zweite Fassung davon liefe irgendwann
        // auseinander.
        let target = ea_sync_protocol::EndpointV1::EntryCommits
            .path_template()
            .replace("{chainId}", &hex_lower(self.config.chain_id.as_bytes()));
        let signed = self.sign(
            HttpMethod::Post,
            &target,
            Some(request.exact_bytes()),
            nonce,
        )?;

        let response = match self.config.transport.send(signed).await {
            Ok(response) => response,
            // Die LEITUNG ist gerissen: begrenzt wiederholen.
            Err(_) => return self.record_transport_failure(entry.entry_object_hash()),
        };

        if !is_automatically_retried(response.status) && response.status != 200 {
            return Err(SyncClientError::NotAutomaticallyRetried);
        }
        if response.status != 200 {
            return self.record_transport_failure(entry.entry_object_hash());
        }

        // Die Antwort traegt die exakten `.esr`-Bytes. Sie werden VERIFIZIERT,
        // bevor sie irgendwo liegen.
        let commit = EntryCommitResponseV1::decode(&response.body)?;
        let receipt_bytes = commit.receipt_bytes().to_vec();
        self.persist_verified_receipt(entry.entry_object_hash(), receipt_bytes)
            .await?;
        Ok(CommitOutcomeV1::Confirmed)
    }

    /// Prueft die Quittung VOLLSTAENDIG und legt sie erst danach ab — lokal
    /// und, sofern konfiguriert, im Netzarchiv.
    async fn persist_verified_receipt(
        &self,
        entry_object_hash: ObjectHash,
        receipt_bytes: Vec<u8>,
    ) -> Result<(), SyncClientError> {
        let backend = Arc::clone(&self.config.backend);
        let anchor_bytes = self.config.anchor_bytes.clone();
        let observed_now = self.config.observed_now;
        let network = self.config.network.clone();

        blocking(move || {
            let anchor = ea_trust::decode_trust_anchor(&anchor_bytes)
                .map_err(|_| SyncClientError::ReceiptInvalid)?;
            let verified = verify_receipt_against_archive(
                &backend.as_archive_source(),
                &anchor,
                entry_object_hash,
                &receipt_bytes,
                observed_now,
            )?;

            // ZUERST das Netzarchiv, DANN lokal — und diese Reihenfolge ist
            // die eigentliche Zusage dieser Funktion.
            //
            // `design.md`:1584 verlangt die Quittung in der lokalen
            // Archivkomponente UND, sofern konfiguriert, im Netzarchiv. Beide
            // sind Bedingung, aber nur EINE von beiden kann der Zeuge sein,
            // und der Zeuge muss die SPAETERE sein: die lokale Quittung ist
            // das, woran die Warteschlange den Eintrag als erledigt erkennt.
            // Laege sie zuerst und bliebe die Netzpublikation aufgeschoben, so
            // naehme der naechste Lauf den Eintrag aus der Warteschlange,
            // obwohl das Netzarchiv die Quittung nie bekommen hat — und der
            // aufgeschobene Plan der Warteschlange (EIN Platz) waere ohnehin
            // vom naechsten Eintragsplan verdraengt worden.
            //
            // So herum gibt es diesen Zustand nicht: solange das Netzarchiv
            // wartet, entsteht KEINE lokale Quittung, der Eintrag bleibt
            // anstehend, und der naechste Lauf wiederholt beides
            // byteidentisch. Create-if-absent macht die Wiederholung idempotent.
            if let Some(network) = network {
                let planned = PlannedPublicationV1::new(vec![(
                    verified.address().clone(),
                    verified.exact_bytes().to_vec(),
                )]);
                let state = network
                    .publish(planned)
                    .map_err(|_| SyncClientError::ReceiptNotPersisted)?;
                if !state.outcome().nothing_outstanding() {
                    return Err(SyncClientError::ReceiptNotPersisted);
                }
            }
            backend
                .create_non_object_if_absent(verified.address(), verified.exact_bytes())
                .map_err(|_| SyncClientError::ReceiptNotPersisted)?;
            backend
                .sync_file(verified.address())
                .map_err(|_| SyncClientError::ReceiptNotPersisted)?;
            backend
                .sync_directory(verified.address())
                .map_err(|_| SyncClientError::ReceiptNotPersisted)?;
            Ok(())
        })
        .await
    }

    fn record_transport_failure(
        &self,
        entry: ObjectHash,
    ) -> Result<CommitOutcomeV1, SyncClientError> {
        let mut jitter = OsJitter;
        match self
            .retry_store
            .record_failure(entry, self.config.observed_now, &mut jitter)?
        {
            Some(_) => Ok(CommitOutcomeV1::Deferred),
            None => Ok(CommitOutcomeV1::Exhausted),
        }
    }

    /// Holt eine FRISCHE Nonce. Sie wird nie aufbewahrt.
    async fn fresh_challenge(&self) -> Result<[u8; 32], SyncClientError> {
        let body = ea_sync_protocol::ChallengeRequestV1::new(self.config.organization_id);
        let request = TransportRequestV1 {
            method: HttpMethod::Post,
            target: "/v1/auth/challenges".to_owned(),
            authority: self.config.authority.clone(),
            content_type: Some(STRUCTURED_MEDIA_TYPE_V1.to_owned()),
            headers: vec![("content-type", STRUCTURED_MEDIA_TYPE_V1.to_owned())],
            body: body.exact_bytes().to_vec(),
            nonce: [0; 32],
        };
        let response = self
            .config
            .transport
            .send(request)
            .await
            .map_err(|_| SyncClientError::Protocol)?;
        if response.status != 200 {
            return Err(SyncClientError::Protocol);
        }
        // Der Challenge-Endpunkt antwortet mit einem signierten
        // `challenge-response-v1`, und nur damit. Es gab hier einmal einen
        // zweiten Zweig, der beliebige 32 Byte als Nonce annahm; er existierte
        // ausschliesslich, damit eine Attrappe sich das Rahmen sparen konnte —
        // also ein Testpfad in der Produktionsflaeche, und obendrein einer,
        // der einen ungerahmten, unzugeordneten Koerper von der Leitung
        // akzeptierte. Die Attrappe rahmt jetzt wie der Dienst.
        Ok(
            ea_sync_protocol::ChallengeResponseV1::decode(&response.body)
                .map_err(|_| SyncClientError::Protocol)?
                .core()
                .nonce,
        )
    }

    /// Signiert genau die Komponentenliste des Profils.
    fn sign(
        &self,
        method: HttpMethod,
        target: &str,
        body: Option<&[u8]>,
        nonce: [u8; 32],
    ) -> Result<TransportRequestV1, SyncClientError> {
        let content_type = body.map(|_| STRUCTURED_MEDIA_TYPE_V1.to_owned());
        let request_id = request_id_from(nonce);
        let parts = RequestParts {
            method,
            authority: self.config.authority.clone(),
            target_uri: format!("https://{}{target}", self.config.authority),
            content_type: content_type.clone(),
            body_digest: body.map(body_digest),
            request_id,
        };
        let created = self.config.observed_now.get().div_euclid(1_000);
        let parameters = SignatureParametersV1::new(
            created,
            created + 300,
            nonce,
            organization_tag(self.config.organization_id),
        );
        let signed = self.config.signer.sign(&parts, &parameters)?;

        let mut headers = vec![
            (
                ea_sync_protocol::REQUEST_ID_HEADER_V1,
                signed.request_id().to_header_value(),
            ),
            ("signature-input", signed.signature_input_header()),
            ("signature", signed.signature_header()),
        ];
        if let Some(media_type) = &content_type {
            headers.push(("content-type", media_type.clone()));
        }
        if let Some(digest) = signed.content_digest_header() {
            headers.push(("content-digest", digest.to_owned()));
        }
        Ok(TransportRequestV1 {
            method,
            target: target.to_owned(),
            authority: self.config.authority.clone(),
            content_type,
            headers,
            body: body.unwrap_or(&[]).to_vec(),
            nonce,
        })
    }
}

/// Der Ausgang EINES Commits.
enum CommitOutcomeV1 {
    /// Quittung verifiziert und abgelegt.
    Confirmed,
    /// Voruebergehend gescheitert; der naechste Versuch ist gebucht.
    Deferred,
    /// Die Schranke des Profils ist erschoepft.
    Exhausted,
}

/// Wird dieser Status AUTOMATISCH wiederholt?
///
/// POSITIV entschieden: nur `5xx` gilt als voruebergehend. Jeder `4xx` — und
/// damit jeder Format-, Signatur-, Fork-, Registry- und Autorisierungsfehler
/// des Dienstes — wird ausdruecklich NICHT wiederholt, denn ein Wiederholen
/// aendert an keinem von ihnen etwas und verdeckte nur, dass etwas nicht
/// stimmt (`design.md`:1584).
#[must_use]
const fn is_automatically_retried(status: u16) -> bool {
    status >= 500 && status < 600
}

/// Die Request-ID aus der Nonce.
///
/// Beide muessen je Request FRISCH sein — der Server fuehrt fuer beide einen
/// Replay-Speicher —, und beide aus derselben frischen Challenge zu ziehen
/// heisst, dass eine wiederverwendete Nonce auch eine wiederverwendete
/// Request-ID waere. Es gibt damit KEINEN Weg, die eine frisch und die andere
/// alt zu senden.
fn request_id_from(nonce: [u8; 32]) -> RequestIdV1 {
    RequestIdV1::try_from(&nonce[..16]).unwrap_or_else(|_| {
        unreachable!("sechzehn Byte einer Zweiunddreissig-Byte-Nonce sind eine Request-ID")
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(nibble(byte >> 4));
        text.push(nibble(byte & 0x0f));
    }
    text
}

const fn nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'a' + value - 10) as char,
    }
}

fn archive_path_of(relative: &str) -> Result<ea_archive::ArchivePath, SyncClientError> {
    let (directory, name) = relative
        .split_once('/')
        .ok_or(SyncClientError::QueueDerivation)?;
    ea_archive::ArchivePath::in_dir(&format!("{directory}/"), name)
        .map_err(|_| SyncClientError::QueueDerivation)
}

/// Fuehrt eine SYNCHRONE Kernoperation auf einem Blockierthread aus.
///
/// Die EINE Stelle, an der das geschieht — dasselbe Muster wie
/// `run_blocking` in `apps/desktop/src-tauri/src/commands/mod.rs`. Der Kern
/// bleibt synchron, und keine seiner Crates erfaehrt von einer Laufzeit.
async fn blocking<T, F>(work: F) -> Result<T, SyncClientError>
where
    F: FnOnce() -> Result<T, SyncClientError> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(result) => result,
        Err(_) => Err(SyncClientError::Archive),
    }
}

/// Der Alias, unter dem das Attributmakro innerhalb dieser Crate erreichbar
/// bleibt, obwohl der Re-Export in `lib.rs` denselben Namen traegt.
mod ea_sync_client_async_trait {
    pub use async_trait::async_trait;
}

// ---------------------------------------------------------------------------
// Der echte Transport: HTTP/1.1 ueber TLS 1.3, hyper auf tokio-rustls.
// ---------------------------------------------------------------------------

/// Der Transport gegen einen echten Dienst.
///
/// # Warum hyper und kein handgeschriebener Rahmen
///
/// `apps/server/tests/common/mod.rs` schreibt seinen HTTP/1.1-Rahmen selbst,
/// und das ist dort richtig: es ist eine TESTHILFE, und fuer eine Testhilfe
/// eine Abhaengigkeitsklasse zu oeffnen waere unverhaeltnismaessig. Hier ist es
/// umgekehrt. Dies ist der PRODUKTIONSPFAD, auf dem committete Archivbytes das
/// Geraet verlassen; ein selbstgebauter Parser waere hier eine zweite,
/// ungepruefte Auslegung von HTTP neben der, die der Server ueber `axum`
/// ohnehin fuehrt. `hyper` 1.x liegt darueber schon im Graphen, und ADR 0004
/// ratifiziert die vier Kanten dieser Familie.
///
/// ALPN nennt AUSSCHLIESSLICH `http/1.1`: der Server bietet `h2` zuerst an,
/// und ohne diese Zeile handelte er es aus.
pub struct HyperTlsTransport {
    address: std::net::SocketAddr,
    server_name: String,
    tls: Arc<rustls::ClientConfig>,
}

/// Wie lange der Transport auf TCP-Verbindung, TLS-Aufbau und Handshake
/// wartet.
///
/// Ohne Deckel haengt der Aufbau am Zeitgeber des Betriebssystems — bei einer
/// stillen Gegenstelle sind das Minuten, und der Anwender sieht in dieser Zeit
/// einen Push, der nichts tut. Zehn Sekunden reichen fuer jedes Netz, in dem
/// ein Einsatz laeuft.
pub const CONNECT_TIMEOUT_MS_V1: u64 = 10_000;

/// Wie lange der Transport auf Antwortkopf UND Antwortkoerper wartet.
///
/// Er umschliesst BEIDES, weil ein Server, der den Kopf schickt und den
/// Koerper nie beendet, sonst genau so lange haengt wie einer, der gar nicht
/// antwortet. Sechzig Sekunden liegen weit ueber jeder gemessenen Commit-Dauer
/// und weit unter „nie".
pub const REQUEST_TIMEOUT_MS_V1: u64 = 60_000;

/// Setzt einen Deckel auf eine Transportphase.
///
/// Laeuft er ab, ist der Befund [`TransportErrorV1::Timeout`] — und genau
/// darum gibt es die Variante: sie war ohne diese Funktion unerreichbar.
async fn within<T, E>(
    millis: u64,
    work: impl core::future::Future<Output = Result<T, E>>,
    on_error: TransportErrorV1,
) -> Result<T, TransportErrorV1> {
    match tokio::time::timeout(core::time::Duration::from_millis(millis), work).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(_)) => Err(on_error),
        Err(_) => Err(TransportErrorV1::Timeout),
    }
}

impl HyperTlsTransport {
    /// Baut den Transport gegen genau diese Wurzeln.
    ///
    /// TLS 1.3 ist die einzige angebotene Fassung, und der Anbieter ist `ring`
    /// — dieselbe Auswahl wie auf der Serverseite. Ein zweiter Anbieter waere
    /// ein zweiter Zertifikatsparser.
    ///
    /// # Errors
    ///
    /// [`SyncClientError::Protocol`], wenn die Wurzeln nicht tragen.
    pub fn new(
        address: std::net::SocketAddr,
        server_name: String,
        roots: rustls::RootCertStore,
    ) -> Result<Self, SyncClientError> {
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| SyncClientError::Protocol)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            address,
            server_name,
            tls: Arc::new(tls),
        })
    }
}

#[ea_sync_client_async_trait::async_trait]
impl SyncTransportV1 for HyperTlsTransport {
    async fn send(
        &self,
        request: TransportRequestV1,
    ) -> Result<TransportResponseV1, TransportErrorV1> {
        use http_body_util::{BodyExt as _, Full};

        // Jede Phase unter einem Deckel: eine stille Gegenstelle haengt sonst
        // den ganzen Push, und `TransportErrorV1::Timeout` waere unerreichbar.
        let stream = within(
            CONNECT_TIMEOUT_MS_V1,
            tokio::net::TcpStream::connect(self.address),
            TransportErrorV1::Unreachable,
        )
        .await?;
        let server_name = rustls::pki_types::ServerName::try_from(self.server_name.clone())
            .map_err(|_| TransportErrorV1::Tls)?;
        let stream = within(
            CONNECT_TIMEOUT_MS_V1,
            tokio_rustls::TlsConnector::from(Arc::clone(&self.tls)).connect(server_name, stream),
            TransportErrorV1::Tls,
        )
        .await?;

        let (mut sender, connection) = within(
            CONNECT_TIMEOUT_MS_V1,
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)),
            TransportErrorV1::Unreachable,
        )
        .await?;
        // Die Verbindung wird GETRIEBEN, solange der Request laeuft. Ohne
        // diesen Treiber blieben Bytes im Puffer liegen und der Request
        // haengte, bis der Zeitgeber der Gegenstelle zuschlaegt.
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });

        let method = match request.method {
            HttpMethod::Get => http::Method::GET,
            HttpMethod::Put => http::Method::PUT,
            HttpMethod::Post => http::Method::POST,
        };
        let mut builder = http::Request::builder()
            .method(method)
            .uri(&request.target)
            .header(http::header::HOST, &request.authority);
        for (name, value) in &request.headers {
            builder = builder.header(*name, value);
        }
        let outgoing = builder
            .body(Full::new(hyper::body::Bytes::from(request.body)))
            .map_err(|_| TransportErrorV1::Unreachable)?;

        // Kopf UND Koerper unter EINEM Deckel: ein Server, der den Kopf
        // schickt und den Koerper nie beendet, haengt sonst genau so lange wie
        // einer, der gar nicht antwortet.
        let read = within(
            REQUEST_TIMEOUT_MS_V1,
            async {
                let response = sender.send_request(outgoing).await?;
                let status = response.status().as_u16();
                let body = response.into_body().collect().await?.to_bytes().to_vec();
                Ok::<_, hyper::Error>((status, body))
            },
            TransportErrorV1::Timeout,
        )
        .await;
        driver.abort();
        let (status, body) = read?;
        Ok(TransportResponseV1 { status, body })
    }
}

#[cfg(test)]
mod tests {
    use super::is_automatically_retried;

    /// NUR `5xx` wird automatisch wiederholt.
    ///
    /// Die Gegenprobe ist der eigentliche Punkt: `400` ist ein Formatfehler,
    /// `401`/`403` sind Autorisierungsfehler und `409` ist der Fork — keiner
    /// von ihnen wird durch Wiederholen besser, und `design.md`:1584 verbietet
    /// ausdruecklich, sie automatisch zu uebergehen.
    #[test]
    fn only_server_side_failures_are_automatically_retried() {
        for status in [500_u16, 502, 503, 504, 599] {
            assert!(is_automatically_retried(status), "{status} ist 5xx");
        }
        for status in [200_u16, 201, 400, 401, 403, 404, 409, 412, 422, 429, 600] {
            assert!(
                !is_automatically_retried(status),
                "{status} darf NICHT automatisch wiederholt werden"
            );
        }
    }
}
