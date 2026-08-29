//! Die Kulisse der Writer-Sync-Tests.
//!
//! Drei Zusagen tragen dieses Modul:
//!
//! 1. **Echte Archivbytes.** Der Bestand entsteht ueber die per `#[path]`
//!    eingebundene [`WriterHarness`] aus `crates/ea-writer/tests/support/mod.rs`
//!    — eine echte Registrierungslinie, ein echtes `.eip`, echte `.eag`. Eine
//!    zweite Fixture waere eine zweite Quelle derselben Linie, und eine von
//!    beiden waere zufaellig die falsche.
//! 2. **Der Server ist eine ATTRAPPE, das Protokoll nicht.** [`FakeServer`]
//!    ersetzt nur den Transport; jeder Request, den er sieht, ist mit dem
//!    echten [`ea_sync_protocol::RequestSigner`] signiert und traegt die
//!    Kopfzeilen des Profils.
//! 3. **Kein Testpfad in die Produktionsflaeche.** Der Zaehler und die
//!    hinterlegte Antwort liegen HIER und nicht in `ea-sync-client`.
#![allow(dead_code)]

#[path = "../../../ea-writer/tests/support/mod.rs"]
pub mod writer_support;

use std::sync::{
    Arc, Mutex, PoisonError,
    atomic::{AtomicUsize, Ordering},
};

use ea_archive::{
    ArchiveBackendError, ArchiveBackendProfileV1, ArchivePath, BoundArchiveProfilePolicyV1,
    ControlledNetworkProfileV1,
};
use ea_archive_fs::{PublicationQueue, PublicationTargetV1, SyncStatus};
use ea_sync_client::{
    PushSummary, SyncClient, SyncClientError, SyncTransportV1, TransportErrorV1,
    TransportRequestV1, TransportResponseV1,
};
use writer_support::{WriterHarness, valid_incident};

/// Das kontrollierte Netzprofil der Sync-Tests.
///
/// Es steht HIER und nicht in der Writer-Fixture: jene konfiguriert einen
/// LOKALEN Ausgabepfad, und `design.md` §11.5 fuehrt beide Profile
/// nebeneinander. Die drei Wiederaufnahmezahlen sind der Grund, warum dieses
/// Profil ueberhaupt in dieser Datei steht — die Schranke der begrenzten
/// Wiederaufnahme kommt aus dem PROFIL und nicht aus einer Konstante des
/// Klienten.
#[must_use]
pub fn controlled_network_profile() -> ArchiveBackendProfileV1 {
    ArchiveBackendProfileV1::ControlledNetworkPath(ControlledNetworkProfileV1 {
        filesystem_row_id: "fixture-sync-fs".to_owned(),
        protocol_id: "smb3".to_owned(),
        server_product: "fixture-nas".to_owned(),
        server_version: "1.0.0".to_owned(),
        mount_options: vec!["nobrl".to_owned(), "vers=3.1.1".to_owned()],
        failover_config_id: "fixture-failover".to_owned(),
        capability_test_vector_id: "cap-v1-sync".to_owned(),
        queue_max_objects: 64,
        queue_max_bytes: 16 * 1024 * 1024,
        resume_backoff_initial_ms: 10,
        resume_backoff_max_ms: 100,
        resume_max_attempts: 3,
    })
}

/// Dasselbe Profil mit einer Queuegrenze von GENAU EINEM Objekt.
///
/// Der einzige Weg zum oeffentlichen Zustand `Fehler`, den ein Bestand aus
/// eigener Kraft erreicht: der Publikationsplan eines Eintrags traegt seine
/// Grants UND das `.eip`, also mindestens zwei Objekte.
#[must_use]
pub fn controlled_network_profile_with_a_single_object_bound() -> ArchiveBackendProfileV1 {
    let ArchiveBackendProfileV1::ControlledNetworkPath(mut profile) = controlled_network_profile()
    else {
        unreachable!("die Fixture baut ein kontrolliertes Netzprofil");
    };
    profile.filesystem_row_id = "fixture-sync-fs-tight".to_owned();
    profile.queue_max_objects = 1;
    ArchiveBackendProfileV1::ControlledNetworkPath(profile)
}

/// Die wirksame Zulassung, die dieses Profil traegt.
///
/// Sie entsteht aus der ECHTEN Policy des gewaehlten Registrierungskopfs, mit
/// der einen ergaenzten Zulassung. Eine daneben gebaute Policy waere eine
/// zweite Quelle derselben Aussage — und alle uebrigen Felder waeren dann
/// erfundene Werte statt der gebundenen.
#[must_use]
pub fn policy_allowing_the_network_profile(
    head: &ea_trust::SelectedRegistryHead,
) -> BoundArchiveProfilePolicyV1 {
    let mut policy = head.policy_fields().clone();
    for profile in [
        controlled_network_profile(),
        controlled_network_profile_with_a_single_object_bound(),
    ] {
        policy.allowed_archive_profile_hashes.push(
            profile
                .profile_hash()
                .expect("das Netzprofil muss hashbar sein"),
        );
    }
    BoundArchiveProfilePolicyV1::from_policy(&policy)
}

/// Das Publikationsziel der Tests — mit SCHALTBARER Erreichbarkeit.
pub struct SwitchableTarget {
    connected: Mutex<bool>,
    published: Mutex<Vec<(String, Vec<u8>)>>,
}

impl SwitchableTarget {
    #[must_use]
    pub fn new(connected: bool) -> Self {
        Self {
            connected: Mutex::new(connected),
            published: Mutex::new(Vec::new()),
        }
    }

    /// Die tatsaechlich veroeffentlichten Adressen, in Reihenfolge.
    #[must_use]
    pub fn published_order(&self) -> Vec<String> {
        self.published
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(path, _)| path.clone())
            .collect()
    }

    /// Die tatsaechlich veroeffentlichten Bytes, in derselben Reihenfolge.
    #[must_use]
    pub fn published_bytes(&self) -> Vec<Vec<u8>> {
        self.published
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(_, bytes)| bytes.clone())
            .collect()
    }

    pub fn connect(&self) {
        *self
            .connected
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = true;
    }
}

impl PublicationTargetV1 for SwitchableTarget {
    fn is_connected(&self) -> bool {
        *self
            .connected
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn reconnect(&self) {
        self.connect();
    }

    fn publish_one(&self, relative: &ArchivePath, bytes: &[u8]) -> Result<(), ArchiveBackendError> {
        if !self.is_connected() {
            return Err(ArchiveBackendError::Io);
        }
        self.published
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((relative.as_str().to_owned(), bytes.to_vec()));
        Ok(())
    }
}

/// Ein Adapter, damit `PublicationQueue` das Ziel BESITZT und die Tests es
/// weiter beobachten koennen.
struct SharedTarget(Arc<SwitchableTarget>);

impl PublicationTargetV1 for SharedTarget {
    fn is_connected(&self) -> bool {
        self.0.is_connected()
    }

    fn reconnect(&self) {
        self.0.reconnect();
    }

    fn publish_one(&self, relative: &ArchivePath, bytes: &[u8]) -> Result<(), ArchiveBackendError> {
        self.0.publish_one(relative, bytes)
    }
}

/// Was die Attrappe auf einen Commit antwortet.
#[derive(Clone)]
pub enum CommitReplyV1 {
    /// Genau diese Quittungsbytes, gerahmt als `entry-commit-response-v1` und
    /// mit HTTP 200. Der RAHMEN ist echt und die Quittung darin ist die
    /// hinterlegte — genau so antwortet der Dienst auch.
    Receipt(Vec<u8>),
    /// Derselbe Rahmen mit dem Ausgang `idempotentReplay`.
    IdempotentReplay(Vec<u8>),
    /// Die Leitung reisst ab — ein Fall fuer die begrenzte Wiederaufnahme.
    Unreachable,
    /// Der Dienst antwortet mit einem 5xx.
    ServerError(u16),
    /// Ein `protocol-error-v1` mit genau diesem Code — NICHT wiederholbar.
    ProtocolError(u16, String),
}

/// Der Sync-Server als Attrappe.
pub struct FakeServer {
    commit_calls: AtomicUsize,
    challenge_calls: AtomicUsize,
    reply: Mutex<CommitReplyV1>,
    /// Jeder Rumpf, den die Attrappe an ihrem Commit-Endpunkt gesehen hat.
    seen_commit_bodies: Mutex<Vec<Vec<u8>>>,
    /// Jede Nonce, mit der ein Commit signiert war.
    seen_nonces: Mutex<Vec<[u8; 32]>>,
    /// Jeder Zielpfad, unter dem ein Commit ankam.
    seen_targets: Mutex<Vec<String>>,
    /// Die Antworten, die vor `reply` der Reihe nach ausgegeben werden.
    scripted: Mutex<Vec<CommitReplyV1>>,
}

impl FakeServer {
    #[must_use]
    pub fn new(reply: CommitReplyV1) -> Self {
        Self {
            commit_calls: AtomicUsize::new(0),
            challenge_calls: AtomicUsize::new(0),
            reply: Mutex::new(reply),
            seen_commit_bodies: Mutex::new(Vec::new()),
            seen_nonces: Mutex::new(Vec::new()),
            seen_targets: Mutex::new(Vec::new()),
            scripted: Mutex::new(Vec::new()),
        }
    }

    /// Die Zahl der Commit-Aufrufe. `0` ist die Zusage von `design.md` §9.3
    /// Schritt 12: vor der Netzarchivpublikation findet KEIN Serverupload statt.
    #[must_use]
    pub fn commit_calls(&self) -> usize {
        self.commit_calls.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn challenge_calls(&self) -> usize {
        self.challenge_calls.load(Ordering::SeqCst)
    }

    /// Legt die Quittung fest, die der naechste Commit zurueckbekommt.
    pub fn return_receipt(&self, bytes: Vec<u8>) {
        *self.reply.lock().unwrap_or_else(PoisonError::into_inner) = CommitReplyV1::Receipt(bytes);
    }

    /// Legt die Antworten der naechsten Aufrufe der Reihe nach fest.
    pub fn script(&self, replies: Vec<CommitReplyV1>) {
        let mut scripted = self.scripted.lock().unwrap_or_else(PoisonError::into_inner);
        *scripted = replies;
        scripted.reverse();
    }

    /// Die Rumpfbytes jedes gesehenen Commits.
    #[must_use]
    pub fn seen_commit_bodies(&self) -> Vec<Vec<u8>> {
        self.seen_commit_bodies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Jede Nonce, mit der ein Commit signiert war.
    #[must_use]
    pub fn seen_nonces(&self) -> Vec<[u8; 32]> {
        self.seen_nonces
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Jeder Zielpfad, unter dem ein Commit ankam.
    #[must_use]
    pub fn seen_targets(&self) -> Vec<String> {
        self.seen_targets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn next_reply(&self) -> CommitReplyV1 {
        self.scripted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()
            .unwrap_or_else(|| {
                self.reply
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone()
            })
    }
}

#[ea_sync_client::async_trait]
impl SyncTransportV1 for FakeServer {
    async fn send(
        &self,
        request: TransportRequestV1,
    ) -> Result<TransportResponseV1, TransportErrorV1> {
        if request.target.ends_with("/auth/challenges") {
            let count = self.challenge_calls.fetch_add(1, Ordering::SeqCst);
            // Eine FRISCHE Nonce je Aufruf, aus dem Zaehler abgeleitet: sie
            // muss sich unterscheiden, damit `seen_nonces` ueberhaupt etwas
            // messen kann.
            let mut nonce = [0_u8; 32];
            nonce[..8].copy_from_slice(&(count as u64 + 1).to_be_bytes());
            // GERAHMT wie beim Dienst. Die Attrappe lieferte hier einmal die
            // 32 Byte roh, und der Klient trug dafuer einen zweiten,
            // nachsichtigen Zweig — ein Testpfad in der Produktionsflaeche.
            // Jetzt laeuft der Zeuge durch denselben `ChallengeResponseV1`,
            // den der Dienst schickt, und der Klient hat nur noch einen Weg.
            return Ok(TransportResponseV1 {
                status: 200,
                body: challenge_response_bytes(nonce),
            });
        }

        // Der SIGNIERTE Zielpfad, wie die Gegenstelle ihn sieht. Er wird
        // aufgezeichnet, weil die Signatur `@target-uri` abdeckt: ein falscher
        // Pfad ist keine stille Fehladressierung, sondern eine Signatur ueber
        // eine andere Ressource — und ohne diese Zeile faende kein Zeuge das.
        self.seen_targets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(request.target.clone());
        self.commit_calls.fetch_add(1, Ordering::SeqCst);
        self.seen_commit_bodies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(request.body.clone());
        self.seen_nonces
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(request.nonce);

        match self.next_reply() {
            CommitReplyV1::Receipt(bytes) => Ok(TransportResponseV1 {
                status: 200,
                body: framed(ea_sync_protocol::EntryCommitOutcome::Accepted, bytes),
            }),
            CommitReplyV1::IdempotentReplay(bytes) => Ok(TransportResponseV1 {
                status: 200,
                body: framed(
                    ea_sync_protocol::EntryCommitOutcome::IdempotentReplay,
                    bytes,
                ),
            }),
            CommitReplyV1::Unreachable => Err(TransportErrorV1::Unreachable),
            CommitReplyV1::ServerError(status) => Ok(TransportResponseV1 {
                status,
                body: Vec::new(),
            }),
            CommitReplyV1::ProtocolError(status, code) => Ok(TransportResponseV1 {
                status,
                body: code.into_bytes(),
            }),
        }
    }
}

/// Der Aufbau EINES Writer-Sync-Laufs.
pub struct SyncHarness {
    writer: WriterHarness,
    pub server: Arc<FakeServer>,
    pub target: Option<Arc<SwitchableTarget>>,
    queue: Option<Arc<PublicationQueue>>,
    last: Option<PushSummary>,
    /// Wie weit die beobachtete Uhr gegenueber der Fixture vorgerueckt ist.
    ///
    /// Die begrenzte Wiederaufnahme wartet WIRKLICH: nach einem vergeblichen
    /// Versuch liegt der naechste Zeitpunkt in der Zukunft, und ein zweiter
    /// Lauf auf derselben Uhr fasst die Leitung zu Recht nicht an. Ein Test,
    /// der zwei Versuche messen will, muss die Uhr also vorstellen — und tut
    /// das ausdruecklich, statt zu schlafen.
    clock_offset_ms: i64,
    /// Der Ausgang des ersten Abschlusses — die Checkpoint-Aussage, die ein
    /// zweiter Eintrag braucht, haengt an ihm.
    first: ea_writer::FinalizeOutcome,
}

impl SyncHarness {
    /// Ein LOKALES Profil mit genau einem committeten Eintrag.
    pub async fn new() -> Self {
        Self::build(None).await
    }

    /// Ein KONTROLLIERTES NETZPROFIL, dessen Ziel gerade nicht erreichbar ist.
    pub async fn controlled_network_disconnected() -> Self {
        Self::build(Some(false)).await
    }

    /// Dasselbe Netzprofil mit erreichbarem Ziel.
    pub async fn controlled_network_connected() -> Self {
        Self::build(Some(true)).await
    }

    /// Ein LOKALES Profil, dessen Linie ein Serverquittungszertifikat traegt.
    ///
    /// Die einzige Kulisse, in der eine Quittung ueberhaupt BESTAETIGT werden
    /// kann: Gate `receipt` verlangt die Capability `serverReceipt`.
    pub async fn with_server_receipt_certificate() -> Self {
        Self::build_with(None, true).await
    }

    /// Dieselbe Linie mit erreichbarem Netzarchiv.
    pub async fn controlled_network_with_server_receipt_certificate() -> Self {
        Self::build_with(Some(true), true).await
    }

    async fn build(network: Option<bool>) -> Self {
        Self::build_with(network, false).await
    }

    /// Ein Bestand mit ZWEI committeten, noch nicht hochgeladenen Eintraegen.
    ///
    /// Die einzige Kulisse, in der sich die Reihenfolgezusage von
    /// `push_pending` ueberhaupt messen laesst: mit genau einem anstehenden
    /// Eintrag sind Abbrechen und Ueberspringen nicht zu unterscheiden.
    pub async fn with_two_pending_entries() -> Self {
        let harness = Self::build(None).await;
        harness.writer.finalize_a_second_entry(&harness.first);
        harness
    }

    /// Ein Netzprofil, dessen Queuegrenze der Plan eines Eintrags ueberschreitet.
    pub async fn controlled_network_with_a_single_object_bound() -> Self {
        let mut harness = Self::build_with(Some(true), false).await;
        let target = Arc::new(SwitchableTarget::new(true));
        harness.queue = Some(Arc::new(
            PublicationQueue::new(
                Box::new(SharedTarget(Arc::clone(&target))),
                controlled_network_profile_with_a_single_object_bound(),
                &policy_allowing_the_network_profile(harness.writer.head()),
            )
            .expect("die Warteschlange des engen Profils muss stehen"),
        ));
        harness.target = Some(target);
        harness
    }

    /// Der Zielpfad, unter dem ein Commit dieser Kette ankommen MUSS.
    ///
    /// Aus der VORLAGE des Endpunkts gebildet, genau wie im Klienten — der
    /// Zeuge vergleicht damit zwei Wege zu derselben Adresse und nicht eine
    /// Adresse mit sich selbst.
    #[must_use]
    pub fn expected_commit_target(&self) -> String {
        let chain = self
            .writer
            .binding()
            .chain_id
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        ea_sync_protocol::EndpointV1::EntryCommits
            .path_template()
            .replace("{chainId}", &chain)
    }

    async fn build_with(network: Option<bool>, server_receipt_certificate: bool) -> Self {
        let writer = WriterHarness::with_variant(writer_support::LineVariantV1 {
            with_server_receipt_certificate: server_receipt_certificate,
            ..writer_support::LineVariantV1::default()
        });
        let first = writer.finalize_once();
        if server_receipt_certificate {
            // Der Bestand bekommt seine VERTRAUENSABLAGE. Ohne sie waehlt der
            // volle Verifizierer keinen Registrierungskopf, meldet null
            // Objektergebnisse — und keine Quittung koennte je bestaetigt
            // werden. Die uebrigen Kulissen lassen sie AUS: sie messen den
            // Bestand, den der Writer selbst geschrieben hat.
            writer.materialize_trust_objects();
        }
        let target = network.map(|connected| Arc::new(SwitchableTarget::new(connected)));
        let queue = target.as_ref().map(|target| {
            Arc::new(
                PublicationQueue::new(
                    Box::new(SharedTarget(Arc::clone(target))),
                    controlled_network_profile(),
                    &policy_allowing_the_network_profile(writer.head()),
                )
                .expect("die Warteschlange des Netzprofils muss stehen"),
            )
        });
        Self {
            writer,
            server: Arc::new(FakeServer::new(CommitReplyV1::Unreachable)),
            target,
            queue,
            last: None,
            clock_offset_ms: 0,
            first,
        }
    }

    /// Stellt die beobachtete Uhr vor.
    pub const fn advance(&mut self, millis: i64) {
        self.clock_offset_ms += millis;
    }

    /// Die beobachtete Uhr dieses Laufs.
    #[must_use]
    pub const fn observed_now(&self) -> ea_types::UnixMillis {
        ea_types::UnixMillis::new(self.writer.observed_now().get() + self.clock_offset_ms)
    }

    /// Ein FRISCH gebauter Klient — jeder Aufruf ist ein Neustart.
    ///
    /// Der Klient teilt zwischen zwei Aufrufen KEIN Feld: die Warteschlange
    /// entsteht jedes Mal neu aus committeten Archivbytes, und dauerhaft ist
    /// allein der Wiederaufnahmezustand in der lokalen Ablage. Genau diese
    /// Zusage misst `resume.rs`.
    fn client(&self) -> SyncClient {
        let ArchiveBackendProfileV1::ControlledNetworkPath(profile) = controlled_network_profile()
        else {
            unreachable!("die Fixture baut ein kontrolliertes Netzprofil");
        };
        SyncClient::new(ea_sync_client::SyncClientConfigV1 {
            backend: self.writer.backend_handle(),
            anchor_bytes: self.writer.anchor_bytes(),
            network: self.queue.clone(),
            transport: Arc::clone(&self.server) as Arc<dyn SyncTransportV1>,
            signer: Arc::new(ea_sync_protocol::RequestSigner::from_secret(
                ea_crypto::SecretBytes::new([0x77; 32]),
            )),
            organization_id: writer_support::trust_support::organization(),
            chain_id: self.writer.binding().chain_id,
            authority: "sync.einsatzarchiv.test".to_owned(),
            database: self.writer.database(),
            // Die Schranken kommen aus dem PROFIL. Eine Konstante hier waere
            // eine zweite Wahrheit neben `resume_max_attempts`.
            retry: ea_types::RetryConfig::new(
                u8::try_from(profile.resume_max_attempts).expect("die Schranke passt in ein u8"),
                profile.resume_backoff_initial_ms,
                profile.resume_backoff_max_ms,
            )
            .expect("die Schranken des Profils sind nicht null"),
            max_resume_attempts: u16::try_from(profile.resume_max_attempts)
                .expect("die Schranke passt in ein u16"),
            observed_now: self.observed_now(),
        })
        .expect("der Klient muss stehen")
    }

    /// Schiebt die anstehenden Eintraege.
    pub async fn push_pending(&mut self) -> Result<PushSummary, SyncClientError> {
        let outcome = self.client().push_pending(16).await;
        if let Ok(summary) = &outcome {
            self.last = Some(summary.clone());
        }
        outcome
    }

    /// Der oeffentliche Zustand des letzten Laufs.
    #[must_use]
    pub fn status(&self) -> SyncStatus {
        self.last
            .as_ref()
            .map_or(SyncStatus::LocallySaved, PushSummary::status)
    }

    /// Der Oberflaechentext der Detailursache — leer, wenn keine anliegt.
    #[must_use]
    pub fn detail(&self) -> &'static str {
        self.last
            .as_ref()
            .and_then(PushSummary::detail_cause)
            .map_or("", ea_archive_fs::DetailCause::label)
    }

    /// Die im LOKALEN Bestand liegenden Quittungen.
    #[must_use]
    pub fn local_receipt_paths(&self) -> Vec<String> {
        self.writer
            .backend()
            .relative_paths_below_for_test("receipts/")
            .into_iter()
            .filter(|path| path.ends_with(".esr"))
            .collect()
    }

    /// Die Bytes der einen lokal abgelegten Quittung.
    #[must_use]
    pub fn local_receipt_bytes(&self) -> Option<Vec<u8>> {
        let paths = self.local_receipt_paths();
        let path = paths.first()?;
        self.writer.backend().read_for_test(path)
    }

    #[must_use]
    pub fn writer(&self) -> &WriterHarness {
        &self.writer
    }

    /// Die Bytes einer ECHTEN Serverquittung auf diesen Eintrag.
    ///
    /// # Panics
    ///
    /// Wenn die Linie kein Serverquittungszertifikat traegt.
    #[must_use]
    pub fn genuine_receipt(&self, entry: &ea_sync_client::PendingEntryV1) -> Vec<u8> {
        genuine_receipt_bytes(&self.writer, entry)
    }

    /// Legt eine FORMGUELTIGE, aber unpruefbare `.esr` in den Bestand.
    ///
    /// Sie traegt das Exact-Object-Praefix einer Quittung, dekodiert
    /// anstandslos und zeigt auf DIESEN Eintrag — nur ihre Serversignatur
    /// stammt von einem Schluessel, den die Registrierungslinie nicht kennt.
    /// Genau so sieht die Faelschung aus, gegen die die Ableitung sich wehren
    /// muss: das Inventar klassifiziert am Praefix, und `esr::parse_body`
    /// prueft Gestalt und Content Type, aber weder Signatur noch Bindung.
    ///
    /// # Panics
    ///
    /// Wenn die Bytes sich nicht bauen oder nicht ablegen lassen.
    pub fn plant_unverifiable_local_receipt(&self, entry: &ea_sync_client::PendingEntryV1) {
        let bytes = forged_receipt_bytes(&self.writer, entry);
        let name = {
            let hash = ea_crypto::object_hash(&bytes);
            let mut text = String::with_capacity(68);
            for byte in hash.as_bytes() {
                text.push_str(&format!("{byte:02x}"));
            }
            text.push_str(".esr");
            text
        };
        self.writer
            .backend()
            .materialize_for_test(&format!("receipts/{name}"), &bytes);
    }

    /// Der Objekthash des einen anstehenden Eintrags.
    pub async fn pending_entry_object_hash(&self) -> Option<ea_types::ObjectHash> {
        self.pending_entry()
            .await
            .as_ref()
            .map(ea_sync_client::PendingEntryV1::entry_object_hash)
    }

    /// Die Zahl der anstehenden Eintraege.
    pub async fn pending_count(&self) -> usize {
        let backend = self.writer.backend_handle();
        let anchor_bytes = self.writer.anchor_bytes();
        let observed_now = self.observed_now();
        tokio::task::spawn_blocking(move || {
            let anchor =
                ea_trust::decode_trust_anchor(&anchor_bytes).expect("der Anker muss dekodieren");
            ea_sync_client::SyncQueueV1::derive(&backend.as_archive_source(), &anchor, observed_now)
                .expect("die Ableitung muss tragen")
                .pending()
                .len()
        })
        .await
        .expect("der Blockierthread darf nicht verlorengehen")
    }

    /// Der eine anstehende Eintrag, so wie die Ableitung ihn sieht.
    pub async fn pending_entry(&self) -> Option<ea_sync_client::PendingEntryV1> {
        let backend = self.writer.backend_handle();
        let anchor_bytes = self.writer.anchor_bytes();
        let observed_now = self.observed_now();
        tokio::task::spawn_blocking(move || {
            let anchor = ea_trust::decode_trust_anchor(&anchor_bytes).ok()?;
            ea_sync_client::SyncQueueV1::derive(&backend.as_archive_source(), &anchor, observed_now)
                .ok()?
                .pending()
                .first()
                .cloned()
        })
        .await
        .expect("der Blockierthread darf nicht verlorengehen")
    }

    /// Der dauerhafte Wiederaufnahmezustand eines Eintrags.
    ///
    /// # Panics
    ///
    /// Wenn die lokale Ablage ihn nicht hergibt.
    #[must_use]
    pub fn retry_schedule(&self, entry: ea_types::ObjectHash) -> ea_sync_client::RetryScheduleV1 {
        ea_sync_client::RetryStore::open(
            self.writer.database(),
            ea_types::RetryConfig::new(3, 10, 100).expect("die Schranken sind nicht null"),
            3,
        )
        .expect("die Wiederaufnahmeablage muss stehen")
        .load(entry)
        .expect("der Wiederaufnahmezustand muss lesbar sein")
    }

    /// Der bestaetigte Cursor, gelesen von einem FRISCH gebauten Klienten.
    #[must_use]
    pub fn resume_cursor(&self, entry: ea_types::ObjectHash) -> Option<Vec<u8>> {
        self.client()
            .resume_cursor(entry)
            .expect("der Wiederaufnahmezustand muss lesbar sein")
    }

    /// Bucht einen ECHTEN, signierten Cursor und gibt seine Tokenbytes heraus.
    ///
    /// Ein echter [`ea_sync_protocol::TechnicalCursorV1`] und keine erfundenen
    /// Bytes: der Klient nimmt nur signierte Cursor an, und ein Test mit
    /// Zufallsbytes pruefte einen Weg, den es nicht gibt.
    ///
    /// # Panics
    ///
    /// Wenn der Cursor nicht ausgestellt oder nicht gebucht werden kann.
    pub fn record_demo_cursor(&self, entry: ea_types::ObjectHash) -> Vec<u8> {
        let cursor = ea_sync_protocol::TechnicalCursorV1::issue(
            &ea_sync_protocol::TechnicalCursorFieldsV1 {
                organization_id: writer_support::trust_support::organization(),
                endpoint: ea_sync_protocol::EndpointV1::ChainEntries,
                chain_id: Some(self.writer.binding().chain_id),
                start_head_entry_hash: None,
                last_technical_index: 1,
                expires_at: ea_types::UnixMillis::new(self.writer.observed_now().get() + 600_000),
                nonce: [0x5c; 16],
            },
            &FixtureCursorSigner,
        )
        .expect("der Cursor der Fixture muss ausstellbar sein");
        let token = cursor.token_bytes().to_vec();
        self.client()
            .record_resume_cursor(entry, &cursor)
            .expect("der Cursor muss buchbar sein");
        token
    }
}

/// Die Felder EINER Quittung auf diesen Eintrag, aus dem committeten `.eip`.
///
/// Die fuenf Bindungen aus `design.md` §14.1 Schritt 7 — `entryHash`,
/// `chainSequence`, `registryVersion`, `registryHeadHash` und
/// `initialGrantPlanHash` — werden AUS DEM MANIFEST gelesen und nicht daneben
/// gebaut. Eine Fixture, die sie selbst zusammensetzt, prueft am Ende sich
/// selbst; so gelesen halten sie per Konstruktion, und was der Test misst, ist
/// die SIGNATUR.
fn receipt_fields_for(
    writer: &WriterHarness,
    entry: &ea_sync_client::PendingEntryV1,
    server_certificate_hash: ea_types::CertificateHash,
    server_key_thumbprint: ea_types::KeyThumbprint,
) -> ea_format::ReceiptCoreFieldsV1 {
    let ea_format::ParsedArchiveObject::Entry(parsed) =
        ea_format::decode_exact_object(entry.entry_bytes())
            .expect("das committete .eip muss dekodieren")
    else {
        unreachable!("ein committetes .eip ist ein Eintragspaket");
    };
    let manifest = parsed.value().manifest().fields();
    ea_format::ReceiptCoreFieldsV1 {
        organization_id: manifest.organization_id,
        chain_id: manifest.chain_id,
        chain_sequence: manifest.chain_sequence,
        entry_hash: entry.entry_hash(),
        entry_object_hash: entry.entry_object_hash(),
        previous_entry_hash: manifest.previous_entry_hash,
        registry_version: manifest.registry_version,
        registry_head_hash: ea_types::Hash32::try_from(&manifest.registry_head_hash[..])
            .expect("32 Byte sind ein Hash"),
        // NICHT gebunden (`receipt_bindings_hold` laesst ihn ausdruecklich
        // aus): ein fester Fuellwert, damit die Fixture ihn nicht aus dem Kopf
        // zieht und am Ende sich selbst prueft.
        policy_object_hash: ea_types::ObjectHash::try_from(&[0x44_u8; 32][..])
            .expect("32 Byte sind ein Objekthash"),
        initial_grant_plan_hash: ea_types::Hash32::try_from(&manifest.initial_grant_plan_hash[..])
            .expect("32 Byte sind ein Hash"),
        initial_grant_object_hashes: {
            let mut hashes: Vec<ea_types::ObjectHash> = entry
                .grant_bytes()
                .iter()
                .map(|bytes| ea_crypto::object_hash(bytes))
                .collect();
            hashes.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
            hashes
        },
        accepted_at_server: writer.observed_now(),
        evidence_due_at: None,
        server_key_thumbprint,
        server_certificate_hash,
    }
}

/// Kodiert Kern und Signatur zu den exakten `.esr`-Objektbytes.
fn encode_receipt_bytes(core: ea_format::ReceiptCoreV1, signature: Vec<u8>) -> Vec<u8> {
    ea_format::encode_receipt(
        &ea_format::ReceiptV1::new(core, signature).expect("die Quittung muss binden"),
    )
    .expect("die Objektbytes muessen entstehen")
    .into_vec()
}

/// Eine ECHTE Serverquittung dieser Linie.
///
/// Der Signierer ist der Schluessel, auf den die Registrierungslinie ihre
/// Geraetezertifikate ausstellt, und das Zertifikat ist das der Art
/// `ServerReceipt`. Die ROLLE kommt vom Zertifikat und nicht vom Schluessel —
/// dieselbe Aufteilung wie in `crates/ea-verify/tests/support`.
///
/// # Panics
///
/// Wenn die Linie kein Serverquittungszertifikat traegt.
fn genuine_receipt_bytes(
    writer: &WriterHarness,
    entry: &ea_sync_client::PendingEntryV1,
) -> Vec<u8> {
    let certificate = writer
        .server_receipt_certificate_hash()
        .expect("diese Kulisse verlangt ein Serverquittungszertifikat");
    let signer = writer_support::trust_support::authorized_device_signer();
    let fields = receipt_fields_for(
        writer,
        entry,
        ea_types::CertificateHash::from(certificate),
        writer_support::trust_support::authorized_device_signing_key_thumbprint(),
    );
    let core = ea_format::ReceiptCoreV1::new(fields).expect("der Quittungskern muss entstehen");
    let signature = signer
        .sign_receipt(core.exact_bytes())
        .expect("der Fixture-Server muss signieren");
    encode_receipt_bytes(core, signature)
}

/// Eine formgueltige `.esr` mit einer Signatur, die niemand bestaetigt.
///
/// Sie traegt das Exact-Object-Praefix einer Quittung, dekodiert anstandslos
/// und zeigt auf DIESEN Eintrag — nur ihr Signaturschluessel ist einer, den
/// die Registrierungslinie nicht fuehrt. Genau so sieht die Faelschung aus,
/// gegen die die Ableitung sich wehren muss: das Inventar klassifiziert am
/// Praefix, und `esr::parse_body` prueft Gestalt und Content Type, aber weder
/// Signatur noch Bindung.
fn forged_receipt_bytes(writer: &WriterHarness, entry: &ea_sync_client::PendingEntryV1) -> Vec<u8> {
    let signer = ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new([0x9e; 32]));
    let certificate_hash = ea_types::CertificateHash::try_from(&[0x77_u8; 32][..])
        .expect("32 Byte sind ein Zertifikatshash");
    let fields = receipt_fields_for(
        writer,
        entry,
        certificate_hash,
        signer
            .public_key()
            .expect("der oeffentliche Punkt ist gueltig")
            .thumbprint(),
    );
    let core = ea_format::ReceiptCoreV1::new(fields).expect("der Quittungskern muss entstehen");
    let signature = signer
        .sign_receipt(core.exact_bytes())
        .expect("die Signatur der Fixture muss entstehen");
    encode_receipt_bytes(core, signature)
}

/// Rahmt eine Nonce als `challenge-response-v1`, so wie der Dienst es tut.
///
/// Mit dem ECHTEN Kern und der ECHTEN COSE-Signatur: `ChallengeResponseV1::new`
/// prueft Profil, Content Type und die Bindung der Signatur an genau diesen
/// Kern, und eine von Hand gebaute Bytefolge kaeme daran nicht vorbei.
fn challenge_response_bytes(nonce: [u8; 32]) -> Vec<u8> {
    let signer = ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new([0x3d; 32]));
    let certificate_hash = ea_types::CertificateHash::try_from(&[0x52_u8; 32][..])
        .expect("32 Byte sind ein Zertifikatshash");
    let core = ea_crypto::ChallengeResponseCoreV1 {
        organization_id: writer_support::trust_support::organization(),
        nonce,
        issued_at_server: ea_types::UnixMillis::new(1),
        expires_at: ea_types::UnixMillis::new(300_001),
        server_certificate_hash: certificate_hash,
    };
    let exact_core =
        ea_crypto::encode_challenge_response_core(&core).expect("der Kern muss kodieren");
    let signature = signer
        .sign_challenge_response(&exact_core)
        .expect("die Attrappe muss signieren");
    ea_sync_protocol::ChallengeResponseV1::new(core, &signature)
        .expect("die Challenge-Antwort muss rahmen")
        .exact_bytes()
        .to_vec()
}

/// Rahmt Quittungsbytes so, wie der Dienst sie ausliefert.
///
/// Der Rahmen entsteht mit dem ECHTEN [`ea_sync_protocol::EntryCommitResponseV1`]
/// und nicht von Hand: eine Attrappe, die ihren eigenen Rahmen baut, pruefte
/// den Klienten gegen eine zweite Auslegung derselben Leitung.
fn framed(outcome: ea_sync_protocol::EntryCommitOutcome, receipt_bytes: Vec<u8>) -> Vec<u8> {
    ea_sync_protocol::EntryCommitResponseV1::new(outcome, receipt_bytes, None)
        .exact_bytes()
        .to_vec()
}

/// Der Cursorsignierer der Fixture — ein ECHTES Ed25519-Paar.
///
/// Der Klient nimmt nur einen ausgestellten [`ea_sync_protocol::TechnicalCursorV1`]
/// an; erfundene Tokenbytes prueften einen Weg, den es nicht gibt.
struct FixtureCursorSigner;

impl ea_sync_protocol::TechnicalCursorSigner for FixtureCursorSigner {
    fn sign_technical_cursor_digest(
        &self,
        digest: ea_types::Hash32,
    ) -> Result<Vec<u8>, ea_crypto::CryptoError> {
        use ed25519_dalek::Signer as _;
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x31; 32]);
        Ok(key.sign(digest.as_bytes()).to_bytes().to_vec())
    }
}

/// Die Bytes, gegen die die Tests messen.
pub mod fixtures {
    /// Eine Quittung, die KEINE ist.
    ///
    /// Sie ist mit Absicht nicht bloss falsch signiert, sondern gar kein
    /// `.esr`: der Klient muss sie schon am Exact-Object-Praefix abweisen, und
    /// damit misst der Zeuge die Abweisung und nicht die Bytelaenge.
    #[must_use]
    pub fn bad_receipt() -> Vec<u8> {
        b"nicht einmal ein Archivobjekt".to_vec()
    }
}

/// Kurzform fuer die Einsatzeingabe der Fixture.
#[must_use]
pub fn incident() -> ea_writer::FinalizationInputV1 {
    valid_incident()
}
