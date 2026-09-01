//! Die Kulisse des inkrementellen Reader-Syncs.
//!
//! Drei Zusagen tragen dieses Modul, und alle drei sind dieselben, die
//! `crates/ea-sync-client/tests/support/mod.rs` fuer die Schreiberseite
//! trifft:
//!
//! 1. **Echte Archivbytes.** Der Bestand kommt aus dem per `#[path]`
//!    eingebundenen Fixture-Modul von `ea-verify`; hier wird keine zweite
//!    Registrierungslinie gebaut.
//! 2. **Der Server ist eine ATTRAPPE, das Protokoll nicht.** [`ReaderSyncHarness::serve`]
//!    LIEST den Request, den `ReaderSyncService::next_request` herausgegeben
//!    hat, und antwortet mit einem echten `reader-batch-v1`. Ein Rueckkanal am
//!    Request vorbei liesse den Zeugen gruen laufen, ohne dass der Pfad
//!    jemals gebildet worden waere.
//! 3. **Kein Testpfad in die Produktionsflaeche.** Der Bytespeicher, der ab dem
//!    n-ten Objekt `QuotaExceeded` liefert, liegt HIER und nicht in
//!    `ea-reader`.
//!
//! `#[path]`-Includes werden je Testtarget uebersetzt; ein Target, das nur
//! einen Teil der Helfer nutzt, erzeugt sonst `dead_code`-Warnungen, die unter
//! `-D warnings` brechen. Daher `allow(dead_code)` auf Modulebene.
#![allow(dead_code)]

/// Das Fixture-Modul aus `ea-verify`, unveraendert weiterverwendet.
///
/// Es bindet seinerseits das Archiv-, das Trust- und das Formatfixture ein.
/// Hier wird nichts davon nachgebaut — dieselbe Kette von Includes, die
/// `crates/ea-recovery/tests/support/mod.rs` und
/// `crates/ea-archive-fs/tests/support/mod.rs` bereits fahren.
#[path = "../../../ea-verify/tests/support/mod.rs"]
pub mod verify_support;

pub mod fixtures;

use std::cell::RefCell;
use std::rc::Rc;

use ea_reader::{
    ConfirmedCursor, InMemoryReaderBlobStore, ReaderBlobError, ReaderBlobKey, ReaderBlobStore,
    ReaderRequestV1, ReaderSyncError, ReaderSyncFaultPoint, ReaderSyncService, UnlockedVault,
    VerifiedSyncBatch,
};
use ea_types::EntryHash;
use ea_verify::ChainHeadV1;

/// Der Bytespeicher, der ab dem `n`-ten Objekt `QuotaExceeded` liefert.
///
/// Das Modell des zweiten browser-eigenen Abbruchpunktes: die
/// Speicherbereinigung des Browsers bricht einen OPFS-Schreibvorgang ab, und
/// der Port meldet das als `EA-READER-BLOB-HOST`. Er zaehlt OBJEKTE und keine
/// Bytes, weil `ReaderBlobStore::put` je Objekt genau einmal gerufen wird und
/// eine Byteschwelle mitten in einem Aufruf im Port gar nicht darstellbar ist.
pub struct QuotaExceededStore {
    inner: InMemoryReaderBlobStore,
    remaining_writes: RefCell<usize>,
}

impl QuotaExceededStore {
    /// Ein Speicher, der `writes` Schreibvorgaenge annimmt und dann aufhoert.
    #[must_use]
    pub fn new(inner: InMemoryReaderBlobStore, writes: usize) -> Self {
        Self {
            inner,
            remaining_writes: RefCell::new(writes),
        }
    }
}

impl ReaderBlobStore for QuotaExceededStore {
    fn put(&mut self, key: &ReaderBlobKey, bytes: &[u8]) -> Result<(), ReaderBlobError> {
        let mut remaining = self.remaining_writes.borrow_mut();
        if *remaining == 0 {
            return Err(ReaderBlobError::Host("QuotaExceededError".to_owned()));
        }
        *remaining -= 1;
        self.inner.put(key, bytes)
    }

    fn get(&self, key: &ReaderBlobKey) -> Result<Option<Vec<u8>>, ReaderBlobError> {
        self.inner.get(key)
    }

    fn delete(&mut self, key: &ReaderBlobKey) -> Result<(), ReaderBlobError> {
        self.inner.delete(key)
    }

    fn keys(&self) -> Result<Vec<ReaderBlobKey>, ReaderBlobError> {
        self.inner.keys()
    }
}

/// Ein Bytespeicher, der einen Schreibvorgang ANNIMMT und ihn dann vergisst.
///
/// Das Modell des Wirts, der `put` mit `Ok` quittiert und den Blob trotzdem
/// nicht dauerhaft macht — bei OPFS etwa ein Handle, dessen `flush` ins Leere
/// lief. Er ist der einzige Weg, die Rueckleseprobe von `confirm` und
/// `rebuild_from_genesis` von aussen zu treffen: ein Speicher, der ehrlich
/// scheitert, kaeme dort nie an.
///
/// Vergessen wird GENAU EINE Adresse, damit der Zeuge misst, was er misst.
pub struct AmnesiacStore {
    inner: InMemoryReaderBlobStore,
    forgets: &'static str,
}

impl AmnesiacStore {
    #[must_use]
    pub fn new(inner: InMemoryReaderBlobStore, forgets: &'static str) -> Self {
        Self { inner, forgets }
    }
}

impl ReaderBlobStore for AmnesiacStore {
    fn put(&mut self, key: &ReaderBlobKey, bytes: &[u8]) -> Result<(), ReaderBlobError> {
        if key.as_str() == self.forgets {
            return Ok(());
        }
        self.inner.put(key, bytes)
    }

    fn get(&self, key: &ReaderBlobKey) -> Result<Option<Vec<u8>>, ReaderBlobError> {
        self.inner.get(key)
    }

    fn delete(&mut self, key: &ReaderBlobKey) -> Result<(), ReaderBlobError> {
        self.inner.delete(key)
    }

    fn keys(&self) -> Result<Vec<ReaderBlobKey>, ReaderBlobError> {
        self.inner.keys()
    }
}

/// Der Server dieser Kulisse: zwei Seiten und eine leere Antwort.
///
/// Er entscheidet AUS DEM REQUEST und nicht aus einem Zaehler: der Reader
/// nennt seine Position im Pfad, und genau daran haengt, welche Seite er
/// bekommt. Ein Zaehler gaebe die zweite Seite auch dann heraus, wenn der
/// Reader gar nicht weitergeblaettert haette.
#[derive(Clone, Copy, Debug, Default)]
pub struct FakeReaderServer;

impl FakeReaderServer {
    /// Die Antwort auf genau diesen Request.
    #[must_use]
    pub fn answer(self, request: &ReaderRequestV1) -> Vec<u8> {
        let query = request
            .target
            .split_once('?')
            .map_or("", |(_, query)| query);
        let mut after_sequence = 0_u64;
        let mut after_entry_hash = fixtures::genesis_entry_hash();
        let mut has_cursor = false;
        for parameter in query.split('&').filter(|part| !part.is_empty()) {
            let (name, value) = parameter
                .split_once('=')
                .expect("jeder Abfrageparameter traegt einen Wert");
            match name {
                "afterSequence" => {
                    after_sequence = value.parse().expect("afterSequence ist eine Zahl");
                }
                "afterEntryHash" => {
                    after_entry_hash = EntryHash::try_from(
                        hex::decode(value)
                            .expect("afterEntryHash ist hexadezimal")
                            .as_slice(),
                    )
                    .expect("afterEntryHash misst 32 Byte");
                }
                "cursor" => has_cursor = true,
                other => {
                    panic!("der Reader hat einen unbekannten Abfrageparameter gebildet: {other}")
                }
            }
        }
        if has_cursor {
            return fixtures::second_page();
        }
        if after_sequence == 0 && after_entry_hash.as_bytes() == &[0_u8; 32] {
            return fixtures::first_page();
        }
        fixtures::empty_page(after_sequence, after_entry_hash)
    }
}

/// Die Kulisse: EIN Tresor, EIN Bytespeicher, EIN Server.
///
/// Der Tresor liegt in einem `Rc`, weil [`ReaderSyncHarness::reopen_store`]
/// eine ZWEITE Kulisse ueber denselben Schluesseln herausgibt und
/// `UnlockedVault` kein `Clone` traegt — es traegt private Schluessel, und ein
/// `Clone` darauf waere die zweite Kopie, die `web-reader-design.md` §6.5
/// ausdruecklich nicht will. Der Bytespeicher liegt in einer `RefCell`, weil
/// die Zeugen ihn ueber `&self` fahren: ein wiedereroeffneter Speicher wird im
/// Test nicht als `mut` gebunden, und genau das ist die Lage im Browser, wo
/// ein Worker denselben Speicher aus mehreren Nachrichten bedient.
pub struct ReaderSyncHarness {
    vault: Option<Rc<UnlockedVault>>,
    store: RefCell<InMemoryReaderBlobStore>,
    server: FakeReaderServer,
    /// Der Cursor, mit dem diese Kulisse begonnen hat.
    started_at: ConfirmedCursor,
}

impl ReaderSyncHarness {
    /// Ein frisches Geraet vor einem Bestand, den der Server in ZWEI Seiten
    /// herausgibt.
    #[must_use]
    pub fn with_two_batches() -> Self {
        let vault = Rc::new(fixtures::unlocked_vault());
        Self {
            vault: Some(vault),
            store: RefCell::new(InMemoryReaderBlobStore::new()),
            server: FakeReaderServer,
            started_at: ConfirmedCursor::genesis(&fixtures::pinned_anchor()),
        }
    }

    /// Dieselbe Kulisse mit GESPERRTEM Tresor.
    ///
    /// Der Anker steht der Kulisse weiterhin zur Verfuegung, weil ein Zeuge
    /// sonst gar keinen Cursor bilden koennte, gegen den er `next_request`
    /// stellt. Das ist eine Eigenschaft der KULISSE und nicht des Readers: im
    /// Browser liegt der Anker im verschlossenen Tresor und ist damit
    /// ebenfalls unerreichbar — die Weigerung faellt dann nur noch frueher.
    #[must_use]
    pub fn with_a_locked_vault() -> Self {
        Self {
            vault: None,
            store: RefCell::new(InMemoryReaderBlobStore::new()),
            server: FakeReaderServer,
            started_at: ConfirmedCursor::genesis(&fixtures::pinned_anchor()),
        }
    }

    /// Der Dienst dieser Kulisse.
    #[must_use]
    pub fn service(&self) -> ReaderSyncService<'_> {
        self.service_with(None)
    }

    /// Derselbe Dienst mit einem eingespielten Abbruchpunkt.
    #[must_use]
    fn service_with(&self, fault: Option<ReaderSyncFaultPoint>) -> ReaderSyncService<'_> {
        let service = match self.vault.as_deref() {
            Some(vault) => ReaderSyncService::open(
                vault,
                fixtures::SYNC_AUTHORITY_V1.to_owned(),
                fixtures::clock(),
            ),
            None => ReaderSyncService::locked(fixtures::clock()),
        };
        match fault {
            Some(point) => service.with_fault(point),
            None => service,
        }
    }

    /// Die Antwort des Servers auf genau diesen Request.
    #[must_use]
    pub fn serve(&self, request: &ReaderRequestV1) -> Vec<u8> {
        self.server.answer(request)
    }

    /// Der bestaetigte Cursor, GELESEN aus dem Bytespeicher.
    #[must_use]
    pub fn confirmed_cursor(&self) -> ConfirmedCursor {
        self.confirmed_cursor_in(&*self.store.borrow())
    }

    /// Derselbe Wert aus einem FREMDEN Bytespeicher.
    #[must_use]
    pub fn confirmed_cursor_in(&self, store: &dyn ReaderBlobStore) -> ConfirmedCursor {
        self.service()
            .confirmed_cursor(store)
            .expect("der Cursorblob dieser Kulisse ist lesbar")
    }

    /// Der bestaetigte Kopf, gebildet aus dem bestaetigten Cursor.
    #[must_use]
    pub fn confirmed_head(&self) -> ChainHeadV1 {
        let cursor = self.confirmed_cursor();
        ChainHeadV1::new(cursor.chain_id(), cursor.sequence(), cursor.entry_hash())
    }

    /// Ein vollstaendiger Sync ab dem bestaetigten Cursor.
    ///
    /// Er blaettert, bis der Server keinen Blaetterschein mehr herausgibt —
    /// genau das, was der Reader im Browser tut, und der Grund, warum die
    /// Kulisse zwei Seiten fuehrt.
    pub fn pull(&self) -> Result<ConfirmedCursor, ReaderSyncError> {
        self.drain_from(self.confirmed_cursor(), None)
    }

    /// GENAU EIN Zyklus, mit `fault` eingespielt.
    pub fn pull_with_fault(
        &mut self,
        fault: ReaderSyncFaultPoint,
    ) -> Result<ConfirmedCursor, ReaderSyncError> {
        self.one_cycle(Some(fault))
    }

    /// GENAU EINE Seite, ohne Abbruchpunkt.
    ///
    /// Der Unterschied zu [`Self::pull`] ist die Absicht: wer eine Kulisse
    /// braucht, die MITTEN in einer Lesestrecke steht — mit gecachten Objekten
    /// und einem Blaetterschein im Cursor —, bekommt sie nur so. Ein voller
    /// Sync liesse den Reader am Ende stehen, und die naechste Antwort waere
    /// eine leere Seite ohne einen einzigen Schreibvorgang.
    pub fn pull_one_page(&mut self) -> Result<ConfirmedCursor, ReaderSyncError> {
        self.one_cycle(None)
    }

    /// Anfragen, ausliefern, annehmen, bestaetigen — genau einmal.
    fn one_cycle(
        &self,
        fault: Option<ReaderSyncFaultPoint>,
    ) -> Result<ConfirmedCursor, ReaderSyncError> {
        let service = self.service_with(fault);
        let cursor = self.confirmed_cursor();
        let request = service.next_request(&cursor)?;
        let response = self.serve(&request);
        let batch = service.accept_batch(&mut *self.store.borrow_mut(), &cursor, &response)?;
        service.confirm(&mut *self.store.borrow_mut(), batch)
    }

    /// Derselbe Sync noch einmal, ab DEMSELBEN Startpunkt.
    ///
    /// Der Server ist deterministisch: derselbe Startkopf bekommt dieselben
    /// Seiten. Das ist der Wiederholversuch nach einer verlorenen Antwort, und
    /// er muss byteweise dasselbe Ergebnis haben.
    pub fn pull_same_batch_again(&mut self) -> Result<ConfirmedCursor, ReaderSyncError> {
        self.drain_from(self.started_at.clone(), None)
    }

    /// Nimmt EINEN Batch an und laesst den Dienst dann fallen — ohne `confirm`.
    ///
    /// Das Modell des schliessenden Tabs: die Objektbytes sind dauerhaft, der
    /// Cursor ist nie geschrieben worden.
    pub fn accept_one_batch_and_drop_the_service(&self) -> Result<(), ReaderSyncError> {
        let service = self.service();
        let cursor = self.confirmed_cursor();
        let request = service.next_request(&cursor)?;
        let response = self.serve(&request);
        let batch = service.accept_batch(&mut *self.store.borrow_mut(), &cursor, &response)?;
        drop(batch);
        drop(service);
        Ok(())
    }

    /// Nimmt EINEN fertigen Rahmen gegen den bestaetigten Cursor an.
    pub fn accept(&self, batch: Vec<u8>) -> Result<VerifiedSyncBatch, ReaderSyncError> {
        let service = self.service();
        let cursor = self.confirmed_cursor();
        service.accept_batch(&mut *self.store.borrow_mut(), &cursor, &batch)
    }

    /// Der Request, den der Dienst auf dem STARTCURSOR dieser Kulisse bildet.
    ///
    /// Auf dem Startcursor und nicht auf dem gelesenen: ein gesperrter Tresor
    /// gibt gar keinen Cursor heraus, und der Zeuge
    /// `a_locked_vault_produces_no_request_at_all` misst genau ihn. Solange der
    /// Speicher leer ist, sind beide Werte ohnehin derselbe.
    pub fn next_request(&self) -> Result<ReaderRequestV1, ReaderSyncError> {
        let service = self.service();
        service.next_request(&self.started_at)
    }

    /// Der Wiederaufbau nach Cacheverlust, gefolgt von einem vollen Sync.
    ///
    /// Der Dienst setzt den Cursor auf den LOKAL verifizierten Stand zurueck —
    /// nach einem geleerten Speicher ist das Genesis —, und erst danach holt
    /// die Kulisse die Bytes erneut. Die Trennung ist die Aussage: der Reader
    /// entscheidet ueber seinen Aufsetzpunkt aus dem, was er selbst
    /// verifizieren kann, und nie aus dem, was ein Server ihm sagt.
    pub fn rebuild_from_genesis(&self) -> Result<ConfirmedCursor, ReaderSyncError> {
        let restart = self
            .service()
            .rebuild_from_genesis(&mut *self.store.borrow_mut())?;
        self.drain_from(restart, None)
    }

    /// Ein NEU GEOEFFNETER Speicher ueber denselben Bytes.
    ///
    /// Alles, was nicht in den Bytes steht, ist danach fort — genau die Probe,
    /// die ein Cursor im Prozessspeicher nicht besteht.
    #[must_use]
    pub fn reopen_store(&mut self) -> Self {
        let reopened = Self {
            vault: self.vault.clone(),
            store: RefCell::new(copy_of(&*self.store.borrow())),
            server: self.server,
            started_at: self.started_at.clone(),
        };
        Self {
            started_at: reopened.confirmed_cursor(),
            ..reopened
        }
    }

    /// Dieselbe Kulisse mit LEEREM Bytespeicher.
    #[must_use]
    pub fn erase_blob_store(&mut self) -> Self {
        Self {
            vault: self.vault.clone(),
            store: RefCell::new(InMemoryReaderBlobStore::new()),
            server: self.server,
            started_at: ConfirmedCursor::genesis(&fixtures::pinned_anchor()),
        }
    }

    /// Die Summe aller Blobbytes im Speicher.
    #[must_use]
    pub fn blob_store_byte_count(&self) -> usize {
        let store = self.store.borrow();
        store
            .keys()
            .expect("das Doppel gibt seine Schluessel heraus")
            .iter()
            .map(|key| {
                store
                    .get(key)
                    .expect("das Doppel gibt seine Blobs heraus")
                    .map_or(0, |bytes| bytes.len())
            })
            .sum()
    }

    /// Eine Kopie des Speichers mit NUR den zwei Adressen des Sync-Zustands.
    ///
    /// Genau der Speicher, den der erste OPFS-Vorlauf im Browser oeffnen kann:
    /// mehr weiss er zu diesem Zeitpunkt nicht. Was `required_blob_keys`
    /// daraus macht, muss also allein aus Cursor und Objektliste stammen.
    #[must_use]
    pub fn sync_state_store(&self) -> InMemoryReaderBlobStore {
        let source = self.store.borrow();
        let mut state = InMemoryReaderBlobStore::new();
        for key in ReaderSyncService::sync_state_blob_keys()
            .expect("die zwei Zustandsadressen sind gueltige Schluessel")
        {
            if let Some(bytes) = source
                .get(&key)
                .expect("das Doppel gibt seine Blobs heraus")
            {
                state
                    .put(&key, &bytes)
                    .expect("ein frisches Doppel nimmt jeden Schluessel an");
            }
        }
        state
    }

    /// Alle `cache/`-Adressen, die der Speicher tatsaechlich fuehrt.
    #[must_use]
    pub fn cached_blob_keys(&self) -> Vec<String> {
        let store = self.store.borrow();
        let mut keys: Vec<String> = store
            .keys()
            .expect("das Doppel gibt seine Schluessel heraus")
            .iter()
            .map(|key| key.as_str().to_owned())
            .filter(|key| key.starts_with("cache/"))
            .collect();
        keys.sort();
        keys
    }

    /// Eine Kopie des Speichers, die den Cursorblob still vergisst.
    #[must_use]
    pub fn blob_store_that_forgets_the_cursor(&self) -> AmnesiacStore {
        AmnesiacStore::new(
            copy_of(&*self.store.borrow()),
            ea_reader::READER_SYNC_CURSOR_BLOB_KEY_V1,
        )
    }

    /// Eine Kopie des Speichers, die nach EINEM Schreibvorgang aufhoert.
    #[must_use]
    pub fn blob_store_that_quits_after_one_object(&self) -> QuotaExceededStore {
        QuotaExceededStore::new(copy_of(&*self.store.borrow()), 1)
    }

    /// Blaettert ab `cursor`, bis der Server keinen Schein mehr herausgibt.
    fn drain_from(
        &self,
        mut cursor: ConfirmedCursor,
        fault: Option<ReaderSyncFaultPoint>,
    ) -> Result<ConfirmedCursor, ReaderSyncError> {
        let service = self.service_with(fault);
        loop {
            let request = service.next_request(&cursor)?;
            let response = self.serve(&request);
            let batch = service.accept_batch(&mut *self.store.borrow_mut(), &cursor, &response)?;
            let has_more = batch.next_cursor().is_some();
            cursor = service.confirm(&mut *self.store.borrow_mut(), batch)?;
            if !has_more {
                return Ok(cursor);
            }
        }
    }
}

/// Ein zweiter Speicher ueber denselben Bytes.
fn copy_of(store: &dyn ReaderBlobStore) -> InMemoryReaderBlobStore {
    let mut copy = InMemoryReaderBlobStore::new();
    for key in store
        .keys()
        .expect("das Doppel gibt seine Schluessel heraus")
    {
        if let Some(bytes) = store.get(&key).expect("das Doppel gibt seine Blobs heraus") {
            copy.put(&key, &bytes)
                .expect("ein frisches Doppel nimmt jeden Schluessel an");
        }
    }
    copy
}
