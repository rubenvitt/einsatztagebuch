//! Die Kulisse des Reader-Syncs fuer den Systemzeugen
//! `e2e_reader_sync_interruptions.rs`.
//!
//! Sie ist eine Abschrift von `crates/ea-reader/tests/sync_support/` — dessen
//! Harness und Fixtures sind testlokal zu `ea-reader` und aus dieser Crate
//! nicht importierbar; das Merkmal `test-support` von `ea-reader` bleibt laut
//! `tests/ea-system-tests/Cargo.toml` ausdruecklich AUS. Die drei Zusagen des
//! Originals gelten unveraendert:
//!
//! 1. **Echte Archivbytes.** Der Bestand kommt aus dem per `#[path]`
//!    eingebundenen Fixture-Modul von `ea-verify`.
//! 2. **Der Server ist eine ATTRAPPE, das Protokoll nicht.** [`ReaderSyncHarness::serve`]
//!    LIEST den Request, den `ReaderSyncService::next_request` herausgegeben
//!    hat, und antwortet mit einem echten `reader-batch-v1`.
//! 3. **Kein Testpfad in die Produktionsflaeche.** Der Bytespeicher, der ab dem
//!    n-ten Objekt `QuotaExceeded` liefert, liegt HIER.
//!
//! # Der eine Unterschied: der Rahmen wird HIER kodiert
//!
//! `ea-sync-protocol` steht NICHT unter den Dev-Kanten dieser Crate
//! (gemessen: `tests/ea-system-tests/Cargo.toml`), und `ea-reader` exportiert
//! aus ihm nur `HttpMethod`. `ReaderBatchV1::new` ist von hier aus also nicht
//! erreichbar, und `Cargo.toml` gehoert nicht zu dieser Aufgabe. [`fixtures`]
//! schreibt die neun Positionen von `reader-batch-v1` deshalb selbst mit
//! `minicbor` — die Layoutabschrift von
//! `crates/ea-sync-protocol/src/reader.rs::ReaderBatchV1::new`. Dass sie
//! nicht still abdriften kann, misst der Reader selbst in JEDEM Lauf:
//! `ReaderBatchV1::decode` kodiert den Rahmen neu und verlangt Bytegleichheit,
//! und ein Rahmen, der davon abweicht, endet als `EA-READER-PROTOCOL` — laut
//! und nie als gruener Zeuge.
//!
//! `#[path]`-Includes werden je Testtarget uebersetzt; ein Target, das nur
//! einen Teil der Helfer nutzt, erzeugt sonst `dead_code`-Warnungen, die unter
//! `-D warnings` brechen. Daher `allow(dead_code)` auf Modulebene.
#![allow(dead_code)]

/// Das Fixture-Modul aus `ea-verify`, unveraendert weiterverwendet — dieselbe
/// Kette von Includes, die `crates/ea-reader/tests/sync_support/mod.rs` faehrt.
#[path = "../../../../crates/ea-verify/tests/support/mod.rs"]
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
/// Bytes, weil `ReaderBlobStore::put` je Objekt genau einmal gerufen wird.
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

    /// Die Bytes, an denen der Abbruch geschah — nach dem Ende des Drucks.
    #[must_use]
    pub fn into_inner(self) -> InMemoryReaderBlobStore {
        self.inner
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

/// Der Server dieser Kulisse: zwei Seiten und eine leere Antwort.
///
/// Er entscheidet AUS DEM REQUEST und nicht aus einem Zaehler: der Reader
/// nennt seine Position im Pfad, und genau daran haengt, welche Seite er
/// bekommt.
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
/// `UnlockedVault` kein `Clone` traegt. Der Bytespeicher liegt in einer
/// `RefCell`, weil die Zeugen ihn ueber `&self` fahren.
pub struct ReaderSyncHarness {
    vault: Rc<UnlockedVault>,
    store: RefCell<InMemoryReaderBlobStore>,
    server: FakeReaderServer,
}

impl ReaderSyncHarness {
    /// Ein frisches Geraet vor einem Bestand, den der Server in ZWEI Seiten
    /// herausgibt.
    #[must_use]
    pub fn fresh() -> Self {
        Self {
            vault: Rc::new(fixtures::unlocked_vault()),
            store: RefCell::new(InMemoryReaderBlobStore::new()),
            server: FakeReaderServer,
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
        let service = ReaderSyncService::open(
            &self.vault,
            fixtures::SYNC_AUTHORITY_V1.to_owned(),
            fixtures::clock(),
        );
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
        self.service()
            .confirmed_cursor(&*self.store.borrow())
            .expect("der Cursorblob dieser Kulisse ist lesbar")
    }

    /// Der bestaetigte Kopf, gebildet aus dem bestaetigten Cursor.
    #[must_use]
    pub fn confirmed_head(&self) -> ChainHeadV1 {
        let cursor = self.confirmed_cursor();
        ChainHeadV1::new(cursor.chain_id(), cursor.sequence(), cursor.entry_hash())
    }

    /// Ein vollstaendiger Sync ab dem bestaetigten Cursor: er blaettert, bis
    /// der Server keinen Blaetterschein mehr herausgibt.
    pub fn pull(&self) -> Result<ConfirmedCursor, ReaderSyncError> {
        let service = self.service();
        let mut cursor = self.confirmed_cursor();
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

    /// GENAU EIN Zyklus, mit `fault` eingespielt.
    pub fn pull_with_fault(
        &mut self,
        fault: ReaderSyncFaultPoint,
    ) -> Result<ConfirmedCursor, ReaderSyncError> {
        self.one_cycle(Some(fault))
    }

    /// GENAU EINE Seite, ohne Abbruchpunkt — die Kulisse steht danach MITTEN
    /// in der Lesestrecke, mit gecachten Objekten und einem Blaetterschein.
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

    /// Holt die naechste Seite gegen einen Speicher, der nach EINEM Objekt
    /// `QuotaExceeded` liefert — und uebernimmt danach GENAU DIESE Bytes.
    ///
    /// Das Modell des OPFS-Schreibvorgangs, den die Speicherbereinigung
    /// abbricht. Die Kulisse faehrt anschliessend auf dem Speicher weiter, an
    /// dem der Abbruch geschah, und nicht auf einer unberuehrten Kopie: nur so
    /// misst der Wiederholversuch die Lage nach dem Druck. Gibt den Befund des
    /// Abbruchs zurueck.
    pub fn abort_the_next_page_under_storage_pressure(&mut self) -> ReaderSyncError {
        let service = self.service();
        let cursor = self.confirmed_cursor();
        let request = service
            .next_request(&cursor)
            .expect("der Request vor dem Speicherdruck entsteht");
        let response = self.serve(&request);
        let mut quota =
            QuotaExceededStore::new(self.store.replace(InMemoryReaderBlobStore::new()), 1);
        let error = service
            .accept_batch(&mut quota, &cursor, &response)
            .expect_err("ein Speicher unter Druck bricht den Batch ab");
        self.store.replace(quota.into_inner());
        error
    }

    /// Legt EINEN Rahmen gegen den bestaetigten Cursor vor und erwartet die
    /// Abweisung.
    pub fn refuse(&self, frame: Vec<u8>) -> ReaderSyncError {
        self.accept(frame)
            .expect_err("der Reader weist diesen Rahmen ab")
    }

    /// Nimmt EINEN fertigen Rahmen gegen den bestaetigten Cursor an.
    pub fn accept(&self, batch: Vec<u8>) -> Result<VerifiedSyncBatch, ReaderSyncError> {
        let service = self.service();
        let cursor = self.confirmed_cursor();
        service.accept_batch(&mut *self.store.borrow_mut(), &cursor, &batch)
    }

    /// Ein NEU GEOEFFNETER Speicher ueber denselben Bytes.
    ///
    /// Alles, was nicht in den Bytes steht, ist danach fort — genau die Probe,
    /// die ein Cursor im Prozessspeicher nicht besteht.
    #[must_use]
    pub fn reopen_store(&mut self) -> Self {
        Self {
            vault: Rc::clone(&self.vault),
            store: RefCell::new(copy_of(&*self.store.borrow())),
            server: self.server,
        }
    }

    /// Dieselbe Kulisse mit LEEREM Bytespeicher — der Cacheverlust.
    #[must_use]
    pub fn erase_blob_store(&mut self) -> Self {
        Self {
            vault: Rc::clone(&self.vault),
            store: RefCell::new(InMemoryReaderBlobStore::new()),
            server: self.server,
        }
    }

    /// Der Wiederaufbau nach Cacheverlust, gefolgt von einem vollen Sync.
    ///
    /// Der Dienst setzt den Cursor auf den LOKAL verifizierten Stand zurueck —
    /// nach einem geleerten Speicher ist das Genesis —, und erst danach holt
    /// die Kulisse die Bytes erneut.
    pub fn rebuild_from_genesis(&self) -> Result<ConfirmedCursor, ReaderSyncError> {
        self.service()
            .rebuild_from_genesis(&mut *self.store.borrow_mut())?;
        self.pull()
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

    /// Alle `cache/`-Adressen, die der Speicher tatsaechlich fuehrt, sortiert.
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
