//! Der verifizierte Batch — und der Bestand, gegen den er verifiziert wurde.
//!
//! # `VerifiedSyncBatch` ist ein NACHWEIS und kein Behaelter
//!
//! Der Typ entsteht ausschliesslich in [`crate::ReaderSyncService::accept_batch`],
//! und sein Konstruktor ist deshalb `pub(crate)`. Wer ihn in der Hand haelt,
//! hat die Zusicherung, dass jedes angekuendigte Objektbyte dauerhaft im
//! Bytespeicher liegt und dass die Kette bis zum Batchende gegen den gepinnten
//! Anker verifiziert. Genau darauf verlaesst sich [`crate::ReaderSyncService::confirm`]
//! — es prueft nichts nach, es SCHREIBT nur noch. Waere der Konstruktor
//! oeffentlich, koennte ein Aufrufer sich einen Nachweis bauen und den Cursor
//! ueber eine ungeprueften Kette schieben.
//!
//! # Der Bestand ist der GANZE Cache und nie nur die neue Seite
//!
//! [`ReaderCacheSourceV1`] reicht `verify_archive_observed` jedes dauerhaft
//! abgelegte Objekt. Eine Quelle ueber nur die neuen Bytes waere billiger und
//! falsch: eine Kette verifiziert an ihrem Kopf und nicht an einer Seite, und
//! ohne die frueheren Eintraege gaebe es zu jedem Batch eine Luecke davor.

use ea_archive::{ArchiveBlob, ArchiveError, ArchiveSource};
use ea_types::ObjectHash;
use ea_verify::{ChainHeadV1, VerificationReportV1};

use crate::blob_store::ReaderBlobStore;
use crate::cache::ReaderObjectCache;

/// Ein Batch, dessen Objektbytes dauerhaft sind und dessen Kette verifiziert.
pub struct VerifiedSyncBatch {
    head: ChainHeadV1,
    next_cursor: Option<Vec<u8>>,
    object_hashes: Vec<ObjectHash>,
    report: VerificationReportV1,
}

impl VerifiedSyncBatch {
    /// Der Nachweis aus seinen vier Bestandteilen. Siehe Modulkopf.
    pub(crate) const fn new(
        head: ChainHeadV1,
        next_cursor: Option<Vec<u8>>,
        object_hashes: Vec<ObjectHash>,
        report: VerificationReportV1,
    ) -> Self {
        Self {
            head,
            next_cursor,
            object_hashes,
            report,
        }
    }

    /// Der Kopf, den der bestaetigte Cursor nach diesem Batch TRAEGT.
    ///
    /// Auf der letzten Seite einer Lesestrecke ist das der verifizierte Kopf
    /// aus [`Self::report`]; auf jeder Seite davor bleibt es der Startkopf der
    /// Strecke, weil der technische Cursor des Servers an genau ihn gebunden
    /// ist. Die Begruendung samt Messstelle steht bei
    /// [`crate::ReaderSyncService::accept_batch`].
    #[must_use]
    pub const fn head(&self) -> ChainHeadV1 {
        self.head
    }

    /// Der Blaetterschein des Servers, falls es weitergeht.
    #[must_use]
    pub fn next_cursor(&self) -> Option<&[u8]> {
        self.next_cursor.as_deref()
    }

    /// Die Objekthashes, die dieser Batch angekuendigt hat — in Rahmenordnung.
    #[must_use]
    pub fn object_hashes(&self) -> &[ObjectHash] {
        &self.object_hashes
    }

    /// Der Bericht des Laufs, der diesen Nachweis getragen hat.
    #[must_use]
    pub const fn report(&self) -> &VerificationReportV1 {
        &self.report
    }
}

impl core::fmt::Debug for VerifiedSyncBatch {
    /// Nennt die Zaehlwerte und nie den Inhalt.
    ///
    /// Dieselbe Regel wie `impl Debug for ReaderBatchV1`: Objektbytes koennen
    /// Ciphertext sein, und ein Debug-Abzug davon gehoert in kein Protokoll.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "VerifiedSyncBatch {{ head: {:?}, objects: {}, has_next_cursor: {} }}",
            self.head,
            self.object_hashes.len(),
            self.next_cursor.is_some()
        )
    }
}

/// Der dauerhaft abgelegte Bestand des Readers als [`ArchiveSource`].
///
/// Die Umsetzung liegt HIER und nicht in `crates/ea-reader/src/cache.rs`: der
/// Cache spricht ueber Bytes und ihre Adressen, der Port `ArchiveSource`
/// gehoert dem Verifizierer. Der Cache gibt deshalb nur die Aufzaehlung heraus
/// (`ReaderObjectCache::visit_exact_objects`), und die Uebersetzung in
/// `ArchiveBlob` steht dort, wo verifiziert wird.
///
/// Die Datei-Modus-Varianten sind eine ZWEITE, getrennte Umsetzung derselben
/// Eigenschaft und entstehen erst im Task „Datei-Modus"; hier entsteht kein
/// Vorgriff darauf.
pub(crate) struct ReaderCacheSourceV1<'a> {
    cache: &'a ReaderObjectCache,
    store: &'a dyn ReaderBlobStore,
}

impl<'a> ReaderCacheSourceV1<'a> {
    pub(crate) const fn new(cache: &'a ReaderObjectCache, store: &'a dyn ReaderBlobStore) -> Self {
        Self { cache, store }
    }
}

impl ArchiveSource for ReaderCacheSourceV1<'_> {
    /// Reicht jedes entschluesselte Objekt als `ArchiveBlob<'_>` weiter.
    ///
    /// Der Pfadhinweis ist die CACHEADRESSE und kein Archivpfad. Das ist
    /// zulaessig und beabsichtigt: `design.md` §11.4 laesst den Hinweis
    /// ausdruecklich nicht klassifizieren — das tut allein das
    /// 9-Byte-Exact-Object-Praefix —, und ein erfundener Archivpfad waere eine
    /// Behauptung darueber, wo diese Bytes einmal lagen.
    fn visit_blobs(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        let mut carried: Option<ArchiveError> = None;
        let visited = self
            .cache
            .visit_exact_objects(self.store, &mut |hash, bytes| {
                let hint = format!("cache/{}", hex::encode(hash.as_bytes()));
                match visitor(ArchiveBlob::new(&hint, bytes)) {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        // Der Befund des Besuchers wird MITGEFUEHRT und nicht in
                        // einen Speicherfehler umgedeutet: `ArchiveInventory::build`
                        // setzt seine Schranken ueber genau diesen Rueckweg durch,
                        // und ein `EA-READER-BLOB-HOST` an seiner Stelle machte aus
                        // einer erreichten Bestandsgrenze einen Wirtsfehler.
                        carried = Some(error);
                        Err(crate::vault::ReaderVaultError::Contents)
                    }
                }
            });
        match (visited, carried) {
            (_, Some(error)) => Err(error),
            (Ok(()), None) => Ok(()),
            // Der Speicher hat Bytes nicht liefern koennen — ein
            // entschluesselbarer Blob fehlte oder der Wirt hat abgewiesen. Genau
            // dafuer traegt der Port `Unavailable`.
            (Err(_), None) => Err(ArchiveError::Unavailable),
        }
    }
}
