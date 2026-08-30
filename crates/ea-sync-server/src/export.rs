//! `GET /v1/archive-exports/current` — der vollstaendige Archivexport.
//!
//! # Was der Strom traegt
//!
//! „Der Archivexport streamt alle verschluesselten Originalobjekte, Stubs,
//! Receipts, Evidence und ein vollstaendiges Trust Bundle ohne
//! Klartexttransformation“ (`design.md` §13.3). Die Menge ist deshalb der
//! GESAMTE Objektbestand der Organisation und keine Auswahl daraus: der
//! Objektindex fuehrt genau die sechs Archivobjektarten, und keine von ihnen
//! wird uebersprungen. Es gibt hier keine Umwandlung, keine Entschluesselung
//! und keine Neukodierung — jedes Objekt geht byteweise so hinaus, wie es
//! liegt.
//!
//! # Warum eine Blaetterposition in `object_index` steht
//!
//! Der Export braucht eine STABILE Ordnung ueber den ganzen Bestand. `OFFSET`
//! ueber `object_hash` waere unter gleichzeitigen Einfuegungen nicht stabil
//! und liesse Objekte aus — genau das, was ein vollstaendiger Export nicht
//! darf. `object_index.technical_index` ist deshalb eine Identitaetsspalte
//! nach demselben Muster wie `checkpoints.technical_index`, und
//! `archive-export-manifest-v1.export-cursor` traegt sie als
//! `lastTechnicalIndex`.
//!
//! Ausgeliefert wird trotzdem nach OBJEKTHASH sortiert: das Manifest verlangt
//! eine bytweise aufsteigende, duplikatfreie Liste. Beides widerspricht sich
//! nicht — die Blaetterung ist technisch, die Ausgabeordnung ist die des
//! Rahmens.
//!
//! # Ohne vollen Puffer
//!
//! [`export_page`] liefert einen PLAN und keine Bytes: Adressen, Arten und
//! Laengen. Der Aufrufer streamt danach Objekt fuer Objekt und haengt das
//! Manifest an. So liegt nie mehr als EIN Objekt im Speicher, und die Satz-
//! wie die Bytedecke wirken, BEVOR akkumuliert wird — sie werden ueber die
//! Groessen des Index entschieden und nicht ueber gelesene Bytes.

use core::fmt;

use ea_sync_protocol::{
    ArchiveExportManifestV1, EndpointV1, ExportObjectRecordV1, MAX_READER_PAGE_BYTES_V1,
    MAX_READER_PAGE_OBJECTS_V1, SyncProtocolError, TechnicalCursorFieldsV1, TechnicalCursorScopeV1,
    TechnicalCursorV1,
};
use ea_types::{ObjectHash, OrganizationId, UnixMillis};

use crate::{
    models::{IndexedObjectV1, RepositoryError},
    ports::{ArchiveExportDirectory, ServerClock, ServerSigner},
};

/// Die Lebensdauer eines Export-Cursors — dieselbe Begruendung wie beim
/// Checkpoint- und beim Lesestapel-Cursor.
pub const EXPORT_CURSOR_TTL_MILLIS_V1: i64 = 900_000;

/// Was der Export an Ports braucht.
pub struct ExportPorts<'a> {
    pub clock: &'a dyn ServerClock,
    pub signer: &'a dyn ServerSigner,
    pub inventory: &'a dyn ArchiveExportDirectory,
}

/// Jeder Befund des Exports.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ExportError {
    /// Ein durchgereichter Rahmen- oder Cursorbefund.
    Protocol(SyncProtocolError),
    /// Datenbank oder Object Store antworten nicht.
    DependencyUnavailable,
    /// Interner Fehler ohne fachliche Ursache.
    Internal,
}

impl ExportError {
    /// Die Arme ohne Nutzlast — damit ein spaeter ergaenzter auffaellt.
    pub const ALL: [Self; 2] = [Self::DependencyUnavailable, Self::Internal];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Protocol(error) => error.code(),
            Self::DependencyUnavailable => "EA-EXPORT-DEPENDENCY-UNAVAILABLE",
            Self::Internal => "EA-EXPORT-INTERNAL",
        }
    }

    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::Protocol(error) => error.http_status(),
            Self::DependencyUnavailable => 503,
            Self::Internal => 500,
        }
    }

    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(self.http_status(), 429 | 500 | 503)
    }
}

impl From<SyncProtocolError> for ExportError {
    fn from(value: SyncProtocolError) -> Self {
        Self::Protocol(value)
    }
}

impl From<RepositoryError> for ExportError {
    fn from(_: RepositoryError) -> Self {
        Self::DependencyUnavailable
    }
}

impl fmt::Display for ExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for ExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for ExportError {}

/// Der Plan EINER Exportseite: was in welcher Reihenfolge hinausgeht.
///
/// Der Plan traegt bewusst KEINE Objektbytes. Er ist die Antwort auf „was
/// gehoert auf diese Seite“, und die Bytes holt der Aufrufer danach einzeln —
/// so bleibt der Export ein Strom und wird nicht zu einem 64-MiB-Puffer.
pub struct ExportPageV1 {
    /// Die Objekte in AUSLIEFERUNGSREIHENFOLGE, aufsteigend nach `objectHash`.
    /// Dieselbe Reihenfolge fuehrt das Manifest.
    objects: Vec<IndexedObjectV1>,
    manifest: ArchiveExportManifestV1,
}

impl ExportPageV1 {
    /// Die Objekte, die der Aufrufer nacheinander streamt.
    #[must_use]
    pub fn objects(&self) -> &[IndexedObjectV1] {
        &self.objects
    }

    /// Das Manifest, das den Strom ABSCHLIESST — als letztes und nie davor.
    #[must_use]
    pub const fn manifest(&self) -> &ArchiveExportManifestV1 {
        &self.manifest
    }

    /// Die Gesamtlaenge der Objektbytes dieser Seite.
    ///
    /// Der Aufrufer braucht sie fuer `Content-Length`: der Strom ist Objekte
    /// PLUS Manifest, und beide Laengen sind vor dem ersten Byte bekannt.
    #[must_use]
    pub fn total_byte_length(&self) -> u64 {
        self.objects
            .iter()
            .map(|object| object.size_bytes)
            .sum::<u64>()
            .saturating_add(self.manifest.exact_bytes().len() as u64)
    }
}

impl fmt::Debug for ExportPageV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ExportPageV1({} objects)", self.objects.len())
    }
}

/// Plant EINE Seite des Archivexports.
///
/// Die beiden Decken der Version 1 — hoechstens
/// [`MAX_READER_PAGE_OBJECTS_V1`] Saetze und hoechstens
/// [`MAX_READER_PAGE_BYTES_V1`] Bytes — wirken hier und damit VOR jeder
/// Akkumulation: entschieden wird ueber die Groessen des Index, nicht ueber
/// gelesene Bytes. Ein Objekt, das die Bytedecke allein sprengte, waere nach
/// [`ea_format::MAX_ARCHIVE_OBJECT_BYTES_V1`] gar nicht ablegbar; es wird
/// trotzdem als erstes Objekt einer Seite zugelassen, damit der Export nicht
/// an ihm stehen bleibt.
///
/// # Errors
///
/// Jeder Arm von [`ExportError`].
pub async fn export_page(
    organization_id: OrganizationId,
    cursor_token: Option<&[u8]>,
    cursor_nonce: [u8; 16],
    ports: &ExportPorts<'_>,
) -> Result<ExportPageV1, ExportError> {
    let now = ports.clock.now();
    let scope = TechnicalCursorScopeV1 {
        organization_id,
        endpoint: EndpointV1::ArchiveExports,
        chain_id: None,
        start_head_entry_hash: None,
    };
    let after_technical_index = match cursor_token {
        Some(token) => {
            TechnicalCursorV1::open(token, ports.signer, now, &scope)?.last_technical_index()
        }
        None => 0,
    };

    let indexed = ports
        .inventory
        .objects_after(
            organization_id,
            after_technical_index,
            MAX_READER_PAGE_OBJECTS_V1,
        )
        .await?;

    let mut objects = Vec::with_capacity(indexed.len());
    let mut bytes: u64 = 0;
    let mut last_technical_index = after_technical_index;
    let mut truncated = false;
    for entry in &indexed {
        let next = bytes.saturating_add(entry.object.size_bytes);
        if !objects.is_empty() && next > MAX_READER_PAGE_BYTES_V1 as u64 {
            truncated = true;
            break;
        }
        bytes = next;
        last_technical_index = entry.technical_index;
        objects.push(entry.object);
    }

    // Die Ausgabeordnung ist die des Rahmens: bytweise aufsteigend nach
    // `objectHash`. Der Objektindex ist ueber `object_hash` Primaerschluessel,
    // also kann eine Seite keinen Hash zweimal tragen.
    objects.sort_unstable_by(|left, right| {
        left.object_hash
            .as_bytes()
            .cmp(right.object_hash.as_bytes())
    });

    let more_pages = truncated || indexed.len() == MAX_READER_PAGE_OBJECTS_V1;
    let export_cursor = if more_pages && !objects.is_empty() {
        Some(
            TechnicalCursorV1::issue(
                &TechnicalCursorFieldsV1 {
                    organization_id,
                    endpoint: EndpointV1::ArchiveExports,
                    chain_id: None,
                    start_head_entry_hash: None,
                    last_technical_index,
                    expires_at: expires_at(now)?,
                    nonce: cursor_nonce,
                },
                ports.signer,
            )?
            .token_bytes()
            .to_vec(),
        )
    } else {
        None
    };

    let manifest = ArchiveExportManifestV1::new(
        organization_id,
        objects
            .iter()
            .map(|object| {
                ExportObjectRecordV1::new(object.kind, object.object_hash, object.size_bytes)
            })
            .collect(),
        export_cursor,
    )?;
    Ok(ExportPageV1 { objects, manifest })
}

fn expires_at(now: UnixMillis) -> Result<UnixMillis, ExportError> {
    Ok(UnixMillis::new(
        now.get()
            .checked_add(EXPORT_CURSOR_TTL_MILLIS_V1)
            .ok_or(ExportError::Internal)?,
    ))
}

/// Die Adressen einer Exportseite in Auslieferungsreihenfolge.
///
/// Sie steht getrennt, weil der Aufrufer sie ohne das Manifest braucht: er
/// streamt sie der Reihe nach und haengt das Manifest erst danach an.
#[must_use]
pub fn export_object_hashes(page: &ExportPageV1) -> Vec<ObjectHash> {
    page.objects()
        .iter()
        .map(|object| object.object_hash)
        .collect()
}
