//! Die drei Leseflaechen des Readers: Stapel, Einzelobjekt und Quittung.
//!
//! # Was ein Lesestapel BINDET
//!
//! `design.md` §14.5: „Der Reader synchronisiert ab seinem hoechsten
//! lueckenlos verifizierten Kettenkopf. Er sendet `chainId`, `afterSequence`,
//! den zugehoerigen `entryHash` und einen technischen Objektcursor. […] jeder
//! Batch bindet den ANGEFRAGTEN Startkopf.“ Der angefragte Startkopf ist
//! deshalb genau der `afterEntryHash` des Aufrufers, und
//! `reader-batch-v1.start-head-entry-hash` traegt ihn zurueck. Der Server
//! prueft ihn gegen den Eintrag, der an `afterSequence` tatsaechlich steht;
//! weichen sie ab, ist das eine KOPFABWEICHUNG und damit `409` — nicht `404`,
//! denn die Kette ist bekannt.
//!
//! Derselbe Startkopf steht im [`TechnicalCursorScopeV1`]. Ein Cursor, der von
//! einer anderen Startposition aus ausgestellt wurde, blaetterte sonst mitten
//! in einer fremden Lesestrecke weiter, obwohl er authentisch ist.
//!
//! # Warum eine Datenbankliste hier nichts beweist
//!
//! Sie beweist nichts, und dieses Modul behauptet auch nichts anderes. Die
//! Zeilen sagen ausschliesslich, WELCHE Adressen zu einer Kettenposition
//! gehoeren; die ausgelieferten Bytes kommen aus dem Object Store und werden
//! vor der Auslieferung gegen ihre eigene Adresse gestellt. Der Empfaenger
//! prueft sie danach selbst (`design.md` §13.2: technische Listen sind nicht
//! autoritativ).
//!
//! # Die Objektantwort traegt keinen Rahmen
//!
//! `GET /v1/objects/{objectHash}` liefert die exakt archivierten Bytes mit
//! `Content-Type: application/einsatzarchiv-object`, `Content-Length` und
//! einem RFC-9530-`content-digest`. Der Digest ist AUSDRUECKLICH NICHT der
//! `objectHash`: [`ea_crypto::object_hash`] ist domaenengetrennt
//! (`OBJECT_DOMAIN ‖ bytes`), RFC 9530 misst dagegen die uebertragenen Bytes
//! blank. Beide entstehen hier in EINEM Durchlauf ueber den Strom, ohne den
//! Koerper zu halten — und der Durchlauf prueft zugleich, dass die gelieferten
//! Bytes das angefragte Objekt SIND.

use core::fmt;

use ea_crypto::{ReaderAckCoreV1, StreamingObjectHasher};
use ea_format::ObjectTypeV1;
use ea_sync_protocol::{
    EndpointV1, GrantListResponseV1, MAX_GRANT_PAGE_OBJECTS_V1, MAX_READER_PAGE_BYTES_V1,
    MAX_READER_PAGE_OBJECTS_V1, ObjectRecordV1, ReaderAckV1, ReaderBatchV1, SyncProtocolError,
    TechnicalCursorFieldsV1, TechnicalCursorScopeV1, TechnicalCursorV1,
};
use ea_types::{ChainId, ChainSequence, EntryHash, Hash32, ObjectHash, OrganizationId, UnixMillis};
use sha2::{Digest, Sha256};

use crate::{
    models::{AppendOutcome, IndexedObjectV1, ReaderAckCommandV1, RepositoryError, StoreError},
    ports::{
        DestructionStore, EntryDirectory, ObjectStore, ObjectTypeDirectory, ReaderAckStore,
        ServerClock, ServerSigner,
    },
};

/// Die Lebensdauer eines Lesestapel-Cursors — dieselbe Begruendung wie beim
/// Checkpoint-Cursor: reichlich fuer die naechste Seite, kurz genug, dass ein
/// abgefangener Cursor nicht dauerhaft blaettert.
pub const READER_CURSOR_TTL_MILLIS_V1: i64 = 900_000;

/// Wie viele EINTRAEGE eine Seite hoechstens aus dem Index holt.
///
/// Die Decke der Leitung zaehlt OBJEKTE (`MAX_READER_PAGE_OBJECTS_V1`), und
/// ein Eintrag traegt mindestens vier davon — `.eip`/`.eds`, Quittung,
/// Checkpoint und den Registrierungskopf — plus einen Grant je aktivem
/// Empfaenger. Diese Zahl ist deshalb bewusst kleiner als die Objektdecke: sie
/// begrenzt die INDEXABFRAGE, damit nie mehr Eintraege gelesen werden, als
/// selbst im guenstigsten Fall auf eine Seite passen. Die eigentliche Decke
/// setzt [`accumulate_entry`] danach objektweise durch.
const MAX_ENTRIES_PER_PAGE_V1: usize = MAX_READER_PAGE_OBJECTS_V1 / 4;

/// Der Sentinelwert, mit dem ein Leser „ab Kettenanfang“ anfragt.
///
/// Ein Reader ohne verifizierten Kopf hat keinen `entryHash`, den er nennen
/// koennte. `afterSequence = 0` allein reichte als Kennzeichen nicht: Sequenz
/// null ist eine gueltige Kettenposition, und ein Stapel „nach Eintrag 0“ ist
/// etwas anderes als einer „ab Genesis“.
#[must_use]
pub fn is_genesis_start(after_sequence: u64, after_entry_hash: EntryHash) -> bool {
    after_sequence == 0 && after_entry_hash.as_bytes() == &[0_u8; 32]
}

/// Was die Leseflaechen an Ports brauchen.
pub struct ReaderPorts<'a> {
    pub clock: &'a dyn ServerClock,
    pub signer: &'a dyn ServerSigner,
    pub objects: &'a dyn ObjectStore,
    pub object_types: &'a dyn ObjectTypeDirectory,
    pub entries: &'a dyn EntryDirectory,
    pub acks: &'a dyn ReaderAckStore,
    pub destructions: &'a dyn DestructionStore,
}

/// Jeder Befund der Leseflaechen.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ReaderError {
    /// Ein durchgereichter Rahmen- oder Cursorbefund.
    Protocol(SyncProtocolError),
    /// Diese Organisation kennt diese Kette nicht.
    ChainUnknown,
    /// An `afterSequence` steht ein ANDERER Eintrag als der genannte, oder
    /// dort steht gar keiner. Eine Kopfabweichung, kein unbekanntes Objekt.
    StartHeadMismatch,
    /// Unter diesem Hash liegt in DIESER Organisation kein Objekt.
    ObjectUnknown,
    /// Dieser `entryHash` gehoert zu keinem Eintrag dieser Organisation.
    EntryUnknown,
    /// Die Quittung ist nicht vom AUFRUFER signiert, oder sie bindet eine
    /// andere Kette als der Eintrag, den sie nennt.
    AckMismatch,
    /// Unter derselben Adresse liegt bereits eine ANDERE Quittung.
    AckConflict,
    /// Datenbank oder Object Store antworten nicht.
    DependencyUnavailable,
    /// Interner Fehler ohne fachliche Ursache.
    Internal,
}

impl ReaderError {
    /// Die Arme ohne Nutzlast — damit ein spaeter ergaenzter auffaellt.
    pub const ALL: [Self; 8] = [
        Self::ChainUnknown,
        Self::StartHeadMismatch,
        Self::ObjectUnknown,
        Self::EntryUnknown,
        Self::AckMismatch,
        Self::AckConflict,
        Self::DependencyUnavailable,
        Self::Internal,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Protocol(error) => error.code(),
            Self::ChainUnknown => "EA-READER-CHAIN-UNKNOWN",
            Self::StartHeadMismatch => "EA-READER-START-HEAD-MISMATCH",
            Self::ObjectUnknown => "EA-READER-OBJECT-UNKNOWN",
            Self::EntryUnknown => "EA-READER-ENTRY-UNKNOWN",
            Self::AckMismatch => "EA-READER-ACK-MISMATCH",
            Self::AckConflict => "EA-READER-ACK-CONFLICT",
            Self::DependencyUnavailable => "EA-READER-DEPENDENCY-UNAVAILABLE",
            Self::Internal => "EA-READER-INTERNAL",
        }
    }

    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::Protocol(error) => error.http_status(),
            // Die 404-Zeile der Abbildung nennt GENAU „unbekanntes Objekt,
            // unbekannte Kette, unbekannter Eintrag, unbekannte
            // Vernichtungs-ID“ — und sonst nichts.
            Self::ChainUnknown | Self::ObjectUnknown | Self::EntryUnknown => 404,
            // Die 409-Zeile nennt „Fork, Kopfabweichung, …“.
            Self::StartHeadMismatch | Self::AckConflict => 409,
            Self::AckMismatch => 422,
            Self::DependencyUnavailable => 503,
            Self::Internal => 500,
        }
    }

    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(self.http_status(), 429 | 500 | 503)
    }
}

impl From<SyncProtocolError> for ReaderError {
    fn from(value: SyncProtocolError) -> Self {
        Self::Protocol(value)
    }
}

impl From<RepositoryError> for ReaderError {
    fn from(_: RepositoryError) -> Self {
        Self::DependencyUnavailable
    }
}

impl From<StoreError> for ReaderError {
    fn from(value: StoreError) -> Self {
        match value {
            // Ein INDIZIERTES Objekt ohne Bytes ist kein „unbekanntes Objekt“
            // des Aufrufers, sondern ein Widerspruch im Bestand des Servers.
            StoreError::NotFound => Self::Internal,
            _ => Self::DependencyUnavailable,
        }
    }
}

impl fmt::Display for ReaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for ReaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for ReaderError {}

/// Die Anfrage eines Lesestapels, wie sie aus Pfad und Abfrage entsteht.
#[derive(Clone, Copy)]
pub struct ReaderBatchRequestV1<'a> {
    pub organization_id: OrganizationId,
    pub chain_id: ChainId,
    pub after_sequence: u64,
    pub after_entry_hash: EntryHash,
    pub cursor_token: Option<&'a [u8]>,
    /// Die Nonce des naechsten Cursors. Sie kommt vom Aufrufer, weil diese
    /// Crate keine Zufallsquelle haelt.
    pub cursor_nonce: [u8; 16],
}

impl fmt::Debug for ReaderBatchRequestV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "ReaderBatchRequestV1(after={})",
            self.after_sequence
        )
    }
}

/// `GET /v1/chains/{chainId}/entries` — ein Lesestapel exakter Objektbytes.
///
/// # Errors
///
/// Jeder Arm von [`ReaderError`].
pub async fn reader_batch(
    request: ReaderBatchRequestV1<'_>,
    ports: &ReaderPorts<'_>,
) -> Result<ReaderBatchV1, ReaderError> {
    let now = ports.clock.now();
    let genesis = is_genesis_start(request.after_sequence, request.after_entry_hash);

    // Die Kette zuerst: eine unbekannte Kette ist `404`, und darueber sagt
    // eine Kopfabweichung nichts.
    if ports
        .entries
        .chain_head(request.organization_id, request.chain_id)
        .await?
        .is_none()
    {
        return Err(ReaderError::ChainUnknown);
    }

    // Der ANGEFRAGTE Startkopf, gegen den tatsaechlichen Eintrag gestellt.
    // Ohne diesen Schritt liefe ein Leser mit einem fremden oder veralteten
    // Kopf weiter, als sei nichts gewesen — und `design.md` §14.5 verlangt
    // ausdruecklich, dass ein „abweichender Startkopf“ den Cursorfortschritt
    // STOPPT.
    if !genesis {
        let sequence = ChainSequence::new(request.after_sequence);
        let bound = ports
            .entries
            .entry_at(request.organization_id, request.chain_id, sequence)
            .await?
            .ok_or(ReaderError::StartHeadMismatch)?;
        if bound.entry_hash != request.after_entry_hash {
            return Err(ReaderError::StartHeadMismatch);
        }
    }

    let scope = TechnicalCursorScopeV1 {
        organization_id: request.organization_id,
        endpoint: EndpointV1::ChainEntries,
        chain_id: Some(request.chain_id),
        start_head_entry_hash: Some(request.after_entry_hash),
    };
    // Ohne Cursor beginnt die Strecke an der angefragten Position; mit Cursor
    // dort, wo die letzte Seite endete. Der Cursor bindet dabei GENAU diese
    // Kette und GENAU diesen Startkopf.
    let after_sequence = match request.cursor_token {
        Some(token) => {
            TechnicalCursorV1::open(token, ports.signer, now, &scope)?.last_technical_index()
        }
        None => request.after_sequence,
    };

    let indexed = ports
        .entries
        .entries_after(
            request.organization_id,
            request.chain_id,
            ChainSequence::new(after_sequence),
            MAX_ENTRIES_PER_PAGE_V1,
        )
        .await?;

    let mut page = PageBuilder::default();
    let mut covered_through = after_sequence;
    let mut truncated = false;
    for entry in &indexed {
        if page.would_overflow() {
            truncated = true;
            break;
        }
        accumulate_entry(
            request.organization_id,
            request.chain_id,
            entry,
            ports,
            &mut page,
        )
        .await?;
        covered_through = entry.sequence.get();
    }

    // Ein Cursor entsteht NUR, wenn es wirklich weitergeht: entweder wurde die
    // Indexabfrage voll ausgeschoepft, oder die Seitendecke hat abgeschnitten.
    // Eine leere oder halbe Seite ist die letzte, und `next-cursor` ist `null`.
    let more_pages = truncated || indexed.len() == MAX_ENTRIES_PER_PAGE_V1;
    let next_cursor = if more_pages && !indexed.is_empty() {
        Some(
            issue_cursor(
                request.organization_id,
                request.chain_id,
                request.after_entry_hash,
                covered_through,
                request.cursor_nonce,
                now,
                ports.signer,
            )?
            .token_bytes()
            .to_vec(),
        )
    } else {
        None
    };

    Ok(ReaderBatchV1::new(
        request.chain_id,
        request.after_sequence,
        request.after_entry_hash,
        request.after_entry_hash,
        page.finish(),
        next_cursor,
        covered_through,
    )?)
}

/// Die Objekte EINER Seite, duplikatfrei gesammelt.
///
/// Ein `BTreeMap` und keine `Vec`: der Registrierungskopf einer Kette
/// wiederholt sich ueber viele Eintraege, und `reader-batch-v1` verlangt eine
/// bytweise aufsteigende, DUPLIKATFREIE Objektliste. Die Sortierung faellt
/// dabei von selbst an, weil `ObjectHash` bytweise ordnet.
#[derive(Default)]
struct PageBuilder {
    records: std::collections::BTreeMap<[u8; 32], Vec<u8>>,
    bytes: usize,
}

impl PageBuilder {
    /// `true`, sobald die Seite ihre Satz- oder ihre Bytedecke erreicht hat.
    ///
    /// Gefragt wird VOR dem naechsten Eintrag und nicht danach: die Decke
    /// begrenzt, was der Server akkumuliert, und nicht erst, was er ausliefert.
    fn would_overflow(&self) -> bool {
        self.records.len() >= MAX_READER_PAGE_OBJECTS_V1 || self.bytes >= MAX_READER_PAGE_BYTES_V1
    }

    fn insert(&mut self, hash: ObjectHash, bytes: Vec<u8>) {
        if let std::collections::btree_map::Entry::Vacant(slot) =
            self.records.entry(*hash.as_bytes())
        {
            self.bytes = self.bytes.saturating_add(bytes.len());
            slot.insert(bytes);
        }
    }

    fn finish(self) -> Vec<ObjectRecordV1> {
        self.records
            .into_iter()
            .map(|(hash, bytes)| {
                ObjectRecordV1::new(
                    ObjectHash::try_from(&hash[..])
                        .unwrap_or_else(|_| unreachable!("a stored key is 32 bytes")),
                    bytes,
                )
            })
            .collect()
    }
}

/// Alle Objekte EINES Eintrags: `.eip`/`.eds`, Quittung, Checkpoint, der
/// gebundene Registrierungskopf und jeder AUSLIEFERBARE Grant.
///
/// Das ist die Menge, die `design.md` §14.5 nennt — „die dazugehoerigen
/// `.eip`/`.eds`, Grants, Trust-, Receipt- und Evidence-Objekte“. Sie wird
/// GANZ oder gar nicht aufgenommen: ein halber Eintrag waere fuer den
/// Empfaenger eine Luecke und keine Seite.
///
/// # Die beiden Filter gelten HIER genauso
///
/// Der Lesestapel ist der Weg, ueber den ein Reader tatsaechlich
/// synchronisiert — er ist damit der WICHTIGSTE Auslieferungspfad und nicht
/// eine Nebenflaeche. Beide Sperren aus [`grant_list`] wirken deshalb auch
/// hier, und zwar Wort fuer Wort dieselben:
///
/// 1. Ein laufender Vernichtungsvorgang sperrt die Auslieferung der Grants
///    dieses Eintrags (`design.md` §16.3, Schritt 2). In dieser Stufe ist die
///    Sperre der EINZIGE Schutz: es gibt noch keinen `.eds`-Stub, das `.eip`
///    liegt unveraendert da, und ein Grant, der weiter hinausgeht, macht die
///    ganze Sperre wirkungslos.
/// 2. Ein abgelaufener historischer Grant wird nicht ausgeliefert
///    (`design.md` §13.3, ohne Einschraenkung auf einen Endpunkt).
///
/// # Warum der Stapel dabei OMITTIERT und nicht abweist
///
/// [`grant_list`] weist einen Vernichtungsziel-Eintrag mit `422` ab, und das
/// ist dort richtig: dieser Endpunkt liefert AUSSCHLIESSLICH Grants, eine
/// leere Antwort waere eine Auskunft ueber den Bestand, die er nicht geben
/// soll. Der Lesestapel liest dagegen die KETTE. Ihn wegen eines einzigen
/// Zieleintrags ganz abzuweisen spraeche dem Leser den Zugang zu jeder
/// anderen Kettenposition ab — und `design.md` §16.3, Schritt 6 haelt
/// ausdruecklich fest, dass „Writer-Signatur, `entryHash` und
/// Kettenkontinuitaet ueber den Stub pruefbar bleiben“. Der Eintrag, seine
/// Quittung, sein Checkpoint und sein Registrierungskopf gehen deshalb weiter
/// hinaus; seine Grants nicht. Die REGEL ist in beiden Pfaden dieselbe — kein
/// Grant eines Zieleintrags verlaesst den Server —, nur die Antwortform
/// unterscheidet sich, und zwar begruendet.
async fn accumulate_entry(
    organization_id: OrganizationId,
    chain_id: ChainId,
    entry: &crate::models::EntryIndexEntryV1,
    ports: &ReaderPorts<'_>,
    page: &mut PageBuilder,
) -> Result<(), ReaderError> {
    let mut hashes = vec![
        entry.entry_object_hash,
        entry.receipt_object_hash,
        entry.registry_head_hash,
    ];
    if let Some(checkpoint) = ports
        .entries
        .checkpoint_covering(organization_id, chain_id, entry.sequence)
        .await?
    {
        hashes.push(checkpoint);
    }
    if !ports
        .destructions
        .is_destruction_target(organization_id, entry.entry_hash)
        .await?
    {
        let now = ports.clock.now();
        for grant in ports
            .entries
            .grants_of(organization_id, entry.entry_hash)
            .await?
        {
            if grant.expires_at.is_some_and(|expires| now > expires) {
                continue;
            }
            hashes.push(grant.object_hash);
        }
    }
    for hash in hashes {
        page.insert(hash, exact_object_bytes(hash, ports).await?);
    }
    Ok(())
}

/// Die exakten Bytes eines indizierten Objekts, gegen SEINE Adresse gestellt.
///
/// Der Rueckvergleich ist die einzige Aussage, die diese Schicht ueber die
/// Bytes trifft: sie sind das Objekt, unter dessen Hash sie stehen. Alles
/// Weitere prueft der Empfaenger.
async fn exact_object_bytes(
    hash: ObjectHash,
    ports: &ReaderPorts<'_>,
) -> Result<Vec<u8>, ReaderError> {
    let bytes = ports
        .objects
        .get_exact(hash)
        .await?
        .collect()
        .await
        .map_err(|_| ReaderError::DependencyUnavailable)?
        .into_bytes()
        .to_vec();
    if ea_crypto::object_hash(&bytes) != hash {
        return Err(ReaderError::Internal);
    }
    Ok(bytes)
}

fn issue_cursor(
    organization_id: OrganizationId,
    chain_id: ChainId,
    start_head_entry_hash: EntryHash,
    last_sequence: u64,
    nonce: [u8; 16],
    now: UnixMillis,
    signer: &dyn ServerSigner,
) -> Result<TechnicalCursorV1, ReaderError> {
    Ok(TechnicalCursorV1::issue(
        &TechnicalCursorFieldsV1 {
            organization_id,
            endpoint: EndpointV1::ChainEntries,
            chain_id: Some(chain_id),
            start_head_entry_hash: Some(start_head_entry_hash),
            last_technical_index: last_sequence,
            expires_at: UnixMillis::new(
                now.get()
                    .checked_add(READER_CURSOR_TTL_MILLIS_V1)
                    .ok_or(ReaderError::Internal)?,
            ),
            nonce,
        },
        signer,
    )?)
}

/// Ein Objekt, wie `GET /v1/objects/{objectHash}` es ausliefert.
///
/// Der Typ traegt Laenge und Digest, aber NICHT die Bytes: die reisen als
/// Strom, und der Sinn dieser Trennung ist, dass sie nie vollstaendig im
/// Speicher liegen.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ObjectResponseHeadV1 {
    pub object_type: ObjectTypeV1,
    pub object_hash: ObjectHash,
    pub byte_length: u64,
    /// Der RFC-9530-Digest ueber GENAU die uebertragenen Bytes — blankes
    /// SHA-256 und ausdruecklich nicht der domaenengetrennte `objectHash`.
    pub content_digest: Hash32,
}

impl fmt::Debug for ObjectResponseHeadV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "ObjectResponseHeadV1({} bytes)",
            self.byte_length
        )
    }
}

/// Bereitet `GET /v1/objects/{objectHash}` vor: Index, Digest und Laenge.
///
/// Der Strom wird dabei EINMAL durchlaufen und nicht gehalten — es werden nur
/// zwei Hasher gefuettert und Bytes gezaehlt. Der Aufrufer holt die Bytes
/// danach ein zweites Mal und reicht sie unveraendert weiter; erst so kann der
/// `content-digest` in den Kopfzeilen stehen, ohne dass der Koerper gepuffert
/// wird.
///
/// # Errors
///
/// [`ReaderError::ObjectUnknown`] fuer ein Objekt, das diese Organisation
/// nicht fuehrt, sowie jeden Ausfallbefund.
pub async fn object_response_head(
    organization_id: OrganizationId,
    object_hash: ObjectHash,
    ports: &ReaderPorts<'_>,
) -> Result<ObjectResponseHeadV1, ReaderError> {
    // ORGANISATIONSGEBUNDEN: ein Objekt einer fremden Organisation ist diesem
    // Aufrufer unbekannt, und `404` sagt weniger als `403` — schon die
    // Auskunft „gibt es, darfst du aber nicht“ waere eine Aussage ueber einen
    // fremden Bestand.
    let indexed: IndexedObjectV1 = ports
        .object_types
        .indexed_object(organization_id, object_hash)
        .await?
        .ok_or(ReaderError::ObjectUnknown)?;

    let mut stream = ports
        .objects
        .get_exact_in(indexed.kind, object_hash)
        .await?;
    let mut address = StreamingObjectHasher::new();
    let mut transferred = Sha256::new();
    let mut length: u64 = 0;
    while let Some(chunk) = stream
        .next()
        .await
        .transpose()
        .map_err(|_| ReaderError::DependencyUnavailable)?
    {
        address.update(&chunk);
        transferred.update(&chunk);
        length = length.saturating_add(chunk.len() as u64);
    }
    if address.finish() != object_hash {
        return Err(ReaderError::Internal);
    }
    let digest: [u8; 32] = transferred.finalize().into();
    Ok(ObjectResponseHeadV1 {
        object_type: indexed.kind,
        object_hash,
        byte_length: length,
        content_digest: Hash32::try_from(&digest[..])
            .unwrap_or_else(|_| unreachable!("SHA-256 always emits exactly 32 bytes")),
    })
}

/// `GET /v1/entries/{entryHash}/grants` — die Grants eines Eintrags.
///
/// Zwei Filter liegen VOR der Auslieferung, und beide sind fail-closed:
///
/// 1. Ein laufender Vernichtungsvorgang sperrt die Auslieferung
///    (`design.md` §16.3, Schritt 2).
/// 2. Ein historischer Grant, dessen Frist abgelaufen ist, wird NICHT
///    ausgeliefert (`design.md` §13.3: „abgelaufene Grants werden weder
///    angenommen noch ausgeliefert“). Die Frist wird dabei ERNEUT gegen die
///    aktuelle Serverzeit gestellt und nicht bei der Annahme abgehakt.
///
/// # Errors
///
/// Jeder Arm von [`ReaderError`], sowie [`crate::destruction::DestructionError::Blocked`]
/// ueber [`GrantListError`].
pub async fn grant_list(
    organization_id: OrganizationId,
    entry_hash: EntryHash,
    ports: &ReaderPorts<'_>,
) -> Result<GrantListResponseV1, GrantListError> {
    if ports
        .entries
        .entry_of(organization_id, entry_hash)
        .await
        .map_err(ReaderError::from)?
        .is_none()
    {
        return Err(GrantListError::Reader(ReaderError::EntryUnknown));
    }
    if ports
        .destructions
        .is_destruction_target(organization_id, entry_hash)
        .await
        .map_err(ReaderError::from)?
    {
        return Err(GrantListError::Blocked);
    }

    let now = ports.clock.now();
    let indexed = ports
        .entries
        .grants_of(organization_id, entry_hash)
        .await
        .map_err(ReaderError::from)?;
    let mut records = Vec::with_capacity(indexed.len().min(MAX_GRANT_PAGE_OBJECTS_V1));
    for grant in indexed {
        if grant.expires_at.is_some_and(|expires| now > expires) {
            continue;
        }
        let bytes = exact_object_bytes(grant.object_hash, ports).await?;
        records.push(ObjectRecordV1::new(grant.object_hash, bytes));
    }
    records.sort_unstable_by(|left, right| {
        left.object_hash()
            .as_bytes()
            .cmp(right.object_hash().as_bytes())
    });
    Ok(GrantListResponseV1::new(entry_hash, records).map_err(ReaderError::from)?)
}

/// Der Befund der Grantliste.
///
/// Eine eigene Familie, weil die Sperre eines Vernichtungsvorgangs weder ein
/// Lese- noch ein Grantformfehler ist: die Identitaet des Aufrufers ist in
/// Ordnung, die Auslieferung ist es nicht.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum GrantListError {
    Reader(ReaderError),
    /// Fuer diesen Eintrag laeuft ein Vernichtungsvorgang.
    Blocked,
}

impl GrantListError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Reader(error) => error.code(),
            Self::Blocked => crate::destruction::DESTRUCTION_BLOCKED_CODE_V1,
        }
    }

    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::Reader(error) => error.http_status(),
            Self::Blocked => 422,
        }
    }

    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(self.http_status(), 429 | 500 | 503)
    }
}

impl From<ReaderError> for GrantListError {
    fn from(value: ReaderError) -> Self {
        Self::Reader(value)
    }
}

impl fmt::Display for GrantListError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for GrantListError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for GrantListError {}

/// `POST /v1/reader-acks` — eine signierte Lesequittung, append-only.
///
/// Die Quittung ist ein SIGNIERTES technisches Objekt und keine Zeile:
/// [`ea_sync_protocol::ReaderAckV1`] rahmt `[core, COSE-Sign1]` und laesst die
/// Signatur ueber `ea-crypto` gegen genau diesen Kern binden. Was hier
/// zusaetzlich geprueft wird, ist die Zuordnung zum AUFRUFER — sonst
/// quittierte ein Geraet fuer ein anderes.
///
/// # Errors
///
/// Jeder Arm von [`ReaderError`].
pub async fn record_reader_ack(
    organization_id: OrganizationId,
    caller_certificate_hash: ea_types::CertificateHash,
    ack: &ReaderAckV1,
    ports: &ReaderPorts<'_>,
) -> Result<(), ReaderError> {
    let core: &ReaderAckCoreV1 = ack.core();
    if core.organization_id != organization_id
        || core.reader_certificate_hash != caller_certificate_hash
    {
        return Err(ReaderError::AckMismatch);
    }

    // Kette, Sequenz und Eintragshash werden in EINEM Zug gebunden: die
    // Quittung nennt alle drei, und nur zusammen sagen sie etwas. Ohne diese
    // Pruefung quittierte ein Leser eine Kettenposition, die der genannte
    // Eintrag gar nicht hat.
    let bound = ports
        .entries
        .entry_at(organization_id, core.chain_id, core.through_sequence)
        .await?
        .ok_or(ReaderError::EntryUnknown)?;
    if bound.entry_hash != core.head_entry_hash {
        return Err(ReaderError::AckMismatch);
    }

    let outcome = ports
        .acks
        .record_reader_ack(ReaderAckCommandV1 {
            organization_id,
            reader_certificate_hash: caller_certificate_hash,
            entry_hash: core.head_entry_hash,
            ack_object_hash: ea_crypto::object_hash(ack.exact_bytes()),
            acknowledged_at: ports.clock.now(),
        })
        .await?;
    match outcome {
        AppendOutcome::Recorded | AppendOutcome::AlreadyRecorded => Ok(()),
        AppendOutcome::Conflict => Err(ReaderError::AckConflict),
    }
}
