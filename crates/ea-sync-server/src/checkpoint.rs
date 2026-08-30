//! Der Standard-Checkpoint und die Checkpoint-KETTE (`design.md` §15.2).
//!
//! # Wo der Checkpoint entsteht — und warum dort
//!
//! IN der Commit-Transaktion. Der Checkpoint wird wie die Quittung VOR der
//! Sperre gebildet, signiert und content-addressed abgelegt, und
//! [`crate::ports::CommitRepository::commit_locked_head`] schaltet ihn
//! GEMEINSAM mit Eintrag, Grants, Objektindex, Quittung und neuem Kettenkopf
//! sichtbar. Das ist die einzige Anordnung, unter der die Zusage „die
//! Checkpoint-Kette gabelt sich nie“ nicht gehofft, sondern erzwungen ist:
//! dieselbe `FOR UPDATE`-Sperre auf dem Kettenkopf, die zwei gleichzeitige
//! Commits derselben Kette hintereinander stellt, stellt damit auch ihre
//! Checkpoints hintereinander. Ein Checkpoint NACH der Transaktion koennte
//! dagegen ausfallen, und dann stuende ein angenommener Eintrag ohne Anker da
//! und `checkpoint-bytes` haenge davon ab, ob ein zweiter Schritt ueberlebt
//! hat.
//!
//! Die NEUN Schritte aus `design.md` §13.3 bleiben davon unberuehrt und
//! werden nicht neu nummeriert: Schritt 7 bildet die Quittung, Schritt 8
//! schaltet sichtbar. Der Checkpoint ist kein zehnter Schritt, sondern der
//! Anker aus §15.2, der an Schritt 8 haengt.
//!
//! # Der abgedeckte Sequenzbereich
//!
//! `covered-from` und `covered-through` fallen zusammen. Ein
//! `checkpoint-core-v1` bindet GENAU EINEN `head-entry-hash` und fuehrt ueber
//! keinen weiteren Eintrag einen Nachweis; ein breiterer Bereich waere eine
//! Behauptung ohne Beleg. Weil jeder angenommene Commit in derselben
//! Transaktion genau einen Checkpoint anlegt, deckt die Kette die
//! Eintragssequenz trotzdem LUECKENLOS ab — Checkpoint N deckt Sequenz N, und
//! `previous-evidence-hash` haelt die Reihenfolge fest.
//!
//! # Was diese Datei nicht tut
//!
//! Sie baut keine zweite Kodierung. Der Kern entsteht in
//! [`ea_format::CheckpointCoreV1`], die Objektbytes ausschliesslich ueber
//! [`ea_format::encode_evidence`]. `CheckpointCoreV1::exact_bytes` ist der
//! KERN und nicht das Objekt; wer ihn fuer die Objektbytes haelt, legt die
//! falschen Bytes ab.
//!
//! Und sie kennt kein RFC-3161-Token. Stufe 6 setzt die CTT-Variante DANEBEN
//! (`ea_format::EvidenceObjectV1::timestamp`) und aendert dabei kein Byte
//! eines historischen Standard-Checkpoints.

use core::fmt;

use ea_crypto::CryptoError;
use ea_format::{
    CheckpointCoreFieldsV1, CheckpointCoreV1, ECP_MAX_RAW_BYTES_V1, EvidenceObjectV1, FormatError,
    encode_evidence,
};
use ea_sync_protocol::{
    CheckpointListResponseV1, EndpointV1, MAX_CHECKPOINT_PAGE_OBJECTS_V1, ObjectRecordV1,
    SyncProtocolError, TechnicalCursorFieldsV1, TechnicalCursorScopeV1, TechnicalCursorV1,
};
use ea_types::{ChainId, ChainSequence, EntryHash, Hash32, ObjectHash, OrganizationId, UnixMillis};

use crate::{
    models::{RepositoryError, StoreError},
    ports::{CheckpointDirectory, ObjectStore, ServerClock, ServerSigner},
};

/// Die Lebensdauer eines Checkpoint-Cursors.
///
/// Der Nachtrag schreibt „ein Gueltigkeitsfenster im Token selbst“ vor und
/// nennt keine Zahl. Fuenfzehn Minuten sind reichlich fuer den naechsten
/// Seitenabruf und kurz genug, dass ein abgefangener Cursor nicht dauerhaft
/// blaettert. Er traegt ohnehin keine fachliche Angabe — nur eine Position.
pub const CHECKPOINT_CURSOR_TTL_MILLIS_V1: i64 = 900_000;

/// Alles, was ein Standard-Checkpoint BINDET.
///
/// Die Ausstellungszeit steht bewusst NICHT darin: sie ist die Annahmezeit
/// des Commits, den dieser Checkpoint ankert, und wird deshalb von
/// [`build_checkpoint`] als eigenes Argument genommen — genauso, wie
/// [`crate::receipt::build_receipt`] seine Annahmezeit nimmt.
///
/// Abdruck und Zertifikat des Servers fehlen aus dem Grund, aus dem sie auch
/// der Quittungsbindung fehlen: sie kommen aus dem [`ServerSigner`], der auch
/// signiert.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CheckpointBindingV1 {
    pub organization_id: OrganizationId,
    pub chain_id: ChainId,
    /// Die Sequenz des Kopf-Eintrags. Sie ist zugleich `covered-from` und
    /// `covered-through`.
    pub covered_sequence: ChainSequence,
    pub head_entry_hash: EntryHash,
    pub registry_head_hash: Hash32,
    /// `None` genau fuer den ersten Checkpoint einer Kette.
    pub previous_evidence_hash: Option<ObjectHash>,
}

impl fmt::Debug for CheckpointBindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "CheckpointBindingV1(covered={})",
            self.covered_sequence.get()
        )
    }
}

/// Warum ein Checkpoint nicht entstand oder nicht gelten darf.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CheckpointError {
    /// Der eingefrorene Konstruktor von `checkpoint-core-v1` weist die Felder
    /// ab, oder der Kodierer weist das Evidence-Objekt ab.
    Shape,
    /// Der Serverschluessel konnte nicht signieren, oder die Signatur bindet
    /// nicht an den Kern.
    Signature,
    /// Die zurueckgelesenen Bytes sind NICHT die gespeicherten.
    ReadBack,
    /// Der genannte Vorgaenger ist nicht der Kopf der Checkpoint-Kette. Die
    /// Kette gabelte sich sonst, und zwei Anker derselben Kette
    /// widerspraechen einander.
    PredecessorConflict,
}

impl CheckpointError {
    /// Alle Arme — damit ein spaeter ergaenzter sofort auffaellt.
    pub const ALL: [Self; 4] = [
        Self::Shape,
        Self::Signature,
        Self::ReadBack,
        Self::PredecessorConflict,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Shape => "EA-CHECKPOINT-SHAPE",
            Self::Signature => "EA-CHECKPOINT-SIGNATURE",
            Self::ReadBack => "EA-CHECKPOINT-READ-BACK",
            Self::PredecessorConflict => "EA-CHECKPOINT-PREDECESSOR-CONFLICT",
        }
    }

    /// Der Vorgaengerkonflikt ist die 409-Zeile der Abbildung — „Fork,
    /// Kopfabweichung, …“. Alles uebrige ist ein interner Fehler: ein
    /// Aufrufer kann an der Form eines Checkpoints nichts falsch machen, weil
    /// der Server ihn selbst bildet.
    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::PredecessorConflict => 409,
            _ => 500,
        }
    }

    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(self.http_status(), 429 | 500 | 503)
    }
}

impl From<FormatError> for CheckpointError {
    fn from(value: FormatError) -> Self {
        match value {
            FormatError::Cose => Self::Signature,
            _ => Self::Shape,
        }
    }
}

impl From<CryptoError> for CheckpointError {
    fn from(_: CryptoError) -> Self {
        Self::Signature
    }
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for CheckpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for CheckpointError {}

/// Ein fertiger Standard-Checkpoint: Kern, exakte `.ecp`-Bytes und Adresse.
///
/// Die drei gehoeren zusammen und werden deshalb zusammen herausgegeben. Wer
/// nur die Bytes bekaeme, muesste die Adresse selbst rechnen — und eine
/// zweite Stelle, die einen Objekthash bildet, ist eine Stelle zu viel.
#[derive(Clone, Eq, PartialEq)]
pub struct StandardCheckpointV1 {
    core: CheckpointCoreV1,
    exact_bytes: Vec<u8>,
    object_hash: ObjectHash,
}

impl StandardCheckpointV1 {
    #[must_use]
    pub const fn core(&self) -> &CheckpointCoreV1 {
        &self.core
    }

    /// Die EXAKTEN archivierten `.ecp`-Bytes.
    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    #[must_use]
    pub const fn object_hash(&self) -> ObjectHash {
        self.object_hash
    }
}

impl fmt::Debug for StandardCheckpointV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StandardCheckpointV1(<bound>)")
    }
}

/// `checkpoint-core-v1` bilden, signieren und als `.ecp` kodieren — EINMAL.
///
/// Die Positionen sind die eingefrorenen aus `design.md` §15.3: Objektversion,
/// die feste Domaene `EINSATZARCHIV-CHECKPOINT-v1`, Organisation, Kette,
/// abgedeckter Bereich, Kopf-Eintragshash, Registry-Head, `issuedAtServer`
/// und `previous-evidence-hash`. Signiert wird ueber die Domaenentrennung des
/// Content-Types [`ea_crypto::ContentType::CheckpointCbor`] — die
/// Zweckbindung laeuft ueber die Domaene und nicht ueber eine achte
/// `CertificateCapability`.
///
/// # Errors
///
/// [`CheckpointError::Shape`] oder [`CheckpointError::Signature`].
pub fn build_checkpoint(
    binding: CheckpointBindingV1,
    issued_at_server: UnixMillis,
    signer: &dyn ServerSigner,
) -> Result<StandardCheckpointV1, CheckpointError> {
    let core = CheckpointCoreV1::new(CheckpointCoreFieldsV1 {
        organization_id: binding.organization_id,
        chain_id: binding.chain_id,
        covered_from_sequence: binding.covered_sequence,
        covered_through_sequence: binding.covered_sequence,
        head_entry_hash: binding.head_entry_hash,
        registry_head_hash: binding.registry_head_hash,
        issued_at_server,
        previous_evidence_hash: binding.previous_evidence_hash,
    })?;
    // Die Signatur laeuft ueber die KERNBYTES, die `CheckpointCoreV1` gerade
    // gebildet hat — nicht ueber eine zweite Kodierung derselben Felder.
    let signature = signer.sign_checkpoint(core.exact_bytes())?;
    // `EvidenceObjectV1::standard` prueft die Signatur gegen den Kern zurueck:
    // Content-Type, Nutzlast und die Abwesenheit eines Zeitstempeltokens. Ein
    // Checkpoint, dessen Signatur nicht an seinen eigenen Kern bindet,
    // entsteht hier gar nicht erst.
    let evidence = EvidenceObjectV1::standard(core, signature)?;
    let exact_bytes = encode_evidence(&evidence)?.into_vec();
    if exact_bytes.len() > ECP_MAX_RAW_BYTES_V1 {
        return Err(CheckpointError::Shape);
    }
    let object_hash = ea_crypto::object_hash(&exact_bytes);
    // Der Kern wird aus den ARCHIVIERTEN Bytes zurueckgelesen und nicht
    // weitergereicht: was der Aufrufer sieht, ist damit das, was im Archiv
    // steht, und nicht das, was der Erbauer gemeint hat.
    let ea_format::DecodedEvidencePayloadV1::Standard { core, .. } = evidence.decoded_payload()?
    else {
        return Err(CheckpointError::Shape);
    };
    Ok(StandardCheckpointV1 {
        core,
        exact_bytes,
        object_hash,
    })
}

/// Was die Checkpoint-Seite an Ports braucht.
pub struct CheckpointPorts<'a> {
    pub clock: &'a dyn ServerClock,
    pub signer: &'a dyn ServerSigner,
    pub objects: &'a dyn ObjectStore,
    pub checkpoints: &'a dyn CheckpointDirectory,
}

/// Jeder Befund der Checkpoint-Seite.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CheckpointPageError {
    /// Ein durchgereichter Rahmen- oder Cursorbefund.
    Protocol(SyncProtocolError),
    /// Datenbank oder Object Store antworten nicht.
    DependencyUnavailable,
    /// Interner Fehler ohne fachliche Ursache.
    Internal,
}

impl CheckpointPageError {
    /// Die Arme ohne Nutzlast — damit ein spaeter ergaenzter auffaellt.
    pub const ALL: [Self; 2] = [Self::DependencyUnavailable, Self::Internal];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Protocol(error) => error.code(),
            Self::DependencyUnavailable => "EA-CHECKPOINT-DEPENDENCY-UNAVAILABLE",
            Self::Internal => "EA-CHECKPOINT-INTERNAL",
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

impl From<SyncProtocolError> for CheckpointPageError {
    fn from(value: SyncProtocolError) -> Self {
        Self::Protocol(value)
    }
}

impl From<RepositoryError> for CheckpointPageError {
    fn from(_: RepositoryError) -> Self {
        Self::DependencyUnavailable
    }
}

impl From<StoreError> for CheckpointPageError {
    fn from(value: StoreError) -> Self {
        match value {
            // Ein indizierter Checkpoint ohne Bytes ist kein „unbekanntes
            // Objekt“ des Aufrufers, sondern ein Widerspruch im Bestand des
            // Servers.
            StoreError::NotFound => Self::Internal,
            _ => Self::DependencyUnavailable,
        }
    }
}

impl fmt::Display for CheckpointPageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for CheckpointPageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for CheckpointPageError {}

/// `GET /v1/checkpoints?after={cursor}` — eine Seite exakter `.ecp`-Bytes.
///
/// Die Seite waehlt ihre Saetze in TECHNISCHER Reihenfolge — nach der
/// Blaetterposition, auf die der Cursor zeigt — und liefert sie nach
/// OBJEKTHASH sortiert aus: `checkpoint-list-response-v1` verlangt eine
/// bytweise aufsteigende, duplikatfreie Objektliste. Beides widerspricht sich
/// nicht, weil die Liste ohnehin nicht autoritativ ist: die Reihenfolge der
/// Kette steht in den Objekten selbst, in `previous-evidence-hash`.
///
/// Ein Cursor wird nur herausgegeben, wenn die Seite VOLL war. Eine leere
/// oder halbe Seite ist die letzte, und `next-cursor` ist dann `null`.
///
/// `cursor_nonce` kommt vom Aufrufer, weil diese Crate keine Zufallsquelle
/// haelt: die des Prozesses liegt in `apps/server` beim TLS-Anbieter.
///
/// # Errors
///
/// Jeder Arm von [`CheckpointPageError`].
pub async fn checkpoint_page(
    organization_id: OrganizationId,
    cursor_token: Option<&[u8]>,
    cursor_nonce: [u8; 16],
    ports: &CheckpointPorts<'_>,
) -> Result<CheckpointListResponseV1, CheckpointPageError> {
    let now = ports.clock.now();
    let scope = TechnicalCursorScopeV1 {
        organization_id,
        endpoint: EndpointV1::Checkpoints,
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
        .checkpoints
        .checkpoints_after(
            organization_id,
            after_technical_index,
            MAX_CHECKPOINT_PAGE_OBJECTS_V1,
        )
        .await?;
    // Die letzte Blaetterposition VOR dem Sortieren: sie folgt der
    // technischen Reihenfolge und nicht der Ausgabereihenfolge.
    let last_technical_index = indexed.last().map(|entry| entry.technical_index);
    let full_page = indexed.len() == MAX_CHECKPOINT_PAGE_OBJECTS_V1;

    let mut records = Vec::with_capacity(indexed.len());
    for entry in indexed {
        let stream = ports.objects.get_exact(entry.object_hash).await?;
        let bytes = stream
            .collect()
            .await
            .map_err(|_| CheckpointPageError::DependencyUnavailable)?
            .into_bytes()
            .to_vec();
        // Der Beweis, dass die gelieferten Bytes DIESES Objekt sind: ihr Hash
        // gegen den Hash, unter dem sie stehen.
        if ea_crypto::object_hash(&bytes) != entry.object_hash {
            return Err(CheckpointPageError::Internal);
        }
        records.push(ObjectRecordV1::new(entry.object_hash, bytes));
    }
    records.sort_unstable_by(|left, right| {
        left.object_hash()
            .as_bytes()
            .cmp(right.object_hash().as_bytes())
    });

    let next_cursor = match (full_page, last_technical_index) {
        (true, Some(last)) => Some(
            TechnicalCursorV1::issue(
                &TechnicalCursorFieldsV1 {
                    organization_id,
                    endpoint: EndpointV1::Checkpoints,
                    chain_id: None,
                    start_head_entry_hash: None,
                    last_technical_index: last,
                    expires_at: UnixMillis::new(
                        now.get()
                            .checked_add(CHECKPOINT_CURSOR_TTL_MILLIS_V1)
                            .ok_or(CheckpointPageError::Internal)?,
                    ),
                    nonce: cursor_nonce,
                },
                ports.signer,
            )?
            .token_bytes()
            .to_vec(),
        ),
        _ => None,
    };

    Ok(CheckpointListResponseV1::new(
        cursor_token.map(<[u8]>::to_vec),
        records,
        next_cursor,
    )?)
}
