//! Schritt 7 von `design.md` §13.3: die Quittung, GENAU EINMAL gebildet.
//!
//! # Was diese Datei nicht tut
//!
//! Sie baut KEINE zweite Kodierung. Die Kernbytes entstehen in
//! [`ea_format::ReceiptCoreV1`], die Objektbytes ausschliesslich ueber
//! [`ea_format::encode_receipt`]. `ReceiptCoreV1::exact_bytes` ist der KERN
//! und nicht das Objekt; wer ihn fuer die Objektbytes haelt, friert die
//! falschen Bytes ein.
//!
//! # Die drei Zahlen, die nur einmal entstehen
//!
//! `design.md`:1547 ist an dieser Stelle woertlich: „Annahmezeit, Due-Zeit und
//! Signatur werden bei einem Commit nie neu berechnet." Deshalb steht hier
//! [`accepted_at`] als EINE Funktion, deren Ergebnis der Aufrufer weiterreicht,
//! und deshalb rechnet [`build_receipt`] die Faelligkeit aus genau der
//! Annahmezeit, mit der es aufgerufen wurde — es holt sich keine zweite Zeit.
//!
//! # Standardprofil und Evidence Grade
//!
//! `design.md`:929: im Standardprofil ist `evidence-due-at = null`, im
//! Evidence-Grade-Profil gilt exakt `accepted-at-server +
//! policy.evidenceMaxDelayMs`. Ein Ueberlauf ist UNGUELTIG und wird nicht
//! gekappt: eine gekappte Frist waere eine Frist, die der Server erfunden hat.
//! Welches Profil gilt, sagt `policy.operating_profile` — derselbe Wert, an
//! dem `crates/ea-writer/src/finalize.rs`:1177 Evidence Grade erkennt.

use core::fmt;

use ea_crypto::CryptoError;
use ea_format::{
    FormatError, PolicyFieldsV1, ReceiptCoreFieldsV1, ReceiptCoreV1, ReceiptV1, encode_receipt,
};
use ea_types::{
    ChainId, ChainSequence, EntryHash, Hash32, ObjectHash, OrganizationId, RegistryVersion,
    UnixMillis,
};

use crate::ports::ServerSigner;

/// Der Wert von `operatingProfile`, der Evidence Grade bezeichnet.
///
/// `policy-core-v1` laesst `0..1` zu (`crates/ea-format/src/etb.rs`:1603);
/// `1` ist Evidence Grade, `0` das Standardprofil.
const EVIDENCE_GRADE_OPERATING_PROFILE_V1: u8 = 1;

/// Alles, was eine Quittung BINDET — ohne die drei Zahlen, die der Server
/// selbst festlegt.
///
/// Annahmezeit, Faelligkeit und Signatur stehen bewusst NICHT darin: sie
/// entstehen in [`build_receipt`] und nirgends sonst. Waeren sie Felder dieser
/// Struktur, koennte ein Aufrufer sie zweimal verschieden setzen — und genau
/// das verbietet Schritt 7.
///
/// Der Serverabdruck und der Serverzertifikatshash fehlen aus demselben Grund:
/// sie kommen aus dem [`ServerSigner`], der auch signiert. Ein Aufrufer, der
/// sie danebenlegen koennte, koennte eine Quittung unter einem fremden
/// Zertifikat ausstellen lassen.
#[derive(Clone, Eq, PartialEq)]
pub struct ReceiptBindingV1 {
    pub organization_id: OrganizationId,
    pub chain_id: ChainId,
    pub chain_sequence: ChainSequence,
    pub entry_hash: EntryHash,
    pub entry_object_hash: ObjectHash,
    /// `None` genau fuer die erste Sequenz einer Kette.
    pub previous_entry_hash: Option<EntryHash>,
    pub registry_version: RegistryVersion,
    pub registry_head_hash: Hash32,
    pub policy_object_hash: ObjectHash,
    pub initial_grant_plan_hash: Hash32,
    /// In BELIEBIGER Reihenfolge; [`build_receipt`] sortiert sie bytweise und
    /// weist Duplikate ab. Die Sortierung gehoert zur Quittung, nicht zum
    /// Aufrufer.
    pub initial_grant_object_hashes: Vec<ObjectHash>,
}

impl fmt::Debug for ReceiptBindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReceiptBindingV1(<bound>)")
    }
}

/// Warum eine Quittung nicht entstand.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ReceiptError {
    /// Die Grant-Hashes sind leer oder tragen ein Duplikat.
    GrantHashes,
    /// `accepted-at-server + policy.evidenceMaxDelayMs` laeuft ueber. Nicht
    /// gekappt: eine gekappte Frist waere eine erfundene Frist.
    EvidenceOverflow,
    /// Der eingefrorene Konstruktor von `receipt-core-v1` weist die Felder ab.
    Shape,
    /// Der Serverschluessel konnte nicht signieren, oder die Signatur bindet
    /// nicht an den Kern.
    Signature,
    /// Die zurueckgelesenen Bytes sind NICHT die gespeicherten
    /// (`design.md` §13.3, Schritt 9).
    ReadBack,
}

impl ReceiptError {
    /// Alle Arme — damit eine spaeter ergaenzte Bedingung sofort auffaellt.
    pub const ALL: [Self; 5] = [
        Self::GrantHashes,
        Self::EvidenceOverflow,
        Self::Shape,
        Self::Signature,
        Self::ReadBack,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::GrantHashes => "EA-RECEIPT-GRANT-HASHES",
            Self::EvidenceOverflow => "EA-RECEIPT-EVIDENCE-OVERFLOW",
            Self::Shape => "EA-RECEIPT-SHAPE",
            Self::Signature => "EA-RECEIPT-SIGNATURE",
            Self::ReadBack => "EA-RECEIPT-READ-BACK",
        }
    }
}

impl From<FormatError> for ReceiptError {
    fn from(value: FormatError) -> Self {
        match value {
            FormatError::Duplicate | FormatError::Unsorted => Self::GrantHashes,
            FormatError::Cose => Self::Signature,
            _ => Self::Shape,
        }
    }
}

impl From<CryptoError> for ReceiptError {
    fn from(_: CryptoError) -> Self {
        Self::Signature
    }
}

impl fmt::Display for ReceiptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for ReceiptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for ReceiptError {}

/// `acceptedAtServer` — Schritt 5 von `design.md` §13.3.
///
/// Das Maximum aus aktueller UTC-Serverzeit und der Annahmezeit des DIREKTEN
/// Vorgaengers. `design.md`:929 verlangt, dass die Annahmezeit je Kette nicht
/// unter die des vorherigen Receipts faellt; eine rueckwaerts laufende
/// Serveruhr darf die Kette deshalb nicht mitnehmen.
///
/// Die Funktion ist INFALLIBEL: ein Maximum zweier Zeitpunkte kann nicht
/// scheitern, und ein `Result` haette hier keinen Arm.
#[must_use]
pub fn accepted_at(server_now: UnixMillis, predecessor: Option<UnixMillis>) -> UnixMillis {
    predecessor.map_or(server_now, |previous| {
        if previous.get() > server_now.get() {
            previous
        } else {
            server_now
        }
    })
}

/// `evidenceDueAt` — Standardprofil `null`, Evidence Grade exakte Addition.
///
/// # Errors
///
/// [`ReceiptError::EvidenceOverflow`], wenn `accepted + delay` den
/// Wertebereich verlaesst.
pub fn evidence_due_at(
    policy: &PolicyFieldsV1,
    accepted_at_server: UnixMillis,
) -> Result<Option<UnixMillis>, ReceiptError> {
    if policy.operating_profile != EVIDENCE_GRADE_OPERATING_PROFILE_V1 {
        return Ok(None);
    }
    let delay =
        i64::try_from(policy.evidence_max_delay_ms).map_err(|_| ReceiptError::EvidenceOverflow)?;
    accepted_at_server
        .get()
        .checked_add(delay)
        .map(UnixMillis::new)
        .map(Some)
        .ok_or(ReceiptError::EvidenceOverflow)
}

/// Die Grant-Hashes in der Ordnung, die `receipt-core-v1` verlangt.
///
/// Bytweise aufsteigend und duplikatfrei. SORTIERT wird hier, ABGEWIESEN wird
/// nur das Duplikat: die Reihenfolge auf der Leitung ist eine
/// Transporteigenschaft, ein doppelter Grant dagegen ein Widerspruch.
fn sorted_grant_object_hashes(hashes: &[ObjectHash]) -> Result<Vec<ObjectHash>, ReceiptError> {
    if hashes.is_empty() {
        return Err(ReceiptError::GrantHashes);
    }
    let mut sorted = hashes.to_vec();
    sorted.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ReceiptError::GrantHashes);
    }
    Ok(sorted)
}

/// Schritt 7: `receipt-core-v1` bilden, signieren, EINMAL.
///
/// Gebunden werden Richtlinienhash, Registry-Head, Planhash, Entry-, Objekt-
/// und Vorgaengerhash sowie Abdruck und Zertifikat des Servers; das
/// Erweiterungsarray bleibt leer (`crates/ea-format/src/esr.rs`). Signiert wird
/// der Receipt-DIGEST ueber die Domaenentrennung des Content-Types
/// [`ea_crypto::ContentType::ReceiptDigest`] — die Zweckbindung
/// `serverReceipt` laeuft ueber die Domaene und nicht ueber eine achte
/// `CertificateCapability`.
///
/// # Errors
///
/// Jeder Arm von [`ReceiptError`] ausser [`ReceiptError::ReadBack`]: der
/// entsteht erst in Schritt 9, nach dem Commit.
pub fn build_receipt(
    binding: ReceiptBindingV1,
    policy: &PolicyFieldsV1,
    accepted_at_server: UnixMillis,
    signer: &dyn ServerSigner,
) -> Result<ReceiptV1, ReceiptError> {
    let initial_grant_object_hashes =
        sorted_grant_object_hashes(&binding.initial_grant_object_hashes)?;
    let evidence_due_at = evidence_due_at(policy, accepted_at_server)?;
    let core = ReceiptCoreV1::new(ReceiptCoreFieldsV1 {
        organization_id: binding.organization_id,
        chain_id: binding.chain_id,
        chain_sequence: binding.chain_sequence,
        entry_hash: binding.entry_hash,
        entry_object_hash: binding.entry_object_hash,
        previous_entry_hash: binding.previous_entry_hash,
        registry_version: binding.registry_version,
        registry_head_hash: binding.registry_head_hash,
        policy_object_hash: binding.policy_object_hash,
        initial_grant_plan_hash: binding.initial_grant_plan_hash,
        initial_grant_object_hashes,
        accepted_at_server,
        evidence_due_at,
        server_key_thumbprint: signer.key_thumbprint(),
        server_certificate_hash: signer.certificate_hash(),
    })?;
    // Die Signatur laeuft ueber die KERNBYTES, die `ReceiptCoreV1` gerade
    // gebildet hat — nicht ueber eine zweite Kodierung derselben Felder.
    let signature = signer.sign_receipt(core.exact_bytes())?;
    // `ReceiptV1::new` prueft die Signatur gegen den Kern zurueck: Content-Type,
    // Abdruck, Zertifikat und Receipt-Digest. Eine Quittung, deren Signatur
    // nicht an ihren eigenen Kern bindet, entsteht hier gar nicht erst.
    Ok(ReceiptV1::new(core, signature)?)
}

/// Die EXAKTEN `.esr`-Objektbytes einer Quittung.
///
/// Die eine Stelle, an der Objektbytes entstehen. Sie ruft
/// [`ea_format::encode_receipt`] und sonst nichts — insbesondere nicht
/// `ReceiptCoreV1::exact_bytes`, das den KERN liefert.
///
/// # Errors
///
/// [`ReceiptError::Shape`], wenn der Kodierer die Quittung abweist.
pub fn exact_receipt_bytes(receipt: &ReceiptV1) -> Result<Vec<u8>, ReceiptError> {
    Ok(encode_receipt(receipt)?.into_vec())
}
