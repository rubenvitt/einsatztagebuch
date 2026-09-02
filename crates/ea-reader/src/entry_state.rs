//! Der technische Zustand eines Eintrags und sein verschluesselter Speicher.
//!
//! # Hier entsteht KEIN Literal der drei Aufzaehlungen
//!
//! `ea_types::VerificationStatus` traegt seit Stufe 1 GENAU die sechs
//! Verifikationsbegriffe aus `design.md` §17.4, `ea_types::EntryStatus` die
//! drei Eintragszustaende, und `ea_verify::ServerConfirmationV1` steht in
//! `crates/ea-verify/src/report.rs`. Alle drei werden IMPORTIERT. Eine eigene
//! Aufzaehlung an dieser Stelle waere eine ZWEITE Statussprache neben §17.4,
//! und die zweite verschiebt sich beim naechsten Umbau still.
//!
//! Die Server-Bestaetigung bleibt eine EIGENE Spalte und DARF NICHT in die
//! Verifikation gefaltet werden: §17.4 verbietet die Vermischung ausdruecklich,
//! und der Datei-Modus macht `notServerConfirmed` zum Regelfall.
//!
//! # DEKLARIERT hier, GEFUELLT anderswo
//!
//! [`ReaderEntryStateV1`] entsteht in dieser Aufgabe, weil ein Speicher seinen
//! Werttyp braucht, bevor der Klassifizierer existiert. Gefuellt wird er von
//! `ReaderVerifier::classify` der Aufgabe „Verifikation vor Entschlüsselung,
//! fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert",
//! die ihn ausdruecklich NICHT ein zweites Mal deklariert — ein zweiter Typ
//! daneben waere die zweite Wahrheit.
//!
//! # Warum `detail_code` eine GESCHLOSSENE Tabelle braucht
//!
//! Das Feld traegt `&'static str` und nie Prosa: ein Prosafeld waere derselbe
//! Fehler in klein, und die Werte sind `ObjectErrorV1::code()`-Werte wie
//! `EA-VERIFY-DECRYPT-CEK-UNWRAP-FAILED`. Aus persistierten Bytes entsteht aber
//! kein `&'static str`. Der Speicher schreibt den Code deshalb als Text und
//! loest ihn beim Lesen ueber [`PERSISTED_DETAIL_CODES_V1`] wieder auf; ein
//! Code, der dort nicht steht, ist eine WEIGERUNG und keine stille Naeherung.
//! Die Tabelle ist die einzige Stelle, an der ein persistierter Code wieder
//! statisch wird, und sie waechst in demselben Commit, der einen neuen
//! `ObjectErrorV1`-Code in einen Eintragszustand schreibt. Die Alternative —
//! den Code beim Lesen zu lecken — waere unbeschraenktes Wachstum aus
//! angreiferkontrollierten Bytes.
//!
//! # Der Speicher haelt je `EntryHash` GENAU EINEN Zustand
//!
//! Und keinen fachlichen Wert. Was hier liegt, ist Technik: Hashes, eine
//! Sequenz, drei Statusbegriffe und hoechstens ein Code.

use core::fmt;

use ea_cbor::{ParserLimits, validate};
use ea_crypto::{AEAD_NONCE_SIZE, CEK_SIZE, SecretBytes, SecretVec, aead_open, aead_seal};
use ea_types::{ChainSequence, EntryHash, EntryStatus, ObjectHash, VerificationStatus};
use ea_verify::ServerConfirmationV1;
use minicbor::{Decoder, Encoder};

use crate::blob_store::{ReaderBlobKey, ReaderBlobStore};
use crate::envelope::blob_aad;
use crate::vault::{ReaderVaultError, UnlockedVault};

/// Das Praefix des Adressraums.
const ENTRY_STATE_KEY_PREFIX: &str = "entry-state/";

/// Die Codes, die ein persistierter Eintragszustand tragen DARF.
///
/// Gelesen aus den `ObjectErrorV1::new`-Aufrufstellen von `crates/ea-verify`
/// (`archive.rs`, `destruction.rs`, `evidence.rs`, `recipient.rs`). Die Tabelle
/// steht HIER und nicht in `ea-verify`, weil `ea-verify` sie nicht braucht:
/// dort ist ein Code ein `&'static str` aus dem Programmtext, und nur der
/// Speicher muss ihn aus Bytes zurueckgewinnen.
const PERSISTED_DETAIL_CODES_V1: [&str; 25] = [
    "EA-VERIFY-CHECKPOINT-UNVERIFIABLE",
    "EA-VERIFY-DECRYPT-CEK-UNWRAP-FAILED",
    "EA-VERIFY-DECRYPT-PAYLOAD-OPEN-FAILED",
    "EA-VERIFY-DESTRUCTION-AUTHORIZATION-UNRESOLVED",
    "EA-VERIFY-DESTRUCTION-HEAD-UNAVAILABLE",
    "EA-VERIFY-DESTRUCTION-SIGNATURE-INVALID",
    "EA-VERIFY-DESTRUCTION-SIGNER-MISMATCH",
    "EA-VERIFY-DESTRUCTION-SIGNER-UNAUTHORIZED",
    "EA-VERIFY-DESTRUCTION-UNVERIFIABLE",
    "EA-VERIFY-EVIDENCE-MISSING",
    "EA-VERIFY-EVIDENCE-OVERDUE",
    "EA-VERIFY-EVIDENCE-RENEWAL-INPUT-UNKNOWN",
    "EA-VERIFY-EVIDENCE-TOKEN-NOT-BOUND",
    "EA-VERIFY-GRANT-AUTHORIZATION-UNVERIFIABLE",
    "EA-VERIFY-GRANT-HEAD-UNAVAILABLE",
    "EA-VERIFY-GRANT-ISSUER-UNVERIFIABLE",
    "EA-VERIFY-GRANT-PLAN-MISMATCH",
    "EA-VERIFY-MANIFEST-SIGNATURE-INVALID",
    "EA-VERIFY-MANIFEST-SIGNER-MISMATCH",
    "EA-VERIFY-MANIFEST-SIGNER-UNAUTHORIZED",
    "EA-VERIFY-MANIFEST-UNVERIFIABLE",
    "EA-VERIFY-NON-CANONICAL-REPORT",
    "EA-VERIFY-RECEIPT-BINDING-MISMATCH",
    "EA-VERIFY-RECEIPT-SIGNATURE-INVALID",
    "EA-VERIFY-RECEIPT-UNTRUSTED-TIME",
];

/// Derselbe Code, wenn er persistierbar ist — sonst `None`.
///
/// Die Schranke faellt HIER und nicht erst in [`ReaderEntryStateStore::put_entry_state`],
/// weil ein Zustand, den der Speicher abwiese, wertlos waere. Der Klassifizierer
/// in `crate::verify` schickt jeden `ObjectErrorV1::code()` durch diese Stelle
/// und laesst einen unbekannten Code fallen, statt ihn mitzufuehren: der
/// ZUSTAND bleibt dann stehen, nur sein Detailgrund faellt weg.
///
/// Gemessener Anlass: `archive_without_a_recovery_grant()` erzeugt in Gate
/// `grant-plan` den Code `EA-GRANT-MISSING-RECOVERY`, der unveraendert aus
/// `ea-format` stammt und deshalb NICHT in [`PERSISTED_DETAIL_CODES_V1`] steht.
/// Die Tabelle waechst in demselben Commit, der einen neuen Code in einen
/// Eintragszustand schreibt — und nicht dadurch, dass hier still etwas anderes
/// durchgelassen wird.
pub(crate) fn persistable_detail_code(code: &'static str) -> Option<&'static str> {
    PERSISTED_DETAIL_CODES_V1.contains(&code).then_some(code)
}

/// Der technische Zustand GENAU EINES Eintrags, drei orthogonale Dimensionen.
#[derive(Clone, Eq, PartialEq)]
pub struct ReaderEntryStateV1 {
    entry_hash: EntryHash,
    object_hash: ObjectHash,
    sequence: ChainSequence,
    verification: VerificationStatus,
    entry_state: EntryStatus,
    server_confirmation: ServerConfirmationV1,
    detail_code: Option<&'static str>,
}

impl ReaderEntryStateV1 {
    /// Der Zustand aus seinen sieben Bestandteilen.
    #[must_use]
    pub const fn new(
        entry_hash: EntryHash,
        object_hash: ObjectHash,
        sequence: ChainSequence,
        verification: VerificationStatus,
        entry_state: EntryStatus,
        server_confirmation: ServerConfirmationV1,
        detail_code: Option<&'static str>,
    ) -> Self {
        Self {
            entry_hash,
            object_hash,
            sequence,
            verification,
            entry_state,
            server_confirmation,
            detail_code,
        }
    }

    /// Der Eintragshash — zugleich die Adresse im Zustandsspeicher.
    #[must_use]
    pub const fn entry_hash(&self) -> EntryHash {
        self.entry_hash
    }

    /// Der Objekthash des Eintragspakets.
    #[must_use]
    pub const fn object_hash(&self) -> ObjectHash {
        self.object_hash
    }

    /// Die Kettensequenz des Eintrags.
    #[must_use]
    pub const fn sequence(&self) -> ChainSequence {
        self.sequence
    }

    /// Der Verifikationsbefund, einer der sechs Begriffe aus §17.4.
    #[must_use]
    pub const fn verification(&self) -> VerificationStatus {
        self.verification
    }

    /// Der Eintragszustand, einer der drei Begriffe aus §17.4.
    #[must_use]
    pub const fn entry_state(&self) -> EntryStatus {
        self.entry_state
    }

    /// Die Server-Bestaetigung — eine EIGENE Dimension neben der Verifikation.
    #[must_use]
    pub const fn server_confirmation(&self) -> ServerConfirmationV1 {
        self.server_confirmation
    }

    /// Der stabile Detailcode, falls einer vorliegt.
    #[must_use]
    pub const fn detail_code(&self) -> Option<&'static str> {
        self.detail_code
    }
}

impl fmt::Debug for ReaderEntryStateV1 {
    /// Hex fuer die Hashes, Codes fuer die Statuswerte.
    ///
    /// Ein abgeleitetes `Debug` uebersetzt nicht — `EntryHash` und `ObjectHash`
    /// tragen keins — und es waere zugleich genau die Serialisierungsflaeche,
    /// die die Kanarienzeile `b"missingGrant"` sucht. Hier steht sie bewusst im
    /// PROGRAMM und nicht im Bytespeicher: `Debug` schreibt in eine
    /// Testmeldung, nie in OPFS.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReaderEntryStateV1 { entry_hash: ")?;
        write_hex(formatter, self.entry_hash.as_bytes())?;
        formatter.write_str(", object_hash: ")?;
        write_hex(formatter, self.object_hash.as_bytes())?;
        write!(
            formatter,
            ", sequence: {}, verification: {}, entry_state: {}, server_confirmation: {}, detail_code: {:?} }}",
            self.sequence.get(),
            self.verification.code(),
            self.entry_state.code(),
            self.server_confirmation.as_str(),
            self.detail_code
        )
    }
}

/// Der verschluesselte Zustandsspeicher EINER entsperrten Sitzung.
///
/// Dieselbe Bauform wie `ReaderObjectCache`: der Schluessel haengt am Tresor,
/// der Bytespeicher wird je Aufruf gereicht und nie gehalten, und die Adresse
/// ist hexadezimal, weil `ReaderBlobStore::keys()` sie im Klartext herausgibt.
pub struct ReaderEntryStateStore {
    entry_state_key: SecretBytes<CEK_SIZE>,
}

impl ReaderEntryStateStore {
    /// Oeffnet den Zustandsspeicher eines entsperrten Tresors.
    ///
    /// # Panics
    /// Nie erreichbar: HKDF-SHA-256 weist eine Ausgabelaenge erst oberhalb von
    /// 255 · 32 Byte ab, und hier sind es 32.
    #[must_use]
    pub fn open(vault: &UnlockedVault) -> Self {
        Self {
            entry_state_key: vault
                .entry_state_key()
                .expect("HKDF-SHA-256 liefert 32 Byte ohne Laengenbeschraenkung"),
        }
    }

    /// Legt GENAU EINEN Zustand unter seinem Eintragshash ab.
    ///
    /// # Errors
    /// `EA-READER-VAULT-CONTENTS` fuer einen Detailcode ausserhalb von
    /// `PERSISTED_DETAIL_CODES_V1` — er waere beim Lesen nicht mehr
    /// rekonstruierbar, und ein Speicher, der still etwas anderes zurueckgibt,
    /// als er bekommen hat, ist schlimmer als einer, der ablehnt. Dazu die
    /// Codes des Bytespeichers und von `ea-crypto`.
    pub fn put_entry_state(
        &self,
        store: &mut dyn ReaderBlobStore,
        state: &ReaderEntryStateV1,
    ) -> Result<(), ReaderVaultError> {
        let key = entry_state_key(state.entry_hash)?;
        let plaintext = encode_entry_state(state)?;
        let mut nonce = [0_u8; AEAD_NONCE_SIZE];
        getrandom::fill(&mut nonce)
            .map_err(|_| ReaderVaultError::Crypto(ea_crypto::CryptoError::LocalRng))?;
        let ciphertext = aead_seal(
            &self.entry_state_key,
            &SecretBytes::new(nonce),
            plaintext,
            &blob_aad(key.as_str().as_bytes()),
        )?;
        let mut blob = Vec::with_capacity(AEAD_NONCE_SIZE + ciphertext.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        store.put(&key, &blob)?;
        Ok(())
    }

    /// Holt den Zustand zu einem Eintragshash. Ein fehlender ist `Ok(None)`.
    ///
    /// # Errors
    /// `EA-CRYPTO-AEAD-OPEN` fuer einen fremden oder verfaelschten Blob,
    /// `EA-READER-VAULT-CONTENTS` fuer eine verfehlte Form.
    pub fn get_entry_state(
        &self,
        store: &dyn ReaderBlobStore,
        entry_hash: EntryHash,
    ) -> Result<Option<ReaderEntryStateV1>, ReaderVaultError> {
        let key = entry_state_key(entry_hash)?;
        let Some(blob) = store.get(&key)? else {
            return Ok(None);
        };
        if blob.len() < AEAD_NONCE_SIZE {
            return Err(ReaderVaultError::Contents);
        }
        let (nonce, ciphertext) = blob.split_at(AEAD_NONCE_SIZE);
        let nonce: [u8; AEAD_NONCE_SIZE] =
            nonce.try_into().map_err(|_| ReaderVaultError::Contents)?;
        let opened = aead_open(
            &self.entry_state_key,
            &SecretBytes::new(nonce),
            ciphertext,
            &blob_aad(key.as_str().as_bytes()),
        )?;
        opened.with_exposed(decode_entry_state).map(Some)
    }
}

/// Die Adresse eines Eintragszustands.
fn entry_state_key(entry_hash: EntryHash) -> Result<ReaderBlobKey, ReaderVaultError> {
    Ok(ReaderBlobKey::new(&format!(
        "{ENTRY_STATE_KEY_PREFIX}{}",
        hex::encode(entry_hash.as_bytes())
    ))?)
}

/// Der Zustand als deterministisches CBOR, in einem Geheimnistraeger.
///
/// Ein [`SecretVec`], obwohl kein Schluessel darin liegt: `aead_seal` nimmt
/// seinen Klartext BESITZEND als `SecretVec`, und die Statuswerte sind genau
/// die Zeichenketten, die die Kanarienzeugen im Bytespeicher suchen. Sie
/// verschwinden damit beim Fallenlassen aus dem Arbeitsspeicher, statt dort
/// liegen zu bleiben.
fn encode_entry_state(state: &ReaderEntryStateV1) -> Result<SecretVec, ReaderVaultError> {
    if let Some(code) = state.detail_code
        && !PERSISTED_DETAIL_CODES_V1.contains(&code)
    {
        return Err(ReaderVaultError::Contents);
    }
    let mut bytes = Vec::with_capacity(128);
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .array(7)
        .and_then(|encoder| encoder.bytes(state.entry_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(state.object_hash.as_bytes()))
        .and_then(|encoder| encoder.u64(state.sequence.get()))
        .and_then(|encoder| encoder.u8(verification_ordinal(state.verification)))
        .and_then(|encoder| encoder.u8(entry_status_ordinal(state.entry_state)))
        .and_then(|encoder| encoder.u8(server_confirmation_ordinal(state.server_confirmation)))
        .expect("encoding a fixed-shape entry state into Vec cannot fail");
    match state.detail_code {
        None => {
            encoder
                .null()
                .expect("encoding a CBOR null into Vec cannot fail");
        }
        Some(code) => {
            encoder
                .str(code)
                .expect("encoding a stable ASCII code into Vec cannot fail");
        }
    }
    debug_assert!(validate(&bytes, ParserLimits::V1).is_ok());
    Ok(SecretVec::new(bytes))
}

/// Der Zustand aus deterministischem CBOR.
///
/// Dieselbe Reihenfolge wie ueberall: `validate`, feldweise, Trailing-Sperre,
/// Rueckprobe gegen die eigenen Bytes.
fn decode_entry_state(bytes: &[u8]) -> Result<ReaderEntryStateV1, ReaderVaultError> {
    validate(bytes, ParserLimits::V1).map_err(|_| ReaderVaultError::Contents)?;
    let mut decoder = Decoder::new(bytes);
    if decoder.array().map_err(|_| ReaderVaultError::Contents)? != Some(7) {
        return Err(ReaderVaultError::Contents);
    }
    let entry_hash = EntryHash::try_from(decoder.bytes().map_err(|_| ReaderVaultError::Contents)?)
        .map_err(|_| ReaderVaultError::Contents)?;
    let object_hash =
        ObjectHash::try_from(decoder.bytes().map_err(|_| ReaderVaultError::Contents)?)
            .map_err(|_| ReaderVaultError::Contents)?;
    let sequence = ChainSequence::new(decoder.u64().map_err(|_| ReaderVaultError::Contents)?);
    let verification =
        verification_from_ordinal(decoder.u8().map_err(|_| ReaderVaultError::Contents)?)?;
    let entry_state =
        entry_status_from_ordinal(decoder.u8().map_err(|_| ReaderVaultError::Contents)?)?;
    let server_confirmation =
        server_confirmation_from_ordinal(decoder.u8().map_err(|_| ReaderVaultError::Contents)?)?;
    let detail_code = if decoder.datatype().map_err(|_| ReaderVaultError::Contents)?
        == minicbor::data::Type::Null
    {
        decoder.null().map_err(|_| ReaderVaultError::Contents)?;
        None
    } else {
        let persisted = decoder.str().map_err(|_| ReaderVaultError::Contents)?;
        Some(
            PERSISTED_DETAIL_CODES_V1
                .into_iter()
                .find(|known| *known == persisted)
                .ok_or(ReaderVaultError::Contents)?,
        )
    };
    if decoder.position() != bytes.len() {
        return Err(ReaderVaultError::Contents);
    }
    let state = ReaderEntryStateV1::new(
        entry_hash,
        object_hash,
        sequence,
        verification,
        entry_state,
        server_confirmation,
        detail_code,
    );
    if !encode_entry_state(&state)?.matches(bytes) {
        return Err(ReaderVaultError::Contents);
    }
    Ok(state)
}

/// Die Ordnungszahl eines Verifikationsbefunds.
///
/// Erschoepfend und ohne `_`-Auffangfall: eine siebte Variante in `ea-types`
/// MUSS die Uebersetzung hier brechen, statt still als `invalid` zu landen.
const fn verification_ordinal(status: VerificationStatus) -> u8 {
    match status {
        VerificationStatus::Verified => 0,
        VerificationStatus::Gap => 1,
        VerificationStatus::MissingGrant => 2,
        VerificationStatus::UnknownKey => 3,
        VerificationStatus::UnsupportedSchema => 4,
        VerificationStatus::Invalid => 5,
    }
}

/// Der Weg zurueck. Eine unbekannte Zahl ist eine Weigerung.
const fn verification_from_ordinal(ordinal: u8) -> Result<VerificationStatus, ReaderVaultError> {
    match ordinal {
        0 => Ok(VerificationStatus::Verified),
        1 => Ok(VerificationStatus::Gap),
        2 => Ok(VerificationStatus::MissingGrant),
        3 => Ok(VerificationStatus::UnknownKey),
        4 => Ok(VerificationStatus::UnsupportedSchema),
        5 => Ok(VerificationStatus::Invalid),
        _ => Err(ReaderVaultError::Contents),
    }
}

/// Die Ordnungszahl eines Eintragszustands.
const fn entry_status_ordinal(status: EntryStatus) -> u8 {
    match status {
        EntryStatus::Present => 0,
        EntryStatus::AuthorizedDestroyed => 1,
        EntryStatus::UnexplainedGap => 2,
    }
}

/// Der Weg zurueck.
const fn entry_status_from_ordinal(ordinal: u8) -> Result<EntryStatus, ReaderVaultError> {
    match ordinal {
        0 => Ok(EntryStatus::Present),
        1 => Ok(EntryStatus::AuthorizedDestroyed),
        2 => Ok(EntryStatus::UnexplainedGap),
        _ => Err(ReaderVaultError::Contents),
    }
}

/// Die Ordnungszahl der Server-Bestaetigung.
const fn server_confirmation_ordinal(confirmation: ServerConfirmationV1) -> u8 {
    match confirmation {
        ServerConfirmationV1::ServerConfirmed => 0,
        ServerConfirmationV1::NotServerConfirmed => 1,
    }
}

/// Der Weg zurueck.
const fn server_confirmation_from_ordinal(
    ordinal: u8,
) -> Result<ServerConfirmationV1, ReaderVaultError> {
    match ordinal {
        0 => Ok(ServerConfirmationV1::ServerConfirmed),
        1 => Ok(ServerConfirmationV1::NotServerConfirmed),
        _ => Err(ReaderVaultError::Contents),
    }
}

/// Schreibt Bytes als Kleinbuchstaben-Hex.
fn write_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}
