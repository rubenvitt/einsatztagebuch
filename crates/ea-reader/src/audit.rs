//! Der signierte lokale Auditschreiber des Readers — drei eingefrorene
//! Aufrufe, kein vierter.
//!
//! `crates/ea-audit` wird AUSDRUECKLICH NICHT angefasst: die Crate steht in
//! `WASM32_EXEMPT_CRATES`, signiert durch den Wirtschluesselspeicher und
//! haengt an die verschluesselte Wirtdatenbank an; ihr `AuditActorProof`
//! zieht ausserdem `ea-operator` mit. Der Reader-Auditschreiber lebt deshalb
//! HIER, ueber den bereits eingefrorenen Kodierern von
//! `crates/ea-format/src/local_audit.rs`, und [`ReaderAuditWriter::record`]
//! ist `encode_local_audit_core`, dann `CoseSigner::sign_local_audit`, dann
//! `encode_local_audit_event` — mehr nicht.
//!
//! # Kein dreizehnter Aktionscode, keine Position fuer einen Pfad
//!
//! `schemas/reports/v1/local-audit.cddl` friert `local-audit-action-v1 =
//! 0..11` ein; der Reader-Einzelexport ist Code `5` mit `context_tag` `3`,
//! `PlaintextExport(ExportContextV1)`. Der Kontext traegt GENAU zwei
//! Positionen, `entry-hash` und `target-kind: uint`. Der Wirtpfad HAT dort
//! keinen Platz, und genau deshalb wird die Zusage „nie der
//! Klartextdateiname" nicht durch Disziplin gehalten, sondern durch die
//! Grammatik: `encode_local_audit_core` weist ueber
//! `validate_unsigned_protocol_core` ab, bevor eine Zeile entsteht.
//!
//! # Die Identitaet kommt von aussen
//!
//! `LocalAuditEventCoreFieldsV1` verlangt `organization_id`, `device_id` und
//! `signer_certificate_object_hash`, und `sign_local_audit` liest den
//! Zertifikatshash aus dem Kern, um ihn in den geschuetzten COSE-Kopf zu
//! binden. Der Browser-Tresor traegt keinen dieser drei Werte — er haelt
//! Schluessel, Anker und Registry-Stand —, und ein Reader-Zertifikat stellt
//! erst die Administrationsstufe aus. [`ReaderAuditIdentityV1`] ist deshalb
//! ein PARAMETER und keine Ableitung: ein aus dem Schluessel erfundener
//! Zertifikatshash waere eine Aussage ueber eine Ausstellung, die nie
//! stattgefunden hat.
//!
//! # Was in der pseudonymen Bedienerbindung steht
//!
//! `operator_binding_object_hash` traegt im Desktop die OS-Kontobindung. Der
//! Browser hat kein OS-Konto; an dessen Stelle tritt SHA-256 ueber die
//! `credentialId` des Authenticators, der die Sitzung eroeffnet hat
//! (`ReaderSession::operator_binding_hash`). Pseudonym, stabil je Passkey,
//! ohne Klarnamen und ohne die Kennung selbst.

use core::fmt;

use ea_cbor::{ParserLimits, validate};
use ea_crypto::{
    AEAD_NONCE_SIZE, CEK_SIZE, CoseSigner, CryptoError, SecretBytes, SecretVec, aead_open,
    aead_seal,
};
use ea_format::{
    FormatError, LocalAuditActionV1, LocalAuditEventCoreFieldsV1, LocalAuditOutcomeV1,
    encode_local_audit_core, encode_local_audit_event,
};
use ea_types::{DeviceId, EventId, Hash32, ObjectHash, OrganizationId, UnixMillis};
use minicbor::{Decoder, Encoder};

use crate::blob_store::{ReaderBlobError, ReaderBlobKey, ReaderBlobStore};
use crate::envelope::blob_aad;
use crate::vault::{ReaderVaultError, UnlockedVault};

/// Die lokale Adresse des versiegelten Auditprotokolls.
pub const READER_AUDIT_LOG_BLOB_KEY_V1: &str = "audit-log";

/// Die Hoechstzahl Zeilen, die ein Protokollblob traegt.
///
/// Das Protokoll ist ein EINZELNER versiegelter Blob, der bei jedem Anhaengen
/// neu versiegelt wird; ohne Grenze wuechse er aus angreiferkontrollierten
/// Bytes unbeschraenkt. Fuenftausend Exportzeilen sind zweieinhalbtausend
/// Exporte — weit jenseits dessen, was ein Reader je auditiert. Die Zahl
/// liegt bewusst UNTER `ParserLimits::V1`: dessen `max_total_items` zaehlt
/// das Array und seine Eintraege zusammen und steht bei 10 000, und ein
/// Protokoll, das an der Grenze des Dekodierers gebaut wuerde, ginge nach
/// der letzten zulaessigen Zeile nicht mehr auf. GEMESSEN: mit 10 000 fiel
/// `a_log_one_line_over_the_limit_is_refused_and_one_at_the_limit_is_not`
/// bereits an der Grenze selbst.
pub const MAX_READER_AUDIT_LOG_EVENTS_V1: usize = 5_000;

/// Der Fehlschlag des Auditschreibers.
#[derive(Clone, Eq, PartialEq)]
pub enum ReaderAuditError {
    /// Der Wirt liefert keine Entropie fuer Ereigniskennung oder Nonce.
    LocalRng,
    /// Die Senke hat die signierte Zeile nicht angenommen.
    Sink,
    /// Das Protokoll ist voll.
    LogFull,
    /// Ein Fehlschlag der Kodierer aus `ea-format`.
    Format(FormatError),
    /// Ein Fehlschlag der Signatur oder der Versiegelung.
    Crypto(CryptoError),
    /// Ein Fehlschlag des Tresors oder des Bytespeichers.
    Vault(ReaderVaultError),
}

impl ReaderAuditError {
    /// Stabiler Fehlercode; umhuellende Arme reichen durch und pruegen keinen
    /// zweiten Namen fuer einen fremden Befund.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::LocalRng => "EA-READER-AUDIT-LOCAL-RNG",
            Self::Sink => "EA-READER-AUDIT-SINK",
            Self::LogFull => "EA-READER-AUDIT-LOG-FULL",
            Self::Format(error) => error.code(),
            Self::Crypto(error) => error.code(),
            Self::Vault(error) => error.code(),
        }
    }
}

impl From<FormatError> for ReaderAuditError {
    fn from(error: FormatError) -> Self {
        Self::Format(error)
    }
}

impl From<CryptoError> for ReaderAuditError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<ReaderVaultError> for ReaderAuditError {
    fn from(error: ReaderVaultError) -> Self {
        Self::Vault(error)
    }
}

impl From<ReaderBlobError> for ReaderAuditError {
    fn from(error: ReaderBlobError) -> Self {
        Self::Vault(ReaderVaultError::from(error))
    }
}

impl fmt::Display for ReaderAuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for ReaderAuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for ReaderAuditError {}

/// Die drei Identitaetsfelder einer Auditzeile, wie das Reader-Zertifikat sie
/// traegt.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ReaderAuditIdentityV1 {
    organization_id: OrganizationId,
    device_id: DeviceId,
    signer_certificate_object_hash: ObjectHash,
}

impl ReaderAuditIdentityV1 {
    /// Die Identitaet aus den geparsten Feldern des Reader-Zertifikats.
    #[must_use]
    pub const fn new(
        organization_id: OrganizationId,
        device_id: DeviceId,
        signer_certificate_object_hash: ObjectHash,
    ) -> Self {
        Self {
            organization_id,
            device_id,
            signer_certificate_object_hash,
        }
    }

    /// Die Organisation.
    #[must_use]
    pub const fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }

    /// Das Geraet.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Der Objekthash des Zertifikats, dessen Schluessel die Zeile signiert.
    #[must_use]
    pub const fn signer_certificate_object_hash(&self) -> ObjectHash {
        self.signer_certificate_object_hash
    }
}

impl fmt::Debug for ReaderAuditIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReaderAuditIdentityV1(<bound>)")
    }
}

/// Wohin eine signierte Auditzeile geht.
///
/// Ein Port, damit der Zeuge die EXAKTEN Bytes sieht, die geschrieben werden,
/// und damit ein Fehlschlag der Senke ein Ergebnis ist und kein Abbruch: die
/// Zeile NACH dem Schreiben darf nicht verschluckt werden.
pub trait ReaderAuditSink {
    /// Haengt GENAU EINE signierte Zeile an — die exakten Bytes von
    /// `encode_local_audit_event`.
    ///
    /// # Errors
    /// `EA-READER-AUDIT-SINK` oder die Codes des Speichers dahinter.
    fn append(&mut self, signed_event: &[u8]) -> Result<(), ReaderAuditError>;
}

/// Eine Senke im Speicher — fuer Zeugen und fuer den Wirtsbau.
#[derive(Debug, Default)]
pub struct InMemoryReaderAuditSink {
    events: Vec<Vec<u8>>,
}

impl InMemoryReaderAuditSink {
    /// Eine leere Senke.
    #[must_use]
    pub const fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Die angehaengten Zeilen, in Reihenfolge.
    #[must_use]
    pub fn events(&self) -> &[Vec<u8>] {
        &self.events
    }
}

impl ReaderAuditSink for InMemoryReaderAuditSink {
    fn append(&mut self, signed_event: &[u8]) -> Result<(), ReaderAuditError> {
        self.events.push(signed_event.to_vec());
        Ok(())
    }
}

/// Der Auditschreiber einer entsperrten Sitzung.
///
/// Er haelt den COSE-Signierer BESITZEND — gebaut aus dem Tresor, gueltig fuer
/// genau die Zeilen, die dieser Schreiber schreibt — und die Senke
/// ausgeliehen. Kein Aenderungs- und kein Loeschpfad; keine Metadaten-API.
pub struct ReaderAuditWriter<'a> {
    signer: CoseSigner,
    identity: ReaderAuditIdentityV1,
    operator_binding_hash: Hash32,
    sink: &'a mut dyn ReaderAuditSink,
}

impl<'a> ReaderAuditWriter<'a> {
    /// Oeffnet den Schreiber ueber dem Tresor einer Sitzung.
    #[must_use]
    pub fn open(
        vault: &UnlockedVault,
        identity: ReaderAuditIdentityV1,
        operator_binding_hash: Hash32,
        sink: &'a mut dyn ReaderAuditSink,
    ) -> Self {
        Self {
            signer: vault.audit_signer(),
            identity,
            operator_binding_hash,
            sink,
        }
    }

    /// Schreibt GENAU EINE signierte Zeile und gibt ihre exakten Bytes zurueck.
    ///
    /// Ereigniskennung und Nonce kommen aus `getrandom`, die Zeit aus dem
    /// Aufrufer. Die Zeile entsteht in drei Aufrufen —
    /// `encode_local_audit_core`, `sign_local_audit`,
    /// `encode_local_audit_event` — und wird DANACH an die Senke gereicht:
    /// eine Senke, die abweist, hat nie eine halbe Zeile gesehen.
    ///
    /// # Errors
    /// `EA-READER-AUDIT-LOCAL-RNG` ohne Entropie, `EA-FORMAT-SHAPE` fuer einen
    /// Kern, den die Grammatik abweist, die Codes von `ea-crypto` und die der
    /// Senke.
    pub fn record(
        &mut self,
        action: LocalAuditActionV1,
        outcome: LocalAuditOutcomeV1,
        effective_now: UnixMillis,
    ) -> Result<Vec<u8>, ReaderAuditError> {
        let event_id = EventId::try_from(fresh::<16>()?.as_slice())
            .expect("16 gezogene Byte sind eine Ereigniskennung");
        let fields = LocalAuditEventCoreFieldsV1 {
            event_id,
            organization_id: self.identity.organization_id,
            device_id: self.identity.device_id,
            operator_binding_object_hash: Some(ObjectHash::from(self.operator_binding_hash)),
            signer_certificate_object_hash: self.identity.signer_certificate_object_hash,
            action,
            outcome,
            effective_now,
            nonce: fresh::<32>()?,
        };
        let core = encode_local_audit_core(&fields)?;
        let cose = self.signer.sign_local_audit(&core)?;
        let exact_bytes = encode_local_audit_event(&core, &cose)?;
        self.sink.append(&exact_bytes)?;
        Ok(exact_bytes)
    }
}

impl fmt::Debug for ReaderAuditWriter<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReaderAuditWriter(<bound>)")
    }
}

/// Frische Zufallsbytes des Wirts.
fn fresh<const N: usize>() -> Result<[u8; N], ReaderAuditError> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|_| ReaderAuditError::LocalRng)?;
    Ok(bytes)
}

/// Das versiegelte lokale Auditprotokoll — ein Blob, angehaengt und neu
/// versiegelt.
///
/// Dieselbe Bauform wie `ReaderTrustStateStore`: ChaCha20-Poly1305 unter
/// einem aus dem Tresorschluessel abgeleiteten Protokollschluessel, die
/// Adresse im zusaetzlichen authentifizierten Datum, `Ok(None)` heisst „nie
/// geschrieben". Jede Zeile darin ist fuer sich signiert; die Versiegelung
/// schuetzt VERTRAULICHKEIT (Entry-Hash, Bindung, Zeit) und macht ein stilles
/// Kuerzen sichtbar, sie ersetzt die Signatur nicht.
pub struct ReaderAuditLogStore {
    audit_log_key: SecretBytes<CEK_SIZE>,
}

impl ReaderAuditLogStore {
    /// Oeffnet das Protokoll eines entsperrten Tresors.
    ///
    /// # Panics
    /// Nie erreichbar: HKDF-SHA-256 weist eine Ausgabelaenge erst oberhalb von
    /// 255 · 32 Byte ab, und hier sind es 32.
    #[must_use]
    pub fn open(vault: &UnlockedVault) -> Self {
        Self {
            audit_log_key: vault
                .audit_log_key()
                .expect("HKDF-SHA-256 liefert 32 Byte ohne Laengenbeschraenkung"),
        }
    }

    /// Alle Zeilen, in Schreibreihenfolge. Ein nie beschriebenes Protokoll ist
    /// leer.
    ///
    /// # Errors
    /// `EA-CRYPTO-AEAD-OPEN` fuer einen fremden oder verfaelschten Blob,
    /// `EA-READER-VAULT-CONTENTS` fuer eine verfehlte Form.
    pub fn events(&self, store: &dyn ReaderBlobStore) -> Result<Vec<Vec<u8>>, ReaderAuditError> {
        let key = audit_log_key()?;
        let Some(blob) = store.get(&key)? else {
            return Ok(Vec::new());
        };
        if blob.len() < AEAD_NONCE_SIZE {
            return Err(ReaderVaultError::Contents.into());
        }
        let (nonce, ciphertext) = blob.split_at(AEAD_NONCE_SIZE);
        let nonce: [u8; AEAD_NONCE_SIZE] =
            nonce.try_into().map_err(|_| ReaderVaultError::Contents)?;
        let opened = aead_open(
            &self.audit_log_key,
            &SecretBytes::new(nonce),
            ciphertext,
            &blob_aad(key.as_str().as_bytes()),
        )?;
        opened.with_exposed(decode_audit_log)
    }

    /// Haengt GENAU EINE signierte Zeile an und versiegelt neu.
    ///
    /// # Errors
    /// `EA-READER-AUDIT-LOG-FULL` jenseits von
    /// [`MAX_READER_AUDIT_LOG_EVENTS_V1`]; daneben die Codes des Lesens, des
    /// Versiegelns und des Bytespeichers.
    pub fn append(
        &self,
        store: &mut dyn ReaderBlobStore,
        signed_event: &[u8],
    ) -> Result<(), ReaderAuditError> {
        let mut events = self.events(store)?;
        ensure_room_for_one_more(&events)?;
        events.push(signed_event.to_vec());
        let key = audit_log_key()?;
        let mut nonce = [0_u8; AEAD_NONCE_SIZE];
        getrandom::fill(&mut nonce).map_err(|_| ReaderAuditError::LocalRng)?;
        let ciphertext = aead_seal(
            &self.audit_log_key,
            &SecretBytes::new(nonce),
            encode_audit_log(&events),
            &blob_aad(key.as_str().as_bytes()),
        )?;
        let mut blob = Vec::with_capacity(AEAD_NONCE_SIZE + ciphertext.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        store.put(&key, &blob)?;
        Ok(())
    }
}

impl fmt::Debug for ReaderAuditLogStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReaderAuditLogStore(<sealed>)")
    }
}

/// Das Protokoll als Senke ueber einem Bytespeicher.
pub struct ReaderAuditLogSink<'a> {
    log: &'a ReaderAuditLogStore,
    store: &'a mut dyn ReaderBlobStore,
}

impl<'a> ReaderAuditLogSink<'a> {
    /// Bindet ein Protokoll an einen Bytespeicher.
    #[must_use]
    pub fn new(log: &'a ReaderAuditLogStore, store: &'a mut dyn ReaderBlobStore) -> Self {
        Self { log, store }
    }
}

impl ReaderAuditSink for ReaderAuditLogSink<'_> {
    fn append(&mut self, signed_event: &[u8]) -> Result<(), ReaderAuditError> {
        self.log.append(self.store, signed_event)
    }
}

impl fmt::Debug for ReaderAuditLogSink<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReaderAuditLogSink(<sealed>)")
    }
}

/// Die Obergrenze VOR dem Anhaengen: ein volles Protokoll nimmt keine Zeile
/// mehr an, statt eines zu schreiben, das beim naechsten Lesen nicht mehr
/// aufgeht.
fn ensure_room_for_one_more(events: &[Vec<u8>]) -> Result<(), ReaderAuditError> {
    if events.len() >= MAX_READER_AUDIT_LOG_EVENTS_V1 {
        return Err(ReaderAuditError::LogFull);
    }
    Ok(())
}

/// Die Adresse des Protokolls.
fn audit_log_key() -> Result<ReaderBlobKey, ReaderAuditError> {
    Ok(ReaderBlobKey::new(READER_AUDIT_LOG_BLOB_KEY_V1)?)
}

/// Das Protokoll als deterministisches CBOR: ein Array aus Bytefolgen, in
/// einem Geheimnistraeger, weil `aead_seal` ihn BESITZEND nimmt.
fn encode_audit_log(events: &[Vec<u8>]) -> SecretVec {
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .array(events.len() as u64)
        .expect("ein Vec waechst ohne Fehler");
    for event in events {
        encoder.bytes(event).expect("ein Vec waechst ohne Fehler");
    }
    SecretVec::new(bytes)
}

/// Das Protokoll aus seinen Bytes — durch den deterministischen Waechter,
/// dann Form fuer Form.
fn decode_audit_log(bytes: &[u8]) -> Result<Vec<Vec<u8>>, ReaderAuditError> {
    validate(bytes, ParserLimits::V1).map_err(|_| ReaderVaultError::Contents)?;
    let mut decoder = Decoder::new(bytes);
    let count = decoder
        .array()
        .map_err(|_| ReaderVaultError::Contents)?
        .ok_or(ReaderVaultError::Contents)?;
    let count = usize::try_from(count).map_err(|_| ReaderVaultError::Contents)?;
    if count > MAX_READER_AUDIT_LOG_EVENTS_V1 {
        return Err(ReaderVaultError::Contents.into());
    }
    let mut events = Vec::with_capacity(count);
    for _ in 0..count {
        let event = decoder.bytes().map_err(|_| ReaderVaultError::Contents)?;
        events.push(event.to_vec());
    }
    if decoder.position() != bytes.len() {
        return Err(ReaderVaultError::Contents.into());
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_READER_AUDIT_LOG_EVENTS_V1, ReaderAuditError, decode_audit_log, encode_audit_log,
        ensure_room_for_one_more,
    };
    use crate::vault::ReaderVaultError;

    /// Die Obergrenze ist eine WEIGERUNG des Dekodierers und keine Zahl im
    /// Kommentar: ein Protokoll mit einer Zeile mehr, als die Grenze zulaesst,
    /// geht nicht auf — gemessen an den Bytes, die `encode_audit_log` selbst
    /// erzeugt, damit die Grenze nicht am Kodierer vorbeiwaechst.
    #[test]
    fn a_log_one_line_over_the_limit_is_refused_and_one_at_the_limit_is_not() {
        let at_limit = vec![Vec::new(); MAX_READER_AUDIT_LOG_EVENTS_V1];
        let encoded = encode_audit_log(&at_limit);
        assert_eq!(
            encoded
                .with_exposed(decode_audit_log)
                .expect("die Grenze selbst ist zulaessig")
                .len(),
            MAX_READER_AUDIT_LOG_EVENTS_V1
        );

        let over = vec![Vec::new(); MAX_READER_AUDIT_LOG_EVENTS_V1 + 1];
        let refused = encode_audit_log(&over)
            .with_exposed(decode_audit_log)
            .expect_err("eine Zeile ueber der Grenze geht nicht auf");
        assert_eq!(refused, ReaderAuditError::Vault(ReaderVaultError::Contents));
    }

    /// Das Anhaengen weist VOR dem Schreiben ab: ein Protokoll an der Grenze
    /// nimmt keine Zeile mehr, eines darunter genau noch eine.
    #[test]
    fn a_full_log_takes_no_further_line_and_one_below_the_limit_takes_exactly_one() {
        let below = vec![Vec::new(); MAX_READER_AUDIT_LOG_EVENTS_V1 - 1];
        assert!(ensure_room_for_one_more(&below).is_ok());
        let full = vec![Vec::new(); MAX_READER_AUDIT_LOG_EVENTS_V1];
        assert_eq!(
            ensure_room_for_one_more(&full).expect_err("voll"),
            ReaderAuditError::LogFull
        );
    }

    /// Nachgestellte Bytes hinter dem Array sind eine verfehlte Form und keine
    /// stille Toleranz.
    #[test]
    fn trailing_bytes_behind_the_log_are_refused() {
        let mut bytes = Vec::new();
        encode_audit_log(&[b"zeile".to_vec()]).with_exposed(|exact| bytes.extend_from_slice(exact));
        assert!(decode_audit_log(&bytes).is_ok());
        bytes.push(0x00);
        assert_eq!(
            decode_audit_log(&bytes).expect_err("nachgestellte Bytes"),
            ReaderAuditError::Vault(ReaderVaultError::Contents)
        );
    }
}
