//! Der bestaetigte Cursor: bis hierher hat der Reader SELBST verifiziert.
//!
//! # Was der Cursor BEHAUPTET
//!
//! Vier Werte und keinen mehr: die Kettenkennung, die hoechste zusammenhaengend
//! verifizierte Sequenz, deren Eintragshash und den undurchsichtigen
//! Blaetterschein des Servers. Die ersten drei sind eine Aussage des READERS —
//! er hat die Kette bis dorthin gegen den gepinnten Anker gerechnet. Der vierte
//! ist eine Aussage des SERVERS und wird hier niemals gedeutet: `TechnicalCursorV1`
//! wird mit dem Serverschluessel geoeffnet, und ein Reader, der ihn aufmachte,
//! haette eine zweite Meinung darueber, wo eine Seite endet.
//!
//! # Warum er DAUERHAFT liegt und nicht gerechnet wird
//!
//! Man koennte den Kopf aus dem lokalen Bestand neu rechnen — das tut
//! [`crate::ReaderSyncService::rebuild_from_genesis`] auch. Als Ersatz taugt es
//! nicht: waeren alle Objektbytes eines Batches geschrieben und der Lauf danach
//! abgebrochen, ergaebe ein gerechneter Kopf einen FORTGESCHRITTENEN Cursor,
//! obwohl nie jemand die Kette bis dorthin abgenommen hat. Genau diesen
//! Unterschied misst
//! `the_cursor_moves_only_after_every_object_is_durable_and_the_chain_verifies`
//! an den Punkten `AfterBlobStoreFlush` und `AfterChainVerification`.
//!
//! # Neben dem Cursor liegt die ADRESSLISTE, auf der er steht
//!
//! [`ReaderCursorStore`] fuehrt ZWEI Blobs, und der zweite ist kein Beiwerk:
//! `OpfsBlobStore::open` verlangt die vollstaendige Schluesselmenge, BEVOR es
//! ein einziges synchrones Zugriffshandle oeffnet, und ein Schluessel, der
//! dort fehlte, ist danach unerreichbar. Ohne eine dauerhafte, RUSTEIGENE
//! Liste der gecachten Objekte muesste der Wirt sie nennen — und dann
//! entschiede JavaScript, welchen Bestand `verify_archive_observed` ueberhaupt
//! zu sehen bekommt. Genau das verbietet `web-reader-design.md` §9.
//!
//! Die Liste ist absichtlich in die SICHERE Richtung fehlbar: nennt sie ein
//! Objekt, das nicht mehr da ist, liest sich dessen Blob als abwesend und der
//! Durchlauf ueberspringt ihn; fehlt ihr eines, das da ist, sieht die
//! Verifikation es nicht und meldet eine Luecke. Das erste ist folgenlos, das
//! zweite fail-closed — deshalb wird sie VOR dem Cursor geschrieben.
//!
//! # Der Blob ist Chiffrat, wie jeder andere auch
//!
//! `ReaderBlobStore::keys()` gibt die Schluessel im Klartext heraus, den INHALT
//! nie: [`ReaderCursorStore`] arbeitet unter einem eigenen abgeleiteten
//! Schluessel und bindet den Blob per AEAD an seine Adresse — dieselbe Bauform
//! wie [`crate::ReaderObjectCache`] und [`crate::ReaderEntryStateStore`].

use ea_cbor::{ParserLimits, validate};
use ea_crypto::{AEAD_NONCE_SIZE, CEK_SIZE, SecretBytes, SecretVec, aead_open, aead_seal};
use ea_trust::TrustAnchorV1;
use ea_types::{ChainId, ChainSequence, EntryHash, Hash32, ObjectHash};
use minicbor::{Decoder, Encoder};

use crate::blob_store::{ReaderBlobKey, ReaderBlobStore};
use crate::envelope::blob_aad;
use crate::vault::{ReaderVaultError, UnlockedVault};

/// Die Adresse des bestaetigten Cursors im Bytespeicher.
///
/// OEFFENTLICH aus demselben Grund wie [`crate::READER_VAULT_BLOB_KEY_V1`]:
/// `OpfsBlobStore::open` verlangt die VOLLSTAENDIGE Schluesselmenge, bevor es
/// ein einziges Zugriffshandle oeffnen kann, und `crates/ea-reader-wasm` muss
/// diese Adresse deshalb benennen koennen, ohne sie ein zweites Mal zu
/// schreiben.
pub const READER_SYNC_CURSOR_BLOB_KEY_V1: &str = "sync/cursor-v1";

/// Die Adresse der Objektliste im Bytespeicher.
///
/// OEFFENTLICH aus demselben Grund wie [`READER_SYNC_CURSOR_BLOB_KEY_V1`]:
/// `crates/ea-reader-wasm` muss beide Adressen im asynchronen Vorlauf nennen
/// koennen, ohne sie ein zweites Mal zu schreiben.
pub const READER_SYNC_OBJECTS_BLOB_KEY_V1: &str = "sync/objects-v1";

/// Hoechstzahl der Objekte, die die dauerhafte Adressliste fuehren kann.
///
/// GERECHNET und nicht gewaehlt: die Liste reist als EIN `bstr` durch
/// `ea_cbor::validate(.., ParserLimits::V1)`, und dessen `max_text_or_bytes`
/// misst 1_048_592 Byte. Bei 32 Byte je Objekthash sind das 32_768 Eintraege.
///
/// # Das ist eine GRENZE und keine Vorgabe
///
/// Sie liegt DEUTLICH unter `ea_archive::MAX_ARCHIVE_BLOBS_V1` (1_048_576),
/// der Schranke, die der Verifizierer selbst an einen Bestand anlegt. Ein
/// Reader, der mehr als 32_768 Objekte dauerhaft haelt, laeuft hier auf eine
/// Weigerung und nicht auf eine stille Kuerzung — eine gekuerzte Liste waere
/// genau der Fall, den dieses Modul verhindern soll. Sie zu heben verlangt
/// eine geblaetterte Liste oder eine Verzeichnisaufzaehlung im OPFS-Wirt;
/// beides gehoert nicht in diese Aufgabe.
pub const MAX_CACHED_OBJECTS_V1: usize = 1_048_592 / 32;

/// Der bestaetigte Cursor EINER Kette.
#[derive(Clone, Eq, PartialEq)]
pub struct ConfirmedCursor {
    chain_id: ChainId,
    sequence: ChainSequence,
    entry_hash: EntryHash,
    technical_cursor: Option<Vec<u8>>,
}

impl ConfirmedCursor {
    /// Der Cursor eines Readers, der noch NICHTS bestaetigt hat.
    ///
    /// Sequenz null und 32 Nullbytes — zeichengleich mit
    /// `ea_verify::ChainHeadV1::sentinel` und mit dem Sentinel, an dem
    /// `ea_sync_server::reader_sync::is_genesis_start` einen Start ab
    /// Kettenanfang erkennt. Ausdruecklich NICHT `anchor.genesis_entry_hash()`:
    /// das behauptete einen verifizierten Genesis-Eintrag, den es noch nicht
    /// gibt. Die Kettenkennung kommt trotzdem aus dem Anker und nie aus einer
    /// Antwort — sie ist die einzige Identitaet, die der Reader schon besitzt.
    #[must_use]
    pub fn genesis(anchor: &TrustAnchorV1) -> Self {
        Self {
            chain_id: anchor.chain_id(),
            sequence: ChainSequence::new(0),
            entry_hash: EntryHash::from(Hash32::ZERO),
            technical_cursor: None,
        }
    }

    /// Ein bestaetigter Cursor aus seinen vier Bestandteilen.
    ///
    /// `pub(crate)`: ein Cursor entsteht ausschliesslich hinter einer
    /// vollstaendigen Verifikation. Waere der Konstruktor oeffentlich, koennte
    /// ein Aufrufer sich an eine Sequenz setzen, die er nie geprueft hat —
    /// genau der Zustand, den dieser Task ausschliesst.
    #[must_use]
    pub(crate) const fn new(
        chain_id: ChainId,
        sequence: ChainSequence,
        entry_hash: EntryHash,
        technical_cursor: Option<Vec<u8>>,
    ) -> Self {
        Self {
            chain_id,
            sequence,
            entry_hash,
            technical_cursor,
        }
    }

    /// Die Kette, ueber die dieser Cursor spricht.
    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Die hoechste zusammenhaengend verifizierte Sequenz.
    #[must_use]
    pub const fn sequence(&self) -> ChainSequence {
        self.sequence
    }

    /// Der Eintragshash auf dieser Sequenz.
    #[must_use]
    pub const fn entry_hash(&self) -> EntryHash {
        self.entry_hash
    }

    /// Der undurchsichtige Blaetterschein des Servers, falls einer vorliegt.
    #[must_use]
    pub fn technical_cursor(&self) -> Option<&[u8]> {
        self.technical_cursor.as_deref()
    }

    /// Ob dieser Cursor noch NICHTS bestaetigt hat.
    ///
    /// Die Unterscheidung traegt die Forkpruefung: auf einem Genesis-Cursor
    /// gibt es keine „schon bestaetigte Sequenz", der ein Kopf widersprechen
    /// koennte, und ein erster Eintrag auf Sequenz null waere sonst selbst der
    /// Widerspruch.
    #[must_use]
    pub(crate) fn is_genesis(&self) -> bool {
        self.sequence.get() == 0 && self.entry_hash.as_bytes() == &[0_u8; 32]
    }
}

impl core::fmt::Debug for ConfirmedCursor {
    /// Hex fuer Kennung und Hash, die LAENGE fuer den Blaetterschein.
    ///
    /// Ein abgeleitetes `Debug` uebersetzt nicht — `ChainId` und `EntryHash`
    /// tragen keins — und der Blaetterschein gehoert nicht in eine Meldung: er
    /// ist ein signiertes Serverartefakt und kein Diagnosewert.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ConfirmedCursor { chain_id: ")?;
        write_hex(formatter, self.chain_id.as_bytes())?;
        formatter.write_str(", entry_hash: ")?;
        write_hex(formatter, self.entry_hash.as_bytes())?;
        write!(
            formatter,
            ", sequence: {}, technical_cursor_bytes: {:?} }}",
            self.sequence.get(),
            self.technical_cursor.as_ref().map(Vec::len)
        )
    }
}

/// Der verschluesselte Sync-Zustand EINER entsperrten Sitzung: Cursor UND
/// Adressliste.
///
/// Dieselbe Bauform wie [`crate::ReaderObjectCache`]: der Schluessel haengt am
/// Tresor, der Bytespeicher wird je Aufruf gereicht und nie gehalten.
///
/// EIN abgeleiteter Schluessel fuer beide Blobs, und das ist kein Sparen: die
/// zwei gehoeren zu EINER Aussage — der Cursor behauptet einen verifizierten
/// Stand, die Liste nennt die Adressen, auf denen diese Behauptung ruht. Sie
/// bleiben trotzdem unverwechselbar, weil das zusaetzliche authentifizierte
/// Datum jeden Blob an SEINE Adresse bindet (`blob_aad`); ein vertauschtes
/// Paar oeffnet nicht.
pub(crate) struct ReaderCursorStore {
    cursor_key: SecretBytes<CEK_SIZE>,
}

impl ReaderCursorStore {
    /// Oeffnet den Cursorspeicher eines entsperrten Tresors.
    ///
    /// # Panics
    /// Nie erreichbar: HKDF-SHA-256 weist eine Ausgabelaenge erst oberhalb von
    /// 255 · 32 Byte ab, und hier sind es 32.
    pub(crate) fn open(vault: &UnlockedVault) -> Self {
        Self {
            cursor_key: vault
                .sync_cursor_key()
                .expect("HKDF-SHA-256 liefert 32 Byte ohne Laengenbeschraenkung"),
        }
    }

    /// Versiegelt einen Klartext unter DIESER Adresse und legt ihn ab.
    ///
    /// Der Nonce wird je Schreibvorgang frisch gezogen, und die Adresse geht
    /// als zusaetzliches authentifiziertes Datum ein — deshalb laesst sich der
    /// Cursorblob nicht als Objektliste ausgeben und umgekehrt.
    fn put_sealed(
        &self,
        store: &mut dyn ReaderBlobStore,
        key: &ReaderBlobKey,
        plaintext: SecretVec,
    ) -> Result<(), ReaderVaultError> {
        let mut nonce = [0_u8; AEAD_NONCE_SIZE];
        getrandom::fill(&mut nonce)
            .map_err(|_| ReaderVaultError::Crypto(ea_crypto::CryptoError::LocalRng))?;
        let ciphertext = aead_seal(
            &self.cursor_key,
            &SecretBytes::new(nonce),
            plaintext,
            &blob_aad(key.as_str().as_bytes()),
        )?;
        let mut blob = Vec::with_capacity(AEAD_NONCE_SIZE + ciphertext.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        store.put(key, &blob)?;
        Ok(())
    }

    /// Oeffnet den Blob unter DIESER Adresse. Ein fehlender ist `Ok(None)`.
    fn get_sealed<T>(
        &self,
        store: &dyn ReaderBlobStore,
        key: &ReaderBlobKey,
        decode: impl FnOnce(&[u8]) -> Result<T, ReaderVaultError>,
    ) -> Result<Option<T>, ReaderVaultError> {
        let Some(blob) = store.get(key)? else {
            return Ok(None);
        };
        if blob.len() < AEAD_NONCE_SIZE {
            return Err(ReaderVaultError::Contents);
        }
        let (nonce, ciphertext) = blob.split_at(AEAD_NONCE_SIZE);
        let nonce: [u8; AEAD_NONCE_SIZE] =
            nonce.try_into().map_err(|_| ReaderVaultError::Contents)?;
        let opened = aead_open(
            &self.cursor_key,
            &SecretBytes::new(nonce),
            ciphertext,
            &blob_aad(key.as_str().as_bytes()),
        )?;
        opened.with_exposed(decode).map(Some)
    }

    /// Schreibt den bestaetigten Cursor.
    pub(crate) fn put_cursor(
        &self,
        store: &mut dyn ReaderBlobStore,
        cursor: &ConfirmedCursor,
    ) -> Result<(), ReaderVaultError> {
        self.put_sealed(store, &cursor_key()?, encode_cursor(cursor))
    }

    /// Schreibt die Adressliste der dauerhaft gecachten Objekte.
    ///
    /// SORTIERT und duplikatfrei, und beides ist tragend: die Liste ist eine
    /// MENGE, und zwei Laeufe ueber denselben Bestand muessen dieselben Bytes
    /// ergeben, sonst waere jeder Vergleich darauf wertlos.
    ///
    /// # Errors
    /// `EA-READER-VAULT-CONTENTS` oberhalb von [`MAX_CACHED_OBJECTS_V1`] — eine
    /// gekuerzte Liste waere eine Verifikation ueber einen Bestand, den niemand
    /// mehr benennen kann, und damit genau der stille Fehlschlag, den diese
    /// Liste verhindert.
    pub(crate) fn put_object_manifest(
        &self,
        store: &mut dyn ReaderBlobStore,
        hashes: &[ObjectHash],
    ) -> Result<(), ReaderVaultError> {
        let mut sorted = hashes.to_vec();
        sorted.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        sorted.dedup_by(|left, right| left.as_bytes() == right.as_bytes());
        if sorted.len() > MAX_CACHED_OBJECTS_V1 {
            return Err(ReaderVaultError::Contents);
        }
        self.put_sealed(store, &objects_key()?, encode_object_manifest(&sorted))
    }

    /// Liest die Adressliste. Ein fehlender Blob ist eine LEERE Liste.
    ///
    /// Leer und nicht `None`: ein frisches Geraet hat noch nichts gecacht, und
    /// das ist kein Sonderfall, ueber den ein Aufrufer entscheiden muesste.
    ///
    /// # Errors
    /// `EA-CRYPTO-AEAD-OPEN` fuer einen fremden oder verfaelschten Blob,
    /// `EA-READER-VAULT-CONTENTS` fuer eine verfehlte Form.
    pub(crate) fn get_object_manifest(
        &self,
        store: &dyn ReaderBlobStore,
    ) -> Result<Vec<ObjectHash>, ReaderVaultError> {
        Ok(self
            .get_sealed(store, &objects_key()?, decode_object_manifest)?
            .unwrap_or_default())
    }

    /// Die ROHEN Blobbytes des Cursors, ohne sie zu deuten.
    ///
    /// Der Ruecknahmepfad von `confirm` braucht genau das: er legt den
    /// VORIGEN Blob wieder hin und rechnet dafuer nichts nach. Ein erneutes
    /// Kodieren des vorigen Cursors waere ein zweiter Weg zu denselben Bytes.
    pub(crate) fn raw_blob(
        &self,
        store: &dyn ReaderBlobStore,
    ) -> Result<Option<Vec<u8>>, ReaderVaultError> {
        Ok(store.get(&cursor_key()?)?)
    }

    /// Legt einen zuvor gelesenen ROHEN Blob zurueck — oder loescht ihn.
    pub(crate) fn restore_raw_blob(
        &self,
        store: &mut dyn ReaderBlobStore,
        blob: Option<&[u8]>,
    ) -> Result<(), ReaderVaultError> {
        let key = cursor_key()?;
        match blob {
            Some(bytes) => store.put(&key, bytes)?,
            None => store.delete(&key)?,
        }
        Ok(())
    }

    /// Liest den bestaetigten Cursor. Ein fehlender Blob ist `Ok(None)`.
    ///
    /// # Errors
    /// `EA-CRYPTO-AEAD-OPEN` fuer einen fremden oder verfaelschten Blob,
    /// `EA-READER-VAULT-CONTENTS` fuer eine verfehlte Form.
    pub(crate) fn get_cursor(
        &self,
        store: &dyn ReaderBlobStore,
    ) -> Result<Option<ConfirmedCursor>, ReaderVaultError> {
        self.get_sealed(store, &cursor_key()?, decode_cursor)
    }
}

/// Die Adresse des Cursorblobs, aus der EINEN Konstante.
fn cursor_key() -> Result<ReaderBlobKey, ReaderVaultError> {
    Ok(ReaderBlobKey::new(READER_SYNC_CURSOR_BLOB_KEY_V1)?)
}

/// Die Adresse der Objektliste, aus der EINEN Konstante.
fn objects_key() -> Result<ReaderBlobKey, ReaderVaultError> {
    Ok(ReaderBlobKey::new(READER_SYNC_OBJECTS_BLOB_KEY_V1)?)
}

/// Die Objektliste als deterministisches CBOR, in einem Geheimnistraeger.
///
/// EIN `bstr` und kein Array aus 32-Byte-Elementen. Der Unterschied ist die
/// Grenze: ein Array liefe gegen `ParserLimits::V1.max_container_items`
/// (10_000), ein einzelner `bstr` gegen `max_text_or_bytes` (1_048_592 Byte)
/// — also gegen [`MAX_CACHED_OBJECTS_V1`] und damit gegen die dreifache Zahl
/// von Objekten. Die Elemente sind fest 32 Byte breit, die Laenge ist damit
/// selbstbeschreibend, und es gibt keine Struktur, ueber die ein Angreifer den
/// Parser fuehren koennte.
fn encode_object_manifest(hashes: &[ObjectHash]) -> SecretVec {
    let mut flat = Vec::with_capacity(hashes.len() * 32);
    for hash in hashes {
        flat.extend_from_slice(hash.as_bytes());
    }
    let mut bytes = Vec::with_capacity(flat.len() + 16);
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .array(2)
        .and_then(|encoder| encoder.u64(1))
        .and_then(|encoder| encoder.bytes(&flat))
        .expect("encoding a fixed-shape object manifest into Vec cannot fail");
    debug_assert!(validate(&bytes, ParserLimits::V1).is_ok());
    SecretVec::new(bytes)
}

/// Die Objektliste aus deterministischem CBOR.
///
/// Dieselbe Reihenfolge wie ueberall: `validate`, feldweise, Trailing-Sperre,
/// Rueckprobe gegen die eigenen Bytes.
fn decode_object_manifest(bytes: &[u8]) -> Result<Vec<ObjectHash>, ReaderVaultError> {
    validate(bytes, ParserLimits::V1).map_err(|_| ReaderVaultError::Contents)?;
    let mut decoder = Decoder::new(bytes);
    if decoder.array().map_err(|_| ReaderVaultError::Contents)? != Some(2) {
        return Err(ReaderVaultError::Contents);
    }
    if decoder.u64().map_err(|_| ReaderVaultError::Contents)? != 1 {
        return Err(ReaderVaultError::Contents);
    }
    let flat = decoder.bytes().map_err(|_| ReaderVaultError::Contents)?;
    if decoder.position() != bytes.len() || flat.len() % 32 != 0 {
        return Err(ReaderVaultError::Contents);
    }
    let hashes = flat
        .chunks_exact(32)
        .map(|chunk| ObjectHash::try_from(chunk).map_err(|_| ReaderVaultError::Contents))
        .collect::<Result<Vec<ObjectHash>, ReaderVaultError>>()?;
    if !encode_object_manifest(&hashes).matches(bytes) {
        return Err(ReaderVaultError::Contents);
    }
    Ok(hashes)
}

/// Der Cursor als deterministisches CBOR, in einem Geheimnistraeger.
///
/// Ein [`SecretVec`], obwohl kein Schluessel darin liegt: `aead_seal` nimmt
/// seinen Klartext BESITZEND als `SecretVec`, und die Bytes tragen den
/// Eintragshash — dieselbe Ueberlegung, die `encode_entry_state` in
/// `crates/ea-reader/src/entry_state.rs` ausschreibt.
fn encode_cursor(cursor: &ConfirmedCursor) -> SecretVec {
    let mut bytes = Vec::with_capacity(96);
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .array(4)
        .and_then(|encoder| encoder.bytes(cursor.chain_id.as_bytes()))
        .and_then(|encoder| encoder.u64(cursor.sequence.get()))
        .and_then(|encoder| encoder.bytes(cursor.entry_hash.as_bytes()))
        .expect("encoding a fixed-shape cursor into Vec cannot fail");
    match cursor.technical_cursor.as_deref() {
        None => {
            encoder
                .null()
                .expect("encoding a CBOR null into Vec cannot fail");
        }
        Some(token) => {
            encoder
                .bytes(token)
                .expect("encoding an opaque token into Vec cannot fail");
        }
    }
    debug_assert!(validate(&bytes, ParserLimits::V1).is_ok());
    SecretVec::new(bytes)
}

/// Der Cursor aus deterministischem CBOR.
///
/// Dieselbe Reihenfolge wie ueberall: `validate`, feldweise, Trailing-Sperre,
/// Rueckprobe gegen die eigenen Bytes.
fn decode_cursor(bytes: &[u8]) -> Result<ConfirmedCursor, ReaderVaultError> {
    validate(bytes, ParserLimits::V1).map_err(|_| ReaderVaultError::Contents)?;
    let mut decoder = Decoder::new(bytes);
    if decoder.array().map_err(|_| ReaderVaultError::Contents)? != Some(4) {
        return Err(ReaderVaultError::Contents);
    }
    let chain_id = ChainId::try_from(decoder.bytes().map_err(|_| ReaderVaultError::Contents)?)
        .map_err(|_| ReaderVaultError::Contents)?;
    let sequence = ChainSequence::new(decoder.u64().map_err(|_| ReaderVaultError::Contents)?);
    let entry_hash = EntryHash::try_from(decoder.bytes().map_err(|_| ReaderVaultError::Contents)?)
        .map_err(|_| ReaderVaultError::Contents)?;
    let technical_cursor = if decoder.datatype().map_err(|_| ReaderVaultError::Contents)?
        == minicbor::data::Type::Null
    {
        decoder.null().map_err(|_| ReaderVaultError::Contents)?;
        None
    } else {
        Some(
            decoder
                .bytes()
                .map_err(|_| ReaderVaultError::Contents)?
                .to_vec(),
        )
    };
    if decoder.position() != bytes.len() {
        return Err(ReaderVaultError::Contents);
    }
    let cursor = ConfirmedCursor::new(chain_id, sequence, entry_hash, technical_cursor);
    if !encode_cursor(&cursor).matches(bytes) {
        return Err(ReaderVaultError::Contents);
    }
    Ok(cursor)
}

/// Schreibt Bytes als Kleinbuchstaben-Hex.
fn write_hex(formatter: &mut core::fmt::Formatter<'_>, bytes: &[u8]) -> core::fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}
