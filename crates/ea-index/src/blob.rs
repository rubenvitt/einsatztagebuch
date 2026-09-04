//! Der als GANZES versiegelte Indexblob.
//!
//! Der Kopf sind [`INDEX_BLOB_HEADER_BYTES_V1`] Klartextbytes: Magic,
//! Formatversion, Nonce. Danach folgt GENAU EIN ChaCha20-Poly1305-Chiffrat
//! ueber den deterministisch kodierten Indexkoerper, mit dem KOPF als AAD —
//! damit sind Formatversion und Nonce authentisiert, und ein Rueckspielen eines
//! aelteren Blobs unter neuem Kopf faellt an der Oeffnung durch.
//!
//! # Der Koerper traegt PAKETE und keine Trefferlisten
//!
//! Die drei Trefferlisten entstehen beim Oeffnen NEU, aus denselben Zeilen, die
//! auch der Rebuild aufnimmt: [`IndexBlobV1::open`] ist buchstaeblich
//! `InvertedIndexV1::rebuild_from` ueber den dekodierten Bestand. Ein Koerper,
//! der Pakete UND Listen truege, koennte einen Term nennen, zu dem es kein
//! Paket gibt — eine Inkonsistenz, die keine Zusicherung dieser Crate sehen
//! wuerde, weil beide Seiten aus denselben Bytes kaemen.
//!
//! # Der Schluessel wird GEREICHT
//!
//! Diese Crate leitet nichts ab. Sie empfaengt ein `SecretBytes<CEK_SIZE>`, das
//! der Aufrufer aus `UnlockedVault::index_key()` bezieht — der oeffentlichen
//! Methode, die intern `HKDF-SHA-256(vault_key, info = VAULT_INDEX_INFO_V1)`
//! rechnet, also denselben Ableitungsweg wie Cache und Zustandsspeicher. Ein
//! zweiter Ableitungspfad hier waere eine zweite Wahrheit ueber denselben
//! Schluessel.

use ea_cbor::{CborError, ParserLimits};
use ea_crypto::{
    AEAD_NONCE_SIZE, AEAD_OVERHEAD, CEK_SIZE, SecretBytes, SecretVec, aead_open, aead_seal,
};
use ea_types::{ChainSequence, EntryHash, RecordId, UnixMillis};

use crate::{
    IndexError,
    inverted::{IndexableRecordV1, InvertedIndexV1, MONOLITHIC_INDEX_MAX_PACKAGES_V1},
};

/// Das Praefix des versiegelten Indexblobs, nach dem Muster von
/// `BUNDLE_MAGIC_V1` in `ea-archive`.
pub const INDEX_BLOB_MAGIC_V1: [u8; 30] = *b"EINSATZARCHIV-READER-INDEX-v1\n";

/// Die Formatversion des Blobs, big-endian im Kopf.
pub const INDEX_FORMAT_VERSION_V1: u32 = 1;

/// 30 Byte Magic + 4 Byte Formatversion (big-endian) + 12 Byte Nonce.
pub const INDEX_BLOB_HEADER_BYTES_V1: usize = INDEX_BLOB_MAGIC_V1.len() + 4 + AEAD_NONCE_SIZE;

/// Die HOECHSTZAHL der Pakete in EINEM Blob.
///
/// Sie ist nicht dieselbe Zahl wie [`MONOLITHIC_INDEX_MAX_PACKAGES_V1`], und
/// die Unterscheidung ist tragend. Die Schwelle dort ist das SIGNAL, ab dem
/// die vorab genehmigte Segmentierung beginnen MUSS; die Aufnahme verweigert
/// dort ausdruecklich nicht, weil fehlender Zugriff nie aus einer
/// Ressourcengrenze folgen darf. Diese Zahl hier ist die FORMGRENZE eines
/// einzelnen Blobs — der Punkt, ab dem ein Einzelblob als missgebildet gilt.
///
/// Der Faktor vier ist der Spielraum zwischen beiden: ein Reader, der das
/// Signal sieht und segmentiert, erreicht ihn nie; einer, der es
/// ueberginge, laeuft in eine SICHTBARE Weigerung statt in einen still
/// wachsenden Einzelblob. Die Weigerung faellt dabei symmetrisch — die
/// Versiegelung prueft ihren eigenen Koerper gegen dieselben Grenzen, es
/// entsteht also nie ein Blob, den die Oeffnung danach nicht mehr annimmt.
pub const INDEX_BLOB_MAX_PACKAGES_V1: usize = 4 * MONOLITHIC_INDEX_MAX_PACKAGES_V1;

/// Die Formgrenzen des Indexkoerpers.
///
/// `ParserLimits::V1` ist hier GEMESSEN unbrauchbar: seine
/// `max_container_items` und `max_total_items` stehen bei je 10 000, und ein
/// Index ueber 50 000 Pakete uebersteigt beide um Groessenordnungen. Ein
/// Koerper unter diesen Grenzen liesse sich weder versiegeln noch oeffnen.
/// Eine eigene Grenzenmenge ist der vorgesehene Weg — `ea-sync-protocol` fuehrt
/// aus demselben Grund `PROTOCOL_PARSER_LIMITS_V1`.
///
/// Jede Zahl ist GERECHNET:
///
/// * `max_depth`: der Koerper schachtelt Paketliste → Paketzeile → Termliste,
///   also drei Behaelter. Acht laesst Luft fuer eine spaetere Spalte und bleibt
///   weit unter jeder Schachtelung, die ein Stapel spuerte.
/// * `max_container_items`: der groesste Behaelter ist die Paketliste, und sie
///   traegt hoechstens [`INDEX_BLOB_MAX_PACKAGES_V1`] Zeilen.
/// * `max_total_items`: eine Zeile kostet 1 Behaelter + 9 Skalare + 1
///   Optionsbehaelter (+1 Wert) + 3 Termbehaelter samt ihren Termen. Bei
///   wenigen Termen je Achse sind das rund zwanzig Marken; der Faktor 32 traegt
///   sie mit Spielraum fuer laengere Fahrzeug- und Personenlisten.
/// * `max_text_or_bytes`: unveraendert der Wert aus `ParserLimits::V1`. Kein
///   Feld dieses Koerpers reicht auch nur in die Naehe — die Textgrenzen der
///   Nutzlast liegen weit darunter —, und eine EIGENE Zahl waere hier eine
///   zweite Wahrheit ueber dieselbe Schranke.
pub const INDEX_PARSER_LIMITS_V1: ParserLimits = ParserLimits {
    max_depth: 8,
    max_container_items: INDEX_BLOB_MAX_PACKAGES_V1,
    max_total_items: 32 * INDEX_BLOB_MAX_PACKAGES_V1,
    max_text_or_bytes: 1_048_592,
};

/// Die Zahl der Positionen EINER Paketzeile im Koerper.
const PACKAGE_ROW_POSITIONS_V1: u64 = 13;

/// Der versiegelte Index.
pub struct IndexBlobV1 {
    bytes: Vec<u8>,
}

impl IndexBlobV1 {
    /// Versiegelt den Bestand unter `key` und `nonce`.
    ///
    /// Die Nonce ist ein PARAMETER und keine Eigenleistung dieser Crate: die
    /// Wahl einer frischen Nonce je Versiegelung gehoert dem Aufrufer, und nur
    /// weil sie hier hereingereicht wird, ist der bytegleiche Rebuild ueberhaupt
    /// pruefbar.
    ///
    /// # Errors
    /// `EA-CBOR-CONTAINER-LIMIT` oberhalb von [`INDEX_BLOB_MAX_PACKAGES_V1`],
    /// jeder andere `EA-CBOR-*`-Code, wenn der eigene Koerper die Rueckprobe
    /// nicht besteht, und `EA-CRYPTO-SIZE-LIMIT`, wenn die Versiegelung ihn
    /// nicht traegt.
    pub fn seal(
        index: &InvertedIndexV1,
        key: &SecretBytes<CEK_SIZE>,
        nonce: &SecretBytes<AEAD_NONCE_SIZE>,
    ) -> Result<Self, IndexError> {
        let body = encode_body(index)?;
        // Die Rueckprobe gegen die eigenen Bytes, wie ueberall in diesem
        // Bestand: was die Oeffnung gleich verlangen wird, muss die
        // Versiegelung schon eingehalten haben.
        ea_cbor::validate(&body, INDEX_PARSER_LIMITS_V1)?;

        let mut bytes = Vec::with_capacity(INDEX_BLOB_HEADER_BYTES_V1 + body.len() + AEAD_OVERHEAD);
        bytes.extend_from_slice(&INDEX_BLOB_MAGIC_V1);
        bytes.extend_from_slice(&INDEX_FORMAT_VERSION_V1.to_be_bytes());
        nonce.with_exposed(|exposed| bytes.extend_from_slice(exposed));
        debug_assert_eq!(bytes.len(), INDEX_BLOB_HEADER_BYTES_V1);

        let header = bytes.clone();
        let ciphertext = aead_seal(key, nonce, SecretVec::new(body), &header)?;
        bytes.extend_from_slice(&ciphertext);
        Ok(Self { bytes })
    }

    /// Oeffnet einen versiegelten Index unter `key`.
    ///
    /// # Errors
    /// `EA-INDEX-BLOB-FORMAT`, wenn die Bytes den Kopf gar nicht tragen —
    /// geprueft VOR jeder Beruehrung des Schluessels. `EA-CRYPTO-AEAD-OPEN` fuer
    /// einen falschen Schluessel, ein veraendertes Chiffrat und einen
    /// veraenderten Kopf, der die Formzusicherungen ueberlebt. `EA-CBOR-*` fuer
    /// einen Koerper, der die Formgrenzen verletzt.
    pub fn open(bytes: &[u8], key: &SecretBytes<CEK_SIZE>) -> Result<InvertedIndexV1, IndexError> {
        if bytes.len() < INDEX_BLOB_HEADER_BYTES_V1 + AEAD_OVERHEAD {
            return Err(IndexError::BlobFormat);
        }
        let (header, ciphertext) = bytes.split_at(INDEX_BLOB_HEADER_BYTES_V1);
        if header[..INDEX_BLOB_MAGIC_V1.len()] != INDEX_BLOB_MAGIC_V1 {
            return Err(IndexError::BlobFormat);
        }
        let version_at = INDEX_BLOB_MAGIC_V1.len();
        let version = u32::from_be_bytes(
            header[version_at..version_at + 4]
                .try_into()
                .map_err(|_| IndexError::BlobFormat)?,
        );
        if version != INDEX_FORMAT_VERSION_V1 {
            return Err(IndexError::BlobFormat);
        }
        let nonce_bytes: [u8; AEAD_NONCE_SIZE] = header[version_at + 4..]
            .try_into()
            .map_err(|_| IndexError::BlobFormat)?;
        let nonce = SecretBytes::new(nonce_bytes);

        let plaintext = aead_open(key, &nonce, ciphertext, header)?;
        plaintext.with_exposed(|body| {
            ea_cbor::validate(body, INDEX_PARSER_LIMITS_V1)?;
            let records = decode_body(body)?;
            InvertedIndexV1::rebuild_from(records.iter())
        })
    }

    /// Die versiegelten Bytes: Kopf und Chiffrat.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Kodiert den Bestand deterministisch.
///
/// Die Pakete reisen in der Ordnung ihres Entry-Hashes, die Terme in der
/// Ordnung ihrer Termschluessel — beides `BTreeMap`/`BTreeSet`-Ordnungen und
/// damit unabhaengig von der Einfuegereihenfolge.
///
/// Der Koerper ist eine LISTE und keine Abbildung. Das ist kein Geschmack:
/// `ea-cbor` ordnet Abbildungsschluessel bytweise ueber ihre KODIERTE Form —
/// bei Textschluesseln also erst nach Laenge, dann nach Inhalt —, waehrend eine
/// `BTreeMap<String, _>` rein lexikographisch ordnet. Zwei Ordnungen fuer
/// dieselbe Menge waeren zwei Wahrheiten, und die Liste hat nur eine.
fn encode_body(index: &InvertedIndexV1) -> Result<Vec<u8>, IndexError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    let packages = u64::try_from(index.packages.len()).map_err(|_| encode_failure())?;
    encoder.array(packages).map_err(|_| encode_failure())?;
    for package in index.packages.values() {
        let hit = &package.hit;
        encoder
            .array(PACKAGE_ROW_POSITIONS_V1)
            .map_err(|_| encode_failure())?;
        encoder
            .bytes(hit.entry_hash().as_bytes())
            .map_err(|_| encode_failure())?;
        encoder
            .u64(hit.chain_sequence().get())
            .map_err(|_| encode_failure())?;
        encoder
            .bytes(hit.record_id().as_bytes())
            .map_err(|_| encode_failure())?;
        encoder
            .str(hit.source_schema().0)
            .map_err(|_| encode_failure())?;
        encoder
            .u64(hit.source_schema().1)
            .map_err(|_| encode_failure())?;
        encoder
            .str(hit.target_schema().0)
            .map_err(|_| encode_failure())?;
        encoder
            .u64(hit.target_schema().1)
            .map_err(|_| encode_failure())?;
        encoder
            .str(hit.human_incident_number())
            .map_err(|_| encode_failure())?;
        encoder
            .i64(hit.occurred_at_start().get())
            .map_err(|_| encode_failure())?;
        match package.occurred_at_end {
            // Ein Optionsbehaelter und kein `null`: `ea-cbor` weist
            // nicht-minimale einfache Werte ab, und ein Behaelter der Laenge
            // null oder eins traegt dieselbe Aussage ohne diese Klippe.
            None => {
                encoder.array(0).map_err(|_| encode_failure())?;
            }
            Some(end) => {
                encoder.array(1).map_err(|_| encode_failure())?;
                encoder.i64(end.get()).map_err(|_| encode_failure())?;
            }
        }
        for terms in [
            &package.keyword_terms,
            &package.vehicle_terms,
            &package.person_terms,
        ] {
            let count = u64::try_from(terms.len()).map_err(|_| encode_failure())?;
            encoder.array(count).map_err(|_| encode_failure())?;
            for term in terms {
                encoder.str(term).map_err(|_| encode_failure())?;
            }
        }
    }
    Ok(encoder.into_writer())
}

/// Dekodiert den Bestand in seine Zeilen.
///
/// Der Koerper hat die Formgrenzen bereits bestanden, wenn diese Funktion
/// laeuft; was hier noch scheitern kann, ist eine falsche STELLIGKEIT oder eine
/// Bytefolge, die keine Herkunftskennung ist.
fn decode_body(body: &[u8]) -> Result<Vec<IndexableRecordV1>, IndexError> {
    let mut decoder = minicbor::Decoder::new(body);
    let packages = decoder
        .array()
        .map_err(|_| decode_failure())?
        .ok_or_else(decode_failure)?;
    let mut records = Vec::with_capacity(usize::try_from(packages).unwrap_or(0));
    for _ in 0..packages {
        let positions = decoder
            .array()
            .map_err(|_| decode_failure())?
            .ok_or_else(decode_failure)?;
        if positions != PACKAGE_ROW_POSITIONS_V1 {
            return Err(decode_failure());
        }
        let source_entry_hash = EntryHash::try_from(decoder.bytes().map_err(|_| decode_failure())?)
            .map_err(|_| decode_failure())?;
        let chain_sequence = ChainSequence::new(decoder.u64().map_err(|_| decode_failure())?);
        let record_id = RecordId::try_from(decoder.bytes().map_err(|_| decode_failure())?)
            .map_err(|_| decode_failure())?;
        let source_schema_id = decoder.str().map_err(|_| decode_failure())?.to_owned();
        let source_schema_version = decoder.u64().map_err(|_| decode_failure())?;
        let target_schema_id = decoder.str().map_err(|_| decode_failure())?.to_owned();
        let target_schema_version = decoder.u64().map_err(|_| decode_failure())?;
        let human_incident_number = decoder.str().map_err(|_| decode_failure())?.to_owned();
        let occurred_at_start = UnixMillis::new(decoder.i64().map_err(|_| decode_failure())?);
        let occurred_at_end = match decoder
            .array()
            .map_err(|_| decode_failure())?
            .ok_or_else(decode_failure)?
        {
            0 => None,
            1 => Some(UnixMillis::new(
                decoder.i64().map_err(|_| decode_failure())?,
            )),
            _ => return Err(decode_failure()),
        };
        let keyword_terms = decode_terms(&mut decoder)?;
        let vehicle_terms = decode_terms(&mut decoder)?;
        let person_terms = decode_terms(&mut decoder)?;
        records.push(IndexableRecordV1 {
            source_entry_hash,
            chain_sequence,
            record_id,
            source_schema_id,
            source_schema_version,
            target_schema_id,
            target_schema_version,
            human_incident_number,
            occurred_at_start,
            occurred_at_end,
            keyword_terms,
            vehicle_terms,
            person_terms,
        });
    }
    if decoder.position() != body.len() {
        return Err(decode_failure());
    }
    Ok(records)
}

/// Eine Termliste an der aktuellen Position.
fn decode_terms(decoder: &mut minicbor::Decoder<'_>) -> Result<Vec<String>, IndexError> {
    let count = decoder
        .array()
        .map_err(|_| decode_failure())?
        .ok_or_else(decode_failure)?;
    let mut terms = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
    for _ in 0..count {
        terms.push(decoder.str().map_err(|_| decode_failure())?.to_owned());
    }
    Ok(terms)
}

/// Der Befund einer gescheiterten Kodierung.
const fn encode_failure() -> IndexError {
    IndexError::Cbor(CborError::Encode)
}

/// Der Befund einer gescheiterten Dekodierung.
const fn decode_failure() -> IndexError {
    IndexError::Cbor(CborError::Invalid)
}
