//! Der Objektcache: EXAKTE Archivbytes, verschluesselt, ueber einem opaken
//! Bytespeicher.
//!
//! # Der Cache kodiert nichts um
//!
//! Er speichert die EXAKTEN Objektbytes — er sortiert nichts, laesst nichts aus
//! und normalisiert nichts. Der Grund steht in der spaeteren Neuindizierung:
//! die Aufgabe „Verschlüsselter invertierter Index in OPFS, Suche,
//! Schemakompatibilität und die GEMESSENE 50.000-Paket-Schwelle" verifiziert
//! GENAU diese Bytes erneut, und eine Umkodierung dazwischen machte jede
//! Signaturpruefung darauf wertlos. `web-reader-design.md` §5.3 verlangt
//! ausserdem im Datei-Modus die vollstaendige Neupruefung bei jedem Oeffnen;
//! auch sie liest von hier.
//!
//! # Der Speicher wird je Aufruf gereicht und nie gehalten
//!
//! [`ReaderObjectCache`] kennt weder OPFS noch einen Worker. Er nimmt den
//! Bytespeicher als `&dyn ReaderBlobStore` beziehungsweise
//! `&mut dyn ReaderBlobStore` je Aufruf entgegen. Ein gehaltener Speicher
//! zwaenge den Cache in die Lebensdauer eines Wirts, den es im Browser nur
//! innerhalb eines Worker-Zyklus gibt.
//!
//! # Der Schluessel haengt am TRESOR und nicht am Speicher
//!
//! [`ReaderObjectCache::open`] leitet ihn mit
//! `derive_key(vault_key, VAULT_CACHE_INFO_V1)` ab und BESITZT ihn. Ein zweiter
//! Tresor oeffnet denselben Bytespeicher deshalb nicht — gemessen von
//! `exact_objects_and_entry_states_are_never_plaintext_in_the_blob_store`, das
//! mit einem fremden Tresor `EA-CRYPTO-AEAD-OPEN` bekommt und nicht etwa ein
//! leeres Ergebnis. Der Besitz ist zugleich ein Lebensdauervertrag: `open`
//! LEIHT den Tresor nicht aus, sonst koennte kein Aufrufer den Cache eines
//! kurzlebigen Tresors ueberhaupt bilden.
//!
//! # Der Adressraum ist hexadezimal, und das ist kein Geschmack
//!
//! `ReaderBlobStore::keys()` gibt die Schluessel im KLARTEXT heraus. Ein
//! fachlicher Bestandteil im Schluessel waere ein Leck, das keine Pruefung des
//! Blobinhalts faengt — deshalb `cache/<hex objectHash>` und nichts sonst.

use ea_crypto::{
    AEAD_NONCE_SIZE, CEK_SIZE, SecretBytes, SecretVec, aead_open, aead_seal, object_hash,
};
use ea_types::ObjectHash;

use crate::blob_store::{ReaderBlobKey, ReaderBlobStore};
use crate::envelope::blob_aad;
use crate::vault::{ReaderVaultError, UnlockedVault};

/// Das Praefix des Adressraums. Es steht hier und nicht als Zeichenkette im
/// Rumpf, damit Schreiben und Lesen dieselbe Adresse bilden.
const CACHE_KEY_PREFIX: &str = "cache/";

/// Der verschluesselte Objektcache EINER entsperrten Sitzung.
pub struct ReaderObjectCache {
    cache_key: SecretBytes<CEK_SIZE>,
}

impl ReaderObjectCache {
    /// Oeffnet den Cache eines entsperrten Tresors.
    ///
    /// # Panics
    /// Nie erreichbar: HKDF-SHA-256 weist eine Ausgabelaenge erst oberhalb von
    /// 255 · 32 Byte ab, und hier sind es 32.
    #[must_use]
    pub fn open(vault: &UnlockedVault) -> Self {
        Self {
            cache_key: vault
                .cache_key()
                .expect("HKDF-SHA-256 liefert 32 Byte ohne Laengenbeschraenkung"),
        }
    }

    /// Legt EXAKTE Objektbytes ab und gibt ihren Objekthash zurueck.
    ///
    /// Der Hash entsteht ueber `ea_crypto::object_hash` und damit ueber
    /// dieselbe Domaenentrennung wie im Archiv; der Cache erfindet keine
    /// zweite Adressierung.
    ///
    /// # Errors
    /// `EA-READER-BLOB-KEY`/`EA-READER-BLOB-HOST` aus dem Bytespeicher,
    /// `EA-LOCAL-CRYPTO-RNG` ohne Entropie und die durchgereichten
    /// AEAD-Codes von `ea-crypto`.
    pub fn put_exact_object(
        &self,
        store: &mut dyn ReaderBlobStore,
        exact_bytes: &[u8],
    ) -> Result<ObjectHash, ReaderVaultError> {
        let hash = object_hash(exact_bytes);
        let key = cache_key(hash)?;
        let mut nonce = [0_u8; AEAD_NONCE_SIZE];
        getrandom::fill(&mut nonce)
            .map_err(|_| ReaderVaultError::Crypto(ea_crypto::CryptoError::LocalRng))?;
        let ciphertext = aead_seal(
            &self.cache_key,
            &SecretBytes::new(nonce),
            SecretVec::new(exact_bytes.to_vec()),
            &blob_aad(key.as_str().as_bytes()),
        )?;
        let mut blob = Vec::with_capacity(AEAD_NONCE_SIZE + ciphertext.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        store.put(&key, &blob)?;
        Ok(hash)
    }

    /// Holt EXAKTE Objektbytes zurueck. Ein fehlender Blob ist `Ok(None)`.
    ///
    /// # Errors
    /// `EA-CRYPTO-AEAD-OPEN`, wenn der Blob unter einem ANDEREN Tresor abgelegt
    /// wurde oder verfaelscht ist; `EA-READER-VAULT-CONTENTS` fuer einen Blob,
    /// der nicht einmal seinen Nonce traegt.
    pub fn get_exact_object(
        &self,
        store: &dyn ReaderBlobStore,
        object_hash: ObjectHash,
    ) -> Result<Option<Vec<u8>>, ReaderVaultError> {
        let key = cache_key(object_hash)?;
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
            &self.cache_key,
            &SecretBytes::new(nonce),
            ciphertext,
            &blob_aad(key.as_str().as_bytes()),
        )?;
        Ok(Some(opened.with_exposed(<[u8]>::to_vec)))
    }
}

/// Die Adresse eines gecachten Objekts.
fn cache_key(object_hash: ObjectHash) -> Result<ReaderBlobKey, ReaderVaultError> {
    Ok(ReaderBlobKey::new(&format!(
        "{CACHE_KEY_PREFIX}{}",
        hex::encode(object_hash.as_bytes())
    ))?)
}
