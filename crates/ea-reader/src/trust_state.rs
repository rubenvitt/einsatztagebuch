//! Das Alter des zuletzt bezogenen Trust-Standes und sein Speicher.
//!
//! # Warum das Alter ueberhaupt sichtbar sein MUSS
//!
//! `web-reader-design.md` §4.2, woertlich: ein Widerruf erreicht ein Geraet
//! erst beim naechsten Bezug des Trust-Bestandes, und ein dauerhaft im
//! Datei-Modus betriebenes Geraet kann deshalb eine widerrufene Bundle-Fassung
//! weiter ausfuehren. Die Anwendung MUSS das Alter des zuletzt bezogenen
//! Standes sichtbar ausweisen und ab der Policyfrist zur Aktualisierung
//! auffordern. Die Ueberschreitung ist eine AUFFORDERUNG und keine Sperre —
//! wer daraus eine Sperre macht, nimmt einem Leser im Einsatz den Zugriff auf
//! ein Archiv, das er lesen darf.
//!
//! # Warum ein EIGENER Speicher und kein fuenfter Tresorwert
//!
//! `web-reader-design.md` §6.1 zaehlt den Tresorinhalt normativ auf: zwei
//! private Schluessel, der gepinnte Anker, der zuletzt verifizierte
//! Registry-Stand. Ein fuenfter Wert im Tresorkoerper aenderte diese Spec und
//! zwaenge jeden bereits versiegelten Tresor zum Neuversiegeln. Der Zeitpunkt
//! liegt deshalb in einem EIGENEN, unter dem Tresorschluessel verschluesselten
//! OPFS-Speicher — der dritte seiner Bauform neben [`crate::ReaderObjectCache`]
//! und [`crate::ReaderEntryStateStore`], mit eigenem Ableitungskontext, damit
//! kein Schluessel zwei Speicher oeffnet.
//!
//! # `0` heisst UNGESETZT
//!
//! `schemas/archive/v1/trust.cddl` notiert an `reader-trust-refresh-ms`
//! woertlich `0 = unset`. Eine Frist von null ist deshalb KEINE Frist von null
//! Millisekunden, sondern gar keine — sonst waere jeder Bestand ab der ersten
//! Millisekunde ueberfaellig, und die Aufforderung verloere ihre Aussage.

use ea_crypto::{AEAD_NONCE_SIZE, CEK_SIZE, SecretBytes, SecretVec, aead_open, aead_seal};
use ea_types::{RegistryVersion, UnixMillis};
use minicbor::{Decoder, Encoder};

use crate::blob_store::{ReaderBlobKey, ReaderBlobStore};
use crate::envelope::blob_aad;
use crate::vault::{ReaderVaultError, UnlockedVault};

/// Die Adresse des Trust-Standes. Er ist EINER je Geraet, nicht einer je Objekt.
const TRUST_STATE_KEY_V1: &str = "trust-state/v1";

/// Der zuletzt bezogene Trust-Stand.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ReaderTrustStateV1 {
    /// Wann der Bestand zuletzt bezogen wurde.
    pub last_trust_refresh_at: UnixMillis,
    /// Der Registry-Stand, den dieser Bezug verifiziert hat.
    pub registry_version: RegistryVersion,
}

/// Das Alter des Trust-Standes, wie die Oberflaeche es ausweist.
///
/// Das TypeScript-Gegenstueck ist `ReaderTrustAgeView` in
/// `crates/ea-ui-contracts/src/emit.rs`; die Feldnamen sind dieselben wie in
/// `FinalizationPreviewView`, weil es dieselbe Policy-Rechnung ist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReaderTrustAgeV1 {
    trust_age_ms: u64,
    reader_trust_refresh_ms: u64,
    trust_refresh_overdue: bool,
}

impl ReaderTrustAgeV1 {
    /// Das Alter des zuletzt bezogenen Standes in Millisekunden.
    #[must_use]
    pub const fn trust_age_ms(&self) -> u64 {
        self.trust_age_ms
    }

    /// Die Policyfrist, `0` heisst ungesetzt.
    #[must_use]
    pub const fn reader_trust_refresh_ms(&self) -> u64 {
        self.reader_trust_refresh_ms
    }

    /// Ob zur Aktualisierung aufgefordert wird. Nie eine Sperre.
    #[must_use]
    pub const fn trust_refresh_overdue(&self) -> bool {
        self.trust_refresh_overdue
    }
}

/// Rechnet das Alter des Trust-Standes gegen die geprueft wirksame Zeit.
///
/// Rein: sie liest nichts, schreibt nichts und zieht keine Uhr. Die drei
/// Eingaben kommen von aussen, weil der Browser seine wirksame Zeit und seine
/// Policyfrist aus dem verifizierten Bestand bezieht und nicht aus
/// `Date.now()`.
///
/// Ein Bezug, der in der ZUKUNFT liegt — eine zurueckgestellte Uhr —, ergibt
/// Alter null und nicht eine negative Zahl: derselbe Boden, den
/// `ea_writer::FinalizationPreview::trust_age_ms` fuer seinen Auswahlzeitpunkt
/// zieht.
#[must_use]
pub fn reader_trust_age_view(
    last_trust_refresh_at: UnixMillis,
    effective_now: UnixMillis,
    reader_trust_refresh_ms: u64,
) -> ReaderTrustAgeV1 {
    let trust_age_ms = effective_now
        .get()
        .saturating_sub(last_trust_refresh_at.get())
        .try_into()
        .unwrap_or(0_u64);
    ReaderTrustAgeV1 {
        trust_age_ms,
        reader_trust_refresh_ms,
        // `0 = unset`: ohne gesetzte Frist gibt es nichts zu ueberschreiten.
        trust_refresh_overdue: reader_trust_refresh_ms != 0
            && trust_age_ms > reader_trust_refresh_ms,
    }
}

/// Der verschluesselte Speicher des Trust-Standes.
pub struct ReaderTrustStateStore {
    trust_state_key: SecretBytes<CEK_SIZE>,
}

impl ReaderTrustStateStore {
    /// Oeffnet den Trust-Standspeicher eines entsperrten Tresors.
    ///
    /// # Panics
    /// Nie erreichbar: HKDF-SHA-256 weist eine Ausgabelaenge erst oberhalb von
    /// 255 · 32 Byte ab, und hier sind es 32.
    #[must_use]
    pub fn open(vault: &UnlockedVault) -> Self {
        Self {
            trust_state_key: vault
                .trust_state_key()
                .expect("HKDF-SHA-256 liefert 32 Byte ohne Laengenbeschraenkung"),
        }
    }

    /// Schreibt den zuletzt bezogenen Trust-Stand.
    ///
    /// # Errors
    /// Die Codes des Bytespeichers und von `ea-crypto`.
    pub fn put_trust_state(
        &self,
        store: &mut dyn ReaderBlobStore,
        state: ReaderTrustStateV1,
    ) -> Result<(), ReaderVaultError> {
        let key = trust_state_key()?;
        let mut nonce = [0_u8; AEAD_NONCE_SIZE];
        getrandom::fill(&mut nonce)
            .map_err(|_| ReaderVaultError::Crypto(ea_crypto::CryptoError::LocalRng))?;
        let ciphertext = aead_seal(
            &self.trust_state_key,
            &SecretBytes::new(nonce),
            encode_trust_state(state),
            &blob_aad(key.as_str().as_bytes()),
        )?;
        let mut blob = Vec::with_capacity(AEAD_NONCE_SIZE + ciphertext.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        store.put(&key, &blob)?;
        Ok(())
    }

    /// Holt den zuletzt bezogenen Trust-Stand. Ein Geraet, das nie bezogen hat,
    /// hat `Ok(None)` — und das ist NICHT dasselbe wie ein Alter von null.
    ///
    /// # Errors
    /// `EA-CRYPTO-AEAD-OPEN` fuer einen fremden oder verfaelschten Blob,
    /// `EA-READER-VAULT-CONTENTS` fuer eine verfehlte Form.
    pub fn get_trust_state(
        &self,
        store: &dyn ReaderBlobStore,
    ) -> Result<Option<ReaderTrustStateV1>, ReaderVaultError> {
        let key = trust_state_key()?;
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
            &self.trust_state_key,
            &SecretBytes::new(nonce),
            ciphertext,
            &blob_aad(key.as_str().as_bytes()),
        )?;
        opened.with_exposed(decode_trust_state).map(Some)
    }
}

/// Die Adresse des Trust-Standes.
fn trust_state_key() -> Result<ReaderBlobKey, ReaderVaultError> {
    Ok(ReaderBlobKey::new(TRUST_STATE_KEY_V1)?)
}

/// Der Stand als deterministisches CBOR, in einem Geheimnistraeger.
///
/// Ein [`SecretVec`], obwohl kein Schluessel darin liegt: `aead_seal` nimmt ihn
/// BESITZEND entgegen und zeroisiert ihn beim Fallenlassen.
fn encode_trust_state(state: ReaderTrustStateV1) -> SecretVec {
    let mut bytes = Vec::with_capacity(24);
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .array(2)
        .and_then(|encoder| encoder.i64(state.last_trust_refresh_at.get()))
        .and_then(|encoder| encoder.u64(state.registry_version.get()))
        .expect("encoding a fixed-shape trust state into Vec cannot fail");
    SecretVec::new(bytes)
}

/// Die Rueckprobe gegen die eigenen Bytes.
fn decode_trust_state(bytes: &[u8]) -> Result<ReaderTrustStateV1, ReaderVaultError> {
    let mut decoder = Decoder::new(bytes);
    let length = decoder.array().map_err(|_| ReaderVaultError::Contents)?;
    if length != Some(2) {
        return Err(ReaderVaultError::Contents);
    }
    let last_trust_refresh_at = decoder.i64().map_err(|_| ReaderVaultError::Contents)?;
    let registry_version = decoder.u64().map_err(|_| ReaderVaultError::Contents)?;
    if decoder.position() != bytes.len() {
        return Err(ReaderVaultError::Contents);
    }
    Ok(ReaderTrustStateV1 {
        last_trust_refresh_at: UnixMillis::new(last_trust_refresh_at),
        registry_version: RegistryVersion::new(registry_version),
    })
}
