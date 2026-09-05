//! Der Browser-Tresor: was er haelt, wie er sich schliesst und warum er sich
//! beim Oeffnen nichts glaubt.
//!
//! `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §11.3
//! streicht den nativen Reader-Key-Provider ERSATZLOS. An seine Stelle tritt
//! dieser Tresor: der private X25519-KEM-Schluessel, der Ed25519-Geraete- und
//! Auditschluessel, der gepinnte Root-Anker und der zuletzt verifizierte
//! Registry-Stand liegen ausschliesslich hier, ChaCha20-Poly1305-versiegelt
//! unter EINEM zufaelligen Tresorschluessel, und der Tresorschluessel liegt je
//! Authenticator einmal umschlossen (`crates/ea-reader/src/envelope.rs`).
//!
//! # Diese Aufgabe steht VOR jeder Verifikation
//!
//! Das ist eine Reihenfolge und keine Bequemlichkeit: der Tresor besitzt die
//! EINGABEN von Gate `trust` und von Gate `recipient-grant`.
//! `ea_verify::verify_archive_observed` nimmt einen `&TrustAnchorV1`, und
//! `ea_verify::VerifyOptions::with_recipient` nimmt einen `KeyThumbprint` UND
//! einen `&HpkeRecipientPrivateKey` — alle drei Werte entstehen ausschliesslich
//! hier, in [`UnlockedVault`].
//!
//! # Der Anker gilt, weil er sich selbst traegt
//!
//! [`ReaderVault::unlock`] schickt die entsiegelten Ankerbytes durch
//! `ea_trust::decode_trust_anchor`, und diese Funktion rechnet
//! `bootstrap_anchor_hash` ueber die Vorstufenbytes NEU. Ein im Tresor
//! untergeschobener Anker faellt deshalb mit `EA-TRUST-ANCHOR-HASH`, und zwar
//! bevor irgendein Schluessel benutzt wird. Waere der Anker geglaubt, weil er im
//! Tresor lag, waere der Tresor selbst die Vertrauenswurzel — und ein
//! kompromittierter Tresorkoerper haette eine ganze Vertrauenskette
//! untergeschoben. `a_flipped_envelope_byte_and_a_substituted_anchor_both_refuse`
//! misst genau diese zwei Weigerungen, und beide reichen einen FREMDEN Code
//! durch statt einen eigenen zu erfinden.
//!
//! # Die Zwei-Authenticator-Pflicht wird hier NICHT gewacht
//!
//! §6.3 verlangt mindestens zwei unabhaengige Authenticators, bevor je ein
//! Tresor geschrieben wird. Diese Zaehlung gehoert an die Enrollmentgrenze und
//! steht dort als harte Ablehnung. [`ReaderVault::seal`] weist ausschliesslich
//! die LEERE Liste ab, weil ein Tresor ohne Envelope unoeffenbar waere. Zwei
//! Waechter fuer dieselbe Zusage waeren zwei Wahrheiten, und die zweite
//! verschiebt sich beim naechsten Umbau still.

use core::fmt;

use ea_cbor::{ParserLimits, validate};
use ea_crypto::{
    AEAD_NONCE_SIZE, CEK_SIZE, CanonicalPublicCoseKey, CoseSigner, CryptoError,
    HpkeRecipientPrivateKey, SecretBytes, SecretVec, aead_open, aead_seal,
};
use ea_trust::{RegistryHeadPin, TrustAnchorV1, TrustError, decode_trust_anchor};
use ea_types::{Hash32, KeyThumbprint, ObjectHash, RegistryVersion};
use ed25519_dalek::{Signer, SigningKey};
use minicbor::{Decoder, Encoder};
use zeroize::Zeroize;

use crate::blob_store::ReaderBlobError;
use crate::envelope::{
    AuthenticatorPrfV1, VAULT_BLOB_AAD_V1, VaultEnvelopeV1, derive_audit_log_key_v1,
    derive_cache_key_v1, derive_confirmation_binding_v1, derive_entry_state_key_v1,
    derive_index_key_v1, derive_kek_v1, derive_sync_cursor_key_v1, derive_trust_state_key_v1,
};

/// Der Fehlschlag des Tresors und der Speicher ueber ihm.
///
/// Die Bauform ist die des ganzen Bauwerks: ein flaches Enum, ein stabiler
/// `code()`, ein `Display`, das AUSSCHLIESSLICH diesen Code schreibt, und ein
/// `Debug`, das an `Display` delegiert — damit ein Testfehlschlag den CODE zeigt
/// und keine Formatierung. Vorbilder sind `ea_crypto::CryptoError` und
/// `ea_trust::TrustError`.
///
/// # Fremde Codes werden DURCHGEREICHT
///
/// [`ReaderVaultError::Crypto`] und [`ReaderVaultError::Trust`] geben
/// `EA-CRYPTO-AEAD-OPEN` beziehungsweise `EA-TRUST-ANCHOR-HASH` unveraendert
/// weiter. Ein zweiter, eigener Code daneben verschoebe die Aussage beim
/// naechsten Umbau still: der Leser eines Fehlerprotokolls koennte nicht mehr
/// sehen, ob die AEAD-Pruefung gefallen ist oder ob der Tresor sie nur so
/// genannt hat.
///
/// # Kein `Copy`
///
/// [`ReaderBlobError`] traegt eine `Host(String)`-Variante, und damit nimmt
/// auch `code()` hier `&self`. Das ist der Preis dafuer, dass ein Fehlschlag
/// des Wirtspeichers nicht unterwegs zu etwas anderem wird.
#[derive(Clone, Eq, PartialEq)]
pub enum ReaderVaultError {
    /// [`ReaderVault::seal`] ohne einen einzigen Authenticator.
    NoAuthenticator,
    /// Kein Envelope traegt die `credentialId` des vorgelegten Authenticators.
    NoEnvelope,
    /// HKDF hat die verlangte Ausgabelaenge abgewiesen.
    KekDerivation,
    /// Der entsiegelte Koerper hat nicht die Form, die er haben muss.
    Contents,
    /// Der Bytespeicher hat abgewiesen.
    Blob(ReaderBlobError),
    /// `ea-crypto` hat abgewiesen — insbesondere `EA-CRYPTO-AEAD-OPEN`.
    Crypto(CryptoError),
    /// `ea-trust` hat abgewiesen — insbesondere `EA-TRUST-ANCHOR-HASH`.
    Trust(TrustError),
}

impl ReaderVaultError {
    /// Der stabile Code des Fehlschlags.
    ///
    /// Zusicherungen stehen gegen ihn und nie gegen eine Formatierung —
    /// dieselbe Regel wie bei [`ReaderBlobError::code`].
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NoAuthenticator => "EA-READER-VAULT-NO-AUTHENTICATOR",
            Self::NoEnvelope => "EA-READER-VAULT-NO-ENVELOPE",
            Self::KekDerivation => "EA-READER-VAULT-KEK-DERIVATION",
            Self::Contents => "EA-READER-VAULT-CONTENTS",
            Self::Blob(error) => error.code(),
            Self::Crypto(error) => error.code(),
            Self::Trust(error) => error.code(),
        }
    }
}

impl From<CryptoError> for ReaderVaultError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<TrustError> for ReaderVaultError {
    fn from(error: TrustError) -> Self {
        Self::Trust(error)
    }
}

impl From<ReaderBlobError> for ReaderVaultError {
    fn from(error: ReaderBlobError) -> Self {
        Self::Blob(error)
    }
}

impl fmt::Display for ReaderVaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for ReaderVaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for ReaderVaultError {}

/// Der Inhalt des Tresors nach `web-reader-design.md` §6.1.
///
/// Vier Werte und kein fuenfter: die beiden privaten Schluessel, die EXAKTEN
/// Bytes des gepinnten Ankers und der zuletzt verifizierte Registry-Stand. Ein
/// fachlicher Wert gehoert hier NICHT hin — der Tresor ist der Speicher der
/// Zugangsmittel und nicht der Speicher des Archivs.
///
/// Der Typ traegt kein `Clone`: [`SecretBytes`] hat keins, und
/// `HpkeRecipientPrivateKey::from_bytes` KONSUMIERT sein Geheimnis. Wer zwei
/// Tresore braucht, baut zweimal.
pub struct VaultContentsV1 {
    kem_private_key: SecretBytes<32>,
    audit_private_key: SecretBytes<32>,
    pinned_anchor_exact_bytes: Vec<u8>,
    last_registry_pin: Option<RegistryHeadPin>,
}

impl VaultContentsV1 {
    /// Der Tresorinhalt aus seinen vier Bestandteilen.
    #[must_use]
    pub const fn new(
        kem_private_key: SecretBytes<32>,
        audit_private_key: SecretBytes<32>,
        pinned_anchor_exact_bytes: Vec<u8>,
        last_registry_pin: Option<RegistryHeadPin>,
    ) -> Self {
        Self {
            kem_private_key,
            audit_private_key,
            pinned_anchor_exact_bytes,
            last_registry_pin,
        }
    }

    /// Der Koerper als deterministisches CBOR, in einem Geheimnistraeger.
    ///
    /// Der Rueckgabewert ist ein [`SecretVec`] und kein `Vec<u8>`, weil er zwei
    /// private Schluessel im Klartext traegt; `aead_seal` nimmt ihn BESITZEND
    /// entgegen und zeroisiert ihn beim Fallenlassen.
    fn to_deterministic_cbor(&self) -> SecretVec {
        let mut bytes = Vec::with_capacity(160 + self.pinned_anchor_exact_bytes.len());
        let mut encoder = Encoder::new(&mut bytes);
        self.kem_private_key
            .with_exposed(|kem| {
                self.audit_private_key.with_exposed(|audit| {
                    encoder
                        .array(4)
                        .and_then(|encoder| encoder.bytes(kem))
                        .and_then(|encoder| encoder.bytes(audit))
                        .and_then(|encoder| encoder.bytes(&self.pinned_anchor_exact_bytes))
                        .map(|_| ())
                })
            })
            .expect("encoding a fixed-shape vault body into Vec cannot fail");
        match self.last_registry_pin.as_ref() {
            None => {
                encoder
                    .null()
                    .expect("encoding a CBOR null into Vec cannot fail");
            }
            Some(pin) => {
                encoder
                    .array(2)
                    .and_then(|encoder| encoder.u64(pin.registry_version().get()))
                    .and_then(|encoder| encoder.bytes(pin.registry_head_hash().as_bytes()))
                    .expect("encoding a fixed-shape registry pin into Vec cannot fail");
            }
        }
        debug_assert!(validate(&bytes, ParserLimits::V1).is_ok());
        SecretVec::new(bytes)
    }

    /// Der Koerper aus deterministischem CBOR.
    ///
    /// Dieselbe Reihenfolge wie ueberall im Bestand: erst
    /// `ea_cbor::validate` gegen die Formgrenzen, dann feldweise dekodieren,
    /// dann die Trailing-Byte-Sperre, dann die Rueckprobe gegen die eigenen
    /// Bytes. Die Rueckprobe ist die eigentliche Zusage — sie schliesst jede
    /// nicht-kanonische Schreibweise aus, die derselbe Parser sonst
    /// durchgehen liesse.
    fn from_deterministic_cbor(bytes: &[u8]) -> Result<Self, ReaderVaultError> {
        validate(bytes, ParserLimits::V1).map_err(|_| ReaderVaultError::Contents)?;
        let mut decoder = Decoder::new(bytes);
        if decoder.array().map_err(|_| ReaderVaultError::Contents)? != Some(4) {
            return Err(ReaderVaultError::Contents);
        }
        let kem = read_secret_32(&mut decoder)?;
        let audit = read_secret_32(&mut decoder)?;
        let anchor = decoder
            .bytes()
            .map_err(|_| ReaderVaultError::Contents)?
            .to_vec();
        let pin = read_registry_pin(&mut decoder)?;
        if decoder.position() != bytes.len() {
            return Err(ReaderVaultError::Contents);
        }
        let contents = Self::new(kem, audit, anchor, pin);
        if !contents.to_deterministic_cbor().matches(bytes) {
            return Err(ReaderVaultError::Contents);
        }
        Ok(contents)
    }
}

/// 32 Byte aus dem Dekodierer, unmittelbar in einen Geheimnistraeger.
fn read_secret_32(decoder: &mut Decoder<'_>) -> Result<SecretBytes<32>, ReaderVaultError> {
    let raw = decoder.bytes().map_err(|_| ReaderVaultError::Contents)?;
    let mut buffer: [u8; 32] = raw.try_into().map_err(|_| ReaderVaultError::Contents)?;
    let secret = SecretBytes::new(buffer);
    buffer.zeroize();
    Ok(secret)
}

/// Der Registry-Stand: `null` oder das Paar aus Version und Kopfhash.
///
/// `ea_trust::RegistryHeadPin` traegt im Bestand KEINE Serialisierung — kein
/// serde, kein minicbor, kein Codec. Der Tresor kodiert ihn deshalb selbst und
/// baut ihn ueber `RegistryHeadPin::new` wieder auf.
fn read_registry_pin(
    decoder: &mut Decoder<'_>,
) -> Result<Option<RegistryHeadPin>, ReaderVaultError> {
    if decoder.datatype().map_err(|_| ReaderVaultError::Contents)? == minicbor::data::Type::Null {
        decoder.null().map_err(|_| ReaderVaultError::Contents)?;
        return Ok(None);
    }
    if decoder.array().map_err(|_| ReaderVaultError::Contents)? != Some(2) {
        return Err(ReaderVaultError::Contents);
    }
    let version = decoder.u64().map_err(|_| ReaderVaultError::Contents)?;
    let head = ObjectHash::try_from(decoder.bytes().map_err(|_| ReaderVaultError::Contents)?)
        .map_err(|_| ReaderVaultError::Contents)?;
    Ok(Some(RegistryHeadPin::new(
        RegistryVersion::new(version),
        head,
    )))
}

/// Der versiegelte Tresor: EIN Koerper, viele Entsperrwege.
///
/// Der Typ traegt ausschliesslich Chiffrat und `credentialId`s und ist deshalb
/// `Clone` — der Zeuge braucht zwei unabhaengige Verfaelschungen desselben
/// Ausgangswerts. `UnlockedVault` daneben ist es ausdruecklich NICHT.
#[derive(Clone)]
pub struct SealedVaultV1 {
    nonce: [u8; AEAD_NONCE_SIZE],
    ciphertext: Vec<u8>,
    envelopes: Vec<VaultEnvelopeV1>,
}

impl SealedVaultV1 {
    /// Die Entsperrwege dieses Tresors, in der Reihenfolge des Versiegelns.
    #[must_use]
    pub fn envelopes(&self) -> &[VaultEnvelopeV1] {
        &self.envelopes
    }

    /// Derselbe Tresor OHNE den Entsperrweg dieses Authenticators.
    ///
    /// PRODUKTIVE Flaeche und kein Testhelfer: das Loeschen eines Passkeys ist
    /// der Regelfall, den §6.2 mit der Envelope-Konstruktion ueberhaupt erst
    /// ueberlebbar macht. Der Koerper bleibt unberuehrt — es faellt ein Weg
    /// weg, nie der Inhalt.
    ///
    /// # Errors
    /// `EA-READER-VAULT-NO-ENVELOPE`, wenn kein Envelope diese `credentialId`
    /// traegt; `EA-READER-VAULT-NO-AUTHENTICATOR`, wenn das Entfernen den
    /// letzten Entsperrweg naehme — ein Tresor ohne Envelope waere
    /// unoeffenbar, und ein stillschweigend erzeugter Datenverlust ist keine
    /// zulaessige Antwort auf einen Loeschwunsch.
    pub fn without_credential(&self, credential_id: Vec<u8>) -> Result<Self, ReaderVaultError> {
        if !self
            .envelopes
            .iter()
            .any(|envelope| envelope.credential_id() == credential_id)
        {
            return Err(ReaderVaultError::NoEnvelope);
        }
        let envelopes: Vec<VaultEnvelopeV1> = self
            .envelopes
            .iter()
            .filter(|envelope| envelope.credential_id() != credential_id)
            .cloned()
            .collect();
        if envelopes.is_empty() {
            return Err(ReaderVaultError::NoAuthenticator);
        }
        Ok(Self {
            nonce: self.nonce,
            ciphertext: self.ciphertext.clone(),
            envelopes,
        })
    }

    /// Der versiegelte Tresor als deterministisches CBOR.
    ///
    /// Der Tresor verlaesst das WASM-Modul ausschliesslich in dieser Gestalt:
    /// `crates/ea-reader-wasm/src/vault_bridge.rs` gibt genau diese Bytes an
    /// JavaScript und bekommt sie beim Entsperren zurueck. Nichts daran ist
    /// Klartext ausser den `credentialId`s und den Nonces, und beide muessen
    /// es sein.
    #[must_use]
    pub fn to_deterministic_cbor(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64 + self.ciphertext.len() + self.envelopes.len() * 96);
        let mut encoder = Encoder::new(&mut bytes);
        encoder
            .array(3)
            .and_then(|encoder| encoder.bytes(&self.nonce))
            .and_then(|encoder| encoder.bytes(&self.ciphertext))
            .and_then(|encoder| encoder.array(self.envelopes.len() as u64))
            .expect("encoding a fixed-shape sealed vault into Vec cannot fail");
        for envelope in &self.envelopes {
            encoder
                .array(3)
                .and_then(|encoder| encoder.bytes(envelope.credential_id()))
                .and_then(|encoder| encoder.bytes(envelope.nonce()))
                .and_then(|encoder| encoder.bytes(envelope.wrapped_vault_key()))
                .expect("encoding a fixed-shape envelope into Vec cannot fail");
        }
        debug_assert!(validate(&bytes, ParserLimits::V1).is_ok());
        bytes
    }

    /// Der versiegelte Tresor aus deterministischem CBOR.
    ///
    /// # Errors
    /// `EA-READER-VAULT-CONTENTS` fuer jede Abweichung von der Form, die
    /// [`SealedVaultV1::to_deterministic_cbor`] schreibt — einschliesslich
    /// jeder nicht-kanonischen Schreibweise, die die abschliessende Rueckprobe
    /// faengt; `EA-READER-VAULT-NO-AUTHENTICATOR` fuer einen Tresor ohne
    /// Envelope.
    pub fn from_deterministic_cbor(bytes: &[u8]) -> Result<Self, ReaderVaultError> {
        validate(bytes, ParserLimits::V1).map_err(|_| ReaderVaultError::Contents)?;
        let mut decoder = Decoder::new(bytes);
        if decoder.array().map_err(|_| ReaderVaultError::Contents)? != Some(3) {
            return Err(ReaderVaultError::Contents);
        }
        let nonce: [u8; AEAD_NONCE_SIZE] = decoder
            .bytes()
            .map_err(|_| ReaderVaultError::Contents)?
            .try_into()
            .map_err(|_| ReaderVaultError::Contents)?;
        let ciphertext = decoder
            .bytes()
            .map_err(|_| ReaderVaultError::Contents)?
            .to_vec();
        let count = decoder
            .array()
            .map_err(|_| ReaderVaultError::Contents)?
            .ok_or(ReaderVaultError::Contents)?;
        let mut envelopes = Vec::new();
        for _ in 0..count {
            if decoder.array().map_err(|_| ReaderVaultError::Contents)? != Some(3) {
                return Err(ReaderVaultError::Contents);
            }
            let credential_id = decoder
                .bytes()
                .map_err(|_| ReaderVaultError::Contents)?
                .to_vec();
            let envelope_nonce: [u8; AEAD_NONCE_SIZE] = decoder
                .bytes()
                .map_err(|_| ReaderVaultError::Contents)?
                .try_into()
                .map_err(|_| ReaderVaultError::Contents)?;
            let wrapped = decoder.bytes().map_err(|_| ReaderVaultError::Contents)?;
            envelopes.push(VaultEnvelopeV1::from_parts(
                credential_id,
                envelope_nonce,
                wrapped,
            )?);
        }
        if decoder.position() != bytes.len() {
            return Err(ReaderVaultError::Contents);
        }
        if envelopes.is_empty() {
            return Err(ReaderVaultError::NoAuthenticator);
        }
        let sealed = Self {
            nonce,
            ciphertext,
            envelopes,
        };
        if sealed.to_deterministic_cbor() != bytes {
            return Err(ReaderVaultError::Contents);
        }
        Ok(sealed)
    }

    /// Kippt ein Byte im umschlossenen Tresorschluessel dieses Entsperrwegs.
    ///
    /// Hinter `test-support` und von der Wurzelkante abgeschaltet. Ohne sie
    /// koennte `a_flipped_envelope_byte_and_a_substituted_anchor_both_refuse`
    /// die AEAD-Weigerung nur behaupten.
    ///
    /// # Panics
    /// Wenn kein Envelope diese `credentialId` traegt. Ein Zeuge, der ins Leere
    /// verfaelscht, waere gruen ohne Aussage.
    #[cfg(any(test, feature = "test-support"))]
    pub fn flip_one_wrapped_key_byte_for_test(&mut self, credential_id: Vec<u8>) {
        let envelope = self
            .envelopes
            .iter_mut()
            .find(|envelope| envelope.credential_id() == credential_id)
            .expect("die verfaelschte credentialId MUSS einen Entsperrweg treffen");
        envelope.flip_one_wrapped_key_byte_for_test();
    }

    /// Ersetzt die gepinnten Ankerbytes im Tresorkoerper und versiegelt NEU.
    ///
    /// Hinter `test-support` und von der Wurzelkante abgeschaltet.
    ///
    /// # Warum diese Hilfe einen Authenticator braucht
    ///
    /// Ein roher Byte-Patch am Chiffrat faellt zuerst mit
    /// `EA-CRYPTO-AEAD-OPEN` und erreicht `decode_trust_anchor` nie; der Zeuge
    /// pruefte dann zweimal dasselbe. Die Ersetzung MUSS also entsiegeln,
    /// tauschen und neu versiegeln — und dafuer braucht sie den
    /// Tresorschluessel, den ausschliesslich ein Authenticator herausgibt.
    /// [`SealedVaultV1`] haelt selbst kein Schluesselmaterial, und genau das
    /// soll so bleiben.
    ///
    /// # Panics
    /// Wenn der vorgelegte Authenticator diesen Tresor nicht oeffnet.
    #[cfg(any(test, feature = "test-support"))]
    pub fn replace_sealed_anchor_bytes_for_test(
        &mut self,
        authenticator: &AuthenticatorPrfV1,
        pinned_anchor_exact_bytes: Vec<u8>,
    ) {
        let vault_key = self
            .unwrap_vault_key(authenticator)
            .expect("der vorgelegte Authenticator MUSS diesen Tresor oeffnen");
        let opened = aead_open(
            &vault_key,
            &SecretBytes::new(self.nonce),
            &self.ciphertext,
            VAULT_BLOB_AAD_V1,
        )
        .expect("ein unveraenderter Tresorkoerper oeffnet unter seinem eigenen Schluessel");
        let contents = opened
            .with_exposed(VaultContentsV1::from_deterministic_cbor)
            .expect("ein unveraenderter Tresorkoerper traegt seine eigene Form");
        let replaced = VaultContentsV1::new(
            contents.kem_private_key,
            contents.audit_private_key,
            pinned_anchor_exact_bytes,
            contents.last_registry_pin,
        );
        let nonce = random_bytes::<AEAD_NONCE_SIZE>()
            .expect("die Zufallsquelle des Wirts steht im Zeugenlauf zur Verfuegung");
        self.ciphertext = aead_seal(
            &vault_key,
            &SecretBytes::new(nonce),
            replaced.to_deterministic_cbor(),
            VAULT_BLOB_AAD_V1,
        )
        .expect("ein Tresorkoerper dieser Groesse ist versiegelbar");
        self.nonce = nonce;
    }

    /// Belegt, dass ein Authenticator DIESEN Tresor oeffnen kann — ohne ihn zu
    /// oeffnen — und gibt die Tresorbindung der Bestaetigung heraus.
    ///
    /// Der Weg der Authenticator-Bestaetigung aus `web-reader-design.md` §6.5
    /// und §8.2: eine frische PRF-Ausgabe ist nur nach einer Zeremonie mit
    /// Nutzerverifikation zu haben, und ob sie ECHT ist, entscheidet nicht der
    /// Aufrufer, sondern die AEAD-Umschliessung des Envelopes. Der
    /// umschlossene Tresorschluessel wird dafuer ausgepackt, zur Bindung
    /// abgeleitet und sofort fallengelassen — unter `ZeroizeOnDrop`, ohne den
    /// Tresorkoerper zu entsiegeln und ohne dass ein zweiter [`UnlockedVault`]
    /// entsteht. Die Bindung ist `HKDF-SHA-256(vault_key, ea-reader-confirmation-v1)`;
    /// [`UnlockedVault::confirmation_binding`] rechnet denselben Wert, und nur
    /// bei Gleichheit eroeffnet oder exportiert die Bestaetigung.
    ///
    /// # Errors
    /// `EA-READER-VAULT-NO-ENVELOPE`, wenn kein Envelope diese `credentialId`
    /// traegt, `EA-CRYPTO-AEAD-OPEN`, wenn die PRF-Ausgabe nicht zu ihm
    /// passt, `EA-READER-VAULT-KEK-DERIVATION`, wenn HKDF abweist.
    pub(crate) fn prove_authenticator(
        &self,
        authenticator: &AuthenticatorPrfV1,
    ) -> Result<Hash32, ReaderVaultError> {
        let vault_key = self.unwrap_vault_key(authenticator)?;
        confirmation_binding_of(&vault_key)
    }

    /// Der Tresorschluessel, geholt ueber genau EINEN Entsperrweg.
    fn unwrap_vault_key(
        &self,
        authenticator: &AuthenticatorPrfV1,
    ) -> Result<SecretBytes<CEK_SIZE>, ReaderVaultError> {
        let envelope = self
            .envelopes
            .iter()
            .find(|envelope| envelope.credential_id() == authenticator.credential_id())
            .ok_or(ReaderVaultError::NoEnvelope)?;
        let kek = derive_kek_v1(authenticator)?;
        envelope.unwrap(&kek)
    }
}

impl fmt::Debug for SealedVaultV1 {
    /// Zeigt AUSSCHLIESSLICH Groessen.
    ///
    /// Ein abgeleitetes `Debug` schriebe das ganze Chiffrat in jede
    /// Fehlermeldung. Das ist kein Klartextleck, aber es ist ein Leck an
    /// Umfang und Struktur — und ein Testfehlschlag soll lesbar bleiben.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "SealedVaultV1 {{ ciphertext_len: {}, envelopes: {} }}",
            self.ciphertext.len(),
            self.envelopes.len()
        )
    }
}

/// Der entsperrte Tresor: die Zugangsmittel EINER Sitzung.
///
/// Kein `Clone` — er haelt [`SecretBytes`] und einen
/// `HpkeRecipientPrivateKey`, und beide sind bewusst nicht klonbar. Kein
/// abgeleitetes `Debug` aus demselben Grund. Der Rohschluessel liegt waehrend
/// einer entsperrten Sitzung im WASM-Speicher; das ist die in §6.5 benannte,
/// bewusst getragene Folge der HPKE-Entkapselung im Modul, und die
/// Gegenmassnahmen dazu — Sperrfristen und `zeroize`-Zeitpunkte — baut die
/// Aufgabe „Sitzungssperre, Zeroize, authenticator-bestätigter Einzelexport und
/// signiertes lokales Audit".
pub struct UnlockedVault {
    vault_key: SecretBytes<CEK_SIZE>,
    kem_private_key: HpkeRecipientPrivateKey,
    kem_key_thumbprint: KeyThumbprint,
    audit_signing_key: SecretBytes<32>,
    pinned_anchor: TrustAnchorV1,
    last_registry_pin: Option<RegistryHeadPin>,
}

impl UnlockedVault {
    /// Der private X25519-Empfaengerschluessel.
    ///
    /// Die EINGABE der HPKE-Entkapselung und damit von
    /// `ea_verify::VerifyOptions::with_recipient`. Er verlaesst die geteilte
    /// Rust-Schicht nie: die Bruecke gibt Sitzungskennung, Abdruecke und
    /// Statuswerte heraus, nie Schluesselmaterial (`web-reader-design.md` §9).
    #[must_use]
    pub const fn kem_private_key(&self) -> &HpkeRecipientPrivateKey {
        &self.kem_private_key
    }

    /// Der Abdruck des KEM-Schluessels.
    ///
    /// Er wird beim Entsperren EINMAL gerechnet und als Feld gehalten, und nur
    /// deshalb ist dieser Getter `const`: `CanonicalPublicCoseKey::thumbprint`
    /// rechnet SHA-256 und ist selbst nicht `const`. Der Wert ist Pflichteingabe
    /// und keine Kuer — `with_recipient` nimmt ZWEI Werte, den Abdruck UND den
    /// Schluessel.
    #[must_use]
    pub const fn kem_key_thumbprint(&self) -> KeyThumbprint {
        self.kem_key_thumbprint
    }

    /// Der Ed25519-Geraete- und Auditschluessel.
    ///
    /// Als [`SecretBytes`] und nicht als Rohbytes: der Wert bleibt in geteiltem
    /// Rust, steht unter `ZeroizeOnDrop` und ist nur ueber `with_exposed`
    /// lesbar. Wer bloss signieren will, nimmt [`UnlockedVault::sign_audit_digest`]
    /// und braucht ihn gar nicht.
    #[must_use]
    pub const fn audit_signing_key(&self) -> &SecretBytes<32> {
        &self.audit_signing_key
    }

    /// Eine ROHE Ed25519-Signatur ueber einen 32-Byte-Digest.
    ///
    /// `ea-crypto` hat dafuer nichts: `CoseSigner` signiert ausschliesslich
    /// COSE_Sign1 und gibt `Vec<u8>` zurueck. Das lokale Audit der Aufgabe
    /// „Sitzungssperre, Zeroize, authenticator-bestätigter Einzelexport und
    /// signiertes lokales Audit" braucht die rohen 64 Byte, also entsteht die
    /// Signatur hier — an EINER Stelle, mit dem Schluessel, der den Tresor nie
    /// verlaesst.
    #[must_use]
    pub fn sign_audit_digest(&self, digest: &[u8; 32]) -> [u8; 64] {
        self.audit_signing_key
            .with_exposed(|seed| SigningKey::from_bytes(seed).sign(digest).to_bytes())
    }

    /// Die Tresorbindung, gegen die eine Authenticator-Bestaetigung geprueft
    /// wird — derselbe Wert, den `SealedVaultV1::prove_authenticator` aus dem
    /// ausgepackten Tresorschluessel ableitet.
    ///
    /// # Panics
    /// Nie erreichbar: HKDF-SHA-256 weist eine Ausgabelaenge erst oberhalb von
    /// 255 · 32 Byte ab, und hier sind es 32.
    #[must_use]
    pub fn confirmation_binding(&self) -> Hash32 {
        confirmation_binding_of(&self.vault_key)
            .expect("HKDF-SHA-256 liefert 32 Byte ohne Laengenbeschraenkung")
    }

    /// Der COSE-Signierer des lokalen Audits, aus DEMSELBEN Ed25519-Schluessel.
    ///
    /// `ea_crypto::CoseSigner::from_secret` nimmt den Seed BESITZEND; die Kopie
    /// entsteht innerhalb von `with_exposed` und faellt mit dem Signierer unter
    /// dessen Zeroize — dieselbe Bauform, mit der `ReaderEnrollment::finish`
    /// seinen `RequestSigner` baut. Der Signierer wird je Auditzeile NEU
    /// gebaut und nirgends zwischengehalten: die Sperre der Sitzung laesst den
    /// Tresor fallen, und mit ihm jeden Weg zu diesem Schluessel.
    #[must_use]
    pub fn audit_signer(&self) -> CoseSigner {
        self.audit_signing_key
            .with_exposed(|seed| CoseSigner::from_secret(SecretBytes::new(*seed)))
    }

    /// Der gepinnte Root-Anker.
    ///
    /// Im Datei-Modus die EINZIGE Vertrauensquelle (§5.3): Trust-Objekte, die
    /// in der geoeffneten Datei mitliegen, begruenden fuer sich kein Vertrauen.
    #[must_use]
    pub const fn pinned_anchor(&self) -> &TrustAnchorV1 {
        &self.pinned_anchor
    }

    /// Die EXAKTEN Bytes des gepinnten Ankers.
    ///
    /// Sie kommen aus dem dekodierten Anker selbst und nicht aus einer zweiten
    /// Kopie daneben — zwei Felder koennten auseinanderlaufen, und dann waere
    /// unklar, welches der Vertrag ist.
    #[must_use]
    pub fn pinned_anchor_bytes(&self) -> &[u8] {
        self.pinned_anchor.exact_bytes()
    }

    /// Der zuletzt verifizierte Registry-Stand, falls einer gepinnt ist.
    #[must_use]
    pub const fn last_registry_pin(&self) -> Option<&RegistryHeadPin> {
        self.last_registry_pin.as_ref()
    }

    /// Der Indexschluessel `HKDF-SHA-256(vault_key, info = VAULT_INDEX_INFO_V1)`.
    ///
    /// Der EINZIGE Weg des Indexschluessels aus dem Tresor heraus, und er gibt
    /// AUSSCHLIESSLICH den abgeleiteten Schluessel heraus, nie den
    /// Tresorschluessel: `crates/ea-index` ist eine fremde Crate, `derive_key`
    /// ist modulprivat, und ohne diesen Zugang haette der Index gar keine
    /// deklarierte Quelle. Der Rueckgabewert liegt in `SecretBytes<CEK_SIZE>`
    /// und damit unter `ZeroizeOnDrop`; er wird bei jedem Aufruf NEU abgeleitet
    /// und nirgends zwischengehalten.
    ///
    /// # Panics
    /// Nie erreichbar: HKDF-SHA-256 weist eine Ausgabelaenge erst oberhalb von
    /// 255 · 32 Byte ab, und hier sind es 32.
    #[must_use]
    pub fn index_key(&self) -> SecretBytes<CEK_SIZE> {
        derive_index_key_v1(&self.vault_key)
            .expect("HKDF-SHA-256 liefert 32 Byte ohne Laengenbeschraenkung")
    }

    /// Der Cacheschluessel dieser Sitzung.
    pub(crate) fn cache_key(&self) -> Result<SecretBytes<CEK_SIZE>, ReaderVaultError> {
        derive_cache_key_v1(&self.vault_key)
    }

    /// Der Schluessel des Zustandsspeichers dieser Sitzung.
    pub(crate) fn trust_state_key(&self) -> Result<SecretBytes<CEK_SIZE>, ReaderVaultError> {
        derive_trust_state_key_v1(&self.vault_key)
    }

    /// Der Schluessel des Eintragszustandsspeichers.
    pub(crate) fn entry_state_key(&self) -> Result<SecretBytes<CEK_SIZE>, ReaderVaultError> {
        derive_entry_state_key_v1(&self.vault_key)
    }

    /// Der Schluessel des signierten lokalen Auditprotokolls.
    pub(crate) fn audit_log_key(&self) -> Result<SecretBytes<CEK_SIZE>, ReaderVaultError> {
        derive_audit_log_key_v1(&self.vault_key)
    }

    /// Der Schluessel des bestaetigten Sync-Cursors.
    ///
    /// Der Cursor liegt im selben Bytespeicher wie Cache und Zustaende und
    /// unterliegt derselben Regel: was OPFS erreicht, ist Chiffrat. Er traegt
    /// Kettenkennung, Sequenz, Eintragshash und den undurchsichtigen
    /// Blaetterschein — im Klartext waere das die Fallgeschichte dieses
    /// Readers, lesbar fuer alles, was dieselbe Herkunft belegt.
    pub(crate) fn sync_cursor_key(&self) -> Result<SecretBytes<CEK_SIZE>, ReaderVaultError> {
        derive_sync_cursor_key_v1(&self.vault_key)
    }
}

/// Die Tresorbindung aus einem Tresorschluessel, als `Hash32`: der
/// abgeleitete Wert ist KEIN Geheimnis mehr — er kann den Schluessel nicht
/// verraten —, und die Bestaetigung traegt ihn als gewoehnlichen Vergleichswert.
fn confirmation_binding_of(vault_key: &SecretBytes<CEK_SIZE>) -> Result<Hash32, ReaderVaultError> {
    let derived = derive_confirmation_binding_v1(vault_key)?;
    Ok(derived.with_exposed(|bytes| Hash32::try_from(bytes.as_slice()).expect("32 Byte")))
}

impl fmt::Debug for UnlockedVault {
    /// Nennt AUSSCHLIESSLICH Abdruecke und Anwesenheiten.
    ///
    /// Kein abgeleitetes `Debug` — es waere unmoeglich (weder [`SecretBytes`]
    /// noch `HpkeRecipientPrivateKey` noch `TrustAnchorV1` tragen eines) und es
    /// waere zugleich ein Leck. Dieselbe Regel schreibt
    /// `impl fmt::Debug for VerifyOptions` in `crates/ea-verify/src/archive.rs`
    /// aus: gibt NIE Schluesselmaterial aus, nur ob eines vorliegt.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UnlockedVault { kem_key_thumbprint: ")?;
        write_hex(formatter, self.kem_key_thumbprint.as_bytes())?;
        formatter.write_str(", trust_anchor_hash: ")?;
        write_hex(formatter, self.pinned_anchor.trust_anchor_hash().as_bytes())?;
        write!(
            formatter,
            ", last_registry_pin: {:?} }}",
            self.last_registry_pin
                .as_ref()
                .map(RegistryHeadPin::registry_version)
        )
    }
}

/// Schreibt Bytes als Kleinbuchstaben-Hex.
///
/// Vorbild `write_hex` in `crates/ea-verify/src/report.rs`: Hashes haben kein
/// `Debug`, weil sie sich nicht beilaeufig in eine Meldung schreiben sollen —
/// wo sie es doch tun, tun sie es an EINER Stelle und in EINER Schreibweise.
fn write_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

/// Der Tresor als Namensraum.
///
/// Ein reiner Namensraum; er hat keinen Zustand und wird nie als Wert gefuehrt
/// — dieselbe Bauform wie `WriterKeyProfile` in
/// `crates/ea-key-provider/src/profile.rs`.
pub struct ReaderVault;

impl ReaderVault {
    /// Versiegelt den Tresorinhalt und umschliesst den Tresorschluessel je
    /// Authenticator einmal.
    ///
    /// Gezogen wird SELBST: ein zufaelliger 32-Byte-Tresorschluessel, ein
    /// 12-Byte-Nonce fuer den Koerper und je Envelope ein weiterer. Die Quelle
    /// ist `getrandom::fill` — im Browser `globalThis.crypto.getRandomValues`,
    /// gemessen im Laufzeitnachweis unter `spikes/wasm-runtime-proof/`.
    /// `ea-crypto` gibt bewusst keine Zufallsquelle heraus.
    ///
    /// # Errors
    /// `EA-READER-VAULT-NO-AUTHENTICATOR` fuer die leere Liste,
    /// `EA-LOCAL-CRYPTO-RNG`, wenn der Wirt keine Entropie liefert, und die
    /// durchgereichten Codes von `ea-crypto`.
    pub fn seal(
        contents: VaultContentsV1,
        authenticators: &[AuthenticatorPrfV1],
    ) -> Result<SealedVaultV1, ReaderVaultError> {
        if authenticators.is_empty() {
            return Err(ReaderVaultError::NoAuthenticator);
        }
        let mut vault_key_bytes = random_bytes::<CEK_SIZE>()?;
        let vault_key = SecretBytes::new(vault_key_bytes);
        vault_key_bytes.zeroize();

        let nonce = random_bytes::<AEAD_NONCE_SIZE>()?;
        let ciphertext = aead_seal(
            &vault_key,
            &SecretBytes::new(nonce),
            contents.to_deterministic_cbor(),
            VAULT_BLOB_AAD_V1,
        )?;

        let mut envelopes = Vec::with_capacity(authenticators.len());
        for authenticator in authenticators {
            let kek = derive_kek_v1(authenticator)?;
            let envelope_nonce = random_bytes::<AEAD_NONCE_SIZE>()?;
            envelopes.push(VaultEnvelopeV1::wrap(
                &kek,
                &vault_key,
                &envelope_nonce,
                authenticator.credential_id().to_vec(),
            )?);
        }

        Ok(SealedVaultV1 {
            nonce,
            ciphertext,
            envelopes,
        })
    }

    /// Oeffnet den Tresor ueber GENAU EINEN Authenticator.
    ///
    /// Die Reihenfolge der Weigerungen ist selbst eine Aussage: erst der
    /// fehlende Entsperrweg (`EA-READER-VAULT-NO-ENVELOPE`), dann die AEAD-
    /// Pruefung des umschlossenen Tresorschluessels (`EA-CRYPTO-AEAD-OPEN`),
    /// dann die des Koerpers, dann die NEU gerechnete Selbsttragung des Ankers
    /// (`EA-TRUST-ANCHOR-HASH`). Ein geloeschter Passkey ist damit von einem
    /// verfaelschten Tresor unterscheidbar, und beides von einem
    /// untergeschobenen Anker.
    ///
    /// # Errors
    /// Die vier genannten Codes sowie `EA-READER-VAULT-CONTENTS` fuer einen
    /// Koerper, der die Form verfehlt.
    pub fn unlock(
        sealed: &SealedVaultV1,
        authenticator: &AuthenticatorPrfV1,
    ) -> Result<UnlockedVault, ReaderVaultError> {
        let vault_key = sealed.unwrap_vault_key(authenticator)?;
        let opened = aead_open(
            &vault_key,
            &SecretBytes::new(sealed.nonce),
            &sealed.ciphertext,
            VAULT_BLOB_AAD_V1,
        )?;
        let contents = opened.with_exposed(VaultContentsV1::from_deterministic_cbor)?;

        let pinned_anchor = decode_trust_anchor(&contents.pinned_anchor_exact_bytes)?;
        let kem_private_key = HpkeRecipientPrivateKey::from_bytes(contents.kem_private_key)?;
        let kem_key_thumbprint =
            CanonicalPublicCoseKey::x25519(*kem_private_key.public_key().as_bytes())?.thumbprint();

        Ok(UnlockedVault {
            vault_key,
            kem_private_key,
            kem_key_thumbprint,
            audit_signing_key: contents.audit_private_key,
            pinned_anchor,
            last_registry_pin: contents.last_registry_pin,
        })
    }
}

/// `N` Byte frischer Entropie vom Wirt.
///
/// Genau der Weg, den `crates/ea-writer/src/entropy.rs` und
/// `crates/ea-audit/src/repository.rs` bereits nehmen; ein zweites RNG entsteht
/// hier nicht.
fn random_bytes<const N: usize>() -> Result<[u8; N], ReaderVaultError> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|_| ReaderVaultError::Crypto(CryptoError::LocalRng))?;
    Ok(bytes)
}
