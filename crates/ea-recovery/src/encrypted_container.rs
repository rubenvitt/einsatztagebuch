//! `EINSATZARCHIV-KEY-CONTAINER-v1`: ein Schluessel unter einer Passphrase.
//!
//! # DIE FORM, BYTE FUER BYTE
//!
//! Ein deterministisches CBOR-Array fester Laenge sieben:
//!
//! ```text
//! [
//!   domain:     tstr  "EINSATZARCHIV-KEY-CONTAINER-v1",
//!   version:    uint  1,
//!   kind:       uint  1 = RecipientKem (X25519), 2 = Signing (Ed25519-Seed),
//!   kdf:        [ 1 = Argon2id, m_kib: uint, t: uint, p: uint ],
//!   salt:       bstr .size 16,
//!   nonce:      bstr .size 12,
//!   ciphertext: bstr .size 48
//! ]
//! ```
//!
//! Die AAD der AEAD sind die deterministischen CBOR-Bytes des KOPFES — des
//! Arrays fester Laenge sechs aus denselben ersten sechs Gliedern. Damit ist
//! jedes Kopfbyte gebunden: wer Domain, Version, Art, KDF-Parameter, Salz oder
//! Nonce aendert, aendert die AAD, und die AEAD oeffnet nicht mehr. Die
//! Schluesselart steht im Kopf, damit ein Recovery-Schluessel nie als
//! Signierschluessel gelesen werden kann — und die Pruefung der Art laeuft VOR
//! dem KDF, damit eine Verwechslung billig ist.
//!
//! # EINE KDF, EINE AEAD, BEIDE GEPINNT
//!
//! Argon2id (RFC 9106) mit `m = 64 MiB`, `t = 3`, `p = 4` — die zweite
//! empfohlene Parametrierung aus RFC 9106 §4 —, Version 0x13, 32 Bytes
//! Ausgabe. Die Werte stehen ZUSAETZLICH im Kopf, und beim Dekodieren werden
//! GENAU diese Werte verlangt: ein Container mit anderen Parametern wird
//! abgewiesen, auch wenn seine AEAD sich oeffnen liesse. Ein Angreifer, der
//! `m` auf 8 KiB setzen koennte, machte die Passphrase sonst zu einem
//! Woerterbuchziel; die Zahlen im Kopf dienen der SELBSTBESCHREIBUNG, nicht
//! der Aushandlung.
//!
//! Zwei Schichten, unabhaengig voneinander: das Dekodieren weist fremde
//! Parameter ab, BEVOR ein KDF laeuft — und taete es das je nicht, bildete
//! die AAD sich aus den Werten, die der Kopf tatsaechlich traegt
//! ([`EncryptedKeyContainer::from_bytes`] bewahrt sie), und die AEAD oeffnete
//! den Container mit veraenderten Parametern nicht. Die erste Schicht ist
//! gemessen (`tests/offline_sources.rs`); die zweite ist die Bauart.
//!
//! Die AEAD ist das ChaCha20-Poly1305 hinter [`ea_crypto::aead_seal`] und
//! [`ea_crypto::aead_open`] — das einzige der Suite 1. Es kommt keine zweite.
//!
//! # GEHEIMNISSE HABEN GENAU EINEN AUFENTHALTSORT
//!
//! Passphrase, abgeleiteter Schluessel und Klartext leben in [`SecretVec`]
//! beziehungsweise [`SecretBytes`] und werden beim Fallenlassen
//! ueberschrieben; die Speicherbloecke des KDF ebenso. Der Container selbst
//! traegt kein `Debug`: Salz und Nonce sind zwar keine Geheimnisse, aber die
//! Global Constraint nennt die Nonce ausdruecklich unter dem, was in kein
//! Protokoll gehoert.

use std::{
    fs::File,
    io::{Read as _, Write as _},
    path::Path,
};

use argon2::{Algorithm, Argon2, Block, Params, Version};
use ea_cbor::ParserLimits;
use ea_crypto::{
    AEAD_NONCE_SIZE, AEAD_OVERHEAD, CEK_SIZE, SecretBytes, SecretVec, aead_open, aead_seal,
};
use minicbor::{Decoder, Encoder};
use zeroize::Zeroize as _;

use crate::{
    RecoveryError,
    key_source::{refuse_unless_owner_only, refuse_unless_regular_file_at},
    report::create_new_file,
    target::restrictive_permissions_available,
};

/// Die Domain des Containers, Glied eins des Kopfes.
pub const KEY_CONTAINER_DOMAIN_V1: &str = "EINSATZARCHIV-KEY-CONTAINER-v1";

/// Die Objektversion, Glied zwei des Kopfes.
pub const KEY_CONTAINER_VERSION_V1: u8 = 1;

/// Argon2id-Speicher in KiB: 64 MiB.
pub const ARGON2ID_MEMORY_KIB_V1: u32 = 65_536;

/// Argon2id-Durchlaeufe.
pub const ARGON2ID_ITERATIONS_V1: u32 = 3;

/// Argon2id-Parallelitaet (Lanes). Ohne `parallel`-Merkmal rechnet die Kiste
/// die Lanes nacheinander; das Ergebnis ist dasselbe.
pub const ARGON2ID_PARALLELISM_V1: u32 = 4;

/// Die Salzgroesse in Bytes.
pub const KEY_CONTAINER_SALT_SIZE_V1: usize = 16;

/// Die Kennung von Argon2id im `kdf`-Glied.
const KDF_ID_ARGON2ID: u8 = 1;

/// Die Groesse des enthaltenen Schluessels: X25519-Schluessel und
/// Ed25519-Seed sind beide 32 Bytes.
const CONTAINED_KEY_SIZE: usize = 32;

/// Die Groesse des Chiffrats: Schluessel plus Poly1305-Tag.
const CIPHERTEXT_SIZE: usize = CONTAINED_KEY_SIZE + AEAD_OVERHEAD;

/// Die Zahl der Glieder des Kopfes.
const HEADER_ITEMS: u64 = 6;

/// Die Zahl der Glieder des ganzen Containers.
const CONTAINER_ITEMS: u64 = 7;

/// Die Obergrenze, bis zu der eine Containerdatei gelesen wird.
///
/// Ein Container ist rund 120 Bytes gross. Eine Datei jenseits dieser Grenze
/// ist kein Container, und sie wird nicht erst vollstaendig in den Speicher
/// geholt, um das festzustellen.
const MAX_CONTAINER_FILE_BYTES: u64 = 1024;

/// Die Schluesselart, die ein Container traegt.
///
/// Der Kennwert steht im Kopf des Containers und ist Teil der AAD.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainedKeyKind {
    /// Ein privater X25519-Empfaengerschluessel (Recovery-KEM).
    RecipientKem,
    /// Ein Ed25519-Seed (HGA-Signierer, Berichtssignierer).
    Signing,
}

impl ContainedKeyKind {
    /// Der Kennwert im Kopf.
    #[must_use]
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::RecipientKem => 1,
            Self::Signing => 2,
        }
    }

    /// Die Art zu einem Kennwert, oder nichts.
    #[must_use]
    pub const fn from_wire_value(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::RecipientKem),
            2 => Some(Self::Signing),
            _ => None,
        }
    }
}

/// Ein versiegelter Schluessel samt allem, was zum Oeffnen noetig ist —
/// ausser der Passphrase.
///
/// # Kein `Debug`
///
/// Siehe den Modulkopf: die Nonce gehoert in kein Protokoll.
#[derive(Clone, Eq, PartialEq)]
pub struct EncryptedKeyContainer {
    kind: ContainedKeyKind,
    /// Die KDF-Parameter, wie der Kopf sie traegt — Teil der AAD.
    ///
    /// Gespeichert und nicht aus den Konstanten nachgebaut, damit die AAD
    /// byteweise der Kopf IST: `from_bytes` verlangt zwar genau die gepinnten
    /// Werte, aber die AEAD-Bindung soll nicht an dieser Pruefung haengen
    /// (Modulkopf, „zwei Schichten").
    kdf: KdfParametersV1,
    salt: [u8; KEY_CONTAINER_SALT_SIZE_V1],
    nonce: [u8; AEAD_NONCE_SIZE],
    ciphertext: [u8; CIPHERTEXT_SIZE],
}

/// Die drei Argon2id-Parameter des `kdf`-Gliedes, in Kopfreihenfolge.
#[derive(Clone, Copy, Eq, PartialEq)]
struct KdfParametersV1 {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

/// Die gepinnte Parametrierung — das Einzige, was `seal` je in den Kopf
/// schreibt und `from_bytes` je daraus annimmt.
const PINNED_KDF_PARAMETERS_V1: KdfParametersV1 = KdfParametersV1 {
    memory_kib: ARGON2ID_MEMORY_KIB_V1,
    iterations: ARGON2ID_ITERATIONS_V1,
    parallelism: ARGON2ID_PARALLELISM_V1,
};

impl EncryptedKeyContainer {
    /// Versiegelt `secret` unter `passphrase` mit frischem Salz und frischer
    /// Nonce.
    ///
    /// # Errors
    ///
    /// [`RecoveryError::SecretEmpty`] fuer eine leere Passphrase;
    /// [`RecoveryError::Io`] mit [`std::io::ErrorKind::Other`], wenn das
    /// Betriebssystem keine Entropie liefert — eine Systemfaehigkeit, die
    /// gescheitert ist, also 20 und kein Befund; [`RecoveryError::KeySource`],
    /// falls die AEAD ein Chiffrat anderer Groesse liefert (unerreichbar, und
    /// trotzdem kein `expect`).
    pub fn seal(
        kind: ContainedKeyKind,
        secret: SecretBytes<CONTAINED_KEY_SIZE>,
        passphrase: &SecretVec,
    ) -> Result<Self, RecoveryError> {
        if passphrase.is_empty() {
            return Err(RecoveryError::SecretEmpty);
        }
        let mut salt = [0_u8; KEY_CONTAINER_SALT_SIZE_V1];
        let mut nonce = [0_u8; AEAD_NONCE_SIZE];
        fill_random(&mut salt)?;
        fill_random(&mut nonce)?;

        let key = derive_key(passphrase, &salt)?;
        let kdf = PINNED_KDF_PARAMETERS_V1;
        let aad = header_bytes(kind, kdf, &salt, &nonce);
        let nonce_secret: SecretBytes<AEAD_NONCE_SIZE> = SecretBytes::new(nonce);
        // Der Klartext wandert in einen `SecretVec`, weil `aead_seal` einen
        // verlangt; die Kopie lebt genau bis zum Ende dieses Aufrufs.
        let plaintext = secret.with_exposed(|bytes| SecretVec::new(bytes.to_vec()));
        let sealed = aead_seal(&key, &nonce_secret, plaintext, &aad)
            .map_err(|_| RecoveryError::KeySource)?;
        let ciphertext: [u8; CIPHERTEXT_SIZE] =
            sealed.try_into().map_err(|_| RecoveryError::KeySource)?;
        Ok(Self {
            kind,
            kdf,
            salt,
            nonce,
            ciphertext,
        })
    }

    /// Oeffnet den Container als Schluessel der Art `kind`.
    ///
    /// # DIE REIHENFOLGE IST TEIL DES VERTRAGS
    ///
    /// 1. Die Art muss stimmen — sonst [`RecoveryError::KeySource`], BEVOR
    ///    irgendetwas gerechnet wird. Eine Verwechslung ist ein Aufruffehler
    ///    und darf nicht 64 MiB und drei Durchlaeufe kosten.
    /// 2. Die Passphrase darf nicht leer sein — sonst
    ///    [`RecoveryError::SecretEmpty`].
    /// 3. Erst dann der KDF, dann die AEAD — und scheitert die AEAD, ist das
    ///    [`RecoveryError::ContainerOpen`]: die Form hat getragen, die
    ///    Entschluesselung nicht.
    ///
    /// Gemessen wird die Reihenfolge in
    /// `tests/offline_sources.rs::a_kind_mismatch_is_refused_before_the_kdf_runs`
    /// ueber die Ausgaenge 1 und 2: dass eine leere Passphrase bei falscher
    /// Art `KeySource` und bei richtiger Art `SecretEmpty` liefert, beweist,
    /// dass die Artpruefung vor allem anderen steht — ohne eine Uhr.
    ///
    /// # Errors
    ///
    /// [`RecoveryError::KeySource`] bei falscher Art — die Datei traegt nicht
    /// das, was der Aufruf verlangt, Exitcode 2; [`RecoveryError::SecretEmpty`]
    /// fuer eine leere Passphrase; [`RecoveryError::ContainerOpen`] bei
    /// falscher Passphrase, verstuemmeltem Chiffrat oder einem Kopf, der noch
    /// dekodiert, aber die AAD veraendert — dieselbe Antwort fuer alle drei,
    /// damit ein Angreifer aus dem Fehler nichts lernt, Exitcode 14. Die
    /// Grenze zwischen 2 und 14 verlaeuft an der AEAD: davor ist es die Form,
    /// dahinter die Entschluesselung.
    pub fn open(
        &self,
        kind: ContainedKeyKind,
        passphrase: &SecretVec,
    ) -> Result<SecretBytes<CONTAINED_KEY_SIZE>, RecoveryError> {
        if self.kind != kind {
            return Err(RecoveryError::KeySource);
        }
        if passphrase.is_empty() {
            return Err(RecoveryError::SecretEmpty);
        }
        let key = derive_key(passphrase, &self.salt)?;
        let aad = header_bytes(self.kind, self.kdf, &self.salt, &self.nonce);
        let nonce_secret: SecretBytes<AEAD_NONCE_SIZE> = SecretBytes::new(self.nonce);
        let plaintext = aead_open(&key, &nonce_secret, &self.ciphertext, &aad)
            .map_err(|_| RecoveryError::ContainerOpen)?;
        let mut material = [0_u8; CONTAINED_KEY_SIZE];
        let exact_size = plaintext.with_exposed(|bytes| {
            if bytes.len() == CONTAINED_KEY_SIZE {
                material.copy_from_slice(bytes);
                true
            } else {
                false
            }
        });
        // Unerreichbar bei 48 Chiffratbytes — und trotzdem die Antwort der
        // Entschluesselung, nicht der Form: die AEAD ist hier bereits gelaufen.
        if !exact_size {
            return Err(RecoveryError::ContainerOpen);
        }
        let secret = SecretBytes::new(material);
        material.zeroize();
        Ok(secret)
    }

    /// Die Schluesselart aus dem Kopf.
    #[must_use]
    pub const fn kind(&self) -> ContainedKeyKind {
        self.kind
    }

    /// Die deterministischen CBOR-Bytes des Containers.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(128);
        let mut encoder = Encoder::new(&mut bytes);
        encoder
            .array(CONTAINER_ITEMS)
            .expect("encoding the container array head cannot fail");
        encode_header_items(&mut encoder, self.kind, self.kdf, &self.salt, &self.nonce);
        encoder
            .bytes(&self.ciphertext)
            .expect("encoding the ciphertext cannot fail");
        debug_assert!(ea_cbor::validate(&bytes, ParserLimits::V1).is_ok());
        bytes
    }

    /// Dekodiert einen Container aus EXAKT diesen Bytes.
    ///
    /// # FAIL-CLOSED, GLIED FUER GLIED
    ///
    /// Erst die deterministische Form ueber [`ea_cbor::validate`], dann jedes
    /// Glied gegen seinen gepinnten Wert: Domain, Version, Art, KDF-Kennung
    /// und alle drei Parameter, die drei Groessen. Jede Abweichung und jedes
    /// nachlaufende Byte ist [`RecoveryError::KeySource`]; es gibt keinen
    /// Container, der „fast" passt.
    ///
    /// # Errors
    ///
    /// [`RecoveryError::KeySource`] fuer jede Abweichung.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RecoveryError> {
        ea_cbor::validate(bytes, ParserLimits::V1).map_err(|_| RecoveryError::KeySource)?;
        let mut decoder = Decoder::new(bytes);
        let shape = RecoveryError::KeySource;

        if decoder.array().map_err(|_| shape)? != Some(CONTAINER_ITEMS) {
            return Err(shape);
        }
        if decoder.str().map_err(|_| shape)? != KEY_CONTAINER_DOMAIN_V1 {
            return Err(shape);
        }
        if decoder.u8().map_err(|_| shape)? != KEY_CONTAINER_VERSION_V1 {
            return Err(shape);
        }
        let kind =
            ContainedKeyKind::from_wire_value(decoder.u8().map_err(|_| shape)?).ok_or(shape)?;

        if decoder.array().map_err(|_| shape)? != Some(4) {
            return Err(shape);
        }
        if decoder.u8().map_err(|_| shape)? != KDF_ID_ARGON2ID {
            return Err(shape);
        }
        // GENAU die gepinnte Parametrierung, siehe den Modulkopf. Die Werte
        // werden trotzdem als die des KOPFES bewahrt: die AAD entsteht aus
        // ihnen, nicht aus den Konstanten.
        let kdf = KdfParametersV1 {
            memory_kib: decoder.u32().map_err(|_| shape)?,
            iterations: decoder.u32().map_err(|_| shape)?,
            parallelism: decoder.u32().map_err(|_| shape)?,
        };
        if kdf != PINNED_KDF_PARAMETERS_V1 {
            return Err(shape);
        }

        let salt: [u8; KEY_CONTAINER_SALT_SIZE_V1] = decoder
            .bytes()
            .map_err(|_| shape)?
            .try_into()
            .map_err(|_| shape)?;
        let nonce: [u8; AEAD_NONCE_SIZE] = decoder
            .bytes()
            .map_err(|_| shape)?
            .try_into()
            .map_err(|_| shape)?;
        let ciphertext: [u8; CIPHERTEXT_SIZE] = decoder
            .bytes()
            .map_err(|_| shape)?
            .try_into()
            .map_err(|_| shape)?;
        // `validate` hat nachlaufende Bytes bereits abgewiesen; die Frage
        // steht trotzdem hier, damit diese Funktion ihre Zusage selbst haelt.
        if decoder.position() != bytes.len() {
            return Err(shape);
        }
        Ok(Self {
            kind,
            kdf,
            salt,
            nonce,
            ciphertext,
        })
    }

    /// Schreibt den Container in eine NEUE Datei mit Rechten `0600`.
    ///
    /// Ueber `create_new_file` aus `crate::report`: „neu angelegt, nie
    /// ueberschrieben, 0600" gilt
    /// fuer jede Datei, die diese Crate schreibt, und steht deshalb an einer
    /// Stelle.
    ///
    /// # Errors
    ///
    /// [`RecoveryError::RestrictivePermissionsUnsupported`] auf einer
    /// Plattform ohne Rechtebits; [`RecoveryError::OutputExists`], wenn `path`
    /// existiert; [`RecoveryError::Io`] fuer jeden anderen Dateisystemfehler.
    pub fn write_new(&self, path: &Path) -> Result<(), RecoveryError> {
        let mut file = create_new_file(path)?;
        file.write_all(&self.to_bytes())?;
        file.sync_all()?;
        Ok(())
    }

    /// Liest einen Container aus einer Datei, die allein ihrem Eigentuemer
    /// gehoert.
    ///
    /// Dieselben Regeln wie [`crate::read_secret_file`], in derselben
    /// Reihenfolge: Plattform, regulaere Datei und kein Symlink VOR dem
    /// Oeffnen (eine FIFO liesse `File::open` sonst nie zurueckkehren),
    /// dieselbe Frage samt `mode & 0o077 == 0` auf dem geoeffneten Handle —
    /// und erst DANN das erste gelesene Byte. Ein Container ist zwar
    /// verschluesselt, aber eine weltlesbare Containerdatei ist ein
    /// Woerterbuchziel, und der Aufrufer soll das erfahren, bevor er die
    /// Passphrase je eingetippt hat.
    ///
    /// # Errors
    ///
    /// [`RecoveryError::RestrictivePermissionsUnsupported`],
    /// [`RecoveryError::KeySourceExposed`], [`RecoveryError::Io`], und
    /// [`RecoveryError::KeySource`] aus [`Self::from_bytes`] — auch fuer eine
    /// Datei jenseits von 1 KiB, die kein Container sein kann.
    pub fn read_from(path: &Path) -> Result<Self, RecoveryError> {
        restrictive_permissions_available()?;
        refuse_unless_regular_file_at(path)?;
        let file = File::open(path)?;
        refuse_unless_owner_only(&file)?;
        let mut bytes = Vec::new();
        // Ein Byte mehr als die Grenze, damit „zu gross" von „genau an der
        // Grenze" unterscheidbar bleibt.
        file.take(MAX_CONTAINER_FILE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_CONTAINER_FILE_BYTES {
            return Err(RecoveryError::KeySource);
        }
        Self::from_bytes(&bytes)
    }
}

/// Die deterministischen CBOR-Bytes des Kopfes — die AAD.
fn header_bytes(
    kind: ContainedKeyKind,
    kdf: KdfParametersV1,
    salt: &[u8; KEY_CONTAINER_SALT_SIZE_V1],
    nonce: &[u8; AEAD_NONCE_SIZE],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(80);
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .array(HEADER_ITEMS)
        .expect("encoding the header array head cannot fail");
    encode_header_items(&mut encoder, kind, kdf, salt, nonce);
    debug_assert!(ea_cbor::validate(&bytes, ParserLimits::V1).is_ok());
    bytes
}

/// Die sechs Kopfglieder, ohne Arraykopf — geteilt zwischen AAD und
/// Container, damit beide byteweise dieselben Glieder tragen.
fn encode_header_items(
    encoder: &mut Encoder<&mut Vec<u8>>,
    kind: ContainedKeyKind,
    kdf: KdfParametersV1,
    salt: &[u8; KEY_CONTAINER_SALT_SIZE_V1],
    nonce: &[u8; AEAD_NONCE_SIZE],
) {
    encoder
        .str(KEY_CONTAINER_DOMAIN_V1)
        .and_then(|encoder| encoder.u8(KEY_CONTAINER_VERSION_V1))
        .and_then(|encoder| encoder.u8(kind.wire_value()))
        .and_then(|encoder| encoder.array(4))
        .and_then(|encoder| encoder.u8(KDF_ID_ARGON2ID))
        .and_then(|encoder| encoder.u32(kdf.memory_kib))
        .and_then(|encoder| encoder.u32(kdf.iterations))
        .and_then(|encoder| encoder.u32(kdf.parallelism))
        .and_then(|encoder| encoder.bytes(salt))
        .and_then(|encoder| encoder.bytes(nonce))
        .expect("encoding fixed header items into a Vec cannot fail");
}

/// Leitet den AEAD-Schluessel aus Passphrase und Salz ab.
///
/// IMMER die gepinnten Konstanten und nie die Werte eines Kopfes: der KDF
/// wird nicht ausgehandelt. Die Kopfwerte gehen allein in die AAD.
///
/// Die Speicherbloecke des KDF werden HIER angelegt und nach dem Lauf
/// ueberschrieben — nicht ueber `hash_password_into`, dessen `alloc`-Merkmal
/// `password-hash` und `phc` ins Lockfile zoege (Begruendung an der
/// `argon2`-Zeile des Wurzelmanifests).
fn derive_key(
    passphrase: &SecretVec,
    salt: &[u8; KEY_CONTAINER_SALT_SIZE_V1],
) -> Result<SecretBytes<CEK_SIZE>, RecoveryError> {
    let params = Params::new(
        ARGON2ID_MEMORY_KIB_V1,
        ARGON2ID_ITERATIONS_V1,
        ARGON2ID_PARALLELISM_V1,
        Some(CEK_SIZE),
    )
    .map_err(|_| RecoveryError::KeySource)?;
    let block_count = params.block_count();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut blocks = vec![Block::new(); block_count];
    let mut output = [0_u8; CEK_SIZE];
    let derived = passphrase.with_exposed(|passphrase| {
        argon2.hash_password_into_with_memory(passphrase, salt, &mut output, blocks.as_mut_slice())
    });
    blocks.zeroize();
    if derived.is_err() {
        output.zeroize();
        return Err(RecoveryError::KeySource);
    }
    let key = SecretBytes::new(output);
    output.zeroize();
    Ok(key)
}

/// Fuellt `destination` aus der Entropiequelle des Betriebssystems.
///
/// Dieselbe Kiste und derselbe Aufruf wie `crates/ea-crypto/src/hpke.rs`.
fn fill_random(destination: &mut [u8]) -> Result<(), RecoveryError> {
    getrandom::fill(destination).map_err(|_| RecoveryError::Io(std::io::ErrorKind::Other))
}
