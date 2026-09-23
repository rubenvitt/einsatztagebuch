//! Zeremonie A des Reader-Key-Escrows im Browser (Profil §5, Scheibe e).
//!
//! # Das Gate ist eine TYPAUSSAGE
//!
//! Profil §5 Schritt 2: der Browser leitet den öffentlichen Schlüssel des
//! privaten KEM ab, den er versiegelt, und verlangt Gleichheit mit dem
//! geprüften Reader-Zertifikat, BEVOR ein Chiffrat entsteht.
//! [`seal_escrow_package`] nimmt deshalb ausschließlich einen
//! [`EscrowSealingKeyMatchV1`], und dieser Wert entsteht nur in
//! [`match_sealing_key`] nach dem Vergleich. Der Beweis BORGT das geprüfte
//! Geheimnis aus dem Tresor; versiegelt wird genau dieses, ohne Kopie — dass
//! das geprüfte und das versiegelte Geheimnis dasselbe sind, folgt aus dem
//! Typ. Kein `Default`, kein `Clone`, kein `Debug`, kein inhärenter
//! `impl`-Block (`tests/reader_key_escrow_package.rs` misst das am Quelltext).
//!
//! ```compile_fail
//! fn forge<'v>(
//!     secret: &'v ea_crypto::SecretBytes<32>,
//!     target: ea_trust::ReaderKeyEscrowSealingTarget,
//! ) -> ea_reader::EscrowSealingKeyMatchV1<'v> {
//!     ea_reader::EscrowSealingKeyMatchV1 { secret, target }
//! }
//! ```
//!
//! # Das Ziel kommt aus einem GEPRÜFTEN Katalog
//!
//! Der Tresor kennt weder Zertifikatshash noch Aktivierungszustand. Das Ziel
//! leitet `ea_trust::verify_reader_key_escrow_sealing_target` aus dem
//! Datei-Modus-Ordner ab, gegen den gepinnten Anker des Tresors und das Ende
//! der Katalog-Linie — dieselbe Enrollment-Regel, die das veröffentlichte
//! Escrow später besteht. Die Publikation selbst bleibt nativ und gesperrt bis
//! zum Cutover (GC:26); hier entsteht nur die Paketdatei der Admin-Inbox
//! (Ruling U3).

use ea_archive::{ArchiveError, ArchiveInventory, ArchiveSource};
use ea_crypto::{
    CanonicalPublicCoseKey, CryptoError, HpkeRecipientPrivateKey, SecretBytes, hpke_aad, hpke_info,
    hpke_seal, reader_key_escrow_core_hash,
};
use ea_format::{
    FormatError, ReaderKeyEscrowCoreV1, ReaderKeyEscrowHpkeContextV1,
    ReaderKeyEscrowTransferKindV1, decode_reader_key_escrow_package,
    encode_reader_key_escrow_package, reader_key_escrow_transfer_file_name,
};
use ea_sync_protocol::SyncProtocolError;
use ea_trust::{
    ReaderKeyEscrowHead, ReaderKeyEscrowSealingTarget, TrustError, load_trust_state,
    verify_reader_key_escrow_sealing_target, verify_trust,
};
use ea_types::{CertificateHash, Hash32, KeyThumbprint, SubjectId, UnixMillis};
use ea_verify::{EphemeralTrustStateStore, verification_state_key};

use crate::vault::UnlockedVault;

/// Der Fehlschlag einer Escrow-Zeremonie im Browser.
///
/// Die eigenen Varianten tragen ihren Code ausgeschrieben, die
/// durchreichenden geben den Code IHRER QUELLE weiter — dieselbe Regel wie
/// bei [`crate::EnrollmentError`].
pub enum ReaderKeyEscrowError {
    /// Der KEM ist nicht der des Reader-Zertifikats: der Tresor-KEM vor dem
    /// Versiegeln (A) oder der wiederhergestellte KEM nach dem Öffnen (B).
    KemMismatch,
    /// Kein gültiges Escrow zur Subject-ID (Zeremonie B).
    NotFound,
    /// Ein Bindungsfeld des Umschlags weicht von seiner Referenz ab.
    RestoreBinding,
    /// Der Trust-Kern hat abgewiesen.
    Trust(TrustError),
    /// Der Codec der Übergabedateien hat abgewiesen.
    Format(FormatError),
    /// Der Bestand hat abgewiesen.
    Archive(ArchiveError),
    /// `ea-crypto` hat abgewiesen.
    Crypto(CryptoError),
    /// Ein Protokollrahmen hat abgewiesen.
    Protocol(SyncProtocolError),
}

impl ReaderKeyEscrowError {
    /// Der stabile Code des Fehlschlags.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::KemMismatch => "EA-READER-ESCROW-KEM-MISMATCH",
            Self::NotFound => "EA-READER-ESCROW-NOT-FOUND",
            Self::RestoreBinding => "EA-READER-ESCROW-RESTORE-BINDING",
            Self::Trust(error) => error.code(),
            Self::Format(error) => error.code(),
            Self::Archive(error) => error.code(),
            Self::Crypto(error) => error.code(),
            Self::Protocol(error) => error.code(),
        }
    }
}

impl From<TrustError> for ReaderKeyEscrowError {
    fn from(error: TrustError) -> Self {
        Self::Trust(error)
    }
}

impl From<FormatError> for ReaderKeyEscrowError {
    fn from(error: FormatError) -> Self {
        Self::Format(error)
    }
}

impl From<ArchiveError> for ReaderKeyEscrowError {
    fn from(error: ArchiveError) -> Self {
        Self::Archive(error)
    }
}

impl From<CryptoError> for ReaderKeyEscrowError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<SyncProtocolError> for ReaderKeyEscrowError {
    fn from(error: SyncProtocolError) -> Self {
        Self::Protocol(error)
    }
}

// Nur der Code: Befunde tragen kein Material.
impl core::fmt::Debug for ReaderKeyEscrowError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl core::fmt::Display for ReaderKeyEscrowError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ReaderKeyEscrowError {}

/// Der Beweis „der KEM, der versiegelt wird, ist der des Zertifikats".
///
/// Konstruierbar AUSSCHLIESSLICH in [`match_sealing_key`]. Er borgt das
/// geprüfte Geheimnis aus dem Tresor; [`seal_escrow_package`] verbraucht ihn.
pub struct EscrowSealingKeyMatchV1<'v> {
    secret: &'v SecretBytes<32>,
    target: ReaderKeyEscrowSealingTarget,
}

/// Das Gleichheitsgate (Profil §5 Schritt 2): der aus dem KEM-Geheimnis des
/// Tresors ABGELEITETE öffentliche Schlüssel muss der X25519-KEM des
/// geprüften Reader-Zertifikats sein.
///
/// # Errors
///
/// `EA-READER-ESCROW-KEM-MISMATCH`, wenn er es nicht ist; die Codes von
/// `ea-crypto`, wenn das Geheimnis kein X25519-Schlüssel ist.
pub fn match_sealing_key(
    vault: &UnlockedVault,
    target: ReaderKeyEscrowSealingTarget,
) -> Result<EscrowSealingKeyMatchV1<'_>, ReaderKeyEscrowError> {
    let secret = vault.kem_secret();
    let derived =
        HpkeRecipientPrivateKey::from_bytes(secret.with_exposed(|bytes| SecretBytes::new(*bytes)))?
            .public_key();
    let derived = CanonicalPublicCoseKey::x25519(*derived.as_bytes())?;
    if derived != *target.reader_kem_public_key() {
        return Err(ReaderKeyEscrowError::KemMismatch);
    }
    Ok(EscrowSealingKeyMatchV1 { secret, target })
}

/// Die Paketdatei der Zeremonie A — alles darin ist öffentlich: der Core mit
/// Chiffrat, die Hashes und der Abdruck zur Anzeige.
pub struct ReaderKeyEscrowPackageFileV1 {
    file_name: String,
    exact_bytes: Vec<u8>,
    escrow_core_hash: Hash32,
    reader_certificate_object_hash: CertificateHash,
    recovery_certificate_object_hash: CertificateHash,
    kem_key_thumbprint: KeyThumbprint,
}

impl ReaderKeyEscrowPackageFileV1 {
    /// `hex(object_hash(bytes))` plus Paketsuffix, aus dem C4-Codec.
    #[must_use]
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    /// `escrow-core-hash` über die exakten Core-Bytes der Datei — der Wert,
    /// den der Administrator freigibt.
    #[must_use]
    pub const fn escrow_core_hash(&self) -> Hash32 {
        self.escrow_core_hash
    }

    #[must_use]
    pub const fn reader_certificate_object_hash(&self) -> CertificateHash {
        self.reader_certificate_object_hash
    }

    #[must_use]
    pub const fn recovery_certificate_object_hash(&self) -> CertificateHash {
        self.recovery_certificate_object_hash
    }

    #[must_use]
    pub const fn kem_key_thumbprint(&self) -> KeyThumbprint {
        self.kem_key_thumbprint
    }
}

/// Versiegelt den geprüften KEM an den Recovery-Empfänger des Ziels und baut
/// die Paketdatei.
///
/// Der HPKE-Kontext entsteht aus dem Core ohne Kapselung und Chiffrat — er
/// enthält keins von beiden —, danach werden beide eingesetzt. Kodiert wird
/// über den C4-Codec; der Corehash wird über die exakten Core-Bytes DER DATEI
/// gerechnet, nie über eine zweite Kodierung.
///
/// # Errors
///
/// Die Codes von `ea-crypto` und des Codecs.
pub fn seal_escrow_package(
    matched: EscrowSealingKeyMatchV1<'_>,
    issued_at: UnixMillis,
) -> Result<ReaderKeyEscrowPackageFileV1, ReaderKeyEscrowError> {
    let target = &matched.target;
    let (enrollment_registry_version, enrollment_registry_head_hash, enrollment_sequence) =
        target.enrollment();
    let mut core = ReaderKeyEscrowCoreV1 {
        organization_id: target.organization_id(),
        reader_certificate_object_hash: target.reader_certificate_object_hash(),
        reader_subject_id: target.reader_subject_id(),
        enrollment_registry_version,
        enrollment_registry_head_hash,
        enrollment_sequence,
        recovery_certificate_object_hash: target.recovery_certificate_object_hash(),
        recovery_kem_key_thumbprint: target.recovery_kem_key_thumbprint(),
        encapsulated_key: [0; 32],
        encrypted_reader_kem_key: [0; 48],
        issued_at,
        root_key_thumbprint: target.root_key_thumbprint(),
    };
    let context = ReaderKeyEscrowHpkeContextV1::from_escrow_core(&core).encode();
    let sealed = hpke_seal(
        &target.recovery_kem_public_key(),
        matched.secret,
        &hpke_info(&context),
        &hpke_aad(&context),
    )?;
    core.encapsulated_key = *sealed.encapsulated_key();
    core.encrypted_reader_kem_key = *sealed.wrapped_cek();
    let exact_bytes = encode_reader_key_escrow_package(&core)?;
    let package = decode_reader_key_escrow_package(&exact_bytes)?;
    Ok(ReaderKeyEscrowPackageFileV1 {
        file_name: reader_key_escrow_transfer_file_name(
            ReaderKeyEscrowTransferKindV1::Package,
            &exact_bytes,
        ),
        escrow_core_hash: reader_key_escrow_core_hash(package.exact_core()),
        reader_certificate_object_hash: core.reader_certificate_object_hash,
        recovery_certificate_object_hash: core.recovery_certificate_object_hash,
        kem_key_thumbprint: target.reader_kem_public_key().thumbprint(),
        exact_bytes,
    })
}

/// Zeremonie A im Browser, ganz: Datei-Modus-Ordner prüfen, Ziel ableiten,
/// Gate, Paket.
///
/// Vertrauen kommt ausschließlich aus dem gepinnten Anker des Tresors
/// (`web-reader-design.md` §5.3); der Ordner liefert nur Bytes. Der
/// Escrow-Bestand des Ordners wird VOLLSTÄNDIG geprüft, fail-closed: ein
/// einziges ungültiges Familienobjekt verweigert das Paket.
///
/// # Errors
///
/// Die Codes des Bestands, des Trust-Kerns (unter anderem
/// `EA-TRUST-ESCROW-ENROLLMENT-MISMATCH`, wenn kein aktives Reader-Zertifikat
/// den KEM des Tresors trägt, und `EA-TRUST-ESCROW-CONFLICT`), das Gate und die
/// Codes von [`seal_escrow_package`].
pub fn seal_reader_key_escrow_package(
    vault: &UnlockedVault,
    source: &dyn ArchiveSource,
    reader_subject_id: SubjectId,
    now: UnixMillis,
) -> Result<ReaderKeyEscrowPackageFileV1, ReaderKeyEscrowError> {
    let inventory = ArchiveInventory::build(source)?;
    let anchor = vault.pinned_anchor();
    let key = verification_state_key(anchor.organization_id());
    let mut state = EphemeralTrustStateStore::new(key, now);
    let trust = verify_trust(anchor, &inventory, load_trust_state(&mut state, key)?)?;
    let target = verify_reader_key_escrow_sealing_target(
        &trust,
        ReaderKeyEscrowHead::CatalogLineTip,
        vault.kem_key_thumbprint(),
        reader_subject_id,
    )?;
    seal_escrow_package(match_sealing_key(vault, target)?, now)
}
