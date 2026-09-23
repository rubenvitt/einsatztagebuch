//! Zeremonie B des Reader-Key-Escrows im Browser (Profil §6 Schritte 1 und 6,
//! §7 — der Transport-Schlüssel).
//!
//! # Der Transport-Schlüssel ist flüchtig — per Signatur
//!
//! Das Transport-Schlüsselpaar entsteht in geteiltem Rust und lebt als
//! `SecretBytes<32>` in [`ReaderKeyEscrowTransportV1`], im linearen
//! WASM-Speicher. Keine Funktion dieses Moduls nimmt einen
//! `ReaderBlobStore`, kein Typ trägt `Serialize`, `Clone` oder `Debug`: es
//! gibt keinen Weg, den Schlüssel zu persistieren (kein OPFS, kein IndexedDB,
//! kein `localStorage`, kein Tresor). Ein Neuladen beendet den Worker und mit
//! ihm den Schlüssel — das ist die Frist (Profil §7).
//!
//! # Genau eine Zeremonie
//!
//! [`ReaderKeyEscrowTransportV1::open`] nimmt `self` als WERT: in JEDEM
//! Ausgang — Erfolg wie Fehler — fällt der Transport, und `SecretBytes`
//! nullt beim Fallen. Ein zweiter Import an denselben Schlüssel ist nicht
//! darstellbar:
//!
//! ```compile_fail
//! fn twice(transport: ea_reader::ReaderKeyEscrowTransportV1, envelope: &[u8]) {
//!     let _ = transport.open(envelope);
//!     let _ = transport.open(envelope);
//! }
//! ```
//!
//! `HpkeRecipientPrivateKey` entsteht nur kurzzeitig aus einer
//! `with_exposed`-Kopie. GEMESSEN (DRK-460, E4): `hpke 0.14.0` hält den
//! X25519-Schlüssel als `x25519_dalek::StaticSecret`, dessen `Drop` unter dem
//! Feature `zeroize` nullt; das Feature ist im Wirts- und im wasm32-Graphen
//! aktiv (`cargo tree -e features -i x25519-dalek`).
//!
//! # Die Prüfreihenfolge von `open` ist Vertrag
//!
//! 1. den Umschlag über den C4-Codec dekodieren;
//! 2. jedes Bindungsfeld gegen seine Referenz im Browser prüfen;
//! 3. HPKE öffnen, `info` und AAD aus der exakten Restore-Bindung;
//! 4. den abgeleiteten öffentlichen Schlüssel gegen den KEM des Escrows.
//!
//! **Benannte Abweichung:** `authorization-object-hash` hat im Browser keine
//! Referenz — die Autorisierung liegt nativ vor und steht vor dem Cutover in
//! keinem Katalog. Der Wert ist über die AEAD gebunden und wird angezeigt,
//! nicht geprüft.

use ea_archive::{ArchiveInventory, ArchiveSource};
use ea_crypto::{
    CanonicalPublicCoseKey, CryptoError, HpkeRecipientPrivateKey, HpkeRecipientPublicKey,
    HpkeSealed, SecretBytes, hpke_aad, hpke_info, hpke_open,
};
use ea_format::{
    ReaderKeyEscrowTransferKindV1, ReaderKeyEscrowTransportRequestV1,
    decode_reader_key_escrow_envelope, encode_reader_key_escrow_transport_request,
    reader_key_escrow_transfer_file_name,
};
use ea_trust::{
    ReaderKeyEscrowHead, TrustAnchorV1, VerifiedReaderKeyEscrow, load_trust_state,
    verify_reader_key_escrows, verify_trust,
};
use ea_types::{CertificateHash, KeyThumbprint, ObjectHash, SubjectId, UnixMillis};
use ea_verify::{EphemeralTrustStateStore, verification_state_key};
use zeroize::Zeroize;

use crate::reader_key_escrow::ReaderKeyEscrowError;

/// Der lebende Transport-Schlüssel EINER Wiederherstellung und das gültige
/// Escrow, an das er gebunden ist.
pub struct ReaderKeyEscrowTransportV1 {
    secret: SecretBytes<32>,
    public: HpkeRecipientPublicKey,
    thumbprint: KeyThumbprint,
    escrow: VerifiedReaderKeyEscrow,
    subject: SubjectId,
}

/// Die Transportdatei (Browser → Admin-Inbox). Öffentlich.
pub struct ReaderKeyEscrowTransportFileV1 {
    file_name: String,
    exact_bytes: Vec<u8>,
}

impl ReaderKeyEscrowTransportFileV1 {
    #[must_use]
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }
}

/// Der wiederhergestellte Reader-KEM. Konstruierbar nur in
/// [`ReaderKeyEscrowTransportV1::open`], nach allen Prüfungen.
pub struct RestoredReaderKemV1 {
    secret: SecretBytes<32>,
    thumbprint: KeyThumbprint,
    authorization_object_hash: ObjectHash,
}

impl RestoredReaderKemV1 {
    /// Der Abdruck des wiederhergestellten KEM — gleich dem des Escrows.
    #[must_use]
    pub const fn kem_key_thumbprint(&self) -> KeyThumbprint {
        self.thumbprint
    }

    /// Nur zur Anzeige (benannte Abweichung, Modulkopf).
    #[must_use]
    pub const fn authorization_object_hash(&self) -> ObjectHash {
        self.authorization_object_hash
    }

    /// Übergibt das Geheimnis an den neuen Tresor (`ReaderEnrollment`).
    #[expect(dead_code, reason = "der neue Tresor übernimmt das Geheimnis in E5")]
    pub(crate) fn into_secret(self) -> SecretBytes<32> {
        self.secret
    }
}

impl ReaderKeyEscrowTransportV1 {
    /// Prüft den Datei-Modus-Ordner gegen den gepinnten Anker, verlangt ein
    /// GÜLTIGES Escrow zu `subject` (widerrufsbewusst, U2) und zieht einen
    /// frischen Transport-Schlüssel.
    ///
    /// # Errors
    ///
    /// `EA-READER-ESCROW-NOT-FOUND` ohne gültiges Escrow zur Subject-ID; die
    /// Codes des Bestands, des Trust-Kerns (fail-closed über den ganzen
    /// Escrow-Bestand) und `EA-LOCAL-CRYPTO-RNG`.
    pub fn begin(
        anchor: &TrustAnchorV1,
        source: &dyn ArchiveSource,
        subject: SubjectId,
        now: UnixMillis,
    ) -> Result<Self, ReaderKeyEscrowError> {
        let inventory = ArchiveInventory::build(source)?;
        let key = verification_state_key(anchor.organization_id());
        let mut state = EphemeralTrustStateStore::new(key, now);
        let trust = verify_trust(anchor, &inventory, load_trust_state(&mut state, key)?)?;
        let escrows = verify_reader_key_escrows(&trust, ReaderKeyEscrowHead::CatalogLineTip)?;
        let escrow = escrows
            .valid_for_subject(subject)
            .ok_or(ReaderKeyEscrowError::NotFound)?
            .clone();

        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| CryptoError::LocalRng)?;
        let secret = SecretBytes::new(bytes);
        bytes.zeroize();
        let public = HpkeRecipientPrivateKey::from_bytes(
            secret.with_exposed(|bytes| SecretBytes::new(*bytes)),
        )?
        .public_key();
        let thumbprint = CanonicalPublicCoseKey::x25519(*public.as_bytes())?.thumbprint();
        Ok(Self {
            secret,
            public,
            thumbprint,
            escrow,
            subject,
        })
    }

    /// Der Abdruck des Transport-Schlüssels — anzuzeigen und den Approvern
    /// außerhalb des Systems vorzulegen (Profil §6 Schritt 1).
    #[must_use]
    pub const fn fingerprint(&self) -> KeyThumbprint {
        self.thumbprint
    }

    #[must_use]
    pub fn escrow_object_hash(&self) -> ObjectHash {
        self.escrow.object_hash()
    }

    #[must_use]
    pub fn reader_certificate_object_hash(&self) -> CertificateHash {
        self.escrow.core().reader_certificate_object_hash
    }

    /// Die Transportdatei: Organisation, Escrow und der ÖFFENTLICHE
    /// Schlüssel, über den C4-Codec.
    ///
    /// # Errors
    ///
    /// Die Codes des Codecs.
    pub fn transport_request(
        &self,
    ) -> Result<ReaderKeyEscrowTransportFileV1, ReaderKeyEscrowError> {
        let exact_bytes =
            encode_reader_key_escrow_transport_request(&ReaderKeyEscrowTransportRequestV1 {
                organization_id: self.escrow.core().organization_id,
                escrow_object_hash: self.escrow.object_hash(),
                target_transport_public_key: *self.public.as_bytes(),
            })?;
        Ok(ReaderKeyEscrowTransportFileV1 {
            file_name: reader_key_escrow_transfer_file_name(
                ReaderKeyEscrowTransferKindV1::TransportRequest,
                &exact_bytes,
            ),
            exact_bytes,
        })
    }

    /// Öffnet den Umschlag — genau einmal; `self` fällt in jedem Ausgang.
    ///
    /// # Errors
    ///
    /// Die Codes des Codecs; `EA-READER-ESCROW-RESTORE-BINDING` für jedes
    /// abweichende Bindungsfeld; `EA-CRYPTO-HPKE-OPEN`, wenn der Umschlag
    /// nicht an diesen Schlüssel versiegelt ist;
    /// `EA-READER-ESCROW-KEM-MISMATCH`, wenn der geöffnete Schlüssel nicht der
    /// KEM des Escrows ist.
    pub fn open(self, envelope: &[u8]) -> Result<RestoredReaderKemV1, ReaderKeyEscrowError> {
        let envelope = decode_reader_key_escrow_envelope(envelope)?;
        let context = &envelope.restore_context;
        let core = self.escrow.core();
        if context.organization_id != core.organization_id
            || context.escrow_object_hash != self.escrow.object_hash()
            || context.reader_certificate_object_hash != core.reader_certificate_object_hash
            || context.reader_subject_id != core.reader_subject_id
            || context.reader_subject_id != self.subject
            || context.target_transport_key_thumbprint != self.thumbprint
        {
            return Err(ReaderKeyEscrowError::RestoreBinding);
        }
        let exact_context = context.encode();
        let recipient = HpkeRecipientPrivateKey::from_bytes(
            self.secret.with_exposed(|bytes| SecretBytes::new(*bytes)),
        )?;
        let secret = hpke_open(
            &recipient,
            &HpkeSealed::from_parts(envelope.encapsulated_key, envelope.sealed_reader_kem_key)?,
            &hpke_info(&exact_context),
            &hpke_aad(&exact_context),
        )?;
        drop(recipient);
        let derived = HpkeRecipientPrivateKey::from_bytes(
            secret.with_exposed(|bytes| SecretBytes::new(*bytes)),
        )?
        .public_key();
        let derived = CanonicalPublicCoseKey::x25519(*derived.as_bytes())?;
        self.escrow
            .require_reader_kem_public_key(&derived)
            .map_err(|_| ReaderKeyEscrowError::KemMismatch)?;
        Ok(RestoredReaderKemV1 {
            secret,
            thumbprint: derived.thumbprint(),
            authorization_object_hash: context.authorization_object_hash,
        })
    }
}
