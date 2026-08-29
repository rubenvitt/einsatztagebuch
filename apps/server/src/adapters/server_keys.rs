//! Der eigene Ed25519-Schluessel des Servers.
//!
//! `design.md`:221 gibt dem Server einen Schluessel fuer Receipts UND
//! Checkpoints; der Sync-Wire-Nachtrag setzt den technischen Cursor als dritten
//! Zweck daneben. Alle drei laufen ueber DENSELBEN Schluessel und werden nicht
//! ueber eine achte `CertificateCapability` getrennt, sondern ueber Domaene und
//! Content-Type — `EINSATZARCHIV-TECHNICAL-CURSOR-v1` beim Cursor,
//! `application/vnd.einsatzarchiv.technical-cursor-digest` als COSE-Inhaltstyp.
//!
//! WAS HIER NICHT LIEGT: kein Reader-, kein Recovery-, kein HGA- und kein
//! Approver-Privatschluessel. Der Server kann Archivinhalte nicht oeffnen, und
//! dieser Speicher ist der Ort, an dem das sichtbar bleibt.
//!
//! ## Generationen
//!
//! Der Speicher fuehrt die AKTUELLE Generation und signiert ausschliesslich mit
//! ihr. Frueherе Generationen werden nicht mitgefuehrt: ein technischer Cursor
//! ist ein kurzlebiges Blaetterzeichen mit eigenem Ablaufdatum, und nach einer
//! Rotation soll er genau NICHT mehr oeffnen. Ein Klient blaettert dann neu an
//! — das ist der Zweck der Rotation und kein Datenverlust.

use ea_crypto::{
    CanonicalPublicCoseKey, CoseSigner, CryptoError, SecretBytes, verify_technical_cursor,
};
use ea_sync_protocol::{TechnicalCursorSigner, TechnicalCursorVerifier};
use ea_sync_server::ServerSigner;
use ea_types::{CertificateHash, Hash32};

pub struct ServerKeyStore {
    signer: CoseSigner,
    public_key: CanonicalPublicCoseKey,
    certificate_hash: CertificateHash,
    generation: u32,
}

impl ServerKeyStore {
    /// Der Schluessel der Generation `generation` unter `certificate_hash`.
    ///
    /// Das Geheimnis wird vom Aufrufer beschafft — aus der Umgebung, einem
    /// Secret-Store oder einem HSM-Adapter. Diese Struktur ist die Stelle, an
    /// der es zur Signaturoperation wird, nicht die, die es findet.
    pub fn new(
        secret: SecretBytes<32>,
        certificate_hash: CertificateHash,
        generation: u32,
    ) -> Result<Self, CryptoError> {
        let signer = CoseSigner::from_secret(secret);
        let public_key = signer.public_key()?;
        Ok(Self {
            signer,
            public_key,
            certificate_hash,
            generation,
        })
    }

    /// Der oeffentliche Schluessel dieser Generation.
    #[must_use]
    pub const fn public_key(&self) -> &CanonicalPublicCoseKey {
        &self.public_key
    }
}

impl ServerSigner for ServerKeyStore {
    fn certificate_hash(&self) -> CertificateHash {
        self.certificate_hash
    }

    fn key_generation(&self) -> u32 {
        self.generation
    }

    fn sign_receipt(&self, exact_receipt_core: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.signer.sign_receipt(exact_receipt_core)
    }

    fn sign_checkpoint(&self, exact_checkpoint_core: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.signer
            .sign_checkpoint(self.certificate_hash, exact_checkpoint_core)
    }
}

impl TechnicalCursorSigner for ServerKeyStore {
    fn sign_technical_cursor_digest(&self, digest: Hash32) -> Result<Vec<u8>, CryptoError> {
        self.signer
            .sign_technical_cursor(self.certificate_hash, digest)
    }
}

impl TechnicalCursorVerifier for ServerKeyStore {
    /// Prueft gegen die AKTUELLE Generation.
    ///
    /// Ein Token einer frueheren Generation scheitert hier, und
    /// `TechnicalCursorV1::open` macht daraus `EA-SYNC-CURSOR-INVALID` — ein
    /// stabiler Code, der dem Klienten nichts ueber die Rotation verraet.
    fn verify_technical_cursor_digest(
        &self,
        digest: Hash32,
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        verify_technical_cursor(signature, &self.public_key, self.certificate_hash, digest)
    }
}
