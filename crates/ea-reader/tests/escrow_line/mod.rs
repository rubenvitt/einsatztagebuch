//! Die Escrow-Linie der Browser-Zeugen (Scheibe e).
//!
//! Baut auf `crates/ea-trust/tests/escrow_support/mod.rs` auf, EINE Kodierung
//! über die Testkit-Bauer. Die einbindende Testdatei MUSS an ihrer Wurzel
//! deklarieren:
//!
//! ```text
//! #[path = "../../ea-trust/tests/support/mod.rs"] mod support;
//! #[path = "../../ea-verify/src/state.rs"] mod state;
//! #[path = "../../ea-trust/tests/escrow_support/mod.rs"] mod escrow_support;
//! ```
#![allow(dead_code)]

use ea_crypto::SecretBytes;
use ea_reader::{
    ArchiveBlob, ArchiveError, ArchiveSource, AuthenticatorPrfV1, ReaderVault, UnlockedVault,
    VaultContentsV1,
};
use ea_trust::TrustObjectSource;

use crate::escrow_support::EscrowLine;

/// Der Audit-Seed jedes Test-Tresors dieser Linie.
pub const AUDIT_SEED: [u8; 32] = [0xa7; 32];

/// Alle Trust-Objekte der Linie als Archivquelle — wie ein Datei-Modus-Ordner
/// sie liefert. Die Klassifikation hängt an den Bytes, nicht am Pfad.
pub struct LineSource {
    blobs: Vec<(String, Vec<u8>)>,
}

impl LineSource {
    pub fn of(escrow: &EscrowLine) -> Self {
        let source = escrow.line.source();
        let mut hashes = Vec::new();
        source
            .visit_trust_object_hashes(&mut |hash| {
                hashes.push(hash);
                Ok(())
            })
            .unwrap();
        let blobs = hashes
            .into_iter()
            .map(|hash| {
                let bytes = source.read_exact_trust_object(hash).unwrap().unwrap();
                (
                    format!("trust/{}.etb", hex::encode(hash.as_bytes())),
                    bytes.to_vec(),
                )
            })
            .collect();
        Self { blobs }
    }

    pub fn blobs(&self) -> impl Iterator<Item = &[u8]> {
        self.blobs.iter().map(|(_, bytes)| bytes.as_slice())
    }
}

impl ArchiveSource for LineSource {
    fn visit_blobs(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        for (path, bytes) in &self.blobs {
            visitor(ArchiveBlob::new(path, bytes))?;
        }
        Ok(())
    }
}

/// Ein entsperrter Tresor mit dem gepinnten Anker DIESER Linie und dem
/// gegebenen KEM-Seed.
pub fn vault_on(escrow: &EscrowLine, kem_seed: [u8; 32]) -> UnlockedVault {
    let contents = VaultContentsV1::new(
        SecretBytes::new(kem_seed),
        SecretBytes::new(AUDIT_SEED),
        escrow.line.exact_anchor_bytes().to_vec(),
        None,
    );
    let authenticator = || AuthenticatorPrfV1::new(vec![0x3c; 16], SecretBytes::new([0x3d; 32]));
    let sealed = ReaderVault::seal(contents, &[authenticator()]).unwrap();
    ReaderVault::unlock(&sealed, &authenticator()).unwrap()
}
