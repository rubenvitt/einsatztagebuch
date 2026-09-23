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

/// Eine Linie mit EINEM veröffentlichten, gültigen Escrow des Reader-KEM
/// (`escrow_support::READER_KEM_SEED`) für `reader_subject`.
pub fn line_with_escrow(reader_subject: ea_types::SubjectId) -> (EscrowLine, ea_types::ObjectHash) {
    use crate::escrow_support::{
        Basis, EscrowLineOptions, READER_KEM_SEED, approval_core, escrow_core, escrow_line,
        publish_escrow,
    };
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let core = escrow_core(
        &escrow,
        &escrow.reader,
        READER_KEM_SEED,
        reader_subject,
        1_200,
    );
    let tip = *escrow.line.heads().last().unwrap();
    let approval = approval_core(
        &escrow.line,
        Basis::of(&tip, tip.effective_from.get()),
        (1_000, 1_300),
        0xe4,
    );
    let (_, escrow_hash) = publish_escrow(&mut escrow, &core, &approval);
    (escrow, escrow_hash)
}

/// Der ganze Weg der Zeremonie B bis zum wiederhergestellten KEM: Transport
/// beginnen, Umschlag an seinen öffentlichen Schlüssel versiegeln — wie der
/// native Öffnungsdienst —, öffnen.
pub fn restored_kem(
    escrow: &EscrowLine,
    escrow_hash: ea_types::ObjectHash,
    reader_subject: ea_types::SubjectId,
) -> ea_reader::RestoredReaderKemV1 {
    use ea_crypto::{HpkeRecipientPublicKey, hpke_aad, hpke_info, hpke_seal};
    use ea_format::{
        ReaderKeyEscrowEnvelopeV1, ReaderKeyEscrowRestoreContextV1,
        decode_reader_key_escrow_transport_request, encode_reader_key_escrow_envelope,
    };
    let anchor = ea_reader::decode_trust_anchor(escrow.line.exact_anchor_bytes()).unwrap();
    let transport = ea_reader::ReaderKeyEscrowTransportV1::begin(
        &anchor,
        &LineSource::of(escrow),
        reader_subject,
        ea_types::UnixMillis::new(2_000),
    )
    .unwrap();
    let request = decode_reader_key_escrow_transport_request(
        transport.transport_request().unwrap().exact_bytes(),
    )
    .unwrap();
    let context = ReaderKeyEscrowRestoreContextV1 {
        organization_id: anchor.organization_id(),
        authorization_object_hash: crate::support::object_hash_marker(0x7a),
        escrow_object_hash: escrow_hash,
        reader_certificate_object_hash: escrow.reader.certificate,
        reader_subject_id: reader_subject,
        target_transport_key_thumbprint: transport.fingerprint(),
    };
    let encoded = context.encode();
    let sealed = hpke_seal(
        &HpkeRecipientPublicKey::from_bytes(request.target_transport_public_key).unwrap(),
        &SecretBytes::new(crate::escrow_support::READER_KEM_SEED),
        &hpke_info(&encoded),
        &hpke_aad(&encoded),
    )
    .unwrap();
    let bytes = encode_reader_key_escrow_envelope(&ReaderKeyEscrowEnvelopeV1 {
        restore_context: context,
        encapsulated_key: *sealed.encapsulated_key(),
        sealed_reader_kem_key: *sealed.wrapped_cek(),
    })
    .unwrap();
    transport.open(&bytes).unwrap()
}
