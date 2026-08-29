//! Die Quittung: VERIFIZIERT, dann abgelegt — nie umgekehrt.
//!
//! # Warum der VOLLE Verifizierer und kein Ausschnitt
//!
//! `design.md`:1584: „`synchronisiert` ist erst zulaessig, wenn der
//! Server-Receipt in der lokalen Archivkomponente und – sofern konfiguriert –
//! im Netzarchiv liegt." Was dort liegen darf, ist eine GEPRUEFTE Quittung,
//! und die Pruefung ist Gate `receipt` aus `design.md` §14.1 Schritt 7: die
//! fuenf Bindungen an den Eintrag, die Quittung als vertrauenswuerdiger
//! Zeitboden gegen die vorbestehende Registrierungsautoritaet, und erst dann
//! die Serversignatur gegen den gewaehlten Kopf.
//!
//! `ea-verify` fuehrt dieses Gate nicht als Einzelfunktion heraus, und das ist
//! kein Mangel dieser Datei: die drei Stufen brauchen den gewaehlten
//! Registrierungskopf, und der entsteht aus dem GANZEN Bestand. Deshalb laeuft
//! hier der vollstaendige [`ea_verify::verify_archive`] ueber die committeten
//! Bytes PLUS die Kandidatenquittung, und bestaetigt gilt sie erst, wenn der
//! Bericht den Eintrag als `serverConfirmed` fuehrt. Ein nachgebauter
//! Ausschnitt waere ein zweiter Verifizierer — und der freundlichere von
//! beiden waere zufaellig der falsche.
//!
//! # Erst pruefen, dann schreiben
//!
//! Die Reihenfolge ist die ganze Zusage. Die Kandidatenbytes werden in einer
//! Lesesicht NEBEN den Bestand gelegt, nicht IN ihn; erst der bestandene
//! Bericht fuehrt zu `create_if_absent`. Eine abgelegte und danach gepruefte
//! Quittung waere ein Bestand, der zwischen den beiden Schritten eine
//! ungepruefte Serveraussage traegt.

use ea_archive::{ArchiveBlob, ArchiveError, ArchivePath, ArchiveSource, RECEIPTS_DIR_V1};
use ea_format::{ParsedArchiveObject, decode_exact_object};
use ea_types::{ObjectHash, UnixMillis};
use ea_verify::{ObjectResultKindV1, ServerConfirmationV1, VerifyOptions, verify_archive};

use crate::SyncClientError;

/// Ein Bestand mit EINER zusaetzlichen Bytesequenz.
///
/// Sie liegt DANEBEN und nicht darin: die Quelle laeuft erst ueber den echten
/// Bestand und gibt dann die Kandidatenbytes aus. Der Bestand auf der Platte
/// bleibt dabei unberuehrt.
struct SourceWithCandidate<'a> {
    inner: &'a dyn ArchiveSource,
    candidate_path: String,
    candidate_bytes: &'a [u8],
}

impl ArchiveSource for SourceWithCandidate<'_> {
    fn visit_blobs(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        self.inner.visit_blobs(visitor)?;
        visitor(ArchiveBlob::new(&self.candidate_path, self.candidate_bytes))
    }
}

/// Eine Quittung, die den vollstaendigen Verifizierer bestanden hat.
///
/// Sie laesst sich NICHT von aussen bauen: der einzige Weg zu diesem Typ ist
/// [`verify_receipt_against_archive`]. „Verifiziert" ist damit eine Eigenschaft
/// des Typs und nicht eine Behauptung des Aufrufers.
pub struct VerifiedReceiptV1 {
    exact_bytes: Vec<u8>,
    object_hash: ObjectHash,
    address: ArchivePath,
}

impl VerifiedReceiptV1 {
    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    #[must_use]
    pub const fn object_hash(&self) -> ObjectHash {
        self.object_hash
    }

    /// Die Adresse, unter der die Quittung liegt.
    ///
    /// Aus dem OBJEKTHASH gebildet und nicht aus einem Namen, den der Server
    /// mitschickt: eine Adresse, die die Gegenstelle waehlt, waere ein Weg,
    /// unter einem fremden Namen zu schreiben.
    #[must_use]
    pub const fn address(&self) -> &ArchivePath {
        &self.address
    }
}

impl core::fmt::Debug for VerifiedReceiptV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("VerifiedReceiptV1(<bound>)")
    }
}

/// Prueft die Kandidatenbytes VOLLSTAENDIG gegen den committeten Bestand.
///
/// # Errors
///
/// [`SyncClientError::ReceiptInvalid`], wenn die Bytes kein `.esr` sind, wenn
/// sie auf einen anderen Eintrag zeigen, oder wenn der vollstaendige Bericht
/// den Eintrag nicht als `serverConfirmed` fuehrt. Es gibt ausdruecklich
/// keinen Zwischenausgang: eine Quittung ist bestaetigt oder sie ist es nicht.
pub fn verify_receipt_against_archive(
    committed: &dyn ArchiveSource,
    anchor: &ea_trust::TrustAnchorV1,
    entry_object_hash: ObjectHash,
    candidate_bytes: &[u8],
    observed_now: UnixMillis,
) -> Result<VerifiedReceiptV1, SyncClientError> {
    // Erste Huerde, VOR jeder Kryptografie: sind das ueberhaupt die Bytes einer
    // Quittung, und zeigen sie auf DIESEN Eintrag? Eine tadellos signierte
    // Quittung ueber einen anderen Eintrag bestaetigt diesen nicht.
    let ParsedArchiveObject::Receipt(receipt) =
        decode_exact_object(candidate_bytes).map_err(|_| SyncClientError::ReceiptInvalid)?
    else {
        return Err(SyncClientError::ReceiptInvalid);
    };
    if receipt.value().core().fields().entry_object_hash != entry_object_hash {
        return Err(SyncClientError::ReceiptInvalid);
    }

    let object_hash = receipt.object_hash();
    let address = address_of(object_hash)?;
    let source = SourceWithCandidate {
        inner: committed,
        candidate_path: address.as_str().to_owned(),
        candidate_bytes,
    };

    let report = verify_archive(&source, anchor, VerifyOptions::new(observed_now))
        .map_err(|_| SyncClientError::ReceiptInvalid)?;
    if !entry_is_server_confirmed(&report, entry_object_hash) {
        return Err(SyncClientError::ReceiptInvalid);
    }

    Ok(VerifiedReceiptV1 {
        exact_bytes: candidate_bytes.to_vec(),
        object_hash,
        address,
    })
}

/// Traegt der Bericht diesen Eintrag als BESTAETIGT?
///
/// Das ist Gate `receipt` VOLLSTAENDIG durchlaufen und nicht bloss ein
/// fehlender Fehler: ein leerer Fehlerbeutel waere auch dann leer, wenn das
/// Gate den Eintrag gar nicht erreicht haette.
///
/// Die EINE Stelle, an der „bestaetigt" definiert ist. Sowohl das Annehmen
/// einer frisch empfangenen Quittung als auch das Ableiten der Warteschlange
/// aus dem Bestand fragen sie — sonst waeren „darf abgelegt werden" und „gilt
/// als erledigt" zwei verschiedene Massstaebe, und der zweite waere der
/// nachsichtigere.
#[must_use]
pub fn entry_is_server_confirmed(
    report: &ea_verify::VerificationReportV1,
    entry_object_hash: ObjectHash,
) -> bool {
    report.object_results().any(|result| {
        result.object_hash() == entry_object_hash
            && result.server_confirmation() == ServerConfirmationV1::ServerConfirmed
            && result.result() == ObjectResultKindV1::Valid
    })
}

/// `receipts/<objectHash>.esr` — der Objekthash als Name.
fn address_of(object_hash: ObjectHash) -> Result<ArchivePath, SyncClientError> {
    let mut name = String::with_capacity(69);
    for byte in object_hash.as_bytes() {
        name.push(hex_digit(byte >> 4));
        name.push(hex_digit(byte & 0x0f));
    }
    name.push_str(".esr");
    ArchivePath::in_dir(RECEIPTS_DIR_V1, &name).map_err(|_| SyncClientError::ReceiptNotPersisted)
}

const fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'a' + nibble - 10) as char,
    }
}

#[cfg(test)]
mod tests {
    use super::address_of;
    use ea_types::ObjectHash;

    /// Die Adresse traegt den Objekthash in Kleinbuchstaben und liegt unter
    /// `receipts/`.
    #[test]
    fn the_address_is_the_object_hash_under_the_receipts_directory() {
        let hash = ObjectHash::try_from(&[0xab_u8; 32][..]).expect("32 Byte sind ein Objekthash");
        let address = address_of(hash).expect("die Adresse muss entstehen");
        assert_eq!(address.directory(), ea_archive::RECEIPTS_DIR_V1);
        assert!(address.as_str().ends_with(".esr"));
        assert!(address.as_str().contains(&"ab".repeat(32)));
    }
}
