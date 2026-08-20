//! Schritt 5: den initialen Grant-Plan bilden und hashen.
//!
//! Der Plan entsteht aus [`SelectedRegistryHead::active_certificates`] und
//! sonst nirgends. Jene Stelle dokumentiert in ihrem eigenen Vertrag, dass die
//! Empfaengerentscheidung dem AUFRUFER gehoert und dass nichts sie erzwingt —
//! genau deshalb liegt sie hier, und genau deshalb ist ein Readerzertifikat
//! ohne KEM-Abdruck hier ein FEHLER und keine Auslassung.
//!
//! Gehasht wird der Plan nicht hier: [`GrantPlanV1::new`] sortiert die Items in
//! die normative Totalordnung, serialisiert sie und hasht sie selbst. Es
//! entsteht kein zweiter Hashpfad, und die Negativregeln — keine Duplikate,
//! genau ein Recovery — kommen aus demselben eingefrorenen Konstruktor.

use ea_format::{CertificateKindV1, GrantPlanItemV1, GrantPlanV1, GrantPurposeV1};
use ea_trust::SelectedRegistryHead;

use crate::WriterError;

/// Bildet den initialen Grant-Plan des gebundenen Head.
///
/// GENAU ein aktiver Recovery-Empfaenger plus AUSNAHMSLOS jedes zur
/// gebundenen Registry-Version und zur neuen Eintragssequenz aktive
/// Readerzertifikat (`design.md` §9.3 Schritt 5). „Ausnahmslos" ist eine
/// Produktinvariante: ein stillschweigend uebersprungener Reader waere ein
/// Eintrag, den ein berechtigter Leser nie oeffnen kann.
///
/// # Errors
///
/// [`WriterError::ReaderWithoutKemKey`], wenn ein aktiver Reader oder
/// Recovery-Empfaenger keinen KEM-Abdruck traegt — ein Empfaenger ohne
/// KEM-Schluessel kann keinen Schluesselumschlag bekommen, und ihn zu
/// ueberspringen waere genau die stille Auslassung, die die Invariante
/// verbietet. [`WriterError::Format`], wenn der eingefrorene Konstruktor den
/// Plan ablehnt — bei KEINEM, bei einem ZWEITEN Recovery-Empfaenger oder bei
/// einem doppelten Empfaenger.
pub fn build_grant_plan(head: &SelectedRegistryHead) -> Result<GrantPlanV1, WriterError> {
    let mut items = Vec::new();
    for (certificate_hash, fields) in head.active_certificates() {
        let purpose = match fields.certificate_kind {
            CertificateKindV1::Reader => GrantPurposeV1::Reader,
            CertificateKindV1::RecoveryRecipient => GrantPurposeV1::Recovery,
            _ => continue,
        };
        let thumbprint = fields
            .kem_key_thumbprint
            .ok_or(WriterError::ReaderWithoutKemKey)?;
        items.push(GrantPlanItemV1::new(thumbprint, certificate_hash, purpose));
    }
    // KEINE nachgebaute Negativregel. `GrantPlanV1::new` weist null
    // Recovery-Empfaenger mit `MissingRecovery`, zwei mit `DuplicateRecovery`
    // und jeden doppelten Empfaenger mit `DuplicateRecipientKey` bzw.
    // `DuplicateRecipientCertificate` ab (`crates/ea-format/src/eag.rs`:109-128).
    // Eine zweite Zaehlung hier waere eine zweite Quelle derselben Wahrheit.
    // Die Zusage „mindestens ein aktiver Recovery-Empfaenger" gehoert Schritt 3
    // und wird dort am HEAD geprueft, vor jeder Serialisierung.
    Ok(GrantPlanV1::new(items)?)
}
