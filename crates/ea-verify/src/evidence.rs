//! Gate `evidence`: Evidence-Objekte und Zeitstempel, sofern gefordert.
//!
//! ENG BEGRENZT, und die Grenze ist normativ. `design.md` §14.1 Schritt 7
//! (:1598) gibt „Server-Receipt und Checkpoints" an Gate `receipt`; Schritt 8
//! (:1599) nennt ausschliesslich „Evidence-Objekte und Zeitstempel, sofern
//! gefordert". Der Checkpoint-KERN ist damit bereits geprueft, wenn dieses Gate
//! laeuft. Hier bleiben genau zwei Dinge:
//!
//! 1. die RFC-3161-Anteile der Varianten `Timestamp` und `Renewal` — ihre
//!    Bindung an das COSE-Objekt, das sie bezeugen, und die Renewal-Kette ueber
//!    `ea_crypto::renewal_input_digest` und die EXAKTEN Vorobjektbytes;
//! 2. die Frist `evidence-due-at` aus einer BESTAETIGTEN Quittung gegen den
//!    Zeitwert des Laufs.
//!
//! # Was hier NICHT geprueft wird, und warum nicht
//!
//! `design.md`:1688 verlangt vom Validator „mindestens COSE-Signatur, Imprint,
//! TSA-Zertifikatskette, `timeStamping`-EKU, Policy, Nonce, `genTime` und
//! Zertifikatsstatus". Davon ist von `ea-verify` aus NICHTS erreichbar, was in
//! das DER-Token hineinsieht — und das ist gemessen, nicht vermutet:
//! `ea-crypto` parst das Token zwar (`crates/ea-crypto/src/cose.rs:745-771`),
//! haelt `validate_timestamp_token_der` aber privat und gibt weder
//! `messageImprint` noch `genTime` heraus. `ea-crypto` ist geschlossen, und
//! eine ASN.1-Abhaengigkeit in `ea-verify` ist ausgeschlossen: diese Crate
//! steht auf der wasm32-Positivliste und traegt nur Workspace-Crates.
//!
//! Der Imprint wird deshalb WEDER geprueft NOCH behauptet. Insbesondere wird
//! das Token nicht nach den 32 Bytes aus
//! `ea_crypto::cose_sign1_ctt_imprint` DURCHSUCHT: ein Fund darin waere kein
//! Nachweis der Bindung, und eine Pruefung, die wie eine aussieht, ohne eine zu
//! sein, ist schlimmer als ihre Verweigerung — dieselbe Regel, nach der
//! `crate::entry::claims_unverifiable_writer_transition` entscheidet.
//!
//! Fail-closed bleibt es trotzdem: ein Token qualifiziert hier nur, wenn seine
//! ERREICHBAREN Bindungen tragen; die TSA-Verifikation selbst ist die
//! Stage-6-Grenze, und ein Bestand, der sie braucht, ist mit diesem Stand
//! nicht als evidence-grade nachgewiesen.

use core::fmt;

use ea_archive::ArchiveInventory;
use ea_crypto::{parse_cose_sign1, renewal_input_digest};
use ea_format::{
    DecodedEvidencePayloadV1, EntryPackageV1, EvidenceObjectV1, Parsed, ReceiptV1,
    Rfc3161EvidenceFieldsV1,
};
use ea_trust::TrustAnchorV1;
use ea_types::ChainSequence;

use crate::{EvidenceRequirementV1, ObjectErrorV1, VerificationReportV1, VerifyOptions};

/// Der Befund von Gate `evidence` ueber GENAU EIN Objekt.
///
/// EIGENE FAMILIE, aus demselben Grund wie bei
/// [`crate::ManifestSignatureErrorV1`] und [`crate::ReceiptGateErrorV1`]: der
/// Code benennt das GATE, an dem der Befund entstand.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EvidenceGateErrorV1 {
    /// Die archivierte RFC-3161-Antwort ist nicht die, die im bezeugten
    /// COSE-Objekt steht.
    ///
    /// `design.md`:1686 setzt das Token als `3161-ctt`-Unprotected-Header IN
    /// das COSE-Objekt; die Felder des `.ecp` archivieren dieselbe Antwort
    /// daneben. Weichen beide voneinander ab, bezeugt das archivierte Token
    /// etwas anderes als das signierte Objekt — und eine nachtraeglich
    /// entfernte oder ausgetauschte CTT-Struktur ist nach :1701 ein Security
    /// Event.
    TokenNotBound,
    /// Ein Renewal beansprucht ein Vorobjekt, das der Bestand nicht enthaelt.
    ///
    /// `renewalInputHash[i]` bindet die EXAKTEN Bytes des erneuerten
    /// Evidence-Objekts (`design.md`:1705-1711). Laesst sich ein Wert im Bestand
    /// nicht wiederfinden, erneuert dieses Renewal etwas, das hier niemand
    /// nachrechnen kann.
    RenewalInputUnknown,
    /// Gefordert, Frist gesetzt, kein qualifizierendes Token — und die Frist
    /// laeuft noch.
    ///
    /// `design.md`:1694 nennt diesen Zustand `ausstehend`. Er wird NUR dann zu
    /// einem Befund, wenn der Aufrufer mit
    /// [`EvidenceRequirementV1::Required`] ausdruecklich einen
    /// VOLLSTAENDIGEN Evidence-Stand verlangt hat.
    Missing,
    /// Gefordert, Frist gesetzt, kein qualifizierendes Token, Frist abgelaufen.
    ///
    /// `design.md`:1699: ueberfaellig bleibt ueberfaellig — ein spaeteres Token
    /// aendert diesen Zustand dauerhaft nicht mehr.
    Overdue,
}

impl EvidenceGateErrorV1 {
    /// Stabiler Fehlercode. Tests assertieren gegen ihn, nie gegen Formatierung.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TokenNotBound => "EA-VERIFY-EVIDENCE-TOKEN-NOT-BOUND",
            Self::RenewalInputUnknown => "EA-VERIFY-EVIDENCE-RENEWAL-INPUT-UNKNOWN",
            Self::Missing => "EA-VERIFY-EVIDENCE-MISSING",
            Self::Overdue => "EA-VERIFY-EVIDENCE-OVERDUE",
        }
    }
}

impl fmt::Display for EvidenceGateErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

/// Ein Evidence-Objekt, dessen erreichbare Bindungen getragen haben.
///
/// Nur solche Objekte qualifizieren fuer eine Frist. Ein `.ecp`, dessen
/// Bindung nicht traegt, ist damit fuer die Frist so gut wie nicht vorhanden —
/// fail-closed.
struct QualifyingToken {
    covered_from_sequence: ChainSequence,
    covered_through_sequence: ChainSequence,
}

/// Faehrt Gate `evidence` ueber den ganzen Bestand.
///
/// `confirmed` sind die Paare aus Eintrag und Quittung, deren Quittung Gate
/// `receipt` BESTANDEN hat. Nur sie duerfen eine Frist behaupten: aus
/// unauthentischen Bytes stammen Zaehler und Fehlereintraege, niemals
/// Sachaussagen — und `evidence-due-at` ist eine Sachaussage des Servers.
pub(crate) fn run_evidence_gate(
    report: &mut VerificationReportV1,
    anchor: &TrustAnchorV1,
    inventory: &ArchiveInventory,
    options: VerifyOptions<'_>,
    confirmed: &[(&Parsed<EntryPackageV1>, &Parsed<ReceiptV1>)],
) {
    let mut qualifying: Vec<QualifyingToken> = Vec::new();
    for evidence in inventory.evidence() {
        // EIN ISOLIERTES OBJEKT WIRD NICHT BENUTZT und bekommt keinen zweiten
        // Befund: eine doppelt abgelegte `.ecp` bleibt im Inventar ihrer
        // Familie (`crates/ea-archive/src/inventory.rs:283-289`) und stuende
        // sonst zugleich in `quarantinedObjects` und in `evidenceErrors`. Sie
        // qualifiziert damit auch fuer keine Frist — fail-closed.
        if report
            .quarantined_objects
            .contains_key(&evidence.object_hash())
        {
            continue;
        }
        match token_finding(inventory, evidence) {
            Err(error) => {
                report
                    .evidence_errors
                    .insert(ObjectErrorV1::new(evidence.object_hash(), error.code()));
            }
            Ok(Some(token)) if covers_this_chain(anchor, evidence) => qualifying.push(token),
            Ok(_) => {}
        }
    }

    if options.evidence_requirement() == EvidenceRequirementV1::NotRequired {
        // Ohne Forderung ist eine Frist kein Mangel: ein Standardprofil-Receipt
        // erzeugt ohne separate Richtlinienaenderung gar keine
        // Evidence-Grade-Konformitaet (`design.md`:1699).
        return;
    }
    let effective_now = options.effective_now();
    for (entry, receipt) in confirmed {
        let Some(due_at) = receipt.value().core().fields().evidence_due_at else {
            continue;
        };
        // Auch hier: eine isolierte Quittung traegt keinen zweiten Befund.
        if report
            .quarantined_objects
            .contains_key(&receipt.object_hash())
        {
            continue;
        }
        let sequence = entry.value().manifest().fields().chain_sequence;
        if qualifying.iter().any(|token| {
            token.covered_from_sequence <= sequence && sequence <= token.covered_through_sequence
        }) {
            continue;
        }
        // DER BEFUND TRAEGT DIE QUITTUNG, nicht den Eintrag. Sie ist das
        // Objekt, das die Frist behauptet, und der Eintrag hat bereits ein
        // Ergebnis in `objectResults` — ein Objekt erscheint in genau einem
        // Feld.
        let error = if effective_now > due_at {
            EvidenceGateErrorV1::Overdue
        } else {
            EvidenceGateErrorV1::Missing
        };
        report
            .evidence_errors
            .insert(ObjectErrorV1::new(receipt.object_hash(), error.code()));
    }
}

/// Bezeugt dieses `.ecp` die Kette des Ankers?
///
/// Die Kettenkennung stammt AUSSCHLIESSLICH aus dem Anker, nie aus dem
/// Bestand — dieselbe Regel wie ueberall im Bericht.
fn covers_this_chain(anchor: &TrustAnchorV1, evidence: &Parsed<EvidenceObjectV1>) -> bool {
    match evidence.value().decoded_payload() {
        Ok(DecodedEvidencePayloadV1::Timestamp { core, .. }) => {
            core.fields().chain_id == anchor.chain_id()
        }
        _ => false,
    }
}

/// Prueft die erreichbaren Bindungen EINES Evidence-Objekts.
///
/// `Ok(None)` heisst: das Objekt traegt gar keine RFC-3161-Anteile (die
/// Standardvariante) und geht dieses Gate nichts an — es ist bereits in Gate
/// `receipt` behandelt.
fn token_finding(
    inventory: &ArchiveInventory,
    evidence: &Parsed<EvidenceObjectV1>,
) -> Result<Option<QualifyingToken>, EvidenceGateErrorV1> {
    match evidence.value().decoded_payload() {
        // Ein `.ecp`, das sich nicht dekodieren laesst, hat Gate `format` gar
        // nicht ueberlebt und liegt in `formatErrors`; dieser Zweig ist
        // unerreichbar und trotzdem fail-closed behandelt.
        Err(_) => Err(EvidenceGateErrorV1::TokenNotBound),
        Ok(DecodedEvidencePayloadV1::Standard { .. }) => Ok(None),
        Ok(DecodedEvidencePayloadV1::Timestamp {
            core,
            exact_cose,
            evidence: fields,
        }) => {
            token_is_bound(&exact_cose, &fields)?;
            Ok(Some(QualifyingToken {
                covered_from_sequence: core.fields().covered_from_sequence,
                covered_through_sequence: core.fields().covered_through_sequence,
            }))
        }
        Ok(DecodedEvidencePayloadV1::Renewal {
            core,
            exact_cose,
            evidence: fields,
        }) => {
            token_is_bound(&exact_cose, &fields)?;
            renewal_inputs_resolve(inventory, core.fields().renewal_input_hashes.as_slice())?;
            // Ein Renewal erneuert Evidence, bezeugt aber keine Sequenzspanne:
            // `renewal-core-v1` traegt den Kettenkopf, kein Intervall
            // (`design.md`:1713-1720). Es qualifiziert deshalb fuer KEINE Frist.
            Ok(None)
        }
    }
}

/// Ist die archivierte RFC-3161-Antwort genau die, die im COSE-Objekt steht?
///
/// Das ist die Bindung, die von hier aus erreichbar ist. Sie prueft nicht die
/// TSA und nicht den Imprint — siehe die Modulnotiz —, aber sie schliesst
/// aus, dass ein Bestand ein Token NEBEN einem Objekt ablegt, das ein anderes
/// bezeugt.
fn token_is_bound(
    exact_cose: &[u8],
    fields: &Rfc3161EvidenceFieldsV1,
) -> Result<(), EvidenceGateErrorV1> {
    let parsed =
        parse_cose_sign1(exact_cose, &[]).map_err(|_| EvidenceGateErrorV1::TokenNotBound)?;
    let bound = parsed
        .timestamp_token()
        .ok_or(EvidenceGateErrorV1::TokenNotBound)?;
    if bound != fields.rfc3161_response_der.as_slice() {
        return Err(EvidenceGateErrorV1::TokenNotBound);
    }
    // Der Imprint wird BERECHNET und damit als Wert festgehalten, aber gegen
    // nichts verglichen: das Token gibt seinen `messageImprint` von hier aus
    // nicht heraus. Der Aufruf steht hier trotzdem, weil er die einzige Stelle
    // ist, an der die Signatur, ueber die der Zeitstempel spricht, ueberhaupt
    // benannt wird — und weil die Stage-6-Pruefung genau ihn braucht.
    let _imprint = ea_crypto::cose_sign1_ctt_imprint(parsed.signature_bytes());
    Ok(())
}

/// Loesen sich alle `renewalInputHash` im Bestand auf?
///
/// Gerechnet wird ueber die EXAKTEN Objektbytes, wie `design.md`:1705-1711 es
/// vorschreibt, und mit `ea_crypto::renewal_input_digest` — die Domain wird
/// hier nicht nachgebaut.
fn renewal_inputs_resolve(
    inventory: &ArchiveInventory,
    inputs: &[ea_types::Hash32],
) -> Result<(), EvidenceGateErrorV1> {
    let mut known: Vec<ea_types::Hash32> = inventory
        .evidence()
        .iter()
        .map(|object| renewal_input_digest(object.exact_bytes().as_bytes()))
        .collect();
    // Binaere Suche statt Streuordnung: in dieser Crate kommt keine vor.
    known.sort_unstable();
    for input in inputs {
        if known.binary_search(input).is_err() {
            return Err(EvidenceGateErrorV1::RenewalInputUnknown);
        }
    }
    Ok(())
}
