//! `authorizedDestructions`: der Stand jedes Vernichtungsvorgangs aus seiner
//! Ereigniskette.
//!
//! DER ZUSTAND STAMMT AUSSCHLIESSLICH AUS DER TRANSITIONSKETTE, nie aus einem
//! Pfad und nie aus der blossen Anwesenheit einer Autorisierung. Klassifiziert
//! wird — wie ueberall im Bestand — am Exact-Object-Praefix und an den
//! GEPARSTEN Feldern; `destructions/<id>/{events,attestations}/` ist ein
//! Hinweis, kein Beweis.
//!
//! DIE AUTORISIERUNG WIRD HIER NICHT SELBST GEPRUEFT, und das ist keine
//! Luecke: `ea_crypto::VerificationContext::destruction_transition_trust_digest`
//! rechnet `object_hash` ueber die uebergebenen Autorisierungsbytes nach und
//! vergleicht ihn mit dem Feld der Transition
//! (`crates/ea-crypto/src/cose.rs:1093-1101`). Eine getragene Transition
//! authentifiziert damit genau den `authorizationObjectHash`, den der Bericht
//! ausweist — aus unauthentischen Bytes stammt hier also keine Sachaussage.
//! Die Vier-Augen-Signaturen der Autorisierung selbst gehoeren zur
//! Ausstellung, nicht zur Zustandsermittlung.
//!
//! WAS EIN WIDERSPRUCH IST UND WAS EIN SIGNATURBEFUND: eine Transition, deren
//! Signatur nicht traegt, ist ein `signatureErrors`-Eintrag und nimmt an der
//! Kettenauswertung GAR NICHT teil. Erst innerhalb der getragenen Ereignisse
//! kann es Widersprueche geben — unzulaessiger Uebergang, gebrochene oder
//! gegabelte Kette, zwei Ereignisse unter derselben `event_id` —, und die
//! werden zu `quarantinedObjects` mit Grund `conflicting`. Damit erscheint
//! jedes Objekt in genau einem Feld, und zwar durch Konstruktion statt durch
//! eine nachtraegliche Pruefung.
//!
//! DIE EINDEUTIGKEIT DER `event_id` GILT JE VORGANG, nicht bestandsweit:
//! `design.md` verbietet, denselben Schritt EINER Operation zweimal
//! auszufuehren. Zwei Vorgaenge mit eigener `destructionId` teilen sich keinen
//! Ereignisraum, und ihre Kennungen zu koppeln hiesse, zwischen unabhaengigen
//! Operationen einen Widerspruch zu erfinden.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use ea_archive::{ArchiveInventory, QuarantineReason};
use ea_crypto::{CryptoError, VerificationContext, parse_cose_sign1, verify_cose_sign1};
use ea_format::{
    DecodedTrustPayloadV1, DeletionAttestationFieldsV1, DestructionTransitionFieldsV1, Parsed,
    TrustObjectV1,
};
use ea_trust::SelectedRegistryHead;
use ea_types::{CertificateHash, ChainSequence, DestructionId, EventId, KeyThumbprint, ObjectHash};

use crate::{
    AuthorizedDestructionV1, DestructionStateV1, ObjectErrorV1, QuarantinedObjectV1,
    VerificationReportV1,
};

/// Der Befund ueber GENAU EIN Destruction-Objekt.
///
/// EIGENE FAMILIE `EA-VERIFY-DESTRUCTION-*`, aus demselben Grund wie bei
/// [`crate::ManifestSignatureErrorV1`]: der Code benennt die Stufe, an der der
/// Befund entstand, nicht bloss die kryptografische Ursache.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DestructionErrorV1 {
    /// Die Autorisierung, auf die sich das Objekt beruft, liegt nicht im
    /// Bestand.
    ///
    /// Ohne ihre Bytes laesst sich der Pruefkontext gar nicht bilden — die
    /// Bindung an `destructionId` und `authorizationObjectHash` steckt genau
    /// darin. Fail-closed: unpruefbar ist nicht dasselbe wie gueltig.
    AuthorizationUnresolved,
    /// Fuer die `authorizationSequence` liess sich kein Registrierungskopf mit
    /// Operationsautoritaet gewinnen.
    HeadUnavailable,
    /// Der Signaturwert traegt nicht.
    SignatureInvalid,
    /// Signierer und Objekt passen nicht zueinander.
    SignerMismatch,
    /// Das Zertifikat traegt hier keine `deletionAttest`-Autoritaet.
    SignerUnauthorized,
    /// Die Signatur liess sich nicht pruefen.
    ///
    /// AUFFANGFALL: [`CryptoError`] ist `#[non_exhaustive]`, eine neue Variante
    /// darf diese Abbildung nicht brechen.
    Unverifiable,
}

impl DestructionErrorV1 {
    /// Stabiler Fehlercode. Tests assertieren gegen ihn, nie gegen Formatierung.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AuthorizationUnresolved => "EA-VERIFY-DESTRUCTION-AUTHORIZATION-UNRESOLVED",
            Self::HeadUnavailable => "EA-VERIFY-DESTRUCTION-HEAD-UNAVAILABLE",
            Self::SignatureInvalid => "EA-VERIFY-DESTRUCTION-SIGNATURE-INVALID",
            Self::SignerMismatch => "EA-VERIFY-DESTRUCTION-SIGNER-MISMATCH",
            Self::SignerUnauthorized => "EA-VERIFY-DESTRUCTION-SIGNER-UNAUTHORIZED",
            Self::Unverifiable => "EA-VERIFY-DESTRUCTION-UNVERIFIABLE",
        }
    }
}

impl From<CryptoError> for DestructionErrorV1 {
    fn from(error: CryptoError) -> Self {
        match error {
            CryptoError::SignatureInvalid => Self::SignatureInvalid,
            CryptoError::SignerMismatch => Self::SignerMismatch,
            CryptoError::SignerUnauthorized | CryptoError::SignerUnresolved => {
                Self::SignerUnauthorized
            }
            _ => Self::Unverifiable,
        }
    }
}

impl fmt::Display for DestructionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl DestructionStateV1 {
    /// Der `destruction-state-v1`-Code, wie er auf dem Draht steht.
    ///
    /// Die Zuordnung ist im Wire-Format-Addendum gepinnt
    /// (`docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-wire-format-addendum.md`:335-336):
    /// 0 requested, 1 inProgress, 2 pendingBackupExpiry, 3
    /// completeManagedScope, 4 incompleteUnreachableReplica.
    const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Requested),
            1 => Some(Self::InProgress),
            2 => Some(Self::PendingBackupExpiry),
            3 => Some(Self::CompleteManagedScope),
            4 => Some(Self::IncompleteUnreachableReplica),
            _ => None,
        }
    }

    /// Der eigene `destruction-state-v1`-Code.
    ///
    /// AUSGESCHRIEBEN statt `as u8`: die Deklarationsreihenfolge des Enums ist
    /// die des Schemas, die Codes stammen aus dem Wire-Format. Dass beide
    /// heute uebereinstimmen, ist kein Grund, sie zu koppeln.
    const fn code(self) -> u8 {
        match self {
            Self::Requested => 0,
            Self::InProgress => 1,
            Self::PendingBackupExpiry => 2,
            Self::CompleteManagedScope => 3,
            Self::IncompleteUnreachableReplica => 4,
        }
    }

    /// Darf dieser Zustand in `next` uebergehen?
    ///
    /// Die Tabelle aus `design.md`:1826-1841, vollstaendig und geschlossen.
    /// NACH `InProgress` GIBT ES KEIN ABBRECHEN, und `CompleteManagedScope`
    /// ist der einzige erfolgreiche Endzustand: er hat gar keine ausgehende
    /// Kante.
    const fn may_advance_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Requested, Self::InProgress)
                | (
                    Self::InProgress,
                    Self::PendingBackupExpiry
                        | Self::CompleteManagedScope
                        | Self::IncompleteUnreachableReplica
                )
                | (
                    Self::PendingBackupExpiry,
                    Self::CompleteManagedScope | Self::IncompleteUnreachableReplica
                )
                | (Self::IncompleteUnreachableReplica, Self::InProgress)
        )
    }
}

/// Der Kontextbauer einer Destruction-Signatur.
///
/// GENAU ZWEI Werte kommen vor: `destruction_transition_trust_digest` und
/// `deletion_attestation_trust_digest`. Beide binden die Autorisierung
/// gleichermassen und unterscheiden sich in der Unterart, gegen die sie den
/// Digest pruefen — die Verwechslung waere ein stiller Autoritaetsverlust,
/// deshalb waehlt der Aufrufer sie und nicht eine Verzweigung im Innern.
type DestructionContextFn =
    fn(&[u8], &[u8], CertificateHash) -> Result<VerificationContext, CryptoError>;

/// Ein Ereignis, dessen Signatur GETRAGEN hat.
///
/// Nur solche Ereignisse erreichen die Kettenauswertung. Ein Ereignis mit
/// Signaturbefund ist bereits abgelegt und taucht hier nicht mehr auf.
struct VerifiedEvent {
    object_hash: ObjectHash,
    fields: DestructionTransitionFieldsV1,
}

/// Traegt `authorizedDestructions`, `quarantinedObjects`, `signatureErrors`
/// und `publicKeyThumbprints` fuer alle Vernichtungsvorgaenge des Bestands ein.
///
/// `head_for` liefert den Registrierungskopf ueber einer Sequenz. Die
/// Zustandsermittlung bleibt damit frei von Trust-Zustandsspeicher, Anker und
/// Uhr — genau wie `ea-chain` frei von CBOR ist.
///
/// GEPRUEFT WIRD NACH AUFSTEIGENDER `authorizationSequence`, nicht in
/// Inventarreihenfolge — und das ist gemessen, nicht vermutet
/// (`tests/destructions.rs::two_leases_are_pinned_in_sequence_order_not_in_object_hash_order`).
/// Die Inventarreihenfolge folgt dem Objekthash, `head_for` zieht die
/// Registrierungslinie aber nur VORWAERTS nach: ein einmal gepinnter Kopf geht
/// nie zurueck. Liefe die Schleife nach Hash, entschiede der Zufall der
/// Hashwerte darueber, welcher Vorgang noch in der Lease seines Kopfes liegt —
/// dieselbe Falle, die die Eintragsschleife in `archive.rs` mit derselben
/// Sortierung meidet. Der Objekthash bleibt zweites Ordnungsmerkmal, damit die
/// Reihenfolge auch bei gleicher Sequenz total und damit reproduzierbar ist.
pub(crate) fn record_destructions(
    report: &mut VerificationReportV1,
    inventory: &ArchiveInventory,
    mut head_for: impl FnMut(ChainSequence) -> Option<SelectedRegistryHead>,
) {
    let authorizations = authorizations(inventory);
    let mut ordered: Vec<DestructionObject<'_>> = Vec::new();
    for trust in inventory.trust() {
        let Ok(payload) = trust.value().decoded_payload() else {
            continue;
        };
        let kind = match payload {
            DecodedTrustPayloadV1::DestructionTransition(fields) => {
                DestructionObjectKind::Transition(fields)
            }
            DecodedTrustPayloadV1::DeletionAttestation(fields) => {
                DestructionObjectKind::Attestation(fields)
            }
            _ => continue,
        };
        // OHNE AUTORISIERUNG GAR KEINE KOPFABFRAGE: das Objekt hat keine
        // Sequenz, gegen die ein Kopf zu waehlen waere, und darf die
        // Registrierungslinie deshalb auch nicht anfassen. Fail-closed und
        // ordnungsfrei.
        let Some(authorization) = authorizations.get(&kind.authorization_object_hash()) else {
            record_signature_error(
                report,
                trust.object_hash(),
                DestructionErrorV1::AuthorizationUnresolved,
            );
            continue;
        };
        ordered.push(DestructionObject {
            authorization: *authorization,
            object_hash: trust.object_hash(),
            trust,
            kind,
        });
    }
    ordered.sort_by_key(|object| (object.authorization.sequence, object.object_hash));

    let mut events: BTreeMap<DestructionId, Vec<VerifiedEvent>> = BTreeMap::new();
    for object in ordered {
        let verified = verify_destruction_object(
            object.trust,
            object.authorization,
            &mut head_for,
            object.kind.context_builder(),
        );
        match verified {
            Ok(thumbprint) => {
                report.public_key_thumbprints.insert(thumbprint);
                // EINE ATTESTIERUNG VERSCHIEBT KEINEN ZUSTAND. Sie ist der
                // Beleg EINER Replik; der Stand des Vorgangs steht in der
                // Kette. Ihr Beitrag zum Bericht ist deshalb genau einer: der
                // Abdruck des Loeschzeugen, der sie getragen hat.
                if let DestructionObjectKind::Transition(fields) = object.kind {
                    events
                        .entry(fields.destruction_id)
                        .or_default()
                        .push(VerifiedEvent {
                            object_hash: object.object_hash,
                            fields,
                        });
                }
            }
            Err(error) => record_signature_error(report, object.object_hash, error),
        }
    }

    for (destruction_id, group) in events {
        if let Some(entry) = assess_destruction(report, destruction_id, group) {
            report.authorized_destructions.insert(destruction_id, entry);
        }
    }
}

/// Ein Destruction-Objekt mit aufgeloester Autorisierung, bereit zur Pruefung.
struct DestructionObject<'a> {
    authorization: Authorization<'a>,
    object_hash: ObjectHash,
    trust: &'a Parsed<TrustObjectV1>,
    kind: DestructionObjectKind,
}

/// Die beiden Unterarten, die eine `deletionAttest`-Signatur tragen.
enum DestructionObjectKind {
    /// Ein Zustandsereignis. Nur diese bilden die Kette.
    Transition(DestructionTransitionFieldsV1),
    /// Der Loeschbeleg EINER Replik.
    Attestation(DeletionAttestationFieldsV1),
}

impl DestructionObjectKind {
    const fn authorization_object_hash(&self) -> ObjectHash {
        match self {
            Self::Transition(fields) => fields.destruction_authorization_object_hash,
            Self::Attestation(fields) => fields.destruction_authorization_object_hash,
        }
    }

    /// Der Kontextbauer der Unterart.
    ///
    /// Die Verwechslung waere ein stiller Autoritaetsverlust: beide Kontexte
    /// binden dieselbe Autorisierung, pruefen den Digest aber gegen
    /// VERSCHIEDENE Unterartkennungen. Deshalb entscheidet die Unterart und
    /// nicht eine Verzweigung in der Pruefung.
    const fn context_builder(&self) -> DestructionContextFn {
        match self {
            Self::Transition(_) => VerificationContext::destruction_transition_trust_digest,
            Self::Attestation(_) => VerificationContext::deletion_attestation_trust_digest,
        }
    }
}

/// Jede Vernichtungsautorisierung des Bestands: ihre exakten Objektbytes und
/// ihre `authorizationSequence`.
///
/// DIE BYTES VOLLSTAENDIG, weil der Pruefkontext `object_hash` darueber
/// nachrechnet — ein blosser Verweis genuegte nicht. Die Sequenz DANEBEN, weil
/// sie sonst je Transition erneut aus denselben Bytes dekodiert wuerde.
fn authorizations(inventory: &ArchiveInventory) -> BTreeMap<ObjectHash, Authorization<'_>> {
    inventory
        .trust()
        .iter()
        .filter_map(|trust| match trust.value().decoded_payload() {
            Ok(DecodedTrustPayloadV1::DestructionAuthorization(fields)) => Some((
                trust.object_hash(),
                Authorization {
                    exact_bytes: trust.exact_bytes().as_bytes(),
                    sequence: ChainSequence::new(fields.authorization_sequence),
                },
            )),
            _ => None,
        })
        .collect()
}

/// Eine Vernichtungsautorisierung, so wie die Signaturpruefung sie braucht.
#[derive(Clone, Copy)]
struct Authorization<'a> {
    exact_bytes: &'a [u8],
    /// Die Sequenz, gegen die `verify_cose_sign1` das Zertifikat auf
    /// Wirksamkeit prueft.
    ///
    /// SIE STAMMT AUS DER AUTORISIERUNG und nicht aus dem Transitionsobjekt:
    /// `destruction_transition_trust_digest` zieht `expected_sequence`,
    /// `registry` und `organization_id` samt und sonders von hier
    /// (`crates/ea-crypto/src/cose.rs:1069-1090`). Der Registrierungskopf muss
    /// deshalb ueber genau dieser Sequenz gewaehlt werden.
    sequence: ChainSequence,
}

/// Prueft die EINE Signatur eines Destruction-Objekts gegen den Kopf ueber der
/// `authorizationSequence`.
///
/// Der Zertifikatshash kommt aus dem geschuetzten Header der Signatur und wird
/// nicht geraten: `verify_cose_sign1` loest genau ihn auf und verlangt
/// anschliessend Rolle und Faehigkeit `deletionAttest`
/// (`crates/ea-crypto/src/cose.rs:1423-1457`). Ihn dem Header zu entnehmen ist
/// deshalb kein Zirkel — er benennt nur, WELCHES Zertifikat sich der Signierer
/// zuschreibt, und die Autoritaet dieses Zertifikats entscheidet die Pruefung.
fn verify_destruction_object(
    trust: &Parsed<TrustObjectV1>,
    authorization: Authorization<'_>,
    head_for: &mut impl FnMut(ChainSequence) -> Option<SelectedRegistryHead>,
    context_for: DestructionContextFn,
) -> Result<KeyThumbprint, DestructionErrorV1> {
    let signature = trust
        .value()
        .signatures()
        .first()
        .ok_or(DestructionErrorV1::SignerMismatch)?;
    let certificate_hash = parse_cose_sign1(signature, &[])
        .map_err(DestructionErrorV1::from)?
        .certificate_hash()
        .ok_or(DestructionErrorV1::SignerMismatch)?;
    let context = context_for(
        trust.value().exact_digest_input(),
        authorization.exact_bytes,
        certificate_hash,
    )
    .map_err(DestructionErrorV1::from)?;
    let selected = head_for(authorization.sequence).ok_or(DestructionErrorV1::HeadUnavailable)?;
    let signer =
        verify_cose_sign1(signature, &selected, &context).map_err(DestructionErrorV1::from)?;
    Ok(signer.key_thumbprint())
}

/// Legt einen Signaturbefund ueber `object_hash` ab.
fn record_signature_error(
    report: &mut VerificationReportV1,
    object_hash: ObjectHash,
    error: DestructionErrorV1,
) {
    report
        .signature_errors
        .insert(ObjectErrorV1::new(object_hash, error.code()));
}

/// Legt `object_hash` als widerspruechlich ab.
fn record_conflicting(report: &mut VerificationReportV1, object_hash: ObjectHash) {
    report.quarantined_objects.insert(
        object_hash,
        QuarantinedObjectV1::new(object_hash, QuarantineReason::Conflicting),
    );
}

/// Wertet die getragenen Ereignisse EINES Vorgangs aus.
///
/// Vier Schritte, in dieser Reihenfolge:
///
/// 1. Zwei Ereignisse unter derselben `event_id` bestreiten einander. Welches
///    das echte ist, ist gerade nicht entscheidbar — also sind BEIDE
///    widerspruechlich und keines nimmt an der Kette teil.
/// 2. Die Wurzel ist das Ereignis ohne Vorgaenger. Sie MUSS `from_state`
///    abwesend und `to_state = requested` tragen; gibt es keine oder mehrere,
///    gibt es keinen Zustand.
/// 3. Die Kette wird VORWAERTS ueber `previous_event_object_hash` gelaufen. Zwei
///    Nachfolger sind eine Gabelung, ein unzulaessiger Uebergang ein
///    Widerspruch; in beiden Faellen endet der Lauf und der Vorgang behaelt den
///    letzten unstrittigen Zustand.
/// 4. Was die Kette nie erreicht hat, ist ein gebrochenes Glied und damit
///    ebenfalls widerspruechlich.
///
/// ZUSTAENDE WIEDERHOLEN SICH ZULAESSIG: `incompleteUnreachableReplica ->
/// inProgress` ist erlaubt. Deshalb wird ueber OBJEKTHASHES gelaufen und nicht
/// ueber besuchte Zustaende — ein Zyklus in den Zustaenden ist kein Zyklus in
/// der Kette.
fn assess_destruction(
    report: &mut VerificationReportV1,
    destruction_id: DestructionId,
    group: Vec<VerifiedEvent>,
) -> Option<AuthorizedDestructionV1> {
    let mut pending: BTreeMap<ObjectHash, VerifiedEvent> = BTreeMap::new();
    for event in contested_event_ids(report, group) {
        pending.insert(event.object_hash, event);
    }

    let roots: Vec<ObjectHash> = pending
        .values()
        .filter(|event| event.fields.previous_event_object_hash.is_none())
        .map(|event| event.object_hash)
        .collect();
    let [root] = roots.as_slice() else {
        // Keine Wurzel: die Kette ist gebrochen. Mehrere Wurzeln: sie ist
        // gegabelt. Beides ist kein Zustand, und beides isoliert JEDES
        // beteiligte Objekt — bei einer Gabelung ist gerade nicht
        // entscheidbar, welche Seite die echte ist.
        for object_hash in pending.keys() {
            record_conflicting(report, *object_hash);
        }
        return None;
    };
    let root = *root;

    let mut current = pending
        .remove(&root)
        .expect("die Wurzel stammt aus derselben Abbildung");
    if current.fields.from_state.is_some()
        || DestructionStateV1::from_code(current.fields.to_state)
            != Some(DestructionStateV1::Requested)
    {
        // EINE WURZEL OHNE VORGAENGER IST IMMER `requested`. Ein Ereignis, das
        // ohne Vorgaenger einen anderen Zustand behauptet, ist kein frischer
        // Anfang, sondern eine Behauptung ueber eine Kette, die es nicht zeigt.
        record_conflicting(report, current.object_hash);
        for object_hash in pending.keys() {
            record_conflicting(report, *object_hash);
        }
        return None;
    }

    let authorization_object_hash = current.fields.destruction_authorization_object_hash;
    let mut state = DestructionStateV1::Requested;
    loop {
        let successors: Vec<ObjectHash> = pending
            .values()
            .filter(|event| event.fields.previous_event_object_hash == Some(current.object_hash))
            .map(|event| event.object_hash)
            .collect();
        let [successor] = successors.as_slice() else {
            if !successors.is_empty() {
                for object_hash in &successors {
                    record_conflicting(report, *object_hash);
                    pending.remove(object_hash);
                }
            }
            break;
        };
        let next = pending
            .remove(successor)
            .expect("der Nachfolger stammt aus derselben Abbildung");
        let advanced = DestructionStateV1::from_code(next.fields.to_state).filter(|to| {
            next.fields.from_state == Some(state.code())
                && next.fields.destruction_authorization_object_hash == authorization_object_hash
                && state.may_advance_to(*to)
        });
        let Some(next_state) = advanced else {
            record_conflicting(report, next.object_hash);
            break;
        };
        state = next_state;
        current = next;
    }

    // Was die Kette nie erreicht hat, haengt an einem Vorgaenger, den es in
    // dieser Kette nicht gibt: ein gebrochenes Glied.
    for object_hash in pending.keys() {
        record_conflicting(report, *object_hash);
    }

    Some(AuthorizedDestructionV1::new(
        destruction_id,
        authorization_object_hash,
        state,
    ))
}

/// Sondert Ereignisse aus, die sich eine `event_id` teilen.
///
/// `design.md` verbietet, denselben Schritt zweimal auszufuehren oder ein bloss
/// erneut gesendetes Ereignis als neue Operation zu werten. Zwei VERSCHIEDENE
/// Objekte unter derselben Kennung sind deshalb kein stiller Zustandswechsel,
/// sondern ein Widerspruch — und zwar fuer beide.
fn contested_event_ids(
    report: &mut VerificationReportV1,
    group: Vec<VerifiedEvent>,
) -> Vec<VerifiedEvent> {
    let mut seen: BTreeMap<EventId, usize> = BTreeMap::new();
    for event in &group {
        *seen.entry(event.fields.event_id).or_default() += 1;
    }
    let contested: BTreeSet<EventId> = seen
        .into_iter()
        .filter(|(_, count)| *count > 1)
        .map(|(event_id, _)| event_id)
        .collect();
    group
        .into_iter()
        .filter(|event| {
            if contested.contains(&event.fields.event_id) {
                record_conflicting(report, event.object_hash);
                return false;
            }
            true
        })
        .collect()
}
