//! Der Einstiegspunkt der Verifikation: [`verify_archive`].
//!
//! DIESE FASSUNG fuehrt ALLE NEUN Gates aus `design.md` §14.1 und danach die
//! Entkapselung, die kein Gate ist. Erst wenn die Strecke vollstaendig
//! durchgelaufen ist, wird `pipeline_completed` gesetzt — ein Lauf, der an Gate
//! `trust` fail-closed endet, erreicht diese Zeile nie und gilt ausdruecklich
//! NICHT als vollstaendig verifiziert.
//!
//! DER ABBRUCH IST ARCHIVWEIT NUR EINER. `run_gates` bricht je Objekt beim
//! ersten fallenden Gate ab; diese Pipeline tut das ausdruecklich nicht, denn
//! ein Befund ueber EIN Objekt darf die Aussage ueber die uebrigen nicht
//! kippen. Sie faehrt deshalb alle Stufen und traegt Befunde je Objekt ein —
//! mit der einen Ausnahme Gate `trust`, dessen Fehlschlag den ganzen Bestand
//! trifft.
//!
//! GATE `receipt` UMFASST QUITTUNG UND CHECKPOINT. `design.md` §14.1 Schritt 7
//! (:1598) nennt „Server-Receipt und Checkpoints, sofern vorhanden"; Schritt 8
//! ist auf Evidence-Objekte und Zeitstempel begrenzt. Die Verwechslung liegt
//! nahe, weil beide Objektarten in `crates/ea-format/src/ecp.rs` wohnen —
//! deshalb steht die Abgrenzung hier ausgeschrieben und nicht bloss im Kopf.

use core::fmt;

use ea_archive::{ArchiveInventory, ArchiveSource, QuarantineReason};
use ea_chain::{
    ChainNode, CheckpointClaim, RollbackAssessment, RollbackFinding, VerifiedChain,
    assess_rollback, build_chain,
};
use ea_crypto::{HpkeRecipient, VerificationContext, parse_cose_sign1, verify_cose_sign1};
use ea_format::{CertificateKindV1, EntryPackageV1, Parsed, ReceiptV1};
use ea_trust::{TrustAnchorV1, TrustStateKey};
use ea_types::{CertificateHash, KeyThumbprint, ObjectHash, UnixMillis};

use crate::{
    ChainGapV1, ChainHeadV1, Decapsulation, EphemeralTrustStateStore, Gate, GateObserver,
    ManifestSignatureErrorV1, ObjectErrorV1, ObjectResultKindV1, ObjectResultV1, ObjectTypeV1,
    QuarantinedObjectV1, ReceiptGateErrorV1, RecipientGrantErrorV1, ServerConfirmationV1,
    SilentObserver, VerificationReportV1, VerifyError,
    destruction::record_destructions,
    entry::{
        entry_chain_node, grant_plan_finding, orphan_grants, receipt_bindings_hold, receipt_for,
        standard_checkpoint_claim, writer_transition_claim_holds,
    },
    evidence::run_evidence_gate,
    gates::StageProtocol,
    recipient::{open_entry, own_grant, record_decapsulation, verify_own_grant},
    state::verification_state_key,
};

/// Die Stellschrauben eines Verifikationslaufs.
///
/// DIE UHR IST PFLICHT und ausdruecklich KEIN `Option`: sie laesst sich aus dem
/// Bestand nicht herleiten. `ea_trust::VerifiedSignedTime` gibt keinen Rohwert
/// heraus (`crates/ea-trust/src/time.rs:19-32`), `prepare_local_time` verwirft
/// jede Zeitquelle, solange kein Kopf gepinnt ist
/// (`crates/ea-trust/src/time.rs:110-114`), und `verify_receipt_time` verlangt
/// eine `PreexistingRegistryAuthority`, die vor dem ersten Pin gar nicht
/// existiert (`crates/ea-trust/src/registry.rs:484`). Ohne uebergebene Uhr kann
/// diese Crate deshalb keinen Registrierungskopf auswaehlen.
///
/// Aus demselben Grund gibt es BEWUSST kein `Default`: ein Vorgabewert waere
/// entweder eine erfundene Zeit oder eine Uhrabfrage — und `SystemTime::now`
/// gehoert nicht in diese Crate.
///
/// Der Lebenszeitparameter traegt die geliehenen Stellschrauben — seit diesem
/// Stand den Empfaengerschluessel.
#[derive(Clone, Copy)]
pub struct VerifyOptions<'a> {
    os_wall_clock: UnixMillis,
    recipient: Option<RecipientKeyV1<'a>>,
    recipient_time_ceiling: Option<UnixMillis>,
    evidence_requirement: EvidenceRequirementV1,
}

impl<'a> VerifyOptions<'a> {
    /// Ein Lauf gegen die uebergebene Betriebssystemuhr.
    ///
    /// OHNE Empfaengerschluessel und OHNE Evidence-Forderung: beides ist eine
    /// Zusatzaussage des Aufrufers, und ein Vorgabewert waere hier eine
    /// Erfindung. Ohne Schluessel wird nichts entschluesselt — was ausdruecklich
    /// KEIN Mangel ist.
    #[must_use]
    pub const fn new(os_wall_clock: UnixMillis) -> Self {
        Self {
            os_wall_clock,
            recipient: None,
            recipient_time_ceiling: None,
            evidence_requirement: EvidenceRequirementV1::NotRequired,
        }
    }

    /// Derselbe Lauf mit dem eigenen Empfaengerschluessel.
    ///
    /// ZWEI TEILE, und das ist keine Bequemlichkeit: `key_thumbprint` benennt,
    /// WER der Aufrufer laut Registrierung ist — daran erkennt Gate
    /// `recipient-grant` den eigenen Grant —, `private_key` ist das Material,
    /// mit dem die Entkapselung dahinter tatsaechlich rechnet. Beide koennen
    /// auseinanderfallen (ein falsch verdrahteter Schluesselspeicher), und
    /// genau dieser Fall MUSS als Entschluesselungsfehler sichtbar werden
    /// statt als fehlender Grant.
    #[must_use]
    pub const fn with_recipient(
        mut self,
        key_thumbprint: KeyThumbprint,
        private_key: &'a dyn HpkeRecipient,
    ) -> Self {
        self.recipient = Some(RecipientKeyV1 {
            key_thumbprint,
            private_key,
        });
        self
    }

    /// Bound historical recipient use to the host's successfully persisted
    /// time. Rechecked against this run's authenticated Receipt/Checkpoint
    /// floor before any HPKE, including if the source changed after preflight.
    #[must_use]
    pub const fn with_recipient_time_ceiling(mut self, ceiling: UnixMillis) -> Self {
        self.recipient_time_ceiling = Some(ceiling);
        self
    }

    /// Derselbe Lauf mit einer Evidence-Forderung.
    #[must_use]
    pub const fn with_evidence_requirement(mut self, requirement: EvidenceRequirementV1) -> Self {
        self.evidence_requirement = requirement;
        self
    }

    /// Die uebergebene Betriebssystemuhr. Roher Vergleichswert, kein Nachweis.
    #[must_use]
    pub const fn os_wall_clock(&self) -> UnixMillis {
        self.os_wall_clock
    }

    /// Der Zeitwert, gegen den Fristen dieses Laufs gemessen werden.
    ///
    /// GLEICH der uebergebenen Uhr, und das ist der einzige erreichbare Wert:
    /// `ea_trust::VerifiedSignedTime` gibt keinen Rohwert heraus
    /// (`crates/ea-trust/src/time.rs:19-32`), und `select_registry_head` misst
    /// seinerseits genau diese Uhr gegen `not-before`/`not-after` des Kopfes.
    /// Ein Kopf, der ueberhaupt gewaehlt wurde, hat diese Uhr also bereits
    /// passieren lassen — die Frist eines Grants haengt damit an derselben
    /// Groesse wie seine Registrierungsautoritaet.
    #[must_use]
    pub const fn effective_now(&self) -> UnixMillis {
        self.os_wall_clock
    }

    /// Der eigene Empfaengerschluessel, sofern einer vorliegt.
    #[must_use]
    pub const fn recipient(&self) -> Option<RecipientKeyV1<'a>> {
        self.recipient
    }

    /// Ob dieser Lauf Evidence fordert.
    #[must_use]
    pub const fn evidence_requirement(&self) -> EvidenceRequirementV1 {
        self.evidence_requirement
    }
}

impl fmt::Debug for VerifyOptions<'_> {
    /// Gibt NIE Schluesselmaterial aus, nur ob eines vorliegt.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifyOptions")
            .field("os_wall_clock", &self.os_wall_clock.get())
            .field("recipient", &self.recipient)
            .field("evidence_requirement", &self.evidence_requirement)
            .finish()
    }
}

/// Der eigene Empfaenger: seine Kennung und sein Schluessel.
#[derive(Clone, Copy)]
pub struct RecipientKeyV1<'a> {
    key_thumbprint: KeyThumbprint,
    private_key: &'a dyn HpkeRecipient,
}

impl<'a> RecipientKeyV1<'a> {
    /// Der Abdruck, unter dem ein Grant diesen Empfaenger benennt.
    #[must_use]
    pub const fn key_thumbprint(&self) -> KeyThumbprint {
        self.key_thumbprint
    }

    /// Das Schluesselmaterial der Entkapselung.
    #[must_use]
    pub const fn private_key(&self) -> &'a dyn HpkeRecipient {
        self.private_key
    }
}

impl fmt::Debug for RecipientKeyV1<'_> {
    /// Der Abdruck ist oeffentlich, der Schluessel nie.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecipientKeyV1 { key_thumbprint: ")?;
        for byte in self.key_thumbprint.as_bytes() {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(", private_key: <secret> }")
    }
}

/// Ob dieser Lauf Evidence fordert.
///
/// `NotRequired` ist der Standardprofilfall: ein Receipt ohne
/// `evidence-due-at` erzeugt ohne separate Richtlinienaenderung gar keine
/// Evidence-Grade-Konformitaet (`design.md`:1699), und wo nichts gefordert
/// ist, ist auch nichts ueberfaellig.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EvidenceRequirementV1 {
    /// Fehlende Evidence ist kein Mangel.
    #[default]
    NotRequired,
    /// Zu jeder Frist muss qualifizierende Evidence vorliegen.
    Required,
}

/// Verifiziert einen Bestand und liefert den Bericht darueber.
///
/// Der Trust Anchor kommt als PARAMETER und nie aus dem Bestand
/// (`design.md` §11.4); daraus stammt insbesondere die Kettenkennung des
/// Berichts, sodass kein untergeschobenes Objekt sie bestimmen kann.
///
/// Ein Befund ueber ein einzelnes Objekt ist NIE ein `Err`: unlesbare, doppelte,
/// widerspruechliche und unzuordenbare Objekte stehen als `formatErrors` und
/// `quarantinedObjects` im Bericht, und der Lauf liefert `Ok`.
///
/// Auch ein Fehlschlag von Gate `trust` liefert `Ok`: er ist FAIL-CLOSED fuer
/// den gesamten Bestand — ohne Vertrauenskette gibt es keine Objektaussage,
/// `objectResults` und `registryVersions` bleiben leer —, aber der Bericht
/// bleibt lesbar, damit die Diagnose sichtbar ist. Ein eigenes Fehlerfeld
/// bekommt dieser Fall NICHT: das Berichtsschema ist geschlossen, und alle
/// Fehlerarrays sind nach `objectHash` geschluesselt. Ein Vertrauensmangel ist
/// aber kein Befund ueber ein einzelnes Objekt; ihm einen Objekthash zu
/// erfinden hiesse, eine Objektidentitaet zu behaupten, die es nicht gibt.
/// Sichtbar wird er stattdessen daran, dass ueber keinen Eintrag etwas
/// ausgesagt wird und [`VerificationReportV1::is_fully_verified`] falsch ist.
///
/// # Errors
///
/// [`VerifyError::Archive`], wenn der Bestand sich nicht vollstaendig
/// durchlaufen laesst, und [`VerifyError::NonCanonicalReport`], wenn der
/// Berichtsschreiber eine Zeichenkette ausser der Reihe vorfindet.
pub fn verify_archive(
    source: &dyn ArchiveSource,
    anchor: &TrustAnchorV1,
    options: VerifyOptions<'_>,
) -> Result<VerificationReportV1, VerifyError> {
    verify_archive_observed(source, anchor, options, &mut SilentObserver)
}

/// Wie [`verify_archive`], meldet aber jede betretene Gate-Stufe an `observer`.
///
/// Das Protokoll ist stets ein PRAEFIX von [`crate::GATE_ORDER_V1`], gefolgt
/// von hoechstens einem [`crate::DECAPSULATION_EVENT_V1`]. Gemeldet wird der
/// Eintritt in eine STUFE der archivweiten Pipeline und nicht der Eintritt je
/// Objekt — die Begruendung steht an [`crate::gates::StageProtocol`].
///
/// # Errors
///
/// Wie [`verify_archive`].
pub fn verify_archive_observed(
    source: &dyn ArchiveSource,
    anchor: &TrustAnchorV1,
    options: VerifyOptions<'_>,
    observer: &mut dyn GateObserver,
) -> Result<VerificationReportV1, VerifyError> {
    let mut protocol = StageProtocol::new(observer);

    // Gate `format`: das Inventar klassifiziert am 9-Byte-Exact-Object-Praefix
    // und parst jede Bytesequenz mit Praefix. Ein Fehlschlag erzeugt PAARWEISE
    // einen `formatError` und einen Quarantaeneeintrag `malformed`.
    protocol.enter(Gate::Format);
    let inventory = ArchiveInventory::build(source)?;

    let mut report = VerificationReportV1::empty(ChainHeadV1::sentinel(anchor.chain_id()));
    report.archive_object_count = inventory.archive_object_count();
    report.non_object_file_count = inventory.non_object_file_count();
    report.entry_package_count = inventory.entries().len();
    report.destroyed_entry_count = inventory.destroyed().len();
    for entry in inventory.format_errors() {
        report.format_errors.insert(
            entry.object_hash(),
            ObjectErrorV1::new(entry.object_hash(), entry.code()),
        );
    }
    for entry in inventory.quarantined() {
        report.quarantined_objects.insert(
            entry.object_hash(),
            QuarantinedObjectV1::new(entry.object_hash(), entry.reason()),
        );
    }

    let key = verification_state_key(anchor.organization_id());
    let mut store = EphemeralTrustStateStore::new(key, options.os_wall_clock());

    // Gate `trust`: einmal fuer den ganzen Bestand — die Vertrauenskette UND
    // jedes Objekt der drei Escrow-Familien (`trust_gate`). Traegt es nicht,
    // endet der Lauf hier — ohne Vertrauenskette laesst sich ueber kein Objekt
    // etwas sagen.
    protocol.enter(Gate::Trust);
    if crate::trust_gate::verified_trust(&mut store, key, anchor, &inventory).is_none() {
        return report.seal();
    }
    // ERST HINTER DEM FAIL-CLOSED-AUSSTIEG, nie davor: `publicKeyThumbprints`
    // ist Nachweis des GEPRUEFTEN. Ein Lauf, dessen Vertrauenskette nicht
    // traegt, hat nichts geprueft und laesst das Feld leer.
    //
    // Eingetragen wird `anchor.root_key_thumbprint()` — die Wurzel, GEGEN die
    // `verify_trust` die Linie geprueft hat, und der einzige Abdruck, den diese
    // Crate dafuer erreichen kann: `VerifiedTrust` gibt die angenommene
    // Wurzellinie nicht heraus. Nach einer Wurzelrotation signieren spaetere
    // Koepfe unter einer nachgezogenen Wurzel; deren Abdruck steht hier
    // ausdruecklich NICHT, weil er nicht der Vertrauensboden dieses Laufs ist.
    report
        .public_key_thumbprints
        .insert(anchor.root_key_thumbprint());

    // Gate `registry`: je Eintragssequenz einzeln. Ein Eintrag, dessen Sequenz
    // keinen Kopf mit Operationsautoritaet findet, bekommt keine Aussage; ein
    // Eintrag, dessen Schreiberzertifikat sich nicht aufloest, wird isoliert.
    //
    // Stable sequence order keeps chain findings deterministic. Each archived
    // signature uses its exact signed historical head; current action pins do
    // not replace or expire that historical attribution.
    let mut ordered: Vec<&Parsed<EntryPackageV1>> = inventory.entries().iter().collect();
    ordered.sort_by_key(|entry| {
        (
            entry.value().manifest().fields().chain_sequence,
            entry.object_hash(),
        )
    });
    // Die Knotenmenge von Gate `chain-position` und die Objekte, die Gate
    // `grant-plan` ueberhaupt erreichen. Beides entsteht in DIESER Schleife,
    // wird aber erst NACH ihr verbraucht: eine Kette ist erst zu beurteilen,
    // wenn alle ihre Knoten vorliegen.
    let mut nodes: Vec<ChainNode> = Vec::new();
    let mut placed: Vec<&Parsed<EntryPackageV1>> = Vec::new();
    // BEIDE Stufen laufen in DIESER Schleife, je Eintrag erst der Kopf, dann
    // die Signatur. Das Protokoll meldet den Eintritt in die Stufe, nicht den
    // Eintritt je Objekt.
    protocol.enter(Gate::Registry);
    protocol.enter(Gate::ManifestSignature);
    for entry in ordered {
        let object_hash = entry.object_hash();
        // Ein bereits isoliertes Objekt geht nicht weiter durch die Gates: es
        // erscheint ENTWEDER in `objectResults` ODER in genau einem
        // Fehler-/Quarantaenearray, niemals in beidem.
        if report.quarantined_objects.contains_key(&object_hash) {
            continue;
        }
        let fields = entry.value().manifest().fields();
        let Some(selected) = crate::historical::historical_registry_head(
            &inventory,
            anchor,
            fields.registry_version,
            ObjectHash::try_from(fields.registry_head_hash.as_slice()).expect("fixed hash"),
            fields.chain_sequence,
            options.os_wall_clock(),
        ) else {
            quarantine_unattributable(&mut report, object_hash);
            continue;
        };
        if !writer_is_active(&selected, fields.writer_certificate_hash) {
            quarantine_unattributable(&mut report, object_hash);
            continue;
        }

        // Gate `manifest-signature`: erst hier werden die Manifestbytes
        // AUTHENTISCH. Vorher sind sie blosse Bytes, und aus unauthentischen
        // Bytes stammen nur Zaehler und Fehlereintraege, niemals Sachaussagen —
        // deshalb wird `registry_version` NACH und nicht VOR dieser Pruefung
        // eingetragen.
        match verified_signer(entry, &selected) {
            Ok(thumbprint) => {
                report.registry_versions.insert(fields.registry_version);
                report.public_key_thumbprints.insert(thumbprint);

                // Ein Eintrag mit FREMDER Kettenkennung kommt gar nicht erst in
                // die Knotenmenge: `build_chain` beantwortete ihn mit
                // `ForeignChainId` und kippte damit die Aussage ueber den
                // GANZEN Bestand. Er ist nicht zuordenbar — und ein nicht
                // zuordenbarer Eintrag darf nie als blosse Luecke erscheinen.
                //
                // DASSELBE fuer einen Schreiberwechsel, der nicht traegt
                // (`design.md`:669: fehlend, zusaetzlich oder unpassend ist
                // ein Trust-Fehler des Objekts). Die Regel wird HIER
                // gerechnet und nirgends sonst: dies ist die eine Stelle, an
                // der der fuer die Sequenz gewaehlte Kopf — und damit der auf
                // ihm wirksame Uebergang — neben dem authentischen Manifest
                // steht. Ein Befund ist ein Befund ueber EIN Objekt, nie ein
                // `Err` des Laufs, und er heisst `unattributable`: der
                // Eintrag behauptet einen Wechsel, den die Linie so nicht
                // vollzogen hat, und ist damit niemandem zurechenbar — genau
                // wie ein Eintrag, dessen Schreiber sich nicht aufloest.
                if fields.chain_id != anchor.chain_id()
                    || !writer_transition_claim_holds(entry, &selected)
                {
                    quarantine_unattributable(&mut report, object_hash);
                    continue;
                }
                nodes.push(entry_chain_node(entry));
                placed.push(entry);
            }
            Err(error) => {
                // NUR ein Signaturbefund, KEIN Quarantaeneeintrag daneben: ein
                // Objekt erscheint in genau einem Fehler-/Quarantaenearray.
                report
                    .signature_errors
                    .insert(ObjectErrorV1::new(object_hash, error.code()));
            }
        }
    }

    // Gate `chain-position`: einmal ueber die ganze Knotenmenge. Sequenz und
    // Vorgaengerbindung sind keine Eigenschaft eines Objekts, sondern eine
    // Beziehung zwischen Objekten — die Frage laesst sich erst beantworten,
    // wenn alle Knoten vorliegen.
    //
    // Original signed Stub identities support provisional chain inspection.
    // Their final results require the later encrypted Writer Evidence below.
    let attestations = record_destructions(
        &mut report,
        &inventory,
        options.os_wall_clock(),
        |version, hash, sequence| {
            crate::historical::historical_registry_head(
                &inventory,
                anchor,
                version,
                hash,
                sequence,
                options.os_wall_clock(),
            )
        },
    );
    let stub_candidates =
        crate::destroyed::candidates(&report, &inventory, anchor, options.os_wall_clock());
    nodes.extend(
        stub_candidates
            .iter()
            .map(|stub| crate::destroyed::node(stub)),
    );
    protocol.enter(Gate::ChainPosition);
    let chain = place_in_chain(&mut report, anchor, &nodes);

    // Ein Grant, dessen `entryHash` auf kein Objekt des Bestands zeigt, gehoert
    // zu keinem Eintrag und beruehrt die Kette nicht.
    for object_hash in orphan_grants(&inventory) {
        quarantine_unattributable(&mut report, object_hash);
    }

    // Gate `grant-plan`: nur ueber Objekte, die Gate `chain-position`
    // ueberstanden haben. Ein Fehlschlag dort verhindert dieses Gate FUER
    // DASSELBE OBJEKT und laesst die uebrigen unberuehrt (design.md:1602/1610)
    // — und ein isoliertes Objekt bekaeme sonst einen zweiten Befund in einem
    // zweiten Array.
    protocol.enter(Gate::GrantPlan);
    for entry in &placed {
        let object_hash = entry.object_hash();
        if report.quarantined_objects.contains_key(&object_hash) {
            continue;
        }
        if let Some(code) = grant_plan_finding(entry, inventory.grants()) {
            report
                .signature_errors
                .insert(ObjectErrorV1::new(object_hash, code));
        }
    }

    // Gate `receipt`, ERSTER TEIL: die Checkpoints. Sie laufen VOR den
    // Quittungen, weil ein Kopfwiderspruch ein Objekt ISOLIERT — und ein
    // isoliertes Objekt darf danach kein `objectResults`-Ergebnis mehr
    // bekommen. Ein Objekt erscheint in genau einem Feld.
    protocol.enter(Gate::Receipt);
    if let Some(chain) = &chain {
        assess_checkpoints(
            &mut report,
            &mut store,
            key,
            anchor,
            &inventory,
            options.os_wall_clock(),
            chain,
        );
    }

    // Gate `receipt`, ZWEITER TEIL: die Quittungen, und mit ihnen die
    // Objektergebnisse.
    let confirmed = confirm_entries(
        &mut report,
        &mut store,
        key,
        anchor,
        &inventory,
        options.os_wall_clock(),
        &placed,
    );

    // Gate `evidence`: Evidence-Objekte und Zeitstempel, sofern gefordert. Die
    // Frist stammt AUSSCHLIESSLICH aus bestaetigten Quittungen — deshalb
    // bekommt dieses Gate `confirmed` und nicht das rohe Inventar der `.esr`.
    protocol.enter(Gate::Evidence);
    run_evidence_gate(&mut report, anchor, &inventory, options, &confirmed);

    // Gate `recipient-grant` und, DAHINTER UND ALS KEIN GATE, die Entkapselung.
    protocol.enter(Gate::RecipientGrant);
    if let Some(ceiling) = options.recipient_time_ceiling
        && let Some(recipient) = options.recipient()
        && inventory.grants().iter().any(|grant| {
            let fields = grant.value().grant_body().fields();
            fields.kind == ea_format::GrantKindV1::Historical
                && fields.recipient_key_thumbprint == recipient.key_thumbprint()
                && placed.iter().any(|entry| {
                    entry.value().entry_hash() == fields.entry_hash
                        && own_grant(&inventory, entry, recipient.key_thumbprint()).is_none()
                })
        })
        && report
            .verified_time_floor
            .map_or(options.os_wall_clock(), |floor| {
                floor.max(options.os_wall_clock())
            })
            > ceiling
    {
        return Err(VerifyError::RecipientTimeNotDurable);
    }
    let mut destruction_evidence = Vec::new();
    let decapsulation = claim_own_grants(
        &mut report,
        &mut store,
        key,
        anchor,
        &inventory,
        options,
        &placed,
        &mut destruction_evidence,
    );
    if decapsulation == Decapsulation::Performed {
        protocol.decapsulated();
    }

    // Preserve public signed identity progression independently of whether
    // this recipient can read the later destruction Evidence. Every public
    // error still withholds this proof; it never authenticates original EIP
    // object hashes or implies that deletion was completed.
    if chain
        .as_ref()
        .is_some_and(ea_chain::VerifiedChain::is_fully_verified)
        && report.gaps.is_empty()
        && report.format_errors.is_empty()
        && report.quarantined_objects.is_empty()
        && report.signature_errors.is_empty()
        && report.evidence_errors.is_empty()
        && report.decryption_errors.is_empty()
    {
        report.public_chain_head = Some(report.chain_head);
    }

    // Final classification uses only Stubs bound by authenticated plaintext
    // Evidence and signed deletion attestations. No Stub ever reaches HPKE.
    if !inventory.destroyed().is_empty() {
        // Start with the continuous signed-identity prefix. Removing an
        // unsupported Stub can disconnect another Evidence, so converge by
        // shrinking both the candidate nodes and the usable Evidence set.
        let mut approved;
        loop {
            let prefix = ea_chain::build_chain(anchor.chain_id(), &nodes)
                .ok()
                .and_then(|chain| {
                    chain
                        .nodes()
                        .first()
                        .filter(|node| node.chain_sequence.get() == 0)?;
                    chain.verified_head().map(|head| head.chain_sequence())
                });
            destruction_evidence.retain(|proof| prefix.is_some_and(|end| proof.sequence <= end));
            approved = stub_candidates
                .iter()
                .filter(|stub| {
                    !report.quarantined_objects.contains_key(&stub.object_hash())
                        && crate::destroyed::evidence_holds(
                            stub,
                            &destruction_evidence,
                            &attestations,
                            &inventory,
                        )
                })
                .map(|stub| stub.object_hash())
                .collect::<std::collections::BTreeSet<_>>();
            let before = nodes.len();
            nodes.retain(|node| {
                node.kind != ea_chain::ChainNodeKind::DestroyedStub
                    || approved.contains(&node.object_hash)
            });
            if nodes.len() == before {
                break;
            }
        }
        for hash in &approved {
            report.object_results.insert(
                *hash,
                ObjectResultV1::new(
                    *hash,
                    ObjectTypeV1::Destroyed,
                    ObjectResultKindV1::AuthorizedDestroyed,
                    ServerConfirmationV1::NotServerConfirmed,
                ),
            );
        }
        report.gaps.clear();
        report.chain_head = ChainHeadV1::sentinel(anchor.chain_id());
        place_in_chain(&mut report, anchor, &nodes);
        for stub in &stub_candidates {
            if !approved.contains(&stub.object_hash()) {
                let sequence = stub
                    .value()
                    .signed_manifest()
                    .manifest()
                    .fields()
                    .chain_sequence;
                report
                    .gaps
                    .entry((anchor.chain_id(), sequence))
                    .or_insert(ChainGapV1::new(anchor.chain_id(), sequence, sequence));
            }
        }
    }

    // ERST HIER, und nach nichts anderem: die Pipeline ist vollstaendig
    // durchgelaufen. Ein frueherer Ausstieg — Gate `trust` traegt nicht —
    // erreicht diese Zeile nie, und der Bestand gilt dann ausdruecklich NICHT
    // als vollstaendig verifiziert.
    report.pipeline_completed = true;
    report.seal()
}

/// Gate `recipient-grant` ueber alle Eintraege mit Ergebnis, und die
/// Entkapselung dahinter.
///
/// NUR EINTRAEGE MIT ERGEBNIS. Ein isolierter Eintrag oder einer mit
/// Signaturbefund hat die neun Gates nicht durchlaufen; ueber seinen eigenen
/// Grant ist dann nichts zu sagen und an ihm nichts zu oeffnen.
///
/// OHNE EMPFAENGERSCHLUESSEL passiert hier gar nichts: „eigener Grant" setzt
/// voraus, dass es ein Eigenes gibt. Das Gate laeuft trotzdem — es hat nur
/// nichts zu pruefen —, und es wird nichts entkapselt und nichts abgewertet.
// Gate inputs stay borrowed from the same verification invocation; the last
// output retains only public destruction identifiers, never opened plaintext.
#[allow(clippy::too_many_arguments)]
fn claim_own_grants(
    report: &mut VerificationReportV1,
    _store: &mut EphemeralTrustStateStore,
    _key: TrustStateKey,
    anchor: &TrustAnchorV1,
    inventory: &ArchiveInventory,
    options: VerifyOptions<'_>,
    placed: &[&Parsed<EntryPackageV1>],
    destruction_evidence: &mut Vec<crate::destroyed::VerifiedEvidence>,
) -> Decapsulation {
    let Some(recipient) = options.recipient() else {
        return Decapsulation::Skipped;
    };
    let mut decapsulation = Decapsulation::Skipped;
    let effective_now = report
        .verified_time_floor
        .map_or(options.os_wall_clock(), |floor| {
            floor.max(options.os_wall_clock())
        });
    for entry in placed {
        if !report.object_results.contains_key(&entry.object_hash()) {
            continue;
        }
        // FEHLENDER GRANT ist kein Befund: der Eintrag bleibt gueltig und
        // sichtbar, er wird nur nicht geoeffnet (`design.md`:1612).
        let Some(grant) = own_grant(inventory, entry, recipient.key_thumbprint()) else {
            // Initial grants have priority. Historical candidates are selected only
            // after verification, so a forged lower hash cannot shadow a valid one.
            let mut first_failure = None;
            for grant in inventory.grants().iter().filter(|grant| {
                let f = grant.value().grant_body().fields();
                f.kind == ea_format::GrantKindV1::Historical
                    && f.entry_hash == entry.value().entry_hash()
                    && f.recipient_key_thumbprint == recipient.key_thumbprint()
            }) {
                if report
                    .quarantined_objects
                    .contains_key(&grant.object_hash())
                {
                    continue;
                }
                match crate::historical::verify_historical_grant(
                    inventory,
                    anchor,
                    entry,
                    grant,
                    effective_now,
                ) {
                    Ok(expires) => {
                        report.recipient_grants.insert(
                            entry.value().entry_hash(),
                            (grant.object_hash(), Some(expires)),
                        );
                        report
                            .public_key_thumbprints
                            .insert(grant.value().grant_body().fields().issuer_key_thumbprint);
                        if record_decapsulation(
                            report,
                            grant,
                            open_for_destruction(
                                grant,
                                entry,
                                recipient,
                                inventory,
                                anchor,
                                effective_now,
                                destruction_evidence,
                            ),
                        ) == Decapsulation::Performed
                        {
                            decapsulation = Decapsulation::Performed;
                        }
                        first_failure = None;
                        break;
                    }
                    Err(code) => {
                        first_failure.get_or_insert((grant.object_hash(), code));
                    }
                }
            }
            if let Some((hash, code)) = first_failure {
                report
                    .recipient_grants
                    .insert(entry.value().entry_hash(), (hash, None));
                report
                    .signature_errors
                    .insert(ObjectErrorV1::new(hash, code));
            }
            continue;
        };
        report
            .recipient_grants
            .insert(entry.value().entry_hash(), (grant.object_hash(), None));
        // EIN ISOLIERTES OBJEKT WIRD NICHT BENUTZT, und es bekommt auch keinen
        // zweiten Befund. Eine doppelt abgelegte `.eag` bleibt im Inventar
        // ihrer Familie (`crates/ea-archive/src/inventory.rs:283-289`) und
        // stuende sonst zugleich in `quarantinedObjects` und in einem
        // Fehlerarray. Fuer diesen Lauf ist ein isolierter Grant deshalb so
        // gut wie keiner — fail-closed und ohne Doppeleintrag.
        if report
            .quarantined_objects
            .contains_key(&grant.object_hash())
        {
            continue;
        }
        let manifest = entry.value().manifest().fields();
        let selected = crate::historical::historical_registry_head(
            inventory,
            anchor,
            manifest.registry_version,
            ObjectHash::try_from(manifest.registry_head_hash.as_slice()).expect("fixed hash"),
            manifest.chain_sequence,
            options.os_wall_clock(),
        );
        let verified = selected
            .ok_or(RecipientGrantErrorV1::HeadUnavailable)
            .and_then(|selected| verify_own_grant(grant, entry, &selected));
        match verified {
            Err(error) => {
                report
                    .signature_errors
                    .insert(ObjectErrorV1::new(grant.object_hash(), error.code()));
                continue;
            }
            Ok(thumbprint) => {
                // Nachweis des Geprueften: der Abdruck des Ausstellers, der
                // die Grantsignatur GETRAGEN hat.
                report.public_key_thumbprints.insert(thumbprint);
            }
        }

        // HPKE-OPEN, KEIN GATE. Erst hier, hinter dem neunten.
        if record_decapsulation(
            report,
            grant,
            open_for_destruction(
                grant,
                entry,
                recipient,
                inventory,
                anchor,
                effective_now,
                destruction_evidence,
            ),
        ) == Decapsulation::Performed
        {
            decapsulation = Decapsulation::Performed;
        }
    }
    decapsulation
}

fn open_for_destruction(
    grant: &Parsed<ea_format::GrantV1>,
    entry: &Parsed<EntryPackageV1>,
    recipient: crate::RecipientKeyV1<'_>,
    inventory: &ArchiveInventory,
    anchor: &TrustAnchorV1,
    now: UnixMillis,
    evidence: &mut Vec<crate::destroyed::VerifiedEvidence>,
) -> Result<(), crate::DecryptionErrorV1> {
    let plaintext = open_entry(grant, entry, recipient)?;
    if !inventory.destroyed().is_empty()
        && let Some(proof) = plaintext
            .with_exposed(|bytes| crate::destroyed::inspect(bytes, entry, inventory, anchor, now))
    {
        evidence.push(proof);
    }
    Ok(())
}

/// Gate `receipt` ueber die Eintraege: Quittung suchen, pruefen, Ergebnis
/// eintragen.
///
/// HIER UND NUR HIER entstehen die `objectResults`. Die Menge ist durch die
/// gepinnte Entweder-oder-Regel bestimmt: ein Ergebnis bekommt genau der
/// Eintrag, der Gate `chain-position` erreicht hat UND weder isoliert ist noch
/// einen Signaturbefund traegt. Deshalb laeuft diese Schleife NACH Gate
/// `grant-plan` — dessen Befunde entstehen erst dort, und ein frueherer
/// Durchlauf gaebe einem Objekt Ergebnis und Fehler zugleich.
///
/// FEHLT DIE QUITTUNG, ist das KEIN Mangel (`design.md`:1608). Im Dateimodus
/// ist `notServerConfirmed` der Regelfall; der Eintrag bleibt `valid`, es
/// entsteht kein Eintrag in einem der sechs Mangelfelder, und
/// [`VerificationReportV1::is_fully_verified`] sinkt nicht. Eine Quittung, die
/// NICHT verifiziert, ist dagegen ein `signatureErrors`-Eintrag — ueber die
/// QUITTUNG, nicht ueber den Eintrag.
///
/// HERAUSGEGEBEN werden die Paare aus Eintrag und BESTAETIGTER Quittung: Gate
/// `evidence` braucht sie, weil `evidence-due-at` eine Sachaussage des Servers
/// ist und aus unauthentischen Bytes keine Sachaussagen stammen duerfen.
fn confirm_entries<'a>(
    report: &mut VerificationReportV1,
    store: &mut EphemeralTrustStateStore,
    key: TrustStateKey,
    anchor: &TrustAnchorV1,
    inventory: &'a ArchiveInventory,
    os_wall_clock: UnixMillis,
    placed: &[&'a Parsed<EntryPackageV1>],
) -> Vec<(&'a Parsed<EntryPackageV1>, &'a Parsed<ReceiptV1>)> {
    let mut confirmed = Vec::new();
    for entry in placed {
        let object_hash = entry.object_hash();
        if report.quarantined_objects.contains_key(&object_hash)
            || report
                .signature_errors
                .iter()
                .any(|error| error.object_hash() == object_hash)
        {
            continue;
        }

        let mut confirmation = ServerConfirmationV1::NotServerConfirmed;
        // EINE ISOLIERTE QUITTUNG WIRD NICHT GEPRUEFT, und sie bekommt auch
        // keinen zweiten Befund — dieselbe Schranke, die [`claim_own_grants`]
        // ueber dem Grant traegt. Zwei `.esr` auf denselben
        // `entryObjectHash` isolieren EINANDER, die echte eingeschlossen
        // (`crates/ea-archive/src/inventory.rs:518-537`), und beide bleiben
        // dabei in ihrer Objektfamilie stehen; [`receipt_for`] waehlt aus
        // dieser nach Objekthash aufsteigenden Sammlung den KLEINSTEN Treffer.
        // Ohne diese Zeile stuende eine untergeschobene Quittung mit kleinerem
        // Objekthash zugleich in `quarantinedObjects` und in
        // `signatureErrors`. Der Ausgang des Laufs aendert sich dadurch nicht
        // — die nicht leere Quarantaene traegt ihn bereits —, wohl aber die
        // Widerspruchsfreiheit des Berichts.
        //
        // FUER GATE `evidence` sagt sie dasselbe noch einmal: aus einem
        // isolierten Objekt stammt keine `evidence-due-at`-Frist, denn es
        // gelangt gar nicht erst in `confirmed`.
        if let Some(receipt) = receipt_for(inventory, entry).filter(|receipt| {
            !report
                .quarantined_objects
                .contains_key(&receipt.object_hash())
        }) {
            match confirm_receipt(store, key, anchor, inventory, os_wall_clock, entry, receipt) {
                Ok(thumbprint) => {
                    // Nachweis des Geprueften: der Abdruck, der die
                    // Serversignatur GETRAGEN hat.
                    report.public_key_thumbprints.insert(thumbprint);
                    let signed_time = receipt.value().core().fields().accepted_at_server;
                    report.verified_time_floor = Some(
                        report
                            .verified_time_floor
                            .map_or(signed_time, |old| old.max(signed_time)),
                    );
                    confirmation = ServerConfirmationV1::ServerConfirmed;
                    confirmed.push((*entry, receipt));
                }
                Err(error) => {
                    report
                        .signature_errors
                        .insert(ObjectErrorV1::new(receipt.object_hash(), error.code()));
                }
            }
        }

        report.object_results.insert(
            object_hash,
            ObjectResultV1::new(
                object_hash,
                ObjectTypeV1::Entry,
                ObjectResultKindV1::Valid,
                confirmation,
            ),
        );
    }
    confirmed
}

/// Prueft GENAU EINE Quittung gegen GENAU EINEN Eintrag.
///
/// Drei Stufen, in dieser Reihenfolge und nicht anders:
///
/// 1. Die fuenf Bindungen aus `design.md` §14.1 Schritt 7. Eine tadellos
///    signierte Quittung ueber einen ANDEREN Eintrag bestaetigt diesen nicht,
///    und das steht vor jeder Kryptografie fest.
/// 2. `ea_trust::verify_receipt_time`: die Quittung als vertrauenswuerdiger
///    Zeitboden gegen die VORBESTEHENDE Registrierungsautoritaet.
/// 3. Die Serversignatur gegen den gewaehlten Kopf. Erst hier wird die Quittung
///    authentisch.
///
/// Liefert bei Erfolg den Schluesselabdruck, der die Pruefung getragen hat.
fn confirm_receipt(
    _store: &mut EphemeralTrustStateStore,
    _key: TrustStateKey,
    anchor: &TrustAnchorV1,
    inventory: &ArchiveInventory,
    os_wall_clock: UnixMillis,
    entry: &Parsed<EntryPackageV1>,
    receipt: &Parsed<ReceiptV1>,
) -> Result<KeyThumbprint, ReceiptGateErrorV1> {
    if !receipt_bindings_hold(entry, receipt) {
        return Err(ReceiptGateErrorV1::BindingMismatch);
    }

    let fields = receipt.value().core().fields();
    let selected = crate::historical::historical_registry_head(
        inventory,
        anchor,
        fields.registry_version,
        ObjectHash::from(fields.registry_head_hash),
        fields.chain_sequence,
        os_wall_clock,
    )
    .ok_or(ReceiptGateErrorV1::UntrustedTime)?;
    selected
        .verify_receipt(receipt)
        .map_err(|_| ReceiptGateErrorV1::UntrustedTime)?;

    let core = receipt.value().core();
    let context = VerificationContext::receipt(core.exact_bytes())
        .map_err(|_| ReceiptGateErrorV1::ReceiptSignatureInvalid)?;
    let signer = verify_cose_sign1(receipt.value().server_signature(), &selected, &context)
        .map_err(|_| ReceiptGateErrorV1::ReceiptSignatureInvalid)?;
    Ok(signer.key_thumbprint())
}

/// Gate `receipt` ueber die Checkpoints: Serveraussagen pruefen, Rueckbau
/// bewerten, Befunde abbilden.
///
/// CHECKPOINTS GEHOEREN HIERHER UND NICHT ZU GATE `evidence`
/// (`design.md`:1598 gegen :1599). Geprueft wird hier ausschliesslich die
/// SERVERSIGNATUR des Checkpoints; die RFC-3161-Anteile bleiben Gate 8.
///
/// Ein Checkpoint, der sich nicht als Serveraussage nachweisen laesst, wird
/// KEIN [`CheckpointClaim`]: `ea_chain::assess_rollback` verlangt bereits
/// authentifizierte Aussagen, sonst behauptete ein untergeschobenes Objekt
/// einen Rueckbau.
///
/// Die Abbildung in den Bericht ist die, die `ea-chain` an seinen Befundtypen
/// festhaelt: eine per Checkpoint BEWIESENE Luecke wird zu `gaps` — es gibt
/// kein Objekt, das man isolieren koennte, es fehlt ja gerade —, ein
/// Kopfwiderspruch zu `quarantinedObjects` mit Grund `conflicting`.
fn assess_checkpoints(
    report: &mut VerificationReportV1,
    _store: &mut EphemeralTrustStateStore,
    _key: TrustStateKey,
    anchor: &TrustAnchorV1,
    inventory: &ArchiveInventory,
    os_wall_clock: UnixMillis,
    chain: &VerifiedChain,
) {
    let chain_id = anchor.chain_id();
    let mut claims: Vec<CheckpointClaim> = Vec::new();
    for evidence in inventory.evidence() {
        let Some(claim) = standard_checkpoint_claim(evidence) else {
            continue;
        };
        let ea_format::DecodedEvidencePayloadV1::Standard { core, .. } = evidence
            .value()
            .decoded_payload()
            .expect("parsed standard checkpoint")
        else {
            continue;
        };
        let fields = core.fields();
        let verified = crate::historical::historical_registry_head_by_hash(
            inventory,
            anchor,
            ObjectHash::from(fields.registry_head_hash),
            claim.covered_through_sequence,
            os_wall_clock,
        )
        .is_some_and(|head| head.verify_checkpoint(evidence).is_ok());
        if !verified {
            report.signature_errors.insert(ObjectErrorV1::new(
                evidence.object_hash(),
                ReceiptGateErrorV1::CheckpointUnverifiable.code(),
            ));
            continue;
        }
        // Der Abdruck, der die Checkpointsignatur GETRAGEN hat.
        // `verify_checkpoint_time` gibt ihn nicht heraus; nach dem Nachweis ist
        // der geschuetzte Header aber authentisch und darf gelesen werden.
        if let Some(thumbprint) = checkpoint_signer_thumbprint(evidence) {
            report.public_key_thumbprints.insert(thumbprint);
        }
        report.verified_time_floor = Some(
            report
                .verified_time_floor
                .map_or(fields.issued_at_server, |old| {
                    old.max(fields.issued_at_server)
                }),
        );
        claims.push(claim);
    }

    let assessment = assess_rollback(chain, &claims);
    if let RollbackAssessment::Rollback(findings) = &assessment {
        for finding in findings {
            if let Some((from, through)) = finding.proven_missing_sequences() {
                // Faellt der Anfang mit einer Luecke aus Gate `chain-position`
                // zusammen, gewinnt die BEWIESENE: sie reicht bis zu der
                // Sequenz, die ein Server nachweislich gesehen hat, und ist
                // damit die staerkere Aussage ueber denselben Anfang. Das
                // Ueberschreiben ist zudem erzwungen — `gaps` ist im Schema
                // nach `(chainId, fromSequence)` eindeutig, zwei Intervalle mit
                // gleichem Anfang darf es dort gar nicht geben.
                report
                    .gaps
                    .insert((chain_id, from), ChainGapV1::new(chain_id, from, through));
            }
            if let RollbackFinding::HeadEntryHashMismatch {
                sequence,
                conflicting_object_hash,
                ..
            } = finding
            {
                quarantine_conflicting(report, *conflicting_object_hash);
                // EIN QUARANTAENISIERTER KOPF IST KEIN VERIFIZIERTER KOPF.
                //
                // `place_in_chain` setzt `chain_head` an Gate `chain-position`
                // aus `VerifiedChain::verified_head` und revidiert es nie. Faellt
                // der Kopfknoten hier in die Quarantaene — und er faellt genau
                // dann hinein, wenn der Checkpoint EBEN DIESE Sequenz bezeugt —,
                // wiese der Bericht sonst in `chainHead` ein Objekt aus, das er
                // selbst unter `quarantinedObjects` als widerspruechlich fuehrt.
                //
                // Das Sentinel ist dafuer die richtige Antwort und keine
                // Notloesung: sein Vertrag lautet auf „kein verifizierter Kopf"
                // (`crates/ea-verify/src/report.rs:167`), und ein Kopf, dem ein
                // nachgewiesener Checkpoint widerspricht, ist keiner mehr. Der
                // Ausstieg des Laufs aendert sich dadurch nicht — die nicht
                // leere Quarantaene traegt ihn bereits nach Regel 1
                // (`crates/ea-recovery/src/exit.rs:82`) —, wohl aber die
                // Widerspruchsfreiheit des Berichts.
                if chain
                    .verified_head()
                    .is_some_and(|head| head.chain_sequence() == *sequence)
                {
                    report.chain_head = ChainHeadV1::sentinel(chain_id);
                }
            }
        }
    }
    report.rollback = assessment;
}

/// Der Schluesselabdruck im geschuetzten Header eines BEREITS nachgewiesenen
/// Checkpoints.
fn checkpoint_signer_thumbprint(
    evidence: &Parsed<ea_format::EvidenceObjectV1>,
) -> Option<KeyThumbprint> {
    let ea_format::DecodedEvidencePayloadV1::Standard { exact_cose, .. } =
        evidence.value().decoded_payload().ok()?
    else {
        return None;
    };
    Some(parse_cose_sign1(&exact_cose, &[]).ok()?.key_thumbprint())
}

/// Gate `chain-position`: setzt die Knoten in die Kette des Ankers und traegt
/// die Befunde in den Bericht.
///
/// Die Abbildung ist die, die `ea-chain` an seinen Befundtypen festhaelt und
/// die hier nicht neu erfunden wird: Luecken werden zu `gaps`, Forks und
/// Kettenbrueche zu `quarantinedObjects` mit Grund `conflicting` — fuer JEDES
/// beteiligte Objekt, denn bei einem Fork ist gerade nicht entscheidbar,
/// welche Seite die echte ist.
///
/// Die `chainId` jedes Berichtsfeldes stammt AUSSCHLIESSLICH aus dem Anker,
/// nie aus dem Bestand; `VerifiedChain::chain_id` ist in `ea-chain` deshalb gar
/// nicht oeffentlich. Bleibt kein verifizierter Kopf uebrig, behaelt der
/// Bericht das Sentinel aus [`ChainHeadV1::sentinel`].
///
/// Die gebaute Kette wird HERAUSGEGEBEN, weil Gate `receipt` sie fuer
/// `ea_chain::assess_rollback` braucht: ein Checkpoint wird gegen das
/// verifizierte Praefix abgeglichen, und das entsteht genau hier. `None` heisst,
/// dass sich gar keine Kette bilden liess — dann bleibt der Rueckbau
/// ausdruecklich NICHT PRUEFBAR, statt aus einer unbrauchbaren Grundlage eine
/// Aussage zu erfinden.
fn place_in_chain(
    report: &mut VerificationReportV1,
    anchor: &TrustAnchorV1,
    nodes: &[ChainNode],
) -> Option<VerifiedChain> {
    let chain_id = anchor.chain_id();
    let Ok(chain) = build_chain(chain_id, nodes) else {
        // UNERREICHBAR, und trotzdem fail-closed behandelt. `build_chain`
        // kennt genau drei Fehler: `ForeignChainId` ist oben aussortiert,
        // `GenesisBinding` erzwingt `ea-format` schon beim Kodieren
        // (`validate_sequence_predecessor`), und `MAX_CHAIN_NODES_V1` ist
        // genauso gross wie `MAX_ARCHIVE_BLOBS_V1`, das der Bestand vorher
        // durchsetzt. Statt hier zu panicken oder — schlimmer — stillschweigend
        // keine Kettenaussage zu treffen, gilt der ganze Knotensatz als
        // widerspruechlich.
        for node in nodes {
            quarantine_conflicting(report, node.object_hash);
        }
        return None;
    };

    for gap in chain.gaps() {
        report.gaps.insert(
            (chain_id, gap.from_sequence()),
            ChainGapV1::new(chain_id, gap.from_sequence(), gap.through_sequence()),
        );
    }
    for fork in chain.forks() {
        for object_hash in fork.competing_object_hashes() {
            quarantine_conflicting(report, object_hash);
        }
    }
    for entry in chain.breaks() {
        quarantine_conflicting(report, entry.object_hash());
    }
    if let Some(head) = chain.verified_head() {
        report.chain_head = ChainHeadV1::new(chain_id, head.chain_sequence(), head.entry_hash());
    }
    Some(chain)
}

/// Loest `writer_certificate_hash` in den zur Sequenz aktiven Zertifikaten auf.
///
/// Verlangt ausdruecklich ein Zertifikat der Art `Writer`: ein Server- oder
/// Adminzertifikat schreibt keine Eintraege, und ein Manifest, das eines als
/// Schreiber benennt, ist nicht zuordenbar.
fn writer_is_active(
    selected: &ea_trust::HistoricalRegistryAuthority,
    writer: CertificateHash,
) -> bool {
    selected
        .active_certificate_fields(writer)
        .is_some_and(|fields| fields.certificate_kind == CertificateKindV1::Writer)
}

/// Gate `manifest-signature`: prueft die Schreibersignatur gegen den
/// aufgeloesten Schreiber.
///
/// Liefert bei Erfolg den Schluesselabdruck, der die Pruefung GETRAGEN hat —
/// genau das ist der Beitrag zu `publicKeyThumbprints`, das ein Nachweis des
/// Geprueften ist und kein Katalogabzug.
///
/// Die uebrigen Manifestbindungen — Nutzlast gegen `record_digest`,
/// `ciphertext_hash` gegen den Ciphertext, das Schreiberzertifikat im
/// geschuetzten Header gegen das Manifest — pruefen `ea-format` und
/// `ea-crypto` bereits beim Parsen beziehungsweise beim Bilden des Kontexts
/// (`crates/ea-format/src/eip.rs:288-296`), und der `entryHash` steht gar nicht
/// erst auf dem Draht. Dieses Gate fuegt genau das hinzu, was dort fehlt: die
/// kryptografische Pruefung gegen den Schluessel des aufgeloesten Zertifikats.
///
/// Ein Fehlschlag ist ein Befund ueber EIN Objekt und nie ein `Err` des Laufs;
/// deshalb faengt schon das Bilden des Kontexts seinen Fehler ab.
fn verified_signer(
    entry: &Parsed<EntryPackageV1>,
    selected: &ea_trust::HistoricalRegistryAuthority,
) -> Result<KeyThumbprint, ManifestSignatureErrorV1> {
    let context = VerificationContext::record(entry.value().signed_manifest().exact_bytes())?;
    let signer = verify_cose_sign1(entry.value().writer_signature(), selected, &context)?;
    Ok(signer.key_thumbprint())
}

/// Traegt `object_hash` als nicht zuordenbar ein.
///
/// Ein Eintrag ohne aufloesbaren Schreiber wird NICHT als Kettenknoten
/// aufgenommen — er duerfte sonst als blosse Luecke erscheinen, und eine
/// Luecke ist eine ganz andere Aussage als ein vorhandenes, aber niemandem
/// zurechenbares Objekt. Genau dafuer gibt es `unattributable` im
/// geschlossenen Grundmengen-Enum des Berichts.
fn quarantine_unattributable(report: &mut VerificationReportV1, object_hash: ObjectHash) {
    report.quarantined_objects.insert(
        object_hash,
        QuarantinedObjectV1::new(object_hash, QuarantineReason::Unattributable),
    );
}

/// Traegt `object_hash` als widerspruechlich ein.
///
/// Der Grund fuer Fork und Kettenbruch: beide Objekte sind DA und wohlgeformt,
/// sie widersprechen einander nur. Das ist eine ganz andere Aussage als eine
/// Luecke — und der Unterschied ist der zwischen einem Angriff und einem
/// Verlust.
fn quarantine_conflicting(report: &mut VerificationReportV1, object_hash: ObjectHash) {
    report.quarantined_objects.insert(
        object_hash,
        QuarantinedObjectV1::new(object_hash, QuarantineReason::Conflicting),
    );
}
