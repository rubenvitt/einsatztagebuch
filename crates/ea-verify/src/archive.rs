//! Der Einstiegspunkt der Verifikation: [`verify_archive`].
//!
//! DIESE FASSUNG fuehrt die Gates `format`, `trust`, `registry`,
//! `manifest-signature`, `chain-position`, `grant-plan` und `receipt` aus. Die
//! Gates `evidence` und `recipient-grant` folgen in den naechsten Tasks;
//! solange bleibt `pipeline_completed` falsch, und der Bestand gilt
//! ausdruecklich NICHT als vollstaendig verifiziert.
//!
//! GATE `receipt` UMFASST QUITTUNG UND CHECKPOINT. `design.md` §14.1 Schritt 7
//! (:1581) nennt „Server-Receipt und Checkpoints, sofern vorhanden"; Schritt 8
//! ist auf Evidence-Objekte und Zeitstempel begrenzt. Die Verwechslung liegt
//! nahe, weil beide Objektarten in `crates/ea-format/src/ecp.rs` wohnen —
//! deshalb steht die Abgrenzung hier ausgeschrieben und nicht bloss im Kopf.

use core::marker::PhantomData;

use ea_archive::{ArchiveInventory, ArchiveSource, QuarantineReason};
use ea_chain::{
    ChainNode, CheckpointClaim, RollbackAssessment, RollbackFinding, VerifiedChain,
    assess_rollback, build_chain,
};
use ea_crypto::{VerificationContext, parse_cose_sign1, verify_cose_sign1};
use ea_format::{CertificateKindV1, EntryPackageV1, Parsed, ReceiptV1};
use ea_trust::{
    PreexistingRegistryAuthority, RegistrySelectionOutcome, SelectedRegistryHead, TrustAnchorV1,
    TrustStateKey, VerifiedSignedTime, VerifiedTrust, load_trust_state, prepare_local_time,
    select_registry_head, verify_checkpoint_time, verify_receipt_time, verify_registry_candidate,
    verify_trust,
};
use ea_types::{CertificateHash, ChainSequence, KeyThumbprint, ObjectHash, UnixMillis};

use crate::{
    ChainGapV1, ChainHeadV1, EphemeralTrustStateStore, ManifestSignatureErrorV1, ObjectErrorV1,
    ObjectResultKindV1, ObjectResultV1, ObjectTypeV1, QuarantinedObjectV1, ReceiptGateErrorV1,
    ServerConfirmationV1, VerificationReportV1, VerifyError,
    entry::{
        claims_unverifiable_writer_transition, entry_chain_node, grant_plan_finding, orphan_grants,
        receipt_bindings_hold, receipt_for, standard_checkpoint_claim,
    },
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
/// Der Lebenszeitparameter traegt die spaeteren geliehenen Stellschrauben
/// (Empfaengerschluessel, Zustandsspeicher, Schema-Registry); bis dahin haelt
/// [`PhantomData`] ihn offen, damit die gepinnte Signatur `VerifyOptions<'_>`
/// nicht spaeter bricht.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifyOptions<'a> {
    os_wall_clock: UnixMillis,
    borrowed: PhantomData<&'a ()>,
}

impl VerifyOptions<'_> {
    /// Ein Lauf gegen die uebergebene Betriebssystemuhr.
    #[must_use]
    pub const fn new(os_wall_clock: UnixMillis) -> Self {
        Self {
            os_wall_clock,
            borrowed: PhantomData,
        }
    }

    /// Die uebergebene Betriebssystemuhr. Roher Vergleichswert, kein Nachweis.
    #[must_use]
    pub const fn os_wall_clock(&self) -> UnixMillis {
        self.os_wall_clock
    }
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
    // Gate `format`: das Inventar klassifiziert am 9-Byte-Exact-Object-Praefix
    // und parst jede Bytesequenz mit Praefix. Ein Fehlschlag erzeugt PAARWEISE
    // einen `formatError` und einen Quarantaeneeintrag `malformed`.
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

    // Gate `trust`: einmal fuer den ganzen Bestand. Traegt es nicht, endet der
    // Lauf hier — ohne Vertrauenskette laesst sich ueber kein Objekt etwas
    // sagen.
    if verified_trust(&mut store, key, anchor, &inventory).is_none() {
        return report.seal();
    }

    // Gate `registry`: je Eintragssequenz einzeln. Ein Eintrag, dessen Sequenz
    // keinen Kopf mit Operationsautoritaet findet, bekommt keine Aussage; ein
    // Eintrag, dessen Schreiberzertifikat sich nicht aufloest, wird isoliert.
    //
    // BEHANDELT WIRD NACH AUFSTEIGENDER SEQUENZ, nicht in Inventarreihenfolge:
    // die folgt dem Objekthash, und die Registrierungslinie laesst sich nur
    // VORWAERTS nachziehen — ein einmal gepinnter Kopf geht nie zurueck. Liefe
    // die Schleife nach Hash, entschiede der Zufall der Hashwerte darueber,
    // welcher Eintrag noch in der Lease seines Kopfes liegt. Der Objekthash
    // bleibt als zweites Ordnungsmerkmal, damit die Reihenfolge auch bei
    // gleicher Sequenz total und damit reproduzierbar ist.
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
    for entry in ordered {
        let object_hash = entry.object_hash();
        // Ein bereits isoliertes Objekt geht nicht weiter durch die Gates: es
        // erscheint ENTWEDER in `objectResults` ODER in genau einem
        // Fehler-/Quarantaenearray, niemals in beidem.
        if report.quarantined_objects.contains_key(&object_hash) {
            continue;
        }
        let fields = entry.value().manifest().fields();
        let Some(selected) = select_head_for_sequence(
            &mut store,
            key,
            anchor,
            &inventory,
            options.os_wall_clock(),
            fields.chain_sequence,
        ) else {
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
                if fields.chain_id != anchor.chain_id()
                    || claims_unverifiable_writer_transition(entry)
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
    // EIN `.eds` WIRD HIER KEIN KNOTEN, und das ist fail-closed und gemessen:
    // `design.md` §14.1 verlangt fuer `authorizedDestroyed` eine AUFLOESBARE
    // `destructionAuthorization`. Diese Aufloesung ist von `ea-verify` aus
    // nicht erreichbar — `ea-trust` exportiert keine Pruefung dafuer
    // (`crates/ea-trust/src/lib.rs:450-469`), `TrustCatalog` ist `pub(crate)`
    // (`crates/ea-trust/src/catalog.rs:11`), und `catalog::load` prueft
    // ueberhaupt keine Signatur, sondern parst nur
    // (`crates/ea-trust/src/catalog.rs:17-66`). Bliebe die blosse Anwesenheit
    // des Autorisierungsobjekts im Inventar — und Inventarmitgliedschaft ist
    // KEINE Autorisierung, genau wie bei
    // [`claims_unverifiable_writer_transition`]. Wer den Stummel trotzdem als
    // Knoten fuehrte, liesse jeden, der ein `.eds` schreiben kann, einen
    // Eintrag spurlos ersetzen. Also gilt `design.md`:1597: ein Stummel ohne
    // vollstaendige Pruefkette BLEIBT EINE LUECKE — das fehlende `.eip`
    // erscheint als `gaps`-Eintrag, `authorizedDestructions` bleibt leer, und
    // `destroyedEntryCount` zaehlt ihn weiterhin als blossen Zaehler.
    let chain = place_in_chain(&mut report, anchor, &nodes);

    // Ein Grant, dessen `entryHash` auf kein Objekt des Bestands zeigt, gehoert
    // zu keinem Eintrag und beruehrt die Kette nicht.
    for object_hash in orphan_grants(&inventory) {
        quarantine_unattributable(&mut report, object_hash);
    }

    // Gate `grant-plan`: nur ueber Objekte, die Gate `chain-position`
    // ueberstanden haben. Ein Fehlschlag dort verhindert dieses Gate FUER
    // DASSELBE OBJEKT und laesst die uebrigen unberuehrt (design.md:1585/1593)
    // — und ein isoliertes Objekt bekaeme sonst einen zweiten Befund in einem
    // zweiten Array.
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
    confirm_entries(
        &mut report,
        &mut store,
        key,
        anchor,
        &inventory,
        options.os_wall_clock(),
        &placed,
    );

    report.seal()
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
/// FEHLT DIE QUITTUNG, ist das KEIN Mangel (`design.md`:1591). Im Dateimodus
/// ist `notServerConfirmed` der Regelfall; der Eintrag bleibt `valid`, es
/// entsteht kein Eintrag in einem der sechs Mangelfelder, und
/// [`VerificationReportV1::is_fully_verified`] sinkt nicht. Eine Quittung, die
/// NICHT verifiziert, ist dagegen ein `signatureErrors`-Eintrag — ueber die
/// QUITTUNG, nicht ueber den Eintrag.
fn confirm_entries(
    report: &mut VerificationReportV1,
    store: &mut EphemeralTrustStateStore,
    key: TrustStateKey,
    anchor: &TrustAnchorV1,
    inventory: &ArchiveInventory,
    os_wall_clock: UnixMillis,
    placed: &[&Parsed<EntryPackageV1>],
) {
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
        if let Some(receipt) = receipt_for(inventory, entry) {
            match confirm_receipt(store, key, anchor, inventory, os_wall_clock, entry, receipt) {
                Ok(thumbprint) => {
                    // Nachweis des Geprueften: der Abdruck, der die
                    // Serversignatur GETRAGEN hat.
                    report.public_key_thumbprints.insert(thumbprint);
                    confirmation = ServerConfirmationV1::ServerConfirmed;
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
    store: &mut EphemeralTrustStateStore,
    key: TrustStateKey,
    anchor: &TrustAnchorV1,
    inventory: &ArchiveInventory,
    os_wall_clock: UnixMillis,
    entry: &Parsed<EntryPackageV1>,
    receipt: &Parsed<ReceiptV1>,
) -> Result<KeyThumbprint, ReceiptGateErrorV1> {
    if !receipt_bindings_hold(entry, receipt) {
        return Err(ReceiptGateErrorV1::BindingMismatch);
    }

    let mut time_verified = false;
    let selected = select_pinned_head(
        store,
        key,
        anchor,
        inventory,
        os_wall_clock,
        entry.value().manifest().fields().chain_sequence,
        |authority| {
            let verified = verify_receipt_time(authority, receipt).ok();
            time_verified = verified.is_some();
            verified
        },
    )
    .ok_or(ReceiptGateErrorV1::UntrustedTime)?;
    if !time_verified {
        return Err(ReceiptGateErrorV1::UntrustedTime);
    }

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
/// (`design.md`:1581 gegen :1583). Geprueft wird hier ausschliesslich die
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
    store: &mut EphemeralTrustStateStore,
    key: TrustStateKey,
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
        let mut verified = false;
        let _ = select_pinned_head(
            store,
            key,
            anchor,
            inventory,
            os_wall_clock,
            claim.covered_through_sequence,
            |authority| {
                let proof = verify_checkpoint_time(authority, evidence).ok();
                verified = proof.is_some();
                proof
            },
        );
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
                conflicting_object_hash,
                ..
            } = finding
            {
                quarantine_conflicting(report, *conflicting_object_hash);
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

/// Waehlt den bereits gepinnten Kopf ueber `sequence` und laesst `verify_time`
/// dabei auf die VORBESTEHENDE Registrierungsautoritaet blicken.
///
/// ZWEITER DURCHLAUF, UND DAS IST NOTWENDIG, nicht bequem. `verify_receipt_time`
/// und `verify_checkpoint_time` verlangen eine
/// [`PreexistingRegistryAuthority`], die den Bezugswert der Aussage traegt
/// (`crates/ea-trust/src/time.rs:179-185`). Solange die Registrierungslinie
/// noch NACHGEZOGEN wird, ist die vorbestehende Autoritaet der VORGAENGERKOPF,
/// dessen Lease die Sequenz gerade nicht deckt — gemessen an einer Linie aus
/// Policy-, Server- und Schreiberkopf: beim Erreichen von `Selected` fuer die
/// erste Eintragssequenz ist die Autoritaet noch der Serverkopf. Erst wenn der
/// Schreiberkopf gepinnt ist, nimmt `verify_registry_candidate` den
/// `current_candidate`-Weg (`crates/ea-trust/src/registry.rs:513-533`) und gibt
/// genau diesen Kopf als vorbestehende Autoritaet heraus. Deshalb laeuft Gate
/// `receipt` erst NACH der Eintragsschleife, und deshalb genuegt hier eine
/// einzige Runde ohne Aufholschritte.
///
/// `verify_time` liefert `None`, wenn die Aussage nicht traegt; dann wird
/// KEINE Zeitquelle eingespeist und der Kopf trotzdem gewaehlt — der Aufrufer
/// braucht ihn fuer seinen eigenen Befund.
fn select_pinned_head<F>(
    store: &mut EphemeralTrustStateStore,
    key: TrustStateKey,
    anchor: &TrustAnchorV1,
    inventory: &ArchiveInventory,
    os_wall_clock: UnixMillis,
    sequence: ChainSequence,
    verify_time: F,
) -> Option<SelectedRegistryHead>
where
    F: FnOnce(&PreexistingRegistryAuthority) -> Option<VerifiedSignedTime>,
{
    let trust = verified_trust(store, key, anchor, inventory)?;
    let candidate = verify_registry_candidate(&trust, sequence).ok()?;
    let sources: Vec<VerifiedSignedTime> = candidate
        .preexisting_authority()
        .and_then(verify_time)
        .into_iter()
        .collect();
    let local_time = prepare_local_time(store, &candidate, os_wall_clock, &sources).ok()?;
    match select_registry_head(candidate, local_time, None).ok()? {
        RegistrySelectionOutcome::Selected(selected) => Some(selected),
        RegistrySelectionOutcome::Advanced(_) | RegistrySelectionOutcome::PendingFuture(_) => None,
    }
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

/// Gate `trust`: laedt den Stand und prueft die Vertrauenskette gegen den Anker.
///
/// `None` ist FAIL-CLOSED fuer den gesamten Bestand.
fn verified_trust(
    store: &mut EphemeralTrustStateStore,
    key: TrustStateKey,
    anchor: &TrustAnchorV1,
    inventory: &ArchiveInventory,
) -> Option<VerifiedTrust> {
    let snapshot = load_trust_state(store, key).ok()?;
    verify_trust(anchor, inventory, snapshot).ok()
}

/// Obergrenze der Aufholschritte je Eintragssequenz.
///
/// Jeder Aufholschritt pinnt eine STRIKT hoehere Registrierungsversion, und
/// jede Version braucht mindestens ein eigenes Registrierungsereignis im
/// Bestand. Mehr Schritte als zulaessige Trust-Objekte kann es deshalb nicht
/// geben; die Schranke ist eine Abbruchgarantie, keine Fachregel.
const MAX_REGISTRY_CATCH_UP_STEPS_V1: usize = ea_trust::MAX_TRUST_OBJECTS_V1;

/// Gate `registry`: waehlt den Kopf mit Operationsautoritaet ueber
/// `proposed_sequence`.
///
/// Die Reihenfolge ist bindend und darf nicht aufgebrochen werden:
/// `load_trust_state` -> `verify_trust` -> `verify_registry_candidate` ->
/// `prepare_local_time` -> `select_registry_head`. `prepare_local_time`
/// verlangt, dass Revision, Zeitzustand und gepinnter Kopf des Speichers
/// EXAKT zum Kandidaten passen; ein fremder Commit dazwischen liefert
/// `TrustError::StateConflict`. Deshalb laeuft auch `verify_trust` je Runde
/// erneut: jede erfolgreiche Auswahl schreibt eine neue Revision, und ein
/// Kandidat aus der Vorrunde ist danach veraltet.
///
/// Nur [`RegistrySelectionOutcome::Selected`] traegt Autoritaet.
/// `PendingFuture` bricht das Gate fuer diese Sequenz ab: ein noch nicht
/// wirksamer Nachfolger ist keine Autoritaet, und Warten hilft nicht, weil die
/// Uhr fest ist.
///
/// [`RegistrySelectionOutcome::Advanced`] wird ebenfalls NICHT als Autoritaet
/// benutzt — der Kopf daraus fliesst in keine Aussage —, beendet aber die
/// Runde nicht, sondern loest die naechste aus. `Advanced` heisst
/// ausdruecklich: es wurde ein Kopf NACHGEZOGEN, der die Sequenz noch nicht
/// abdeckt. Ein Verifizierer startet aus einem leeren Stand und muss die
/// Registrierungslinie von Version eins an nachziehen; schon die kleinste
/// echte Linie braucht dafuer zwei Koepfe (einen fuer die Policy, einen fuer
/// das Schreiberzertifikat). Wer beim ersten `Advanced` abbraeche, koennte
/// keinen einzigen Eintrag je zuordnen.
fn select_head_for_sequence(
    store: &mut EphemeralTrustStateStore,
    key: TrustStateKey,
    anchor: &TrustAnchorV1,
    inventory: &ArchiveInventory,
    os_wall_clock: UnixMillis,
    proposed_sequence: ChainSequence,
) -> Option<SelectedRegistryHead> {
    for _ in 0..MAX_REGISTRY_CATCH_UP_STEPS_V1 {
        let trust = verified_trust(store, key, anchor, inventory)?;
        let candidate = verify_registry_candidate(&trust, proposed_sequence).ok()?;
        // Zeitquellen bleiben leer, solange der Speicher keinen Kopf traegt:
        // `prepare_local_time` verwirft jede Quelle, deren Autoritaetskopf
        // nicht der gepinnte ist, und vor der ersten Auswahl ist keiner
        // gepinnt.
        let local_time = prepare_local_time(store, &candidate, os_wall_clock, &[]).ok()?;
        match select_registry_head(candidate, local_time, None).ok()? {
            RegistrySelectionOutcome::Selected(selected) => return Some(selected),
            RegistrySelectionOutcome::Advanced(_) => {}
            RegistrySelectionOutcome::PendingFuture(_) => return None,
        }
    }
    None
}

/// Loest `writer_certificate_hash` in den zur Sequenz aktiven Zertifikaten auf.
///
/// Verlangt ausdruecklich ein Zertifikat der Art `Writer`: ein Server- oder
/// Adminzertifikat schreibt keine Eintraege, und ein Manifest, das eines als
/// Schreiber benennt, ist nicht zuordenbar.
fn writer_is_active(selected: &SelectedRegistryHead, writer: CertificateHash) -> bool {
    selected.active_certificates().any(|(hash, fields)| {
        hash == writer && fields.certificate_kind == CertificateKindV1::Writer
    })
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
    selected: &SelectedRegistryHead,
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
