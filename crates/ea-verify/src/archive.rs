//! Der Einstiegspunkt der Verifikation: [`verify_archive`].
//!
//! DIESE FASSUNG fuehrt die Gates `format`, `trust`, `registry`,
//! `manifest-signature`, `chain-position` und `grant-plan` aus. Die Gates
//! `receipt` bis `recipient-grant` folgen in den naechsten Tasks; solange
//! bleibt `pipeline_completed` falsch, und der Bestand gilt ausdruecklich NICHT
//! als vollstaendig verifiziert.

use core::marker::PhantomData;

use ea_archive::{ArchiveInventory, ArchiveSource, QuarantineReason};
use ea_chain::{ChainNode, build_chain};
use ea_crypto::{VerificationContext, verify_cose_sign1};
use ea_format::{CertificateKindV1, EntryPackageV1, Parsed};
use ea_trust::{
    RegistrySelectionOutcome, SelectedRegistryHead, TrustAnchorV1, TrustStateKey, VerifiedTrust,
    load_trust_state, prepare_local_time, select_registry_head, verify_registry_candidate,
    verify_trust,
};
use ea_types::{CertificateHash, ChainSequence, KeyThumbprint, ObjectHash, UnixMillis};

use crate::{
    ChainGapV1, ChainHeadV1, EphemeralTrustStateStore, ManifestSignatureErrorV1, ObjectErrorV1,
    QuarantinedObjectV1, VerificationReportV1, VerifyError,
    entry::{
        claims_unverifiable_writer_transition, entry_chain_node, grant_plan_finding, orphan_grants,
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
    place_in_chain(&mut report, anchor, &nodes);

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
    for entry in placed {
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

    report.seal()
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
fn place_in_chain(report: &mut VerificationReportV1, anchor: &TrustAnchorV1, nodes: &[ChainNode]) {
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
        return;
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
