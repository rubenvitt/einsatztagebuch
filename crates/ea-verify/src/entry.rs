//! Die Gates `chain-position` und `grant-plan` ueber einzelne Objekte.
//!
//! Hier steht die Uebersetzung geparster Archivobjekte in die WERTE, mit denen
//! `ea-chain` rechnet, und die Rekonstruktion des initialen Grant-Plans aus den
//! vorhandenen `.eag`. Beides ist bewusst von der Pipeline getrennt: was ein
//! Objekt in der Kette ist und was sein Grant-Plan sagt, haengt allein an dem
//! Objekt — nicht an der Reihenfolge, in der der Bestand durchlaufen wird.

use ea_archive::ArchiveInventory;
use ea_chain::{ChainNode, ChainNodeKind, CheckpointClaim};
use ea_format::{
    DecodedEvidencePayloadV1, EntryPackageV1, EvidenceObjectV1, GrantKindV1, GrantPlanItemV1,
    GrantPlanV1, GrantV1, ManifestCoreFieldsV1, Parsed, ReceiptV1,
};
use ea_trust::{EffectiveWriterTransitionV1, SelectedRegistryHead};
use ea_types::{EntryHash, ObjectHash};

/// Der eigene Code von Gate `grant-plan`.
///
/// EIGENE FAMILIE, genau wie bei [`crate::ManifestSignatureErrorV1`]: der Code
/// benennt das GATE, an dem der Befund entstand, nicht die Ursache. Die
/// uebrigen Befunde dieses Gates — fehlender oder doppelter Recovery-Grant,
/// doppelter Empfaenger — tragen dagegen die Codes von
/// `ea_format::FormatError` unveraendert weiter: `ea-format` kennt diese
/// Bedingungen bereits und vergibt fuer sie stabile `EA-GRANT-*`-Codes. Einen
/// zweiten Satz danebenzustellen hiesse, dieselbe Aussage zweimal zu benennen.
pub const GRANT_PLAN_MISMATCH_CODE_V1: &str = "EA-VERIFY-GRANT-PLAN-MISMATCH";

/// Der Kettenknoten eines Eintragspakets.
///
/// Der `kind` ist ein PARAMETER und nicht fest verdrahtet: derselbe Weg fuehrt
/// den Stummel eines autorisiert vernichteten Eintrags
/// ([`ChainNodeKind::DestroyedStub`]) in die Kette, und der belegt sein
/// Sequenzfach genauso vollstaendig wie ein Eintragspaket. Diese Fassung
/// erzeugt ausschliesslich [`ChainNodeKind::EntryPackage`]; die `.eds`-Seite
/// folgt, sobald die Stummel dieselbe Gate-Strecke durchlaufen.
pub(crate) fn entry_chain_node(entry: &Parsed<EntryPackageV1>) -> ChainNode {
    let fields = entry.value().manifest().fields();
    ChainNode {
        chain_id: fields.chain_id,
        chain_sequence: fields.chain_sequence,
        previous_entry_hash: fields.previous_entry_hash,
        entry_hash: entry.value().entry_hash(),
        object_hash: entry.object_hash(),
        writer_certificate_hash: fields.writer_certificate_hash,
        writer_transition_event_hash: fields.writer_transition_event_hash,
        kind: ChainNodeKind::EntryPackage,
    }
}

/// Traegt die Aussage des Manifests ueber den Schreiberwechsel gegen den
/// fuer seine Sequenz gewaehlten Kopf?
///
/// `design.md`:669 ist die Norm: `writerTransitionEventHash` ist GENAU DANN
/// 32 Byte lang, wenn sich das Writer-Zertifikat gegenueber dem direkten
/// Vorgaenger aendert, und nennt dann den `objectHash` des WIRKSAMEN
/// Root-signierten `writerTransition`-Ereignisses; ein fehlender,
/// zusaetzlicher oder unpassender Hash ist ein Trust-Fehler des Objekts.
/// §14.1 Schritt 5 stellt die Pruefung neben Sequenz und Vorgaengerbindung.
///
/// Bis Stufe 5 stand hier eine Pauschalabweisung: `ea-trust` gab den
/// wirksamen Uebergang nicht heraus, und jedes gesetzte Feld wurde isoliert.
/// Seit [`SelectedRegistryHead::effective_writer_transition`] existiert, tritt
/// die Regel selbst an diese Stelle — siehe [`transition_claim_holds`].
///
/// # Warum die Pruefung keinen Vorgaenger liest
///
/// Die Norm spricht vom „direkten Vorgaenger", die Pruefung liest den
/// Eintrag `N` trotzdem nicht. Der Uebergang bindet den VERTRAUTEN KOPF
/// selbst: das Root-signierte Transitionsobjekt traegt `previous_entry_hash`
/// — den `entryHash` des letzten Eintrags des alten Writers — und
/// `effective_from_sequence`, und `ea-trust` gibt beides als ZUSTAND des
/// gewaehlten Kopfes heraus, nicht als Katalogobjekt: ein Uebergang, den kein
/// Ereignis der Linie angewandt hat, erscheint dort gar nicht. Ob „sich das
/// Writer-Zertifikat gegenueber dem direkten Vorgaenger aendert", sagt damit
/// der Kopf, an dessen Sequenz und an dessen Vorgaengerhash der Eintrag
/// gemessen wird. Ein Blick in das Inventar waere schwaecher, nicht staerker:
/// der Vorgaenger kann dort fehlen, und seine Anwesenheit bewiese keine
/// Autorisierung — Katalogmitgliedschaft ist keine. Die gewoehnliche
/// Vorgaengerbindung von `N + 1` an `N` bleibt Sache von Gate
/// `chain-position` ueber die Knotenmenge; derselbe `previous_entry_hash`
/// geht in den [`ChainNode`].
pub(crate) fn writer_transition_claim_holds(
    entry: &Parsed<EntryPackageV1>,
    selected: &SelectedRegistryHead,
) -> bool {
    transition_claim_holds(
        entry.value().manifest().fields(),
        selected.effective_writer_transition(),
    )
}

/// Der Kern der Transitionsregel, ohne Kopf und ohne Paket — damit jede
/// einzelne Bedingung fuer sich falsifizierbar ist.
///
/// `t` ist der wirksame Uebergang des Kopfes, sofern seine
/// `effective_from_sequence` die Sequenz des Eintrags ist; ein Uebergang, der
/// an einer anderen Sequenz wirksam wurde, ist fuer diesen Eintrag keiner.
/// Dann gilt, ueber dem Paar aus Manifestfeld und `t`:
///
/// - `(None, None)`: traegt — Genesis oder unveraenderter Writer;
/// - `(Some(hash), Some(t))`: traegt genau dann, wenn `hash` der Objekthash
///   des Uebergangs ist, `previous_entry_hash` der des Uebergangs ist und
///   `writer_certificate_hash` der neue Writer;
/// - `(Some(_), None)`: zusaetzlich — traegt nicht;
/// - `(None, Some(_))`: fehlend — traegt nicht.
///
/// Die dritte Bindung ist an der Aufrufstelle bereits durch die Aufloesung
/// des laufenden Writers gedeckt — auf dem Kopf, der den Uebergang traegt,
/// ist nur der neue Writer aktiv. Sie steht trotzdem hier, weil die Regel
/// ueber dem OBJEKT formuliert ist und ihre Aussage nicht an der Reihenfolge
/// der Gates haengen soll.
fn transition_claim_holds(
    fields: &ManifestCoreFieldsV1,
    transition: Option<&EffectiveWriterTransitionV1>,
) -> bool {
    let transition = transition
        .filter(|transition| transition.effective_from_sequence() == fields.chain_sequence);
    match (fields.writer_transition_event_hash, transition) {
        (None, None) => true,
        (Some(hash), Some(transition)) => {
            hash == transition.object_hash()
                && fields.previous_entry_hash == Some(transition.previous_entry_hash())
                && fields.writer_certificate_hash == transition.new_writer_certificate_hash()
        }
        (Some(_), None) | (None, Some(_)) => false,
    }
}

/// Gate `grant-plan` ueber GENAU EIN Eintragspaket.
///
/// Liefert `None`, wenn das Gate traegt, sonst den stabilen Code des Befunds.
///
/// Der Plan wird aus den vorhandenen `.eag` REKONSTRUIERT und dann gegen den
/// Manifestwert gerechnet. Die Sortierung und die Kodierung stammen
/// vollstaendig aus `ea_format::GrantPlanV1`; hier wird beides weder nachgebaut
/// noch neu erfunden. `GrantPlanV1::new` erzwingt zugleich den VERPFLICHTENDEN
/// Recovery-Grant: fehlt er, entsteht gar kein Plan und der Befund ist
/// `EA-GRANT-MISSING-RECOVERY`. Das ist fail-closed — ein Bestand ohne
/// Recovery-Grant ist ein Bestand, den niemand mehr oeffnen kann.
pub(crate) fn grant_plan_finding(
    entry: &Parsed<EntryPackageV1>,
    grants: &[Parsed<GrantV1>],
) -> Option<&'static str> {
    let fields = entry.value().manifest().fields();
    match GrantPlanV1::new(plan_items(entry.value().entry_hash(), grants)) {
        // Fehlender oder doppelter Recovery-Grant, doppelter Empfaenger: die
        // Codes kommen unveraendert aus `ea-format`, statt hier aufgezaehlt zu
        // werden. Eine neue Bedingung dort traegt damit sofort ihren eigenen
        // Code, ohne dass dieses Gate davon wissen muss.
        Err(error) => Some(error.code()),
        Ok(plan) => (*plan.hash().as_bytes() != fields.initial_grant_plan_hash)
            .then_some(GRANT_PLAN_MISMATCH_CODE_V1),
    }
}

/// Die Planeintraege der initialen Grants auf `entry_hash`.
///
/// Zugeordnet wird ALLEIN ueber den `entryHash` — dieselbe Regel, nach der
/// [`orphan_grants`] entscheidet. Waeren die beiden Regeln verschieden, gaebe
/// es Grants, die weder in einen Plan noch in die Verwaisung fielen: sie
/// verschwaenden lautlos aus dem Bericht.
///
/// Historische Grants bleiben aussen vor: der initiale Plan ist die Menge, die
/// beim Schreiben feststand; ein spaeter ausgestellter historischer Grant darf
/// ihn nicht rueckwirkend veraendern.
fn plan_items(entry_hash: EntryHash, grants: &[Parsed<GrantV1>]) -> Vec<GrantPlanItemV1> {
    grants
        .iter()
        .map(|grant| grant.value().grant_body().fields())
        .filter(|fields| fields.kind == GrantKindV1::Initial && fields.entry_hash == entry_hash)
        .map(|fields| {
            GrantPlanItemV1::new(
                fields.recipient_key_thumbprint,
                fields.recipient_certificate_hash,
                fields.purpose,
            )
        })
        .collect()
}

/// Die Grants, deren `entryHash` auf KEIN geparstes Objekt des Bestands zeigt.
///
/// Ein solcher Grant ist niemandem zuzuordnen: er behauptet einen Eintrag, den
/// es hier nicht gibt. Er beruehrt die Kette ausdruecklich nicht — ein Grant
/// beansprucht kein Sequenzfach —, ist aber auch kein blosses Beiwerk, denn er
/// traegt ein Exact-Object-Praefix und eine Ausstelleraussage.
///
/// Stummel zaehlen mit: ein `.eds` traegt den `entryHash` des vernichteten
/// Eintrags weiter, und dessen Grants sind deshalb nicht verwaist, sondern
/// gehoeren zu einem Eintrag, den es noch gibt — als Stummel.
pub(crate) fn orphan_grants(inventory: &ArchiveInventory) -> Vec<ObjectHash> {
    let mut known: Vec<EntryHash> = inventory
        .entries()
        .iter()
        .map(|entry| entry.value().entry_hash())
        .chain(
            inventory
                .destroyed()
                .iter()
                .map(|stub| stub.value().entry_hash()),
        )
        .collect();
    // Binaere Suche statt `HashSet`: in dieser Crate kommt keine Streuordnung
    // vor, damit keine Iterationsreihenfolge in den Bericht sickert.
    known.sort_unstable();
    inventory
        .grants()
        .iter()
        .filter(|grant| {
            known
                .binary_search(&grant.value().grant_body().fields().entry_hash)
                .is_err()
        })
        .map(Parsed::object_hash)
        .collect()
}

/// Die Quittung, die GENAU DIESES Eintragspaket bezeugt.
///
/// Zugeordnet wird ueber `entry_object_hash` und nicht ueber den `entryHash`:
/// die Quittung bestaetigt die BYTES, die der Server angenommen hat.
///
/// # Diese Auswahl filtert NICHT nach Quarantaene, und das ist Absicht
///
/// Das Inventar isoliert zwei Quittungen auf denselben Eintrag zwar als
/// Widerspruch (`crates/ea-archive/src/inventory.rs:518-537`), laesst dabei
/// aber BEIDE in ihrer Objektfamilie stehen — die echte eingeschlossen. Hier
/// bleibt deshalb ausdruecklich nicht hoechstens eine uebrig, und `find`
/// liefert aus dieser nach Objekthash aufsteigenden Sammlung den KLEINSTEN
/// Treffer, isoliert oder nicht. Diese Stelle kennt den Bericht nicht und kann
/// die Frage gar nicht beantworten; die Schranke sitzt an der einzigen
/// Aufrufstelle, `confirm_entries` in `crates/ea-verify/src/archive.rs`, nach
/// demselben Muster wie die des Grantpfads in `claim_own_grants`.
///
/// GEMESSEN in `crates/ea-verify/tests/receipt_checkpoint.rs`,
/// `a_forged_second_receipt_with_a_smaller_object_hash_is_never_the_chosen_one`:
/// ohne jene Schranke traegt der Bericht dort die Faelschung zugleich in
/// `quarantinedObjects` und in `signatureErrors`.
pub(crate) fn receipt_for<'a>(
    inventory: &'a ArchiveInventory,
    entry: &Parsed<EntryPackageV1>,
) -> Option<&'a Parsed<ReceiptV1>> {
    let object_hash = entry.object_hash();
    inventory
        .receipts()
        .iter()
        .find(|receipt| receipt.value().core().fields().entry_object_hash == object_hash)
}

/// Halten die fuenf Bindungen aus `design.md` §14.1 Schritt 7?
///
/// `entryHash`, `chainSequence`, `registryVersion`, `registryHeadHash` und
/// `initialGrantPlanHash` — jede gegen das Manifest des Eintrags. Der
/// `policyObjectHash` der Quittung gehoert ausdruecklich NICHT dazu: er
/// benennt die Policy des Servers, nicht die des Eintrags, und das Manifest
/// traegt ihn gar nicht.
///
/// Diese Pruefung laeuft VOR der Signaturpruefung und ist von ihr unabhaengig:
/// eine perfekt signierte Quittung ueber einen anderen Eintrag bestaetigt
/// diesen hier nicht.
pub(crate) fn receipt_bindings_hold(
    entry: &Parsed<EntryPackageV1>,
    receipt: &Parsed<ReceiptV1>,
) -> bool {
    let manifest = entry.value().manifest().fields();
    let fields = receipt.value().core().fields();
    fields.entry_hash == entry.value().entry_hash()
        && fields.chain_sequence == manifest.chain_sequence
        && fields.registry_version == manifest.registry_version
        && *fields.registry_head_hash.as_bytes() == manifest.registry_head_hash
        && *fields.initial_grant_plan_hash.as_bytes() == manifest.initial_grant_plan_hash
}

/// Der Checkpoint-Kern eines `.ecp`, sofern es einen STANDARD-Checkpoint traegt.
///
/// AUSDRUECKLICH NUR die Standardvariante. `ea_trust::verify_checkpoint_time`
/// weist jede andere mit `TimeSourceUnsupported` ab
/// (`crates/ea-trust/src/time.rs:210-212`); der Checkpoint-Kern einer
/// Timestamp-Variante ist damit in diesem Stand nicht als Serveraussage
/// nachweisbar. Aus ihm entsteht deshalb KEIN [`CheckpointClaim`] — was
/// fail-closed ist: weniger Aussagen koennen nur zu
/// [`ea_chain::RollbackAssessment::NotAssessable`] fuehren, nie zu einem
/// falschen `Consistent`. Die RFC-3161-Anteile solcher Objekte gehoeren
/// ohnehin in Gate `evidence`.
pub(crate) fn standard_checkpoint_claim(
    evidence: &Parsed<EvidenceObjectV1>,
) -> Option<CheckpointClaim> {
    let DecodedEvidencePayloadV1::Standard { core, .. } =
        evidence.value().decoded_payload().ok()?
    else {
        return None;
    };
    let fields = core.fields();
    Some(CheckpointClaim {
        chain_id: fields.chain_id,
        covered_from_sequence: fields.covered_from_sequence,
        covered_through_sequence: fields.covered_through_sequence,
        head_entry_hash: fields.head_entry_hash,
        checkpoint_object_hash: evidence.object_hash(),
    })
}

#[cfg(test)]
mod tests {
    //! Der Transitionskern, Bedingung fuer Bedingung.
    //!
    //! Die Integrationszeugen in `tests/writer_transition.rs` messen die Regel
    //! ueber einen ganzen Bestand; dort deckt die Aufloesung des laufenden
    //! Writers die dritte Bindung schon vor dem Kern ab. Hier steht jede
    //! Bedingung fuer sich, gegen einen Uebergang aus
    //! `EffectiveWriterTransitionV1::fixture` (Merkmal `test-support` von
    //! `ea-trust`, nur als Dev-Dependency).

    use ea_format::ManifestCoreFieldsV1;
    use ea_trust::EffectiveWriterTransitionV1;
    use ea_types::{
        CertificateHash, ChainId, ChainSequence, EntryHash, Hash32, ObjectHash, OrganizationId,
        RegistryVersion,
    };

    use super::transition_claim_holds;

    fn hash32(byte: u8) -> Hash32 {
        Hash32::try_from(&[byte; 32][..]).expect("32 Bytes")
    }

    fn certificate(byte: u8) -> CertificateHash {
        CertificateHash::from(ObjectHash::from(hash32(byte)))
    }

    const SEQUENCE: u64 = 7;

    fn transition() -> EffectiveWriterTransitionV1 {
        EffectiveWriterTransitionV1::fixture(
            ObjectHash::from(hash32(0x01)),
            certificate(0x02),
            certificate(0x03),
            ChainSequence::new(SEQUENCE),
            EntryHash::from(hash32(0x04)),
        )
    }

    fn fields(
        sequence: u64,
        previous_entry_hash: Option<EntryHash>,
        writer: CertificateHash,
        claim: Option<ObjectHash>,
    ) -> ManifestCoreFieldsV1 {
        ManifestCoreFieldsV1 {
            organization_id: OrganizationId::try_from(&[0x21; 16][..]).expect("16 Bytes"),
            chain_id: ChainId::try_from(&[0x22; 16][..]).expect("16 Bytes"),
            chain_sequence: ChainSequence::new(sequence),
            previous_entry_hash,
            writer_certificate_hash: writer,
            writer_transition_event_hash: claim,
            registry_version: RegistryVersion::new(1),
            registry_head_hash: [0; 32],
            initial_grant_plan_hash: [0; 32],
            nonce: [0; 12],
        }
    }

    /// Das Manifest, das den Uebergang aus [`transition`] EXAKT beansprucht.
    fn exact_claim() -> ManifestCoreFieldsV1 {
        let transition = transition();
        fields(
            SEQUENCE,
            Some(transition.previous_entry_hash()),
            transition.new_writer_certificate_hash(),
            Some(transition.object_hash()),
        )
    }

    #[test]
    fn no_claim_and_no_transition_holds() {
        let manifest = fields(
            SEQUENCE,
            Some(EntryHash::from(hash32(0x09))),
            certificate(0x02),
            None,
        );
        assert!(transition_claim_holds(&manifest, None));
    }

    #[test]
    fn the_exact_claim_holds() {
        assert!(transition_claim_holds(&exact_claim(), Some(&transition())));
    }

    #[test]
    fn a_missing_claim_does_not_hold() {
        let mut manifest = exact_claim();
        manifest.writer_transition_event_hash = None;
        assert!(!transition_claim_holds(&manifest, Some(&transition())));
    }

    #[test]
    fn an_additional_claim_does_not_hold() {
        let manifest = exact_claim();
        assert!(!transition_claim_holds(&manifest, None));
    }

    #[test]
    fn a_claim_naming_another_object_does_not_hold() {
        let mut manifest = exact_claim();
        manifest.writer_transition_event_hash = Some(ObjectHash::from(hash32(0x99)));
        assert!(!transition_claim_holds(&manifest, Some(&transition())));
    }

    #[test]
    fn a_claim_binding_another_predecessor_does_not_hold() {
        let mut manifest = exact_claim();
        manifest.previous_entry_hash = Some(EntryHash::from(hash32(0x99)));
        assert!(!transition_claim_holds(&manifest, Some(&transition())));
    }

    #[test]
    fn a_claim_by_the_old_writer_does_not_hold() {
        let mut manifest = exact_claim();
        manifest.writer_certificate_hash = transition().old_writer_certificate_hash();
        assert!(!transition_claim_holds(&manifest, Some(&transition())));
    }

    #[test]
    fn a_transition_effective_at_another_sequence_is_none_for_this_entry() {
        // Der Uebergang gilt ab `SEQUENCE`; fuer den Eintrag danach ist er
        // keiner mehr — ein Hash dort ist zusaetzlich, kein Hash dort traegt.
        let mut later_claim = exact_claim();
        later_claim.chain_sequence = ChainSequence::new(SEQUENCE + 1);
        assert!(!transition_claim_holds(&later_claim, Some(&transition())));
        let mut later_plain = later_claim;
        later_plain.writer_transition_event_hash = None;
        assert!(transition_claim_holds(&later_plain, Some(&transition())));
    }
}
