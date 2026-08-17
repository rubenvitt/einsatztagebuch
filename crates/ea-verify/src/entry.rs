//! Die Gates `chain-position` und `grant-plan` ueber einzelne Objekte.
//!
//! Hier steht die Uebersetzung geparster Archivobjekte in die WERTE, mit denen
//! `ea-chain` rechnet, und die Rekonstruktion des initialen Grant-Plans aus den
//! vorhandenen `.eag`. Beides ist bewusst von der Pipeline getrennt: was ein
//! Objekt in der Kette ist und was sein Grant-Plan sagt, haengt allein an dem
//! Objekt — nicht an der Reihenfolge, in der der Bestand durchlaufen wird.

use ea_archive::ArchiveInventory;
use ea_chain::{ChainNode, ChainNodeKind};
use ea_format::{EntryPackageV1, GrantKindV1, GrantPlanItemV1, GrantPlanV1, GrantV1, Parsed};
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

/// Behauptet das Manifest einen Schreiberwechsel, den dieser Lauf nicht
/// nachpruefen kann?
///
/// FAIL-CLOSED UND AUSDRUECKLICH KEINE PRUEFUNG. `design.md` §14.1 Schritt 5
/// verlangt, dass ein gesetztes `writerTransitionEventHash` auf ein im
/// Trust-Katalog aufloesbares, fuer diese Sequenz WIRKSAMES
/// `writerTransition`-Ereignis zeigt. Diese Aufloesung ist von `ea-verify` aus
/// nicht erreichbar: `ea-trust` haelt sowohl
/// `VerifiedTrustInner::catalog` als auch
/// `CandidateState::writer_transition_object_hash` `pub(crate)`
/// (`crates/ea-trust/src/anchor.rs:128`, `crates/ea-trust/src/resolver.rs:32`),
/// und `SelectedRegistryHead` gibt keinen Uebergang heraus. `ea-trust` ist
/// geschlossen und wird dafuer nicht aufgebohrt.
///
/// Ein Objekt, dessen Schreiberwechsel sich nicht pruefen laesst, gilt deshalb
/// als nicht zuordenbar — es wird ISOLIERT, nicht angenommen. Das ist die
/// konservative Antwort und keine Verifikation: sobald `ea-trust` einen
/// Zugriff auf die wirksamen Uebergaenge herausgibt, tritt hier die echte
/// Pruefung an ihre Stelle. Ein Vergleich gegen die blosse Anwesenheit des
/// Objekts im Inventar waere ausdruecklich KEIN Ersatz — Katalogmitgliedschaft
/// ist keine Autorisierung, und eine Pruefung, die wie eine aussieht, ohne eine
/// zu sein, ist schlimmer als die Verweigerung.
pub(crate) fn claims_unverifiable_writer_transition(entry: &Parsed<EntryPackageV1>) -> bool {
    entry
        .value()
        .manifest()
        .fields()
        .writer_transition_event_hash
        .is_some()
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
