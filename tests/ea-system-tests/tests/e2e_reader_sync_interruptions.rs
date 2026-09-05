//! Jeder Punkt des Abschnitts `sync-cursor` wird unterbrochen — und der
//! bestaetigte Cursor steht danach dort, wo er stand.
//!
//! Der Systemzeuge zu AK-43 und zum Plansatz „`e2e_reader_sync_interruptions.rs`
//! unterbricht jeden Punkt des Abschnitts `sync-cursor`, einschliesslich der
//! zwei nur im Browser moeglichen — ein waehrend eines Batches geschlossener
//! Tab und ein durch Storage-Eviction abgebrochener OPFS-Schreibvorgang — und
//! belegt, dass der bestaetigte Cursor nach jedem Abbruch unveraendert bleibt
//! und der Wiederholversuch idempotent auf denselben Kopf laeuft"
//! (`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-4-reader.md`,
//! Task 14).
//!
//! # Was ihn von `crates/ea-reader/tests/sync_resume.rs` unterscheidet
//!
//! Dort treibt `ReaderSyncFaultPoint::ALL` die Schleife — die Liste, die die
//! Crate ueber sich selbst fuehrt. HIER treibt das MANIFEST
//! `docs/traceability/stage-4-fault-points.json`: jeder `name` des Abschnitts
//! `sync-cursor` wird auf seine Rust-Darstellung abgebildet, und die Menge der
//! Manifestnamen muss der Menge der Darstellungen in BEIDEN Richtungen
//! gleichen. Ein Punkt, der nur im Manifest steht, hat keinen Zeugen; ein
//! Punkt, der nur in der Crate steht, hat keine Ledgerzeile — beides ist rot.
//!
//! Drei Namen des Abschnitts sind KEINE Variante des Enums, und das ist
//! gemessen (`crates/ea-reader/src/sync.rs`, zwoelf Varianten gegen fuenfzehn
//! Manifestzeilen): die zwei browser-eigenen Punkte sind ein fallen gelassener
//! Dienst bzw. ein Bytespeicher, der `QuotaExceeded` liefert — dieselben
//! Modelle, die `sync_resume.rs` fuehrt —, und `refusal-leaves-the-cursor` ist
//! kein Abbruch des Wirts, sondern eine ABWEISUNG des Rahmens durch den
//! Reader. Alle drei werden hier ausdruecklich gefahren und nicht
//! uebersprungen.
//!
//! # Was „idempotent auf denselben Kopf" hier misst
//!
//! Nicht nur den Eintragshash. Ein ungestoerter Lauf liefert die Referenz —
//! Kopf, die Menge der gecachten Adressen und die Summe der Blobbytes —, und
//! jeder Wiederholversuch nach einem Abbruch muss ALLE drei treffen. Der
//! Bytevergleich ist der Duplikatnachweis: ein Batch, der nach `AfterFirstObjectWrite`
//! ein zweites Mal geholt wird, darf im Speicher kein zweites Byte hinterlassen.

#[path = "sync_interruption_support/mod.rs"]
mod sync_interruption_support;

use std::collections::BTreeSet;
use std::fs;

use ea_reader::{ConfirmedCursor, ReaderSyncFaultPoint};
use ea_system_tests::workspace_root;
use sync_interruption_support::{ReaderSyncHarness, fixtures};

/// Das Manifest, das den Abschnitt `sync-cursor` fuehrt — relativ zur
/// Werkstattwurzel, wie `conformance_golden_vectors.rs` seine Vektoren nennt.
const FAULT_POINTS_MANIFEST_PATH: &str = "docs/traceability/stage-4-fault-points.json";

/// Der Abschnitt dieses Zeugen.
const SYNC_CURSOR_SECTION: &str = "sync-cursor";

/// Der erste browser-eigene Punkt: ein Tab schliesst mitten im Batch.
const TAB_CLOSED_MID_BATCH: &str = "tab-closed-mid-batch";

/// Der zweite: die Speicherbereinigung bricht einen OPFS-Schreibvorgang ab.
const OPFS_WRITE_ABORTED_BY_STORAGE_PRESSURE: &str = "opfs-write-aborted-by-storage-pressure";

/// Kein Abbruchpunkt, sondern die Abweisung: der Reader lehnt den Rahmen ab.
const REFUSAL_LEAVES_THE_CURSOR: &str = "refusal-leaves-the-cursor";

/// Die Rust-Darstellung EINES Manifestnamens.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Interruption {
    /// Einer der zwoelf Punkte, die der ausgelieferte Dienst selbst kennt.
    FaultPoint(ReaderSyncFaultPoint),
    /// Der Dienst wird nach `accept_batch` fallen gelassen; `confirm` laeuft nie.
    TabClosedMidBatch,
    /// Der Bytespeicher liefert ab dem zweiten Objekt `QuotaExceeded`.
    OpfsWriteAbortedByStoragePressure,
    /// EINER der vier abgewiesenen Rahmen aus `sync_attacks.rs`, benannt mit
    /// seinem Label aus `fixtures::REFUSED_FRAME_LABELS`.
    Refusal(&'static str),
}

impl Interruption {
    /// Die Laeufe zu EINEM Manifestnamen — leer, wenn das Manifest einen Punkt
    /// nennt, den dieser Zeuge nicht fahren kann.
    ///
    /// Ein Name ergibt einen Lauf; `refusal-leaves-the-cursor` ergibt VIER,
    /// weil sein Bracket vier Abweisungsgruende nennt und jeder auf einer
    /// eigenen Kulisse laufen muss: ein Rahmen, der Bytes in den Cache
    /// schreibt, praegte sonst den Befund des naechsten.
    fn named(name: &str) -> Vec<Self> {
        if let Some(point) = ReaderSyncFaultPoint::ALL
            .into_iter()
            .find(|point| point.name() == name)
        {
            return vec![Self::FaultPoint(point)];
        }
        match name {
            TAB_CLOSED_MID_BATCH => vec![Self::TabClosedMidBatch],
            OPFS_WRITE_ABORTED_BY_STORAGE_PRESSURE => {
                vec![Self::OpfsWriteAbortedByStoragePressure]
            }
            REFUSAL_LEAVES_THE_CURSOR => fixtures::REFUSED_FRAME_LABELS
                .into_iter()
                .map(Self::Refusal)
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Der Name, unter dem ein Lauf in einer Zusicherung erscheint.
    fn label(self) -> String {
        match self {
            Self::FaultPoint(point) => point.name().to_owned(),
            Self::TabClosedMidBatch => TAB_CLOSED_MID_BATCH.to_owned(),
            Self::OpfsWriteAbortedByStoragePressure => {
                OPFS_WRITE_ABORTED_BY_STORAGE_PRESSURE.to_owned()
            }
            Self::Refusal(frame) => format!("{REFUSAL_LEAVES_THE_CURSOR}/{frame}"),
        }
    }

    /// Jeder Name, den dieser Zeuge fahren kann: die zwoelf des Enums und die
    /// drei, die nur hier eine Darstellung haben.
    fn every_name() -> BTreeSet<&'static str> {
        ReaderSyncFaultPoint::ALL
            .into_iter()
            .map(ReaderSyncFaultPoint::name)
            .chain([
                TAB_CLOSED_MID_BATCH,
                OPFS_WRITE_ABORTED_BY_STORAGE_PRESSURE,
                REFUSAL_LEAVES_THE_CURSOR,
            ])
            .collect()
    }
}

/// Die `name`-Eintraege des Abschnitts `sync-cursor`, in Manifestreihenfolge.
fn declared_sync_cursor_names() -> Vec<String> {
    let path = workspace_root().join(FAULT_POINTS_MANIFEST_PATH);
    let manifest: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display())),
    )
    .expect("das Manifest der Abbruchpunkte ist JSON");
    let section = manifest
        .get(SYNC_CURSOR_SECTION)
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| {
            panic!("{FAULT_POINTS_MANIFEST_PATH} fuehrt keinen Abschnitt `{SYNC_CURSOR_SECTION}`")
        });
    section
        .iter()
        .map(|entry| {
            entry
                .get("name")
                .and_then(serde_json::Value::as_str)
                .expect("jeder Abbruchpunkt traegt einen `name`")
                .to_owned()
        })
        .collect()
}

/// Das, worauf ein Lauf endet: Kopf, gecachte Adressen, Blobbytes.
///
/// Drei Masse und nicht eines, weil „derselbe Kopf" allein ein Duplikat im
/// Speicher nicht saehe.
#[derive(Debug, Eq, PartialEq)]
struct SyncOutcome {
    sequence: u64,
    entry_hash: [u8; 32],
    cached_keys: Vec<String>,
    blob_bytes: usize,
}

impl SyncOutcome {
    fn of(harness: &ReaderSyncHarness) -> Self {
        let head = harness.confirmed_head();
        Self {
            sequence: head.sequence().get(),
            entry_hash: *head.entry_hash().as_bytes(),
            cached_keys: harness.cached_blob_keys(),
            blob_bytes: harness.blob_store_byte_count(),
        }
    }
}

/// Stellt die Kulisse auf und faehrt GENAU DIESEN Abbruch.
///
/// Gibt den bestaetigten Cursor UNMITTELBAR VOR dem Abbruch zurueck — bei
/// den meisten Punkten Genesis, beim OPFS-Punkt der Stand nach der ersten
/// Seite: dort muss die Kulisse mitten in der Lesestrecke stehen, sonst
/// vergliche der Zeuge Genesis mit Genesis (die Begruendung steht in
/// `sync_resume.rs::an_opfs_write_the_browser_aborts_leaves_the_cursor_where_it_was`).
fn stage_and_interrupt(
    harness: &mut ReaderSyncHarness,
    interruption: Interruption,
) -> ConfirmedCursor {
    match interruption {
        Interruption::FaultPoint(point) => {
            let before = harness.confirmed_cursor();
            let error = harness
                .pull_with_fault(point)
                .expect_err("ein eingespielter Abbruchpunkt bricht ab");
            assert!(
                matches!(error.code(), "EA-READER-TRANSPORT" | "EA-READER-STORE"),
                "{} brach mit {} ab statt mit einer Aussage ueber den Wirt",
                point.name(),
                error.code()
            );
            before
        }
        Interruption::TabClosedMidBatch => {
            let before = harness.confirmed_cursor();
            harness
                .accept_one_batch_and_drop_the_service()
                .expect("die erste Seite wird angenommen, bevor der Tab schliesst");
            before
        }
        Interruption::OpfsWriteAbortedByStoragePressure => {
            let mid_run = harness
                .pull_one_page()
                .expect("die erste Seite laeuft ungestoert durch");
            assert_ne!(
                mid_run,
                ConfirmedCursor::genesis(&fixtures::pinned_anchor()),
                "die erste Seite MUSS den Cursor bewegt haben, sonst misst dieser Punkt nichts"
            );
            assert_eq!(
                harness.abort_the_next_page_under_storage_pressure().code(),
                "EA-READER-STORE"
            );
            mid_run
        }
        Interruption::Refusal(label) => {
            let before = harness.confirmed_cursor();
            let (frame, code) = fixtures::refused_frame(label);
            assert_eq!(harness.refuse(frame).code(), code);
            before
        }
    }
}

/// Alle Laeufe des Abschnitts, in Manifestreihenfolge.
fn every_declared_run() -> Vec<Interruption> {
    declared_sync_cursor_names()
        .iter()
        .flat_map(|name| {
            let runs = Interruption::named(name);
            assert!(!runs.is_empty(), "`{name}` hat keine Darstellung");
            runs
        })
        .collect()
}

/// Das Manifest und der Reader nennen DIESELBEN Punkte — in beiden Richtungen.
///
/// Ein Name, der im Manifest steht und hier keine Darstellung hat, ist eine
/// Ledgerzeile ohne Zeugen; eine Darstellung ohne Manifestzeile ist ein Zeuge
/// ohne Ledgerzeile. Und ein doppelter Name ist eine Zeile, die zweimal
/// zaehlt.
#[test]
fn the_manifest_and_the_reader_name_the_same_interruptions() {
    let declared = declared_sync_cursor_names();
    let declared_set: BTreeSet<&str> = declared.iter().map(String::as_str).collect();
    assert_eq!(
        declared_set.len(),
        declared.len(),
        "der Abschnitt `{SYNC_CURSOR_SECTION}` fuehrt einen Namen doppelt"
    );
    for name in &declared {
        assert!(
            !Interruption::named(name).is_empty(),
            "`{name}` steht im Manifest, hat hier aber keine Darstellung"
        );
    }
    assert_eq!(
        declared_set,
        Interruption::every_name(),
        "Manifest und Reader nennen verschiedene Punkte"
    );
}

/// Nach JEDEM Abbruch steht der bestaetigte Cursor dort, wo er stand — gelesen
/// aus einem NEU GEOEFFNETEN Speicher, nicht aus dem Dienst.
#[test]
fn every_declared_interruption_leaves_the_confirmed_cursor_where_it_was() {
    for run in every_declared_run() {
        let name = run.label();
        let mut harness = ReaderSyncHarness::fresh();
        let before = stage_and_interrupt(&mut harness, run);
        assert_eq!(
            harness.confirmed_cursor(),
            before,
            "`{name}` bewegte den Cursor im Speicher, an dem der Abbruch geschah"
        );
        assert_eq!(
            harness.reopen_store().confirmed_cursor(),
            before,
            "`{name}` bewegte den Cursor ueber einen Abbruch hinweg"
        );
    }
}

/// Der Wiederholversuch nach JEDEM Abbruch laeuft auf denselben Kopf wie ein
/// ungestoerter Lauf — mit derselben Adressmenge und denselben Blobbytes.
#[test]
fn every_retry_after_an_interruption_lands_idempotently_on_the_same_head() {
    let undisturbed = {
        let harness = ReaderSyncHarness::fresh();
        harness.pull().expect("der ungestoerte Lauf traegt");
        SyncOutcome::of(&harness)
    };
    let expected_head = fixtures::batch_end_head();
    assert_eq!(
        undisturbed.entry_hash,
        *expected_head.entry_hash().as_bytes()
    );
    assert!(
        undisturbed.cached_keys.len() > 1,
        "die Kulisse muss mehrere Objekte cachen, sonst misst der Bytevergleich nichts"
    );

    for run in every_declared_run() {
        let name = run.label();
        let mut harness = ReaderSyncHarness::fresh();
        let _ = stage_and_interrupt(&mut harness, run);

        let mut reopened = harness.reopen_store();
        if run == Interruption::Refusal(fixtures::FORK_AT_THE_HEAD) {
            let recovered = retry_after_a_refused_fork(&mut reopened);
            assert_eq!(
                SyncOutcome::of(&recovered),
                undisturbed,
                "der Wiederaufbau nach `{name}` endete anders als der ungestoerte Lauf"
            );
            assert_eq!(recovered.confirmed_head(), expected_head);
            continue;
        }
        reopened.pull().unwrap_or_else(|error| {
            panic!("der Wiederholversuch nach `{name}` scheiterte: {error}")
        });
        assert_eq!(
            SyncOutcome::of(&reopened),
            undisturbed,
            "der Wiederholversuch nach `{name}` endete anders als der ungestoerte Lauf"
        );
        assert_eq!(reopened.confirmed_head(), expected_head);
    }
}

/// Der EINE gemessene Befund, an dem der Wiederholversuch NICHT auf denselben
/// Kopf laeuft: der abgewiesene Fork.
///
/// Das Bracket von `refusal-leaves-the-cursor` sagte in seiner Erstfassung,
/// keiner der vier Abweisungsgruende „bewegt Zustand". Fuer den CURSOR stimmt
/// das, und `every_declared_interruption_leaves_the_confirmed_cursor_where_it_was`
/// misst es. Fuer den CACHE stimmt es nicht, und seit dem 2026-09-05 sagt das
/// Bracket beides: `accept_batch`
/// (`crates/ea-reader/src/sync.rs`, Objektschleife vor `classify`) legt jedes
/// Objekt ab, dessen Bytes seine Adresse tragen — und der konkurrierende
/// Genesis-Eintrag traegt sie, er ist vollstaendig gueltig signiert. Erst der
/// Verifikationslauf danach meldet den Fork und weist ab. Der Eintrag bleibt
/// im inhaltsadressierten Cache, `ReaderObjectCache` kennt kein Entfernen, und
/// jeder ehrliche Wiederholversuch verifiziert den GESAMTEN lokalen Bestand
/// erneut in denselben Fork. Auch `rebuild_from_genesis` hilft nicht: es setzt
/// den Cursor auf den Kopf, den der Verifizierer ueber dem verforkten Bestand
/// noch ausweist (gemessen: Sequenz 1), den Bestand selbst raeumt es nicht,
/// und der naechste Lauf forkt erneut. Weil dieser Wiederaufbau eine
/// ABSICHTLICHE Ruecksetzung ist, die den Cursor schreiben DARF, steht die
/// Zusicherung „der abgewiesene Wiederholversuch bewegt den Cursor nicht"
/// davor und nicht dahinter.
///
/// Was zurueck auf den Kopf fuehrt, ist der Cacheverlust — der Weg, den
/// `sync_resume.rs::a_lost_cache_rebuilds_from_genesis_to_the_same_head` fuer
/// den unverschuldeten Verlust belegt. Dieser Zeuge haelt beides fest, damit
/// eine Aenderung in BEIDE Richtungen rot wird: ein Reader, der den Fork nicht
/// mehr im Cache behaelt, laesst die erste Zusicherung fallen; einer, der ihn
/// auch nach dem Cacheverlust wiederfindet, die zweite.
fn retry_after_a_refused_fork(reopened: &mut ReaderSyncHarness) -> ReaderSyncHarness {
    let before = reopened.confirmed_cursor();
    assert_eq!(
        reopened
            .pull()
            .expect_err("der konkurrierende Eintrag liegt im Cache, der Wiederholversuch forkt")
            .code(),
        "EA-READER-CHAIN-FORK"
    );
    assert_eq!(
        reopened.confirmed_cursor(),
        before,
        "auch der abgewiesene Wiederholversuch bewegt den Cursor nicht"
    );
    assert_eq!(
        reopened
            .rebuild_from_genesis()
            .expect_err("der Wiederaufbau ohne Cacheverlust forkt ebenso")
            .code(),
        "EA-READER-CHAIN-FORK"
    );
    let erased = reopened.erase_blob_store();
    erased
        .rebuild_from_genesis()
        .expect("nach dem Cacheverlust laeuft der Wiederaufbau ab Genesis durch");
    erased
}
