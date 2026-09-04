//! Die Reader-Ansichten: der EINE geoeffnete Bestand und seine sechs
//! Ausfuhren.
//!
//! # Der Bestand muss das Oeffnen ueberleben
//!
//! GEMESSEN vor dieser Aufgabe: die zwei Oeffnungsausfuhren in
//! [`crate::file_access`] renderten `file_mode_archive_json` und liessen den
//! `OpenedArchiveV1` fallen — es gab keinen sitzungsgebundenen Bestand, aus
//! dem `readerEntryView` je haette lesen koennen. Dieses Modul fuehrt ihn
//! deshalb in einem `thread_local!`, in derselben Bauform wie `VAULT_SESSIONS`
//! in [`crate::vault_bridge`]: der Worker ist einfaedig, und alle Ausfuhren
//! muessen denselben Faden sehen.
//!
//! # Die Reihenfolge bleibt wortgleich
//!
//! [`build_stand`] bekommt einen FERTIG klassifizierten Bestand. Tor 9 und die
//! HPKE-Oeffnung laufen ERST hier, NACH der vollstaendigen Klassifikation, und
//! nur ueber die Zeugenpaare, die [`ea_reader::ReaderClassification`]
//! herausgibt — `web-reader-design.md` §14.1 steht damit in den Typen:
//! [`ea_reader::decrypt_verified`] ist mit nichts anderem formulierbar.
//!
//! # Was die Grenze ueberquert
//!
//! JSON, hand-gebaut ueber [`crate::bridge::Json`] wie jede Ausfuhr dieser
//! Crate. Die Klartexte liegen ausschliesslich in `SecretVec` innerhalb der
//! [`ea_reader::VerifiedDecryptedRecord`]-Werte, die Faeden und Karte hier
//! BESITZEN, und verlassen das Modul nur als die vier Felder von
//! `ReaderIncidentView` — Einsatznummer, Startzeit, Zeitzone, Stichwort — und
//! als die vier Felder eines Suchtreffers. Kein `Debug` gibt sie heraus;
//! [`ReaderStand`] traegt keines.
//!
//! # `incident: null` ist eine Aussage und kein leerer Einsatz
//!
//! `design.md` §17.2: Einsatznummer, Einsatzzeit und Stichwort erscheinen ERST
//! nach erfolgreicher lokaler Entschluesselung. `null` sagt genau das. Es gilt
//! fuer `fehlender Grant` und `unbekannter Schluessel` ebenso wie fuer einen
//! entschluesselten Datensatz OHNE Einsatznutzlast: Genesis,
//! Schluesseluebergang, Vernichtungsnachweis — und der Nachtrag, dessen
//! Nutzlast keine eigene Einsatzzeit und kein eigenes Stichwort traegt. Ein
//! Nachtrag zeigt seinen technischen Zustand; sein Zusammenhang steht im
//! Faden.
//!
//! # Die Integritaetsleiste erfindet keinen Knoten
//!
//! Siehe [`chain_nodes`]. Sie ist eine Aussage ueber den BESTAND, und sie
//! entsteht aus zwei Signalen: dem Protokoll des `RecordingObserver` und den
//! Fehlerkanaelen des Berichts.
//!
//! # Was im SERVER-Modus fehlt — BENANNTE GRENZE
//!
//! Diese Aufgabe fuellt den Bestand NICHT aus dem OPFS-Cache: der
//! Cache-Einstieg gehoert in dieselbe Hand wie der Wiederherstellungseinstieg
//! (`rebuild_from_genesis`). Ohne Bestand gibt `readerStandView` `null`
//! heraus, und die Oberflaeche zeigt den technischen Zustand „kein Bestand
//! geoeffnet" — nie einen leeren Einsatz.

use core::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use ea_reader::{
    AmendmentJoinErrorV1, EntryHash, Gate, IndexError, ObjectHash, OpenedArchiveV1, PayloadV1,
    ReaderClassification, ReaderEntryStateV1, ReaderEntryThread, ReaderError, ReaderQueryV1,
    ReaderSearch, ReaderSearchHitV1, RecordId, RecordingObserver, SchemaRegistry,
    ServerConfirmationV1, UnixMillis, UnlockedVault, VerificationReportV1, VerificationStatus,
    VerifiedDecryptedRecord, decrypt_verified,
};

use crate::bridge::{Json, quoted};
use crate::file_access::ConfirmationTally;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// Die Codes dieses Moduls
// ---------------------------------------------------------------------------

/// Es ist kein Bestand geoeffnet.
///
/// Ein Aufruffehler und kein Befund ueber ein Archiv — dieselbe Trennung wie
/// `EA-READER-FILE-MODE-BRIDGE-ARGUMENT` in [`crate::file_access`].
pub const EA_READER_VIEW_NO_STAND: &str = "EA-READER-VIEW-NO-STAND";

/// Der Eintragshash ist keine Zustandszeile dieses Bestands — oder gar kein
/// Hash.
pub const EA_READER_VIEW_UNKNOWN_ENTRY: &str = "EA-READER-VIEW-UNKNOWN-ENTRY";

/// Der Eintrag ist bekannt, traegt aber kein VERIFIZIERTES Manifest, aus dem
/// eine technische Ansicht lesbar waere.
///
/// Zwei Faelle, EIN Code, weil die Aussage dieselbe ist: ein `.eds`-Stummel
/// hat kein Eintragspaket im Inventar, und ein `ungueltiges` Objekt hat eines,
/// dessen Bytes nicht authentisch sind — „aus unauthentischen Bytes stammen
/// nur Zaehler und Fehlereintraege, niemals Sachaussagen" (`ea-verify`). Beide
/// erscheinen unter `Pruefprobleme` beziehungsweise als `Luecke`, nie als
/// technische Ansicht.
pub const EA_READER_VIEW_NO_MANIFEST: &str = "EA-READER-VIEW-NO-MANIFEST";

/// Der Eintrag ist bekannt, gehoert aber keinem Original/Nachtrag-Faden an.
pub const EA_READER_VIEW_NO_THREAD: &str = "EA-READER-VIEW-NO-THREAD";

/// Der Grund einer Abweisung als stabiler Code.
///
/// `AmendmentJoinErrorV1` traegt keinen `code()`; der Faden ist eine
/// Projektion und keine Fehlerflaeche. Das DTO verlangt eine Zeichenkette, und
/// eine `Debug`-Formatierung waere ein Vertrag, den niemand versprochen hat.
/// Die Zuordnung ist ERSCHOEPFEND: eine neue Variante bricht die Uebersetzung
/// hier und nicht still die Oberflaeche.
const fn join_error_code(reason: AmendmentJoinErrorV1) -> &'static str {
    match reason {
        AmendmentJoinErrorV1::NotAnIncident => "EA-READER-AMENDMENT-NOT-AN-INCIDENT",
        AmendmentJoinErrorV1::NotAnAmendment => "EA-READER-AMENDMENT-NOT-AN-AMENDMENT",
        AmendmentJoinErrorV1::OriginalRecordIdMismatch => {
            "EA-READER-AMENDMENT-ORIGINAL-RECORD-ID-MISMATCH"
        }
        AmendmentJoinErrorV1::OriginalEntryHashMismatch => {
            "EA-READER-AMENDMENT-ORIGINAL-ENTRY-HASH-MISMATCH"
        }
        AmendmentJoinErrorV1::OriginalSequenceMismatch => {
            "EA-READER-AMENDMENT-ORIGINAL-SEQUENCE-MISMATCH"
        }
        AmendmentJoinErrorV1::IncidentNumberMismatch => {
            "EA-READER-AMENDMENT-INCIDENT-NUMBER-MISMATCH"
        }
        AmendmentJoinErrorV1::DuplicateSequence => "EA-READER-AMENDMENT-DUPLICATE-SEQUENCE",
    }
}

/// Das Praefix der vier Codes von `ea_verify::ManifestSignatureErrorV1`.
///
/// `signatureErrors` ist EIN Kanal fuer VIER Tore: Gate `manifest-signature`
/// schreibt die Manifestcodes unter den Eintrags-Objekthash, Gate `grant-plan`
/// seine `EA-GRANT-*`- und `EA-VERIFY-GRANT-PLAN-*`-Codes unter DENSELBEN
/// Adressraum, Gate `receipt` Checkpointcodes unter den Checkpointhash und
/// Gate `recipient-grant` unter den Granthash (`crates/ea-verify/src/archive.rs`).
/// Objektart trennt drei davon; die zwei Tore ueber dem Eintragshash trennt
/// allein der Code. `confirm_entries` gibt einem Eintrag mit Befund KEIN
/// Objektergebnis, ein zweites Unterscheidungsmerkmal gibt es also nicht.
const MANIFEST_SIGNATURE_CODE_PREFIX: &str = "EA-VERIFY-MANIFEST-";

// ---------------------------------------------------------------------------
// Der Bestand
// ---------------------------------------------------------------------------

/// Wo der entschluesselte Datensatz eines Eintrags liegt.
///
/// `VerifiedDecryptedRecord` traegt kein `Clone`; die Faeden BESITZEN ihre
/// Datensaetze, und dieser Index ist der Weg von einem Eintragshash zu ihnen.
#[derive(Clone, Copy)]
enum RecordLocation {
    /// Das Original des Fadens an dieser Stelle.
    Original(usize),
    /// Der Nachtrag `amendment` im Faden `thread`.
    Amendment { thread: usize, amendment: usize },
    /// Ein Datensatz ohne Faden: Genesis, Schluesseluebergang,
    /// Vernichtungsnachweis, oder ein Nachtrag, dessen Original nicht
    /// entschluesselt wurde.
    Other,
}

/// Ein Knoten der Integritaetsleiste.
struct ChainNode {
    gate: Gate,
    verified: bool,
    detail: Option<&'static str>,
}

/// Der EINE geoeffnete Bestand: Klassifikation, Klartexte, Index und Faeden.
///
/// Kein `Debug` und kein `Clone` — derselbe Grund wie bei
/// [`ea_reader::ReaderEntryThread`]: die Faeden halten Klartext in
/// `SecretVec`, und beide Ableitungen waeren ein Ausgabe- beziehungsweise
/// Vervielfaeltigungsweg. Beim Fallen zeroisiert jeder `SecretVec` sich
/// selbst; [`close_stand`] ist deshalb ein blosses `take()`.
pub struct ReaderStand {
    opened: OpenedArchiveV1,
    threads: Vec<ReaderEntryThread>,
    others: BTreeMap<EntryHash, VerifiedDecryptedRecord>,
    located: BTreeMap<EntryHash, RecordLocation>,
    search: ReaderSearch,
    /// Was die Entschluesselung ueber eine Zustandszeile HINAUS gesagt hat.
    ///
    /// `classify` entschluesselt nichts; der sechste Begriff aus §17.4,
    /// `nicht darstellbares Schema`, entsteht erst hier, wenn ein Klartext
    /// vorliegt und keine Schemabestimmung ihn traegt (der Modulkommentar
    /// von `the_measured_states` in `verify_fixtures` misst genau das). Jeder
    /// ANDERE Fehlschlag trotz Zeugenpaar — CEK-Entkapselung, AEAD-Oeffnung,
    /// veralteter Zeuge — ist ein Objekt, das seine Zusage nicht haelt, und
    /// faellt fail-closed auf `ungueltig`. Beide tragen ihren Code.
    decryption_verdicts: BTreeMap<EntryHash, (VerificationStatus, &'static str)>,
    chain: Vec<ChainNode>,
    server_confirmation: ServerConfirmationV1,
}

impl ReaderStand {
    /// Der geoeffnete Bestand, unveraendert.
    ///
    /// Die zwei Oeffnungsausfuhren rendern `FileModeArchiveView` weiterhin
    /// hierueber, byteidentisch zur Fassung vor dieser Aufgabe.
    #[must_use]
    pub const fn opened(&self) -> &OpenedArchiveV1 {
        &self.opened
    }

    /// Verifikationsbegriff und Detailcode einer Zustandszeile, NACH der
    /// Entschluesselung.
    ///
    /// Die Zeile selbst bleibt unveraendert; was hier dazukommt, ist das
    /// Urteil des Schritts, den `classify` nicht gehen konnte.
    fn effective(&self, state: &ReaderEntryStateV1) -> (VerificationStatus, Option<&'static str>) {
        self.decryption_verdicts.get(&state.entry_hash()).map_or(
            (state.verification(), state.detail_code()),
            |(status, code)| (*status, Some(code)),
        )
    }

    /// Der Datensatz eines Eintrags, sofern er entschluesselt wurde.
    fn record_of(&self, entry_hash: EntryHash) -> Option<&VerifiedDecryptedRecord> {
        match *self.located.get(&entry_hash)? {
            RecordLocation::Original(thread) => {
                self.threads.get(thread).map(ReaderEntryThread::original)
            }
            RecordLocation::Amendment { thread, amendment } => self
                .threads
                .get(thread)
                .and_then(|thread| thread.amendments().get(amendment)),
            RecordLocation::Other => self.others.get(&entry_hash),
        }
    }

    /// Der Faden, dem ein Eintrag angehoert — als Original oder als Nachtrag.
    fn thread_of(&self, entry_hash: EntryHash) -> Option<&ReaderEntryThread> {
        match *self.located.get(&entry_hash)? {
            RecordLocation::Original(thread) | RecordLocation::Amendment { thread, .. } => {
                self.threads.get(thread)
            }
            RecordLocation::Other => None,
        }
    }
}

/// Die drei Referenzen, mit denen ein Nachtrag sein Original benennt.
///
/// Sie dienen hier AUSSCHLIESSLICH der Vorsortierung: welcher Faden einen
/// Kandidaten ueberhaupt zu sehen bekommt. Die Vergleiche selbst fuehrt
/// `ReaderEntryThread::build`. Ein Kandidat gehoert zu dem Original, auf das
/// IRGENDEINE der drei zeigt — nur so erreicht ein Nachtrag mit fremder
/// `originalRecordId`, aber richtigem Eintragshash den Faden und faellt dort
/// als `OriginalRecordIdMismatch`; eine Vorsortierung allein ueber die
/// Kennung liesse genau dieses Pruefproblem still verschwinden (GEMESSEN am
/// Nachtragsbestand: Sequenz fuenf fehlte unter `rejected`). Zeigt keine der
/// drei auf ein entschluesseltes Original, hat der Nachtrag keinen Faden.
#[derive(Clone, Copy)]
struct AmendmentReferences {
    original_record_id: RecordId,
    original_entry_hash: EntryHash,
    original_sequence: ea_reader::ChainSequence,
}

impl AmendmentReferences {
    fn points_at(&self, original: &VerifiedDecryptedRecord, record_id: RecordId) -> bool {
        self.original_record_id == record_id
            || self.original_entry_hash == original.entry_hash()
            || self.original_sequence == original.chain_sequence()
    }
}

/// Die Nutzlastart eines entschluesselten Datensatzes, soweit der Faden sie
/// braucht.
enum RecordKind {
    Incident,
    Amendment(AmendmentReferences),
    Other,
}

fn kind_of(record: &VerifiedDecryptedRecord) -> RecordKind {
    record.with_payload(|payload| match payload {
        PayloadV1::Incident(_) => RecordKind::Incident,
        PayloadV1::Amendment(amendment) => RecordKind::Amendment(AmendmentReferences {
            original_record_id: amendment.original_record_id(),
            original_entry_hash: amendment.original_entry_hash(),
            original_sequence: amendment.original_sequence(),
        }),
        PayloadV1::Genesis(_) | PayloadV1::KeyTransition(_) | PayloadV1::DestructionEvidence(_) => {
            RecordKind::Other
        }
    })
}

fn incident_record_id(record: &VerifiedDecryptedRecord) -> Option<RecordId> {
    record.with_payload(|payload| match payload {
        PayloadV1::Incident(incident) => Some(incident.header().record_id()),
        _ => None,
    })
}

/// Baut den Bestand ueber einem fertig klassifizierten Archiv.
///
/// Die REINE Haelfte: sie uebersetzt auf jedem Ziel und ist der Zeuge in
/// `tests/view_dto.rs`. Entschluesselt wird jeder Eintrag, fuer den
/// [`ea_reader::ReaderClassification`] BEIDE Zeugen herausgibt; ein
/// Fehlschlag dabei ist ein Pruefproblem mit seinem Code und bricht den
/// Bestand nicht ab. Der Index nimmt jeden Datensatz entgegen und weist die
/// ohne fachliche Zeile (`EA-READER-SCHEMA-UNSUPPORTED`) still ab — das ist
/// die Aussage „kein Einsatz" und kein Problem.
///
/// `observer_events` ist das Protokoll, unter dem `opened` entstand; die
/// Leiste liest daraus, welche Tore BETRETEN wurden.
#[must_use]
pub fn build_stand(
    opened: OpenedArchiveV1,
    vault: &UnlockedVault,
    effective_now: UnixMillis,
    observer_events: &[&'static str],
) -> ReaderStand {
    let classification = opened.classification();
    let schemas = SchemaRegistry::v1();

    let mut decrypted: Vec<VerifiedDecryptedRecord> = Vec::new();
    let mut decryption_verdicts: BTreeMap<EntryHash, (VerificationStatus, &'static str)> =
        BTreeMap::new();
    for state in classification.states() {
        let entry_hash = state.entry_hash();
        let (Some(entry), Some(grant)) = (
            classification.verified_entry(entry_hash),
            classification.verified_grant(entry_hash),
        ) else {
            continue;
        };
        let mut observer = RecordingObserver::new();
        match decrypt_verified(entry, grant, vault, &schemas, effective_now, &mut observer) {
            Ok(record) => decrypted.push(record),
            Err(error) => {
                let status = match error {
                    ReaderError::UnsupportedSchema => VerificationStatus::UnsupportedSchema,
                    ReaderError::Verify(_)
                    | ReaderError::Format(_)
                    | ReaderError::Decryption(_)
                    | ReaderError::StaleWitness => VerificationStatus::Invalid,
                };
                decryption_verdicts.insert(entry_hash, (status, error.code()));
            }
        }
    }

    let mut search = ReaderSearch::empty();
    for record in &decrypted {
        // `Err` ist hier ausschliesslich `EA-READER-SCHEMA-UNSUPPORTED`: das
        // Paket traegt keine fachliche Zeile. Das ist kein Befund.
        let _ = search.index(record);
    }

    // Partition nach Nutzlast. Die Kandidaten je Original werden VOR dem
    // Faden ueber die `originalRecordId` vorsortiert; die vier Vergleiche
    // selbst fuehrt `ReaderEntryThread::build` und niemand hier.
    let mut originals: Vec<VerifiedDecryptedRecord> = Vec::new();
    let mut amendments: Vec<(AmendmentReferences, VerifiedDecryptedRecord)> = Vec::new();
    let mut others: BTreeMap<EntryHash, VerifiedDecryptedRecord> = BTreeMap::new();
    for record in decrypted {
        match kind_of(&record) {
            RecordKind::Incident => originals.push(record),
            RecordKind::Amendment(references) => amendments.push((references, record)),
            RecordKind::Other => {
                others.insert(record.entry_hash(), record);
            }
        }
    }
    originals.sort_by_key(|record| (record.chain_sequence(), record.entry_hash()));

    let mut threads: Vec<ReaderEntryThread> = Vec::new();
    let mut located: BTreeMap<EntryHash, RecordLocation> = BTreeMap::new();
    for original in originals {
        let Some(record_id) = incident_record_id(&original) else {
            // Unerreichbar: `kind_of` hat die Nutzlast gerade als Einsatz
            // bestimmt. Fail-closed ohne Faden statt `expect`.
            others.insert(original.entry_hash(), original);
            continue;
        };
        // Originale laufen in `(chain_sequence, entry_hash)`-Ordnung; ein
        // Kandidat, der auf zwei Originale zeigte, ginge deshalb reproduzierbar
        // an das fruehere.
        let (mine, rest): (Vec<_>, Vec<_>) = amendments
            .into_iter()
            .partition(|(references, _)| references.points_at(&original, record_id));
        amendments = rest;
        let candidates: Vec<VerifiedDecryptedRecord> =
            mine.into_iter().map(|(_, record)| record).collect();
        // `build` faellt NUR mit `NotAnIncident`, und die Nutzlast ist hier
        // ein Einsatz; der Arm ist durch Konstruktion unerreichbar. Traefe er
        // doch, bliebe die Zustandszeile stehen und `incident` waere `null` —
        // fail-closed und ohne `expect`.
        if let Ok(thread) = ReaderEntryThread::build(original, candidates) {
            let index = threads.len();
            located.insert(
                thread.original().entry_hash(),
                RecordLocation::Original(index),
            );
            for (amendment, record) in thread.amendments().iter().enumerate() {
                located.insert(
                    record.entry_hash(),
                    RecordLocation::Amendment {
                        thread: index,
                        amendment,
                    },
                );
            }
            threads.push(thread);
        }
    }
    // Nachtraege ohne entschluesseltes Original: kein Faden, aber ein
    // entschluesselter Datensatz mit technischem Zustand.
    for (_, record) in amendments {
        others.insert(record.entry_hash(), record);
    }
    for entry_hash in others.keys() {
        located.insert(*entry_hash, RecordLocation::Other);
    }

    let report = classification.report();
    let chain = chain_nodes(classification, observer_events);
    let server_confirmation = ConfirmationTally::over(
        report
            .object_results()
            .map(ea_reader::ObjectResultV1::server_confirmation),
    )
    .archive_wide;

    ReaderStand {
        opened,
        threads,
        others,
        located,
        search,
        decryption_verdicts,
        chain,
        server_confirmation,
    }
}

// ---------------------------------------------------------------------------
// Die Integritaetsleiste
// ---------------------------------------------------------------------------

/// Das Urteil ueber EIN Tor, soweit die zwei Signale es tragen.
enum Verdict {
    Passed,
    Failed(Option<&'static str>),
    /// Der Bericht traegt einen Befund, den er keinem Tor zuordnet.
    Unknown,
}

/// Leitet die Knoten der Leiste aus Protokoll und Bericht ab.
///
/// `VerificationReportV1` traegt kein Tor-Feld, und drei der neun Tore
/// (`registry`, `grant-plan`, `receipt`) haben keinen eigenen Fehlerkanal.
/// Der `RecordingObserver` meldet je Lauf den EINTRITT in eine STUFE, nicht je
/// Objekt (`StageProtocol` in `crates/ea-verify/src/gates.rs`); das Protokoll
/// ist damit stets ein Praefix von `GATE_ORDER_V1`, und es sagt, welche Tore
/// BETRETEN wurden — ein betretenes Tor ist noch kein bestandenes, weil die
/// archivweite Pipeline einen Objektbefund nicht abbrechen laesst. Der
/// EINZIGE Fruehausstieg ist Gate `trust`: traegt es nicht, wird `registry`
/// nie betreten.
///
/// Die Regel:
/// - `is_fully_verified()` ⇒ alle neun Tore `true`.
/// - sonst, in Torreihenfolge: jedes betretene Tor VOR dem ersten belegten
///   Fehler `true`; das fehlgeschlagene `false` mit seinem Code als `detail`
///   (oder `null`, wo der Bericht keinen Code kennt: `trust` und
///   `chain-position`); und KEIN Knoten dahinter.
/// - Ein Quarantaenebefund, der mit keinem Formatfehler gepaart ist, laesst
///   sich keinem Tor zuordnen — `unattributable` entsteht in `registry` UND
///   hinter `manifest-signature`, `conflicting` in `receipt` —, und die
///   Leiste endet dann VOR `registry`, dem fruehesten Tor, das ihn tragen
///   koennte. Im Zweifel weniger Knoten.
///
/// Die Zuordnung der Kanaele: `formatErrors` → `format`; kein `registry` im
/// Protokoll → `trust`; `signatureErrors` ueber einem Eintragshash mit
/// [`MANIFEST_SIGNATURE_CODE_PREFIX`] → `manifest-signature`, mit anderem Code
/// → `grant-plan`; `gaps` → `chain-position`; `signatureErrors` ueber einem
/// Objekt, das weder Eintrag noch Grant ist → `receipt`; `evidenceErrors` →
/// `evidence`; `decryptionErrors` und `signatureErrors` ueber einem Granthash
/// → `recipient-grant`.
fn chain_nodes(
    classification: &ReaderClassification,
    observer_events: &[&'static str],
) -> Vec<ChainNode> {
    let report: &VerificationReportV1 = classification.report();
    let inventory = classification.inventory();
    if report.is_fully_verified() {
        return Gate::ALL
            .into_iter()
            .map(|gate| ChainNode {
                gate,
                verified: true,
                detail: None,
            })
            .collect();
    }

    let entered = |gate: Gate| observer_events.contains(&gate.name());
    let entry_hashes: BTreeSet<ObjectHash> = inventory
        .entries()
        .iter()
        .map(|entry| entry.object_hash())
        .collect();
    let grant_hashes: BTreeSet<ObjectHash> = inventory
        .grants()
        .iter()
        .map(|grant| grant.object_hash())
        .collect();
    let format_error_hashes: BTreeSet<ObjectHash> = report
        .format_errors()
        .map(ea_reader::ObjectErrorV1::object_hash)
        .collect();
    let unattributed_quarantine = report
        .quarantined_objects()
        .any(|quarantined| !format_error_hashes.contains(&quarantined.object_hash()));
    let signature_error = |select: &dyn Fn(ObjectHash, &'static str) -> bool| {
        report
            .signature_errors()
            .find(|error| select(error.object_hash(), error.code()))
            .map(ea_reader::ObjectErrorV1::code)
    };

    let mut nodes = Vec::with_capacity(Gate::ALL.len());
    for gate in Gate::ALL {
        if !entered(gate) {
            break;
        }
        let verdict = match gate {
            Gate::Format => report
                .format_errors()
                .next()
                .map_or(Verdict::Passed, |error| Verdict::Failed(Some(error.code()))),
            Gate::Trust => {
                if entered(Gate::Registry) {
                    Verdict::Passed
                } else {
                    Verdict::Failed(None)
                }
            }
            Gate::Registry => {
                if unattributed_quarantine {
                    Verdict::Unknown
                } else {
                    Verdict::Passed
                }
            }
            Gate::ManifestSignature => signature_error(&|hash, code| {
                entry_hashes.contains(&hash) && code.starts_with(MANIFEST_SIGNATURE_CODE_PREFIX)
            })
            .map_or(Verdict::Passed, |code| Verdict::Failed(Some(code))),
            Gate::ChainPosition => {
                if report.gaps().len() > 0 {
                    Verdict::Failed(None)
                } else {
                    Verdict::Passed
                }
            }
            Gate::GrantPlan => signature_error(&|hash, code| {
                entry_hashes.contains(&hash) && !code.starts_with(MANIFEST_SIGNATURE_CODE_PREFIX)
            })
            .map_or(Verdict::Passed, |code| Verdict::Failed(Some(code))),
            Gate::Receipt => signature_error(&|hash, _| {
                !entry_hashes.contains(&hash) && !grant_hashes.contains(&hash)
            })
            .map_or(Verdict::Passed, |code| Verdict::Failed(Some(code))),
            Gate::Evidence => report
                .evidence_errors()
                .next()
                .map_or(Verdict::Passed, |error| Verdict::Failed(Some(error.code()))),
            Gate::RecipientGrant => report
                .decryption_errors()
                .next()
                .map(ea_reader::ObjectErrorV1::code)
                .or_else(|| signature_error(&|hash, _| grant_hashes.contains(&hash)))
                .map_or(Verdict::Passed, |code| Verdict::Failed(Some(code))),
        };
        match verdict {
            Verdict::Passed => nodes.push(ChainNode {
                gate,
                verified: true,
                detail: None,
            }),
            Verdict::Failed(detail) => {
                nodes.push(ChainNode {
                    gate,
                    verified: false,
                    detail,
                });
                break;
            }
            Verdict::Unknown => break,
        }
    }
    nodes
}

// ---------------------------------------------------------------------------
// Die JSON-Renderer: die reine Haelfte jeder Ausfuhr
// ---------------------------------------------------------------------------

fn hex_of(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn optional_string(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_owned(), quoted)
}

fn array_of(items: impl Iterator<Item = String>) -> String {
    let mut out = String::from("[");
    for (index, item) in items.enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&item);
    }
    out.push(']');
    out
}

/// `ReaderEntryStateView`, Feld fuer Feld aus `ReaderEntryStateV1` — mit dem
/// Verifikationsbegriff NACH der Entschluesselung ([`ReaderStand::effective`]).
fn state_json(stand: &ReaderStand, state: &ReaderEntryStateV1) -> String {
    let (verification, detail_code) = stand.effective(state);
    let mut json = Json::object();
    json.string("entryHash", &hex_of(state.entry_hash().as_bytes()));
    json.string("objectHash", &hex_of(state.object_hash().as_bytes()));
    json.raw("sequence", &state.sequence().get().to_string());
    json.string("verification", verification.label());
    json.string("entryState", state.entry_state().label());
    json.string("serverConfirmation", state.server_confirmation().label());
    json.raw("detailCode", &optional_string(detail_code));
    json.finish()
}

/// `ReaderIncidentView` aus einem entschluesselten EINSATZ — oder `null`.
///
/// Der einzige Ort, an dem ein Klartextwert das Modul verlaesst. Die
/// Projektion laeuft INNERHALB von `with_payload`; die Nutzlast selbst
/// ueberquert nichts. Das Stichwort ist der freie Text oder der ANZEIGETEXT
/// des Referenzarms — dieselbe Wahl wie `keyword_terms` in
/// `crates/ea-reader/src/search.rs`, damit Anzeige und Suche dasselbe Wort
/// kennen.
fn incident_json(record: Option<&VerifiedDecryptedRecord>) -> String {
    let Some(record) = record else {
        return "null".to_owned();
    };
    record.with_payload(|payload| {
        let PayloadV1::Incident(incident) = payload else {
            return "null".to_owned();
        };
        let keyword = incident.keyword();
        let keyword_text = keyword
            .as_free_text()
            .or_else(|| keyword.as_reference().map(|(_, display_text)| display_text))
            .unwrap_or_default();
        let mut json = Json::object();
        json.string("incidentNumber", incident.human_incident_number());
        json.raw(
            "occurredAtStartMs",
            &incident.occurred_at().start().get().to_string(),
        );
        json.string("timezone", incident.header().timezone());
        json.string("keyword", keyword_text);
        json.finish()
    })
}

/// `ReaderEntryView` ueber einer Zustandszeile des Bestands.
fn entry_view_json(stand: &ReaderStand, state: &ReaderEntryStateV1) -> String {
    let mut json = Json::object();
    json.raw("state", &state_json(stand, state));
    json.raw(
        "incident",
        &incident_json(stand.record_of(state.entry_hash())),
    );
    json.finish()
}

/// Die Ansicht EINES Eintrags.
///
/// # Errors
/// [`EA_READER_VIEW_UNKNOWN_ENTRY`], wenn der Hash keine Zustandszeile dieses
/// Bestands ist.
pub fn entry_json(stand: &ReaderStand, entry_hash: EntryHash) -> Result<String, &'static str> {
    let state = stand
        .opened
        .classification()
        .state_of(entry_hash)
        .ok_or(EA_READER_VIEW_UNKNOWN_ENTRY)?;
    Ok(entry_view_json(stand, state))
}

/// Die technische Ansicht EINES Eintrags, Feld fuer Feld aus dem Manifest des
/// Eintragspakets und aus dem Bericht.
///
/// Gelesen wird ausschliesslich ein Manifest, dessen Signatur Gate
/// `manifest-signature` getragen hat: jede Zustandszeile ausser `ungueltig`
/// steht auf einem Eintrag mit gueltigem Objektergebnis (`classify_entry` in
/// `crates/ea-reader/src/verify.rs`). `evidenceDetailCode` ist der Code des
/// Berichts unter dem Objekthash dieses Eintrags — ein Eintrag mit
/// Evidence-Befund ist `ungueltig` und erreicht diese Ansicht nie; das Feld
/// steht trotzdem, weil der Vertrag es fuehrt und ein spaeterer Bericht es
/// fuellen kann.
///
/// # Errors
/// [`EA_READER_VIEW_UNKNOWN_ENTRY`] fuer einen unbekannten Hash,
/// [`EA_READER_VIEW_NO_MANIFEST`] fuer einen Stummel oder ein ungueltiges
/// Objekt.
pub fn technical_json(stand: &ReaderStand, entry_hash: EntryHash) -> Result<String, &'static str> {
    let classification = stand.opened.classification();
    let state = classification
        .state_of(entry_hash)
        .ok_or(EA_READER_VIEW_UNKNOWN_ENTRY)?;
    if stand.effective(state).0 == VerificationStatus::Invalid {
        return Err(EA_READER_VIEW_NO_MANIFEST);
    }
    let package = classification
        .inventory()
        .entries()
        .iter()
        .find(|entry| entry.object_hash() == state.object_hash())
        .ok_or(EA_READER_VIEW_NO_MANIFEST)?;
    let signed = package.value().signed_manifest();
    let fields = signed.manifest().fields();
    let evidence_detail = classification
        .report()
        .evidence_errors()
        .find(|error| error.object_hash() == state.object_hash())
        .map(ea_reader::ObjectErrorV1::code);

    let mut json = Json::object();
    json.raw("sequence", &fields.chain_sequence.get().to_string());
    json.raw(
        "previousEntryHash",
        &fields.previous_entry_hash.map_or_else(
            || "null".to_owned(),
            |hash| quoted(&hex_of(hash.as_bytes())),
        ),
    );
    json.string("entryHash", &hex_of(entry_hash.as_bytes()));
    json.string(
        "ciphertextHash",
        &hex_of(signed.ciphertext_hash().as_bytes()),
    );
    json.string(
        "writerCertificateHash",
        &hex_of(fields.writer_certificate_hash.as_bytes()),
    );
    json.raw(
        "registryVersion",
        &fields.registry_version.get().to_string(),
    );
    json.string("registryHeadHash", &hex_of(&fields.registry_head_hash));
    json.string("serverConfirmation", state.server_confirmation().label());
    json.raw("evidenceDetailCode", &optional_string(evidence_detail));
    Ok(json.finish())
}

/// `ReaderAmendmentThreadView` ueber dem Faden, dem ein Eintrag angehoert.
///
/// Der Hash darf der des Originals oder der eines beigetretenen Nachtrags
/// sein; beide fuehren zu demselben Faden, byteidentisch.
///
/// # Errors
/// [`EA_READER_VIEW_UNKNOWN_ENTRY`] fuer einen unbekannten Hash,
/// [`EA_READER_VIEW_NO_THREAD`] fuer einen Eintrag ohne Faden.
pub fn thread_json(stand: &ReaderStand, entry_hash: EntryHash) -> Result<String, &'static str> {
    let classification = stand.opened.classification();
    classification
        .state_of(entry_hash)
        .ok_or(EA_READER_VIEW_UNKNOWN_ENTRY)?;
    let thread = stand
        .thread_of(entry_hash)
        .ok_or(EA_READER_VIEW_NO_THREAD)?;
    let view_of = |record: &VerifiedDecryptedRecord| {
        classification
            .state_of(record.entry_hash())
            .map(|state| entry_view_json(stand, state))
    };
    let original = view_of(thread.original()).ok_or(EA_READER_VIEW_UNKNOWN_ENTRY)?;
    let amendments = array_of(thread.amendments().iter().filter_map(view_of));
    let rejected = array_of(thread.rejected().iter().map(|rejected| {
        let mut json = Json::object();
        json.string("entryHash", &hex_of(rejected.entry_hash.as_bytes()));
        json.raw("sequence", &rejected.chain_sequence.get().to_string());
        json.string("reason", join_error_code(rejected.reason));
        json.finish()
    }));

    let mut json = Json::object();
    json.raw("original", &original);
    json.raw("amendments", &amendments);
    json.raw("rejected", &rejected);
    Ok(json.finish())
}

fn hit_json(hit: &ReaderSearchHitV1) -> String {
    let mut json = Json::object();
    json.string("entryHash", &hex_of(hit.entry_hash().as_bytes()));
    json.raw("sequence", &hit.chain_sequence().get().to_string());
    json.string("incidentNumber", hit.human_incident_number());
    json.raw(
        "occurredAtStartMs",
        &hit.occurred_at_start().get().to_string(),
    );
    json.finish()
}

/// Die vier Filter, unveraendert an `ReaderSearch::search`; das Ergebnis ist
/// ein Array von `ReaderSearchHitView` in `(sequence, entryHash)`-Ordnung.
///
/// Eine leere Anfrage trifft den ganzen indizierten Bestand — die
/// Oberflaeche entscheidet, ob sie das anbietet.
///
/// # Errors
/// Durchgereicht aus `crates/ea-index`.
pub fn search_json(stand: &ReaderStand, query: &ReaderQueryV1) -> Result<String, IndexError> {
    let hits = stand.search.search(query)?;
    Ok(array_of(hits.iter().map(hit_json)))
}

/// `ReaderStandView` ueber dem ganzen Bestand.
///
/// `entries` traegt AUSSCHLIESSLICH Zustandszeilen, die nicht `ungueltig`
/// sind; ein ungueltiges Objekt lebt allein in `problems` (`design.md`
/// §17.2). `problems` ist nach Objekthash dedupliziert: die Zustandszeile
/// nennt den Wortlaut, und wo sie keinen Detailcode traegt, der Bericht aber
/// einen fuehrt, steht der des Berichts — ein Code ist eine Aussage mehr,
/// nicht eine andere.
#[must_use]
pub fn stand_json(stand: &ReaderStand) -> String {
    let classification = stand.opened.classification();
    let report = classification.report();

    let entries = array_of(
        classification
            .states()
            .iter()
            .filter(|state| stand.effective(state).0 != VerificationStatus::Invalid)
            .map(|state| entry_view_json(stand, state)),
    );

    let mut problems: BTreeMap<ObjectHash, (VerificationStatus, Option<&'static str>)> =
        BTreeMap::new();
    let mut note =
        |object_hash: ObjectHash, status: VerificationStatus, code: Option<&'static str>| {
            let slot = problems.entry(object_hash).or_insert((status, code));
            if slot.1.is_none() {
                slot.1 = code;
            }
        };
    for state in classification.states() {
        let (verification, detail_code) = stand.effective(state);
        if verification == VerificationStatus::Invalid {
            note(state.object_hash(), verification, detail_code);
        }
    }
    for error in report
        .format_errors()
        .chain(report.signature_errors())
        .chain(report.evidence_errors())
        .chain(report.decryption_errors())
    {
        note(
            error.object_hash(),
            VerificationStatus::Invalid,
            Some(error.code()),
        );
    }
    for quarantined in report.quarantined_objects() {
        note(quarantined.object_hash(), VerificationStatus::Invalid, None);
    }
    let problems = array_of(problems.iter().map(|(object_hash, (status, code))| {
        let mut json = Json::object();
        json.string("objectHash", &hex_of(object_hash.as_bytes()));
        json.string("verification", status.label());
        json.raw("detailCode", &optional_string(*code));
        json.finish()
    }));

    let chain = array_of(stand.chain.iter().map(|node| {
        let mut json = Json::object();
        json.string("label", node.gate.name());
        json.bool("verified", node.verified);
        json.raw("detail", &optional_string(node.detail));
        json.finish()
    }));

    let mut json = Json::object();
    json.raw("entries", &entries);
    json.raw("problems", &problems);
    json.raw("chain", &chain);
    json.bool("fullyVerified", report.is_fully_verified());
    json.string("serverConfirmation", stand.server_confirmation.label());
    json.finish()
}

// ---------------------------------------------------------------------------
// Der EINE Bestand des Fadens
// ---------------------------------------------------------------------------

thread_local! {
    /// Der geoeffnete Bestand dieses Workers — hoechstens einer.
    ///
    /// Dieselbe Bauform wie `VAULT_SESSIONS`; der `const`-Initialisierer ist
    /// Pflicht, sonst faellt `clippy::missing_const_for_thread_local` unter
    /// `-D warnings`.
    static CURRENT_STAND: RefCell<Option<ReaderStand>> = const { RefCell::new(None) };
}

/// Macht `stand` zum geoeffneten Bestand; ein vorheriger faellt dabei.
pub fn install_stand(stand: ReaderStand) {
    CURRENT_STAND.with(|current| {
        *current.borrow_mut() = Some(stand);
    });
}

/// Laesst den geoeffneten Bestand fallen.
///
/// Der EINE Aufruf, mit dem die Sitzungssperre der Aufgabe „Sitzungssperre,
/// Zeroize, authenticator-bestätigter Einzelexport und signiertes lokales
/// Audit" den Bestand beim Sperren loswird: jeder `SecretVec` darin
/// zeroisiert sich beim Fallen.
pub fn close_stand() {
    CURRENT_STAND.with(|current| {
        current.borrow_mut().take();
    });
}

/// Fuehrt eine Rechnung auf dem geoeffneten Bestand aus, oder `None`.
///
/// Die Ausleihe wird NIE ueber einen JS-Aufruf hinweg gehalten — dieselbe
/// Regel wie bei den Tresorsitzungen.
pub fn with_current_stand<R>(use_it: impl FnOnce(&ReaderStand) -> R) -> Option<R> {
    CURRENT_STAND.with(|current| current.borrow().as_ref().map(use_it))
}

/// `ReaderStandView` des geoeffneten Bestands, oder das Literal `null`.
#[must_use]
pub fn current_stand_json() -> String {
    with_current_stand(stand_json).unwrap_or_else(|| "null".to_owned())
}

/// Der Eintragshash aus seiner hexadezimalen Bruecken-Schreibweise.
///
/// Ein unparsbarer oder zu kurzer Wert ist ein unbekannter Eintrag — es gibt
/// keinen Bestand, in dem er stuende. `pub` als reine Haelfte der drei
/// eintragsbezogenen Ausfuhren, aus demselben Grund wie `file_mode_archive_json`.
#[must_use]
pub fn parse_entry_hash(entry_hash_hex: &str) -> Option<EntryHash> {
    let bytes = hex::decode(entry_hash_hex).ok()?;
    EntryHash::try_from(bytes.as_slice()).ok()
}

/// Die gemeinsame Form der drei eintragsbezogenen Ausfuhren.
#[cfg(target_arch = "wasm32")]
fn over_current_entry(
    entry_hash_hex: &str,
    render: impl FnOnce(&ReaderStand, EntryHash) -> Result<String, &'static str>,
) -> Result<String, JsValue> {
    let entry_hash = parse_entry_hash(entry_hash_hex)
        .ok_or_else(|| JsValue::from_str(EA_READER_VIEW_UNKNOWN_ENTRY))?;
    with_current_stand(|stand| render(stand, entry_hash))
        .ok_or_else(|| JsValue::from_str(EA_READER_VIEW_NO_STAND))?
        .map_err(JsValue::from_str)
}

/// Die Anfrage aus den fuenf Bruecken-Argumenten — die reine Haelfte von
/// `readerSearch`.
///
/// Leere Zeichenketten und fehlende Grenzen sind „kein Filter". Eine halbe
/// Zeitgrenze ist ein halboffener Zeitraum: die fehlende Seite wird auf den
/// Rand des Wertebereichs gesetzt, statt den Filter still fallen zu lassen.
#[must_use]
pub fn query_from(
    from_ms: Option<i64>,
    to_ms: Option<i64>,
    keyword: &str,
    vehicle: &str,
    person: &str,
) -> ReaderQueryV1 {
    let mut query = ReaderQueryV1::default();
    if from_ms.is_some() || to_ms.is_some() {
        query = query.and_period(
            UnixMillis::new(from_ms.unwrap_or(i64::MIN)),
            UnixMillis::new(to_ms.unwrap_or(i64::MAX)),
        );
    }
    if !keyword.is_empty() {
        query = query.and_keyword(keyword);
    }
    if !vehicle.is_empty() {
        query = query.and_vehicle(vehicle);
    }
    if !person.is_empty() {
        query = query.and_person(person);
    }
    query
}

// ---------------------------------------------------------------------------
// Die sechs Ausfuhren. JEDE traegt ihr eigenes `cfg(target_arch = "wasm32")`
// unmittelbar ueber ihrem Attribut — `every_wasm_bindgen_export_sits_behind_the
// _wasm32_cfg` liest das als Text und folgt keinem `mod`.
// ---------------------------------------------------------------------------

/// Der ganze Bestand als `ReaderStandView`, oder `null`, wenn keiner offen ist.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerStandView")]
#[must_use]
pub fn reader_stand_view() -> String {
    current_stand_json()
}

/// Die Ansicht EINES Eintrags als JSON-DTO.
///
/// `incident` ist `null`, solange nichts entschluesselt wurde — und das ist die
/// Zusage aus `design.md` §17.2: Einsatznummer, Einsatzzeit und Stichwort
/// erscheinen ERST nach erfolgreicher lokaler Entschluesselung. Ein leeres
/// Objekt statt `null` waere genau der leere Einsatz, den §17.2 verbietet.
///
/// # Errors
/// `EA-READER-VIEW-NO-STAND` ohne geoeffneten Bestand,
/// `EA-READER-VIEW-UNKNOWN-ENTRY` fuer einen Hash, der keine Zustandszeile ist.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerEntryView")]
pub fn reader_entry_view(entry_hash: &str) -> Result<String, JsValue> {
    over_current_entry(entry_hash, entry_json)
}

/// Die technische Ansicht EINES Eintrags als JSON-DTO.
///
/// # Errors
/// Wie [`reader_entry_view`], dazu `EA-READER-VIEW-NO-MANIFEST` fuer einen
/// Stummel oder ein ungueltiges Objekt.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerTechnicalView")]
pub fn reader_technical_view(entry_hash: &str) -> Result<String, JsValue> {
    over_current_entry(entry_hash, technical_json)
}

/// Der Original/Nachtrag-Faden, dem ein Eintrag angehoert, als JSON-DTO.
///
/// # Errors
/// Wie [`reader_entry_view`], dazu `EA-READER-VIEW-NO-THREAD` fuer einen
/// Eintrag ohne Faden.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerAmendmentThread")]
pub fn reader_amendment_thread(entry_hash: &str) -> Result<String, JsValue> {
    over_current_entry(entry_hash, thread_json)
}

/// Die vier Filter, unveraendert an `ReaderSearch::search`; leere Zeichenketten
/// und fehlende Grenzen sind „kein Filter".
///
/// # Errors
/// `EA-READER-VIEW-NO-STAND` ohne geoeffneten Bestand, sonst der Code aus
/// `crates/ea-index`.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerSearch")]
pub fn reader_search(
    from_ms: Option<i64>,
    to_ms: Option<i64>,
    keyword: &str,
    vehicle: &str,
    person: &str,
) -> Result<String, JsValue> {
    let query = query_from(from_ms, to_ms, keyword, vehicle, person);
    with_current_stand(|stand| search_json(stand, &query))
        .ok_or_else(|| JsValue::from_str(EA_READER_VIEW_NO_STAND))?
        .map_err(|error| JsValue::from_str(error.code()))
}

/// Laesst den geoeffneten Bestand fallen.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerStandClose")]
pub fn reader_stand_close() {
    close_stand();
}

#[cfg(test)]
mod tests {
    use ea_reader::{ReaderQueryV1, UnixMillis};

    use super::query_from;

    /// Leere Zeichenketten und fehlende Grenzen sind KEIN Filter; eine halbe
    /// Zeitgrenze ist ein halboffener Zeitraum und kein fallengelassener.
    #[test]
    fn empty_arguments_are_no_filter_and_a_half_bound_is_a_half_open_period() {
        assert_eq!(query_from(None, None, "", "", ""), ReaderQueryV1::default());
        assert_eq!(
            query_from(Some(5), None, "", "", ""),
            ReaderQueryV1::period(UnixMillis::new(5), UnixMillis::new(i64::MAX))
        );
        assert_eq!(
            query_from(None, Some(5), "Brand", "", "Ada"),
            ReaderQueryV1::period(UnixMillis::new(i64::MIN), UnixMillis::new(5))
                .and_keyword("Brand")
                .and_person("Ada")
        );
    }
}
