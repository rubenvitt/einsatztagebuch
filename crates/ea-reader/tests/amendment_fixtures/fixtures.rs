//! EIN lueckenloser Bestand, in dem VERSCHIEDENE Eintraege VERSCHIEDENE
//! Klartexte tragen — und der Zwilling, der die doppelte Sequenz moeglich
//! macht.
//!
//! # Warum der Bestand ZWEIMAL gebaut wird
//!
//! Ein Nachtrag nennt den `entryHash` seines Originals. Dieser Hash steht erst
//! fest, NACHDEM der Bestand gebaut ist: er haengt an der Schreibersignatur
//! ueber dem gebundenen Manifest, und das Manifest haengt am Ciphertext. Ein
//! Nachtrag kann seinen eigenen Bestand also nicht beschreiben, solange dieser
//! Bestand entsteht.
//!
//! Der Ausweg ist ein zweistufiger Bau. Der PROBEBESTAND traegt an den
//! Nachtragsplaetzen [`verify_support::COMPLETE_PLAINTEXT_V1`] und liefert den
//! Eintragshash der Sequenz [`ORIGINAL_SEQUENCE_V1`]; der ENDBESTAND traegt an
//! denselben Plaetzen die echten Nachtraege, die diesen Hash nennen. Das
//! traegt, weil `build_complete_entry` den Eintrag ausschliesslich aus seinen
//! eigenen Feldern und dem Hash seines VORGAENGERS bildet: der Eintrag auf
//! Sequenz vier haengt an den Eintraegen null bis vier und an nichts dahinter.
//!
//! Das ist eine BEHAUPTUNG ueber fremden Code, und deshalb wird sie gemessen
//! und nicht geglaubt: [`amendment_archive`] haelt den Eintragshash der
//! Sequenz vier aus beiden Laeufen gegeneinander, und [`twin_archive`] tut
//! dasselbe ueber einer dritten, kuerzeren Kette.
//!
//! # Die Belegung der elf Plaetze
//!
//! | Sequenz | Klartext                                   | Rolle |
//! |---------|--------------------------------------------|-------|
//! | 0       | eingefrorener Genesis-Vektor               | [`a_genesis_record`] fuer `NotAnIncident` |
//! | 1       | FREMDER Einsatz, andere Einsatznummer      | [`an_incident_record`] fuer `NotAnAmendment` |
//! | 2, 3    | `COMPLETE_PLAINTEXT_V1`                    | Fuellung, wird nie entschluesselt |
//! | 4       | Einsatz `2026-0001`                        | das ORIGINAL |
//! | 5       | Nachtrag mit fremder `originalRecordId`    | [`amendment_with_foreign_record_id`] |
//! | 6       | Nachtrag mit gekipptem `originalEntryHash` | [`amendment_with_flipped_entry_hash`] |
//! | 7       | gueltiger Nachtrag                         | [`amendment_a`] |
//! | 8       | Nachtrag mit falscher `originalSequence`   | [`amendment_with_wrong_sequence`] |
//! | 9       | gueltiger Nachtrag                         | [`amendment_b`] |
//! | 10      | Nachtrag mit fremder Einsatznummer         | [`amendment_with_other_incident_number`] |
//!
//! Die Sequenzen vier, sieben und neun sind NICHT frei gewaehlt: der Plantext
//! des Tasks sichert sie woertlich zu (`ChainSequence::new(7)`,
//! `ChainSequence::new(9)`, `original_sequence: ChainSequence::new(4)`). Die
//! Fuellplaetze zwei und drei stehen dazwischen, damit die Sequenzen
//! lueckenlos ab null laufen — eine Luecke faellt an Gate `chain-position`,
//! und der Zeuge maesse dann die Kulisse statt die Projektion.
//!
//! # Der Zwilling
//!
//! Zwei Nachtraege auf DERSELBEN Kettensequenz koennen nicht aus einer Kette
//! stammen; eine Kette traegt je Sequenz genau einen Eintrag. Der Fall
//! `DuplicateSequence` ist deshalb nur ueber ZWEI Bestaende bezeugbar.
//! [`twin_archive`] traegt bis Sequenz sechs dieselben Klartexte und auf
//! Sequenz sieben einen Nachtrag, der dasselbe Original korrekt referenziert,
//! aber einen anderen Grund nennt — gleiche Sequenz, ANDERER Eintragshash.
//!
//! # Jeder Bestand wird GENAU EINMAL gebaut
//!
//! Aus demselben Grund wie in `verify_fixtures/fixtures.rs`: die `.eag`
//! entstehen ueber eine echte HPKE-Kapselung, und `hpke_seal` zieht seinen
//! ephemeren Schluessel je Aufruf neu. Die Bestaende liegen deshalb in
//! `OnceLock`-Statics. Die Fixture-FUNKTIONEN geben trotzdem jedes Mal einen
//! frisch entschluesselten [`VerifiedDecryptedRecord`] heraus:
//! `decrypt_verified` ist sein einziger Konstruktor, und der Typ traegt
//! bewusst kein `Clone`.
//!
//! # Hashvergleiche laufen ueber `assert!`
//!
//! `hash_newtype!` und `id_newtype!` in `crates/ea-types/src/ids.rs` leiten
//! `Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash` ab — KEIN `Debug`.
//! [`ea_types::EntryHash`] und [`ea_types::RecordId`] lassen sich deshalb nur
//! mit `assert!(a == b)` vergleichen, nicht mit `assert_eq!`.

use std::sync::OnceLock;

use ea_reader::{
    ReaderClassification, SchemaRegistry, SilentObserver, UnlockedVault, VerifiedDecryptedRecord,
    decrypt_verified,
};
use ea_schema::{
    AmendmentChangeV1, AmendmentV1, CommonHeaderV1, IncidentV1, KeywordV1, LocationV1,
    NativeSourceV1, OccurredAtV1, OperatorSnapshotV1, PatientCount, PayloadV1, encode_payload,
};
use ea_types::{
    ChainSequence, EntryHash, ObjectHash, OperatorSubjectId, OrganizationId, RecordId,
    RegistryVersion, UnixMillis,
};

use super::verify_fixtures::fixtures as reader_fixtures;
use super::verify_fixtures::verify_support::{self, archive_support::ArchiveFixture};

// ---------------------------------------------------------------------------
// Die Adressen in der Kette
// ---------------------------------------------------------------------------

/// Zahl der Eintraege des Nachtragsbestands.
pub const ENTRIES_IN_THE_AMENDMENT_ARCHIVE_V1: usize = 11;

/// Die Sequenz des Genesis-Eintrags — zugleich die des Bestandsanfangs.
pub const GENESIS_SEQUENCE_V1: u64 = verify_support::COMPLETE_GENESIS_SEQUENCE_V1;
/// Die Sequenz des FREMDEN Einsatzes.
pub const FOREIGN_INCIDENT_SEQUENCE_V1: u64 = 1;
/// Die Sequenz des ORIGINALS.
pub const ORIGINAL_SEQUENCE_V1: u64 = 4;
/// Die Sequenz des Nachtrags mit fremder `originalRecordId`.
pub const FOREIGN_RECORD_ID_SEQUENCE_V1: u64 = 5;
/// Die Sequenz des Nachtrags mit gekipptem `originalEntryHash`.
pub const FLIPPED_ENTRY_HASH_SEQUENCE_V1: u64 = 6;
/// Die Sequenz des ersten gueltigen Nachtrags.
pub const AMENDMENT_A_SEQUENCE_V1: u64 = 7;
/// Die Sequenz des Nachtrags mit falscher `originalSequence`.
pub const WRONG_SEQUENCE_SEQUENCE_V1: u64 = 8;
/// Die Sequenz des zweiten gueltigen Nachtrags.
pub const AMENDMENT_B_SEQUENCE_V1: u64 = 9;
/// Die Sequenz des Nachtrags mit fremder Einsatznummer.
pub const OTHER_INCIDENT_NUMBER_SEQUENCE_V1: u64 = 10;

/// Die Einsatznummer des Originals.
pub const ORIGINAL_INCIDENT_NUMBER_V1: &str = "2026-0001";
/// Die Einsatznummer des FREMDEN Einsatzes.
///
/// Sie traegt zwei Rollen zugleich: sie ist die Nummer des Einsatzes auf
/// Sequenz eins UND die, die der Nachtrag auf Sequenz zehn faelschlich nennt.
/// Genau daran haengt die Zusage des Plans, dass sonst „zwei verschiedene
/// Einsaetze ueber eine gemeinsame Sequenz zusammenwuechsen".
pub const FOREIGN_INCIDENT_NUMBER_V1: &str = "2026-0002";

/// Die Zeitzone jedes Kopfes dieser Kulisse.
///
/// Kanonisch und nicht `Etc/Unknown`: `validate_timezone` weist beides ab, und
/// ein Klartext, der schon an der Schemapruefung faellt, traegt keinen Zeugen.
const FIXTURE_TIMEZONE_V1: &str = "Europe/Berlin";

// Die Saatwerte der `recordId`. Je Datensatz ein eigener: zwei Datensaetze
// unter derselben `recordId` waeren im Faden nicht mehr unterscheidbar.
const ORIGINAL_RECORD_SEED_V1: u8 = 0x01;
const FOREIGN_INCIDENT_RECORD_SEED_V1: u8 = 0x02;
const FOREIGN_RECORD_ID_AMENDMENT_SEED_V1: u8 = 0x03;
const FLIPPED_ENTRY_HASH_AMENDMENT_SEED_V1: u8 = 0x04;
const AMENDMENT_A_SEED_V1: u8 = 0x05;
const WRONG_SEQUENCE_AMENDMENT_SEED_V1: u8 = 0x06;
const AMENDMENT_B_SEED_V1: u8 = 0x07;
const OTHER_INCIDENT_NUMBER_AMENDMENT_SEED_V1: u8 = 0x08;
const TWIN_AMENDMENT_A_SEED_V1: u8 = 0x09;
/// Das Original, das der Nachtrag auf Sequenz fuenf faelschlich nennt: eine
/// `recordId`, die es in diesem Bestand ueberhaupt nicht gibt.
const NONEXISTENT_ORIGINAL_RECORD_SEED_V1: u8 = 0x0a;

// ---------------------------------------------------------------------------
// Die Bestaende
// ---------------------------------------------------------------------------

static PROBED_ORIGINAL_ENTRY_HASH_V1: OnceLock<EntryHash> = OnceLock::new();
static AMENDMENT_ARCHIVE_V1: OnceLock<verify_support::CompleteArchive> = OnceLock::new();
static TWIN_ARCHIVE_V1: OnceLock<verify_support::CompleteArchive> = OnceLock::new();
static ORIGINAL_PLAINTEXT_V1: OnceLock<Vec<u8>> = OnceLock::new();

/// Der Eintragshash des Originals, aus dem PROBEBESTAND gewonnen.
///
/// Der Probebestand traegt an den sechs Nachtragsplaetzen
/// [`verify_support::COMPLETE_PLAINTEXT_V1`] und ist damit unabhaengig von
/// jedem Nachtrag. Was er liefert, ist die EINGABE der Nachtraege des
/// Endbestands.
///
/// # Panics
///
/// Wenn auf [`ORIGINAL_SEQUENCE_V1`] kein Eintrag liegt.
#[must_use]
pub fn probed_original_entry_hash() -> EntryHash {
    *PROBED_ORIGINAL_ENTRY_HASH_V1.get_or_init(|| {
        let mut plaintexts = prefix_plaintexts();
        plaintexts.resize(
            ENTRIES_IN_THE_AMENDMENT_ARCHIVE_V1,
            verify_support::COMPLETE_PLAINTEXT_V1.to_vec(),
        );
        let probe = verify_support::complete_valid_archive_with_plaintexts(&borrowed(&plaintexts));
        reader_fixtures::entry_hash_at(&probe.fixture, ORIGINAL_SEQUENCE_V1)
    })
}

/// Der ENDBESTAND: elf lueckenlose Eintraege, sechs davon Nachtraege.
///
/// # Panics
///
/// Wenn der Eintragshash des Originals zwischen Probe- und Endbestand
/// abweicht — dann haengt der Eintrag auf Sequenz vier doch an etwas dahinter,
/// und die ganze Kulisse ist hinfaellig.
#[must_use]
pub fn amendment_archive() -> &'static ArchiveFixture {
    &AMENDMENT_ARCHIVE_V1
        .get_or_init(|| {
            let original_entry_hash = probed_original_entry_hash();
            let original_record_id = record_id(ORIGINAL_RECORD_SEED_V1);
            let original_sequence = ChainSequence::new(ORIGINAL_SEQUENCE_V1);
            let mut plaintexts = prefix_plaintexts();
            // 5: die `originalRecordId` nennt einen Datensatz, den dieser
            // Bestand nicht traegt. Alle drei uebrigen Referenzen stimmen.
            plaintexts.push(amendment_payload(
                FOREIGN_RECORD_ID_AMENDMENT_SEED_V1,
                ORIGINAL_INCIDENT_NUMBER_V1,
                record_id(NONEXISTENT_ORIGINAL_RECORD_SEED_V1),
                original_entry_hash,
                original_sequence,
                "Verweis auf einen fremden Datensatz",
            ));
            // 6: EIN einziges gekipptes Byte im `originalEntryHash`.
            plaintexts.push(amendment_payload(
                FLIPPED_ENTRY_HASH_AMENDMENT_SEED_V1,
                ORIGINAL_INCIDENT_NUMBER_V1,
                original_record_id,
                flip_one_byte(original_entry_hash),
                original_sequence,
                "Ein gekipptes Byte im Eintragshash",
            ));
            // 7: gueltig.
            plaintexts.push(amendment_payload(
                AMENDMENT_A_SEED_V1,
                ORIGINAL_INCIDENT_NUMBER_V1,
                original_record_id,
                original_entry_hash,
                original_sequence,
                "Stichwort berichtigt",
            ));
            // 8: die `originalSequence` zeigt auf den Nachbarn.
            plaintexts.push(amendment_payload(
                WRONG_SEQUENCE_AMENDMENT_SEED_V1,
                ORIGINAL_INCIDENT_NUMBER_V1,
                original_record_id,
                original_entry_hash,
                ChainSequence::new(ORIGINAL_SEQUENCE_V1 + 1),
                "Falsche Sequenz genannt",
            ));
            // 9: gueltig, mit HOEHERER Sequenz als 7.
            plaintexts.push(amendment_payload(
                AMENDMENT_B_SEED_V1,
                ORIGINAL_INCIDENT_NUMBER_V1,
                original_record_id,
                original_entry_hash,
                original_sequence,
                "Einsatzort praezisiert",
            ));
            // 10: technisch korrekte Referenz, aber die Einsatznummer eines
            // ANDEREN Einsatzes.
            plaintexts.push(amendment_payload(
                OTHER_INCIDENT_NUMBER_AMENDMENT_SEED_V1,
                FOREIGN_INCIDENT_NUMBER_V1,
                original_record_id,
                original_entry_hash,
                original_sequence,
                "Fremde Einsatznummer genannt",
            ));
            assert_eq!(plaintexts.len(), ENTRIES_IN_THE_AMENDMENT_ARCHIVE_V1);

            let archive =
                verify_support::complete_valid_archive_with_plaintexts(&borrowed(&plaintexts));
            // GEMESSEN und nicht geglaubt: der Eintragshash der Sequenz vier
            // ist ueber beide Laeufe derselbe. Waere er es nicht, naennten die
            // Nachtraege einen Hash, den es im Endbestand gar nicht gibt, und
            // JEDER von ihnen fiele mit `OriginalEntryHashMismatch` — ein
            // Fixture-Fehler, der wie ein Reader-Befund aussaehe.
            assert!(
                reader_fixtures::entry_hash_at(&archive.fixture, ORIGINAL_SEQUENCE_V1)
                    == original_entry_hash,
                "der Eintragshash der Sequenz vier haengt an etwas hinter ihr"
            );
            archive
        })
        .fixture
}

/// Der ZWILLING: dieselben Klartexte bis Sequenz sechs, ein ANDERER Nachtrag
/// auf Sequenz sieben.
///
/// Er ist die einzige Quelle eines zweiten Datensatzes auf
/// [`AMENDMENT_A_SEQUENCE_V1`]: innerhalb EINER Kette gibt es je Sequenz genau
/// einen Eintrag, und `chain-position` liesse eine zweite gar nicht zu.
///
/// # Panics
///
/// Wenn der Eintragshash des Originals abweicht oder der Nachtrag auf Sequenz
/// sieben denselben Eintragshash traegt wie der des Endbestands — dann waere
/// der Zwilling kein zweiter Datensatz, sondern derselbe.
#[must_use]
pub fn twin_archive() -> &'static ArchiveFixture {
    &TWIN_ARCHIVE_V1
        .get_or_init(|| {
            let original_entry_hash = probed_original_entry_hash();
            let original_record_id = record_id(ORIGINAL_RECORD_SEED_V1);
            let original_sequence = ChainSequence::new(ORIGINAL_SEQUENCE_V1);
            let mut plaintexts = prefix_plaintexts();
            plaintexts.push(amendment_payload(
                FOREIGN_RECORD_ID_AMENDMENT_SEED_V1,
                ORIGINAL_INCIDENT_NUMBER_V1,
                record_id(NONEXISTENT_ORIGINAL_RECORD_SEED_V1),
                original_entry_hash,
                original_sequence,
                "Verweis auf einen fremden Datensatz",
            ));
            plaintexts.push(amendment_payload(
                FLIPPED_ENTRY_HASH_AMENDMENT_SEED_V1,
                ORIGINAL_INCIDENT_NUMBER_V1,
                original_record_id,
                flip_one_byte(original_entry_hash),
                original_sequence,
                "Ein gekipptes Byte im Eintragshash",
            ));
            // Der Doppelgaenger: gueltige Referenz, eigene `recordId`, anderer
            // Grund — und damit ein anderer Ciphertext und ein anderer
            // Eintragshash auf DERSELBEN Sequenz.
            plaintexts.push(amendment_payload(
                TWIN_AMENDMENT_A_SEED_V1,
                ORIGINAL_INCIDENT_NUMBER_V1,
                original_record_id,
                original_entry_hash,
                original_sequence,
                "Stichwort ein zweites Mal berichtigt",
            ));
            assert_eq!(
                plaintexts.len(),
                usize::try_from(AMENDMENT_A_SEQUENCE_V1 + 1).expect("acht Eintraege")
            );

            let archive =
                verify_support::complete_valid_archive_with_plaintexts(&borrowed(&plaintexts));
            assert!(
                reader_fixtures::entry_hash_at(&archive.fixture, ORIGINAL_SEQUENCE_V1)
                    == original_entry_hash,
                "auch die kuerzere Kette bindet die Sequenz vier gleich"
            );
            assert!(
                reader_fixtures::entry_hash_at(&archive.fixture, AMENDMENT_A_SEQUENCE_V1)
                    != reader_fixtures::entry_hash_at(amendment_archive(), AMENDMENT_A_SEQUENCE_V1),
                "der Doppelgaenger muss ein ANDERER Eintrag sein"
            );
            archive
        })
        .fixture
}

// ---------------------------------------------------------------------------
// Die Datensaetze
// ---------------------------------------------------------------------------

/// Das ORIGINAL: der Einsatz [`ORIGINAL_INCIDENT_NUMBER_V1`] auf Sequenz vier.
#[must_use]
pub fn original() -> VerifiedDecryptedRecord {
    record_at(classified_amendment_archive(), ORIGINAL_SEQUENCE_V1)
}

/// Die `recordId` des Originals.
#[must_use]
pub fn original_record_id() -> RecordId {
    record_id(ORIGINAL_RECORD_SEED_V1)
}

/// Der Eintragshash des Originals.
#[must_use]
pub fn original_entry_hash() -> EntryHash {
    probed_original_entry_hash()
}

/// Die EXAKTEN Klartextbytes des Originals.
///
/// Aus derselben Kodierung gewonnen, die auch in den Bestand ging: der Zeuge
/// misst damit, dass `with_plaintext` byteweise DEN Klartext herausgibt, den
/// der Schreiber verschluesselt hat, und nicht irgendeinen Einsatz.
#[must_use]
pub fn original_plaintext() -> &'static [u8] {
    ORIGINAL_PLAINTEXT_V1
        .get_or_init(|| incident_payload(ORIGINAL_RECORD_SEED_V1, ORIGINAL_INCIDENT_NUMBER_V1))
}

/// Der erste gueltige Nachtrag, auf Sequenz [`AMENDMENT_A_SEQUENCE_V1`].
#[must_use]
pub fn amendment_a() -> VerifiedDecryptedRecord {
    record_at(classified_amendment_archive(), AMENDMENT_A_SEQUENCE_V1)
}

/// Der zweite gueltige Nachtrag, auf der HOEHEREN Sequenz
/// [`AMENDMENT_B_SEQUENCE_V1`].
#[must_use]
pub fn amendment_b() -> VerifiedDecryptedRecord {
    record_at(classified_amendment_archive(), AMENDMENT_B_SEQUENCE_V1)
}

/// Ein zweiter Nachtrag auf DERSELBEN Sequenz wie [`amendment_a`], aus dem
/// Zwillingsbestand.
#[must_use]
pub fn amendment_a_again_at_the_same_sequence() -> VerifiedDecryptedRecord {
    record_at(classified_twin_archive(), AMENDMENT_A_SEQUENCE_V1)
}

/// Ein Nachtrag, dessen `originalRecordId` einen fremden Datensatz nennt.
#[must_use]
pub fn amendment_with_foreign_record_id() -> VerifiedDecryptedRecord {
    record_at(
        classified_amendment_archive(),
        FOREIGN_RECORD_ID_SEQUENCE_V1,
    )
}

/// Ein Nachtrag mit EINEM gekippten Byte im `originalEntryHash`.
#[must_use]
pub fn amendment_with_flipped_entry_hash() -> VerifiedDecryptedRecord {
    record_at(
        classified_amendment_archive(),
        FLIPPED_ENTRY_HASH_SEQUENCE_V1,
    )
}

/// Ein Nachtrag, dessen `originalSequence` auf den Nachbarn zeigt.
#[must_use]
pub fn amendment_with_wrong_sequence() -> VerifiedDecryptedRecord {
    record_at(classified_amendment_archive(), WRONG_SEQUENCE_SEQUENCE_V1)
}

/// Ein Nachtrag mit korrekter Referenz, aber der Einsatznummer eines ANDEREN
/// Einsatzes.
#[must_use]
pub fn amendment_with_other_incident_number() -> VerifiedDecryptedRecord {
    record_at(
        classified_amendment_archive(),
        OTHER_INCIDENT_NUMBER_SEQUENCE_V1,
    )
}

/// Ein Einsatz, der KEIN Nachtrag ist: der fremde Einsatz auf Sequenz eins.
#[must_use]
pub fn an_incident_record() -> VerifiedDecryptedRecord {
    record_at(classified_amendment_archive(), FOREIGN_INCIDENT_SEQUENCE_V1)
}

/// Ein Genesis-Datensatz: kein Einsatz, also kein taugliches Original.
#[must_use]
pub fn a_genesis_record() -> VerifiedDecryptedRecord {
    record_at(classified_amendment_archive(), GENESIS_SEQUENCE_V1)
}

// ---------------------------------------------------------------------------
// Der Weg vom Bestand zum Zeugentyp
// ---------------------------------------------------------------------------

/// Ein Bestand samt der EINEN Klassifikation, die ihn beurteilt hat.
///
/// Die Klassifikation faehrt neun Gates ueber elf Eintraege und elf Grants
/// samt echter HPKE-Kapselung; sie einmal je Fixture-Aufruf zu wiederholen
/// kostete das Vielfache der Zeugenlaufzeit und maesse dabei nichts, was
/// `verification_order.rs` nicht schon misst. Sie liegt deshalb ebenfalls in
/// einem `OnceLock`.
///
/// Das ist zulaessig, weil die Frischepruefung von `decrypt_verified` gegen
/// [`reader_fixtures::EFFECTIVE_NOW`] misst und dieser Wert eine Konstante
/// ist: die Zeugen dieser Klassifikation bleiben fuer JEDEN Lauf dieser
/// Kulisse frisch.
struct ClassifiedArchiveV1 {
    fixture: &'static ArchiveFixture,
    classification: ReaderClassification,
}

static VAULT_V1: OnceLock<UnlockedVault> = OnceLock::new();
static AMENDMENT_CLASSIFIED_V1: OnceLock<ClassifiedArchiveV1> = OnceLock::new();
static TWIN_CLASSIFIED_V1: OnceLock<ClassifiedArchiveV1> = OnceLock::new();

/// Die EINE entsperrte Sitzung dieser Kulisse.
///
/// Derselbe Tresor fuer beide Bestaende: sie tragen denselben Anker und
/// denselben Empfaengerabdruck, weil sie ueber dieselbe Registrierungslinie
/// gebaut sind.
fn vault() -> &'static UnlockedVault {
    VAULT_V1.get_or_init(reader_fixtures::unlocked_vault_with_pinned_anchor)
}

fn classified_amendment_archive() -> &'static ClassifiedArchiveV1 {
    AMENDMENT_CLASSIFIED_V1.get_or_init(|| ClassifiedArchiveV1 {
        fixture: amendment_archive(),
        classification: reader_fixtures::classify(amendment_archive(), vault()),
    })
}

fn classified_twin_archive() -> &'static ClassifiedArchiveV1 {
    TWIN_CLASSIFIED_V1.get_or_init(|| ClassifiedArchiveV1 {
        fixture: twin_archive(),
        classification: reader_fixtures::classify(twin_archive(), vault()),
    })
}

/// Gibt den Eintrag auf `chain_sequence` FRISCH entschluesselt heraus.
///
/// Entschluesselt wird bei JEDEM Aufruf neu, und das ist kein Umweg:
/// [`VerifiedDecryptedRecord`] traegt kein `Clone`, weil sein Klartext in
/// einem `SecretVec` liegt, und `decrypt_verified` ist sein einziger
/// Konstruktor. Ein `OnceLock` darueber gaebe es nur um den Preis, den Zeugen
/// als Ausleihe herauszureichen — und `ReaderEntryThread::build` nimmt ihn
/// BESITZEND.
///
/// # Panics
///
/// Wenn der Eintrag keinen Zeugen traegt oder sein Klartext keine
/// Schemabestimmung findet.
fn record_at(source: &ClassifiedArchiveV1, chain_sequence: u64) -> VerifiedDecryptedRecord {
    let entry_hash = reader_fixtures::entry_hash_at(source.fixture, chain_sequence);
    let entry = source
        .classification
        .verified_entry(entry_hash)
        .expect("der Eintrag dieser Sequenz traegt einen Zeugen");
    let grant = source
        .classification
        .verified_grant(entry_hash)
        .expect("und einen eigenen Grant");
    decrypt_verified(
        entry,
        grant,
        vault(),
        &SchemaRegistry::v1(),
        reader_fixtures::EFFECTIVE_NOW,
        &mut SilentObserver,
    )
    .expect("der Klartext dieser Kulisse traegt genau eine Schemabestimmung")
}

// ---------------------------------------------------------------------------
// Die Klartexte
// ---------------------------------------------------------------------------

/// Die fuenf Klartexte der Sequenzen null bis vier.
///
/// Sie sind in JEDEM Bestand dieses Moduls dieselben — daran haengt, dass der
/// Eintragshash der Sequenz vier ueber alle drei Laeufe derselbe ist.
fn prefix_plaintexts() -> Vec<Vec<u8>> {
    vec![
        reader_fixtures::genesis_plaintext().to_vec(),
        incident_payload(FOREIGN_INCIDENT_RECORD_SEED_V1, FOREIGN_INCIDENT_NUMBER_V1),
        verify_support::COMPLETE_PLAINTEXT_V1.to_vec(),
        verify_support::COMPLETE_PLAINTEXT_V1.to_vec(),
        incident_payload(ORIGINAL_RECORD_SEED_V1, ORIGINAL_INCIDENT_NUMBER_V1),
    ]
}

/// Die Ausleihform, die `complete_valid_archive_with_plaintexts` nimmt.
fn borrowed(plaintexts: &[Vec<u8>]) -> Vec<&[u8]> {
    plaintexts.iter().map(Vec::as_slice).collect()
}

/// Ein `ea.incident`-Klartext, ueber `ea_schema::encode_payload` kodiert.
///
/// # Panics
///
/// Wenn der Einsatz nicht validiert oder nicht kodiert.
fn incident_payload(record_id_seed: u8, human_incident_number: &str) -> Vec<u8> {
    let incident = IncidentV1::new(
        header(record_id(record_id_seed)),
        human_incident_number,
        OccurredAtV1::new(
            UnixMillis::new(verify_support::FIXTURE_OS_WALL_CLOCK_V1),
            None,
        )
        .expect("ein Startzeitpunkt ohne Ende ist ein gueltiges Intervall"),
        KeywordV1::free_text("Brand").expect("ein Stichwort mit fuenf Zeichen ist gueltig"),
        LocationV1::free_text("Hauptstrasse 1", None).expect("ein Freitextort ist gueltig"),
        vec![],
        Some("Keine Kraefte erfasst".to_owned()),
        vec![],
        Some("Keine Fahrzeuge erfasst".to_owned()),
        PatientCount::Unknown,
        None,
        vec![],
    )
    .expect("der Kulisseneinsatz muss validieren");
    encode_payload(&PayloadV1::Incident(incident)).expect("der Kulisseneinsatz muss kodieren")
}

/// Ein `ea.amendment`-Klartext ueber vier frei gewaehlten Referenzfeldern.
///
/// Genau diese vier vergleicht die Projektion; jeder Zeuge dieser Kulisse
/// verstellt HOECHSTENS EINES davon, damit ein abgewiesener Nachtrag seinen
/// Grund eindeutig benennt.
///
/// # Panics
///
/// Wenn der Nachtrag nicht validiert oder nicht kodiert.
fn amendment_payload(
    record_id_seed: u8,
    original_incident_number: &str,
    original_record_id: RecordId,
    original_entry_hash: EntryHash,
    original_sequence: ChainSequence,
    reason: &str,
) -> Vec<u8> {
    let amendment = AmendmentV1::new(
        header(record_id(record_id_seed)),
        original_incident_number,
        original_record_id,
        original_entry_hash,
        original_sequence,
        reason,
        vec![
            AmendmentChangeV1::new("keyword", "Brand statt Rauchentwicklung")
                .expect("eine Aenderung mit Pfad und Text ist gueltig"),
        ],
    )
    .expect("der Kulissennachtrag muss validieren");
    encode_payload(&PayloadV1::Amendment(amendment)).expect("der Kulissennachtrag muss kodieren")
}

/// Der gemeinsame Kopf jedes Datensatzes dieser Kulisse.
///
/// # Panics
///
/// Wenn der Kopf nicht validiert.
fn header(record_id: RecordId) -> CommonHeaderV1 {
    CommonHeaderV1::new(
        record_id,
        UnixMillis::new(verify_support::FIXTURE_OS_WALL_CLOCK_V1),
        FIXTURE_TIMEZONE_V1,
        OperatorSnapshotV1::new(
            organization_id(0x10),
            OperatorSubjectId::try_from(&[0x20; 16][..]).expect("sechzehn Bytes sind eine Kennung"),
            "Erika Beispiel",
            "Einsatzleitung",
            [0x30; 32],
            object_hash(0x40),
        )
        .expect("der Kulissenoperator muss binden"),
        NativeSourceV1::new("writer-native", 1).expect("die Kulissenquelle muss binden"),
        RegistryVersion::new(7),
    )
    .expect("der Kulissenkopf muss validieren")
}

// ---------------------------------------------------------------------------
// Die Kennungen
// ---------------------------------------------------------------------------

/// Eine `recordId` in UUIDv7-GESTALT.
///
/// `AmendmentV1::validate` und `CommonHeaderV1::new` pruefen Version und
/// Variante ueber `validate_uuid_v7`; sechzehn gleiche Bytes faellten dort mit
/// `EA-SCHEMA-UUID-V7`. Die zwei gesetzten Halbbytes sind genau die, die
/// `crates/ea-schema/tests/v1_validation.rs` seit Stufe 1 setzt.
///
/// # Panics
///
/// Nie erreichbar: sechzehn Bytes sind immer eine Kennung.
fn record_id(seed: u8) -> RecordId {
    let mut bytes = [seed; 16];
    bytes[6] = 0x70 | (seed & 0x0f);
    bytes[8] = 0x80 | (seed & 0x3f);
    RecordId::try_from(&bytes[..]).expect("sechzehn Bytes sind eine Kennung")
}

fn organization_id(seed: u8) -> OrganizationId {
    OrganizationId::try_from(&[seed; 16][..]).expect("sechzehn Bytes sind eine Kennung")
}

fn object_hash(seed: u8) -> ObjectHash {
    ObjectHash::try_from(&[seed; 32][..]).expect("zweiunddreissig Bytes sind ein Hash")
}

/// Derselbe Eintragshash mit EINEM gekippten Byte.
///
/// # Panics
///
/// Nie erreichbar: zweiunddreissig Bytes bleiben zweiunddreissig Bytes.
fn flip_one_byte(entry_hash: EntryHash) -> EntryHash {
    let mut bytes = *entry_hash.as_bytes();
    bytes[0] ^= 0x01;
    EntryHash::try_from(&bytes[..]).expect("zweiunddreissig Bytes sind ein Hash")
}
