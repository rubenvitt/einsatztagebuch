//! Die Kulisse des Reader-Syncs: EIN echter, lueckenloser Bestand, ein Tresor,
//! der GENAU dessen Anker pinnt, und die Seiten, in denen ein Server ihn
//! herausgibt.
//!
//! Abschrift von `crates/ea-reader/tests/sync_support/fixtures.rs`; die
//! Begruendungen stehen dort und werden hier nicht wiederholt. Der eine
//! Unterschied — der Rahmen wird mit `minicbor` selbst geschrieben, weil
//! `ea-sync-protocol` keine Dev-Kante dieser Crate ist — steht am Kopf von
//! `mod.rs` und an [`batch`].
//!
//! # Der Bestand wird GENAU EINMAL gebaut
//!
//! Weil er NICHT deterministisch ist: die `.eag` der Fixture entstehen ueber
//! eine echte HPKE-Kapselung, und `hpke_seal` zieht seinen ephemeren Schluessel
//! je Aufruf neu. Zwei Aufrufe von `isolation_archive` liefern VERSCHIEDENE
//! Grantbytes unter verschiedenen Objekthashes — und der Bytevergleich des
//! Systemzeugen verglich dann zwei verschiedene Bestaende.

use std::sync::OnceLock;

use ea_archive::{ArchiveBlob, ArchiveError, ArchiveSource};
use ea_crypto::{SecretBytes, object_hash};
use ea_reader::{ReaderVault, UnlockedVault, VaultContentsV1};
use ea_trust::{TrustAnchorV1, decode_trust_anchor};
use ea_types::{EntryHash, ObjectHash, UnixMillis};
use ea_verify::{ChainHeadV1, SilentObserver, VerifyOptions, verify_archive_observed};

use super::verify_support;

/// Die Betriebssystemuhr dieser Kulisse — dieselbe, gegen die die
/// Fixture-Registrierungslinie ihren Kopf waehlt.
pub fn clock() -> UnixMillis {
    UnixMillis::new(verify_support::FIXTURE_OS_WALL_CLOCK_V1)
}

/// Die Herkunft, gegen die jeder Request dieser Kulisse signiert wird.
pub const SYNC_AUTHORITY_V1: &str = "sync.einsatzarchiv.invalid";

/// Der KEM-Schluessel des Kulissen-Tresors.
const READER_KEM_SEED: [u8; 32] = [0x51; 32];
/// Der Ed25519-Geraete- und Auditschluessel des Kulissen-Tresors.
const READER_AUDIT_SEED: [u8; 32] = [0x52; 32];
/// Die PRF-Ausgabe des einen Entsperrwegs dieser Kulisse.
const READER_PRF_OUTPUT: [u8; 32] = [0xa1; 32];

/// Die letzte Sequenz des Bestandes.
const LAST_SEQUENCE_V1: u64 = verify_support::ISOLATION_ENTRY_COUNT_V1 - 1;

/// Die letzte Sequenz der ERSTEN Seite.
const FIRST_PAGE_THROUGH_V1: u64 = LAST_SEQUENCE_V1 - 1;

/// Der undurchsichtige Blaetterschein zwischen erster und zweiter Seite.
const PAGE_TWO_TOKEN_V1: &[u8] = b"ea-reader-fixture-page-2";

/// Ein Bestand als Paare aus Pfadhinweis und Bytes, samt seinen Ankerbytes.
struct FixtureArchive {
    blobs: Vec<(String, Vec<u8>)>,
    anchor_bytes: Vec<u8>,
}

impl FixtureArchive {
    fn of(built: &verify_support::CompleteArchive) -> Self {
        Self {
            blobs: built.fixture.blobs().to_vec(),
            anchor_bytes: built.anchor_bytes.clone(),
        }
    }
}

/// Der Bestand als `ArchiveSource`, fuer den EINEN Lauf von
/// [`batch_end_head`].
struct FixtureArchiveSource<'a>(&'a [(String, Vec<u8>)]);

impl ArchiveSource for FixtureArchiveSource<'_> {
    fn visit_blobs(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        for (hint, bytes) in self.0 {
            visitor(ArchiveBlob::new(hint, bytes))?;
        }
        Ok(())
    }
}

/// Der lueckenlose Bestand mit drei verketteten Eintraegen.
fn archive() -> &'static FixtureArchive {
    static ARCHIVE: OnceLock<FixtureArchive> = OnceLock::new();
    ARCHIVE.get_or_init(|| {
        FixtureArchive::of(&verify_support::isolation_archive(
            verify_support::IsolationDefectV1::None,
        ))
    })
}

/// Derselbe Bestand mit einem Grant an einen FREMDEN Empfaenger — sein Eintrag
/// auf Sequenz null ist gueltig und traegt trotzdem einen ANDEREN `entryHash`.
fn archive_with_a_competing_genesis_entry() -> &'static FixtureArchive {
    static COMPETING: OnceLock<FixtureArchive> = OnceLock::new();
    COMPETING.get_or_init(|| FixtureArchive::of(&verify_support::archive_without_the_own_grant()))
}

/// Die EXAKTEN Ankerbytes der Registrierungslinie dieses Bestandes.
pub fn anchor_exact_bytes() -> Vec<u8> {
    archive().anchor_bytes.clone()
}

/// Der gepinnte Anker, bei JEDEM Aufruf frisch dekodiert — `TrustAnchorV1`
/// traegt weder `Clone` noch `Debug`.
pub fn pinned_anchor() -> TrustAnchorV1 {
    decode_trust_anchor(&anchor_exact_bytes())
        .expect("der Fixture-Anker traegt seinen Bootstrap-Hash")
}

/// Der Tresor dieser Kulisse, entsperrt: er pinnt den Anker des Bestandes und
/// traegt den Ed25519-Schluessel, mit dem der Request unterschrieben wird.
pub fn unlocked_vault() -> UnlockedVault {
    let contents = VaultContentsV1::new(
        SecretBytes::new(READER_KEM_SEED),
        SecretBytes::new(READER_AUDIT_SEED),
        anchor_exact_bytes(),
        None,
    );
    let authenticator = ea_reader::AuthenticatorPrfV1::new(
        b"ea-reader-sync-passkey".to_vec(),
        SecretBytes::new(READER_PRF_OUTPUT),
    );
    let sealed = ReaderVault::seal(contents, std::slice::from_ref(&authenticator))
        .expect("ein Authenticator genuegt zum Versiegeln");
    ReaderVault::unlock(&sealed, &authenticator)
        .expect("derselbe Authenticator oeffnet sein Envelope")
}

/// Der Kopf, auf dem der Bestand als GANZES verifiziert — GERECHNET ueber
/// `verify_archive_observed` und nicht abgeschrieben.
pub fn batch_end_head() -> ChainHeadV1 {
    verify_archive_observed(
        &FixtureArchiveSource(&archive().blobs),
        &pinned_anchor(),
        VerifyOptions::new(clock()),
        &mut SilentObserver,
    )
    .expect("der lueckenlose Fixture-Bestand traegt")
    .chain_head()
}

// ---------------------------------------------------------------------------
// Der Bestand, nach Sequenzen aufgeteilt
// ---------------------------------------------------------------------------

/// Die Sequenz, zu der ein Pfadhinweis gehoert — oder `None` fuer Beiwerk.
fn sequence_of(path_hint: &str) -> Option<u64> {
    let name = path_hint.rsplit('/').next()?;
    let digits: String = name.chars().take_while(char::is_ascii_digit).collect();
    if digits.len() == 12 {
        digits.parse().ok()
    } else {
        None
    }
}

/// Alle Bytes des Bestandes, die zu KEINER Sequenz gehoeren: die
/// Vertrauensobjekte.
fn base_objects() -> Vec<Vec<u8>> {
    archive()
        .blobs
        .iter()
        .filter(|(hint, _)| sequence_of(hint).is_none())
        .map(|(_, bytes)| bytes.clone())
        .collect()
}

/// Alle Bytes des Bestandes, die zu einer Sequenz aus `range` gehoeren.
fn objects_for_sequences(from: u64, through: u64) -> Vec<Vec<u8>> {
    archive()
        .blobs
        .iter()
        .filter(|(hint, _)| {
            sequence_of(hint).is_some_and(|sequence| (from..=through).contains(&sequence))
        })
        .map(|(_, bytes)| bytes.clone())
        .collect()
}

/// Die Bytes des Eintrags auf `sequence`, ohne seinen Grant.
fn entry_bytes_at(archive: &FixtureArchive, sequence: u64) -> Vec<u8> {
    archive
        .blobs
        .iter()
        .find(|(hint, _)| hint.ends_with("_entry.eip") && sequence_of(hint) == Some(sequence))
        .map(|(_, bytes)| bytes.clone())
        .expect("der Fixture-Bestand traegt einen Eintrag auf dieser Sequenz")
}

/// Ein Satz aus `objectHash` und exakten Objektbytes — die Gestalt von
/// `ea_sync_protocol::ObjectRecordV1`, hier ohne die Crate.
struct Record {
    object_hash: ObjectHash,
    exact_object_bytes: Vec<u8>,
}

/// Baut die Objektliste eines Rahmens: bytweise sortiert und duplikatfrei —
/// beides verlangt `ReaderBatchV1::decode` auf der Leitung.
fn records(objects: Vec<Vec<u8>>) -> Vec<Record> {
    let mut sorted: Vec<Record> = objects
        .into_iter()
        .map(|bytes| Record {
            object_hash: object_hash(&bytes),
            exact_object_bytes: bytes,
        })
        .collect();
    sorted.sort_by(|left, right| {
        left.object_hash
            .as_bytes()
            .cmp(right.object_hash.as_bytes())
    });
    sorted.dedup_by(|left, right| left.object_hash.as_bytes() == right.object_hash.as_bytes());
    sorted
}

/// Kodiert einen Rahmen `reader-batch-v1` aus seinen sieben Positionen.
///
/// Die neun CBOR-Positionen in der Reihenfolge von
/// `crates/ea-sync-protocol/src/reader.rs::ReaderBatchV1::new`: Version 1,
/// `chainId`, `requestedAfterSequence`, `requestedAfterEntryHash`,
/// `startHeadEntryHash`, die Objektliste als Paare, `nextCursor` oder `null`,
/// `coveredThroughSequence` und der leere Erweiterungsplatz (ein leeres
/// Array). `minicbor` schreibt Koepfe in minimaler Breite — dieselbe Form, die
/// `cbor::head` dort erzeugt; `decode` misst die Gleichheit in jedem Lauf.
fn batch(
    after_sequence: u64,
    after_entry_hash: EntryHash,
    objects: Vec<Record>,
    next_cursor: Option<Vec<u8>>,
    covered_through: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    let mut encoder = minicbor::Encoder::new(&mut out);
    encoder
        .array(9)
        .and_then(|encoder| encoder.u64(1))
        .and_then(|encoder| encoder.bytes(pinned_anchor().chain_id().as_bytes()))
        .and_then(|encoder| encoder.u64(after_sequence))
        .and_then(|encoder| encoder.bytes(after_entry_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(after_entry_hash.as_bytes()))
        .and_then(|encoder| encoder.array(objects.len() as u64))
        .expect("ein Vec nimmt jedes Byte an");
    for record in &objects {
        encoder
            .array(2)
            .and_then(|encoder| encoder.bytes(record.object_hash.as_bytes()))
            .and_then(|encoder| encoder.bytes(&record.exact_object_bytes))
            .expect("ein Vec nimmt jedes Byte an");
    }
    match next_cursor {
        Some(cursor) => encoder.bytes(&cursor),
        None => encoder.null(),
    }
    .and_then(|encoder| encoder.u64(covered_through))
    .and_then(|encoder| encoder.array(0))
    .expect("ein Vec nimmt jedes Byte an");
    out
}

/// Der Sentinel-Eintragshash: „ab Kettenanfang".
pub fn genesis_entry_hash() -> EntryHash {
    EntryHash::try_from(&[0_u8; 32][..]).expect("32 Nullbytes sind ein Eintragshash")
}

// ---------------------------------------------------------------------------
// Die zwei Seiten des Servers
// ---------------------------------------------------------------------------

/// Die ERSTE Seite: Vertrauensobjekte und die Sequenzen bis
/// [`FIRST_PAGE_THROUGH_V1`], mit Blaetterschein.
pub fn first_page() -> Vec<u8> {
    let mut objects = base_objects();
    objects.extend(objects_for_sequences(0, FIRST_PAGE_THROUGH_V1));
    batch(
        0,
        genesis_entry_hash(),
        records(objects),
        Some(PAGE_TWO_TOKEN_V1.to_vec()),
        FIRST_PAGE_THROUGH_V1,
    )
}

/// Die ZWEITE Seite: die restlichen Sequenzen, ohne Blaetterschein. Sie
/// bindet DENSELBEN Startkopf wie die erste — das Verhalten des echten
/// Servers innerhalb einer Lesestrecke.
pub fn second_page() -> Vec<u8> {
    batch(
        0,
        genesis_entry_hash(),
        records(objects_for_sequences(
            FIRST_PAGE_THROUGH_V1 + 1,
            LAST_SEQUENCE_V1,
        )),
        None,
        LAST_SEQUENCE_V1,
    )
}

/// Eine LEERE Seite auf dem genannten Kopf.
pub fn empty_page(after_sequence: u64, after_entry_hash: EntryHash) -> Vec<u8> {
    batch(
        after_sequence,
        after_entry_hash,
        Vec::new(),
        None,
        after_sequence,
    )
}

// ---------------------------------------------------------------------------
// Die vier abgewiesenen Rahmen
// ---------------------------------------------------------------------------

/// Die vier Abweisungsgruende, in der Reihenfolge des Manifest-Brackets von
/// `refusal-leaves-the-cursor`: falscher Startkopf, fehlendes Objekt, Luecke,
/// Fork.
pub const REFUSED_FRAME_LABELS: [&str; 4] = [
    DIFFERENT_START_HEAD,
    MISSING_OBJECT,
    SEQUENCE_GAP,
    FORK_AT_THE_HEAD,
];

/// Ein Rahmen, der an einem fremden Startkopf ansetzt.
pub const DIFFERENT_START_HEAD: &str = "different-start-head";
/// Ein Rahmen, dessen einer Satz seine Adresse nicht traegt.
pub const MISSING_OBJECT: &str = "missing-object";
/// Ein Rahmen, der die mittlere Sequenz auslaesst.
pub const SEQUENCE_GAP: &str = "sequence-gap";
/// Ein Rahmen mit zwei zurechenbaren Eintraegen auf derselben Sequenz.
pub const FORK_AT_THE_HEAD: &str = "fork-at-the-head";

/// Der abgewiesene Rahmen zu `label`, mit dem Code seiner Abweisung — dieselben
/// vier, die
/// `crates/ea-reader/tests/sync_attacks.rs::every_refusal_carries_its_own_code_and_leaves_the_cursor_where_it_was`
/// fuehrt.
pub fn refused_frame(label: &str) -> (Vec<u8>, &'static str) {
    match label {
        DIFFERENT_START_HEAD => (
            batch_for_a_different_start_head(),
            "EA-READER-START-HEAD-MISMATCH",
        ),
        MISSING_OBJECT => (batch_with_a_missing_object(), "EA-READER-MISSING-OBJECT"),
        SEQUENCE_GAP => (batch_with_a_sequence_gap(), "EA-READER-CHAIN-GAP"),
        FORK_AT_THE_HEAD => (batch_forking_at_the_head(), "EA-READER-CHAIN-FORK"),
        other => panic!("kein abgewiesener Rahmen heisst `{other}`"),
    }
}

/// Ein Rahmen, der an einem FREMDEN Startkopf ansetzt.
fn batch_for_a_different_start_head() -> Vec<u8> {
    let mut objects = base_objects();
    objects.extend(objects_for_sequences(0, FIRST_PAGE_THROUGH_V1));
    batch(
        7,
        EntryHash::try_from(&[0x7e_u8; 32][..]).expect("32 Byte sind ein Eintragshash"),
        records(objects),
        None,
        FIRST_PAGE_THROUGH_V1,
    )
}

/// Ein Rahmen, dessen einer Satz andere Bytes traegt als seinen `objectHash`.
/// Die BYTES werden verkippt und nicht der Hash, damit die Sortierung des
/// Rahmens steht und der Zeuge den Cursor misst statt den Rahmen.
fn batch_with_a_missing_object() -> Vec<u8> {
    let mut objects = base_objects();
    objects.extend(objects_for_sequences(0, FIRST_PAGE_THROUGH_V1));
    let mut announced = records(objects);
    let mut victim = announced
        .pop()
        .expect("die erste Seite traegt mindestens einen Satz");
    let last = victim.exact_object_bytes.len() - 1;
    victim.exact_object_bytes[last] ^= 0xff;
    announced.push(victim);
    batch(
        0,
        genesis_entry_hash(),
        announced,
        None,
        FIRST_PAGE_THROUGH_V1,
    )
}

/// Ein Rahmen, der die mittlere Sequenz auslaesst.
fn batch_with_a_sequence_gap() -> Vec<u8> {
    let mut objects = base_objects();
    objects.extend(objects_for_sequences(0, 0));
    objects.extend(objects_for_sequences(LAST_SEQUENCE_V1, LAST_SEQUENCE_V1));
    batch(
        0,
        genesis_entry_hash(),
        records(objects),
        None,
        LAST_SEQUENCE_V1,
    )
}

/// Ein Rahmen mit ZWEI zurechenbaren Eintraegen auf DERSELBEN Sequenz.
fn batch_forking_at_the_head() -> Vec<u8> {
    let competing = archive_with_a_competing_genesis_entry();
    assert_eq!(
        competing.anchor_bytes,
        anchor_exact_bytes(),
        "beide Bestaende MUESSEN unter derselben Registrierungslinie stehen"
    );
    let mut objects = base_objects();
    objects.extend(objects_for_sequences(0, 0));
    objects.push(entry_bytes_at(competing, 0));
    batch(0, genesis_entry_hash(), records(objects), None, 0)
}
