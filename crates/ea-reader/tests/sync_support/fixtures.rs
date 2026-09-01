//! Die Kulisse des Reader-Syncs: EIN echter, lueckenloser Bestand, ein Tresor,
//! der GENAU dessen Anker pinnt, und die Seiten, in denen ein Server ihn
//! herausgibt.
//!
//! # Der Bestand wird NICHT nachgebaut
//!
//! Er kommt ueber das per `#[path]` eingebundene Fixture-Modul von `ea-verify`
//! und damit aus derselben Registrierungslinie, gegen die Stufe 1 und 2 ihre
//! Gates messen. Ein zweiter, hier gebastelter Bestand waere eine zweite Quelle
//! derselben Kette — und eine von beiden waere irgendwann die falsche. Dieselbe
//! Entscheidung fuehren `crates/ea-recovery/tests/support/mod.rs` und
//! `crates/ea-archive-fs/tests/support/mod.rs`.
//!
//! # Der Anker des TRESORS ist der Anker des BESTANDES
//!
//! `crates/ea-reader/tests/fixtures/mod.rs` pinnt einen eigenen Anker mit
//! Wurzelseed `0x11`; gegen ihn faellt JEDE Verifikation dieses Bestandes
//! bereits an Gate `trust`. Der Tresor dieser Kulisse wird deshalb ueber
//! `VaultContentsV1` NEU versiegelt, und zwar mit den Ankerbytes, die die Linie
//! selbst ausgibt. Ein Anker daneben waere kein Zeuge, sondern ein rotes Gate
//! ohne Aussage.
//!
//! # Zwei Seiten, und beide sind echt
//!
//! Der Bestand traegt drei verkettete Eintraege. Die erste Seite liefert die
//! Vertrauensobjekte und die Sequenzen null und eins, die zweite die Sequenz
//! zwei — genau die Aufteilung, die `crates/ea-sync-server/src/reader_sync.rs`
//! trifft, wenn die Seitendecke greift. Nur so misst der Zeuge einen Cursor,
//! der WEITERBLAETTERT, statt einen, der genau einmal springt.

use std::sync::OnceLock;

use ea_archive::{ArchiveBlob, ArchiveError, ArchiveSource};
use ea_crypto::{SecretBytes, object_hash};
use ea_reader::{ReaderVault, UnlockedVault, VaultContentsV1};
use ea_sync_protocol::{ObjectRecordV1, ReaderBatchV1};
use ea_trust::{TrustAnchorV1, decode_trust_anchor};
use ea_types::{EntryHash, UnixMillis};
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
///
/// Der Reader deutet ihn NIE — `TechnicalCursorV1` gehoert dem Server und wird
/// mit dessen Schluessel geoeffnet. Hier steht deshalb bewusst ein Bytestrang
/// ohne Struktur: waere er ein echter Cursor, prueft der Zeuge versehentlich
/// den Server statt den Reader.
const PAGE_TWO_TOKEN_V1: &[u8] = b"ea-reader-fixture-page-2";

/// Ein Bestand als Paare aus Pfadhinweis und Bytes, samt seinen Ankerbytes.
///
/// # Warum der Bestand GENAU EINMAL gebaut wird
///
/// Weil er NICHT deterministisch ist, und das ist ein gemessener Befund: die
/// `.eag` der Fixture entstehen ueber eine echte HPKE-Kapselung, und
/// `hpke_seal` zieht seinen ephemeren Schluessel je Aufruf neu. Zwei Aufrufe
/// von `isolation_archive` liefern deshalb VERSCHIEDENE Grantbytes unter
/// verschiedenen Objekthashes — die Eintraege bleiben gleich, weil sie mit
/// festem CEK und festem Nonce gebaut werden. Ein je Aufruf neu gebauter
/// Bestand liesse `a_repeated_batch_writes_no_second_byte_and_moves_nothing`
/// fallen, und zwar zu Recht: die zweite Seite waere gar nicht dieselbe.
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

/// Derselbe Bestand mit einem Grant an einen FREMDEN Empfaenger.
///
/// Sein Eintrag auf Sequenz null ist vollstaendig gueltig und traegt trotzdem
/// einen ANDEREN `entryHash`: der Planhash des fremden Empfaengers steht im
/// signierten Manifestkern. Genau das braucht [`batch_forking_at_the_head`] —
/// zwei zurechenbare Eintraege auf derselben Sequenz.
fn archive_with_a_competing_genesis_entry() -> &'static FixtureArchive {
    static COMPETING: OnceLock<FixtureArchive> = OnceLock::new();
    COMPETING.get_or_init(|| FixtureArchive::of(&verify_support::archive_without_the_own_grant()))
}

/// Die EXAKTEN Ankerbytes der Registrierungslinie dieses Bestandes.
pub fn anchor_exact_bytes() -> Vec<u8> {
    archive().anchor_bytes.clone()
}

/// Der gepinnte Anker, bei JEDEM Aufruf frisch dekodiert.
///
/// `TrustAnchorV1` traegt weder `Clone` noch `Debug`; ein zwischengehaltener
/// Wert liesse sich gar nicht herausgeben.
pub fn pinned_anchor() -> TrustAnchorV1 {
    decode_trust_anchor(&anchor_exact_bytes())
        .expect("der Fixture-Anker traegt seinen Bootstrap-Hash")
}

/// Der Tresor dieser Kulisse, entsperrt.
///
/// Er pinnt den Anker des Bestandes und traegt den Ed25519-Schluessel, mit dem
/// `RequestSigner` die Lesestapel-Anfrage unterschreibt.
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

/// Der Kopf, auf dem der Bestand als GANZES verifiziert.
///
/// GERECHNET und nicht abgeschrieben: der Bestand wird einmal vollstaendig
/// durch `verify_archive_observed` geschickt, und sein `chainHead` ist der
/// Wert. Ein von Hand notierter Eintragshash waere eine zweite Quelle derselben
/// Aussage — und der Zeuge mass dann die Abschrift statt die Kette.
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
///
/// Gelesen aus dem zwoelfstelligen Zahlenteil, den `push_entry`/`push_grant`
/// in den Hinweis schreiben. Der Hinweis KLASSIFIZIERT nichts (`design.md`
/// §11.4); er ordnet hier ausschliesslich zu, welche Bytes ein Server auf
/// welcher Seite herausgaebe.
fn sequence_of(path_hint: &str) -> Option<u64> {
    let name = path_hint.rsplit('/').next()?;
    let digits: String = name.chars().take_while(char::is_ascii_digit).collect();
    if digits.len() == 12 {
        digits.parse().ok()
    } else {
        None
    }
}

/// Alle Bytes des Bestandes, die zu KEINER Sequenz gehoeren.
///
/// Das sind die Vertrauensobjekte: Wurzelzertifikat, Registrierungskoepfe,
/// Geraetezertifikate. Ohne sie traegt Gate `trust` nicht, und ohne Gate
/// `trust` sagt der Bericht ueber kein einziges Objekt etwas.
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

/// Baut die Objektliste eines Rahmens: bytweise sortiert und duplikatfrei.
///
/// Beide Eigenschaften stehen auf der Leitung und nicht erst im Verbraucher
/// (`crates/ea-sync-protocol/src/reader.rs`); `ReaderBatchV1::new` weist eine
/// unsortierte oder doppelte Liste ab.
fn records(objects: Vec<Vec<u8>>) -> Vec<ObjectRecordV1> {
    let mut sorted: Vec<(ea_types::ObjectHash, Vec<u8>)> = objects
        .into_iter()
        .map(|bytes| (object_hash(&bytes), bytes))
        .collect();
    sorted.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    sorted.dedup_by(|left, right| left.0.as_bytes() == right.0.as_bytes());
    sorted
        .into_iter()
        .map(|(hash, bytes)| ObjectRecordV1::new(hash, bytes))
        .collect()
}

/// Kodiert einen Rahmen aus seinen sieben Positionen.
fn batch(
    after_sequence: u64,
    after_entry_hash: EntryHash,
    objects: Vec<ObjectRecordV1>,
    next_cursor: Option<Vec<u8>>,
    covered_through: u64,
) -> Vec<u8> {
    ReaderBatchV1::new(
        pinned_anchor().chain_id(),
        after_sequence,
        after_entry_hash,
        after_entry_hash,
        objects,
        next_cursor,
        covered_through,
    )
    .expect("der Fixture-Rahmen haelt jede Formgrenze ein")
    .exact_bytes()
    .to_vec()
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

/// Die ZWEITE Seite: die restlichen Sequenzen, ohne Blaetterschein.
///
/// Sie bindet DENSELBEN Startkopf wie die erste, und das ist keine
/// Nachlaessigkeit der Attrappe, sondern das Verhalten des echten Servers:
/// `crates/ea-sync-server/src/reader_sync.rs` schreibt
/// `request.after_entry_hash` in `requested-after-entry-hash` UND in
/// `start-head-entry-hash` und bindet seinen technischen Cursor an genau
/// diesen Startkopf. Innerhalb einer Lesestrecke bleibt der Startkopf stehen;
/// nur der Blaetterschein wandert.
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
///
/// Die ehrliche Antwort eines Servers, der nichts Neues hat: der Reader hat
/// bereits alles, der Rahmen bindet trotzdem den angefragten Startkopf.
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

/// Ein Rahmen, der an einem FREMDEN Startkopf ansetzt.
pub fn batch_for_a_different_start_head() -> Vec<u8> {
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

/// Derselbe Rahmen auf einer beliebigen fremden Sequenz, IN SICH stimmig.
pub fn internally_valid_batch_at_sequence(sequence: u64) -> Vec<u8> {
    let mut objects = base_objects();
    objects.extend(objects_for_sequences(0, FIRST_PAGE_THROUGH_V1));
    batch(
        sequence,
        EntryHash::try_from(&[0x41_u8; 32][..]).expect("32 Byte sind ein Eintragshash"),
        records(objects),
        None,
        sequence + 1,
    )
}

/// Ein Rahmen, dessen einer Satz andere Bytes traegt als seinen `objectHash`.
///
/// Die BYTES werden verkippt und nicht der Hash: eine geaenderte Adresse
/// zerstoerte die bytweise Sortierung des Rahmens, und `ReaderBatchV1::new`
/// wiese ihn schon dort ab — der Zeuge maesse dann den Rahmen statt den Cursor.
pub fn batch_with_a_missing_object() -> Vec<u8> {
    let mut objects = base_objects();
    objects.extend(objects_for_sequences(0, FIRST_PAGE_THROUGH_V1));
    let mut announced = records(objects);
    let victim = announced
        .pop()
        .expect("die erste Seite traegt mindestens einen Satz");
    let mut bytes = victim.exact_object_bytes().to_vec();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    announced.push(ObjectRecordV1::new(victim.object_hash(), bytes));
    batch(
        0,
        genesis_entry_hash(),
        announced,
        None,
        FIRST_PAGE_THROUGH_V1,
    )
}

/// Ein Rahmen, der die mittlere Sequenz auslaesst.
pub fn batch_with_a_sequence_gap() -> Vec<u8> {
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
///
/// Beide sind vollstaendig gueltig und tragen verschiedene `entryHash`-Werte;
/// `ea-chain` meldet dafuer einen Fork, und `ea-verify` traegt beide Objekte
/// als `conflicting` in die Quarantaene. Das ist eine Aussage ueber den SERVER
/// — er liefert zwei Ketten — und ausdruecklich keine ueber einen Verlust.
pub fn batch_forking_at_the_head() -> Vec<u8> {
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
