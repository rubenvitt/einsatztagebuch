//! EIN Tresor, EINE Registrierungslinie und die Bestaende, an denen die
//! Zustandssprache aus `design.md` §17.4 auseinanderfaellt.
//!
//! # Jeder Bestand wird GENAU EINMAL gebaut
//!
//! Nicht aus Sparsamkeit, sondern weil er NICHT deterministisch ist: die `.eag`
//! der Fixture entstehen ueber eine echte HPKE-Kapselung, und `hpke_seal` zieht
//! seinen ephemeren Schluessel je Aufruf neu. Zwei Aufrufe derselben Fixture
//! liefern verschiedene Grantbytes unter verschiedenen Objekthashes — gemessen,
//! und derselbe Grund, den `crates/ea-reader/tests/sync_support/fixtures.rs`
//! bereits ausschreibt. Ein Zeuge, der einen Bestand zweimal baut und beide
//! gegen denselben Hash haelt, misst deshalb nichts.
//!
//! # EIN Anker fuer ALLE Bestaende
//!
//! `trust_support::RegistryLineBuilder::new()` haelt `ROOT_SECRET`,
//! `organization()` und `chain_id()` als Konstanten; jede Linie dieses
//! Fixture-Moduls faengt damit an, und `exact_anchor_bytes()` haengt allein an
//! dieser Wurzel. ALLE Bestaende tragen deshalb denselben Anker, und EIN Tresor
//! klassifiziert sie alle. [`each_public_verification_failure`] prueft das
//! nach, statt es zu glauben.
//!
//! # Hashvergleiche laufen ueber `assert!`
//!
//! `hash_newtype!` in `crates/ea-types/src/ids.rs` leitet `Clone, Copy, Eq,
//! PartialEq, Ord, PartialOrd, Hash` ab — KEIN `Debug`. `assert_eq!` verlangt
//! `Debug` und uebersetzt darauf gar nicht erst. Aus demselben Grund sind
//! [`pinned_anchor_hash`] und [`entry_hash`] FUNKTIONEN und keine Konstanten:
//! fuer diese Typen gibt es kein `const fn new`. `ChainSequence` ist der
//! Gegenfall — `integer_newtype!` leitet `Debug` ab und gibt `pub const fn new`
//! heraus.

use std::sync::OnceLock;

use ea_archive::{ArchiveInventory, ArchiveSource};
use ea_crypto::SecretBytes;
use ea_reader::{
    AuthenticatorPrfV1, ReaderClassification, ReaderMode, ReaderVault, ReaderVerifier,
    SilentObserver, UnlockedVault, VaultContentsV1,
};
use ea_trust::decode_trust_anchor;
use ea_types::{EntryHash, Hash32, ObjectHash, UnixMillis, VerificationStatus};
use ea_verify::{DecryptionErrorV1, ManifestSignatureErrorV1};

use super::verify_support::{self, archive_support::ArchiveFixture};

// ---------------------------------------------------------------------------
// Die Uhr des Laufs
// ---------------------------------------------------------------------------

/// Die Betriebssystemuhr jedes Laufs dieser Kulisse.
///
/// Der Wert ist NICHT frei: `select_registry_head` misst gegen das
/// not-before/not-after-Fenster der Fixture-Koepfe, und `verify_support` haelt
/// mit `FIXTURE_OS_WALL_CLOCK_V1` genau den Wert, gegen den die Linie gebaut
/// ist. Ein eigener Wert daneben liesse Gate `trust` oder Gate `registry`
/// fallen, und der Zeuge maesse dann etwas anderes als sein Name sagt.
pub const EFFECTIVE_NOW: UnixMillis = UnixMillis::new(verify_support::FIXTURE_OS_WALL_CLOCK_V1);

/// Die Uhr eines ZWEITEN Laufs.
///
/// Genau eine Millisekunde spaeter, und mehr braucht es nicht: die
/// Frischepruefung von `decrypt_verified` vergleicht EXAKT und ohne Toleranz.
/// Ein Zeuge gilt fuer den Lauf, in dem er entstand, weil Gate
/// `recipient-grant` seine Nutzungsfrist gegen genau diesen Wert gemessen hat.
pub const LATER_EFFECTIVE_NOW: UnixMillis =
    UnixMillis::new(verify_support::FIXTURE_OS_WALL_CLOCK_V1 + 1);

// ---------------------------------------------------------------------------
// Der Tresor
// ---------------------------------------------------------------------------

/// Der Ed25519-Audit- und Geraeteschluessel des Kulissen-Tresors.
const VAULT_AUDIT_SEED_V1: [u8; 32] = [0x52; 32];
/// Die `credentialId` des einen Entsperrwegs.
const VAULT_CREDENTIAL_ID_V1: &[u8] = b"ea-reader-verify-passkey";
/// Die rohe PRF-Ausgabe dieses Entsperrwegs.
const VAULT_PRF_OUTPUT_V1: [u8; 32] = [0xa1; 32];

/// Eine entsperrte Sitzung, die den Anker der Fixturelinie PINNT und deren
/// KEM-Schluessel den eigenen Grants dieser Linie gehoert.
///
/// Beide Bindungen sind erzwungen und keine Wahl:
///
/// 1. Der Anker MUSS `complete_archive_anchor_bytes()` sein. Gegen den Anker
///    aus `crates/ea-reader/tests/fixtures/mod.rs` faellt jeder Bestand dieser
///    Linie an Gate `trust`, und der Lauf stiege mit einem Protokoll aus zwei
///    Eintraegen aus — genau der Ausgang, den `pinned_anchor.rs` ABSICHTLICH
///    herbeifuehrt.
/// 2. Der KEM-Seed MUSS `verify_support::complete_recipient_secret_bytes()`
///    sein. `ReaderVault::unlock` rechnet `kem_key_thumbprint` als
///    `CanonicalPublicCoseKey::x25519(*kem_private_key.public_key().as_bytes())?
///    .thumbprint()` — zeichengleich zu `verify_support::key_thumbprint_of`.
///    Nur so nennt der Abdruck der Sitzung denselben Empfaenger, den die Grants
///    der Linie adressieren, und nur dann entsteht ueberhaupt ein eigener
///    Grant. Der Seed `[0x51; 32]` der beiden Nachbarkulissen trifft ihn nicht.
///
/// # Panics
///
/// Wenn Versiegeln oder Entsperren scheitert.
#[must_use]
pub fn unlocked_vault_with_pinned_anchor() -> UnlockedVault {
    vault_pinning(complete_archive_anchor_bytes().to_vec())
}

/// Derselbe Tresor ueber BELIEBIGEN Ankerbytes.
///
/// Herausgezogen, damit `pinned_anchor.rs` einen Tresor auf einem fremden
/// Anker bauen kann, ohne die Versiegelung ein zweites Mal aufzuschreiben.
///
/// # Panics
///
/// Wenn Versiegeln oder Entsperren scheitert.
#[must_use]
pub fn vault_pinning(pinned_anchor_exact_bytes: Vec<u8>) -> UnlockedVault {
    let contents = VaultContentsV1::new(
        SecretBytes::new(verify_support::complete_recipient_secret_bytes()),
        SecretBytes::new(VAULT_AUDIT_SEED_V1),
        pinned_anchor_exact_bytes,
        None,
    );
    let sealed = ReaderVault::seal(contents, &[authenticator()])
        .expect("der Kulissen-Tresor muss sich versiegeln lassen");
    ReaderVault::unlock(&sealed, &authenticator())
        .expect("derselbe Authenticator muss ihn wieder oeffnen")
}

/// Der eine Entsperrweg dieser Kulisse.
///
/// Bei jedem Aufruf neu gebaut, weil `AuthenticatorPrfV1` kein `Clone` traegt:
/// es haelt eine PRF-Ausgabe, und eine zweite Kopie davon ist genau das, was
/// `web-reader-design.md` §6.5 nicht will.
fn authenticator() -> AuthenticatorPrfV1 {
    AuthenticatorPrfV1::new(
        VAULT_CREDENTIAL_ID_V1.to_vec(),
        SecretBytes::new(VAULT_PRF_OUTPUT_V1),
    )
}

// ---------------------------------------------------------------------------
// Die Bestaende
// ---------------------------------------------------------------------------

static COMPLETE_ARCHIVE_V1: OnceLock<verify_support::CompleteArchive> = OnceLock::new();
static NO_OWN_GRANT_ARCHIVE_V1: OnceLock<verify_support::CompleteArchive> = OnceLock::new();
static FORGED_HISTORICAL_ARCHIVE_V1: OnceLock<verify_support::ForgedHistoricalGrantArchive> =
    OnceLock::new();
static ISOLATION_ARCHIVE_V1: OnceLock<verify_support::CompleteArchive> = OnceLock::new();
static MUTATED_SIGNATURE_ARCHIVE_V1: OnceLock<verify_support::SignedEntryArchive> = OnceLock::new();
static MUTATED_THUMBPRINT_ARCHIVE_V1: OnceLock<verify_support::SignedEntryArchive> =
    OnceLock::new();
static MALFORMED_ARCHIVE_V1: OnceLock<ArchiveFixture> = OnceLock::new();
static SWAPPED_PREDECESSORS_ARCHIVE_V1: OnceLock<verify_support::ChainArchive> = OnceLock::new();
static MISSING_MIDDLE_ARCHIVE_V1: OnceLock<verify_support::ChainArchive> = OnceLock::new();
static ORPHAN_GRANT_ARCHIVE_V1: OnceLock<verify_support::ChainArchive> = OnceLock::new();
static MISMATCHED_PLAN_ARCHIVE_V1: OnceLock<verify_support::ChainArchive> = OnceLock::new();
static NO_RECOVERY_GRANT_ARCHIVE_V1: OnceLock<verify_support::ChainArchive> = OnceLock::new();
static UNKNOWN_WRITER_ARCHIVE_V1: OnceLock<verify_support::WriterArchive> = OnceLock::new();
static UNRESOLVABLE_STUB_ARCHIVE_V1: OnceLock<verify_support::ReportArchive> = OnceLock::new();
static RESOLVABLE_STUB_ARCHIVE_V1: OnceLock<verify_support::ReportArchive> = OnceLock::new();
static FORGED_STUB_ARCHIVE_V1: OnceLock<verify_support::ReportArchive> = OnceLock::new();
static FOREIGN_TARGET_STUB_ARCHIVE_V1: OnceLock<verify_support::ReportArchive> = OnceLock::new();
static GENESIS_PLAINTEXT_ARCHIVE_V1: OnceLock<verify_support::CompleteArchive> = OnceLock::new();
static GENESIS_PLAINTEXT_V1: OnceLock<Vec<u8>> = OnceLock::new();

/// Der lueckenlose Bestand: GENAU EIN Eintrag auf
/// [`verify_support::COMPLETE_GENESIS_SEQUENCE_V1`], mit echter HPKE-Kapselung
/// auf den Abdruck des Tresors.
///
/// Ein Eintrag ist hier ein VORTEIL und kein Sparzwang: nur an einem
/// einentraegigen Bestand sagt eine Aussage ueber das archivweite Protokoll
/// etwas ueber DIESEN Eintrag aus.
#[must_use]
pub fn complete_archive() -> &'static ArchiveFixture {
    &complete().fixture
}

fn complete() -> &'static verify_support::CompleteArchive {
    COMPLETE_ARCHIVE_V1.get_or_init(verify_support::complete_valid_archive)
}

/// Der lueckenlose Bestand, dessen einziger Eintrag den EINGEFRORENEN
/// Genesis-Klartext traegt.
///
/// Das ist der EINZIGE Bestand dieses Moduls mit schemagueltigem Klartext, und
/// er ist der Traeger des vollen Erfolgspfads von `decrypt_verified`: alle
/// anderen Bestaende tragen `verify_support::COMPLETE_PLAINTEXT_V1`, an dem
/// die Schemabestimmung erwartungsgemaess scheitert. Er entsteht ueber
/// `complete_valid_archive_with_plaintext` und damit ueber DENSELBEN Bau wie
/// [`complete_archive`]; nur der Klartext ist ein anderer. Derselbe Anker,
/// derselbe Tresor.
#[must_use]
pub fn complete_archive_with_a_genesis_plaintext() -> &'static ArchiveFixture {
    &GENESIS_PLAINTEXT_ARCHIVE_V1
        .get_or_init(|| verify_support::complete_valid_archive_with_plaintext(genesis_plaintext()))
        .fixture
}

/// Der eingefrorene Genesis-Vektor aus `vectors/format/payload-v1/genesis.hex`
/// — dieselbe Quelle, gegen die `crates/ea-schema/tests/v1_validation.rs`
/// seine Bestimmung misst.
///
/// Aus dem Vektor und nicht aus `ea_schema::encode_payload`: der Zeuge soll
/// den Klartext gegen etwas messen, das NICHT der Reader selbst erzeugt hat.
#[must_use]
pub fn genesis_plaintext() -> &'static [u8] {
    GENESIS_PLAINTEXT_V1.get_or_init(|| {
        hex::decode(include_str!("../../../../vectors/format/payload-v1/genesis.hex").trim_end())
            .expect("der eingefrorene Genesis-Vektor ist gueltiges Hex")
    })
}

/// Die EXAKTEN Ankerbytes der Fixture-Registrierungslinie.
#[must_use]
pub fn complete_archive_anchor_bytes() -> &'static [u8] {
    &complete().anchor_bytes
}

/// Der Selbsttragungshash desselben Ankers.
///
/// FUNKTION und keine Konstante: `Hash32` hat kein `const fn new` und kein
/// `Debug`.
///
/// # Panics
///
/// Wenn die Ankerbytes der Linie nicht dekodieren.
#[must_use]
pub fn pinned_anchor_hash() -> Hash32 {
    decode_trust_anchor(complete_archive_anchor_bytes())
        .expect("der Anker der Fixturelinie traegt seinen eigenen Bootstrap-Hash")
        .trust_anchor_hash()
}

/// Derselbe Bestand, dessen einziger Grant einen FREMDEN Empfaenger nennt.
///
/// Der Eintrag bleibt vollstaendig gueltig, der Bestand bleibt
/// `is_fully_verified()`: ein fehlender eigener Grant ist KEIN Mangel.
#[must_use]
pub fn entry_without_own_grant() -> &'static ArchiveFixture {
    &NO_OWN_GRANT_ARCHIVE_V1
        .get_or_init(verify_support::archive_without_the_own_grant)
        .fixture
}

/// Derselbe Bestand PLUS einem gefaelschten historischen Grant.
///
/// GEMESSEN, und anders als es der fruehere Plantext behauptete: der Bestand
/// traegt den initialen eigenen Grant WEITERHIN. `own_grant` filtert auf
/// `GrantKindV1::Initial`, sieht den historischen nie, und der Eintrag bleibt
/// damit vollstaendig verifiziert. Der historische Grant hinterlaesst
/// schlicht NICHTS — kein Befund, kein Code, kein Ereignis.
#[must_use]
pub fn archive_with_a_forged_historical_grant() -> &'static ArchiveFixture {
    &forged_historical().archive.fixture
}

/// Der Objekthash des gefaelschten historischen Grants in
/// [`archive_with_a_forged_historical_grant`].
///
/// Er liegt UNTER dem des initialen eigenen Grants — die Fixture mahlt ihn so
/// —, und `inventory.grants()` liegt aufsteigend nach Objekthash. Ein
/// `own_grant`, das die Art nicht filtert, faende deshalb ZUERST die
/// Faelschung; genau diese Ordnung macht den Zeugen ueberhaupt scharf.
#[must_use]
pub fn forged_historical_grant_object_hash() -> ObjectHash {
    forged_historical().forged_grant_object_hash
}

fn forged_historical() -> &'static verify_support::ForgedHistoricalGrantArchive {
    FORGED_HISTORICAL_ARCHIVE_V1
        .get_or_init(verify_support::complete_archive_with_a_forged_historical_grant)
}

/// Ein Grant, der den EIGENEN Abdruck nennt und auf FREMDES Material gekapselt
/// ist.
///
/// Der Zustand `unbekannter Schluessel` aus `design.md` §17.4: der Grant nennt
/// denselben Abdruck und dasselbe Zertifikat — beides geht in den Planhash ein
/// —, gekapselt ist er auf den oeffentlichen Schluessel des anderen
/// Empfaengers. Der Befund landet unter dem Objekthash des GRANTS, waehrend der
/// Eintrag sein `ObjectResultKindV1::Valid` behaelt.
///
/// ACHTUNG: der Bestand traegt DREI Eintraege, von denen zwei mit eigenem Grant
/// erfolgreich oeffnen. Er darf in keinem Zeugen stehen, der die Abwesenheit
/// von `hpke-open` behauptet.
#[must_use]
pub fn grant_on_own_thumbprint_wrong_material() -> &'static ArchiveFixture {
    &ISOLATION_ARCHIVE_V1
        .get_or_init(|| {
            verify_support::isolation_archive(
                verify_support::IsolationDefectV1::ForeignEncapsulation,
            )
        })
        .fixture
}

/// Ein Eintrag mit EINEM verkippten Byte im rohen Ed25519-Signaturwert.
///
/// Der Befund steht unter dem EINTRAGS-Objekthash und macht die Zeile
/// `ungueltig`. Die Grants dieser Familie adressieren
/// `recovery_recipient_key_thumbprint()` und koennen den Abdruck des Tresors
/// nie treffen — es gibt hier also garantiert kein `hpke-open`.
#[must_use]
pub fn entry_with_a_flipped_manifest_byte() -> &'static ArchiveFixture {
    &MUTATED_SIGNATURE_ARCHIVE_V1
        .get_or_init(|| {
            verify_support::archive_with_one_mutated_entry(
                verify_support::MUTATED_EIP_SIGNATURE_OFFSET_V1,
            )
        })
        .fixture
}

/// Ein Bestand mit einem `.eds`, dessen Vernichtung im Bestand auf NICHTS
/// zeigt.
///
/// Der Stummel traegt `DestructionId([0x43; 16])`, die abgelegte Vernichtung
/// traegt `[REPORT_DESTRUCTION_MARKER_V1; 16]`. Der Join gegen
/// `authorized_destructions()` geht ins Leere: `ungeklaerte Luecke`.
#[must_use]
pub fn stub_without_resolvable_authorization() -> &'static ArchiveFixture {
    &UNRESOLVABLE_STUB_ARCHIVE_V1
        .get_or_init(verify_support::complete_report_archive)
        .fixture
}

/// Derselbe Bestand, dessen `.eds` die Vernichtung darin AUFLOEST.
///
/// Der Stummel nennt die Kennung und den Autorisierungshash des Vorgangs, der
/// tatsaechlich abgelegt ist, und dessen Autorisierung nennt den Eintrag des
/// Stummels: `autorisiert vernichtet`.
#[must_use]
pub fn stub_with_resolvable_authorization() -> &'static ArchiveFixture {
    &RESOLVABLE_STUB_ARCHIVE_V1
        .get_or_init(verify_support::report_archive_with_a_resolvable_stub)
        .fixture
}

/// Derselbe Bestand mit einem GEFAELSCHTEN `.eds`.
///
/// Ein kopiertes, korrekt signiertes Manifest unter der ECHTEN Kennung des
/// abgelegten Vorgangs, aber mit einem Autorisierungshash, unter dem im
/// Bestand nichts liegt. Der Bericht traegt dazu keinen einzigen Befund —
/// `ea-verify` prueft die beiden Stummelfelder nicht —, und genau deshalb muss
/// der Reader sie pruefen: `ungeklaerte Luecke`.
#[must_use]
pub fn stub_naming_a_forged_authorization_hash() -> &'static ArchiveFixture {
    &FORGED_STUB_ARCHIVE_V1
        .get_or_init(verify_support::report_archive_with_a_stub_naming_a_forged_authorization_hash)
        .fixture
}

/// Derselbe Bestand, dessen Vernichtung einen ANDEREN Eintrag nennt.
///
/// Kennung und Autorisierungshash des Stummels treffen; die Autorisierung
/// selbst nennt unter `targets` aber nicht den Eintrag des Stummels. Die
/// Pruefkette bricht am letzten Glied: `ungeklaerte Luecke`.
#[must_use]
pub fn stub_of_an_authorization_targeting_another_entry() -> &'static ArchiveFixture {
    &FOREIGN_TARGET_STUB_ARCHIVE_V1
        .get_or_init(
            verify_support::report_archive_with_a_stub_of_an_authorization_targeting_another_entry,
        )
        .fixture
}

/// Ein Bestand mit einer Luecke OHNE Traeger.
///
/// [`verify_support::MISSING_MIDDLE_SEQUENCE_V1`] ist ausgelassen; zu dieser
/// Sequenz existiert per Definition kein Objekt und damit weder ein
/// `EntryHash` noch ein `ObjectHash`. Sie ist deshalb ausschliesslich
/// SEQUENZadressiert darstellbar.
#[must_use]
pub fn archive_with_a_gap_without_a_stub() -> &'static ArchiveFixture {
    &missing_middle().fixture
}

fn missing_middle() -> &'static verify_support::ChainArchive {
    MISSING_MIDDLE_ARCHIVE_V1.get_or_init(verify_support::archive_with_a_missing_middle_entry)
}

// ---------------------------------------------------------------------------
// Die Adressen in den Bestaenden
// ---------------------------------------------------------------------------

/// Der Eintragshash des EINEN Eintrags eines Bestands.
///
/// Aus dem geparsten `.eip` gewonnen und NIE als Literal abgeschrieben: ein
/// abgeschriebener Hash waere beim naechsten Layoutwechsel in `ea-format` eine
/// stille Luege. Die Zusicherung auf genau einen Eintrag steht hier, damit ein
/// mehrentraegiger Bestand nicht versehentlich ueber `entries()[0]` in einen
/// Zeugen rutscht — dafuer gibt es [`entry_hash_at`].
///
/// # Panics
///
/// Wenn der Bestand nicht genau einen Eintrag traegt.
#[must_use]
pub fn entry_hash(source: &dyn ArchiveSource) -> EntryHash {
    let inventory = inventory_of(source);
    assert_eq!(
        inventory.entries().len(),
        1,
        "entry_hash gilt nur fuer einen einentraegigen Bestand"
    );
    inventory.entries()[0].value().entry_hash()
}

/// Der Eintragshash des Eintrags auf `chain_sequence`.
///
/// # Panics
///
/// Wenn kein oder mehr als ein Eintrag auf dieser Sequenz liegt.
#[must_use]
pub fn entry_hash_at(source: &dyn ArchiveSource, chain_sequence: u64) -> EntryHash {
    let inventory = inventory_of(source);
    let mut found = inventory
        .entries()
        .iter()
        .filter(|entry| entry.value().manifest().fields().chain_sequence.get() == chain_sequence);
    let entry = found
        .next()
        .expect("auf dieser Sequenz liegt ein Eintrag")
        .value()
        .entry_hash();
    assert!(
        found.next().is_none(),
        "auf dieser Sequenz liegt genau ein Eintrag"
    );
    entry
}

/// Der Eintragshash, den der `.eds`-Stummel eines Bestands weitertraegt.
///
/// Er ist der EINZIGE Schluessel, unter dem eine Luecke ueberhaupt als Zeile
/// darstellbar ist: `DestroyedEntryStubV1` fuehrt `entry_hash()` und ueber sein
/// `signed_manifest()` die `chain_sequence` selbst.
///
/// # Panics
///
/// Wenn der Bestand nicht genau einen Stummel traegt.
#[must_use]
pub fn stub_entry_hash(source: &dyn ArchiveSource) -> EntryHash {
    let inventory = inventory_of(source);
    assert_eq!(
        inventory.destroyed().len(),
        1,
        "stub_entry_hash gilt nur fuer einen Bestand mit genau einem Stummel"
    );
    inventory.destroyed()[0].value().entry_hash()
}

fn inventory_of(source: &dyn ArchiveSource) -> ArchiveInventory {
    ArchiveInventory::build(source).expect("die Fixture-Bestaende sind inventarisierbar")
}

// ---------------------------------------------------------------------------
// Die Tabellen
// ---------------------------------------------------------------------------

/// Ein oeffentlich sichtbarer Verifikationsfehlschlag samt der Adresse, fuer
/// die der Lauf KEINEN Zeugen herausgeben darf.
pub struct PublicFailure {
    /// Der Name, unter dem ein Fehlschlag im Zeugen erscheint.
    pub label: &'static str,
    /// Der Bestand.
    pub source: &'static ArchiveFixture,
    /// Der Eintrag, den der Bericht bemaengelt — sofern es einen gibt.
    ///
    /// `None` fuer die drei Bestaende, deren Befund gar keinen Eintrag trifft:
    /// eine trägerlose Luecke, ein verwaister Grant und unlesbare Bytes. Sie
    /// bleiben in der Tabelle, weil die Abwesenheitszusage ueber `hpke-open`
    /// auch fuer sie gilt.
    pub invalid_entry_hash: Option<EntryHash>,
}

/// Wie viele Zeilen von [`each_public_verification_failure`] einen bemaengelten
/// EINTRAG nennen.
///
/// Der Zaehler steht hier, damit die `Option` nicht still zu lauter `None`
/// verkommen kann: ein Zeuge, der ueber neun Bestaende laeuft und nirgends eine
/// Adresse prueft, waere gruen, ohne etwas zu messen.
pub const PUBLIC_FAILURES_WITH_AN_INVALID_ENTRY_V1: usize = 6;

/// Jeder Bestand, dessen Fehlschlag VOR der Entkapselung sichtbar wird.
///
/// Die Auswahl ist gemessen und keine Bequemlichkeit: kein Bestand dieser
/// Tabelle traegt einen oeffenbaren eigenen Grant. Die Grants der Ketten- und
/// der Schreiberfamilie adressieren `recovery_recipient_key_thumbprint()` und
/// koennen den Abdruck des Tresors nie treffen; die Schreiberfamilie legt
/// ueberhaupt keine Grants ab.
///
/// AUSDRUECKLICH NICHT dabei ist [`grant_on_own_thumbprint_wrong_material`]:
/// dort bleiben zwei von drei Eintraegen unversehrt und oeffnen mit eigenem
/// Grant, und die Abwesenheitszusage wuerde aus einem unbeteiligten Eintrag
/// heraus rot.
///
/// # Panics
///
/// Wenn ein Bestand einen anderen Anker traegt als der Tresor pinnt.
#[must_use]
pub fn each_public_verification_failure() -> Vec<PublicFailure> {
    let swapped = SWAPPED_PREDECESSORS_ARCHIVE_V1
        .get_or_init(verify_support::archive_with_swapped_predecessors);
    let orphan = ORPHAN_GRANT_ARCHIVE_V1.get_or_init(verify_support::archive_with_an_orphan_grant);
    let mismatched = MISMATCHED_PLAN_ARCHIVE_V1
        .get_or_init(verify_support::archive_with_a_mismatched_grant_plan_hash);
    let no_recovery =
        NO_RECOVERY_GRANT_ARCHIVE_V1.get_or_init(verify_support::archive_without_a_recovery_grant);
    let unknown_writer =
        UNKNOWN_WRITER_ARCHIVE_V1.get_or_init(verify_support::archive_with_one_unknown_writer);
    let thumbprint = MUTATED_THUMBPRINT_ARCHIVE_V1.get_or_init(|| {
        verify_support::archive_with_one_mutated_entry(
            verify_support::MUTATED_EIP_KEY_THUMBPRINT_OFFSET_V1,
        )
    });

    for (label, anchor_bytes) in [
        ("swapped_predecessors", swapped.anchor_bytes.as_slice()),
        ("orphan_grant", orphan.anchor_bytes.as_slice()),
        ("mismatched_plan", mismatched.anchor_bytes.as_slice()),
        ("no_recovery_grant", no_recovery.anchor_bytes.as_slice()),
        ("unknown_writer", unknown_writer.anchor_bytes.as_slice()),
        ("mutated_thumbprint", thumbprint.anchor_bytes.as_slice()),
        ("missing_middle", missing_middle().anchor_bytes.as_slice()),
    ] {
        assert!(
            anchor_bytes == complete_archive_anchor_bytes(),
            "{label} traegt einen anderen Anker als der Tresor pinnt"
        );
    }

    vec![
        PublicFailure {
            label: "verkippte Schreibersignatur",
            source: entry_with_a_flipped_manifest_byte(),
            invalid_entry_hash: Some(entry_hash(entry_with_a_flipped_manifest_byte())),
        },
        PublicFailure {
            label: "verkippter Schluesselabdruck im geschuetzten Header",
            source: &thumbprint.fixture,
            invalid_entry_hash: Some(entry_hash(&thumbprint.fixture)),
        },
        PublicFailure {
            label: "vertauschte Vorgaenger",
            source: &swapped.fixture,
            invalid_entry_hash: Some(entry_hash_at(
                &swapped.fixture,
                verify_support::FIRST_ENTRY_SEQUENCE_V1 + 1,
            )),
        },
        PublicFailure {
            label: "ausgelassene Sequenz ohne Stummel",
            source: &missing_middle().fixture,
            invalid_entry_hash: None,
        },
        PublicFailure {
            label: "verwaister Grant",
            source: &orphan.fixture,
            invalid_entry_hash: None,
        },
        PublicFailure {
            label: "Grantplan des Eintrags passt nicht",
            source: &mismatched.fixture,
            invalid_entry_hash: Some(entry_hash(&mismatched.fixture)),
        },
        PublicFailure {
            label: "kein Recovery-Grant im Plan",
            source: &no_recovery.fixture,
            invalid_entry_hash: Some(entry_hash(&no_recovery.fixture)),
        },
        PublicFailure {
            label: "unbekannter Schreiber",
            source: &unknown_writer.fixture,
            invalid_entry_hash: Some(entry_hash_at(
                &unknown_writer.fixture,
                verify_support::UNKNOWN_WRITER_SEQUENCE_V1,
            )),
        },
        PublicFailure {
            label: "unlesbare Bytes mit Exact-Object-Praefix",
            source: archive_with_malformed_bytes(),
            invalid_entry_hash: None,
        },
    ]
}

/// Ein unversehrter Bestand PLUS Bytes, die Gate `format` nicht ueberleben.
///
/// Der unversehrte Eintrag ist erzwungen und nicht Beiwerk: ohne
/// Vertrauensobjekte stiege der Lauf schon an Gate `trust` aus, und der
/// Formatbefund faende gar nicht mehr statt. Der Bestand legt KEINE Grants ab,
/// also gibt es hier garantiert kein `hpke-open`.
fn archive_with_malformed_bytes() -> &'static ArchiveFixture {
    MALFORMED_ARCHIVE_V1.get_or_init(|| {
        let mut fixture = verify_support::archive_with_one_signed_entry().fixture;
        fixture.push_exact_bytes(
            &format!("{}malformed.eip", ea_archive::ENTRIES_DIR_V1),
            verify_support::archive_support::eip_with_one_mutated_body_byte(),
        );
        fixture
    })
}

/// Ein Zustand, den die Klassifikation ueber genau einer Adresse bilden muss.
pub struct StateCase {
    /// Der Name, unter dem die Zeile im Zeugen erscheint.
    pub label: &'static str,
    /// Der Bestand.
    pub source: &'static ArchiveFixture,
    /// Die Adresse der Zustandszeile.
    pub key: EntryHash,
    /// Der erwartete Verifikationsstatus.
    pub expected: VerificationStatus,
    /// Der erwartete Detailcode.
    pub expected_code: Option<&'static str>,
}

/// Die Zustaende, die `design.md` §17.4 auseinanderhaelt, an je einem Bestand.
///
/// FUENF der sechs Begriffe stehen hier. `UnsupportedSchema` fehlt, und das ist
/// gemessen und kein Versehen: er entsteht erst, wenn ein Klartext vorliegt und
/// keine der fuenf Schemabestimmungen ihn traegt — `classify` entschluesselt
/// aber nichts. Sein Zeuge ist deshalb der Rueckgabecode von
/// `decrypt_verified` und steht in `historical_expiry.rs`.
///
/// `Invalid` steht ZWEIMAL, mit und ohne Detailcode. Das ist die Schranke aus
/// `PERSISTED_DETAIL_CODES_V1`: `archive_without_a_recovery_grant()` erzeugt
/// gemessen den Code `EA-GRANT-MISSING-RECOVERY`, und der steht NICHT in der
/// persistierbaren Tabelle. Ein Zustand, den der Zustandsspeicher nicht
/// annaehme, waere wertlos — der Detailgrund faellt hier also weg, der Zustand
/// bleibt.
#[must_use]
pub fn the_measured_states() -> Vec<StateCase> {
    let isolation = grant_on_own_thumbprint_wrong_material();
    let unresolvable = stub_without_resolvable_authorization();
    let no_recovery =
        NO_RECOVERY_GRANT_ARCHIVE_V1.get_or_init(verify_support::archive_without_a_recovery_grant);
    vec![
        StateCase {
            label: "verifiziert",
            source: complete_archive(),
            key: entry_hash(complete_archive()),
            expected: VerificationStatus::Verified,
            expected_code: None,
        },
        StateCase {
            label: "fehlender Grant",
            source: entry_without_own_grant(),
            key: entry_hash(entry_without_own_grant()),
            expected: VerificationStatus::MissingGrant,
            expected_code: None,
        },
        StateCase {
            label: "unbekannter Schluessel",
            source: isolation,
            key: entry_hash_at(isolation, verify_support::ISOLATION_DEFECT_SEQUENCE_V1),
            expected: VerificationStatus::UnknownKey,
            expected_code: Some(DecryptionErrorV1::CekUnwrapFailed.code()),
        },
        StateCase {
            label: "ungueltig",
            source: entry_with_a_flipped_manifest_byte(),
            key: entry_hash(entry_with_a_flipped_manifest_byte()),
            expected: VerificationStatus::Invalid,
            expected_code: Some(ManifestSignatureErrorV1::SignatureInvalid.code()),
        },
        StateCase {
            label: "ungueltig ohne persistierbaren Detailgrund",
            source: &no_recovery.fixture,
            key: entry_hash(&no_recovery.fixture),
            expected: VerificationStatus::Invalid,
            expected_code: None,
        },
        StateCase {
            label: "Luecke",
            source: unresolvable,
            key: stub_entry_hash(unresolvable),
            expected: VerificationStatus::Gap,
            expected_code: None,
        },
    ]
}

// ---------------------------------------------------------------------------
// Die Klassifikation
// ---------------------------------------------------------------------------

/// Ein Klassifikationslauf ueber [`EFFECTIVE_NOW`], ohne Protokollmitschrift.
///
/// # Panics
///
/// Wenn die Klassifikation scheitert. Ein Befund ueber ein EINZELNES Objekt ist
/// nie ein `Err` — dieselbe Regel, die `crates/ea-verify/src/lib.rs`
/// ausschreibt.
#[must_use]
pub fn classify(source: &dyn ArchiveSource, session: &UnlockedVault) -> ReaderClassification {
    classify_at(source, session, EFFECTIVE_NOW)
}

/// Derselbe Lauf ueber einer gewaehlten Uhr.
///
/// # Panics
///
/// Wie [`classify`].
#[must_use]
pub fn classify_at(
    source: &dyn ArchiveSource,
    session: &UnlockedVault,
    effective_now: UnixMillis,
) -> ReaderClassification {
    ReaderVerifier::new(ReaderMode::Server, effective_now)
        .classify(source, session, &mut SilentObserver)
        .expect("ein Fixture-Bestand laesst sich klassifizieren")
}
