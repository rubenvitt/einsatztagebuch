//! Bestaende, deren Registrierungsfenster die ECHTE Betriebssystemuhr
//! enthalten.
//!
//! # Warum diese Familie existiert
//!
//! Die geerbten Bestaende aus [`super::verify_support`] tragen samtlich Koepfe
//! aus `trust_support::HeadOptions::default()` (`issued_at = 100`,
//! `not_after = 10_000`). Unter der echten Uhr — gemessen 1_786_938_024_364 —
//! sind die laengst veraltet, Gate `trust` traegt nicht mehr, und der Bericht
//! sagt ueber KEIN Objekt etwas aus, obwohl `is_fully_verified()` wahr bleibt.
//! Die Fixture-Uhr `FIXTURE_OS_WALL_CLOCK_V1 = 800` rettet sie dort, wo die Uhr
//! ein Parameter ist; im Wiederherstellungspfad ist sie es nicht.
//!
//! # Die drei Werte, an denen alles haengt
//!
//! GEMESSEN und nicht hergeleitet:
//!
//! - Der Policy-Kopf bleibt zur echten Uhr VERALTET
//!   ([`LIVE_POLICY_NOT_AFTER_V1`] liegt vor `now`). Genau deshalb wird er
//!   nachgezogen statt gewaehlt, und der Schreiberkopf deckt die Sequenz null
//!   selbst. Diese Asymmetrie ist der ganze Mechanismus — sie zu
//!   "appreparieren" macht den Genesis-Eintrag `unattributable`. Die Tabelle
//!   an `verify_support::GENESIS_GAP_SEQUENCE_V1` misst alle fuenf Varianten
//!   durch.
//! - [`LIVE_POLICY_MAX_REGISTRY_AGE_MS_V1`] hebt allein die Altersschranke auf,
//!   die den ganzen Linienstand sonst verwerfen wuerde.
//! - Der Schreiberkopf ist bis [`LIVE_WRITER_NOT_AFTER_V1`] gueltig und deshalb
//!   waehlbar.
//!
//! # Determinismus
//!
//! Nur die VERIFIKATIONSUHR kommt aus [`SystemTime::now`]. Jedes Byte eines
//! Bestands ist von ihr unabhaengig; `created_at_device` ist die feste
//! Konstante [`LIVE_CREATED_AT_DEVICE_V1`]. Ein aus `now` abgeleitetes Feld
//! machte den Bestand von Lauf zu Lauf anders und zerstoerte jede
//! Byteidentitaetsaussage.
//!
//! DAVON UNBERUEHRT: `ea_crypto::hpke_seal` zieht je Aufruf ein FRISCHES
//! ephemeres Schluesselpaar. Zwei Konstruktionen desselben Fixtures liefern
//! deshalb verschiedene Grantbytes. Wer Byteidentitaet misst, materialisiert
//! EINEN Bestand und laesst ihn zweimal laufen — er baut ihn nicht zweimal.

use std::time::{SystemTime, UNIX_EPOCH};

use ea_crypto::{
    HPKE_ENCAPSULATED_KEY_SIZE, HPKE_WRAPPED_CEK_SIZE, HpkeRecipientPublicKey, SecretBytes,
    object_hash,
};
use ea_format::{
    CertificateKindV1, EntryPackageV1, GrantBodyFieldsV1, GrantBodyV1, GrantKindV1,
    GrantPlanItemV1, GrantPlanV1, GrantPurposeV1, GrantV1, ManifestCoreFieldsV1, ManifestCoreV1,
    SignedManifestV1, encode_entry_package, encode_grant,
};
use ea_trust::{TrustAnchorV1, TrustObjectSource, decode_trust_anchor};
use ea_types::{
    CertificateHash, ChainId, ChainSequence, EntryHash, Hash32, ObjectHash, RegistryVersion,
    UnixMillis,
};
use ea_verify::VerifyOptions;

use super::verify_support::{
    archive_support::{ArchiveFixture, trust_support},
    complete_recipient_certificate_hash, complete_recipient_key_thumbprint,
    complete_recipient_private_key, other_recipient_private_key, writer_device_key_thumbprint,
    writer_device_signer,
};

/// Ende der Gueltigkeit des Policy-Kopfes: 2001-09-09.
///
/// LIEGT BEWUSST IN DER VERGANGENHEIT. Ein Registrierungskopf, der zur Uhr des
/// Laufs veraltet ist, wird nicht gewaehlt, sondern nachgezogen
/// (`crates/ea-trust/src/registry.rs:594` und `:640-647`). Genau dadurch wird
/// der Schreiberkopf die Autoritaet ueber die Sequenz null, und erst dadurch
/// ist der Genesis-Eintrag zuordenbar.
pub const LIVE_POLICY_NOT_AFTER_V1: i64 = 1_000_000_000_000;

/// Die Altersschranke, die die Policy dieses Bestands setzt.
///
/// NICHT `u64::MAX`: die Schranke rechnet `issued_at + max_age`, und der
/// Maximalwert liefe dabei ueber. `1 << 60` ist gemessen ausreichend und
/// liegt rund 36 Millionen Jahre in der Zukunft.
pub const LIVE_POLICY_MAX_REGISTRY_AGE_MS_V1: u64 = 1 << 60;

/// Ende der Gueltigkeit des Schreiberkopfes: 2100-01-01T00:00:00Z.
///
/// DAS AUSDRUECKLICHE VERFALLSDATUM DIESER FIXTUREFAMILIE. Ab diesem Zeitpunkt
/// ist der Schreiberkopf zur echten Uhr veraltet und diese Bestaende sagen
/// nichts mehr aus. Wer nach 2100 hier steht, hebt den Wert an — er repariert
/// nicht die Tests.
pub const LIVE_WRITER_NOT_AFTER_V1: i64 = 4_102_444_800_000;

/// Erste Sequenz der Lease des Schreiberkopfes.
pub const LIVE_WRITER_LEASE_FROM_V1: u64 = 0;
/// Letzte Sequenz dieser Lease.
pub const LIVE_WRITER_LEASE_THROUGH_V1: u64 = 100;
/// Die Sequenz des Genesis-Eintrags.
pub const LIVE_GENESIS_SEQUENCE_V1: u64 = 0;

/// Die Sequenz, die [`live_clock_archive_with_a_missing_middle_entry`]
/// AUSLAESST.
///
/// Die MITTLERE und nicht die letzte: eine Luecke am oberen Rand waere von
/// einem schlicht kuerzeren Bestand nicht zu unterscheiden. Dieselbe
/// Ueberlegung wie an `verify_support::UNKNOWN_WRITER_SEQUENCE_V1`.
pub const LIVE_MISSING_MIDDLE_SEQUENCE_V1: u64 = LIVE_GENESIS_SEQUENCE_V1 + 1;

/// Der `created_at_device`-Wert jedes Grants dieser Familie.
///
/// FEST und nicht aus [`SystemTime::now`]: die Bytes eines Bestands duerfen von
/// der Uhr des Laufs nicht abhaengen, sonst gibt es keine Byteidentitaet zu
/// messen. Der Wert liegt in der Vergangenheit und erzeugt deshalb auch keinen
/// Zukunftsversatz.
pub const LIVE_CREATED_AT_DEVICE_V1: i64 = 1_000_000_000;

/// Der Klartext hinter dem Ciphertext jedes Eintrags dieser Familie.
///
/// Beliebige, aber FESTE Bytes: kein Gate liest ihn, und der Bericht enthaelt
/// ihn nie. Er ist da, damit die Entschluesselung etwas zu pruefen hat.
pub const LIVE_PLAINTEXT_V1: &[u8] = b"einsatzarchiv-live-fixture-payload";

/// Der Pfad des Beiwerks unter [`ea_archive::FORMAT_SCHEMAS_DIR_V1`].
///
/// GESCHACHTELT, und das ist der Zweck: der Pfad uebt `create_dir_all` sowohl
/// in `super::materialize` als auch im Exportschreiber. Ein Bestand aus lauter
/// Dateien auf einer Ebene pruefte das nie.
///
/// Als Literal geschrieben, weil `concat!` nur Literale nimmt. Die Bindung an
/// [`ea_archive::FORMAT_SCHEMAS_DIR_V1`] stellt deshalb [`build`] her — sonst
/// hoerte dieser Bestand still auf, den geschachtelten Fall zu pruefen, falls
/// das Layout je umzieht.
pub const LIVE_FORMAT_SCHEMA_FILE_V1: &str = "format/schemas/ea.entry-package.v1.cddl";

/// Der Text der Formatbeschreibung dieser Bestaende.
const LIVE_README_BYTES_V1: &[u8] = b"Einsatzarchiv v1 -- Beiwerk, kein Archivobjekt.\n";

/// Der Text des Schemabeiwerks.
const LIVE_SCHEMA_BYTES_V1: &[u8] = b"; ea.entry-package.v1 -- Beiwerk, kein Archivobjekt.\n";

/// Der Inhaltsschluessel eines Eintrags, JE SEQUENZ EIN EIGENER.
///
/// Keine Kosmetik: ein zweiter Eintrag unter demselben Paar aus Schluessel und
/// `nonce` waere eine Nonce-Wiederverwendung und damit ein echter Bruch der
/// AEAD-Annahme. Eine Fixture, die das vormacht, lehrt das Falsche.
fn live_cek(chain_sequence: u64) -> [u8; 32] {
    let mut cek = [0x7b_u8; 32];
    cek[0] ^= u8::try_from(chain_sequence & 0xff).expect("ein Byte");
    cek
}

/// Die `nonce` des Manifests und damit die des AEAD, je Sequenz eine eigene.
fn live_nonce(chain_sequence: u64) -> [u8; 12] {
    let mut nonce = [0x2d_u8; 12];
    nonce[0] ^= u8::try_from(chain_sequence & 0xff).expect("ein Byte");
    nonce
}

/// Die ECHTE Betriebssystemuhr als [`UnixMillis`].
///
/// # Panics
///
/// Wenn die Systemuhr vor der Unix-Epoche steht. Dann ist nicht die Fixture
/// falsch, sondern die Maschine, und das muss laut werden.
#[must_use]
pub fn live_clock() -> UnixMillis {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("die Systemuhr muss hinter der Unix-Epoche stehen")
        .as_millis();
    UnixMillis::new(i64::try_from(millis).expect("die Systemuhr passt bis 292278994 in i64"))
}

/// Ein Verifikationslauf gegen die echte Uhr, OHNE Empfaengerschluessel.
///
/// Ohne Schluessel wird nichts entkapselt — was ausdruecklich kein Mangel ist.
/// Wer die Entkapselung messen will, haengt `with_recipient` selbst an; der
/// private Schluessel muss dafuer beim Aufrufer leben.
#[must_use]
pub fn live_clock_options() -> VerifyOptions<'static> {
    VerifyOptions::new(live_clock())
}

/// Ein Bestand, dessen Registrierungsfenster die echte Uhr enthaelt.
pub struct LiveArchive {
    pub fixture: ArchiveFixture,
    pub anchor_bytes: Vec<u8>,
    /// Objekthashes der abgelegten `.eip`, in Sequenzreihenfolge.
    pub entry_object_hashes: Vec<ObjectHash>,
    /// Objekthashes der abgelegten `.eag`, in derselben Reihenfolge.
    ///
    /// KUERZER als [`Self::entry_object_hashes`], wenn ein Eintrag bewusst
    /// ohne Grant abgelegt wurde — siehe
    /// [`live_clock_archive_with_mutated_writer_signature`].
    pub grant_object_hashes: Vec<ObjectHash>,
    /// Der Klartext hinter jedem Ciphertext dieses Bestands.
    pub plaintext: &'static [u8],
}

impl LiveArchive {
    /// Der Trust Anchor dieses Bestands.
    ///
    /// Er kommt als PARAMETER in die Verifikation und nie aus dem Bestand.
    #[must_use]
    pub fn anchor(&self) -> TrustAnchorV1 {
        decode_trust_anchor(&self.anchor_bytes).expect("der Fixture-Anker muss dekodieren")
    }
}

/// Version UND Objekthash eines Registrierungskopfes.
///
/// Beides, weil jedes Manifest und jeder Grant beides traegt und beides
/// gebunden wird. Nachgebaut und nicht importiert: die Fassung in
/// `verify_support` ist privat, und ein `#[path]`-Include macht private Glieder
/// eines Kindmoduls nicht sichtbar.
#[derive(Clone, Copy)]
struct LiveHeadRef {
    version: RegistryVersion,
    hash: Hash32,
}

impl LiveHeadRef {
    fn of(head: &trust_support::BuiltHead) -> Self {
        Self {
            version: head.version,
            hash: Hash32::try_from(head.object_hash.as_bytes().as_slice())
                .expect("ein Objekthash sind 32 Bytes"),
        }
    }
}

/// Die Linie: veralteter Policy-Kopf, dann der Schreiberkopf ab Sequenz null.
struct LiveLine {
    line: trust_support::RegistryLineBuilder,
    head: trust_support::BuiltHead,
    writer_certificate_hash: CertificateHash,
    anchor_bytes: Vec<u8>,
}

impl LiveLine {
    fn anchor(&self) -> TrustAnchorV1 {
        decode_trust_anchor(&self.anchor_bytes).expect("der Fixture-Anker muss dekodieren")
    }

    fn head_ref(&self) -> LiveHeadRef {
        LiveHeadRef::of(&self.head)
    }
}

/// Baut die Linie aus GENAU ZWEI Uebergaengen.
///
/// Mehr geht nicht: ein Registrierungskopf traegt genau EINEN Uebergang, und
/// `verify_registry_candidate` verlangt eine wirksame Policy, bevor irgendein
/// Geraetezertifikat zaehlt. Der erste Kopf muss deshalb der Policy-Kopf sein.
fn live_line() -> LiveLine {
    let mut line = trust_support::RegistryLineBuilder::new();
    line.push(
        trust_support::ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        trust_support::HeadOptions {
            effective_from: Some(0),
            valid_through: Some(0),
            not_after: UnixMillis::new(LIVE_POLICY_NOT_AFTER_V1),
            policy_max_registry_age_ms_override: Some(LIVE_POLICY_MAX_REGISTRY_AGE_MS_V1),
            ..trust_support::HeadOptions::default()
        },
    );
    let head = line.push(
        trust_support::ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x11,
            effective_from: Some(LIVE_WRITER_LEASE_FROM_V1),
        },
        trust_support::HeadOptions {
            effective_from: Some(LIVE_WRITER_LEASE_FROM_V1),
            valid_through: Some(LIVE_WRITER_LEASE_THROUGH_V1),
            not_after: UnixMillis::new(LIVE_WRITER_NOT_AFTER_V1),
            ..trust_support::HeadOptions::default()
        },
    );
    let writer_certificate_hash = CertificateHash::from(
        head.direct_object_hash
            .expect("ein Device-Uebergang traegt ein direktes Ziel"),
    );
    let anchor_bytes = line.exact_anchor_bytes().to_vec();
    LiveLine {
        line,
        head,
        writer_certificate_hash,
        anchor_bytes,
    }
}

/// Der Defekt, den GENAU EIN Objekt eines Live-Bestands traegt.
///
/// EINER JE BESTAND. Die Exitcodeableitung nimmt den KLEINSTEN zutreffenden
/// Code; ein zweiter Befund lenkte den Bestand still auf einen anderen Code um
/// und machte ihn als Beleg wertlos.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiveDefect {
    /// Keiner.
    None,
    /// Die Schreibersignatur des mittleren Eintrags traegt ein verkipptes Byte.
    MutatedWriterSignature,
    /// Der Grant des mittleren Eintrags ist auf einen FREMDEN Schluessel
    /// gekapselt.
    ForeignEncapsulation,
    /// Der mittlere Eintrag fehlt im Bestand.
    MissingMiddleEntry,
}

/// Was ein Bestand an Trust-Objekten mitbringt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiveTrustObjects {
    /// Die vollstaendige Linie.
    Present,
    /// Keines. Gate `trust` traegt dann nicht.
    Absent,
}

/// Der Bauplan eines Live-Bestands.
struct LiveSpec {
    entry_count: u64,
    defect: LiveDefect,
    trust_objects: LiveTrustObjects,
    beiwerk: bool,
}

/// Ein lueckenloser Bestand mit GENAU EINEM Eintrag auf Sequenz null.
///
/// TRAEGT ALS EINZIGER BEIWERK: [`ea_archive::README_FORMAT_FILE_V1`] und eine
/// Datei unter [`ea_archive::FORMAT_SCHEMAS_DIR_V1`]. Ohne sie waere
/// `nonObjectFileCount` in jedem Bestand null, und jede Aussage ueber
/// Nicht-Objekt-Dateien — die Textausgabe der CLI wie die Mengengleichheit des
/// Exports — waere VAKUUM-WAHR. Nur hier und nicht in der ganzen Familie,
/// damit die Zaehler der uebrigen Bestaende unberuehrt bleiben.
#[must_use]
pub fn live_clock_archive() -> LiveArchive {
    build(&LiveSpec {
        entry_count: 1,
        defect: LiveDefect::None,
        trust_objects: LiveTrustObjects::Present,
        beiwerk: true,
    })
}

/// Derselbe Bestand mit ZWEI verketteten Eintraegen und je einem Grant.
#[must_use]
pub fn live_clock_archive_with_two_entries() -> LiveArchive {
    build(&LiveSpec {
        entry_count: 2,
        defect: LiveDefect::None,
        trust_objects: LiveTrustObjects::Present,
        beiwerk: false,
    })
}

/// Derselbe Bestand OHNE ein einziges Trust-Objekt.
///
/// Gate `trust` traegt dann nicht, und der Lauf endet FAIL-CLOSED: ueber kein
/// Objekt wird etwas ausgesagt, und `publicKeyThumbprints` bleibt leer. Der
/// Anker bleibt derselbe — es fehlt die Linie, nicht das Vertrauen an sich.
#[must_use]
pub fn live_clock_archive_without_trust_objects() -> LiveArchive {
    build(&LiveSpec {
        entry_count: 1,
        defect: LiveDefect::None,
        trust_objects: LiveTrustObjects::Absent,
        beiwerk: false,
    })
}

/// Drei Eintraege, von denen der MITTLERE ein verkipptes Byte in seiner
/// Schreibersignatur traegt.
///
/// Der defekte Eintrag bekommt AUSDRUECKLICH KEINEN Grant. Der `entryHash`
/// haengt an der Schreibersignatur; ein mitgelieferter Grant zeigte nach der
/// Mutation ins Leere und stuende als VERWAISTER Grant mit einem ZWEITEN Befund
/// im Bericht. Ihn gegen die manipulierten Bytes neu zu bauen hiesse, eine
/// Fixture zu bauen, in der ein Angreifer mitsigniert. Dieselbe Entscheidung
/// trifft `verify_support::isolation_archive`, und aus demselben Grund.
#[must_use]
pub fn live_clock_archive_with_mutated_writer_signature() -> LiveArchive {
    build(&LiveSpec {
        entry_count: 3,
        defect: LiveDefect::MutatedWriterSignature,
        trust_objects: LiveTrustObjects::Present,
        beiwerk: false,
    })
}

/// Drei Eintraege, von denen der MITTLERE fehlt.
///
/// Die Nachfolgerbindung des dritten Eintrags stammt aus dem gebauten, aber
/// nicht abgelegten zweiten. Das ist der ehrliche Verlustfall: der Bestand
/// wurde lueckenlos geschrieben, und danach ist ein Objekt verloren gegangen.
/// `ea_chain` vergleicht Vorgaengerbindungen nur zwischen unmittelbar
/// benachbarten Sequenzen; es entsteht deshalb eine LUECKE und ausdruecklich
/// kein Bruch.
#[must_use]
pub fn live_clock_archive_with_a_missing_middle_entry() -> LiveArchive {
    build(&LiveSpec {
        entry_count: 3,
        defect: LiveDefect::MissingMiddleEntry,
        trust_objects: LiveTrustObjects::Present,
        beiwerk: false,
    })
}

/// Drei Eintraege, deren MITTLERER Grant auf einen FREMDEN Schluessel gekapselt
/// ist.
///
/// Der Grant nennt weiterhin den EIGENEN Abdruck und dasselbe Zertifikat —
/// beides geht in den Planhash ein, ein anderer Empfaenger faellte schon an
/// Gate `grant-plan`. Der Ciphertext bleibt unangetastet; eine Mutation dort
/// faellt bereits an Gate `manifest-signature`. Gescheitert wird ausschliesslich
/// in der Entkapselung — und die findet nur statt, wenn der Lauf einen
/// Empfaengerschluessel bekommt.
#[must_use]
pub fn live_clock_archive_with_foreign_encapsulation() -> LiveArchive {
    build(&LiveSpec {
        entry_count: 3,
        defect: LiveDefect::ForeignEncapsulation,
        trust_objects: LiveTrustObjects::Present,
        beiwerk: false,
    })
}

/// Baut einen Live-Bestand nach `spec`.
fn build(spec: &LiveSpec) -> LiveArchive {
    let line = live_line();
    let anchor = line.anchor();
    let mut fixture = ArchiveFixture::new();
    if spec.trust_objects == LiveTrustObjects::Present {
        push_trust_objects(&mut fixture, &line.line);
    }

    let plan_hash = live_grant_plan_hash();
    let own_public_key = complete_recipient_private_key().public_key();
    let foreign_public_key = other_recipient_private_key().public_key();

    let mut entry_object_hashes = Vec::new();
    let mut grant_object_hashes = Vec::new();
    let mut previous_entry_hash = None;
    for sequence in LIVE_GENESIS_SEQUENCE_V1..LIVE_GENESIS_SEQUENCE_V1 + spec.entry_count {
        let defective = sequence == LIVE_MISSING_MIDDLE_SEQUENCE_V1;
        let entry = build_live_entry(
            line.head_ref(),
            line.writer_certificate_hash,
            anchor.chain_id(),
            plan_hash,
            sequence,
            previous_entry_hash,
        );
        let mut entry_bytes = encode_entry_package(&entry)
            .expect("das Live-Eintragspaket muss kodieren")
            .into_vec();
        // Die Nachfolgerbindung stammt aus den UNVERSEHRTEN Bytes: der Bestand
        // wurde gueltig geschrieben, und erst danach ist etwas passiert.
        previous_entry_hash = Some(entry.entry_hash());

        if defective && spec.defect == LiveDefect::MissingMiddleEntry {
            continue;
        }

        let mutated = defective && spec.defect == LiveDefect::MutatedWriterSignature;
        if mutated {
            assert!(
                entry_bytes.ends_with(entry.writer_signature()),
                "die Eintragsbytes enden nicht mehr auf der Schreibersignatur"
            );
            let offset = entry_bytes.len() - 64;
            entry_bytes[offset] ^= 0x01;
        }
        entry_object_hashes.push(object_hash(&entry_bytes));

        if !mutated {
            let sealed_to = if defective && spec.defect == LiveDefect::ForeignEncapsulation {
                &foreign_public_key
            } else {
                &own_public_key
            };
            let grant_bytes = live_grant_bytes(
                line.head_ref(),
                line.writer_certificate_hash,
                anchor.chain_id(),
                entry.entry_hash(),
                sequence,
                sealed_to,
            );
            grant_object_hashes.push(object_hash(&grant_bytes));
            fixture.push_exact_bytes(
                &format!("{}{sequence:012}_grant.eag", ea_archive::GRANTS_DIR_V1),
                grant_bytes,
            );
        }

        fixture.push_exact_bytes(
            &format!("{}{sequence:012}_entry.eip", ea_archive::ENTRIES_DIR_V1),
            entry_bytes,
        );
    }

    if spec.beiwerk {
        assert!(
            LIVE_FORMAT_SCHEMA_FILE_V1.starts_with(ea_archive::FORMAT_SCHEMAS_DIR_V1),
            "das Schemabeiwerk muss unter FORMAT_SCHEMAS_DIR_V1 liegen, sonst uebt \
             dieser Bestand den geschachtelten Pfad nicht mehr"
        );
        fixture.push_non_object(ea_archive::README_FORMAT_FILE_V1, LIVE_README_BYTES_V1);
        fixture.push_non_object(LIVE_FORMAT_SCHEMA_FILE_V1, LIVE_SCHEMA_BYTES_V1);
    }

    LiveArchive {
        fixture,
        anchor_bytes: line.anchor_bytes,
        entry_object_hashes,
        grant_object_hashes,
        plaintext: LIVE_PLAINTEXT_V1,
    }
}

/// Legt jedes Trust-Objekt der Linie im Bestand ab.
///
/// Der Pfadhinweis ist ein HINWEIS: klassifiziert wird am 9-Byte-Praefix.
fn push_trust_objects(fixture: &mut ArchiveFixture, line: &trust_support::RegistryLineBuilder) {
    let source = line.source();
    let mut hashes = Vec::new();
    source
        .visit_trust_object_hashes(&mut |hash| {
            hashes.push(hash);
            Ok(())
        })
        .expect("die Live-Linie muss aufzaehlen");
    for hash in hashes {
        let bytes = source
            .read_exact_trust_object(hash)
            .expect("die Live-Linie muss lesen")
            .expect("ein aufgezaehltes Trust-Objekt muss lesbar sein");
        fixture.push_exact_bytes(
            &format!(
                "{}{}.etb",
                ea_archive::REGISTRY_EVENTS_DIR_V1,
                hex::encode(hash.as_bytes())
            ),
            bytes.to_vec(),
        );
    }
}

/// Der Planhash: GENAU EIN Recovery-Grant an den eigenen Empfaenger.
fn live_grant_plan_hash() -> Hash32 {
    GrantPlanV1::new(vec![GrantPlanItemV1::new(
        complete_recipient_key_thumbprint(),
        complete_recipient_certificate_hash(),
        GrantPurposeV1::Recovery,
    )])
    .expect("ein Plan mit genau einem Recovery-Grant muss entstehen")
    .hash()
}

/// Baut einen Eintrag mit ECHTEM Ciphertext.
///
/// ZWEI DURCHGAENGE, und das ist kein Umweg: `manifestCore` traegt die LAENGE
/// des Ciphertexts, nicht dessen Bytes. Der erste Durchgang baut den Kern ueber
/// einen Platzhalter GLEICHER Laenge und liefert damit exakt die AAD-Bytes; der
/// zweite baut denselben Kern ueber den echten Ciphertext. Die Zusicherung
/// unten MISST, dass beide Kerne byteidentisch sind, statt es zu glauben.
///
/// Die Reihenfolge ist zwingend und nicht zirkulaer: Planhash aus den
/// Empfaengern, Manifest ueber den Planhash, `entryHash` aus dem signierten
/// Manifest — und erst der Grant ueber den `entryHash`.
fn build_live_entry(
    head: LiveHeadRef,
    writer_certificate_hash: CertificateHash,
    chain_id: ChainId,
    plan_hash: Hash32,
    chain_sequence: u64,
    previous_entry_hash: Option<EntryHash>,
) -> EntryPackageV1 {
    let fields = || ManifestCoreFieldsV1 {
        organization_id: trust_support::organization(),
        chain_id,
        chain_sequence: ChainSequence::new(chain_sequence),
        previous_entry_hash,
        writer_certificate_hash,
        writer_transition_event_hash: None,
        registry_version: head.version,
        registry_head_hash: *head.hash.as_bytes(),
        initial_grant_plan_hash: *plan_hash.as_bytes(),
        nonce: live_nonce(chain_sequence),
    };
    let placeholder = vec![0x00; LIVE_PLAINTEXT_V1.len() + ea_crypto::AEAD_OVERHEAD];
    let draft =
        ManifestCoreV1::new(fields(), &placeholder).expect("das Live-Manifest muss kodieren");
    let aad = ea_crypto::payload_aad(draft.exact_bytes());
    let ciphertext = ea_crypto::aead_seal(
        &SecretBytes::new(live_cek(chain_sequence)),
        &SecretBytes::new(live_nonce(chain_sequence)),
        ea_crypto::SecretVec::new(LIVE_PLAINTEXT_V1.to_vec()),
        &aad,
    )
    .expect("der Live-Klartext muss sich verschluesseln lassen");
    let manifest =
        ManifestCoreV1::new(fields(), &ciphertext).expect("das Live-Manifest muss kodieren");
    assert!(
        manifest.exact_bytes() == draft.exact_bytes(),
        "der Manifestkern haengt an der LAENGE des Ciphertexts, nicht an seinen Bytes"
    );
    let signed = SignedManifestV1::new(manifest, &ciphertext).expect("das Manifest muss binden");
    let signature = writer_device_signer()
        .sign_record(signed.exact_bytes())
        .expect("der Live-Signierer muss signieren");
    EntryPackageV1::new(signed, ciphertext, signature)
        .expect("das Live-Eintragspaket muss sich zusammensetzen")
}

/// Baut den initialen Recovery-Grant mit ECHTER Kapselung.
///
/// Auch hier zwei Durchgaenge und auch hier ohne Zirkel: `grant-context-v1`
/// traegt WEDER den Kapselungswert NOCH den umschlossenen CEK. Der erste
/// Durchgang liefert bereits die endgueltigen Kontextbytes, aus denen
/// `hpkeInfo` und `hpkeAad` entstehen; der zweite setzt die Kapselung ein.
fn live_grant_bytes(
    head: LiveHeadRef,
    writer_certificate_hash: CertificateHash,
    chain_id: ChainId,
    entry_hash: EntryHash,
    chain_sequence: u64,
    recipient_public_key: &HpkeRecipientPublicKey,
) -> Vec<u8> {
    let fields = |encapsulated_key, wrapped_cek| GrantBodyFieldsV1 {
        organization_id: trust_support::organization(),
        chain_id,
        entry_hash,
        kind: GrantKindV1::Initial,
        purpose: GrantPurposeV1::Recovery,
        recipient_key_thumbprint: complete_recipient_key_thumbprint(),
        recipient_certificate_hash: complete_recipient_certificate_hash(),
        issuer_key_thumbprint: writer_device_key_thumbprint(),
        issuer_certificate_hash: writer_certificate_hash,
        registry_version: head.version,
        registry_head_hash: head.hash,
        created_at_device: UnixMillis::new(LIVE_CREATED_AT_DEVICE_V1),
        original_recovery_grant_object_hash: None,
        grant_authorization_object_hash: None,
        encapsulated_key,
        wrapped_cek,
    };
    let draft = GrantBodyV1::new(fields(
        [0x00; HPKE_ENCAPSULATED_KEY_SIZE],
        [0x00; HPKE_WRAPPED_CEK_SIZE],
    ))
    .expect("der Live-Grantrumpf muss kodieren");
    let context = exact_grant_context(draft.exact_bytes());
    let sealed = ea_crypto::hpke_seal(
        recipient_public_key,
        &SecretBytes::new(live_cek(chain_sequence)),
        &ea_crypto::hpke_info(&context),
        &ea_crypto::hpke_aad(&context),
    )
    .expect("der Live-CEK muss sich kapseln lassen");
    let body = GrantBodyV1::new(fields(*sealed.encapsulated_key(), *sealed.wrapped_cek()))
        .expect("der Live-Grantrumpf muss kodieren");
    assert!(
        exact_grant_context(body.exact_bytes()) == context,
        "der Grantkontext haengt nicht an der Kapselung"
    );
    let signature = writer_device_signer()
        .sign_initial_grant(body.exact_bytes())
        .expect("der Live-Aussteller muss signieren");
    let grant = GrantV1::new(body, signature).expect("der Live-Grant muss binden");
    encode_grant(&grant)
        .expect("der Live-Grant muss kodieren")
        .into_vec()
}

/// Die exakten Bytes des `grant-context-v1` aus einem `grant-body-v1`.
///
/// Ueber den CBOR-Dekoder und nicht ueber bekannte Laengen — ein zweiter Weg
/// auf dieselben Bytes. Stimmten sie nicht ueberein, waeren `hpkeInfo` und
/// `hpkeAad` falsch gebildet und die Entkapselung schluege fehl, ohne dass ein
/// Test sagte warum.
fn exact_grant_context(exact_grant_body: &[u8]) -> Vec<u8> {
    let mut decoder = minicbor::Decoder::new(exact_grant_body);
    assert!(
        decoder.array().expect("der Grantrumpf ist ein CBOR-Array") == Some(3),
        "grant-body-v1 hat genau drei Glieder"
    );
    let start = decoder.position();
    decoder
        .skip()
        .expect("der Kontext muss ueberspringbar sein");
    exact_grant_body[start..decoder.position()].to_vec()
}
