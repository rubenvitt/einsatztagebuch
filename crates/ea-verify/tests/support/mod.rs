//! Archivfixtures mit einer ECHTEN Registrierungslinie, fuer die Gates
//! `trust` und `registry`.
//!
//! Wird per `#[path]` in Testtargets eingebunden, nie in das Lib-Target —
//! genau wie das Archiv- und das Trust-Support-Modul, auf denen es aufsetzt.
//! Damit bleibt `ed25519-dalek` aus dem Lib-Graphen und `clippy
//! --all-features` sieht keinen Fixture-Code im Lib-Target.
//!
//! `#[path]`-Includes werden je Testtarget uebersetzt; ein Target, das nur
//! einen Teil der Helfer nutzt, erzeugt sonst `dead_code`-Warnungen, die unter
//! `-D warnings` brechen. Daher `allow(dead_code)` auf Modulebene.
#![allow(dead_code)]

/// Das Archiv-Support-Modul aus `ea-archive`, unveraendert weiterverwendet.
///
/// Bindet seinerseits das Trust- und das Formatfixture ein und liefert
/// [`archive_support::ArchiveFixture`]. Hier wird nichts davon nachgebaut.
#[path = "../../../ea-archive/tests/support/mod.rs"]
pub mod archive_support;

use ea_crypto::object_hash;
use ea_format::{
    CertificateKindV1, EntryPackageV1, ManifestCoreFieldsV1, ManifestCoreV1, SignedManifestV1,
    encode_entry_package,
};
use ea_trust::{TrustAnchorV1, TrustObjectSource, decode_trust_anchor};
use ea_types::{CertificateHash, ChainId, ChainSequence, EntryHash, Hash32, ObjectHash};

use archive_support::{ArchiveFixture, format_support, trust_support};

/// Die Betriebssystemuhr der Fixtures.
///
/// Muss im Zeitfenster von [`trust_support::HeadOptions::default`] liegen
/// (`not_before` 90, `not_after` 10_000), sonst waehlt `select_registry_head`
/// den Kopf nur als `Advanced` aus und traegt keine Operationsautoritaet.
/// Derselbe Wert, den `tests/ea-system-tests/tests/task8_trust_time.rs` fuer
/// seine stabilen Auswahlen benutzt.
pub const FIXTURE_OS_WALL_CLOCK_V1: i64 = 800;

/// Die Lease des ersten Kopfes: das Genesisfach, das kein `.eip` traegt.
///
/// Ein Registrierungskopf traegt genau EINEN Uebergang. Die Linie braucht
/// deshalb zwei Koepfe: einen, der die Policy setzt (ohne die liefert
/// `verify_registry_candidate` `EA-TRUST-ACTION-MISMATCH`), und einen, der das
/// Schreiberzertifikat aktiviert. Der erste bekommt das Genesisfach, damit die
/// Lease des zweiten bei Sequenz eins beginnt und die Eintragskette luecken-
/// und platzhalterfrei bleibt.
pub const POLICY_LEASE_FROM_V1: u64 = 0;
/// Letzte Sequenz der Lease des Policy-Kopfes.
pub const POLICY_LEASE_THROUGH_V1: u64 = 0;

/// Erste Sequenz der Lease des Kopfes, der das Schreiberzertifikat aktiviert.
pub const WRITER_LEASE_FROM_V1: u64 = 1;
/// Letzte Sequenz der Lease dieses Kopfes.
pub const WRITER_LEASE_THROUGH_V1: u64 = 100;

/// Die Sequenz des Eintrags mit AUFLOESBAREM Schreiberzertifikat.
pub const KNOWN_WRITER_SEQUENCE_V1: u64 = 1;

/// Die Sequenz des Eintrags mit UNBEKANNTEM Schreiberzertifikat.
///
/// Bewusst die HOECHSTE Sequenz des Bestands: laege der unbekannte Schreiber
/// in der Mitte, waere der Befund nicht von einer Kettenluecke zu
/// unterscheiden. So ist er es.
pub const UNKNOWN_WRITER_SEQUENCE_V1: u64 = 2;

/// Ein Zertifikatshash, den keine Registrierungslinie je vergibt.
///
/// Ein Objekthash entsteht aus SHA-256 ueber Objektbytes; eine konstante
/// Bytefolge ist deshalb mit an Sicherheit grenzender Wahrscheinlichkeit
/// keiner.
#[must_use]
pub fn unknown_writer_certificate_hash() -> CertificateHash {
    CertificateHash::try_from(&[0x99_u8; 32][..]).expect("32 Bytes sind ein Zertifikatshash")
}

/// Ein Bestand mit zwei Registrierungskoepfen und zwei Eintragspaketen.
///
/// Der Trust Anchor liegt BEWUSST neben dem Bestand und nicht darin: er ist
/// nach `design.md` §11.4 nie Teil der Inventarklassifikation.
pub struct WriterArchive {
    pub fixture: ArchiveFixture,
    pub anchor_bytes: Vec<u8>,
    /// Die Registrierungsversion des Kopfes, der die Eintragssequenzen deckt.
    pub registry_version: ea_types::RegistryVersion,
    /// Das Schreiberzertifikat, das die Linie tatsaechlich aktiviert.
    pub writer_certificate_hash: CertificateHash,
    /// Objekthash des `.eip`, dessen Schreiber sich aufloesen laesst.
    pub known_writer_object_hash: ObjectHash,
    /// Objekthash des `.eip`, dessen Schreiber sich NICHT aufloesen laesst.
    pub unknown_writer_object_hash: ObjectHash,
    pub trust_object_count: usize,
}

impl WriterArchive {
    #[must_use]
    pub fn anchor(&self) -> TrustAnchorV1 {
        decode_trust_anchor(&self.anchor_bytes).expect("der Fixture-Anker muss dekodieren")
    }
}

/// Baut einen Bestand aus einer Registrierungslinie und zwei `.eip`.
///
/// Bewusst OHNE `.eds`, `.eag`, `.esr` und `.ecp`: jede weitere Objektfamilie
/// gibt dem Inventar eine weitere Gelegenheit zu isolieren, und der Befund
/// dieses Fixtures ist genau EIN Quarantaeneeintrag.
#[must_use]
pub fn archive_with_one_unknown_writer() -> WriterArchive {
    let mut line = trust_support::RegistryLineBuilder::new();
    line.push(
        policy_action(),
        trust_support::HeadOptions {
            effective_from: Some(POLICY_LEASE_FROM_V1),
            valid_through: Some(POLICY_LEASE_THROUGH_V1),
            ..trust_support::HeadOptions::default()
        },
    );
    let head = line.push(
        trust_support::ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x11,
            effective_from: None,
        },
        trust_support::HeadOptions {
            effective_from: Some(WRITER_LEASE_FROM_V1),
            valid_through: Some(WRITER_LEASE_THROUGH_V1),
            ..trust_support::HeadOptions::default()
        },
    );
    let writer_certificate_hash = CertificateHash::from(
        head.direct_object_hash
            .expect("ein Device-Uebergang traegt ein direktes Ziel"),
    );
    let anchor_bytes = line.exact_anchor_bytes().to_vec();
    let anchor = decode_trust_anchor(&anchor_bytes).expect("der Fixture-Anker muss dekodieren");
    let registry_head_hash = Hash32::try_from(head.object_hash.as_bytes().as_slice())
        .expect("ein Objekthash sind 32 Bytes");

    let mut fixture = ArchiveFixture::new();
    let trust_object_count = push_trust_objects(&mut fixture, &line);

    // Sequenz 1 folgt auf den Genesis-Eintrag des Ankers: ein Manifest mit
    // Sequenz > 0 MUSS einen Vorgaenger benennen (`ea-format` prueft das schon
    // beim Kodieren). Gate `chain-position` prueft die Kette selbst erst
    // spaeter; hier zaehlt nur, dass die Bytes wohlgeformt sind.
    let (known_entry, known_bytes) = entry_package(
        anchor.chain_id(),
        KNOWN_WRITER_SEQUENCE_V1,
        Some(anchor.genesis_entry_hash()),
        writer_certificate_hash,
        head.version,
        registry_head_hash,
    );
    let (_, unknown_bytes) = entry_package(
        anchor.chain_id(),
        UNKNOWN_WRITER_SEQUENCE_V1,
        Some(known_entry.entry_hash()),
        unknown_writer_certificate_hash(),
        head.version,
        registry_head_hash,
    );
    let known_writer_object_hash = object_hash(&known_bytes);
    let unknown_writer_object_hash = object_hash(&unknown_bytes);
    assert!(
        known_writer_object_hash != unknown_writer_object_hash,
        "die beiden Eintraege muessen verschiedene Objekte sein"
    );

    fixture.push_exact_bytes(
        &format!(
            "{}{KNOWN_WRITER_SEQUENCE_V1:012}_entry.eip",
            ea_archive::ENTRIES_DIR_V1
        ),
        known_bytes,
    );
    fixture.push_exact_bytes(
        &format!(
            "{}{UNKNOWN_WRITER_SEQUENCE_V1:012}_entry.eip",
            ea_archive::ENTRIES_DIR_V1
        ),
        unknown_bytes,
    );

    WriterArchive {
        fixture,
        anchor_bytes,
        registry_version: head.version,
        writer_certificate_hash,
        known_writer_object_hash,
        unknown_writer_object_hash,
        trust_object_count,
    }
}

/// Die Lease des dritten Kopfes in [`archive_with_a_second_lease`].
pub const SECOND_LEASE_FROM_V1: u64 = 2;
/// Letzte Sequenz dieser Lease.
pub const SECOND_LEASE_THROUGH_V1: u64 = 100;

/// Das Fuellbyte, das die Inventarreihenfolge gegen die Sequenzreihenfolge
/// stellt.
///
/// Das Inventar ordnet nach Objekthash. Damit ein Test ueberhaupt merken kann,
/// ob die Pipeline nach Sequenz behandelt, muss der Eintrag mit der HOEHEREN
/// Sequenz den KLEINEREN Objekthash tragen. Dieses Byte ist der dafuer
/// gesuchte Wert; [`archive_with_a_second_lease`] behauptet die Eigenschaft
/// nicht, sondern prueft sie und bricht laut, falls eine Layoutaenderung in
/// `ea-format` sie kippt. Bewusst ein fester Wert statt einer Suche zur
/// Laufzeit: eine Suche faende immer irgendeinen Wert und machte den Test
/// stillschweigend wieder aussagelos.
pub const DESCENDING_HASH_MARKER_V1: u8 = 0x01;

/// Ein Bestand, dessen zwei Eintraege unter VERSCHIEDENEN Registrierungskoepfen
/// liegen und dessen Inventarreihenfolge der Sequenzreihenfolge widerspricht.
///
/// Drei Koepfe: Policy auf dem Genesisfach, dann der Kopf mit dem
/// Schreiberzertifikat fuer genau Sequenz eins, dann ein Policy-Kopf fuer den
/// Rest. Beide Eintraege benennen dasselbe, aufloesbare Schreiberzertifikat.
///
/// Damit ist pruefbar, was sonst nur ein Kommentar waere: eine
/// Registrierungslinie laesst sich nur VORWAERTS nachziehen. Wer den Eintrag
/// mit der hoeheren Sequenz zuerst behandelt, pinnt den dritten Kopf — und der
/// Eintrag mit der niedrigeren Sequenz faellt danach aus dessen Lease.
pub struct LeasedArchive {
    pub fixture: ArchiveFixture,
    pub anchor_bytes: Vec<u8>,
    /// Registrierungsversion des Kopfes ueber Sequenz eins.
    pub early_registry_version: ea_types::RegistryVersion,
    /// Registrierungsversion des Kopfes ueber Sequenz zwei.
    pub late_registry_version: ea_types::RegistryVersion,
    /// Objekthash des Eintrags auf der NIEDRIGEREN Sequenz.
    pub early_object_hash: ObjectHash,
    /// Objekthash des Eintrags auf der HOEHEREN Sequenz.
    pub late_object_hash: ObjectHash,
}

impl LeasedArchive {
    #[must_use]
    pub fn anchor(&self) -> TrustAnchorV1 {
        decode_trust_anchor(&self.anchor_bytes).expect("der Fixture-Anker muss dekodieren")
    }
}

/// Baut den Bestand aus [`LeasedArchive`].
///
/// # Panics
///
/// Wenn [`DESCENDING_HASH_MARKER_V1`] die gesuchte Hashordnung nicht mehr
/// herstellt. Dann ist der Test aussagelos geworden und muss es laut sagen.
#[must_use]
pub fn archive_with_a_second_lease() -> LeasedArchive {
    let mut line = trust_support::RegistryLineBuilder::new();
    line.push(
        policy_action(),
        trust_support::HeadOptions {
            effective_from: Some(POLICY_LEASE_FROM_V1),
            valid_through: Some(POLICY_LEASE_THROUGH_V1),
            ..trust_support::HeadOptions::default()
        },
    );
    let writer_head = line.push(
        trust_support::ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x11,
            effective_from: None,
        },
        trust_support::HeadOptions {
            effective_from: Some(WRITER_LEASE_FROM_V1),
            valid_through: Some(WRITER_LEASE_FROM_V1),
            ..trust_support::HeadOptions::default()
        },
    );
    let late_head = line.push(
        policy_action(),
        trust_support::HeadOptions {
            effective_from: Some(SECOND_LEASE_FROM_V1),
            valid_through: Some(SECOND_LEASE_THROUGH_V1),
            ..trust_support::HeadOptions::default()
        },
    );
    let writer_certificate_hash = CertificateHash::from(
        writer_head
            .direct_object_hash
            .expect("ein Device-Uebergang traegt ein direktes Ziel"),
    );
    let anchor_bytes = line.exact_anchor_bytes().to_vec();
    let anchor = decode_trust_anchor(&anchor_bytes).expect("der Fixture-Anker muss dekodieren");
    let mut fixture = ArchiveFixture::new();
    push_trust_objects(&mut fixture, &line);

    let early_head_hash = Hash32::try_from(writer_head.object_hash.as_bytes().as_slice())
        .expect("ein Objekthash sind 32 Bytes");
    let late_head_hash = Hash32::try_from(late_head.object_hash.as_bytes().as_slice())
        .expect("ein Objekthash sind 32 Bytes");
    let (early_entry, early_bytes) = entry_package(
        anchor.chain_id(),
        KNOWN_WRITER_SEQUENCE_V1,
        Some(anchor.genesis_entry_hash()),
        writer_certificate_hash,
        writer_head.version,
        early_head_hash,
    );
    let (_, late_bytes) = entry_package_marked(
        anchor.chain_id(),
        UNKNOWN_WRITER_SEQUENCE_V1,
        Some(early_entry.entry_hash()),
        writer_certificate_hash,
        late_head.version,
        late_head_hash,
        DESCENDING_HASH_MARKER_V1,
    );
    let early_object_hash = object_hash(&early_bytes);
    let late_object_hash = object_hash(&late_bytes);
    assert!(
        late_object_hash < early_object_hash,
        "DESCENDING_HASH_MARKER_V1 stellt die Inventarreihenfolge nicht mehr \
         gegen die Sequenzreihenfolge; der Test waere sonst aussagelos"
    );

    fixture.push_exact_bytes(
        &format!(
            "{}{KNOWN_WRITER_SEQUENCE_V1:012}_entry.eip",
            ea_archive::ENTRIES_DIR_V1
        ),
        early_bytes,
    );
    fixture.push_exact_bytes(
        &format!(
            "{}{UNKNOWN_WRITER_SEQUENCE_V1:012}_entry.eip",
            ea_archive::ENTRIES_DIR_V1
        ),
        late_bytes,
    );

    LeasedArchive {
        fixture,
        anchor_bytes,
        early_registry_version: writer_head.version,
        late_registry_version: late_head.version,
        early_object_hash,
        late_object_hash,
    }
}

/// Der Policy-Uebergang der Fixtures, ohne Besonderheiten.
fn policy_action() -> trust_support::ActionSpec {
    trust_support::ActionSpec::Policy {
        policy_version: None,
        previous_policy_hash: None,
        effective_from: None,
    }
}

/// Legt jedes Trust-Objekt der Linie im Bestand ab und zaehlt sie.
///
/// Der Pfadhinweis ist ein Hinweis: klassifiziert wird am Praefix.
fn push_trust_objects(
    fixture: &mut ArchiveFixture,
    line: &trust_support::RegistryLineBuilder,
) -> usize {
    let source = line.source();
    let mut hashes = Vec::new();
    source
        .visit_trust_object_hashes(&mut |hash| {
            hashes.push(hash);
            Ok(())
        })
        .expect("die Fixture-Linie muss aufzaehlen");
    let mut count = 0;
    for hash in hashes {
        let bytes = source
            .read_exact_trust_object(hash)
            .expect("die Fixture-Linie muss lesen")
            .expect("ein aufgezaehltes Trust-Objekt muss lesbar sein");
        fixture.push_exact_bytes(
            &format!(
                "{}{}.etb",
                ea_archive::REGISTRY_EVENTS_DIR_V1,
                hex::encode(hash.as_bytes())
            ),
            bytes.to_vec(),
        );
        count += 1;
    }
    count
}

/// Ein signiertes `.eip` mit frei gewaehltem Schreiberzertifikat.
///
/// Die COSE-Bindung des Schreibers folgt dem Manifest: `sign_record` liest den
/// Zertifikatshash aus den signierten Manifestbytes. Die Bytes sind damit
/// parsbar, und ob das Zertifikat existiert, entscheidet erst Gate `registry`.
fn entry_package(
    chain_id: ChainId,
    chain_sequence: u64,
    previous_entry_hash: Option<EntryHash>,
    writer_certificate_hash: CertificateHash,
    registry_version: ea_types::RegistryVersion,
    registry_head_hash: Hash32,
) -> (EntryPackageV1, Vec<u8>) {
    entry_package_marked(
        chain_id,
        chain_sequence,
        previous_entry_hash,
        writer_certificate_hash,
        registry_version,
        registry_head_hash,
        0x6b,
    )
}

/// Wie [`entry_package`], aber mit waehlbarem Fuellbyte im Grant-Plan-Hash.
///
/// Das Byte veraendert nichts Fachliches — kein Gate dieses Tasks liest den
/// Grant-Plan-Hash —, wohl aber den Objekthash des Eintrags. Genau das braucht
/// [`archive_with_a_second_lease`], um die Inventarreihenfolge gezielt gegen
/// die Sequenzreihenfolge zu stellen.
fn entry_package_marked(
    chain_id: ChainId,
    chain_sequence: u64,
    previous_entry_hash: Option<EntryHash>,
    writer_certificate_hash: CertificateHash,
    registry_version: ea_types::RegistryVersion,
    registry_head_hash: Hash32,
    grant_plan_marker: u8,
) -> (EntryPackageV1, Vec<u8>) {
    let ciphertext = vec![0x5a; 16];
    let manifest = ManifestCoreV1::new(
        ManifestCoreFieldsV1 {
            organization_id: trust_support::organization(),
            chain_id,
            chain_sequence: ChainSequence::new(chain_sequence),
            previous_entry_hash,
            writer_certificate_hash,
            writer_transition_event_hash: None,
            registry_version,
            registry_head_hash: *registry_head_hash.as_bytes(),
            initial_grant_plan_hash: [grant_plan_marker; 32],
            nonce: [0x07; 12],
        },
        &ciphertext,
    )
    .expect("das Fixture-Manifest muss kodieren");
    let signed = SignedManifestV1::new(manifest, &ciphertext).expect("das Manifest muss binden");
    let signature = format_support::signer()
        .sign_record(signed.exact_bytes())
        .expect("der Fixture-Signierer muss signieren");
    let entry = EntryPackageV1::new(signed, ciphertext, signature)
        .expect("das Fixture-Eintragspaket muss sich zusammensetzen");
    let bytes = encode_entry_package(&entry)
        .expect("das Fixture-Eintragspaket muss kodieren")
        .into_vec();
    (entry, bytes)
}
