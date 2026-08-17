//! Archivfixtures mit einer ECHTEN Registrierungslinie, fuer die Gates
//! `trust`, `registry`, `manifest-signature`, `chain-position` und
//! `grant-plan`.
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

use ea_crypto::{
    CanonicalPublicCoseKey, CoseSigner, HPKE_ENCAPSULATED_KEY_SIZE, HPKE_WRAPPED_CEK_SIZE,
    SecretBytes, object_hash,
};
use ea_format::{
    CertificateKindV1, CheckpointCoreFieldsV1, CheckpointCoreV1, DestroyedEntryStubV1,
    EIP_PREFIX_V1, EntryPackageV1, EvidenceObjectV1, GrantBodyFieldsV1, GrantBodyV1, GrantKindV1,
    GrantPlanItemV1, GrantPlanV1, GrantPurposeV1, GrantV1, ManifestCoreFieldsV1, ManifestCoreV1,
    ReceiptCoreFieldsV1, ReceiptCoreV1, ReceiptV1, SignedManifestV1, encode_destroyed_entry_stub,
    encode_entry_package, encode_evidence, encode_grant, encode_receipt,
};
use ea_trust::{TrustAnchorV1, TrustObjectSource, decode_trust_anchor};
use ea_types::{
    CertificateHash, ChainId, ChainSequence, DestructionId, EntryHash, Hash32, KeyThumbprint,
    ObjectHash, RegistryVersion, UnixMillis,
};
use ed25519_dalek::SigningKey;

use archive_support::{ArchiveFixture, trust_support};

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
/// Lease des zweiten bei Sequenz eins beginnt.
///
/// Die Kehrseite ist [`GENESIS_GAP_SEQUENCE_V1`]: das Genesisfach bleibt damit
/// unbesetzt, und Gate `chain-position` meldet es — zu Recht — als Luecke.
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

/// Der geheime Schluessel, den die Registrierungslinie in JEDES
/// Geraetezertifikat schreibt.
///
/// GESPIEGELT, nicht importiert: `trust_support` haelt denselben Wert als
/// privaten `NEW_ADMIN_SECRET` (`crates/ea-trust/tests/support/mod.rs:46`), und
/// `ea-trust` ist geschlossen. Die Spiegelung ist ungefaehrlich, weil
/// [`writer_device_signer`] sie nicht behauptet, sondern gegen den
/// oeffentlichen Abdruck `trust_support::authorized_device_signing_key_thumbprint()`
/// prueft und laut bricht, sobald die Linie einen anderen Schluessel benutzt.
///
/// Ohne diesen Schluessel ist Gate `manifest-signature` gar nicht erreichbar:
/// `verify_cose_sign1` verwirft jede Signatur, deren Abdruck im geschuetzten
/// Header nicht der oeffentliche Schluessel des aufgeloesten Zertifikats ist
/// (`crates/ea-crypto/src/cose.rs:1435-1437`) — noch bevor die Signatur selbst
/// geprueft wird.
const WRITER_DEVICE_SECRET_V1: [u8; 32] = [
    0x83, 0x3f, 0xe6, 0x24, 0x09, 0x23, 0x7b, 0x9d, 0x62, 0xec, 0x77, 0x58, 0x75, 0x20, 0x91, 0x1e,
    0x9a, 0x75, 0x9c, 0xec, 0x1d, 0x19, 0x75, 0x5b, 0x7d, 0xa9, 0x01, 0xb9, 0x6d, 0xca, 0x3d, 0x42,
];

/// Der Abdruck des Schluessels aus [`WRITER_DEVICE_SECRET_V1`].
///
/// # Panics
///
/// Wenn die Registrierungslinie ihre Geraetezertifikate auf einen anderen
/// Schluessel ausstellt. Dann waere jede Signatur dieses Moduls unpruefbar, und
/// die Fixture muss das laut sagen statt still ein rotes Gate zu erzeugen.
#[must_use]
pub fn writer_device_key_thumbprint() -> KeyThumbprint {
    let thumbprint = CanonicalPublicCoseKey::ed25519(
        *SigningKey::from_bytes(&WRITER_DEVICE_SECRET_V1)
            .verifying_key()
            .as_bytes(),
    )
    .expect("der Fixture-Schluessel muss ein Ed25519-COSE-Schluessel sein")
    .thumbprint();
    assert!(
        thumbprint == trust_support::authorized_device_signing_key_thumbprint(),
        "WRITER_DEVICE_SECRET_V1 ist nicht mehr der Schluessel der \
         Geraetezertifikate der Registrierungslinie"
    );
    thumbprint
}

/// Der Signierer, dessen oeffentlicher Schluessel im Schreiberzertifikat steht.
#[must_use]
pub fn writer_device_signer() -> CoseSigner {
    let _ = writer_device_key_thumbprint();
    CoseSigner::from_secret(SecretBytes::new(WRITER_DEVICE_SECRET_V1))
}

/// Die Luecke, die JEDES Fixture dieses Moduls traegt: der Genesis-Eintrag.
///
/// GEMESSEN, nicht behauptet. `ea_chain::build_chain` zaehlt Sequenzen ab null;
/// ein Bestand, dessen niedrigster Knoten auf Sequenz eins liegt, traegt
/// deshalb die Luecke `0..=0` (`crates/ea-chain/src/chain.rs:769-792`, dort
/// ausdruecklich gepinnt: „das Fehlen des Genesis-Knotens ist ein BEFUND").
///
/// Ein Eintrag auf Sequenz NULL ist mit `trust_support::RegistryLineBuilder`
/// nicht herstellbar. Vier Linienformen wurden dafuer gemessen, jede mit einem
/// `.eip` auf Sequenz null:
///
/// | Linie                                        | Ergebnis                    |
/// |----------------------------------------------|-----------------------------|
/// | nur `Device(Writer)`, Lease `0..=100`        | Gate `registry` faellt ganz |
/// | `Device` `0..=0`, dann `Policy` `1..=100`    | Gate `registry` faellt ganz |
/// | `Policy` `0..=0`, dann `Device` `1..=100`    | `unattributable`            |
/// | `Policy` `0..=100`, dann `Device` `0..=100`  | `unattributable`            |
///
/// Der Grund ist strukturell: `verify_registry_candidate` verlangt eine
/// wirksame Policy, ein Registrierungskopf traegt genau EINEN Uebergang, und
/// die Leases muessen aufsteigen. Der erste Kopf muss deshalb der Policy-Kopf
/// sein, und dessen Kandidatenstand kennt das Schreiberzertifikat des zweiten
/// Kopfes noch nicht — auch dann nicht, wenn das Zertifikat selbst ab Sequenz
/// null wirksam ist. Die Luecke ist damit die WAHRE Aussage ueber diese
/// Bestaende: sie tragen keinen verifizierten Genesis-Eintrag. Genau deshalb
/// setzt der Bericht dort auch nie `anchor.genesis_entry_hash()` ein
/// (`crates/ea-verify/src/report.rs:159-170`).
///
/// Wer diese Luecke „wegrepariert", macht die Fixtures unwahr. Tests dieses
/// Moduls rechnen sie deshalb ausdruecklich mit, statt sie zu verstecken.
pub const GENESIS_GAP_SEQUENCE_V1: u64 = 0;

/// Der Empfaenger des Recovery-Grants jedes Fixture-Eintrags.
///
/// Feste Bytes und kein echtes Schluesselmaterial: Gate `grant-plan` prueft den
/// PLAN, nicht die Entkapselung. Wer den Empfaenger tatsaechlich benutzt, ist
/// Sache von Gate `recipient-grant` und der Entkapselung dahinter.
#[must_use]
pub fn recovery_recipient_key_thumbprint() -> KeyThumbprint {
    KeyThumbprint::try_from(&[0x21_u8; 32][..]).expect("32 Bytes sind ein Schluesselabdruck")
}

/// Das Zertifikat des Recovery-Empfaengers.
#[must_use]
pub fn recovery_recipient_certificate_hash() -> CertificateHash {
    CertificateHash::try_from(&[0x22_u8; 32][..]).expect("32 Bytes sind ein Zertifikatshash")
}

/// Der Empfaenger des Reader-Grants.
#[must_use]
pub fn reader_recipient_key_thumbprint() -> KeyThumbprint {
    KeyThumbprint::try_from(&[0x23_u8; 32][..]).expect("32 Bytes sind ein Schluesselabdruck")
}

/// Das Zertifikat des Reader-Empfaengers.
#[must_use]
pub fn reader_recipient_certificate_hash() -> CertificateHash {
    CertificateHash::try_from(&[0x24_u8; 32][..]).expect("32 Bytes sind ein Zertifikatshash")
}

/// Der Planhash eines Eintrags mit GENAU EINEM Recovery-Grant.
///
/// Wird ueber `ea_format::GrantPlanV1` gebildet und nicht nachgebaut: die
/// Sortierung und die Kodierung des Plans sind dort bereits total definiert,
/// und Gate `grant-plan` rechnet gegen genau diese Bytes.
#[must_use]
pub fn recovery_grant_plan_hash() -> Hash32 {
    GrantPlanV1::new(vec![GrantPlanItemV1::new(
        recovery_recipient_key_thumbprint(),
        recovery_recipient_certificate_hash(),
        GrantPurposeV1::Recovery,
    )])
    .expect("ein Plan mit genau einem Recovery-Grant muss entstehen")
    .hash()
}

/// Welchen Grant-Plan ein Fixture-Eintrag behauptet und mitliefert.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantPlanSpec {
    /// Genau ein Recovery-Grant, und das Manifest traegt dessen ECHTEN
    /// Planhash. Der Regelfall jedes gesunden Fixture-Eintrags.
    Recovery,
    /// Genau ein Recovery-Grant, aber das Manifest traegt einen abweichenden
    /// Planhash.
    MismatchedHash,
    /// Nur ein Reader-Grant: der verpflichtende Recovery-Grant fehlt.
    ///
    /// Der Planhash des Manifests ist hier bedeutungslos, weil der Plan sich
    /// gar nicht erst bilden laesst — `GrantPlanV1::new` bricht mit
    /// `EA-GRANT-MISSING-RECOVERY` ab, bevor ein Hash entstuende.
    ReaderOnly,
    /// Gar kein Grant.
    ///
    /// Fuer Eintraege, die Gate `manifest-signature` nicht ueberleben: ihr
    /// `entryHash` weicht von dem des unversehrten Eintrags ab, ein
    /// mitgelieferter Grant waere deshalb VERWAIST und erzeugte einen zweiten
    /// Befund neben dem, den das Fixture zeigen will.
    Omitted,
}

impl GrantPlanSpec {
    /// Der Wert, den das Manifest als `initial_grant_plan_hash` traegt.
    fn manifest_plan_hash(self) -> [u8; 32] {
        let mut hash = *recovery_grant_plan_hash().as_bytes();
        match self {
            Self::Recovery | Self::Omitted => hash,
            // Genau ein verkipptes Bit: der Eintrag ist unversehrt signiert und
            // faellt allein an der Planbindung.
            Self::MismatchedHash => {
                hash[0] ^= 0x01;
                hash
            }
            Self::ReaderOnly => [0x00; 32],
        }
    }

    /// Der Zweck des Grants, den das Fixture neben den Eintrag legt.
    const fn grant_purpose(self) -> Option<GrantPurposeV1> {
        match self {
            Self::Recovery | Self::MismatchedHash => Some(GrantPurposeV1::Recovery),
            Self::ReaderOnly => Some(GrantPurposeV1::Reader),
            Self::Omitted => None,
        }
    }
}

/// Die Bestandteile eines Fixture-Eintrags.
struct EntrySpec {
    chain_id: ChainId,
    chain_sequence: u64,
    previous_entry_hash: Option<EntryHash>,
    writer_certificate_hash: CertificateHash,
    registry_version: RegistryVersion,
    registry_head_hash: Hash32,
    /// Fuellbyte der `nonce`. Kein Gate dieses Stands liest sie; sie ist der
    /// einzige Freiheitsgrad, der den Objekthash veraendert, ohne eine
    /// Sachaussage des Manifests anzutasten.
    nonce_marker: u8,
    plan: GrantPlanSpec,
}

/// Ein gebauter Eintrag mitsamt seinem Grant.
struct BuiltEntry {
    entry: EntryPackageV1,
    bytes: Vec<u8>,
    grant_bytes: Option<Vec<u8>>,
}

/// Baut ein signiertes `.eip` und den Grant, der zu seinem Plan gehoert.
///
/// Die Reihenfolge ist zwingend und nicht zirkulaer: der Planhash haengt allein
/// an den Empfaengern, das Manifest an dem Planhash, der `entryHash` an dem
/// signierten Manifest — und erst der Grant an dem `entryHash`.
fn build_entry(spec: &EntrySpec) -> BuiltEntry {
    let ciphertext = vec![0x5a; 16];
    let manifest = ManifestCoreV1::new(
        ManifestCoreFieldsV1 {
            organization_id: trust_support::organization(),
            chain_id: spec.chain_id,
            chain_sequence: ChainSequence::new(spec.chain_sequence),
            previous_entry_hash: spec.previous_entry_hash,
            writer_certificate_hash: spec.writer_certificate_hash,
            writer_transition_event_hash: None,
            registry_version: spec.registry_version,
            registry_head_hash: *spec.registry_head_hash.as_bytes(),
            initial_grant_plan_hash: spec.plan.manifest_plan_hash(),
            nonce: [spec.nonce_marker; 12],
        },
        &ciphertext,
    )
    .expect("das Fixture-Manifest muss kodieren");
    let signed = SignedManifestV1::new(manifest, &ciphertext).expect("das Manifest muss binden");
    let signature = writer_device_signer()
        .sign_record(signed.exact_bytes())
        .expect("der Fixture-Signierer muss signieren");
    let entry = EntryPackageV1::new(signed, ciphertext, signature)
        .expect("das Fixture-Eintragspaket muss sich zusammensetzen");
    let bytes = encode_entry_package(&entry)
        .expect("das Fixture-Eintragspaket muss kodieren")
        .into_vec();
    let grant_bytes = spec.plan.grant_purpose().map(|purpose| {
        grant_bytes(
            spec.chain_id,
            entry.entry_hash(),
            purpose,
            spec.writer_certificate_hash,
            spec.registry_version,
            spec.registry_head_hash,
        )
    });
    BuiltEntry {
        entry,
        bytes,
        grant_bytes,
    }
}

/// Ein signierter initialer Grant auf `entry_hash`.
///
/// Der Aussteller ist derselbe Schluessel, der auch die Eintraege signiert:
/// `GrantV1::new` bindet die Ausstellersignatur an
/// `issuer_key_thumbprint`/`issuer_certificate_hash` des Rumpfes, und nur so
/// ist der Grant ueberhaupt parsbar. Ob dieser Aussteller die Capability
/// tatsaechlich traegt, entscheidet Gate `recipient-grant`, nicht dieses Modul.
fn grant_bytes(
    chain_id: ChainId,
    entry_hash: EntryHash,
    purpose: GrantPurposeV1,
    writer_certificate_hash: CertificateHash,
    registry_version: RegistryVersion,
    registry_head_hash: Hash32,
) -> Vec<u8> {
    let (recipient_key_thumbprint, recipient_certificate_hash) = match purpose {
        GrantPurposeV1::Recovery => (
            recovery_recipient_key_thumbprint(),
            recovery_recipient_certificate_hash(),
        ),
        GrantPurposeV1::Reader => (
            reader_recipient_key_thumbprint(),
            reader_recipient_certificate_hash(),
        ),
    };
    let body = GrantBodyV1::new(GrantBodyFieldsV1 {
        organization_id: trust_support::organization(),
        chain_id,
        entry_hash,
        kind: GrantKindV1::Initial,
        purpose,
        recipient_key_thumbprint,
        recipient_certificate_hash,
        issuer_key_thumbprint: writer_device_key_thumbprint(),
        issuer_certificate_hash: writer_certificate_hash,
        registry_version,
        registry_head_hash,
        created_at_device: UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1),
        original_recovery_grant_object_hash: None,
        grant_authorization_object_hash: None,
        encapsulated_key: [0x07; HPKE_ENCAPSULATED_KEY_SIZE],
        wrapped_cek: [0x08; HPKE_WRAPPED_CEK_SIZE],
    })
    .expect("der Fixture-Grantrumpf muss kodieren");
    let signature = writer_device_signer()
        .sign_initial_grant(body.exact_bytes())
        .expect("der Fixture-Aussteller muss signieren");
    let grant = GrantV1::new(body, signature).expect("der Fixture-Grant muss binden");
    encode_grant(&grant)
        .expect("der Fixture-Grant muss kodieren")
        .into_vec()
}

/// Die Linie aus Policy-Kopf und Schreiberkopf, die alle Eintragsfixtures
/// teilen.
struct WriterLine {
    line: trust_support::RegistryLineBuilder,
    head: trust_support::BuiltHead,
    writer_certificate_hash: CertificateHash,
    anchor_bytes: Vec<u8>,
}

impl WriterLine {
    fn anchor(&self) -> TrustAnchorV1 {
        decode_trust_anchor(&self.anchor_bytes).expect("der Fixture-Anker muss dekodieren")
    }

    /// Der Kopfhash als `Hash32`, wie ihn das Manifest traegt.
    fn head_hash(&self) -> Hash32 {
        Hash32::try_from(self.head.object_hash.as_bytes().as_slice())
            .expect("ein Objekthash sind 32 Bytes")
    }
}

/// Baut die geteilte Linie: Policy auf dem Genesisfach, dann das
/// Schreiberzertifikat fuer die Sequenzen eins bis hundert.
fn writer_line() -> WriterLine {
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
    WriterLine {
        line,
        head,
        writer_certificate_hash,
        anchor_bytes,
    }
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
    let line = writer_line();
    let anchor = line.anchor();
    let mut fixture = ArchiveFixture::new();
    let trust_object_count = push_trust_objects(&mut fixture, &line.line);

    // Sequenz 1 folgt auf den Genesis-Eintrag des Ankers: ein Manifest mit
    // Sequenz > 0 MUSS einen Vorgaenger benennen (`ea-format` prueft das schon
    // beim Kodieren).
    let known = build_entry(&EntrySpec {
        chain_id: anchor.chain_id(),
        chain_sequence: KNOWN_WRITER_SEQUENCE_V1,
        previous_entry_hash: Some(anchor.genesis_entry_hash()),
        writer_certificate_hash: line.writer_certificate_hash,
        registry_version: line.head.version,
        registry_head_hash: line.head_hash(),
        nonce_marker: DEFAULT_NONCE_MARKER_V1,
        plan: GrantPlanSpec::Recovery,
    });
    let unknown = build_entry(&EntrySpec {
        chain_id: anchor.chain_id(),
        chain_sequence: UNKNOWN_WRITER_SEQUENCE_V1,
        previous_entry_hash: Some(known.entry.entry_hash()),
        writer_certificate_hash: unknown_writer_certificate_hash(),
        registry_version: line.head.version,
        registry_head_hash: line.head_hash(),
        nonce_marker: DEFAULT_NONCE_MARKER_V1,
        plan: GrantPlanSpec::Recovery,
    });
    let known_writer_object_hash = object_hash(&known.bytes);
    let unknown_writer_object_hash = object_hash(&unknown.bytes);
    assert!(
        known_writer_object_hash != unknown_writer_object_hash,
        "die beiden Eintraege muessen verschiedene Objekte sein"
    );

    push_entry(&mut fixture, KNOWN_WRITER_SEQUENCE_V1, known);
    push_entry(&mut fixture, UNKNOWN_WRITER_SEQUENCE_V1, unknown);

    WriterArchive {
        fixture,
        anchor_bytes: line.anchor_bytes,
        registry_version: line.head.version,
        writer_certificate_hash: line.writer_certificate_hash,
        known_writer_object_hash,
        unknown_writer_object_hash,
        trust_object_count,
    }
}

/// Die Lease des dritten Kopfes in [`archive_with_a_second_lease`].
pub const SECOND_LEASE_FROM_V1: u64 = 2;
/// Letzte Sequenz dieser Lease.
pub const SECOND_LEASE_THROUGH_V1: u64 = 100;

/// Das Fuellbyte der `nonce`, das die Inventarreihenfolge gegen die
/// Sequenzreihenfolge stellt.
///
/// Das Inventar ordnet nach Objekthash. Damit ein Test ueberhaupt merken kann,
/// ob die Pipeline nach Sequenz behandelt, muss der Eintrag mit der HOEHEREN
/// Sequenz den KLEINEREN Objekthash tragen. Dieses Byte ist der dafuer
/// gesuchte Wert; [`archive_with_a_second_lease`] behauptet die Eigenschaft
/// nicht, sondern prueft sie und bricht laut, falls eine Layoutaenderung in
/// `ea-format` sie kippt. Bewusst ein fester Wert statt einer Suche zur
/// Laufzeit: eine Suche faende immer irgendeinen Wert und machte den Test
/// stillschweigend wieder aussagelos.
///
/// Der Wert wanderte von `0x01` auf `0x02`, als die Eintraege dieses Moduls auf
/// den Schluessel der Registrierungslinie umgestellt wurden
/// ([`writer_device_signer`]): eine andere Signatur sind andere Bytes und damit
/// ein anderer Objekthash. Genau dafuer ist die Behauptung in
/// [`archive_with_a_second_lease`] eine Pruefung — sie brach laut, statt den
/// Test still aussagelos werden zu lassen.
///
/// Mit Gate `grant-plan` wanderte der Marker vom `initial_grant_plan_hash` in
/// die `nonce` und dabei von `0x02` auf `0x01`. Der Planhash ist seither eine
/// SACHAUSSAGE — Gate 6 rechnet gegen ihn —, und ein Fuellbyte darin haette
/// entweder den Test verfaelscht oder das Gate. Die `nonce` liest in diesem
/// Stand kein Gate; sie ist damit der einzige Freiheitsgrad, der den Objekthash
/// bewegt, ohne eine Aussage anzutasten. Der neue Wert ist der KLEINSTE, der
/// die gesuchte Ordnung herstellt; ein Durchlauf ueber alle 256 Fuellbytes
/// liefert 67 taugliche, die Auswahl ist also weder knapp noch zufaellig.
pub const DESCENDING_HASH_MARKER_V1: u8 = 0x01;

/// Das Fuellbyte der `nonce` aller uebrigen Fixture-Eintraege.
pub const DEFAULT_NONCE_MARKER_V1: u8 = 0x07;

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
    let early = build_entry(&EntrySpec {
        chain_id: anchor.chain_id(),
        chain_sequence: KNOWN_WRITER_SEQUENCE_V1,
        previous_entry_hash: Some(anchor.genesis_entry_hash()),
        writer_certificate_hash,
        registry_version: writer_head.version,
        registry_head_hash: early_head_hash,
        nonce_marker: DEFAULT_NONCE_MARKER_V1,
        plan: GrantPlanSpec::Recovery,
    });
    let late = build_entry(&EntrySpec {
        chain_id: anchor.chain_id(),
        chain_sequence: UNKNOWN_WRITER_SEQUENCE_V1,
        previous_entry_hash: Some(early.entry.entry_hash()),
        writer_certificate_hash,
        registry_version: late_head.version,
        registry_head_hash: late_head_hash,
        nonce_marker: DESCENDING_HASH_MARKER_V1,
        plan: GrantPlanSpec::Recovery,
    });
    let early_object_hash = object_hash(&early.bytes);
    let late_object_hash = object_hash(&late.bytes);
    assert!(
        late_object_hash < early_object_hash,
        "DESCENDING_HASH_MARKER_V1 stellt die Inventarreihenfolge nicht mehr \
         gegen die Sequenzreihenfolge; der Test waere sonst aussagelos"
    );

    push_entry(&mut fixture, KNOWN_WRITER_SEQUENCE_V1, early);
    push_entry(&mut fixture, UNKNOWN_WRITER_SEQUENCE_V1, late);

    LeasedArchive {
        fixture,
        anchor_bytes,
        early_registry_version: writer_head.version,
        late_registry_version: late_head.version,
        early_object_hash,
        late_object_hash,
    }
}

/// Ein Bestand mit GENAU EINEM Eintragspaket, wahlweise mit einem
/// verkippten Byte.
///
/// Bewusst nur ein `.eip` und keine weitere Objektfamilie: der Befund der
/// Mutationsfaelle ist genau EIN `signatureErrors`-Eintrag, und jedes weitere
/// Objekt gaebe dem Inventar eine zusaetzliche Gelegenheit, etwas anderes zu
/// melden.
pub struct SignedEntryArchive {
    pub fixture: ArchiveFixture,
    pub anchor_bytes: Vec<u8>,
    /// Registrierungsversion, unter der der Eintrag steht.
    pub registry_version: ea_types::RegistryVersion,
    /// Das Schreiberzertifikat, das die Linie aktiviert.
    pub writer_certificate_hash: CertificateHash,
    /// Objekthash der abgelegten Eintragsbytes — nach der Mutation.
    pub entry_object_hash: ObjectHash,
}

impl SignedEntryArchive {
    #[must_use]
    pub fn anchor(&self) -> TrustAnchorV1 {
        decode_trust_anchor(&self.anchor_bytes).expect("der Fixture-Anker muss dekodieren")
    }
}

/// Laenge der Eintragsbytes aus [`archive_with_one_signed_entry`].
///
/// Gepinnt, damit die beiden Mutationsstellen ueberhaupt eine feste Bedeutung
/// haben koennen.
pub const SIGNED_EIP_LENGTH_V1: usize = 535;

/// Erstes Byte des Schluesselabdrucks im GESCHUETZTEN COSE-Header.
///
/// Erreichbare Signaturklasse (a): der Abdruck geht in die `Sig_structure` ein,
/// wird beim Parsen aber nirgends gebunden — `VerificationContext::record`
/// setzt `expected_key_thumbprint` auf `None`
/// (`crates/ea-crypto/src/cose.rs:859-873`). Die Bytes ueberleben Gate `format`
/// und fallen erst an Gate `manifest-signature`.
pub const MUTATED_EIP_KEY_THUMBPRINT_OFFSET_V1: usize = 352;

/// Erstes Byte des rohen Ed25519-Signaturwerts am Ende der COSE-Struktur.
///
/// Erreichbare Signaturklasse (b): die Signatur wird beim Parsen nicht
/// kryptografisch geprueft, sondern erst an Gate `manifest-signature`.
pub const MUTATED_EIP_SIGNATURE_OFFSET_V1: usize = SIGNED_EIP_LENGTH_V1 - 64;

/// Ein Bestand mit genau einem unversehrten, signierten Eintragspaket.
#[must_use]
pub fn archive_with_one_signed_entry() -> SignedEntryArchive {
    signed_entry_archive(None)
}

/// Derselbe Bestand mit GENAU EINEM verkippten Byte an `offset`.
///
/// # Panics
///
/// Wenn die verkippten Bytes Gate `format` nicht mehr ueberleben. Dann traefe
/// der Test Gate 1 statt Gate 4 und waere aussagelos.
#[must_use]
pub fn archive_with_one_mutated_entry(offset: usize) -> SignedEntryArchive {
    signed_entry_archive(Some(offset))
}

/// Baut den Bestand aus [`SignedEntryArchive`].
///
/// # Panics
///
/// Wenn das Layout der Eintragsbytes sich verschoben hat: Laenge, Lage des
/// Schluesselabdrucks und Lage des rohen Signaturwerts werden geprueft, nie
/// behauptet. Eine Layoutaenderung in `ea-format` bricht hier laut, statt die
/// Mutationen stillschweigend an eine andere Stelle wandern zu lassen.
fn signed_entry_archive(mutation: Option<usize>) -> SignedEntryArchive {
    let line = writer_line();
    let anchor = line.anchor();
    let writer_certificate_hash = line.writer_certificate_hash;
    let head = line.head;

    let mut fixture = ArchiveFixture::new();
    push_trust_objects(&mut fixture, &line.line);

    // OHNE Grant, sobald mutiert wird: die Mutation trifft in beiden Faellen
    // die COSE-Struktur der Schreibersignatur und veraendert damit den
    // `entryHash`. Ein mitgelieferter Grant zeigte danach ins Leere und waere
    // ein VERWAISTER Grant — ein zweiter Befund neben dem einen, den diese
    // Fixture zeigen will.
    let built = build_entry(&EntrySpec {
        chain_id: anchor.chain_id(),
        chain_sequence: KNOWN_WRITER_SEQUENCE_V1,
        previous_entry_hash: Some(anchor.genesis_entry_hash()),
        writer_certificate_hash,
        registry_version: head.version,
        registry_head_hash: line.head_hash(),
        nonce_marker: DEFAULT_NONCE_MARKER_V1,
        plan: if mutation.is_none() {
            GrantPlanSpec::Recovery
        } else {
            GrantPlanSpec::Omitted
        },
    });
    let bytes = built.bytes;
    assert_eq!(
        bytes.len(),
        SIGNED_EIP_LENGTH_V1,
        "die gepinnte Laenge der Eintragsbytes stimmt nicht mehr"
    );
    assert_eq!(
        &bytes[MUTATED_EIP_KEY_THUMBPRINT_OFFSET_V1..MUTATED_EIP_KEY_THUMBPRINT_OFFSET_V1 + 32],
        writer_device_key_thumbprint().as_bytes(),
        "der Schluesselabdruck steht nicht mehr an der gepinnten Stelle"
    );
    assert_eq!(
        bytes
            .windows(32)
            .filter(|window| *window == writer_device_key_thumbprint().as_bytes())
            .count(),
        1,
        "der Schluesselabdruck kommt nicht mehr genau einmal vor"
    );
    assert_eq!(
        MUTATED_EIP_SIGNATURE_OFFSET_V1,
        bytes.len() - 64,
        "der rohe Signaturwert steht nicht mehr in den letzten 64 Bytes"
    );

    let bytes = match mutation {
        None => bytes,
        Some(offset) => mutate_one_byte(&bytes, offset),
    };
    let entry_object_hash = object_hash(&bytes);
    fixture.push_exact_bytes(
        &format!(
            "{}{KNOWN_WRITER_SEQUENCE_V1:012}_entry.eip",
            ea_archive::ENTRIES_DIR_V1
        ),
        bytes,
    );
    if let Some(grant) = built.grant_bytes {
        push_grant(&mut fixture, KNOWN_WRITER_SEQUENCE_V1, grant);
    }

    SignedEntryArchive {
        fixture,
        anchor_bytes: line.anchor_bytes,
        registry_version: head.version,
        writer_certificate_hash,
        entry_object_hash,
    }
}

/// Verkippt genau ein Byte und belegt, dass die Bytes Gate `format` ueberleben.
fn mutate_one_byte(bytes: &[u8], offset: usize) -> Vec<u8> {
    let mut mutated = bytes.to_vec();
    mutated[offset] ^= 0x01;
    assert_eq!(
        mutated.len(),
        bytes.len(),
        "die Mutation darf die Laenge nicht aendern"
    );
    assert_eq!(
        mutated
            .iter()
            .zip(bytes.iter())
            .filter(|(left, right)| left != right)
            .count(),
        1,
        "genau ein Byte darf sich unterscheiden"
    );
    assert!(
        mutated.starts_with(&EIP_PREFIX_V1),
        "die Mutation muss das Exact-Object-Praefix unangetastet lassen"
    );
    assert!(
        ea_format::decode_exact_object(&mutated).is_ok(),
        "die Mutation an {offset} ueberlebt Gate `format` nicht; der Test traefe \
         Gate 1 statt Gate 4"
    );
    mutated
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

/// Legt einen gebauten Eintrag samt seinem Grant im Bestand ab.
///
/// Der Pfadhinweis ist ein Hinweis: klassifiziert wird am Praefix.
fn push_entry(fixture: &mut ArchiveFixture, chain_sequence: u64, built: BuiltEntry) {
    fixture.push_exact_bytes(
        &format!(
            "{}{chain_sequence:012}_entry.eip",
            ea_archive::ENTRIES_DIR_V1
        ),
        built.bytes,
    );
    if let Some(grant) = built.grant_bytes {
        push_grant(fixture, chain_sequence, grant);
    }
}

/// Legt Grantbytes im Bestand ab.
fn push_grant(fixture: &mut ArchiveFixture, chain_sequence: u64, bytes: Vec<u8>) {
    fixture.push_exact_bytes(
        &format!(
            "{}{chain_sequence:012}_grant.eag",
            ea_archive::GRANTS_DIR_V1
        ),
        bytes,
    );
}

/// Ein Bestand mit einer echten Registrierungslinie und einer Eintragskette.
///
/// Ein Typ fuer alle Fixtures der Gates `chain-position` und `grant-plan`: die
/// fuenf Faelle unterscheiden sich im BESTAND, nicht in dem, was ein Test von
/// ihm wissen muss.
pub struct ChainArchive {
    pub fixture: ArchiveFixture,
    pub anchor_bytes: Vec<u8>,
    /// Objekthashes der abgelegten Eintraege, in Sequenzreihenfolge.
    pub entry_object_hashes: Vec<ObjectHash>,
    /// Eintragshashes derselben Eintraege, in derselben Reihenfolge.
    pub entry_hashes: Vec<EntryHash>,
    /// Objekthash des verwaisten Grants, falls das Fixture einen ablegt.
    pub orphan_grant_object_hash: Option<ObjectHash>,
}

impl ChainArchive {
    #[must_use]
    pub fn anchor(&self) -> TrustAnchorV1 {
        decode_trust_anchor(&self.anchor_bytes).expect("der Fixture-Anker muss dekodieren")
    }
}

/// Erste Sequenz der Eintragsketten dieses Moduls.
///
/// Eins und nicht null: siehe [`GENESIS_GAP_SEQUENCE_V1`].
pub const FIRST_ENTRY_SEQUENCE_V1: u64 = 1;

/// Die Sequenz, die [`archive_with_a_missing_middle_entry`] auslaesst.
pub const MISSING_MIDDLE_SEQUENCE_V1: u64 = 3;

/// Ein Bestand, in dem zwei Eintraege ihre Vorgaengerbindung TAUSCHEN.
///
/// Drei Sequenzen, eins bis drei. Der erste Eintrag bindet den Genesis-Eintrag
/// des Ankers und bleibt unstrittig.
///
/// DER TAUSCH IST NOTWENDIG UNSYMMETRISCH, und das ist keine Nachlaessigkeit,
/// sondern eine Folge der Hashkette. Sequenz drei traegt `EA`, den
/// Eintragshash von Sequenz eins — also genau die Bindung, die SEQUENZ ZWEI
/// tragen muesste. Die Gegenrichtung ist unerreichbar: Sequenz zwei muesste
/// dafuer den Eintragshash von Sequenz drei tragen, und der haengt an einem
/// Manifest, das seinerseits erst entsteht, wenn Sequenz zwei feststeht.
/// Stattdessen traegt Sequenz zwei `EB` — den Eintragshash der UNGETAUSCHTEN
/// zweiten Fassung, die gebaut und nie abgelegt wird. Ihre Bindung zeigt damit
/// auf ein Objekt, das es im Bestand nicht gibt.
///
/// WER DAS ZU EINEM SYMMETRISCHEN TAUSCH „REPARIERT", zerstoert den Test: die
/// Symmetrie ist ohne eine Hashkollision nicht konstruierbar, und jeder
/// Versuch endet entweder in einer Zirkelrechnung oder in nur EINEM Bruch.
///
/// Erwarteter Befund, beide Male ein Vorgaengerbruch gegen die unmittelbar
/// vorangehende Sequenz: Sequenz zwei bindet `EB`, die Sequenz eins traegt aber
/// `EA`; Sequenz drei bindet `EA`, die Sequenz zwei traegt aber ihren eigenen,
/// neuen Eintragshash. Also ZWEI isolierte Objekte mit Grund `conflicting` —
/// und ausdruecklich keine Luecke ueber den beiden Sequenzen: die Eintraege
/// sind da, sie widersprechen sich nur.
#[must_use]
pub fn archive_with_swapped_predecessors() -> ChainArchive {
    let line = writer_line();
    let anchor = line.anchor();
    let mut fixture = ArchiveFixture::new();
    push_trust_objects(&mut fixture, &line.line);

    let first = build_entry(&chain_entry_spec(
        &line,
        anchor.chain_id(),
        FIRST_ENTRY_SEQUENCE_V1,
        Some(anchor.genesis_entry_hash()),
    ));
    // Die ungetauschte zweite Fassung: sie liefert allein ihren Eintragshash
    // und wird nicht abgelegt.
    let unswapped_second = build_entry(&chain_entry_spec(
        &line,
        anchor.chain_id(),
        FIRST_ENTRY_SEQUENCE_V1 + 1,
        Some(first.entry.entry_hash()),
    ));
    let second = build_entry(&chain_entry_spec(
        &line,
        anchor.chain_id(),
        FIRST_ENTRY_SEQUENCE_V1 + 1,
        Some(unswapped_second.entry.entry_hash()),
    ));
    let third = build_entry(&chain_entry_spec(
        &line,
        anchor.chain_id(),
        FIRST_ENTRY_SEQUENCE_V1 + 2,
        Some(first.entry.entry_hash()),
    ));

    let entry_object_hashes = vec![
        object_hash(&first.bytes),
        object_hash(&second.bytes),
        object_hash(&third.bytes),
    ];
    let entry_hashes = vec![
        first.entry.entry_hash(),
        second.entry.entry_hash(),
        third.entry.entry_hash(),
    ];
    push_entry(&mut fixture, FIRST_ENTRY_SEQUENCE_V1, first);
    push_entry(&mut fixture, FIRST_ENTRY_SEQUENCE_V1 + 1, second);
    push_entry(&mut fixture, FIRST_ENTRY_SEQUENCE_V1 + 2, third);

    ChainArchive {
        fixture,
        anchor_bytes: line.anchor_bytes,
        entry_object_hashes,
        entry_hashes,
        orphan_grant_object_hash: None,
    }
}

/// Ein Bestand, dem GENAU EIN Eintrag in der Mitte fehlt.
///
/// Die Sequenzen eins, zwei und vier liegen vor, die drei fehlt. Der Eintrag
/// auf Sequenz vier bindet dabei den Eintragshash des FEHLENDEN Eintrags —
/// genau so sieht ein Bestand aus, aus dem ein Objekt verschwunden ist, und
/// gerade nicht wie ein Bruch: `ea-chain` vergleicht Vorgaengerbindungen nur
/// zwischen unmittelbar benachbarten Sequenzen.
#[must_use]
pub fn archive_with_a_missing_middle_entry() -> ChainArchive {
    let line = writer_line();
    let anchor = line.anchor();
    let mut fixture = ArchiveFixture::new();
    push_trust_objects(&mut fixture, &line.line);

    let first = build_entry(&chain_entry_spec(
        &line,
        anchor.chain_id(),
        FIRST_ENTRY_SEQUENCE_V1,
        Some(anchor.genesis_entry_hash()),
    ));
    let second = build_entry(&chain_entry_spec(
        &line,
        anchor.chain_id(),
        FIRST_ENTRY_SEQUENCE_V1 + 1,
        Some(first.entry.entry_hash()),
    ));
    // Der Eintrag, der fehlt. Er wird gebaut und nicht abgelegt.
    let missing = build_entry(&chain_entry_spec(
        &line,
        anchor.chain_id(),
        MISSING_MIDDLE_SEQUENCE_V1,
        Some(second.entry.entry_hash()),
    ));
    let fourth = build_entry(&chain_entry_spec(
        &line,
        anchor.chain_id(),
        MISSING_MIDDLE_SEQUENCE_V1 + 1,
        Some(missing.entry.entry_hash()),
    ));

    let entry_object_hashes = vec![
        object_hash(&first.bytes),
        object_hash(&second.bytes),
        object_hash(&fourth.bytes),
    ];
    let entry_hashes = vec![
        first.entry.entry_hash(),
        second.entry.entry_hash(),
        fourth.entry.entry_hash(),
    ];
    push_entry(&mut fixture, FIRST_ENTRY_SEQUENCE_V1, first);
    push_entry(&mut fixture, FIRST_ENTRY_SEQUENCE_V1 + 1, second);
    push_entry(&mut fixture, MISSING_MIDDLE_SEQUENCE_V1 + 1, fourth);

    ChainArchive {
        fixture,
        anchor_bytes: line.anchor_bytes,
        entry_object_hashes,
        entry_hashes,
        orphan_grant_object_hash: None,
    }
}

/// Der Eintragshash, auf den der verwaiste Grant zeigt.
///
/// Ein Eintragshash entsteht aus SHA-256 ueber signiertes Manifest und
/// Signatur; eine konstante Bytefolge ist deshalb mit an Sicherheit grenzender
/// Wahrscheinlichkeit keiner.
#[must_use]
pub fn orphan_grant_entry_hash() -> EntryHash {
    EntryHash::try_from(&[0x77_u8; 32][..]).expect("32 Bytes sind ein Eintragshash")
}

/// Ein unstrittiger Bestand mit EINEM zusaetzlichen, verwaisten Grant.
///
/// Der Grant ist wohlgeformt und ausstellersigniert, sein `entryHash` zeigt
/// aber auf kein Objekt des Bestands. Er ist damit niemandem zuzuordnen —
/// `unattributable` — und beruehrt die Kette nicht: ein Grant beansprucht kein
/// Sequenzfach.
#[must_use]
pub fn archive_with_an_orphan_grant() -> ChainArchive {
    let line = writer_line();
    let anchor = line.anchor();
    let mut fixture = ArchiveFixture::new();
    push_trust_objects(&mut fixture, &line.line);

    let first = build_entry(&chain_entry_spec(
        &line,
        anchor.chain_id(),
        FIRST_ENTRY_SEQUENCE_V1,
        Some(anchor.genesis_entry_hash()),
    ));
    let second = build_entry(&chain_entry_spec(
        &line,
        anchor.chain_id(),
        FIRST_ENTRY_SEQUENCE_V1 + 1,
        Some(first.entry.entry_hash()),
    ));
    let entry_object_hashes = vec![object_hash(&first.bytes), object_hash(&second.bytes)];
    let entry_hashes = vec![first.entry.entry_hash(), second.entry.entry_hash()];
    push_entry(&mut fixture, FIRST_ENTRY_SEQUENCE_V1, first);
    push_entry(&mut fixture, FIRST_ENTRY_SEQUENCE_V1 + 1, second);

    let orphan = grant_bytes(
        anchor.chain_id(),
        orphan_grant_entry_hash(),
        GrantPurposeV1::Recovery,
        line.writer_certificate_hash,
        line.head.version,
        line.head_hash(),
    );
    let orphan_grant_object_hash = object_hash(&orphan);
    push_grant(&mut fixture, MISSING_MIDDLE_SEQUENCE_V1 + 6, orphan);

    ChainArchive {
        fixture,
        anchor_bytes: line.anchor_bytes,
        entry_object_hashes,
        entry_hashes,
        orphan_grant_object_hash: Some(orphan_grant_object_hash),
    }
}

/// Ein Bestand mit genau einem Eintrag, dessen `initial_grant_plan_hash`
/// NICHT der Hash des mitgelieferten Plans ist.
///
/// Der Eintrag ist unversehrt signiert und kettenrichtig; er faellt allein an
/// Gate `grant-plan`.
#[must_use]
pub fn archive_with_a_mismatched_grant_plan_hash() -> ChainArchive {
    single_entry_archive(GrantPlanSpec::MismatchedHash)
}

/// Ein Bestand mit genau einem Eintrag, dem der VERPFLICHTENDE Recovery-Grant
/// fehlt: neben ihm liegt nur ein Reader-Grant.
#[must_use]
pub fn archive_without_a_recovery_grant() -> ChainArchive {
    single_entry_archive(GrantPlanSpec::ReaderOnly)
}

/// Ein Bestand mit genau einem Eintrag auf der ersten Sequenz.
fn single_entry_archive(plan: GrantPlanSpec) -> ChainArchive {
    let line = writer_line();
    let anchor = line.anchor();
    let mut fixture = ArchiveFixture::new();
    push_trust_objects(&mut fixture, &line.line);

    let mut spec = chain_entry_spec(
        &line,
        anchor.chain_id(),
        FIRST_ENTRY_SEQUENCE_V1,
        Some(anchor.genesis_entry_hash()),
    );
    spec.plan = plan;
    let built = build_entry(&spec);
    let entry_object_hashes = vec![object_hash(&built.bytes)];
    let entry_hashes = vec![built.entry.entry_hash()];
    push_entry(&mut fixture, FIRST_ENTRY_SEQUENCE_V1, built);

    ChainArchive {
        fixture,
        anchor_bytes: line.anchor_bytes,
        entry_object_hashes,
        entry_hashes,
        orphan_grant_object_hash: None,
    }
}

/// Der gemeinsame Zuschnitt eines Kettenfixture-Eintrags.
fn chain_entry_spec(
    line: &WriterLine,
    chain_id: ChainId,
    chain_sequence: u64,
    previous_entry_hash: Option<EntryHash>,
) -> EntrySpec {
    EntrySpec {
        chain_id,
        chain_sequence,
        previous_entry_hash,
        writer_certificate_hash: line.writer_certificate_hash,
        registry_version: line.head.version,
        registry_head_hash: line.head_hash(),
        nonce_marker: DEFAULT_NONCE_MARKER_V1,
        plan: GrantPlanSpec::Recovery,
    }
}

// ---------------------------------------------------------------------------
// Gate `receipt`: Quittungen, Checkpoints und Stummel
// ---------------------------------------------------------------------------

/// Letzte Sequenz der Lease des Policy-Kopfes der Quittungslinie.
pub const RECEIPT_POLICY_LEASE_THROUGH_V1: u64 = 0;

/// Die Lease des Kopfes, der das SERVERZERTIFIKAT aktiviert.
///
/// Ein eigener Kopf ist unvermeidlich: ein Registrierungskopf traegt genau
/// EINEN Uebergang, und Gate `receipt` braucht neben dem Schreiberzertifikat
/// zwingend ein Zertifikat der Art [`CertificateKindV1::ServerReceipt`] —
/// `VerificationContext::receipt` verlangt die Capability `serverReceipt`
/// (`crates/ea-crypto/src/cose.rs:913-930`). Die Leases muessen aufsteigen,
/// deshalb belegt dieser Kopf das Fach eins.
pub const RECEIPT_SERVER_LEASE_V1: u64 = 1;

/// Erste Sequenz der Lease des Schreiberkopfes der Quittungslinie.
pub const RECEIPT_WRITER_LEASE_FROM_V1: u64 = 2;
/// Letzte Sequenz dieser Lease.
pub const RECEIPT_WRITER_LEASE_THROUGH_V1: u64 = 100;

/// Die Luecke, die JEDER Bestand der Quittungslinie traegt: `0..=1`.
///
/// GEMESSEN, nicht behauptet, und dieselbe Ursache wie
/// [`GENESIS_GAP_SEQUENCE_V1`], nur um ein Fach breiter: die Linie braucht drei
/// Koepfe (Policy, Serverzertifikat, Schreiberzertifikat), und die ersten
/// beiden verbrauchen die Faecher null und eins, bevor das Schreiberzertifikat
/// ueberhaupt aktiv ist. Ein `.eip` auf diesen Sequenzen ist damit nicht
/// herstellbar, und `ea_chain::build_chain` meldet das Fehlen — zu Recht — als
/// Luecke. Wer sie „wegrepariert", macht die Fixtures unwahr.
pub const RECEIPT_PRE_ENTRY_GAP_THROUGH_V1: u64 = 1;

/// Sequenz des ersten Eintrags der Quittungsbestaende.
pub const RECEIPT_FIRST_SEQUENCE_V1: u64 = 2;
/// Sequenz des zweiten und letzten Eintrags — zugleich der Kettenkopf.
pub const RECEIPT_HEAD_SEQUENCE_V1: u64 = 3;

/// Die Sequenz, bis zu der der abschneidende Checkpoint bezeugt.
///
/// Deutlich ueber dem Kettenkopf, damit die bewiesene Luecke `4..=5` von der
/// Vorlauf-Luecke `0..=1` unterscheidbar bleibt.
pub const CHECKPOINT_TRUNCATED_THROUGH_V1: u64 = 5;

/// Erste bewiesen fehlende Sequenz des abschneidenden Checkpoints.
pub const CHECKPOINT_PROVEN_GAP_FROM_V1: u64 = RECEIPT_HEAD_SEQUENCE_V1 + 1;

/// Die Sequenz, auf der der Stummel-Bestand sein `.eip` NICHT ablegt.
pub const DESTROYED_STUB_SEQUENCE_V1: u64 = 4;

/// Ein Kopf-Eintragshash, den kein Eintrag dieses Moduls je traegt.
#[must_use]
pub fn foreign_head_entry_hash() -> EntryHash {
    EntryHash::try_from(&[0x66_u8; 32][..]).expect("32 Bytes sind ein Eintragshash")
}

/// Welchen Checkpoint ein Quittungsbestand mitliefert.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointSpec {
    /// Gar keinen. Ueber Rollback ist dann NICHTS gesagt.
    None,
    /// Einer, der eine Sequenz OBERHALB des Kettenkopfes bezeugt.
    Truncated,
    /// Einer, der die Kopfsequenz bezeugt, aber einen anderen Eintragshash.
    HeadMismatch,
}

/// Der Zuschnitt eines Quittungsbestands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptArchiveSpec {
    /// Legt der Bestand zu JEDEM Eintrag eine gueltige Quittung dazu?
    pub receipts: bool,
    /// Welcher Checkpoint liegt dabei?
    pub checkpoint: CheckpointSpec,
    /// Liegt zusaetzlich ein `.eds` auf [`DESTROYED_STUB_SEQUENCE_V1`]?
    pub destroyed_stub: bool,
}

impl ReceiptArchiveSpec {
    /// Zwei Eintraege, keine Quittung, kein Checkpoint, kein Stummel.
    #[must_use]
    pub const fn bare() -> Self {
        Self {
            receipts: false,
            checkpoint: CheckpointSpec::None,
            destroyed_stub: false,
        }
    }

    /// Derselbe Bestand MIT Quittungen.
    #[must_use]
    pub const fn with_receipts(mut self) -> Self {
        self.receipts = true;
        self
    }

    /// Derselbe Bestand mit `checkpoint`.
    #[must_use]
    pub const fn with_checkpoint(mut self, checkpoint: CheckpointSpec) -> Self {
        self.checkpoint = checkpoint;
        self
    }

    /// Derselbe Bestand mit einem Stummel statt eines vierten `.eip`.
    #[must_use]
    pub const fn with_destroyed_stub(mut self) -> Self {
        self.destroyed_stub = true;
        self
    }
}

/// Ein Bestand der Quittungslinie.
pub struct ReceiptArchive {
    pub fixture: ArchiveFixture,
    pub anchor_bytes: Vec<u8>,
    /// Objekthashes der abgelegten `.eip`, in Sequenzreihenfolge.
    pub entry_object_hashes: Vec<ObjectHash>,
    /// Eintragshashes derselben Eintraege, in derselben Reihenfolge.
    pub entry_hashes: Vec<EntryHash>,
    /// Objekthashes der abgelegten `.esr`, in derselben Reihenfolge.
    pub receipt_object_hashes: Vec<ObjectHash>,
    /// Objekthash des abgelegten `.ecp`, falls einer dabei liegt.
    pub checkpoint_object_hash: Option<ObjectHash>,
    /// Objekthash des abgelegten `.eds`, falls einer dabei liegt.
    pub destroyed_stub_object_hash: Option<ObjectHash>,
}

impl ReceiptArchive {
    #[must_use]
    pub fn anchor(&self) -> TrustAnchorV1 {
        decode_trust_anchor(&self.anchor_bytes).expect("der Fixture-Anker muss dekodieren")
    }
}

/// Die Linie aus Policy-, Server- und Schreiberkopf.
struct ReceiptLine {
    line: trust_support::RegistryLineBuilder,
    head: trust_support::BuiltHead,
    writer_certificate_hash: CertificateHash,
    server_certificate_hash: CertificateHash,
    anchor_bytes: Vec<u8>,
}

impl ReceiptLine {
    fn anchor(&self) -> TrustAnchorV1 {
        decode_trust_anchor(&self.anchor_bytes).expect("der Fixture-Anker muss dekodieren")
    }

    fn head_hash(&self) -> Hash32 {
        Hash32::try_from(self.head.object_hash.as_bytes().as_slice())
            .expect("ein Objekthash sind 32 Bytes")
    }
}

/// Baut die Linie: Policy, dann das Serverzertifikat, dann das
/// Schreiberzertifikat.
///
/// BEWUSST NEBEN [`writer_line`] und nicht als Erweiterung: fuenf Fixtures
/// haengen an deren zwei Koepfen, und `signed_entry_archive` pinnt sogar die
/// Bytelaenge des entstehenden `.eip`. Ein dritter Kopf dort verschoebe
/// `line.head` und braeche vier bestehende Testtargets.
fn receipt_line() -> ReceiptLine {
    let mut line = trust_support::RegistryLineBuilder::new();
    line.push(
        policy_action(),
        trust_support::HeadOptions {
            effective_from: Some(POLICY_LEASE_FROM_V1),
            valid_through: Some(RECEIPT_POLICY_LEASE_THROUGH_V1),
            ..trust_support::HeadOptions::default()
        },
    );
    let server_head = line.push(
        trust_support::ActionSpec::Device {
            kind: CertificateKindV1::ServerReceipt,
            marker: 0x21,
            effective_from: None,
        },
        trust_support::HeadOptions {
            effective_from: Some(RECEIPT_SERVER_LEASE_V1),
            valid_through: Some(RECEIPT_SERVER_LEASE_V1),
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
            effective_from: Some(RECEIPT_WRITER_LEASE_FROM_V1),
            valid_through: Some(RECEIPT_WRITER_LEASE_THROUGH_V1),
            ..trust_support::HeadOptions::default()
        },
    );
    let writer_certificate_hash = CertificateHash::from(
        head.direct_object_hash
            .expect("ein Device-Uebergang traegt ein direktes Ziel"),
    );
    let server_certificate_hash = CertificateHash::from(
        server_head
            .direct_object_hash
            .expect("ein Device-Uebergang traegt ein direktes Ziel"),
    );
    let anchor_bytes = line.exact_anchor_bytes().to_vec();
    ReceiptLine {
        line,
        head,
        writer_certificate_hash,
        server_certificate_hash,
        anchor_bytes,
    }
}

/// Baut einen Bestand der Quittungslinie nach `spec`.
///
/// # Panics
///
/// Wenn eines der Fixture-Objekte sich nicht bauen oder kodieren laesst.
#[must_use]
pub fn receipt_archive(spec: ReceiptArchiveSpec) -> ReceiptArchive {
    let line = receipt_line();
    let anchor = line.anchor();
    let mut fixture = ArchiveFixture::new();
    push_trust_objects(&mut fixture, &line.line);

    let first = build_entry(&receipt_entry_spec(
        &line,
        anchor.chain_id(),
        RECEIPT_FIRST_SEQUENCE_V1,
        Some(anchor.genesis_entry_hash()),
    ));
    let second = build_entry(&receipt_entry_spec(
        &line,
        anchor.chain_id(),
        RECEIPT_HEAD_SEQUENCE_V1,
        Some(first.entry.entry_hash()),
    ));
    let entry_object_hashes = vec![object_hash(&first.bytes), object_hash(&second.bytes)];
    let entry_hashes = vec![first.entry.entry_hash(), second.entry.entry_hash()];

    let mut receipt_object_hashes = Vec::new();
    if spec.receipts {
        for (index, (sequence, built)) in [
            (RECEIPT_FIRST_SEQUENCE_V1, &first),
            (RECEIPT_HEAD_SEQUENCE_V1, &second),
        ]
        .into_iter()
        .enumerate()
        {
            let previous = if index == 0 {
                anchor.genesis_entry_hash()
            } else {
                entry_hashes[0]
            };
            let bytes = receipt_bytes(
                &line,
                anchor.chain_id(),
                sequence,
                built.entry.entry_hash(),
                entry_object_hashes[index],
                previous,
            );
            receipt_object_hashes.push(object_hash(&bytes));
            fixture.push_exact_bytes(
                &format!("{}{sequence:012}_receipt.esr", ea_archive::RECEIPTS_DIR_V1),
                bytes,
            );
        }
    }

    let checkpoint_object_hash = match spec.checkpoint {
        CheckpointSpec::None => None,
        CheckpointSpec::Truncated => Some(push_checkpoint(
            &mut fixture,
            &line,
            anchor.chain_id(),
            CHECKPOINT_TRUNCATED_THROUGH_V1,
            entry_hashes[1],
        )),
        CheckpointSpec::HeadMismatch => Some(push_checkpoint(
            &mut fixture,
            &line,
            anchor.chain_id(),
            RECEIPT_HEAD_SEQUENCE_V1,
            foreign_head_entry_hash(),
        )),
    };

    let mut entry_object_hashes = entry_object_hashes;
    let mut entry_hashes = entry_hashes;
    let destroyed_stub_object_hash = spec.destroyed_stub.then(|| {
        let destroyed = build_entry(&receipt_entry_spec(
            &line,
            anchor.chain_id(),
            DESTROYED_STUB_SEQUENCE_V1,
            Some(second.entry.entry_hash()),
        ));
        let stub_hash = push_destroyed_stub(&mut fixture, &destroyed);
        // EIN EINTRAG OBERHALB DES STUMMELS ist notwendig, damit das fehlende
        // `.eip` ueberhaupt als Luecke sichtbar wird: `ea_chain` bildet
        // oberhalb des hoechsten Knotens grundsaetzlich kein Intervall
        // (`crates/ea-chain/src/chain.rs:763-767`), weil ueber nicht
        // existierende Fortsetzungen keine Aussage moeglich ist. Ohne diesen
        // Nachfolger waere die Vernichtung von einem schlicht kuerzeren Bestand
        // nicht zu unterscheiden.
        let successor = build_entry(&receipt_entry_spec(
            &line,
            anchor.chain_id(),
            DESTROYED_STUB_SEQUENCE_V1 + 1,
            Some(destroyed.entry.entry_hash()),
        ));
        entry_object_hashes.push(object_hash(&successor.bytes));
        entry_hashes.push(successor.entry.entry_hash());
        push_entry(&mut fixture, DESTROYED_STUB_SEQUENCE_V1 + 1, successor);
        stub_hash
    });

    push_entry(&mut fixture, RECEIPT_FIRST_SEQUENCE_V1, first);
    push_entry(&mut fixture, RECEIPT_HEAD_SEQUENCE_V1, second);

    ReceiptArchive {
        fixture,
        anchor_bytes: line.anchor_bytes,
        entry_object_hashes,
        entry_hashes,
        receipt_object_hashes,
        checkpoint_object_hash,
        destroyed_stub_object_hash,
    }
}

/// Der gemeinsame Zuschnitt eines Eintrags der Quittungslinie.
fn receipt_entry_spec(
    line: &ReceiptLine,
    chain_id: ChainId,
    chain_sequence: u64,
    previous_entry_hash: Option<EntryHash>,
) -> EntrySpec {
    EntrySpec {
        chain_id,
        chain_sequence,
        previous_entry_hash,
        writer_certificate_hash: line.writer_certificate_hash,
        registry_version: line.head.version,
        registry_head_hash: line.head_hash(),
        nonce_marker: DEFAULT_NONCE_MARKER_V1,
        plan: GrantPlanSpec::Recovery,
    }
}

/// Baut die Bytes einer gueltigen Serverquittung auf einen Eintrag.
///
/// Der Signierer ist derselbe Schluessel wie ueberall in dieser Linie: die
/// Registrierungslinie stellt JEDES Geraetezertifikat auf
/// `trust_support::authorized_device_signing_key_thumbprint()` aus. Die
/// Serverrolle kommt vom ZERTIFIKAT, nicht vom Schluessel.
fn receipt_bytes(
    line: &ReceiptLine,
    chain_id: ChainId,
    chain_sequence: u64,
    entry_hash: EntryHash,
    entry_object_hash: ObjectHash,
    previous_entry_hash: EntryHash,
) -> Vec<u8> {
    let core = ReceiptCoreV1::new(ReceiptCoreFieldsV1 {
        organization_id: trust_support::organization(),
        chain_id,
        chain_sequence: ChainSequence::new(chain_sequence),
        entry_hash,
        entry_object_hash,
        previous_entry_hash: Some(previous_entry_hash),
        registry_version: line.head.version,
        registry_head_hash: line.head_hash(),
        policy_object_hash: fixture_policy_object_hash(),
        initial_grant_plan_hash: recovery_grant_plan_hash(),
        initial_grant_object_hashes: vec![fixture_grant_object_hash()],
        accepted_at_server: UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1),
        evidence_due_at: None,
        server_key_thumbprint: writer_device_key_thumbprint(),
        server_certificate_hash: line.server_certificate_hash,
    })
    .expect("der Fixture-Quittungskern muss kodieren");
    let signature = writer_device_signer()
        .sign_receipt(core.exact_bytes())
        .expect("der Fixture-Server muss signieren");
    let receipt = ReceiptV1::new(core, signature).expect("die Fixture-Quittung muss binden");
    encode_receipt(&receipt)
        .expect("die Fixture-Quittung muss kodieren")
        .into_vec()
}

/// Ein Policy-Objekthash fuer die Quittung.
///
/// Gate `receipt` prueft nach `design.md` §14.1 Schritt 7 die Bindungen
/// `entryHash`, `chainSequence`, `registryVersion`, `registryHeadHash` und
/// `initialGrantPlanHash`; der Policy-Hash gehoert NICHT dazu und ist deshalb
/// ein fester Fuellwert. Waere er gebunden, muesste dieses Fixture ihn aus dem
/// gewaehlten Kopf ziehen — dann pruefte der Test die Fixture, nicht das Gate.
#[must_use]
fn fixture_policy_object_hash() -> ObjectHash {
    ObjectHash::try_from(&[0x31_u8; 32][..]).expect("32 Bytes sind ein Objekthash")
}

/// Ein Grant-Objekthash fuer die Quittung; `ea-format` verlangt mindestens einen.
fn fixture_grant_object_hash() -> ObjectHash {
    ObjectHash::try_from(&[0x32_u8; 32][..]).expect("32 Bytes sind ein Objekthash")
}

/// Legt einen signierten Standard-Checkpoint ab und liefert seinen Objekthash.
fn push_checkpoint(
    fixture: &mut ArchiveFixture,
    line: &ReceiptLine,
    chain_id: ChainId,
    covered_through_sequence: u64,
    head_entry_hash: EntryHash,
) -> ObjectHash {
    let core = CheckpointCoreV1::new(CheckpointCoreFieldsV1 {
        organization_id: trust_support::organization(),
        chain_id,
        covered_from_sequence: ChainSequence::new(RECEIPT_FIRST_SEQUENCE_V1),
        covered_through_sequence: ChainSequence::new(covered_through_sequence),
        head_entry_hash,
        registry_head_hash: line.head_hash(),
        issued_at_server: UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1),
        previous_evidence_hash: None,
    })
    .expect("der Fixture-Checkpointkern muss kodieren");
    let signature = writer_device_signer()
        .sign_checkpoint(line.server_certificate_hash, core.exact_bytes())
        .expect("der Fixture-Server muss signieren");
    let evidence =
        EvidenceObjectV1::standard(core, signature).expect("der Fixture-Checkpoint muss binden");
    let bytes = encode_evidence(&evidence)
        .expect("der Fixture-Checkpoint muss kodieren")
        .into_vec();
    let hash = object_hash(&bytes);
    fixture.push_exact_bytes(
        &format!(
            "{}{covered_through_sequence:012}_checkpoint.ecp",
            ea_archive::CHECKPOINTS_DIR_V1
        ),
        bytes,
    );
    hash
}

/// Legt einen `.eds` ab, dessen urspruengliches `.eip` NICHT im Bestand liegt.
///
/// Genau so sieht ein autorisiert vernichteter Eintrag aus: der Stummel traegt
/// das signierte Manifest und die Schreibersignatur weiter, der Klartext ist
/// fort.
fn push_destroyed_stub(fixture: &mut ArchiveFixture, built: &BuiltEntry) -> ObjectHash {
    let original_eip_object_hash = object_hash(&built.bytes);
    let stub = DestroyedEntryStubV1::new(
        built.entry.signed_manifest().clone(),
        built.entry.writer_signature().to_vec(),
        original_eip_object_hash,
        DestructionId::try_from(&[0x43_u8; 16][..])
            .expect("16 Bytes sind eine Vernichtungskennung"),
        ObjectHash::try_from(&[0x44_u8; 32][..]).expect("32 Bytes sind ein Objekthash"),
    )
    .expect("der Fixture-Stummel muss binden");
    let bytes = encode_destroyed_entry_stub(&stub)
        .expect("der Fixture-Stummel muss kodieren")
        .into_vec();
    let hash = object_hash(&bytes);
    fixture.push_exact_bytes(
        &format!(
            "{}{DESTROYED_STUB_SEQUENCE_V1:012}_entry.eds",
            ea_archive::DESTROYED_ENTRIES_DIR_V1
        ),
        bytes,
    );
    hash
}
