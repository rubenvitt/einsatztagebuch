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
    HpkeRecipientPrivateKey, HpkeRecipientPublicKey, SecretBytes, object_hash,
};
use ea_format::{
    CertificateKindV1, CheckpointCoreFieldsV1, CheckpointCoreV1, DeletionAttestationFieldsV1,
    DestroyedEntryStubV1, DestructionAuthorizationFieldsV1, DestructionTargetV1,
    DestructionTransitionFieldsV1, EIP_PREFIX_V1, EntryPackageV1, EvidenceObjectV1,
    GrantBodyFieldsV1, GrantBodyV1, GrantKindV1, GrantPlanItemV1, GrantPlanV1, GrantPurposeV1,
    GrantV1, ManifestCoreFieldsV1, ManifestCoreV1, ReceiptCoreFieldsV1, ReceiptCoreV1, ReceiptV1,
    SignedManifestV1, TrustObjectV1, TrustPayloadV1, encode_destroyed_entry_stub,
    encode_entry_package, encode_evidence, encode_grant, encode_receipt, encode_trust,
};
use ea_trust::{TrustAnchorV1, TrustObjectSource, decode_trust_anchor};
use ea_types::{
    CertificateHash, ChainId, ChainSequence, DestructionId, EntryHash, EventId, Hash32,
    KeyThumbprint, ObjectHash, RegistryVersion, UnixMillis,
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

/// Die Luecke, die JEDES Fixture dieses Moduls traegt AUSSER dem lueckenfreien:
/// der Genesis-Eintrag.
///
/// GEMESSEN, nicht behauptet. `ea_chain::build_chain` zaehlt Sequenzen ab null;
/// ein Bestand, dessen niedrigster Knoten auf Sequenz eins liegt, traegt
/// deshalb die Luecke `0..=0` (`crates/ea-chain/src/chain.rs:769-792`, dort
/// ausdruecklich gepinnt: "das Fehlen des Genesis-Knotens ist ein BEFUND").
///
/// Ein Eintrag auf Sequenz NULL braucht einen Kopf, der die Sequenz null deckt
/// UND unter dem das Schreiberzertifikat schon aktiv ist. Fuenf Linienformen
/// wurden dafuer gemessen, jede mit einem `.eip` auf Sequenz null:
///
/// | Linie                                              | Ergebnis                    |
/// |----------------------------------------------------|-----------------------------|
/// | nur `Device(Writer)`, Lease `0..=100`              | Gate `registry` faellt ganz |
/// | `Device` `0..=0`, dann `Policy` `1..=100`          | Gate `registry` faellt ganz |
/// | `Policy` `0..=0`, dann `Device` `1..=100`          | `unattributable`            |
/// | `Policy` `0..=100`, dann `Device` `0..=100`        | `unattributable`            |
/// | `Policy` `0..=0` VERALTET, dann `Device` `0..=100` | lueckenfrei, zuordenbar     |
///
/// Die ersten vier scheitern strukturell: `verify_registry_candidate` verlangt
/// eine wirksame Policy, ein Registrierungskopf traegt genau EINEN Uebergang,
/// der erste Kopf muss deshalb der Policy-Kopf sein — und dessen
/// Kandidatenstand kennt das Schreiberzertifikat des zweiten Kopfes noch nicht,
/// auch dann nicht, wenn das Zertifikat selbst ab Sequenz null wirksam ist.
/// Deckt der Policy-Kopf die Sequenz null, wird GENAU ER gewaehlt, und unter
/// ihm ist der Schreiber unbekannt.
///
/// Die fuenfte Form loest das: ein Kopf, der zur Uhr des Laufs VERALTET ist,
/// wird nicht gewaehlt, sondern nachgezogen
/// (`crates/ea-trust/src/registry.rs:594` und `:640-647` — `stale` fuehrt zu
/// `Advanced`). Der Schreiberkopf deckt die Sequenz null dann selbst. Genau so
/// ist [`complete_valid_archive`] gebaut, und genau daran haengt, dass ein
/// Bestand ueberhaupt `is_fully_verified()` erreichen kann.
///
/// FUER DIE UEBRIGEN FIXTURES BLEIBT DIE LUECKE WAHR: sie tragen keinen
/// verifizierten Genesis-Eintrag. Genau deshalb setzt der Bericht dort auch nie
/// `anchor.genesis_entry_hash()` ein
/// (`crates/ea-verify/src/report.rs:159-170`). Wer sie "wegrepariert", macht
/// diese Fixtures unwahr; ihre Tests rechnen sie deshalb ausdruecklich mit.
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

/// Ein Registrierungskopf, so wie ein Objekt ihn benennt.
///
/// Version UND Objekthash, weil jedes Manifest, jeder Grant, jede Quittung und
/// jeder Checkpoint beides tragen und beides gebunden wird. Der Typ existiert,
/// damit die Bausteine dieses Moduls sich von IRGENDEINER Linie bedienen
/// lassen und nicht je Linie nachgebaut werden muessen — die Linien
/// unterscheiden sich in ihren Koepfen, nicht in dem, was ein Objekt von einem
/// Kopf wissen muss.
#[derive(Clone, Copy)]
struct HeadRefV1 {
    version: RegistryVersion,
    hash: Hash32,
}

impl HeadRefV1 {
    /// Der Kopf, den `head` bezeichnet.
    fn of(head: &trust_support::BuiltHead) -> Self {
        Self {
            version: head.version,
            hash: Hash32::try_from(head.object_hash.as_bytes().as_slice())
                .expect("ein Objekthash sind 32 Bytes"),
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
    /// Welches `evidence-due-at` tragen die Quittungen?
    ///
    /// `None` ist das Standardprofil (`design.md`:1679): ohne Frist entsteht
    /// keine Evidence-Grade-Konformitaet und Gate `evidence` hat nichts zu
    /// fordern. `Some` macht die Quittung zum FRISTANKER — und nur eine
    /// Quittung, die Gate `receipt` bestanden hat, darf diese Frist ueberhaupt
    /// behaupten.
    pub evidence_due_at: Option<i64>,
}

impl ReceiptArchiveSpec {
    /// Zwei Eintraege, keine Quittung, kein Checkpoint, kein Stummel.
    #[must_use]
    pub const fn bare() -> Self {
        Self {
            receipts: false,
            checkpoint: CheckpointSpec::None,
            destroyed_stub: false,
            evidence_due_at: None,
        }
    }

    /// Derselbe Bestand, dessen Quittungen `evidence-due-at` tragen.
    #[must_use]
    pub const fn with_evidence_due_at(mut self, due_at: i64) -> Self {
        self.evidence_due_at = Some(due_at);
        self
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

    fn head_ref(&self) -> HeadRefV1 {
        HeadRefV1::of(&self.head)
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
                line.head_ref(),
                line.server_certificate_hash,
                recovery_grant_plan_hash(),
                anchor.chain_id(),
                sequence,
                built.entry.entry_hash(),
                entry_object_hashes[index],
                Some(previous),
                spec.evidence_due_at,
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
            line.head_ref(),
            line.server_certificate_hash,
            anchor.chain_id(),
            RECEIPT_FIRST_SEQUENCE_V1,
            CHECKPOINT_TRUNCATED_THROUGH_V1,
            entry_hashes[1],
        )),
        CheckpointSpec::HeadMismatch => Some(push_checkpoint(
            &mut fixture,
            line.head_ref(),
            line.server_certificate_hash,
            anchor.chain_id(),
            RECEIPT_FIRST_SEQUENCE_V1,
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

/// Die drei Sequenzen eines Isolations-Quittungsbestands.
///
/// Sie schliessen unmittelbar an [`RECEIPT_FIRST_SEQUENCE_V1`] an; die
/// Vorlauf-Luecke `0..=1` aus [`RECEIPT_PRE_ENTRY_GAP_THROUGH_V1`] bleibt davon
/// unberuehrt und ist von den Tests ausdruecklich mitzurechnen.
pub const ISOLATION_RECEIPT_SEQUENCES_V1: [u64; 3] = [
    RECEIPT_FIRST_SEQUENCE_V1,
    RECEIPT_FIRST_SEQUENCE_V1 + 1,
    RECEIPT_FIRST_SEQUENCE_V1 + 2,
];

/// Drei Eintraege mit je einer gueltigen Quittung, von denen GENAU EINE eine
/// Evidence-Frist behauptet.
///
/// BEWUSST NEBEN [`receipt_archive`] und nicht als weiterer Schalter darin:
/// sechs Tests haengen an dessen Zwei-Eintrags-Gestalt, und eine dritte Sequenz
/// dort verschoebe deren Kettenkopf. Gebaut wird aus denselben Bausteinen —
/// [`receipt_line`], `build_entry`, `receipt_bytes` —, hier wird nichts
/// nachgebaut.
///
/// Die Frist traegt der mittlere Eintrag ([`ISOLATION_DEFECT_INDEX_V1`]). Die
/// beiden anderen Quittungen bleiben fristlos und damit im Standardprofil
/// (`design.md`:1679): ohne Frist hat Gate `evidence` an ihnen nichts zu
/// fordern.
#[must_use]
pub fn receipt_archive_with_one_deadline(due_at: i64) -> ReceiptArchive {
    let line = receipt_line();
    let anchor = line.anchor();
    let mut fixture = ArchiveFixture::new();
    push_trust_objects(&mut fixture, &line.line);

    let mut previous_entry_hash = anchor.genesis_entry_hash();
    let mut entry_object_hashes = Vec::new();
    let mut entry_hashes = Vec::new();
    let mut receipt_object_hashes = Vec::new();
    let mut built = Vec::new();
    for (index, sequence) in ISOLATION_RECEIPT_SEQUENCES_V1.into_iter().enumerate() {
        let entry = build_entry(&receipt_entry_spec(
            &line,
            anchor.chain_id(),
            sequence,
            Some(previous_entry_hash),
        ));
        let entry_object_hash = object_hash(&entry.bytes);
        let bytes = receipt_bytes(
            line.head_ref(),
            line.server_certificate_hash,
            recovery_grant_plan_hash(),
            anchor.chain_id(),
            sequence,
            entry.entry.entry_hash(),
            entry_object_hash,
            Some(previous_entry_hash),
            (index == ISOLATION_DEFECT_INDEX_V1).then_some(due_at),
        );
        receipt_object_hashes.push(object_hash(&bytes));
        fixture.push_exact_bytes(
            &format!("{}{sequence:012}_receipt.esr", ea_archive::RECEIPTS_DIR_V1),
            bytes,
        );
        entry_object_hashes.push(entry_object_hash);
        entry_hashes.push(entry.entry.entry_hash());
        previous_entry_hash = entry.entry.entry_hash();
        built.push((sequence, entry));
    }
    for (sequence, entry) in built {
        push_entry(&mut fixture, sequence, entry);
    }

    ReceiptArchive {
        fixture,
        anchor_bytes: line.anchor_bytes,
        entry_object_hashes,
        entry_hashes,
        receipt_object_hashes,
        checkpoint_object_hash: None,
        destroyed_stub_object_hash: None,
    }
}

/// Das Sequenzfach im PFADHINWEIS der gefaelschten `.esr`.
///
/// Frei waehlbar und ausdruecklich ohne Aussage: Pfade klassifizieren im
/// Bestand nichts. Es ist nur ein anderer Hinweis als der der echten Quittung,
/// damit beide Objekte nebeneinander liegen.
const RECEIPT_FORGED_SEQUENCE_V1: u64 = 900;

/// Ein Quittungsbestand samt dem Objekthash der Faelschung, die in ihm liegt.
pub struct ForgedReceiptArchive {
    pub archive: ReceiptArchive,
    pub forged_receipt_object_hash: ObjectHash,
}

/// Derselbe Zwei-Eintrags-Bestand mit Quittungen, dem eine ZWEITE Quittung auf
/// den ERSTEN Eintrag untergeschoben wurde — auf denselben
/// `entryObjectHash`, mit KLEINEREM Objekthash.
///
/// # Warum der Objekthash kleiner sein MUSS
///
/// `inventory.receipts()` entsteht aus einer `BTreeMap` ueber dem Objekthash
/// und ist damit aufsteigend geordnet; `receipt_for` nimmt mit `find` den
/// ERSTEN Treffer. Nur ein kleinerer Hash verdraengt die echte Quittung.
/// Gemahlen wird ueber `acceptedAtServer` — ein Feld, das der Faelscher frei
/// waehlt und das an keiner der fuenf Bindungen aus `design.md` §14.1
/// Schritt 7 haengt.
///
/// # Was die Faelschung NICHT kann
///
/// Ihr `entryHash` ist ein fremder ([`foreign_head_entry_hash`]), also faellt
/// sie an der ERSTEN Bindung und noch vor jeder Kryptografie
/// (`crates/ea-verify/src/archive.rs:726`). Genau so sieht die erreichbare
/// Faelschung aus: `validate_server_signature`
/// (`crates/ea-format/src/esr.rs:198-208`) haelt Inhaltstyp, Abdruck,
/// Zertifikatshash und Digest gegen die Felder DESSELBEN Kerns; der
/// kryptografische Beweis sitzt in `verify_cose_sign1` und laeuft auf dem
/// Einlesepfad nie. Diese Fixture benutzt trotzdem den echten
/// Fixture-Signierer — nicht, weil sie muesste, sondern weil ein Angreifer
/// ohne Schluessel exakt dasselbe Objekt bauen kann und der Unterschied fuer
/// die AUSWAHL keiner ist.
///
/// # Beide Quittungen sind danach isoliert
///
/// `receipt_conflicts` (`crates/ea-archive/src/inventory.rs:518-537`)
/// gruppiert ueber `entryObjectHash` und isoliert JEDES Mitglied einer Gruppe
/// mit mehr als einem Objekt — die echte Quittung also mit. Der zweite Eintrag
/// des Bestands bleibt davon unberuehrt und behaelt seine Bestaetigung; er ist
/// die Kontrolle dieses Zeugen.
#[must_use]
pub fn receipt_archive_with_a_forged_second_receipt() -> ForgedReceiptArchive {
    let mut archive = receipt_archive(ReceiptArchiveSpec::bare().with_receipts());
    let line = receipt_line();
    let anchor = line.anchor();
    let genuine = archive.receipt_object_hashes[0];
    assert!(
        object_hash(&receipt_bytes(
            line.head_ref(),
            line.server_certificate_hash,
            recovery_grant_plan_hash(),
            anchor.chain_id(),
            RECEIPT_FIRST_SEQUENCE_V1,
            archive.entry_hashes[0],
            archive.entry_object_hashes[0],
            Some(anchor.genesis_entry_hash()),
            None,
        )) == genuine,
        "die Fixture-Quittungslinie ist nicht mehr deterministisch"
    );

    let forged = forged_receipt_bytes(
        line.head_ref(),
        line.server_certificate_hash,
        anchor.chain_id(),
        archive.entry_object_hashes[0],
        anchor.genesis_entry_hash(),
        genuine,
    );
    let forged_receipt_object_hash = object_hash(&forged);
    assert!(
        forged_receipt_object_hash < genuine,
        "die untergeschobene Quittung muss die echte verdraengen koennen"
    );
    archive.fixture.push_exact_bytes(
        &format!(
            "{}{RECEIPT_FORGED_SEQUENCE_V1:012}_receipt.esr",
            ea_archive::RECEIPTS_DIR_V1
        ),
        forged,
    );
    ForgedReceiptArchive {
        archive,
        forged_receipt_object_hash,
    }
}

/// Mahlt eine Quittung auf `entry_object_hash`, deren Objekthash unter `below`
/// liegt und deren `entryHash` ein fremder ist.
fn forged_receipt_bytes(
    head: HeadRefV1,
    server_certificate_hash: CertificateHash,
    chain_id: ChainId,
    entry_object_hash: ObjectHash,
    previous_entry_hash: EntryHash,
    below: ObjectHash,
) -> Vec<u8> {
    for attempt in 0..4096_i64 {
        let core = ReceiptCoreV1::new(ReceiptCoreFieldsV1 {
            organization_id: trust_support::organization(),
            chain_id,
            chain_sequence: ChainSequence::new(RECEIPT_FIRST_SEQUENCE_V1),
            entry_hash: foreign_head_entry_hash(),
            entry_object_hash,
            previous_entry_hash: Some(previous_entry_hash),
            registry_version: head.version,
            registry_head_hash: head.hash,
            policy_object_hash: fixture_policy_object_hash(),
            initial_grant_plan_hash: recovery_grant_plan_hash(),
            initial_grant_object_hashes: vec![fixture_grant_object_hash()],
            accepted_at_server: UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1 + attempt),
            evidence_due_at: None,
            server_key_thumbprint: writer_device_key_thumbprint(),
            server_certificate_hash,
        })
        .expect("der gefaelschte Quittungskern muss kodieren");
        let signature = writer_device_signer()
            .sign_receipt(core.exact_bytes())
            .expect("der Fixture-Server muss signieren");
        let receipt =
            ReceiptV1::new(core, signature).expect("die gefaelschte Quittung muss binden");
        let bytes = encode_receipt(&receipt)
            .expect("die gefaelschte Quittung muss kodieren")
            .into_vec();
        if object_hash(&bytes) < below {
            return bytes;
        }
    }
    panic!("kein Objekthash unter der echten Quittung gefunden");
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
#[allow(clippy::too_many_arguments)]
fn receipt_bytes(
    head: HeadRefV1,
    server_certificate_hash: CertificateHash,
    initial_grant_plan_hash: Hash32,
    chain_id: ChainId,
    chain_sequence: u64,
    entry_hash: EntryHash,
    entry_object_hash: ObjectHash,
    previous_entry_hash: Option<EntryHash>,
    evidence_due_at: Option<i64>,
) -> Vec<u8> {
    let core = ReceiptCoreV1::new(ReceiptCoreFieldsV1 {
        organization_id: trust_support::organization(),
        chain_id,
        chain_sequence: ChainSequence::new(chain_sequence),
        entry_hash,
        entry_object_hash,
        previous_entry_hash,
        registry_version: head.version,
        registry_head_hash: head.hash,
        policy_object_hash: fixture_policy_object_hash(),
        initial_grant_plan_hash,
        initial_grant_object_hashes: vec![fixture_grant_object_hash()],
        accepted_at_server: UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1),
        evidence_due_at: evidence_due_at.map(UnixMillis::new),
        server_key_thumbprint: writer_device_key_thumbprint(),
        server_certificate_hash,
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
#[allow(clippy::too_many_arguments)]
fn push_checkpoint(
    fixture: &mut ArchiveFixture,
    head: HeadRefV1,
    server_certificate_hash: CertificateHash,
    chain_id: ChainId,
    covered_from_sequence: u64,
    covered_through_sequence: u64,
    head_entry_hash: EntryHash,
) -> ObjectHash {
    let core = CheckpointCoreV1::new(CheckpointCoreFieldsV1 {
        organization_id: trust_support::organization(),
        chain_id,
        covered_from_sequence: ChainSequence::new(covered_from_sequence),
        covered_through_sequence: ChainSequence::new(covered_through_sequence),
        head_entry_hash,
        registry_head_hash: head.hash,
        issued_at_server: UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1),
        previous_evidence_hash: None,
    })
    .expect("der Fixture-Checkpointkern muss kodieren");
    let signature = writer_device_signer()
        .sign_checkpoint(server_certificate_hash, core.exact_bytes())
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
    push_destroyed_stub_for(
        fixture,
        DESTROYED_STUB_SEQUENCE_V1,
        &built.entry,
        object_hash(&built.bytes),
    )
}

/// Das Fuellbyte der Vorgangskennung eines Stummels, dessen Vernichtung im
/// Bestand auf NICHTS zeigt.
///
/// Der Wert ist bewusst KEIN Marker eines abgelegten Vorgangs: `push_destruction`
/// leitet seine [`DestructionId`] aus `DestructionSpec::marker` ab, und solange
/// kein Vorgang mit diesem Marker im Bestand liegt, laeuft der Join
/// `DestroyedEntryStubV1::destruction_id()` gegen `authorizedDestructions` ins
/// Leere. Genau das ist der Ausgang `ungeklaerte Luecke`.
pub const UNRESOLVABLE_STUB_DESTRUCTION_MARKER_V1: u8 = 0x43;
/// Das Fuellbyte des Autorisierungshashes desselben Stummels.
///
/// Getrennt vom Kennungsmarker, weil `ea-format` beide Felder getrennt bindet
/// und ein einziges Fuellbyte fuer zwei Rollen die Verwechslung erst moeglich
/// machte, die dieser Stummel ausschliessen soll.
pub const UNRESOLVABLE_STUB_AUTHORIZATION_MARKER_V1: u8 = 0x44;

/// Dasselbe fuer ein beliebiges Eintragspaket auf einer beliebigen Sequenz.
///
/// `original_eip_object_hash` kommt als PARAMETER und wird nicht aus dem Paket
/// hergeleitet: der Stummel bezeugt die Bytes, die ABGELEGT waren, und die
/// kennt nur der Erbauer des Bestands.
///
/// Die Vernichtung, auf die dieser Stummel zeigt, liegt NICHT im Bestand — der
/// aufloesbare Gegenfall laeuft ueber [`push_destroyed_stub_authorized_by`].
fn push_destroyed_stub_for(
    fixture: &mut ArchiveFixture,
    chain_sequence: u64,
    entry: &EntryPackageV1,
    original_eip_object_hash: ObjectHash,
) -> ObjectHash {
    push_destroyed_stub_authorized_by(
        fixture,
        chain_sequence,
        entry,
        original_eip_object_hash,
        DestructionId::try_from(&[UNRESOLVABLE_STUB_DESTRUCTION_MARKER_V1; 16][..])
            .expect("16 Bytes sind eine Vernichtungskennung"),
        ObjectHash::try_from(&[UNRESOLVABLE_STUB_AUTHORIZATION_MARKER_V1; 32][..])
            .expect("32 Bytes sind ein Objekthash"),
    )
}

/// Derselbe Stummel unter einer BENANNTEN Vernichtung.
///
/// Die zwei Felder, die den Stummel mit einem Vorgang verbinden, kommen als
/// Parameter, weil nur der Erbauer des Bestands weiss, ob der Vorgang darin
/// ueberhaupt liegt. Ein `.eds` wird nie ein Kettenknoten (siehe den
/// Kommentarblock vor `protocol.enter(Gate::ChainPosition)`), und `ea-verify`
/// prueft die beiden Felder an keiner Stelle — sie tragen allein den Join, den
/// ein Leser ueber `authorizedDestructions` selbst zieht. Genau deshalb sind
/// BEIDE Ausgaenge nur ueber diesen Parameter erreichbar.
fn push_destroyed_stub_authorized_by(
    fixture: &mut ArchiveFixture,
    chain_sequence: u64,
    entry: &EntryPackageV1,
    original_eip_object_hash: ObjectHash,
    destruction_id: DestructionId,
    destruction_authorization_object_hash: ObjectHash,
) -> ObjectHash {
    let stub = DestroyedEntryStubV1::new(
        entry.signed_manifest().clone(),
        entry.writer_signature().to_vec(),
        original_eip_object_hash,
        destruction_id,
        destruction_authorization_object_hash,
    )
    .expect("der Fixture-Stummel muss binden");
    let bytes = encode_destroyed_entry_stub(&stub)
        .expect("der Fixture-Stummel muss kodieren")
        .into_vec();
    let hash = object_hash(&bytes);
    fixture.push_exact_bytes(
        &format!(
            "{}{chain_sequence:012}_entry.eds",
            ea_archive::DESTROYED_ENTRIES_DIR_V1
        ),
        bytes,
    );
    hash
}

// ---------------------------------------------------------------------------
// Der lueckenfreie Bestand fuer die Gates `evidence`, `recipient-grant` und
// die Entkapselung dahinter.
// ---------------------------------------------------------------------------

/// Das `not-after` des Policy-Kopfes der lueckenfreien Linie.
///
/// KLEINER ALS [`FIXTURE_OS_WALL_CLOCK_V1`], und genau darin liegt der Trick.
/// `select_registry_head` liefert fuer einen Kopf, der zur Uhr des Laufs
/// VERALTET ist, `Advanced` statt `Selected`
/// (`crates/ea-trust/src/registry.rs:594` und `:640-647`). Der Policy-Kopf
/// tritt damit zur Seite, und der Schreiberkopf deckt die Sequenz NULL — was
/// der Genesis-Eintrag braucht, ohne den kein Bestand je lueckenfrei ist
/// (`crates/ea-chain/src/chain.rs:769-792` zaehlt Sequenzen ab null).
///
/// Das ist keine Umgehung, sondern der Regelfall des Aufholens: ein
/// abgeloester Kopf ist nicht mehr die Autoritaet, und die Linie wird
/// vorwaerts nachgezogen. Gemessen ist beides — mit `not-after` oberhalb der
/// Uhr wird derselbe Eintrag `unattributable`, siehe die Tabelle an
/// [`GENESIS_GAP_SEQUENCE_V1`].
pub const COMPLETE_POLICY_NOT_AFTER_V1: i64 = 500;

/// Die Lease des Schreiberkopfes der lueckenfreien Linie.
pub const COMPLETE_WRITER_LEASE_FROM_V1: u64 = 0;
/// Letzte Sequenz dieser Lease.
pub const COMPLETE_WRITER_LEASE_THROUGH_V1: u64 = 100;
/// Die Sequenz des Genesis-Eintrags des lueckenfreien Bestands.
pub const COMPLETE_GENESIS_SEQUENCE_V1: u64 = 0;

/// Der private X25519-Schluessel des Empfaengers, den die Fixtures BESITZEN.
///
/// Echtes Schluesselmaterial und kein Fuellwert: ohne den passenden privaten
/// Schluessel gibt es keine Entkapselung, und ohne Entkapselung liesse sich
/// `hpke-open` nur behaupten statt messen.
const COMPLETE_RECIPIENT_SECRET_V1: [u8; 32] = [
    0x4c, 0x2b, 0x1f, 0x90, 0x77, 0xd3, 0x0a, 0x65, 0xb8, 0x11, 0xe4, 0x39, 0x5d, 0xa7, 0xc0, 0x62,
    0x8e, 0x14, 0x73, 0xbb, 0x2f, 0x96, 0x51, 0xcd, 0x08, 0xaf, 0x36, 0x7a, 0xd2, 0x45, 0x19, 0x83,
];

/// Ein ZWEITER privater Schluessel: ein anderer Empfaenger, ein falscher
/// Schluessel.
const OTHER_RECIPIENT_SECRET_V1: [u8; 32] = [
    0x91, 0x7d, 0x35, 0xe2, 0x4a, 0x08, 0xc6, 0x13, 0x2f, 0xba, 0x59, 0x87, 0x60, 0xd1, 0x3c, 0xe8,
    0x05, 0x72, 0xab, 0x46, 0x1e, 0xf3, 0x88, 0x2a, 0x64, 0x9b, 0xd7, 0x50, 0x11, 0xcc, 0x27, 0x6f,
];

/// Der Inhaltsschluessel eines Eintrags, den sein Grant umschliesst.
///
/// JE SEQUENZ EIN EIGENER, und das ist keine Kosmetik: ein zweiter Eintrag
/// unter demselben Paar aus Schluessel und `nonce` waere eine
/// Nonce-Wiederverwendung und damit ein echter Bruch der AEAD-Annahme. Eine
/// Fixture, die so etwas vormacht, lehrt das Falsche.
fn complete_cek(chain_sequence: u64) -> [u8; 32] {
    let mut cek = [0x3c_u8; 32];
    cek[0] ^= u8::try_from(chain_sequence & 0xff).expect("ein Byte");
    cek
}

/// Die `nonce` des Manifests und damit die des AEAD, je Sequenz eine eigene.
fn complete_nonce(chain_sequence: u64) -> [u8; 12] {
    let mut nonce = [0x5e_u8; 12];
    nonce[0] ^= u8::try_from(chain_sequence & 0xff).expect("ein Byte");
    nonce
}

/// Der Klartext hinter dem Ciphertext des lueckenfreien Eintrags.
///
/// Beliebige Bytes: kein Gate liest ihn, und der Bericht enthaelt ihn NIE.
/// Er ist ausschliesslich da, damit die Entschluesselung etwas zu pruefen hat.
/// Oeffentlich, weil ein Leser ihn nach der Entkapselung gegen KEINE der
/// fuenf Schemabestimmungen bringt und ein Zeuge das an genau diesen Bytes
/// festmacht.
pub const COMPLETE_PLAINTEXT_V1: &[u8] = b"einsatzarchiv-fixture-payload";

/// Der private Empfaengerschluessel, fuer den der Grant gebaut ist.
#[must_use]
pub fn complete_recipient_private_key() -> HpkeRecipientPrivateKey {
    HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(COMPLETE_RECIPIENT_SECRET_V1))
        .expect("der Fixture-Empfaengerschluessel muss ein X25519-Schluessel sein")
}

/// Ein anderer privater Schluessel — der FALSCHE zu diesem Grant.
#[must_use]
pub fn other_recipient_private_key() -> HpkeRecipientPrivateKey {
    HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(OTHER_RECIPIENT_SECRET_V1))
        .expect("der zweite Fixture-Empfaengerschluessel muss ein X25519-Schluessel sein")
}

/// Die ROHEN 32 Bytes von [`complete_recipient_private_key`].
///
/// # Warum das Material selbst herausgeht
///
/// `decrypt` nimmt seinen Empfaengerschluessel als DATEI entgegen, und ein Test
/// dieses Pfades muss diese Datei schreiben koennen.
/// [`ea_crypto::HpkeRecipientPrivateKey`] gibt sein Material bewusst nicht mehr
/// heraus — richtig so —, weshalb die Bytes hier aus derselben Konstante
/// stammen, aus der auch der Schluessel gebaut wird. Ein zweites Literal
/// anderswo im Workspace koennte auseinanderlaufen, ohne dass ein Test es
/// saehe.
#[must_use]
pub const fn complete_recipient_secret_bytes() -> [u8; 32] {
    COMPLETE_RECIPIENT_SECRET_V1
}

/// Die rohen 32 Bytes des ZWEITEN, falschen Schluessels.
#[must_use]
pub const fn other_recipient_secret_bytes() -> [u8; 32] {
    OTHER_RECIPIENT_SECRET_V1
}

/// Der Abdruck des Schluessels aus [`complete_recipient_private_key`].
#[must_use]
pub fn complete_recipient_key_thumbprint() -> KeyThumbprint {
    key_thumbprint_of(&complete_recipient_private_key())
}

/// Der Abdruck des zweiten Schluessels.
#[must_use]
pub fn other_recipient_key_thumbprint() -> KeyThumbprint {
    key_thumbprint_of(&other_recipient_private_key())
}

fn key_thumbprint_of(key: &HpkeRecipientPrivateKey) -> KeyThumbprint {
    CanonicalPublicCoseKey::x25519(*key.public_key().as_bytes())
        .expect("ein X25519-Punkt muss ein COSE-Schluessel sein")
        .thumbprint()
}

/// Das Zertifikat des Empfaengers des lueckenfreien Bestands.
///
/// Ein Fuellwert, und das ist gemessen und nicht bequem: Gate
/// `recipient-grant` loest den AUSSTELLER auf, nie den Empfaenger — der
/// Empfaenger weist sich durch den Besitz seines privaten Schluessels aus.
#[must_use]
pub fn complete_recipient_certificate_hash() -> CertificateHash {
    CertificateHash::try_from(&[0x41_u8; 32][..]).expect("32 Bytes sind ein Zertifikatshash")
}

/// Das Zertifikat des zweiten Empfaengers.
#[must_use]
pub fn other_recipient_certificate_hash() -> CertificateHash {
    CertificateHash::try_from(&[0x42_u8; 32][..]).expect("32 Bytes sind ein Zertifikatshash")
}

/// Der Planhash des lueckenfreien Bestands: GENAU EIN Recovery-Grant an
/// `recipient`.
fn complete_grant_plan_hash(
    recipient_key_thumbprint: KeyThumbprint,
    recipient_certificate_hash: CertificateHash,
) -> Hash32 {
    GrantPlanV1::new(vec![GrantPlanItemV1::new(
        recipient_key_thumbprint,
        recipient_certificate_hash,
        GrantPurposeV1::Recovery,
    )])
    .expect("ein Plan mit genau einem Recovery-Grant muss entstehen")
    .hash()
}

/// Die exakten Bytes des `grant-context-v1` aus einem `grant-body-v1`.
///
/// UNABHAENGIG von der Fassung in `ea-verify` gebaut: dort wird der Kontext
/// ueber die bekannten Laengen der beiden letzten Glieder herausgeschnitten,
/// hier ueber den CBOR-Dekoder. Zwei verschiedene Wege auf dieselben Bytes —
/// stimmten sie nicht ueberein, waere `hpke_info`/`hpke_aad` falsch gebildet
/// und die Entkapselung schluege fehl, ohne dass ein Test sagte warum.
fn exact_grant_context(exact_grant_body: &[u8]) -> Vec<u8> {
    let mut decoder = minicbor::Decoder::new(exact_grant_body);
    assert_eq!(
        decoder.array().expect("der Grantrumpf ist ein CBOR-Array"),
        Some(3),
        "grant-body-v1 hat genau drei Glieder"
    );
    let start = decoder.position();
    decoder
        .skip()
        .expect("der Kontext muss ueberspringbar sein");
    exact_grant_body[start..decoder.position()].to_vec()
}

/// Ein Bestand OHNE Luecke, mit echtem Ciphertext und echten Grants.
pub struct CompleteArchive {
    pub fixture: ArchiveFixture,
    pub anchor_bytes: Vec<u8>,
    /// Objekthashes der abgelegten `.eip`, in Sequenzreihenfolge.
    pub entry_object_hashes: Vec<ObjectHash>,
    /// Objekthashes der abgelegten `.eag`, in derselben Reihenfolge.
    pub grant_object_hashes: Vec<ObjectHash>,
}

impl CompleteArchive {
    #[must_use]
    pub fn anchor(&self) -> TrustAnchorV1 {
        decode_trust_anchor(&self.anchor_bytes).expect("der Fixture-Anker muss dekodieren")
    }

    /// Der Objekthash des Genesis-Eintrags.
    #[must_use]
    pub fn entry_object_hash(&self) -> ObjectHash {
        self.entry_object_hashes[0]
    }

    /// Der Objekthash des Grants auf den Genesis-Eintrag.
    #[must_use]
    pub fn grant_object_hash(&self) -> ObjectHash {
        self.grant_object_hashes[0]
    }
}

/// Die lueckenfreie Linie: veralteter Policy-Kopf, dann der Schreiberkopf ab
/// Sequenz null.
struct CompleteLine {
    line: trust_support::RegistryLineBuilder,
    head: trust_support::BuiltHead,
    writer_certificate_hash: CertificateHash,
    anchor_bytes: Vec<u8>,
}

impl CompleteLine {
    fn anchor(&self) -> TrustAnchorV1 {
        decode_trust_anchor(&self.anchor_bytes).expect("der Fixture-Anker muss dekodieren")
    }

    fn head_ref(&self) -> HeadRefV1 {
        HeadRefV1::of(&self.head)
    }
}

fn complete_line() -> CompleteLine {
    let mut line = trust_support::RegistryLineBuilder::new();
    line.push(
        policy_action(),
        trust_support::HeadOptions {
            effective_from: Some(POLICY_LEASE_FROM_V1),
            valid_through: Some(POLICY_LEASE_THROUGH_V1),
            not_after: UnixMillis::new(COMPLETE_POLICY_NOT_AFTER_V1),
            ..trust_support::HeadOptions::default()
        },
    );
    let head = line.push(
        trust_support::ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x11,
            effective_from: Some(COMPLETE_WRITER_LEASE_FROM_V1),
        },
        trust_support::HeadOptions {
            effective_from: Some(COMPLETE_WRITER_LEASE_FROM_V1),
            valid_through: Some(COMPLETE_WRITER_LEASE_THROUGH_V1),
            ..trust_support::HeadOptions::default()
        },
    );
    let writer_certificate_hash = CertificateHash::from(
        head.direct_object_hash
            .expect("ein Device-Uebergang traegt ein direktes Ziel"),
    );
    let anchor_bytes = line.exact_anchor_bytes().to_vec();
    CompleteLine {
        line,
        head,
        writer_certificate_hash,
        anchor_bytes,
    }
}

/// Ein lueckenloser Bestand mit GENAU EINEM Eintrag, dessen Recovery-Grant an
/// [`complete_recipient_key_thumbprint`] geht.
#[must_use]
pub fn complete_valid_archive() -> CompleteArchive {
    complete_valid_archive_with_plaintext(COMPLETE_PLAINTEXT_V1)
}

/// Derselbe Bestand ueber einem GEWAEHLTEN Klartext.
///
/// Fuer den einen Zeugen, der den Klartext nach der Entkapselung auch LIEST
/// und dafuer eine der fuenf Schemabestimmungen treffen muss; alle uebrigen
/// Bestaende tragen [`COMPLETE_PLAINTEXT_V1`], und die Mutationsfixtures mit
/// festen Byteversaetzen haengen an DESSEN Laenge — ein schemagueltiger
/// Klartext gehoert dort nie hinein.
#[must_use]
pub fn complete_valid_archive_with_plaintext(plaintext: &[u8]) -> CompleteArchive {
    complete_archive_for(
        complete_recipient_key_thumbprint(),
        complete_recipient_certificate_hash(),
        &complete_recipient_private_key().public_key(),
        1,
        plaintext,
    )
}

/// Derselbe Bestand mit ZWEI verketteten Eintraegen und je einem Grant.
///
/// Misst, was ein einzelner Eintrag nicht messen kann: dass Gate
/// `recipient-grant` seinen Kopf je Eintrag erneut gewinnt, dass zwei Grants
/// unabhaengig geprueft und geoeffnet werden, und dass zwei Entkapselungen
/// trotzdem GENAU EIN `hpke-open` melden — das Ereignis benennt den Schritt der
/// Pipeline, nicht die Zahl der geoeffneten Objekte.
#[must_use]
pub fn complete_valid_archive_with_two_entries() -> CompleteArchive {
    complete_archive_for(
        complete_recipient_key_thumbprint(),
        complete_recipient_certificate_hash(),
        &complete_recipient_private_key().public_key(),
        2,
        COMPLETE_PLAINTEXT_V1,
    )
}

/// Derselbe Bestand, dessen einziger Grant an einen ANDEREN Empfaenger geht.
///
/// Der Plan bleibt vollstaendig — ein Recovery-Grant ist da —, nur ist es
/// nicht der eigene. Genau der Zustand FEHLENDER GRANT aus `design.md`:1595.
#[must_use]
pub fn archive_without_the_own_grant() -> CompleteArchive {
    complete_archive_for(
        other_recipient_key_thumbprint(),
        other_recipient_certificate_hash(),
        &other_recipient_private_key().public_key(),
        1,
        COMPLETE_PLAINTEXT_V1,
    )
}

/// Derselbe Bestand, dem ein GEFAELSCHTER historischer Grant untergeschoben
/// wurde — auf denselben `entryHash`, an denselben Empfaenger, mit KLEINEREM
/// Objekthash.
///
/// # Warum das ohne jedes Schluesselmaterial geht
///
/// Der Einlesepfad einer `.eag` prueft die Ausstellersignatur nur auf FORM:
/// `validate_issuer_signature` (`crates/ea-format/src/eag.rs:324-337`) haelt
/// Inhaltstyp, Abdruck, Zertifikatshash und Digest gegen die Felder DESSELBEN
/// Rumpfes; der kryptografische Beweis sitzt in
/// `CoseSign1::verify_with_key` (`crates/ea-crypto/src/cose.rs:653-669`) und
/// laeuft hier nie. Diese Fixture benutzt trotzdem den echten Fixture-Signierer
/// — nicht, weil sie muesste, sondern weil ein Angreifer ohne Schluessel exakt
/// dasselbe Objekt bauen kann und der Unterschied fuer die AUSWAHL keiner ist.
///
/// # Warum der Objekthash kleiner sein MUSS
///
/// `inventory.grants()` entsteht aus einer `BTreeMap` ueber dem Objekthash
/// (`crates/ea-archive/src/inventory.rs:600`) und ist damit aufsteigend
/// geordnet; `own_grant` nimmt mit `find` den ERSTEN Treffer. Nur ein
/// kleinerer Hash verdraengt den echten Grant. Gemahlen wird ueber
/// `created_at_device` — ein Feld, das der Faelscher frei waehlt.
#[must_use]
pub fn complete_archive_with_a_forged_historical_grant() -> ForgedHistoricalGrantArchive {
    let mut archive = complete_valid_archive();
    let line = complete_line();
    let anchor = line.anchor();
    let entry = build_complete_entry(
        line.head_ref(),
        line.writer_certificate_hash,
        anchor.chain_id(),
        complete_grant_plan_hash(
            complete_recipient_key_thumbprint(),
            complete_recipient_certificate_hash(),
        ),
        COMPLETE_GENESIS_SEQUENCE_V1,
        None,
        COMPLETE_PLAINTEXT_V1,
    );
    assert!(
        object_hash(
            &encode_entry_package(&entry)
                .expect("das Fixture-Eintragspaket muss kodieren")
                .into_vec()
        ) == archive.entry_object_hash(),
        "die Fixture-Kette ist nicht mehr deterministisch"
    );

    let genuine = archive.grant_object_hash();
    let forged = forged_historical_grant_bytes(
        line.head_ref(),
        line.writer_certificate_hash,
        anchor.chain_id(),
        entry.entry_hash(),
        genuine,
    );
    let forged_grant_object_hash = object_hash(&forged);
    assert!(
        forged_grant_object_hash < genuine,
        "der untergeschobene Grant muss den echten verdraengen koennen"
    );
    push_grant(
        &mut archive.fixture,
        COMPLETE_FORGED_GRANT_SEQUENCE_V1,
        forged,
    );
    ForgedHistoricalGrantArchive {
        archive,
        forged_grant_object_hash,
    }
}

/// Das Sequenzfach im PFADHINWEIS der gefaelschten `.eag`.
///
/// Frei waehlbar und ausdruecklich ohne Aussage: Pfade klassifizieren im
/// Bestand nichts. Es ist nur ein anderer Hinweis als der des echten Grants,
/// damit beide Objekte nebeneinander liegen.
const COMPLETE_FORGED_GRANT_SEQUENCE_V1: u64 = 900;

/// Ein Bestand samt dem Objekthash der Faelschung, die in ihm liegt.
pub struct ForgedHistoricalGrantArchive {
    pub archive: CompleteArchive,
    pub forged_grant_object_hash: ObjectHash,
}

/// Mahlt einen historischen Grant, dessen Objekthash unter `below` liegt.
///
/// `GrantKindV1::Historical` verlangt nach
/// `validate_grant_field_correlations` (`crates/ea-format/src/eag.rs:418-434`)
/// genau dreierlei: `GrantPurposeV1::Reader` und zwei gesetzte Objekthashes.
/// Alle drei sind frei waehlbar, und keiner davon wird in diesem Lauf gegen
/// irgendetwas gehalten.
fn forged_historical_grant_bytes(
    head: HeadRefV1,
    writer_certificate_hash: CertificateHash,
    chain_id: ChainId,
    entry_hash: EntryHash,
    below: ObjectHash,
) -> Vec<u8> {
    for attempt in 0..4096_i64 {
        let body = GrantBodyV1::new(GrantBodyFieldsV1 {
            organization_id: trust_support::organization(),
            chain_id,
            entry_hash,
            kind: GrantKindV1::Historical,
            purpose: GrantPurposeV1::Reader,
            recipient_key_thumbprint: complete_recipient_key_thumbprint(),
            recipient_certificate_hash: complete_recipient_certificate_hash(),
            issuer_key_thumbprint: writer_device_key_thumbprint(),
            issuer_certificate_hash: writer_certificate_hash,
            registry_version: head.version,
            registry_head_hash: head.hash,
            created_at_device: UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1 + attempt),
            original_recovery_grant_object_hash: Some(below),
            grant_authorization_object_hash: Some(below),
            encapsulated_key: [0x5a; HPKE_ENCAPSULATED_KEY_SIZE],
            wrapped_cek: [0x5a; HPKE_WRAPPED_CEK_SIZE],
        })
        .expect("der gefaelschte Grantrumpf muss kodieren");
        let signature = writer_device_signer()
            .sign_historical_grant(body.exact_bytes())
            .expect("der Fixture-Aussteller muss signieren");
        let grant = GrantV1::new(body, signature).expect("der gefaelschte Grant muss binden");
        let bytes = encode_grant(&grant)
            .expect("der gefaelschte Grant muss kodieren")
            .into_vec();
        if object_hash(&bytes) < below {
            return bytes;
        }
    }
    panic!("kein Objekthash unter dem echten Grant gefunden");
}

fn complete_archive_for(
    recipient_key_thumbprint: KeyThumbprint,
    recipient_certificate_hash: CertificateHash,
    recipient_public_key: &HpkeRecipientPublicKey,
    entry_count: u64,
    plaintext: &[u8],
) -> CompleteArchive {
    complete_archive_with(
        recipient_key_thumbprint,
        recipient_certificate_hash,
        recipient_public_key,
        entry_count,
        IsolationDefectV1::None,
        plaintext,
    )
}

/// Der Defekt, den GENAU EIN Objekt eines Isolationsbestands traegt.
///
/// EINER JE BESTAND, und stets auf dem MITTLEREN Eintrag. Ein zweiter Defekt
/// machte nicht mehr unterscheidbar, welches Objekt welchen Befund traegt; der
/// mittlere und nicht der letzte, weil ein Defekt am oberen Rand von einem
/// schlicht kuerzeren Bestand nicht zu unterscheiden waere — dieselbe
/// Ueberlegung wie bei [`UNKNOWN_WRITER_SEQUENCE_V1`], nur andersherum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolationDefectV1 {
    /// Keiner: drei unversehrte, verkettete Eintraege.
    None,
    /// Die Schreibersignatur des mittleren Eintrags traegt ein verkipptes Byte.
    ///
    /// Trifft Gate `manifest-signature` und nicht Gate `format`: die Signatur
    /// wird beim Parsen nicht kryptografisch geprueft.
    MutatedWriterSignature,
    /// Der Grant des mittleren Eintrags ist auf einen FREMDEN Schluessel
    /// gekapselt.
    ///
    /// Der Grant nennt weiterhin den EIGENEN Abdruck und dasselbe Zertifikat —
    /// beides geht in den Planhash ein, und ein anderer Empfaenger im Grant
    /// faellte bereits an Gate `grant-plan`. Gescheitert wird ausschliesslich in
    /// der Entkapselung: `hpke_open` bekommt eine Kapselung, die nicht fuer den
    /// vorgelegten privaten Schluessel gebildet wurde. Der Ciphertext bleibt
    /// ausdruecklich unangetastet — eine Mutation dort faellt schon an Gate
    /// `manifest-signature`, weil der Ciphertexthash im signierten Manifest
    /// steht.
    ForeignEncapsulation,
    /// Der mittlere Eintrag liegt ZWEIMAL im Bestand, unter zwei Pfadhinweisen.
    DuplicateEntry,
}

/// Zahl der Eintraege eines Isolationsbestands.
pub const ISOLATION_ENTRY_COUNT_V1: u64 = 3;

/// Der Index des Eintrags, der den Defekt traegt.
pub const ISOLATION_DEFECT_INDEX_V1: usize = 1;

/// Die Sequenz dieses Eintrags in der lueckenfreien Linie.
pub const ISOLATION_DEFECT_SEQUENCE_V1: u64 =
    COMPLETE_GENESIS_SEQUENCE_V1 + ISOLATION_DEFECT_INDEX_V1 as u64;

/// Drei verkettete Eintraege, von denen hoechstens EINER `defect` traegt.
#[must_use]
pub fn isolation_archive(defect: IsolationDefectV1) -> CompleteArchive {
    complete_archive_with(
        complete_recipient_key_thumbprint(),
        complete_recipient_certificate_hash(),
        &complete_recipient_private_key().public_key(),
        ISOLATION_ENTRY_COUNT_V1,
        defect,
        COMPLETE_PLAINTEXT_V1,
    )
}

/// Baut den lueckenfreien Bestand und setzt `defect` auf den mittleren Eintrag.
///
/// `grant_object_hashes` bleibt zu `entry_object_hashes` INDEXGLEICH — mit der
/// einen Ausnahme [`IsolationDefectV1::MutatedWriterSignature`]: dort traegt der
/// defekte Eintrag gar keinen Grant, und die Liste ist um einen kuerzer. Das ist
/// gewollt. Der `entryHash` haengt an der Schreibersignatur; ein mitgelieferter
/// Grant zeigte nach der Mutation ins Leere und stuende als VERWAISTER Grant mit
/// einem zweiten Befund auf einem zweiten Objekt im Bericht. Ihn stattdessen
/// gegen die manipulierten Bytes neu zu bauen hiesse, eine Fixture zu bauen, in
/// der ein Angreifer mitsigniert.
fn complete_archive_with(
    recipient_key_thumbprint: KeyThumbprint,
    recipient_certificate_hash: CertificateHash,
    recipient_public_key: &HpkeRecipientPublicKey,
    entry_count: u64,
    defect: IsolationDefectV1,
    plaintext: &[u8],
) -> CompleteArchive {
    let line = complete_line();
    let anchor = line.anchor();
    let mut fixture = ArchiveFixture::new();
    push_trust_objects(&mut fixture, &line.line);

    let plan_hash = complete_grant_plan_hash(recipient_key_thumbprint, recipient_certificate_hash);
    let foreign_public_key = other_recipient_private_key().public_key();
    let mut entry_object_hashes = Vec::new();
    let mut grant_object_hashes = Vec::new();
    let mut previous_entry_hash = None;
    for (index, sequence) in
        (COMPLETE_GENESIS_SEQUENCE_V1..COMPLETE_GENESIS_SEQUENCE_V1 + entry_count).enumerate()
    {
        let defective = index == ISOLATION_DEFECT_INDEX_V1;
        let entry = build_complete_entry(
            line.head_ref(),
            line.writer_certificate_hash,
            anchor.chain_id(),
            plan_hash,
            sequence,
            previous_entry_hash,
            plaintext,
        );
        let mut entry_bytes = encode_entry_package(&entry)
            .expect("das Fixture-Eintragspaket muss kodieren")
            .into_vec();
        // DIE NACHFOLGERBINDUNG STAMMT AUS DEN UNVERSEHRTEN BYTES, und das ist
        // der ehrliche Fall: der Bestand wurde gueltig geschrieben, und erst
        // danach hat jemand ein Byte verkippt. Der mutierte Eintrag wird
        // ohnehin kein Kettenknoten — er faellt an Gate `manifest-signature` —,
        // und `ea-chain` vergleicht Vorgaengerbindungen nur zwischen
        // unmittelbar benachbarten Sequenzen. Es entsteht deshalb eine LUECKE
        // und ausdruecklich kein Bruch.
        previous_entry_hash = Some(entry.entry_hash());

        let mutated = defective && defect == IsolationDefectV1::MutatedWriterSignature;
        if mutated {
            // Der rohe Ed25519-Wert steht in den letzten 64 Bytes. GEPRUEFT und
            // nicht behauptet: die exakten Bytes enden auf der COSE-Struktur der
            // Schreibersignatur.
            assert!(
                entry_bytes.ends_with(entry.writer_signature()),
                "die Eintragsbytes enden nicht mehr auf der Schreibersignatur"
            );
            let offset = entry_bytes.len() - 64;
            entry_bytes = mutate_one_byte(&entry_bytes, offset);
        }
        entry_object_hashes.push(object_hash(&entry_bytes));

        if !mutated {
            let sealed_to = if defective && defect == IsolationDefectV1::ForeignEncapsulation {
                &foreign_public_key
            } else {
                recipient_public_key
            };
            let grant_bytes = complete_grant_bytes(
                line.head_ref(),
                line.writer_certificate_hash,
                anchor.chain_id(),
                entry.entry_hash(),
                sequence,
                recipient_key_thumbprint,
                recipient_certificate_hash,
                sealed_to,
            );
            grant_object_hashes.push(object_hash(&grant_bytes));
            push_grant(&mut fixture, sequence, grant_bytes);
        }

        fixture.push_exact_bytes(
            &format!("{}{sequence:012}_entry.eip", ea_archive::ENTRIES_DIR_V1),
            entry_bytes.clone(),
        );
        if defective && defect == IsolationDefectV1::DuplicateEntry {
            // DIESELBEN BYTES unter einem zweiten Hinweis: klassifiziert wird am
            // Praefix, und der Objekthash ist derselbe. Genau das ist ein
            // Duplikat im Sinne von `QuarantineReason::Duplicate`.
            fixture.push_exact_bytes(
                &format!(
                    "{}{sequence:012}_entry_copy.eip",
                    ea_archive::ENTRIES_DIR_V1
                ),
                entry_bytes,
            );
        }
    }

    CompleteArchive {
        fixture,
        anchor_bytes: line.anchor_bytes,
        entry_object_hashes,
        grant_object_hashes,
    }
}

/// Baut einen Eintrag der lueckenfreien Kette mit ECHTEM Ciphertext.
///
/// Zwei Durchgaenge, und das ist kein Umweg: `manifestCore` traegt die LAENGE
/// des Ciphertexts, nicht dessen Hash (`design.md`:669-671 haelt ausdruecklich
/// fest, dass daraus kein Zirkel entsteht). Der erste Durchgang baut den Kern
/// ueber einen Platzhalter GLEICHER Laenge und liefert damit exakt die Bytes,
/// die als AAD in die Verschluesselung gehen; der zweite baut denselben Kern
/// ueber den echten Ciphertext. Beide Kerne sind byteidentisch — die
/// Zusicherung unten misst das, statt es zu glauben.
///
/// `plaintext` kommt als Parameter, weil ein Leser den Klartext AUCH liest:
/// [`complete_valid_archive_with_plaintext`] legt einen schemagueltigen ab,
/// alle uebrigen Bestaende [`COMPLETE_PLAINTEXT_V1`].
fn build_complete_entry(
    head: HeadRefV1,
    writer_certificate_hash: CertificateHash,
    chain_id: ChainId,
    plan_hash: Hash32,
    chain_sequence: u64,
    previous_entry_hash: Option<EntryHash>,
    plaintext: &[u8],
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
        nonce: complete_nonce(chain_sequence),
    };
    let placeholder = vec![0x00; plaintext.len() + ea_crypto::AEAD_OVERHEAD];
    let draft =
        ManifestCoreV1::new(fields(), &placeholder).expect("das Fixture-Manifest muss kodieren");
    let aad = ea_crypto::payload_aad(draft.exact_bytes());
    let ciphertext = ea_crypto::aead_seal(
        &SecretBytes::new(complete_cek(chain_sequence)),
        &SecretBytes::new(complete_nonce(chain_sequence)),
        ea_crypto::SecretVec::new(plaintext.to_vec()),
        &aad,
    )
    .expect("der Fixture-Klartext muss sich verschluesseln lassen");
    let manifest =
        ManifestCoreV1::new(fields(), &ciphertext).expect("das Fixture-Manifest muss kodieren");
    assert!(
        manifest.exact_bytes() == draft.exact_bytes(),
        "der Manifestkern haengt an der LAENGE des Ciphertexts, nicht an seinen Bytes"
    );
    let signed = SignedManifestV1::new(manifest, &ciphertext).expect("das Manifest muss binden");
    let signature = writer_device_signer()
        .sign_record(signed.exact_bytes())
        .expect("der Fixture-Signierer muss signieren");
    EntryPackageV1::new(signed, ciphertext, signature)
        .expect("das Fixture-Eintragspaket muss sich zusammensetzen")
}

/// Baut den initialen Recovery-Grant mit ECHTER Kapselung.
///
/// Auch hier zwei Durchgaenge, und auch hier ohne Zirkel:
/// `grant-context-v1` traegt WEDER den Kapselungswert NOCH den umschlossenen
/// CEK (`design.md`:747-772). Der erste Durchgang liefert also bereits die
/// endgueltigen Kontextbytes, aus denen `hpkeInfo` und `hpkeAad` entstehen;
/// der zweite setzt die Kapselung ein. Die Zusicherung unten misst, dass der
/// Kontext dabei unveraendert bleibt.
#[allow(clippy::too_many_arguments)]
fn complete_grant_bytes(
    head: HeadRefV1,
    writer_certificate_hash: CertificateHash,
    chain_id: ChainId,
    entry_hash: EntryHash,
    chain_sequence: u64,
    recipient_key_thumbprint: KeyThumbprint,
    recipient_certificate_hash: CertificateHash,
    recipient_public_key: &HpkeRecipientPublicKey,
) -> Vec<u8> {
    let fields = |encapsulated_key, wrapped_cek| GrantBodyFieldsV1 {
        organization_id: trust_support::organization(),
        chain_id,
        entry_hash,
        kind: GrantKindV1::Initial,
        purpose: GrantPurposeV1::Recovery,
        recipient_key_thumbprint,
        recipient_certificate_hash,
        issuer_key_thumbprint: writer_device_key_thumbprint(),
        issuer_certificate_hash: writer_certificate_hash,
        registry_version: head.version,
        registry_head_hash: head.hash,
        created_at_device: UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1),
        original_recovery_grant_object_hash: None,
        grant_authorization_object_hash: None,
        encapsulated_key,
        wrapped_cek,
    };
    let draft = GrantBodyV1::new(fields(
        [0x00; HPKE_ENCAPSULATED_KEY_SIZE],
        [0x00; HPKE_WRAPPED_CEK_SIZE],
    ))
    .expect("der Fixture-Grantrumpf muss kodieren");
    let context = exact_grant_context(draft.exact_bytes());
    let sealed = ea_crypto::hpke_seal(
        recipient_public_key,
        &SecretBytes::new(complete_cek(chain_sequence)),
        &ea_crypto::hpke_info(&context),
        &ea_crypto::hpke_aad(&context),
    )
    .expect("der Fixture-CEK muss sich kapseln lassen");
    let body = GrantBodyV1::new(fields(*sealed.encapsulated_key(), *sealed.wrapped_cek()))
        .expect("der Fixture-Grantrumpf muss kodieren");
    assert!(
        exact_grant_context(body.exact_bytes()) == context,
        "der Grantkontext haengt nicht an der Kapselung"
    );
    let signature = writer_device_signer()
        .sign_initial_grant(body.exact_bytes())
        .expect("der Fixture-Aussteller muss signieren");
    let grant = GrantV1::new(body, signature).expect("der Fixture-Grant muss binden");
    encode_grant(&grant)
        .expect("der Fixture-Grant muss kodieren")
        .into_vec()
}

// ---------------------------------------------------------------------------
// Vernichtungsvorgaenge: `authorizedDestructions` und die Signierer, die sie
// tragen.
// ---------------------------------------------------------------------------

/// Erste Sequenz der Lease des Kopfes, der das `deletionAttest`-Zertifikat
/// aktiviert.
///
/// LIEGT HINTER [`COMPLETE_WRITER_LEASE_THROUGH_V1`], und das ist keine
/// Kosmetik: `verify_cose_sign1` verlangt fuer die Transitionssignatur, dass
/// die `authorizationSequence` sowohl hinter der `effective_from_sequence` des
/// Zertifikats als auch hinter der des REGISTRIERUNGSKOPFES liegt
/// (`crates/ea-crypto/src/cose.rs:1434-1443`). Ein eigener Kopf traegt genau
/// EINEN Uebergang, also bekommt das `deletionAttest`-Zertifikat einen eigenen
/// — und dessen Lease beginnt hinter der des Schreibers.
pub const DESTRUCTION_LEASE_FROM_V1: u64 = 101;
/// Letzte Sequenz dieser Lease.
pub const DESTRUCTION_LEASE_THROUGH_V1: u64 = 200;

/// Die `authorizationSequence` jeder Fixture-Vernichtungsautorisierung.
///
/// GLEICH dem Beginn der Lease: `destruction_transition_trust_digest` zieht
/// `expected_sequence` AUSSCHLIESSLICH aus der Autorisierung
/// (`crates/ea-crypto/src/cose.rs:1069-1090`), nicht aus dem Transitionsobjekt.
pub const DESTRUCTION_AUTHORIZATION_SEQUENCE_V1: u64 = DESTRUCTION_LEASE_FROM_V1;

/// Erste Sequenz der ZWEITEN Loeschzeugen-Lease.
///
/// Sie existiert, damit sich messen laesst, was mit einer einzigen Lease
/// unsichtbar bleibt: die Registrierungslinie laesst sich nur VORWAERTS
/// nachziehen, und ein einmal gepinnter Kopf geht nie zurueck. Zwei
/// Vernichtungen unter VERSCHIEDENEN Leases decken deshalb auf, ob die
/// Pipeline ihre Kopfabfragen nach Sequenz ordnet oder dem Zufall der
/// Objekthashes ueberlaesst.
pub const SECOND_DESTRUCTION_LEASE_FROM_V1: u64 = 201;
/// Letzte Sequenz dieser Lease.
pub const SECOND_DESTRUCTION_LEASE_THROUGH_V1: u64 = 300;
/// Die `authorizationSequence` der Vorgaenge in der zweiten Lease.
pub const SECOND_DESTRUCTION_AUTHORIZATION_SEQUENCE_V1: u64 = SECOND_DESTRUCTION_LEASE_FROM_V1;

/// Die fuenf `destruction-state-v1`-Codes aus dem Wire-Format-Addendum
/// (`docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-wire-format-addendum.md`:335-336).
pub const DESTRUCTION_STATE_REQUESTED_V1: u8 = 0;
/// In Ausfuehrung.
pub const DESTRUCTION_STATE_IN_PROGRESS_V1: u8 = 1;
/// Wartet auf den Ablauf von Sicherungen.
pub const DESTRUCTION_STATE_PENDING_BACKUP_EXPIRY_V1: u8 = 2;
/// Im verwalteten Bereich vollstaendig.
pub const DESTRUCTION_STATE_COMPLETE_MANAGED_SCOPE_V1: u8 = 3;
/// Unvollstaendig, weil eine Replik nicht erreichbar war.
pub const DESTRUCTION_STATE_INCOMPLETE_UNREACHABLE_REPLICA_V1: u8 = 4;

/// Mit WELCHEM Zertifikat die Ereignisse eines Vorgangs signiert werden.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestructionSignerSpec {
    /// Das `deletionAttest`-Zertifikat. Die Pruefung traegt.
    DeletionAttest,
    /// Das Schreiberzertifikat: richtige Organisation, richtiger Schluessel,
    /// aber weder die Rolle noch die Faehigkeit `deletionAttest`. Genau der
    /// Fall, in dem eine tadellose Ed25519-Signatur trotzdem keine Autoritaet
    /// traegt.
    Writer,
}

/// Ein Vernichtungsvorgang, wie ihn die Fixture ablegt.
#[derive(Clone, Debug)]
pub struct DestructionSpec {
    /// Unterscheidet Vorgaenge: `destructionId`, Ereigniskennungen und
    /// Zielhashes werden daraus abgeleitet.
    pub marker: u8,
    /// Die `to_state`-Codes der Ereigniskette, in Ablagereihenfolge.
    ///
    /// Das erste Ereignis ist die Wurzel (`previousEventObjectHash` und
    /// `fromState` beide abwesend); jedes weitere bindet an das vorige und
    /// traegt dessen `to_state` als `from_state`. UNZULAESSIGE Uebergaenge
    /// werden hier schlicht hingeschrieben — das Wire-Format laesst jeden Code
    /// 0..4 zu, die Zulaessigkeit ist eine Aussage der Verifikation.
    pub events: Vec<u8>,
    /// Wer signiert.
    pub signer: DestructionSignerSpec,
    /// Ob zusaetzlich eine Loeschbestaetigung abgelegt wird.
    pub attestation: bool,
    /// Ob ALLE Ereignisse dieselbe `event_id` tragen.
    pub duplicate_event_id: bool,
    /// Ob der Vorgang in der ZWEITEN Loeschzeugen-Lease autorisiert ist.
    pub second_lease: bool,
    /// WELCHE Eintraege die Autorisierung nennt.
    ///
    /// `None` steht fuer das Pseudoziel `[marker; 32]` auf der
    /// `authorizationSequence` — genug fuer `ea-verify`, das die Ziele nie
    /// liest. Ein Leser, der einen `.eds` ueber die Ziele der Autorisierung
    /// aufloest, braucht dagegen den ECHTEN Eintragshash darin; dafuer setzt
    /// [`DestructionSpec::targeting`] das Feld.
    pub targets: Option<Vec<DestructionTargetV1>>,
}

impl DestructionSpec {
    /// Ein Vorgang mit gueltiger Signatur, ohne Attestierung.
    #[must_use]
    pub fn new(marker: u8, events: &[u8]) -> Self {
        Self {
            marker,
            events: events.to_vec(),
            signer: DestructionSignerSpec::DeletionAttest,
            attestation: false,
            duplicate_event_id: false,
            second_lease: false,
            targets: None,
        }
    }

    /// Derselbe Vorgang, dessen Autorisierung GENAU diesen Eintrag nennt.
    #[must_use]
    pub fn targeting(mut self, entry_hash: EntryHash, chain_sequence: u64) -> Self {
        self.targets = Some(vec![DestructionTargetV1::new(
            *entry_hash.as_bytes(),
            chain_sequence,
        )]);
        self
    }

    /// Derselbe Vorgang, autorisiert in der ZWEITEN Loeschzeugen-Lease.
    #[must_use]
    pub fn in_the_second_lease(mut self) -> Self {
        self.second_lease = true;
        self
    }

    /// Derselbe Vorgang mit einer Loeschbestaetigung.
    #[must_use]
    pub fn with_attestation(mut self) -> Self {
        self.attestation = true;
        self
    }

    /// Derselbe Vorgang, signiert vom Schreiber statt vom Loeschzeugen.
    #[must_use]
    pub fn signed_by_the_writer(mut self) -> Self {
        self.signer = DestructionSignerSpec::Writer;
        self
    }

    /// Derselbe Vorgang, dessen Ereignisse dieselbe Kennung tragen.
    #[must_use]
    pub fn with_one_event_id(mut self) -> Self {
        self.duplicate_event_id = true;
        self
    }
}

/// Was von einem abgelegten Vorgang bekannt ist.
pub struct BuiltDestruction {
    pub destruction_id: DestructionId,
    pub authorization_object_hash: ObjectHash,
    /// Objekthashes der Transitionsobjekte, in Kettenreihenfolge.
    pub event_object_hashes: Vec<ObjectHash>,
    /// Objekthash der Loeschbestaetigung, sofern eine abgelegt wurde.
    pub attestation_object_hash: Option<ObjectHash>,
}

/// Ein Bestand aus Registrierungslinie und Vernichtungsvorgaengen.
///
/// BEWUSST OHNE EINTRAEGE: dann kann der Abdruck des Geraeteschluessels in
/// `publicKeyThumbprints` nur aus einer Destruction-Signatur stammen. Mit
/// Eintraegen waere dieselbe Zahl auch ohne jede gepruefte Transition
/// erreichbar — die Registrierungslinie stellt JEDES Geraetezertifikat auf
/// denselben Schluessel aus.
pub struct DestructionArchive {
    pub fixture: ArchiveFixture,
    pub anchor_bytes: Vec<u8>,
    pub destructions: Vec<BuiltDestruction>,
}

impl DestructionArchive {
    #[must_use]
    pub fn anchor(&self) -> TrustAnchorV1 {
        decode_trust_anchor(&self.anchor_bytes).expect("der Fixture-Anker muss dekodieren")
    }
}

/// Eine Loeschzeugen-Lease: ihr Kopf, ihr Zertifikat und ihre
/// `authorizationSequence`.
#[derive(Clone, Copy)]
struct DestructionLease {
    head: trust_support::BuiltHead,
    certificate_hash: CertificateHash,
    authorization_sequence: u64,
}

impl DestructionLease {
    fn head_hash(&self) -> Hash32 {
        Hash32::try_from(self.head.object_hash.as_bytes().as_slice())
            .expect("ein Objekthash sind 32 Bytes")
    }
}

/// Die Linie der Vernichtungsfixtures: Policy, Schreiber, ZWEI Loeschzeugen.
///
/// ZWEI und nicht einer, obwohl die meisten Fixtures nur den ersten brauchen.
/// Mit einer einzigen Lease deckte jede Kopfabfrage denselben Kopf ab, und die
/// Reihenfolge der Abfragen waere unbeobachtbar — obwohl die
/// Registrierungslinie sich nur vorwaerts nachziehen laesst und ein zu frueh
/// gepinnter Kopf jede niedrigere Sequenz danach unerreichbar macht.
struct DestructionLine {
    line: trust_support::RegistryLineBuilder,
    authority: DestructionAuthority,
    anchor_bytes: Vec<u8>,
}

/// Alles, was ein Vernichtungsvorgang von seiner Linie braucht.
///
/// BEWUSST NEBEN [`DestructionLine`] und nicht darin: die Vorgaenge selbst
/// haengen weder am `RegistryLineBuilder` noch am Anker, sondern allein an den
/// beiden Loeschzeugen-Leases und dem Schreiberzertifikat. Erst diese Trennung
/// laesst dieselben Vorgaenge in einer ANDEREN Linie ablegen — etwa der des
/// Gesamtberichts, die neben den Loeschzeugen auch Server- und
/// Schreiberzertifikate fuehrt.
#[derive(Clone, Copy)]
struct DestructionAuthority {
    leases: [DestructionLease; 2],
    writer_certificate_hash: CertificateHash,
}

impl DestructionAuthority {
    fn lease(&self, spec: &DestructionSpec) -> DestructionLease {
        self.leases[usize::from(spec.second_lease)]
    }

    fn certificate_hash(
        &self,
        signer: DestructionSignerSpec,
        lease: DestructionLease,
    ) -> CertificateHash {
        match signer {
            DestructionSignerSpec::DeletionAttest => lease.certificate_hash,
            DestructionSignerSpec::Writer => self.writer_certificate_hash,
        }
    }
}

fn destruction_line() -> DestructionLine {
    let mut line = trust_support::RegistryLineBuilder::new();
    line.push(
        policy_action(),
        trust_support::HeadOptions {
            effective_from: Some(POLICY_LEASE_FROM_V1),
            valid_through: Some(POLICY_LEASE_THROUGH_V1),
            not_after: UnixMillis::new(COMPLETE_POLICY_NOT_AFTER_V1),
            ..trust_support::HeadOptions::default()
        },
    );
    let writer = line.push(
        trust_support::ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x11,
            effective_from: Some(COMPLETE_WRITER_LEASE_FROM_V1),
        },
        trust_support::HeadOptions {
            effective_from: Some(COMPLETE_WRITER_LEASE_FROM_V1),
            valid_through: Some(COMPLETE_WRITER_LEASE_THROUGH_V1),
            ..trust_support::HeadOptions::default()
        },
    );
    let mut lease = |marker: u8, from: u64, through: u64, sequence: u64| {
        let head = line.push(
            trust_support::ActionSpec::Device {
                kind: CertificateKindV1::DeletionAttest,
                marker,
                effective_from: Some(from),
            },
            trust_support::HeadOptions {
                effective_from: Some(from),
                valid_through: Some(through),
                ..trust_support::HeadOptions::default()
            },
        );
        DestructionLease {
            certificate_hash: CertificateHash::from(
                head.direct_object_hash
                    .expect("ein Device-Uebergang traegt ein direktes Ziel"),
            ),
            head,
            authorization_sequence: sequence,
        }
    };
    let leases = [
        lease(
            0x12,
            DESTRUCTION_LEASE_FROM_V1,
            DESTRUCTION_LEASE_THROUGH_V1,
            DESTRUCTION_AUTHORIZATION_SEQUENCE_V1,
        ),
        lease(
            0x13,
            SECOND_DESTRUCTION_LEASE_FROM_V1,
            SECOND_DESTRUCTION_LEASE_THROUGH_V1,
            SECOND_DESTRUCTION_AUTHORIZATION_SEQUENCE_V1,
        ),
    ];
    let anchor_bytes = line.exact_anchor_bytes().to_vec();
    DestructionLine {
        authority: DestructionAuthority {
            leases,
            writer_certificate_hash: CertificateHash::from(
                writer
                    .direct_object_hash
                    .expect("ein Device-Uebergang traegt ein direktes Ziel"),
            ),
        },
        line,
        anchor_bytes,
    }
}

/// Baut einen Bestand aus der Linie und den beschriebenen Vorgaengen.
#[must_use]
pub fn destruction_archive(specs: &[DestructionSpec]) -> DestructionArchive {
    let line = destruction_line();
    let mut fixture = ArchiveFixture::new();
    push_trust_objects(&mut fixture, &line.line);

    let mut destructions = Vec::new();
    for spec in specs {
        destructions.push(push_destruction(&mut fixture, line.authority, spec));
    }

    DestructionArchive {
        fixture,
        anchor_bytes: line.anchor_bytes,
        destructions,
    }
}

fn push_destruction(
    fixture: &mut ArchiveFixture,
    authority: DestructionAuthority,
    spec: &DestructionSpec,
) -> BuiltDestruction {
    let destruction_id = DestructionId::try_from(&[spec.marker; 16][..])
        .expect("16 Bytes sind eine Vorgangskennung");
    let lease = authority.lease(spec);
    let targets = spec.targets.clone().unwrap_or_else(|| {
        vec![DestructionTargetV1::new(
            [spec.marker; 32],
            lease.authorization_sequence,
        )]
    });
    let authorization = destruction_authorization_bytes(authority, lease, destruction_id, targets);
    let authorization_object_hash = object_hash(&authorization);
    fixture.push_exact_bytes(
        &format!(
            "{}{}/authorization.etb",
            ea_archive::DESTRUCTIONS_DIR_V1,
            hex::encode(destruction_id.as_bytes())
        ),
        authorization,
    );
    // Die Autorisierung muss VOR den Transitionen stehen: jede Transition
    // bindet ihren Objekthash, und `sign_destruction_transition_digest`
    // rechnet ihn selbst nach.
    let authorization_bytes = fixture
        .blobs()
        .last()
        .expect("die Autorisierung liegt im Bestand")
        .1
        .clone();

    let certificate_hash = authority.certificate_hash(spec.signer, lease);
    let mut event_object_hashes = Vec::new();
    let mut previous_event_object_hash = None;
    let mut previous_state = None;
    for (index, to_state) in spec.events.iter().copied().enumerate() {
        let event_marker = if spec.duplicate_event_id {
            spec.marker
        } else {
            spec.marker
                .wrapping_add(u8::try_from(index).expect("ein Byte je Ereignis"))
        };
        let bytes = destruction_transition_bytes(
            &authorization_bytes,
            destruction_id,
            authorization_object_hash,
            EventId::try_from(&[event_marker; 16][..]).expect("16 Bytes sind eine Ereigniskennung"),
            previous_event_object_hash,
            previous_state,
            to_state,
            certificate_hash,
        );
        let hash = object_hash(&bytes);
        fixture.push_exact_bytes(
            &format!(
                "{}{}/{}{}.etb",
                ea_archive::DESTRUCTIONS_DIR_V1,
                hex::encode(destruction_id.as_bytes()),
                ea_archive::DESTRUCTION_EVENTS_SUBDIR_V1,
                hex::encode(hash.as_bytes())
            ),
            bytes,
        );
        event_object_hashes.push(hash);
        previous_event_object_hash = Some(hash);
        previous_state = Some(to_state);
    }

    let attestation_object_hash = spec.attestation.then(|| {
        let bytes = deletion_attestation_bytes(
            &authorization_bytes,
            destruction_id,
            authorization_object_hash,
            spec.marker,
            certificate_hash,
        );
        let hash = object_hash(&bytes);
        fixture.push_exact_bytes(
            &format!(
                "{}{}/{}{}.etb",
                ea_archive::DESTRUCTIONS_DIR_V1,
                hex::encode(destruction_id.as_bytes()),
                ea_archive::DESTRUCTION_ATTESTATIONS_SUBDIR_V1,
                hex::encode(hash.as_bytes())
            ),
            bytes,
        );
        hash
    });

    BuiltDestruction {
        destruction_id,
        authorization_object_hash,
        event_object_hashes,
        attestation_object_hash,
    }
}

/// Baut die Vernichtungsautorisierung eines Vorgangs.
///
/// ZWEI SIGNATUREN UNTER VERSCHIEDENEN ZERTIFIKATEN, weil `ea-format` fuer
/// diese Unterart mindestens zwei verlangt
/// (`crates/ea-format/src/etb.rs:1248`): das Vier-Augen-Prinzip aus
/// `design.md`:1818 steht schon im Wire-Format, und es verlangt ZWEI
/// UNTERSCHIEDLICHE Approver. Zweimal dasselbe Zertifikat ergaebe zwei
/// byteidentische Signaturen — strukturell zulaessig und fachlich eine Luege.
///
/// Die Signaturen sind darueber hinaus STRUKTURELL gueltig und werden von
/// dieser Pipeline nie geprueft: `ea-verify` prueft die Transitionen, und die
/// binden den Objekthash der Autorisierung kryptografisch mit ein.
///
/// Die `targets` kommen als Parameter, weil `ea-verify` sie nie liest, ein
/// Leser sie aber gegen den `entryHash` eines `.eds` haelt — siehe
/// [`DestructionSpec::targets`].
fn destruction_authorization_bytes(
    authority: DestructionAuthority,
    lease: DestructionLease,
    destruction_id: DestructionId,
    targets: Vec<DestructionTargetV1>,
) -> Vec<u8> {
    let payload = TrustPayloadV1::destruction_authorization(DestructionAuthorizationFieldsV1 {
        destruction_id,
        organization_id: trust_support::organization(),
        registry_version: lease.head.version,
        registry_head_hash: lease.head_hash(),
        authorization_sequence: lease.authorization_sequence,
        targets,
        scope_code: 0,
        legal_reason_code: 0,
    })
    .expect("die Fixture-Vernichtungsautorisierung muss kodieren");
    let signer = writer_device_signer();
    let signatures = [lease.certificate_hash, authority.writer_certificate_hash]
        .into_iter()
        .map(|certificate_hash| {
            signer
                .sign_destruction_approval_digest(certificate_hash, payload.exact_digest_input())
                .expect("der Fixture-Signierer muss signieren")
        })
        .collect();
    encode_trust(&TrustObjectV1::new(payload, signatures).expect("die Autorisierung muss binden"))
        .expect("die Autorisierung muss kodieren")
        .into_vec()
}

#[allow(clippy::too_many_arguments)]
fn destruction_transition_bytes(
    authorization_bytes: &[u8],
    destruction_id: DestructionId,
    authorization_object_hash: ObjectHash,
    event_id: EventId,
    previous_event_object_hash: Option<ObjectHash>,
    from_state: Option<u8>,
    to_state: u8,
    certificate_hash: CertificateHash,
) -> Vec<u8> {
    let payload = TrustPayloadV1::destruction_transition(DestructionTransitionFieldsV1 {
        destruction_id,
        destruction_authorization_object_hash: authorization_object_hash,
        event_id,
        previous_event_object_hash,
        from_state,
        to_state,
        trigger_code: 0,
        executed_at: UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1),
    })
    .expect("die Fixture-Transition muss kodieren");
    let signature = writer_device_signer()
        .sign_destruction_transition_digest(
            certificate_hash,
            payload.exact_digest_input(),
            authorization_bytes,
        )
        .expect("der Fixture-Signierer muss signieren");
    encode_trust(&TrustObjectV1::new(payload, vec![signature]).expect("die Transition muss binden"))
        .expect("die Transition muss kodieren")
        .into_vec()
}

fn deletion_attestation_bytes(
    authorization_bytes: &[u8],
    destruction_id: DestructionId,
    authorization_object_hash: ObjectHash,
    marker: u8,
    certificate_hash: CertificateHash,
) -> Vec<u8> {
    let payload = TrustPayloadV1::deletion_attestation(DeletionAttestationFieldsV1 {
        destruction_id,
        destruction_authorization_object_hash: authorization_object_hash,
        replica_id: [marker; 16],
        replica_kind: 0,
        removed_object_hashes: vec![
            ObjectHash::try_from(&[marker; 32][..]).expect("32 Bytes sind ein Objekthash"),
        ],
        result: 0,
        backup_expiry_at: None,
        executed_at: UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1),
    })
    .expect("die Fixture-Loeschbestaetigung muss kodieren");
    let signature = writer_device_signer()
        .sign_deletion_attestation_digest(
            certificate_hash,
            payload.exact_digest_input(),
            authorization_bytes,
        )
        .expect("der Fixture-Signierer muss signieren");
    encode_trust(
        &TrustObjectV1::new(payload, vec![signature]).expect("die Loeschbestaetigung muss binden"),
    )
    .expect("die Loeschbestaetigung muss kodieren")
    .into_vec()
}

// ---------------------------------------------------------------------------
// Der Gesamtbestand: EIN Archiv, das jedes Pflichtfeld des Berichts fuellt.
// ---------------------------------------------------------------------------

/// Die einzige Sequenz, die der FRUEHE Registrierungskopf deckt.
///
/// GENAU EINE, und der Zuschnitt ist gemessen statt gewaehlt. Die Pipeline
/// zieht die Registrierungslinie waehrend der Eintragsschleife nach und pinnt
/// dabei den hoechsten erreichten Kopf; die Stufen DAHINTER — Quittung,
/// Checkpoint, eigener Grant — fragen ueber
/// `select_pinned_head` erneut nach einem Kopf und bekommen NUR noch diesen
/// gepinnten. `resolve_selected` verwirft ausserdem jedes Objekt, dessen
/// gebundene Registrierungsversion nicht die des gewaehlten Kopfes ist
/// (`crates/ea-trust/src/resolver.rs:180-182`).
///
/// Beides zusammen heisst: ein Eintrag unter einem FRUEHEREN Kopf ist nach dem
/// Nachziehen fuer die spaeteren Stufen unerreichbar. Gemessen an einem
/// Zwischenstand dieses Bestands mit drei Eintraegen unterhalb des zweiten
/// Kopfes: drei `EA-VERIFY-GRANT-HEAD-UNAVAILABLE` und zwei
/// `EA-VERIFY-RECEIPT-UNTRUSTED-TIME`.
///
/// Der Bestand traegt deshalb genau EINEN Eintrag unter dem fruehen Kopf, und
/// dieser Eintrag braucht keine spaetere Stufe: er hat keine Quittung und sein
/// Recovery-Grant geht an einen ANDEREN Empfaenger. Ein fehlender eigener Grant
/// ist ausdruecklich kein Mangel (`design.md`:1595), und ohne Quittung ist
/// `notServerConfirmed` ebenfalls keiner (`design.md`:1591). So traegt
/// `registryVersions` ZWEI Werte, ohne dass ein Eintrag stillschweigend
/// verlorenginge.
pub const REPORT_EARLY_SEQUENCE_V1: u64 = 0;

/// Erste Sequenz der Lease des SPAETEN Registrierungskopfes.
pub const REPORT_LATE_LEASE_FROM_V1: u64 = REPORT_EARLY_SEQUENCE_V1 + 1;
/// Letzte Sequenz dieser Lease.
pub const REPORT_LATE_LEASE_THROUGH_V1: u64 = 100;

/// Die Sequenz des VERIFIZIERTEN Kettenkopfes.
///
/// Der hoechste Eintrag, bis zu dem die Kette lueckenlos und
/// vorgaengergebunden ist. Ueber ihm liegt der Stummel, und
/// `walk_verified_prefix` haelt vor jeder Luecke an
/// (`crates/ea-chain/src/chain.rs:732-753`).
pub const REPORT_HEAD_SEQUENCE_V1: u64 = 3;

/// Die Sequenz des Eintrags unter dem spaeten Kopf OHNE Quittung.
pub const REPORT_UNCONFIRMED_SEQUENCE_V1: u64 = REPORT_HEAD_SEQUENCE_V1;

/// Die Sequenz des `.eds`: hier liegt ein Stummel statt eines `.eip`.
///
/// SIE IST DIE LUECKE DES BESTANDS, und das ist gemessen statt gewaehlt. Ein
/// `.eds` wird in diesem Stand NIE ein Kettenknoten —
/// `crates/ea-verify/src/archive.rs:410-425` haelt fest, warum: die
/// `destructionAuthorization` ist von `ea-verify` aus nicht aufloesbar,
/// `ea-trust` exportiert keine Pruefung dafuer, und Inventarmitgliedschaft ist
/// keine Autorisierung. Der Stummel BLEIBT deshalb eine Luecke
/// (`design.md`:1597).
pub const REPORT_DESTROYED_STUB_SEQUENCE_V1: u64 = REPORT_HEAD_SEQUENCE_V1 + 1;

/// Die Sequenz des Eintrags OBERHALB der Luecke.
///
/// Ohne ihn waere die Luecke unsichtbar: `collect_gaps` bildet oberhalb des
/// hoechsten Knotens grundsaetzlich kein Intervall
/// (`crates/ea-chain/src/chain.rs:766-768`), weil ueber nicht existierende
/// Fortsetzungen keine Aussage moeglich ist.
pub const REPORT_TRAILING_SEQUENCE_V1: u64 = REPORT_DESTROYED_STUB_SEQUENCE_V1 + 1;

/// Die Sequenzen, zu denen der Gesamtbestand eine Quittung ablegt.
///
/// BEWUSST NICHT ALLE: `notServerConfirmed` ist kein Mangel
/// (`design.md`:1591), und ein Bestand, in dem jeder Eintrag bestaetigt ist,
/// koennte das gar nicht zeigen.
pub const REPORT_RECEIPTED_SEQUENCES_V1: [u64; 3] = [1, 2, REPORT_TRAILING_SEQUENCE_V1];

/// Die Sequenz des DOPPELT abgelegten Eintrags.
///
/// OBERHALB aller Knoten: ein Duplikat ISOLIERT sein Objekt, der Eintrag
/// verschwindet damit aus der Kette, und ein Nachfolger verloere seine
/// Vorgaengerbindung.
pub const REPORT_DUPLICATE_SEQUENCE_V1: u64 = REPORT_TRAILING_SEQUENCE_V1 + 1;

/// Die Sequenz, auf der ZWEI Eintraege denselben Platz beanspruchen.
///
/// Der Widerspruch faellt bereits im INVENTAR auf: zwei Objekte auf demselben
/// Fach aus `(chainId, chainSequence)` werden dort isoliert
/// (`crates/ea-archive/src/inventory.rs:497-505` und `:565-577`). Sie werden
/// deshalb gar nicht erst Kettenknoten — und erzeugen ueber sich auch keine
/// Luecke.
pub const REPORT_FORK_SEQUENCE_V1: u64 = REPORT_DUPLICATE_SEQUENCE_V1 + 1;

/// Erste Sequenz der Luecke, die der Stummel hinterlaesst.
pub const REPORT_GAP_FROM_V1: u64 = REPORT_DESTROYED_STUB_SEQUENCE_V1;
/// Letzte Sequenz dieser Luecke.
pub const REPORT_GAP_THROUGH_V1: u64 = REPORT_DESTROYED_STUB_SEQUENCE_V1;

/// Die Fuellbytes der beiden konkurrierenden Eintraege auf
/// [`REPORT_FORK_SEQUENCE_V1`].
const REPORT_FORK_NONCE_MARKERS_V1: [u8; 2] = [0xa1, 0xa2];

/// Der Marker des Vernichtungsvorgangs des Gesamtbestands.
pub const REPORT_DESTRUCTION_MARKER_V1: u8 = 0x91;

/// Das Fuellbyte des Autorisierungshashes eines GEFAELSCHTEN Stummels.
///
/// Er nennt die echte Kennung des abgelegten Vorgangs, aber einen
/// Autorisierungshash, unter dem im Bestand nichts liegt. Bewusst weder
/// [`UNRESOLVABLE_STUB_AUTHORIZATION_MARKER_V1`] noch ein Marker eines
/// abgelegten Objekts, damit die Faelschung an genau EINEM Feld haengt.
pub const FORGED_STUB_AUTHORIZATION_MARKER_V1: u8 = 0xee;

/// Ein Bestand, der JEDES Pflichtfeld des Berichts fuellt.
pub struct ReportArchive {
    pub fixture: ArchiveFixture,
    pub anchor_bytes: Vec<u8>,
    /// Registrierungsversion des Kopfes ueber [`REPORT_EARLY_SEQUENCE_V1`].
    pub early_registry_version: RegistryVersion,
    /// Registrierungsversion des Kopfes ueber alle uebrigen Sequenzen.
    pub late_registry_version: RegistryVersion,
    /// Objekthashes der Eintraege, die ein Ergebnis bekommen sollen, in
    /// Sequenzreihenfolge.
    pub valid_entry_object_hashes: Vec<ObjectHash>,
    /// Objekthashes der Eintraege, deren Quittung sie bestaetigt.
    pub confirmed_entry_object_hashes: Vec<ObjectHash>,
    /// Objekthash des doppelt abgelegten Eintrags.
    pub duplicate_object_hash: ObjectHash,
    /// Objekthashes der beiden konkurrierenden Eintraege.
    pub conflicting_object_hashes: Vec<ObjectHash>,
    /// Objekthash des `.eds`.
    pub destroyed_stub_object_hash: ObjectHash,
    /// Objekthash des `.ecp`.
    pub checkpoint_object_hash: ObjectHash,
    /// Objekthash der unlesbaren Bytes.
    pub malformed_object_hash: ObjectHash,
    /// Objekthashes der abgelegten Quittungen.
    pub receipt_object_hashes: Vec<ObjectHash>,
    /// Der abgelegte Vernichtungsvorgang.
    pub destructions: Vec<BuiltDestruction>,
    /// Zahl der abgelegten Trust-Objekte.
    pub trust_object_count: usize,
    /// Zahl der abgelegten Bytesequenzen OHNE Exact-Object-Praefix.
    pub non_object_count: usize,
}

impl ReportArchive {
    #[must_use]
    pub fn anchor(&self) -> TrustAnchorV1 {
        decode_trust_anchor(&self.anchor_bytes).expect("der Fixture-Anker muss dekodieren")
    }
}

/// Die Linie des Gesamtbestands.
///
/// SECHS KOEPFE, und jeder einzelne ist erzwungen: ein Registrierungskopf
/// traegt genau EINEN Uebergang.
///
/// 1. Policy, Lease `0..=0`, VERALTET zur Uhr des Laufs. Sie setzt die
///    Richtlinie und tritt danach zur Seite — genau der Kunstgriff aus
///    [`COMPLETE_POLICY_NOT_AFTER_V1`], ohne den kein Eintrag je auf der
///    Sequenz null liegen koennte.
/// 2. Serverzertifikat, Lease `0..=0`, ebenfalls veraltet. Sein Zertifikat ist
///    ab Sequenz NULL wirksam; `verify_cose_sign1` verlangt fuer eine Quittung
///    genau das (`crates/ea-crypto/src/cose.rs:1435-1443`), waehrend der Kopf
///    selbst keine Eintragssequenz decken muss.
/// 3. Schreiberzertifikat, Lease `0..=0` — der FRUEHE Kopf.
/// 4. Policy, Lease `1..=100` — der SPAETE Kopf, unter dem alles Uebrige liegt.
/// 5. und 6. Zwei Loeschzeugen-Leases oberhalb der Eintragssequenzen, wie in
///    [`destruction_line`] und aus demselben Grund.
struct ReportLine {
    line: trust_support::RegistryLineBuilder,
    early_head: trust_support::BuiltHead,
    late_head: trust_support::BuiltHead,
    writer_certificate_hash: CertificateHash,
    server_certificate_hash: CertificateHash,
    authority: DestructionAuthority,
    anchor_bytes: Vec<u8>,
}

impl ReportLine {
    fn anchor(&self) -> TrustAnchorV1 {
        decode_trust_anchor(&self.anchor_bytes).expect("der Fixture-Anker muss dekodieren")
    }

    /// Der Kopf, unter dem `chain_sequence` liegt.
    fn head_for(&self, chain_sequence: u64) -> HeadRefV1 {
        if chain_sequence == REPORT_EARLY_SEQUENCE_V1 {
            HeadRefV1::of(&self.early_head)
        } else {
            HeadRefV1::of(&self.late_head)
        }
    }
}

fn report_line() -> ReportLine {
    let mut line = trust_support::RegistryLineBuilder::new();
    line.push(
        policy_action(),
        trust_support::HeadOptions {
            effective_from: Some(REPORT_EARLY_SEQUENCE_V1),
            valid_through: Some(REPORT_EARLY_SEQUENCE_V1),
            not_after: UnixMillis::new(COMPLETE_POLICY_NOT_AFTER_V1),
            ..trust_support::HeadOptions::default()
        },
    );
    let server_head = line.push(
        trust_support::ActionSpec::Device {
            kind: CertificateKindV1::ServerReceipt,
            marker: 0x21,
            effective_from: Some(REPORT_EARLY_SEQUENCE_V1),
        },
        trust_support::HeadOptions {
            effective_from: Some(REPORT_EARLY_SEQUENCE_V1),
            valid_through: Some(REPORT_EARLY_SEQUENCE_V1),
            not_after: UnixMillis::new(COMPLETE_POLICY_NOT_AFTER_V1),
            ..trust_support::HeadOptions::default()
        },
    );
    let early_head = line.push(
        trust_support::ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x11,
            effective_from: Some(REPORT_EARLY_SEQUENCE_V1),
        },
        trust_support::HeadOptions {
            effective_from: Some(REPORT_EARLY_SEQUENCE_V1),
            valid_through: Some(REPORT_EARLY_SEQUENCE_V1),
            ..trust_support::HeadOptions::default()
        },
    );
    let late_head = line.push(
        policy_action(),
        trust_support::HeadOptions {
            effective_from: Some(REPORT_LATE_LEASE_FROM_V1),
            valid_through: Some(REPORT_LATE_LEASE_THROUGH_V1),
            ..trust_support::HeadOptions::default()
        },
    );
    let mut lease = |marker: u8, from: u64, through: u64, sequence: u64| {
        let head = line.push(
            trust_support::ActionSpec::Device {
                kind: CertificateKindV1::DeletionAttest,
                marker,
                effective_from: Some(from),
            },
            trust_support::HeadOptions {
                effective_from: Some(from),
                valid_through: Some(through),
                ..trust_support::HeadOptions::default()
            },
        );
        DestructionLease {
            certificate_hash: CertificateHash::from(
                head.direct_object_hash
                    .expect("ein Device-Uebergang traegt ein direktes Ziel"),
            ),
            head,
            authorization_sequence: sequence,
        }
    };
    let leases = [
        lease(
            0x12,
            DESTRUCTION_LEASE_FROM_V1,
            DESTRUCTION_LEASE_THROUGH_V1,
            DESTRUCTION_AUTHORIZATION_SEQUENCE_V1,
        ),
        lease(
            0x13,
            SECOND_DESTRUCTION_LEASE_FROM_V1,
            SECOND_DESTRUCTION_LEASE_THROUGH_V1,
            SECOND_DESTRUCTION_AUTHORIZATION_SEQUENCE_V1,
        ),
    ];
    let writer_certificate_hash = CertificateHash::from(
        early_head
            .direct_object_hash
            .expect("ein Device-Uebergang traegt ein direktes Ziel"),
    );
    let server_certificate_hash = CertificateHash::from(
        server_head
            .direct_object_hash
            .expect("ein Device-Uebergang traegt ein direktes Ziel"),
    );
    let anchor_bytes = line.exact_anchor_bytes().to_vec();
    ReportLine {
        authority: DestructionAuthority {
            leases,
            writer_certificate_hash,
        },
        line,
        early_head,
        late_head,
        writer_certificate_hash,
        server_certificate_hash,
        anchor_bytes,
    }
}

/// Wie der `.eds` des Gesamtbestands mit dessen Vernichtung verbunden ist.
///
/// Die Ausgaenge sind NICHT Sichten auf denselben Bestand, sondern eigene
/// Bestaende: der Stummel bindet Kennung und Autorisierungshash in seine
/// Bytes ein, und damit haengt sein Objekthash daran.
///
/// Die drei Glieder der Pruefkette eines Lesers — Kennung, Autorisierungshash,
/// Ziel der Autorisierung — werden hier EINZELN gebrochen, damit ein Zeuge
/// jedes Glied fuer sich messen kann und keine zwei Brueche einander decken.
#[derive(Clone, Copy, Eq, PartialEq)]
enum StubAuthorizationV1 {
    /// Der Stummel nennt eine Kennung, die im Bestand auf nichts zeigt.
    Unresolvable,
    /// Der Stummel nennt die Kennung und den Autorisierungshash des Vorgangs,
    /// der tatsaechlich im Bestand liegt, und dessen Autorisierung nennt den
    /// Eintrag des Stummels.
    Resolvable,
    /// Der Stummel nennt die echte Kennung, aber einen Autorisierungshash,
    /// unter dem nichts liegt — ein kopiertes Manifest unter fremdem Siegel.
    ForgedAuthorizationHash,
    /// Kennung und Autorisierungshash treffen, aber die Autorisierung nennt
    /// einen ANDEREN Eintrag als den des Stummels.
    AuthorizationTargetingAnotherEntry,
}

/// Der Vernichtungsvorgang des Gesamtbestands.
///
/// Herausgezogen, weil der aufloesbare Stummel seine Kennung und seinen
/// Autorisierungshash NENNEN muss, bevor der Vorgang abgelegt ist; beide
/// entstehen erst in [`push_destruction`].
///
/// `target` ist der Eintrag, den die Autorisierung nennt — der des Stummels,
/// sofern der Bestand nicht gerade das Gegenteil zeigen soll. `None` laesst
/// das Pseudoziel aus [`DestructionSpec::new`] stehen.
fn report_destruction_spec(target: Option<(EntryHash, u64)>) -> DestructionSpec {
    let spec = DestructionSpec::new(
        REPORT_DESTRUCTION_MARKER_V1,
        &[
            DESTRUCTION_STATE_REQUESTED_V1,
            DESTRUCTION_STATE_IN_PROGRESS_V1,
            DESTRUCTION_STATE_COMPLETE_MANAGED_SCOPE_V1,
        ],
    )
    .with_attestation();
    match target {
        Some((entry_hash, chain_sequence)) => spec.targeting(entry_hash, chain_sequence),
        None => spec,
    }
}

/// Kennung und Autorisierungshash dieses Vorgangs, VORAB gerechnet.
///
/// Der Vorgang wird dafuer in einen Wegwerf-Bestand gelegt und dieser
/// verworfen. Das kostet einen zweiten Bau und haelt dafuer die Ablagestelle
/// der echten Vernichtung unveraendert am Ende des Bestands — aus dem Grund,
/// der dort steht. Zulaessig ist das, weil [`push_destruction`] deterministisch
/// ist: die Kennung kommt aus dem Marker, und Ed25519 signiert nach RFC 8032
/// ohne Zufall. Der Aufrufer reicht DENSELBEN Spec, den er spaeter ablegt —
/// sonst rechnete der Join einen Hash vor, der im Bestand nie erscheint.
fn report_destruction_join(
    authority: DestructionAuthority,
    spec: &DestructionSpec,
) -> (DestructionId, ObjectHash) {
    let mut scratch = ArchiveFixture::new();
    let built = push_destruction(&mut scratch, authority, spec);
    (built.destruction_id, built.authorization_object_hash)
}

/// Baut den Gesamtbestand.
///
/// Sein `.eds` nennt eine Vernichtung, die im Bestand auf NICHTS zeigt — der
/// Ausgang `ungeklaerte Luecke`. Den Gegenfall baut
/// [`report_archive_with_a_resolvable_stub`].
///
/// # Panics
///
/// Wenn eines der Fixture-Objekte sich nicht bauen oder kodieren laesst.
#[must_use]
pub fn complete_report_archive() -> ReportArchive {
    report_archive(StubAuthorizationV1::Unresolvable)
}

/// Derselbe Bestand, dessen `.eds` die Vernichtung darin AUFLOEST.
///
/// Der Stummel traegt `DestructionId([REPORT_DESTRUCTION_MARKER_V1; 16])` und
/// den Autorisierungshash des abgelegten Vorgangs, und dessen Autorisierung
/// nennt unter `targets` den Eintragshash und die Sequenz des Stummels. Die
/// Pruefkette eines Lesers — Kennung gegen
/// `VerificationReportV1::authorized_destructions`, Hash gegen den Hash des
/// Berichts, Eintrag gegen die Ziele der Autorisierung — schliesst sich damit
/// an jedem Glied. Alles Uebrige ist byteweise der Bestand von
/// [`complete_report_archive`] — bis auf den Stummel selbst, dessen Objekthash
/// sich mit seinen Feldern aendert.
///
/// # Panics
///
/// Wie [`complete_report_archive`].
#[must_use]
pub fn report_archive_with_a_resolvable_stub() -> ReportArchive {
    report_archive(StubAuthorizationV1::Resolvable)
}

/// Derselbe Bestand mit einem GEFAELSCHTEN `.eds`.
///
/// Der Stummel nennt die echte Kennung des abgelegten Vorgangs, aber als
/// Autorisierungshash `[FORGED_STUB_AUTHORIZATION_MARKER_V1; 32]`. Ein Join,
/// der allein ueber die Kennung laeuft, hielte ihn fuer aufgeloest; die
/// Pruefkette bricht am zweiten Glied.
///
/// # Panics
///
/// Wie [`complete_report_archive`].
#[must_use]
pub fn report_archive_with_a_stub_naming_a_forged_authorization_hash() -> ReportArchive {
    report_archive(StubAuthorizationV1::ForgedAuthorizationHash)
}

/// Derselbe Bestand, dessen Vernichtung einen ANDEREN Eintrag nennt.
///
/// Kennung und Autorisierungshash des Stummels treffen den abgelegten
/// Vorgang; dessen Autorisierung nennt aber das Pseudoziel
/// `[REPORT_DESTRUCTION_MARKER_V1; 32]` statt des Stummel-Eintrags. Die
/// Pruefkette bricht am dritten Glied. Dieser Bestand unterscheidet sich von
/// [`report_archive_with_a_resolvable_stub`] also in Autorisierung UND Stummel,
/// weil der Stummel den Hash der anderen Autorisierung traegt.
///
/// # Panics
///
/// Wie [`complete_report_archive`].
#[must_use]
pub fn report_archive_with_a_stub_of_an_authorization_targeting_another_entry() -> ReportArchive {
    report_archive(StubAuthorizationV1::AuthorizationTargetingAnotherEntry)
}

fn report_archive(stub_authorization: StubAuthorizationV1) -> ReportArchive {
    let line = report_line();
    let anchor = line.anchor();
    let chain_id = anchor.chain_id();
    let mut fixture = ArchiveFixture::new();
    let trust_object_count = push_trust_objects(&mut fixture, &line.line);

    let own_plan_hash = complete_grant_plan_hash(
        complete_recipient_key_thumbprint(),
        complete_recipient_certificate_hash(),
    );
    let foreign_plan_hash = complete_grant_plan_hash(
        other_recipient_key_thumbprint(),
        other_recipient_certificate_hash(),
    );
    let own_public_key = complete_recipient_private_key().public_key();
    let foreign_public_key = other_recipient_private_key().public_key();

    let mut valid_entry_object_hashes = Vec::new();
    let mut confirmed_entry_object_hashes = Vec::new();
    let mut receipt_object_hashes = Vec::new();
    let mut previous_entry_hash: Option<EntryHash> = None;
    let mut head_entry_hash = None;
    let mut destroyed_stub_object_hash = None;
    let mut destruction_spec = None;

    // Die Sequenzen bis oberhalb der Luecke, in AUFSTEIGENDER Ordnung: nur
    // vorwaerts laesst sich eine Registrierungslinie nachziehen.
    for sequence in REPORT_EARLY_SEQUENCE_V1..=REPORT_TRAILING_SEQUENCE_V1 {
        let head = line.head_for(sequence);
        let own = sequence != REPORT_EARLY_SEQUENCE_V1;
        let plan_hash = if own {
            own_plan_hash
        } else {
            foreign_plan_hash
        };
        let entry = build_complete_entry(
            head,
            line.writer_certificate_hash,
            chain_id,
            plan_hash,
            sequence,
            previous_entry_hash,
            COMPLETE_PLAINTEXT_V1,
        );
        let entry_bytes = encode_entry_package(&entry)
            .expect("das Fixture-Eintragspaket muss kodieren")
            .into_vec();
        let entry_object_hash = object_hash(&entry_bytes);
        let entry_hash = entry.entry_hash();
        let receipt_previous_entry_hash = previous_entry_hash;
        previous_entry_hash = Some(entry_hash);
        if sequence == REPORT_HEAD_SEQUENCE_V1 {
            head_entry_hash = Some(entry_hash);
        }

        // DER STUMMEL STATT DES EINTRAGS: das `.eip` wird gebaut, damit seine
        // Bytes einen Objekthash haben, den der Stummel bezeugen kann — und
        // ausdruecklich NICHT abgelegt. Genau so sieht ein autorisiert
        // vernichteter Eintrag aus, und genau so entsteht die Luecke.
        if sequence == REPORT_DESTROYED_STUB_SEQUENCE_V1 {
            // Die Autorisierung nennt den Eintrag des Stummels — ausser der
            // Bestand soll gerade zeigen, was geschieht, wenn sie es nicht tut.
            let spec = report_destruction_spec(match stub_authorization {
                StubAuthorizationV1::AuthorizationTargetingAnotherEntry => None,
                _ => Some((entry_hash, sequence)),
            });
            let (destruction_id, authorization_object_hash) =
                report_destruction_join(line.authority, &spec);
            destruction_spec = Some(spec);
            destroyed_stub_object_hash = Some(match stub_authorization {
                StubAuthorizationV1::Unresolvable => {
                    push_destroyed_stub_for(&mut fixture, sequence, &entry, entry_object_hash)
                }
                StubAuthorizationV1::Resolvable
                | StubAuthorizationV1::AuthorizationTargetingAnotherEntry => {
                    push_destroyed_stub_authorized_by(
                        &mut fixture,
                        sequence,
                        &entry,
                        entry_object_hash,
                        destruction_id,
                        authorization_object_hash,
                    )
                }
                StubAuthorizationV1::ForgedAuthorizationHash => push_destroyed_stub_authorized_by(
                    &mut fixture,
                    sequence,
                    &entry,
                    entry_object_hash,
                    destruction_id,
                    ObjectHash::try_from(&[FORGED_STUB_AUTHORIZATION_MARKER_V1; 32][..])
                        .expect("32 Bytes sind ein Objekthash"),
                ),
            });
            continue;
        }

        fixture.push_exact_bytes(
            &format!("{}{sequence:012}_entry.eip", ea_archive::ENTRIES_DIR_V1),
            entry_bytes,
        );
        valid_entry_object_hashes.push(entry_object_hash);

        let grant = complete_grant_bytes(
            head,
            line.writer_certificate_hash,
            chain_id,
            entry_hash,
            sequence,
            if own {
                complete_recipient_key_thumbprint()
            } else {
                other_recipient_key_thumbprint()
            },
            if own {
                complete_recipient_certificate_hash()
            } else {
                other_recipient_certificate_hash()
            },
            if own {
                &own_public_key
            } else {
                &foreign_public_key
            },
        );
        push_grant(&mut fixture, sequence, grant);

        if REPORT_RECEIPTED_SEQUENCES_V1.contains(&sequence) {
            let bytes = receipt_bytes(
                head,
                line.server_certificate_hash,
                plan_hash,
                chain_id,
                sequence,
                entry_hash,
                entry_object_hash,
                receipt_previous_entry_hash,
                None,
            );
            receipt_object_hashes.push(object_hash(&bytes));
            confirmed_entry_object_hashes.push(entry_object_hash);
            fixture.push_exact_bytes(
                &format!("{}{sequence:012}_receipt.esr", ea_archive::RECEIPTS_DIR_V1),
                bytes,
            );
        }
    }
    let head_entry_hash = head_entry_hash.expect("die Kette traegt einen Kopf");
    let destroyed_stub_object_hash =
        destroyed_stub_object_hash.expect("der Stummel liegt im Bestand");

    // DER CHECKPOINT, und mit ihm das Evidence-Objekt mit Serverzeitstempel.
    // Er bezeugt genau das verifizierte Praefix und ist damit widerspruchsfrei;
    // ein Checkpoint oberhalb des Kopfes waere ein Rueckbaubefund und gehoert zu
    // den Fixtures, die genau den zeigen sollen.
    let checkpoint_object_hash = push_checkpoint(
        &mut fixture,
        line.head_for(REPORT_HEAD_SEQUENCE_V1),
        line.server_certificate_hash,
        chain_id,
        REPORT_LATE_LEASE_FROM_V1,
        REPORT_HEAD_SEQUENCE_V1,
        head_entry_hash,
    );

    // DAS DUPLIKAT: dieselben Bytes unter zwei Hinweisen.
    let duplicate_object_hash = {
        let head = line.head_for(REPORT_DUPLICATE_SEQUENCE_V1);
        let entry = build_complete_entry(
            head,
            line.writer_certificate_hash,
            chain_id,
            own_plan_hash,
            REPORT_DUPLICATE_SEQUENCE_V1,
            previous_entry_hash,
            COMPLETE_PLAINTEXT_V1,
        );
        let bytes = encode_entry_package(&entry)
            .expect("das Fixture-Eintragspaket muss kodieren")
            .into_vec();
        previous_entry_hash = Some(entry.entry_hash());
        for hint in ["entry.eip", "entry_copy.eip"] {
            fixture.push_exact_bytes(
                &format!(
                    "{}{REPORT_DUPLICATE_SEQUENCE_V1:012}_{hint}",
                    ea_archive::ENTRIES_DIR_V1
                ),
                bytes.clone(),
            );
        }
        object_hash(&bytes)
    };

    // DER KONFLIKT: zwei Eintraege auf derselben Sequenz. Sie tragen KEINEN
    // Grant — ein isoliertes Objekt wird nicht benutzt, und ein Grant darauf
    // waere ein zweiter Befund auf einem zweiten Objekt.
    let mut conflicting_object_hashes = Vec::new();
    for nonce_marker in REPORT_FORK_NONCE_MARKERS_V1 {
        let head = line.head_for(REPORT_FORK_SEQUENCE_V1);
        let built = build_entry(&EntrySpec {
            chain_id,
            chain_sequence: REPORT_FORK_SEQUENCE_V1,
            previous_entry_hash,
            writer_certificate_hash: line.writer_certificate_hash,
            registry_version: head.version,
            registry_head_hash: head.hash,
            nonce_marker,
            plan: GrantPlanSpec::Omitted,
        });
        conflicting_object_hashes.push(object_hash(&built.bytes));
        fixture.push_exact_bytes(
            &format!(
                "{}{REPORT_FORK_SEQUENCE_V1:012}_entry_{nonce_marker:02x}.eip",
                ea_archive::ENTRIES_DIR_V1
            ),
            built.bytes,
        );
    }
    assert!(
        conflicting_object_hashes[0] != conflicting_object_hashes[1],
        "die beiden konkurrierenden Eintraege muessen verschiedene Objekte sein"
    );

    // DIE UNLESBAREN BYTES: ein Exact-Object-Praefix mit verkipptem Rumpf. Sie
    // beanspruchen kein Sequenzfach und erzeugen deshalb PAARWEISE genau einen
    // `formatError` und einen Quarantaeneeintrag.
    let malformed = archive_support::eip_with_one_mutated_body_byte();
    let malformed_object_hash = object_hash(&malformed);
    fixture.push_exact_bytes(
        &format!("{}malformed.eip", ea_archive::ENTRIES_DIR_V1),
        malformed,
    );

    // DIE VERNICHTUNG, mit Ereigniskette und Loeschbestaetigung.
    //
    // ZULETZT abgelegt und ZULETZT geprueft: ihre `authorizationSequence` liegt
    // oberhalb jeder Eintragssequenz, und die Registrierungslinie laesst sich
    // nur VORWAERTS nachziehen. Liefe dieser Schritt frueher, zoege er die Linie
    // ueber die Lease des spaeten Kopfes hinaus und kein Eintrag waere danach
    // noch zuzuordnen (`crates/ea-verify/src/archive.rs:503-522`).
    let destructions = vec![push_destruction(
        &mut fixture,
        line.authority,
        &destruction_spec.expect("der Stummel hat den Vorgang festgelegt"),
    )];

    // DAS NICHT-ARCHIVOBJEKT: Bytes OHNE Exact-Object-Praefix. Sie sind kein
    // Archivobjekt und werden nie isoliert — sie zaehlen.
    fixture.push_non_object(ea_archive::README_FORMAT_FILE_V1, b"Einsatzarchiv v1\n");

    ReportArchive {
        fixture,
        anchor_bytes: line.anchor_bytes,
        early_registry_version: line.early_head.version,
        late_registry_version: line.late_head.version,
        valid_entry_object_hashes,
        confirmed_entry_object_hashes,
        duplicate_object_hash,
        conflicting_object_hashes,
        destroyed_stub_object_hash,
        checkpoint_object_hash,
        malformed_object_hash,
        receipt_object_hashes,
        destructions,
        trust_object_count,
        non_object_count: 1,
    }
}
