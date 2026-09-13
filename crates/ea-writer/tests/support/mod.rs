//! Die Fixture der Finalisierungstests.
//!
//! Drei Zusagen tragen dieses Modul:
//!
//! 1. **Jeder Test serialisiert sich selbst.** Eine prozessweite Sperre plus
//!    eine eigene Temporaerwurzel je Test, nach dem Muster von
//!    `tools/xtask/tests/stage_gate.rs`. Die Wurzel entsteht aus einem
//!    MONOTONEN Zaehler und nicht aus Nanosekunden — derselbe beobachtete
//!    Kollisionsfall wie in `crates/ea-archive-fs/tests/support/mod.rs`. Kein
//!    Test dieses Ziels braucht `--test-threads=1`.
//! 2. **Kein zweiter Kryptobaukasten.** Registrierungslinie, Anker, Objekte
//!    und Signaturen kommen unveraendert aus dem `#[path]`-eingebundenen
//!    Supportmodul von `ea-trust`.
//! 3. **EINE Linie fuer alles.** Registry, Bedienerbindung, Profilzeile,
//!    Archivprofil und Schluesselspeicher gehoeren derselben Organisation und
//!    demselben Head. Zwei Linien hiessen zwei Wahrheiten, und eine von beiden
//!    waere zufaellig die falsche.
//!
//! # Was diese Fixture ANDERS macht als ihre Vorbilder
//!
//! Das Writer-Zertifikat traegt den oeffentlichen Signaturschluessel DIESES
//! Providers, und die Bedienerbindung traegt die aus DIESER Profilzeile
//! nachgerechnete Zusage. Ohne beides pruefte die Finalisierung gegen
//! synthetische Werte, und ihre zwei tragenden Vergleiche waeren Dekoration.
#![allow(dead_code)]

#[path = "../../../ea-trust/tests/support/mod.rs"]
pub mod trust_support;

use std::{
    cell::RefCell,
    fs,
    path::PathBuf,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use ea_archive::{ArchiveBackendProfileV1, BoundArchiveProfilePolicyV1, LocalPathProfileV1};
use ea_archive_fs::{CapabilityTestVectorV1, LocalPathBackend};
use ea_crypto::CanonicalPublicCoseKey;
use ea_draft::{
    AutosaveDraftRepository, DraftRepository, IncidentNumberRegister, OperatorProfileRepository,
};
use ea_format::{CertificateKindV1, KeyProtectionProfileV1, OperatorRoleV1};
use ea_key_provider::{InMemoryKeyProvider, KeyHandle, KeyProvider, SecretPurpose};
use ea_local_store::{EncryptedDatabase, StoreValue};
use ea_operator::{
    BoundOperator, OperatorAuthenticator, OperatorError, OperatorSessionProof, OsAccountProvider,
    ReauthPurpose,
};
use ea_schema::NativeSourceV1;
use ea_time::TrustedTimeState;
use ea_trust::{
    ClockReleaseReplayKey, IndependentTimeCommit, PersistedTrustRecord, RegistryHeadPin,
    RegistrySelectionCommit, RegistrySelectionOutcome, SelectedRegistryHead, StateStoreError,
    TrustStateKey, TrustStateStore, prepare_local_time, select_registry_head,
    verify_registry_candidate,
};
use ea_types::{
    CertificateHash, ChainSequence, DeviceId, EntryHash, Hash32, KeyThumbprint, ObjectHash,
    OrganizationId, UnixMillis,
};
use ea_writer::{
    FinalizationFaultPoint, FinalizationInputV1, KeyTransitionInputV1, ReachedState,
    WriterBindingV1, WriterError, WriterService,
};
use ed25519_dalek::{Signer as _, SigningKey};

use trust_support::{ActionSpec, HeadOptions, Pin, RegistryLineBuilder};

/// Der Bedienerinstanzschluessel der Fixture — ein ECHTES Ed25519-Paar.
const INSTANCE_SECRET: [u8; 32] = [
    0x2f, 0x8d, 0x11, 0x4c, 0x63, 0xa0, 0xde, 0x57, 0x94, 0x21, 0xbb, 0x0e, 0x77, 0xf3, 0x48, 0x9c,
    0x15, 0x6a, 0xd2, 0x30, 0xcb, 0x84, 0x39, 0x62, 0xe1, 0x0d, 0x5f, 0xa7, 0x48, 0x76, 0x91, 0x23,
];
/// Der Signaturschluessel des Writer-Zertifikats der ZWEITEN Linie.
///
/// Er existiert ALLEIN, damit eine zweite Bedienerbindung mit einem anderen
/// Objekthash entsteht (siehe
/// [`WriterHarness::proof_of_another_operator_binding`]). Ein anderer
/// Signaturschluessel ist die kleinste Abweichung, die den Zertifikatshash und
/// damit den Bindungshash verschiebt, ohne irgendeine markerabgeleitete
/// Groesse anzuruehren.
const OTHER_WRITER_SECRET: [u8; 32] = [
    0x51, 0xac, 0x0d, 0x74, 0x2e, 0xb8, 0x96, 0x1f, 0x43, 0xd5, 0x60, 0x8a, 0x27, 0xce, 0x19, 0xb3,
    0x7d, 0x04, 0xe2, 0x5b, 0x98, 0x36, 0xaf, 0x11, 0x6c, 0xd9, 0x40, 0x83, 0x2a, 0xf7, 0x65, 0x1e,
];
/// Der Seed des Schluesselspeichers des NEUEN Writer-Geraets.
///
/// Ein ZWEITER Provider und nicht ein zweiter Schluessel im ersten: die
/// Adresse eines Griffs ist (Speicher, Konto, Zweck), und `WriterSigningKey`
/// ist je Konto GENAU EIN Platz. Ein zweites `generate` schriebe frisches
/// Material an dieselbe Adresse — das ist der Fall, den
/// [`WriterHarness::with_variant`] fuer den Datenbankschluessel ausdruecklich
/// ausschliesst. Der neue Writer ist ein anderes Geraet, und das ist hier
/// wortwoertlich so gebaut.
const NEW_WRITER_PROVIDER_SEED: [u8; 32] = [0x9e; 32];
/// Der private X25519-Schluessel des OEFFENBAREN Recovery-Empfaengers.
///
/// Die Vorgabe-Empfaengerschluessel der Fixture (`kem_key`) sind blosse
/// oeffentliche Punkte ohne privates Gegenstueck: mit ihnen kann KEIN Test
/// einen veroeffentlichten Eintrag oeffnen. Ein Zeuge, der die versiegelte
/// Nutzlast eines `keyTransition` nachlesen muss, braucht einen Empfaenger,
/// dessen Geheimnis er kennt.
const OPENABLE_RECOVERY_SECRET: [u8; 32] = [
    0x6b, 0x1e, 0x3f, 0xa8, 0x90, 0x27, 0xd4, 0x5c, 0x12, 0xf0, 0x8b, 0x39, 0xc6, 0x4d, 0xe7, 0x71,
    0x0a, 0x95, 0x2c, 0xb3, 0x58, 0xdf, 0x46, 0x8e, 0x63, 0x1a, 0xf9, 0x24, 0xc1, 0x7d, 0x0f, 0x52,
];
/// Die organisatorische Begruendung der Uebergangszeugen — ein Kanarienvogel,
/// der in KEINEM veroeffentlichten Bytestrom auftauchen darf.
pub const CANARY_TRANSITION_REASON: &str = "CANARY-TRANSITION-REASON-Schluesselwechsel";
const BINDING_MARKER: u8 = 0x22;
const WRITER_MARKER: u8 = 0x61;
/// Der Marker des ZWEITEN Writer-Zertifikats derselben Linie.
const NEW_WRITER_MARKER: u8 = 0x67;
const RECOVERY_MARKER: u8 = 0x62;
const READER_ONE_MARKER: u8 = 0x63;
const READER_TWO_MARKER: u8 = 0x64;
const SECOND_RECOVERY_MARKER: u8 = 0x65;
const SERVER_RECEIPT_MARKER: u8 = 0x66;

/// Der Ausstellungszeitpunkt jedes Head-Ereignisses und der Bezugspunkt des
/// Vertrauensalters — 2026-01-01T00:00:00Z.
///
/// Eine ECHTE Zeit und kein kleiner Zaehler: das oertliche Kalenderjahr des
/// Einsatzes geht in den Registerschluessel der Einsatznummer ein
/// (`design.md`:361-373), und mit einer Zeit nahe der Epoche waere dieses Jahr
/// 1970 — ein Schluessel, den kein Test absichtlich waehlen wuerde.
const FIXTURE_ISSUED_AT_MS: i64 = 1_767_225_600_000;
/// Die Betriebssystemuhr der Fixture, und damit `effectiveNow` des Head: eine
/// Stunde nach der Ausstellung.
const FIXTURE_NOW_MS: i64 = FIXTURE_ISSUED_AT_MS + 3_600_000;
/// `notAfter` des Head. Hinter [`FIXTURE_NOW_MS`], damit der glatte Pfad einen
/// FRISCHEN Head hat, und innerhalb von `maxRegistryAgeMs = 86_400_000`, damit
/// die Kandidatenpruefung ihn annimmt.
const FIXTURE_NOT_AFTER_MS: i64 = FIXTURE_ISSUED_AT_MS + 86_399_000;
/// Eine Auffrischungsfrist UNTER dem Alter des Head zur beobachteten Zeit
/// (eine Minute gegen eine Stunde) — der einzige Weg zu einer ueberschrittenen
/// Frist bei einem FRISCHEN Head.
const FIXTURE_SHORT_TRUST_REFRESH_MS: u64 = 60_000;
/// Das oertliche Kalenderjahr des Einsatzes in `Europe/Berlin`.
pub const FIXTURE_LOCAL_CIVIL_YEAR: i32 = 2026;
mod incident_input;
pub use incident_input::FIXTURE_INCIDENT_NUMBER;
/// Die Sequenz, die die Fixture beansprucht. Ein LEERER Bestand hat keinen
/// verifizierten Kopf, also ist die einzige gueltige Sequenz die NULL.
const PROPOSED_SEQUENCE: u64 = 0;
const FIXTURE_PROVIDER_SEED: [u8; 32] = [0x7c; 32];

/// Die Profilzeile der Fixture — EINGEFROREN.
const FIXTURE_DISPLAY_NAME: &str = "Ada Lovelace";
const FIXTURE_FUNCTION_LABEL: &str = "Einsatzleitung";
const FIXTURE_PROFILE_COMMITMENT_SALT: [u8; 32] = [0x33; 32];

const DATABASE_FILE: &str = "writer.sqlite3";
/// Die Beiwerkdateien der SQLite-Datenbank und die Sperrdatei des Entwurfs.
///
/// Dieselbe Liste und dieselbe Begruendung wie in
/// `crates/ea-draft/tests/support/mod.rs`: eine Rueckspielung, die ein WAL
/// stehen laesst, das die Sicherung nicht kennt, waere eine Mischung aus zwei
/// Zustaenden und keine Rueckspielung.
const DATABASE_SIDECARS: [&str; 2] = ["writer.sqlite3-wal", "writer.sqlite3-shm"];
const LOCK_FILE: &str = "writer.sqlite3.draft-lock";

static HARNESS_LOCK: Mutex<()> = Mutex::new(());
static ROOT_COUNTER: AtomicU64 = AtomicU64::new(0);

fn take_lock() -> MutexGuard<'static, ()> {
    HARNESS_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

fn fixture_root(label: &str) -> PathBuf {
    let sequence = ROOT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let root = std::env::temp_dir().join(format!(
        "ea-writer-{label}-{}-{sequence}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("die Temporaerwurzel muss anlegbar sein");
    root
}

fn signing_key(secret: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&secret)
}

fn public_key(secret: [u8; 32]) -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::ed25519(signing_key(secret).verifying_key().to_bytes())
        .expect("der Instanzschluessel der Fixture ist gueltig")
}

/// Die NACHGERECHNETE Profilzusage dieser Profilzeile.
///
/// Sie entsteht ueber DIESELBE Domaine und DIESELBE Feldreihenfolge wie im
/// Writer (`design.md`:242-252) — aber ueber einen eigenen Kodierer, damit die
/// Zusicherung eine zweite Rechnung ist und nicht dieselbe zweimal.
fn expected_profile_commitment(organization: OrganizationId) -> Hash32 {
    let mut bytes = Vec::new();
    minicbor::Encoder::new(&mut bytes)
        .array(5)
        .and_then(|encoder| encoder.bytes(organization.as_bytes()))
        .and_then(|encoder| encoder.bytes(&[BINDING_MARKER; 16]))
        .and_then(|encoder| encoder.str(FIXTURE_DISPLAY_NAME))
        .and_then(|encoder| encoder.str(FIXTURE_FUNCTION_LABEL))
        .and_then(|encoder| encoder.bytes(&FIXTURE_PROFILE_COMMITMENT_SALT))
        .expect("das Urbild der Profilzusage kodiert");
    ea_crypto::operator_profile_digest(&bytes)
}

/// Eine Profilzusage, die zu KEINER Profilzeile dieser Fixture passt.
///
/// KEIN Nullhash: `Hash32::ZERO` waere auch der Wert eines vergessenen Feldes,
/// und ein Waechter, der gegen ihn anspricht, spraeche vielleicht gegen eine
/// Auslassung an und nicht gegen eine Abweichung.
fn foreign_profile_commitment() -> Hash32 {
    let mut bytes = [0x5a_u8; 32];
    bytes[0] = 0xa5;
    Hash32::try_from(bytes.as_slice()).expect("32 Byte sind 32 Byte")
}

fn head_options(effective_from: u64, valid_through: u64) -> HeadOptions {
    HeadOptions {
        effective_from: Some(effective_from),
        valid_through: Some(valid_through),
        issued_at: UnixMillis::new(FIXTURE_ISSUED_AT_MS),
        not_before: UnixMillis::new(FIXTURE_ISSUED_AT_MS - 10),
        not_after: UnixMillis::new(FIXTURE_NOT_AFTER_MS),
        ..HeadOptions::default()
    }
}

/// Ein X25519-Empfaengerschluessel je Empfaenger.
///
/// VERSCHIEDENE Schluessel: der Vorgabewert der Stufe-1-Fixture ist fuer JEDEN
/// Reader und JEDEN Recovery-Empfaenger derselbe, und `GrantPlanV1::new`
/// verbietet doppelte Empfaenger. Mit dem Vorgabewert waere der Plan „ein
/// Recovery plus zwei Reader" nicht baubar.
fn kem_key(marker: u8) -> CanonicalPublicCoseKey {
    let mut bytes = [0_u8; 32];
    bytes[0] = marker;
    bytes[31] = 0x40;
    CanonicalPublicCoseKey::x25519(bytes).expect("ein X25519-Schluessel ist 32 Byte lang")
}

/// Der private Schluessel des oeffenbaren Recovery-Empfaengers.
fn openable_recovery_private_key() -> ea_crypto::HpkeRecipientPrivateKey {
    ea_crypto::HpkeRecipientPrivateKey::from_bytes(ea_crypto::SecretBytes::new(
        OPENABLE_RECOVERY_SECRET,
    ))
    .expect("der oeffenbare Empfaengerschluessel ist ein X25519-Schluessel")
}

/// Der oeffentliche COSE-Schluessel zu [`openable_recovery_private_key`] —
/// derselbe Abdruck, den die Grants dieser Linie adressieren.
fn openable_recovery_public_key() -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::x25519(*openable_recovery_private_key().public_key().as_bytes())
        .expect("ein X25519-Punkt ist ein COSE-Schluessel")
}

/// Das ZWEITE Writer-Zertifikat einer Linie samt seiner Bedienerbindung.
#[derive(Clone, Copy)]
struct SecondWriterLine {
    certificate_hash: ObjectHash,
    binding_object_hash: ObjectHash,
}

/// Was aus der gebauten Linie herausgereicht wird.
struct BuiltLine {
    line: RegistryLineBuilder,
    binding_object_hash: ObjectHash,
    writer_certificate_hash: ObjectHash,
    /// Der Objekthash des Serverquittungszertifikats — `None`, solange die
    /// Variante es nicht anfordert.
    server_receipt_certificate_hash: Option<ObjectHash>,
    /// Das zweite Writer-Zertifikat und seine Bindung — `None`, solange kein
    /// zweiter Writer-Schluessel uebergeben wurde.
    second_writer: Option<SecondWriterLine>,
}

/// Wie eine Fixture von der glatten Linie abweicht.
#[derive(Clone, Copy, Default)]
pub struct LineVariantV1 {
    /// Der ZWEITE Reader traegt keinen KEM-Abdruck.
    pub reader_without_kem_key: bool,
    /// Ein ZWEITER Recovery-Empfaenger ist aktiv.
    pub second_recovery_recipient: bool,
    /// Die Policy traegt `operatingProfile = 1` — Evidence Grade.
    pub evidence_grade: bool,
    /// Die Policy traegt `registryExpiryBehavior = 1` — signiertes `block`.
    pub signed_block_expiry: bool,
    /// Die Policy traegt eine Auffrischungsfrist UNTER dem Alter, das der Head
    /// der Fixture zur beobachteten Zeit schon hat.
    ///
    /// Ohne sie ist eine ueberschrittene Frist bei einem FRISCHEN Head
    /// arithmetisch unerreichbar: die Vorgabe `86_400_000` liegt ueber der
    /// Lebensdauer des Head (`notAfter = issuedAt + 86_399_000`), und `Fresh`
    /// verlangt eine Zeit vor `notAfter`.
    pub short_reader_trust_refresh: bool,
    /// Die Bedienerbindung traegt eine ANDERE Profilzusage als die, die sich
    /// aus der Profilzeile dieser Fixture nachrechnen laesst.
    ///
    /// Der einzige Weg zu `EA-OPERATOR-PROFILE-COMMITMENT`: die Zusage steht in
    /// der SIGNIERTEN Bindung, und der Writer rechnet sie in Schritt 4 aus der
    /// lokalen Profilzeile nach. Stimmen beide ueberein — und in der glatten
    /// Fixture tun sie das per Konstruktion —, ist der Waechter eine Zeile, die
    /// kein Test je ausfuehrt.
    pub foreign_operator_profile_commitment: bool,
    /// Die Linie traegt ein Zertifikat der Art
    /// [`CertificateKindV1::ServerReceipt`].
    ///
    /// ADDITIV und per Vorgabe AUS: eingeschaltet schiebt es einen weiteren
    /// Registrierungskopf in die Linie und verschiebt damit jeden Kopfhash
    /// dahinter. Jede bestehende Fixture laesst es deshalb aus und sieht
    /// dieselbe Linie wie zuvor.
    ///
    /// Es existiert, weil Gate `receipt` ohne dieses Zertifikat gar nicht
    /// durchlaufen werden kann: `VerificationContext::receipt` verlangt die
    /// Capability `serverReceipt`, und ohne einen Bestand, in dem eine
    /// Serverquittung wirklich BESTAETIGT wird, bliebe die annehmende Haelfte
    /// des Quittungspfades ungetestet.
    pub with_server_receipt_certificate: bool,
    /// KEIN Recovery-Empfaenger ist aktiv.
    ///
    /// Das NULL-Bein der dritten Produktinvariante. Die beiden anderen Beine
    /// sind ueber `second_recovery_recipient` (zu viele) und ueber den
    /// vollstaendigen Plan (genau einer je aktivem Empfaenger) bezeugt; ohne
    /// diesen Knopf gibt es keinen Aufbau, in dem der Waechter
    /// `NoActiveRecoveryRecipient` ueberhaupt erreichbar ist.
    pub without_recovery_recipient: bool,
    /// Der Recovery-Empfaenger traegt einen Schluessel, dessen PRIVATES
    /// Gegenstueck die Fixture kennt ([`OPENABLE_RECOVERY_SECRET`]).
    ///
    /// ADDITIV und per Vorgabe AUS: der Vorgabeschluessel bleibt der blosse
    /// oeffentliche Punkt aus `kem_key`, und jede bestehende Fixture sieht
    /// dieselben Zertifikatsbytes wie zuvor. Eingeschaltet kann
    /// [`WriterHarness::decrypt_entry_as_recovery_recipient`] einen
    /// veroeffentlichten Eintrag wirklich oeffnen — ueber den Grant, HPKE und
    /// AEAD, wie ein Recovery-Empfaenger es tut.
    pub recovery_recipient_openable: bool,
    pub reader_recipient_openable: bool,
}

/// Baut die EINE Registrierungslinie der Fixture.
///
/// `second_writer_public_key` haengt ein ZWEITES Writer-Zertifikat und eine
/// Bindung DESSELBEN Bedieners daran — freigegeben und bereichsaktiv, aber
/// nicht der laufende Writer, solange kein Change 3 folgt. Genau die Lage vor
/// einem Writer-Uebergang. `None` laesst die Linie, wie sie war.
fn build_line(
    writer_public_key: &CanonicalPublicCoseKey,
    profile_hashes: Vec<Hash32>,
    variant: LineVariantV1,
    second_writer_public_key: Option<&CanonicalPublicCoseKey>,
) -> BuiltLine {
    let mut line = RegistryLineBuilder::new();
    line.push(
        ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        HeadOptions {
            policy_allowed_archive_profile_hashes_override: Some(profile_hashes),
            policy_operating_profile_override: variant.evidence_grade.then_some(1),
            policy_registry_expiry_behavior_override: variant.signed_block_expiry.then_some(1),
            policy_reader_trust_refresh_ms_override: variant
                .short_reader_trust_refresh
                .then_some(FIXTURE_SHORT_TRUST_REFRESH_MS),
            ..head_options(0, 10)
        },
    );
    let writer = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: WRITER_MARKER,
            effective_from: Some(0),
        },
        HeadOptions {
            signing_public_key_override: Some(writer_public_key.clone()),
            ..head_options(0, 20)
        },
    );
    if !variant.without_recovery_recipient {
        line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::RecoveryRecipient,
                marker: RECOVERY_MARKER,
                effective_from: Some(0),
            },
            HeadOptions {
                kem_public_key_override: Some(if variant.recovery_recipient_openable {
                    openable_recovery_public_key()
                } else {
                    kem_key(RECOVERY_MARKER)
                }),
                ..head_options(0, 30)
            },
        );
    }
    line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Reader,
            marker: READER_ONE_MARKER,
            effective_from: Some(0),
        },
        HeadOptions {
            kem_public_key_override: Some(if variant.reader_recipient_openable {
                CanonicalPublicCoseKey::x25519(
                    *ea_crypto::HpkeRecipientPrivateKey::from_bytes(ea_crypto::SecretBytes::new(
                        [0x72; 32],
                    ))
                    .unwrap()
                    .public_key()
                    .as_bytes(),
                )
                .unwrap()
            } else {
                kem_key(READER_ONE_MARKER)
            }),
            ..head_options(0, 40)
        },
    );
    line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Reader,
            marker: READER_TWO_MARKER,
            effective_from: Some(0),
        },
        HeadOptions {
            kem_public_key_override: Some(kem_key(READER_TWO_MARKER)),
            omit_kem_public_key: variant.reader_without_kem_key,
            ..head_options(0, 50)
        },
    );
    if variant.second_recovery_recipient {
        line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::RecoveryRecipient,
                marker: SECOND_RECOVERY_MARKER,
                effective_from: Some(0),
            },
            HeadOptions {
                kem_public_key_override: Some(kem_key(SECOND_RECOVERY_MARKER)),
                ..head_options(0, 60)
            },
        );
    }
    let server_receipt_certificate_hash = variant.with_server_receipt_certificate.then(|| {
        line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::ServerReceipt,
                marker: SERVER_RECEIPT_MARKER,
                effective_from: Some(0),
            },
            head_options(0, 70),
        )
        .direct_object_hash
        .expect("das Serverquittungszertifikat ist ein direktes Ziel")
    });
    let writer_certificate_hash = writer
        .direct_object_hash
        .expect("das Writer-Zertifikat ist ein direktes Ziel");
    // Die Bindungsoptionen sind fuer BEIDE Bindungen dieselben: derselbe
    // Bediener meldet sich auf beiden Geraeten an. Nur das Zertifikat weicht
    // ab, und damit der Bindungshash.
    let binding_options = |valid_through: u64| HeadOptions {
        binding_instance_key_thumbprint_override: Some(KeyThumbprint::from(
            Hash32::try_from(
                public_key(INSTANCE_SECRET)
                    .thumbprint()
                    .as_bytes()
                    .as_slice(),
            )
            .expect("ein Thumbprint ist 32 Byte lang"),
        )),
        binding_operator_profile_commitment_override: Some(
            if variant.foreign_operator_profile_commitment {
                foreign_profile_commitment()
            } else {
                expected_profile_commitment(trust_support::organization())
            },
        ),
        ..head_options(0, valid_through)
    };
    let binding = line.push(
        ActionSpec::OperatorBinding {
            certificate_hash: writer_certificate_hash,
            role: OperatorRoleV1::Writer,
            marker: BINDING_MARKER,
            effective_from: Some(0),
        },
        binding_options(100),
    );
    let second_writer = second_writer_public_key.map(|public| {
        let certificate = line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::Writer,
                marker: NEW_WRITER_MARKER,
                effective_from: Some(0),
            },
            HeadOptions {
                signing_public_key_override: Some(public.clone()),
                ..head_options(0, 110)
            },
        );
        let certificate_hash = certificate
            .direct_object_hash
            .expect("das zweite Writer-Zertifikat ist ein direktes Ziel");
        let binding = line.push(
            ActionSpec::OperatorBinding {
                certificate_hash,
                role: OperatorRoleV1::Writer,
                marker: BINDING_MARKER,
                effective_from: Some(0),
            },
            binding_options(120),
        );
        SecondWriterLine {
            certificate_hash,
            binding_object_hash: binding
                .direct_object_hash
                .expect("die zweite Bedienerbindung ist ein direktes Ziel"),
        }
    });
    BuiltLine {
        binding_object_hash: binding
            .direct_object_hash
            .expect("die Bedienerbindung ist ein direktes Ziel"),
        writer_certificate_hash,
        server_receipt_certificate_hash,
        second_writer,
        line,
    }
}

struct ModelStore {
    key: TrustStateKey,
    revision: u64,
    trusted_time: TrustedTimeState,
    pinned_head: RegistryHeadPin,
}

impl TrustStateStore for ModelStore {
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        if key != self.key {
            return Err(StateStoreError::Conflict);
        }
        Ok(PersistedTrustRecord::new(
            self.revision,
            self.trusted_time.clone(),
            Some(self.pinned_head),
        ))
    }

    fn commit_independent_time(
        &mut self,
        _key: TrustStateKey,
        _expected_revision: u64,
        _commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }

    fn clock_release_consumed(
        &mut self,
        _key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        Ok(false)
    }

    fn commit_registry_selection(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        if key != self.key || expected_revision != self.revision {
            return Err(StateStoreError::Conflict);
        }
        self.revision += 1;
        self.trusted_time = commit.next_trusted_time().clone();
        self.pinned_head = *commit.next_head();
        Ok(PersistedTrustRecord::new(
            self.revision,
            self.trusted_time.clone(),
            Some(self.pinned_head),
        ))
    }
}

/// Waehlt den Head der Fixture FUER EINE Sequenz.
///
/// Die vorgeschlagene Sequenz steckt IM gewaehlten Head: Schritt 3 der
/// Finalisierung vergleicht sie gegen den aus committeten Bytes gerechneten
/// Kettenkopf und haelt bei Abweichung mit
/// `EA-WRITER-HEAD-RECONCILIATION-REQUIRED` an. Ein zweiter Eintrag braucht
/// deshalb einen fuer SEINE Sequenz gewaehlten Head und nicht den des ersten.
fn select_head_for_sequence(
    line: &RegistryLineBuilder,
    now_ms: i64,
    proposed: u64,
) -> SelectedRegistryHead {
    let head_index = line.heads().len() - 1;
    let head = line.heads()[head_index];
    let key = trust_support::state_key();
    let trusted_time = TrustedTimeState::initial(UnixMillis::new(now_ms));
    let trust = line.verified_with_record(Pin::Head(head_index), 17, trusted_time.clone(), key);
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(proposed))
        .expect("der Kandidat der Fixture muss verifizieren");
    let mut store = ModelStore {
        key,
        revision: 17,
        trusted_time,
        pinned_head: RegistryHeadPin::new(head.version, head.object_hash),
    };
    let local_time = prepare_local_time(&mut store, &candidate, UnixMillis::new(now_ms), &[])
        .expect("die lokale Zeit der Fixture muss vorbereitbar sein");
    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(candidate, local_time, None)
            .expect("die Auswahl der Fixture muss gelingen")
    else {
        panic!("die Fixture muss ihren eigenen aktuellen Head waehlen");
    };
    selected
}

fn select_head(line: &RegistryLineBuilder, now_ms: i64) -> SelectedRegistryHead {
    select_head_for_sequence(line, now_ms, PROPOSED_SEQUENCE)
}

struct FakeAccount {
    binding_hash: Hash32,
}

impl OsAccountProvider for FakeAccount {
    fn os_account_binding_hash(
        &self,
        _organization_id: OrganizationId,
        _device_id: DeviceId,
    ) -> Result<Hash32, OperatorError> {
        Ok(self.binding_hash)
    }

    fn operator_instance_public_key(
        &self,
    ) -> Result<Option<CanonicalPublicCoseKey>, OperatorError> {
        Ok(Some(public_key(INSTANCE_SECRET)))
    }
}

struct FakeAuthenticator {
    bound: BoundOperator,
    signing_key: SigningKey,
    challenges: RefCell<Vec<Vec<u8>>>,
}

impl OperatorAuthenticator for FakeAuthenticator {
    fn bound_operator(&self) -> &BoundOperator {
        &self.bound
    }

    fn prove_presence_and_sign(&self, challenge: &[u8]) -> Result<[u8; 64], OperatorError> {
        self.challenges.borrow_mut().push(challenge.to_vec());
        Ok(self.signing_key.sign(challenge).to_bytes())
    }
}

/// Das lokale Archivprofil der Fixture.
fn local_profile() -> ArchiveBackendProfileV1 {
    ArchiveBackendProfileV1::LocalPath(LocalPathProfileV1 {
        filesystem_row_id: "fixture-writer-fs".to_owned(),
        capability_test_vector_id: "cap-v1-writer".to_owned(),
    })
}

fn capability_test_vector() -> CapabilityTestVectorV1 {
    CapabilityTestVectorV1::new("stage2:writer-fixture", b"ea-writer capability probe")
        .expect("der Testvektor der Fixture ist gueltig")
}

/// Die geoeffnete verschluesselte Ablage.
///
/// Als eigener Wert, weil die Rueckspielung einer Sicherung sie SCHLIESSEN
/// muss: eine Datei unter einer offenen SQLite-Verbindung zu ersetzen waere
/// keine Rueckspielung, sondern ein halber Zustand.
struct OpenStore {
    database: Arc<EncryptedDatabase>,
    repository: Arc<dyn DraftRepository>,
}

/// Die geoeffnete Fixture.
pub struct WriterHarness {
    _lock: MutexGuard<'static, ()>,
    root: PathBuf,
    provider: Arc<InMemoryKeyProvider>,
    database_key: KeyHandle,
    draft_dek_handle: KeyHandle,
    open: Option<OpenStore>,
    /// Die Datenbankdateien, wie sie NACH dem Setzen der Profilzeile und dem
    /// Speichern des Entwurfs dalagen — an der GESCHLOSSENEN Datenbank
    /// genommen.
    backup: Vec<(String, Vec<u8>)>,
    backend: Arc<LocalPathBackend>,
    server_receipt_certificate_hash: Option<ObjectHash>,
    /// Das zweite Writer-Zertifikat der Linie — `None` in jeder Fixture, die
    /// keinen Writer-Uebergang vorbereitet.
    second_writer: Option<SecondWriterLine>,
    head: SelectedRegistryHead,
    binding: WriterBindingV1,
    line: RegistryLineBuilder,
}

impl WriterHarness {
    /// Eine Fixture mit gesetzter Profilzeile, gefuelltem Entwurf und LEEREM
    /// Bestand.
    #[must_use]
    pub fn with_incident() -> Self {
        Self::with_variant(LineVariantV1::default())
    }

    /// Der Fehler, mit dem die KANDIDATENPRUEFUNG diese Variante ablehnt.
    ///
    /// `None`, wenn die Variante eine gueltige Linie ergibt. Sie existiert,
    /// weil eine Variante, die Stufe 1 schon am Vertrauenspfad abweist, den
    /// Writer nie erreicht — und das ist eine Aussage, die belegt gehoert und
    /// nicht als Panik in einer Fixture.
    #[must_use]
    pub fn candidate_rejection(variant: LineVariantV1) -> Option<&'static str> {
        let provider = InMemoryKeyProvider::new_for_test(FIXTURE_PROVIDER_SEED);
        provider
            .generate(
                SecretPurpose::WriterSigningKey,
                KeyProtectionProfileV1::OsWrapped,
            )
            .expect("der In-Prozess-Provider erreicht OsWrapped");
        let writer_public = CanonicalPublicCoseKey::ed25519(
            provider
                .signing_public_key_for_test(SecretPurpose::WriterSigningKey)
                .expect("der erzeugte Signaturschluessel ist lesbar"),
        )
        .expect("ein erzeugter Ed25519-Schluessel ist gueltig");
        let profile_hash = local_profile()
            .profile_hash()
            .expect("das Profil der Fixture ist kodierbar");
        let built = build_line(&writer_public, vec![profile_hash], variant, None);
        let head_index = built.line.heads().len() - 1;
        let key = trust_support::state_key();
        let trusted_time = TrustedTimeState::initial(UnixMillis::new(FIXTURE_NOW_MS));
        let trust = built
            .line
            .verified_with_record(Pin::Head(head_index), 17, trusted_time, key);
        verify_registry_candidate(&trust, ChainSequence::new(PROPOSED_SEQUENCE))
            .err()
            .map(|error| error.code())
    }

    /// Eine Fixture, deren Registrierungslinie GENAU in einem Punkt abweicht.
    #[must_use]
    pub fn with_variant(variant: LineVariantV1) -> Self {
        Self::with_variant_and_second_writer(variant, None)
    }

    /// Wie [`Self::with_variant`], mit einem ZWEITEN Writer-Zertifikat auf
    /// derselben Linie — siehe [`build_line`].
    fn with_variant_and_second_writer(
        variant: LineVariantV1,
        second_writer_public_key: Option<&CanonicalPublicCoseKey>,
    ) -> Self {
        let lock = take_lock();
        ea_writer::reset_entropy_draws();
        let root = fixture_root("finalize");
        let provider = Arc::new(InMemoryKeyProvider::new_for_test(FIXTURE_PROVIDER_SEED));

        // Der Writer-Signaturschluessel entsteht IM Schluesselspeicher, und das
        // Zertifikat der Linie traegt genau seinen oeffentlichen Teil.
        let writer_signing_handle = provider
            .generate(
                SecretPurpose::WriterSigningKey,
                KeyProtectionProfileV1::OsWrapped,
            )
            .expect("der In-Prozess-Provider erreicht OsWrapped");
        let writer_public = CanonicalPublicCoseKey::ed25519(
            provider
                .signing_public_key_for_test(SecretPurpose::WriterSigningKey)
                .expect("der erzeugte Signaturschluessel ist lesbar"),
        )
        .expect("ein erzeugter Ed25519-Schluessel ist gueltig");

        // Der Profilhash kommt vom PROFIL und nicht von einem geoeffneten
        // Bestand: `open` verlangt die Policy, die ihn schon enthalten muss.
        let profile_hash = local_profile()
            .profile_hash()
            .expect("das Profil der Fixture ist kodierbar");
        // Die Linie und der Head entstehen ZUERST; die Policybindung des
        // Backends kommt danach aus GENAU der signierten Policy des gewaehlten
        // Head. Eine zweite, danebenlaufende Policy waere die Luecke, die die
        // Profilpruefung wertlos macht.
        let built = build_line(
            &writer_public,
            vec![profile_hash],
            variant,
            second_writer_public_key,
        );
        let head = select_head(&built.line, FIXTURE_NOW_MS);
        let backend = LocalPathBackend::open(
            root.join("archive"),
            local_profile(),
            &BoundArchiveProfilePolicyV1::from_policy(head.policy_fields()),
        )
        .expect("der Bestand der Fixture muss sich oeffnen lassen");

        // DER Griff, EINMAL erzeugt: ein zweites `generate` schriebe frisches
        // Material an dieselbe Adresse, und die Datenbank waere nach einer
        // Rueckspielung nicht mehr zu oeffnen.
        let database_key = provider
            .generate(
                SecretPurpose::LocalDatabaseKey,
                KeyProtectionProfileV1::OsWrapped,
            )
            .expect("der In-Prozess-Provider erreicht OsWrapped");
        let open = open_store(&root, &provider, &database_key);
        seed_operator_profile(&open.database, &built);
        let draft = open
            .repository
            .load_or_create()
            .expect("der Entwurf der Fixture muss entstehen");
        let saved = open
            .repository
            .save(draft.with_notes("CANARY-INCIDENT-TEXT"))
            .expect("die Fixture muss speichern koennen");
        // Die ADRESSE des `draftDEK` — Anbieter, Konto und Zweck — und kein
        // Abbild des Geheimnisses. Sie ist nach Schritt 13 dieselbe (der
        // Entwurfsspeicher bildet sie aus genau diesen drei Teilen), also ist
        // sie der Griff, unter dem gemessen wird, was der Writer nach dem
        // Abschluss noch hergeben kann.
        let draft_dek_handle = open
            .repository
            .draft_dek_handle(&saved)
            .expect("der Griff auf den draftDEK der Fixture muss lesbar sein");

        // Die Sicherung wird an der GESCHLOSSENEN Datenbank genommen, NACH der
        // Profilzeile und dem Entwurf: eine Kopie einer offenen WAL-Datenbank
        // waere ein halber Zustand, und die Rueckspielung rollte weiter zurueck
        // als der Test behauptet.
        drop(open);
        let backup = capture_database_files(&root);
        let open = open_store(&root, &provider, &database_key);

        let binding = WriterBindingV1 {
            binding_object_hash: built.binding_object_hash,
            writer_certificate_hash: built.writer_certificate_hash.into(),
            writer_key_thumbprint: writer_public.thumbprint(),
            writer_signing_handle,
            // Die Kettenkennung kommt aus DEM GEWAEHLTEN HEAD und nicht aus
            // einem eigenen Literal. Ein eigenes Literal war genau der Zustand,
            // den die Finalisierung inzwischen fail-closed abweist: die Bindung
            // behauptete eine Kette, die die Vertrauenslinie dieser Fixture
            // nicht fuehrt, und auf einem LEEREN Bestand faellt das nirgends
            // auf — dort gibt es keinen Knoten, an dem eine fremde Kennung
            // erkennbar waere.
            chain_id: head.chain_id(),
            archive_profile_hash: profile_hash,
        };

        Self {
            _lock: lock,
            root,
            provider,
            database_key,
            draft_dek_handle,
            open: Some(open),
            backup,
            server_receipt_certificate_hash: built.server_receipt_certificate_hash,
            second_writer: built.second_writer,
            backend: Arc::new(backend),
            head,
            binding,
            line: built.line,
        }
    }

    /// Die geoeffnete Ablage.
    fn store(&self) -> &OpenStore {
        self.open
            .as_ref()
            .expect("die Ablage der Fixture ist offen")
    }

    /// Die BEOBACHTETE Zeit des glatten Pfades — die Betriebssystemuhr der
    /// Fixture, dieselbe, die den Head ausgewaehlt hat.
    #[must_use]
    pub const fn observed_now(&self) -> UnixMillis {
        UnixMillis::new(FIXTURE_NOW_MS)
    }

    /// Eine beobachtete Zeit EINE Millisekunde hinter `notAfter` des gebundenen
    /// Head.
    ///
    /// Der Head war bei seiner AUSWAHL frisch — anders gaebe
    /// `select_registry_head` ihn gar nicht heraus — und ist zu dieser Zeit
    /// veraltet. Genau dieser Verlauf ist der Fall, den
    /// `registryExpiryBehavior` regelt.
    #[must_use]
    pub const fn observed_now_after_expiry(&self) -> UnixMillis {
        UnixMillis::new(FIXTURE_NOT_AFTER_MS + 1)
    }

    /// Das Alter, das der gebundene Head zur beobachteten Zeit hat —
    /// NACHGERECHNET aus den zwei Zeiten und nicht als Zahl wiederholt.
    #[must_use]
    pub fn expected_trust_age_ms(&self, observed_now: UnixMillis) -> u64 {
        u64::try_from(observed_now.get() - self.head.issued_at().get())
            .expect("die beobachtete Zeit liegt hinter der Ausstellung")
    }

    /// Der Dienst dieser Fixture.
    ///
    /// `source` kommt von aussen, weil [`Self::source`] einen kurzlebigen
    /// Adapter auf das Backend liefert: haelte die Fixture ihn, waere sie
    /// selbstreferenziell. Der Test haelt ihn, und der Dienst leiht ihn.
    #[must_use]
    pub fn service<'a>(&'a self, source: &'a dyn ea_archive::ArchiveSource) -> WriterService<'a> {
        WriterService::new(
            Arc::clone(&self.store().repository),
            Arc::clone(&self.provider) as Arc<dyn KeyProvider>,
            self.backend.as_ref(),
            source,
            &self.head,
            &[],
            IncidentNumberRegister::new(Arc::clone(&self.store().database)),
            OperatorProfileRepository::new(Arc::clone(&self.store().database)),
            self.binding,
        )
    }

    /// Derselbe Dienst mit einer ABWEICHENDEN Geraetebindung.
    ///
    /// Sie ist der einzige Weg, eine Bindung zu messen, die nicht zu dieser
    /// Vertrauenslinie gehoert: die Fixture bildet ihre Bindung aus GENAU dem
    /// gewaehlten Head, und eine unstimmige entsteht darum nur absichtlich.
    #[must_use]
    pub fn service_with_binding<'a>(
        &'a self,
        source: &'a dyn ea_archive::ArchiveSource,
        binding: WriterBindingV1,
    ) -> WriterService<'a> {
        WriterService::new(
            Arc::clone(&self.store().repository),
            Arc::clone(&self.provider) as Arc<dyn KeyProvider>,
            self.backend.as_ref(),
            source,
            &self.head,
            &[],
            IncidentNumberRegister::new(Arc::clone(&self.store().database)),
            OperatorProfileRepository::new(Arc::clone(&self.store().database)),
            binding,
        )
    }

    /// Derselbe Dienst mit erreichbaren SERVER-CHECKPOINTAUSSAGEN.
    ///
    /// Der glatte Pfad gibt `&[]` weiter. Ohne eine Aussage ueber DIESE Kette
    /// ist Schritt 2 `NotAssessable` (`ea_chain::assess_rollback`), und der
    /// Rollbackwaechter kann gar nicht ansprechen — er waere eine Zeile, die
    /// kein Test je ausfuehrt. Erst eine Aussage macht ihn messbar, und erst
    /// eine STIMMIGE Aussage daneben macht die Messung falsifizierbar.
    #[must_use]
    pub fn service_with_checkpoints<'a>(
        &'a self,
        source: &'a dyn ea_archive::ArchiveSource,
        checkpoint_claims: &'a [ea_chain::CheckpointClaim],
    ) -> WriterService<'a> {
        WriterService::new(
            Arc::clone(&self.store().repository),
            Arc::clone(&self.provider) as Arc<dyn KeyProvider>,
            self.backend.as_ref(),
            source,
            &self.head,
            checkpoint_claims,
            IncidentNumberRegister::new(Arc::clone(&self.store().database)),
            OperatorProfileRepository::new(Arc::clone(&self.store().database)),
            self.binding,
        )
    }

    /// Ein VOLLER Abschluss gegen einen Schluesselspeicher, dessen `delete`
    /// sein `Ok` meldet und NICHTS tut.
    ///
    /// Der Dienst bekommt den tauben Doppelgaenger, die Entwurfsablage behaelt
    /// den wahrhaftigen Provider — dieselbe Aufteilung wie in
    /// `DraftHarness::discard_service_with_deaf_keystore`: gemessen wird die
    /// Abwesenheitsbestaetigung des DIENSTES, und dafuer muss der Entwurf
    /// vorher normal lesbar und speicherbar sein.
    ///
    /// Kein dreizehnter Abbruchpunkt: `FinalizationFaultPoint` beschreibt
    /// STELLEN der Reihenfolge, und ein luegender Schluesselspeicher ist keine
    /// Stelle, sondern ein Verhalten eines Ports. `stage-2-fault-points.json`
    /// bleibt bei zwoelf.
    pub fn finalize_with_deaf_keystore(&self) -> Result<ea_writer::FinalizeOutcome, WriterError> {
        let source = self.source();
        let deaf: Arc<dyn KeyProvider> = Arc::new(DeafDeleteProvider {
            inner: Arc::clone(&self.provider),
        });
        let service = WriterService::new(
            Arc::clone(&self.store().repository),
            deaf,
            self.backend.as_ref(),
            &source,
            &self.head,
            &[],
            IncidentNumberRegister::new(Arc::clone(&self.store().database)),
            OperatorProfileRepository::new(Arc::clone(&self.store().database)),
            self.binding,
        );
        let proof = self.proof_for(ReauthPurpose::Finalize);
        let preview = service.preview(&proof, valid_incident(), self.observed_now())?;
        service.finalize(&proof, valid_incident(), &preview, self.observed_now())
    }

    /// Der Lesezugriff auf den Bestand.
    #[must_use]
    pub fn source(&self) -> ea_archive_fs::LocalPathArchiveSource<'_> {
        self.backend.as_archive_source()
    }

    #[must_use]
    pub fn backend(&self) -> &LocalPathBackend {
        &self.backend
    }

    /// Der GETEILTE Griff auf denselben Bestand.
    ///
    /// Er existiert fuer die Schale vor dem Kern: `ea-sync-client` reicht jeden
    /// synchronen Aufruf durch `spawn_blocking`, und das verlangt einen
    /// besitzenden `'static`-Wert. Ein zweiter, daneben geoeffneter Bestand
    /// waere ein zweiter Griff auf dieselben Bytes — und damit eine zweite
    /// Gelegenheit, sie verschieden zu sehen.
    #[must_use]
    pub fn backend_handle(&self) -> Arc<LocalPathBackend> {
        Arc::clone(&self.backend)
    }

    /// Finalisiert einen ZWEITEN Eintrag auf derselben Kette.
    ///
    /// Er braucht zweierlei, was der erste nicht braucht: eine ANDERE
    /// Einsatznummer — die Nummernvergabe laesst keine zweite Belegung zu —
    /// und eine Checkpoint-Aussage ueber den bereits committeten Kopf. Ohne
    /// die zweite bleibt Schritt 2 mit `EA-WRITER-HEAD-RECONCILIATION-REQUIRED`
    /// stehen: ohne Serveraussage ist der Rueckbau NICHT bewertbar, und
    /// fail-closed heisst dann anhalten.
    ///
    /// # Panics
    ///
    /// Wenn der zweite Abschluss nicht traegt.
    pub fn finalize_a_second_entry(
        &self,
        first: &ea_writer::FinalizeOutcome,
    ) -> ea_writer::FinalizeOutcome {
        let source = self.source();
        let claims = [ea_chain::CheckpointClaim {
            chain_id: self.head.chain_id(),
            covered_from_sequence: ChainSequence::new(0),
            covered_through_sequence: first.sequence,
            head_entry_hash: first.entry_hash,
            checkpoint_object_hash: ObjectHash::try_from([0xc7_u8; 32].as_slice())
                .expect("32 Byte sind ein Objekthash"),
        }];
        let head = select_head_for_sequence(
            &self.line,
            FIXTURE_NOW_MS,
            first.sequence.get().saturating_add(1),
        );
        let service = WriterService::new(
            Arc::clone(&self.store().repository),
            Arc::clone(&self.provider) as Arc<dyn KeyProvider>,
            self.backend.as_ref(),
            &source,
            &head,
            &claims,
            IncidentNumberRegister::new(Arc::clone(&self.store().database)),
            OperatorProfileRepository::new(Arc::clone(&self.store().database)),
            self.binding,
        );
        let proof = issue_proof(
            &head,
            self.binding.binding_object_hash,
            ReauthPurpose::Finalize,
        );
        let preview = service
            .preview(&proof, other_incident(), self.observed_now())
            .expect("die zweite Vorschau muss tragen");
        service
            .finalize(&proof, other_incident(), &preview, self.observed_now())
            .expect("der zweite Abschluss muss tragen")
    }

    /// Legt JEDES Trust-Objekt der Linie in den Bestand.
    ///
    /// Ohne diesen Schritt traegt der Bestand der Fixture zwar Eintraege und
    /// Grants, aber keine Vertrauensablage — und ein
    /// [`ea_verify::verify_archive`] darueber waehlt dann gar keinen
    /// Registrierungskopf, meldet null Objektergebnisse und kann folglich auch
    /// keine Serverquittung bestaetigen. Der Pfadhinweis ist ein HINWEIS;
    /// klassifiziert wird am Exact-Object-Praefix
    /// (`crates/ea-archive/src/source.rs`).
    ///
    /// Sie wird AUSDRUECKLICH nicht beim Aufbau gerufen: die Finalisierungs-
    /// und Wiederherstellungstests messen Bestandsgroessen und
    /// Gesundheitsbefunde ueber einem Bestand, der nur enthaelt, was der
    /// Writer selbst geschrieben hat.
    ///
    /// # Panics
    ///
    /// Wenn die Linie nicht aufzaehlbar oder der Bestand nicht beschreibbar ist.
    pub fn materialize_trust_objects(&self) {
        let source = self.line.source();
        let mut hashes = Vec::new();
        ea_trust::TrustObjectSource::visit_trust_object_hashes(&source, &mut |hash| {
            hashes.push(hash);
            Ok(())
        })
        .expect("die Linie muss aufzaehlen");
        for hash in hashes {
            let bytes = ea_trust::TrustObjectSource::read_exact_trust_object(&source, hash)
                .expect("die Linie muss lesen")
                .expect("ein aufgezaehltes Trust-Objekt muss lesbar sein");
            let name: String = hash
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            self.backend.materialize_for_test(
                &format!("{}{name}.etb", ea_archive::REGISTRY_EVENTS_DIR_V1),
                &bytes,
            );
        }
    }

    /// Der Objekthash des Serverquittungszertifikats dieser Linie.
    ///
    /// `None`, solange die Variante es nicht angefordert hat — und dann kann
    /// ueber dieser Linie auch keine Quittung bestaetigt werden, weil Gate
    /// `receipt` die Capability `serverReceipt` verlangt.
    #[must_use]
    pub const fn server_receipt_certificate_hash(&self) -> Option<ObjectHash> {
        self.server_receipt_certificate_hash
    }

    /// Die EXAKTEN Ankerbytes dieser Linie.
    ///
    /// Neben [`Self::anchor`], weil ein Verifikationslauf hinter einer
    /// `spawn_blocking`-Grenze den Anker nicht ausleihen kann und
    /// `TrustAnchorV1` nicht `Clone` ist; die Bytes reisen, der Anker entsteht
    /// drueben aus GENAU ihnen.
    #[must_use]
    pub fn anchor_bytes(&self) -> Vec<u8> {
        self.line.exact_anchor_bytes().to_vec()
    }

    /// Finalisiert GENAU EINEN Eintrag und laesst ihn committet liegen.
    ///
    /// Die Kulisse jedes Sync-Tests: eine Warteschlange entsteht nur aus
    /// committeten Archivbytes, also muss vorher wirklich einer committet
    /// worden sein.
    ///
    /// # Panics
    ///
    /// Wenn die Finalisierung nicht traegt.
    #[must_use]
    pub fn finalize_once(&self) -> ea_writer::FinalizeOutcome {
        let source = self.source();
        let service = self.service(&source);
        let proof = self.proof_for(ReauthPurpose::Finalize);
        let preview = service
            .preview(&proof, valid_incident(), self.observed_now())
            .expect("die Vorschau der Fixture muss tragen");
        service
            .finalize(&proof, valid_incident(), &preview, self.observed_now())
            .expect("die Finalisierung der Fixture muss tragen")
    }

    #[must_use]
    pub const fn head(&self) -> &SelectedRegistryHead {
        &self.head
    }

    #[must_use]
    pub const fn binding(&self) -> WriterBindingV1 {
        self.binding
    }

    /// Der Vertrauensanker DIESER Linie.
    ///
    /// Er wird herausgegeben, weil ein Verifikationslauf UEBER den erzeugten
    /// Bestand gegen GENAU diesen Anker laufen muss; ein zweiter, daneben
    /// gebauter Anker waere eine zweite Wahrheit.
    #[must_use]
    pub fn anchor(&self) -> ea_trust::TrustAnchorV1 {
        ea_trust::decode_trust_anchor(self.line.exact_anchor_bytes())
            .expect("der Anker der Fixture muss dekodieren")
    }

    #[must_use]
    pub fn repository(&self) -> Arc<dyn DraftRepository> {
        Arc::clone(&self.store().repository)
    }

    #[must_use]
    pub fn provider(&self) -> Arc<InMemoryKeyProvider> {
        Arc::clone(&self.provider)
    }

    #[must_use]
    pub fn database(&self) -> Arc<EncryptedDatabase> {
        Arc::clone(&self.store().database)
    }

    /// Ein ECHTER Praesenznachweis fuer `purpose`, gegen den gewaehlten Head.
    #[must_use]
    pub fn proof_for(&self, purpose: ReauthPurpose) -> OperatorSessionProof {
        issue_proof(&self.head, self.binding.binding_object_hash, purpose)
    }

    pub fn context_proof(
        &self,
        preview: &ea_writer::FinalizationPreview,
        purpose: ReauthPurpose,
        now: UnixMillis,
    ) -> OperatorSessionProof {
        let time = self.reauthentication_time_at(now, false).unwrap();
        self.context_proof_with_time(preview, purpose, &time)
    }

    pub fn context_proof_with_time(
        &self,
        preview: &ea_writer::FinalizationPreview,
        purpose: ReauthPurpose,
        time: &ea_trust::PreexistingEffectiveNow,
    ) -> OperatorSessionProof {
        let authenticator = FakeAuthenticator {
            bound: BoundOperator::resolve(&self.head, self.binding.binding_object_hash).unwrap(),
            signing_key: signing_key(INSTANCE_SECRET),
            challenges: RefCell::new(Vec::new()),
        };
        authenticator
            .reauthenticate_for_context(
                Box::new(FakeAccount {
                    binding_hash: trust_support::hash32(BINDING_MARKER.wrapping_add(2)),
                }),
                purpose,
                time,
                preview.preview_hash(),
            )
            .unwrap()
    }

    pub fn reauthentication_time_at(
        &self,
        now: UnixMillis,
        independent_reference: bool,
    ) -> Result<ea_trust::PreexistingEffectiveNow, ea_trust::RegistryError> {
        let head_index = self.line.heads().len() - 1;
        let head = self.line.heads()[head_index];
        let key = trust_support::state_key();
        let trusted_time = TrustedTimeState::from_persisted(
            self.observed_now(),
            independent_reference.then(|| {
                ea_time::IndependentTimeInput::new(
                    ea_time::IndependentTimeKind::Receipt,
                    ObjectHash::from(trust_support::hash32(0x67)),
                    self.observed_now(),
                )
            }),
        )
        .unwrap();
        let trust =
            self.line
                .verified_with_record(Pin::Head(head_index), 17, trusted_time.clone(), key);
        let candidate = verify_registry_candidate(&trust, self.head.proposed_sequence()).unwrap();
        let mut store = ModelStore {
            key,
            revision: 17,
            trusted_time,
            pinned_head: RegistryHeadPin::new(head.version, head.object_hash),
        };
        let block = prepare_local_time(&mut store, &candidate, now, &[]).unwrap();
        block.reauthentication_time(&self.head)
    }

    /// A verified future policy successor to the still-pinned Writer Head.
    pub fn add_known_successor(&mut self, ready: UnixMillis) {
        self.line.push(
            ActionSpec::Policy {
                policy_version: None,
                previous_policy_hash: None,
                effective_from: None,
            },
            HeadOptions {
                issued_at: ready,
                not_before: UnixMillis::new(ready.get() - 1),
                not_after: UnixMillis::new(ready.get() + 1_000_000),
                policy_registry_expiry_behavior_override: Some(1),
                ..head_options(0, 1_000)
            },
        );
    }

    pub fn fallback_reauthentication_time(
        &self,
        now: UnixMillis,
    ) -> Result<ea_trust::PreexistingEffectiveNow, ea_trust::RegistryError> {
        let index = self.line.heads().len() - 2;
        let key = trust_support::state_key();
        let trusted_time = TrustedTimeState::initial(self.observed_now());
        let trust = self
            .line
            .verified_with_record(Pin::Head(index), 17, trusted_time.clone(), key);
        let successor = verify_registry_candidate(&trust, ChainSequence::new(0)).unwrap();
        let mut store = ModelStore {
            key,
            revision: 17,
            trusted_time,
            pinned_head: RegistryHeadPin::new(
                self.head.registry_version(),
                self.head.registry_head_hash(),
            ),
        };
        let time = prepare_local_time(&mut store, &successor, self.observed_now(), &[]).unwrap();
        let RegistrySelectionOutcome::PendingFuture(pending) =
            select_registry_head(successor, time, None).unwrap()
        else {
            panic!("the signed successor must still be future at observation");
        };
        let fallback = ea_trust::verify_current_head_fallback(&trust, pending).unwrap();
        prepare_local_time(&mut store, &fallback, now, &[])
            .unwrap()
            .reauthentication_time(&self.head)
    }

    pub fn stale_writer_head(&self, now: UnixMillis) -> ea_trust::StaleWriterRegistryHead {
        let key = trust_support::state_key();
        let trusted_time = TrustedTimeState::initial(now);
        let index = self.line.heads().len() - 1;
        let trust = self
            .line
            .verified_with_record(Pin::Head(index), 17, trusted_time.clone(), key);
        let candidate = verify_registry_candidate(&trust, self.head.proposed_sequence()).unwrap();
        let mut store = ModelStore {
            key,
            revision: 17,
            trusted_time,
            pinned_head: RegistryHeadPin::new(
                self.head.registry_version(),
                self.head.registry_head_hash(),
            ),
        };
        let time = prepare_local_time(&mut store, &candidate, now, &[]).unwrap();
        ea_trust::select_stale_writer_registry_head(candidate, time).unwrap()
    }
    pub fn service_for_writer<'a>(
        &'a self,
        source: &'a dyn ea_archive::ArchiveSource,
        head: ea_trust::WriterRegistryHeadRef<'a>,
    ) -> WriterService<'a> {
        WriterService::new_for_writer(
            Arc::clone(&self.store().repository),
            Arc::clone(&self.provider) as Arc<dyn KeyProvider>,
            self.backend.as_ref(),
            source,
            head,
            &[],
            IncidentNumberRegister::new(self.database()),
            OperatorProfileRepository::new(self.database()),
            self.binding,
        )
    }
    pub fn writer_context_proof(
        &self,
        head: ea_trust::WriterRegistryHeadRef<'_>,
        purpose: ReauthPurpose,
        preview: Option<&ea_writer::FinalizationPreview>,
    ) -> OperatorSessionProof {
        let auth = FakeAuthenticator {
            bound: BoundOperator::resolve_writer(head, self.binding.binding_object_hash).unwrap(),
            signing_key: signing_key(INSTANCE_SECRET),
            challenges: RefCell::new(Vec::new()),
        };
        let account = Box::new(FakeAccount {
            binding_hash: trust_support::hash32(BINDING_MARKER.wrapping_add(2)),
        });
        if let Some(preview) = preview {
            auth.reauthenticate_for_context(
                account,
                purpose,
                head.preexisting_effective_now(),
                preview.preview_hash(),
            )
            .unwrap()
        } else {
            auth.reauthenticate(account, purpose).unwrap()
        }
    }

    pub fn reselected_head(&self, now: UnixMillis) -> SelectedRegistryHead {
        select_head(&self.line, now.get())
    }

    pub fn select_sequence(&mut self, proposed: u64) {
        self.head = select_head_for_sequence(&self.line, self.observed_now().get(), proposed);
    }

    pub fn candidate_beyond_lease(
        &self,
    ) -> Result<ea_trust::RegistryCandidate, ea_trust::RegistryError> {
        let index = self.line.heads().len() - 1;
        let trust = self.line.verified_with_record(
            Pin::Head(index),
            17,
            TrustedTimeState::initial(self.observed_now()),
            trust_support::state_key(),
        );
        verify_registry_candidate(
            &trust,
            ChainSequence::new(self.head.valid_through_sequence().get() + 1),
        )
    }

    pub fn audit_bytes(&self, id: ea_types::EventId) -> Vec<u8> {
        self.database()
            .query_row(
                "SELECT exact_bytes FROM local_audit_event WHERE event_id = ?1",
                &[StoreValue::Blob(id.as_bytes().to_vec())],
            )
            .unwrap()
            .unwrap()
            .blob(0)
            .unwrap()
            .to_vec()
    }

    pub fn reopen_store(&mut self) {
        self.open = None;
        self.open = Some(open_store(&self.root, &self.provider, &self.database_key));
    }

    /// Ein ECHTER, aber ABGELAUFENER Nachweis fuer `Finalize`.
    ///
    /// Er ist gegen DIESELBE Linie und DIESELBE Bindung ausgestellt — nur
    /// gegen einen FRUEHER gewaehlten Head. Sein Fuenfminutenfenster beginnt
    /// bei [`FIXTURE_ISSUED_AT_MS`] und endet lange vor der `effectiveNow` des
    /// gebundenen Head (eine Stunde spaeter). Die Bindung stimmt also, der
    /// Zweck stimmt, und ALLEIN die Zeit entscheidet — dieselbe Bauart wie
    /// `DraftHarness::expired_proof` auf der Verwerfensseite.
    #[must_use]
    pub fn expired_proof(&self) -> OperatorSessionProof {
        let earlier_head = select_head(&self.line, FIXTURE_ISSUED_AT_MS);
        issue_proof(
            &earlier_head,
            self.binding.binding_object_hash,
            ReauthPurpose::Finalize,
        )
    }

    /// Ein ECHTER, TAUFRISCHER Nachweis fuer `purpose` — aber fuer eine
    /// ANDERE Bedienerbindung.
    ///
    /// # Warum eine zweite Linie und nicht ein erfundener Hash
    ///
    /// `OperatorSessionProof` entsteht ausschliesslich ueber
    /// `OperatorAuthenticator::reauthenticate` aus einem `BoundOperator`, und
    /// der wiederum nur ueber `BoundOperator::resolve` aus einem Head, in dem
    /// die Bindung AKTIV ist. Ein Nachweis mit erfundenem Bindungshash ist
    /// nicht konstruierbar — und ein Dienst, der auf einen erfundenen Hash
    /// gebunden waere, faellt schon an `active_operator_binding_fields` und
    /// bezeugte damit einen ANDEREN Waechter unter demselben Code.
    ///
    /// Diese zweite Linie weicht in GENAU EINEM Punkt ab: ihr
    /// Writer-Zertifikat traegt einen anderen Signaturschluessel. Damit weicht
    /// der Zertifikatshash ab, damit die `certificateHash` der Bindung, damit
    /// ihr Objekthash. Alles Markerabgeleitete — `osAccountBindingHash`, die
    /// Instanzschluesselzusage, die Profilzusage — bleibt gleich, also meldet
    /// sich derselbe Bediener wirklich an, und der Nachweis ist echt.
    #[must_use]
    pub fn proof_of_another_operator_binding(
        &self,
        purpose: ReauthPurpose,
    ) -> OperatorSessionProof {
        let profile_hash = local_profile()
            .profile_hash()
            .expect("das Profil der Fixture ist kodierbar");
        let other = build_line(
            &public_key(OTHER_WRITER_SECRET),
            vec![profile_hash],
            LineVariantV1::default(),
            None,
        );
        let other_head = select_head(&other.line, FIXTURE_NOW_MS);
        issue_proof(&other_head, other.binding_object_hash, purpose)
    }

    /// Wie viele Grants der Plan tragen MUSS: ein Recovery plus jeder aktive
    /// Reader — ABGELEITET aus der synthetisierten Registry und nicht als Zahl
    /// wiederholt.
    #[must_use]
    pub fn expected_grant_count(&self) -> usize {
        self.head
            .active_certificates()
            .filter(|(_, fields)| {
                matches!(
                    fields.certificate_kind,
                    CertificateKindV1::Reader | CertificateKindV1::RecoveryRecipient
                )
            })
            .count()
    }

    #[must_use]
    pub fn expected_registry_version(&self) -> ea_types::RegistryVersion {
        self.head.registry_version()
    }

    /// Ob eine Einsatznummer im Register dieses Jahres schon verbraucht ist.
    #[must_use]
    pub fn incident_number_is_taken(&self, number: &str) -> bool {
        IncidentNumberRegister::new(Arc::clone(&self.store().database))
            .contains(
                trust_support::organization(),
                FIXTURE_LOCAL_CIVIL_YEAR,
                number,
            )
            .expect("das Register muss lesbar sein")
    }

    /// Nimmt die Profilzeile aus der verschluesselten Ablage.
    ///
    /// Der einzige Weg zu `EA-OPERATOR-PROFILE-MISSING`: die Fixture SETZT die
    /// Zeile beim Oeffnen (`seed_operator_profile`), weil ohne sie kein
    /// einziger glatter Pfad liefe. Ein Bestand ohne Zeile ist die Lage nach
    /// einer zurueckgespielten Sicherung, die aelter ist als die Bedieneranlage
    /// — und Schritt 4 MUSS dort abbrechen statt eine Momentaufnahme aus
    /// Vorgabewerten zu bauen.
    pub fn remove_operator_profile(&self) {
        self.store()
            .database
            .execute("DELETE FROM operator_profile", &[])
            .expect("die Profilzeile muss sich entfernen lassen");
    }

    /// Beansprucht die Nummer der Fixture VORAB im Register.
    ///
    /// Sie isoliert die Anspruchspruefung von der Kettenfortschreibung: ein
    /// zweiter Abschluss im selben Bestand faellt schon an Schritt 3, weil der
    /// gebundene Head fuer die verbrauchte Sequenz gewaehlt ist.
    pub fn preclaim_incident_number(&self) {
        IncidentNumberRegister::new(Arc::clone(&self.store().database))
            .claim(
                trust_support::organization(),
                FIXTURE_LOCAL_CIVIL_YEAR,
                FIXTURE_INCIDENT_NUMBER,
            )
            .expect("die Vorabbeanspruchung muss tragen");
    }

    /// Die Zahl der GESTAGTEN, noch nicht veroeffentlichten Objekte.
    #[must_use]
    pub fn staged_object_count(&self) -> usize {
        ["entries/", "grants/"]
            .into_iter()
            .flat_map(|directory| self.backend.relative_paths_below_for_test(directory))
            .filter(|path| path.ends_with(".staging"))
            .count()
    }

    /// Ob der aktive Entwurf LEER ist.
    #[must_use]
    pub fn draft_is_blank(&self) -> bool {
        self.store()
            .repository
            .load_or_create()
            .map(|draft| draft.notes().is_empty())
            .unwrap_or(false)
    }

    /// Ob der `draftDEK` des aktiven Entwurfs noch da ist.
    #[must_use]
    pub fn draft_dek_is_present(&self) -> bool {
        self.store().repository.load_or_create().is_ok()
    }

    /// Ob der SCHLUESSELSPEICHER den `draftDEK` dieser Fixture nicht mehr
    /// fuehrt.
    ///
    /// Eine ANDERE Frage als [`Self::draft_dek_is_present`], und die Trennung
    /// ist der Punkt: jene liest die ABLAGE (`load_or_create` scheitert, wenn
    /// die Entwurfszeile ihr Geheimnis nicht mehr findet), diese fragt den
    /// SCHLUESSELSPEICHER unter der Adresse, die die Fixture beim Saeen
    /// genommen hat. Nach einer Rueckspielung sind die beiden Antworten
    /// dasselbe Ereignis von zwei Seiten — und nur diese Seite ist keine
    /// Wiederholung der Bedingung, die den Fall ueberhaupt erkannt hat.
    ///
    /// # Das Fenster, in dem dieser Leser etwas sagt
    ///
    /// Die Adresse ist (Speicher, Konto, `DraftDek`) und damit EIN Platz, den
    /// Schritt 13 mit dem Schluessel des neuen LEEREN Entwurfs wieder belegt.
    /// „Fort" ist deshalb die Aussage des Fensters ZWISCHEN dem Loeschen und
    /// dem leeren Entwurf — nach einem vollendeten Abschluss ist der Platz
    /// wieder belegt, und das ist die Nachbedingung und kein Verstoss. Was nach
    /// einem vollendeten Abschluss gemessen gehoert, ist
    /// [`Self::writer_keys_cannot_decrypt`].
    #[must_use]
    pub fn draft_dek_entry_is_absent(&self) -> bool {
        !self
            .provider
            .contains(&self.draft_dek_handle)
            .expect("der In-Prozess-Provider antwortet immer")
    }

    /// Die VEROEFFENTLICHTEN Eintraege — ohne jede Staging-Adresse.
    ///
    /// `"x.eip.staging".ends_with(".eip")` ist falsch, also trennt schon der
    /// Filter das Veroeffentlichte vom Vorbereiteten.
    #[must_use]
    pub fn published_entry_paths(&self) -> Vec<String> {
        self.backend
            .relative_paths_below_for_test("entries/")
            .into_iter()
            .filter(|path| path.ends_with(".eip"))
            .collect()
    }

    /// Die VEROEFFENTLICHTEN Grants — ohne jede Staging-Adresse.
    #[must_use]
    pub fn published_grant_paths(&self) -> Vec<String> {
        self.backend
            .relative_paths_below_for_test("grants/")
            .into_iter()
            .filter(|path| path.ends_with(".eag"))
            .collect()
    }

    /// Fuehrt eine Finalisierung, die an GENAU `point` abbricht.
    ///
    /// Fuer [`FinalizationFaultPoint::BackupRestoreAfterKeyDeletion`] ist der
    /// Abbruch nur die HAELFTE: der Punkt IST die Rueckspielung, und ohne sie
    /// waere er derselbe Programmpunkt wie
    /// [`FinalizationFaultPoint::AfterAbsenceConfirmation`] und damit eine
    /// Verdopplung statt einer zweiten Messung. Dieselbe Bauart wie
    /// `DraftHarness::discard_with_fault` in `ea-draft`.
    pub fn finalize_with_fault(
        &mut self,
        point: FinalizationFaultPoint,
    ) -> Result<ReachedState, WriterError> {
        let reached = {
            let source = self.source();
            let service = self.service(&source);
            let proof = self.proof_for(ReauthPurpose::Finalize);
            service.finalize_interrupted_at(&proof, valid_incident(), self.observed_now(), point)
        };
        if point == FinalizationFaultPoint::BackupRestoreAfterKeyDeletion {
            self.restore_captured_backup();
        }
        reached
    }

    /// Laesst BEIDE Sperrdateien liegen, als waere der Prozess unter ihnen
    /// gestorben.
    ///
    /// `SIGKILL` oder Stromausfall mitten in der Finalisierung hinterlaesst
    /// genau das: die Sperrdatei des Bestands und die des Entwurfs stehen da,
    /// aber kein Prozess haelt eine Sperre darauf. Der Neustartpfad
    /// [`ea_writer::WriterService::recover_pending`] nimmt BEIDE Sperren, in
    /// dieser Reihenfolge — solange sie am DASEIN der Dateien haengen, kommt
    /// er an keiner von beiden vorbei.
    ///
    /// AUSDRUECKLICH nicht [`Self::restore_captured_backup`]: das raeumt die
    /// Sperrdateien ab und stellte damit genau die Lage her, die hier gemessen
    /// werden soll, gerade NICHT her.
    pub fn leave_stale_lock_files(&self) {
        fs::write(
            self.backend.root().join(ea_archive_fs::CONTROL_FILES_V1[0]),
            b"",
        )
        .expect("die Sperrdatei des Bestands muss anlegbar sein");
        fs::write(self.root.join(LOCK_FILE), b"")
            .expect("die Sperrdatei des Entwurfs muss anlegbar sein");
    }

    /// Ob BEIDE Sperrdateien (noch) liegen.
    #[must_use]
    pub fn both_lock_files_are_present(&self) -> bool {
        self.backend
            .root()
            .join(ea_archive_fs::CONTROL_FILES_V1[0])
            .exists()
            && self.root.join(LOCK_FILE).exists()
    }

    /// Legt die aufgenommene Sicherung zurueck.
    ///
    /// Der Schluesselspeichereintrag kehrt NICHT zurueck: er ist geraetegebunden
    /// und liegt nicht in diesen Dateien. Genau diese Asymmetrie ist der Punkt.
    pub fn restore_captured_backup(&mut self) {
        // Erst schliessen: eine Datei unter einer offenen Verbindung zu
        // ersetzen ist keine Rueckspielung. Und erst alles fort, was jetzt
        // daliegt, sonst ueberlebte ein WAL, das die Sicherung nicht kennt.
        self.open = None;
        for name in std::iter::once(DATABASE_FILE)
            .chain(DATABASE_SIDECARS)
            .chain([LOCK_FILE])
        {
            let _ = fs::remove_file(self.root.join(name));
        }
        for (name, bytes) in &self.backup {
            fs::write(self.root.join(name), bytes).expect("die Sicherung muss schreibbar sein");
        }
        self.open = Some(open_store(&self.root, &self.provider, &self.database_key));
    }

    /// Ob eine liegende Abschlussmarke in der Ablage steht.
    #[must_use]
    pub fn prepared_marker_is_present(&self) -> bool {
        self.store()
            .repository
            .prepared_finalization_marker()
            .expect("die Ablage muss lesbar sein")
            .is_some()
    }

    /// Ob KEIN Geheimnis, das dieser Schluesselspeicher hergibt, den committed
    /// Eintrag oeffnet.
    ///
    /// # Was hier GEMESSEN wird
    ///
    /// Der Ciphertext des veroeffentlichten `.eip` wird mit JEDEM Geheimnis
    /// probiert, das der Provider dieses Writers ausgibt: der `draftDEK` unter
    /// seiner unveraenderten Adresse (nach Schritt 13 der des LEEREN Entwurfs),
    /// der Writer-Signaturschluessel und der Datenbankschluessel. Die
    /// Zusicherung ist FALSIFIZIERBAR: laege die CEK dieses Eintrags an einer
    /// dieser Adressen, oeffnete `aead_open` und die Antwort waere `false`.
    /// Damit sie nicht leer ist, MUSS mindestens ein Geheimnis wirklich bis
    /// `aead_open` gekommen sein.
    ///
    /// # Was hier NICHT gemessen wird
    ///
    /// „Kein privater Reader- oder Recovery-Schluessel auf dem Writer" ist eine
    /// Aussage des TYPSYSTEMS und nicht dieser Messung: `SecretPurpose` hat vier
    /// Varianten, und keine davon ist ein KEM-Empfaengerzweck
    /// (`crates/ea-key-provider/src/contract.rs`, `KeyPurpose` fuehrt sie als
    /// FREMDES Material). Ein solcher Schluessel ist an diesem Port nicht
    /// speicherbar.
    #[must_use]
    pub fn writer_keys_cannot_decrypt(&self, entry_hash: EntryHash) -> bool {
        let entry = self.published_entry(entry_hash);
        let nonce = ea_crypto::SecretBytes::new(entry.value().manifest().fields().nonce);
        let aad = ea_crypto::payload_aad(entry.value().manifest().exact_bytes());

        // POSITIVKONTROLLE: mit dem RICHTIGEN Schluessel oeffnet derselbe
        // Aufruf ueber dieselbe Nonce und dieselben Zusatzdaten. Ohne sie waere
        // ein fehlgeschlagenes `aead_open` unten auch dann gruen, wenn Nonce,
        // Zusatzdaten oder der Ciphertextschnitt gar nicht die dieses Eintrags
        // waeren — die Zusicherung koennte nicht mehr fehlschlagen.
        let control_key = ea_crypto::SecretBytes::new([0x5c; 32]);
        let control = ea_crypto::aead_seal(
            &control_key,
            &nonce,
            ea_crypto::SecretVec::new(b"KONTROLLE".to_vec()),
            &aad,
        )
        .expect("die Kontrolle muss versiegeln");
        assert!(
            ea_crypto::aead_open(&control_key, &nonce, &control, &aad).is_ok(),
            "Nonce und Zusatzdaten dieses Eintrags sind benutzbar"
        );

        // JEDE der vier Adressen dieses Schluesselspeichers, und nicht nur die
        // drei, die diese Finalisierung benutzt: `SecretPurpose` ist
        // geschlossen, also ist die Aufzaehlung vollstaendig, und ein
        // Schluessel, der die CEK an einer unbenutzten Adresse aufbewahrte,
        // faellt genauso auf.
        let account = self.database_key.account_instance();
        let keystore = self.database_key.keystore_provider();
        // Die abgeleitete Adresse IST die des Entwurfsschluessels. Ohne diese
        // Gleichheit koennte die Aufzaehlung an vier leeren Adressen probieren
        // und waere gruen, ohne etwas zu beruehren.
        assert!(
            KeyHandle::new(keystore, account, SecretPurpose::DraftDek) == self.draft_dek_handle,
            "die abgeleiteten Adressen sind die des Entwurfsspeichers"
        );
        let mut secrets = Vec::new();
        for purpose in [
            SecretPurpose::WriterSigningKey,
            SecretPurpose::OperatorInstanceKey,
            SecretPurpose::DraftDek,
            SecretPurpose::LocalDatabaseKey,
        ] {
            let handle = KeyHandle::new(keystore, account, purpose);
            if let Ok(secret) = self.provider.unwrap_secret(&handle) {
                secrets.push(secret);
            }
            if let Ok(database_key) = self.provider.unwrap_database_key(&handle) {
                database_key.with_exposed(|raw| {
                    if let Ok(exact) = <[u8; 32]>::try_from(raw) {
                        secrets.push(ea_crypto::SecretBytes::new(exact));
                    }
                });
            }
        }
        assert!(
            !secrets.is_empty(),
            "die Zusicherung waere leer: kein einziges Geheimnis ist bis aead_open gekommen"
        );
        secrets.iter().all(|secret| {
            ea_crypto::aead_open(secret, &nonce, entry.value().ciphertext(), &aad).is_err()
        })
    }

    /// Der VEROEFFENTLICHTE Eintrag mit diesem `entryHash`, dekodiert.
    ///
    /// # Panics
    ///
    /// Wenn unter `entries/` kein Eintrag mit diesem Hash liegt oder die
    /// liegenden Bytes kein Eintragspaket sind.
    #[must_use]
    pub fn published_entry(
        &self,
        entry_hash: EntryHash,
    ) -> ea_format::Parsed<ea_format::EntryPackageV1> {
        let path = self
            .published_entry_paths()
            .into_iter()
            .find(|path| path.contains(&hex(entry_hash.as_bytes())))
            .expect("der committed Eintrag muss unter seinem Layoutnamen liegen");
        let bytes = self
            .backend
            .read_for_test(&path)
            .expect("das committed .eip muss lesbar sein");
        let parsed =
            ea_format::decode_exact_object(&bytes).expect("das committed .eip muss dekodieren");
        let ea_format::ParsedArchiveObject::Entry(entry) = parsed else {
            panic!("unter entries/ liegt ein Eintragspaket");
        };
        // `assert_eq!` verlangt `Debug`, und Stufe 1 leitet fuer `EntryHash`
        // keines ab — ein Hash gehoert in keine Protokollzeile.
        assert!(
            entry.value().entry_hash() == entry_hash,
            "gemessen wird GENAU der Eintrag, dessen Hash der Abschluss gemeldet hat"
        );
        entry
    }

    /// JEDER veroeffentlichte Bytestrom des Bestands — Eintraege und Grants,
    /// ohne Staging-Adressen — als `(Pfad, Bytes)`.
    ///
    /// Die Kulisse eines Kanarienvogel-Zeugen: was hier NICHT vorkommt, hat
    /// der Writer nicht im Klartext veroeffentlicht.
    #[must_use]
    pub fn published_archive_bytes(&self) -> Vec<(String, Vec<u8>)> {
        self.published_entry_paths()
            .into_iter()
            .chain(self.published_grant_paths())
            .map(|path| {
                let bytes = self
                    .backend
                    .read_for_test(&path)
                    .expect("ein veroeffentlichtes Objekt muss lesbar sein");
                (path, bytes)
            })
            .collect()
    }

    /// Oeffnet den veroeffentlichten Eintrag SO, wie der Recovery-Empfaenger
    /// ihn oeffnet: sein Grant, HPKE ueber `grant-context-v1`, dann AEAD ueber
    /// den Manifestkern. Liefert den Klartext der Nutzlast.
    ///
    /// Verlangt eine Linie mit
    /// [`LineVariantV1::recovery_recipient_openable`]; ohne sie gibt es keinen
    /// Empfaenger, dessen Geheimnis die Fixture kennt.
    ///
    /// # Panics
    ///
    /// Wenn kein Grant dieses Eintrags an den oeffenbaren Empfaenger
    /// adressiert ist oder eine der beiden Entschluesselungen scheitert.
    #[must_use]
    pub fn decrypt_entry_as_recovery_recipient(&self, entry_hash: EntryHash) -> Vec<u8> {
        let entry = self.published_entry(entry_hash);
        let private = openable_recovery_private_key();
        let thumbprint = openable_recovery_public_key().thumbprint();
        for path in self.published_grant_paths() {
            let bytes = self
                .backend
                .read_for_test(&path)
                .expect("ein veroeffentlichter Grant muss lesbar sein");
            let parsed = ea_format::decode_exact_object(&bytes)
                .expect("ein veroeffentlichter Grant muss dekodieren");
            let ea_format::ParsedArchiveObject::Grant(grant) = &parsed else {
                continue;
            };
            let body = grant.value().grant_body();
            let fields = body.fields();
            if fields.entry_hash != entry_hash || fields.recipient_key_thumbprint != thumbprint {
                continue;
            }
            let context = body
                .exact_grant_context()
                .expect("ein veroeffentlichter Grant traegt seinen Kontext");
            let sealed =
                ea_crypto::HpkeSealed::from_parts(fields.encapsulated_key, fields.wrapped_cek)
                    .expect("die Kapselung des Grants ist wohlgeformt");
            let cek = ea_crypto::hpke_open(
                &private,
                &sealed,
                &ea_crypto::hpke_info(context),
                &ea_crypto::hpke_aad(context),
            )
            .expect("der oeffenbare Empfaenger entkapselt seinen Grant");
            let nonce = ea_crypto::SecretBytes::new(entry.value().manifest().fields().nonce);
            let aad = ea_crypto::payload_aad(entry.value().manifest().exact_bytes());
            let plaintext = ea_crypto::aead_open(&cek, &nonce, entry.value().ciphertext(), &aad)
                .expect("die CEK des Grants oeffnet den Eintrag");
            return plaintext.with_exposed(<[u8]>::to_vec);
        }
        panic!("kein Grant dieses Eintrags ist an den oeffenbaren Recovery-Empfaenger adressiert");
    }

    #[must_use]
    pub const fn root(&self) -> &PathBuf {
        &self.root
    }

    #[must_use]
    pub const fn line(&self) -> &RegistryLineBuilder {
        &self.line
    }
}

/// Das NEUE Writer-Geraet: eigener Schluesselspeicher, eigene Ablage, eigene
/// Bindung — und derselbe Bestand wie das alte.
///
/// Der neue Writer uebernimmt den Bestand, nicht die Datenbank: Profilzeile,
/// Entwurf und Nummernregister sind geraetegebunden und entstehen hier neu,
/// mit derselben Bedienerin auf demselben Bestand.
struct NewWriterDevice {
    provider: Arc<InMemoryKeyProvider>,
    open: OpenStore,
    binding: WriterBindingV1,
}

/// Die Kulisse eines Writer-Uebergangs: zwei Geraete, EIN Bestand, EINE Linie.
///
/// Sie besitzt eine [`WriterHarness`] (das alte Geraet, dem der Bestand und
/// die Sperre gehoeren) und ein [`NewWriterDevice`]. Der Change 3 wird ERST
/// gedrueckt, wenn der alte Writer seinen letzten Eintrag geschrieben hat:
/// der Uebergang nennt dessen `entryHash`, und der ist vorher nicht bekannt.
pub struct TransitionHarness {
    old: WriterHarness,
    new_device: NewWriterDevice,
    /// Die Linie OHNE den Change 3 — der stale Kopf des alten Writers.
    pre_transition_line: RegistryLineBuilder,
    transition_object_hash: Option<ObjectHash>,
}

impl TransitionHarness {
    /// Zwei Geraete auf einer Linie mit zwei freigegebenen Writer-Zertifikaten
    /// und noch OHNE Uebergang.
    ///
    /// # Panics
    ///
    /// Wenn Schluesselspeicher, Ablage oder Linie nicht entstehen.
    #[must_use]
    pub fn new() -> Self {
        let provider = Arc::new(InMemoryKeyProvider::new_for_test(NEW_WRITER_PROVIDER_SEED));
        let signing_handle = provider
            .generate(
                SecretPurpose::WriterSigningKey,
                KeyProtectionProfileV1::OsWrapped,
            )
            .expect("der In-Prozess-Provider erreicht OsWrapped");
        let public = CanonicalPublicCoseKey::ed25519(
            provider
                .signing_public_key_for_test(SecretPurpose::WriterSigningKey)
                .expect("der erzeugte Signaturschluessel ist lesbar"),
        )
        .expect("ein erzeugter Ed25519-Schluessel ist gueltig");
        let old = WriterHarness::with_variant_and_second_writer(
            LineVariantV1 {
                recovery_recipient_openable: true,
                ..LineVariantV1::default()
            },
            Some(&public),
        );
        let second = old
            .second_writer
            .expect("die Linie traegt das zweite Writer-Zertifikat");

        let root = old.root.join("new-writer");
        fs::create_dir_all(&root).expect("die Wurzel des neuen Geraets muss anlegbar sein");
        let database_key = provider
            .generate(
                SecretPurpose::LocalDatabaseKey,
                KeyProtectionProfileV1::OsWrapped,
            )
            .expect("der In-Prozess-Provider erreicht OsWrapped");
        let open = open_store(&root, &provider, &database_key);
        seed_operator_profile_for_binding(&open.database, second.binding_object_hash);
        let draft = open
            .repository
            .load_or_create()
            .expect("der Entwurf des neuen Geraets muss entstehen");
        open.repository
            .save(draft)
            .expect("das neue Geraet muss speichern koennen");

        let binding = WriterBindingV1 {
            binding_object_hash: second.binding_object_hash,
            writer_certificate_hash: second.certificate_hash.into(),
            writer_key_thumbprint: public.thumbprint(),
            writer_signing_handle: signing_handle,
            chain_id: old.head.chain_id(),
            archive_profile_hash: old.binding.archive_profile_hash,
        };
        let pre_transition_line = old.line.clone();
        Self {
            old,
            new_device: NewWriterDevice {
                provider,
                open,
                binding,
            },
            pre_transition_line,
            transition_object_hash: None,
        }
    }

    /// Das alte Geraet, dem der Bestand gehoert.
    #[must_use]
    pub const fn old(&self) -> &WriterHarness {
        &self.old
    }

    #[must_use]
    pub const fn old_mut(&mut self) -> &mut WriterHarness {
        &mut self.old
    }

    /// Der alte Writer schreibt seinen ersten — und letzten — Eintrag.
    ///
    /// # Panics
    ///
    /// Wenn die Finalisierung nicht traegt.
    #[must_use]
    pub fn old_writer_finalizes_first_entry(&self) -> ea_writer::FinalizeOutcome {
        self.old.finalize_once()
    }

    /// Drueckt den Change 3: ab `effective_from` schreibt der neue Writer, und
    /// der Uebergang nennt `previous_entry_hash` als letzten Eintrag des alten.
    ///
    /// Liefert den Objekthash des Root-signierten `writerTransition`-Objekts —
    /// GENAU den Hash, den das Manifest des ersten neuen Eintrags tragen muss.
    ///
    /// # Panics
    ///
    /// Wenn schon ein Uebergang gedrueckt wurde.
    pub fn activate_transition(
        &mut self,
        effective_from: u64,
        previous_entry_hash: EntryHash,
    ) -> ObjectHash {
        assert!(
            self.transition_object_hash.is_none(),
            "die Fixture drueckt GENAU EINEN Change 3"
        );
        let second = self
            .old
            .second_writer
            .expect("die Linie traegt das zweite Writer-Zertifikat");
        let head = self.old.line.push(
            ActionSpec::WriterTransition {
                old_writer: ObjectHash::try_from(
                    self.old
                        .binding
                        .writer_certificate_hash
                        .as_bytes()
                        .as_slice(),
                )
                .expect("ein Zertifikatshash ist ein 32-Byte-Objekthash"),
                new_writer: second.certificate_hash,
                effective_from: None,
            },
            HeadOptions {
                writer_transition_previous_entry_hash: Some(previous_entry_hash),
                ..head_options(effective_from, effective_from.saturating_add(129))
            },
        );
        let hash = head
            .direct_object_hash
            .expect("der Uebergang ist ein direktes Ziel");
        self.transition_object_hash = Some(hash);
        hash
    }

    /// Der Objekthash des gedrueckten Uebergangs.
    ///
    /// # Panics
    ///
    /// Wenn noch kein Uebergang gedrueckt wurde.
    #[must_use]
    pub fn transition_object_hash(&self) -> ObjectHash {
        self.transition_object_hash
            .expect("der Uebergang muss gedrueckt sein")
    }

    /// Der Kopf NACH dem Change 3, gewaehlt fuer `proposed`.
    ///
    /// # Panics
    ///
    /// Wenn noch kein Uebergang gedrueckt wurde.
    #[must_use]
    pub fn post_transition_head(&self, proposed: u64) -> SelectedRegistryHead {
        assert!(
            self.transition_object_hash.is_some(),
            "der Kopf nach dem Uebergang verlangt den Uebergang"
        );
        select_head_for_sequence(&self.old.line, FIXTURE_NOW_MS, proposed)
    }

    /// Der Kopf VOR dem Change 3 — der stale Kopf des alten Writers —,
    /// gewaehlt fuer `proposed`.
    #[must_use]
    pub fn pre_transition_head(&self, proposed: u64) -> SelectedRegistryHead {
        select_head_for_sequence(&self.pre_transition_line, FIXTURE_NOW_MS, proposed)
    }

    /// Eine Server-Checkpointaussage ueber den committeten Kopf `through`.
    #[must_use]
    pub fn checkpoint_claims_through(
        &self,
        through: &ea_writer::FinalizeOutcome,
    ) -> [ea_chain::CheckpointClaim; 1] {
        [ea_chain::CheckpointClaim {
            chain_id: self.old.head.chain_id(),
            covered_from_sequence: ChainSequence::new(0),
            covered_through_sequence: through.sequence,
            head_entry_hash: through.entry_hash,
            checkpoint_object_hash: ObjectHash::try_from([0xc7_u8; 32].as_slice())
                .expect("32 Byte sind ein Objekthash"),
        }]
    }

    /// Der Dienst des NEUEN Geraets auf dem GETEILTEN Bestand.
    #[must_use]
    pub fn new_writer_service<'a>(
        &'a self,
        source: &'a dyn ea_archive::ArchiveSource,
        head: &'a SelectedRegistryHead,
        checkpoint_claims: &'a [ea_chain::CheckpointClaim],
    ) -> WriterService<'a> {
        WriterService::new(
            Arc::clone(&self.new_device.open.repository),
            Arc::clone(&self.new_device.provider) as Arc<dyn KeyProvider>,
            self.old.backend.as_ref(),
            source,
            head,
            checkpoint_claims,
            IncidentNumberRegister::new(Arc::clone(&self.new_device.open.database)),
            OperatorProfileRepository::new(Arc::clone(&self.new_device.open.database)),
            self.new_device.binding,
        )
    }

    /// Der Dienst des ALTEN Geraets gegen einen beliebigen Kopf.
    #[must_use]
    pub fn old_writer_service<'a>(
        &'a self,
        source: &'a dyn ea_archive::ArchiveSource,
        head: &'a SelectedRegistryHead,
        checkpoint_claims: &'a [ea_chain::CheckpointClaim],
    ) -> WriterService<'a> {
        WriterService::new(
            Arc::clone(&self.old.store().repository),
            Arc::clone(&self.old.provider) as Arc<dyn KeyProvider>,
            self.old.backend.as_ref(),
            source,
            head,
            checkpoint_claims,
            IncidentNumberRegister::new(Arc::clone(&self.old.store().database)),
            OperatorProfileRepository::new(Arc::clone(&self.old.store().database)),
            self.old.binding,
        )
    }

    /// Ein ECHTER Nachweis der NEUEN Bindung gegen `head`.
    ///
    /// Nur gegen einen Kopf ausstellbar, auf dem das neue Zertifikat der
    /// laufende Writer ist — vorher ist es fuer `BoundOperator::resolve`
    /// nicht aktiv.
    #[must_use]
    pub fn new_writer_proof(&self, head: &SelectedRegistryHead) -> OperatorSessionProof {
        issue_proof(
            head,
            self.new_device.binding.binding_object_hash,
            ReauthPurpose::Finalize,
        )
    }

    /// Ein ECHTER Nachweis der ALTEN Bindung gegen `head`.
    #[must_use]
    pub fn old_writer_proof(&self, head: &SelectedRegistryHead) -> OperatorSessionProof {
        issue_proof(
            head,
            self.old.binding.binding_object_hash,
            ReauthPurpose::Finalize,
        )
    }

    #[must_use]
    pub fn new_writer_certificate_hash(&self) -> CertificateHash {
        self.new_device.binding.writer_certificate_hash
    }

    #[must_use]
    pub fn old_writer_certificate_hash(&self) -> CertificateHash {
        self.old.binding.writer_certificate_hash
    }

    /// Ob der `draftDEK` des NEUEN Geraets noch da ist.
    #[must_use]
    pub fn new_writer_draft_dek_is_present(&self) -> bool {
        self.new_device.open.repository.load_or_create().is_ok()
    }

    /// Ob eine Einsatznummer im Register des NEUEN Geraets verbraucht ist.
    #[must_use]
    pub fn new_writer_incident_number_is_taken(&self, number: &str) -> bool {
        IncidentNumberRegister::new(Arc::clone(&self.new_device.open.database))
            .contains(
                trust_support::organization(),
                FIXTURE_LOCAL_CIVIL_YEAR,
                number,
            )
            .expect("das Register muss lesbar sein")
    }

    /// Oeffnet einen veroeffentlichten Eintrag als Recovery-Empfaenger —
    /// siehe [`WriterHarness::decrypt_entry_as_recovery_recipient`].
    #[must_use]
    pub fn decrypt_entry_as_recovery_recipient(&self, entry_hash: EntryHash) -> Vec<u8> {
        self.old.decrypt_entry_as_recovery_recipient(entry_hash)
    }

    // -----------------------------------------------------------------------
    // Die Verwaltungsseite des Uebergangs (Stufe 5, Task 5, Systemzeuge)
    // -----------------------------------------------------------------------
    //
    // Die Methoden darunter existieren fuer GENAU EINEN Aufrufer:
    // `tests/ea-system-tests/tests/e2e_writer_transition.rs`, der den
    // Uebergang nicht ueber `activate_transition` von der Fixture signieren
    // laesst, sondern ueber `ea_admin::WriterTransitionService` und die
    // ECHTE Wurzelzeremonie (`RootCeremonyService::publish_authorized_target`)
    // — auf DIESER Linie, mit DIESEN beiden Writer-Geraeten. Die
    // Zeremonienfixture von `ea-admin` (`writer_transition_ceremony_line`)
    // baut ihre eigene Linie mit synthetischen Geraeteschluesseln; auf ihr
    // kann kein Writer einen Eintrag finalisieren. Die Linie muss deshalb
    // HIER bleiben, und die Verwaltung muss an sie heran: die Autorisierung
    // in den Katalog legen, den Kopf VOR dem Change 3 waehlen, und den
    // Change 3 mit dem Ereignis pushen, das die Ereignisfabrik von `ea-admin`
    // geplant hat. Alles ADDITIV; `activate_transition` bleibt, wie es war.

    /// Der Kopf der Linie, WIE SIE JETZT STEHT, gewaehlt fuer `proposed` —
    /// vor oder nach dem Change 3, ohne Behauptung darueber.
    ///
    /// Neben [`Self::pre_transition_head`], weil jener Kopf aus der KOPIE
    /// der Linie kommt, die beim Aufbau genommen wurde: eine Autorisierung,
    /// die [`Self::prepare_transition_authorization`] spaeter in den Katalog
    /// legt, kennt er nicht — und `ea_trust::verify_intended_trust_target`
    /// sucht sie im Katalog des GEWAEHLTEN Kopfes.
    #[must_use]
    pub fn line_head(&self, proposed: u64) -> SelectedRegistryHead {
        select_head_for_sequence(&self.old.line, FIXTURE_NOW_MS, proposed)
    }

    /// Legt die Administrationsautorisierung eines Uebergangs auf den neuen
    /// Writer ab `effective_from` mit `previous_entry_hash` in den Katalog —
    /// gebunden an den aktuellen Kopf, mit einem Nutzungsfenster um
    /// `effectiveNow` — und gibt ihren Objekthash samt der UNSIGNIERTEN
    /// Nutzlast heraus, die die Fixture fuer denselben Uebergang gebaut hat.
    ///
    /// Das Transitionsobjekt selbst bleibt aus dem Katalog fort: es entsteht
    /// in der Zeremonie. Dieselbe Bauart wie `writer_transition_ceremony_line`
    /// in `crates/ea-admin/tests/support/mod.rs`; der `reason_code` ist der
    /// der `ea-trust`-Fixture (`1`), und ein Antrag, der die Autorisierung
    /// nutzen will, muss ihn nennen.
    ///
    /// # Panics
    ///
    /// Wenn schon ein Uebergang gedrueckt wurde.
    pub fn prepare_transition_authorization(
        &mut self,
        effective_from: u64,
        previous_entry_hash: EntryHash,
    ) -> (ObjectHash, ea_format::TrustPayloadV1) {
        assert!(
            self.transition_object_hash.is_none(),
            "die Autorisierung gehoert VOR den Change 3"
        );
        let second = self
            .old
            .second_writer
            .expect("die Linie traegt das zweite Writer-Zertifikat");
        self.old.line.prepare_unsigned(
            ActionSpec::WriterTransition {
                old_writer: self.old_writer_certificate_object_hash(),
                new_writer: second.certificate_hash,
                effective_from: Some(effective_from),
            },
            HeadOptions {
                // Das Nutzungsfenster der Autorisierung ist
                // `(issued_at, issued_at + 1000)`; die Zeremonie nutzt sie
                // zur `effectiveNow` des gewaehlten Kopfes.
                issued_at: UnixMillis::new(FIXTURE_NOW_MS),
                writer_transition_previous_entry_hash: Some(previous_entry_hash),
                ..HeadOptions::default()
            },
        )
    }

    /// Drueckt den Change 3 mit einem VEROEFFENTLICHTEN Transitionsobjekt und
    /// dem Ereignis, das die Verwaltung dafuer geplant hat.
    ///
    /// Die Bytes wandern in den Katalog, der Kopf traegt GENAU `event` —
    /// `ChangeOverride::Raw` laesst die Fixture die Aenderung der Verwaltung
    /// uebernehmen, ihr eigenes Zielobjekt und dessen Autorisierung bleiben
    /// fort. Die Fixture signiert das EREIGNIS mit der Wurzel der Linie und
    /// stellt seine Autorisierung aus; das ZIEL hat sie nicht signiert.
    /// Dieselbe Bauart wie `the_full_transition_moves_the_current_writer_on_the_successor_head`
    /// in `crates/ea-admin/tests/writer_transition.rs`.
    ///
    /// # Panics
    ///
    /// Wenn schon ein Uebergang gedrueckt wurde.
    pub fn activate_published_transition(
        &mut self,
        exact_transition_object: &[u8],
        event: &ea_format::RegistryEventFieldsV1,
    ) -> trust_support::BuiltHead {
        assert!(
            self.transition_object_hash.is_none(),
            "die Fixture drueckt GENAU EINEN Change 3"
        );
        let second = self
            .old
            .second_writer
            .expect("die Linie traegt das zweite Writer-Zertifikat");
        self.old.line.add_object(exact_transition_object.to_vec());
        let head = self.old.line.push(
            ActionSpec::WriterTransition {
                old_writer: self.old_writer_certificate_object_hash(),
                new_writer: second.certificate_hash,
                effective_from: None,
            },
            HeadOptions {
                effective_from: Some(event.effective_from_sequence.get()),
                valid_through: Some(event.valid_through_sequence.get()),
                issued_at: event.issued_at,
                not_before: event.not_before,
                not_after: event.not_after,
                change_override: trust_support::ChangeOverride::Raw(event.change.clone()),
                omit_direct_object: true,
                omit_direct_authorization: true,
                ..HeadOptions::default()
            },
        );
        self.transition_object_hash = Some(ea_crypto::object_hash(exact_transition_object));
        head
    }

    /// Das alte Writer-Zertifikat als Objekthash — `ActionSpec` nennt seine
    /// Zertifikate als Objekte.
    fn old_writer_certificate_object_hash(&self) -> ObjectHash {
        ObjectHash::try_from(
            self.old
                .binding
                .writer_certificate_hash
                .as_bytes()
                .as_slice(),
        )
        .expect("ein Zertifikatshash ist ein 32-Byte-Objekthash")
    }

    /// Der Schluesselspeicher des NEUEN Geraets.
    ///
    /// Herausgegeben, damit ein Zeuge ein Manifest mit dem ECHTEN Schluessel
    /// des neuen Writers nachsignieren kann — ein Manifest, das sich vom
    /// veroeffentlichten allein im `writer_transition_event_hash`
    /// unterscheidet, ist die einzige saubere Kulisse fuer die Serverregel
    /// „fehlend, zusaetzlich oder abweichend".
    #[must_use]
    pub fn new_writer_provider(&self) -> Arc<InMemoryKeyProvider> {
        Arc::clone(&self.new_device.provider)
    }

    /// Die Bindung des NEUEN Geraets: Zertifikat, Griff, Kette.
    #[must_use]
    pub const fn new_writer_binding(&self) -> WriterBindingV1 {
        self.new_device.binding
    }

    /// Eine KOPIE des Bestands, wie er JETZT daliegt, als eigener Bestand
    /// unter der Wurzel des alten Geraets.
    ///
    /// Die Kulisse des zurueckgespielten alten Writers, der WEITERSCHREIBT:
    /// er arbeitet auf seiner Sicherung des Bestands, nicht auf dem
    /// geteilten. Auf dem geteilten Bestand koennte er es gar nicht — dort
    /// liegt ab dem Uebergang der Eintrag des neuen Writers an derselben
    /// Sequenz, und Schritt 3 hielte mit
    /// `EA-WRITER-HEAD-RECONCILIATION-REQUIRED` an, BEVOR ein Eintrag
    /// entsteht. Der Eintrag, den der Server abweisen muss, entsteht nur auf
    /// einem Bestand, der den Uebergang nicht kennt.
    ///
    /// Die Datenbank des alten Geraets bleibt, wie sie ist; die Rueckspielung
    /// der DATENBANK aus einer Sicherung bezeugt
    /// `crates/ea-writer/tests/key_transition.rs` (der `draftDEK` kehrt nicht
    /// zurueck, ein Abschluss scheitert dort an Schritt 9).
    ///
    /// # Panics
    ///
    /// Wenn die Kopie nicht anlegbar oder der Bestand nicht zu oeffnen ist.
    #[must_use]
    pub fn old_writer_archive_replica(&self) -> LocalPathBackend {
        let source = self.old.root.join("archive");
        let replica = self.old.root.join("restored-archive");
        assert!(
            !replica.exists(),
            "die Fixture legt GENAU EINE Kopie des Bestands an"
        );
        copy_directory(&source, &replica);
        LocalPathBackend::open(
            replica,
            local_profile(),
            &BoundArchiveProfilePolicyV1::from_policy(self.old.head.policy_fields()),
        )
        .expect("die Kopie des Bestands muss sich oeffnen lassen")
    }
}

/// Kopiert `source` samt Unterverzeichnissen nach `target`.
fn copy_directory(source: &std::path::Path, target: &std::path::Path) {
    fs::create_dir_all(target).expect("das Zielverzeichnis muss anlegbar sein");
    for entry in fs::read_dir(source).expect("das Quellverzeichnis muss lesbar sein") {
        let entry = entry.expect("ein Verzeichniseintrag muss lesbar sein");
        let path = entry.path();
        let destination = target.join(entry.file_name());
        if path.is_dir() {
            copy_directory(&path, &destination);
        } else {
            fs::copy(&path, &destination).expect("eine Bestandsdatei muss kopierbar sein");
        }
    }
}

impl Default for TransitionHarness {
    fn default() -> Self {
        Self::new()
    }
}

/// Stellt einen ECHTEN Praesenznachweis fuer `binding_object_hash` gegen `head`
/// aus.
///
/// EINE Stelle fuer alle drei Nachweise der Fixture — der frische, der
/// abgelaufene und der einer fremden Bindung. Waeren es drei Kopien, koennte
/// eine von ihnen leise etwas anderes tun als „derselbe Bediener meldet sich
/// wieder an", und genau das ist der Unterschied, den die drei Zusicherungen
/// messen.
fn issue_proof(
    head: &SelectedRegistryHead,
    binding_object_hash: ObjectHash,
    purpose: ReauthPurpose,
) -> OperatorSessionProof {
    let bound = BoundOperator::resolve(head, binding_object_hash)
        .expect("die Bindung ist an der gewaehlten Sequenz aktiv");
    let authenticator = FakeAuthenticator {
        bound,
        signing_key: signing_key(INSTANCE_SECRET),
        challenges: RefCell::new(Vec::new()),
    };
    let account: Box<dyn OsAccountProvider> = Box::new(FakeAccount {
        binding_hash: trust_support::hash32(BINDING_MARKER.wrapping_add(2)),
    });
    authenticator
        .reauthenticate(account, purpose)
        .expect("der gebundene Bediener meldet sich wieder an")
}

/// Ein Schluesselspeicher, der sein `delete` VERSCHLUCKT und `Ok` meldet.
///
/// Er existiert, damit die Abwesenheitsbestaetigung in Schritt 9 TRAGEND ist
/// und nicht dekorativ: gegen einen wahrhaftigen Provider kann sie nie
/// fehlschlagen, also waere `WriterError::KeyDeletionNotConfirmed` ohne diesen
/// Doppelgaenger eine Zeile, die kein Test je ausfuehrt. Wortgleich zum
/// Doppelgaenger der VERWERFENSSEITE (`crates/ea-draft/tests/support/mod.rs`) —
/// dieselbe Zusage, dieselbe Bauart, und die Asymmetrie zwischen den beiden
/// Seiten war der Befund.
struct DeafDeleteProvider {
    inner: Arc<InMemoryKeyProvider>,
}

impl KeyProvider for DeafDeleteProvider {
    fn generate(
        &self,
        purpose: SecretPurpose,
        protection: KeyProtectionProfileV1,
    ) -> Result<KeyHandle, ea_key_provider::KeyError> {
        self.inner.generate(purpose, protection)
    }

    fn sign(
        &self,
        handle: &KeyHandle,
        content_type: ea_crypto::ContentType,
        certificate_hash: ea_types::CertificateHash,
        payload: &[u8],
    ) -> Result<ea_key_provider::CoseSign1Bytes, ea_key_provider::KeyError> {
        self.inner
            .sign(handle, content_type, certificate_hash, payload)
    }

    fn wrap_secret(
        &self,
        purpose: SecretPurpose,
        secret: ea_crypto::SecretBytes<32>,
    ) -> Result<KeyHandle, ea_key_provider::KeyError> {
        self.inner.wrap_secret(purpose, secret)
    }

    fn unwrap_secret(
        &self,
        handle: &KeyHandle,
    ) -> Result<ea_crypto::SecretBytes<32>, ea_key_provider::KeyError> {
        self.inner.unwrap_secret(handle)
    }

    fn unwrap_database_key(
        &self,
        handle: &KeyHandle,
    ) -> Result<ea_crypto::SecretVec, ea_key_provider::KeyError> {
        self.inner.unwrap_database_key(handle)
    }

    /// Meldet Erfolg und tut NICHTS.
    fn delete(&self, _handle: &KeyHandle) -> Result<(), ea_key_provider::KeyError> {
        Ok(())
    }

    fn contains(&self, handle: &KeyHandle) -> Result<bool, ea_key_provider::KeyError> {
        self.inner.contains(handle)
    }

    fn reached_protection_profile(
        &self,
        handle: &KeyHandle,
    ) -> Result<KeyProtectionProfileV1, ea_key_provider::KeyError> {
        self.inner.reached_protection_profile(handle)
    }
}

/// Oeffnet Datenbank und Ablage mit DEMSELBEN Griff.
fn open_store(
    root: &std::path::Path,
    provider: &Arc<InMemoryKeyProvider>,
    database_key: &KeyHandle,
) -> OpenStore {
    let database = Arc::new(
        EncryptedDatabase::open(&root.join(DATABASE_FILE), provider.as_ref(), database_key)
            .expect("die verschluesselte Datenbank muss sich oeffnen lassen"),
    );
    let repository: Arc<dyn DraftRepository> = Arc::new(AutosaveDraftRepository::new(
        Arc::clone(&database),
        Arc::clone(provider) as Arc<dyn KeyProvider>,
    ));
    OpenStore {
        database,
        repository,
    }
}

/// Nimmt die Datenbankdateien, wie sie JETZT dalegen.
fn capture_database_files(root: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    std::iter::once(DATABASE_FILE)
        .chain(DATABASE_SIDECARS)
        .filter_map(|name| {
            fs::read(root.join(name))
                .ok()
                .map(|bytes| (name.to_owned(), bytes))
        })
        .collect()
}

/// Setzt die EINE Profilzeile mit rohem SQL.
///
/// Ueber `OperatorProfileRepository` gibt es keinen Schreibarm, und genau das
/// soll so bleiben: Stufe 2 konsumiert Bedieneridentitaet und stellt sie nicht
/// aus.
fn seed_operator_profile(database: &EncryptedDatabase, built: &BuiltLine) {
    seed_operator_profile_for_binding(database, built.binding_object_hash);
}

/// Setzt die EINE Profilzeile fuer `binding_object_hash` — dieselbe Bedienerin,
/// gebunden auf ein anderes Geraet.
fn seed_operator_profile_for_binding(
    database: &EncryptedDatabase,
    binding_object_hash: ObjectHash,
) {
    database
        .execute(
            "INSERT INTO operator_profile (singleton, organization_id, operator_subject_id, \
             display_name, function_label, profile_commitment_salt, \
             operator_binding_object_hash) VALUES (0, ?1, ?2, ?3, ?4, ?5, ?6)",
            &[
                StoreValue::Blob(trust_support::organization().as_bytes().to_vec()),
                StoreValue::Blob([BINDING_MARKER; 16].to_vec()),
                StoreValue::Text(FIXTURE_DISPLAY_NAME.to_owned()),
                StoreValue::Text(FIXTURE_FUNCTION_LABEL.to_owned()),
                StoreValue::Blob(FIXTURE_PROFILE_COMMITMENT_SALT.to_vec()),
                StoreValue::Blob(binding_object_hash.as_bytes().to_vec()),
            ],
        )
        .expect("die Profilzeile muss sich setzen lassen");
}

/// Die Eingabe eines `keyTransition` — Zeitzone und Quelle wie beim Einsatz,
/// dazu die versiegelte organisatorische Begruendung.
///
/// Der Uebergangshash steht ABSICHTLICH nicht hier: der Writer liest ihn aus
/// dem gewaehlten Kopf und nimmt ihn von keinem Aufrufer entgegen.
#[must_use]
pub fn key_transition_input(organizational_reason: &str) -> KeyTransitionInputV1 {
    KeyTransitionInputV1 {
        timezone: "Europe/Berlin".to_owned(),
        source: NativeSourceV1::new("ea.writer.fixture", 1)
            .expect("die Quelle der Fixture ist gueltig"),
        organizational_reason: organizational_reason.to_owned(),
    }
}

/// Kleinbuchstaben-Hex, wie jeder Dateiname des Layouts.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// Ein gueltiger Einsatz — dieselben Werte bei jedem Aufruf.
///
/// Die Typen sind nicht `Clone` (Stufe 1 gibt sie bewusst nicht heraus), also
/// baut jeder Aufruf sie NEU. Zwei Aufrufe ergeben denselben Inhalt und damit
/// dieselbe Vorschau — das ist die Voraussetzung dafuer, dass `finalize` den
/// `previewHash` nachrechnen kann.
#[must_use]
pub fn valid_incident() -> FinalizationInputV1 {
    incident_numbered(FIXTURE_INCIDENT_NUMBER)
}

/// Ein GUELTIGER Einsatz mit einer ANDEREN Einsatznummer.
///
/// Er unterscheidet sich in genau einem Feld, und dieses Feld geht ueber den
/// `recordDigest` in den `previewHash` ein — er ist damit der Aufbau, mit dem
/// sich eine Vorschau von einem Inhalt unterscheiden laesst.
#[must_use]
pub fn other_incident() -> FinalizationInputV1 {
    incident_numbered("2026-000043")
}

/// Ein GUELTIGER Einsatz mit einer frei gewaehlten Einsatznummer.
///
/// Oeffentlich fuer den Systemzeugen des Writer-Uebergangs: ein alter Writer,
/// der auf seiner Kopie des Bestands WEITERSCHREIBT, braucht je Eintrag eine
/// Nummer, die sein Register noch nicht fuehrt — und die beiden festen Nummern
/// oben sind nach zwei Eintraegen verbraucht.
#[must_use]
pub fn incident_numbered(number: &str) -> FinalizationInputV1 {
    incident_input::incident_numbered_at(number, UnixMillis::new(FIXTURE_NOW_MS - 3_600_000))
}

/// Die Kulisse der BEREINIGUNG.
///
/// Sie steht neben [`WriterHarness`] und nicht darin, weil sie eine andere
/// Frage stellt: nicht „wie loest ein Neustart eine liegende Marke auf", sondern
/// „wann genau duerfen die Reste fallen". Sie besitzt eine `WriterHarness` und
/// erfindet keine zweite Linie.
pub struct RecoveryHarness {
    inner: WriterHarness,
}

impl RecoveryHarness {
    /// Ein Bestand mit UNTERBROCHENER Finalisierung, VOR der unwiderruflichen
    /// Grenze.
    ///
    /// [`FinalizationFaultPoint::AfterPreparedMarkerCommit`] ist der letzte
    /// Punkt vor der Grenze: die Abschlussmarke liegt, der `draftDEK` liegt
    /// auch, und das Staging ist vollstaendig geschrieben. Genau hier muss
    /// sichtbar werden, dass vor der Grenze nichts entfernt wird.
    ///
    /// # Panics
    ///
    /// Wenn der Abbruch nicht erreichbar ist.
    #[must_use]
    pub fn prepared_finalization_interrupted() -> Self {
        let mut inner = WriterHarness::with_incident();
        inner
            .finalize_with_fault(FinalizationFaultPoint::AfterPreparedMarkerCommit)
            .expect("der Abbruch an der Marke muss erreichbar sein");
        Self { inner }
    }

    /// Alle wurzelrelativen Pfade des Bestands.
    ///
    /// Ueber die OEFFENTLICHE Adressliste von `LocalPathBackend` — dieselbe,
    /// die der Gesundheitscheck und der Sync-Klient lesen. Ein eigener
    /// Verzeichnisdurchlauf hier waere ein zweiter Blick auf denselben Bestand.
    ///
    /// # Errors
    ///
    /// Der Fehler des Ports.
    pub fn relative_paths(&self) -> Result<Vec<String>, ea_archive::ArchiveBackendError> {
        self.inner.backend().relative_paths()
    }

    /// Loest eine liegende Abschlussmarke auf.
    ///
    /// # Errors
    ///
    /// Der Fehler der Wiederherstellung.
    pub fn recover_pending(&self) -> Result<ea_writer::RecoveryOutcome, WriterError> {
        let source = self.inner.source();
        self.inner.service(&source).recover_pending()
    }

    /// Bereinigt hinter einem NACHGEWIESENEN Ausgang.
    ///
    /// # Errors
    ///
    /// Der Fehler der Bereinigung.
    pub fn reconcile_to_completion(
        &self,
    ) -> Result<ea_writer::ReconciliationOutcomeV1, WriterError> {
        let source = self.inner.source();
        self.inner.service(&source).reconcile_to_completion()
    }

    /// Traegt der Bestand noch eine Staging-Datei?
    ///
    /// # Panics
    ///
    /// Wenn der Bestand nicht lesbar ist.
    #[must_use]
    pub fn has_staging(&self) -> bool {
        self.relative_paths()
            .expect("der Bestand muss lesbar sein")
            .iter()
            .any(|path| ea_archive::is_staging_path(path))
    }

    /// Der Befund `OrphanGrantOrTemporaryFile` des Gesundheitschecks.
    ///
    /// Er laeuft ueber den ECHTEN [`ea_archive_fs::ArchiveHealthCheckV1`] und
    /// nicht ueber eine nachgebaute Regel: die Frage lautet, ob der Bestand
    /// nach der Bereinigung noch einen temporaeren Rest MELDET, und das
    /// entscheidet der Check und nicht dieser Test.
    ///
    /// # Panics
    ///
    /// Wenn der Check nicht laeuft.
    #[must_use]
    pub fn raises_orphan_or_temporary_finding(&self) -> bool {
        // Ein LEERES Erwartungsinventar. Es macht den Befund nur
        // WAHRSCHEINLICHER und nie unwahrscheinlicher: Erkenner 7 meldet jeden
        // Grant, den das Inventar nicht fuehrt, und ein leeres fuehrt keinen.
        // Eine gruene Zusicherung darueber ist damit die staerkere Aussage.
        let inventory = ea_format::ArchiveInventoryListV1::new(Vec::new())
            .expect("ein leeres Inventar ist gueltig");
        let capabilities = self
            .inner
            .backend()
            .run_capability_test(&capability_test_vector())
            .expect("der Capability-Test muss laufen");
        // Der ECHTE Bericht ueber den ECHTEN Bestand. Ein leerer waere hier
        // nicht baubar — `VerificationReportV1::empty` ist crate-intern —, und
        // er waere auch falsch: fuenf der zehn Erkenner lesen ausschliesslich
        // ihn.
        let source = self.inner.source();
        let anchor = self.inner.anchor();
        let verification = ea_verify::verify_archive(
            &source,
            &anchor,
            ea_verify::VerifyOptions::new(self.inner.observed_now()),
        )
        .expect("der Verifikationslauf muss ein Ergebnis liefern");
        ea_archive_fs::ArchiveHealthCheckV1::new(
            self.inner.backend(),
            &inventory,
            ea_archive_fs::FreeSpaceV1 {
                required_bytes: 0,
                available_bytes: u64::MAX,
            },
            &capabilities,
            &verification,
        )
        .run()
        .expect("der Gesundheitscheck muss laufen")
        .contains(ea_archive_fs::HealthFinding::OrphanGrantOrTemporaryFile)
    }

    #[must_use]
    pub const fn inner(&self) -> &WriterHarness {
        &self.inner
    }
}
