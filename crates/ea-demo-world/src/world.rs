//! Das Saatgut der FIXTURE-DEMOWELT.
//!
//! Alles, was hier entsteht, trägt das Wort `fixture-demo` im Namen oder im
//! Inhalt. Die Schlüssel sind Quelltextkonstanten und damit öffentlich; ein
//! Bestand, der so entstanden ist, ist kein Bestand, sondern eine Vorführung.
//!
//! # Was gebaut wird
//!
//! Eine Registrierungslinie mit Policy, Gerätezertifikaten, Reader-Grant und
//! einem finalisierten Eintrag entsteht NICHT hier neu, sondern kommt aus
//! [`historical::fixture_with_host_options`] — derselben Quelle, gegen die die
//! Bestandstests laufen. Diese Datei setzt nur den DELTA darauf, den eine
//! vorführbare Welt zusätzlich braucht:
//!
//! 1. eine zweite Policy, deren `allowed-archive-profile-hashes` das
//!    Archivprofil der Writer-Station ENTHÄLT (ohne das weist der Writer jede
//!    Serialisierung ab),
//! 2. eine Writer-Bedienerbindung für das VORHANDENE Writer-Zertifikat der
//!    Fixture, die — wie die Adminbindung aus der Fixture — an
//!    Betriebssystemkonto, Instanzschlüssel und Profilzusage gebunden ist.
//!    Kein zweites Writer-Zertifikat: nur das erste einer Linie ist der
//!    laufende Writer.
//!
//! Die Adminbindung mit Rolle `OrganizationAdmin` und der finalisierte Eintrag
//! stehen bereits in der Fixture; sie werden nicht nachgebaut.
//!
//! # Wo die Ankerbytes liegen
//!
//! AUSSERHALB des Archivverzeichnisses. `OperatorArchiveSnapshot::open`
//! (`crates/ea-admin/src/operator_runtime.rs`) kanonisiert beide Pfade und
//! weist einen Anker IM Archiv ab.
//!
//! # Warum zwei Stationen
//!
//! `--writer-config` und `--administration-config` schließen sich am Wirt
//! gegenseitig aus: `runtime/writer.rs` verlangt `role == Writer`,
//! `runtime/administration.rs` verlangt `role == OrganizationAdmin`. Eine
//! einzige Bedienerkonfiguration kann nie beides sein, also entstehen zwei
//! Stationsverzeichnisse mit je eigener Konfiguration und je eigener
//! SQLCipher-Datenbank.

use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::support::{
    self, LIVE_POLICY_MAX_REGISTRY_AGE_MS_V1, LIVE_WRITER_LEASE_THROUGH_V1,
    LIVE_WRITER_NOT_AFTER_V1,
    verify_support::{
        archive_support::trust_support::{self, ActionSpec, HeadOptions, RegistryLineBuilder},
        historical::{self, HostOptions},
    },
};
use ea_archive::{ArchiveBackendProfileV1, LocalPathProfileV1};
use ea_crypto::CanonicalPublicCoseKey;
use ea_format::{CertificateKindV1, KeyProtectionProfileV1, OperatorRoleV1};
use ea_key_provider::{InMemoryKeyProvider, KeyProvider as _, SecretPurpose};
use ea_local_store::{EncryptedDatabase, StoreValue};
use ea_trust::TrustObjectSource as _;
use ea_types::{DeviceId, Hash32, ObjectHash, OperatorSubjectId, UnixMillis};
use ed25519_dalek::SigningKey;

/// Der Klartext des einen finalisierten Eintrags der Demowelt.
/// Als `&str` und nicht als Bytesliteral: ein `b"…"` nimmt nur ASCII, und
/// „Vorführung" trägt ein ü.
const DEMO_ENTRY_PLAINTEXT: &str =
    "FIXTURE-DEMO: dieser Eintrag ist eine Vorführung und kein Einsatz.";

/// Betriebssystemkonto, Instanzschlüssel und Profilangaben der Demowelt.
///
/// Diese Werte sind ABSICHTLICH dieselben, die der bestehende Fixture-Helfer
/// in `apps/cli/tests/operator.rs` meldet (`TEST_GUID`, `PROFILE_SALT`,
/// `INSTANCE_SECRET` und die Uid 501/502). Ein Helfer, der dem dort
/// gemessenen Protokoll folgt, passt damit ohne eine einzige weitere Zahl auf
/// eine hier gesäte Welt.
pub(crate) const DEMO_GUID_WRITER: &str = "00112233-4455-6677-8899-aabbccddeeff";
pub(crate) const DEMO_GUID_ADMIN: &str = "ffeeddcc-bbaa-9988-7766-554433221100";
pub(crate) const DEMO_UID_WRITER: u32 = 501;
pub(crate) const DEMO_UID_ADMIN: u32 = 502;
/// Die Windows-SID der Demowelt. Rohbytes einer `S-1-5-21-…`-Kontokennung.
///
/// Windows hat in diesem Arbeitsbereich KEINEN produktiven Ernter des echten
/// Kontos: `crates/ea-operator/src/windows.rs` trägt ausdrücklich nur die
/// typisierte Übergabe und sagt, dass die Win32-Familie ADR-pflichtig ist.
/// Die Demowelt nimmt deshalb auf allen drei Plattformen ein FESTES
/// Fixture-Konto — auf Windows genau wie auf macOS und Linux.
pub(crate) const DEMO_WINDOWS_SUBAUTHORITIES: [u32; 5] =
    [21, 1_111_111_111, 2_222_222_222, 3_333_333_333, 1001];
pub(crate) const DEMO_WINDOWS_IDENTIFIER_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];

pub(crate) const DEMO_WRITER_INSTANCE_SECRET: [u8; 32] = [0x47; 32];
pub(crate) const DEMO_ADMIN_INSTANCE_SECRET: [u8; 32] = [0x68; 32];
const DEMO_PROFILE_SALT: [u8; 32] = [0x53; 32];
const DEMO_WRITER_NAME: &str = "Fixture-Demo Schreiberin";
const DEMO_WRITER_FUNCTION: &str = "Fixture-Demo Einsatzleitung";
const DEMO_ADMIN_NAME: &str = "Fixture-Demo Administrator";
const DEMO_ADMIN_FUNCTION: &str = "Fixture-Demo Organisationsleitung";
/// Die Saaten, aus denen der `InMemoryKeyProvider` den Datenbankschlüssel
/// ableitet — dieselben wie in `database_provider_for` der CLI-Tests.
pub(crate) const DEMO_WRITER_DATABASE_SEED: [u8; 32] = [0x94; 32];
pub(crate) const DEMO_ADMIN_DATABASE_SEED: [u8; 32] = [0x95; 32];

/// Die Gerätekennung des Fixture-Writers (`historical.rs`, Marker 0x55; die
/// Fixture-Kette leitet `marker + 0x40` ab). Die Kontobindung hängt an ihr.
const DEMO_WRITER_DEVICE: [u8; 16] = [0x95; 16];
const DEMO_ADMIN_DEVICE: [u8; 16] = [0x52; 16];
const DEMO_WRITER_SUBJECT: [u8; 16] = [0x71; 16];
const DEMO_ADMIN_SUBJECT: [u8; 16] = [0x42; 16];

/// Was beim Säen schiefgehen kann. Bewusst grob: ein Saatlauf, der nicht
/// durchläuft, hat kein Zwischenergebnis, das jemand retten wollte.
#[derive(Debug)]
pub enum SeedError {
    /// Das Zielverzeichnis existiert und ist nicht leer.
    DirectoryNotEmpty(PathBuf),
    /// Ein Schreib- oder Lesefehler unter dem Zielverzeichnis.
    Io(std::io::Error),
    /// Ein Bauschritt der Welt selbst.
    World(String),
}
impl std::fmt::Display for SeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DirectoryNotEmpty(path) => write!(
                f,
                "das Zielverzeichnis {} ist nicht leer; die Demowelt überschreibt nichts",
                path.display()
            ),
            Self::Io(error) => write!(f, "Dateifehler: {error}"),
            Self::World(reason) => write!(f, "die Demowelt ließ sich nicht bauen: {reason}"),
        }
    }
}
impl std::error::Error for SeedError {}
impl From<std::io::Error> for SeedError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Eine Station: ein Verzeichnis mit Bedienerkonfiguration, Datenbank und der
/// rollenspezifischen zweiten Konfiguration.
pub struct DemoStation {
    pub directory: PathBuf,
    /// Die öffentliche Bedienerkonfiguration (`--operator-config`).
    pub operator_config: PathBuf,
    /// Die rollenspezifische Konfiguration (`--writer-config` bzw.
    /// `--administration-config`).
    pub role_config: PathBuf,
    pub database: PathBuf,
    pub certificate_hash: ObjectHash,
    pub binding_object_hash: ObjectHash,
}

/// Was eine gesäte Demowelt ist und wo sie liegt. Alle Pfade sind absolut und
/// kanonisiert: `OperatorArchiveSnapshot::open` kanonisiert selbst und
/// verglich sonst gegen etwas anderes, als hier geschrieben wurde.
pub struct DemoWorld {
    pub root: PathBuf,
    pub archive_directory: PathBuf,
    pub anchor_path: PathBuf,
    pub writer: DemoStation,
    pub admin: DemoStation,
    /// Das Verzeichnis, das die Web-Anwendung über „Archiv öffnen" lädt.
    /// Es ist dasselbe Archivverzeichnis — der Reader liest den Bestand, nicht
    /// eine Kopie davon.
    pub reader_archive_directory: PathBuf,
    /// Die eine `.eip`-Datei des finalisierten Eintrags.
    pub reader_entry_package: PathBuf,
    /// Die Grant-Datei, ohne die der Reader nichts zeigt.
    pub reader_grant: PathBuf,
    /// Der private X25519-Schlüssel des Readers, hex. FIXTURE, öffentlich
    /// bekannt.
    pub reader_private_key_hex: String,
    pub reader_certificate_hash: ObjectHash,
    /// Der `profile_hash()` des Archivprofils, wie er in der wirksamen Policy
    /// steht.
    pub archive_profile_hash: Hash32,
}

/// Das Archivprofil der Demowelt. Sein `profile_hash()` muss in der wirksamen
/// Policy stehen, sonst weist der Writer jede Serialisierung ab.
#[must_use]
pub fn demo_archive_profile() -> ArchiveBackendProfileV1 {
    ArchiveBackendProfileV1::LocalPath(LocalPathProfileV1 {
        filesystem_row_id: "fixture-demo-local-filesystem".into(),
        capability_test_vector_id: "fixture-demo-capability-v1".into(),
    })
}

/// Das FESTE Fixture-Betriebssystemkonto einer Station der Demowelt.
///
/// Die drei Plattformzweige spiegeln `ea_admin::native_provider`s eigene
/// Fallunterscheidung. Auf Windows steht ein festes SID-Tripel, weil dieser
/// Arbeitsbereich dort keinen produktiven Kontoernter hat.
///
/// Aus DIESEM Wert entstehen beide Seiten: der Bindungshash, den die Saat in
/// die Registry schreibt, und die `account`-Antwort des Fixture-Helfers in
/// [`crate::native_fixture`]. Zwei getrennte Ableitungen könnten
/// auseinanderlaufen; eine kann es nicht.
pub(crate) fn demo_account_inputs(admin: bool) -> ea_operator::OsAccountInputs {
    let guid = if admin {
        DEMO_GUID_ADMIN
    } else {
        DEMO_GUID_WRITER
    };
    let uid = if admin {
        DEMO_UID_ADMIN
    } else {
        DEMO_UID_WRITER
    };
    if cfg!(target_os = "macos") {
        ea_operator::macos::account_inputs(vec![guid.into()], vec![uid.to_string()], uid)
    } else if cfg!(windows) {
        let mut sid = Vec::with_capacity(8 + 4 * DEMO_WINDOWS_SUBAUTHORITIES.len());
        sid.push(1);
        sid.push(u8::try_from(DEMO_WINDOWS_SUBAUTHORITIES.len()).unwrap());
        sid.extend_from_slice(&DEMO_WINDOWS_IDENTIFIER_AUTHORITY);
        for sub in DEMO_WINDOWS_SUBAUTHORITIES {
            sid.extend_from_slice(&sub.to_le_bytes());
        }
        // Die letzte Subauthority trennt die zwei Stationen.
        let mut subs = DEMO_WINDOWS_SUBAUTHORITIES.to_vec();
        if admin {
            *subs.last_mut().unwrap() += 1;
            let offset = sid.len() - 4;
            sid[offset..].copy_from_slice(&subs.last().unwrap().to_le_bytes());
        }
        ea_operator::windows::account_inputs(sid, DEMO_WINDOWS_IDENTIFIER_AUTHORITY, subs)
    } else {
        ea_operator::linux::account_inputs(format!("{}\n", guid.replace('-', "")).into_bytes(), uid)
    }
}

/// Der Bindungshash des FESTEN Fixture-Betriebssystemkontos der Demowelt.
fn demo_account_hash(admin: bool, device: DeviceId) -> Hash32 {
    demo_account_inputs(admin)
        .binding_hash(trust_support::organization(), device)
        .expect("das Fixture-Konto muss einen Bindungshash ergeben")
}

fn public_key(secret: [u8; 32]) -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::ed25519(SigningKey::from_bytes(&secret).verifying_key().to_bytes())
        .expect("ein Fixture-Ed25519-Schlüssel muss kanonisch sein")
}

/// Sät die Fixture-Demowelt unter `root`.
///
/// `root` darf nicht existieren oder muss leer sein: die Demowelt
/// überschreibt niemals etwas, das schon da ist.
///
/// # Errors
///
/// [`SeedError`], wenn das Zielverzeichnis belegt ist, ein Schreibvorgang
/// scheitert oder ein Bauschritt der Welt nicht durchläuft.
pub fn seed_demo_world(root: &Path) -> Result<DemoWorld, SeedError> {
    seed(root, false)
}

/// GEGENPROBE, keine Welt zum Benutzen: sät die frühere, falsche Form mit
/// einem ZWEITEN Writer-Zertifikat für die Writer-Station. Ein Zeuge, der die
/// Writer-Sitzung wirklich öffnet, muss an dieser Welt scheitern — sonst sähe
/// er den Fehler nicht, gegen den er steht.
///
/// # Errors
///
/// Wie [`seed_demo_world`].
#[doc(hidden)]
pub fn seed_demo_world_with_second_writer_certificate(root: &Path) -> Result<DemoWorld, SeedError> {
    seed(root, true)
}

fn seed(root: &Path, second_writer_certificate: bool) -> Result<DemoWorld, SeedError> {
    if root.exists() && fs::read_dir(root)?.next().is_some() {
        return Err(SeedError::DirectoryNotEmpty(root.to_path_buf()));
    }
    fs::create_dir_all(root)?;
    // Kanonisieren, BEVOR irgendein Pfad in eine Konfiguration geht:
    // `OperatorArchiveSnapshot::open` kanonisiert das Archivverzeichnis
    // selbst, und auf macOS liegen `/tmp` und `/var` hinter Symlinks. Ohne
    // diesen Schritt stünde in der Konfiguration ein anderer Pfad als der,
    // gegen den der Wirt später vergleicht.
    let root = root.canonicalize()?;

    // Die Gegenprobe trägt die Gerätekennung der früheren Fassung ([0x51; 16]),
    // damit sie an genau der alten Stelle scheitert und nicht an einer
    // doppelten Kennung.
    let writer_device_bytes = if second_writer_certificate {
        [0x51; 16]
    } else {
        DEMO_WRITER_DEVICE
    };
    let writer_device = DeviceId::try_from(writer_device_bytes.as_slice())
        .map_err(|_| SeedError::World("Writer-Gerätekennung".into()))?;
    let admin_device = DeviceId::try_from(DEMO_ADMIN_DEVICE.as_slice())
        .map_err(|_| SeedError::World("Admin-Gerätekennung".into()))?;
    let writer_subject = OperatorSubjectId::try_from(DEMO_WRITER_SUBJECT.as_slice())
        .map_err(|_| SeedError::World("Writer-Subjektkennung".into()))?;
    let admin_subject = OperatorSubjectId::try_from(DEMO_ADMIN_SUBJECT.as_slice())
        .map_err(|_| SeedError::World("Admin-Subjektkennung".into()))?;

    // Schritt 1: die Welt aus der GETEILTEN Fixture. Sie trägt bereits
    // Policy, Gerätezertifikate, den Reader samt Grant, den finalisierten
    // Eintrag und die an das Wirtskonto gebundene Adminbindung.
    let mut material = historical::fixture_with_host_options(
        |_, _| DEMO_ENTRY_PLAINTEXT.as_bytes().to_vec(),
        Some(HostOptions {
            not_after: LIVE_WRITER_NOT_AFTER_V1,
            max_age: LIVE_POLICY_MAX_REGISTRY_AGE_MS_V1,
            instance: DEMO_ADMIN_INSTANCE_SECRET,
            account_hash: demo_account_hash(true, admin_device),
            commitment: ea_crypto::operator_profile_commitment(
                trust_support::organization(),
                admin_subject,
                DEMO_ADMIN_NAME,
                DEMO_ADMIN_FUNCTION,
                &DEMO_PROFILE_SALT,
            ),
        }),
    );

    let profile = demo_archive_profile();
    let archive_profile_hash = profile
        .profile_hash()
        .map_err(|error| SeedError::World(format!("Archivprofilhash: {}", error.code())))?;

    // Schritt 2: die Policy, die das Archivprofil der Writer-Station ZULÄSST.
    // Ohne diesen Eintrag in `allowed-archive-profile-hashes` weist der Writer
    // jede Serialisierung ab, bevor ein Byte entsteht.
    let previous_policy = material.line.current_policy_hash();
    let current_sequence = material.current_sequence;
    material.line.push(
        ActionSpec::Policy {
            policy_version: Some(2),
            previous_policy_hash: Some(previous_policy),
            effective_from: Some(current_sequence),
        },
        HeadOptions {
            effective_from: Some(current_sequence),
            valid_through: Some(LIVE_WRITER_LEASE_THROUGH_V1),
            not_after: UnixMillis::new(LIVE_WRITER_NOT_AFTER_V1),
            policy_max_registry_age_ms_override: Some(LIVE_POLICY_MAX_REGISTRY_AGE_MS_V1),
            policy_allowed_archive_profile_hashes_override: Some(vec![archive_profile_hash]),
            ..HeadOptions::default()
        },
    );

    // Schritt 3: die Writer-Bedienerbindung. Die Fixture bringt einen Writer
    // mit, aber ohne Kontobindung und ohne Instanzschlüssel — eine native
    // Sitzung kann ihn so nicht führen. Die neue Bindung gilt DEMSELBEN
    // Zertifikat, das den alten Eintrag signiert hat.
    //
    // Kein zweites Writer-Zertifikat: `ea-trust` macht nur das ERSTE
    // Writer-Zertifikat einer Linie zum laufenden Writer (`registry.rs`,
    // `current_writer_certificate_hash.is_none()`), und jedes andere gilt dem
    // Resolver als nicht aktiv. Eine frühere Fassung dieser Saat legte eines an;
    // die Writer-Station brach dann in JEDEM Wirt mit
    // `EA-OPERATOR-DEVICE-CERTIFICATE-NOT-ACTIVE` ab.
    let writer_certificate = if second_writer_certificate {
        // NUR die Gegenprobe (`seed_demo_world_with_second_writer_certificate`):
        // genau die frühere, falsche Form.
        material
            .line
            .push(
                ActionSpec::Device {
                    kind: CertificateKindV1::Writer,
                    marker: 0x11,
                    effective_from: Some(current_sequence),
                },
                HeadOptions {
                    effective_from: Some(current_sequence),
                    valid_through: Some(LIVE_WRITER_LEASE_THROUGH_V1),
                    not_after: UnixMillis::new(LIVE_WRITER_NOT_AFTER_V1),
                    device_id_override: Some(writer_device),
                    ..HeadOptions::default()
                },
            )
            .direct_object_hash
    } else {
        ObjectHash::try_from(material.writer_certificate.as_bytes().as_slice()).ok()
    }
    .ok_or_else(|| SeedError::World("das Writer-Zertifikat hat keinen Objekthash".into()))?;

    let writer_head = material.line.push(
        ActionSpec::OperatorBinding {
            certificate_hash: writer_certificate,
            role: OperatorRoleV1::Writer,
            marker: 0x71,
            effective_from: Some(current_sequence),
        },
        HeadOptions {
            effective_from: Some(current_sequence),
            valid_through: Some(LIVE_WRITER_LEASE_THROUGH_V1),
            not_after: UnixMillis::new(LIVE_WRITER_NOT_AFTER_V1),
            binding_operator_profile_commitment_override: Some(
                ea_crypto::operator_profile_commitment(
                    trust_support::organization(),
                    writer_subject,
                    DEMO_WRITER_NAME,
                    DEMO_WRITER_FUNCTION,
                    &DEMO_PROFILE_SALT,
                ),
            ),
            binding_instance_key_thumbprint_override: Some(
                public_key(DEMO_WRITER_INSTANCE_SECRET).thumbprint(),
            ),
            binding_os_account_hash_override: Some(demo_account_hash(false, writer_device)),
            ..HeadOptions::default()
        },
    );
    let writer_binding = writer_head
        .direct_object_hash
        .ok_or_else(|| SeedError::World("die Writer-Bindung hat keinen Objekthash".into()))?;

    // Schritt 4: DER READER-GRANT. Ohne ihn zeigt die Web-Anwendung nichts:
    // die Fixture bringt nur den ursprünglichen RECOVERY-Grant mit, und der
    // adressiert einen anderen Schlüssel. `install_grant` baut die
    // Grant-Autorisierung und den historischen Reader-Grant für den
    // Readerschlüssel derselben Linie — wieder aus der geteilten Quelle und
    // nicht hier nachgebaut.
    //
    // `head` wird VORHER auf den zuletzt gebauten Kopf gesetzt: Autorisierung
    // und Grant binden Registrierungsversion und Kopfhash, und das muss der
    // Kopf sein, unter dem die Welt ausgeliefert wird — nicht der, der vor
    // Policy und Writer galt.
    material.head = writer_head;
    let mut material = historical::install_grant(material, LIVE_WRITER_NOT_AFTER_V1);

    // Schritt 5: die neu entstandenen Vertrauensobjekte in den Bestand
    // nachziehen. Dieselbe Form wie `Installation::new` in
    // `apps/cli/tests/operator.rs`: was die Linie kennt und der Bestand noch
    // nicht hat, wird byteweise übernommen.
    push_new_trust_objects(&mut material.line, &mut material.fixture)?;

    // Schritt 6: alles auf die Platte.
    let archive_directory = root.join("archiv");
    support::materialize(&material.fixture, &archive_directory);
    let archive_directory = archive_directory.canonicalize()?;

    // Der Anker liegt AUSSERHALB des Archivs — `OperatorArchiveSnapshot::open`
    // weist einen Anker im Archivverzeichnis ab.
    let anchor_path = root.join("fixture-demo-trust-anchor.etb");
    fs::write(&anchor_path, material.line.exact_anchor_bytes())?;
    let anchor_path = anchor_path.canonicalize()?;

    let admin_certificate = material.line.second_bootstrap_admin_hash();

    let writer = write_writer_station(
        &root.join("writer-station"),
        &archive_directory,
        writer_certificate,
        writer_binding,
        writer_subject,
        &profile,
    )?;
    let admin = write_admin_station(
        &root.join("admin-station"),
        &archive_directory,
        admin_certificate,
        material.operator_binding,
        admin_subject,
        &profile,
    )?;

    let reader_certificate_hash =
        ObjectHash::try_from(material.recipient_certificate_hash.as_bytes().as_slice())
            .map_err(|_| SeedError::World("Readerzertifikat".into()))?;

    Ok(DemoWorld {
        reader_archive_directory: archive_directory.clone(),
        reader_entry_package: archive_directory.join("entries/000000000000_entry.eip"),
        reader_grant: archive_directory.join("grants/historical.eag"),
        reader_private_key_hex: hex::encode(
            crate::support::verify_support::other_recipient_secret_bytes(),
        ),
        reader_certificate_hash,
        archive_profile_hash,
        root,
        archive_directory,
        anchor_path,
        writer,
        admin,
    })
}

/// Übernimmt jedes Vertrauensobjekt der Linie, das der Bestand noch nicht
/// trägt — byteweise und ohne Umkodierung.
fn push_new_trust_objects(
    line: &mut RegistryLineBuilder,
    fixture: &mut crate::support::verify_support::archive_support::ArchiveFixture,
) -> Result<(), SeedError> {
    let source = line.source();
    let mut hashes = Vec::new();
    source
        .visit_trust_object_hashes(&mut |hash| {
            hashes.push(hash);
            Ok(())
        })
        .map_err(|_| {
            SeedError::World("die Vertrauensobjekte ließen sich nicht aufzählen".into())
        })?;
    let mut new = Vec::new();
    for hash in hashes {
        let bytes = source
            .read_exact_trust_object(hash)
            .map_err(|_| SeedError::World("ein Vertrauensobjekt ließ sich nicht lesen".into()))?
            .ok_or_else(|| SeedError::World("ein Vertrauensobjekt fehlt in der Linie".into()))?
            .to_vec();
        if !fixture
            .blobs()
            .iter()
            .any(|(_, existing)| existing == &bytes)
        {
            new.push(bytes);
        }
    }
    drop(source);
    for bytes in new {
        let name = format!(
            "{}.etb",
            hex::encode(ea_crypto::object_hash(&bytes).as_bytes())
        );
        fixture.push_exact_bytes(&name, bytes);
    }
    Ok(())
}

/// Legt die Datenbank einer Station an und schreibt die eine
/// `operator_profile`-Zeile hinein, gegen die die Laufzeit die Profilzusage
/// der Bindung nachrechnet.
fn write_station_database(
    path: &Path,
    seed: [u8; 32],
    subject: OperatorSubjectId,
    name: &str,
    function: &str,
    binding: ObjectHash,
) -> Result<(), SeedError> {
    let provider = InMemoryKeyProvider::new_for_test(seed);
    let key = provider
        .generate(
            SecretPurpose::LocalDatabaseKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .map_err(|error| SeedError::World(format!("Datenbankschlüssel: {}", error.code())))?;
    let database = EncryptedDatabase::open(path, &provider, &key)
        .map_err(|error| SeedError::World(format!("Datenbank: {}", error.code())))?;
    database
        .execute(
            "INSERT INTO operator_profile VALUES(0,?1,?2,?3,?4,?5,?6)",
            &[
                StoreValue::Blob(trust_support::organization().as_bytes().to_vec()),
                StoreValue::Blob(subject.as_bytes().to_vec()),
                StoreValue::Text(name.into()),
                StoreValue::Text(function.into()),
                StoreValue::Blob(DEMO_PROFILE_SALT.to_vec()),
                StoreValue::Blob(binding.as_bytes().to_vec()),
            ],
        )
        .map_err(|error| SeedError::World(format!("Profilzeile: {}", error.code())))?;
    Ok(())
}

fn profile_json(profile: &ArchiveBackendProfileV1) -> serde_json::Value {
    match profile {
        ArchiveBackendProfileV1::LocalPath(local) => serde_json::json!({
            "kind": "local-path",
            "filesystem_row_id": local.filesystem_row_id,
            "capability_test_vector_id": local.capability_test_vector_id,
        }),
        ArchiveBackendProfileV1::ControlledNetworkPath(_) => {
            unreachable!("die Demowelt führt ausschließlich ein lokales Archivprofil")
        }
    }
}

fn write_json(path: &Path, value: &serde_json::Value) -> Result<(), SeedError> {
    fs::write(
        path,
        serde_json::to_vec_pretty(value)
            .map_err(|_| SeedError::World("eine Konfiguration ließ sich nicht kodieren".into()))?,
    )?;
    Ok(())
}

fn write_writer_station(
    directory: &Path,
    archive_directory: &Path,
    certificate: ObjectHash,
    binding: ObjectHash,
    subject: OperatorSubjectId,
    profile: &ArchiveBackendProfileV1,
) -> Result<DemoStation, SeedError> {
    fs::create_dir_all(directory)?;
    let directory = directory.canonicalize()?;
    let database = directory.join("operator.sqlite");
    write_station_database(
        &database,
        DEMO_WRITER_DATABASE_SEED,
        subject,
        DEMO_WRITER_NAME,
        DEMO_WRITER_FUNCTION,
        binding,
    )?;
    let operator_config = directory.join("operator.json");
    write_json(
        &operator_config,
        &serde_json::json!({
            "archive_directory": archive_directory,
            "database_path": database,
            "device_certificate_hash": hex::encode(certificate.as_bytes()),
            "binding_object_hash": hex::encode(binding.as_bytes()),
            "role": "writer",
            "purpose": "finalize",
        }),
    )?;
    let role_config = directory.join("writer.json");
    write_json(
        &role_config,
        &serde_json::json!({
            "version": 1,
            "timezone": "Europe/Berlin",
            "archive_profile": profile_json(profile),
        }),
    )?;
    Ok(DemoStation {
        directory,
        operator_config,
        role_config,
        database,
        certificate_hash: certificate,
        binding_object_hash: binding,
    })
}

fn write_admin_station(
    directory: &Path,
    archive_directory: &Path,
    certificate: ObjectHash,
    binding: ObjectHash,
    subject: OperatorSubjectId,
    profile: &ArchiveBackendProfileV1,
) -> Result<DemoStation, SeedError> {
    fs::create_dir_all(directory)?;
    let directory = directory.canonicalize()?;
    let database = directory.join("operator.sqlite");
    write_station_database(
        &database,
        DEMO_ADMIN_DATABASE_SEED,
        subject,
        DEMO_ADMIN_NAME,
        DEMO_ADMIN_FUNCTION,
        binding,
    )?;
    // `AdministrationResources::open` verlangt ein ECHTES Verzeichnis und
    // weist einen Symlink ausdrücklich ab (`symlink_metadata`).
    let inbox = directory.join("registrierungs-eingang");
    fs::create_dir_all(&inbox)?;
    let exchange = directory.join("zeremonie-austausch");
    fs::create_dir_all(&exchange)?;
    let operator_config = directory.join("operator.json");
    write_json(
        &operator_config,
        &serde_json::json!({
            "archive_directory": archive_directory,
            "database_path": database,
            "device_certificate_hash": hex::encode(certificate.as_bytes()),
            "binding_object_hash": hex::encode(binding.as_bytes()),
            "role": "organization-admin",
            "purpose": "admin-root-ceremony",
            // Die Station ist ihr eigener Austauschpartner: eine Demowelt hat
            // keine zweite Maschine. `authority` bleibt AUS — mit `true`
            // verlangte `AdministrationResources::open` einen Autoritätswirt
            // und wiese die Station ab.
            "admin_certificate_hash": hex::encode(certificate.as_bytes()),
            "admin_binding_object_hash": hex::encode(binding.as_bytes()),
            "ceremony_exchange_directory": exchange,
            "authority": false,
        }),
    )?;
    let role_config = directory.join("administration.json");
    write_json(
        &role_config,
        &serde_json::json!({
            "version": 1,
            "registration_inbox": inbox,
            "archive_profile": profile_json(profile),
        }),
    )?;
    Ok(DemoStation {
        directory,
        operator_config,
        role_config,
        database,
        certificate_hash: certificate,
        binding_object_hash: binding,
    })
}
