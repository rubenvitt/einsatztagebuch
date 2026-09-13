//! Das lokale Wirtbackend: Create-if-absent, Flush, Rename und Sperre auf
//! `std::fs`.
//!
//! Diese Datei ist der Grund, aus dem `ea-archive-fs` ueberhaupt existiert.
//! `ea-archive` darf `std::fs` nicht beruehren, sonst faellt es von der
//! wasm32-Positivliste — es traegt die zielunabhaengigen Ports und den
//! host-freien Containerleser, aber keine Wirtimplementierung. Hier steht das
//! Gegenstueck.
mod managed;

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
};

use ea_archive::{
    ArchiveBackend, ArchiveBackendError, ArchiveBackendProfileV1, ArchiveBlob, ArchiveError,
    ArchivePath, ArchiveSource, BoundArchiveProfilePolicyV1, LAYOUT_PATHS_V1, STAGING_SUFFIX_V1,
    WriterLock, WriterLockRelease,
};
use ea_crypto::object_hash;
use ea_format::{
    ActiveProfilePointerCoreV1, ArchiveInventoryEntryV1, ArchiveInventoryListV1, ExactObjectBytes,
    encode_active_profile_pointer_core,
};
use ea_types::Hash32;

use crate::{FormatPackageOutcomeV1, format_package::materialize_format_package_reporting};

/// Die Kontrolldateien des Backends an der Bestandswurzel.
///
/// Sie sind KEIN Archivbeiwerk und gehoeren in kein Inventar: die Sperrdatei
/// traegt einen Betriebszustand und der Profilzeiger eine Aussage ueber die
/// INSTALLATION, keine von beiden eine ueber den Bestand. Wuerden sie
/// mitinventarisiert, waere das Quellinventar eines Profilwechsels nie gleich
/// dem Zielinventar.
///
/// Das galt schon, als die Sperrdatei nur SOLANGE dalag, wie jemand die Sperre
/// hielt — die Quelle haelt beim Kopieren ihre Sperre. Seit die Sperre eine
/// Betriebssystemsperre ueber der Datei ist (siehe
/// [`ArchiveBackend::acquire_writer_lock`] an [`LocalPathBackend`]), bleibt
/// die Datei DAUERHAFT liegen: sie entsteht beim ersten Nehmen und wird nie
/// wieder entfernt. Der Grund ist damit staerker geworden und nicht schwaecher.
/// Ein frisch angelegtes Ziel traegt sie noch nicht, eine gewachsene Quelle
/// laengst — ohne diese Zeile waere der Inventarvergleich eines Profilwechsels
/// dauerhaft ungleich statt nur waehrend eines gehaltenen Griffs.
pub const CONTROL_FILES_V1: [&str; 2] = [".ea-writer.lock", ".ea-active-profile"];

#[cfg(any(
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(
        target_os = "linux",
        target_env = "gnu",
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn read_existing_profile_pointer(
    root: &Path,
) -> Result<Option<ActiveProfilePointerCoreV1>, ArchiveBackendError> {
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    // Same pinned native constants as lock_diagnosis.rs; Linux aarch64's
    // O_NOFOLLOW differs from x86_64. No extra dependency or unsafe call.
    #[cfg(target_os = "macos")]
    const NOFOLLOW_NONBLOCK: i32 = 0x100 | 0x4;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    const NOFOLLOW_NONBLOCK: i32 = 0x20000 | 2048;
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    const NOFOLLOW_NONBLOCK: i32 = 0x8000 | 2048;

    let root_before = fs::symlink_metadata(root).map_err(|_| ArchiveBackendError::Io)?;
    let valid_root = |metadata: &fs::Metadata| {
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.mode() & 0o444 != 0
            && metadata.mode() & 0o111 != 0
    };
    if !valid_root(&root_before) {
        return Err(ArchiveBackendError::Io);
    }
    let same = |left: &fs::Metadata, right: &fs::Metadata| {
        left.dev() == right.dev() && left.ino() == right.ino()
    };
    let root_file = OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW_NONBLOCK)
        .open(root)
        .map_err(|_| ArchiveBackendError::Io)?;
    let root_unchanged = || {
        let (Ok(opened), Ok(named)) = (root_file.metadata(), fs::symlink_metadata(root)) else {
            return false;
        };
        if !valid_root(&opened)
            || !valid_root(&named)
            || !same(&root_before, &opened)
            || !same(&opened, &named)
        {
            return false;
        }
        // Mode bits do not reflect ACL denials. Exercise actual directory
        // access, including the first read, without exposing entry names or
        // walking the inventory. The held descriptor and named root must
        // still identify the original directory after that access.
        if fs::read_dir(root)
            .and_then(|mut entries| entries.next().transpose().map(|_| ()))
            .is_err()
        {
            return false;
        }
        fs::symlink_metadata(root)
            .is_ok_and(|current| valid_root(&current) && same(&opened, &current))
    };
    if !root_unchanged() {
        return Err(ArchiveBackendError::Io);
    }
    let path = root.join(CONTROL_FILES_V1[1]);
    let before = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return if root_unchanged() {
                Ok(None)
            } else {
                Err(ArchiveBackendError::Io)
            };
        }
        Err(_) => return Err(ArchiveBackendError::Io),
    };
    if !before.is_file() || before.file_type().is_symlink() || before.mode() & 0o444 == 0 {
        return Err(ArchiveBackendError::Io);
    }
    let limit = ActiveProfilePointerCoreV1::MAX_ENCODED_BYTES;
    if before.len() > limit as u64 {
        return Err(ArchiveBackendError::Format(ea_format::FormatError::Shape));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW_NONBLOCK)
        .open(&path)
        .map_err(|_| ArchiveBackendError::Io)?;
    let unchanged = || {
        let (Ok(opened), Ok(named)) = (file.metadata(), fs::symlink_metadata(&path)) else {
            return false;
        };
        root_unchanged()
            && opened.is_file()
            && named.is_file()
            && !named.file_type().is_symlink()
            && same(&before, &opened)
            && same(&opened, &named)
            && opened.len() == before.len()
            && named.len() == before.len()
            && opened.mtime() == before.mtime()
            && opened.mtime_nsec() == before.mtime_nsec()
            && opened.ctime() == before.ctime()
            && opened.ctime_nsec() == before.ctime_nsec()
    };
    if !unchanged() {
        return Err(ArchiveBackendError::Io);
    }
    let mut bytes = Vec::with_capacity(limit + 1);
    (&file)
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ArchiveBackendError::Io)?;
    if !unchanged() || bytes.len() as u64 != before.len() {
        return Err(ArchiveBackendError::Io);
    }
    ea_format::decode_active_profile_pointer_core(&bytes)
        .map(Some)
        .map_err(ArchiveBackendError::Format)
}

#[cfg(not(any(
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(
        target_os = "linux",
        target_env = "gnu",
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
)))]
fn read_existing_profile_pointer(
    _: &Path,
) -> Result<Option<ActiveProfilePointerCoreV1>, ArchiveBackendError> {
    Err(ArchiveBackendError::Io)
}

/// Das Verzeichnis, in dem der Capability-Test arbeitet.
///
/// Es liegt UNTERHALB der Bestandswurzel, damit der Rename-Nachweis auf
/// demselben Dateisystem laeuft — und es ist deshalb ausdruecklich NICHT aus
/// dem Inventar und aus der Lesesicht ausgeblendet: Bytes, die hier
/// liegenbleiben, weil ein Capability-Test abgebrochen ist, sind ein
/// Gesundheitsbefund (temporaere Datei) und keine unsichtbare Restmenge. Der
/// Name gehoert damit zum Layout-/Gesundheitsvertrag und nicht zu einer
/// Filterliste; `ArchiveHealthCheckV1` liest ihn.
pub const CAPABILITY_SCRATCH_DIR_V1: &str = ".ea-capability";

/// Der Capability-Testvektor eines Profils.
///
/// `design.md` §11.5 verlangt, dass der Test ZUFALLSOBJEKTE schreibt und deren
/// exakte Bytes nachprueft. Der Vektor traegt diese Bytes, damit der Lauf
/// reproduzierbar ist: ein Test, dessen Eingabe je Lauf wechselt, kann einen
/// Fehlschlag nicht wiederholen.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityTestVectorV1 {
    id: String,
    object_bytes: Vec<u8>,
}

impl CapabilityTestVectorV1 {
    /// Prueft und baut den Vektor.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::Path`], wenn die Kennung leer ist, einen Trenner
    /// traegt oder die Bytes leer sind.
    pub fn new(id: &str, object_bytes: &[u8]) -> Result<Self, ArchiveBackendError> {
        if id.is_empty()
            || object_bytes.is_empty()
            || id.contains('/')
            || id.contains('\\')
            || id.contains("..")
        {
            return Err(ArchiveBackendError::Path);
        }
        Ok(Self {
            id: id.to_owned(),
            object_bytes: object_bytes.to_vec(),
        })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn object_bytes(&self) -> &[u8] {
        &self.object_bytes
    }
}

/// Das Ergebnis eines Capability-Tests.
///
/// Sieben Zusagen, jede EINZELN ausgewiesen. Ein einziges Boolean „bestanden"
/// liesse sich nicht mehr zurueckverfolgen, und `design.md` §11.5 zaehlt die
/// Faehigkeiten namentlich auf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityReportV1 {
    exclusive_create_without_overwrite: bool,
    byte_conflict_detection: bool,
    same_filesystem_atomic_rename: bool,
    file_flush: bool,
    directory_flush: bool,
    exclusive_writer_lock: bool,
    disconnect_and_resume_keeps_exact_bytes: bool,
}

impl CapabilityReportV1 {
    /// Ein Bericht, in dem KEINE Faehigkeit belegt ist.
    ///
    /// Fail-closed: der Lauf setzt jede Zusage einzeln, und was er nicht
    /// gesetzt hat, gilt als nicht belegt.
    #[must_use]
    pub const fn unproven() -> Self {
        Self {
            exclusive_create_without_overwrite: false,
            byte_conflict_detection: false,
            same_filesystem_atomic_rename: false,
            file_flush: false,
            directory_flush: false,
            exclusive_writer_lock: false,
            disconnect_and_resume_keeps_exact_bytes: false,
        }
    }

    #[must_use]
    pub const fn exclusive_create_without_overwrite(&self) -> bool {
        self.exclusive_create_without_overwrite
    }

    #[must_use]
    pub const fn byte_conflict_detection(&self) -> bool {
        self.byte_conflict_detection
    }

    #[must_use]
    pub const fn same_filesystem_atomic_rename(&self) -> bool {
        self.same_filesystem_atomic_rename
    }

    #[must_use]
    pub const fn file_flush(&self) -> bool {
        self.file_flush
    }

    #[must_use]
    pub const fn directory_flush(&self) -> bool {
        self.directory_flush
    }

    #[must_use]
    pub const fn exclusive_writer_lock(&self) -> bool {
        self.exclusive_writer_lock
    }

    #[must_use]
    pub const fn disconnect_and_resume_keeps_exact_bytes(&self) -> bool {
        self.disconnect_and_resume_keeps_exact_bytes
    }

    /// Sind ALLE sieben Zusagen belegt?
    ///
    /// Der Gesundheitscheck liest genau das: eine unbelegte Zusage ist
    /// ungeeignete Dateisystemsemantik.
    #[must_use]
    pub const fn all_proven(&self) -> bool {
        self.exclusive_create_without_overwrite
            && self.byte_conflict_detection
            && self.same_filesystem_atomic_rename
            && self.file_flush
            && self.directory_flush
            && self.exclusive_writer_lock
            && self.disconnect_and_resume_keeps_exact_bytes
    }
}

/// Gibt die Sperre des lokalen Backends frei.
///
/// Der GRIFF auf die Sperrdatei liegt HIER und nicht bloss ihr Pfad: die
/// Betriebssystemsperre haengt am geoeffneten Griff, und ein weggeworfener
/// Griff waere eine sofort wieder freie Sperre. [`File::unlock`] nimmt `&self`,
/// also genuegt das schlichte Feld — es muss nichts herausbewegt werden.
struct LocalWriterLockRelease {
    held: Arc<AtomicBool>,
    lock_file: File,
}

impl WriterLockRelease for LocalWriterLockRelease {
    fn release(&self) {
        // Erst die Betriebssystemsperre, dann die Flagge: waere es umgekehrt,
        // koennte ein zweiter Nehmer die Flagge schon frei sehen, waehrend die
        // Sperre des Kerns noch steht — und dann an ihr scheitern statt sie zu
        // bekommen.
        //
        // Die DATEI bleibt liegen, und das ist Absicht. Wer sie entfernte,
        // oeffnete ein Fenster: ein zweiter Halter kann den Griff auf denselben
        // Inode schon haben, waehrend ein dritter unter demselben Namen eine
        // NEUE Datei anlegt und darauf ungehindert sperrt — zwei Halter
        // derselben Sperre. Die liegengebliebene Datei ist harmlos: sie traegt
        // keinen Inhalt, sperrt nichts, und [`CONTROL_FILES_V1`] haelt sie
        // ohnehin aus Inventar und Gesundheitsbericht heraus.
        //
        // Ein Fehlschlag ist nicht behandelbar und folgenlos: das Schliessen
        // des Griffs — spaetestens, wenn dieser Waechter faellt — gibt die
        // Sperre ohnehin frei.
        let _ = self.lock_file.unlock();
        self.held.store(false, Ordering::SeqCst);
    }
}

/// Ein Bestand auf dem lokalen Dateisystem.
pub struct LocalPathBackend {
    root: PathBuf,
    existing_only: bool,
    profile: ArchiveBackendProfileV1,
    held: Arc<AtomicBool>,
    /// Adressen, die die Fixture als „auf einem anderen Dateisystem" markiert.
    ///
    /// Ein echter Gerätewechsel innerhalb einer Bestandswurzel verlangt einen
    /// Mountpunkt und damit Rechte, die ein Test nicht hat; die Geraetepruefung
    /// unten laeuft trotzdem ECHT. Diese Menge ist die einzige Moeglichkeit,
    /// den ABLEHNUNGSZWEIG deterministisch zu belegen. Die native
    /// Zertifizierung ueber echte Mountgrenzen bleibt Stufe 7.
    foreign: Mutex<BTreeSet<String>>,
    /// Was die Erzeugungsstrecke mit dem Formatbeiwerk getan hat.
    ///
    /// Ein Feld und kein Rueckgabewert von [`LocalPathBackend::open`], weil die
    /// Aussage zum BESTAND gehoert und nicht zu einem Aufruf: wer das Backend
    /// spaeter in die Hand bekommt, muss sie noch lesen koennen.
    format_package: FormatPackageOutcomeV1,
}

impl LocalPathBackend {
    /// Oeffnet einen Bestand unter `root` mit `profile`.
    ///
    /// Die Reihenfolge ist die Zusage: der `archiveProfileHash` wird
    /// NEU BERECHNET und gegen `allowed-archive-profile-hashes` der gebundenen
    /// Policy gestellt, BEVOR irgendein Pfad des Ziels benutzt wird. Ein
    /// abgelehntes Profil legt deshalb nicht einmal die Wurzel an.
    ///
    /// Der letzte Schritt ist
    /// [`materialize_format_package`](crate::materialize_format_package): das
    /// Formatbeiwerk aus `design.md` §11.4 entsteht mit dem Bestand und nicht
    /// spaeter. Der Aufruf ist idempotent — ein bestehender Bestand erlebt
    /// einen Leerlauf — und er laeuft UNTER der exklusiven Schreibersperre;
    /// [`Self::format_package_outcome`] sagt danach, was tatsaechlich geschah.
    ///
    /// # Das Beiwerk entsteht UNTER der Sperre, oder es entsteht nicht
    ///
    /// Diese Strecke ist der einzige Schreibweg, der VOR jeder fachlichen
    /// Sperre laeuft, und die Nicht-Klobber-Zusage von
    /// [`Self::create_if_absent`] beruht ausdruecklich darauf, dass zwischen
    /// Pruefung und Schreiben kein zweiter Schreiber steht (siehe
    /// [`Self::atomic_rename_same_fs`]). Deshalb nimmt `open` die Sperre um
    /// genau diesen Aufruf und gibt sie danach wieder frei. Haelt sie ein
    /// anderer, wird das Beiwerk AUFGESCHOBEN
    /// ([`FormatPackageOutcomeV1::Deferred`]) und nicht sperrenfrei
    /// geschrieben: sonst saehe ein zweiter Oeffner die halb geschriebene
    /// Datei des ersten und hielte sie fuer eine Abweichung. Ohne Sperre kein
    /// Byte — und ein gehaltener Schreiber verhindert das Oeffnen nie.
    ///
    /// # Ein veraendertes Beiwerkbyte macht den Bestand NICHT unoeffenbar
    ///
    /// Traegt eine Beiwerkadresse andere Bytes, bleiben diese Bytes
    /// unangetastet und `open` traegt trotzdem; die Abweichung steht mit ihrer
    /// ZAHL als [`FormatPackageOutcomeV1::Deviating`] an
    /// [`Self::format_package_outcome`]. Das UEBRIGE Beiwerk entsteht dabei
    /// vollstaendig — die Abweichung einer Adresse laesst keine zweite
    /// ungeschrieben —, sonst waere ein Bestand mit einer fremden
    /// `README-FORMAT.txt` (Eintrag 1 von 18) offen und benutzbar und traege
    /// siebzehn Beiwerkadressen nicht. Das ist keine Nachsicht, sondern die
    /// Stelle, an die der Befund gehoert: das Beiwerk ist inventarisiert, seine
    /// Abweichung ist damit `EA-ARCHIVE-HEALTH-MODIFIED-FILE` des
    /// Gesundheitschecks — und der braucht ein OFFENES Backend, um einen
    /// beschaedigten Bestand ueberhaupt befunden zu koennen. Ein Bestand, den
    /// sein eigenes Diagnosewerkzeug nicht mehr aufmacht, ist nicht
    /// fail-closed, sondern stumm.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::ProfileNotAllowed`] fail-closed, wenn die Policy
    /// das Profil nicht traegt; sonst der Fehler des Wirtdateisystems. Ein
    /// Bytekonflikt des Beiwerks ist ausdruecklich KEIN Fehler dieser Strecke.
    pub fn open(
        root: PathBuf,
        profile: ArchiveBackendProfileV1,
        policy: &BoundArchiveProfilePolicyV1,
    ) -> Result<Self, ArchiveBackendError> {
        Self::open_with_mode(root, profile, policy, false)
    }

    /// Opens an existing directory, never creating its root or missing parents.
    /// Subsequent writes retain this restriction. This path-based check does
    /// not establish mount identity or exclude replacement/symlink races.
    ///
    /// # Errors
    /// Rejects disallowed profiles before I/O; absent roots, non-directories
    /// and filesystem failures return an error.
    pub fn open_existing(
        root: PathBuf,
        profile: ArchiveBackendProfileV1,
        policy: &BoundArchiveProfilePolicyV1,
    ) -> Result<Self, ArchiveBackendError> {
        Self::open_with_mode(root, profile, policy, true)
    }

    fn open_with_mode(
        root: PathBuf,
        profile: ArchiveBackendProfileV1,
        policy: &BoundArchiveProfilePolicyV1,
        existing_only: bool,
    ) -> Result<Self, ArchiveBackendError> {
        policy.require(profile.profile_hash()?)?;
        if existing_only {
            require_directory(&root)?;
        } else {
            fs::create_dir_all(&root).map_err(|_| ArchiveBackendError::Io)?;
        }
        let backend = Self {
            root,
            existing_only,
            profile,
            held: Arc::new(AtomicBool::new(false)),
            foreign: Mutex::new(BTreeSet::new()),
            format_package: FormatPackageOutcomeV1::NotAttempted,
        };
        // Der LETZTE Schritt der Erzeugungsstrecke, bevor die erste
        // Archivadresse benutzt wird: `design.md` §11.4 fuehrt das
        // Formatbeiwerk als Verpflichtung JEDES Bestands, und Stufe 2 ist die
        // erste, die Bestaende erzeugt.
        let format_package = backend.materialize_format_package_under_lock()?;
        backend.require_existing_root()?;
        Ok(Self {
            format_package,
            ..backend
        })
    }

    /// Materialisiert das Beiwerk UNTER der exklusiven Schreibersperre.
    ///
    /// Drei Ausgaenge, und keiner davon ist ein Fehler dieser Strecke: die
    /// Sperre ist frei und das Beiwerk entsteht; die Sperre ist fremd und das
    /// Beiwerk wird aufgeschoben; einzelne Adressen weichen ab, der REST
    /// entsteht trotzdem und der Bestand bleibt offenbar. Der Fehler des
    /// Wirtdateisystems wird dagegen herausgereicht —
    /// ein Bestand, in den nicht geschrieben werden kann, ist kein Bestand, den
    /// dieses Programm fuehren kann.
    fn materialize_format_package_under_lock(
        &self,
    ) -> Result<FormatPackageOutcomeV1, ArchiveBackendError> {
        let lock = match self.acquire_writer_lock() {
            Ok(lock) => lock,
            Err(ArchiveBackendError::AlreadyLocked) => return Ok(FormatPackageOutcomeV1::Deferred),
            Err(error) => return Err(error),
        };
        if self.existing_only {
            // Only the fixed format package may prepare its nested schema
            // directories. Each child is created under an existing parent;
            // arbitrary archive writes never recreate a missing parent chain.
            for (relative, _) in crate::FORMAT_PACKAGE_FILES_V1 {
                if let Some(parent) = Path::new(relative).parent() {
                    let mut directory = self.root.clone();
                    for component in parent.components() {
                        directory.push(component);
                        self.ensure_directory(&directory)?;
                    }
                }
            }
        }
        // Der berichtende Weg und nicht `materialize_format_package`: die
        // Zahl der Abweichungen ist der Beobachtungspunkt, und ein `Result`,
        // das im Fehlerfall den Bericht verwirft, traegt sie nicht.
        let outcome = match materialize_format_package_reporting(self)? {
            (_, deviating) if deviating.is_empty() => FormatPackageOutcomeV1::Materialized,
            (_, deviating) => FormatPackageOutcomeV1::Deviating {
                deviating_file_count: deviating.len(),
            },
        };
        // AUSDRUECKLICH hier: die Sperre gehoert zur Materialisierung und nicht
        // zum Backend. Wer nach `open` schreiben will, nimmt sie selbst — sonst
        // haette das Oeffnen eines Bestands ihn stillschweigend belegt.
        drop(lock);
        Ok(outcome)
    }

    /// Wie [`Self::open`], aber OHNE Policypruefung.
    ///
    /// Nur fuer die Kratzwurzel des Capability-Tests: sie ist kein Bestand und
    /// traegt keine Archivobjekte.
    fn open_scratch(
        root: PathBuf,
        profile: ArchiveBackendProfileV1,
        existing_only: bool,
    ) -> Result<Self, ArchiveBackendError> {
        if existing_only {
            require_directory(&root)?;
        } else {
            fs::create_dir_all(&root).map_err(|_| ArchiveBackendError::Io)?;
        }
        Ok(Self {
            root,
            existing_only,
            profile,
            held: Arc::new(AtomicBool::new(false)),
            foreign: Mutex::new(BTreeSet::new()),
            // Die Kratzwurzel ist kein Bestand: sie traegt kein Beiwerk, und
            // der Versuch findet hier ausdruecklich nicht statt.
            format_package: FormatPackageOutcomeV1::NotAttempted,
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Was die Erzeugungsstrecke mit dem Formatbeiwerk getan hat.
    ///
    /// Der Beobachtungspunkt zu [`Self::open`]: das Beiwerk entsteht unter der
    /// Sperre, wird bei fremder Sperre aufgeschoben und macht einen Bestand mit
    /// abweichendem Byte nicht unoeffenbar.
    #[must_use]
    pub const fn format_package_outcome(&self) -> FormatPackageOutcomeV1 {
        self.format_package
    }

    #[must_use]
    pub const fn profile(&self) -> &ArchiveBackendProfileV1 {
        &self.profile
    }

    /// Der neu berechnete `archiveProfileHash` dieses Bestands.
    ///
    /// # Errors
    ///
    /// Der Kodierfehler des Profilkerns.
    pub fn profile_hash(&self) -> Result<Hash32, ArchiveBackendError> {
        self.profile.profile_hash()
    }

    fn absolute(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    /// Das vollstaendige Objektinventar dieses Bestands.
    ///
    /// Wurzelrelativ, byteweise aufsteigend, duplikatfrei, mit
    /// [`ea_crypto::object_hash`] ueber die EXAKTEN Dateibytes je Eintrag —
    /// auch fuer Beiwerk ohne Exact-Object-Praefix. Die Kontrolldateien aus
    /// [`CONTROL_FILES_V1`] bleiben draussen.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::Io`] beim Lesen, sonst der Formfehler der Liste.
    pub fn inventory(&self) -> Result<ArchiveInventoryListV1, ArchiveBackendError> {
        let mut entries = Vec::new();
        for relative in self.walk()? {
            let bytes = fs::read(self.absolute(&relative)).map_err(|_| ArchiveBackendError::Io)?;
            entries.push(ArchiveInventoryEntryV1::new(&relative, object_hash(&bytes)));
        }
        ArchiveInventoryListV1::new(entries).map_err(ArchiveBackendError::Format)
    }

    /// Alle wurzelrelativen Pfade unter `root`, ohne die Kontrolldateien.
    ///
    /// Ausgeblendet werden GENAU die zwei Kontrolldateien an der Wurzel und
    /// sonst nichts — die Kratzwurzel des Capability-Tests eingeschlossen.
    /// Ein Verzeichnis am NAMEN auszublenden hiesse, dass Bytes darin fuer
    /// Inventar, Verifikation und Waisenerkennung unsichtbar waeren.
    fn walk(&self) -> Result<Vec<String>, ArchiveBackendError> {
        let mut found = Vec::new();
        self.walk_into(&self.root, "", &mut found)?;
        found.sort();
        Ok(found)
    }

    fn walk_into(
        &self,
        directory: &Path,
        prefix: &str,
        found: &mut Vec<String>,
    ) -> Result<(), ArchiveBackendError> {
        // Jeder Lesefehler wird PROPAGIERT und nie als „leeres Verzeichnis"
        // gelesen. Ein verschluckter `PermissionDenied` machte das Inventar
        // still kuerzer, und an der Wurzel machte er es LEER — dann waeren
        // Quell- und Zielinventar eines Profilwechsels beide leer und
        // bytegleich, und der Zeiger schaltete auf eine Migration um, die
        // nichts uebernommen hat. Genau diese stille Herabstufung ist
        // verboten.
        let read = fs::read_dir(directory).map_err(|_| ArchiveBackendError::Io)?;
        for entry in read {
            let entry = entry.map_err(|_| ArchiveBackendError::Io)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let relative = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}{name}")
            };
            let kind = entry.file_type().map_err(|_| ArchiveBackendError::Io)?;
            if kind.is_dir() {
                self.walk_into(&entry.path(), &format!("{relative}/"), found)?;
            } else if kind.is_file() && !CONTROL_FILES_V1.contains(&relative.as_str()) {
                found.push(relative);
            }
        }
        Ok(())
    }

    /// Schreibt den aktiven Profilzeiger ATOMAR.
    ///
    /// Erst in eine Nebendatei, dann Flush, dann Rename: ein halb
    /// geschriebener Zeiger waere ein Bestand ohne aktives Profil.
    ///
    /// Dies ist die EINZIGE ueberschreibende Schreibstelle dieser Crate, und
    /// sie ist es mit Absicht: der Zeiger ist eine Aussage ueber die
    /// INSTALLATION und kein Archivobjekt, und die Ruecknahme eines
    /// vollzogenen Wechsels schreibt ihn ein zweites Mal mit ANDEREN Bytes
    /// (Quellprofil, naechsthoehere Generation). Sie laeuft deshalb bewusst
    /// ueber `fs::rename` und nicht ueber
    /// [`ArchiveBackend::atomic_rename_same_fs`], die ein bestehendes Ziel
    /// niemals ersetzt — ein Zeigerwechsel dorthin geleitet endete am
    /// Bytekonflikt und die Ruecknahme waere unmoeglich.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::Io`] oder [`ArchiveBackendError::FlushFailed`].
    pub fn write_active_profile_pointer(
        &self,
        pointer: &ActiveProfilePointerCoreV1,
    ) -> Result<(), ArchiveBackendError> {
        self.require_existing_root()?;
        let bytes =
            encode_active_profile_pointer_core(pointer).map_err(ArchiveBackendError::Format)?;
        let target = self.absolute(CONTROL_FILES_V1[1]);
        let staging = self.absolute(&format!("{}{STAGING_SUFFIX_V1}", CONTROL_FILES_V1[1]));
        let _ = fs::remove_file(&staging);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging)
            .map_err(|_| ArchiveBackendError::Io)?;
        file.write_all(&bytes)
            .map_err(|_| ArchiveBackendError::Io)?;
        file.sync_all()
            .map_err(|_| ArchiveBackendError::FlushFailed)?;
        drop(file);
        fs::rename(&staging, &target).map_err(|_| ArchiveBackendError::Io)?;
        sync_directory_at(&self.root)
    }

    /// Die Lesesicht dieses Bestands als [`ArchiveSource`].
    ///
    /// PRODUKTIONSFLAECHE und keine Testhilfe: die vollstaendige
    /// Offlineverifikation des Ziels braucht sie, und `ea-verify` nimmt genau
    /// diesen Port.
    #[must_use]
    pub const fn as_archive_source(&self) -> LocalPathArchiveSource<'_> {
        LocalPathArchiveSource { backend: self }
    }

    /// Der aktive Profilzeiger, sofern einer geschrieben wurde.
    #[must_use]
    pub fn active_profile_pointer_bytes(&self) -> Option<Vec<u8>> {
        fs::read(self.absolute(CONTROL_FILES_V1[1])).ok()
    }

    /// Reads an existing canonical pointer without creating files or a root.
    ///
    /// Only an absent pointer under a readable existing root returns `None`.
    /// Supported macOS/GNU Linux targets use the same no-follow/nonblocking
    /// open and inode checks as the local lock diagnosis. Other targets refuse
    /// the read. The caller must keep ancestor names stable: these path-based
    /// checks do not prove an atomic snapshot or mount identity.
    ///
    /// # Errors
    /// [`ArchiveBackendError::Io`] for unavailable roots, nonregular/symlink
    /// files, unreadable or replaced paths; [`ArchiveBackendError::Format`]
    /// for oversized or invalid/noncanonical pointer bytes.
    pub fn read_active_profile_pointer(
        &self,
    ) -> Result<Option<ActiveProfilePointerCoreV1>, ArchiveBackendError> {
        self.require_existing_root()?;
        let result = read_existing_profile_pointer(&self.root);
        self.require_existing_root()?;
        result
    }

    /// Fuehrt den Capability-Test dieses Profils aus.
    ///
    /// Er laeuft in einer KRATZWURZEL unterhalb der Bestandswurzel — also auf
    /// demselben Dateisystem, sonst sagte der Rename-Nachweis nichts ueber den
    /// Bestand — und raeumt sie danach ab. Er benutzt ausdruecklich die ECHTEN
    /// Trait-Methoden; ein nachgebauter Pfad bewiese nichts ueber den Code, der
    /// spaeter schreibt.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::Io`], wenn die Kratzwurzel nicht anlegbar ist.
    pub fn run_capability_test(
        &self,
        vector: &CapabilityTestVectorV1,
    ) -> Result<CapabilityReportV1, ArchiveBackendError> {
        self.require_existing_root()?;
        let scratch_parent = self.root.join(CAPABILITY_SCRATCH_DIR_V1);
        let scratch_root = scratch_parent.join(vector.id());
        let _ = fs::remove_dir_all(&scratch_root);
        if self.existing_only {
            self.ensure_directory(&scratch_parent)?;
            self.ensure_directory(&scratch_root)?;
        }
        let scratch = Self::open_scratch(
            scratch_root.clone(),
            self.profile.clone(),
            self.existing_only,
        )?;
        let report = scratch.capability_probes(vector);
        let _ = fs::remove_dir_all(&scratch_root);
        report
    }

    fn capability_probes(
        &self,
        vector: &CapabilityTestVectorV1,
    ) -> Result<CapabilityReportV1, ArchiveBackendError> {
        let mut report = CapabilityReportV1::unproven();
        let probe = ArchivePath::in_dir(ea_archive::RECOVERY_REPORTS_DIR_V1, "capability.probe")?;
        let renamed =
            ArchivePath::in_dir(ea_archive::RECOVERY_REPORTS_DIR_V1, "capability.renamed")?;

        self.create_non_object_if_absent(&probe, vector.object_bytes())?;
        // Exklusives Create ohne Ueberschreiben: die bytegleiche Wiederholung
        // traegt, die Datei bleibt unveraendert.
        self.create_non_object_if_absent(&probe, vector.object_bytes())?;
        report.exclusive_create_without_overwrite =
            fs::read(self.absolute(probe.as_str())).ok().as_deref() == Some(vector.object_bytes());

        let mut other = vector.object_bytes().to_vec();
        other[0] ^= 0x01;
        report.byte_conflict_detection = matches!(
            self.create_non_object_if_absent(&probe, &other),
            Err(ArchiveBackendError::ByteConflict)
        );

        report.file_flush = self.sync_file(&probe).is_ok();
        report.directory_flush = self.sync_directory(&probe).is_ok();

        report.same_filesystem_atomic_rename = self.atomic_rename_same_fs(&probe, &renamed).is_ok()
            && fs::read(self.absolute(renamed.as_str())).ok().as_deref()
                == Some(vector.object_bytes());

        // Die Sperre wird an ZWEI GRIFFEN gemessen und nicht an einem. Ein
        // einzelnes `LocalPathBackend` weist den zweiten Griff schon an seiner
        // prozessinternen Flagge ab, BEVOR das Dateisystem ueberhaupt gefragt
        // ist — die Zusage, die dieser Bericht traegt, ist aber eine ueber das
        // DATEISYSTEM. Ein zweiter Griff traegt eine eigene Flagge; die
        // Ablehnung unten kann deshalb nur aus der Betriebssystemsperre kommen,
        // und ein Traeger, der `flock`/`LockFileEx` stillschweigend ignoriert,
        // faellt hier auf statt durch.
        let contender =
            Self::open_scratch(self.root.clone(), self.profile.clone(), self.existing_only)?;
        let held = self.acquire_writer_lock()?;
        report.exclusive_writer_lock = matches!(
            contender.acquire_writer_lock(),
            Err(ArchiveBackendError::AlreadyLocked)
        );
        drop(held);
        report.exclusive_writer_lock =
            report.exclusive_writer_lock && contender.acquire_writer_lock().is_ok();

        // Verbindungsabbruch und Wiederanlauf: der Bestand wird ERNEUT
        // geoeffnet — alle Griffe des ersten Oeffnens sind damit fort — und die
        // Bytes werden exakt nachgeprueft.
        let reopened =
            Self::open_scratch(self.root.clone(), self.profile.clone(), self.existing_only)?;
        report.disconnect_and_resume_keeps_exact_bytes =
            reopened.read_bytes(renamed.as_str()).as_deref() == Some(vector.object_bytes())
                && matches!(
                    reopened.create_non_object_if_absent(&renamed, vector.object_bytes()),
                    Ok(())
                );
        Ok(report)
    }

    fn read_bytes(&self, relative: &str) -> Option<Vec<u8>> {
        fs::read(self.absolute(relative)).ok()
    }

    /// Die Bytes unter einer wurzelrelativen Adresse.
    ///
    /// Crate-intern und NICHT hinter dem Testfeature: der Gesundheitscheck
    /// braucht sie im Produktionspfad.
    pub(crate) fn read_relative(&self, relative: &str) -> Option<Vec<u8>> {
        self.read_bytes(relative)
    }

    /// Alle wurzelrelativen Pfade des Bestands, aufsteigend.
    ///
    /// OEFFENTLICH seit Task 10, und zwar so eng wie moeglich: sie gibt
    /// ADRESSEN heraus und kein einziges Byte. Der Gesundheitscheck brauchte
    /// sie schon crate-intern; seit dieser Stufe braucht sie auch der
    /// Writer-Sync-Klient, der aus committeten Archivbytes eine Warteschlange
    /// ableitet und dafuer wissen muss, unter welcher Adresse ein Objekt
    /// committet liegt. Das GEGENSTUECK — `relative_paths_below_for_test` —
    /// bleibt hinter `test-support`: es filtert, und ein Filter ist eine
    /// Bequemlichkeit des Tests und keine Zusage des Ports.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::Io`] beim Durchlaufen des Bestands.
    pub fn relative_paths(&self) -> Result<Vec<String>, ArchiveBackendError> {
        self.walk()
    }

    fn require_existing_root(&self) -> Result<(), ArchiveBackendError> {
        if self.existing_only {
            require_directory(&self.root)?;
        }
        Ok(())
    }

    // Existing mode creates one directory only. In particular the configured
    // root is never itself a create target, even for a flat archive filename.
    fn ensure_directory(&self, directory: &Path) -> Result<(), ArchiveBackendError> {
        if !self.existing_only {
            return fs::create_dir_all(directory).map_err(|_| ArchiveBackendError::Io);
        }
        self.require_existing_root()?;
        if directory == self.root {
            return Ok(());
        }
        if !directory.starts_with(&self.root) {
            return Err(ArchiveBackendError::Path);
        }
        require_directory(directory.parent().ok_or(ArchiveBackendError::Path)?)?;
        match fs::create_dir(directory) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                require_directory(directory)
            }
            Err(_) => Err(ArchiveBackendError::Io),
        }
    }

    fn create_bytes_if_absent(
        &self,
        relative: &ArchivePath,
        bytes: &[u8],
    ) -> Result<(), ArchiveBackendError> {
        self.require_existing_root()?;
        let absolute = self.absolute(relative.as_str());
        if let Ok(existing) = fs::read(&absolute) {
            return if existing == bytes {
                Ok(())
            } else {
                Err(ArchiveBackendError::ByteConflict)
            };
        }
        if let Some(parent) = absolute.parent() {
            self.ensure_directory(parent)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&absolute)
            .map_err(|_| ArchiveBackendError::Io)?;
        file.write_all(bytes).map_err(|_| ArchiveBackendError::Io)?;
        Ok(())
    }
}

fn require_directory(path: &Path) -> Result<(), ArchiveBackendError> {
    let metadata = fs::metadata(path).map_err(|_| ArchiveBackendError::Io)?;
    if !metadata.is_dir() {
        return Err(ArchiveBackendError::Io);
    }
    Ok(())
}

/// Oeffnet `path` und belegt es mit der exklusiven Betriebssystemsperre.
///
/// Preserves I/O errors separately from actual lock contention. The legacy
/// open mode maps them back to AlreadyLocked at its public boundary.
/// `create(true)` never truncates the persistent lock file.
fn open_and_lock_exclusively(path: &Path) -> Result<File, ArchiveBackendError> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|_| ArchiveBackendError::Io)?;
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => ArchiveBackendError::AlreadyLocked,
        std::fs::TryLockError::Error(_) => ArchiveBackendError::Io,
    })?;
    Ok(file)
}

/// Flusht ein Verzeichnis.
///
/// Auf Unix wird das Verzeichnis geoeffnet und `fsync` gerufen — ohne diesen
/// zweiten Flush kann ein neu angelegter Name nach einem Stromausfall fehlen.
/// Auf anderen Plattformen laesst sich ein Verzeichnis nicht als Datei oeffnen;
/// dort bleibt der dauerhafte Verzeichniseintrag eine Zusage des
/// Backendprofils, und ihr nativer Nachweis gehoert zur Stufe-7-Zertifizierung.
fn sync_directory_at(directory: &Path) -> Result<(), ArchiveBackendError> {
    #[cfg(unix)]
    {
        let file = File::open(directory).map_err(|_| ArchiveBackendError::FlushFailed)?;
        file.sync_all()
            .map_err(|_| ArchiveBackendError::FlushFailed)
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
        Ok(())
    }
}

/// Die Geraetekennung eines Pfades.
#[cfg(unix)]
fn device_of(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt as _;
    fs::metadata(path).ok().map(|metadata| metadata.dev())
}

#[cfg(not(unix))]
fn device_of(path: &Path) -> Option<u64> {
    let _ = path;
    None
}

impl ArchiveBackend for LocalPathBackend {
    fn create_if_absent(
        &self,
        relative: &ArchivePath,
        bytes: &ExactObjectBytes,
    ) -> Result<(), ArchiveBackendError> {
        self.create_bytes_if_absent(relative, bytes.as_bytes())
    }

    fn create_non_object_if_absent(
        &self,
        relative: &ArchivePath,
        bytes: &[u8],
    ) -> Result<(), ArchiveBackendError> {
        self.create_bytes_if_absent(relative, bytes)
    }

    fn sync_file(&self, relative: &ArchivePath) -> Result<(), ArchiveBackendError> {
        let file = File::open(self.absolute(relative.as_str()))
            .map_err(|_| ArchiveBackendError::FlushFailed)?;
        file.sync_all()
            .map_err(|_| ArchiveBackendError::FlushFailed)
    }

    fn sync_directory(&self, relative: &ArchivePath) -> Result<(), ArchiveBackendError> {
        sync_directory_at(&self.absolute(relative.directory()))
    }

    fn staged_paths(&self) -> Result<Vec<String>, ArchiveBackendError> {
        Ok(self
            .walk()?
            .into_iter()
            .filter(|relative| ea_archive::is_staging_path(relative))
            .collect())
    }

    fn visit_managed_blobs(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        self.visit_managed_contents(visitor)
    }

    /// Entfernt die Adresse und macht den VERSCHWUNDENEN Namen dauerhaft.
    ///
    /// Der zweite Flush ist dieselbe Zusage wie bei
    /// [`ArchiveBackend::create_directory_if_absent`], nur in die andere
    /// Richtung: ohne ihn kann ein entfernter Name nach einem Stromausfall
    /// wieder dastehen, obwohl seine Bytes fort sind. Eine FEHLENDE Adresse
    /// laeuft durch, ohne das Verzeichnis anzufassen — es gibt dann nichts,
    /// dessen Verschwinden dauerhaft zu machen waere.
    fn remove_if_present(&self, relative: &ArchivePath) -> Result<(), ArchiveBackendError> {
        self.require_existing_root()?;
        let absolute = self.absolute(relative.as_str());
        match fs::remove_file(&absolute) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(ArchiveBackendError::Io),
        }
        sync_directory_at(&self.absolute(relative.directory()))
    }

    fn atomic_rename_same_fs(
        &self,
        from: &ArchivePath,
        to: &ArchivePath,
    ) -> Result<(), ArchiveBackendError> {
        {
            let foreign = self.foreign.lock().unwrap_or_else(PoisonError::into_inner);
            if foreign.contains(from.as_str()) || foreign.contains(to.as_str()) {
                return Err(ArchiveBackendError::NotSameFilesystem);
            }
        }
        self.require_existing_root()?;
        let source = self.absolute(from.as_str());
        let target = self.absolute(to.as_str());
        let target_directory = self.absolute(to.directory());
        self.ensure_directory(&target_directory)?;
        // Die ECHTE Geraetepruefung. Sie vergleicht die tragenden
        // Verzeichnisse, weil das Ziel noch nicht existiert.
        let source_device = device_of(&self.absolute(from.directory()));
        let target_device = device_of(&target_directory);
        if let (Some(left), Some(right)) = (source_device, target_device)
            && left != right
        {
            return Err(ArchiveBackendError::NotSameFilesystem);
        }
        // NICHT KLOBBERND. `fs::rename` ersetzt auf POSIX ein bestehendes Ziel
        // stillschweigend; genau darueber liesse sich Create-if-absent
        // umgehen — die Staging-Adresse ist frei, also traegt der Rename, und
        // die veroeffentlichten Bytes waeren ueberschrieben. Ein bestehendes
        // Ziel MUSS deshalb bytegleich sein: dann wird die Quelladresse
        // verworfen und das Ziel bleibt unangetastet. Sonst ist es ein
        // Bytekonflikt.
        //
        // Die exklusive Schreibersperre und die Produktzusage „genau ein
        // aktiver Writer" schliessen einen zweiten Schreiber zwischen Pruefung
        // und Rename aus; ohne sie waere auch das `create_new` von
        // Create-if-absent nur die halbe Aussage.
        if let Ok(existing) = fs::read(&target) {
            let staged = fs::read(&source).map_err(|_| ArchiveBackendError::Io)?;
            if existing != staged {
                return Err(ArchiveBackendError::ByteConflict);
            }
            return fs::remove_file(&source).map_err(|_| ArchiveBackendError::Io);
        }
        fs::rename(&source, &target).map_err(|_| ArchiveBackendError::Io)
    }

    fn create_directory_if_absent(&self, directory: &str) -> Result<(), ArchiveBackendError> {
        if !LAYOUT_PATHS_V1.contains(&directory) || !directory.ends_with('/') {
            return Err(ArchiveBackendError::Path);
        }
        let absolute = self.absolute(directory);
        self.ensure_directory(&absolute)?;
        // Beide Flushes sind noetig und keiner ist Zutat: der erste macht das
        // Verzeichnis selbst dauerhaft, der zweite seinen NAMEN, der im
        // Elternverzeichnis lebt. Ein leeres Verzeichnis traegt keine Datei, an
        // deren Adresse sich `sync_directory` haengen liesse.
        sync_directory_at(&absolute)?;
        if let Some(parent) = absolute.parent() {
            sync_directory_at(parent)?;
        }
        Ok(())
    }

    /// Nimmt die exklusive Schreibersperre des Bestands.
    ///
    /// Die Sperre ist eine BETRIEBSSYSTEMSPERRE ueber der Sperrdatei —
    /// `flock(2)` auf Unix, `LockFileEx` auf Windows, beides ueber
    /// [`File::try_lock`] — und ausdruecklich NICHT das blosse Anlegen der
    /// Datei. Der Unterschied ist der harte Abbruch: `create_new` haengt die
    /// Sperre an das DASEIN der Datei, und nach `SIGKILL` oder Stromausfall
    /// liegt sie fuer immer da. Der Bestand waere dann dauerhaft
    /// unbeschreibbar — auch fuer die Wiederaufnahme von `ea-writer`, die
    /// selbst diese Sperre nimmt. Der Kern dagegen gibt die Sperre beim
    /// Prozessende frei; die zurueckbleibende Datei ist danach ein leeres
    /// Gehaeuse.
    ///
    /// # Kein Reaper und keine PID-Pruefung
    ///
    /// Beide waeren die uebliche Nacharbeit an einer Dasein-Sperre und beide
    /// sind hier UEBERFLUESSIG: eine hinterlegte PID muss geraten werden (sie
    /// kann laengst neu vergeben sein), und ein Aufraeumer, der eine „alte"
    /// Sperrdatei entfernt, entscheidet ueber Leben und Tod eines fremden
    /// Prozesses ohne Beleg. Die Sperre des Kerns kennt die Antwort dagegen
    /// genau und ohne Heuristik.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::AlreadyLocked`], wenn sie schon gehalten wird —
    /// im Legacy-Modus ebenso bei I/O-Fehlern; Existing-Modus reicht diese
    /// als [`ArchiveBackendError::Io`] heraus. Fail-closed:
    /// ohne genommene Sperre wird nicht geschrieben, und der Aufrufer hat an
    /// dieser Stelle ohnehin nur EINE Handlung.
    fn acquire_writer_lock(&self) -> Result<WriterLock, ArchiveBackendError> {
        self.require_existing_root()?;
        if self.held.swap(true, Ordering::SeqCst) {
            return Err(ArchiveBackendError::AlreadyLocked);
        }
        let lock_file = self.absolute(CONTROL_FILES_V1[0]);
        // ZWEI Stufen, und die aeussere ist nicht bloss Beiwerk: die
        // Prozessflagge schliesst einen zweiten Nehmer ueber DIESES Backend
        // aus, die Betriebssystemsperre einen ueber jedes andere — ein zweites
        // `LocalPathBackend` auf derselben Wurzel oder einen fremden Prozess.
        // Fehlt eine von beiden, ist die Sperre in genau einem der beiden
        // Faelle wirkungslos.
        //
        match open_and_lock_exclusively(&lock_file) {
            Ok(file) => Ok(WriterLock::new(Arc::new(LocalWriterLockRelease {
                held: Arc::clone(&self.held),
                lock_file: file,
            }))),
            Err(error) => {
                self.held.store(false, Ordering::SeqCst);
                Err(if self.existing_only {
                    error
                } else {
                    ArchiveBackendError::AlreadyLocked
                })
            }
        }
    }
}

impl std::fmt::Debug for LocalPathBackend {
    /// Nennt NICHT die Wurzel.
    ///
    /// Der Ausgabepfad ist genau die Groesse, die aus jedem Urbild und jedem
    /// Auditereignis herausgehalten wird (`design.md` §11.5); eine Fehlerzeile
    /// ist kein Grund, sie doch zu nennen. Der Rumpf existiert, damit
    /// `Result::unwrap_err` an diesem Typ aufrufbar ist.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalPathBackend")
            .field("writer_lock_held", &self.held.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

/// Die Lesesicht auf einen VEROEFFENTLICHTEN lokalen Bestand.
///
/// Sie liefert JEDE veroeffentlichte Bytesequenz — auch Beiwerk ohne
/// Exact-Object-Praefix, sonst waere `nonObjectFileCount` nicht bildbar. Die
/// Kontrolldateien des Backends bleiben draussen: sie gehoeren der
/// Installation, nicht dem Bestand.
///
/// # Warum die Staging-Adressen draussen bleiben
///
/// [`ea_archive::ArchiveInventory`] klassifiziert AUSSCHLIESSLICH am 9-Byte-
/// Exact-Object-Praefix, und der Pfadhinweis ist dort ausdruecklich keine
/// Identitaet. Die gestagten Bytes SIND das exakte Archivobjekt; ohne diesen
/// Filter waere eine liegengebliebene `entries/<seq>_<hash>.eip.staging`
/// deshalb ein Kettenknoten wie jeder andere — und weil ein zweiter Anlauf
/// frische Geheimnisse und damit einen ANDEREN `entryHash` zieht, lagen danach
/// zwei Eintragsobjekte mit derselben Sequenz im Bestand. Die Kettenpruefung
/// meldete eine `SequenceCollision`, und der Gesundheitsbericht traege
/// DAUERHAFT einen Fork-Befund ueber einen Bestand, dessen COMMITTETE Bytes
/// stimmen.
///
/// Die Regel steht deshalb genau EINMAL, in [`ea_archive::is_staging_path`],
/// und jeder Verbraucher dieser Sicht teilt sie: der Kettenkopf der
/// Finalisierung, jeder Verifikationslauf und der Gesundheitscheck.
///
/// Verloren geht dabei nichts: [`LocalPathBackend::relative_paths`] blendet
/// nichts aus, und der Gesundheitscheck meldet die liegengebliebene Datei
/// darueber weiterhin als temporaere Datei
/// ([`crate::HealthFinding::OrphanGrantOrTemporaryFile`]).
pub struct LocalPathArchiveSource<'a> {
    backend: &'a LocalPathBackend,
}

impl ArchiveSource for LocalPathArchiveSource<'_> {
    fn visit_blobs(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        let paths = self.backend.walk().map_err(|_| ArchiveError::Unavailable)?;
        for relative in paths {
            if ea_archive::is_staging_path(&relative) {
                continue;
            }
            let bytes = fs::read(self.backend.absolute(&relative))
                .map_err(|_| ArchiveError::Unavailable)?;
            visitor(ArchiveBlob::new(&relative, &bytes))?;
        }
        Ok(())
    }
}

/// Die Beobachtungsflaeche, die Task 10 und Task 12 benutzen.
///
/// Hinter `feature = "test-support"`, das aus einem Cargo-Grund ein
/// Default-Feature ist: ein Integrationstest kann das Feature SEINER EIGENEN
/// Crate nicht einschalten, und der uebliche Ausweg — eine
/// Selbst-Dev-Dependency — schriebe `Cargo.lock` um. Ein Release der Stufe 7
/// baut mit `--no-default-features` und traegt diese Flaeche dann nicht.
#[cfg(any(test, feature = "test-support"))]
impl LocalPathBackend {
    #[must_use]
    pub fn exists_for_test(&self, relative: &str) -> bool {
        self.absolute(relative).is_file()
    }

    #[must_use]
    pub fn directory_exists_for_test(&self, relative: &str) -> bool {
        self.absolute(relative).is_dir()
    }

    #[must_use]
    pub fn read_for_test(&self, relative: &str) -> Option<Vec<u8>> {
        self.read_bytes(relative)
    }

    /// Alle wurzelrelativen Pfade unterhalb von `relative`, aufsteigend.
    #[must_use]
    pub fn relative_paths_below_for_test(&self, relative: &str) -> Vec<String> {
        self.walk()
            .unwrap_or_default()
            .into_iter()
            .filter(|found| found.starts_with(relative))
            .collect()
    }

    /// Schreibt Bytes UNTER UMGEHUNG von Create-if-absent.
    ///
    /// Nur so lassen sich „unerwartet geaenderte Datei" und ein
    /// liegengebliebenes Staging-Artefakt ueberhaupt herstellen. Sie ist die
    /// einzige mutierende Methode dieser Flaeche und ausdruecklich kein Weg,
    /// den ein Produktionspfad nehmen darf.
    ///
    /// # Panics
    ///
    /// Wenn das Wirtdateisystem das Schreiben ablehnt.
    pub fn overwrite_for_test(&self, relative: &str, bytes: &[u8]) {
        self.require_existing_root()
            .expect("die Bestandswurzel muss vorhanden sein");
        let absolute = self.absolute(relative);
        if let Some(parent) = absolute.parent() {
            self.ensure_directory(parent)
                .expect("das Elternverzeichnis muss anlegbar sein");
        }
        fs::write(absolute, bytes).expect("das Schreiben muss gelingen");
    }

    /// Legt Bytes ohne Klassifikation ab — der Weg, mit dem eine Fixture einen
    /// vollstaendigen Bestand materialisiert.
    ///
    /// # Panics
    ///
    /// Wie [`Self::overwrite_for_test`].
    pub fn materialize_for_test(&self, relative: &str, bytes: &[u8]) {
        self.overwrite_for_test(relative, bytes);
    }

    /// Entfernt eine Datei.
    ///
    /// # Panics
    ///
    /// Wenn die Datei nicht entfernbar ist.
    pub fn remove_for_test(&self, relative: &str) {
        fs::remove_file(self.absolute(relative)).expect("das Entfernen muss gelingen");
    }

    /// Markiert `relative` als auf einem ANDEREN Dateisystem liegend.
    pub fn mark_foreign_filesystem_for_test(&self, relative: &str) {
        self.foreign
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(relative.to_owned());
    }

    /// Nimmt die Markierung zurueck.
    ///
    /// Sie existiert, damit ein Zeuge nicht nur den ABBRUCH messen kann,
    /// sondern auch, dass er FORTSETZBAR ist: ein Renamefehler, der die
    /// Zieladresse frei laesst, muss propagieren UND das unversehrte Staging
    /// liegen lassen, aus dem derselbe Pfad danach umbenennt. Ohne die
    /// Ruecknahme waere die zweite Haelfte nicht messbar.
    pub fn clear_foreign_filesystem_for_test(&self, relative: &str) {
        self.foreign
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(relative);
    }
}
