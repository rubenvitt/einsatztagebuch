//! Die dateigestuetzte Ablage des Zeremoniezustands.
//!
//! [`BootstrapStore`] ist der Port; eine Zeremonie ueberlebt Neustarts nur,
//! wenn ihn jemand umsetzt. Die Zeugen in `crates/ea-admin/tests` benutzen
//! dafuer eine Ablage im Speicher — die ueberlebt den Prozess nicht, und genau
//! das soll sie auch nicht. Diese hier ist die produktive Umsetzung fuer einen
//! Wirt mit einem Dateisystem.
//!
//! # Warum in dieser Crate und nicht in einer eigenen `ea-admin-fs`
//!
//! Der Baum trennt Dateisystemarbeit dort in eine eigene Kiste, wo sie ein
//! eigenes PROTOKOLL ist: `ea-archive-fs` traegt Create-if-absent,
//! Verzeichnis-Flush, Rename auf demselben Dateisystem und exklusive
//! Schreibsperren ueber einem Bestand aus vielen Objekten. Hier gibt es EINE
//! Datei, zwei Vorgaenge und kein Protokoll darueber hinaus; `ea-recovery`
//! haelt mit `load_trust_anchor` auf derselben Ebene ebenfalls einen
//! Dateizugriff, ohne dafuer eine Kiste zu eroeffnen. Eine Crategrenze koennte
//! hier nichts trennen, was nicht schon getrennt ist — sie kostete einen
//! Manifesteintrag und eine Ausnahme auf der wasm32-Positivliste, und
//! `ea-admin` steht dort ohnehin schon als ausgenommen
//! (`tools/xtask/src/main.rs`).
//!
//! # Was hier NICHT entschieden wird
//!
//! Wo die Datei liegt. Den Pfad waehlt der Aufrufer; `apps/cli` legt sie neben
//! den kuenftigen Anker und begruendet das dort. Diese Ablage schreibt, was
//! ihr gegeben wird, an den Ort, der ihr genannt wird.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
};

use crate::{AdminError, BootstrapStateV1, BootstrapStore};

/// Der Zeremoniezustand in EINER Datei.
pub struct FileBootstrapStore {
    path: PathBuf,
    // The descriptor's lifetime is the kernel lease; closing it releases the
    // lock even after process death. Never unlink the lock file on release.
    lease: Option<File>,
    #[cfg(feature = "test-support")]
    fail_after_rename_once: bool,
}

impl FileBootstrapStore {
    /// Die Ablage unter `path`.
    ///
    /// Legt nichts an: eine Ablage, die beim Bauen schriebe, hinterliesse eine
    /// Zeremonie, die niemand begonnen hat.
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self {
            path,
            lease: None,
            #[cfg(feature = "test-support")]
            fail_after_rename_once: false,
        }
    }

    /// Holds the exclusive kernel lease until this store is dropped.
    /// Acquire before loading state and keep the store for the whole ceremony
    /// operation. Acquisition itself never reads or creates ceremony state.
    ///
    /// Supported on macOS x86_64/aarch64 and Linux GNU 64-bit x86_64/aarch64.
    /// Other platforms refuse this explicit API; their legacy unleased port
    /// remains unchanged and provides no continuous lease guarantee.
    ///
    /// # Errors
    /// [`AdminError::BootstrapStoreUnavailable`] on contention, unsupported
    /// platforms, or an unsafe/unavailable lock file. No host path is exposed.
    pub fn acquire_lease(mut self) -> Result<Self, AdminError> {
        if let Some(lease) = &self.lease {
            validate_bootstrap_lock(&self.lock_path(), lease)?;
        } else {
            self.lease = Some(open_bootstrap_lock(&self.lock_path())?);
        }
        Ok(self)
    }

    /// Internal host boundary: require a retained lease and its current inode.
    pub(crate) fn ensure_lease(&self) -> Result<(), AdminError> {
        let lease = self
            .lease
            .as_ref()
            .ok_or(AdminError::BootstrapStoreUnavailable)?;
        validate_bootstrap_lock(&self.lock_path(), lease)
    }

    /// Injects one test-only error after the real state rename, before its
    /// parent flush. It cannot roll back the state already present on disk.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn fail_next_parent_flush_after_rename_for_test(&mut self) {
        self.fail_after_rename_once = true;
    }

    /// Der Pfad der Zustandsdatei.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Der Pfad, auf dem das neue Abbild entsteht, bevor es das alte ersetzt.
    ///
    /// Als Suffix an die GANZE Zeichenkette angehaengt und nicht ueber
    /// [`Path::with_extension`]: das ersetzte eine vorhandene Endung und liesse
    /// zwei verschiedene Zustandsdateien auf dieselbe Zwischendatei zeigen.
    fn temporary_path(&self) -> PathBuf {
        let mut temporary = self.path.clone().into_os_string();
        temporary.push(".writing");
        PathBuf::from(temporary)
    }

    fn lock_path(&self) -> PathBuf {
        let mut lock = self.path.clone().into_os_string();
        lock.push(".lock");
        PathBuf::from(lock)
    }
}

impl BootstrapStore for FileBootstrapStore {
    /// # Errors
    /// [`AdminError::BootstrapStoreUnavailable`], wenn die Datei nicht LESBAR
    /// ist, und [`AdminError::BootstrapStateShape`], wenn sie lesbar ist und
    /// nicht passt. Die Trennung ist dieselbe wie bei
    /// `ea_recovery::RecoveryError::{Io, TrustAnchor}`: ein Betreiber
    /// unterscheidet daran einen nicht eingehaengten Datentraeger von einem
    /// Zustand, der nicht mehr der seine ist.
    ///
    /// Eine FEHLENDE Datei ist keines von beidem, sondern schlicht keine
    /// Zeremonie.
    fn load(&self) -> Result<Option<BootstrapStateV1>, AdminError> {
        if let Some(lease) = &self.lease {
            validate_bootstrap_lock(&self.lock_path(), lease)?;
        }
        match fs::read(&self.path) {
            Ok(image) => BootstrapStateV1::from_persisted_image(&image).map(Some),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(AdminError::BootstrapStoreUnavailable),
        }
    }

    /// Schreibt GENAU [`BootstrapStateV1::persisted_image`] — vollstaendig
    /// oder gar nicht, und niemals einen frueheren Schritt ueber einen
    /// spaeteren.
    ///
    /// # Die Monotonie gehoert HIERHIN
    ///
    /// [`crate::BootstrapCoordinator`] weist einen Rueckschritt bereits ab —
    /// aber gegen den Zustand, den ER im Speicher haelt. Der Zeremoniezustand
    /// lebt jedoch in dieser Datei, und in sie schreiben auch zwei
    /// Koordinatoren nacheinander: ein aelterer Schnappschuss, aus einem
    /// zweiten Lauf oder einer laenger gehaltenen Instanz, naehme der
    /// Zeremonie sonst still ihre Versiegelung — und `:1349` liesse danach nur
    /// noch neue Organisations- und Ketten-IDs zu. Der vorhandene Stand wird
    /// deshalb vor jedem Schreiben gelesen; [`crate::BootstrapStep`] ist
    /// `Ord`, und „nur vorwaerts" ist damit ein Vergleich.
    ///
    /// Ein Abbild, das diese Ablage nicht ZURUECKLESEN koennte, wird gar nicht
    /// erst geschrieben — es entstuende sonst eine Zeremonie, die beim
    /// naechsten Start nicht mehr auffindbar waere. Heute kann sie jedes
    /// lesen; die Pruefung steht als Riegel und kostet eine Kodierung.
    ///
    /// # Wie geschrieben wird
    ///
    /// Erst in eine Zwischendatei — mit `O_CREAT|O_EXCL` und einem
    /// ausdruecklichen Rechtebit, wie `crates/ea-recovery/src/report.rs:208-231`
    /// und `crates/ea-archive-fs/src/bundle.rs:248-250` —, dann `sync_all`,
    /// dann ein Rename ueber die Zustandsdatei, dann ein `sync_all` auf das
    /// VERZEICHNIS (`bundle.rs:305-318`). `File::create` waere hier zweimal
    /// falsch: es folgte einem untergeschobenen Symlink und truebe das Ziel
    /// ab, und ohne den Verzeichnis-Flush waere die Zusage „entweder das alte
    /// Abbild oder das neue, nie ein halbes" ueber einen Absturz hinweg nicht
    /// wahr.
    ///
    /// # Errors
    /// [`AdminError::BootstrapStepRegression`] fuer einen frueheren Schritt als
    /// den persistierten; [`AdminError::BootstrapStateShape`] fuer ein Abbild,
    /// das diese Ablage nicht zurueckliest;
    /// [`AdminError::BootstrapStoreUnavailable`] fuer jeden Befund des
    /// Dateisystems. Die zugrunde liegende [`io::Error`] wird ausdruecklich
    /// NICHT durchgereicht — ihre Anzeige nimmt je nach Pfad den Hostpfad auf,
    /// und der gehoert in keine Diagnose.
    fn store(&mut self, state: &BootstrapStateV1) -> Result<(), AdminError> {
        // Legacy callers participate in the same kernel lock for this write,
        // including the monotonicity read and every .writing cleanup. Their
        // separate earlier load + later store is NOT a cross-process CAS.
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
        let _write_lease = if let Some(lease) = &self.lease {
            validate_bootstrap_lock(&self.lock_path(), lease)?;
            None
        } else {
            Some(open_bootstrap_lock(&self.lock_path())?)
        };
        let image = state.persisted_image();
        if BootstrapStateV1::from_persisted_image(&image)?.step() != state.step() {
            return Err(AdminError::BootstrapStateShape);
        }
        if let Some(persisted) = self.load()?
            && state.step() < persisted.step()
        {
            return Err(AdminError::BootstrapStepRegression);
        }

        let temporary = self.temporary_path();
        // Under the supported-platform lease, a leftover from a crashed writer
        // may be removed. A participating live writer cannot own it now.
        // The legacy path on other platforms has no such lease guarantee.
        let _ = fs::remove_file(&temporary);
        let written = (|| -> io::Result<()> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;

                options.mode(STATE_FILE_MODE_V1);
            }
            let mut file = options.open(&temporary)?;
            file.write_all(&image)?;
            file.sync_all()
        })();
        if written.is_err() {
            let _ = fs::remove_file(&temporary);
            return Err(AdminError::BootstrapStoreUnavailable);
        }
        fs::rename(&temporary, &self.path).map_err(|_| {
            let _ = fs::remove_file(&temporary);
            AdminError::BootstrapStoreUnavailable
        })?;
        #[cfg(feature = "test-support")]
        if std::mem::take(&mut self.fail_after_rename_once) {
            return Err(AdminError::BootstrapStoreUnavailable);
        }
        sync_parent_directory(&self.path)
    }
}

/// Das Rechtebit der Zustandsdatei.
///
/// Derselbe Wert und derselbe Grund wie `ea_recovery::OUTPUT_FILE_MODE_V1`
/// (`crates/ea-recovery/src/report.rs:113`): der Zeremoniezustand traegt zwar
/// kein Geheimnis, aber er traegt die Kennungen und Abdruecke einer
/// entstehenden Organisation, und die gehen niemanden ausser dem Konto an, das
/// die Zeremonie fuehrt.
const STATE_FILE_MODE_V1: u32 = 0o600;

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
fn open_bootstrap_lock(path: &Path) -> Result<File, AdminError> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    // Same pinned O_NOFOLLOW | O_NONBLOCK constants as ea-archive-fs's
    // local_path/lock_diagnosis. Linux aarch64 differs from x86_64.
    #[cfg(target_os = "macos")]
    const NOFOLLOW_NONBLOCK: i32 = 0x100 | 0x4;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    const NOFOLLOW_NONBLOCK: i32 = 0x20000 | 2048;
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    const NOFOLLOW_NONBLOCK: i32 = 0x8000 | 2048;

    let before = match fs::symlink_metadata(path) {
        Ok(metadata) if valid_bootstrap_lock(&metadata) => Some(metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        _ => return Err(AdminError::BootstrapStoreUnavailable),
    };
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(STATE_FILE_MODE_V1)
        .custom_flags(NOFOLLOW_NONBLOCK)
        .open(path)
        .map_err(|_| AdminError::BootstrapStoreUnavailable)?;
    let opened = file
        .metadata()
        .map_err(|_| AdminError::BootstrapStoreUnavailable)?;
    if !valid_bootstrap_lock(&opened)
        || before.is_some_and(|before| before.dev() != opened.dev() || before.ino() != opened.ino())
    {
        return Err(AdminError::BootstrapStoreUnavailable);
    }
    file.try_lock()
        .map_err(|_| AdminError::BootstrapStoreUnavailable)?;
    validate_bootstrap_lock(path, &file)?;
    Ok(file)
}

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
fn valid_bootstrap_lock(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    metadata.is_file()
        && metadata.len() == 0
        && metadata.nlink() == 1
        && metadata.mode() & 0o7777 == STATE_FILE_MODE_V1
}

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
fn validate_bootstrap_lock(path: &Path, file: &File) -> Result<(), AdminError> {
    use std::os::unix::fs::MetadataExt as _;
    let opened = file
        .metadata()
        .map_err(|_| AdminError::BootstrapStoreUnavailable)?;
    let named = fs::symlink_metadata(path).map_err(|_| AdminError::BootstrapStoreUnavailable)?;
    if valid_bootstrap_lock(&opened)
        && valid_bootstrap_lock(&named)
        && opened.dev() == named.dev()
        && opened.ino() == named.ino()
    {
        Ok(())
    } else {
        Err(AdminError::BootstrapStoreUnavailable)
    }
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
fn open_bootstrap_lock(_: &Path) -> Result<File, AdminError> {
    Err(AdminError::BootstrapStoreUnavailable)
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
fn validate_bootstrap_lock(_: &Path, _: &File) -> Result<(), AdminError> {
    Err(AdminError::BootstrapStoreUnavailable)
}

/// Flusht den Verzeichniseintrag, der eben durch das Rename entstanden ist.
///
/// Ohne ihn ist der Rename auf unix nach einem Stromausfall nicht zwingend da,
/// und die Zusage „entweder das alte Abbild oder das neue" gilt nur bis zum
/// naechsten Absturz. Dieselbe Bewegung und dieselbe Begruendung wie
/// `ea_archive_fs::bundle::sync_parent_directory`.
fn sync_parent_directory(target: &Path) -> Result<(), AdminError> {
    #[cfg(unix)]
    {
        let parent = match target.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let directory = File::open(parent).map_err(|_| AdminError::BootstrapStoreUnavailable)?;
        directory
            .sync_all()
            .map_err(|_| AdminError::BootstrapStoreUnavailable)
    }
    #[cfg(not(unix))]
    {
        let _ = target;
        Ok(())
    }
}
