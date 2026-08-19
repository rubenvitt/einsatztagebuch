//! Die Haltung eines Produktivgeraets und die Zeilen der Support-Matrix.
//!
//! `design.md`:1969 verlangt von einem Produktivgeraet vollstaendige
//! Datentraegerverschluesselung, gesperrte Benutzerkonten, eine automatische
//! Bildschirmsperre und einen unterstuetzten Patchstand — und im selben Satz,
//! dass die Anwendung PRUEFT, was das Betriebssystem zuverlaessig meldet, und
//! nicht automatisch pruefbare Voraussetzungen im Go-live-Bericht dokumentiert.
//! Diese Datei uebersetzt das in vier benannte Anforderungen mit DREI moeglichen
//! Ergebnissen. Das dritte ist der Zweck der Uebung: ein Signal, das eine
//! Plattform nicht belegen kann, ist `Unknown` und niemals ein Pass.
//!
//! Ein `Fail` sperrt eine Sitzung in produktiver Rolle. Ein `Unknown` sperrt sie
//! ebenfalls UND erzeugt zusaetzlich eine Pflichtzeile fuer den Go-live-Bericht:
//! an einem gemessenen Mangel ist nichts aufzuklaeren, an einem unbelegbaren
//! Signal sehr wohl.

use ea_format::KeyProtectionProfileV1;

use crate::contract::KeyError;

/// Eine der vier Anforderungen an ein Produktivgeraet.
///
/// Geschlossen und ohne Platzhalter: eine fuenfte Anforderung bricht jeden
/// `match` dieser Datei und erzwingt eine Entscheidung.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PostureRequirement {
    /// Vollstaendige Datentraegerverschluesselung.
    FullDiskEncryption,
    /// Ein gesperrtes und nicht geteiltes Benutzerkonto.
    LockedNonSharedAccount,
    /// Eine automatische Bildschirmsperre.
    AutomaticScreenLock,
    /// Ein unterstuetzter Patchstand des Betriebssystems.
    SupportedOsPatchLevel,
}

impl PostureRequirement {
    /// Alle vier Anforderungen, in Deklarationsreihenfolge.
    pub const ALL: [Self; 4] = [
        Self::FullDiskEncryption,
        Self::LockedNonSharedAccount,
        Self::AutomaticScreenLock,
        Self::SupportedOsPatchLevel,
    ];

    /// Der Beweiscode eines erfuellten Signals.
    #[must_use]
    pub const fn pass(self) -> PostureCheck {
        PostureCheck::Pass {
            evidence_code: match self {
                Self::FullDiskEncryption => "EA-POSTURE-FDE-ENABLED",
                Self::LockedNonSharedAccount => "EA-POSTURE-ACCOUNT-LOCKED-EXCLUSIVE",
                Self::AutomaticScreenLock => "EA-POSTURE-SCREEN-LOCK-ENFORCED",
                Self::SupportedOsPatchLevel => "EA-POSTURE-OS-PATCH-SUPPORTED",
            },
        }
    }

    /// Der Beweiscode eines GEMESSENEN Mangels.
    #[must_use]
    pub const fn fail(self) -> PostureCheck {
        PostureCheck::Fail {
            evidence_code: match self {
                Self::FullDiskEncryption => "EA-POSTURE-FDE-DISABLED",
                Self::LockedNonSharedAccount => "EA-POSTURE-ACCOUNT-SHARED",
                Self::AutomaticScreenLock => "EA-POSTURE-SCREEN-LOCK-ABSENT",
                Self::SupportedOsPatchLevel => "EA-POSTURE-OS-PATCH-UNSUPPORTED",
            },
        }
    }

    /// Der Beweiscode eines Signals, das diese Plattform nicht belegen kann.
    #[must_use]
    pub const fn unknown(self) -> PostureCheck {
        PostureCheck::Unknown {
            evidence_code: match self {
                Self::FullDiskEncryption => "EA-POSTURE-FDE-UNREPORTABLE",
                Self::LockedNonSharedAccount => "EA-POSTURE-ACCOUNT-UNREPORTABLE",
                Self::AutomaticScreenLock => "EA-POSTURE-SCREEN-LOCK-UNREPORTABLE",
                Self::SupportedOsPatchLevel => "EA-POSTURE-OS-PATCH-UNREPORTABLE",
            },
        }
    }
}

/// Das Ergebnis EINER Haltungspruefung.
///
/// Die drei Varianten sind getrennt und tragen je einen Beweiscode. Es gibt
/// keinen `bool`: ein `bool` haette `Unknown` in ein `false` oder — schlimmer —
/// in ein `true` gedrueckt.
///
/// Die Beweiscodes stammen aus [`PostureRequirement`] und nicht aus einem
/// Adapter. Ein nativer Adapter entscheidet, WELCHES Ergebnis er meldet, und
/// nicht, wie es heisst.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PostureCheck {
    /// Das Signal ist gelesen und erfuellt.
    Pass {
        /// Stabiler Beweiscode.
        evidence_code: &'static str,
    },
    /// Das Signal ist gelesen und NICHT erfuellt.
    Fail {
        /// Stabiler Beweiscode.
        evidence_code: &'static str,
    },
    /// Das Signal ist auf dieser Plattform nicht belegbar.
    Unknown {
        /// Stabiler Beweiscode.
        evidence_code: &'static str,
    },
}

impl PostureCheck {
    #[must_use]
    pub const fn evidence_code(self) -> &'static str {
        match self {
            Self::Pass { evidence_code }
            | Self::Fail { evidence_code }
            | Self::Unknown { evidence_code } => evidence_code,
        }
    }

    #[must_use]
    pub const fn is_pass(self) -> bool {
        matches!(self, Self::Pass { .. })
    }

    #[must_use]
    pub const fn is_unknown(self) -> bool {
        matches!(self, Self::Unknown { .. })
    }
}

/// Die Haltung eines Geraets ueber die vier Anforderungen.
///
/// Die Felder sind oeffentlich, weil ein Bericht genau diese vier Ergebnisse IST
/// und nichts weiter verbirgt. Was er ausdruecklich nicht traegt:
/// Wiederherstellungsschluessel, Benutzernamen, Softwareinventare oder sonstige
/// Haltungsdaten.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DevicePostureReport {
    /// Vollstaendige Datentraegerverschluesselung.
    pub full_disk_encryption: PostureCheck,
    /// Gesperrtes, nicht geteiltes Benutzerkonto.
    pub locked_non_shared_account: PostureCheck,
    /// Automatische Bildschirmsperre.
    pub automatic_screen_lock: PostureCheck,
    /// Unterstuetzter Patchstand des Betriebssystems.
    pub supported_os_patch_level: PostureCheck,
}

impl DevicePostureReport {
    /// Ein Bericht, in dem KEINE der vier Anforderungen belegt ist.
    ///
    /// Der Ausgangszustand jedes nativen Adapters der Stufe 2: sie liest keines
    /// der vier Signale, weil dafuer keine native API-Familie zur Verfuegung
    /// steht (`docs/adr/0001-toolchain-and-cryptography-dependencies.md:152-153`).
    /// Vier `Unknown` sind die WAHRE Aussage darueber; vier `Pass` waeren eine
    /// falsche und vier `Fail` eine ebenso falsche.
    #[must_use]
    pub const fn unresolved() -> Self {
        Self {
            full_disk_encryption: PostureRequirement::FullDiskEncryption.unknown(),
            locked_non_shared_account: PostureRequirement::LockedNonSharedAccount.unknown(),
            automatic_screen_lock: PostureRequirement::AutomaticScreenLock.unknown(),
            supported_os_patch_level: PostureRequirement::SupportedOsPatchLevel.unknown(),
        }
    }

    /// Das Ergebnis EINER Anforderung.
    #[must_use]
    pub const fn check(&self, requirement: PostureRequirement) -> PostureCheck {
        match requirement {
            PostureRequirement::FullDiskEncryption => self.full_disk_encryption,
            PostureRequirement::LockedNonSharedAccount => self.locked_non_shared_account,
            PostureRequirement::AutomaticScreenLock => self.automatic_screen_lock,
            PostureRequirement::SupportedOsPatchLevel => self.supported_os_patch_level,
        }
    }

    /// Ob eine Sitzung in produktiver Rolle entstehen darf.
    ///
    /// Nur wenn ALLE VIER Anforderungen belegt erfuellt sind. Ein `Fail` sperrt,
    /// und ein `Unknown` sperrt ebenfalls — es ist kein automatischer Pass.
    #[must_use]
    pub fn is_production_ready(&self) -> bool {
        PostureRequirement::ALL
            .into_iter()
            .all(|requirement| self.check(requirement).is_pass())
    }

    /// Die Anforderungen, die eine Go-live-Evidenzzeile erzwingen.
    ///
    /// Genau die unbelegbaren. Ein `Fail` steht NICHT hier: er ist gemessen, und
    /// die Abhilfe ist das Einschalten des Signals, nicht eine Evidenzzeile.
    #[must_use]
    pub fn go_live_follow_up(&self) -> Vec<PostureRequirement> {
        PostureRequirement::ALL
            .into_iter()
            .filter(|requirement| self.check(*requirement).is_unknown())
            .collect()
    }
}

/// Der synchrone Port zur Haltung des Geraets.
///
/// Synchron wie der ganze Rust-Kern, damit `Box<dyn DevicePostureProvider>`
/// trivial konstruierbar ist.
pub trait DevicePostureProvider {
    /// Liest die vier Signale dieser Plattform.
    fn report(&self) -> Result<DevicePostureReport, KeyError>;
}

/// Eine Zeile der v0.1-Support-Matrix.
///
/// Vier Zeilen, weil `design.md` genau vier Produktivziele nennt: Windows 11
/// `x86_64`, aktuelles und vorheriges macOS auf `arm64`, unterstuetztes Intel
/// `x86_64` und Ubuntu 24.04 LTS `x86_64`. Die Zeile entscheidet, WELCHE Signale
/// ein Adapter ueberhaupt lesen darf — ein Signal, das nur auf einer anderen
/// Zeile verlaesslich ist, ist auf dieser keines.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SupportMatrixRow {
    /// Windows 11 auf `x86_64`.
    Windows11X86_64,
    /// macOS auf `arm64`.
    MacOsArm64,
    /// macOS auf unterstuetztem Intel `x86_64`.
    MacOsX86_64,
    /// Ubuntu 24.04 LTS auf `x86_64`.
    Ubuntu2404X86_64,
}

impl SupportMatrixRow {
    /// Alle vier Zeilen, in Deklarationsreihenfolge.
    pub const ALL: [Self; 4] = [
        Self::Windows11X86_64,
        Self::MacOsArm64,
        Self::MacOsX86_64,
        Self::Ubuntu2404X86_64,
    ];

    /// Die Zeile des HOSTS, auf dem dieser Code laeuft.
    ///
    /// `None` fuer jedes andere Ziel; das ist kein Fehler, sondern die Aussage,
    /// dass v0.1 dieses Ziel nicht als Produktivziel fuehrt.
    ///
    /// Ueber `cfg!` und nicht ueber `#[cfg]`: so uebersetzen alle vier Zweige auf
    /// jedem Host, und ein Tippfehler in einem Zielnamen faellt hier statt erst
    /// auf dem Zielsystem auf.
    #[must_use]
    pub const fn current_host() -> Option<Self> {
        if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
            Some(Self::Windows11X86_64)
        } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            Some(Self::MacOsArm64)
        } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
            Some(Self::MacOsX86_64)
        } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            Some(Self::Ubuntu2404X86_64)
        } else {
            None
        }
    }

    /// Das Schutzprofil, das der native Schluesselspeicher dieser Zeile
    /// erreicht.
    ///
    /// [`KeyProtectionProfileV1::OsWrapped`] fuer alle vier, und das ist eine
    /// Entscheidung und kein Versaeumnis: `HardwareNonExportable` ist nach
    /// `design.md`:1489 nur mit einem ausdruecklich unterstuetzten Provider
    /// zulaessig, und die Liste dieser Provider
    /// ([`crate::require_claimed_protection_profile`]) ist leer. Eine Zeile, die
    /// hier Hardware nennte, ohne dort zu stehen, waere der stille Ruecktritt
    /// auf ungeschuetzte Schluesseldateien, den derselbe Absatz verbietet.
    ///
    /// Rueckgabetyp ist das Profil des WIRE-FORMATS. Diese Crate fuehrt
    /// ausdruecklich keine zweite Schutzprofil-Aufzaehlung.
    #[must_use]
    pub const fn reachable_protection_profile(self) -> KeyProtectionProfileV1 {
        match self {
            Self::Windows11X86_64
            | Self::MacOsArm64
            | Self::MacOsX86_64
            | Self::Ubuntu2404X86_64 => KeyProtectionProfileV1::OsWrapped,
        }
    }

    /// Der native Haltungsadapter dieser Zeile.
    #[must_use]
    pub fn posture_provider(self) -> Box<dyn DevicePostureProvider> {
        match self {
            Self::Windows11X86_64 => Box::new(crate::windows::WindowsDevicePosture),
            Self::MacOsArm64 | Self::MacOsX86_64 => Box::new(crate::macos::MacOsDevicePosture),
            Self::Ubuntu2404X86_64 => Box::new(crate::linux::UbuntuDevicePosture),
        }
    }
}

/// Eine Haltungsattrappe mit VORGEGEBENEM Bericht.
///
/// Nur unter `test-support`, das nie ein Default-Feature ist: ein Produktivbau
/// darf keinen Haltungsanbieter uebersetzen, dessen Ergebnis ein Aufrufer
/// bestimmt.
#[cfg(feature = "test-support")]
pub struct DevicePostureProviderFake {
    report: DevicePostureReport,
}

#[cfg(feature = "test-support")]
impl DevicePostureProviderFake {
    /// Alle vier Anforderungen belegt erfuellt.
    #[must_use]
    pub const fn all_passing() -> Self {
        Self {
            report: DevicePostureReport {
                full_disk_encryption: PostureRequirement::FullDiskEncryption.pass(),
                locked_non_shared_account: PostureRequirement::LockedNonSharedAccount.pass(),
                automatic_screen_lock: PostureRequirement::AutomaticScreenLock.pass(),
                supported_os_patch_level: PostureRequirement::SupportedOsPatchLevel.pass(),
            },
        }
    }

    /// Keine der vier Anforderungen belegbar.
    #[must_use]
    pub const fn unreportable() -> Self {
        Self {
            report: DevicePostureReport::unresolved(),
        }
    }

    /// Genau `requirement` gemessen mangelhaft, die uebrigen erfuellt.
    #[must_use]
    pub fn failing(requirement: PostureRequirement) -> Self {
        Self {
            report: Self::all_passing()
                .report
                .with(requirement, requirement.fail()),
        }
    }

    /// Genau `requirement` unbelegbar, die uebrigen erfuellt.
    #[must_use]
    pub fn unknown(requirement: PostureRequirement) -> Self {
        Self {
            report: Self::all_passing()
                .report
                .with(requirement, requirement.unknown()),
        }
    }

    /// Die fehlende automatische Bildschirmsperre.
    #[must_use]
    pub fn failing_screen_lock() -> Self {
        Self::failing(PostureRequirement::AutomaticScreenLock)
    }
}

#[cfg(feature = "test-support")]
impl DevicePostureReport {
    fn with(mut self, requirement: PostureRequirement, check: PostureCheck) -> Self {
        match requirement {
            PostureRequirement::FullDiskEncryption => self.full_disk_encryption = check,
            PostureRequirement::LockedNonSharedAccount => self.locked_non_shared_account = check,
            PostureRequirement::AutomaticScreenLock => self.automatic_screen_lock = check,
            PostureRequirement::SupportedOsPatchLevel => self.supported_os_patch_level = check,
        }
        self
    }
}

#[cfg(feature = "test-support")]
impl DevicePostureProvider for DevicePostureProviderFake {
    fn report(&self) -> Result<DevicePostureReport, KeyError> {
        Ok(self.report)
    }
}
