//! Die Grammatik der Schluesselquellen und ihre Aufloesung.
//!
//! # EINE QUELLE WIRD BENANNT, NIE GEFUNDEN
//!
//! Drei Formen, und sonst keine:
//!
//! - `<pfad>` oder `file:<pfad>` — die Datei der Stufe 4: 32 Rohbytes oder
//!   64 Hexzeichen. Ein blosser Pfad ist diese Form, damit jeder Aufruf der
//!   Stufe 4 unveraendert weiterlaeuft.
//! - `container:<pfad>;passphrase-file=<pfad>` — der verschluesselte
//!   Container aus [`crate::encrypted_container`] mit der Passphrase aus einer
//!   Datei mit restriktiven Rechten.
//! - `pkcs11:module=<pfad>;token=<label>;id=<hex>;pin-file=<pfad>` — die
//!   vollstaendige PKCS#11-Referenz aus [`crate::pkcs11`] mit der PIN aus
//!   einer solchen Datei.
//!
//! Kein Scannen, keine Voreinstellung, keine Umgebungsvariable, kein Prompt:
//! die Quelle steht vollstaendig in der Angabe. Passphrase und PIN kommen aus
//! einer DATEI, weil argv in `ps` sichtbar ist, die Umgebung an Kindprozesse
//! vererbt wird und ein echofreier Terminalprompt eine weitere Kiste
//! (`termios`) braeuchte.
//!
//! # DIE FELDGRAMMATIK
//!
//! Hinter dem Praefix trennen `;` die Felder. Bei `container:` steht der Pfad
//! POSITIONAL als erstes Glied, alle weiteren Glieder sind `name=wert`. Bei
//! `pkcs11:` sind alle Glieder `name=wert`. Benannte Felder duerfen in
//! beliebiger Reihenfolge stehen; jedes ist Pflicht, keines darf doppelt
//! stehen, kein unbekanntes ist erlaubt, kein Wert darf leer sein. Ein Wert
//! kann kein `;` enthalten — das Trennzeichen ist nicht maskierbar, und ein
//! Pfad mit Semikolon ist in dieser Grammatik nicht benennbar.
//!
//! Die Praefixe werden EXAKT und klein geschrieben verglichen. `FILE:` ist
//! kein Praefix, sondern der Anfang eines Pfades.
//!
//! # NICHT-UTF-8 IST EIN PFAD
//!
//! Ein Argument, das kein gueltiges UTF-8 ist, kann keine Praefixgrammatik
//! tragen und wird als Pfad der Dateiform genommen — auch dann, wenn seine
//! ersten Bytes wie ein Praefix aussehen. Pfade duerfen nach der Regel der
//! CLI beliebige Bytes tragen; ein halb geparster Pfad waere die schlechtere
//! Antwort.

use core::fmt;
use std::{
    ffi::OsStr,
    fs::{self, File},
    io::{self, Read as _},
    path::{Path, PathBuf},
};

use ea_crypto::{CoseSigner, HpkeRecipientPrivateKey, SecretBytes, SecretVec};

use crate::{
    ExitCode, RecoveryError,
    decrypt::load_key_material,
    encrypted_container::{ContainedKeyKind, EncryptedKeyContainer},
    pkcs11::Pkcs11KeyReference,
    target::restrictive_permissions_available,
};

/// Eine explizit benannte Schluesselquelle. Kein Scannen, keine Voreinstellung.
///
/// # Kein `Debug`
///
/// Jede Variante traegt Hostpfade eines Recovery-Mediums. Sie duerfen nach
/// der Global Constraint des Stage-5-Plans in keine Ausgabe gelangen, und ein
/// `Debug` waere der bequemste Weg dorthin.
#[derive(Clone, Eq, PartialEq)]
pub enum KeySourceSpec {
    /// Stufe-4-Form: 32 Rohbytes oder 64 Hexzeichen (`<pfad>` oder
    /// `file:<pfad>`).
    File(PathBuf),
    /// `container:<pfad>;passphrase-file=<pfad>`.
    Container {
        /// Der Container aus [`EncryptedKeyContainer::write_new`].
        path: PathBuf,
        /// Die Datei mit der Passphrase, gelesen ueber [`read_secret_file`].
        passphrase_file: PathBuf,
    },
    /// `pkcs11:module=<pfad>;token=<label>;id=<hex>;pin-file=<pfad>`.
    Pkcs11 {
        /// Modul, Token und Schluessel-ID — alle drei Pflicht.
        reference: Pkcs11KeyReference,
        /// Die Datei mit der PIN, gelesen ueber [`read_secret_file`].
        pin_file: PathBuf,
    },
}

/// Das Praefix der ausgeschriebenen Dateiform.
const FILE_PREFIX: &str = "file:";
/// Das Praefix des verschluesselten Containers.
const CONTAINER_PREFIX: &str = "container:";
/// Das Praefix der PKCS#11-Referenz.
const PKCS11_PREFIX: &str = "pkcs11:";
/// Das Trennzeichen zwischen zwei Feldern.
const FIELD_SEPARATOR: char = ';';

impl KeySourceSpec {
    /// Parst GENAU EINEN argv-Wert. Rein: liest keine Datei und beruehrt kein
    /// Medium.
    ///
    /// # Errors
    ///
    /// Ein [`KeySourceSpecError`] fuer jedes fehlende, doppelte, unbekannte,
    /// leere oder falsch geformte Feld einer `container:`- oder
    /// `pkcs11:`-Angabe. Die Dateiform kann nicht scheitern: jeder Pfad ist
    /// ein Pfad.
    pub fn parse(argument: &OsStr) -> Result<Self, KeySourceSpecError> {
        let Some(text) = argument.to_str() else {
            return Ok(Self::File(PathBuf::from(argument)));
        };
        if let Some(path) = text.strip_prefix(FILE_PREFIX) {
            return Ok(Self::File(PathBuf::from(path)));
        }
        if let Some(rest) = text.strip_prefix(CONTAINER_PREFIX) {
            return parse_container(rest);
        }
        if let Some(rest) = text.strip_prefix(PKCS11_PREFIX) {
            return parse_pkcs11(rest);
        }
        Ok(Self::File(PathBuf::from(text)))
    }
}

/// `container:<pfad>;passphrase-file=<pfad>`.
fn parse_container(rest: &str) -> Result<KeySourceSpec, KeySourceSpecError> {
    const SOURCE: KeySourceKind = KeySourceKind::Container;
    const PASSPHRASE_FILE: &str = "passphrase-file=";

    let mut segments = rest.split(FIELD_SEPARATOR);
    // Der Pfad ist POSITIONAL: `split` liefert immer mindestens ein Glied.
    let path = segments.next().unwrap_or_default();
    if path.is_empty() {
        return Err(KeySourceSpecError::EmptyValue {
            source: SOURCE,
            field: "path",
        });
    }
    let mut fields = NamedFields::new(SOURCE, &[PASSPHRASE_FILE]);
    for segment in segments {
        fields.take(segment)?;
    }
    let passphrase_file = fields.required(PASSPHRASE_FILE)?;
    Ok(KeySourceSpec::Container {
        path: PathBuf::from(path),
        passphrase_file: PathBuf::from(passphrase_file),
    })
}

/// `pkcs11:module=<pfad>;token=<label>;id=<hex>;pin-file=<pfad>`.
fn parse_pkcs11(rest: &str) -> Result<KeySourceSpec, KeySourceSpecError> {
    const SOURCE: KeySourceKind = KeySourceKind::Pkcs11;
    const MODULE: &str = "module=";
    const TOKEN: &str = "token=";
    const ID: &str = "id=";
    const PIN_FILE: &str = "pin-file=";

    let mut fields = NamedFields::new(SOURCE, &[MODULE, TOKEN, ID, PIN_FILE]);
    for segment in rest.split(FIELD_SEPARATOR) {
        fields.take(segment)?;
    }
    // Die Pflichtpruefung laeuft in der DOKUMENTIERTEN Reihenfolge, damit ein
    // Aufruf, dem mehrere Felder fehlen, immer dasselbe zuerst benannt
    // bekommt.
    let module = fields.required(MODULE)?;
    let token = fields.required(TOKEN)?;
    let id = fields.required(ID)?;
    let pin_file = fields.required(PIN_FILE)?;
    let reference = Pkcs11KeyReference::new(PathBuf::from(module), token.to_owned(), id)?;
    Ok(KeySourceSpec::Pkcs11 {
        reference,
        pin_file: PathBuf::from(pin_file),
    })
}

/// Die benannten Felder einer Angabe, waehrend sie eingesammelt werden.
///
/// Die Feldnamen tragen ihr `=` mit (`passphrase-file=`), damit die Anzeige
/// eines Fehlers genau das Glied nennt, das der Aufrufer tippen muss.
struct NamedFields<'a> {
    source: KeySourceKind,
    known: &'a [&'static str],
    values: Vec<(&'static str, &'a str)>,
}

impl<'a> NamedFields<'a> {
    const fn new(source: KeySourceKind, known: &'a [&'static str]) -> Self {
        Self {
            source,
            known,
            values: Vec::new(),
        }
    }

    /// Nimmt ein Glied `name=wert` entgegen.
    fn take(&mut self, segment: &'a str) -> Result<(), KeySourceSpecError> {
        // Ein Glied ohne `=` wird NICHT zurueckgespiegelt: es koennte ein
        // Pfad sein, der an die falsche Stelle geraten ist.
        let Some(equals) = segment.find('=') else {
            return Err(KeySourceSpecError::MalformedField {
                source: self.source,
            });
        };
        let (name, value) = segment.split_at(equals + 1);
        let Some(field) = self.known.iter().copied().find(|known| *known == name) else {
            // Der NAME wird genannt, nie der Wert: der Name ist Grammatik, die
            // der Aufrufer selbst getippt hat; der Wert kann ein Pfad sein.
            return Err(KeySourceSpecError::UnknownField {
                source: self.source,
                field: name.trim_end_matches('=').to_owned(),
            });
        };
        if self.values.iter().any(|(seen, _)| *seen == field) {
            return Err(KeySourceSpecError::DuplicateField {
                source: self.source,
                field,
            });
        }
        if value.is_empty() {
            return Err(KeySourceSpecError::EmptyValue {
                source: self.source,
                field,
            });
        }
        self.values.push((field, value));
        Ok(())
    }

    /// Der Wert eines Pflichtfeldes.
    fn required(&self, field: &'static str) -> Result<&'a str, KeySourceSpecError> {
        self.values
            .iter()
            .find(|(seen, _)| *seen == field)
            .map(|(_, value)| *value)
            .ok_or(KeySourceSpecError::MissingField {
                source: self.source,
                field,
            })
    }
}

/// Die Quellart, in deren Grammatik ein Fehler liegt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeySourceKind {
    /// `container:`.
    Container,
    /// `pkcs11:`.
    Pkcs11,
}

impl KeySourceKind {
    /// Der Praefixname ohne Doppelpunkt, wie er in der Anzeige steht.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Container => "container",
            Self::Pkcs11 => "pkcs11",
        }
    }
}

impl fmt::Display for KeySourceKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Ein Fehler in der Quellenangabe: ein AUFRUFFEHLER, Exitcode 2.
///
/// Die Anzeige benennt das betroffene Feld WOERTLICH und nennt nie einen
/// Wert: Werte sind Pfade eines Recovery-Mediums. `Debug` ist abgeleitet,
/// weil kein Feld dieses Typs einen Wert traegt — [`Self::UnknownField`]
/// traegt den NAMEN, den der Aufrufer selbst getippt hat.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KeySourceSpecError {
    /// Ein Pflichtfeld fehlt.
    MissingField {
        /// Die Quellart.
        source: KeySourceKind,
        /// Das Feld samt `=`, wie es zu tippen ist.
        field: &'static str,
    },
    /// Ein Feld steht zweimal.
    DuplicateField {
        /// Die Quellart.
        source: KeySourceKind,
        /// Das Feld samt `=`.
        field: &'static str,
    },
    /// Ein Feld, das diese Quellart nicht kennt.
    UnknownField {
        /// Die Quellart.
        source: KeySourceKind,
        /// Der getippte Feldname ohne `=`.
        field: String,
    },
    /// Ein Glied ohne `=`. Wird nicht zurueckgespiegelt — es koennte ein
    /// Pfad sein.
    MalformedField {
        /// Die Quellart.
        source: KeySourceKind,
    },
    /// Ein Feld ohne Wert.
    EmptyValue {
        /// Die Quellart.
        source: KeySourceKind,
        /// Das Feld samt `=`, oder `path` fuer das positionale Glied.
        field: &'static str,
    },
    /// Ein Feld, das Hex sein muss und keines ist.
    NotHex {
        /// Die Quellart.
        source: KeySourceKind,
        /// Das Feld samt `=`.
        field: &'static str,
    },
    /// Ein Wert jenseits seiner Obergrenze.
    ValueTooLong {
        /// Die Quellart.
        source: KeySourceKind,
        /// Das Feld samt `=`.
        field: &'static str,
    },
}

impl KeySourceSpecError {
    /// Stabiler Fehlercode. Tests assertieren gegen ihn, nie gegen Formatierung.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::MissingField { .. } => "EA-KEY-SOURCE-SPEC-MISSING-FIELD",
            Self::DuplicateField { .. } => "EA-KEY-SOURCE-SPEC-DUPLICATE-FIELD",
            Self::UnknownField { .. } => "EA-KEY-SOURCE-SPEC-UNKNOWN-FIELD",
            Self::MalformedField { .. } => "EA-KEY-SOURCE-SPEC-MALFORMED-FIELD",
            Self::EmptyValue { .. } => "EA-KEY-SOURCE-SPEC-EMPTY-VALUE",
            Self::NotHex { .. } => "EA-KEY-SOURCE-SPEC-NOT-HEX",
            Self::ValueTooLong { .. } => "EA-KEY-SOURCE-SPEC-VALUE-TOO-LONG",
        }
    }

    /// Der Exitcode: IMMER [`ExitCode::Usage`].
    ///
    /// Eine Quellenangabe ist eine Aufrufform und nie ein Befund ueber einen
    /// Bestand — dieselbe Aussage wie beim Argumentparser der CLI.
    #[must_use]
    pub const fn exit_code(&self) -> ExitCode {
        ExitCode::Usage
    }
}

impl fmt::Display for KeySourceSpecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField { source, field } => {
                write!(formatter, "{source}: missing `{field}`")
            }
            Self::DuplicateField { source, field } => {
                write!(formatter, "{source}: duplicate field `{field}`")
            }
            Self::UnknownField { source, field } => {
                write!(formatter, "{source}: unknown field `{field}`")
            }
            Self::MalformedField { source } => write!(formatter, "{source}: field without `=`"),
            Self::EmptyValue { source, field } => write!(formatter, "{source}: `{field}` is empty"),
            Self::NotHex { source, field } => write!(formatter, "{source}: `{field}` is not hex"),
            Self::ValueTooLong { source, field } => write!(
                formatter,
                "{source}: `{field}` exceeds {} bytes",
                crate::pkcs11::PKCS11_KEY_ID_MAX_BYTES
            ),
        }
    }
}

impl std::error::Error for KeySourceSpecError {}

/// Loest eine Quelle zum privaten EMPFAENGERSCHLUESSEL (X25519) auf.
///
/// # Errors
///
/// Die Dateiform: genau wie [`crate::load_recipient_key`]. Der Container:
/// [`RecoveryError::KeySourceExposed`] und [`RecoveryError::SecretEmpty`] aus
/// der Passphrasendatei, [`RecoveryError::KeySource`] bei fremder
/// Schluesselart oder einem Container, der nicht dekodiert (Exitcode 2),
/// [`RecoveryError::ContainerOpen`] bei falscher Passphrase oder einem
/// Container, der dekodiert und trotzdem nicht oeffnet (Exitcode 14). PKCS#11:
/// die Fehler der PIN-Datei, [`RecoveryError::Io`] fuer ein fehlendes Modul,
/// danach IMMER [`RecoveryError::Pkcs11Unbound`] — die benannte Grenze.
pub fn resolve_recipient_key(
    spec: &KeySourceSpec,
) -> Result<HpkeRecipientPrivateKey, RecoveryError> {
    let material = resolve_material(spec, ContainedKeyKind::RecipientKem)?;
    HpkeRecipientPrivateKey::from_bytes(material).map_err(|_| RecoveryError::KeySource)
}

/// Loest eine Quelle zum SIGNIERSCHLUESSEL (Ed25519-Seed) auf.
///
/// Die Dateiform nimmt dieselben zwei Formen wie der Empfaengerschluessel —
/// 32 Rohbytes oder 64 Hexzeichen — als Seed. Jeder 32-Byte-Wert ist ein
/// gueltiger Ed25519-Seed; die Dateiform kann deshalb nur an der FORM
/// scheitern, nie am Wert.
///
/// # Errors
///
/// Wie [`resolve_recipient_key`]; der Container muss die Art
/// [`ContainedKeyKind::Signing`] tragen.
pub fn resolve_signing_key(spec: &KeySourceSpec) -> Result<CoseSigner, RecoveryError> {
    let material = resolve_material(spec, ContainedKeyKind::Signing)?;
    Ok(CoseSigner::from_secret(material))
}

/// Die 32 Schluesselbytes aus einer Quelle, fuer GENAU EINE Schluesselart.
///
/// Die Art ist ein Parameter und keine Ableitung aus dem Material: 32 Bytes
/// sehen als X25519-Schluessel und als Ed25519-Seed gleich aus, und nur der
/// Container traegt die Art im Kopf. Bei der Dateiform entscheidet allein der
/// Aufrufer, was er in der Datei erwartet — so wie in Stufe 4.
fn resolve_material(
    spec: &KeySourceSpec,
    kind: ContainedKeyKind,
) -> Result<SecretBytes<32>, RecoveryError> {
    match spec {
        KeySourceSpec::File(path) => load_key_material(path),
        KeySourceSpec::Container {
            path,
            passphrase_file,
        } => {
            // Die Passphrasendatei ZUERST: ihre Rechte sind der billigere und
            // der haeufigere Fehler, und der Container wird nicht angefasst,
            // solange die Passphrase nicht gesichert vorliegt.
            let passphrase = read_secret_file(passphrase_file)?;
            let container = EncryptedKeyContainer::read_from(path)?;
            container.open(kind, &passphrase)
        }
        KeySourceSpec::Pkcs11 {
            reference,
            pin_file,
        } => {
            // Dieselbe Reihenfolge wie beim Container: die PIN-Datei wird
            // vollstaendig gelesen und geprueft, BEVOR das Modul beruehrt
            // wird — eine offene PIN-Datei ist ein Aufruffehler (2) und
            // schlaegt die Grenze (21).
            let _pin = read_secret_file(pin_file)?;
            module_is_a_regular_file(reference.module())?;
            Err(RecoveryError::Pkcs11Unbound)
        }
    }
}

/// Prueft, dass die Modulbibliothek EXISTIERT und eine Datei ist.
///
/// `fs::metadata` und ausdruecklich nicht `symlink_metadata`: eine
/// Modulbibliothek ist auf jedem Betriebssystem ueblicherweise ein Link auf
/// ihre versionierte Datei, und der Link ist hier die richtige Antwort. Was
/// hinter dem Pfad steht, wird in dieser Stufe nicht geladen.
fn module_is_a_regular_file(module: &Path) -> Result<(), RecoveryError> {
    let metadata = fs::metadata(module)?;
    if !metadata.is_file() {
        return Err(RecoveryError::Io(io::ErrorKind::InvalidInput));
    }
    Ok(())
}

/// Liest eine Passphrasen- oder PIN-Datei in einen [`SecretVec`].
///
/// # DIE REGELN, UND WARUM JEDE EINZELNE
///
/// 1. Diese Plattform kann Rechte lesen — sonst
///    [`RecoveryError::RestrictivePermissionsUnsupported`], BEVOR ein Byte
///    gelesen wird. Ohne Rechtebits laesst sich die Zusicherung „nur der
///    Eigentuemer" weder pruefen noch halten.
/// 2. Der Pfad ist KEIN Symlink ([`fs::symlink_metadata`]). Ein Link traegt
///    eigene Rechte, die ueber die Datei dahinter nichts sagen; ein Geheimnis
///    hinter einem Link ist nicht als eingegrenzt erwiesen —
///    [`RecoveryError::KeySourceExposed`].
/// 3. Die Datei ist eine regulaere Datei, und ihre Rechte — gelesen auf dem
///    GEOEFFNETEN HANDLE, nicht auf dem Pfad, damit dazwischen kein Fenster
///    liegt — tragen kein Bit fuer Gruppe oder Welt (`mode & 0o077 == 0`).
///    Sonst [`RecoveryError::KeySourceExposed`].
/// 4. Der Inhalt geht UNMITTELBAR in einen [`SecretVec`]; kein `Vec`, der ihn
///    haelt, ueberlebt diese Funktion.
/// 5. GENAU EIN abschliessendes `\n` oder `\r\n` wird entfernt — das eine,
///    das ein Editor anhaengt. Ein zweites gehoert zur Passphrase.
/// 6. Eine leere Passphrase ist keine — [`RecoveryError::SecretEmpty`].
///
/// # Errors
///
/// [`RecoveryError::Io`], wenn die Datei fehlt oder nicht lesbar ist, plus
/// die vier oben genannten Varianten.
pub fn read_secret_file(path: &Path) -> Result<SecretVec, RecoveryError> {
    restrictive_permissions_available()?;
    if fs::symlink_metadata(path)?.is_symlink() {
        return Err(RecoveryError::KeySourceExposed);
    }
    let mut file = File::open(path)?;
    refuse_unless_owner_only(&file)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    strip_one_line_ending(&mut bytes);
    let secret = SecretVec::new(bytes);
    if secret.is_empty() {
        return Err(RecoveryError::SecretEmpty);
    }
    Ok(secret)
}

/// Entfernt genau ein abschliessendes `\n` oder `\r\n`.
fn strip_one_line_ending(bytes: &mut Vec<u8>) {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
}

/// Verweigert eine Datei, die nicht allein ihrem Eigentuemer gehoert.
///
/// Gelesen wird auf dem HANDLE: der Pfad koennte nach der Pruefung auf etwas
/// anderes zeigen, das Handle nicht. Dieselbe Regel, nach der
/// `crate::report` die Rechte einer neuen Datei setzt.
#[cfg(unix)]
pub(crate) fn refuse_unless_owner_only(file: &File) -> Result<(), RecoveryError> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(RecoveryError::KeySourceExposed);
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(RecoveryError::KeySourceExposed);
    }
    Ok(())
}

/// Wird auf dieser Plattform nie erreicht: [`restrictive_permissions_available`]
/// hat den Lauf bereits beendet, bevor eine Datei geoeffnet wird.
#[cfg(not(unix))]
pub(crate) const fn refuse_unless_owner_only(_file: &File) -> Result<(), RecoveryError> {
    Err(RecoveryError::RestrictivePermissionsUnsupported)
}
