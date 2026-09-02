//! Der Datei-Modus: EINE exportierte Datei oder ein dauerhaft angebundener
//! Ordner, gegen den gepinnten Anker des Tresors und ohne jeden Serveraufruf.
//!
//! `web-reader-design.md` §5.2 bis §5.4. Der Modus ist durch seine ABWESENHEIT
//! definiert: dieses Modul nennt keine Adresse, keinen Endpunkt und keinen
//! Cursor, es faehrt kein OPFS-I/O und keine Indizierung. Was es tut, ist
//! Bytes in [`crate::ReaderVerifier::classify`] zu geben — den EINEN Weg in
//! die Pipeline — und das Ergebnis als [`OpenedArchiveV1`] herauszugeben.
//!
//! # Es entsteht kein Gate und kein zweiter Parser
//!
//! `ea_verify::verify_archive_observed` wird hier NICHT gerufen; das tut
//! [`crate::ReaderVerifier`], und die Gate-Reihenfolge aus `design.md` §14.1
//! gilt in beiden Modi wortgleich — `classify` liest den Modus ohnehin nicht.
//! Der einzige Unterschied ist Schritt 7: geprueft wird, was der Port liefert,
//! also genau die im Buendel beziehungsweise Ordner enthaltenen Quittungen und
//! Checkpoints. Das tut `ea-verify` bereits von sich aus, und dieses Modul
//! fuegt dafuer nichts hinzu.
//!
//! # Der Anker hat keinen Platz in der Signatur
//!
//! Keiner der vier Eingaenge nimmt einen `TrustAnchorV1` oder einen
//! [`crate::PinnedTrustAnchor`]. Der Anker entsteht INNERHALB des Aufrufs,
//! ueber `PinnedTrustAnchor::from_vault(vault)` in `classify`, und sonst
//! nirgendher. Das ist §5.3 als KONSTRUKTIONSREGEL und nicht als Disziplin:
//! ein Aufrufer kann keinen zweiten Anker anbieten, weil die Signatur keinen
//! Platz dafuer hat, und Trust-Objekte, die IN der geoeffneten Datei liegen,
//! begruenden von sich aus nichts. Die BINDUNG selbst gehoert dem Modul
//! `anchor` und wird hier weder wiederholt noch neu gerechnet.
//!
//! # Es gibt keinen Cursor, und er entfaellt ERSATZLOS
//!
//! Im Server-Modus bewegt [`crate::ConfirmedCursor`] sich erst, wenn jedes
//! Objektbyte dauerhaft ist UND die Kette bis zum Batchende verifiziert. Im
//! Datei-Modus gibt es nichts zu merken: jedes Objekt wird bei JEDEM Oeffnen
//! vollstaendig geprueft (`web-reader-design.md` §5.4). Der Beleg dafuer ist
//! eine UEBERSETZUNGSGRENZE und keine Zusicherung ueber einen Namen — dieselbe
//! Form, die `crates/ea-key-provider/src/lib.rs` und
//! `crates/ea-crypto/src/secret.rs` fuer ihre Flaechenverbote schon fuehren,
//! und die `cargo test --workspace --doc --all-features --locked` in
//! `verify_quick_commands()` mitfaehrt. Ein Laufzeitverbot daneben waere eine
//! Zeile, die jemand vergessen kann.
//!
//! Aus einem geoeffneten Bestand faellt kein Cursor:
//!
//! ```compile_fail
//! use ea_reader::{ConfirmedCursor, OpenedArchiveV1};
//!
//! fn reject(opened: &OpenedArchiveV1) -> ConfirmedCursor {
//!     opened.confirmed_cursor()
//! }
//! ```
//!
//! Und aus dem Eingang dieses Modus faellt kein Synchronisierungsdienst:
//!
//! ```compile_fail
//! use ea_reader::{ReaderFileMode, ReaderSyncService};
//!
//! fn reject(mode: &ReaderFileMode) -> &ReaderSyncService<'_> {
//!     mode.sync_service()
//! }
//! ```
//!
//! [`crate::ReaderSyncService`] traegt seinen Lebensdauerparameter wirklich
//! (`crates/ea-reader/src/sync.rs`); das `<'_>` oben ist also kein Schmuck,
//! ohne es schluege der Block aus dem falschen Grund fehl.
//!
//! Der positive Gegenpart steht daneben, aus demselben Grund, den
//! `crates/ea-key-provider/src/lib.rs` neben seine vier Verbote schreibt: er
//! loest JEDEN Pfad einmal erfolgreich auf, den die zwei Bloecke oben
//! benennen. Ohne ihn belegten sie nur einen kaputten Import und nicht die
//! fehlenden Methoden.
//!
//! ```
//! use ea_reader::{ConfirmedCursor, OpenedArchiveV1, ReaderFileMode, ReaderSyncService};
//!
//! fn resolve(
//!     _cursor: &ConfirmedCursor,
//!     _opened: &OpenedArchiveV1,
//!     _mode: &ReaderFileMode,
//!     _sync: &ReaderSyncService<'_>,
//! ) {
//! }
//! ```

use core::fmt;

use ea_archive::{ArchiveBundleSource, BundleError};
use ea_types::UnixMillis;
use ea_verify::{GateObserver, SilentObserver, VerificationReportV1};

use crate::{
    archive_source::{DirectoryHandleSource, ReaderArchiveSourceV1},
    mode::ReaderMode,
    vault::UnlockedVault,
    verify::{ReaderClassification, ReaderError, ReaderVerifier},
};

/// Jeder Befund, der ein OEFFNEN im Datei-Modus abbricht.
///
/// Bauform der sieben modulweisen Fehlertypen dieser Crate: flaches
/// Aufzaehlungswerk, ein `code()` je Arm, FREMDE Codes DURCHGEREICHT,
/// [`fmt::Display`] schreibt ausschliesslich den Code, [`fmt::Debug`]
/// delegiert an [`fmt::Display`].
///
/// # KEIN eigener Code
///
/// Der Container hat mit `EA-BUNDLE-MALFORMED`, `EA-BUNDLE-BLOB-LIMIT` und
/// `EA-BUNDLE-TOTAL-BYTE-LIMIT` bereits stabile Codes, und die Klassifikation
/// hat ihre eigenen. Ein Code dieses Moduls daneben waere ein zweiter Satz
/// Codes fuer dieselbe Tatsache — und die Oberflaeche muesste raten, welcher
/// von beiden gilt.
///
/// # Und KEIN Arm fuer `ArchiveError`
///
/// GEMESSEN und deshalb weggelassen: `EA-ARCHIVE-UNAVAILABLE` und die zwei
/// Archivdeckel erreichen diesen Typ nicht als eigener Arm, sondern als
/// [`Self::Classification`]. `ReaderVerifier::classify` faellt bei einer
/// Quelle, die nicht liefert, in `ea_verify::verify_archive_observed`, und
/// `VerifyError` reicht den Archivcode unveraendert durch — der Zeuge
/// `a_directory_whose_permission_was_revoked_reports_the_archive_code_and_no_report`
/// misst genau das. Ein eigener Arm brauchte einen zweiten Erzeuger: eine
/// Vorlaufpruefung im Eingang, die entweder ein zweiter voller Durchlauf ueber
/// den Bestand waere oder eine zweite Stelle, an der „nicht verfuegbar"
/// entschieden wird. Ein Arm, den kein Zeuge faerben kann, ist kein
/// fail-closed-Verhalten, sondern ein unbelegter Zweig — dieselbe Begruendung,
/// mit der [`ReaderError`] seine Arme fuer `TrustError` und `SchemaError`
/// ablehnt. Die Deckel der Verzeichnisquelle reist der Aufrufer ohnehin
/// direkt als `ea_archive::ArchiveError` aus
/// [`DirectoryHandleSource::push_blob`] ein, lange bevor ein Oeffnen beginnt.
#[derive(Clone, Eq, PartialEq)]
pub enum ReaderFileModeError {
    /// Die Bytes aus dem Dateidialog sind kein Container.
    Bundle(BundleError),
    /// Ueber diesen Bestand liess sich gar kein Bericht bilden.
    ///
    /// Ein Befund ueber ein EINZELNES Objekt ist nie ein `Err`, und ein
    /// Fehlschlag von Gate `trust` erst recht nicht: er liefert `Ok` mit einem
    /// Bericht, der ueber keinen Eintrag etwas sagt.
    Classification(ReaderError),
}

impl ReaderFileModeError {
    /// Der stabile Code des Befunds.
    ///
    /// Zusicherungen stehen gegen ihn und nie gegen eine Formatierung; die
    /// Bruecke gibt ihn als `JsValue::from_str(error.code())` heraus.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Bundle(error) => error.code(),
            Self::Classification(error) => error.code(),
        }
    }
}

impl From<BundleError> for ReaderFileModeError {
    fn from(error: BundleError) -> Self {
        Self::Bundle(error)
    }
}

impl From<ReaderError> for ReaderFileModeError {
    fn from(error: ReaderError) -> Self {
        Self::Classification(error)
    }
}

impl fmt::Display for ReaderFileModeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for ReaderFileModeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for ReaderFileModeError {}

/// Der Eingang des Datei-Modus.
///
/// Ein tragloser Typ und kein Dienst: er haelt keine Sitzung, keine Uhr und
/// keinen Zustand zwischen zwei Oeffnungen — es gibt naemlich nichts zu
/// halten. Genau das ist die Aussage von §5.4, und sie steht deshalb in der
/// Form des Typs und nicht in einem Kommentar.
///
/// Die vier Eingaenge sind zwei mal zwei: EINE Datei oder EIN Ordner, jeweils
/// still oder unter einem [`GateObserver`]. Der beobachtete Zwilling ist kein
/// Komfort — ohne ihn waere das Gate-Protokoll nur ueber die Datei messbar und
/// der Ordnerweg an dieser Stelle unbezeugt.
pub struct ReaderFileMode;

impl ReaderFileMode {
    /// Oeffnet die EINE exportierte Datei aus dem gewoehnlichen Dateidialog.
    ///
    /// Der universelle Weg. Er MUSS immer angeboten werden, weil
    /// `showDirectoryPicker` in Safari und Firefox fehlt; die Dateiendung ist
    /// dabei ein HINWEIS des Dialogfilters, entschieden wird an
    /// `ea_archive::BUNDLE_MAGIC_V1`.
    ///
    /// # Errors
    ///
    /// [`ReaderFileModeError::Bundle`], wenn die Bytes keinen gueltigen
    /// Container bilden — und dann entsteht KEIN Teilbericht, weil
    /// `ArchiveBundleSource::from_bytes` den Container vollstaendig prueft,
    /// bevor es einen einzigen Blob herausgibt. Sonst der Fehler von
    /// [`Self::open_bundle_observed`].
    pub fn open_bundle(
        bytes: Vec<u8>,
        vault: &UnlockedVault,
        effective_now: UnixMillis,
    ) -> Result<OpenedArchiveV1, ReaderFileModeError> {
        Self::open_bundle_observed(bytes, vault, effective_now, &mut SilentObserver)
    }

    /// Wie [`Self::open_bundle`], unter einem Gate-Beobachter.
    ///
    /// # Errors
    ///
    /// Siehe [`Self::open_bundle`].
    pub fn open_bundle_observed(
        bytes: Vec<u8>,
        vault: &UnlockedVault,
        effective_now: UnixMillis,
        observer: &mut dyn GateObserver,
    ) -> Result<OpenedArchiveV1, ReaderFileModeError> {
        let source = ArchiveBundleSource::from_bytes(bytes)?;
        open(
            ReaderArchiveSourceV1::Bundle(source),
            vault,
            effective_now,
            observer,
        )
    }

    /// Oeffnet einen angebundenen Ordner, dessen Bytes bereits eingereicht sind.
    ///
    /// Der Chromium-Komfortweg. Die Quelle wird UEBERNOMMEN und faellt am Ende
    /// des Aufrufs; siehe [`OpenedArchiveV1`].
    ///
    /// # Errors
    ///
    /// Der Fehler von [`Self::open_directory_observed`].
    pub fn open_directory(
        source: DirectoryHandleSource,
        vault: &UnlockedVault,
        effective_now: UnixMillis,
    ) -> Result<OpenedArchiveV1, ReaderFileModeError> {
        Self::open_directory_observed(source, vault, effective_now, &mut SilentObserver)
    }

    /// Wie [`Self::open_directory`], unter einem Gate-Beobachter.
    ///
    /// # Errors
    ///
    /// [`ReaderFileModeError::Classification`] mit `EA-ARCHIVE-UNAVAILABLE`,
    /// wenn dem Ordner die Berechtigung entzogen wurde
    /// ([`DirectoryHandleSource::mark_unavailable`]), und sonst der Fehler der
    /// Klassifikation.
    pub fn open_directory_observed(
        source: DirectoryHandleSource,
        vault: &UnlockedVault,
        effective_now: UnixMillis,
        observer: &mut dyn GateObserver,
    ) -> Result<OpenedArchiveV1, ReaderFileModeError> {
        open(
            ReaderArchiveSourceV1::Directory(source),
            vault,
            effective_now,
            observer,
        )
    }
}

/// Der EINE Weg in die Pipeline, ueber den alle vier Eingaenge laufen.
///
/// Er nennt [`ReaderMode::File`] genau einmal, und [`OpenedArchiveV1::mode`]
/// gibt danach zurueck, womit der Klassifizierer wirklich gefahren ist — nicht
/// einen zweiten, danebenliegenden Wert derselben Tatsache.
///
/// Die Quelle wird hier BESITZEND genommen und faellt am Ende. Sie zu halten
/// kostete an der Obergrenze ein zweites Mal zwei Gibibyte, denn
/// `ArchiveBundleSource` haelt den vollstaendigen Container und das Inventar
/// der Klassifikation haelt die geparsten Objekte daneben; es ist dasselbe
/// Argument, mit dem `write_archive_bundle` sein `drop(blobs)` begruendet.
fn open(
    source: ReaderArchiveSourceV1,
    vault: &UnlockedVault,
    effective_now: UnixMillis,
    observer: &mut dyn GateObserver,
) -> Result<OpenedArchiveV1, ReaderFileModeError> {
    let verifier = ReaderVerifier::new(ReaderMode::File, effective_now);
    let classification = verifier.classify(&source, vault, observer)?;
    Ok(OpenedArchiveV1 {
        classification,
        mode: verifier.mode(),
    })
}

/// Das Ergebnis EINES Oeffnens.
///
/// OHNE Lebensdauerparameter und OHNE die Quelle: [`ReaderClassification`]
/// besitzt Bericht und Inventar, nach `classify` borgt nichts mehr. Der Typ
/// haelt genau zwei Werte, und keiner davon ist ein Fortschritt — es gibt
/// nichts, was ein zweites Oeffnen ueberspringen duerfte.
///
/// # Kein `Debug`
///
/// Wie [`ReaderClassification`], die er haelt: das Inventar traegt die
/// geparsten Objekte des Bestands, und ein abgeleitetes `Debug` gaebe sie
/// heraus. Fehlerpruefungen in Zeugen laufen deshalb ueber `.err().expect(..)`
/// und nie ueber `unwrap_err`.
pub struct OpenedArchiveV1 {
    classification: ReaderClassification,
    mode: ReaderMode,
}

impl OpenedArchiveV1 {
    /// Die vollstaendige Klassifikation dieses Oeffnens.
    ///
    /// Zustandszeilen, Luecken und die Zeugenpaare fuer
    /// [`crate::decrypt_verified`] kommen von hier; dieses Modul rechnet
    /// nichts davon nach.
    #[must_use]
    pub const fn classification(&self) -> &ReaderClassification {
        &self.classification
    }

    /// Der unveraenderte Bericht der neun Gates.
    ///
    /// Die Abkuerzung ueber [`Self::classification`], weil jeder Aufrufer
    /// dieses Modus zuerst ihn liest.
    #[must_use]
    pub const fn report(&self) -> &VerificationReportV1 {
        self.classification.report()
    }

    /// Der Modus, in dem dieser Bestand geoeffnet wurde.
    ///
    /// Immer [`ReaderMode::File`] — der Wert kommt aus dem Klassifizierer und
    /// nicht aus einem zweiten Literal daneben. Er verlaesst die Crate
    /// ausdruecklich NICHT als DTO-Feld: eine emittierte Vereinigung
    /// `'server' | 'file'` verbaenne das Literal `file` aus jeder
    /// handgeschriebenen Web-Quelle und damit `<input type="file">` aus der
    /// Oberflaeche, die den universellen Weg anbietet.
    #[must_use]
    pub const fn mode(&self) -> ReaderMode {
        self.mode
    }
}
