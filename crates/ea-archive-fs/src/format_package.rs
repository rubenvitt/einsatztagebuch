//! Das Formatbeiwerk, das JEDER Bestand traegt (`design.md` §11.4,
//! Zeilen 1252-1288).
//!
//! `design.md` fuehrt `README-FORMAT.txt`, `format/schemas/`,
//! `format/transformations/`, `format/compatibility-matrix.json` und
//! `recovery-reports/` als Verpflichtung jedes Archivs. Stufe 2 ist die erste
//! Stufe, die Archive ERZEUGT; deshalb entsteht das Beiwerk hier.
//!
//! # Drei Entscheidungen, die dieses Modul tragen
//!
//! 1. **Die Bytes sind EINGEBETTET** (`include_bytes!`). Damit sind die
//!    Archivbytes die Repositorybytes DURCH DIE BAUWEISE und koennen nicht
//!    abdriften; ein fehlender Pfad ist ein Uebersetzungsfehler und kein
//!    Laufzeitbefund. Die Tests stellen die Gleichheit zusaetzlich gegen den
//!    ARBEITSBAUM, damit ein versehentlich geaenderter Einbettungspfad laut
//!    wird.
//! 2. **Der Schreibweg ist [`ArchiveBackend::create_non_object_if_absent`]**
//!    und nie `create_if_absent`. Kein Byte des Beiwerks traegt das 9-Byte-
//!    Exact-Object-Praefix, es ist also KEIN Archivobjekt: die Inventarisierung
//!    zaehlt es in `nonObjectFileCount` und isoliert es nie
//!    (`design.md:1290-1291`, `:1296`). Der Typunterschied der beiden Methoden
//!    IST die Klassifikation.
//! 3. **Kein Pfad wird der Layoutliste hinzugefuegt.** Jede Adresse entsteht
//!    ueber [`ArchivePath::in_dir`] unter [`FORMAT_SCHEMAS_DIR_V1`] oder ueber
//!    [`ArchivePath::at_layout_file`]; `LAYOUT_PATHS_V1` bleibt unberuehrt und
//!    bleibt gegen `design.md` §11.4 gepinnt.
//!
//! # Warum zwei Verzeichnisse leer bleiben
//!
//! `format/transformations/` bleibt leer, weil jede Sicht von v0.1 `identity`
//! mit `preservesSourceBytes` ist (`schemas/compatibility-matrix.json`) — es
//! gibt keine Ableitung zu beschreiben. `recovery-reports/` bleibt leer, weil
//! ein Wiederherstellungsbericht erst mit einem echten Wiederherstellungslauf
//! entsteht. Beide existieren dennoch: ein Leser muss eine LEERE Verpflichtung
//! von einer FEHLENDEN unterscheiden koennen.

use ea_archive::{
    ArchiveBackend, ArchiveBackendError, ArchivePath, COMPATIBILITY_MATRIX_FILE_V1, FORMAT_DIR_V1,
    FORMAT_SCHEMAS_DIR_V1, FORMAT_TRANSFORMATIONS_DIR_V1, README_FORMAT_FILE_V1,
    RECOVERY_REPORTS_DIR_V1,
};

/// Die vier Verzeichnisse, die das Beiwerk belegt.
///
/// Alle vier werden angelegt, auch die zwei, die Dateien tragen: eine
/// gleichfoermige Behandlung macht den Bericht wahr, ohne dass eine
/// Sonderregel („diese zwei entstehen nebenbei") mitgepflegt werden muss.
const FORMAT_PACKAGE_DIRECTORIES_V1: [&str; 4] = [
    FORMAT_DIR_V1,
    FORMAT_SCHEMAS_DIR_V1,
    FORMAT_TRANSFORMATIONS_DIR_V1,
    RECOVERY_REPORTS_DIR_V1,
];

/// Die GESCHLOSSENE Liste des Beiwerks: Zieladresse und eingebettete Bytes.
///
/// Der erste Eintrag jedes Paares ist die WURZELRELATIVE Zieladresse im
/// Bestand, nicht schon eine [`ArchivePath`]: der Adresstyp haelt einen
/// `String` und kann deshalb in keiner `const` stehen.
/// [`format_package_target`] bildet die Adresse ab und weist einen Pfad, der
/// nicht in die Layoutliste passt, fail-closed ab — ein vertippter Eintrag
/// dieser Liste ist damit ein Fehler und keine still falsche Ablage.
///
/// Die Liste fuehrt JEDE Datei unter `schemas/` ausser der
/// Kompatibilitaetsmatrix, die ihre eigene Layoutadresse hat. Das ist mehr als
/// die Aufzaehlung der normativen Dokumente des Wire-Format-Addendums: auch
/// `payload/v1/payload.cddl` und `reports/v1/import-report.cddl` sind
/// eingecheckte Grammatiken, die ein Leser braucht, und
/// `every_schema_file_of_the_repository_is_mirrored_byte_identically` haelt die
/// Liste gegen das Verzeichnis, damit ein spaeter hinzugefuegtes Schema
/// auffaellt statt still in jedem neuen Bestand zu fehlen.
pub const FORMAT_PACKAGE_FILES_V1: &[(&str, &[u8])] = &[
    (
        README_FORMAT_FILE_V1,
        include_bytes!("../../../docs/format/README-FORMAT.txt"),
    ),
    (
        COMPATIBILITY_MATRIX_FILE_V1,
        include_bytes!("../../../schemas/compatibility-matrix.json"),
    ),
    (
        "format/schemas/archive/v1/archive-profile.cddl",
        include_bytes!("../../../schemas/archive/v1/archive-profile.cddl"),
    ),
    (
        "format/schemas/archive/v1/archive.cddl",
        include_bytes!("../../../schemas/archive/v1/archive.cddl"),
    ),
    (
        "format/schemas/archive/v1/evidence.cddl",
        include_bytes!("../../../schemas/archive/v1/evidence.cddl"),
    ),
    (
        "format/schemas/archive/v1/trust.cddl",
        include_bytes!("../../../schemas/archive/v1/trust.cddl"),
    ),
    (
        "format/schemas/identity/v1/os-account.cddl",
        include_bytes!("../../../schemas/identity/v1/os-account.cddl"),
    ),
    (
        "format/schemas/payload/v1/amendment.schema.json",
        include_bytes!("../../../schemas/payload/v1/amendment.schema.json"),
    ),
    (
        "format/schemas/payload/v1/destruction-evidence.schema.json",
        include_bytes!("../../../schemas/payload/v1/destruction-evidence.schema.json"),
    ),
    (
        "format/schemas/payload/v1/genesis.schema.json",
        include_bytes!("../../../schemas/payload/v1/genesis.schema.json"),
    ),
    (
        "format/schemas/payload/v1/incident.schema.json",
        include_bytes!("../../../schemas/payload/v1/incident.schema.json"),
    ),
    (
        "format/schemas/payload/v1/key-transition.schema.json",
        include_bytes!("../../../schemas/payload/v1/key-transition.schema.json"),
    ),
    (
        "format/schemas/payload/v1/payload.cddl",
        include_bytes!("../../../schemas/payload/v1/payload.cddl"),
    ),
    (
        "format/schemas/protocol/v1/signed-protocol.cddl",
        include_bytes!("../../../schemas/protocol/v1/signed-protocol.cddl"),
    ),
    (
        "format/schemas/reports/v1/import-report.cddl",
        include_bytes!("../../../schemas/reports/v1/import-report.cddl"),
    ),
    (
        "format/schemas/reports/v1/key-inventory.schema.json",
        include_bytes!("../../../schemas/reports/v1/key-inventory.schema.json"),
    ),
    (
        "format/schemas/reports/v1/local-audit.cddl",
        include_bytes!("../../../schemas/reports/v1/local-audit.cddl"),
    ),
    (
        "format/schemas/reports/v1/verification-report.schema.json",
        include_bytes!("../../../schemas/reports/v1/verification-report.schema.json"),
    ),
];

/// Die Zieladresse eines Eintrags von [`FORMAT_PACKAGE_FILES_V1`].
///
/// Unterhalb von [`FORMAT_SCHEMAS_DIR_V1`] ueber [`ArchivePath::in_dir`], sonst
/// als feste Wurzeldatei ueber [`ArchivePath::at_layout_file`]. Ein Pfad, der
/// keines von beidem ist, wird abgewiesen; diese Funktion fuegt der
/// Layoutliste keinen Pfad hinzu.
///
/// # Errors
///
/// [`ArchiveBackendError::Path`], wenn `relative` weder unter dem
/// Schemaverzeichnis liegt noch ein Dateieintrag der Layoutliste ist.
pub fn format_package_target(relative: &str) -> Result<ArchivePath, ArchiveBackendError> {
    if let Some(below) = relative.strip_prefix(FORMAT_SCHEMAS_DIR_V1) {
        return ArchivePath::in_dir(FORMAT_SCHEMAS_DIR_V1, below);
    }
    ArchivePath::at_layout_file(relative)
}

/// Was ein Bestand nach [`materialize_format_package`] an Beiwerk traegt.
///
/// Beide Zahlen sind VERPFLICHTUNGEN und keine Differenzen: sie beschreiben,
/// was nach dem Lauf im Bestand liegt, nicht was dieser Lauf neu angelegt hat.
/// Anders herum gelesen meldete der zweite, idempotente Lauf null und die
/// Zusicherung, dass ein frischer Bestand GENAU dieses Beiwerk traegt, waere
/// nicht mehr formulierbar.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FormatPackageReport {
    written_file_count: usize,
    directories: [&'static str; 4],
}

impl FormatPackageReport {
    /// Die Zahl der Beiwerkdateien, die der Bestand traegt.
    #[must_use]
    pub const fn written_file_count(&self) -> usize {
        self.written_file_count
    }

    /// Die vier Verzeichnisse des Beiwerks.
    #[must_use]
    pub const fn directories(&self) -> &[&'static str] {
        &self.directories
    }
}

/// Was die Erzeugungsstrecke eines Bestands mit dem Formatbeiwerk getan hat.
///
/// Sie schreibt es UNTER der exklusiven Schreibersperre oder gar nicht, und ein
/// abweichendes Beiwerkbyte laesst den Bestand nicht unoeffenbar werden. Beide
/// Aussagen brauchen einen Beobachtungspunkt, sonst waeren sie stille
/// Zustaende: ein Aufrufer, der nicht erfaehrt, dass das Beiwerk aufgeschoben
/// oder abweichend ist, kann daraus nichts folgern.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormatPackageOutcomeV1 {
    /// GAR NICHT versucht.
    ///
    /// Die Kratzwurzel des Capability-Tests ist kein Bestand und traegt
    /// ausdruecklich kein Beiwerk.
    NotAttempted,
    /// Das Beiwerk liegt vollstaendig und bytegleich im Bestand.
    Materialized,
    /// AUFGESCHOBEN: ein anderer Schreiber hielt die Sperre.
    ///
    /// Das Beiwerk ist eingebettet und wird bei jedem Oeffnen erneut
    /// materialisiert; der Sperrhalter schreibt es, und das naechste Oeffnen
    /// ohne fremde Sperre traegt es nach. Deshalb ist der aufgeschobene Fall
    /// KEIN Fehler: das Oeffnen an einer fremden Sperre scheitern zu lassen
    /// waere ein Bestand, den ein zweiter Leser nicht mehr aufmacht.
    Deferred,
    /// `deviating_file_count` Beiwerkadressen tragen ANDERE Bytes als dieses
    /// Programm einbettet — der REST des Beiwerks liegt vollstaendig im
    /// Bestand.
    ///
    /// Die abweichenden Bytes bleiben unangetastet — Create-if-absent
    /// ueberschreibt nichts —, und das Oeffnen traegt trotzdem: der
    /// Gesundheitscheck ist das Werkzeug, das einen BESCHAEDIGTEN Bestand
    /// befunden soll, und er braucht dafuer ein offenes Backend. Eine
    /// Beiwerkdatei ist im Inventar; ihre Abweichung ist damit
    /// `EA-ARCHIVE-HEALTH-MODIFIED-FILE` und kein Grund, den Bestand
    /// wegzuschliessen.
    ///
    /// Die ZAHL steht hier, weil sie sonst nirgends stehen wuerde: der
    /// Gesundheitscheck vergleicht gegen ein Erwartungsinventar, das der
    /// Aufrufer mitbringt, und fuer einen frischen Bestand fuehrt es die
    /// Beiwerkadressen nicht. `Deviating { deviating_file_count: 1 }` ist damit
    /// von `Deviating { deviating_file_count: 18 }` unterscheidbar — „ein Byte
    /// weicht ab" von „der ganze Bestand traegt fremdes Beiwerk". Die
    /// ADRESSLISTE ist ausdruecklich nicht Teil dieses Zustands: sie waere eine
    /// Allokation an einem `Copy`-Typ, und die Diagnose je Adresse ist Aufgabe
    /// des Gesundheitschecks auf einem inventarisierten Bestand.
    Deviating { deviating_file_count: usize },
}

/// Schreibt das vollstaendige Formatbeiwerk in `backend`.
///
/// Reihenfolge: erst die vier Verzeichnisse — auch die zwei, die leer bleiben
/// —, dann jede Datei mit
/// [`ArchiveBackend::create_non_object_if_absent`], gefolgt von
/// [`ArchiveBackend::sync_file`] und [`ArchiveBackend::sync_directory`].
///
/// IDEMPOTENT: ein zweiter Lauf auf demselben Bestand schreibt nichts und
/// liefert denselben Bericht. Genau deshalb duerfen die Erzeugungsstrecken
/// beider Backends sie unbesehen rufen, und genau deshalb legt Task 11 kein
/// eigenes Beiwerk an. Ein VERAENDERTES Beiwerkbyte ist dagegen ein
/// [`ArchiveBackendError::ByteConflict`] — dieselbe Zusage wie fuer
/// Archivobjekte, auf demselben Weg.
///
/// # Der Bytekonflikt bricht den Lauf NICHT ab
///
/// JEDER Eintrag wird versucht; der Konflikt wird gesammelt und erst NACH dem
/// vollstaendigen Durchlauf gemeldet. Sonst haette eine einzige abweichende
/// Datei alle SPAETEREN Adressen ungeschrieben gelassen — und
/// `README-FORMAT.txt` ist Eintrag 1 von 18, der schlechteste Fall waere also
/// der wahrscheinlichste. Weil die Erzeugungsstrecke den Konflikt nicht
/// herausreicht ([`FormatPackageOutcomeV1::Deviating`]), waere der Bestand
/// danach offen und benutzbar, mit siebzehn fehlenden Beiwerkadressen. Ein
/// Fehler des Wirtdateisystems bricht dagegen weiterhin sofort ab: er sagt
/// nichts ueber die uebrigen Eintraege aus.
///
/// # Der Aufruf gehoert UNTER die Schreibersperre
///
/// Diese Funktion schreibt in den Bestand und nimmt selbst KEINE Sperre: sie
/// nimmt den Port und nicht das Wirtbackend, und die Sperre gehoert dem
/// Aufrufer, der sie ueber die Dauer seiner ganzen Arbeit haelt. Die
/// Erzeugungsstrecke von [`LocalPathBackend::open`](crate::LocalPathBackend::open)
/// nimmt sie deshalb um genau diesen Aufruf und meldet den Bytekonflikt als
/// [`FormatPackageOutcomeV1::Deviating`], statt ihn herauszureichen.
///
/// # Dauerhaftigkeit der Zwischenverzeichnisse — benannte Luecke
///
/// [`ArchivePath::directory`] liefert das LAYOUTVERZEICHNIS
/// (`format/schemas/`), nicht `format/schemas/archive/v1/`. Die
/// Zwischenebenen entstehen im Wirt durch `create_dir_all` und werden nicht
/// einzeln geflusht; nach einem Stromausfall kann ihr Verzeichniseintrag also
/// fehlen. Das ist tragbar und ausdruecklich nicht mit einer breiteren
/// Verzeichnisprimitive geheilt: das Beiwerk ist EINGEBETTET und
/// wiederherstellbar, und die Erzeugungsstrecke ruft diese Funktion bei jedem
/// Oeffnen erneut. Was fehlt, entsteht neu; was da ist, bleibt bytegleich.
///
/// # Errors
///
/// [`ArchiveBackendError::ByteConflict`], wenn MINDESTENS eine Beiwerkadresse
/// ANDERE Bytes traegt — nach dem vollstaendigen Durchlauf; sonst der Fehler
/// des Wirtdateisystems, sofort.
pub fn materialize_format_package(
    backend: &dyn ArchiveBackend,
) -> Result<FormatPackageReport, ArchiveBackendError> {
    let (report, deviating) = materialize_format_package_reporting(backend)?;
    if deviating.is_empty() {
        return Ok(report);
    }
    Err(ArchiveBackendError::ByteConflict)
}

/// Wie [`materialize_format_package`], aber die Abweichungen kommen als LISTE
/// zurueck statt als Fehler.
///
/// Der Unterschied ist ausschliesslich der Rueckkanal: beide schreiben dasselbe
/// und versuchen jeden Eintrag. Die Erzeugungsstrecke von
/// [`LocalPathBackend::open`](crate::LocalPathBackend::open) braucht die ZAHL
/// der Abweichungen fuer [`FormatPackageOutcomeV1::Deviating`], und ein
/// `Result`, das im Fehlerfall den Bericht verwirft, kann sie nicht tragen.
///
/// Crate-privat: die oeffentliche Flaeche des Briefs bleibt
/// [`materialize_format_package`] mit seiner gepinnten Signatur. Braucht ein
/// spaeterer Aufrufer die Zahl, wird diese Funktion befoerdert.
///
/// # Errors
///
/// Der Fehler des Wirtdateisystems, sofort. Ein Bytekonflikt ist hier KEIN
/// Fehler, sondern ein Eintrag der zurueckgegebenen Liste.
pub(crate) fn materialize_format_package_reporting(
    backend: &dyn ArchiveBackend,
) -> Result<(FormatPackageReport, Vec<&'static str>), ArchiveBackendError> {
    for directory in FORMAT_PACKAGE_DIRECTORIES_V1 {
        backend.create_directory_if_absent(directory)?;
    }
    let mut deviating = Vec::new();
    for (relative, bytes) in FORMAT_PACKAGE_FILES_V1 {
        let path = format_package_target(relative)?;
        match backend.create_non_object_if_absent(&path, bytes) {
            Ok(()) => {}
            // GESAMMELT und nicht herausgereicht: die Bytes dieser Adresse
            // bleiben fremd, aber die uebrigen Eintraege entstehen trotzdem.
            // Geflusht wird hier nichts — geschrieben wurde nichts.
            Err(ArchiveBackendError::ByteConflict) => {
                deviating.push(*relative);
                continue;
            }
            Err(other) => return Err(other),
        }
        backend.sync_file(&path)?;
        backend.sync_directory(&path)?;
    }
    Ok((
        FormatPackageReport {
            written_file_count: FORMAT_PACKAGE_FILES_V1.len(),
            directories: FORMAT_PACKAGE_DIRECTORIES_V1,
        },
        deviating,
    ))
}
