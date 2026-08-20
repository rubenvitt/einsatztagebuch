//! Der dokumentierte UTF-8-CSV-Import der Stammdaten.
//!
//! Er nimmt GENAU zwei Kopfzeilen an, und beide sind eingefroren
//! (`ImportSourceKindV1::header_line`). Daran haengt die negative Zusage
//! dieses Tasks: der Importpfad kann eine Einsatznummer weder praegen noch
//! transportieren, weil keine annehmbare Kopfzeile eine Spalte dafuer hat und
//! weil er das Einsatznummernregister nie anfasst. Eine Einsatznummer entsteht
//! beim Abschluss unter der ausschliesslichen Writer-Sperre und nirgends sonst.
//!
//! Der Ablauf ist zweistufig und ausdruecklich nicht einstufig:
//!
//! 1. [`CsvImporter::dry_run`] hasht die EXAKTEN Eingabebytes, prueft jede
//!    Zeile und gibt einen [`ImportReportV1`] zurueck. Er schreibt NICHTS.
//! 2. [`CsvImporter::commit`] nimmt genau diesen Bericht und dieselben Bytes an.
//!    Er lehnt einen Bericht mit Fehlern ab, lehnt einen veraenderten
//!    Eingabestand ab und schreibt sonst EINE Transaktion.
//!
//! Anfuehrungszeichen nach RFC 4180 werden AUSDRUECKLICH nicht ausgewertet: die
//! zwei eingefrorenen Kopfzeilen tragen keine Spalte, in der ein Komma fachlich
//! vorkommt, und ein maskiertes Feld faellt fail-closed als
//! `field-count-mismatch` auf, statt still falsch zerlegt zu werden. Eine
//! stillschweigend halbe Anfuehrungsbehandlung waere schlimmer als keine.
//!
//! Microsoft Access ist vollstaendig ausserhalb des Scopes. Eine erkannte
//! Access-Datei wird deshalb NAMENTLICH abgelehnt und nicht als kaputtes CSV
//! behandelt — sonst laege der Verdacht nahe, ein Importpfad dafuer existiere
//! irgendwo doch.

use core::fmt;
use std::{collections::BTreeSet, sync::Arc};

use ea_format::{
    FormatError, ImportIssueCodeV1, ImportIssueV1, ImportReportFieldsV1, ImportReportV1,
    ImportSourceKindV1,
};
use ea_local_store::{EncryptedDatabase, StoreError, unix_millis_now};
use ea_types::Hash32;
use sha2::{Digest as _, Sha256};

use crate::master_data::{
    ImportedPersonRowV1, ImportedRowsV1, ImportedVehicleRowV1, MasterDataError,
    MasterDataRepository,
};

/// Die Byte-Order-Mark von UTF-8.
const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// Die Dateikennungen der Access-Formate.
///
/// Sie werden VOR der UTF-8-Pruefung geprueft: die vier Kopfbytes einer
/// Access-Datei sind gueltiges UTF-8, und ohne diese Reihenfolge fiele eine
/// Access-Datei als „unbekannte Kopfzeile" auf und nicht als das, was sie ist.
const ACCESS_MAGICS: [&[u8]; 2] = [
    b"\x00\x01\x00\x00Standard Jet DB",
    b"\x00\x01\x00\x00Standard ACE DB",
];

/// Ein Fehlschlag des Imports.
///
/// DATEIWEITE Ablehnungen tragen ihren gepinnten [`ImportIssueCodeV1`]; die
/// uebrigen Arme sind Fehlschlaege des Vorgangs und keine Befunde an der Datei.
/// Kein Arm traegt Dateiinhalt: eine Fehlerausgabe ist eine Protokollzeile, und
/// Stammdaten gehoeren nicht hinein.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum ImportError {
    /// Die Eingabe beginnt mit einer Byte-Order-Mark.
    ByteOrderMark,
    /// Die Eingabe ist kein UTF-8.
    NotUtf8,
    /// Die Kopfzeile ist keine der zwei eingefrorenen.
    UnknownHeader { expected: &'static str },
    /// Die Kopfzeile nennt eine Spalte zweimal.
    DuplicateHeaderColumn,
    /// Die Eingabe ist eine Access-Datei. Access ist ausserhalb des Scopes.
    AccessFormatDetected,
    /// Die Eingabe ist groesser als [`CsvImporter::MAX_INPUT_BYTES`].
    InputTooLarge,
    /// Der Bericht traegt Fehler und wird deshalb nicht gebucht.
    ReportHasErrors,
    /// Die Bytes sind nicht mehr die, ueber die der Trockenlauf lief.
    InputChanged,
    /// Der Bericht passt nicht zu dieser Eingabe.
    ReportMismatch,
    /// Das Urbild liess sich nicht kodieren.
    Report(FormatError),
    /// Die Stammdatenablage hat abgelehnt.
    MasterData(MasterDataError),
}

impl ImportError {
    /// Stabiler Fehlercode.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ByteOrderMark => "EA-IMPORT-BYTE-ORDER-MARK",
            Self::NotUtf8 => "EA-IMPORT-NOT-UTF8",
            Self::UnknownHeader { .. } => "EA-IMPORT-UNKNOWN-HEADER",
            Self::DuplicateHeaderColumn => "EA-IMPORT-DUPLICATE-HEADER-COLUMN",
            Self::AccessFormatDetected => "EA-IMPORT-ACCESS-FORMAT",
            Self::InputTooLarge => "EA-IMPORT-INPUT-TOO-LARGE",
            Self::ReportHasErrors => "EA-IMPORT-REPORT-HAS-ERRORS",
            Self::InputChanged => "EA-IMPORT-INPUT-CHANGED",
            Self::ReportMismatch => "EA-IMPORT-REPORT-MISMATCH",
            Self::Report(error) => error.code(),
            Self::MasterData(error) => error.code(),
        }
    }

    /// Der gepinnte Befundcode, wenn diese Ablehnung DATEIWEIT ist.
    ///
    /// `None` fuer jeden Arm, der kein Befund an der Datei ist. Die Zuordnung
    /// liegt hier und nicht an der Aufrufstelle: derselbe Sachverhalt darf
    /// nicht an zwei Stellen zwei Codes bekommen.
    #[must_use]
    pub const fn issue_code(self) -> Option<ImportIssueCodeV1> {
        match self {
            Self::ByteOrderMark => Some(ImportIssueCodeV1::ByteOrderMarkPresent),
            Self::NotUtf8 => Some(ImportIssueCodeV1::InputNotUtf8),
            Self::UnknownHeader { .. } => Some(ImportIssueCodeV1::UnknownHeader),
            Self::DuplicateHeaderColumn => Some(ImportIssueCodeV1::DuplicateHeaderColumn),
            Self::AccessFormatDetected => Some(ImportIssueCodeV1::AccessFormatDetected),
            _ => None,
        }
    }
}

impl fmt::Display for ImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for ImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for ImportError {}

impl From<FormatError> for ImportError {
    fn from(value: FormatError) -> Self {
        Self::Report(value)
    }
}

impl From<MasterDataError> for ImportError {
    fn from(value: MasterDataError) -> Self {
        Self::MasterData(value)
    }
}

impl From<StoreError> for ImportError {
    fn from(value: StoreError) -> Self {
        Self::MasterData(MasterDataError::Store(value))
    }
}

/// Der Importeur.
pub struct CsvImporter {
    database: Arc<EncryptedDatabase>,
}

impl CsvImporter {
    /// Die EINZIGEN zwei annehmbaren Kopfzeilen, nach der Diskriminante der
    /// Quellart geordnet.
    ///
    /// Sie stehen NICHT ein zweites Mal hier, sondern kommen aus
    /// `ImportSourceKindV1::header_line`: eine zweite Tabelle koennte
    /// auseinanderlaufen, ohne dass es auffaellt. Keine der beiden nennt eine
    /// Einsatznummernspalte, und eine dritte Kopfzeile gibt es nicht.
    pub const ACCEPTED_HEADERS: [&'static str; 2] = [
        ImportSourceKindV1::Persons.header_line(),
        ImportSourceKindV1::Vehicles.header_line(),
    ];

    /// Die groesste annehmbare Eingabe, in Bytes.
    ///
    /// Dieselbe Schranke, die Stufe 1 fuer eine Klartextnutzlast fuehrt. Eine
    /// unbegrenzt gelesene Datei waere eine Arbeitsgrenze ohne Deckel.
    pub const MAX_INPUT_BYTES: usize = 1_048_576;

    /// Die groesste annehmbare Zeichenzahl EINES Feldes.
    pub const MAX_FIELD_CHARS: usize = 200;

    /// Der Name der Spalte, die die Stammdatenkennung traegt.
    const ID_COLUMN: &'static str = "id";

    /// Der Name der Spalte, die den Anzeigenamen traegt.
    const DISPLAY_NAME_COLUMN: &'static str = "display_name";

    /// Der Name der Wahrheitswertspalte.
    const ACTIVE_COLUMN: &'static str = "active";

    #[must_use]
    pub const fn new(database: Arc<EncryptedDatabase>) -> Self {
        Self { database }
    }

    /// Prueft die Eingabe und schreibt NICHTS.
    ///
    /// Der Bericht traegt den rohen, domainfreien `SHA-256` der exakten
    /// Eingabebytes; genau dieser Wert macht [`Self::commit`] gegen eine
    /// zwischenzeitliche Aenderung pruefbar, und genau derselbe steht im Urbild.
    ///
    /// # Errors
    ///
    /// Jeder DATEIWEITE Befund ist ein [`ImportError`] mit seinem gepinnten
    /// Code — Byte-Order-Mark, kein UTF-8, unbekannte oder doppelte Kopfspalte,
    /// erkanntes Access-Format. Zeilenbezogene Verletzungen stehen IM Bericht
    /// und sind kein `Err`: eine Datei mit drei brauchbaren und einer kaputten
    /// Zeile ist eine Aussage und kein Fehlschlag.
    pub fn dry_run(
        &self,
        source_kind: ImportSourceKindV1,
        input: &[u8],
    ) -> Result<ImportReportV1, ImportError> {
        self.parse(source_kind, input).map(|parsed| parsed.report)
    }

    /// Bucht einen fehlerfreien Bericht ueber UNVERAENDERTEN Bytes.
    ///
    /// Die AUFBEWAHRTEN Bytes sind `report.exact_bytes()` und nicht eine
    /// zweite Kodierung: eine neue Kodierung traege eine andere
    /// `imported-at`-Zeit, und der in der Momentaufnahme versiegelte Hash haette
    /// dann kein Urbild mehr. Genau daran haengt die Provenienzzusage AK 28.
    ///
    /// # Errors
    ///
    /// [`ImportError::ReportHasErrors`] bei einem Bericht mit Fehlern,
    /// [`ImportError::InputChanged`], wenn der rohe Hash der Bytes nicht mehr
    /// der des Berichts ist, [`ImportError::ReportMismatch`], wenn der Bericht
    /// zu diesen Bytes nicht passt, sonst [`ImportError::MasterData`] — darunter
    /// jede Verletzung einer Schemabedingung, die die GANZE Transaktion
    /// zurueckrollt.
    pub fn commit(&self, report: &ImportReportV1, input: &[u8]) -> Result<(), ImportError> {
        if !report.errors_on_the_wire().is_empty() {
            return Err(ImportError::ReportHasErrors);
        }
        if raw_sha256(input).as_bytes() != report.input_file_hash().as_bytes() {
            return Err(ImportError::InputChanged);
        }
        let parsed = self.parse(report.source_kind(), input)?;
        // Der Hash deckt die BYTES ab, nicht den Bericht. Ein untergeschobener
        // Bericht mit erfundenen Zaehlern haette denselben Eingabehash; erst
        // dieser Vergleich schliesst ihn aus.
        if parsed.report.total() != report.total()
            || parsed.report.accepted() != report.accepted()
            || parsed.report.rejected() != report.rejected()
            || parsed.report.errors_on_the_wire() != report.errors_on_the_wire()
            || parsed.report.warnings() != report.warnings()
        {
            return Err(ImportError::ReportMismatch);
        }
        MasterDataRepository::new(Arc::clone(&self.database))
            .commit_import(report, &parsed.rows)
            .map_err(ImportError::MasterData)
    }

    fn parse(
        &self,
        source_kind: ImportSourceKindV1,
        input: &[u8],
    ) -> Result<ParsedImport, ImportError> {
        if input.len() > Self::MAX_INPUT_BYTES {
            return Err(ImportError::InputTooLarge);
        }
        if input.starts_with(&UTF8_BOM) {
            return Err(ImportError::ByteOrderMark);
        }
        if ACCESS_MAGICS.iter().any(|magic| input.starts_with(magic)) {
            return Err(ImportError::AccessFormatDetected);
        }
        let text = core::str::from_utf8(input).map_err(|_| ImportError::NotUtf8)?;
        let expected_header = source_kind.header_line();
        let mut lines = text.split('\n');
        let header = lines.next().unwrap_or_default();
        let header = header.strip_suffix('\r').unwrap_or(header);
        let columns: Vec<&str> = header.split(',').collect();
        for (position, column) in columns.iter().enumerate() {
            if columns[..position].contains(column) {
                return Err(ImportError::DuplicateHeaderColumn);
            }
        }
        if header != expected_header {
            return Err(ImportError::UnknownHeader {
                expected: expected_header,
            });
        }

        let data: Vec<&str> = lines
            .map(|line| line.strip_suffix('\r').unwrap_or(line))
            .collect();
        // Der ABSCHLIESSENDE Zeilenvorschub erzeugt beim Trennen ein letztes,
        // leeres Element. Es ist der Abschluss und keine Zeile.
        let data = match data.split_last() {
            Some((&"", head)) => head,
            _ => data.as_slice(),
        };
        // Die Grenze zwischen „abschliessend leer" und „mitten drin leer": nur
        // die erste ist eine uebersprungene Leerzeile, die zweite ist eine
        // Zeile mit falscher Feldzahl.
        let last_filled = data.iter().rposition(|line| !line.is_empty());

        let mut warnings: Vec<ImportIssueV1> = Vec::new();
        let mut errors: Vec<ImportIssueV1> = Vec::new();
        let mut persons: Vec<ImportedPersonRowV1> = Vec::new();
        let mut vehicles: Vec<ImportedVehicleRowV1> = Vec::new();
        // Eine Menge und keine Liste: `contains` auf einer Liste waere quadratisch,
        // und `MAX_INPUT_BYTES` laesst Zehntausende Zeilen zu. `BTreeSet` und nicht
        // `HashSet`, damit kein Hashstartwert in den Ablauf hineinreicht.
        let mut seen_ids: BTreeSet<&str> = BTreeSet::new();
        let mut total = 0_u64;
        let mut accepted = 0_u64;
        let mut rejected = 0_u64;

        for (position, line) in data.iter().enumerate() {
            let row = u64::try_from(position + 1).map_err(|_| ImportError::InputTooLarge)?;
            if line.is_empty() {
                if last_filled.is_none_or(|filled| position > filled) {
                    warnings.push(ImportIssueV1::new(
                        row,
                        None,
                        ImportIssueCodeV1::TrailingEmptyLineSkipped,
                    )?);
                    continue;
                }
                total += 1;
                rejected += 1;
                errors.push(ImportIssueV1::new(
                    row,
                    None,
                    ImportIssueCodeV1::FieldCountMismatch,
                )?);
                continue;
            }
            total += 1;
            let fields: Vec<&str> = line.split(',').collect();
            if fields.len() != columns.len() {
                rejected += 1;
                errors.push(ImportIssueV1::new(
                    row,
                    None,
                    ImportIssueCodeV1::FieldCountMismatch,
                )?);
                continue;
            }

            let mut row_errors: Vec<ImportIssueV1> = Vec::new();
            let mut active = false;
            for (column, value) in columns.iter().zip(&fields) {
                if value.chars().count() > Self::MAX_FIELD_CHARS {
                    row_errors.push(ImportIssueV1::new(
                        row,
                        Some((*column).to_owned()),
                        ImportIssueCodeV1::ValueTooLong,
                    )?);
                    continue;
                }
                if matches!(*column, Self::ID_COLUMN | Self::DISPLAY_NAME_COLUMN)
                    && value.is_empty()
                {
                    row_errors.push(ImportIssueV1::new(
                        row,
                        Some((*column).to_owned()),
                        ImportIssueCodeV1::EmptyRequiredValue,
                    )?);
                    continue;
                }
                if *column == Self::ACTIVE_COLUMN {
                    match *value {
                        "true" => active = true,
                        "false" => active = false,
                        _ => row_errors.push(ImportIssueV1::new(
                            row,
                            Some((*column).to_owned()),
                            ImportIssueCodeV1::InvalidBoolean,
                        )?),
                    }
                }
            }

            // Die Kennung wird fuer JEDE Zeile vermerkt, auch fuer eine
            // abgelehnte: eine zweimal vergebene Kennung ist ein Mangel der
            // Datei und nicht eine Folge der Guete der anderen Zeile.
            // Die Feldpositionen sind gesichert: die Kopfzeile ist oben BYTEGLEICH
            // gegen die eingefrorene Konstante geprueft, und `fields.len()`
            // stimmt mit `columns.len()`. `id` steht in beiden Kopfzeilen an
            // Position 0, `display_name` an 1.
            let id = fields.first().copied().unwrap_or_default();
            if !id.is_empty() && !seen_ids.insert(id) {
                row_errors.push(ImportIssueV1::new(
                    row,
                    Some(Self::ID_COLUMN.to_owned()),
                    ImportIssueCodeV1::DuplicateMasterId,
                )?);
            }

            if row_errors.is_empty() {
                accepted += 1;
                if !active {
                    warnings.push(ImportIssueV1::new(
                        row,
                        Some(Self::ACTIVE_COLUMN.to_owned()),
                        ImportIssueCodeV1::InactiveRowImported,
                    )?);
                }
                match source_kind {
                    ImportSourceKindV1::Persons => persons.push(ImportedPersonRowV1 {
                        master_personnel_id: id.to_owned(),
                        display_name: fields[1].to_owned(),
                        role_or_function: optional_field(fields[2]),
                        active,
                    }),
                    ImportSourceKindV1::Vehicles => vehicles.push(ImportedVehicleRowV1 {
                        master_vehicle_id: id.to_owned(),
                        display_name: fields[1].to_owned(),
                        radio_call_sign: optional_field(fields[2]),
                        license_plate: optional_field(fields[3]),
                        active,
                    }),
                }
            } else {
                rejected += 1;
                errors.append(&mut row_errors);
            }
        }

        let report = ImportReportV1::new(ImportReportFieldsV1 {
            source_kind,
            source_format_version: SOURCE_FORMAT_VERSION_V1,
            input_file_hash: raw_sha256(input),
            header_line: expected_header.to_owned(),
            imported_at: unix_millis_now(),
            row_count_total: total,
            row_count_accepted: accepted,
            row_count_rejected: rejected,
            warnings,
            errors,
        })?;
        let rows = match source_kind {
            ImportSourceKindV1::Persons => ImportedRowsV1::Persons(persons),
            ImportSourceKindV1::Vehicles => ImportedRowsV1::Vehicles(vehicles),
        };
        Ok(ParsedImport { report, rows })
    }
}

/// Die Fassung des Quellformats. Beide Kopfzeilen sind Fassung `1`.
const SOURCE_FORMAT_VERSION_V1: u64 = 1;

struct ParsedImport {
    report: ImportReportV1,
    rows: ImportedRowsV1,
}

fn optional_field(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

/// Der ROHE, domainfreie `SHA-256` der exakten Eingabebytes.
///
/// Ohne Domaintrennung und ausdruecklich so: `import-report-v1` friert
/// `input-file-hash` als „SHA-256 der EXAKTEN Eingabebytes, ohne Domain" ein,
/// damit eine zweite Implementierung denselben Wert mit einem gewoehnlichen
/// `sha256sum` nachrechnen kann. Die Domaintrennung dieses Urbilds sitzt eine
/// Ebene hoeher, im `object_hash` ueber den Berichtsbytes.
fn raw_sha256(input: &[u8]) -> Hash32 {
    let digest: [u8; 32] = Sha256::digest(input).into();
    Hash32::try_from(digest.as_slice()).expect("SHA-256 liefert immer genau 32 Bytes")
}
