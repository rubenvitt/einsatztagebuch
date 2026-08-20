//! Das normative Urbild des `importProtocolHash`.
//!
//! `imported-provenance-v1` traegt an einer PFLICHTPOSITION einen 32-Byte-Hash
//! (`schemas/payload/v1/payload.cddl`:125-129). Ohne ein kanonisches Urbild
//! wuerde dort in Task 11 ein geratener Wert unwiderruflich versiegelt. Dieses
//! Modul ist dieses Urbild: `import-report-v1` nach
//! `schemas/reports/v1/import-report.cddl`, mit
//!
//! ```text
//! importProtocolHash = SHA-256("EINSATZARCHIV-OBJECT-v1" || exactImportReportV1Bytes)
//! ```
//!
//! also nach der BESTEHENDEN Objektkonvention (`ea_crypto::object_hash`,
//! `crates/ea-crypto/src/digest.rs`:63-66). Eine neue Domainkonstante entsteht
//! ausdruecklich nicht (D-B01), also bleiben die eingefrorene Familie der
//! Trennzeichenketten und jeder bestehende Vektor unberuehrt.
//!
//! Der Kodierer lebt HIER und nicht in `ea-draft`: `ea-format` besitzt die
//! deterministischen Kodierer und die eingefrorenen Wire-Typen, und eine zweite
//! Typmenge ist genau der Weg, auf dem falsche Bytes entstehen.
//!
//! Der Bericht bleibt LOKAL. Er wird nie archiviert und ist deshalb kein
//! Archivobjekt: kein `.eXX`-Praefix, kein Magic, kein siebtes Objektpraefix —
//! der Formatfreeze ueber die sechs Praefixe bleibt unangetastet.

use core::fmt;

use ea_cbor::ParserLimits;
use ea_crypto::object_hash;
use ea_types::{Hash32, ObjectHash};
use minicbor::Encoder;

use crate::object::FormatError;

/// Die Art der Importquelle. GESCHLOSSEN, zwei Arme.
///
/// Der Quellbezeichner und die akzeptierte Kopfzeile haengen an DIESEM Typ und
/// nicht an einer zweiten Tabelle: eine Quelle, deren Kopfzeile anderswo steht,
/// koennte auseinanderlaufen, ohne dass es auffaellt.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ImportSourceKindV1 {
    Persons = 0,
    Vehicles = 1,
}

impl ImportSourceKindV1 {
    /// Beide Arme, in Positionsordnung ihrer Diskriminanten.
    pub const ALL: [Self; 2] = [Self::Persons, Self::Vehicles];

    /// Die gepinnte Diskriminante, wie sie auf dem Draht steht.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Der Quellbezeichner an Position `source-id`.
    ///
    /// Er benennt die IMPORTQUELLE und keine Stammdatenzeile; der eingefrorene
    /// Vektor `vectors/format/payload-v1/incident.hex` traegt
    /// `["csv-vehicles", 1, h'81…81']` in genau dieser Position.
    #[must_use]
    pub const fn source_id(self) -> &'static str {
        match self {
            Self::Persons => "csv-persons",
            Self::Vehicles => "csv-vehicles",
        }
    }

    /// Die EINZIGE Kopfzeile, die diese Quelle annimmt.
    ///
    /// Beide Kopfzeilen sind eingefroren und nennen keine
    /// Einsatznummernspalte. Das ist die STRUKTURELLE Fassung der negativen
    /// Zusage: der Importpfad kann eine Einsatznummer nicht transportieren,
    /// weil keine Kopfzeile eine traegt.
    #[must_use]
    pub const fn header_line(self) -> &'static str {
        match self {
            Self::Persons => "id,display_name,role,active",
            Self::Vehicles => "id,display_name,radio_call_sign,license_plate,active",
        }
    }
}

/// Der GESCHLOSSENE Codebereich eines Importbefunds.
///
/// Die Diskriminanten sind gepinnt, weil der `importProtocolHash` ueber sie
/// gebildet wird: ein wandernder Code ergaebe einen anderen Hash bei
/// unveraendertem Sachverhalt. `local-audit-event-v1` pinnt seine `0..11`
/// genauso.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum ImportIssueCodeV1 {
    ByteOrderMarkPresent = 0,
    InputNotUtf8 = 1,
    UnknownHeader = 2,
    DuplicateHeaderColumn = 3,
    AccessFormatDetected = 4,
    FieldCountMismatch = 5,
    EmptyRequiredValue = 6,
    InvalidBoolean = 7,
    DuplicateMasterId = 8,
    ValueNotInClosedSet = 9,
    ValueTooLong = 10,
    InactiveRowImported = 11,
    TrailingEmptyLineSkipped = 12,
}

impl ImportIssueCodeV1 {
    /// Alle dreizehn Codes, aufsteigend nach Diskriminante.
    pub const ALL: [Self; 13] = [
        Self::ByteOrderMarkPresent,
        Self::InputNotUtf8,
        Self::UnknownHeader,
        Self::DuplicateHeaderColumn,
        Self::AccessFormatDetected,
        Self::FieldCountMismatch,
        Self::EmptyRequiredValue,
        Self::InvalidBoolean,
        Self::DuplicateMasterId,
        Self::ValueNotInClosedSet,
        Self::ValueTooLong,
        Self::InactiveRowImported,
        Self::TrailingEmptyLineSkipped,
    ];

    /// Die gepinnte Diskriminante.
    #[must_use]
    pub const fn code(self) -> u32 {
        self as u32
    }

    /// Ob dieser Code eine WARNUNG ist.
    ///
    /// Die Klassifikation gehoert dem CODE und nie der Aufrufstelle: derselbe
    /// Sachverhalt darf nicht an einer Stelle Fehler und an einer anderen
    /// Warnung sein, sonst haengt der Hash am Aufrufer.
    #[must_use]
    pub const fn is_warning(self) -> bool {
        matches!(
            self,
            Self::InactiveRowImported | Self::TrailingEmptyLineSkipped
        )
    }

    /// Ob dieser Code DATEIWEIT gilt.
    ///
    /// Dateiweite Codes tragen `row = 0` und `column = null`.
    #[must_use]
    pub const fn is_file_wide(self) -> bool {
        matches!(
            self,
            Self::ByteOrderMarkPresent
                | Self::InputNotUtf8
                | Self::UnknownHeader
                | Self::DuplicateHeaderColumn
                | Self::AccessFormatDetected
        )
    }

    /// Der stabile Name, gegen den Tests und Protokolle assertieren.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ByteOrderMarkPresent => "byte-order-mark-present",
            Self::InputNotUtf8 => "input-not-utf8",
            Self::UnknownHeader => "unknown-header",
            Self::DuplicateHeaderColumn => "duplicate-header-column",
            Self::AccessFormatDetected => "access-format-detected",
            Self::FieldCountMismatch => "field-count-mismatch",
            Self::EmptyRequiredValue => "empty-required-value",
            Self::InvalidBoolean => "invalid-boolean",
            Self::DuplicateMasterId => "duplicate-master-id",
            Self::ValueNotInClosedSet => "value-not-in-closed-set",
            Self::ValueTooLong => "value-too-long",
            Self::InactiveRowImported => "inactive-row-imported",
            Self::TrailingEmptyLineSkipped => "trailing-empty-line-skipped",
        }
    }
}

/// EIN Befund: die Zeile, die Spalte und der Code.
///
/// Die Feldreihenfolge IST der Sortierschluessel: das abgeleitete `Ord`
/// vergleicht `row`, dann `column` — `None` vor jedem `Some`, danach byteweise
/// —, dann `code`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ImportIssueV1 {
    row: u64,
    column: Option<String>,
    code: ImportIssueCodeV1,
}

impl ImportIssueV1 {
    /// # Errors
    ///
    /// [`FormatError::Shape`], wenn Zeile und Code nicht zusammenpassen: ein
    /// dateiweiter Code MUSS `row = 0` und `column = None` tragen, ein
    /// zeilenbezogener eine Zeile ab `1`. Ohne diese Bedingung koennte
    /// dieselbe Aussage zwei verschiedene Urbilder haben.
    pub fn new(
        row: u64,
        column: Option<String>,
        code: ImportIssueCodeV1,
    ) -> Result<Self, FormatError> {
        if code.is_file_wide() {
            if row != 0 || column.is_some() {
                return Err(FormatError::Shape);
            }
        } else if row == 0 {
            return Err(FormatError::Shape);
        }
        Ok(Self { row, column, code })
    }

    #[must_use]
    pub const fn row(&self) -> u64 {
        self.row
    }

    #[must_use]
    pub fn column(&self) -> Option<&str> {
        self.column.as_deref()
    }

    #[must_use]
    pub const fn code(&self) -> ImportIssueCodeV1 {
        self.code
    }
}

/// Die zeilenweise Sicht auf die Fehlerliste.
///
/// GENAU EIN Eintrag je fehlerhafter Zeile, und er zaehlt jede Verletzung
/// dieser Zeile auf. Auf dem Draht steht die andere Projektion — eine
/// `import-issue-v1` je Verletzung —, weil das feste `(row, column, code)`-Tripel
/// und sein Sortierschluessel genau die verlangen.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportRowErrorV1 {
    row: u64,
    issues: Vec<ImportIssueV1>,
}

impl ImportRowErrorV1 {
    #[must_use]
    pub const fn row(&self) -> u64 {
        self.row
    }

    #[must_use]
    pub fn issues(&self) -> &[ImportIssueV1] {
        &self.issues
    }
}

/// Die Eingaben eines Importberichts.
///
/// Offene Felder, wie [`crate::LocalAuditEventCoreFieldsV1`] sie fuehrt; die
/// Zusicherungen greifen im Konstruktor von [`ImportReportV1`], nicht hier.
/// `source-id` ist AUSDRUECKLICH kein Feld: er haengt an `source_kind` und
/// koennte sonst von ihm abweichen.
pub struct ImportReportFieldsV1 {
    pub source_kind: ImportSourceKindV1,
    pub source_format_version: u64,
    /// Roher, DOMAINFREIER `SHA-256` ueber die exakten Eingabebytes.
    pub input_file_hash: Hash32,
    pub header_line: String,
    /// Epoch-Millis. Technische Zeit des Imports, keine Vertrauenszeit.
    pub imported_at: i64,
    pub row_count_total: u64,
    pub row_count_accepted: u64,
    pub row_count_rejected: u64,
    /// In Autorenreihenfolge. Der Konstruktor sortiert.
    pub warnings: Vec<ImportIssueV1>,
    /// In Autorenreihenfolge, EINE Zeile je Verletzung. Der Konstruktor
    /// sortiert.
    pub errors: Vec<ImportIssueV1>,
}

/// Der fertige Bericht: Inhalt, exakte Bytes und ihr Objekthash.
///
/// Die Felder sind privat und es gibt genau einen Konstruktor: die exakten
/// Bytes und der Hash sind daraus ABGELEITET, und ein Setzer waere die Tuer,
/// durch die ein Hash ohne sein Urbild kaeme.
pub struct ImportReportV1 {
    fields: ImportReportFieldsV1,
    exact_bytes: Vec<u8>,
    import_protocol_hash: ObjectHash,
}

impl fmt::Debug for ImportReportV1 {
    /// Zaehlend und nicht ausschuettend: ein Importbericht nennt Spaltennamen
    /// und Zeilennummern von Stammdaten, und eine `assert`-Ausgabe ist eine
    /// Protokollzeile.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "ImportReportV1({}, total={}, accepted={}, rejected={}, warnings={}, errors={})",
            self.fields.source_kind.source_id(),
            self.fields.row_count_total,
            self.fields.row_count_accepted,
            self.fields.row_count_rejected,
            self.fields.warnings.len(),
            self.fields.errors.len()
        )
    }
}

impl ImportReportV1 {
    /// Die eingefrorene Fassung des Berichts an Position `report-version`.
    pub const REPORT_VERSION: u8 = 1;

    /// Baut den Bericht, sortiert beide Listen und kodiert ihn EINMAL.
    ///
    /// Sortiert wird HIER und nicht im Kodierer: sonst gaebe der Leser eine
    /// unsortierte Liste heraus, waehrend die Bytes eine sortierte tragen, und
    /// die zwei widersprachen sich stillschweigend.
    ///
    /// # Errors
    ///
    /// [`FormatError::Shape`], wenn die Kopfzeile nicht die der Quelle ist,
    /// wenn die Zeilenzahlen nicht aufgehen oder wenn ein Code in der falschen
    /// Liste steht; [`FormatError::Duplicate`] bei zwei identischen Befunden;
    /// [`FormatError::Cbor`], wenn die erzeugten Bytes die strenge
    /// Kanonisierungspruefung nicht bestehen.
    pub fn new(mut fields: ImportReportFieldsV1) -> Result<Self, FormatError> {
        if fields.header_line != fields.source_kind.header_line() {
            return Err(FormatError::Shape);
        }
        if fields
            .row_count_accepted
            .checked_add(fields.row_count_rejected)
            != Some(fields.row_count_total)
        {
            return Err(FormatError::Shape);
        }
        if fields.warnings.iter().any(|issue| !issue.code.is_warning())
            || fields.errors.iter().any(|issue| issue.code.is_warning())
        {
            return Err(FormatError::Shape);
        }
        fields.warnings.sort();
        fields.errors.sort();
        for list in [&fields.warnings, &fields.errors] {
            if list.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(FormatError::Duplicate);
            }
        }
        let exact_bytes = encode_fields(&fields)?;
        let import_protocol_hash = object_hash(&exact_bytes);
        Ok(Self {
            fields,
            exact_bytes,
            import_protocol_hash,
        })
    }

    #[must_use]
    pub const fn source_kind(&self) -> ImportSourceKindV1 {
        self.fields.source_kind
    }

    #[must_use]
    pub const fn source_id(&self) -> &'static str {
        self.fields.source_kind.source_id()
    }

    #[must_use]
    pub const fn source_format_version(&self) -> u64 {
        self.fields.source_format_version
    }

    /// Der rohe, domainfreie `SHA-256` der exakten Eingabebytes.
    #[must_use]
    pub const fn input_file_hash(&self) -> Hash32 {
        self.fields.input_file_hash
    }

    #[must_use]
    pub fn header_line(&self) -> &str {
        &self.fields.header_line
    }

    #[must_use]
    pub const fn imported_at(&self) -> i64 {
        self.fields.imported_at
    }

    #[must_use]
    pub const fn total(&self) -> u64 {
        self.fields.row_count_total
    }

    #[must_use]
    pub const fn accepted(&self) -> u64 {
        self.fields.row_count_accepted
    }

    #[must_use]
    pub const fn rejected(&self) -> u64 {
        self.fields.row_count_rejected
    }

    /// Die sortierten Warnungen, wie sie auf dem Draht stehen.
    #[must_use]
    pub fn warnings(&self) -> &[ImportIssueV1] {
        &self.fields.warnings
    }

    /// Die Fehler je VERLETZUNG, wie sie auf dem Draht stehen.
    #[must_use]
    pub fn errors_on_the_wire(&self) -> &[ImportIssueV1] {
        &self.fields.errors
    }

    /// Die Fehler je fehlerhafter ZEILE.
    ///
    /// Abgeleitet und nicht mitgefuehrt: zwei gespeicherte Sichten derselben
    /// Liste koennten auseinanderlaufen.
    #[must_use]
    pub fn errors(&self) -> Vec<ImportRowErrorV1> {
        let mut grouped: Vec<ImportRowErrorV1> = Vec::new();
        for issue in &self.fields.errors {
            match grouped.last_mut() {
                Some(last) if last.row == issue.row => last.issues.push(issue.clone()),
                _ => grouped.push(ImportRowErrorV1 {
                    row: issue.row,
                    issues: vec![issue.clone()],
                }),
            }
        }
        grouped
    }

    /// Die EXAKTEN `import-report-v1`-Bytes, ueber die der Hash gebildet ist.
    ///
    /// Genau diese Bytes bewahrt der Writer auf. Ein Aufrufer, der sie neu
    /// kodiert statt sie aufzubewahren, verliert die Provenienzzusage: eine
    /// zweite Kodierung traegt eine andere `imported-at`-Zeit.
    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    /// `SHA-256("EINSATZARCHIV-OBJECT-v1" || exact_bytes)`.
    #[must_use]
    pub const fn import_protocol_hash(&self) -> ObjectHash {
        self.import_protocol_hash
    }
}

/// Kodiert den Bericht deterministisch nach `import-report-v1`.
///
/// Neu kodiert und nicht bloss zurueckgegeben: nur so ist die Behauptung
/// „diese Bytes sind das Urbild dieses Inhalts" ueberhaupt pruefbar.
///
/// # Errors
///
/// [`FormatError::Shape`] bei einem Kodierfehlschlag und
/// [`FormatError::Cbor`], wenn die Bytes die strenge Kanonisierungspruefung
/// nicht bestehen — etwa weil eine Textposition nicht NFC-normalisiert ist oder
/// eine Liste die Parsergrenzen der Suite 1 sprengt.
pub fn encode_import_report(report: &ImportReportV1) -> Result<Vec<u8>, FormatError> {
    encode_fields(&report.fields)
}

fn encode_fields(fields: &ImportReportFieldsV1) -> Result<Vec<u8>, FormatError> {
    let mut exact = Vec::with_capacity(256);
    let mut encoder = Encoder::new(&mut exact);
    encoder
        .array(12)
        .and_then(|encoder| encoder.u8(ImportReportV1::REPORT_VERSION))
        .and_then(|encoder| encoder.u8(fields.source_kind.code()))
        .and_then(|encoder| encoder.str(fields.source_kind.source_id()))
        .and_then(|encoder| encoder.u64(fields.source_format_version))
        .and_then(|encoder| encoder.bytes(fields.input_file_hash.as_bytes()))
        .and_then(|encoder| encoder.str(&fields.header_line))
        .and_then(|encoder| encoder.i64(fields.imported_at))
        .and_then(|encoder| encoder.u64(fields.row_count_total))
        .and_then(|encoder| encoder.u64(fields.row_count_accepted))
        .and_then(|encoder| encoder.u64(fields.row_count_rejected))
        .map_err(|_| FormatError::Shape)?;
    encode_issues(&mut encoder, &fields.warnings)?;
    encode_issues(&mut encoder, &fields.errors)?;
    // Die STRENGE Pruefung und nicht bloss eine Umkodierung: sie verlangt
    // minimale Koepfe, bestimmte Laengen, NFC-Text und die Parsergrenzen der
    // Suite 1 — genau der Lauf, den `xtask validate-schemas` ueber den
    // eingefrorenen Vektor fuehrt.
    ea_cbor::validate(&exact, ParserLimits::V1)?;
    Ok(exact)
}

fn encode_issues(
    encoder: &mut Encoder<&mut Vec<u8>>,
    issues: &[ImportIssueV1],
) -> Result<(), FormatError> {
    let length = u64::try_from(issues.len()).map_err(|_| FormatError::Shape)?;
    encoder.array(length).map_err(|_| FormatError::Shape)?;
    for issue in issues {
        encoder
            .array(3)
            .and_then(|encoder| encoder.u64(issue.row))
            .map_err(|_| FormatError::Shape)?;
        match issue.column.as_deref() {
            Some(column) => encoder.str(column).map(|_| ()),
            None => encoder.null().map(|_| ()),
        }
        .map_err(|_| FormatError::Shape)?;
        encoder
            .u32(issue.code.code())
            .map_err(|_| FormatError::Shape)?;
    }
    Ok(())
}
