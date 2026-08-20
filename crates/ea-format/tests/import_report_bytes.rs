//! Die Bytes des `import-report-v1`-Urbilds.
//!
//! `importProtocolHash` sitzt an einer PFLICHTPOSITION von
//! `imported-provenance-v1` (`schemas/payload/v1/payload.cddl`:125-129). Ohne
//! ein kanonisches Urbild wuerde in Task 11 ein geratener 32-Byte-Wert
//! unwiderruflich versiegelt. Diese Datei messt genau das Urbild: dass es
//! deterministisch ist, dass es kanonisches CBOR ist und dass der Hash die
//! BESTEHENDE Objektkonvention `SHA-256("EINSATZARCHIV-OBJECT-v1" || bytes)`
//! benutzt — eine neue Domainkonstante entsteht nicht (D-B01).
//!
//! Die Fixture liegt als INNERES Modul und nicht in `tests/support/mod.rs`:
//! jenes Modul wird von vier anderen Zielen eingebunden und braucht von
//! Stammdatenimporten nichts.

use ea_format::{
    ImportIssueCodeV1, ImportIssueV1, ImportReportFieldsV1, ImportReportV1, ImportSourceKindV1,
};
use ea_types::Hash32;

/// Die EINGEFROHRENEN Bytes des Vektors dieser Familie.
const VECTOR_BYTES: &[u8] = include_bytes!(
    "../../../vectors/reports/import-report-v1/import-report/persons-two-issues-in-one-row.bin"
);

/// Das Manifest derselben Familie, als Text.
const VECTOR_MANIFEST: &str =
    include_str!("../../../vectors/reports/import-report-v1/manifest.json");

mod support {
    use ea_format::{
        ImportIssueCodeV1, ImportIssueV1, ImportReportFieldsV1, ImportReportV1, ImportSourceKindV1,
    };
    use ea_types::Hash32;

    /// Der Rohhash der Eingabedatei — SYNTHETISCH und unveraenderlich.
    ///
    /// Er ist kein echter SHA-256 einer Datei: der Vektor friert BYTES ein, und
    /// ein Wert, der aus einer Beispieldatei neu berechnet wuerde, machte den
    /// eingefrorenen Vektor von dieser Datei abhaengig.
    pub const FIXTURE_INPUT_FILE_HASH: [u8; 32] = [0x91; 32];

    /// Die eingefrorene Importzeit des Vektors, Epoch-Millis.
    pub const FIXTURE_IMPORTED_AT_MS: i64 = 1_760_000_000_000;

    fn hash() -> Hash32 {
        Hash32::try_from(FIXTURE_INPUT_FILE_HASH.as_slice()).unwrap()
    }

    fn issue(row: u64, column: Option<&str>, code: ImportIssueCodeV1) -> ImportIssueV1 {
        ImportIssueV1::new(row, column.map(str::to_owned), code).unwrap()
    }

    /// Der Bericht des Vektors: EIN fehlerhafter Zeile mit ZWEI Verletzungen.
    ///
    /// Genau diese Gestalt trennt die zwei Projektionen derselben Liste:
    /// `errors()` traegt EINEN Eintrag (die Zeile), `errors_on_the_wire()` traegt
    /// ZWEI (die Verletzungen), und die Bytes tragen die zweite.
    #[must_use]
    pub fn persons_report_with_two_issues_in_one_row() -> ImportReportV1 {
        ImportReportV1::new(ImportReportFieldsV1 {
            source_kind: ImportSourceKindV1::Persons,
            source_format_version: 1,
            input_file_hash: hash(),
            header_line: ImportSourceKindV1::Persons.header_line().to_owned(),
            imported_at: FIXTURE_IMPORTED_AT_MS,
            row_count_total: 3,
            row_count_accepted: 2,
            row_count_rejected: 1,
            warnings: vec![issue(
                2,
                Some("active"),
                ImportIssueCodeV1::InactiveRowImported,
            )],
            errors: vec![
                issue(
                    3,
                    Some("display_name"),
                    ImportIssueCodeV1::EmptyRequiredValue,
                ),
                issue(3, Some("role"), ImportIssueCodeV1::ValueNotInClosedSet),
            ],
        })
        .unwrap()
    }

    /// Derselbe Berichtstyp, beide Listen in UMGEKEHRTER Sortierordnung
    /// uebergeben.
    ///
    /// Umgekehrt und nicht bloss vertauscht: eine Fixture, die zufaellig schon
    /// sortiert danebenliegt, liesse die Sortierzusicherung leer laufen. Die
    /// fuenf Fehler erschoepfen alle drei Schluesselteile — eine dateiweite
    /// Zeile 0 mit `null`-Spalte gegen benannte Spalten, zwei Eintraege mit
    /// GLEICHEM `(row, column)`, die sich nur im Code unterscheiden, und eine
    /// spaetere Zeile mit lexikografisch kleinerer Spalte.
    #[must_use]
    pub fn persons_report_with_shuffled_issues() -> ImportReportV1 {
        ImportReportV1::new(ImportReportFieldsV1 {
            source_kind: ImportSourceKindV1::Persons,
            source_format_version: 1,
            input_file_hash: hash(),
            header_line: ImportSourceKindV1::Persons.header_line().to_owned(),
            imported_at: FIXTURE_IMPORTED_AT_MS,
            row_count_total: 3,
            row_count_accepted: 1,
            row_count_rejected: 2,
            warnings: vec![
                issue(2, Some("active"), ImportIssueCodeV1::InactiveRowImported),
                issue(1, None, ImportIssueCodeV1::TrailingEmptyLineSkipped),
            ],
            errors: vec![
                issue(3, Some("active"), ImportIssueCodeV1::InvalidBoolean),
                issue(2, Some("display_name"), ImportIssueCodeV1::ValueTooLong),
                issue(
                    2,
                    Some("display_name"),
                    ImportIssueCodeV1::EmptyRequiredValue,
                ),
                issue(2, None, ImportIssueCodeV1::FieldCountMismatch),
                issue(0, None, ImportIssueCodeV1::ByteOrderMarkPresent),
            ],
        })
        .unwrap()
    }
}

#[test]
fn import_report_bytes_are_canonical_and_hash_over_the_object_domain() {
    let report = support::persons_report_with_two_issues_in_one_row();
    let bytes = ea_format::encode_import_report(&report).unwrap();
    assert_eq!(bytes, ea_format::encode_import_report(&report).unwrap());
    assert_eq!(
        ea_cbor::canonical_reencode(&bytes, ea_cbor::ParserLimits::V1).unwrap(),
        bytes
    );
    // Die STRENGE Pruefung zusaetzlich zur entspannten Umkodierung: sie
    // verlangt NFC-Text und minimale Koepfe und ist derselbe Lauf, den
    // `xtask validate-schemas` ueber den Vektor fuehrt.
    ea_cbor::validate(&bytes, ea_cbor::ParserLimits::V1).unwrap();
    // `ObjectHash` traegt bewusst kein `Debug`; der Vergleich laeuft ueber alle
    // 32 Bytes und verliert deshalb keine Staerke.
    assert_eq!(
        report.import_protocol_hash().as_bytes(),
        ea_crypto::object_hash(&bytes).as_bytes()
    );
    // Die gespeicherten Bytes sind DIESELBEN, die der Kodierer erzeugt. Nur
    // dann ist das aufbewahrte Urbild dasjenige, ueber das der versiegelte Hash
    // gebildet wurde.
    assert_eq!(report.exact_bytes(), bytes.as_slice());
}

#[test]
fn issue_lists_sort_by_row_then_column_then_code_with_null_column_first() {
    let report = support::persons_report_with_shuffled_issues();
    let issues = report.errors_on_the_wire();
    let keys: Vec<(u64, Option<&str>, u32)> = issues
        .iter()
        .map(|i| (i.row(), i.column(), i.code() as u32))
        .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
    assert_eq!(keys[0], (0, None, 0));
    // Die Fixture wurde UMGEKEHRT uebergeben: waere die Sortierung fort, waere
    // `keys` genau die Umkehrung und diese Zusicherung faellt.
    let mut reversed = sorted.clone();
    reversed.reverse();
    assert_ne!(keys, reversed);
    // Regel 2 gilt fuer BEIDE Listen.
    let warning_keys: Vec<(u64, Option<&str>, u32)> = report
        .warnings()
        .iter()
        .map(|i| (i.row(), i.column(), i.code() as u32))
        .collect();
    let mut sorted_warnings = warning_keys.clone();
    sorted_warnings.sort();
    assert_eq!(warning_keys, sorted_warnings);
    assert_eq!(warning_keys[0], (1, None, 12));
}

#[test]
fn issue_codes_keep_their_pinned_discriminants() {
    let discriminants: Vec<u32> = ImportIssueCodeV1::ALL
        .iter()
        .map(|code| *code as u32)
        .collect();
    assert_eq!(discriminants, (0..=12).collect::<Vec<u32>>());
}

#[test]
fn the_error_versus_warning_classification_belongs_to_the_code_and_not_the_call_site() {
    // Die Klassifikation ist PRO CODE festgeschrieben. Ein Warncode in der
    // Fehlerliste — oder umgekehrt — ist deshalb kein Ermessen des Aufrufers,
    // sondern ein Abbruch des Konstruktors.
    let warning_in_the_error_list = ImportReportV1::new(ImportReportFieldsV1 {
        source_kind: ImportSourceKindV1::Persons,
        source_format_version: 1,
        input_file_hash: Hash32::try_from([0x91; 32].as_slice()).unwrap(),
        header_line: ImportSourceKindV1::Persons.header_line().to_owned(),
        imported_at: 1,
        row_count_total: 1,
        row_count_accepted: 0,
        row_count_rejected: 1,
        warnings: Vec::new(),
        errors: vec![ImportIssueV1::new(1, None, ImportIssueCodeV1::InactiveRowImported).unwrap()],
    });
    assert!(warning_in_the_error_list.is_err());

    let error_in_the_warning_list = ImportReportV1::new(ImportReportFieldsV1 {
        source_kind: ImportSourceKindV1::Persons,
        source_format_version: 1,
        input_file_hash: Hash32::try_from([0x91; 32].as_slice()).unwrap(),
        header_line: ImportSourceKindV1::Persons.header_line().to_owned(),
        imported_at: 1,
        row_count_total: 1,
        row_count_accepted: 1,
        row_count_rejected: 0,
        warnings: vec![ImportIssueV1::new(1, None, ImportIssueCodeV1::EmptyRequiredValue).unwrap()],
        errors: Vec::new(),
    });
    assert!(error_in_the_warning_list.is_err());

    // Und ein dateiweiter Code, der eine Zeilennummer traegt, ist keine
    // dateiweite Aussage mehr.
    assert!(
        ImportIssueV1::new(2, None, ImportIssueCodeV1::ByteOrderMarkPresent).is_err(),
        "die Codes 0..4 sind dateiweit und tragen row = 0"
    );
    assert!(
        ImportIssueV1::new(0, None, ImportIssueCodeV1::EmptyRequiredValue).is_err(),
        "ein zeilenbezogener Code ohne Zeile ist keine Aussage"
    );
}

#[test]
fn the_row_grouped_view_and_the_wire_list_are_two_projections_of_one_list() {
    let report = support::persons_report_with_two_issues_in_one_row();
    // EINE fehlerhafte Zeile, ZWEI Verletzungen. Genau diese Trennung ist der
    // Grund, aus dem der Vektor `persons-two-issues-in-one-row` heisst.
    assert_eq!(report.errors().len(), 1);
    assert_eq!(report.errors_on_the_wire().len(), 2);
    let row = &report.errors()[0];
    assert_eq!(row.row(), 3);
    assert_eq!(row.issues().len(), 2);
    let codes: Vec<u32> = row.issues().iter().map(|i| i.code() as u32).collect();
    assert_eq!(codes, vec![6, 9]);
}

#[test]
fn the_committed_vector_reproduces_the_encoder_and_its_manifest_expectation() {
    let report = support::persons_report_with_two_issues_in_one_row();
    let bytes = ea_format::encode_import_report(&report).unwrap();
    assert_eq!(
        VECTOR_BYTES, bytes,
        "der eingefrorene Vektor ist nicht mehr das, was der Kodierer erzeugt"
    );
    assert!(
        VECTOR_MANIFEST.contains(&format!("\"objectBytes\": \"{}\"", hex::encode(&bytes))),
        "das Manifest nennt andere objectBytes als der Kodierer erzeugt"
    );
    assert!(
        VECTOR_MANIFEST.contains(&format!(
            "\"objectHash\": \"{}\"",
            hex::encode(ea_crypto::object_hash(&bytes).as_bytes())
        )),
        "das Manifest nennt einen anderen objectHash als die Objektkonvention ergibt"
    );
    assert!(
        VECTOR_MANIFEST.contains("\"file\": \"import-report/persons-two-issues-in-one-row.bin\""),
        "das Manifest nennt die Vektordatei nicht"
    );
}

#[test]
fn a_report_that_claims_another_source_format_version_is_refused() {
    // Kanonisierungsregel 6 sagt „`source-format-version` ist `1`". Die
    // Grammatik sagt an dieser Position nur `uint`, und `CsvImporter::commit`
    // vergleicht Zaehler und Befundlisten, nicht die Fassung. Bliebe die Regel
    // Prosa, buchte ein selbstgebauter Bericht ueber denselben Eingabebytes eine
    // beliebige `sourceFormatVersion` in die `ImportedProvenanceV1`, die Task 11
    // VERSIEGELT — irreversibel und ohne zweiten Leser. Der Konstruktor ist die
    // einzige Stelle, an der die Regel jeden Aufrufer bindet.
    assert_eq!(ImportReportV1::SOURCE_FORMAT_VERSION, 1);
    for claimed in [0_u64, 2, 7, u64::MAX] {
        // `FormatError` traegt bewusst kein `Debug`; der Code ist die
        // vergleichbare Fassung derselben Aussage.
        let refused = ImportReportV1::new(persons_fields_with_source_format_version(claimed))
            .err()
            .map(ea_format::FormatError::code);
        assert_eq!(
            refused,
            Some("EA-FORMAT-SHAPE"),
            "Fassung {claimed} wurde gebucht statt abgelehnt"
        );
    }
    let pinned = ImportReportV1::new(persons_fields_with_source_format_version(
        ImportReportV1::SOURCE_FORMAT_VERSION,
    ));
    assert!(
        pinned.is_ok(),
        "die gepinnte Fassung muss weiterhin baubar sein"
    );
}

/// Ein sonst gueltiger Personenbericht mit frei gesetzter Quellformatfassung.
fn persons_fields_with_source_format_version(version: u64) -> ImportReportFieldsV1 {
    ImportReportFieldsV1 {
        source_kind: ImportSourceKindV1::Persons,
        source_format_version: version,
        input_file_hash: Hash32::try_from([0x91; 32].as_slice()).unwrap(),
        header_line: ImportSourceKindV1::Persons.header_line().to_owned(),
        imported_at: support::FIXTURE_IMPORTED_AT_MS,
        row_count_total: 1,
        row_count_accepted: 1,
        row_count_rejected: 0,
        warnings: Vec::new(),
        errors: Vec::new(),
    }
}
