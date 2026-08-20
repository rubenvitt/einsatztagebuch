//! Trockenlauf, Alles-oder-nichts und die negative Zusage des Importpfads.
//!
//! AK 28 (`design.md`:404, :2139) verlangt eine nachpruefbare Provenienz. Diese
//! Datei messt die vier Zusagen, die dafuer tragen: der Trockenlauf schreibt
//! nichts, das Buchen ist eine Transaktion, ein veraenderter Eingabestand wird
//! abgelehnt, und der Importpfad kann eine Einsatznummer weder praegen noch
//! transportieren.

mod support;

use ea_draft::{CsvImporter, ImportError};
use ea_format::{ImportReportFieldsV1, ImportReportV1, ImportSourceKindV1};

use self::support::ImportHarness;

#[test]
fn dry_run_does_not_write_and_commit_is_all_or_nothing() {
    let harness = ImportHarness::new();
    let (importer, repo) = (harness.importer(), harness.master_data_repo());
    let csv = b"id,display_name,role,active\np1,Ada,Fuehrung,true\nbad,,X,true\n";
    let report = importer.dry_run(ImportSourceKindV1::Persons, csv).unwrap();
    assert_eq!((report.accepted(), report.errors().len()), (1, 1));
    assert_eq!(repo.person_count().unwrap(), 0);
    assert!(importer.commit(&report, csv).is_err());
    assert_eq!(repo.person_count().unwrap(), 0);
}

#[test]
fn vehicle_csv_accepts_its_own_header_and_rejects_the_person_header() {
    let harness = ImportHarness::new();
    let importer = harness.importer();
    let vehicles = b"id,display_name,radio_call_sign,license_plate,active\n\
                     v1,MTW,Rotkreuz 1,HH-DRK 1,true\n";
    assert_eq!(
        importer
            .dry_run(ImportSourceKindV1::Vehicles, vehicles)
            .unwrap()
            .accepted(),
        1
    );
    let persons_header = b"id,display_name,role,active\np1,Ada,Fuehrung,true\n";
    assert!(matches!(
        importer
            .dry_run(ImportSourceKindV1::Vehicles, persons_header)
            .unwrap_err(),
        ImportError::UnknownHeader { .. }
    ));
}

#[test]
fn commit_rejects_a_mutated_dry_run_hash() {
    let harness = ImportHarness::new();
    let (importer, repo) = (harness.importer(), harness.master_data_repo());
    let mut csv = b"id,display_name,role,active\np1,Ada,Fuehrung,true\n".to_vec();
    let first = importer.dry_run(ImportSourceKindV1::Persons, &csv).unwrap();
    csv[29] = b'B';
    let second = importer.dry_run(ImportSourceKindV1::Persons, &csv).unwrap();
    // `Hash32` traegt kein `Debug`; der Vergleich laeuft ueber alle 32 Bytes.
    assert_ne!(
        first.input_file_hash().as_bytes(),
        second.input_file_hash().as_bytes()
    );
    assert!(importer.commit(&first, &csv).is_err());
    assert_eq!(repo.person_count().unwrap(), 0);
    // Der UNVERAENDERTE Stand geht durch: sonst koennte die Ablehnung oben von
    // etwas anderem als dem Hashvergleich kommen.
    assert!(importer.commit(&second, &csv).is_ok());
    assert_eq!(repo.person_count().unwrap(), 1);
}

#[test]
fn retained_protocol_bytes_reproduce_the_snapshot_hash() {
    let harness = ImportHarness::new();
    let (importer, repo) = (harness.importer(), harness.master_data_repo());
    let csv = b"id,display_name,role,active\np1,Ada,Fuehrung,true\n";
    let report = importer.dry_run(ImportSourceKindV1::Persons, csv).unwrap();
    // Die Wartezeit ist TRAGEND und keine Bequemlichkeit: `commit` liest die
    // Eingabe erneut, um an die Zeilen zu kommen, und der dabei entstehende
    // zweite Bericht traegt eine andere `imported-at`-Zeit. Ohne einen
    // Millisekundenwechsel dazwischen waeren beide Kodierungen byteidentisch
    // und die Zusicherung „AUFBEWAHRT und nicht neu kodiert" liefe leer.
    std::thread::sleep(std::time::Duration::from_millis(5));
    importer.commit(&report, csv).unwrap();
    let snapshot = repo.snapshot_person("p1").unwrap();
    let hash = snapshot
        .imported_provenance()
        .unwrap()
        .import_protocol_hash();
    let retained = repo.import_report_bytes(&hash).unwrap().unwrap();
    assert_eq!(retained, report.exact_bytes());
    assert_eq!(
        ea_crypto::object_hash(&retained).as_bytes(),
        hash.as_bytes()
    );
    // Ein Hash, der nie aufbewahrt wurde, meldet ABWESENHEIT und nicht
    // irgendwelche Bytes.
    let unknown = ea_crypto::object_hash(b"kein aufbewahrtes Urbild");
    assert!(repo.import_report_bytes(&unknown).unwrap().is_none());
}

#[test]
fn csv_import_can_neither_mint_nor_carry_an_incident_number() {
    let harness = ImportHarness::new();
    let (importer, repo) = (harness.importer(), harness.master_data_repo());
    let persons = b"id,display_name,role,active\np1,Ada,Fuehrung,true\n";
    let vehicles = b"id,display_name,radio_call_sign,license_plate,active\n\
                     v1,MTW,Rotkreuz 1,HH-DRK 1,true\n";
    importer
        .commit(
            &importer
                .dry_run(ImportSourceKindV1::Persons, persons)
                .unwrap(),
            persons,
        )
        .unwrap();
    importer
        .commit(
            &importer
                .dry_run(ImportSourceKindV1::Vehicles, vehicles)
                .unwrap(),
            vehicles,
        )
        .unwrap();
    assert_eq!(harness.consumed_incident_number_count(), 0);
    assert_eq!(
        CsvImporter::ACCEPTED_HEADERS,
        [
            "id,display_name,role,active",
            "id,display_name,radio_call_sign,license_plate,active"
        ]
    );
    assert_eq!(repo.person_count().unwrap(), 1);
    assert_eq!(repo.vehicle_count().unwrap(), 1);
}

#[test]
fn a_header_carrying_an_incident_number_column_is_not_an_accepted_header() {
    // Die negative Zusage strukturell und nicht bloss gezaehlt: die einzigen
    // zwei akzeptierten Kopfzeilen nennen keine Einsatznummernspalte, und eine
    // dritte Kopfzeile existiert nicht.
    let harness = ImportHarness::new();
    let importer = harness.importer();
    for header in CsvImporter::ACCEPTED_HEADERS {
        assert!(
            !header.contains("incident"),
            "eine akzeptierte Kopfzeile nennt eine Einsatznummernspalte: {header}"
        );
    }
    let smuggled = b"id,display_name,role,active,incident_number\n\
                     p1,Ada,Fuehrung,true,2026-0001\n";
    assert!(matches!(
        importer
            .dry_run(ImportSourceKindV1::Persons, smuggled)
            .unwrap_err(),
        ImportError::UnknownHeader { .. }
    ));
    assert_eq!(harness.consumed_incident_number_count(), 0);
}

#[test]
fn every_documented_rejection_carries_its_pinned_issue_code() {
    let harness = ImportHarness::new();
    let importer = harness.importer();
    let cases: [(&[u8], u32); 5] = [
        (
            b"\xef\xbb\xbfid,display_name,role,active\np1,Ada,Fuehrung,true\n",
            0,
        ),
        (b"id,display_name,role,active\np1,Ada,\xffX,true\n", 1),
        (b"id,name,role,active\np1,Ada,Fuehrung,true\n", 2),
        (b"id,display_name,role,role\np1,Ada,Fuehrung,true\n", 3),
        (
            b"\x00\x01\x00\x00Standard Jet DB\x00id,display_name,role,active\n",
            4,
        ),
    ];
    for (input, expected) in cases {
        let error = importer
            .dry_run(ImportSourceKindV1::Persons, input)
            .unwrap_err();
        assert_eq!(
            error.issue_code().unwrap() as u32,
            expected,
            "die Ablehnung traegt einen anderen Code als den gepinnten: {}",
            error.code()
        );
    }
}

#[test]
fn a_row_level_violation_stays_inside_the_report_and_carries_its_column() {
    let harness = ImportHarness::new();
    let (importer, repo) = (harness.importer(), harness.master_data_repo());
    let csv = b"id,display_name,role,active\n\
                p1,Ada,Fuehrung,vielleicht\n\
                p1,Bob,Fuehrung,true\n\
                ,Cid,Fuehrung,true\n\
                p4,Dora,Fuehrung,false\n\
                \n";
    let report = importer.dry_run(ImportSourceKindV1::Persons, csv).unwrap();
    let wire: Vec<(u64, Option<&str>, u32)> = report
        .errors_on_the_wire()
        .iter()
        .map(|issue| (issue.row(), issue.column(), issue.code() as u32))
        .collect();
    assert_eq!(
        wire,
        vec![
            (1, Some("active"), 7),
            (2, Some("id"), 8),
            (3, Some("id"), 6),
        ]
    );
    let warnings: Vec<(u64, Option<&str>, u32)> = report
        .warnings()
        .iter()
        .map(|issue| (issue.row(), issue.column(), issue.code() as u32))
        .collect();
    assert_eq!(warnings, vec![(4, Some("active"), 11), (5, None, 12)]);
    assert_eq!(
        (
            report.total(),
            report.accepted(),
            report.rejected(),
            report.errors().len()
        ),
        (4, 1, 3, 3)
    );
    // Ein Bericht mit Fehlern wird nie gebucht — auch nicht teilweise.
    assert!(importer.commit(&report, csv).is_err());
    assert_eq!(repo.person_count().unwrap(), 0);
}

#[test]
fn a_field_count_mismatch_is_a_row_error_and_not_a_file_rejection() {
    let harness = ImportHarness::new();
    let importer = harness.importer();
    let csv = b"id,display_name,role,active\np1,Ada,Fuehrung\n";
    let report = importer.dry_run(ImportSourceKindV1::Persons, csv).unwrap();
    let wire: Vec<(u64, Option<&str>, u32)> = report
        .errors_on_the_wire()
        .iter()
        .map(|issue| (issue.row(), issue.column(), issue.code() as u32))
        .collect();
    assert_eq!(wire, vec![(1, None, 5)]);
}

#[test]
fn a_value_beyond_the_documented_length_is_rejected_with_its_own_code() {
    let harness = ImportHarness::new();
    let importer = harness.importer();
    let mut csv = b"id,display_name,role,active\np1,".to_vec();
    csv.extend(std::iter::repeat_n(b'A', CsvImporter::MAX_FIELD_CHARS + 1));
    csv.extend_from_slice(b",Fuehrung,true\n");
    let report = importer.dry_run(ImportSourceKindV1::Persons, &csv).unwrap();
    let wire: Vec<(u64, Option<&str>, u32)> = report
        .errors_on_the_wire()
        .iter()
        .map(|issue| (issue.row(), issue.column(), issue.code() as u32))
        .collect();
    assert_eq!(wire, vec![(1, Some("display_name"), 10)]);
}

#[test]
fn a_second_import_that_collides_mid_transaction_writes_no_row_at_all() {
    // DAS ist die Zusage „alles oder nichts": die Ablehnung faellt MITTEN in
    // der Transaktion, nachdem das Urbild und eine Stammdatenzeile schon
    // eingefuegt sind. Ohne eine echte Transaktion stuende danach `n2` in der
    // Tabelle und das Urbild des zweiten Imports daneben.
    let harness = ImportHarness::new();
    let (importer, repo) = (harness.importer(), harness.master_data_repo());
    let first = b"id,display_name,role,active\np1,Ada,Fuehrung,true\n";
    importer
        .commit(
            &importer
                .dry_run(ImportSourceKindV1::Persons, first)
                .unwrap(),
            first,
        )
        .unwrap();
    assert_eq!(repo.person_count().unwrap(), 1);

    let second = b"id,display_name,role,active\n\
                   n2,Neu,Fuehrung,true\n\
                   p1,Kollision,Fuehrung,true\n";
    let report = importer
        .dry_run(ImportSourceKindV1::Persons, second)
        .unwrap();
    assert_eq!(report.accepted(), 2);
    assert!(importer.commit(&report, second).is_err());
    assert_eq!(repo.person_count().unwrap(), 1);
    assert!(
        repo.import_report_bytes(&report.import_protocol_hash())
            .unwrap()
            .is_none(),
        "das Urbild des zurueckgerollten Imports darf nicht liegenbleiben"
    );
}

#[test]
fn the_accepted_headers_are_indexed_by_the_source_kind_discriminant() {
    // Ohne diese Zusicherung koennten Konstantenreihenfolge und
    // Aufzaehlungsreihenfolge auseinanderlaufen, und der Importeur pruefte die
    // Personenkopfzeile gegen eine Fahrzeugdatei.
    for kind in ImportSourceKindV1::ALL {
        assert_eq!(
            CsvImporter::ACCEPTED_HEADERS[kind.code() as usize],
            kind.header_line()
        );
    }
    assert_eq!(
        CsvImporter::ACCEPTED_HEADERS.len(),
        ImportSourceKindV1::ALL.len()
    );
}

#[test]
fn an_input_beyond_the_documented_limit_is_refused_before_it_is_parsed() {
    let harness = ImportHarness::new();
    let importer = harness.importer();
    let mut csv = b"id,display_name,role,active\n".to_vec();
    csv.resize(CsvImporter::MAX_INPUT_BYTES + 1, b'x');
    assert_eq!(
        importer
            .dry_run(ImportSourceKindV1::Persons, &csv)
            .unwrap_err()
            .code(),
        ImportError::InputTooLarge.code()
    );
}

#[test]
fn a_forged_report_over_the_same_bytes_is_refused() {
    // Der Eingabehash deckt die BYTES ab und nicht den Bericht. Ein Aufrufer
    // kann `ImportReportV1::new` selbst rufen und einen Bericht mit erfundenen
    // Zaehlern ueber denselben Bytes bauen; erst der Abgleich in `commit`
    // schliesst ihn aus.
    let harness = ImportHarness::new();
    let (importer, repo) = (harness.importer(), harness.master_data_repo());
    let csv = b"id,display_name,role,active\np1,Ada,Fuehrung,true\n";
    let honest = importer.dry_run(ImportSourceKindV1::Persons, csv).unwrap();
    let forged = ImportReportV1::new(ImportReportFieldsV1 {
        source_kind: ImportSourceKindV1::Persons,
        source_format_version: 1,
        input_file_hash: honest.input_file_hash(),
        header_line: ImportSourceKindV1::Persons.header_line().to_owned(),
        imported_at: honest.imported_at(),
        row_count_total: 0,
        row_count_accepted: 0,
        row_count_rejected: 0,
        warnings: Vec::new(),
        errors: Vec::new(),
    })
    .unwrap();
    assert_eq!(
        importer.commit(&forged, csv).unwrap_err().code(),
        ImportError::ReportMismatch.code()
    );
    assert_eq!(repo.person_count().unwrap(), 0);
    assert!(
        repo.import_report_bytes(&forged.import_protocol_hash())
            .unwrap()
            .is_none()
    );

    // Die Fassung des Quellformats deckt dieser Abgleich NICHT ab: `commit`
    // vergleicht Zaehler und Befundlisten. Sie ist deshalb im Konstruktor
    // gepinnt — ein Bericht mit einer erfundenen `sourceFormatVersion` entsteht
    // gar nicht und kann darum nicht in die von Task 11 versiegelte
    // `ImportedProvenanceV1` gelangen.
    assert!(
        ImportReportV1::new(ImportReportFieldsV1 {
            source_kind: ImportSourceKindV1::Persons,
            source_format_version: 7,
            input_file_hash: honest.input_file_hash(),
            header_line: ImportSourceKindV1::Persons.header_line().to_owned(),
            imported_at: honest.imported_at(),
            row_count_total: honest.total(),
            row_count_accepted: honest.accepted(),
            row_count_rejected: honest.rejected(),
            warnings: Vec::new(),
            errors: Vec::new(),
        })
        .is_err(),
        "eine andere Quellformatfassung als 1 ist nicht buchbar, weil sie nicht baubar ist"
    );
}

#[test]
fn a_quoted_field_with_a_comma_fails_closed_instead_of_splitting_wrong() {
    // Anfuehrungszeichen nach RFC 4180 werden nicht ausgewertet. Die Zusage ist
    // deshalb nicht „es funktioniert", sondern „es faellt auf": eine maskierte
    // Zeile wird als Zeile mit falscher Feldzahl abgelehnt und nicht mit einem
    // halb zerlegten Anzeigenamen gebucht.
    let harness = ImportHarness::new();
    let (importer, repo) = (harness.importer(), harness.master_data_repo());
    let csv = b"id,display_name,role,active\np1,\"Lovelace, Ada\",Fuehrung,true\n";
    let report = importer.dry_run(ImportSourceKindV1::Persons, csv).unwrap();
    let wire: Vec<(u64, Option<&str>, u32)> = report
        .errors_on_the_wire()
        .iter()
        .map(|issue| (issue.row(), issue.column(), issue.code() as u32))
        .collect();
    assert_eq!(wire, vec![(1, None, 5)]);
    assert_eq!(report.accepted(), 0);
    assert!(importer.commit(&report, csv).is_err());
    assert_eq!(repo.person_count().unwrap(), 0);
}
