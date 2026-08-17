use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

/// Die sechs Vektorfamilien, die Stufe 1 verlangt — lexikografisch, damit der
/// Bericht und die Fehlerzeile byteidentisch reproduzierbar bleiben.
const STAGE_ONE_FAMILIES: [&str; 6] = [
    "crypto", "evidence", "format", "grants", "receipts", "trust",
];

/// Die vier Fuzz-Ziele, die die fuenf Flaechen aus `design.md` §22.1 abdecken —
/// lexikografisch, weil der Gate sie aus einem `BTreeSet` liefert.
const STAGE_ONE_FUZZ_TARGETS: [&str; 4] =
    ["cbor_object", "cose_sign1", "hpke_grant", "object_bounds"];

/// Legt ein frisches Fixture-Wurzelverzeichnis unter `std::env::temp_dir()` an.
///
/// Der Gate liest sonst den echten Arbeitsbaum. Ein Test, der einen
/// FEHLERzustand festhaelt, wuerde dort invertieren, sobald ein spaeterer Task
/// die Vektorfamilien nachliefert. Gegen ein Fixture bleibt er stabil.
///
/// Das Fixture bringt ein vollstaendiges Fuzz-Manifest sowie das eingecheckte
/// Formatpaket und den eingecheckten Gate-Bericht mit, damit jeder Test, der
/// einen ANDEREN Fehlerzustand festhaelt, nicht an der Fuzz- oder
/// Dokumentpruefung haengt.
fn fixture_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "ea-stage-gate-{label}-{}-{nanos}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("vectors")).unwrap();
    write_fuzz_manifest(&root, &STAGE_ONE_FUZZ_TARGETS);
    copy_from_the_workspace(&root, FORMAT_PACKAGE_PATH);
    copy_from_the_workspace(&root, GATE_REPORT_PATH);
    root
}

/// Kopiert eine eingecheckte Datei an dieselbe relative Stelle im Fixture.
fn copy_from_the_workspace(root: &Path, relative: &str) {
    let target = root.join(relative);
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::copy(workspace_root().join(relative), &target)
        .unwrap_or_else(|error| panic!("{relative} must be readable: {error}"));
}

/// Schreibt ein Fuzz-Manifest, das genau die genannten Ziele deklariert.
fn write_fuzz_manifest(root: &Path, targets: &[&str]) {
    let path = root.join("fuzz/Cargo.toml");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut text = String::from("[package]\nname = \"ea-fuzz\"\nversion = \"0.0.0\"\n");
    for target in targets {
        text.push_str(&format!(
            "\n[[bin]]\nname = \"{target}\"\npath = \"fuzz_targets/{target}.rs\"\n\
             test = false\ndoc = false\nbench = false\n"
        ));
    }
    fs::write(&path, text).unwrap();
}

/// Kopfzeile des Requirement-Ledgers — jedes Feld ist gequotet, wie der
/// Spaltenvertrag es verlangt.
const LEDGER_HEADER: &str = concat!(
    r#""requirement_id","version","source","title","primary_acceptance_criterion","#,
    r#""related_acceptance_criteria","evidence","stage","status""#
);

/// Die Pflichtidentifikatoren, die das Fixture-Designdokument aufzaehlt.
///
/// Bewusst synthetisch und winzig: der Gate leitet die Menge aus dem Dokument
/// ab, und ein Fixture haelt den Fehlerzustand ueber die gesamte Taskkette
/// stabil. Dass der Parser den ECHTEN Entwurf richtig liest, pinnt der
/// Unit-Test in `tools/xtask/src/main.rs`.
const FIXTURE_IDENTIFIERS: [(&str, &str); 8] = [
    ("AK-01", "1"),
    ("AK-02", "2"),
    ("AK-03", "3"),
    ("FR-001", ""),
    ("FR-002", ""),
    ("GATE-21", ""),
    ("GATE-22", ""),
    ("GATE-25", ""),
];

/// Schreibt ein synthetisches Designdokument mit genau drei Abnahmekriterien
/// und genau zwei funktionalen Anforderungen.
///
/// Das Dokument enthaelt absichtlich eine nummerierte Liste in Abschnitt 24 und
/// eine `FR-`-Zeile in Abschnitt 27.2. Beide duerfen NICHT in die
/// Pflichtzeilenmenge geraten.
fn write_design_document(root: &Path) {
    let path = root.join("docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        "# Fixture\n\
         \n\
         ## 23. Abnahmekriterien\n\
         \n\
         1. **Erstes Kriterium:** Text.\n\
         2. **Zweites Kriterium:** Text.\n\
         3. **Drittes Kriterium:** Text.\n\
         \n\
         ## 24. Interne Lieferstufen\n\
         \n\
         1. **Vertrauenskern und Format:** zaehlt nicht als Abnahmekriterium.\n\
         \n\
         ### 27.1 Funktionale Anforderungen\n\
         \n\
         | PRD-ID | Kurzanforderung | Normative Spec | Nachweis |\n\
         |---|---|---|---|\n\
         | FR-001 | erste Anforderung | 8.5 | AK 1 |\n\
         | FR-002 | zweite Anforderung | 6 | AK 2 |\n\
         \n\
         ### 27.2 Nichtfunktionale Anforderungen\n\
         \n\
         | PRD-ID | Kurzanforderung | Normative Spec | Nachweis |\n\
         |---|---|---|---|\n\
         | FR-900 | zaehlt nicht als Pflichtzeile | 20 | AK 3 |\n",
    )
    .unwrap();
}

fn ledger_row(identifier: &str, primary: &str, evidence: &str, status: &str) -> String {
    format!(
        "\"{identifier}\",\"v1\",\"design.md 23\",\"Titel {identifier}\",\"{primary}\",\"\",\
         \"{evidence}\",\"1\",\"{status}\""
    )
}

/// Baut ein Ledger, das jede Pflichtzeile abdeckt, und laesst den Aufrufer
/// genau eine Zeile ersetzen oder streichen.
fn ledger(edit: impl Fn(&str, String) -> Option<String>) -> String {
    let mut text = String::from(LEDGER_HEADER);
    text.push('\n');
    for (identifier, primary) in FIXTURE_IDENTIFIERS {
        let row = ledger_row(identifier, primary, "xtask stage-gate 1", "planned");
        if let Some(row) = edit(identifier, row) {
            text.push_str(&row);
            text.push('\n');
        }
    }
    text
}

fn write_ledger(root: &Path, text: &str) {
    let path = root.join("docs/traceability/v0.1-requirements.csv");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, text).unwrap();
}

fn write_family_manifest(root: &Path, family: &str) {
    let directory = root.join("vectors").join(family);
    fs::create_dir_all(&directory).unwrap();
    fs::write(
        directory.join("manifest.json"),
        format!("{{\"family\":\"{family}\"}}\n"),
    )
    .unwrap();
}

fn run_stage_gate(root: &Path, stage: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["stage-gate", stage])
        .env("EA_STAGE_GATE_ROOT", root)
        .output()
        .expect("xtask stage-gate must start")
}

#[test]
fn stage_one_gate_requires_every_vector_family() {
    // Phase 1: keine einzige Familie — der Gate nennt alle sechs namentlich.
    let root = fixture_root("empty");
    let output = run_stage_gate(&root, "1");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "stage-gate 1 must exit 2 over an empty vectors directory; stderr: {stderr}"
    );
    for family in STAGE_ONE_FAMILIES {
        assert!(
            stderr.contains(family),
            "stage-gate 1 must name the missing vector family {family}; stderr: {stderr}"
        );
    }

    // Phase 2: fuenf Familien vorhanden — nur die sechste wird genannt. Eine
    // Verzeichnisexistenzpruefung reichte nicht: `vectors/format/payload-v1/`
    // existiert im echten Baum ohne `manifest.json`.
    let root = fixture_root("partial");
    for family in STAGE_ONE_FAMILIES {
        if family != "grants" {
            write_family_manifest(&root, family);
        }
    }
    fs::create_dir_all(root.join("vectors/grants/payload-v1")).unwrap();
    // Die Vektorpruefung laeuft VOR der Ledgerpruefung; das vollstaendige
    // Ledger stellt sicher, dass Phase 3 an der Vektorlage haengt, nicht an
    // einer fehlenden Nachweiszeile.
    write_design_document(&root);
    write_ledger(&root, &ledger(|_, row| Some(row)));
    let output = run_stage_gate(&root, "1");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "a vector family directory without manifest.json must not satisfy the gate; \
         stderr: {stderr}"
    );
    assert!(
        stderr.contains("grants"),
        "stage-gate 1 must name grants as the missing family; stderr: {stderr}"
    );
    for family in STAGE_ONE_FAMILIES {
        if family != "grants" {
            assert!(
                !stderr.contains(family),
                "stage-gate 1 must not report the present family {family}; stderr: {stderr}"
            );
        }
    }

    // Phase 3: alle sechs Familien vorhanden — deterministischer JSON-Bericht.
    write_family_manifest(&root, "grants");
    let output = run_stage_gate(&root, "1");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        output.status.success(),
        "stage-gate 1 must succeed once every family carries a manifest; stderr: {stderr}"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let report: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("stdout must be JSON: {error}; stdout: {stdout}"));
    assert_eq!(report["stage"], serde_json::json!(1));
    assert_eq!(
        report["vector_families"],
        serde_json::json!(STAGE_ONE_FAMILIES)
    );
    assert_eq!(
        report["primary_acceptance_criteria"],
        serde_json::json!([4, 5, 6, 9, 14, 16, 17, 20, 38, 51])
    );
    assert_eq!(
        report["rows"],
        serde_json::json!(
            FIXTURE_IDENTIFIERS
                .iter()
                .map(|(identifier, _)| *identifier)
                .collect::<Vec<_>>()
        )
    );
    assert_eq!(
        report["evidenced_acceptance_criteria"],
        serde_json::json!([])
    );
    assert_eq!(
        report["fuzz_targets"],
        serde_json::json!(STAGE_ONE_FUZZ_TARGETS)
    );
    let repeated = run_stage_gate(&root, "1");
    assert_eq!(
        String::from_utf8(repeated.stdout).unwrap(),
        stdout,
        "the stage gate report must be byte-identical across runs"
    );
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn stage_one_gate_requires_a_complete_requirement_ledger() {
    let root = fixture_root("ledger");
    for family in STAGE_ONE_FAMILIES {
        write_family_manifest(&root, family);
    }
    write_design_document(&root);

    // Phase 1: kein Ledger. Der Gate nennt JEDEN Pflichtidentifikator einzeln,
    // statt einen Datei-IO-Fehler zu melden.
    let output = run_stage_gate(&root, "1");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "stage-gate 1 must exit 2 without a requirement ledger; stderr: {stderr}"
    );
    for (identifier, _) in FIXTURE_IDENTIFIERS {
        assert!(
            stderr.contains(identifier),
            "stage-gate 1 must name the uncovered identifier {identifier}; stderr: {stderr}"
        );
    }

    // Phase 2: genau eine Pflichtzeile fehlt — nur sie wird genannt.
    write_ledger(
        &root,
        &ledger(|identifier, row| (identifier != "AK-02").then_some(row)),
    );
    let output = run_stage_gate(&root, "1");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "a ledger missing AK-02 must not satisfy the gate; stderr: {stderr}"
    );
    assert!(
        stderr.contains("AK-02"),
        "stage-gate 1 must name the uncovered identifier AK-02; stderr: {stderr}"
    );
    for (identifier, _) in FIXTURE_IDENTIFIERS {
        if identifier != "AK-02" {
            assert!(
                !stderr.contains(identifier),
                "stage-gate 1 must not report the covered identifier {identifier}; \
                 stderr: {stderr}"
            );
        }
    }

    // Phase 3: eine Zeile traegt eine Spalte zu wenig.
    write_ledger(
        &root,
        &ledger(|identifier, row| {
            Some(if identifier == "FR-001" {
                row.rsplit_once(',').unwrap().0.to_owned()
            } else {
                row
            })
        }),
    );
    let output = run_stage_gate(&root, "1");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "a row with eight columns must not satisfy the gate; stderr: {stderr}"
    );
    assert!(
        stderr.contains('8') && stderr.contains('9'),
        "the gate must report the declared and the observed column count; stderr: {stderr}"
    );

    // Phase 4: `evidence` ist leer — die Zeile ist unvollstaendig.
    write_ledger(
        &root,
        &ledger(|identifier, row| {
            Some(if identifier == "GATE-22" {
                ledger_row(identifier, "", "", "planned")
            } else {
                row
            })
        }),
    );
    let output = run_stage_gate(&root, "1");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "a row without evidence must not satisfy the gate; stderr: {stderr}"
    );
    assert!(
        stderr.contains("GATE-22") && stderr.contains("evidence"),
        "the gate must name the incomplete row and the empty column; stderr: {stderr}"
    );

    // Phase 5: `status` liegt ausserhalb des erlaubten Vokabulars.
    write_ledger(
        &root,
        &ledger(|identifier, row| {
            Some(if identifier == "AK-03" {
                ledger_row(identifier, "3", "xtask stage-gate 1", "done")
            } else {
                row
            })
        }),
    );
    let output = run_stage_gate(&root, "1");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "an unknown status must not satisfy the gate; stderr: {stderr}"
    );
    assert!(
        stderr.contains("AK-03") && stderr.contains("done"),
        "the gate must name the row and the rejected status; stderr: {stderr}"
    );

    // Phase 6: die Zeilen stehen nicht nach `requirement_id` sortiert.
    let complete = ledger(|_, row| Some(row));
    let mut rows: Vec<String> = complete.lines().skip(1).map(str::to_owned).collect();
    rows.swap(0, 1);
    let mut unsorted = String::from(LEDGER_HEADER);
    unsorted.push('\n');
    for row in &rows {
        unsorted.push_str(row);
        unsorted.push('\n');
    }
    write_ledger(&root, &unsorted);
    let output = run_stage_gate(&root, "1");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "an unsorted ledger must not satisfy the gate; stderr: {stderr}"
    );
    assert!(
        stderr.contains("sorted"),
        "the gate must report the broken sort order; stderr: {stderr}"
    );

    // Phase 7: vollstaendiges Ledger — deterministischer JSON-Bericht.
    //
    // Zwei Zeilen tragen einen belegten Status, damit
    // `evidenced_acceptance_criteria` in dem Zustand geprueft wird, auf den es
    // ankommt: der Bericht MUSS ihre Abnahmekriterien nennen und die dritte,
    // nur geplante Zeile weglassen.
    write_ledger(
        &root,
        &ledger(|identifier, row| {
            Some(match identifier {
                "AK-01" => ledger_row(identifier, "1", "xtask stage-gate 1", "implemented"),
                "AK-03" => ledger_row(identifier, "3", "xtask stage-gate 1", "integrated"),
                _ => row,
            })
        }),
    );
    let output = run_stage_gate(&root, "1");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        output.status.success(),
        "stage-gate 1 must succeed over a complete ledger; stderr: {stderr}"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let report: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("stdout must be JSON: {error}; stdout: {stdout}"));
    assert_eq!(
        report["rows"],
        serde_json::json!(
            FIXTURE_IDENTIFIERS
                .iter()
                .map(|(identifier, _)| *identifier)
                .collect::<Vec<_>>()
        )
    );
    assert_eq!(
        report["primary_acceptance_criteria"],
        serde_json::json!([4, 5, 6, 9, 14, 16, 17, 20, 38, 51])
    );
    assert_eq!(
        report["evidenced_acceptance_criteria"],
        serde_json::json!([1, 3]),
        "only implemented and integrated rows may count as evidence; stdout: {stdout}"
    );
    let repeated = run_stage_gate(&root, "1");
    assert_eq!(
        String::from_utf8(repeated.stdout).unwrap(),
        stdout,
        "the stage gate report must be byte-identical across runs"
    );
    fs::remove_dir_all(&root).unwrap();
}

/// Die sieben MUSS-Anforderungen des Web-Reader-Specs, in der Reihenfolge, in
/// der das Ledger sie fuehrt: Identifikator, Abschnitt der Normativquelle und
/// die Stufe, in der die Anforderung faellig wird.
///
/// Entscheidung D3 vom 2026-08-17: der Spec ist eine freigegebene
/// Normativquelle, seine MUSS-Saetze werden als `v1.1`-Zeilen gefuehrt.
const WEB_READER_MUST_ROWS: [(&str, &str, &str); 7] = [
    ("WR-041", "4.1", "3"),
    ("WR-042", "4.2", "3"),
    ("WR-043", "4.3", "3"),
    ("WR-052", "5.2", "4"),
    ("WR-063", "6.3", "4"),
    ("WR-075", "7.5", "5"),
    ("WR-082", "8.2", "4"),
];

/// Wurzel des echten Arbeitsbaums, von `tools/xtask` aus gerechnet.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("the workspace root must be reachable from tools/xtask")
}

/// Zerlegt eine Ledger-Zeile in ihre gequoteten Felder.
///
/// Bewusst simpel: das eingecheckte Ledger fuehrt KEIN Anfuehrungszeichen im
/// Freitext. Die Zusicherung steht als Assertion drin, damit ein spaeterer
/// Eintrag mit maskiertem Anfuehrungszeichen hier laut wird statt still eine
/// Spalte zu verschieben.
fn ledger_fields(line: &str) -> Vec<String> {
    let inner = line
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or_else(|| panic!("every ledger field must be quoted: {line}"));
    let fields: Vec<String> = inner.split("\",\"").map(str::to_owned).collect();
    assert_eq!(
        fields.len(),
        9,
        "every ledger row carries nine fields: {line}"
    );
    for value in &fields {
        assert!(
            !value.contains('"'),
            "the checked-in ledger must not carry a double quote inside a field: {line}"
        );
    }
    fields
}

/// Haelt die volle abgeleitete Identifikatormenge des ECHTEN Entwurfs gegen das
/// ECHTE Requirement-Ledger.
///
/// Der Gate laeuft gegen ein Fixture, das die sechs Vektormanifeste synthetisch
/// mitbringt und `design.md` sowie das Ledger aus dem Arbeitsbaum kopiert. Ein
/// zweiter Lauf gegen den echten Arbeitsbaum wuerde an den noch fehlenden
/// Vektorfamilien haengen und in Task 7 invertieren.
///
/// Die Zaehlungen sind auf `version` = `v1` eingeschraenkt: Task 6 nimmt sieben
/// v1.1-Zeilen des Web-Reader-Specs auf, und eine blanke Praefixzaehlung wuerde
/// dort rot werden, ohne dass sich am Vertrag dieses Tasks etwas aendert.
#[test]
fn stage_one_gate_covers_every_functional_requirement_and_acceptance_criterion() {
    let workspace = workspace_root();
    let ledger_relative = Path::new("docs/traceability/v0.1-requirements.csv");
    let design_relative =
        Path::new("docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md");

    let root = fixture_root("real-ledger");
    for family in STAGE_ONE_FAMILIES {
        write_family_manifest(&root, family);
    }
    for relative in [design_relative, ledger_relative] {
        let target = root.join(relative);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::copy(workspace.join(relative), &target)
            .unwrap_or_else(|error| panic!("{} must be readable: {error}", relative.display()));
    }

    let output = run_stage_gate(&root, "1");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        output.status.success(),
        "the checked-in requirement ledger must cover every derived identifier; stderr: {stderr}"
    );

    let text = fs::read_to_string(workspace.join(ledger_relative)).unwrap();
    let rows: Vec<Vec<String>> = text
        .lines()
        .skip(1)
        .filter(|line| !line.is_empty())
        .map(ledger_fields)
        .collect();
    let version_one: Vec<&Vec<String>> = rows.iter().filter(|row| row[1] == "v1").collect();
    for (prefix, expected) in [("FR-", 69_usize), ("AK-", 54), ("GATE-", 3)] {
        let found = version_one
            .iter()
            .filter(|row| row[0].starts_with(prefix))
            .count();
        assert_eq!(
            found, expected,
            "the ledger must carry exactly {expected} v1 rows starting with {prefix}, found {found}"
        );
    }

    let gate_twenty_two = version_one
        .iter()
        .find(|row| row[0] == "GATE-22")
        .expect("the ledger must carry GATE-22");
    assert_eq!(
        gate_twenty_two[8], "implemented",
        "GATE-22 turns implemented once every fuzz surface from 22.1 carries a target"
    );
    for target in STAGE_ONE_FUZZ_TARGETS {
        assert!(
            gate_twenty_two[6].contains(target),
            "GATE-22 evidence must name the fuzz target {target}; evidence: {}",
            gate_twenty_two[6]
        );
    }

    fs::remove_dir_all(&root).unwrap();
}

/// Haelt Entscheidung D3 fest: die sieben MUSS-Anforderungen des
/// Web-Reader-Specs stehen als `v1.1`-Zeilen im Ledger, und die beiden durch
/// den Spec ueberholten Zeilen FR-100 und FR-103 in `design.md` §27.1 tragen
/// die nachgezogene Rollen- und Speicheraufteilung.
///
/// Der Test liest den ECHTEN Arbeitsbaum und haelt einen ZIELzustand fest, kein
/// Fehlerbild: er kann durch spaetere Tasks nicht invertieren.
#[test]
fn web_reader_must_requirements_are_recorded_as_v1_1_rows() {
    let workspace = workspace_root();
    let ledger = fs::read_to_string(workspace.join("docs/traceability/v0.1-requirements.csv"))
        .expect("the requirement ledger must be readable");
    let rows: Vec<Vec<String>> = ledger
        .lines()
        .skip(1)
        .filter(|line| !line.is_empty())
        .map(ledger_fields)
        .collect();

    for (identifier, section, stage) in WEB_READER_MUST_ROWS {
        let row = rows
            .iter()
            .find(|row| row[0] == identifier)
            .unwrap_or_else(|| {
                panic!("missing v1.1 ledger row for {identifier} (web-reader-design.md §{section})")
            });
        assert_eq!(
            row[1], "v1.1",
            "{identifier} must carry version v1.1, found {}",
            row[1]
        );
        assert!(
            row[2].contains("2026-08-15-einsatzarchiv-web-reader-design.md")
                && row[2].ends_with(section),
            "{identifier} must cite the web reader spec section {section}; source: {}",
            row[2]
        );
        assert!(
            !row[3].is_empty(),
            "{identifier} must carry a title; row: {row:?}"
        );
        assert_eq!(
            row[7], stage,
            "{identifier} becomes due in stage {stage}, found {}",
            row[7]
        );
        assert_eq!(
            row[8], "planned",
            "{identifier} must stay planned until its stage delivers it, found {}",
            row[8]
        );
    }

    // D2 traegt WR-042: das Traegerfeld existiert bereits, der positive Vektor
    // folgt in Task 10 dieses Plans.
    let refresh = rows
        .iter()
        .find(|row| row[0] == "WR-042")
        .expect("WR-042 must exist");
    assert!(
        refresh[6].contains("reader-trust-refresh-ms") && refresh[6].contains("Task 10"),
        "WR-042 evidence must name the policy field and the vector task; evidence: {}",
        refresh[6]
    );

    // D1 traegt WR-075: die 2-of-N-Familie entsteht in Stufe 5,
    // `organizationAdminAuthorization` bleibt unveraendert.
    let ceremony = rows
        .iter()
        .find(|row| row[0] == "WR-075")
        .expect("WR-075 must exist");
    assert!(
        ceremony[6].contains("organizationAdminAuthorization") && ceremony[6].contains("2-of-N"),
        "WR-075 evidence must record decision D1; evidence: {}",
        ceremony[6]
    );

    // Teil B: FR-100 und FR-103 in `design.md` §27.1.
    let design = fs::read_to_string(
        workspace.join("docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md"),
    )
    .expect("the design document must be readable");
    let start = design
        .find("\n### 27.1 Funktionale Anforderungen\n")
        .expect("design.md must carry section 27.1");
    let tail = &design[start..];
    let end = tail
        .find("\n### 27.2 Nichtfunktionale Anforderungen\n")
        .expect("design.md must carry section 27.2");
    let functional = &tail[..end];
    let functional_rows: Vec<&str> = functional
        .lines()
        .filter(|line| line.starts_with("| FR-"))
        .collect();
    assert_eq!(
        functional_rows.len(),
        69,
        "section 27.1 must keep exactly 69 functional requirement rows"
    );

    let hundred = functional_rows
        .iter()
        .find(|line| line.starts_with("| FR-100 |"))
        .expect("section 27.1 must carry FR-100");
    assert!(
        !hundred.contains("gemeinsame App"),
        "FR-100 must no longer claim a shared application; row: {hundred}"
    );
    for marker in [
        "Desktop",
        "Browser-Reader",
        "2026-08-15-einsatzarchiv-web-reader-design.md",
        "3",
    ] {
        assert!(
            hundred.contains(marker),
            "FR-100 must record the split roles and cite the web reader spec ({marker}); \
             row: {hundred}"
        );
    }

    let hundred_three = functional_rows
        .iter()
        .find(|line| line.starts_with("| FR-103 |"))
        .expect("section 27.1 must carry FR-103");
    assert!(
        !hundred_three.contains("Reader-Cache und Index verschlüsselt |"),
        "FR-103 must no longer describe the SQLCipher cache; row: {hundred_three}"
    );
    for marker in [
        "OPFS",
        "ChaCha20-Poly1305",
        "2026-08-15-einsatzarchiv-web-reader-design.md",
        "8.1",
    ] {
        assert!(
            hundred_three.contains(marker),
            "FR-103 must record the encrypted Rust index ({marker}); row: {hundred_three}"
        );
    }
}

/// Die fuenf Flaechen aus `design.md` §22.1 in Entwurfsreihenfolge, jeweils mit
/// dem Wort, unter dem der Entwurfstext sie fuehrt, und dem Ziel, das sie
/// abdeckt.
///
/// `object_bounds` traegt zwei Flaechen: Objektgrenzen und Ressourcenlimits
/// werden am selben Objektrahmen gemessen.
const STAGE_ONE_FUZZ_SURFACES: [(&str, &str, &str); 5] = [
    ("cbor", "CBOR", "cbor_object"),
    ("cose", "COSE", "cose_sign1"),
    ("hpke", "HPKE", "hpke_grant"),
    ("object-bounds", "Objektgrenzen", "object_bounds"),
    ("resource-limits", "Ressourcenlimits", "object_bounds"),
];

/// Haelt fest, dass `fuzz/Cargo.toml` jede der fuenf Fuzz-Flaechen aus
/// `design.md` §22.1 mit einem Ziel belegt.
///
/// Phase 1 laeuft gegen ein Fixture und haelt den FEHLERzustand fest — er
/// bleibt ueber die Taskkette stabil. Phase 2 laeuft gegen das ECHTE
/// Fuzz-Manifest und haelt den ZIELzustand fest; sie kann durch spaetere Tasks
/// nicht invertieren, weil ein spaeterer Task Ziele nur ergaenzt.
#[test]
fn stage_one_gate_requires_every_fuzz_surface_from_design_22_1() {
    let workspace = workspace_root();
    let design_relative =
        Path::new("docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md");
    let ledger_relative = Path::new("docs/traceability/v0.1-requirements.csv");

    // Der Entwurfstext ist die Quelle der Flaechenliste. Ohne diese Zusicherung
    // pruefte der Test eine selbst erfundene Menge gegen sich selbst.
    let design = fs::read_to_string(workspace.join(design_relative))
        .expect("the design document must be readable");
    let fuzzing_line = design
        .lines()
        .find(|line| line.starts_with("- Fuzzing "))
        .expect("design.md 22.1 must carry the fuzzing line");
    for (_, word, _) in STAGE_ONE_FUZZ_SURFACES {
        assert!(
            fuzzing_line.contains(word),
            "design.md 22.1 must name the fuzz surface {word}; line: {fuzzing_line}"
        );
    }

    let root = fixture_root("fuzz-surfaces");
    for family in STAGE_ONE_FAMILIES {
        write_family_manifest(&root, family);
    }
    for relative in [design_relative, ledger_relative] {
        let target = root.join(relative);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::copy(workspace.join(relative), &target)
            .unwrap_or_else(|error| panic!("{} must be readable: {error}", relative.display()));
    }

    // Phase 1: nur das CBOR-Ziel ist deklariert — der Gate nennt die erste
    // unbelegte Flaeche und das Ziel, das sie tragen muss.
    write_fuzz_manifest(&root, &["cbor_object"]);
    let output = run_stage_gate(&root, "1");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "a fuzz manifest without the COSE surface must not satisfy the gate; stderr: {stderr}"
    );
    assert!(
        stderr.contains("missing fuzz target for surface cose"),
        "the gate must name the uncovered surface and its target; stderr: {stderr}"
    );

    // Phase 2: das ECHTE Fuzz-Manifest. Jede Flaeche ist belegt, der Bericht
    // nennt die Ziele und die Zuordnung.
    let fuzz_relative = Path::new("fuzz/Cargo.toml");
    fs::copy(workspace.join(fuzz_relative), root.join(fuzz_relative))
        .expect("fuzz/Cargo.toml must be readable");
    let output = run_stage_gate(&root, "1");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        output.status.success(),
        "the checked-in fuzz manifest must cover every surface from 22.1; stderr: {stderr}"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let report: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("stdout must be JSON: {error}; stdout: {stdout}"));
    assert_eq!(
        report["fuzz_targets"],
        serde_json::json!(STAGE_ONE_FUZZ_TARGETS),
        "the report must name exactly the four declared targets; stdout: {stdout}"
    );
    assert_eq!(
        report["fuzz_surfaces"],
        serde_json::json!(
            STAGE_ONE_FUZZ_SURFACES
                .iter()
                .map(|(surface, _, target)| serde_json::json!({
                    "surface": surface,
                    "target": target
                }))
                .collect::<Vec<_>>()
        ),
        "the report must carry the surface-to-target table; stdout: {stdout}"
    );
    let repeated = run_stage_gate(&root, "1");
    assert_eq!(
        String::from_utf8(repeated.stdout).unwrap(),
        stdout,
        "the stage gate report must be byte-identical across runs"
    );

    // Ein deklariertes Ziel ohne Quelldatei waere eine leere Zusage.
    for target in STAGE_ONE_FUZZ_TARGETS {
        let source = workspace.join(format!("fuzz/fuzz_targets/{target}.rs"));
        assert!(
            source.is_file(),
            "the declared fuzz target {target} must carry a source file at {}",
            source.display()
        );
    }

    fs::remove_dir_all(&root).unwrap();
}

/// Die beiden Dokumente, die Stufe 1 als oeffentliches Formatpaket und als
/// Gate-Bericht liefert — relativ zur Gate-Wurzel.
const FORMAT_PACKAGE_PATH: &str = "docs/format/README-FORMAT.txt";
const GATE_REPORT_PATH: &str = "docs/traceability/stage-1-gate.md";

/// Die zehn primaeren Abnahmekriterien der Stufe 1, die der Gate-Bericht auf
/// konkrete Belege abbilden MUSS.
const PRIMARY_ACCEPTANCE_CRITERIA: [u32; 10] = [4, 5, 6, 9, 14, 16, 17, 20, 38, 51];

/// Treibt den Gate gegen den ECHTEN Arbeitsbaum.
///
/// `env_remove` ist zwingend: eine geerbte `EA_STAGE_GATE_ROOT` wuerde den Lauf
/// still auf ein fremdes Fixture umlenken.
fn run_stage_gate_in_the_workspace(stage: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["stage-gate", stage])
        .env_remove("EA_STAGE_GATE_ROOT")
        .output()
        .expect("xtask stage-gate must start")
}

/// Baut ein Fixture, das jede fruehere Gate-Bedingung erfuellt.
///
/// Formatpaket und Gate-Bericht bringt bereits [`fixture_root`] mit; die
/// Mutationsphasen brauchen genau diesen Zustand: sie veraendern EIN Dokument
/// und halten fest, dass der Gate genau daran haengt.
fn fixture_with_the_checked_in_documents(label: &str) -> PathBuf {
    let root = fixture_root(label);
    for family in STAGE_ONE_FAMILIES {
        write_family_manifest(&root, family);
    }
    for relative in [
        "docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md",
        "docs/traceability/v0.1-requirements.csv",
        "fuzz/Cargo.toml",
    ] {
        copy_from_the_workspace(&root, relative);
    }
    root
}

/// Liest die Reichweitenklausel dort, wo sie normativ steht: im Kommentar ueber
/// dem `wasm32-unknown-unknown`-Kommando in `verify_quick_commands()`.
///
/// Der Bericht MUSS sie woertlich tragen. Die Klausel hier zu wiederholen
/// hiesse, den Bericht gegen eine zweite Abschrift zu pruefen statt gegen die
/// Quelle.
fn wasm32_scope_clause_from_the_gate_source() -> String {
    let source = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"))
        .expect("the xtask source must be readable");
    let mut clause = String::new();
    for line in source.lines() {
        let trimmed = line.trim();
        if clause.is_empty() {
            if !trimmed.starts_with("// Belegt ausschliesslich") {
                continue;
            }
        } else if !trimmed.starts_with("//") {
            break;
        }
        if !clause.is_empty() {
            clause.push(' ');
        }
        clause.push_str(trimmed.trim_start_matches('/').trim());
        if clause.ends_with("steht aus.") {
            break;
        }
    }
    assert!(
        clause.ends_with("steht aus."),
        "verify_quick_commands() must carry the wasm32 scope comment; found: {clause}"
    );
    clause
}

/// Ersetzt ein Dokument im Fixture.
fn write_document(root: &Path, relative: &str, text: &str) {
    fs::write(root.join(relative), text).unwrap();
}

/// Ueberschrift des Abschnitts, in dem der Gate-Bericht den gemessenen
/// Stufe-1-Gate-Lauf protokolliert.
const MEASURED_RUN_HEADING: &str = "## Gemessener Gate-Lauf";

/// Die acht Kommandos der Schritt-4-Folge des Stufe-1-Plans
/// (`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md`),
/// in genau der Reihenfolge, in der der Plan sie vorschreibt.
///
/// Der wasm32-Check steht mit seinem Praefix, nicht mit seiner vollen
/// Positivliste: die Belegzeile MUSS ihn nennen, soll die Liste der zehn Crates
/// aber nicht ein zweites Mal woertlich abschreiben.
const STEP_FOUR_COMMANDS: [&str; 8] = [
    "pnpm test:core",
    "pnpm test:golden",
    "pnpm test:property",
    "pnpm test:fuzz --smoke-seconds 60",
    "pnpm test:recovery",
    "cargo run --locked -p xtask -- stage-gate 1",
    "cargo check --target wasm32-unknown-unknown --locked",
    "pnpm verify:quick",
];

/// Liest die Belegzeilen des Abschnitts [`MEASURED_RUN_HEADING`] als Tabelle.
///
/// Fehlt der Abschnitt, liefert die Funktion eine leere Liste statt zu
/// panicken: sonst schluege der Test mit einer Meldung ueber die fehlende
/// Ueberschrift fehl statt mit der Meldung ueber das fehlende Kommando, und der
/// RED dieses Tasks nennte nicht mehr die Sache, um die es geht.
fn measured_run_rows(report: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut inside = false;
    for line in report.lines() {
        if line.trim_end() == MEASURED_RUN_HEADING {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        if line.starts_with("## ") {
            break;
        }
        let trimmed = line.trim();
        if !trimmed.starts_with('|') {
            continue;
        }
        let cells: Vec<String> = trimmed
            .trim_matches('|')
            .split('|')
            .map(|cell| cell.trim().to_owned())
            .collect();
        if cells.iter().all(|cell| cell.chars().all(|c| c == '-')) {
            continue;
        }
        rows.push(cells);
    }
    rows
}

/// Haelt fest, dass der Gate-Bericht den vorgeschriebenen vollen Lauf GEMESSEN
/// protokolliert statt ihn zu behaupten.
///
/// Der Test liest den ECHTEN Arbeitsbaum und haelt einen ZIELzustand fest: jede
/// der acht Kommandozeilen aus Schritt 4 des Stufe-1-Plans braucht eine eigene
/// Belegzeile mit Kommando, Exitcode und gemessenem Ergebnis. Er kann durch
/// spaetere Tasks nicht invertieren.
///
/// Die Zeile fuer `pnpm test:fuzz --smoke-seconds 60` wird VOR der Schleife
/// geprueft: sie ist die Zeile, die dieser Task ueberhaupt erst erzwingt — der
/// Fuzz-Smoke ist das einzige Kommando der Folge, das kein anderes Gate mitlaeuft.
#[test]
fn stage_one_gate_report_records_the_measured_full_gate_run() {
    let workspace = workspace_root();
    let report = fs::read_to_string(workspace.join(GATE_REPORT_PATH))
        .expect("the stage 1 gate report must be readable");
    let rows = measured_run_rows(&report);

    let fuzz = "pnpm test:fuzz --smoke-seconds 60";
    assert!(
        rows.iter().any(|row| row[0].contains(fuzz)),
        "stage-1-gate.md must record the measured run for `{fuzz}`"
    );

    for command in STEP_FOUR_COMMANDS {
        let matching: Vec<&Vec<String>> =
            rows.iter().filter(|row| row[0].contains(command)).collect();
        assert_eq!(
            matching.len(),
            1,
            "stage-1-gate.md must record the measured run for `{command}` exactly once"
        );
        let row = matching[0];
        assert!(
            row.len() >= 3,
            "the measured row for `{command}` must carry command, exit code and result: {row:?}"
        );
        assert_eq!(
            row[1], "0",
            "the measured run for `{command}` must have ended with exit code 0: {row:?}"
        );
        assert!(
            !row[2].is_empty(),
            "the measured row for `{command}` must name the measured result: {row:?}"
        );
        assert!(
            !row[2].contains("0 passed"),
            "`0 passed; N filtered out` is a broken filter, not a result: {row:?}"
        );
    }

    assert_eq!(
        rows.len(),
        STEP_FOUR_COMMANDS.len() + 1,
        "the measured run section carries one header row and one row per step 4 command: {rows:?}"
    );
    assert!(
        report.contains(MEASURED_RUN_HEADING),
        "stage-1-gate.md must carry the section {MEASURED_RUN_HEADING}"
    );
}

/// Haelt fest, dass `stage-gate 1` das Formatpaket und den Gate-Bericht prueft.
///
/// Phase 1 laeuft gegen den ECHTEN Arbeitsbaum und haelt den ZIELzustand fest —
/// sie kann durch spaetere Tasks nicht invertieren. Jede Mutationsphase laeuft
/// gegen ein Fixture und haelt einen FEHLERzustand an genau einer Stelle fest.
#[test]
fn stage_one_gate_requires_the_format_package_and_the_gate_report() {
    // Phase 1: der echte Arbeitsbaum. Beide Dokumente liegen vor, der Gate
    // beendet mit 0 und nennt die zehn primaeren Abnahmekriterien, die der
    // Bericht auf Belege abbildet.
    let output = run_stage_gate_in_the_workspace("1");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        output.status.success(),
        "stage-gate 1 must accept the checked-in format package and gate report; stderr: {stderr}"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let report: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("stdout must be JSON: {error}; stdout: {stdout}"));
    assert_eq!(
        report["format_package"],
        serde_json::json!(FORMAT_PACKAGE_PATH)
    );
    assert_eq!(report["gate_report"], serde_json::json!(GATE_REPORT_PATH));
    assert_eq!(
        report["gate_report_acceptance_criteria"],
        serde_json::json!(PRIMARY_ACCEPTANCE_CRITERIA),
        "the gate report must map every primary acceptance criterion; stdout: {stdout}"
    );

    // Phase 2: die Reichweitenklausel steht woertlich so im Bericht, wie der
    // Kommentar in `verify_quick_commands()` sie formuliert.
    let workspace = workspace_root();
    let clause = wasm32_scope_clause_from_the_gate_source();
    let report_text = fs::read_to_string(workspace.join(GATE_REPORT_PATH))
        .expect("the stage 1 gate report must be readable");
    assert!(
        report_text.contains(&clause),
        "the gate report must carry the wasm32 scope clause verbatim: {clause}"
    );

    let root = fixture_with_the_checked_in_documents("documents");
    let format_package = fs::read_to_string(workspace.join(FORMAT_PACKAGE_PATH)).unwrap();
    let gate_report = fs::read_to_string(workspace.join(GATE_REPORT_PATH)).unwrap();

    // Phase 3: kein Formatpaket.
    fs::remove_file(root.join(FORMAT_PACKAGE_PATH)).unwrap();
    let output = run_stage_gate(&root, "1");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "a missing format package must not satisfy the gate; stderr: {stderr}"
    );
    assert!(
        stderr.contains(FORMAT_PACKAGE_PATH),
        "the gate must name the missing format package; stderr: {stderr}"
    );

    // Phase 4: kein Gate-Bericht.
    write_document(&root, FORMAT_PACKAGE_PATH, &format_package);
    fs::remove_file(root.join(GATE_REPORT_PATH)).unwrap();
    let output = run_stage_gate(&root, "1");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "a missing gate report must not satisfy the gate; stderr: {stderr}"
    );
    assert!(
        stderr.contains(GATE_REPORT_PATH),
        "the gate must name the missing gate report; stderr: {stderr}"
    );

    // Phase 5: das Formatpaket behauptet allgemeine Gerichtsverwertbarkeit.
    // Verboten nach Global Constraint Zeile 27 des Stufe-1-Plans.
    write_document(&root, GATE_REPORT_PATH, &gate_report);
    write_document(
        &root,
        FORMAT_PACKAGE_PATH,
        &format!("{format_package}\nDieses Archiv ist allgemein gerichtsverwertbar.\n"),
    );
    let output = run_stage_gate(&root, "1");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "a legal overclaim must not satisfy the gate; stderr: {stderr}"
    );
    assert!(
        stderr.contains("gerichtsverwert") && stderr.contains("NICHT BEHAUPTET:"),
        "the gate must name the claimed term and the required disclaimer form; stderr: {stderr}"
    );

    // Phase 6: das Formatpaket nennt das Magic nicht mehr.
    write_document(
        &root,
        FORMAT_PACKAGE_PATH,
        &format_package.replace("h'45413100'", "h'00000000'"),
    );
    let output = run_stage_gate(&root, "1");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "a format package without the magic must not satisfy the gate; stderr: {stderr}"
    );
    assert!(
        stderr.contains("45413100"),
        "the gate must name the missing literal; stderr: {stderr}"
    );

    // Phase 7: der Bericht traegt die Reichweitenklausel nicht mehr.
    write_document(&root, FORMAT_PACKAGE_PATH, &format_package);
    write_document(
        &root,
        GATE_REPORT_PATH,
        &gate_report
            .lines()
            .filter(|line| !line.contains(&clause))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    let output = run_stage_gate(&root, "1");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "a gate report without the wasm32 scope clause must not satisfy the gate; stderr: {stderr}"
    );
    assert!(
        stderr.contains("wasm32 scope clause"),
        "the gate must report the missing scope clause; stderr: {stderr}"
    );

    // Phase 8: dem Bericht fehlt die Belegzeile fuer AK 51.
    write_document(
        &root,
        GATE_REPORT_PATH,
        &gate_report
            .lines()
            .filter(|line| !line.starts_with("| AK 51 |"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    let output = run_stage_gate(&root, "1");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "a gate report without the AK 51 row must not satisfy the gate; stderr: {stderr}"
    );
    assert!(
        stderr.contains("51"),
        "the gate must name the unmapped acceptance criterion; stderr: {stderr}"
    );

    // Phase 9: beide Dokumente unveraendert — deterministischer JSON-Bericht.
    write_document(&root, GATE_REPORT_PATH, &gate_report);
    let output = run_stage_gate(&root, "1");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        output.status.success(),
        "the checked-in documents must satisfy the gate; stderr: {stderr}"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let report: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("stdout must be JSON: {error}; stdout: {stdout}"));
    assert_eq!(
        report["gate_report_acceptance_criteria"],
        serde_json::json!(PRIMARY_ACCEPTANCE_CRITERIA)
    );
    let repeated = run_stage_gate(&root, "1");
    assert_eq!(
        String::from_utf8(repeated.stdout).unwrap(),
        stdout,
        "the stage gate report must be byte-identical across runs"
    );
    fs::remove_dir_all(&root).unwrap();
}
