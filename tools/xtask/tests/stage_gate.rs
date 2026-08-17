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

/// Legt ein frisches Fixture-Wurzelverzeichnis unter `std::env::temp_dir()` an.
///
/// Der Gate liest sonst den echten Arbeitsbaum. Ein Test, der einen
/// FEHLERzustand festhaelt, wuerde dort invertieren, sobald ein spaeterer Task
/// die Vektorfamilien nachliefert. Gegen ein Fixture bleibt er stabil.
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
    root
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
    assert_eq!(report["fuzz_targets"], serde_json::json!([]));
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
        gate_twenty_two[8], "planned",
        "GATE-22 must stay planned while only one fuzz target exists"
    );
    assert!(
        gate_twenty_two[6].contains("Task 12"),
        "GATE-22 must point at Task 12 for the missing fuzz surfaces; evidence: {}",
        gate_twenty_two[6]
    );

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
