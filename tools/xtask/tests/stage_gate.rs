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
/// der das Ledger sie fuehrt: Identifikator, Abschnitt der Normativquelle, die
/// Stufe, in der die Anforderung faellig wird, und der Status, den ihre Zeile
/// dort traegt.
///
/// Entscheidung D3 vom 2026-08-17: der Spec ist eine freigegebene
/// Normativquelle, seine MUSS-Saetze werden als `v1.1`-Zeilen gefuehrt.
///
/// Entscheidung D-HE2 vom 2026-08-18 UEBERSCHREIBT die Stufenzuordnung, die D3
/// GENAU EINER dieser Zeilen gegeben hat: `WR-052` (der universelle Datei-Weg)
/// wird von Stufe 2 geliefert und nicht von Stufe 4 — Task 12 dieses Plans
/// baut den Ein-Datei-Buendelexport, ohne ein siebtes Objektpraefix zu praegen.
/// Die Zeile wandert deshalb auf Stufe `2` und Status `integrated`. Die
/// uebrigen sechs Zeilen behalten ihre Stufe UND ihr `planned`; die
/// Erwartungsspalte ist hinzugekommen, damit diese eine Verschiebung
/// AUSGESCHRIEBEN dasteht statt die Zusicherung fuer alle sieben aufzuweichen.
/// Der geschlossene Stufe-1-Gate-Bericht (`docs/traceability/stage-1-gate.md`)
/// wird dafuer NICHT angefasst: er haelt den Stand am Stufe-1-Gate fest.
///
/// Die Stufe-3-Abnahme (Task 12) VERSCHIEBT drei dieser Zeilen und ergaenzt
/// eine vierte, und beides steht hier AUSGESCHRIEBEN, nach dem Muster, das
/// D-HE2 darueber schon verwendet:
///
/// `WR-041`, `WR-042` und `WR-043` wandern von Stufe `3` auf Stufe `4` und
/// behalten `planned`. Alle drei sind BROWSERseitig — getrennter
/// Auslieferungsursprung (web-reader-design.md:72), Service-Worker-Aktivierung
/// gegen ein gepinntes Release (:84), erzwungener Fingerprint-Vergleich
/// (:117) — und ihr Bauartefakt `apps/web` fuehrt web-reader-design.md
/// Abschnitt 12 (:467-469) ein, dessen Stufe-4-Eintrag (:454-457) die
/// Reader-Tasks schreibt. Die FAMILIENDEFINITION dagegen liefert Stufe 3.
///
/// Genau dafuer kommt EINE Zeile hinzu: `WR-042D`, Stufe `3`, `implemented`.
/// Das Schema `WR-0<Abschnitt>` kann fuer Abschnitt 4.2 keine zweite Zeile
/// ausdruecken, deshalb traegt sie ausdruecklich einen Identifikator
/// AUSSERHALB des Schemas. Die Stelligkeit geht damit von ACHT auf NEUN.
///
/// Die geschlossenen Gate-Berichte der Stufen 1 und 2 werden dafuer NICHT
/// angefasst; `docs/traceability/stage-2-gate.md:348` traegt diesen
/// Mechanismus als Praezedenz.
///
/// Der Stufe-4-Vorlauf (dieser Task) ergaenzt ZWEI weitere Zeilen,
/// `WR-053` und `WR-054`, beide Stufe `4` und `planned`: der gepinnte
/// Root-Anchor als einzige Vertrauensquelle im Datei-Modus (§5.3) und die
/// sichtbare "nicht server-bestaetigt"-Kennzeichnung ohne Cursor im
/// Datei-Modus (§5.4). Beide Zeilen entstehen HIER und nicht in der
/// Datei-Modus-Aufgabe selbst, weil `web_reader_must_requirements_are_recorded_as_v1_1_rows`
/// je Tupel eine vorhandene Ledgerzeile verlangt und die gewachsene Konstante
/// sonst rot stuende, bevor die Aufgabe laeuft, die sie einloest. Die
/// Stelligkeit geht damit von NEUN auf ELF.
///
/// Die Stufe-4-Abnahme (Aufgabe „Reader-Interoperabilitaet, Browser-Matrix,
/// Datei-Modus, Privatheit und das Stufe-4-Gate") bewegt SIEBEN Statusspalten
/// und KEIN Tupel: die Stelligkeit bleibt ELF. Ausgeschrieben, nach dem Muster
/// der Entscheidung D-HE2 weiter oben, weil jede Aenderung dieser
/// Erwartungsspalte eine Ledgerbewegung IST und nicht nur begleitet —
/// `web_reader_must_requirements_are_recorded_as_v1_1_rows` vergleicht sie mit
/// `assert_eq!` gegen die neunte Spalte der CSV-Zeile:
///
/// - `WR-041` `planned` -> `implemented` (CODE-Seite der Origin-Trennung;
///   die betriebliche Haelfte bleibt offen und steht im Gate-Bericht unter
///   `## Offen in spaeterer Stufe`)
/// - `WR-042` `planned` -> `implemented`
/// - `WR-043` `planned` -> `integrated`
/// - `WR-053` `planned` -> `integrated`
/// - `WR-054` `planned` -> `integrated`
/// - `WR-063` `planned` -> `implemented`
/// - `WR-082` `planned` -> `integrated`
///
/// `WR-042D` (Stufe 3, `implemented`), `WR-052` (Stufe 2, `integrated`),
/// `WR-064` (Stufe 3, `implemented`) und `WR-075` (Stufe 5, `planned`) bleiben
/// UNANGETASTET. Die geschlossenen Gate-Berichte der Stufen 1 bis 3 werden
/// dafuer nicht angefasst; `docs/traceability/stage-2-gate.md:348` traegt
/// diesen Mechanismus als Praezedenz.
const WEB_READER_MUST_ROWS: [(&str, &str, &str, &str); 11] = [
    ("WR-041", "4.1", "4", "implemented"),
    ("WR-042", "4.2", "4", "implemented"),
    ("WR-042D", "4.2", "3", "implemented"),
    ("WR-043", "4.3", "4", "integrated"),
    ("WR-052", "5.2", "2", "integrated"),
    ("WR-053", "5.3", "4", "integrated"),
    ("WR-054", "5.4", "4", "integrated"),
    ("WR-063", "6.3", "4", "implemented"),
    ("WR-064", "6.4", "3", "implemented"),
    ("WR-075", "7.5", "5", "planned"),
    ("WR-082", "8.2", "4", "integrated"),
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

    for (identifier, section, stage, status) in WEB_READER_MUST_ROWS {
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
            row[8], status,
            "{identifier} must carry status {status} in stage {stage}, found {}",
            row[8]
        );
    }

    // D2 traegt WR-042: das Traegerfeld existiert bereits, und sein positiver
    // Vektor ist seit Stufe 1 EINGEFROREN — nicht mehr angekuendigt. Der Pin
    // wandert deshalb mit der Ledgerverschiebung der Stufe-3-Abnahme in
    // DEMSELBEN Commit von der Ankuendigung auf den Vektornamen (Ruling R-75),
    // damit Belegspalte und Zusicherung nicht auseinanderdriften koennen.
    let refresh = rows
        .iter()
        .find(|row| row[0] == "WR-042")
        .expect("WR-042 must exist");
    assert!(
        refresh[6].contains("reader-trust-refresh-ms")
            && refresh[6].contains("accepted-policy-core-reader-trust-refresh"),
        "WR-042 evidence must name the policy field and the frozen vectors; evidence: {}",
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
/// Positivliste: die Belegzeile MUSS ihn nennen, soll die Liste der Crates aber
/// nicht ein zweites Mal woertlich abschreiben. Wie lang die Liste WAR, als der
/// Stufe-1-Lauf sie fuhr, steht im Stufe-1-Bericht und nicht hier; sie ist
/// seither gewachsen, und dieser Pin misst die Kommandofolge und nicht ihre
/// Laenge.
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

// ===========================================================================
// Stufe 2 — „Offline Writer".
//
// Fixturegetrieben wie die Stufe-1-Tests darueber: jede Phase haelt einen
// FEHLERzustand an genau EINER Stelle fest. Der ZIELzustand gegen den echten
// Arbeitsbaum ist Sache von Task 18 — der echte Gate-Bericht existiert vor
// diesem Task nicht, und die Stufe-2-Ledgerzeilen stehen noch auf `planned`.
// ===========================================================================

/// Die beiden Vektorfamilien, die Stufe 2 additiv anlegt.
const STAGE_TWO_FAMILIES: [&str; 2] = ["local-audit", "reports"];

/// Die zwoelf primaeren Abnahmekriterien der Stufe 2.
const STAGE_TWO_PRIMARY_ACCEPTANCE_CRITERIA: [u32; 12] =
    [1, 2, 3, 15, 23, 25, 28, 34, 39, 46, 48, 54];

/// Die vier Zielarchitekturen, fuer die Stufe 2 keine lokale Behauptung
/// aufstellt und deren Nachweis als offene Stufe-7-Ledgerzeile steht.
const STAGE_TWO_HOST_TARGETS: [&str; 4] = [
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
];

/// Die fuenf Skripte, die die Wurzel-`package.json` fuehren MUSS.
const STAGE_TWO_SCRIPTS: [&str; 5] = [
    "desktop:e2e",
    "desktop:test",
    "desktop:typecheck",
    "stage-gate:2",
    "supply-chain",
];

/// Der Stufe-2-Gate-Bericht, relativ zur Gate-Wurzel.
const STAGE_TWO_GATE_REPORT_PATH: &str = "docs/traceability/stage-2-gate.md";

/// Das Manifest der deklarierten Abbruchpunkte, relativ zur Gate-Wurzel.
const STAGE_TWO_FAULT_POINTS_PATH: &str = "docs/traceability/stage-2-fault-points.json";

/// Das Requirement-Ledger und das Entwurfsdokument, relativ zur Gate-Wurzel.
const REQUIREMENT_LEDGER_RELATIVE: &str = "docs/traceability/v0.1-requirements.csv";
const DESIGN_DOCUMENT_RELATIVE: &str =
    "docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md";

/// Die beiden Feldeklarationen des Stufe-2-Inhaltsvertrags, wie sie in der
/// Gate-Quelle stehen.
///
/// Sie stehen hier als Konstante, weil sowohl [`write_stage_two_report`] als
/// auch die Phasen von [`the_stage_two_gate_report_must_carry_its_content_contract`]
/// dieselbe Liste lesen muessen: das Fixture laesst ein Element aus, der Test
/// nennt dasselbe Element in seiner Zusicherung.
const STAGE_TWO_GATE_REPORT_SECTIONS_DECLARATION: &str =
    "const STAGE_TWO_GATE_REPORT_SECTIONS: [&str; 5] = [";
const STAGE_TWO_GATE_REPORT_LITERALS_DECLARATION: &str =
    "const STAGE_TWO_GATE_REPORT_LITERALS: [&str; 16] = [";

/// Liest ein Feld von Zeichenkettenliteralen dort, wo es normativ steht: in der
/// Gate-Quelle.
///
/// Das Fixture soll den Inhaltsvertrag ERFUELLEN, nicht ihn abschreiben. Eine
/// zweite Abschrift der fuenfzehn Literale und der fuenf Abschnitte in dieser
/// Datei wuerde den Bericht gegen die Abschrift pruefen statt gegen die Quelle,
/// und dieselbe Entscheidung liegt schon
/// [`wasm32_scope_clause_from_the_gate_source`] zugrunde.
fn string_array_from_the_gate_source(declaration: &str) -> Vec<String> {
    let source = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"))
        .expect("the xtask source must be readable");
    let at = source
        .find(declaration)
        .unwrap_or_else(|| panic!("the xtask source must carry the declaration {declaration}"));
    let body_at = at + declaration.len();
    // Der Abschluss haengt an der Klammer, mit der die Deklaration OEFFNET:
    // ein Feldliteral endet auf `];`, ein `concat!` auf `);`. Ein festes `];`
    // liefe ueber ein `concat!` hinaus in die naechste Deklaration.
    let terminator = if declaration.ends_with('(') {
        ");"
    } else {
        "];"
    };
    let body_end = body_at
        + source[body_at..]
            .find(terminator)
            .unwrap_or_else(|| panic!("{declaration} must be terminated with `{terminator}`"));
    let body = &source[body_at..body_end];
    assert!(
        !body.contains('\\'),
        "{declaration} must not carry an escape sequence, or this extractor would misread it"
    );
    let mut literals = Vec::new();
    let mut rest = body;
    while let Some(open) = rest.find('"') {
        let tail = &rest[open + 1..];
        let close = tail
            .find('"')
            .unwrap_or_else(|| panic!("{declaration} carries an unterminated literal"));
        literals.push(tail[..close].to_owned());
        rest = &tail[close + 1..];
    }
    assert!(
        !literals.is_empty(),
        "{declaration} must carry at least one literal"
    );
    literals
}

/// Liest die Reichweitenklausel der Stufe 2 aus ihrer `concat!`-Deklaration.
///
/// Wie [`wasm32_scope_clause_from_the_gate_source`]: der Bericht MUSS sie
/// woertlich tragen, und das Fixture stellt sie deshalb aus der Quelle her.
fn stage_two_host_scope_clause_from_the_gate_source() -> String {
    let clause =
        string_array_from_the_gate_source("const STAGE_TWO_HOST_SCOPE_CLAUSE: &str = concat!(")
            .concat();
    assert!(
        clause.ends_with("statt lokal behauptet."),
        "the stage 2 host scope clause must be readable from the gate source; found: {clause}"
    );
    clause
}

/// Der Fehlerzustand, den [`write_stage_two_ledger`] in das Ledger einbaut.
#[derive(Clone, Copy)]
enum LedgerDefect {
    /// Jede Stufe-2-Zeile traegt `implemented`, jede Host-Zeile steht.
    None,
    /// Die genannte Stufe-2-Zeile bleibt auf `planned`, und die Host-Zeile, die
    /// das genannte Ziel nennt, entfaellt — zwei Luecken auf einen Schlag.
    OneRowPlannedAndOneHostTargetUnnamed(&'static str, &'static str),
}

/// Die vier synthetischen Ledgerzeilen, die die Host-Zielarchitekturen als
/// offenen Stufe-7-Nachweis fuehren.
///
/// `ZZ-` sortiert hinter jeden echten Identifikator, also haengen die Zeilen an
/// das kopierte Ledger an, ohne dass es neu sortiert werden muss. Der Gate
/// prueft, dass jede PFLICHTzeile abgedeckt ist, nie dass keine weitere Zeile
/// existiert — eine zusaetzliche Zeile ist deshalb erlaubt.
fn host_target_rows() -> Vec<(String, &'static str)> {
    STAGE_TWO_HOST_TARGETS
        .iter()
        .enumerate()
        .map(|(index, target)| (format!("ZZ-HOST-{:02}", index + 1), *target))
        .collect()
}

/// Schreibt das Requirement-Ledger des Fixtures.
///
/// Grundlage ist das ECHTE eingecheckte Ledger: nur so bleibt die aus
/// `design.md` abgeleitete Pflichtzeilenmenge abgedeckt, ohne sie hier
/// abzuschreiben. Darueber genau zwei Eingriffe: jede Stufe-2-Zeile wandert auf
/// `implemented`, und die vier Host-Zeilen kommen hinzu.
fn write_stage_two_ledger(root: &Path, defect: LedgerDefect) {
    let source = fs::read_to_string(workspace_root().join(REQUIREMENT_LEDGER_RELATIVE))
        .expect("the checked-in requirement ledger must be readable");
    let mut lines = source.split('\n');
    let mut text = String::from(lines.next().expect("the ledger must carry a header line"));
    text.push('\n');
    let mut stage_two_rows = 0_usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let mut fields = ledger_fields(line);
        if fields[7] == "2" {
            stage_two_rows += 1;
            let force_planned = matches!(
                defect,
                LedgerDefect::OneRowPlannedAndOneHostTargetUnnamed(identifier, _)
                    if identifier == fields[0]
            );
            // GESETZT und nicht bloss stehengelassen: seit Task 18 traegt die
            // eingecheckte Zeile `integrated`, und ein Fixture, das den Status
            // nur nicht ueberschreibt, erzeugte damit gar keinen Mangel mehr.
            // Der Fixture-Zustand kommt vom DEFEKT und nie vom Arbeitsbaum.
            fields[8] = if force_planned {
                "planned".to_owned()
            } else {
                "implemented".to_owned()
            };
        }
        // Die Belegspalten der KOPIERTEN Zeilen duerfen keine Zielarchitektur
        // nennen: seit Task 18 fuehrt das eingecheckte Ledger vier eigene
        // Stufe-7-Zeilen, die alle vier nennen, und die Phase „genau EIN
        // unbenanntes Ziel" waere sonst nicht mehr herstellbar. Welche Ziele
        // benannt sind, entscheidet ausschliesslich `host_target_rows` unten.
        for target in STAGE_TWO_HOST_TARGETS {
            fields[6] = fields[6].replace(target, "<Zielarchitektur>");
        }
        text.push_str(&format!("\"{}\"", fields.join("\",\"")));
        text.push('\n');
    }
    assert!(
        stage_two_rows > 0,
        "the checked-in ledger must carry stage 2 rows, or this fixture measures nothing"
    );
    for (identifier, target) in host_target_rows() {
        if matches!(
            defect,
            LedgerDefect::OneRowPlannedAndOneHostTargetUnnamed(_, unnamed) if unnamed == target
        ) {
            continue;
        }
        text.push_str(&format!(
            "\"{identifier}\",\"v1\",\"global-constraints.md\",\
             \"offener Plattformnachweis\",\"\",\"\",\
             \"Stufe 7, offener Nachweis fuer {target}\",\"7\",\"planned\"\n"
        ));
    }
    let path = root.join(REQUIREMENT_LEDGER_RELATIVE);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, text).unwrap();
}

/// Der Fehlerzustand, den [`write_fault_point_manifest`] in das Manifest
/// einbaut.
#[derive(Clone, Copy)]
enum FaultManifestDefect {
    None,
    /// Der Finalisierungsteil verschwindet ganz.
    NoFinalizationSection,
    /// Der Finalisierungsteil bleibt als Objekt, verliert aber seine
    /// Punkteliste: eine Schrittliste allein deklariert keinen Abbruchpunkt.
    FinalizationWithoutPoints,
    /// Derselbe Abbruchpunkt steht zweimal im SELBEN Abschnitt.
    DuplicateWithinASection,
    /// Ein Abbruchpunkt ohne Klammertext.
    EntryWithoutBrackets,
    /// Der Vorrangpunkt fehlt.
    NoPrecedencePoint,
    /// Ein Abschnitt steht als LEERES Feld: die Ueberschrift ist da, die
    /// Deklaration nicht.
    EmptyDiscardSection,
}

/// Schreibt ein synthetisches Manifest der deklarierten Abbruchpunkte.
///
/// Die drei Abschnitte stehen als Feld — der Gate akzeptiert daneben die
/// eingecheckte Objektform mit `points`, und `FinalizationWithoutPoints` haelt
/// fest, dass eine Objektform ohne Punkteliste NICHT durchgeht.
fn write_fault_point_manifest(root: &Path, defect: FaultManifestDefect) {
    let mut manifest = serde_json::json!({
        "stage": 2,
        "discard": [
            {
                "name": "BeforeIntentCommit",
                "brackets": "vor dem dauerhaften Buchen der Verwerfensabsicht"
            },
            {
                "name": "AfterKeystoreDelete",
                "brackets": "nach dem Loeschen des draftDEK"
            }
        ],
        "finalization": [
            {
                "name": "AfterPreparedMarkerCommit",
                "brackets": "nach dem Buchen der Abschlussmarke"
            },
            {
                "name": "AfterEntryDirectoryFlush",
                "brackets": "nach dem Verzeichnisflush der Eintraege"
            }
        ],
        "precedence": [
            {
                "name": "PreparedFinalizationBeatsDiscardIntent",
                "brackets": "vor jedem Eingang des Verwerfens"
            }
        ]
    });
    let object = manifest.as_object_mut().unwrap();
    match defect {
        FaultManifestDefect::None => {}
        FaultManifestDefect::NoFinalizationSection => {
            object.remove("finalization");
        }
        FaultManifestDefect::FinalizationWithoutPoints => {
            object.insert(
                "finalization".to_owned(),
                serde_json::json!({ "steps": [{ "number": 1, "name": "RebuildLocalHead" }] }),
            );
        }
        FaultManifestDefect::DuplicateWithinASection => {
            let discard = object["discard"].as_array().unwrap().clone();
            object["discard"]
                .as_array_mut()
                .unwrap()
                .push(discard[0].clone());
        }
        FaultManifestDefect::EntryWithoutBrackets => {
            object["discard"][0]
                .as_object_mut()
                .unwrap()
                .insert("brackets".to_owned(), serde_json::json!("   "));
        }
        FaultManifestDefect::NoPrecedencePoint => {
            object["precedence"][0]
                .as_object_mut()
                .unwrap()
                .insert("name".to_owned(), serde_json::json!("SomethingElse"));
        }
        FaultManifestDefect::EmptyDiscardSection => {
            object["discard"].as_array_mut().unwrap().clear();
        }
    }
    let path = root.join(STAGE_TWO_FAULT_POINTS_PATH);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, serde_json::to_string_pretty(&manifest).unwrap()).unwrap();
}

/// Der Fehlerzustand, den [`write_stage_two_report`] in den Bericht einbaut.
#[derive(Clone, Copy)]
enum ReportDefect {
    None,
    /// Die Belegzeile des genannten Abnahmekriteriums laesst die Spalte
    /// `Offen in spaeterer Stufe` leer.
    EmptyOpenColumn(u32),
    /// Der Pflichtabschnitt mit dem genannten Index fehlt im Bericht.
    ///
    /// Der Index zeigt in die aus der Gate-Quelle gelesene Liste, damit weder
    /// Fixture noch Zusicherung eine Ueberschrift abschreiben.
    MissingSection(usize),
    /// Das Pflichtliteral mit dem genannten Index fehlt im Bericht — Index
    /// wie bei [`ReportDefect::MissingSection`].
    MissingLiteral(usize),
    /// Der Bericht traegt die Reichweitenklausel der Stufe 2 nicht.
    NoScopeClause,
}

/// Schreibt einen synthetischen Stufe-2-Gate-Bericht, der den Inhaltsvertrag
/// erfuellt.
///
/// Abschnitte, Literale und Reichweitenklausel kommen aus der Gate-Quelle; die
/// Belegtabelle entsteht aus den zwoelf primaeren Abnahmekriterien.
fn write_stage_two_report(root: &Path, defect: ReportDefect) {
    let mut text = String::from("# Stufe-2-Gate (Fixture)\n\n");
    if !matches!(defect, ReportDefect::NoScopeClause) {
        text.push_str(&stage_two_host_scope_clause_from_the_gate_source());
        text.push_str("\n\n");
    }
    for (index, literal) in
        string_array_from_the_gate_source(STAGE_TWO_GATE_REPORT_LITERALS_DECLARATION)
            .into_iter()
            .enumerate()
    {
        if matches!(defect, ReportDefect::MissingLiteral(omitted) if omitted == index) {
            continue;
        }
        text.push_str(&format!("- {literal}\n"));
    }
    text.push('\n');
    for (index, section) in
        string_array_from_the_gate_source(STAGE_TWO_GATE_REPORT_SECTIONS_DECLARATION)
            .into_iter()
            .enumerate()
    {
        if matches!(defect, ReportDefect::MissingSection(omitted) if omitted == index) {
            continue;
        }
        text.push_str(&format!("{section}\n\n"));
    }
    // Die Kopfzeile beginnt bewusst NICHT mit `| AK `: der Gate liest jede
    // solche Zeile als Belegzeile und verlangt dort eine Nummer.
    text.push_str("| Kriterium | Titel | Beleg | Offen in spaeterer Stufe |\n|---|---|---|---|\n");
    for criterion in STAGE_TWO_PRIMARY_ACCEPTANCE_CRITERIA {
        let open = match defect {
            ReportDefect::EmptyOpenColumn(number) if number == criterion => "",
            _ => "Stufe 7",
        };
        text.push_str(&format!(
            "| AK {criterion} | Titel {criterion} | tests/stage_gate.rs | {open} |\n"
        ));
    }
    let path = root.join(STAGE_TWO_GATE_REPORT_PATH);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, text).unwrap();
}

/// Schreibt eine Wurzel-`package.json`, die genau die genannten Skripte fuehrt.
fn write_package_manifest(root: &Path, scripts: &[&str]) {
    let mut declared = serde_json::Map::new();
    for script in scripts {
        declared.insert(
            (*script).to_owned(),
            serde_json::json!(format!("echo {script}")),
        );
    }
    let manifest = serde_json::json!({
        "name": "einsatzarchiv-fixture",
        "private": true,
        "scripts": serde_json::Value::Object(declared),
    });
    let path = root.join("package.json");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, serde_json::to_string_pretty(&manifest).unwrap()).unwrap();
}

/// Baut eine gruene Stufe-2-Grundlage.
///
/// Nach dem Muster von [`fixture_with_the_checked_in_documents`]: die beiden
/// Vektorfamilien der Stufe 2, das kopierte Entwurfsdokument und dann jedes der
/// vier Stufe-2-Artefakte in seiner mangelfreien Fassung. Formatpaket und
/// Fuzz-Manifest bringt [`fixture_root`] mit.
fn stage_two_fixture(label: &str) -> PathBuf {
    let root = fixture_root(label);
    for family in STAGE_TWO_FAMILIES {
        write_family_manifest(&root, family);
    }
    copy_from_the_workspace(&root, DESIGN_DOCUMENT_RELATIVE);
    write_stage_two_ledger(&root, LedgerDefect::None);
    write_fault_point_manifest(&root, FaultManifestDefect::None);
    write_stage_two_report(&root, ReportDefect::None);
    write_package_manifest(&root, &STAGE_TWO_SCRIPTS);
    root
}

#[test]
fn stage_two_gate_names_every_missing_declaration_at_once() {
    // Phase 1: die gruene Grundlage. Der Gate beendet mit 0 und liefert die
    // vier additiven Berichtsfelder.
    let root = stage_two_fixture("baseline");
    let output = run_stage_gate(&root, "2");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        output.status.success(),
        "stage-gate 2 must accept the complete fixture; stderr: {stderr}"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let report: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("stdout must be JSON: {error}; stdout: {stdout}"));
    assert_eq!(report["stage"], serde_json::json!(2));
    assert_eq!(
        report["vector_families"],
        serde_json::json!(STAGE_TWO_FAMILIES)
    );
    assert_eq!(
        report["stage_two_primary_acceptance_criteria"],
        serde_json::json!(STAGE_TWO_PRIMARY_ACCEPTANCE_CRITERIA)
    );
    assert!(
        report["declared_fault_points"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "PreparedFinalizationBeatsDiscardIntent"),
        "the declared points carry the precedence point; stdout: {stdout}"
    );
    assert!(!report["host_evidence_rows"].as_array().unwrap().is_empty());
    assert!(
        report["stage_two_rows_still_planned"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    // Phase 2: der Gate-Bericht fehlt, ein Stufe-2-Ledgereintrag steht auf
    // `planned`, und eine Host-Zielarchitektur wird von keiner Zeile genannt.
    // Der Gate nennt ALLE DREI in EINER Fehlermeldung — sonst begruendet der
    // RED-Schritt der Stufenabnahme nur den ersten Mangel.
    let root = stage_two_fixture("three-gaps");
    fs::remove_file(root.join(STAGE_TWO_GATE_REPORT_PATH)).unwrap();
    write_stage_two_ledger(
        &root,
        LedgerDefect::OneRowPlannedAndOneHostTargetUnnamed("FR-043", "x86_64-pc-windows-msvc"),
    );
    let output = run_stage_gate(&root, "2");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2));
    for expected in [STAGE_TWO_GATE_REPORT_PATH, "FR-043"] {
        assert!(
            stderr.contains(expected),
            "stage-gate 2 must name {expected} in the same failure; stderr: {stderr}"
        );
    }
    for target in STAGE_TWO_HOST_TARGETS {
        assert_eq!(
            stderr.contains(target),
            target == "x86_64-pc-windows-msvc",
            "stage-gate 2 must name exactly the unnamed host target; stderr: {stderr}"
        );
    }

    // Phase 3: das Fault-Punkt-Manifest verliert seinen Finalisierungsteil.
    let root = stage_two_fixture("manifest");
    write_fault_point_manifest(&root, FaultManifestDefect::NoFinalizationSection);
    let output = run_stage_gate(&root, "2");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("finalization"),
        "stage-gate 2 must name the empty manifest section; stderr: {stderr}"
    );

    // Phase 4: eine Abnahmekriteriumszeile ohne Eintrag in der Spalte
    // `Offen in spaeterer Stufe`. Eine leere Spalte ist genau die
    // Scheinzusage, die dieser Bericht ausschliesst.
    let root = stage_two_fixture("empty-open-column");
    write_stage_two_report(&root, ReportDefect::EmptyOpenColumn(46));
    let output = run_stage_gate(&root, "2");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("AK 46"),
        "stage-gate 2 must name the incomplete row; stderr: {stderr}"
    );

    // Phase 5: die drei Frontend-Skripte fehlen in der Wurzel-`package.json`.
    // Ohne sie hat die Stufe keine UI-Spur, und jede exakte UI-Zusage waere
    // nach Stufe 2 unbelegt.
    let root = stage_two_fixture("scripts");
    write_package_manifest(&root, &["stage-gate:2", "supply-chain"]);
    let output = run_stage_gate(&root, "2");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("desktop:e2e"),
        "stage-gate 2 must name the missing frontend script; stderr: {stderr}"
    );
}

/// Haelt die Formregeln des Abbruchpunkt-Manifests fest, die
/// `stage_two_gate_names_every_missing_declaration_at_once` nicht beruehrt.
///
/// Ohne diesen Test liefen die Objektform ohne `points`, die Doppelung
/// innerhalb eines Abschnitts, der leere Klammertext, das leere Abschnittsfeld
/// und die Abwesenheit des Vorrangpunkts ungemessen mit.
#[test]
fn the_fault_point_manifest_must_declare_shaped_entries() {
    // Phase 1: Objektform ohne `points`. Eine Schrittliste allein deklariert
    // keinen Abbruchpunkt — genau die Mutation, die die eingecheckte Objektform
    // andernfalls still passieren liesse.
    let root = stage_two_fixture("no-points");
    write_fault_point_manifest(&root, FaultManifestDefect::FinalizationWithoutPoints);
    let output = run_stage_gate(&root, "2");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("finalization"),
        "the gate must name the section without a points array; stderr: {stderr}"
    );

    // Phase 2: derselbe Abbruchpunkt zweimal im selben Abschnitt.
    let root = stage_two_fixture("duplicate");
    write_fault_point_manifest(&root, FaultManifestDefect::DuplicateWithinASection);
    let output = run_stage_gate(&root, "2");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("BeforeIntentCommit"),
        "the gate must name the duplicated fault point; stderr: {stderr}"
    );

    // Phase 3: ein Abbruchpunkt ohne Klammertext. Ein Name ohne Klammer sagt
    // nicht, WANN der Absturz eintritt, und belegt damit nichts.
    let root = stage_two_fixture("no-brackets");
    write_fault_point_manifest(&root, FaultManifestDefect::EntryWithoutBrackets);
    let output = run_stage_gate(&root, "2");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("BeforeIntentCommit") && stderr.contains("brackets"),
        "the gate must name the entry without a bracketed step; stderr: {stderr}"
    );

    // Phase 4: ein Abschnitt steht als leeres Feld. Eine Ueberschrift ohne
    // Eintrag deklariert nichts, und der Gate muss den Abschnitt nennen — ohne
    // diese Phase liesse sich die Leerpruefung streichen, ohne dass ein Test
    // fiele, weil Phase 3 des Brieftests den Schluessel ganz entfernt.
    let root = stage_two_fixture("empty-section");
    write_fault_point_manifest(&root, FaultManifestDefect::EmptyDiscardSection);
    let output = run_stage_gate(&root, "2");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("discard") && stderr.contains("empty"),
        "the gate must name the empty manifest section; stderr: {stderr}"
    );

    // Phase 5: der Vorrangpunkt fehlt. Er liegt bewusst NICHT in
    // `DiscardFaultPoint::ALL` und muss deshalb namentlich verlangt werden.
    let root = stage_two_fixture("no-precedence");
    write_fault_point_manifest(&root, FaultManifestDefect::NoPrecedencePoint);
    let output = run_stage_gate(&root, "2");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("PreparedFinalizationBeatsDiscardIntent"),
        "the gate must name the missing precedence fault point; stderr: {stderr}"
    );
}

/// Haelt die beiden Pruefungen fest, die der Stufe-2-Zweig an der Wurzel
/// wiederholt: die zwei additiven Vektorfamilien und das oeffentliche
/// Formatpaket.
///
/// Ohne diese Phasen liesse sich beides aus dem Zweig streichen, ohne dass ein
/// Test fiele — das Fixture bringt sie in jedem anderen Test mit.
#[test]
fn stage_two_gate_requires_the_new_families_and_the_format_package() {
    // Phase 1: die Familie `reports` traegt kein Manifest mehr. Sie liefert das
    // Urbild des Importprotokolls; ohne sie ist AK 28 unbelegt.
    let root = stage_two_fixture("families");
    fs::remove_dir_all(root.join("vectors/reports")).unwrap();
    let output = run_stage_gate(&root, "2");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("reports") && !stderr.contains("local-audit"),
        "the gate must name exactly the family without a manifest; stderr: {stderr}"
    );

    // Phase 2: das oeffentliche Formatpaket fehlt. Der Stufe-2-Bericht NENNT
    // seinen Pfad; ein genanntes und nie gelesenes Dokument waere genau die
    // Scheinzusage, die dieser Gate ausschliesst.
    let root = stage_two_fixture("format-package");
    fs::remove_file(root.join(FORMAT_PACKAGE_PATH)).unwrap();
    let output = run_stage_gate(&root, "2");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains(FORMAT_PACKAGE_PATH),
        "the gate must name the missing format package; stderr: {stderr}"
    );
}

/// Bezeugt die drei Inhaltspruefungen des Stufe-2-Gate-Berichts, die sonst
/// kein Test beruehrt: die fuenf Pflichtabschnitte, die fuenfzehn
/// Pflichtliterale und die woertliche Reichweitenklausel
/// (`tools/xtask/src/main.rs`, Schritt 6b).
///
/// Das Fixture stellt alle drei aus der Gate-Quelle her und erfuellt den
/// Vertrag deshalb immer. Ohne diese Phasen liessen sich die drei Bloecke im
/// Gate streichen, ohne dass ein Test faellt — und der gruene
/// ZIELzustandslauf der Stufenabnahme waere danach genauso gruen, die Luecke
/// also dauerhaft. Die Phasen haben die Form von
/// [`ReportDefect::EmptyOpenColumn`]: ein Fehlerzustand an genau einer Stelle.
#[test]
fn the_stage_two_gate_report_must_carry_its_content_contract() {
    // Phase 1: ein Pflichtabschnitt fehlt. Der Gate nennt ihn.
    let sections = string_array_from_the_gate_source(STAGE_TWO_GATE_REPORT_SECTIONS_DECLARATION);
    let omitted_section = &sections[1];
    let root = stage_two_fixture("missing-section");
    write_stage_two_report(&root, ReportDefect::MissingSection(1));
    let output = run_stage_gate(&root, "2");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains(omitted_section.as_str()),
        "stage-gate 2 must name the missing section {omitted_section}; stderr: {stderr}"
    );

    // Phase 2: ein Pflichtliteral fehlt. `draftDEK` steht in keiner anderen
    // Meldung des Zweigs, die Zusicherung kann also nicht von einem fremden
    // Mangel bedient werden.
    let literals = string_array_from_the_gate_source(STAGE_TWO_GATE_REPORT_LITERALS_DECLARATION);
    let omitted_literal = &literals[8];
    assert_eq!(
        omitted_literal, "draftDEK",
        "the omitted literal must stay the one this phase argues about"
    );
    let root = stage_two_fixture("missing-literal");
    write_stage_two_report(&root, ReportDefect::MissingLiteral(8));
    let output = run_stage_gate(&root, "2");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains(omitted_literal.as_str()),
        "stage-gate 2 must name the missing literal {omitted_literal}; stderr: {stderr}"
    );

    // Phase 3: die Reichweitenklausel fehlt. Ein gruener Stufe-2-Gate ohne sie
    // liest sich als Plattformnachweis, den die Stufe nicht erbringt.
    let root = stage_two_fixture("no-scope-clause");
    write_stage_two_report(&root, ReportDefect::NoScopeClause);
    let output = run_stage_gate(&root, "2");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("scope clause"),
        "stage-gate 2 must report the missing scope clause; stderr: {stderr}"
    );
    for target in STAGE_TWO_HOST_TARGETS {
        assert!(
            !stderr.contains(target),
            "the missing-clause message must not quote the clause, or it would \
             become indistinguishable from an unnamed host target; stderr: {stderr}"
        );
    }
}

#[test]
fn the_stage_switch_still_refuses_an_undefined_stage() {
    // Stufe 5 und nicht mehr Stufe 4: die Stufe-4-Abnahme oeffnet den Schalter
    // fuer 4, und die Zusicherung dieses Tests ist die UNVERAENDERTE — eine
    // undefinierte Stufe wird abgewiesen, und die Fehlerzeile nennt die
    // definierten. Sie WANDERT mit dem Schalter, statt aufgeweicht zu werden;
    // die Stufe-3-Abnahme hat sie von 3 auf 4 gestellt und `"stages 1 and 2"`
    // auf `"stages 1, 2 and 3"`, die Stufe-4-Abnahme stellt sie von 4 auf 5
    // und auf `"stages 1, 2, 3 and 4"`. Der Pin steht bewusst auf dem KURZEN
    // Teilstring: ein `grep -rn "only defined for stages"` trifft ihn deshalb
    // NICHT, und wer den Schalter oeffnet, findet ihn ueber diesen Kommentar.
    let root = stage_two_fixture("stage-five");
    let output = run_stage_gate(&root, "5");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("stages 1, 2, 3 and 4"),
        "the switch must name the stages it defines; stderr: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Stufe 2 — die ZIELzustandstests der Stufenabnahme (Task 18).
//
// Sie lesen den ECHTEN Arbeitsbaum und halten einen ZIELzustand. Sie koennen
// durch einen spaeteren Task nicht invertieren: was hier gruen ist, bleibt
// gruen, solange die Stufe geschlossen bleibt.
// ---------------------------------------------------------------------------

/// Die zwoelf Abbruchpunkte der Finalisierung, als LITERALE.
///
/// Textgleich mit den Varianten von `ea_writer::FinalizationFaultPoint`
/// (`crates/ea-writer/src/fault.rs`), aber ausdruecklich als Zeichenketten:
/// so bleibt `tools/xtask/Cargo.toml` frei von jeder Stufe-2-Abhaengigkeit, und
/// die Deklaration wird gegen eine UNABHAENGIGE Liste verglichen statt gegen
/// sich selbst. Verglichen mit der Aufzaehlung selbst koennte eine Aufzaehlung
/// mit einer einzigen Variante beide Zusagen erfuellen und gruen melden.
const FINALIZATION_FAULT_POINT_NAMES: &[&str] = &[
    "BeforeStagingCreate",
    "AfterStagingCreateBeforeFileFlush",
    "AfterStagingFileFlushBeforeDirectoryFlush",
    "AfterStagingDirectoryFlushBeforeMarker",
    "AfterPreparedMarkerCommit",
    "AfterKeystoreDelete",
    "AfterAbsenceConfirmation",
    "AfterGrantPublishBeforeEntryRename",
    "AfterEntryRenameBeforeDirectoryFlush",
    "AfterEntryDirectoryFlush",
    "AfterReconciliationBeforeBlankDraft",
    "BackupRestoreAfterKeyDeletion",
];

/// Die sechs Abbruchpunkte des Verwerfens, als LITERALE.
///
/// Textgleich mit den Varianten von `ea_draft::DiscardFaultPoint`
/// (`crates/ea-draft/src/fault.rs`); dieselbe Begruendung wie oben.
const DISCARD_FAULT_POINT_NAMES: &[&str] = &[
    "BeforeIntentCommit",
    "AfterIntentCommit",
    "AfterKeystoreDelete",
    "AfterAbsenceConfirmation",
    "AfterDraftRemoval",
    "BackupRestoreAfterKeyDeletion",
];

/// Haelt fest, dass der Stufe-2-Gate jede unwiderrufliche Grenze DEKLARIERT.
///
/// Die Kanarienzusicherung ist hier ABSICHTLICH nicht dabei: ob ein
/// Kanarienvogel gefunden wurde, ist eine Aussage ueber einen LAUF, und die
/// traegt `tests/ea-system-tests/tests/privacy_canaries_writer.rs`.
#[test]
fn stage_two_gate_declares_every_irreversible_boundary() {
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["stage-gate", "2"])
        .env_remove("EA_STAGE_GATE_ROOT")
        .output()
        .expect("xtask stage-gate must start");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let declared = report["declared_fault_points"].as_array().unwrap();
    for point in FINALIZATION_FAULT_POINT_NAMES
        .iter()
        .chain(DISCARD_FAULT_POINT_NAMES)
    {
        assert!(
            declared.iter().any(|value| value == point),
            "der Stufe-2-Gate deklariert {point} nicht"
        );
    }
    assert_eq!(
        report["stage_two_primary_acceptance_criteria"],
        serde_json::json!([1, 2, 3, 15, 23, 25, 28, 34, 39, 46, 48, 54])
    );
    assert!(!report["host_evidence_rows"].as_array().unwrap().is_empty());
    let planned = report["stage_two_rows_still_planned"].as_array().unwrap();
    assert!(
        planned.is_empty(),
        "Stufe-2-Ledgerzeilen stehen noch auf planned: {planned:?}"
    );
}

/// Die zehn Kommandos der Schritt-6-Folge dieses Plans, in genau der
/// Reihenfolge, in der der Plan sie vorschreibt.
///
/// Das erste Kommando steht mit seinem Praefix, nicht mit seiner vollen
/// Paketliste: die Belegzeile MUSS es nennen, soll die zehn `-p`-Namen aber
/// nicht ein zweites Mal woertlich abschreiben.
const STAGE_TWO_STEP_SIX_COMMANDS: [&str; 10] = [
    "cargo test --locked -p ea-writer",
    "cargo test --locked -p ea-system-tests --test fault_injection_writer_matrix",
    "cargo test --locked -p ea-system-tests --test privacy_canaries_writer",
    "cargo test --locked -p ea-system-tests --test e2e_writer_archive",
    "pnpm desktop:typecheck",
    "pnpm desktop:test",
    "pnpm desktop:e2e",
    "pnpm supply-chain",
    "pnpm stage-gate:2",
    "pnpm verify:quick",
];

/// Haelt fest, dass der Stufe-2-Gate-Bericht den vorgeschriebenen vollen Lauf
/// GEMESSEN protokolliert statt ihn zu behaupten.
///
/// Er lebt hier und nicht im Gate, aus dem Grund, den Stufe 1 schon
/// entschieden hat: der protokollierte Lauf enthaelt `pnpm stage-gate:2` und
/// `pnpm verify:quick` selbst, und ein Gate, der seine eigene Messzeile
/// verlangte, koennte auf dem Lauf, der sie erzeugt, nie gruen sein.
#[test]
fn stage_two_gate_report_records_the_measured_full_gate_run() {
    let report = fs::read_to_string(workspace_root().join("docs/traceability/stage-2-gate.md"))
        .expect("the stage 2 gate report must be readable");
    let rows = measured_run_rows(&report);
    for command in STAGE_TWO_STEP_SIX_COMMANDS {
        let matching: Vec<&Vec<String>> =
            rows.iter().filter(|row| row[0].contains(command)).collect();
        assert_eq!(
            matching.len(),
            1,
            "stage-2-gate.md must record the measured run for `{command}` exactly once"
        );
        let row = matching[0];
        assert!(row.len() >= 3, "{row:?}");
        assert_eq!(
            row[1], "0",
            "`{command}` must have ended with exit code 0: {row:?}"
        );
        assert!(!row[2].is_empty(), "{row:?}");
        assert!(
            !row[2].contains("0 passed"),
            "`0 passed; N filtered out` is a broken filter, not a result: {row:?}"
        );
    }
    assert_eq!(rows.len(), STAGE_TWO_STEP_SIX_COMMANDS.len() + 1);

    // Und die ausgeschriebene Zahl in der Belegzeile von `pnpm verify:quick`,
    // damit sie nicht wieder driftet: die Welle des Abschlussreviews hat drei
    // Teilkommandos hinzugefuegt und die Zahl in dieser Zeile stehen gelassen
    // (SIEBEN statt ACHT), und kein Gate hat es gefangen, weil kein Literal die
    // Zahl hielt.
    //
    // Die Zusicherung lebt IN diesem Test und nicht in einem eigenen: ein
    // zweites `#[test]` erhoehte die Testzahl des Workspace, und genau die
    // steht zwei Saetze weiter in derselben Zeile, die hier geprueft wird.
    let verify_quick: Vec<&Vec<String>> = rows
        .iter()
        .filter(|row| row[0].contains("pnpm verify:quick"))
        .collect();
    assert_eq!(
        verify_quick.len(),
        1,
        "stage-2-gate.md must record the measured run for `pnpm verify:quick` exactly once"
    );
    let cell = verify_quick[0];
    assert!(cell.len() >= 3, "{cell:?}");
    let stated = cell[2]
        .split_whitespace()
        .next()
        .expect("the verify:quick evidence cell must not be empty");
    assert_eq!(
        stated, STAGE_TWO_MEASURED_SUBCOMMAND_COUNT,
        "stage-2-gate.md must open the verify:quick evidence cell with the spelled-out number of \
         subcommands that the stage 2 run actually measured"
    );
}

/// Die Zahl der Teilkommandos, die der Stufe-2-Gate-Bericht TATSAECHLICH
/// protokolliert, in seiner eigenen Schreibweise (`ACHT Teilkommandos gruen`).
///
/// Ein historisches LITERAL und kein LIVE gezaehlter Wert, und darin liegt die
/// Aussage: eine gemessene Zahl ist eine Aussage ueber den Lauf, der sie
/// erzeugt hat, und keine Aussage ueber eine spaetere Quelle. Bis Stufe 4 stand
/// hier ein Zaehler ueber `verify_quick_commands()`; die Aufgabe
/// „wasm32-Reichweite: `ea-reader`, die Bruecken-Crate und die geteilten
/// Browserkerne" hob die wasm32-Positivliste von zehn auf dreizehn Pakete, und
/// ein Bericht, den eine spaetere Stufe rot faerbt, misst nicht mehr sich
/// selbst. `docs/traceability/stage-2-gate.md` ist eine ABGESCHLOSSENE
/// Ausfuehrungsaufzeichnung und wird nicht umgeschrieben.
///
/// Die LIVE-Deckung uebernimmt der Stufe-4-Bericht: die Aufgabe
/// „Reader-Interoperabilitaet, Browser-Matrix, Datei-Modus, Privatheit und das
/// Stufe-4-Gate" legt die Zaehler und die Zahlwortliste dort neu an, wo sie
/// gegen einen Bericht DIESER Stufe stehen.
const STAGE_TWO_MEASURED_SUBCOMMAND_COUNT: &str = "ACHT";

// ---------------------------------------------------------------------------
// Stufe 3 — „Blind Sync".
//
// Der ZIELzustandstest liest den ECHTEN Arbeitsbaum; die Mangelphasen laufen
// gegen ein Fixture und halten je EINEN Fehlerzustand fest. Beide Formen sind
// die der Stufe 2, und der Grund ist derselbe: ein Zielzustandstest kann durch
// einen spaeteren Task nicht invertieren, und ein Fehlerzustand bleibt gegen
// ein Fixture stabil.
// ---------------------------------------------------------------------------

/// Die Vektorfamilie, die Stufe 3 additiv anlegt.
const STAGE_THREE_FAMILIES: [&str; 1] = ["web-bundle"];

/// Die sieben primaeren Abnahmekriterien der Stufe 3.
const STAGE_THREE_PRIMARY_ACCEPTANCE_CRITERIA: [u32; 7] = [7, 8, 13, 33, 36, 45, 50];

/// Die vier Skripte, die die Wurzel-`package.json` fuer Stufe 3 fuehren MUSS.
const STAGE_THREE_SCRIPTS: [&str; 4] = [
    "stage-gate:3",
    "supply-chain",
    "test:server",
    "verify:quick",
];

/// Der Stufe-3-Gate-Bericht und das Szenarienmanifest, relativ zur Gate-Wurzel.
const STAGE_THREE_GATE_REPORT_PATH: &str = "docs/traceability/stage-3-gate.md";
const STAGE_THREE_FAULT_POINTS_PATH: &str = "docs/traceability/stage-3-fault-points.json";

/// Die NEUN Szenarien, die das Manifest deklarieren MUSS — als LITERALE.
///
/// Sie stehen hier ausgeschrieben und nicht aus dem Manifest gelesen: gegen
/// sich selbst verglichen koennte ein Manifest mit einem einzigen Szenario
/// beide Zusagen erfuellen und gruen melden.
const STAGE_THREE_SCENARIOS: [&str; 9] = [
    "cursor-key-rotation",
    "db-after-object-put",
    "db-before-commit",
    "nonce-replay",
    "parallel-fork",
    "response-loss",
    "restore",
    "s3-stage",
    "tls-downgrade",
];

/// Schreibt das Requirement-Ledger des Stufe-3-Fixtures.
///
/// Grundlage ist das ECHTE eingecheckte Ledger — nur so bleibt die aus
/// `design.md` abgeleitete Pflichtzeilenmenge abgedeckt, ohne sie hier
/// abzuschreiben. `reopened` stellt GENAU EINE Stufe-3-Zeile zurueck auf
/// `planned`, damit die Mangelphase den Filter an einer benannten Zeile misst.
fn write_stage_three_ledger(root: &Path, reopened: Option<&str>) {
    let source = fs::read_to_string(workspace_root().join(REQUIREMENT_LEDGER_RELATIVE))
        .expect("the requirement ledger must be readable");
    let mut lines = Vec::new();
    for (index, line) in source.lines().enumerate() {
        if index == 0 || line.is_empty() {
            lines.push(line.to_owned());
            continue;
        }
        let mut fields = ledger_fields(line);
        if Some(fields[0].as_str()) == reopened && fields[7] == "3" {
            fields[8] = "planned".to_owned();
        }
        lines.push(format!("\"{}\"", fields.join("\",\"")));
    }
    let path = root.join(REQUIREMENT_LEDGER_RELATIVE);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
}

/// Baut eine gruene Stufe-3-Grundlage.
///
/// Nach dem Muster von [`stage_two_fixture`]: die additive Vektorfamilie, das
/// kopierte Entwurfsdokument und dann jedes der vier Stufe-3-Artefakte in
/// seiner mangelfreien Fassung. Szenarienmanifest und Gate-Bericht kommen aus
/// dem Arbeitsbaum — das Fixture soll den Vertrag ERFUELLEN, nicht ihn
/// abschreiben; dieselbe Entscheidung liegt schon
/// [`string_array_from_the_gate_source`] zugrunde.
fn stage_three_fixture(label: &str) -> PathBuf {
    let root = fixture_root(label);
    for family in STAGE_THREE_FAMILIES {
        write_family_manifest(&root, family);
    }
    copy_from_the_workspace(&root, DESIGN_DOCUMENT_RELATIVE);
    copy_from_the_workspace(&root, STAGE_THREE_FAULT_POINTS_PATH);
    copy_from_the_workspace(&root, STAGE_THREE_GATE_REPORT_PATH);
    // Die Zeugendateien gehoeren ZUM Fixture, seit der Gate jeden `witness`
    // auf eine wirklich vorhandene Testfunktion aufloest. Kopiert wird genau,
    // was das Manifest nennt — ein von Hand gefuehrter zweiter Dateiname waere
    // die Liste, die auseinanderlaeuft.
    for witness in fault_point_witness_files(&root, STAGE_THREE_FAULT_POINTS_PATH) {
        copy_from_the_workspace(&root, &witness);
    }
    write_stage_three_ledger(&root, None);
    write_package_manifest(&root, &STAGE_THREE_SCRIPTS);
    root
}

/// Die Dateien, auf die die `witness`-Felder eines Szenarienmanifests zeigen.
///
/// `manifest_path` ist ein Parameter und kein eingebrannter Pfad, seit Stufe 4
/// ein zweites Manifest derselben Form fuehrt: eine zweite Abschrift dieser
/// Schleife waere die Liste, die auseinanderlaeuft.
fn fault_point_witness_files(root: &Path, manifest_path: &str) -> Vec<String> {
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(root.join(manifest_path)).unwrap()).unwrap();
    let mut files = Vec::new();
    for (section, value) in manifest.as_object().unwrap() {
        if section == "stage" {
            continue;
        }
        for entry in value.as_array().into_iter().flatten() {
            let witness = entry["witness"].as_str().unwrap();
            let (file, _) = witness.split_once("::").unwrap_or_else(|| {
                panic!("every witness carries <path>::<function>; found {witness}")
            });
            if !files.iter().any(|known: &String| known == file) {
                files.push(file.to_owned());
            }
        }
    }
    assert!(
        !files.is_empty(),
        "the manifest must name witness files, or the fixture copies nothing"
    );
    files
}

/// Entfernt EINEN Abschnitt aus einem Szenarienmanifest des Fixtures.
///
/// In DIESER Form herausgehoben, weil zwei Stufen denselben Schritt fahren:
/// Stufe 3 nimmt ihrem Manifest den Rueckspielabschnitt `restore`, Stufe 4
/// ihren Datei-Modus-Abschnitt `file-mode`. Die Zusicherung, dass wirklich
/// etwas entfernt wurde, gehoert dazu — ein Tippfehler im Abschnittsnamen
/// erzeugte sonst ein unveraendertes Manifest und einen gruenen Gate, und der
/// Test behauptete einen Mangel, den er nie hergestellt hat.
fn remove_fault_point_section(root: &Path, manifest_path: &str, section: &str) {
    let path = root.join(manifest_path);
    let mut value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    let removed = value
        .as_object_mut()
        .unwrap_or_else(|| panic!("{manifest_path} must be a JSON object"))
        .remove(section);
    assert!(
        removed.is_some(),
        "{manifest_path} must really carry the {section} section, or this fixture removes nothing"
    );
    fs::write(&path, serde_json::to_string_pretty(&value).unwrap()).unwrap();
}

/// Haelt fest, dass `stage-gate 3` die echten Dienstfehler, die neun Szenarien
/// und die sieben primaeren Abnahmekriterien verlangt.
///
/// Phase 1 laeuft gegen den ECHTEN Arbeitsbaum und haelt den ZIELzustand fest.
/// Jede weitere Phase laeuft gegen ein Fixture und haelt einen FEHLERzustand
/// an genau einer Stelle fest.
///
/// KEINE Phase braucht die zwei Integrationsdienste. Der Stufe-3-Gate liest
/// Dokumente, das Ledger und ein Manifest — er oeffnet weder Datenbank noch
/// Object Store. Gemessen: mit abgeraeumten Containern enden `stage-gate 1`,
/// `stage-gate 2` und `stage-gate 3` weiterhin mit Exitcode 0, und dieses
/// Testziel bleibt gruen. Das ist die Eigenschaft, die diesen Test in
/// `pnpm verify:quick` auch auf einem Rechner ohne Docker lauffaehig haelt.
#[test]
fn stage_three_gate_requires_real_service_failures_and_primary_ak() {
    // Phase 1: der echte Arbeitsbaum.
    let output = run_stage_gate_in_the_workspace("3");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        output.status.success(),
        "stage-gate 3 must accept the checked-in tree; stderr: {stderr}"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let report: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("stdout must be JSON: {error}; stdout: {stdout}"));
    assert_eq!(report["stage"], serde_json::json!(3));
    assert_eq!(
        report["vector_families"],
        serde_json::json!(STAGE_THREE_FAMILIES)
    );
    assert_eq!(
        report["stage_three_primary_acceptance_criteria"],
        serde_json::json!(STAGE_THREE_PRIMARY_ACCEPTANCE_CRITERIA)
    );
    // Der Schluessel heisst `declared_fault_points` wie in Stufe 2: das
    // Berichtsschema wird ERGAENZT, nie umbenannt, und der Inhalt ist derselbe.
    let declared = report["declared_fault_points"]
        .as_array()
        .expect("the gate must report the declared scenarios");
    for scenario in STAGE_THREE_SCENARIOS {
        assert!(
            declared.iter().any(|value| value == scenario),
            "the declared scenarios must carry {scenario}; stdout: {stdout}"
        );
    }
    assert_eq!(
        declared.len(),
        STAGE_THREE_SCENARIOS.len(),
        "the manifest declares exactly the nine scenarios; stdout: {stdout}"
    );
    assert!(
        report["stage_three_rows_still_planned"]
            .as_array()
            .unwrap()
            .is_empty(),
        "no stage 3 ledger row may still be planned; stdout: {stdout}"
    );
    // Und jeder der neun Zeugen ist AUFGELOEST — Datei und Funktionsname.
    // Ohne diese Zeile bliebe `witness` ein Feld, das nichts liest.
    let witnesses = report["stage_three_fault_point_witnesses"]
        .as_array()
        .expect("the gate must report the resolved witnesses");
    assert_eq!(
        witnesses.len(),
        STAGE_THREE_SCENARIOS.len(),
        "every declared scenario resolves to exactly one witness; stdout: {stdout}"
    );

    // Phase 2: der Gate-Bericht fehlt UND eine Stufe-3-Zeile steht wieder auf
    // `planned`. Der Gate nennt BEIDE in EINER Fehlermeldung — sonst
    // begruendete der RED-Schritt der Stufenabnahme nur den ersten Mangel.
    let root = stage_three_fixture("stage-three-two-gaps");
    fs::remove_file(root.join(STAGE_THREE_GATE_REPORT_PATH)).unwrap();
    write_stage_three_ledger(&root, Some("FR-081"));
    let output = run_stage_gate(&root, "3");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2));
    for expected in [
        STAGE_THREE_GATE_REPORT_PATH,
        "stage 3 requirement ledger rows still on planned: FR-081",
    ] {
        assert!(
            stderr.contains(expected),
            "stage-gate 3 must name {expected} in the same failure; stderr: {stderr}"
        );
    }

    // Phase 3: das Szenarienmanifest verliert seinen Rueckspielabschnitt. Der
    // Abschnitt traegt GENAU EINEN Eintrag, und genau deshalb muss er benannt
    // werden koennen: ein einzelner Eintrag verschwindet sonst lautlos.
    let root = stage_three_fixture("stage-three-manifest");
    // Ueber den Helfer und nicht mehr INLINE: die Stufe 4 faehrt denselben
    // Schritt gegen ihren Abschnitt `file-mode`, und zwei Abschriften
    // derselben vier Zeilen waeren die erste, die auseinanderlaeuft.
    remove_fault_point_section(&root, STAGE_THREE_FAULT_POINTS_PATH, "restore");
    let output = run_stage_gate(&root, "3");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("restore"),
        "stage-gate 3 must name the missing manifest section; stderr: {stderr}"
    );

    // Phase 3b: ein Zeuge wird umbenannt. GENAU der Fall, den es vorher nicht
    // gab: das Manifest bleibt formal vollstaendig, die Testfunktion heisst
    // aber nicht mehr so — und die Fehlermatrix waere ohne diese Pruefung ein
    // Dokument statt eines Gates.
    let root = stage_three_fixture("stage-three-renamed-witness");
    let manifest = fs::read_to_string(root.join(STAGE_THREE_FAULT_POINTS_PATH)).unwrap();
    let renamed = manifest.replace(
        "::a_tls12_only_client_handshake_is_rejected",
        "::a_tls12_only_client_handshake_is_rejected_renamed",
    );
    assert_ne!(
        manifest, renamed,
        "the fixture must really rename a witness"
    );
    fs::write(root.join(STAGE_THREE_FAULT_POINTS_PATH), renamed).unwrap();
    let output = run_stage_gate(&root, "3");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("a_tls12_only_client_handshake_is_rejected_renamed"),
        "stage-gate 3 must name the witness that no longer resolves; stderr: {stderr}"
    );

    // Phase 3c: ein Zeuge zeigt auf eine Funktion, die es gibt — aber ohne
    // Testattribut. Ein Hilfsfunktionsname ist kein Zeuge.
    let root = stage_three_fixture("stage-three-witness-without-attribute");
    let manifest = fs::read_to_string(root.join(STAGE_THREE_FAULT_POINTS_PATH)).unwrap();
    let helper = manifest.replace(
        "apps/server/tests/fault_scenarios.rs::a_tls12_only_client_handshake_is_rejected",
        "apps/server/tests/fault_scenarios.rs::main",
    );
    assert_ne!(manifest, helper, "the fixture must really point elsewhere");
    fs::write(root.join(STAGE_THREE_FAULT_POINTS_PATH), helper).unwrap();
    fs::write(
        root.join("apps/server/tests/fault_scenarios.rs"),
        "fn main() {}\n",
    )
    .unwrap();
    let output = run_stage_gate(&root, "3");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("#[test]"),
        "stage-gate 3 must say why a plain function is no witness; stderr: {stderr}"
    );

    // Phase 4: die Serverspur fehlt in der Wurzel-`package.json`. Ohne
    // `test:server` haette die Stufe keine ausfuehrbare Serverspur, und jede
    // Serverzusage waere danach unbelegt.
    let root = stage_three_fixture("stage-three-scripts");
    write_package_manifest(&root, &["stage-gate:3", "supply-chain", "verify:quick"]);
    let output = run_stage_gate(&root, "3");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("test:server"),
        "stage-gate 3 must name the missing server script; stderr: {stderr}"
    );

    // Phase 5: die additive Vektorfamilie fehlt.
    let root = stage_three_fixture("stage-three-family");
    fs::remove_dir_all(root.join("vectors/web-bundle")).unwrap();
    let output = run_stage_gate(&root, "3");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("web-bundle"),
        "stage-gate 3 must name the missing vector family; stderr: {stderr}"
    );
}

/// Die ACHT Kommandos der Schritt-4-Folge dieses Plans, in genau der
/// Reihenfolge, in der der Plan sie vorschreibt.
///
/// `integration up` steht zuerst und `integration down` zuletzt: dieser Task
/// ist der einzige der Stufe, der die Dienste wieder abraeumt, und die
/// Belegzeile haelt beides fest.
const STAGE_THREE_STEP_SIX_COMMANDS: [&str; 8] = [
    "cargo run --locked -p xtask -- integration up",
    "pnpm test:server",
    "cargo test --locked -p einsatzarchiv-server --test privacy_canaries_server",
    "cargo test --locked -p einsatzarchiv-server --test backup_restore_server_restore",
    "pnpm supply-chain",
    "pnpm stage-gate:3",
    "pnpm verify:quick",
    "cargo run --locked -p xtask -- integration down",
];

/// Die zwei Zahlen, die der Stufe-3-Gate-Bericht in seiner
/// `pnpm verify:quick`-Belegzeile TATSAECHLICH protokolliert, in seiner eigenen
/// Schreibweise: `ACHT Teilkommandos` und `der wasm32-Check ueber die ZEHN
/// Pakete der Positivliste`.
///
/// Historische LITERALE und keine LIVE gezaehlten Werte, aus dem Grund, den
/// [`STAGE_TWO_MEASURED_SUBCOMMAND_COUNT`] ausschreibt. Fuer die wasm32-Zahl
/// war die Kollision zusaetzlich HART: die Nachschlagetabelle der deutschen
/// Zahlwoerter deckte die Indizes `0..=12`, und die dreizehn Pakete der
/// gewachsenen Positivliste haetten den Test PANIKEN lassen statt eine Aussage
/// zu treffen. `docs/traceability/stage-3-gate.md` ist eine ABGESCHLOSSENE
/// Ausfuehrungsaufzeichnung und wird nicht umgeschrieben.
const STAGE_THREE_MEASURED_COUNTS: [(&str, &str); 2] =
    [("ACHT", "subcommands"), ("ZEHN", "wasm32 packages")];

/// Haelt fest, dass der Stufe-3-Gate-Bericht den vorgeschriebenen vollen Lauf
/// GEMESSEN protokolliert statt ihn zu behaupten.
///
/// Er lebt hier und nicht im Gate, aus dem Grund, den Stufe 1 schon
/// entschieden hat: der protokollierte Lauf enthaelt `pnpm stage-gate:3` und
/// `pnpm verify:quick` selbst, und ein Gate, der seine eigene Messzeile
/// verlangte, koennte auf dem Lauf, der sie erzeugt, nie gruen sein.
#[test]
fn stage_three_gate_report_records_the_measured_full_gate_run() {
    let report = fs::read_to_string(workspace_root().join(STAGE_THREE_GATE_REPORT_PATH))
        .expect("the stage 3 gate report must be readable");
    // NUR die Belegtabelle, nicht die Untertabellen des Abschnitts.
    //
    // `measured_run_rows` liest bis zur naechsten `## `-Ueberschrift, und der
    // Stufe-3-Abschnitt fuehrt darunter die `### `-Unterabschnitte (a) bis (f)
    // — darin die Lizenztabelle mit ihren vierzehn Zeilen. Ohne diesen Schnitt
    // zaehlte die Stelligkeitszusicherung unten 24 statt 9 (gemessen). Der
    // Schnitt steht HIER und nicht in `measured_run_rows`: die Stufen 1 und 2
    // fuehren unter ihrer Belegtabelle keine Untertabelle, und ihre beiden
    // Tests sollen sich durch diesen Task nicht aendern.
    let heading_at = report
        .find(MEASURED_RUN_HEADING)
        .expect("the stage 3 gate report must carry the measured run section");
    let section_end = report[heading_at..]
        .find("\n### ")
        .map_or(report.len(), |offset| heading_at + offset);
    let rows = measured_run_rows(&report[heading_at..section_end]);
    for command in STAGE_THREE_STEP_SIX_COMMANDS {
        let matching: Vec<&Vec<String>> =
            rows.iter().filter(|row| row[0].contains(command)).collect();
        assert_eq!(
            matching.len(),
            1,
            "stage-3-gate.md must record the measured run for `{command}` exactly once"
        );
        let row = matching[0];
        assert!(row.len() >= 4, "{row:?}");
        assert_eq!(
            row[1], "0",
            "`{command}` must have ended with exit code 0: {row:?}"
        );
        assert!(!row[2].is_empty(), "{row:?}");
        assert!(
            !row[2].contains("0 passed"),
            "`0 passed; N filtered out` is a broken filter, not a result: {row:?}"
        );
        // Die vierte Spalte ist die gemessene LAUFZEIT. Sie ist der Grund, aus
        // dem diese Tabelle „gemessen" heisst, und eine leere Zelle machte die
        // Zeile zu einer Behauptung.
        assert!(
            !row[3].is_empty(),
            "`{command}` must carry a measured runtime: {row:?}"
        );
    }
    assert_eq!(rows.len(), STAGE_THREE_STEP_SIX_COMMANDS.len() + 1);

    // Die Belegzeile von `pnpm verify:quick` traegt ZWEI ausgeschriebene
    // Zahlen: die der Teilkommandos und die der Pakete auf der
    // wasm32-Positivliste. Beide stehen als historisches Literal in
    // [`STAGE_THREE_MEASURED_COUNTS`] und werden nicht mehr LIVE an der Quelle
    // gezaehlt — die Begruendung traegt diese Konstante.
    let verify_quick: Vec<&Vec<String>> = rows
        .iter()
        .filter(|row| row[0].contains("pnpm verify:quick"))
        .collect();
    assert_eq!(verify_quick.len(), 1);
    let cell = &verify_quick[0][2];
    for (expected, what) in STAGE_THREE_MEASURED_COUNTS {
        assert!(
            cell.contains(expected),
            "the verify:quick evidence cell must spell out the number of {what} that the stage 3 \
             run actually measured ({expected}); cell: {cell}"
        );
    }

    // Und die Auflegung, gegen die gemessen wurde, IM Abschnitt des
    // gemessenen Laufs — samt seiner Unterabschnitte, denn dort steht sie.
    //
    // Die Zusicherung ist bewusst auf den Abschnitt GESCHNITTEN und nicht auf
    // den ganzen Bericht: die woertliche Reichweitenklausel prueft der Gate
    // selbst in Abschnitt 2, und eine zweite Suche ueber das ganze Dokument
    // waere davon bedient und belegte nichts. Was hier zaehlt, ist, dass der
    // GEMESSENE Lauf seine Auflegung benennt.
    let measured_section_end = report[heading_at..]
        .find("\n## ")
        .map_or(report.len(), |offset| heading_at + offset);
    assert!(
        report[heading_at..measured_section_end].contains("Auflegung A"),
        "the measured run section of stage-3-gate.md must name the deployment it ran against"
    );
}

// ---------------------------------------------------------------------------
// Stufe 4 — „Browser-Reader".
//
// Dieselbe Zweiteilung wie in den Stufen 2 und 3: der ZIELzustandstest liest
// den ECHTEN Arbeitsbaum, die Mangelphasen laufen gegen ein Fixture und halten
// je EINEN Fehlerzustand fest.
// ---------------------------------------------------------------------------

/// Die Vektorfamilien der Stufe 4 — KEINE.
///
/// Leer und das ist die Aussage: Stufe 4 friert keine Familie ein.
/// `vectors/crypto/suite-1/`, `vectors/trust/v1/` und `vectors/web-bundle/v1/`
/// werden ausschliesslich GELESEN; die ersten beiden sind Stufe-1-Familien, die
/// dritte hat Stufe 3 eingefroren. Der Gate MUSS trotzdem ein leeres Array
/// ausweisen, statt den Schluessel wegzulassen — ein fehlender Schluessel waere
/// von einem Bericht ohne Vektorabschnitt nicht zu unterscheiden.
const STAGE_FOUR_FAMILIES: [&str; 0] = [];

/// Die drei primaeren Abnahmekriterien der Stufe 4.
const STAGE_FOUR_PRIMARY_ACCEPTANCE_CRITERIA: [u32; 3] = [10, 42, 43];

/// Die sechs Skripte, die die Wurzel-`package.json` fuer Stufe 4 fuehren MUSS.
const STAGE_FOUR_SCRIPTS: [&str; 6] = [
    "stage-gate:4",
    "supply-chain",
    "test:reader",
    "verify:quick",
    "web:browser-test",
    "web:e2e",
];

/// Der Stufe-4-Gate-Bericht und das Szenarienmanifest, relativ zur Gate-Wurzel.
const STAGE_FOUR_GATE_REPORT_PATH: &str = "docs/traceability/stage-4-gate.md";
const STAGE_FOUR_FAULT_POINTS_PATH: &str = "docs/traceability/stage-4-fault-points.json";

/// Die ZWEIUNDDREISSIG Szenarien, die das Manifest deklarieren MUSS — als
/// LITERALE, lexikografisch.
///
/// Sie stehen hier ausgeschrieben und nicht aus dem Manifest gelesen, aus dem
/// Grund, den [`STAGE_THREE_SCENARIOS`] ausschreibt: gegen sich selbst
/// verglichen koennte ein Manifest mit einem einzigen Szenario beide Zusagen
/// erfuellen und gruen melden.
const STAGE_FOUR_SCENARIOS: [&str; 32] = [
    "aborted-authenticator-confirmation",
    "after-batch-request",
    "after-blob-store-flush",
    "after-chain-verification",
    "after-cursor-persist",
    "after-first-object-write",
    "after-start-head-check",
    "audit-failure-after-bytes-left",
    "background-tab-before-write",
    "before-batch-request",
    "before-blob-store-flush",
    "before-chain-verification",
    "before-cursor-persist",
    "before-object-write",
    "before-start-head-check",
    "bundle-truncated",
    "directory-permission-revoked",
    "foreign-root-candidate",
    "historical-grant-unresolvable",
    "lock-during-target-choice",
    "missing-own-grant",
    "opfs-write-aborted-by-storage-pressure",
    "own-thumbprint-wrong-material",
    "refusal-leaves-the-cursor",
    "revoked-release",
    "stale-trust-state",
    "stale-witness",
    "stub-without-authorization",
    "substituted-archive",
    "substituted-archive-own-trust-chain",
    "tab-closed-mid-batch",
    "unsigned-candidate",
];

/// Die Zahl der VERSCHIEDENEN Zeugen, die das Stufe-4-Manifest fuehren MUSS.
///
/// Sie ist NICHT die Zahl der Szenarien, und die Differenz ist gemessen:
/// `resolved_fault_point_witnesses` in `tools/xtask/src/main.rs` sammelt in ein
/// `BTreeSet<String>`, und ZWOELF der fuenfzehn Szenarien des Abschnitts
/// `sync-cursor` teilen EINEN Zeugen — die Abbruchpunkte des Sync-Laufs sind
/// Rahmen DESSELBEN Durchlaufs, und ein eigener Zeuge je Rahmen waere
/// zwoelfmal dieselbe Aussage. Das Stufe-4-Manifest deklariert deshalb
/// 32 Szenarien und 21 verschiedene Zeugen.
///
/// AUSGESCHRIEBEN und nicht abgeleitet, aus genau dem Grund, den
/// [`STAGE_FOUR_SCENARIOS`] fuer die Szenarien ausschreibt: eine ABGELEITETE
/// Zahl liest dasselbe Manifest, das auch der Gate liest, also kann die
/// Gleichheit zwischen beiden eine falsche Zahl nie finden. GEMESSEN am
/// 2026-09-05 durch Mutation: wer alle zweiunddreissig `witness`-Felder auf
/// EINEN vorhandenen Test umschreibt, bekommt `pnpm stage-gate:4` mit
/// Exitcode 0 und EINEM ausgewiesenen Zeugen, und alle achtzehn Tests dieser
/// Datei bleiben gruen. Einunddreissig Szenarien waeren damit stillschweigend
/// wieder ein Dokument — genau das, was `resolved_fault_point_witnesses`
/// verhindern soll.
///
/// Wer einen Zeugen aufteilt oder zusammenlegt, hebt die Zahl HIER in
/// DERSELBEN Aufgabe. Das ist kein Nachteil, sondern der Zweck: die Aenderung
/// wird an einer Stelle sichtbar, die ein Mensch liest.
const STAGE_FOUR_DISTINCT_WITNESSES: usize = 21;

/// Die Zeugen eines Szenarienmanifests, je Abschnitt und in Manifestreihenfolge.
///
/// Getrennt nach Abschnitt und nicht als eine Menge, weil die schaerfere
/// Zusage der Stufe 4 abschnittsweise faellt: GENAU EIN Abschnitt teilt Zeugen
/// (`sync-cursor`), und in den uebrigen vieren steht je Szenario ein eigener.
fn witnesses_by_section(root: &Path, manifest_path: &str) -> Vec<(String, Vec<String>)> {
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(root.join(manifest_path)).unwrap()).unwrap();
    let mut sections = Vec::new();
    for (section, value) in manifest.as_object().unwrap() {
        if section == "stage" {
            continue;
        }
        let witnesses = value
            .as_array()
            .into_iter()
            .flatten()
            .map(|entry| entry["witness"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        sections.push((section.clone(), witnesses));
    }
    sections
}

/// Die Zahl der VERSCHIEDENEN Zeugen, wie sie im Manifest wirklich steht.
///
/// Sie belegt fuer sich genommen nichts — der Gate leitet seine eigene Zahl
/// aus derselben Datei ab. Tragend wird sie erst gegen
/// [`STAGE_FOUR_DISTINCT_WITNESSES`] gestellt.
fn distinct_witnesses_in(root: &Path, manifest_path: &str) -> usize {
    let mut witnesses: Vec<String> = Vec::new();
    for (_, section_witnesses) in witnesses_by_section(root, manifest_path) {
        for witness in section_witnesses {
            if !witnesses.contains(&witness) {
                witnesses.push(witness);
            }
        }
    }
    assert!(
        !witnesses.is_empty(),
        "{manifest_path} must name witnesses, or this counter measures nothing"
    );
    witnesses.len()
}

/// Schreibt das Requirement-Ledger des Stufe-4-Fixtures.
///
/// Wie [`write_stage_three_ledger`], nur gegen die Stufenspalte `4`:
/// Grundlage ist das ECHTE eingecheckte Ledger, und `reopened` stellt GENAU
/// EINE Stufe-4-Zeile zurueck auf `planned`.
fn write_stage_four_ledger(root: &Path, reopened: Option<&str>) {
    let source = fs::read_to_string(workspace_root().join(REQUIREMENT_LEDGER_RELATIVE))
        .expect("the requirement ledger must be readable");
    let mut lines = Vec::new();
    let mut reopened_rows = 0_usize;
    for (index, line) in source.lines().enumerate() {
        if index == 0 || line.is_empty() {
            lines.push(line.to_owned());
            continue;
        }
        let mut fields = ledger_fields(line);
        if Some(fields[0].as_str()) == reopened && fields[7] == "4" {
            fields[8] = "planned".to_owned();
            reopened_rows += 1;
        }
        lines.push(format!("\"{}\"", fields.join("\",\"")));
    }
    if let Some(identifier) = reopened {
        assert_eq!(
            reopened_rows, 1,
            "the fixture must really reopen exactly one stage 4 row for {identifier}"
        );
    }
    let path = root.join(REQUIREMENT_LEDGER_RELATIVE);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
}

/// Baut eine gruene Stufe-4-Grundlage.
///
/// Nach dem Muster von [`stage_three_fixture`], mit EINEM Unterschied: es wird
/// keine Vektorfamilie angelegt, weil Stufe 4 keine einfriert.
fn stage_four_fixture(label: &str) -> PathBuf {
    let root = fixture_root(label);
    copy_from_the_workspace(&root, DESIGN_DOCUMENT_RELATIVE);
    copy_from_the_workspace(&root, STAGE_FOUR_FAULT_POINTS_PATH);
    copy_from_the_workspace(&root, STAGE_FOUR_GATE_REPORT_PATH);
    for witness in fault_point_witness_files(&root, STAGE_FOUR_FAULT_POINTS_PATH) {
        copy_from_the_workspace(&root, &witness);
    }
    write_stage_four_ledger(&root, None);
    write_package_manifest(&root, &STAGE_FOUR_SCRIPTS);
    root
}

/// Haelt fest, dass `stage-gate 4` die zwei Reader, die Browsermatrix und den
/// Datei-Modus verlangt.
///
/// Phase 1 laeuft gegen den ECHTEN Arbeitsbaum und haelt den ZIELzustand fest;
/// die beiden Mangelphasen laufen gegen ein Fixture. Wie die Stufe-3-Phasen
/// braucht KEINE davon einen laufenden Dienst, einen Browser oder einen
/// `chromedriver`: der Gate liest Dokumente, das Ledger und ein Manifest.
#[test]
fn stage_four_gate_requires_two_readers_the_browser_matrix_and_the_file_mode() {
    // Phase 1: der echte Arbeitsbaum.
    let output = run_stage_gate_in_the_workspace("4");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        output.status.success(),
        "stage-gate 4 must accept the checked-in tree; stderr: {stderr}"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let report: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("stdout must be JSON: {error}; stdout: {stdout}"));

    assert_eq!(report["stage"], serde_json::json!(4));
    assert_eq!(
        report["stage_four_primary_acceptance_criteria"],
        serde_json::json!(STAGE_FOUR_PRIMARY_ACCEPTANCE_CRITERIA)
    );
    // Der Schluessel steht mit einem LEEREN Array da und fehlt nicht.
    assert_eq!(
        report["vector_families"],
        serde_json::json!(STAGE_FOUR_FAMILIES)
    );

    let declared = report["declared_fault_points"]
        .as_array()
        .expect("the gate must report the declared scenarios");
    for scenario in STAGE_FOUR_SCENARIOS {
        assert!(
            declared.iter().any(|value| value == scenario),
            "the declared scenarios must carry {scenario}; stdout: {stdout}"
        );
    }
    assert_eq!(
        declared.len(),
        STAGE_FOUR_SCENARIOS.len(),
        "the manifest declares exactly the thirty-two scenarios; stdout: {stdout}"
    );
    // Die Zeugen. Die Zahl ist die der VERSCHIEDENEN Zeugen und nicht die der
    // Szenarien — ZWOELF Szenarien des Abschnitts `sync-cursor` teilen EINEN
    // Zeugen —, und sie steht in [`STAGE_FOUR_DISTINCT_WITNESSES`]
    // AUSGESCHRIEBEN. Beide Seiten werden gegen die Konstante gestellt und
    // nicht gegeneinander: Manifest und Gate lesen dieselbe Datei, eine
    // Gleichheit zwischen ihnen ginge auch dann durch, wenn alle
    // zweiunddreissig Szenarien auf EINEN Zeugen zeigten.
    assert_eq!(
        distinct_witnesses_in(&workspace_root(), STAGE_FOUR_FAULT_POINTS_PATH),
        STAGE_FOUR_DISTINCT_WITNESSES,
        "{STAGE_FOUR_FAULT_POINTS_PATH} must name exactly \
         {STAGE_FOUR_DISTINCT_WITNESSES} distinct witnesses"
    );
    assert_eq!(
        report["stage_four_fault_point_witnesses"]
            .as_array()
            .expect("the gate must report the resolved witnesses")
            .len(),
        STAGE_FOUR_DISTINCT_WITNESSES,
        "the gate must resolve all {STAGE_FOUR_DISTINCT_WITNESSES} distinct witnesses; \
         stdout: {stdout}"
    );

    // Die schaerfere Zusage, und sie ist GEMESSEN: geteilte Zeugen sind die
    // Ausnahme EINES Abschnitts. `sync-cursor` fuehrt fuenfzehn Abbruchpunkte
    // desselben Durchlaufs auf vier Zeugen; die uebrigen vier Abschnitte
    // (`bundle-activation` 4, `verification` 6, `file-mode` 3,
    // `session-and-export` 4) tragen je Szenario einen EIGENEN. Ohne diese
    // Zusicherung deckte die Gesamtzahl 21 auch eine Verteilung, in der ein
    // weiterer Abschnitt still zusammenfaellt, solange `sync-cursor` sich im
    // Gegenzug aufteilt.
    for (section, witnesses) in
        witnesses_by_section(&workspace_root(), STAGE_FOUR_FAULT_POINTS_PATH)
    {
        let mut distinct = witnesses.clone();
        distinct.sort_unstable();
        distinct.dedup();
        if section == "sync-cursor" {
            assert!(
                distinct.len() < witnesses.len(),
                "the sync-cursor section is the ONE section that shares witnesses; if it stopped \
                 sharing, this exception has to go instead of being carried along: \
                 {} points, {} distinct",
                witnesses.len(),
                distinct.len()
            );
            continue;
        }
        assert_eq!(
            distinct.len(),
            witnesses.len(),
            "outside sync-cursor every scenario must carry its OWN witness; the {section} section \
             names {} points on {} distinct witnesses",
            witnesses.len(),
            distinct.len()
        );
    }
    assert!(
        report["stage_four_rows_still_planned"]
            .as_array()
            .unwrap()
            .is_empty(),
        "no stage 4 ledger row may still be planned; stdout: {stdout}"
    );

    // Phase 2: der Gate-Bericht fehlt UND eine Stufe-4-Zeile steht wieder auf
    // `planned`. Der Gate nennt BEIDE in EINER Fehlermeldung.
    let root = stage_four_fixture("stage-four-two-gaps");
    fs::remove_file(root.join(STAGE_FOUR_GATE_REPORT_PATH)).unwrap();
    write_stage_four_ledger(&root, Some("FR-103"));
    let output = run_stage_gate(&root, "4");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    for expected in [
        STAGE_FOUR_GATE_REPORT_PATH,
        "stage 4 requirement ledger rows still on planned: FR-103",
    ] {
        assert!(
            stderr.contains(expected),
            "stage-gate 4 must name {expected} in the same failure; stderr: {stderr}"
        );
    }

    // Phase 3: das Szenarienmanifest verliert seinen Datei-Modus-Abschnitt.
    let root = stage_four_fixture("stage-four-manifest");
    remove_fault_point_section(&root, STAGE_FOUR_FAULT_POINTS_PATH, "file-mode");
    let output = run_stage_gate(&root, "4");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("file-mode"),
        "stage-gate 4 must name the missing manifest section; stderr: {stderr}"
    );
}

/// Die SECHZEHN Kommandos der Schritt-4-Folge dieses Plans, in genau der
/// Reihenfolge, in der der Plan sie vorschreibt.
///
/// `cargo metadata --format-version 1` steht ganz vorn und ist das GENAU EINE
/// Kommando dieser Stufe ohne `--locked`: die Dev-Kante `ea-reader` in
/// `tests/ea-system-tests/Cargo.toml` schreibt `Cargo.lock` fort, und jedes
/// Kommando danach — `integration up` eingeschlossen — fiele sonst an einem
/// ueberholten Lockfile. `integration up` steht deshalb an zweiter und
/// `integration down` an letzter Stelle; `browsers up` … `browsers down` aus
/// ADR 0005 klammern die zwei Kommandos, die Engine-Baus und einen
/// `chromedriver` voraussetzen.
const STAGE_FOUR_STEP_SIX_COMMANDS: [&str; 17] = [
    "cargo metadata --format-version 1",
    "cargo run --locked -p xtask -- integration up",
    "cargo run --locked -p xtask -- browsers up",
    "pnpm build:wasm",
    "pnpm test:reader",
    "pnpm index:scale",
    "pnpm web:browser-test",
    "cargo test --locked -p ea-system-tests --test cross_platform_two_readers",
    "cargo test --locked -p ea-system-tests --test e2e_reader_sync_interruptions",
    "cargo test --locked -p ea-system-tests --test reader_file_mode_interop",
    "cargo test --locked -p ea-system-tests --test privacy_canaries_reader",
    "pnpm web:e2e",
    "pnpm supply-chain",
    "pnpm stage-gate:4",
    "pnpm verify:quick",
    "cargo run --locked -p xtask -- browsers down",
    "cargo run --locked -p xtask -- integration down",
];

/// Die deutschen Zahlwoerter in der Schreibweise der Belegzeile, indiziert mit
/// der Zahl selbst.
///
/// Der Bericht schreibt die Zahl aus und in Grossbuchstaben (`ZWOELF
/// Teilkommandos gruen`), also vergleicht der Test gegen genau diese
/// Schreibweise und nicht gegen `12`.
///
/// `[&str; 15]` und nicht mehr `[&str; 13]`: die Stufe faehrt gemessen ZWOELF
/// Teilkommandos und VIERZEHN wasm32-Pakete, der hoechste gebrauchte Index ist
/// also 14. Die alte Stelligkeit deckte nur `0..=12` und haette an `get(14)`
/// mit `None` PANIKT, statt ein Urteil zu faellen. Wer den Zaehler spaeter
/// weiter treibt, hebt die Stelligkeit in DERSELBEN Aufgabe.
const GERMAN_COUNT_WORDS: [&str; 15] = [
    "NULL", "EIN", "ZWEI", "DREI", "VIER", "FUENF", "SECHS", "SIEBEN", "ACHT", "NEUN", "ZEHN",
    "ELF", "ZWOELF", "DREIZEHN", "VIERZEHN",
];

/// Zaehlt die Teilkommandos von `verify_quick_commands()` an dem zeichengenauen
/// Pin, der sie festhaelt.
///
/// Gezaehlt wird am PIN und nicht am Rumpf der Funktion: der Rumpf traegt
/// zwischen den Tupeln Kommentare, und einer davon nennt woertlich
/// `Command::new("pnpm")` — jede Zaehlung ueber die Programmliterale des Rumpfs
/// verzaehlte sich daran. Der Pin traegt keinen Kommentar, und
/// `verify_quick_uses_the_required_locked_commands` (Unit-Test in
/// `tools/xtask/src/main.rs`) haelt ihn zeichengenau gegen die Funktion — wer
/// die Funktion aendert und den Pin nicht, wird DORT rot und nicht hier.
///
/// Gezaehlt wird ueber die Klammerbilanz und nicht ueber die Programmnamen: ein
/// Tupel ist ein `(`, das auf der aeussersten Ebene des `vec![` oeffnet. Das
/// bleibt richtig, gleichgueltig wie rustfmt die Liste bricht.
fn verify_quick_subcommand_count() -> usize {
    const CALL: &str = "super::verify_quick_commands(),";

    let source = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"))
        .expect("the xtask source must be readable");
    let at = source
        .find(CALL)
        .unwrap_or_else(|| panic!("the xtask source must pin the commands with `{CALL}`"));
    let list_at = at
        + source[at..]
            .find("vec![")
            .unwrap_or_else(|| panic!("`{CALL}` must be pinned against a `vec![` literal"))
        + "vec![".len();

    let mut depth = 0_i32;
    let mut in_string = false;
    let mut count = 0_usize;
    for character in source[list_at..].chars() {
        // Ein `\` im Pin brachte die Zeichenkettenbilanz aus dem Tritt und
        // damit die Zaehlung; der Pin traegt keines, und wenn eines dazukaeme,
        // soll dieser Zaehler abbrechen statt falsch zu zaehlen.
        assert!(
            character != '\\',
            "the pin of verify_quick_commands() must not carry an escape sequence, or this counter \
             would misread it"
        );
        if character == '"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        match character {
            '(' => {
                if depth == 0 {
                    count += 1;
                }
                depth += 1;
            }
            '[' => depth += 1,
            ')' => depth -= 1,
            ']' => {
                if depth == 0 {
                    return count;
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    panic!("the pin of verify_quick_commands() must be closed");
}

/// Zaehlt die Pakete der wasm32-Positivliste an demselben zeichengenauen Pin,
/// an dem [`verify_quick_subcommand_count`] die Teilkommandos zaehlt.
///
/// Ein Paket ist ein `"-p"` NACH dem Zielliteral `"wasm32-unknown-unknown"`
/// im Pin, und die Einschraenkung ist eine KORREKTUR, keine Verzierung: die
/// bis Stufe 3 gefahrene Fassung zaehlte `"-p"` ueber den GANZEN Pin und
/// begruendete das damit, die Positivliste sei „die einzige Stelle der Liste,
/// die `-p` fuehrt". Gemessen am 2026-09-05 ist das nicht mehr wahr — das
/// Teilkommando `cargo run --locked -p xtask -- build-wasm` steht seit der
/// wasm-Aufgabe in derselben Liste und traegt sein eigenes `-p`. Die alte
/// Zaehlung ergaebe heute 15 statt 14 und wuerde damit ein VIERZEHN im
/// Bericht abweisen, das richtig ist. Der wasm32-Check steht als letztes
/// Tupel der Liste, also reicht der Schnitt am Zielliteral.
///
/// `verify_quick_uses_the_required_locked_commands` (Unit-Test in
/// `tools/xtask/src/main.rs`) haelt den Pin zeichengenau gegen die Funktion —
/// wer die Funktion aendert und den Pin nicht, wird DORT rot und nicht hier.
fn wasm32_positive_list_count() -> usize {
    const CALL: &str = "super::verify_quick_commands(),";
    const TARGET: &str = "\"wasm32-unknown-unknown\"";

    let source = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"))
        .expect("the xtask source must be readable");
    let at = source
        .find(CALL)
        .unwrap_or_else(|| panic!("the xtask source must pin the commands with `{CALL}`"));
    let list_at = at
        + source[at..]
            .find("vec![")
            .unwrap_or_else(|| panic!("`{CALL}` must be pinned against a `vec![` literal"))
        + "vec![".len();
    let end = source[list_at..]
        .find("\n            ]\n        );")
        .unwrap_or_else(|| panic!("the pin of verify_quick_commands() must be closed"));
    let pin = &source[list_at..list_at + end];
    let target_at = pin
        .find(TARGET)
        .unwrap_or_else(|| panic!("the pin must carry the wasm32 check with {TARGET}"));
    let count = pin[target_at..].matches("\"-p\"").count();
    assert!(
        count > 0,
        "the pin must carry the wasm32 positive list, or this counter measures nothing"
    );
    count
}

/// Haelt fest, dass der Stufe-4-Gate-Bericht den vorgeschriebenen vollen Lauf
/// GEMESSEN protokolliert statt ihn zu behaupten.
///
/// Er lebt hier und nicht im Gate, aus dem Grund, den Stufe 1 schon
/// entschieden hat: der protokollierte Lauf enthaelt `pnpm stage-gate:4` und
/// `pnpm verify:quick` selbst, und ein Gate, der seine eigene Messzeile
/// verlangte, koennte auf dem Lauf, der sie erzeugt, nie gruen sein.
///
/// Die zwei LIVE-Zaehler stehen HIER und nur hier: die abgeschlossenen
/// Berichte der Stufen 2 und 3 sind auf historische Literale umgestellt, weil
/// eine gemessene Zahl eine Aussage ueber den Lauf ist, der sie erzeugt hat.
/// Dieser Bericht ist der einzige noch OFFENE, also traegt er die Bindung an
/// die Quelle.
#[test]
fn stage_four_gate_report_records_the_measured_full_gate_run() {
    let report = fs::read_to_string(workspace_root().join(STAGE_FOUR_GATE_REPORT_PATH))
        .expect("the stage 4 gate report must be readable");
    let heading_at = report
        .find(MEASURED_RUN_HEADING)
        .expect("the stage 4 gate report must carry the measured run section");
    // Wie in Stufe 3 auf die Belegtabelle GESCHNITTEN: eine spaeter ergaenzte
    // `### `-Untertabelle darf die Stelligkeitszusicherung unten nicht
    // verfaelschen.
    let section_end = report[heading_at..]
        .find("\n### ")
        .map_or(report.len(), |offset| heading_at + offset);
    let rows = measured_run_rows(&report[heading_at..section_end]);
    for command in STAGE_FOUR_STEP_SIX_COMMANDS {
        let matching: Vec<&Vec<String>> =
            rows.iter().filter(|row| row[0].contains(command)).collect();
        assert_eq!(
            matching.len(),
            1,
            "stage-4-gate.md must record the measured run for `{command}` exactly once"
        );
        let row = matching[0];
        assert!(row.len() >= 4, "{row:?}");
        assert_eq!(
            row[1], "0",
            "`{command}` must have ended with exit code 0: {row:?}"
        );
        assert!(!row[2].is_empty(), "{row:?}");
        assert!(
            !row[2].contains("0 passed"),
            "`0 passed; N filtered out` is a broken filter, not a result: {row:?}"
        );
        assert!(
            !row[3].is_empty(),
            "`{command}` must carry a measured runtime: {row:?}"
        );
    }
    assert_eq!(rows.len(), STAGE_FOUR_STEP_SIX_COMMANDS.len() + 1);

    // Die Belegzeile von `pnpm verify:quick` traegt ZWEI Zahlen gegen ihre
    // QUELLE: die Zahl der Teilkommandos und die Zahl der Pakete auf der
    // wasm32-Positivliste. Beide stehen ausgeschrieben, beide werden am Pin
    // gezaehlt, und keine wird hier abgeschrieben.
    let verify_quick: Vec<&Vec<String>> = rows
        .iter()
        .filter(|row| row[0].contains("pnpm verify:quick"))
        .collect();
    assert_eq!(verify_quick.len(), 1);
    let cell = &verify_quick[0][2];
    for (count, what) in [
        (verify_quick_subcommand_count(), "subcommands"),
        (wasm32_positive_list_count(), "wasm32 packages"),
    ] {
        let expected = GERMAN_COUNT_WORDS.get(count).unwrap_or_else(|| {
            panic!("{what}: {count} is covered by no spelled-out number in GERMAN_COUNT_WORDS")
        });
        // Auf WORTGRENZEN verglichen und nicht als Teilkette, und der
        // Unterschied ist gemessen: `ZWOELF` enthaelt `ELF`, `VIERZEHN`
        // enthaelt `ZEHN` UND `VIER`, `DREIZEHN` enthaelt `DREI` und `ZEHN`.
        // Ein `contains` nahm deshalb einen UEBERTRIEBENEN Bericht an — mit
        // elf Teilkommandos in der Quelle und `ZWOELF` in der Zelle blieb
        // dieser Test gruen, obwohl das ehrliche Wort `ELF` gewesen waere.
        // Zerlegt wird an allem, was kein Buchstabe ist, weil die Zelle die
        // Zahl in Fliesstext traegt (`ZWOELF Teilkommandos gruen`).
        assert!(
            cell.split(|character: char| !character.is_alphabetic())
                .any(|word| word == *expected),
            "the verify:quick evidence cell must spell out the number of {what} that the source \
             actually carries ({count} = {expected}) as its own word; cell: {cell}"
        );
    }
}
