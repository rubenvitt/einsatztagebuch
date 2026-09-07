//! Das Verwaltungskommando `writer-transition prepare|activate`.
//!
//! # Zwei Messebenen, wie in `registry_workflows.rs`
//!
//! Gegen das GEBAUTE Binary wird gemessen, was den Prozess verlaesst:
//! Grammatikzeile, Exitcode, welcher Strom, welcher Code. Gegen die per
//! `#[path]` eingebundenen Einheiten [`args`] und [`output`] wird gemessen,
//! WELCHE Zuordnung der Parser trifft und WELCHE ZEILEN entstehen — ohne
//! Prozessstart und ohne Bestand.
//!
//! # Was hier NICHT gemessen wird — und warum
//!
//! Der Happy Path durch `OperatorRuntime::open`. Er braucht einen
//! provisionierten Bediener auf der Platte: einen verifizierten Bestand mit
//! aktivem Geraetezertifikat, eine verschluesselte Datenbank unter einem
//! OS-gebundenen Schluessel und einen signierten nativen Hilfsprozess. Die
//! einzige Kulisse dafuer wohnt PRIVAT in
//! `apps/cli/tests/operator.rs::process_native` (eine Kopie des Binaries,
//! ein Shell-Helfer, der das Testbinary als nativen Helfer wieder startet,
//! und `fixture_cli`, das ausschliesslich `Command::Operator` ueber
//! `run_with_runtime_opener` dispatcht). Sie ist weder ein Modul unter
//! `tests/support` noch auf ein anderes Kommando uebertragbar. Der
//! Laufzeitpfad wird deshalb bis zur Bedienerdatei und zum Anker gemessen —
//! genau wie `registry_workflows.rs` es fuer `revocation-plan` tut — und der
//! Vollzug gegen einen echten Kopf in
//! `crates/ea-admin/tests/writer_transition.rs`.
#![cfg(test)]

#[allow(dead_code)]
#[path = "../src/args.rs"]
mod args;
#[allow(dead_code)]
#[path = "../src/output.rs"]
mod output;

use std::{
    ffi::OsString,
    path::PathBuf,
    process::{Command as Process, Output},
};

use ea_types::{
    CertificateHash, ChainId, ChainSequence, EntryHash, Hash32, ObjectHash, OrganizationId,
    RegistryVersion, UnixMillis,
};

use args::{
    Command, Format, Invocation, NOT_AFTER_SWITCH, OPERATOR_CONFIG_SWITCH, REQUEST_SWITCH,
    TRANSITION_OBJECT_SWITCH, TRUST_ANCHOR_SWITCH, UsageError, VALID_THROUGH_SWITCH,
    WRITER_TRANSITION_ACTIVATE_SUBCOMMAND, WRITER_TRANSITION_PREPARE_COMMAND,
    WRITER_TRANSITION_PREPARE_SUBCOMMAND, parse,
};
use output::{WriterTransitionActivateView, WriterTransitionPrepareView};

/// Die beiden Grammatikzeilen, wie das Werkzeug sie druckt.
const PREPARE_GRAMMAR_LINE: &str = "einsatzarchiv --trust-anchor <file> writer-transition prepare \
     --operator-config <file> --request <file>";
const ACTIVATE_GRAMMAR_LINE: &str = "einsatzarchiv --trust-anchor <file> writer-transition \
     activate --operator-config <file> --request <file> --transition-object <file> \
     --valid-through <sequence> --not-after <unix-millis>";

// ---------------------------------------------------------------------------
// Hilfen
// ---------------------------------------------------------------------------

fn parsed(tokens: &[&str]) -> Result<Invocation, UsageError> {
    parse(tokens.iter().copied().map(OsString::from))
}

fn rejected(tokens: &[&str]) -> UsageError {
    parsed(tokens).expect_err("die Argumentfolge muss abgelehnt werden")
}

/// Startet das Werkzeug mit `tokens` und liefert seinen vollstaendigen Ausgang.
fn run(tokens: &[&str]) -> Output {
    Process::new(env!("CARGO_BIN_EXE_einsatzarchiv"))
        .args(tokens)
        .output()
        .expect("das Testbinary muss startbar sein")
}

fn hash32(byte: u8) -> Hash32 {
    Hash32::try_from([byte; 32].as_slice()).expect("32 Byte")
}

fn id16(byte: u8) -> [u8; 16] {
    [byte; 16]
}

/// Eine Vorbereitung, deren Zahlen und Bytes saemtlich verschieden sind,
/// damit eine vertauschte Zuordnung auffaellt.
fn prepare_view() -> WriterTransitionPrepareView {
    WriterTransitionPrepareView {
        organization_id: OrganizationId::try_from(id16(0x01).as_slice()).expect("16 Byte"),
        chain_id: ChainId::try_from(id16(0x02).as_slice()).expect("16 Byte"),
        old_writer_certificate_hash: CertificateHash::from(ObjectHash::from(hash32(0x11))),
        new_writer_certificate_hash: CertificateHash::from(ObjectHash::from(hash32(0x22))),
        trusted_head_chain_sequence: ChainSequence::new(41),
        trusted_head_entry_hash: EntryHash::from(hash32(0x33)),
        effective_from_sequence: ChainSequence::new(42),
        reason_code: 7,
        registry_version: RegistryVersion::new(5),
        registry_head_hash: ObjectHash::from(hash32(0x44)),
        admin_authorization_object_hash: None,
    }
}

/// Dieselbe Vorbereitung MIT dem Hash der erteilten Autorisierung.
fn bound_prepare_view() -> WriterTransitionPrepareView {
    WriterTransitionPrepareView {
        admin_authorization_object_hash: Some(ObjectHash::from(hash32(0x66))),
        ..prepare_view()
    }
}

/// Eine Aktivierung mit denselben Vorsichtsmassnahmen.
fn activate_view() -> WriterTransitionActivateView {
    WriterTransitionActivateView {
        registry_version: RegistryVersion::new(6),
        previous_registry_hash: Some(hash32(0x44)),
        effective_from_sequence: ChainSequence::new(42),
        valid_through_sequence: ChainSequence::new(200),
        issued_at: UnixMillis::new(1_000),
        not_before: UnixMillis::new(1_000),
        not_after: UnixMillis::new(10_000_000),
        transition_object_hash: ObjectHash::from(hash32(0x55)),
    }
}

/// Ein eigenes, leeres Arbeitsverzeichnis unter dem Temp-Pfad des Systems.
fn tempdir(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "einsatzarchiv-writer-transition-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("das Arbeitsverzeichnis muss anlegbar sein");
    directory
}

/// Eine Bedienerdatei in Form, mit einem Bestand, den es nicht gibt.
fn write_config(directory: &std::path::Path) -> PathBuf {
    let config = directory.join("operator.json");
    std::fs::write(
        &config,
        format!(
            r#"{{"archive_directory":"archive","database_path":"operator.sqlite","device_certificate_hash":"{}","binding_object_hash":"{}","role":"organization-admin","purpose":"admin-root-ceremony"}}"#,
            "11".repeat(32),
            "22".repeat(32)
        ),
    )
    .expect("die Bedienerdatei muss schreibbar sein");
    config
}

/// Eine Antragsdatei in Form — mit oder ohne Autorisierungshash.
fn write_request(directory: &std::path::Path, with_authorization: bool) -> PathBuf {
    let request = directory.join(if with_authorization {
        "transition-authorized.json"
    } else {
        "transition.json"
    });
    let authorization = if with_authorization {
        format!(
            r#","admin_authorization_object_hash":"{}""#,
            "66".repeat(32)
        )
    } else {
        String::new()
    };
    std::fs::write(
        &request,
        format!(
            r#"{{"old_writer_certificate_hash":"{}","new_writer_certificate_hash":"{}","trusted_head":{{"chain_sequence":41,"entry_hash":"{}"}},"reason_code":7{authorization}}}"#,
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32)
        ),
    )
    .expect("die Antragsdatei muss schreibbar sein");
    request
}

fn path_str(path: &std::path::Path) -> &str {
    path.to_str().expect("Testpfad ist UTF-8")
}

// ---------------------------------------------------------------------------
// 1. Der Parser
// ---------------------------------------------------------------------------

#[test]
fn writer_transition_prepare_parses_in_its_full_form() {
    assert_eq!(
        parsed(&[
            TRUST_ANCHOR_SWITCH,
            "anchor.etb",
            "writer-transition",
            WRITER_TRANSITION_PREPARE_SUBCOMMAND,
            OPERATOR_CONFIG_SWITCH,
            "operator.json",
            REQUEST_SWITCH,
            "transition.json"
        ])
        .expect("writer-transition prepare muss parsen"),
        Invocation {
            anchor: PathBuf::from("anchor.etb"),
            format: Format::Text,
            include_runtime_metadata: false,
            report_signing_key: None,
            command: Command::WriterTransitionPrepare {
                config: PathBuf::from("operator.json"),
                request: PathBuf::from("transition.json"),
            },
        }
    );
}

/// `activate` traegt ZWEI Fensterzahlen und nicht drei: die
/// Wirksamkeitssequenz folgt aus dem Antrag.
#[test]
fn writer_transition_activate_parses_in_its_full_form() {
    assert_eq!(
        parsed(&[
            TRUST_ANCHOR_SWITCH,
            "anchor.etb",
            "--format",
            "json",
            "writer-transition",
            WRITER_TRANSITION_ACTIVATE_SUBCOMMAND,
            OPERATOR_CONFIG_SWITCH,
            "operator.json",
            REQUEST_SWITCH,
            "transition.json",
            TRANSITION_OBJECT_SWITCH,
            "transition.etb",
            VALID_THROUGH_SWITCH,
            "200",
            NOT_AFTER_SWITCH,
            "1700000000000"
        ])
        .expect("writer-transition activate muss parsen"),
        Invocation {
            anchor: PathBuf::from("anchor.etb"),
            format: Format::Json,
            include_runtime_metadata: false,
            report_signing_key: None,
            command: Command::WriterTransitionActivate {
                config: PathBuf::from("operator.json"),
                request: PathBuf::from("transition.json"),
                transition_object: PathBuf::from("transition.etb"),
                valid_through_sequence: ChainSequence::new(200),
                not_after: UnixMillis::new(1_700_000_000_000),
            },
        }
    );
}

/// Ohne Antrag gibt es nichts vorzubereiten — bei BEIDEN Unterkommandos.
#[test]
fn both_subcommands_require_the_request_file() {
    for subcommand in [
        WRITER_TRANSITION_PREPARE_SUBCOMMAND,
        WRITER_TRANSITION_ACTIVATE_SUBCOMMAND,
    ] {
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "writer-transition",
                subcommand,
                OPERATOR_CONFIG_SWITCH,
                "operator.json"
            ]),
            UsageError::MissingSwitch {
                switch: REQUEST_SWITCH,
                command: "writer-transition",
            },
            "{subcommand} darf ohne {REQUEST_SWITCH} nicht durchgehen"
        );
    }
}

/// `activate` verlangt das Objekt und beide Fensterzahlen.
#[test]
fn activate_requires_the_object_and_both_window_numbers() {
    for missing in [
        TRANSITION_OBJECT_SWITCH,
        VALID_THROUGH_SWITCH,
        NOT_AFTER_SWITCH,
    ] {
        let mut tokens = vec![
            TRUST_ANCHOR_SWITCH,
            "anchor.etb",
            "writer-transition",
            WRITER_TRANSITION_ACTIVATE_SUBCOMMAND,
            OPERATOR_CONFIG_SWITCH,
            "operator.json",
            REQUEST_SWITCH,
            "transition.json",
        ];
        for (switch, value) in [
            (TRANSITION_OBJECT_SWITCH, "transition.etb"),
            (VALID_THROUGH_SWITCH, "200"),
            (NOT_AFTER_SWITCH, "1700000000000"),
        ] {
            if switch != missing {
                tokens.extend([switch, value]);
            }
        }
        assert_eq!(
            rejected(&tokens),
            UsageError::MissingSwitch {
                switch: missing,
                command: "writer-transition",
            },
            "activate darf ohne {missing} nicht durchgehen"
        );
    }
}

/// Was nur `activate` nimmt, weist `prepare` mit SEINEM Namen ab.
#[test]
fn prepare_refuses_the_switches_that_only_activate_takes() {
    for (switch, value) in [
        (TRANSITION_OBJECT_SWITCH, "transition.etb"),
        (VALID_THROUGH_SWITCH, "200"),
        (NOT_AFTER_SWITCH, "1700000000000"),
    ] {
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "writer-transition",
                WRITER_TRANSITION_PREPARE_SUBCOMMAND,
                OPERATOR_CONFIG_SWITCH,
                "operator.json",
                REQUEST_SWITCH,
                "transition.json",
                switch,
                value
            ]),
            UsageError::SwitchNotAllowed {
                switch,
                command: WRITER_TRANSITION_PREPARE_COMMAND,
            },
            "prepare darf {switch} nicht annehmen"
        );
    }
}

/// `--effective-from` nimmt KEINES der beiden Unterkommandos: die
/// Wirksamkeitssequenz ist keine Entscheidung des Betreibers.
#[test]
fn neither_subcommand_takes_effective_from() {
    for subcommand in [
        WRITER_TRANSITION_PREPARE_SUBCOMMAND,
        WRITER_TRANSITION_ACTIVATE_SUBCOMMAND,
    ] {
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "--effective-from",
                "42",
                "writer-transition",
                subcommand
            ]),
            UsageError::SwitchNotAllowed {
                switch: "--effective-from",
                command: "writer-transition",
            },
            "{subcommand} darf --effective-from nicht annehmen"
        );
    }
}

/// Die beiden neuen Schalter gehoeren GENAU `writer-transition`.
#[test]
fn the_new_switches_are_rejected_outside_writer_transition() {
    for (switch, value) in [
        (REQUEST_SWITCH, "transition.json"),
        (TRANSITION_OBJECT_SWITCH, "transition.etb"),
    ] {
        for (command, positional) in [("verify", "archive"), ("registry", "revocation-plan")] {
            assert_eq!(
                rejected(&[
                    TRUST_ANCHOR_SWITCH,
                    "anchor.etb",
                    switch,
                    value,
                    command,
                    positional
                ]),
                UsageError::SwitchNotAllowed { switch, command },
                "{command} darf {switch} nicht annehmen"
            );
        }
    }
}

/// Was keine nichtnegative Dezimalzahl ist, wird WOERTLICH zurueckgegeben —
/// und ein `--not-after` jenseits der Unixzeit ebenso.
#[test]
fn a_non_numeric_valid_through_is_rejected_verbatim() {
    assert_eq!(
        rejected(&[
            TRUST_ANCHOR_SWITCH,
            "anchor.etb",
            "writer-transition",
            WRITER_TRANSITION_ACTIVATE_SUBCOMMAND,
            VALID_THROUGH_SWITCH,
            "zweihundert"
        ]),
        UsageError::UnknownNumber {
            switch: VALID_THROUGH_SWITCH,
            value: "zweihundert".to_owned(),
        }
    );
    assert_eq!(
        rejected(&[
            TRUST_ANCHOR_SWITCH,
            "anchor.etb",
            "writer-transition",
            WRITER_TRANSITION_ACTIVATE_SUBCOMMAND,
            OPERATOR_CONFIG_SWITCH,
            "operator.json",
            REQUEST_SWITCH,
            "transition.json",
            TRANSITION_OBJECT_SWITCH,
            "transition.etb",
            VALID_THROUGH_SWITCH,
            "200",
            NOT_AFTER_SWITCH,
            "18446744073709551615"
        ]),
        UsageError::UnknownNumber {
            switch: NOT_AFTER_SWITCH,
            value: "18446744073709551615".to_owned(),
        }
    );
}

/// Die angehaengte Wertform ist auch hier ein unbekannter Schalter.
#[test]
fn an_attached_value_is_an_unknown_switch() {
    for token in [
        "--request=transition.json",
        "--transition-object=transition.etb",
    ] {
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                token,
                "writer-transition",
                WRITER_TRANSITION_PREPARE_SUBCOMMAND
            ]),
            UsageError::UnknownSwitch(token.to_owned())
        );
    }
}

#[test]
fn an_unknown_writer_transition_subcommand_is_rejected_verbatim() {
    assert_eq!(
        rejected(&[
            TRUST_ANCHOR_SWITCH,
            "anchor.etb",
            "writer-transition",
            "publish",
            OPERATOR_CONFIG_SWITCH,
            "operator.json",
            REQUEST_SWITCH,
            "transition.json"
        ]),
        UsageError::UnknownSubcommand {
            command: "writer-transition",
            value: "publish".to_owned(),
            expected: "prepare or activate",
        }
    );
}

// ---------------------------------------------------------------------------
// 2. Die Ausgabe
// ---------------------------------------------------------------------------

/// Die Textform der Vorbereitung ist eine GESCHLOSSENE Zeilenfolge.
#[test]
fn the_prepare_report_is_a_closed_line_sequence() {
    assert_eq!(
        output::writer_transition_prepare_lines(&prepare_view()),
        vec![
            format!("organization_id={}", "01".repeat(16)),
            format!("chain_id={}", "02".repeat(16)),
            format!("old_writer_certificate_hash={}", "11".repeat(32)),
            format!("new_writer_certificate_hash={}", "22".repeat(32)),
            "trusted_head.chain_sequence=41".to_owned(),
            format!("trusted_head.entry_hash={}", "33".repeat(32)),
            "effective_from_sequence=42".to_owned(),
            "reason_code=7".to_owned(),
            "registry_version=5".to_owned(),
            format!("registry_head_hash={}", "44".repeat(32)),
            "admin_authorization_object_hash=none".to_owned(),
            output::WRITER_TRANSITION_PLACEHOLDER_NOTE_V1.to_owned(),
        ]
    );
}

/// MIT Hash tragen die letzten beiden Zeilen den Hash und den ANDEREN Text;
/// alles davor bleibt gleich.
#[test]
fn a_bound_authorization_changes_exactly_the_last_two_lines() {
    let placeholder = output::writer_transition_prepare_lines(&prepare_view());
    let bound = output::writer_transition_prepare_lines(&bound_prepare_view());
    assert_eq!(placeholder.len(), bound.len());
    assert_eq!(
        placeholder[..placeholder.len() - 2],
        bound[..bound.len() - 2]
    );
    assert_eq!(
        bound[bound.len() - 2],
        format!("admin_authorization_object_hash={}", "66".repeat(32))
    );
    assert_eq!(
        bound[bound.len() - 1],
        output::WRITER_TRANSITION_BOUND_NOTE_V1
    );
}

/// Die JSON-Form der Vorbereitung traegt DIESELBEN geschlossenen Felder.
#[test]
fn the_prepare_json_carries_the_same_closed_fields() {
    assert_eq!(
        output::writer_transition_prepare_json(&prepare_view()),
        format!(
            "{{\"organization_id\":\"{}\",\"chain_id\":\"{}\",\
             \"old_writer_certificate_hash\":\"{}\",\"new_writer_certificate_hash\":\"{}\",\
             \"trusted_head\":{{\"chain_sequence\":41,\"entry_hash\":\"{}\"}},\
             \"effective_from_sequence\":42,\"reason_code\":7,\"registry_version\":5,\
             \"registry_head_hash\":\"{}\",\"admin_authorization_object_hash\":null,\
             \"authorization_note\":\"{}\"}}",
            "01".repeat(16),
            "02".repeat(16),
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
            "44".repeat(32),
            output::WRITER_TRANSITION_PLACEHOLDER_NOTE_V1
        )
    );
    let bound = output::writer_transition_prepare_json(&bound_prepare_view());
    assert!(
        bound.contains(&format!(
            "\"admin_authorization_object_hash\":\"{}\",\"authorization_note\":\"{}\"}}",
            "66".repeat(32),
            output::WRITER_TRANSITION_BOUND_NOTE_V1
        )),
        "war: {bound}"
    );
}

/// Die beiden festen Zeilen sind ZWEI Texte: der eine sagt, dass die
/// Autorisierung erst die Zeremonie bindet, der andere, dass sie gebunden
/// WURDE und `activate` genau diese Nutzlast haelt.
#[test]
fn the_two_authorization_notes_are_distinct_and_name_their_situation() {
    let placeholder = output::writer_transition_authorization_note(false);
    let bound = output::writer_transition_authorization_note(true);
    assert_ne!(placeholder, bound);
    assert_eq!(placeholder, output::WRITER_TRANSITION_PLACEHOLDER_NOTE_V1);
    assert_eq!(bound, output::WRITER_TRANSITION_BOUND_NOTE_V1);
    for phrase in [
        "bound at the root ceremony",
        "not by this run",
        "placeholder authorization hash",
        "admin_authorization_object_hash",
    ] {
        assert!(
            placeholder.contains(phrase),
            "die Platzhalterzeile muss {phrase} nennen, war: {placeholder}"
        );
    }
    for phrase in ["was bound into the prepared payload", "activate holds"] {
        assert!(
            bound.contains(phrase),
            "die gebundene Zeile muss {phrase} nennen, war: {bound}"
        );
    }
    assert!(!bound.contains("placeholder"));
}

/// Die Textform der Aktivierung ist eine GESCHLOSSENE Zeilenfolge.
#[test]
fn the_activate_report_is_a_closed_line_sequence() {
    assert_eq!(
        output::writer_transition_activate_lines(&activate_view()),
        vec![
            "registry_version=6".to_owned(),
            format!("previous_registry_hash={}", "44".repeat(32)),
            "effective_from_sequence=42".to_owned(),
            "valid_through_sequence=200".to_owned(),
            "issued_at=1000".to_owned(),
            "not_before=1000".to_owned(),
            "not_after=10000000".to_owned(),
            "registry_change=3".to_owned(),
            format!("transition_object_hash={}", "55".repeat(32)),
            output::WRITER_TRANSITION_ACTIVATE_NOTE_V1.to_owned(),
        ]
    );
    let mut without_predecessor = activate_view();
    without_predecessor.previous_registry_hash = None;
    assert_eq!(
        output::writer_transition_activate_lines(&without_predecessor)[1],
        "previous_registry_hash=none"
    );
}

/// Die JSON-Form der Aktivierung traegt DIESELBEN Felder; ein fehlender
/// Vorgaengerhash ist `null`.
#[test]
fn the_activate_json_carries_the_same_closed_fields() {
    assert_eq!(
        output::writer_transition_activate_json(&activate_view()),
        format!(
            "{{\"registry_version\":6,\"previous_registry_hash\":\"{}\",\
             \"effective_from_sequence\":42,\"valid_through_sequence\":200,\
             \"issued_at\":1000,\"not_before\":1000,\"not_after\":10000000,\
             \"registry_change\":3,\"transition_object_hash\":\"{}\",\
             \"activation_note\":\"{}\"}}",
            "44".repeat(32),
            "55".repeat(32),
            output::WRITER_TRANSITION_ACTIVATE_NOTE_V1
        )
    );
    let mut without_predecessor = activate_view();
    without_predecessor.previous_registry_hash = None;
    assert!(
        output::writer_transition_activate_json(&without_predecessor)
            .contains("\"previous_registry_hash\":null,"),
        "ein fehlender Vorgaengerhash ist null"
    );
}

/// Die Aenderung ist die 3 — als Zusage der Bauart und nicht als Rechnung.
#[test]
fn the_registry_change_of_a_writer_transition_is_three() {
    assert_eq!(output::WRITER_TRANSITION_REGISTRY_CHANGE_V1, 3);
}

// ---------------------------------------------------------------------------
// 3. Der Prozess
// ---------------------------------------------------------------------------

/// Die Grammatik fuehrt beide Unterkommandos WOERTLICH.
#[test]
fn the_grammar_lists_both_writer_transition_forms() {
    let output = run(&[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in [PREPARE_GRAMMAR_LINE, ACTIVATE_GRAMMAR_LINE] {
        assert!(
            stdout.contains(line),
            "die Grammatik muss {line} enthalten, war: {stdout}"
        );
    }
    assert!(
        stdout.contains("neither signs nor publishes anything"),
        "die Grammatik muss sagen, dass nichts signiert wird, war: {stdout}"
    );
}

/// `writer-transition` ohne Unterkommando ist ein Aufruffehler, der das
/// Kommando nennt — auf stderr, ohne Grammatik auf stdout.
#[test]
fn writer_transition_without_a_subcommand_is_a_usage_error() {
    let output = run(&[TRUST_ANCHOR_SWITCH, "anchor.etb", "writer-transition"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("writer-transition"),
        "die Meldung muss das Kommando nennen, war: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Ein neuer Schalter ohne Wert nennt SEINEN Namen.
#[test]
fn a_new_switch_without_a_value_is_rejected_by_the_process() {
    for switch in [REQUEST_SWITCH, TRANSITION_OBJECT_SWITCH] {
        let output = run(&[TRUST_ANCHOR_SWITCH, "anchor.etb", switch]);
        assert_eq!(output.status.code(), Some(2), "{switch}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(switch),
            "{switch} muss woertlich genannt werden"
        );
        assert!(output.stdout.is_empty(), "{switch}");
    }
}

/// Eine fehlende Antragsdatei endet mit dem I/O-Code und dem stabilen
/// Fehlercode, bevor die Bedienerdatei oder ein Archiv gelesen wird.
///
/// Die Bedienerdatei existiert absichtlich NICHT: waere sie zuerst dran,
/// stuende `EA-OPERATOR-IO` auf stderr und nicht der Antragscode.
#[test]
fn a_missing_request_file_ends_the_run_before_the_operator_config() {
    let directory = tempdir("missing-request");
    for subcommand in [
        WRITER_TRANSITION_PREPARE_SUBCOMMAND,
        WRITER_TRANSITION_ACTIVATE_SUBCOMMAND,
    ] {
        let mut tokens = vec![
            TRUST_ANCHOR_SWITCH,
            "anchor.etb",
            "writer-transition",
            subcommand,
            OPERATOR_CONFIG_SWITCH,
            "absent-operator.json",
            REQUEST_SWITCH,
            "absent-transition.json",
        ];
        if subcommand == WRITER_TRANSITION_ACTIVATE_SUBCOMMAND {
            tokens.extend([
                TRANSITION_OBJECT_SWITCH,
                "absent-transition.etb",
                VALID_THROUGH_SWITCH,
                "200",
                NOT_AFTER_SWITCH,
                "1700000000000",
            ]);
        }
        let output = Process::new(env!("CARGO_BIN_EXE_einsatzarchiv"))
            .args(&tokens)
            .current_dir(&directory)
            .output()
            .expect("das Testbinary muss startbar sein");
        assert_eq!(output.status.code(), Some(20), "{subcommand}");
        assert!(output.stdout.is_empty(), "{subcommand}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("EA-TRANSITION-REQUEST-UNREADABLE"),
            "{subcommand}: die Meldung muss den Antragscode tragen, war: {stderr}"
        );
        assert!(
            !stderr.contains("EA-OPERATOR-IO"),
            "{subcommand}: der Antrag steht VOR der Bedienerdatei, war: {stderr}"
        );
    }
}

/// Eine Antragsdatei ohne Form ist ein Aufruffehler — Exitcode 2 wie bei
/// einer Bedienerdatei ohne Form — und zeigt NICHTS aus ihrem Inhalt.
#[test]
fn a_malformed_request_file_is_a_usage_error_that_shows_no_content() {
    let directory = tempdir("malformed-request");
    let request = directory.join("transition.json");
    std::fs::write(
        &request,
        r#"{"old_writer_certificate_hash":"private-name-never-printed","reason_code":1}"#,
    )
    .expect("die Antragsdatei muss schreibbar sein");
    let output = run(&[
        TRUST_ANCHOR_SWITCH,
        "anchor.etb",
        "writer-transition",
        WRITER_TRANSITION_PREPARE_SUBCOMMAND,
        OPERATOR_CONFIG_SWITCH,
        "absent-operator.json",
        REQUEST_SWITCH,
        path_str(&request),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("EA-TRANSITION-REQUEST-SHAPE"),
        "war: {stderr}"
    );
    assert!(
        !stderr.contains("private-name-never-printed"),
        "der Inhalt der Antragsdatei darf nicht erscheinen, war: {stderr}"
    );
}

/// Ein Antrag in Form und eine Bedienerdatei in Form kommen an beiden
/// Eingabepruefungen VORBEI und scheitern erst am Bestand.
///
/// Der Anker existiert absichtlich nicht: der Lauf soll SPAETER scheitern —
/// beim Oeffnen des Bestands — und nicht an einer der beiden Dateien. Der
/// Exitcode ist 20 (`EA-RECOVERY-IO` fuer den fehlenden Anker) und stdout
/// bleibt leer: es ist kein Kopf gewaehlt worden, ueber den etwas zu sagen
/// waere.
#[test]
fn a_well_formed_request_and_config_reach_the_archive() {
    let directory = tempdir("reaches-archive");
    let config = write_config(&directory);
    let request = write_request(&directory, false);
    let anchor = directory.join("absent-anchor.etb");
    let output = run(&[
        TRUST_ANCHOR_SWITCH,
        path_str(&anchor),
        "writer-transition",
        WRITER_TRANSITION_PREPARE_SUBCOMMAND,
        OPERATOR_CONFIG_SWITCH,
        path_str(&config),
        REQUEST_SWITCH,
        path_str(&request),
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for absent in [
        "EA-TRANSITION-REQUEST",
        "EA-OPERATOR-CONFIG",
        "EA-OPERATOR-IO",
    ] {
        assert!(
            !stderr.contains(absent),
            "beide Dateien sind in Form und duerfen nicht abgelehnt werden, war: {stderr}"
        );
    }
    assert_eq!(output.status.code(), Some(20), "war: {stderr}");
    assert!(output.stdout.is_empty());
}

/// Bei `activate` steht die Objektdatei VOR der Bedienerdatei: eine
/// fehlende endet mit `EA-OPERATOR-IO` (20), bevor ein Archiv geoeffnet wird.
#[test]
fn a_missing_transition_object_ends_the_run_before_any_archive() {
    let directory = tempdir("missing-object");
    let config = write_config(&directory);
    let request = write_request(&directory, true);
    let output = run(&[
        TRUST_ANCHOR_SWITCH,
        "anchor.etb",
        "writer-transition",
        WRITER_TRANSITION_ACTIVATE_SUBCOMMAND,
        OPERATOR_CONFIG_SWITCH,
        path_str(&config),
        REQUEST_SWITCH,
        path_str(&request),
        TRANSITION_OBJECT_SWITCH,
        path_str(&directory.join("absent.etb")),
        VALID_THROUGH_SWITCH,
        "200",
        NOT_AFTER_SWITCH,
        "1700000000000",
    ]);
    assert_eq!(output.status.code(), Some(20));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("EA-OPERATOR-IO"),
        "war: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `activate` mit einem Antrag OHNE Autorisierungshash ist ein Aufruffehler
/// (2), der das Feld nennt — VOR der Bedienerdatei und vor dem Objekt.
///
/// Bedienerdatei und Objekt existieren absichtlich NICHT: staende eines von
/// beiden vorher, hiesse die Meldung `EA-OPERATOR-IO`. Derselbe Antrag geht
/// bei `prepare` durch (Gegenzeuge: dort steht der Antragscode nicht auf
/// stderr, der Lauf scheitert erst am Anker).
#[test]
fn activate_refuses_a_request_without_the_authorization_hash_before_the_config() {
    let directory = tempdir("activate-without-authorization");
    let request = write_request(&directory, false);
    let output = run(&[
        TRUST_ANCHOR_SWITCH,
        "anchor.etb",
        "writer-transition",
        WRITER_TRANSITION_ACTIVATE_SUBCOMMAND,
        OPERATOR_CONFIG_SWITCH,
        path_str(&directory.join("absent-operator.json")),
        REQUEST_SWITCH,
        path_str(&request),
        TRANSITION_OBJECT_SWITCH,
        path_str(&directory.join("absent.etb")),
        VALID_THROUGH_SWITCH,
        "200",
        NOT_AFTER_SWITCH,
        "1700000000000",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("admin_authorization_object_hash"),
        "die Ablehnung muss das fehlende Feld benennen, war: {stderr}"
    );
    for absent in ["EA-OPERATOR-IO", "EA-TRANSITION-REQUEST"] {
        assert!(!stderr.contains(absent), "war: {stderr}");
    }

    let config = write_config(&directory);
    let prepare = run(&[
        TRUST_ANCHOR_SWITCH,
        path_str(&directory.join("absent-anchor.etb")),
        "writer-transition",
        WRITER_TRANSITION_PREPARE_SUBCOMMAND,
        OPERATOR_CONFIG_SWITCH,
        path_str(&config),
        REQUEST_SWITCH,
        path_str(&request),
    ]);
    let stderr = String::from_utf8_lossy(&prepare.stderr);
    assert!(
        !stderr.contains("admin_authorization_object_hash"),
        "prepare nimmt denselben Antrag ohne Hash, war: {stderr}"
    );
    assert_eq!(prepare.status.code(), Some(20), "war: {stderr}");
}

/// Ein Antrag MIT Hash kommt bei `activate` an der Ablehnung VORBEI und an
/// der Bedienerdatei ebenso; der Lauf scheitert erst am Anker.
#[test]
fn activate_with_the_authorization_hash_reaches_the_archive() {
    let directory = tempdir("activate-with-authorization");
    let config = write_config(&directory);
    let request = write_request(&directory, true);
    let object = directory.join("transition.etb");
    std::fs::write(&object, b"not decoded before the archive is open").expect("schreibbar");
    let output = run(&[
        TRUST_ANCHOR_SWITCH,
        path_str(&directory.join("absent-anchor.etb")),
        "writer-transition",
        WRITER_TRANSITION_ACTIVATE_SUBCOMMAND,
        OPERATOR_CONFIG_SWITCH,
        path_str(&config),
        REQUEST_SWITCH,
        path_str(&request),
        TRANSITION_OBJECT_SWITCH,
        path_str(&object),
        VALID_THROUGH_SWITCH,
        "200",
        NOT_AFTER_SWITCH,
        "1700000000000",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for absent in [
        "admin_authorization_object_hash",
        "EA-TRANSITION",
        "EA-OPERATOR-CONFIG",
        "EA-OPERATOR-IO",
    ] {
        assert!(!stderr.contains(absent), "war: {stderr}");
    }
    assert_eq!(output.status.code(), Some(20), "war: {stderr}");
    assert!(output.stdout.is_empty());
}
