//! Die vollstaendige §16.1-Grammatik samt Schluesselquellen, gemessen am
//! echten Prozess.
//!
//! # Was hier gemessen wird
//!
//! Drei Dinge, die nur ein Prozessstart zeigt: dass jedes Kommandowort der
//! Norm den Parser passiert und mit dem Code endet, den seine Eingaben
//! verdienen; dass `grant` und `recovery-test` VERIFIZIEREN, ihre Quellen
//! aufloesen und ihre Dateien lesen, bevor sie an ihrer benannten Grenze
//! (21) enden — und dass ein Befund, ein Aufruffehler und ein fremder Anker
//! diese Grenze nie erreichen; und dass `--key` die drei Quellformen nimmt
//! und der Container byteweise dasselbe entschluesselt wie die Rohdatei.
//!
//! # DIE UHR IST HIER KEIN PARAMETER
//!
//! Jeder Bestand stammt aus der `live_clock_*`-Familie; die Begruendung
//! steht in `apps/cli/tests/support/mod.rs`.
//!
//! # Was eine stderr-Zeile NIE traegt
//!
//! Den Temporaerpfad, ein Schluesselbyte, eine Passphrase. Gemessen wird das
//! am Erfolgspfad von `grant`, der alle drei in Haenden hatte.

#[path = "support/mod.rs"]
mod support;

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use ea_crypto::{SecretBytes, SecretVec};
use ea_recovery::{ContainedKeyKind, EncryptedKeyContainer};

use support::{
    LiveArchive, TempDir, live_clock_archive, live_clock_archive_with_mutated_writer_signature,
    materialize, temp_dir,
    verify_support::{archive_support::trust_support, complete_recipient_secret_bytes},
};

/// Der Name der einzigen Klartextdatei eines Bestands mit genau einem
/// Eintrag auf Sequenz null — derselbe wie in `apps/cli/tests/decrypt.rs`.
const GENESIS_PLAINTEXT_FILE_V1: &str = "000000000000.bin";

/// Die Passphrase jedes Containers dieses Targets.
const PASSPHRASE_V1: &str = "richtig";

/// Die PIN jeder `pkcs11:`-Referenz dieses Targets — UNVERWECHSELBAR, damit
/// ihr Fehlen auf stderr etwas beweist.
const PIN_V1: &str = "pin-7731-distinct";

/// Die Grammatik, wie das Werkzeug sie ohne Argumente druckt — GESCHLOSSEN.
///
/// Geschlossen und nicht „mindestens diese Zeilen": nur ein vollstaendiger
/// Vergleich faellt ueber eine zusaetzliche oder umsortierte Zeile. Die
/// ersten sieben Zeilen sind `design.md` §16.1 in dessen Reihenfolge.
const PRINTED_GRAMMAR_V1: [&str; 24] = [
    "einsatzarchiv --trust-anchor <file> verify <archive-path>",
    "einsatzarchiv --trust-anchor <file> list <archive-path>",
    "einsatzarchiv --trust-anchor <file> decrypt <archive-path> --key <key-source> --output <target>",
    "einsatzarchiv --trust-anchor <file> grant <entry-or-archive> --recovery-key <source> --authority-key <source> --authorization <file> --recipient-cert <file>",
    "einsatzarchiv --trust-anchor <file> report <archive-path> --output <report-file>",
    "einsatzarchiv --trust-anchor <file> export <archive-or-server> --output <new-target>",
    "einsatzarchiv --trust-anchor <file> recovery-test <archive-path> --key-inventory <file> --output <report-file>",
    "einsatzarchiv --trust-anchor <new-file> organization init",
    "einsatzarchiv --trust-anchor <file> posture target --operator-config <file> --output <new-target.json>",
    "einsatzarchiv --trust-anchor <file> posture issue --operator-config <file> --posture-target <target.json> --evidence-reference <public-document> --valid-for-ms <1..86400000> --output <new-document.cbor>",
    "einsatzarchiv --trust-anchor <file> posture import --operator-config <file> --posture-document <document.cbor>",
    "einsatzarchiv --trust-anchor <file> operator provision|verify-session|revoke --operator-config <file>",
    "einsatzarchiv --trust-anchor <file> registry revocation-plan --operator-config <file> --effective-from <sequence> --valid-through <sequence> --not-after <unix-millis>",
    "einsatzarchiv --trust-anchor <file> clock-release apply --operator-config <file> --release <file>",
    "einsatzarchiv --trust-anchor <file> writer-transition prepare --operator-config <file> --request <file>",
    "einsatzarchiv --trust-anchor <file> writer-transition activate --operator-config <file> --request <file> --transition-object <file> --valid-through <sequence> --not-after <unix-millis>",
    "key-source is <path> | file:<path> | container:<path>;passphrase-file=<path> | pkcs11:module=<path>;token=<label>;id=<hex>;pin-file=<path>; passphrase and pin are read from the named file with owner-only permissions, never from argv or the environment",
    "grant verifies the archive and requires --operator-config for native historical-regrant presence; signed audited grants are appended under --output or archive/grants",
    "recovery-test verifies the archive, requires a free output path and reads the key inventory, then ends with exit 21 naming the missing recovery test service; it writes nothing",
    "organization init begins or resumes the ceremony and reports its step; it drives no step that needs offline key sources",
    "operator config contains public archive/database paths, certificate/binding hashes, role and purpose; authority mode requires authority=true and target_certificate_hash; offline exchange uses ceremony_exchange_directory",
    "registry revocation-plan prepares change 1 for the object named by target_certificate_hash in the operator config and reports its reach; it publishes nothing, because publishing needs the root signature",
    "clock-release apply consumes an already issued release file and never prints its bytes; issuing one is a step of the administration workflow and not of this tool",
    "writer-transition prepare checks the request file against the selected head and shows the fields the root ceremony will sign; activate holds the published transition object against the same request and plans change 3; neither signs nor publishes anything",
];

/// Ein abgelegter Bestand samt einem Verzeichnis AUSSERHALB fuer alle
/// weiteren Eingaben — Anker, Schluessel, Passphrasen, Dateien, Ziele.
///
/// Nichts davon liegt im Bestand: `ea_recovery::FsArchiveSource::open`
/// zaehlte es sonst als Beiwerk. Das ist zugleich die raeumliche Form von
/// `design.md`:1782: der Anker kommt VON AUSSEN.
struct Laid {
    archive: TempDir,
    outside: TempDir,
}

impl Laid {
    fn archive_path(&self) -> String {
        path_argument(self.archive.path())
    }

    fn outside(&self, name: &str) -> PathBuf {
        self.outside.path().join(name)
    }

    fn outside_path(&self, name: &str) -> String {
        path_argument(&self.outside(name))
    }

    fn anchor_path(&self) -> String {
        self.outside_path("anchor.bin")
    }

    /// Die rohe Schluesseldatei des Empfaengers (Stufe-4-Form).
    fn recovery_key_path(&self) -> String {
        self.outside_path("recovery.key")
    }

    /// Ein Zielpfad, der AUSDRUECKLICH noch nicht existiert.
    fn target(&self, name: &str) -> PathBuf {
        self.outside(name)
    }
}

/// Ein vom Testrahmen selbst gebildeter Pfad als Argumentzeichenkette.
fn path_argument(path: &Path) -> String {
    path.to_str()
        .expect("der vom Testrahmen selbst gebildete Pfad ist UTF-8")
        .to_owned()
}

/// Legt `built` samt Anker und roher Schluesseldatei ab.
fn lay_out(tag: &str, built: &LiveArchive) -> Laid {
    lay_out_with_anchor(tag, built, &built.anchor_bytes)
}

/// Wie [`lay_out`], aber mit einem FREMDEN Anker.
fn lay_out_with_anchor(tag: &str, built: &LiveArchive, anchor_bytes: &[u8]) -> Laid {
    let archive = temp_dir(&format!("{tag}-archive"));
    materialize(&built.fixture, archive.path());
    let outside = temp_dir(&format!("{tag}-outside"));
    fs::write(outside.path().join("anchor.bin"), anchor_bytes)
        .expect("die Ankerdatei muss schreibbar sein");
    fs::write(
        outside.path().join("recovery.key"),
        complete_recipient_secret_bytes(),
    )
    .expect("die Schluesseldatei muss schreibbar sein");
    Laid { archive, outside }
}

/// Legt die beiden Dateieingaben von `grant` an und liefert ihre Pfade.
fn lay_out_grant_files(laid: &Laid) -> (String, String) {
    fs::write(laid.outside("authorization.bin"), b"authorization-bytes").expect("schreibbar");
    fs::write(
        laid.outside("recipient.cert"),
        b"recipient-certificate-bytes",
    )
    .expect("schreibbar");
    (
        laid.outside_path("authorization.bin"),
        laid.outside_path("recipient.cert"),
    )
}

/// Schreibt `bytes` nach `path` mit den Rechten `mode`.
#[cfg(unix)]
fn write_with_mode(path: &Path, bytes: &[u8], mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;

    fs::write(path, bytes).expect("die Datei muss schreibbar sein");
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .expect("die Rechte muessen setzbar sein");
}

/// Legt einen Container der Art `kind` um `secret` samt Passphrasendatei
/// (Rechte `passphrase_mode`) an und liefert die `container:`-Angabe.
#[cfg(unix)]
fn container_argument(
    laid: &Laid,
    name: &str,
    kind: ContainedKeyKind,
    secret: [u8; 32],
    passphrase_mode: u32,
) -> String {
    let container = laid.outside(&format!("{name}.container"));
    EncryptedKeyContainer::seal(
        kind,
        SecretBytes::new(secret),
        &SecretVec::new(PASSPHRASE_V1.as_bytes().to_vec()),
    )
    .expect("versiegeln muss gelingen")
    .write_new(&container)
    .expect("der Container muss anlegbar sein");
    let passphrase_file = laid.outside(&format!("{name}.passphrase"));
    write_with_mode(
        &passphrase_file,
        format!("{PASSPHRASE_V1}\n").as_bytes(),
        passphrase_mode,
    );
    format!(
        "container:{};passphrase-file={}",
        path_argument(&container),
        path_argument(&passphrase_file)
    )
}

/// Eine `pkcs11:`-Referenz auf eine existierende Moduldatei mit einer
/// PIN-Datei der Rechte `pin_mode`.
#[cfg(unix)]
fn pkcs11_argument(laid: &Laid, name: &str, pin_mode: u32) -> String {
    let module = laid.outside(&format!("{name}.so"));
    fs::write(&module, b"kein echtes Modul").expect("die Moduldatei muss schreibbar sein");
    let pin_file = laid.outside(&format!("{name}.pin"));
    write_with_mode(&pin_file, format!("{PIN_V1}\n").as_bytes(), pin_mode);
    format!(
        "pkcs11:module={};token=t;id=0a;pin-file={}",
        path_argument(&module),
        path_argument(&pin_file)
    )
}

/// Startet das Werkzeug mit `tokens` und liefert seinen vollstaendigen Ausgang.
fn run(tokens: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_einsatzarchiv"))
        .args(tokens)
        .output()
        .expect("das Testbinary muss startbar sein")
}

/// Der Exitcode eines Laufs.
fn code_of(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("der Prozess muss regulaer enden")
}

/// Die stderr-Zeile eines Laufs als Text.
fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Prueft, dass `tokens` mit Exitcode 2 endet und `name` WOERTLICH auf stderr
/// nennt — und dass stdout leer bleibt.
fn assert_usage_error(tokens: &[&str], name: &str) {
    let output = run(tokens);
    assert_eq!(code_of(&output), 2, "exit code fuer {tokens:?}");
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains(name),
        "die Meldung zu {tokens:?} muss {name} woertlich nennen, war: {stderr}"
    );
    assert!(
        output.stdout.is_empty(),
        "eine Fehlermeldung gehoert nicht nach stdout, war: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// Prueft die benannte Grenze: `code` auf dem Prozess, `code_name` auf
/// stderr, NICHTS auf stdout.
fn assert_refusal(output: &Output, code: i32, code_name: &str) {
    assert_eq!(code_of(output), code, "exit code");
    let stderr = stderr_of(output);
    assert!(
        stderr.contains(code_name),
        "stderr muss {code_name} nennen, war: {stderr}"
    );
    assert!(
        output.stdout.is_empty(),
        "die Grenze schreibt nichts auf stdout, war: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// Die vollstaendige `grant`-Aufrufzeile gegen `laid`.
fn grant_argv(
    laid: &Laid,
    recovery_key: &str,
    authority_key: &str,
    authorization: &str,
    recipient_certificate: &str,
) -> Vec<String> {
    vec![
        "--trust-anchor".to_owned(),
        laid.anchor_path(),
        "grant".to_owned(),
        laid.archive_path(),
        "--recovery-key".to_owned(),
        recovery_key.to_owned(),
        "--authority-key".to_owned(),
        authority_key.to_owned(),
        "--authorization".to_owned(),
        authorization.to_owned(),
        "--recipient-cert".to_owned(),
        recipient_certificate.to_owned(),
    ]
}

/// Die vollstaendige `recovery-test`-Aufrufzeile gegen `laid`.
fn recovery_test_argv(laid: &Laid, key_inventory: &str, output: &str) -> Vec<String> {
    vec![
        "--trust-anchor".to_owned(),
        laid.anchor_path(),
        "recovery-test".to_owned(),
        laid.archive_path(),
        "--key-inventory".to_owned(),
        key_inventory.to_owned(),
        "--output".to_owned(),
        output.to_owned(),
    ]
}

/// Die `decrypt`-Aufrufzeile gegen `laid` mit der Quellenangabe `key`.
fn decrypt_argv(laid: &Laid, key: &str, target: &str) -> Vec<String> {
    vec![
        "--trust-anchor".to_owned(),
        laid.anchor_path(),
        "decrypt".to_owned(),
        laid.archive_path(),
        "--key".to_owned(),
        key.to_owned(),
        "--output".to_owned(),
        target.to_owned(),
    ]
}

/// `&[String]` als `&[&str]`.
fn as_tokens(argv: &[String]) -> Vec<&str> {
    argv.iter().map(String::as_str).collect()
}

// ===========================================================================
// Die Grammatik
// ===========================================================================

/// Ohne Argumente kommt die GANZE Grammatik — geschlossen, in dieser Ordnung.
#[test]
fn the_printed_grammar_is_a_closed_line_sequence() {
    let output = run(&[]);
    assert_eq!(code_of(&output), 2, "exit code");
    let expected = PRINTED_GRAMMAR_V1
        .iter()
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    assert_eq!(String::from_utf8_lossy(&output.stdout), expected);
    assert!(output.stderr.is_empty());
}

/// Jedes Kommandowort aus `design.md` §16.1 passiert den Parser.
///
/// Gemessen am ersten Schritt HINTER der Grammatik: der Anker fehlt als
/// Datei, also endet jeder Lauf mit 20 (`EA-RECOVERY-IO`) — und nicht mit 2,
/// „unknown command". Alle Pflichtschalter sind gesetzt, damit allein das
/// Kommandowort entscheidet.
#[test]
fn every_section_16_1_command_word_is_accepted() {
    let outside = temp_dir("grammar-words");
    let missing_anchor = path_argument(&outside.path().join("fehlt.bin"));
    let archive = path_argument(outside.path());
    for tokens in [
        vec!["verify", &archive],
        vec!["list", &archive],
        vec!["decrypt", &archive, "--key", "k", "--output", "t"],
        vec![
            "grant",
            &archive,
            "--recovery-key",
            "r",
            "--authority-key",
            "a",
            "--authorization",
            "z",
            "--recipient-cert",
            "c",
        ],
        vec!["report", &archive, "--output", "r.json"],
        vec!["export", &archive, "--output", "t"],
        vec![
            "recovery-test",
            &archive,
            "--key-inventory",
            "i",
            "--output",
            "r.json",
        ],
    ] {
        let mut argv = vec!["--trust-anchor", &missing_anchor];
        argv.extend(tokens.iter().copied());
        let output = run(&argv);
        assert_eq!(code_of(&output), 20, "{tokens:?} muss am Anker enden");
        let stderr = stderr_of(&output);
        assert!(
            stderr.contains("EA-RECOVERY-IO") && !stderr.contains("unknown command"),
            "{tokens:?}: {stderr}"
        );
    }
}

/// Jeder der vier `grant`-Schalter ist Pflicht und wird WOERTLICH genannt;
/// stdout bleibt leer, und es wurde kein Byte gelesen — der Anker ist hier
/// bloss ein Name.
#[test]
fn grant_requires_each_of_its_four_switches() {
    let full = [
        ("--recovery-key", "recovery.key"),
        ("--authority-key", "authority.key"),
        ("--authorization", "authorization.bin"),
        ("--recipient-cert", "recipient.cert"),
    ];
    for (missing, _) in full {
        let mut tokens = vec!["--trust-anchor", "anchor.etb", "grant", "archive"];
        for (switch, value) in full {
            if switch != missing {
                tokens.extend([switch, value]);
            }
        }
        assert_usage_error(&tokens, missing);
    }
}

#[test]
fn recovery_test_requires_inventory_and_output() {
    assert_usage_error(
        &[
            "--trust-anchor",
            "anchor.etb",
            "recovery-test",
            "archive",
            "--output",
            "r.json",
        ],
        "--key-inventory",
    );
    assert_usage_error(
        &[
            "--trust-anchor",
            "anchor.etb",
            "recovery-test",
            "archive",
            "--key-inventory",
            "inventory.json",
        ],
        "--output",
    );
}

/// Jeder neue Schalter an einem fremden Kommando ist ein Aufruffehler, der
/// den Schalter nennt.
#[test]
fn every_new_switch_is_rejected_on_a_foreign_command() {
    for (switch, command) in [
        ("--recovery-key", "verify"),
        ("--authority-key", "list"),
        ("--authorization", "recovery-test"),
        ("--recipient-cert", "export"),
        ("--key-inventory", "grant"),
        ("--key", "grant"),
    ] {
        let output = run(&[
            "--trust-anchor",
            "anchor.etb",
            switch,
            "value",
            command,
            "archive",
        ]);
        assert_eq!(
            code_of(&output),
            2,
            "{command} darf {switch} nicht annehmen"
        );
        let stderr = stderr_of(&output);
        assert!(
            stderr.contains(switch) && stderr.contains("is not allowed"),
            "{command} {switch}: {stderr}"
        );
    }
}

/// Auch die beiden neuen Kommandos verlangen den Anker von aussen.
#[test]
fn grant_and_recovery_test_require_the_trust_anchor() {
    assert_usage_error(
        &[
            "grant",
            "archive",
            "--recovery-key",
            "r",
            "--authority-key",
            "a",
            "--authorization",
            "z",
            "--recipient-cert",
            "c",
        ],
        "--trust-anchor",
    );
    assert_usage_error(
        &[
            "recovery-test",
            "archive",
            "--key-inventory",
            "i",
            "--output",
            "r.json",
        ],
        "--trust-anchor",
    );
}

/// Eine `container:`-Angabe ohne `passphrase-file=` ist ein Aufruffehler,
/// der den Schalter UND das Feld nennt — und noch kein Byte gelesen hat.
#[test]
fn a_container_source_without_a_passphrase_file_names_the_field() {
    let output = run(&[
        "--trust-anchor",
        "anchor.etb",
        "decrypt",
        "archive",
        "--key",
        "container:recipient.container",
        "--output",
        "target",
    ]);
    assert_eq!(code_of(&output), 2, "exit code");
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("--key") && stderr.contains("passphrase-file="),
        "war: {stderr}"
    );
    assert!(output.stdout.is_empty());
}

// ===========================================================================
// Kein impliziter Anker
// ===========================================================================

/// Ein FREMDER, in sich stimmiger Anker endet mit 12 — VOR dem
/// Autoritaetsschluessel und VOR den Dateien.
///
/// Der Autoritaetsschluessel ist eine PKCS#11-Referenz mit OFFENER
/// PIN-Datei (2), die beiden Dateien fehlen (20): gewaenne eines davon,
/// stuende 2 oder 20 da. Es steht 12, also hat die Verifikation zuerst
/// entschieden. Dass der RECOVERY-Schluessel davor aufgeloest wird, ist
/// kein Gegenbeispiel, sondern die Voraussetzung: der Bericht braucht seinen
/// Abdruck (`crates/ea-recovery/src/grant.rs`) — deshalb ist die Sonde hier
/// der Autoritaetsschluessel.
///
/// Die Trust-Objekte des Bestands liegen dabei im Archiv und werden NIE als
/// Anker genommen: der Lauf haette sonst 0 oder 21, nie 12.
#[cfg(unix)]
#[test]
fn a_foreign_anchor_fails_with_twelve_before_the_authority_key_is_touched() {
    let built = live_clock_archive();
    let foreign_line = trust_support::RegistryLineBuilder::with_first_admin_revoked_from(Some(
        ea_types::ChainSequence::new(1),
    ));
    let foreign_anchor_bytes = foreign_line.exact_anchor_bytes().to_vec();
    assert_ne!(foreign_anchor_bytes, built.anchor_bytes);
    let laid = lay_out_with_anchor("grant-foreign-anchor", &built, &foreign_anchor_bytes);
    let authority = pkcs11_argument(&laid, "authority", 0o644);

    let argv = grant_argv(
        &laid,
        &laid.recovery_key_path(),
        &authority,
        &laid.outside_path("fehlt.bin"),
        &laid.outside_path("fehlt.cert"),
    );
    let output = run(&as_tokens(&argv));
    assert_eq!(code_of(&output), 12, "exit code");
    assert!(output.stdout.is_empty());

    // Dasselbe fuer `recovery-test`: das Ziel ist belegt (2), das Inventar
    // fehlt (20), der Anker ist fremd (12).
    let laid = lay_out_with_anchor("rt-foreign-anchor", &built, &foreign_anchor_bytes);
    fs::write(laid.outside("busy.json"), b"schon da").expect("schreibbar");
    let argv = recovery_test_argv(
        &laid,
        &laid.outside_path("fehlt.json"),
        &laid.outside_path("busy.json"),
    );
    let output = run(&as_tokens(&argv));
    assert_eq!(code_of(&output), 12, "exit code");
    assert!(output.stdout.is_empty());
}

// ===========================================================================
// `decrypt` mit Container und PKCS#11
// ===========================================================================

/// Der Container entschluesselt BYTEWEISE dasselbe wie die Rohdatei.
#[cfg(unix)]
#[test]
fn decrypt_from_a_container_equals_decrypt_from_the_raw_file() {
    let built = live_clock_archive();
    let laid = lay_out("decrypt-container", &built);
    let container = container_argument(
        &laid,
        "recovery",
        ContainedKeyKind::RecipientKem,
        complete_recipient_secret_bytes(),
        0o600,
    );

    let raw_target = laid.target("klartext-raw");
    let argv = decrypt_argv(
        &laid,
        &laid.recovery_key_path(),
        &path_argument(&raw_target),
    );
    assert_eq!(code_of(&run(&as_tokens(&argv))), 0, "die Rohform");

    let container_target = laid.target("klartext-container");
    let argv = decrypt_argv(&laid, &container, &path_argument(&container_target));
    let output = run(&as_tokens(&argv));
    assert_eq!(
        code_of(&output),
        0,
        "die Containerform: {}",
        stderr_of(&output)
    );

    let from_raw =
        fs::read(raw_target.join(GENESIS_PLAINTEXT_FILE_V1)).expect("die Rohform hat geschrieben");
    let from_container = fs::read(container_target.join(GENESIS_PLAINTEXT_FILE_V1))
        .expect("die Containerform hat geschrieben");
    assert_eq!(from_raw, built.plaintext);
    assert_eq!(from_container, from_raw);
}

/// Die falsche Passphrase ist 14 — der Container hat die Form erfuellt,
/// gescheitert ist die Entschluesselung —, und es entsteht kein Ziel.
#[cfg(unix)]
#[test]
fn decrypt_with_the_wrong_passphrase_fails_with_fourteen() {
    let built = live_clock_archive();
    let laid = lay_out("decrypt-wrong-pass", &built);
    let container = container_argument(
        &laid,
        "recovery",
        ContainedKeyKind::RecipientKem,
        complete_recipient_secret_bytes(),
        0o600,
    );
    write_with_mode(&laid.outside("recovery.passphrase"), b"falsch\n", 0o600);

    let target = laid.target("klartext");
    let argv = decrypt_argv(&laid, &container, &path_argument(&target));
    let output = run(&as_tokens(&argv));
    assert_refusal(&output, 14, "EA-RECOVERY-CONTAINER-OPEN");
    assert!(!target.exists(), "ohne Schluessel entsteht kein Ziel");
}

/// Eine OFFENE Passphrasendatei ist ein Aufruffehler, benannt, vor dem
/// ersten gelesenen Byte.
#[cfg(unix)]
#[test]
fn decrypt_with_an_exposed_passphrase_file_fails_with_two() {
    let built = live_clock_archive();
    let laid = lay_out("decrypt-exposed", &built);
    let container = container_argument(
        &laid,
        "recovery",
        ContainedKeyKind::RecipientKem,
        complete_recipient_secret_bytes(),
        0o644,
    );

    let target = laid.target("klartext");
    let argv = decrypt_argv(&laid, &container, &path_argument(&target));
    let output = run(&as_tokens(&argv));
    assert_refusal(&output, 2, "EA-RECOVERY-KEY-SOURCE-EXPOSED");
    assert!(!target.exists());
}

/// Eine PKCS#11-Referenz endet an der benannten Grenze, 21 — und die PIN,
/// die dafuer gelesen wurde, steht nicht auf stderr.
#[cfg(unix)]
#[test]
fn decrypt_from_a_pkcs11_source_ends_at_the_named_boundary() {
    let built = live_clock_archive();
    let laid = lay_out("decrypt-pkcs11", &built);
    let reference = pkcs11_argument(&laid, "recovery", 0o600);

    let target = laid.target("klartext");
    let argv = decrypt_argv(&laid, &reference, &path_argument(&target));
    let output = run(&as_tokens(&argv));
    assert_refusal(&output, 21, "EA-RECOVERY-PKCS11-UNAVAILABLE");
    assert!(!target.exists());
    let stderr = stderr_of(&output);
    assert!(
        !stderr.contains(PIN_V1),
        "stderr darf die PIN nicht tragen: {stderr}"
    );
}

// ===========================================================================
// `grant`
// ===========================================================================

/// DER KERN: verifiziert, beide Quellen aufgeloest, beide Dateien gelesen —
/// und dann die benannte Grenze. Und stderr traegt weder den Temporaerpfad
/// noch ein Schluesselbyte noch die Passphrase.
#[cfg(unix)]
#[test]
fn grant_resolves_every_input_and_requires_native_configuration() {
    let built = live_clock_archive();
    let laid = lay_out("grant-ok", &built);
    let authority = container_argument(
        &laid,
        "authority",
        ContainedKeyKind::Signing,
        [0x5d; 32],
        0o600,
    );
    let (authorization, recipient_certificate) = lay_out_grant_files(&laid);

    let argv = grant_argv(
        &laid,
        &laid.recovery_key_path(),
        &authority,
        &authorization,
        &recipient_certificate,
    );
    let output = run(&as_tokens(&argv));
    assert_refusal(&output, 2, "EA-GRANT-NATIVE-CONFIGURATION-REQUIRED");

    let stderr = stderr_of(&output);
    let temp_root = path_argument(laid.outside.path());
    assert!(
        !stderr.contains(&temp_root) && !stderr.contains(&laid.archive_path()),
        "stderr darf keinen Hostpfad tragen: {stderr}"
    );
    let key_hex = hex::encode(complete_recipient_secret_bytes());
    let authority_hex = hex::encode([0x5d_u8; 32]);
    assert!(
        !stderr.contains(&key_hex) && !stderr.contains(&authority_hex),
        "stderr darf kein Schluesselbyte tragen: {stderr}"
    );
    assert!(
        !stderr.contains(PASSPHRASE_V1),
        "stderr darf die Passphrase nicht tragen: {stderr}"
    );
    // `--format json` aendert nichts: es gibt kein Dokument, dessen Form zu
    // waehlen waere — dieselbe Regel wie bei `decrypt` und `export`.
    let mut json_argv = vec!["--format".to_owned(), "json".to_owned()];
    json_argv.extend(argv);
    let output = run(&as_tokens(&json_argv));
    assert_refusal(&output, 2, "EA-GRANT-NATIVE-CONFIGURATION-REQUIRED");
}

/// Ein `pkcs11:`-Recovery-Schluessel endet an SEINER Grenze, 21 mit
/// `EA-RECOVERY-PKCS11-UNAVAILABLE` — und nicht an der des fehlenden Dienstes:
/// der Recovery-Schluessel wird als Erstes aufgeloest, und die gelesene PIN
/// steht nicht auf stderr.
#[cfg(unix)]
#[test]
fn grant_with_a_pkcs11_recovery_key_ends_at_the_pkcs11_boundary() {
    let built = live_clock_archive();
    let laid = lay_out("grant-pkcs11-recovery", &built);
    let recovery = pkcs11_argument(&laid, "recovery", 0o600);
    let authority = container_argument(
        &laid,
        "authority",
        ContainedKeyKind::Signing,
        [0x5d; 32],
        0o600,
    );
    let (authorization, recipient_certificate) = lay_out_grant_files(&laid);

    let argv = grant_argv(
        &laid,
        &recovery,
        &authority,
        &authorization,
        &recipient_certificate,
    );
    let output = run(&as_tokens(&argv));
    assert_refusal(&output, 21, "EA-RECOVERY-PKCS11-UNAVAILABLE");
    let stderr = stderr_of(&output);
    assert!(
        !stderr.contains("EA-CLI-GRANT-SERVICE-UNAVAILABLE"),
        "die PKCS#11-Grenze kommt vor der Dienstgrenze: {stderr}"
    );
    assert!(
        !stderr.contains(PIN_V1),
        "stderr darf die PIN nicht tragen: {stderr}"
    );
}

/// Eine fehlende Autorisierungsdatei ist 20 — die Grenze wird nie erreicht.
#[cfg(unix)]
#[test]
fn grant_with_a_missing_authorization_file_fails_with_twenty() {
    let built = live_clock_archive();
    let laid = lay_out("grant-missing-file", &built);
    let authority = container_argument(
        &laid,
        "authority",
        ContainedKeyKind::Signing,
        [0x5d; 32],
        0o600,
    );
    let (_, recipient_certificate) = lay_out_grant_files(&laid);

    let argv = grant_argv(
        &laid,
        &laid.recovery_key_path(),
        &authority,
        &laid.outside_path("fehlt.bin"),
        &recipient_certificate,
    );
    let output = run(&as_tokens(&argv));
    assert_refusal(&output, 20, "EA-RECOVERY-IO");
    assert!(!stderr_of(&output).contains("EA-CLI-GRANT-SERVICE-UNAVAILABLE"));
}

/// Ein Container der FALSCHEN Art als Autoritaetsschluessel ist 2: der Kopf
/// traegt die Art, und ein Recovery-Schluessel signiert nie.
#[cfg(unix)]
#[test]
fn grant_with_a_recipient_container_as_authority_key_fails_with_two() {
    let built = live_clock_archive();
    let laid = lay_out("grant-wrong-kind", &built);
    let authority = container_argument(
        &laid,
        "authority",
        ContainedKeyKind::RecipientKem,
        [0x4c; 32],
        0o600,
    );
    let (authorization, recipient_certificate) = lay_out_grant_files(&laid);

    let argv = grant_argv(
        &laid,
        &laid.recovery_key_path(),
        &authority,
        &authorization,
        &recipient_certificate,
    );
    let output = run(&as_tokens(&argv));
    assert_refusal(&output, 2, "EA-RECOVERY-KEY-SOURCE");
    assert!(!stderr_of(&output).contains("EA-CLI-GRANT-SERVICE-UNAVAILABLE"));
}

/// Ein Befund endet mit SEINEM Code — verify-before-use, nicht die Grenze.
#[test]
fn grant_on_a_finding_ends_with_the_finding_and_not_the_boundary() {
    let built = live_clock_archive_with_mutated_writer_signature();
    let laid = lay_out("grant-finding", &built);
    let (authorization, recipient_certificate) = lay_out_grant_files(&laid);

    let argv = grant_argv(
        &laid,
        &laid.recovery_key_path(),
        &laid.recovery_key_path(),
        &authorization,
        &recipient_certificate,
    );
    let output = run(&as_tokens(&argv));
    assert_eq!(code_of(&output), 10, "exit code");
    assert!(output.stdout.is_empty());
    assert!(!stderr_of(&output).contains("EA-CLI-GRANT-SERVICE-UNAVAILABLE"));
}

// ===========================================================================
// `recovery-test`
// ===========================================================================

/// Verifiziert, Ziel frei, Inventar gelesen — die Grenze, und am Zielpfad
/// liegt NICHTS.
#[test]
fn recovery_test_reads_the_inventory_and_ends_at_the_named_boundary_without_a_file() {
    let built = live_clock_archive();
    let laid = lay_out("rt-ok", &built);
    fs::write(laid.outside("inventory.json"), b"{}").expect("schreibbar");
    let target = laid.target("recovery-test.json");

    let argv = recovery_test_argv(
        &laid,
        &laid.outside_path("inventory.json"),
        &path_argument(&target),
    );
    let output = run(&as_tokens(&argv));
    assert_refusal(&output, 21, "EA-CLI-RECOVERY-TEST-SERVICE-UNAVAILABLE");
    assert!(!target.exists(), "die Grenze legt keine Berichtsdatei an");
    assert!(!stderr_of(&output).contains(&laid.archive_path()));

    // `--format json`: dieselbe Grenze, dasselbe Schweigen.
    let mut json_argv = vec!["--format".to_owned(), "json".to_owned()];
    json_argv.extend(argv);
    let output = run(&as_tokens(&json_argv));
    assert_refusal(&output, 21, "EA-CLI-RECOVERY-TEST-SERVICE-UNAVAILABLE");
    assert!(!target.exists());
}

/// Ein belegtes Ziel ist 2 und bleibt unberuehrt.
#[test]
fn recovery_test_with_an_existing_output_fails_with_two() {
    let built = live_clock_archive();
    let laid = lay_out("rt-busy", &built);
    fs::write(laid.outside("inventory.json"), b"{}").expect("schreibbar");
    fs::write(laid.outside("busy.json"), b"schon da").expect("schreibbar");

    let argv = recovery_test_argv(
        &laid,
        &laid.outside_path("inventory.json"),
        &laid.outside_path("busy.json"),
    );
    let output = run(&as_tokens(&argv));
    assert_refusal(&output, 2, "EA-RECOVERY-OUTPUT-EXISTS");
    assert_eq!(
        fs::read(laid.outside("busy.json")).expect("lesbar"),
        b"schon da"
    );
}

/// Ein fehlendes Inventar ist 20.
#[test]
fn recovery_test_with_a_missing_inventory_fails_with_twenty() {
    let built = live_clock_archive();
    let laid = lay_out("rt-missing", &built);
    let target = laid.target("recovery-test.json");

    let argv = recovery_test_argv(
        &laid,
        &laid.outside_path("fehlt.json"),
        &path_argument(&target),
    );
    let output = run(&as_tokens(&argv));
    assert_refusal(&output, 20, "EA-RECOVERY-IO");
    assert!(!target.exists());
}

/// Ein Befund endet mit SEINEM Code, auch bei belegtem Ziel und fehlendem
/// Inventar.
#[test]
fn recovery_test_on_a_finding_ends_with_the_finding_and_not_the_boundary() {
    let built = live_clock_archive_with_mutated_writer_signature();
    let laid = lay_out("rt-finding", &built);
    fs::write(laid.outside("busy.json"), b"schon da").expect("schreibbar");

    let argv = recovery_test_argv(
        &laid,
        &laid.outside_path("fehlt.json"),
        &laid.outside_path("busy.json"),
    );
    let output = run(&as_tokens(&argv));
    assert_eq!(code_of(&output), 10, "exit code");
    assert!(output.stdout.is_empty());
    assert!(!stderr_of(&output).contains("EA-CLI-RECOVERY-TEST-SERVICE-UNAVAILABLE"));
}
