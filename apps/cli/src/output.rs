//! Die Ausgabeform des Werkzeugs.
//!
//! # Zwei Stroeme, und sie werden nicht vermischt
//!
//! FEHLERMELDUNGEN gehen nach stderr, NUTZAUSGABEN nach stdout. Wer die
//! Berichtsausgabe in eine Datei umlenkt, darf darin keine Meldung finden; wer
//! nach der Grammatik fragt, bekommt eine Nutzausgabe und keinen Fehlertext.
//! Deshalb ist [`UsageError::NoArguments`] der einzige Aufruffall, der nach
//! stdout schreibt.
//!
//! # Was eine Meldung NIE enthaelt
//!
//! Den Inhalt einer Datei und jeden Hostpfad, den der Aufrufer nicht selbst
//! eingegeben hat. Ein von ihm eingegebener Pfad darf zurueckkommen — er
//! stammt aus der Eingabezeile und nicht aus dem Bestand. [`RecoveryError`]
//! zeigt ohnehin nur seinen stabilen Code an; ein Hostpfad kann von dort gar
//! nicht erst hierher gelangen.
//!
//! # WAS EINE AUSGABE NIE ENTHAELT
//!
//! Eine Uhrzeit, einen Hostpfad und jede Laufzeitangabe — in der TEXTFORM
//! genauso wie im Berichtsdokument. Die Regel ist dieselbe und aus demselben
//! Grund: nichtdeterministische Felder entstehen ausschliesslich ueber
//! `--include-runtime-metadata`, und eine Textausgabe, die eine Uhrzeit
//! mitschriebe, waere der Schleichweg daran vorbei. Gemessen wird das nicht
//! ueber ein `contains`, sondern indem
//! `apps/cli/tests/exit_codes.rs::the_text_output_is_a_closed_line_sequence`
//! die GANZE Ausgabe vergleicht: eine zusaetzliche Zeile faellt nur so auf.
//!
//! # Warum `list` kein eigenes JSON hat
//!
//! `schemas/` ist geschlossen, es gibt kein Schema fuer eine Auflistung, und
//! `objectResults` IST die Liste. Eine erfundene `ea.archive-listing/v1` waere
//! eine Schemaaenderung durch die Hintertuer. `list --format json` und
//! `verify --format json` schreiben deshalb BEIDE genau das Dokument
//! `ea.verification-report/v1` — byteweise dasselbe.
//!
//! # `--format` bei `grant` und `recovery-test`: angenommen, wirkungslos
//!
//! Beide Kommandos schreiben in dieser Stufe NICHTS auf stdout — weder in
//! der Text- noch in der JSON-Form —, genau wie `decrypt` und `export`. Die
//! Regel von `organization init` (JSON verweigert, 21) greift hier NICHT,
//! und das ist kein Widerspruch, sondern ihre Grenze: sie sagt, dass ein
//! Kommando mit einer TEXTAUSGABE, die kein Verifikationsbericht ist, keine
//! JSON-Form hat, weil `schemas/` geschlossen ist. `grant` und
//! `recovery-test` haben keine Ausgabe, deren Form zu waehlen waere; ihr
//! Ergebnis IST der Exitcode, und spaeter — Task 8 und 9 — ein Grant-Objekt
//! beziehungsweise die Berichtsdatei, deren Form `--format` so wenig
//! aendert wie bei `report`. Eine Verweigerung heute waere eine Zusage, die
//! Task 9 zuruecknaehme, und sie muesste VOR der Verifikation stehen (wie
//! `--report-signing-key`) und damit einen Befund mit 21 ueberdecken.
//! `--format json` wird deshalb bei beiden GENAU SO angenommen wie bei
//! `decrypt` und `export`: es parst und entscheidet nichts. Gemessen in
//! `apps/cli/tests/full_grammar.rs`.

use std::io::{self, Write};

use ea_admin::{
    AdminError, BootstrapStep, ProductionState,
    clock_release::{ClockReleaseAvailability, ClockReleaseWorkflowError},
    operator_runtime::{OperatorGoLiveReport, OperatorRuntimeError},
    registry::RegistryWorkflowError,
    revocation::RevocationTargetClass,
    writer_transition::{WriterTransitionError, WriterTransitionRequestError},
};
use ea_recovery::RecoveryError;
use ea_types::{
    CertificateHash, ChainId, ChainSequence, EntryHash, Hash32, ObjectHash, OrganizationId,
    RegistryVersion, UnixMillis,
};
use ea_verify::VerificationReportV1;

use crate::args::{Format, UsageError};

/// Die geschlossene Grammatik, Zeile fuer Zeile.
///
/// Die verfügbaren Aufrufformen. Der Text ist Teil
/// des beobachtbaren Verhaltens und wird als solcher gemessen.
///
/// # Die ersten sieben Zeilen sind `design.md` §16.1, in dessen Reihenfolge
///
/// `verify`, `list`, `decrypt`, `grant`, `report`, `export`,
/// `recovery-test` — die normative Grammatik vollstaendig und in der Ordnung
/// der Norm; die uebrigen Zeilen sind die Kommandos des Umsetzungsplans.
/// `grant` und `recovery-test` stehen hier, obwohl beide in dieser Stufe an
/// einer benannten Grenze enden (`crate::commands::grant`,
/// `crate::commands::recovery_test`): anders als `--report-signing-key` sind
/// sie keine Schalter, die ausnahmslos verweigert werden, sondern Kommandos,
/// die verifizieren, ihre Quellen aufloesen und ihre Eingaben lesen — mit
/// den Codes, die der Dienst spaeter traegt. Was sie NICHT tun, sagt ihre
/// Scope-Zeile ([`GRANT_SCOPE_NOTE_V1`], [`RECOVERY_TEST_SCOPE_NOTE_V1`]).
///
/// # Warum die Zeile von `organization init` `<new-file>` sagt
///
/// Bei den Wiederherstellungskommandos ist der Anker eine gepruefte EINGABE.
/// Bei `organization init` ist er das, was die Zeremonie am Ende bildet — der
/// Pfad benennt also einen Platz, der noch frei sein muss. Die Begruendung
/// steht in `crate::commands::organization`; hier steht sie in einem Wort,
/// damit ein Aufrufer sie schon in der Grammatik sieht.
const GRAMMAR_V1: [&str; 13] = [
    "einsatzarchiv --trust-anchor <file> verify  <archive-path>",
    "einsatzarchiv --trust-anchor <file> list    <archive-path>",
    "einsatzarchiv --trust-anchor <file> decrypt <archive-path> --key <key-source> --output <target>",
    "einsatzarchiv --trust-anchor <file> grant <entry-or-archive> --recovery-key <source> --authority-key <source> --authorization <file> --recipient-cert <file>",
    "einsatzarchiv --trust-anchor <file> report  <archive-path> --output <report-file>",
    "einsatzarchiv --trust-anchor <file> export  <archive-or-server> --output <new-target>",
    "einsatzarchiv --trust-anchor <file> recovery-test <archive-path> --key-inventory <file> --output <report-file>",
    "einsatzarchiv --trust-anchor <new-file> organization init",
    "einsatzarchiv --trust-anchor <file> operator provision|verify-session|revoke --operator-config <file>",
    "einsatzarchiv --trust-anchor <file> registry revocation-plan --operator-config <file> --effective-from <sequence> --valid-through <sequence> --not-after <unix-millis>",
    "einsatzarchiv --trust-anchor <file> clock-release apply --operator-config <file> --release <file>",
    "einsatzarchiv --trust-anchor <file> writer-transition prepare --operator-config <file> --request <file>",
    "einsatzarchiv --trust-anchor <file> writer-transition activate --operator-config <file> --request <file> --transition-object <file> --valid-through <sequence> --not-after <unix-millis>",
];

/// Was `organization init` TUT — und was ausdruecklich nicht.
///
/// # Warum diese Zeile ueberhaupt gedruckt wird
///
/// Die uebrigen fuenf Kommandos tun, was ihr Name sagt. Das sechste tut
/// WENIGER, als sein Name vermuten laesst: es beginnt oder setzt die Zeremonie
/// fort und berichtet ihren Schritt, aber es fuehrt keinen Schritt aus, der
/// eine Offline-Schluesselquelle braucht — `ea_key_provider::SecretPurpose`
/// kennt vier lokale Writer-Zwecke und ausdruecklich keinen Wurzelzweck
/// (`crates/ea-key-provider/src/contract.rs:32-51`), und ein CLI-Prozess kann
/// die aeusseren Schluessel nicht herbeireden. Wer das erst an einem
/// ausbleibenden Schritt bemerkt, hat die Zeremonie bereits begonnen.
///
/// Englisch wie jede andere beobachtbare Zeichenkette dieses Binaers.
const ORGANIZATION_SCOPE_NOTE_V1: &str = "organization init begins or resumes the ceremony and \
     reports its step; it drives no step that needs offline key sources";

/// Druckt die Grammatik auf stdout.
///
/// `println!` und ausdruecklich kein gepufferter Schreiber: der Aufrufer
/// beendet den Prozess unmittelbar danach, und ein Puffer, der dabei nicht
/// mehr geleert wird, machte die Ausgabe von der Zeitplanung abhaengig.
pub fn print_grammar() {
    for line in GRAMMAR_V1 {
        println!("{line}");
    }
    println!("{KEY_SOURCE_NOTE_V1}");
    println!("{GRANT_SCOPE_NOTE_V1}");
    println!("{RECOVERY_TEST_SCOPE_NOTE_V1}");
    println!("{ORGANIZATION_SCOPE_NOTE_V1}");
    println!(
        "operator config contains public archive/database paths, certificate/binding hashes, role and purpose; authority mode requires authority=true and target_certificate_hash; offline exchange uses ceremony_exchange_directory"
    );
    println!("{REGISTRY_SCOPE_NOTE_V1}");
    println!("{CLOCK_RELEASE_SCOPE_NOTE_V1}");
    println!("{WRITER_TRANSITION_SCOPE_NOTE_V1}");
}

/// Die Grammatik einer `<key-source>`, Wort fuer Wort.
///
/// # Warum sie GEDRUCKT wird, obwohl `--format` es nicht wird
///
/// `--format text|json` erklaert die Grammatik nirgends: seine zwei Woerter
/// stehen im Fehlertext, sobald ein drittes kommt. Eine Schluesselquelle hat
/// drei Formen mit je einem Praefix und benannten Feldern, und ein Aufrufer,
/// der sie nur aus `unknown field` erraten muesste, tippte sie nie richtig.
/// Die Zeile nennt deshalb die Formen — und die Regel, die alle drei teilen:
/// Passphrase und PIN kommen aus einer benannten Datei, nie aus argv und
/// nie aus der Umgebung (`ea_recovery::key_source`). Definiert ist die
/// Grammatik dort; hier steht ihre Anzeige.
///
/// Englisch wie jede andere beobachtbare Zeichenkette dieses Binaers.
const KEY_SOURCE_NOTE_V1: &str = "key-source is <path> | file:<path> | \
     container:<path>;passphrase-file=<path> | \
     pkcs11:module=<path>;token=<label>;id=<hex>;pin-file=<path>; passphrase and pin are read \
     from the named file with owner-only permissions, never from argv or the environment";

/// Was `grant` TUT — und wo es in dieser Stufe endet.
///
/// Dieselbe Bauart wie [`ORGANIZATION_SCOPE_NOTE_V1`]: das Kommando tut
/// WENIGER, als sein Name verspricht, und die Grammatik sagt das, bevor ein
/// Aufrufer es an der Verweigerung bemerkt. Die Begruendung fuer die 21 steht
/// in `crate::commands::grant`.
///
/// Englisch wie jede andere beobachtbare Zeichenkette dieses Binaers.
const GRANT_SCOPE_NOTE_V1: &str = "grant verifies the archive with the recovery key, resolves \
     both key sources and reads both files, then ends with exit 21 naming the missing \
     historical grant service; it issues nothing";

/// Was `recovery-test` TUT — und wo es in dieser Stufe endet.
///
/// Englisch wie jede andere beobachtbare Zeichenkette dieses Binaers.
const RECOVERY_TEST_SCOPE_NOTE_V1: &str = "recovery-test verifies the archive, requires a free \
     output path and reads the key inventory, then ends with exit 21 naming the missing recovery \
     test service; it writes nothing";

/// Was `registry revocation-plan` TUT — und was ausdruecklich nicht.
///
/// Dieselbe Bauart wie [`ORGANIZATION_SCOPE_NOTE_V1`] und aus demselben Grund:
/// das Kommando tut WENIGER, als ein Leser vermuten koennte. Es bereitet die
/// Aenderung 1 vor und benennt ihre Reichweite; veroeffentlicht wird sie erst
/// mit der Wurzelsignatur, und die dafuer noetigen Offline-Schluesselquellen
/// hat ein CLI-Prozess nicht. Das Ziel steht in der Bedienerdatei und nicht in
/// der Aufrufzeile — dazu die Begruendung in `crate::commands::registry`.
///
/// Englisch wie jede andere beobachtbare Zeichenkette dieses Binaers.
const REGISTRY_SCOPE_NOTE_V1: &str = "registry revocation-plan prepares change 1 for the object \
     named by target_certificate_hash in the operator config and reports its reach; it publishes \
     nothing, because publishing needs the root signature";

/// Was `clock-release apply` TUT — und warum es kein `issue` gibt.
///
/// Englisch wie jede andere beobachtbare Zeichenkette dieses Binaers.
const CLOCK_RELEASE_SCOPE_NOTE_V1: &str = "clock-release apply consumes an already issued release \
     file and never prints its bytes; issuing one is a step of the administration workflow and not \
     of this tool";

/// Was `writer-transition` TUT — und was ausdruecklich nicht.
///
/// Dieselbe Bauart wie [`REGISTRY_SCOPE_NOTE_V1`]: beide Unterkommandos tun
/// WENIGER, als ihr Name vermuten laesst. `prepare` prueft und zeigt,
/// `activate` haelt und plant; signiert wird in der Wurzelzeremonie, und die
/// hat dieser Prozess nicht.
///
/// Englisch wie jede andere beobachtbare Zeichenkette dieses Binaers.
const WRITER_TRANSITION_SCOPE_NOTE_V1: &str = "writer-transition prepare checks the request file \
     against the selected head and shows the fields the root ceremony will sign; activate holds \
     the published transition object against the same request and plans change 3; neither signs \
     nor publishes anything";

/// Nur stabile Fehlercodes; keine privaten Profil-, Konto- oder Pfadangaben.
pub fn print_operator_error(error: &OperatorRuntimeError) {
    eprintln!("einsatzarchiv: {error}");
}

pub fn print_operator_authority_error(error: &ea_admin::operator_authority::AuthorityError) {
    eprintln!("einsatzarchiv: {error}");
}

pub fn print_operator_authority_report(
    count: usize,
    format: Format,
) -> Result<(), OperatorRuntimeError> {
    let body = match format {
        Format::Json => format!("{{\"authority\":true,\"processed_requests\":{count}}}\n"),
        Format::Text => format!("authority=true\nprocessed_requests={count}\n"),
    };
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(body.as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(|_| OperatorRuntimeError::Io)
}

/// Das oeffentliche Betriebsprotokoll enthaelt keine Klartext-Personendaten.
pub fn print_operator_report(
    report: &OperatorGoLiveReport,
    format: Format,
) -> Result<(), OperatorRuntimeError> {
    let body = match format {
        Format::Json => report.to_json()?,
        Format::Text => format!(
            "binding_state={}\nproductive_binding_hashes={}\nrevoked_binding_hashes={}\ndevice_certificate_hash={}\nrole={}\nos_account_binding_hash={}\ncurrent_native_account_match={}\nregistry_head_hash={}\nnext_sequence={}\nrevocation_procedure={}",
            report.binding_state,
            report.productive_binding_hashes.join(","),
            report.revoked_binding_hashes.join(","),
            report.device_certificate_hash,
            report.role,
            report.os_account_binding_hash,
            report.current_native_account_match,
            report.registry_head_hash,
            report.next_sequence,
            report.revocation_procedure,
        ),
    };
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(body.as_bytes())
        .and_then(|()| stdout.write_all(b"\n"))
        .and_then(|()| stdout.flush())
        .map_err(|_| OperatorRuntimeError::Io)
}

/// Druckt einen Aufruffehler auf stderr.
///
/// Das Praefix benennt das Werkzeug, damit die Zeile in einem Protokoll
/// zuzuordnen ist, in dem mehrere Prozesse schreiben.
pub fn print_usage_error(error: &UsageError) {
    eprintln!("einsatzarchiv: {error}");
}

/// Druckt einen Laufzeitfehler auf stderr.
///
/// Angezeigt wird der STABILE Fehlercode und nichts weiter — `RecoveryError`
/// traegt bewusst weder Pfad noch Bytes. Ein Test darf auf den Code
/// assertieren; ein Betreiber soll daran erkennen, was gescheitert ist.
pub fn print_recovery_error(error: &RecoveryError) {
    eprintln!("einsatzarchiv: {error}");
}

/// Druckt einen Zeremoniefehler auf stderr.
///
/// Dieselbe Form wie [`print_recovery_error`] und aus demselben Grund:
/// [`AdminError`] zeigt ausschliesslich seinen STABILEN Code an
/// (`crates/ea-admin/src/error.rs`), traegt weder Pfad noch Bytes, und ein
/// Test darf darauf assertieren.
pub fn print_admin_error(error: &AdminError) {
    eprintln!("einsatzarchiv: {error}");
}

/// Die Ablehnung einer belegten Ankerdatei, Wort fuer Wort.
///
/// # Sie NENNT den Grund, statt auf eine Option zu verweisen
///
/// Die Datei an diesem Pfad kann eine lebende Vertrauensquelle sein.
/// `design.md`:1782 laesst dieses Werkzeug keinen Anker erfinden und keinen aus
/// dem geprueften Bestand nehmen; eine bestehende Datei ersatzweise zu
/// ueberschreiben naehme einer Organisation ihre Wurzel. Der Exitcode ist 2 und
/// nicht 20: es ist nichts misslungen, und der Lauf ist mit einem freien Pfad
/// unveraendert wiederholbar.
///
/// Englisch wie jede andere beobachtbare Zeichenkette dieses Binaers.
const ANCHOR_PATH_OCCUPIED_REFUSAL_V1: &str = "the --trust-anchor path of organization init names \
     the place this ceremony's anchor will occupy, and a file already exists there: this tool \
     never overwrites a trust source, so choose a free path";

/// Druckt die Ablehnung einer belegten Ankerdatei auf stderr.
///
/// stdout bleibt LEER: es ist keine Zeremonie entstanden, ueber die etwas zu
/// sagen waere.
pub fn print_anchor_path_occupied_refusal() {
    eprintln!("einsatzarchiv: {ANCHOR_PATH_OCCUPIED_REFUSAL_V1}");
}

/// Die Ablehnung der JSON-Form fuer den Zeremoniestatus, Wort fuer Wort.
///
/// # Warum es kein `organization init --format json` gibt
///
/// `schemas/` ist geschlossen, und die einzige JSON-Ausgabe dieses Werkzeugs
/// ist `ea.verification-report/v1`. Ein Zeremoniestatus ist kein
/// Verifikationsbericht; ein hier erfundenes Dokument waere eine
/// Schemaaenderung durch die Hintertuer — dieselbe Ueberlegung, die oben schon
/// `list` kein eigenes JSON gibt. Der Exitcode ist 21: es ist nichts
/// misslungen, es ist etwas nicht vorhanden.
///
/// Englisch wie jede andere beobachtbare Zeichenkette dieses Binaers.
const ORGANIZATION_JSON_REFUSAL_V1: &str = "organization init has a text form only: schemas/ is \
     closed, ea.verification-report/v1 is the only report document of this tool, and a ceremony \
     status is not a verification report";

/// Druckt die Ablehnung der JSON-Form auf stderr.
pub fn print_organization_json_refusal() {
    eprintln!("einsatzarchiv: {ORGANIZATION_JSON_REFUSAL_V1}");
}

/// Schreibt den Zeremoniestatus als geschlossene Zeilenfolge auf stdout.
///
/// # Die Form ist GELIEHEN, nicht erfunden
///
/// Dieselben Regeln wie [`print_report_text`]: stabile Schluessel-Wert-Paare,
/// eine Zeile je Angabe, gepunktete Schluessel fuer zusammengehoerige Felder
/// wie bei `chainHead.sequence`, Bytefolgen als Kleinbuchstaben-Hex. Keine
/// Uhrzeit, kein Hostpfad, keine Laufzeitangabe — die Regel dieses Moduls gilt
/// hier unveraendert.
///
/// `bootstrapStep.count` steht dabei ausdruecklich in der Ausgabe: ohne die
/// Zwoelf sagt eine Nummer allein nicht, wie weit die Zeremonie noch ist.
///
/// # Errors
///
/// [`RecoveryError::Io`], wenn stdout nicht schreibbar ist.
pub fn print_bootstrap_status_text(
    step: BootstrapStep,
    organization: &[u8; 16],
    chain: &[u8; 16],
    production_state: ProductionState,
) -> Result<(), RecoveryError> {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    writeln!(out, "bootstrapStep.number {}", step.number())?;
    writeln!(out, "bootstrapStep.name {}", step.name())?;
    writeln!(out, "bootstrapStep.count {}", BootstrapStep::ALL.len())?;
    write!(out, "organizationId ")?;
    write_hex(&mut out, organization)?;
    writeln!(out)?;
    write!(out, "chainId ")?;
    write_hex(&mut out, chain)?;
    writeln!(out)?;
    writeln!(out, "productionState {production_state:?}")?;

    out.flush()?;
    Ok(())
}

/// Die Verweigerung der Berichtssignatur, Wort fuer Wort.
///
/// # Sie NENNT das fehlende Element und beruhigt nicht
///
/// Drei Dinge stehen darin, und alle drei sind pruefbar: dass es fuer
/// `ea.verification-report/v1` keinen `contentType` gibt, dass es weder
/// Signiererrolle noch Zertifikatsfaehigkeit fuer einen Bericht gibt, und dass
/// ein unsignierter, GEHASHTER Bericht deshalb das normkonforme Ergebnis ist
/// (`design.md`:1781: „sofern eine autorisierte Signaturrolle verfuegbar ist").
/// Die fuenf Codestellen dazu stehen in
/// `docs/adr/0001-toolchain-and-cryptography-dependencies.md`.
///
/// Englisch wie jede andere beobachtbare Zeichenkette dieses Binaers; die
/// Begruendungen bleiben in den Doc-Kommentaren.
const REPORT_SIGNING_REFUSAL_V1: &str = "report signing is unavailable in suite v1: there is no \
     contentType for ea.verification-report/v1, no signer role and no certificate capability for \
     a verification report; without them an unsigned, hashed report is the conformant result";

/// Druckt die Verweigerung der Berichtssignatur auf stderr.
///
/// stdout bleibt LEER: es ist kein Bericht entstanden, ueber den etwas zu sagen
/// waere.
pub fn print_report_signing_refusal() {
    eprintln!("einsatzarchiv: {REPORT_SIGNING_REFUSAL_V1}");
}

/// Der stabile Code, mit dem `grant` seine Grenze benennt.
///
/// `EA-CLI-` und nicht `EA-RECOVERY-`: die Grenze liegt im KOMMANDOPFAD —
/// `ea-recovery` hat jede Eingabe aufgeloest und traegt keinen Fehler; was
/// fehlt, ist der Dienst, den dieses Werkzeug rufen wuerde. Ein Skript
/// unterscheidet daran diese 21 von der PKCS#11-Grenze
/// (`EA-RECOVERY-PKCS11-UNBOUND`) und von einer Plattform ohne Rechtebits.
pub const GRANT_SERVICE_UNAVAILABLE_CODE: &str = "EA-CLI-GRANT-SERVICE-UNAVAILABLE";

/// Der stabile Code, mit dem `recovery-test` seine Grenze benennt.
pub const RECOVERY_TEST_SERVICE_UNAVAILABLE_CODE: &str = "EA-CLI-RECOVERY-TEST-SERVICE-UNAVAILABLE";

/// Die Verweigerung des historischen Grants, Wort fuer Wort.
///
/// # Sie NENNT, was geschehen ist, was fehlt und was NICHT entstanden ist
///
/// Drei Aussagen, alle pruefbar: der Bestand ist verifiziert und jede Eingabe
/// aufgeloest (sonst stuende ein anderer Code da), der
/// `HistoricalGrantService` ist Stage-5 Task 8, und es wurde nichts
/// ausgestellt und nichts geschrieben. Ohne die dritte Aussage suchte ein
/// Betreiber nach einem Grant-Objekt, das es nicht gibt. Die Begruendung fuer
/// 21 statt 0 oder 15 steht in `crate::commands::grant`.
///
/// Sie nennt KEINEN Pfad und KEIN Byte einer Eingabe: die Zeile ist fest und
/// haengt von keinem Argument ab — dieselbe Regel wie bei
/// [`CLOCK_RELEASE_APPLIED_V1`].
///
/// Englisch wie jede andere beobachtbare Zeichenkette dieses Binaers.
const GRANT_SERVICE_REFUSAL_V1: &str = "the archive verified and every grant input resolved, \
     but the historical grant service arrives with Stage-5 Task 8: nothing was issued and \
     nothing was written";

/// Druckt die Verweigerung des historischen Grants auf stderr.
///
/// stdout bleibt LEER: es ist kein Grant entstanden, ueber den etwas zu sagen
/// waere.
pub fn print_grant_service_refusal() {
    eprintln!("einsatzarchiv: {GRANT_SERVICE_UNAVAILABLE_CODE}: {GRANT_SERVICE_REFUSAL_V1}");
}

/// Die Verweigerung des Wiederherstellungstests, Wort fuer Wort.
///
/// Dieselbe Bauart wie [`GRANT_SERVICE_REFUSAL_V1`]; der Dienst ist Task 9,
/// und die dritte Aussage heisst hier: die Berichtsdatei ist NICHT angelegt.
///
/// Englisch wie jede andere beobachtbare Zeichenkette dieses Binaers.
const RECOVERY_TEST_SERVICE_REFUSAL_V1: &str = "the archive verified, the output path is free \
     and the key inventory was read, but the recovery test service arrives with Stage-5 Task 9: \
     no report was written";

/// Druckt die Verweigerung des Wiederherstellungstests auf stderr.
///
/// stdout bleibt LEER, und am Zielpfad liegt nichts.
pub fn print_recovery_test_service_refusal() {
    eprintln!(
        "einsatzarchiv: {RECOVERY_TEST_SERVICE_UNAVAILABLE_CODE}: \
         {RECOVERY_TEST_SERVICE_REFUSAL_V1}"
    );
}

/// Die Ablehnung einer Quelle, die kein Dateisystembestand ist, Wort fuer Wort.
///
/// # Sie NENNT die fehlende Faehigkeit
///
/// Die Grammatik nennt `<archive-or-server>`; Stage 1 hat keine Serverquelle.
/// Wer eine Adresse oder einen Tippfehler uebergibt, soll erfahren, dass diese
/// Stufe ausschliesslich ein Verzeichnis im Dateisystem exportiert — und nicht
/// bloss einen Fehlercode sehen, aus dem er auf eine volle Platte schliesst.
/// Der Exitcode ist 21 und ausdruecklich nicht 20: es ist nichts misslungen, es
/// ist etwas nicht vorhanden.
///
/// Englisch wie jede andere beobachtbare Zeichenkette dieses Binaers; die
/// Begruendungen bleiben in den Doc-Kommentaren.
const EXPORT_SOURCE_REFUSAL_V1: &str = "export takes a file system archive directory only: this \
     stage has no server source, and the given path is not an existing directory";

/// Druckt die Ablehnung der Exportquelle auf stderr.
///
/// stdout bleibt LEER: es ist kein Bericht entstanden, ueber den etwas zu sagen
/// waere, und im Ziel steht nichts.
pub fn print_export_source_refusal() {
    eprintln!("einsatzarchiv: {EXPORT_SOURCE_REFUSAL_V1}");
}

/// Schreibt `bytes` als Kleinbuchstaben-Hex.
///
/// Von Hand und nicht ueber `hex`: die Kiste ist eine DEV-Dependency dieses
/// Pakets und gehoert nicht in den Auslieferungsgraphen eines
/// Wiederherstellungswerkzeugs. Die Form ist dieselbe, die
/// `crates/ea-verify/src/json.rs` fuer das Berichtsdokument erzwingt.
fn write_hex(out: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    for byte in bytes {
        write!(out, "{byte:02x}")?;
    }
    Ok(())
}

/// Schreibt den Bericht als geschlossene Zeilenfolge auf stdout.
///
/// # Die Reihenfolge ist GELIEHEN, nicht erfunden
///
/// Erst die vier Zaehler und der Kettenkopf, dann JE FEHLERARRAY seine Anzahl
/// in der Gliederreihenfolge des Berichtsdokuments
/// (`crates/ea-verify/src/report.rs::write_document`: `gaps`, `formatErrors`,
/// `quarantinedObjects`, `signatureErrors`, `evidenceErrors`,
/// `decryptionErrors`), zuletzt `reportHash`. Eine zweite, eigene Ordnung
/// haette keinen Nutzen und einen Preis: sie muesste getrennt gepflegt werden
/// und wuerde still auseinanderlaufen.
///
/// # Errors
///
/// [`RecoveryError::Io`], wenn stdout nicht schreibbar ist — etwa, weil der
/// Empfaenger der Pipe bereits beendet wurde.
pub fn print_report_text(report: &VerificationReportV1) -> Result<(), RecoveryError> {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    writeln!(out, "archiveObjectCount {}", report.archive_object_count())?;
    writeln!(out, "entryPackageCount {}", report.entry_package_count())?;
    writeln!(
        out,
        "destroyedEntryCount {}",
        report.destroyed_entry_count()
    )?;
    writeln!(out, "nonObjectFileCount {}", report.non_object_file_count())?;
    writeln!(
        out,
        "chainHead.sequence {}",
        report.chain_head().sequence().get()
    )?;
    write!(out, "chainHead.entryHash ")?;
    write_hex(&mut out, report.chain_head().entry_hash().as_bytes())?;
    writeln!(out)?;

    writeln!(out, "gaps {}", report.gaps().len())?;
    writeln!(out, "formatErrors {}", report.format_errors().len())?;
    writeln!(
        out,
        "quarantinedObjects {}",
        report.quarantined_objects().len()
    )?;
    writeln!(out, "signatureErrors {}", report.signature_errors().len())?;
    writeln!(out, "evidenceErrors {}", report.evidence_errors().len())?;
    writeln!(out, "decryptionErrors {}", report.decryption_errors().len())?;

    write!(out, "reportHash ")?;
    write_hex(&mut out, report.report_hash().as_bytes())?;
    writeln!(out)?;

    out.flush()?;
    Ok(())
}

/// Schreibt die Auflistung als Zeilenfolge auf stdout.
///
/// Je Objektergebnis eine Zeile `<objectHash> <objectType> <result>
/// <serverConfirmation>`, danach je isoliertem Objekt eine Zeile
/// `<objectHash> <reason>`. Beide Folgen stehen in der ORDNUNG DES BERICHTS —
/// aufsteigend nach `objectHash` —, weil sie unmittelbar aus dessen
/// `BTreeMap`s stammen und hier nichts umsortiert wird.
///
/// `objectType` erscheint als ZAHL und nicht als Name: das Berichtsschema
/// fuehrt `objectResult.objectType` als Typbyte 1..6, und `schemas/` ist
/// geschlossen. Ein hier erfundener Name waere ein zweites, ungeprueftes
/// Vokabular ueber derselben Sache.
///
/// # Errors
///
/// Wie [`print_report_text`].
pub fn print_listing_text(report: &VerificationReportV1) -> Result<(), RecoveryError> {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for result in report.object_results() {
        write_hex(&mut out, result.object_hash().as_bytes())?;
        writeln!(
            out,
            " {} {} {}",
            result.object_type().code(),
            result.result().as_str(),
            result.server_confirmation().as_str()
        )?;
    }
    for quarantined in report.quarantined_objects() {
        write_hex(&mut out, quarantined.object_hash().as_bytes())?;
        writeln!(out, " {}", quarantined.reason().as_str())?;
    }

    out.flush()?;
    Ok(())
}

/// Schreibt das kanonische Berichtsdokument auf stdout.
///
/// OHNE abschliessenden Zeilenumbruch. `crates/ea-verify/src/json.rs:20-23`
/// friert diese Form ein; ein Umbruch waere ein zusaetzliches Byte und braeche
/// die Byteidentitaet, auf der jede spaetere Aussage ueber den Bericht steht.
///
/// # Errors
///
/// [`RecoveryError::Verify`], falls der Bericht je eine Zeichenkette ausser der
/// Reihe truege — das ist ein Integritaetsbefund und kein Schreibfehler.
/// [`RecoveryError::Io`], wenn stdout nicht schreibbar ist.
pub fn print_report_json(report: &VerificationReportV1) -> Result<(), RecoveryError> {
    let document = report.to_canonical_json()?;
    let stdout = io::stdout();
    let mut out = stdout.lock();
    out.write_all(document.as_bytes())?;
    out.flush()?;
    Ok(())
}

/// Die Reichweite eines geplanten Widerrufs, abgelesen und nicht behauptet.
///
/// # Warum dieser Typ hier steht und nicht `ea_admin::revocation::RevocationEffect` gedruckt wird
///
/// [`ea_admin::revocation::RevocationEffect`] hat keinen oeffentlichen
/// Konstruktor — er entsteht ausschliesslich in `plan_revocation` aus einem
/// gewaehlten Registrierungskopf. Ein Drucker, der ihn naehme, waere ausserhalb
/// von `ea-admin` nicht messbar: es gaebe keinen Weg, ihm einen Wert
/// vorzulegen, ohne eine vollstaendige, OS-gebundene Bedienerlaufzeit zu
/// bauen. Die Zeilen tragen aber genau die Zusagen des Plans, und eine Zusage,
/// die kein Zeuge liest, ist keine.
///
/// Deshalb liest `crate::commands::registry` die vier Angaben an GENAU EINER
/// Stelle vom Effekt ab und legt sie hier hinein. Der Effekt bleibt die
/// Wahrheit; dieser Typ ist ihre Anzeige.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevocationPlanView {
    /// Die Zielart, die `classify_revocation_target` aus dem Bestand
    /// hergeleitet hat.
    pub target_class: RevocationTargetClass,
    /// Die Registrierungsversion des geplanten Ereignisses.
    pub registry_version: RegistryVersion,
    /// `RevocationEffect::stops_new_grants_from`.
    pub stops_new_grants_from: ChainSequence,
    /// Die Obergrenze des Lease des geplanten Ereignisses.
    pub valid_through_sequence: ChainSequence,
    /// `RevocationEffect::recalls_issued_grants` — vertraglich `false`.
    pub recalls_issued_grants: bool,
    /// `RevocationEffect::recalls_decrypted_plaintext` — vertraglich `false`.
    pub recalls_decrypted_plaintext: bool,
}

/// Was ein Widerruf NICHT zurueckholt, Wort fuer Wort.
///
/// # Warum dieser Satz gedruckt wird und kein Kommentar bleibt
///
/// „Widerruf holt nichts zurueck" ist eine Produktinvariante der Global
/// Constraints und eine ausdrueckliche Zusage des Umsetzungsplans an die
/// BEDIENFUEHRUNG. Ein Betreiber, der einen Widerruf ausloest, soll nicht
/// glauben, damit sei ein bereits erteilter Zugriff eingesammelt; die
/// Schluesselumschlaege liegen im Archiv und in Repliken, die diese Handlung
/// nicht erreicht, und entschluesselter Klartext liegt ausserhalb der
/// Reichweite jeder Registrierungsaenderung.
///
/// Englisch wie jede andere beobachtbare Zeichenkette dieses Binaers.
pub const REVOCATION_SCOPE_NOTE_V1: &str = "already issued grants and already decrypted plaintext \
     are not recalled by this revocation: only new grants stop, and they stop from the effective \
     sequence onwards";

/// Das Wort einer Zielart, wie es in der Ausgabe steht.
const fn target_class_word(class: RevocationTargetClass) -> &'static str {
    match class {
        RevocationTargetClass::NonAdminDevice => "non-admin-device",
        RevocationTargetClass::OperatorBinding => "operator-binding",
        RevocationTargetClass::Component => "component",
    }
}

/// Die Textform des Widerrufsplans als GESCHLOSSENE Zeilenfolge.
///
/// Geschlossen und nicht „mindestens diese Zeilen": nur ein vollstaendiger
/// Vergleich faellt ueber eine zusaetzliche Zeile. Keine Uhrzeit, kein
/// Hostpfad, keine Laufzeitangabe — die Regel dieses Moduls gilt unveraendert;
/// insbesondere stehen `issuedAt`, `notBefore` und `notAfter` des geplanten
/// Ereignisses ausdruecklich NICHT hier.
#[must_use]
pub fn revocation_plan_lines(view: &RevocationPlanView) -> Vec<String> {
    vec![
        format!("target_class={}", target_class_word(view.target_class)),
        format!("registry_version={}", view.registry_version.get()),
        format!("stops_new_grants_from={}", view.stops_new_grants_from.get()),
        format!(
            "valid_through_sequence={}",
            view.valid_through_sequence.get()
        ),
        format!("recalls_issued_grants={}", view.recalls_issued_grants),
        format!(
            "recalls_decrypted_plaintext={}",
            view.recalls_decrypted_plaintext
        ),
        REVOCATION_SCOPE_NOTE_V1.to_owned(),
    ]
}

/// Dieselben Angaben als EINE JSON-Zeile.
///
/// Von Hand gebaut wie [`print_operator_authority_report`]: alle Werte sind
/// Zahlen, Wahrheitswerte oder feste ASCII-Woerter dieses Moduls, also gibt es
/// nichts zu maskieren. Ein Serialisierer daefuer waere eine Dependency fuer
/// sieben Felder.
///
/// Ausdruecklich KEIN neues Schema: `schemas/` ist geschlossen, und diese Zeile
/// ist eine Anzeige und kein Dokument — dieselbe Ueberlegung, aus der
/// `organization init` gar keine JSON-Form hat.
#[must_use]
pub fn revocation_plan_json(view: &RevocationPlanView) -> String {
    format!(
        "{{\"target_class\":\"{}\",\"registry_version\":{},\"stops_new_grants_from\":{},\
         \"valid_through_sequence\":{},\"recalls_issued_grants\":{},\
         \"recalls_decrypted_plaintext\":{},\"scope_note\":\"{REVOCATION_SCOPE_NOTE_V1}\"}}",
        target_class_word(view.target_class),
        view.registry_version.get(),
        view.stops_new_grants_from.get(),
        view.valid_through_sequence.get(),
        view.recalls_issued_grants,
        view.recalls_decrypted_plaintext,
    )
}

/// Schreibt den Widerrufsplan auf stdout.
///
/// # Errors
///
/// [`OperatorRuntimeError::Io`], wenn stdout nicht schreibbar ist.
pub fn print_revocation_plan_report(
    view: &RevocationPlanView,
    format: Format,
) -> Result<(), OperatorRuntimeError> {
    let body = match format {
        Format::Json => revocation_plan_json(view),
        Format::Text => revocation_plan_lines(view).join("\n"),
    };
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(body.as_bytes())
        .and_then(|()| stdout.write_all(b"\n"))
        .and_then(|()| stdout.flush())
        .map_err(|_| OperatorRuntimeError::Io)
}

/// Die Ablehnung einer Bedienerdatei ohne Widerrufsziel, Wort fuer Wort.
///
/// Englisch wie jede andere beobachtbare Zeichenkette dieses Binaers.
const MISSING_REVOCATION_TARGET_REFUSAL_V1: &str = "registry revocation-plan revokes the object \
     named by target_certificate_hash in the operator config, and this config names none";

/// Druckt die Ablehnung einer Bedienerdatei ohne Widerrufsziel auf stderr.
pub fn print_missing_revocation_target_refusal() {
    eprintln!("einsatzarchiv: {MISSING_REVOCATION_TARGET_REFUSAL_V1}");
}

/// Die Quittung einer verbrauchten Uhrfreigabe.
///
/// EINE feste Zeile ohne jeden Platzhalter, und das ist ihr Zweck: die
/// Freigabebytes binden eine Zufalls-Nonce
/// (`ea_format::ClockReleaseContextV1`), und eine Ausgabe, die irgendetwas aus
/// ihnen wiedergaebe, truege sie in jede Protokolldatei. Was von keinem
/// Eingabebyte abhaengt, kann sie nicht tragen.
///
/// Sie sagt ausserdem NICHT, welcher Kopf gewaehlt wurde. Der Grund ist keine
/// Zurueckhaltung, sondern eine Grenze: `apply_clock_release` liefert ein
/// `ea_trust::RegistrySelectionOutcome`, und dieses Paket fuehrt keine Kante zu
/// `ea-trust` — es kann den Ausgang also nicht auseinandernehmen. Solange
/// `ea-admin` dafuer keinen eigenen Berichtstyp herausgibt, ist eine Quittung
/// ohne Kopfangabe ehrlicher als eine erfundene.
///
/// Englisch wie jede andere beobachtbare Zeichenkette dieses Binaers.
pub const CLOCK_RELEASE_APPLIED_V1: &str = "clock_release=applied";

/// Der Bedienhinweis zu einer Verfuegbarkeit, Wort fuer Wort.
///
/// # Warum die drei Ausgaenge UNTERSCHIEDLICH klingen muessen
///
/// „Es wird gar keine Freigabe angeboten" und „eine Freigabe wurde angeboten
/// und abgewiesen" sind zwei verschiedene Lagen, und der Umsetzungsplan
/// verlangt ausdruecklich, dass die Bedienfuehrung sie unterscheidet. Ohne
/// unabhaengige Zeitreferenz gibt es nichts, wogegen eine Freigabe messen
/// koennte — ein Betreiber, dem beides gleich klingt, sucht nach einer
/// Freigabe, die es nicht gibt.
///
/// Englisch wie jede andere beobachtbare Zeichenkette dieses Binaers.
#[must_use]
pub const fn clock_release_availability_note(
    availability: ClockReleaseAvailability,
) -> &'static str {
    match availability {
        ClockReleaseAvailability::Offered => {
            "a clock release was offered for this state and this one was refused"
        }
        ClockReleaseAvailability::IndependentTimeUnavailable => {
            "no clock release is offered at all: without an independent time reference there is \
             nothing to measure one against"
        }
        ClockReleaseAvailability::NotBlocked => {
            "the clock is not blocked, so a clock release has no subject here"
        }
    }
}

/// Schreibt die Quittung einer verbrauchten Uhrfreigabe auf stdout.
///
/// # Errors
///
/// [`OperatorRuntimeError::Io`], wenn stdout nicht schreibbar ist.
pub fn print_clock_release_applied(format: Format) -> Result<(), OperatorRuntimeError> {
    let body = match format {
        Format::Json => "{\"clock_release\":\"applied\"}".to_owned(),
        Format::Text => CLOCK_RELEASE_APPLIED_V1.to_owned(),
    };
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(body.as_bytes())
        .and_then(|()| stdout.write_all(b"\n"))
        .and_then(|()| stdout.flush())
        .map_err(|_| OperatorRuntimeError::Io)
}

/// Druckt den Bedienhinweis zu einer Verfuegbarkeit auf stderr.
///
/// stderr und nicht stdout: er erlaeutert einen FEHLSCHLAG. Ein Aufrufer, der
/// die Quittung in eine Datei umlenkt, darf darin keinen Hinweistext finden.
pub fn print_clock_release_availability(availability: ClockReleaseAvailability) {
    eprintln!(
        "einsatzarchiv: {}",
        clock_release_availability_note(availability)
    );
}

/// Nur der stabile Fehlercode der Registrierungsablaeufe.
///
/// [`RegistryWorkflowError`] zeigt ausschliesslich ihn an — weder Objekthash
/// noch Bytes koennen von dort hierher gelangen.
pub fn print_registry_workflow_error(error: &RegistryWorkflowError) {
    eprintln!("einsatzarchiv: {error}");
}

/// Nur der stabile Fehlercode der Uhrfreigabe.
///
/// [`ClockReleaseWorkflowError`] formatiert ausdruecklich AUSSCHLIESSLICH
/// seinen Code — auch sein `Debug` —, damit der Freigabekontext und mit ihm die
/// Nonce in keine Protokollzeile geraet.
pub fn print_clock_release_error(error: &ClockReleaseWorkflowError) {
    eprintln!("einsatzarchiv: {error}");
}

/// Schreibt `bytes` als Kleinbuchstaben-Hex in eine Zeichenkette.
///
/// Dieselbe Regel wie [`write_hex`] und aus demselben Grund von Hand: `hex`
/// ist eine DEV-Dependency dieses Pakets. Die Zeilenbauer unten liefern
/// `String`s, damit ein Zeuge sie ohne Prozessstart vergleichen kann.
fn hex_string(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // `write!` in einen `String` kann nicht scheitern.
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// Der vorbereitete Writer-Uebergang, abgelesen und nicht behauptet.
///
/// # Warum dieser Typ hier steht und nicht `PreparedWriterTransition` gedruckt wird
///
/// Dieselbe Ueberlegung wie bei [`RevocationPlanView`]:
/// `ea_admin::writer_transition::PreparedWriterTransition` hat keinen
/// oeffentlichen Konstruktor — er entsteht ausschliesslich in `prepare` aus
/// einem gewaehlten Kopf. Ein Drucker, der ihn naehme, waere ausserhalb von
/// `ea-admin` nicht messbar. `crate::commands::writer_transition` liest die
/// Angaben an GENAU EINER Stelle von der Vorbereitung und vom Kopf ab und
/// legt sie hier hinein.
///
/// Organisation und Kette stammen aus dem KOPF (ueber die Felder der
/// Vorbereitung, die `prepare` von dort uebernimmt), Registrierungsversion
/// und Kopfhash ebenfalls: sie sagen dem Betreiber, GEGEN WELCHEN Stand der
/// Antrag geprueft wurde.
///
/// Kein `Debug`: die Hashtypen von `ea-types` fuehren keines, und eine hier
/// erfundene Anzeige waere eine zweite Hexform.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct WriterTransitionPrepareView {
    /// Die Organisation der Wurzelurkunde des gewaehlten Kopfes.
    pub organization_id: OrganizationId,
    /// Die Kette des gewaehlten Kopfes.
    pub chain_id: ChainId,
    /// Der laufende Writer, der abgibt.
    pub old_writer_certificate_hash: CertificateHash,
    /// Der freigegebene Writer, der uebernimmt.
    pub new_writer_certificate_hash: CertificateHash,
    /// Die Sequenz des abgeglichenen Kettenkopfes aus dem Antrag.
    pub trusted_head_chain_sequence: ChainSequence,
    /// Der Eintragshash des abgeglichenen Kettenkopfes aus dem Antrag.
    pub trusted_head_entry_hash: EntryHash,
    /// Die erste Sequenz des neuen Writers — `trusted_head + 1`.
    pub effective_from_sequence: ChainSequence,
    /// Der Begruendungscode, unveraendert durchgereicht.
    pub reason_code: u64,
    /// Die Registrierungsversion des gewaehlten Kopfes.
    pub registry_version: RegistryVersion,
    /// Der Objekthash des gewaehlten Kopfes.
    pub registry_head_hash: ObjectHash,
    /// Der Hash der erteilten Administrationsautorisierung aus dem Antrag —
    /// `None`, wenn der Antrag keinen nennt und der Platzhalter kodiert hat.
    pub admin_authorization_object_hash: Option<ObjectHash>,
}

/// Wo die Administrationsautorisierung gebunden wird, wenn der Antrag KEINEN
/// Hash nennt.
///
/// # Warum dieser Satz gedruckt wird
///
/// Ohne Hash ruft `prepare` den Dienst mit dem Platzhalter
/// `ObjectHash::from(Hash32::ZERO)` — genau wie
/// `ea_admin::policy::plan_initial_policy` die Policy-Form prueft, bevor eine
/// Autorisierung erteilt ist. Der echte Hash tritt beim Signieren an diese
/// Stelle: die Zeremonie fuehrt ihren Beweiszustand ueber die Nutzlast, die
/// SIE mit dem Hash der erteilten Autorisierung bildet
/// (`ea_trust::VerifiedAdminAuthorizationIntent`), und diesen Zustand hat
/// ein CLI-Prozess nicht — die Zeremonie ist Host-Arbeit, wie in Task 4. Ein
/// Betreiber, der die gezeigten Felder mit den signierten vergleicht, soll
/// wissen, dass der Autorisierungshash der EINE Unterschied ist.
///
/// Englisch wie jede andere beobachtbare Zeichenkette dieses Binaers.
pub const WRITER_TRANSITION_PLACEHOLDER_NOTE_V1: &str = "the admin authorization is bound at \
     the root ceremony and not by this run: the fields above were checked against the selected \
     head with a placeholder authorization hash, and the ceremony signs them with the real one; \
     activate needs the request file to name admin_authorization_object_hash";

/// Wo die Administrationsautorisierung gebunden wurde, wenn der Antrag den
/// Hash NENNT.
///
/// Ein ZWEITER Text und keine Variante des ersten mit Platzhalter: die
/// beiden Lagen sind verschieden — im einen Fall ist die gezeigte Nutzlast
/// die der Zeremonie bis auf den Hash, im anderen ist sie GENAU die, die die
/// Zeremonie signiert, und `activate` kann die veroeffentlichten Bytes
/// dagegen halten. Ein Betreiber soll die Lage an der Zeile erkennen.
///
/// Englisch wie jede andere beobachtbare Zeichenkette dieses Binaers.
pub const WRITER_TRANSITION_BOUND_NOTE_V1: &str = "the admin authorization named by the request \
     file was bound into the prepared payload: it is the payload the root ceremony signs, and \
     activate holds the published object against exactly this payload";

/// Die Zeile, die zur Lage des Antrags gehoert.
#[must_use]
pub const fn writer_transition_authorization_note(bound: bool) -> &'static str {
    if bound {
        WRITER_TRANSITION_BOUND_NOTE_V1
    } else {
        WRITER_TRANSITION_PLACEHOLDER_NOTE_V1
    }
}

/// Die Textform der Vorbereitung als GESCHLOSSENE Zeilenfolge.
///
/// Dieselbe Form wie [`revocation_plan_lines`]: stabile Schluessel-Wert-Paare,
/// gepunktete Schluessel fuer den zusammengehoerigen Kettenkopf, Bytefolgen
/// als Kleinbuchstaben-Hex. Keine Uhrzeit, kein Hostpfad.
#[must_use]
pub fn writer_transition_prepare_lines(view: &WriterTransitionPrepareView) -> Vec<String> {
    vec![
        format!(
            "organization_id={}",
            hex_string(view.organization_id.as_bytes())
        ),
        format!("chain_id={}", hex_string(view.chain_id.as_bytes())),
        format!(
            "old_writer_certificate_hash={}",
            hex_string(view.old_writer_certificate_hash.as_bytes())
        ),
        format!(
            "new_writer_certificate_hash={}",
            hex_string(view.new_writer_certificate_hash.as_bytes())
        ),
        format!(
            "trusted_head.chain_sequence={}",
            view.trusted_head_chain_sequence.get()
        ),
        format!(
            "trusted_head.entry_hash={}",
            hex_string(view.trusted_head_entry_hash.as_bytes())
        ),
        format!(
            "effective_from_sequence={}",
            view.effective_from_sequence.get()
        ),
        format!("reason_code={}", view.reason_code),
        format!("registry_version={}", view.registry_version.get()),
        format!(
            "registry_head_hash={}",
            hex_string(view.registry_head_hash.as_bytes())
        ),
        format!(
            "admin_authorization_object_hash={}",
            view.admin_authorization_object_hash
                .map_or_else(|| "none".to_owned(), |hash| hex_string(hash.as_bytes()))
        ),
        writer_transition_authorization_note(view.admin_authorization_object_hash.is_some())
            .to_owned(),
    ]
}

/// Dieselben Angaben als EINE JSON-Zeile.
///
/// Von Hand gebaut wie [`revocation_plan_json`]: Zahlen, Hex und feste
/// ASCII-Saetze dieses Moduls, nichts zu maskieren. Ausdruecklich KEIN neues
/// Schema — `schemas/` ist geschlossen, und diese Zeile ist eine Anzeige.
#[must_use]
pub fn writer_transition_prepare_json(view: &WriterTransitionPrepareView) -> String {
    format!(
        "{{\"organization_id\":\"{}\",\"chain_id\":\"{}\",\
         \"old_writer_certificate_hash\":\"{}\",\"new_writer_certificate_hash\":\"{}\",\
         \"trusted_head\":{{\"chain_sequence\":{},\"entry_hash\":\"{}\"}},\
         \"effective_from_sequence\":{},\"reason_code\":{},\"registry_version\":{},\
         \"registry_head_hash\":\"{}\",\"admin_authorization_object_hash\":{},\
         \"authorization_note\":\"{}\"}}",
        hex_string(view.organization_id.as_bytes()),
        hex_string(view.chain_id.as_bytes()),
        hex_string(view.old_writer_certificate_hash.as_bytes()),
        hex_string(view.new_writer_certificate_hash.as_bytes()),
        view.trusted_head_chain_sequence.get(),
        hex_string(view.trusted_head_entry_hash.as_bytes()),
        view.effective_from_sequence.get(),
        view.reason_code,
        view.registry_version.get(),
        hex_string(view.registry_head_hash.as_bytes()),
        view.admin_authorization_object_hash.map_or_else(
            || "null".to_owned(),
            |hash| format!("\"{}\"", hex_string(hash.as_bytes()))
        ),
        writer_transition_authorization_note(view.admin_authorization_object_hash.is_some()),
    )
}

/// Die Ablehnung eines Antrags ohne Autorisierungshash bei `activate`, Wort
/// fuer Wort.
///
/// Dieselbe Bauart wie [`MISSING_REVOCATION_TARGET_REFUSAL_V1`] und aus
/// demselben Grund Exitcode 2 und nicht ein `EA-TRANSITION-REQUEST-`-Code:
/// die Datei IST in Form — `prepare` nimmt sie —, ihr fehlt ein Feld, das
/// GENAU DIESES Kommando braucht. Ohne den Hash bildete `activate` die
/// Nutzlast mit dem Platzhalter, und die veroeffentlichten Bytes hielten
/// niemals dagegen; ein Lauf, der das erst am Bestand meldete, haette ein
/// Archiv geoeffnet, um einen Aufruffehler zu finden.
///
/// Englisch wie jede andere beobachtbare Zeichenkette dieses Binaers.
const MISSING_AUTHORIZATION_HASH_REFUSAL_V1: &str = "writer-transition activate holds the \
     published object against the payload the root ceremony signed, and that payload names the \
     admin authorization: the request file must carry admin_authorization_object_hash";

/// Druckt die Ablehnung eines Antrags ohne Autorisierungshash auf stderr.
pub fn print_missing_authorization_hash_refusal() {
    eprintln!("einsatzarchiv: {MISSING_AUTHORIZATION_HASH_REFUSAL_V1}");
}

/// Schreibt die Vorbereitung auf stdout.
///
/// # Errors
///
/// [`OperatorRuntimeError::Io`], wenn stdout nicht schreibbar ist.
pub fn print_writer_transition_prepare_report(
    view: &WriterTransitionPrepareView,
    format: Format,
) -> Result<(), OperatorRuntimeError> {
    let body = match format {
        Format::Json => writer_transition_prepare_json(view),
        Format::Text => writer_transition_prepare_lines(view).join("\n"),
    };
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(body.as_bytes())
        .and_then(|()| stdout.write_all(b"\n"))
        .and_then(|()| stdout.flush())
        .map_err(|_| OperatorRuntimeError::Io)
}

/// Die Registrierungsaenderung eines Writer-Uebergangs, als Zahl.
///
/// Fest und nicht abgelesen: `ActivatedWriterTransition` entsteht
/// ausschliesslich in `WriterTransitionService::activate`, und das plant
/// ausschliesslich `RegistryActionV1::WriterTransition` — Aktion 3, Aenderung
/// 3 (`crates/ea-admin/src/registry.rs`). Dieses Paket fuehrt keine Kante zu
/// `ea-format` und koennte die Aenderung des Ereignisses ohnehin nicht
/// benennen; eine Zahl, die aus der Bauart folgt, ist ehrlicher als eine, die
/// hier nachgerechnet wuerde.
pub const WRITER_TRANSITION_REGISTRY_CHANGE_V1: u8 = 3;

/// Das geplante Aenderung-3-Ereignis, abgelesen und nicht behauptet.
///
/// # Warum hier Zeitfelder stehen, obwohl dieses Modul keine Uhrzeit druckt
///
/// Die Regel dieses Moduls verbietet LAUFZEITANGABEN — wann der Lauf war,
/// auf welchem Host. `issued_at`, `not_before` und `not_after` sind hier
/// etwas anderes: sie sind FELDER des geplanten Ereignisses, und das
/// Ereignis ist der Gegenstand der Ausgabe. Die Wurzel signiert genau diese
/// Felder; ein Bericht, der sie verschwiege, zeigte ein Ereignis, das
/// niemand nachbauen und mit dem signierten vergleichen koennte. Beim
/// Widerrufsplan ist der Gegenstand die REICHWEITE, nicht das Ereignis —
/// deshalb fehlen sie dort. Dass `issued_at` von der Uhr des Laufs stammt
/// (`OperatorBindingService::registry_event` setzt es auf `now`), ist die
/// Folge davon, dass das Ereignis sie traegt, und kein Schleichweg: ein
/// Zeuge vergleicht diese Zeilen ohne Prozessstart ueber die Sicht.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct WriterTransitionActivateView {
    /// Die Registrierungsversion des geplanten Ereignisses — `+1` auf den Kopf.
    pub registry_version: RegistryVersion,
    /// Der Hash des Vorgaengerkopfes, an den das Ereignis bindet.
    pub previous_registry_hash: Option<Hash32>,
    /// Ab dieser Sequenz wirkt der Uebergang — die des Antrags.
    pub effective_from_sequence: ChainSequence,
    /// Bis zu dieser Sequenz reicht das Lease des Ereignisses.
    pub valid_through_sequence: ChainSequence,
    pub issued_at: UnixMillis,
    pub not_before: UnixMillis,
    pub not_after: UnixMillis,
    /// Der Objekthash der veroeffentlichten Bytes, den die Aenderung nennt.
    pub transition_object_hash: ObjectHash,
}

/// Was `activate` NICHT getan hat, Wort fuer Wort.
///
/// Englisch wie jede andere beobachtbare Zeichenkette dieses Binaers.
pub const WRITER_TRANSITION_ACTIVATE_NOTE_V1: &str = "this is the planned change 3 event and not \
     a published one: the root signs it, the successor head is selected afterwards, and the new \
     writer's first entry is the keyTransition that names the transition object hash";

/// Die Textform der Aktivierung als GESCHLOSSENE Zeilenfolge.
#[must_use]
pub fn writer_transition_activate_lines(view: &WriterTransitionActivateView) -> Vec<String> {
    vec![
        format!("registry_version={}", view.registry_version.get()),
        format!(
            "previous_registry_hash={}",
            view.previous_registry_hash
                .map_or_else(|| "none".to_owned(), |hash| hex_string(hash.as_bytes()))
        ),
        format!(
            "effective_from_sequence={}",
            view.effective_from_sequence.get()
        ),
        format!(
            "valid_through_sequence={}",
            view.valid_through_sequence.get()
        ),
        format!("issued_at={}", view.issued_at.get()),
        format!("not_before={}", view.not_before.get()),
        format!("not_after={}", view.not_after.get()),
        format!("registry_change={WRITER_TRANSITION_REGISTRY_CHANGE_V1}"),
        format!(
            "transition_object_hash={}",
            hex_string(view.transition_object_hash.as_bytes())
        ),
        WRITER_TRANSITION_ACTIVATE_NOTE_V1.to_owned(),
    ]
}

/// Dieselben Angaben als EINE JSON-Zeile; ein fehlender Vorgaengerhash ist
/// `null`.
#[must_use]
pub fn writer_transition_activate_json(view: &WriterTransitionActivateView) -> String {
    format!(
        "{{\"registry_version\":{},\"previous_registry_hash\":{},\
         \"effective_from_sequence\":{},\"valid_through_sequence\":{},\
         \"issued_at\":{},\"not_before\":{},\"not_after\":{},\
         \"registry_change\":{WRITER_TRANSITION_REGISTRY_CHANGE_V1},\
         \"transition_object_hash\":\"{}\",\
         \"activation_note\":\"{WRITER_TRANSITION_ACTIVATE_NOTE_V1}\"}}",
        view.registry_version.get(),
        view.previous_registry_hash.map_or_else(
            || "null".to_owned(),
            |hash| format!("\"{}\"", hex_string(hash.as_bytes()))
        ),
        view.effective_from_sequence.get(),
        view.valid_through_sequence.get(),
        view.issued_at.get(),
        view.not_before.get(),
        view.not_after.get(),
        hex_string(view.transition_object_hash.as_bytes()),
    )
}

/// Schreibt die Aktivierung auf stdout.
///
/// # Errors
///
/// [`OperatorRuntimeError::Io`], wenn stdout nicht schreibbar ist.
pub fn print_writer_transition_activate_report(
    view: &WriterTransitionActivateView,
    format: Format,
) -> Result<(), OperatorRuntimeError> {
    let body = match format {
        Format::Json => writer_transition_activate_json(view),
        Format::Text => writer_transition_activate_lines(view).join("\n"),
    };
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(body.as_bytes())
        .and_then(|()| stdout.write_all(b"\n"))
        .and_then(|()| stdout.flush())
        .map_err(|_| OperatorRuntimeError::Io)
}

/// Nur der stabile Fehlercode des Writer-Uebergangs.
///
/// [`WriterTransitionError`] zeigt ausschliesslich ihn an — auch sein
/// `Debug`; weder Objekthash noch Bytes koennen von dort hierher gelangen.
pub fn print_writer_transition_error(error: &WriterTransitionError) {
    eprintln!("einsatzarchiv: {error}");
}

/// Nur der stabile Fehlercode der Antragsdatei.
///
/// Der Inhalt der Datei kommt NIE hierher: [`WriterTransitionRequestError`]
/// traegt ihn nicht, und der vom Aufrufer eingegebene Pfad steht bereits in
/// seiner Aufrufzeile.
pub fn print_writer_transition_request_error(error: &WriterTransitionRequestError) {
    eprintln!("einsatzarchiv: {error}");
}
