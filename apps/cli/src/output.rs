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

use std::io::{self, Write};

use ea_admin::{
    AdminError, BootstrapStep, ProductionState,
    clock_release::{ClockReleaseAvailability, ClockReleaseWorkflowError},
    operator_runtime::{OperatorGoLiveReport, OperatorRuntimeError},
    registry::RegistryWorkflowError,
    revocation::RevocationTargetClass,
};
use ea_recovery::RecoveryError;
use ea_types::{ChainSequence, RegistryVersion};
use ea_verify::VerificationReportV1;

use crate::args::{Format, UsageError};

/// Die geschlossene Grammatik, Zeile fuer Zeile.
///
/// Die verfügbaren Aufrufformen. Der Text ist Teil
/// des beobachtbaren Verhaltens und wird als solcher gemessen.
///
/// # Warum die sechste Zeile `<new-file>` sagt
///
/// Bei den fuenf ersten ist der Anker eine gepruefte EINGABE. Bei
/// `organization init` ist er das, was die Zeremonie am Ende bildet — der Pfad
/// benennt also einen Platz, der noch frei sein muss. Die Begruendung steht in
/// `crate::commands::organization`; hier steht sie in einem Wort, damit ein
/// Aufrufer sie schon in der Grammatik sieht.
const GRAMMAR_V1: [&str; 9] = [
    "einsatzarchiv --trust-anchor <file> verify  <archive-path>",
    "einsatzarchiv --trust-anchor <file> list    <archive-path>",
    "einsatzarchiv --trust-anchor <file> decrypt <archive-path> --key <key-source> --output <target>",
    "einsatzarchiv --trust-anchor <file> report  <archive-path> --output <report-file>",
    "einsatzarchiv --trust-anchor <file> export  <archive-or-server> --output <new-target>",
    "einsatzarchiv --trust-anchor <new-file> organization init",
    "einsatzarchiv --trust-anchor <file> operator provision|verify-session|revoke --operator-config <file>",
    "einsatzarchiv --trust-anchor <file> registry revocation-plan --operator-config <file> --effective-from <sequence> --valid-through <sequence> --not-after <unix-millis>",
    "einsatzarchiv --trust-anchor <file> clock-release apply --operator-config <file> --release <file>",
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
    println!("{ORGANIZATION_SCOPE_NOTE_V1}");
    println!(
        "operator config contains public archive/database paths, certificate/binding hashes, role and purpose; authority mode requires authority=true and target_certificate_hash; offline exchange uses ceremony_exchange_directory"
    );
    println!("{REGISTRY_SCOPE_NOTE_V1}");
    println!("{CLOCK_RELEASE_SCOPE_NOTE_V1}");
}

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
