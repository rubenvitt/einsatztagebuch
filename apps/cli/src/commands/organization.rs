//! Kommando `organization init`.
//!
//! Beginnt die Ersteinrichtung einer Organisation oder setzt die persistierte
//! fort und berichtet, wo sie steht.
//!
//! # Woher dieses Kommando kommt — und woher NICHT
//!
//! Nicht aus der Spezifikation. Deren CLI-Grammatik
//! (`docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md:1787-1793`)
//! fuehrt `verify`, `list`, `decrypt`, `grant`, `report`, `export` und
//! `recovery-test` und kennt `organization init` nicht. Das Kommando stammt aus
//! dem Umsetzungsplan
//! (`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-5-administration-recovery.md`,
//! Task 2, Step 3). Der Zwoelfschrittablauf selbst ist dagegen normativ
//! (`§12.1`, `:1336-1349`); nur seine CLI-Oberflaeche ist es nicht.
//!
//! # Was `--trust-anchor` HIER bedeutet
//!
//! Bei den fuenf Wiederherstellungskommandos ist der Anker eine gepruefte
//! EINGABE: `ea_recovery::load_trust_anchor` liest ihn, und `:1782` laesst dazu
//! keinen Spielraum — kein Trust-on-first-use, kein Anker aus dem geprueften
//! Bestand. Waehrend der Ersteinrichtung gibt es ihn noch gar nicht: er ist
//! genau das, was Schritt 11 am Ende BILDET.
//!
//! Der Schalter bleibt trotzdem Pflicht, damit die Grammatik ueber alle sechs
//! Kommandos dieselbe ist, und er benennt hier den PLATZ, den der Anker dieser
//! Zeremonie einnehmen wird. Daraus folgt unmittelbar die Fail-Closed-Regel
//! dieses Pfades: **eine belegte Datei an diesem Platz beendet den Lauf mit
//! Exitcode 2, bevor irgendetwas entsteht.** Die Datei dort kann eine LEBENDE
//! Vertrauensquelle sein; sie ersatzweise zu ueberschreiben waere schlimmer als
//! ein erfundener Anker — es naehme einer bestehenden Organisation ihre Wurzel.
//! Zwei Zeremonien nebeneinander waeren ausserdem zwei Wahrheiten ueber
//! dieselbe Organisation, was `crate::args` schon der Grammatik ansieht.
//!
//! # Die Grenze dieser Scheibe, und warum sie keine Ersatzhandlung kennt
//!
//! Der Koordinator nimmt die AEUSSEREN Schluessel — Root, Recovery-KEM, HGA,
//! Approver — als wirtseitig gestellte, opake Griffe entgegen.
//! `ea_key_provider::SecretPurpose` traegt vier LOKALE Writer-Zwecke und
//! ausdruecklich keinen Wurzelzweck
//! (`crates/ea-key-provider/src/contract.rs:32-51`); ein CLI-Prozess kann diese
//! Schluessel also weder erzeugen noch adressieren, und die Ports fuer
//! Offline-Schluesselquellen sind Plan-Task 7 und nicht dieser.
//!
//! Dieses Kommando fuehrt deshalb GENAU DREI Dinge aus: es beginnt eine
//! Zeremonie mit zufaelligen Organisations- und Ketten-IDs (`:1336`) oder
//! setzt die persistierte fort, es berichtet Schritt, Kennungen und
//! Produktivzustand, und es beendet den Prozess mit dem passenden Code. Es
//! taeuscht keinen Schritt vor, den es nicht ausfuehren kann; die Grammatik
//! sagt das mit (`crate::output`).
//!
//! # Wo der Zeremoniezustand liegt
//!
//! In `<trust-anchor>.bootstrap-state`, also NEBEN dem kuenftigen Anker und
//! unter dessen vollem Namen als Praefix. Zwei Gruende: der Aufrufer hat mit
//! dem Ankerpfad bereits den Ort benannt, an dem diese Organisation entsteht —
//! ein zweiter Schalter fuer denselben Ort waere eine zweite Wahrheit —, und
//! `Path::with_extension` kaeme dafuer nicht in Frage, weil es `anchor.etb` und
//! `anchor.bin` auf dieselbe Zustandsdatei abbildete. Angehaengt wird deshalb
//! an die ganze Zeichenkette. Was in dieser Datei stehen darf, entscheidet
//! nicht dieses Paket, sondern `ea_admin::BootstrapStateV1::persisted_image`:
//! oeffentlicher Zeremoniezustand und opake Griffe, kein Geheimnis.

use std::path::PathBuf;

use ea_admin::{
    AdminError, BootstrapCoordinator, FileBootstrapStore, SystemRandomSource, machine_fingerprint,
};
use ea_recovery::{ExitCode, RecoveryError, exit_code_for_error};

use crate::{
    args::{Format, Invocation},
    output,
};

/// Das Suffix der Zustandsdatei neben dem Ankerpfad.
const STATE_FILE_SUFFIX: &str = ".bootstrap-state";

/// Der stabile Code des Befundes „die lokale Zufallsquelle liefert nicht".
///
/// Er wird als CODE verglichen und nicht als Variantenmuster
/// `AdminError::Crypto(ea_crypto::CryptoError::LocalRng)`: das Muster
/// verlangte eine `ea-crypto`-Kante im Auslieferungsgraphen dieses Werkzeugs,
/// und der Code IST das stabile Aussenverhalten dieses Befundes
/// (`crates/ea-crypto/src/error.rs`, `crates/ea-admin/src/error.rs`) — genau
/// das, wonach die Zuordnung hier fragt.
const LOCAL_RANDOM_SOURCE_CODE: &str = "EA-LOCAL-CRYPTO-RNG";

/// Fuehrt `organization init` aus.
///
/// Nimmt ausdruecklich KEINE Uhr entgegen. Die uebrigen fuenf Kommandos
/// brauchen sie, weil ein Verifikationsurteil an ihr haengt; hier wird nichts
/// verifiziert und nichts datiert — der persistierte Zeremoniezustand traegt
/// keinen Zeitpunkt, und eine Ausgabe mit Uhrzeit verstiesse gegen die Regel
/// von `crate::output`.
pub fn run(invocation: &Invocation) -> ExitCode {
    // 1 — die Form der Ausgabe, VOR jeder Wirkung. Eine Zeremonie, die
    // begaenne und danach an der Ausgabeform scheiterte, hinterliesse einen
    // Zustand, den der Aufrufer nie zu sehen bekam.
    if invocation.format == Format::Json {
        output::print_organization_json_refusal();
        return ExitCode::Unsupported;
    }

    // 2 — der Platz des kuenftigen Ankers. Fail-closed: was sich nicht
    // pruefen laesst, gilt nicht als frei.
    match invocation.anchor.try_exists() {
        Ok(false) => {}
        Ok(true) => {
            output::print_anchor_path_occupied_refusal();
            return ExitCode::Usage;
        }
        Err(error) => {
            let error = RecoveryError::from(error);
            output::print_recovery_error(&error);
            return exit_code_for_error(&error);
        }
    }

    // 3 — die Zeremonie. Fortsetzen, wenn es etwas fortzusetzen gibt, sonst
    // beginnen; welcher der beiden Faelle eintrat, ist keine Frage dieses
    // Pfades, sondern des persistierten Zustands.
    let mut store = FileBootstrapStore::new(state_path(&invocation.anchor));
    let coordinator = match BootstrapCoordinator::resume_or_begin(
        &mut store,
        &mut SystemRandomSource,
        ceremony_machine(),
    ) {
        Ok(coordinator) => coordinator,
        Err(error) => {
            output::print_admin_error(&error);
            return exit_code_for_admin_error(error);
        }
    };

    // 4 — der Bericht. Ein gescheitertes SCHREIBEN ueberstimmt den Erfolg: wer
    // die Ausgabe nicht bekommen hat, darf nicht erfahren, dass alles in
    // Ordnung sei. Die Zeremonie steht trotzdem — sie ist persistiert.
    if let Err(error) = output::print_bootstrap_status_text(
        coordinator.step(),
        coordinator.organization_id().as_bytes(),
        coordinator.chain_id().as_bytes(),
        coordinator.production_state(),
    ) {
        output::print_recovery_error(&error);
        return exit_code_for_error(&error);
    }

    ExitCode::Success
}

/// Der Rechner, auf dem DIESE Zeremonie laeuft — soweit dieses Werkzeug ihn
/// benennen kann.
///
/// Schritt 12 verlangt „einen frischen Rechner" (`design.md`:1347), und
/// „frisch" ist ein Vergleich gegen den Rechner der Zeremonie. Wer diesen Wert
/// erst BEIM Vergleich nennte, waere die Partei, die den Produktivzustand
/// will; er wird deshalb in Schritt 1 festgehalten.
///
/// Geerntet wird ausschliesslich, was das Betriebssystem ohnehin als seine
/// Identitaet fuehrt und was `ea-operator` fuer die Kontobindung derselben
/// Maschine liest (`crates/ea-operator/src/linux.rs:4-40`). Gehasht wird das
/// in `ea-admin` — dieses Paket traegt bewusst keine `ea-crypto`-Kante, siehe
/// [`LOCAL_RANDOM_SOURCE_CODE`].
///
/// `None`, wo sich der Rechner nicht benennen laesst. Das ist kein
/// Fehlschlag dieses Kommandos: Schritt 1 gelingt, und Schritt 12 ist danach
/// fail-closed unerreichbar — eine Zeremonie ohne benannten Rechner kann
/// „nicht derselbe Rechner" nicht messen. Ein Abbruch hier waere die
/// schlechtere Wahl: er verhinderte auch die elf Schritte, die es nicht
/// betrifft.
fn ceremony_machine() -> Option<ea_types::Hash32> {
    for source in MACHINE_IDENTITY_SOURCES {
        if let Ok(identity) = std::fs::read(source) {
            let trimmed = identity.trim_ascii();
            if !trimmed.is_empty() {
                return Some(machine_fingerprint(trimmed));
            }
        }
    }
    None
}

/// Die Orte, an denen ein Wirt seine Maschinenidentitaet fuehrt.
///
/// In der Reihenfolge, in der `systemd` sie selbst liest: `/etc/machine-id`
/// zuerst, der D-Bus-Ort als Rueckfall auf aelteren Installationen. Auf einem
/// Wirt ohne beide bleibt es bei `None`.
const MACHINE_IDENTITY_SOURCES: [&str; 2] = ["/etc/machine-id", "/var/lib/dbus/machine-id"];

/// Der Pfad der Zustandsdatei neben `anchor`.
///
/// An die GANZE Zeichenkette angehaengt und nicht ueber
/// [`std::path::Path::with_extension`]: das ersetzte eine vorhandene Endung und
/// liesse `anchor.etb` und `anchor.bin` auf dieselbe Datei zeigen. Der Pfad
/// geht als [`std::ffi::OsString`] durch, weil ein Pfad auf darwin und Linux
/// eine Bytefolge ist — dieselbe Zusage, die `crate::args` fuer alle
/// Pfadwerte gibt.
fn state_path(anchor: &std::path::Path) -> PathBuf {
    let mut path = anchor.to_path_buf().into_os_string();
    path.push(STATE_FILE_SUFFIX);
    PathBuf::from(path)
}

/// Leitet den Exitcode aus einem Befund der Zeremonie ab.
///
/// # Warum diese Tabelle HIER steht und nicht in einer Bibliothek
///
/// `ea_recovery::exit_code_for_error` ist das Vorbild und bleibt die Tabelle
/// fuer `ea_recovery::RecoveryError`. Eine zweite fuer [`AdminError`] koennte
/// dort nur wohnen, wenn `ea-recovery` an `ea-admin` haenge — das zoege die
/// Zeremonie in den Graphen eines WIEDERHERSTELLUNGSWERKZEUGS, das Jahre
/// spaeter noch bauen soll. Umgekehrt kennt `ea-admin` den Exitcodebegriff
/// nicht und soll ihn nicht kennen: die normative Tabelle
/// (`design.md`:1800-1815) ist eine Zusage des PROZESSES. Die Zuordnung ist
/// damit genau das, was `apps/cli/src/main.rs`:3-14 diesem Paket zuschreibt.
///
/// # Die Zuordnung, Zeile fuer Zeile
///
/// `:1815` gilt durchgehend: bei mehreren Fehlern der kleinste spezifische
/// Code.
fn exit_code_for_admin_error(error: AdminError) -> ExitCode {
    // „I/O-, Speicher- oder Transportfehler": die Zufallsquelle des Wirts hat
    // nicht geliefert. Das ist kein Format-, Hash- oder Signaturbefund, und
    // deshalb steht dieser eine Fall vor der Tabelle — siehe
    // [`LOCAL_RANDOM_SOURCE_CODE`].
    if error.code() == LOCAL_RANDOM_SOURCE_CODE {
        return ExitCode::Io;
    }

    match error {
        // „I/O-, Speicher- oder Transportfehler". Die Ablage des
        // Zeremoniezustands und die Recovery-Medien sind Speicher; ein Medium,
        // das nicht antwortet oder andere Bytes zurueckliest, ist derselbe
        // Befund eine Ebene tiefer.
        AdminError::BootstrapStoreUnavailable
        | AdminError::MediaUnavailable
        | AdminError::MediaReadbackMismatch => ExitCode::Io,
        // „Format-, Hash- oder Signaturfehler". Der persistierte Zustand ist
        // lesbar und PASST NICHT — dieselbe Trennung, die `ea-recovery`
        // zwischen `Io` und `TrustAnchor` zieht.
        AdminError::BootstrapStateShape | AdminError::Format(_) => ExitCode::Integrity,
        // „Trust-, Registry- oder Autorisierungsfehler". `:1782` ist fuer den
        // Anker unmissverstaendlich: „Jede Abweichung endet mit Exitcode 12."
        // Ein finaler Anker, der eine ANDERE als die festgeschriebene Vorstufe
        // fortsetzt, ist genau diese Abweichung.
        AdminError::AnchorPreFieldChanged
        | AdminError::SecondChannelMismatch
        | AdminError::ReauthMismatch
        | AdminError::BindingMismatch
        | AdminError::BindingInactive
        | AdminError::HeadMismatch
        | AdminError::AuthorizationMismatch
        | AdminError::TargetMismatch
        | AdminError::RootCertificateMismatch
        | AdminError::RootSignatureMismatch
        // Ein Gegenstand, der zu einer anderen Organisation, Kette oder einem
        // anderen Anker gehoert, ist ein Vertrauensbefund und kein Tippfehler
        // im Aufruf: `:1782` laesst fuer einen abweichenden Anker keinen
        // Spielraum.
        | AdminError::BootstrapContextMismatch
        | AdminError::Trust(_) => ExitCode::Trust,
        // „Schluessel fehlt oder Entschluesselung fehlgeschlagen" — der Port
        // des Schluesselspeichers hat den Eintrag nicht hergegeben.
        AdminError::Key(_) => ExitCode::Key,
        // „Aufruf- oder Konfigurationsfehler": so, wie dieser Lauf aufgerufen
        // wurde, wird er nicht ausgefuehrt. Ein Schritt, der zurueckfaellt
        // oder seinen Vorgaenger ueberspringt, eine unbestaetigte Vorstufe und
        // eine unerreichte Mindestzahl sagen alle dasselbe — am Bestand liegt
        // es nicht, und der naechste Aufruf kann es richtig machen.
        AdminError::BootstrapStepRegression
        | AdminError::BootstrapStepOutOfOrder
        | AdminError::BootstrapPreAnchorUnconfirmed
        | AdminError::BootstrapQuorumMissing
        | AdminError::MediaQuorumMissing
        | AdminError::GenesisSequence
        | AdminError::GenesisContextMismatch => ExitCode::Usage,
        // „vollstaendig geprueft, aber fachlich unvollstaendig": der
        // Recovery-Test ist gelaufen und hat NICHT bestanden. `:1897` verbietet
        // ausdruecklich, dass ein Teilerfolg als Erfolg erscheint — 15 sagt
        // genau das und nicht mehr.
        AdminError::RecoveryTestFailed | AdminError::RecoveryTestSameMachine => {
            ExitCode::Incomplete
        }
        // Jeder verbleibende Kryptobefund ist Hash, Signatur oder Kodierung;
        // die eine Ausnahme steht oben vor der Tabelle.
        AdminError::Crypto(_) => ExitCode::Integrity,
        // Die Auditzeile blieb aus — die Zielbytes bleiben zurueck.
        AdminError::AuditFailed => ExitCode::Io,
        // KEIN stiller Befundcode fuer eine kuenftige Variante: `AdminError`
        // ist `#[non_exhaustive]` und wohnt in einer anderen Crate, ein
        // Auffangarm ist hier also Pflicht. Dieses Bauwerk kennt sie nicht, und
        // genau das sagt 21 — dieselbe Entscheidung wie in
        // `ea_recovery::exit_code_for_error` fuer `ArchiveError` und
        // `VerifyError`.
        _ => ExitCode::Unsupported,
    }
}
