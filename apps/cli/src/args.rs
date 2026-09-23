//! Die geschlossene Aufrufgrammatik, von Hand geparst.
//!
//! # Warum von Hand und nicht mit `clap`
//!
//! Die Grammatik ist mit zwoelf Kommandos, siebzehn wertnehmenden Schaltern
//! und einem Flag abgeschlossen und klein. Das Repo ist dependency-diszipliniert:
//! jede externe Kiste traegt eine begruendete Zeile in
//! `docs/adr/0001-toolchain-and-cryptography-dependencies.md`. Eine
//! Argumentbibliothek in den Graphen eines WIEDERHERSTELLUNGSWERKZEUGS zu
//! ziehen, das Jahre nach seiner Uebersetzung noch bauen und laufen soll, ist
//! der teurere Weg — nicht der billigere.
//!
//! # [`parse`] ist REIN
//!
//! Sie nimmt einen Iterator und ruft nirgends [`std::env::args_os`] selbst.
//! Nur so ist jeder Aufruffehler ohne Prozessstart messbar; der Prozessstart
//! misst danach den Exitcode und nicht mehr die Grammatik.
//!
//! # Zwei festgeschriebene Konventionen
//!
//! - **Werte stehen als EIGENES Argument hinter dem Schalter.** `--format=json`
//!   ist ein unbekannter Schalter und damit [`UsageError::UnknownSwitch`]. Eine
//!   Form, die beides stillschweigend annimmt, hat doppelt so viele Pfade und
//!   halb so viele Tests.
//! - **Ein Argument, dessen erstes Byte `-` ist, ist ein SCHALTER.** Auch als
//!   Wert eines Schalters: `--output --format` meldet den fehlenden Wert von
//!   `--output`, statt `--format` als Zielpfad zu verschlucken. Ein Zielpfad,
//!   der wirklich mit `-` beginnt, wird als `./-name` uebergeben.
//!
//! # Nicht-UTF-8
//!
//! SCHALTERNAMEN und Kommandonamen muessen UTF-8 sein — sie werden gegen feste
//! Zeichenketten verglichen, und was sich damit nicht vergleichen laesst, ist
//! keiner von ihnen. PFADWERTE gehen dagegen unbesehen als [`OsString`] in
//! [`PathBuf`]: auf darwin und Linux ist ein Pfad eine Bytefolge, und ein
//! Wiederherstellungswerkzeug, das einen Bestand wegen der Kodierung seines
//! Verzeichnisnamens nicht oeffnet, versagt genau dann, wenn es gebraucht wird.
//!
//! # Schluesselquellen werden HIER geparst, aber DORT definiert
//!
//! `--key`, `--recovery-key` und `--authority-key` tragen eine
//! `<key-source>`-Angabe. Ihre Grammatik — `<path>` | `file:<path>` |
//! `container:<path>;passphrase-file=<path>` |
//! `pkcs11:module=<path>;token=<label>;id=<hex>;pin-file=<path>` — wohnt in
//! `ea_recovery::KeySourceSpec::parse` und wird von hier nur AUFGERUFEN: ein
//! Parser, der sie ein zweites Mal fuehrte, koennte still von ihr abweichen.
//! Ein Grammatikfehler dort ist ein Aufruffehler hier
//! ([`UsageError::KeySource`]), Exitcode 2, und nennt den Schalter UND das
//! Feld. Ein blosser Pfad bleibt die Dateiform der Stufe 4, damit jeder
//! bisherige Aufruf unveraendert weiterlaeuft.

#[path = "args/recovery.rs"]
pub(crate) mod recovery;
pub use recovery::RecoveryRuntimeArguments;
use std::{
    ffi::OsString,
    fmt,
    path::{Path, PathBuf},
};

use ea_recovery::{KeySourceSpec, KeySourceSpecError};
use ea_types::{ChainSequence, RegistryVersion, UnixMillis};

/// Start/resume retains the existing ceremony without advancing offline steps.
pub const ORGANIZATION_INIT_SUBCOMMAND: &str = "init";
pub const ORGANIZATION_CERTIFY_ROOT_SUBCOMMAND: &str = "certify-root";
/// Zeremonie A des Reader-Key-Escrows (DRK-458) — bis zum Cutover gesperrt.
pub const ORGANIZATION_READER_KEY_ESCROW_PUBLISH_SUBCOMMAND: &str = "reader-key-escrow-publish";
/// Die minimale Root-Zeremonie der Bundle-Familie (U4): Freigabe und Widerruf
/// einer Fassung des Web-Bundles, neben `certify-root`.
pub const ORGANIZATION_WEB_BUNDLE_RELEASE_SUBCOMMAND: &str = "web-bundle-release";
pub const ORGANIZATION_WEB_BUNDLE_REVOKE_SUBCOMMAND: &str = "web-bundle-revoke";
pub const ORGANIZATION_SUBCOMMANDS: &str =
    "init|certify-root|reader-key-escrow-publish|web-bundle-release|web-bundle-revoke";
/// Die beiden Unterkommandos von `reader-key-escrow` (Zeremonie B).
pub const READER_KEY_ESCROW_OPEN_SUBCOMMAND: &str = "open";
pub const READER_KEY_ESCROW_PICKUP_SUBCOMMAND: &str = "pickup";
pub const READER_KEY_ESCROW_SUBCOMMANDS: &str = "open|pickup";
pub const INITIAL_REGISTRY_VERSION_SWITCH: &str = "--initial-registry-version";
/// Das EINZIGE Unterkommando von `registry`.
///
/// Es heisst `revocation-plan` und nicht `revoke`, weil es GENAU DAS tut, was
/// die Fassade leistet: `ea_admin::revocation::plan_revocation` BEREITET die
/// Aenderung 1 vor und gibt ihre Reichweite heraus. Veroeffentlicht wird sie
/// erst, wenn die Wurzel sie signiert hat — und die dafuer noetigen
/// Offline-Schluesselquellen kann ein CLI-Prozess so wenig herbeireden wie bei
/// `organization init`. Ein Kommando namens `revoke` verspraeche einen
/// Vollzug, den dieser Lauf nicht hat.
pub const REGISTRY_REVOCATION_PLAN_SUBCOMMAND: &str = "revocation-plan";
/// Das EINZIGE Unterkommando von `clock-release`.
///
/// Ausdruecklich NUR `apply`. Das Ausstellen einer Freigabe
/// (`ea_admin::clock_release::ClockReleaseService::issue`) ist von hier aus
/// nicht erreichbar: es verlangt einen `ea_trust::RegistryCandidate` in seiner
/// Signatur, und dieses Paket fuehrt keine Kante dorthin.
///
/// Die Verfuegbarkeit ist inzwischen sehr wohl erreichbar —
/// `ea_admin::operator_runtime::OperatorRuntime::clock_release_availability`
/// gibt sie heraus, ohne dass ein Fremdtyp die Paketgrenze ueberquert. Sie
/// bekommt trotzdem KEIN eigenes Unterkommando: sie ist der Bedienhinweis zu
/// einem gescheiterten `apply` und kein eigener Vollzug. Die Grammatik fuehrt
/// deshalb weder `issue` noch `availability`.
pub const CLOCK_RELEASE_APPLY_SUBCOMMAND: &str = "apply";
/// Die BEIDEN Unterkommandos von `writer-transition`.
///
/// `prepare` prueft den Antrag gegen den gewaehlten Kopf und zeigt die
/// Felder, die die Wurzelzeremonie unterschreiben wird; `activate` haelt die
/// veroeffentlichten Objektbytes gegen dieselbe Vorbereitung und plant das
/// Aenderung-3-Ereignis. Keines von beiden signiert oder veroeffentlicht —
/// dieselbe Grenze wie bei `registry revocation-plan`, und aus demselben
/// Grund: die Zeremonie braucht Offline-Schluesselquellen und den
/// Beweiszustand `ea_trust::VerifiedAdminAuthorizationIntent`, und beides hat
/// ein CLI-Prozess nicht. Die Begruendung steht in
/// `crate::commands::writer_transition`.
pub const WRITER_TRANSITION_PREPARE_SUBCOMMAND: &str = "prepare";
pub const WRITER_TRANSITION_ACTIVATE_SUBCOMMAND: &str = "activate";
/// Der Name, unter dem ein Schalter abgelehnt wird, den nur `activate`
/// nimmt: `prepare` kennt weder das Objekt noch das Fenster.
pub const WRITER_TRANSITION_PREPARE_COMMAND: &str = "writer-transition prepare";

/// `--trust-anchor <file>`, PFLICHT bei allen Kommandos.
///
/// # Bei `organization init` bedeutet er etwas ANDERES
///
/// Bei den sieben Wiederherstellungskommandos aus §16.1 ist der Anker eine
/// gepruefte EINGABE: `ea_recovery::load_trust_anchor` liest ihn, und `design.md`:1782
/// verbietet jede andere Herkunft. Waehrend der Ersteinrichtung gibt es ihn
/// noch gar nicht — er ist das, was die Zeremonie am Ende BILDET. Der Schalter
/// bleibt trotzdem Pflicht, damit die Grammatik ueber alle Kommandos
/// dieselbe ist, und benennt dort den PLATZ, den der Anker dieser Zeremonie
/// einnehmen wird. Die Folge steht in `crate::commands::organization`: eine
/// belegte Datei an diesem Platz ist ein Aufruffehler und kein Ziel.
pub const TRUST_ANCHOR_SWITCH: &str = "--trust-anchor";
/// `--format text|json`, Vorgabe `text`.
pub const FORMAT_SWITCH: &str = "--format";
/// `--output <target>`, bei `decrypt`, `grant`, `report`, `export` und `recovery-test`.
pub const OUTPUT_SWITCH: &str = "--output";
/// `--key <key-source>`, nur bei `decrypt`.
pub const KEY_SWITCH: &str = "--key";
/// `--recovery-key <source>`, nur bei `grant`.
///
/// Der private Recovery-KEM-Schluessel, mit dessen Abdruck verifiziert wird.
/// Ein EIGENER Schalter neben [`KEY_SWITCH`] und nicht derselbe unter anderem
/// Kommando, weil `grant` ZWEI Schluesselquellen traegt und `design.md` §16.1
/// beide beim Namen nennt: wer `--key` an `grant` haengt, hat sich vertan,
/// und die Grammatik sagt das.
pub const RECOVERY_KEY_SWITCH: &str = "--recovery-key";
/// `--authority-key <source>`, nur bei `grant`.
///
/// Der GETRENNTE Signierschluessel der historischen Grant-Autoritaet
/// (`design.md` §16.2). Getrennt heisst: eine andere Quelle als der
/// Recovery-Schluessel, und `ea_recovery::resolve_signing_key` liest einen
/// Container nur, wenn sein Kopf die Signierart traegt.
pub const AUTHORITY_KEY_SWITCH: &str = "--authority-key";
/// `--authorization <file>`, nur bei `grant`.
///
/// Die Datei traegt die von zwei `historicalGrantApprove`-Subjekten signierte
/// Autorisierung. Sie wird in dieser Stufe GELESEN und nicht geparst — der
/// Parser gehoert zum Dienst (`ea_recovery::grant`).
pub const AUTHORIZATION_SWITCH: &str = "--authorization";
/// `--recipient-cert <file>`, nur bei `grant`.
///
/// Das Zertifikat des Empfaengers, der den historischen Grant bekommen soll.
/// Wie die Autorisierung: gelesen, nicht geparst.
pub const RECIPIENT_CERT_SWITCH: &str = "--recipient-cert";
/// `--key-inventory <file>`, nur bei `recovery-test`.
///
/// Das Inventar `ea.key-inventory/v1`. Seine Rust-Bindung ist Stage-5 Task 9;
/// hier wird die Datei gelesen, und ihre Bytes gehen ungeparst an die
/// Fassade (`ea_recovery::recovery_test`).
pub const KEY_INVENTORY_SWITCH: &str = "--key-inventory";
/// Public operator configuration; required only by operator commands.
///
/// `registry` und `clock-release` verlangen dieselbe Datei und aus demselben
/// Grund: sie ist der einzige oeffentliche Weg zu Bestand, Datenbank und
/// Bindung. Bei `registry revocation-plan` benennt ihr Feld
/// `target_certificate_hash` zusaetzlich das Widerrufsziel — dazu die
/// Begruendung in `crate::commands::registry`.
pub const OPERATOR_CONFIG_SWITCH: &str = "--operator-config";
/// `--network-archive-profile <file>`, nur bei `operator register-network-archive`.
///
/// Die Datei trägt das Netzprofil in der bestehenden Wiederherstellungs-
/// JSON-Grammatik (`ea_admin::recovery_test_runtime::parse_recovery_archive_profile`,
/// camelCase, `kind: "controlledNetworkPath"`) und wird GELESEN und nicht
/// hier geparst — dieses Paket reicht die Bytes unverändert an die Fassade
/// durch, wie `--release` und `--transition-object` es auch tun.
///
/// NICHT `--archive-profile`: `recovery::SWITCHES` führt dieses Wort schon
/// für `recovery-test`s eigene Quellengrammatik
/// (`apps/cli/src/args/recovery.rs`), und der Parser erkennt jeden Schalter
/// GLOBAL, bevor er das Kommando kennt — derselbe Wortlaut für `operator`
/// liefe deshalb immer in die `recovery-test`-Ablehnung, nie in diesen
/// Zweig.
pub const NETWORK_ARCHIVE_PROFILE_SWITCH: &str = "--network-archive-profile";
/// `--effective-from <sequence>`, nur bei `registry`.
///
/// Ausdruecklich NICHT bei `writer-transition activate`: dort ist die
/// Wirksamkeitssequenz keine Entscheidung des Betreibers, sondern folgt aus
/// dem abgeglichenen Kettenkopf des Antrags (`chain_sequence + 1`), und
/// `ea_admin::writer_transition::WriterTransitionService::activate` weist
/// jedes Fenster ab, das woanders beginnt. Ein Schalter, dessen einziger
/// gueltiger Wert feststeht, waere eine Gelegenheit, ihn falsch zu setzen.
pub const EFFECTIVE_FROM_SWITCH: &str = "--effective-from";
/// `--valid-through <sequence>`, bei `registry` und `writer-transition activate`.
pub const VALID_THROUGH_SWITCH: &str = "--valid-through";
/// `--not-after <unix-millis>`, bei `registry` und `writer-transition activate`.
pub const NOT_AFTER_SWITCH: &str = "--not-after";
/// `--request <file>`, nur bei `writer-transition`.
///
/// Die Datei traegt den Antrag — zwei Zertifikatshashes, den abgeglichenen
/// Kettenkopf und den Begruendungscode — und wird von `ea-admin` gelesen
/// (`ea_admin::writer_transition::WriterTransitionRequest::load`). Ein
/// eigener Schalter und kein Feld der Bedienerdatei, weil der Antrag zu EINEM
/// Uebergang gehoert und die Bedienerdatei zu einem Bediener; die
/// Ueberladung von `target_certificate_hash` beim Widerruf wird hier nicht
/// wiederholt.
pub const REQUEST_SWITCH: &str = "--request";
/// `--transition-object <file>`, nur bei `writer-transition activate`.
///
/// Die Datei traegt die EXAKTEN Bytes des Transitionsobjekts, wie die
/// Wurzelzeremonie sie herausgegeben hat. Sie wird unveraendert an
/// `ea-admin` durchgereicht; dieses Paket dekodiert sie nicht.
pub const TRANSITION_OBJECT_SWITCH: &str = "--transition-object";
/// `--release <file>`, nur bei `clock-release`.
///
/// Die Datei traegt die EXAKTEN Bytes einer signierten
/// `local-audit-event-v1`-Zeile, wie
/// `ea_admin::clock_release::IssuedClockRelease::exact_bytes` sie herausgibt.
/// Sie wird unveraendert durchgereicht: dieses Paket dekodiert sie nicht, und
/// es zeigt nichts aus ihr an — sie bindet eine Zufalls-Nonce.
pub const RELEASE_SWITCH: &str = "--release";
/// `--include-runtime-metadata`, nur bei `report`.
pub const INCLUDE_RUNTIME_METADATA_SWITCH: &str = "--include-runtime-metadata";
/// `--escrow-inbox <dir>`, bei `reader-key-escrow` und
/// `organization reader-key-escrow-publish`.
///
/// Die EIGENE Escrow-Inbox (Ruling U3): Paket- und Transportdateien, deren
/// Name allein der Hash ihrer Bytes ist. Nicht die Registrierungs-Inbox.
pub const ESCROW_INBOX_SWITCH: &str = "--escrow-inbox";
/// `--escrow-outbox <dir>`, nur bei `reader-key-escrow`: dorthin geht allein
/// der versiegelte Umschlag.
pub const ESCROW_OUTBOX_SWITCH: &str = "--escrow-outbox";
/// `--bundle <file>`, nur bei `organization web-bundle-release`: die exakten
/// Bytes des Bundles, dessen Hash (`ea_crypto::web_bundle_hash`) die Freigabe
/// nennt.
pub const BUNDLE_SWITCH: &str = "--bundle";
/// `--bundle-version <version>`, nur bei `organization web-bundle-release`.
pub const BUNDLE_VERSION_SWITCH: &str = "--bundle-version";
/// `--effective-from-registry-version <u64>`, nur bei den beiden
/// Bundle-Unterkommandos; ohne ihn gilt die Version des gewählten Kopfes.
pub const EFFECTIVE_FROM_REGISTRY_VERSION_SWITCH: &str = "--effective-from-registry-version";
/// `--report-signing-key <source>`, nur bei `report` — und IMMER verweigert.
///
/// # Warum ein Schalter, der nie etwas tut
///
/// Er wird ANGENOMMEN, damit der Lauf mit einer benannten Begruendung endet
/// statt mit „unbekannter Schalter". Der Unterschied ist der ganze Zweck: ein
/// Betreiber, der eine Berichtssignatur verlangt, soll erfahren, dass Suite v1
/// keine autorisierte Signaturrolle kennt — und nicht glauben, er habe sich
/// vertippt. Die fuenf Belege stehen in
/// `docs/adr/0001-toolchain-and-cryptography-dependencies.md`.
///
/// # Warum er NICHT in [`crate::output`]s Grammatik steht
///
/// Die Grammatik nennt, was das Werkzeug KANN. Ein Schalter, der ausnahmslos
/// mit [`ea_recovery::ExitCode::Unsupported`] endet, ist keine Faehigkeit; ihn
/// dort aufzufuehren waere ein Versprechen, das der naechste Lauf bricht.
pub const REPORT_SIGNING_KEY_SWITCH: &str = "--report-signing-key";

/// Die Ausgabeform.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Format {
    /// Zeilenweise stabile Schluessel-Wert-Paare.
    Text,
    /// Das Berichtsdokument `ea.verification-report/v1`.
    Json,
}

pub const POSTURE_TARGET_SWITCH: &str = "--posture-target";
pub const POSTURE_DOCUMENT_SWITCH: &str = "--posture-document";
pub const EVIDENCE_REFERENCE_SWITCH: &str = "--evidence-reference";
pub const VALID_FOR_MS_SWITCH: &str = "--valid-for-ms";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PostureAction {
    Target {
        output: PathBuf,
    },
    Issue {
        target: PathBuf,
        evidence_reference: PathBuf,
        lifetime_ms: i64,
        output: PathBuf,
    },
    Import {
        document: PathBuf,
    },
}

/// Die geschlossenen Operator-Aktionen; Identität kommt ausschließlich vom Provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatorAction {
    Provision,
    VerifySession,
    Revoke,
    RegisterNetworkArchive,
}

/// Eine geparste Schluesselquelle, wie sie in [`Command`] steht.
///
/// # Warum ein Huelltyp und nicht [`KeySourceSpec`] selbst
///
/// [`Command`] leitet `Debug` ab, damit die Unittests dieses Moduls
/// `assert_eq!` ueber ganze Aufrufe fuehren koennen. [`KeySourceSpec`] fuehrt
/// BEWUSST keines: jede Variante traegt Hostpfade eines Recovery-Mediums, und
/// ein `Debug` waere der bequemste Weg, sie in eine Ausgabe zu bringen. Der
/// Huelltyp haelt beides zusammen: seine Anzeige nennt allein die QUELLART
/// — `file`, `container`, `pkcs11` — und keinen Pfad.
#[derive(Clone, Eq, PartialEq)]
pub struct KeySourceArgument(KeySourceSpec);

impl KeySourceArgument {
    /// Die Quellenangabe, wie `ea-recovery` sie aufloest.
    #[must_use]
    pub const fn spec(&self) -> &KeySourceSpec {
        &self.0
    }

    /// Das Wort der Quellart, wie es in der Anzeige steht.
    const fn kind_word(&self) -> &'static str {
        match self.0 {
            KeySourceSpec::File(_) => "file",
            KeySourceSpec::Container { .. } => "container",
            KeySourceSpec::Pkcs11 { .. } => "pkcs11",
        }
    }
}

impl From<KeySourceSpec> for KeySourceArgument {
    fn from(spec: KeySourceSpec) -> Self {
        Self(spec)
    }
}

impl fmt::Debug for KeySourceArgument {
    /// Nur die Quellart. Kein Pfad, kein Label, keine ID.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "KeySourceArgument({})", self.kind_word())
    }
}

/// Das gewaehlte Kommando samt seinen Pfaden.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    /// Bestand pruefen und berichten.
    Verify {
        /// Wurzel des Bestands.
        archive: PathBuf,
    },
    /// Bestand pruefen und seine Objektergebnisse auflisten.
    List {
        /// Wurzel des Bestands.
        archive: PathBuf,
    },
    /// Bestand pruefen und danach Klartext in ein neues Ziel schreiben.
    Decrypt {
        /// Wurzel des Bestands.
        archive: PathBuf,
        /// Herkunft des Empfaengerschluessels.
        key: KeySourceArgument,
        /// Neues oder leeres Zielverzeichnis.
        output: PathBuf,
    },
    /// Bestand pruefen und die Eingaben eines historischen Re-Grants
    /// aufloesen.
    ///
    /// Das Positionsargument heisst in `design.md` §16.1 `<entry-or-archive>`.
    /// In dieser Stufe ist es die Wurzel des Bestands: die Eingrenzung auf
    /// einen einzelnen Eintrag ist eine Entscheidung des Dienstes (Task 8)
    /// und nicht der Grammatik — ein Pfad, der auf eine Datei zeigt, ist
    /// heute ein nicht lesbarer Bestand und endet mit 20.
    Grant {
        /// Wurzel des Bestands.
        archive: PathBuf,
        /// Herkunft des privaten Recovery-KEM-Schluessels.
        recovery_key: KeySourceArgument,
        /// Herkunft des getrennten HGA-Signierschluessels.
        authority_key: KeySourceArgument,
        /// Die Autorisierungsdatei.
        authorization: PathBuf,
        /// Das Empfaengerzertifikat.
        recipient_certificate: PathBuf,
        /// Native operator configuration; required for issuance.
        operator_config: Option<PathBuf>,
        /// New output directory; defaults to archive/grants.
        output: Option<PathBuf>,
    },
    /// Bestand pruefen und die Eingaben eines Wiederherstellungstests
    /// aufloesen.
    RecoveryTest {
        runtime: Option<RecoveryRuntimeArguments>,
        /// Wurzel des Bestands.
        archive: PathBuf,
        /// Das Schluesselinventar.
        key_inventory: PathBuf,
        /// Zieldatei des Berichts.
        output: PathBuf,
    },
    /// Bestand pruefen und den Bericht kanonisch in eine Datei schreiben.
    Report {
        /// Wurzel des Bestands.
        archive: PathBuf,
        /// Zieldatei des Berichts.
        output: PathBuf,
    },
    /// Bestand pruefen und ihn VERSCHLUESSELT vollstaendig kopieren.
    Export {
        /// Wurzel des Bestands oder Serverquelle.
        source: PathBuf,
        /// Neues oder leeres Zielverzeichnis.
        output: PathBuf,
    },
    /// Die Ersteinrichtung einer Organisation beginnen oder fortsetzen.
    ///
    /// The location remains `Invocation::anchor`.
    OrganizationInit,
    /// Certify only the existing installed native Root and retain step 2.
    OrganizationCertifyRoot {
        initial_registry_version: RegistryVersion,
    },
    /// Zeremonie A des Reader-Key-Escrows; bis zum Cutover gesperrt.
    OrganizationReaderKeyEscrowPublish { config: PathBuf, inbox: PathBuf },
    /// Root signiert eine `webBundleRelease` (U4).
    OrganizationWebBundleRelease {
        config: PathBuf,
        bundle: PathBuf,
        bundle_version: String,
        effective_from: Option<RegistryVersion>,
    },
    /// Root signiert einen `webBundleRevocation` der Freigabe in `release`.
    OrganizationWebBundleRevoke {
        config: PathBuf,
        release: PathBuf,
        effective_from: Option<RegistryVersion>,
    },
    /// Zeremonie B: ein Escrow öffnen und den Umschlag ausliefern.
    ReaderKeyEscrowOpen {
        config: PathBuf,
        recovery_key: KeySourceArgument,
        authorization: PathBuf,
        inbox: PathBuf,
        outbox: PathBuf,
    },
    /// Zeremonie B: eine abgebrochene Auslieferung fortsetzen.
    ReaderKeyEscrowPickup {
        config: PathBuf,
        authorization: PathBuf,
        inbox: PathBuf,
        outbox: PathBuf,
    },
    /// Verwaltung des nativen, OS-kontogebundenen Operators.
    Operator {
        action: OperatorAction,
        config: PathBuf,
        /// Nur bei `register-network-archive`: das Netzprofil.
        archive_profile: Option<PathBuf>,
    },
    Posture {
        action: PostureAction,
        config: PathBuf,
    },
    /// Eine Aenderung 1 fuer das in der Bedienerdatei benannte Ziel PLANEN.
    ///
    /// Die drei Fensterzahlen sind die Entscheidung des Betreibers und werden
    /// hier nur ANGENOMMEN: `crate::commands::registry` rechnet keine
    /// Sequenz und keine Frist aus, sondern legt sie unveraendert in
    /// `ea_admin::RegistryWindow`.
    RegistryRevocationPlan {
        /// Die oeffentliche Bedienerdatei.
        config: PathBuf,
        /// Ab dieser Sequenz wirkt die geplante Aenderung.
        effective_from_sequence: ChainSequence,
        /// Bis zu dieser Sequenz reicht das Lease des Ereignisses.
        valid_through_sequence: ChainSequence,
        /// Die Zeitgrenze des Ereignisses.
        not_after: UnixMillis,
    },
    /// Eine bereits ausgestellte Uhrfreigabe VERBRAUCHEN.
    ClockReleaseApply {
        /// Die oeffentliche Bedienerdatei.
        config: PathBuf,
        /// Die Datei mit den exakten Freigabebytes.
        release: PathBuf,
    },
    /// Einen Writer-Uebergang gegen den gewaehlten Kopf VORBEREITEN.
    ///
    /// Traegt KEIN Fenster: die Vorbereitung plant kein Ereignis, sie prueft
    /// den Antrag und zeigt die Felder, die die Zeremonie unterschreiben soll.
    WriterTransitionPrepare {
        /// Die oeffentliche Bedienerdatei.
        config: PathBuf,
        /// Die Antragsdatei.
        request: PathBuf,
    },
    /// Die veroeffentlichten Bytes eines Uebergangs gegen den Antrag halten
    /// und das Aenderung-3-Ereignis PLANEN.
    ///
    /// Zwei Fensterzahlen und nicht drei: die Wirksamkeitssequenz folgt aus
    /// dem Antrag (siehe [`EFFECTIVE_FROM_SWITCH`]).
    WriterTransitionActivate {
        /// Die oeffentliche Bedienerdatei.
        config: PathBuf,
        /// Die Antragsdatei — DIESELBE wie bei `prepare`.
        request: PathBuf,
        /// Die Datei mit den exakten Bytes des veroeffentlichten Objekts.
        transition_object: PathBuf,
        /// Bis zu dieser Sequenz reicht das Lease des Ereignisses.
        valid_through_sequence: ChainSequence,
        /// Die Zeitgrenze des Ereignisses.
        not_after: UnixMillis,
    },
}

/// Ein vollstaendig geparster Aufruf.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invocation {
    /// Der Trust Anchor. Kommt von aussen und NIE aus dem Bestand.
    pub anchor: PathBuf,
    /// Die Ausgabeform.
    pub format: Format,
    /// Der EINZIGE Weg zu nichtdeterministischen Berichtsfeldern.
    pub include_runtime_metadata: bool,
    /// Die verlangte Herkunft eines Berichtssignierschluessels.
    ///
    /// Steht neben `include_runtime_metadata` und nicht in
    /// [`Command::Report`], weil beide dasselbe sind: ein Schalter, den genau
    /// `report` annimmt. Der Wert wird NIE gelesen — er entscheidet allein, ob
    /// der Lauf mit der begruendeten Verweigerung endet.
    pub report_signing_key: Option<PathBuf>,
    /// Das gewaehlte Kommando.
    pub command: Command,
}

/// Ein Aufruffehler. Endet ausnahmslos mit [`ea_recovery::ExitCode::Usage`].
///
/// Jede Auspraegung nennt in ihrer Anzeige den fehlenden oder falschen Namen
/// WOERTLICH. Ein Test darf darauf assertieren; ein Aufrufer soll daran
/// erkennen, was er zu aendern hat.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UsageError {
    /// Es wurde ueberhaupt kein Argument uebergeben.
    ///
    /// Der EINZIGE Fall, dessen Ausgabe nach stdout geht: eine Grammatik, nach
    /// der jemand ohne Argumente fragt, ist eine Nutzausgabe und keine
    /// Fehlermeldung.
    NoArguments,
    /// Ein Argument beginnt mit `-` und ist keiner der bekannten Schalter.
    UnknownSwitch(String),
    /// Ein wertnehmender Schalter steht ohne Wert da.
    MissingValue(&'static str),
    /// Derselbe Schalter wurde mehr als einmal angegeben.
    DuplicateSwitch(&'static str),
    /// `--format` traegt etwas anderes als `text` oder `json`.
    UnknownFormat(String),
    /// Ein zahlnehmender Schalter traegt keine Zahl seines Wertebereichs.
    ///
    /// Ein eigener Arm neben [`Self::UnknownFormat`], weil er dieselbe Frage
    /// fuer einen OFFENEN Wertebereich beantwortet: bei `--format` gibt es
    /// zwei erlaubte Woerter, hier eine Zahl, die nicht ueberlaufen darf.
    UnknownNumber {
        /// Der Schalter, dessen Wert keine Zahl ist.
        switch: &'static str,
        /// Was statt einer Zahl dastand, woertlich.
        value: String,
    },
    /// Das erste Positionsargument ist keines der bekannten Kommandos.
    UnknownCommand(String),
    /// Es wurde ein Schalter, aber kein Kommando angegeben.
    MissingCommand,
    /// `--trust-anchor` fehlt.
    MissingTrustAnchor,
    /// Das Kommando braucht ein Positionsargument, bekam aber keines.
    MissingPositional(&'static str),
    /// Das Kommando nimmt genau ein Positionsargument, bekam aber mehrere.
    SurplusPositional(&'static str),
    /// Das Kommando verlangt einen Schalter, der fehlt.
    MissingSwitch {
        /// Der fehlende Schalter.
        switch: &'static str,
        /// Das Kommando, das ihn verlangt.
        command: &'static str,
    },
    /// Das Kommando kennt dieses Unterkommando nicht.
    ///
    /// Ein eigener Arm neben [`Self::UnknownCommand`], weil er eine andere
    /// Frage beantwortet: das Kommando wurde erkannt, seine zweite Haelfte
    /// nicht.
    UnknownSubcommand {
        /// Das erkannte Kommando.
        command: &'static str,
        /// Was statt eines Unterkommandos dastand, woertlich.
        value: String,
        /// Die erwarteten Unterkommandos dieses Kommandos.
        expected: &'static str,
    },
    /// Der Schalter existiert, gehoert aber nicht zu diesem Kommando.
    SwitchNotAllowed {
        /// Der abgelehnte Schalter.
        switch: &'static str,
        /// Das Kommando, das ihn nicht kennt.
        command: &'static str,
    },
    /// Eine `<key-source>`-Angabe verletzt die Quellengrammatik.
    ///
    /// Traegt den SCHALTER, weil `grant` zwei Schluesselquellen fuehrt und
    /// der Aufrufer wissen soll, welche er zu aendern hat — dieselbe Regel wie
    /// bei [`Self::UnknownNumber`]. Den FEHLER traegt es unveraendert:
    /// [`KeySourceSpecError`] nennt das betroffene Feld woertlich und nie
    /// einen Wert, und eine hiesige Abschrift koennte still von ihm
    /// abweichen.
    KeySource {
        /// Der Schalter, dessen Wert keine gueltige Quellenangabe ist.
        switch: &'static str,
        /// Der Grammatikfehler, wie `ea-recovery` ihn meldet.
        error: KeySourceSpecError,
    },
}

impl fmt::Display for UsageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoArguments => formatter.write_str("no command was given"),
            Self::UnknownSwitch(switch) => write!(formatter, "unknown switch {switch}"),
            Self::MissingValue(switch) => write!(formatter, "{switch} requires a value"),
            Self::DuplicateSwitch(switch) => {
                write!(formatter, "{switch} was given more than once")
            }
            Self::UnknownFormat(value) => write!(
                formatter,
                "{FORMAT_SWITCH} accepts only text or json, not {value}"
            ),
            Self::UnknownNumber { switch, value } => write!(
                formatter,
                "{switch} accepts only a decimal number within its range, not {value}"
            ),
            Self::UnknownCommand(command) => write!(
                formatter,
                "unknown command {command}; expected verify, list, decrypt, grant, report, \
                 export, recovery-test, organization, operator, registry, clock-release, \
                 writer-transition or reader-key-escrow"
            ),
            Self::MissingCommand => formatter.write_str(
                "no command was given; expected verify, list, decrypt, grant, report, export, \
                 recovery-test, organization, operator, registry, clock-release, \
                 writer-transition or reader-key-escrow",
            ),
            Self::MissingTrustAnchor => write!(
                formatter,
                "{TRUST_ANCHOR_SWITCH} is required for every command"
            ),
            Self::MissingPositional(command) => write!(
                formatter,
                "{command} requires exactly one positional argument, none was given"
            ),
            Self::SurplusPositional(command) => write!(
                formatter,
                "{command} takes exactly one positional argument, more were given"
            ),
            Self::UnknownSubcommand {
                command,
                value,
                expected,
            } => write!(
                formatter,
                "unknown {command} subcommand {value}; expected {expected}"
            ),
            Self::MissingSwitch { switch, command } => {
                write!(formatter, "{command} requires {switch}")
            }
            Self::SwitchNotAllowed { switch, command } => {
                write!(formatter, "{switch} is not allowed for {command}")
            }
            Self::KeySource { switch, error } => write!(formatter, "{switch}: {error}"),
        }
    }
}

impl std::error::Error for UsageError {}

/// Welches der zwoelf Kommandos gemeint ist.
///
/// Eine eigene Aufzaehlung statt einer Zeichenkette, damit die Auswertung unten
/// VOLLSTAENDIG ist und kein `unreachable!()` braucht. Ein `unreachable!()`
/// waere eine Behauptung; eine Aufzaehlung ist ein Beweis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandKind {
    Verify,
    List,
    Decrypt,
    Grant,
    Report,
    Export,
    RecoveryTest,
    Organization,
    Operator,
    Posture,
    Registry,
    ClockRelease,
    WriterTransition,
    ReaderKeyEscrow,
}

impl CommandKind {
    /// Der Name, wie er in der Eingabezeile steht und in Meldungen erscheint.
    const fn name(self) -> &'static str {
        match self {
            Self::Verify => "verify",
            Self::List => "list",
            Self::Decrypt => "decrypt",
            Self::Grant => "grant",
            Self::Report => "report",
            Self::Export => "export",
            Self::RecoveryTest => "recovery-test",
            Self::Organization => "organization",
            Self::Operator => "operator",
            Self::Posture => "posture",
            Self::Registry => "registry",
            Self::ClockRelease => "clock-release",
            Self::WriterTransition => "writer-transition",
            Self::ReaderKeyEscrow => "reader-key-escrow",
        }
    }

    /// Erkennt ein Kommando. Die Zuordnung ist exakt und ohne Abkuerzungen.
    fn from_token(token: &str) -> Option<Self> {
        match token {
            "verify" => Some(Self::Verify),
            "list" => Some(Self::List),
            "decrypt" => Some(Self::Decrypt),
            "grant" => Some(Self::Grant),
            "report" => Some(Self::Report),
            "export" => Some(Self::Export),
            "recovery-test" => Some(Self::RecoveryTest),
            "organization" => Some(Self::Organization),
            "operator" => Some(Self::Operator),
            "posture" => Some(Self::Posture),
            "registry" => Some(Self::Registry),
            "clock-release" => Some(Self::ClockRelease),
            "writer-transition" => Some(Self::WriterTransition),
            "reader-key-escrow" => Some(Self::ReaderKeyEscrow),
            _ => None,
        }
    }
}

/// Wahr, wenn das Argument als Schalter zu lesen ist.
///
/// Prueft das erste BYTE und nicht das erste Zeichen: ein nicht-UTF-8-Argument
/// hat kein erstes Zeichen, aber sehr wohl ein erstes Byte, und ob es ein
/// Schalter sein WILL, entscheidet sich vor jeder Kodierungsfrage.
fn looks_like_switch(argument: &OsString) -> bool {
    argument.as_encoded_bytes().first() == Some(&b'-')
}

/// Liest den Wert eines wertnehmenden Schalters in `slot`.
///
/// Erkennt dabei die doppelte Angabe: der Slot ist die einzige Stelle, an der
/// „schon gesetzt" ueberhaupt sichtbar ist.
fn take_path_value(
    slot: &mut Option<PathBuf>,
    switch: &'static str,
    arguments: &mut impl Iterator<Item = OsString>,
) -> Result<(), UsageError> {
    if slot.is_some() {
        return Err(UsageError::DuplicateSwitch(switch));
    }
    let value = arguments.next().ok_or(UsageError::MissingValue(switch))?;
    if looks_like_switch(&value) {
        return Err(UsageError::MissingValue(switch));
    }
    *slot = Some(PathBuf::from(value));
    Ok(())
}

/// Liest die SCHLUESSELQUELLE eines Schalters in `slot`.
///
/// Dieselben zwei Konventionen wie [`take_path_value`], und danach die
/// Quellengrammatik aus `ea-recovery`: was mit `-` beginnt, ist ein Schalter
/// und kein Wert; was danach die Grammatik verletzt, ist ein Aufruffehler,
/// der Schalter und Feld nennt. Ein Nicht-UTF-8-Wert ist nach
/// [`KeySourceSpec::parse`] ein Pfad der Dateiform — dieselbe Regel wie fuer
/// jeden anderen Pfadwert dieses Parsers.
fn take_key_source_value(
    slot: &mut Option<KeySourceArgument>,
    switch: &'static str,
    arguments: &mut impl Iterator<Item = OsString>,
) -> Result<(), UsageError> {
    if slot.is_some() {
        return Err(UsageError::DuplicateSwitch(switch));
    }
    let value = arguments.next().ok_or(UsageError::MissingValue(switch))?;
    if looks_like_switch(&value) {
        return Err(UsageError::MissingValue(switch));
    }
    let spec =
        KeySourceSpec::parse(&value).map_err(|error| UsageError::KeySource { switch, error })?;
    *slot = Some(KeySourceArgument::from(spec));
    Ok(())
}

/// Liest den ZAHLWERT eines Schalters in `slot`.
///
/// Dieselben zwei Konventionen wie [`take_path_value`]: der Wert steht als
/// eigenes Argument, und was mit `-` beginnt, ist ein Schalter und kein Wert.
/// Anders als bei einem Pfad muss der Wert UTF-8 sein — er wird gegen eine
/// Zahl verglichen, und was sich damit nicht vergleichen laesst, ist keine.
///
/// Gelesen wird IMMER als `u64`. Eine negative Sequenz gibt es nicht, und eine
/// Unixzeit vor der Epoche ist in diesem Bauwerk keine Lage; der Aufrufer
/// verengt danach auf seinen eigenen Bereich.
fn take_number_value(
    slot: &mut Option<u64>,
    switch: &'static str,
    arguments: &mut impl Iterator<Item = OsString>,
) -> Result<(), UsageError> {
    if slot.is_some() {
        return Err(UsageError::DuplicateSwitch(switch));
    }
    let value = arguments.next().ok_or(UsageError::MissingValue(switch))?;
    if looks_like_switch(&value) {
        return Err(UsageError::MissingValue(switch));
    }
    let parsed = value
        .to_str()
        .and_then(|text| text.parse::<u64>().ok())
        .ok_or_else(|| UsageError::UnknownNumber {
            switch,
            value: value.to_string_lossy().into_owned(),
        })?;
    *slot = Some(parsed);
    Ok(())
}

/// Verengt den Wert von `--not-after` auf eine Unixzeit.
///
/// Die einzige Verengung dieses Parsers: eine Unixzeit ist
/// `i64`-Millisekunden. Sie steht HIER und nicht in [`take_number_value`],
/// weil die Sequenzen den vollen `u64`-Bereich fuehren — und in Schritt 6
/// der Pruefreihenfolge, also HINTER den verlangten Schaltern.
fn unix_millis(not_after: u64) -> Result<UnixMillis, UsageError> {
    i64::try_from(not_after)
        .map(UnixMillis::new)
        .map_err(|_| UsageError::UnknownNumber {
            switch: NOT_AFTER_SWITCH,
            value: not_after.to_string(),
        })
}

/// Parst die Argumente OHNE den Programmnamen.
///
/// Der Aufrufer uebergibt `std::env::args_os().skip(1)`. Das `skip` steht dort
/// und nicht hier, damit jeder Unittest die reine Argumentfolge schreibt und
/// nicht ein Fuellelement mitschleppt, das niemanden interessiert.
///
/// # Pruefreihenfolge
///
/// Fest und dokumentiert, damit bei mehreren Verstoessen immer dieselbe Meldung
/// erscheint:
///
/// 1. Fehler waehrend des Durchlaufs, in der Reihenfolge der Argumente:
///    unbekannter Schalter, fehlender Wert, doppelter Schalter, unbekannter
///    `--format`-Wert, unbekanntes Kommando.
/// 2. Gar kein Argument, danach: kein Kommando.
/// 3. Fehlender `--trust-anchor`.
/// 4. Schalter, die dieses Kommando nicht kennt.
/// 5. Anzahl der Positionsargumente.
/// 6. Schalter, die dieses Kommando verlangt.
///
/// # Errors
///
/// [`UsageError`] in jeder oben genannten Lage. Ein Aufruffehler ist
/// ausdruecklich KEIN Befund ueber einen Bestand: hier wurde noch kein Byte
/// gelesen.
pub fn parse(arguments: impl Iterator<Item = OsString>) -> Result<Invocation, UsageError> {
    let mut arguments = arguments;

    let mut anchor: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut key: Option<KeySourceArgument> = None;
    let mut recovery_key: Option<KeySourceArgument> = None;
    let mut authority_key: Option<KeySourceArgument> = None;
    let mut authorization: Option<PathBuf> = None;
    let mut recipient_certificate: Option<PathBuf> = None;
    let mut key_inventory: Option<PathBuf> = None;
    let mut recovery_mode = None;
    let mut recovery_paths = std::collections::BTreeMap::new();
    let mut report_signing_key: Option<PathBuf> = None;
    let mut operator_config: Option<PathBuf> = None;
    let mut archive_profile: Option<PathBuf> = None;
    let mut posture_target = None;
    let mut posture_document = None;
    let mut evidence_reference = None;
    let mut valid_for_ms = None;
    let mut release: Option<PathBuf> = None;
    let mut request: Option<PathBuf> = None;
    let mut transition_object: Option<PathBuf> = None;
    let mut initial_registry_version: Option<u64> = None;
    let mut effective_from: Option<u64> = None;
    let mut valid_through: Option<u64> = None;
    let mut not_after: Option<u64> = None;
    let mut escrow_inbox: Option<PathBuf> = None;
    let mut escrow_outbox: Option<PathBuf> = None;
    let mut bundle: Option<PathBuf> = None;
    let mut bundle_version: Option<PathBuf> = None;
    let mut effective_from_registry_version: Option<u64> = None;
    let mut format: Option<Format> = None;
    let mut include_runtime_metadata: Option<bool> = None;
    let mut command_kind: Option<CommandKind> = None;
    let mut positionals: Vec<PathBuf> = Vec::new();
    let mut saw_any_argument = false;

    while let Some(argument) = arguments.next() {
        saw_any_argument = true;

        if looks_like_switch(&argument) {
            let Some(switch) = argument.to_str() else {
                // Kein Schaltername des Repertoires ist nicht-UTF-8, also ist
                // dieser hier keiner. Die verlustbehaftete Wiedergabe ist die
                // Eingabe des Aufrufers und nichts aus einem Bestand.
                return Err(UsageError::UnknownSwitch(
                    argument.to_string_lossy().into_owned(),
                ));
            };
            match switch {
                recovery::MODE => {
                    take_path_value(&mut recovery_mode, recovery::MODE, &mut arguments)?
                }
                value if recovery::SWITCHES.contains(&value) => {
                    let name = *recovery::SWITCHES
                        .iter()
                        .find(|name| **name == value)
                        .expect("matched recovery switch");
                    if recovery_paths.contains_key(name) {
                        return Err(UsageError::DuplicateSwitch(name));
                    }
                    let mut path = None;
                    take_path_value(&mut path, name, &mut arguments)?;
                    recovery_paths.insert(name, path.expect("required value"));
                }
                TRUST_ANCHOR_SWITCH => {
                    take_path_value(&mut anchor, TRUST_ANCHOR_SWITCH, &mut arguments)?;
                }
                INITIAL_REGISTRY_VERSION_SWITCH => take_number_value(
                    &mut initial_registry_version,
                    INITIAL_REGISTRY_VERSION_SWITCH,
                    &mut arguments,
                )?,
                OUTPUT_SWITCH => take_path_value(&mut output, OUTPUT_SWITCH, &mut arguments)?,
                KEY_SWITCH => take_key_source_value(&mut key, KEY_SWITCH, &mut arguments)?,
                RECOVERY_KEY_SWITCH => {
                    take_key_source_value(&mut recovery_key, RECOVERY_KEY_SWITCH, &mut arguments)?
                }
                AUTHORITY_KEY_SWITCH => {
                    take_key_source_value(&mut authority_key, AUTHORITY_KEY_SWITCH, &mut arguments)?
                }
                AUTHORIZATION_SWITCH => {
                    take_path_value(&mut authorization, AUTHORIZATION_SWITCH, &mut arguments)?
                }
                RECIPIENT_CERT_SWITCH => take_path_value(
                    &mut recipient_certificate,
                    RECIPIENT_CERT_SWITCH,
                    &mut arguments,
                )?,
                KEY_INVENTORY_SWITCH => {
                    take_path_value(&mut key_inventory, KEY_INVENTORY_SWITCH, &mut arguments)?
                }
                OPERATOR_CONFIG_SWITCH => {
                    take_path_value(&mut operator_config, OPERATOR_CONFIG_SWITCH, &mut arguments)?
                }
                NETWORK_ARCHIVE_PROFILE_SWITCH => take_path_value(
                    &mut archive_profile,
                    NETWORK_ARCHIVE_PROFILE_SWITCH,
                    &mut arguments,
                )?,
                POSTURE_TARGET_SWITCH => {
                    take_path_value(&mut posture_target, POSTURE_TARGET_SWITCH, &mut arguments)?
                }
                POSTURE_DOCUMENT_SWITCH => take_path_value(
                    &mut posture_document,
                    POSTURE_DOCUMENT_SWITCH,
                    &mut arguments,
                )?,
                EVIDENCE_REFERENCE_SWITCH => take_path_value(
                    &mut evidence_reference,
                    EVIDENCE_REFERENCE_SWITCH,
                    &mut arguments,
                )?,
                VALID_FOR_MS_SWITCH => {
                    take_number_value(&mut valid_for_ms, VALID_FOR_MS_SWITCH, &mut arguments)?
                }
                RELEASE_SWITCH => take_path_value(&mut release, RELEASE_SWITCH, &mut arguments)?,
                REQUEST_SWITCH => take_path_value(&mut request, REQUEST_SWITCH, &mut arguments)?,
                TRANSITION_OBJECT_SWITCH => take_path_value(
                    &mut transition_object,
                    TRANSITION_OBJECT_SWITCH,
                    &mut arguments,
                )?,
                EFFECTIVE_FROM_SWITCH => {
                    take_number_value(&mut effective_from, EFFECTIVE_FROM_SWITCH, &mut arguments)?
                }
                VALID_THROUGH_SWITCH => {
                    take_number_value(&mut valid_through, VALID_THROUGH_SWITCH, &mut arguments)?
                }
                NOT_AFTER_SWITCH => {
                    take_number_value(&mut not_after, NOT_AFTER_SWITCH, &mut arguments)?
                }
                ESCROW_INBOX_SWITCH => {
                    take_path_value(&mut escrow_inbox, ESCROW_INBOX_SWITCH, &mut arguments)?
                }
                ESCROW_OUTBOX_SWITCH => {
                    take_path_value(&mut escrow_outbox, ESCROW_OUTBOX_SWITCH, &mut arguments)?
                }
                BUNDLE_SWITCH => take_path_value(&mut bundle, BUNDLE_SWITCH, &mut arguments)?,
                BUNDLE_VERSION_SWITCH => {
                    take_path_value(&mut bundle_version, BUNDLE_VERSION_SWITCH, &mut arguments)?
                }
                EFFECTIVE_FROM_REGISTRY_VERSION_SWITCH => take_number_value(
                    &mut effective_from_registry_version,
                    EFFECTIVE_FROM_REGISTRY_VERSION_SWITCH,
                    &mut arguments,
                )?,
                REPORT_SIGNING_KEY_SWITCH => take_path_value(
                    &mut report_signing_key,
                    REPORT_SIGNING_KEY_SWITCH,
                    &mut arguments,
                )?,
                FORMAT_SWITCH => {
                    if format.is_some() {
                        return Err(UsageError::DuplicateSwitch(FORMAT_SWITCH));
                    }
                    let value = arguments
                        .next()
                        .ok_or(UsageError::MissingValue(FORMAT_SWITCH))?;
                    if looks_like_switch(&value) {
                        return Err(UsageError::MissingValue(FORMAT_SWITCH));
                    }
                    format = Some(match value.to_str() {
                        Some("text") => Format::Text,
                        Some("json") => Format::Json,
                        _ => {
                            return Err(UsageError::UnknownFormat(
                                value.to_string_lossy().into_owned(),
                            ));
                        }
                    });
                }
                INCLUDE_RUNTIME_METADATA_SWITCH => {
                    if include_runtime_metadata.is_some() {
                        return Err(UsageError::DuplicateSwitch(INCLUDE_RUNTIME_METADATA_SWITCH));
                    }
                    include_runtime_metadata = Some(true);
                }
                _ => return Err(UsageError::UnknownSwitch(switch.to_owned())),
            }
        } else if command_kind.is_none() {
            let kind = argument
                .to_str()
                .and_then(CommandKind::from_token)
                .ok_or_else(|| {
                    UsageError::UnknownCommand(argument.to_string_lossy().into_owned())
                })?;
            command_kind = Some(kind);
        } else {
            positionals.push(PathBuf::from(argument));
        }
    }

    // 2 — gar nichts, danach: nur Schalter.
    if !saw_any_argument {
        return Err(UsageError::NoArguments);
    }
    let command_kind = command_kind.ok_or(UsageError::MissingCommand)?;
    let command_name = command_kind.name();

    // 3 — der Anker. `design.md`:1765: er kommt von aussen, bei JEDEM Kommando.
    let anchor = anchor.ok_or(UsageError::MissingTrustAnchor)?;

    // 4 — Schalter, die dieses Kommando nicht kennt. Sie werden GLOBAL geparst
    // und HIER abgelehnt: ein Aufrufer, der `--key` an `verify` haengt, hat
    // sich vertan, und ein stilles Ignorieren liesse ihn glauben, der
    // Schluessel sei benutzt worden.
    for (present, switch) in [
        (posture_target.is_some(), POSTURE_TARGET_SWITCH),
        (posture_document.is_some(), POSTURE_DOCUMENT_SWITCH),
        (evidence_reference.is_some(), EVIDENCE_REFERENCE_SWITCH),
        (valid_for_ms.is_some(), VALID_FOR_MS_SWITCH),
    ] {
        if present && command_kind != CommandKind::Posture {
            return Err(UsageError::SwitchNotAllowed {
                switch,
                command: command_name,
            });
        }
    }
    if initial_registry_version.is_some() && command_kind != CommandKind::Organization {
        return Err(UsageError::SwitchNotAllowed {
            switch: INITIAL_REGISTRY_VERSION_SWITCH,
            command: command_name,
        });
    }
    if key.is_some() && command_kind != CommandKind::Decrypt {
        return Err(UsageError::SwitchNotAllowed {
            switch: KEY_SWITCH,
            command: command_name,
        });
    }
    // Die vier Eingaben von `grant` gehoeren allein `grant`, das Inventar
    // allein `recovery-test`. `--key` bleibt bei `decrypt`: `grant` fuehrt
    // seine beiden Schluesselquellen unter eigenem Namen.
    // `reader-key-escrow` nimmt Recovery-Schlüssel und Autorisierung unter
    // denselben Namen: es ist dieselbe Art Eingabe, eine andere Operation.
    for (present, switch) in [
        (recovery_key.is_some(), RECOVERY_KEY_SWITCH),
        (authorization.is_some(), AUTHORIZATION_SWITCH),
    ] {
        if present
            && !matches!(
                command_kind,
                CommandKind::Grant | CommandKind::ReaderKeyEscrow
            )
        {
            return Err(UsageError::SwitchNotAllowed {
                switch,
                command: command_name,
            });
        }
    }
    for (present, switch) in [
        (authority_key.is_some(), AUTHORITY_KEY_SWITCH),
        (recipient_certificate.is_some(), RECIPIENT_CERT_SWITCH),
    ] {
        if present && command_kind != CommandKind::Grant {
            return Err(UsageError::SwitchNotAllowed {
                switch,
                command: command_name,
            });
        }
    }
    if key_inventory.is_some() && command_kind != CommandKind::RecoveryTest {
        return Err(UsageError::SwitchNotAllowed {
            switch: KEY_INVENTORY_SWITCH,
            command: command_name,
        });
    }
    if (recovery_mode.is_some() || !recovery_paths.is_empty())
        && command_kind != CommandKind::RecoveryTest
    {
        return Err(UsageError::SwitchNotAllowed {
            switch: recovery::MODE,
            command: command_name,
        });
    }
    // `organization` nimmt die Bedienerdatei und die Escrow-Inbox allein für
    // `reader-key-escrow-publish`, die Bedienerdatei auch für die beiden
    // Bundle-Unterkommandos; `init` und `certify-root` bleiben ohne.
    let organization_subcommand = |name: &str| {
        command_kind == CommandKind::Organization
            && positionals.first().map(PathBuf::as_path) == Some(Path::new(name))
    };
    let escrow_publication =
        organization_subcommand(ORGANIZATION_READER_KEY_ESCROW_PUBLISH_SUBCOMMAND);
    let bundle_release = organization_subcommand(ORGANIZATION_WEB_BUNDLE_RELEASE_SUBCOMMAND);
    let bundle_revoke = organization_subcommand(ORGANIZATION_WEB_BUNDLE_REVOKE_SUBCOMMAND);
    for (present, switch) in [
        (bundle.is_some(), BUNDLE_SWITCH),
        (bundle_version.is_some(), BUNDLE_VERSION_SWITCH),
    ] {
        if present && !bundle_release {
            return Err(UsageError::SwitchNotAllowed {
                switch,
                command: command_name,
            });
        }
    }
    if effective_from_registry_version.is_some() && !bundle_release && !bundle_revoke {
        return Err(UsageError::SwitchNotAllowed {
            switch: EFFECTIVE_FROM_REGISTRY_VERSION_SWITCH,
            command: command_name,
        });
    }
    if operator_config.is_some()
        && !escrow_publication
        && !bundle_release
        && !bundle_revoke
        && !matches!(
            command_kind,
            CommandKind::RecoveryTest
                | CommandKind::Grant
                | CommandKind::Posture
                | CommandKind::Operator
                | CommandKind::Registry
                | CommandKind::ClockRelease
                | CommandKind::WriterTransition
                | CommandKind::ReaderKeyEscrow
        )
    {
        return Err(UsageError::SwitchNotAllowed {
            switch: OPERATOR_CONFIG_SWITCH,
            command: command_name,
        });
    }
    // Grobkörnig hier (das Kommando), fein — nur `register-network-archive`
    // — im `CommandKind::Operator`-Zweig unten, dieselbe Bauart wie bei
    // `posture`s Modus-Schaltern.
    if escrow_inbox.is_some() && !escrow_publication && command_kind != CommandKind::ReaderKeyEscrow
    {
        return Err(UsageError::SwitchNotAllowed {
            switch: ESCROW_INBOX_SWITCH,
            command: command_name,
        });
    }
    if escrow_outbox.is_some() && command_kind != CommandKind::ReaderKeyEscrow {
        return Err(UsageError::SwitchNotAllowed {
            switch: ESCROW_OUTBOX_SWITCH,
            command: command_name,
        });
    }
    if archive_profile.is_some() && command_kind != CommandKind::Operator {
        return Err(UsageError::SwitchNotAllowed {
            switch: NETWORK_ARCHIVE_PROFILE_SWITCH,
            command: command_name,
        });
    }
    if release.is_some() && command_kind != CommandKind::ClockRelease && !bundle_revoke {
        return Err(UsageError::SwitchNotAllowed {
            switch: RELEASE_SWITCH,
            command: command_name,
        });
    }
    for (present, switch) in [
        (request.is_some(), REQUEST_SWITCH),
        (transition_object.is_some(), TRANSITION_OBJECT_SWITCH),
    ] {
        if present && command_kind != CommandKind::WriterTransition {
            return Err(UsageError::SwitchNotAllowed {
                switch,
                command: command_name,
            });
        }
    }
    // `--effective-from` gehoert allein `registry`; die beiden anderen
    // Fensterzahlen nimmt auch `writer-transition` — ob sein Unterkommando
    // sie nimmt, entscheidet Schritt 6.
    if effective_from.is_some() && command_kind != CommandKind::Registry {
        return Err(UsageError::SwitchNotAllowed {
            switch: EFFECTIVE_FROM_SWITCH,
            command: command_name,
        });
    }
    for (present, switch) in [
        (valid_through.is_some(), VALID_THROUGH_SWITCH),
        (not_after.is_some(), NOT_AFTER_SWITCH),
    ] {
        if present
            && !matches!(
                command_kind,
                CommandKind::Registry | CommandKind::WriterTransition
            )
        {
            return Err(UsageError::SwitchNotAllowed {
                switch,
                command: command_name,
            });
        }
    }
    if output.is_some()
        && matches!(
            command_kind,
            CommandKind::Verify
                | CommandKind::List
                | CommandKind::Organization
                | CommandKind::Operator
                | CommandKind::Registry
                | CommandKind::ClockRelease
                | CommandKind::WriterTransition
                | CommandKind::ReaderKeyEscrow
        )
    {
        return Err(UsageError::SwitchNotAllowed {
            switch: OUTPUT_SWITCH,
            command: command_name,
        });
    }
    let include_runtime_metadata = include_runtime_metadata.unwrap_or(false);
    if include_runtime_metadata && command_kind != CommandKind::Report {
        return Err(UsageError::SwitchNotAllowed {
            switch: INCLUDE_RUNTIME_METADATA_SWITCH,
            command: command_name,
        });
    }
    // Der Berichtsschluessel gehoert dem Bericht. Dass `report` ihn danach
    // VERWEIGERT, ist eine Aussage ueber die Suite und nicht ueber den Aufruf;
    // hier steht nur, an welchem Kommando er ueberhaupt etwas bedeutet.
    if report_signing_key.is_some() && command_kind != CommandKind::Report {
        return Err(UsageError::SwitchNotAllowed {
            switch: REPORT_SIGNING_KEY_SWITCH,
            command: command_name,
        });
    }

    // 5 — genau ein Positionsargument: ein Archivpfad oder ein Unterkommando.
    let mut positionals = positionals.into_iter();
    let path = positionals
        .next()
        .ok_or(UsageError::MissingPositional(command_name))?;
    if positionals.next().is_some() {
        return Err(UsageError::SurplusPositional(command_name));
    }

    // 6 — Schalter, die dieses Kommando verlangt.
    let command = match command_kind {
        CommandKind::Verify => Command::Verify { archive: path },
        CommandKind::List => Command::List { archive: path },
        CommandKind::Decrypt => Command::Decrypt {
            archive: path,
            key: key.ok_or(UsageError::MissingSwitch {
                switch: KEY_SWITCH,
                command: command_name,
            })?,
            output: output.ok_or(UsageError::MissingSwitch {
                switch: OUTPUT_SWITCH,
                command: command_name,
            })?,
        },
        // Die vier Pflichtschalter in der Reihenfolge von `design.md` §16.1,
        // damit ein Aufruf, dem mehrere fehlen, immer denselben zuerst
        // genannt bekommt.
        CommandKind::Grant => Command::Grant {
            archive: path,
            recovery_key: recovery_key.ok_or(UsageError::MissingSwitch {
                switch: RECOVERY_KEY_SWITCH,
                command: command_name,
            })?,
            authority_key: authority_key.ok_or(UsageError::MissingSwitch {
                switch: AUTHORITY_KEY_SWITCH,
                command: command_name,
            })?,
            authorization: authorization.ok_or(UsageError::MissingSwitch {
                switch: AUTHORIZATION_SWITCH,
                command: command_name,
            })?,
            operator_config,
            output,
            recipient_certificate: recipient_certificate.ok_or(UsageError::MissingSwitch {
                switch: RECIPIENT_CERT_SWITCH,
                command: command_name,
            })?,
        },
        CommandKind::Report => Command::Report {
            archive: path,
            output: output.ok_or(UsageError::MissingSwitch {
                switch: OUTPUT_SWITCH,
                command: command_name,
            })?,
        },
        CommandKind::Export => Command::Export {
            source: path,
            output: output.ok_or(UsageError::MissingSwitch {
                switch: OUTPUT_SWITCH,
                command: command_name,
            })?,
        },
        CommandKind::RecoveryTest => Command::RecoveryTest {
            runtime: recovery::build(recovery_mode, operator_config, recovery_paths)?,
            archive: path,
            key_inventory: key_inventory.ok_or(UsageError::MissingSwitch {
                switch: KEY_INVENTORY_SWITCH,
                command: command_name,
            })?,
            output: output.ok_or(UsageError::MissingSwitch {
                switch: OUTPUT_SWITCH,
                command: command_name,
            })?,
        },
        CommandKind::Organization => match path.to_str() {
            Some(ORGANIZATION_INIT_SUBCOMMAND) => {
                if initial_registry_version.is_some() {
                    return Err(UsageError::SwitchNotAllowed {
                        switch: INITIAL_REGISTRY_VERSION_SWITCH,
                        command: "organization init",
                    });
                }
                Command::OrganizationInit
            }
            Some(ORGANIZATION_CERTIFY_ROOT_SUBCOMMAND) => Command::OrganizationCertifyRoot {
                initial_registry_version: RegistryVersion::new(initial_registry_version.ok_or(
                    UsageError::MissingSwitch {
                        switch: INITIAL_REGISTRY_VERSION_SWITCH,
                        command: "organization certify-root",
                    },
                )?),
            },
            Some(ORGANIZATION_READER_KEY_ESCROW_PUBLISH_SUBCOMMAND) => {
                const COMMAND: &str = "organization reader-key-escrow-publish";
                if initial_registry_version.is_some() {
                    return Err(UsageError::SwitchNotAllowed {
                        switch: INITIAL_REGISTRY_VERSION_SWITCH,
                        command: COMMAND,
                    });
                }
                Command::OrganizationReaderKeyEscrowPublish {
                    config: operator_config.ok_or(UsageError::MissingSwitch {
                        switch: OPERATOR_CONFIG_SWITCH,
                        command: COMMAND,
                    })?,
                    inbox: escrow_inbox.ok_or(UsageError::MissingSwitch {
                        switch: ESCROW_INBOX_SWITCH,
                        command: COMMAND,
                    })?,
                }
            }
            Some(ORGANIZATION_WEB_BUNDLE_RELEASE_SUBCOMMAND) => {
                const COMMAND: &str = "organization web-bundle-release";
                if initial_registry_version.is_some() {
                    return Err(UsageError::SwitchNotAllowed {
                        switch: INITIAL_REGISTRY_VERSION_SWITCH,
                        command: COMMAND,
                    });
                }
                let bundle_version = bundle_version.ok_or(UsageError::MissingSwitch {
                    switch: BUNDLE_VERSION_SWITCH,
                    command: COMMAND,
                })?;
                Command::OrganizationWebBundleRelease {
                    config: operator_config.ok_or(UsageError::MissingSwitch {
                        switch: OPERATOR_CONFIG_SWITCH,
                        command: COMMAND,
                    })?,
                    bundle: bundle.ok_or(UsageError::MissingSwitch {
                        switch: BUNDLE_SWITCH,
                        command: COMMAND,
                    })?,
                    bundle_version: bundle_version
                        .to_str()
                        .ok_or(UsageError::MissingValue(BUNDLE_VERSION_SWITCH))?
                        .to_owned(),
                    effective_from: effective_from_registry_version.map(RegistryVersion::new),
                }
            }
            Some(ORGANIZATION_WEB_BUNDLE_REVOKE_SUBCOMMAND) => {
                const COMMAND: &str = "organization web-bundle-revoke";
                if initial_registry_version.is_some() {
                    return Err(UsageError::SwitchNotAllowed {
                        switch: INITIAL_REGISTRY_VERSION_SWITCH,
                        command: COMMAND,
                    });
                }
                Command::OrganizationWebBundleRevoke {
                    config: operator_config.ok_or(UsageError::MissingSwitch {
                        switch: OPERATOR_CONFIG_SWITCH,
                        command: COMMAND,
                    })?,
                    release: release.ok_or(UsageError::MissingSwitch {
                        switch: RELEASE_SWITCH,
                        command: COMMAND,
                    })?,
                    effective_from: effective_from_registry_version.map(RegistryVersion::new),
                }
            }
            _ => {
                return Err(UsageError::UnknownSubcommand {
                    command: command_name,
                    value: path.to_string_lossy().into_owned(),
                    expected: ORGANIZATION_SUBCOMMANDS,
                });
            }
        },
        CommandKind::Operator => {
            let action = match path.to_str() {
                Some("provision") => OperatorAction::Provision,
                Some("verify-session") => OperatorAction::VerifySession,
                Some("revoke") => OperatorAction::Revoke,
                Some("register-network-archive") => OperatorAction::RegisterNetworkArchive,
                _ => {
                    return Err(UsageError::UnknownSubcommand {
                        command: command_name,
                        value: path.to_string_lossy().into_owned(),
                        expected: "provision, verify-session, revoke or register-network-archive",
                    });
                }
            };
            // Fein: `--network-archive-profile` gehört ausschließlich diesem
            // einen Unterkommando, nicht `operator` insgesamt.
            if archive_profile.is_some() && action != OperatorAction::RegisterNetworkArchive {
                return Err(UsageError::SwitchNotAllowed {
                    switch: NETWORK_ARCHIVE_PROFILE_SWITCH,
                    command: command_name,
                });
            }
            let archive_profile = if action == OperatorAction::RegisterNetworkArchive {
                Some(archive_profile.ok_or(UsageError::MissingSwitch {
                    switch: NETWORK_ARCHIVE_PROFILE_SWITCH,
                    command: command_name,
                })?)
            } else {
                None
            };
            Command::Operator {
                action,
                config: operator_config.ok_or(UsageError::MissingSwitch {
                    switch: OPERATOR_CONFIG_SWITCH,
                    command: command_name,
                })?,
                archive_profile,
            }
        }
        CommandKind::Posture => {
            let config = operator_config.ok_or(UsageError::MissingSwitch {
                switch: OPERATOR_CONFIG_SWITCH,
                command: command_name,
            })?;
            let mode = path.to_str().unwrap_or("");
            for (present, switch, allowed) in [
                (
                    posture_target.is_some(),
                    POSTURE_TARGET_SWITCH,
                    mode == "issue",
                ),
                (
                    posture_document.is_some(),
                    POSTURE_DOCUMENT_SWITCH,
                    mode == "import",
                ),
                (
                    evidence_reference.is_some(),
                    EVIDENCE_REFERENCE_SWITCH,
                    mode == "issue",
                ),
                (valid_for_ms.is_some(), VALID_FOR_MS_SWITCH, mode == "issue"),
                (
                    output.is_some(),
                    OUTPUT_SWITCH,
                    mode == "target" || mode == "issue",
                ),
            ] {
                if present && !allowed {
                    return Err(UsageError::SwitchNotAllowed {
                        switch,
                        command: "posture",
                    });
                }
            }
            let missing = |switch| UsageError::MissingSwitch {
                switch,
                command: "posture",
            };
            let action = match mode {
                "target" => PostureAction::Target {
                    output: output.ok_or_else(|| missing(OUTPUT_SWITCH))?,
                },
                "issue" => {
                    let target = posture_target.ok_or_else(|| missing(POSTURE_TARGET_SWITCH))?;
                    let evidence_reference =
                        evidence_reference.ok_or_else(|| missing(EVIDENCE_REFERENCE_SWITCH))?;
                    let value = valid_for_ms.ok_or_else(|| missing(VALID_FOR_MS_SWITCH))?;
                    let lifetime_ms = i64::try_from(value)
                        .ok()
                        .filter(|value| (1..=86_400_000).contains(value))
                        .ok_or_else(|| UsageError::UnknownNumber {
                            switch: VALID_FOR_MS_SWITCH,
                            value: value.to_string(),
                        })?;
                    PostureAction::Issue {
                        target,
                        evidence_reference,
                        lifetime_ms,
                        output: output.ok_or_else(|| missing(OUTPUT_SWITCH))?,
                    }
                }
                "import" => PostureAction::Import {
                    document: posture_document.ok_or_else(|| missing(POSTURE_DOCUMENT_SWITCH))?,
                },
                _ => {
                    return Err(UsageError::UnknownSubcommand {
                        command: "posture",
                        value: mode.to_owned(),
                        expected: "target, issue or import",
                    });
                }
            };
            Command::Posture { action, config }
        }
        CommandKind::Registry => {
            if path != Path::new(REGISTRY_REVOCATION_PLAN_SUBCOMMAND) {
                return Err(UsageError::UnknownSubcommand {
                    command: command_name,
                    value: path.to_string_lossy().into_owned(),
                    expected: REGISTRY_REVOCATION_PLAN_SUBCOMMAND,
                });
            }
            let config = operator_config.ok_or(UsageError::MissingSwitch {
                switch: OPERATOR_CONFIG_SWITCH,
                command: command_name,
            })?;
            let effective_from = effective_from.ok_or(UsageError::MissingSwitch {
                switch: EFFECTIVE_FROM_SWITCH,
                command: command_name,
            })?;
            let valid_through = valid_through.ok_or(UsageError::MissingSwitch {
                switch: VALID_THROUGH_SWITCH,
                command: command_name,
            })?;
            let not_after = not_after.ok_or(UsageError::MissingSwitch {
                switch: NOT_AFTER_SWITCH,
                command: command_name,
            })?;
            Command::RegistryRevocationPlan {
                config,
                effective_from_sequence: ChainSequence::new(effective_from),
                valid_through_sequence: ChainSequence::new(valid_through),
                not_after: unix_millis(not_after)?,
            }
        }
        CommandKind::ClockRelease => {
            if path != Path::new(CLOCK_RELEASE_APPLY_SUBCOMMAND) {
                return Err(UsageError::UnknownSubcommand {
                    command: command_name,
                    value: path.to_string_lossy().into_owned(),
                    expected: CLOCK_RELEASE_APPLY_SUBCOMMAND,
                });
            }
            Command::ClockReleaseApply {
                config: operator_config.ok_or(UsageError::MissingSwitch {
                    switch: OPERATOR_CONFIG_SWITCH,
                    command: command_name,
                })?,
                release: release.ok_or(UsageError::MissingSwitch {
                    switch: RELEASE_SWITCH,
                    command: command_name,
                })?,
            }
        }
        CommandKind::ReaderKeyEscrow => {
            let missing = |switch| UsageError::MissingSwitch {
                switch,
                command: command_name,
            };
            let open = match path.to_str() {
                Some(READER_KEY_ESCROW_OPEN_SUBCOMMAND) => true,
                Some(READER_KEY_ESCROW_PICKUP_SUBCOMMAND) => false,
                _ => {
                    return Err(UsageError::UnknownSubcommand {
                        command: command_name,
                        value: path.to_string_lossy().into_owned(),
                        expected: READER_KEY_ESCROW_SUBCOMMANDS,
                    });
                }
            };
            // Die Abholung versiegelt nie neu und liest deshalb keinen
            // Recovery-Schlüssel.
            if !open && recovery_key.is_some() {
                return Err(UsageError::SwitchNotAllowed {
                    switch: RECOVERY_KEY_SWITCH,
                    command: "reader-key-escrow pickup",
                });
            }
            let config = operator_config.ok_or_else(|| missing(OPERATOR_CONFIG_SWITCH))?;
            let recovery_key = if open {
                Some(recovery_key.ok_or_else(|| missing(RECOVERY_KEY_SWITCH))?)
            } else {
                None
            };
            let authorization = authorization.ok_or_else(|| missing(AUTHORIZATION_SWITCH))?;
            let inbox = escrow_inbox.ok_or_else(|| missing(ESCROW_INBOX_SWITCH))?;
            let outbox = escrow_outbox.ok_or_else(|| missing(ESCROW_OUTBOX_SWITCH))?;
            match recovery_key {
                Some(recovery_key) => Command::ReaderKeyEscrowOpen {
                    config,
                    recovery_key,
                    authorization,
                    inbox,
                    outbox,
                },
                None => Command::ReaderKeyEscrowPickup {
                    config,
                    authorization,
                    inbox,
                    outbox,
                },
            }
        }
        CommandKind::WriterTransition => {
            let config = operator_config.ok_or(UsageError::MissingSwitch {
                switch: OPERATOR_CONFIG_SWITCH,
                command: command_name,
            })?;
            let request = request.ok_or(UsageError::MissingSwitch {
                switch: REQUEST_SWITCH,
                command: command_name,
            })?;
            if path == Path::new(WRITER_TRANSITION_PREPARE_SUBCOMMAND) {
                // Was nur `activate` nimmt, weist `prepare` mit seinem
                // eigenen Namen ab — dieselbe Regel wie Schritt 4, eine
                // Ebene tiefer: ein stilles Ignorieren liesse den Aufrufer
                // glauben, das Objekt sei gehalten und das Fenster geplant.
                for (present, switch) in [
                    (transition_object.is_some(), TRANSITION_OBJECT_SWITCH),
                    (valid_through.is_some(), VALID_THROUGH_SWITCH),
                    (not_after.is_some(), NOT_AFTER_SWITCH),
                ] {
                    if present {
                        return Err(UsageError::SwitchNotAllowed {
                            switch,
                            command: WRITER_TRANSITION_PREPARE_COMMAND,
                        });
                    }
                }
                Command::WriterTransitionPrepare { config, request }
            } else if path == Path::new(WRITER_TRANSITION_ACTIVATE_SUBCOMMAND) {
                let transition_object = transition_object.ok_or(UsageError::MissingSwitch {
                    switch: TRANSITION_OBJECT_SWITCH,
                    command: command_name,
                })?;
                let valid_through = valid_through.ok_or(UsageError::MissingSwitch {
                    switch: VALID_THROUGH_SWITCH,
                    command: command_name,
                })?;
                let not_after = not_after.ok_or(UsageError::MissingSwitch {
                    switch: NOT_AFTER_SWITCH,
                    command: command_name,
                })?;
                Command::WriterTransitionActivate {
                    config,
                    request,
                    transition_object,
                    valid_through_sequence: ChainSequence::new(valid_through),
                    not_after: unix_millis(not_after)?,
                }
            } else {
                return Err(UsageError::UnknownSubcommand {
                    command: command_name,
                    value: path.to_string_lossy().into_owned(),
                    expected: "prepare or activate",
                });
            }
        }
    };

    Ok(Invocation {
        anchor,
        format: format.unwrap_or(Format::Text),
        include_runtime_metadata,
        report_signing_key,
        command,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        AUTHORITY_KEY_SWITCH, AUTHORIZATION_SWITCH, CLOCK_RELEASE_APPLY_SUBCOMMAND, Command,
        EFFECTIVE_FROM_SWITCH, FORMAT_SWITCH, Format, INCLUDE_RUNTIME_METADATA_SWITCH, Invocation,
        KEY_INVENTORY_SWITCH, KEY_SWITCH, KeySourceArgument, NOT_AFTER_SWITCH,
        OPERATOR_CONFIG_SWITCH, ORGANIZATION_INIT_SUBCOMMAND, ORGANIZATION_SUBCOMMANDS,
        OUTPUT_SWITCH, RECIPIENT_CERT_SWITCH, RECOVERY_KEY_SWITCH,
        REGISTRY_REVOCATION_PLAN_SUBCOMMAND, RELEASE_SWITCH, REPORT_SIGNING_KEY_SWITCH,
        TRUST_ANCHOR_SWITCH, UsageError, VALID_THROUGH_SWITCH, parse,
    };
    use ea_recovery::{KeySourceKind, KeySourceSpec, KeySourceSpecError};
    use ea_types::{ChainSequence, UnixMillis};
    use std::{ffi::OsString, path::PathBuf};

    /// Parst eine Argumentfolge OHNE Programmnamen und ohne Prozessstart.
    fn parsed(tokens: &[&str]) -> Result<Invocation, UsageError> {
        parse(tokens.iter().copied().map(OsString::from))
    }

    /// Der Aufruffehler dieser Argumentfolge.
    fn rejected(tokens: &[&str]) -> UsageError {
        parsed(tokens).expect_err("die Argumentfolge muss abgelehnt werden")
    }

    #[test]
    fn every_command_parses_in_its_full_form() {
        assert_eq!(
            parsed(&[TRUST_ANCHOR_SWITCH, "anchor.etb", "verify", "archive"])
                .expect("verify muss parsen"),
            Invocation {
                anchor: PathBuf::from("anchor.etb"),
                format: Format::Text,
                include_runtime_metadata: false,
                report_signing_key: None,
                command: Command::Verify {
                    archive: PathBuf::from("archive")
                },
            }
        );
        assert_eq!(
            parsed(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                FORMAT_SWITCH,
                "json",
                "list",
                "archive"
            ])
            .expect("list muss parsen"),
            Invocation {
                anchor: PathBuf::from("anchor.etb"),
                format: Format::Json,
                include_runtime_metadata: false,
                report_signing_key: None,
                command: Command::List {
                    archive: PathBuf::from("archive")
                },
            }
        );
        assert_eq!(
            parsed(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "decrypt",
                "archive",
                KEY_SWITCH,
                "recipient.key",
                OUTPUT_SWITCH,
                "target"
            ])
            .expect("decrypt muss parsen"),
            Invocation {
                anchor: PathBuf::from("anchor.etb"),
                format: Format::Text,
                include_runtime_metadata: false,
                report_signing_key: None,
                command: Command::Decrypt {
                    archive: PathBuf::from("archive"),
                    key: file_key("recipient.key"),
                    output: PathBuf::from("target"),
                },
            }
        );
        assert_eq!(
            parsed(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                INCLUDE_RUNTIME_METADATA_SWITCH,
                "report",
                "archive",
                OUTPUT_SWITCH,
                "report.json"
            ])
            .expect("report muss parsen"),
            Invocation {
                anchor: PathBuf::from("anchor.etb"),
                format: Format::Text,
                include_runtime_metadata: true,
                report_signing_key: None,
                command: Command::Report {
                    archive: PathBuf::from("archive"),
                    output: PathBuf::from("report.json"),
                },
            }
        );
        assert_eq!(
            parsed(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "export",
                "archive",
                OUTPUT_SWITCH,
                "target"
            ])
            .expect("export muss parsen"),
            Invocation {
                anchor: PathBuf::from("anchor.etb"),
                format: Format::Text,
                include_runtime_metadata: false,
                report_signing_key: None,
                command: Command::Export {
                    source: PathBuf::from("archive"),
                    output: PathBuf::from("target"),
                },
            }
        );
    }

    /// `organization` traegt als Positionsargument ein WORT und keinen Pfad.
    ///
    /// Die Anzahl ist dieselbe wie bei den sieben Kommandos aus §16.1 — genau
    /// eines —, die Bedeutung nicht: hier steht das Unterkommando. Der Anker bleibt
    /// trotzdem Pflicht; was er bei diesem Kommando bedeutet, steht an
    /// [`TRUST_ANCHOR_SWITCH`].
    #[test]
    fn organization_init_parses_in_its_full_form() {
        assert_eq!(
            parsed(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "organization",
                ORGANIZATION_INIT_SUBCOMMAND
            ])
            .expect("organization init muss parsen"),
            Invocation {
                anchor: PathBuf::from("anchor.etb"),
                format: Format::Text,
                include_runtime_metadata: false,
                report_signing_key: None,
                command: Command::OrganizationInit,
            }
        );
    }

    /// Ein anderes Wort ist kein Unterkommando und wird woertlich genannt.
    #[test]
    fn an_unknown_organization_subcommand_is_rejected_verbatim() {
        assert_eq!(
            rejected(&[TRUST_ANCHOR_SWITCH, "anchor.etb", "organization", "iniit"]),
            UsageError::UnknownSubcommand {
                command: "organization",
                value: "iniit".to_owned(),
                expected: ORGANIZATION_SUBCOMMANDS,
            }
        );
    }

    /// Der Anker ist bei JEDEM Kommando Pflicht, nicht nur bei `verify`: hier
    /// die sieben Kommandos aus `design.md` §16.1 und `organization init`.
    #[test]
    fn every_command_requires_the_trust_anchor() {
        for tokens in [
            vec!["verify", "archive"],
            vec!["list", "archive"],
            vec!["decrypt", "archive", KEY_SWITCH, "k", OUTPUT_SWITCH, "t"],
            vec![
                "grant",
                "archive",
                RECOVERY_KEY_SWITCH,
                "r",
                AUTHORITY_KEY_SWITCH,
                "a",
                AUTHORIZATION_SWITCH,
                "z",
                RECIPIENT_CERT_SWITCH,
                "c",
            ],
            vec!["report", "archive", OUTPUT_SWITCH, "r.json"],
            vec!["export", "archive", OUTPUT_SWITCH, "t"],
            vec![
                "recovery-test",
                "archive",
                KEY_INVENTORY_SWITCH,
                "i",
                OUTPUT_SWITCH,
                "r.json",
            ],
            vec!["organization", ORGANIZATION_INIT_SUBCOMMAND],
        ] {
            assert_eq!(
                rejected(&tokens),
                UsageError::MissingTrustAnchor,
                "{tokens:?} darf ohne Anker nicht durchgehen"
            );
        }
    }

    #[test]
    fn an_unknown_command_is_rejected_verbatim() {
        assert_eq!(
            rejected(&[TRUST_ANCHOR_SWITCH, "anchor.etb", "veriify", "archive"]),
            UsageError::UnknownCommand("veriify".to_owned())
        );
    }

    #[test]
    fn a_missing_positional_argument_is_rejected() {
        assert_eq!(
            rejected(&[TRUST_ANCHOR_SWITCH, "anchor.etb", "verify"]),
            UsageError::MissingPositional("verify")
        );
    }

    #[test]
    fn a_surplus_positional_argument_is_rejected() {
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "verify",
                "archive",
                "second"
            ]),
            UsageError::SurplusPositional("verify")
        );
    }

    #[test]
    fn a_missing_output_is_rejected_for_every_writing_command() {
        for command in ["decrypt", "report", "export"] {
            let mut tokens = vec![TRUST_ANCHOR_SWITCH, "anchor.etb", command, "archive"];
            if command == "decrypt" {
                tokens.extend([KEY_SWITCH, "recipient.key"]);
            }
            assert_eq!(
                rejected(&tokens),
                UsageError::MissingSwitch {
                    switch: OUTPUT_SWITCH,
                    command,
                },
                "{command} darf ohne {OUTPUT_SWITCH} nicht durchgehen"
            );
        }
    }

    #[test]
    fn a_missing_key_is_rejected_for_decrypt() {
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "decrypt",
                "archive",
                OUTPUT_SWITCH,
                "target"
            ]),
            UsageError::MissingSwitch {
                switch: KEY_SWITCH,
                command: "decrypt",
            }
        );
    }

    /// `grant` ohne einen einzigen seiner vier Schalter nennt `--recovery-key`
    /// — den ERSTEN der dokumentierten Reihenfolge — und nicht irgendeinen.
    ///
    /// Die Reihenfolge ist Teil des Vertrags: wer mehrere Schalter vergessen
    /// hat, bekommt immer denselben zuerst genannt und arbeitet die
    /// Grammatikzeile von links nach rechts ab.
    #[test]
    fn a_grant_without_any_of_its_switches_names_the_recovery_key_first() {
        assert_eq!(
            rejected(&[TRUST_ANCHOR_SWITCH, "anchor.etb", "grant", "archive"]),
            UsageError::MissingSwitch {
                switch: RECOVERY_KEY_SWITCH,
                command: "grant",
            }
        );
    }

    /// Auch die `--format=json`-Form: sie ist ausdruecklich KEIN Wert, sondern
    /// ein unbekannter Schalter.
    #[test]
    fn an_unknown_format_value_is_rejected() {
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                FORMAT_SWITCH,
                "yaml",
                "verify",
                "archive"
            ]),
            UsageError::UnknownFormat("yaml".to_owned())
        );
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "--format=json",
                "verify",
                "archive"
            ]),
            UsageError::UnknownSwitch("--format=json".to_owned())
        );
    }

    /// Sowohl am Ende der Zeile als auch vor dem naechsten Schalter.
    #[test]
    fn a_switch_without_a_value_is_rejected() {
        assert_eq!(
            rejected(&[TRUST_ANCHOR_SWITCH]),
            UsageError::MissingValue(TRUST_ANCHOR_SWITCH)
        );
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "report",
                "archive",
                OUTPUT_SWITCH,
                FORMAT_SWITCH,
                "json"
            ]),
            UsageError::MissingValue(OUTPUT_SWITCH)
        );
    }

    /// Auch das Flag zaehlt: doppelt gesetzt ist doppelt gesetzt.
    #[test]
    fn a_duplicated_switch_is_rejected() {
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "one.etb",
                TRUST_ANCHOR_SWITCH,
                "two.etb",
                "verify",
                "archive"
            ]),
            UsageError::DuplicateSwitch(TRUST_ANCHOR_SWITCH)
        );
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                FORMAT_SWITCH,
                "text",
                FORMAT_SWITCH,
                "json",
                "verify",
                "archive"
            ]),
            UsageError::DuplicateSwitch(FORMAT_SWITCH)
        );
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                INCLUDE_RUNTIME_METADATA_SWITCH,
                INCLUDE_RUNTIME_METADATA_SWITCH,
                "report",
                "archive",
                OUTPUT_SWITCH,
                "report.json"
            ]),
            UsageError::DuplicateSwitch(INCLUDE_RUNTIME_METADATA_SWITCH)
        );
    }

    /// `--include-runtime-metadata` ist der EINZIGE Weg zu
    /// nichtdeterministischen Berichtsfeldern und gehoert deshalb genau einem
    /// Kommando.
    #[test]
    fn runtime_metadata_is_rejected_outside_report() {
        for command in ["verify", "list", "decrypt", "export"] {
            let mut tokens = vec![
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                INCLUDE_RUNTIME_METADATA_SWITCH,
                command,
                "archive",
            ];
            if command == "decrypt" {
                tokens.extend([KEY_SWITCH, "recipient.key"]);
            }
            if command == "decrypt" || command == "export" {
                tokens.extend([OUTPUT_SWITCH, "target"]);
            }
            assert_eq!(
                rejected(&tokens),
                UsageError::SwitchNotAllowed {
                    switch: INCLUDE_RUNTIME_METADATA_SWITCH,
                    command,
                },
                "{command} darf {INCLUDE_RUNTIME_METADATA_SWITCH} nicht annehmen"
            );
        }
    }

    /// Der Berichtsschluessel PARST — abgewiesen wird er erst im Lauf.
    ///
    /// Die Trennung ist der Gegenstand: die GRAMMATIK kennt den Schalter (sonst
    /// meldete sie „unbekannter Schalter" und verschwiege den wahren Grund),
    /// und der Kommandopfad verweigert ihn mit
    /// [`ea_recovery::ExitCode::Unsupported`] und einer benannten Begruendung.
    /// Gemessen wird jene Haelfte in `apps/cli/tests/report_signature.rs`.
    #[test]
    fn a_report_signing_key_parses_and_is_refused_only_at_run_time() {
        assert_eq!(
            parsed(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "report",
                "archive",
                OUTPUT_SWITCH,
                "report.json",
                REPORT_SIGNING_KEY_SWITCH,
                "signer.key"
            ])
            .expect("der Schalter muss PARSEN"),
            Invocation {
                anchor: PathBuf::from("anchor.etb"),
                format: Format::Text,
                include_runtime_metadata: false,
                report_signing_key: Some(PathBuf::from("signer.key")),
                command: Command::Report {
                    archive: PathBuf::from("archive"),
                    output: PathBuf::from("report.json"),
                },
            }
        );
    }

    /// Er gehoert genau EINEM Kommando — wie `--include-runtime-metadata`.
    #[test]
    fn a_report_signing_key_is_rejected_outside_report() {
        for command in ["verify", "list", "decrypt", "export"] {
            let mut tokens = vec![
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                REPORT_SIGNING_KEY_SWITCH,
                "signer.key",
                command,
                "archive",
            ];
            if command == "decrypt" {
                tokens.extend([KEY_SWITCH, "recipient.key"]);
            }
            if command == "decrypt" || command == "export" {
                tokens.extend([OUTPUT_SWITCH, "target"]);
            }
            assert_eq!(
                rejected(&tokens),
                UsageError::SwitchNotAllowed {
                    switch: REPORT_SIGNING_KEY_SWITCH,
                    command,
                },
                "{command} darf {REPORT_SIGNING_KEY_SWITCH} nicht annehmen"
            );
        }
    }

    /// Ein `--key` an einem Kommando, das nichts entschluesselt, ist ein
    /// Irrtum ueber den Lauf und wird nicht stillschweigend verworfen.
    #[test]
    fn a_switch_of_another_command_is_rejected() {
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "verify",
                "archive",
                KEY_SWITCH,
                "recipient.key"
            ]),
            UsageError::SwitchNotAllowed {
                switch: KEY_SWITCH,
                command: "verify",
            }
        );
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "list",
                "archive",
                OUTPUT_SWITCH,
                "target"
            ]),
            UsageError::SwitchNotAllowed {
                switch: OUTPUT_SWITCH,
                command: "list",
            }
        );
    }

    #[test]
    fn an_empty_argument_list_is_its_own_case() {
        assert_eq!(rejected(&[]), UsageError::NoArguments);
        assert_eq!(
            rejected(&[TRUST_ANCHOR_SWITCH, "anchor.etb"]),
            UsageError::MissingCommand
        );
    }

    /// `registry revocation-plan` traegt sein Fenster als DREI Schalter.
    ///
    /// Das Fenster ist eine Entscheidung des Betreibers und keine Ableitung:
    /// `crate::commands::registry` rechnet es nicht aus, sondern reicht die
    /// drei Zahlen an `ea_admin::RegistryWindow` durch.
    #[test]
    fn registry_revocation_plan_parses_in_its_full_form() {
        assert_eq!(
            parsed(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "registry",
                REGISTRY_REVOCATION_PLAN_SUBCOMMAND,
                OPERATOR_CONFIG_SWITCH,
                "operator.json",
                EFFECTIVE_FROM_SWITCH,
                "10",
                VALID_THROUGH_SWITCH,
                "20",
                NOT_AFTER_SWITCH,
                "1700000000000"
            ])
            .expect("registry revocation-plan muss parsen"),
            Invocation {
                anchor: PathBuf::from("anchor.etb"),
                format: Format::Text,
                include_runtime_metadata: false,
                report_signing_key: None,
                command: Command::RegistryRevocationPlan {
                    config: PathBuf::from("operator.json"),
                    effective_from_sequence: ChainSequence::new(10),
                    valid_through_sequence: ChainSequence::new(20),
                    not_after: UnixMillis::new(1_700_000_000_000),
                },
            }
        );
    }

    #[test]
    fn clock_release_apply_parses_in_its_full_form() {
        assert_eq!(
            parsed(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "clock-release",
                CLOCK_RELEASE_APPLY_SUBCOMMAND,
                OPERATOR_CONFIG_SWITCH,
                "operator.json",
                RELEASE_SWITCH,
                "release.local-audit"
            ])
            .expect("clock-release apply muss parsen"),
            Invocation {
                anchor: PathBuf::from("anchor.etb"),
                format: Format::Text,
                include_runtime_metadata: false,
                report_signing_key: None,
                command: Command::ClockReleaseApply {
                    config: PathBuf::from("operator.json"),
                    release: PathBuf::from("release.local-audit"),
                },
            }
        );
    }

    /// Die angehaengte Wertform gilt auch fuer die drei ZAHLSCHALTER.
    ///
    /// `--effective-from=10` ist keine zweite zugelassene Schreibweise,
    /// sondern ein unbekannter Schalter — dieselbe Zusage wie bei
    /// `--format=json`.
    #[test]
    fn an_attached_window_value_is_an_unknown_switch() {
        for token in [
            "--effective-from=10",
            "--valid-through=20",
            "--not-after=1700000000000",
            "--release=release.local-audit",
        ] {
            assert_eq!(
                rejected(&[
                    TRUST_ANCHOR_SWITCH,
                    "anchor.etb",
                    token,
                    "registry",
                    REGISTRY_REVOCATION_PLAN_SUBCOMMAND
                ]),
                UsageError::UnknownSwitch(token.to_owned()),
                "{token} darf nicht als Wertform durchgehen"
            );
        }
    }

    /// Auch ein Zahlschalter ohne Wert meldet SEINEN Namen.
    #[test]
    fn a_window_switch_without_a_value_is_rejected() {
        for switch in [
            EFFECTIVE_FROM_SWITCH,
            VALID_THROUGH_SWITCH,
            NOT_AFTER_SWITCH,
        ] {
            assert_eq!(
                rejected(&[
                    TRUST_ANCHOR_SWITCH,
                    "anchor.etb",
                    "registry",
                    REGISTRY_REVOCATION_PLAN_SUBCOMMAND,
                    switch,
                    FORMAT_SWITCH,
                    "text"
                ]),
                UsageError::MissingValue(switch),
                "{switch} ohne Wert muss sich selbst nennen"
            );
        }
    }

    /// Was keine nichtnegative Dezimalzahl ist, wird WOERTLICH zurueckgegeben.
    #[test]
    fn a_non_numeric_window_value_is_rejected_verbatim() {
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "registry",
                REGISTRY_REVOCATION_PLAN_SUBCOMMAND,
                EFFECTIVE_FROM_SWITCH,
                "zehn"
            ]),
            UsageError::UnknownNumber {
                switch: EFFECTIVE_FROM_SWITCH,
                value: "zehn".to_owned(),
            }
        );
    }

    /// `--not-after` ist eine Unixzeit in Millisekunden und passt in `i64`.
    ///
    /// Die Verengung steht in Schritt 6 der dokumentierten Pruefreihenfolge und
    /// damit HINTER den verlangten Schaltern; die Folge ist vollstaendig
    /// angegeben, sonst meldete der Parser zuerst den fehlenden Schalter.
    #[test]
    fn a_not_after_beyond_unix_millis_is_rejected_verbatim() {
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "registry",
                REGISTRY_REVOCATION_PLAN_SUBCOMMAND,
                OPERATOR_CONFIG_SWITCH,
                "operator.json",
                EFFECTIVE_FROM_SWITCH,
                "10",
                VALID_THROUGH_SWITCH,
                "20",
                NOT_AFTER_SWITCH,
                "18446744073709551615"
            ]),
            UsageError::UnknownNumber {
                switch: NOT_AFTER_SWITCH,
                value: "18446744073709551615".to_owned(),
            }
        );
    }

    /// Die drei Fensterschalter gehoeren GENAU `registry`.
    #[test]
    fn window_switches_are_rejected_outside_registry() {
        for switch in [
            EFFECTIVE_FROM_SWITCH,
            VALID_THROUGH_SWITCH,
            NOT_AFTER_SWITCH,
        ] {
            assert_eq!(
                rejected(&[
                    TRUST_ANCHOR_SWITCH,
                    "anchor.etb",
                    switch,
                    "10",
                    "verify",
                    "archive"
                ]),
                UsageError::SwitchNotAllowed {
                    switch,
                    command: "verify",
                },
                "verify darf {switch} nicht annehmen"
            );
        }
    }

    /// `--release` gehoert GENAU `clock-release`.
    #[test]
    fn the_release_switch_is_rejected_outside_clock_release() {
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                RELEASE_SWITCH,
                "release.local-audit",
                "registry",
                REGISTRY_REVOCATION_PLAN_SUBCOMMAND
            ]),
            UsageError::SwitchNotAllowed {
                switch: RELEASE_SWITCH,
                command: "registry",
            }
        );
    }

    /// Beide neuen Kommandos verlangen dieselbe oeffentliche Bedienerdatei
    /// wie `operator` — sie ist der einzige Weg zu Bestand und Datenbank.
    #[test]
    fn both_new_commands_require_the_operator_configuration() {
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "registry",
                REGISTRY_REVOCATION_PLAN_SUBCOMMAND,
                EFFECTIVE_FROM_SWITCH,
                "10",
                VALID_THROUGH_SWITCH,
                "20",
                NOT_AFTER_SWITCH,
                "1700000000000"
            ]),
            UsageError::MissingSwitch {
                switch: OPERATOR_CONFIG_SWITCH,
                command: "registry",
            }
        );
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "clock-release",
                CLOCK_RELEASE_APPLY_SUBCOMMAND,
                RELEASE_SWITCH,
                "release.local-audit"
            ]),
            UsageError::MissingSwitch {
                switch: OPERATOR_CONFIG_SWITCH,
                command: "clock-release",
            }
        );
    }

    /// Ohne Fenster gibt es keinen Plan: der Widerruf muss sagen, AB WANN
    /// neue Freigaben ausbleiben.
    #[test]
    fn registry_requires_its_three_window_switches() {
        for missing in [
            EFFECTIVE_FROM_SWITCH,
            VALID_THROUGH_SWITCH,
            NOT_AFTER_SWITCH,
        ] {
            let mut tokens = vec![
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "registry",
                REGISTRY_REVOCATION_PLAN_SUBCOMMAND,
                OPERATOR_CONFIG_SWITCH,
                "operator.json",
            ];
            for (switch, value) in [
                (EFFECTIVE_FROM_SWITCH, "10"),
                (VALID_THROUGH_SWITCH, "20"),
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
                    command: "registry",
                },
                "registry darf ohne {missing} nicht durchgehen"
            );
        }
    }

    /// `clock-release apply` verlangt die exakten Freigabebytes.
    #[test]
    fn clock_release_requires_its_release_file() {
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "clock-release",
                CLOCK_RELEASE_APPLY_SUBCOMMAND,
                OPERATOR_CONFIG_SWITCH,
                "operator.json"
            ]),
            UsageError::MissingSwitch {
                switch: RELEASE_SWITCH,
                command: "clock-release",
            }
        );
    }

    #[test]
    fn an_unknown_subcommand_of_the_new_commands_is_rejected_verbatim() {
        assert_eq!(
            rejected(&[TRUST_ANCHOR_SWITCH, "anchor.etb", "registry", "revoke"]),
            UsageError::UnknownSubcommand {
                command: "registry",
                value: "revoke".to_owned(),
                expected: REGISTRY_REVOCATION_PLAN_SUBCOMMAND,
            }
        );
        assert_eq!(
            rejected(&[TRUST_ANCHOR_SWITCH, "anchor.etb", "clock-release", "issue"]),
            UsageError::UnknownSubcommand {
                command: "clock-release",
                value: "issue".to_owned(),
                expected: CLOCK_RELEASE_APPLY_SUBCOMMAND,
            }
        );
    }

    /// Die Stufe-4-Form eines Schluessels als Kommandowert.
    fn file_key(path: &str) -> KeySourceArgument {
        KeySourceArgument::from(KeySourceSpec::File(PathBuf::from(path)))
    }

    /// `grant` traegt seine vier Eingaben als VIER Schalter, in der Reihenfolge
    /// von `design.md` §16.1.
    #[test]
    fn grant_parses_in_its_full_form() {
        assert_eq!(
            parsed(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "grant",
                "archive",
                RECOVERY_KEY_SWITCH,
                "recovery.key",
                AUTHORITY_KEY_SWITCH,
                "file:authority.key",
                AUTHORIZATION_SWITCH,
                "authorization.bin",
                RECIPIENT_CERT_SWITCH,
                "recipient.cert"
            ])
            .expect("grant muss parsen"),
            Invocation {
                anchor: PathBuf::from("anchor.etb"),
                format: Format::Text,
                include_runtime_metadata: false,
                report_signing_key: None,
                command: Command::Grant {
                    archive: PathBuf::from("archive"),
                    recovery_key: file_key("recovery.key"),
                    authority_key: file_key("authority.key"),
                    authorization: PathBuf::from("authorization.bin"),
                    recipient_certificate: PathBuf::from("recipient.cert"),
                    operator_config: None,
                    output: None,
                },
            }
        );
    }

    #[test]
    fn grant_accepts_native_config_and_optional_output() {
        assert!(
            parsed(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "grant",
                "archive",
                RECOVERY_KEY_SWITCH,
                "recovery.key",
                AUTHORITY_KEY_SWITCH,
                "authority.key",
                AUTHORIZATION_SWITCH,
                "authorization.eat",
                RECIPIENT_CERT_SWITCH,
                "reader.eat",
                OPERATOR_CONFIG_SWITCH,
                "operator.json",
                OUTPUT_SWITCH,
                "grants"
            ])
            .is_ok()
        );
    }

    #[test]
    fn recovery_test_parses_in_its_full_form() {
        assert_eq!(
            parsed(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "recovery-test",
                "archive",
                KEY_INVENTORY_SWITCH,
                "inventory.json",
                OUTPUT_SWITCH,
                "recovery-test.json"
            ])
            .expect("recovery-test muss parsen"),
            Invocation {
                anchor: PathBuf::from("anchor.etb"),
                format: Format::Text,
                include_runtime_metadata: false,
                report_signing_key: None,
                command: Command::RecoveryTest {
                    runtime: None,
                    archive: PathBuf::from("archive"),
                    key_inventory: PathBuf::from("inventory.json"),
                    output: PathBuf::from("recovery-test.json"),
                },
            }
        );
    }

    /// Jeder der vier `grant`-Schalter ist Pflicht und wird WOERTLICH genannt.
    #[test]
    fn grant_requires_each_of_its_four_switches() {
        let full = [
            (RECOVERY_KEY_SWITCH, "recovery.key"),
            (AUTHORITY_KEY_SWITCH, "authority.key"),
            (AUTHORIZATION_SWITCH, "authorization.bin"),
            (RECIPIENT_CERT_SWITCH, "recipient.cert"),
        ];
        for (missing, _) in full {
            let mut tokens = vec![TRUST_ANCHOR_SWITCH, "anchor.etb", "grant", "archive"];
            for (switch, value) in full {
                if switch != missing {
                    tokens.extend([switch, value]);
                }
            }
            assert_eq!(
                rejected(&tokens),
                UsageError::MissingSwitch {
                    switch: missing,
                    command: "grant",
                },
                "grant darf ohne {missing} nicht durchgehen"
            );
        }
    }

    /// `recovery-test` verlangt Inventar UND Zieldatei.
    #[test]
    fn recovery_test_requires_inventory_and_output() {
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "recovery-test",
                "archive",
                OUTPUT_SWITCH,
                "recovery-test.json"
            ]),
            UsageError::MissingSwitch {
                switch: KEY_INVENTORY_SWITCH,
                command: "recovery-test",
            }
        );
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "recovery-test",
                "archive",
                KEY_INVENTORY_SWITCH,
                "inventory.json"
            ]),
            UsageError::MissingSwitch {
                switch: OUTPUT_SWITCH,
                command: "recovery-test",
            }
        );
    }

    /// Die vier `grant`-Schalter gehoeren GENAU `grant`, `--key-inventory`
    /// genau `recovery-test` — und `--key` bleibt bei `decrypt`.
    /// Das optionale Grant-Ausgabeziel wird im positiven Grant-Test geprüft.
    #[test]
    fn the_new_switches_are_rejected_on_every_other_command() {
        for switch in [
            RECOVERY_KEY_SWITCH,
            AUTHORITY_KEY_SWITCH,
            AUTHORIZATION_SWITCH,
            RECIPIENT_CERT_SWITCH,
        ] {
            for command in ["verify", "recovery-test"] {
                assert_eq!(
                    rejected(&[
                        TRUST_ANCHOR_SWITCH,
                        "anchor.etb",
                        switch,
                        "value",
                        command,
                        "archive"
                    ]),
                    UsageError::SwitchNotAllowed { switch, command },
                    "{command} darf {switch} nicht annehmen"
                );
            }
        }
        for command in ["verify", "grant"] {
            assert_eq!(
                rejected(&[
                    TRUST_ANCHOR_SWITCH,
                    "anchor.etb",
                    KEY_INVENTORY_SWITCH,
                    "inventory.json",
                    command,
                    "archive"
                ]),
                UsageError::SwitchNotAllowed {
                    switch: KEY_INVENTORY_SWITCH,
                    command,
                },
                "{command} darf {KEY_INVENTORY_SWITCH} nicht annehmen"
            );
        }
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                KEY_SWITCH,
                "recovery.key",
                "grant",
                "archive"
            ]),
            UsageError::SwitchNotAllowed {
                switch: KEY_SWITCH,
                command: "grant",
            }
        );
    }

    /// Auch die beiden neuen Kommandos verlangen den Anker — und die Pruefung
    /// steht VOR ihren Pflichtschaltern: hier fehlt alles, gemeldet wird der
    /// Anker.
    #[test]
    fn grant_and_recovery_test_require_the_trust_anchor() {
        assert_eq!(
            rejected(&["grant", "archive"]),
            UsageError::MissingTrustAnchor
        );
        assert_eq!(
            rejected(&["recovery-test", "archive"]),
            UsageError::MissingTrustAnchor
        );
    }

    /// `--key` parst durch die Quellengrammatik: die drei Formen gehen durch,
    /// ein Grammatikfehler nennt den Schalter UND das Feld.
    #[test]
    fn a_key_source_parses_through_the_source_grammar() {
        let Ok(Invocation {
            command: Command::Decrypt { key, .. },
            ..
        }) = parsed(&[
            TRUST_ANCHOR_SWITCH,
            "anchor.etb",
            "decrypt",
            "archive",
            KEY_SWITCH,
            "file:recipient.key",
            OUTPUT_SWITCH,
            "target",
        ])
        else {
            panic!("die ausgeschriebene Dateiform muss parsen");
        };
        assert!(key == file_key("recipient.key"));

        let Ok(Invocation {
            command: Command::Decrypt { key, .. },
            ..
        }) = parsed(&[
            TRUST_ANCHOR_SWITCH,
            "anchor.etb",
            "decrypt",
            "archive",
            KEY_SWITCH,
            "container:recipient.container;passphrase-file=pass.txt",
            OUTPUT_SWITCH,
            "target",
        ])
        else {
            panic!("die Containerform muss parsen");
        };
        assert!(
            key == KeySourceArgument::from(KeySourceSpec::Container {
                path: PathBuf::from("recipient.container"),
                passphrase_file: PathBuf::from("pass.txt"),
            })
        );

        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "decrypt",
                "archive",
                KEY_SWITCH,
                "container:recipient.container",
                OUTPUT_SWITCH,
                "target"
            ]),
            UsageError::KeySource {
                switch: KEY_SWITCH,
                error: KeySourceSpecError::MissingField {
                    source: KeySourceKind::Container,
                    field: "passphrase-file=",
                },
            }
        );
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "grant",
                "archive",
                RECOVERY_KEY_SWITCH,
                "recovery.key",
                AUTHORITY_KEY_SWITCH,
                "pkcs11:module=m.so;token=t;pin-file=p",
            ]),
            UsageError::KeySource {
                switch: AUTHORITY_KEY_SWITCH,
                error: KeySourceSpecError::MissingField {
                    source: KeySourceKind::Pkcs11,
                    field: "id=",
                },
            }
        );
    }

    /// Die Anzeige einer Quellenangabe nennt die QUELLART und keinen Pfad.
    #[test]
    fn a_key_source_argument_debugs_without_its_paths() {
        let shown = format!(
            "{:?}",
            KeySourceArgument::from(KeySourceSpec::Container {
                path: PathBuf::from("/media/recovery/key.container"),
                passphrase_file: PathBuf::from("/media/recovery/pass.txt"),
            })
        );
        assert_eq!(shown, "KeySourceArgument(container)");
        assert!(!shown.contains("media"));
    }

    /// Ein Pfadwert geht unbesehen durch, ein Schaltername nicht.
    #[test]
    fn path_values_survive_non_utf8_but_switch_names_do_not() {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt as _;

            let raw = OsString::from_vec(vec![b'a', 0xff, b'r']);
            let invocation = parse(
                [
                    OsString::from(TRUST_ANCHOR_SWITCH),
                    OsString::from("anchor.etb"),
                    OsString::from("verify"),
                    raw.clone(),
                ]
                .into_iter(),
            )
            .expect("ein nicht-UTF-8-Pfad muss durchgehen");
            assert_eq!(
                invocation.command,
                Command::Verify {
                    archive: PathBuf::from(raw)
                }
            );

            let raw_switch = OsString::from_vec(vec![b'-', b'-', 0xff]);
            assert!(matches!(
                parse([raw_switch].into_iter()),
                Err(UsageError::UnknownSwitch(_))
            ));
        }
    }

    /// Die Bundle-Unterkommandos (U4): `--bundle` und `--bundle-version` nur
    /// bei der Freigabe, `--release` nur beim Widerruf, die Wirksamkeit bei
    /// beiden und sonst nirgends.
    #[test]
    fn web_bundle_commands_parse_with_their_own_switches() {
        let base = [TRUST_ANCHOR_SWITCH, "anchor.etb", "organization"];
        let with = |tail: &[&'static str]| {
            let mut tokens = base.to_vec();
            tokens.extend_from_slice(tail);
            tokens
        };
        assert_eq!(
            parsed(&with(&[
                "web-bundle-release",
                OPERATOR_CONFIG_SWITCH,
                "operator.json",
                super::BUNDLE_SWITCH,
                "bundle.bin",
                super::BUNDLE_VERSION_SWITCH,
                "2026.4.0",
            ]))
            .expect("web-bundle-release muss parsen")
            .command,
            Command::OrganizationWebBundleRelease {
                config: PathBuf::from("operator.json"),
                bundle: PathBuf::from("bundle.bin"),
                bundle_version: "2026.4.0".to_owned(),
                effective_from: None,
            }
        );
        assert_eq!(
            parsed(&with(&[
                "web-bundle-revoke",
                OPERATOR_CONFIG_SWITCH,
                "operator.json",
                RELEASE_SWITCH,
                "release.etb",
                super::EFFECTIVE_FROM_REGISTRY_VERSION_SWITCH,
                "7",
            ]))
            .expect("web-bundle-revoke muss parsen")
            .command,
            Command::OrganizationWebBundleRevoke {
                config: PathBuf::from("operator.json"),
                release: PathBuf::from("release.etb"),
                effective_from: Some(super::RegistryVersion::new(7)),
            }
        );
        assert_eq!(
            rejected(&with(&[
                "web-bundle-release",
                OPERATOR_CONFIG_SWITCH,
                "operator.json",
                super::BUNDLE_SWITCH,
                "bundle.bin",
            ])),
            UsageError::MissingSwitch {
                switch: super::BUNDLE_VERSION_SWITCH,
                command: "organization web-bundle-release",
            }
        );
        assert_eq!(
            rejected(&with(&[
                "web-bundle-revoke",
                OPERATOR_CONFIG_SWITCH,
                "operator.json",
                RELEASE_SWITCH,
                "release.etb",
                super::BUNDLE_SWITCH,
                "bundle.bin",
            ])),
            UsageError::SwitchNotAllowed {
                switch: super::BUNDLE_SWITCH,
                command: "organization",
            }
        );
        assert_eq!(
            rejected(&with(&[
                "web-bundle-release",
                OPERATOR_CONFIG_SWITCH,
                "operator.json",
                super::BUNDLE_SWITCH,
                "bundle.bin",
                super::BUNDLE_VERSION_SWITCH,
                "2026.4.0",
                RELEASE_SWITCH,
                "release.etb",
            ])),
            UsageError::SwitchNotAllowed {
                switch: RELEASE_SWITCH,
                command: "organization",
            }
        );
        assert_eq!(
            rejected(&with(&[
                "certify-root",
                super::INITIAL_REGISTRY_VERSION_SWITCH,
                "1",
                super::EFFECTIVE_FROM_REGISTRY_VERSION_SWITCH,
                "2",
            ])),
            UsageError::SwitchNotAllowed {
                switch: super::EFFECTIVE_FROM_REGISTRY_VERSION_SWITCH,
                command: "organization",
            }
        );
    }

    /// DRK-458: die drei Escrow-Kommandos, ihre Pflichtschalter und ihre
    /// Grenzen. `--escrow-outbox` gehört nur der Öffnung, der
    /// Recovery-Schlüssel nie der Abholung, Bedienerdatei und Inbox an
    /// `organization` nur der Publikation.
    #[test]
    fn reader_key_escrow_commands_parse_with_their_own_switches() {
        let open = parsed(&[
            TRUST_ANCHOR_SWITCH,
            "anchor.etb",
            "reader-key-escrow",
            "open",
            OPERATOR_CONFIG_SWITCH,
            "operator.json",
            RECOVERY_KEY_SWITCH,
            "recovery.key",
            AUTHORIZATION_SWITCH,
            "authorization.etb",
            super::ESCROW_INBOX_SWITCH,
            "inbox",
            super::ESCROW_OUTBOX_SWITCH,
            "outbox",
        ])
        .expect("reader-key-escrow open muss parsen");
        assert!(matches!(
            open.command,
            Command::ReaderKeyEscrowOpen { ref inbox, ref outbox, .. }
                if inbox == &PathBuf::from("inbox") && outbox == &PathBuf::from("outbox")
        ));
        let pickup = parsed(&[
            TRUST_ANCHOR_SWITCH,
            "anchor.etb",
            "reader-key-escrow",
            "pickup",
            OPERATOR_CONFIG_SWITCH,
            "operator.json",
            AUTHORIZATION_SWITCH,
            "authorization.etb",
            super::ESCROW_INBOX_SWITCH,
            "inbox",
            super::ESCROW_OUTBOX_SWITCH,
            "outbox",
        ])
        .expect("reader-key-escrow pickup muss parsen");
        assert!(matches!(
            pickup.command,
            Command::ReaderKeyEscrowPickup { .. }
        ));
        assert_eq!(
            parsed(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "organization",
                "reader-key-escrow-publish",
                OPERATOR_CONFIG_SWITCH,
                "operator.json",
                super::ESCROW_INBOX_SWITCH,
                "inbox",
            ])
            .expect("organization reader-key-escrow-publish muss parsen")
            .command,
            Command::OrganizationReaderKeyEscrowPublish {
                config: PathBuf::from("operator.json"),
                inbox: PathBuf::from("inbox"),
            }
        );
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "reader-key-escrow",
                "pickup",
                OPERATOR_CONFIG_SWITCH,
                "operator.json",
                RECOVERY_KEY_SWITCH,
                "recovery.key",
                AUTHORIZATION_SWITCH,
                "authorization.etb",
                super::ESCROW_INBOX_SWITCH,
                "inbox",
                super::ESCROW_OUTBOX_SWITCH,
                "outbox",
            ]),
            UsageError::SwitchNotAllowed {
                switch: RECOVERY_KEY_SWITCH,
                command: "reader-key-escrow pickup",
            }
        );
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "reader-key-escrow",
                "open",
                OPERATOR_CONFIG_SWITCH,
                "operator.json",
                AUTHORIZATION_SWITCH,
                "authorization.etb",
                super::ESCROW_INBOX_SWITCH,
                "inbox",
                super::ESCROW_OUTBOX_SWITCH,
                "outbox",
            ]),
            UsageError::MissingSwitch {
                switch: RECOVERY_KEY_SWITCH,
                command: "reader-key-escrow",
            }
        );
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "organization",
                "reader-key-escrow-publish",
                OPERATOR_CONFIG_SWITCH,
                "operator.json",
                super::ESCROW_INBOX_SWITCH,
                "inbox",
                super::ESCROW_OUTBOX_SWITCH,
                "outbox",
            ]),
            UsageError::SwitchNotAllowed {
                switch: super::ESCROW_OUTBOX_SWITCH,
                command: "organization",
            }
        );
        for subcommand in ["init", "certify-root"] {
            assert_eq!(
                rejected(&[
                    TRUST_ANCHOR_SWITCH,
                    "anchor.etb",
                    "organization",
                    subcommand,
                    OPERATOR_CONFIG_SWITCH,
                    "operator.json",
                ]),
                UsageError::SwitchNotAllowed {
                    switch: OPERATOR_CONFIG_SWITCH,
                    command: "organization",
                }
            );
        }
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "reader-key-escrow",
                "close",
            ]),
            UsageError::UnknownSubcommand {
                command: "reader-key-escrow",
                value: "close".to_owned(),
                expected: "open|pickup",
            }
        );
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                super::ESCROW_INBOX_SWITCH,
                "inbox",
                "verify",
                "archive",
            ]),
            UsageError::SwitchNotAllowed {
                switch: super::ESCROW_INBOX_SWITCH,
                command: "verify",
            }
        );
    }
}

#[cfg(test)]
mod recovery_runtime_grammar_tests {
    use super::*;
    fn invoke(extra: &[&str]) -> Result<Invocation, UsageError> {
        let mut args = vec![
            "--trust-anchor",
            "anchor.etb",
            "recovery-test",
            "archive",
            "--key-inventory",
            "inventory.json",
            "--output",
            "report.cbor",
        ];
        args.extend_from_slice(extra);
        parse(args.into_iter().map(OsString::from))
    }
    #[test]
    fn recovery_runtime_modes_require_explicit_native_and_backup_inputs() {
        assert!(
            invoke(&[
                "--recovery-mode",
                "capture",
                "--operator-config",
                "operator.json",
                "--archive-profile",
                "profile.json",
                "--snapshot",
                "snapshot.db",
                "--backup-passphrase-file",
                "backup.passphrase"
            ])
            .is_ok()
        );
        assert!(
            invoke(&[
                "--recovery-mode",
                "restore-run",
                "--operator-config",
                "operator.json",
                "--archive-profile",
                "profile.json",
                "--source-envelope",
                "source.cbor",
                "--snapshot",
                "snapshot.db",
                "--backup-passphrase-file",
                "backup.passphrase",
                "--restore-database",
                "restore.sqlite",
                "--media-sources",
                "media.json"
            ])
            .is_ok()
        );
        assert!(
            invoke(&[
                "--recovery-mode",
                "import",
                "--operator-config",
                "operator.json",
                "--archive-profile",
                "profile.json",
                "--source-envelope",
                "source.cbor",
                "--completed-report",
                "completed.cbor"
            ])
            .is_ok()
        );
        assert!(
            invoke(&[
                "--recovery-mode",
                "status",
                "--operator-config",
                "operator.json",
                "--archive-profile",
                "profile.json"
            ])
            .is_ok()
        );
        for extra in [
            vec!["--recovery-mode", "unknown"],
            vec!["--recovery-mode", "capture"],
            vec!["--snapshot", "snapshot.db"],
            vec![
                "--recovery-mode",
                "status",
                "--operator-config",
                "operator.json",
                "--archive-profile",
                "profile.json",
                "--snapshot",
                "snapshot.db",
            ],
            vec![
                "--recovery-mode",
                "restore-run",
                "--operator-config",
                "operator.json",
                "--archive-profile",
                "profile.json",
                "--source-envelope",
                "source.cbor",
                "--snapshot",
                "snapshot.db",
                "--backup-passphrase-file",
                "backup.passphrase",
                "--restore-database",
                "restore.sqlite",
            ],
            vec![
                "--recovery-mode",
                "status",
                "--operator-config",
                "operator.json",
                "--archive-profile",
                "profile.json",
                "--machine-hash",
                "11",
            ],
        ] {
            assert!(
                invoke(&extra).is_err(),
                "inconsistent recovery mode must be rejected"
            );
        }
    }
}
