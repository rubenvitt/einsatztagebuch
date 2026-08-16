//! Verzeichnisstruktur eines Bestands nach `design.md` §11.4.
//!
//! Die Konstanten dieses Moduls bilden den Codeblock aus §11.4 eins zu eins
//! ab. `tools/xtask/tests/spec_completeness.rs` haelt beide Richtungen
//! ausfuehrbar gepinnt: jeder feste Pfad aus §11.4 steht hier, und hier steht
//! kein Pfad, den §11.4 nicht nennt.

/// Vertrauensablage des Bestands.
pub const TRUST_DIR_V1: &str = "trust/";
/// Vertrauensanker-naher Organisationsstand als Trust-Objekt.
pub const ORGANIZATION_TRUST_FILE_V1: &str = "trust/organization.etb";
/// Registrierungsereignisse der Vertrauenskette.
pub const REGISTRY_EVENTS_DIR_V1: &str = "trust/registry-events/";
/// Bindungen zwischen Bedienenden und Geraetezertifikaten.
pub const OPERATOR_BINDINGS_DIR_V1: &str = "trust/operator-bindings/";
/// Autorisierungen (Admin, Freigabe, Vernichtung).
pub const AUTHORIZATIONS_DIR_V1: &str = "trust/authorizations/";
/// Signierte Eintragspakete der Kette.
pub const ENTRIES_DIR_V1: &str = "entries/";
/// Stummel autorisiert vernichteter Eintraege.
pub const DESTROYED_ENTRIES_DIR_V1: &str = "destroyed-entries/";
/// Freigaben auf Eintraege.
pub const GRANTS_DIR_V1: &str = "grants/";
/// Serverquittungen.
pub const RECEIPTS_DIR_V1: &str = "receipts/";
/// Checkpoints und Zeitnachweise.
pub const CHECKPOINTS_DIR_V1: &str = "checkpoints/";
/// Vernichtungsvorgaenge, je Vorgang ein Unterverzeichnis.
pub const DESTRUCTIONS_DIR_V1: &str = "destructions/";
/// Unterverzeichnis eines Vernichtungsvorgangs mit den Uebergangsereignissen.
///
/// Relativ zum Vorgangsverzeichnis, weil dessen Name die Vorgangskennung
/// traegt und damit kein fester Pfad ist.
pub const DESTRUCTION_EVENTS_SUBDIR_V1: &str = "events/";
/// Unterverzeichnis eines Vernichtungsvorgangs mit den Loeschbestaetigungen.
///
/// Relativ zum Vorgangsverzeichnis, aus demselben Grund wie
/// [`DESTRUCTION_EVENTS_SUBDIR_V1`].
pub const DESTRUCTION_ATTESTATIONS_SUBDIR_V1: &str = "attestations/";
/// Formatbeiwerk. Traegt kein Exact-Object-Praefix.
pub const FORMAT_DIR_V1: &str = "format/";
/// Schemata als Beiwerk.
pub const FORMAT_SCHEMAS_DIR_V1: &str = "format/schemas/";
/// Transformationsbeschreibungen als Beiwerk.
pub const FORMAT_TRANSFORMATIONS_DIR_V1: &str = "format/transformations/";
/// Kompatibilitaetsmatrix als Beiwerk.
pub const COMPATIBILITY_MATRIX_FILE_V1: &str = "format/compatibility-matrix.json";
/// Wiederherstellungsberichte als Beiwerk.
pub const RECOVERY_REPORTS_DIR_V1: &str = "recovery-reports/";
/// Formatbeschreibung fuer Menschen als Beiwerk.
pub const README_FORMAT_FILE_V1: &str = "README-FORMAT.txt";

/// Alle festen Layoutpfade aus `design.md` §11.4.
///
/// Diese Pfade sind Hinweise fuer Erzeuger, niemals Klassifikationsgrundlage.
/// Die Inventarisierung entscheidet ausschliesslich am 9-Byte-Exact-Object-
/// Praefix, nie am Dateinamen und nie am Verzeichnis. Ein gueltiges Objekt
/// unter [`README_FORMAT_FILE_V1`] ist ein Archivobjekt; eine Textdatei unter
/// [`ENTRIES_DIR_V1`] ist keines. Die Klasse ist damit nicht durch Umbenennen
/// waehlbar. Diese Liste dient dem Erzeugen und dem Pruefen gegen §11.4, nicht
/// dem Verifizieren.
pub const LAYOUT_PATHS_V1: [&str; 19] = [
    TRUST_DIR_V1,
    ORGANIZATION_TRUST_FILE_V1,
    REGISTRY_EVENTS_DIR_V1,
    OPERATOR_BINDINGS_DIR_V1,
    AUTHORIZATIONS_DIR_V1,
    ENTRIES_DIR_V1,
    DESTROYED_ENTRIES_DIR_V1,
    GRANTS_DIR_V1,
    RECEIPTS_DIR_V1,
    CHECKPOINTS_DIR_V1,
    DESTRUCTIONS_DIR_V1,
    DESTRUCTION_EVENTS_SUBDIR_V1,
    DESTRUCTION_ATTESTATIONS_SUBDIR_V1,
    FORMAT_DIR_V1,
    FORMAT_SCHEMAS_DIR_V1,
    FORMAT_TRANSFORMATIONS_DIR_V1,
    COMPATIBILITY_MATRIX_FILE_V1,
    RECOVERY_REPORTS_DIR_V1,
    README_FORMAT_FILE_V1,
];

/// Obergrenze fuer die Zahl der Bytesequenzen eines Bestands.
///
/// Der Bestand ist eine Obermenge der Vertrauensablage. Die Schranke darf
/// `ea_trust::MAX_TRUST_OBJECTS_V1` deshalb nicht unterschreiten, sonst wiese
/// sie einen Bestand ab, dessen Trust-Teilmenge fuer sich zulaessig ist.
pub const MAX_ARCHIVE_BLOBS_V1: usize = 1_048_576;

/// Obergrenze fuer die Gesamtbytezahl eines Bestands.
///
/// Aus demselben Grund wie [`MAX_ARCHIVE_BLOBS_V1`] nicht kleiner als
/// `ea_trust::MAX_TOTAL_TRUST_OBJECT_BYTES_V1`.
///
/// Nach oben begrenzt `wasm32-unknown-unknown`: dort ist `usize` 32 Bit breit.
/// Der Wert muss deshalb in `u32` passen, und zwar mit Abstand, damit das
/// Aufsummieren beim Inventarisieren nicht schon vor dem Erreichen der
/// Schranke ueberlaeuft. 2 GiB lassen die volle obere Haelfte des
/// Wertebereichs frei.
pub const MAX_TOTAL_ARCHIVE_BYTES_V1: usize = 2_147_483_648;
