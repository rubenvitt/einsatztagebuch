//! Die drei Urbilder des Archivbackendprofils.
//!
//! Drei geschlossene, deterministisch kodierte Kerne und nichts sonst:
//! `archive-backend-profile-core-v1` mit seinen fuenfzehn Positionen,
//! `archive-inventory-list-v1` und `active-profile-pointer-core-v1`. Ihre
//! Grammatik steht normativ in `schemas/archive/v1/archive-profile.cddl`, ihre
//! Hashregeln im Wire-Format-Addendum, und `ea-crypto` traegt die drei
//! domaingetrennten Digestfunktionen darueber.
//!
//! # Was hier NICHT vorkommt
//!
//! Kein Ausgabepfad, kein Hostname, kein Kontoname. Das ist keine
//! Bequemlichkeit, sondern die Zusage, die die drei Digests ueber
//! Organisationsgrenzen hinweg reproduzierbar macht: wer dieselbe
//! Profilzeile, dasselbe Protokoll und dieselben Grenzen fuehrt, errechnet
//! denselben `archiveProfileHash` — auch auf einem anderen Rechner mit einem
//! anderen Ausgabepfad. `allowed-archive-profile-hashes` im Root-signierten
//! `policy-core-v1` traegt genau diese Werte.

use core::fmt;

use minicbor::Encoder;
use unicode_normalization::{UnicodeNormalization, is_nfc};

use ea_types::{Hash32, ObjectHash};

use crate::FormatError;

/// Die Art eines Archivbackendprofils — GESCHLOSSEN, zwei Arme.
///
/// Die Diskriminanten sind die Wirewerte von `profile-kind: 0..1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum ArchiveProfileKindV1 {
    /// Ein lokaler Ausgabepfad auf einem gepinnten Dateisystem.
    LocalPath = 0,
    /// Ein kontrolliertes Netzlaufwerk mit gepinntem Protokoll, Serverprodukt,
    /// Version, Mountoptionen, Failoverkonfiguration und Capability-Testvektor.
    ControlledNetworkPath = 1,
}

impl ArchiveProfileKindV1 {
    /// Beide Arme, in Deklarationsreihenfolge.
    pub const ALL: [Self; 2] = [Self::LocalPath, Self::ControlledNetworkPath];

    /// Der Wirewert an Position zwei.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// Die dreizehn offenen Eingabefelder von `archive-backend-profile-core-v1`.
///
/// Ohne das Versionsliteral und ohne die leere Erweiterungsliste: beide
/// schreibt der Kodierer selbst, damit kein Aufrufer sie waehlen kann. Nach dem
/// Muster von [`crate::LocalAuditEventCoreFieldsV1`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveBackendProfileCoreFieldsV1 {
    pub kind: ArchiveProfileKindV1,
    /// Zeilen-ID der `support-matrix.json` der Stufe 7 — NIE ein Pfad.
    pub filesystem_row_id: String,
    pub protocol_id: String,
    pub server_product: String,
    pub server_version: String,
    /// Byteweise aufsteigend und duplikatfrei; der Konstruktor erzwingt es.
    pub mount_options: Vec<String>,
    pub failover_config_id: String,
    pub capability_test_vector_id: String,
    pub queue_max_objects: u64,
    pub queue_max_bytes: u64,
    pub resume_backoff_initial_ms: u64,
    pub resume_backoff_max_ms: u64,
    pub resume_max_attempts: u64,
}

/// Der geprueft gebaute Profilkern.
///
/// Private Felder und EIN Konstruktor: ein frei gesetztes Feld waere ein
/// Profilkern, dessen Digest niemand nachrechnen kann, weil er die
/// Nullungsregel des `localPath`-Arms verletzt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveBackendProfileCoreV1 {
    fields: ArchiveBackendProfileCoreFieldsV1,
}

impl ArchiveBackendProfileCoreV1 {
    /// Die Strukturversion an Position eins. Der Kodierer schreibt sie.
    pub const STRUCTURE_VERSION: u64 = 1;

    /// Prueft und baut den Kern.
    ///
    /// Drei Regeln, alle aus der Grammatik:
    ///
    /// 1. `mount-options` steht byteweise aufsteigend und duplikatfrei.
    /// 2. Im `localPath`-Arm sind `protocol-id`, `server-product`,
    ///    `server-version`, `failover-config-id` und `mount-options` LEER und
    ///    die fuenf Queue- und Wiederaufnahmezahlen NULL. Ohne diese Regel
    ///    truege ein lokales Profil Netzparameter, die es nicht hat, und zwei
    ///    Schreiber mit demselben Dateisystem errechneten verschiedene Hashes.
    /// 3. `filesystem-row-id` und `capability-test-vector-id` sind nichtleer:
    ///    ein Profil ohne gepinnte Dateisystemzeile und ohne Testvektor ist
    ///    genau das unprofilierte Backend, das `design.md` §11.5 fail-closed
    ///    ablehnt.
    ///
    /// # Errors
    ///
    /// [`FormatError::Unsorted`] fuer unsortierte, [`FormatError::Duplicate`]
    /// fuer doppelte Mountoptionen, sonst [`FormatError::Shape`].
    pub fn new(fields: ArchiveBackendProfileCoreFieldsV1) -> Result<Self, FormatError> {
        for pair in fields.mount_options.windows(2) {
            match pair[0].as_bytes().cmp(pair[1].as_bytes()) {
                core::cmp::Ordering::Less => {}
                core::cmp::Ordering::Equal => return Err(FormatError::Duplicate),
                core::cmp::Ordering::Greater => return Err(FormatError::Unsorted),
            }
        }
        if fields.filesystem_row_id.is_empty() || fields.capability_test_vector_id.is_empty() {
            return Err(FormatError::Shape);
        }
        if fields.kind == ArchiveProfileKindV1::LocalPath
            && (!fields.protocol_id.is_empty()
                || !fields.server_product.is_empty()
                || !fields.server_version.is_empty()
                || !fields.failover_config_id.is_empty()
                || !fields.mount_options.is_empty()
                || fields.queue_max_objects != 0
                || fields.queue_max_bytes != 0
                || fields.resume_backoff_initial_ms != 0
                || fields.resume_backoff_max_ms != 0
                || fields.resume_max_attempts != 0)
        {
            return Err(FormatError::Shape);
        }
        Ok(Self { fields })
    }

    /// Die geprueften Felder, nur lesend.
    #[must_use]
    pub const fn fields(&self) -> &ArchiveBackendProfileCoreFieldsV1 {
        &self.fields
    }

    /// Die Art dieses Profils.
    #[must_use]
    pub const fn kind(&self) -> ArchiveProfileKindV1 {
        self.fields.kind
    }
}

/// Die deterministischen `archive-backend-profile-core-v1`-Bytes.
///
/// # Errors
///
/// [`FormatError::Shape`], wenn das Kodieren nicht gelingt.
pub fn encode_archive_backend_profile_core(
    core: &ArchiveBackendProfileCoreV1,
) -> Result<Vec<u8>, FormatError> {
    let fields = &core.fields;
    let mount_option_count =
        u64::try_from(fields.mount_options.len()).map_err(|_| FormatError::Shape)?;
    let mut bytes = Vec::with_capacity(256);
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .array(15)
        .and_then(|encoder| encoder.u64(ArchiveBackendProfileCoreV1::STRUCTURE_VERSION))
        .and_then(|encoder| encoder.u8(fields.kind.code()))
        .and_then(|encoder| encoder.str(&fields.filesystem_row_id))
        .and_then(|encoder| encoder.str(&fields.protocol_id))
        .and_then(|encoder| encoder.str(&fields.server_product))
        .and_then(|encoder| encoder.str(&fields.server_version))
        .and_then(|encoder| encoder.array(mount_option_count))
        .map_err(|_| FormatError::Shape)?;
    for option in &fields.mount_options {
        encoder.str(option).map_err(|_| FormatError::Shape)?;
    }
    encoder
        .str(&fields.failover_config_id)
        .and_then(|encoder| encoder.str(&fields.capability_test_vector_id))
        .and_then(|encoder| encoder.u64(fields.queue_max_objects))
        .and_then(|encoder| encoder.u64(fields.queue_max_bytes))
        .and_then(|encoder| encoder.u64(fields.resume_backoff_initial_ms))
        .and_then(|encoder| encoder.u64(fields.resume_backoff_max_ms))
        .and_then(|encoder| encoder.u64(fields.resume_max_attempts))
        .and_then(|encoder| encoder.array(0))
        .map_err(|_| FormatError::Shape)?;
    Ok(bytes)
}

/// Ein Inventareintrag: wurzelrelativer Pfad und Inhaltshash.
///
/// `content_hash` ist [`ea_crypto::object_hash`] ueber die EXAKTEN Dateibytes,
/// fuer JEDE inventarisierte Datei — auch fuer das Formatbeiwerk, das kein
/// Exact-Object-Praefix traegt. Ohne diese Regel haetten die Schema- und
/// Berichtsbytes, die `design.md` §11.5 im Inventar verlangt, gar keine
/// Identitaet.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct ArchiveInventoryEntryV1 {
    relative_path: String,
    content_hash: ObjectHash,
}

impl ArchiveInventoryEntryV1 {
    /// Nimmt Pfad und Inhaltshash auf.
    ///
    /// Absichtlich UNGEPRUEFT: die Pfadregeln gehoeren der Liste, weil erst
    /// dort Sortierung und Duplikatfreiheit entstehen und ein einzelner
    /// Eintrag ueber sie nichts sagen kann.
    #[must_use]
    pub fn new(relative_path: &str, content_hash: ObjectHash) -> Self {
        Self {
            relative_path: relative_path.to_owned(),
            content_hash,
        }
    }

    /// Der wurzelrelative Pfad mit `/` als Trenner, UTF-8 NFC.
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    #[must_use]
    pub const fn content_hash(&self) -> ObjectHash {
        self.content_hash
    }
}

/// Das vollstaendige Objektinventar eines Bestands.
#[derive(Clone, Eq, PartialEq)]
pub struct ArchiveInventoryListV1 {
    entries: Vec<ArchiveInventoryEntryV1>,
}

impl ArchiveInventoryListV1 {
    /// Die Strukturversion an Position eins.
    pub const STRUCTURE_VERSION: u64 = 1;

    /// Sortiert, prueft und baut die Liste.
    ///
    /// Sortiert wird byteweise aufsteigend nach dem Pfad — deshalb ist die
    /// Reihenfolge der EINGABE ohne Wirkung auf die Bytes und damit auf
    /// `inventoryHash`. Abgewiesen werden ein leerer Pfad, eine absolute
    /// Wurzel, ein Rueckwaertsschritt `..`, ein Backslash, ein leeres
    /// Pfadsegment und ein Pfad, der nicht in NFC steht; und danach jeder
    /// Pfad, der zweimal vorkommt.
    ///
    /// # Errors
    ///
    /// `EA-FORMAT-INVENTORY-PATH` fuer einen unzulaessigen Pfad,
    /// `EA-FORMAT-INVENTORY-DUPLICATE` fuer einen doppelten.
    pub fn new(mut entries: Vec<ArchiveInventoryEntryV1>) -> Result<Self, FormatError> {
        for entry in &entries {
            validate_inventory_path(&entry.relative_path)?;
        }
        entries.sort_by(|left, right| {
            left.relative_path
                .as_bytes()
                .cmp(right.relative_path.as_bytes())
        });
        for pair in entries.windows(2) {
            if pair[0].relative_path == pair[1].relative_path {
                return Err(FormatError::InventoryDuplicate);
            }
        }
        Ok(Self { entries })
    }

    /// Die Eintraege, byteweise aufsteigend und duplikatfrei.
    #[must_use]
    pub fn entries(&self) -> &[ArchiveInventoryEntryV1] {
        &self.entries
    }

    /// Die Zahl der tatsaechlich getragenen Eintraege.
    ///
    /// KEIN zweites Feld: `count` an Position zwei wird aus dieser Laenge
    /// geschrieben, damit die Zahl nicht von der Liste abweichen kann.
    #[must_use]
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Der Inhaltshash zum Pfad, sofern das Inventar ihn fuehrt.
    #[must_use]
    pub fn content_hash_of(&self, relative_path: &str) -> Option<ObjectHash> {
        self.entries
            .binary_search_by(|entry| entry.relative_path.as_bytes().cmp(relative_path.as_bytes()))
            .ok()
            .map(|at| self.entries[at].content_hash)
    }
}

/// Die Pfadregeln eines Inventareintrags.
fn validate_inventory_path(path: &str) -> Result<(), FormatError> {
    if path.is_empty() || path.starts_with('/') || path.contains('\\') || !is_nfc(path) {
        return Err(FormatError::InventoryPath);
    }
    // Ein Windows-Laufwerksbuchstabe ist ebenso eine absolute Wurzel wie ein
    // fuehrender Schraegstrich; ohne diese Zeile waere `C:/…` wurzelrelativ.
    if path.len() >= 2 && path.as_bytes()[1] == b':' {
        return Err(FormatError::InventoryPath);
    }
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(FormatError::InventoryPath);
        }
    }
    // Belegt, dass `is_nfc` nicht bloss die ASCII-Faelle durchlaesst: der
    // Vergleich gegen die normalisierte Form ist dieselbe Aussage und dient
    // hier als Zweitpruefung fuer den Fall, dass `is_nfc` eine Form als
    // `Maybe` einordnet.
    if path.nfc().collect::<String>() != path {
        return Err(FormatError::InventoryPath);
    }
    Ok(())
}

/// Die deterministischen `archive-inventory-list-v1`-Bytes.
///
/// # Errors
///
/// [`FormatError::Shape`], wenn das Kodieren nicht gelingt.
pub fn encode_archive_inventory_list(
    list: &ArchiveInventoryListV1,
) -> Result<Vec<u8>, FormatError> {
    let count = u64::try_from(list.entries.len()).map_err(|_| FormatError::Shape)?;
    let head = 2_u64.checked_add(count).ok_or(FormatError::Shape)?;
    let mut bytes = Vec::with_capacity(64 + list.entries.len() * 64);
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .array(head)
        .and_then(|encoder| encoder.u64(ArchiveInventoryListV1::STRUCTURE_VERSION))
        .and_then(|encoder| encoder.u64(count))
        .map_err(|_| FormatError::Shape)?;
    for entry in &list.entries {
        encoder
            .array(2)
            .and_then(|encoder| encoder.str(&entry.relative_path))
            .and_then(|encoder| encoder.bytes(entry.content_hash.as_bytes()))
            .map_err(|_| FormatError::Shape)?;
    }
    Ok(bytes)
}

/// Der aktive Profilzeiger.
///
/// `generation` steigt je erfolgreichem Wechsel um GENAU EINS. Ein Rueckfall
/// auf ein frueheres Profil ergibt deshalb eine neue, hoehere Generation und
/// damit einen anderen `activePointerHash` — ein Wiedereinspielen eines alten
/// Zeigers ist an seinem Hash erkennbar.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ActiveProfilePointerCoreV1 {
    active_profile_hash: Hash32,
    generation: u64,
}

impl ActiveProfilePointerCoreV1 {
    /// Die Strukturversion an Position eins.
    pub const STRUCTURE_VERSION: u64 = 1;

    #[must_use]
    pub const fn new(active_profile_hash: Hash32, generation: u64) -> Self {
        Self {
            active_profile_hash,
            generation,
        }
    }

    #[must_use]
    pub const fn active_profile_hash(&self) -> Hash32 {
        self.active_profile_hash
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Die deterministischen `active-profile-pointer-core-v1`-Bytes.
///
/// # Errors
///
/// [`FormatError::Shape`], wenn das Kodieren nicht gelingt.
pub fn encode_active_profile_pointer_core(
    core: &ActiveProfilePointerCoreV1,
) -> Result<Vec<u8>, FormatError> {
    let mut bytes = Vec::with_capacity(48);
    Encoder::new(&mut bytes)
        .array(3)
        .and_then(|encoder| encoder.u64(ActiveProfilePointerCoreV1::STRUCTURE_VERSION))
        .and_then(|encoder| encoder.bytes(core.active_profile_hash.as_bytes()))
        .and_then(|encoder| encoder.u64(core.generation))
        .map_err(|_| FormatError::Shape)?;
    Ok(bytes)
}

/// Kleinbuchstaben-Hex, damit `Debug` ohne `hex`-Abhaengigkeit auskommt.
fn write_lower_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8; 32]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

impl fmt::Debug for ArchiveInventoryEntryV1 {
    /// Pfad und Inhaltshash. Beide sind STRUKTURELL — ein Layoutpfad und ein
    /// Digest —, es steht kein fachlicher Name darin.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "ArchiveInventoryEntryV1({}, ",
            self.relative_path
        )?;
        write_lower_hex(formatter, self.content_hash.as_bytes())?;
        formatter.write_str(")")
    }
}

impl fmt::Debug for ArchiveInventoryListV1 {
    /// Nennt die Zahl der Eintraege, nicht deren Inhalt: ein vollstaendiges
    /// Inventar in einer Fehlerzeile ist unlesbar.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArchiveInventoryListV1")
            .field("count", &self.entries.len())
            .finish()
    }
}

impl fmt::Debug for ActiveProfilePointerCoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ActiveProfilePointerCoreV1(")?;
        write_lower_hex(formatter, self.active_profile_hash.as_bytes())?;
        write!(formatter, ", {})", self.generation)
    }
}
