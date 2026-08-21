//! Die Fixture der Stufe-2-Abnahme.
//!
//! Drei Zusagen tragen dieses Modul:
//!
//! 1. **Kein zweiter Baukasten.** Registrierungslinie, Bedienerbindung,
//!    Schluesselspeicher, Entwurfsablage und Bestand kommen unveraendert aus
//!    den `#[path]`-eingebundenen Supportmodulen von `ea-writer`, `ea-draft`
//!    und `ea-archive-fs` — dasselbe Muster, mit dem
//!    `tests/ea-system-tests/tests/task8_trust_time.rs` die Vertrauensfixture
//!    einbindet. Ein zweiter Aufbau derselben Linie waere eine zweite Wahrheit,
//!    und eine von beiden waere zufaellig die falsche.
//! 2. **Jeder Test serialisiert sich selbst.** Jede eingebundene Fixture haelt
//!    ihre eigene prozessweite Sperre und ihre eigene Temporaerwurzel je Test.
//!    Kein Kommando dieses Tasks traegt `-- --test-threads=1`, weil
//!    `cargo test --workspace --all-targets --locked` dieselben Binaries
//!    unmittelbar danach parallel faehrt.
//! 3. **Was hier NEU ist, ist die Zusammensetzung.** Die crateweisen Tests
//!    messen ihre Invariante je Crate; dieses Modul setzt Writer, Entwurf,
//!    Bestand, Gesundheitscheck und Verifikation in EINEN Prozess und misst,
//!    was keine einzelne Crate messen kann: dass nach jedem Abbruchpunkt jedes
//!    VEROEFFENTLICHTE Archivobjekt vollstaendig ist.
//!
//! # Die zwei Modulausnahmen
//!
//! `#[path]`-Includes werden je Testtarget uebersetzt; daher
//! `allow(dead_code)` auf Modulebene, genau wie in den eingebundenen Modulen.
//!
//! `allow(clippy::duplicate_mod)` kommt dazu, weil dieses Modul DREI Fixtures
//! einbindet und alle drei ihrerseits `crates/ea-trust/tests/support/mod.rs`
//! einbinden. Die Alternative waere, die Vertrauensfixture hier ein zweites Mal
//! nachzubauen — genau die zweite Wahrheit, die Zusage 1 ausschliesst. Die
//! Kopien sind getrennte Module und werden nie gemischt: jede Harness benutzt
//! ausschliesslich die Linie ihres eigenen Fixtures.
#![allow(dead_code, clippy::duplicate_mod)]

#[path = "../../../../crates/ea-archive-fs/tests/support/mod.rs"]
pub mod archive_support;
#[path = "../../../../crates/ea-draft/tests/support/mod.rs"]
pub mod draft_support;
#[path = "../../../../crates/ea-writer/tests/support/mod.rs"]
pub mod writer_support;

use std::{fs, path::Path};

use ea_archive::STAGING_SUFFIX_V1;
use ea_archive_fs::{ArchiveHealthCheckV1, ArchiveHealthReport, FreeSpaceV1, LocalPathBackend};
use ea_operator::ReauthPurpose;
use ea_schema::{
    ExternalOrganizationV1, KeywordV1, LocationV1, NativeSourceV1, OccurredAtV1, PatientCount,
    PersonnelSnapshotV1, StructuredAddressV1, VehicleSnapshotV1,
};
use ea_types::{EntryHash, UnixMillis};
use ea_writer::{
    FinalizationFaultPoint, FinalizationInputV1, ReachedState, RecoveryOutcome, WriterError,
};

use writer_support::WriterHarness;

/// Wie das Medium einen dauerhaften Schreibvorgang verweigert.
///
/// # Was hier reproduziert wird, und was NICHT
///
/// Reproduziert wird die AUSSAGE „das Medium nimmt die Bytes nicht an", und zwar
/// an zwei verschiedenen Stellen des Bestands. NICHT reproduziert wird die
/// `errno`: `ENOSPC` liesse sich portabel nur ueber ein eigenes Dateisystem
/// oder ueber `setrlimit` herstellen, und beides steht diesem Workspace nicht
/// zur Verfuegung (`#![forbid(unsafe_code)]`, keine `libc`-Kante). Fuer die
/// Zusage, um die es geht — ein Archivobjekt existiert mit ALLEN seinen Bytes
/// oder gar nicht —, ist die `errno` ohne Belang; die verweigerte Adresse ist
/// es nicht, und die unterscheiden die beiden Varianten.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediumFailure {
    /// Der Traeger ist voll: die zwei VEROEFFENTLICHUNGSverzeichnisse nehmen
    /// nichts mehr an, waehrend die Wurzel weiter beschreibbar bleibt. Genau
    /// das Fenster, in dem ein halb geschriebener Bestand entstehen wuerde.
    NoSpaceLeft,
    /// Der Traeger ist nur lesend eingehaengt: kein VERZEICHNIS UNTERHALB der
    /// Bestandswurzel nimmt noch etwas an.
    ///
    /// Die Wurzel selbst bleibt beschreibbar, und das ist gemessen und nicht
    /// abgesprochen: die Schreibersperre ist eine Datei IN der Wurzel
    /// (`ea_archive::CONTROL_FILES_V1[0]`, angelegt mit `create_new`). Eine
    /// nur lesende Wurzel weist damit schon `acquire_writer_lock` mit
    /// [`ea_archive::ArchiveBackendError::AlreadyLocked`] ab — VOR dem ersten
    /// dauerhaften Schritt. Die Verweigerung waere dann eine Aussage ueber die
    /// Sperrdatei und keine ueber das Medium, und genau diese Leere soll dieser
    /// Test nicht haben.
    ReadOnlyMount,
}

/// Der Zustand, in den ein Neustart nach einem Abbruch der Finalisierung
/// fuehrt.
///
/// GENAU drei Arme, und alle drei sind von `ea-writer` her belegt:
/// [`RecoveryOutcome::is_original_draft`], die Vollendung aus den vorbereiteten
/// Bytes, und der EINE benannte Sonderfall
/// [`FinalizationFaultPoint::BackupRestoreAfterKeyDeletion`], an dem die
/// zurueckgespielten Datenbankdateien die Abschlussmarke mitnehmen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatrixOutcome {
    /// Der Entwurf steht unveraendert und die Sequenz ist unverbraucht.
    DraftUnchanged,
    /// Dieselbe vorbereitete Transaktion ist vollendet.
    Committed,
    /// Die Sicherung hat die vorbereiteten Bytes mitgenommen: kein halber
    /// Zustand, aber auch keine Vollendung.
    BackupTookThePreparedBytes,
}

/// Die Fixture der Stufe-2-Fehlermatrix.
pub struct WriterMatrixHarness {
    inner: WriterHarness,
    notes_before: String,
}

impl WriterMatrixHarness {
    /// Eine Fixture mit gefuelltem Entwurf und leerem Bestand.
    #[must_use]
    pub fn with_incident() -> Self {
        let inner = WriterHarness::with_incident();
        let notes_before = inner
            .repository()
            .load_or_create()
            .expect("der Entwurf der Fixture muss lesbar sein")
            .notes()
            .to_owned();
        assert!(
            !notes_before.is_empty(),
            "die Fixture MUSS einen Entwurf MIT Inhalt saeen, sonst ist die \
             Unveraendertheitszusicherung leer"
        );
        Self {
            inner,
            notes_before,
        }
    }

    #[must_use]
    pub const fn inner(&self) -> &WriterHarness {
        &self.inner
    }

    /// Der Entwurfsinhalt VOR dem Abbruch.
    #[must_use]
    pub fn notes_before(&self) -> &str {
        &self.notes_before
    }

    /// Bricht eine Finalisierung an GENAU `point` ab und liefert die exakten
    /// Bytes der Abschlussmarke, sofern eine liegt.
    ///
    /// Die Marke wird HIER genommen und nicht in einem eigenen Vorlauf: eine
    /// zweite Finalisierung desselben Einsatzes stritte um Sequenz und
    /// Einsatznummer, und die verglichenen Bytes waeren die einer anderen
    /// Transaktion.
    pub fn interrupt_at(&mut self, point: FinalizationFaultPoint) -> Option<Vec<u8>> {
        let reached = self.inner.finalize_with_fault(point);
        Self::prepared_bytes_of(point, reached.as_ref())
    }

    fn prepared_bytes_of(
        point: FinalizationFaultPoint,
        reached: Result<&ReachedState, &WriterError>,
    ) -> Option<Vec<u8>> {
        let reached = reached.unwrap_or_else(|error| {
            panic!("{point:?} muss erreichbar sein: {error:?}");
        });
        assert!(
            reached.reached_step().is_some(),
            "{point:?}: der Lauf hat keinen einzigen Schritt ausgefuehrt"
        );
        reached
            .prepared()
            .map(|prepared| prepared.exact_bytes().to_vec())
    }

    /// Oeffnet aus der Ablage neu und laeuft den Wiederaufnahmepfad.
    pub fn restart_from_disk(&mut self) -> MatrixOutcome {
        let source = self.inner.source();
        let service = self.inner.service(&source);
        let outcome = service
            .recover_pending()
            .expect("die Wiederaufnahme muss tragen");
        // Ein ZWEITES recover ist ein no-op — eine GLEICHHEIT und keine
        // Beschreibung.
        assert_eq!(
            service
                .recover_pending()
                .expect("das zweite recover muss tragen"),
            RecoveryOutcome::NothingPending,
            "ein zweites recover ist ein no-op"
        );
        match outcome {
            RecoveryOutcome::CommittedFromPreparedBytes { .. } => MatrixOutcome::Committed,
            // `NothingPending` heisst „der Entwurf steht unveraendert" —
            // AUSSER, wenn er gar nicht mehr da ist. Genau das ist der
            // Zustand nach einer Rueckspielung: die Datenbankdateien sind
            // zurueck, der geraetegebundene Schluessel nicht, und der
            // Entwurf laesst sich nicht mehr oeffnen. Der Ausgang allein
            // trennt die beiden nicht, also wird HIER zusaetzlich die
            // Ablage gelesen.
            RecoveryOutcome::NothingPending if self.draft_notes().is_none() => {
                MatrixOutcome::BackupTookThePreparedBytes
            }
            other => {
                assert!(
                    other.is_original_draft(),
                    "unerwarteter Wiederaufnahmeausgang: {other:?}"
                );
                MatrixOutcome::DraftUnchanged
            }
        }
    }

    /// Der Entwurfsinhalt, wie er jetzt in der Ablage steht.
    #[must_use]
    pub fn draft_notes(&self) -> Option<String> {
        self.inner
            .repository()
            .load_or_create()
            .ok()
            .map(|draft| draft.notes().to_owned())
    }

    /// Ob KEIN Eintrag im Bestand veroeffentlicht ist.
    #[must_use]
    pub fn archive_has_no_entry(&self) -> bool {
        self.inner.published_entry_paths().is_empty()
    }

    /// Ob der `draftDEK` DIESES Einsatzes fort ist.
    ///
    /// Gemessen wird der ENTWURF und nicht die blosse Anwesenheit EINES
    /// Schluessels: Schritt 13 oeffnet einen leeren Entwurf mit FRISCHEM
    /// `draftDEK`, und der ist die Nachbedingung und nicht der Verstoss.
    #[must_use]
    pub fn draft_key_is_gone(&self) -> bool {
        self.inner.draft_is_blank() || !self.inner.draft_dek_is_present()
    }

    /// Die exakten Bytes des veroeffentlichten Eintrags, falls einer liegt.
    #[must_use]
    pub fn committed_entry_bytes(&self) -> Option<Vec<u8>> {
        let paths = self.inner.published_entry_paths();
        let path = paths.first()?;
        self.inner.backend().read_for_test(path)
    }

    /// Die exakten Bytes JEDES veroeffentlichten Grants, in Inventarordnung.
    #[must_use]
    pub fn committed_grant_bytes(&self) -> Vec<(String, Vec<u8>)> {
        self.inner
            .published_grant_paths()
            .into_iter()
            .filter_map(|path| {
                self.inner
                    .backend()
                    .read_for_test(&path)
                    .map(|bytes| (path, bytes))
            })
            .collect()
    }

    /// Der Wiederaufnahmepfad AUS DER ABLAGE, mit seinem Ergebnis.
    ///
    /// Anders als [`Self::restart_from_disk`] bricht er nicht ab: hinter der
    /// unwiderruflichen Grenze ist die Wiederaufnahme der EINZIGE Weg, auf dem
    /// noch Bytes in den Bestand gehen (`WriterService::recover_pending` ruft
    /// denselben `publish_from_prepared`-Pfad wie der glatte Lauf), und ein
    /// verweigerndes Medium MUSS dort als Fehler sichtbar werden.
    pub fn resume_pending(&self) -> Result<RecoveryOutcome, WriterError> {
        let source = self.inner.source();
        let service = self.inner.service(&source);
        service.recover_pending()
    }

    /// Ob JEDES veroeffentlichte Archivobjekt vollstaendig ist.
    ///
    /// Das ist die Zusage „ein Archivobjekt existiert mit allen seinen Bytes
    /// oder gar nicht", und sie ist FALSIFIZIERBAR: abgeschnittene Bytes
    /// behalten ihr Exact-Object-Praefix, bleiben also ein Archivobjekt, und
    /// `decode_exact_object` scheitert dahinter (dieselbe Mechanik, die
    /// `crates/ea-archive-fs/tests/bundle_export.rs::export_refuses_an_archive_that_does_not_fully_verify`
    /// benutzt). Staging-Adressen sind ausgenommen: sie tragen den Suffix
    /// `.staging`, sind nicht veroeffentlicht und gehoeren dem Bestand nicht.
    pub fn every_published_object_is_complete(&self) -> Result<(), String> {
        published_objects_are_complete(self.inner.backend())
    }

    /// Verweigert das Medium ab jetzt an den Adressen, die `failure` benennt.
    ///
    /// Liefert eine Probe, die belegt, dass die Verweigerung WIRKLICH greift:
    /// ohne sie waere jede folgende Zusicherung auch gruen, wenn das `chmod`
    /// nichts bewirkt haette.
    pub fn fail_the_medium(&self, failure: MediumFailure) {
        let root = self.inner.backend().root().to_owned();
        // Die zwei VEROEFFENTLICHUNGSverzeichnisse werden angelegt, wenn sie
        // noch fehlen: `LocalPathBackend` legt sie erst beim ersten
        // Create-if-absent an, und vor dem ersten Staging gibt es sie nicht.
        // Ohne diesen Schritt griffe BEIDE Verweigerungen an einem Punkt vor
        // dem Staging ins Leere — die Adresse, die verweigern soll, existierte
        // nicht, und der Lauf legte sie selbst an. Ein LEERES Verzeichnis ist
        // kein Archivobjekt und steht in keinem Inventar, veraendert also den
        // Bestand nicht.
        let publication = vec![
            root.join(ea_archive::ENTRIES_DIR_V1.trim_end_matches('/')),
            root.join(ea_archive::GRANTS_DIR_V1.trim_end_matches('/')),
        ];
        for directory in &publication {
            fs::create_dir_all(directory).expect("die Adresse muss anlegbar sein");
        }
        let directories = match failure {
            MediumFailure::NoSpaceLeft => publication,
            MediumFailure::ReadOnlyMount => every_directory_under(&root)
                .into_iter()
                .filter(|directory| directory != &root)
                .collect(),
        };
        for directory in &directories {
            if directory.is_dir() {
                set_read_only(directory);
            }
        }
        // POSITIVKONTROLLE. Sie steht HIER und nicht im Test, weil sie zur
        // Injektion gehoert: ein `chmod`, das nicht beisst, macht jede folgende
        // Zusicherung leer.
        let probed = directories
            .iter()
            .filter(|directory| directory.is_dir())
            .map(|directory| fs::write(directory.join("ea-probe.tmp"), b"probe"))
            .collect::<Vec<_>>();
        assert!(
            !probed.is_empty(),
            "{failure:?}: kein einziges Verzeichnis wurde erreicht"
        );
        assert!(
            probed.iter().all(std::result::Result::is_err),
            "{failure:?}: das Medium nimmt weiterhin Bytes an, die Injektion greift nicht"
        );
    }

    /// Nimmt die Verweigerung zurueck — der Neustart nach dem Medienfehler.
    pub fn heal_the_medium(&self) {
        for directory in every_directory_under(self.inner.backend().root()) {
            set_writable(&directory);
        }
    }

    /// Eine Finalisierung auf dem glatten Pfad, ohne Abbruchpunkt.
    pub fn finalize(&self) -> Result<ea_writer::FinalizeOutcome, WriterError> {
        let source = self.inner.source();
        let service = self.inner.service(&source);
        let proof = self.inner.proof_for(ReauthPurpose::Finalize);
        let preview = service.preview(
            &proof,
            writer_support::valid_incident(),
            self.inner.observed_now(),
        )?;
        service.finalize(
            &proof,
            writer_support::valid_incident(),
            &preview,
            self.inner.observed_now(),
        )
    }

    /// Die Bytekarte des Bestands: jede relative Adresse auf den Hash ihrer
    /// Bytes.
    ///
    /// Sie ist der Zeuge dafuer, dass ein FEHLGESCHLAGENER Schreibvorgang den
    /// Bestand nicht angetastet hat. Ohne sie waere die Medienpruefung fuer die
    /// Punkte hinter der Grenze leer: dort weist eine zweite Finalisierung schon
    /// wegen der verbrauchten Sequenz ab, und `is_err()` allein sagte dann
    /// nichts ueber das Medium.
    #[must_use]
    pub fn archive_digest_map(&self) -> std::collections::BTreeMap<String, String> {
        every_file_under(self.inner.backend().root())
            .into_iter()
            .map(|(relative, bytes)| {
                (
                    relative,
                    hex::encode(ea_crypto::object_hash(&bytes).as_bytes()),
                )
            })
            .collect()
    }

    /// Das Inventar des Bestands, wie es JETZT dasteht.
    #[must_use]
    pub fn inventory(&self) -> ea_format::ArchiveInventoryListV1 {
        self.inner
            .backend()
            .inventory()
            .expect("das Inventar muss entstehen")
    }

    /// Der Gesundheitsbericht gegen ein ERWARTETES Inventar.
    ///
    /// Das erwartete Inventar kommt von AUSSEN und wird nicht hier gebildet:
    /// aus den tatsaechlichen Bytes gebildet, koennten
    /// [`ea_archive_fs::HealthFinding::MissingFile`] und
    /// [`ea_archive_fs::HealthFinding::ModifiedFile`] nie feuern, und die
    /// Zusicherung waere leer.
    #[must_use]
    pub fn health_against(
        &self,
        expected: &ea_format::ArchiveInventoryListV1,
    ) -> ArchiveHealthReport {
        let backend = self.inner.backend();
        let capabilities = backend
            .run_capability_test(&archive_support::capability_test_vector())
            .expect("der Capability-Test muss laufen");
        let verification = ea_verify::verify_archive(
            &backend.as_archive_source(),
            &self.inner.anchor(),
            ea_verify::VerifyOptions::new(self.inner.observed_now()),
        )
        .expect("der Verifikationslauf muss ein Ergebnis liefern");
        ArchiveHealthCheckV1::new(
            backend,
            expected,
            FreeSpaceV1 {
                required_bytes: 1_024,
                available_bytes: 1_048_576,
            },
            &capabilities,
            &verification,
        )
        .run()
        .expect("der Gesundheitscheck muss laufen")
    }
}

/// Ob jedes veroeffentlichte Archivobjekt von `backend` vollstaendig ist.
pub fn published_objects_are_complete(backend: &LocalPathBackend) -> Result<(), String> {
    for directory in [ea_archive::ENTRIES_DIR_V1, ea_archive::GRANTS_DIR_V1] {
        for relative in backend.relative_paths_below_for_test(directory) {
            if relative.ends_with(STAGING_SUFFIX_V1) {
                continue;
            }
            let bytes = backend
                .read_for_test(&relative)
                .ok_or_else(|| format!("{relative} ist inventarisiert und nicht lesbar"))?;
            let parsed = ea_format::decode_exact_object(&bytes)
                .map_err(|error| format!("{relative} ist kein vollstaendiges Objekt: {error:?}"))?;
            let fits = matches!(
                (directory, &parsed),
                (
                    ea_archive::ENTRIES_DIR_V1,
                    ea_format::ParsedArchiveObject::Entry(_)
                ) | (
                    ea_archive::GRANTS_DIR_V1,
                    ea_format::ParsedArchiveObject::Grant(_)
                )
            );
            if !fits {
                return Err(format!(
                    "{relative} traegt {parsed:?} und nicht seine Objektart"
                ));
            }
        }
    }
    Ok(())
}

/// Wie oft `needle` in `haystack` steht.
///
/// Der Zaehler traegt die Byteidentitaetszusicherung: die Abschlussmarke traegt
/// GENAU die veroeffentlichten Objekte, und ein zweites `.eip` oder ein
/// fehlender Grant faellt hier auf.
#[must_use]
pub fn occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|w| *w == needle)
        .count()
}

/// Die EINE Stelle, an der `needle` in `haystack` steht.
///
/// [`None`], wenn es keine oder mehr als eine gibt: eine Enthaltenseinspruefung
/// sagt nicht, dass die Bytes GENAU EINMAL und an einer bestimmten Stelle
/// stehen, und die Byteidentitaet hinter der Grenze ist genau diese Aussage.
#[must_use]
pub fn single_offset(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let mut found = None;
    for (offset, window) in haystack.windows(needle.len()).enumerate() {
        if window == needle {
            if found.is_some() {
                return None;
            }
            found = Some(offset);
        }
    }
    found
}

/// Jedes Verzeichnis unter `root`, `root` selbst eingeschlossen.
#[must_use]
pub fn every_directory_under(root: &Path) -> Vec<std::path::PathBuf> {
    let mut found = vec![root.to_owned()];
    let mut index = 0;
    while index < found.len() {
        let current = found[index].clone();
        index += 1;
        let Ok(entries) = fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                found.push(entry.path());
            }
        }
    }
    found
}

/// Jede Datei unter `root`, als Paar aus relativem Pfad und Bytes.
#[must_use]
pub fn every_file_under(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_owned()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(bytes) = fs::read(&path) {
                let relative = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .into_owned();
                found.push((relative, bytes));
            }
        }
    }
    found.sort_by(|left, right| left.0.cmp(&right.0));
    found
}

/// Jeder Datei- UND Verzeichnisname unter `root`, als ein Bytestrom.
#[must_use]
pub fn every_path_name_under(root: &Path) -> Vec<u8> {
    let mut names = Vec::new();
    let mut stack = vec![root.to_owned()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            names.extend_from_slice(path.to_string_lossy().as_bytes());
            names.push(b'\n');
            if path.is_dir() {
                stack.push(path);
            }
        }
    }
    names
}

/// Der Modus, mit dem ein Verzeichnis nichts mehr annimmt: lesen und betreten,
/// nicht schreiben.
const READ_ONLY_DIRECTORY_MODE: u32 = 0o555;

/// Der Modus, mit dem es wieder annimmt.
const WRITABLE_DIRECTORY_MODE: u32 = 0o755;

/// Setzt den Modus EXPLIZIT und nicht ueber `Permissions::set_readonly`:
/// `set_readonly(false)` machte die Adresse weltschreibbar, und clippy weist es
/// zu Recht ab.
fn set_directory_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;

    let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
}

fn set_read_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(READ_ONLY_DIRECTORY_MODE))
        .expect("die Rechte muessen setzbar sein");
}

fn set_writable(path: &Path) {
    set_directory_mode(path, WRITABLE_DIRECTORY_MODE);
}

// ---------------------------------------------------------------------------
// Die Kanarienvoegel.
// ---------------------------------------------------------------------------

/// Der Kanarienvogel je fachlichem Feld — EIN eigener Marker pro Feld.
///
/// Die Namen sind die der Felder von [`FinalizationInputV1`] plus der
/// Entwurfsfreitext. Ein gemeinsamer Marker fuer zwei Felder liesse offen,
/// welches von beiden geleckt hat.
/// `patient_count` traegt AUSDRUECKLICH keinen Marker: der Typ ist
/// `PatientCount::Known(u32) | PatientCount::Unknown`
/// (`crates/ea-schema/src/model.rs:238-241`) und fuehrt keinen Bedienertext.
/// Ein Marker dafuer waere nicht konstruierbar, und eine kleine Zahl als Marker
/// waere in jedem Bytestrom zufaellig zu finden — eine Zusicherung, die nie
/// fehlschlagen KANN, ist ein Defekt.
pub const CANARY_MARKERS: [(&str, &str); 9] = [
    ("keyword", "KANARIE-STICHWORT-7f3a"),
    ("location", "KANARIE-ORT-1c8d"),
    ("personnel", "KANARIE-PERSONAL-4b21"),
    ("vehicles", "KANARIE-FAHRZEUG-9e05"),
    ("external_organizations", "KANARIE-FREMDORG-2d77"),
    ("human_incident_number", "2026-000777"),
    ("notes", "KANARIE-FREITEXT-b512"),
    ("personnel_empty_reason", "KANARIE-GRUND-PERSONAL-3f60"),
    ("vehicles_empty_reason", "KANARIE-GRUND-FAHRZEUG-8c1e"),
];

/// Welche Auspraegung des Einsatzes eine Kanarienfixture traegt.
///
/// ZWEI und nicht eine, und der Grund ist eine GESCHLOSSENE Stufe-1-Regel:
/// `ea-schema` weist eine nichtleere Liste MIT Leergrund ab
/// (`EA-SCHEMA-LIST-REASON`, gemessen). Ein einziger Einsatz kann deshalb nicht
/// gleichzeitig Personal- und Fahrzeugzeilen UND die beiden Leergruende tragen.
/// Die zwei Auspraegungen zusammen saeen jeden Marker genau einmal, und
/// `privacy_canaries_writer.rs` belegt, dass ihre Vereinigung vollstaendig ist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanaryVariantV1 {
    /// Personal-, Fahrzeug- und Fremdorganisationszeilen sind BESETZT, die
    /// Leergruende sind `None`.
    PopulatedLists,
    /// Die Listen sind LEER und tragen ihre beiden Leergruende.
    EmptyListsWithReasons,
}

impl CanaryVariantV1 {
    /// Beide Auspraegungen.
    pub const ALL: [Self; 2] = [Self::PopulatedLists, Self::EmptyListsWithReasons];

    /// Die Felder, deren Marker DIESE Auspraegung wirklich saet.
    #[must_use]
    pub const fn seeded_fields(self) -> &'static [&'static str] {
        match self {
            Self::PopulatedLists => &[
                "keyword",
                "location",
                "personnel",
                "vehicles",
                "external_organizations",
                "human_incident_number",
                "notes",
            ],
            Self::EmptyListsWithReasons => &[
                "keyword",
                "location",
                "human_incident_number",
                "notes",
                "personnel_empty_reason",
                "vehicles_empty_reason",
            ],
        }
    }
}

/// Die Fixture der Kanarienvogelpruefung.
pub struct CanaryHarness {
    variant: CanaryVariantV1,
    inner: WriterHarness,
    /// Die Debug-Ausgaben, die der Kern in eine Panik oder eine Fehlerzeile
    /// legen KANN — der einzige „Absturzausgang", den dieser Workspace hat.
    crash_output: Vec<u8>,
}

impl CanaryHarness {
    /// Eine Fixture, deren Entwurf und Einsatzinhalt je Feld GENAU EINEN
    /// Kanarienvogel tragen — in der Auspraegung `variant`.
    #[must_use]
    pub fn with_one_canary_per_field(variant: CanaryVariantV1) -> Self {
        let inner = WriterHarness::with_incident();
        let repository = inner.repository();
        let draft = repository
            .load_or_create()
            .expect("der Entwurf der Fixture muss lesbar sein");
        repository
            .save(draft.with_notes(canary("notes")))
            .expect("die Fixture muss speichern koennen");
        Self {
            variant,
            inner,
            crash_output: Vec::new(),
        }
    }

    #[must_use]
    pub const fn variant(&self) -> CanaryVariantV1 {
        self.variant
    }

    #[must_use]
    pub const fn inner(&self) -> &WriterHarness {
        &self.inner
    }

    /// Die Marker dieser Fixture.
    #[must_use]
    pub fn canaries(&self) -> Vec<&'static [u8]> {
        CANARY_MARKERS
            .iter()
            .map(|(_, marker)| marker.as_bytes())
            .collect()
    }

    /// Die Marker, die DIESE Auspraegung wirklich gesaet hat.
    #[must_use]
    pub fn seeded_canaries(&self) -> Vec<&'static [u8]> {
        self.variant
            .seeded_fields()
            .iter()
            .map(|field| canary(field).as_bytes())
            .collect()
    }

    /// Die Einsatznummer, die dieser Einsatz beansprucht.
    #[must_use]
    pub fn incident_number(&self) -> &'static str {
        canary("human_incident_number")
    }

    /// Finalisiert den Einsatz mit den Kanarienvoegeln.
    ///
    /// Jede beobachtbare Debug-Ausgabe des Weges wird MITGESCHRIEBEN: Vorschau,
    /// Erreichungszustand und Abschlussergebnis. Sie ist der Absturzausgang
    /// dieses Kerns — ein Panikstrom entsteht aus `Debug` und nirgends sonst.
    pub fn finalize(&mut self) -> Result<EntryHash, WriterError> {
        let source = self.inner.source();
        let service = self.inner.service(&source);
        let proof = self.inner.proof_for(ReauthPurpose::Finalize);
        let preview = service.preview(
            &proof,
            canary_incident(self.variant),
            self.inner.observed_now(),
        )?;
        // `FinalizationPreview` leitet ABSICHTLICH kein `Debug` ab — dieselbe
        // Stufe-1-Doktrin, die den Geheimnistraegern keines gibt: was in keine
        // Protokollzeile darf, bekommt keine Darstellung. Der Strom traegt
        // deshalb nur, was der Kern wirklich ausgeben KANN.
        let outcome = service.finalize(
            &proof,
            canary_incident(self.variant),
            &preview,
            self.inner.observed_now(),
        );
        self.crash_output
            .extend_from_slice(format!("{outcome:?}").as_bytes());
        // Auch der FEHLERWEG gehoert in den Strom: eine zweite Finalisierung
        // gegen dieselbe Sequenz wird abgewiesen, und ihre Fehlerzeile ist
        // genau das, was ein Bediener zu sehen bekaeme.
        let refused = service.finalize(
            &proof,
            canary_incident(self.variant),
            &preview,
            self.inner.observed_now(),
        );
        self.crash_output
            .extend_from_slice(format!("{refused:?}").as_bytes());
        outcome.map(|outcome| outcome.entry_hash)
    }

    /// Der Entwurfsfreitext, wie er JETZT in der Ablage steht.
    #[must_use]
    pub fn draft_notes(&self) -> Option<String> {
        self.inner
            .repository()
            .load_or_create()
            .ok()
            .map(|draft| draft.notes().to_owned())
    }

    /// Ob die Einsatznummer dieses Einsatzes verbraucht ist.
    #[must_use]
    pub fn incident_number_is_taken(&self) -> bool {
        self.inner.incident_number_is_taken(self.incident_number())
    }

    /// Legt die Sicherung von VOR der Finalisierung zurueck.
    ///
    /// Der Schluesselspeichereintrag kehrt NICHT zurueck: er ist
    /// geraetegebunden und liegt nicht in diesen Dateien.
    pub fn restore_pre_finalization_backup(&mut self) {
        self.inner.restore_captured_backup();
    }

    /// Ob KEIN Geheimnis dieses Schluesselspeichers den committed Eintrag
    /// oeffnet.
    #[must_use]
    pub fn writer_keys_cannot_decrypt(&self, entry_hash: EntryHash) -> bool {
        self.inner.writer_keys_cannot_decrypt(entry_hash)
    }

    /// Ob der `draftDEK` DIESES Einsatzes fort ist.
    #[must_use]
    pub fn draft_key_is_gone(&self) -> bool {
        self.inner.draft_is_blank() || !self.inner.draft_dek_is_present()
    }

    /// Legt einen Marker WIRKLICH auf die Platte — die Gegenkontrolle.
    ///
    /// Sie belegt, dass die Suche jede Datei unter der Wurzel erreicht und dass
    /// `contains_canary` greift. Ohne sie waere eine leere Stromsammlung von
    /// einem sauberen Bestand nicht zu unterscheiden.
    pub fn plant_marker_for_test(&self, marker: &str) {
        fs::write(self.inner.root().join("ea-kanarie-probe.bin"), marker)
            .expect("die Probe muss schreibbar sein");
    }

    /// Jeder beobachtbare Bytestrom dieser Fixture, benannt.
    ///
    /// Datenbankdatei samt WAL, Journal und Temporaerueberlauf, jede Datei des
    /// Bestands einschliesslich der Staging-Deskriptoren, jeder Datei- und
    /// Verzeichnisname und die Debug-Ausgaben des Weges.
    #[must_use]
    pub fn every_observable_byte_stream(&self) -> Vec<(String, Vec<u8>)> {
        let mut streams = every_file_under(self.inner.root());
        assert!(
            streams.len() >= 2,
            "die Fixture MUSS mindestens Datenbank und Bestand tragen, sonst ist die Suche leer"
        );
        streams.push((
            "jeder Datei- und Verzeichnisname".to_owned(),
            every_path_name_under(self.inner.root()),
        ));
        streams.push((
            "Debug-Ausgabe des Weges".to_owned(),
            self.crash_output.clone(),
        ));
        streams
    }
}

/// Der Marker des Feldes `field`.
#[must_use]
pub fn canary(field: &str) -> &'static str {
    CANARY_MARKERS
        .iter()
        .find(|(name, _)| *name == field)
        .map(|(_, marker)| *marker)
        .expect("jedes benannte Feld traegt einen Marker")
}

/// Ein GUELTIGER Einsatz, dessen jedes fachliche Feld einen Kanarienvogel
/// traegt.
#[must_use]
pub fn canary_incident(variant: CanaryVariantV1) -> FinalizationInputV1 {
    let populated = variant == CanaryVariantV1::PopulatedLists;
    FinalizationInputV1 {
        timezone: "Europe/Berlin".to_owned(),
        source: NativeSourceV1::new("ea.system-tests.canary", 1)
            .expect("die Quelle der Fixture ist gueltig"),
        human_incident_number: canary("human_incident_number").to_owned(),
        occurred_at: OccurredAtV1::new(UnixMillis::new(CANARY_OCCURRED_AT_MS), None)
            .expect("das Intervall der Fixture ist gueltig"),
        keyword: KeywordV1::free_text(canary("keyword")).expect("das Stichwort ist gueltig"),
        location: LocationV1::structured(
            StructuredAddressV1::new(
                Some(canary("location").to_owned()),
                Some("1".to_owned()),
                Some("12345".to_owned()),
                Some("Musterstadt".to_owned()),
                None,
                Some("DE".to_owned()),
            )
            .expect("die Adresse ist gueltig"),
            None,
        )
        .expect("der Ort ist gueltig"),
        // Liste ODER Leergrund, nie beides: `ea-schema` weist eine nichtleere
        // Liste mit Leergrund ab (`EA-SCHEMA-LIST-REASON`). Genau deshalb gibt
        // es zwei Auspraegungen.
        personnel: if populated {
            vec![
                PersonnelSnapshotV1::ad_hoc(canary("personnel"), None)
                    .expect("die Personalzeile ist gueltig"),
            ]
        } else {
            Vec::new()
        },
        personnel_empty_reason: if populated {
            None
        } else {
            Some(canary("personnel_empty_reason").to_owned())
        },
        vehicles: if populated {
            vec![
                VehicleSnapshotV1::ad_hoc(canary("vehicles"), None, None)
                    .expect("die Fahrzeugzeile ist gueltig"),
            ]
        } else {
            Vec::new()
        },
        vehicles_empty_reason: if populated {
            None
        } else {
            Some(canary("vehicles_empty_reason").to_owned())
        },
        // `patient_count` traegt keinen Marker (siehe [`CANARY_MARKERS`]).
        patient_count: PatientCount::Unknown,
        notes: Some(canary("notes").to_owned()),
        external_organizations: if populated {
            vec![
                ExternalOrganizationV1::new(None, canary("external_organizations"))
                    .expect("die Fremdorganisation ist gueltig"),
            ]
        } else {
            Vec::new()
        },
    }
}

/// Der Ereigniszeitpunkt der Kanarienfixture — die Ausstellungszeit des
/// gebundenen Head, wie bei `writer_support::valid_incident`.
const CANARY_OCCURRED_AT_MS: i64 = 1_767_225_600_000;
