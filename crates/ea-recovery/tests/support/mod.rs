//! Fixtures fuer `ea-recovery`, plus die zwei Helfer, die sie auf die Platte
//! bringen.
//!
//! Es entsteht KEINE neue Fixture-Crate. Das Repo bindet Testsupport per
//! relativem `#[path]` ein — `crates/ea-verify/tests/support/mod.rs` bindet so
//! den Support von `ea-archive` ein, dieser wiederum den von `ea-trust` und
//! `ea-format`. Genau diese Kette wird hier fortgesetzt; nachgebaut wird
//! nichts. `ea-testkit` (Task 11) wird ausdruecklich NICHT vorgezogen.
//!
//! `#[path]`-Includes werden je Testtarget uebersetzt; ein Target, das nur
//! einen Teil der Helfer nutzt, erzeugt sonst `dead_code`-Warnungen, die unter
//! `-D warnings` brechen. Daher `allow(dead_code)` auf Modulebene.
//!
//! # ZWEI FIXTUREFAMILIEN, UND SIE SIND NICHT AUSTAUSCHBAR
//!
//! Die GEERBTEN Bestaende aus [`verify_support`] — `complete_valid_archive`,
//! `isolation_archive`, `archive_with_a_missing_middle_entry`,
//! `destruction_archive` und alles Uebrige — tragen samtlich
//! Registrierungskoepfe aus `trust_support::HeadOptions::default()`
//! (`issued_at = 100`, `not_after = 10_000`, Policy `max_registry_age`
//! 86_400_000). Sie sind AUSSCHLIESSLICH unter der Fixture-Uhr
//! [`verify_support::FIXTURE_OS_WALL_CLOCK_V1`] aussagekraeftig. Unter der
//! echten Betriebssystemuhr sind ALLE ihre Koepfe veraltet, Gate `trust` traegt
//! nicht mehr, und der Bericht degeneriert zu einer LEEREN Aussage, die
//! faelschlich wie Erfolg aussieht — gemessen in
//! `crates/ea-recovery/tests/live_clock.rs`.
//!
//! Daraus folgt eine feste Trennung:
//!
//! - Die geerbten Bestaende sind NUR dort zulaessig, wo die Uhr ein PARAMETER
//!   ist — also in `crates/ea-recovery/tests`, wo `verify_directory` sie
//!   entgegennimmt. In keinem Test unter `apps/cli` duerfen sie vorkommen: die
//!   CLI kennt genau EINE Uhr, `SystemTime::now()`.
//! - Fuer alles, was gegen die ECHTE Uhr laeuft, gibt es die
//!   `live_clock_*`-Familie dieses Moduls. Ihre Registrierungsfenster
//!   enthalten die echte Uhr; ihre Befunde sind deshalb unter
//!   `SystemTime::now()` messbar.
#![allow(dead_code)]

/// Die Fixture-Kette aus `ea-verify`, unveraendert weiterverwendet.
#[path = "../../../ea-verify/tests/support/mod.rs"]
pub mod verify_support;

mod live;

// GLOBAL wiederausgefuehrt, damit die Familie unter `support::` steht und nicht
// unter `support::live::`.
//
// Das `allow` hat denselben Grund wie das `allow(dead_code)` oben: dieses Modul
// wird je Testtarget EINZELN uebersetzt, und ein Target, das die Live-Familie
// gar nicht anfasst — `fs_source` etwa —, sieht eine ungenutzte
// Wiederausfuhr. Das ist eine Aussage ueber das Target, nicht ueber den Code,
// und unter `-D warnings` braeche sie den Bau.
#[allow(unused_imports)]
pub use live::*;

use std::{
    env, fs,
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicUsize, Ordering},
};

use verify_support::archive_support::ArchiveFixture;

/// Ein Verzeichnis, das beim Fallenlassen rekursiv verschwindet.
///
/// Von Hand und nicht ueber `tempfile`: dieser Task nimmt KEINE neue externe
/// Dependency auf, und die Grammatik dieses Bedarfs ist klein genug, um sie
/// hier zu tragen.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Das Wurzelverzeichnis. Existiert, solange dieser Wert lebt.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    /// Loescht rekursiv und schluckt dabei jeden Fehler.
    ///
    /// Ein `Drop`, das waehrend des Abwickelns eines fehlgeschlagenen Tests
    /// panisch wird, bricht den Prozess ab und VERNICHTET die Fehlermeldung,
    /// derentwegen der Test ueberhaupt lief. Aufraeumen ist Beiwerk; die
    /// Diagnose ist es nicht.
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Laufende Nummer, damit zwei Aufrufe im selben Prozess nie kollidieren.
///
/// `cargo test` faehrt die `#[test]`-Funktionen eines Binaries parallel in
/// Threads; die Prozess-ID allein trennt sie deshalb nicht.
static NEXT_TEMP_DIR_INDEX: AtomicUsize = AtomicUsize::new(0);

/// Ein frisches, leeres Verzeichnis unter [`env::temp_dir`].
///
/// `tag` benennt den Zweck und taucht im Pfad auf, damit ein liegen
/// gebliebenes Verzeichnis zuzuordnen ist.
#[must_use]
pub fn temp_dir(tag: &str) -> TempDir {
    let index = NEXT_TEMP_DIR_INDEX.fetch_add(1, Ordering::Relaxed);
    let path = env::temp_dir().join(format!("ea-{tag}-{}-{index}", process::id()));
    // Prozess-IDs werden vom Betriebssystem wiederverwendet. Ein Rest aus einem
    // abgebrochenen frueheren Lauf wuerde sonst als Bestandsinhalt gelesen.
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("das Temporaerverzeichnis muss anlegbar sein");
    TempDir { path }
}

/// Schreibt jeden Blob des Bestands unter seinem Pfadhinweis nach `root`.
///
/// Die Bytes gehen UNVERAENDERT hinaus: ein materialisierter Bestand muss
/// byteweise derselbe sein wie der im Speicher, sonst misst kein Vergleich
/// dahinter noch etwas.
pub fn materialize(fixture: &ArchiveFixture, root: &Path) {
    for (path_hint, bytes) in fixture.blobs() {
        let target = resolve_within(root, path_hint);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).expect("das Zwischenverzeichnis muss anlegbar sein");
        }
        fs::write(&target, bytes).expect("der Blob muss schreibbar sein");
    }
}

/// Loest einen Pfadhinweis GEGEN `root` auf und laesst ihn nicht hinaus.
///
/// Der Hinweis wird komponentenweise angehaengt statt ueber `Path::join` auf
/// die ganze Zeichenkette: ein absoluter Hinweis ersetzte damit stillschweigend
/// die Wurzel, und `..` liefe aus dem Temporaerverzeichnis heraus. Beides ist
/// hier ein Fixture-Fehler und muss laut werden, bevor irgendetwas geschrieben
/// wird.
fn resolve_within(root: &Path, path_hint: &str) -> PathBuf {
    let mut target = root.to_path_buf();
    for component in path_hint.split('/') {
        assert!(
            !component.is_empty() && component != "." && component != "..",
            "der Pfadhinweis muss relativ und ohne Sonderkomponenten sein: {path_hint}"
        );
        target.push(component);
    }
    target
}
