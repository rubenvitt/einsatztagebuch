//! Testsupport der CLI.
//!
//! # Warum hier (noch) KEINE Fixture-Kette haengt
//!
//! `crates/ea-recovery/tests/support/mod.rs` bindet ueber `#[path]` die
//! Fixture-Kette aus `ea-verify`, `ea-archive`, `ea-trust` und `ea-format` ein
//! und traegt zusaetzlich die `live_clock_*`-Familie. Dieses Modul bindet sie
//! ABSICHTLICH NICHT ein: die Aufrufgrammatik entscheidet JEDEN ihrer Faelle,
//! bevor ein einziges Byte gelesen wird. Ein echter Bestand fuegte dem Nachweis
//! nichts hinzu und der Uebersetzung dieses Targets die gesamte Kette.
//!
//! Ein Kommandopfad, der wirklich verifiziert, braucht sie — und bekommt sie
//! dann hier, mit den Anforderungen in der Hand.
//!
//! # Die Uhrenregel bleibt trotzdem stehen
//!
//! Sobald hier Bestaende einziehen, duerfen es AUSSCHLIESSLICH die
//! `live_clock_*`-Bestaende sein. Die geerbten Bestaende aus
//! `crates/ea-verify/tests/support` tragen Registrierungskoepfe, die unter der
//! echten Betriebssystemuhr saemtlich veraltet sind; die CLI kennt aber genau
//! EINE Uhr, `SystemTime::now()`, und unter ihr degenerieren sie zu einer
//! leeren Aussage, die faelschlich wie Erfolg aussieht. Gemessen in
//! `crates/ea-recovery/tests/live_clock.rs`.
//!
//! `#[path]`-Includes werden je Testtarget uebersetzt; ein Target, das nur
//! einen Teil der Helfer nutzt, erzeugt sonst `dead_code`-Warnungen, die unter
//! `-D warnings` brechen. Daher `allow(dead_code)` auf Modulebene.
#![allow(dead_code)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicUsize, Ordering},
};

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
