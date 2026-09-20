//! Die FIXTURE-DEMOWELT: eine vollständige, auf die Platte geschriebene
//! Einsatzarchiv-Welt für Vorführung und Handprobe.
//!
//! Alles hier ist Fixture. Nichts hier ist Bestand, nichts hier ist Beweis,
//! und nichts hier darf in eine echte Organisation geraten. Die Schlüssel
//! stehen als Konstanten im Quelltext und sind damit öffentlich bekannt.
//!
//! # Warum diese Crate überhaupt existiert
//!
//! Die Bauwerkzeuge für eine Welt — `RegistryLineBuilder`, `ActionSpec`,
//! `HeadOptions`, `fixture_with_host_options`, `materialize` — lagen bisher
//! ausschließlich in `tests/support/`-Modulen und waren damit nur aus einem
//! Testziel erreichbar. Ein `xtask`-Ziel ist kein Testziel.
//!
//! # Warum die Module EINGEBUNDEN und nicht VERSCHOBEN sind
//!
//! Das Repo bindet Testsupport per relativem `#[path]` ein; die Kette
//! `ea-recovery -> ea-verify -> ea-archive -> ea-trust`/`ea-format` wird an
//! über fünfzig Stellen so referenziert, davon einige aus `src/`
//! (`crates/ea-trust/src/time.rs`, `crates/ea-admin/src/lib.rs`). Ein
//! Verschieben der Dateien hätte jede dieser Stellen angefasst — viel
//! Blastradius für null Gewinn an Wahrheit.
//!
//! Diese Crate bindet deshalb GENAU DIESELBEN Quelldateien per `#[path]` ein,
//! die die Testziele einbinden. Damit gibt es weiterhin genau EINE Quelle je
//! Bauwerkzeug: was ein Test baut und was die Demowelt baut, entsteht aus
//! demselben Text. Die Richtung ist umgekehrt zur naiven Erwartung — nicht die
//! Tests ziehen aus der Crate, sondern beide ziehen aus derselben Datei —,
//! aber die Zusage „keine zwei Wahrheiten" hält buchstäblich.
//!
//! # Erreichbarkeit
//!
//! Ohne `fixture-world` ist diese Crate leer. Sie hat dann keine einzige
//! aufgelöste Kante, und kein Produktionswirt kann sie erreichen.
#![cfg(feature = "fixture-world")]

/// Die Fixture-Kette, wie `ea-recovery` sie führt: `TempDir`, `temp_dir`,
/// `materialize`, die `live_clock_*`-Familie und darüber `verify_support`
/// mit `historical::fixture_with_host_options`, `archive_support` und
/// `trust_support` mit `RegistryLineBuilder`, `ActionSpec` und `HeadOptions`.
///
/// `#[path]` auf die ORIGINALDATEI: dieselbe Quelle, die jedes Testziel
/// einbindet.
#[path = "../../ea-recovery/tests/support/mod.rs"]
pub mod support;

pub mod world;

pub use world::{DemoWorld, SeedError, seed_demo_world};
