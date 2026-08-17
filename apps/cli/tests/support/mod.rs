//! Testsupport der CLI.
//!
//! # Die Fixture-Kette wird EINGEBUNDEN, nicht nachgebaut
//!
//! Das Repo bindet Testsupport per relativem `#[path]` ein:
//! `crates/ea-verify/tests/support/mod.rs` bindet so den Support von
//! `ea-archive` ein, dieser wiederum den von `ea-trust` und `ea-format`, und
//! `crates/ea-recovery/tests/support/mod.rs` setzt die Kette mit `materialize`,
//! `temp_dir` und der `live_clock_*`-Familie fort. Hier wird genau dieses eine
//! Glied weitergereicht — `TempDir`, `temp_dir` und `materialize` stehen
//! deshalb an GENAU EINER Stelle im Workspace und nicht zweimal fast gleich.
//!
//! Solange nur die Aufrufgrammatik gemessen wurde, war die Kette hier
//! ueberfluessig: sie entscheidet jeden ihrer Faelle, bevor ein Byte gelesen
//! wird. `verify` und `list` lesen wirklich, und damit zieht sie ein.
//!
//! # DIE UHRENREGEL — und ihre EINE begruendete Ausnahme
//!
//! Die CLI kennt genau EINE Uhr, `SystemTime::now()`. Die geerbten Bestaende
//! aus `crates/ea-verify/tests/support` tragen Registrierungskoepfe aus
//! `trust_support::HeadOptions::default()` (`issued_at = 100`,
//! `not_after = 10_000`); unter der echten Uhr sind sie samtlich veraltet, Gate
//! `trust` traegt nicht mehr, und der Bericht degeneriert zu einer LEEREN
//! Aussage, die faelschlich wie Erfolg aussieht. Gemessen in
//! `crates/ea-recovery/tests/live_clock.rs`.
//!
//! Deshalb gilt: jeder Bestand, der hier einen BEFUND belegen soll, stammt aus
//! der `live_clock_*`-Familie. `isolation_archive`,
//! `archive_with_a_missing_middle_entry` und `destruction_archive` kommen in
//! `apps/cli` NICHT vor; ihre Befunde sind unter der echten Uhr unerreichbar
//! und werden dort gemessen, wo die Uhr ein Parameter ist —
//! `crates/ea-recovery/tests/exit_codes.rs`.
//!
//! Die AUSNAHME ist `complete_valid_archive`, und sie ist keine Aufweichung,
//! sondern der Gegenstand: dieser Bestand wird hier benutzt, WEIL er unter der
//! echten Uhr degeneriert. Er ist der gepinnte Gegenfall zu Exitcode 15
//! („vollstaendig geprueft, und ueber den einen geparsten Eintrag ist nichts
//! ausgesagt") und ausdruecklich kein Erfolgspfad. Faellt diese Zusicherung
//! weg, meldete die CLI genau hier Erfolg ueber einen Bestand, ueber den sie
//! nichts gesagt hat.
//!
//! `#[path]`-Includes werden je Testtarget uebersetzt; ein Target, das nur
//! einen Teil der Helfer nutzt, erzeugt sonst `dead_code`-Warnungen, die unter
//! `-D warnings` brechen. Daher `allow(dead_code)` auf Modulebene.
#![allow(dead_code)]

/// Die Fixture-Kette, wie `ea-recovery` sie bereits fuehrt.
#[path = "../../../../crates/ea-recovery/tests/support/mod.rs"]
mod recovery_support;

// GLOBAL wiederausgefuehrt, damit `support::temp_dir`, `support::materialize`,
// `support::live_clock_*` und `support::verify_support::*` unmittelbar
// erreichbar sind. Das `allow` hat denselben Grund wie das `allow(dead_code)`
// oben: dieses Modul wird je Testtarget EINZELN uebersetzt, und ein Target, das
// nur die Grammatik misst, sieht ungenutzte Wiederausfuhren.
#[allow(unused_imports)]
pub use recovery_support::*;
