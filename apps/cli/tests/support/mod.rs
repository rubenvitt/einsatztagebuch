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
//! # Betriebssystemuhr und historische Verifikation
//!
//! Die CLI verwendet `SystemTime::now()`. Die `live_clock_*`-Familie hat
//! aktuell waehlbare Registry-Koepfe. Geerbte kurze Leases bleiben fuer
//! historische Lesefaelle geeignet: Task 8 verifiziert exakt gebundene
//! Registry/Sequenz ohne eine alte Lease zur Lesefrist zu machen.
//! `exit_codes.rs` belegt dies am echten verify- und list-Prozess.
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
