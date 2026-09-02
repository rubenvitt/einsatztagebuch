//! Die Kulisse der Verifikation vor der Entschluesselung.
//!
//! # Ein EIGENES Verzeichnis neben `tests/fixtures`
//!
//! `crates/ea-reader/tests/fixtures/mod.rs` bleibt unberuehrt, und das ist
//! keine Bequemlichkeit: sieben Testziele haengen daran, sein Anker steht
//! bewusst auf dem Wurzelseed `0x11` — gegen ihn faellt JEDE Verifikation der
//! Fixture-Registrierungslinie bereits an Gate `trust` —, und sein
//! `entry_hash()` ist mit einem ganz anderen Wert belegt. Ein zweiter
//! Zweck in derselben Datei haette eine der beiden Rollen still verdorben.
//!
//! Genau diese Fremdheit wird an EINER Stelle zum Zeugen: `pinned_anchor.rs`
//! bindet das Nachbarmodul zusaetzlich ein und klassifiziert den vollstaendigen
//! Bestand gegen dessen Tresor. Der Einschluss steht dort und nicht hier, weil
//! `crates/ea-reader-wasm` diese Kulisse ueber dieselbe `#[path]`-Kette benutzt
//! und die Kanten des Nachbarmoduls (`ea-testkit`, `ea-sync-protocol`) dort
//! nicht liegen.
//!
//! # Der Bestand wird NICHT nachgebaut
//!
//! Er kommt ueber das per `#[path]` eingebundene Fixture-Modul von `ea-verify`
//! und damit aus derselben Registrierungslinie, gegen die Stufe 1 und 2 ihre
//! Gates messen — dieselbe Kette von Includes, die
//! `crates/ea-reader/tests/sync_support/mod.rs`,
//! `crates/ea-recovery/tests/support/mod.rs` und
//! `crates/ea-archive-fs/tests/support/mod.rs` bereits fahren.
//!
//! `#[path]`-Includes werden je Testziel uebersetzt; ein Ziel, das nur einen
//! Teil der Helfer nutzt, erzeugt sonst `dead_code`-Warnungen, die unter
//! `-D warnings` brechen. Daher `allow(dead_code)` auf Modulebene.
#![allow(dead_code)]

/// Das Fixture-Modul aus `ea-verify`, unveraendert weiterverwendet.
///
/// Es bindet seinerseits das Archiv-, das Trust- und das Formatfixture ein.
#[path = "../../../ea-verify/tests/support/mod.rs"]
pub mod verify_support;

pub mod fixtures;
