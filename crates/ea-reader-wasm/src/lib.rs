#![forbid(unsafe_code)]
//! Die Bruecke zwischen dem geteilten Rust-Kern und der Browser-Umgebung.
//!
//! # Kein Skelett mehr
//!
//! Bis zur Aufgabe „wasm32-Reichweite" stand hier genau so viel, wie diese
//! Reichweite belegen konnte: EINE reine Funktion und EIN duenner Export
//! darueber. Der echte Uebergang steht jetzt daneben — [`bridge`] traegt den
//! Laufzeitzeugen nach `web-reader-design.md` §14.1 und die zwei
//! Bytespeicher-Ausfuhren, [`opfs_worker`] den OPFS-Wirt dahinter, und
//! [`vault_bridge`] seit der Aufgabe „Browser-Vault: PRF-Envelopes,
//! Schlüsselprofil und die Verwahrung von Anchor und KEM-Schlüssel" die zwei
//! Tresorausfuhren. [`webauthn`] kommt mit der Aufgabe „Browser-Enrollment:
//! zwei Pflicht-Authenticators und das nicht überspringbare Fingerprint-Gate"
//! dazu und trägt die fünf Enrollment-Ausfuhren samt der Browserfassung des
//! Endpunktports. [`fetch`] kommt mit der Aufgabe „Inkrementeller Reader-Sync
//! und verifizierter Cursor-Fortschritt in OPFS" dazu und traegt GENAU ZWEI
//! Ausfuhren: den fertig signierten Lesestapel-Request hinaus und die
//! Antwortbytes hinein. [`view`] kommt mit der Aufgabe „Integritätszentrierte
//! Reader-Oberfläche" dazu: der EINE geoeffnete Bestand des Workers und die
//! sechs Ansichtsausfuhren, die ihn als generierte DTOs herausgeben.
//! [`visibility`] und [`export_bridge`] kommen mit der Aufgabe
//! „Sitzungssperre, Zeroize, authenticator-bestätigter Einzelexport und
//! signiertes lokales Audit" dazu: drei Sitzungsausfuhren, an die `apps/web`
//! seine Sichtbarkeits- und Eingabehaken haengt, und GENAU EINE Exportausfuhr,
//! die GENAU EINEN Eintragshash nimmt. Seit derselben Aufgabe haelt
//! [`vault_bridge`] je Kennung eine `ReaderSession` statt eines nackten
//! Tresors, und jede Ausfuhr, die den Tresor braucht, reicht ihre Uhr an
//! `ReaderSession::vault` durch — die Sperre faellt beim Zugriff, nicht im
//! Timer.
//!
//! # Was hier NICHT liegt
//!
//! Die Rechnung selbst gehoert den geteilten Crates. `bridge.rs` ruft
//! `ea_crypto` und `ea_reader` und entscheidet nichts; `opfs_worker.rs` legt
//! OPAKE Bytes ab und weiss nicht, was in ihnen steht. Waere es anders, gaebe
//! es eine zweite Stelle, an der ueber Klartext entschieden wird — und
//! `web-reader-design.md` §9 laesst Kryptographie ausschliesslich in geteiltem
//! Rust zu.
//!
//! # Die Bauform: reine Funktion, duenner Export
//!
//! [`bridge_echo`] traegt die Rechnung und ist auf JEDEM Ziel uebersetzbar;
//! darueber liegt ein Export, der nichts tut, als sie zu rufen, und der hinter
//! `cfg(target_arch = "wasm32")` steht. Das ist keine Formsache, sondern die
//! Voraussetzung von zwei Dingen zugleich: der Wirtsbau von
//! `cargo test --workspace --all-targets --locked` uebersetzt das
//! wasm-bindgen-Attribut nicht, und die Rechnung bleibt fuer einen gewoehnlichen
//! Wirtstest erreichbar. `crates/ea-reader-wasm/tests/bridge_boundary.rs` liest
//! diese Lage als Text und wird rot, sobald ein Export ohne sein cfg
//! danebensteht.
//!
//! **Dieser Zeuge ist die EINZIGE Instanz, die das merkt, und das ist
//! GEMESSEN.** Mit entferntem cfg enden Uebersetzung, Testbau und Clippy-Gate
//! alle drei mit 0 und ohne eine einzige Diagnose; nur der Zeuge faellt. Der
//! Compiler ist hier also KEIN zweites Netz — wer ein weiteres Modul mit einer
//! Ausfuhr anlegt und ihr cfg vergisst, wird nirgends sonst gewarnt. Die
//! Messung samt ihren vier Kommandos steht im Doc-Kommentar von
//! `every_wasm_bindgen_export_sits_behind_the_wasm32_cfg`.

/// Die Ausfuhren nach JavaScript und der Laufzeitzeuge.
///
/// Das Modul ist auf JEDEM Ziel uebersetzbar; nur seine Ausfuhren stehen
/// hinter `cfg(target_arch = "wasm32")`. Das ist dieselbe Bauform wie unten:
/// die Rechnung bleibt fuer einen gewoehnlichen Wirtstest erreichbar.
pub mod bridge;

/// Die Bruecke des Einzelexports: GENAU EINE Ausfuhr, GENAU EIN Eintragshash.
///
/// Ohne cfg an der `mod`-Zeile, weil das Modul eine Ausfuhr traegt und die
/// reine Haelfte — das Bericht-DTO und die Zielart aus ihrer Zahl — auf dem
/// Wirt bezeugt wird.
pub mod export_bridge;

/// Die Bruecke des inkrementellen Lesestapels: GENAU ZWEI Ausfuhren.
///
/// Das Modul steht OHNE cfg an der `mod`-Zeile, weil es Ausfuhren traegt und
/// die Regel „cfg am Item" dann fuer jede einzelne von ihnen gilt — dieselbe
/// Lage wie bei [`bridge`] und [`vault_bridge`] und ausdruecklich nicht die von
/// `opfs_worker`.
///
/// Beide Ausfuhren laufen IM DEDIZIERTEN WORKER: sie oeffnen OPFS-Speicher, und
/// synchrone Zugriffshandles gibt es nur dort. Der eigentliche `fetch` liegt
/// dagegen NICHT hier — er liegt in `apps/web/src/sync/transport.ts`, und die
/// Naht dazwischen ist der Sinn dieses Moduls: geteiltes Rust signiert und
/// entscheidet, JavaScript bewegt Bytes.
pub mod fetch;

/// Der Datei-Modus: die SECHS Ausfuhren der zwei Wege aus dem Dateisystem.
///
/// Das Modul steht OHNE cfg an der `mod`-Zeile, weil es Ausfuhren traegt und
/// die Regel „cfg am Item" dann fuer jede einzelne von ihnen gilt — dieselbe
/// Lage wie bei [`bridge`], [`fetch`] und [`vault_bridge`] und ausdruecklich
/// nicht die von `opfs_worker`.
///
/// Alle sechs Ausfuhren laufen IM DEDIZIERTEN WORKER, und der Grund ist nicht
/// OPFS: `ea_reader::ReaderFileMode` verlangt einen entsperrten Tresor, und die
/// Sitzungstabelle dafuer liegt in einem `thread_local!` in [`vault_bridge`].
/// Der `FileSystemDirectoryHandle` selbst wird auf dem Hauptthread abgelaufen —
/// die Naht dazwischen ist wieder die Nachrichtenform von
/// `apps/web/src/bridge/opfs-worker.ts`.
///
/// Hier faellt KEINE Entscheidung: die zwei Deckel setzt
/// `ea_reader::DirectoryHandleSource` durch, die Klassifikation faehrt
/// `ea_reader::ReaderVerifier`, und der Modus verlaesst die Crate nicht einmal
/// als DTO-Feld.
pub mod file_access;

/// Der OPFS-Bytespeicher — NUR auf `wasm32-unknown-unknown`.
///
/// Das Tor steht hier an der `mod`-Zeile und nicht an jedem Item, und das ist
/// zulaessig, weil das Modul KEINE `wasm_bindgen`-Ausfuhr traegt: die Regel
/// „cfg am Item" von `every_wasm_bindgen_export_sits_behind_the_wasm32_cfg`
/// gilt genau den Ausfuhren, und die stehen in [`bridge`]. Auf einem Wirtsziel
/// gaebe es fuer `FileSystemSyncAccessHandle` ohnehin keinen Wirt.
///
/// Die Attributschreibweise steht hier bewusst OHNE ihre Klammern: der Zeuge
/// liest Text und unterscheidet eine Ausfuhr nicht von einer Erwaehnung. Ein
/// ausgeschriebenes Attribut in einem Fliesstext faerbte ihn rot — GEMESSEN
/// an genau dieser Zeile.
#[cfg(target_arch = "wasm32")]
pub mod opfs_worker;

/// Die Tresorbruecke: die zwei Ausfuhren des Browser-Tresors.
///
/// Das Modul steht OHNE cfg an der `mod`-Zeile, weil es Ausfuhren traegt und
/// die Regel „cfg am Item" dann fuer jede einzelne von ihnen gilt — dieselbe
/// Lage wie bei [`bridge`] und ausdruecklich nicht die von `opfs_worker`.
///
/// Hier ueberquert die PRF-Ausgabe die Grenze, und zwar NUR in dieser
/// Richtung: `web-reader-design.md` §9 laesst nach JavaScript Sitzungskennung,
/// Fingerabdruecke und Statuswerte, nie Schluesselmaterial.
pub mod vault_bridge;

/// Die Bruecke der Sitzungssperre: DREI Ausfuhren, keine entscheidet.
///
/// Ohne cfg an der `mod`-Zeile, aus demselben Grund wie bei [`fetch`]; die
/// reine Haelfte — das Sitzungs-DTO — wird auf dem Wirt bezeugt.
pub mod visibility;

/// Das Browser-Enrollment: die fuenf Ausfuhren und der Endpunktport dahinter.
///
/// Das Modul steht OHNE cfg an der `mod`-Zeile, weil es Ausfuhren traegt und
/// die Regel „cfg am Item" dann fuer jede einzelne von ihnen gilt — dieselbe
/// Lage wie bei [`bridge`] und [`vault_bridge`] und ausdruecklich nicht die
/// von `opfs_worker`. Ein `pub mod` und kein `mod`, weil der Zeuge
/// `crates/ea-reader-wasm/tests/bridge_boundary.rs` und die Aufgabe selbst die
/// Ausfuhren unter `ea_reader_wasm::webauthn` benennen.
///
/// Alle fuenf Ausfuhren laufen IM DEDIZIERTEN WORKER: der Zustand liegt in
/// einem `thread_local!`, OPFS und das synchrone `XMLHttpRequest` gibt es nur
/// dort. `navigator.credentials` gibt es umgekehrt nur auf dem Hauptthread —
/// die Naht dazwischen ist die Nachrichtenform von
/// `apps/web/src/bridge/opfs-worker.ts`.
pub mod webauthn;

/// Die Reader-Ansichten: der EINE geoeffnete Bestand und seine SECHS Ausfuhren.
///
/// Das Modul steht OHNE cfg an der `mod`-Zeile, weil es Ausfuhren traegt und
/// die Regel „cfg am Item" dann fuer jede einzelne von ihnen gilt — dieselbe
/// Lage wie bei [`bridge`], [`fetch`], [`file_access`] und [`vault_bridge`]
/// und ausdruecklich nicht die von `opfs_worker`. Ein `pub mod`, weil
/// `tests/view_dto.rs` die reine Haelfte unter `ea_reader_wasm::view` misst.
///
/// Alle sechs Ausfuhren laufen IM DEDIZIERTEN WORKER: der Bestand liegt in
/// einem `thread_local!` neben den Tresorsitzungen, und die zwei
/// Oeffnungsausfuhren von [`file_access`] fuellen ihn dort. Hier faellt KEINE
/// Entscheidung: die Klassifikation kommt aus `ea_reader::ReaderVerifier`, die
/// Entschluesselung aus `ea_reader::decrypt_verified`, der Faden aus
/// `ea_reader::ReaderEntryThread`, die Suche aus `ea_reader::ReaderSearch` —
/// das Modul formt DTOs und rechnet nichts nach.
pub mod view;

/// Der Rundlauf ueber die Bruecke, ohne eine einzige Zusage darueber hinaus.
///
/// Die Funktion gibt zurueck, was ihr Aufrufer ihr reicht, versehen mit dem
/// Namen der Crate. Sie belegt damit BEIDE Richtungen: dass ein Argument die
/// Grenze erreicht und dass ein Wert sie wieder verlaesst. Ein Export, der nur
/// einen Rueckgabewert liefert, belegte die erste Haelfte nicht — genau die
/// Luecke, die `echo_from_js` im Spike `spikes/wasm-runtime-proof/src/lib.rs`
/// geschlossen hat.
#[must_use]
pub fn bridge_echo(value: &str) -> String {
    format!("ea-reader-wasm: {value}")
}

/// [`bridge_echo`], ausgefuehrt nach JavaScript.
///
/// `js_name` in lowerCamelCase, weil der Name auf der JS-Seite gelesen wird.
/// Die volle Qualifizierung des Attributs statt eines `use` im Kopf: ein
/// `use wasm_bindgen::prelude::*;` waere auf einem Wirtsziel unbenutzt und
/// muesste selbst ein cfg tragen.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(js_name = bridgeEcho)]
#[must_use]
pub fn bridge_echo_js(value: &str) -> String {
    bridge_echo(value)
}
