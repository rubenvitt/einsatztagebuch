//! Die ZWEI Inhalte, die der normale Finalisierungspfad tragen kann.
//!
//! Ein `keyTransition` geht durch DIESELBEN dreizehn Schritte wie ein Einsatz
//! (`design.md` §9.3): derselbe Kopf, derselbe Kettenkopf, dieselbe Vorschau,
//! dieselbe Grenze, derselbe Veroeffentlichungspfad. Was sich unterscheidet,
//! ist der Inhalt von Schritt 4 und das Manifestfeld
//! `writer_transition_event_hash` — und genau das steht hier als geschlossene
//! Vereinigung, damit `finalize.rs` an JEDER Stelle, an der der Inhalt zaehlt,
//! ueber beide Arme entscheiden MUSS.
//!
//! Was hier NICHT steht: der Uebergangshash. Der Writer liest ihn aus dem
//! gewaehlten Kopf (`SelectedRegistryHead::effective_writer_transition`) und
//! nimmt ihn von keinem Aufrufer entgegen — ein Aufrufer, der ihn setzen
//! koennte, koennte einen Uebergang behaupten, den die Linie nie angewandt
//! hat.

use ea_schema::NativeSourceV1;

use crate::incident::FinalizationInputV1;

/// Der fachliche Inhalt eines abzuschliessenden `keyTransition`.
///
/// Zeitzone und Quelle sind dieselben Kopffelder, die auch ein Einsatz traegt
/// (siehe [`FinalizationInputV1`]); `recordId`, `finalizedAtDevice`, der
/// `operator`-Snapshot und die `registryVersion` entstehen wie dort in
/// Schritt 4 aus Sitzung, Profilzeile und gebundenem Head.
///
/// Die organisatorische Begruendung ist VERSIEGELT: sie geht in die
/// verschluesselte Nutzlast und in keine oeffentliche Archivmetadatenposition
/// (`design.md`:397).
pub struct KeyTransitionInputV1 {
    /// Die Geraetezeitzone, kanonisiert gegen die gepinnte tzdb — geprueft in
    /// `CommonHeaderV1::new`.
    pub timezone: String,
    pub source: NativeSourceV1,
    pub organizational_reason: String,
}

/// Was ein Lauf der dreizehn Schritte abschliesst.
///
/// Der Einsatz liegt in einer `Box`, weil seine Momentaufnahmen den Wert um
/// ein Vielfaches groesser machen als den Uebergang; der Inhalt wird GENAU
/// EINMAL in Schritt 4 entnommen, und nichts liest ihn davor.
pub(crate) enum FinalizationContent {
    Incident(Box<FinalizationInputV1>),
    KeyTransition(KeyTransitionInputV1),
}
