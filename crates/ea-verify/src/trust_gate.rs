//! Gate `trust` über den GESAMTEN Bestand — die EINE Stelle für den Prüflauf
//! ([`crate::verify_archive`]) und die historische Autorität
//! ([`crate::historical_registry_head`]).
//!
//! `verify_trust` allein prüft kein Objekt der drei Escrow-Familien
//! (Freigabe, Escrow, Öffnungsautorisierung). Hier kommt deshalb
//! `verify_reader_key_escrows` gegen das Ende der Katalog-Linie dazu: ein
//! einziges ungültiges Familienobjekt oder zwei widersprüchliche gültige
//! Escrows lassen das Gate für den ganzen Bestand scheitern (v1.1-Profil §9,
//! Ruling Q11). Ohne Familienobjekt wird dafür keine Linie nachgespielt.
//!
//! Die Cutover-Vorbedingung (aktive `webBundleRelease` eines v1.1-fähigen
//! Bundles) prüft der Offline-Prüfer bewusst NICHT: sie ist gegen die
//! Initialwurzel gepinnt und würde nach einer Wurzelrotation jedes Archiv mit
//! Escrow unprüfbar machen. Sie bleibt eine Regel der Publikation und der
//! Serverannahme.
use ea_archive::ArchiveInventory;
use ea_trust::{
    ReaderKeyEscrowHead, TrustAnchorV1, TrustStateKey, VerifiedTrust, load_trust_state,
    verify_reader_key_escrows, verify_trust,
};

use crate::state::EphemeralTrustStateStore;

/// Lädt den Stand und prüft Vertrauenskette und Escrow-Menge gegen den Anker.
///
/// `None` ist FAIL-CLOSED für den gesamten Bestand.
pub(crate) fn verified_trust(
    store: &mut EphemeralTrustStateStore,
    key: TrustStateKey,
    anchor: &TrustAnchorV1,
    inventory: &ArchiveInventory,
) -> Option<VerifiedTrust> {
    let snapshot = load_trust_state(store, key).ok()?;
    let trust = verify_trust(anchor, inventory, snapshot).ok()?;
    verify_reader_key_escrows(&trust, ReaderKeyEscrowHead::CatalogLineTip).ok()?;
    Some(trust)
}
