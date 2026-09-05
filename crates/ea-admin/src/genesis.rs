//! Schritt 11, erste Haelfte: Genesis als Sequenz 0.
//!
//! # Hier steht KEIN zweiter Genesis-Kodierer
//!
//! Das ist die tragende Entscheidung dieser Datei. Der Genesis-Koerper aus
//! `docs/superpowers/specs/2026-08-14-einsatzarchiv-v0-1-payload-wire-addendum.md:90-101`
//! — `[organizationId, chainId, initialWriterCertificateObjectHash,
//! formatVersion, "EINSATZARCHIV-SUITE-1", initialPolicyObjectHash]` — ist im
//! Baum bereits umgesetzt: [`ea_schema::GenesisV1`] traegt die sechs Felder
//! samt eigener Pruefung (`crates/ea-schema/src/model.rs:258-330`), und
//! `encode_genesis` schreibt sie (`crates/ea-schema/src/encode.rs:462-478`).
//! Ledgerzeile FR-001 fuehrt das als `integrated`.
//!
//! Diese Datei kodiert deshalb nichts. Sie nimmt den fertigen
//! [`ea_schema::GenesisV1`] entgegen und stellt genau die drei Aussagen fest,
//! die die Zeremonie und nicht das Schema treffen kann — die Regel dieser
//! Crate, wie sie `crates/ea-admin/src/root_ceremony.rs` fuer den Kernhash
//! schon einmal ausspricht: eine zweite Kopie waere eine zweite Wahrheit.
//!
//! # Die drei Aussagen
//!
//! 1. **Sequenz 0 ohne Vorgaenger.** „Fuer Genesis ist
//!    `previous-entry-hash = null`; danach sind exakt 32 Bytes erforderlich"
//!    (`design.md:927`). Beides gehoert zur Huelle `eip-v1` und nicht zum
//!    Genesis-Koerper, also kann [`ea_schema::GenesisV1`] es strukturell nicht
//!    sehen.
//! 2. **Die Kennungen dieser Zeremonie.** Der Genesis-Koerper nennt
//!    Organisation und Kette; ob es DIE der laufenden Zeremonie sind, weiss
//!    nur die Zeremonie.
//! 3. **Der letzte Registrierungskopf.** „Genesis bindet den so entstandenen
//!    letzten Head" (`:1145`). Der Kopf entsteht in Schritt 10; Genesis muss
//!    ihn nennen und nicht einen frueheren.
//!
//! # Was hier NICHT entsteht
//!
//! Der `genesisEntryHash` selbst. Er ist
//! `ea_crypto::entry_hash(recordDigest, exactWriterCose)` und verlangt damit
//! eine ECHTE Writer-Finalisierung — die lebt in `ea-writer` und hat heute
//! keinen Port hierher. Der Wert kommt folgerichtig vom Wirt, wie schon der
//! Wurzelgriff in `RootCeremonyService::new`. Diese Datei bindet ihn nur an
//! die drei Aussagen oben, damit der finale Anker (`:1346`) ihn nicht
//! ungeprueft uebernimmt.

use ea_schema::GenesisV1;
use ea_types::{ChainId, ChainSequence, EntryHash, ObjectHash, OrganizationId, RegistryVersion};

use crate::AdminError;

/// Die Huellenfelder des Genesis-Eintrags aus `eip-v1`.
///
/// Sie stehen NICHT im Genesis-Koerper aus dem Nutzlastnachtrag `:90-101` und
/// koennen deshalb von [`ea_schema::GenesisV1`] strukturell nicht geprueft
/// werden — sie gehoeren der Huelle (`design.md:927`). Als Buendel, weil sie
/// zusammen genau eine Aussage bilden: „dies ist der erste Eintrag der Kette".
pub struct GenesisEnvelopeV1 {
    /// Die Kettensequenz. Fuer Genesis 0.
    pub chain_sequence: ChainSequence,
    /// Die Vorgaengerbindung. Fuer Genesis `None` (`design.md:927`).
    pub previous_entry_hash: Option<EntryHash>,
    /// Der Eintragshash, den die Writer-Finalisierung erzeugt hat.
    pub genesis_entry_hash: EntryHash,
}

/// Der gepruefte Genesis-Bezug fuer den finalen Anker.
///
/// Private Felder und kein oeffentlicher Konstruktor: er ist die
/// Eintrittskarte in
/// [`BootstrapCoordinator::create_genesis_and_final_anchor`], und eine frei
/// baubare Eintrittskarte waere keine.
///
/// [`BootstrapCoordinator::create_genesis_and_final_anchor`]: crate::BootstrapCoordinator::create_genesis_and_final_anchor
pub struct GenesisBinding {
    genesis_entry_hash: EntryHash,
    registry_version: RegistryVersion,
}

impl GenesisBinding {
    /// Der Eintragshash, der in `genesis-entry-hash` des finalen Ankers geht
    /// (`:1346`, CDDL `:1750-1763`).
    #[must_use]
    pub const fn genesis_entry_hash(&self) -> EntryHash {
        self.genesis_entry_hash
    }

    /// Die Registrierungsfassung des Kopfes, den dieser Genesis bindet
    /// (`:1145`).
    #[must_use]
    pub const fn registry_version(&self) -> RegistryVersion {
        self.registry_version
    }
}

/// Bindet einen fertigen Genesis an die laufende Zeremonie.
///
/// `genesis` ist der vom Wirt gebaute und von `ea-schema` bereits gegen den
/// Koerper aus dem Nutzlastnachtrag `:90-101` validierte Datensatz;
/// `envelope` traegt die Huellenfelder aus `eip-v1` samt dem aus der
/// Writer-Finalisierung entstandenen Eintragshash.
///
/// # Errors
/// [`AdminError::GenesisSequence`] mit `EA-CEREMONY-GENESIS-SEQUENCE`, wenn
/// die Sequenz nicht 0 ist oder ein Vorgaengerhash anliegt (`design.md:927`);
/// [`AdminError::GenesisContextMismatch`] mit
/// `EA-CEREMONY-GENESIS-CONTEXT-MISMATCH`, wenn Organisation, Kette, initiale
/// Richtlinie oder der gebundene Registrierungskopf nicht die dieser Zeremonie
/// sind.
pub fn bind_genesis(
    genesis: &GenesisV1,
    organization_id: OrganizationId,
    chain_id: ChainId,
    initial_policy_object_hash: ObjectHash,
    last_registry_head_version: RegistryVersion,
    envelope: &GenesisEnvelopeV1,
) -> Result<GenesisBinding, AdminError> {
    if envelope.chain_sequence.get() != 0 || envelope.previous_entry_hash.is_some() {
        return Err(AdminError::GenesisSequence);
    }
    if genesis.organization_id() != organization_id
        || genesis.chain_id() != chain_id
        || genesis.initial_policy_object_hash() != initial_policy_object_hash
        || genesis.header().registry_version() != last_registry_head_version
    {
        return Err(AdminError::GenesisContextMismatch);
    }
    Ok(GenesisBinding {
        genesis_entry_hash: envelope.genesis_entry_hash,
        registry_version: last_registry_head_version,
    })
}
