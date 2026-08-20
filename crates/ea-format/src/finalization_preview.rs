//! Das Urbild der Abschlussvorschau — `finalization-preview-core-v1`.
//!
//! EIN geschlossener, deterministisch kodierter Kern mit dreizehn Positionen
//! und nichts sonst. Seine Grammatik steht normativ in
//! `schemas/reports/v1/finalization-preview.cddl`, seine Hashregel im
//! Wire-Format-Addendum, und `ea-crypto` traegt die domaingetrennte
//! Digestfunktion darueber
//! ([`ea_crypto::finalization_preview_digest`]).
//!
//! # Warum die Feldliste die Sicherheitsentscheidung IST
//!
//! `finalize` rechnet `previewHash` unter dem Writer-Lock nach und weist jede
//! Abweichung fail-closed ab. Die Zusage „eine andere oder neu gebaute Vorschau
//! wird abgelehnt, und jeder Replay scheitert" gilt genau so weit, wie dieses
//! Urbild alles deckt, worauf `finalize` handelt. Eine fehlende Position ist
//! deshalb kein Schoenheitsfehler, sondern ein Feld, das die Bestaetigung nicht
//! mehr abdeckt.
//!
//! # Was hier NICHT vorkommt
//!
//! Kein Einsatztext, kein Ausgabepfad, kein Bedienername — jede Position ist
//! ein festbreiter Skalar, `null` oder die leere Erweiterungsliste. Die
//! Vorschau reist ueber eine Oberflaeche und in eine signierte Auditzeile; ein
//! Freitextfeld waere Klartext an beiden Stellen.
//!
//! # Was hier NICHT geprueft wird
//!
//! Die Kopplung „Sequenz null genau dann, wenn kein Vorgaenger" steht in
//! [`crate::ManifestCoreV1::new`] und wird hier ABSICHTLICH nicht wiederholt.
//! Der Vorschaukern ist ein Hashurbild und kein Archivobjekt; eine zweite
//! Durchsetzungsstelle waere eine zweite Quelle derselben Wahrheit, und die
//! Vorschau entsteht ohnehin VOR dem Schritt, der `manifestCore` baut.

use minicbor::Encoder;

use ea_types::{
    ChainId, ChainSequence, EntryHash, Hash32, ObjectHash, OrganizationId, RegistryVersion,
    UnixMillis,
};

use crate::FormatError;

/// Die elf offenen Eingabefelder von `finalization-preview-core-v1`.
///
/// Ohne das Versionsliteral und ohne die leere Erweiterungsliste: beide
/// schreibt der Kodierer selbst, damit kein Aufrufer sie waehlen kann. Nach dem
/// Muster von [`crate::ArchiveBackendProfileCoreFieldsV1`].
// KEIN `Debug`: `ObjectHash`, `EntryHash` und `Hash32` tragen in Stufe 1
// absichtlich keines, damit kein Hashwert versehentlich in ein Protokoll
// geraet. Ein `Debug` hier zoege es fuer den ganzen Kern nach.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FinalizationPreviewCoreFieldsV1 {
    pub organization_id: OrganizationId,
    pub chain_id: ChainId,
    /// Der Kopf des gebundenen Registry-Head.
    pub registry_head_hash: Hash32,
    pub registry_version: RegistryVersion,
    /// `notAfter` desselben Head — die Zeitgrenze, die die Vorschau anzeigt.
    pub registry_not_after: UnixMillis,
    pub policy_object_hash: ObjectHash,
    /// Die Sequenz, die diese Finalisierung beansprucht.
    pub proposed_sequence: ChainSequence,
    /// Der direkte Vorgaenger, oder `None` ohne Vorgaenger.
    pub previous_entry_hash: Option<EntryHash>,
    /// [`ea_crypto::record_digest`] ueber den EXAKTEN, deterministisch
    /// serialisierten Nutzlastsatz von Spec-Schritt 4 — NICHT ueber den
    /// `signedManifest`, der erst nach der einmaligen CSPRNG-Ziehung von
    /// Schritt 6 existiert.
    pub record_digest: Hash32,
    /// Genau der `initialGrantPlanHash`, den
    /// [`crate::GrantPlanV1::new`] selbst rechnet.
    pub grant_plan_digest: Hash32,
    /// Die wirksame Zeit des gewaehlten Head zum Zeitpunkt der Vorschau.
    pub effective_now: UnixMillis,
}

/// Der Vorschaukern.
///
/// Private Felder und EIN Konstruktor, wie bei den uebrigen Kernen dieser
/// Crate: ein frei gesetztes Feld waere ein Kern, dessen Digest niemand
/// nachrechnen kann.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FinalizationPreviewCoreV1 {
    fields: FinalizationPreviewCoreFieldsV1,
}

impl FinalizationPreviewCoreV1 {
    /// Die Strukturversion an Position eins. Der Kodierer schreibt sie.
    pub const STRUCTURE_VERSION: u64 = 1;

    /// Die Zahl der Arraypositionen — dreizehn, gepinnt von
    /// `tools/xtask/tests/spec_completeness.rs` gegen die Grammatik.
    pub const POSITIONS: u64 = 13;

    /// Baut den Kern.
    ///
    /// Unfehlbar, weil es hier NICHTS zu pruefen gibt: jedes Feld ist ein
    /// festbreiter, in Stufe 1 schon validierter Typ, und die einzige denkbare
    /// Querbedingung — Sequenz null genau dann, wenn kein Vorgaenger — gehoert
    /// [`crate::ManifestCoreV1::new`] und wird hier nicht verdoppelt.
    #[must_use]
    pub const fn new(fields: FinalizationPreviewCoreFieldsV1) -> Self {
        Self { fields }
    }

    #[must_use]
    pub const fn fields(&self) -> &FinalizationPreviewCoreFieldsV1 {
        &self.fields
    }
}

/// Die deterministischen `finalization-preview-core-v1`-Bytes.
///
/// # Errors
///
/// [`FormatError::Shape`], wenn das Kodieren nicht gelingt.
pub fn encode_finalization_preview_core(
    core: &FinalizationPreviewCoreV1,
) -> Result<Vec<u8>, FormatError> {
    let fields = &core.fields;
    let mut bytes = Vec::with_capacity(256);
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .array(FinalizationPreviewCoreV1::POSITIONS)
        .and_then(|encoder| encoder.u64(FinalizationPreviewCoreV1::STRUCTURE_VERSION))
        .and_then(|encoder| encoder.bytes(fields.organization_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.chain_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.registry_head_hash.as_bytes()))
        .and_then(|encoder| encoder.u64(fields.registry_version.get()))
        .and_then(|encoder| encoder.i64(fields.registry_not_after.get()))
        .and_then(|encoder| encoder.bytes(fields.policy_object_hash.as_bytes()))
        .and_then(|encoder| encoder.u64(fields.proposed_sequence.get()))
        .map_err(|_| FormatError::Shape)?;
    match fields.previous_entry_hash {
        Some(previous) => encoder.bytes(previous.as_bytes()).map(|_| ()),
        None => encoder.null().map(|_| ()),
    }
    .map_err(|_| FormatError::Shape)?;
    encoder
        .bytes(fields.record_digest.as_bytes())
        .and_then(|encoder| encoder.bytes(fields.grant_plan_digest.as_bytes()))
        .and_then(|encoder| encoder.i64(fields.effective_now.get()))
        .and_then(|encoder| encoder.array(0))
        .map_err(|_| FormatError::Shape)?;
    Ok(bytes)
}
