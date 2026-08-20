//! `operatorProfileCommitment`, aus der Profilzeile NACHGERECHNET.
//!
//! Es entsteht KEIN neues Byte-Urbild: Praeimage, Domaintrennung,
//! Kanonisierung und Feldreihenfolge sind in Stufe 1 eingefroren
//! (`design.md`:242-252, `crates/ea-crypto/src/digest.rs` mit
//! `OPERATOR_PROFILE_DOMAIN`, und dieselben fuenf Felder in derselben
//! Reihenfolge wie der `operator`-Snapshot des signierten Kopfes,
//! `crates/ea-schema/src/encode.rs`).
//!
//! Der Kodierer steht HIER, weil es keinen zweiten Verbraucher gibt: die
//! Zusage wird nur beim Abschluss nachgerechnet. Er kodiert die FUENF
//! Zusageeingaben und ausdruecklich NICHT den `operatorBindingObjectHash` —
//! der ist Teil des Snapshots, aber nicht des Urbilds, und ihn mitzunehmen
//! ergaebe einen Wert, den die Root-signierte Bindung nie tragen kann.

use ea_draft::OperatorProfile;
use ea_types::Hash32;
use minicbor::Encoder;

use crate::WriterError;

/// Rechnet die Profilzusage aus der Profilzeile nach.
///
/// # Errors
///
/// [`WriterError::OperatorProfileCommitment`], wenn das Kodieren nicht gelingt
/// — dann ist der Vergleich nicht durchfuehrbar, und fail-closed heisst hier
/// ablehnen.
pub(crate) fn operator_profile_commitment(
    profile: &OperatorProfile,
) -> Result<Hash32, WriterError> {
    let mut bytes = Vec::with_capacity(128);
    Encoder::new(&mut bytes)
        .array(5)
        .and_then(|encoder| encoder.bytes(profile.organization_id().as_bytes()))
        .and_then(|encoder| encoder.bytes(profile.operator_subject_id().as_bytes()))
        .and_then(|encoder| encoder.str(profile.display_name()))
        .and_then(|encoder| encoder.str(profile.function_label()))
        .and_then(|encoder| encoder.bytes(profile.profile_commitment_salt()))
        .map_err(|_| WriterError::OperatorProfileCommitment)?;
    Ok(ea_crypto::operator_profile_digest(&bytes))
}
