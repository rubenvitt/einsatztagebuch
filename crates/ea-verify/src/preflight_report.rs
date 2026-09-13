//! Strict decoding of the existing canonical, fully successful report in a
//! signed preflight job. This validates the claim's shape and target coverage;
//! it does not authenticate its signer or mint archive/current authority.
use crate::{
    AuthorizedDestructionV1, ChainHeadV1, DestructionStateV1, ObjectResultKindV1, ObjectResultV1,
    ObjectTypeV1, ServerConfirmationV1, VerificationReportV1,
};
use ea_types::{
    ChainId, ChainSequence, DestructionId, EntryHash, KeyThumbprint, ObjectHash, RegistryVersion,
};
use serde_json::Value;
const INVALID: &str = "EA-VERIFY-DESTRUCTION-PREFLIGHT-REPORT";
pub fn verify_destruction_preflight_report(
    exact: &[u8],
    chain: ChainId,
    targets: &[(EntryHash, ChainSequence, ObjectHash)],
) -> Result<(), &'static str> {
    let value: Value = serde_json::from_slice(exact).map_err(|_| INVALID)?;
    if value["schemaId"].as_str() != Some("ea.verification-report/v1") || targets.is_empty() {
        return Err(INVALID);
    }
    let h = &value["chainHead"];
    let head = ChainHeadV1::new(
        ChainId::try_from(hex::<16>(&h["chainId"])?.as_slice()).map_err(|_| INVALID)?,
        ChainSequence::new(uint(&h["sequence"])?),
        EntryHash::try_from(hex::<32>(&h["entryHash"])?.as_slice()).map_err(|_| INVALID)?,
    );
    if head.chain_id() != chain {
        return Err(INVALID);
    }
    let mut report = VerificationReportV1::empty(head);
    report.archive_object_count = count(&value["archiveObjectCount"])?;
    report.entry_package_count = count(&value["entryPackageCount"])?;
    report.destroyed_entry_count = count(&value["destroyedEntryCount"])?;
    report.non_object_file_count = count(&value["nonObjectFileCount"])?;
    for key in [
        "gaps",
        "formatErrors",
        "quarantinedObjects",
        "signatureErrors",
        "evidenceErrors",
        "decryptionErrors",
    ] {
        if !array(&value[key])?.is_empty() {
            return Err(INVALID);
        }
    }
    for value in array(&value["registryVersions"])? {
        report
            .registry_versions
            .insert(RegistryVersion::new(uint(value)?));
    }
    for value in array(&value["publicKeyThumbprints"])? {
        report
            .public_key_thumbprints
            .insert(KeyThumbprint::try_from(hex::<32>(value)?.as_slice()).map_err(|_| INVALID)?);
    }
    for value in array(&value["objectResults"])? {
        let hash = ObjectHash::try_from(hex::<32>(&value["objectHash"])?.as_slice())
            .map_err(|_| INVALID)?;
        let kind = match uint(&value["objectType"])? {
            1 => ObjectTypeV1::Entry,
            2 => ObjectTypeV1::Grant,
            3 => ObjectTypeV1::Receipt,
            4 => ObjectTypeV1::Evidence,
            5 => ObjectTypeV1::Trust,
            6 => ObjectTypeV1::Destroyed,
            _ => return Err(INVALID),
        };
        let result = match value["result"].as_str() {
            Some("valid") => ObjectResultKindV1::Valid,
            Some("authorizedDestroyed") => ObjectResultKindV1::AuthorizedDestroyed,
            _ => return Err(INVALID),
        };
        let confirmation = match value["serverConfirmation"].as_str() {
            Some("serverConfirmed") => ServerConfirmationV1::ServerConfirmed,
            Some("notServerConfirmed") => ServerConfirmationV1::NotServerConfirmed,
            _ => return Err(INVALID),
        };
        if (kind == ObjectTypeV1::Destroyed) != (result == ObjectResultKindV1::AuthorizedDestroyed)
        {
            return Err(INVALID);
        }
        report
            .object_results
            .insert(hash, ObjectResultV1::new(hash, kind, result, confirmation));
    }
    for value in array(&value["authorizedDestructions"])? {
        let id = DestructionId::try_from(hex::<16>(&value["destructionId"])?.as_slice())
            .map_err(|_| INVALID)?;
        let authorization =
            ObjectHash::try_from(hex::<32>(&value["authorizationObjectHash"])?.as_slice())
                .map_err(|_| INVALID)?;
        let state = (0..=4)
            .filter_map(DestructionStateV1::from_code)
            .find(|state| Some(state.as_str()) == value["state"].as_str())
            .ok_or(INVALID)?;
        report
            .authorized_destructions
            .insert(id, AuthorizedDestructionV1::new(id, authorization, state));
    }
    report.pipeline_completed = true;
    let report = report.seal().map_err(|_| INVALID)?;
    // Reusing the original writer checks every field, order, duplicate,
    // reportHash and numeric representation, including nested unknown fields.
    if report.to_canonical_json().map_err(|_| INVALID)?.as_bytes() != exact
        || !report.is_fully_verified()
    {
        return Err(INVALID);
    }
    if report
        .object_results()
        .filter(|r| r.object_type() == ObjectTypeV1::Entry)
        .count()
        != report.entry_package_count()
        || report
            .object_results()
            .filter(|r| r.object_type() == ObjectTypeV1::Destroyed)
            .count()
            != report.destroyed_entry_count()
        || report
            .entry_package_count()
            .checked_add(report.destroyed_entry_count())
            .is_none_or(|count| count > report.archive_object_count())
        || targets.len() > report.entry_package_count()
    {
        return Err(INVALID);
    }
    let mut entries = std::collections::BTreeSet::new();
    let mut originals = std::collections::BTreeSet::new();
    for (entry, sequence, original) in targets {
        if !entries.insert(*entry)
            || !originals.insert(*original)
            || *sequence > head.sequence()
            || (*sequence == head.sequence() && *entry != head.entry_hash())
            || !report.object_results.get(original).is_some_and(|result| {
                result.object_type() == ObjectTypeV1::Entry
                    && result.result() == ObjectResultKindV1::Valid
            })
        {
            return Err(INVALID);
        }
    }
    Ok(())
}
fn uint(value: &Value) -> Result<u64, &'static str> {
    value.as_u64().ok_or(INVALID)
}
fn count(value: &Value) -> Result<usize, &'static str> {
    usize::try_from(uint(value)?).map_err(|_| INVALID)
}
fn array(value: &Value) -> Result<&[Value], &'static str> {
    value.as_array().map(Vec::as_slice).ok_or(INVALID)
}
fn hex<const N: usize>(value: &Value) -> Result<[u8; N], &'static str> {
    let text = value.as_str().ok_or(INVALID)?.as_bytes();
    if text.len() != N * 2 {
        return Err(INVALID);
    }
    let nibble = |b: u8| match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(INVALID),
    };
    let mut out = [0; N];
    for (index, pair) in text.chunks_exact(2).enumerate() {
        out[index] = nibble(pair[0])? * 16 + nibble(pair[1])?;
    }
    Ok(out)
}
