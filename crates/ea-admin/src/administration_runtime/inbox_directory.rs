//! Closed local transport intake. Exact captured bytes, never file flags, form an intent.
use super::{ceremony, inbox::ObservedRegistration, registration, views::current_view};
use crate::{
    OperatorLifecycleError, TrustCeremonyStep,
    operator_runtime::{OperatorRuntime, OperatorRuntimeError},
};
use ea_crypto::object_hash;
use ea_local_store::StoreValue;
use ea_types::{ObjectHash, UnixMillis};
use std::{collections::BTreeMap, fs, io::Read, path::Path};

const MAX_PAIRS: usize = 32;
const MAX_EXACT_BYTES: u64 = 65_536;
const MAX_JOURNAL_REQUESTS: i64 = 4096;
fn error() -> OperatorRuntimeError {
    OperatorLifecycleError::JournalConflict.into()
}
fn blob(bytes: &[u8]) -> StoreValue {
    StoreValue::Blob(bytes.to_vec())
}
struct Pair {
    request: Option<Vec<u8>>,
    target: Option<Vec<u8>>,
}
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.len() == b.len()
            && a.mtime() == b.mtime()
            && a.mtime_nsec() == b.mtime_nsec()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        a.len() == b.len() && a.modified().ok() == b.modified().ok()
    }
}
fn read_regular(path: &Path) -> Result<Vec<u8>, OperatorRuntimeError> {
    let before = fs::symlink_metadata(path).map_err(|_| error())?;
    if !before.is_file()
        || before.is_symlink()
        || before.len() == 0
        || before.len() > MAX_EXACT_BYTES
    {
        return Err(error());
    }
    let file = fs::File::open(path).map_err(|_| error())?;
    let opened = file.metadata().map_err(|_| error())?;
    if !opened.is_file() || !same_file(&before, &opened) {
        return Err(error());
    }
    let mut bytes = Vec::new();
    file.take(MAX_EXACT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| error())?;
    let after = fs::symlink_metadata(path).map_err(|_| error())?;
    if after.is_symlink() || !same_file(&before, &after) || bytes.len() as u64 != before.len() {
        return Err(error());
    }
    Ok(bytes)
}
struct CapturedPair {
    request: Vec<u8>,
    target: Vec<u8>,
}
fn read_pairs(path: &Path) -> Result<Vec<CapturedPair>, OperatorRuntimeError> {
    let before = fs::symlink_metadata(path).map_err(|_| error())?;
    if !before.is_dir() || before.is_symlink() {
        return Err(error());
    }
    let mut pairs = BTreeMap::<String, Pair>::new();
    for (index, entry) in fs::read_dir(path).map_err(|_| error())?.enumerate() {
        if index >= MAX_PAIRS * 2 {
            return Err(error());
        }
        let entry = entry.map_err(|_| error())?;
        let name = entry.file_name().into_string().map_err(|_| error())?;
        let (stem, is_request) = if let Some(stem) = name.strip_suffix(".registration.cbor") {
            (stem, true)
        } else if let Some(stem) = name.strip_suffix(".certificate-intent.cbor") {
            (stem, false)
        } else {
            return Err(error());
        };
        if stem.len() != 64
            || !stem
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(error());
        }
        let exact = read_regular(&entry.path())?;
        let pair = pairs.entry(stem.to_owned()).or_insert(Pair {
            request: None,
            target: None,
        });
        let slot = if is_request {
            &mut pair.request
        } else {
            &mut pair.target
        };
        if slot.replace(exact).is_some() {
            return Err(error());
        }
    }
    let after = fs::symlink_metadata(path).map_err(|_| error())?;
    if after.is_symlink() || !same_file(&before, &after) {
        return Err(error());
    }
    pairs
        .into_iter()
        .map(|(stem, pair)| {
            let request = pair.request.ok_or_else(error)?;
            let target = pair.target.ok_or_else(error)?;
            let hash = object_hash(&request);
            if hex::encode(hash.as_bytes()) != stem {
                return Err(error());
            }
            Ok(CapturedPair { request, target })
        })
        .collect()
}
pub(super) fn pending(
    runtime: &mut OperatorRuntime,
    directory: &Path,
) -> Result<Vec<ObservedRegistration>, OperatorRuntimeError> {
    current_view(runtime)?;
    let pairs = read_pairs(directory)?;
    // Validate the entire batch, including exact correspondence with earlier
    // intake, before the first insert. A current action never trusts a saved flag.
    for CapturedPair { request, target } in &pairs {
        registration::verify_material(runtime.anchor().organization_id(), request, target)?;
        let id = object_hash(target);
        let row=runtime.database().query_row(
            "SELECT source_bytes,target_payload,source_kind FROM administration_ceremony_intent WHERE intent_hash=?1",
            &[blob(id.as_bytes())])?;
        if let Some(row) = row {
            if row.integer(2)? != 1 || row.blob(0)? != request || row.blob(1)? != target {
                return Err(error());
            }
            ceremony::load(runtime, id)?;
        } else {
            registration::validate(runtime, request, target)?;
            // The same self-signed request cannot quietly acquire another intent.
            if runtime.database().query_row(
                "SELECT intent_hash FROM administration_ceremony_intent WHERE source_kind=1 AND source_bytes=?1",
                &[blob(request)])?.is_some() {return Err(error());}
        }
    }
    runtime.ensure_same_action_authority()?;
    runtime.database().transaction(|tx| {
        ceremony::affirm_persisted(runtime, tx)?;
        for CapturedPair { request, target } in &pairs {
            registration::insert_in(runtime, tx, request, target)?;
        }
        Ok::<(), OperatorRuntimeError>(())
    })?;
    runtime.ensure_same_action_authority()?;
    let count = runtime
        .database()
        .query_row(
            "SELECT COUNT(*) FROM administration_ceremony_intent WHERE source_kind=1",
            &[],
        )?
        .ok_or_else(error)?
        .integer(0)?;
    if !(0..=MAX_JOURNAL_REQUESTS).contains(&count) {
        return Err(error());
    }
    let mut pending = Vec::new();
    for offset in 0..count {
        let row=runtime.database().query_row(
            "SELECT intent_hash,source_bytes,target_payload,created_at FROM administration_ceremony_intent WHERE source_kind=1 ORDER BY intent_hash LIMIT 1 OFFSET ?1",
            &[StoreValue::Integer(offset)])?.ok_or_else(error)?;
        let id = ObjectHash::try_from(row.blob(0)?).map_err(|_| error())?;
        let request = registration::verify_material(
            runtime.anchor().organization_id(),
            row.blob(1)?,
            row.blob(2)?,
        )?;
        let ceremony = ceremony::load(runtime, id)?;
        if ceremony.step() == TrustCeremonyStep::TargetPublished
            && let Some(child) = ceremony.linked_ceremony_id()
            && ceremony::load(runtime, child)?.step() == TrustCeremonyStep::RegistryPublished
        {
            continue;
        }
        let received_at = UnixMillis::new(row.integer(3)?);
        if received_at.get() < 0 || received_at > runtime.head().preexisting_effective_now().value()
        {
            return Err(error());
        }
        pending.push(ObservedRegistration {
            request_hash: request.request_hash(),
            ceremony_id: id,
            certificate_kind: if request.core().requested_role == 0 {
                ea_format::CertificateKindV1::Writer
            } else {
                ea_format::CertificateKindV1::Reader
            },
            received_at,
        });
    }
    runtime.ensure_same_action_authority()?;
    Ok(pending)
}
