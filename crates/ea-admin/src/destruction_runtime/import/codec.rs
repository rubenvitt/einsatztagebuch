use super::*;
use minicbor::{Decoder, Encoder};
const SET_DOMAIN: &str = "EINSATZARCHIV-NATIVE-DESTRUCTION-IMPORT-SET";
const ADMISSION_DOMAIN: &str = "EINSATZARCHIV-NATIVE-DESTRUCTION-IMPORT-ADMISSION";
pub(super) struct Admission<'a> {
    pub set: &'a [u8],
    pub version: u64,
    pub head: &'a [u8],
    pub sequence: u64,
    pub now: i64,
    pub last: ObjectHash,
}
pub(super) fn encode_set(
    saved: &SavedDestruction,
    objects: &BTreeMap<ObjectHash, Vec<u8>>,
) -> Result<Vec<u8>, Error> {
    let job = saved.job.as_ref().ok_or(DestructionError::Storage)?;
    let mut bytes = Vec::new();
    (|| -> Result<(), minicbor::encode::Error<std::convert::Infallible>> {
        let mut e = Encoder::new(&mut bytes);
        e.array(8)?
            .str(SET_DOMAIN)?
            .u8(1)?
            .bytes(saved.auth.fields().organization_id.as_bytes())?
            .bytes(job.chain_id().as_bytes())?
            .bytes(saved.auth.fields().destruction_id.as_bytes())?
            .bytes(saved.auth.object_hash().as_bytes())?
            .bytes(job.job_hash().as_bytes())?
            .array(objects.len() as u64)?;
        for (hash, exact) in objects {
            e.array(2)?.bytes(hash.as_bytes())?.bytes(exact)?;
        }
        Ok(())
    })()
    .map_err(|_| DestructionError::Format)?;
    Ok(bytes)
}
pub(super) fn decode_set(
    exact: &[u8],
    saved: &SavedDestruction,
) -> Result<BTreeMap<ObjectHash, Vec<u8>>, Error> {
    let job = saved.job.as_ref().ok_or(DestructionError::Storage)?;
    let parsed = (|| -> Result<Vec<Vec<u8>>, minicbor::decode::Error> {
        let bad = || minicbor::decode::Error::message("invalid destruction import set");
        let mut d = Decoder::new(exact);
        if d.array()? != Some(8)
            || d.str()? != SET_DOMAIN
            || d.u8()? != 1
            || d.bytes()? != saved.auth.fields().organization_id.as_bytes()
            || d.bytes()? != job.chain_id().as_bytes()
            || d.bytes()? != saved.auth.fields().destruction_id.as_bytes()
            || d.bytes()? != saved.auth.object_hash().as_bytes()
            || d.bytes()? != job.job_hash().as_bytes()
        {
            return Err(bad());
        }
        let count = d.array()?.ok_or_else(bad)?;
        if count == 0 || count > MAX_NATIVE_DESTRUCTION_IMPORT_OBJECTS as u64 {
            return Err(bad());
        }
        let mut objects = Vec::new();
        let mut previous = None;
        for _ in 0..count {
            if d.array()? != Some(2) {
                return Err(bad());
            }
            let hash = ObjectHash::try_from(d.bytes()?).map_err(|_| bad())?;
            let object = d.bytes()?;
            if object_hash(object) != hash || previous.is_some_and(|old| old >= hash) {
                return Err(bad());
            }
            previous = Some(hash);
            objects.push(object.to_vec());
        }
        if d.position() != exact.len() {
            return Err(bad());
        }
        Ok(objects)
    })()
    .map_err(|_| DestructionError::Format)?;
    let objects = bounded_set(&parsed)?;
    if encode_set(saved, &objects)? != exact {
        return Err(DestructionError::Format.into());
    }
    Ok(objects)
}
pub(super) fn encode_context(
    set: &[u8],
    head: &ea_trust::SelectedRegistryHead,
    last: ObjectHash,
) -> Result<Vec<u8>, Error> {
    context_bytes(
        set,
        head.registry_version().get(),
        head.registry_head_hash().as_bytes(),
        head.proposed_sequence().get(),
        head.preexisting_effective_now().value().get(),
        last,
    )
}
fn context_bytes(
    set: &[u8],
    version: u64,
    head: &[u8],
    sequence: u64,
    now: i64,
    last: ObjectHash,
) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    (|| -> Result<(), minicbor::encode::Error<std::convert::Infallible>> {
        Encoder::new(&mut bytes)
            .array(8)?
            .str(ADMISSION_DOMAIN)?
            .u8(1)?
            .bytes(set)?
            .u64(version)?
            .bytes(head)?
            .u64(sequence)?
            .i64(now)?
            .bytes(last.as_bytes())?;
        Ok(())
    })()
    .map_err(|_| DestructionError::Format)?;
    Ok(bytes)
}
pub(super) fn decode_context(exact: &[u8]) -> Result<Admission<'_>, Error> {
    let parsed = (|| -> Result<Admission<'_>, minicbor::decode::Error> {
        let bad = || minicbor::decode::Error::message("invalid destruction import admission");
        let mut d = Decoder::new(exact);
        if d.array()? != Some(8) || d.str()? != ADMISSION_DOMAIN || d.u8()? != 1 {
            return Err(bad());
        }
        let result = Admission {
            set: d.bytes()?,
            version: d.u64()?,
            head: d.bytes()?,
            sequence: d.u64()?,
            now: d.i64()?,
            last: ObjectHash::try_from(d.bytes()?).map_err(|_| bad())?,
        };
        if d.position() != exact.len() || result.head.len() != 32 || result.now < 0 {
            return Err(bad());
        }
        Ok(result)
    })()
    .map_err(|_| DestructionError::Format)?;
    if context_bytes(
        parsed.set,
        parsed.version,
        parsed.head,
        parsed.sequence,
        parsed.now,
        parsed.last,
    )? != exact
    {
        return Err(DestructionError::Format.into());
    }
    Ok(parsed)
}
