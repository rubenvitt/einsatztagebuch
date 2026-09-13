//! Fresh host composition for a previously signed destruction job. Local
//! signed chain progress and the persisted Registry pin are separate inputs.
use crate::{
    DirectoryHandleSource, ReaderBlobStore, ReaderCacheDestruction,
    ReaderDestructionInstructionBytes, ReaderObjectCache, UnlockedVault,
    VerifiedReaderDestructionInstruction,
};
use ea_archive::{ArchiveInventory, ArchiveSource};
use ea_crypto::{AEAD_NONCE_SIZE, SecretBytes, SecretVec, aead_open, aead_seal};
use ea_trust::{
    RegistryHeadPin, RegistrySelectionOutcome, load_trust_state, prepare_local_time,
    select_registry_head, verify_registry_candidate, verify_trust,
};
use ea_types::{ChainSequence, ObjectHash, RegistryVersion, UnixMillis};
use std::collections::BTreeSet;
const INVALID: &str = "EA-READER-DESTRUCTION-UNVERIFIED";
pub(crate) fn prepare(
    vault: &UnlockedVault,
    store: &mut dyn ReaderBlobStore,
    source: &dyn ArchiveSource,
    input: ReaderDestructionInstructionBytes<'_>,
    now: UnixMillis,
) -> Result<VerifiedReaderDestructionInstruction, &'static str> {
    prepare_with(vault, store, source, input, now, |_, _, _| Ok(())).map(|(proof, ())| proof)
}
pub(crate) fn prepare_with<T>(
    vault: &UnlockedVault,
    store: &mut dyn ReaderBlobStore,
    source: &dyn ArchiveSource,
    input: ReaderDestructionInstructionBytes<'_>,
    now: UnixMillis,
    inspect: impl FnOnce(
        &ArchiveInventory,
        &ea_trust::SelectedRegistryHead,
        &VerifiedReaderDestructionInstruction,
    ) -> Result<T, &'static str>,
) -> Result<(VerifiedReaderDestructionInstruction, T), &'static str> {
    if !store.inventory_is_complete() {
        return Err(INVALID);
    }
    let incoming = ArchiveInventory::build(source).map_err(|_| INVALID)?;
    if !incoming.quarantined().is_empty() || !incoming.format_errors().is_empty() {
        return Err(INVALID);
    }
    let mut combined = DirectoryHandleSource::new();
    let mut seen = BTreeSet::new();
    source
        .visit_blobs(&mut |blob| {
            if seen.insert(ea_crypto::object_hash(blob.bytes())) {
                combined.push_blob(blob.path_hint(), blob.bytes())?;
            }
            Ok(())
        })
        .map_err(|_| INVALID)?;
    let cache = ReaderObjectCache::open(vault);
    for key in store.keys().map_err(|_| INVALID)? {
        let Some(hash) = crate::cache::object_hash_of(&key) else {
            continue;
        };
        if !seen.insert(hash) {
            continue;
        }
        if let Some(bytes) = cache.get_unfiltered(store, hash).map_err(|_| INVALID)? {
            combined
                .push_blob("cached-exact-object", &bytes)
                .map_err(|_| INVALID)?;
        }
    }
    let anchor = vault.pinned_anchor();
    let (stored_pin, stored_time) = read(vault, store)?;
    let mut pin = vault.last_registry_pin().copied();
    if let Some(stored) = stored_pin {
        if let Some(vault_pin) = pin
            && stored.registry_version() == vault_pin.registry_version()
            && stored.registry_head_hash() != vault_pin.registry_head_hash()
        {
            return Err(INVALID);
        }
        if pin.is_none_or(|known| stored.registry_version() >= known.registry_version()) {
            pin = Some(stored);
        }
    }
    let now = vault.observe_effective_time(now.max(stored_time));
    let report = ea_verify::verify_archive(&combined, anchor, ea_verify::VerifyOptions::new(now))
        .map_err(|_| INVALID)?;
    let public = report.verified_public_chain_head().ok_or(INVALID)?;
    let core =
        ea_crypto::decode_destruction_preflight_core(input.preflight_core).map_err(|_| INVALID)?;
    let local_next = if report.entry_package_count() + report.destroyed_entry_count() == 0 {
        0
    } else {
        public.sequence().get().checked_add(1).ok_or(INVALID)?
    };
    let sequence = ChainSequence::new(core.execution_sequence.max(local_next));
    let inventory = ArchiveInventory::build(&combined).map_err(|_| INVALID)?;
    // A published future HEAD is not current action authority, but its
    // signed dependency chain must still be complete before physical removal.
    // Use its own signed sequence solely to verify historical provenance.
    if let Some((version, hash, sequence)) = inventory
        .trust()
        .iter()
        .filter_map(|object| match object.value().decoded_payload().ok()? {
            ea_format::DecodedTrustPayloadV1::RegistryEvent(event) => Some((
                event.fields().registry_version,
                object.object_hash(),
                event.fields().effective_from_sequence,
            )),
            _ => None,
        })
        .max_by_key(|(version, _, _)| *version)
    {
        ea_verify::historical_registry_head(&inventory, anchor, version, hash, sequence, now)
            .ok_or(INVALID)?;
    }
    let key = ea_verify::verification_state_key(anchor.organization_id());
    let mut state = ea_verify::EphemeralTrustStateStore::with_pin(key, now, pin);
    for _ in 0..=inventory.trust().len() {
        let trust = verify_trust(
            anchor,
            &inventory,
            load_trust_state(&mut state, key).map_err(|_| INVALID)?,
        )
        .map_err(|_| INVALID)?;
        let previous = trust.pinned_head().copied();
        let candidate = verify_registry_candidate(&trust, sequence).map_err(|_| INVALID)?;
        let mut sources = Vec::new();
        if let Some(authority) = candidate.preexisting_authority() {
            for receipt in inventory.receipts() {
                if let Ok(time) = ea_trust::verify_receipt_time(authority, receipt) {
                    sources.push(time)
                }
            }
            for evidence in inventory.evidence() {
                if let Ok(time) = ea_trust::verify_checkpoint_time(authority, evidence) {
                    sources.push(time)
                }
            }
        }
        let time =
            prepare_local_time(&mut state, &candidate, now, &sources).map_err(|_| INVALID)?;
        match select_registry_head(candidate, time, None).map_err(|_| INVALID)? {
            RegistrySelectionOutcome::Selected(head) => {
                if !previous.is_some_and(|pin| {
                    pin.registry_head_hash() == head.registry_head_hash()
                        && pin.registry_version() == head.registry_version()
                }) {
                    continue;
                }
                let proof = VerifiedReaderDestructionInstruction::verify(
                    &inventory,
                    anchor,
                    &head,
                    vault.kem_key_thumbprint(),
                    input,
                )?;
                let pin = RegistryHeadPin::new(head.registry_version(), head.registry_head_hash());
                let time = head.preexisting_effective_now().value();
                write(vault, store, pin, time)?;
                let (saved, saved_time) = read(vault, store)?;
                if saved.is_none_or(|saved| {
                    saved.registry_version() != pin.registry_version()
                        || saved.registry_head_hash() != pin.registry_head_hash()
                }) || saved_time != time
                {
                    return Err(INVALID);
                }
                let admitted = inspect(&inventory, &head, &proof)?;
                return Ok((proof, admitted));
            }
            RegistrySelectionOutcome::Advanced(_) => {}
            RegistrySelectionOutcome::PendingFuture(_) => return Err(INVALID),
        }
    }
    Err(INVALID)
}
pub(crate) fn affirm_execution(
    vault: &UnlockedVault,
    store: &mut dyn ReaderBlobStore,
    instruction: &VerifiedReaderDestructionInstruction,
) -> Result<(), &'static str> {
    let (pin, time) = read(vault, store)?;
    let time = vault.observe_effective_time(time);
    let expected = instruction.current_pin;
    if pin.is_some_and(|pin| {
        pin.registry_version() > expected.registry_version()
            || (pin.registry_version() == expected.registry_version()
                && pin.registry_head_hash() != expected.registry_head_hash())
    }) || time > instruction.current_time
    {
        return Err(INVALID);
    }
    write(vault, store, expected, instruction.current_time)?;
    let (pin, time) = read(vault, store)?;
    if pin.is_none_or(|pin| {
        pin.registry_version() != expected.registry_version()
            || pin.registry_head_hash() != expected.registry_head_hash()
    }) || time != instruction.current_time
    {
        return Err(INVALID);
    }
    Ok(())
}
pub(crate) fn observed_time(
    vault: &UnlockedVault,
    store: &dyn ReaderBlobStore,
) -> Result<UnixMillis, &'static str> {
    read(vault, store).map(|(_, time)| time)
}
fn read(
    vault: &UnlockedVault,
    store: &dyn ReaderBlobStore,
) -> Result<(Option<RegistryHeadPin>, UnixMillis), &'static str> {
    let address = ReaderCacheDestruction::authority_key(vault).map_err(|_| INVALID)?;
    let Some(bytes) = store.get(&address).map_err(|_| INVALID)? else {
        return Ok((None, UnixMillis::new(0)));
    };
    if bytes.len() < AEAD_NONCE_SIZE {
        return Err(INVALID);
    }
    let (nonce, ciphertext) = bytes.split_at(AEAD_NONCE_SIZE);
    let nonce = nonce.try_into().map_err(|_| INVALID)?;
    let opened = aead_open(
        &vault.cache_key().map_err(|_| INVALID)?,
        &SecretBytes::new(nonce),
        ciphertext,
        &crate::envelope::blob_aad(address.as_str().as_bytes()),
    )
    .map_err(|_| INVALID)?;
    opened.with_exposed(|bytes| {
        ea_cbor::validate(bytes, ea_cbor::ParserLimits::V1).map_err(|_| INVALID)?;
        let mut d = minicbor::Decoder::new(bytes);
        if d.array().map_err(|_| INVALID)? != Some(4)
            || d.str().map_err(|_| INVALID)? != "EINSATZARCHIV-READER-DESTRUCTION-AUTHORITY-v1"
        {
            return Err(INVALID);
        }
        let version = RegistryVersion::new(d.u64().map_err(|_| INVALID)?);
        let hash = ObjectHash::try_from(d.bytes().map_err(|_| INVALID)?).map_err(|_| INVALID)?;
        let time = UnixMillis::new(d.i64().map_err(|_| INVALID)?);
        if d.position() != bytes.len() {
            return Err(INVALID);
        }
        Ok((Some(RegistryHeadPin::new(version, hash)), time))
    })
}
fn write(
    vault: &UnlockedVault,
    store: &mut dyn ReaderBlobStore,
    pin: RegistryHeadPin,
    time: UnixMillis,
) -> Result<(), &'static str> {
    let address = ReaderCacheDestruction::authority_key(vault).map_err(|_| INVALID)?;
    let mut bytes = Vec::new();
    let mut e = minicbor::Encoder::new(&mut bytes);
    e.array(4)
        .unwrap()
        .str("EINSATZARCHIV-READER-DESTRUCTION-AUTHORITY-v1")
        .unwrap()
        .u64(pin.registry_version().get())
        .unwrap()
        .bytes(pin.registry_head_hash().as_bytes())
        .unwrap()
        .i64(time.get())
        .unwrap();
    let mut nonce = [0; AEAD_NONCE_SIZE];
    getrandom::fill(&mut nonce).map_err(|_| INVALID)?;
    let encrypted = aead_seal(
        &vault.cache_key().map_err(|_| INVALID)?,
        &SecretBytes::new(nonce),
        SecretVec::new(bytes),
        &crate::envelope::blob_aad(address.as_str().as_bytes()),
    )
    .map_err(|_| INVALID)?;
    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&encrypted);
    store.put(&address, &blob).map_err(|_| INVALID)
}
