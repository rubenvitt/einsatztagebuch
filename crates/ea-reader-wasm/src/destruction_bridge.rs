//! Delivery of signed jobs to complete OPFS inventory and durable local measurement.
/// Shape/size admission only. All signatures, identities and authority remain
/// the responsibility of the existing actual Reader Apply path below.
#[cfg(any(test, target_arch = "wasm32"))]
fn decode_delivery_upload(
    authorization: &[u8],
    event: &[u8],
    upload: &[u8],
) -> Result<ea_reader::DestructionJobUploadV1, &'static str> {
    if authorization.is_empty()
        || event.is_empty()
        || authorization.len() > ea_reader::ETB_MAX_RAW_BYTES_V1
        || event.len() > ea_reader::ETB_MAX_RAW_BYTES_V1
    {
        return Err("EA-READER-DESTRUCTION-UNVERIFIED");
    }
    ea_reader::DestructionJobUploadV1::decode(upload)
        .map_err(|_| "EA-READER-DESTRUCTION-UNVERIFIED")
}

/// Three existing public originals, not a new container or authority token.
/// Invalid shapes are refused before consuming the registered directory source.
/// Valid shapes delegate to the unchanged session/source/OPFS Apply boundary.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerDestructionApplyDelivery")]
pub async fn reader_destruction_apply_delivery(
    session: u32,
    source: u32,
    authorization: Vec<u8>,
    event: Vec<u8>,
    job_upload: Vec<u8>,
    now: i64,
) -> Result<String, JsValue> {
    let upload =
        decode_delivery_upload(&authorization, &event, &job_upload).map_err(JsValue::from_str)?;
    reader_destruction_apply(
        session,
        source,
        authorization,
        event,
        upload.core_bytes().to_vec(),
        upload.signature_bytes().to_vec(),
        upload.inventory_bytes().to_vec(),
        upload.certificate_hash().as_bytes().to_vec(),
        now,
    )
    .await
}

#[cfg(target_arch = "wasm32")]
use crate::{opfs_worker::OpfsBlobStore, vault_bridge::with_unlocked_vault};
#[cfg(target_arch = "wasm32")]
use ea_reader::{
    ReaderCacheDestruction, ReaderCacheRemovalReceipt, ReaderDestructionInstructionBytes,
    UnixMillis,
};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
struct ActionClock {
    started_at: f64,
    effective_start: UnixMillis,
    performance: web_sys::Performance,
}
#[cfg(target_arch = "wasm32")]
impl ActionClock {
    fn start(effective_start: UnixMillis) -> Result<Self, JsValue> {
        let performance = js_sys::global()
            .dyn_into::<web_sys::WorkerGlobalScope>()
            .map_err(|_| JsValue::from_str("EA-READER-DESTRUCTION-CLOCK"))?
            .performance()
            .ok_or_else(|| JsValue::from_str("EA-READER-DESTRUCTION-CLOCK"))?;
        let started_at = performance.now();
        if !started_at.is_finite() {
            return Err(JsValue::from_str("EA-READER-DESTRUCTION-CLOCK"));
        }
        Ok(Self {
            started_at,
            effective_start,
            performance,
        })
    }
    fn now(&self) -> Result<UnixMillis, JsValue> {
        let elapsed = (self.performance.now() - self.started_at).ceil();
        if !elapsed.is_finite() || elapsed < 0.0 || elapsed >= i64::MAX as f64 {
            return Err(JsValue::from_str("EA-READER-DESTRUCTION-CLOCK"));
        }
        self.effective_start
            .get()
            .checked_add(elapsed as i64)
            .map(UnixMillis::new)
            .ok_or_else(|| JsValue::from_str("EA-READER-DESTRUCTION-CLOCK"))
    }
}
#[cfg(target_arch = "wasm32")]
fn receipt_json(receipt: &ReaderCacheRemovalReceipt) -> String {
    let mut json = crate::bridge::Json::object();
    json.string("jobHash", &hex::encode(receipt.job_hash().as_bytes()));
    json.string("replicaId", &hex::encode(receipt.replica_id().as_bytes()));
    json.raw(
        "removedObjectHashes",
        &format!(
            "[{}]",
            receipt
                .removed_object_hashes()
                .iter()
                .map(|hash| format!("\"{}\"", hex::encode(hash.as_bytes())))
                .collect::<Vec<_>>()
                .join(",")
        ),
    );
    json.raw(
        "remainingObjectCount",
        &receipt.remaining_object_count().to_string(),
    );
    json.finish()
}
/// No key material crosses this boundary. The result is a local measurement,
/// not the component's separately signed v1 deletion attestation.
#[allow(clippy::too_many_arguments)]
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerDestructionApply")]
pub async fn reader_destruction_apply(
    session: u32,
    source: u32,
    authorization: Vec<u8>,
    event: Vec<u8>,
    core: Vec<u8>,
    signature: Vec<u8>,
    inventory: Vec<u8>,
    certificate: Vec<u8>,
    now: i64,
) -> Result<String, JsValue> {
    // Awaiting OPFS leases must not freeze action/session time. The caller's
    // observed wall time remains bounded below by actual monotone elapsed time.
    let clock = ActionClock::start(UnixMillis::new(now))?;
    let source = crate::file_access::take_directory_source(source)?;
    let now =
        crate::file_access::observe_grant_time(session, &source, UnixMillis::new(now)).await?;
    let certificate = certificate
        .as_slice()
        .try_into()
        .map_err(|_| JsValue::from_str("EA-READER-DESTRUCTION-UNVERIFIED"))?;
    let authority = with_unlocked_vault(session, now, ReaderCacheDestruction::authority_key)?
        .map_err(|e| JsValue::from_str(e.code()))?;
    let journal = ReaderCacheDestruction::journal_key().map_err(|e| JsValue::from_str(e.code()))?;
    let mut store = OpfsBlobStore::open_all("ea-reader", &[authority, journal])
        .await
        .map_err(|e| JsValue::from_str(e.code()))?;
    let now = now.max(clock.now()?);
    let proof = with_unlocked_vault(session, now, |vault| {
        ReaderCacheDestruction::prepare(
            vault,
            &mut store,
            &source,
            ReaderDestructionInstructionBytes {
                authorization: &authorization,
                initiating_event: &event,
                preflight_core: &core,
                preflight_signature: &signature,
                inventory: &inventory,
                preflight_certificate: certificate,
            },
            now,
        )
    })?
    .map_err(JsValue::from_str)?;
    let selected_time = with_unlocked_vault(session, now, |vault| {
        ReaderCacheDestruction::observed_authority_time(vault, &store)
    })?
    .map_err(JsValue::from_str)?;
    let now = crate::file_access::persist_grant_time(session, selected_time).await?;
    let now = now.max(clock.now()?);
    // Release all in-memory archive/plaintext views before first physical removal.
    crate::view::close_stand();
    crate::file_access::clear_directory_sources();
    let receipt = with_unlocked_vault(session, now, |vault| {
        ReaderCacheDestruction::execute(vault, &mut store, &proof, source, now)
    })?
    .map_err(|e| JsValue::from_str(e.code()))?;
    Ok(receipt_json(&receipt))
}
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerDestructionReceipt")]
pub async fn reader_destruction_receipt(
    session: u32,
    job: Vec<u8>,
    now: i64,
) -> Result<String, JsValue> {
    let now = UnixMillis::new(now);
    let job = ea_reader::ObjectHash::try_from(job.as_slice())
        .map_err(|_| JsValue::from_str("EA-READER-DESTRUCTION-UNVERIFIED"))?;
    let key = ReaderCacheDestruction::journal_key().map_err(|e| JsValue::from_str(e.code()))?;
    let store = OpfsBlobStore::open_all("ea-reader", &[key])
        .await
        .map_err(|e| JsValue::from_str(e.code()))?;
    let receipt = with_unlocked_vault(session, now, |vault| {
        ReaderCacheDestruction::receipt(vault, &store, job)
    })?
    .map_err(|e| JsValue::from_str(e.code()))?;
    Ok(receipt
        .as_ref()
        .map(receipt_json)
        .unwrap_or_else(|| "null".into()))
}

/// Local Reader component evidence only; no request/start/controller operation.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerDestructionAttest")]
pub async fn reader_destruction_attest(
    session: u32,
    source: u32,
    job: Vec<u8>,
    certificate: Vec<u8>,
    now: i64,
) -> Result<Vec<u8>, JsValue> {
    let clock = ActionClock::start(UnixMillis::new(now))?;
    let source = crate::file_access::take_directory_source(source)?;
    let now =
        crate::file_access::observe_grant_time(session, &source, UnixMillis::new(now)).await?;
    let job = ea_reader::ObjectHash::try_from(job.as_slice())
        .map_err(|_| JsValue::from_str("EA-READER-DESTRUCTION-UNVERIFIED"))?;
    let certificate = certificate
        .as_slice()
        .try_into()
        .map_err(|_| JsValue::from_str("EA-READER-DESTRUCTION-UNVERIFIED"))?;
    let authority = with_unlocked_vault(session, now, ReaderCacheDestruction::authority_key)?
        .map_err(|e| JsValue::from_str(e.code()))?;
    let journal = ReaderCacheDestruction::journal_key().map_err(|e| JsValue::from_str(e.code()))?;
    let evidence =
        ReaderCacheDestruction::attestation_key(job).map_err(|e| JsValue::from_str(e.code()))?;
    let mut store = OpfsBlobStore::open_all("ea-reader", &[authority, journal, evidence])
        .await
        .map_err(|e| JsValue::from_str(e.code()))?;
    let now = now.max(clock.now()?);
    let exact = with_unlocked_vault(session, now, |vault| {
        ReaderCacheDestruction::attest(vault, &mut store, &source, job, certificate, now)
    })?
    .map_err(|e| JsValue::from_str(e.code()))?;
    let selected_time = with_unlocked_vault(session, now.max(clock.now()?), |vault| {
        ReaderCacheDestruction::observed_authority_time(vault, &store)
    })?
    .map_err(JsValue::from_str)?;
    let now = crate::file_access::persist_grant_time(session, selected_time)
        .await?
        .max(clock.now()?);
    // This second current-action admission includes actual elapsed signing and
    // flush time; a repeated call verifies and returns the stored bytes only.
    let reread = with_unlocked_vault(session, now, |vault| {
        ReaderCacheDestruction::attest(vault, &mut store, &source, job, certificate, now)
    })?
    .map_err(|e| JsValue::from_str(e.code()))?;
    if reread != exact {
        return Err(JsValue::from_str("EA-READER-DESTRUCTION-UNVERIFIED"));
    }
    with_unlocked_vault(session, now.max(clock.now()?), |_| ())?;
    Ok(reread)
}
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerDestructionAttestation")]
pub async fn reader_destruction_attestation(
    session: u32,
    source: u32,
    job: Vec<u8>,
    now: i64,
) -> Result<Vec<u8>, JsValue> {
    let clock = ActionClock::start(UnixMillis::new(now))?;
    let source = crate::file_access::take_directory_source(source)?;
    let job = ea_reader::ObjectHash::try_from(job.as_slice())
        .map_err(|_| JsValue::from_str("EA-READER-DESTRUCTION-UNVERIFIED"))?;
    let journal = ReaderCacheDestruction::journal_key().map_err(|e| JsValue::from_str(e.code()))?;
    let evidence =
        ReaderCacheDestruction::attestation_key(job).map_err(|e| JsValue::from_str(e.code()))?;
    let mut store = OpfsBlobStore::open_all("ea-reader", &[journal, evidence])
        .await
        .map_err(|e| JsValue::from_str(e.code()))?;
    let exact = with_unlocked_vault(session, clock.now()?, |vault| {
        ReaderCacheDestruction::historical_attestation(vault, &mut store, &source, job)
    })?
    .map_err(|e| JsValue::from_str(e.code()))?
    .ok_or_else(|| JsValue::from_str("EA-READER-DESTRUCTION-UNVERIFIED"))?;
    with_unlocked_vault(session, clock.now()?, |_| ())?;
    Ok(exact)
}

#[cfg(test)]
mod delivery_adapter_tests {
    use super::*;

    #[test]
    fn delivery_decoder_preserves_existing_upload_fields_without_claiming_authority() {
        let certificate = ea_types::CertificateHash::try_from(&[0x33; 32][..]).unwrap();
        let upload = ea_reader::DestructionJobUploadV1::new(
            b"core",
            b"signature",
            b"inventory",
            certificate,
        )
        .unwrap();
        let decoded =
            decode_delivery_upload(b"authorization", b"event", upload.exact_bytes()).unwrap();
        assert_eq!(decoded.exact_bytes(), upload.exact_bytes());
        assert_eq!(decoded.core_bytes(), b"core");
        assert_eq!(decoded.signature_bytes(), b"signature");
        assert_eq!(decoded.inventory_bytes(), b"inventory");
        assert!(decoded.certificate_hash() == certificate);
    }

    #[test]
    fn delivery_decoder_refuses_empty_oversized_and_malformed_original_inputs() {
        let certificate = ea_types::CertificateHash::try_from(&[0x33; 32][..]).unwrap();
        let upload = ea_reader::DestructionJobUploadV1::new(
            b"core",
            b"signature",
            b"inventory",
            certificate,
        )
        .unwrap();
        for (authorization, event) in [
            (b"".as_slice(), b"event".as_slice()),
            (b"authorization".as_slice(), b"".as_slice()),
        ] {
            assert!(decode_delivery_upload(authorization, event, upload.exact_bytes()).is_err());
        }
        let oversized = vec![0; ea_reader::ETB_MAX_RAW_BYTES_V1 + 1];
        assert!(decode_delivery_upload(&oversized, b"event", upload.exact_bytes()).is_err());
        assert!(
            decode_delivery_upload(b"authorization", &oversized, upload.exact_bytes()).is_err()
        );
        for invalid in [
            vec![],
            vec![0x80],
            vec![0x85],
            vec![0x84, 0x40, 0x40, 0x40, 0x40],
        ] {
            assert!(decode_delivery_upload(b"authorization", b"event", &invalid).is_err());
        }
        let mut trailing = upload.exact_bytes().to_vec();
        trailing.push(0);
        assert!(decode_delivery_upload(b"authorization", b"event", &trailing).is_err());
        // Existing protocol page bound is exercised by the actual decoder.
        let oversized_upload = vec![0; 64 * 1024 * 1024 + 1];
        assert!(decode_delivery_upload(b"authorization", b"event", &oversized_upload).is_err());
    }
}
