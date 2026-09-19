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
#[cfg(any(test, target_arch = "wasm32"))]
use ea_reader::UnixMillis;
#[cfg(target_arch = "wasm32")]
use ea_reader::{
    ReaderCacheDestruction, ReaderCacheRemovalReceipt, ReaderDestructionInstructionBytes,
};
#[cfg(any(test, target_arch = "wasm32"))]
use std::cell::Cell;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
/// The single refusal of every clock path: an unusable time source never
/// degrades to a guessed time.
#[cfg(any(test, target_arch = "wasm32"))]
const CLOCK_REFUSAL: &str = "EA-READER-DESTRUCTION-CLOCK";

/// Time source of one action: a monotonic reading (`performance.now()` in the
/// worker) and the wall clock (`Date.now()`), both in milliseconds. Injectable
/// so the arithmetic below is witnessed natively, without a browser.
#[cfg(any(test, target_arch = "wasm32"))]
trait ClockSource {
    fn monotonic_ms(&self) -> f64;
    fn wall_ms(&self) -> f64;
}

/// Action time: `max(anchor + monotonic elapsed, wall clock, previous value)`.
///
/// - Every verified floor (grant/authority time) re-anchors the monotonic term,
///   so time keeps running from a lifted floor instead of standing still at
///   it when the device clock is set back (B1).
/// - The wall clock bounds the result from below, so a suspend during which
///   `performance.now()` does not advance cannot hand session and expiry
///   checks an older time (B2). A wall clock set back is absorbed by `max`.
/// - The high-water mark keeps the action time nondecreasing across calls.
///
/// Values stay inside the Reader: only callers' existing `now` parameters see
/// them, in whole milliseconds, like the caller's own `Date.now()`.
#[cfg(any(test, target_arch = "wasm32"))]
struct ActionClock<S: ClockSource> {
    source: S,
    anchor_monotonic: Cell<f64>,
    anchor_time: Cell<i64>,
    high_water: Cell<i64>,
}
#[cfg(any(test, target_arch = "wasm32"))]
impl<S: ClockSource> ActionClock<S> {
    fn start(source: S, effective_start: UnixMillis) -> Result<Self, &'static str> {
        let anchor_monotonic = monotonic_reading(&source)?;
        Ok(Self {
            source,
            anchor_monotonic: Cell::new(anchor_monotonic),
            anchor_time: Cell::new(effective_start.get()),
            high_water: Cell::new(effective_start.get()),
        })
    }
    fn now(&self) -> Result<UnixMillis, &'static str> {
        self.read().map(|(_, now)| UnixMillis::new(now))
    }
    /// Admits a verified floor (grant or authority time) and re-anchors the
    /// monotonic term on the admitted value.
    fn observe_floor(&self, floor: UnixMillis) -> Result<UnixMillis, &'static str> {
        let (monotonic, now) = self.read()?;
        let now = now.max(floor.get());
        self.anchor_monotonic.set(monotonic);
        self.anchor_time.set(now);
        self.high_water.set(now);
        Ok(UnixMillis::new(now))
    }
    fn read(&self) -> Result<(f64, i64), &'static str> {
        let monotonic = monotonic_reading(&self.source)?;
        let elapsed = (monotonic - self.anchor_monotonic.get()).ceil();
        if !elapsed.is_finite() || elapsed < 0.0 || elapsed >= i64::MAX as f64 {
            return Err(CLOCK_REFUSAL);
        }
        let running = self
            .anchor_time
            .get()
            .checked_add(elapsed as i64)
            .ok_or(CLOCK_REFUSAL)?;
        let wall = self.source.wall_ms().floor();
        if !wall.is_finite() || wall < 0.0 || wall >= i64::MAX as f64 {
            return Err(CLOCK_REFUSAL);
        }
        let now = running.max(wall as i64).max(self.high_water.get());
        self.high_water.set(now);
        Ok((monotonic, now))
    }
}
#[cfg(any(test, target_arch = "wasm32"))]
fn monotonic_reading(source: &impl ClockSource) -> Result<f64, &'static str> {
    let reading = source.monotonic_ms();
    if reading.is_finite() {
        Ok(reading)
    } else {
        Err(CLOCK_REFUSAL)
    }
}

#[cfg(target_arch = "wasm32")]
struct WorkerClock(web_sys::Performance);
#[cfg(target_arch = "wasm32")]
impl ClockSource for WorkerClock {
    fn monotonic_ms(&self) -> f64 {
        self.0.now()
    }
    fn wall_ms(&self) -> f64 {
        js_sys::Date::now()
    }
}
#[cfg(target_arch = "wasm32")]
fn start_action_clock(effective_start: UnixMillis) -> Result<ActionClock<WorkerClock>, JsValue> {
    let performance = js_sys::global()
        .dyn_into::<web_sys::WorkerGlobalScope>()
        .map_err(|_| JsValue::from_str(CLOCK_REFUSAL))?
        .performance()
        .ok_or_else(|| JsValue::from_str(CLOCK_REFUSAL))?;
    Ok(ActionClock::start(
        WorkerClock(performance),
        effective_start,
    )?)
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
    // Awaiting OPFS leases must not freeze action/session time: every verified
    // floor re-anchors the clock, which then keeps running from there.
    let clock = start_action_clock(UnixMillis::new(now))?;
    let source = crate::file_access::take_directory_source(source)?;
    let now = clock.observe_floor(
        crate::file_access::observe_grant_time(session, &source, UnixMillis::new(now)).await?,
    )?;
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
    let now = clock
        .observe_floor(crate::file_access::persist_grant_time(session, selected_time).await?)?;
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
    let clock = start_action_clock(UnixMillis::new(now))?;
    let source = crate::file_access::take_directory_source(source)?;
    let now = clock.observe_floor(
        crate::file_access::observe_grant_time(session, &source, UnixMillis::new(now)).await?,
    )?;
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
    let now = clock
        .observe_floor(crate::file_access::persist_grant_time(session, selected_time).await?)?;
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
    let clock = start_action_clock(UnixMillis::new(now))?;
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

#[cfg(test)]
mod action_clock_tests {
    use super::*;
    use std::cell::Cell;

    /// Scripted readings: the test moves both clocks explicitly.
    struct ScriptedClock {
        monotonic: Cell<f64>,
        wall: Cell<f64>,
    }
    impl ScriptedClock {
        fn new(monotonic: f64, wall: f64) -> Self {
            Self {
                monotonic: Cell::new(monotonic),
                wall: Cell::new(wall),
            }
        }
    }
    impl ClockSource for &ScriptedClock {
        fn monotonic_ms(&self) -> f64 {
            self.monotonic.get()
        }
        fn wall_ms(&self) -> f64 {
            self.wall.get()
        }
    }

    /// B1: the device clock is set back, so the caller's start lies below the
    /// verified grant/authority floor. Time must keep running from the lifted
    /// floor instead of standing still at it.
    #[test]
    fn b1_clock_keeps_running_from_the_lifted_verified_floor() {
        let source = ScriptedClock::new(10.0, 1_000.0);
        let clock = ActionClock::start(&source, UnixMillis::new(1_000)).unwrap();
        let lifted = clock.observe_floor(UnixMillis::new(50_000)).unwrap();
        assert_eq!(lifted, UnixMillis::new(50_000));
        source.monotonic.set(5_010.0);
        assert_eq!(clock.now().unwrap(), UnixMillis::new(55_000));
        // A second, lower floor must not pull the running time back.
        assert_eq!(
            clock.observe_floor(UnixMillis::new(40_000)).unwrap(),
            UnixMillis::new(55_000)
        );
    }

    /// B2: the monotonic clock stood still during a system suspend while the
    /// wall clock advanced. Session and expiry checks must see the later time.
    #[test]
    fn b2_suspend_that_freezes_the_monotonic_clock_is_caught_by_the_wall_clock() {
        let start = 1_700_000_000_000.0;
        let source = ScriptedClock::new(10.0, start);
        let clock = ActionClock::start(&source, UnixMillis::new(start as i64)).unwrap();
        source.wall.set(start + 3_600_000.0);
        assert_eq!(
            clock.now().unwrap(),
            UnixMillis::new(start as i64 + 3_600_000)
        );
    }

    /// Regression guard (green before and after): the action time never runs
    /// backwards, even when the wall clock is set back mid-action.
    #[test]
    fn action_time_is_nondecreasing_across_calls() {
        let source = ScriptedClock::new(0.0, 500.0);
        let clock = ActionClock::start(&source, UnixMillis::new(100)).unwrap();
        let mut last = clock.now().unwrap();
        for (monotonic, wall) in [(10.0, 90.0), (20.0, 5_000.0), (30.0, 0.0), (40.0, 200.0)] {
            source.monotonic.set(monotonic);
            source.wall.set(wall);
            let now = clock.now().unwrap();
            assert!(now >= last, "{now:?} < {last:?}");
            last = now;
            let floored = clock.observe_floor(UnixMillis::new(150)).unwrap();
            assert!(floored >= last, "{floored:?} < {last:?}");
            last = floored;
        }
    }

    /// Fail-closed: an unusable reading of either source refuses with the one
    /// clock code instead of guessing a time.
    #[test]
    fn unusable_time_sources_refuse_with_the_clock_code() {
        let source = ScriptedClock::new(f64::NAN, 1_000.0);
        assert_eq!(
            ActionClock::start(&source, UnixMillis::new(1_000)).err(),
            Some(CLOCK_REFUSAL)
        );
        for (monotonic, wall) in [
            (f64::NAN, 1_000.0),
            (f64::INFINITY, 1_000.0),
            (-5.0, 1_000.0),
            (20.0, f64::NAN),
            (20.0, -1.0),
            (20.0, f64::INFINITY),
        ] {
            let source = ScriptedClock::new(10.0, 1_000.0);
            let clock = ActionClock::start(&source, UnixMillis::new(1_000)).unwrap();
            source.monotonic.set(monotonic);
            source.wall.set(wall);
            assert_eq!(clock.now().err(), Some(CLOCK_REFUSAL), "{monotonic} {wall}");
            assert_eq!(
                clock.observe_floor(UnixMillis::new(1_000)).err(),
                Some(CLOCK_REFUSAL),
                "{monotonic} {wall}"
            );
        }
        // Overflow of the action time is refused, not wrapped.
        let source = ScriptedClock::new(0.0, 1_000.0);
        let clock = ActionClock::start(&source, UnixMillis::new(i64::MAX - 1)).unwrap();
        source.monotonic.set(10.0);
        assert_eq!(clock.now().err(), Some(CLOCK_REFUSAL));
    }
}
