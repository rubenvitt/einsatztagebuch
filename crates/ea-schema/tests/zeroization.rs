//! Observe actual released allocations, including forced reallocations, without
//! inspecting freed memory. The caller's input remains alive outside the probe.
use core::{alloc::Layout, cell::Cell};
use std::alloc::{GlobalAlloc, System};
const CANARY: &[u8] = b"T9-SCHEMA-SECRET-COPY-MUST-BE-WIPED";
thread_local! {static ACTIVE:Cell<bool>=const {Cell::new(false)};static LEAKS:Cell<usize>=const {Cell::new(0)};}
struct Probe;
fn inspect(ptr: *mut u8, len: usize) {
    ACTIVE.with(|active| {
        if active.get() {
            // SAFETY: Probe initializes every allocation's whole capacity. This
            // callback runs before release, with the original live allocation.
            let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
            if bytes.windows(CANARY.len()).any(|w| w == CANARY) {
                LEAKS.with(|n| n.set(n.get() + 1));
            }
        }
    });
}
// SAFETY: pointers/layouts are passed unchanged to System. Realloc preserves
// min(old,new) initialized bytes and releases only the original allocation.
unsafe impl GlobalAlloc for Probe {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        inspect(ptr, layout.size());
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let next = unsafe {
            System.alloc_zeroed(Layout::from_size_align(new_size, layout.align()).unwrap())
        };
        if !next.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(ptr, next, layout.size().min(new_size));
                self.dealloc(ptr, layout);
            }
        }
        next
    }
}
#[global_allocator]
static ALLOCATOR: Probe = Probe;
fn measured(operation: impl FnOnce()) -> usize {
    LEAKS.with(|n| n.set(0));
    ACTIVE.with(|v| v.set(true));
    operation();
    ACTIVE.with(|v| v.set(false));
    LEAKS.with(Cell::get)
}
fn fixture() -> Vec<u8> {
    let mut bytes =
        hex::decode(include_str!("../../../vectors/format/payload-v1/incident.hex").trim())
            .unwrap();
    let mut decoder = minicbor::Decoder::new(&bytes);
    decoder.array().unwrap();
    for _ in 0..6 {
        decoder.skip().unwrap();
    }
    decoder.array().unwrap();
    decoder.skip().unwrap();
    decoder.skip().unwrap();
    let start = decoder.position();
    decoder.str().unwrap();
    let end = decoder.position();
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.str(std::str::from_utf8(CANARY).unwrap()).unwrap();
    bytes.splice(start..end, encoder.into_writer());
    bytes
}
#[test]
fn successful_schema_validation_wipes_every_owned_plaintext_copy_before_release() {
    let bytes = fixture();
    let registry = ea_schema::SchemaRegistry::v1();
    let leaks = measured(|| {
        let value = registry.validate("ea.incident", 1, &bytes).unwrap();
        assert_eq!(value.exact_bytes(), bytes);
        drop(value);
    });
    assert_eq!(
        leaks, 0,
        "schema-owned plaintext allocation released without wiping"
    );
}
#[test]
fn partial_decoder_failure_wipes_text_already_read_from_the_secret_payload() {
    let mut bytes = fixture();
    let mut decoder = minicbor::Decoder::new(&bytes);
    decoder.array().unwrap();
    for _ in 0..10 {
        decoder.skip().unwrap();
    }
    decoder.array().unwrap();
    decoder.skip().unwrap();
    decoder.array().unwrap();
    decoder.skip().unwrap();
    let start = decoder.position();
    decoder.skip().unwrap();
    let end = decoder.position();
    bytes.splice(start..end, [0xf4]);
    let leaks = measured(|| {
        assert!(
            ea_schema::SchemaRegistry::v1()
                .validate("ea.incident", 1, &bytes)
                .is_err()
        )
    });
    assert_eq!(
        leaks, 0,
        "decoder error released previously decoded secret text"
    );
}
