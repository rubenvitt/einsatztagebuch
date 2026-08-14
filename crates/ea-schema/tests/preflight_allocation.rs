use core::{alloc::Layout, cell::Cell};
use std::alloc::{GlobalAlloc, System};

use ea_schema::{PAYLOAD_PLAINTEXT_MAX_BYTES_V1, SchemaError, SchemaRegistry};

struct Probe;

thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static THRESHOLD: Cell<usize> = const { Cell::new(usize::MAX) };
    static LARGE_ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

fn record_allocation(size: usize) {
    ACTIVE.with(|active| {
        if active.get() {
            THRESHOLD.with(|threshold| {
                if size >= threshold.get() {
                    LARGE_ALLOCATIONS.with(|count| count.set(count.get() + 1));
                }
            });
        }
    });
}

// SAFETY: every operation delegates to the process System allocator with the
// original pointer/layout and only records thread-local allocation sizes.
unsafe impl GlobalAlloc for Probe {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        // SAFETY: the same layout is forwarded unchanged to System.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        // SAFETY: the same layout is forwarded unchanged to System.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_allocation(new_size);
        // SAFETY: the pointer/layout came from System and the new size is
        // forwarded unchanged.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the allocation came from System with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Probe = Probe;

fn with_large_allocation_probe<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    THRESHOLD.with(|value| value.set(64 * 1024));
    LARGE_ALLOCATIONS.with(|value| value.set(0));
    ACTIVE.with(|value| value.set(true));
    let result = operation();
    ACTIVE.with(|value| value.set(false));
    let count = LARGE_ALLOCATIONS.with(Cell::get);
    (result, count)
}

#[test]
fn validator_preflight_rejects_before_any_input_sized_allocation() {
    let oversized = vec![0xff; PAYLOAD_PLAINTEXT_MAX_BYTES_V1 + 1];
    let registry = SchemaRegistry::v1();

    let (unsupported, allocations) =
        with_large_allocation_probe(|| registry.validate("ea.not-registered", 1, &oversized));
    assert!(matches!(unsupported, Err(SchemaError::Unsupported { .. })));
    assert_eq!(
        allocations, 0,
        "unsupported preflight must precede every input-sized allocation"
    );

    let (over_limit, allocations) =
        with_large_allocation_probe(|| registry.validate("ea.incident", 1, &oversized));
    assert_eq!(over_limit.unwrap_err().code(), "EA-SCHEMA-PLAINTEXT-LIMIT");
    assert_eq!(
        allocations, 0,
        "plaintext cap must precede every input-sized allocation"
    );
}
