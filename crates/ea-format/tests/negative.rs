use core::{alloc::Layout, cell::Cell};
use std::alloc::{GlobalAlloc, System};

use ea_format::{
    EAG_MAX_RAW_BYTES_V1, EAG_PREFIX_V1, ECP_MAX_RAW_BYTES_V1, ECP_PREFIX_V1, EDS_MAX_RAW_BYTES_V1,
    EDS_PREFIX_V1, EIP_MAX_RAW_BYTES_V1, EIP_PREFIX_V1, ESR_MAX_RAW_BYTES_V1, ESR_PREFIX_V1,
    ETB_MAX_RAW_BYTES_V1, ETB_PREFIX_V1, MAX_ARCHIVE_OBJECT_BYTES_V1, decode_exact_object,
};

mod support;

struct Probe;

thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static THRESHOLD: Cell<usize> = const { Cell::new(usize::MAX) };
    static LARGE_ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: this delegates every operation to the process System allocator and
// only updates thread-local counters before delegation.
unsafe impl GlobalAlloc for Probe {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ACTIVE.with(|active| {
            if active.get() {
                THRESHOLD.with(|threshold| {
                    if layout.size() >= threshold.get() {
                        LARGE_ALLOCATIONS.with(|count| count.set(count.get() + 1));
                    }
                });
            }
        });
        // SAFETY: the same layout is forwarded unchanged to System.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the allocation came from System with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Probe = Probe;

fn with_allocation_probe<T>(threshold: usize, operation: impl FnOnce() -> T) -> (T, usize) {
    THRESHOLD.with(|value| value.set(threshold));
    LARGE_ALLOCATIONS.with(|value| value.set(0));
    ACTIVE.with(|value| value.set(true));
    let result = operation();
    ACTIVE.with(|value| value.set(false));
    let count = LARGE_ALLOCATIONS.with(Cell::get);
    (result, count)
}

#[test]
fn exact_prefixes_and_raw_cap_precedence_hold_for_all_families_without_large_allocations() {
    let literal_prefixes = [
        [0x85, 0x44, b'E', b'A', b'1', 0, 1, 1, 0x80],
        [0x85, 0x44, b'E', b'A', b'1', 0, 2, 1, 0x80],
        [0x85, 0x44, b'E', b'A', b'1', 0, 3, 1, 0x80],
        [0x85, 0x44, b'E', b'A', b'1', 0, 4, 1, 0x80],
        [0x85, 0x44, b'E', b'A', b'1', 0, 5, 1, 0x80],
        [0x85, 0x44, b'E', b'A', b'1', 0, 6, 1, 0x80],
    ];
    assert_eq!(
        [
            EIP_PREFIX_V1,
            EAG_PREFIX_V1,
            ESR_PREFIX_V1,
            ECP_PREFIX_V1,
            ETB_PREFIX_V1,
            EDS_PREFIX_V1,
        ],
        literal_prefixes
    );
    let cases = [
        (
            literal_prefixes[0],
            EIP_MAX_RAW_BYTES_V1,
            "EA-FORMAT-EIP-RAW-LIMIT",
        ),
        (
            literal_prefixes[1],
            EAG_MAX_RAW_BYTES_V1,
            "EA-FORMAT-EAG-RAW-LIMIT",
        ),
        (
            literal_prefixes[2],
            ESR_MAX_RAW_BYTES_V1,
            "EA-FORMAT-ESR-RAW-LIMIT",
        ),
        (
            literal_prefixes[3],
            ECP_MAX_RAW_BYTES_V1,
            "EA-FORMAT-GLOBAL-RAW-LIMIT",
        ),
        (
            literal_prefixes[4],
            ETB_MAX_RAW_BYTES_V1,
            "EA-FORMAT-GLOBAL-RAW-LIMIT",
        ),
        (
            literal_prefixes[5],
            EDS_MAX_RAW_BYTES_V1,
            "EA-FORMAT-EDS-RAW-LIMIT",
        ),
    ];

    for (prefix, accepted, rejected_code) in cases {
        assert_eq!(prefix.len(), 9);
        let at_cap = support::malformed_at_raw_length(prefix, accepted);
        let (result, allocations) =
            with_allocation_probe(64 * 1024, || decode_exact_object(&at_cap));
        let error = result.unwrap_err();
        assert_ne!(error.code(), rejected_code);
        assert!(error.code().starts_with("EA-CBOR-") || error.code() == "EA-FORMAT-SHAPE");
        assert_eq!(
            allocations, 0,
            "preflight/full scan must not allocate from raw length"
        );

        let over_cap = support::malformed_at_raw_length(prefix, accepted + 1);
        let (result, allocations) =
            with_allocation_probe(64 * 1024, || decode_exact_object(&over_cap));
        assert_eq!(result.unwrap_err().code(), rejected_code);
        assert_eq!(
            allocations, 0,
            "raw rejection must not allocate from input length"
        );
    }
}

#[test]
fn global_cap_precedes_prefix_inspection_and_allocation() {
    let bytes = vec![0xff; MAX_ARCHIVE_OBJECT_BYTES_V1 + 1];
    let (result, allocations) = with_allocation_probe(64 * 1024, || decode_exact_object(&bytes));
    assert_eq!(result.unwrap_err().code(), "EA-FORMAT-GLOBAL-RAW-LIMIT");
    assert_eq!(allocations, 0);
}

#[test]
fn exact_prefix_stage_rejects_invalid_and_noncanonical_forms_before_family_caps() {
    for (bytes, code) in [
        (Vec::new(), "EA-FORMAT-PREFIX"),
        (EIP_PREFIX_V1[..8].to_vec(), "EA-FORMAT-PREFIX"),
        (
            vec![0x85, 0x44, b'E', b'A', b'1', 0, 0, 1, 0x80],
            "EA-FORMAT-PREFIX",
        ),
        (
            vec![0x85, 0x44, b'E', b'A', b'1', 0, 7, 1, 0x80],
            "EA-FORMAT-PREFIX",
        ),
        (
            vec![0x9f, 0x44, b'E', b'A', b'1', 0, 2, 1, 0x80],
            "EA-FORMAT-PREFIX",
        ),
        (
            vec![0x85, 0x44, b'E', b'A', b'1', 0x18, 2, 1, 0x80],
            "EA-FORMAT-PREFIX",
        ),
        (
            vec![0x85, 0x44, b'E', b'A', b'1', 0, 2, 0x18, 1, 0x80],
            "EA-FORMAT-UNKNOWN-VERSION",
        ),
        (
            vec![0x85, 0x44, b'E', b'A', b'1', 0, 2, 1, 0x9f],
            "EA-FORMAT-CRITICAL-EXTENSION",
        ),
    ] {
        assert_eq!(decode_exact_object(&bytes).unwrap_err().code(), code);
    }

    for (literal_prefix, family_cap) in [
        (
            [0x85, 0x44, b'E', b'A', b'1', 0, 2, 1, 0x80],
            EAG_MAX_RAW_BYTES_V1,
        ),
        (
            [0x85, 0x44, b'E', b'A', b'1', 0, 3, 1, 0x80],
            ESR_MAX_RAW_BYTES_V1,
        ),
        (
            [0x85, 0x44, b'E', b'A', b'1', 0, 6, 1, 0x80],
            EDS_MAX_RAW_BYTES_V1,
        ),
    ] {
        let mut bytes = support::malformed_at_raw_length(literal_prefix, family_cap + 1);
        bytes[5] = 1;
        let (result, allocations) =
            with_allocation_probe(64 * 1024, || decode_exact_object(&bytes));
        assert_eq!(result.unwrap_err().code(), "EA-FORMAT-PREFIX");
        assert_eq!(allocations, 0);
    }
}

#[test]
fn one_byte_prefix_mutations_have_exact_fail_closed_errors() {
    let valid = support::valid_eip(vec![0; 16]);
    for (index, code) in [
        (0, "EA-FORMAT-PREFIX"),
        (1, "EA-FORMAT-PREFIX"),
        (2, "EA-FORMAT-PREFIX"),
        (6, "EA-FORMAT-PREFIX"),
        (7, "EA-FORMAT-UNKNOWN-VERSION"),
        (8, "EA-FORMAT-CRITICAL-EXTENSION"),
    ] {
        let mut mutated = valid.clone();
        mutated[index] ^= 1;
        assert_eq!(decode_exact_object(&mutated).unwrap_err().code(), code);
    }
}

#[test]
fn signed_time_width_rejects_values_outside_i64_in_both_directions() {
    for bytes in [
        support::esr_with_received_time_raw(&[0x1b, 0x80, 0, 0, 0, 0, 0, 0, 0]),
        support::esr_with_received_time_raw(&[0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0]),
    ] {
        assert_eq!(
            decode_exact_object(&bytes).unwrap_err().code(),
            "EA-FORMAT-SHAPE"
        );
    }
}

#[test]
fn unknown_evidence_variant_fails_at_the_exact_local_tag_gate() {
    assert_eq!(
        decode_exact_object(&support::evidence_with_unknown_variant())
            .unwrap_err()
            .code(),
        "EA-FORMAT-TAG-MISMATCH"
    );
}

#[test]
fn trust_payload_mutation_with_stale_cose_digest_fails_at_the_exact_binding_gate() {
    assert_eq!(
        decode_exact_object(&support::trust_with_stale_payload_digest())
            .unwrap_err()
            .code(),
        "EA-FORMAT-COSE"
    );
}
