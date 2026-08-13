#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = ea_cbor::ParserLimits::V1;
    if ea_cbor::validate(data, limits).is_ok() {
        let canonical = ea_cbor::canonical_reencode(data, limits)
            .expect("validated input must have a canonical representation");
        assert_eq!(canonical, data, "accepted input must already be canonical");
        let repeated = ea_cbor::canonical_reencode(&canonical, limits)
            .expect("canonical input must remain encodable");
        assert_eq!(repeated, canonical, "canonical encoding must be stable");
        ea_cbor::validate(&repeated, limits)
            .expect("repeated canonical encoding must remain valid");
    }
});
