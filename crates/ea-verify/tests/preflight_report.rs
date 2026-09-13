#[path = "support/mod.rs"]
mod support;
use ea_types::*;
#[test]
fn canonical_full_report_binds_every_original_target_and_exact_chain() {
    let f = support::destruction_v12::OriginalFixture::new(support::COMPLETE_PLAINTEXT_V1);
    let report = ea_verify::verify_archive(
        &f.source(),
        &f.anchor,
        ea_verify::VerifyOptions::new(UnixMillis::new(800)),
    )
    .unwrap()
    .to_canonical_json()
    .unwrap();
    let targets = [(
        f.entry_hash,
        ChainSequence::new(0),
        ea_crypto::object_hash(&f.original_bytes),
    )];
    assert!(
        ea_verify::verify_destruction_preflight_report(
            report.as_bytes(),
            f.anchor.chain_id(),
            &targets
        )
        .is_ok()
    );
    assert!(
        ea_verify::verify_destruction_preflight_report(b"{}", f.anchor.chain_id(), &targets)
            .is_err()
    );
    let false_targets = [(
        f.entry_hash,
        ChainSequence::new(1),
        ea_crypto::object_hash(&f.original_bytes),
    )];
    assert!(
        ea_verify::verify_destruction_preflight_report(
            report.as_bytes(),
            f.anchor.chain_id(),
            &false_targets
        )
        .is_err()
    );
    let false_objects = [(
        f.entry_hash,
        ChainSequence::new(0),
        ObjectHash::from(Hash32::ZERO),
    )];
    assert!(
        ea_verify::verify_destruction_preflight_report(
            report.as_bytes(),
            f.anchor.chain_id(),
            &false_objects
        )
        .is_err()
    );
}
