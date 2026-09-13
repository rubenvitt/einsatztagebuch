#[path = "verify_fixtures/mod.rs"]
mod verify_fixtures;
use verify_fixtures::verify_support as support;
#[path = "../../ea-verify/tests/destruction_stub_support/mod.rs"]
mod stub_support;
use ea_crypto::SecretBytes;
use ea_reader::{
    EntryStatus, ReaderMode, ReaderVault, ReaderVerifier, SilentObserver, VaultContentsV1,
    VerificationStatus,
};
use ea_types::UnixMillis;

#[test]
fn a_fully_proven_stub_is_authorized_destroyed_and_has_no_decryption_witness() {
    let f = stub_support::fixture(true, true);
    let vault = vault(&f);
    let result = ReaderVerifier::new(ReaderMode::File, UnixMillis::new(800))
        .classify(&f.source, &vault, &mut SilentObserver)
        .unwrap();
    let state = result.state_of(f.original.entry_hash).unwrap();
    assert_eq!(state.entry_state(), EntryStatus::AuthorizedDestroyed);
    assert_eq!(state.verification(), VerificationStatus::Verified);
    assert!(result.verified_entry(f.original.entry_hash).is_none());
    assert!(result.verified_grant(f.original.entry_hash).is_none());
}

#[test]
fn a_state_event_without_bound_deletion_evidence_does_not_authorize_the_stub() {
    let f = stub_support::fixture(false, true);
    let vault = vault(&f);
    let result = ReaderVerifier::new(ReaderMode::File, UnixMillis::new(800))
        .classify(&f.source, &vault, &mut SilentObserver)
        .unwrap();
    let state = result.state_of(f.original.entry_hash).unwrap();
    assert_eq!(state.entry_state(), EntryStatus::UnexplainedGap);
    assert_eq!(state.verification(), VerificationStatus::Gap);
}

fn vault(f: &stub_support::Fixture) -> ea_reader::UnlockedVault {
    let sealed = ReaderVault::seal(
        VaultContentsV1::new(
            SecretBytes::new(support::complete_recipient_secret_bytes()),
            SecretBytes::new([0x52; 32]),
            f.original.line.exact_anchor_bytes().to_vec(),
            None,
        ),
        &[verify_fixtures::fixtures::authenticator()],
    )
    .unwrap();
    ReaderVault::unlock(&sealed, &verify_fixtures::fixtures::authenticator()).unwrap()
}
