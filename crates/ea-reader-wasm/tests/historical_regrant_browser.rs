#![cfg(target_arch = "wasm32")]

#[path = "../../ea-reader/tests/verify_fixtures/mod.rs"]
mod verify_fixtures;

use ea_crypto::SecretBytes;
use ea_reader::{ReaderVault, VaultContentsV1};
use ea_reader_wasm::{file_access::*, vault_bridge::*, view::*};
use verify_fixtures::{fixtures, verify_support as support};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

fn unlock(bytes: &[u8], now: f64) -> u32 {
    reader_vault_unlock(
        bytes.to_vec(),
        fixtures::VAULT_CREDENTIAL_ID_V1.to_vec(),
        fixtures::VAULT_PRF_OUTPUT_V1.to_vec(),
        now,
    )
    .unwrap()
}

async fn open(
    session: u32,
    f: &support::historical::HistoricalFixture,
    now: i64,
) -> serde_json::Value {
    let directory = file_mode_begin_directory();
    for (path, bytes) in f.fixture.blobs() {
        file_mode_push_blob(directory, path, bytes).unwrap();
    }
    let result = file_mode_open_directory(session, directory, now)
        .await
        .unwrap();
    serde_json::from_str(&result).unwrap()
}

#[wasm_bindgen_test]
async fn browser_exports_persist_expiry_before_reopening_the_vault_with_a_rolled_back_clock() {
    let f = support::historical::fixture_with_expired_original_head(|version, binding| {
        verify_fixtures::operator::bound_plaintext(
            fixtures::genesis_plaintext(),
            binding,
            version.get(),
            verify_fixtures::operator::Defect::None,
        )
    });
    let f = support::historical::install_grant(f, 800);
    let sealed = ReaderVault::seal(
        VaultContentsV1::new(
            SecretBytes::new(support::other_recipient_secret_bytes()),
            SecretBytes::new([0x52; 32]),
            f.line.exact_anchor_bytes().to_vec(),
            None,
        ),
        &[fixtures::authenticator()],
    )
    .unwrap();
    let bytes = sealed.to_deterministic_cbor();
    let session = unlock(&bytes, 800.0);
    let initial = open(session, &f, 800).await;
    assert_eq!(initial["fullyVerified"], true);
    let entry = reader_entry_view(&hex::encode(f.entry_hash.as_bytes())).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&entry).unwrap()["state"]["verification"],
        "verifiziert"
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&reader_stand_view()).unwrap()["fullyVerified"],
        true
    );
    assert_eq!(open(session, &f, 801).await["fullyVerified"], false);
    with_session(session, |session| session.lock()).unwrap();
    reader_stand_close();
    let reopened = unlock(&bytes, 799.0);
    assert_eq!(
        open(reopened, &f, 799).await["fullyVerified"],
        false,
        "a fresh vault session must consume the OPFS floor before HPKE"
    );
    let expired = reader_entry_view(&hex::encode(f.entry_hash.as_bytes())).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&expired).unwrap()["state"]["verification"],
        "ungültig"
    );
    with_session(reopened, |session| session.lock()).unwrap();
    reader_stand_close();
    // A signed receipt can advance expiry while the host clock stays behind.
    // Reopen the older export without that receipt using the same sealed vault.
    let later = support::historical::fixture_with_expired_original_head(|version, binding| {
        verify_fixtures::operator::bound_plaintext(
            fixtures::genesis_plaintext(),
            binding,
            version.get(),
            verify_fixtures::operator::Defect::None,
        )
    });
    let mut later = support::historical::install_grant(later, 850);
    let older = support::historical::install_grant(
        support::historical::fixture_with_expired_original_head(|version, binding| {
            verify_fixtures::operator::bound_plaintext(
                fixtures::genesis_plaintext(),
                binding,
                version.get(),
                verify_fixtures::operator::Defect::None,
            )
        }),
        850,
    );
    later.fixture.push_exact_bytes(
        "receipts/current.esr",
        support::historical::signed_receipt(&later, 900),
    );
    let receipt_session = unlock(&bytes, 800.0);
    assert_eq!(
        open(receipt_session, &later, 800).await["fullyVerified"],
        false
    );
    with_session(receipt_session, |session| session.lock()).unwrap();
    reader_stand_close();
    let without_receipt = unlock(&bytes, 800.0);
    assert_eq!(
        open(without_receipt, &older, 800).await["fullyVerified"],
        false,
        "removing the receipt after reopen cannot reverse its committed floor900"
    );
    with_session(without_receipt, |session| session.lock()).unwrap();
    reader_stand_close();
}
