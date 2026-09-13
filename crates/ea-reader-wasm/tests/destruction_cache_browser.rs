#![cfg(target_arch = "wasm32")]
#[path = "../../ea-reader/tests/verify_fixtures/mod.rs"]
mod verify_fixtures;
use verify_fixtures::verify_support as support;
#[path = "../../ea-reader/tests/destruction_cache_support/mod.rs"]
mod fixtures;
use ea_reader::{
    ReaderBlobKey, ReaderBlobStore, ReaderCacheDestruction, ReaderObjectCache, ReaderVault,
    VaultContentsV1, VerifiedReaderDestructionInstruction,
};
use ea_reader_wasm::opfs_worker::OpfsBlobStore;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
wasm_bindgen_test_configure!(run_in_dedicated_worker);
#[wasm_bindgen_test]
async fn actual_opfs_enumeration_removes_unknown_grant_holdings_and_rereads_after_reopen() {
    let f = fixtures::Fixture::new();
    let sealed = ReaderVault::seal(
        VaultContentsV1::new(
            ea_crypto::SecretBytes::new(support::other_recipient_secret_bytes()),
            ea_crypto::SecretBytes::new([0x52; 32]),
            f.original.line.exact_anchor_bytes().to_vec(),
            None,
        ),
        &[verify_fixtures::fixtures::authenticator()],
    )
    .unwrap();
    let vault = ReaderVault::unlock(&sealed, &verify_fixtures::fixtures::authenticator()).unwrap();
    let inventory = ea_archive::ArchiveInventory::build(&f.original.source()).unwrap();
    let proof = VerifiedReaderDestructionInstruction::verify(
        &inventory,
        &f.original.anchor,
        &f.current(),
        f.reader,
        f.input(),
    )
    .unwrap();
    let directory = format!("t12-reader-cache-{}", js_sys::Date::now());
    let entry = ea_crypto::object_hash(&f.original.original_bytes);
    let grant = ea_crypto::object_hash(&f.original.initial_grant_bytes);
    let key = |hash: ea_types::ObjectHash| {
        ReaderBlobKey::new(&format!("cache/{}", hex::encode(hash.as_bytes()))).unwrap()
    };
    let journal = ReaderCacheDestruction::journal_key().unwrap();
    let state = ReaderBlobKey::new(&format!(
        "entry-state/{}",
        hex::encode(f.original.entry_hash.as_bytes())
    ))
    .unwrap();
    {
        let mut store = OpfsBlobStore::open(
            &directory,
            &[key(entry), key(grant), journal.clone(), state.clone()],
        )
        .await
        .unwrap();
        let cache = ReaderObjectCache::open(&vault);
        cache
            .put_exact_object(&mut store, &f.original.original_bytes)
            .unwrap();
        cache
            .put_exact_object(&mut store, &f.original.initial_grant_bytes)
            .unwrap();
        store
            .put(&state, b"opaque encrypted derived state")
            .unwrap();
    }
    {
        // No object-key list from JS/the coordinator: enumerate actual OPFS.
        let mut store = OpfsBlobStore::open_all(
            &directory,
            &[
                journal.clone(),
                ReaderCacheDestruction::authority_key(&vault).unwrap(),
            ],
        )
        .await
        .unwrap();
        let receipt = ReaderCacheDestruction::execute(
            &vault,
            &mut store,
            &proof,
            f.original.source(),
            ea_types::UnixMillis::new(800),
        )
        .expect("complete actual OPFS must yield a durable measured receipt");
        assert_eq!(receipt.removed_object_hashes().len(), 2);
    }
    drop(vault);
    let reopened =
        ReaderVault::unlock(&sealed, &verify_fixtures::fixtures::authenticator()).unwrap();
    let mut store = OpfsBlobStore::open_all(&directory, &[journal])
        .await
        .unwrap();
    let receipt = ReaderCacheDestruction::receipt(&reopened, &store, proof.job_hash())
        .unwrap()
        .unwrap();
    assert_eq!(receipt.removed_object_hashes().len(), 2);
    assert!(store.get(&key(entry)).unwrap().is_none());
    assert!(store.get(&key(grant)).unwrap().is_none());
    assert!(store.get(&state).unwrap().is_none());
    assert!(
        ReaderObjectCache::open(&reopened)
            .put_exact_object(&mut store, &f.original.original_bytes)
            .is_err()
    );
}

#[wasm_bindgen_test]
async fn product_exports_verify_remove_and_reread_actual_opfs_after_vault_reopen() {
    use ea_reader_wasm::{destruction_bridge::*, file_access::*, vault_bridge::*};
    let f = fixtures::Fixture::with_reader_attestation_key([0x55; 32]);
    let sealed = ReaderVault::seal(
        VaultContentsV1::new(
            ea_crypto::SecretBytes::new(support::other_recipient_secret_bytes()),
            ea_crypto::SecretBytes::new([0x55; 32]),
            f.original.line.exact_anchor_bytes().to_vec(),
            None,
        ),
        &[verify_fixtures::fixtures::authenticator()],
    )
    .unwrap();
    let exact = sealed.to_deterministic_cbor();
    let unlock = || {
        reader_vault_unlock(
            exact.clone(),
            verify_fixtures::fixtures::VAULT_CREDENTIAL_ID_V1.to_vec(),
            verify_fixtures::fixtures::VAULT_PRF_OUTPUT_V1.to_vec(),
            800.0,
        )
        .unwrap()
    };
    let source = || {
        let handle = file_mode_begin_directory();
        for (path, bytes) in f.original.source().blobs() {
            file_mode_push_blob(handle, path, bytes).unwrap();
        }
        handle
    };
    let vault = ReaderVault::unlock(&sealed, &verify_fixtures::fixtures::authenticator()).unwrap();
    let entry = ea_crypto::object_hash(&f.original.original_bytes);
    let grant = ea_crypto::object_hash(&f.original.initial_grant_bytes);
    let key = |hash: ea_types::ObjectHash| {
        ReaderBlobKey::new(&format!("cache/{}", hex::encode(hash.as_bytes()))).unwrap()
    };
    {
        let mut store = OpfsBlobStore::open(
            "ea-reader",
            &[
                key(entry),
                key(grant),
                ReaderCacheDestruction::journal_key().unwrap(),
            ],
        )
        .await
        .unwrap();
        let cache = ReaderObjectCache::open(&vault);
        cache
            .put_exact_object(&mut store, &f.original.original_bytes)
            .unwrap();
        cache
            .put_exact_object(&mut store, &f.original.initial_grant_bytes)
            .unwrap();
    }
    let session = unlock();
    file_mode_open_directory(session, source(), 800)
        .await
        .unwrap();
    assert_ne!(ea_reader_wasm::view::reader_stand_view(), "null");
    let pending_source = source();
    let mut bad = f.signature.clone();
    bad[0] ^= 1;
    assert!(
        reader_destruction_apply(
            session,
            source(),
            f.authorization.clone(),
            f.event.clone(),
            f.core.clone(),
            bad,
            f.inventory.clone(),
            f.original.deletion.as_bytes().to_vec(),
            800
        )
        .await
        .is_err()
    );
    {
        let store = OpfsBlobStore::open("ea-reader", &[key(entry), key(grant)])
            .await
            .unwrap();
        assert!(store.get(&key(entry)).unwrap().is_some());
        assert!(store.get(&key(grant)).unwrap().is_some());
    }
    let receipt = reader_destruction_apply(
        session,
        source(),
        f.authorization.clone(),
        f.event.clone(),
        f.core.clone(),
        f.signature.clone(),
        f.inventory.clone(),
        f.original.deletion.as_bytes().to_vec(),
        800,
    )
    .await
    .expect("actual product export must execute verified cache removal");
    let receipt: serde_json::Value = serde_json::from_str(&receipt).unwrap();
    assert_eq!(receipt["removedObjectHashes"].as_array().unwrap().len(), 2);
    assert_eq!(receipt["remainingObjectCount"], 0);
    assert_eq!(ea_reader_wasm::view::reader_stand_view(), "null");
    assert!(file_mode_directory_unavailable(pending_source).is_err());

    assert!(
        reader_destruction_attest(
            session,
            source(),
            ea_crypto::object_hash(&f.core).as_bytes().to_vec(),
            f.event_certificate.as_bytes().to_vec(),
            800,
        )
        .await
        .is_err(),
        "a controller certificate cannot substitute for the actual vault component"
    );
    let attestation = reader_destruction_attest(
        session,
        source(),
        ea_crypto::object_hash(&f.core).as_bytes().to_vec(),
        f.reader_attestation_certificate
            .unwrap()
            .as_bytes()
            .to_vec(),
        800,
    )
    .await
    .unwrap();
    let ea_format::ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(&attestation).unwrap()
    else {
        panic!()
    };
    let context = ea_crypto::VerificationContext::deletion_attestation_trust_digest(
        parsed.value().exact_digest_input(),
        &f.authorization,
        f.reader_attestation_certificate.unwrap(),
    )
    .unwrap();
    ea_crypto::verify_cose_sign1(&parsed.value().signatures()[0], &f.current(), &context).unwrap();
    with_session(session, |session| session.lock()).unwrap();
    let reopened = unlock();
    let saved = reader_destruction_attestation(
        reopened,
        source(),
        ea_crypto::object_hash(&f.core).as_bytes().to_vec(),
        799,
    )
    .await
    .unwrap();
    assert_eq!(saved, attestation);
    let reread = reader_destruction_receipt(
        reopened,
        ea_crypto::object_hash(&f.core).as_bytes().to_vec(),
        799,
    )
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&reread).unwrap(),
        receipt
    );
    let store = OpfsBlobStore::open("ea-reader", &[key(entry), key(grant)])
        .await
        .unwrap();
    assert!(store.get(&key(entry)).unwrap().is_none());
    assert!(store.get(&key(grant)).unwrap().is_none());
    with_session(reopened, |session| session.lock()).unwrap();
}
