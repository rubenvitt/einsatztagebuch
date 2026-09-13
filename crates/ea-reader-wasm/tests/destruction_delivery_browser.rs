#![cfg(target_arch = "wasm32")]
#[path = "../../ea-reader/tests/verify_fixtures/mod.rs"]
mod verify_fixtures;
use verify_fixtures::verify_support as support;
#[path = "../../ea-reader/tests/destruction_cache_support/mod.rs"]
mod fixtures;
use ea_reader::{
    ReaderBlobKey, ReaderBlobStore, ReaderCacheDestruction, ReaderObjectCache, ReaderVault,
    VaultContentsV1,
};
use ea_reader_wasm::{
    destruction_bridge::*, file_access::*, opfs_worker::OpfsBlobStore, vault_bridge::*,
};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[wasm_bindgen_test]
async fn three_original_adapter_keeps_source_and_session_guards_and_removes_actual_opfs() {
    let f = fixtures::Fixture::new();
    let sealed = ReaderVault::seal(
        VaultContentsV1::new(
            ea_crypto::SecretBytes::new(support::other_recipient_secret_bytes()),
            ea_crypto::SecretBytes::new([0x59; 32]),
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
    let upload = ea_reader::DestructionJobUploadV1::new(
        &f.core,
        &f.signature,
        &f.inventory,
        f.original.deletion,
    )
    .unwrap();
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
    let locked = unlock();
    with_session(locked, |session| session.lock()).unwrap();
    assert!(
        reader_destruction_apply_delivery(
            locked,
            source(),
            f.authorization.clone(),
            f.event.clone(),
            upload.exact_bytes().to_vec(),
            800
        )
        .await
        .is_err()
    );
    let session = unlock();
    assert!(
        reader_destruction_apply_delivery(
            session,
            u32::MAX,
            f.authorization.clone(),
            f.event.clone(),
            upload.exact_bytes().to_vec(),
            800
        )
        .await
        .is_err()
    );
    let mut bad_signature = f.signature.clone();
    bad_signature[0] ^= 1;
    let corrupt = ea_reader::DestructionJobUploadV1::new(
        &f.core,
        &bad_signature,
        &f.inventory,
        f.original.deletion,
    )
    .unwrap();
    assert!(
        reader_destruction_apply_delivery(
            session,
            source(),
            f.authorization.clone(),
            f.event.clone(),
            corrupt.exact_bytes().to_vec(),
            800
        )
        .await
        .is_err()
    );
    for (authorization, event) in [
        (vec![0], f.event.clone()),
        (f.authorization.clone(), vec![0]),
    ] {
        assert!(
            reader_destruction_apply_delivery(
                session,
                source(),
                authorization,
                event,
                upload.exact_bytes().to_vec(),
                800
            )
            .await
            .is_err()
        );
    }
    {
        let store = OpfsBlobStore::open("ea-reader", &[key(entry), key(grant)])
            .await
            .unwrap();
        assert!(store.get(&key(entry)).unwrap().is_some());
        assert!(store.get(&key(grant)).unwrap().is_some());
    }
    file_mode_open_directory(session, source(), 800)
        .await
        .unwrap();
    assert_ne!(ea_reader_wasm::view::reader_stand_view(), "null");
    let pending_source = source();
    let reusable_source = source();
    assert!(
        reader_destruction_apply_delivery(
            session,
            reusable_source,
            f.authorization.clone(),
            f.event.clone(),
            vec![0x80],
            800
        )
        .await
        .is_err()
    );
    // Malformed envelope was refused before consuming the actual registered source.
    let receipt = reader_destruction_apply_delivery(
        session,
        reusable_source,
        f.authorization.clone(),
        f.event.clone(),
        upload.exact_bytes().to_vec(),
        800,
    )
    .await
    .unwrap();
    let receipt: serde_json::Value = serde_json::from_str(&receipt).unwrap();
    assert_eq!(
        receipt["jobHash"],
        hex::encode(ea_crypto::object_hash(&f.core).as_bytes())
    );
    let head = f.current();
    let reader = head
        .known_certificate_fields()
        .find(|(_, certificate)| {
            certificate.certificate_kind == ea_format::CertificateKindV1::Reader
                && certificate.kem_key_thumbprint == Some(f.reader)
        })
        .unwrap()
        .1
        .device_id;
    assert_eq!(receipt["replicaId"], hex::encode(reader.as_bytes()));
    assert_eq!(receipt["removedObjectHashes"].as_array().unwrap().len(), 2);
    assert_eq!(receipt["remainingObjectCount"], 0);
    assert_eq!(ea_reader_wasm::view::reader_stand_view(), "null");
    assert!(file_mode_directory_unavailable(pending_source).is_err());
    assert!(file_mode_directory_unavailable(reusable_source).is_err());
    with_session(session, |session| session.lock()).unwrap();
    let reopened = unlock();
    let durable = reader_destruction_receipt(
        reopened,
        ea_crypto::object_hash(&f.core).as_bytes().to_vec(),
        800,
    )
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&durable).unwrap(),
        receipt
    );
    let store = OpfsBlobStore::open("ea-reader", &[key(entry), key(grant)])
        .await
        .unwrap();
    assert!(store.get(&key(entry)).unwrap().is_none());
    assert!(store.get(&key(grant)).unwrap().is_none());
    with_session(reopened, |session| session.lock()).unwrap();
}
