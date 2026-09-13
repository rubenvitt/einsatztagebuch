use ea_admin::recovery_test_runtime::parse_recovery_media_sources;
use ea_recovery::KeyInventory;
use serde_json::json;

fn declared_inventory(protection: &str) -> KeyInventory {
    KeyInventory::parse(&serde_json::to_vec(&json!({
        "schemaId":"ea.key-inventory/v1", "inventoryId":"12".repeat(16),
        "media":[{"mediumId":"token-signing", "keyRole":"deletionAttest",
            "expectedKeyThumbprint":"34".repeat(32), "certificateObjectHash":"56".repeat(32),
            "protectionProfile":protection, "testKind":"providerPresence"}]
    })).unwrap()).unwrap()
}

#[test]
fn explicit_pkcs11_routing_does_not_claim_stronger_provider_protection() {
    // These paths deliberately do not exist: routing must refuse unsupported
    // protection before a PIN file, module or any secret is opened.
    let exact=serde_json::to_vec(&json!({"schemaId":"ea.recovery-media-sources/v1",
        "media":[{"mediumId":"token-signing",
            "source":"pkcs11:module=/missing/module;token=test;id=d1;pin-file=/missing/pin"}]
    })).unwrap();
    assert!(parse_recovery_media_sources(&exact,&declared_inventory("pkcs11")).is_ok());
    for protection in ["hardwareNonExportable", "serverSecretStoreOrHsm"] {
        let error=match parse_recovery_media_sources(&exact,&declared_inventory(protection)) {
            Ok(_) => panic!("PKCS11 routing cannot attest {protection}"),
            Err(error) => error,
        };
        assert_eq!(error.code(),"EA-RECOVERY-TEST-PROTECTION-UNVERIFIED");
    }
}
