//! Separate Linux-source/Mac-target witness using only existing task token objects.
use super::*;
use ea_recovery::RecoveryKem;

#[path = "../../../../crates/ea-recovery/tests/source_manifest/token.rs"]
mod token;

#[test]
#[ignore = "explicit isolated Mac native target and existing fixture-v1 c1/d1 only"]
fn export_target_native_pkcs11_context() {
    export_target_native_context();
    let directory = PathBuf::from(std::env::var_os("EA_T9_TARGET_DIRECTORY").unwrap());
    let media = token::TokenMedia::open(&directory);
    let path = directory.join("public-context.json");
    let mut context: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    context["pkcs11"] = json!({
        "signingThumbprint": media.signing_thumbprint(),
        "recoveryThumbprint": hex::encode(media.recovery.key_thumbprint().unwrap().as_bytes()),
    });
    assert_ne!(
        context["pkcs11"]["signingThumbprint"],
        context["pkcs11"]["recoveryThumbprint"]
    );
    // Public observations only: neither PIN, private material nor host module paths.
    fs::write(path, serde_json::to_vec(&context).unwrap()).unwrap();
}

pub(super) fn explicit_source(row: &Value, target: &Path) -> String {
    let id = row["pkcs11Id"].as_str().unwrap();
    assert!(matches!(id, "c1" | "d1"));
    let module = PathBuf::from(std::env::var_os("EA_TEST_PKCS11_MODULE").unwrap())
        .canonicalize()
        .unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../.superpowers/pkcs11-fixture-v1")
        .canonicalize()
        .unwrap();
    assert!(
        module.starts_with(fixture),
        "only the existing task module is permitted"
    );
    let source = format!(
        "pkcs11:module={};token=drk250-fixture;id={id};pin-file={}",
        module.display(),
        target.join("test-token.pin").display()
    );
    ea_recovery::KeySourceSpec::parse(std::ffi::OsStr::new(&source)).unwrap();
    source
}
