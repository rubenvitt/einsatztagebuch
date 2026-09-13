//! Provision public test vectors into the explicitly isolated SoftHSM fixture.
//! This example is excluded unless the dedicated fixture feature is selected.
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    object::{Attribute as A, KeyType, ObjectClass},
    session::UserType,
    types::AuthPin,
};
use ea_crypto::{CoseSigner, HpkeRecipientPrivateKey, SecretBytes};

fn main() {
    let module =
        std::env::var_os("EA_TEST_PKCS11_MODULE").expect("explicit isolated fixture module");
    let context = Pkcs11::new(module).unwrap();
    context
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();
    let info = context.get_library_info().unwrap();
    assert_eq!(info.manufacturer_id(), "SoftHSM");
    assert_eq!(info.library_description(), "Implementation of PKCS11");
    assert_eq!(info.library_version().major(), 2);
    assert_eq!(info.library_version().minor(), 7);
    let slots: Vec<_> = context
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .filter(|slot| context.get_token_info(*slot).unwrap().label() == "drk250-fixture")
        .collect();
    assert_eq!(slots.len(), 1, "exact isolated fixture token required");
    let session = context.open_rw_session(slots[0]).unwrap();
    session
        .login(UserType::User, Some(&AuthPin::new("12345678".into())))
        .unwrap();
    // Public repository fixture vectors. Never operator-supplied key material.
    let recovery = [
        0x4c, 0x2b, 0x1f, 0x90, 0x77, 0xd3, 0x0a, 0x65, 0xb8, 0x11, 0xe4, 0x39, 0x5d, 0xa7, 0xc0,
        0x62, 0x8e, 0x14, 0x73, 0xbb, 0x2f, 0x96, 0x51, 0xcd, 0x08, 0xaf, 0x36, 0x7a, 0xd2, 0x45,
        0x19, 0x83,
    ];
    let signing = [
        0x83, 0x3f, 0xe6, 0x24, 0x09, 0x23, 0x7b, 0x9d, 0x62, 0xec, 0x77, 0x58, 0x75, 0x20, 0x91,
        0x1e, 0x9a, 0x75, 0x9c, 0xec, 0x1d, 0x19, 0x75, 0x5b, 0x7d, 0xa9, 0x01, 0xb9, 0x6d, 0xca,
        0x3d, 0x42,
    ];
    for (id, seed, curve) in [
        (0xa1, [0x71; 32], 0x6e),
        (0xb1, [0x72; 32], 0x70),
        (0xc1, recovery, 0x6e),
        (0xd1, signing, 0x70),
    ] {
        // Idempotence only for already provisioned fixture IDs. Product tests
        // independently compare c1/d1 against the signed fixture certificate.
        let existing = session.find_objects(&[A::Id(vec![id])]).unwrap();
        if !existing.is_empty() {
            assert_eq!(existing.len(), 2);
            continue;
        }
        let public = if curve == 0x6e {
            HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(seed))
                .unwrap()
                .public_key()
                .as_bytes()
                .to_vec()
        } else {
            let ea_crypto::CanonicalPublicCoseKey::Ed25519(bytes) =
                CoseSigner::from_secret(SecretBytes::new(seed))
                    .public_key()
                    .unwrap()
            else {
                unreachable!()
            };
            bytes.to_vec()
        };
        let oid = vec![6, 3, 0x2b, 0x65, curve];
        session
            .create_object(&[
                A::Class(ObjectClass::PUBLIC_KEY),
                A::KeyType(KeyType::EC_EDWARDS),
                A::Token(true),
                A::Private(false),
                A::Id(vec![id]),
                A::Label(b"drk250-public-test-vector".to_vec()),
                A::EcParams(oid.clone()),
                A::EcPoint(public),
            ])
            .unwrap();
        session
            .create_object(&[
                A::Class(ObjectClass::PRIVATE_KEY),
                A::KeyType(KeyType::EC_EDWARDS),
                A::Token(true),
                A::Private(true),
                A::Sensitive(true),
                A::Extractable(false),
                A::AlwaysAuthenticate(false),
                A::Id(vec![id]),
                A::Label(b"drk250-private-test-vector".to_vec()),
                A::EcParams(oid),
                A::Value(seed.to_vec()),
                A::Derive(curve == 0x6e),
                A::Sign(curve == 0x70),
            ])
            .unwrap();
    }
    session.logout().unwrap();
    drop(session);
    context.finalize().unwrap();
    println!("Isolated SoftHSM fixture vectors provisioned.");
}
