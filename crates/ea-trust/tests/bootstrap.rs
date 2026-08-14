use ea_crypto::{CanonicalPublicCoseKey, bootstrap_anchor_hash, object_hash, trust_anchor_hash};
use ea_time::TrustedTimeState;
use ea_trust::{
    ClockReleaseReplayKey, IndependentTimeCommit, PersistedTrustRecord, RegistryHeadPin,
    RegistrySelectionCommit, StateStoreError, TrustObjectSource, TrustSourceError, TrustStateKey,
    TrustStateStore, decode_trust_anchor, load_trust_state, verify_trust,
};
use ea_types::{DeviceId, OrganizationId, RegistryVersion, UnixMillis};
use minicbor::{Decoder, Encoder};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    ops::Range,
    sync::Arc,
};

const PRE_ANCHOR_HEX: &str = concat!(
    "8a782145494e5341545a4152434849562d54525553542d414e43484f522d5052452d763101",
    "50000102030405060708090a0b0c0d0e0f50101112131415161718191a1b1c1d1e1f",
    "5828a3010120062158202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
    "5820ee5ce0c67cc72d49015fb20337327af13572fc6ed9517fcc02edfb019342f36c",
    "5820909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
    "825820101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
    "5820303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
    "825820505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f",
    "5820707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f80",
);

const FINAL_ANCHOR_HEX: &str = concat!(
    "8c781d45494e5341545a4152434849562d54525553542d414e43484f522d763101",
    "5820b9318bc313a46ea719405295fd28e9226523f02d4a26533e5a41df0b3bd40978",
    "50000102030405060708090a0b0c0d0e0f50101112131415161718191a1b1c1d1e1f",
    "5828a3010120062158202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
    "5820ee5ce0c67cc72d49015fb20337327af13572fc6ed9517fcc02edfb019342f36c",
    "5820909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
    "825820101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
    "5820303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
    "825820505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f",
    "5820707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    "5820fb015b674e76a4b7924e0509dc91eda4a7e6c1f12fc4f997383059de425c1a6e80",
);

const BOOTSTRAP_ANCHOR_HASH_HEX: &str =
    "b9318bc313a46ea719405295fd28e9226523f02d4a26533e5a41df0b3bd40978";
const TRUST_ANCHOR_HASH_HEX: &str =
    "d4341b705e5b4f3c88ce69f5508ec8675e7c95c69befdbbf2f1477764ba21216";

const TASK5_ANCHOR_HEX: &str = concat!(
    "8c781d45494e5341545a4152434849562d54525553542d414e43484f522d763101",
    "582095c671496b9980738eaff4afb9a791ad39adfbedf53b97c599a2e4d6d22fd74b",
    "50212121212121212121212121212121215031313131313131313131313131313131",
    "5828a301012006215820d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "5820866eefbd6718c8846cd7ddfe43fc74ab1daac4538ff8514ea2ec2d410a415743",
    "58201ff2cb95ac5ab47d39ce2edfa8904d5fa4e871ab937608b653b176a7ee927ee3",
    "8258205a445148a98491bebdb938edc5a1ce215099ad935160b4cf50d51881f195fb3e",
    "5820e358370f85f5f097de41c5489b41fd24b2b374ac9756e717e494dd8498bb848a",
    "8258202af868be8dea000e4fdf678b29d1dc50208410d40e783edbc8f3cdd2b4908c30",
    "5820cbb83538597cf2984425cb7598629760a573891245ccba526a531223897f1425",
    "5820444444444444444444444444444444444444444444444444444444444444444480",
);

const TASK5_OBJECT_HEX: [&str; 5] = [
    concat!(
        "854445413100050180836f726f6f74436572746966696361746587015021212121212121212121212121212121",
        "5828a301012006215820d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "5820866eefbd6718c8846cd7ddfe43fc74ab1daac4538ff8514ea2ec2d410a415743f6008081",
        "d2845857a401320282030403782a6170706c69636174696f6e2f766e642e65696e7361747a6172636869762e74727573742d646967657374",
        "045820866eefbd6718c8846cd7ddfe43fc74ab1daac4538ff8514ea2ec2d410a415743a0",
        "58202eeda82328661f8584b3767ba4708bdf1ca5d6a0062e74c876290f905f8bd7e1",
        "5840fc071c8b6c28a9c0187f7887717ef247956a0149f3e17e20d5b149d38d85a820741a31335181f14a1d19f9a1a4bf074e0197a83d480d736525e2c7bf604ee406",
    ),
    concat!(
        "854445413100050180836f6f70657261746f7242696e64696e678b015021212121212121212121212121212121",
        "504141414141414141414141414141414158207171717171717171717171717171717171717171717171717171717171717171",
        "58205a445148a98491bebdb938edc5a1ce215099ad935160b4cf50d51881f195fb3e02",
        "58208181818181818181818181818181818181818181818181818181818181818181",
        "5820919191919191919191919191919191919191919191919191919191919191919100f68081",
        "d2845899a50132028303046f63657274696669636174654861736803782a6170706c69636174696f6e2f766e642e65696e7361747a6172636869762e74727573742d646967657374",
        "045820866eefbd6718c8846cd7ddfe43fc74ab1daac4538ff8514ea2ec2d410a415743",
        "6f63657274696669636174654861736858201ff2cb95ac5ab47d39ce2edfa8904d5fa4e871ab937608b653b176a7ee927ee3a0",
        "5820461e59f5a0f7062dc692ae7440112cb8d910cf359894b52fd9415b2d35f99fa9",
        "58404bd1a39dd63af0fb44a5dcb11264205b5ae38726423914b897ae8db94dca2193d55bfe407ba4abf86e5bd6df73efce6b425f0bb6f725044dc4c2a982b8aac80e",
    ),
    concat!(
        "854445413100050180837164657669636543657274696669636174658e015021212121212121212121212121212121",
        "505151515151515151515151515151515102",
        "5828a3010120062158203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660cf6",
        "58205c840f7a40230170abdee5151a594efdf270f7a89825f5c310badf6b589c5c59f681",
        "78186f7267616e697a6174696f6e41646d696e417070726f76650000f650414141414141414141414141414141418081",
        "d2845899a50132028303046f63657274696669636174654861736803782a6170706c69636174696f6e2f766e642e65696e7361747a6172636869762e74727573742d646967657374",
        "045820866eefbd6718c8846cd7ddfe43fc74ab1daac4538ff8514ea2ec2d410a415743",
        "6f63657274696669636174654861736858201ff2cb95ac5ab47d39ce2edfa8904d5fa4e871ab937608b653b176a7ee927ee3a0",
        "582037a5f61c0bc83008d7a3280dfa13da71fdc6105ad4b5abd9bff91dd41b478873",
        "58403804d9cac2dbf35538b724f9dd2dcd264756fb388c8ffe88747a339d0ff3c812729633c16547b77da5580616ec05cd2b0e359c78eb441bd75b0425d0d657580e",
    ),
    concat!(
        "854445413100050180836f6f70657261746f7242696e64696e678b015021212121212121212121212121212121",
        "504242424242424242424242424242424258207171717171717171717171717171717171717171717171717171717171717171",
        "5820e358370f85f5f097de41c5489b41fd24b2b374ac9756e717e494dd8498bb848a02",
        "58208282828282828282828282828282828282828282828282828282828282828282",
        "5820929292929292929292929292929292929292929292929292929292929292929200f68081",
        "d2845899a50132028303046f63657274696669636174654861736803782a6170706c69636174696f6e2f766e642e65696e7361747a6172636869762e74727573742d646967657374",
        "045820866eefbd6718c8846cd7ddfe43fc74ab1daac4538ff8514ea2ec2d410a415743",
        "6f63657274696669636174654861736858201ff2cb95ac5ab47d39ce2edfa8904d5fa4e871ab937608b653b176a7ee927ee3a0",
        "58206d99471cce52d1fb0666dabd2914db62d3e9f130d63453fcfbc9dff60b176d00",
        "58409ea265289c51d28133c1c66eee8678c0fc5640bff24954a28d0838a67e4fe0be84b8e238ed1fe373f5d0c7ea6a2062fcf60f0a3f4b82946f1199ca768e139000",
    ),
    concat!(
        "854445413100050180837164657669636543657274696669636174658e015021212121212121212121212121212121",
        "505252525252525252525252525252525202",
        "5828a301012006215820fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025f6",
        "582051d53691575b17e32587f41e5b9c85feeec5cccd5c0826be4abd2dfe7d33a6eef681",
        "78186f7267616e697a6174696f6e41646d696e417070726f76650000f650424242424242424242424242424242428081",
        "d2845899a50132028303046f63657274696669636174654861736803782a6170706c69636174696f6e2f766e642e65696e7361747a6172636869762e74727573742d646967657374",
        "045820866eefbd6718c8846cd7ddfe43fc74ab1daac4538ff8514ea2ec2d410a415743",
        "6f63657274696669636174654861736858201ff2cb95ac5ab47d39ce2edfa8904d5fa4e871ab937608b653b176a7ee927ee3a0",
        "58209f9ce7b6b0fee9bcf02b91a9d67f5fb3acf0b2e97146cd6a9254987c7ec59527",
        "58402b6ecd5b8a7238c39b87da20087f92a6c65610629ed19b71e464571b882de34d6746ea40167c1b840e380ed196281ab7e9ec14d71c458e90c53916c7d67a3509",
    ),
];

#[test]
fn final_anchor_reconstructs_the_pinned_pre_anchor_and_all_exact_pins() {
    let exact_final = decode_hex(FINAL_ANCHOR_HEX);
    let anchor = decode_trust_anchor(&exact_final).expect("pinned final Anchor must decode");

    assert_eq!(anchor.exact_bytes(), exact_final);
    assert_eq!(anchor.exact_pre_anchor_bytes(), decode_hex(PRE_ANCHOR_HEX));
    assert_eq!(
        anchor.bootstrap_anchor_hash().as_bytes(),
        decode_hex(BOOTSTRAP_ANCHOR_HASH_HEX).as_slice()
    );
    assert_eq!(
        anchor.trust_anchor_hash().as_bytes(),
        decode_hex(TRUST_ANCHOR_HASH_HEX).as_slice()
    );
    assert_eq!(anchor.organization_id().as_bytes(), &ascending::<16>(0x00));
    assert_eq!(anchor.chain_id().as_bytes(), &ascending::<16>(0x10));
    assert_eq!(
        anchor.root_public_cose_key_bytes(),
        decode_hex(
            "a3010120062158202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
        )
    );
    assert_eq!(
        anchor.root_key_thumbprint().as_bytes(),
        decode_hex("ee5ce0c67cc72d49015fb20337327af13572fc6ed9517fcc02edfb019342f36c").as_slice()
    );
    assert_eq!(
        anchor.root_certificate_object_hash().as_bytes(),
        &ascending::<32>(0x90)
    );
    assert_eq!(anchor.initial_admin_certificate_object_hashes().len(), 2);
    assert_eq!(
        anchor.initial_admin_certificate_object_hashes()[0].as_bytes(),
        &ascending::<32>(0x10)
    );
    assert_eq!(
        anchor.initial_admin_certificate_object_hashes()[1].as_bytes(),
        &ascending::<32>(0x30)
    );
    assert_eq!(
        anchor.initial_admin_operator_binding_object_hashes()[0].as_bytes(),
        &ascending::<32>(0x50)
    );
    assert_eq!(
        anchor.initial_admin_operator_binding_object_hashes()[1].as_bytes(),
        &ascending::<32>(0x70)
    );
    assert_eq!(
        anchor.genesis_entry_hash().as_bytes(),
        decode_hex("fb015b674e76a4b7924e0509dc91eda4a7e6c1f12fc4f997383059de425c1a6e").as_slice()
    );
}

#[test]
fn verified_bootstrap_owns_the_exact_anchor_catalog_and_state_snapshot() {
    let anchor_bytes = decode_hex(TASK5_ANCHOR_HEX);
    let anchor = decode_trust_anchor(&anchor_bytes).expect("Task 5 Anchor must decode");
    let source = PinnedTask5Source::new();
    let key = TrustStateKey {
        organization_id: anchor.organization_id(),
        device_id: DeviceId::try_from([0xf0; 16].as_slice()).unwrap(),
    };
    let persisted_head = RegistryHeadPin::new(
        RegistryVersion::new(9),
        object_hash(b"not-yet-correlated Task 7 Registry pin"),
    );
    let mut store = MemoryStore {
        key,
        persisted: PersistedTrustRecord::new(
            37,
            TrustedTimeState::initial(UnixMillis::new(1_700_000_000_000)),
            Some(persisted_head),
        ),
    };
    let snapshot = load_trust_state(&mut store, key).unwrap();

    let verified = verify_trust(&anchor, &source, snapshot)
        .expect("two exact Root-signed and Anchor-pinned Admin pairs must verify");
    assert!(verified.organization_id() == anchor.organization_id());
    assert!(verified.chain_id() == anchor.chain_id());
    assert!(verified.trust_anchor_hash() == anchor.trust_anchor_hash());
    assert!(verified.state_key() == key);
    assert_eq!(verified.state_revision(), 37);
    assert_eq!(
        verified.trusted_time().floor(),
        UnixMillis::new(1_700_000_000_000)
    );
    assert!(verified.pinned_head() == Some(&persisted_head));
    assert_eq!(source.visits.get(), 1);
    assert!(source.reads.borrow().values().all(|count| *count == 1));

    drop(source);
    assert_eq!(verified.state_revision(), 37);
    assert_eq!(verified.initial_admin_pair_count(), 2);
}

#[test]
fn final_anchor_shared_fields_lists_and_exact_shape_fail_closed() {
    let exact_final = decode_hex(FINAL_ANCHOR_HEX);
    let offsets = anchor_offsets(&exact_final);
    let mut attacks = vec![
        (
            "domain",
            mutate_byte(&exact_final, offsets.domain.start, b'X'),
            "EA-TRUST-ANCHOR-SHAPE",
        ),
        (
            "version",
            mutate_byte(&exact_final, offsets.version, 2),
            "EA-TRUST-ANCHOR-SHAPE",
        ),
        (
            "bootstrap hash",
            flip_byte(&exact_final, offsets.bootstrap_hash.start),
            "EA-TRUST-ANCHOR-HASH",
        ),
        (
            "organization",
            flip_byte(&exact_final, offsets.organization.start),
            "EA-TRUST-ANCHOR-HASH",
        ),
        (
            "chain",
            flip_byte(&exact_final, offsets.chain.start),
            "EA-TRUST-ANCHOR-HASH",
        ),
        (
            "valid alternative COSE key curve",
            mutate_byte(&exact_final, offsets.root_key.start + 4, 4),
            "EA-TRUST-ANCHOR-PIN",
        ),
        (
            "root thumbprint",
            flip_byte(&exact_final, offsets.root_thumbprint.start),
            "EA-TRUST-ANCHOR-PIN",
        ),
        (
            "root certificate object hash",
            flip_byte(&exact_final, offsets.root_certificate_hash.start),
            "EA-TRUST-ANCHOR-HASH",
        ),
        (
            "admin certificate hash",
            flip_byte(&exact_final, offsets.admin_certificates[0].end - 1),
            "EA-TRUST-ANCHOR-HASH",
        ),
        (
            "admin Binding hash",
            flip_byte(&exact_final, offsets.admin_bindings[0].end - 1),
            "EA-TRUST-ANCHOR-HASH",
        ),
    ];

    let mut unsorted_certificates = exact_final.clone();
    swap_ranges(
        &mut unsorted_certificates,
        offsets.admin_certificates[0].clone(),
        offsets.admin_certificates[1].clone(),
    );
    attacks.push((
        "unsorted Admin certificate list",
        unsorted_certificates,
        "EA-TRUST-ANCHOR-SHAPE",
    ));

    let mut duplicate_certificates = exact_final.clone();
    copy_range(
        &mut duplicate_certificates,
        offsets.admin_certificates[0].clone(),
        offsets.admin_certificates[1].clone(),
    );
    attacks.push((
        "duplicate Admin certificate",
        duplicate_certificates,
        "EA-TRUST-ANCHOR-SHAPE",
    ));

    let mut unsorted_bindings = exact_final.clone();
    swap_ranges(
        &mut unsorted_bindings,
        offsets.admin_bindings[0].clone(),
        offsets.admin_bindings[1].clone(),
    );
    attacks.push((
        "unsorted Admin Binding list",
        unsorted_bindings,
        "EA-TRUST-ANCHOR-SHAPE",
    ));

    let mut duplicate_bindings = exact_final.clone();
    copy_range(
        &mut duplicate_bindings,
        offsets.admin_bindings[0].clone(),
        offsets.admin_bindings[1].clone(),
    );
    attacks.push((
        "duplicate Admin Binding",
        duplicate_bindings,
        "EA-TRUST-ANCHOR-SHAPE",
    ));

    attacks.push((
        "only one Admin pair",
        encode_final_anchor_with_lists(&[ascending::<32>(0x10)], &[ascending::<32>(0x50)]),
        "EA-TRUST-ANCHOR-SHAPE",
    ));
    attacks.push((
        "unequal Admin list counts",
        encode_final_anchor_with_lists(
            &[ascending::<32>(0x10), ascending::<32>(0x30)],
            &[ascending::<32>(0x50)],
        ),
        "EA-TRUST-ANCHOR-SHAPE",
    ));

    let mut nonempty_extensions = exact_final.clone();
    *nonempty_extensions.last_mut().expect("fixture is nonempty") = 0x81;
    nonempty_extensions.push(0);
    attacks.push((
        "critical extension",
        nonempty_extensions,
        "EA-TRUST-ANCHOR-SHAPE",
    ));

    let mut trailing_item = exact_final.clone();
    trailing_item.push(0);
    attacks.push(("trailing item", trailing_item, "EA-TRUST-ANCHOR-SHAPE"));

    let mut nonminimal_version = exact_final.clone();
    nonminimal_version.splice(offsets.version..=offsets.version, [0x18, 0x01]);
    attacks.push((
        "non-minimal deterministic CBOR",
        nonminimal_version,
        "EA-TRUST-ANCHOR-SHAPE",
    ));

    for (label, bytes, expected_code) in attacks {
        let error = match decode_trust_anchor(&bytes) {
            Ok(_) => panic!("{label} must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.code(), expected_code, "{label}");
        assert_eq!(error.to_string(), expected_code, "{label}");
        assert_eq!(format!("{error:?}"), expected_code, "{label}");
    }
}

#[test]
fn genesis_mutation_defines_a_distinct_final_anchor_without_changing_pre_anchor() {
    let exact_final = decode_hex(FINAL_ANCHOR_HEX);
    let offsets = anchor_offsets(&exact_final);
    let original = decode_trust_anchor(&exact_final).expect("pinned final Anchor must decode");
    let changed_bytes = flip_byte(&exact_final, offsets.genesis.start);
    let changed = decode_trust_anchor(&changed_bytes).expect("a different pinned genesis is valid");

    assert_eq!(
        changed.exact_pre_anchor_bytes(),
        original.exact_pre_anchor_bytes()
    );
    assert_ne!(
        changed.genesis_entry_hash().as_bytes(),
        original.genesis_entry_hash().as_bytes()
    );
    assert_ne!(
        changed.trust_anchor_hash().as_bytes(),
        original.trust_anchor_hash().as_bytes()
    );
}

#[test]
fn self_consistent_x25519_root_anchor_is_rejected() {
    let root_key = CanonicalPublicCoseKey::x25519([0x44; 32]).unwrap();
    let exact_root_key = root_key.to_deterministic_cbor();
    let root_thumbprint = root_key.thumbprint();
    let pre_anchor = encode_pre_anchor_for_key(&exact_root_key, root_thumbprint.as_bytes());
    let bootstrap_hash = bootstrap_anchor_hash(&pre_anchor);
    let final_anchor = encode_final_anchor_parts(
        &exact_root_key,
        root_thumbprint.as_bytes(),
        bootstrap_hash.as_bytes(),
        &[ascending::<32>(0x10), ascending::<32>(0x30)],
        &[ascending::<32>(0x50), ascending::<32>(0x70)],
    );
    let recomputed_final_hash = trust_anchor_hash(&final_anchor);
    assert_ne!(
        recomputed_final_hash.as_bytes(),
        decode_hex(TRUST_ANCHOR_HASH_HEX).as_slice()
    );

    let error = match decode_trust_anchor(&final_anchor) {
        Ok(_) => panic!("an organization Root must not use the X25519 KEM key type"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "EA-TRUST-ANCHOR-PIN");
}

#[test]
fn anchor_preflight_rejects_oversized_key_and_unbounded_or_indefinite_lists() {
    let exact_final = decode_hex(FINAL_ANCHOR_HEX);
    let offsets = anchor_offsets(&exact_final);

    let mut oversized_root_key = exact_final.clone();
    let root_key_header_length = offsets.root_key.start - 1;
    assert_eq!(oversized_root_key[root_key_header_length], 40);
    oversized_root_key[root_key_header_length] = 41;
    oversized_root_key.insert(offsets.root_key.end, 0);

    let mut indefinite_certificates = exact_final.clone();
    let certificate_list_header = offsets.admin_certificates[0].start - 3;
    assert_eq!(indefinite_certificates[certificate_list_header], 0x82);
    indefinite_certificates[certificate_list_header] = 0x9f;
    indefinite_certificates.insert(offsets.admin_certificates[1].end, 0xff);

    let oversized_certificates = vec![[0x10; 32]; 10_001];
    let oversized_list = encode_final_anchor_with_lists(
        &oversized_certificates,
        &[ascending::<32>(0x50), ascending::<32>(0x70)],
    );

    for (label, bytes) in [
        ("oversized Root key", oversized_root_key),
        ("indefinite Admin certificate list", indefinite_certificates),
        ("oversized Admin certificate list", oversized_list),
    ] {
        let error = match decode_trust_anchor(&bytes) {
            Ok(_) => panic!("{label} must fail the bounded flat preflight"),
            Err(error) => error,
        };
        assert_eq!(error.code(), "EA-TRUST-ANCHOR-SHAPE", "{label}");
    }
}

#[test]
fn state_port_is_externally_implementable_without_forging_a_snapshot() {
    let key = TrustStateKey {
        organization_id: OrganizationId::try_from([0x41; 16].as_slice()).unwrap(),
        device_id: DeviceId::try_from([0x42; 16].as_slice()).unwrap(),
    };
    let head = RegistryHeadPin::new(
        RegistryVersion::new(7),
        ea_types::ObjectHash::try_from([0x43; 32].as_slice()).unwrap(),
    );
    let persisted = PersistedTrustRecord::new(
        11,
        TrustedTimeState::initial(UnixMillis::new(1_700_000_000_000)),
        Some(head),
    );
    assert_eq!(persisted.revision(), 11);
    assert_eq!(
        persisted.trusted_time().floor(),
        UnixMillis::new(1_700_000_000_000)
    );
    assert_eq!(
        persisted
            .pinned_head()
            .expect("test record has a pinned head")
            .registry_version(),
        RegistryVersion::new(7)
    );

    let mut store = MemoryStore { key, persisted };
    let snapshot = load_trust_state(&mut store, key).expect("store record is valid");

    assert!(snapshot.key() == key);
    assert_eq!(snapshot.revision(), 11);
    assert_eq!(
        snapshot.trusted_time().floor(),
        UnixMillis::new(1_700_000_000_000)
    );
    assert_eq!(
        snapshot
            .pinned_head()
            .expect("snapshot preserves the pin")
            .registry_head_hash()
            .as_bytes(),
        &[0x43; 32]
    );
}

#[test]
fn state_store_errors_map_to_static_secret_free_trust_codes() {
    let key = TrustStateKey {
        organization_id: OrganizationId::try_from([0x51; 16].as_slice()).unwrap(),
        device_id: DeviceId::try_from([0x52; 16].as_slice()).unwrap(),
    };
    let cases = [
        (StateStoreError::Conflict, "EA-TRUST-STATE-CONFLICT"),
        (
            StateStoreError::ReplayAlreadyConsumed,
            "EA-TRUST-CLOCK-RELEASE-REPLAY",
        ),
        (
            StateStoreError::MonotonicityViolation,
            "EA-TRUST-STATE-MONOTONICITY",
        ),
        (StateStoreError::Unavailable, "EA-TRUST-STATE-UNAVAILABLE"),
    ];

    for (store_error, expected_code) in cases {
        assert_eq!(store_error.code(), expected_code);
        assert_eq!(store_error.to_string(), expected_code);
        assert_eq!(format!("{store_error:?}"), expected_code);
        let mut store = FailingStore { error: store_error };
        let trust_error = match load_trust_state(&mut store, key) {
            Ok(_) => panic!("a state load error must fail closed"),
            Err(error) => error,
        };
        assert_eq!(trust_error.code(), expected_code);
        assert_eq!(trust_error.to_string(), expected_code);
        assert_eq!(format!("{trust_error:?}"), expected_code);
    }
}

struct MemoryStore {
    key: TrustStateKey,
    persisted: PersistedTrustRecord,
}

struct PinnedTask5Source {
    hashes: Vec<ea_types::ObjectHash>,
    objects: BTreeMap<ea_types::ObjectHash, Arc<[u8]>>,
    visits: Cell<usize>,
    reads: RefCell<BTreeMap<ea_types::ObjectHash, usize>>,
}

impl PinnedTask5Source {
    fn new() -> Self {
        let mut objects = BTreeMap::new();
        let mut hashes = Vec::new();
        for literal in TASK5_OBJECT_HEX {
            let exact: Arc<[u8]> = Arc::from(decode_hex(literal));
            let hash = object_hash(&exact);
            assert!(objects.insert(hash, exact).is_none());
            hashes.push(hash);
        }
        hashes.reverse();
        Self {
            hashes,
            objects,
            visits: Cell::new(0),
            reads: RefCell::new(BTreeMap::new()),
        }
    }
}

impl TrustObjectSource for PinnedTask5Source {
    fn visit_trust_object_hashes(
        &self,
        visitor: &mut dyn FnMut(ea_types::ObjectHash) -> Result<(), TrustSourceError>,
    ) -> Result<(), TrustSourceError> {
        self.visits.set(self.visits.get() + 1);
        for hash in &self.hashes {
            visitor(*hash)?;
        }
        Ok(())
    }

    fn read_exact_trust_object(
        &self,
        object_hash: ea_types::ObjectHash,
    ) -> Result<Option<Arc<[u8]>>, TrustSourceError> {
        *self.reads.borrow_mut().entry(object_hash).or_default() += 1;
        Ok(self.objects.get(&object_hash).cloned())
    }
}

struct FailingStore {
    error: StateStoreError,
}

impl TrustStateStore for FailingStore {
    fn load(&mut self, _key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(self.error)
    }

    fn commit_independent_time(
        &mut self,
        _key: TrustStateKey,
        _expected_revision: u64,
        _commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(self.error)
    }

    fn clock_release_consumed(
        &mut self,
        _key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        Err(self.error)
    }

    fn commit_registry_selection(
        &mut self,
        _key: TrustStateKey,
        _expected_revision: u64,
        _commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(self.error)
    }
}

impl TrustStateStore for MemoryStore {
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        if key != self.key {
            return Err(StateStoreError::Unavailable);
        }
        Ok(PersistedTrustRecord::new(
            self.persisted.revision(),
            self.persisted.trusted_time().clone(),
            self.persisted.pinned_head().copied(),
        ))
    }

    fn commit_independent_time(
        &mut self,
        _key: TrustStateKey,
        _expected_revision: u64,
        commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        let _ = commit.next_trusted_time();
        Err(StateStoreError::Conflict)
    }

    fn clock_release_consumed(
        &mut self,
        key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        let _ = (key.organization_id(), key.target_device_id(), key.nonce());
        Ok(false)
    }

    fn commit_registry_selection(
        &mut self,
        _key: TrustStateKey,
        _expected_revision: u64,
        commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        let _ = (
            commit.next_trusted_time(),
            commit.next_head(),
            commit.replay_key(),
        );
        Err(StateStoreError::MonotonicityViolation)
    }
}

fn decode_hex(input: &str) -> Vec<u8> {
    assert!(input.len().is_multiple_of(2));
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]);
            let low = hex_nibble(pair[1]);
            (high << 4) | low
        })
        .collect()
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("fixture contains only lowercase hexadecimal"),
    }
}

fn ascending<const N: usize>(start: u8) -> [u8; N] {
    std::array::from_fn(|index| start.wrapping_add(u8::try_from(index).unwrap()))
}

struct AnchorOffsets {
    domain: Range<usize>,
    version: usize,
    bootstrap_hash: Range<usize>,
    organization: Range<usize>,
    chain: Range<usize>,
    root_key: Range<usize>,
    root_thumbprint: Range<usize>,
    root_certificate_hash: Range<usize>,
    admin_certificates: [Range<usize>; 2],
    admin_bindings: [Range<usize>; 2],
    genesis: Range<usize>,
}

fn anchor_offsets(input: &[u8]) -> AnchorOffsets {
    let mut decoder = Decoder::new(input);
    assert_eq!(decoder.array().unwrap(), Some(12));
    let domain = text_contents(&mut decoder);
    let version = decoder.position();
    assert_eq!(decoder.u64().unwrap(), 1);
    let bootstrap_hash = bytes_contents(&mut decoder);
    let organization = bytes_contents(&mut decoder);
    let chain = bytes_contents(&mut decoder);
    let root_key = bytes_contents(&mut decoder);
    let root_thumbprint = bytes_contents(&mut decoder);
    let root_certificate_hash = bytes_contents(&mut decoder);
    assert_eq!(decoder.array().unwrap(), Some(2));
    let admin_certificates = [bytes_contents(&mut decoder), bytes_contents(&mut decoder)];
    assert_eq!(decoder.array().unwrap(), Some(2));
    let admin_bindings = [bytes_contents(&mut decoder), bytes_contents(&mut decoder)];
    let genesis = bytes_contents(&mut decoder);
    assert_eq!(decoder.array().unwrap(), Some(0));
    assert_eq!(decoder.position(), input.len());
    AnchorOffsets {
        domain,
        version,
        bootstrap_hash,
        organization,
        chain,
        root_key,
        root_thumbprint,
        root_certificate_hash,
        admin_certificates,
        admin_bindings,
        genesis,
    }
}

fn text_contents(decoder: &mut Decoder<'_>) -> Range<usize> {
    let value = decoder.str().unwrap();
    decoder.position() - value.len()..decoder.position()
}

fn bytes_contents(decoder: &mut Decoder<'_>) -> Range<usize> {
    let value = decoder.bytes().unwrap();
    decoder.position() - value.len()..decoder.position()
}

fn mutate_byte(input: &[u8], index: usize, value: u8) -> Vec<u8> {
    let mut mutated = input.to_vec();
    mutated[index] = value;
    mutated
}

fn flip_byte(input: &[u8], index: usize) -> Vec<u8> {
    mutate_byte(input, index, input[index] ^ 1)
}

fn swap_ranges(bytes: &mut [u8], left: Range<usize>, right: Range<usize>) {
    assert_eq!(left.len(), right.len());
    let left_value = bytes[left.clone()].to_vec();
    let right_value = bytes[right.clone()].to_vec();
    bytes[left].copy_from_slice(&right_value);
    bytes[right].copy_from_slice(&left_value);
}

fn copy_range(bytes: &mut [u8], source: Range<usize>, target: Range<usize>) {
    assert_eq!(source.len(), target.len());
    let source_value = bytes[source].to_vec();
    bytes[target].copy_from_slice(&source_value);
}

fn encode_final_anchor_with_lists(
    admin_certificates: &[[u8; 32]],
    admin_bindings: &[[u8; 32]],
) -> Vec<u8> {
    encode_final_anchor_parts(
        &decode_hex(
            "a3010120062158202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
        ),
        &decode_hex("ee5ce0c67cc72d49015fb20337327af13572fc6ed9517fcc02edfb019342f36c"),
        &decode_hex(BOOTSTRAP_ANCHOR_HASH_HEX),
        admin_certificates,
        admin_bindings,
    )
}

fn encode_final_anchor_parts(
    exact_root_key: &[u8],
    root_thumbprint: &[u8],
    bootstrap_hash: &[u8],
    admin_certificates: &[[u8; 32]],
    admin_bindings: &[[u8; 32]],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .array(12)
        .unwrap()
        .str("EINSATZARCHIV-TRUST-ANCHOR-v1")
        .unwrap()
        .u64(1)
        .unwrap()
        .bytes(bootstrap_hash)
        .unwrap()
        .bytes(&ascending::<16>(0x00))
        .unwrap()
        .bytes(&ascending::<16>(0x10))
        .unwrap()
        .bytes(exact_root_key)
        .unwrap()
        .bytes(root_thumbprint)
        .unwrap()
        .bytes(&ascending::<32>(0x90))
        .unwrap()
        .array(u64::try_from(admin_certificates.len()).unwrap())
        .unwrap();
    for hash in admin_certificates {
        encoder.bytes(hash).unwrap();
    }
    encoder
        .array(u64::try_from(admin_bindings.len()).unwrap())
        .unwrap();
    for hash in admin_bindings {
        encoder.bytes(hash).unwrap();
    }
    encoder
        .bytes(&decode_hex(
            "fb015b674e76a4b7924e0509dc91eda4a7e6c1f12fc4f997383059de425c1a6e",
        ))
        .unwrap()
        .array(0)
        .unwrap();
    bytes
}

fn encode_pre_anchor_for_key(exact_root_key: &[u8], root_thumbprint: &[u8]) -> Vec<u8> {
    let certificates = [ascending::<32>(0x10), ascending::<32>(0x30)];
    let bindings = [ascending::<32>(0x50), ascending::<32>(0x70)];
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .array(10)
        .unwrap()
        .str("EINSATZARCHIV-TRUST-ANCHOR-PRE-v1")
        .unwrap()
        .u64(1)
        .unwrap()
        .bytes(&ascending::<16>(0x00))
        .unwrap()
        .bytes(&ascending::<16>(0x10))
        .unwrap()
        .bytes(exact_root_key)
        .unwrap()
        .bytes(root_thumbprint)
        .unwrap()
        .bytes(&ascending::<32>(0x90))
        .unwrap()
        .array(2)
        .unwrap();
    for hash in certificates {
        encoder.bytes(&hash).unwrap();
    }
    encoder.array(2).unwrap();
    for hash in bindings {
        encoder.bytes(&hash).unwrap();
    }
    encoder.array(0).unwrap();
    bytes
}
