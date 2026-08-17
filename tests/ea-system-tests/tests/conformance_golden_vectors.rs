//! Die eingefrorene Vektorfamilie `crypto/suite-1` gegen die echte
//! `ea-crypto`-API.
//!
//! DIES IST KEIN SNAPSHOT-ABGLEICH GEGEN SICH SELBST. Der Test liest die
//! eingefrorenen Bytes, fuehrt jede Primitive tatsaechlich aus und stellt das
//! Ergebnis gegen die Datei. Wo ein veroeffentlichter Known-Answer-Test
//! existiert — RFC 8032 §7.1 fuer Ed25519, RFC 8439 §2.8.2 fuer
//! ChaCha20-Poly1305, RFC 7748 §6.1 fuer X25519, FIPS 180-4 fuer SHA-256 —
//! stammen Eingabe UND Ausgabe aus dem Standard, nicht aus diesem Workspace.
//!
//! # Warum HPKE nur in der entkapselnden Richtung geprueft wird
//!
//! `ea_crypto::hpke_seal` zieht bei jedem Aufruf einen frischen ephemeren
//! Schluessel aus dem Betriebssystem; der Injektionspunkt fuer Testentropie ist
//! privat und durch einen `compile_fail`-Doctest gegen Veroeffentlichung
//! gesichert (`crates/ea-crypto/src/hpke.rs`). Die Kapselung ist damit von
//! aussen NICHT reproduzierbar, und ein Vektor, der sie nachrechnen wollte,
//! muesste entweder die API aufweiten oder bei jedem Lauf andere Bytes
//! erzeugen. Die Vektoren dieser Familie halten `enc` und den umschlossenen CEK
//! deshalb EINMAL fest und pruefen sie deterministisch ueber `hpke_open` nach;
//! das Manifest sagt das mit `VectorSource::FrozenOnce` ausdruecklich an.
//!
//! Die RFC-9180-Vektoren aus Anhang A sind hier nicht einsetzbar: `hpke_open`
//! ist auf genau 32 Byte Klartext (den CEK) und 48 Byte Chiffrat festgelegt,
//! waehrend die Anhangsvektoren beliebige Nachrichten kapseln. Die
//! RFC-9180-Bindung entsteht stattdessen ueber die eingefrorenen
//! Suite-Identifikatoren und die KEM-Schluesselableitung aus RFC 7748.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    sync::Arc,
};

use ea_crypto::{
    AEAD_NONCE_SIZE, CEK_SIZE, CanonicalPublicCoseKey, ContentType, GRANT_SUITE_ID, HPKE_AEAD_ID,
    HPKE_ENCAPSULATED_KEY_SIZE, HPKE_KDF_ID, HPKE_KEM_ID, HPKE_MODE, HPKE_WRAPPED_CEK_SIZE,
    HpkeRecipientPrivateKey, HpkeSealed, ProtectedHeader, SUITE_ID, SecretBytes, SecretVec,
    aead_open, aead_seal, authorized_trust_digest, bootstrap_anchor_hash, ciphertext_digest,
    cose_sign1_ctt_imprint, entry_hash, grant_digest, grant_plan_digest, hpke_aad, hpke_info,
    hpke_open, linux_os_account_binding_hash, object_hash, operator_profile_digest,
    parse_cose_sign1, payload_aad, receipt_digest, record_digest, recovery_test_digest,
    renewal_input_digest, trust_anchor_hash, trust_digest, validate_unsigned_protocol_core,
    verification_report_hash,
};
use ea_format::{
    DecodedEvidencePayloadV1, DecodedTrustPayloadV1, GrantKindV1, GrantPlanItemV1, GrantPlanV1,
    GrantPurposeV1, GrantV1, ParsedArchiveObject, ReceiptV1, Rfc3161EvidenceFieldsV1,
    decode_exact_object,
};
use ea_schema::{CommonHeaderV1, NativeSourceV1, OperatorSnapshotV1, SchemaRegistry};
use ea_system_tests::workspace_root;
use ea_testkit::{
    ED25519_RFC8032_TEST1_SEED, ED25519_RFC8032_TEST2_SEED, EVIDENCE_TOKEN_MESSAGE_IMPRINT_OFFSET,
    EVIDENCE_TOKEN_POLICY_OID_LENGTH, EVIDENCE_TOKEN_POLICY_OID_OFFSET, ExpectedOutcome,
    GRANT_PLAN_ITEM_BYTES, TEST_ENTROPY_AEAD_NONCE, TEST_ENTROPY_CONTENT_ENCRYPTION_KEY,
    TEST_ENTROPY_RECIPIENT_X25519_SEED, VectorEntry, VectorManifest, VectorSource,
    X25519_RFC7748_BOB_PRIVATE_KEY, X25519_RFC7748_BOB_PUBLIC_KEY, sha256_hex, verify_manifest_at,
};
use ea_time::TrustedTimeState;
use ea_trust::{
    ClockReleaseReplayKey, IndependentTimeCommit, PersistedTrustRecord, RegistryHeadPin,
    RegistrySelectionCommit, StateStoreError, TrustObjectSource, TrustSourceError, TrustStateKey,
    TrustStateStore, decode_trust_anchor, load_trust_state, verify_registry_candidate,
    verify_trust,
};
use ea_types::{
    CertificateHash, ChainSequence, DeviceId, Hash32, Id16, KeyThumbprint, ObjectHash,
    OperatorSubjectId, OrganizationId, RecordId, RegistryVersion, UnixMillis,
};
use ea_verify::EvidenceGateErrorV1;
use ed25519_dalek::{Signer, SigningKey};
use minicbor::Decoder;

/// Die Vektorwurzel, relativ zur Arbeitsbaumwurzel.
const VECTOR_ROOT: &str = "vectors/crypto/suite-1";

/// Der Manifestpfad, relativ zur Arbeitsbaumwurzel.
const MANIFEST_PATH: &str = "vectors/crypto/suite-1/manifest.json";

/// Die Zahl der Eintraege. Ein truncatiertes Manifest darf nicht still
/// durchlaufen: ohne diese Schranke waere ein leeres Manifest trivial gruen.
const EXPECTED_ENTRY_COUNT: usize = 66;

/// Die Zahl der VERSCHIEDENEN `EINSATZARCHIV-`-Zeichenketten im Quelltext von
/// `crates/ea-crypto`. Ohne diese Schranke koennte ein Scanner, der nichts
/// findet, die Abdeckungspruefung leer bestehen.
const EA_CRYPTO_DOMAIN_STRING_COUNT: usize = 21;

/// Das feste Urbild der Domain-Digest-Vektoren.
const PROBE: &[u8] = b"suite-1 digest probe";

/// Die Quelldateien, die auf Domain-Trennungszeichenketten abgesucht werden.
const EA_CRYPTO_SOURCE_DIRECTORY: &str = "crates/ea-crypto/src";

type DigestFn = fn(&[u8]) -> Hash32;

/// Die domaingetrennten Digestfunktionen mit ihrer Zeichenkette.
///
/// Eine Tabelle, kein Fliesstext: Erzeuger und Test leiten ihre Eintraege aus
/// derselben Aufzaehlung ab, und eine neue Domain faellt sofort als fehlender
/// Eintrag auf.
const DOMAIN_DIGESTS: [(&str, &str, DigestFn); 11] = [
    (
        "domain-digest/ciphertext-digest",
        "EINSATZARCHIV-CIPHERTEXT-v1",
        ciphertext_digest,
    ),
    (
        "domain-digest/record-digest",
        "EINSATZARCHIV-RECORD-v1",
        record_digest,
    ),
    (
        "domain-digest/grant-plan-digest",
        "EINSATZARCHIV-GRANT-PLAN-v1",
        grant_plan_digest,
    ),
    (
        "domain-digest/grant-digest",
        "EINSATZARCHIV-GRANT-v1",
        grant_digest,
    ),
    (
        "domain-digest/receipt-digest",
        "EINSATZARCHIV-RECEIPT-v1",
        receipt_digest,
    ),
    (
        "domain-digest/trust-digest",
        "EINSATZARCHIV-TRUST-OBJECT-v1",
        trust_digest,
    ),
    (
        "domain-digest/authorized-trust-digest",
        "EINSATZARCHIV-ADMIN-AUTHORIZED-TRUST-v1",
        authorized_trust_digest,
    ),
    (
        "domain-digest/renewal-input-digest",
        "EINSATZARCHIV-EVIDENCE-RENEWAL-INPUT-v1",
        renewal_input_digest,
    ),
    (
        "domain-digest/bootstrap-anchor-hash",
        "EINSATZARCHIV-TRUST-ANCHOR-PRE-v1",
        bootstrap_anchor_hash,
    ),
    (
        "domain-digest/trust-anchor-hash",
        "EINSATZARCHIV-TRUST-ANCHOR-v1",
        trust_anchor_hash,
    ),
    (
        "domain-digest/operator-profile-digest",
        "EINSATZARCHIV-OPERATOR-PROFILE-v1",
        operator_profile_digest,
    ),
];

type ContextFn = fn(&[u8]) -> Vec<u8>;

/// Die Praefixfunktionen, deren Ausgabe die Domain selbst enthaelt.
const DOMAIN_CONTEXTS: [(&str, &str, ContextFn); 3] = [
    (
        "domain-context/payload-aad",
        "EINSATZARCHIV-AAD-v1",
        payload_aad,
    ),
    (
        "domain-context/hpke-info",
        "EINSATZARCHIV-HPKE-INFO-v1",
        hpke_info,
    ),
    (
        "domain-context/hpke-aad",
        "EINSATZARCHIV-HPKE-AAD-v1",
        hpke_aad,
    ),
];

/// Die 20 Domain-Trennungszeichenketten als eigene Eintraege.
const DOMAIN_STRINGS: [&str; 20] = [
    "EINSATZARCHIV-ADMIN-AUTHORIZED-TRUST-v1",
    "EINSATZARCHIV-AAD-v1",
    "EINSATZARCHIV-CHECKPOINT-v1",
    "EINSATZARCHIV-CIPHERTEXT-v1",
    "EINSATZARCHIV-EVIDENCE-RENEWAL-INPUT-v1",
    "EINSATZARCHIV-EVIDENCE-RENEWAL-v1",
    "EINSATZARCHIV-GRANT-PLAN-v1",
    "EINSATZARCHIV-GRANT-v1",
    "EINSATZARCHIV-HPKE-AAD-v1",
    "EINSATZARCHIV-HPKE-INFO-v1",
    "EINSATZARCHIV-OBJECT-v1",
    "EINSATZARCHIV-OPERATOR-PROFILE-v1",
    "EINSATZARCHIV-OS-ACCOUNT-v1",
    "EINSATZARCHIV-PACKAGE-v1",
    "EINSATZARCHIV-RECEIPT-v1",
    "EINSATZARCHIV-RECORD-v1",
    "EINSATZARCHIV-RECOVERY-TEST-v1",
    "EINSATZARCHIV-TRUST-ANCHOR-PRE-v1",
    "EINSATZARCHIV-TRUST-ANCHOR-v1",
    "EINSATZARCHIV-TRUST-OBJECT-v1",
];

/// Der Schluessel des RFC-8439-Vektors: 0x80 bis 0x9f.
fn rfc8439_key() -> [u8; CEK_SIZE] {
    core::array::from_fn(|index| 0x80_u8.wrapping_add(u8::try_from(index).unwrap()))
}

/// Die Nonce des RFC-8439-Vektors: 32-Bit-Konstante plus 64-Bit-IV.
const RFC8439_NONCE: [u8; AEAD_NONCE_SIZE] = [
    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
];

/// Die zusaetzlichen authentifizierten Daten des RFC-8439-Vektors.
const RFC8439_AAD: [u8; 12] = [
    0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
];

/// Die Organisationskennung der strukturierten Vektoren.
const VECTOR_ORGANIZATION_ID: [u8; 16] = [0x10; 16];

/// Die Geraetekennung der strukturierten Vektoren.
const VECTOR_DEVICE_ID: [u8; 16] = [0x11; 16];

fn organization_id() -> OrganizationId {
    OrganizationId::from(Id16::try_from(VECTOR_ORGANIZATION_ID.as_slice()).unwrap())
}

/// Der Eintrag mit diesem Namen; fehlt er, ist das Manifest unvollstaendig.
fn entry<'a>(entries: &'a [VectorEntry], name: &str) -> &'a VectorEntry {
    entries
        .iter()
        .find(|entry| entry.name == name)
        .unwrap_or_else(|| panic!("the manifest misses the entry {name}"))
}

/// Der erwartete Fehlercode eines Ablehnungsvektors.
fn rejection_code(entry: &VectorEntry) -> &str {
    match &entry.expected_outcome {
        ExpectedOutcome::Rejected { error_code } => error_code,
        ExpectedOutcome::Accepted => {
            panic!("entry {} must record a rejection", entry.name)
        }
    }
}

fn expect_accepted(entry: &VectorEntry) {
    assert_eq!(
        entry.expected_outcome,
        ExpectedOutcome::Accepted,
        "entry {} must record acceptance",
        entry.name
    );
}

fn intermediate(entry: &VectorEntry, name: &str) -> String {
    let digest = entry
        .intermediate_digests
        .get(name)
        .unwrap_or_else(|| panic!("entry {} misses the intermediate digest {name}", entry.name));
    hex::encode(digest)
}

/// Ein 32-Byte-Feld aus einem Eintragsfeld.
fn array32(bytes: &[u8], label: &str) -> [u8; 32] {
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("{label} must be 32 bytes, not {}", bytes.len()))
}

#[test]
fn crypto_suite_one_vectors_reproduce_every_primitive_and_domain_string() {
    let root = workspace_root();
    let text = fs::read_to_string(root.join(MANIFEST_PATH))
        .unwrap_or_else(|error| panic!("failed to read {MANIFEST_PATH}: {error}"));
    let manifest = VectorManifest::from_json(&text)
        .unwrap_or_else(|error| panic!("failed to parse {MANIFEST_PATH}: {error}"));
    assert_eq!(manifest.family, "crypto");
    assert_eq!(manifest.version, "suite-1");
    assert_eq!(
        manifest.entries.len(),
        EXPECTED_ENTRY_COUNT,
        "a truncated manifest must not pass"
    );

    // Jede Datei wird neu gehasht; das Manifest darf seiner Platte nicht
    // widersprechen.
    let report = verify_manifest_at(&root.join(VECTOR_ROOT))
        .unwrap_or_else(|error| panic!("failed to verify {VECTOR_ROOT}: {error}"));
    assert_eq!(report.entries_checked, EXPECTED_ENTRY_COUNT);
    assert!(
        report.is_clean(),
        "the frozen files contradict their manifest: {:?}",
        report.mismatches
    );

    let entries = &manifest.entries;
    let mut executed = BTreeSet::new();
    for name in check_suite_identifiers(entries)
        .into_iter()
        .chain(check_domain_strings(entries))
        .chain(check_sha256(entries))
        .chain(check_domain_digests(entries))
        .chain(check_domain_contexts(entries))
        .chain(check_ed25519(entries))
        .chain(check_aead(entries))
        .chain(check_hpke(entries))
        .chain(check_thumbprints(entries))
        .chain(check_protocol_cores(entries))
        .chain(check_uuid_v7(entries))
    {
        assert!(executed.insert(name.clone()), "{name} was executed twice");
    }

    // Beide Richtungen: kein Eintrag bleibt ungerechnet, und keine Pruefung
    // laeuft gegen einen Namen, den das Manifest nicht kennt.
    let recorded = entries
        .iter()
        .map(|entry| entry.name.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        recorded.len(),
        EXPECTED_ENTRY_COUNT,
        "entry names must be unique"
    );
    assert_eq!(
        recorded, executed,
        "every manifest entry must be recomputed, and every recomputation must \
         address a manifest entry"
    );

    check_every_domain_string_is_frozen(entries);
}

/// Die Suite-Identifikatoren und die HPKE-Suite nach RFC 9180.
fn check_suite_identifiers(entries: &[VectorEntry]) -> Vec<String> {
    let suite = entry(entries, "suite/suite-identifier");
    expect_accepted(suite);
    assert_eq!(suite.object_bytes, SUITE_ID.as_bytes());
    assert_eq!(SUITE_ID, "EINSATZARCHIV-SUITE-1");

    let grant = entry(entries, "suite/grant-suite-identifier");
    expect_accepted(grant);
    assert_eq!(grant.object_bytes, GRANT_SUITE_ID.as_bytes());
    assert_eq!(GRANT_SUITE_ID, "EINSATZARCHIV-HPKE-1");

    let hpke = entry(entries, "suite/hpke-suite-identifiers");
    expect_accepted(hpke);
    let mut expected = vec![HPKE_MODE];
    expected.extend_from_slice(&HPKE_KEM_ID.to_be_bytes());
    expected.extend_from_slice(&HPKE_KDF_ID.to_be_bytes());
    expected.extend_from_slice(&HPKE_AEAD_ID.to_be_bytes());
    assert_eq!(
        hpke.object_bytes, expected,
        "the frozen HPKE suite identifiers must match the running constants"
    );

    // RFC 9864 unterscheidet den vollstaendig spezifizierten Ed25519 (-19) vom
    // generischen EdDSA (-8). Ein Signaturvektor kann das nicht belegen — die
    // Signaturmathematik ist in beiden Faellen dieselbe. Belegt wird es an der
    // Kennung, die der Protected Header tatsaechlich schreibt.
    let algorithm = entry(entries, "suite/cose-ed25519-algorithm-identifier");
    expect_accepted(algorithm);
    assert_ne!(
        algorithm.object_bytes,
        vec![0x27],
        "the generic EdDSA identifier -8 is expressly not the frozen algorithm"
    );
    let thumbprint = KeyThumbprint::try_from([0x50_u8; 32].as_slice()).unwrap();
    let certificate = CertificateHash::try_from([0x51_u8; 32].as_slice()).unwrap();
    for (header, map_header) in [
        (
            ProtectedHeader::normal(ContentType::RecordDigest, thumbprint, certificate),
            0xa5_u8,
        ),
        (ProtectedHeader::initial_root(thumbprint), 0xa4),
        (ProtectedHeader::enrollment(thumbprint), 0xa4),
    ] {
        let encoded = header.to_deterministic_cbor();
        assert_eq!(
            encoded[0], map_header,
            "the protected header opens with its fixed map header"
        );
        assert_eq!(encoded[1], 0x01, "label 1 carries the algorithm");
        assert_eq!(
            &encoded[2..2 + algorithm.object_bytes.len()],
            algorithm.object_bytes.as_slice(),
            "every protected header must carry the frozen fully specified algorithm"
        );
    }

    vec![
        suite.name.clone(),
        grant.name.clone(),
        hpke.name.clone(),
        algorithm.name.clone(),
    ]
}

/// Jede Domain-Trennungszeichenkette liegt als eigene Datei.
fn check_domain_strings(entries: &[VectorEntry]) -> Vec<String> {
    let mut names = Vec::new();
    for domain in DOMAIN_STRINGS {
        let name = format!("domain-string/{}", domain.to_lowercase());
        let entry = entry(entries, &name);
        expect_accepted(entry);
        assert_eq!(
            entry.object_bytes,
            domain.as_bytes(),
            "{name} must freeze its literal domain string"
        );
        names.push(entry.name.clone());
    }
    names
}

/// SHA-256 gegen die veroeffentlichten Vektoren.
///
/// `verification_report_hash` ist die einzige Funktion von `ea-crypto` ohne
/// Domain-Praefix und damit der einzige Einstieg, an dem sich reines SHA-256
/// gegen einen Standardvektor stellen laesst.
fn check_sha256(entries: &[VectorEntry]) -> Vec<String> {
    let mut names = Vec::new();
    for name in ["sha-256/empty", "sha-256/abc"] {
        let entry = entry(entries, name);
        expect_accepted(entry);
        let digest = verification_report_hash(&entry.input_bytes);
        assert_eq!(
            digest.as_bytes().as_slice(),
            entry.object_bytes.as_slice(),
            "{name} must reproduce its published digest"
        );
        names.push(entry.name.clone());
    }
    // Die beiden Antworten stehen so in FIPS 180-4 und RFC 6234 §8.5.
    assert_eq!(
        hex::encode(&entry(entries, "sha-256/empty").object_bytes),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        entry(entries, "sha-256/abc").input_bytes,
        b"abc".to_vec(),
        "the published preimage is the three letters abc"
    );
    assert_eq!(
        hex::encode(&entry(entries, "sha-256/abc").object_bytes),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    names
}

/// Die domaingetrennten Digests, zweifach nachgerechnet.
///
/// Einmal ueber `ea-crypto` und einmal unabhaengig als
/// `SHA-256(domain || urbild)`. Stimmen beide, ist die eingefrorene Domain
/// byteweise die, die `ea-crypto` heute verwendet.
fn check_domain_digests(entries: &[VectorEntry]) -> Vec<String> {
    let mut names = Vec::new();
    for (name, domain, digest_fn) in DOMAIN_DIGESTS {
        let entry = entry(entries, name);
        expect_accepted(entry);
        let digest = digest_fn(&entry.input_bytes);
        assert_eq!(
            digest.as_bytes().as_slice(),
            entry.object_bytes.as_slice(),
            "{name} must reproduce its frozen digest"
        );
        let mut preimage = domain.as_bytes().to_vec();
        preimage.extend_from_slice(&entry.input_bytes);
        assert_eq!(
            sha256_hex(&preimage),
            hex::encode(&entry.object_bytes),
            "{name} must hash exactly domain || preimage"
        );
        assert_eq!(
            intermediate(entry, "domainString"),
            sha256_hex(domain.as_bytes()),
            "{name} must record the digest of its domain string"
        );
        names.push(entry.name.clone());
    }

    let object = entry(entries, "domain-digest/object-hash");
    expect_accepted(object);
    assert_eq!(
        object_hash(&object.input_bytes).as_bytes().as_slice(),
        object.object_bytes.as_slice()
    );
    assert_eq!(
        intermediate(object, "domainString"),
        sha256_hex(b"EINSATZARCHIV-OBJECT-v1")
    );
    names.push(object.name.clone());

    let package = entry(entries, "domain-digest/entry-hash");
    expect_accepted(package);
    let (record, writer) = package.input_bytes.split_at(32);
    let record = Hash32::try_from(record).unwrap();
    assert_eq!(
        entry_hash(record, writer).as_bytes().as_slice(),
        package.object_bytes.as_slice()
    );
    assert_eq!(
        intermediate(package, "domainString"),
        sha256_hex(b"EINSATZARCHIV-PACKAGE-v1")
    );
    names.push(package.name.clone());

    let recovery = entry(entries, "domain-digest/recovery-test-digest");
    expect_accepted(recovery);
    let (challenge, thumbprint) = recovery.input_bytes.split_at(32);
    let digest = recovery_test_digest(
        SecretBytes::new(array32(challenge, "the recovery challenge")),
        KeyThumbprint::try_from(thumbprint).unwrap(),
    );
    assert_eq!(
        digest.as_bytes().as_slice(),
        recovery.object_bytes.as_slice()
    );
    assert_eq!(
        intermediate(recovery, "domainString"),
        sha256_hex(b"EINSATZARCHIV-RECOVERY-TEST-v1")
    );
    names.push(recovery.name.clone());

    let account = entry(entries, "domain-digest/os-account-linux");
    expect_accepted(account);
    assert_eq!(account.input_bytes.len(), 16 + 16 + 33 + 4);
    assert_eq!(account.input_bytes[..16], VECTOR_ORGANIZATION_ID);
    assert_eq!(account.input_bytes[16..32], VECTOR_DEVICE_ID);
    let machine_id_file = &account.input_bytes[32..65];
    let uid = u32::from_be_bytes(array4(&account.input_bytes[65..]));
    let binding = linux_os_account_binding_hash(
        OrganizationId::from(Id16::try_from(&account.input_bytes[..16]).unwrap()),
        DeviceId::from(Id16::try_from(&account.input_bytes[16..32]).unwrap()),
        machine_id_file,
        uid,
    )
    .expect("the frozen Linux account inputs must bind");
    assert_eq!(
        binding.as_bytes().as_slice(),
        account.object_bytes.as_slice()
    );
    assert_eq!(
        intermediate(account, "domainString"),
        sha256_hex(b"EINSATZARCHIV-OS-ACCOUNT-v1")
    );
    names.push(account.name.clone());

    names
}

fn array4(bytes: &[u8]) -> [u8; 4] {
    bytes.try_into().expect("the uid field must be four bytes")
}

/// Die Praefixfunktionen liefern die Domain unveraendert mit aus.
fn check_domain_contexts(entries: &[VectorEntry]) -> Vec<String> {
    let mut names = Vec::new();
    for (name, domain, context_fn) in DOMAIN_CONTEXTS {
        let entry = entry(entries, name);
        expect_accepted(entry);
        assert_eq!(
            context_fn(&entry.input_bytes),
            entry.object_bytes,
            "{name} must reproduce its frozen context"
        );
        assert!(
            entry.object_bytes.starts_with(domain.as_bytes()),
            "{name} must carry its domain string verbatim"
        );
        names.push(entry.name.clone());
    }
    names
}

/// Ed25519 nach RFC 8032 §7.1, geprueft in beiden Richtungen.
///
/// Die Signaturen sind nicht abgeschrieben: Ed25519 signiert deterministisch,
/// und der Seed stammt aus dem Standard. `ea-testkit` misst im eigenen Test,
/// dass der Seed seinen veroeffentlichten oeffentlichen Schluessel ableitet.
fn check_ed25519(entries: &[VectorEntry]) -> Vec<String> {
    let mut names = Vec::new();
    for (name, seed) in [
        ("ed25519/rfc8032-test1", ED25519_RFC8032_TEST1_SEED),
        ("ed25519/rfc8032-test2", ED25519_RFC8032_TEST2_SEED),
    ] {
        let entry = entry(entries, name);
        expect_accepted(entry);
        let signing = SigningKey::from_bytes(&seed);
        let public = signing.verifying_key().to_bytes();
        assert_eq!(
            signing.sign(&entry.input_bytes).to_bytes().as_slice(),
            entry.object_bytes.as_slice(),
            "{name} must reproduce the RFC 8032 signature"
        );
        let key = CanonicalPublicCoseKey::ed25519(public).unwrap();
        key.verify_ed25519_strict(&entry.input_bytes, &array64(&entry.object_bytes))
            .unwrap_or_else(|error| panic!("{name} must verify strictly: {error}"));
        assert_eq!(
            intermediate(entry, "signerThumbprint"),
            hex::encode(key.thumbprint().as_bytes())
        );
        names.push(entry.name.clone());
    }

    let flipped = entry(entries, "ed25519/flipped-signature");
    let key = CanonicalPublicCoseKey::ed25519(
        SigningKey::from_bytes(&ED25519_RFC8032_TEST1_SEED)
            .verifying_key()
            .to_bytes(),
    )
    .unwrap();
    let error = key
        .verify_ed25519_strict(&flipped.input_bytes, &array64(&flipped.object_bytes))
        .expect_err("a flipped signature must not verify");
    assert_eq!(error.code(), rejection_code(flipped));
    assert_eq!(
        intermediate(flipped, "signerThumbprint"),
        hex::encode(key.thumbprint().as_bytes())
    );
    names.push(flipped.name.clone());

    let weak = entry(entries, "ed25519/weak-public-key");
    let error = CanonicalPublicCoseKey::ed25519(array32(&weak.object_bytes, "the weak public key"))
        .err()
        .expect("a low-order public key must be refused");
    assert_eq!(error.code(), rejection_code(weak));
    names.push(weak.name.clone());

    names
}

fn array64(bytes: &[u8]) -> [u8; 64] {
    bytes
        .try_into()
        .expect("an Ed25519 signature is exactly 64 bytes")
}

/// ChaCha20-Poly1305, einmal gegen RFC 8439 und einmal gegen die deklarierte
/// Testentropie.
fn check_aead(entries: &[VectorEntry]) -> Vec<String> {
    let rfc = entry(entries, "aead/rfc8439-2.8.2");
    expect_accepted(rfc);
    let key = rfc8439_key();
    assert_eq!(intermediate(rfc, "keyDigest"), sha256_hex(&key));
    assert_eq!(intermediate(rfc, "nonceDigest"), sha256_hex(&RFC8439_NONCE));
    assert_eq!(intermediate(rfc, "aadDigest"), sha256_hex(&RFC8439_AAD));
    let sealed = aead_seal(
        &SecretBytes::new(key),
        &SecretBytes::new(RFC8439_NONCE),
        SecretVec::new(rfc.input_bytes.clone()),
        &RFC8439_AAD,
    )
    .expect("the RFC 8439 vector must seal");
    assert_eq!(
        sealed, rfc.object_bytes,
        "the RFC 8439 ciphertext and tag must reproduce byte for byte"
    );

    let declared = entry(entries, "aead/declared-entropy");
    expect_accepted(declared);
    let cek = SecretBytes::new(TEST_ENTROPY_CONTENT_ENCRYPTION_KEY);
    let nonce = SecretBytes::new(TEST_ENTROPY_AEAD_NONCE);
    let aad = payload_aad(PROBE);
    assert_eq!(
        intermediate(declared, "keyDigest"),
        sha256_hex(&TEST_ENTROPY_CONTENT_ENCRYPTION_KEY)
    );
    assert_eq!(
        intermediate(declared, "nonceDigest"),
        sha256_hex(&TEST_ENTROPY_AEAD_NONCE)
    );
    assert_eq!(intermediate(declared, "aadDigest"), sha256_hex(&aad));
    let sealed = aead_seal(
        &cek,
        &nonce,
        SecretVec::new(declared.input_bytes.clone()),
        &aad,
    )
    .expect("the declared entropy vector must seal");
    assert_eq!(sealed, declared.object_bytes);
    let opened = aead_open(&cek, &nonce, &declared.object_bytes, &aad)
        .unwrap_or_else(|error| panic!("the frozen ciphertext must open: {error}"));
    assert!(
        opened.matches(&declared.input_bytes),
        "opening the frozen ciphertext must return the frozen plaintext"
    );

    let tampered = entry(entries, "aead/tampered-tag");
    let error = aead_open(&cek, &nonce, &tampered.object_bytes, &aad)
        .err()
        .expect("a tampered tag must not open");
    assert_eq!(error.code(), rejection_code(tampered));

    vec![
        rfc.name.clone(),
        declared.name.clone(),
        tampered.name.clone(),
    ]
}

/// HPKE Base Mode: Schluesselableitung gegen RFC 7748, Entkapselung gegen die
/// eingefrorenen Bytes.
fn check_hpke(entries: &[VectorEntry]) -> Vec<String> {
    let published = entry(entries, "hpke/rfc7748-recipient-public-key");
    expect_accepted(published);
    assert_eq!(
        published.input_bytes,
        X25519_RFC7748_BOB_PRIVATE_KEY.to_vec()
    );
    let recipient = HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(array32(
        &published.input_bytes,
        "the RFC 7748 private key",
    )))
    .expect("the RFC 7748 private key must load");
    assert_eq!(
        recipient.public_key().as_bytes().as_slice(),
        published.object_bytes.as_slice(),
        "the KEM must derive the published RFC 7748 public key"
    );
    assert_eq!(
        published.object_bytes,
        X25519_RFC7748_BOB_PUBLIC_KEY.to_vec()
    );

    let sealed = entry(entries, "hpke/base-mode-wrapped-cek");
    expect_accepted(sealed);
    assert_eq!(
        sealed.source,
        VectorSource::FrozenOnce {
            verified_via: "hpke_open".to_owned(),
        },
        "the sealing direction draws fresh entropy and is checked in reverse"
    );
    let recipient =
        HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(TEST_ENTROPY_RECIPIENT_X25519_SEED))
            .expect("the declared recipient key must load");
    let info = hpke_info(PROBE);
    let aad = hpke_aad(PROBE);
    assert_eq!(intermediate(sealed, "infoDigest"), sha256_hex(&info));
    assert_eq!(intermediate(sealed, "aadDigest"), sha256_hex(&aad));
    assert_eq!(
        intermediate(sealed, "recipientPublicKeyThumbprint"),
        hex::encode(
            CanonicalPublicCoseKey::x25519(*recipient.public_key().as_bytes())
                .unwrap()
                .thumbprint()
                .as_bytes()
        )
    );
    let opened = hpke_open(&recipient, &hpke_sealed(&sealed.object_bytes), &info, &aad)
        .expect("the frozen encapsulation must open");
    assert!(
        opened.matches(&array32(&sealed.input_bytes, "the wrapped content key")),
        "hpke_open must return the frozen content encryption key"
    );

    let mut names = vec![published.name.clone(), sealed.name.clone()];
    for name in ["hpke/flipped-encapsulated-key", "hpke/flipped-wrapped-cek"] {
        let broken = entry(entries, name);
        let error = hpke_open(&recipient, &hpke_sealed(&broken.object_bytes), &info, &aad)
            .err()
            .unwrap_or_else(|| panic!("{name} must not open"));
        assert_eq!(error.code(), rejection_code(broken));
        assert_eq!(
            broken.object_bytes.len(),
            sealed.object_bytes.len(),
            "{name} must differ from the valid vector in exactly one byte's value"
        );
        let differing = broken
            .object_bytes
            .iter()
            .zip(&sealed.object_bytes)
            .filter(|(left, right)| left != right)
            .count();
        assert_eq!(differing, 1, "{name} must flip exactly one byte");
        names.push(broken.name.clone());
    }
    names
}

/// Zerlegt die eingefrorenen 80 Byte in Kapselungswert und umschlossenen CEK.
fn hpke_sealed(bytes: &[u8]) -> HpkeSealed {
    assert_eq!(
        bytes.len(),
        HPKE_ENCAPSULATED_KEY_SIZE + HPKE_WRAPPED_CEK_SIZE
    );
    let (encapsulated, wrapped) = bytes.split_at(HPKE_ENCAPSULATED_KEY_SIZE);
    HpkeSealed::from_parts(
        encapsulated
            .try_into()
            .expect("the encapsulated key is 32 bytes"),
        wrapped.try_into().expect("the wrapped key is 48 bytes"),
    )
    .expect("the frozen encapsulation must parse")
}

/// RFC 9679 Key-Thumbprints ueber die kanonische COSE-Key-Kodierung.
fn check_thumbprints(entries: &[VectorEntry]) -> Vec<String> {
    let mut names = Vec::new();
    for (key_name, thumbprint_name, public) in [
        (
            "thumbprint/ed25519-canonical-cose-key",
            "thumbprint/ed25519",
            SigningKey::from_bytes(&ED25519_RFC8032_TEST1_SEED)
                .verifying_key()
                .to_bytes(),
        ),
        (
            "thumbprint/x25519-canonical-cose-key",
            "thumbprint/x25519",
            X25519_RFC7748_BOB_PUBLIC_KEY,
        ),
    ] {
        let is_ed25519 = key_name.contains("ed25519");
        let key = if is_ed25519 {
            CanonicalPublicCoseKey::ed25519(public)
        } else {
            CanonicalPublicCoseKey::x25519(public)
        }
        .expect("the published public key must load");

        let encoded = entry(entries, key_name);
        expect_accepted(encoded);
        assert_eq!(encoded.input_bytes, public.to_vec());
        assert_eq!(
            key.to_deterministic_cbor(),
            encoded.object_bytes,
            "{key_name} must reproduce the canonical COSE key encoding"
        );
        assert_eq!(
            CanonicalPublicCoseKey::from_deterministic_cbor(&encoded.object_bytes)
                .expect("the canonical encoding must decode")
                .thumbprint()
                .as_bytes()
                .as_slice(),
            entry(entries, thumbprint_name).object_bytes.as_slice()
        );
        names.push(encoded.name.clone());

        let thumbprint = entry(entries, thumbprint_name);
        expect_accepted(thumbprint);
        assert_eq!(thumbprint.input_bytes, encoded.object_bytes);
        assert_eq!(
            key.thumbprint().as_bytes().as_slice(),
            thumbprint.object_bytes.as_slice(),
            "{thumbprint_name} must reproduce the RFC 9679 thumbprint"
        );
        assert_eq!(
            sha256_hex(&encoded.object_bytes),
            hex::encode(&thumbprint.object_bytes),
            "an RFC 9679 thumbprint is SHA-256 over the canonical key bytes"
        );
        names.push(thumbprint.name.clone());
    }

    let unknown = entry(entries, "thumbprint/unknown-curve");
    let error = CanonicalPublicCoseKey::from_deterministic_cbor(&unknown.object_bytes)
        .err()
        .expect("an unknown curve must be refused");
    assert_eq!(error.code(), rejection_code(unknown));
    names.push(unknown.name.clone());

    names
}

/// Die beiden Protokollkern-Zeichenketten, positiv und negativ.
fn check_protocol_cores(entries: &[VectorEntry]) -> Vec<String> {
    let mut names = Vec::new();
    for (name, content_type, domain) in [
        (
            "protocol-core/checkpoint",
            ContentType::CheckpointCbor,
            "EINSATZARCHIV-CHECKPOINT-v1",
        ),
        (
            "protocol-core/evidence-renewal",
            ContentType::EvidenceRenewalCbor,
            "EINSATZARCHIV-EVIDENCE-RENEWAL-v1",
        ),
    ] {
        let valid = entry(entries, name);
        expect_accepted(valid);
        validate_unsigned_protocol_core(content_type, &valid.object_bytes)
            .unwrap_or_else(|error| panic!("{name} must validate: {error}"));
        assert!(
            valid
                .object_bytes
                .windows(domain.len())
                .any(|window| window == domain.as_bytes()),
            "{name} must carry its type string verbatim"
        );
        names.push(valid.name.clone());

        let mutated_name = format!("{name}-mutated-type-string");
        let mutated = entry(entries, &mutated_name);
        let error = validate_unsigned_protocol_core(content_type, &mutated.object_bytes)
            .err()
            .unwrap_or_else(|| panic!("{mutated_name} must be refused"));
        assert_eq!(error.code(), rejection_code(mutated));
        assert!(
            !mutated
                .object_bytes
                .windows(domain.len())
                .any(|window| window == domain.as_bytes()),
            "{mutated_name} must not carry the valid type string"
        );
        assert_eq!(
            mutated.object_bytes.len(),
            valid.object_bytes.len(),
            "{mutated_name} must differ from the valid core only in the type string"
        );
        names.push(mutated.name.clone());
    }
    names
}

/// RFC 9562 UUIDv7 ueber den einzigen Bestandspfad, der die Version prueft.
fn check_uuid_v7(entries: &[VectorEntry]) -> Vec<String> {
    let valid = entry(entries, "uuid-v7/valid");
    expect_accepted(valid);
    common_header(&valid.object_bytes).expect("a UUIDv7 record identifier must be accepted");
    assert_eq!(valid.object_bytes[6] >> 4, 7, "the version nibble is seven");
    assert_eq!(
        valid.object_bytes[8] & 0xc0,
        0x80,
        "the variant bits are RFC 9562"
    );

    let refused = entry(entries, "uuid-v7/version-four");
    let error = common_header(&refused.object_bytes)
        .err()
        .expect("a version four identifier must be refused");
    assert_eq!(error.code(), rejection_code(refused));
    assert_eq!(refused.object_bytes[6] >> 4, 4);

    vec![valid.name.clone(), refused.name.clone()]
}

fn common_header(record_id: &[u8]) -> Result<CommonHeaderV1, ea_schema::SchemaError> {
    CommonHeaderV1::new(
        RecordId::from(Id16::try_from(record_id).expect("a record identifier is 16 bytes")),
        UnixMillis::new(1_700_000_000_000),
        "Europe/Berlin",
        OperatorSnapshotV1::new(
            organization_id(),
            OperatorSubjectId::from(Id16::try_from([0x12_u8; 16].as_slice()).unwrap()),
            "Vektor",
            "Vektor",
            [0x13; 32],
            ObjectHash::from(Hash32::try_from([0x14_u8; 32].as_slice()).unwrap()),
        )?,
        NativeSourceV1::new("vector", 1)?,
        RegistryVersion::new(1),
    )
}

/// Keine Domain-Trennungszeichenkette von `ea-crypto` bleibt ungefroren.
///
/// Die Liste wird aus dem QUELLTEXT abgeleitet, nicht aus dieser Datei: eine
/// neue Domain in `ea-crypto` laesst diesen Test fallen, bis sie einen Vektor
/// hat. Die Zahl ist mitgemessen, damit ein Scanner, der nichts findet, nicht
/// leer besteht.
fn check_every_domain_string_is_frozen(entries: &[VectorEntry]) {
    let directory = workspace_root().join(EA_CRYPTO_SOURCE_DIRECTORY);
    let mut found = BTreeSet::new();
    for source in fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("failed to list {}: {error}", directory.display()))
    {
        let path = source.expect("a readable directory entry").path();
        // Der Scanner liest genau eine Ebene. Ein Unterverzeichnis waere fuer
        // ihn unsichtbar, die Zahl bliebe stimmig, und die Abdeckungszusage
        // waere still falsch — deshalb faellt der Test, statt zu uebersehen.
        assert!(
            !path.is_dir(),
            "{} holds a subdirectory; the domain string scanner reads one level only",
            path.display()
        );
        if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
            continue;
        }
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        for literal in scan_domain_strings(&text) {
            found.insert(literal);
        }
    }
    assert_eq!(
        found.len(),
        EA_CRYPTO_DOMAIN_STRING_COUNT,
        "the scanner must find every domain string of ea-crypto: {found:?}"
    );

    let frozen = entries
        .iter()
        .map(|entry| entry.object_bytes.clone())
        .collect::<BTreeSet<_>>();
    for literal in found
        .iter()
        .cloned()
        .chain([ea_types::SUITE_ID_V1.to_owned()])
    {
        assert!(
            frozen.contains(literal.as_bytes()),
            "{literal} is used by ea-crypto but no vector freezes it"
        );
    }
}

/// Alle `EINSATZARCHIV-`-Zeichenketten eines Quelltexts.
fn scan_domain_strings(text: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("EINSATZARCHIV-") {
        let tail = &rest[at..];
        let end = tail
            .find(|character: char| !character.is_ascii_alphanumeric() && character != '-')
            .unwrap_or(tail.len());
        literals.push(tail[..end].to_owned());
        rest = &tail[end..];
    }
    literals
}

// ---------------------------------------------------------------------------
// Die Vektorfamilie `format/v1`
// ---------------------------------------------------------------------------
//
// Zwei Wurzeln, zwei Manifeste: `valid/` traegt je ein gueltiges Objekt der
// sechs Objektfamilien, `invalid/` die Ablehnungsvektoren nach `design.md`
// §22.1. Auch hier wird NICHTS gegen sich selbst verglichen — jeder Vektor
// laeuft durch `ea_format::decode_exact_object`, und der zurueckkommende
// Fehlercode wird gegen den eingefrorenen gestellt.

/// Der Manifestpfad der gueltigen Objekte, relativ zur Arbeitsbaumwurzel.
const FORMAT_VALID_MANIFEST_PATH: &str = "vectors/format/v1/valid/manifest.json";

/// Der Manifestpfad der Ablehnungsvektoren.
const FORMAT_INVALID_MANIFEST_PATH: &str = "vectors/format/v1/invalid/manifest.json";

/// Die Wurzel der gueltigen Objekte.
const FORMAT_VALID_ROOT: &str = "vectors/format/v1/valid";

/// Die Wurzel der Ablehnungsvektoren.
const FORMAT_INVALID_ROOT: &str = "vectors/format/v1/invalid";

/// Die sechs Objektfamilien: Name, Schema-Identifikator, Objekttyp-Tag.
///
/// Die Tags sind LITERALE. Sie aus `ea-format` zu importieren machte den Vektor
/// zur Tautologie: eine Umnummerierung zoege ihn stillschweigend mit.
const FORMAT_FAMILIES: [(&str, &str, u8); 6] = [
    ("eip", "eip-v1", 1),
    ("eag", "eag-v1", 2),
    ("esr", "esr-v1", 3),
    ("ecp", "ecp-v1", 4),
    ("etb", "etb-v1", 5),
    ("eds", "eds-v1", 6),
];

/// Die Mutationen, die JEDE Familie tragen muss.
const FORMAT_PER_FAMILY_MUTATIONS: [&str; 5] = [
    "magic-byte-flip",
    "object-type-tag",
    "object-version",
    "critical-extension",
    "cose-payload-byte-flip",
];

/// Die familienspezifischen Mutationen an Manifest und Ciphertext.
const FORMAT_TARGETED_MUTATIONS: [&str; 3] = [
    "eds/signed-manifest-byte-flip",
    "eip/ciphertext-byte-flip",
    "eip/signed-manifest-byte-flip",
];

/// Die CBOR-Ebene: doppelte Keys, nicht-kanonische Laenge, Verschachtelung und
/// die beiden Elementzahlgrenzen.
const FORMAT_CBOR_MUTATIONS: [&str; 5] = [
    "cbor/container-items-over-limit",
    "cbor/duplicate-map-key",
    "cbor/nesting-depth-17",
    "cbor/non-canonical-length",
    "cbor/total-items-over-limit",
];

/// Die drei Wertgrenzen, je um genau ein Byte ueberschritten.
const FORMAT_LIMIT_MUTATIONS: [&str; 3] = [
    "limits/cbor-text-or-bytes-plus-one",
    "limits/ciphertext-length-plus-one",
    "limits/plaintext-plus-one",
];

/// Der Schema-Identifikator, dessen Vektor NICHT von `ea-format` geprueft wird.
///
/// `MAX_PLAINTEXT_BYTES_V1` ist keine Formatgrenze: `ea-format` oeffnet den
/// AEAD-Ciphertext nie. Die Grenze steht in `crates/ea-schema/src/v1.rs` und
/// wird von `SchemaRegistry::validate` durchgesetzt. Der Vektor nennt deshalb
/// seinen eigenen Pruefer.
const FORMAT_SCHEMA_CHECKED_SCHEMA_ID: &str = "ea.incident";

#[test]
fn format_v1_valid_objects_and_single_byte_mutations_match_their_manifests() {
    let root = workspace_root();
    let valid_text = fs::read_to_string(root.join(FORMAT_VALID_MANIFEST_PATH))
        .unwrap_or_else(|error| panic!("failed to read {FORMAT_VALID_MANIFEST_PATH}: {error}"));
    let valid = VectorManifest::from_json(&valid_text)
        .unwrap_or_else(|error| panic!("failed to parse {FORMAT_VALID_MANIFEST_PATH}: {error}"));
    let invalid_text = fs::read_to_string(root.join(FORMAT_INVALID_MANIFEST_PATH))
        .unwrap_or_else(|error| panic!("failed to read {FORMAT_INVALID_MANIFEST_PATH}: {error}"));
    let invalid = VectorManifest::from_json(&invalid_text)
        .unwrap_or_else(|error| panic!("failed to parse {FORMAT_INVALID_MANIFEST_PATH}: {error}"));

    assert_eq!(valid.family, "format");
    assert_eq!(valid.version, "v1/valid");
    assert_eq!(invalid.family, "format");
    assert_eq!(invalid.version, "v1/invalid");

    for (path, manifest_root, manifest) in [
        (FORMAT_VALID_ROOT, FORMAT_VALID_ROOT, &valid),
        (FORMAT_INVALID_ROOT, FORMAT_INVALID_ROOT, &invalid),
    ] {
        let report = verify_manifest_at(&root.join(manifest_root))
            .unwrap_or_else(|error| panic!("failed to verify {path}: {error}"));
        assert_eq!(report.entries_checked, manifest.entries.len());
        assert!(
            report.is_clean(),
            "the frozen files of {path} contradict their manifest: {:?}",
            report.mismatches
        );
    }

    check_format_valid_objects(&valid.entries);
    check_format_invalid_objects(&invalid.entries);
}

/// Jedes gueltige Objekt parst, traegt sein Tag und seinen eingefrorenen
/// Objekthash.
fn check_format_valid_objects(entries: &[VectorEntry]) {
    let recorded = entries
        .iter()
        .map(|entry| entry.name.clone())
        .collect::<BTreeSet<_>>();
    let expected = FORMAT_FAMILIES
        .iter()
        .map(|(family, _, _)| format!("{family}/valid"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        recorded, expected,
        "the valid manifest must hold exactly one object per family"
    );
    assert_eq!(entries.len(), expected.len(), "entry names must be unique");

    for (family, schema_id, tag) in FORMAT_FAMILIES {
        let vector = entry(entries, &format!("{family}/valid"));
        expect_accepted(vector);
        assert_eq!(vector.schema_id, schema_id);
        assert_eq!(vector.suite_id, "EINSATZARCHIV-SUITE-1");
        assert_eq!(
            vector.object_bytes.get(..9).map(<[u8]>::to_vec),
            Some(vec![0x85, 0x44, b'E', b'A', b'1', 0, tag, 1, 0x80]),
            "{family} must carry the frozen nine-byte prefix"
        );

        let parsed = decode_exact_object(&vector.object_bytes)
            .unwrap_or_else(|error| panic!("{} must parse, not {error}", vector.name));
        let (exact, object_hash) = format_parsed_parts(&parsed);
        assert_eq!(
            exact, vector.object_bytes,
            "{} must round-trip byte for byte",
            vector.name
        );
        assert_eq!(
            intermediate(vector, "objectHash"),
            hex::encode(object_hash.as_bytes()),
            "{} must record its own object hash",
            vector.name
        );
    }
}

/// Jeder Ablehnungsvektor liefert exakt den eingefrorenen Fehlercode.
fn check_format_invalid_objects(entries: &[VectorEntry]) {
    let recorded = entries
        .iter()
        .map(|entry| entry.name.clone())
        .collect::<BTreeSet<_>>();
    let mut expected = BTreeSet::new();
    for (family, _, _) in FORMAT_FAMILIES {
        for mutation in FORMAT_PER_FAMILY_MUTATIONS {
            expected.insert(format!("{family}/{mutation}"));
        }
    }
    for name in FORMAT_TARGETED_MUTATIONS
        .into_iter()
        .chain(FORMAT_CBOR_MUTATIONS)
        .chain(FORMAT_LIMIT_MUTATIONS)
    {
        expected.insert(name.to_owned());
    }
    assert_eq!(
        recorded, expected,
        "the invalid manifest must cover exactly the mandated negative scope"
    );
    assert_eq!(entries.len(), expected.len(), "entry names must be unique");

    for vector in entries {
        let expected_code = rejection_code(vector);
        let actual = format_rejection_of(vector);
        assert_eq!(
            actual, expected_code,
            "{} must be rejected with the frozen code",
            vector.name
        );
        check_format_mutation_origin(vector);
    }
}

/// Ein Mutationsvektor nennt sein Urbild, und das Urbild ist selbst gueltig.
///
/// Ohne diese Pruefung koennte ein Vektor behaupten, aus einem gueltigen Objekt
/// zu stammen, waehrend er in Wahrheit irgendwelche Bytes traegt — und die
/// Zusage `Ein-Byte-Manipulation` waere unbelegt.
fn check_format_mutation_origin(vector: &VectorEntry) {
    let derived = FORMAT_FAMILIES
        .iter()
        .any(|(family, _, _)| vector.name.starts_with(&format!("{family}/")))
        || vector.name == "limits/ciphertext-length-plus-one";
    if !derived {
        assert!(
            vector.input_bytes.is_empty() && vector.intermediate_digests.is_empty(),
            "{} is synthetic and must not claim an origin",
            vector.name
        );
        return;
    }

    assert!(
        !vector.input_bytes.is_empty(),
        "{} must record the valid object it was derived from",
        vector.name
    );
    decode_exact_object(&vector.input_bytes)
        .unwrap_or_else(|error| panic!("the origin of {} must parse, not {error}", vector.name));
    assert_eq!(
        intermediate(vector, "sourceObjectHash"),
        hex::encode(ea_crypto::object_hash(&vector.input_bytes).as_bytes()),
        "{} must record the object hash of its own origin",
        vector.name
    );

    let distance = format_byte_distance(&vector.input_bytes, &vector.object_bytes);
    let expected = if vector.name.ends_with("/critical-extension") {
        // Ein unbekanntes kritisches Feld ist keine Kippung, sondern ein
        // EINGESCHOBENES Element: der leere Erweiterungsschlitz wird einelementig.
        FormatDistance::Inserted(1)
    } else if vector.name == "limits/ciphertext-length-plus-one" {
        // Die angekuendigte Laenge waechst von einem zweibyteigen auf ein
        // fuenfbyteiges kanonisches CBOR-Argument.
        FormatDistance::Inserted(3)
    } else {
        FormatDistance::Flipped(1)
    };
    assert_eq!(
        distance, expected,
        "{} must differ from its origin exactly as its name says",
        vector.name
    );
}

/// Der Abstand zweier Vektoren: gekippte Bytes bei gleicher Laenge, sonst der
/// Laengenzuwachs.
#[derive(Debug, Eq, PartialEq)]
enum FormatDistance {
    Flipped(usize),
    Inserted(usize),
}

fn format_byte_distance(origin: &[u8], mutated: &[u8]) -> FormatDistance {
    if origin.len() == mutated.len() {
        return FormatDistance::Flipped(
            origin
                .iter()
                .zip(mutated)
                .filter(|(left, right)| left != right)
                .count(),
        );
    }
    FormatDistance::Inserted(mutated.len() - origin.len())
}

/// Fuehrt den fuer diesen Vektor zustaendigen Pruefer aus.
fn format_rejection_of(vector: &VectorEntry) -> String {
    if vector.schema_id == FORMAT_SCHEMA_CHECKED_SCHEMA_ID {
        // Die Laenge ist die Aussage dieses Vektors, und sie steht nirgends
        // sonst: `spec_completeness.rs` pinnt die beiden anderen Wertgrenzen,
        // diese nicht. Ohne die Zeile belegte der Vektor nur, dass IRGENDEINE
        // zu lange Eingabe abgelehnt wird.
        assert_eq!(
            vector.object_bytes.len(),
            ea_schema::PAYLOAD_PLAINTEXT_MAX_BYTES_V1 + 1,
            "{} must exceed the plaintext limit by exactly one byte",
            vector.name
        );
        return SchemaRegistry::v1()
            .validate(FORMAT_SCHEMA_CHECKED_SCHEMA_ID, 1, &vector.object_bytes)
            .map_or_else(|error| error.code().to_owned(), |_| "accepted".to_owned());
    }
    decode_exact_object(&vector.object_bytes)
        .map_or_else(|error| error.code().to_owned(), |_| "accepted".to_owned())
}

/// Exakte Bytes und Objekthash eines geparsten Objekts, familienunabhaengig.
fn format_parsed_parts(parsed: &ParsedArchiveObject) -> (Vec<u8>, ObjectHash) {
    match parsed {
        ParsedArchiveObject::Entry(value) => {
            (value.exact_bytes().as_bytes().to_vec(), value.object_hash())
        }
        ParsedArchiveObject::Grant(value) => {
            (value.exact_bytes().as_bytes().to_vec(), value.object_hash())
        }
        ParsedArchiveObject::Receipt(value) => {
            (value.exact_bytes().as_bytes().to_vec(), value.object_hash())
        }
        ParsedArchiveObject::Evidence(value) => {
            (value.exact_bytes().as_bytes().to_vec(), value.object_hash())
        }
        ParsedArchiveObject::Trust(value) => {
            (value.exact_bytes().as_bytes().to_vec(), value.object_hash())
        }
        ParsedArchiveObject::Destroyed(value) => {
            (value.exact_bytes().as_bytes().to_vec(), value.object_hash())
        }
    }
}

// ---------------------------------------------------------------------------
// Die Vektorfamilie `trust/v1`
// ---------------------------------------------------------------------------
//
// Der Negativumfang ist woertlich durch `design.md` §22.1, letzter Punkt,
// vorgegeben. Jeder dort genannte Fall hat genau einen Vektor, und KEIN Fall
// wird gegen sich selbst geprueft: der Test fuehrt die echte Pipeline aus —
// `ea_format::decode_exact_object`, `ea_trust::decode_trust_anchor`,
// `ea_trust::verify_trust`, `ea_trust::verify_registry_candidate` — und stellt
// den zurueckkommenden Fehlercode gegen den eingefrorenen.
//
// # Wie ein Fall aufgebaut ist
//
// Ein Fall ist ein Verzeichnis `<stufe>/<fall>/` mit einem Eintrag je Objekt.
// Die Stufe im Namen sagt, WELCHE Pipeline ueber den Fall entscheidet, und sie
// ist damit maschinell ableitbar statt Testwissen:
//
// * `object/`    — `decode_exact_object` auf genau einem Objekt,
// * `anchor/`    — `decode_trust_anchor` auf den Anchor-Bytes,
// * `bootstrap/` — zusaetzlich `verify_trust` gegen den Objektkatalog,
// * `registry/`  — zusaetzlich `verify_registry_candidate`.
//
// Jeder Fall ist VOLLSTAENDIG: er traegt alle Objekte, die seine Stufe braucht.
// Eine Vererbung zwischen Faellen gaebe es hier zwar kompakter, doch eine
// fremde Implementierung muesste sie nachbauen, bevor sie einen einzigen Vektor
// pruefen koennte. Die Wiederholung ist der Preis dafuer, dass jeder Fall fuer
// sich lesbar bleibt.
//
// Das URTEIL eines Falls steht am Eintrag, der die Pipeline betritt: bei
// `object/` am Objekt selbst, sonst am Eintrag `anchor`. Alle uebrigen
// Eintraege eines Falls tragen ihr EIGENES Parseergebnis — ein wohlgeformtes
// Wurzelzertifikat bleibt wohlgeformt, auch wenn der Fall als Ganzes scheitert.

/// Der Manifestpfad der Trust-Vektoren, relativ zur Arbeitsbaumwurzel.
const TRUST_MANIFEST_PATH: &str = "vectors/trust/v1/manifest.json";

/// Die Wurzel der Trust-Vektoren.
const TRUST_VECTOR_ROOT: &str = "vectors/trust/v1";

/// Der Schema-Identifikator eines Vertrauensbausteins.
const TRUST_OBJECT_SCHEMA_ID: &str = "etb-v1";

/// Der Schema-Identifikator der finalen Anchor-Bytes.
const TRUST_ANCHOR_SCHEMA_ID: &str = "trust-anchor-v1";

/// Der Schema-Identifikator der bestaetigten Anchor-Vorstufe.
const TRUST_PRE_ANCHOR_SCHEMA_ID: &str = "trust-anchor-pre-v1";

/// Der Subtype, dessen Eintraege die Reichweitennotiz zu §7.5 tragen muessen.
const TRUST_ADMIN_AUTHORIZATION_SUBTYPE: &str = "organizationAdminAuthorization";

/// Der einzige zulaessige Wert eines Action-Code-Negativvektors.
///
/// LITERAL, und der Nachbarwert `7` ist verboten: `trust.cddl` deklariert
/// `action-code: 0..6`, und eine v1.1-Erweiterung des Wertebereichs wuerde einen
/// eingefrorenen `7`-Vektor von `abgelehnt` nach `akzeptiert` drehen.
const TRUST_INVALID_ACTION_CODE: u64 = 200;

/// Das einzige zulaessige Literal eines Subtype-Negativvektors.
const TRUST_UNKNOWN_SUBTYPE: &str = "xxUnknownxx";

/// Namen, die spaeter echte Trust-Objektfamilien werden koennten und deshalb in
/// keinem eingefrorenen Negativvektor stehen duerfen.
const TRUST_RESERVED_SUBTYPE_NAMES: [&str; 2] = ["webBundleRelease", "readerKeyEscrow"];

/// Der Registry-Fall, gegen den sich jeder andere Registry-Fall abgrenzt.
const TRUST_REGISTRY_BASELINE: &str = "registry/accepted-bootstrap-and-first-head";

/// Ein Fall der Familie.
struct TrustCase {
    /// Verzeichnis des Falls, `<stufe>/<fall>`.
    path: &'static str,
    /// Die Bezeichnung aus `design.md` §22.1; leer, wenn der Fall aus der
    /// Vektorhygiene stammt statt aus dem Text.
    design_22_1: &'static str,
    /// Der Eintrag, dessen Objekthash den gepinnten Registry-Kopf bildet.
    pinned_head_slot: Option<&'static str>,
    /// Die Kettensequenz, fuer die der Kandidat geprueft wird.
    proposed_sequence: u64,
    /// Die Slots eines Registry-Falls, deren Bytes von
    /// [`TRUST_REGISTRY_BASELINE`] abweichen.
    ///
    /// DER DEFEKTORT, ausgeschrieben. Drei Faelle dieser Stufe messen denselben
    /// Fehlercode `EA-TRUST-SIGNATURE`; ohne diese Angabe koennten sie
    /// unbemerkt derselbe Vektor unter drei Namen sein. Fuer Faelle anderer
    /// Stufen bleibt die Liste leer und ungeprueft.
    differing_slots: &'static [&'static str],
}

/// Alle Faelle der Familie.
///
/// Die Zuordnung `design.md`-Bezeichnung zu Fall ist eine BIJEKTION: jeder in
/// §22.1 genannte Fall hat genau einen Eintrag, und jeder Fall mit Bezeichnung
/// nennt genau einen §22.1-Fall.
const TRUST_CASES: [TrustCase; 19] = [
    TrustCase {
        path: "object/accepted-policy-core-reader-trust-refresh-disabled",
        design_22_1: "",
        pinned_head_slot: None,
        proposed_sequence: 0,
        differing_slots: &[],
    },
    TrustCase {
        path: "object/accepted-policy-core-reader-trust-refresh-set",
        design_22_1: "",
        pinned_head_slot: None,
        proposed_sequence: 0,
        differing_slots: &[],
    },
    TrustCase {
        path: "registry/accepted-bootstrap-and-first-head",
        design_22_1: "positiver Pre-Registry-Signer",
        pinned_head_slot: None,
        proposed_sequence: 1,
        differing_slots: &[],
    },
    TrustCase {
        path: "registry/accepted-admin-rotation",
        design_22_1: "Adminrotation",
        pinned_head_slot: Some("head-event"),
        proposed_sequence: 101,
        differing_slots: &[],
    },
    TrustCase {
        path: "registry/rejected-authorized-core-hash-mismatch",
        design_22_1: "Admin-Authorization/Core-Hash",
        pinned_head_slot: None,
        proposed_sequence: 1,
        differing_slots: &[
            "policy-authorization",
            "policy",
            "head-authorization",
            "head-event",
        ],
    },
    TrustCase {
        path: "registry/rejected-root-only-signed-by-admin",
        design_22_1: "Root-only",
        pinned_head_slot: None,
        proposed_sequence: 1,
        differing_slots: &["head-event"],
    },
    TrustCase {
        path: "registry/rejected-admin-only-signed-by-root",
        design_22_1: "Admin-only",
        pinned_head_slot: None,
        proposed_sequence: 1,
        differing_slots: &["head-authorization", "head-event"],
    },
    TrustCase {
        path: "registry/rejected-reused-authorization-id-and-nonce",
        design_22_1: "wiederverwendete ID/Nonce",
        pinned_head_slot: None,
        proposed_sequence: 1,
        differing_slots: &["head-authorization", "head-event"],
    },
    TrustCase {
        path: "registry/rejected-signer-context-deviation",
        design_22_1: "Signer-Kontext-Abweichung",
        pinned_head_slot: None,
        proposed_sequence: 1,
        differing_slots: &[
            "policy-authorization",
            "policy",
            "head-authorization",
            "head-event",
        ],
    },
    TrustCase {
        path: "registry/rejected-null-context-after-first-head",
        design_22_1: "erneute Nullkontext-Nutzung nach erstem Head",
        pinned_head_slot: None,
        proposed_sequence: 1,
        differing_slots: &["head-authorization", "head-event"],
    },
    TrustCase {
        path: "bootstrap/rejected-unpinned-admin-pair",
        design_22_1: "unpinned Admin-Zertifikate/-Bindings",
        pinned_head_slot: None,
        proposed_sequence: 1,
        differing_slots: &[],
    },
    TrustCase {
        path: "bootstrap/rejected-hash-divergent-admin-certificate",
        design_22_1: "hashabweichende Admin-Zertifikate/-Bindings",
        pinned_head_slot: None,
        proposed_sequence: 1,
        differing_slots: &[],
    },
    TrustCase {
        path: "bootstrap/rejected-mispaired-admin-binding",
        design_22_1: "falsch gepaarte Admin-Zertifikate/-Bindings",
        pinned_head_slot: None,
        proposed_sequence: 1,
        differing_slots: &[],
    },
    TrustCase {
        path: "bootstrap/rejected-shared-os-and-instance-key",
        design_22_1: "fehlende OS-/Instanzschluessel-Pruefung",
        pinned_head_slot: None,
        proposed_sequence: 1,
        differing_slots: &[],
    },
    TrustCase {
        path: "anchor/rejected-mutated-pre-anchor-field",
        design_22_1: "veraenderte Vorstufenfelder",
        pinned_head_slot: None,
        proposed_sequence: 1,
        differing_slots: &[],
    },
    TrustCase {
        path: "anchor/rejected-wrong-bootstrap-anchor-hash",
        design_22_1: "falscher bootstrap-anchor-hash",
        pinned_head_slot: None,
        proposed_sequence: 1,
        differing_slots: &[],
    },
    TrustCase {
        path: "object/rejected-action-code-200",
        design_22_1: "falscher Action-Code",
        pinned_head_slot: None,
        proposed_sequence: 1,
        differing_slots: &[],
    },
    TrustCase {
        path: "object/rejected-unknown-target-subtype",
        design_22_1: "",
        pinned_head_slot: None,
        proposed_sequence: 1,
        differing_slots: &[],
    },
    TrustCase {
        path: "object/accepted-handmade-admin-authorization",
        design_22_1: "",
        pinned_head_slot: None,
        proposed_sequence: 1,
        differing_slots: &[],
    },
];

/// Die in `design.md` §22.1 namentlich genannten Faelle, woertlich uebernommen.
///
/// Die Liste ist die zweite Haelfte der Bijektion: sie steht hier, damit ein
/// verschwundener Fall auffaellt, statt still ungeprueft zu bleiben.
const TRUST_DESIGN_22_1_CASES: [&str; 15] = [
    "Admin-Authorization/Core-Hash",
    "Adminrotation",
    "Admin-only",
    "Root-only",
    "Signer-Kontext-Abweichung",
    "erneute Nullkontext-Nutzung nach erstem Head",
    "falsch gepaarte Admin-Zertifikate/-Bindings",
    "falscher Action-Code",
    "falscher bootstrap-anchor-hash",
    "fehlende OS-/Instanzschluessel-Pruefung",
    "hashabweichende Admin-Zertifikate/-Bindings",
    "positiver Pre-Registry-Signer",
    "unpinned Admin-Zertifikate/-Bindings",
    "veraenderte Vorstufenfelder",
    "wiederverwendete ID/Nonce",
];

#[test]
fn trust_v1_vectors_cover_every_negative_named_in_design_22_1() {
    let root = workspace_root();
    let text = fs::read_to_string(root.join(TRUST_MANIFEST_PATH))
        .unwrap_or_else(|error| panic!("failed to read {TRUST_MANIFEST_PATH}: {error}"));
    let manifest = VectorManifest::from_json(&text)
        .unwrap_or_else(|error| panic!("failed to parse {TRUST_MANIFEST_PATH}: {error}"));
    assert_eq!(manifest.family, "trust");
    assert_eq!(manifest.version, "v1");

    // Das Manifest darf seiner Platte nicht widersprechen.
    let report = verify_manifest_at(&root.join(TRUST_VECTOR_ROOT))
        .unwrap_or_else(|error| panic!("failed to verify {TRUST_VECTOR_ROOT}: {error}"));
    assert_eq!(report.entries_checked, manifest.entries.len());
    assert!(
        report.is_clean(),
        "the frozen files contradict their manifest: {:?}",
        report.mismatches
    );

    let entries = &manifest.entries;
    check_trust_case_paths(entries);
    check_trust_design_bijection();
    check_trust_hygiene(entries, &text);

    let mut executed = BTreeSet::new();
    for case in &TRUST_CASES {
        for name in check_trust_case(case, entries) {
            assert!(executed.insert(name.clone()), "{name} was executed twice");
        }
    }
    check_trust_registry_defect_sites(entries);

    let recorded = entries
        .iter()
        .map(|entry| entry.name.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(recorded.len(), entries.len(), "entry names must be unique");
    assert_eq!(
        recorded, executed,
        "every manifest entry must be executed, and every execution must address \
         a manifest entry"
    );
}

/// Der Fallname ohne seine Stufe.
fn trust_case_basename(path: &str) -> &str {
    path.rsplit_once('/')
        .unwrap_or_else(|| panic!("{path} must be named <stufe>/<fall>"))
        .1
}

/// Der Slotname eines Eintrags: alles nach dem letzten Schraegstrich.
fn trust_slot_name(name: &str) -> &str {
    name.rsplit_once('/')
        .unwrap_or_else(|| panic!("{name} must be named <stufe>/<fall>/<slot>"))
        .1
}

/// Der Eintrag, der die Pipeline eines Falls betritt und sein Urteil traegt.
fn trust_verdict_entry<'a>(case: &TrustCase, members: &[&'a VectorEntry]) -> &'a VectorEntry {
    if case.path.starts_with("object/") {
        assert_eq!(members.len(), 1, "{} is a single object case", case.path);
        return members[0];
    }
    single_by_schema(members, TRUST_ANCHOR_SCHEMA_ID, case.path)
}

/// Jeder Registry-Fall weicht genau dort vom Basisfall ab, wo sein Name es
/// sagt.
///
/// Drei Faelle dieser Stufe messen denselben Code `EA-TRUST-SIGNATURE`. Der
/// gemessene Fehlercode allein belegt deshalb NICHT, dass es drei verschiedene
/// Defekte sind — er waere auch dann gleich, wenn dreimal dasselbe Objekt
/// unter drei Namen laege. Die Menge der abweichenden Slots trennt sie.
fn check_trust_registry_defect_sites(entries: &[VectorEntry]) {
    let baseline = entries
        .iter()
        .filter(|vector| trust_case_path(&vector.name) == TRUST_REGISTRY_BASELINE)
        .map(|vector| {
            (
                trust_slot_name(&vector.name),
                vector.object_bytes.as_slice(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert!(
        !baseline.is_empty(),
        "{TRUST_REGISTRY_BASELINE} must exist as the reference case"
    );

    let mut fingerprints = BTreeSet::new();
    for case in &TRUST_CASES {
        if !case.path.starts_with("registry/") {
            assert!(
                case.differing_slots.is_empty(),
                "{} is not a registry case and declares no defect site",
                case.path
            );
            continue;
        }
        let members = entries
            .iter()
            .filter(|vector| trust_case_path(&vector.name) == case.path)
            .collect::<Vec<_>>();
        let mut differing = BTreeSet::new();
        let mut additional = BTreeSet::new();
        for vector in &members {
            let slot = trust_slot_name(&vector.name);
            match baseline.get(slot) {
                Some(reference) if *reference == vector.object_bytes.as_slice() => {}
                Some(_) => {
                    differing.insert(slot.to_owned());
                }
                // Ein Slot, den der Basisfall nicht kennt: der Fall setzt
                // Objekte HINZU, statt welche zu ersetzen. `accepted-admin-rotation`
                // ist genau das — sein erster Kopf ist byteidentisch, und der
                // zweite kommt dazu.
                None => {
                    additional.insert(slot.to_owned());
                }
            }
        }
        let declared = case
            .differing_slots
            .iter()
            .map(|slot| (*slot).to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            differing, declared,
            "{} must differ from the baseline exactly where it declares",
            case.path
        );

        let verdict = match &trust_verdict_entry(case, &members).expected_outcome {
            ExpectedOutcome::Accepted => "accepted".to_owned(),
            ExpectedOutcome::Rejected { error_code } => {
                assert!(
                    !differing.is_empty() || !additional.is_empty(),
                    "{} claims a rejection but carries the baseline bytes",
                    case.path
                );
                error_code.clone()
            }
        };
        assert!(
            fingerprints.insert((differing, additional, verdict)),
            "{} shares defect site and verdict with another case and is therefore \
             the same vector under two names",
            case.path
        );
    }
}

/// Der Fallpfad eines Eintrags: alles vor dem letzten Schraegstrich.
fn trust_case_path(name: &str) -> &str {
    name.rsplit_once('/')
        .unwrap_or_else(|| panic!("{name} must be named <stufe>/<fall>/<slot>"))
        .0
}

/// Das Manifest deckt genau die Faelle dieser Tabelle ab.
fn check_trust_case_paths(entries: &[VectorEntry]) {
    let recorded = entries
        .iter()
        .map(|entry| trust_case_path(&entry.name).to_owned())
        .collect::<BTreeSet<_>>();
    let expected = TRUST_CASES
        .iter()
        .map(|case| case.path.to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        recorded, expected,
        "the manifest must hold exactly the mandated cases"
    );
}

/// Jeder in §22.1 genannte Fall hat genau einen Vektor, und umgekehrt.
fn check_trust_design_bijection() {
    let mut named = BTreeSet::new();
    for case in &TRUST_CASES {
        if case.design_22_1.is_empty() {
            continue;
        }
        assert!(
            named.insert(case.design_22_1.to_owned()),
            "{} is claimed by more than one case",
            case.design_22_1
        );
    }
    let expected = TRUST_DESIGN_22_1_CASES
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        expected.len(),
        TRUST_DESIGN_22_1_CASES.len(),
        "the design list must not repeat itself"
    );
    assert_eq!(
        named, expected,
        "every case named in design.md §22.1 must have exactly one vector"
    );
}

/// Die Vektorhygiene, die nicht aus dem Bestand folgt, sondern gesetzt ist.
fn check_trust_hygiene(entries: &[VectorEntry], manifest_text: &str) {
    for reserved in TRUST_RESERVED_SUBTYPE_NAMES {
        assert!(
            !manifest_text.contains(reserved),
            "{reserved} could become a real trust object family and must not appear \
             in a frozen negative vector"
        );
    }

    let action = entry(
        entries,
        "object/rejected-action-code-200/admin-authorization",
    );
    let (subtype, action_code, target) = trust_object_parts(&action.object_bytes);
    assert_eq!(subtype, TRUST_ADMIN_AUTHORIZATION_SUBTYPE);
    assert_eq!(
        action_code,
        Some(TRUST_INVALID_ACTION_CODE),
        "the action code negative must carry 200; the neighbour value 7 would flip \
         from rejected to accepted once v1.1 widens the range"
    );
    assert_eq!(target.as_deref(), Some("policy"));

    let unknown = entry(
        entries,
        "object/rejected-unknown-target-subtype/admin-authorization",
    );
    let (subtype, action_code, target) = trust_object_parts(&unknown.object_bytes);
    assert_eq!(subtype, TRUST_ADMIN_AUTHORIZATION_SUBTYPE);
    assert_eq!(action_code, Some(2));
    assert_eq!(
        target.as_deref(),
        Some(TRUST_UNKNOWN_SUBTYPE),
        "the unknown subtype negative must carry the reserved-free literal"
    );

    let control = entry(
        entries,
        "object/accepted-handmade-admin-authorization/admin-authorization",
    );
    expect_accepted(control);
    let (_, action_code, target) = trust_object_parts(&control.object_bytes);
    assert_eq!(
        (action_code, target.as_deref()),
        (Some(2), Some("policy")),
        "the control proves the hand written encoder is faithful, so each negative \
         isolates exactly one defect"
    );

    let mut authorizations = 0_usize;
    for vector in entries {
        if vector.schema_id != TRUST_OBJECT_SCHEMA_ID {
            continue;
        }
        let (subtype, _, _) = trust_object_parts(&vector.object_bytes);
        if subtype != TRUST_ADMIN_AUTHORIZATION_SUBTYPE {
            continue;
        }
        authorizations += 1;
        let note = vector.scope_note.as_deref().unwrap_or_else(|| {
            panic!(
                "{} carries an organizationAdminAuthorization and must state what it \
                 does NOT prove",
                vector.name
            )
        });
        assert!(
            note.contains("7.5"),
            "{} must name the web reader spec §7.5 gap: {note}",
            vector.name
        );
    }
    assert!(
        authorizations > 0,
        "the family must freeze organizationAdminAuthorization vectors"
    );
}

/// Ein Fall, vollstaendig ausgefuehrt. Liefert die Namen der geprueften
/// Eintraege.
fn check_trust_case(case: &TrustCase, entries: &[VectorEntry]) -> Vec<String> {
    let members = entries
        .iter()
        .filter(|vector| trust_case_path(&vector.name) == case.path)
        .collect::<Vec<_>>();
    assert!(!members.is_empty(), "{} has no vectors", case.path);

    let tier = case
        .path
        .split_once('/')
        .unwrap_or_else(|| panic!("{} must name its tier", case.path))
        .0;

    // Die Polaritaet steht im Namen und ist damit eine ZUSAGE, nicht nur eine
    // Aufzeichnung. Ohne diese Pruefung koennte ein spaeterer Erzeugungslauf
    // einen `rejected-`-Fall still auf `Accepted` umschreiben: beide Tests
    // blieben gruen, und die MUSS-Zusage aus §22.1 waere lautlos verletzt.
    let verdict_outcome = &trust_verdict_entry(case, &members).expected_outcome;
    match trust_case_basename(case.path) {
        name if name.starts_with("rejected-") => assert!(
            matches!(verdict_outcome, ExpectedOutcome::Rejected { .. }),
            "{} is named a rejection and must reject",
            case.path
        ),
        name if name.starts_with("accepted-") => assert_eq!(
            verdict_outcome,
            &ExpectedOutcome::Accepted,
            "{} is named an acceptance and must be accepted",
            case.path
        ),
        name => panic!("{name} must name its polarity as accepted- or rejected-"),
    }

    // Jedes Vertrauensobjekt parst fuer sich, unabhaengig vom Urteil des Falls.
    for vector in &members {
        if vector.schema_id != TRUST_OBJECT_SCHEMA_ID {
            continue;
        }
        let outcome = match decode_exact_object(&vector.object_bytes) {
            Ok(parsed) => {
                let (exact, hash) = format_parsed_parts(&parsed);
                assert_eq!(
                    exact, vector.object_bytes,
                    "{} must round-trip byte for byte",
                    vector.name
                );
                assert_eq!(
                    intermediate(vector, "objectHash"),
                    hex::encode(hash.as_bytes()),
                    "{} must record its own object hash",
                    vector.name
                );
                ExpectedOutcome::Accepted
            }
            Err(error) => ExpectedOutcome::Rejected {
                error_code: error.code().to_owned(),
            },
        };
        assert_eq!(
            outcome, vector.expected_outcome,
            "{} must parse exactly as its manifest records",
            vector.name
        );
    }

    if tier == "object" {
        assert_eq!(members.len(), 1, "{} is a single object case", case.path);
        return members.iter().map(|vector| vector.name.clone()).collect();
    }

    let anchor_vector = single_by_schema(&members, TRUST_ANCHOR_SCHEMA_ID, case.path);
    let pre_anchor = members
        .iter()
        .find(|vector| vector.schema_id == TRUST_PRE_ANCHOR_SCHEMA_ID);
    let catalog = members
        .iter()
        .filter(|vector| vector.schema_id == TRUST_OBJECT_SCHEMA_ID)
        .map(|vector| vector.object_bytes.clone())
        .collect::<Vec<_>>();

    if let Some(pre_anchor) = pre_anchor {
        let computed = bootstrap_anchor_hash(&pre_anchor.object_bytes);
        assert_eq!(
            intermediate(pre_anchor, "bootstrapAnchorHash"),
            hex::encode(computed.as_bytes()),
            "{} must record its own bootstrap anchor hash",
            pre_anchor.name
        );
        assert_eq!(
            hex::encode(computed.as_bytes()),
            hex::encode(trust_anchor_embedded_hash(&anchor_vector.object_bytes)),
            "{} must be the confirmed pre stage of its final anchor",
            pre_anchor.name
        );
        expect_accepted(pre_anchor);
    }

    let pin = case.pinned_head_slot.map(|slot| {
        let head = entry(entries, &format!("{}/{slot}", case.path));
        // Der erste Kopf traegt Registry-Version 1; der Fall pinnt ihn, damit
        // der zweite Kopf ueberhaupt Kandidat werden kann.
        RegistryHeadPin::new(RegistryVersion::new(1), object_hash(&head.object_bytes))
    });

    let outcome = run_trust_case(
        tier,
        &anchor_vector.object_bytes,
        &catalog,
        pin,
        case.proposed_sequence,
    );
    assert_eq!(
        outcome, anchor_vector.expected_outcome,
        "{} must reach exactly the verdict its manifest records",
        anchor_vector.name
    );
    assert_eq!(
        intermediate(anchor_vector, "trustAnchorHash"),
        hex::encode(trust_anchor_hash(&anchor_vector.object_bytes).as_bytes()),
        "{} must record its own trust anchor hash",
        anchor_vector.name
    );

    members.iter().map(|vector| vector.name.clone()).collect()
}

/// Genau ein Eintrag eines Falls traegt dieses Schema.
fn single_by_schema<'a>(
    members: &[&'a VectorEntry],
    schema_id: &str,
    case: &str,
) -> &'a VectorEntry {
    let mut found = members
        .iter()
        .filter(|vector| vector.schema_id == schema_id);
    let first = found
        .next()
        .unwrap_or_else(|| panic!("{case} misses its {schema_id} entry"));
    assert!(
        found.next().is_none(),
        "{case} must hold exactly one {schema_id} entry"
    );
    first
}

/// Fuehrt die Pipeline der Stufe aus und liefert das gemessene Ergebnis.
fn run_trust_case(
    tier: &str,
    anchor_bytes: &[u8],
    catalog: &[Vec<u8>],
    pin: Option<RegistryHeadPin>,
    proposed_sequence: u64,
) -> ExpectedOutcome {
    let anchor = match decode_trust_anchor(anchor_bytes) {
        Ok(anchor) => anchor,
        Err(error) => {
            return ExpectedOutcome::Rejected {
                error_code: error.code().to_owned(),
            };
        }
    };
    if tier == "anchor" {
        return ExpectedOutcome::Accepted;
    }

    let source = TrustCatalogSource(
        catalog
            .iter()
            .map(|bytes| (object_hash(bytes), Arc::<[u8]>::from(bytes.clone())))
            .collect(),
    );
    let state_key = TrustStateKey {
        organization_id: anchor.organization_id(),
        device_id: DeviceId::try_from(&[0xf0; 16][..]).expect("16 bytes"),
    };
    let mut store = TrustSnapshotStore {
        key: state_key,
        record: Some(PersistedTrustRecord::new(
            17,
            TrustedTimeState::initial(UnixMillis::new(1_700_000_000_000)),
            pin,
        )),
    };
    let snapshot = load_trust_state(&mut store, state_key).expect("the fixture store answers");
    let trust = match verify_trust(&anchor, &source, snapshot) {
        Ok(trust) => trust,
        Err(error) => {
            return ExpectedOutcome::Rejected {
                error_code: error.code().to_owned(),
            };
        }
    };
    if tier == "bootstrap" {
        return ExpectedOutcome::Accepted;
    }

    match verify_registry_candidate(&trust, ChainSequence::new(proposed_sequence)) {
        Ok(_) => ExpectedOutcome::Accepted,
        Err(error) => ExpectedOutcome::Rejected {
            error_code: error.code().to_owned(),
        },
    }
}

/// Der im Anchor eingebettete `bootstrap-anchor-hash`.
fn trust_anchor_embedded_hash(anchor_bytes: &[u8]) -> Vec<u8> {
    let mut decoder = Decoder::new(anchor_bytes);
    assert_eq!(decoder.array().expect("anchor array"), Some(12));
    assert_eq!(
        decoder.str().expect("anchor domain"),
        "EINSATZARCHIV-TRUST-ANCHOR-v1"
    );
    assert_eq!(decoder.u64().expect("anchor version"), 1);
    decoder.bytes().expect("embedded hash").to_vec()
}

/// Subtype, Action-Code und Ziel-Subtype eines Vertrauensbausteins, roh
/// gelesen.
///
/// Roh, weil die Negativvektoren gerade NICHT durch `ea-format` gehen: ein
/// Action-Code von 200 wird dort abgelehnt, bevor irgendein Feld herauskaeme.
fn trust_object_parts(object_bytes: &[u8]) -> (String, Option<u64>, Option<String>) {
    let body = object_bytes
        .get(9..)
        .unwrap_or_else(|| panic!("a trust object carries the nine byte prefix"));
    let mut decoder = Decoder::new(body);
    assert_eq!(decoder.array().expect("trust body array"), Some(3));
    let subtype = decoder.str().expect("trust subtype").to_owned();
    if subtype != TRUST_ADMIN_AUTHORIZATION_SUBTYPE {
        return (subtype, None, None);
    }
    assert_eq!(
        decoder.array().expect("authorization array"),
        Some(15),
        "the organizationAdminAuthorization stays at fifteen fields"
    );
    for _ in 0..8 {
        decoder.skip().expect("authorization prefix field");
    }
    let action_code = decoder.u64().expect("action code");
    let target = decoder.str().expect("target subtype").to_owned();
    (subtype, Some(action_code), Some(target))
}

/// Ein Objektkatalog aus eingefrorenen Bytes.
struct TrustCatalogSource(BTreeMap<ObjectHash, Arc<[u8]>>);

impl TrustObjectSource for TrustCatalogSource {
    fn visit_trust_object_hashes(
        &self,
        visitor: &mut dyn FnMut(ObjectHash) -> Result<(), TrustSourceError>,
    ) -> Result<(), TrustSourceError> {
        for hash in self.0.keys().rev().copied() {
            visitor(hash)?;
        }
        Ok(())
    }

    fn read_exact_trust_object(
        &self,
        object_hash: ObjectHash,
    ) -> Result<Option<Arc<[u8]>>, TrustSourceError> {
        Ok(self.0.get(&object_hash).map(Arc::clone))
    }
}

/// Ein Zustandsspeicher, der genau einen Datensatz herausgibt.
struct TrustSnapshotStore {
    key: TrustStateKey,
    record: Option<PersistedTrustRecord>,
}

impl TrustStateStore for TrustSnapshotStore {
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        if key != self.key {
            return Err(StateStoreError::Unavailable);
        }
        self.record.take().ok_or(StateStoreError::Unavailable)
    }

    fn commit_independent_time(
        &mut self,
        _key: TrustStateKey,
        _expected_revision: u64,
        _commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }

    fn clock_release_consumed(
        &mut self,
        _key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }

    fn commit_registry_selection(
        &mut self,
        _key: TrustStateKey,
        _expected_revision: u64,
        _commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }
}

// ---------------------------------------------------------------------------
// Die Vektorfamilien `grants/v1`, `receipts/v1` und `evidence/v1`
// ---------------------------------------------------------------------------
//
// KEIN SNAPSHOT-ABGLEICH GEGEN SICH SELBST. Der Test liest die eingefrorenen
// Bytes und fuehrt die echte Pipeline darueber:
// `ea_format::decode_exact_object` fuer jedes Archivobjekt,
// `ea_format::GrantPlanV1::new` fuer die Plan-Sortierung und das
// Duplikatverbot, `ea_crypto::hpke_open` fuer Kapselungswert und umschlossenen
// CEK, `ea_crypto::cose_sign1_ctt_imprint` fuer den RFC-9921-Hash des
// CBOR-kodierten Signaturfelds.
//
// # Wo die Stufe-1-Grenze liegt, und warum sie im Manifest steht
//
// Gate `evidence` von `ea-verify` ist von aussen NICHT aufrufbar:
// `run_evidence_gate` ist `pub(crate)` und braucht einen vollstaendigen
// Bestand. Was von hier aus erreichbar ist, ist die Bindung, die
// `token_is_bound` prueft — das im COSE eingebettete Token gegen das daneben
// archivierte —, und genau die fuehrt dieser Test nach; der erwartete Code
// stammt dabei aus `ea_verify::EvidenceGateErrorV1`, nicht aus einem Literal.
//
// Alles, was IM DER-Token steht, bleibt unerreichbar: `ea-crypto` haelt
// `validate_timestamp_token_der` privat und gibt weder `messageImprint` noch
// Policy heraus. Die betroffenen Vektoren sind deshalb `accepted` — und tragen
// eine Reichweitennotiz, die das ausspricht. Ein `accepted` ohne Notiz waere
// hier eine Falschaussage.

/// Der Manifestpfad der Grant-Vektoren, relativ zur Arbeitsbaumwurzel.
const GRANTS_MANIFEST_PATH: &str = "vectors/grants/v1/manifest.json";

/// Die Wurzel der Grant-Vektoren.
const GRANTS_VECTOR_ROOT: &str = "vectors/grants/v1";

/// Der Manifestpfad der Receipt-Vektoren, relativ zur Arbeitsbaumwurzel.
const RECEIPTS_MANIFEST_PATH: &str = "vectors/receipts/v1/manifest.json";

/// Die Wurzel der Receipt-Vektoren.
const RECEIPTS_VECTOR_ROOT: &str = "vectors/receipts/v1";

/// Der Manifestpfad der Evidence-Vektoren, relativ zur Arbeitsbaumwurzel.
const EVIDENCE_MANIFEST_PATH: &str = "vectors/evidence/v1/manifest.json";

/// Die Wurzel der Evidence-Vektoren.
const EVIDENCE_VECTOR_ROOT: &str = "vectors/evidence/v1";

/// Die Zahl der Grant-Eintraege. Ohne diese Schranke liefe ein truncatiertes
/// Manifest still durch.
const GRANTS_EXPECTED_ENTRY_COUNT: usize = 14;

/// Die Zahl der Receipt-Eintraege.
const RECEIPTS_EXPECTED_ENTRY_COUNT: usize = 7;

/// Die Zahl der Evidence-Eintraege.
const EVIDENCE_EXPECTED_ENTRY_COUNT: usize = 8;

/// Der Grant-Suite-Identifikator, EINGEFROREN.
const GRANTS_FROZEN_SUITE_ID: &str = "EINSATZARCHIV-HPKE-1";

/// Der Suite-Identifikator der Receipt- und Evidence-Vektoren, EINGEFROREN.
const ARCHIVE_FROZEN_SUITE_ID: &str = "EINSATZARCHIV-SUITE-1";

#[test]
fn grant_receipt_and_evidence_vectors_match_their_manifests() {
    let root = workspace_root();
    let grants = load_frozen_family(
        &root,
        GRANTS_MANIFEST_PATH,
        GRANTS_VECTOR_ROOT,
        "grants",
        GRANTS_EXPECTED_ENTRY_COUNT,
    );
    let receipts = load_frozen_family(
        &root,
        RECEIPTS_MANIFEST_PATH,
        RECEIPTS_VECTOR_ROOT,
        "receipts",
        RECEIPTS_EXPECTED_ENTRY_COUNT,
    );
    let evidence = load_frozen_family(
        &root,
        EVIDENCE_MANIFEST_PATH,
        EVIDENCE_VECTOR_ROOT,
        "evidence",
        EVIDENCE_EXPECTED_ENTRY_COUNT,
    );

    for (family, entries, suite) in [
        ("grants", &grants.entries, GRANTS_FROZEN_SUITE_ID),
        ("receipts", &receipts.entries, ARCHIVE_FROZEN_SUITE_ID),
        ("evidence", &evidence.entries, ARCHIVE_FROZEN_SUITE_ID),
    ] {
        for vector in entries.iter() {
            assert_eq!(
                vector.suite_id, suite,
                "{family} entry {} must name its frozen suite",
                vector.name
            );
        }
    }

    for (entries, executed) in [
        (&grants.entries, check_grant_vectors(&grants.entries)),
        (&receipts.entries, check_receipt_vectors(&receipts.entries)),
        (&evidence.entries, check_evidence_vectors(&evidence.entries)),
    ] {
        let recorded = entries
            .iter()
            .map(|vector| vector.name.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(recorded.len(), entries.len(), "entry names must be unique");
        assert_eq!(
            recorded, executed,
            "every manifest entry must be executed, and every execution must \
             address a manifest entry"
        );
    }
}

/// Liest ein Manifest, prueft es gegen die Platte und gibt es zurueck.
fn load_frozen_family(
    root: &Path,
    manifest_path: &str,
    vector_root: &str,
    family: &str,
    expected_entries: usize,
) -> VectorManifest {
    let text = fs::read_to_string(root.join(manifest_path))
        .unwrap_or_else(|error| panic!("failed to read {manifest_path}: {error}"));
    let manifest = VectorManifest::from_json(&text)
        .unwrap_or_else(|error| panic!("failed to parse {manifest_path}: {error}"));
    assert_eq!(manifest.family, family);
    assert_eq!(manifest.version, "v1");
    assert_eq!(
        manifest.entries.len(),
        expected_entries,
        "{family} must freeze exactly {expected_entries} vectors"
    );
    let report = verify_manifest_at(&root.join(vector_root))
        .unwrap_or_else(|error| panic!("failed to verify {vector_root}: {error}"));
    assert_eq!(report.entries_checked, manifest.entries.len());
    assert!(
        report.is_clean(),
        "the frozen files contradict their manifest: {:?}",
        report.mismatches
    );
    manifest
}

// ---------------------------------------------------------------------------
// grants/v1
// ---------------------------------------------------------------------------

/// Die vier Plaene, die `GrantPlanV1::new` ablehnen MUSS.
const GRANT_REJECTED_PLANS: [&str; 4] = [
    "plan/rejected-duplicate-recipient-certificate",
    "plan/rejected-duplicate-recipient-key",
    "plan/rejected-duplicate-recovery",
    "plan/rejected-missing-recovery",
];

/// Die drei Ein-Byte-Abweichungen am initialen Grant, mit ihrem Defektort.
///
/// DER DEFEKTORT, ausgeschrieben. Alle drei messen `EA-FORMAT-COSE`; der
/// gemessene Code allein belegt deshalb nicht, dass es drei verschiedene
/// Defekte sind. Der Ort trennt sie, und er wird aus den Feldwerten des
/// ANGENOMMENEN Grants gesucht, nicht aus einem gezaehlten Versatz.
const GRANT_SINGLE_BYTE_DEFECTS: [(&str, GrantDefectSite); 3] = [
    (
        "grant/rejected-flipped-encapsulated-key",
        GrantDefectSite::EncapsulatedKey,
    ),
    (
        "grant/rejected-flipped-wrapped-cek",
        GrantDefectSite::WrappedCek,
    ),
    (
        "grant/rejected-flipped-signed-grant-digest",
        GrantDefectSite::SignedGrantDigest,
    ),
];

/// Der Ort, an dem ein Negativvektor sein Byte kippt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum GrantDefectSite {
    EncapsulatedKey,
    WrappedCek,
    SignedGrantDigest,
}

/// Die Grant-Familie, vollstaendig ausgefuehrt.
fn check_grant_vectors(entries: &[VectorEntry]) -> BTreeSet<String> {
    let mut executed = BTreeSet::new();

    let suite = entry(entries, "suite/grant-suite-id");
    expect_accepted(suite);
    assert_eq!(
        suite.object_bytes,
        GRANT_SUITE_ID.as_bytes(),
        "the frozen grant suite identifier must equal the one ea-crypto uses"
    );
    executed.insert(suite.name.clone());

    // Der angenommene initiale Grant traegt den Kontext, auf den sich beide
    // Kontextvektoren beziehen.
    let accepted = entry(entries, "grant/accepted-initial-reader");
    let parsed =
        decode_exact_object(&accepted.object_bytes).expect("the accepted initial grant must parse");
    let grant = match &parsed {
        ParsedArchiveObject::Grant(grant) => grant.value(),
        _ => panic!("an .eag must parse as a grant"),
    };
    let context = grant_context_of(grant.exact_grant_body());

    for (name, derive) in [
        (
            "context/initial-grant-hpke-info",
            hpke_info as fn(&[u8]) -> Vec<u8>,
        ),
        ("context/initial-grant-hpke-aad", hpke_aad),
    ] {
        let vector = entry(entries, name);
        expect_accepted(vector);
        assert_eq!(
            vector.input_bytes, context,
            "{name} must carry the grant context of the accepted initial grant"
        );
        assert_eq!(
            vector.object_bytes,
            derive(&vector.input_bytes),
            "{name} must be exactly what ea-crypto derives"
        );
        assert_eq!(
            intermediate(vector, "grantContextDigest"),
            sha256_hex(&vector.input_bytes)
        );
        executed.insert(vector.name.clone());
    }

    // Die totale Sortierung. Der Erzeuger reicht die Eintraege in UMGEKEHRTER
    // Ordnung ein; `GrantPlanV1::new` muss dieselbe Folge liefern wie das
    // eingefrorene Ergebnis.
    let plan = entry(entries, "plan/accepted-total-order");
    expect_accepted(plan);
    assert_ne!(
        plan.input_bytes, plan.object_bytes,
        "an input that already is the enforced order would prove nothing"
    );
    let built = GrantPlanV1::new(grant_plan_items(&plan.input_bytes))
        .expect("the frozen grant plan must be accepted");
    assert_eq!(
        grant_plan_flat(built.items()),
        plan.object_bytes,
        "GrantPlanV1 must enforce exactly the frozen total order"
    );
    assert_eq!(
        intermediate(plan, "grantPlanHash"),
        hex::encode(built.hash().as_bytes()),
        "the frozen plan hash must be what grant_plan_digest computes"
    );
    executed.insert(plan.name.clone());

    for name in GRANT_REJECTED_PLANS {
        let vector = entry(entries, name);
        let error = GrantPlanV1::new(grant_plan_items(&vector.object_bytes))
            .err()
            .unwrap_or_else(|| panic!("{name} must be rejected"));
        assert_eq!(error.code(), rejection_code(vector));
        executed.insert(vector.name.clone());
    }

    for name in [
        "grant/accepted-initial-reader",
        "grant/accepted-historical-reader",
    ] {
        executed.insert(check_accepted_grant(entry(entries, name)));
    }

    let fields = grant.grant_body().fields();
    let digest = grant_digest(grant.exact_grant_body());
    for (name, site) in GRANT_SINGLE_BYTE_DEFECTS {
        let vector = entry(entries, name);
        let error = decode_exact_object(&vector.object_bytes)
            .err()
            .unwrap_or_else(|| panic!("{name} must be rejected"));
        assert_eq!(error.code(), rejection_code(vector));
        let needle: &[u8] = match site {
            GrantDefectSite::EncapsulatedKey => &fields.encapsulated_key,
            GrantDefectSite::WrappedCek => &fields.wrapped_cek,
            GrantDefectSite::SignedGrantDigest => digest.as_bytes(),
        };
        let start = unique_offset(&accepted.object_bytes, needle);
        let offsets = differing_offsets(&accepted.object_bytes, &vector.object_bytes);
        assert_eq!(offsets.len(), 1, "{name} must flip exactly one byte");
        assert!(
            (start..start + needle.len()).contains(&offsets[0]),
            "{name} must flip its byte inside {site:?}"
        );
        executed.insert(vector.name.clone());
    }

    // Der wiedersignierte Vektor passiert die Formatebene und scheitert erst
    // an `hpke_open` — die Reihenfolge, in der auch `ea-recovery` arbeitet.
    let resigned = entry(entries, "grant/rejected-resigned-flipped-encapsulated-key");
    let parsed = decode_exact_object(&resigned.object_bytes)
        .expect("the resigned grant must pass the format layer");
    let resigned_grant = match &parsed {
        ParsedArchiveObject::Grant(grant) => grant.value(),
        _ => panic!("an .eag must parse as a grant"),
    };
    let Err(error) = open_grant(resigned_grant) else {
        panic!("the resigned grant must not open")
    };
    assert_eq!(error.code(), rejection_code(resigned));
    let resigned_fields = resigned_grant.grant_body().fields();
    assert_eq!(
        differing_offsets(&fields.encapsulated_key, &resigned_fields.encapsulated_key).len(),
        1,
        "the resigned vector must flip exactly one byte of the encapsulated key"
    );
    assert_eq!(
        resigned_fields.wrapped_cek, fields.wrapped_cek,
        "the resigned vector must keep the wrapped content key"
    );
    assert_ne!(
        resigned_grant.issuer_signature(),
        grant.issuer_signature(),
        "the resigned vector must carry a signature over its own body"
    );
    executed.insert(resigned.name.clone());

    executed
}

/// Ein angenommener Grant, vollstaendig geprueft.
fn check_accepted_grant(vector: &VectorEntry) -> String {
    expect_accepted(vector);
    assert_eq!(
        vector.source,
        VectorSource::FrozenOnce {
            verified_via: "hpke_open".to_owned(),
        },
        "the sealing direction draws fresh entropy and is checked in reverse"
    );
    let parsed = decode_exact_object(&vector.object_bytes).expect("an accepted grant must parse");
    let (exact, hash) = format_parsed_parts(&parsed);
    assert_eq!(exact, vector.object_bytes, "the grant must round-trip");
    assert_eq!(
        intermediate(vector, "objectHash"),
        hex::encode(hash.as_bytes())
    );
    let grant = match &parsed {
        ParsedArchiveObject::Grant(grant) => grant.value(),
        _ => panic!("an .eag must parse as a grant"),
    };
    assert_eq!(
        intermediate(vector, "grantDigest"),
        hex::encode(grant_digest(grant.exact_grant_body()).as_bytes()),
        "{} must record the digest its issuer signature covers",
        vector.name
    );
    assert_eq!(
        intermediate(vector, "grantBodyDigest"),
        sha256_hex(grant.exact_grant_body())
    );
    check_eag_field_positions(grant);
    let opened = open_grant(grant).expect("an accepted grant must open for its recipient");
    assert!(
        opened.matches(&array32(&vector.input_bytes, "the wrapped content key")),
        "{} must release exactly the frozen content encryption key",
        vector.name
    );
    vector.name.clone()
}

/// Oeffnet den Grant mit dem deklarierten Empfaengerschluessel.
fn open_grant(grant: &GrantV1) -> Result<SecretBytes<CEK_SIZE>, ea_crypto::CryptoError> {
    let recipient =
        HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(TEST_ENTROPY_RECIPIENT_X25519_SEED))
            .expect("the declared recipient key must load");
    let fields = grant.grant_body().fields();
    let sealed = HpkeSealed::from_parts(fields.encapsulated_key, fields.wrapped_cek)?;
    let context = grant_context_of(grant.exact_grant_body());
    hpke_open(
        &recipient,
        &sealed,
        &hpke_info(&context),
        &hpke_aad(&context),
    )
}

/// Der Grant-Kontext eines Rumpfes.
///
/// Derselbe Schnitt, den `ea-recovery` fuer `hpke_info`/`hpke_aad` nimmt:
/// `grant-body-v1` ist ein Array fester Laenge drei, dessen zweites und drittes
/// Glied Bytefolgen fester Groesse 32 und 48 sind.
fn grant_context_of(exact_grant_body: &[u8]) -> Vec<u8> {
    let tail = 4 + HPKE_ENCAPSULATED_KEY_SIZE + HPKE_WRAPPED_CEK_SIZE;
    assert_eq!(exact_grant_body[0], 0x83);
    let end = exact_grant_body.len() - tail;
    assert_eq!(exact_grant_body[end], 0x58);
    assert_eq!(
        usize::from(exact_grant_body[end + 1]),
        HPKE_ENCAPSULATED_KEY_SIZE
    );
    exact_grant_body[1..end].to_vec()
}

/// Die Eintraege eines Plans aus seiner Flachform.
fn grant_plan_items(flat: &[u8]) -> Vec<GrantPlanItemV1> {
    assert_eq!(
        flat.len() % GRANT_PLAN_ITEM_BYTES,
        0,
        "a flat plan is a whole number of items"
    );
    flat.chunks_exact(GRANT_PLAN_ITEM_BYTES)
        .map(|item| {
            GrantPlanItemV1::new(
                KeyThumbprint::try_from(&item[..32]).expect("32 bytes"),
                CertificateHash::try_from(&item[32..64]).expect("32 bytes"),
                match item[64] {
                    0 => GrantPurposeV1::Recovery,
                    1 => GrantPurposeV1::Reader,
                    other => panic!("a plan purpose is 0 or 1, not {other}"),
                },
            )
        })
        .collect()
}

/// Die Flachform einer Eintragsfolge.
fn grant_plan_flat(items: &[GrantPlanItemV1]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(items.len() * GRANT_PLAN_ITEM_BYTES);
    for item in items {
        bytes.extend_from_slice(item.recipient_key_thumbprint().as_bytes());
        bytes.extend_from_slice(item.recipient_certificate_hash().as_bytes());
        bytes.push(item.purpose() as u8);
    }
    bytes
}

/// Jede Feldposition von `eag-v1`, positionsweise gegen den echten Parser.
///
/// Der Rumpf wird HIER eigenstaendig durchlaufen. Ein Vergleich der Felder
/// gegen sich selbst wuerde nichts belegen; gepruefte Aussage ist, dass an
/// Position `i` genau das Feld steht, das `ea-format` dort meldet.
fn check_eag_field_positions(grant: &GrantV1) {
    let body = grant.exact_grant_body();
    let fields = grant.grant_body().fields();
    let mut decoder = Decoder::new(body);
    assert_eq!(decoder.array().expect("outer array"), Some(3));
    assert_eq!(decoder.array().expect("core array"), Some(17));
    assert_eq!(decoder.u64().expect("version"), 1);
    assert_eq!(
        decoder.bytes().expect("organizationId"),
        fields.organization_id.as_bytes()
    );
    assert_eq!(
        decoder.bytes().expect("chainId"),
        fields.chain_id.as_bytes()
    );
    assert_eq!(
        decoder.bytes().expect("entryHash"),
        fields.entry_hash.as_bytes()
    );
    assert_eq!(
        decoder.u64().expect("kind"),
        match fields.kind {
            GrantKindV1::Initial => 0,
            GrantKindV1::Historical => 1,
        }
    );
    assert_eq!(decoder.u64().expect("purpose"), fields.purpose as u64);
    assert_eq!(
        decoder.bytes().expect("recipientKeyThumbprint"),
        fields.recipient_key_thumbprint.as_bytes()
    );
    assert_eq!(
        decoder.bytes().expect("recipientCertificateHash"),
        fields.recipient_certificate_hash.as_bytes()
    );
    assert_eq!(
        decoder.bytes().expect("issuerKeyThumbprint"),
        fields.issuer_key_thumbprint.as_bytes()
    );
    assert_eq!(
        decoder.bytes().expect("issuerCertificateHash"),
        fields.issuer_certificate_hash.as_bytes()
    );
    assert_eq!(
        decoder.str().expect("capability"),
        match fields.kind {
            GrantKindV1::Initial => "initialGrant",
            GrantKindV1::Historical => "historicalGrant",
        }
    );
    assert_eq!(
        decoder.u64().expect("registryVersion"),
        fields.registry_version.get()
    );
    assert_eq!(
        decoder.bytes().expect("registryHeadHash"),
        fields.registry_head_hash.as_bytes()
    );
    assert_eq!(decoder.str().expect("grantSuiteId"), GRANT_SUITE_ID);
    assert_eq!(
        decoder.i64().expect("createdAtDevice"),
        fields.created_at_device.get()
    );
    assert_eq!(
        optional_hash(&mut decoder, "originalRecoveryGrantObjectHash"),
        fields
            .original_recovery_grant_object_hash
            .map(|hash| hash.as_bytes().to_vec())
    );
    assert_eq!(
        optional_hash(&mut decoder, "grantAuthorizationObjectHash"),
        fields
            .grant_authorization_object_hash
            .map(|hash| hash.as_bytes().to_vec())
    );
    assert_eq!(
        decoder.bytes().expect("encapsulatedKey"),
        fields.encapsulated_key.as_slice()
    );
    assert_eq!(
        decoder.bytes().expect("wrappedCek"),
        fields.wrapped_cek.as_slice()
    );
    assert_eq!(decoder.position(), body.len(), "eag-v1 is a closed shape");
}

/// Ein optionaler 32-Byte-Hash an der aktuellen Position.
fn optional_hash(decoder: &mut Decoder<'_>, label: &str) -> Option<Vec<u8>> {
    if decoder.datatype().expect(label) == minicbor::data::Type::Null {
        decoder.null().expect(label);
        return None;
    }
    Some(decoder.bytes().expect(label).to_vec())
}

/// Der einzige Versatz, an dem `needle` in `haystack` steht.
fn unique_offset(haystack: &[u8], needle: &[u8]) -> usize {
    let mut found = None;
    for start in 0..=haystack.len().saturating_sub(needle.len()) {
        if &haystack[start..start + needle.len()] == needle {
            assert!(found.is_none(), "the needle must occur exactly once");
            found = Some(start);
        }
    }
    found.expect("the needle must occur")
}

/// Die Versaetze, an denen sich zwei gleich lange Bytefolgen unterscheiden.
fn differing_offsets(left: &[u8], right: &[u8]) -> Vec<usize> {
    assert_eq!(
        left.len(),
        right.len(),
        "the two vectors must be equally long"
    );
    left.iter()
        .zip(right)
        .enumerate()
        .filter(|(_, (left, right))| left != right)
        .map(|(index, _)| index)
        .collect()
}

// ---------------------------------------------------------------------------
// receipts/v1
// ---------------------------------------------------------------------------

/// Die Quittungen, die `decode_exact_object` ablehnen MUSS, mit ihrem
/// Defektort.
///
/// DER DEFEKTORT, ausgeschrieben — dieselbe Regel wie bei den Grants und bei
/// `check_trust_registry_defect_sites`. Zwei dieser Vektoren messen denselben
/// Code `EA-FORMAT-COSE`; der gemessene Code allein waere auch dann gleich,
/// wenn zweimal dieselben Bytes unter zwei Namen laegen. `to_json` verbietet
/// doppelte Namen und doppelte Dateien, aber NICHT doppelte Objektbytes — die
/// Replay-Zeile dieser Familie lebt genau davon. Der Ort trennt sie.
const RECEIPT_REJECTED_VECTORS: [(&str, ReceiptDefectSite); 4] = [
    (
        "receipt/rejected-duplicate-grant-hashes",
        ReceiptDefectSite::Elsewhere,
    ),
    (
        "receipt/rejected-flipped-accepted-at-server",
        ReceiptDefectSite::AcceptedAtServer,
    ),
    (
        "receipt/rejected-flipped-signed-receipt-digest",
        ReceiptDefectSite::SignedReceiptDigest,
    ),
    (
        "receipt/rejected-unsorted-grant-hashes",
        ReceiptDefectSite::Elsewhere,
    ),
];

/// Der Ort, an dem ein Receipt-Negativvektor sein Byte kippt.
///
/// `Elsewhere` steht fuer die beiden Vektoren, deren Fehlercode sie bereits
/// eindeutig macht: `EA-FORMAT-UNSORTED` und `EA-FORMAT-DUPLICATE` koennen
/// nicht von demselben Objekt stammen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiptDefectSite {
    AcceptedAtServer,
    SignedReceiptDigest,
    Elsewhere,
}

/// Die Receipt-Familie, vollstaendig ausgefuehrt.
fn check_receipt_vectors(entries: &[VectorEntry]) -> BTreeSet<String> {
    let mut executed = BTreeSet::new();

    let accepted = entry(entries, "receipt/accepted-with-evidence-due");
    let without_due = entry(entries, "receipt/accepted-without-evidence-due");
    for vector in [accepted, without_due] {
        executed.insert(check_accepted_receipt(vector));
    }

    // Der Replay. Die eingefrorene Aussage aus Abnahmekriterium 50 ist die
    // BYTEGLEICHHEIT: ein Replay aendert weder Zeit noch Bytes.
    let replay = entry(entries, "receipt/replay-of-accepted-with-evidence-due");
    assert_eq!(
        replay.object_bytes, accepted.object_bytes,
        "a replay must not change a single byte"
    );
    assert_eq!(
        replay.intermediate_digests, accepted.intermediate_digests,
        "a replay must not change the receipt digest"
    );
    let note = replay
        .scope_note
        .as_deref()
        .expect("the replay vector must say what it freezes");
    assert!(
        note.contains("Replay"),
        "the replay vector must name the replay rule: {note}"
    );
    assert_eq!(
        receipt_facts(&accepted.object_bytes),
        receipt_facts(&replay.object_bytes),
        "a replay must change neither the times nor the server signature"
    );
    executed.insert(replay.name.clone());

    let accepted_receipt_digest = receipt_digest(
        match &decode_exact_object(&accepted.object_bytes).expect("the accepted receipt must parse")
        {
            ParsedArchiveObject::Receipt(receipt) => receipt.value().core().exact_bytes(),
            _ => panic!("an .esr must parse as a receipt"),
        },
    );
    let accepted_at_server = accepted_at_server_needle(&accepted.object_bytes);
    for (name, site) in RECEIPT_REJECTED_VECTORS {
        let vector = entry(entries, name);
        let error = decode_exact_object(&vector.object_bytes)
            .err()
            .unwrap_or_else(|| panic!("{name} must be rejected"));
        assert_eq!(error.code(), rejection_code(vector));
        let offsets = differing_offsets(&accepted.object_bytes, &vector.object_bytes);
        assert!(
            !offsets.is_empty(),
            "{name} must differ from the accepted receipt"
        );
        let needle: Option<&[u8]> = match site {
            ReceiptDefectSite::AcceptedAtServer => Some(&accepted_at_server),
            ReceiptDefectSite::SignedReceiptDigest => Some(accepted_receipt_digest.as_bytes()),
            ReceiptDefectSite::Elsewhere => None,
        };
        if let Some(needle) = needle {
            assert_eq!(offsets.len(), 1, "{name} must flip exactly one byte");
            let start = unique_offset(&accepted.object_bytes, needle);
            assert!(
                (start..start + needle.len()).contains(&offsets[0]),
                "{name} must flip its byte inside {site:?}"
            );
        }
        executed.insert(vector.name.clone());
    }

    executed
}

/// Eine angenommene Quittung, vollstaendig geprueft.
fn check_accepted_receipt(vector: &VectorEntry) -> String {
    expect_accepted(vector);
    let parsed = decode_exact_object(&vector.object_bytes).expect("an accepted receipt must parse");
    let (exact, hash) = format_parsed_parts(&parsed);
    assert_eq!(exact, vector.object_bytes, "the receipt must round-trip");
    assert_eq!(
        intermediate(vector, "objectHash"),
        hex::encode(hash.as_bytes())
    );
    let receipt = match &parsed {
        ParsedArchiveObject::Receipt(receipt) => receipt.value(),
        _ => panic!("an .esr must parse as a receipt"),
    };
    assert_eq!(
        intermediate(vector, "receiptDigest"),
        hex::encode(receipt_digest(receipt.core().exact_bytes()).as_bytes()),
        "{} must record the digest its server signature covers",
        vector.name
    );
    check_esr_field_positions(receipt);
    vector.name.clone()
}

/// Die CBOR-Kodierung der Annahmezeit, aus dem Objekt selbst gelesen.
///
/// Nicht aus einer Konstante dieses Tests: der Wert kommt vom echten Parser,
/// und die Kodierung wird daneben nachgebaut. Ein Objekt, das seine Zeit anders
/// kodierte, faende `unique_offset` nicht wieder.
fn accepted_at_server_needle(object_bytes: &[u8]) -> Vec<u8> {
    let (accepted_at_server, _, _) = receipt_facts(object_bytes);
    let mut needle = vec![0x1b];
    needle.extend_from_slice(
        &u64::try_from(accepted_at_server)
            .expect("the frozen server time is positive")
            .to_be_bytes(),
    );
    needle
}

/// Annahmezeit, Evidence-Frist und Serversignatur einer Quittung.
fn receipt_facts(bytes: &[u8]) -> (i64, Option<i64>, Vec<u8>) {
    let parsed = decode_exact_object(bytes).expect("an accepted receipt must parse");
    match &parsed {
        ParsedArchiveObject::Receipt(receipt) => {
            let fields = receipt.value().core().fields();
            (
                fields.accepted_at_server.get(),
                fields.evidence_due_at.map(UnixMillis::get),
                receipt.value().server_signature().to_vec(),
            )
        }
        _ => panic!("an .esr must parse as a receipt"),
    }
}

/// Jede Feldposition von `esr-v1`, positionsweise gegen den echten Parser.
fn check_esr_field_positions(receipt: &ReceiptV1) {
    let core = receipt.core().exact_bytes();
    let fields = receipt.core().fields();
    let mut decoder = Decoder::new(core);
    assert_eq!(decoder.array().expect("core array"), Some(17));
    assert_eq!(decoder.u64().expect("version"), 1);
    assert_eq!(
        decoder.bytes().expect("organizationId"),
        fields.organization_id.as_bytes()
    );
    assert_eq!(
        decoder.bytes().expect("chainId"),
        fields.chain_id.as_bytes()
    );
    assert_eq!(
        decoder.u64().expect("chainSequence"),
        fields.chain_sequence.get()
    );
    assert_eq!(
        decoder.bytes().expect("entryHash"),
        fields.entry_hash.as_bytes()
    );
    assert_eq!(
        decoder.bytes().expect("entryObjectHash"),
        fields.entry_object_hash.as_bytes()
    );
    assert_eq!(
        optional_hash(&mut decoder, "previousEntryHash"),
        fields
            .previous_entry_hash
            .map(|hash| hash.as_bytes().to_vec())
    );
    assert_eq!(
        decoder.u64().expect("registryVersion"),
        fields.registry_version.get()
    );
    assert_eq!(
        decoder.bytes().expect("registryHeadHash"),
        fields.registry_head_hash.as_bytes()
    );
    assert_eq!(
        decoder.bytes().expect("policyObjectHash"),
        fields.policy_object_hash.as_bytes()
    );
    assert_eq!(
        decoder.bytes().expect("initialGrantPlanHash"),
        fields.initial_grant_plan_hash.as_bytes()
    );
    let count = decoder
        .array()
        .expect("initialGrantObjectHashes")
        .expect("a definite length array");
    assert_eq!(
        usize::try_from(count).expect("a small count"),
        fields.initial_grant_object_hashes.len()
    );
    for expected in &fields.initial_grant_object_hashes {
        assert_eq!(
            decoder.bytes().expect("initialGrantObjectHash"),
            expected.as_bytes()
        );
    }
    assert_eq!(
        decoder.i64().expect("acceptedAtServer"),
        fields.accepted_at_server.get()
    );
    match fields.evidence_due_at {
        None => {
            assert_eq!(
                decoder.datatype().expect("evidenceDueAt"),
                minicbor::data::Type::Null
            );
            decoder.null().expect("evidenceDueAt");
        }
        Some(value) => assert_eq!(decoder.i64().expect("evidenceDueAt"), value.get()),
    }
    assert_eq!(
        decoder.bytes().expect("serverKeyThumbprint"),
        fields.server_key_thumbprint.as_bytes()
    );
    assert_eq!(
        decoder.bytes().expect("serverCertificateHash"),
        fields.server_certificate_hash.as_bytes()
    );
    assert_eq!(
        decoder.array().expect("extensions"),
        Some(0),
        "esr-v1 reserves an empty extension array"
    );
    assert_eq!(decoder.position(), core.len(), "esr-v1 is a closed shape");
}

// ---------------------------------------------------------------------------
// evidence/v1
// ---------------------------------------------------------------------------

/// Die Zeitstempelvektoren, die die Formatebene ANNIMMT.
const EVIDENCE_ACCEPTED_TIMESTAMPS: [&str; 4] = [
    "timestamp/accepted-bound-token",
    "timestamp/accepted-mismatched-imprint",
    "timestamp/accepted-wrong-request-nonce",
    "timestamp/accepted-wrong-tsa-policy",
];

/// Die Evidence-Familie, vollstaendig ausgefuehrt.
fn check_evidence_vectors(entries: &[VectorEntry]) -> BTreeSet<String> {
    let mut executed = BTreeSet::new();

    let imprint = entry(entries, "imprint/accepted-checkpoint-signature");
    expect_accepted(imprint);
    assert_eq!(
        imprint.object_bytes,
        cose_sign1_ctt_imprint(&array64(&imprint.input_bytes))
            .as_bytes()
            .to_vec(),
        "the frozen imprint must be the RFC 9921 hash of the CBOR encoded signature field"
    );
    executed.insert(imprint.name.clone());

    let bound = entry(entries, "timestamp/accepted-bound-token");
    let bound_fields = evidence_timestamp_fields(&bound.object_bytes);
    for name in EVIDENCE_ACCEPTED_TIMESTAMPS {
        let vector = entry(entries, name);
        expect_accepted(vector);
        let parsed = decode_exact_object(&vector.object_bytes)
            .unwrap_or_else(|_| panic!("{name} must pass the format layer"));
        let (exact, hash) = format_parsed_parts(&parsed);
        assert_eq!(exact, vector.object_bytes, "{name} must round-trip");
        assert_eq!(
            intermediate(vector, "objectHash"),
            hex::encode(hash.as_bytes())
        );
        let (core, cose, fields) = evidence_timestamp_parts(&parsed);
        assert_eq!(core, vector.input_bytes, "{name} must carry its own core");
        let signature = *parse_cose_sign1(&cose, &[])
            .expect("the frozen COSE object parses")
            .signature_bytes();
        let ctt = cose_sign1_ctt_imprint(&signature);
        assert_eq!(
            intermediate(vector, "cttImprint"),
            hex::encode(ctt.as_bytes()),
            "{name} must record the imprint of its own signature"
        );
        // Die ERREICHBARE Bindung: das eingebettete Token gegen das daneben
        // archivierte. Dasselbe, was `ea_verify::evidence::token_is_bound`
        // prueft; das Gate selbst ist von aussen nicht aufrufbar.
        assert_eq!(
            parse_cose_sign1(&cose, &[])
                .expect("the frozen COSE object parses")
                .timestamp_token(),
            Some(fields.rfc3161_response_der.as_slice()),
            "{name} must archive exactly the token it embeds"
        );
        let token_imprint = token_message_imprint(&fields.rfc3161_response_der);
        let policy = token_policy_oid(&fields.rfc3161_response_der);
        match name {
            "timestamp/accepted-bound-token" => {
                assert_eq!(token_imprint, ctt.as_bytes().as_slice());
                assert_eq!(policy, fields.policy_oid_der.as_slice());
                assert_eq!(fields.request_nonce, bound_fields.request_nonce);
            }
            "timestamp/accepted-mismatched-imprint" => {
                assert_ne!(
                    token_imprint,
                    ctt.as_bytes().as_slice(),
                    "the mismatched vector must carry an imprint that is not its signature's"
                );
                assert_eq!(
                    differing_offsets(token_imprint, ctt.as_bytes()).len(),
                    1,
                    "the mismatch must be a single byte"
                );
            }
            "timestamp/accepted-wrong-request-nonce" => {
                assert_eq!(token_imprint, ctt.as_bytes().as_slice());
                assert_ne!(
                    fields.request_nonce, bound_fields.request_nonce,
                    "the nonce vector must carry a different nonce"
                );
            }
            "timestamp/accepted-wrong-tsa-policy" => {
                assert_eq!(token_imprint, ctt.as_bytes().as_slice());
                assert_ne!(
                    policy,
                    fields.policy_oid_der.as_slice(),
                    "the policy vector must contradict its own archived policy"
                );
            }
            other => panic!("{other} is not a declared timestamp vector"),
        }
        if name != "timestamp/accepted-bound-token" {
            let note = vector
                .scope_note
                .as_deref()
                .unwrap_or_else(|| panic!("{name} must state why stage 1 accepts it"));
            assert!(
                note.contains("Stufe-6-Grenze"),
                "{name} must name the stage 6 boundary: {note}"
            );
        }
        executed.insert(vector.name.clone());
    }

    // Der entfernte CTT-Header faellt schon an der Formatebene: die
    // Zeitstempelvariante VERLANGT den Header.
    let removed = entry(entries, "timestamp/rejected-removed-ctt-header");
    let error = decode_exact_object(&removed.object_bytes)
        .expect_err("a timestamp variant without its CTT header must be rejected");
    assert_eq!(error.code(), rejection_code(removed));
    executed.insert(removed.name.clone());

    // Der ersetzte CTT-Header passiert die Formatebene und faellt an der
    // Bindung. Der erwartete Code stammt aus `ea-verify`, nicht aus einem
    // Literal dieses Tests.
    let replaced = entry(entries, "timestamp/rejected-replaced-ctt-header");
    let parsed = decode_exact_object(&replaced.object_bytes)
        .expect("a replaced CTT header still passes the format layer");
    let (_, cose, fields) = evidence_timestamp_parts(&parsed);
    assert_ne!(
        parse_cose_sign1(&cose, &[])
            .expect("the frozen COSE object parses")
            .timestamp_token(),
        Some(fields.rfc3161_response_der.as_slice()),
        "the replaced vector must archive a token other than the one it embeds"
    );
    assert_eq!(
        EvidenceGateErrorV1::TokenNotBound.code(),
        rejection_code(replaced),
        "the frozen code must be the one ea-verify raises"
    );
    executed.insert(replaced.name.clone());

    // Das Renewal bindet die EXAKTEN Bytes des erneuerten Objekts.
    let renewal = entry(entries, "renewal/accepted-bound-token");
    expect_accepted(renewal);
    let parsed =
        decode_exact_object(&renewal.object_bytes).expect("an accepted renewal must parse");
    let (_, hash) = format_parsed_parts(&parsed);
    assert_eq!(
        intermediate(renewal, "objectHash"),
        hex::encode(hash.as_bytes())
    );
    let evidence = match &parsed {
        ParsedArchiveObject::Evidence(evidence) => evidence.value(),
        _ => panic!("an .ecp must parse as evidence"),
    };
    match evidence
        .decoded_payload()
        .expect("an accepted renewal decodes")
    {
        DecodedEvidencePayloadV1::Renewal {
            core,
            exact_cose,
            evidence: fields,
        } => {
            assert_eq!(core.exact_bytes(), renewal.input_bytes.as_slice());
            let input = renewal_input_digest(&bound.object_bytes);
            assert_eq!(
                intermediate(renewal, "renewalInputDigest"),
                hex::encode(input.as_bytes())
            );
            assert_eq!(
                core.fields()
                    .renewal_input_hashes
                    .iter()
                    .map(|hash| hex::encode(hash.as_bytes()))
                    .collect::<Vec<_>>(),
                vec![hex::encode(input.as_bytes())],
                "the renewal must bind the exact bytes of the object it renews"
            );
            let signature = *parse_cose_sign1(&exact_cose, &[])
                .expect("the frozen COSE object parses")
                .signature_bytes();
            assert_eq!(
                intermediate(renewal, "cttImprint"),
                hex::encode(cose_sign1_ctt_imprint(&signature).as_bytes())
            );
            assert_eq!(
                token_message_imprint(&fields.rfc3161_response_der),
                cose_sign1_ctt_imprint(&signature).as_bytes().as_slice()
            );
        }
        _ => panic!("the renewal vector must decode as a renewal"),
    }
    executed.insert(renewal.name.clone());

    executed
}

/// Kern, COSE und Archivfelder eines Zeitstempelobjekts.
fn evidence_timestamp_parts(
    parsed: &ParsedArchiveObject,
) -> (Vec<u8>, Vec<u8>, Rfc3161EvidenceFieldsV1) {
    let evidence = match parsed {
        ParsedArchiveObject::Evidence(evidence) => evidence.value(),
        _ => panic!("an .ecp must parse as evidence"),
    };
    match evidence
        .decoded_payload()
        .expect("an accepted timestamp decodes")
    {
        DecodedEvidencePayloadV1::Timestamp {
            core,
            exact_cose,
            evidence,
        } => (core.exact_bytes().to_vec(), exact_cose, evidence),
        _ => panic!("the vector must decode as a timestamp"),
    }
}

/// Die Archivfelder eines Zeitstempelobjekts.
fn evidence_timestamp_fields(bytes: &[u8]) -> Rfc3161EvidenceFieldsV1 {
    let parsed = decode_exact_object(bytes).expect("an accepted timestamp must parse");
    evidence_timestamp_parts(&parsed).2
}

/// Der `messageImprint`-Hashwert im Zeitstempeltoken.
///
/// Der Versatz kommt aus `ea-testkit` und wird HIER gegen die DER-Umgebung
/// gestellt: ohne diese Pruefung koennte ein verschobener Versatz auf beliebige
/// Bytes zeigen und trotzdem gruen bleiben.
fn token_message_imprint(der: &[u8]) -> &[u8] {
    const SHA256_IMPRINT_PREFIX: [u8; 15] = [
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
    ];
    let start = EVIDENCE_TOKEN_MESSAGE_IMPRINT_OFFSET;
    assert_eq!(
        &der[start - SHA256_IMPRINT_PREFIX.len()..start],
        SHA256_IMPRINT_PREFIX.as_slice(),
        "the frozen offset must sit behind the SHA-256 message imprint header"
    );
    &der[start..start + 32]
}

/// Die TSA-Policy-OID im Zeitstempeltoken.
fn token_policy_oid(der: &[u8]) -> &[u8] {
    let start = EVIDENCE_TOKEN_POLICY_OID_OFFSET;
    let slice = &der[start..start + EVIDENCE_TOKEN_POLICY_OID_LENGTH];
    assert_eq!(slice[0], 0x06, "the frozen offset must sit on an OID");
    assert_eq!(
        usize::from(slice[1]),
        EVIDENCE_TOKEN_POLICY_OID_LENGTH - 2,
        "the policy OID keeps its length"
    );
    slice
}

// ---------------------------------------------------------------------------
// Die `policy-core-v1`-Positivvektoren der Familie `trust/v1`
// ---------------------------------------------------------------------------

/// Die Position von `reader-trust-refresh-ms` im geschlossenen
/// `policy-core-v1`-Array, nullbasiert.
///
/// `schemas/archive/v1/trust.cddl` setzt das Feld unmittelbar hinter
/// `reader-inactivity-ms`. Der Wert steht hier als Zahl, damit ein
/// eingeschobenes Feld auffaellt statt still durchzulaufen.
const POLICY_READER_TRUST_REFRESH_POSITION: usize = 10;

/// Die Zahl der Positionen im geschlossenen `policy-core-v1`-Array.
const POLICY_CORE_POSITIONS: u64 = 22;

/// Die beiden Positivvektoren und der Wert, den sie belegen.
const POLICY_CORE_VECTORS: [(&str, u64); 2] = [
    (
        "object/accepted-policy-core-reader-trust-refresh-disabled/policy",
        0,
    ),
    (
        "object/accepted-policy-core-reader-trust-refresh-set/policy",
        86_400_000,
    ),
];

#[test]
fn policy_core_v1_positive_vectors_pin_the_device_side_trust_refresh_deadline() {
    let root = workspace_root();
    let text = fs::read_to_string(root.join(TRUST_MANIFEST_PATH))
        .unwrap_or_else(|error| panic!("failed to read {TRUST_MANIFEST_PATH}: {error}"));
    let manifest = VectorManifest::from_json(&text)
        .unwrap_or_else(|error| panic!("failed to parse {TRUST_MANIFEST_PATH}: {error}"));

    let mut measured = BTreeSet::new();
    for (name, expected) in POLICY_CORE_VECTORS {
        let vector = entry(&manifest.entries, name);
        expect_accepted(vector);
        assert_eq!(vector.schema_id, TRUST_OBJECT_SCHEMA_ID);
        let note = vector
            .scope_note
            .as_deref()
            .unwrap_or_else(|| panic!("{name} must name the normative source of its deadline"));
        assert!(
            note.contains("12.3"),
            "{name} must point at design.md §12.3: {note}"
        );

        let parsed = decode_exact_object(&vector.object_bytes).expect("a policy vector must parse");
        let (exact, hash) = format_parsed_parts(&parsed);
        assert_eq!(exact, vector.object_bytes, "{name} must round-trip");
        assert_eq!(
            intermediate(vector, "objectHash"),
            hex::encode(hash.as_bytes())
        );
        let trust = match &parsed {
            ParsedArchiveObject::Trust(trust) => trust.value(),
            _ => panic!("an .etb must parse as a trust object"),
        };
        let core = match trust
            .decoded_payload()
            .expect("a policy vector decodes as a policy")
        {
            DecodedTrustPayloadV1::Policy(core) => core,
            _ => panic!("{name} must decode as a policy"),
        };
        assert_eq!(
            core.fields().reader_trust_refresh_ms,
            expected,
            "{name} must carry the value its name announces"
        );

        // Die POSITION, unabhaengig vom Feldnamen nachgerechnet.
        let mut decoder = Decoder::new(core.exact_core());
        assert_eq!(
            decoder.array().expect("policy core array"),
            Some(POLICY_CORE_POSITIONS),
            "policy-core-v1 is a closed array of {POLICY_CORE_POSITIONS} positions"
        );
        for _ in 0..POLICY_READER_TRUST_REFRESH_POSITION {
            decoder.skip().expect("a policy core position");
        }
        assert_eq!(
            decoder.u64().expect("readerTrustRefreshMs"),
            expected,
            "{name} must carry the deadline at position \
             {POLICY_READER_TRUST_REFRESH_POSITION}"
        );
        assert_eq!(
            decoder.bool().expect("readerHistoryAccessAllowed"),
            core.fields().reader_history_access_allowed,
            "the position after the deadline is readerHistoryAccessAllowed"
        );
        measured.insert(expected);
    }
    assert_eq!(
        measured,
        BTreeSet::from([0, 86_400_000]),
        "the two positive vectors must cover a set and an unset deadline"
    );
}
