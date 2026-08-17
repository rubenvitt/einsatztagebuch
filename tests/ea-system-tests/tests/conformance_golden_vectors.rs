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

use std::{collections::BTreeSet, fs};

use ea_crypto::{
    AEAD_NONCE_SIZE, CEK_SIZE, CanonicalPublicCoseKey, ContentType, GRANT_SUITE_ID, HPKE_AEAD_ID,
    HPKE_ENCAPSULATED_KEY_SIZE, HPKE_KDF_ID, HPKE_KEM_ID, HPKE_MODE, HPKE_WRAPPED_CEK_SIZE,
    HpkeRecipientPrivateKey, HpkeSealed, ProtectedHeader, SUITE_ID, SecretBytes, SecretVec,
    aead_open, aead_seal, authorized_trust_digest, bootstrap_anchor_hash, ciphertext_digest,
    entry_hash, grant_digest, grant_plan_digest, hpke_aad, hpke_info, hpke_open,
    linux_os_account_binding_hash, object_hash, operator_profile_digest, payload_aad,
    receipt_digest, record_digest, recovery_test_digest, renewal_input_digest, trust_anchor_hash,
    trust_digest, validate_unsigned_protocol_core, verification_report_hash,
};
use ea_format::{ParsedArchiveObject, decode_exact_object};
use ea_schema::{CommonHeaderV1, NativeSourceV1, OperatorSnapshotV1, SchemaRegistry};
use ea_system_tests::workspace_root;
use ea_testkit::{
    ED25519_RFC8032_TEST1_SEED, ED25519_RFC8032_TEST2_SEED, ExpectedOutcome,
    TEST_ENTROPY_AEAD_NONCE, TEST_ENTROPY_CONTENT_ENCRYPTION_KEY,
    TEST_ENTROPY_RECIPIENT_X25519_SEED, VectorEntry, VectorManifest, VectorSource,
    X25519_RFC7748_BOB_PRIVATE_KEY, X25519_RFC7748_BOB_PUBLIC_KEY, sha256_hex, verify_manifest_at,
};
use ea_types::{
    CertificateHash, DeviceId, Hash32, Id16, KeyThumbprint, ObjectHash, OperatorSubjectId,
    OrganizationId, RecordId, RegistryVersion, UnixMillis,
};
use ed25519_dalek::{Signer, SigningKey};

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
