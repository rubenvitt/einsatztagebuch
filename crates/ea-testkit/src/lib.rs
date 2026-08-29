#![forbid(unsafe_code)]
//! Deterministische Testentropie, veroeffentlichte KAT-Schluessel und die
//! Manifest-Emission fuer die eingefrorenen Vektoren des Einsatzarchivs.
//!
//! Diese Crate ist ADDITIV. Sie loest die bestehende `#[path]`-Support-Kette
//! NICHT ab: `crates/ea-recovery/tests/support/mod.rs` haelt fest, dass
//! `ea-verify` den Support von `ea-archive` einbindet, dieser den von
//! `ea-trust` und `ea-format`, und dass genau diese Kette so gewollt ist. Hier
//! entsteht kein Ersatz, sondern die zweite, unabhaengige Aufgabe: Bytes, die
//! auf die Platte gehen und dort dauerhaft liegen bleiben.
//!
//! # Kein geteilter Browsercode
//!
//! Diese Crate besitzt die Datei- und Manifest-Emission ueber `std::fs` und
//! ist damit hostseitiger Generatorcode. Nach
//! `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §9
//! ist ausschliesslich die Verifikationspipeline geteilter Rust-Code, und die
//! endet bei `ea-verify`. `ea-testkit` steht deshalb auf der begruendeten
//! Ausnahmeliste `WASM32_EXEMPT_CRATES` in `tools/xtask/src/main.rs`, nicht auf
//! der wasm32-Positivliste.
//!
//! # Zwei Sorten Vektoren, und sie sind nicht austauschbar
//!
//! DETERMINISTISCH REGENERIERBAR ist alles, dessen Erzeugung ihre Entropie als
//! Parameter entgegennimmt: `aead_seal` nimmt die Nonce explizit
//! (`crates/ea-crypto/src/aead.rs`), `CoseSigner` baut aus festen
//! Schluesselbytes (`crates/ea-crypto/src/cose.rs`), und Ed25519 signiert
//! deterministisch. Fuer solche Familien darf ein spaeterer Lauf die Bytes neu
//! erzeugen und gegen das Manifest stellen.
//!
//! NICHT REGENERIERBAR ist jedes Objekt, das einen Kapselungswert oder einen
//! umschlossenen CEK traegt. `hpke_seal` (`crates/ea-crypto/src/hpke.rs`) zieht
//! bei jedem Aufruf einen frischen ephemeren Schluessel aus dem
//! Betriebssystem; der einzige Injektionspunkt ist privat und durch einen
//! absichtlichen `compile_fail`-Doctest gegen Veroeffentlichung gesichert. Die
//! ea-crypto-API wird dafuer NICHT aufgeweitet. Solche Bytes werden EINMAL
//! erzeugt, eingefroren und ausschliesslich in der entkapselnden Richtung ueber
//! `hpke_open` nachgeprueft. [`VectorSource::FrozenOnce`] haelt genau das im
//! Manifest fest, damit ein spaeterer Leser die Richtung nicht raten muss.
//!
//! # Umfang dieser Stufe
//!
//! Aufgebaut sind hier das Schluesselmaterial, das Manifestformat mit seinen
//! neun Pflichtangaben je Eintrag, die Emission und der Re-Hash-Verifizierer.
//! Die familienweisen Erzeuger entstehen mit ihren Vektoren zusammen, weil erst
//! dort entschieden ist, welche der beiden Sorten die jeweilige Familie ist.
//!
//! # Was die Objektfamilie `format/v1` NICHT belegt
//!
//! Drei Zusagen aus `design.md` §22.1 und §23 lassen sich auf der Formatebene
//! nicht einloesen, und keine davon wird hier stillschweigend behauptet.
//!
//! SIDECARS gibt es im Archiv nicht. Abnahmekriterium 4 nennt sie, doch weder
//! `crates/ea-archive/src/layout.rs` noch irgendein Quelltext des Workspace
//! kennt den Begriff — gemessen mit einer Volltextsuche ueber `crates`, `apps`,
//! `tools` und `tests`. Die Objekte, die einen `.eip` im Archiv begleiten, sind
//! `.eag`, `.esr` und `.eds`; ihre Mutationsvektoren stehen unter genau diesen
//! Namen. Ein eigener `sidecar/`-Vektor waere ein erfundener Beleg.
//!
//! Eine Kippung in den 64 SIGNATURBYTES einer COSE-Struktur wird von
//! `ea_format::decode_exact_object` ANGENOMMEN: die Formatebene prueft die
//! Bindung von Inhaltstyp, Zertifikatshash und Nutzinhalt, nicht die
//! Ed25519-Rechnung. Diese Familie mutiert deshalb den Nutzinhalt; die
//! Signaturpruefung selbst gehoert zu `ea-verify`.
//!
//! `EA-FORMAT-TAG-MISMATCH` ist ueber `decode_exact_object` unerreichbar.
//! `preflight` liest den Objekttyp aus Byte 6, und `validate_outer` stellt
//! genau dieses Byte gegen sich selbst; die beiden koennen nicht auseinander
//! laufen. Ein vertauschtes Tag schickt den Rumpf in den Parser einer fremden
//! Familie, und was von dort zurueckkommt, steht gemessen im Manifest.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::{Component, Path, PathBuf},
};

use ea_crypto::{
    CanonicalPublicCoseKey, ContentType, CoseSigner, HPKE_ENCAPSULATED_KEY_SIZE,
    HPKE_WRAPPED_CEK_SIZE, HpkeRecipientPrivateKey, ProtectedHeader, SecretBytes, SecretVec,
    UnverifiedRfc3161TimeStampToken, aead_seal, attach_rfc3161_ctt, authorized_trust_digest,
    bootstrap_anchor_hash, cose_sign1_ctt_imprint, grant_digest, hpke_aad, hpke_info, object_hash,
    parse_cose_sign1, payload_aad, receipt_digest, record_digest, renewal_input_digest,
    trust_anchor_hash, trust_digest,
};
use ea_format::{
    AdminRootContextV1, ArchiveProfileMigrationContextV1, BindingLifecycleContextV1,
    CertificateKindV1, CheckpointCoreFieldsV1, CheckpointCoreV1, ClockReleaseContextV1,
    ClockReleaseJustificationV1, DestroyedEntryStubV1, DestructionContextV1,
    DeviceCertificateFieldsV1, EntryPackageV1, EvidenceObjectV1, ExportContextV1,
    FreeTextPolicyFieldsV1, GenericAuditContextV1, GrantBodyFieldsV1, GrantBodyV1, GrantKindV1,
    GrantPlanItemV1, GrantPlanV1, GrantPurposeV1, GrantV1, HistoricalRegrantContextV1,
    IndependentTimeKindV1, IndependentTimeReferenceV1, KeyProtectionProfileV1, LocalAuditActionV1,
    LocalAuditEventCoreFieldsV1, LocalAuditOutcomeV1, ManifestCoreFieldsV1, ManifestCoreV1,
    OperatorBindingFieldsV1, OperatorRoleV1, OrganizationAdminAuthorizationFieldsV1,
    PolicyFieldsV1, ReceiptCoreFieldsV1, ReceiptCoreV1, ReceiptV1, RegistryChangeV1,
    RegistryEventFieldsV1, RenewalCoreFieldsV1, RenewalCoreV1, RetentionPolicyFieldsV1,
    Rfc3161EvidenceFieldsV1, RootCertificateFieldsV1, SignedManifestV1, StaleRegistryContextV1,
    TrustObjectV1, TrustPayloadV1, TrustSubtypeV1, WebBundleReleaseCoreV1,
    WebBundleRevocationCoreV1, encode_destroyed_entry_stub, encode_entry_package, encode_evidence,
    encode_grant, encode_local_audit_core, encode_local_audit_event, encode_receipt, encode_trust,
};
use ea_types::{
    AuthorizationId, CertificateHash, ChainId, ChainSequence, DestructionId, DeviceId, EntryHash,
    EventId, Hash32, KeyThumbprint, ObjectHash, OperatorSubjectId, OrganizationId, RegistryVersion,
    SubjectId, UnixMillis,
};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Schluesselmaterial
// ---------------------------------------------------------------------------

/// Ed25519-Seed aus RFC 8032 §7.1, TEST 1.
///
/// Veroeffentlichter Known-Answer-Test. Der zugehoerige oeffentliche
/// Schluessel steht in [`ED25519_RFC8032_TEST1_PUBLIC_KEY`]; beide werden im
/// Test dieser Crate gegeneinander nachgerechnet.
pub const ED25519_RFC8032_TEST1_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// Ed25519-Public-Key aus RFC 8032 §7.1, TEST 1.
pub const ED25519_RFC8032_TEST1_PUBLIC_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

/// Ed25519-Seed aus RFC 8032 §7.1, TEST 2.
pub const ED25519_RFC8032_TEST2_SEED: [u8; 32] = [
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
];

/// Ed25519-Public-Key aus RFC 8032 §7.1, TEST 2.
pub const ED25519_RFC8032_TEST2_PUBLIC_KEY: [u8; 32] = [
    0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
    0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
];

/// X25519-Privatschluessel aus RFC 7748 §6.1, Seite Alice.
pub const X25519_RFC7748_ALICE_PRIVATE_KEY: [u8; 32] = [
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
    0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
];

/// X25519-Public-Key aus RFC 7748 §6.1, Seite Alice.
pub const X25519_RFC7748_ALICE_PUBLIC_KEY: [u8; 32] = [
    0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
    0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
];

/// X25519-Privatschluessel aus RFC 7748 §6.1, Seite Bob.
pub const X25519_RFC7748_BOB_PRIVATE_KEY: [u8; 32] = [
    0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
    0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
];

/// X25519-Public-Key aus RFC 7748 §6.1, Seite Bob.
pub const X25519_RFC7748_BOB_PUBLIC_KEY: [u8; 32] = [
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
    0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
];

/// Gemeinsames Geheimnis aus RFC 7748 §6.1.
pub const X25519_RFC7748_SHARED_SECRET: [u8; 32] = [
    0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
    0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
];

// AUSDRUECKLICH DEKLARIERTE TESTENTROPIE. Die folgenden Konstanten stammen aus
// KEINEM Standard. Es sind willkuerlich gewaehlte, konstante Bytefolgen, und sie
// sind ausschliesslich Testmaterial. Jede traegt ein eigenes Fuellbyte, damit
// eine Verwechslung im Vektormaterial sofort sichtbar wird statt still
// durchzulaufen; `declared_test_entropy_is_pairwise_distinct` misst das.

/// Deklarierte Testentropie fuer den Root-Signaturschluessel.
pub const TEST_ENTROPY_ROOT_ED25519_SEED: [u8; 32] = [0xa0; 32];

/// Ausdruecklich deklarierte Testentropie fuer den Organisationsadministrator.
pub const TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED: [u8; 32] = [0xa1; 32];

/// Ausdruecklich deklarierte Testentropie fuer einen Geraeteschluessel.
pub const TEST_ENTROPY_DEVICE_ED25519_SEED: [u8; 32] = [0xa2; 32];

/// Ausdruecklich deklarierte Testentropie fuer den ZWEITEN
/// Organisationsadministrator.
///
/// Die Anchor-Vorstufe verlangt mindestens zwei Administratorpaare mit
/// verschiedenen Signaturschluesseln und verschiedenen Subjekten
/// (`crates/ea-trust/src/anchor.rs`), also braucht die Trust-Familie ein
/// zweites Schluesselpaar.
pub const TEST_ENTROPY_SECOND_ORGANIZATION_ADMIN_ED25519_SEED: [u8; 32] = [0xa3; 32];

/// Ausdruecklich deklarierte Testentropie fuer einen nachtraeglich
/// ausgestellten Organisationsadministrator.
pub const TEST_ENTROPY_ROTATED_ORGANIZATION_ADMIN_ED25519_SEED: [u8; 32] = [0xa4; 32];

/// Ausdruecklich deklarierte Testentropie fuer einen Empfaengerschluessel.
pub const TEST_ENTROPY_RECIPIENT_X25519_SEED: [u8; 32] = [0xb0; 32];

/// Ausdruecklich deklarierte Testentropie fuer einen Inhaltsschluessel.
pub const TEST_ENTROPY_CONTENT_ENCRYPTION_KEY: [u8; 32] = [0xc0; 32];

/// Ausdruecklich deklarierte Testentropie fuer eine AEAD-Nonce.
pub const TEST_ENTROPY_AEAD_NONCE: [u8; 12] = [0xd0; 12];

/// Alle deklarierten Testentropie-Konstanten mit ihrem Namen.
///
/// Der Selbsttest dieser Crate stellt darueber sicher, dass keine zwei Rollen
/// dasselbe Material tragen.
pub const DECLARED_TEST_ENTROPY: [(&str, &[u8]); 8] = [
    ("root-ed25519-seed", &TEST_ENTROPY_ROOT_ED25519_SEED),
    (
        "organization-admin-ed25519-seed",
        &TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED,
    ),
    (
        "second-organization-admin-ed25519-seed",
        &TEST_ENTROPY_SECOND_ORGANIZATION_ADMIN_ED25519_SEED,
    ),
    (
        "rotated-organization-admin-ed25519-seed",
        &TEST_ENTROPY_ROTATED_ORGANIZATION_ADMIN_ED25519_SEED,
    ),
    ("device-ed25519-seed", &TEST_ENTROPY_DEVICE_ED25519_SEED),
    ("recipient-x25519-seed", &TEST_ENTROPY_RECIPIENT_X25519_SEED),
    (
        "content-encryption-key",
        &TEST_ENTROPY_CONTENT_ENCRYPTION_KEY,
    ),
    ("aead-nonce", &TEST_ENTROPY_AEAD_NONCE),
];

/// Sucht eine Bytefolge in einer Bytefolge. Kein Kanary-Treffer heisst: nicht
/// enthalten.
///
/// Ein LEERER Kanarienvogel meldet `false` und nicht `true`: die leere Folge
/// steckt in jeder Folge, und ein Aufrufer, der versehentlich nichts uebergibt,
/// bekaeme sonst von jeder Zusicherung „enthalten" — und von jeder
/// negierten Zusicherung ein stillschweigendes Bestehen.
#[must_use]
pub fn contains_canary(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// SHA-256 ueber `bytes`, hexadezimal in Kleinbuchstaben.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Der oeffentliche Ed25519-Schluessel zu einem deklarierten Seed.
///
/// Die Ableitung steht hier, weil sie im Bestand an vier Stellen gebraucht
/// wird und vier Kopien vier Gelegenheiten waeren, sie verschieden zu machen.
#[must_use]
pub fn ed25519_public_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Eine ROHE Ed25519-Signatur ueber `message`.
///
/// Die Testhaelfte zu [`ea_crypto::CanonicalPublicCoseKey::verify_ed25519_strict`]
/// — und ausdruecklich KEIN Weg, im Bestand ohne Domaenenkonstante zu
/// signieren: die einzige Nachricht ohne eigene Domaene ist die WebAuthn-
/// Assertion, deren Domaenentrennung `authenticatorData` selbst traegt
/// (`rpIdHash`). Diese Crate ist eine Testhilfe und wird von keinem
/// Auslieferungsziel gezogen.
#[must_use]
pub fn ed25519_sign_raw(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(message).to_bytes()
}

// ---------------------------------------------------------------------------
// Manifestmodell
// ---------------------------------------------------------------------------

/// Herkunft eines Vektors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VectorSource {
    /// Aus einem veroeffentlichten Standard uebernommen, etwa `RFC 8032 §7.1`.
    Standard(String),
    /// Von einem Erzeuger dieser Crate deterministisch erzeugt; der Wert nennt
    /// den Commit des Erzeugers.
    GeneratorCommit(String),
    /// Einmalig erzeugt und danach eingefroren, weil die erzeugende Richtung
    /// frische Entropie zieht. Der Wert benennt die deterministische
    /// Gegenrichtung, in der die Nachpruefung stattfindet, etwa `hpke_open`.
    FrozenOnce { verified_via: String },
}

impl VectorSource {
    fn to_value(&self) -> Value {
        let mut map = BTreeMap::new();
        match self {
            Self::Standard(standard) => {
                map.insert("kind".into(), Value::String("standard".into()));
                map.insert("standard".into(), Value::String(standard.clone()));
            }
            Self::GeneratorCommit(commit) => {
                map.insert("kind".into(), Value::String("generatorCommit".into()));
                map.insert("commit".into(), Value::String(commit.clone()));
            }
            Self::FrozenOnce { verified_via } => {
                map.insert("kind".into(), Value::String("frozenOnce".into()));
                map.insert("verifiedVia".into(), Value::String(verified_via.clone()));
            }
        }
        sorted_object(map)
    }

    fn from_value(value: &Value) -> Result<Self, TestkitError> {
        let kind = string_field(value, "kind")?;
        match kind.as_str() {
            "standard" => Ok(Self::Standard(string_field(value, "standard")?)),
            "generatorCommit" => Ok(Self::GeneratorCommit(string_field(value, "commit")?)),
            "frozenOnce" => Ok(Self::FrozenOnce {
                verified_via: string_field(value, "verifiedVia")?,
            }),
            other => Err(TestkitError::Malformed(format!(
                "unknown vector source kind {other}"
            ))),
        }
    }
}

/// Erwartetes Ergebnis der Pruefung eines Vektors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedOutcome {
    /// Der Vektor MUSS angenommen werden.
    Accepted,
    /// Der Vektor MUSS mit genau diesem Fehlercode abgelehnt werden.
    Rejected { error_code: String },
}

impl ExpectedOutcome {
    fn to_value(&self) -> Value {
        let mut map = BTreeMap::new();
        match self {
            Self::Accepted => {
                map.insert("kind".into(), Value::String("accepted".into()));
            }
            Self::Rejected { error_code } => {
                map.insert("kind".into(), Value::String("rejected".into()));
                map.insert("errorCode".into(), Value::String(error_code.clone()));
            }
        }
        sorted_object(map)
    }

    fn from_value(value: &Value) -> Result<Self, TestkitError> {
        let kind = string_field(value, "kind")?;
        match kind.as_str() {
            "accepted" => Ok(Self::Accepted),
            "rejected" => Ok(Self::Rejected {
                error_code: string_field(value, "errorCode")?,
            }),
            other => Err(TestkitError::Malformed(format!(
                "unknown expected outcome kind {other}"
            ))),
        }
    }
}

/// Ein Manifesteintrag mit allen neun Pflichtangaben.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorEntry {
    /// Eindeutiger Name innerhalb der Familie; zugleich die Sortierschluessel.
    pub name: String,
    /// Schema-Identifikator des Objekts, etwa `eag-v1`.
    pub schema_id: String,
    /// Suite-Identifikator, etwa `suite-1`.
    pub suite_id: String,
    /// Herkunft.
    pub source: VectorSource,
    /// Exakte Eingabebytes des Erzeugers.
    pub input_bytes: Vec<u8>,
    /// Erwartete Zwischen-Digests, benannt und sortiert.
    pub intermediate_digests: BTreeMap<String, [u8; 32]>,
    /// Exakte Objektbytes; identisch mit dem Inhalt der Datei.
    pub object_bytes: Vec<u8>,
    /// Erwarteter Annahme- oder Fehlercode.
    pub expected_outcome: ExpectedOutcome,
    /// Pfad der Datei, relativ zur Manifestwurzel.
    pub file: String,
    /// Was dieser Vektor ausdruecklich NICHT belegt.
    ///
    /// Ein Vektor beweist genau das, was seine Pipeline rechnet. Wo ein Leser
    /// naheliegend mehr hineinlesen wuerde, haelt diese Notiz die Grenze fest.
    ///
    /// FEHLT DER SCHLUESSEL IM MANIFEST, wenn kein Vermerk vorliegt. `null` zu
    /// schreiben waere eine Aenderung an JEDEM bereits eingefrorenen Manifest,
    /// und eingefrorene Bytes bleiben, was sie sind.
    pub scope_note: Option<String>,
}

impl VectorEntry {
    /// SHA-256 der Objektbytes, hexadezimal in Kleinbuchstaben.
    #[must_use]
    pub fn file_sha256(&self) -> String {
        sha256_hex(&self.object_bytes)
    }

    fn to_value(&self) -> Value {
        let mut digests = BTreeMap::new();
        for (name, digest) in &self.intermediate_digests {
            digests.insert(name.clone(), Value::String(hex::encode(digest)));
        }
        let mut map = BTreeMap::new();
        map.insert("name".into(), Value::String(self.name.clone()));
        map.insert("schemaId".into(), Value::String(self.schema_id.clone()));
        map.insert("suiteId".into(), Value::String(self.suite_id.clone()));
        map.insert("source".into(), self.source.to_value());
        map.insert(
            "inputBytes".into(),
            Value::String(hex::encode(&self.input_bytes)),
        );
        map.insert("intermediateDigests".into(), sorted_object(digests));
        map.insert(
            "objectBytes".into(),
            Value::String(hex::encode(&self.object_bytes)),
        );
        map.insert("expectedOutcome".into(), self.expected_outcome.to_value());
        map.insert("file".into(), Value::String(self.file.clone()));
        map.insert("fileSha256".into(), Value::String(self.file_sha256()));
        if let Some(scope_note) = &self.scope_note {
            map.insert("scopeNote".into(), Value::String(scope_note.clone()));
        }
        sorted_object(map)
    }

    fn from_value(value: &Value) -> Result<Self, TestkitError> {
        let mut intermediate_digests = BTreeMap::new();
        let digests = value
            .get("intermediateDigests")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                TestkitError::Malformed("intermediateDigests must be an object".into())
            })?;
        for (name, digest) in digests {
            let bytes = decode_hex(digest.as_str().ok_or_else(|| {
                TestkitError::Malformed(format!("intermediate digest {name} must be a hex string"))
            })?)?;
            let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                TestkitError::Malformed(format!("intermediate digest {name} must be 32 bytes"))
            })?;
            intermediate_digests.insert(name.clone(), bytes);
        }
        let entry = Self {
            name: string_field(value, "name")?,
            schema_id: string_field(value, "schemaId")?,
            suite_id: string_field(value, "suiteId")?,
            source: VectorSource::from_value(
                value
                    .get("source")
                    .ok_or_else(|| TestkitError::Malformed("entry misses source".into()))?,
            )?,
            input_bytes: decode_hex(&string_field(value, "inputBytes")?)?,
            intermediate_digests,
            object_bytes: decode_hex(&string_field(value, "objectBytes")?)?,
            expected_outcome: ExpectedOutcome::from_value(
                value.get("expectedOutcome").ok_or_else(|| {
                    TestkitError::Malformed("entry misses expectedOutcome".into())
                })?,
            )?,
            file: string_field(value, "file")?,
            scope_note: match value.get("scopeNote") {
                None => None,
                Some(note) => Some(
                    note.as_str()
                        .ok_or_else(|| {
                            TestkitError::Malformed("scopeNote must be a string".into())
                        })?
                        .to_owned(),
                ),
            },
        };
        let recorded = string_field(value, "fileSha256")?;
        if recorded != entry.file_sha256() {
            return Err(TestkitError::Malformed(format!(
                "entry {} records a fileSha256 that does not hash its own objectBytes",
                entry.name
            )));
        }
        Ok(entry)
    }
}

/// Ein Vektormanifest: eine Familie, eine Version, sortierte Eintraege.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorManifest {
    /// Familienname, etwa `crypto` oder `grants`.
    pub family: String,
    /// Versionsordner der Familie, etwa `v1` oder `suite-1`.
    pub version: String,
    /// Eintraege. [`VectorManifest::to_json`] sortiert sie nach Namen.
    pub entries: Vec<VectorEntry>,
}

/// Der Dateiname des Manifests innerhalb einer Vektorwurzel.
pub const MANIFEST_FILE_NAME: &str = "manifest.json";

impl VectorManifest {
    /// Serialisiert das Manifest deterministisch.
    ///
    /// Die Eintraege werden nach Namen sortiert, Objektschluessel stehen
    /// alphabetisch, und die Ausgabe endet auf genau einem Zeilenumbruch.
    ///
    /// # Errors
    ///
    /// [`TestkitError::DuplicateEntry`] bei doppeltem Eintragsnamen,
    /// [`TestkitError::UnsafePath`] bei einem Dateipfad, der die Wurzel
    /// verlassen koennte.
    pub fn to_json(&self) -> Result<String, TestkitError> {
        let mut seen_names = BTreeSet::new();
        let mut seen_files = BTreeSet::new();
        for entry in &self.entries {
            if !seen_names.insert(entry.name.as_str()) {
                return Err(TestkitError::DuplicateEntry(entry.name.clone()));
            }
            check_relative_path(&entry.file)?;
            if !seen_files.insert(entry.file.as_str()) {
                return Err(TestkitError::DuplicateEntry(entry.file.clone()));
            }
        }
        let mut sorted = self.entries.clone();
        sorted.sort_by(|left, right| left.name.cmp(&right.name));
        let entries = sorted.iter().map(VectorEntry::to_value).collect::<Vec<_>>();
        let mut map = BTreeMap::new();
        map.insert("entries".into(), Value::Array(entries));
        map.insert("family".into(), Value::String(self.family.clone()));
        map.insert("version".into(), Value::String(self.version.clone()));
        let mut text = serde_json::to_string_pretty(&sorted_object(map))
            .map_err(|error| TestkitError::Malformed(error.to_string()))?;
        text.push('\n');
        Ok(text)
    }

    /// Liest ein Manifest aus seiner Textdarstellung.
    ///
    /// # Errors
    ///
    /// [`TestkitError::Malformed`] bei fehlenden oder falsch getypten Feldern.
    pub fn from_json(text: &str) -> Result<Self, TestkitError> {
        let value: Value = serde_json::from_str(text)
            .map_err(|error| TestkitError::Malformed(error.to_string()))?;
        let entries = value
            .get("entries")
            .and_then(Value::as_array)
            .ok_or_else(|| TestkitError::Malformed("entries must be an array".into()))?
            .iter()
            .map(VectorEntry::from_value)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            family: string_field(&value, "family")?,
            version: string_field(&value, "version")?,
            entries,
        })
    }

    /// Schreibt Manifest und Objektdateien unter `root`.
    ///
    /// Vorhandene Dateien werden ueberschrieben; bestehende Verzeichnisse
    /// bleiben erhalten.
    ///
    /// # Errors
    ///
    /// [`TestkitError::Io`] bei Schreibfehlern, sonst die Fehler von
    /// [`VectorManifest::to_json`].
    pub fn emit(&self, root: &Path) -> Result<(), TestkitError> {
        let text = self.to_json()?;
        create_dir(root)?;
        for entry in &self.entries {
            let target = root.join(&entry.file);
            if let Some(parent) = target.parent() {
                create_dir(parent)?;
            }
            write_file(&target, &entry.object_bytes)?;
        }
        write_file(&root.join(MANIFEST_FILE_NAME), text.as_bytes())
    }
}

// ---------------------------------------------------------------------------
// Re-Hash-Verifizierer
// ---------------------------------------------------------------------------

/// Ein einzelner Befund des Re-Hash-Verifizierers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mismatch {
    /// Die im Manifest genannte Datei fehlt.
    MissingFile { entry: String, file: String },
    /// Der SHA-256 der Datei weicht vom Manifestwert ab.
    FileSha256 {
        entry: String,
        expected: String,
        actual: String,
    },
    /// Die Datei enthaelt andere Bytes als das Manifest unter `objectBytes`.
    ObjectBytes { entry: String },
}

impl fmt::Display for Mismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingFile { entry, file } => {
                write!(formatter, "entry {entry} misses its file {file}")
            }
            Self::FileSha256 {
                entry,
                expected,
                actual,
            } => write!(
                formatter,
                "entry {entry} hashes to {actual}, the manifest records {expected}"
            ),
            Self::ObjectBytes { entry } => write!(
                formatter,
                "entry {entry} carries file bytes that differ from its recorded objectBytes"
            ),
        }
    }
}

/// Ergebnis eines Re-Hash-Laufs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    /// Zahl der geprueften Eintraege.
    pub entries_checked: usize,
    /// Alle Befunde, in Eintragsreihenfolge.
    pub mismatches: Vec<Mismatch>,
}

impl VerificationReport {
    /// Wahr, wenn kein Befund vorliegt.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.mismatches.is_empty()
    }
}

/// Prueft ein Manifest gegen die Dateien auf der Platte.
///
/// Ein fehlender oder unlesbarer Manifestpfad ist ein Fehler; eine fehlende
/// oder abweichende Objektdatei ist ein Befund im Bericht, damit ein Lauf alle
/// Abweichungen auf einmal nennt statt nur die erste.
///
/// # Errors
///
/// [`TestkitError::Io`] wenn das Manifest nicht lesbar ist,
/// [`TestkitError::Malformed`] wenn es nicht wohlgeformt ist,
/// [`TestkitError::UnsafePath`] wenn ein Eintrag die Wurzel verliesse.
pub fn verify_manifest_at(root: &Path) -> Result<VerificationReport, TestkitError> {
    let manifest_path = root.join(MANIFEST_FILE_NAME);
    let text = fs::read_to_string(&manifest_path).map_err(|error| TestkitError::Io {
        path: manifest_path.display().to_string(),
        source: error,
    })?;
    let manifest = VectorManifest::from_json(&text)?;
    let mut mismatches = Vec::new();
    for entry in &manifest.entries {
        check_relative_path(&entry.file)?;
        let path = root.join(&entry.file);
        let Ok(bytes) = fs::read(&path) else {
            mismatches.push(Mismatch::MissingFile {
                entry: entry.name.clone(),
                file: entry.file.clone(),
            });
            continue;
        };
        let actual = sha256_hex(&bytes);
        let expected = entry.file_sha256();
        if actual != expected {
            mismatches.push(Mismatch::FileSha256 {
                entry: entry.name.clone(),
                expected,
                actual,
            });
        }
        if bytes != entry.object_bytes {
            mismatches.push(Mismatch::ObjectBytes {
                entry: entry.name.clone(),
            });
        }
    }
    Ok(VerificationReport {
        entries_checked: manifest.entries.len(),
        mismatches,
    })
}

// ---------------------------------------------------------------------------
// Vektorfamilie crypto/suite-1
// ---------------------------------------------------------------------------

/// Der Familienname der Primitivvektoren.
pub const CRYPTO_FAMILY: &str = "crypto";

/// Der Versionsordner der Primitivvektoren.
pub const CRYPTO_SUITE_ONE_VERSION: &str = "suite-1";

/// Die Wurzel der Primitivvektoren, relativ zur Arbeitsbaumwurzel.
pub const CRYPTO_SUITE_ONE_ROOT: &str = "vectors/crypto/suite-1";

/// Die Herkunftsangabe der Vektoren, die kein veroeffentlichter Standard
/// liefert.
///
/// Benannt wird die erzeugende Funktion, nicht ein Commit-Hash: der Hash des
/// Commits, der einen Vektor einfriert, ist zur Erzeugungszeit noch nicht
/// bekannt, und ein nachtraeglich eingetragener Hash waere eine Behauptung
/// statt einer Angabe. `git log -L` auf diese Funktion liefert die Historie
/// vollstaendig.
const CRYPTO_GENERATOR: &str = "ea-testkit::crypto_suite_one_manifest";

/// Der Suite-Identifikator, EINGEFROREN.
///
/// Bewusst ein Literal und keine Uebernahme aus `ea-types`: der Vektor soll
/// dem Quelltext WIDERSPRECHEN koennen. Wuerde er die Konstante importieren,
/// zoege eine Umbenennung den Vektor stillschweigend mit, und die Familie
/// belegte nur noch sich selbst. `ea-system-tests` stellt beide gegeneinander.
const CRYPTO_SUITE_ONE_SUITE_ID: &str = "EINSATZARCHIV-SUITE-1";

/// Der Grant-Suite-Identifikator, aus demselben Grund eingefroren.
const CRYPTO_SUITE_ONE_GRANT_SUITE_ID: &str = "EINSATZARCHIV-HPKE-1";

/// Das feste Urbild aller Domain-Digest-Vektoren.
const CRYPTO_PROBE: &[u8] = b"suite-1 digest probe";

/// Die Organisationskennung der strukturierten Vektoren.
const CRYPTO_ORGANIZATION_ID: [u8; 16] = [0x10; 16];

/// Die Geraetekennung der strukturierten Vektoren.
const CRYPTO_DEVICE_ID: [u8; 16] = [0x11; 16];

/// Die 24 Domain-Trennungszeichenketten von `crates/ea-crypto`.
///
/// Abgeleitet aus dem Quelltext, nicht aus dem Gedaechtnis:
/// `crates/ea-crypto/src/digest.rs` fuehrt siebzehn Hashdomaenen und drei
/// Praefixfunktionen, `os_account.rs` eine Bindungsdomaene und `cose.rs` die
/// beiden Typzeichenketten der signierten Protokollkerne.
/// `tests/ea-system-tests/tests/conformance_golden_vectors.rs` sucht den
/// Quelltext erneut ab und faellt, sobald dort eine Zeichenkette ohne Vektor
/// steht.
///
/// ADDITIV erweitert um die drei Domaenen des Archivbackendprofils (D-B02) und
/// um die Vorschaudomaene der Abschlussbestaetigung.
/// Kein bestehender Eintrag wurde umbenannt, entfernt oder umsortiert; das
/// Manifest sortiert seine Eintraege ohnehin nach Namen
/// ([`VectorManifest::to_json`]).
const CRYPTO_DOMAIN_STRINGS: [&str; 24] = [
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
    "EINSATZARCHIV-ARCHIVE-PROFILE-v1",
    "EINSATZARCHIV-ARCHIVE-INVENTORY-v1",
    "EINSATZARCHIV-ACTIVE-PROFILE-POINTER-v1",
    "EINSATZARCHIV-FINALIZATION-PREVIEW-v1",
];

/// Die domaingetrennten Digestfunktionen mit ihrer Domaene.
const CRYPTO_DOMAIN_DIGESTS: [(&str, &str); 16] = [
    (
        "domain-digest/ciphertext-digest",
        "EINSATZARCHIV-CIPHERTEXT-v1",
    ),
    ("domain-digest/record-digest", "EINSATZARCHIV-RECORD-v1"),
    (
        "domain-digest/grant-plan-digest",
        "EINSATZARCHIV-GRANT-PLAN-v1",
    ),
    ("domain-digest/grant-digest", "EINSATZARCHIV-GRANT-v1"),
    ("domain-digest/receipt-digest", "EINSATZARCHIV-RECEIPT-v1"),
    (
        "domain-digest/trust-digest",
        "EINSATZARCHIV-TRUST-OBJECT-v1",
    ),
    (
        "domain-digest/authorized-trust-digest",
        "EINSATZARCHIV-ADMIN-AUTHORIZED-TRUST-v1",
    ),
    (
        "domain-digest/renewal-input-digest",
        "EINSATZARCHIV-EVIDENCE-RENEWAL-INPUT-v1",
    ),
    (
        "domain-digest/bootstrap-anchor-hash",
        "EINSATZARCHIV-TRUST-ANCHOR-PRE-v1",
    ),
    (
        "domain-digest/trust-anchor-hash",
        "EINSATZARCHIV-TRUST-ANCHOR-v1",
    ),
    (
        "domain-digest/operator-profile-digest",
        "EINSATZARCHIV-OPERATOR-PROFILE-v1",
    ),
    ("domain-digest/object-hash", "EINSATZARCHIV-OBJECT-v1"),
    (
        "domain-digest/archive-profile-digest",
        "EINSATZARCHIV-ARCHIVE-PROFILE-v1",
    ),
    (
        "domain-digest/archive-inventory-digest",
        "EINSATZARCHIV-ARCHIVE-INVENTORY-v1",
    ),
    (
        "domain-digest/active-profile-pointer-digest",
        "EINSATZARCHIV-ACTIVE-PROFILE-POINTER-v1",
    ),
    (
        "domain-digest/finalization-preview-digest",
        "EINSATZARCHIV-FINALIZATION-PREVIEW-v1",
    ),
];

/// Die drei Praefixfunktionen, deren Ausgabe die Domaene mittraegt.
const CRYPTO_DOMAIN_CONTEXTS: [(&str, &str); 3] = [
    ("domain-context/payload-aad", "EINSATZARCHIV-AAD-v1"),
    ("domain-context/hpke-info", "EINSATZARCHIV-HPKE-INFO-v1"),
    ("domain-context/hpke-aad", "EINSATZARCHIV-HPKE-AAD-v1"),
];

/// Die Ed25519-Signatur aus RFC 8032 §7.1, TEST 1 — leere Nachricht.
///
/// NICHT ABGESCHRIEBEN, sondern erzeugt: Ed25519 signiert deterministisch, und
/// der Seed ist der des Standards. `ea-system-tests` signiert im Testlauf neu
/// und stellt das Ergebnis gegen diese Bytes.
const ED25519_RFC8032_TEST1_SIGNATURE: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

/// Die Ed25519-Signatur aus RFC 8032 §7.1, TEST 2 — Nachricht `0x72`.
const ED25519_RFC8032_TEST2_SIGNATURE: &str = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

/// Der Schluessel des AEAD-Vektors aus RFC 8439 §2.8.2: `0x80` bis `0x9f`.
const RFC8439_KEY: &str = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";

/// Die Nonce aus RFC 8439 §2.8.2: 32-Bit-Konstante plus 64-Bit-IV.
const RFC8439_NONCE: &str = "070000004041424344454647";

/// Die zusaetzlichen authentifizierten Daten aus RFC 8439 §2.8.2.
const RFC8439_AAD: &str = "50515253c0c1c2c3c4c5c6c7";

/// Der Klartext aus RFC 8439 §2.8.2.
const RFC8439_PLAINTEXT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

/// Chiffrat und Poly1305-Tag aus RFC 8439 §2.8.2.
const RFC8439_CIPHERTEXT: &str = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691";

/// Das Chiffrat ueber [`CRYPTO_PROBE`] unter der deklarierten Testentropie.
const DECLARED_ENTROPY_CIPHERTEXT: &str =
    "22ffe3aa374a6984b02a584dd0bbdfe2d55ae456849bba93d9a755c2ffae7054e3635833";

/// Der oeffentliche X25519-Schluessel zu [`TEST_ENTROPY_RECIPIENT_X25519_SEED`].
///
/// Abgeleitet, nicht gewuerfelt; `ea-system-tests` leitet ihn im Testlauf neu
/// ab und stellt ihn gegen den eingefrorenen Kapselungsvektor.
const RECIPIENT_X25519_PUBLIC_KEY: &str =
    "80e1a53d3eee82b62b3048578cf38c980ddd1131243a1047fe48482942d6b648";

/// Kapselungswert und umschlossener CEK, EINMALIG erzeugt und eingefroren.
///
/// `hpke_seal` zieht bei jedem Aufruf frische Entropie aus dem Betriebssystem
/// (`crates/ea-crypto/src/hpke.rs`), und der Injektionspunkt fuer Testentropie
/// ist privat. Diese 80 Byte sind deshalb nicht regenerierbar; nachgeprueft
/// werden sie ausschliesslich in der entkapselnden Richtung ueber `hpke_open`,
/// und das Manifest sagt das ueber [`VectorSource::FrozenOnce`] an.
const HPKE_ENCAPSULATED_KEY: &str =
    "53a33a9a549bc5a3d0978e07af5562b3b12d358f56083327888e89be98a4dd01";

/// Der umschlossene Inhaltsschluessel zum eingefrorenen Kapselungswert.
const HPKE_WRAPPED_CEK: &str = "d8a66d3b3a51a539cb44797af5eb6e9d05ba9d1b8f8dd05caa6373052856871904e0febf4442d852bfb000af7ae2750d";

/// Ein Datensatzbezeichner nach RFC 9562: Version 7, Variante 0b10.
const UUID_V7_ACCEPTED: &str = "018f2c3d4e5a7b6c8d9ea0b1c2d3e4f5";

/// Derselbe Bezeichner mit Version 4 — von `ea-schema` abzulehnen.
const UUID_VERSION_FOUR: &str = "018f2c3d4e5a4b6c8d9ea0b1c2d3e4f5";

/// Der Inhalt von `/etc/machine-id` im OS-Kontovektor.
const LINUX_MACHINE_ID_FILE: &[u8] = b"0123456789abcdef0123456789abcdef\n";

/// Die Benutzerkennung im OS-Kontovektor.
const LINUX_UID: u32 = 1000;

/// Das Manifest der Vektorfamilie `crypto/suite-1`.
///
/// Deterministisch: zwei Laeufe liefern dieselben Bytes. Alles, was nicht aus
/// einem veroeffentlichten Standard stammt, wird hier aus festen Konstanten
/// gerechnet — mit einer Ausnahme, der HPKE-Kapselung, die als
/// [`VectorSource::FrozenOnce`] gekennzeichnet ist.
///
/// # Panics
///
/// Wenn eine der eingefrorenen Hexkonstanten dieser Datei nicht dekodierbar
/// ist. Das ist ein Programmierfehler in dieser Crate, kein Laufzeitzustand.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn crypto_suite_one_manifest() -> VectorManifest {
    // Die Suite-Identifikatoren.
    //
    // Die COSE-Algorithmuskennung steht hier in der deterministischen
    // CBOR-Kodierung des Protected Headers: `0x32` ist die einbytige,
    // laengenminimale Darstellung der negativen Ganzzahl -19, also des
    // VOLLSTAENDIG SPEZIFIZIERTEN Ed25519 nach RFC 9864. Die generische
    // EdDSA-Kennung -8 (`0x27`) ist ausdruecklich NICHT gemeint; genau diese
    // Unterscheidung traegt RFC 9864 ein, und sie laesst sich nur ueber die
    // Kennung selbst einfrieren, nicht ueber einen Signaturvektor: die
    // Signaturmathematik ist in beiden Faellen dieselbe.
    //
    // Modus, KEM, KDF und AEAD der Grant-Suite stehen in Netzwerkbyteordnung.
    let mut entries = vec![
        crypto_entry(
            "suite/suite-identifier",
            "ea.crypto.suite-identifier/v1",
            CRYPTO_SUITE_ONE_SUITE_ID,
            generator_source(),
            Vec::new(),
            BTreeMap::new(),
            CRYPTO_SUITE_ONE_SUITE_ID.as_bytes().to_vec(),
            ExpectedOutcome::Accepted,
        ),
        crypto_entry(
            "suite/grant-suite-identifier",
            "ea.crypto.suite-identifier/v1",
            CRYPTO_SUITE_ONE_GRANT_SUITE_ID,
            generator_source(),
            Vec::new(),
            BTreeMap::new(),
            CRYPTO_SUITE_ONE_GRANT_SUITE_ID.as_bytes().to_vec(),
            ExpectedOutcome::Accepted,
        ),
        crypto_entry(
            "suite/cose-ed25519-algorithm-identifier",
            "ea.crypto.cose-algorithm-identifier/v1",
            CRYPTO_SUITE_ONE_SUITE_ID,
            VectorSource::Standard("RFC 9864, COSE Algorithms registry: Ed25519 = -19".to_owned()),
            Vec::new(),
            BTreeMap::new(),
            vec![0x32],
            ExpectedOutcome::Accepted,
        ),
        crypto_entry(
            "suite/hpke-suite-identifiers",
            "ea.crypto.hpke-suite/v1",
            CRYPTO_SUITE_ONE_GRANT_SUITE_ID,
            VectorSource::Standard("RFC 9180 §7.1, §7.2, §7.3".to_owned()),
            Vec::new(),
            BTreeMap::new(),
            vec![0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x03],
            ExpectedOutcome::Accepted,
        ),
    ];

    // Die Domain-Trennungszeichenketten selbst.
    for domain in CRYPTO_DOMAIN_STRINGS {
        entries.push(crypto_entry(
            &format!("domain-string/{}", domain.to_lowercase()),
            "ea.crypto.domain-separation-string/v1",
            CRYPTO_SUITE_ONE_SUITE_ID,
            generator_source(),
            Vec::new(),
            BTreeMap::new(),
            domain.as_bytes().to_vec(),
            ExpectedOutcome::Accepted,
        ));
    }

    // SHA-256 gegen die veroeffentlichten Antworten.
    for (name, preimage) in [
        ("sha-256/empty", b"".as_slice()),
        ("sha-256/abc", b"abc".as_slice()),
    ] {
        entries.push(crypto_entry(
            name,
            "ea.crypto.sha-256/v1",
            CRYPTO_SUITE_ONE_SUITE_ID,
            VectorSource::Standard("FIPS 180-4, RFC 6234 §8.5".to_owned()),
            preimage.to_vec(),
            BTreeMap::new(),
            sha256(preimage).to_vec(),
            ExpectedOutcome::Accepted,
        ));
    }

    // Die domaingetrennten Digests ueber ein festes Urbild.
    for (name, domain) in CRYPTO_DOMAIN_DIGESTS {
        entries.push(crypto_entry(
            name,
            "ea.crypto.domain-digest/v1",
            CRYPTO_SUITE_ONE_SUITE_ID,
            generator_source(),
            CRYPTO_PROBE.to_vec(),
            domain_digest_intermediates(domain),
            domain_digest(domain, CRYPTO_PROBE).to_vec(),
            ExpectedOutcome::Accepted,
        ));
    }

    // `entry_hash` bindet Datensatzdigest und Schreibersignatur zusammen. Das
    // Urbild IST die Eingabe: Digest und Signaturbytes stehen hintereinander.
    let record_digest = domain_digest("EINSATZARCHIV-RECORD-v1", CRYPTO_PROBE);
    let mut entry_hash_input = record_digest.to_vec();
    entry_hash_input.extend_from_slice(CRYPTO_PROBE);
    let entry_hash_object = domain_digest("EINSATZARCHIV-PACKAGE-v1", &entry_hash_input).to_vec();
    entries.push(crypto_entry(
        "domain-digest/entry-hash",
        "ea.crypto.domain-digest/v1",
        CRYPTO_SUITE_ONE_SUITE_ID,
        generator_source(),
        entry_hash_input,
        domain_digest_intermediates("EINSATZARCHIV-PACKAGE-v1"),
        entry_hash_object,
        ExpectedOutcome::Accepted,
    ));

    // `recovery_test_digest` hasht einen deterministischen CBOR-Kontext.
    let challenge = [0x41_u8; 32];
    let thumbprint = [0x40_u8; 32];
    let mut recovery_input = challenge.to_vec();
    recovery_input.extend_from_slice(&thumbprint);
    let mut recovery_context = vec![0x83, 0x01];
    recovery_context.extend_from_slice(&cbor_bytes(&challenge));
    recovery_context.extend_from_slice(&cbor_bytes(&thumbprint));
    entries.push(crypto_entry(
        "domain-digest/recovery-test-digest",
        "ea.crypto.domain-digest/v1",
        CRYPTO_SUITE_ONE_SUITE_ID,
        generator_source(),
        recovery_input,
        domain_digest_intermediates("EINSATZARCHIV-RECOVERY-TEST-v1"),
        domain_digest("EINSATZARCHIV-RECOVERY-TEST-v1", &recovery_context).to_vec(),
        ExpectedOutcome::Accepted,
    ));

    // Die Betriebssystemkontobindung ueber ihren kanonischen CBOR-Kontext.
    let mut account_input = CRYPTO_ORGANIZATION_ID.to_vec();
    account_input.extend_from_slice(&CRYPTO_DEVICE_ID);
    account_input.extend_from_slice(LINUX_MACHINE_ID_FILE);
    account_input.extend_from_slice(&LINUX_UID.to_be_bytes());
    let mut account_context = vec![0x83];
    account_context.extend_from_slice(&cbor_bytes(&CRYPTO_ORGANIZATION_ID));
    account_context.extend_from_slice(&cbor_bytes(&CRYPTO_DEVICE_ID));
    account_context.extend_from_slice(&[0x84, 0x01, 0x02]);
    account_context.extend_from_slice(&cbor_bytes(&decode("0123456789abcdef0123456789abcdef")));
    account_context.extend_from_slice(&cbor_unsigned(u64::from(LINUX_UID)));
    entries.push(crypto_entry(
        "domain-digest/os-account-linux",
        "ea.crypto.domain-digest/v1",
        CRYPTO_SUITE_ONE_SUITE_ID,
        generator_source(),
        account_input,
        domain_digest_intermediates("EINSATZARCHIV-OS-ACCOUNT-v1"),
        domain_digest("EINSATZARCHIV-OS-ACCOUNT-v1", &account_context).to_vec(),
        ExpectedOutcome::Accepted,
    ));

    // Die Praefixfunktionen liefern die Domaene mit aus.
    for (name, domain) in CRYPTO_DOMAIN_CONTEXTS {
        let mut context = domain.as_bytes().to_vec();
        context.extend_from_slice(CRYPTO_PROBE);
        entries.push(crypto_entry(
            name,
            "ea.crypto.domain-context/v1",
            CRYPTO_SUITE_ONE_SUITE_ID,
            generator_source(),
            CRYPTO_PROBE.to_vec(),
            BTreeMap::new(),
            context,
            ExpectedOutcome::Accepted,
        ));
    }

    // Ed25519 nach RFC 8032.
    for (name, message, signature, public, test) in [
        (
            "ed25519/rfc8032-test1",
            Vec::new(),
            ED25519_RFC8032_TEST1_SIGNATURE,
            ED25519_RFC8032_TEST1_PUBLIC_KEY,
            "TEST 1",
        ),
        (
            "ed25519/rfc8032-test2",
            vec![0x72],
            ED25519_RFC8032_TEST2_SIGNATURE,
            ED25519_RFC8032_TEST2_PUBLIC_KEY,
            "TEST 2",
        ),
    ] {
        entries.push(crypto_entry(
            name,
            "ea.crypto.ed25519-signature/v1",
            CRYPTO_SUITE_ONE_SUITE_ID,
            VectorSource::Standard(format!("RFC 8032 §7.1 {test}")),
            message,
            signer_thumbprint_intermediates(0x06, &public),
            decode(signature),
            ExpectedOutcome::Accepted,
        ));
    }
    let mut flipped_signature = decode(ED25519_RFC8032_TEST1_SIGNATURE);
    flipped_signature[0] ^= 0x01;
    entries.push(crypto_entry(
        "ed25519/flipped-signature",
        "ea.crypto.ed25519-signature/v1",
        CRYPTO_SUITE_ONE_SUITE_ID,
        generator_source(),
        Vec::new(),
        signer_thumbprint_intermediates(0x06, &ED25519_RFC8032_TEST1_PUBLIC_KEY),
        flipped_signature,
        ExpectedOutcome::Rejected {
            error_code: "EA-TRUST-SIGNATURE-INVALID".to_owned(),
        },
    ));
    entries.push(crypto_entry(
        "ed25519/weak-public-key",
        "ea.crypto.ed25519-public-key/v1",
        CRYPTO_SUITE_ONE_SUITE_ID,
        generator_source(),
        Vec::new(),
        BTreeMap::new(),
        vec![0; 32],
        ExpectedOutcome::Rejected {
            error_code: "EA-CRYPTO-INVALID-PUBLIC-KEY".to_owned(),
        },
    ));

    // ChaCha20-Poly1305.
    entries.push(crypto_entry(
        "aead/rfc8439-2.8.2",
        "ea.crypto.chacha20poly1305-ciphertext/v1",
        CRYPTO_SUITE_ONE_SUITE_ID,
        VectorSource::Standard("RFC 8439 §2.8.2".to_owned()),
        RFC8439_PLAINTEXT.to_vec(),
        aead_intermediates(
            &decode(RFC8439_KEY),
            &decode(RFC8439_NONCE),
            &decode(RFC8439_AAD),
        ),
        decode(RFC8439_CIPHERTEXT),
        ExpectedOutcome::Accepted,
    ));
    let mut declared_aad = b"EINSATZARCHIV-AAD-v1".to_vec();
    declared_aad.extend_from_slice(CRYPTO_PROBE);
    entries.push(crypto_entry(
        "aead/declared-entropy",
        "ea.crypto.chacha20poly1305-ciphertext/v1",
        CRYPTO_SUITE_ONE_SUITE_ID,
        generator_source(),
        CRYPTO_PROBE.to_vec(),
        aead_intermediates(
            &TEST_ENTROPY_CONTENT_ENCRYPTION_KEY,
            &TEST_ENTROPY_AEAD_NONCE,
            &declared_aad,
        ),
        decode(DECLARED_ENTROPY_CIPHERTEXT),
        ExpectedOutcome::Accepted,
    ));
    let mut tampered = decode(DECLARED_ENTROPY_CIPHERTEXT);
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    entries.push(crypto_entry(
        "aead/tampered-tag",
        "ea.crypto.chacha20poly1305-ciphertext/v1",
        CRYPTO_SUITE_ONE_SUITE_ID,
        generator_source(),
        CRYPTO_PROBE.to_vec(),
        aead_intermediates(
            &TEST_ENTROPY_CONTENT_ENCRYPTION_KEY,
            &TEST_ENTROPY_AEAD_NONCE,
            &declared_aad,
        ),
        tampered,
        ExpectedOutcome::Rejected {
            error_code: "EA-CRYPTO-AEAD-OPEN".to_owned(),
        },
    ));

    // HPKE Base Mode.
    entries.push(crypto_entry(
        "hpke/rfc7748-recipient-public-key",
        "ea.crypto.hpke-recipient-public-key/v1",
        CRYPTO_SUITE_ONE_GRANT_SUITE_ID,
        VectorSource::Standard("RFC 7748 §6.1".to_owned()),
        X25519_RFC7748_BOB_PRIVATE_KEY.to_vec(),
        BTreeMap::new(),
        X25519_RFC7748_BOB_PUBLIC_KEY.to_vec(),
        ExpectedOutcome::Accepted,
    ));
    let mut sealed = decode(HPKE_ENCAPSULATED_KEY);
    sealed.extend_from_slice(&decode(HPKE_WRAPPED_CEK));
    entries.push(crypto_entry(
        "hpke/base-mode-wrapped-cek",
        "ea.crypto.hpke-sealed-cek/v1",
        CRYPTO_SUITE_ONE_GRANT_SUITE_ID,
        VectorSource::FrozenOnce {
            verified_via: "hpke_open".to_owned(),
        },
        TEST_ENTROPY_CONTENT_ENCRYPTION_KEY.to_vec(),
        hpke_intermediates(),
        sealed.clone(),
        ExpectedOutcome::Accepted,
    ));
    for (name, index) in [
        ("hpke/flipped-encapsulated-key", 0),
        ("hpke/flipped-wrapped-cek", 32),
    ] {
        let mut broken = sealed.clone();
        broken[index] ^= 0x01;
        entries.push(crypto_entry(
            name,
            "ea.crypto.hpke-sealed-cek/v1",
            CRYPTO_SUITE_ONE_GRANT_SUITE_ID,
            VectorSource::FrozenOnce {
                verified_via: "hpke_open".to_owned(),
            },
            TEST_ENTROPY_CONTENT_ENCRYPTION_KEY.to_vec(),
            hpke_intermediates(),
            broken,
            ExpectedOutcome::Rejected {
                error_code: "EA-CRYPTO-HPKE-OPEN".to_owned(),
            },
        ));
    }

    // RFC 9679 Key-Thumbprints.
    for (curve, public, key_name, thumbprint_name) in [
        (
            0x06_u8,
            ED25519_RFC8032_TEST1_PUBLIC_KEY,
            "thumbprint/ed25519-canonical-cose-key",
            "thumbprint/ed25519",
        ),
        (
            0x04,
            X25519_RFC7748_BOB_PUBLIC_KEY,
            "thumbprint/x25519-canonical-cose-key",
            "thumbprint/x25519",
        ),
    ] {
        let encoded = canonical_public_cose_key(curve, &public);
        entries.push(crypto_entry(
            key_name,
            "ea.crypto.cose-key/v1",
            CRYPTO_SUITE_ONE_SUITE_ID,
            VectorSource::Standard("RFC 9679 §3".to_owned()),
            public.to_vec(),
            digest_map(&[("thumbprint", sha256(&encoded))]),
            encoded.clone(),
            ExpectedOutcome::Accepted,
        ));
        entries.push(crypto_entry(
            thumbprint_name,
            "ea.crypto.cose-key-thumbprint/v1",
            CRYPTO_SUITE_ONE_SUITE_ID,
            VectorSource::Standard("RFC 9679 §3".to_owned()),
            encoded.clone(),
            BTreeMap::new(),
            sha256(&encoded).to_vec(),
            ExpectedOutcome::Accepted,
        ));
    }
    entries.push(crypto_entry(
        "thumbprint/unknown-curve",
        "ea.crypto.cose-key/v1",
        CRYPTO_SUITE_ONE_SUITE_ID,
        generator_source(),
        ED25519_RFC8032_TEST1_PUBLIC_KEY.to_vec(),
        BTreeMap::new(),
        canonical_public_cose_key(0x01, &ED25519_RFC8032_TEST1_PUBLIC_KEY),
        ExpectedOutcome::Rejected {
            error_code: "EA-CRYPTO-UNSUPPORTED-SUITE".to_owned(),
        },
    ));

    // Die signierten Protokollkerne mit ihrer Typzeichenkette.
    for (name, schema, valid, mutated, core) in [
        (
            "protocol-core/checkpoint",
            "ea.crypto.checkpoint-core/v1",
            "EINSATZARCHIV-CHECKPOINT-v1",
            "EINSATZARCHIV-CHECKPOINT-v2",
            checkpoint_core as fn(&str) -> Vec<u8>,
        ),
        (
            "protocol-core/evidence-renewal",
            "ea.crypto.evidence-renewal-core/v1",
            "EINSATZARCHIV-EVIDENCE-RENEWAL-v1",
            "EINSATZARCHIV-EVIDENCE-RENEWAL-v2",
            renewal_core as fn(&str) -> Vec<u8>,
        ),
    ] {
        entries.push(crypto_entry(
            name,
            schema,
            CRYPTO_SUITE_ONE_SUITE_ID,
            generator_source(),
            Vec::new(),
            BTreeMap::new(),
            core(valid),
            ExpectedOutcome::Accepted,
        ));
        entries.push(crypto_entry(
            &format!("{name}-mutated-type-string"),
            schema,
            CRYPTO_SUITE_ONE_SUITE_ID,
            generator_source(),
            Vec::new(),
            BTreeMap::new(),
            core(mutated),
            ExpectedOutcome::Rejected {
                error_code: "EA-CRYPTO-INVALID-PROTOCOL-CORE".to_owned(),
            },
        ));
    }

    // RFC 9562 UUIDv7.
    entries.push(crypto_entry(
        "uuid-v7/valid",
        "ea.crypto.uuid-v7/v1",
        CRYPTO_SUITE_ONE_SUITE_ID,
        VectorSource::Standard("RFC 9562 §5.7".to_owned()),
        Vec::new(),
        BTreeMap::new(),
        decode(UUID_V7_ACCEPTED),
        ExpectedOutcome::Accepted,
    ));
    entries.push(crypto_entry(
        "uuid-v7/version-four",
        "ea.crypto.uuid-v7/v1",
        CRYPTO_SUITE_ONE_SUITE_ID,
        generator_source(),
        Vec::new(),
        BTreeMap::new(),
        decode(UUID_VERSION_FOUR),
        ExpectedOutcome::Rejected {
            error_code: "EA-SCHEMA-UUID-V7".to_owned(),
        },
    ));

    VectorManifest {
        family: CRYPTO_FAMILY.to_owned(),
        version: CRYPTO_SUITE_ONE_VERSION.to_owned(),
        entries,
    }
}

fn generator_source() -> VectorSource {
    VectorSource::GeneratorCommit(CRYPTO_GENERATOR.to_owned())
}

/// Baut einen Manifesteintrag und leitet seinen Dateipfad aus dem Namen ab.
///
/// Die breite Signatur ist der Vertrag selbst: ein Eintrag hat neun
/// Pflichtangaben, und acht davon sind hier zu waehlen. Sie zu Gruppen zu
/// buendeln verstecke den Vertrag, statt ihn zu zeigen — deshalb steht hier ein
/// ausdrueckliches `allow` und keine Hilfsstruktur.
#[allow(clippy::too_many_arguments)]
fn crypto_entry(
    name: &str,
    schema_id: &str,
    suite_id: &str,
    source: VectorSource,
    input_bytes: Vec<u8>,
    intermediate_digests: BTreeMap<String, [u8; 32]>,
    object_bytes: Vec<u8>,
    expected_outcome: ExpectedOutcome,
) -> VectorEntry {
    VectorEntry {
        name: name.to_owned(),
        schema_id: schema_id.to_owned(),
        suite_id: suite_id.to_owned(),
        source,
        input_bytes,
        intermediate_digests,
        object_bytes,
        expected_outcome,
        file: format!("{name}.bin"),
        scope_note: None,
    }
}

/// SHA-256 ueber `bytes`.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// `SHA-256(domain || urbild)` — die Formel jeder domaingetrennten
/// Hashfunktion von `ea-crypto`.
fn domain_digest(domain: &str, preimage: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(preimage);
    hasher.finalize().into()
}

fn digest_map(pairs: &[(&str, [u8; 32])]) -> BTreeMap<String, [u8; 32]> {
    pairs
        .iter()
        .map(|(name, digest)| ((*name).to_owned(), *digest))
        .collect()
}

fn domain_digest_intermediates(domain: &str) -> BTreeMap<String, [u8; 32]> {
    digest_map(&[("domainString", sha256(domain.as_bytes()))])
}

fn signer_thumbprint_intermediates(curve: u8, public: &[u8; 32]) -> BTreeMap<String, [u8; 32]> {
    digest_map(&[(
        "signerThumbprint",
        sha256(&canonical_public_cose_key(curve, public)),
    )])
}

fn aead_intermediates(key: &[u8], nonce: &[u8], aad: &[u8]) -> BTreeMap<String, [u8; 32]> {
    digest_map(&[
        ("aadDigest", sha256(aad)),
        ("keyDigest", sha256(key)),
        ("nonceDigest", sha256(nonce)),
    ])
}

fn hpke_intermediates() -> BTreeMap<String, [u8; 32]> {
    let mut info = b"EINSATZARCHIV-HPKE-INFO-v1".to_vec();
    info.extend_from_slice(CRYPTO_PROBE);
    let mut aad = b"EINSATZARCHIV-HPKE-AAD-v1".to_vec();
    aad.extend_from_slice(CRYPTO_PROBE);
    let public: [u8; 32] = decode(RECIPIENT_X25519_PUBLIC_KEY)
        .try_into()
        .expect("the frozen recipient public key is 32 bytes");
    digest_map(&[
        ("aadDigest", sha256(&aad)),
        ("infoDigest", sha256(&info)),
        (
            "recipientPublicKeyThumbprint",
            sha256(&canonical_public_cose_key(0x04, &public)),
        ),
    ])
}

/// Die kanonische COSE-Key-Kodierung nach RFC 9679: `{1: 1, -1: crv, -2: x}`.
///
/// Von Hand kodiert, damit dieser Erzeuger keine CBOR-Bibliothek braucht und
/// die Kodierung nicht aus derselben Quelle stammt wie die geprueften Bytes.
fn canonical_public_cose_key(curve: u8, public: &[u8; 32]) -> Vec<u8> {
    let mut bytes = vec![0xa3, 0x01, 0x01, 0x20, curve, 0x21];
    bytes.extend_from_slice(&cbor_bytes(public));
    bytes
}

/// Ein deterministisch kodierter CBOR-Bytestring.
fn cbor_bytes(value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(value.len() + 2);
    match value.len() {
        length if length < 24 => bytes.push(0x40 | u8::try_from(length).expect("below 24")),
        length if length < 256 => {
            bytes.push(0x58);
            bytes.push(u8::try_from(length).expect("below 256"));
        }
        length => panic!("no vector carries a byte string of {length} bytes"),
    }
    bytes.extend_from_slice(value);
    bytes
}

/// Eine deterministisch kodierte vorzeichenlose CBOR-Ganzzahl.
fn cbor_unsigned(value: u64) -> Vec<u8> {
    if value < 24 {
        return vec![u8::try_from(value).expect("below 24")];
    }
    if value <= u64::from(u8::MAX) {
        return vec![0x18, u8::try_from(value).expect("below 256")];
    }
    if value <= u64::from(u16::MAX) {
        let mut bytes = vec![0x19];
        bytes.extend_from_slice(&u16::try_from(value).expect("below 65536").to_be_bytes());
        return bytes;
    }
    if value <= u64::from(u32::MAX) {
        let mut bytes = vec![0x1a];
        bytes.extend_from_slice(&u32::try_from(value).expect("below 2^32").to_be_bytes());
        return bytes;
    }
    let mut bytes = vec![0x1b];
    bytes.extend_from_slice(&value.to_be_bytes());
    bytes
}

/// Eine deterministisch kodierte CBOR-Textzeichenkette unter 256 Zeichen.
fn cbor_text(value: &str) -> Vec<u8> {
    let length = u8::try_from(value.len()).expect("every type string is shorter than 256 bytes");
    assert!(length >= 24, "the type strings are longer than 23 bytes");
    let mut bytes = vec![0x78, length];
    bytes.extend_from_slice(value.as_bytes());
    bytes
}

/// Der unsignierte Checkpoint-Kern nach `validate_checkpoint_core`.
fn checkpoint_core(type_string: &str) -> Vec<u8> {
    let mut bytes = vec![0x8b, 0x01];
    bytes.extend_from_slice(&cbor_text(type_string));
    bytes.extend_from_slice(&cbor_bytes(&CRYPTO_ORGANIZATION_ID));
    bytes.extend_from_slice(&cbor_bytes(&CRYPTO_DEVICE_ID));
    bytes.extend_from_slice(&cbor_unsigned(1000));
    bytes.extend_from_slice(&cbor_unsigned(10000));
    bytes.extend_from_slice(&cbor_bytes(&[0x21; 32]));
    bytes.extend_from_slice(&cbor_bytes(&[0x22; 32]));
    bytes.extend_from_slice(&cbor_unsigned(3600));
    bytes.extend_from_slice(&cbor_bytes(&[0x23; 32]));
    bytes.push(0x80);
    bytes
}

/// Der unsignierte Erneuerungskern nach `validate_renewal_core`.
fn renewal_core(type_string: &str) -> Vec<u8> {
    let mut bytes = vec![0x88, 0x01];
    bytes.extend_from_slice(&cbor_text(type_string));
    bytes.extend_from_slice(&cbor_bytes(&CRYPTO_ORGANIZATION_ID));
    bytes.extend_from_slice(&cbor_bytes(&CRYPTO_DEVICE_ID));
    bytes.extend_from_slice(&cbor_bytes(&[0x31; 32]));
    bytes.push(0xf6);
    bytes.push(0x81);
    bytes.extend_from_slice(&cbor_bytes(&[0x32; 32]));
    bytes.push(0x80);
    bytes
}

/// Dekodiert eine eingefrorene Hexkonstante dieser Datei.
fn decode(text: &str) -> Vec<u8> {
    hex::decode(text).expect("every frozen constant of this file is lowercase hex")
}

// ---------------------------------------------------------------------------
// Die Vektorfamilie `format/v1`
// ---------------------------------------------------------------------------

/// Der Familienname der Objektvektoren.
pub const FORMAT_FAMILY: &str = "format";

/// Der Versionsordner der gueltigen Objekte.
pub const FORMAT_V1_VALID_VERSION: &str = "v1/valid";

/// Der Versionsordner der Ablehnungsvektoren.
pub const FORMAT_V1_INVALID_VERSION: &str = "v1/invalid";

/// Die Wurzel der gueltigen Objekte, relativ zur Arbeitsbaumwurzel.
pub const FORMAT_V1_VALID_ROOT: &str = "vectors/format/v1/valid";

/// Die Wurzel der Ablehnungsvektoren, relativ zur Arbeitsbaumwurzel.
pub const FORMAT_V1_INVALID_ROOT: &str = "vectors/format/v1/invalid";

/// Die Herkunftsangabe der deterministisch erzeugten Objektvektoren.
const FORMAT_GENERATOR: &str = "ea-testkit::format_v1_objects";

/// Der Suite-Identifikator der Objektvektoren, EINGEFROREN.
const FORMAT_SUITE_ID: &str = "EINSATZARCHIV-SUITE-1";

/// Die Organisationskennung aller Objektvektoren.
const FORMAT_ORGANIZATION_ID: [u8; 16] = [0x20; 16];

/// Die Kettenkennung aller Objektvektoren.
const FORMAT_CHAIN_ID: [u8; 16] = [0x21; 16];

/// Der Zertifikatshash des schreibenden Geraets.
const FORMAT_WRITER_CERTIFICATE_HASH: [u8; 32] = [0x22; 32];

/// Der Registrierungskopf-Hash aller Objektvektoren.
const FORMAT_REGISTRY_HEAD_HASH: [u8; 32] = [0x23; 32];

/// Der Hash des initialen Grant-Plans.
const FORMAT_INITIAL_GRANT_PLAN_HASH: [u8; 32] = [0x24; 32];

/// Der Zertifikatshash der Serverseite: Receipt und Checkpoint.
const FORMAT_SERVER_CERTIFICATE_HASH: [u8; 32] = [0x26; 32];

/// Der Zertifikatshash des Empfaengers eines Grants.
const FORMAT_RECIPIENT_CERTIFICATE_HASH: [u8; 32] = [0x27; 32];

/// Der Schluesselabdruck des Empfaengers eines Grants.
const FORMAT_RECIPIENT_KEY_THUMBPRINT: [u8; 32] = [0x28; 32];

/// Die Kennung der Vernichtung im `.eds`.
const FORMAT_DESTRUCTION_ID: [u8; 16] = [0x29; 16];

/// Der Objekthash der Vernichtungsautorisierung im `.eds`.
const FORMAT_DESTRUCTION_AUTHORIZATION_OBJECT_HASH: [u8; 32] = [0x2a; 32];

/// Der Objekthash der Richtlinie im `.esr`.
const FORMAT_POLICY_OBJECT_HASH: [u8; 32] = [0x2b; 32];

/// Der Klartext, den der `.eip`-Vektor verschluesselt traegt.
///
/// Kurz genug, dass jeder abgeleitete Vektor unter 256 Byte Chiffrat bleibt und
/// die Laengenkodierung der Bytestrings einbyteig bleibt.
const FORMAT_PLAINTEXT: &[u8] = b"format/v1 vector plaintext";

/// Die Geraetezeit aller Objektvektoren in Millisekunden seit der Epoche.
const FORMAT_DEVICE_TIME_MS: i64 = 1_700_000_000_000;

/// Die Serverzeit aller Objektvektoren in Millisekunden seit der Epoche.
const FORMAT_SERVER_TIME_MS: i64 = 1_700_000_001_000;

/// Die Registrierungsversion aller Objektvektoren.
const FORMAT_REGISTRY_VERSION: u64 = 4;

/// `MAX_CBOR_TEXT_OR_BYTES_V1` plus genau ein Byte.
const FORMAT_TEXT_OR_BYTES_OVER_LIMIT: u64 = 1_048_593;

/// `MAX_CIPHERTEXT_BYTES_V1` plus genau ein Byte.
///
/// Zahlengleich mit [`FORMAT_TEXT_OR_BYTES_OVER_LIMIT`], und das ist kein
/// Zufall: `checked_ciphertext_length` addiert genau das 16 Byte lange
/// Poly1305-Tag, `MAX_CIPHERTEXT_BYTES_V1 = MAX_PLAINTEXT_BYTES_V1 + 16`, und
/// die CBOR-Grenze ist auf denselben Wert gesetzt.
const FORMAT_CIPHERTEXT_OVER_LIMIT: u64 = 1_048_593;

/// `MAX_PLAINTEXT_BYTES_V1` plus genau ein Byte.
const FORMAT_PLAINTEXT_OVER_LIMIT: usize = 1_048_577;

/// Die groesste Containerelementzahl plus eins.
const FORMAT_CONTAINER_ITEMS_OVER_LIMIT: u64 = 10_001;

/// Die groesste Containerelementzahl selbst.
///
/// Ein Container GENAU an der Grenze passiert `read_container_length` und
/// laesst die Gesamtzahl der Elemente ueberlaufen — nur so ist
/// `MAX_TOTAL_ITEMS_V1 + 1` ueberhaupt erreichbar, weil beide Grenzen auf
/// 10_000 stehen.
const FORMAT_CONTAINER_ITEMS_AT_LIMIT: u64 = 10_000;

/// Der Schema-Identifikator des Vektors, den `ea-schema` prueft.
const FORMAT_SCHEMA_CHECKED_SCHEMA_ID: &str = "ea.incident";

/// Die sechs Objektfamilien mit Schema-Identifikator und Objekttyp-Tag.
const FORMAT_FAMILIES: [(&str, &str, u8); 6] = [
    ("eip", "eip-v1", 1),
    ("eag", "eag-v1", 2),
    ("esr", "esr-v1", 3),
    ("ecp", "ecp-v1", 4),
    ("etb", "etb-v1", 5),
    ("eds", "eds-v1", 6),
];

/// Die sechs gueltigen Objekte samt der Teile, aus denen die Mutationen
/// entstehen.
struct FormatObjects {
    objects: [Vec<u8>; 6],
    cose_payloads: [Vec<u8>; 6],
    eip_manifest_exact: Vec<u8>,
    eip_ciphertext: Vec<u8>,
    eip_ciphertext_hash: [u8; 32],
    eip_writer_signature: Vec<u8>,
    organization_needle: Vec<u8>,
}

impl FormatObjects {
    /// Das Objekt der Familie mit diesem Namen.
    fn object(&self, family: &str) -> &[u8] {
        &self.objects[format_family_index(family)]
    }

    /// Der COSE-Nutzinhalt, dessen Mutation die Bindung bricht.
    fn cose_payload(&self, family: &str) -> &[u8] {
        &self.cose_payloads[format_family_index(family)]
    }
}

/// Der Index einer Familie in [`FORMAT_FAMILIES`].
fn format_family_index(family: &str) -> usize {
    FORMAT_FAMILIES
        .iter()
        .position(|(name, _, _)| *name == family)
        .unwrap_or_else(|| panic!("{family} is not one of the six object families"))
}

/// Ein Signierer aus deklarierter Testentropie.
fn format_signer(seed: [u8; 32]) -> CoseSigner {
    CoseSigner::from_secret(SecretBytes::new(seed))
}

/// Der kanonische oeffentliche COSE-Key zu einem Ed25519-Seed.
fn format_public_key(seed: [u8; 32]) -> CanonicalPublicCoseKey {
    let verifying = SigningKey::from_bytes(&seed).verifying_key();
    CanonicalPublicCoseKey::ed25519(*verifying.as_bytes())
        .expect("a declared Ed25519 seed yields a canonical public key")
}

/// Die sechs gueltigen Objekte, deterministisch erzeugt.
///
/// # Panics
///
/// Wenn eine der Konstruktionen fehlschlaegt. Das waere ein Programmierfehler
/// dieser Crate, kein Laufzeitzustand.
fn format_objects() -> FormatObjects {
    let writer = format_signer(TEST_ENTROPY_DEVICE_ED25519_SEED);
    let writer_thumbprint = format_public_key(TEST_ENTROPY_DEVICE_ED25519_SEED).thumbprint();
    let server = format_signer(TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED);
    let server_thumbprint =
        format_public_key(TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED).thumbprint();
    let root = format_signer(TEST_ENTROPY_ROOT_ED25519_SEED);
    let root_key = format_public_key(TEST_ENTROPY_ROOT_ED25519_SEED);

    // `.eip`. Der Ciphertext ist ein ECHTER AEAD-Wert: `aead_seal` nimmt die
    // Nonce als Parameter, also ist er reproduzierbar. Die AAD haengt am
    // Manifestkern, der Manifestkern nur an der LAENGE des Ciphertexts —
    // deshalb der Vorlauf mit einem gleich langen Platzhalter.
    let ciphertext_length = FORMAT_PLAINTEXT.len() + ea_crypto::AEAD_OVERHEAD;
    let probe = format_manifest_core(&vec![0_u8; ciphertext_length]);
    let aad = payload_aad(probe.exact_bytes());
    let ciphertext = aead_seal(
        &SecretBytes::new(TEST_ENTROPY_CONTENT_ENCRYPTION_KEY),
        &SecretBytes::new(TEST_ENTROPY_AEAD_NONCE),
        SecretVec::new(FORMAT_PLAINTEXT.to_vec()),
        &aad,
    )
    .expect("sealing the frozen plaintext cannot fail");
    let manifest = format_manifest_core(&ciphertext);
    let eip_manifest_exact = manifest.exact_bytes().to_vec();
    let signed = SignedManifestV1::new(manifest, &ciphertext)
        .expect("the manifest matches its own ciphertext");
    let eip_ciphertext_hash = *signed.ciphertext_hash().as_bytes();
    let writer_signature = writer
        .sign_record(signed.exact_bytes())
        .expect("signing the frozen signed manifest cannot fail");
    let eip_record_digest = record_digest(signed.exact_bytes()).as_bytes().to_vec();
    let entry = EntryPackageV1::new(signed.clone(), ciphertext.clone(), writer_signature.clone())
        .expect("the frozen entry package is well formed");
    let entry_hash = entry.entry_hash();
    let eip = encode_entry_package(&entry)
        .expect("encoding the frozen entry package cannot fail")
        .into_vec();

    // `.eag`. Kapselungswert und umschlossener CEK sind die EINMAL erzeugten
    // Bytes der Familie `crypto/suite-1`; `hpke_seal` zieht bei jedem Aufruf
    // frische Entropie und ist von aussen nicht reproduzierbar. Sie sind hier
    // FUELLUNG vorgeschriebener Laenge und NICHT an den Grant-Kontext dieses
    // Objekts gebunden — `hpke_open` gegen diesen Kontext liefert gemessen
    // `EA-CRYPTO-HPKE-OPEN`. `ea-format` oeffnet sie nie; die Bindung eines
    // Grants an seinen Empfaenger belegt die Familie `grants`, ihre
    // Entkapselung die Familie `crypto/suite-1`. Siehe [`format_source`].
    let grant_body = GrantBodyV1::new(GrantBodyFieldsV1 {
        organization_id: format_organization_id(),
        chain_id: ChainId::try_from(FORMAT_CHAIN_ID.as_slice()).expect("16 bytes"),
        entry_hash,
        kind: GrantKindV1::Initial,
        purpose: GrantPurposeV1::Reader,
        recipient_key_thumbprint: KeyThumbprint::try_from(
            FORMAT_RECIPIENT_KEY_THUMBPRINT.as_slice(),
        )
        .expect("32 bytes"),
        recipient_certificate_hash: CertificateHash::try_from(
            FORMAT_RECIPIENT_CERTIFICATE_HASH.as_slice(),
        )
        .expect("32 bytes"),
        issuer_key_thumbprint: writer_thumbprint,
        issuer_certificate_hash: format_writer_certificate_hash(),
        registry_version: RegistryVersion::new(FORMAT_REGISTRY_VERSION),
        registry_head_hash: Hash32::try_from(FORMAT_REGISTRY_HEAD_HASH.as_slice())
            .expect("32 bytes"),
        created_at_device: UnixMillis::new(FORMAT_DEVICE_TIME_MS),
        original_recovery_grant_object_hash: None,
        grant_authorization_object_hash: None,
        encapsulated_key: decode(HPKE_ENCAPSULATED_KEY)
            .try_into()
            .expect("the frozen encapsulated key is 32 bytes"),
        wrapped_cek: decode(HPKE_WRAPPED_CEK)
            .try_into()
            .expect("the frozen wrapped CEK is 48 bytes"),
    })
    .expect("the frozen grant body is well formed");
    let eag_grant_digest = grant_digest(grant_body.exact_bytes()).as_bytes().to_vec();
    let grant_signature = writer
        .sign_initial_grant(grant_body.exact_bytes())
        .expect("signing the frozen grant body cannot fail");
    let grant = GrantV1::new(grant_body, grant_signature).expect("the frozen grant is well formed");
    let eag = encode_grant(&grant)
        .expect("encoding the frozen grant cannot fail")
        .into_vec();

    // `.esr`.
    let receipt_core = ReceiptCoreV1::new(ReceiptCoreFieldsV1 {
        organization_id: format_organization_id(),
        chain_id: ChainId::try_from(FORMAT_CHAIN_ID.as_slice()).expect("16 bytes"),
        chain_sequence: ChainSequence::new(0),
        entry_hash,
        entry_object_hash: object_hash(&eip),
        previous_entry_hash: None,
        registry_version: RegistryVersion::new(FORMAT_REGISTRY_VERSION),
        registry_head_hash: Hash32::try_from(FORMAT_REGISTRY_HEAD_HASH.as_slice())
            .expect("32 bytes"),
        policy_object_hash: ObjectHash::try_from(FORMAT_POLICY_OBJECT_HASH.as_slice())
            .expect("32 bytes"),
        initial_grant_plan_hash: Hash32::try_from(FORMAT_INITIAL_GRANT_PLAN_HASH.as_slice())
            .expect("32 bytes"),
        initial_grant_object_hashes: vec![object_hash(&eag)],
        accepted_at_server: UnixMillis::new(FORMAT_SERVER_TIME_MS),
        evidence_due_at: None,
        server_key_thumbprint: server_thumbprint,
        server_certificate_hash: format_server_certificate_hash(),
    })
    .expect("the frozen receipt core is well formed");
    let esr_receipt_digest = receipt_digest(receipt_core.exact_bytes())
        .as_bytes()
        .to_vec();
    let receipt_signature = server
        .sign_receipt(receipt_core.exact_bytes())
        .expect("signing the frozen receipt core cannot fail");
    let receipt =
        ReceiptV1::new(receipt_core, receipt_signature).expect("the frozen receipt is well formed");
    let esr = encode_receipt(&receipt)
        .expect("encoding the frozen receipt cannot fail")
        .into_vec();

    // `.ecp`. Der COSE-Nutzinhalt ist hier der Kern SELBST, nicht sein Digest;
    // er steht deshalb ZWEIMAL im Objekt, und die Mutation muss das zweite
    // Vorkommen treffen.
    let checkpoint_core = CheckpointCoreV1::new(CheckpointCoreFieldsV1 {
        organization_id: format_organization_id(),
        chain_id: ChainId::try_from(FORMAT_CHAIN_ID.as_slice()).expect("16 bytes"),
        covered_from_sequence: ChainSequence::new(0),
        covered_through_sequence: ChainSequence::new(0),
        head_entry_hash: entry_hash,
        registry_head_hash: Hash32::try_from(FORMAT_REGISTRY_HEAD_HASH.as_slice())
            .expect("32 bytes"),
        issued_at_server: UnixMillis::new(FORMAT_SERVER_TIME_MS),
        previous_evidence_hash: None,
    })
    .expect("the frozen checkpoint core is well formed");
    let ecp_cose_payload = checkpoint_core.exact_bytes().to_vec();
    let checkpoint_signature = server
        .sign_checkpoint(
            format_server_certificate_hash(),
            checkpoint_core.exact_bytes(),
        )
        .expect("signing the frozen checkpoint core cannot fail");
    let evidence = EvidenceObjectV1::standard(checkpoint_core, checkpoint_signature)
        .expect("the frozen checkpoint object is well formed");
    let ecp = encode_evidence(&evidence)
        .expect("encoding the frozen checkpoint cannot fail")
        .into_vec();

    // `.etb`. Das initiale Wurzelzertifikat ist der einzige Vertrauensbaustein
    // ohne Vorgaenger und damit der kleinste vollstaendige Vektor.
    let trust_payload = TrustPayloadV1::initial_root_certificate(RootCertificateFieldsV1 {
        organization_id: format_organization_id(),
        root_public_cose_key: root_key.to_deterministic_cbor(),
        root_key_thumbprint: root_key.thumbprint(),
        previous_root_certificate_object_hash: None,
        effective_from_registry_version: RegistryVersion::new(FORMAT_REGISTRY_VERSION),
    })
    .expect("the frozen root certificate payload is well formed");
    let etb_trust_digest = trust_digest(trust_payload.exact_digest_input())
        .as_bytes()
        .to_vec();
    let trust_signature = root
        .sign_initial_root(&etb_trust_digest)
        .expect("signing the frozen trust digest cannot fail");
    let trust = TrustObjectV1::new(trust_payload, vec![trust_signature])
        .expect("the frozen trust object is well formed");
    let etb = encode_trust(&trust)
        .expect("encoding the frozen trust object cannot fail")
        .into_vec();

    // `.eds`. Derselbe signierte Manifestkern wie im `.eip`, ohne Ciphertext.
    let stub = DestroyedEntryStubV1::new(
        signed,
        writer_signature.clone(),
        object_hash(&eip),
        DestructionId::try_from(FORMAT_DESTRUCTION_ID.as_slice()).expect("16 bytes"),
        ObjectHash::try_from(FORMAT_DESTRUCTION_AUTHORIZATION_OBJECT_HASH.as_slice())
            .expect("32 bytes"),
    )
    .expect("the frozen destroyed entry stub is well formed");
    let eds = encode_destroyed_entry_stub(&stub)
        .expect("encoding the frozen stub cannot fail")
        .into_vec();

    FormatObjects {
        objects: [eip, eag, esr, ecp, etb, eds],
        cose_payloads: [
            eip_record_digest.clone(),
            eag_grant_digest,
            esr_receipt_digest,
            ecp_cose_payload,
            etb_trust_digest,
            eip_record_digest,
        ],
        eip_manifest_exact,
        eip_ciphertext: ciphertext,
        eip_ciphertext_hash,
        eip_writer_signature: writer_signature,
        organization_needle: FORMAT_ORGANIZATION_ID.to_vec(),
    }
}

/// Die Organisationskennung als getypter Wert.
fn format_organization_id() -> OrganizationId {
    OrganizationId::try_from(FORMAT_ORGANIZATION_ID.as_slice()).expect("16 bytes")
}

/// Der Zertifikatshash des Schreibers als getypter Wert.
fn format_writer_certificate_hash() -> CertificateHash {
    CertificateHash::try_from(FORMAT_WRITER_CERTIFICATE_HASH.as_slice()).expect("32 bytes")
}

/// Der Zertifikatshash der Serverseite als getypter Wert.
fn format_server_certificate_hash() -> CertificateHash {
    CertificateHash::try_from(FORMAT_SERVER_CERTIFICATE_HASH.as_slice()).expect("32 bytes")
}

/// Der Manifestkern zu einem Ciphertext dieser Laenge.
fn format_manifest_core(ciphertext: &[u8]) -> ManifestCoreV1 {
    ManifestCoreV1::new(
        ManifestCoreFieldsV1 {
            organization_id: format_organization_id(),
            chain_id: ChainId::try_from(FORMAT_CHAIN_ID.as_slice()).expect("16 bytes"),
            chain_sequence: ChainSequence::new(0),
            previous_entry_hash: None,
            writer_certificate_hash: format_writer_certificate_hash(),
            writer_transition_event_hash: None,
            registry_version: RegistryVersion::new(FORMAT_REGISTRY_VERSION),
            registry_head_hash: FORMAT_REGISTRY_HEAD_HASH,
            initial_grant_plan_hash: FORMAT_INITIAL_GRANT_PLAN_HASH,
            nonce: TEST_ENTROPY_AEAD_NONCE,
        },
        ciphertext,
    )
    .expect("the frozen manifest core is well formed")
}

/// Das Manifest der gueltigen Objekte.
///
/// # Panics
///
/// Wenn eine der Konstruktionen dieser Datei fehlschlaegt.
#[must_use]
pub fn format_v1_valid_manifest() -> VectorManifest {
    let built = format_objects();
    let entries = FORMAT_FAMILIES
        .iter()
        .map(|(family, schema_id, _)| {
            let bytes = built.object(family).to_vec();
            let hash = *object_hash(&bytes).as_bytes();
            format_entry(
                &format!("{family}/valid"),
                schema_id,
                format_source(),
                Vec::new(),
                digest_map(&[("objectHash", hash)]),
                bytes,
                ExpectedOutcome::Accepted,
            )
        })
        .collect();
    VectorManifest {
        family: FORMAT_FAMILY.to_owned(),
        version: FORMAT_V1_VALID_VERSION.to_owned(),
        entries,
    }
}

/// Die Herkunft eines Vektors dieser Familie: durchweg der Erzeuger.
///
/// AUCH FUER `.eag`, und das ist eine bewusste Entscheidung. Kapselungswert und
/// umschlossener CEK des Grants sind zwar EINMAL von `hpke_seal` gezogene
/// Bytes — aber dieser Erzeuger zieht sie nicht, er LIEST sie als feste
/// Konstanten. Seine Ausgabe ist damit deterministisch regenerierbar, und genau
/// das sagt [`VectorSource::GeneratorCommit`] an.
///
/// [`VectorSource::FrozenOnce`] waere hier sogar FALSCH. Sein Feld
/// `verified_via` benennt die Richtung, in der die Bytes nachgeprueft werden,
/// und `hpke_open` gegen den Grant-Kontext DIESES Objekts liefert gemessen
/// `EA-CRYPTO-HPKE-OPEN`: die 80 Byte wurden unter `hpke_info`/`hpke_aad` des
/// Urbilds von `crypto/suite-1` gekapselt, nicht unter dem 17-Feld-Kontext
/// dieses Grants. Ihre Entkapselung ist in der Familie `crypto/suite-1`
/// nachgewiesen und gehoert dorthin. `ea-format` oeffnet sie nie; auf dieser
/// Ebene sind sie zwei Bytestrings vorgeschriebener Laenge, und die
/// kryptografische Bindung eines Grants an seinen Empfaenger ist der
/// Liefergegenstand der Familie `grants`.
fn format_source() -> VectorSource {
    VectorSource::GeneratorCommit(FORMAT_GENERATOR.to_owned())
}

/// Das Manifest der Ablehnungsvektoren.
///
/// # Panics
///
/// Wenn eine der Konstruktionen dieser Datei fehlschlaegt.
#[must_use]
pub fn format_v1_invalid_manifest() -> VectorManifest {
    let built = format_objects();
    let mut entries = Vec::new();

    for (family, schema_id, tag) in FORMAT_FAMILIES {
        let source = built.object(family).to_vec();
        let digests = digest_map(&[("sourceObjectHash", *object_hash(&source).as_bytes())]);

        // Magic. Das dritte Byte des Bytestrings `EA1\0`.
        let mut magic = source.clone();
        magic[2] = b'D';
        entries.push(format_entry(
            &format!("{family}/magic-byte-flip"),
            schema_id,
            format_source(),
            source.clone(),
            digests.clone(),
            magic,
            format_rejected("EA-FORMAT-PREFIX"),
        ));

        // Objekttyp-Tag. Der Parser leitet daraus den Rumpfparser ab; ein
        // fremdes Tag schickt den Rumpf in die falsche Familie.
        let mut retagged = source.clone();
        retagged[6] = tag % 6 + 1;
        entries.push(format_entry(
            &format!("{family}/object-type-tag"),
            schema_id,
            format_source(),
            source.clone(),
            digests.clone(),
            retagged,
            format_rejected(format_object_type_tag_code(family)),
        ));

        // Objektversion.
        let mut versioned = source.clone();
        versioned[7] = 2;
        entries.push(format_entry(
            &format!("{family}/object-version"),
            schema_id,
            format_source(),
            source.clone(),
            digests.clone(),
            versioned,
            format_rejected("EA-FORMAT-UNKNOWN-VERSION"),
        ));

        // Unbekanntes kritisches Feld: der Erweiterungsschlitz ist leer und
        // MUSS leer bleiben.
        let mut extended = source[..8].to_vec();
        extended.extend_from_slice(&[0x81, 0x00]);
        extended.extend_from_slice(&source[9..]);
        entries.push(format_entry(
            &format!("{family}/critical-extension"),
            schema_id,
            format_source(),
            source.clone(),
            digests.clone(),
            extended,
            format_rejected("EA-FORMAT-CRITICAL-EXTENSION"),
        ));

        // COSE-Bindung. Mutiert wird der NUTZINHALT der Signaturstruktur, nicht
        // ihre 64 Signaturbytes: `ea-format` prueft die Bindung, nicht die
        // Ed25519-Rechnung. Ein Bitflip in den Signaturbytes allein bliebe auf
        // dieser Ebene unentdeckt und wird erst von `ea-verify` gefunden.
        let mutated = format_flip_last_occurrence(&source, built.cose_payload(family));
        entries.push(format_entry(
            &format!("{family}/cose-payload-byte-flip"),
            schema_id,
            format_source(),
            source.clone(),
            digests.clone(),
            mutated,
            format_rejected("EA-FORMAT-COSE"),
        ));
    }

    // Manifest und Ciphertext.
    let eip = built.object("eip").to_vec();
    let eip_digests = digest_map(&[("sourceObjectHash", *object_hash(&eip).as_bytes())]);
    entries.push(format_entry(
        "eip/signed-manifest-byte-flip",
        "eip-v1",
        format_source(),
        eip.clone(),
        eip_digests.clone(),
        format_flip_last_occurrence(&eip, &built.organization_needle),
        format_rejected("EA-FORMAT-COSE"),
    ));
    entries.push(format_entry(
        "eip/ciphertext-byte-flip",
        "eip-v1",
        format_source(),
        eip.clone(),
        eip_digests.clone(),
        format_flip_last_occurrence(&eip, &built.eip_ciphertext),
        format_rejected("EA-FORMAT-SHAPE"),
    ));
    let eds = built.object("eds").to_vec();
    entries.push(format_entry(
        "eds/signed-manifest-byte-flip",
        "eds-v1",
        format_source(),
        eds.clone(),
        digest_map(&[("sourceObjectHash", *object_hash(&eds).as_bytes())]),
        format_flip_last_occurrence(&eds, &built.organization_needle),
        format_rejected("EA-FORMAT-COSE"),
    ));

    // Die CBOR-Ebene. Diese Vektoren sind SYNTHETISCH: die sechs Familien sind
    // durchweg Arrays, ihre einzige Map sitzt im geschuetzten COSE-Kopf und
    // damit in einem Bytestring, in den der aeussere Scanner nicht hineinlaeuft.
    // Ein doppelter Map-Key ist deshalb nur im Rumpfschlitz darstellbar.
    for (name, body, code) in [
        (
            "cbor/duplicate-map-key",
            vec![0xa2, 0x01, 0x01, 0x01, 0x02],
            "EA-CBOR-DUPLICATE-KEY",
        ),
        (
            "cbor/non-canonical-length",
            vec![0x18, 0x05],
            "EA-CBOR-NONMINIMAL",
        ),
        (
            "cbor/nesting-depth-17",
            format_nested_arrays(16),
            "EA-CBOR-DEPTH-LIMIT",
        ),
        (
            "cbor/container-items-over-limit",
            format_array_header(FORMAT_CONTAINER_ITEMS_OVER_LIMIT),
            "EA-CBOR-CONTAINER-LIMIT",
        ),
        (
            "cbor/total-items-over-limit",
            format_saturated_array(),
            "EA-CBOR-TOKEN-LIMIT",
        ),
        (
            "limits/cbor-text-or-bytes-plus-one",
            format_byte_string_header(FORMAT_TEXT_OR_BYTES_OVER_LIMIT),
            "EA-CBOR-ITEM-LIMIT",
        ),
    ] {
        let mut object = vec![0x85, 0x44, b'E', b'A', b'1', 0, 1, 1, 0x80];
        object.extend_from_slice(&body);
        entries.push(format_entry(
            name,
            "format-object-v1",
            VectorSource::GeneratorCommit(FORMAT_GENERATOR.to_owned()),
            Vec::new(),
            BTreeMap::new(),
            object,
            format_rejected(code),
        ));
    }

    // Die Ciphertextgrenze, um genau ein Byte ueberschritten. Der Wert steht im
    // Manifestkern; der Kern wird an seinem letzten Feldpaar nachgeschnitten,
    // damit der Vektor klein bleibt statt ein Megabyte zu tragen.
    entries.push(format_entry(
        "limits/ciphertext-length-plus-one",
        "eip-v1",
        format_source(),
        eip.clone(),
        eip_digests,
        format_eip_with_declared_ciphertext_length(&built, FORMAT_CIPHERTEXT_OVER_LIMIT),
        format_rejected("EA-FORMAT-CIPHERTEXT-LENGTH"),
    ));

    // Die Klartextgrenze. Sie ist KEINE Formatgrenze: `ea-format` oeffnet den
    // AEAD-Ciphertext nie. `crates/ea-schema/src/v1.rs` fuehrt sie, und
    // `SchemaRegistry::validate` entscheidet vor jeder eingabegrossen
    // Allokation allein an der Laenge — der Inhalt dieser Bytes ist deshalb
    // gleichgueltig.
    entries.push(format_entry(
        "limits/plaintext-plus-one",
        FORMAT_SCHEMA_CHECKED_SCHEMA_ID,
        VectorSource::GeneratorCommit(FORMAT_GENERATOR.to_owned()),
        Vec::new(),
        BTreeMap::new(),
        vec![0xff; FORMAT_PLAINTEXT_OVER_LIMIT],
        format_rejected("EA-SCHEMA-PLAINTEXT-LIMIT"),
    ));

    VectorManifest {
        family: FORMAT_FAMILY.to_owned(),
        version: FORMAT_V1_INVALID_VERSION.to_owned(),
        entries,
    }
}

/// Der GEMESSENE Fehlercode eines vertauschten Objekttyp-Tags.
///
/// Das Tag ist KEIN Widerspruch zwischen zwei Feldern: `preflight` liest es aus
/// Byte 6, und `validate_outer` stellt genau dieses Byte gegen sich selbst.
/// `EA-FORMAT-TAG-MISMATCH` ist ueber `decode_exact_object` deshalb
/// unerreichbar. Was zurueckkommt, entscheidet der Rumpfparser der FREMDEN
/// Familie — je Quellfamilie ein anderer Wert, hier einzeln gemessen und nicht
/// hergeleitet.
fn format_object_type_tag_code(family: &str) -> &'static str {
    match family {
        // Alle sechs GEMESSEN, nicht geschlossen: der Rumpf der Quellfamilie
        // scheitert im fremden Rumpfparser an der Elementzahl des aeusseren
        // Arrays, und das ist in allen sechs Richtungen dieselbe Aussage.
        "eip" | "eag" | "esr" | "ecp" | "etb" | "eds" => "EA-FORMAT-SHAPE",
        other => panic!("{other} is not one of the six object families"),
    }
}

/// Eine Ablehnung mit genau diesem Code.
fn format_rejected(code: &str) -> ExpectedOutcome {
    ExpectedOutcome::Rejected {
        error_code: code.to_owned(),
    }
}

/// Kippt das erste Bit des LETZTEN Vorkommens von `needle`.
///
/// Das letzte Vorkommen, nicht das erste: im `.ecp` steht der Checkpointkern
/// zweimal — einmal als Element und einmal als COSE-Nutzinhalt —, und nur die
/// zweite Stelle bricht die Bindung statt der Struktur.
fn format_flip_last_occurrence(bytes: &[u8], needle: &[u8]) -> Vec<u8> {
    assert!(!needle.is_empty(), "the needle must not be empty");
    let at = (0..=bytes.len().saturating_sub(needle.len()))
        .rev()
        .find(|start| bytes[*start..*start + needle.len()] == *needle)
        .unwrap_or_else(|| panic!("the object does not carry the {} byte needle", needle.len()));
    let mut mutated = bytes.to_vec();
    mutated[at] ^= 1;
    mutated
}

/// `depth` ineinandergeschachtelte einelementige Arrays mit einer 0 im Kern.
fn format_nested_arrays(depth: usize) -> Vec<u8> {
    let mut bytes = vec![0x81; depth];
    bytes.push(0x00);
    bytes
}

/// Ein kanonischer CBOR-Arraykopf ueber `length` Elemente.
fn format_array_header(length: u64) -> Vec<u8> {
    format_header(0x80, length)
}

/// Ein kanonischer CBOR-Bytestringkopf ueber `length` Byte, OHNE Nutzlast.
///
/// Der Scanner prueft die angekuendigte Laenge, BEVOR er sie liest
/// (`crates/ea-cbor/src/decode.rs`). Ein Vektor ueber der Grenze braucht seine
/// Nutzlast deshalb nicht mitzubringen und bleibt zwanzig Byte gross statt
/// einem Megabyte.
fn format_byte_string_header(length: u64) -> Vec<u8> {
    format_header(0x40, length)
}

/// Ein KANONISCHER CBOR-Kopf: kleinste Argumentbreite, Haupttyp aufgepraegt.
///
/// Die kleinste Breite ist keine Kosmetik: `ea-cbor` lehnt jede weitere Form
/// als `EA-CBOR-NONMINIMAL` ab, und ein Vektor, der schon daran scheitert,
/// haette die Grenze, die er belegen soll, nie erreicht.
fn format_header(major: u8, length: u64) -> Vec<u8> {
    let mut bytes = cbor_unsigned(length);
    bytes[0] |= major;
    bytes
}

/// Ein Array GENAU an der Containergrenze, das die Gesamtelementzahl sprengt.
fn format_saturated_array() -> Vec<u8> {
    let mut bytes = format_array_header(FORMAT_CONTAINER_ITEMS_AT_LIMIT);
    bytes.resize(
        bytes.len()
            + usize::try_from(FORMAT_CONTAINER_ITEMS_AT_LIMIT)
                .expect("the frozen container length fits in a usize"),
        0x00,
    );
    bytes
}

/// Ein `.eip`, dessen Manifestkern eine andere Ciphertextlaenge ANKUENDIGT.
///
/// Der Kern endet auf `<laenge> <leeres array>`; nur dieses Paar wird ersetzt.
/// Das Objekt wird danach von Hand wieder zusammengesetzt, weil `ea-format`
/// eine widerspruechliche Ankuendigung — zu Recht — nicht kodiert.
fn format_eip_with_declared_ciphertext_length(built: &FormatObjects, length: u64) -> Vec<u8> {
    let mut core = built.eip_manifest_exact.clone();
    let mut declared = cbor_unsigned(
        u64::try_from(built.eip_ciphertext.len()).expect("the frozen ciphertext length fits"),
    );
    declared.push(0x80);
    assert!(
        core.ends_with(&declared),
        "the frozen manifest core must end in its ciphertext length and an empty extension array"
    );
    core.truncate(core.len() - declared.len());
    core.extend_from_slice(&cbor_unsigned(length));
    core.push(0x80);

    let mut signed = vec![0x82];
    signed.extend_from_slice(&core);
    signed.extend_from_slice(&cbor_bytes(&built.eip_ciphertext_hash));

    let mut body = vec![0x83];
    body.extend_from_slice(&signed);
    body.extend_from_slice(&cbor_bytes(&built.eip_ciphertext));
    body.extend_from_slice(&built.eip_writer_signature);

    let mut object = vec![0x85, 0x44, b'E', b'A', b'1', 0, 1, 1, 0x80];
    object.extend_from_slice(&body);
    object
}

/// Baut einen Manifesteintrag der Objektfamilien und leitet seinen Dateipfad
/// aus dem Namen ab.
fn format_entry(
    name: &str,
    schema_id: &str,
    source: VectorSource,
    input_bytes: Vec<u8>,
    intermediate_digests: BTreeMap<String, [u8; 32]>,
    object_bytes: Vec<u8>,
    expected_outcome: ExpectedOutcome,
) -> VectorEntry {
    VectorEntry {
        name: name.to_owned(),
        schema_id: schema_id.to_owned(),
        suite_id: FORMAT_SUITE_ID.to_owned(),
        source,
        input_bytes,
        intermediate_digests,
        object_bytes,
        expected_outcome,
        file: format!("{name}.bin"),
        scope_note: None,
    }
}

// ---------------------------------------------------------------------------
// Vektorfamilie trust/v1
// ---------------------------------------------------------------------------
//
// Der Negativumfang steht woertlich in `design.md` §22.1, letzter Punkt. Jeder
// dort genannte Fall bekommt genau ein Verzeichnis `<stufe>/<fall>/`, und die
// Stufe im Namen sagt, welche Pipeline ueber den Fall entscheidet:
//
// * `object/`    — `ea_format::decode_exact_object` auf genau einem Objekt,
// * `anchor/`    — `ea_trust::decode_trust_anchor` auf den Anchor-Bytes,
// * `bootstrap/` — zusaetzlich `ea_trust::verify_trust`,
// * `registry/`  — zusaetzlich `ea_trust::verify_registry_candidate`.
//
// DIESE CRATE FUEHRT KEINE DIESER PIPELINES AUS. Sie haengt bewusst nicht von
// `ea-trust` ab: der Erzeuger erzeugt Bytes und BEHAUPTET ein Urteil,
// `ea-system-tests` MISST es. Waeren Erzeugung und Messung dieselbe Crate, waere
// jedes Urteil eine Tautologie.
//
// Jeder Fall ist vollstaendig: er traegt alle Objekte, die seine Stufe braucht.
// Das wiederholt die Bootstrap-Objekte ueber die Faelle hinweg, und das ist der
// Preis dafuer, dass eine fremde Implementierung einen Fall pruefen kann, ohne
// ein Vererbungsschema nachzubauen.

/// Der Familienname der Trust-Vektoren.
pub const TRUST_FAMILY: &str = "trust";

/// Der Versionsordner der Trust-Vektoren.
pub const TRUST_V1_VERSION: &str = "v1";

/// Die Wurzel der Trust-Vektoren, relativ zur Arbeitsbaumwurzel.
pub const TRUST_V1_ROOT: &str = "vectors/trust/v1";

/// Die Herkunftsangabe der Trust-Vektoren.
const TRUST_GENERATOR: &str = "ea-testkit::trust_v1_manifest";

/// Der Suite-Identifikator der Trust-Vektoren, EINGEFROREN.
const TRUST_SUITE_ID: &str = "EINSATZARCHIV-SUITE-1";

/// Der Schema-Identifikator eines Vertrauensbausteins.
const TRUST_OBJECT_SCHEMA_ID: &str = "etb-v1";

/// Der Schema-Identifikator der finalen Anchor-Bytes.
const TRUST_ANCHOR_SCHEMA_ID: &str = "trust-anchor-v1";

/// Der Schema-Identifikator der bestaetigten Anchor-Vorstufe.
const TRUST_PRE_ANCHOR_SCHEMA_ID: &str = "trust-anchor-pre-v1";

/// Die Organisationskennung aller Trust-Vektoren.
const TRUST_ORGANIZATION_ID: [u8; 16] = [0x21; 16];

/// Die Kettenkennung aller Trust-Vektoren.
const TRUST_CHAIN_ID: [u8; 16] = [0x31; 16];

/// Der Genesis-Eintragshash im finalen Anchor.
const TRUST_GENESIS_ENTRY_HASH: [u8; 32] = [0x44; 32];

/// Die Reichweitennotiz, die JEDER `organizationAdminAuthorization`-Eintrag
/// traegt.
///
/// Ohne sie liest sich der eingefrorene Vektor als Beleg fuer §7.5 des
/// Web-Reader-Specs, und das ist er nicht: diese Familie bindet KEINEN
/// Ziel-Transport-Public-Key-Fingerprint. Sie hat Signatur-Kardinalitaet 1
/// (`schemas/archive/v1/trust.cddl`) und fuenfzehn Felder mit leerem
/// Erweiterungsarray an Position 15. Die in §7.5 geforderte Bindung kommt als
/// EIGENE 2-of-N-Familie nach dem Vorbild von
/// `grantAuthorization`/`destructionAuthorization` (`[2* cose-sign1-v1]`) in
/// Stufe 5 als v1.1.
const TRUST_ADMIN_AUTHORIZATION_SCOPE_NOTE: &str = "Diese Familie belegt NICHT die Bindung eines Ziel-Transport-Public-Key-Fingerprints aus Web-Reader-Spec §7.5. organizationAdminAuthorization bleibt bei Signatur-Kardinalitaet 1 und fuenfzehn Feldern; die 2-of-N-Bindung entsteht als eigene Objektfamilie nach dem Vorbild von grantAuthorization/destructionAuthorization in Stufe 5 als v1.1.";

/// Der unzulaessige Action-Code des Negativvektors.
///
/// LITERAL `200`, und der Nachbarwert `7` ist verboten: `trust.cddl` deklariert
/// `action-code: 0..6`, und eine v1.1-Erweiterung des Wertebereichs wuerde einen
/// eingefrorenen `7`-Vektor von `abgelehnt` nach `akzeptiert` drehen.
const TRUST_INVALID_ACTION_CODE: u64 = 200;

/// Das Literal des Subtype-Negativvektors.
///
/// Jeder Name, der spaeter eine echte Trust-Objektfamilie werden koennte, ist
/// hier verboten; `xxUnknownxx` kann keine werden.
const TRUST_UNKNOWN_SUBTYPE: &str = "xxUnknownxx";

/// Die Zeichenkette des Admin-Authorization-Subtypes.
const TRUST_ADMIN_AUTHORIZATION_SUBTYPE: &str = "organizationAdminAuthorization";

/// Die Faelle mit Katalog: Bootstrap, Anchor und Registry.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TrustCaseV1 {
    AcceptedBootstrapAndFirstHead,
    AcceptedAdminRotation,
    RejectedAuthorizedCoreHashMismatch,
    RejectedRootOnlySignedByAdmin,
    RejectedAdminOnlySignedByRoot,
    RejectedReusedAuthorizationIdAndNonce,
    RejectedSignerContextDeviation,
    RejectedNullContextAfterFirstHead,
    RejectedUnpinnedAdminPair,
    RejectedHashDivergentAdminCertificate,
    RejectedMispairedAdminBinding,
    RejectedSharedOsAndInstanceKey,
    RejectedMutatedPreAnchorField,
    RejectedWrongBootstrapAnchorHash,
}

/// Alle Faelle mit Katalog, ihr Verzeichnis und ihr BEHAUPTETES Urteil.
///
/// Das Urteil steht hier als Zeichenkette, nicht als Aufzaehlung von `ea-trust`:
/// wuerde der Erzeuger den Fehlercode importieren, zoege eine Umbenennung den
/// Vektor stillschweigend mit. `ea-system-tests` fuehrt die Pipeline aus und
/// stellt das gemessene Ergebnis gegen diese Zeichenkette.
const TRUST_CASES_V1: [(TrustCaseV1, &str, Option<&str>); 14] = [
    (
        TrustCaseV1::AcceptedBootstrapAndFirstHead,
        "registry/accepted-bootstrap-and-first-head",
        None,
    ),
    (
        TrustCaseV1::AcceptedAdminRotation,
        "registry/accepted-admin-rotation",
        None,
    ),
    (
        TrustCaseV1::RejectedAuthorizedCoreHashMismatch,
        "registry/rejected-authorized-core-hash-mismatch",
        Some("EA-TRUST-ACTION-MISMATCH"),
    ),
    (
        TrustCaseV1::RejectedRootOnlySignedByAdmin,
        "registry/rejected-root-only-signed-by-admin",
        Some("EA-TRUST-SIGNATURE"),
    ),
    (
        TrustCaseV1::RejectedAdminOnlySignedByRoot,
        "registry/rejected-admin-only-signed-by-root",
        Some("EA-TRUST-SIGNATURE"),
    ),
    (
        TrustCaseV1::RejectedReusedAuthorizationIdAndNonce,
        "registry/rejected-reused-authorization-id-and-nonce",
        Some("EA-TRUST-AUTH-REPLAY"),
    ),
    (
        TrustCaseV1::RejectedSignerContextDeviation,
        "registry/rejected-signer-context-deviation",
        Some("EA-TRUST-SIGNATURE"),
    ),
    (
        TrustCaseV1::RejectedNullContextAfterFirstHead,
        "registry/rejected-null-context-after-first-head",
        Some("EA-TRUST-ACTION-MISMATCH"),
    ),
    (
        TrustCaseV1::RejectedUnpinnedAdminPair,
        "bootstrap/rejected-unpinned-admin-pair",
        Some("EA-TRUST-ANCHOR-PIN"),
    ),
    (
        TrustCaseV1::RejectedHashDivergentAdminCertificate,
        "bootstrap/rejected-hash-divergent-admin-certificate",
        Some("EA-TRUST-ANCHOR-PIN"),
    ),
    (
        TrustCaseV1::RejectedMispairedAdminBinding,
        "bootstrap/rejected-mispaired-admin-binding",
        Some("EA-TRUST-BOOTSTRAP-PAIR"),
    ),
    (
        TrustCaseV1::RejectedSharedOsAndInstanceKey,
        "bootstrap/rejected-shared-os-and-instance-key",
        Some("EA-TRUST-BOOTSTRAP-PAIR"),
    ),
    (
        TrustCaseV1::RejectedMutatedPreAnchorField,
        "anchor/rejected-mutated-pre-anchor-field",
        Some("EA-TRUST-ANCHOR-HASH"),
    ),
    (
        TrustCaseV1::RejectedWrongBootstrapAnchorHash,
        "anchor/rejected-wrong-bootstrap-anchor-hash",
        Some("EA-TRUST-ANCHOR-HASH"),
    ),
];

impl TrustCaseV1 {
    /// Das Verzeichnis dieses Falls.
    fn path(self) -> &'static str {
        TRUST_CASES_V1
            .iter()
            .find(|(case, _, _)| *case == self)
            .map(|(_, path, _)| *path)
            .expect("every case is listed in TRUST_CASES_V1")
    }

    /// Das behauptete Urteil dieses Falls.
    fn verdict(self) -> ExpectedOutcome {
        TRUST_CASES_V1
            .iter()
            .find(|(case, _, _)| *case == self)
            .map(|(_, _, code)| match code {
                None => ExpectedOutcome::Accepted,
                Some(code) => ExpectedOutcome::Rejected {
                    error_code: (*code).to_owned(),
                },
            })
            .expect("every case is listed in TRUST_CASES_V1")
    }

    /// Die Stufe dieses Falls.
    fn tier(self) -> &'static str {
        self.path()
            .split_once('/')
            .expect("every case path names its tier")
            .0
    }

    /// Ein Fall, der nur die Anchor-Bytes entscheidet, braucht keinen Katalog.
    fn is_anchor_tier(self) -> bool {
        self.tier() == "anchor"
    }

    /// Ein Fall, der bei `verify_trust` endet, braucht keine Registry-Objekte.
    fn is_registry_tier(self) -> bool {
        self.tier() == "registry"
    }
}

/// Ein benanntes Objekt eines Falls.
struct TrustSlot {
    name: &'static str,
    schema_id: &'static str,
    bytes: Vec<u8>,
}

/// Die Organisationskennung als getypter Wert.
fn trust_organization_id() -> OrganizationId {
    OrganizationId::try_from(TRUST_ORGANIZATION_ID.as_slice()).expect("16 bytes")
}

/// Ein Ed25519-Signierer aus deklarierter Testentropie.
fn trust_signer(seed: [u8; 32]) -> CoseSigner {
    CoseSigner::from_secret(SecretBytes::new(seed))
}

/// Der kanonische oeffentliche COSE-Key zu einem Ed25519-Seed.
fn trust_public_key(seed: [u8; 32]) -> CanonicalPublicCoseKey {
    let verifying = SigningKey::from_bytes(&seed).verifying_key();
    CanonicalPublicCoseKey::ed25519(*verifying.as_bytes())
        .expect("a declared Ed25519 seed yields a canonical public key")
}

/// Ein Hash32 aus einem Fuellbyte.
fn trust_hash32(byte: u8) -> Hash32 {
    Hash32::try_from([byte; 32].as_slice()).expect("32 bytes")
}

/// Das fertige Objekt zu Nutzinhalt und Signaturen.
fn trust_exact_object(payload: TrustPayloadV1, signatures: Vec<Vec<u8>>) -> Vec<u8> {
    encode_trust(
        &TrustObjectV1::new(payload, signatures).expect("the frozen trust object is well formed"),
    )
    .expect("encoding a well formed trust object cannot fail")
    .into_vec()
}

/// Eine COSE_Sign1 im Normalprofil, von Hand kodiert.
///
/// Von Hand, weil `CoseSigner::sign_organization_admin_trust_digest` den
/// Zertifikatshash aus dem Nutzinhalt ABLEITET. Der Negativvektor
/// `rejected-signer-context-deviation` braucht aber genau die Abweichung
/// zwischen beidem, und die ist ueber den bequemen Weg nicht erreichbar.
fn trust_signed_normal(
    seed: [u8; 32],
    certificate_hash: CertificateHash,
    payload: &[u8],
) -> Vec<u8> {
    let public = trust_public_key(seed);
    let protected = ProtectedHeader::normal(
        ContentType::TrustDigest,
        public.thumbprint(),
        certificate_hash,
    );
    let signature = SigningKey::from_bytes(&seed)
        .sign(&protected.sig_structure_bytes(payload))
        .to_bytes();
    let mut encoded = vec![0xd2, 0x84];
    encoded.extend_from_slice(&cbor_bytes(&protected.to_deterministic_cbor()));
    encoded.push(0xa0);
    encoded.extend_from_slice(&cbor_bytes(payload));
    encoded.extend_from_slice(&cbor_bytes(&signature));
    encoded
}

/// Der Digest-Eingang, den eine Admin-Authorization ueber ihren Zielkern
/// bindet.
///
/// Der autorisierte Nutzinhalt ist `[kern, autorisierungshash]`. Der Kern wird
/// hier ohne CBOR-Bibliothek herausgeschnitten: das Array hat zwei Elemente,
/// also ein Kopfbyte, und der Hash ist ein 32-Byte-Bytestring, also vierunddreissig
/// Bytes am Ende.
fn trust_authorized_core_input(payload: &TrustPayloadV1) -> Vec<u8> {
    let exact = payload.exact_payload();
    let tail = exact
        .len()
        .checked_sub(34)
        .expect("an authorized payload carries at least its trailing hash");
    assert_eq!(
        exact[0], 0x82,
        "an authorized payload is a two element array"
    );
    assert_eq!(
        &exact[tail..tail + 2],
        &[0x58, 0x20],
        "an authorized payload ends on a 32 byte string"
    );
    let mut input = vec![0x82];
    input.extend_from_slice(&trust_cbor_text(payload.subtype().as_str()));
    input.extend_from_slice(&exact[1..tail]);
    input
}

/// Eine deterministisch kodierte CBOR-Textzeichenkette beliebiger Laenge unter
/// 256 Zeichen.
///
/// [`cbor_text`] verlangt mindestens vierundzwanzig Zeichen; die Trust-Vektoren
/// tragen auch kurze Zeichenketten wie `policy` und `xxUnknownxx`.
fn trust_cbor_text(value: &str) -> Vec<u8> {
    let length = value.len();
    let mut bytes = if length < 24 {
        vec![0x60 | u8::try_from(length).expect("below 24")]
    } else {
        vec![
            0x78,
            u8::try_from(length).expect("every subtype is shorter than 256 bytes"),
        ]
    };
    bytes.extend_from_slice(value.as_bytes());
    bytes
}

/// Ein deterministisch kodierter CBOR-Arraykopf unter 24 Elementen.
fn trust_cbor_array(length: u64) -> Vec<u8> {
    assert!(length < 24, "no trust vector array holds 24 items or more");
    vec![0x80 | u8::try_from(length).expect("below 24")]
}

/// Das initiale Wurzelzertifikat: der einzige Baustein ohne Vorgaenger.
fn trust_root_certificate() -> Vec<u8> {
    let root_key = trust_public_key(TEST_ENTROPY_ROOT_ED25519_SEED);
    let payload = TrustPayloadV1::initial_root_certificate(RootCertificateFieldsV1 {
        organization_id: trust_organization_id(),
        root_public_cose_key: root_key.to_deterministic_cbor(),
        root_key_thumbprint: root_key.thumbprint(),
        previous_root_certificate_object_hash: None,
        effective_from_registry_version: RegistryVersion::new(1),
    })
    .expect("the frozen root certificate payload is well formed");
    let signature = trust_signer(TEST_ENTROPY_ROOT_ED25519_SEED)
        .sign_initial_root(trust_digest(payload.exact_digest_input()).as_bytes())
        .expect("signing the frozen root certificate cannot fail");
    trust_exact_object(payload, vec![signature])
}

/// Ein Administratorzertifikat der Anchor-Vorstufe, direkt von der Wurzel
/// signiert.
fn trust_initial_admin_certificate(
    root_certificate_hash: CertificateHash,
    seed: [u8; 32],
    device: u8,
    subject: u8,
) -> Vec<u8> {
    let public = trust_public_key(seed);
    let payload = TrustPayloadV1::initial_admin_device_certificate(DeviceCertificateFieldsV1 {
        organization_id: trust_organization_id(),
        device_id: DeviceId::try_from([device; 16].as_slice()).expect("16 bytes"),
        certificate_kind: CertificateKindV1::OrganizationAdmin,
        signing_public_cose_key: Some(public.to_deterministic_cbor()),
        kem_public_cose_key: None,
        signing_key_thumbprint: Some(public.thumbprint()),
        kem_key_thumbprint: None,
        capabilities: vec!["organizationAdminApprove".to_owned()],
        key_protection_profile: KeyProtectionProfileV1::OsWrapped,
        effective_from_sequence: ChainSequence::new(0),
        revoked_from_sequence: None,
        authority_subject_id: Some(
            SubjectId::try_from([subject; 16].as_slice()).expect("16 bytes"),
        ),
    })
    .expect("the frozen admin certificate payload is well formed");
    let signature = trust_signer(TEST_ENTROPY_ROOT_ED25519_SEED)
        .sign_initial_admin_trust_digest(root_certificate_hash, payload.exact_digest_input())
        .expect("signing the frozen admin certificate cannot fail");
    trust_exact_object(payload, vec![signature])
}

/// Ein Operator-Binding der Anchor-Vorstufe.
fn trust_initial_admin_binding(
    root_certificate_hash: CertificateHash,
    admin_certificate_hash: CertificateHash,
    subject: u8,
    os_account: u8,
    instance: u8,
) -> Vec<u8> {
    let payload = TrustPayloadV1::initial_admin_operator_binding(OperatorBindingFieldsV1 {
        organization_id: trust_organization_id(),
        operator_subject_id: OperatorSubjectId::try_from([subject; 16].as_slice())
            .expect("16 bytes"),
        operator_profile_commitment: trust_hash32(subject.wrapping_add(0x30)),
        device_certificate_hash: admin_certificate_hash,
        operator_role: OperatorRoleV1::OrganizationAdmin,
        os_account_binding_hash: trust_hash32(os_account),
        operator_instance_key_thumbprint: KeyThumbprint::from(trust_hash32(instance)),
        effective_from_sequence: ChainSequence::new(0),
        revoked_from_sequence: None,
    })
    .expect("the frozen admin binding payload is well formed");
    let signature = trust_signer(TEST_ENTROPY_ROOT_ED25519_SEED)
        .sign_initial_admin_trust_digest(root_certificate_hash, payload.exact_digest_input())
        .expect("signing the frozen admin binding cannot fail");
    trust_exact_object(payload, vec![signature])
}

/// Die Anchor-Vorstufe nach `EINSATZARCHIV-TRUST-ANCHOR-PRE-v1`.
fn trust_pre_anchor_bytes(
    organization_id: &[u8; 16],
    root_certificate_object_hash: ObjectHash,
    admin_certificates: &[ObjectHash],
    admin_bindings: &[ObjectHash],
) -> Vec<u8> {
    let root_key = trust_public_key(TEST_ENTROPY_ROOT_ED25519_SEED);
    let mut bytes = trust_cbor_array(10);
    bytes.extend_from_slice(&cbor_text("EINSATZARCHIV-TRUST-ANCHOR-PRE-v1"));
    bytes.extend_from_slice(&cbor_unsigned(1));
    bytes.extend_from_slice(&cbor_bytes(organization_id));
    bytes.extend_from_slice(&cbor_bytes(&TRUST_CHAIN_ID));
    bytes.extend_from_slice(&cbor_bytes(&root_key.to_deterministic_cbor()));
    bytes.extend_from_slice(&cbor_bytes(root_key.thumbprint().as_bytes()));
    bytes.extend_from_slice(&cbor_bytes(root_certificate_object_hash.as_bytes()));
    bytes.extend_from_slice(&trust_hash_list(admin_certificates));
    bytes.extend_from_slice(&trust_hash_list(admin_bindings));
    bytes.extend_from_slice(&trust_cbor_array(0));
    bytes
}

/// Der finale Anchor nach `EINSATZARCHIV-TRUST-ANCHOR-v1`.
fn trust_anchor_bytes(
    embedded_bootstrap_hash: &[u8; 32],
    root_certificate_object_hash: ObjectHash,
    admin_certificates: &[ObjectHash],
    admin_bindings: &[ObjectHash],
) -> Vec<u8> {
    let root_key = trust_public_key(TEST_ENTROPY_ROOT_ED25519_SEED);
    let mut bytes = trust_cbor_array(12);
    bytes.extend_from_slice(&cbor_text("EINSATZARCHIV-TRUST-ANCHOR-v1"));
    bytes.extend_from_slice(&cbor_unsigned(1));
    bytes.extend_from_slice(&cbor_bytes(embedded_bootstrap_hash));
    bytes.extend_from_slice(&cbor_bytes(&TRUST_ORGANIZATION_ID));
    bytes.extend_from_slice(&cbor_bytes(&TRUST_CHAIN_ID));
    bytes.extend_from_slice(&cbor_bytes(&root_key.to_deterministic_cbor()));
    bytes.extend_from_slice(&cbor_bytes(root_key.thumbprint().as_bytes()));
    bytes.extend_from_slice(&cbor_bytes(root_certificate_object_hash.as_bytes()));
    bytes.extend_from_slice(&trust_hash_list(admin_certificates));
    bytes.extend_from_slice(&trust_hash_list(admin_bindings));
    bytes.extend_from_slice(&cbor_bytes(&TRUST_GENESIS_ENTRY_HASH));
    bytes.extend_from_slice(&trust_cbor_array(0));
    bytes
}

/// Eine Liste von Objekthashes als CBOR-Array.
fn trust_hash_list(hashes: &[ObjectHash]) -> Vec<u8> {
    let mut bytes = trust_cbor_array(u64::try_from(hashes.len()).expect("a short list"));
    for hash in hashes {
        bytes.extend_from_slice(&cbor_bytes(hash.as_bytes()));
    }
    bytes
}

/// Die Richtlinienfelder aller Trust-Vektoren.
fn trust_policy_fields() -> PolicyFieldsV1 {
    PolicyFieldsV1 {
        organization_id: trust_organization_id(),
        policy_version: 1,
        previous_policy_object_hash: None,
        operating_profile: 0,
        max_registry_age_ms: 86_400_000,
        max_future_clock_skew_ms: 300_000,
        registry_expiry_behavior: 0,
        evidence_max_delay_ms: 60_000,
        reader_inactivity_ms: 900_000,
        reader_trust_refresh_ms: 86_400_000,
        reader_history_access_allowed: true,
        allowed_archive_profile_hashes: vec![trust_hash32(0xa1)],
        backup_frequency_ms: 86_400_000,
        restore_test_interval_ms: 2_592_000_000,
        retention_policy: RetentionPolicyFieldsV1 {
            minimum_retention_ms: Some(86_400_000),
            destruction_enabled: true,
            eds_privacy_decision_document_hash: Some(trust_hash32(0xa2)),
        },
        free_text_policy: FreeTextPolicyFieldsV1 {
            free_text_allowed: false,
            rule_set_version: "trust-v1".to_owned(),
            local_pattern_warning_enabled: true,
        },
        allowed_crypto_suite_ids: vec![TRUST_SUITE_ID.to_owned()],
        allowed_format_versions: vec![1],
        effective_from_sequence: ChainSequence::new(1),
    }
}

/// Die Angaben einer Admin-Authorization, so weit die Vektoren sie variieren.
struct TrustAuthorizationSpec {
    action_code: u8,
    target_trust_subtype: TrustSubtypeV1,
    authorization_id: u8,
    nonce: u8,
    registry_version: u64,
    registry_head_hash: Hash32,
    admin_seed: [u8; 32],
    admin_certificate_object_hash: ObjectHash,
    admin_binding_object_hash: ObjectHash,
    /// Der Zertifikatshash im COSE-Protected-Header, wenn er vom Feld
    /// abweichen soll.
    signing_certificate_object_hash: Option<ObjectHash>,
    /// Ein Kernhash, der den autorisierten Kern NICHT bindet.
    core_hash_override: Option<Hash32>,
}

/// Eine Admin-Authorization ueber diesen Zielkern.
fn trust_authorization(target: &TrustPayloadV1, spec: &TrustAuthorizationSpec) -> Vec<u8> {
    let payload =
        TrustPayloadV1::organization_admin_authorization(OrganizationAdminAuthorizationFieldsV1 {
            authorization_id: AuthorizationId::try_from([spec.authorization_id; 16].as_slice())
                .expect("16 bytes"),
            organization_id: trust_organization_id(),
            registry_version: RegistryVersion::new(spec.registry_version),
            registry_head_hash: spec.registry_head_hash,
            admin_key_thumbprint: trust_public_key(spec.admin_seed).thumbprint(),
            admin_certificate_hash: CertificateHash::from(spec.admin_certificate_object_hash),
            admin_operator_binding_object_hash: spec.admin_binding_object_hash,
            action_code: spec.action_code,
            target_trust_subtype: spec.target_trust_subtype,
            authorized_trust_core_hash: spec
                .core_hash_override
                .unwrap_or_else(|| authorized_trust_digest(&trust_authorized_core_input(target))),
            issued_at: UnixMillis::new(100),
            expires_at: UnixMillis::new(1_100),
            nonce: [spec.nonce; 32],
        })
        .expect("the frozen authorization payload is well formed");
    let signature = trust_signed_normal(
        spec.admin_seed,
        CertificateHash::from(
            spec.signing_certificate_object_hash
                .unwrap_or(spec.admin_certificate_object_hash),
        ),
        trust_digest(payload.exact_digest_input()).as_bytes(),
    );
    trust_exact_object(payload, vec![signature])
}

/// Alle Objekte eines Falls, benannt.
#[allow(clippy::too_many_lines)]
fn trust_case_slots(case: TrustCaseV1) -> Vec<TrustSlot> {
    let root_bytes = trust_root_certificate();
    let root_object_hash = object_hash(&root_bytes);
    let root_certificate_hash = CertificateHash::from(root_object_hash);

    let admin_a = trust_initial_admin_certificate(
        root_certificate_hash,
        TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED,
        0x51,
        0x41,
    );
    let admin_b = trust_initial_admin_certificate(
        root_certificate_hash,
        TEST_ENTROPY_SECOND_ORGANIZATION_ADMIN_ED25519_SEED,
        0x52,
        0x42,
    );
    let admin_a_hash = object_hash(&admin_a);
    let admin_b_hash = object_hash(&admin_b);

    let binding_a = trust_initial_admin_binding(
        root_certificate_hash,
        CertificateHash::from(admin_a_hash),
        0x41,
        0x81,
        0x91,
    );
    let binding_b = match case {
        // Beide Bindungen zeigen auf dasselbe Zertifikat.
        TrustCaseV1::RejectedMispairedAdminBinding => trust_initial_admin_binding(
            root_certificate_hash,
            CertificateHash::from(admin_a_hash),
            0x42,
            0x82,
            0x92,
        ),
        // Dieselbe OS-Kontobindung UND derselbe Instanzschluessel wie A.
        TrustCaseV1::RejectedSharedOsAndInstanceKey => trust_initial_admin_binding(
            root_certificate_hash,
            CertificateHash::from(admin_b_hash),
            0x42,
            0x81,
            0x91,
        ),
        _ => trust_initial_admin_binding(
            root_certificate_hash,
            CertificateHash::from(admin_b_hash),
            0x42,
            0x82,
            0x92,
        ),
    };
    let binding_a_hash = object_hash(&binding_a);
    let binding_b_hash = object_hash(&binding_b);

    let mut anchor_admins = vec![admin_a_hash, admin_b_hash];
    if case == TrustCaseV1::RejectedHashDivergentAdminCertificate {
        // Der Anchor nennt einen Zertifikatshash, zu dem es kein Objekt gibt.
        anchor_admins[1] = ObjectHash::from(trust_hash32(0xcc));
    }
    let mut anchor_bindings = vec![binding_a_hash, binding_b_hash];
    anchor_admins.sort_unstable();
    anchor_bindings.sort_unstable();

    // Die Vorstufe, deren Hash in den finalen Anchor wandert. Beim Fall
    // `rejected-mutated-pre-anchor-field` traegt sie eine ANDERE
    // Organisationskennung als der Anchor, der aus ihr gebildet wird.
    let pre_anchor_organization = if case == TrustCaseV1::RejectedMutatedPreAnchorField {
        [0x22; 16]
    } else {
        TRUST_ORGANIZATION_ID
    };
    let pre_anchor = trust_pre_anchor_bytes(
        &pre_anchor_organization,
        root_object_hash,
        &anchor_admins,
        &anchor_bindings,
    );
    let mut embedded = *bootstrap_anchor_hash(&pre_anchor).as_bytes();
    if case == TrustCaseV1::RejectedWrongBootstrapAnchorHash {
        embedded[31] ^= 1;
    }
    let anchor = trust_anchor_bytes(
        &embedded,
        root_object_hash,
        &anchor_admins,
        &anchor_bindings,
    );

    let mut slots = Vec::new();
    if !case.is_anchor_tier() {
        slots.push(TrustSlot {
            name: "root-certificate",
            schema_id: TRUST_OBJECT_SCHEMA_ID,
            bytes: root_bytes,
        });
        slots.push(TrustSlot {
            name: "admin-certificate-a",
            schema_id: TRUST_OBJECT_SCHEMA_ID,
            bytes: admin_a,
        });
        slots.push(TrustSlot {
            name: "admin-certificate-b",
            schema_id: TRUST_OBJECT_SCHEMA_ID,
            bytes: admin_b,
        });
        slots.push(TrustSlot {
            name: "admin-binding-a",
            schema_id: TRUST_OBJECT_SCHEMA_ID,
            bytes: binding_a,
        });
        slots.push(TrustSlot {
            name: "admin-binding-b",
            schema_id: TRUST_OBJECT_SCHEMA_ID,
            bytes: binding_b,
        });
    }

    if case == TrustCaseV1::RejectedUnpinnedAdminPair {
        // Ein Paar im Katalog, das der Anchor nicht nennt.
        let extra = trust_initial_admin_certificate(
            root_certificate_hash,
            TEST_ENTROPY_ROTATED_ORGANIZATION_ADMIN_ED25519_SEED,
            0x53,
            0x43,
        );
        let extra_binding = trust_initial_admin_binding(
            root_certificate_hash,
            CertificateHash::from(object_hash(&extra)),
            0x43,
            0x83,
            0x93,
        );
        slots.push(TrustSlot {
            name: "unpinned-admin-certificate",
            schema_id: TRUST_OBJECT_SCHEMA_ID,
            bytes: extra,
        });
        slots.push(TrustSlot {
            name: "unpinned-admin-binding",
            schema_id: TRUST_OBJECT_SCHEMA_ID,
            bytes: extra_binding,
        });
    }

    if case.is_registry_tier() {
        slots.extend(trust_first_head_slots(
            case,
            root_certificate_hash,
            admin_a_hash,
            admin_b_hash,
            binding_a_hash,
        ));
    }

    // Die Vorstufe des Falls `rejected-wrong-bootstrap-anchor-hash` wuerde
    // ihren Anchor NICHT binden — es gibt keine. Genau das ist der Defekt, und
    // `decode_trust_anchor` weist ihn nach.
    if case != TrustCaseV1::RejectedWrongBootstrapAnchorHash {
        slots.push(TrustSlot {
            name: "pre-anchor",
            schema_id: TRUST_PRE_ANCHOR_SCHEMA_ID,
            bytes: pre_anchor,
        });
    }
    slots.push(TrustSlot {
        name: "anchor",
        schema_id: TRUST_ANCHOR_SCHEMA_ID,
        bytes: anchor,
    });
    slots
}

/// Der erste Registry-Kopf und, wo der Fall ihn braucht, der zweite.
#[allow(clippy::too_many_lines)]
fn trust_first_head_slots(
    case: TrustCaseV1,
    root_certificate_hash: CertificateHash,
    admin_a_hash: ObjectHash,
    admin_b_hash: ObjectHash,
    binding_a_hash: ObjectHash,
) -> Vec<TrustSlot> {
    let root_key = trust_public_key(TEST_ENTROPY_ROOT_ED25519_SEED);

    // Die Richtlinie. Ihr Autorisierungshash steht IM Nutzinhalt, also entsteht
    // sie zweimal: einmal mit Nullhash, um den Kern zu binden, und einmal mit
    // dem Hash der fertigen Autorisierung.
    let provisional_policy =
        TrustPayloadV1::policy(trust_policy_fields(), ObjectHash::from(Hash32::ZERO))
            .expect("the frozen policy payload is well formed");
    let policy_authorization = trust_authorization(
        &provisional_policy,
        &TrustAuthorizationSpec {
            action_code: 2,
            target_trust_subtype: TrustSubtypeV1::Policy,
            authorization_id: 0x20,
            nonce: 0x60,
            registry_version: 0,
            registry_head_hash: Hash32::ZERO,
            admin_seed: TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED,
            admin_certificate_object_hash: admin_a_hash,
            admin_binding_object_hash: binding_a_hash,
            signing_certificate_object_hash: (case == TrustCaseV1::RejectedSignerContextDeviation)
                .then_some(admin_b_hash),
            core_hash_override: (case == TrustCaseV1::RejectedAuthorizedCoreHashMismatch)
                .then(|| trust_hash32(0xde)),
        },
    );
    let policy_payload =
        TrustPayloadV1::policy(trust_policy_fields(), object_hash(&policy_authorization))
            .expect("the frozen policy payload is well formed");
    let policy_signature = trust_signed_normal(
        TEST_ENTROPY_ROOT_ED25519_SEED,
        root_certificate_hash,
        trust_digest(policy_payload.exact_digest_input()).as_bytes(),
    );
    let policy_bytes = trust_exact_object(policy_payload, vec![policy_signature]);
    let policy_hash = object_hash(&policy_bytes);

    // Der Kopf. Beim Fall `rejected-null-context-after-first-head` autorisiert
    // er ein Objekt der NULLKONTEXT-Vorstufe, das nur dort gueltig ist.
    let change = if case == TrustCaseV1::RejectedNullContextAfterFirstHead {
        RegistryChangeV1::AdminCertificate {
            object_hash: admin_a_hash,
            effect: 0,
        }
    } else {
        RegistryChangeV1::Policy {
            object_hash: policy_hash,
        }
    };
    let head_fields = RegistryEventFieldsV1 {
        organization_id: trust_organization_id(),
        registry_version: RegistryVersion::new(1),
        previous_registry_hash: None,
        effective_from_sequence: ChainSequence::new(1),
        valid_through_sequence: ChainSequence::new(100),
        issued_at: UnixMillis::new(100),
        not_before: UnixMillis::new(90),
        not_after: UnixMillis::new(10_000),
        policy_object_hash: policy_hash,
        change,
        root_key_thumbprint: root_key.thumbprint(),
    };
    let provisional_head =
        TrustPayloadV1::registry_event(head_fields.clone(), ObjectHash::from(Hash32::ZERO))
            .expect("the frozen registry event payload is well formed");
    let head_authorization = trust_authorization(
        &provisional_head,
        &TrustAuthorizationSpec {
            action_code: if case == TrustCaseV1::RejectedNullContextAfterFirstHead {
                5
            } else {
                2
            },
            target_trust_subtype: TrustSubtypeV1::RegistryEvent,
            // Derselbe Bezeichner und dieselbe Nonce wie die Autorisierung des
            // direkten Ziels.
            authorization_id: if case == TrustCaseV1::RejectedReusedAuthorizationIdAndNonce {
                0x20
            } else {
                0x21
            },
            nonce: if case == TrustCaseV1::RejectedReusedAuthorizationIdAndNonce {
                0x60
            } else {
                0x61
            },
            registry_version: 0,
            registry_head_hash: Hash32::ZERO,
            // Die Wurzel darf keine Admin-Authorization ausstellen.
            admin_seed: if case == TrustCaseV1::RejectedAdminOnlySignedByRoot {
                TEST_ENTROPY_ROOT_ED25519_SEED
            } else {
                TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED
            },
            admin_certificate_object_hash: if case == TrustCaseV1::RejectedAdminOnlySignedByRoot {
                ObjectHash::from(
                    Hash32::try_from(root_certificate_hash.as_bytes().as_slice())
                        .expect("32 bytes"),
                )
            } else {
                admin_a_hash
            },
            admin_binding_object_hash: binding_a_hash,
            signing_certificate_object_hash: None,
            core_hash_override: None,
        },
    );
    let head_payload =
        TrustPayloadV1::registry_event(head_fields, object_hash(&head_authorization))
            .expect("the frozen registry event payload is well formed");
    // Nur die Wurzel darf ein Registry-Ereignis signieren.
    let head_signature = if case == TrustCaseV1::RejectedRootOnlySignedByAdmin {
        trust_signed_normal(
            TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED,
            CertificateHash::from(admin_a_hash),
            trust_digest(head_payload.exact_digest_input()).as_bytes(),
        )
    } else {
        trust_signed_normal(
            TEST_ENTROPY_ROOT_ED25519_SEED,
            root_certificate_hash,
            trust_digest(head_payload.exact_digest_input()).as_bytes(),
        )
    };
    let head_bytes = trust_exact_object(head_payload, vec![head_signature]);
    let head_hash = object_hash(&head_bytes);

    let mut slots = vec![
        TrustSlot {
            name: "policy-authorization",
            schema_id: TRUST_OBJECT_SCHEMA_ID,
            bytes: policy_authorization,
        },
        TrustSlot {
            name: "policy",
            schema_id: TRUST_OBJECT_SCHEMA_ID,
            bytes: policy_bytes,
        },
        TrustSlot {
            name: "head-authorization",
            schema_id: TRUST_OBJECT_SCHEMA_ID,
            bytes: head_authorization,
        },
        TrustSlot {
            name: "head-event",
            schema_id: TRUST_OBJECT_SCHEMA_ID,
            bytes: head_bytes,
        },
    ];
    if case != TrustCaseV1::AcceptedAdminRotation {
        return slots;
    }

    // Der zweite Kopf: ein neues Administratorzertifikat unter dem ersten Kopf.
    let head_hash32 =
        Hash32::try_from(head_hash.as_bytes().as_slice()).expect("an object hash is 32 bytes");
    let rotated_key = trust_public_key(TEST_ENTROPY_ROTATED_ORGANIZATION_ADMIN_ED25519_SEED);
    let rotation_fields = DeviceCertificateFieldsV1 {
        organization_id: trust_organization_id(),
        device_id: DeviceId::try_from([0x54; 16].as_slice()).expect("16 bytes"),
        certificate_kind: CertificateKindV1::OrganizationAdmin,
        signing_public_cose_key: Some(rotated_key.to_deterministic_cbor()),
        kem_public_cose_key: None,
        signing_key_thumbprint: Some(rotated_key.thumbprint()),
        kem_key_thumbprint: None,
        capabilities: vec!["organizationAdminApprove".to_owned()],
        key_protection_profile: KeyProtectionProfileV1::OsWrapped,
        effective_from_sequence: ChainSequence::new(101),
        revoked_from_sequence: None,
        authority_subject_id: Some(SubjectId::try_from([0x44; 16].as_slice()).expect("16 bytes")),
    };
    let provisional_rotation = TrustPayloadV1::authorized_device_certificate(
        rotation_fields.clone(),
        ObjectHash::from(Hash32::ZERO),
    )
    .expect("the frozen rotation payload is well formed");
    let rotation_authorization = trust_authorization(
        &provisional_rotation,
        &TrustAuthorizationSpec {
            action_code: 5,
            target_trust_subtype: TrustSubtypeV1::DeviceCertificate,
            authorization_id: 0x22,
            nonce: 0x62,
            registry_version: 1,
            registry_head_hash: head_hash32,
            admin_seed: TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED,
            admin_certificate_object_hash: admin_a_hash,
            admin_binding_object_hash: binding_a_hash,
            signing_certificate_object_hash: None,
            core_hash_override: None,
        },
    );
    let rotation_payload = TrustPayloadV1::authorized_device_certificate(
        rotation_fields,
        object_hash(&rotation_authorization),
    )
    .expect("the frozen rotation payload is well formed");
    let rotation_signature = trust_signed_normal(
        TEST_ENTROPY_ROOT_ED25519_SEED,
        root_certificate_hash,
        trust_digest(rotation_payload.exact_digest_input()).as_bytes(),
    );
    let rotation_bytes = trust_exact_object(rotation_payload, vec![rotation_signature]);

    let second_fields = RegistryEventFieldsV1 {
        organization_id: trust_organization_id(),
        registry_version: RegistryVersion::new(2),
        previous_registry_hash: Some(head_hash32),
        effective_from_sequence: ChainSequence::new(101),
        valid_through_sequence: ChainSequence::new(200),
        issued_at: UnixMillis::new(100),
        not_before: UnixMillis::new(90),
        not_after: UnixMillis::new(10_000),
        policy_object_hash: policy_hash,
        change: RegistryChangeV1::AdminCertificate {
            object_hash: object_hash(&rotation_bytes),
            effect: 0,
        },
        root_key_thumbprint: root_key.thumbprint(),
    };
    let provisional_second =
        TrustPayloadV1::registry_event(second_fields.clone(), ObjectHash::from(Hash32::ZERO))
            .expect("the frozen registry event payload is well formed");
    let second_authorization = trust_authorization(
        &provisional_second,
        &TrustAuthorizationSpec {
            action_code: 5,
            target_trust_subtype: TrustSubtypeV1::RegistryEvent,
            authorization_id: 0x23,
            nonce: 0x63,
            registry_version: 1,
            registry_head_hash: head_hash32,
            admin_seed: TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED,
            admin_certificate_object_hash: admin_a_hash,
            admin_binding_object_hash: binding_a_hash,
            signing_certificate_object_hash: None,
            core_hash_override: None,
        },
    );
    let second_payload =
        TrustPayloadV1::registry_event(second_fields, object_hash(&second_authorization))
            .expect("the frozen registry event payload is well formed");
    let second_signature = trust_signed_normal(
        TEST_ENTROPY_ROOT_ED25519_SEED,
        root_certificate_hash,
        trust_digest(second_payload.exact_digest_input()).as_bytes(),
    );
    let second_bytes = trust_exact_object(second_payload, vec![second_signature]);

    slots.push(TrustSlot {
        name: "rotation-authorization",
        schema_id: TRUST_OBJECT_SCHEMA_ID,
        bytes: rotation_authorization,
    });
    slots.push(TrustSlot {
        name: "admin-certificate-rotated",
        schema_id: TRUST_OBJECT_SCHEMA_ID,
        bytes: rotation_bytes,
    });
    slots.push(TrustSlot {
        name: "second-head-authorization",
        schema_id: TRUST_OBJECT_SCHEMA_ID,
        bytes: second_authorization,
    });
    slots.push(TrustSlot {
        name: "second-head-event",
        schema_id: TRUST_OBJECT_SCHEMA_ID,
        bytes: second_bytes,
    });
    slots
}

/// Eine von Hand kodierte Admin-Authorization.
///
/// Von Hand, weil beide Negativvektoren ueber die oeffentliche API
/// UNERREICHBAR sind: `encode_organization_admin_authorization` lehnt einen
/// Action-Code ueber 6 ab, und `TrustSubtypeV1` kennt keinen unbekannten
/// Ziel-Subtype. Der Kontrollvektor mit gueltigen Werten belegt, dass dieser
/// Kodierer den Bestand trifft — sonst wuerde ein Negativvektor womoeglich an
/// einem ganz anderen Defekt scheitern als an dem, den er benennt.
fn trust_handmade_authorization(action_code: u64, target_subtype: &str) -> Vec<u8> {
    let admin_key = trust_public_key(TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED);
    let mut payload = trust_cbor_array(15);
    payload.extend_from_slice(&cbor_unsigned(1));
    payload.extend_from_slice(&cbor_bytes(&[0x30; 16]));
    payload.extend_from_slice(&cbor_bytes(&TRUST_ORGANIZATION_ID));
    payload.extend_from_slice(&cbor_unsigned(1));
    payload.extend_from_slice(&cbor_bytes(&[0x31; 32]));
    payload.extend_from_slice(&cbor_bytes(admin_key.thumbprint().as_bytes()));
    payload.extend_from_slice(&cbor_bytes(&[0x32; 32]));
    payload.extend_from_slice(&cbor_bytes(&[0x33; 32]));
    payload.extend_from_slice(&cbor_unsigned(action_code));
    payload.extend_from_slice(&trust_cbor_text(target_subtype));
    payload.extend_from_slice(&cbor_bytes(&[0x34; 32]));
    payload.extend_from_slice(&cbor_unsigned(100));
    payload.extend_from_slice(&cbor_unsigned(1_100));
    payload.extend_from_slice(&cbor_bytes(&[0x35; 32]));
    payload.extend_from_slice(&trust_cbor_array(0));

    let mut digest_input = trust_cbor_array(2);
    digest_input.extend_from_slice(&cbor_text(TRUST_ADMIN_AUTHORIZATION_SUBTYPE));
    digest_input.extend_from_slice(&payload);

    let signature = trust_signed_normal(
        TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED,
        CertificateHash::try_from([0x32; 32].as_slice()).expect("32 bytes"),
        trust_digest(&digest_input).as_bytes(),
    );

    let mut body = trust_cbor_array(3);
    body.extend_from_slice(&cbor_text(TRUST_ADMIN_AUTHORIZATION_SUBTYPE));
    body.extend_from_slice(&payload);
    body.extend_from_slice(&trust_cbor_array(1));
    body.extend_from_slice(&signature);

    let mut object = vec![0x85, 0x44, b'E', b'A', b'1', 0, 5, 1, 0x80];
    object.extend_from_slice(&body);
    object
}

/// Die drei handkodierten Objektfaelle: Verzeichnis, Action-Code, Ziel-Subtype
/// und behauptetes Urteil.
const TRUST_OBJECT_CASES_V1: [(&str, u64, &str, Option<&str>); 3] = [
    (
        "object/accepted-handmade-admin-authorization",
        2,
        "policy",
        None,
    ),
    (
        "object/rejected-action-code-200",
        TRUST_INVALID_ACTION_CODE,
        "policy",
        Some("EA-FORMAT-SHAPE"),
    ),
    (
        "object/rejected-unknown-target-subtype",
        2,
        TRUST_UNKNOWN_SUBTYPE,
        Some("EA-FORMAT-TAG-MISMATCH"),
    ),
];

/// Die beiden Positivvektoren fuer `policy-core-v1`.
///
/// Sie unterscheiden sich in GENAU EINEM Feld: `reader-trust-refresh-ms`. Das
/// Feld traegt die geraeteseitige Aktualisierungsfrist des Readers und ist
/// weder `max-registry-age-ms` — eine Ausstellungsschranke am
/// Registry-Ereignis — noch `registry-expiry-behavior`, das an die
/// Finalisierung gebunden ist, eine Operation, die ein Reader nicht ausfuehrt.
/// Der Wert `0` heisst: KEINE geraeteseitige Frist.
const TRUST_POLICY_CASES_V1: [(&str, u64); 2] = [
    (
        "object/accepted-policy-core-reader-trust-refresh-disabled",
        0,
    ),
    (
        "object/accepted-policy-core-reader-trust-refresh-set",
        86_400_000,
    ),
];

/// Die Reichweitennotiz jedes `policy-core-v1`-Positivvektors.
const TRUST_POLICY_SCOPE_NOTE: &str = "Dieser Vektor friert das geschlossene 22-Positionen-Array von policy-core-v1 ein, einschliesslich reader-trust-refresh-ms an Position 11 (schemas/archive/v1/trust.cddl). Die normative Semantik der Frist steht in design.md 12.3; dieser Vektor belegt sie NICHT, sondern nur die Feldposition und die Kodierung. Der Wert 0 heisst: keine geraeteseitige Frist.";

/// Der Zertifikatshash, mit dem die freistehenden Richtlinienvektoren signiert
/// sind.
///
/// Ein Objektvektor wird gegen keinen Katalog aufgeloest; der Hash ist deshalb
/// eine feste Konstante und kein Objekthash.
const TRUST_POLICY_CERTIFICATE_HASH: u8 = 0xa4;

/// Der Autorisierungshash der freistehenden Richtlinienvektoren.
const TRUST_POLICY_AUTHORIZATION_HASH: u8 = 0xa5;

/// Das Manifest der Vektorfamilie `trust/v1`.
///
/// Deterministisch: Ed25519 signiert deterministisch, alle Felder sind feste
/// Konstanten, und keine Kapselung zieht Entropie. Zwei Laeufe liefern dieselben
/// Bytes.
///
/// # Panics
///
/// Wenn eine der Konstruktionen fehlschlaegt. Das waere ein Programmierfehler
/// dieser Crate, kein Laufzeitzustand.
#[must_use]
pub fn trust_v1_manifest() -> VectorManifest {
    let mut entries = Vec::new();

    for (case, path, _) in TRUST_CASES_V1 {
        let slots = trust_case_slots(case);
        for slot in slots {
            let name = format!("{path}/{}", slot.name);
            // Das Urteil des Falls steht am Eintrag, der die Pipeline betritt.
            let expected_outcome = if slot.name == "anchor" {
                case.verdict()
            } else {
                ExpectedOutcome::Accepted
            };
            let intermediate_digests = match slot.schema_id {
                TRUST_PRE_ANCHOR_SCHEMA_ID => digest_map(&[(
                    "bootstrapAnchorHash",
                    *bootstrap_anchor_hash(&slot.bytes).as_bytes(),
                )]),
                TRUST_ANCHOR_SCHEMA_ID => digest_map(&[(
                    "trustAnchorHash",
                    *trust_anchor_hash(&slot.bytes).as_bytes(),
                )]),
                _ => digest_map(&[("objectHash", *object_hash(&slot.bytes).as_bytes())]),
            };
            entries.push(trust_entry(
                &name,
                slot.schema_id,
                intermediate_digests,
                slot.bytes,
                expected_outcome,
            ));
        }
    }

    for (path, action_code, target_subtype, code) in TRUST_OBJECT_CASES_V1 {
        let bytes = trust_handmade_authorization(action_code, target_subtype);
        let expected_outcome = match code {
            None => ExpectedOutcome::Accepted,
            Some(code) => ExpectedOutcome::Rejected {
                error_code: code.to_owned(),
            },
        };
        entries.push(trust_entry(
            &format!("{path}/admin-authorization"),
            TRUST_OBJECT_SCHEMA_ID,
            digest_map(&[("objectHash", *object_hash(&bytes).as_bytes())]),
            bytes,
            expected_outcome,
        ));
    }

    for (path, reader_trust_refresh_ms) in TRUST_POLICY_CASES_V1 {
        let bytes = trust_policy_object(reader_trust_refresh_ms);
        entries.push(trust_entry(
            &format!("{path}/policy"),
            TRUST_OBJECT_SCHEMA_ID,
            digest_map(&[("objectHash", *object_hash(&bytes).as_bytes())]),
            bytes,
            ExpectedOutcome::Accepted,
        ));
    }

    VectorManifest {
        family: TRUST_FAMILY.to_owned(),
        version: TRUST_V1_VERSION.to_owned(),
        entries,
    }
}

/// Ein freistehendes Richtlinienobjekt mit gesetzter Aktualisierungsfrist.
///
/// Es steht fuer sich: ein Objektvektor durchlaeuft nur
/// `decode_exact_object`, wird gegen keinen Katalog aufgeloest und braucht
/// deshalb weder ein Wurzelzertifikat noch eine Admin-Authorization im
/// Bestand. Alle uebrigen Felder stammen unveraendert aus
/// [`trust_policy_fields`]; die beiden Vektoren unterscheiden sich in genau
/// einem Wert.
fn trust_policy_object(reader_trust_refresh_ms: u64) -> Vec<u8> {
    let mut fields = trust_policy_fields();
    fields.reader_trust_refresh_ms = reader_trust_refresh_ms;
    let payload = TrustPayloadV1::policy(
        fields,
        ObjectHash::from(trust_hash32(TRUST_POLICY_AUTHORIZATION_HASH)),
    )
    .expect("the frozen policy payload is well formed");
    let certificate_hash = CertificateHash::from(ObjectHash::from(trust_hash32(
        TRUST_POLICY_CERTIFICATE_HASH,
    )));
    let signature = trust_signed_normal(
        TEST_ENTROPY_ROOT_ED25519_SEED,
        certificate_hash,
        trust_digest(payload.exact_digest_input()).as_bytes(),
    );
    trust_exact_object(payload, vec![signature])
}

/// Ein Eintrag der Trust-Familie.
///
/// Die Reichweitennotiz haengt am SUBTYPE, nicht am Namen: jeder
/// `organizationAdminAuthorization`-Vektor bekommt sie, gleich in welchem Fall
/// er steht.
fn trust_entry(
    name: &str,
    schema_id: &str,
    intermediate_digests: BTreeMap<String, [u8; 32]>,
    object_bytes: Vec<u8>,
    expected_outcome: ExpectedOutcome,
) -> VectorEntry {
    let scope_note = if schema_id != TRUST_OBJECT_SCHEMA_ID {
        None
    } else {
        match trust_body_subtype(&object_bytes).as_str() {
            TRUST_ADMIN_AUTHORIZATION_SUBTYPE => {
                Some(TRUST_ADMIN_AUTHORIZATION_SCOPE_NOTE.to_owned())
            }
            "policy" if name.starts_with("object/accepted-policy-core-") => {
                Some(TRUST_POLICY_SCOPE_NOTE.to_owned())
            }
            _ => None,
        }
    };
    VectorEntry {
        name: name.to_owned(),
        schema_id: schema_id.to_owned(),
        suite_id: TRUST_SUITE_ID.to_owned(),
        source: VectorSource::GeneratorCommit(TRUST_GENERATOR.to_owned()),
        input_bytes: Vec::new(),
        intermediate_digests,
        object_bytes,
        expected_outcome,
        file: format!("{name}.bin"),
        scope_note,
    }
}

/// Der Subtype eines Vertrauensbausteins, roh aus dem Rumpf gelesen.
///
/// Roh, weil die Negativvektoren gerade nicht durch `ea-format` gehen. Der
/// Rumpf ist `[subtype, nutzinhalt, [signaturen]]` hinter dem neun Byte langen
/// Objektpraefix, und die Zeichenkette steht laengenminimal kodiert an zweiter
/// Stelle.
fn trust_body_subtype(object_bytes: &[u8]) -> String {
    let body = &object_bytes[9..];
    assert_eq!(body[0], 0x83, "a trust body is a three element array");
    let (length, start) = match body[1] {
        header @ 0x60..=0x77 => (usize::from(header & 0x1f), 2),
        0x78 => (usize::from(body[2]), 3),
        header => panic!("a subtype string is shorter than 256 bytes, not {header:#x}"),
    };
    String::from_utf8(body[start..start + length].to_vec())
        .expect("a subtype string is valid UTF-8")
}

// ---------------------------------------------------------------------------
// Vektorfamilie grants/v1
// ---------------------------------------------------------------------------

/// Der Familienname der Grant-Vektoren.
pub const GRANTS_FAMILY: &str = "grants";

/// Der Versionsordner der Grant-Vektoren.
pub const GRANTS_V1_VERSION: &str = "v1";

/// Die Wurzel der Grant-Vektoren, relativ zur Arbeitsbaumwurzel.
pub const GRANTS_V1_ROOT: &str = "vectors/grants/v1";

/// Die Herkunftsangabe der deterministisch erzeugten Grant-Vektoren.
const GRANTS_GENERATOR: &str = "ea-testkit::grants_v1_manifest";

/// Der Grant-Suite-Identifikator, EINGEFROREN.
///
/// Bewusst ein Literal und keine Uebernahme aus `ea-crypto`: der Vektor soll
/// dem Quelltext WIDERSPRECHEN koennen. `ea-system-tests` stellt beide
/// gegeneinander.
const GRANTS_SUITE_ID: &str = "EINSATZARCHIV-HPKE-1";

/// Der Schema-Identifikator eines Grants.
const GRANT_SCHEMA_ID: &str = "eag-v1";

/// Der Schema-Identifikator eines Grant-Plans in der Flachform.
const GRANT_PLAN_SCHEMA_ID: &str = "grant-plan-v1";

/// Der Schema-Identifikator eines Grant-Kontextes und seiner Ableitungen.
const GRANT_CONTEXT_SCHEMA_ID: &str = "grant-context-v1";

/// Der Schema-Identifikator des Suite-Identifikators.
const GRANT_SUITE_SCHEMA_ID: &str = "grant-suite-id-v1";

/// Die Laenge eines Plan-Eintrags in der FLACHFORM dieser Familie.
///
/// 32 Byte Schluesselabdruck, 32 Byte Zertifikatshash, ein Byte Zweck. DAS IST
/// NICHT DIE DRAHTKODIERUNG: `ea_format::GrantPlanV1` kodiert seine Eintraege
/// als CBOR-Vierertupel, und ein zweiter Kodierer in dieser Crate waere eine
/// ZWEITE Quelle der Wahrheit. Die Flachform ist ausschliesslich der Transport,
/// in dem Erzeuger und Test dieselbe Eintragsfolge benennen; geprueft wird die
/// Sortierung ueber `GrantPlanV1::items()` und `GrantPlanV1::hash()`.
pub const GRANT_PLAN_ITEM_BYTES: usize = 65;

/// Die Organisationskennung aller Grant-Vektoren.
const GRANTS_ORGANIZATION_ID: [u8; 16] = [0x30; 16];

/// Die Kettenkennung aller Grant-Vektoren.
const GRANTS_CHAIN_ID: [u8; 16] = [0x31; 16];

/// Der Eintragshash, den die Grants freigeben.
const GRANTS_ENTRY_HASH: [u8; 32] = [0x32; 32];

/// Der Registrierungskopf-Hash aller Grant-Vektoren.
const GRANTS_REGISTRY_HEAD_HASH: [u8; 32] = [0x33; 32];

/// Der Zertifikatshash des ausstellenden Geraets.
const GRANTS_ISSUER_CERTIFICATE_HASH: [u8; 32] = [0x34; 32];

/// Der Objekthash des urspruenglichen Recovery-Grants im historischen Grant.
const GRANTS_ORIGINAL_RECOVERY_GRANT_OBJECT_HASH: [u8; 32] = [0x35; 32];

/// Der Objekthash der Grant-Authorization im historischen Grant.
const GRANTS_GRANT_AUTHORIZATION_OBJECT_HASH: [u8; 32] = [0x36; 32];

/// Der Zertifikatshash des Empfaengers.
const GRANTS_RECIPIENT_CERTIFICATE_HASH: [u8; 32] = [0x37; 32];

/// Schluesselabdruck und Zertifikatshash des Recovery-Empfaengers im Plan.
const GRANTS_PLAN_RECOVERY_KEY_THUMBPRINT: [u8; 32] = [0x40; 32];

/// Der Zertifikatshash des Recovery-Empfaengers im Plan.
const GRANTS_PLAN_RECOVERY_CERTIFICATE_HASH: [u8; 32] = [0x41; 32];

/// Der Schluesselabdruck des zweiten Lese-Empfaengers im Plan.
const GRANTS_PLAN_READER_KEY_THUMBPRINT: [u8; 32] = [0x42; 32];

/// Der Zertifikatshash des zweiten Lese-Empfaengers im Plan.
const GRANTS_PLAN_READER_CERTIFICATE_HASH: [u8; 32] = [0x43; 32];

/// Die Registrierungsversion aller Grant-Vektoren.
const GRANTS_REGISTRY_VERSION: u64 = 9;

/// Die Geraetezeit aller Grant-Vektoren in Millisekunden seit der Epoche.
const GRANTS_DEVICE_TIME_MS: i64 = 1_700_000_002_000;

/// Kapselungswert des initialen Grants, EINMALIG erzeugt und eingefroren.
///
/// `hpke_seal` zieht bei jedem Aufruf frische Entropie aus dem Betriebssystem
/// (`crates/ea-crypto/src/hpke.rs`), und der Injektionspunkt fuer Testentropie
/// ist privat und durch einen `compile_fail`-Doctest gegen Veroeffentlichung
/// gesichert. Diese Bytes sind deshalb NICHT regenerierbar; nachgeprueft werden
/// sie ausschliesslich in der entkapselnden Richtung ueber `hpke_open`, und das
/// Manifest sagt das ueber [`VectorSource::FrozenOnce`] an. Erzeugt vom
/// `#[ignore]`-Lauf `freeze_grant_encapsulations` dieser Crate.
const GRANT_INITIAL_ENCAPSULATED_KEY: &str =
    "4533e636f0fa8c71ef75da785377b81f4c25e975de42107c478fdbb7afeec913";

/// Der umschlossene Inhaltsschluessel des initialen Grants.
const GRANT_INITIAL_WRAPPED_CEK: &str = "82ffa41f04e5bfed6157ffde82cc077149a46c325c7c787e71d276fd3e64cd6533dcba4631364801408bb6d2dc1dd455";

/// Kapselungswert des historischen Grants, EINMALIG erzeugt und eingefroren.
const GRANT_HISTORICAL_ENCAPSULATED_KEY: &str =
    "87999e8f65e53e60824eaa0d341ad84e429cb36c5b303f1cb110db7896c9863f";

/// Der umschlossene Inhaltsschluessel des historischen Grants.
const GRANT_HISTORICAL_WRAPPED_CEK: &str = "5d9cfa41f59fbbd0011f33f1692c06e54673966487089554f61c8324ca829edc543f7ffde198e26b23ee3f1c560a41db";

/// Die Reichweitennotiz jedes Vektors, dessen Defekt an einem Feld des
/// Grant-Rumpfes sitzt.
///
/// Drei Negativvektoren messen denselben Code `EA-FORMAT-COSE`. Ohne die
/// Angabe des Defektortes waeren sie moeglicherweise derselbe Vektor unter drei
/// Namen; `ea-system-tests` rechnet den Ort zusaetzlich nach.
const GRANT_DEFECT_SITE_NOTE: &str = "Dieser Vektor kippt genau ein Byte im benannten Feld des Grant-Rumpfes. Der gemessene Code EA-FORMAT-COSE entsteht, weil grant_digest ueber den geaenderten Rumpf laeuft und der COSE-Nutzinhalt ihn nicht mehr trifft; er belegt NICHT die Ed25519-Rechnung, die zu ea-verify gehoert.";

/// Die Reichweitennotiz des wiedersignierten Kapselungsvektors.
const GRANT_RESIGNED_NOTE: &str = "Dieser Vektor kippt ein Byte im Kapselungswert UND signiert den Rumpf neu. Er passiert die Formatebene deshalb vollstaendig; abgelehnt wird er erst von hpke_open, und genau das ist der Fehlercode im Manifest.";

/// Die erzeugten Bestandteile der Grant-Familie.
struct GrantObjects {
    /// Der Grant-Plan in Eingabereihenfolge, flach kodiert.
    plan_input: Vec<u8>,
    /// Derselbe Plan in der von `GrantPlanV1` erzwungenen Ordnung.
    plan_sorted: Vec<u8>,
    /// Der Plan-Hash der sortierten Eintraege.
    plan_hash: [u8; 32],
    /// Die vier Plaene, die `GrantPlanV1::new` ablehnen MUSS.
    rejected_plans: [(&'static str, Vec<u8>, &'static str); 4],
    /// Der Grant-Kontext des initialen Grants.
    initial_context: Vec<u8>,
    /// Das initiale `.eag` samt Rumpf, Digest und Objekthash.
    initial: GrantVector,
    /// Das historische `.eag`.
    historical: GrantVector,
    /// Die drei Ein-Byte-Abweichungen am initialen `.eag`.
    single_byte_defects: [(&'static str, Vec<u8>); 3],
    /// Der wiedersignierte Kapselungsvektor.
    resigned_encapsulation: Vec<u8>,
}

/// Ein fertiges `.eag` mit den Zwischenwerten, die das Manifest festhaelt.
struct GrantVector {
    object: Vec<u8>,
    grant_digest: [u8; 32],
    body: Vec<u8>,
}

/// Die Organisationskennung als getypter Wert.
fn grants_organization_id() -> OrganizationId {
    OrganizationId::try_from(GRANTS_ORGANIZATION_ID.as_slice()).expect("16 bytes")
}

/// Ein 32-Byte-Schluesselabdruck als getypter Wert.
fn grants_thumbprint(bytes: [u8; 32]) -> KeyThumbprint {
    KeyThumbprint::try_from(bytes.as_slice()).expect("32 bytes")
}

/// Ein 32-Byte-Zertifikatshash als getypter Wert.
fn grants_certificate_hash(bytes: [u8; 32]) -> CertificateHash {
    CertificateHash::try_from(bytes.as_slice()).expect("32 bytes")
}

/// Der Empfaengerschluessel aus deklarierter Testentropie.
fn grants_recipient_public_key() -> [u8; 32] {
    let private =
        HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(TEST_ENTROPY_RECIPIENT_X25519_SEED))
            .expect("the declared recipient seed loads");
    *private.public_key().as_bytes()
}

/// Der Schluesselabdruck des Empfaengers nach RFC 9679.
fn grants_recipient_thumbprint() -> KeyThumbprint {
    CanonicalPublicCoseKey::x25519(grants_recipient_public_key())
        .expect("the derived recipient key is canonical")
        .thumbprint()
}

/// Die Flachform einer Eintragsfolge.
fn grant_plan_flat(items: &[GrantPlanItemV1]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(items.len().saturating_mul(GRANT_PLAN_ITEM_BYTES));
    for item in items {
        bytes.extend_from_slice(item.recipient_key_thumbprint().as_bytes());
        bytes.extend_from_slice(item.recipient_certificate_hash().as_bytes());
        bytes.push(item.purpose() as u8);
    }
    bytes
}

/// Die drei Eintraege des gueltigen Plans.
fn grant_plan_items() -> Vec<GrantPlanItemV1> {
    vec![
        GrantPlanItemV1::new(
            grants_thumbprint(GRANTS_PLAN_RECOVERY_KEY_THUMBPRINT),
            grants_certificate_hash(GRANTS_PLAN_RECOVERY_CERTIFICATE_HASH),
            GrantPurposeV1::Recovery,
        ),
        GrantPlanItemV1::new(
            grants_thumbprint(GRANTS_PLAN_READER_KEY_THUMBPRINT),
            grants_certificate_hash(GRANTS_PLAN_READER_CERTIFICATE_HASH),
            GrantPurposeV1::Reader,
        ),
        GrantPlanItemV1::new(
            grants_recipient_thumbprint(),
            grants_certificate_hash(GRANTS_RECIPIENT_CERTIFICATE_HASH),
            GrantPurposeV1::Reader,
        ),
    ]
}

/// Der Grant-Kontext eines Rumpfes: alles vor Kapselungswert und CEK.
///
/// Derselbe Schnitt, den `ea_recovery::decrypt` fuer `hpke_info`/`hpke_aad`
/// nimmt: `grant-body-v1` ist ein Array fester Laenge drei, dessen zweites und
/// drittes Glied Bytefolgen fester Groesse 32 und 48 sind. Der Schwanz wird
/// unabhaengig aus den dekodierten Feldern nachgebaut und gegen den Rumpf
/// gestellt.
fn grant_context(body: &GrantBodyV1) -> Vec<u8> {
    let exact = body.exact_bytes();
    let fields = body.fields();
    let mut tail = Vec::with_capacity(4 + HPKE_ENCAPSULATED_KEY_SIZE + HPKE_WRAPPED_CEK_SIZE);
    tail.push(0x58);
    tail.push(u8::try_from(HPKE_ENCAPSULATED_KEY_SIZE).expect("32 fits in a byte"));
    tail.extend_from_slice(&fields.encapsulated_key);
    tail.push(0x58);
    tail.push(u8::try_from(HPKE_WRAPPED_CEK_SIZE).expect("48 fits in a byte"));
    tail.extend_from_slice(&fields.wrapped_cek);
    let end = exact.len() - tail.len();
    assert_eq!(
        &exact[end..],
        tail.as_slice(),
        "the grant body tail is fixed"
    );
    assert_eq!(exact[0], 0x83, "a grant body is a three element array");
    exact[1..end].to_vec()
}

/// Die Rumpffelder eines Grants dieser Familie.
fn grant_body_fields(
    kind: GrantKindV1,
    issuer_key_thumbprint: KeyThumbprint,
    encapsulated_key: [u8; HPKE_ENCAPSULATED_KEY_SIZE],
    wrapped_cek: [u8; HPKE_WRAPPED_CEK_SIZE],
) -> GrantBodyFieldsV1 {
    let historical = matches!(kind, GrantKindV1::Historical);
    GrantBodyFieldsV1 {
        organization_id: grants_organization_id(),
        chain_id: ChainId::try_from(GRANTS_CHAIN_ID.as_slice()).expect("16 bytes"),
        entry_hash: EntryHash::try_from(GRANTS_ENTRY_HASH.as_slice()).expect("32 bytes"),
        kind,
        purpose: GrantPurposeV1::Reader,
        recipient_key_thumbprint: grants_recipient_thumbprint(),
        recipient_certificate_hash: grants_certificate_hash(GRANTS_RECIPIENT_CERTIFICATE_HASH),
        issuer_key_thumbprint,
        issuer_certificate_hash: grants_certificate_hash(GRANTS_ISSUER_CERTIFICATE_HASH),
        registry_version: RegistryVersion::new(GRANTS_REGISTRY_VERSION),
        registry_head_hash: Hash32::try_from(GRANTS_REGISTRY_HEAD_HASH.as_slice())
            .expect("32 bytes"),
        created_at_device: UnixMillis::new(GRANTS_DEVICE_TIME_MS),
        original_recovery_grant_object_hash: historical.then(|| {
            ObjectHash::try_from(GRANTS_ORIGINAL_RECOVERY_GRANT_OBJECT_HASH.as_slice())
                .expect("32 bytes")
        }),
        grant_authorization_object_hash: historical.then(|| {
            ObjectHash::try_from(GRANTS_GRANT_AUTHORIZATION_OBJECT_HASH.as_slice())
                .expect("32 bytes")
        }),
        encapsulated_key,
        wrapped_cek,
    }
}

/// Ein fertiges `.eag` aus Kapselungswert und umschlossenem CEK.
fn grant_vector(
    kind: GrantKindV1,
    encapsulated_key: [u8; HPKE_ENCAPSULATED_KEY_SIZE],
    wrapped_cek: [u8; HPKE_WRAPPED_CEK_SIZE],
) -> GrantVector {
    let issuer = format_signer(TEST_ENTROPY_DEVICE_ED25519_SEED);
    let issuer_thumbprint = format_public_key(TEST_ENTROPY_DEVICE_ED25519_SEED).thumbprint();
    let body = GrantBodyV1::new(grant_body_fields(
        kind,
        issuer_thumbprint,
        encapsulated_key,
        wrapped_cek,
    ))
    .expect("the frozen grant body is well formed");
    let digest = grant_digest(body.exact_bytes());
    let signature = match kind {
        GrantKindV1::Initial => issuer.sign_initial_grant(body.exact_bytes()),
        GrantKindV1::Historical => issuer.sign_historical_grant(body.exact_bytes()),
    }
    .expect("signing the frozen grant body cannot fail");
    let body_bytes = body.exact_bytes().to_vec();
    let grant = GrantV1::new(body, signature).expect("the frozen grant is well formed");
    let object = encode_grant(&grant)
        .expect("encoding the frozen grant cannot fail")
        .into_vec();
    GrantVector {
        object,
        grant_digest: *digest.as_bytes(),
        body: body_bytes,
    }
}

/// Die Bestandteile der Grant-Familie, deterministisch erzeugt.
///
/// # Panics
///
/// Wenn eine der Konstruktionen fehlschlaegt. Das waere ein Programmierfehler
/// dieser Crate, kein Laufzeitzustand.
fn grant_objects() -> GrantObjects {
    let plan = GrantPlanV1::new(grant_plan_items()).expect("the frozen grant plan is well formed");
    let plan_sorted = grant_plan_flat(plan.items());
    let mut reversed = plan.items().to_vec();
    reversed.reverse();
    let plan_input = grant_plan_flat(&reversed);
    assert_ne!(
        plan_input, plan_sorted,
        "the input order must differ from the enforced order"
    );

    let recovery = GrantPlanItemV1::new(
        grants_thumbprint(GRANTS_PLAN_RECOVERY_KEY_THUMBPRINT),
        grants_certificate_hash(GRANTS_PLAN_RECOVERY_CERTIFICATE_HASH),
        GrantPurposeV1::Recovery,
    );
    let reader = GrantPlanItemV1::new(
        grants_thumbprint(GRANTS_PLAN_READER_KEY_THUMBPRINT),
        grants_certificate_hash(GRANTS_PLAN_READER_CERTIFICATE_HASH),
        GrantPurposeV1::Reader,
    );
    let second_recovery = GrantPlanItemV1::new(
        grants_recipient_thumbprint(),
        grants_certificate_hash(GRANTS_RECIPIENT_CERTIFICATE_HASH),
        GrantPurposeV1::Recovery,
    );
    let same_key = GrantPlanItemV1::new(
        grants_thumbprint(GRANTS_PLAN_READER_KEY_THUMBPRINT),
        grants_certificate_hash(GRANTS_RECIPIENT_CERTIFICATE_HASH),
        GrantPurposeV1::Reader,
    );
    let same_certificate = GrantPlanItemV1::new(
        grants_recipient_thumbprint(),
        grants_certificate_hash(GRANTS_PLAN_READER_CERTIFICATE_HASH),
        GrantPurposeV1::Reader,
    );
    let rejected_plans = [
        (
            "plan/rejected-duplicate-recipient-certificate",
            grant_plan_flat(&[recovery.clone(), reader.clone(), same_certificate]),
            "EA-GRANT-DUPLICATE-RECIPIENT-CERTIFICATE",
        ),
        (
            "plan/rejected-duplicate-recipient-key",
            grant_plan_flat(&[recovery.clone(), reader.clone(), same_key]),
            "EA-GRANT-DUPLICATE-RECIPIENT-KEY",
        ),
        (
            "plan/rejected-duplicate-recovery",
            grant_plan_flat(&[recovery.clone(), reader.clone(), second_recovery]),
            "EA-GRANT-DUPLICATE-RECOVERY",
        ),
        (
            "plan/rejected-missing-recovery",
            grant_plan_flat(&[reader]),
            "EA-GRANT-MISSING-RECOVERY",
        ),
    ];

    let initial_encapsulated: [u8; HPKE_ENCAPSULATED_KEY_SIZE] =
        decode(GRANT_INITIAL_ENCAPSULATED_KEY)
            .try_into()
            .expect("the frozen encapsulated key is 32 bytes");
    let initial_wrapped: [u8; HPKE_WRAPPED_CEK_SIZE] = decode(GRANT_INITIAL_WRAPPED_CEK)
        .try_into()
        .expect("the frozen wrapped CEK is 48 bytes");
    let initial = grant_vector(GrantKindV1::Initial, initial_encapsulated, initial_wrapped);
    let historical = grant_vector(
        GrantKindV1::Historical,
        decode(GRANT_HISTORICAL_ENCAPSULATED_KEY)
            .try_into()
            .expect("the frozen encapsulated key is 32 bytes"),
        decode(GRANT_HISTORICAL_WRAPPED_CEK)
            .try_into()
            .expect("the frozen wrapped CEK is 48 bytes"),
    );

    let initial_body = GrantBodyV1::new(grant_body_fields(
        GrantKindV1::Initial,
        format_public_key(TEST_ENTROPY_DEVICE_ED25519_SEED).thumbprint(),
        initial_encapsulated,
        initial_wrapped,
    ))
    .expect("the frozen grant body is well formed");
    let initial_context = grant_context(&initial_body);

    // Die drei Ein-Byte-Abweichungen. Jede sitzt an einem ANDEREN Ort, und der
    // Ort wird hier ueber die Bytes des Feldes gefunden, nicht ueber einen
    // gezaehlten Versatz: ein gezaehlter Versatz waere still falsch, sobald
    // sich die Kodierung eines vorangehenden Feldes aendert.
    let mut flipped_encapsulated = initial.object.clone();
    let offset = unique_offset(&initial.object, &initial_encapsulated);
    flipped_encapsulated[offset] ^= 0x01;
    let mut flipped_wrapped = initial.object.clone();
    let offset = unique_offset(&initial.object, &initial_wrapped);
    flipped_wrapped[offset] ^= 0x01;
    let mut flipped_digest = initial.object.clone();
    let offset = unique_offset(&initial.object, &initial.grant_digest);
    flipped_digest[offset] ^= 0x01;

    let mut resigned = initial_encapsulated;
    resigned[0] ^= 0x01;
    let resigned_encapsulation =
        grant_vector(GrantKindV1::Initial, resigned, initial_wrapped).object;

    GrantObjects {
        plan_input,
        plan_sorted,
        plan_hash: *plan.hash().as_bytes(),
        rejected_plans,
        initial_context,
        initial,
        historical,
        single_byte_defects: [
            (
                "grant/rejected-flipped-encapsulated-key",
                flipped_encapsulated,
            ),
            ("grant/rejected-flipped-wrapped-cek", flipped_wrapped),
            ("grant/rejected-flipped-signed-grant-digest", flipped_digest),
        ],
        resigned_encapsulation,
    }
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

/// Das Manifest der Vektorfamilie `grants/v1`.
///
/// Bis auf Kapselungswert und umschlossenen CEK vollstaendig deterministisch:
/// Ed25519 signiert deterministisch, und alle Felder sind feste Konstanten. Die
/// beiden Kapselungen sind EINMAL erzeugt und eingefroren; ihre Nachpruefung
/// laeuft ausschliesslich in der entkapselnden Richtung ueber `hpke_open`.
///
/// # Panics
///
/// Wenn eine der Konstruktionen fehlschlaegt.
#[must_use]
pub fn grants_v1_manifest() -> VectorManifest {
    let built = grant_objects();
    let mut entries = Vec::new();

    entries.push(grants_entry(
        "suite/grant-suite-id",
        GRANT_SUITE_SCHEMA_ID,
        grants_source(),
        Vec::new(),
        BTreeMap::new(),
        GRANTS_SUITE_ID.as_bytes().to_vec(),
        ExpectedOutcome::Accepted,
        None,
    ));

    for (name, derived) in [
        (
            "context/initial-grant-hpke-info",
            hpke_info(&built.initial_context),
        ),
        (
            "context/initial-grant-hpke-aad",
            hpke_aad(&built.initial_context),
        ),
    ] {
        entries.push(grants_entry(
            name,
            GRANT_CONTEXT_SCHEMA_ID,
            grants_source(),
            built.initial_context.clone(),
            digest_map(&[("grantContextDigest", sha256(&built.initial_context))]),
            derived,
            ExpectedOutcome::Accepted,
            None,
        ));
    }

    entries.push(grants_entry(
        "plan/accepted-total-order",
        GRANT_PLAN_SCHEMA_ID,
        grants_source(),
        built.plan_input.clone(),
        digest_map(&[("grantPlanHash", built.plan_hash)]),
        built.plan_sorted.clone(),
        ExpectedOutcome::Accepted,
        None,
    ));
    for (name, flat, code) in built.rejected_plans {
        entries.push(grants_entry(
            name,
            GRANT_PLAN_SCHEMA_ID,
            grants_source(),
            flat.clone(),
            BTreeMap::new(),
            flat,
            ExpectedOutcome::Rejected {
                error_code: code.to_owned(),
            },
            None,
        ));
    }

    for (name, vector) in [
        ("grant/accepted-initial-reader", &built.initial),
        ("grant/accepted-historical-reader", &built.historical),
    ] {
        entries.push(grants_entry(
            name,
            GRANT_SCHEMA_ID,
            frozen_once_source(),
            TEST_ENTROPY_CONTENT_ENCRYPTION_KEY.to_vec(),
            digest_map(&[
                ("grantDigest", vector.grant_digest),
                ("objectHash", *object_hash(&vector.object).as_bytes()),
                ("grantBodyDigest", sha256(&vector.body)),
            ]),
            vector.object.clone(),
            ExpectedOutcome::Accepted,
            None,
        ));
    }

    for (name, bytes) in built.single_byte_defects {
        entries.push(grants_entry(
            name,
            GRANT_SCHEMA_ID,
            frozen_once_source(),
            TEST_ENTROPY_CONTENT_ENCRYPTION_KEY.to_vec(),
            digest_map(&[("objectHash", *object_hash(&bytes).as_bytes())]),
            bytes,
            ExpectedOutcome::Rejected {
                error_code: "EA-FORMAT-COSE".to_owned(),
            },
            Some(GRANT_DEFECT_SITE_NOTE),
        ));
    }

    entries.push(grants_entry(
        "grant/rejected-resigned-flipped-encapsulated-key",
        GRANT_SCHEMA_ID,
        frozen_once_source(),
        TEST_ENTROPY_CONTENT_ENCRYPTION_KEY.to_vec(),
        digest_map(&[(
            "objectHash",
            *object_hash(&built.resigned_encapsulation).as_bytes(),
        )]),
        built.resigned_encapsulation.clone(),
        ExpectedOutcome::Rejected {
            error_code: "EA-CRYPTO-HPKE-OPEN".to_owned(),
        },
        Some(GRANT_RESIGNED_NOTE),
    ));

    VectorManifest {
        family: GRANTS_FAMILY.to_owned(),
        version: GRANTS_V1_VERSION.to_owned(),
        entries,
    }
}

/// Die Herkunftsangabe der deterministischen Grant-Vektoren.
fn grants_source() -> VectorSource {
    VectorSource::GeneratorCommit(GRANTS_GENERATOR.to_owned())
}

/// Die Herkunftsangabe jedes Vektors, der eine Kapselung traegt.
fn frozen_once_source() -> VectorSource {
    VectorSource::FrozenOnce {
        verified_via: "hpke_open".to_owned(),
    }
}

/// Ein Eintrag der Grant-Familie.
#[allow(clippy::too_many_arguments)]
fn grants_entry(
    name: &str,
    schema_id: &str,
    source: VectorSource,
    input_bytes: Vec<u8>,
    intermediate_digests: BTreeMap<String, [u8; 32]>,
    object_bytes: Vec<u8>,
    expected_outcome: ExpectedOutcome,
    scope_note: Option<&str>,
) -> VectorEntry {
    VectorEntry {
        name: name.to_owned(),
        schema_id: schema_id.to_owned(),
        suite_id: GRANTS_SUITE_ID.to_owned(),
        source,
        input_bytes,
        intermediate_digests,
        object_bytes,
        expected_outcome,
        file: format!("{name}.bin"),
        scope_note: scope_note.map(ToOwned::to_owned),
    }
}

// ---------------------------------------------------------------------------
// Vektorfamilie receipts/v1
// ---------------------------------------------------------------------------

/// Der Familienname der Receipt-Vektoren.
pub const RECEIPTS_FAMILY: &str = "receipts";

/// Der Versionsordner der Receipt-Vektoren.
pub const RECEIPTS_V1_VERSION: &str = "v1";

/// Die Wurzel der Receipt-Vektoren, relativ zur Arbeitsbaumwurzel.
pub const RECEIPTS_V1_ROOT: &str = "vectors/receipts/v1";

/// Die Herkunftsangabe der Receipt-Vektoren.
const RECEIPTS_GENERATOR: &str = "ea-testkit::receipts_v1_manifest";

/// Der Suite-Identifikator der Receipt-Vektoren, EINGEFROREN.
const RECEIPTS_SUITE_ID: &str = "EINSATZARCHIV-SUITE-1";

/// Der Schema-Identifikator einer Quittung.
const RECEIPT_SCHEMA_ID: &str = "esr-v1";

/// Die Organisationskennung aller Receipt-Vektoren.
const RECEIPTS_ORGANIZATION_ID: [u8; 16] = [0x50; 16];

/// Die Kettenkennung aller Receipt-Vektoren.
const RECEIPTS_CHAIN_ID: [u8; 16] = [0x51; 16];

/// Der Eintragshash der bestaetigten Quittung.
const RECEIPTS_ENTRY_HASH: [u8; 32] = [0x52; 32];

/// Der Objekthash des bestaetigten Eintrags.
const RECEIPTS_ENTRY_OBJECT_HASH: [u8; 32] = [0x53; 32];

/// Der Eintragshash des Vorgaengers.
const RECEIPTS_PREVIOUS_ENTRY_HASH: [u8; 32] = [0x54; 32];

/// Der Registrierungskopf-Hash aller Receipt-Vektoren.
const RECEIPTS_REGISTRY_HEAD_HASH: [u8; 32] = [0x55; 32];

/// Der Objekthash der wirksamen Richtlinie.
const RECEIPTS_POLICY_OBJECT_HASH: [u8; 32] = [0x56; 32];

/// Der Hash des initialen Grant-Plans.
const RECEIPTS_INITIAL_GRANT_PLAN_HASH: [u8; 32] = [0x57; 32];

/// Der Zertifikatshash der Serverseite.
const RECEIPTS_SERVER_CERTIFICATE_HASH: [u8; 32] = [0x59; 32];

/// Die drei Grant-Objekthashes der Quittung, aufsteigend sortiert.
const RECEIPTS_GRANT_OBJECT_HASHES: [[u8; 32]; 3] = [[0x60; 32], [0x61; 32], [0x62; 32]];

/// Die Registrierungsversion aller Receipt-Vektoren.
const RECEIPTS_REGISTRY_VERSION: u64 = 11;

/// Die Kettensequenz der bestaetigten Quittung.
const RECEIPTS_CHAIN_SEQUENCE: u64 = 7;

/// Die Annahmezeit der Quittung in Millisekunden seit der Epoche.
const RECEIPTS_ACCEPTED_AT_SERVER_MS: i64 = 1_700_000_003_000;

/// Die Evidence-Frist der Quittung in Millisekunden seit der Epoche.
const RECEIPTS_EVIDENCE_DUE_AT_MS: i64 = 1_700_086_400_000;

/// Die Reichweitennotiz des Replay-Vektors.
const RECEIPT_REPLAY_NOTE: &str = "Dieser Vektor ist BYTEIDENTISCH mit receipt/accepted-with-evidence-due. Das ist die eingefrorene Aussage aus Abnahmekriterium 50: acceptedAtServer und evidenceDueAt werden beim Commit genau einmal signiert, und ein Replay aendert weder Zeit noch Bytes.";

/// Die Organisationskennung als getypter Wert.
fn receipts_organization_id() -> OrganizationId {
    OrganizationId::try_from(RECEIPTS_ORGANIZATION_ID.as_slice()).expect("16 bytes")
}

/// Die Kernfelder einer Quittung dieser Familie.
fn receipt_core_fields(with_evidence_due: bool) -> ReceiptCoreFieldsV1 {
    let hashes = if with_evidence_due {
        RECEIPTS_GRANT_OBJECT_HASHES
            .iter()
            .map(|hash| ObjectHash::try_from(hash.as_slice()).expect("32 bytes"))
            .collect()
    } else {
        vec![ObjectHash::try_from(RECEIPTS_GRANT_OBJECT_HASHES[0].as_slice()).expect("32 bytes")]
    };
    ReceiptCoreFieldsV1 {
        organization_id: receipts_organization_id(),
        chain_id: ChainId::try_from(RECEIPTS_CHAIN_ID.as_slice()).expect("16 bytes"),
        chain_sequence: ChainSequence::new(if with_evidence_due {
            RECEIPTS_CHAIN_SEQUENCE
        } else {
            0
        }),
        entry_hash: EntryHash::try_from(RECEIPTS_ENTRY_HASH.as_slice()).expect("32 bytes"),
        entry_object_hash: ObjectHash::try_from(RECEIPTS_ENTRY_OBJECT_HASH.as_slice())
            .expect("32 bytes"),
        previous_entry_hash: with_evidence_due.then(|| {
            EntryHash::try_from(RECEIPTS_PREVIOUS_ENTRY_HASH.as_slice()).expect("32 bytes")
        }),
        registry_version: RegistryVersion::new(RECEIPTS_REGISTRY_VERSION),
        registry_head_hash: Hash32::try_from(RECEIPTS_REGISTRY_HEAD_HASH.as_slice())
            .expect("32 bytes"),
        policy_object_hash: ObjectHash::try_from(RECEIPTS_POLICY_OBJECT_HASH.as_slice())
            .expect("32 bytes"),
        initial_grant_plan_hash: Hash32::try_from(RECEIPTS_INITIAL_GRANT_PLAN_HASH.as_slice())
            .expect("32 bytes"),
        initial_grant_object_hashes: hashes,
        accepted_at_server: UnixMillis::new(RECEIPTS_ACCEPTED_AT_SERVER_MS),
        evidence_due_at: with_evidence_due.then(|| UnixMillis::new(RECEIPTS_EVIDENCE_DUE_AT_MS)),
        server_key_thumbprint: format_public_key(TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED)
            .thumbprint(),
        server_certificate_hash: grants_certificate_hash(RECEIPTS_SERVER_CERTIFICATE_HASH),
    }
}

/// Eine fertige Quittung samt Digest.
fn receipt_vector(with_evidence_due: bool) -> (Vec<u8>, [u8; 32]) {
    let server = format_signer(TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED);
    let core = ReceiptCoreV1::new(receipt_core_fields(with_evidence_due))
        .expect("the frozen receipt core is well formed");
    let digest = receipt_digest(core.exact_bytes());
    let signature = server
        .sign_receipt(core.exact_bytes())
        .expect("signing the frozen receipt core cannot fail");
    let receipt = ReceiptV1::new(core, signature).expect("the frozen receipt is well formed");
    let object = encode_receipt(&receipt)
        .expect("encoding the frozen receipt cannot fail")
        .into_vec();
    (object, *digest.as_bytes())
}

/// Das Manifest der Vektorfamilie `receipts/v1`.
///
/// Vollstaendig deterministisch: Ed25519 signiert deterministisch, alle Felder
/// sind feste Konstanten, und keine Kapselung zieht Entropie.
///
/// # Panics
///
/// Wenn eine der Konstruktionen fehlschlaegt.
#[must_use]
pub fn receipts_v1_manifest() -> VectorManifest {
    let (accepted, accepted_digest) = receipt_vector(true);
    let (without_due, without_due_digest) = receipt_vector(false);

    let mut unsorted = accepted.clone();
    let first = unique_offset(&accepted, &RECEIPTS_GRANT_OBJECT_HASHES[0]);
    let second = unique_offset(&accepted, &RECEIPTS_GRANT_OBJECT_HASHES[1]);
    unsorted[first..first + 32].copy_from_slice(&RECEIPTS_GRANT_OBJECT_HASHES[1]);
    unsorted[second..second + 32].copy_from_slice(&RECEIPTS_GRANT_OBJECT_HASHES[0]);

    let mut duplicate = accepted.clone();
    duplicate[second..second + 32].copy_from_slice(&RECEIPTS_GRANT_OBJECT_HASHES[0]);

    let mut accepted_at = accepted.clone();
    let mut needle = vec![0x1b];
    needle.extend_from_slice(
        &u64::try_from(RECEIPTS_ACCEPTED_AT_SERVER_MS)
            .expect("the frozen server time is positive")
            .to_be_bytes(),
    );
    let offset = unique_offset(&accepted, &needle);
    accepted_at[offset + needle.len() - 1] ^= 0x01;

    let mut signed_digest = accepted.clone();
    let offset = unique_offset(&accepted, &accepted_digest);
    signed_digest[offset] ^= 0x01;

    let entries = vec![
        receipts_entry(
            "receipt/accepted-with-evidence-due",
            digest_map(&[
                ("receiptDigest", accepted_digest),
                ("objectHash", *object_hash(&accepted).as_bytes()),
            ]),
            accepted.clone(),
            ExpectedOutcome::Accepted,
            None,
        ),
        receipts_entry(
            "receipt/accepted-without-evidence-due",
            digest_map(&[
                ("receiptDigest", without_due_digest),
                ("objectHash", *object_hash(&without_due).as_bytes()),
            ]),
            without_due,
            ExpectedOutcome::Accepted,
            None,
        ),
        receipts_entry(
            "receipt/replay-of-accepted-with-evidence-due",
            digest_map(&[
                ("receiptDigest", accepted_digest),
                ("objectHash", *object_hash(&accepted).as_bytes()),
            ]),
            accepted,
            ExpectedOutcome::Accepted,
            Some(RECEIPT_REPLAY_NOTE),
        ),
        receipts_entry(
            "receipt/rejected-duplicate-grant-hashes",
            digest_map(&[("objectHash", *object_hash(&duplicate).as_bytes())]),
            duplicate,
            ExpectedOutcome::Rejected {
                error_code: "EA-FORMAT-DUPLICATE".to_owned(),
            },
            None,
        ),
        receipts_entry(
            "receipt/rejected-flipped-accepted-at-server",
            digest_map(&[("objectHash", *object_hash(&accepted_at).as_bytes())]),
            accepted_at,
            ExpectedOutcome::Rejected {
                error_code: "EA-FORMAT-COSE".to_owned(),
            },
            None,
        ),
        receipts_entry(
            "receipt/rejected-flipped-signed-receipt-digest",
            digest_map(&[("objectHash", *object_hash(&signed_digest).as_bytes())]),
            signed_digest,
            ExpectedOutcome::Rejected {
                error_code: "EA-FORMAT-COSE".to_owned(),
            },
            None,
        ),
        receipts_entry(
            "receipt/rejected-unsorted-grant-hashes",
            digest_map(&[("objectHash", *object_hash(&unsorted).as_bytes())]),
            unsorted,
            ExpectedOutcome::Rejected {
                error_code: "EA-FORMAT-UNSORTED".to_owned(),
            },
            None,
        ),
    ];

    VectorManifest {
        family: RECEIPTS_FAMILY.to_owned(),
        version: RECEIPTS_V1_VERSION.to_owned(),
        entries,
    }
}

/// Ein Eintrag der Receipt-Familie.
fn receipts_entry(
    name: &str,
    intermediate_digests: BTreeMap<String, [u8; 32]>,
    object_bytes: Vec<u8>,
    expected_outcome: ExpectedOutcome,
    scope_note: Option<&str>,
) -> VectorEntry {
    VectorEntry {
        name: name.to_owned(),
        schema_id: RECEIPT_SCHEMA_ID.to_owned(),
        suite_id: RECEIPTS_SUITE_ID.to_owned(),
        source: VectorSource::GeneratorCommit(RECEIPTS_GENERATOR.to_owned()),
        input_bytes: Vec::new(),
        intermediate_digests,
        object_bytes,
        expected_outcome,
        file: format!("{name}.bin"),
        scope_note: scope_note.map(ToOwned::to_owned),
    }
}

// ---------------------------------------------------------------------------
// Vektorfamilie evidence/v1
// ---------------------------------------------------------------------------

/// Der Familienname der Evidence-Vektoren.
pub const EVIDENCE_FAMILY: &str = "evidence";

/// Der Versionsordner der Evidence-Vektoren.
pub const EVIDENCE_V1_VERSION: &str = "v1";

/// Die Wurzel der Evidence-Vektoren, relativ zur Arbeitsbaumwurzel.
pub const EVIDENCE_V1_ROOT: &str = "vectors/evidence/v1";

/// Die Herkunftsangabe der Evidence-Vektoren.
const EVIDENCE_GENERATOR: &str = "ea-testkit::evidence_v1_manifest";

/// Der Suite-Identifikator der Evidence-Vektoren, EINGEFROREN.
const EVIDENCE_SUITE_ID: &str = "EINSATZARCHIV-SUITE-1";

/// Der Schema-Identifikator eines Evidence-Objekts.
const EVIDENCE_SCHEMA_ID: &str = "ecp-v1";

/// Der Schema-Identifikator eines RFC-9921-Imprints.
const EVIDENCE_IMPRINT_SCHEMA_ID: &str = "cose-ctt-imprint-v1";

/// Die Organisationskennung aller Evidence-Vektoren.
const EVIDENCE_ORGANIZATION_ID: [u8; 16] = [0x70; 16];

/// Die Kettenkennung aller Evidence-Vektoren.
const EVIDENCE_CHAIN_ID: [u8; 16] = [0x71; 16];

/// Der Kopf-Eintragshash der bezeugten Spanne.
const EVIDENCE_HEAD_ENTRY_HASH: [u8; 32] = [0x72; 32];

/// Der Registrierungskopf-Hash aller Evidence-Vektoren.
const EVIDENCE_REGISTRY_HEAD_HASH: [u8; 32] = [0x73; 32];

/// Der Zertifikatshash der Serverseite.
const EVIDENCE_SERVER_CERTIFICATE_HASH: [u8; 32] = [0x74; 32];

/// Die Ausstellzeit des Checkpoints in Millisekunden seit der Epoche.
const EVIDENCE_ISSUED_AT_SERVER_MS: i64 = 1_700_000_004_000;

/// Die letzte bezeugte Kettensequenz.
const EVIDENCE_COVERED_THROUGH_SEQUENCE: u64 = 7;

/// Die Nonce der Zeitstempelanfrage, wie sie das Archiv festhaelt.
const EVIDENCE_REQUEST_NONCE: [u8; 16] = [0x80; 16];

/// Die Nonce des Negativvektors: sie gehoert zu keiner Anfrage dieses Tokens.
const EVIDENCE_WRONG_REQUEST_NONCE: [u8; 16] = [0x81; 16];

/// Der Versatz des `messageImprint`-Hashwertes im Zeitstempeltoken.
///
/// GEMESSEN, nicht gezaehlt: das Vorlagentoken traegt genau EINE
/// SHA-256-`AlgorithmIdentifier` mit nachfolgendem 32-Byte-OCTET-STRING, und
/// `evidence_timestamp_token` prueft die Umgebung bei jedem Aufbau nach.
pub const EVIDENCE_TOKEN_MESSAGE_IMPRINT_OFFSET: usize = 100;

/// Der Versatz der TSA-Policy-OID im Zeitstempeltoken.
pub const EVIDENCE_TOKEN_POLICY_OID_OFFSET: usize = 75;

/// Die Laenge der TSA-Policy-OID einschliesslich ihres DER-Kopfes.
pub const EVIDENCE_TOKEN_POLICY_OID_LENGTH: usize = 6;

/// Die DER-Kodierung der erwarteten TSA-Policy: OID 1.2.3.4.1.
const EVIDENCE_POLICY_OID_DER: [u8; EVIDENCE_TOKEN_POLICY_OID_LENGTH] =
    [0x06, 0x04, 0x2a, 0x03, 0x04, 0x01];

/// Der Platzhalter der TSA-Zertifikatskette.
///
/// `ecp-v1` verlangt eine NICHTLEERE Kette (`decode_bstr_array` mit
/// `require_nonempty`), parst sie in Stufe 1 aber nicht: die Kettenpruefung
/// ist nach `design.md` 22.6 Gegenstand der Stufe 6. Der Platzhalter ist
/// deshalb eine minimale, wohlgeformte DER-SEQUENCE und KEIN Zertifikat.
const EVIDENCE_TSA_CERTIFICATE_DER: [u8; 5] = [0x30, 0x03, 0x02, 0x01, 0x00];

/// Die DER-Kodierung der abweichenden TSA-Policy: OID 1.2.3.4.2.
const EVIDENCE_WRONG_POLICY_OID_DER: [u8; EVIDENCE_TOKEN_POLICY_OID_LENGTH] =
    [0x06, 0x04, 0x2a, 0x03, 0x04, 0x02];

/// Die DER-Kodierung der SHA-256-`AlgorithmIdentifier` mit NULL-Parametern und
/// dem Kopf des nachfolgenden 32-Byte-OCTET-STRINGs.
const EVIDENCE_SHA256_IMPRINT_PREFIX: [u8; 15] = [
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
];

/// Die Reichweitennotiz jedes Vektors, dessen Defekt IM Zeitstempeltoken sitzt.
///
/// Ohne sie liest sich ein `accepted` als Freispruch. Es ist keiner: `ea-verify`
/// kommt an den Inhalt des DER-Tokens nicht heran — `validate_timestamp_token_der`
/// ist in `ea-crypto` privat und gibt weder `messageImprint` noch Policy heraus
/// (`crates/ea-verify/src/evidence.rs`). Der Vektor haelt den Defekt trotzdem
/// fest, und der Test rechnet ihn ueber die eingefrorenen Versaetze nach; die
/// Ablehnung selbst ist die Stufe-6-Grenze.
const EVIDENCE_TOKEN_INTERNAL_NOTE: &str = "Der Defekt sitzt IM DER-Zeitstempeltoken. Stufe 1 nimmt dieses Objekt an: ea-verify sieht nicht in das Token hinein, weil validate_timestamp_token_der in ea-crypto privat ist und weder messageImprint noch TSA-Policy herausgibt (crates/ea-verify/src/evidence.rs). Der Test rechnet den Defekt ueber die eingefrorenen Versaetze nach; die Ablehnung ist die Stufe-6-Grenze.";

/// Die Reichweitennotiz des Nonce-Vektors.
const EVIDENCE_NONCE_NOTE: &str = "Dieser Vektor traegt eine Nonce, die zu keiner Anfrage dieses Tokens gehoert. Stufe 1 nimmt ihn an: die Nonce steht im Archivfeld request-nonce, und der Vergleich mit dem Token setzt einen DER-Parser voraus, den ea-verify nicht hat. Die Ablehnung ist die Stufe-6-Grenze.";

/// Die Reichweitennotiz des ersetzten CTT-Headers.
const EVIDENCE_REPLACED_NOTE: &str = "Der Fehlercode stammt aus ea_verify::EvidenceGateErrorV1::TokenNotBound. Gate evidence ist von aussen nicht aufrufbar — run_evidence_gate ist pub(crate) und braucht einen vollstaendigen Bestand. Der Test fuehrt deshalb die ERREICHBARE Bindung aus token_is_bound nach: das im COSE eingebettete Token gegen das daneben archivierte. Die Formatebene nimmt dieses Objekt an.";
/// Das Vorlagentoken der Evidence-Vektoren: die RFC-9921-Beispielantwort.
///
/// UEBERNOMMEN aus `crates/ea-crypto/tests/cose_profile.rs`, wo sie den
/// CTT-Header-Nachweis traegt. Sie ist hier VORLAGE, nicht Vektor: die
/// Evidence-Familie ersetzt darin zwei Felder gleicher Laenge, damit der
/// `messageImprint` die Signatur DIESER Objekte benennt. Ein Eintrag dieser
/// Familie ist deshalb von RFC 9921 ABGELEITET, nicht von dort uebernommen.
const EVIDENCE_RFC3161_TOKEN_TEMPLATE: &str = concat!(
    "3082154906092a864886f70d010702a082153a30821536020103310f300d0609608648016503040203050030820184060b2a864886f70d",
    "0109100104a08201730482016f3082016b02010106042a0304013031300d060960864801650304020105000420dd9471efe743c4051335",
    "df8f6d2882f3badc387700f7ed3f7091672a3eeaf7c8020400b8a1ea180f32303235303832393037353330305a0101ffa0820111a48201",
    "0d308201093111300f060355040a13084672656520545341310c300a060355040b130354534131763074060355040d136d546869732063",
    "65727469666963617465206469676974616c6c79207369676e7320646f63756d656e747320616e642074696d65207374616d7020726571",
    "7565737473206d616465207573696e672074686520667265657473612e6f7267206f6e6c696e6520736572766963657331183016060355",
    "0403130f7777772e667265657473612e6f72673122302006092a864886f70d0109011613627573696c657a617340676d61696c2e636f6d",
    "3112301006035504071309577565727a62757267310b3009060355040613024445310f300d0603550408130642617965726ea082100830",
    "820801308205e9a003020102020900c1e986160da8e982300d06092a864886f70d01010d05003081953111300f060355040a1308467265",
    "65205453413110300e060355040b1307526f6f74204341311830160603550403130f7777772e667265657473612e6f7267312230200609",
    "2a864886f70d0109011613627573696c657a617340676d61696c2e636f6d3112301006035504071309577565727a62757267310f300d06",
    "03550408130642617965726e310b3009060355040613024445301e170d3136303331333031353733395a170d3236303331313031353733",
    "395a308201093111300f060355040a13084672656520545341310c300a060355040b130354534131763074060355040d136d5468697320",
    "6365727469666963617465206469676974616c6c79207369676e7320646f63756d656e747320616e642074696d65207374616d70207265",
    "717565737473206d616465207573696e672074686520667265657473612e6f7267206f6e6c696e65207365727669636573311830160603",
    "550403130f7777772e667265657473612e6f72673122302006092a864886f70d0109011613627573696c657a617340676d61696c2e636f",
    "6d3112301006035504071309577565727a62757267310b3009060355040613024445310f300d0603550408130642617965726e30820222",
    "300d06092a864886f70d01010105000382020f003082020a0282020100b591048c4e486f34e9dc08627fc2375162236984b82cb130beff",
    "517cfc38f84bce5c65a874dab2621ae0bce7e33563e0ede934fd5f8823159f07848808227460c1ed88261706f4281334359dfbb81bd135",
    "3fc179610af1a8c8c865dc00ea23b3a89be6bd03ba85a9ec827d60565905e22d6a584ed1380ae150280cee397e98a012f3804640078624",
    "43bc077cb95f421af31712d9683cdb6dffbaf3c8ba5ba566ae523d459d6177346d4d840e27886b7c01c5b890d78a2e27bba8dd2f9a2812",
    "e157d62f921c65962548069dcdb7d06de181de0e9570d66f87220ce28b628ab55906f3ee0c210f7051e8f4858af8b9a92d09e46af2d9cb",
    "a5bfcfad168cdf604491a4b06603b114caf7031f065e7eeefa53c575f3490c059d2e32ddc76ac4d4c4c710683b97fd1be591bc61055186",
    "d88f9a0391b307b6f91ed954daa36f9acd6a1e14aa2e4adf17464b54db18dbb6ffe30080246547370436ce4e77bae5de6fe0f3f9d6e7ff",
    "beb461e794e92fb0951f8aae61a412cce9b21074635c8be327ae1a0f6b4a646eb0f8463bc63bf845530435d19e802511ec9f66c3496952",
    "d8becb69b0aa4d4c41f60515fe7dcbb89319cdda59ba6aea4be3ceae718e6fcb6ccd7db9fc50bb15b12f3665b0aa307289c2e6dd4b111c",
    "e48ba2d9efdb5a6b9a506069334fb34f6fc7ae330f0b34208aac80df3266fdd90465876ba2cb898d9505315b6e7b0203010001a38201db",
    "308201d730090603551d1304023000301d0603551d0e041604146e760b7b4e4f9ce160ca6d2ce927a2a294b37737301f0603551d230418",
    "30168014fa550d8c346651434cf7e7b3a76c95af7ae6a497300b0603551d0f0404030206c030160603551d250101ff040c300a06082b06",
    "010505070308306306082b0601050507010104573055302a06082b06010505073002861e687474703a2f2f7777772e667265657473612e",
    "6f72672f7473612e637274302706082b06010505073001861b687474703a2f2f7777772e667265657473612e6f72673a32353630303706",
    "03551d1f0430302e302ca02aa0288626687474703a2f2f7777772e667265657473612e6f72672f63726c2f726f6f745f63612e63726c30",
    "81c60603551d200481be3081bb3081b80601003081b2303306082b060105050702011627687474703a2f2f7777772e667265657473612e",
    "6f72672f667265657473615f6370732e68746d6c303206082b060105050702011626687474703a2f2f7777772e667265657473612e6f72",
    "672f667265657473615f6370732e706466304706082b06010505070202303b1a394672656554534120747275737465642074696d657374",
    "616d70696e6720536f6674776172652061732061205365727669636520285361615329300d06092a864886f70d01010d05000382020100",
    "a5c944e2c6fac0a14d930a7fd0a0b172b41fc1483c3e957c68a2bcd9b9764f1a950161fd72472d41a5eed277786203b5422240fb3a26cd",
    "e176087b6fb1011df4cc19e2571aa4a051109665e94c46f50bd2adee6ac4137e251b25a39dabda451515d8ff9e07209e8ec20b7874f7e1",
    "a0ede7c00937fe84a334f8b3265ced2d8ed9df61396583677feb382c1ee3b23e6ea5f05df30de7b9f89005d25266f612f39c8b4f6daba6",
    "d7bfbac19632b90637329f52a6f066a10e43eaa81f849a6c5fe3fe8b5ea23275f687f2052e502ea6c30762a668cce07871dd8e97e315bb",
    "a929e25589977a0a312ce96c5106b1437c779f2b361b182888f3ee8a234374fa063e956192627f7c431073965d1260928eba009e803429",
    "ae324cf96f042354f37bca5afddc79f79346ab388bfc79f01dc9861254ea6cc129941076b83d20556f3be51326837f2876f7833b370e7c",
    "3d410523827d4f53400c72218d75229ff10c6f8893a9a3a1c0c42bb4c898c13df41c7f6573b4fc56515971a610a7b0d2857c8225a9fb20",
    "4eaceca2e8971aa1af87886a2ae3c72fe0a0aae842980a77bef16b92115458090d982b5946603764e75a0ad3d11454b9986f678b9ab6af",
    "e8497033ae3abfd4eb43b7bc9dee68815949e6481582a82e785277f2282107efe390200e0508acb8ea82ea2505276f3c9da2a3d3b4ad38",
    "bbf8842bda36fc2448291f558dc02dd1e0308207ff308205e7a003020102020900c1e986160da8e980300d06092a864886f70d01010d05",
    "003081953111300f060355040a130846726565205453413110300e060355040b1307526f6f74204341311830160603550403130f777777",
    "2e667265657473612e6f72673122302006092a864886f70d0109011613627573696c657a617340676d61696c2e636f6d31123010060355",
    "04071309577565727a62757267310f300d0603550408130642617965726e310b3009060355040613024445301e170d3136303331333031",
    "353231335a170d3431303330373031353231335a3081953111300f060355040a130846726565205453413110300e060355040b1307526f",
    "6f74204341311830160603550403130f7777772e667265657473612e6f72673122302006092a864886f70d0109011613627573696c657a",
    "617340676d61696c2e636f6d3112301006035504071309577565727a62757267310f300d0603550408130642617965726e310b30090603",
    "5504061302444530820222300d06092a864886f70d01010105000382020f003082020a0282020100b6028e0e3032f11110d964cda94b9d",
    "0278e1942ae913aaa59907cda69793995bd9ac7e33bad9fe3704da1c01a98d21afe3f591a59d7067705167998f5016722e0ab462b21f43",
    "9171d2cfcc4593f3735af794a5ab311f6c010c7898de33d75c4510ee76f4bd1d1498cf17d303f06a5dd9f796cc6ca9b657a56fe3ea4fef",
    "be7ce6b6a18d3e35a30cee5ff170d1cf39a333d3fda8964d22db685b29e561be890f0aa845873b2e84ab26ab839ffe8fade9d23bb31e61",
    "d273cc9b880649185fabecfa0534600aba901b614e2e854582dea2226fc19cd7df52bed50d8777cd9988c053a3fc7dc3287a068a4ff12b",
    "713cd9803666e955385456ff38f80298cf6b93856e9224774a66cf1cdd11c2f8efd85203d7458b25664b13ed639cded4ff8113d6cc5353",
    "d2729473c3c307157c722aa5b5dd0bfb2d6c38b1b93749c881ec60026d08951b3824bd71bacbce473aebd636f0b918b4a2c8ff4694f074",
    "57af2d6f1cf82554d1770fd79ff5d314dcd104cddcabc94138056dfcf017e7eb8572fd52f70144f188da05f5823f58dd06297e7387bed2",
    "d772c13da8266601045fe412dd70986c0c987ba7344b9037387516d258e7885b51f8968b7f2601213bc4cb4c85f8ff0b84af6a988337cd",
    "fb81868f7ecf31dca6716d7ec2dd802c1672629e5c0052cb357dd29aafc43f615b3b1ff9d4e1ce08c71c73e1febb7dc56a33621329e9ed",
    "6c230203010001a382024e3082024a300c0603551d13040530030101ff300e0603551d0f0101ff0404030201c6301d0603551d0e041604",
    "14fa550d8c346651434cf7e7b3a76c95af7ae6a4973081ca0603551d230481c23081bf8014fa550d8c346651434cf7e7b3a76c95af7ae6",
    "a497a1819ba481983081953111300f060355040a130846726565205453413110300e060355040b1307526f6f7420434131183016060355",
    "0403130f7777772e667265657473612e6f72673122302006092a864886f70d0109011613627573696c657a617340676d61696c2e636f6d",
    "3112301006035504071309577565727a62757267310f300d0603550408130642617965726e310b3009060355040613024445820900c1e9",
    "86160da8e98030330603551d1f042c302a3028a026a0248622687474703a2f2f7777772e667265657473612e6f72672f726f6f745f6361",
    "2e63726c3081cf0603551d200481c73081c43081c1060a2b0601040181f22401013081b2303306082b060105050702011627687474703a",
    "2f2f7777772e667265657473612e6f72672f667265657473615f6370732e68746d6c303206082b060105050702011626687474703a2f2f",
    "7777772e667265657473612e6f72672f667265657473615f6370732e706466304706082b06010505070202303b1a394672656554534120",
    "747275737465642074696d657374616d70696e6720536f6674776172652061732061205365727669636520285361615329303706082b06",
    "010505070101042b3029302706082b06010505073001861b687474703a2f2f7777772e667265657473612e6f72673a32353630300d0609",
    "2a864886f70d01010d0500038202010068af7ebf938562ef4ceb3b580be2faf6cc35a26772962f3d95901fa5630c87d09198984ce8a06a",
    "33f8a9c282ed9f1cb11ac6c23e17108ee4efce6fb294de95c133262255725522ca61971d4a3b7f78250dfb8d4aeec0fb1959b164100520",
    "b9c10e64c62662e4ad4d0abae2298fc948fc4e99e8d9e6b8fdbe4404121ec7c1422eacb2c9d7328e07396e60b4f3bb803ad4a555c80fef",
    "b53f85e7764a0a9fb4afc399f4cd2f5fbf587105c6081cf3d05337b6bb7d1b010b749f4888c912f3696ba1b6902d77b7dfc046c04a0cc1",
    "ec4f8d185e2da55dfb7bc2a2036c6219246a4f99ddbb6f1f829398f3b803dc0ad90dcb59bef4c27c77404b99043b78271867991152c399",
    "f12cbfc4c625adc096355ae44e342100ec517a502e2f06f940b8d43599bbc1154f8ae761a0b0d555fb4a1391d4f3420af8dbf12f2d7ddb",
    "9d77dce1537804074af175e4f2d6d55b34b5d6f7dcbdd31730af56480d4c0cff143f9e83bc151866d0ba0f0bbdc47fe27864176bbd6c1a",
    "b85df325edf777889bc4471bf3fa73e56cc591e8b160cda7b0786a1ec04ac3b24fa2e28d5d19e5e48004d5e166a83c82ec6fd54fb385eb",
    "af7133a85b52de46db5244e1c34ae8d36e712f9fce0d493d7d3edd586c6198e3ec3e6e96346f417ac9f221e0aff33a8f6a0b1ef4c02363",
    "0b76adaa8d91433825ecc41c49a5b98b181c7da30e997ab954c73c2cd805afda993182038a308203860201013081a33081953111300f06",
    "0355040a130846726565205453413110300e060355040b1307526f6f74204341311830160603550403130f7777772e667265657473612e",
    "6f72673122302006092a864886f70d0109011613627573696c657a617340676d61696c2e636f6d3112301006035504071309577565727a",
    "62757267310f300d0603550408130642617965726e310b3009060355040613024445020900c1e986160da8e982300d0609608648016503",
    "0402030500a081b8301a06092a864886f70d010903310d060b2a864886f70d0109100104301c06092a864886f70d010905310f170d3235",
    "303832393037353330305a302b060b2a864886f70d010910020c311c301a301830160414916da3d860ecca82e34bc59d1793e7e968875f",
    "14304f06092a864886f70d010904314204401d3b1f355cc995b2c7a38dfee19a0815ae93a9078cea6db540501eedf305e9f9f41349096a",
    "089bf5358380d6ed01eb508cbb551d120e9aca924429148ef1a229300d06092a864886f70d0101010500048202004f22fe5e554c950f7f",
    "74462adde4f7c4c412d60479c6950c2509d1a5063e04c284eb42dda42e3591447b63fdc72c953ef04c81c1e59874c4d02cfb6b63de977d",
    "439998995e960a25755304a12ed23e7ccae97678a3dd94bc4025399806c9d00454a740800d3dc13016143af48b80c1d24033694f2bedb7",
    "c25d35c065e9c2fe71cee598ac2e8700bed5b755f001da3227f85fc178f27c56564ef5ff64b874916ab6fd2d966c542936a9940d0a5685",
    "463dc8e5b6ee82d639abb683433603541db3362ad77667e2ded4160c8f87e5c048d6bd05a7831871bb1052ddac132f35baadc2ceea4183",
    "4efd276d4d2a8525879bd909b3d930d3cd4ef1d87d1a5f47bd9bef00956fee8e55d2d40b7447074a7295b204f07ee086775729d9cdb594",
    "0795612722388cb3af8a96fac65c79179c7e5292ce06e3f582e3f7d8fa6d7d41759bbd593b32a0fac8149a2b015e795fca2810133c2d76",
    "8ef8d9da66ba192cbf142d2e4571e491ed7f7b0eb920f22c4492ba0260d30fef98a4d503693afe3dcc561b04bb3b32d8a49f27f988fefa",
    "a5f7b1af110bdad64a2825348a46651e1371e625c9792dfe9780528e5eb17f6078fcb418a420129e7a19bf8f27508b256e755753d8e6b4",
    "36c384fa350c2e4e9018fd372cf54f303d462832675c8ac89f04c360a1d0d82f8d52ff7d815e74ad4aa19a68a9acfd2450855dcb3b2a52",
    "8063d426dc30268f",
);

/// Die Organisationskennung als getypter Wert.
fn evidence_organization_id() -> OrganizationId {
    OrganizationId::try_from(EVIDENCE_ORGANIZATION_ID.as_slice()).expect("16 bytes")
}

/// Ein Zeitstempeltoken mit gesetztem Imprint und gesetzter Policy.
///
/// Das Vorlagentoken ist die RFC-9921-Beispielantwort aus dem Bestand
/// (`crates/ea-crypto/tests/cose_profile.rs`). Ersetzt werden AUSSCHLIESSLICH
/// zwei Felder gleicher Laenge — der 32 Byte lange `messageImprint`-Hashwert
/// und die vier Byte lange Policy-OID. Alle DER-Laengen bleiben damit
/// unveraendert, und `UnverifiedRfc3161TimeStampToken::from_der` prueft das
/// Ergebnis bei jedem Aufbau nach. DAS ERGEBNIS IST KEIN RFC-9921-VEKTOR MEHR;
/// es ist davon ABGELEITET.
fn evidence_timestamp_token(imprint: &[u8; 32], policy: &[u8; 6]) -> Vec<u8> {
    let mut der = decode(EVIDENCE_RFC3161_TOKEN_TEMPLATE);
    assert_eq!(
        &der[EVIDENCE_TOKEN_MESSAGE_IMPRINT_OFFSET - EVIDENCE_SHA256_IMPRINT_PREFIX.len()
            ..EVIDENCE_TOKEN_MESSAGE_IMPRINT_OFFSET],
        EVIDENCE_SHA256_IMPRINT_PREFIX.as_slice(),
        "the frozen offset must sit behind the SHA-256 message imprint header"
    );
    assert_eq!(
        &der[EVIDENCE_TOKEN_POLICY_OID_OFFSET
            ..EVIDENCE_TOKEN_POLICY_OID_OFFSET + EVIDENCE_TOKEN_POLICY_OID_LENGTH],
        EVIDENCE_POLICY_OID_DER.as_slice(),
        "the frozen offset must sit on the TSA policy OID"
    );
    der[EVIDENCE_TOKEN_MESSAGE_IMPRINT_OFFSET..EVIDENCE_TOKEN_MESSAGE_IMPRINT_OFFSET + 32]
        .copy_from_slice(imprint);
    der[EVIDENCE_TOKEN_POLICY_OID_OFFSET
        ..EVIDENCE_TOKEN_POLICY_OID_OFFSET + EVIDENCE_TOKEN_POLICY_OID_LENGTH]
        .copy_from_slice(policy);
    UnverifiedRfc3161TimeStampToken::from_der(&der)
        .expect("the spliced token keeps its DER structure");
    der
}

/// Die Archivfelder eines Zeitstempels.
fn evidence_fields(token: &[u8], nonce: &[u8; 16], policy: &[u8; 6]) -> Rfc3161EvidenceFieldsV1 {
    Rfc3161EvidenceFieldsV1 {
        rfc3161_response_der: token.to_vec(),
        request_nonce: nonce.to_vec(),
        policy_oid_der: policy.to_vec(),
        tsa_certificate_chain_der: vec![EVIDENCE_TSA_CERTIFICATE_DER.to_vec()],
        revocation_data_der: Vec::new(),
        validation_data_der: Vec::new(),
    }
}

/// Die 64 Signaturbytes einer COSE-Struktur.
fn evidence_signature(cose: &[u8]) -> [u8; 64] {
    *parse_cose_sign1(cose, &[])
        .expect("the frozen COSE object parses")
        .signature_bytes()
}

/// Der Checkpoint-Kern aller Zeitstempelvektoren.
fn evidence_checkpoint_core() -> CheckpointCoreV1 {
    CheckpointCoreV1::new(CheckpointCoreFieldsV1 {
        organization_id: evidence_organization_id(),
        chain_id: ChainId::try_from(EVIDENCE_CHAIN_ID.as_slice()).expect("16 bytes"),
        covered_from_sequence: ChainSequence::new(0),
        covered_through_sequence: ChainSequence::new(EVIDENCE_COVERED_THROUGH_SEQUENCE),
        head_entry_hash: EntryHash::try_from(EVIDENCE_HEAD_ENTRY_HASH.as_slice())
            .expect("32 bytes"),
        registry_head_hash: Hash32::try_from(EVIDENCE_REGISTRY_HEAD_HASH.as_slice())
            .expect("32 bytes"),
        issued_at_server: UnixMillis::new(EVIDENCE_ISSUED_AT_SERVER_MS),
        previous_evidence_hash: None,
    })
    .expect("the frozen checkpoint core is well formed")
}

/// Die erzeugten Bestandteile der Evidence-Familie.
struct EvidenceObjects {
    core: Vec<u8>,
    imprint: [u8; 32],
    bound: Vec<u8>,
    mismatched_imprint: Vec<u8>,
    wrong_nonce: Vec<u8>,
    wrong_policy: Vec<u8>,
    removed_ctt: Vec<u8>,
    replaced_ctt: Vec<u8>,
    renewal: Vec<u8>,
    renewal_core: Vec<u8>,
    renewal_imprint: [u8; 32],
    renewal_input_digest: [u8; 32],
    signature: [u8; 64],
}

/// Die Bestandteile der Evidence-Familie, deterministisch erzeugt.
///
/// # Panics
///
/// Wenn eine der Konstruktionen fehlschlaegt.
fn evidence_objects() -> EvidenceObjects {
    let server = format_signer(TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED);
    let certificate = grants_certificate_hash(EVIDENCE_SERVER_CERTIFICATE_HASH);
    let core = evidence_checkpoint_core();
    let base = server
        .sign_checkpoint(certificate, core.exact_bytes())
        .expect("signing the frozen checkpoint core cannot fail");
    let signature = evidence_signature(&base);
    let imprint = *cose_sign1_ctt_imprint(&signature).as_bytes();
    let mut mismatched = imprint;
    mismatched[0] ^= 0x01;

    let token = evidence_timestamp_token(&imprint, &EVIDENCE_POLICY_OID_DER);
    let mismatched_token = evidence_timestamp_token(&mismatched, &EVIDENCE_POLICY_OID_DER);
    let wrong_policy_token = evidence_timestamp_token(&imprint, &EVIDENCE_WRONG_POLICY_OID_DER);

    let timestamped = attach_rfc3161_ctt(
        &base,
        &UnverifiedRfc3161TimeStampToken::from_der(&token).expect("the spliced token parses"),
    )
    .expect("attaching the frozen token cannot fail");

    let bound = evidence_object(
        &core,
        &timestamped,
        &evidence_fields(&token, &EVIDENCE_REQUEST_NONCE, &EVIDENCE_POLICY_OID_DER),
    );
    let mismatched_imprint = evidence_object(
        &core,
        &attach_rfc3161_ctt(
            &base,
            &UnverifiedRfc3161TimeStampToken::from_der(&mismatched_token)
                .expect("the spliced token parses"),
        )
        .expect("attaching the frozen token cannot fail"),
        &evidence_fields(
            &mismatched_token,
            &EVIDENCE_REQUEST_NONCE,
            &EVIDENCE_POLICY_OID_DER,
        ),
    );
    let wrong_nonce = evidence_object(
        &core,
        &timestamped,
        &evidence_fields(
            &token,
            &EVIDENCE_WRONG_REQUEST_NONCE,
            &EVIDENCE_POLICY_OID_DER,
        ),
    );
    let wrong_policy = evidence_object(
        &core,
        &attach_rfc3161_ctt(
            &base,
            &UnverifiedRfc3161TimeStampToken::from_der(&wrong_policy_token)
                .expect("the spliced token parses"),
        )
        .expect("attaching the frozen token cannot fail"),
        &evidence_fields(
            &wrong_policy_token,
            &EVIDENCE_REQUEST_NONCE,
            &EVIDENCE_POLICY_OID_DER,
        ),
    );
    // Der ersetzte CTT-Header: im COSE steht das gueltige Token, daneben
    // archiviert liegt ein anderes. `ea-format` vergleicht die beiden NICHT;
    // die Bindung ist der Gegenstand von Gate `evidence`.
    let replaced_ctt = evidence_object(
        &core,
        &timestamped,
        &evidence_fields(
            &wrong_policy_token,
            &EVIDENCE_REQUEST_NONCE,
            &EVIDENCE_POLICY_OID_DER,
        ),
    );
    // Der entfernte CTT-Header. `EvidenceObjectV1::timestamp` wuerde ihn
    // ablehnen, also entsteht er durch Austausch der COSE-Struktur im fertigen
    // Objekt. Ein CBOR-Array traegt keine Bytelaenge, und das Objektpraefix
    // ebenso wenig — der Austausch ist deshalb ein reiner Bytetausch.
    let offset = unique_offset(&bound, &timestamped);
    let mut removed_ctt = Vec::with_capacity(bound.len());
    removed_ctt.extend_from_slice(&bound[..offset]);
    removed_ctt.extend_from_slice(&base);
    removed_ctt.extend_from_slice(&bound[offset + timestamped.len()..]);

    // Das Renewal erneuert genau dieses Zeitstempelobjekt.
    let input = renewal_input_digest(&bound);
    let renewal_core = RenewalCoreV1::new(RenewalCoreFieldsV1 {
        organization_id: evidence_organization_id(),
        chain_id: ChainId::try_from(EVIDENCE_CHAIN_ID.as_slice()).expect("16 bytes"),
        current_entry_hash: EntryHash::try_from(EVIDENCE_HEAD_ENTRY_HASH.as_slice())
            .expect("32 bytes"),
        previous_renewal_hash: None,
        renewal_input_hashes: vec![input],
    })
    .expect("the frozen renewal core is well formed");
    let renewal_base = server
        .sign_evidence_renewal(certificate, renewal_core.exact_bytes())
        .expect("signing the frozen renewal core cannot fail");
    let renewal_imprint = *cose_sign1_ctt_imprint(&evidence_signature(&renewal_base)).as_bytes();
    let renewal_token = evidence_timestamp_token(&renewal_imprint, &EVIDENCE_POLICY_OID_DER);
    let renewal_signed = attach_rfc3161_ctt(
        &renewal_base,
        &UnverifiedRfc3161TimeStampToken::from_der(&renewal_token)
            .expect("the spliced token parses"),
    )
    .expect("attaching the frozen token cannot fail");
    let renewal = encode_evidence(
        &EvidenceObjectV1::renewal(
            RenewalCoreV1::new(RenewalCoreFieldsV1 {
                organization_id: evidence_organization_id(),
                chain_id: ChainId::try_from(EVIDENCE_CHAIN_ID.as_slice()).expect("16 bytes"),
                current_entry_hash: EntryHash::try_from(EVIDENCE_HEAD_ENTRY_HASH.as_slice())
                    .expect("32 bytes"),
                previous_renewal_hash: None,
                renewal_input_hashes: vec![input],
            })
            .expect("the frozen renewal core is well formed"),
            renewal_signed,
            evidence_fields(
                &renewal_token,
                &EVIDENCE_REQUEST_NONCE,
                &EVIDENCE_POLICY_OID_DER,
            ),
        )
        .expect("the frozen renewal object is well formed"),
    )
    .expect("encoding the frozen renewal cannot fail")
    .into_vec();

    EvidenceObjects {
        core: core.exact_bytes().to_vec(),
        imprint,
        bound,
        mismatched_imprint,
        wrong_nonce,
        wrong_policy,
        removed_ctt,
        replaced_ctt,
        renewal,
        renewal_core: renewal_core.exact_bytes().to_vec(),
        renewal_imprint,
        renewal_input_digest: *input.as_bytes(),
        signature,
    }
}

/// Ein fertiges `.ecp` der Zeitstempelvariante.
fn evidence_object(
    core: &CheckpointCoreV1,
    signature: &[u8],
    fields: &Rfc3161EvidenceFieldsV1,
) -> Vec<u8> {
    let rebuilt = CheckpointCoreV1::new(core.fields().clone())
        .expect("the frozen checkpoint core is well formed");
    encode_evidence(
        &EvidenceObjectV1::timestamp(rebuilt, signature.to_vec(), fields.clone())
            .expect("the frozen timestamp object is well formed"),
    )
    .expect("encoding the frozen timestamp cannot fail")
    .into_vec()
}

/// Das Manifest der Vektorfamilie `evidence/v1`.
///
/// Vollstaendig deterministisch: Ed25519 signiert deterministisch, das
/// Vorlagentoken ist eingefroren, und keine Kapselung zieht Entropie.
///
/// # Panics
///
/// Wenn eine der Konstruktionen fehlschlaegt.
#[must_use]
pub fn evidence_v1_manifest() -> VectorManifest {
    let built = evidence_objects();
    let entries = vec![
        evidence_entry(
            "imprint/accepted-checkpoint-signature",
            EVIDENCE_IMPRINT_SCHEMA_ID,
            built.signature.to_vec(),
            BTreeMap::new(),
            built.imprint.to_vec(),
            ExpectedOutcome::Accepted,
            None,
        ),
        evidence_entry(
            "renewal/accepted-bound-token",
            EVIDENCE_SCHEMA_ID,
            built.renewal_core.clone(),
            digest_map(&[
                ("cttImprint", built.renewal_imprint),
                ("objectHash", *object_hash(&built.renewal).as_bytes()),
                ("renewalInputDigest", built.renewal_input_digest),
            ]),
            built.renewal,
            ExpectedOutcome::Accepted,
            None,
        ),
        evidence_entry(
            "timestamp/accepted-bound-token",
            EVIDENCE_SCHEMA_ID,
            built.core.clone(),
            digest_map(&[
                ("cttImprint", built.imprint),
                ("objectHash", *object_hash(&built.bound).as_bytes()),
            ]),
            built.bound,
            ExpectedOutcome::Accepted,
            None,
        ),
        evidence_entry(
            "timestamp/accepted-mismatched-imprint",
            EVIDENCE_SCHEMA_ID,
            built.core.clone(),
            digest_map(&[
                ("cttImprint", built.imprint),
                (
                    "objectHash",
                    *object_hash(&built.mismatched_imprint).as_bytes(),
                ),
            ]),
            built.mismatched_imprint,
            ExpectedOutcome::Accepted,
            Some(EVIDENCE_TOKEN_INTERNAL_NOTE),
        ),
        evidence_entry(
            "timestamp/accepted-wrong-request-nonce",
            EVIDENCE_SCHEMA_ID,
            built.core.clone(),
            digest_map(&[
                ("cttImprint", built.imprint),
                ("objectHash", *object_hash(&built.wrong_nonce).as_bytes()),
            ]),
            built.wrong_nonce,
            ExpectedOutcome::Accepted,
            Some(EVIDENCE_NONCE_NOTE),
        ),
        evidence_entry(
            "timestamp/accepted-wrong-tsa-policy",
            EVIDENCE_SCHEMA_ID,
            built.core.clone(),
            digest_map(&[
                ("cttImprint", built.imprint),
                ("objectHash", *object_hash(&built.wrong_policy).as_bytes()),
            ]),
            built.wrong_policy,
            ExpectedOutcome::Accepted,
            Some(EVIDENCE_TOKEN_INTERNAL_NOTE),
        ),
        evidence_entry(
            "timestamp/rejected-removed-ctt-header",
            EVIDENCE_SCHEMA_ID,
            built.core.clone(),
            digest_map(&[("objectHash", *object_hash(&built.removed_ctt).as_bytes())]),
            built.removed_ctt,
            ExpectedOutcome::Rejected {
                error_code: "EA-FORMAT-COSE".to_owned(),
            },
            None,
        ),
        evidence_entry(
            "timestamp/rejected-replaced-ctt-header",
            EVIDENCE_SCHEMA_ID,
            built.core,
            digest_map(&[
                ("cttImprint", built.imprint),
                ("objectHash", *object_hash(&built.replaced_ctt).as_bytes()),
            ]),
            built.replaced_ctt,
            ExpectedOutcome::Rejected {
                error_code: "EA-VERIFY-EVIDENCE-TOKEN-NOT-BOUND".to_owned(),
            },
            Some(EVIDENCE_REPLACED_NOTE),
        ),
    ];

    VectorManifest {
        family: EVIDENCE_FAMILY.to_owned(),
        version: EVIDENCE_V1_VERSION.to_owned(),
        entries,
    }
}

/// Ein Eintrag der Evidence-Familie.
fn evidence_entry(
    name: &str,
    schema_id: &str,
    input_bytes: Vec<u8>,
    intermediate_digests: BTreeMap<String, [u8; 32]>,
    object_bytes: Vec<u8>,
    expected_outcome: ExpectedOutcome,
    scope_note: Option<&str>,
) -> VectorEntry {
    VectorEntry {
        name: name.to_owned(),
        schema_id: schema_id.to_owned(),
        suite_id: EVIDENCE_SUITE_ID.to_owned(),
        source: VectorSource::GeneratorCommit(EVIDENCE_GENERATOR.to_owned()),
        input_bytes,
        intermediate_digests,
        object_bytes,
        expected_outcome,
        file: format!("{name}.bin"),
        scope_note: scope_note.map(ToOwned::to_owned),
    }
}

// ---------------------------------------------------------------------------
// Das Eigenschaftskorpus `properties/v1`
// ---------------------------------------------------------------------------

// Dieses Korpus ist die EINZIGE Eingabequelle der Eigenschaftstests in
// `tests/ea-system-tests/tests/conformance_properties.rs`. Es tritt bewusst an
// die Stelle eines Property-Frameworks: der Workspace fuehrt keines, und es
// kommt keines dazu.
//
// # Es liegt NICHT auf der Platte
//
// Anders als `crypto/suite-1`, `format/v1`, `trust/v1`, `grants/v1`,
// `receipts/v1` und `evidence/v1` schreibt diese Familie keine Dateien. Ihr
// Manifest ist eine Zeichenkette ([`PropertyCorpus::manifest_json`]), und
// eingefroren ist deren SHA-256 ([`PROPERTY_CORPUS_MANIFEST_SHA256`]).
// [`verify_manifest_at`] ist auf sie NICHT anwendbar — es gibt keine Wurzel,
// gegen die es pruefen koennte. Der Grund ist der Zweck: eingefroren werden
// muss hier die REPRODUZIERBARKEIT eines Fehlschlags, und dafuer genuegen Seed,
// Umfang und ein Digest ueber das Ganze. Zweihundert Objektdateien ins
// Repository zu legen, die kein Standard und kein alter Leser je liest, waere
// Ballast ohne Aussage.
//
// # Warum SHA-256 im Zaehlermodus und kein PRNG-Crate
//
// [`PropertyRng`] baut aus einem Baustein, der ohnehin im Graphen steht. Ein
// zusaetzliches PRNG-Crate waere eine neue externe Abhaengigkeit; ein
// handgeschriebener LCG waere neuer, ungeprueft und ohne jeden Gewinn. Die
// Folge ist bewusst: dieser Strom ist kein kryptografischer Zufall und will
// keiner sein. Er erzeugt Testeingaben, nichts weiter.
//
// # Kein `hpke_seal`
//
// Der `.eag`-Vektor dieses Korpus traegt dieselben EINMAL erzeugten Bytes wie
// die Familie `format/v1`: [`HPKE_ENCAPSULATED_KEY`] und
// [`HPKE_WRAPPED_CEK`] sind hier FUELLUNG vorgeschriebener Laenge und NICHT an
// den Grant-Kontext des jeweiligen Objekts gebunden. Das Korpus belegt die
// Kodierung eines Grants, nicht seine Entkapselung; letztere belegt
// `crypto/suite-1` ueber `hpke_open`.

/// Der Familienname des Eigenschaftskorpus.
pub const PROPERTY_FAMILY: &str = "properties";

/// Der Versionsname des Eigenschaftskorpus.
pub const PROPERTY_V1_VERSION: &str = "v1";

/// Die Herkunftsangabe des Eigenschaftskorpus.
const PROPERTY_GENERATOR: &str = "ea-testkit::property_corpus";

/// Die Domaenentrennung des Korpus-PRNG.
///
/// BEWUSST OHNE das Praefix `EINSATZARCHIV-`: der Domaenenscanner in
/// `tests/ea-system-tests/tests/conformance_golden_vectors.rs` zaehlt genau
/// diese Zeichenketten in `crates/ea-crypto` und verlangt fuer jede einen
/// eingefrorenen Vektor. Eine Testentropie-Domaene ist keine Hashdomaene des
/// Protokolls und hat in jener Zaehlung nichts verloren.
const PROPERTY_RNG_DOMAIN: &[u8] = b"ea-testkit/property-corpus/v1";

/// Der Seed des Eigenschaftskorpus, EINGEFROREN.
///
/// Ein Fehlschlag der Eigenschaftstests ist aus dieser Zahl allein
/// wiederherstellbar. Genau das leistet ein zufaellig geseedetes
/// Property-Framework nicht.
pub const PROPERTY_CORPUS_SEED: u64 = 0x4541_3100_5052_4f50;

/// Die Zahl der zufaelligen Feldbelegungen.
pub const PROPERTY_CORPUS_ASSIGNMENT_COUNT: usize = 8;

/// Die Zahl der Korpusobjekte: sechs Familien je Belegung.
pub const PROPERTY_CORPUS_CASE_COUNT: usize = PROPERTY_CORPUS_ASSIGNMENT_COUNT * 6;

/// Die Laenge der verketteten `.eip`-Folge.
pub const PROPERTY_CORPUS_CHAIN_LENGTH: usize = 6;

/// Die Zahl der Einfeld-Differenzpaare.
///
/// Zahlengleich mit den variierten Feldern von [`PropertyAssignmentV1`]; der
/// Selbsttest dieser Crate stellt beides gegeneinander.
pub const PROPERTY_CORPUS_FIELD_DELTA_COUNT: usize = 12;

/// Die Zahl der Mutationen je Objekt.
pub const PROPERTY_CORPUS_MUTATIONS_PER_OBJECT: usize = 4;

/// Die Gesamtzahl der Mutationen.
pub const PROPERTY_CORPUS_MUTATION_COUNT: usize = (PROPERTY_CORPUS_CASE_COUNT
    + PROPERTY_CORPUS_CHAIN_LENGTH)
    * PROPERTY_CORPUS_MUTATIONS_PER_OBJECT;

/// Die Zahl der Cross-Version-Faelle: drei je Objektfamilie.
pub const PROPERTY_CORPUS_CROSS_VERSION_COUNT: usize = 18;

/// SHA-256 ueber [`PropertyCorpus::manifest_json`], EINGEFROREN.
///
/// Aendert sich der Erzeuger, aendert sich dieser Wert. Er ist deshalb kein
/// Selbstabgleich, sondern die Stelle, an der eine Aenderung am Korpus BEWUSST
/// eingetragen werden muss.
pub const PROPERTY_CORPUS_MANIFEST_SHA256: &str =
    "6fa88c30548bf3a916ed55634a9370bbdb28323864253154b0a4f60f97a612fa";

/// Reproduzierbarer Testentropiestrom: SHA-256 im Zaehlermodus.
///
/// KEIN kryptografischer Zufall. Der Strom haengt ausschliesslich an Seed und
/// Zaehler und ist damit auf jeder Plattform und in jedem Lauf derselbe.
#[derive(Clone, Debug)]
pub struct PropertyRng {
    seed: u64,
    counter: u64,
    block: [u8; 32],
    used: usize,
}

impl PropertyRng {
    /// Ein Strom fuer diesen Seed.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            seed,
            counter: 0,
            block: [0; 32],
            // Erzwingt das erste Nachfuellen vor der ersten Ausgabe.
            used: 32,
        }
    }

    fn refill(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(PROPERTY_RNG_DOMAIN);
        hasher.update(self.seed.to_be_bytes());
        hasher.update(self.counter.to_be_bytes());
        self.counter = self.counter.wrapping_add(1);
        self.block = hasher.finalize().into();
        self.used = 0;
    }

    /// Fuellt `out` aus dem Strom.
    pub fn fill(&mut self, out: &mut [u8]) {
        for byte in out.iter_mut() {
            if self.used == self.block.len() {
                self.refill();
            }
            *byte = self.block[self.used];
            self.used += 1;
        }
    }

    /// `length` Bytes aus dem Strom.
    #[must_use]
    pub fn bytes(&mut self, length: usize) -> Vec<u8> {
        let mut out = vec![0_u8; length];
        self.fill(&mut out);
        out
    }

    /// Ein Feld fester Groesse aus dem Strom.
    #[must_use]
    pub fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0_u8; N];
        self.fill(&mut out);
        out
    }

    /// Eine 64-Bit-Zahl aus dem Strom.
    #[must_use]
    pub fn next_u64(&mut self) -> u64 {
        u64::from_be_bytes(self.array::<8>())
    }

    /// Eine Zahl echt unterhalb von `bound`.
    ///
    /// # Panics
    ///
    /// Wenn `bound` null ist.
    #[must_use]
    pub fn below(&mut self, bound: usize) -> usize {
        assert!(bound > 0, "the bound of a corpus index must be positive");
        let drawn = self.next_u64();
        usize::try_from(drawn % bound as u64).expect("a value below a usize bound fits a usize")
    }
}

/// Die variierten Felder einer Belegung.
///
/// Der Zuschnitt folgt `manifest-core-v1`: das `.eip` traegt den breitesten
/// Feldsatz aller sechs Familien, und nur dort ist Injektivitaet feldweise
/// messbar. Die uebrigen fuenf Familien uebernehmen die Teilmenge, die sie
/// selbst fuehren.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PropertyAssignmentV1 {
    /// Organisationskennung.
    pub organization_id: [u8; 16],
    /// Kettenkennung.
    pub chain_id: [u8; 16],
    /// Position in der Kette.
    pub chain_sequence: u64,
    /// Vorgaengerbindung. Genau bei Sequenz 0 `None`.
    pub previous_entry_hash: Option<[u8; 32]>,
    /// Zertifikat des schreibenden Geraets.
    pub writer_certificate_hash: [u8; 32],
    /// Uebergangsereignis, falls der Schreiber gewechselt hat.
    pub writer_transition_event_hash: Option<[u8; 32]>,
    /// Registrierungsversion.
    pub registry_version: u64,
    /// Registrierungskopf-Hash.
    pub registry_head_hash: [u8; 32],
    /// Hash des initialen Grant-Plans.
    pub initial_grant_plan_hash: [u8; 32],
    /// AEAD-Nonce.
    pub nonce: [u8; 12],
    /// Inhaltsschluessel.
    pub content_encryption_key: [u8; 32],
    /// Klartext des Nutzinhalts.
    pub plaintext: Vec<u8>,
}

/// Die Namen der zwoelf variierten Felder, in der Reihenfolge der
/// Differenzpaare.
pub const PROPERTY_VARIED_FIELDS: [&str; PROPERTY_CORPUS_FIELD_DELTA_COUNT] = [
    "organizationId",
    "chainId",
    "chainSequence",
    "previousEntryHash",
    "writerCertificateHash",
    "writerTransitionEventHash",
    "registryVersion",
    "registryHeadHash",
    "initialGrantPlanHash",
    "nonce",
    "contentEncryptionKey",
    "plaintext",
];

/// Ein Objekt des Korpus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PropertyCase {
    /// Eindeutiger Name, etwa `assignment-3/eip`.
    pub name: String,
    /// Objektfamilie: `eip`, `eag`, `esr`, `ecp`, `etb` oder `eds`.
    pub family: &'static str,
    /// Schema-Identifikator, etwa `eip-v1`.
    pub schema_id: &'static str,
    /// Objekttyp-Tag 1 bis 6.
    pub object_type: u8,
    /// Exakte Objektbytes.
    pub bytes: Vec<u8>,
}

/// Ein Knoten der verketteten `.eip`-Folge, als reine Werte.
///
/// `ea-testkit` haengt bewusst NICHT von `ea-chain` ab: das Korpus liefert
/// Fakten, die Kettenaussage trifft der Test.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PropertyChainNodeV1 {
    /// Kettenkennung, ueber die ganze Folge gleich.
    pub chain_id: [u8; 16],
    /// Position in der Kette. Genesis ist 0.
    pub chain_sequence: u64,
    /// Vorgaengerbindung. Genau bei Sequenz 0 `None`.
    pub previous_entry_hash: Option<[u8; 32]>,
    /// Eintragshash dieses Knotens.
    pub entry_hash: [u8; 32],
    /// Objekthash des `.eip`.
    pub object_hash: [u8; 32],
    /// Zertifikat des schreibenden Geraets.
    pub writer_certificate_hash: [u8; 32],
    /// Exakte Objektbytes des `.eip`.
    pub bytes: Vec<u8>,
}

/// Zwei `.eip`-Objekte, deren Belegungen sich in GENAU einem Feld
/// unterscheiden.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PropertyFieldDeltaV1 {
    /// Das eine Feld, das sich unterscheidet.
    pub field: &'static str,
    /// Die Bytes unter der Grundbelegung.
    pub base_bytes: Vec<u8>,
    /// Die Bytes unter der geaenderten Belegung.
    pub changed_bytes: Vec<u8>,
}

/// Ein mutierter Eingabebytestring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PropertyMutationV1 {
    /// Eindeutiger Name, etwa `assignment-3/eip/flip`.
    pub name: String,
    /// Die mutierten Bytes.
    pub bytes: Vec<u8>,
}

/// Ein Objekt, dessen Kopf eine unbekannte Version, eine kritische Erweiterung
/// oder ein fremdes Objekttyp-Tag ankuendigt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PropertyCrossVersionCaseV1 {
    /// Eindeutiger Name, etwa `eip/object-version-2`.
    pub name: String,
    /// Die Bytes.
    pub bytes: Vec<u8>,
    /// Der Fehlercode, mit dem ein v1-Leser sie ablehnen MUSS.
    pub expected_error_code: &'static str,
}

/// Das vollstaendige Eingabekorpus der Eigenschaftstests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PropertyCorpus {
    /// Der Seed, aus dem alles Folgende entstanden ist.
    pub seed: u64,
    /// Die Objekte: sechs Familien je Belegung.
    pub cases: Vec<PropertyCase>,
    /// Die verkettete `.eip`-Folge.
    pub chain: Vec<PropertyChainNodeV1>,
    /// Die Einfeld-Differenzpaare der Familie `.eip`.
    pub field_deltas: Vec<PropertyFieldDeltaV1>,
    /// Die mutierten Eingaben.
    pub mutations: Vec<PropertyMutationV1>,
    /// Die Cross-Version-Faelle.
    pub cross_version: Vec<PropertyCrossVersionCaseV1>,
}

impl PropertyCorpus {
    /// Das Manifest des Korpus als deterministische JSON-Zeichenkette.
    ///
    /// Objektschluessel stehen alphabetisch, die Ausgabe endet auf genau einem
    /// Zeilenumbruch. Der Seed steht als Hexzeichenkette, damit kein
    /// JSON-Backend ihn ueber eine Gleitkommazahl fuehren kann.
    ///
    /// # Panics
    ///
    /// Wenn `serde_json` ein Objekt aus Zeichenketten und Zahlen nicht
    /// serialisieren kann. Das waere ein Fehler von `serde_json`, kein
    /// Laufzeitzustand.
    #[must_use]
    pub fn manifest_json(&self) -> String {
        let cases = self
            .cases
            .iter()
            .map(|case| {
                let mut map = BTreeMap::new();
                map.insert("family".into(), Value::String(case.family.to_owned()));
                map.insert("length".into(), Value::from(case.bytes.len()));
                map.insert("name".into(), Value::String(case.name.clone()));
                map.insert("objectType".into(), Value::from(case.object_type));
                map.insert("schemaId".into(), Value::String(case.schema_id.to_owned()));
                map.insert("sha256".into(), Value::String(sha256_hex(&case.bytes)));
                sorted_object(map)
            })
            .collect::<Vec<_>>();
        let chain = self
            .chain
            .iter()
            .map(|node| {
                let mut map = BTreeMap::new();
                map.insert(
                    "chainSequence".into(),
                    Value::String(node.chain_sequence.to_string()),
                );
                map.insert(
                    "entryHash".into(),
                    Value::String(hex::encode(node.entry_hash)),
                );
                map.insert(
                    "objectHash".into(),
                    Value::String(hex::encode(node.object_hash)),
                );
                map.insert(
                    "previousEntryHash".into(),
                    node.previous_entry_hash.map_or_else(
                        || Value::String(String::new()),
                        |hash| Value::String(hex::encode(hash)),
                    ),
                );
                map.insert("sha256".into(), Value::String(sha256_hex(&node.bytes)));
                sorted_object(map)
            })
            .collect::<Vec<_>>();
        let field_deltas = self
            .field_deltas
            .iter()
            .map(|delta| {
                let mut map = BTreeMap::new();
                map.insert(
                    "baseSha256".into(),
                    Value::String(sha256_hex(&delta.base_bytes)),
                );
                map.insert(
                    "changedSha256".into(),
                    Value::String(sha256_hex(&delta.changed_bytes)),
                );
                map.insert("field".into(), Value::String(delta.field.to_owned()));
                sorted_object(map)
            })
            .collect::<Vec<_>>();
        let mutations = self
            .mutations
            .iter()
            .map(|mutation| {
                let mut map = BTreeMap::new();
                map.insert("length".into(), Value::from(mutation.bytes.len()));
                map.insert("name".into(), Value::String(mutation.name.clone()));
                map.insert("sha256".into(), Value::String(sha256_hex(&mutation.bytes)));
                sorted_object(map)
            })
            .collect::<Vec<_>>();
        let cross_version = self
            .cross_version
            .iter()
            .map(|case| {
                let mut map = BTreeMap::new();
                map.insert(
                    "expectedErrorCode".into(),
                    Value::String(case.expected_error_code.to_owned()),
                );
                map.insert("name".into(), Value::String(case.name.clone()));
                map.insert("sha256".into(), Value::String(sha256_hex(&case.bytes)));
                sorted_object(map)
            })
            .collect::<Vec<_>>();

        let mut map = BTreeMap::new();
        map.insert("cases".into(), Value::Array(cases));
        map.insert("chain".into(), Value::Array(chain));
        map.insert("crossVersion".into(), Value::Array(cross_version));
        map.insert("family".into(), Value::String(PROPERTY_FAMILY.to_owned()));
        map.insert("fieldDeltas".into(), Value::Array(field_deltas));
        map.insert(
            "generator".into(),
            Value::String(PROPERTY_GENERATOR.to_owned()),
        );
        map.insert("mutations".into(), Value::Array(mutations));
        map.insert("seed".into(), Value::String(format!("{:#018x}", self.seed)));
        map.insert(
            "version".into(),
            Value::String(PROPERTY_V1_VERSION.to_owned()),
        );
        let mut text = serde_json::to_string_pretty(&sorted_object(map))
            .expect("a manifest of strings and numbers serializes");
        text.push('\n');
        text
    }
}

/// Das vollstaendige Eingabekorpus der Eigenschaftstests.
///
/// Deterministisch: zwei Aufrufe liefern dasselbe Korpus, auf jeder Plattform.
///
/// # Panics
///
/// Wenn eine der Objektkonstruktionen fehlschlaegt. Das waere ein
/// Programmierfehler dieser Crate, kein Laufzeitzustand.
#[must_use]
pub fn property_corpus() -> PropertyCorpus {
    let mut rng = PropertyRng::new(PROPERTY_CORPUS_SEED);

    let mut cases = Vec::with_capacity(PROPERTY_CORPUS_CASE_COUNT);
    for index in 0..PROPERTY_CORPUS_ASSIGNMENT_COUNT {
        let assignment = property_random_assignment(&mut rng);
        let built = property_objects(&assignment);
        for (position, (family, schema_id, object_type)) in FORMAT_FAMILIES.iter().enumerate() {
            cases.push(PropertyCase {
                name: format!("assignment-{index}/{family}"),
                family,
                schema_id,
                object_type: *object_type,
                bytes: built.objects[position].clone(),
            });
        }
    }

    let chain = property_chain(&mut rng);
    let field_deltas = property_field_deltas();
    let mutations = property_mutations(&mut rng, &cases, &chain);
    let cross_version = property_cross_version_cases(&cases);

    PropertyCorpus {
        seed: PROPERTY_CORPUS_SEED,
        cases,
        chain,
        field_deltas,
        mutations,
        cross_version,
    }
}

/// Eine Belegung, in der JEDES variierte Feld frisch gezogen ist.
fn property_random_assignment(rng: &mut PropertyRng) -> PropertyAssignmentV1 {
    PropertyAssignmentV1 {
        organization_id: rng.array(),
        chain_id: rng.array(),
        // Echt groesser null: die Vorgaengerbindung ist dann `Some`, und die
        // Belegung deckt den Regelfall statt des Sonderfalls Genesis ab.
        chain_sequence: (rng.next_u64() % 4096) + 1,
        previous_entry_hash: Some(rng.array()),
        writer_certificate_hash: rng.array(),
        writer_transition_event_hash: None,
        registry_version: (rng.next_u64() % 1024) + 1,
        registry_head_hash: rng.array(),
        initial_grant_plan_hash: rng.array(),
        nonce: rng.array(),
        content_encryption_key: rng.array(),
        plaintext: rng.bytes(PROPERTY_PLAINTEXT_BYTES),
    }
}

/// Die Klartextlaenge aller Korpusobjekte.
///
/// Fest, nicht gezogen: eine variable Laenge aenderte die Chiffratlaenge und
/// damit den Manifestkern, und das Differenzpaar `plaintext` belegte dann die
/// Laenge statt des Inhalts.
const PROPERTY_PLAINTEXT_BYTES: usize = 48;

/// Die Grundbelegung der Differenzpaare.
///
/// Fest verdrahtet und nicht aus dem Strom gezogen: ein Differenzpaar soll aus
/// dem Quelltext ablesbar sein, nicht aus einem Zaehlerstand.
fn property_base_assignment() -> PropertyAssignmentV1 {
    PropertyAssignmentV1 {
        organization_id: [0x40; 16],
        chain_id: [0x41; 16],
        chain_sequence: 7,
        previous_entry_hash: Some([0x42; 32]),
        writer_certificate_hash: [0x43; 32],
        writer_transition_event_hash: None,
        registry_version: 9,
        registry_head_hash: [0x44; 32],
        initial_grant_plan_hash: [0x45; 32],
        nonce: [0x46; 12],
        content_encryption_key: [0x47; 32],
        plaintext: [0x48; PROPERTY_PLAINTEXT_BYTES].to_vec(),
    }
}

/// Zwoelf Paare, die sich in genau einem Feld unterscheiden.
fn property_field_deltas() -> Vec<PropertyFieldDeltaV1> {
    let base = property_base_assignment();
    let base_bytes = property_objects(&base).objects[0].clone();

    PROPERTY_VARIED_FIELDS
        .iter()
        .map(|field| {
            let mut changed = base.clone();
            match *field {
                "organizationId" => changed.organization_id = [0x50; 16],
                "chainId" => changed.chain_id = [0x51; 16],
                "chainSequence" => changed.chain_sequence = 8,
                "previousEntryHash" => changed.previous_entry_hash = Some([0x52; 32]),
                "writerCertificateHash" => changed.writer_certificate_hash = [0x53; 32],
                "writerTransitionEventHash" => {
                    changed.writer_transition_event_hash = Some([0x54; 32]);
                }
                "registryVersion" => changed.registry_version = 10,
                "registryHeadHash" => changed.registry_head_hash = [0x55; 32],
                "initialGrantPlanHash" => changed.initial_grant_plan_hash = [0x56; 32],
                "nonce" => changed.nonce = [0x57; 12],
                "contentEncryptionKey" => changed.content_encryption_key = [0x58; 32],
                // Gleiche LAENGE, anderer Inhalt: sonst belegte das Paar die
                // Chiffratlaenge statt des Klartexts.
                "plaintext" => changed.plaintext = [0x59; PROPERTY_PLAINTEXT_BYTES].to_vec(),
                other => panic!("{other} is not one of the varied fields"),
            }
            PropertyFieldDeltaV1 {
                field,
                base_bytes: base_bytes.clone(),
                changed_bytes: property_objects(&changed).objects[0].clone(),
            }
        })
        .collect()
}

/// Eine verkettete `.eip`-Folge: Sequenz 0 bis
/// [`PROPERTY_CORPUS_CHAIN_LENGTH`] minus eins.
fn property_chain(rng: &mut PropertyRng) -> Vec<PropertyChainNodeV1> {
    let chain_id: [u8; 16] = rng.array();
    let organization_id: [u8; 16] = rng.array();
    let mut nodes = Vec::with_capacity(PROPERTY_CORPUS_CHAIN_LENGTH);
    let mut previous_entry_hash: Option<[u8; 32]> = None;

    for sequence in 0..PROPERTY_CORPUS_CHAIN_LENGTH {
        let assignment = PropertyAssignmentV1 {
            organization_id,
            chain_id,
            chain_sequence: sequence as u64,
            previous_entry_hash,
            writer_certificate_hash: rng.array(),
            writer_transition_event_hash: None,
            registry_version: (rng.next_u64() % 1024) + 1,
            registry_head_hash: rng.array(),
            initial_grant_plan_hash: rng.array(),
            nonce: rng.array(),
            content_encryption_key: rng.array(),
            plaintext: rng.bytes(PROPERTY_PLAINTEXT_BYTES),
        };
        let built = property_objects(&assignment);
        nodes.push(PropertyChainNodeV1 {
            chain_id,
            chain_sequence: assignment.chain_sequence,
            previous_entry_hash,
            entry_hash: built.entry_hash,
            object_hash: built.entry_object_hash,
            writer_certificate_hash: assignment.writer_certificate_hash,
            bytes: built.objects[0].clone(),
        });
        previous_entry_hash = Some(built.entry_hash);
    }
    nodes
}

/// Vier Mutationen je Objekt: Bitkippung, Kuerzung, Anhang, Nullung.
fn property_mutations(
    rng: &mut PropertyRng,
    cases: &[PropertyCase],
    chain: &[PropertyChainNodeV1],
) -> Vec<PropertyMutationV1> {
    let sources = cases
        .iter()
        .map(|case| (case.name.clone(), case.bytes.clone()))
        .chain(chain.iter().map(|node| {
            (
                format!("chain-{}/eip", node.chain_sequence),
                node.bytes.clone(),
            )
        }))
        .collect::<Vec<_>>();

    let mut mutations = Vec::with_capacity(PROPERTY_CORPUS_MUTATION_COUNT);
    for (name, bytes) in sources {
        let mut flipped = bytes.clone();
        let offset = rng.below(flipped.len());
        flipped[offset] ^= 1 << (rng.below(8));
        mutations.push(PropertyMutationV1 {
            name: format!("{name}/flip"),
            bytes: flipped,
        });

        let cut = rng.below(bytes.len());
        mutations.push(PropertyMutationV1 {
            name: format!("{name}/truncate"),
            bytes: bytes[..cut].to_vec(),
        });

        let mut extended = bytes.clone();
        extended.push(rng.array::<1>()[0]);
        mutations.push(PropertyMutationV1 {
            name: format!("{name}/extend"),
            bytes: extended,
        });

        let mut zeroed = bytes.clone();
        let offset = rng.below(zeroed.len());
        zeroed[offset] = 0;
        mutations.push(PropertyMutationV1 {
            name: format!("{name}/zero"),
            bytes: zeroed,
        });
    }
    mutations
}

/// Drei Kopfmutationen je Familie, jede mit dem Code, der sie ablehnt.
///
/// Die Bytepositionen stammen aus `crates/ea-format/src/parser.rs`: Byte 6
/// traegt das Objekttyp-Tag, Byte 7 die Objektversion, Byte 8 die leere
/// Erweiterungsliste.
fn property_cross_version_cases(cases: &[PropertyCase]) -> Vec<PropertyCrossVersionCaseV1> {
    let mut built = Vec::with_capacity(PROPERTY_CORPUS_CROSS_VERSION_COUNT);
    for (family, _, object_type) in FORMAT_FAMILIES {
        let origin = cases
            .iter()
            .find(|case| case.family == family)
            .unwrap_or_else(|| panic!("the corpus holds a {family} object"));
        assert_eq!(origin.bytes[6], object_type);

        let mut future_version = origin.bytes.clone();
        future_version[7] = 2;
        built.push(PropertyCrossVersionCaseV1 {
            name: format!("{family}/object-version-2"),
            bytes: future_version,
            expected_error_code: "EA-FORMAT-UNKNOWN-VERSION",
        });

        let mut critical = origin.bytes.clone();
        critical[8] = 0x81;
        built.push(PropertyCrossVersionCaseV1 {
            name: format!("{family}/critical-extension"),
            bytes: critical,
            expected_error_code: "EA-FORMAT-CRITICAL-EXTENSION",
        });

        let mut unknown_tag = origin.bytes.clone();
        unknown_tag[6] = 7;
        built.push(PropertyCrossVersionCaseV1 {
            name: format!("{family}/unknown-object-type"),
            bytes: unknown_tag,
            expected_error_code: "EA-FORMAT-PREFIX",
        });
    }
    built
}

/// Die sechs Objekte einer Belegung und die Kettenfakten des `.eip`.
struct PropertyBuilt {
    objects: [Vec<u8>; 6],
    entry_hash: [u8; 32],
    entry_object_hash: [u8; 32],
}

/// Ein aus Domaene und Feld abgeleiteter 32-Byte-Wert.
///
/// Die Begleithashes eines Objekts — Empfaenger, Richtlinie, Vernichtung —
/// sind nicht selbst variierte Felder, muessen aber mit der Belegung wandern,
/// damit zwei Belegungen nie dasselbe `.esr` oder `.eds` erzeugen.
fn property_derived(domain: &str, seed: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PROPERTY_RNG_DOMAIN);
    hasher.update(domain.as_bytes());
    hasher.update(seed);
    hasher.finalize().into()
}

/// Die sechs Objekte zu einer Belegung.
///
/// Gebaut mit denselben oeffentlichen Konstruktoren wie [`format_objects`] —
/// ein zweiter Kodierer waere eine zweite Quelle der Wahrheit.
fn property_objects(assignment: &PropertyAssignmentV1) -> PropertyBuilt {
    let writer = format_signer(TEST_ENTROPY_DEVICE_ED25519_SEED);
    let writer_thumbprint = format_public_key(TEST_ENTROPY_DEVICE_ED25519_SEED).thumbprint();
    let server = format_signer(TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED);
    let server_thumbprint =
        format_public_key(TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED).thumbprint();
    let root = format_signer(TEST_ENTROPY_ROOT_ED25519_SEED);
    let root_key = format_public_key(TEST_ENTROPY_ROOT_ED25519_SEED);

    let organization_id =
        OrganizationId::try_from(assignment.organization_id.as_slice()).expect("16 bytes");
    let chain_id = ChainId::try_from(assignment.chain_id.as_slice()).expect("16 bytes");
    let chain_sequence = ChainSequence::new(assignment.chain_sequence);
    let previous_entry_hash = assignment
        .previous_entry_hash
        .map(|hash| EntryHash::try_from(hash.as_slice()).expect("32 bytes"));
    let writer_certificate_hash =
        CertificateHash::try_from(assignment.writer_certificate_hash.as_slice()).expect("32 bytes");
    let registry_version = RegistryVersion::new(assignment.registry_version);
    let registry_head_hash =
        Hash32::try_from(assignment.registry_head_hash.as_slice()).expect("32 bytes");
    let server_certificate_hash = CertificateHash::try_from(
        property_derived("server-certificate", &assignment.chain_id).as_slice(),
    )
    .expect("32 bytes");
    let device_time = UnixMillis::new(
        FORMAT_DEVICE_TIME_MS + i64::try_from(assignment.registry_version).expect("in range"),
    );
    let server_time = UnixMillis::new(
        FORMAT_SERVER_TIME_MS + i64::try_from(assignment.registry_version).expect("in range"),
    );

    // `.eip`. Die AAD haengt am Manifestkern, der Manifestkern nur an der
    // LAENGE des Chiffrats — deshalb der Vorlauf mit einem gleich langen
    // Platzhalter, genau wie in [`format_objects`].
    let ciphertext_length = assignment.plaintext.len() + ea_crypto::AEAD_OVERHEAD;
    let probe = ManifestCoreV1::new(
        property_manifest_fields(assignment),
        &vec![0_u8; ciphertext_length],
    )
    .expect("the probe manifest core is well formed");
    let aad = payload_aad(probe.exact_bytes());
    let ciphertext = aead_seal(
        &SecretBytes::new(assignment.content_encryption_key),
        &SecretBytes::new(assignment.nonce),
        SecretVec::new(assignment.plaintext.clone()),
        &aad,
    )
    .expect("sealing a corpus plaintext cannot fail");
    let manifest = ManifestCoreV1::new(property_manifest_fields(assignment), &ciphertext)
        .expect("the corpus manifest core is well formed");
    let signed =
        SignedManifestV1::new(manifest, &ciphertext).expect("the manifest matches its ciphertext");
    let writer_signature = writer
        .sign_record(signed.exact_bytes())
        .expect("signing a corpus signed manifest cannot fail");
    let entry = EntryPackageV1::new(signed.clone(), ciphertext, writer_signature.clone())
        .expect("the corpus entry package is well formed");
    let entry_hash = entry.entry_hash();
    let eip = encode_entry_package(&entry)
        .expect("encoding a corpus entry package cannot fail")
        .into_vec();
    let eip_object_hash = object_hash(&eip);

    // `.eag`. Kapselungswert und umschlossener CEK sind die EINMAL erzeugten
    // Bytes; siehe den Abschnittskopf.
    let grant_body = GrantBodyV1::new(GrantBodyFieldsV1 {
        organization_id,
        chain_id,
        entry_hash,
        kind: GrantKindV1::Initial,
        purpose: GrantPurposeV1::Reader,
        recipient_key_thumbprint: KeyThumbprint::try_from(
            property_derived("recipient-key", &assignment.chain_id).as_slice(),
        )
        .expect("32 bytes"),
        recipient_certificate_hash: CertificateHash::try_from(
            property_derived("recipient-certificate", &assignment.chain_id).as_slice(),
        )
        .expect("32 bytes"),
        issuer_key_thumbprint: writer_thumbprint,
        issuer_certificate_hash: writer_certificate_hash,
        registry_version,
        registry_head_hash,
        created_at_device: device_time,
        original_recovery_grant_object_hash: None,
        grant_authorization_object_hash: None,
        encapsulated_key: decode(HPKE_ENCAPSULATED_KEY)
            .try_into()
            .expect("the frozen encapsulated key is 32 bytes"),
        wrapped_cek: decode(HPKE_WRAPPED_CEK)
            .try_into()
            .expect("the frozen wrapped CEK is 48 bytes"),
    })
    .expect("the corpus grant body is well formed");
    let grant_signature = writer
        .sign_initial_grant(grant_body.exact_bytes())
        .expect("signing a corpus grant body cannot fail");
    let grant = GrantV1::new(grant_body, grant_signature).expect("the corpus grant is well formed");
    let eag = encode_grant(&grant)
        .expect("encoding a corpus grant cannot fail")
        .into_vec();

    // `.esr`.
    let receipt_core = ReceiptCoreV1::new(ReceiptCoreFieldsV1 {
        organization_id,
        chain_id,
        chain_sequence,
        entry_hash,
        entry_object_hash: eip_object_hash,
        previous_entry_hash,
        registry_version,
        registry_head_hash,
        policy_object_hash: ObjectHash::try_from(
            property_derived("policy", &assignment.chain_id).as_slice(),
        )
        .expect("32 bytes"),
        initial_grant_plan_hash: Hash32::try_from(assignment.initial_grant_plan_hash.as_slice())
            .expect("32 bytes"),
        initial_grant_object_hashes: vec![object_hash(&eag)],
        accepted_at_server: server_time,
        evidence_due_at: None,
        server_key_thumbprint: server_thumbprint,
        server_certificate_hash,
    })
    .expect("the corpus receipt core is well formed");
    let receipt_signature = server
        .sign_receipt(receipt_core.exact_bytes())
        .expect("signing a corpus receipt core cannot fail");
    let receipt =
        ReceiptV1::new(receipt_core, receipt_signature).expect("the corpus receipt is well formed");
    let esr = encode_receipt(&receipt)
        .expect("encoding a corpus receipt cannot fail")
        .into_vec();

    // `.ecp`.
    let checkpoint_core = CheckpointCoreV1::new(CheckpointCoreFieldsV1 {
        organization_id,
        chain_id,
        covered_from_sequence: chain_sequence,
        covered_through_sequence: chain_sequence,
        head_entry_hash: entry_hash,
        registry_head_hash,
        issued_at_server: server_time,
        previous_evidence_hash: None,
    })
    .expect("the corpus checkpoint core is well formed");
    let checkpoint_signature = server
        .sign_checkpoint(server_certificate_hash, checkpoint_core.exact_bytes())
        .expect("signing a corpus checkpoint core cannot fail");
    let evidence = EvidenceObjectV1::standard(checkpoint_core, checkpoint_signature)
        .expect("the corpus checkpoint object is well formed");
    let ecp = encode_evidence(&evidence)
        .expect("encoding a corpus checkpoint cannot fail")
        .into_vec();

    // `.etb`.
    let trust_payload = TrustPayloadV1::initial_root_certificate(RootCertificateFieldsV1 {
        organization_id,
        root_public_cose_key: root_key.to_deterministic_cbor(),
        root_key_thumbprint: root_key.thumbprint(),
        previous_root_certificate_object_hash: None,
        effective_from_registry_version: registry_version,
    })
    .expect("the corpus root certificate payload is well formed");
    let etb_trust_digest = trust_digest(trust_payload.exact_digest_input())
        .as_bytes()
        .to_vec();
    let trust_signature = root
        .sign_initial_root(&etb_trust_digest)
        .expect("signing a corpus trust digest cannot fail");
    let trust = TrustObjectV1::new(trust_payload, vec![trust_signature])
        .expect("the corpus trust object is well formed");
    let etb = encode_trust(&trust)
        .expect("encoding a corpus trust object cannot fail")
        .into_vec();

    // `.eds`. Derselbe signierte Manifestkern wie im `.eip`, ohne Chiffrat.
    let stub = DestroyedEntryStubV1::new(
        signed,
        writer_signature,
        eip_object_hash,
        DestructionId::try_from(
            property_derived("destruction", &assignment.chain_id)[..16].as_ref(),
        )
        .expect("16 bytes"),
        ObjectHash::try_from(
            property_derived("destruction-authorization", &assignment.chain_id).as_slice(),
        )
        .expect("32 bytes"),
    )
    .expect("the corpus destroyed entry stub is well formed");
    let eds = encode_destroyed_entry_stub(&stub)
        .expect("encoding a corpus stub cannot fail")
        .into_vec();

    PropertyBuilt {
        objects: [eip, eag, esr, ecp, etb, eds],
        entry_hash: *entry_hash.as_bytes(),
        entry_object_hash: *eip_object_hash.as_bytes(),
    }
}

/// Die Manifestkernfelder einer Belegung.
fn property_manifest_fields(assignment: &PropertyAssignmentV1) -> ManifestCoreFieldsV1 {
    ManifestCoreFieldsV1 {
        organization_id: OrganizationId::try_from(assignment.organization_id.as_slice())
            .expect("16 bytes"),
        chain_id: ChainId::try_from(assignment.chain_id.as_slice()).expect("16 bytes"),
        chain_sequence: ChainSequence::new(assignment.chain_sequence),
        previous_entry_hash: assignment
            .previous_entry_hash
            .map(|hash| EntryHash::try_from(hash.as_slice()).expect("32 bytes")),
        writer_certificate_hash: CertificateHash::try_from(
            assignment.writer_certificate_hash.as_slice(),
        )
        .expect("32 bytes"),
        writer_transition_event_hash: assignment
            .writer_transition_event_hash
            .map(|hash| ObjectHash::try_from(hash.as_slice()).expect("32 bytes")),
        registry_version: RegistryVersion::new(assignment.registry_version),
        registry_head_hash: assignment.registry_head_hash,
        initial_grant_plan_hash: assignment.initial_grant_plan_hash,
        nonce: assignment.nonce,
    }
}

// ---------------------------------------------------------------------------
// Fehler und Helfer
// ---------------------------------------------------------------------------

/// Fehler der Manifest-Emission und -Pruefung.
#[derive(Debug)]
pub enum TestkitError {
    /// Ein Dateizugriff schlug fehl.
    Io {
        /// Betroffener Pfad.
        path: String,
        /// Zugrunde liegender Fehler.
        source: std::io::Error,
    },
    /// Das Manifest ist nicht wohlgeformt.
    Malformed(String),
    /// Ein Dateipfad ist absolut oder verliesse die Manifestwurzel.
    UnsafePath(String),
    /// Ein Eintragsname oder ein Dateipfad kommt doppelt vor.
    DuplicateEntry(String),
}

impl TestkitError {
    /// Stabiler Fehlercode, gegen den Tests assertieren duerfen.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Io { .. } => "io",
            Self::Malformed(_) => "malformed_manifest",
            Self::UnsafePath(_) => "unsafe_path",
            Self::DuplicateEntry(_) => "duplicate_entry",
        }
    }
}

impl fmt::Display for TestkitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(formatter, "cannot access {path}: {source}"),
            Self::Malformed(detail) => write!(formatter, "malformed manifest: {detail}"),
            Self::UnsafePath(path) => write!(
                formatter,
                "{path} is not a relative path below the manifest root"
            ),
            Self::DuplicateEntry(name) => write!(formatter, "{name} occurs more than once"),
        }
    }
}

impl std::error::Error for TestkitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Baut ein JSON-Objekt mit alphabetisch sortierten Schluesseln.
///
/// `serde_json::Map` ist nur OHNE das Feature `preserve_order` eine `BTreeMap`;
/// mit dem Feature behaelt es die EINFUEGEreihenfolge. Die Manifestbytes werden
/// dauerhaft eingefroren und duerfen nicht davon abhaengen, ob irgendjemand im
/// Abhaengigkeitsgraphen dieses Feature einschaltet. Die Sortierung entsteht
/// deshalb hier und nicht im Backend.
fn sorted_object(fields: BTreeMap<String, Value>) -> Value {
    Value::Object(fields.into_iter().collect())
}

fn string_field(value: &Value, field: &str) -> Result<String, TestkitError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| TestkitError::Malformed(format!("{field} must be a string")))
}

fn decode_hex(text: &str) -> Result<Vec<u8>, TestkitError> {
    hex::decode(text)
        .map_err(|error| TestkitError::Malformed(format!("{text} is not lowercase hex: {error}")))
}

fn check_relative_path(file: &str) -> Result<(), TestkitError> {
    let path = PathBuf::from(file);
    let unsafe_component = path.components().any(|component| {
        !matches!(component, Component::Normal(_)) || component.as_os_str().is_empty()
    });
    if file.is_empty() || unsafe_component {
        return Err(TestkitError::UnsafePath(file.to_owned()));
    }
    Ok(())
}

fn create_dir(path: &Path) -> Result<(), TestkitError> {
    fs::create_dir_all(path).map_err(|error| TestkitError::Io {
        path: path.display().to_string(),
        source: error,
    })
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), TestkitError> {
    fs::write(path, bytes).map_err(|error| TestkitError::Io {
        path: path.display().to_string(),
        source: error,
    })
}

// ---------------------------------------------------------------------------
// Vektorfamilie local-audit/v1
// ---------------------------------------------------------------------------

/// Der Familienname der lokalen Auditvektoren.
pub const LOCAL_AUDIT_FAMILY: &str = "local-audit";

/// Der Versionsordner der lokalen Auditvektoren.
pub const LOCAL_AUDIT_V1_VERSION: &str = "v1";

/// Die Wurzel der lokalen Auditvektoren, relativ zur Arbeitsbaumwurzel.
pub const LOCAL_AUDIT_V1_ROOT: &str = "vectors/local-audit/v1";

/// Die Herkunftsangabe der lokalen Auditvektoren.
const LOCAL_AUDIT_GENERATOR: &str = "ea-testkit::local_audit_v1_manifest";

/// Der Suite-Identifikator der lokalen Auditvektoren, EINGEFROREN.
const LOCAL_AUDIT_SUITE_ID: &str = "EINSATZARCHIV-SUITE-1";

/// Der Schema-Identifikator eines signierten Auditereignisses.
const LOCAL_AUDIT_SCHEMA_ID: &str = "local-audit-event-v1";

/// Die Organisationskennung aller lokalen Auditvektoren.
const LOCAL_AUDIT_ORGANIZATION_ID: [u8; 16] = [0x30; 16];

/// Die Geraetekennung aller lokalen Auditvektoren.
const LOCAL_AUDIT_DEVICE_ID: [u8; 16] = [0x31; 16];

/// Der Objekthash der Bedienerbindung, wo sie steht.
const LOCAL_AUDIT_BINDING_OBJECT_HASH: [u8; 32] = [0x32; 32];

/// Der Objekthash des Signaturzertifikats. `CoseSigner::sign_local_audit`
/// entnimmt ihn dem Kern selbst, es braucht also kein Zertifikatsobjekt.
const LOCAL_AUDIT_SIGNER_CERTIFICATE_OBJECT_HASH: [u8; 32] = [0x33; 32];

/// Die Wirkzeit aller lokalen Auditvektoren in Millisekunden seit der Epoche.
///
/// EINE Zeit fuer alle zwoelf: `effective-now` ist die einzige Position
/// veraenderlicher Laenge vor dem Kontext, und die drei Byteversaetze unten
/// haengen daran.
const LOCAL_AUDIT_EFFECTIVE_NOW_MS: i64 = 1_700_000_000_000;

/// Das Fuellbyte der Ereigniskennung, um den Aktionscode erhoeht.
const LOCAL_AUDIT_EVENT_ID_FILL_BASE: u8 = 0x40;

/// Das Fuellbyte der Nonce, um den Aktionscode erhoeht.
const LOCAL_AUDIT_NONCE_FILL_BASE: u8 = 0x90;

// Die Fuellbytes der Kontexthashes, je Kontext ein eigener Abschnitt. Jedes
// Fuellbyte kommt in der Familie genau EINMAL vor, damit eine Verwechslung im
// Vektormaterial sichtbar wird statt still durchzulaufen — dieselbe Regel, die
// `declared_test_entropy_is_pairwise_distinct` fuer das Schluesselmaterial
// misst.

/// Der Gegenstand des `login`-Ereignisses.
const LOCAL_AUDIT_LOGIN_SUBJECT_FILL: u8 = 0x71;

/// Die Vorgaengerbindung des Widerrufs.
const LOCAL_AUDIT_BINDING_OLD_FILL: u8 = 0x72;

/// Die Nachfolgerbindung der Bindungsaenderung.
const LOCAL_AUDIT_BINDING_NEW_FILL: u8 = 0x73;

/// Der Registrierungskopf des veralteten Registers.
const LOCAL_AUDIT_STALE_REGISTRY_HEAD_FILL: u8 = 0x74;

/// Die wirksame Richtlinie des veralteten Registers.
const LOCAL_AUDIT_STALE_POLICY_FILL: u8 = 0x75;

/// Der D-B02-Slot `previewHash`.
const LOCAL_AUDIT_STALE_PREVIEW_FILL: u8 = 0x76;

/// Der exportierte Eintrag.
const LOCAL_AUDIT_EXPORT_ENTRY_FILL: u8 = 0x77;

/// Der Registrierungskopf der Taktfreigabe.
const LOCAL_AUDIT_CLOCK_REGISTRY_HEAD_FILL: u8 = 0x78;

/// Die Wachrichtlinie der Taktfreigabe.
const LOCAL_AUDIT_CLOCK_GUARD_POLICY_FILL: u8 = 0x79;

/// Die unabhaengige Zeitreferenz der Taktfreigabe.
const LOCAL_AUDIT_CLOCK_REFERENCE_FILL: u8 = 0x7a;

/// Die Autorisierung der Root-Zeremonie.
const LOCAL_AUDIT_ADMIN_AUTHORIZATION_FILL: u8 = 0x7b;

/// Das Ziel der Root-Zeremonie.
const LOCAL_AUDIT_ADMIN_TARGET_FILL: u8 = 0x7c;

/// Der Gegenstand des Wiederherstellungstests.
const LOCAL_AUDIT_RECOVERY_SUBJECT_FILL: u8 = 0x7d;

/// Die Autorisierung des nachtraeglichen Grants.
const LOCAL_AUDIT_REGRANT_AUTHORIZATION_FILL: u8 = 0x7e;

/// Der Eintrag des nachtraeglichen Grants.
const LOCAL_AUDIT_REGRANT_ENTRY_FILL: u8 = 0x7f;

/// Der urspruengliche Recovery-Grant.
const LOCAL_AUDIT_REGRANT_ORIGINAL_GRANT_FILL: u8 = 0x80;

/// Das Empfaengerzertifikat des nachtraeglichen Grants.
const LOCAL_AUDIT_REGRANT_RECIPIENT_FILL: u8 = 0x81;

/// Der neue Grant.
const LOCAL_AUDIT_REGRANT_NEW_GRANT_FILL: u8 = 0x82;

/// Die Vernichtungsautorisierung.
const LOCAL_AUDIT_DESTRUCTION_AUTHORIZATION_FILL: u8 = 0x83;

/// Das Zustandsereignis der Vernichtung.
const LOCAL_AUDIT_DESTRUCTION_STATE_EVENT_FILL: u8 = 0x84;

/// Der D-B02-Slot `sourceProfileHash`.
const LOCAL_AUDIT_MIGRATION_SOURCE_FILL: u8 = 0x85;

/// Der D-B02-Slot `targetProfileHash`.
const LOCAL_AUDIT_MIGRATION_TARGET_FILL: u8 = 0x86;

/// Der D-B02-Slot `inventoryHash`.
const LOCAL_AUDIT_MIGRATION_INVENTORY_FILL: u8 = 0x87;

/// Der D-B02-Slot `activePointerHash`.
const LOCAL_AUDIT_MIGRATION_ACTIVE_POINTER_FILL: u8 = 0x88;

/// Die Sequenz, ab der die neue Bindung wirkt.
const LOCAL_AUDIT_BINDING_CHANGE_SEQUENCE: u64 = 41;

/// Die Sequenz, ab der der Widerruf wirkt.
const LOCAL_AUDIT_REVOCATION_SEQUENCE: u64 = 42;

/// Die vorgeschlagene Sequenz des veralteten Registers.
const LOCAL_AUDIT_STALE_PROPOSED_SEQUENCE: u64 = 43;

/// Die Registrierungsversion der Taktfreigabe.
const LOCAL_AUDIT_CLOCK_REGISTRY_VERSION: u64 = 44;

/// Die zugelassene Vorwaertsabweichung der Taktfreigabe.
const LOCAL_AUDIT_MAX_FUTURE_CLOCK_SKEW_MS: u64 = 300_000;

/// Die Zielart des Exports.
const LOCAL_AUDIT_EXPORT_TARGET_KIND: u64 = 1;

/// Der Aktionscode der Root-Zeremonie innerhalb ihres Kontexts.
const LOCAL_AUDIT_ADMIN_CONTEXT_ACTION_CODE: u64 = 3;

/// Der Versatz des Aktionscodes im Kern eines Ereignisses MIT Bindung.
///
/// Ausgerechnet, nicht gezaehlt: ein `array(12)`-Kopfbyte, das Versionsliteral
/// `1`, drei 16-Byte-Bytestrings mit Einbytekopf (je 17), zwei
/// 32-Byte-Bytestrings mit Zweibytekopf (je 34). Jeder Gebrauch prueft das Byte
/// VOR der Aenderung, damit eine Fixtureverschiebung beim Erzeugen auffaellt
/// statt still das falsche Byte zu treffen.
const LOCAL_AUDIT_ACTION_CODE_OFFSET: usize = 1 + 1 + 3 * 17 + 2 * 34;

/// Der Versatz des Ausgangs, unmittelbar hinter dem Aktionscode.
const LOCAL_AUDIT_OUTCOME_OFFSET: usize = LOCAL_AUDIT_ACTION_CODE_OFFSET + 1;

/// Der Versatz der Kontextmarke: hinter dem Ausgang, der neunstelligen
/// `effective-now` und dem Kopfbyte des Kontextpaares.
const LOCAL_AUDIT_CONTEXT_TAG_OFFSET: usize = LOCAL_AUDIT_OUTCOME_OFFSET + 1 + 9 + 1;

/// Die Reichweitennotiz der beiden Vektoren mit D-B02-Hashslots.
const LOCAL_AUDIT_HASH_SLOT_NOTE: &str = "Die 32-Byte-Hashslots dieses Vektors tragen ERKLAERTE TESTKONSTANTEN. Der Vektor belegt, dass der Kodierer sie an ihrer Position schreibt und der Dekodierer sie dort wiederfindet — und NICHTS darueber, wie sie berechnet werden: die Urbilder und die Domain-Zeichenketten der vier D-B02-Slots (previewHash, sourceProfileHash, targetProfileHash, inventoryHash, activePointerHash) entstehen mit ihren eigenen Vektoren in einer spaeteren Aufgabe.";

/// Die Reichweitennotiz des Vektors mit gekippter Nonce.
const LOCAL_AUDIT_NONCE_NOTE: &str = "Dieser Vektor ist der Beleg, dass die CDDL NICHT die Annahmegrenze ist: seine Gestalt ist grammatisch einwandfrei — die Nonce bleibt ein 32-Byte-Bytestring — und er wird ausschliesslich deshalb abgewiesen, weil die COSE-Nutzlast nicht mehr Byte fuer Byte der Kern ist.";

/// Die Reichweitennotiz des Vektors mit dem unzulaessigen Aktionscode.
const LOCAL_AUDIT_UNKNOWN_ACTION_NOTE: &str = "Der Aktionscode 200 ist durch die eingefrorene Vektorhygiene fuer einen UNZULAESSIGEN Code reserviert, damit eine spaetere v1.1-Erweiterung diesen Vektor nicht von abgelehnt zu angenommen drehen kann. Er ist deshalb ausdruecklich KEINE Einbytekippung: 200 braucht einen Zweibytekopf, und ein benachbarter Einbytewert waere ein Code, den eine Erweiterung belegen darf.";

fn local_audit_event_id(fill: u8) -> EventId {
    EventId::try_from([fill; 16].as_slice()).expect("16 bytes")
}

fn local_audit_object_hash(fill: u8) -> ObjectHash {
    ObjectHash::try_from([fill; 32].as_slice()).expect("32 bytes")
}

fn local_audit_entry_hash(fill: u8) -> EntryHash {
    EntryHash::try_from([fill; 32].as_slice()).expect("32 bytes")
}

fn local_audit_hash32(fill: u8) -> Hash32 {
    Hash32::try_from([fill; 32].as_slice()).expect("32 bytes")
}

/// Ein Ereignis dieser Familie: die Kennungen folgen dem Aktionscode, damit
/// eine Verwechslung im Vektormaterial sichtbar wird.
fn local_audit_event(
    action: LocalAuditActionV1,
    outcome: LocalAuditOutcomeV1,
    operator_binding_object_hash: Option<ObjectHash>,
) -> LocalAuditEventCoreFieldsV1 {
    let code = action.code();
    LocalAuditEventCoreFieldsV1 {
        event_id: local_audit_event_id(LOCAL_AUDIT_EVENT_ID_FILL_BASE + code),
        organization_id: OrganizationId::try_from(LOCAL_AUDIT_ORGANIZATION_ID.as_slice())
            .expect("16 bytes"),
        device_id: DeviceId::try_from(LOCAL_AUDIT_DEVICE_ID.as_slice()).expect("16 bytes"),
        operator_binding_object_hash,
        signer_certificate_object_hash: ObjectHash::try_from(
            LOCAL_AUDIT_SIGNER_CERTIFICATE_OBJECT_HASH.as_slice(),
        )
        .expect("32 bytes"),
        action,
        outcome,
        effective_now: UnixMillis::new(LOCAL_AUDIT_EFFECTIVE_NOW_MS),
        nonce: [LOCAL_AUDIT_NONCE_FILL_BASE + code; 32],
    }
}

/// Die zwoelf Ereignisse, eines je Aktion, mit ihrem Vektornamen.
///
/// Alle neun Kontextmarken kommen vor, und beide nullbaren Stellen stehen
/// mindestens einmal als `null`: die Bedienerbindung im `login`-Ereignis, der
/// Vorgaenger und der Nachfolger im Bindungslebenslauf.
fn local_audit_accepted_events() -> Vec<(&'static str, LocalAuditEventCoreFieldsV1)> {
    let binding =
        Some(ObjectHash::try_from(LOCAL_AUDIT_BINDING_OBJECT_HASH.as_slice()).expect("32 bytes"));
    vec![
        (
            "event/accepted-login",
            local_audit_event(
                LocalAuditActionV1::Login(GenericAuditContextV1::new(Some(
                    local_audit_object_hash(LOCAL_AUDIT_LOGIN_SUBJECT_FILL),
                ))),
                LocalAuditOutcomeV1::Accepted,
                None,
            ),
        ),
        (
            "event/accepted-reauth-failure",
            local_audit_event(
                LocalAuditActionV1::ReauthFailure(GenericAuditContextV1::new(None)),
                LocalAuditOutcomeV1::Failed,
                binding,
            ),
        ),
        (
            "event/accepted-binding-change",
            local_audit_event(
                LocalAuditActionV1::BindingChange(BindingLifecycleContextV1::new(
                    None,
                    Some(local_audit_object_hash(LOCAL_AUDIT_BINDING_NEW_FILL)),
                    ChainSequence::new(LOCAL_AUDIT_BINDING_CHANGE_SEQUENCE),
                )),
                LocalAuditOutcomeV1::Completed,
                binding,
            ),
        ),
        (
            "event/accepted-revocation",
            local_audit_event(
                LocalAuditActionV1::Revocation(BindingLifecycleContextV1::new(
                    Some(local_audit_object_hash(LOCAL_AUDIT_BINDING_OLD_FILL)),
                    None,
                    ChainSequence::new(LOCAL_AUDIT_REVOCATION_SEQUENCE),
                )),
                LocalAuditOutcomeV1::Completed,
                binding,
            ),
        ),
        (
            "event/accepted-registry-stale-warn-acceptance",
            local_audit_event(
                LocalAuditActionV1::RegistryStaleWarnAcceptance(StaleRegistryContextV1::new(
                    local_audit_object_hash(LOCAL_AUDIT_STALE_REGISTRY_HEAD_FILL),
                    local_audit_object_hash(LOCAL_AUDIT_STALE_POLICY_FILL),
                    ChainSequence::new(LOCAL_AUDIT_STALE_PROPOSED_SEQUENCE),
                    UnixMillis::new(LOCAL_AUDIT_EFFECTIVE_NOW_MS - 60_000),
                    UnixMillis::new(LOCAL_AUDIT_EFFECTIVE_NOW_MS),
                    local_audit_hash32(LOCAL_AUDIT_STALE_PREVIEW_FILL),
                )),
                LocalAuditOutcomeV1::Accepted,
                binding,
            ),
        ),
        (
            "event/accepted-plaintext-export",
            local_audit_event(
                LocalAuditActionV1::PlaintextExport(ExportContextV1::new(
                    local_audit_entry_hash(LOCAL_AUDIT_EXPORT_ENTRY_FILL),
                    LOCAL_AUDIT_EXPORT_TARGET_KIND,
                )),
                LocalAuditOutcomeV1::Completed,
                binding,
            ),
        ),
        (
            "event/accepted-clock-skew-release",
            local_audit_event(
                LocalAuditActionV1::ClockSkewRelease(ClockReleaseContextV1::new(
                    UnixMillis::new(LOCAL_AUDIT_EFFECTIVE_NOW_MS - 1_000),
                    UnixMillis::new(LOCAL_AUDIT_EFFECTIVE_NOW_MS),
                    LOCAL_AUDIT_MAX_FUTURE_CLOCK_SKEW_MS,
                    RegistryVersion::new(LOCAL_AUDIT_CLOCK_REGISTRY_VERSION),
                    local_audit_object_hash(LOCAL_AUDIT_CLOCK_REGISTRY_HEAD_FILL),
                    local_audit_object_hash(LOCAL_AUDIT_CLOCK_GUARD_POLICY_FILL),
                    IndependentTimeReferenceV1::new(
                        IndependentTimeKindV1::Checkpoint,
                        local_audit_object_hash(LOCAL_AUDIT_CLOCK_REFERENCE_FILL),
                        UnixMillis::new(LOCAL_AUDIT_EFFECTIVE_NOW_MS - 2_000),
                    ),
                    ClockReleaseJustificationV1::PlatformTimeSourceRecovery,
                    UnixMillis::new(LOCAL_AUDIT_EFFECTIVE_NOW_MS),
                    UnixMillis::new(
                        LOCAL_AUDIT_EFFECTIVE_NOW_MS
                            + i64::try_from(LOCAL_AUDIT_MAX_FUTURE_CLOCK_SKEW_MS)
                                .expect("the frozen skew fits an i64"),
                    ),
                )),
                LocalAuditOutcomeV1::Accepted,
                binding,
            ),
        ),
        (
            "event/accepted-admin-root-ceremony",
            local_audit_event(
                LocalAuditActionV1::AdminRootCeremony(AdminRootContextV1::new(
                    local_audit_object_hash(LOCAL_AUDIT_ADMIN_AUTHORIZATION_FILL),
                    local_audit_object_hash(LOCAL_AUDIT_ADMIN_TARGET_FILL),
                    LOCAL_AUDIT_ADMIN_CONTEXT_ACTION_CODE,
                )),
                LocalAuditOutcomeV1::Completed,
                binding,
            ),
        ),
        (
            "event/accepted-recovery-test",
            local_audit_event(
                LocalAuditActionV1::RecoveryTest(GenericAuditContextV1::new(Some(
                    local_audit_object_hash(LOCAL_AUDIT_RECOVERY_SUBJECT_FILL),
                ))),
                LocalAuditOutcomeV1::Completed,
                binding,
            ),
        ),
        (
            "event/accepted-historical-regrant",
            local_audit_event(
                LocalAuditActionV1::HistoricalRegrant(HistoricalRegrantContextV1::new(
                    local_audit_object_hash(LOCAL_AUDIT_REGRANT_AUTHORIZATION_FILL),
                    local_audit_entry_hash(LOCAL_AUDIT_REGRANT_ENTRY_FILL),
                    local_audit_object_hash(LOCAL_AUDIT_REGRANT_ORIGINAL_GRANT_FILL),
                    local_audit_object_hash(LOCAL_AUDIT_REGRANT_RECIPIENT_FILL),
                    local_audit_object_hash(LOCAL_AUDIT_REGRANT_NEW_GRANT_FILL),
                )),
                LocalAuditOutcomeV1::Completed,
                binding,
            ),
        ),
        (
            "event/accepted-destruction",
            local_audit_event(
                LocalAuditActionV1::Destruction(DestructionContextV1::new(
                    local_audit_object_hash(LOCAL_AUDIT_DESTRUCTION_AUTHORIZATION_FILL),
                    local_audit_object_hash(LOCAL_AUDIT_DESTRUCTION_STATE_EVENT_FILL),
                )),
                LocalAuditOutcomeV1::Completed,
                binding,
            ),
        ),
        (
            "event/accepted-archive-profile-migration",
            local_audit_event(
                LocalAuditActionV1::ArchiveProfileMigration(ArchiveProfileMigrationContextV1::new(
                    local_audit_hash32(LOCAL_AUDIT_MIGRATION_SOURCE_FILL),
                    local_audit_hash32(LOCAL_AUDIT_MIGRATION_TARGET_FILL),
                    local_audit_hash32(LOCAL_AUDIT_MIGRATION_INVENTORY_FILL),
                    local_audit_hash32(LOCAL_AUDIT_MIGRATION_ACTIVE_POINTER_FILL),
                )),
                LocalAuditOutcomeV1::Completed,
                binding,
            ),
        ),
    ]
}

/// Das Paar aus Kern und Signatur, wie `encode_local_audit_event` es schreibt.
///
/// Von Hand, weil die vier Defektvektoren einen Kern tragen, den der Kodierer
/// zu Recht nicht mehr annimmt. `array(2)` ist genau ein Byte — zwei Elemente
/// liegen weit unter der 24er-Grenze der definiten CBOR-Kopfbytes.
fn local_audit_wrapper(core: &[u8], cose: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(1 + core.len() + cose.len());
    bytes.push(0x82);
    bytes.extend_from_slice(core);
    bytes.extend_from_slice(cose);
    bytes
}

/// Setzt ein Byte des Kerns und prueft seinen Wert VORHER.
fn local_audit_edited_core(core: &[u8], offset: usize, expected: u8, replacement: u8) -> Vec<u8> {
    assert_eq!(
        core[offset], expected,
        "the fixture moved: offset {offset} carries {:#04x}, not {expected:#04x}",
        core[offset]
    );
    let mut edited = core.to_vec();
    edited[offset] = replacement;
    edited
}

/// Das Manifest der Vektorfamilie `local-audit/v1`.
///
/// Vollstaendig deterministisch: `CoseSigner` baut aus festen Schluesselbytes,
/// Ed25519 signiert deterministisch, und jedes Feld ist eine feste Konstante.
///
/// KEINE Zwischen-Digests: die Signatur eines lokalen Audits deckt den Kern
/// BYTE FUER BYTE und nicht einen Digest davon (`ContentType::LocalAuditCbor`
/// ist kein Digesttyp). Es gibt hier also keinen Zwischenwert, den ein Manifest
/// benennen koennte; `fileSha256` haelt die Bytes, und `objectBytes` haelt sie
/// ein zweites Mal.
///
/// # Panics
///
/// Wenn eine der Konstruktionen fehlschlaegt.
#[must_use]
pub fn local_audit_v1_manifest() -> VectorManifest {
    let signer = format_signer(TEST_ENTROPY_DEVICE_ED25519_SEED);
    let mut entries = Vec::new();
    let mut export_core = Vec::new();
    let mut export_cose = Vec::new();
    let mut export_nonce = [0_u8; 32];

    for (name, fields) in local_audit_accepted_events() {
        let core = encode_local_audit_core(&fields).expect("a frozen audit core is well formed");
        let cose = signer
            .sign_local_audit(&core)
            .expect("signing a frozen audit core cannot fail");
        let object_bytes =
            encode_local_audit_event(&core, &cose).expect("a frozen audit event is well formed");
        if name == "event/accepted-plaintext-export" {
            export_nonce = fields.nonce;
            export_core = core;
            export_cose = cose;
        }
        let scope_note = match name {
            "event/accepted-registry-stale-warn-acceptance"
            | "event/accepted-archive-profile-migration" => Some(LOCAL_AUDIT_HASH_SLOT_NOTE),
            _ => None,
        };
        entries.push(local_audit_entry(
            name,
            object_bytes,
            ExpectedOutcome::Accepted,
            scope_note,
        ));
    }
    assert!(
        !export_core.is_empty(),
        "the four single byte defects need the accepted export event"
    );

    // Die Aktion springt von `plaintextExport` auf `login`, waehrend die
    // Kontextmarke `3` stehen bleibt: die Grammatik bindet Aktion 0 an den
    // generischen Kontext.
    let flipped_action =
        local_audit_edited_core(&export_core, LOCAL_AUDIT_ACTION_CODE_OFFSET, 5, 0);
    // Die Kontextmarke springt von `3` auf `0`, waehrend die Aktion `5` bleibt.
    let flipped_tag = local_audit_edited_core(&export_core, LOCAL_AUDIT_CONTEXT_TAG_OFFSET, 3, 0);
    // Der Ausgang `3` liegt jenseits von `local-audit-outcome-v1 = 0..2`.
    let flipped_outcome = local_audit_edited_core(&export_core, LOCAL_AUDIT_OUTCOME_OFFSET, 2, 3);
    // Ein Noncebyte, Laenge unveraendert.
    let nonce_offset = unique_offset(&export_core, &export_nonce);
    let mut flipped_nonce = export_core.clone();
    flipped_nonce[nonce_offset] ^= 0x01;

    // Der unzulaessige Aktionscode 200 braucht einen Zweibytekopf und macht den
    // Kern damit um genau ein Byte laenger.
    let mut unknown_action = export_core.clone();
    assert_eq!(
        unknown_action[LOCAL_AUDIT_ACTION_CODE_OFFSET], 5,
        "the fixture moved: the action code is not where it is expected"
    );
    unknown_action.splice(
        LOCAL_AUDIT_ACTION_CODE_OFFSET..=LOCAL_AUDIT_ACTION_CODE_OFFSET,
        [0x18, 0xc8],
    );

    for (name, core, error_code, scope_note) in [
        (
            "event/rejected-flipped-action-code",
            flipped_action,
            LOCAL_AUDIT_CORE_ERROR_CODE,
            None,
        ),
        (
            "event/rejected-flipped-context-tag",
            flipped_tag,
            LOCAL_AUDIT_CORE_ERROR_CODE,
            None,
        ),
        (
            "event/rejected-flipped-outcome",
            flipped_outcome,
            LOCAL_AUDIT_CORE_ERROR_CODE,
            None,
        ),
        (
            "event/rejected-flipped-nonce-byte",
            flipped_nonce,
            LOCAL_AUDIT_COSE_ERROR_CODE,
            Some(LOCAL_AUDIT_NONCE_NOTE),
        ),
        (
            "event/rejected-unknown-action-code-200",
            unknown_action,
            LOCAL_AUDIT_CORE_ERROR_CODE,
            Some(LOCAL_AUDIT_UNKNOWN_ACTION_NOTE),
        ),
    ] {
        entries.push(local_audit_entry(
            name,
            local_audit_wrapper(&core, &export_cose),
            ExpectedOutcome::Rejected {
                error_code: error_code.to_owned(),
            },
            scope_note,
        ));
    }

    VectorManifest {
        family: LOCAL_AUDIT_FAMILY.to_owned(),
        version: LOCAL_AUDIT_V1_VERSION.to_owned(),
        entries,
    }
}

/// Der Code, mit dem `ea-format` einen Kern abweist, den die Signaturgrenze
/// nicht annimmt.
const LOCAL_AUDIT_CORE_ERROR_CODE: &str = "EA-FORMAT-SHAPE";

/// Der Code, mit dem `ea-format` eine Signatur abweist, die diesen Kern nicht
/// deckt.
const LOCAL_AUDIT_COSE_ERROR_CODE: &str = "EA-FORMAT-COSE";

/// Ein Eintrag der lokalen Auditfamilie.
fn local_audit_entry(
    name: &str,
    object_bytes: Vec<u8>,
    expected_outcome: ExpectedOutcome,
    scope_note: Option<&str>,
) -> VectorEntry {
    VectorEntry {
        name: name.to_owned(),
        schema_id: LOCAL_AUDIT_SCHEMA_ID.to_owned(),
        suite_id: LOCAL_AUDIT_SUITE_ID.to_owned(),
        source: VectorSource::GeneratorCommit(LOCAL_AUDIT_GENERATOR.to_owned()),
        input_bytes: Vec::new(),
        intermediate_digests: BTreeMap::new(),
        object_bytes,
        expected_outcome,
        file: format!("{name}.bin"),
        scope_note: scope_note.map(ToOwned::to_owned),
    }
}

// ---------------------------------------------------------------------------
// Vektorfamilie web-bundle/v1
// ---------------------------------------------------------------------------

/// Der Familienname der Bundle-Freigaben.
pub const WEB_BUNDLE_FAMILY: &str = "web-bundle";

/// Der Versionsordner der Bundle-Vektoren.
pub const WEB_BUNDLE_V1_VERSION: &str = "v1";

/// Die Wurzel der Bundle-Vektoren, relativ zur Arbeitsbaumwurzel.
///
/// Eine EIGENE Familie, ausdruecklich nicht `vectors/trust/v1`: das dortige
/// Manifest ist Stufe-1-Bestand und wird nicht neu erzeugt, und seine
/// Vektorhygiene verbietet die Literale dieser Familie im Manifesttext.
pub const WEB_BUNDLE_V1_ROOT: &str = "vectors/web-bundle/v1";

/// Die Herkunftsangabe der Bundle-Vektoren.
const WEB_BUNDLE_GENERATOR: &str = "ea-testkit::web_bundle_v1_manifest";

/// Der Suite-Identifikator der Bundle-Vektoren, EINGEFROREN.
const WEB_BUNDLE_SUITE_ID: &str = "EINSATZARCHIV-SUITE-1";

/// Der Schema-Identifikator eines Vertrauensbausteins.
const WEB_BUNDLE_SCHEMA_ID: &str = "etb-v1";

/// Die Organisationskennung aller Bundle-Vektoren.
const WEB_BUNDLE_ORGANIZATION_ID: [u8; 16] = [0x90; 16];

/// Der Bundle-Hash der Freigabe.
const WEB_BUNDLE_HASH: [u8; 32] = [0x91; 32];

/// Der Zertifikatshash, unter dem die Wurzel signiert.
///
/// Eine erklaerte Testkonstante und kein Objekthash: ein Objektvektor wird
/// gegen keinen Katalog aufgeloest — dieselbe Begruendung wie bei
/// [`TRUST_POLICY_CERTIFICATE_HASH`].
const WEB_BUNDLE_ROOT_CERTIFICATE_HASH: [u8; 32] = [0x92; 32];

/// Der Zertifikatshash der ZWEITEN Signatur des Kardinalitaetsnegativs.
const WEB_BUNDLE_SECOND_ROOT_CERTIFICATE_HASH: [u8; 32] = [0x93; 32];

/// Die Bundle-Version der Freigabe.
const WEB_BUNDLE_VERSION_STRING: &str = "2026.3.1";

/// Die Registry-Version, ab der die Freigabe wirksam ist.
const WEB_BUNDLE_RELEASE_EFFECTIVE_FROM_REGISTRY_VERSION: u64 = 6;

/// Die Registry-Version, ab der der Widerruf wirksam ist.
const WEB_BUNDLE_REVOCATION_EFFECTIVE_FROM_REGISTRY_VERSION: u64 = 7;

/// Der Ausstellungszeitpunkt der Freigabe.
const WEB_BUNDLE_RELEASE_ISSUED_AT_MS: i64 = 1_700_000_005_000;

/// Der Ausstellungszeitpunkt des Widerrufs.
const WEB_BUNDLE_REVOCATION_ISSUED_AT_MS: i64 = 1_700_000_006_000;

/// Das Literal des Subtype-Negativvektors dieser Familie.
///
/// Es steht AUSSCHLIESSLICH in den hexkodierten Objektbytes und nie in einem
/// Eintragsnamen; die Namen bleiben kebab-case.
const WEB_BUNDLE_UNKNOWN_SUBTYPE: &str = "webBundleReleases";

/// Der Code, mit dem `ea-format` eine unzulaessige Gestalt abweist.
const WEB_BUNDLE_SHAPE_ERROR_CODE: &str = "EA-FORMAT-SHAPE";

/// Der Code, mit dem `ea-format` ein unbekanntes Subtype-Literal abweist.
const WEB_BUNDLE_TAG_MISMATCH_ERROR_CODE: &str = "EA-FORMAT-TAG-MISMATCH";

/// Die Organisationskennung als getypter Wert.
fn web_bundle_organization_id() -> OrganizationId {
    OrganizationId::try_from(WEB_BUNDLE_ORGANIZATION_ID.as_slice()).expect("16 bytes")
}

/// Die Felder der Freigabe.
fn web_bundle_release_fields() -> WebBundleReleaseCoreV1 {
    WebBundleReleaseCoreV1 {
        organization_id: web_bundle_organization_id(),
        bundle_hash: Hash32::try_from(WEB_BUNDLE_HASH.as_slice()).expect("32 bytes"),
        bundle_version: WEB_BUNDLE_VERSION_STRING.to_owned(),
        effective_from_registry_version: RegistryVersion::new(
            WEB_BUNDLE_RELEASE_EFFECTIVE_FROM_REGISTRY_VERSION,
        ),
        issued_at: UnixMillis::new(WEB_BUNDLE_RELEASE_ISSUED_AT_MS),
        root_key_thumbprint: trust_public_key(TEST_ENTROPY_ROOT_ED25519_SEED).thumbprint(),
    }
}

/// Die Felder des Widerrufs zu einer gegebenen Freigabe.
fn web_bundle_revocation_fields(release_object_hash: ObjectHash) -> WebBundleRevocationCoreV1 {
    WebBundleRevocationCoreV1 {
        organization_id: web_bundle_organization_id(),
        release_object_hash,
        effective_from_registry_version: RegistryVersion::new(
            WEB_BUNDLE_REVOCATION_EFFECTIVE_FROM_REGISTRY_VERSION,
        ),
        issued_at: UnixMillis::new(WEB_BUNDLE_REVOCATION_ISSUED_AT_MS),
        root_key_thumbprint: trust_public_key(TEST_ENTROPY_ROOT_ED25519_SEED).thumbprint(),
    }
}

/// Die Wurzelsignatur ueber den Digest-Eingang genau dieses Nutzinhalts.
fn web_bundle_root_signature(certificate_hash: [u8; 32], exact_digest_input: &[u8]) -> Vec<u8> {
    trust_signed_normal(
        TEST_ENTROPY_ROOT_ED25519_SEED,
        CertificateHash::try_from(certificate_hash.as_slice()).expect("32 bytes"),
        trust_digest(exact_digest_input).as_bytes(),
    )
}

/// Ein von Hand gebauter Vertrauensbaustein `[subtype, nutzinhalt, [sig*]]`.
///
/// Von Hand, weil die Negativvektoren gerade NICHT durch `TrustObjectV1::new`
/// gehen duerfen: null und zwei Signaturen weist der Kodierer ab, und genau
/// diese Bytes sollen eingefroren werden.
fn web_bundle_handmade_object(
    subtype: &str,
    exact_payload: &[u8],
    signatures: &[Vec<u8>],
) -> Vec<u8> {
    let mut object = vec![0x85, 0x44, b'E', b'A', b'1', 0, 5, 1, 0x80];
    object.extend_from_slice(&trust_cbor_array(3));
    object.extend_from_slice(&trust_cbor_text(subtype));
    object.extend_from_slice(exact_payload);
    object.extend_from_slice(&trust_cbor_array(
        u64::try_from(signatures.len()).expect("no vector carries 24 signatures"),
    ));
    for signature in signatures {
        object.extend_from_slice(signature);
    }
    object
}

/// Der Digest-Eingang `[subtype, nutzinhalt]`, von Hand.
fn web_bundle_digest_input(subtype: &str, exact_payload: &[u8]) -> Vec<u8> {
    let mut input = trust_cbor_array(2);
    input.extend_from_slice(&trust_cbor_text(subtype));
    input.extend_from_slice(exact_payload);
    input
}

/// Der Releasekern OHNE sein leeres Erweiterungsarray: sieben statt acht
/// Positionen.
fn web_bundle_release_core_without_extension_array(exact_payload: &[u8]) -> Vec<u8> {
    assert_eq!(
        exact_payload[0], 0x88,
        "a release core is an eight element array"
    );
    assert_eq!(
        exact_payload[exact_payload.len() - 1],
        0x80,
        "a release core ends on its empty extension array"
    );
    let mut shortened = vec![0x87];
    shortened.extend_from_slice(&exact_payload[1..exact_payload.len() - 1]);
    shortened
}

/// Das Manifest der Vektorfamilie `web-bundle/v1`.
///
/// Deterministisch: Ed25519 signiert deterministisch, alle Felder sind feste
/// Konstanten, und keine Kapselung zieht Entropie. Zwei Laeufe liefern
/// dieselben Bytes.
///
/// # Panics
///
/// Wenn eine der Konstruktionen fehlschlaegt. Das waere ein Programmierfehler
/// dieser Kiste, kein Laufzeitzustand.
#[must_use]
pub fn web_bundle_v1_manifest() -> VectorManifest {
    let release_payload = TrustPayloadV1::web_bundle_release(web_bundle_release_fields())
        .expect("the frozen release payload is well formed");
    let release_signature = web_bundle_root_signature(
        WEB_BUNDLE_ROOT_CERTIFICATE_HASH,
        release_payload.exact_digest_input(),
    );
    let release_digest = trust_digest(release_payload.exact_digest_input());
    let release_exact_payload = release_payload.exact_payload().to_vec();
    let release_bytes = trust_exact_object(release_payload, vec![release_signature.clone()]);

    let revocation_payload = TrustPayloadV1::web_bundle_revocation(web_bundle_revocation_fields(
        object_hash(&release_bytes),
    ))
    .expect("the frozen revocation payload is well formed");
    let revocation_signature = web_bundle_root_signature(
        WEB_BUNDLE_ROOT_CERTIFICATE_HASH,
        revocation_payload.exact_digest_input(),
    );
    let revocation_digest = trust_digest(revocation_payload.exact_digest_input());
    let revocation_bytes = trust_exact_object(revocation_payload, vec![revocation_signature]);

    let mut entries = vec![
        web_bundle_entry(
            "object/accepted-release",
            release_bytes,
            digest_map(&[("trust-digest", *release_digest.as_bytes())]),
            ExpectedOutcome::Accepted,
        ),
        web_bundle_entry(
            "object/accepted-revocation",
            revocation_bytes,
            digest_map(&[("trust-digest", *revocation_digest.as_bytes())]),
            ExpectedOutcome::Accepted,
        ),
    ];

    // Null Signaturen: die Grammatik schreibt `[cose-sign1-v1]` vor, also
    // genau eine.
    entries.push(web_bundle_entry(
        "object/rejected-release-without-signature",
        web_bundle_handmade_object(
            TrustSubtypeV1::WebBundleRelease.as_str(),
            &release_exact_payload,
            &[],
        ),
        BTreeMap::new(),
        web_bundle_rejected(WEB_BUNDLE_SHAPE_ERROR_CODE),
    ));

    // Zwei fuer sich wohlgeformte Wurzelsignaturen. Die Kardinalitaet faellt
    // VOR der Signaturpruefung, und genau das ist die Aussage des Vektors.
    entries.push(web_bundle_entry(
        "object/rejected-release-with-two-signatures",
        web_bundle_handmade_object(
            TrustSubtypeV1::WebBundleRelease.as_str(),
            &release_exact_payload,
            &[
                release_signature.clone(),
                web_bundle_root_signature(
                    WEB_BUNDLE_SECOND_ROOT_CERTIFICATE_HASH,
                    &web_bundle_digest_input(
                        TrustSubtypeV1::WebBundleRelease.as_str(),
                        &release_exact_payload,
                    ),
                ),
            ],
        ),
        BTreeMap::new(),
        web_bundle_rejected(WEB_BUNDLE_SHAPE_ERROR_CODE),
    ));

    // Ein Literal, das um genau ein `s` neben dem echten liegt. Es steht nur
    // in den Objektbytes.
    let unknown_digest_input =
        web_bundle_digest_input(WEB_BUNDLE_UNKNOWN_SUBTYPE, &release_exact_payload);
    entries.push(web_bundle_entry(
        "object/rejected-unknown-bundle-subtype",
        web_bundle_handmade_object(
            WEB_BUNDLE_UNKNOWN_SUBTYPE,
            &release_exact_payload,
            &[web_bundle_root_signature(
                WEB_BUNDLE_ROOT_CERTIFICATE_HASH,
                &unknown_digest_input,
            )],
        ),
        BTreeMap::new(),
        web_bundle_rejected(WEB_BUNDLE_TAG_MISMATCH_ERROR_CODE),
    ));

    // Der Kern ohne sein leeres Erweiterungsarray: sieben statt acht
    // Positionen. Die Gestalt faellt, bevor die Signatur geprueft wird.
    entries.push(web_bundle_entry(
        "object/rejected-release-core-without-extension-array",
        web_bundle_handmade_object(
            TrustSubtypeV1::WebBundleRelease.as_str(),
            &web_bundle_release_core_without_extension_array(&release_exact_payload),
            &[release_signature],
        ),
        BTreeMap::new(),
        web_bundle_rejected(WEB_BUNDLE_SHAPE_ERROR_CODE),
    ));

    VectorManifest {
        family: WEB_BUNDLE_FAMILY.to_owned(),
        version: WEB_BUNDLE_V1_VERSION.to_owned(),
        entries,
    }
}

/// Ein abgelehnter Ausgang mit seinem Fehlercode.
fn web_bundle_rejected(code: &str) -> ExpectedOutcome {
    ExpectedOutcome::Rejected {
        error_code: code.to_owned(),
    }
}

/// Ein Eintrag der Bundle-Familie.
fn web_bundle_entry(
    name: &str,
    object_bytes: Vec<u8>,
    intermediate_digests: BTreeMap<String, [u8; 32]>,
    expected_outcome: ExpectedOutcome,
) -> VectorEntry {
    VectorEntry {
        name: name.to_owned(),
        schema_id: WEB_BUNDLE_SCHEMA_ID.to_owned(),
        suite_id: WEB_BUNDLE_SUITE_ID.to_owned(),
        source: VectorSource::GeneratorCommit(WEB_BUNDLE_GENERATOR.to_owned()),
        input_bytes: Vec::new(),
        intermediate_digests,
        object_bytes,
        expected_outcome,
        file: format!("{name}.bin"),
        scope_note: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn scratch_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir()
            .join("ea-testkit-selftest")
            .join(format!("{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        root
    }

    fn sample_entry(name: &str, file: &str, object: &[u8]) -> VectorEntry {
        let mut intermediate_digests = BTreeMap::new();
        let digest: [u8; 32] = Sha256::digest(object).into();
        intermediate_digests.insert("object".to_owned(), digest);
        VectorEntry {
            name: name.to_owned(),
            schema_id: "eip-v1".to_owned(),
            suite_id: "suite-1".to_owned(),
            source: VectorSource::GeneratorCommit("0000000".to_owned()),
            input_bytes: b"input".to_vec(),
            intermediate_digests,
            object_bytes: object.to_vec(),
            expected_outcome: ExpectedOutcome::Accepted,
            file: file.to_owned(),
            scope_note: None,
        }
    }

    fn sample_manifest() -> VectorManifest {
        VectorManifest {
            family: "format".to_owned(),
            version: "v1".to_owned(),
            entries: vec![
                sample_entry("second", "valid/second.eip", b"second object"),
                sample_entry("first", "valid/first.eip", b"first object"),
            ],
        }
    }

    /// Die Ed25519-KAT-Seeds sind gemessen, nicht behauptet.
    #[test]
    fn published_ed25519_key_pairs_derive_their_recorded_public_key() {
        for (seed, public) in [
            (ED25519_RFC8032_TEST1_SEED, ED25519_RFC8032_TEST1_PUBLIC_KEY),
            (ED25519_RFC8032_TEST2_SEED, ED25519_RFC8032_TEST2_PUBLIC_KEY),
        ] {
            let derived = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
            assert_eq!(
                hex::encode(derived),
                hex::encode(public),
                "the RFC 8032 seed must derive its published public key"
            );
        }
    }

    /// Ebenso die X25519-KAT-Schluessel samt gemeinsamem Geheimnis.
    #[test]
    fn published_x25519_key_pairs_agree_on_the_recorded_shared_secret() {
        let alice = StaticSecret::from(X25519_RFC7748_ALICE_PRIVATE_KEY);
        let bob = StaticSecret::from(X25519_RFC7748_BOB_PRIVATE_KEY);
        assert_eq!(
            hex::encode(PublicKey::from(&alice).to_bytes()),
            hex::encode(X25519_RFC7748_ALICE_PUBLIC_KEY)
        );
        assert_eq!(
            hex::encode(PublicKey::from(&bob).to_bytes()),
            hex::encode(X25519_RFC7748_BOB_PUBLIC_KEY)
        );
        assert_eq!(
            hex::encode(alice.diffie_hellman(&PublicKey::from(&bob)).to_bytes()),
            hex::encode(X25519_RFC7748_SHARED_SECRET)
        );
        assert_eq!(
            hex::encode(bob.diffie_hellman(&PublicKey::from(&alice)).to_bytes()),
            hex::encode(X25519_RFC7748_SHARED_SECRET)
        );
    }

    /// Keine zwei Rollen teilen sich dieselbe deklarierte Testentropie.
    #[test]
    fn declared_test_entropy_is_pairwise_distinct() {
        let mut seen = BTreeSet::new();
        for (name, bytes) in DECLARED_TEST_ENTROPY {
            assert!(
                bytes.iter().any(|byte| *byte != 0),
                "{name} must not be all zero"
            );
            assert!(seen.insert(bytes), "{name} repeats other test entropy");
        }
    }

    #[test]
    fn emission_is_byte_identical_across_runs_and_independent_of_entry_order() {
        let manifest = sample_manifest();
        let reversed = VectorManifest {
            entries: manifest.entries.iter().rev().cloned().collect(),
            ..manifest.clone()
        };
        let text = manifest.to_json().unwrap();
        assert_eq!(text, manifest.to_json().unwrap());
        assert_eq!(text, reversed.to_json().unwrap());
        assert!(text.ends_with('\n'));
        let parsed = VectorManifest::from_json(&text).unwrap();
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].name, "first");
        assert_eq!(parsed.family, "format");
    }

    /// Die Schluesselreihenfolge haengt NICHT am `preserve_order`-Feature von
    /// `serde_json`. Ohne das Feature ist `serde_json::Map` eine `BTreeMap` und
    /// sortiert von selbst; mit dem Feature behielte sie die
    /// Einfuegereihenfolge, und die ist in `VectorEntry::to_value`
    /// ausdruecklich NICHT alphabetisch. Dieser Test misst das Ergebnis, damit
    /// die eingefrorenen Manifestbytes nicht von einer fremden
    /// Featureaktivierung abhaengen.
    #[test]
    fn emitted_object_keys_are_alphabetical_and_not_in_insertion_order() {
        let manifest = VectorManifest {
            family: "format".to_owned(),
            version: "v1".to_owned(),
            entries: vec![sample_entry("only", "valid/only.eip", b"only object")],
        };
        let text = manifest.to_json().unwrap();
        let insertion_order = [
            "name",
            "schemaId",
            "suiteId",
            "source",
            "inputBytes",
            "intermediateDigests",
            "objectBytes",
            "expectedOutcome",
            "file",
            "fileSha256",
        ];
        let mut alphabetical = insertion_order;
        alphabetical.sort_unstable();
        assert_ne!(
            insertion_order, alphabetical,
            "this test is only meaningful while the insertion order differs"
        );
        let mut previous = 0;
        for key in alphabetical {
            let at = text
                .find(&format!("\"{key}\":"))
                .unwrap_or_else(|| panic!("the manifest must carry {key}"));
            assert!(
                at > previous,
                "{key} must follow the alphabetically preceding key"
            );
            previous = at;
        }
    }

    #[test]
    fn emitted_files_verify_against_their_manifest() {
        let root = scratch_root("clean");
        let manifest = sample_manifest();
        manifest.emit(&root).unwrap();
        let report = verify_manifest_at(&root).unwrap();
        assert_eq!(report.entries_checked, 2);
        assert!(report.is_clean(), "{:?}", report.mismatches);
        assert_eq!(
            fs::read(root.join("valid/first.eip")).unwrap(),
            b"first object"
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_single_flipped_byte_on_disk_is_reported_as_a_hash_mismatch() {
        let root = scratch_root("tampered");
        let manifest = sample_manifest();
        manifest.emit(&root).unwrap();
        let target = root.join("valid/first.eip");
        let mut bytes = fs::read(&target).unwrap();
        bytes[0] ^= 0x01;
        fs::write(&target, &bytes).unwrap();

        let report = verify_manifest_at(&root).unwrap();
        assert!(!report.is_clean());
        assert_eq!(report.mismatches.len(), 2);
        assert!(matches!(
            &report.mismatches[0],
            Mismatch::FileSha256 { entry, expected, actual }
                if entry == "first" && expected != actual
        ));
        assert!(matches!(
            &report.mismatches[1],
            Mismatch::ObjectBytes { entry } if entry == "first"
        ));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_deleted_file_is_reported_instead_of_aborting_the_run() {
        let root = scratch_root("missing");
        let manifest = sample_manifest();
        manifest.emit(&root).unwrap();
        fs::remove_file(root.join("valid/second.eip")).unwrap();

        let report = verify_manifest_at(&root).unwrap();
        assert_eq!(report.entries_checked, 2);
        assert_eq!(
            report.mismatches,
            vec![Mismatch::MissingFile {
                entry: "second".to_owned(),
                file: "valid/second.eip".to_owned(),
            }]
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn duplicate_names_and_escaping_paths_are_refused_before_anything_is_written() {
        let duplicate = VectorManifest {
            family: "format".to_owned(),
            version: "v1".to_owned(),
            entries: vec![
                sample_entry("same", "valid/a.eip", b"a"),
                sample_entry("same", "valid/b.eip", b"b"),
            ],
        };
        assert_eq!(
            duplicate.to_json().unwrap_err().code(),
            "duplicate_entry",
            "a duplicate entry name must never reach the disk"
        );

        for escaping in ["../outside.eip", "/absolute.eip", ""] {
            let manifest = VectorManifest {
                family: "format".to_owned(),
                version: "v1".to_owned(),
                entries: vec![sample_entry("escaping", escaping, b"a")],
            };
            assert_eq!(
                manifest.to_json().unwrap_err().code(),
                "unsafe_path",
                "{escaping} must be refused"
            );
        }
    }

    /// Die Arbeitsbaumwurzel, unabhaengig vom Arbeitsverzeichnis des Laufs.
    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    /// Schreibt die Vektorfamilie `crypto/suite-1` in den Arbeitsbaum.
    ///
    /// `#[ignore]`, weil dieser Test SCHREIBT. Er ist der dokumentierte
    /// Erzeugungslauf und wird ausdruecklich angefordert:
    /// `cargo test -p ea-testkit -- --ignored emit_crypto_suite_one_vectors`.
    ///
    /// EINMAL EINGEFRORENE BYTES SIND UNVERAENDERLICH. Ein Lauf, der andere
    /// Bytes schreibt als die eingecheckten, ist kein Regenerierungslauf,
    /// sondern ein Befund.
    #[test]
    #[ignore = "writes into the working tree; run deliberately to regenerate"]
    fn emit_crypto_suite_one_vectors() {
        let root = workspace_root().join(CRYPTO_SUITE_ONE_ROOT);
        crypto_suite_one_manifest().emit(&root).unwrap();
        assert!(verify_manifest_at(&root).unwrap().is_clean());
    }

    /// Das eingecheckte Manifest ist genau die Ausgabe des Erzeugers.
    ///
    /// Damit haengt die Familie nicht an einem Lauf, den niemand wiederholen
    /// kann: wer den Erzeuger aendert, sieht es hier, und nicht erst, wenn ein
    /// Vektor still von seiner Beschreibung abweicht.
    #[test]
    fn the_committed_crypto_suite_one_family_is_exactly_what_the_generator_emits() {
        let root = workspace_root().join(CRYPTO_SUITE_ONE_ROOT);
        let text = fs::read_to_string(root.join(MANIFEST_FILE_NAME)).unwrap_or_else(|error| {
            panic!("failed to read the committed crypto manifest: {error}")
        });
        assert_eq!(
            text,
            crypto_suite_one_manifest().to_json().unwrap(),
            "the committed manifest must be byte-identical to the generator output"
        );
        let report = verify_manifest_at(&root).unwrap();
        assert!(report.is_clean(), "{:?}", report.mismatches);
    }

    /// Der Erzeuger liefert 74 verschiedene Eintraege, und jeder Dateipfad
    /// liegt unter der Familienwurzel.
    #[test]
    fn the_crypto_generator_names_every_entry_and_file_exactly_once() {
        let manifest = crypto_suite_one_manifest();
        assert_eq!(manifest.entries.len(), 74);
        let names = manifest
            .entries
            .iter()
            .map(|entry| entry.name.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(names.len(), manifest.entries.len());
        for entry in &manifest.entries {
            assert_eq!(entry.file, format!("{}.bin", entry.name));
            assert!(matches!(
                entry.suite_id.as_str(),
                CRYPTO_SUITE_ONE_SUITE_ID | CRYPTO_SUITE_ONE_GRANT_SUITE_ID
            ));
        }
        // Die Emission ist deterministisch, sonst waere jeder Regenerierungslauf
        // ein Diff.
        assert_eq!(
            manifest.to_json().unwrap(),
            crypto_suite_one_manifest().to_json().unwrap()
        );
    }

    #[test]
    fn a_manifest_whose_recorded_hash_contradicts_its_own_bytes_is_malformed() {
        let text = sample_manifest().to_json().unwrap();
        let broken = text.replace(
            &sha256_hex(b"first object"),
            &sha256_hex(b"a different object"),
        );
        assert_ne!(text, broken);
        assert_eq!(
            VectorManifest::from_json(&broken).unwrap_err().code(),
            "malformed_manifest"
        );
    }

    /// Schreibt die Vektorfamilie `format/v1` in den Arbeitsbaum.
    ///
    /// `#[ignore]`, weil dieser Test SCHREIBT. Er ist der dokumentierte
    /// Erzeugungslauf und wird ausdruecklich angefordert:
    /// `cargo test -p ea-testkit -- --ignored emit_format_v1_vectors`.
    #[test]
    #[ignore = "writes into the working tree; run deliberately to regenerate"]
    fn emit_format_v1_vectors() {
        for (relative, manifest) in [
            (FORMAT_V1_VALID_ROOT, format_v1_valid_manifest()),
            (FORMAT_V1_INVALID_ROOT, format_v1_invalid_manifest()),
        ] {
            let root = workspace_root().join(relative);
            manifest.emit(&root).unwrap();
            assert!(verify_manifest_at(&root).unwrap().is_clean());
        }
    }

    /// Die eingecheckten Objektmanifeste sind genau die Ausgabe des Erzeugers.
    #[test]
    fn the_committed_format_v1_families_are_exactly_what_the_generator_emits() {
        for (relative, manifest) in [
            (FORMAT_V1_VALID_ROOT, format_v1_valid_manifest()),
            (FORMAT_V1_INVALID_ROOT, format_v1_invalid_manifest()),
        ] {
            let root = workspace_root().join(relative);
            let text = fs::read_to_string(root.join(MANIFEST_FILE_NAME)).unwrap_or_else(|error| {
                panic!("failed to read the committed manifest of {relative}: {error}")
            });
            assert_eq!(
                text,
                manifest.to_json().unwrap(),
                "the committed manifest of {relative} must be byte-identical to the generator \
                 output"
            );
            let report = verify_manifest_at(&root).unwrap();
            assert!(report.is_clean(), "{:?}", report.mismatches);
        }
    }

    /// Der Erzeuger benennt jeden Eintrag und jede Datei genau einmal, und die
    /// Emission ist deterministisch.
    #[test]
    fn the_format_generator_names_every_entry_and_file_exactly_once() {
        for (expected_entries, manifest) in [
            (6_usize, format_v1_valid_manifest()),
            (41, format_v1_invalid_manifest()),
        ] {
            assert_eq!(manifest.entries.len(), expected_entries);
            let names = manifest
                .entries
                .iter()
                .map(|entry| entry.name.clone())
                .collect::<BTreeSet<_>>();
            assert_eq!(names.len(), manifest.entries.len());
            for entry in &manifest.entries {
                assert_eq!(entry.file, format!("{}.bin", entry.name));
                assert_eq!(entry.suite_id, FORMAT_SUITE_ID);
            }
            assert_eq!(manifest.family, FORMAT_FAMILY);
        }
        assert_eq!(
            format_v1_valid_manifest().to_json().unwrap(),
            format_v1_valid_manifest().to_json().unwrap()
        );
        assert_eq!(
            format_v1_invalid_manifest().to_json().unwrap(),
            format_v1_invalid_manifest().to_json().unwrap()
        );
    }

    /// Erzeugt die eingefrorenen Kapselungen der Grant-Familie EINMALIG.
    ///
    /// `#[ignore]`, weil `hpke_seal` frische Entropie zieht: jeder Lauf liefert
    /// andere Bytes. Der dokumentierte Erzeugungslauf ist
    /// `cargo test -p ea-testkit -- --ignored --nocapture freeze_grant_encapsulations`;
    /// seine Ausgabe wird in [`GRANT_INITIAL_ENCAPSULATED_KEY`] und die drei
    /// benachbarten Konstanten uebernommen und danach NIE wieder erzeugt.
    #[test]
    #[ignore = "draws fresh entropy; run deliberately to freeze the encapsulations"]
    fn freeze_grant_encapsulations() {
        let recipient =
            ea_crypto::HpkeRecipientPublicKey::from_bytes(grants_recipient_public_key())
                .expect("the derived recipient key loads");
        let issuer = format_public_key(TEST_ENTROPY_DEVICE_ED25519_SEED).thumbprint();
        for (label, kind) in [
            ("INITIAL", GrantKindV1::Initial),
            ("HISTORICAL", GrantKindV1::Historical),
        ] {
            let body = GrantBodyV1::new(grant_body_fields(
                kind,
                issuer,
                [0; HPKE_ENCAPSULATED_KEY_SIZE],
                [0; HPKE_WRAPPED_CEK_SIZE],
            ))
            .expect("the placeholder grant body is well formed");
            let context = grant_context(&body);
            let sealed = ea_crypto::hpke_seal(
                &recipient,
                &SecretBytes::new(TEST_ENTROPY_CONTENT_ENCRYPTION_KEY),
                &hpke_info(&context),
                &hpke_aad(&context),
            )
            .expect("sealing the declared content key cannot fail");
            println!(
                "GRANT_{label}_ENCAPSULATED_KEY = {}",
                hex::encode(sealed.encapsulated_key())
            );
            println!(
                "GRANT_{label}_WRAPPED_CEK = {}",
                hex::encode(sealed.wrapped_cek())
            );
        }
    }

    /// Schreibt die Vektorfamilie `trust/v1` in den Arbeitsbaum.
    ///
    /// `#[ignore]`, weil dieser Test SCHREIBT. Er ist der dokumentierte
    /// Erzeugungslauf und wird ausdruecklich angefordert:
    /// `cargo test -p ea-testkit -- --ignored emit_trust_v1_vectors`.
    #[test]
    #[ignore = "writes into the working tree; run deliberately to regenerate"]
    fn emit_trust_v1_vectors() {
        let root = workspace_root().join(TRUST_V1_ROOT);
        trust_v1_manifest().emit(&root).unwrap();
        assert!(verify_manifest_at(&root).unwrap().is_clean());
    }

    /// Das eingecheckte Trust-Manifest ist genau die Ausgabe des Erzeugers.
    #[test]
    fn the_committed_trust_v1_family_is_exactly_what_the_generator_emits() {
        let root = workspace_root().join(TRUST_V1_ROOT);
        let text = fs::read_to_string(root.join(MANIFEST_FILE_NAME))
            .unwrap_or_else(|error| panic!("failed to read the committed trust manifest: {error}"));
        assert_eq!(
            text,
            trust_v1_manifest().to_json().unwrap(),
            "the committed manifest must be byte-identical to the generator output"
        );
        let report = verify_manifest_at(&root).unwrap();
        assert!(report.is_clean(), "{:?}", report.mismatches);
    }

    /// Der Trust-Erzeuger benennt jeden Eintrag und jede Datei genau einmal,
    /// jeder Fall traegt genau einen Anchor, und die Emission ist
    /// deterministisch.
    #[test]
    fn the_trust_generator_names_every_entry_and_file_exactly_once() {
        let manifest = trust_v1_manifest();
        let names = manifest
            .entries
            .iter()
            .map(|entry| entry.name.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(names.len(), manifest.entries.len());
        for entry in &manifest.entries {
            assert_eq!(entry.file, format!("{}.bin", entry.name));
            assert_eq!(entry.suite_id, TRUST_SUITE_ID);
            assert!(matches!(
                entry.schema_id.as_str(),
                TRUST_OBJECT_SCHEMA_ID | TRUST_ANCHOR_SCHEMA_ID | TRUST_PRE_ANCHOR_SCHEMA_ID
            ));
        }
        assert_eq!(manifest.family, TRUST_FAMILY);
        assert_eq!(manifest.version, TRUST_V1_VERSION);

        for (case, path, _) in TRUST_CASES_V1 {
            let anchors = manifest
                .entries
                .iter()
                .filter(|entry| {
                    entry.name.starts_with(&format!("{path}/"))
                        && entry.schema_id == TRUST_ANCHOR_SCHEMA_ID
                })
                .count();
            assert_eq!(anchors, 1, "{path} must hold exactly one anchor");
            assert_eq!(case.path(), path);
        }

        assert_eq!(
            manifest.to_json().unwrap(),
            trust_v1_manifest().to_json().unwrap()
        );
    }

    /// Jeder `organizationAdminAuthorization`-Vektor traegt die
    /// Reichweitennotiz zu §7.5, und kein Vektor nennt einen reservierten
    /// Namen.
    #[test]
    fn every_trust_admin_authorization_states_what_it_does_not_prove() {
        let manifest = trust_v1_manifest();
        let text = manifest.to_json().unwrap();
        for reserved in ["webBundleRelease", "readerKeyEscrow"] {
            assert!(
                !text.contains(reserved),
                "{reserved} could become a real trust object family"
            );
        }
        let mut authorizations = 0_usize;
        for entry in &manifest.entries {
            if entry.schema_id != TRUST_OBJECT_SCHEMA_ID
                || trust_body_subtype(&entry.object_bytes) != TRUST_ADMIN_AUTHORIZATION_SUBTYPE
            {
                // Die freistehenden Richtlinienvektoren tragen die einzige
                // ANDERE Notiz dieser Familie; alles Uebrige traegt keine.
                if entry.name.starts_with("object/accepted-policy-core-") {
                    assert_eq!(
                        entry.scope_note.as_deref(),
                        Some(TRUST_POLICY_SCOPE_NOTE),
                        "{} must name the normative source of its deadline",
                        entry.name
                    );
                } else {
                    assert!(entry.scope_note.is_none(), "{} needs no note", entry.name);
                }
                continue;
            }
            authorizations += 1;
            assert_eq!(
                entry.scope_note.as_deref(),
                Some(TRUST_ADMIN_AUTHORIZATION_SCOPE_NOTE),
                "{} must state what it does NOT prove",
                entry.name
            );
        }
        assert!(authorizations >= TRUST_OBJECT_CASES_V1.len());
    }

    /// Schreibt die Vektorfamilien `grants/v1`, `receipts/v1` und
    /// `evidence/v1` in den Arbeitsbaum.
    ///
    /// `#[ignore]`, weil dieser Test SCHREIBT. Er ist der dokumentierte
    /// Erzeugungslauf und wird ausdruecklich angefordert:
    /// `cargo test -p ea-testkit -- --ignored emit_grant_receipt_and_evidence_vectors`.
    #[test]
    #[ignore = "writes into the working tree; run deliberately to regenerate"]
    fn emit_grant_receipt_and_evidence_vectors() {
        for (root, manifest) in [
            (GRANTS_V1_ROOT, grants_v1_manifest()),
            (RECEIPTS_V1_ROOT, receipts_v1_manifest()),
            (EVIDENCE_V1_ROOT, evidence_v1_manifest()),
        ] {
            let root = workspace_root().join(root);
            manifest.emit(&root).unwrap();
            assert!(verify_manifest_at(&root).unwrap().is_clean());
        }
    }

    /// Die eingecheckten Manifeste der drei Familien sind genau die Ausgabe
    /// ihrer Erzeuger.
    #[test]
    fn the_committed_grant_receipt_and_evidence_families_match_their_generators() {
        for (root, manifest) in [
            (GRANTS_V1_ROOT, grants_v1_manifest()),
            (RECEIPTS_V1_ROOT, receipts_v1_manifest()),
            (EVIDENCE_V1_ROOT, evidence_v1_manifest()),
        ] {
            let root = workspace_root().join(root);
            let text = fs::read_to_string(root.join(MANIFEST_FILE_NAME))
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", root.display()));
            assert_eq!(
                text,
                manifest.to_json().unwrap(),
                "the committed manifest must be byte-identical to the generator output"
            );
            let report = verify_manifest_at(&root).unwrap();
            assert!(report.is_clean(), "{:?}", report.mismatches);
        }
    }

    /// Jeder Erzeuger benennt jeden Eintrag und jede Datei genau einmal, und
    /// die Emission ist deterministisch.
    #[test]
    fn the_grant_receipt_and_evidence_generators_are_deterministic() {
        for (family, version, expected, manifest) in [
            (
                GRANTS_FAMILY,
                GRANTS_V1_VERSION,
                14_usize,
                grants_v1_manifest(),
            ),
            (
                RECEIPTS_FAMILY,
                RECEIPTS_V1_VERSION,
                7,
                receipts_v1_manifest(),
            ),
            (
                EVIDENCE_FAMILY,
                EVIDENCE_V1_VERSION,
                8,
                evidence_v1_manifest(),
            ),
        ] {
            assert_eq!(manifest.family, family);
            assert_eq!(manifest.version, version);
            assert_eq!(manifest.entries.len(), expected);
            let names = manifest
                .entries
                .iter()
                .map(|entry| entry.name.clone())
                .collect::<BTreeSet<_>>();
            assert_eq!(names.len(), manifest.entries.len());
            for entry in &manifest.entries {
                assert_eq!(entry.file, format!("{}.bin", entry.name));
            }
        }
        assert_eq!(
            grants_v1_manifest().to_json().unwrap(),
            grants_v1_manifest().to_json().unwrap()
        );
        assert_eq!(
            receipts_v1_manifest().to_json().unwrap(),
            receipts_v1_manifest().to_json().unwrap()
        );
        assert_eq!(
            evidence_v1_manifest().to_json().unwrap(),
            evidence_v1_manifest().to_json().unwrap()
        );
    }

    /// Der PRNG haengt AUSSCHLIESSLICH an Seed und Zaehler.
    #[test]
    fn the_property_rng_depends_only_on_its_seed() {
        let mut first = PropertyRng::new(PROPERTY_CORPUS_SEED);
        let mut second = PropertyRng::new(PROPERTY_CORPUS_SEED);
        assert_eq!(first.bytes(200), second.bytes(200));

        let mut other = PropertyRng::new(PROPERTY_CORPUS_SEED + 1);
        assert_ne!(
            PropertyRng::new(PROPERTY_CORPUS_SEED).bytes(200),
            other.bytes(200)
        );

        // Die Blockgrenze von 32 Byte darf nicht durchschlagen: 200 Byte am
        // Stueck muessen dieselbe Folge sein wie 200 einzelne Ziehungen.
        let mut streamed = PropertyRng::new(PROPERTY_CORPUS_SEED);
        let single = (0..200)
            .map(|_| streamed.array::<1>()[0])
            .collect::<Vec<_>>();
        assert_eq!(single, PropertyRng::new(PROPERTY_CORPUS_SEED).bytes(200));
    }

    /// Der Umfang des Korpus steht in den Konstanten, nicht nur im Erzeuger.
    #[test]
    fn the_property_corpus_matches_its_frozen_scope() {
        assert_eq!(
            PROPERTY_VARIED_FIELDS.len(),
            PROPERTY_CORPUS_FIELD_DELTA_COUNT
        );
        assert_eq!(
            PROPERTY_VARIED_FIELDS.iter().collect::<BTreeSet<_>>().len(),
            PROPERTY_CORPUS_FIELD_DELTA_COUNT,
            "no varied field may appear twice"
        );

        let corpus = property_corpus();
        assert_eq!(corpus.seed, PROPERTY_CORPUS_SEED);
        assert_eq!(corpus.cases.len(), PROPERTY_CORPUS_CASE_COUNT);
        assert_eq!(corpus.chain.len(), PROPERTY_CORPUS_CHAIN_LENGTH);
        assert_eq!(corpus.field_deltas.len(), PROPERTY_CORPUS_FIELD_DELTA_COUNT);
        assert_eq!(corpus.mutations.len(), PROPERTY_CORPUS_MUTATION_COUNT);
        assert_eq!(
            corpus.cross_version.len(),
            PROPERTY_CORPUS_CROSS_VERSION_COUNT
        );

        let names = corpus
            .cases
            .iter()
            .map(|case| case.name.clone())
            .chain(corpus.mutations.iter().map(|entry| entry.name.clone()))
            .chain(corpus.cross_version.iter().map(|case| case.name.clone()))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            names.len(),
            corpus.cases.len() + corpus.mutations.len() + corpus.cross_version.len(),
            "every corpus name is unique"
        );

        assert_eq!(
            sha256_hex(corpus.manifest_json().as_bytes()),
            PROPERTY_CORPUS_MANIFEST_SHA256
        );
        assert_eq!(property_corpus().manifest_json(), corpus.manifest_json());
    }

    /// Schreibt die Vektorfamilie `local-audit/v1` in den Arbeitsbaum.
    ///
    /// `#[ignore]`, weil dieser Test SCHREIBT. Er ist der dokumentierte
    /// Erzeugungslauf und wird ausdruecklich angefordert:
    /// `cargo test -p ea-testkit -- --ignored emit_local_audit_vectors`.
    /// Danach sind die eingecheckten Bytes die Autoritaet.
    #[test]
    #[ignore = "writes into the working tree; run deliberately to regenerate"]
    fn emit_local_audit_vectors() {
        let root = workspace_root().join(LOCAL_AUDIT_V1_ROOT);
        local_audit_v1_manifest().emit(&root).unwrap();
        assert!(verify_manifest_at(&root).unwrap().is_clean());
    }

    /// Das eingecheckte Manifest der Familie ist genau die Ausgabe ihres
    /// Erzeugers.
    ///
    /// Damit haengt der Kodierer an den eingefrorenen Bytes: aenderte
    /// `encode_local_audit_core` eine Position, fiele dieser Test, und die
    /// Bytes muessten bewusst neu erzeugt werden statt still zu veralten.
    #[test]
    fn the_committed_local_audit_family_matches_its_generator() {
        let root = workspace_root().join(LOCAL_AUDIT_V1_ROOT);
        let text = fs::read_to_string(root.join(MANIFEST_FILE_NAME))
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", root.display()));
        assert_eq!(
            text,
            local_audit_v1_manifest().to_json().unwrap(),
            "the committed manifest must be byte-identical to the generator output"
        );
        let report = verify_manifest_at(&root).unwrap();
        assert!(report.is_clean(), "{:?}", report.mismatches);
    }

    /// Schreibt die Vektorfamilie `web-bundle/v1` in den Arbeitsbaum.
    ///
    /// `#[ignore]`, weil dieser Test SCHREIBT. Er ist der dokumentierte
    /// Erzeugungslauf und wird ausdruecklich angefordert:
    /// `cargo test -p ea-testkit -- --ignored emit_web_bundle_v1_vectors`.
    /// Ab dem Einfriercommit sind die eingecheckten Bytes die Autoritaet und
    /// werden NICHT neu erzeugt; eine spaetere Verhaltensaenderung legt
    /// `vectors/web-bundle/v2/` DANEBEN.
    #[test]
    #[ignore = "writes into the working tree; run deliberately to regenerate"]
    fn emit_web_bundle_v1_vectors() {
        let root = workspace_root().join(WEB_BUNDLE_V1_ROOT);
        web_bundle_v1_manifest().emit(&root).unwrap();
        assert!(verify_manifest_at(&root).unwrap().is_clean());
    }

    /// Das eingecheckte Manifest der Bundle-Familie ist genau die Ausgabe
    /// ihres Erzeugers.
    #[test]
    fn the_committed_web_bundle_v1_family_matches_its_generator() {
        let root = workspace_root().join(WEB_BUNDLE_V1_ROOT);
        let text = fs::read_to_string(root.join(MANIFEST_FILE_NAME))
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", root.display()));
        assert_eq!(
            text,
            web_bundle_v1_manifest().to_json().unwrap(),
            "the committed manifest must be byte-identical to the generator output"
        );
        let report = verify_manifest_at(&root).unwrap();
        assert!(report.is_clean(), "{:?}", report.mismatches);
    }

    /// Der Erzeuger der Bundle-Familie benennt jeden Eintrag und jede Datei
    /// genau einmal, ist deterministisch und haelt die Vektorhygiene ein.
    ///
    /// Die Hygiene ist der Grund fuer die eigene Familie: kein Eintragsname
    /// und kein Notizfeld traegt das Subtype-Literal, es steht ausschliesslich
    /// in den hexkodierten Objektbytes.
    #[test]
    fn the_web_bundle_generator_keeps_its_names_free_of_the_subtype_literal() {
        let manifest = web_bundle_v1_manifest();
        assert_eq!(manifest.family, WEB_BUNDLE_FAMILY);
        assert_eq!(manifest.version, WEB_BUNDLE_V1_VERSION);
        assert_eq!(manifest.entries.len(), 6);
        let names = manifest
            .entries
            .iter()
            .map(|entry| entry.name.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(names.len(), manifest.entries.len());
        let accepted = manifest
            .entries
            .iter()
            .filter(|entry| entry.expected_outcome == ExpectedOutcome::Accepted)
            .count();
        assert_eq!(accepted, 2, "one accepted vector per subtype of the family");
        assert_eq!(manifest.entries.len() - accepted, 4);
        for entry in &manifest.entries {
            assert_eq!(entry.file, format!("{}.bin", entry.name));
            assert_eq!(entry.schema_id, WEB_BUNDLE_SCHEMA_ID);
            assert_eq!(entry.suite_id, WEB_BUNDLE_SUITE_ID);
            assert!(entry.scope_note.is_none(), "{} needs no note", entry.name);
            assert!(
                entry.name.chars().all(|value| value.is_ascii_lowercase()
                    || value.is_ascii_digit()
                    || value == '-'
                    || value == '/'),
                "{} must stay kebab-case",
                entry.name
            );
        }
        assert!(
            !manifest.to_json().unwrap().contains("webBundle"),
            "the subtype literals live in the hex recorded object bytes only"
        );
        assert_eq!(
            web_bundle_v1_manifest().to_json().unwrap(),
            web_bundle_v1_manifest().to_json().unwrap()
        );
    }

    /// Der Erzeuger benennt jeden Eintrag und jede Datei genau einmal, deckt
    /// alle zwoelf Aktionen ab und ist deterministisch.
    #[test]
    fn the_local_audit_generator_is_deterministic() {
        let manifest = local_audit_v1_manifest();
        assert_eq!(manifest.family, LOCAL_AUDIT_FAMILY);
        assert_eq!(manifest.version, LOCAL_AUDIT_V1_VERSION);
        assert_eq!(manifest.entries.len(), 17);
        let names = manifest
            .entries
            .iter()
            .map(|entry| entry.name.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(names.len(), manifest.entries.len());
        let accepted = manifest
            .entries
            .iter()
            .filter(|entry| entry.expected_outcome == ExpectedOutcome::Accepted)
            .count();
        assert_eq!(
            accepted, 12,
            "one accepted vector per action of local-audit-action-v1"
        );
        assert_eq!(manifest.entries.len() - accepted, 5);
        for entry in &manifest.entries {
            assert_eq!(entry.file, format!("{}.bin", entry.name));
            assert_eq!(entry.schema_id, LOCAL_AUDIT_SCHEMA_ID);
            assert_eq!(entry.suite_id, LOCAL_AUDIT_SUITE_ID);
            assert!(
                entry.intermediate_digests.is_empty(),
                "a local audit signature covers the core itself, so there is no \
                 intermediate value to name"
            );
        }
        assert_eq!(
            local_audit_v1_manifest().to_json().unwrap(),
            local_audit_v1_manifest().to_json().unwrap()
        );
    }
}
