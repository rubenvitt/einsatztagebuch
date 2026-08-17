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
    CanonicalPublicCoseKey, ContentType, CoseSigner, ProtectedHeader, SecretBytes, SecretVec,
    aead_seal, authorized_trust_digest, bootstrap_anchor_hash, grant_digest, object_hash,
    payload_aad, receipt_digest, record_digest, trust_anchor_hash, trust_digest,
};
use ea_format::{
    CertificateKindV1, CheckpointCoreFieldsV1, CheckpointCoreV1, DestroyedEntryStubV1,
    DeviceCertificateFieldsV1, EntryPackageV1, EvidenceObjectV1, FreeTextPolicyFieldsV1,
    GrantBodyFieldsV1, GrantBodyV1, GrantKindV1, GrantPurposeV1, GrantV1, KeyProtectionProfileV1,
    ManifestCoreFieldsV1, ManifestCoreV1, OperatorBindingFieldsV1, OperatorRoleV1,
    OrganizationAdminAuthorizationFieldsV1, PolicyFieldsV1, ReceiptCoreFieldsV1, ReceiptCoreV1,
    ReceiptV1, RegistryChangeV1, RegistryEventFieldsV1, RetentionPolicyFieldsV1,
    RootCertificateFieldsV1, SignedManifestV1, TrustObjectV1, TrustPayloadV1, TrustSubtypeV1,
    encode_destroyed_entry_stub, encode_entry_package, encode_evidence, encode_grant,
    encode_receipt, encode_trust,
};
use ea_types::{
    AuthorizationId, CertificateHash, ChainId, ChainSequence, DestructionId, DeviceId, Hash32,
    KeyThumbprint, ObjectHash, OperatorSubjectId, OrganizationId, RegistryVersion, SubjectId,
    UnixMillis,
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

/// SHA-256 ueber `bytes`, hexadezimal in Kleinbuchstaben.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
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

/// Die 20 Domain-Trennungszeichenketten von `crates/ea-crypto`.
///
/// Abgeleitet aus dem Quelltext, nicht aus dem Gedaechtnis:
/// `crates/ea-crypto/src/digest.rs` fuehrt vierzehn Hashdomaenen und drei
/// Praefixfunktionen, `os_account.rs` eine Bindungsdomaene und `cose.rs` die
/// beiden Typzeichenketten der signierten Protokollkerne.
/// `tests/ea-system-tests/tests/conformance_golden_vectors.rs` sucht den
/// Quelltext erneut ab und faellt, sobald dort eine Zeichenkette ohne Vektor
/// steht.
const CRYPTO_DOMAIN_STRINGS: [&str; 20] = [
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

/// Die domaingetrennten Digestfunktionen mit ihrer Domaene.
const CRYPTO_DOMAIN_DIGESTS: [(&str, &str); 12] = [
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

    VectorManifest {
        family: TRUST_FAMILY.to_owned(),
        version: TRUST_V1_VERSION.to_owned(),
        entries,
    }
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
    let scope_note = (schema_id == TRUST_OBJECT_SCHEMA_ID
        && trust_body_subtype(&object_bytes) == TRUST_ADMIN_AUTHORIZATION_SUBTYPE)
        .then(|| TRUST_ADMIN_AUTHORIZATION_SCOPE_NOTE.to_owned());
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

    /// Der Erzeuger liefert 66 verschiedene Eintraege, und jeder Dateipfad
    /// liegt unter der Familienwurzel.
    #[test]
    fn the_crypto_generator_names_every_entry_and_file_exactly_once() {
        let manifest = crypto_suite_one_manifest();
        assert_eq!(manifest.entries.len(), 66);
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
                assert!(entry.scope_note.is_none(), "{} needs no note", entry.name);
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
}
