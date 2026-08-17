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

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::{Component, Path, PathBuf},
};

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
pub const DECLARED_TEST_ENTROPY: [(&str, &[u8]); 6] = [
    ("root-ed25519-seed", &TEST_ENTROPY_ROOT_ED25519_SEED),
    (
        "organization-admin-ed25519-seed",
        &TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED,
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
}
