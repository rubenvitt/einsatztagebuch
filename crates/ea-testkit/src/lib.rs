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
