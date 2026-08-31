//! Die Bruecke nach JavaScript: der Laufzeitzeuge und der Bytespeicher-Zugang.
//!
//! # Warum jede Ausfuhr JSON herausgibt
//!
//! TypeScript bekommt Ansichts- und Status-DTOs und nie ein Rechenobjekt. Ein
//! strukturierter Rueckgabewert waere ein zweiter, handgeschriebener Vertrag
//! neben `apps/web/src/bridge/generated-contracts.ts`, und genau den verbietet
//! `no-hand-written-contracts.test.ts`.
//!
//! # Woher die Erwartungswerte stammen
//!
//! Der Laufzeitzeuge ist die AUS dem Spike gehobene Fassung von
//! `spikes/wasm-runtime-proof/src/lib.rs::runtime_proof_json`. Die
//! Erwartungswerte sind NICHT neu hergeleitet: sie stammen aus
//! `vectors/crypto/suite-1/manifest.json` und aus den Konstanten von
//! `ea-testkit`, die der native Test
//! `tests/ea-system-tests/tests/conformance_golden_vectors.rs` (`check_hpke`,
//! `check_ed25519`) benutzt. `ea-testkit` wird hier KEIN Abhaengiger: es steht
//! wegen seiner `std::fs`-Vektorausgabe in `WASM32_EXEMPT_CRATES`, und eine
//! Kante dorthin naehme `crates/ea-reader-wasm` die Positivliste. Die
//! Konstanten stehen deshalb woertlich mit Fundstellenangabe unten, genau wie
//! im Spike.
//!
//! # Die Vektoren sind einkompiliert
//!
//! `include_bytes!` statt `std::fs`: das wasm-Modul hat kein Dateisystem, und
//! ein Zeuge, der seine Eingabe erst zur Laufzeit sucht, belegt im Browser
//! nichts.

use ea_crypto::{
    CanonicalPublicCoseKey, CryptoError, HPKE_ENCAPSULATED_KEY_SIZE, HPKE_WRAPPED_CEK_SIZE,
    HpkeRecipientPrivateKey, HpkeSealed, SecretBytes, hpke_open, hpke_seal,
};
use sha2::{Digest, Sha256};

// Nur der Browserpfad braucht die Bruecken- und Speichertypen. Die `use`-Zeile
// traegt ihr eigenes cfg: auf einem Wirtsziel waere sie unbenutzt, und
// `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
// faellt an einer unbenutzten Einfuhr genauso wie an einem echten Fehler.
#[cfg(target_arch = "wasm32")]
use ea_reader::{ReaderBlobError, ReaderBlobKey, ReaderBlobStore};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
use crate::opfs_worker::OpfsBlobStore;

// ---------------------------------------------------------------------------
// Eingefrorene Vektoren, per include_bytes! einkompiliert.
// ---------------------------------------------------------------------------

/// `vectors/crypto/suite-1/hpke/base-mode-wrapped-cek.bin`
/// 80 B = enc[0..32) ‖ wrapped_cek[32..80) (32 B Chiffrat + 16 B Poly1305-Tag).
const HPKE_SEALED_VECTOR: &[u8; 80] =
    include_bytes!("../../../vectors/crypto/suite-1/hpke/base-mode-wrapped-cek.bin");

/// Dieselben 80 B, Byte 0 mit 0x01 verodert. Manifest: `EA-CRYPTO-HPKE-OPEN`.
const HPKE_FLIPPED_ENCAPSULATED: &[u8; 80] =
    include_bytes!("../../../vectors/crypto/suite-1/hpke/flipped-encapsulated-key.bin");

/// Dieselben 80 B, Byte 32 mit 0x01 verodert. Manifest: `EA-CRYPTO-HPKE-OPEN`.
const HPKE_FLIPPED_WRAPPED: &[u8; 80] =
    include_bytes!("../../../vectors/crypto/suite-1/hpke/flipped-wrapped-cek.bin");

/// `vectors/crypto/suite-1/hpke/rfc7748-recipient-public-key.bin` (RFC 7748 §6.1, Bob).
const RFC7748_BOB_PUBLIC_KEY: &[u8; 32] =
    include_bytes!("../../../vectors/crypto/suite-1/hpke/rfc7748-recipient-public-key.bin");

/// `info` und `aad` liegen als eigene eingefrorene Vektoren vor; ihr SHA-256 ist
/// genau das, was das Manifest als `infoDigest`/`aadDigest` fuehrt.
const HPKE_INFO: &[u8; 46] =
    include_bytes!("../../../vectors/crypto/suite-1/domain-context/hpke-info.bin");
const HPKE_AAD: &[u8; 45] =
    include_bytes!("../../../vectors/crypto/suite-1/domain-context/hpke-aad.bin");

/// `vectors/crypto/suite-1/ed25519/rfc8032-test1.bin` — 64 B Signatur R‖S ueber
/// die LEERE Nachricht (Manifest `inputBytes` = "").
const ED25519_SIGNATURE_VECTOR: &[u8; 64] =
    include_bytes!("../../../vectors/crypto/suite-1/ed25519/rfc8032-test1.bin");

/// Dieselbe Signatur, Byte 0 verfaelscht. Manifest: `EA-TRUST-SIGNATURE-INVALID`.
const ED25519_FLIPPED_SIGNATURE_VECTOR: &[u8; 64] =
    include_bytes!("../../../vectors/crypto/suite-1/ed25519/flipped-signature.bin");

// ---------------------------------------------------------------------------
// Werte, die NICHT in den .bin-Dateien stehen (sie tragen nur `objectBytes`).
// ---------------------------------------------------------------------------

/// `ea_testkit::TEST_ENTROPY_RECIPIENT_X25519_SEED` (`crates/ea-testkit/src/lib.rs:203`).
/// Empfaenger der eingefrorenen Kapselung — NICHT der RFC-7748-Schluessel.
const RECIPIENT_X25519_SEED: [u8; 32] = [0xb0; 32];

/// `ea_testkit::TEST_ENTROPY_CONTENT_ENCRYPTION_KEY` (`crates/ea-testkit/src/lib.rs:206`).
/// Identisch mit `inputBytes` von `hpke/base-mode-wrapped-cek` im Manifest.
const EXPECTED_CONTENT_ENCRYPTION_KEY: [u8; 32] = [0xc0; 32];

/// `inputBytes` von `hpke/rfc7748-recipient-public-key` (RFC 7748 §6.1, Bobs
/// privater Schluessel).
const RFC7748_BOB_PRIVATE_KEY: [u8; 32] = [
    0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
    0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
];

/// `ea_testkit::ED25519_RFC8032_TEST1_PUBLIC_KEY` (`crates/ea-testkit/src/lib.rs:127`).
///
/// Der Systemtest LEITET diesen Schluessel aus dem Seed ab; hier steht er als
/// Konstante, damit kein `ed25519_dalek::SigningKey` in den Browserpfad
/// geraet — der Reader signiert nie.
const ED25519_PUBLIC_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

/// RFC 8032 §7.1 TEST 1 signiert die LEERE Nachricht.
const ED25519_MESSAGE: &[u8] = b"";

// Erwartungswerte aus vectors/crypto/suite-1/manifest.json, woertlich.
const MANIFEST_INFO_DIGEST: &str =
    "dc2a276919943d010ad7e804a655f596458a7d16a8ede594ff2bc0a7258a3a67";
const MANIFEST_AAD_DIGEST: &str =
    "485e08ef1cbfa06e20c9df779fdf67e3f9a2d59e8b73556e563d11a25bcad68d";
const MANIFEST_RECIPIENT_PUBLIC_KEY_THUMBPRINT: &str =
    "923bd3c45f6ea86fb4667bc0108740cf6701c11306e131f59750ffdd95b74e8b";
const MANIFEST_SIGNER_THUMBPRINT: &str =
    "866eefbd6718c8846cd7ddfe43fc74ab1daac4538ff8514ea2ec2d410a415743";
const MANIFEST_HPKE_FILE_SHA256: &str =
    "35db387d02afca4c46b2ae77cfce83702ed52d2b5f61d65aef9ea794b814f1ea";
const MANIFEST_ED25519_FILE_SHA256: &str =
    "a99e560bf0a0bbf8566a5a13200f1348301b6f691644d95b8ea276ae34c429e6";

// ---------------------------------------------------------------------------
// Minimaler JSON-Bauer. Kein serde: zwischen der Bruecke und `ea-crypto` soll
// so wenig Graph wie moeglich liegen.
// ---------------------------------------------------------------------------

struct Json(String);

impl Json {
    fn object() -> Self {
        Self(String::from("{"))
    }

    fn comma(&mut self) {
        if !self.0.ends_with('{') {
            self.0.push(',');
        }
    }

    fn string(&mut self, key: &str, value: &str) -> &mut Self {
        self.comma();
        self.0.push_str(&format!("\"{key}\":\"{value}\""));
        self
    }

    fn bool(&mut self, key: &str, value: bool) -> &mut Self {
        self.comma();
        self.0.push_str(&format!("\"{key}\":{value}"));
        self
    }

    fn number(&mut self, key: &str, value: usize) -> &mut Self {
        self.comma();
        self.0.push_str(&format!("\"{key}\":{value}"));
        self
    }

    fn raw(&mut self, key: &str, value: &str) -> &mut Self {
        self.comma();
        self.0.push_str(&format!("\"{key}\":{value}"));
        self
    }

    fn finish(mut self) -> String {
        self.0.push('}');
        self.0
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

// ---------------------------------------------------------------------------
// Element 2: getrandom/wasm_js in einer echten JS-Umgebung.
// ---------------------------------------------------------------------------

/// Zieht zweimal 32 Byte ueber `getrandom::fill` und laesst zusaetzlich
/// `ea_crypto::hpke_seal` frische Entropie ziehen (das ist der EINZIGE
/// RNG-Aufruf in ea-crypto, `crates/ea-crypto/src/hpke.rs:32`), dann wird das
/// Ergebnis wieder geoeffnet. Ein stumpfes Nullraum-RNG faellt hier auf.
fn prove_getrandom() -> Result<String, String> {
    let mut first = [0_u8; 32];
    let mut second = [0_u8; 32];
    getrandom::fill(&mut first).map_err(|error| format!("getrandom::fill failed: {error}"))?;
    getrandom::fill(&mut second).map_err(|error| format!("getrandom::fill failed: {error}"))?;

    if first == second {
        return Err("two successive getrandom draws were identical".to_owned());
    }
    if first == [0_u8; 32] || second == [0_u8; 32] {
        return Err("a getrandom draw was all zero".to_owned());
    }

    let mut seen = [false; 256];
    for byte in first.iter().chain(second.iter()) {
        seen[usize::from(*byte)] = true;
    }
    let distinct = seen.iter().filter(|value| **value).count();

    // Eine grosse Ziehung deckt den 65536-Byte-Chunker von
    // getrandom-0.4.3/src/backends/wasm_js.rs:19-23 mit ab.
    let mut large = vec![0_u8; 100_000];
    getrandom::fill(&mut large)
        .map_err(|error| format!("getrandom::fill(100000) failed: {error}"))?;
    let large_all_zero = large.iter().all(|byte| *byte == 0);
    if large_all_zero {
        return Err("a 100000-byte getrandom draw was all zero".to_owned());
    }

    // Ein echter hpke_seal-Aufruf: er zieht die ephemere KEM-Entropie aus
    // getrandom und ist damit der Beweis, dass ea-crypto selbst RNG bekommt.
    let recipient = HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(RECIPIENT_X25519_SEED))
        .map_err(|error| format!("recipient key: {}", error.code()))?;
    let cek = SecretBytes::new(EXPECTED_CONTENT_ENCRYPTION_KEY);
    let sealed_a = hpke_seal(&recipient.public_key(), &cek, HPKE_INFO, HPKE_AAD)
        .map_err(|error| format!("hpke_seal: {}", error.code()))?;
    let sealed_b = hpke_seal(&recipient.public_key(), &cek, HPKE_INFO, HPKE_AAD)
        .map_err(|error| format!("hpke_seal: {}", error.code()))?;
    if sealed_a.encapsulated_key() == sealed_b.encapsulated_key() {
        return Err("two hpke_seal calls produced the same ephemeral key".to_owned());
    }
    let reopened = hpke_open(&recipient, &sealed_a, HPKE_INFO, HPKE_AAD)
        .map_err(|error| format!("hpke_open of the fresh seal: {}", error.code()))?;
    if !reopened.matches(&EXPECTED_CONTENT_ENCRYPTION_KEY) {
        return Err("the freshly sealed CEK did not survive the roundtrip".to_owned());
    }

    let mut json = Json::object();
    json.string("backend", "getrandom 0.4.3 / feature wasm_js")
        .string("draw1", &hex::encode(first))
        .string("draw2", &hex::encode(second))
        .bool("draw1DiffersFromDraw2", true)
        .bool("neitherDrawWasAllZero", true)
        .number("distinctByteValuesAcross64Bytes", distinct)
        .number("largeDrawLength", large.len())
        .bool("largeDrawWasNotAllZero", true)
        .string(
            "freshSealEncapsulatedKeyA",
            &hex::encode(sealed_a.encapsulated_key()),
        )
        .string(
            "freshSealEncapsulatedKeyB",
            &hex::encode(sealed_b.encapsulated_key()),
        )
        .bool("freshSealsUsedDistinctEphemeralKeys", true)
        .bool("freshSealOpenRoundtripRecoveredTheCek", true);
    Ok(json.finish())
}

// ---------------------------------------------------------------------------
// Element 3: HPKE-Entkapselung gegen den eingefrorenen Vektor.
// ---------------------------------------------------------------------------

/// Zerlegt die 80 eingefrorenen Byte genau so, wie `hpke_sealed` es im nativen
/// Test tut (`conformance_golden_vectors.rs`).
fn sealed_from(bytes: &[u8; 80]) -> Result<HpkeSealed, CryptoError> {
    let (encapsulated, wrapped) = bytes.split_at(HPKE_ENCAPSULATED_KEY_SIZE);
    debug_assert_eq!(wrapped.len(), HPKE_WRAPPED_CEK_SIZE);
    HpkeSealed::from_parts(
        encapsulated
            .try_into()
            .expect("the encapsulated key is 32 bytes"),
        wrapped.try_into().expect("the wrapped key is 48 bytes"),
    )
}

fn prove_hpke() -> Result<String, String> {
    // Datei-Identitaet: die einkompilierten Bytes sind die des Manifests.
    let sealed_file_sha256 = sha256_hex(HPKE_SEALED_VECTOR);
    if sealed_file_sha256 != MANIFEST_HPKE_FILE_SHA256 {
        return Err(format!(
            "base-mode-wrapped-cek.bin hashes to {sealed_file_sha256}, manifest says {MANIFEST_HPKE_FILE_SHA256}"
        ));
    }
    let info_digest = sha256_hex(HPKE_INFO);
    if info_digest != MANIFEST_INFO_DIGEST {
        return Err(format!("infoDigest mismatch: {info_digest}"));
    }
    let aad_digest = sha256_hex(HPKE_AAD);
    if aad_digest != MANIFEST_AAD_DIGEST {
        return Err(format!("aadDigest mismatch: {aad_digest}"));
    }

    // RFC 7748 §6.1: der KEM leitet den veroeffentlichten Public Key ab.
    let bob = HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(RFC7748_BOB_PRIVATE_KEY))
        .map_err(|error| format!("RFC 7748 private key: {}", error.code()))?;
    if bob.public_key().as_bytes() != RFC7748_BOB_PUBLIC_KEY {
        return Err("the KEM did not derive the published RFC 7748 public key".to_owned());
    }

    let recipient = HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(RECIPIENT_X25519_SEED))
        .map_err(|error| format!("recipient key: {}", error.code()))?;

    let recipient_thumbprint = hex::encode(
        CanonicalPublicCoseKey::x25519(*recipient.public_key().as_bytes())
            .map_err(|error| format!("recipient COSE key: {}", error.code()))?
            .thumbprint()
            .as_bytes(),
    );
    if recipient_thumbprint != MANIFEST_RECIPIENT_PUBLIC_KEY_THUMBPRINT {
        return Err(format!(
            "recipientPublicKeyThumbprint mismatch: {recipient_thumbprint}"
        ));
    }

    // DIE Entkapselung.
    let sealed = sealed_from(HPKE_SEALED_VECTOR)
        .map_err(|error| format!("the frozen encapsulation must parse: {}", error.code()))?;
    let opened = hpke_open(&recipient, &sealed, HPKE_INFO, HPKE_AAD)
        .map_err(|error| format!("the frozen encapsulation must open: {}", error.code()))?;
    if !opened.matches(&EXPECTED_CONTENT_ENCRYPTION_KEY) {
        return Err("hpke_open returned a different content encryption key".to_owned());
    }
    // Die Klammer ist KEIN Ueberfluss: `with_exposed` nimmt eine
    // hoehergestufte Lebenszeit, und `hex::encode` direkt als Funktionswert
    // uebersetzt daran nicht (gemessen, `spikes/wasm-runtime-proof/README.md`
    // Abschnitt c).
    let recovered = opened.with_exposed(|bytes| hex::encode(bytes));

    // Negativfaelle: je ein gekipptes Byte.
    let mut negatives = String::from("{");
    for (label, vector) in [
        ("flippedEncapsulatedKey", HPKE_FLIPPED_ENCAPSULATED),
        ("flippedWrappedCek", HPKE_FLIPPED_WRAPPED),
    ] {
        let differing = vector
            .iter()
            .zip(HPKE_SEALED_VECTOR.iter())
            .filter(|(left, right)| left != right)
            .count();
        if differing != 1 {
            return Err(format!(
                "{label} must differ in exactly one byte, not {differing}"
            ));
        }
        let broken =
            sealed_from(vector).map_err(|error| format!("{label} must parse: {}", error.code()))?;
        match hpke_open(&recipient, &broken, HPKE_INFO, HPKE_AAD) {
            Ok(_) => return Err(format!("{label} MUST NOT open, but it did")),
            Err(error) => {
                if error.code() != "EA-CRYPTO-HPKE-OPEN" {
                    return Err(format!("{label} rejected with {}", error.code()));
                }
                if !negatives.ends_with('{') {
                    negatives.push(',');
                }
                negatives.push_str(&format!("\"{label}\":\"{}\"", error.code()));
            }
        }
    }
    negatives.push('}');

    let mut json = Json::object();
    json.string(
        "vectorFile",
        "vectors/crypto/suite-1/hpke/base-mode-wrapped-cek.bin",
    )
    .string("vectorSha256", &sealed_file_sha256)
    .string("suiteId", "EINSATZARCHIV-HPKE-1")
    .string("encapsulatedKey", &hex::encode(sealed.encapsulated_key()))
    .string("wrappedCek", &hex::encode(sealed.wrapped_cek()))
    .string("infoDigest", &info_digest)
    .string("aadDigest", &aad_digest)
    .string("recipientPublicKeyThumbprint", &recipient_thumbprint)
    .string(
        "rfc7748DerivedPublicKey",
        &hex::encode(bob.public_key().as_bytes()),
    )
    .string("recoveredContentEncryptionKey", &recovered)
    .raw("rejectedTamperedVectors", &negatives);
    Ok(json.finish())
}

// ---------------------------------------------------------------------------
// Element 4: Ed25519-Signaturpruefung, positiv UND negativ.
// ---------------------------------------------------------------------------

fn prove_ed25519() -> Result<String, String> {
    let file_sha256 = sha256_hex(ED25519_SIGNATURE_VECTOR);
    if file_sha256 != MANIFEST_ED25519_FILE_SHA256 {
        return Err(format!(
            "rfc8032-test1.bin hashes to {file_sha256}, manifest says {MANIFEST_ED25519_FILE_SHA256}"
        ));
    }

    let key = CanonicalPublicCoseKey::ed25519(ED25519_PUBLIC_KEY)
        .map_err(|error| format!("the RFC 8032 public key must load: {}", error.code()))?;

    let signer_thumbprint = hex::encode(key.thumbprint().as_bytes());
    if signer_thumbprint != MANIFEST_SIGNER_THUMBPRINT {
        return Err(format!("signerThumbprint mismatch: {signer_thumbprint}"));
    }

    key.verify_ed25519_strict(ED25519_MESSAGE, ED25519_SIGNATURE_VECTOR)
        .map_err(|error| format!("RFC 8032 §7.1 TEST 1 must verify: {}", error.code()))?;

    let differing = ED25519_FLIPPED_SIGNATURE_VECTOR
        .iter()
        .zip(ED25519_SIGNATURE_VECTOR.iter())
        .filter(|(left, right)| left != right)
        .count();
    if differing != 1 {
        return Err(format!(
            "flipped-signature.bin must differ in exactly one byte, not {differing}"
        ));
    }

    let rejection =
        match key.verify_ed25519_strict(ED25519_MESSAGE, ED25519_FLIPPED_SIGNATURE_VECTOR) {
            Ok(()) => return Err("the tampered signature MUST NOT verify, but it did".to_owned()),
            Err(error) => error.code(),
        };
    if rejection != "EA-TRUST-SIGNATURE-INVALID" {
        return Err(format!(
            "the tampered signature was rejected with {rejection}"
        ));
    }

    let mut json = Json::object();
    json.string(
        "vectorFile",
        "vectors/crypto/suite-1/ed25519/rfc8032-test1.bin",
    )
    .string("vectorSha256", &file_sha256)
    .string("suiteId", "EINSATZARCHIV-SUITE-1")
    .string("standard", "RFC 8032 §7.1 TEST 1")
    .string("publicKey", &hex::encode(ED25519_PUBLIC_KEY))
    .string("message", &hex::encode(ED25519_MESSAGE))
    .string("signature", &hex::encode(ED25519_SIGNATURE_VECTOR))
    .string("signerThumbprint", &signer_thumbprint)
    .bool("acceptedValidSignature", true)
    .string(
        "tamperedVectorFile",
        "vectors/crypto/suite-1/ed25519/flipped-signature.bin",
    )
    .string(
        "tamperedSignature",
        &hex::encode(ED25519_FLIPPED_SIGNATURE_VECTOR),
    )
    .bool("rejectedTamperedSignature", true)
    .string("tamperedRejectionCode", rejection);
    Ok(json.finish())
}

// ---------------------------------------------------------------------------
// Gesamtergebnis.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
const TARGET_TRIPLE: &str = "wasm32-unknown-unknown";
#[cfg(not(target_arch = "wasm32"))]
const TARGET_TRIPLE: &str = "native";

/// Die Rechnung des Laufzeitzeugen, auf JEDEM Ziel uebersetzbar.
///
/// Der Bericht ist IMMER wohlgeformtes JSON; ein Fehlschlag steht als
/// `"ok": false` samt `"errors"` darin, damit der Aufrufer ihn ausgeben kann,
/// statt an einem Trap zu ersticken. `"targetTriple"` sagt, WO gerechnet wurde
/// — `apps/web/src/bridge/wasm-runtime.test.ts` prueft als erstes, dass dort
/// `wasm32-unknown-unknown` und nicht `native` steht.
#[must_use]
pub fn runtime_witness_json() -> String {
    let mut json = Json::object();
    json.string("spec", "web-reader-design.md §14.1")
        .string("targetTriple", TARGET_TRIPLE);

    let mut ok = true;
    let mut failures: Vec<String> = Vec::new();

    match prove_getrandom() {
        Ok(value) => {
            json.raw("getrandom", &value);
        }
        Err(error) => {
            ok = false;
            failures.push(format!("getrandom: {error}"));
            json.raw("getrandom", "null");
        }
    }
    match prove_hpke() {
        Ok(value) => {
            json.raw("hpke", &value);
        }
        Err(error) => {
            ok = false;
            failures.push(format!("hpke: {error}"));
            json.raw("hpke", "null");
        }
    }
    match prove_ed25519() {
        Ok(value) => {
            json.raw("ed25519", &value);
        }
        Err(error) => {
            ok = false;
            failures.push(format!("ed25519: {error}"));
            json.raw("ed25519", "null");
        }
    }

    json.bool("ok", ok);
    json.string("errors", &failures.join(" | "));
    json.finish()
}

// ---------------------------------------------------------------------------
// Die Ausfuhren. JEDE traegt ihr eigenes `#[cfg(target_arch = "wasm32")]`
// unmittelbar ueber dem Attribut — `every_wasm_bindgen_export_sits_behind_the
// _wasm32_cfg` liest das als Text und folgt keinem `mod`.
// ---------------------------------------------------------------------------

/// Der Name des OPFS-Verzeichnisses, unter dem die Bruecke ihre Blobs ablegt.
///
/// Ein fester Name und kein Argument: der Aufrufer ist der Worker-Einstieg
/// `apps/web/src/bridge/opfs-worker.ts`, und der soll zustellen, nicht
/// entscheiden.
#[cfg(target_arch = "wasm32")]
const BRIDGE_BLOB_DIRECTORY: &str = "ea-reader";

/// Uebersetzt einen Speicherfehler in einen JS-Wert, der NUR den Code traegt.
///
/// Der Text einer Wirtsmeldung kann einen Schluessel und damit einen
/// Ablagepfad nennen; ueber die Bruecke geht deshalb der stabile Code und
/// sonst nichts — dieselbe Regel, die `ReaderBlobError::code` aufschreibt.
#[cfg(target_arch = "wasm32")]
fn blob_failure(error: &ReaderBlobError) -> JsValue {
    JsValue::from_str(error.code())
}

/// Der Laufzeitzeuge nach `web-reader-design.md` §14.1, als JSON-Bericht.
///
/// Er ist die AUS dem Spike gehobene Fassung von
/// `spikes/wasm-runtime-proof/src/lib.rs::runtime_proof_json` und rechnet
/// unveraendert mit `ea_crypto::hpke_open` gegen
/// `vectors/crypto/suite-1/hpke/base-mode-wrapped-cek.bin` und mit
/// `CanonicalPublicCoseKey::verify_ed25519_strict` gegen
/// `vectors/crypto/suite-1/ed25519/rfc8032-test1.bin`. Die Vektoren sind per
/// `include_bytes!` einkompiliert: das Modul braucht kein Dateisystem.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerRuntimeWitness")]
#[must_use]
pub fn reader_runtime_witness() -> String {
    runtime_witness_json()
}

/// Legt einen OPAKEN Blob ab. Wird ausschliesslich aus dem Worker gerufen.
///
/// # Errors
/// Der stabile Code des Fehlschlags als JS-Zeichenkette: `EA-READER-BLOB-KEY`
/// fuer einen abgewiesenen Schluessel, `EA-READER-BLOB-HOST` fuer jeden
/// Fehlschlag des Wirtspeichers.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "blobPut")]
pub fn blob_put(key: &str, bytes: &[u8]) -> Result<(), JsValue> {
    let key = ReaderBlobKey::new(key).map_err(|error| blob_failure(&error))?;
    let mut store =
        OpfsBlobStore::open(BRIDGE_BLOB_DIRECTORY).map_err(|error| blob_failure(&error))?;
    store.put(&key, bytes).map_err(|error| blob_failure(&error))
}

/// Holt einen OPAKEN Blob. Ein fehlender Blob ist `undefined` und kein Fehler.
///
/// # Errors
/// Wie [`blob_put`].
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "blobGet")]
pub fn blob_get(key: &str) -> Result<Option<Box<[u8]>>, JsValue> {
    let key = ReaderBlobKey::new(key).map_err(|error| blob_failure(&error))?;
    let store = OpfsBlobStore::open(BRIDGE_BLOB_DIRECTORY).map_err(|error| blob_failure(&error))?;
    let found = store.get(&key).map_err(|error| blob_failure(&error))?;
    Ok(found.map(Vec::into_boxed_slice))
}
