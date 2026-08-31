// Node-Treiber fuer den Laufzeitnachweis nach web-reader-design.md 14.1.
//
// Laedt die von `wasm-bindgen --target nodejs` erzeugte CommonJS-Glue, ruft den
// wasm-bindgen-Export auf und prueft JEDEN erwarteten Wert. Jede Abweichung
// beendet den Prozess mit != 0.

import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const pkgPath = path.resolve(here, "..", "pkg", "ea_wasm_runtime_proof.js");
const require = createRequire(import.meta.url);

const failures = [];
function check(name, condition, detail) {
  if (condition) {
    console.log(`  ok   ${name}`);
  } else {
    console.log(`  FAIL ${name}${detail ? ` -- ${detail}` : ""}`);
    failures.push(name);
  }
}

// --- Umgebung: das ist die Voraussetzung fuer getrandom/wasm_js -------------
console.log(`node ${process.version} on ${process.platform}/${process.arch}`);
check(
  "globalThis.crypto.getRandomValues is present (getrandom/wasm_js binds to it)",
  typeof globalThis.crypto?.getRandomValues === "function",
);

// --- Element 1: die wasm-bindgen-Schicht laedt und ruft ---------------------
const wasm = require(pkgPath);
check("wasm-bindgen glue exports run_runtime_proof", typeof wasm.run_runtime_proof === "function");
check("wasm-bindgen glue exports echo_from_js", typeof wasm.echo_from_js === "function");

const echoed = wasm.echo_from_js("hello from node");
check(
  "a string argument crosses the wasm-bindgen bridge in both directions",
  echoed === "wasm received: hello from node",
  `got ${JSON.stringify(echoed)}`,
);

const raw = wasm.run_runtime_proof();
check("run_runtime_proof returned a string", typeof raw === "string");
const report = JSON.parse(raw);
check("the wasm side reported ok", report.ok === true, report.errors);
check("the wasm module ran on wasm32-unknown-unknown", report.targetTriple === "wasm32-unknown-unknown");

// --- Element 2: getrandom ---------------------------------------------------
const g = report.getrandom ?? {};
check("getrandom: two 32-byte draws returned", /^[0-9a-f]{64}$/.test(g.draw1 ?? "") && /^[0-9a-f]{64}$/.test(g.draw2 ?? ""));
check("getrandom: the two draws differ", g.draw1 !== g.draw2);
check("getrandom: draw1 is not all zero", g.draw1 !== "0".repeat(64));
check("getrandom: draw2 is not all zero", g.draw2 !== "0".repeat(64));
check(
  "getrandom: >= 40 distinct byte values across 64 drawn bytes",
  (g.distinctByteValuesAcross64Bytes ?? 0) >= 40,
  `saw ${g.distinctByteValuesAcross64Bytes}`,
);
check("getrandom: a 100000-byte draw crossed the 65536-byte chunk boundary", g.largeDrawLength === 100000 && g.largeDrawWasNotAllZero === true);
check("getrandom: ea-crypto hpke_seal drew fresh ephemeral entropy", g.freshSealsUsedDistinctEphemeralKeys === true && g.freshSealEncapsulatedKeyA !== g.freshSealEncapsulatedKeyB);
check("getrandom: the freshly sealed CEK survived seal->open", g.freshSealOpenRoundtripRecoveredTheCek === true);

// --- Element 3: HPKE --------------------------------------------------------
const h = report.hpke ?? {};
check("hpke: the embedded vector is base-mode-wrapped-cek.bin", h.vectorFile === "vectors/crypto/suite-1/hpke/base-mode-wrapped-cek.bin");
check(
  "hpke: the embedded bytes hash to the manifest fileSha256",
  h.vectorSha256 === "35db387d02afca4c46b2ae77cfce83702ed52d2b5f61d65aef9ea794b814f1ea",
  h.vectorSha256,
);
check(
  "hpke: the encapsulated key is the frozen one",
  h.encapsulatedKey === "53a33a9a549bc5a3d0978e07af5562b3b12d358f56083327888e89be98a4dd01",
  h.encapsulatedKey,
);
check(
  "hpke: the wrapped CEK is the frozen one",
  h.wrappedCek === "d8a66d3b3a51a539cb44797af5eb6e9d05ba9d1b8f8dd05caa6373052856871904e0febf4442d852bfb000af7ae2750d",
  h.wrappedCek,
);
check("hpke: infoDigest matches the manifest", h.infoDigest === "dc2a276919943d010ad7e804a655f596458a7d16a8ede594ff2bc0a7258a3a67", h.infoDigest);
check("hpke: aadDigest matches the manifest", h.aadDigest === "485e08ef1cbfa06e20c9df779fdf67e3f9a2d59e8b73556e563d11a25bcad68d", h.aadDigest);
check(
  "hpke: recipientPublicKeyThumbprint matches the manifest",
  h.recipientPublicKeyThumbprint === "923bd3c45f6ea86fb4667bc0108740cf6701c11306e131f59750ffdd95b74e8b",
  h.recipientPublicKeyThumbprint,
);
check(
  "hpke: the KEM derived the published RFC 7748 6.1 public key",
  h.rfc7748DerivedPublicKey === "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
  h.rfc7748DerivedPublicKey,
);
// Ground truth: manifest inputBytes of hpke/base-mode-wrapped-cek, identical to
// ea_testkit::TEST_ENTROPY_CONTENT_ENCRYPTION_KEY = [0xc0; 32], which the native
// test tests/ea-system-tests/tests/conformance_golden_vectors.rs::check_hpke
// asserts via opened.matches(...).
check(
  "hpke: DECAPSULATION recovered the frozen content encryption key (0xc0 x 32)",
  h.recoveredContentEncryptionKey === "c0".repeat(32),
  h.recoveredContentEncryptionKey,
);
check(
  "hpke: a flipped encapsulated key is REJECTED with EA-CRYPTO-HPKE-OPEN",
  h.rejectedTamperedVectors?.flippedEncapsulatedKey === "EA-CRYPTO-HPKE-OPEN",
  JSON.stringify(h.rejectedTamperedVectors),
);
check(
  "hpke: a flipped wrapped CEK is REJECTED with EA-CRYPTO-HPKE-OPEN",
  h.rejectedTamperedVectors?.flippedWrappedCek === "EA-CRYPTO-HPKE-OPEN",
  JSON.stringify(h.rejectedTamperedVectors),
);

// --- Element 4: Ed25519 -----------------------------------------------------
const e = report.ed25519 ?? {};
check("ed25519: the embedded vector is rfc8032-test1.bin", e.vectorFile === "vectors/crypto/suite-1/ed25519/rfc8032-test1.bin");
check(
  "ed25519: the embedded bytes hash to the manifest fileSha256",
  e.vectorSha256 === "a99e560bf0a0bbf8566a5a13200f1348301b6f691644d95b8ea276ae34c429e6",
  e.vectorSha256,
);
check(
  "ed25519: the signature is the RFC 8032 7.1 TEST 1 signature",
  e.signature === "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  e.signature,
);
check("ed25519: the message is the empty string", e.message === "");
check(
  "ed25519: signerThumbprint matches the manifest",
  e.signerThumbprint === "866eefbd6718c8846cd7ddfe43fc74ab1daac4538ff8514ea2ec2d410a415743",
  e.signerThumbprint,
);
check("ed25519: the valid signature VERIFIED strictly", e.acceptedValidSignature === true);
check(
  "ed25519: the tampered signature was REJECTED",
  e.rejectedTamperedSignature === true && e.tamperedRejectionCode === "EA-TRUST-SIGNATURE-INVALID",
  e.tamperedRejectionCode,
);
check(
  "ed25519: the tampered vector is flipped-signature.bin",
  e.tamperedSignature === "e4564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  e.tamperedSignature,
);

console.log("");
console.log("--- wasm report ---");
console.log(JSON.stringify(report, null, 2));
console.log("");

if (failures.length > 0) {
  console.error(`FAILED: ${failures.length} assertion(s): ${failures.join(", ")}`);
  process.exit(1);
}
console.log(`PASS: all assertions held in Node ${process.version} against the wasm32 module.`);
