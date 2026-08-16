# Einsatzarchiv Stage 1 Trust Core and Format Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish the shared Rust trust boundary, exact archive formats, permanent vectors, archive verification, and recovery CLI baseline on which every later stage depends.

**Architecture:** Split primitive types, bounded deterministic CBOR, cryptographic suite orchestration, wire formats, schemas, time/registry evaluation, trust, chain, archive inventory, and verification into one-way-dependent crates. Verified-state constructors remain private so adapters cannot decrypt or advance state from unverified bytes. Resolve every remaining wire-format ambiguity in a reviewed normative addendum before writing an encoder.

**Tech Stack:** Rust workspace, RFC 8949 deterministic CBOR, RFC 9052 COSE Sign1 with RFC 9864 fully specified Ed25519, SHA-256, ChaCha20-Poly1305, RFC 9180 HPKE Base Mode with X25519/HKDF-SHA-256/ChaCha20-Poly1305, RFC 9562 UUIDv7, RFC 9679 key thumbprints, property testing, coverage-guided fuzzing, snapshot/golden tests.

## Global Constraints

- Die Schlüsselwörter **MUSS**, **DARF NICHT**, **SOLL**, **SOLL NICHT** und **DARF** sind normativ zu verstehen. Ein Release darf von einer MUSS-Anforderung nicht abweichen. Eine Abweichung von SOLL erfordert eine dokumentierte Sicherheits- oder Betriebsbegründung.
- Microsoft Access ist vollständig außerhalb des Scopes. **Access Grant/Zugriffsfreigabe** bezeichnet ausschließlich einen signierten Schlüsselumschlag; `legacyImport` und `legacy-access-import` are invalid.
- Non-goals are fixed: no live incident log, dispatch/alarm/control-center integration, patient record or identifying patient data, concurrent offline Writers, normal-app mutation/deletion of finalized content, AI summarization/OCR, public links, server-side content search, unprofiled network paths, qualified personal electronic signature, TR-ESOR certification claim, screenshot/transcription prevention, or cryptographic recall of already decrypted data.
- Product invariants apply verbatim: exactly one active Writer; never-reused predecessor-bound sequences; immutable `.eip` bytes except whole-object authorized replacement by `.eds`; amendment-only corrections; one fresh CEK/ciphertext; one signed grant per recipient; exactly one active Recovery grant before commit; no Reader/Recovery/HGA/Approver private key on Writer; no retained CEK/decryptable draft key; no server decrypt/grant key; server-independent archive verification; independent schema/format/suite versions with old bytes unchanged; separate Sync/verification/Evidence/Entry/destruction statuses; no legal overclaim from a hash chain; every active Reader initially granted; external-anchor recovery; and only Root-signed OS/device-bound operator snapshots.
- Exactly one active Writer exists; every committed sequence is unique and binds its direct predecessor.
- Final `.eip` bytes are immutable. Corrections are new amendments; destruction replaces a whole `.eip` only with a separately verified `.eds`.
- Each payload has one fresh CEK and one ciphertext; each recipient has a separate signed grant; exactly one active Recovery recipient and every active Reader are in the initial grant plan.
- Writer devices contain no private Reader, Recovery, Historical Grant Authority, or Key Approver keys and retain neither CEK nor decryptable draft key after finalization. The server has no content-decryption or grant-signing key.
- The archive is verifiable without server or mutable status database. Schema, format, and suite versions evolve independently and old bytes remain unchanged.
- Authentic recovery starts from an independently held Trust Anchor; archive-contained trust is never TOFU. Operator snapshots come only from valid Root-signed OS-account/device-bound bindings.
- Writer, Administration, and CLI target supported Windows 11 `x86_64`, current/previous macOS on `arm64` and supported Intel `x86_64`, and Ubuntu 24.04 LTS `x86_64`; server target is Linux OCI `amd64`. Der **Reader läuft im Browser** als installierbare PWA (`docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §3); seine Support-Achsen sind Engine, Version und Plattform (§11.4). Release proof is deferred to Stage 7 but Stage 1 code must remain portable and must compile for `wasm32-unknown-unknown`.
- Die **Desktop-UI für Writer und Administration** uses Ant Design 6 with German `ConfigProvider`, exact lockfile pin, `zeroRuntime: true`, statically extracted local hashed CSS from the specified shared tokens, CSP without runtime/external styles, Ant `App` overlay context, and direct CSR `@phosphor-icons/react` imports only; accessibility/status constraints from §5.4 apply to every later UI task. Der Web-Reader ist von dieser Kette nicht erfasst; seine UI-Grundlage wird in der Stage-4-Überarbeitung festgelegt.
- Security- or format-critical logic is Rust-only and shared by Desktop, Server, and CLI. TypeScript may consume generated view DTOs only.
- Private keys, payload/plaintext, decrypted content, nonces, clear incident numbers, locations, names, and free text MUST NOT appear in logs, dumps, crash output, server metadata, or unencrypted configuration. Persistence is permitted only where a normative signed/encrypted wire object requires it or where the user explicitly requests decrypted CLI output. Protocol nonces may exist only in their specified signed or encrypted objects. Explicit decrypted CLI output MUST use a user-selected newly created or empty target with restrictive permissions. Plaintext temporary files remain forbidden. Local databases are fully encrypted in later stages.
- Preserve exact status vocabularies defined in §17.4 and never claim general court admissibility, TR-ESOR certification, or complete metadata blindness.
- v0.1 is complete only after Stage 7 and every acceptance criterion and unnumbered gate passes.

Suite v1 is fixed to `formatVersion = 1`, `objectVersion = 1`, `cryptoSuiteId = "EINSATZARCHIV-SUITE-1"`, grant suite `EINSATZARCHIV-HPKE-1`, magic `h'45413100'`, and object type tags `.eip=1`, `.eag=2`, `.esr=3`, `.ecp=4`, `.etb=5`, `.eds=6`. Raw family limits are `.eip=2_097_152`, `.eag=65_536`, `.esr=65_536`, `.ecp=4_194_304`, `.etb=4_194_304`, and `.eds=262_144` bytes. Value and work limits are exactly `MAX_PLAINTEXT_BYTES_V1 = 1_048_576`, `MAX_CBOR_TEXT_OR_BYTES_V1 = 1_048_592`, `MAX_CIPHERTEXT_BYTES_V1 = 1_048_592`, nesting 16, `MAX_CONTAINER_ITEMS_V1 = 10_000` elements per container, and `MAX_TOTAL_ITEMS_V1 = 10_000` tokens per top-level item.

---

### Task 1: Reproducible Monorepo and Dependency Decision Record

**Files:**
- Create: `Cargo.toml`
- Create: `Cargo.lock`
- Create: `rust-toolchain.toml`
- Create: `.cargo/config.toml`
- Create: `.cargo/fuzz-toolchain.toml`
- Create: `.node-version`
- Create: `.npmrc`
- Create: `package.json`
- Create: `pnpm-workspace.yaml`
- Create: `pnpm-lock.yaml`
- Create: `deny.toml`
- Create: `tools/xtask/Cargo.toml`
- Create: `tools/xtask/src/main.rs`
- Create: `tests/ea-system-tests/Cargo.toml`
- Create: `tests/ea-system-tests/src/lib.rs`
- Create: `docs/adr/0001-toolchain-and-cryptography-dependencies.md`
- Test: `tools/xtask/tests/workspace.rs`

**Interfaces:**
- Consumes: approved design specification only.
- Produces: exact committed toolchain/lockfile pins and stable root commands `verify:quick`, `test:core`, `test:golden`, `test:property`, `test:fuzz`, and `test:recovery`.

- [ ] **Step 1: Write the workspace smoke test**

```rust
// tools/xtask/tests/workspace.rs
use std::{collections::BTreeSet, fs, process::Command};
use toml::Value;

#[test]
fn workspace_declares_exact_initial_members_and_shared_dependencies() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    assert!(root.join("Cargo.lock").is_file());
    assert!(root.join("pnpm-lock.yaml").is_file());
    let root_manifest: Value = fs::read_to_string(root.join("Cargo.toml")).unwrap().parse().unwrap();
    let member_array = root_manifest["workspace"]["members"].as_array().unwrap();
    assert_eq!(member_array.len(), 2, "workspace members must not be duplicated or omitted");
    let members = member_array
        .iter().map(|member| member.as_str().unwrap()).collect::<BTreeSet<_>>();
    assert_eq!(members, BTreeSet::from(["tools/xtask", "tests/ea-system-tests"]));
    let workspace_dependencies = root_manifest["workspace"]["dependencies"].as_table().unwrap();
    assert!(!workspace_dependencies.is_empty(), "workspace.dependencies must contain shared dependencies");
    for member in ["tools/xtask", "tests/ea-system-tests"] {
        let manifest: Value = fs::read_to_string(root.join(member).join("Cargo.toml")).unwrap().parse().unwrap();
        let mut member_dependency_references = 0;
        for table_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
            if let Some(dependencies) = manifest[table_name].as_table() {
                for (name, dependency) in dependencies {
                    member_dependency_references += 1;
                    assert!(workspace_dependencies.contains_key(name), "{member} {table_name} dependency {name} is not shared at workspace scope");
                    assert_eq!(dependency.as_table().and_then(|spec| spec.get("workspace")).and_then(Value::as_bool), Some(true), "{member} {table_name} dependency {name} must use workspace = true");
                }
            }
        }
        assert!(member_dependency_references > 0, "{member} must reference at least one shared workspace dependency");
    }
    assert!(Command::new("cargo").args(["metadata", "--locked", "--no-deps"])
        .current_dir(root).status().unwrap().success());
}
```

- [ ] **Step 2: Run the smoke test and confirm the empty repository fails**

Run: `cargo test --manifest-path tools/xtask/Cargo.toml --test workspace --locked`

Expected: FAIL because the workspace manifests and lockfiles do not exist.

- [ ] **Step 3: Create the pinned workspace and record dependency evidence**

Use the currently installed, verified toolchain as the initial exact pin:

```toml
# rust-toolchain.toml
[toolchain]
channel = "1.95.0"
profile = "minimal"
components = ["clippy", "rustfmt"]
```

```text
# .node-version
26.7.0
```

```ini
# .npmrc
save-exact=true
engine-strict=true
```

```yaml
# pnpm-workspace.yaml
packages:
  - apps/desktop
```

Create a virtual root `package.json` with `packageManager: "pnpm@11.20.0"`; implement each root script as `cargo run --locked -p xtask -- <gate>`. Create a Cargo workspace with resolver `2`, edition `2024`, and `rust-version = "1.95"`. Initially list only the packages this task actually creates: `tools/xtask` and a non-production `ea-system-tests` package at `tests/ea-system-tests`. Every later crate task adds its own concrete path to `workspace.members` in the same commit as its real manifest and source; never list a package whose manifest does not yet exist and never create empty scaffold crates. Later cross-crate Rust integration tests go directly in `tests/ea-system-tests/tests/` so every documented `cargo test -p ea-system-tests --test <name>` command is executable. Add dependencies only at workspace scope: root `workspace.dependencies` holds each shared dependency and every created member manifest declares it with `workspace = true`, rather than an independent version. Each initial member MUST contain at least one justified workspace-scoped dependency reference in `dependencies`, `dev-dependencies`, or `build-dependencies`; do not add an unused dependency merely to satisfy this gate—each reference must support that package's Task 1 implementation or tests. Declare the `toml` parser required by this smoke test at workspace scope and consume it from `xtask` with `workspace = true`. Resolve the latest compatible crate releases once, commit `Cargo.lock`, and document for each crypto/format dependency its upstream, maintained status, audit/security rationale, enabled features, and rejected alternatives in ADR 0001. The initial lockfile-generation commands below are the sole bootstrap resolution exception; every later dependency-resolving Cargo/pnpm command uses `--locked` or `--frozen-lockfile`.

Select from current evidence and commit one exact dated Nightly Rust toolchain and one exact `cargo-fuzz` version independently of the production/MSRV Rust `1.95.0` pin. Record the two resolved values and their evidence in ADR 0001 and in `.cargo/fuzz-toolchain.toml`; the descriptive fields in this plan MUST be replaced by those exact committed values during implementation, not guessed here. Install the selected external tool exactly and with its own locked resolution:

```bash
cargo install cargo-fuzz --version <exact-version> --locked
```

Implement `xtask test-fuzz` as the stable root gate: it reads the committed values, invokes `cargo +<exact-dated-nightly> fuzz` (never ambient Nightly), and resolves the fuzz target against the committed `fuzz/Cargo.lock`. Its smoke duration is caller-configurable so Task 4 can request 30 seconds and the Stage 1 gate can request 60 seconds.

Implement `xtask` so `verify-quick` executes these processes without a shell:

```rust
for (program, args) in [
    ("cargo", vec!["fmt", "--all", "--check"]),
    ("cargo", vec!["clippy", "--workspace", "--all-targets", "--all-features", "--locked", "--", "-D", "warnings"]),
    ("cargo", vec!["test", "--workspace", "--all-targets", "--locked"]),
    ("cargo", vec!["check", "--target", "wasm32-unknown-unknown", "--locked", "-p", "ea-types", "-p", "ea-cbor", "-p", "ea-crypto", "-p", "ea-format", "-p", "ea-schema", "-p", "ea-time", "-p", "ea-trust"]),
] {
    let status = std::process::Command::new(program).args(args).status()?;
    if !status.success() { std::process::exit(status.code().unwrap_or(1)); }
}
```

Der vierte Eintrag stammt aus `docs/superpowers/plans/2026-08-16-einsatzarchiv-web-reader-stage-1-prerequisites.md` und erfüllt `2026-08-15-einsatzarchiv-web-reader-design.md` §10. Er ist eine Positivliste über die Bibliotheks-Crates — nicht `--workspace` (`xtask` ist nicht wasm-tauglich) und nicht `--all-targets` (zöge Dev-Dependencies in den wasm-Graph). Er belegt Übersetzbarkeit, nicht Lauffähigkeit. Jede später entstehende Bibliotheks-Crate MUSS aufgenommen werden.

- [ ] **Step 4: Generate lockfiles and verify the workspace**

Run:

```bash
cargo generate-lockfile
corepack pnpm install --frozen-lockfile=false
cargo test --locked -p xtask --test workspace
cargo run --locked -p xtask -- verify-quick
```

Expected: PASS; the ADR contains actual resolved versions and sources, and both lockfiles are tracked.

- [ ] **Step 5: Commit the reproducible scaffold**

```bash
git add Cargo.toml Cargo.lock rust-toolchain.toml .cargo/config.toml .cargo/fuzz-toolchain.toml .node-version .npmrc package.json pnpm-workspace.yaml pnpm-lock.yaml deny.toml tools/xtask tests/ea-system-tests docs/adr/0001-toolchain-and-cryptography-dependencies.md
git commit -m "build: establish pinned Einsatzarchiv workspace"
```

### Task 2: Close Normative Wire-Format Gaps Before Encoding

**Files:**
- Create: `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-wire-format-addendum.md`
- Create: `schemas/archive/v1/archive.cddl`
- Create: `schemas/archive/v1/trust.cddl`
- Create: `schemas/archive/v1/evidence.cddl`
- Create: `schemas/reports/v1/verification-report.schema.json`
- Create: `schemas/reports/v1/key-inventory.schema.json`
- Create: `schemas/reports/v1/local-audit.cddl`
- Test: `tools/xtask/tests/spec_completeness.rs`

**Interfaces:**
- Consumes: fixed structures and semantics from design §§10–16.
- Produces: exact array positions and tags for every `.ecp`, `.eds`, and `.etb` subtype, stable `ea.verification-report/v1` and `ea.key-inventory/v1` JSON schemas, and the signed cleartext-free `local-audit-event-v1` contract.

- [ ] **Step 1: Write a completeness test that enumerates every required object and trust subtype**

```rust
#[test]
fn cddl_registers_every_v1_wire_type() {
    let archive = include_str!("../../../schemas/archive/v1/archive.cddl");
    let trust = include_str!("../../../schemas/archive/v1/trust.cddl");
    let evidence = include_str!("../../../schemas/archive/v1/evidence.cddl");
    for name in ["eip-v1", "eag-v1", "esr-v1", "ecp-v1", "etb-v1", "eds-v1"] {
        assert!(archive.contains(name), "missing {name}");
    }
    for subtype in [
        "root-certificate-core-v1", "device-certificate-core-v1", "operator-binding-core-v1",
        "organization-admin-authorization-v1", "registry-event-core-v1", "policy-core-v1",
        "writer-transition-core-v1", "grant-authorization-core-v1",
        "destruction-authorization-core-v1", "destruction-transition-core-v1",
        "deletion-attestation-core-v1",
    ] { assert!(trust.contains(subtype), "missing {subtype}"); }
    for name in ["checkpoint-core-v1", "timestamp-evidence-v1", "renewal-core-v1"] {
        assert!(evidence.contains(name), "missing {name}");
    }
    let audit = include_str!("../../../schemas/reports/v1/local-audit.cddl");
    for name in ["local-audit-event-v1", "stale-registry-context-v1", "clock-release-context-v1"] {
        assert!(audit.contains(name), "missing {name}");
    }
}
```

- [ ] **Step 2: Run the completeness test and verify missing schemas fail**

Run: `cargo test --locked -p xtask --test spec_completeness`

Expected: FAIL because the CDDL and report schemas do not exist.

- [ ] **Step 3: Write and review the exact addendum**

The addendum must state that it is normative for v0.1, cannot override an already fixed design field, and is accepted before Task 3. Use these exact new discriminators and outer shapes:

```cddl
ecp-v1 = [h'45413100', 4, 1, [],
  ([0, standard-checkpoint-v1] /
   [1, timestamp-evidence-v1] /
   [2, renewal-evidence-v1])
]

checkpoint-core-v1 = [
  1, domain: "EINSATZARCHIV-CHECKPOINT-v1",
  organization-id: bstr .size 16, chain-id: bstr .size 16,
  covered-from-sequence: uint, covered-through-sequence: uint,
  head-entry-hash: bstr .size 32, registry-head-hash: bstr .size 32,
  issued-at-server: int, previous-evidence-hash: (bstr .size 32) / null, []
]

standard-checkpoint-v1 = [checkpoint-core-v1, #6.18(COSE-Sign1)]
timestamp-evidence-v1 = [
  checkpoint-core-v1, #6.18(COSE-Sign1),
  rfc3161-response-der: bstr, hash-algorithm: 0, ; 0 SHA-256
  request-nonce: bstr, policy-oid-der: bstr,
  tsa-certificate-chain-der: [+ bstr], revocation-data-der: [* bstr],
  validation-data-der: [* bstr]
]

renewal-core-v1 = [
  1, domain: "EINSATZARCHIV-EVIDENCE-RENEWAL-v1",
  organization-id: bstr .size 16, chain-id: bstr .size 16,
  current-entry-hash: bstr .size 32,
  previous-renewal-hash: (bstr .size 32) / null,
  sorted-renewal-input-hashes: [+ bstr .size 32], []
]
renewal-evidence-v1 = [
  renewal-core-v1, #6.18(COSE-Sign1), rfc3161-response-der: bstr,
  hash-algorithm: 0, request-nonce: bstr, policy-oid-der: bstr,
  tsa-certificate-chain-der: [+ bstr], revocation-data-der: [* bstr],
  validation-data-der: [* bstr]
]

eds-v1 = [h'45413100', 6, 1, [], [
  1, signed-manifest: [manifest-core-v1, bstr .size 32],
  writer-signature: #6.18(COSE-Sign1), entry-hash: bstr .size 32,
  ciphertext-hash: bstr .size 32, original-eip-object-hash: bstr .size 32,
  destruction-id: bstr .size 16,
  destruction-authorization-object-hash: bstr .size 32, []
]]
```

Use these exact Trust core arrays; a nullable key is allowed only when the certificate kind does not use that algorithm. Capability strings and hash lists are UTF-8/bytewise sorted and duplicate-free.

```cddl
etb-v1 = [h'45413100', 5, 1, [], etb-body-v1]
trust-subtype-v1 = "rootCertificate" / "deviceCertificate" / "operatorBinding" /
  "organizationAdminAuthorization" / "registryEvent" / "policy" /
  "writerTransition" / "grantAuthorization" / "destructionAuthorization" /
  "destructionTransition" / "deletionAttestation"

cose-sign1-v1 = #6.18(COSE-Sign1)
etb-body-v1 =
  ["rootCertificate", (root-certificate-core-v1 /
    authorized-trust-payload-v1<root-certificate-core-v1>), [+ cose-sign1-v1]] /
  ["deviceCertificate", (initial-admin-device-certificate-core-v1 /
    authorized-trust-payload-v1<device-certificate-core-v1>), [+ cose-sign1-v1]] /
  ["operatorBinding", (initial-admin-operator-binding-core-v1 /
    authorized-trust-payload-v1<operator-binding-core-v1>), [+ cose-sign1-v1]] /
  ["organizationAdminAuthorization", organization-admin-authorization-v1,
    [cose-sign1-v1]] /
  ["registryEvent", authorized-trust-payload-v1<registry-event-core-v1>, [+ cose-sign1-v1]] /
  ["policy", authorized-trust-payload-v1<policy-core-v1>, [+ cose-sign1-v1]] /
  ["writerTransition", authorized-trust-payload-v1<writer-transition-core-v1>, [+ cose-sign1-v1]] /
  ["grantAuthorization", grant-authorization-core-v1, [2* cose-sign1-v1]] /
  ["destructionAuthorization", destruction-authorization-core-v1, [2* cose-sign1-v1]] /
  ["destructionTransition", destruction-transition-core-v1, [+ cose-sign1-v1]] /
  ["deletionAttestation", deletion-attestation-core-v1, [+ cose-sign1-v1]]

; 0 writer, 1 reader, 2 organizationAdmin, 3 keyApprover,
; 4 recoveryRecipient, 5 historicalGrantAuthority, 6 serverReceipt,
; 7 deletionAttest
certificate-kind-v1 = 0..7
; 0 osWrapped, 1 hardwareNonExportable, 2 offlineEncryptedContainer,
; 3 pkcs11, 4 serverSecretStoreOrHsm
key-protection-profile-v1 = 0..4

root-certificate-core-v1 = [
  1, organization-id: bstr .size 16,
  root-public-cose-key: bstr, root-key-thumbprint: bstr .size 32,
  previous-root-certificate-object-hash: (bstr .size 32) / null,
  effective-from-registry-version: uint, []
]

device-certificate-core-v1 =
  device-certificate-core-for-v1<(0 / 1 / 4..7), null> /
  device-certificate-core-for-v1<(2 / 3), bstr .size 16>
initial-admin-device-certificate-core-v1 =
  device-certificate-core-for-v1<2, bstr .size 16>
device-certificate-core-for-v1<KIND, AUTHORITY_SUBJECT_ID> = [
  1, organization-id: bstr .size 16, device-id: bstr .size 16,
  certificate-kind: KIND,
  signing-public-cose-key: bstr / null, kem-public-cose-key: bstr / null,
  signing-key-thumbprint: (bstr .size 32) / null,
  kem-key-thumbprint: (bstr .size 32) / null,
  capabilities: [* tstr], key-protection-profile: key-protection-profile-v1,
  effective-from-sequence: uint, revoked-from-sequence: uint / null,
  authority-subject-id: AUTHORITY_SUBJECT_ID, []
]

operator-binding-core-v1 = operator-binding-core-for-v1<0..2>
initial-admin-operator-binding-core-v1 = operator-binding-core-for-v1<2>
operator-binding-core-for-v1<ROLE> = [
  1, organization-id: bstr .size 16, operator-subject-id: bstr .size 16,
  operator-profile-commitment: bstr .size 32,
  device-certificate-hash: bstr .size 32,
  operator-role: ROLE, ; writer, reader, organization admin
  os-account-binding-hash: bstr .size 32,
  operator-instance-key-thumbprint: bstr .size 32,
  effective-from-sequence: uint, revoked-from-sequence: uint / null, []
]

organization-admin-authorization-v1 = [
  1, authorization-id: bstr .size 16, organization-id: bstr .size 16,
  registry-version: uint, registry-head-hash: bstr .size 32,
  admin-key-thumbprint: bstr .size 32, admin-certificate-hash: bstr .size 32,
  admin-operator-binding-object-hash: bstr .size 32,
  action-code: 0..6,
  target-trust-subtype: "deviceCertificate" / "operatorBinding" /
    "registryEvent" / "policy" / "writerTransition" / "rootCertificate",
  authorized-trust-core-hash: bstr .size 32,
  issued-at: int, expires-at: int, nonce: bstr .size 32, []
]

; Every event changes exactly one action class.
; target-kind 0 = deviceCertificate with CertificateKind Writer, Reader, KeyApprover, RecoveryRecipient, or HistoricalGrantAuthority
; target-kind 1 = operatorBinding
; target-kind 2 = deviceCertificate with CertificateKind ServerReceipt or DeletionAttest
; OrganizationAdmin is invalid under Change 1
registry-change-v1 =
  [0, certificate-object-hash: bstr .size 32] /                 ; deviceApprove
  [1, target-kind: 0..2, target-object-hash: bstr .size 32] / ; device/operator/component revoke
  [2, policy-object-hash: bstr .size 32] /                    ; policyChange
  [3, writer-transition-object-hash: bstr .size 32] /         ; writerTransition
  [4, operator-binding-object-hash: bstr .size 32] /          ; operatorBinding
  [5, admin-certificate-object-hash: bstr .size 32, effect: 0..1] / ; activate/revoke
  [6, root-certificate-object-hash: bstr .size 32]             ; rootRotation

registry-event-core-v1 = [
  1, organization-id: bstr .size 16, registry-version: uint,
  previous-registry-hash: (bstr .size 32) / null,
  effective-from-sequence: uint, valid-through-sequence: uint,
  issued-at: int, not-before: int, not-after: int,
  policy-object-hash: bstr .size 32, change: registry-change-v1,
  root-key-thumbprint: bstr .size 32, []
]

retention-policy-v1 = [
  minimum-retention-ms: uint / null,
  destruction-enabled: bool,
  eds-privacy-decision-document-hash: (bstr .size 32) / null
]
free-text-policy-v1 = [
  free-text-allowed: bool, rule-set-version: tstr,
  local-pattern-warning-enabled: bool
]
policy-core-v1 = [
  1, organization-id: bstr .size 16, policy-version: uint,
  previous-policy-object-hash: (bstr .size 32) / null,
  operating-profile: 0..1, ; standard, evidence-grade
  max-registry-age-ms: uint, max-future-clock-skew-ms: uint,
  registry-expiry-behavior: 0..1, ; warn, block
  evidence-max-delay-ms: uint, reader-inactivity-ms: uint,
  reader-history-access-allowed: bool,
  allowed-archive-profile-hashes: [+ bstr .size 32],
  network-outage-behavior: 0, ; local commit then byte-identical publication
  backup-frequency-ms: uint, restore-test-interval-ms: uint,
  retention-policy: retention-policy-v1, free-text-policy: free-text-policy-v1,
  allowed-crypto-suite-ids: [+ tstr], allowed-format-versions: [+ uint],
  effective-from-sequence: uint, []
]

writer-transition-core-v1 = [
  1, organization-id: bstr .size 16, chain-id: bstr .size 16,
  old-writer-certificate-hash: bstr .size 32,
  new-writer-certificate-hash: bstr .size 32,
  effective-from-sequence: uint, previous-entry-hash: bstr .size 32,
  reason-code: uint, []
]

grant-authorization-core-v1 = [
  1, authorization-id: bstr .size 16, organization-id: bstr .size 16,
  registry-version: uint, registry-head-hash: bstr .size 32,
  authorization-sequence: uint,
  sorted-entry-hashes: [+ bstr .size 32],
  recipient-key-thumbprint: bstr .size 32,
  recipient-certificate-hash: bstr .size 32,
  purpose: 1, expires-at: int, []
]

destruction-authorization-core-v1 = [
  1, destruction-id: bstr .size 16, organization-id: bstr .size 16,
  registry-version: uint, registry-head-hash: bstr .size 32,
  authorization-sequence: uint,
  ; Nonempty and ascending by (entryHash bytes, chainSequence numeric).
  ; Target identity is entryHash; any repeated entryHash is invalid, even with a
  ; different sequence. chainSequence is a signed-manifest cross-check. Equal
  ; chainSequence values with different entryHash values are not duplicates.
  sorted-targets: [+ [entry-hash: bstr .size 32, chain-sequence: uint]],
  scope-code: uint, legal-reason-code: uint, []
]

; 0 requested, 1 inProgress, 2 pendingBackupExpiry,
; 3 completeManagedScope, 4 incompleteUnreachableReplica
destruction-state-v1 = 0..4
destruction-transition-core-v1 = [
  1, destruction-id: bstr .size 16,
  destruction-authorization-object-hash: bstr .size 32,
  event-id: bstr .size 16,
  previous-event-object-hash: (bstr .size 32) / null,
  from-state: destruction-state-v1 / null,
  to-state: destruction-state-v1, trigger-code: uint,
  executed-at: int, []
]

deletion-attestation-core-v1 = [
  1, destruction-id: bstr .size 16,
  destruction-authorization-object-hash: bstr .size 32,
  replica-id: bstr .size 16, replica-kind: uint,
  sorted-removed-object-hashes: [* bstr .size 32],
  result: 0..2, ; removed, pending immutable expiry, unreachable/failed
  backup-expiry-at: int / null, executed-at: int, []
]

; Initial Root/Admin exceptions carry the core directly. Every other authorized
; target carries the exact Admin authorization object hash as its second item.
authorized-trust-payload-v1<T> = [authorized-trust-core: T,
                                  organization-admin-authorization-object-hash: bstr .size 32]
```

Compatibility is fail-closed: `device-certificate-core-v1 length 13 is invalid`
and `clock-release-context-v1 length 6 is invalid`. There is no v2 or legacy
decoder.

The Stage-1 trust contract follows the approved Task-8 closure exactly. Every
authorization binds the already selected previous head and every Registry event
is its checked direct successor:

```text
authorization.registryVersion = previousHead.registryVersion
authorization.registryHeadHash = previousHead.objectHash
event.registryVersion = checked_add(authorization.registryVersion, 1)
```

Version 1 requires authorization version 0/zero32 and a null previous hash;
later versions require the authorization head hash. Direct target and activation
event use separate one-time authorization IDs/nonces but the same previous head.
Head 1 uses only Change 2 for the initial Policy; anchor-pinned Admin pairs are
external basis state, not another change. The closed action matrix includes
Action 4 `operatorBinding` with Registry Change 4 and Action 6 `rootRotation`
with Registry Change 6. Change 5 Effect 0 activates a newly authorized Admin
certificate, Effect 1 revokes an active one, and Change 1 never revokes Admins.

Bootstrap Policy correlation is exact:

```text
initialPolicy.policyVersion = 1
initialPolicy.previousPolicyObjectHash = null
initialPolicy.effectiveFromSequence = head1.effectiveFromSequence
```

Admin and Key-Approver certificates require `authoritySubjectId`; every other
kind requires null. Admin IDs equal their correlated Binding
`operatorSubjectId`, remain stable across externally verified same-person
rotation, drive distinct-person checks, and prevent self-authorization.
Policy/hash/effective-sequence correlations and
`root.effectiveFromRegistryVersion = event.registryVersion` are exact. Active
signers are resolved against the unchanged previous-head state at
`preTransitionSequence`: the event sequence inside the previous lease, or the
previous lease end for its checked immediate successor.
Head 1 is the explicit lease-free exception with
`preTransitionSequence = head1.effectiveFromSequence`. Both direct-target and
event authorizations are historically valid at the signed activation
`event.issuedAt`, inclusive at both bounds; current wall time is irrelevant.

Define the local, encrypted-database audit record as deterministic CBOR plus identity-bearing COSE. Action and context discriminators are stable and all detail is allowlisted; there is no free-text detail field.

```cddl
; 0 login, 1 reauthFailure, 2 bindingChange, 3 revocation,
; 4 registryStaleWarnAcceptance, 5 plaintextExport, 6 clockSkewRelease,
; 7 adminRootCeremony, 8 recoveryTest, 9 historicalRegrant, 10 destruction,
; 11 archiveProfileMigration
local-audit-action-v1 = 0..11
; 0 failed, 1 accepted, 2 completed
local-audit-outcome-v1 = 0..2

stale-registry-context-v1 = [
  registry-head-hash: bstr .size 32, policy-object-hash: bstr .size 32,
  proposed-sequence: uint, registry-not-after: int, acknowledged-at: int,
  preview-hash: bstr .size 32
]
clock-release-context-v1 = [
  trusted-time-floor: int, observed-os-wall-clock: int,
  max-future-clock-skew-ms: uint, registry-version: uint,
  registry-head-hash: bstr .size 32,
  guard-policy-object-hash: bstr .size 32,
  independent-time-reference: independent-time-reference-v1,
  justification-code: 0..2, issued-at: int, expires-at: int
]
independent-time-reference-v1 =
  [0, receipt-object-hash: bstr .size 32, verified-time: int] /
  [1, checkpoint-object-hash: bstr .size 32, verified-time: int] /
  [2, tsa-evidence-object-hash: bstr .size 32, verified-time: int]
export-context-v1 = [entry-hash: bstr .size 32, target-kind: uint]
binding-lifecycle-context-v1 = [
  old-binding-object-hash: (bstr .size 32) / null,
  new-binding-object-hash: (bstr .size 32) / null,
  effective-from-sequence: uint
]
admin-root-context-v1 = [
  authorization-object-hash: bstr .size 32,
  target-object-hash: bstr .size 32, action-code: uint
]
historical-regrant-context-v1 = [
  authorization-object-hash: bstr .size 32, entry-hash: bstr .size 32,
  original-recovery-grant-object-hash: bstr .size 32,
  recipient-certificate-object-hash: bstr .size 32,
  new-grant-object-hash: bstr .size 32
]
destruction-context-v1 = [
  destruction-authorization-object-hash: bstr .size 32,
  state-event-object-hash: bstr .size 32
]
archive-profile-migration-context-v1 = [
  source-profile-hash: bstr .size 32, target-profile-hash: bstr .size 32,
  inventory-hash: bstr .size 32, active-pointer-hash: bstr .size 32
]
local-audit-context-v1 =
  generic-audit-context-v1 / stale-audit-context-v1 /
  clock-release-audit-context-v1 / export-audit-context-v1 /
  binding-audit-context-v1 / admin-root-audit-context-v1 /
  historical-regrant-audit-context-v1 / destruction-audit-context-v1 /
  archive-profile-migration-audit-context-v1

generic-audit-context-v1 = [0, subject-object-hash: (bstr .size 32) / null]
stale-audit-context-v1 = [1, stale-registry-context-v1]
clock-release-audit-context-v1 = [2, clock-release-context-v1]
export-audit-context-v1 = [3, export-context-v1]
binding-audit-context-v1 = [4, binding-lifecycle-context-v1]
admin-root-audit-context-v1 = [5, admin-root-context-v1]
historical-regrant-audit-context-v1 = [6, historical-regrant-context-v1]
destruction-audit-context-v1 = [7, destruction-context-v1]
archive-profile-migration-audit-context-v1 = [8, archive-profile-migration-context-v1]

local-audit-event-core-v1 =
  local-audit-event-core-for-v1<0, generic-audit-context-v1> /
  local-audit-event-core-for-v1<1, generic-audit-context-v1> /
  local-audit-event-core-for-v1<2, binding-audit-context-v1> /
  local-audit-event-core-for-v1<3, binding-audit-context-v1> /
  local-audit-event-core-for-v1<4, stale-audit-context-v1> /
  local-audit-event-core-for-v1<5, export-audit-context-v1> /
  local-audit-event-core-for-v1<6, clock-release-audit-context-v1> /
  local-audit-event-core-for-v1<7, admin-root-audit-context-v1> /
  local-audit-event-core-for-v1<8, generic-audit-context-v1> /
  local-audit-event-core-for-v1<9, historical-regrant-audit-context-v1> /
  local-audit-event-core-for-v1<10, destruction-audit-context-v1> /
  local-audit-event-core-for-v1<11, archive-profile-migration-audit-context-v1>

local-audit-event-core-for-v1<ACTION, CONTEXT> = [
  1, event-id: bstr .size 16, organization-id: bstr .size 16,
  device-id: bstr .size 16,
  operator-binding-object-hash: (bstr .size 32) / null,
  signer-certificate-object-hash: bstr .size 32,
  action: ACTION, outcome: local-audit-outcome-v1,
  effective-now: int, context: CONTEXT,
  nonce: bstr .size 32, []
]
local-audit-event-v1 = [local-audit-event-core-v1, #6.18(COSE-Sign1)]
```

The COSE payload is exactly the deterministic encoding of `local-audit-event-core-v1`; protected headers resolve the signer to the named active device or Admin certificate. Generic context contains only an object hash or null. Enforce the fixed action-to-context table: login/reauth failure/recovery test use generic; binding change/revocation use binding lifecycle; stale acceptance, export, clock release, Admin/Root ceremony, historical re-grant, destruction, and profile migration each use only their same-named typed context. Export stores only target kind, never a path. The stale-warning context is the one-use finalization acknowledgement. The exact ten-field Clock Release binds `registry-head-hash`, `guard-policy-object-hash`, and a deterministically selected `independent-time-reference-v1`; its reference tag and justification are both closed to 0..2, hashes are exactly 32 bytes, `issuedAt < expiresAt`, `clockRelease.issuedAt <= EffectiveNow <= clockRelease.expiresAt`, and the outer effective time equals the maximum of observed wall clock and trusted floor. All wire outcomes 0..2 remain valid; only full Runtime Phase B verification of Action 6/Outcome 1 can create an opaque, by-value `VerifiedClockRelease`. It never lowers `trustedTimeFloor` or waives `notBefore`, Registry expiry, lease, authorization expiry, or signature checks.

For `grantAuthorization` and `destructionAuthorization`, the outer `.etb` signature list must contain at least two signatures, sorted by signer certificate hash, from distinct active subject IDs with the matching Approver capability. Root rotation has exactly one outer signature from the previous accepted Root line; its Admin authorization is hash-bound in the authorized payload. The initial Root proof-of-possession is the only `certificateHash` exception among authorized operational/archive signatures; the separate Enrollment-PoP is pre-authorization and not a Trust signature.

Define the two JSON schemas with `additionalProperties: false` at every object level. `ea.verification-report/v1` requires exactly `schemaId`, `archiveObjectCount`, `entryPackageCount`, `destroyedEntryCount`, `chainHead`, `registryVersions`, `objectResults`, `authorizedDestructions`, `gaps`, `signatureErrors`, `evidenceErrors`, `decryptionErrors`, `publicKeyThumbprints`, and `reportHash`; it permits only optional `reportSignature` and `runtimeMetadata`, and runtime time/host/path fields are valid only inside that metadata object. `ea.key-inventory/v1` requires exactly `schemaId`, `inventoryId`, and duplicate-free `media`, where each medium contains `mediumId`, `keyRole`, `expectedKeyThumbprint`, `certificateObjectHash`, `protectionProfile`, and `testKind` (`signatureChallenge`, `recoveryDecrypt`, or `providerPresence`). Every array declares its stable complete sort key and duplicate key as machine-readable `x-ea-sort-key` and `x-ea-unique-key`; the schema gate rejects missing contracts, unsorted instances, and equal complete keys even when non-key fields differ. Productive serializers in Tasks 9/10 and Stage 5 MUST implement the same annotations.

Add a review table mapping every added field back to a design paragraph. Any design contradiction blocks implementation and is fixed in the design plus addendum in the same review commit; production code never chooses between them.

- [ ] **Step 4: Validate syntax, names, and report schemas**

Run:

```bash
cargo test --locked -p xtask --test spec_completeness
cargo run --locked -p xtask -- validate-schemas
```

Expected: PASS; no required subtype is absent, every JSON schema rejects unknown properties, and the addendum review table has no unresolved row.

- [ ] **Step 5: Commit the normative addendum separately**

```bash
git add docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-wire-format-addendum.md schemas/archive/v1 schemas/reports/v1 tools/xtask/tests/spec_completeness.rs
git commit -m "docs: close v0.1 wire format definitions"
```

### Task 3: Primitive Types, Status Boundaries, and Cleartext-Free Errors

**Files:**
- Create: `crates/ea-types/Cargo.toml`
- Create: `crates/ea-types/src/lib.rs`
- Create: `crates/ea-types/src/ids.rs`
- Create: `crates/ea-types/src/status.rs`
- Create: `crates/ea-types/src/error.rs`
- Create: `crates/ea-types/src/redaction.rs`
- Test: `crates/ea-types/tests/contracts.rs`

**Interfaces:**
- Consumes: no prior application crate.
- Produces: IDs/hashes/versions, normative status enums, `TechnicalErrorCode`, and `Redacted<T>` used by every later crate.

- [ ] **Step 1: Write contract and redaction tests**

```rust
use ea_types::{
    EntryHash, ErrorClass, Hash32, RetryDisposition, SyncStatus,
    TechnicalError, TechnicalErrorCode,
};

#[test]
fn hashes_require_exact_length_and_errors_do_not_echo_input() {
    assert!(Hash32::try_from(&[0_u8; 31][..]).is_err());
    let err = TechnicalError::new(TechnicalErrorCode::InvalidObject).with_secret("CANARY-NAME");
    assert_eq!(format!("{err}"), "EA-FORMAT-INVALID-OBJECT");
    assert!(!format!("{err:?}").contains("CANARY-NAME"));
}

#[test]
fn status_is_machine_stable() {
    assert_eq!(SyncStatus::UploadPending.code(), "uploadPending");
    assert_eq!(EntryHash::from(Hash32::ZERO).as_bytes(), &[0_u8; 32]);
}

#[test]
fn every_error_class_has_one_fail_closed_retry_contract() {
    assert_eq!(ErrorClass::Domain.disposition(), RetryDisposition::CorrectInput);
    assert_eq!(ErrorClass::LocalResource.disposition(), RetryDisposition::RetainDraftAndBlock);
    assert_eq!(ErrorClass::TemporaryTransport.disposition(), RetryDisposition::BoundedRetry);
    assert_eq!(ErrorClass::TrustSecurity.disposition(), RetryDisposition::FailClosed);
    assert_eq!(ErrorClass::Format.disposition(), RetryDisposition::IsolateObject);
    assert_eq!(ErrorClass::Evidence.disposition(), RetryDisposition::PreserveEntryAndReport);
    assert_eq!(ErrorClass::RecoveryDestruction.disposition(), RetryDisposition::ReportExactPartialState);
}
```

- [ ] **Step 2: Run tests and verify the crate is absent**

Run: `cargo test --locked -p ea-types --test contracts`

Expected: FAIL because `ea-types` and its public types do not exist.

- [ ] **Step 3: Implement closed newtypes, statuses, and redacted errors**

```rust
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Hash32([u8; 32]);
impl Hash32 {
    pub const ZERO: Self = Self([0; 32]);
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}
impl TryFrom<&[u8]> for Hash32 {
    type Error = LengthError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        value.try_into().map(Self).map_err(|_| LengthError::new(32, value.len()))
    }
}

pub enum SyncStatus { LocallySecured, UploadPending, Synchronized, Error }
pub enum VerificationStatus { Verified, Gap, MissingGrant, UnknownKey, UnsupportedSchema, Invalid }
pub enum EvidenceStatus { Complete, Pending, Overdue, Invalid }
pub enum EntryStatus { Present, AuthorizedDestroyed, UnexplainedGap }
pub enum ErrorClass {
    Domain, LocalResource, TemporaryTransport, TrustSecurity,
    Format, Evidence, RecoveryDestruction,
}
pub enum RetryDisposition {
    CorrectInput, RetainDraftAndBlock, BoundedRetry, FailClosed,
    IsolateObject, PreserveEntryAndReport, ReportExactPartialState,
}
```

Implement the exact §19.1 class-to-disposition mapping shown in the test. `TechnicalError` carries exactly one class and stable code; only `TemporaryTransport` permits automatic bounded retry, with jittered capped backoff and an explicit exhausted state. Implement `Display` and `Debug` using only stable technical codes and non-sensitive numeric metadata. Keep raw secret context inside a non-formatting `Redacted<T>` wrapper solely for immediate control flow; do not implement serialization for it.

- [ ] **Step 4: Run focused tests and lint**

Run: `cargo test --locked -p ea-types && cargo clippy --locked -p ea-types --all-targets -- -D warnings`

Expected: PASS; `CANARY-NAME` never appears in formatted output.

- [ ] **Step 5: Commit the shared type boundary**

```bash
git add crates/ea-types Cargo.toml Cargo.lock
git commit -m "feat(core): add stable identifiers and status types"
```

### Task 4: Bounded Deterministic CBOR

**Files:**
- Create: `crates/ea-cbor/Cargo.toml`
- Create: `crates/ea-cbor/src/lib.rs`
- Create: `crates/ea-cbor/src/encode.rs`
- Create: `crates/ea-cbor/src/decode.rs`
- Create: `crates/ea-cbor/src/limits.rs`
- Test: `crates/ea-cbor/tests/canonical.rs`
- Test: `crates/ea-cbor/tests/limits.rs`
- Create: `fuzz/Cargo.toml`
- Create: `fuzz/Cargo.lock`
- Create: `fuzz/fuzz_targets/cbor_object.rs`

**Interfaces:**
- Consumes: `ea_types::TechnicalErrorCode`.
- Produces: `to_deterministic_vec<T>(&T)`, `BoundedDecoder`, `ParserLimits::V1`, and a parser that rejects floats, indefinite lengths, duplicate map keys, non-minimal integers, invalid UTF-8/NFC fields, and non-canonical order before large allocation.

- [ ] **Step 1: Write canonical and boundary tests**

```rust
#[test]
fn maps_encode_in_rfc_8949_deterministic_order() {
    let map = std::collections::BTreeMap::from([("aa", 1_u64), ("b", 2_u64)]);
    let bytes = ea_cbor::to_deterministic_vec(&map).unwrap();
    assert_eq!(hex::encode(bytes), "a261620262616101");
}

#[test]
fn oversized_and_indefinite_values_fail_before_allocation() {
    let limits = ea_cbor::ParserLimits::V1;
    assert_eq!(ea_cbor::validate(&[0x5f, 0xff], limits).unwrap_err().code(), "EA-CBOR-INDEFINITE");
    let header_for_2_mib = [0x5a, 0x00, 0x20, 0x00, 0x01];
    assert_eq!(ea_cbor::validate(&header_for_2_mib, limits).unwrap_err().code(), "EA-CBOR-ITEM-LIMIT");
}
```

- [ ] **Step 2: Run tests and verify missing deterministic behavior**

Run: `cargo test --locked -p ea-cbor`

Expected: FAIL because the encoder, streaming validator, and limits do not exist.

- [ ] **Step 3: Implement deterministic serialization and a token-budgeted decoder**

```rust
pub const V1: ParserLimits = ParserLimits {
    max_depth: 16,
    max_container_items: 10_000,
    max_total_items: 10_000,
    max_text_or_bytes: 1_048_592,
};

pub fn validate(input: &[u8], limits: ParserLimits) -> Result<(), CborError> {
    let mut decoder = BoundedDecoder::new(input, limits);
    decoder.validate_one()?;
    if !decoder.is_eof() { return Err(CborError::TrailingBytes); }
    Ok(())
}
```

Wrap the selected upstream CBOR library rather than implementing cryptographic primitives. The wrapper must inspect headers before allocating, enforce minimal integer representation, track depth/item counts, compare canonical map-key encodings, reject floats/indefinite items/duplicate keys, and re-encode accepted input to prove byte-for-byte determinism.

`MAX_TOTAL_ITEMS_V1 = 10_000` is an intentional CPU/work bound per top-level
item in addition to the 10,000-element limit per container. Count the top-level
item itself, every array/map container, every map key and value separately, every
tag and tagged value, and every scalar `tstr`, `bstr`, integer, boolean, or null.
tstr/bstr payload byte length does not add tokens. container and total budgets
are cumulative.

- [ ] **Step 4: Run unit, property, and short fuzz smoke tests**

Run:

```bash
cargo test --locked -p ea-cbor
cargo test --locked -p ea-cbor --test canonical --test limits
cargo run --locked -p xtask -- test-fuzz --smoke-seconds 30 --target cbor_object
```

Expected: PASS; the locked root/xtask gate invokes the Task 1-pinned dated Nightly and committed fuzz lockfile, and fuzzing exits without panic, uncontrolled allocation, or accepted non-canonical input.

- [ ] **Step 5: Commit deterministic CBOR**

```bash
git add crates/ea-cbor fuzz/Cargo.toml fuzz/Cargo.lock fuzz/fuzz_targets Cargo.toml Cargo.lock
git commit -m "feat(core): add bounded deterministic CBOR"
```

### Task 5: Cryptographic Suite 1 and Signer Identity Resolution

**Files:**
- Create: `crates/ea-crypto/Cargo.toml`
- Create: `crates/ea-crypto/src/lib.rs`
- Create: `crates/ea-crypto/src/digest.rs`
- Create: `crates/ea-crypto/src/cose.rs`
- Create: `crates/ea-crypto/src/aead.rs`
- Create: `crates/ea-crypto/src/hpke.rs`
- Create: `crates/ea-crypto/src/thumbprint.rs`
- Create: `crates/ea-crypto/src/secret.rs`
- Test: `crates/ea-crypto/tests/suite_v1.rs`
- Test: `crates/ea-crypto/tests/identity.rs`
- Test: `crates/ea-crypto/tests/cose_profile.rs`
- Test: `crates/ea-crypto/tests/aead_hpke.rs`
- Test: `crates/ea-crypto/tests/secret_hygiene.rs`

**Interfaces:**
- Consumes: exact deterministic bytes from `ea-cbor`, identifiers from `ea-types`.
- Produces: `SuiteV1`, domain-separated digest functions, `CoseSigner`, `CoseVerifier`, AEAD seal/open, HPKE seal/open, RFC-9679 thumbprints, and zeroizing `SecretBytes`.

- [ ] **Step 1: Write exhaustive hard-coded known-answer, wire-profile, and identity-coherence tests**

```rust
#[test]
fn suite_v1_domains_do_not_alias() {
    let input = b"same bytes";
    assert_ne!(record_digest(input), object_hash(input).into_hash32());
    assert_ne!(grant_digest(input), receipt_digest(input));
}

#[test]
fn suite_v1_domain_digests_match_known_answers() {
    let input = b"known answer input";
    assert_eq!(hex::encode(record_digest(input)), "bd22d085eac876e0ff43481f554a754010e1543accc876f0b33bc66e8acdb94d");
    assert_eq!(hex::encode(object_hash(input).into_hash32()), "b4d5d9a05190e4b9914c0587995e8d7c50b0a0b91c029631b18bf01a57315609");
}

#[test]
fn normal_and_initial_root_protected_bytes_match_hard_coded_answers() {
    assert_eq!(hex::encode(fixtures::normal_protected_bytes()), fixtures::NORMAL_PROTECTED_HEX);
    assert_eq!(hex::encode(fixtures::initial_root_protected_bytes()), fixtures::INITIAL_ROOT_PROTECTED_HEX);
}

#[test]
fn recovery_test_digest_matches_hard_coded_answer_and_rejects_productive_inputs() {
    let digest = recovery_test_digest(fixtures::challenge32(), fixtures::thumbprint32());
    assert_eq!(hex::encode(digest), fixtures::RECOVERY_TEST_DIGEST_HEX);
    assert!(fixtures::recovery_test_signer().sign(fixtures::production_trust_digest()).is_err());
}

#[test]
fn certificate_hash_and_thumbprint_must_resolve_to_one_certificate() {
    let signature = fixtures::signature_with_mixed_certificate_and_key();
    let err = verify_cose_sign1(&signature, fixtures::trust_set()).unwrap_err();
    assert_eq!(err.code(), "EA-TRUST-SIGNER-MISMATCH");
}
```

Do not generate expected values through the production implementation under
test. Commit literal expected bytes/digests calculated independently. Preserve
the existing Record/Object constants above. Add a hard-coded KAT for **every**
implemented design domain and construction, including ciphertext, package, grant
plan, grant, receipt, trust object, admin-authorized trust, OS account, operator
profile, anchor pre/final, recovery test, checkpoint, renewal input, payload AAD,
HPKE info, and HPKE AAD. Each KAT must pin the exact domain bytes, deterministic
CBOR bytes, concatenated preimage, and final digest/output where applicable.

Pin the complete protected-map bstr bytes for a normal signature, the initial
Root-PoP exception, and the pre-authorization Enrollment-PoP, the exact
`Sig_structure` bytes with empty `external_aad`,
Tag 18, embedded payload, and a 64-byte Ed25519 signature. Test the closed content
type registry and exact payload-to-content-type mapping:

```text
application/vnd.einsatzarchiv.record-digest
application/vnd.einsatzarchiv.grant-digest
application/vnd.einsatzarchiv.receipt-digest
application/vnd.einsatzarchiv.trust-digest
application/vnd.einsatzarchiv.checkpoint+cbor
application/vnd.einsatzarchiv.evidence-renewal+cbor
application/vnd.einsatzarchiv.local-audit+cbor
application/vnd.einsatzarchiv.challenge-response+cbor
application/vnd.einsatzarchiv.device-registration-request+cbor
application/vnd.einsatzarchiv.reader-ack+cbor
application/vnd.einsatzarchiv.recovery-test-digest
```

Add table-driven one-byte mutations over every domain separator, deterministic
CBOR context/AAD/info byte sequence, protected-map byte sequence, payload, and
signature. Add negative fixtures for the deprecated `alg = -8`, unknown or
mismatched content types, unknown,
missing, duplicate, reordered, or wrongly typed `crit` entries, non-empty or
unknown unprotected headers, non-empty `external_aad`, detached payloads, missing
Tag 18, wrong signature length, and mixed certificate/key resolution. Verify the
only allowed unprotected exception is RFC-9921 `3161-ctt` label 270 with a DER-TST
bstr as the sole entry for Checkpoint/Renewal Evidence.
Use one fixed RFC-3161 fixture to pin the complete DER `TimeStampResp` stored in
the `.ecp` separately from the extracted complete DER `TimeStampToken`
(`ContentInfo`) stored as the sole `{270: bstr}` unprotected entry. Assert the
two byte strings are not interchangeable and explicitly reject a COSE object
whose label-270 value is the complete `TimeStampResp`, even when its type is bstr
and it is the sole unprotected entry.
For all `+cbor` protocol signatures, pin and sign only the deterministic unsigned
core bytes. Challenge Response, Device Registration Request, and Reader Ack are
each `[...-core-v1, COSE_Sign1]`; reject signing/verifying a final signaturized
wrapper, a core containing its own signature, or any self-referential form.
Derive their hard-coded Golden Core and wrapper bytes exclusively from the
normative `schemas/protocol/v1/signed-protocol.cddl`; the test must fail if a
plan-local or ad-hoc layout is used.

For the OS-account construction, implement and pin the exact
`os-account-context-v1` / `canonical-os-account-id-v1` union from the separate
normative `schemas/identity/v1/os-account.cddl`.
Hard-code at least these independently derived deterministic-CBOR answers for
the canonical account identifier itself:

```text
Windows S-1-5-21-1-2-3-1000:
830100581c010500000000000515000000010000000200000003000000e8030000
macOS GUID f81d4fae-7dec-11d0-a765-00a0c91e6bf6, UID 501:
84010150f81d4fae7dec11d0a76500a0c91e6bf61901f5
Linux machine-id 0123456789abcdef0123456789abcdef, UID 1000:
840102500123456789abcdef0123456789abcdef1903e8
```

Pin the complete context bytes after prepending fixed 16-byte organization and
device IDs, their domain-concatenated preimage, and final SHA-256. Negative KATs
must reject Windows SID text, wrong revision/count/length/endianness or trailing
bytes; macOS malformed/multiple/null GUIDs, COM-GUID byte swapping, text UID and
`0xffffffff`; and Linux uppercase/empty/all-zero/`uninitialized`/wrong-newline
machine-id, text UID and `0xffffffff`. No test helper may normalize a free string
into the wire value.

Use published upstream KATs where available: RFC 8032 Ed25519, RFC 8439
ChaCha20-Poly1305, RFC 9679 thumbprints, and RFC 9180 Appendix A.2 HPKE Base Mode.
Where an application-composed vector has no published upstream result, use a
committed deterministic fixed-seed fixture and hard-code every input and output.
Test AEAD sizes and overflow (`CEK = 32`, nonce `= 12`, tag/overhead `= 16`,
checked `ciphertextLength = plaintextLength + 16`) and HPKE identifiers/sizes
(`mode = 0`, KEM `0x0020`, KDF `0x0001`, AEAD `0x0003`, `enc = 32`, CEK
ciphertext `= 48`).

- [ ] **Step 2: Run the suite tests and verify failure**

Run: `cargo test --locked -p ea-crypto --test suite_v1 --test identity --test cose_profile --test aead_hpke --test secret_hygiene`

Expected: FAIL because Suite 1 and protected-header resolution do not exist.

- [ ] **Step 3: Implement Suite 1 exclusively through reviewed upstream primitives**

```rust
pub const SUITE_ID: &str = "EINSATZARCHIV-SUITE-1";
pub const GRANT_SUITE_ID: &str = "EINSATZARCHIV-HPKE-1";

pub fn record_digest(bytes: &[u8]) -> Hash32 {
    sha256_parts(&[b"EINSATZARCHIV-RECORD-v1", bytes])
}
pub fn object_hash(bytes: &[u8]) -> ObjectHash {
    ObjectHash(sha256_parts(&[b"EINSATZARCHIV-OBJECT-v1", bytes]))
}

pub struct ProtectedSigner {
    pub algorithm: Algorithm,
    pub key_thumbprint: KeyThumbprint,
    pub certificate_hash: CertificateHash,
    pub content_type: ContentType,
    pub critical: Vec<HeaderLabel>,
}
```

Implement all design domain strings literally, including ciphertext, package, grant plan, grant, receipt, trust object, admin-authorized trust, OS account, operator profile, anchor pre/final, recovery test, checkpoint, and renewal input. Keep the symbolic `keyThumbprint` API, but serialize it exactly as protected COSE `kid` label 4. Implement normal protected headers exactly as `{1:-19, 2:[3,4,"certificateHash"], 3:<closed Einsatzarchiv tstr>, 4:bstr32, "certificateHash":bstr32}`, initial Root-PoP exactly as `{1:-19,2:[3,4],3:"application/vnd.einsatzarchiv.trust-digest",4:bstr32}`, and pre-authorization Enrollment-PoP exactly as `{1:-19,2:[3,4],3:"application/vnd.einsatzarchiv.device-registration-request+cbor",4:bstr32}`. RFC 9864 fully specifies Ed25519 as `-19`; reject the deprecated polymorphic RFC-9053 EdDSA value `-8`. Encode the map using RFC-8949 Core Deterministic Encoding and embed those bytes as a bstr. Use exactly RFC-9052 `Sig_structure = ["Signature1", protected, h'', payload]`, Tag 18, embedded payload, and 64-byte Ed25519 signatures.

Validate every OS-account source before CBOR encoding: Windows revision `1`,
count `1..15`, exact `8 + 4 * count` bytes and little-endian u32
SubAuthorities; macOS exactly one nonzero RFC-9562 GUID decoded without
COM-GUID swapping and a matching UID in `0..4294967294`; Linux exactly one
nonzero 16-byte machine ID from `sd_id128_get_machine()` or the strict file
fallback and UID in `0..4294967294`. Fail closed before hashing on any mismatch.
Raw account identifiers and source strings must never be persisted, logged, or
exported; retain only the domain-separated hash. Do not replace the specified
literal Linux machine ID with an app-specific derivation without a reviewed
normative design revision.

Reject every content type outside the closed registry and every payload/content-type mismatch. Enforce empty unprotected COSE headers except RFC-9921 `3161-ctt` label 270 as the sole unprotected DER-TST bstr for Checkpoint/Renewal Evidence in Stage 6. Initial Root-PoP is the sole `certificateHash` exception among authorized operational/archive signatures. Enrollment-PoP is a separate pre-authorization variant: its payload is exactly deterministic CBOR of unsigned `device-registration-request-core-v1`, and the final request is `[core, COSE_Sign1]`; reject the final request, a core containing `self-signature`, or any self-referential bytes as a signature payload. Validate it only against the core-embedded signing key, never route it through `SignerCertificateResolver`, and never infer role, Trust, archive, or device authority. Task 5 may expose and validate this closed profile variant for Stage 3 without implementing the Stage-3 enrollment workflow. Reject Enrollment-PoP in ordinary and Trust-signature resolver paths. Challenge Response and Reader Ack similarly sign only their unsigned core bytes. Initial Root and Root rotation each have exactly one outer signature; the rotation signer is the previous accepted Root line, while Admin authorization is hash-bound in the authorized payload and is not an outer signature.

Implement Recovery-Test-Digest exactly as `SHA-256("EINSATZARCHIV-RECOVERY-TEST-v1" || deterministicCbor([1, random-challenge: bstr .size 32, key-thumbprint: bstr .size 32]))`; its signing path must reject raw productive payloads and productive Trust digests. Use a 32-byte CEK, 12-byte nonce, 16-byte tag, and checked length addition. Fix HPKE to Base `0`, KEM `0x0020`, KDF `0x0001`, AEAD `0x0003`, `enc = 32`, and wrapped CEK `= 48`.

Zeroize CEKs, nonces held as secret state, plaintext serialization buffers, HPKE shared secrets, deterministic fixture secrets, and recovery challenges on drop. Add instrumentation-backed zeroize tests that observe the owned backing storage after drop where the abstraction permits it, plus error/debug/display/log-capture tests proving private keys, CEKs, shared secrets, plaintext fixture canaries, and recovery challenges never appear in formatted errors, tracing, panic payloads, or snapshots.

- [ ] **Step 4: Run KAT, one-byte mutation, and misuse tests**

Run: `cargo test --locked -p ea-crypto`

Expected: PASS; hard-coded domain/AAD/info, COSE protected-byte, Ed25519,
RFC-9679, AEAD, and HPKE vectors match; every one-byte mutation,
certificate/thumbprint mismatch, unknown content type/`crit`/unprotected value,
non-empty `external_aad`, Root-/Enrollment-exception misuse, overflow, secret-retention, and
secret-leakage fixture is rejected.

- [ ] **Step 5: Commit Suite 1**

```bash
git add crates/ea-crypto Cargo.toml Cargo.lock
git commit -m "feat(core): implement cryptographic suite one"
```

### Task 6: Exact Archive Objects, Grants, Receipts, and Parser Limits

**Files:**
- Create: `crates/ea-format/Cargo.toml`
- Create: `crates/ea-format/src/lib.rs`
- Create: `crates/ea-format/src/object.rs`
- Create: `crates/ea-format/src/eip.rs`
- Create: `crates/ea-format/src/eag.rs`
- Create: `crates/ea-format/src/esr.rs`
- Create: `crates/ea-format/src/ecp.rs`
- Create: `crates/ea-format/src/etb.rs`
- Create: `crates/ea-format/src/eds.rs`
- Create: `crates/ea-format/src/parser.rs`
- Test: `crates/ea-format/tests/object_roundtrip.rs`
- Test: `crates/ea-format/tests/grant_plan.rs`
- Test: `crates/ea-format/tests/negative.rs`

**Interfaces:**
- Consumes: `ea-cbor`, `ea-crypto`, `ea-types`, reviewed CDDL from Task 2.
- Produces: non-relaxable `decode_exact_object(bytes)`, exact encoders for all six types, `ManifestCoreV1`, `GrantPlanV1`, `GrantV1`, `ReceiptCoreV1`, `DestroyedEntryStubV1`, and opaque `ExactObjectBytes`.

- [ ] **Step 1: Write fixed-position, grant-plan, and negative tests**

```rust
#[test]
fn grant_plan_is_total_sorted_unique_and_has_one_recovery() {
    let plan = GrantPlanV1::new(vec![fixtures::reader_b(), fixtures::recovery(), fixtures::reader_a()]).unwrap();
    assert_eq!(plan.items(), &[fixtures::recovery(), fixtures::reader_a(), fixtures::reader_b()]);
    assert_eq!(plan.hash(), fixtures::expected_grant_plan_hash());
    assert_eq!(GrantPlanV1::new(vec![fixtures::recovery(), fixtures::recovery()]).unwrap_err().code(),
               "EA-GRANT-DUPLICATE-RECOVERY");
}

#[test]
fn top_level_and_manifest_tags_must_match() {
    let bytes = fixtures::eip_with_manifest_object_type(2);
    assert_eq!(decode_exact_object(&bytes).unwrap_err().code(),
               "EA-FORMAT-TAG-MISMATCH");
}

#[test]
fn manifest_ciphertext_length_matches_the_exact_ciphertext_bstr() {
    let encoded = fixtures::encode_eip_from_ciphertext(vec![0; 17]);
    assert_eq!(fixtures::manifest_ciphertext_length(&encoded), 17);
    assert_eq!(fixtures::exact_ciphertext_bstr(&encoded).len(), 17);

    for mismatch in [
        fixtures::eip_with_declared_and_actual_ciphertext_lengths(16, 17),
        fixtures::eip_with_declared_and_actual_ciphertext_lengths(18, 17),
    ] {
        assert_eq!(decode_exact_object(&mismatch).unwrap_err().code(),
                   "EA-FORMAT-CIPHERTEXT-LENGTH");
    }
}
```

The first mismatch is declared shorter than actual; the second is declared
longer than actual, and both lengths remain within 16..1_048_592. These are
semantic negative tests, not CDDL range tests.

The prefix/limit negative suite MUST cover this exact table, where each tuple is
`(family, exact accepted preflight boundary, first rejected raw length)`:

```text
(.eip, 2_097_152, 2_097_153)
(.eag, 65_536, 65_537)
(.esr, 65_536, 65_537)
(.ecp, 4_194_304, 4_194_305)
(.etb, 4_194_304, 4_194_305)
(.eds, 262_144, 262_145)
```

For every row, encode and assert the exact nine prefix bytes listed in Step 3.
At the exact boundary, a fixture with that exact prefix and a deliberately
malformed body MUST pass the applicable raw-size preflight and reach the expected
full-CBOR/body error. At the first rejected length, the same malformed body MUST
fail at the applicable earlier raw-size stage. For families below the global cap,
the malformed oversized body MUST return the family raw-limit error before any
full-CBOR/body error and before any input-sized allocation. Because `.ecp` and
`.etb` equal the global cap, their `4_194_305` fixtures MUST return the global
raw-limit error in Stage 1 before prefix inspection. Use an allocation probe in
these negatives and assert zero allocations proportional to the supplied input.

- [ ] **Step 2: Run focused tests and confirm format constructors are absent**

Run: `cargo test --locked -p ea-format --test object_roundtrip --test grant_plan --test negative`

Expected: FAIL because exact format models and parsers are not implemented.

- [ ] **Step 3: Implement typed positional models and exact-byte preservation**

```rust
pub enum ParsedArchiveObject {
    Entry(Parsed<EntryPackageV1>),
    Grant(Parsed<GrantV1>),
    Receipt(Parsed<ReceiptV1>),
    Evidence(Parsed<EvidenceObjectV1>),
    Trust(Parsed<TrustObjectV1>),
    Destroyed(Parsed<DestroyedEntryStubV1>),
}

pub struct Parsed<T> {
    value: T,
    exact_bytes: ExactObjectBytes,
    object_hash: ObjectHash,
}

pub fn decode_exact_object(bytes: &[u8])
    -> Result<ParsedArchiveObject, FormatError>;
```

The public v1 seam is non-relaxable and uses this exact preflight contract:

```text
MAX_ARCHIVE_OBJECT_BYTES_V1 = 4_194_304
FIXED_PREFIX_V1 = 85 44 45 41 31 00 TT 01 80
TT = 01..06
EIP_PREFIX_V1 = 85 44 45 41 31 00 01 01 80
EAG_PREFIX_V1 = 85 44 45 41 31 00 02 01 80
ESR_PREFIX_V1 = 85 44 45 41 31 00 03 01 80
ECP_PREFIX_V1 = 85 44 45 41 31 00 04 01 80
ETB_PREFIX_V1 = 85 44 45 41 31 00 05 01 80
EDS_PREFIX_V1 = 85 44 45 41 31 00 06 01 80
EIP_MAX_RAW_BYTES_V1 = 2_097_152
EAG_MAX_RAW_BYTES_V1 = 65_536
ESR_MAX_RAW_BYTES_V1 = 65_536
ECP_MAX_RAW_BYTES_V1 = 4_194_304
ETB_MAX_RAW_BYTES_V1 = 4_194_304
EDS_MAX_RAW_BYTES_V1 = 262_144
```

`PREFLIGHT_STAGE_1_GLOBAL_RAW_CAP`: first require
`bytes.len() <= MAX_ARCHIVE_OBJECT_BYTES_V1` before any CBOR inspection.

`PREFLIGHT_STAGE_2_EXACT_PREFIX`: inspect only the first nine bytes and accept
exactly one of `EIP_PREFIX_V1` through `EDS_PREFIX_V1`; no other encoding of magic,
type, version, or the empty extension array selects a family. File names are
untrusted.

`PREFLIGHT_STAGE_3_FAMILY_RAW_CAP`: immediately enforce the selected family raw
cap before full validation, body decoding, or input-sized allocation. An input at
the cap proceeds; its first byte over the cap fails here. (`.ecp`/`.etb` first
fail at Stage 1 because their cap equals the global cap.)

`PREFLIGHT_STAGE_4_FULL_CBOR_AND_BODY`: only after the preceding stages succeed,
run full deterministic-CBOR validation, decode the body, and enforce outer/body
type correlation. A malformed oversized body cannot replace the earlier raw-limit
error with a CBOR/body error.

`ea-cbor::ParserLimits::V1` owns structural CBOR budgets; `ea-format` owns family
raw-byte and semantic limits.

`MANIFEST_CIPHERTEXT_LENGTH_RULE_V1 = ACTUAL_EXACT_CIPHERTEXT_BSTR_LENGTH` is a
semantic v1 invariant: `manifestCore.ciphertext-length` MUST equal the actual
exact ciphertext `bstr` length; encoders MUST derive
`manifestCore.ciphertext-length` from the exact ciphertext `bstr` bytes; callers
cannot supply an independent declared value. Decoders reject either mismatch
direction before returning a parsed object. CDDL range checks do not establish
this cross-field equality; they only constrain each value independently.

For destruction authorizations, `sorted-targets` is nonempty and ascending by
`(entryHash bytes, chainSequence numeric)`: unsigned bytewise `entryHash`, then
unsigned numeric `chainSequence`. Target identity is entryHash; any repeated
entryHash is invalid even with a different sequence, while `chainSequence` is a
signed-manifest cross-check. Equal chainSequence values with different entryHash
values are not duplicates. Future Task-6 negative tests reject unsorted tuples,
exact duplicate tuples, and repeated hashes with conflicting sequences.

Decode arrays positionally, verify magic/type/version/critical extensions twice where required, preserve exact input bytes, and never serialize a parsed object merely to compute its object hash. Derive `entryHash` only from `recordDigest` and exact COSE signature bytes. Initial grant creation signs `grantBody`, including encapsulated key and wrapped CEK. Receipt hash lists are bytewise sorted and duplicate-free.

- [ ] **Step 4: Run all format and mutation tests**

Run: `cargo test --locked -p ea-format`

Expected: PASS for every object family; one-byte changes, duplicate keys/hashes, overflow, non-empty v1 critical extensions, and unknown object versions fail closed.

- [ ] **Step 5: Commit exact object formats**

```bash
git add crates/ea-format Cargo.toml Cargo.lock
git commit -m "feat(core): implement exact archive object formats"
```

### Task 7: Versioned Payload Schemas and Compatibility Registry

**Closed normative prerequisite (2026-08-14):** Task 7 MUST consume, without
reinterpreting, the exact 11-position deterministic-CBOR families in
`schemas/payload/v1/payload.cddl`, the payload-wire addendum, and the five
literal `vectors/format/payload-v1/*.hex` fixtures. The correction also pins
`jiff = 0.2.35`, `jiff-tzdb = 0.1.8`, embedded IANA tzdb `2026c`, the
canonical-name lookup route, and the local-calendar-year basis. It creates no
`ea-schema`, JSON payload schema, or compatibility matrix itself.

`xtask` uses `JsonSchemaProfile::DeterministicReport` for deterministic report
schemas and `JsonSchemaProfile::PayloadProjection` for payload projections.
Both recursively require closed objects. Only the report profile requires
`x-ea-sort-key`, `x-ea-unique-key`, and `uniqueItems`; ordered authoring arrays
for personnel, vehicles, and external organizations remain valid without a
sort key under the payload profile.

**Files:**
- Consume: `schemas/payload/v1/payload.cddl`
- Consume: `docs/superpowers/specs/2026-08-14-einsatzarchiv-v0-1-payload-wire-addendum.md`
- Consume: `vectors/format/payload-v1/{genesis,incident,amendment,key-transition,destruction-evidence}.hex`
- Create: `crates/ea-schema/Cargo.toml`
- Create: `crates/ea-schema/src/lib.rs`
- Create: `crates/ea-schema/src/v1.rs`
- Create: `crates/ea-schema/src/registry.rs`
- Create: `crates/ea-schema/src/transform.rs`
- Create: `schemas/payload/v1/incident.schema.json`
- Create: `schemas/payload/v1/amendment.schema.json`
- Create: `schemas/payload/v1/genesis.schema.json`
- Create: `schemas/payload/v1/key-transition.schema.json`
- Create: `schemas/payload/v1/destruction-evidence.schema.json`
- Create: `schemas/compatibility-matrix.json`
- Test: `crates/ea-schema/tests/v1_validation.rs`
- Test: `crates/ea-schema/tests/compatibility.rs`

**Interfaces:**
- Consumes: primitive IDs/time types, deterministic CBOR, the exact payload
  CDDL/vectors, and only the bundled tzdb `2026c` through the reviewed exact
  workspace pins.
- Produces: `SchemaRegistry::validate`, `SchemaRegistry::derive_view`,
  `PayloadV1`, `UnsupportedSchema`, and the single-payload incident-number key
  `(organizationId, localCivilYear, NFC UTF-8 number bytes)`; no historical
  byte mutation and no cross-record uniqueness enforcement.

- [ ] **Step 1: Write payload boundary and unsupported-schema tests**

```rust
#[test]
fn patient_count_zero_unknown_and_positive_are_distinct() {
    assert!(incident(patient_status("known", Some(0))).validate().is_ok());
    assert!(incident(patient_status("known", Some(3))).validate().is_ok());
    assert!(incident(patient_status("unknown", None)).validate().is_ok());
    assert_eq!(incident(patient_status("unknown", Some(0))).validate().unwrap_err().field(), "patientCount");
}

#[test]
fn unknown_schema_is_not_an_empty_incident() {
    let result = SchemaRegistry::v1().derive_view("ea.incident", 99, b"bytes");
    assert!(matches!(result, Err(SchemaError::Unsupported { .. })));
}
```

Add literal-vector tests that decode exactly one 11-item array, pin full hex
and exact `recordType`/`schemaId`/version pairs, enforce UUIDv7 bits, and prove
append/truncate/family/schema/version mutations fail. The incident fixture MUST
retain its ordinary Zulu-before-Alpha authoring list and reject a Float
coordinate. Every fixture MUST validate against its CDDL family root and remain
byte-identical under `ea-cbor` canonical re-encoding.

Add timezone tests that construct only `TimeZoneDatabase::bundled()`, compare
the input byte-for-byte with the canonical name returned by `jiff_tzdb::get`,
and reject case variants plus `Etc/Unknown`. Pin the observed database version
`2026c` and both year boundaries:

```text
1798763400000 in America/New_York -> 2026
1798759800000 in Europe/Berlin -> 2027
```

Changing `finalizedAtDevice` or a UI-like `YYYY-` number prefix MUST NOT change
the derived local year.

- [ ] **Step 2: Run schema tests and verify failure**

Run: `cargo test --locked -p ea-schema`

Expected: FAIL because the registry and v1 validators are missing.

- [ ] **Step 3: Implement v1 typed variants and their own historical rules**

```rust
pub enum PayloadV1 {
    Genesis(GenesisV1),
    Incident(IncidentV1),
    Amendment(AmendmentV1),
    KeyTransition(KeyTransitionV1),
    DestructionEvidence(DestructionEvidenceV1),
}

pub enum PatientCount {
    Known(u32),
    Unknown,
}
```

Map the Rust models and encoder/decoder exactly to the committed CDDL arrays;
JSON Schemas are closed logical projections and never an alternate byte
authority. Enforce UUIDv7 record IDs; signed-`i64` epoch milliseconds; Unicode
NFC; no floats; only source tag `0` native; v1 `extensionData = []`; and exact
family/schema/version pairs. Use the explicitly constructed bundled database,
never `/usr/share/zoneinfo`, `TZ`, `TZDIR`, a system timezone, or Jiff's global
database.

`IncidentV1` requires a 1–64-character `humanIncidentNumber`, interval start
with optional end not before start, 1–128-character keyword/reference,
integer-E7 coordinates, at most 200 personnel and 100 vehicles with a required
nonempty reason for either empty list, `PatientCount::Known(nonnegative)` or
`Unknown`, optional notes of at most 20,000 characters with no registered
patient-identifying fields, and at most 100 external organizations. Personnel,
vehicle, and external-organization lists preserve authoring order. Derive the
local-year key from `occurredAt.start` in the payload timezone using tzdb
`2026c`; do not enforce repository-wide uniqueness in this crate.

`GenesisV1` binds organization, chain, initial Writer certificate, format,
suite, and initial policy. `AmendmentV1` binds original incident number/record
ID/Entry hash/sequence, reason, and nonempty structured changes; the common
operator snapshot is its creator and is not duplicated in the body.
`KeyTransitionV1` binds the public Writer-transition event hash plus encrypted
organizational reason. `DestructionEvidenceV1` binds targets, authorization,
scope, execution results, Stub hashes, attestations, and explicit
successful/pending/unreachable replicas without asserting unconfirmed
deletion. Generate and validate `schemas/compatibility-matrix.json` from the
same Rust registry. A derived old view names source and target schema and never
replaces verified source bytes.

- [ ] **Step 4: Run validation and cross-version fixture tests**

Run: `cargo test --locked -p ea-schema && cargo run --locked -p xtask -- validate-schemas`

Expected: PASS; `legacyImport`, `legacy-access-import`, alternate source tags,
floats, non-NFC strings, noncanonical/unknown timezone names, unknown critical
namespaces, oversized plaintext, and unsupported suites/schemas fail with
distinct errors. Existing deterministic-report sorted/duplicate-key tests
remain green, while payload projection authoring arrays need no report sort
extensions.

- [ ] **Step 5: Commit payload schemas**

```bash
git add crates/ea-schema schemas/payload schemas/compatibility-matrix.json Cargo.toml Cargo.lock
git commit -m "feat(core): add versioned payload schemas"
```

### Task 8: Trust/Time v1 Closure, then Runtime Verification

Task 8 is split into two atomic phases. The prerequisite normative/wire
correction is
[`2026-08-14-einsatzarchiv-task-8-trust-time-normative-correction.md`](2026-08-14-einsatzarchiv-task-8-trust-time-normative-correction.md).
Only after that phase is atomically integrated may Runtime Phase B execute the
authoritative plan
[`2026-08-14-einsatzarchiv-task-8-trust-time-implementation.md`](2026-08-14-einsatzarchiv-task-8-trust-time-implementation.md).
The latter owns all `ea-time`/`ea-trust` files, proof states, historical state
traversal, replay persistence, and activation semantics; Phase A creates none of
them.

**Files:**
- Create: `crates/ea-time/Cargo.toml`
- Create: `crates/ea-time/src/lib.rs`
- Create: `crates/ea-trust/Cargo.toml`
- Create: `crates/ea-trust/src/lib.rs`
- Create: `crates/ea-trust/src/anchor.rs`
- Create: `crates/ea-trust/src/certificate.rs`
- Create: `crates/ea-trust/src/admin_authorization.rs`
- Create: `crates/ea-trust/src/registry.rs`
- Create: `crates/ea-trust/src/policy.rs`
- Create: `crates/ea-trust/src/operator_binding.rs`
- Create: `crates/ea-trust/src/clock_release.rs`
- Test: `crates/ea-time/tests/effective_now.rs`
- Test: `crates/ea-trust/tests/bootstrap.rs`
- Test: `crates/ea-trust/tests/registry_attacks.rs`
- Test: `crates/ea-trust/tests/clock_release.rs`

**Interfaces:**
- Consumes: exact `.etb` bytes, crypto identity resolution, IDs/time types.
- Produces: `EffectiveNow`, `VerifiedTrust`, `VerifiedAdminAuthorization`, and
  `RegistrySelectionOutcome` with `Selected(SelectedRegistryHead)`,
  `Advanced(AdvancedRegistryHead)`, and
  `PendingFuture(PendingFutureSuccessor)`, plus capability checks used by all
  clients/server.

- [ ] **Step 1: Write clock, bootstrap, and head-selection attack tests**

```rust
#[test]
fn wall_clock_rollback_never_reduces_effective_now() {
    let state = TrustedTimeState::new(UnixMillis(2_000));
    let now = effective_now(UnixMillis(1_000), state, &[]).unwrap();
    assert_eq!(now.millis(), UnixMillis(2_000));
    assert_eq!(now.warning(), Some(TimeWarning::ClockRollback));
}

#[test]
fn null_context_accepts_only_anchor_pinned_admin_pair_once() {
    assert!(verify_bootstrap(fixtures::pinned_pair(), fixtures::pre_anchor()).is_ok());
    assert_eq!(verify_bootstrap(fixtures::unpinned_root_signed_pair(), fixtures::pre_anchor()).unwrap_err().code(),
               "EA-TRUST-BOOTSTRAP-UNPINNED");
    assert_eq!(verify_bootstrap_after_first_head(fixtures::pinned_pair()).unwrap_err().code(),
               "EA-TRUST-BOOTSTRAP-CLOSED");
}
```

- [ ] **Step 2: Run trust tests and verify failure**

Run: `cargo test --locked -p ea-time -p ea-trust`

Expected: FAIL because no anchor, admin authorization, Registry, or effective-time evaluator exists.

- [ ] **Step 3: Execute the authoritative Runtime Phase-B plan**

The sole source for `TrustObjectSource`, validated `TrustStateSnapshot`,
`verify_trust`, mutable `LocalTimeBlock` preparation/release verification, and
the complete `RegistrySelectionOutcome` is
[`2026-08-14-einsatzarchiv-task-8-trust-time-implementation.md`](2026-08-14-einsatzarchiv-task-8-trust-time-implementation.md).
This Stage-1 overview deliberately does not duplicate those public signatures or
collapse Pending/Advanced outcomes into a selected-only return.

The archive adapter implements visitor-based
`TrustObjectSource::visit_trust_object_hashes` without first cloning an
unbounded hash list. It enforces and reports the versioned limits
`MAX_TRUST_OBJECTS_V1 = 65_536` and
`MAX_TOTAL_TRUST_OBJECT_BYTES_V1 = 268_435_456` while scanning, before adding
the next inventory record. `ea-trust` independently rechecks the count and uses
`checked_add` on the exact unique ETB lengths before decode and `before
retention`; failures stay distinct as `EA-TRUST-SOURCE-COUNT-LIMIT` and
`EA-TRUST-SOURCE-BYTE-LIMIT`. Each file read is independently bounded by the
existing ETB raw limit before allocation.

Build the preexisting floor only from persisted state, previously activated
Registry times, and fully verified Receipt/Checkpoint/TSA references; the current
candidate cannot self-activate. Verify historical chain, previous-head/+1,
Action/Change, activation, Policy and authorization-time correlations into an
opaque `RegistryCandidate`. Decide future skew against its guard Policy and the
deterministic independent reference. A Clock Release can only discharge that
specific skew block. Then apply `issuedAt`/`notBefore`, select the head, and only
after selection atomically persist candidate floor, head pin, and any by-value
release replay consumption. Future heads remain pending. No public proof
constructor or raw-CBOR escape hatch exists.

- [ ] **Step 4: Run the full positive/negative trust vector matrix**

Run: `cargo test --locked -p ea-time -p ea-trust`

Expected: PASS; Root-only, Admin-only, wrong core/action, self-admin rotation, mismatched OS/instance binding, replayed nonce/ID, future-only head, stale strict Registry, clock rollback, mismatched/expired clock release, and replayed release all fail exactly as designed.

- [ ] **Step 5: Commit trust and time evaluation**

```bash
git add crates/ea-time crates/ea-trust Cargo.toml Cargo.lock
git commit -m "feat(core): verify anchors registry and trusted time"
```

### Task 9: Chain, Archive Inventory, and Verification Pipeline

**Files:**
- Create: `crates/ea-chain/Cargo.toml`
- Create: `crates/ea-chain/src/lib.rs`
- Create: `crates/ea-archive/Cargo.toml`
- Create: `crates/ea-archive/src/lib.rs`
- Create: `crates/ea-archive/src/layout.rs`
- Create: `crates/ea-archive/src/inventory.rs`
- Create: `crates/ea-verify/Cargo.toml`
- Create: `crates/ea-verify/src/lib.rs`
- Create: `crates/ea-verify/src/entry.rs`
- Create: `crates/ea-verify/src/archive.rs`
- Create: `crates/ea-verify/src/report.rs`
- Test: `crates/ea-chain/tests/gaps_forks.rs`
- Test: `crates/ea-verify/tests/order.rs`
- Test: `crates/ea-verify/tests/filename_independence.rs`

**Interfaces:**
- Consumes: parsed exact objects, verified trust, schema registry.
- Produces: `ArchiveInventory`, `VerifiedEncryptedEntry`, `VerifiedChain`, `VerificationReportV1`, and `verify_archive`; filenames are hints only.

**wasm32-Pflicht.** `ea-chain`, `ea-archive` und `ea-verify` MÜSSEN in die Positivliste des wasm32-Gates in `tools/xtask/src/main.rs` aufgenommen werden, und dieser Task MUSS `tools/xtask/tests/workspace.rs` um eine Klassifikationszusicherung erweitern: jedes Mitglied unter `crates/` steht entweder in der wasm32-Positivliste oder in einer ausdrücklich begründeten Ausnahmeliste; ein neues Mitglied ohne Zuordnung lässt den Test fehlschlagen. Grund: `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §9 macht die Verifikationspipeline zu geteiltem Rust-Code, der im Browser läuft, und §10 macht `wasm32-unknown-unknown` zum verbindlichen Gate-Ziel.

Drei konkrete Fallen: die dateisystemgestützte `ArchiveSource`-Implementierung gehört hinter ein Nicht-Default-Feature oder außerhalb der Crate; Zeit wird als Parameter übergeben statt über `SystemTime::now()` bezogen; JSON-Schema-Validierung des Reports gehört NICHT in `ea-verify`, weil `jsonschema` `getrandom 0.3.4` in den wasm-Graph zöge — und 0.3.4 benötigt auf `wasm32` zusätzlich das `--cfg getrandom_backend`, das in `docs/superpowers/plans/2026-08-16-einsatzarchiv-web-reader-stage-1-prerequisites.md` bewusst nicht gesetzt wird.

**Reportform, verbindlich** (geschlossen in `docs/superpowers/plans/2026-08-16-einsatzarchiv-task-9-phase-a-report-and-gate-order.md`). `VerificationReportV1` trägt `formatErrors` und `quarantinedObjects` — Grund aus dem geschlossenen Enum `malformed`/`duplicate`/`conflicting`/`unattributable` — sowie je Objektergebnis `serverConfirmation` mit den Werten `serverConfirmed`/`notServerConfirmed` als eigene Dimension **neben** `result`. Die Server-Bestätigung wird ausdrücklich NICHT in `result` hineingefaltet; `design.md` §17.4 verbietet die Vermischung. Fail-closed bleibt unangetastet: ein quarantänisiertes Objekt DARF NIEMALS dazu führen, dass der Bestand als vollständig verifiziert dargestellt wird, und `notServerConfirmed` ist kein Mangel. Die JSON-Schema-Validierung des Reports gehört NICHT in `ea-verify` — `jsonschema` zöge `getrandom 0.3.4` in den wasm-Graph — sondern in `xtask` und die Tests.

**Adapterverhältnis, verbindlich.** `ArchiveSource` ist der neue, breitere Port über **alle** Archivbytes; `TrustObjectSource` (`crates/ea-trust/src/source.rs`) bleibt unverändert der schmale, archiv-agnostische Trust-Port. `ea-archive` liefert den offiziellen `ArchiveInventory`-Adapter, der `TrustObjectSource` **implementiert** — es wird nichts dupliziert, und `ea-trust` erfährt nichts über Archivlayout. Der Adapter ruft den Visitor direkt beim Durchlaufen seines beschränkten Trust-Index auf, hält vor dem nächsten Element an, sobald der Visitor einen Fehler liefert, und baut ausdrücklich **keinen** zwischenzeitlichen unbeschränkten `Vec` von Hashes (`2026-08-14-einsatzarchiv-task-8-trust-time-implementation.md:614-617`). Die Schranken `MAX_TRUST_OBJECTS_V1` und `MAX_TOTAL_TRUST_OBJECT_BYTES_V1` gelten unverändert und werden nicht neu definiert.

- [ ] **Step 1: Write verification-order and filename-independence tests**

```rust
#[test]
fn verification_stops_before_grant_or_decryption_on_bad_signature() {
    let events = RecordingVerifier::run(fixtures::bad_writer_signature()).unwrap_err().events;
    assert_eq!(events, ["format", "trust", "registry", "manifest-signature"]);
    assert!(!events.contains(&"hpke-open"));
}

#[test]
fn a_fully_valid_entry_records_every_gate_in_order_before_decryption() {
    let events = RecordingVerifier::run(fixtures::complete_valid_entry()).unwrap().events;
    assert_eq!(
        events,
        [
            "format",
            "trust",
            "registry",
            "manifest-signature",
            "chain-position",
            "grant-plan",
            "receipt",
            "evidence",
            "recipient-grant",
            "hpke-open",
        ]
    );
}

#[test]
fn renamed_objects_rebuild_the_same_chain() {
    let canonical = fixtures::canonical_paths();
    let randomized = fixtures::randomized_paths();
    let a = verify_archive(&canonical, fixtures::anchor(), VerifyOptions::default()).unwrap();
    let b = verify_archive(&randomized, fixtures::anchor(), VerifyOptions::default()).unwrap();
    assert_eq!(a.chain_head(), b.chain_head());
}
```

Die neun Gate-Bezeichner sind normativ in `design.md` §14.1 festgelegt und gelten unverändert im Browser (`2026-08-15-einsatzarchiv-web-reader-design.md` §9). `hpke-open` ist kein Gate, sondern die auf das neunte folgende Entkapselung.

**Signaturfestlegung:** `fixtures::canonical_paths()` und `fixtures::randomized_paths()` liefern je einen Typ, der `ArchiveSource` implementiert — keine `Vec<PathBuf>`. Der Aufruf `&canonical` ist damit die Unsize-Coercion auf `&dyn ArchiveSource`, kein Typwechsel gegenüber der Signatur in Step 3.

- [ ] **Step 2: Run focused tests and verify failure**

Run: `cargo test --locked -p ea-chain -p ea-verify`

Expected: FAIL because inventory and proof-state verification do not exist.

- [ ] **Step 3: Implement reconstruction from bytes and ordered proof states**

```rust
pub fn verify_archive(
    source: &dyn ArchiveSource,
    anchor: &TrustAnchorV1,
    options: VerifyOptions,
) -> Result<VerificationReportV1, VerifyError>;

pub fn verify_entry(
    object: &Parsed<EntryPackageV1>,
    trust: &VerifiedTrust,
    predecessor: Option<&VerifiedEncryptedEntry>,
) -> Result<VerifiedEncryptedEntry, VerifyError>;
```

Implement the exact archive layout `trust/{organization.etb,registry-events/,operator-bindings/,authorizations/}`, `entries/`, `destroyed-entries/`, `grants/`, `receipts/`, `checkpoints/`, `destructions/<destruction-id>/{events,attestations}/`, `format/{schemas,transformations,compatibility-matrix.json}`, `recovery-reports/`, and `README-FORMAT.txt`. Inventory all bytes by parsed type and object hash, treating every filename only as a hint; quarantine malformed/duplicate/conflicting objects, reconstruct Trust and chain from content, and enforce Genesis sequence 0 followed by exact increments and predecessor hashes. Verify format, Trust/Registry/Writer, signed manifest and hashes, transition, grant plan/Recovery grant, Receipt/checkpoint/evidence when present, and recipient grant in that order. A valid `.eds` preserves chain identity and becomes `AuthorizedDestroyed`; missing `.eip` without a complete Stub/authorization/evidence chain remains `UnexplainedGap`.

- [ ] **Step 4: Run chain, archive, and mutation tests**

Run: `cargo test --locked -p ea-chain -p ea-archive -p ea-verify`

Expected: PASS; gap, swap, fork, rollback, orphan grant, unknown Writer, invalid Stub, and filename manipulation have distinct deterministic outcomes.

- [ ] **Step 5: Commit verification pipeline**

```bash
git add crates/ea-chain crates/ea-archive crates/ea-verify Cargo.toml Cargo.lock
git commit -m "feat(core): verify archive trust and chain"
```

### Task 10: Recovery CLI Baseline and Deterministic Reports

**Files:**
- Create: `crates/ea-recovery/Cargo.toml`
- Create: `crates/ea-recovery/src/lib.rs`
- Create: `crates/ea-recovery/src/verify.rs`
- Create: `crates/ea-recovery/src/decrypt.rs`
- Create: `crates/ea-recovery/src/export.rs`
- Create: `crates/ea-recovery/src/report.rs`
- Create: `apps/cli/Cargo.toml`
- Create: `apps/cli/src/main.rs`
- Create: `apps/cli/src/args.rs`
- Create: `apps/cli/src/output.rs`
- Create: `apps/cli/src/commands/{verify,list,decrypt,report,export}.rs`
- Test: `apps/cli/tests/commands.rs`
- Test: `apps/cli/tests/exit_codes.rs`
- Test: `apps/cli/tests/determinism.rs`

**Interfaces:**
- Consumes: `verify_archive`, a separate `KemDecapsulator`, schema registry, archive source/sink.
- Produces: required CLI grammar, `ea.verification-report/v1` JSON, exit codes `0,2,10,11,12,13,14,15,20,21`, and full encrypted export.

- [ ] **Step 1: Write CLI anchor, ordering, and report determinism tests**

```rust
#[test]
fn trust_commands_require_external_anchor() {
    cli().args(["verify", fixture_path("archive")]).assert()
        .failure().code(2).stderr(predicate::str::contains("--trust-anchor"));
}

#[test]
fn report_is_byte_identical_without_runtime_metadata() {
    let first = run_report(fixtures::archive(), fixtures::anchor(), false);
    let second = run_report(fixtures::archive(), fixtures::anchor(), false);
    assert_eq!(first, second);
}

// Die eingefrorene Baseline enthaelt formatErrors, quarantinedObjects und je
// Objektergebnis serverConfirmation. Sie wird erst eingefroren, nachdem Phase A
// (2026-08-16-einsatzarchiv-task-9-phase-a-report-and-gate-order.md) diese
// Felder geschlossen hat.

#[test]
fn report_is_hashed_and_only_signed_by_an_explicit_authorized_role() {
    let unsigned = run_report_with_signer(fixtures::archive(), None);
    assert_eq!(unsigned.report_hash, sha256(&unsigned.canonical_report_bytes));
    assert!(unsigned.signature.is_none());
    let signed = run_report_with_signer(fixtures::archive(), Some(fixtures::authorized_report_signer()));
    assert!(verify_report_signature(&signed).is_ok());
    assert!(run_report_with_signer(fixtures::archive(), Some(fixtures::unauthorized_writer_signer())).is_err());
}
```

- [ ] **Step 2: Run CLI tests and verify failure**

Run: `cargo test --locked -p einsatzarchiv-cli`

Expected: FAIL because the binary and command handlers do not exist.

- [ ] **Step 3: Implement the baseline commands with verify-before-use**

```rust
#[repr(i32)]
pub enum ExitCode {
    Success = 0, Usage = 2, Integrity = 10, Chain = 11, Trust = 12,
    Evidence = 13, Key = 14, Incomplete = 15, Io = 20, Unsupported = 21,
}
```

Implement exactly:

```text
einsatzarchiv --trust-anchor <file> verify <archive-path>
einsatzarchiv --trust-anchor <file> list <archive-path>
einsatzarchiv --trust-anchor <file> decrypt <archive-path> --key <key-source> --output <target>
einsatzarchiv --trust-anchor <file> report <archive-path> --output <report-file>
einsatzarchiv --trust-anchor <file> export <archive-or-server> --output <new-target>
```

Every command supports `--format text|json`. `decrypt` and `export` call full verification first and write only to a newly created or empty target with restrictive permissions. `report` sorts all arrays and maps canonically and excludes host path, current time, and runtime metadata unless `--include-runtime-metadata` is supplied. It always emits `reportHash = SHA-256(canonical report bytes without reportHash/signature)` and, only when the caller explicitly supplies a currently authorized report-signing key source, a detached COSE Sign1 over that hash with the signer certificate/capability recorded in the envelope. No available authorized signer means a valid hashed unsigned report, not an implicit use of any other key. If multiple errors exist, return the smallest applicable specific exit code while retaining all details in the report.

- [ ] **Step 4: Run CLI, fresh-anchor attack, and export tests**

Run: `cargo test --locked -p ea-recovery -p einsatzarchiv-cli`

Expected: PASS; a self-consistent foreign Root/Genesis fails with code 12, export preserves every original byte, and identical input produces identical report bytes.

- [ ] **Step 5: Commit the recovery baseline**

```bash
git add crates/ea-recovery apps/cli Cargo.toml Cargo.lock
git commit -m "feat(cli): add offline verification and recovery baseline"
```

### Task 11: Permanent Vectors, Property/Fuzz Gates, Format Package, and Traceability

**Files:**
- Create: `crates/ea-testkit/Cargo.toml`
- Create: `crates/ea-testkit/src/lib.rs`
- Create: `vectors/crypto/suite-1/manifest.json`
- Create: `vectors/format/v1/{valid,invalid}/manifest.json`
- Create: `vectors/trust/v1/manifest.json`
- Create: `vectors/grants/v1/manifest.json`
- Create: `vectors/receipts/v1/manifest.json`
- Create: `vectors/evidence/v1/manifest.json`
- Create: `tests/ea-system-tests/tests/conformance_golden_vectors.rs`
- Create: `tests/ea-system-tests/tests/conformance_properties.rs`
- Create: `docs/format/README-FORMAT.txt`
- Create: `docs/traceability/v0.1-requirements.csv`
- Create: `docs/traceability/stage-1-gate.md`
- Modify: `tools/xtask/src/main.rs`
- Test: `tools/xtask/tests/stage_gate.rs`

**Interfaces:**
- Consumes: every Stage 1 crate and schema.
- Produces: immutable versioned test vectors, public format package, requirement ledger, and `xtask stage-gate 1`.

<!-- vector-hygiene-rule -->
**Vektor-Hygiene, verbindlich.** Negativvektoren, die einen unzulässigen `action_code` kodieren, MÜSSEN den Wert `200` verwenden. Erzeugt dieser Task zusätzlich einen Negativvektor für einen unbekannten Trust-Subtype, MUSS er das Literal `xxUnknownxx` verwenden. Nächstliegende Nachbarwerte des heutigen Bestands — insbesondere der `action_code` 7 und jeder Name, der später eine echte Trust-Objektfamilie werden könnte — sind verboten. Grund: ein dauerhaft eingefrorener Negativvektor, der einen nachbarschaftlichen Wert benutzt, dreht sich bei einer späteren v1.1-Erweiterung von `abgelehnt` nach `akzeptiert`. Das wäre der einzige echte Bruch des Permanenzversprechens dieses Tasks — die Byte-Unveränderlichkeit selbst ist davon nicht betroffen.
<!-- /vector-hygiene-rule -->

<!-- web-reader-blockers -->
**BLOCKIERT — Formentscheidung nach `web-reader-design.md` §7.5.** Dieser Task friert `organizationAdminAuthorization` mit Positiv- UND Negativvektoren ein, während `crates/ea-trust/src/admin_authorization.rs:142-149` die Signatur-Kardinalität 1 samt hart indiziertem `signatures()[0]` und `schemas/archive/v1/trust.cddl:22` `[cose-sign1-v1]` pinnen. Spec §7.5 verlangt zwei verschiedene Approver plus die Bindung eines Ziel-Transport-Public-Key-Fingerprints, für den es im 15-Feld-Array kein Feld gibt (Position 15 ist ein an drei Stellen auf Länge 0 geprüftes leeres Extension-Array: `crates/ea-format/src/etb.rs:676`, `:1489`, `crates/ea-crypto/src/cose.rs:2781`). Solange nicht entschieden ist, ob die Kardinalität aufgeweitet oder eine eigene 2-of-N-Familie nach dem Vorbild von `grantAuthorization`/`destructionAuthorization` (`trust.cddl:28-30`, `[2* cose-sign1-v1]`) angelegt wird, DARF dieser Task keine Vektoren für `organizationAdminAuthorization` einfrieren.

**BLOCKIERT — Zuordnung der Policy-Frist nach `web-reader-design.md` §4.2.** Spec §4.2 fordert, dass die Anwendung das Alter des zuletzt bezogenen Trust-Standes sichtbar ausweist und ab einer in der Policy konfigurierten Frist zur Aktualisierung auffordert. Weder `max_registry_age_ms` (Ausstellungsschranke am Registry-Ereignis, `design.md:1347`) noch `registry_expiry_behavior` (normativ an die Finalisierung gebunden, `design.md:1426`, eine Operation die der Reader nicht ausführt) deckt das ab. Ist eine eigene geräteseitige Frist erforderlich, ist `policy-core-v1` betroffen — ein geschlossenes Array fester Positionen (`schemas/archive/v1/trust.cddl:127-141`, `crates/ea-format/src/etb.rs:210-229`). Solange das offen ist, DARF dieser Task keine Positivvektoren für `policy-core-v1` einfrieren.

**BLOCKIERT — Traceability der Web-Reader-Anforderungen.** Dieser Task füllt das Requirement-Ledger „for every normative paragraph". `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` ist eine freigegebene Normativquelle mit eigenen MUSS-Anforderungen (§4.1 getrennter Origin, §4.2 Aktivierung nur gegen eine gepinnte, Root-signierte `webBundleRelease`, §4.3 nicht überspringbarer Fingerprint-Vergleich, §5.2 universeller Datei-Weg immer angeboten, §6.3 zwei Pflicht-Authenticators, §7.5 Verweigerung der Re-Encryption bei abweichendem Transport-Fingerprint, §8.2 kein Klartext in Telemetrie). Zusätzlich sind `design.md` FR-100 („gemeinsame App, signierte Rollentrennung") und FR-103 („Reader-Cache und Index verschlüsselt") inhaltlich überholt. Vor dem Einfrieren ist zu entscheiden, ob diese Anforderungen als v1.1-Zeilen aufgenommen oder ausdrücklich zurückgestellt werden. Schweigen ist die einzige Variante, die nach dem Einfrieren teuer wird.

**Reichweite des wasm32-Gates.** `docs/traceability/stage-1-gate.md` MUSS ausdrücklich festhalten: das `wasm32-unknown-unknown`-Kommando in `verify_quick_commands()` belegt Übersetzbarkeit, nicht Lauffähigkeit. Der Laufzeitnachweis nach `web-reader-design.md` §14.1 steht aus.
<!-- /web-reader-blockers -->

- [ ] **Step 1: Write a gate test that rejects absent vectors and incomplete ledger rows**

```rust
#[test]
fn stage_one_gate_requires_every_vector_family_and_primary_ak() {
    let result = xtask_test::stage_gate(1);
    assert!(result.vector_families.contains_all(["crypto", "format", "trust", "grants", "receipts", "evidence"]));
    let required_primary_ak = [4, 5, 6, 9, 14, 16, 17, 20, 38, 51];
    assert_eq!(result.primary_acceptance_criteria, required_primary_ak);
    let represented_rows = result.rows.iter()
        .filter(|row| required_primary_ak.contains(&row.primary_acceptance_criterion))
        .collect::<Vec<_>>();
    assert_eq!(represented_rows.iter().map(|row| row.primary_acceptance_criterion)
        .collect::<std::collections::BTreeSet<_>>(), required_primary_ak.into_iter().collect());
    for ak in required_primary_ak {
        let rows = represented_rows.iter().filter(|row| row.primary_acceptance_criterion == ak).collect::<Vec<_>>();
        assert!(!rows.is_empty(), "missing concrete ledger row for primary AK {ak}");
        assert!(rows.iter().all(|row| row.is_complete()), "incomplete ledger row for primary AK {ak}");
    }
    assert!(represented_rows.iter().all(|row| matches!(row.status, Status::Implemented | Status::Integrated)));
}
```

- [ ] **Step 2: Run the Stage 1 gate and confirm missing evidence fails**

Run: `cargo test --locked -p xtask --test stage_gate`

Expected: FAIL listing each absent vector family and ledger entry.

- [ ] **Step 3: Generate deterministic vectors and populate exact traceability**

Use fixed published/KAT keys and explicit deterministic test entropy only inside `ea-testkit`. Each vector manifest records schema ID, suite ID, source standard or fixture generator commit, exact input bytes, expected intermediate digests, exact object bytes, expected acceptance/error code, and SHA-256 file hash. Include:

- every Suite 1 primitive and domain string;
- valid and one-byte-mutated `.eip/.eag/.esr/.ecp/.etb/.eds`;
- grant total sorting, duplicate rejection, HPKE info/AAD, encapsulated key, wrapped CEK, and signature digest;
- receipt field positions, sorted grant hashes, digest, signature, and replay bytes;
- Root/Admin/bootstrap positives and every negative listed in §22.1;
- schema/format/suite compatibility and safe unsupported behavior;
- deterministic encoding, chain, and parser properties.

Populate the requirement ledger for every normative paragraph, AK 1–54, and unnumbered §§21/22/25 gate. Stage 1 rows may be `implemented` or `integrated`; cross-stage rows remain `planned`. `README-FORMAT.txt` documents object tags, directory layout, independent-anchor rule, hash/domain formulas, parser limits, and compatibility files without promising legal evidentiary status.

- [ ] **Step 4: Run the complete Stage 1 gate**

Run:

```bash
pnpm test:core
pnpm test:golden
pnpm test:property
pnpm test:fuzz -- --smoke-seconds 60
pnpm test:recovery
cargo run --locked -p xtask -- stage-gate 1
cargo check --target wasm32-unknown-unknown --locked -p ea-types -p ea-cbor -p ea-crypto -p ea-format -p ea-schema -p ea-time -p ea-trust
pnpm verify:quick
```

Expected: PASS. The gate report maps primary AK 4, 5, 6, 9, 14, 16, 17, 20, 38, and 51 to concrete evidence and explicitly leaves their later-stage contributions open.

- [ ] **Step 5: Commit the Stage 1 gate**

```bash
git add crates/ea-testkit vectors tests/ea-system-tests/tests docs/format docs/traceability tools/xtask package.json Cargo.toml Cargo.lock
git commit -m "test(core): close trust core and format stage"
```
