# Einsatzarchiv Stage 7 Release Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the integrated product into a releasable v0.1 by proving every platform, durability, performance, privacy, supply-chain, recovery, operational, legal-decision, and security-review gate and closing the complete requirement ledger.

**Architecture:** Add no new fachliche behavior in this stage. Drive all release tests from one signed/versioned support matrix, emit machine-verifiable evidence bundles, and require external/manual attestations through schemas rather than free-form “done” flags. A release verifier checks exact source/lock/vector hashes, platform reports, installers, SBOM/signatures/provenance, backup/recovery evidence, current cryptographic review, independent security review, and every ledger row before producing a release decision.

**Tech Stack:** Shared Rust `xtask` release verifier, signed canonical JSON/COSE artifacts, CI on Windows/macOS/Ubuntu and Linux OCI `amd64`, Tauri installers, fault injection, criterion-style benchmarks, SBOM/advisory/license/secret scanners selected and pinned in ADR 0001, reproducible/provenance tooling, restore environment, structured Go-live evidence.

## Global Constraints

- Die Schlüsselwörter **MUSS**, **DARF NICHT**, **SOLL**, **SOLL NICHT** und **DARF** sind normativ zu verstehen. Ein Release darf von einer MUSS-Anforderung nicht abweichen. Eine Abweichung von SOLL erfordert eine dokumentierte Sicherheits- oder Betriebsbegründung.
- **Merker Web-Reader**, `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §12 und §11.4: die Support-Matrix erhält für den Reader eine Browser-Achse aus Engine, Version und Plattform; die Achsen Architektur, Installerformat und Key-Provider entfallen für den Reader und gelten weiterhin für Writer, Administration und CLI. Reader-Installer und native Key-Provider-Smokes des Readers entfallen. Neu sind: PWA-Installation, Service-Worker-Update unter Pinning, und ein Gate, das die **Ablehnung eines nicht Root-signierten Bundles** nachweist. Die Browser-Mindestversionen je Plattform werden hier gepinnt und gegen die dann aktuelle Lage geprüft; Ausgangslage nach §14.3 (Recherche vom 2026-08-15): Firefox ab 148, Chrome ab 147 einschließlich PRF-on-create, Safari ab 18 mit iCloud-Passkeys. Eine neue Reader-Version erfordert eine Root-Zeremonie (§4.4); spontane Web-Deployments sind ausgeschlossen.
- **Übertrag — die ADR-Nummer 0002 ist vergeben**: Workstream A, Task 1 will `docs/adr/0002-support-matrix-signature.md` anlegen. Die Nummer 0002 trägt bereits `docs/adr/0002-local-database-encryption.md`, und `tools/xtask/tests/adr_gate.rs` pinnt genau diesen Pfad in der Konstante `ADR_PATH`. Der Files-Block dieses Tasks MUSS auf die nächste freie Nummer umgestellt werden; anderenfalls überschreibt der Task ein bestehendes, laufend geprüftes ADR. Ein eigenständiger Defekt dieses Plans, hier zu beheben.
- **Übertrag R57(b) — native Key-Provider- und Re-Auth-API-Familien (Stand 2026-08-28)**: Die Key-Provider-Schicht der Stufe 2 ist eine PORTSCHICHT OHNE NATIVE AUFRUFE. Keine der verlangten API-Familien ist aufgerufen — nicht CNG/DPAPI, nicht Windows Hello, nicht Keychain oder Secure Enclave, nicht LocalAuthentication, nicht PAM/Polkit, nicht Secret Service, nicht BitLocker/FileVault/LUKS. `HARDWARE_CAPABLE_PROVIDERS` (`crates/ea-key-provider/src/profile.rs`) ist deshalb leer und fail-closed, und vier Posture-Werte bleiben `Unknown`. Hier zu liefern: die nativen API-Familien je Plattform, ADR 0003, und der Nachweis auf echter Hardware je Betriebssystem. Ledgeranker: `AK-23` `v1.1`, Stufe 7, `planned` — die Zeile trägt den Satz „Ein gruener Stufe-2-Gate ist ausdruecklich kein Beleg fuer hardwaregebundene Schluessel." wörtlich.
- **Übertrag R59 Teil 2 — Plattform-Sperrbeobachter (Stand 2026-08-28)**: Teil 1 ist gebaut und bezeugt (`draft_load_core` gibt den Entwurfsklartext nur gegen einen `OperatorSessionProof` heraus, `apps/desktop/src-tauri/src/commands/writer.rs::loading_the_active_draft_without_a_session_proof_never_reads_the_payload`). Hier zu liefern: die Plattformbeobachter je Betriebssystem für das Sperrereignis UND die Auswertung von `is_valid_for`/`MAX_INACTIVITY_MS` im Wirt — heute wertet der Wirt beides nicht aus, und die Inaktivitätssperre wirkt nur über die Frist im Nachweis. Ledgeranker: `AK-53` `v1.1`, Stufe 7, `planned`.
- **Übertrag R60 — Sperrnachweis auf drei Betriebssystemen (Stand 2026-08-28)**: Die echte Betriebssystemsperre IST seit dem 2026-08-28 gebaut: `crates/ea-archive-fs/src/local_path.rs::acquire_writer_lock` und `crates/ea-draft/src/lock.rs` nehmen die Sperrdatei per `std::fs::File::try_lock` (`flock` bzw. `LockFileEx`, ohne neue Abhängigkeit); kein Reaper und keine PID-Prüfung. Hier bleibt NUR der Nachweis: advisory-lock-Semantik auf drei Betriebssystemen und auf Netzdateisystemen, dazu die signierte Betriebssystem- und Dateisystemmatrix. Mitzunehmen ist der Nebenbefund, dass `ea-recovery` (`FsArchiveSource`) die Sperrdatei als `nonObjectFile` zählt und `ea-recovery export` sie mitkopiert (Präzedenz `.ea-active-profile`). Ledgeranker: `AK-39` `v1.1`, Stufe 7, `planned`.
- **Übertrag QS-12 — `cargo deny` als Pflichtausführung**: Der Lieferkettenlauf ist ab Stufe 2 als `pnpm supply-chain` verdrahtet und im Stufe-2-Gate-Bericht gemessen; hier MUSS er Pflichtbestandteil des Releaselaufs sein und darf nicht als optionaler Schritt geführt werden. Die sechzehn namentlichen `[advisories]`-`ignore`-Einträge in `deny.toml` sind hier erneut zu bewerten; Ledgeranker: `GATE-25` `v1.1`, Stufe 7, `planned`, der alle sechzehn RUSTSEC-Kennungen nennt.
- **Übertrag QS-11 — COSE-Prüfung kryptografisch vor dem Commit**: Die Signaturprüfung der Releaseartefakte MUSS kryptografisch erfolgen (echte COSE-Verifikation gegen den freigegebenen Schlüssel), nicht strukturell und nicht über einen Hashvergleich allein, und sie MUSS VOR dem Commit des Releasestands laufen, nicht danach.
- Microsoft Access is entirely outside scope; there is no Access implementation, migration, or release gate. **Access Grant** remains the signed key envelope.
- Non-goals are fixed: no live incident log, dispatch/alarm/control-center integration, patient record or identifying patient data, concurrent offline Writers, normal-app mutation/deletion of finalized content, AI summarization/OCR, public links, server-side content search, unprofiled network paths, qualified personal electronic signature, TR-ESOR certification claim, screenshot/transcription prevention, or cryptographic recall of already decrypted data.
- All 17 product guarantees from §3 remain cumulative: one Writer; unique predecessor-bound sequence; immutable `.eip`; amendment-only corrections; one fresh CEK/ciphertext; separate grants; exactly one Recovery grant; forbidden Writer keys; no retained CEK/draft key; no server decrypt/grant key; server-independent verification; independent versioning; separated status dimensions; no overclaim of hash-chain legal effect; every active Reader granted; external anchor; signed OS-bound operator snapshot.
- Supported release platforms are all Microsoft-supported Windows 11 releases `x86_64`; current and previous macOS major on `arm64` and also `x86_64` where Intel is officially supported; Ubuntu 24.04 LTS `x86_64`; server Linux OCI `amd64`. Windows Arm and Linux `arm64` are out of v0.1.
- Each release ships a signed, versioned `support-matrix.json` pinning min/max OS build/version, architecture, installer, key provider, and tested local filesystem per combination. Every combination runs crypto/format goldens plus key-provider/filesystem/installer smokes; full Writer/Reader/Admin/CLI E2E runs at each architecture's pinned minimum and maximum OS.
- UI release gates verify the shared Ant Design 6 German/static-`zeroRuntime` exact-token build, bundled hashed CSS, CSP ban on runtime/external styles, Ant `App` overlay context, direct CSR `@phosphor-icons/react` imports only, no Webfonts/`react-icons`, visible focus, semantic/status text, keyboard/screen-reader behavior, and `prefers-reduced-motion`.
- Controlled network profiles additionally pin protocol, server product/version, mount options, failover setup, and capability vector; generic paths remain fail-closed.
- All security/format logic remains shared Rust. Every old vector remains in CI. No dependency/tool/OCI base/installer silently floats during release.
- No private key, payload, decrypted data, nonce, clear incident number/location/name/free text, Recovery plaintext, or unredacted operator identity appears in logs, crash output, filenames, server DB/Object Store metadata, telemetry, SBOM, provenance, or committed evidence.
- Destruction remains disabled without the documented privacy decision; technical integrity is not organizational/legal “Revisionssicherheit.” No court-effect, TR-ESOR certification, or complete metadata-blindness claim.
- External BSI TR-02102-1 currency assessment, independent security review, named operational ownership, privacy decision, and key custody evidence cannot be replaced by automated tests.
- v0.1 is complete only after this stage and every acceptance criterion plus unnumbered §§21/22/25 gate passes.

Performance gates are exact: finalizing a 1 MiB payload on a workstation with at least four CPU cores, 8 GiB RAM, and SSD takes at most three seconds; Reader verifies/indexes at least 50,000 packages; server streams without retaining a full payload copy. Offline Writer and TSA independence remain mandatory.

---

## Workstream A: Platform, Durability, and Performance

### Task 1: Signed Support-Matrix Format and Release Verifier

**Files:**
- Create: `docs/adr/0002-support-matrix-signature.md`
- Create: `schemas/release/support-matrix.schema.json`
- Create: `schemas/release/platform-evidence.schema.json`
- Create: `schemas/release/release-decision.schema.json`
- Create: `ops/release/support-matrix.json`
- Create: `ops/release/support-matrix.cose`
- Create: `tools/xtask/src/release/mod.rs`
- Create: `tools/xtask/src/release/matrix.rs`
- Create: `tools/xtask/src/release/signature.rs`
- Test: `tools/xtask/tests/support_matrix.rs`

**Interfaces:**
- Consumes: exact release matrix bytes and separate product-release signing key.
- Produces: `SupportMatrix::verify_signed -> VerifiedSupportMatrix`, schema-validated platform evidence, and a release decision that cannot use an unsigned/expired/wrong-source matrix.

- [ ] **Step 1: Write exact-byte signature and matrix-coverage tests**

```rust
#[test]
fn any_matrix_byte_change_invalidates_signature() {
    let verified = VerifiedSupportMatrix::from_files(matrix_path(), signature_path(), release_public_key()).unwrap();
    assert_eq!(verified.version(), "0.1");
    let changed = replace_exact_byte(matrix_bytes(), b"Ubuntu 24.04", b"Ubuntu 24.05");
    assert!(VerifiedSupportMatrix::from_bytes(&changed, signature_bytes(), release_public_key()).is_err());
}

#[test]
fn matrix_requires_every_component_platform_and_min_max_e2e_edge() {
    let matrix = load_fixture("missing-macos-intel-when-supported.json");
    assert_eq!(validate_matrix(matrix).unwrap_err().code(), "EA-RELEASE-MATRIX-COVERAGE");
}
```

- [ ] **Step 2: Run tests and verify release formats are absent**

Run: `cargo test --locked -p xtask --test support_matrix`

Expected: FAIL because matrix schema/signature/verifier do not exist.

- [ ] **Step 3: Define exact signature representation and current matrix population procedure**

ADR 0002 fixes UTF-8 JSON serialized with RFC 8785 JSON Canonicalization Scheme and a companion COSE Sign1 over:

```text
SHA-256("EINSATZARCHIV-SUPPORT-MATRIX-v1" || exactCanonicalSupportMatrixBytes)
```

Use an Ed25519 product-release signing key separate from every organization Root/key role. Protected headers include algorithm, release-key RFC-9679 thumbprint, content type `application/einsatzarchiv-support-matrix+json;v=1`, and critical fields; unprotected headers are empty. The application/CLI embeds the authorized product-release public key or certificate chain and verifies matrix bytes before use.

At release preparation, query authoritative Microsoft/Apple/Ubuntu support sources, record URLs and retrieval timestamps in each matrix source entry, and pin all currently supported/minimum/maximum builds demanded by §4. Pin installer format, native provider profile, local filesystem, and expected smoke suite per component/architecture. Each desktop row also pins the documented OS signal and expected `Pass`/`Fail`/`Unknown` contract for full-disk encryption, locked/non-shared account, automatic screen lock, and supported patch level; unsupported signals require a named Go-live evidence field rather than a fabricated pass. For controlled network profiles pin protocol, server product/version, mount flags, failover topology, and vector ID. The schema rejects `windows-arm64` and `linux-arm64` for v0.1.

- [ ] **Step 4: Sign and verify the complete current matrix**

Run:

```bash
cargo run --locked -p xtask -- release matrix validate ops/release/support-matrix.json
cargo run --locked -p xtask -- release matrix sign ops/release/support-matrix.json --key-source release-key
cargo run --locked -p xtask -- release matrix verify ops/release/support-matrix.json ops/release/support-matrix.cose
```

Expected: PASS; the verified matrix expands to every required smoke/E2E job and records current authoritative support sources.

- [ ] **Step 5: Commit the signed release-matrix contract**

```bash
git add docs/adr/0002-support-matrix-signature.md schemas/release ops/release/support-matrix.json ops/release/support-matrix.cose tools/xtask
git commit -m "build(release): define signed support matrix"
```

### Task 2: Matrix-Driven CI, Installers, and Native Provider/File-System Smokes

**Files:**
- Create: `.github/workflows/release-matrix.yml`
- Create: `.github/workflows/release-artifacts.yml`
- Create: `tools/xtask/src/release/jobs.rs`
- Create: `tools/xtask/src/release/installer.rs`
- Create: `tests/ea-system-tests/tests/cross_platform_installer_smoke.rs`
- Create: `tests/ea-system-tests/tests/cross_platform_native_provider_smoke.rs`
- Create: `tests/ea-system-tests/tests/cross_platform_device_posture_smoke.rs`
- Create: `tests/ea-system-tests/tests/cross_platform_filesystem_smoke.rs`
- Create: `ops/release/README.md`
- Test: `tools/xtask/tests/matrix_jobs.rs`

**Interfaces:**
- Consumes: `VerifiedSupportMatrix`.
- Produces: deterministic CI job list, signed native installers, and schema-valid evidence per required combination.

- [ ] **Step 1: Write job-expansion and evidence-completeness tests**

```rust
#[test]
fn every_matrix_row_expands_to_required_smokes_and_edge_e2e() {
    let jobs = expand_jobs(verified_matrix());
    for row in verified_matrix().rows() {
        assert!(jobs.has(row, Gate::CryptoGolden));
        assert!(jobs.has(row, Gate::FormatGolden));
        assert!(jobs.has(row, Gate::KeyProviderSmoke));
        assert!(jobs.has(row, Gate::DevicePostureSmoke));
        assert!(jobs.has(row, Gate::FilesystemSmoke));
        assert!(jobs.has(row, Gate::InstallerSmoke));
        if row.is_min_or_max_for_architecture() { assert!(jobs.has(row, Gate::FullE2e)); }
    }
}
```

- [ ] **Step 2: Run job tests and verify CI orchestration is absent**

Run: `cargo test --locked -p xtask --test matrix_jobs`

Expected: FAIL because matrix job expansion and workflows do not exist.

- [ ] **Step 3: Implement provider-agnostic `xtask` jobs and GitHub runners**

Workflows validate matrix signature first, use exact toolchain/lockfiles, and dispatch every expanded job. Each runner records OS build, architecture, filesystem, installer hash/signature verification, key provider and protection profile, test/vector commit hashes, start/end times, result, and cleartext-free diagnostics in `platform-evidence/v1` JSON. Native smokes cover key generation/sign/open/wrap/delete, non-exportability claim, wrong user, provider outage, re-authentication, OS lock, deletion, and backup restore. Posture smokes force pass/fail/unreportable responses for full-disk encryption, account lock/sharing, automatic screen lock, and patch support, prove that fail blocks production session creation, and prove unknown remains unresolved with its support-matrix evidence code. Ubuntu additionally covers deleted/recreated same UID, reused home, lost Secret Service instance, and restored backup. Installer smoke installs, launches, validates CSP/local resources, verifies bundled schemas/vectors/matrix, exercises role-specific startup, then uninstalls without removing user archive.

If hosted CI cannot supply a pinned historical/minimum OS, use a documented dedicated runner image/host matching the exact matrix row; do not substitute a newer OS while labelling it minimum.

- [ ] **Step 4: Expand, lint, and execute all currently available matrix jobs**

Run:

```bash
cargo run --locked -p xtask -- release jobs --matrix ops/release/support-matrix.json --check-workflows
cargo run --locked -p xtask -- release smoke --matrix-row host
cargo run --locked -p xtask -- release evidence validate ops/release/evidence/v0.1/platform
```

Expected: PASS for the host row; CI must supply signed evidence for every other row before the final gate.

- [ ] **Step 5: Commit matrix CI and smoke harnesses**

```bash
git add .github tools/xtask tests/ea-system-tests ops/release/README.md
git commit -m "ci: drive platform release gates from signed matrix"
```

### Task 3: Exhaustive Fault Injection and Controlled Network Backend Certification

**Files:**
- Create: `tools/xtask/src/release/fault_matrix.rs`
- Create: `tests/ea-system-tests/tests/fault_injection_archive_platform.rs`
- Create: `tests/ea-system-tests/tests/fault_injection_writer_process_kill.rs`
- Create: `tests/ea-system-tests/tests/fault_injection_server_process_kill.rs`
- Create: `tests/ea-system-tests/tests/fault_injection_network_backend.rs`
- Create: `schemas/release/backend-capability-report.schema.json`
- Create: `docs/operations/archive-backend-certification.md`
- Test: `tools/xtask/tests/fault_coverage.rs`

**Interfaces:**
- Consumes: verified support matrix, all Stage 2/3 fault points, real local/network profiles.
- Produces: exhaustive platform/backend capability reports and zero uncovered irreversible boundary.

- [ ] **Step 1: Write fault-coverage test against source-enumerated points**

```rust
#[test]
fn every_declared_fault_point_has_before_after_restart_evidence_per_backend() {
    let declared = collect_declared_fault_points();
    let matrix = load_fault_matrix();
    for backend in verified_matrix().archive_backends() {
        for point in &declared {
            assert!(matrix.has(backend, point, Edge::Before));
            assert!(matrix.has(backend, point, Edge::After));
            assert!(matrix.has_restart_assertion(backend, point));
        }
    }
}
```

- [ ] **Step 2: Run coverage test and verify native evidence is incomplete**

Run: `cargo test --locked -p xtask --test fault_coverage`

Expected: FAIL with each missing platform/backend/fault edge.

- [ ] **Step 3: Execute hard-kill and durability certification on every matrix backend**

Inject before/after every file flush, directory flush, create-if-absent, rename, exclusive lock, `discardIntent`, key delete/confirmation, SQLite transaction, Object Store stage/put, PostgreSQL lock/commit, Receipt readback, cursor confirm, profile pointer swap, Stub flush, deletion, attestation, and Evidence publication. Kill the real process, restart, and verify unchanged draft or exact prepared completion, no key resurrection, exact sequence/UUID, no visible server partial state, idempotent Receipt/cursor/destruction resume, and reconstruction from bytes.

For every controlled network row, exercise disconnect, remount, server restart, link loss during each write/flush/rename, failover, conflicting existing bytes, and recovery; verify grants before `.eip`, byte equality, no server upload before remote publication, and exact `Upload ausstehend`/`Netzarchiv wartet`. Produce a signed backend report with profile identity, versions/options/topology, vector ID, filesystem semantics, every operation/result, and exact test hashes. Reject unprofiled paths.

- [ ] **Step 4: Run and validate the full fault/backend matrix**

Run:

```bash
pnpm test:fault -- --matrix ops/release/support-matrix.json
cargo run --locked -p xtask -- release backend-evidence validate ops/release/evidence/v0.1/backends
cargo test --locked -p xtask --test fault_coverage
```

Expected: PASS only when every required row has genuine host/backend evidence; emulated unit adapters alone are insufficient.

- [ ] **Step 5: Commit certification harness and documentation**

```bash
git add tools/xtask tests/fault-injection schemas/release docs/operations
git commit -m "test(release): certify archive durability matrix"
```

### Task 4: Performance and Responsiveness Gates

**Files:**
- Create: `tests/ea-system-tests/tests/performance_finalize_1mib.rs`
- Create: `tests/ea-system-tests/tests/performance_reader_50000.rs`
- Create: `tests/ea-system-tests/tests/performance_server_streaming.rs`
- Create: `tests/e2e/sync_responsiveness.spec.ts`
- Create: `schemas/release/performance-report.schema.json`
- Create: `tools/xtask/src/release/performance.rs`
- Test: `tools/xtask/tests/performance_gate.rs`

**Interfaces:**
- Consumes: release-built Writer/Reader/server and hardware inventory.
- Produces: signed performance reports and exact pass criteria from §20.3.

- [ ] **Step 1: Write performance gate logic and nonblocking UI test**

```rust
#[test]
fn finalization_and_reader_thresholds_are_normative() {
    let report = PerformanceReport::load(fixture_report());
    assert!(report.host.cpu_cores >= 4 && report.host.ram_gib >= 8 && report.host.storage.is_ssd());
    assert!(report.finalize_1_mib_p95 <= Duration::from_secs(3));
    assert!(report.reader_verified_and_indexed >= 50_000);
    assert!(!report.server_buffered_full_payload);
}
```

```ts
test('Writer input remains usable while sync transport is deliberately blocked', async ({ page }) => {
  await blockSyncResponse(page)
  await page.getByLabel('Einsatzstichwort').fill('Brand')
  await expect(page.getByLabel('Einsatzstichwort')).toHaveValue('Brand')
  await expect(page.getByText('Upload ausstehend')).toBeVisible()
})
```

- [ ] **Step 2: Run performance gate and verify evidence is absent**

Run: `cargo test --locked -p xtask --test performance_gate`

Expected: FAIL because benchmark reports do not exist.

- [ ] **Step 3: Implement release-mode benchmarks with controlled data**

Finalize an exactly 1 MiB deterministic payload with the production grant set on a recorded four-or-more-core/8-GiB/SSD host, warm up, run enough samples to report distribution and require p95 <= 3 seconds. Generate and fully verify/decrypt/index 50,000 exact packages with realistic grants/Trust/checkpoints and require completion without corruption or resource exhaustion; include a realistic Trust catalog near `MAX_TRUST_OBJECTS_V1 = 65_536` and `MAX_TOTAL_TRUST_OBJECT_BYTES_V1 = 268_435_456`, and report duration plus peak RSS without inventing a stricter time promise. Stream maximum-size server objects with instrumentation proving the application never retains a full body; pin the chosen bounded buffer size in ADR 0001. UI test blocks sync completion and proves form/autosave operations continue through independent async execution rather than adopting an unstated millisecond SLA.

- [ ] **Step 4: Run release benchmarks and validate signed reports**

Run:

```bash
pnpm test:performance
cargo run --locked -p xtask -- release performance validate ops/release/evidence/v0.1/performance
pnpm --dir apps/desktop exec playwright test tests/e2e/sync_responsiveness.spec.ts
```

Expected: PASS with the exact 3-second and 50,000-package thresholds satisfied on qualifying hardware.

- [ ] **Step 5: Commit performance gates**

```bash
git add tests/ea-system-tests tests/e2e/sync_responsiveness.spec.ts schemas/release tools/xtask
git commit -m "test(release): enforce performance targets"
```

## Workstream B: Privacy, Supply Chain, and Restore

### Task 5: Whole-System Privacy Canary and Crash-Dump Gate

**Files:**
- Create: `tests/ea-system-tests/tests/privacy_canaries_full_system.rs`
- Create: `tests/privacy-canaries/canary_manifest.json`
- Create: `tools/xtask/src/release/privacy.rs`
- Create: `schemas/release/privacy-report.schema.json`
- Create: `docs/security/logging-and-crash-policy.md`
- Test: `tools/xtask/tests/privacy_gate.rs`

**Interfaces:**
- Consumes: release installers/container and canaries in every fachliche field.
- Produces: signed zero-finding privacy report or a release-blocking list of exact storage classes (not leaked values).

- [ ] **Step 1: Write scanner-coverage test**

```rust
#[test]
fn privacy_gate_scans_every_required_surface() {
    let report = run_fixture_scan();
    assert!(report.surfaces.contains_all([
        "writer-logs", "reader-logs", "admin-logs", "cli-output", "server-logs",
        "crash-output", "filenames", "postgres", "object-keys", "object-tags",
        "object-metadata", "metrics", "traces", "temp-directories", "audit-events",
    ]));
    assert!(report.findings.is_empty());
}
```

- [ ] **Step 2: Run scanner test and verify full-system evidence is absent**

Run: `cargo test --locked -p xtask --test privacy_gate`

Expected: FAIL because the whole-system scanner/report does not exist.

- [ ] **Step 3: Execute release binaries with unique field canaries**

Seed distinct non-overlapping markers into incident number/time/keyword/location/person/vehicle/patient/notes/external organization, operator display/function, CSV, amendment, destruction reason details, Recovery sample, and export. Exercise success and every error path, forced crash, sync, Reader, Admin, CLI, TSA, backup, restore, and destruction. Verify every required local audit row is validly signed, schema-valid, append-only, and free of those markers; corrupt signatures and forbidden generic/free-text contexts must fail the gate. Scan only authorized test stores and redact values from findings, reporting canary ID and surface/path class. Confirm automatic telemetry/crash upload off. If crash dumps are enabled in the operational profile, prove configured exclusion/redaction of secret/fachliche memory; otherwise production remains blocked.

- [ ] **Step 4: Run and validate zero-finding privacy evidence**

Run:

```bash
pnpm test:privacy
cargo run --locked -p xtask -- release privacy validate ops/release/evidence/v0.1/privacy
```

Expected: PASS with zero canary findings and destruction disabled when the privacy decision fixture is absent.

- [ ] **Step 5: Commit privacy harness and policy**

```bash
git add tests/privacy-canaries tools/xtask schemas/release docs/security
git commit -m "test(release): gate plaintext leakage across the system"
```

### Task 6: SBOM, Advisories, Licenses, Secrets, Reproducibility, and Artifact Signatures

**Files:**
- Create: `docs/adr/0003-release-supply-chain.md`
- Create: `tools/xtask/src/release/supply_chain.rs`
- Create: `schemas/release/supply-chain-report.schema.json`
- Create: `ops/release/policy/allowed-licenses.json`
- Create: `ops/release/policy/advisory-exceptions.json`
- Create: `ops/release/policy/source-allowlist.json`
- Modify: `.github/workflows/release-artifacts.yml`
- Test: `tools/xtask/tests/supply_chain.rs`

**Interfaces:**
- Consumes: clean tagged source, committed lockfiles/toolchains/base digest, release signing key.
- Produces: SBOMs, dependency/license/advisory/secret reports, checksums, signatures, and reproducible-build or verifiable provenance for every artifact.

- [ ] **Step 1: Write completeness and exception-expiry tests**

```rust
#[test]
fn every_release_artifact_has_sbom_checksum_signature_and_provenance() {
    let report = SupplyChainReport::load(fixture_report());
    for artifact in report.artifacts() {
        assert!(artifact.sbom.is_some());
        assert!(artifact.sha256.is_some());
        assert!(artifact.signature.is_verified());
        assert!(artifact.provenance.matches_source_and_lockfiles());
    }
    assert!(report.exceptions().iter().all(|e| e.expires_at > report.release_time));
}
```

- [ ] **Step 2: Run supply-chain test and verify evidence is absent**

Run: `cargo test --locked -p xtask --test supply_chain`

Expected: FAIL because policies/reports/artifact mapping do not exist.

- [ ] **Step 3: Pin and implement the complete supply-chain gate**

ADR 0003 records exact scanner/SBOM/signing/provenance tool names, versions, sources, configuration hashes, and update procedure. Generate CycloneDX or SPDX SBOMs for Rust, pnpm, each installer, CLI, and OCI image; audit advisories, licenses, secrets, source registries, lockfile integrity, and container packages. Any exception has advisory/license ID, risk rationale, compensating control, owner, issue, and expiration before next release; expired/unsigned exceptions fail. Build twice in isolated clean environments and compare artifacts byte-for-byte or emit verifiable provenance explaining only documented nondeterminism. Sign/checksum every installer, CLI archive, OCI digest, support matrix, schema/vector bundle, and SBOM; verify signatures before final gate.

- [ ] **Step 4: Generate and validate the supply-chain evidence bundle**

Run:

```bash
pnpm verify:supply-chain
cargo run --locked -p xtask -- release supply-chain validate ops/release/evidence/v0.1/supply-chain
```

Expected: PASS with no unapproved advisory/license/source/secret finding and every artifact mapped to exact source/toolchain/lock hashes.

- [ ] **Step 5: Commit supply-chain policy and automation**

```bash
git add docs/adr/0003-release-supply-chain.md tools/xtask schemas/release ops/release/policy .github/workflows/release-artifacts.yml
git commit -m "build(release): verify software supply chain"
```

### Task 7: Backup/Restore, Archive Export, and Fresh-Machine Recovery Drill

**Files:**
- Create: `ops/backup-restore/backup.md`
- Create: `ops/backup-restore/restore.md`
- Create: `ops/compose/restore.yaml`
- Create: `tests/ea-system-tests/tests/backup_restore_full_restore.rs`
- Create: `tests/ea-system-tests/tests/backup_restore_fresh_machine.rs`
- Create: `schemas/release/restore-report.schema.json`
- Create: `tools/xtask/src/release/restore.rs`
- Test: `tools/xtask/tests/restore_gate.rs`

**Interfaces:**
- Consumes: independent backups, known signed checkpoint, full encrypted export, independent final anchor, complete key inventory.
- Produces: separate-environment restore report and successful fresh-machine Recovery drill.

- [ ] **Step 1: Write checkpoint and independent-anchor restore tests**

```rust
#[test]
fn restore_gate_requires_database_objects_and_checkpoint_agreement() {
    let report = RestoreReport::load(fixture_report());
    assert_eq!(report.restored_chain_head, report.known_checkpoint_head);
    assert_eq!(report.missing_objects, 0);
    assert_eq!(report.conflicting_objects, 0);
    assert!(report.fresh_machine_anchor_external);
    assert!(report.guided_recovery_test_complete);
}
```

- [ ] **Step 2: Run restore gate and verify evidence is absent**

Run: `cargo test --locked -p xtask --test restore_gate`

Expected: FAIL because full restore procedures/evidence do not exist.

- [ ] **Step 3: Implement separate-environment recovery procedure and harness**

Back up PostgreSQL, versioned Object Store, Writer/Reader archives according to policy, while excluding non-roaming instance/draft keys as designed. Restore to new isolated server endpoints and storage, reconcile every object/content hash, rebuild technical indexes, verify Registry/head/Receipt/Checkpoint, and prove no invisible orphan becomes accepted without full revalidation. Export full encrypted archive; on a fresh supported machine provide anchor from separate media and explicit Recovery key source, run CLI verify/list/decrypt/report/export and guided inventory test. Compare deterministic reports and archive bytes. Record actual recovery point/time observations without converting them into unapproved product guarantees.

- [ ] **Step 4: Run full restore and validate reports**

Run:

```bash
cargo run --locked -p xtask -- release restore --environment ops/compose/restore.yaml
cargo run --locked -p xtask -- release restore validate ops/release/evidence/v0.1/restore
```

Expected: PASS with the restored head equal to the known checkpoint and every required key medium verified.

- [ ] **Step 5: Commit restore procedures and harness**

```bash
git add ops/backup-restore ops/compose/restore.yaml tests/ea-system-tests schemas/release tools/xtask
git commit -m "test(release): prove backup restore and fresh recovery"
```

## Workstream C: Operations, External Review, and Final Acceptance

### Task 8: Operations, Monitoring, Security Events, and Lifecycle Runbooks

**Files:**
- Create: `docs/operations/server-operations.md`
- Create: `docs/operations/monitoring.md`
- Create: `docs/operations/security-events.md`
- Create: `ops/runbooks/device-loss-and-revocation.md`
- Create: `ops/runbooks/writer-loss-and-transition.md`
- Create: `ops/runbooks/historical-regrant.md`
- Create: `ops/runbooks/destruction.md`
- Create: `ops/runbooks/archive-profile-migration.md`
- Create: `ops/runbooks/key-rotation.md`
- Create: `ops/runbooks/update-and-rollback.md`
- Create: `ops/runbooks/incident-response.md`
- Create: `ops/runbooks/quarterly-recovery-test.md`
- Create: `schemas/release/operations-readiness.schema.json`
- Test: `tools/xtask/tests/operations_docs.rs`

**Interfaces:**
- Consumes: actual command/API/status/failure behavior.
- Produces: executable cleartext-free runbooks and operations readiness evidence with named responsibilities held in the secure release evidence bundle.

- [ ] **Step 1: Write runbook command and required-topic validation tests**

```rust
#[test]
fn operations_docs_cover_every_required_lifecycle_without_unknown_commands() {
    let docs = OperationsDocs::load("ops/runbooks").unwrap();
    assert!(docs.topics().contains_all([
        "reader-loss", "writer-loss", "registry-stale", "root-admin-key-loss",
        "historical-regrant", "destruction", "profile-migration", "backup-restore",
        "server-key-rotation", "update-rollback", "security-event", "quarterly-recovery-test",
    ]));
    assert!(docs.commands().iter().all(|c| cli_schema().contains(c)));
}
```

- [ ] **Step 2: Run documentation test and verify runbooks are absent**

Run: `cargo test --locked -p xtask --test operations_docs`

Expected: FAIL because the operational set is incomplete.

- [ ] **Step 3: Write executable procedures and cleartext-free monitoring**

Each runbook defines trigger, authorized roles/capabilities, prerequisites, re-authentication/key sources, exact commands/API/UI steps, expected statuses, rollback or no-return boundary, verification, Security Event/audit evidence, escalation, and closure. Document no Root-only recovery when all Admin keys are lost; no recall of old Reader plaintext; no silent backend fallback; no cancellation after destruction `inProgress`; no Recovery success on partial inventory.

Monitoring covers availability, capacity, queue age, checkpoint/TSA state, Registry age/lease, backup freshness/restore test, certificate/provider health, Security Events, and privileged admin audit using object hashes/pseudonymous IDs only. Never label contents or include source IP beyond justified access/security logs with retention policy. Update/rollback requires signed artifacts and prevents format/schema/vector rollback that would silently lose readability.

- [ ] **Step 4: Validate commands, topics, links, and a tabletop execution transcript**

Run: `cargo test --locked -p xtask --test operations_docs && cargo run --locked -p xtask -- release operations validate ops/release/evidence/v0.1/operations`

Expected: PASS; the transcript exercises at least Writer loss, Reader loss, Registry stale, server restore, Evidence outage, and unreachable destruction replica.

- [ ] **Step 5: Commit operations documentation**

```bash
git add docs/operations ops/runbooks schemas/release
git commit -m "docs(operations): add production lifecycle runbooks"
```

### Task 9: Current Cryptographic Review, Independent Security Review, and Go-Live Record

**Files:**
- Create: `docs/release/templates/cryptography-review.md`
- Create: `docs/release/templates/security-review-acceptance.md`
- Create: `docs/release/templates/go-live-report.md`
- Create: `schemas/release/cryptography-review.schema.json`
- Create: `schemas/release/security-review.schema.json`
- Create: `schemas/release/go-live-report.schema.json`
- Create: `tools/xtask/src/release/external_evidence.rs`
- Test: `tools/xtask/tests/external_evidence.rs`

**Interfaces:**
- Consumes: release-current BSI source, independent reviewer report, secure organization Go-live evidence.
- Produces: validated external evidence; any missing/rejected/unresolved item blocks production release.

- [ ] **Step 1: Write external-evidence freshness and unresolved-finding tests**

```rust
#[test]
fn external_gate_rejects_missing_stale_or_unresolved_reviews() {
    for bundle in [fixtures::missing_bsi_review(), fixtures::older_release_review(),
                   fixtures::security_review_with_open_critical(), fixtures::missing_privacy_decision()] {
        assert!(verify_external_evidence(bundle, release_manifest()).is_err());
    }
}
```

- [ ] **Step 2: Run external-evidence test and verify real evidence is absent**

Run: `cargo test --locked -p xtask --test external_evidence`

Expected: FAIL until the actual release evidence bundle is supplied; templates alone never pass.

- [ ] **Step 3: Obtain and structure genuine release-specific evidence**

Have a qualified reviewer assess `EINSATZARCHIV-SUITE-1` against the then-current BSI TR-02102-1, recording exact publication/version/date, algorithms/parameters, result, deviations, and whether a new suite ID is required. If not approved, do not ship Suite 1; create a new design/plan rather than rewriting old objects.

Commission an independent security review of trust/bootstrap/admin authorization, key/provider separation, parser/crypto use, Writer transaction, server protocol/persistence, Reader gates, re-grant, destruction, Evidence, supply chain, and operations. Record report hash, reviewer independence/scope/method/date, findings, severity, resolution commits, retest evidence, and formal acceptance; unresolved release-blocking findings fail.

Complete the secure Go-live report with every §21 item: named data/Admin/server/Recovery/Approver/HGA roles and deputies; two Admin keys/backups/rotation; every production Operator binding/OS account/provider/revocation; key custody/media/anchor copies/fingerprint; Reader/Writer loss processes; Registry/policy/profile/TSA/renewal; free-text, retention and destruction rules; explicit `.eds` privacy approval or disabled decision; backup/restore interval/evidence; archive backend semantics; update/rollback; monitoring/Security Event ownership; full Recovery test. For every production desktop, include current full-disk-encryption, locked/non-shared-account, automatic-screen-lock, and supported-patch evidence: import validated application evidence for reportable checks and a named/manual attestation with date/source/owner for every `Unknown`; any `Fail`, missing attestation, or unsupported patch blocks Go-live. Include the documented administrative clock-release procedure, authorization ownership, expiry/replay limits, and a verified sample audit record. Explicitly distinguish technical integrity from organizational/legal Revisionssicherheit.

- [ ] **Step 4: Validate the actual external evidence against this release**

Run:

```bash
cargo run --locked -p xtask -- release external-evidence validate ops/release/evidence/v0.1/external
```

Expected: PASS only when evidence hashes bind the exact release source, artifacts, matrix, schemas, and vectors and no blocking finding/decision is unresolved.

- [ ] **Step 5: Commit templates and verifier, not sensitive organization evidence**

```bash
git add docs/release/templates schemas/release tools/xtask
git commit -m "docs(release): require cryptographic security and go-live review"
```

Keep actual named/sensitive evidence in the access-controlled release store referenced by hash; do not commit private keys, personal contact data, media locations, or unredacted reviewer material to the public source repository.

### Task 10: Complete Acceptance Ledger and Produce the v0.1 Release Decision

**Files:**
- Create: `docs/traceability/stage-7-gate.md`
- Create: `docs/traceability/v0.1-acceptance-map.md`
- Modify: `docs/traceability/v0.1-requirements.csv`
- Create: `tools/xtask/src/release/ledger.rs`
- Create: `tools/xtask/src/release/decision.rs`
- Test: `tools/xtask/tests/release_gate.rs`

**Interfaces:**
- Consumes: all Stage 1–7 automated, platform, and external evidence.
- Produces: `xtask verify-release` and canonical signed `ea.release-decision/v1`; no success if any row is merely implemented/integrated or blocked external.

- [ ] **Step 1: Write the fail-closed final-gate test**

```rust
#[test]
fn release_requires_all_54_criteria_and_every_unnumbered_gate() {
    let decision = evaluate_release(fixtures::complete_bundle()).unwrap();
    assert_eq!(decision.acceptance_criteria, (1_u8..=54).collect::<Vec<_>>());
    assert!(decision.unnumbered_sections.contains_all(["21", "22.1", "22.2", "22.3", "22.4", "22.5", "22.6", "22.7", "25"]));
    assert!(decision.rows.iter().all(|r| r.status == RequirementStatus::ReleaseVerified));
    for incomplete in fixtures::each_single_missing_requirement() {
        assert!(evaluate_release(incomplete).is_err());
    }
}
```

- [ ] **Step 2: Run final gate and verify incomplete release fails**

Run: `cargo test --locked -p xtask --test release_gate`

Expected: FAIL until all platform and genuine external evidence exists.

- [ ] **Step 3: Reconcile every design paragraph, AK, risk, and gate to evidence**

For each ledger row, verify exact spec reference, normative summary hash, primary/contributing stages, plan/task, automated evidence hash, manual/external evidence hash, and status transition history. Mark `release-verified` only after the final verifier loads and validates those artifacts. Primary Stage 7 AK are 19, 21, 22, 31, and 32, but the gate reopens every earlier criterion and cross-stage contribution. Explicitly record Access scope exclusion with no gate. `blocked-external` always means release denied.

Generate `v0.1-acceptance-map.md` from the ledger so it cannot drift. Verify all old vectors remain, public CDDL/schemas/compatibility/README ship with Desktop and CLI, support matrix signature verifies, all artifacts/signatures/SBOM/provenance map, release notes preserve exact legal/status boundaries, and every §25 risk has an implemented control plus residual-risk owner.

- [ ] **Step 4: Run the full release verification once and follow the same process to exit**

Run:

```bash
pnpm verify:release -- --matrix ops/release/support-matrix.json --evidence-dir ops/release/evidence/v0.1
```

Expected: PASS with exit 0 and a signed canonical `ea.release-decision/v1` containing all 54 AK, all unnumbered gates, exact source/artifact/matrix/ledger hashes, and no unresolved/blocked row. Any other exit means v0.1 is not releasable.

- [ ] **Step 5: Commit the final traceability state after the genuine gate is green**

```bash
git add docs/traceability tools/xtask
git commit -m "release: verify Einsatzarchiv v0.1 acceptance"
```

Do not create this commit from fixture-only evidence. The commit is authorized only after the real matrix and external evidence pass the exact Step 4 command.
