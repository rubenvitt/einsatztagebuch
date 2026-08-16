# Einsatzarchiv Stage 4 Reader Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a cross-platform Reader that incrementally replicates exact archive objects, fully verifies them before local decryption, maintains an encrypted local search index, and presents content and technical integrity without conflating missing access with corruption.

**Architecture:** Reader sync durably stores raw exact bytes and advances only through a `VerifiedSyncBatch`. The verification pipeline consumes Stage 1 proof types in the fixed §14.1 order; only `VerifiedEncryptedEntry` plus `VerifiedGrantForRecipient` can reach the HPKE decryptor. Decrypted records enter an encrypted local database and generated view DTOs, while technical entries without a grant remain visible outside the fachliche index.

**Tech Stack:** Shared Rust trust/format/schema/sync crates, native Reader X25519 and Ed25519 keys, SQLCipher/equivalent encrypted SQLite, Tauri 2, React 19, TypeScript, Ant Design 6, Vitest/React Testing Library, Playwright.

## Global Constraints

- Die Schlüsselwörter **MUSS**, **DARF NICHT**, **SOLL**, **SOLL NICHT** und **DARF** sind normativ zu verstehen. Ein Release darf von einer MUSS-Anforderung nicht abweichen. Eine Abweichung von SOLL erfordert eine dokumentierte Sicherheits- oder Betriebsbegründung.
- **Merker Web-Reader**, `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §12: Tasks 1, 2, 4 und 7 werden neu geschrieben. Task 3 behält seinen Rust-Kern und erhält neue Bindungen sowie den gepinnten Anchor im Datei-Modus. Task 5 bleibt unverändert. Task 6 wird angepasst. Task 8 wird um Browser-Matrix und Datei-Modus erweitert. **Achtung:** Dieser Plan schreibt an mehreren Stellen noch SQLCipher, Tauri 2 und den nativen Key-Provider fest — alles durch §8.1 (invertierter Rust-Index, ChaCha20-Poly1305, OPFS) und §11.3 (nativer Reader-Key-Provider entfällt) widerlegt. Die verbindliche Größenschwelle des Index nach §8.1 wird in dieser Überarbeitung festgelegt.

<!-- web-reader-stage-4-block -->
**BLOCKIERT — Laufzeitnachweis nach `web-reader-design.md` §14.1.** Die Überarbeitung dieses Plans darf erst beginnen, wenn ein ausführbarer Spike vorliegt: `wasm-bindgen`-Schicht, `getrandom` mit `wasm_js` in einer echten JS-Umgebung, eine HPKE-Entkapselung und eine Signaturprüfung gegen einen bestehenden Testvektor. Belegt ist bisher ausschließlich, dass die Bibliotheks-Crates für `wasm32-unknown-unknown` übersetzen. Scheitert der Spike, fällt die Browser-Entscheidung aus §2 Punkt 1 in sich zusammen.

Rücknahmeliste für diesen Fall, erzeugt von `docs/superpowers/plans/2026-08-16-einsatzarchiv-web-reader-stage-1-prerequisites.md`:
1. `targets = ["wasm32-unknown-unknown"]` in `rust-toolchain.toml`;
2. das Feature `wasm_js` in `Cargo.toml` samt dem 2-Zeilen-Delta in `Cargo.lock` und der `getrandom`-Zeile in `docs/adr/0001-toolchain-and-cryptography-dependencies.md`;
3. der vierte Eintrag in `verify_quick_commands()` samt Pin-Test, `ensure_wasm32_target_available()`, dem normativen Codeblock und der Gate-Kommandoliste im Stage-1-Plan;
4. die Merker-Zeilen in den Stage-Plänen 2 bis 7;
5. die Normativkorrekturen an `design.md` (§5.1, §5.2, §5.3, §7, §14.2, §17.4, §18.3, Support-Matrix) und an den Global Constraints des Stage-1-Plans.
<!-- /web-reader-stage-4-block -->
- Microsoft Access is outside scope; **Access Grant** means only the signed key envelope.
- Non-goals are fixed: no live incident log, dispatch/alarm/control-center integration, patient record or identifying patient data, concurrent offline Writers, normal-app mutation/deletion of finalized content, AI summarization/OCR, public links, server-side content search, unprofiled network paths, qualified personal electronic signature, TR-ESOR certification claim, screenshot/transcription prevention, or cryptographic recall of already decrypted data.
- Product invariants apply verbatim: exactly one active Writer; never-reused predecessor-bound sequences; immutable `.eip` bytes except whole-object authorized replacement by `.eds`; amendment-only corrections; one fresh CEK/ciphertext; one signed grant per recipient; exactly one active Recovery grant before commit; no Reader/Recovery/HGA/Approver private key on Writer; no retained CEK/decryptable draft key; no server decrypt/grant key; server-independent archive verification; independent schema/format/suite versions with old bytes unchanged; separate Sync/verification/Evidence/Entry/destruction statuses; no legal overclaim from a hash chain; every active Reader initially granted; external-anchor recovery; and only Root-signed OS/device-bound operator snapshots.
- Archive and Trust bytes remain immutable and server-independent. Schema, format, and suite versions stay independent.
- Verification always precedes HPKE decapsulation and decryption. Unknown/invalid/incomplete objects are isolated, not indexed, and never shown as an empty incident.
- Missing own grant is exactly `fehlender Grant`: the valid technical chain entry stays visible but is neither decrypted nor fachlich indexed.
- A valid `.eds` with its full authorization/evidence chain is exactly `autorisiert vernichtet`; an incomplete Stub is an `ungeklärte Lücke`.
- Reader has separate X25519 KEM and Ed25519 device/audit keys. Admin role grants no content access; local configuration cannot expand a signed role.
- Reader cache, index, audit, and keys are encrypted/protected. No decrypted content enters temp files, clipboard, crash dumps, logs, filenames, server metadata, or telemetry.
- Unencrypted bulk export is disabled. A single export requires deliberate target choice, native re-authentication, and signed local audit.
- Reader locks after configured inactivity; secure default is five minutes and OS lock ends the session.
- UI uses exact verification/evidence/entry language, text in addition to color/icon, keyboard and screen-reader access, and keeps invalid objects in `Prüfprobleme`.
- UI remains on Ant Design 6 with German `ConfigProvider`, shared exact tokens, `zeroRuntime: true`, statically extracted local hashed CSS, CSP without runtime/external styles, Ant `App` overlay context, direct CSR `@phosphor-icons/react` imports only, visible focus, and reduced-motion support.
- Supported desktop/CLI platforms match the global Stage 7 matrix; Stage 4 code and host smokes must already be portable.
- Crypto/format/Trust remains shared Rust; TypeScript receives only view/status DTOs.
- v0.1 is complete only after Stage 7 and every acceptance criterion/gate passes.

The decryption gate order is exact: (1) format/limits, (2) Root and Trust chain, (3) bound Registry/lease/Writer, (4) manifest/signature/Entry/object/ciphertext hashes, (5) sequence/predecessor/Writer transition, (6) grant plan and Recovery grant, (7) Receipt/checkpoints if present, (8) required Evidence, (9) own grant including issuer capability, authorization, `effectiveNow <= expiresAt`, and Entry hash; only then HPKE-open and AEAD-open.

---

### Task 1: Reader Key Profile, Encrypted Cache, and Technical State Store

**Files:**
- Create: `crates/ea-reader/Cargo.toml`
- Create: `crates/ea-reader/src/lib.rs`
- Create: `crates/ea-reader/src/key_profile.rs`
- Create: `crates/ea-reader/src/store.rs`
- Create: `crates/ea-local-store/migrations/0002_reader.sql`
- Test: `crates/ea-reader/tests/key_profile.rs`
- Test: `crates/ea-reader/tests/encrypted_store.rs`

**Interfaces:**
- Consumes: native `KeyProvider`, encrypted DB service, Reader certificate/Operator binding.
- Produces: `ReaderKeyProfile`, `ReaderStore::{put_exact_object,get_exact_object,put_entry_state}`, and encrypted cursor/index tables.

- [ ] **Step 1: Write separated-key and raw-store encryption tests**

```rust
#[test]
fn reader_requires_distinct_kem_and_authentication_keys() {
    let same = fixtures::same_key_for_both_roles();
    assert_eq!(ReaderKeyProfile::validate(same).unwrap_err().code(), "EA-KEY-ROLE-COLLISION");
}

#[tokio::test]
async fn exact_objects_and_index_canaries_are_not_plaintext_on_disk() {
    let h = ReaderHarness::new().await;
    h.store.put_exact_object(fixtures::entry_bytes()).await.unwrap();
    h.store.put_test_search_value("CANARY-PERSON").await.unwrap();
    let raw = h.database_bytes();
    assert!(!raw.contains_subslice(fixtures::entry_bytes().as_ref()));
    assert!(!raw.contains_subslice(b"CANARY-PERSON"));
}
```

- [ ] **Step 2: Run tests and verify Reader persistence is absent**

Run: `cargo test --locked -p ea-reader --test key_profile --test encrypted_store`

Expected: FAIL because Reader key/profile/store code does not exist.

- [ ] **Step 3: Implement encrypted raw-object and derived-state storage**

```rust
pub enum ReaderEntryState {
    VerifiedEncrypted,
    MissingGrant,
    UnsupportedSchema,
    AuthorizedDestroyed,
    Invalid { code: TechnicalErrorCode },
}
```

Require distinct KEM/auth certificate keys and reject Writer/Recovery/HGA/Approver private roles in the profile. Encrypt the SQLCipher database key through the native provider. Store exact object bytes keyed by object hash, technical relationships, last durably verified cursor/head, encrypted derived record/index data, and signed local audit events. Do not store fachliche fields in unencrypted columns or migration diagnostics.

- [ ] **Step 4: Run storage, wrong-key, and backup-restore tests**

Run: `cargo test --locked -p ea-reader --test key_profile --test encrypted_store`

Expected: PASS; wrong OS account/provider key cannot open the database and a restored DB without its excluded key remains unreadable.

- [ ] **Step 5: Commit Reader storage foundation**

```bash
git add crates/ea-reader crates/ea-local-store Cargo.toml Cargo.lock
git commit -m "feat(reader): add encrypted Reader state"
```

### Task 2: Incremental Reader Sync and Verified Cursor Advancement

**Files:**
- Create: `crates/ea-reader/src/sync.rs`
- Create: `crates/ea-reader/src/cursor.rs`
- Create: `crates/ea-reader/src/batch.rs`
- Test: `crates/ea-reader/tests/sync_resume.rs`
- Test: `crates/ea-reader/tests/sync_attacks.rs`

**Interfaces:**
- Consumes: Stage 3 `ReaderBatchV1`, exact object store, `verify_archive/verify_chain`.
- Produces: `ReaderSyncService::pull(cursor) -> VerifiedSyncBatch`, `ConfirmedCursor`, and rebuild from Genesis or verified checkpoint.

- [ ] **Step 1: Write interruption and start-head mismatch tests**

```rust
#[tokio::test]
async fn cursor_moves_only_after_all_objects_are_durable_and_chain_verified() {
    for fault in ReaderSyncFaultPoint::ALL {
        let mut h = ReaderSyncHarness::new().await;
        let before = h.confirmed_cursor();
        let _ = h.pull_with_fault(*fault).await;
        let reopened = h.restart().await;
        assert_eq!(reopened.confirmed_cursor(), before);
        reopened.pull().await.unwrap();
        assert_eq!(reopened.confirmed_head(), fixtures::batch_end_head());
    }
}

#[tokio::test]
async fn mismatched_start_head_stops_without_cursor_progress() {
    let err = harness.pull(fixtures::batch_for_different_head()).await.unwrap_err();
    assert_eq!(err.code(), "EA-READER-START-HEAD-MISMATCH");
}
```

- [ ] **Step 2: Run sync tests and verify missing service**

Run: `cargo test --locked -p ea-reader --test sync_resume --test sync_attacks`

Expected: FAIL because incremental sync and proof-state cursor do not exist.

- [ ] **Step 3: Implement durable batch processing**

```rust
pub async fn pull(&self, cursor: ConfirmedCursor)
    -> Result<VerifiedSyncBatch, ReaderSyncError>;

impl ReaderStore {
    pub async fn confirm_batch(&self, batch: VerifiedSyncBatch)
        -> Result<ConfirmedCursor, StoreError>;
}
```

Send chain ID, highest contiguous verified sequence, its Entry hash, and opaque technical cursor. Verify the response binds that exact start head. Stream each object with limits, store exact bytes durably, reconstruct/verify Trust and chain through batch end, and only then atomically persist the next cursor/head. On interruption, retry from the previous confirmed cursor. Stop on missing object, gap, fork, or wrong start head. Rebuild after cache loss from Genesis or a locally verified checkpoint without trusting server lists.

- [ ] **Step 4: Run every batch fault point and rebuild tests**

Run: `cargo test --locked -p ea-reader --test sync_resume --test sync_attacks -- --test-threads=1`

Expected: PASS; retries are idempotent and no invalid batch advances state.

- [ ] **Step 5: Commit incremental Reader sync**

```bash
git add crates/ea-reader
git commit -m "feat(reader): verify incremental sync before cursor advance"
```

### Task 3: Verification-Before-Decryption and Missing-Grant Semantics

**Files:**
- Create: `crates/ea-reader/src/verify.rs`
- Create: `crates/ea-reader/src/grant.rs`
- Create: `crates/ea-reader/src/decrypt.rs`
- Create: `crates/ea-reader/src/entry_state.rs`
- Test: `crates/ea-reader/tests/verification_order.rs`
- Test: `crates/ea-reader/tests/missing_grant.rs`
- Test: `crates/ea-reader/tests/historical_expiry.rs`
- Test: `crates/ea-reader/tests/destroyed_stub.rs`

**Interfaces:**
- Consumes: verified archive/Trust proof states, Reader KEM handle, schema registry.
- Produces: `ReaderVerifier::classify`, `VerifiedGrantForRecipient`, `ReaderDecryptor::decrypt`, `VerifiedDecryptedRecord`.

- [ ] **Step 1: Write proof-order, missing-grant, expiry, and Stub tests**

```rust
#[tokio::test]
async fn hpke_is_never_called_before_all_public_checks_pass() {
    for broken in fixtures::each_public_verification_failure() {
        let kem = RecordingKem::new();
        assert!(ReaderDecryptor::new(&kem).open(broken).await.is_err());
        assert_eq!(kem.open_calls(), 0);
    }
}

#[test]
fn valid_entry_without_own_grant_is_technical_missing_grant() {
    let state = ReaderVerifier::classify(fixtures::valid_entry_without_own_grant()).unwrap();
    assert!(matches!(state, ReaderEntryState::MissingGrant));
    assert!(state.is_chain_visible());
    assert!(!state.is_decryptable());
}
```

- [ ] **Step 2: Run verification tests and verify failure**

Run: `cargo test --locked -p ea-reader --test verification_order --test missing_grant --test historical_expiry --test destroyed_stub`

Expected: FAIL because Reader proof-state classification/decryption is absent.

- [ ] **Step 3: Implement typed decryption gates**

```rust
pub async fn decrypt(
    &self,
    entry: &VerifiedEncryptedEntry,
    grant: &VerifiedGrantForRecipient,
    recipient: &dyn KemDecapsulator,
    schemas: &SchemaRegistry,
) -> Result<VerifiedDecryptedRecord, ReaderError>;
```

Only `ReaderVerifier` can create `VerifiedGrantForRecipient`, after checking issuer certificate/capability, initial versus historical fields, original Recovery grant, two-Approver authorization, Entry/recipient/Registry binding, and current usage deadline. Recompute `effectiveNow` before every historical decapsulation; expired grants remain archived but classify `Invalid` with detail `historische Freigabe abgelaufen`. AEAD-open uses exact manifest AAD and validates payload schema/operator commitment before returning a record. A valid Stub never calls HPKE and exposes only `AuthorizedDestroyed` technical data.

- [ ] **Step 4: Run mutation and two-reader interoperability tests**

Run: `cargo test --locked -p ea-reader`

Expected: PASS; two distinct Reader KEM keys open one ciphertext through separate grants, while every one-byte object/grant mutation fails before fachliche indexing.

- [ ] **Step 5: Commit Reader verification/decryption**

```bash
git add crates/ea-reader
git commit -m "feat(reader): decrypt only fully verified entries"
```

### Task 4: Encrypted Local Index, Schema Compatibility, and Search

**Files:**
- Create: `crates/ea-reader/src/index.rs`
- Create: `crates/ea-reader/src/search.rs`
- Create: `crates/ea-reader/src/schema_view.rs`
- Modify: `crates/ea-local-store/migrations/0002_reader.sql`
- Test: `crates/ea-reader/tests/search.rs`
- Test: `crates/ea-reader/tests/schema_compatibility.rs`
- Test: `crates/ea-reader/tests/reindex.rs`

**Interfaces:**
- Consumes: `VerifiedDecryptedRecord`, Stage 1 `SchemaRegistry` transformations.
- Produces: `ReaderIndex::upsert/rebuild/search`, `ReaderQuery`, `ReaderSearchHit`, and source/target schema-labelled views.

- [ ] **Step 1: Write local-only search and compatibility tests**

```rust
#[tokio::test]
async fn search_filters_only_decrypted_verified_records() {
    index.upsert(fixtures::verified_record("2026-0001", "Brand", "LF 10", "Ada")).await.unwrap();
    index.record_technical_state(fixtures::missing_grant_entry()).await.unwrap();
    let hits = index.search(ReaderQuery::vehicle("LF 10")).await.unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].human_incident_number, "2026-0001");
}

#[test]
fn old_view_is_labelled_and_unknown_schema_is_not_indexed() {
    assert_eq!(derive_view(fixtures::v1_record()).unwrap().source_schema(), ("ea.incident", 1));
    assert!(matches!(derive_view(fixtures::unknown_schema()), Err(SchemaError::Unsupported { .. })));
}
```

- [ ] **Step 2: Run index tests and verify failure**

Run: `cargo test --locked -p ea-reader --test search --test schema_compatibility --test reindex`

Expected: FAIL because Reader index/search do not exist.

- [ ] **Step 3: Implement encrypted derived indexing with full rebuild**

Index only `VerifiedDecryptedRecord` and normalized derived views. Support filters by incident period, keyword, vehicle, and person locally. Keep source Entry hash/sequence/schema and derived target schema with each row. Technical entries with missing grants, invalid objects, Stubs, or unsupported schemas go to technical state tables, never fake incident rows. Rebuild deletes only derived index rows and re-verifies/decrypts from exact cached archive bytes; no mutable index state is authoritative.

- [ ] **Step 4: Run search, cache-loss, and historical-schema tests**

Run: `cargo test --locked -p ea-reader --test search --test schema_compatibility --test reindex`

Expected: PASS; later current-schema rules do not invalidate v1 payloads and unknown schemas remain isolated.

- [ ] **Step 5: Commit encrypted local search**

```bash
git add crates/ea-reader crates/ea-local-store
git commit -m "feat(reader): index verified records locally"
```

### Task 5: Amendment References and Original/Amendment Projection

**Files:**
- Create: `crates/ea-reader/src/amendment.rs`
- Test: `crates/ea-reader/tests/amendments.rs`

**Interfaces:**
- Consumes: verified original and amendment records.
- Produces: `CorrectionReference { original_record_id, original_entry_hash, original_sequence }`, `ReaderEntryThread`, and Stage 5 Writer import contract.

- [ ] **Step 1: Write multi-amendment and no-replacement tests**

```rust
#[test]
fn amendments_join_without_replacing_original() {
    let thread = ReaderEntryThread::build(fixtures::original(), vec![fixtures::amendment_b(), fixtures::amendment_a()]).unwrap();
    assert_eq!(thread.original().record_id(), fixtures::original_id());
    assert_eq!(thread.amendments().iter().map(|a| a.sequence()).collect::<Vec<_>>(), vec![7, 9]);
    assert_eq!(thread.correction_reference(), CorrectionReference {
        original_record_id: fixtures::original_id(),
        original_entry_hash: fixtures::original_hash(),
        original_sequence: ChainSequence(4),
    });
}
```

- [ ] **Step 2: Run amendment tests and verify missing projection**

Run: `cargo test --locked -p ea-reader --test amendments`

Expected: FAIL because amendment grouping/reference types do not exist.

- [ ] **Step 3: Implement exact references and stable ordering**

Validate each amendment's original record ID/hash/sequence and incident number against the verified original. Sort multiple amendments by chain sequence, retain every original and amendment byte/hash, and generate a cleartext-free correction reference containing only original ID, sequence, and Entry hash for Writer handoff. Never mark an original superseded or hidden.

- [ ] **Step 4: Run malformed-reference and multiple-amendment tests**

Run: `cargo test --locked -p ea-reader --test amendments`

Expected: PASS; mismatched hash/sequence remains a verification problem rather than joining the thread.

- [ ] **Step 5: Commit amendment projection**

```bash
git add crates/ea-reader
git commit -m "feat(reader): link originals and amendments"
```

### Task 6: Session Lock, Signed Audit, and Single-Record Export

**Files:**
- Modify: `crates/ea-audit/src/lib.rs`
- Create: `crates/ea-audit/src/export.rs`
- Create: `crates/ea-reader/src/session.rs`
- Create: `crates/ea-reader/src/export.rs`
- Test: `crates/ea-reader/tests/session_lock.rs`
- Test: `crates/ea-reader/tests/export.rs`
- Modify: `crates/ea-audit/tests/redaction.rs`

**Interfaces:**
- Consumes: native `OperatorAuthenticator`, Reader signing key, Stage 2 `LocalAuditService`, `VerifiedDecryptedRecord`, empty/new target.
- Produces: `ReaderSession`, `ReaderService::export_one`, and signed cleartext-free export audit context; no bulk-export API.

- [ ] **Step 1: Write lock and export authorization tests**

```rust
#[tokio::test]
async fn inactivity_and_os_lock_clear_decrypted_session_state() {
    let mut session = ReaderSession::new(Duration::from_secs(300));
    session.open(fixtures::record());
    session.advance_inactivity(Duration::from_secs(301));
    assert!(session.is_locked());
    assert!(session.open_records().is_empty());
}

#[tokio::test]
async fn export_requires_new_target_and_matching_reauth_purpose() {
    assert!(service.export_one(record(), existing_nonempty_target(), export_proof()).await.is_err());
    assert!(service.export_one(record(), new_target(), finalize_proof()).await.is_err());
}
```

- [ ] **Step 2: Run session/export tests and verify failure**

Run: `cargo test --locked -p ea-audit -p ea-reader --test session_lock --test export`

Expected: FAIL because Reader session and export controls do not exist.

- [ ] **Step 3: Implement strict single-record export**

End session on five-minute configured inactivity default or OS lock; zero decrypted Rust buffers and clear UI view state best-effort. Export only one explicitly selected verified record after native `ReauthPurpose::PlaintextExport`; require deliberate new/empty local target with restrictive permissions; never expose a method taking “all records” or search results. Sign an audit digest containing pseudonymous operator binding hash, Entry hash, target type (not full path), time from `EffectiveNow`, action code, and success/failure—never payload or clear filename.

- [ ] **Step 4: Run API-surface, audit-canary, and permissions tests**

Run: `cargo test --locked -p ea-audit -p ea-reader`

Expected: PASS; public API inspection finds no bulk export, and canaries are absent from audit bytes/logs.

- [ ] **Step 5: Commit Reader session/export controls**

```bash
git add crates/ea-audit crates/ea-reader Cargo.toml Cargo.lock
git commit -m "feat(reader): lock sessions and audit single exports"
```

### Task 7: Reader Tauri Commands and Integrity-Centered UI

**Files:**
- Create: `apps/desktop/src-tauri/src/commands/reader.rs`
- Create: `apps/desktop/src/features/reader/ReaderPage.tsx`
- Create: `apps/desktop/src/features/reader/SearchPanel.tsx`
- Create: `apps/desktop/src/features/reader/EntryView.tsx`
- Create: `apps/desktop/src/features/reader/TechnicalView.tsx`
- Create: `apps/desktop/src/features/reader/VerificationProblems.tsx`
- Create: `apps/desktop/src/features/reader/AmendmentThread.tsx`
- Create: `apps/desktop/src/components/integrity/VerificationBadge.tsx`
- Create: `apps/desktop/src/components/integrity/EvidenceStatus.tsx`
- Create: `apps/desktop/src/components/integrity/FingerprintBlock.tsx`
- Create: `apps/desktop/src/components/integrity/ChainIntegrityRail.tsx`
- Test: `apps/desktop/src/features/reader/ReaderPage.test.tsx`
- Test: `tests/e2e/reader.spec.ts`

**Interfaces:**
- Consumes: generated Reader view/status DTOs only.
- Produces: Reader UX required by §§17.2, 17.4, and 17.5.

- [ ] **Step 1: Write state-separation and accessibility tests**

```tsx
it('shows missing grant technically without rendering an empty incident', async () => {
  render(<ReaderPage bridge={bridgeWithMissingGrant()} />)
  expect(await screen.findByText('fehlender Grant')).toBeVisible()
  expect(screen.getByText(/Sequenz 12/)).toBeVisible()
  expect(screen.queryByRole('heading', { name: /Einsatznummer/ })).not.toBeInTheDocument()
})

it('keeps invalid objects in Prüfprobleme', async () => {
  render(<ReaderPage bridge={bridgeWithInvalidObject()} />)
  await user.click(screen.getByRole('tab', { name: 'Prüfprobleme' }))
  expect(screen.getByText('ungültig')).toBeVisible()
})
```

- [ ] **Step 2: Run UI tests and verify components are absent**

Run: `pnpm --dir apps/desktop test --run ReaderPage`

Expected: FAIL because Reader UI/commands do not exist.

- [ ] **Step 3: Implement Reader presentation without security logic**

Show incident number/time/keyword only from a decrypted DTO. Keep a permanent textual verification status. Technical view explains sequence, hashes, Writer key/certificate, Registry, Receipt, and Evidence; `ChainIntegrityRail` renders only actually verified nodes. Missing grant remains technical. Authorized destruction shows no content and exact entry state. Unsupported schema says `nicht darstellbares Schema`; invalid objects live only in `Prüfprobleme`. Original, amendments, and evidence are separate views within one thread. Export UI selects one target, warns that copies cannot be revoked, and invokes native re-authentication. All controls are keyboard reachable with visible focus and accessible labels/tooltips.

- [ ] **Step 4: Run component, keyboard, Reader E2E, and CSP tests**

Run:

```bash
pnpm --dir apps/desktop test --run
pnpm --dir apps/desktop exec playwright test tests/e2e/reader.spec.ts
pnpm --dir apps/desktop build
```

Expected: PASS; UI remains responsive during simulated sync and no icon/color is the sole status carrier.

- [ ] **Step 5: Commit Reader UI**

```bash
git add apps/desktop tests/e2e pnpm-lock.yaml
git commit -m "feat(desktop): deliver verified Reader experience"
```

### Task 8: Reader Interoperability, Privacy, and Stage Gate

**Files:**
- Create: `tests/ea-system-tests/tests/cross_platform_two_readers.rs`
- Create: `tests/ea-system-tests/tests/e2e_reader_sync_interruptions.rs`
- Create: `tests/ea-system-tests/tests/privacy_canaries_reader.rs`
- Create: `docs/traceability/stage-4-gate.md`
- Modify: `docs/traceability/v0.1-requirements.csv`
- Modify: `tools/xtask/src/main.rs`
- Test: `tools/xtask/tests/stage_gate.rs`

**Interfaces:**
- Consumes: complete Stage 4 Reader.
- Produces: `xtask stage-gate 4`, evidence for primary AK 10, 42, 43 and integrated contributions to AK 17, 23, 30, 33, 40, 41, 51, 53.

- [ ] **Step 1: Write cumulative Reader gate test**

```rust
#[test]
fn stage_four_gate_requires_two_readers_and_every_cursor_fault() {
    let gate = xtask_test::stage_gate(4);
    assert_eq!(gate.primary_acceptance_criteria, [10, 42, 43]);
    assert!(gate.scenarios.contains("same-ciphertext-two-distinct-grants"));
    assert!(gate.scenarios.contains_all(ReaderSyncFaultPoint::ALL));
    assert!(gate.canary_findings.is_empty());
}
```

- [ ] **Step 2: Run the gate and confirm missing evidence fails**

Run: `cargo test --locked -p xtask --test stage_gate stage_four`

Expected: FAIL listing missing Reader interoperability, sync, and privacy evidence.

- [ ] **Step 3: Add end-to-end Reader evidence and ledger links**

Generate one Writer ciphertext with grants for two distinct Reader certificates/KEM keys; replicate and verify/decrypt it independently. Remove each Reader's grant in turn and prove only that Reader sees `fehlender Grant`. Interrupt every network receive, object flush, DB transaction, verification, and cursor step. Exercise gap, fork, wrong start head, bad Receipt, unsupported schema/suite, expired historical grant, valid/invalid Stub, index rebuild, inactivity lock, wrong OS user, and single export. Search logs, cache bytes, temp directories, crash output, filenames, clipboard hooks, and UI traces for canaries.

Update ledger to `implemented`/`integrated` only; cross-platform min/max, 50,000-record performance, and native provider matrices stay open for Stage 7.

- [ ] **Step 4: Run the complete Stage 4 gate**

Run:

```bash
pnpm test:reader-sync
pnpm test:interop
cargo run --locked -p xtask -- test-privacy --scope reader
pnpm --dir apps/desktop exec playwright test tests/e2e/reader.spec.ts
cargo run --locked -p xtask -- stage-gate 4
pnpm verify:quick
```

Expected: PASS locally with open Stage 7 release rows identified explicitly.

- [ ] **Step 5: Commit the Stage 4 gate**

```bash
git add tests docs/traceability tools/xtask
git commit -m "test(reader): close Reader stage"
```
