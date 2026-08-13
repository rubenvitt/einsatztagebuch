# Einsatzarchiv Stage 2 Offline Writer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a cross-platform Writer that can capture, review, and irreversibly finalize exactly one encrypted draft into a durable local archive without any network dependency.

**Architecture:** Keep draft storage, native key handling, archive durability, and finalization as separate Rust modules behind proof-state interfaces. The finalization transaction prepares immutable bytes first, crosses its irreversible boundary only after confirmed `draftDEK` deletion, publishes grants before `.eip`, and reconstructs every mutable queue/head from committed archive bytes. Tauri exposes narrow commands and React renders only validated Writer view models.

**Tech Stack:** Shared Stage 1 Rust crates, platform-native key/identity providers, SQLCipher or equivalently reviewed full SQLite encryption, Tauri 2, React 19, TypeScript, Ant Design 6, `@ant-design/static-style-extract`, `@phosphor-icons/react`, Vitest, React Testing Library, Playwright, pnpm.

## Global Constraints

- Die Schlüsselwörter **MUSS**, **DARF NICHT**, **SOLL**, **SOLL NICHT** und **DARF** sind normativ zu verstehen. Ein Release darf von einer MUSS-Anforderung nicht abweichen. Eine Abweichung von SOLL erfordert eine dokumentierte Sicherheits- oder Betriebsbegründung.
- Microsoft Access ist vollständig außerhalb des Scopes. There is no Access import path; **Access Grant/Zugriffsfreigabe** means only a signed CEK envelope.
- Non-goals are fixed: no live incident log, dispatch/alarm/control-center integration, patient record or identifying patient data, concurrent offline Writers, normal-app mutation/deletion of finalized content, AI summarization/OCR, public links, server-side content search, unprofiled network paths, qualified personal electronic signature, TR-ESOR certification claim, screenshot/transcription prevention, or cryptographic recall of already decrypted data.
- Product invariants apply verbatim: exactly one active Writer; never-reused predecessor-bound sequences; immutable `.eip` bytes except whole-object authorized replacement by `.eds`; amendment-only corrections; one fresh CEK/ciphertext; one signed grant per recipient; exactly one active Recovery grant before commit; no Reader/Recovery/HGA/Approver private key on Writer; no retained CEK/decryptable draft key; no server decrypt/grant key; server-independent archive verification; independent schema/format/suite versions with old bytes unchanged; separate Sync/verification/Evidence/Entry/destruction statuses; no legal overclaim from a hash chain; every active Reader initially granted; external-anchor recovery; and only Root-signed OS/device-bound operator snapshots.
- Exactly one active Writer and one active draft exist. Every committed sequence is unique and binds the direct predecessor.
- `.eip` bytes are never overwritten. Corrections are later signed amendments. A payload is encrypted exactly once with a fresh CEK and nonce.
- Before local commit there is exactly one Recovery grant and one initial grant for every Reader active in the bound Registry; grants publish before `.eip`.
- A Writer device contains no private Reader, Recovery, Historical Grant Authority, or Key Approver key. After finalization it retains neither CEK nor decryptable `draftDEK`.
- The server is not required for capture or finalization. Archive bytes, not SQLite status, are authoritative.
- Schema, format, and suite versions remain independent; all Stage 1 exact bytes and vectors are immutable.
- Operator data comes from a valid Root-signed device/OS-account binding and native re-authentication, never editable identity text.
- Writer must build on supported Windows 11 `x86_64`, current/previous macOS `arm64` plus supported Intel `x86_64`, and Ubuntu 24.04 LTS `x86_64`; full signed min/max release proof belongs to Stage 7.
- Cryptographic and format logic remains in shared Rust. TypeScript never creates grants, hashes, signatures, ciphertexts, Registry decisions, or archive bytes.
- SQLCipher/equivalent protects local data. No plaintext temp files or sensitive logs; telemetry/crash upload is off by default.
- UI uses exact Sync status copy `lokal gesichert`, `Upload ausstehend`, `synchronisiert`, `Fehler`, separates ordinary save from finalization, and never offers history or final-content access to Writer.
- v0.1 is complete only after Stage 7 and every acceptance criterion passes.

UI constraints are exact: Ant Design 6 with German `ConfigProvider`, shared tokens `eaInk #172033`, `eaSurface #F5F7FA`, `eaAction #245EA8`, `eaDanger #C6352B`, `eaVerified #187255`, `eaWarning #A65F00`, `zeroRuntime: true`, statically extracted local hashed CSS, CSP blocking runtime/external styles, Ant `App` context for overlays, direct CSR icon imports from `@phosphor-icons/react`, no `react-icons`, visible focus, semantic DOM, text in addition to color/icon, and `prefers-reduced-motion`.

---

### Task 1: Native Key-Provider Contract and Writer Role Guard

**Files:**
- Create: `crates/ea-key-provider/Cargo.toml`
- Create: `crates/ea-key-provider/src/lib.rs`
- Create: `crates/ea-key-provider/src/contract.rs`
- Create: `crates/ea-key-provider/src/in_memory.rs`
- Create: `crates/ea-key-provider/src/profile.rs`
- Test: `crates/ea-key-provider/tests/provider_contract.rs`
- Test: `crates/ea-key-provider/tests/writer_role_guard.rs`

**Interfaces:**
- Consumes: Stage 1 IDs, secret wrappers, COSE/HPKE types, Trust capabilities.
- Produces: `KeyProvider`, `KeyHandle`, `KeyPurpose`, `SecretPurpose`, `KeyProtectionProfile`, `WriterKeyProfile::validate`, and a deterministic in-memory provider confined to tests.

- [ ] **Step 1: Write provider and role-separation tests**

```rust
#[tokio::test]
async fn deleted_secret_cannot_be_unwrapped_or_restored() {
    let provider = InMemoryKeyProvider::new_for_test([7; 32]);
    let handle = provider.wrap_secret(SecretPurpose::DraftDek, SecretBytes::from([3; 32])).await.unwrap();
    provider.delete(&handle).await.unwrap();
    assert!(!provider.contains(&handle).await.unwrap());
    assert_eq!(provider.unwrap_secret(&handle).await.unwrap_err().code(), "EA-KEY-NOT-FOUND");
}

#[test]
fn writer_profile_rejects_forbidden_private_key_purposes() {
    for purpose in [KeyPurpose::ReaderKem, KeyPurpose::RecoveryKem,
                    KeyPurpose::HistoricalGrantAuthority, KeyPurpose::KeyApprover] {
        assert!(WriterKeyProfile::validate(&[purpose]).is_err());
    }
}
```

- [ ] **Step 2: Run tests and verify the provider contract is absent**

Run: `cargo test --locked -p ea-key-provider`

Expected: FAIL because the crate and provider types do not exist.

- [ ] **Step 3: Implement capability-scoped opaque handles**

```rust
#[async_trait::async_trait]
pub trait KeyProvider: Send + Sync {
    async fn generate(&self, purpose: KeyPurpose, protection: KeyProtectionProfile)
        -> Result<KeyHandle, KeyError>;
    async fn sign(&self, handle: &KeyHandle, digest: Hash32)
        -> Result<CoseSign1Bytes, KeyError>;
    async fn hpke_open(&self, handle: &KeyHandle, input: HpkeOpenInput)
        -> Result<SecretBytes, KeyError>;
    async fn wrap_secret(&self, purpose: SecretPurpose, secret: SecretBytes)
        -> Result<KeyHandle, KeyError>;
    async fn unwrap_secret(&self, handle: &KeyHandle) -> Result<SecretBytes, KeyError>;
    async fn delete(&self, handle: &KeyHandle) -> Result<(), KeyError>;
    async fn contains(&self, handle: &KeyHandle) -> Result<bool, KeyError>;
}

pub enum KeyProtectionProfile { OsWrapped, HardwareNonExportable }
```

Make `KeyHandle` opaque, bind it to provider, application, account instance, purpose, and non-roaming policy, and reject purpose mismatch before provider invocation. Production builds must not compile the in-memory provider. `WriterKeyProfile::validate` permits only Writer signing, draft wrapping, and operator instance signing.

- [ ] **Step 4: Run contract and compile-feature tests**

Run: `cargo test --locked -p ea-key-provider && cargo check --locked -p ea-key-provider --no-default-features`

Expected: PASS; tests cannot export private key material through the public API.

- [ ] **Step 5: Commit the provider boundary**

```bash
git add crates/ea-key-provider Cargo.toml Cargo.lock
git commit -m "feat(writer): define native key provider boundary"
```

### Task 2: Windows, macOS, and Ubuntu Writer Providers and Re-authentication Ports

**Files:**
- Create: `crates/ea-key-provider/src/windows.rs`
- Create: `crates/ea-key-provider/src/macos.rs`
- Create: `crates/ea-key-provider/src/linux.rs`
- Create: `crates/ea-key-provider/src/posture.rs`
- Create: `crates/ea-operator/Cargo.toml`
- Create: `crates/ea-operator/src/lib.rs`
- Create: `crates/ea-operator/src/account.rs`
- Create: `crates/ea-operator/src/session.rs`
- Create: `crates/ea-operator/src/windows.rs`
- Create: `crates/ea-operator/src/macos.rs`
- Create: `crates/ea-operator/src/linux.rs`
- Test: `crates/ea-operator/tests/session_contract.rs`
- Test: `crates/ea-key-provider/tests/device_posture.rs`
- Test: `tests/ea-system-tests/tests/cross_platform_key_provider_smoke.rs`

**Interfaces:**
- Consumes: `KeyProvider`, verified `OperatorBindingCoreV1`, `EffectiveNow`.
- Produces: closed `ReauthPurpose`, `OsAccountProvider`, `OperatorAuthenticator::reauthenticate`, `OperatorSessionProof` with a five-minute maximum inactivity default, and `DevicePostureProvider` with explicit pass/fail/unknown results.

- [ ] **Step 1: Write account-binding and session-expiry contract tests**

```rust
#[tokio::test]
async fn finalization_requires_matching_account_instance_key_and_fresh_presence() {
    let auth = FakeAuthenticator::new(fixtures::binding());
    assert_eq!(auth.reauthenticate(fixtures::wrong_account(), ReauthPurpose::Finalize).await.unwrap_err().code(),
               "EA-OPERATOR-ACCOUNT-MISMATCH");
    assert_eq!(auth.reauthenticate(fixtures::missing_instance_key(), ReauthPurpose::Finalize).await.unwrap_err().code(),
               "EA-OPERATOR-INSTANCE-KEY-MISSING");
    let proof = auth.reauthenticate(fixtures::valid_account(), ReauthPurpose::Finalize).await.unwrap();
    assert!(proof.is_valid_for(ReauthPurpose::Finalize, fixtures::effective_now()));
}

#[tokio::test]
async fn an_unreportable_posture_requirement_is_never_claimed_as_passed() {
    let report = provider.report().await.unwrap();
    assert_eq!(report.full_disk_encryption, PostureCheck::Unknown { evidence_code: "EA-POSTURE-FDE-UNREPORTABLE" });
    assert!(!report.is_production_ready());
    assert!(report.go_live_follow_up().contains(&PostureRequirement::FullDiskEncryption));
}
```

- [ ] **Step 2: Run tests and verify native adapters are missing**

Run: `cargo test --locked -p ea-operator --test session_contract && cargo test --locked -p ea-key-provider --test device_posture`

Expected: FAIL because account binding, re-authentication, and posture reporting are not implemented.

- [ ] **Step 3: Implement OS-specific account and presence adapters**

Compute only:

```text
SHA-256("EINSATZARCHIV-OS-ACCOUNT-v1" ||
  deterministicCbor([organizationId, deviceId, canonicalOsAccountId]))
```

Use Windows SID with CNG/DPAPI and Windows Hello/Credential UI; macOS directory identifier plus UID with Keychain/Secure Enclave where supported and LocalAuthentication; Ubuntu machine ID plus UID with PAM/Polkit and a PAM-unlocked Secret Service collection carrying a random account-instance identifier. Operator instance keys are app-installation-bound, non-roaming, excluded from normal backup, and challenged with a fresh domain-separated signature at login and re-authentication. Production code stores no OS password and never accepts account identity from the UI.

```rust
pub enum ReauthPurpose {
    Finalize,
    DiscardDraft,
    RegistryStaleFinalize,
    PlaintextExport,
    AdminRootCeremony,
    RecoveryTest,
    HistoricalRegrant,
    Destruction,
    ClockSkewRelease,
    ArchiveProfileMigration,
}
```

Bind the purpose, organization, device, operator binding, random challenge, issued time, and expiry into the opaque `OperatorSessionProof`; a proof is one-purpose and cannot authorize a different action.

Implement `DevicePostureReport` with separate `PostureCheck::{Pass { evidence_code }, Fail { evidence_code }, Unknown { evidence_code }}` values for full-disk encryption, locked/non-shared account, automatic screen lock, and supported OS patch level. Each native adapter uses only documented OS signals that are reliable on its exact support-matrix row. A reported `Fail` blocks production-role session creation; `Unknown` is shown as unresolved and creates a mandatory Go-live evidence row, never an automatic pass. Do not collect recovery keys, usernames, installed-software inventories, or other posture data.

- [ ] **Step 4: Run host contract tests and compile all target adapters**

Run:

```bash
cargo test --locked -p ea-operator
cargo test --locked -p ea-key-provider --test device_posture
cargo check --locked -p ea-key-provider --target x86_64-pc-windows-msvc
cargo check --locked -p ea-key-provider --target x86_64-unknown-linux-gnu
cargo check --locked -p ea-key-provider --target aarch64-apple-darwin
cargo check --locked -p ea-key-provider --target x86_64-apple-darwin
```

Expected: PASS where installed cross-targets permit compile checking; native smoke execution is recorded as an open Stage 7 matrix row, not claimed locally.

- [ ] **Step 5: Commit native provider adapters**

```bash
git add crates/ea-key-provider crates/ea-operator tests/ea-system-tests Cargo.toml Cargo.lock docs/traceability/v0.1-requirements.csv
git commit -m "feat(writer): bind keys and sessions to native accounts"
```

### Task 3: Encrypted Local Store and Single-Draft Autosave

**Files:**
- Create: `crates/ea-local-store/Cargo.toml`
- Create: `crates/ea-local-store/src/lib.rs`
- Create: `crates/ea-local-store/src/database.rs`
- Create: `crates/ea-local-store/src/migrations.rs`
- Create: `crates/ea-local-store/migrations/0001_writer.sql`
- Create: `crates/ea-audit/Cargo.toml`
- Create: `crates/ea-audit/src/lib.rs`
- Create: `crates/ea-audit/src/event.rs`
- Create: `crates/ea-audit/src/repository.rs`
- Create: `crates/ea-draft/Cargo.toml`
- Create: `crates/ea-draft/src/lib.rs`
- Create: `crates/ea-draft/src/model.rs`
- Create: `crates/ea-draft/src/repository.rs`
- Create: `crates/ea-draft/src/autosave.rs`
- Test: `crates/ea-draft/tests/single_draft.rs`
- Test: `crates/ea-draft/tests/crash_recovery.rs`
- Test: `crates/ea-audit/tests/redaction.rs`

**Interfaces:**
- Consumes: `KeyProvider`, schema types, SQLCipher database key handle.
- Produces: `DraftRepository::{load_or_create,save}`, `DraftId`, `EncryptedDraft`, an autosave service that permits exactly one active draft, and `LocalAuditService::record_signed` backed by the same encrypted database boundary.

- [ ] **Step 1: Write single-draft and restart tests**

```rust
#[tokio::test]
async fn exactly_one_encrypted_draft_is_restored_after_restart() {
    let harness = DraftHarness::new().await;
    let draft = harness.repo.load_or_create().await.unwrap();
    harness.repo.save(draft.with_notes("CANARY-DRAFT")).await.unwrap();
    drop(harness.repo);
    let reopened = harness.reopen().await.repo.load_or_create().await.unwrap();
    assert_eq!(reopened.notes(), "CANARY-DRAFT");
    assert_eq!(harness.active_draft_row_count().await, 1);
    assert!(!harness.raw_database_bytes().contains_subslice(b"CANARY-DRAFT"));
}

#[tokio::test]
async fn local_audit_is_signed_durable_and_cleartext_free() {
    let session = fixtures::operator_session();
    let event = audit.record_signed(AuditActorProof::OperatorSession(&session), fixtures::login_event("CANARY-OPERATOR-NAME")).await.unwrap();
    assert!(fixtures::device_audit_verifier().verify(&event).is_ok());
    assert!(!event.exact_bytes().contains_subslice(b"CANARY-OPERATOR-NAME"));
    drop(audit);
    assert_eq!(reopen_audit().await.event(event.id()).unwrap().exact_bytes(), event.exact_bytes());
}
```

- [ ] **Step 2: Run tests and verify missing encrypted persistence**

Run: `cargo test --locked -p ea-draft && cargo test --locked -p ea-audit --test redaction`

Expected: FAIL because the encrypted store, audit repository, migration, and draft repository do not exist.

- [ ] **Step 3: Implement SQLCipher storage plus per-draft AEAD**

```rust
pub trait DraftRepository: Send + Sync {
    async fn load_or_create(&self) -> Result<Draft, DraftError>;
    async fn save(&self, draft: Draft) -> Result<SavedDraft, DraftError>;
}
```

Open SQLite only after retrieving its key through the native provider. Add a unique singleton row, `draft_id`, encrypted payload, AEAD nonce, wrapped-key handle reference, monotonic save revision, and timestamps without fachliche content. Generate a fresh random `draftDEK` per new draft, encrypt the application payload before SQLCipher storage, and store only the wrapped handle. Use a transaction for revision compare-and-swap so overlapping autosaves cannot resurrect old content.

In the same SQLCipher migration, add append-only audit rows keyed by `eventId`, storing only exact `local-audit-event-v1` bytes, their object hash, and a monotonic insertion sequence. `LocalAuditService` accepts typed allowlisted contexts only, resolves the signer certificate and operator binding from the verified session, signs deterministic CBOR through the native provider, verifies the finished COSE before commit, and flushes the transaction before returning. It has no free-text metadata API, no update/delete API, and formats errors without event context. Login, failed re-authentication, binding lifecycle, stale-Registry acceptance, export, clock release, Admin/Root ceremony, Recovery test, re-grant, and destruction reuse this single service in later tasks.

```rust
pub enum LocalAuditAction {
    Login, ReauthFailure, BindingChange, Revocation,
    RegistryStaleWarnAcceptance, PlaintextExport, ClockSkewRelease,
    AdminRootCeremony, RecoveryTest, HistoricalRegrant, Destruction,
    ArchiveProfileMigration,
}
pub enum LocalAuditContext {
    Subject(Option<ObjectHash>),
    StaleRegistry(StaleRegistryAuditContext),
    ClockRelease(ClockReleaseAuditContext),
    Export(ExportAuditContext),
    BindingLifecycle(BindingLifecycleAuditContext),
    AdminRoot(AdminRootAuditContext),
    HistoricalRegrant(HistoricalRegrantAuditContext),
    Destruction(DestructionAuditContext),
    ArchiveProfileMigration(ArchiveProfileMigrationAuditContext),
}
pub struct TypedLocalAuditEvent {
    pub action: LocalAuditAction,
    pub outcome: LocalAuditOutcome,
    pub context: LocalAuditContext,
}
#[async_trait::async_trait]
pub trait LocalAuditService: Send + Sync {
    async fn record_signed(
        &self,
        actor: AuditActorProof<'_>,
        event: TypedLocalAuditEvent,
    ) -> Result<SignedLocalAuditEvent, AuditError>;
}
```

`AuditActorProof::OperatorSession` is required for successful privileged actions. `AuditActorProof::AuthenticatedDevice` exists only so login and failed re-authentication can be recorded even when no new operator proof is issued; it carries the verified device signer and optional already-known binding hash, never an unchecked account value.

- [ ] **Step 4: Run restart, concurrency, and plaintext-canary tests**

Run: `cargo test --locked -p ea-local-store -p ea-audit -p ea-draft`

Expected: PASS; one draft survives restart and neither database pages nor application logs contain the canary.

- [ ] **Step 5: Commit encrypted draft storage**

```bash
git add crates/ea-local-store crates/ea-audit crates/ea-draft Cargo.toml Cargo.lock
git commit -m "feat(writer): persist one encrypted autosaved draft"
```

### Task 4: Irreversible Draft Discard and Crash Resume

**Files:**
- Create: `crates/ea-draft/src/discard.rs`
- Modify: `crates/ea-local-store/migrations/0001_writer.sql`
- Modify: `crates/ea-draft/src/repository.rs`
- Test: `crates/ea-draft/tests/discard_faults.rs`

**Interfaces:**
- Consumes: fresh `OperatorSessionProof` for `ReauthPurpose::DiscardDraft`, `KeyProvider::delete/contains`, exclusive draft lock.
- Produces: `DraftRepository::{begin_discard,resume_discard}` and `DiscardOutcome::NewBlankDraft`.

- [ ] **Step 1: Write fault tests around intent and key deletion**

```rust
#[tokio::test]
async fn every_discard_fault_yields_old_draft_or_permanent_blank_draft() {
    for point in DiscardFaultPoint::ALL {
        let mut h = DraftHarness::with_nonempty_draft().await;
        let _ = h.discard_with_fault(*point).await;
        let state = h.restart_and_resume().await.unwrap();
        assert!(matches!(state, RestartState::OriginalDraftUnchanged | RestartState::NewBlankDraft));
        assert!(!matches!(state, RestartState::DiscardedDraftReadable));
    }
}
```

- [ ] **Step 2: Run the fault test and verify failure**

Run: `cargo test --locked -p ea-draft --test discard_faults`

Expected: FAIL because discard intent and resumable deletion do not exist.

- [ ] **Step 3: Implement the exact discard state machine**

```rust
pub enum DiscardPhase { Editable, IntentDurable, KeyAbsent, DraftRemoved }

pub async fn resume_discard(&self) -> Result<DiscardOutcome, DraftError> {
    let intent = self.repo.pending_discard().await?;
    self.key_provider.delete(&intent.draft_dek_handle).await?;
    if self.key_provider.contains(&intent.draft_dek_handle).await? {
        return Err(DraftError::KeyDeletionNotConfirmed);
    }
    self.repo.remove_ciphertext_and_intent_create_blank(intent.draft_id).await
}
```

Under the exclusive draft lock, durably commit `discardIntent` first. Before that commit a crash changes nothing; after it, restart resumes deletion. Clear UI/Rust buffers, delete and confirm absence of the `draftDEK`, then transactionally remove ciphertext and intent and create a blank draft with new ID/key. Do not allocate a sequence, chain entry, or trash copy.

- [ ] **Step 4: Run all discard fault points twice for idempotency**

Run: `cargo test --locked -p ea-draft --test discard_faults -- --test-threads=1`

Expected: PASS; a second resume is a no-op and no discarded key becomes readable after simulated backup restore.

- [ ] **Step 5: Commit discard recovery**

```bash
git add crates/ea-draft crates/ea-local-store
git commit -m "feat(writer): make draft discard irreversible and resumable"
```

### Task 5: Master Data, CSV Dry Run, and Immutable Snapshots

**Files:**
- Create: `crates/ea-draft/src/master_data.rs`
- Create: `crates/ea-draft/src/csv_import.rs`
- Modify: `crates/ea-local-store/migrations/0001_writer.sql`
- Test: `crates/ea-draft/tests/csv_import.rs`
- Test: `crates/ea-draft/tests/snapshots.rs`

**Interfaces:**
- Consumes: encrypted local store and v1 snapshot schema.
- Produces: `MasterDataRepository`, `CsvImporter::{dry_run,commit}`, `ImportReportV1`, `PersonSnapshotV1`, `VehicleSnapshotV1`, and explicit `AdHocSnapshotV1`.

- [ ] **Step 1: Write CSV transaction and snapshot immutability tests**

```rust
#[tokio::test]
async fn dry_run_does_not_write_and_commit_is_all_or_nothing() {
    let csv = b"id,display_name,role,active\np1,Ada,Fuehrung,true\nbad,,X,true\n";
    let report = importer.dry_run(PersonCsv, csv).await.unwrap();
    assert_eq!((report.accepted, report.errors.len()), (1, 1));
    assert_eq!(repo.person_count().await, 0);
    assert!(importer.commit(report).await.is_err());
    assert_eq!(repo.person_count().await, 0);
}

#[tokio::test]
async fn later_master_change_does_not_modify_captured_snapshot() {
    let captured = repo.snapshot_person("p1").await.unwrap();
    repo.rename_person("p1", "Neue Anzeige").await.unwrap();
    assert_ne!(captured.display_name, repo.snapshot_person("p1").await.unwrap().display_name);
}
```

- [ ] **Step 2: Run tests and verify import functionality is absent**

Run: `cargo test --locked -p ea-draft --test csv_import --test snapshots`

Expected: FAIL because master data and import reports do not exist.

- [ ] **Step 3: Implement documented UTF-8 imports and snapshot provenance**

Accept exactly `id,display_name,role,active` for people and `id,display_name,radio_call_sign,license_plate,active` for vehicles. Reject BOM ambiguity, invalid UTF-8, duplicate/unknown headers, duplicate IDs, invalid booleans, empty required values, and Access formats. Dry run hashes exact input and returns format version, row counts, warnings, and errors without writing. Commit accepts only an unchanged error-free dry-run hash and writes one transaction. Captured imported snapshots include source ID, import format version, and import report hash. Ad-hoc snapshots are visibly flagged and never create master rows.

- [ ] **Step 4: Run import, rollback, and provenance tests**

Run: `cargo test --locked -p ea-draft --test csv_import --test snapshots`

Expected: PASS; historical incident import is impossible through these APIs.

- [ ] **Step 5: Commit master data and CSV import**

```bash
git add crates/ea-draft crates/ea-local-store
git commit -m "feat(writer): add master data and transactional CSV import"
```

### Task 6: Durable Archive Backends, Health Check, and Atomic Profile Migration

**Files:**
- Create: `crates/ea-archive/src/backend.rs`
- Create: `crates/ea-archive/src/local_path.rs`
- Create: `crates/ea-archive/src/controlled_network.rs`
- Create: `crates/ea-archive/src/transaction.rs`
- Create: `crates/ea-archive/src/health.rs`
- Create: `crates/ea-archive/src/profile_migration.rs`
- Test: `crates/ea-archive/tests/backend_capabilities.rs`
- Test: `crates/ea-archive/tests/profile_migration.rs`

**Interfaces:**
- Consumes: Stage 1 exact bytes/inventory/verifier, fresh `ReauthPurpose::ArchiveProfileMigration` proof, and `LocalAuditService`.
- Produces: `ArchiveBackend`, `ArchiveBackendProfile::{LocalPath,ControlledNetworkPath}`, `ArchiveTransaction`, `ArchiveHealthReport`, and `ProfileMigrator`.

- [ ] **Step 1: Write create-if-absent and migration rollback tests**

```rust
#[tokio::test]
async fn create_if_absent_accepts_only_identical_existing_bytes() {
    backend.create_if_absent("grants/x.eag", b"one").await.unwrap();
    backend.create_if_absent("grants/x.eag", b"one").await.unwrap();
    assert_eq!(backend.create_if_absent("grants/x.eag", b"two").await.unwrap_err().code(),
               "EA-ARCHIVE-BYTE-CONFLICT");
}

#[tokio::test]
async fn migration_failure_leaves_only_old_profile_active() {
    let result = migrator.with_fault(MigrationFault::BeforePointerSwap).run().await;
    assert!(result.is_err());
    assert_eq!(profiles.active_id().await, OLD_PROFILE);
    assert!(finalization_lock.is_available().await);
}

#[tokio::test]
async fn migration_requires_matching_reauth_and_audits_the_pointer_result() {
    assert!(migrator.run_with(fixtures::finalize_proof()).await.is_err());
    let result = migrator.run_with(fixtures::profile_migration_proof()).await.unwrap();
    assert!(audit.is_signed_and_flushed(result.audit_event_id()).await);
}
```

- [ ] **Step 2: Run tests and verify backend semantics are absent**

Run: `cargo test --locked -p ea-archive --test backend_capabilities --test profile_migration`

Expected: FAIL because durable backend ports and migration do not exist.

- [ ] **Step 3: Implement explicit durability primitives and fail-closed profiles**

```rust
#[async_trait::async_trait]
pub trait ArchiveBackend: Send + Sync {
    async fn create_if_absent(&self, relative: &ArchivePath, bytes: &ExactObjectBytes) -> Result<(), ArchiveError>;
    async fn sync_file(&self, relative: &ArchivePath) -> Result<(), ArchiveError>;
    async fn sync_directory(&self, relative: &ArchivePath) -> Result<(), ArchiveError>;
    async fn atomic_rename_same_fs(&self, from: &ArchivePath, to: &ArchivePath) -> Result<(), ArchiveError>;
    async fn acquire_writer_lock(&self) -> Result<WriterLock, ArchiveError>;
}
```

`LocalPath` pins a tested filesystem profile. `ControlledNetworkPath` contains an encrypted durable local commit component plus a separately pinned network target, queue bounds, and retry parameters. Never accept a generic UNC/SMB/NFS/WebDAV path. The health report detects missing or modified files; hash/signature/chain errors; absent mandatory grants; invalid or unauthorized Stubs; incomplete Trust data; orphan grants and temporary files; unexpected sequence/fork/rollback; insufficient free space; and unsuitable filesystem semantics. Capability checks prove exclusive create, byte-conflict detection, same-filesystem atomic rename, file and directory flush, exclusive lock, disconnect/reconnect, and exact bytes. Migration requires its exact fresh re-authentication purpose, locks finalization/profile changes/cleanup, finishes pending old-profile publications, inventories every Trust/schema/object/report byte, copies create-if-absent, verifies the target fully offline, compares exact object set plus chain/Trust heads, flushes every directory, then atomically swaps the local profile pointer; any error leaves only the old profile active. Flush a signed local audit event binding source/target profile hashes, inventory hash, result, and active-pointer hash before returning; no path or fachliche name enters audit. The old profile remains read-only or is separately controlled by retention policy and is never auto-deleted.

- [ ] **Step 4: Run backend and migration fault matrices**

Run: `cargo test --locked -p ea-archive --test backend_capabilities --test profile_migration -- --test-threads=1`

Expected: PASS on the host test filesystem; controlled-network contract tests use a deterministic disconnecting adapter and leave native backend certification open to Stage 7.

- [ ] **Step 5: Commit archive durability**

```bash
git add crates/ea-archive
git commit -m "feat(writer): add durable archive backend transactions"
```

### Task 7: Prepared Finalization State Machine

**Files:**
- Create: `crates/ea-writer/Cargo.toml`
- Create: `crates/ea-writer/src/lib.rs`
- Create: `crates/ea-writer/src/preview.rs`
- Create: `crates/ea-writer/src/grant_plan.rs`
- Create: `crates/ea-writer/src/stale_registry.rs`
- Create: `crates/ea-writer/src/finalize.rs`
- Create: `crates/ea-writer/src/recover.rs`
- Create: `crates/ea-writer/src/fault.rs`
- Test: `crates/ea-writer/tests/offline_finalize.rs`
- Test: `crates/ea-writer/tests/prepared_recovery.rs`
- Test: `crates/ea-writer/tests/grant_completeness.rs`
- Test: `crates/ea-writer/tests/sequence_id.rs`
- Test: `crates/ea-writer/tests/stale_registry_warning.rs`

**Interfaces:**
- Consumes: verified Trust/head, validated payload, fresh operator proof, Writer signer, archive transaction, draft key provider, and signed local audit service.
- Produces: `WriterService::{preview,acknowledge_stale_registry,finalize,recover_pending}`, `FinalizationPreview`, opaque one-use `StaleRegistryAcknowledgement`, `PreparedFinalization`, and `FinalizeOutcome { sequence, entry_hash, object_hash, sync_status }` with no payload.

- [ ] **Step 1: Write offline, grant-set, and every-fault-point tests**

```rust
#[tokio::test]
async fn offline_finalize_commits_grants_then_entry_and_returns_no_content() {
    let out = harness.offline_finalize(valid_incident()).await.unwrap();
    assert_eq!(out.sync_status, SyncStatus::LocallySecured);
    assert_eq!(harness.archive.publish_order(), ["recovery.eag", "reader-a.eag", "entry.eip"]);
    assert!(harness.writer_keys_cannot_decrypt(out.entry_hash).await);
    assert!(harness.current_draft().await.is_blank());
}

#[tokio::test]
async fn every_fault_recovers_original_draft_or_same_prepared_bytes() {
    for point in FinalizationFaultPoint::ALL {
        let mut h = WriterHarness::new().await;
        let prepared = h.capture_prepared_bytes();
        let _ = h.finalize_with_fault(*point).await;
        let recovered = h.restart_and_recover().await.unwrap();
        assert!(recovered.is_original_draft() || recovered.committed_bytes() == prepared);
    }
}

#[tokio::test]
async fn stale_standard_warn_requires_durable_signed_one_use_acknowledgement() {
    let preview = harness.preview_with_stale_warn_registry().await.unwrap();
    assert_eq!(harness.finalize(preview.clone(), None).await.unwrap_err().code(), "EA-REGISTRY-STALE-ACK-REQUIRED");
    let ack = harness.acknowledge_after_reauth(&preview).await.unwrap();
    assert!(harness.audit_is_signed_and_flushed(ack.audit_event_id()).await);
    harness.finalize(preview, Some(ack.clone())).await.unwrap();
    assert_eq!(harness.reuse_ack(ack).await.unwrap_err().code(), "EA-REGISTRY-STALE-ACK-REPLAY");
    assert!(harness.evidence_grade_finalize_with_any_ack().await.is_err());
}
```

- [ ] **Step 2: Run finalization tests and verify state machine is absent**

Run: `cargo test --locked -p ea-writer`

Expected: FAIL because preview, finalization, and recovery are not implemented.

- [ ] **Step 3: Implement the thirteen-step finalization sequence literally**

```rust
pub enum FinalizationPhase {
    ReversibleDraft,
    PreparedAndFlushed,
    DraftKeyAbsent,
    GrantsPublished,
    EntryCommitted,
    Reconciled,
}
```

Under one exclusive Writer lock: rebuild head from archive; compare a reachable trusted checkpoint; select highest applicable Registry head; verify time/lease/operator/Recovery; validate and serialize; build the exact all-Reader plus one-Recovery plan; generate UUIDv7/sequence/CEK/nonce once; construct `.eip` and every `.eag`; stage exact bytes plus hashed transaction descriptor; reread/verify/flush bytes and staging directory; zero CEK/buffers and delete/confirm `draftDEK`; publish grants create-if-absent and flush directory; publish `.eip` last by create-if-absent same-filesystem rename and flush entries directory; publish the same bytes to a configured network archive before server eligibility; derive head/queue from committed archive; reconcile staging and create a blank draft.

For a stale head, `preview` returns a typed decision rather than silently continuing. Evidence Grade, signed `block`, or exhausted sequence lease always returns a hard error. Only Standard plus signed `warn` can call `acknowledge_stale_registry`, after a non-bypassable visible warning, fresh `ReauthPurpose::RegistryStaleFinalize`, and explicit confirmation. The signed audit context binds Registry/policy hashes, proposed sequence, `notAfter`, current `EffectiveNow`, and preview hash; it is durably flushed before the acknowledgement proof is returned. `finalize` consumes that proof atomically, rejects a different/rebuilt preview or any replay, and re-evaluates Registry/time under the Writer lock before crossing the `draftDEK` boundary.

Before confirmed `draftDEK` deletion, recovery restores the draft and may discard staging. After deletion, it uses only stored exact prepared bytes—no serialization, new randomness, ID, or sequence. Quarantine orphan grants until linked prepared transaction is proven. A restored Writer backup blocks finalization until external head reconciliation.

- [ ] **Step 4: Run finalization, parallelism, crash, and replay tests**

Run: `cargo test --locked -p ea-writer -- --test-threads=1`

Expected: PASS; no fault creates both a committed `.eip` and usable draft key, duplicate UUIDv7, reused sequence, partial valid grant set, or invalid head.

- [ ] **Step 5: Commit Writer finalization**

```bash
git add crates/ea-writer Cargo.toml Cargo.lock
git commit -m "feat(writer): finalize immutable archives offline"
```

### Task 8: Tauri Bridge, Static Ant Design Foundation, and Role-Gated Shell

**Files:**
- Create: `apps/desktop/package.json`
- Create: `apps/desktop/tsconfig.json`
- Create: `apps/desktop/vite.config.ts`
- Create: `apps/desktop/index.html`
- Create: `apps/desktop/src/main.tsx`
- Create: `apps/desktop/src/app/AppShell.tsx`
- Create: `apps/desktop/src/app/role-gate.ts`
- Create: `apps/desktop/src/design/tokens.ts`
- Create: `apps/desktop/src/design/icons.tsx`
- Create: `apps/desktop/src/design/extract-static-css.tsx`
- Create: `apps/desktop/src/design/static-antd.css`
- Create: `apps/desktop/src/bridge/generated-contracts.ts`
- Create: `apps/desktop/src-tauri/Cargo.toml`
- Create: `apps/desktop/src-tauri/tauri.conf.json`
- Create: `apps/desktop/src-tauri/src/main.rs`
- Create: `apps/desktop/src-tauri/src/state.rs`
- Create: `apps/desktop/src-tauri/src/commands/session.rs`
- Test: `apps/desktop/src/app/AppShell.test.tsx`
- Test: `apps/desktop/src/design/static-css.test.ts`
- Test: `apps/desktop/src/design/icons.test.tsx`

**Interfaces:**
- Consumes: verified device role/session DTO from Rust only.
- Produces: local-only CSP-hardened shell, generated bridge contracts, exact tokens, and no local role escalation.

- [ ] **Step 1: Write UI role and static-style tests**

```tsx
it('does not enable Writer routes from local configuration', async () => {
  render(<AppShell session={{ role: 'reader', capabilities: [] }} />)
  expect(screen.queryByRole('link', { name: /einsatz erfassen/i })).not.toBeInTheDocument()
  localStorage.setItem('role', 'writer')
  expect(screen.queryByRole('link', { name: /einsatz erfassen/i })).not.toBeInTheDocument()
})

it('ships extracted styles and creates no runtime style tags', () => {
  render(<AppShell session={writerSession} />)
  expect(document.querySelectorAll('style[data-ant-cssinjs]').length).toBe(0)
})
```

- [ ] **Step 2: Run UI tests and verify the desktop app is absent**

Run: `pnpm --dir apps/desktop test --run`

Expected: FAIL because the React/Tauri project and shell do not exist.

- [ ] **Step 3: Implement the shell and static style pipeline**

```ts
export const eaTokens = {
  colorText: '#172033', colorBgLayout: '#F5F7FA', colorPrimary: '#245EA8',
  colorError: '#C6352B', colorSuccess: '#187255', colorWarning: '#A65F00',
  fontFamilyCode: 'ui-monospace, SFMono-Regular, Consolas, monospace',
} as const
```

Use `ConfigProvider` with German locale, the same exported token object for runtime component configuration and `@ant-design/static-style-extract`, `zeroRuntime: true`, and Ant `App` context. Hash and bundle `static-antd.css` locally. Set Tauri CSP to permit only packaged scripts/styles/resources and deny inline/runtime styles and network fonts. Generate TypeScript DTOs from Rust `ea-ui-contracts`; reject manually duplicated security enums. Route only from the verified Rust session response.

Use the native UI sans-serif stack for prose and the declared local monospace stack only for hashes, fingerprints, and technical IDs; bundle no Webfont. Import each Phosphor icon directly from `@phosphor-icons/react` with `weight="regular"` by default and `weight="fill"` only for an active or positively confirmed state. Decorative icons use `aria-hidden="true"`; every icon-only button has an accessible name and tooltip. Security, integrity, Evidence, and destruction state always include exact text and never rely on icon or color alone. Disable or shorten nonessential transitions under `prefers-reduced-motion` and preserve visible keyboard focus on every interactive control.

- [ ] **Step 4: Run typecheck, style determinism, CSP, and component tests**

Run: `pnpm --dir apps/desktop typecheck && pnpm --dir apps/desktop test --run && pnpm --dir apps/desktop build`

Expected: PASS; two style extractions are byte-identical and the production bundle has no external font/style URL or `react-icons` import.

- [ ] **Step 5: Commit the desktop foundation**

```bash
git add apps/desktop package.json pnpm-lock.yaml Cargo.toml Cargo.lock
git commit -m "feat(desktop): add role-gated static UI foundation"
```

### Task 9: Writer Form, Review, Discard, and Finalization UX

**Files:**
- Create: `apps/desktop/src/features/writer/WriterPage.tsx`
- Create: `apps/desktop/src/features/writer/IncidentForm.tsx`
- Create: `apps/desktop/src/features/writer/MasterDataSelect.tsx`
- Create: `apps/desktop/src/features/writer/ReviewStep.tsx`
- Create: `apps/desktop/src/features/writer/FinalizeStep.tsx`
- Create: `apps/desktop/src/features/writer/StaleRegistryWarning.tsx`
- Create: `apps/desktop/src/features/writer/DiscardDraftAction.tsx`
- Create: `apps/desktop/src/components/integrity/SyncStatus.tsx`
- Create: `apps/desktop/src/components/integrity/IrreversibleActionConfirm.tsx`
- Create: `apps/desktop/src/components/integrity/PatientDataWarning.tsx`
- Create: `apps/desktop/src-tauri/src/commands/writer.rs`
- Test: `apps/desktop/src/features/writer/WriterPage.test.tsx`
- Test: `tests/e2e/writer-offline.spec.ts`

**Interfaces:**
- Consumes: `WriterService::preview/finalize`, draft/master-data services, re-authentication, `FinalizeOutcome` without content.
- Produces: exact Writer UX contract and no route or command for opening final content.

- [ ] **Step 1: Write workflow and accessibility tests**

```tsx
it('distinguishes known zero from unknown and blocks finalize before review confirmation', async () => {
  render(<WriterPage bridge={fakeWriterBridge()} />)
  await user.selectOptions(screen.getByLabelText('Patientenzahl'), 'known')
  await user.clear(screen.getByLabelText('Anzahl'))
  await user.type(screen.getByLabelText('Anzahl'), '0')
  await user.click(screen.getByRole('button', { name: 'Prüfen' }))
  expect(screen.getByText('0 Patienten')).toBeVisible()
  expect(screen.getByRole('button', { name: 'Unwiderruflich finalisieren' })).toBeDisabled()
  await user.click(screen.getByRole('checkbox', { name: /unwiderruflich/i }))
  expect(screen.getByRole('button', { name: 'Unwiderruflich finalisieren' })).toBeEnabled()
})

it('never offers a bypass for stale Registry and obtains a signed acknowledgement only after re-auth', async () => {
  const bridge = staleWarnBridge()
  render(<WriterPage bridge={bridge} />)
  await advanceToFinalize()
  expect(screen.getByRole('alert')).toHaveTextContent(/Registry.*abgelaufen/i)
  expect(screen.queryByRole('button', { name: /trotzdem ohne bestätigung/i })).not.toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Warnung bestätigen und erneut authentisieren' }))
  expect(bridge.acknowledgeStaleRegistry).toHaveBeenCalledTimes(1)
  expect(screen.getByText(/signierte Bestätigung erfasst/i)).toBeVisible()
})
```

- [ ] **Step 2: Run Writer tests and verify the workflow is absent**

Run: `pnpm --dir apps/desktop test --run WriterPage`

Expected: FAIL because Writer components and commands do not exist.

- [ ] **Step 3: Implement exact Writer behavior**

Start always on the active or blank draft. Suggest `YYYY-NNNN` but allow controlled editing until finalization and enforce organization/year uniqueness. Support searchable/favorite/multi-select people/vehicles and highlighted ad-hoc snapshots. Show autosave state and a local-only patient-data warning on all free text. Review displays every field/snapshot plus archive health, Recovery recipient, Registry, and head. For Standard `warn`, show the stale Registry version/head, expiry, consequence, and offline limitation in a persistent `role="alert"`; enable acknowledgement only after the separate native re-authentication action returns the Rust-issued signed proof. Offer no close icon, keyboard escape, “remember,” or generic continue path. Evidence Grade, `block`, and exhausted lease show a blocking state with no finalize control. Finalize and discard each require native re-authentication and separate irreversible confirmation. After commit, clear UI state, show only hashes/sequence and `lokal gesichert`, then open a blank form. Provide no history, “last incident,” decrypt, delete-final, or content-bearing sync queue UI.

- [ ] **Step 4: Run unit, keyboard, offline E2E, and command-allowlist tests**

Run:

```bash
pnpm --dir apps/desktop test --run
pnpm --dir apps/desktop exec playwright test tests/e2e/writer-offline.spec.ts
cargo test --locked -p einsatzarchiv-desktop writer_commands
```

Expected: PASS with network disabled; the test finalizes, sees a blank form, verifies no content-opening command, and completes all controls by keyboard with named screen-reader labels.

- [ ] **Step 5: Commit Writer UX**

```bash
git add apps/desktop tests/e2e package.json pnpm-lock.yaml Cargo.toml Cargo.lock
git commit -m "feat(desktop): deliver offline Writer workflow"
```

### Task 10: Stage 2 Fault Matrix and Acceptance Gate

**Files:**
- Create: `tests/ea-system-tests/tests/fault_injection_writer_matrix.rs`
- Create: `tests/ea-system-tests/tests/privacy_canaries_writer.rs`
- Create: `tests/ea-system-tests/tests/e2e_writer_archive.rs`
- Create: `docs/traceability/stage-2-gate.md`
- Modify: `docs/traceability/v0.1-requirements.csv`
- Modify: `tools/xtask/src/main.rs`
- Test: `tools/xtask/tests/stage_gate.rs`

**Interfaces:**
- Consumes: every Stage 2 service and host capability report.
- Produces: `xtask stage-gate 2`, evidence for primary AK 1, 2, 3, 15, 23, 25, 28, 34, 39, 46, 48, 54, and explicit open Stage 7 platform rows.

- [ ] **Step 1: Write the cumulative gate test**

```rust
#[test]
fn stage_two_gate_requires_all_irreversible_boundaries() {
    let gate = xtask_test::stage_gate(2);
    assert!(gate.fault_points.contains_all(FinalizationFaultPoint::ALL));
    assert!(gate.fault_points.contains_all(DiscardFaultPoint::ALL));
    assert_eq!(gate.primary_acceptance_criteria, [1, 2, 3, 15, 23, 25, 28, 34, 39, 46, 48, 54]);
    assert!(gate.canary_findings.is_empty());
}
```

- [ ] **Step 2: Run the gate and confirm missing evidence fails**

Run: `cargo test --locked -p xtask --test stage_gate stage_two`

Expected: FAIL listing uncovered fault points, AK rows, and host evidence.

- [ ] **Step 3: Add exhaustive host-independent fault and privacy evidence**

Inject before and after every file flush, directory flush, create-if-absent, rename, `discardIntent` commit, `draftDEK` delete, SQLite transaction, staging transition, and profile pointer swap. Hard-stop and reopen from disk for each point. Verify exactly one outcome: unchanged readable draft before irreversible boundary or byte-identical completion after it. Restore a captured pre/post backup and prove no finalized/discarded key returns. Search logs, SQLite bytes, filenames, staging descriptors, UI traces, and crash output for canaries in every fachliche field.

Update ledger statuses to `implemented` or `integrated`, never `release-verified`. Record Windows/macOS/Linux native execution as Stage 7 required evidence if not run in this checkout.

- [ ] **Step 4: Run the complete Stage 2 gate**

Run:

```bash
cargo test --locked -p ea-writer -p ea-draft -p ea-archive -p ea-key-provider -p ea-operator -- --test-threads=1
pnpm --dir apps/desktop test --run
pnpm --dir apps/desktop exec playwright test tests/e2e/writer-offline.spec.ts
cargo run --locked -p xtask -- test-fault --scope writer
cargo run --locked -p xtask -- test-privacy --scope writer
cargo run --locked -p xtask -- stage-gate 2
pnpm verify:quick
```

Expected: PASS locally; the gate report distinguishes completed implementation/integration from the still-open signed OS matrix.

- [ ] **Step 5: Commit the Stage 2 gate**

```bash
git add tests docs/traceability tools/xtask
git commit -m "test(writer): close offline Writer stage"
```
