# DRK-320 Controlled-Network Archive Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans (or subagent-driven-development) task by task. Each task is one reviewable commit. Steps use checkbox (`- [ ]`) syntax. Read only your task section plus Global Constraints; everything you need is named there.

**Goal:** Make `controlledNetworkPath` a working native profile: first registration of the local SQLCipher component, startup from remote ⊎ local, a Desktop Writer committing into the component, a derived durable publication queue with byte-identical grants-first/`.eip`-last publication, and Recovery capture/restore of a configured network source including the §19.3 read-only copy resource. The last parked RED (`apps/cli/tests/operator_recovery/native_archive.rs`) becomes green.

**Architecture:** `ea-archive-fs` keeps storage primitives (SQLCipher backend, capability measurement, queue derivation, the production publication target). `ea-admin` owns admission: registration, startup union, the network Writer source, the publication host and the Recovery archive handle. The Desktop composes. The remote is only ever a read source for verification and a create-if-absent publication target; the Writer writes only locally. Nothing new is stored for the queue: it is derived from committed local bytes versus the live remote.

**Tech Stack:** Rust workspace, SQLCipher via `ea-local-store`, `ea-archive`/`ea-archive-fs`, `ea-recovery::FsArchiveSource`, native operator fixture in `apps/cli/tests/operator.rs`.

**Spec:** `docs/superpowers/specs/2026-09-21-einsatzarchiv-controlled-network-archive-profile.md` (rule IDs `EA-CNA-*`); `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md` §§9.3, 9.4, 11.5, 19.3; `docs/superpowers/specs/2026-09-09-einsatzarchiv-recovery-source-profile.md`.

## Global Constraints

- Every shell command: `source .superpowers/env.sh && <command>` (zsh). Never `--workspace`; run only the named targets. No Docker.
- Do not change `crates/ea-crypto/src/native_archive.rs`, the vector `domain-string/einsatzarchiv-native-archive-component-v1` in `vectors/crypto/suite-1/manifest.json`, any migration file, any `LocalAuditActionV1` code, any domain string or any archive object format.
- No profile relabeling, no new signature family, no Reader private key on the Writer, no caller-supplied readiness boolean, no fallback to another target (`fell_back_to_another_target()` stays `false`).
- Never write or reinterpret the active-profile pointer (`LocalPathBackend::write_active_profile_pointer`) and never touch `ProfileMigrator`. Reading the pointer (`read_active_profile_pointer`) is allowed where a task says so.
- LocalPath behavior stays byte-for-byte unchanged unless a task says otherwise (only Task 1 adds one refusal for a LocalPath config on a registered anchor).
- Do not move any status in `docs/traceability/v0.1-requirements.csv`. DRK-320 keeps no ledger row.
- The CLI native tests live in `apps/cli/tests/operator.rs` under `#[cfg(unix)] mod process_native { … mod recovery { include!("operator_recovery/mod.rs") } … }`. Their command is `cargo test --locked -p einsatzarchiv-cli --test operator <filter>`; Desktop tests there additionally need `--features desktop-fixture`. A new file under `operator_recovery/` must be added as `mod <name>;` in `apps/cli/tests/operator_recovery/mod.rs`.
- TDD: write the named RED test first, run it, record the failure reason, then implement. A test that is red for a reason other than the missing behavior is not a RED.
- Commit subjects: English Conventional Commits. Bodies: German with real umlauts. Trailer `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`. Comments and docs in German use real umlauts (legacy `ae/oe/ue` in existing code stays; do not copy it).
- Clippy per task: `cargo clippy --locked -p <crate> --all-targets -- -D warnings` for every crate the task modifies (for `einsatzarchiv-cli` add `--features desktop-fixture` when the task touches Desktop).
- Error codes, names and diagnostics never contain host paths, keys or plaintext.

## Dependency order

```
T1 ─┬─ T2
    ├─ T3 ─────────────┐
    └─ T4 ─┬─ T5 ◄─────┘
           ├─ T7 ─┐
T6 ────────┴──────┴─ T8 ─ T9
T10 last (after T3 for the gate sentence; plan corrections any time)
```

T6 is independent of T1–T5 and may run first or in parallel.

---

### Task 1: Registration and activation contract in `ea-admin`

**Rules:** EA-CNA-REG-1 … REG-10.

**Files:**
- Modify: `crates/ea-admin/src/native_archive.rs`
- Create: `apps/cli/tests/operator_recovery/native_archive_registration.rs`
- Modify: `apps/cli/tests/operator_recovery/mod.rs` (add `mod native_archive_registration;`)
- Modify: `apps/cli/tests/operator_recovery/native_archive_existing_component.rs` (positive seeds → registration API)

**Interfaces (add to `native_archive.rs`):**

```rust
#[derive(Clone)]
pub struct NativeArchiveConfig { /* unchanged fields */ }

#[derive(Debug)]
pub enum NativeArchiveOpenError {
    Config, Runtime(OperatorRuntimeError), Backend(ArchiveBackendError), // existing
    Role, RegistrationConflict, PointerConflict, ProfileMismatch, Audit, Capability,
}
impl NativeArchiveOpenError {
    pub fn code(&self) -> &'static str; // EA-NATIVE-ARCHIVE-{CONFIG,ROLE,REGISTRATION-CONFLICT,
    // POINTER-CONFLICT,PROFILE-MISMATCH,AUDIT}; Capability => "EA-ARCHIVE-HEALTH-FILESYSTEM-SEMANTICS";
    // Runtime(e)/Backend(e) => e.code()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeArchiveRegistrationOutcome { Registered, AlreadyRegistered }

pub fn register_network_component(
    runtime: &OperatorRuntime,
    config: NativeArchiveConfig,
) -> Result<(NativeArchiveRegistrationOutcome, NativeArchiveExistingComponent), NativeArchiveOpenError>;
```

- [x] **Step 1: RED tests** in `native_archive_registration.rs` (reuse `profile()`/`config()`/`state()`/`observe_archive_writes()` by moving them into a shared `pub(super)` helper block at the top of `native_archive_existing_component.rs` or duplicating minimal copies; installation via `RecoveryInstallation::with_profile(None, false, Some(profile()))`, which is an `OrganizationAdmin` runtime):
  - `registration_inserts_scope_component_and_one_audit_row_atomically` — after `register_network_component`, `native_archive_component` and `local_commit_scope` each have exactly one row whose values equal `ea_crypto::native_archive_component_namespace(anchor, profile_hash)`, the profile hash and `encode_archive_backend_profile_core` bytes; `local_audit_event` gained exactly one row; outcome is `Registered`; `NativeArchiveExistingComponent::open_current` then succeeds.
  - `registration_is_idempotent_for_the_identical_row_without_presence_or_audit` — second call returns `AlreadyRegistered`; rows of `native_archive_component`, `local_commit_scope`, `local_commit_object`, `local_commit_directory` and the `local_audit_event` count are unchanged (do not install the `observe_archive_writes` witness here: the returned `open_current` legitimately inserts and deletes the at-rest probe).
  - `registration_refuses_every_precondition_without_writes` — table-driven, each case leaves `state()` and the audit count unchanged: LocalPath profile (`Config`), missing DB path (`Config`), other DB file (`Config`), policy-disallowed profile (`Backend(ProfileNotAllowed)`), migration 26 row deleted (`Backend(MissingLocalCommitComponent)`), remote directory renamed away (`Backend(Io)`), a remote `active-profile` pointer written via `LocalPathBackend::write_active_profile_pointer` naming another hash (`PointerConflict`), a pre-existing differing component row inserted by raw SQL (`RegistrationConflict`), a pre-existing scope row with other limits (`RegistrationConflict`).
  - `registration_is_refused_for_a_writer_runtime` — open a Writer-role runtime (`InteractiveOperatorRuntime` is not accepted by the signature; assert on an `OperatorRuntime` whose `config().role == Writer` if the fixture offers one, otherwise assert the role check by a unit test inside `native_archive.rs` behind `#[cfg(test)]` on a helper `fn require_admin(role: OperatorRoleV1) -> Result<(), NativeArchiveOpenError>`) → `Role`.
  - `registered_anchor_refuses_local_path_configuration` — after registration, `open_current` with the LocalPath fixture profile and `local_commit_database_path: None` → `ProfileMismatch`.
- [x] **Step 2:** `cargo test --locked -p einsatzarchiv-cli --test operator recovery::native_archive_registration` → fails to compile (missing API). Record.
- [x] **Step 3: Implement** in this exact order (EA-CNA-REG-2):
  1. `runtime.ensure_current()?`; `require_admin(runtime.config().role)?`.
  2. Shape checks as in the existing private `open` (network ⇔ DB path; canonical DB path equality with `runtime.database().path()`), exact profile bytes and `profile_hash`; limits `>0` and `i64`.
  3. `BoundArchiveProfilePolicyV1::from_policy(runtime.head().policy_fields()).require(profile_hash)?`.
  4. `database.has_migration(16)` and `(26)`.
  5. `let remote = LocalPathBackend::open_existing(runtime.config().archive_directory.clone(), config.profile.clone(), &policy)?;` then `remote.run_capability_test(&CapabilityTestVectorV1::new(&p.capability_test_vector_id, b"EINSATZARCHIV-NATIVE-CAPABILITY-v1")?)?.all_proven()` else `Capability`.
  6. `remote.read_active_profile_pointer()?`: `Some(p)` with `p.active_profile_hash() != profile_hash` → `PointerConflict`; keep the exact bytes via `remote.active_profile_pointer_bytes()` for the audit context.
  7. Read-only transaction: existing component row for anchor — identical → return `(AlreadyRegistered, NativeArchiveExistingComponent::open_current(runtime, config)?)`; differing → `RegistrationConflict`; scope row for namespace with other limits → `RegistrationConflict`.
  8. `let session = runtime.reauthenticate_for(ReauthPurpose::ArchiveProfileMigration)?;` `runtime.ensure_current()?`.
  9. Context `ArchiveProfileMigrationContextV1::new(profile_hash, profile_hash, archive_inventory_digest(&encode_archive_inventory_list(&remote.inventory()?)?), pointer_hash_or_zero)`; `runtime.audit_service().prepare_signed(AuditActorProof::OperatorSession(session.proof()), TypedLocalAuditEvent { action: LocalAuditActionV1::ArchiveProfileMigration(ctx), outcome: LocalAuditOutcomeV1::Accepted })` → `Audit` on error.
  10. `runtime.ensure_current()?`; one `database.transaction`: `INSERT OR IGNORE` is **not** used; insert scope only if absent (identical existing scope reused), insert component row, `SqliteLocalAuditRepository::append_prepared_in(tx, &audit)`. Never call `SqliteCommitStore::new`.
  11. Return `(Registered, NativeArchiveExistingComponent::open_current(runtime, config)?)` (EA-CNA-REG-7).
  - In the private `open`, LocalPath arm: if migration 26 is present and a row exists for `anchor`, return `ProfileMismatch` before any I/O.
- [x] **Step 4:** Replace the positive `seed(&runtime, &installed.profile, "")` calls in `native_archive_existing_component.rs` (tests `…opens_offline…` and `…current_writer_entry…`) with `register_network_component(&runtime, config(&runtime, installed.profile.clone())).unwrap()`. Keep `seed` for the mutation cases (it documents deliberately corrupt fixtures) and update its doc comment accordingly.
- [x] **Step 5:** `cargo test --locked -p einsatzarchiv-cli --test operator recovery::native_archive` → all registration and existing-component tests pass (the parked `native_archive.rs` test stays ignored until Task 3). `cargo clippy --locked -p ea-admin --all-targets -- -D warnings`; `cargo clippy --locked -p einsatzarchiv-cli --all-targets -- -D warnings`.
- [x] **Step 6:** Commit `feat(admin): register the controlled-network component once per anchor`.

---

### Task 2: CLI entry `operator register-network-archive`

**Depends on:** Task 1. **Rules:** EA-CNA-REG-1.

**Files:**
- Modify: `apps/cli/src/args.rs` (`OperatorAction`, parser near `Some("provision") => OperatorAction::Provision` at ~1236, a new `--archive-profile <file>` option valid only for this verb)
- Modify: `apps/cli/src/commands/operator.rs` (dispatch in `run_with_runtime_opener`)
- Modify: `apps/cli/src/output.rs` (normative grammar line `operator provision|verify-session|revoke` at ~115)
- Modify: `apps/cli/tests/full_grammar.rs` (grammar literal at ~71)
- Modify: `apps/cli/tests/operator_recovery/native_archive_registration.rs` (process test)

**Interface:** `OperatorAction::RegisterNetworkArchive`; grammar line `einsatzarchiv --trust-anchor <file> operator register-network-archive --operator-config <file> --archive-profile <file>`. The profile file uses the existing JSON grammar `ea_admin::recovery_test_runtime::parse_recovery_archive_profile` (camelCase, `kind: "controlledNetworkPath"`). The local DB path is `runtime.config().database_path` (the operator config is the explicit declaration). Output on success: the existing JSON success envelope with `"registration":"registered"|"already-registered"`; failure: `NativeArchiveOpenError::code()`.

- [x] **Step 1: RED:** in `full_grammar.rs` extend the expected grammar literal; add process test `cli_registers_network_component_and_reports_already_registered_on_repeat` using the existing fixture binary pattern of `operator verify-session` tests (run twice; second prints `already-registered`; DB contains one component row).
- [x] **Step 2:** `cargo test --locked -p einsatzarchiv-cli --test full_grammar` and `… --test operator register_network` → red.
- [x] **Step 3:** Implement parser, dispatch (`authority` configs refuse this verb like other non-`verify-session` verbs), output.
- [x] **Step 4:** Both commands green; `cargo test --locked -p einsatzarchiv-cli --bin einsatzarchiv` (args unit tests) green; clippy for `einsatzarchiv-cli`.
- [x] **Step 5:** Commit `feat(cli): register a controlled-network archive component`.

---

### Task 3: Recovery archive handle, SQLCipher capability and the un-parked RED

**Depends on:** Task 1. **Rules:** EA-CNA-WRT-4, EA-CNA-REC-1, EA-CNA-REC-2.

**Files:**
- Modify: `crates/ea-archive-fs/src/sqlcipher_backend.rs` (capability measurement)
- Modify: `crates/ea-archive-fs/src/lib.rs` (export report type)
- Modify: `crates/ea-archive-fs/tests/sqlcipher_backend.rs` (tests)
- Modify: `crates/ea-admin/src/native_archive.rs` (internal enum instead of `Box<dyn ArchiveBackend>`; capability helper)
- Modify: `crates/ea-admin/src/recovery_test_runtime.rs`, `…/recovery_test_runtime/{execution,import,native_medium}.rs`
- Modify: `apps/cli/tests/operator_recovery/native_archive.rs`

**Interfaces:**

```rust
// ea-archive-fs
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqlcipherCapabilityReportV1 { durable_wal_full: bool, physical_flush: bool, exclusive_writer_lock: bool }
impl SqlcipherCapabilityReportV1 { pub const fn all_proven(&self) -> bool; /* + three getters */ }
impl SqlcipherArchiveBackend {
    /// Measures only; writes no object, directory or probe row.
    pub fn run_capability_test(&self) -> Result<SqlcipherCapabilityReportV1, ArchiveBackendError>;
}

// ea-admin native_archive.rs
impl NativeArchiveExistingComponent {
    /// LocalPath: run_capability_test(vector).all_proven().
    /// Network: SQLCipher report all_proven AND remote LocalPathBackend::open_existing(..).run_capability_test(vector).all_proven().
    pub fn require_capabilities(&self, archive_directory: &Path, policy: &BoundArchiveProfilePolicyV1) -> Result<(), NativeArchiveOpenError>;
    pub fn is_network(&self) -> bool;
    pub fn sqlcipher_backend(&self) -> Option<&SqlcipherArchiveBackend>;
}

// ea-admin recovery_test_runtime.rs
enum RecoveryArchiveHandle {
    LocalPath(LocalPathBackend),
    Network { component: NativeArchiveExistingComponent, remote: LocalPathBackend },
}
struct RecoveryArchiveLocks { _local: WriterLock, _remote: Option<WriterLock> }
impl RecoveryTestRuntime {
    fn archive_locks(&self) -> Result<RecoveryArchiveLocks, RecoveryRuntimeError>; // SQLCipher first, then remote
    fn archive_source(&self) -> Result<FsArchiveSource, RecoveryRuntimeError>;   // LocalPath: FsArchiveSource::open(dir)
}
```

`capability_test` implementation: one `transaction` that runs `require_durability` and `flush_physical` (existing private fns) → `durable_wal_full`, `physical_flush`; lock: `acquire_writer_lock()` held, then open the same `<db>.archive-writer.lock` with a second `OpenOptions` handle and assert `try_lock` fails, drop the first, assert the second succeeds, release.

- [x] **Step 1: RED** (`ea-archive-fs/tests/sqlcipher_backend.rs`): `sqlcipher_capability_measures_durability_flush_and_exclusive_lock_without_writes` — all three true on a real SQLCipher DB; `local_commit_object`, `local_commit_directory`, `local_commit_probe` row counts unchanged; and `sqlcipher_capability_reports_lock_contention_when_already_held` — while a `WriterLock` from a second backend on the same DB is held, `run_capability_test` returns `Err(AlreadyLocked)`.
- [x] **Step 2: RED** (`apps/cli/tests/operator_recovery/native_archive.rs`): delete the `#[ignore = "DRK-320: …"]` line. Insert after `let runtime=installed.open();`:
  `ea_admin::native_archive::register_network_component(&runtime, NativeArchiveConfig{profile:installed.profile.clone(),local_commit_database_path:Some(runtime.database().path().to_owned())}).unwrap();`
  Keep the remaining assertions. Add a second test `native_recovery_network_handle_holds_sqlcipher_then_remote_lock` asserting that while the recovery runtime runs `reopen_restored_source` preconditions, a fresh `SqlcipherArchiveBackend` writer lock on the same DB returns `AlreadyLocked` — if that is not observable through public API, assert instead that `RecoveryTestRuntime::new(runtime, network_profile)` still returns `EA-RECOVERY-TEST-SOURCE` (EA-CNA-REC-1).
- [x] **Step 3:** `cargo test --locked -p ea-archive-fs --test sqlcipher_backend` and `cargo test --locked -p einsatzarchiv-cli --test operator recovery::native_archive::` → red for the missing behavior (`EA-RECOVERY-TEST-SOURCE`).
- [x] **Step 4: Implement.** Replace `backend: Box<dyn ArchiveBackend>` in `NativeArchiveExistingComponent` by a private enum `{ Local(LocalPathBackend), Network { backend: SqlcipherArchiveBackend, component: ControlledNetworkLocalComponentV1 } }`; `local_backend()` keeps returning `&dyn ArchiveBackend`. `with_archive_config`: LocalPath with `None` → existing `new`; Network → `ensure_current`, admin role check (same as `new`), `NativeArchiveExistingComponent::open_current(&runtime, config)?`, `require_capabilities(...)`, `remote = LocalPathBackend::open_existing(...)`, `ensure_current`. `archive_profile_hash` returns the component hash for Network. Replace every `self.backend.acquire_writer_lock()` (recovery_test_runtime.rs ~144/267/465, execution.rs ~258/516/562, import.rs ~102/188, native_medium.rs ~101) by `self.archive_locks()?` and every `FsArchiveSource::open(&self.runtime.config().archive_directory)` in those files by `self.archive_source()?`. In this task `capture_source` and `restore_source` on the Network handle return `Err(RecoveryTestError::Source.into())` immediately after taking the locks (Task 5 lifts this).
- [x] **Step 5:** Both commands green; also `cargo test --locked -p einsatzarchiv-cli --test operator recovery::` (the whole recovery module, LocalPath regressions). Clippy `ea-archive-fs`, `ea-admin`, `einsatzarchiv-cli`.
- [x] **Step 6:** Commit `feat(recovery): open a registered controlled-network component as recovery source`.

---

### Task 4: Startup source remote ⊎ local, action baseline and new runtime errors

**Depends on:** Task 1. **Rules:** EA-CNA-SRC-1 … SRC-4.

**Files:**
- Modify: `crates/ea-admin/src/operator_runtime.rs` (`OperatorArchiveSnapshot`, `open_resources` ~1149, `OperatorRuntime::{open_without_acquisition, acquire_using, reopened_for_action}`, `OperatorRuntimeError`)
- Modify: `crates/ea-admin/src/operator_runtime/writer.rs` (`InteractiveOperatorRuntime::{acquire_using, open_without_acquisition, reopened_for_action}`, `StaleWriterRuntime::open_using`)
- Modify: `crates/ea-admin/src/native_archive.rs` (read helper for the registered row)
- Create: `apps/cli/tests/operator_recovery/native_archive_startup.rs`; register in `mod.rs`

**Interfaces:**

```rust
pub enum OperatorRuntimeError { /* … */ NetworkArchiveUnavailable, NetworkArchiveConflict }
// codes: "EA-OPERATOR-NETWORK-ARCHIVE-UNAVAILABLE", "EA-OPERATOR-NETWORK-ARCHIVE-CONFLICT"

impl OperatorArchiveSnapshot {
    pub fn open(directory: &Path, anchor_path: &Path, now: UnixMillis) -> Result<Self, OperatorRuntimeError>; // unchanged behavior
    pub(crate) fn open_with_anchor(
        directory: &Path, anchor: TrustAnchorV1, now: UnixMillis,
        component: Option<&dyn ArchiveSource>, baseline: Option<Arc<FsArchiveSource>>,
    ) -> Result<Self, OperatorRuntimeError>;
    /// Remote committed view actually used (live or baseline); None for LocalPath.
    pub fn remote_baseline(&self) -> Option<&Arc<FsArchiveSource>>;
}
impl OperatorRuntime { pub fn archive_snapshot(&self) -> &OperatorArchiveSnapshot; }
impl InteractiveOperatorRuntime { pub fn archive_snapshot(&self) -> &OperatorArchiveSnapshot; }

// native_archive.rs
pub(crate) struct RegisteredNetworkComponent { pub(crate) profile: ArchiveBackendProfileV1, pub(crate) namespace: Hash32 }
pub(crate) fn registered_component(database: &Arc<EncryptedDatabase>, anchor: Hash32)
    -> Result<Option<RegisteredNetworkComponent>, OperatorRuntimeError>; // decodes exact_profile; no writes
```

`open_resources` gains a last parameter `baseline: Option<Arc<FsArchiveSource>>`, threaded through `OperatorRuntime::open_without_acquisition` and `acquire_using` and the `InteractiveOperatorRuntime`/`StaleWriterRuntime` equivalents. Only the two `reopened_for_action` methods pass `self.archive_snapshot().remote_baseline().cloned()`; every other entry point passes `None`.

New order inside `open_resources`: `load_trust_anchor(anchor_path)` and the anchor-outside-archive check (moved out of `OperatorArchiveSnapshot::open`) → `open_native` → `signer` → DB exists/generate/open (unchanged logic, uses only `config.role` and `config.database_path`) → `registered_component(&database, anchor.trust_anchor_hash())` → if `Some`: `SqliteCommitStore::open_existing` + `SqlcipherArchiveBackend::open` (read side only; no probe) as `component`; remote read `FsArchiveSource::open_committed(dir)`: `Ok` → use it; `Err(_)` → `baseline` if `Some`, else `NetworkArchiveUnavailable`; union via `with_exact_component(component)` mapping `ByteConflict|Path|InventoryMismatch` → `NetworkArchiveConflict` → `verify_archive` etc. exactly as today → device certificate lookup → `OperatorTrustStateStore::open` (needs only anchor ids). If `None`: today's `FsArchiveSource::open_committed` path, no baseline. Update every exhaustive `match` on `OperatorRuntimeError` that `cargo check` reports.

- [x] **Step 1: RED** in `native_archive_startup.rs` (fixture: `RecoveryInstallation::with_profile(None,false,Some(profile()))`, register via Task 1, then write a valid committed grant and `.eip` for the next sequence into the component using the material the fixture already has — reuse `epochs::append_kem_epoch` bytes (`installed.historical_epoch`) by building the installation with `historical=true` and **moving** `entries/000000000001_epoch.eip` and `grants/000000000001_epoch.eag` out of the remote into the component via `component.local_backend().create_non_object_if_absent(...)` + `sync_file` before reopening; if the fixture's sequence layout differs, move the highest-sequence `.eip` and its grants instead — the remote must keep at least one entry):
  - `network_startup_verifies_remote_union_local_and_advances_next_sequence` — reopened runtime's `next_sequence()` equals the value with both objects present in the remote (compare with a LocalPath control reopened before moving).
  - `network_startup_refuses_byte_conflict_between_remote_and_local` — same address, different bytes → `EA-OPERATOR-NETWORK-ARCHIVE-CONFLICT`.
  - `network_cold_start_refuses_unreadable_remote` — rename the archive dir, `installed.open()` equivalent returns `EA-OPERATOR-NETWORK-ARCHIVE-UNAVAILABLE`.
  - `network_reopen_for_action_uses_baseline_when_remote_disappears` — open, rename remote away, `reopened_for_action()` succeeds with the same `next_sequence()`.
  - `local_path_startup_is_unchanged` — a LocalPath installation opens without touching `native_archive_component` (temp trigger witness as in `observe_archive_writes`).
- [x] **Step 2:** `cargo test --locked -p einsatzarchiv-cli --test operator recovery::native_archive_startup` → red.
- [x] **Step 3:** Implement as specified above.
- [x] **Step 4:** Green; regressions: `cargo test --locked -p ea-admin --test operator_runtime`, `cargo test --locked -p einsatzarchiv-cli --test operator recovery::`, `cargo test --locked -p einsatzarchiv-cli --test operator posture`. Clippy `ea-admin`, `einsatzarchiv-cli`.
- [x] **Step 5:** Commit `feat(admin): start controlled-network runtimes from remote union local component`.

---

### Task 5: Recovery capture/restore of a configured network source and the read-only copy resource

**Depends on:** Tasks 3 and 4. **Rules:** EA-CNA-REC-2 … REC-6.

**Files:**
- Modify: `crates/ea-admin/src/recovery_test_runtime.rs` (+ `execution.rs`, `import.rs` only via the helpers from Task 3)
- Modify: `apps/cli/src/commands/recovery_test.rs` (~110), `apps/desktop/src-tauri/src/runtime/recovery.rs` (~99), `apps/desktop/src-tauri/src/runtime/administration.rs` (~519): call `with_archive_config` with `local_commit_database_path` = `Some(runtime.config().database_path.clone())` for a network profile, `None` for LocalPath
- Create: `apps/cli/tests/operator_recovery/native_archive_source.rs`; register in `mod.rs`

**Interfaces:**

```rust
enum RecoveryArchiveHandle { LocalPath(..), Network { .. }, ReadOnlyCopy { lock: LocalPathBackend, component_export: PathBuf } }
impl RecoveryTestRuntime {
    pub fn capture_source_with_component_export(
        &mut self, request: RecoverySourceCapture<'_>, component_export: &Path,
    ) -> Result<VerifiedRecoverySource, RecoveryRuntimeError>;     // Network only
    pub fn for_archive_copy(
        runtime: OperatorRuntime, profile: ArchiveBackendProfileV1, component_export: PathBuf,
    ) -> Result<Self, RecoveryRuntimeError>;                          // target §19.3, no capability test
}
```

`capture_source` on Network or ReadOnlyCopy → `EA-RECOVERY-TEST-SOURCE`; `capture_source_with_component_export` on LocalPath or ReadOnlyCopy → same. Share the body with `capture_source` by extracting `fn capture_from(&mut self, request, source: impl Fn() -> Result<FsArchiveSource, _>)`. Export: refuse if `component_export` exists or its canonical parent is inside the canonical `archive_directory`; `create_dir`; for each `visit_managed_blobs` row create parents with `create_dir`, write with `OpenOptions::new().write(true).create_new(true)`, `sync_all` file, then sync every created directory bottom-up; read back with `FsArchiveSource::open(component_export)` and require the multiset of `(path, bytes)` equals the component's managed blobs. The capture source is `FsArchiveSource::open(remote)?.with_exact_component(&FsArchiveSource::open(export)?)`, used for the inventory hash, the probe/tip check against `runtime.next_sequence()` (union-based since Task 4), `verify_recovery_source`, and the after-snapshot comparison. `archive_source()` for ReadOnlyCopy returns the same union over the copy; its `archive_locks()` returns only `lock.acquire_writer_lock()`; it never exposes a backend.

- [x] **Step 1: RED** in `native_archive_source.rs` (network installation with one locally committed, unpublished grant+`.eip` as in Task 4's fixture):
  - `network_capture_binds_unpublished_local_entry_and_exports_it_exactly` — capture succeeds; export dir holds exactly the component's managed blobs; `recovery_archive_inventory_hash(remote ⊎ export)` equals the envelope's `archive_inventory_hash`; the tip equals the local `.eip`.
  - `network_capture_without_the_local_set_fails` — `ea_recovery::verify_recovery_source(envelope, &FsArchiveSource::open(remote)?, anchor, inventory, now)` over the remote alone returns `EA-RECOVERY-TEST-SOURCE` (inventory hash and tip no longer match).
  - `network_capture_refuses_existing_or_nested_export_directory`.
  - `archive_copy_restores_on_other_machine_without_backend_or_publication` — copy remote dir + export to a target installation (use the existing `target_config` flow of `RecoveryInstallation::with_target`), `for_archive_copy(...)`, `restore_source` succeeds, `capture_source` returns `EA-RECOVERY-TEST-SOURCE`, the target DB has no `native_archive_component` row, the copy's object files are byte-identical before/after.
- [x] **Step 2:** `cargo test --locked -p einsatzarchiv-cli --test operator recovery::native_archive_source` → red.
- [x] **Step 3:** Implement; update the three callers.
- [x] **Step 4:** Green; regressions `cargo test --locked -p einsatzarchiv-cli --test operator recovery::` and `cargo test --locked -p einsatzarchiv-cli --features desktop-fixture --test operator recovery::desktop`. Clippy `ea-admin`, `einsatzarchiv-cli` (with and without `desktop-fixture`), `ea-desktop`.
- [x] **Step 5:** Commit `feat(recovery): capture and restore controlled-network sources with their local component`.

---

### Task 6: Derived publication queue, merge fix and the production network target

**Depends on:** nothing (pure `ea-archive-fs`). **Rules:** EA-CNA-PUB-1, PUB-2, PUB-3, PUB-6, PUB-7.

**Files:**
- Modify: `crates/ea-archive-fs/src/publication_queue.rs`
- Create: `crates/ea-archive-fs/src/network_target.rs`; export from `lib.rs`
- Modify: `crates/ea-archive-fs/tests/publication_queue.rs`
- Modify: `crates/ea-sync-client/src/client.rs` (comment at ~463–476 that argues from the single displaced slot)

**Interfaces:**

```rust
impl PlannedPublicationV1 {
    /// EA-CNA-PUB-1/2: committed local objects missing at the remote, ordered by
    /// sequence prefix, non-.eip before .eip; same address with other bytes → ByteConflict.
    pub fn derive_pending(local: &dyn ArchiveSource, remote: &LocalPathBackend) -> Result<Self, ArchiveBackendError>;
}
pub struct NetworkArchiveTargetV1 { /* network_root, profile, policy, held Mutex<Option<LocalPathBackend>> */ }
impl NetworkArchiveTargetV1 {
    pub fn new(network_root: PathBuf, profile: ArchiveBackendProfileV1, policy: BoundArchiveProfilePolicyV1) -> Result<Self, ArchiveBackendError>; // policy.require first, no I/O
}
impl PublicationTargetV1 for NetworkArchiveTargetV1 {
    // is_connected: LocalPathBackend::open_existing succeeds (cached); reconnect: drop cache and retry;
    // publish_one: ea_format::decode_exact_object(bytes)? (objects only), acquire remote writer lock,
    // create_non_object_if_absent, sync_file, sync_directory, re-read via read_relative and compare bytes.
}
```

`PublicationQueue::publish` (the overwrite at `publication_queue.rs:318`, and the implicit loss when a connected `publish` ignores an outstanding plan): take the pending plan, merge `pending ⊎ planned` (identical addresses once, differing bytes → `Err(ByteConflict)` leaving `pending` unchanged, order pending-first), check limits on the merged plan, then either store the merged plan (disconnected) or `drain(merged)`. `drain`'s two re-store sites keep storing the (merged) plan they were given.

- [x] **Step 1: RED** in `tests/publication_queue.rs`:
  - `second_offline_publish_keeps_the_first_plan_and_resumes_both_in_order` — two plans published while disconnected; after reconnect `resume()` publishes both, first plan's order first, bytes exact.
  - `connected_publish_drains_an_outstanding_plan_before_the_new_one`.
  - `merge_with_conflicting_bytes_is_refused_and_keeps_the_pending_plan`.
  - `merged_plan_over_the_queue_limit_is_refused_without_dropping_pending`.
  - `derive_pending_orders_grants_before_their_entry_by_sequence` — temp remote `LocalPathBackend` with seq 1 present; local source with seq 2 grants `grants/000000000002_b.eag`, `grants/000000000002_a.eag`, entry `entries/000000000002_x.eip` and seq 1 entry identical → plan is `[a.eag, b.eag, x.eip]`.
  - `derive_pending_refuses_differing_bytes_at_the_remote`.
  - `network_target_publishes_create_if_absent_and_verifies_readback` and `network_target_reports_disconnected_when_root_is_missing_and_never_creates_it`.
- [x] **Step 2:** `cargo test --locked -p ea-archive-fs --test publication_queue` → red.
- [x] **Step 3:** Implement. Correct the `client.rs` comment so it no longer claims the next plan displaces the deferred one (German, real umlauts; keep the receipt-ordering argument, which stays valid).
- [x] **Step 4:** Green; regressions `cargo test --locked -p ea-archive-fs --test controlled_network_profile`, `cargo test --locked -p ea-sync-client --test status`, `cargo test --locked -p ea-sync-client --test resume`. Clippy `ea-archive-fs`, `ea-sync-client`.
- [x] **Step 5:** Commit `fix(archive-fs): never drop a deferred publication plan and derive the network queue`.

---

### Task 7: Desktop Writer on the SQLCipher component

**Depends on:** Tasks 1, 3, 4. **Rules:** EA-CNA-WRT-1 … WRT-7.

**Files:**
- Modify: `apps/desktop/src-tauri/src/runtime/writer_config.rs`, `runtime/writer.rs` (`WriterResources` ~28–79, `writer_action` ~132)
- Modify: `crates/ea-destruction/src/inventory.rs` (`observe_writer_archive` ~62, `observe_local_archive`, `observe_archive`)
- Modify: `crates/ea-admin/src/native_archive.rs` (network Writer source; `ObservedArchiveHoldingV1` impl)
- Modify: `crates/ea-destruction/tests/preflight.rs` (~341 caller)
- Create: `apps/cli/tests/operator_desktop/network_writer.rs`; include from `operator_desktop/mod.rs`

**Interfaces:**

```rust
// writer_config.rs — WriterConfig gains `#[serde(default)] local_commit_database_path: Option<PathBuf>`
pub(super) struct WriterSettings { timezone, archive_profile, pub(super) local_commit_database_path: Option<PathBuf> }
// relative path resolved beside the writer config file; present ⇔ network profile, else CONFIG_ERROR

// writer.rs
enum WriterArchive { Local(LocalPathBackend), Network(NativeArchiveExistingComponent) }
pub(super) struct WriterResources { archive: WriterArchive, timezone: String, profile_hash: Hash32 }

// ea-destruction inventory.rs
pub trait ObservedArchiveHoldingV1 {
    fn profile_hash(&self) -> Result<Hash32, ArchiveBackendError>;
    fn acquire_writer_lock(&self) -> Result<WriterLock, ArchiveBackendError>;
    fn canonical_location(&self) -> Result<PathBuf, ArchiveBackendError>;
    fn visit_committed(&self, visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>) -> Result<(), ArchiveError>;
}
impl ObservedArchiveHoldingV1 for LocalPathBackend { /* root(), as_archive_source() — identical to today */ }
pub fn observe_writer_archive(&self, head: WriterRegistryHeadRef<'_>, certificate: CertificateHash, archive: &dyn ObservedArchiveHoldingV1) -> …;
// observe_local_archive keeps taking &LocalPathBackend and forwards.

// ea-admin native_archive.rs
impl ObservedArchiveHoldingV1 for NativeArchiveExistingComponent { /* location: canonical DB path (Network) or root (Local) */ }
pub struct NetworkWriterSourceV1<'a> { baseline: &'a FsArchiveSource, local: &'a SqlcipherArchiveBackend }
impl ArchiveSource for NetworkWriterSourceV1<'_> // each visit: baseline.committed_view().with_exact_component(local) then visit
impl NativeArchiveExistingComponent { pub fn writer_source<'a>(&'a self, snapshot: &'a OperatorArchiveSnapshot) -> Result<NetworkWriterSourceV1<'a>, NativeArchiveOpenError>; }
```

`WriterResources::open` network arm: role Writer check (existing), `NativeArchiveExistingComponent::open_writer(runtime, NativeArchiveConfig{profile, local_commit_database_path})` (runtime is `InteractiveOperatorRuntime`), `require_capabilities(...)` (Task 3) else `EA-ARCHIVE-HEALTH-FILESYSTEM-SEMANTICS`, `observe_writer_archive(.., &component)`. `writer_action`: the backend passed to `WriterService::new_for_writer` is `component.local_backend()`; the source is `component.writer_source(runtime.archive_snapshot())`. Remove `EA-DESKTOP-NETWORK-COMMIT-UNAVAILABLE`. Location hash domain `EINSATZARCHIV-MANAGED-ARCHIVE-LOCATION-v1` is reused unchanged with the canonical DB path string.

- [x] **Step 1: RED:**
  - `crates/ea-destruction/tests/preflight.rs`: existing LocalPath observation test still passes through the trait (compile-level RED until the trait exists); add `writer_observation_of_a_local_path_backend_records_the_same_location_hash_as_before` pinning the hash of today's preimage.
  - `apps/cli/tests/operator_desktop/network_writer.rs` (`--features desktop-fixture`): fixture `NetworkWriterInstallation` (in this file) = the Desktop Writer `Installation` from `apps/cli/tests/operator.rs` (~366) plus, on its `line`, an `ActionSpec::AdminIssue { marker, effective_from }` and an `ActionSpec::OperatorBinding { certificate_hash, role: OperatorRoleV1::OrganizationAdmin, marker, effective_from }` with the native account/instance overrides, modeled on the `target_config` branch of `RecoveryInstallation::with_profile` (`apps/cli/tests/operator_recovery/mod.rs` ~150–160), a policy allowing the network profile hash, and a second operator JSON (`"role":"organization-admin","purpose":"archive-profile-migration"`, `authority` absent) with the **same** `database_path`. Both roles share one native installation and therefore one DB key (`NativeKeyProvider::slot` maps `SecretPurpose::LocalDatabaseKey` to `"database-key"` independent of the signing slot; the fixture helper assigns installation `c1` to every non-`authority` config). Register through the admin runtime, drop it, then start the Desktop Writer. If the native fixture cannot expose an admin-slot public key matching the issued admin certificate, report that before improvising. Tests: `network_writer_finalizes_into_the_local_component_and_not_the_remote` (after `writer.finalize` the `.eip` and grants exist in `local_commit_object`, the remote dir has no new files, outcome sequence is next); `network_writer_finalizes_after_the_remote_disappears_mid_session` (rename remote after login; finalize succeeds via baseline, EA-CNA-SRC-4); `network_writer_config_requires_the_runtime_database_path` (missing/other path → `CONFIG_ERROR`/`EA-NATIVE-ARCHIVE-CONFIG`); `network_writer_refuses_when_sqlcipher_capability_fails` (hold a foreign `SqlcipherArchiveBackend` writer lock during `WriterResources::open` → `EA-ARCHIVE-HEALTH-FILESYSTEM-SEMANTICS`); `network_writer_queue_limit_blocks_before_irreversible_step` (profile with `queue_max_objects` small → finalize fails, draft preserved, no committed `.eip`).
- [x] **Step 2:** `cargo test --locked -p ea-destruction --test preflight`; `cargo test --locked -p einsatzarchiv-cli --features desktop-fixture --test operator desktop::network_writer` → red.
- [x] **Step 3:** Implement.
- [x] **Step 4:** Green; regressions `cargo test --locked -p einsatzarchiv-cli --features desktop-fixture --test operator desktop::`, `cargo test --locked -p ea-desktop --test writer_commands`, `cargo test --locked -p ea-desktop --lib`. Clippy `ea-destruction`, `ea-admin`, `ea-desktop`, `einsatzarchiv-cli --features desktop-fixture`.
- [x] **Step 5:** Commit `feat(desktop): commit controlled-network Writer entries into the SQLCipher component`.

---

### Task 8: Publication host, Writer step 12, pruning and sync state

**Depends on:** Tasks 4, 6, 7. **Rules:** EA-CNA-SRC-5, EA-CNA-PUB-3, PUB-4, PUB-6, PUB-8, EA-CNA-REC-2, EA-CNA-WRT-7.

**Files:**
- Modify: `crates/ea-writer/src/finalize.rs` (step 12 ~2091–2103; `WriterService` field + builder), `crates/ea-writer/src/lib.rs` (export)
- Create: `crates/ea-admin/src/network_publication.rs`; `pub mod` in `lib.rs`
- Modify: `crates/ea-admin/src/operator_runtime.rs` (pruning call after the verified union in `open_resources`)
- Modify: `crates/ea-archive-fs/src/sqlcipher_backend.rs` (prune primitive)
- Modify: `apps/desktop/src-tauri/src/runtime/writer.rs`, `runtime/mod.rs` (host loop thread, `SyncStatePort` for network writers via `DesktopState::with_sync_state`)
- Create: `crates/ea-writer/tests/network_publication_step.rs`; `apps/cli/tests/operator_desktop/network_publication.rs`

**Interfaces:**

```rust
// ea-writer
pub trait NetworkPublicationPortV1: Send + Sync {
    /// Called once after step 11. Never fails finalization; outcome is only reported.
    fn publish_committed(&self) -> PublicationOutcomeV1;
}
impl<'a> WriterService<'a> { pub fn with_network_publication(self, port: &'a dyn NetworkPublicationPortV1) -> Self; }

// ea-archive-fs
impl SqlcipherArchiveBackend {
    /// Deletes committed rows whose exact bytes are present at the same address in `remote`.
    /// Requires `lock` to be this database's writer lock; never touches staging, directories or the probe.
    pub fn prune_published(&self, remote: &dyn ArchiveSource, lock: &WriterLock) -> Result<usize, ArchiveBackendError>;
    pub fn try_writer_lock(&self) -> Result<Option<WriterLock>, ArchiveBackendError>; // None when held elsewhere
}

// ea-admin network_publication.rs
pub struct NetworkPublicationHost { queue: PublicationQueue, local: /* component handle */, remote_root: PathBuf, profile: ControlledNetworkProfileV1, state: Mutex<HostState> }
impl NetworkPublicationHost {
    pub fn new(component: &NativeArchiveExistingComponent, archive_directory: &Path, policy: &BoundArchiveProfilePolicyV1) -> Result<Self, NativeArchiveOpenError>;
    pub fn run_once(&self) -> PublicationStateV1;      // derive_pending → queue.publish; Deferred on unreachable remote
    pub fn sync_state(&self) -> (SyncStatus, Option<DetailCause>); // EA-CNA-PUB-4
    pub fn next_delay(&self) -> Option<std::time::Duration>;       // profile backoff; None when attempts exhausted
}
impl NetworkPublicationPortV1 for NetworkPublicationHost { fn publish_committed(&self) -> PublicationOutcomeV1 { self.run_once().outcome() } }
```

Step 12 in `finalize.rs`: if a port is attached, call it and ignore its outcome for control flow; phase/step markers stay exactly as today. Pruning in `open_resources`: only on the network branch, only when the remote was read live (not baseline), after `verify_archive` succeeded: `if let Some(lock) = local.try_writer_lock()? { local.prune_published(&remote_live, &lock)?; }`. Desktop: create one `NetworkPublicationHost` next to `WriterResources` for a network profile; attach it in `writer_action`; call `run_once` after `resolve_pending_finalization`; spawn one `std::thread` that loops `run_once` + `sleep(next_delay)` until `None` or shutdown (an `Arc<AtomicBool>` set on drop); register `SyncStatePort` returning `SyncStateView { status, detail_cause }`.

- [x] **Step 1: RED:**
  - `crates/ea-writer/tests/network_publication_step.rs`: `step_twelve_calls_the_port_once_after_the_entry_commit_and_never_fails_finalization` (fake port records call order relative to backend renames; returns `Deferred`; finalize `Ok`).
  - `crates/ea-archive-fs/tests/sqlcipher_backend.rs`: `prune_removes_only_committed_rows_identical_at_the_remote` and `prune_is_skipped_when_the_writer_lock_is_held`.
  - `apps/cli/tests/operator_desktop/network_publication.rs`: `finalize_publishes_grants_then_entry_byte_identically` (remote files equal local bytes; creation order observed via a remote directory listing between `publish_one` calls is not possible, so assert via a `PublicationTargetV1` spy wrapping `NetworkArchiveTargetV1` in an `ea-admin` unit test instead, and here assert exact bytes and that `sync_state` returns `lokal gesichert`); `finalize_while_remote_is_gone_reports_upload_pending_network_waiting_then_resumes_after_reconnect` (rename remote away, finalize, `sync_state` = `Upload ausstehend`/`Netzarchiv wartet`, rename back, `run_once` → `PublishedCompletely`, bytes identical); `restart_rederives_the_queue_from_committed_bytes` (drop host while deferred, reopen Desktop, pending plan equals the committed local set); `reopen_prunes_published_rows_and_keeps_the_union_identical`.
  - `crates/ea-admin/src/network_publication.rs` `#[cfg(test)]`: `publication_order_is_grants_first_entry_last` with a spy target.
- [x] **Step 2:** `cargo test --locked -p ea-writer --test network_publication_step`; `cargo test --locked -p ea-archive-fs --test sqlcipher_backend`; `cargo test --locked -p ea-admin --lib network_publication`; `cargo test --locked -p einsatzarchiv-cli --features desktop-fixture --test operator desktop::network_publication` → red.
- [x] **Step 3:** Implement.
- [x] **Step 4:** Green; regressions `cargo test --locked -p ea-writer --test offline_finalize`, `--test finalize_faults`, `--test fault_point_manifest`, `--test prepared_recovery` (each as its own `cargo test --locked -p ea-writer --test <name>`), `cargo test --locked -p einsatzarchiv-cli --features desktop-fixture --test operator desktop::`, `cargo test --locked -p einsatzarchiv-cli --test operator recovery::native_archive`. Clippy `ea-writer`, `ea-archive-fs`, `ea-admin`, `ea-desktop`, `einsatzarchiv-cli --features desktop-fixture`.
- [x] **Step 5:** Commit `feat(writer): publish controlled-network commits grants-first with a derived queue`.

---

### Task 9: SyncClient reads the network union instead of a remote `LocalPathBackend`

**Depends on:** Tasks 6 and 8. **Rules:** EA-CNA-PUB-5.

**Files:**
- Modify: `crates/ea-sync-client/src/client.rs` (`SyncClientConfigV1.backend` ~153, `derive_queue` ~328, `persist_verified_receipt` ~446), `crates/ea-sync-client/src/lib.rs`
- Modify: `crates/ea-sync-client/tests/support/mod.rs` (~529), `apps/server/tests/writer_sync_e2e.rs` (~350, ~628) only if coercion does not compile
- Modify: `crates/ea-admin/src/network_publication.rs` (impl for the network component)
- Modify: `crates/ea-sync-client/tests/status.rs`

**Interfaces:**

```rust
pub trait SyncLocalArchiveV1: Send + Sync {
    fn backend(&self) -> &dyn ArchiveBackend;                 // receipt create-if-absent + sync_file/sync_directory
    fn committed_source(&self) -> Result<Box<dyn ArchiveSource + '_>, ArchiveBackendError>;
}
impl SyncLocalArchiveV1 for LocalPathBackend { /* backend = self; source = Box::new(self.as_archive_source()) */ }
pub struct SyncClientConfigV1 { pub backend: Arc<dyn SyncLocalArchiveV1>, /* rest unchanged */ }
// ea-admin: impl SyncLocalArchiveV1 for a NetworkSyncArchiveV1 { component, baseline } whose source is the union (Task 7 NetworkWriterSourceV1 semantics)
```

- [x] **Step 1: RED** in `tests/status.rs`: `server_commit_is_not_sent_while_network_publication_is_deferred_for_a_union_source` — a test `SyncLocalArchiveV1` whose `committed_source` is a two-part union (in-test `ArchiveSource`), network queue over the existing `SwitchableTarget` disconnected; `push_pending` sends no commit request (transport spy) and status is `Upload ausstehend`/`Netzarchiv wartet`.
- [x] **Step 2:** `cargo test --locked -p ea-sync-client --test status` → red (type mismatch).
- [x] **Step 3:** Implement; existing constructions keep compiling via unsized coercion of `Arc<LocalPathBackend>`.
- [ ] **Step 4:** Green; regressions `cargo test --locked -p ea-sync-client --test resume`, `cargo test --locked -p einsatzarchiv-server --test writer_sync_e2e`. Clippy `ea-sync-client`, `ea-admin`.
- [x] **Step 5:** Commit `refactor(sync-client): take the committed archive through a local-archive port`.

---

### Task 10: Documentation corrections

**Depends on:** Task 3 (the parked RED must be gone). **Rules:** none (docs).

**Files:**
- Modify: `docs/traceability/stage-5-gate.md` (only the sentence at ~358–360)
- Modify: `docs/superpowers/plans/2026-09-09-native-archive-recovery-source.md`

- [x] **Step 1:** In `stage-5-gate.md` replace exactly the sentence „Die vier REDs aus `f39c56f` bleiben mit `#[ignore = "DRK-320: …"]` geparkt, ebenso der offene RED `cargo test -p ea-recovery --test fs_source_union`.“ by: „Die vier aus `f39c56f` geparkten REDs sind entparkt: die drei Zeugen in `crates/ea-recovery/tests/fs_source_union.rs` seit `1e7f835` (`FsArchiveSource::with_exact_component`), der letzte, `apps/cli/tests/operator_recovery/native_archive.rs`, mit DRK-320.“ Leave every other line and `docs/traceability/v0.1-requirements.csv` untouched.
- [x] **Step 2:** In the 2026-09-09 plan, correct the drifted names and lines: `NativeArchiveResources` → `NativeArchiveExistingComponent`; `NativeArchiveError` → `NativeArchiveOpenError`; `recovery_test_runtime.rs:103` → `:112`; Desktop `runtime/writer.rs:71` → `:47`; the proposed `network()`, `snapshot_source()`, `acquire_writer_lock()` methods do not exist (the lock is `local_backend().acquire_writer_lock()`); `NativeArchiveSnapshot`/`NativeArchiveLock` were not built. Add one line under the title: „Überholt durch `docs/superpowers/specs/2026-09-21-einsatzarchiv-controlled-network-archive-profile.md` und den DRK-320-Plan vom 2026-09-21.“
- [x] **Step 3:** `cargo test --locked -p xtask --test stage_gate` (it reads `stage-5-gate.md`); it must stay green. If it pins the old sentence literally, update only that literal in the same commit.
- [x] **Step 4:** Commit `docs(traceability): record the un-parked DRK-320 REDs`.

---

## Rulings

1. **Registration writes no active-profile pointer** (EA-CNA-REG-8). The pointer is a control file in the remote root; the registration is a SQLCipher row. Registration only reads the pointer and refuses a conflicting one. *Cost if wrong:* a later profile-migration integration must reconcile pointer and component itself; no data is lost because both rows are immutable and the pointer is untouched.
2. **Registration audit reuses `ArchiveProfileMigration` with `source == target` and a zero pointer hash when no pointer exists** (EA-CNA-REG-4). No new action code or domain string is allowed. *Cost if wrong:* an audit reader that interprets code 11 strictly as a completed switch would misread registrations; mitigated by the equal hashes and documented here. Alternative would be a new audit code (format change) — rejected by the constraints.
3. **Eine Current-Runtime registriert ihre eigene Datenbank – `OrganizationAdmin` oder `Writer`** (EA-CNA-REG-1, Entscheidung vom 2026-09-21, ersetzt „nur `OrganizationAdmin`“). Eigene frische Präsenz (`ArchiveProfileMigration`), eigenes signiertes Audit, Profilhash exakt in der signierten Policy, einmalig, abweichende Zeile wird abgelehnt; andere Rollen und Authority-Konfigurationen nie. *Warum:* Die Präsenz ist an die einzige `operator_profile`-Zeile der eigenen Datenbank gebunden, eine Admin-Runtime kann auf der Writer-Datenbank keine Präsenz erbringen; die Autorität liegt in der signierten Policy, nicht in der Rolle. *Kosten, falls falsch:* Ein Writer kann ein vom Admin zugelassenes Profil ohne Admin vor Ort aktivieren; das Profil selbst bleibt Admin-Entscheidung.
4. **The network profile at startup comes from the DB row, not from configuration** (EA-CNA-SRC-2). `OperatorRuntimeConfig` is `deny_unknown_fields` and carries no profile. *Cost if wrong:* a config/row divergence surfaces only when the Writer/Recovery config is opened (refused there), not at runtime start.
5. **Remote must be readable on cold start; reopen may use the in-memory baseline** (EA-CNA-SRC-4, EA-CNA-S7-2). *Cost if wrong:* a Writer cannot start while the share is unmounted; AK 39 holds only for sessions that lose the share after start. A full offline cold start would need a verified local baseline store (new ticket).
6. **Published local rows are pruned only on open with a live remote read under `try_lock`** (EA-CNA-SRC-5). Without pruning the per-namespace limits in `put_in` would stop the Writer permanently after `queue_max_objects` rows. *Cost if wrong:* pruning in a hot path could race Recovery capture — excluded by the SQLCipher lock; skipped pruning only delays reclaiming capacity.
7. **The queue is derived, never stored; `PublicationQueue` merges instead of replacing** (EA-CNA-PUB-1/7). Keeps `0004_sync_retry.sql`'s stance. *Cost if wrong:* none durable; a process crash re-derives the same plan.
8. **SQLCipher capability measures durability pragmas, physical flush and cross-handle lock exclusivity only** (EA-CNA-WRT-4); create/conflict/rename are proven by backend tests, never by probe writes into the productive namespace (immutable scope rows would make a scratch namespace permanent). *Cost if wrong:* a storage fault in SQL semantics would be caught by tests, not at runtime admission.
9. **Custody location of the local component is the canonical DB path under the unchanged `EINSATZARCHIV-MANAGED-ARCHIVE-LOCATION-v1` domain** (EA-CNA-WRT-7). *Cost if wrong:* moving the DB file changes the location hash and creates a second custody obligation; destruction on network profiles is out of scope anyway.
10. **Recovery capture exports the local component to an exclusively new directory; the target uses copy ⊎ export** (EA-CNA-REC-3/5). Needed because `verify_recovery_source` must verify the union before the snapshot may be decrypted. *Cost if wrong:* one more backup artefact to keep with the snapshot; forgetting it makes target restore fail closed.
11. **The registration's host entry is a new CLI verb `operator register-network-archive`** (Task 2), not a Desktop assistant. *Cost if wrong:* a Desktop UI flow can be added later on the same API.
12. **`SyncClient` gets a local-archive port instead of `Arc<LocalPathBackend>`** (Task 9) although the Desktop has no production sync host yet. *Cost if wrong:* a small refactor without production consumer; keeps EA-CNA-PUB-5 enforceable once a host appears.
13. **Startup unions the registered component without a policy check** (EA-CNA-SRC-2): before `select_current` there is no head to ask. Safe because local bytes are untrusted verifier input and cannot create trust. *Cost if wrong:* after a policy drops the profile, runtimes still read the immutable component (reads only); every write/publication path re-checks policy and blocks with `EA-ARCHIVE-PROFILE-NOT-ALLOWED`, so no unauthorised write follows.
