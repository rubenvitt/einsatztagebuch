# DRK-250 Runtime Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the production integration gaps identified during the full DRK-250 preflight, in addition to the fourteen existing Stage-5 tasks.

**Architecture:** Reuse the shipped typed Admin, Operator, Writer, Recovery and verification services. Native and external state is consumed through actual adapters. A DTO or test double never becomes an authorization proof. Durable signed outcomes and exact archive bytes carry the result across restarts.

**Tech Stack:** Existing Rust/SQLCipher core, native Windows/macOS/Ubuntu helpers, Tauri/React/Ant Design, PostgreSQL/S3 and explicit offline key sources.

**Spec:** `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md` §§6.8, 12, 16, 18.4, 19, 21, 23; `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §§6.6, 7, 12. The original `2026-08-13-einsatzarchiv-stage-5-administration-recovery.md` remains the primary contract, including all Global Constraints.

## Global Constraints

- Preserve existing v1 bytes, the exact seven Admin action codes and cardinality-one existing Admin authorizations. The decided escrow additions are a separate v1.1 family/cutover, not an arity rewrite.
- An unverified caller boolean, deserialized reference or mutable database status never grants authority.
- Every privileged operation requires its real purpose-specific native proof and signed durable audit. Key, account, binding, current head, time floor and capability checks remain active.
- `Pass`, `Fail`, `Unknown` stay distinct. Fail blocks production sessions; Unknown remains unresolved in Go-live and never turns green.
- No private key, profile salt, challenge, decrypted payload, display name or sensitive path leaks into public reports, logs or DTOs.
- Work in the DRK-250 isolated worktree. Each code slice has one owner; native runtime/Writer/CLI exports are serialized where shared.
- Stage 7 retains installed native minimum/maximum cases, production custody, external privacy approval and quarterly exercises. Missing runtime code remains a Stage-5 obligation.

### Task 1: Enforce measured device posture at the production session boundary

**Files:** modify `crates/ea-key-provider/src/{posture,windows,macos,linux}.rs`, `crates/ea-admin/src/operator_runtime.rs`; create `crates/ea-admin/tests/operator_posture.rs`; extend `crates/ea-key-provider/tests/device_posture.rs`; add a dependency ADR only if a new native API dependency is needed.

**Interfaces:** consume the existing synchronous `DevicePostureProvider::report() -> Result<DevicePostureReport, KeyError>` and `OperatorRuntime::reauthenticate() -> Result<VerifiedOperatorSession, OperatorRuntimeError>`. Produce a production session only after the actual provider report satisfies `DevicePostureReport::is_production_ready()`. Preserve the four stable `PostureRequirement` evidence-code families and `go_live_follow_up()` output.

- [ ] Write session-level tests with a valid native account/instance/reauth fixture and independently substitute each measured Fail and Unknown. Assert the privileged session/action is refused, not only the report predicate. Assert all-Pass permits the otherwise valid session. Assert provider I/O failure refuses the session and an Unknown remains visible as Unknown in Go-live.
- [ ] Run `cargo test --locked -p ea-admin --test operator_posture` and record the behavioral RED.
- [ ] Read the actual native platform signals through bounded fixed-command/API adapters, with no caller-supplied executable or shell interpolation. Read disk encryption, account restrictions, automatic screen lock and supported-version policy only where reliable; absent/unparseable/unsupported signals remain Unknown. Never infer non-shared human use solely from a username or assume a patch is current from its major version. Consume the report immediately before native session issuance and before returning a privileged result if the runtime performs lengthy work. Tests inject the provider; production chooses only its matching platform adapter.
- [ ] Run `cargo test --locked -p ea-key-provider --test device_posture` and `cargo test --locked -p ea-admin --test operator_posture`; include real read-only host observation as a bounded native measurement without claiming other platforms were run. Record denied-action evidence and retained Unknown fields.
- [ ] Independently review and commit the slice; regenerate any affected Go-live DTOs through the existing emitter, then validate typecheck/static styles.

### Task 2: Compose actual Desktop Admin, reauth and session invalidation

**Files:** create a focused `apps/desktop/src-tauri/src/runtime/` module; modify `apps/desktop/src-tauri/src/{lib,state}.rs`, command registration and relevant capability declarations; consume existing `crates/ea-admin/src/{native_provider,operator_runtime}.rs`; create a native command integration test under `apps/desktop/src-tauri/tests/` or existing lib tests where private seams require it.

**Interfaces:** concrete implementations of existing `AdministrationPort` and `ReauthPort`, configured `DesktopState` at actual startup, and native watcher invalidation into existing `announce_session_lock`. Consume actual verified independent anchor, encrypted DB, archive/Trust state, native installed provider and offline request/exchange paths. The empty first-start state is an explicit setup state, not a successful runtime.

- [ ] Write a command-to-real-port-to-core-to-persisted-signature witness using a temporary real archive/SQLCipher repository and controlled native process fixture. Reopen the repository and independently verify the exact result and audit. A missing configuration, wrong native account, lock event or audit persistence failure must deny the operation.
- [ ] Run the named focused native command target and record the expected unavailable-port RED.
- [ ] Construct real ports in startup from explicit setup/configuration; never use fixture keys, fake pending requests or arbitrary role flags. Bridge existing continuous native watcher invalidation before UI cleanup, invalidate outstanding reauth markers/proofs on lock and expire them according to the existing inactivity contract. Route pending device requests and offline Root exchange through real verified service methods and selected explicit sources.
- [ ] Run the command integration test and relevant host/bridge tests. Keep browser tests as UI evidence and the native command/repository test as composition evidence. Verify generated contract and command allowlist consistency.
- [ ] Independently review and commit; later Recovery/Destruction assistants attach their actual services to this runtime instead of introducing another startup.

### Task 3: Complete the host-driven twelve-step bootstrap

**Files:** modify `apps/cli/src/commands/organization.rs` and focused CLI grammar; add focused host orchestration alongside `crates/ea-admin/src/bootstrap.rs`; extend existing bootstrap tests and add a CLI end-to-end bootstrap target.

**Interfaces:** existing `BootstrapCoordinator` durable steps and external pre/final anchor readback; explicit offline key handles and independent media; the completed Task-9 report is the only path to final Recovery readiness. Retain `organization init` as start/resume until all steps are actually verified.

- [ ] Write a real CLI orchestration test that resumes across step boundaries, creates and verifies signed public objects, confirms two independent anchor media and remains `BlockedRecoveryTest` until a complete fresh-machine Recovery result. Change one pre-anchor field and assert new organization/chain identity is required.
- [ ] Run the focused test to observe that current `organization init` does not advance steps 2–12.
- [ ] Wire each existing coordinator method to explicit input/output and durable forward-only state. Resolve machine identity from the actual platform helper, not Linux paths on every OS. Keep secret material behind opaque handles; Reader/Recovery/HGA/Approver secrets never enter the Writer. A missing medium/provider or incomplete report leaves the exact current step resumable.
- [ ] Exercise restart, incorrect media/hash/pairing, key loss, wrong machine, failed audit and final anchor readback. Feed the actual complete Task-9 report and re-verify all generated objects against the independent anchor.
- [ ] Independently review and commit; use this host flow in the cumulative fresh-machine/lifecycle gate.

### Task 4: Bind explicit PKCS11 modules through non-exporting offline ports

**Files:** extend `crates/ea-recovery/src/{pkcs11,key_source}.rs` and narrow T8 KEM/signing ports; add `crates/ea-recovery/tests/pkcs11_module.rs`; update dependency ADR0001 or a new ADR, exact workspace/lock dependencies and `deny.toml` only as justified; add deterministic SoftHSM fixture provisioning to `ops/compose/browsers.yaml` or its narrowly scoped fixture build context.

**Interfaces:** the existing explicit `Pkcs11KeyReference` and restrictive PIN file reader; operational KEM/signing provider handles rather than `resolve_material` private-byte export. The software/container resolver remains compatible. Token selection requires one exact token-label match and one exact key-ID/kind match.

- [ ] Establish a real SoftHSM module fixture with generated test-only Ed25519 and X25519 keys. Write positive module login/public binding/sign/HPKE interoperability tests, negative wrong/ambiguous token and key IDs, wrong PIN, wrong key kind and unavailable mechanism tests. Assert private-key extraction is never requested by the adapter.
- [ ] Record RED against the existing `EA-RECOVERY-PKCS11-UNBOUND` boundary. Research exact cryptoki/cryptoki-sys/libloading/secrecy versions and fresh RustSec/license evidence before dependency admission; preserve native-only graph and wasm exclusions.
- [ ] Load only the explicit selected module and execute operations through non-exporting handles. Derive short-lived DH/CEK data only into protected memory, remove transient token objects and zero host secrets on success/error. Map provider failures to stable existing exit categories without paths/PIN/key labels in logs. No token scanning, first-object fallback or software private-key export fallback.
- [ ] Run actual module tests, existing source/container tests, cryptographic interop vectors and `cargo deny check`; prove grant/recovery-test consumers use this provider successfully. Pin fixture source/digest and document any explicit module-specific legacy X25519 representation in the fixture, without silently accepting arbitrary key kinds.
- [ ] Independently review and commit the adapter, ADR/lock/licence and runnable fixture together. Hardware custody/release matrix remains separately named Stage-7 evidence.

### Task 5: Diagnose and safely resolve inconsistent prepared state

**Files:** extend `crates/ea-writer/src/recover.rs` and a focused administration diagnostic service; add explicit CLI command and focused tests; consume `crates/ea-archive-fs/src/local_path.rs` kernel lock proof without deleting a lock file as a remedy.

**Interfaces:** exact existing prepared marker, durable archive/backend state, draft key-presence boundary, fresh authorized native Admin/Root proof, signed audit and exclusive Writer/draft access. Produce a cleartext-free diagnostic and an explicitly verified resolution result; preserve an unresolved/quarantined result where exact irreversible completion cannot be proved.

- [ ] Write fault witnesses for mismatch before and after draft-key deletion, abandoned file with no kernel owner, live kernel owner, wrong original hashes, partial commit, replay and restart. Snapshot bytes/sequence/key state before diagnostics and assert read-only inspection preserves them.
- [ ] Run the focused diagnostics target against the current unavailable administrative path.
- [ ] Implement bounded diagnosis with exact discrepancy codes. Resolution requires independent cryptographic reconstruction: reversible state can restore only the original encrypted draft; irreversible state can finish only independently verified exact prepared objects. Conflicting evidence is retained/quarantined and never silently cleared, resequenced or reserialized. Deny mutation under a live Writer lock, absent fresh authority or failed durable audit. Crash recovery resumes the same authorized action.
- [ ] Run the new fault witnesses and existing `ea-writer --test prepared_recovery` target. Prove no new bypass of permanent inconsistent-state blockers and no lock deletion based only on filename or caller assertion.
- [ ] Independently review the resolution policy/code and commit. A truly non-reconstructible archive remains a reported recovery failure, not fabricated success.

## Additional escrow work and ordering

The original Stage-5 Global Constraints require **two further tasks**, E1 enrollment escrow and E2 authorized opening. Their exact additive wire profiles and deployment cutover must be specified and independently reviewed before codec implementation; the previous decisions (own 2-of-N family, escrow in ordinary replicated `trust/`, unchanged old Admin arity) are already fixed. The new profile must reconcile Root/Admin authorized-core binding for escrow publication without silently broadening the old seven-action table. Both families must ship across verifier/Reader-bundle/server/CLI before first escrow enrollment emits either family; legacy verifiers remain fail-closed on new subtypes.

E1 acceptance: Root-signed Reader certificate first; browser seals only its X25519 KEM key with AAD binding exact certificate hash, pseudonymous subject and enrollment Registry version; Root-signed exact escrow trust object is admitted, replicated and exported. Old wire bytes stay identical and Ed25519 key material never enters escrow.

E2 acceptance: two current distinct-person approvals bind identity, purpose and exact target transport-key fingerprint; verified one-use authorization, native reauth and signed durable audit precede output; plaintext KEM exists only in protected memory and is immediately re-encrypted to the new browser Vault. Wrong target key, subject, old Registry binding, key kind, approval or replay releases nothing. New audit/device key is independently generated and certified.

Execution order: T8 and T11 are parallel; R62 owns Writer before T10; T9 consumes T8 provider and bootstrap seams; T12 consumes T11 and follows T10 on Writer files; native runtime is composed once before T9/T13 host completion; E1/E2 precede T14. T14 may move the nineteen ledger rows only after all these actual product paths and the complete original command/test requirements have evidence.
