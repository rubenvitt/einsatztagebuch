# DRK-271 Native Completion Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development to implement and independently review each task.

**Goal:** Complete the operator lifecycle in existing PR #17, including native providers and executable CLI workflows.

**Architecture:** The verified Rust trust, operator and audit services remain authoritative. A native provider owns current-account discovery, installation-bound secrets and OS presence; the CLI composes it with SQLCipher, a persistent trust store and the existing Admin/Root ceremony. Publication is gated by durable profile and native-key readiness, including after restart.

**Tech Stack:** Rust 1.95, existing exact-pinned workspace dependencies, SQLCipher; platform-native identity, keystore and authentication facilities.

**Spec:** `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md` §6.8 and Stage 5 Task 3; ClickUp DRK-271.

## Global Constraints

- This plan supersedes the earlier core-only delivery boundary. The user explicitly requested continuation of the omitted native and CLI work on 2026-09-06.
- Continue the published `drk-271-operator-lifecycle` branch and PR #17. Fetch latest `origin/main`; do not merge the PR or modify local main.
- No frozen Suite v1 wire-format changes, alternate trust verification or test-only signing provider in production.
- No caller-typed identity as proof; identity requires independent organizational verification and stable 16-byte subject ID.
- No plaintext profile or private-key files; no OS-password storage; installation loss and ordinary backup restore must not revive the old binding.
- Every authentication attempt is audited with a verified local signing identity. Audit failure blocks the action.
- Ledger status changes remain in S5-T14. Platform compilation and actual native acceptance must be reported separately.

### Task 1: Verified Reader snapshot

Files: `crates/ea-reader/src/decrypt.rs`, adjacent validation and tests.

- [x] Add adversarial tests for decrypted profile fields, salt and binding substitution.
- [x] Verify the commitment against the historically verified binding using existing canonical encoding/digest.
- [x] Run Reader tests and wasm checks; preserve historical attribution after later revocation.

### Task 2: Durable operator host state

Files: `crates/ea-admin/src/operator.rs`, new host/journal and persistent trust modules; append-only migrations in `ea-local-store`.

- [x] Add RED witnesses for early failed-login audit, profile failure, interrupted publication, replay and restart.
- [x] Persist trust pins, time state and consumed authorization dimensions atomically in SQLCipher.
- [x] Gate publication on exact prepared objects, committed profile and current native key/account; reconcile without silently reprovisioning.
- [x] Run targeted lifecycle, audit and concurrent persistence tests.

### Task 3: Actual native providers

Files: native helper sources under `crates/ea-admin/native/`, a Rust provider adapter, dependency ADR and packaging instructions.

- [x] Review official account, keystore, native presence and backup APIs for each target OS.
- [x] Implement actual account discovery, per-installation nonroaming secrets, native presence and lock checks with bounded private IPC.
- [x] Exercise protocol/error controls and available native paths; compile other platform sources where toolchains permit.

Native source and fixture verification is complete for macOS, Ubuntu and Windows
x64/ARM64. The platform verification/acceptance documents keep the measured
build and fixture results separate from real signed OS deployment, account,
presence and restore acceptance. The latter is still required before operation.

### Task 4: Functional CLI composition

Files: `apps/cli/src/args.rs`, `commands/operator.rs`, output and tests; reusable orchestration in `ea-admin`.

- [x] Specify and test configuration grammar and independent trust-anchor input.
- [x] Compose selected current trust head/sequence/time, SQLCipher, native identity, external identity confirmation and Admin/Root authorization.
- [x] Execute provision, verify-session and revoke through the existing services; provide safe resumption/publication and go-live evidence.
- [x] Verify genuine positive paths and rejection of identity/key/profile/anchor substitutions.

CLI evidence: separate target/authority processes, independent SQLCipher/key
stores and real controlling-terminal input exercise the production dispatcher
and lifecycle services. Provision, restart/login, exact reply replay, revoke
and same-subject replacement passed. Actual target termination preserves the
pending request/key; interruption after publication resumes with the Authority
offline. Watch invalidation during private input publishes nothing. The native
provider in these process tests is an explicit test executable: this evidence
does not replace the outstanding signed OS/account/presence/restore acceptance.

Two further process tests recover the original revocation request after loss of
an already committed Authority reply, including a later actual wall-clock and
retained exchange media. An injected target-journal failure rolls back replay
and Root/revocation audit rows together; restart uses the retained public Root
signature and identical request/key without another Authority Root signature.

The native Writer host must never acquire an Admin or Root private key. Provisioning therefore uses a separate offline authority instance of the CLI, with bounded request/response exchange. Requests carry the authenticated device, current verified chain/Registry context and a fresh reply-encryption public key; replies are signed by the active Admin and encrypted for that request. Personal profile/identity data never appears in cleartext exchange files. The authority runs the existing `RootCeremonyService`; a target-side signing adapter can only return the exact already verified signature for its authorized target. External identity remains an explicit organizational attestation, not an OS name or a CLI text field used as proof.

The target validates remote Admin account/key presence against its pinned binding and handles the decrypted Admin snapshot only in SQLCipher while the ceremony runs. Publication cannot occur until the target profile and native instance are ready. Native acceptance requires provisioned test accounts and a separate authority; automated fixture success is not an OS-presence acceptance result.

### Task 5: Independent review and PR delivery

- [x] Obtain independent lifecycle/security and requirements/test-quality reviews; reproduce and fix confirmed findings.
- [x] Run fmt, Clippy, affected tests/docs, xtask, cargo deny when the graph changes, and `pnpm verify:quick` with actual exits.
- [x] Refresh origin/main and prepare the reviewed implementation, existing PR description and ClickUp handoff with current results and concrete remaining acceptance needs; preserve Draft and do not merge.

Final local verification on 2026-09-06: `pnpm verify:quick` exited 0 in
440.38 seconds, with 1,972 Rust tests passed, zero failed and 11 ignored,
plus 95 Desktop and 93 Web tests. Formatting, strict workspace Clippy,
typechecks, builds, documentation and WASM checks passed. This includes all
42 CLI tests and the six actual offline PTY scenarios. The two ignored CLI
entry functions are explicitly executed as child processes by those tests.
The preceding affected-package run passed 977 tests; 112 affected doc tests,
114 xtask tests and `cargo deny check` also passed. The additional terminal
frame regression is covered by the final workspace gate.

The first-byte/pipe regression failed before the fixture correction with
`Broken pipe`, then passed all 12 trials after serializing the terminal frame
before its atomic write. The delivery marker remains after emission; the
production watcher and original test/security deadlines are unchanged.

The fetched base is `origin/main` at
`99f88ebd2a5a9d4f48eb1698645be257ea421118`. Publication and subsequent remote
CI state are recorded in [PR #17](https://github.com/rubenvitt/einsatztagebuch/pull/17)
and [DRK-271](https://app.clickup.com/t/123zgec129z). Real signed OS/account,
presence, restore and macOS EndpointSecurity-entitlement acceptance remain
open; local green gates do not close those requirements or the ledger.
