# Task 8 Trust/Time v1 Contract Alignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Atomically align the unreleased v1 normative contracts, CDDL, existing exact-format parser, crypto verifier, and permanent literals with the approved Task-8 trust/time closure before creating `ea-time` or `ea-trust`.

**Architecture:** This is a prerequisite compatibility break, not a runtime feature. It changes exactly two v1 wire structures: Device Certificate cores become 14-element arrays with `authoritySubjectId`, and Clock Release contexts become 10-element arrays with a mandatory independent-time reference. The existing crypto Trust-correlation hook is corrected to bind an authorization to the previous Registry head and the event to its direct `+1` successor. Old 13-/6-element forms remain invalid; there is no v2 or legacy parser.

**Tech Stack:** Rust 1.95 workspace, `ea-types`, `ea-cbor`, `ea-format`, `ea-crypto`, deterministic CBOR via `minicbor`, CDDL via `cddl-cat`, `xtask`, Cargo, pnpm.

## Global Constraints

- Work only in `.worktrees/einsatzarchiv-v0-1` on `codex/einsatzarchiv-v0-1`.
- Read and follow `/Users/rubeen/.codex/RTK.md`; run repository commands through `rtk`.
- Use `apply_patch` for tracked edits. Preserve unrelated user changes.
- Start each behavior change with an executable RED and record the exact command, exit code, and focused failure.
- Reuse the existing `ea_types::SubjectId` as the Rust representation of `authoritySubjectId`; do not introduce a second indistinguishable 16-byte authority-ID type.
- `authoritySubjectId` compares byte-for-byte with `OperatorSubjectId` through `as_bytes()`; certificate/device/hash identifiers never substitute for a person identity.
- Do not create `ea-time` or `ea-trust` in this plan.
- Do not add a v2 decoder, permissive legacy branch, caller-selectable parser limits, raw-CBOR public escape hatch, or a public proof constructor.
- Do not broaden Clock Release semantics in `ea-crypto`: this phase validates exact local wire shape and local correlations only. Head, policy, authority, replay, and persistence belong to the runtime plan.
- Keep errors code-only. The existing format/crypto error variants are sufficient for this phase; do not embed identifiers, exact bytes, nonces, or justification text.
- The corrected normative docs, CDDL, parser behavior, crypto behavior, tests, and KATs must be committed together. Intermediate commits are forbidden because none describes a valid v1 state.
- Never stage `.superpowers/`, generated `target/`, or `node_modules/`.

## Required Acceptance Matrix

| Contract | Positive evidence | Negative evidence |
|---|---|---|
| Device Certificate | Kinds 2/3 with `Some(SubjectId)`; all other kinds with `None` | old length 13; kinds 2/3 with null; any other kind with non-null |
| Registry successor | auth `v0/zero32` to event `v1/null`; auth `vN/headN` to event `vN+1/headN` | same version, version gap, overflow, wrong/null previous hash |
| Local action/change hooks | closed local `(action,targetSubtype)` and `(action,changeKind)` matrices, including `(4,4)` and `(6,6)` | crossed local target/change/certificate-kind inputs; activation, Change-5 state/effect, self-authorization, and Head correlation remain Runtime Phase B |
| Clock Release shape | action 6, any closed audit outcome 0–2, exact 10-field context and reference tags 0–2; positive literal uses outcome 1 | old 6 fields, tag 3, wrong hash length, justification 3, `issuedAt >= expiresAt`, outer/context now mismatch |
| Compatibility | corrected literals and all unaffected object families | any acceptance of the old 13-/6-field wire forms |

---

### Task 1: Pin the correction with machine-readable normative REDs

**Files:**
- Modify: `tools/xtask/tests/spec_completeness.rs`
- Read: `docs/superpowers/specs/2026-08-14-einsatzarchiv-task-8-trust-time-closure-design.md`
- Read: `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md`
- Read: `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-wire-format-addendum.md`
- Read: `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md`
- Read: `schemas/archive/v1/trust.cddl`
- Read: `schemas/reports/v1/local-audit.cddl`

- [ ] **Step 1: Add one exact contract-completeness test**

Add a test named `task8_trust_time_closure_is_consistent_across_normative_sources`. It must read the approved closure design plus the main design, wire addendum, Stage-1 plan, Trust CDDL, and local-audit CDDL. Assert literal markers for:

```text
device-certificate-core-for-v1<KIND, AUTHORITY_SUBJECT_ID>
authority-subject-id
authorization.registryVersion = previousHead.registryVersion
event.registryVersion = checked_add(authorization.registryVersion, 1)
action 4 operatorBinding -> registryEvent change 4
action 6 rootRotation -> registryEvent change 6
independent-time-reference-v1
clock-release-context-v1
registry-head-hash
guard-policy-object-hash
```

Also assert the Stage-1 plan explicitly rejects `device-certificate-core-v1` length 13 and Clock Release context length 6.

- [ ] **Step 2: Extend the existing CDDL fixture model**

Update only test-side builders:

```rust
struct DeviceCertificateFixture {
    certificate_kind: u8,
    authority_subject_id: Option<[u8; 16]>,
}

enum AuditContextFixture {
    ClockRelease {
        registry_version: u64,
        registry_head_hash: [u8; 32],
        guard_policy_object_hash: [u8; 32],
        independent_reference: (u8, [u8; 32], i64),
    },
    // existing variants
}
```

Build valid 14-/10-field values and explicit old-shape fixtures.

- [ ] **Step 3: Run the focused RED**

Run:

```bash
rtk cargo test --locked -p xtask --test spec_completeness task8_trust_time_closure_is_consistent_across_normative_sources -- --exact --nocapture
```

Expected: exit 101 because the main normative sources and CDDL still describe the old shapes/rules. Record each independent assertion failure; do not edit production or normative sources before this run.

---

### Task 2: Align all normative prose without changing more wire structures

**Files:**
- Modify: `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md`
- Modify: `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-wire-format-addendum.md`
- Modify: `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md`
- Modify: `docs/superpowers/plans/2026-08-13-einsatzarchiv-v0-1.md`
- Modify: `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-5-administration-recovery.md`
- Reference: `docs/superpowers/specs/2026-08-14-einsatzarchiv-task-8-trust-time-closure-design.md`
- Reference/link: `docs/superpowers/plans/2026-08-14-einsatzarchiv-task-8-trust-time-implementation.md`

- [ ] **Step 1: Correct Registry authorization and activation prose**

Mirror the approved design exactly:

```text
authorization.registryVersion = previousHead.registryVersion
authorization.registryHeadHash = previousHead.objectHash
event.registryVersion = checked_add(authorization.registryVersion, 1)
event.previousRegistryHash = null iff event.registryVersion == 1
event.previousRegistryHash = authorization.registryHeadHash otherwise
```

State that direct object authorization and activation-event authorization are separate objects/nonces but bind the same previous head. Pin the first head to Change 2 for the initial Policy; Anchor-pinned Admin pairs are external basis state, not another Registry change.

- [ ] **Step 2: Replace the action/change and policy/sequence tables**

Copy the complete action 0–6 table from the approved closure. Explicitly distinguish Change 5 Effect 0 activation from Effect 1 revocation, forbid Admin revocation through Change 1, and add Registry targets for actions 4 and 6. Add:

```text
preTransitionSequence = transitionSequence
  when previous.effectiveFrom <= transitionSequence <= previous.validThrough
preTransitionSequence = previous.validThrough
  when transitionSequence == checked_add(previous.validThrough, 1)
```

Pin Policy version/hash/effective-sequence rules and Root effective Registry version.

- [ ] **Step 3: Correct historical authorization time**

State that both the direct target authorization and activation-event authorization are checked at the signed activation event `issuedAt`, inclusive at both authorization bounds, while `authorization.issuedAt < authorization.expiresAt` remains strict. Forbid evaluation against current wall clock or an invented Root-signature time.

- [ ] **Step 4: Correct authority identity and Clock Release prose**

Specify the 14th Device Certificate field immediately before critical extensions, exact nullability, Admin Binding equality, distinct approver identities, and self-authorization rejection. Replace the old Clock Release shape with the 10-field context and three-tag independent reference. Pin the phased candidate/release/selection order, guard-policy selection, no-reference warning, by-value proof consumption, and atomic replay/head/floor commit.

- [ ] **Step 5: Correct downstream plan seams**

In the Stage-1 plan, split Task 8 into this prerequisite phase and link the exact runtime path `docs/superpowers/plans/2026-08-14-einsatzarchiv-task-8-trust-time-implementation.md`. Remove the obsolete `effective_now_with_clock_release(&...)` and old three-argument selection seam. In the umbrella and Stage-5 plans, reference the opaque proof states and the bound Head/Policy/reference Clock Release context without claiming implementation in this phase.

- [ ] **Step 6: Run the prose portion of the focused test**

Run the same focused command. Expected: prose assertions pass; CDDL assertions may remain RED until Task 3.

---

### Task 3: Correct Trust and local-audit CDDL

**Files:**
- Modify: `schemas/archive/v1/trust.cddl`
- Modify: `schemas/reports/v1/local-audit.cddl`
- Test: `tools/xtask/tests/spec_completeness.rs`
- Test: `tools/xtask/tests/schema_validation.rs`

- [ ] **Step 1: Make Device Certificate nullability structural**

Define:

```cddl
device-certificate-core-v1 =
  device-certificate-core-for-v1<0 / 1 / 4..7, null> /
  device-certificate-core-for-v1<2 / 3, bstr .size 16>
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
```

Do not modify the separate 13-element Registry Event core.

- [ ] **Step 2: Make Clock Release exact and closed**

Define:

```cddl
independent-time-reference-v1 =
  [0, receipt-object-hash: bstr .size 32, verified-time: int] /
  [1, checkpoint-object-hash: bstr .size 32, verified-time: int] /
  [2, tsa-evidence-object-hash: bstr .size 32, verified-time: int]

clock-release-context-v1 = [
  trusted-time-floor: int,
  observed-os-wall-clock: int,
  max-future-clock-skew-ms: uint,
  registry-version: uint,
  registry-head-hash: bstr .size 32,
  guard-policy-object-hash: bstr .size 32,
  independent-time-reference: independent-time-reference-v1,
  justification-code: 0..2,
  issued-at: int,
  expires-at: int
]
```

- [ ] **Step 3: Add explicit old-shape rejection fixtures**

The xtask tests must validate the new positive values against the named CDDL roots and assert that old 13-field Device Certificates and old 6-field Clock Release contexts fail.

- [ ] **Step 4: Run CDDL GREEN gates**

Run:

```bash
rtk cargo test --locked -p xtask --test spec_completeness --test schema_validation
rtk cargo run --locked -p xtask -- validate-schemas
```

Expected: all tests pass and schema counts remain otherwise unchanged.

---

### Task 4: Change the exact-format Device Certificate contract test-first

**Files:**
- Modify: `crates/ea-format/tests/support/mod.rs`
- Modify: `crates/ea-format/tests/object_roundtrip.rs`
- Modify: `crates/ea-format/tests/negative.rs`
- Modify: `crates/ea-format/src/etb.rs`

- [ ] **Step 1: Update typed and literal fixtures before production**

Add `authority_subject_id: Option<SubjectId>` to every Device Certificate fixture. Use the same 16 bytes as the paired `OperatorSubjectId` for Admin fixtures, a distinct stable ID for Key Approvers, and `None` for Writer/Reader/Recovery/Historical/Server/Deletion kinds.

- [ ] **Step 2: Add the exact RED matrix**

Tests must cover:

```text
OrganizationAdmin + Some -> accepted
KeyApprover + Some -> accepted
each other kind + None -> accepted
old 13-element core -> EA-FORMAT-SHAPE
OrganizationAdmin or KeyApprover + None -> EA-FORMAT-SHAPE
each other kind + Some -> EA-FORMAT-SHAPE
```

Add `device_certificate_v1_production_bytes_match_pinned_literal`: construct
`DeviceCertificateFieldsV1`, encode a real Trust object through the production
encoder, extract the exact core test-side, and compare it with an independently
pinned complete 14-field literal. The normal decode/re-encode roundtrip must
preserve exact bytes and subtype. A typed decoded-field API is deliberately
added only in Runtime Phase B.

Name the closed negative table
`device_certificate_authority_subject_id_matrix_is_closed`.

- [ ] **Step 3: Run the format RED**

Run:

```bash
rtk cargo test --locked -p ea-format --test object_roundtrip device_certificate_v1_production_bytes_match_pinned_literal -- --exact --nocapture
rtk cargo test --locked -p ea-format --test negative device_certificate_authority_subject_id_matrix_is_closed -- --exact --nocapture
```

Expected: compile/behavior RED because the field and 14-element codec do not exist.

- [ ] **Step 4: Implement the minimal 14-element codec**

Change:

```rust
pub struct DeviceCertificateFieldsV1 {
    // existing fields
    pub revoked_from_sequence: Option<ChainSequence>,
    pub authority_subject_id: Option<SubjectId>,
}
```

Encode array length 14 and write the optional 16-byte subject immediately before `[]`. Decode/validate length 14. Require `Some` exactly for `OrganizationAdmin` and `KeyApprover`; require `None` for every other closed kind. Keep all existing signing/KEM/key/thumbprint rules intact.

- [ ] **Step 5: Run focused and full format GREEN gates**

Run:

```bash
rtk cargo test --locked -p ea-format --test object_roundtrip device_certificate_v1_production_bytes_match_pinned_literal -- --exact --nocapture
rtk cargo test --locked -p ea-format --test negative device_certificate_authority_subject_id_matrix_is_closed -- --exact --nocapture
rtk cargo test --locked -p ea-format
```

Expected: all format suites pass.

---

### Task 5: Align crypto certificate parsing and expose the verified authority ID

**Files:**
- Modify: `crates/ea-crypto/tests/identity.rs`
- Modify: `crates/ea-crypto/src/cose.rs`
- Modify: `crates/ea-crypto/src/lib.rs`

- [ ] **Step 1: Add crypto certificate REDs**

Update all exact ETB builders to 14 fields. Extend the 8-kind matrix with old-length and both nullability violations. Add the exact test `certificate_authority_subject_id_is_closed_and_propagated`, proving:

```rust
assert_eq!(verified_writer.authority_subject_id(), None);
assert_eq!(verified_admin.authority_subject_id(), Some(admin_subject));
assert_eq!(verified_approver.authority_subject_id(), Some(approver_subject));
```

- [ ] **Step 2: Run the focused RED**

Run:

```bash
rtk cargo test --locked -p ea-crypto --test identity certificate_authority_subject_id_is_closed_and_propagated -- --exact --nocapture
```

Expected: 14-field fixtures fail or the getter is missing.

- [ ] **Step 3: Update the private duplicate parser once**

Add `authority_subject_id: Option<SubjectId>` to `ParsedSignerCertificate` and `VerifiedSigner`. The Device parser must require length 14 and the same nullability matrix as `ea-format`; Root certificates use `None`. Carry the parsed ID through `verify_cose_sign1` and expose only:

```rust
impl VerifiedSigner {
    pub const fn authority_subject_id(&self) -> Option<SubjectId>;
}
```

Do not expose raw certificate fields or a public constructor.

Explicitly add `VerifiedSigner` to the public `pub use cose::{...}` list in
`crates/ea-crypto/src/lib.rs`; Runtime Phase B must be able to name the proof
returned by `verify_cose_sign1`.

- [ ] **Step 4: Run the certificate GREEN tests**

Run the focused command and then:

```bash
rtk cargo test --locked -p ea-crypto --test identity
```

Expected: all tests pass; violations normalize to `EA-TRUST-SIGNER-MISMATCH`.

---

### Task 6: Correct existing Root Trust previous-head and action correlation

**Files:**
- Modify: `crates/ea-crypto/tests/identity.rs`
- Modify: `crates/ea-crypto/src/cose.rs`

- [ ] **Step 1: Parameterize authorization/event fixtures**

Add the exact table-driven test
`root_registry_authorization_binds_previous_head_and_successor`. Allow it to
set authorization version/head, event version/previous, action, change
kind/effect, and direct subtype independently.

- [ ] **Step 2: Add exact transition REDs**

Required positives:

```text
auth v0/zero32 -> event v1/null
auth v3/head3 -> event v4/head3
action 4 direct operatorBinding and event Change 4
action 6 direct rootCertificate and event Change 6
```

Required negatives:

```text
auth/event same version
version jump > 1
auth version u64::MAX
event v1 with non-null previous
event vN>1 with null/wrong previous
action 4/change 6 and action 6/change 4
```

- [ ] **Step 3: Run the behavioral REDs**

Run:

```bash
rtk cargo test --locked -p ea-crypto --test identity root_registry_authorization_binds_previous_head_and_successor -- --exact --nocapture
```

Expected: at least the old same-version fixture is accepted and actions 4/6 Registry targets are rejected.

- [ ] **Step 4: Implement typed internal bindings**

Extend the internal authorization binding with `registry_head_hash: Hash32`. Replace the Registry parser tuple with:

```rust
struct RegistryEventCoreBindings {
    organization_id: OrganizationId,
    registry_version: RegistryVersion,
    previous_registry_hash: Option<Hash32>,
    effective_from_sequence: ChainSequence,
    change_kind: u64,
}
```

In `root_trust_bindings`:

```text
expectedEventVersion = checked_add(auth.registryVersion, 1)
event v1 => auth v0 + zero32 + previous null
event vN>1 => previous == auth.registryHeadHash
RootTrustBindings.registry = auth.registryVersion
```

This last equality intentionally resolves the Root against the previous head. Extend direct-target and change matrices for actions 4 and 6. Do not implement historical activation/state traversal here.

- [ ] **Step 5: Run focused GREEN**

Run the focused test and full `identity`. Expected: all pass with invalid correlations returning `EA-CRYPTO-INVALID-PROTOCOL-CORE`.

---

### Task 7: Validate the corrected Clock Release core locally

**Files:**
- Modify: `crates/ea-crypto/tests/cose_profile.rs`
- Modify: `crates/ea-crypto/src/cose.rs`

- [ ] **Step 1: Add a dedicated literal positive core**

Add the exact test `clock_release_local_core_is_exact_and_closed`. Its positive
fixture uses action 6/outcome 1 and pins this complete core literal rather than
assembling expected bytes dynamically:

```text
8c0150000102030405060708090a0b0c0d0e0f50101112131415161718191a1b1c1d1e1f50202122232425262728292a2b2c2d2e2f5820303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f5820404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f060119044c82028a1903e819044c1864075820a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf5820b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf83005820c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf190384001903e81904b05820d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef80
```

- [ ] **Step 2: Add local-correlation REDs**

Mutate independently:

```text
old context length 6
independent reference tag 3
reference/head/policy hash length != 32
justification 3
issuedAt == expiresAt and issuedAt > expiresAt
outer effectiveNow != max(observedOsWallClock, trustedTimeFloor)
action != 6 for the Clock Release context tag
```

Outcomes 0, 1, and 2 remain valid local-audit wire values. Only Runtime Phase B
may turn Outcome 1 into a `VerifiedClockRelease`; Phase A must not reject a
failed or indeterminate Clock Release attempt as malformed.

- [ ] **Step 3: Run the focused RED**

Run:

```bash
rtk cargo test --locked -p ea-crypto --test cose_profile clock_release_local_core_is_exact_and_closed -- --exact --nocapture
```

Expected: the new valid context is rejected or one or more invalid mutations are accepted.

- [ ] **Step 4: Implement exact local validation**

Retain outer `effective_now` in `validate_local_audit_core` and pass it to a dedicated `validate_clock_release_context`. Require array length 10, reference length 3/tag 0–2, exact bstr32 values, justification 0–2, strict issued/expires ordering, and outer-now equality. Accept all closed audit outcomes 0–2. Keep accepted-outcome proof creation, signer activity, Registry Head, policy, independent-proof authenticity, and replay outside this validator.

- [ ] **Step 5: Run focused GREEN**

Run the focused test and full `cose_profile`. Expected: all local violations return `EA-CRYPTO-INVALID-PROTOCOL-CORE`.

---

### Task 8: Re-pin every affected literal and prove mutation sensitivity

**Files:**
- Modify: `crates/ea-crypto/tests/suite_v1_literal_kats.rs`
- Modify: `crates/ea-format/tests/support/mod.rs`
- Modify: `crates/ea-format/tests/object_roundtrip.rs`
- Test: all `ea-format` and `ea-crypto` suites

- [ ] **Step 1: Independently derive the affected Device Certificate literals**

Only literals containing a Device Certificate core may change. For the existing authorized server-receipt certificate context, pin:

```text
827164657669636543657274696669636174658e0150000102030405060708090a0b0c0d0e0f50404142434445464748494a4b4c4d4e4f065828a3010120062158202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12f65820ee5ce0c67cc72d49015fb20337327af13572fc6ed9517fcc02edfb019342f36cf6816d736572766572526563656970740400f6f680
```

and digest:

```text
7cd7378a90d9c9d31e3f0337b8ec51d77d3158d3967eead41133e3bc36b2fbd4
```

Both `authorized_device_certificate` entries must pin the same complete values:

```text
context_hex = 827164657669636543657274696669636174658e0150000102030405060708090a0b0c0d0e0f50404142434445464748494a4b4c4d4e4f065828a3010120062158202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12f65820ee5ce0c67cc72d49015fb20337327af13572fc6ed9517fcc02edfb019342f36cf6816d736572766572526563656970740400f6f680
preimage_hex = 45494e5341545a4152434849562d41444d494e2d415554484f52495a45442d54525553542d7631827164657669636543657274696669636174658e0150000102030405060708090a0b0c0d0e0f50404142434445464748494a4b4c4d4e4f065828a3010120062158202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12f65820ee5ce0c67cc72d49015fb20337327af13572fc6ed9517fcc02edfb019342f36cf6816d736572766572526563656970740400f6f680
sha256_hex = 7cd7378a90d9c9d31e3f0337b8ec51d77d3158d3967eead41133e3bc36b2fbd4
mutation_index = 54
```

Recompute from an independent one-off derivation, then hard-code the result. Do not derive expected values via production code at assertion time.

- [ ] **Step 2: Add one temporary production-byte mutant**

Temporarily move or alter the new `authoritySubjectId` encoding position by one byte. Run the production-linked exact test, not only the static digest table:

```bash
rtk cargo test --locked -p ea-format --test object_roundtrip device_certificate_v1_production_bytes_match_pinned_literal -- --exact --nocapture
```

Record the RED and revert the mutant completely with `apply_patch`. Then run
the `suite_v1_literal_kats` target to prove the independently pinned digest
table is green on the corrected bytes.

- [ ] **Step 3: Run all focused suites**

Run:

```bash
rtk cargo test --locked -p ea-crypto --test identity --test cose_profile --test suite_v1_literal_kats
rtk cargo test --locked -p ea-format
rtk cargo test --locked -p ea-crypto
```

Expected: all pass after the mutant is removed.

---

### Task 9: Full gates, two independent reviews, and one atomic commit

**Files:**
- Review all files changed by Tasks 1–8
- Update ignored evidence only: `.superpowers/sdd/2026-08-13-einsatzarchiv-stage-1-trust-core-format/task-8-normative-correction-report.md`
- Update ignored SDD ledger for Task 8 Phase A

- [ ] **Step 1: Run the complete fresh gate set**

Run from a clean generated-artifact state:

```bash
rtk cargo test --locked -p xtask --test spec_completeness --test schema_validation
rtk cargo run --locked -p xtask -- validate-schemas
rtk cargo test --locked -p ea-format
rtk cargo test --locked -p ea-crypto
rtk pnpm test:golden
rtk cargo fmt --all -- --check
rtk cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
rtk cargo test --workspace --all-targets --locked
rtk pnpm verify:quick
rtk git diff --check
```

If pnpm fails only because the sandbox cannot open its external SQLite package store, rerun the identical command with approved host access and record both outcomes separately.

- [ ] **Step 2: Audit exact scope and forbidden regressions**

Confirm:

```text
no old 13-field Device Certificate accepted
no old 6-field Clock Release accepted
no v2/legacy parser
no ea-time/ea-trust files
no unsafe code
no secret/identifier-bearing errors
no unrelated manifest or schema changes
```

- [ ] **Step 3: Request independent spec and quality/security reviews**

Give reviewers the approved closure design, this plan, exact diff, RED/GREEN evidence, and gate log. Require explicit `CLEAN` or file:line Critical/Important findings. Fix confirmed findings test-first and repeat all affected gates/reviews.

- [ ] **Step 4: Write the ignored report and ledger**

Record each RED, minimal GREEN, literal mutation proof, final counts, review outcomes, exact file scope, and environmental reruns. Do not stage ignored evidence.

- [ ] **Step 5: Make exactly one targeted atomic commit attempt**

Stage the complete atomic scope explicitly:

```bash
rtk git add -- \
  docs/superpowers/plans/2026-08-14-einsatzarchiv-task-8-trust-time-normative-correction.md \
  docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md \
  docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-wire-format-addendum.md \
  docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md \
  docs/superpowers/plans/2026-08-13-einsatzarchiv-v0-1.md \
  docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-5-administration-recovery.md \
  schemas/archive/v1/trust.cddl \
  schemas/reports/v1/local-audit.cddl \
  crates/ea-format/src/etb.rs \
  crates/ea-format/tests/support/mod.rs \
  crates/ea-format/tests/object_roundtrip.rs \
  crates/ea-format/tests/negative.rs \
  crates/ea-crypto/src/cose.rs \
  crates/ea-crypto/src/lib.rs \
  crates/ea-crypto/tests/identity.rs \
  crates/ea-crypto/tests/cose_profile.rs \
  crates/ea-crypto/tests/suite_v1_literal_kats.rs \
  tools/xtask/tests/spec_completeness.rs
rtk git diff --cached --check
rtk git commit -m "fix(core): align trust and clock-release v1 contracts"
```

If linked-worktree `index.lock` permissions block the single stage attempt, do not retry or escalate from a subagent. Hand the exact file list and commit command to the root controller.

## Phase-A Completion Criteria

Phase A is complete only when:

1. The approved closure, main design, addendum, plans, and CDDL say the same thing.
2. `ea-format` and `ea-crypto` accept only the 14-/10-field forms.
3. Previous-head/`+1` and actions 4/6 are covered by executable positives and crossed negatives.
4. A production-byte mutant breaks a pinned literal.
5. Full gates and both independent reviews are clean.
6. The exact atomic commit exists, or the root controller has a precise clean handoff after the single permitted index attempt.
