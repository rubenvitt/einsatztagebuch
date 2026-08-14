# Task 8 Trust Anchors, Registry, and Monotonic Time Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `ea-time` and `ea-trust` so an externally anchored Trust line can be verified historically, a Registry candidate can be selected without self-activating time, independent signed time advances monotonically, and a bound one-use Clock Release can lift only a provable future-skew block.

**Architecture:** `ea-time` is pure checked arithmetic and owns no authority. `ea-trust` owns all opaque proof states, exact Anchor/Trust evaluation, the Previous-Head resolver, phased time/candidate selection, and persistence transaction ports. Exact Trust and local-audit CBOR remain owned by `ea-format`; signature/key operations remain owned by `ea-crypto`. `TrustObjectSource` is read-only and archive-agnostic; Task 9 supplies its `ArchiveInventory` adapter from a higher crate. Independent-time advancement commits immediately after proof verification; candidate floor/head/replay commit atomically only after selection.

**Tech Stack:** Rust 1.95 workspace, `ea-types`, `ea-cbor`, `ea-crypto`, `ea-format`, new `ea-time` and `ea-trust`, deterministic CBOR with `minicbor`, Cargo/xtask/pnpm.

## Hard Prerequisite

Do not begin this plan until the complete plan in
`docs/superpowers/plans/2026-08-14-einsatzarchiv-task-8-trust-time-normative-correction.md`
is committed and all of these are true:

```text
Device Certificate core is exactly 14 fields
Clock Release context is exactly 10 fields
authorization binds Previous Head and Registry event is version +1
actions 4 and 6 admit their exact Registry changes
old 13-/6-field forms are rejected by CDDL, ea-format, and ea-crypto
```

## Dependency Direction

```text
ea-types
  ├── ea-crypto
  ├── ea-time
  └── ea-schema

ea-types + ea-crypto
  └── ea-format

ea-types + ea-crypto + ea-format + ea-time
  └── ea-trust

Task 9 only:
ea-archive + ea-trust
  └── ea-verify::InventoryTrustSource
```

`ea-time` must not depend on `ea-trust`, `ea-format`, or `ea-crypto`. `ea-trust` must not depend on `ea-archive`, storage engines, server code, CLI code, or UI code.

## Global Constraints

- Work only in `.worktrees/einsatzarchiv-v0-1`; follow `/Users/rubeen/.codex/RTK.md` and use `rtk`.
- Use strict RED → minimal GREEN → refactor. Record every first failure and final exact count.
- Use `apply_patch` for edits. Preserve unrelated changes.
- No public proof-state constructors from raw time, role, capability, hash, or free-form metadata.
- `VerifiedSignedTime`, `VerifiedAdminAuthorization`, `PreexistingRegistryAuthority`, `PendingFutureSuccessor`, `AdvancedRegistryHead`, `RegistryCandidate`, `VerifiedClockRelease`, `PreexistingEffectiveNow`, `SelectedRegistryHead`, and `VerifiedTrust` expose getters only. None implements `Default` or deserialization. `PendingFutureSuccessor`, `AdvancedRegistryHead`, `RegistryCandidate`, `VerifiedClockRelease`, and `LocalTimeBlock` do not implement `Clone` or `Copy`.
- A Registry candidate's own `issuedAt`/`notBefore` never contributes to the time used to activate it.
- Registry times may raise the general floor only after selection; they never become an independent-time reference.
- A newly verified Receipt/Checkpoint/TSA reference and its floor increase persist atomically immediately, even if later Registry candidate evaluation fails.
- A Clock Release lifts only `FutureSkew::Blocked`; it cannot lift stale Registry, sequence lease, `notBefore`, signature, authorization-time, fork, rollback, or policy failures.
- Replay uniqueness is persistent under `(organizationId, targetDeviceId, nonce)`, not memory-only.
- All arithmetic uses checked operations. No saturating time/version/sequence arithmetic.
- Trust discovery is version-bounded by `MAX_TRUST_OBJECTS_V1 = 65_536` and
  `MAX_TOTAL_TRUST_OBJECT_BYTES_V1 = 268_435_456`. Hash enumeration is
  visitor-based; the official source and `ea-trust` enforce the count before
  growth, and `ea-trust` uses `checked_add` on exact unique ETB lengths before
  decoding or `before retention`.
- All errors have stable static codes and optional static field labels only. Debug/Display must not expose exact bytes, hashes, IDs, nonces, certificate material, or audit justification data.
- TSA tag 2 is public-runtime fail-closed in Task 8. Stage 6 must first add a lower-layer opaque `ea_crypto::VerifiedTsaEvidence` produced by full RFC-3161 validation; only then may a separately reviewed `ea-trust` adapter derive a TSA `VerifiedSignedTime`. No callback returning raw `UnixMillis` is allowed.
- No new external dependency is needed. Every new Cargo dependency must use `workspace = true`.
- Do not stage `.superpowers/`, `target/`, or `node_modules/`.

## Mandatory Intermediate-Commit Gate

Every Task 2–12 commit boundary must leave both new crates buildable and all
then-existing targets warning-free. Immediately before the task-specific
`rtk git add`, run:

```bash
rtk cargo test --locked -p ea-time -p ea-trust
rtk cargo clippy --locked -p ea-time -p ea-trust --all-targets --all-features -- -D warnings
rtk cargo fmt --all -- --check
```

When a task changes `ea-format`, also run its complete test and all-target
Clippy suites before staging. Do not commit a slice while a later-task test has
already been added and remains RED; introduce each executable contract test in
the task that makes it GREEN.

## Stable Public Proof Flow

```rust
let anchor = decode_trust_anchor(exact_anchor_bytes)?;
let snapshot = load_trust_state(store, state_key)?;
let trust = verify_trust(&anchor, source, snapshot)?;
let candidate = verify_registry_candidate(&trust, proposed_sequence)?;
let signed_times = match candidate.preexisting_authority() {
    Some(authority) => vec![
        verify_receipt_time(authority, receipt)?,
        verify_checkpoint_time(authority, checkpoint)?,
    ],
    None => Vec::new(), // bootstrap has no previously selected Registry authority
};
let local_time = prepare_local_time(store, &candidate, os_wall_clock, &signed_times)?;
let release = exact_audit_bytes
    .map(|bytes| verify_clock_release(&candidate, &mut local_time, bytes))
    .transpose()?;
let outcome = select_registry_head(candidate, local_time, release)?;
```

`RegistrySelectionOutcome::Selected` is the only operation-authorizing result.
`Advanced` means an intermediate Head was atomically committed but still does
not cover the proposed sequence; it exposes no Resolver/capability authority
and requires a full reload/next iteration. A `PendingFuture` outcome may be
consumed only by the separately specified current-Head fallback flow after
reloading state; it is never permission to skip or ignore the direct successor.
The exact API may use associated service methods to carry configuration, but it
must preserve this order and proof ownership.

## Stable Error Families

At minimum expose separate code-only variants/codes for:

```text
EA-TIME-OVERFLOW
EA-TRUST-SOURCE
EA-TRUST-SOURCE-COUNT-LIMIT
EA-TRUST-SOURCE-BYTE-LIMIT
EA-TRUST-ANCHOR-SHAPE
EA-TRUST-ANCHOR-HASH
EA-TRUST-ANCHOR-PIN
EA-TRUST-BOOTSTRAP-PAIR
EA-TRUST-SIGNATURE
EA-TRUST-SIGNER-INACTIVE
EA-TRUST-SUBJECT-MISMATCH
EA-TRUST-SELF-AUTHORIZATION
EA-TRUST-AUTH-REPLAY
EA-TRUST-AUTH-NOT-YET-VALID
EA-TRUST-AUTH-EXPIRED
EA-TRUST-REGISTRY-GAP
EA-TRUST-REGISTRY-FORK
EA-TRUST-REGISTRY-ROLLBACK
EA-TRUST-REGISTRY-OVERFLOW
EA-TRUST-REGISTRY-PREVIOUS
EA-TRUST-ACTION-MISMATCH
EA-TRUST-ACTIVATION-MISSING
EA-TRUST-ACTIVATION-HEAD
EA-TRUST-POLICY-MISMATCH
EA-TRUST-SEQUENCE-LEASE
EA-TRUST-PENDING-FUTURE
EA-TRUST-SUCCESSOR-READY
EA-TRUST-STALE
EA-TRUST-FUTURE-SKEW
EA-TRUST-TIME-SOURCE-UNSUPPORTED
EA-TRUST-CLOCK-RELEASE-MISMATCH
EA-TRUST-CLOCK-RELEASE-EXPIRED
EA-TRUST-CLOCK-RELEASE-REPLAY
EA-TRUST-STATE-CONFLICT
EA-TRUST-STATE-MONOTONICITY
EA-TRUST-STATE-UNAVAILABLE
```

---

### Task 1: Scaffold the two crates and capture genuine contract REDs

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `crates/ea-time/Cargo.toml`
- Create: `crates/ea-time/src/lib.rs`
- Create: `crates/ea-trust/Cargo.toml`
- Create: `crates/ea-trust/src/lib.rs`
- Modify: `tools/xtask/tests/workspace.rs`

- [ ] **Step 1: Capture the missing-package RED before adding files**

Run:

```bash
rtk cargo test --locked -p ea-time -p ea-trust
```

Expected: exit 101 because neither package exists. Record this as RED 1.

- [ ] **Step 2: Add the workspace-membership test and capture its RED**

Before creating either manifest, require both exact member paths and local
workspace dependency entries in `tools/xtask/tests/workspace.rs`. Run:

```bash
rtk cargo test --locked -p xtask --test workspace
```

Expected: the new assertions fail while all prior workspace assertions pass.

- [ ] **Step 3: Add only workspace membership/manifests/empty libraries**

Use workspace dependencies only:

```toml
# ea-time
ea-types.workspace = true

# ea-trust
ea-cbor.workspace = true
ea-crypto.workspace = true
ea-format.workspace = true
ea-time.workspace = true
ea-types.workspace = true
minicbor.workspace = true
```

Add `ea-time` and `ea-trust` to the workspace member/dependency lists and create
empty `#![forbid(unsafe_code)]` libraries. Update the lockfile offline.

- [ ] **Step 4: Run the scaffold GREEN**

Run:

```bash
rtk cargo test --locked -p xtask --test workspace
rtk cargo test --locked -p ea-time -p ea-trust
```

Expected: workspace contract and both intentionally empty libraries pass. The
first compile RED for each real public contract is written in its own task, so
no broad end-state test keeps intermediate commits permanently red.

Do not commit the empty skeleton separately.

---

### Task 2: Implement pure monotonic-time arithmetic in `ea-time`

**Files:**
- Create: `crates/ea-time/src/model.rs`
- Create: `crates/ea-time/src/evaluate.rs`
- Create: `crates/ea-time/src/error.rs`
- Modify: `crates/ea-time/src/lib.rs`
- Create: `crates/ea-time/tests/reference_order.rs`
- Create: `crates/ea-time/tests/effective_now.rs`

- [ ] **Step 1: Write the full arithmetic RED table**

Test:

```text
largest verifiedTime wins
equal time: smaller kind tag wins (Receipt < Checkpoint < TSA)
equal time/tag: bytewise smaller objectHash wins
persisted newer reference is retained
newer reference raises both reference and general floor
Registry floor raises only general floor
OS below floor returns rawNow=floor plus ClockRollback warning
no independent reference returns UnprovableWithoutIndependentReference warning/state
OS below floor with no reference reports both warnings simultaneously
OS exactly reference+limit is WithinLimit
OS one millisecond above is Blocked
checked_add overflow returns EA-TIME-OVERFLOW
```

- [ ] **Step 2: Run focused RED**

Run:

```bash
rtk cargo test --locked -p ea-time --test reference_order --test effective_now
```

Expected: compile/behavior failure.

- [ ] **Step 3: Implement only non-authoritative value types and arithmetic**

Use:

```rust
#[repr(u8)]
pub enum IndependentTimeKind { Receipt = 0, Checkpoint = 1, Tsa = 2 }

pub struct IndependentTimeInput {
    kind: IndependentTimeKind,
    object_hash: ObjectHash,
    verified_time: UnixMillis,
}

pub struct IndependentTimeReference { /* private fields + getters */ }
pub struct TrustedTimeState { /* private floor/reference + validated storage conversion */ }
pub struct TimeAdvance { state: TrustedTimeState, changed: bool }
pub struct TimeWarnings {
    clock_rollback: bool,
    independent_time_unavailable: bool,
}
pub enum FutureSkew { WithinLimit, UnprovableWithoutIndependentReference, Blocked }
pub struct TimeEvaluation { /* private raw_now/warnings/future_skew + getters */ }
```

Because `IndependentTimeInput` is deliberately non-authoritative arithmetic
input, it has a public `new(kind, object_hash, verified_time)` constructor.
`TrustedTimeState` has only validated `initial(floor)` and
`from_persisted(floor, Option<IndependentTimeInput>) -> Result<_, TimeError>`
constructors, plus read-only floor/reference getters. This lets an external
store reconstruct persistence data without gaining an `ea-trust` proof; the
private `IndependentTimeReference` is canonicalized inside `ea-time`. None of
these APIs creates authority.

Public functions:

```rust
pub fn merge_independent_references(
    persisted: &TrustedTimeState,
    verified_inputs: &[IndependentTimeInput],
) -> Result<TimeAdvance, TimeError>;

pub fn evaluate_preexisting_time(
    os_wall_clock: UnixMillis,
    state: &TrustedTimeState,
    max_future_clock_skew_ms: u64,
) -> Result<TimeEvaluation, TimeError>;

pub fn advance_registry_floor(
    state: &TrustedTimeState,
    issued_at: UnixMillis,
    not_before: UnixMillis,
) -> TrustedTimeState;
```

`IndependentTimeInput` is arithmetic input, not a trust proof; document that only `ea-trust` may derive it from verified evidence in production.

- [ ] **Step 4: Run GREEN and quality gates**

```bash
rtk cargo test --locked -p ea-time
rtk cargo clippy --locked -p ea-time --all-targets --all-features -- -D warnings
rtk cargo fmt --all -- --check
```

- [ ] **Step 5: Commit the pure time slice**

```bash
rtk git add -- Cargo.toml Cargo.lock tools/xtask/tests/workspace.rs \
  crates/ea-time crates/ea-trust/Cargo.toml crates/ea-trust/src/lib.rs
rtk git diff --cached --check
rtk git commit -m "feat(time): evaluate monotonic trusted time"
```

Include the empty `ea-trust` skeleton only if required for workspace consistency.

---

### Task 3: Give `ea-trust` typed exact-format views instead of a second CBOR parser

**Files:**
- Create: `crates/ea-format/src/trust_view.rs`
- Create: `crates/ea-format/src/local_audit.rs`
- Modify: `crates/ea-format/src/lib.rs`
- Modify: `crates/ea-format/src/etb.rs`
- Modify: `crates/ea-format/src/ecp.rs`
- Modify: `crates/ea-format/tests/object_roundtrip.rs`
- Create: `crates/ea-format/tests/local_audit.rs`

- [ ] **Step 1: Add external read-API REDs**

From integration tests, decode exact `.etb` values and inspect every Task-8
field without reparsing CBOR. Decode Standard, Timestamp, and Renewal `.ecp`
fixtures; inspect every typed Checkpoint/Renewal field plus exact core, COSE,
and RFC-3161 byte regions. Decode an exact Clock Release audit wrapper and
inspect its core, signature bytes, bound IDs/hashes, nonce, and ten context
fields. Assert every returned exact slice matches the corresponding input byte
region. These assertions must all be present before the RED command, so ETB,
ECP, and Clock-Release view APIs independently fail to compile.

- [ ] **Step 2: Run format RED**

```bash
rtk cargo test --locked -p ea-format --test object_roundtrip --test local_audit
```

Expected: missing typed read APIs.

- [ ] **Step 3: Add an owned typed Trust payload view**

Expose:

```rust
pub struct AuthorizedTrustCoreV1<T> {
    fields: T,
    authorization_object_hash: ObjectHash,
    exact_core: Vec<u8>,
    exact_digest_input: Vec<u8>,
}

impl<T> AuthorizedTrustCoreV1<T> {
    pub fn fields(&self) -> &T;
    pub fn authorization_object_hash(&self) -> ObjectHash;
    pub fn exact_core(&self) -> &[u8];
    pub fn exact_digest_input(&self) -> &[u8];
}

pub enum DecodedTrustPayloadV1 {
    InitialRoot(RootCertificateFieldsV1),
    InitialAdminDevice(DeviceCertificateFieldsV1),
    InitialAdminOperatorBinding(OperatorBindingFieldsV1),
    AuthorizedRoot(AuthorizedTrustCoreV1<RootCertificateFieldsV1>),
    AuthorizedDevice(AuthorizedTrustCoreV1<DeviceCertificateFieldsV1>),
    AuthorizedOperatorBinding(AuthorizedTrustCoreV1<OperatorBindingFieldsV1>),
    OrganizationAdminAuthorization(OrganizationAdminAuthorizationFieldsV1),
    RegistryEvent(AuthorizedTrustCoreV1<RegistryEventFieldsV1>),
    Policy(AuthorizedTrustCoreV1<PolicyFieldsV1>),
    WriterTransition(AuthorizedTrustCoreV1<WriterTransitionFieldsV1>),
    GrantAuthorization(GrantAuthorizationFieldsV1),
    DestructionAuthorization(DestructionAuthorizationFieldsV1),
    DestructionTransition(DestructionTransitionFieldsV1),
    DeletionAttestation(DeletionAttestationFieldsV1),
}

impl TrustObjectV1 {
    pub fn decoded_payload(&self) -> Result<DecodedTrustPayloadV1, FormatError>;
}
```

The parser stays inside `ea-format`, returns typed fields plus exact core/digest input, and preserves existing exact object bytes/hash. Do not expose a generic raw-CBOR decoder.

Also expose a typed Evidence view so `ea-trust` never reparses `.ecp`:

```rust
pub enum DecodedEvidencePayloadV1 {
    Standard {
        core: CheckpointCoreV1,
        exact_cose: Vec<u8>,
    },
    Timestamp {
        core: CheckpointCoreV1,
        exact_cose: Vec<u8>,
        evidence: Rfc3161EvidenceFieldsV1,
    },
    Renewal {
        core: RenewalCoreV1,
        exact_cose: Vec<u8>,
        evidence: Rfc3161EvidenceFieldsV1,
    },
}

impl EvidenceObjectV1 {
    pub fn decoded_payload(&self) -> Result<DecodedEvidencePayloadV1, FormatError>;
}
```

The returned Checkpoint/Renewal cores retain their existing typed fields and
exact core bytes; COSE and RFC-3161 material remain exact owned bytes.

- [ ] **Step 4: Add the narrow Clock Release audit decoder**

Expose the exact closed value/read API:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum IndependentTimeKindV1 { Receipt = 0, Checkpoint = 1, Tsa = 2 }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ClockReleaseJustificationV1 {
    OperatorVerifiedWallClock = 0,
    PlatformTimeSourceRecovery = 1,
    HardwareClockMaintenance = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LocalAuditOutcomeV1 { Failed = 0, Accepted = 1, Completed = 2 }

pub struct IndependentTimeReferenceV1 {
    kind: IndependentTimeKindV1,
    object_hash: ObjectHash,
    verified_time: UnixMillis,
}

impl IndependentTimeReferenceV1 {
    pub fn kind(&self) -> IndependentTimeKindV1;
    pub fn object_hash(&self) -> ObjectHash;
    pub fn verified_time(&self) -> UnixMillis;
}

pub struct ClockReleaseContextV1 {
    trusted_time_floor: UnixMillis,
    observed_os_wall_clock: UnixMillis,
    max_future_clock_skew_ms: u64,
    registry_version: RegistryVersion,
    registry_head_hash: ObjectHash,
    guard_policy_object_hash: ObjectHash,
    independent_reference: IndependentTimeReferenceV1,
    justification: ClockReleaseJustificationV1,
    issued_at: UnixMillis,
    expires_at: UnixMillis,
}

impl ClockReleaseContextV1 {
    pub fn trusted_time_floor(&self) -> UnixMillis;
    pub fn observed_os_wall_clock(&self) -> UnixMillis;
    pub fn max_future_clock_skew_ms(&self) -> u64;
    pub fn registry_version(&self) -> RegistryVersion;
    pub fn registry_head_hash(&self) -> ObjectHash;
    pub fn guard_policy_object_hash(&self) -> ObjectHash;
    pub fn independent_reference(&self) -> &IndependentTimeReferenceV1;
    pub fn justification(&self) -> ClockReleaseJustificationV1;
    pub fn issued_at(&self) -> UnixMillis;
    pub fn expires_at(&self) -> UnixMillis;
}

pub struct ClockReleaseAuditV1 {
    event_id: EventId,
    organization_id: OrganizationId,
    target_device_id: DeviceId,
    admin_operator_binding_object_hash: ObjectHash,
    signer_certificate_object_hash: ObjectHash,
    outcome: LocalAuditOutcomeV1,
    effective_now: UnixMillis,
    context: ClockReleaseContextV1,
    nonce: [u8; 32],
    exact_core: Vec<u8>,
    exact_cose: Vec<u8>,
    signature: Vec<u8>,
}

impl ClockReleaseAuditV1 {
    pub fn event_id(&self) -> EventId;
    pub fn organization_id(&self) -> OrganizationId;
    pub fn target_device_id(&self) -> DeviceId;
    pub fn admin_operator_binding_object_hash(&self) -> ObjectHash;
    pub fn signer_certificate_object_hash(&self) -> ObjectHash;
    pub fn outcome(&self) -> LocalAuditOutcomeV1;
    pub fn effective_now(&self) -> UnixMillis;
    pub fn context(&self) -> &ClockReleaseContextV1;
    pub fn nonce(&self) -> &[u8; 32];
    pub fn exact_core(&self) -> &[u8];
    pub fn exact_cose(&self) -> &[u8];
    pub fn signature_bytes(&self) -> &[u8];
}

pub fn decode_clock_release_audit(
    exact_bytes: &[u8],
) -> Result<ClockReleaseAuditV1, FormatError>;
```

Require exact wrapper `[core, COSE_Sign1]`, action 6, closed outcome 0–2,
non-null Binding, empty critical extensions, exact single CBOR item, and the
corrected 10-field context. Structural COSE parsing may delegate to `ea-crypto`;
signature authority and the Runtime requirement Outcome 1 are not decided here.

- [ ] **Step 5: Run full format GREEN and commit**

```bash
rtk cargo test --locked -p ea-format
rtk cargo clippy --locked -p ea-format --all-targets --all-features -- -D warnings
rtk git add -- crates/ea-format/src/ecp.rs crates/ea-format/src/etb.rs \
  crates/ea-format/src/trust_view.rs crates/ea-format/src/local_audit.rs \
  crates/ea-format/src/lib.rs crates/ea-format/tests/object_roundtrip.rs \
  crates/ea-format/tests/local_audit.rs
rtk git diff --cached --check
rtk git commit -m "feat(format): expose typed trust and clock-release views"
```

---

### Task 4: Implement exact Anchor decoding and a Trust-object catalog

**Files:**
- Create: `crates/ea-trust/src/error.rs`
- Create: `crates/ea-trust/src/source.rs`
- Create: `crates/ea-trust/src/catalog.rs`
- Create: `crates/ea-trust/src/anchor.rs`
- Create: `crates/ea-trust/src/state.rs`
- Modify: `crates/ea-trust/src/lib.rs`
- Create: `crates/ea-trust/tests/bootstrap.rs`

- [ ] **Step 1: Add exact Anchor/source REDs**

Pin complete Pre-Anchor and final Anchor hex fixtures. Mutate every shared field, bootstrap hash, Root key/thumbprint/object hash, sorted Admin certificate list, sorted Binding list, list count, duplicate, critical extensions, trailing byte, and source lookup hash.

Also pin `MAX_TRUST_OBJECTS_V1 = 65_536` and
`MAX_TOTAL_TRUST_OBJECT_BYTES_V1 = 268_435_456`. The source table must prove
the exact count and aggregate-byte boundaries, `checked_add` overflow, distinct
`EA-TRUST-SOURCE-COUNT-LIMIT` / `EA-TRUST-SOURCE-BYTE-LIMIT` errors, no object
read after a count failure, and byte failure before decode or retention.

Inside `catalog.rs`, add a crate-private table-driven unit test named
`trust_catalog_source_attacks_are_closed`. Its fake source returns duplicate
hashes, unsorted hashes, missing bytes, non-ETB bytes, and bytes whose actual
`object_hash` differs from the requested key. Keep `TrustCatalog` crate-private;
do not publish an intermediate catalog API merely for an integration test.

- [ ] **Step 2: Run RED**

```bash
rtk cargo test --locked -p ea-trust --test bootstrap
rtk cargo test --locked -p ea-trust --lib catalog::tests::trust_catalog_source_attacks_are_closed -- --exact --nocapture
```

Expected: missing APIs.

- [ ] **Step 3: Implement the read-only source seam**

```rust
pub trait TrustObjectSource {
    fn visit_trust_object_hashes(
        &self,
        visitor: &mut dyn FnMut(ObjectHash) -> Result<(), TrustSourceError>,
    ) -> Result<(), TrustSourceError>;

    fn read_exact_trust_object(
        &self,
        object_hash: ObjectHash,
    ) -> Result<Option<Arc<[u8]>>, TrustSourceError>;
}
```

The official `ArchiveInventory` adapter invokes the visitor directly while it
scans its bounded Trust index and stops before the next item when the visitor
returns an error; it does not first assemble another unbounded hash `Vec`.
`TrustCatalog::load` collects at most `MAX_TRUST_OBJECTS_V1`, sorts returned
hashes, rejects duplicate/conflicting declarations rather than silently
choosing, and reads each exact object once. It adds each unique exact byte
length with `checked_add`, requires the sum to remain at most
`MAX_TOTAL_TRUST_OBJECT_BYTES_V1` before retention, checks actual `object_hash`
against the lookup key, calls `ea_format::decode_exact_object`, requires ETB,
and indexes by subtype/hash. It never trusts filenames or source order.

Define the complete storage port and validated snapshot needed by the stable
public flow now, before `verify_trust` is introduced:

```rust
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TrustStateKey {
    pub organization_id: OrganizationId,
    pub device_id: DeviceId,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RegistryHeadPin {
    registry_version: RegistryVersion,
    registry_head_hash: ObjectHash,
}

pub struct PersistedTrustRecord {
    revision: u64,
    trusted_time: TrustedTimeState,
    pinned_head: Option<RegistryHeadPin>,
}

pub struct TrustStateSnapshot { /* private key + validated record */ }

pub struct ClockReleaseReplayKey {
    organization_id: OrganizationId,
    target_device_id: DeviceId,
    nonce: [u8; 32],
}

pub struct IndependentTimeCommit {
    next_trusted_time: TrustedTimeState,
}

pub struct RegistrySelectionCommit {
    next_trusted_time: TrustedTimeState,
    next_head: RegistryHeadPin,
    replay_key: Option<ClockReleaseReplayKey>,
}

pub enum StateStoreError {
    Conflict,
    ReplayAlreadyConsumed,
    MonotonicityViolation,
    Unavailable,
}

pub trait TrustStateStore {
    fn load(&mut self, key: TrustStateKey)
        -> Result<PersistedTrustRecord, StateStoreError>;
    fn commit_independent_time(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError>;
    fn clock_release_consumed(
        &mut self,
        key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError>;
    fn commit_registry_selection(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError>;
}

pub fn load_trust_state(
    store: &mut dyn TrustStateStore,
    key: TrustStateKey,
) -> Result<TrustStateSnapshot, TrustError>;
```

The persistence value types are publicly usable without becoming authority
proofs:

```rust
impl RegistryHeadPin {
    pub fn new(registry_version: RegistryVersion, registry_head_hash: ObjectHash) -> Self;
    pub fn registry_version(&self) -> RegistryVersion;
    pub fn registry_head_hash(&self) -> ObjectHash;
}

impl PersistedTrustRecord {
    pub fn new(
        revision: u64,
        trusted_time: TrustedTimeState,
        pinned_head: Option<RegistryHeadPin>,
    ) -> Self;
    pub fn revision(&self) -> u64;
    pub fn trusted_time(&self) -> &TrustedTimeState;
    pub fn pinned_head(&self) -> Option<&RegistryHeadPin>;
}

impl ClockReleaseReplayKey {
    pub fn organization_id(&self) -> OrganizationId;
    pub fn target_device_id(&self) -> DeviceId;
    pub fn nonce(&self) -> &[u8; 32];
}

impl IndependentTimeCommit {
    pub fn next_trusted_time(&self) -> &TrustedTimeState;
}

impl RegistrySelectionCommit {
    pub fn next_trusted_time(&self) -> &TrustedTimeState;
    pub fn next_head(&self) -> &RegistryHeadPin;
    pub fn replay_key(&self) -> Option<&ClockReleaseReplayKey>;
}
```

`TrustStateSnapshot` itself has no public constructor: only
`load_trust_state` can bind a key to a validated persisted record.

`ClockReleaseReplayKey` is declared with private fields in this state module.
All replay/commit DTOs expose public read-only getters for external store
implementations, but Task 4 deliberately adds no unused private constructor:
Task 9 introduces `IndependentTimeCommit` construction at its first production
use, Task 10 introduces the replay-key constructor from verified audit fields,
and Task 11 introduces `RegistrySelectionCommit` construction. Those
constructors remain crate-private. Snapshot construction validates key/record
relationships but does not confer Trust; `verify_trust`/Task 7 must correlate
any pin with the exact verified Registry line. Task 9 supplies transactional
behavior tests and the production orchestration over this already-compilable
port.

- [ ] **Step 4: Implement exact final-Anchor verification**

```rust
pub fn decode_trust_anchor(exact_bytes: &[u8]) -> Result<TrustAnchorV1, TrustError>;
```

Validate deterministic CBOR/exact-one item, fixed domain/version, closed empty extensions, sorted unique nonempty lists of equal length and at least two. Reconstruct the exact Pre-Anchor array from the final Anchor's shared fields, recompute `bootstrap_anchor_hash`, recompute Root thumbprint from exact COSE_Key, and compute final `trust_anchor_hash`. Preserve exact final bytes. Never accept an Anchor extracted from the archive source as implicit authority.

- [ ] **Step 5: Run GREEN and commit**

```bash
rtk cargo test --locked -p ea-trust --test bootstrap
rtk cargo test --locked -p ea-trust --lib catalog::tests::trust_catalog_source_attacks_are_closed -- --exact --nocapture
rtk cargo clippy --locked -p ea-trust --all-targets --all-features -- -D warnings
rtk git add -- crates/ea-trust/src/error.rs crates/ea-trust/src/source.rs \
  crates/ea-trust/src/catalog.rs crates/ea-trust/src/anchor.rs \
  crates/ea-trust/src/state.rs crates/ea-trust/src/lib.rs \
  crates/ea-trust/tests/bootstrap.rs
rtk git diff --cached --check
rtk git commit -m "feat(trust): verify external anchors and trust objects"
```

---

### Task 5: Verify Anchor bootstrap Admin pairs and establish Previous-Head state

**Files:**
- Modify: `crates/ea-crypto/src/cose.rs`
- Modify: `crates/ea-crypto/tests/identity.rs`
- Create: `crates/ea-trust/src/certificate.rs`
- Create: `crates/ea-trust/src/operator_binding.rs`
- Create: `crates/ea-trust/src/resolver.rs`
- Modify: `crates/ea-trust/src/anchor.rs`
- Modify: `crates/ea-trust/src/lib.rs`
- Modify: `crates/ea-trust/tests/bootstrap.rs`
- Create: `crates/ea-trust/tests/certificate_attacks.rs`

- [ ] **Step 1: Add bootstrap identity REDs**

Required positive: two Root-signed, Anchor-pinned Admin Device Certificate/Operator Binding pairs with distinct `authoritySubjectId` values and exact certificate-hash pairing.

The complete bootstrap independence rule is: `pairwise distinct Admin
certificate signing-key thumbprints`, `pairwise distinct OS-account binding
hashes`, and `pairwise distinct operator-instance-key thumbprints`; within each
pair the `operator-instance-key thumbprint differs from its own Admin
certificate signing-key thumbprint`. Shared hardware is permitted, so
`deviceId values need not be distinct`. Every negative must re-sign and re-pin
the otherwise valid pair so the semantic independence check is reached.

First add a lower-layer crypto RED proving that the existing authorized-wrapper
path cannot sign or verify either direct Bootstrap exception. Require
`CoseSigner::sign_initial_admin_trust_digest` and
`VerificationContext::initial_admin_trust_digest` to share the private
`initial_admin_trust_bindings` parser. It accepts only a
`direct initial Admin Device Certificate or Operator Binding`, derives the
exact Trust digest, organization and effective sequence, binds the supplied
Root certificate hash, and uses `RegistryVersion::new(0)` exactly `without an
organizationAdminAuthorization wrapper`. Crossed subtype/kind/role, an
authorized wrapper, another direct Trust form, wrong certificate hash and
signature mutation must fail independently.

Required negatives:

```text
unpinned Root/Admin/Binding
Root key/thumbprint/object-hash mismatch
one Admin pair only
two certificates with the same authoritySubjectId
null Admin authoritySubjectId
Admin authoritySubjectId != Binding operatorSubjectId
Binding points at another certificate
wrong organization/certificate kind/Binding role
Admin certificate missing organizationAdminApprove capability
wrong OS-account or operator-instance-key binding
certificate/binding not effective at sequence 0
non-Root initial signature profile
```

- [ ] **Step 2: Run RED**

```bash
rtk cargo test --locked -p ea-trust --test bootstrap --test certificate_attacks
```

- [ ] **Step 3: Implement verified bootstrap state**

Create private typed `ActiveCertificate`, `ActiveOperatorBinding`, `RootAuthority`, and `PreviousHeadState`. Use `ea-crypto` for exact signatures/keys and `ea-format` typed fields for semantic correlation. Compare authority/operator IDs bytewise. Pair Anchor lists through `operatorBinding.device_certificate_hash`, not list position alone.

The initial Admin signatures use the standard `CoseVerifier` with
`VerificationContext::initial_admin_trust_digest` and a Root-only immutable
resolver. The lower layer validates the direct exception and COSE signature;
`ea-trust` must not parse or verify COSE a second time.

Expose only:

```rust
pub struct VerifiedTrust { inner: Arc<VerifiedTrustInner> }

pub fn verify_trust(
    anchor: &TrustAnchorV1,
    source: &dyn TrustObjectSource,
    snapshot: TrustStateSnapshot,
) -> Result<VerifiedTrust, TrustError>;
```

At this slice the result contains the Anchor-verified catalog/bootstrap basis
and owns the exact state key/revision/time/pin snapshot. It must not mark any
prepared but unactivated object active. Task 7 correlates a non-null pin to the
verified Registry line before it can become signer/time authority.

- [ ] **Step 4: Implement the crypto resolver adapter**

`PreviousHeadResolver` implements `ea_crypto::SignerCertificateResolver` only from immutable pre-transition state. It resolves exact certificate bytes and effective/revoked/root-line disposition at a supplied sequence. It cannot see the object being activated.

- [ ] **Step 5: Run GREEN and commit**

```bash
rtk cargo test --locked -p ea-trust --test bootstrap --test certificate_attacks
rtk cargo test --locked -p ea-crypto --test identity
rtk git add -- crates/ea-crypto/src/cose.rs crates/ea-crypto/tests/identity.rs \
  crates/ea-trust/src/certificate.rs \
  crates/ea-trust/src/operator_binding.rs crates/ea-trust/src/resolver.rs \
  crates/ea-trust/src/anchor.rs crates/ea-trust/src/lib.rs \
  crates/ea-trust/tests/bootstrap.rs crates/ea-trust/tests/certificate_attacks.rs
rtk git diff --cached --check
rtk git commit -m "feat(trust): verify bootstrap admin authority"
```

---

### Task 6: Verify Admin authorizations historically and reject self-authorization

**Files:**
- Modify: `Cargo.lock`
- Modify: `crates/ea-trust/Cargo.toml`
- Create: `crates/ea-trust/src/admin_authorization.rs`
- Modify: `crates/ea-trust/src/error.rs`
- Modify: `crates/ea-trust/src/resolver.rs`
- Modify: `crates/ea-trust/src/lib.rs`

- [ ] **Step 1: Add exact crate-private Admin authorization REDs**

Place one table-driven unit test named
`admin_authorization_historical_matrix_is_closed` inside
`src/admin_authorization.rs`. The proof constructor remains crate-private, so
do not create an integration-test-only public entry point merely for this
slice. Task 7 adds the public end-to-end Registry attack tests.

The test fixture uses `ed25519-dalek` as a dev-only dependency to construct
cryptographically coherent wrong-role and wrong-semantics signatures without
adding a raw signing escape hatch to the production `ea-crypto` API.

Test Root-only, Admin-only, wrong core hash, wrong action/subtype, mismatched certificate/key/Binding, inactive/revoked signer, repeated authorization ID, repeated nonce, different IDs with same nonce, self-admin issue/revoke, and two certificates for one authority subject.

Boundary table for activation event time:

```text
event.issuedAt == authorization.issuedAt -> accepted
event.issuedAt == authorization.expiresAt -> accepted
one millisecond before -> EA-TRUST-AUTH-NOT-YET-VALID
one millisecond after -> EA-TRUST-AUTH-EXPIRED
authorization.issuedAt >= authorization.expiresAt -> invalid shape
```

- [ ] **Step 2: Run RED**

```bash
rtk cargo test --locked -p ea-trust --lib admin_authorization::tests::admin_authorization_historical_matrix_is_closed -- --exact --nocapture
```

- [ ] **Step 3: Implement opaque authorization proof**

```rust
pub struct VerifiedAdminAuthorization {
    inner: VerifiedAuthorizationInner,
}
```

Only a private verifier constructs it after exact object hash, Root/COSE signature, active Admin certificate, active matching Binding, capability/role, authority subject, action, target subtype, authorized core hash, previous Registry version/head, ID/nonce uniqueness, and inclusive use-time checks. Store the bound previous head and signer authority subject privately.

For Admin certificate Effect 0/1, require target authority subject to differ from the signer's active authority subject. Change 1 must never target an Admin certificate.

- [ ] **Step 4: Run GREEN and commit**

```bash
rtk cargo test --locked -p ea-trust --lib admin_authorization::tests::admin_authorization_historical_matrix_is_closed -- --exact --nocapture
rtk git add -- Cargo.lock crates/ea-trust/Cargo.toml \
  crates/ea-trust/src/admin_authorization.rs crates/ea-trust/src/error.rs \
  crates/ea-trust/src/resolver.rs crates/ea-trust/src/lib.rs
rtk git diff --cached --check
rtk git commit -m "feat(trust): verify historical admin authorization"
```

---

### Task 7: Build the complete historical Registry candidate without candidate time

**Files:**
- Create: `crates/ea-trust/src/policy.rs`
- Create: `crates/ea-trust/src/registry.rs`
- Modify: `crates/ea-trust/src/certificate.rs`
- Modify: `crates/ea-trust/src/error.rs`
- Modify: `crates/ea-trust/src/operator_binding.rs`
- Modify: `crates/ea-trust/src/resolver.rs`
- Modify: `crates/ea-trust/src/lib.rs`
- Create: `crates/ea-trust/tests/support/mod.rs`
- Create: `crates/ea-trust/tests/registry_transitions.rs`
- Create: `crates/ea-trust/tests/registry_attacks.rs`

- [ ] **Step 1: Add version/head/lease REDs**

Cover:

```text
auth v0/zero -> event v1/null
auth vN/headN -> event vN+1/headN
same version, gap, overflow, wrong previous
same-version different object hash fork
lower version rollback against persisted pin
transition inside prior lease
transition exactly previous.validThrough+1
larger sequence gap
transition before previous.effectiveFrom
previous.validThrough == u64::MAX does not trigger an overflowing eager +1
current Lease overlaps direct successor and successor.effectiveFrom <= proposed sequence -> singular successor candidate
direct successor.effectiveFrom > proposed sequence -> current-Head operation candidate if covered
intermediate successor.validThrough < proposed sequence -> catch-up candidate that cannot mint operation authority
intermediate successor is returned only as a non-operation RegistryCandidate
```

Advanced, PendingFuture, and Selected outcomes remain Task 11-only. The
expired-intermediate `Advanced -> reload -> Selected` evidence is therefore
tested in Task 11, after those consuming selection types and the atomic commit
path exist. Task 7 proves only the singular structurally verified catch-up
candidate and that it exposes no operation-authorizing candidate-state proof.

Assert Immediate Successor signer state is evaluated at `previous.validThroughSequence`, not the future transition sequence.

Add a prefix-closure attack: H2 is future and rotates Root/Policy/certificate;
H3 is signed under that new state but has an already reached timestamp. The API
must return only singular H2, and H3 cannot be a candidate, Resolver authority,
or time authority until H2 has been selected and persisted.

- [ ] **Step 2: Add the complete action/activation RED matrix**

Test every action 0–6 direct target and exact Registry change. Include actions 4/6, Change 5 Effect 0/1, Change 1 non-Admin-only, direct target without activation, activation under another previous head, wrong target hash, reused authorization, and more than one action class per event.

Pin the Change-1 mapping and cross every tag with every wrong object class:

```text
target-kind 0 = deviceCertificate with CertificateKind Writer, Reader, KeyApprover, RecoveryRecipient, or HistoricalGrantAuthority
target-kind 1 = operatorBinding
target-kind 2 = deviceCertificate with CertificateKind ServerReceipt or DeletionAttest
OrganizationAdmin is invalid under Change 1
```

The referenced object must be active in the unchanged Previous-Head state;
unknown and merely prepared catalog objects are not revocation targets.

- [ ] **Step 3: Add Policy/Root/sequence REDs**

Test Bootstrap Policy version 1/null previous, Policy version `+1`, exact previous policy hash, event policy hash behavior for Change 2 versus all others, equal effective sequence for activated certificate/policy/writer/binding, Root effective Registry version, and active previous Root signing the rotation event.

- [ ] **Step 4: Run RED**

```bash
rtk cargo test --locked -p ea-trust --test registry_transitions --test registry_attacks
```

- [ ] **Step 5: Implement candidate construction**

Expose:

```rust
pub struct PreexistingRegistryAuthority { inner: Arc<PreviousHeadState> }
pub struct RegistryCandidate { inner: RegistryCandidateInner }

pub fn verify_registry_candidate(
    trust: &VerifiedTrust,
    proposed_sequence: ChainSequence,
) -> Result<RegistryCandidate, RegistryError>;
```

`RegistryError` is a distinct public, code-only error type. RegistryError preserves every lower-layer TrustError code losslessly and adds stable Task-7 classes for gap, fork, rollback, version overflow, wrong predecessor, activation, Policy, and sequence-Lease failures. `Display` and `Debug` emit only `code()`; no error contains object bytes, identifiers, keys, nonces, or caller text. Task-11-only PendingFuture/Stale/skew classes are not added here.

Return one singular candidate, never a set. First inspect only the exact direct
Registry successor: Bootstrap Head 1, otherwise version `pinned + 1` with the
pinned Head hash as predecessor. If its `effectiveFromSequence <=
proposed_sequence`, it is the candidate even while the previous Head's Lease
overlaps; this is required so an already applicable revocation, Policy change,
or Root rotation cannot be ignored. The candidate may be an intermediate
catch-up Head whose Lease ends before `proposed_sequence`; after selecting and
persisting it, the caller reloads and evaluates the next direct successor.

Only when no direct successor is sequence-eligible may the already pinned Head
become the current-Head operation candidate, and then it must cover
`proposed_sequence`. Reject gaps/forks/rollback before constructing either
form. Never inspect a later successor.

When a persisted Head exists, replay and verify the Registry prefix through
that exact version/hash, then place the resulting immutable previous-state
resolver in an opaque `PreexistingRegistryAuthority` owned by the candidate.
Expose only `RegistryCandidate::preexisting_authority() ->
Option<&PreexistingRegistryAuthority>`. Bootstrap returns `None`. This proof is
created before applying the candidate transition and can never resolve the
candidate target or any successor.

For that one transition derive `preTransitionSequence`, verify both direct and
event authorizations against the unchanged previous state and common event
`issuedAt`, then apply exactly one change to form the candidate state. Store the
fully resolved exact `(version, head_hash, target_policy, guard_policy)` in the
opaque candidate: previous policy for a transition, initial candidate policy for
Bootstrap, current policy for a current-Head operation.

For Head 1, derive `preTransitionSequence = head1.effectiveFromSequence`; the
external Registry-0 basis has no signed Lease. For later Heads use the closed
within-Lease or exact `previous.validThroughSequence + 1` rule.

`TrustCatalog` has already format-decoded every admitted ETB before Registry
verification. To distinguish a missing direct successor from a later-version
gap or a same-version fork, topology-only lookahead may read only organization, registryVersion, previousRegistryHash, and objectHash. It must not verify a
later signature or Authorization, resolve a later direct target, Policy, or
certificate, apply later state, or inspect later time semantics. Once an exact
direct successor exists, defects in any later topology or semantics cannot
alter that singular candidate. Do not semantically apply a later successor
until this candidate has itself been selected and persisted. Future objects
remain in the catalog only; they provide neither Resolver authority nor signed
time. This makes the Registry line temporally prefix-closed and prevents a
pending Root/Policy/certificate change from authorizing a later Head.

If a direct successor is later proven solely `PendingFuture`, Task 11 may emit
an opaque `PendingFutureSuccessor` bound to that exact successor, previous Head,
post-independent-time state revision, and proposed sequence. A separate
`verify_current_head_fallback(&VerifiedTrust, PendingFutureSuccessor)` consumes
that proof to build a singular current-Head candidate only if the reloaded
snapshot matches and the previous Head still covers the sequence. That fallback
candidate retains the pending successor barrier and must recheck at final
selection that it remains future; if it has become active, the successor wins.
No caller-selectable Current-versus-Successor flag exists.

Correlate `PersistedTrustRecord::pinned_head()`, when present, with one exact
version/hash in the verified line and retain that immutable state only in the
candidate's `PreexistingRegistryAuthority` as the authority basis for
independent Receipt/Checkpoint verification. A missing pin is valid only before
the first selected Head; a foreign, forked, or rolled-back pin is an error.

Do not compare `issuedAt`/`notBefore` to wall clock here and do not update any time floor.

- [ ] **Step 6: Run GREEN and commit**

```bash
rtk cargo test --locked -p ea-trust --test registry_transitions --test registry_attacks
rtk git add -- crates/ea-trust/src/policy.rs crates/ea-trust/src/registry.rs \
  crates/ea-trust/src/certificate.rs crates/ea-trust/src/error.rs \
  crates/ea-trust/src/operator_binding.rs \
  crates/ea-trust/src/resolver.rs crates/ea-trust/src/lib.rs \
  crates/ea-trust/tests/support/mod.rs crates/ea-trust/tests/registry_transitions.rs \
  crates/ea-trust/tests/registry_attacks.rs
rtk git diff --cached --check
rtk git commit -m "feat(trust): verify registry transitions"
```

---

### Task 8: Add candidate-independent verified Receipt/Checkpoint time

**Files:**
- Create: `crates/ea-trust/src/time.rs`
- Modify: `crates/ea-trust/src/error.rs`
- Modify: `crates/ea-trust/src/lib.rs`
- Create: `crates/ea-trust/tests/time_sources.rs`

- [ ] **Step 1: Add signed-time REDs**

Receipt tests: exact `.esr`, active ServerReceipt certificate/capability, organization/Registry binding, digest/signature, server acceptance time, and object hash.

Checkpoint tests: exact standard `.ecp`, active ServerReceipt certificate/capability, organization/Registry/range binding, digest/signature, server checkpoint time, and object hash.

TSA tests: any attempt to use a tag-2 Clock Release reference or timestamp `.ecp`
as Task-8 independent time returns the distinct fail-closed
`EA-TRUST-TIME-SOURCE-UNSUPPORTED`. No test-only public verifier callback or raw
time constructor exists.

Passing Registry-event time as an independent source must be impossible at the type/API boundary.

Both Receipt and Checkpoint signer resolution must use only the candidate's
borrowed `PreexistingRegistryAuthority`, which represents the exact previously
persisted/verified selected Head and cannot resolve candidate state. A
certificate activated only by the candidate must therefore fail and cannot
bootstrap that candidate's time. Bootstrap has no such authority and accepts no
new signed-time proof in this phase.

- [ ] **Step 2: Run RED**

```bash
rtk cargo test --locked -p ea-trust --test time_sources
```

- [ ] **Step 3: Implement opaque signed-time proofs**

```rust
pub struct VerifiedSignedTime {
    input: IndependentTimeInput,
    authority_head: RegistryHeadPin,
}

pub fn verify_receipt_time(
    authority: &PreexistingRegistryAuthority,
    receipt: &Parsed<ReceiptV1>,
) -> Result<VerifiedSignedTime, TrustError>;

pub fn verify_checkpoint_time(
    authority: &PreexistingRegistryAuthority,
    evidence: &Parsed<EvidenceObjectV1>,
) -> Result<VerifiedSignedTime, TrustError>;
```

`VerifiedSignedTime` stores the publicly constructible but explicitly
non-authoritative `ea_time::IndependentTimeInput`; authority comes only from
the private `authority_head` binding and the inaccessible proof constructor.
Receipt/Checkpoint verification resolves signer/capability exclusively through
the exact borrowed `PreexistingRegistryAuthority`. A certificate activated by
the candidate or any successor is rejected and cannot supply time for that
candidate.

Stage 6 later adds an opaque `ea_crypto::VerifiedTsaEvidence` after full
RFC-3161 status/imprint/nonce/policy/genTime/chain/EKU/revocation validation.
Only an `ea-trust` function consuming that lower proof may create a TSA
`VerifiedSignedTime`; this Task-8 plan intentionally exposes no such public path.

- [ ] **Step 4: Run GREEN and commit**

```bash
rtk cargo test --locked -p ea-trust --test time_sources
rtk git add -- crates/ea-trust/src/time.rs crates/ea-trust/src/error.rs \
  crates/ea-trust/src/lib.rs \
  crates/ea-trust/tests/time_sources.rs
rtk git diff --cached --check
rtk git commit -m "feat(trust): verify independent signed time sources"
```

---

### Task 9: Define persistent CAS transactions and commit independent time early

**Files:**
- Modify: `crates/ea-trust/src/state.rs`
- Modify: `crates/ea-trust/src/time.rs`
- Modify: `crates/ea-trust/src/error.rs`
- Modify: `crates/ea-trust/src/lib.rs`
- Modify: `crates/ea-trust/tests/support/mod.rs`
- Create: `crates/ea-trust/tests/state_atomicity.rs`

- [ ] **Step 1: Add independent-time transactional REDs with a deterministic model store**

Test successful load, stale revision CAS, monotonic floor, independent-reference replacement order, write failure before commit, and candidate failure after independent commit. Add explicit conflicts when the store advances between `verify_trust` and `prepare_local_time`, when the pin changes at the same organization/device, and when a different key is supplied. Include an external test implementation of the store trait whose `commit_registry_selection` method compiles using only DTO getters. Actual Head/replay partial-failure and concurrent-consumer behavior is introduced in Task 11, after the production selection path can construct the crate-private DTO.

- [ ] **Step 2: Run RED**

```bash
rtk cargo test --locked -p ea-trust --test state_atomicity
```

- [ ] **Step 3: Implement and test the already declared storage port**

Use the Task-4 port without widening it. Add the crate-private
`IndependentTimeCommit` constructor at this first production call site;
`RegistrySelectionCommit` remains getter-only until Task 11 adds its first
constructor. Verify exact mappings for
`StateStoreError::{Conflict, ReplayAlreadyConsumed, MonotonicityViolation,
Unavailable}`.

Map `ea_time::TimeError::Overflow` losslessly to a narrow
`TrustError::TimeOverflow` whose code remains exactly `EA-TIME-OVERFLOW`.
If evaluation overflows after a successful independent-time CAS, the already
committed reference/floor remains durable; it is not rolled back or collapsed
into a state-error family.

`commit_registry_selection` atomically checks revision, monotonic floor, no
Head rollback/fork, inserts an optional replay key under a unique constraint,
and writes Head pin plus candidate floor.

- [ ] **Step 4: Implement `prepare_local_time`**

```rust
pub struct LocalTimeBlock<'store> { /* non-Clone, exclusive store borrow */ }

pub fn prepare_local_time<'store>(
    store: &'store mut dyn TrustStateStore,
    candidate: &RegistryCandidate,
    os_wall_clock: UnixMillis,
    sources: &[VerifiedSignedTime],
) -> Result<LocalTimeBlock<'store>, TrustError>;
```

The singular candidate privately carries the `TrustStateSnapshot` key, revision,
trusted-time state, and pinned Head used by `verify_trust`. Reload exactly that
key before any arithmetic. Any changed revision, Head pin, organization/device
key, or trusted-time state returns `EA-TRUST-STATE-CONFLICT` and requires a full
proof-flow restart.

Reject any Receipt/Checkpoint proof whose private `authority_head` is not that
same pinned selected Head. Derive arithmetic inputs only after this check, call
`merge_independent_references`, and commit a changed independent reference/floor
immediately. `LocalTimeBlock` adopts only the returned new revision and state.
Evaluate OS/floor/skew under the candidate's already resolved guard Policy, but
do not select or persist candidate times.

- [ ] **Step 5: Run GREEN and commit**

```bash
rtk cargo test --locked -p ea-trust --test state_atomicity
rtk git add -- crates/ea-trust/src/state.rs crates/ea-trust/src/time.rs \
  crates/ea-trust/src/error.rs crates/ea-trust/src/lib.rs \
  crates/ea-trust/tests/support/mod.rs crates/ea-trust/tests/state_atomicity.rs \
  docs/superpowers/plans/2026-08-14-einsatzarchiv-task-8-trust-time-implementation.md
rtk git diff --cached --check
rtk git commit -m "feat(trust): bind verified time to persistent state"
```

---

### Task 10: Verify a bound one-use Clock Release without consuming it early

**Files:**
- Create: `crates/ea-trust/src/clock_release.rs`
- Create: `crates/ea-trust/src/clock_release/tests.rs`
- Modify: `crates/ea-trust/src/error.rs`
- Modify: `crates/ea-trust/src/lib.rs`
- Modify: `crates/ea-trust/src/state.rs`
- Modify: `crates/ea-trust/src/time.rs`
- Modify: `crates/ea-trust/tests/support/mod.rs`
- Create: `crates/ea-trust/tests/clock_release.rs`

- [ ] **Step 1: Add the full Clock Release RED matrix**

Start with one valid exact local-audit object. Mutate independently:

```text
signature/content type/action/outcome
organization or target device
signer certificate or non-null Admin Binding
signer/binding inactive at preTransitionSequence
Registry version or Head hash
guard Policy hash
trusted floor, OS wallclock, skew limit
independent reference kind/hash/time
outer effectiveNow
justification
issued/expires boundaries
nonce replay
release presented when skew is WithinLimit or unprovable
reference tag 2 while Task-8 TSA verification is unavailable
```

Prove a Release cannot be verified from raw context fields without exact signed audit bytes.

- [ ] **Step 2: Run RED**

```bash
rtk cargo test --locked -p ea-trust --test clock_release
```

- [ ] **Step 3: Implement the non-clonable proof**

```rust
pub struct VerifiedClockRelease {
    inner: ClockReleaseProof,
}

pub fn verify_clock_release(
    candidate: &RegistryCandidate,
    local_time: &mut LocalTimeBlock<'_>,
    exact_audit_bytes: &[u8],
) -> Result<VerifiedClockRelease, ClockReleaseError>;
```

Call `ea_format::decode_clock_release_audit`, build the exact `ea_crypto::VerificationContext::local_audit` for OrganizationAdmin at `preTransitionSequence`, and verify through the previous-state resolver. Require exact candidate/head/guard-policy/time/reference/device/Binding/outcome correlations and inclusive `issuedAt <= rawNow <= expiresAt` with strict interval shape. Query `clock_release_consumed` exactly once only after complete decode, COSE, previous-Admin, Binding, semantic, and time verification, immediately before proof construction. It is an early rejection of an already consumed nonce only; Task 10 never persists replay.

Runtime proof creation requires `outcome == 1`; outcomes 0 and 2 remain valid
decoded audit records but cannot mint a Release. Reference tag 0 must match an
exact Receipt proof retained by `LocalTimeBlock`, and tag 1 an exact Checkpoint
proof. Reference tag 2 returns `EA-TRUST-TIME-SOURCE-UNSUPPORTED` until Stage 6
provides the lower opaque TSA proof; no raw timestamp fallback is allowed.

Privately bind every compared value plus replay key and candidate identity into `ClockReleaseProof`. Do not implement `Clone`/`Copy`.

At this first production use, add the crate-private
`ClockReleaseReplayKey::from_verified_audit(...)`; it accepts only fields after
the complete audit verification above. Its public getters remain storage-only.

- [ ] **Step 4: Add compile-fail API evidence**

Rustdoc compile-fail examples must prove:

```text
VerifiedClockRelease cannot be constructed with fields
VerifiedClockRelease cannot be cloned
raw audit bytes cannot be passed where VerifiedClockRelease is required
```

- [ ] **Step 5: Run GREEN and commit**

```bash
rtk cargo test --locked -p ea-trust --test clock_release
rtk cargo test --locked -p ea-trust --doc
rtk git add -- crates/ea-trust/src/clock_release.rs crates/ea-trust/src/clock_release/tests.rs \
  crates/ea-trust/src/error.rs crates/ea-trust/src/lib.rs crates/ea-trust/src/state.rs \
  crates/ea-trust/src/time.rs \
  crates/ea-trust/tests/support/mod.rs crates/ea-trust/tests/clock_release.rs \
  docs/superpowers/plans/2026-08-14-einsatzarchiv-task-8-trust-time-implementation.md
rtk git diff --cached --check
rtk git commit -m "feat(trust): verify one-use clock releases"
```

---

### Task 11: Select and pin a Registry Head atomically

**Files:**
- Modify: `crates/ea-trust/src/registry.rs`
- Modify: `crates/ea-trust/src/state.rs`
- Modify: `crates/ea-trust/src/lib.rs`
- Modify: `crates/ea-trust/tests/registry_attacks.rs`
- Modify: `crates/ea-trust/tests/state_atomicity.rs`
- Create: `crates/ea-trust/tests/head_selection.rs`

- [ ] **Step 1: Add phased-time/self-activation REDs**

Test:

```text
future candidate stays PendingFuture when only its own issuedAt/notBefore would raise floor
pending direct successor stops the temporal prefix; a later Head with earlier time is not considered
an already time-applicable overlapping direct successor wins over the current Head
a solely future overlapping direct successor yields an opaque fallback proof and leaves the covering current Head usable
if time advances before fallback selection, the now-applicable successor wins and current fallback is rejected
new Policy cannot use its own larger skew limit to activate
two overlapping Heads with different skew limits use only the singular candidate's resolved guard Policy
transition uses Previous-Head guard Policy
Bootstrap uses fully verified initial Policy
current-head operation uses current Policy
independent proof advances time and makes a previously pending Head selectable
without independent reference: warning, no provable skew block/release, lease still enforced
OS rollback keeps floor and warning
Registry time never becomes independent reference
stale intermediate Head can be Advanced historically but cannot expose operation authority
```

- [ ] **Step 2: Add atomic selection/replay REDs**

Inject failures before replay insert, after tentative replay insert, and before Head/floor write. Assert no partial candidate floor/head/replay state. Assert the independent reference committed in Task 9 remains after later selection failure. Run two simulated concurrent consumers at the same prior revision; exactly one may commit. Add a second-store-handle race that commits the successor after current-fallback recheck but before compare-and-affirm; the old-Head selection must fail `EA-TRUST-STATE-CONFLICT` and return no proof. Run the same CAS race for an ordinary current-Head operation without a Release.

- [ ] **Step 3: Prove waiver scope is narrow**

With a valid Release, independently retain failures for a stale/expired Head
that would otherwise return `Selected`, exhausted operation sequence lease,
authorization expiry, signature failure, fork, rollback, and candidate
`notBefore`. Only `FutureSkew::Blocked` may change to allowed. Separately prove
that an expired intermediate catch-up can return only `Advanced`, never
`Selected`, with or without a Release.

- [ ] **Step 4: Run RED**

```bash
rtk cargo test --locked -p ea-trust --test head_selection --test state_atomicity --test registry_attacks
```

- [ ] **Step 5: Implement consuming selection**

```rust
pub struct PreexistingEffectiveNow { value: UnixMillis }
pub struct SelectedRegistryHead { inner: Arc<SelectedHeadInner> }
pub struct PendingFutureSuccessor { inner: PendingSuccessorProof }
pub struct AdvancedRegistryHead { inner: CommittedCatchUpProof }

pub enum RegistrySelectionOutcome {
    Selected(SelectedRegistryHead),
    Advanced(AdvancedRegistryHead),
    PendingFuture(PendingFutureSuccessor),
}

pub fn select_registry_head(
    candidate: RegistryCandidate,
    local_time: LocalTimeBlock<'_>,
    release: Option<VerifiedClockRelease>,
) -> Result<RegistrySelectionOutcome, RegistryError>;

pub fn verify_current_head_fallback(
    trust: &VerifiedTrust,
    pending: PendingFutureSuccessor,
) -> Result<RegistryCandidate, RegistryError>;
```

At this first production use, add the crate-private
`RegistrySelectionCommit` constructors for new-Head advancement and
current-Head compare-and-affirm. Neither is publicly callable.

Evaluate only the singular candidate already fixed before `prepare_local_time`;
never select from a set. Require its proposed sequence, preexisting time,
`issuedAt`, `notBefore`, Policy links, and transition sequence rules. An
applicable direct successor always wins over an overlapping current Head. A
direct successor is historical-advance-only when either its Lease does not
cover the eventual operation sequence or current `PreexistingEffectiveNow >
notAfter`. After its atomic commit return only `AdvancedRegistryHead`, which
exposes Head version/hash and committed revision for diagnostics but no
Resolver, Policy, capability, certificate, or operation authority. The caller
must reload and repeat one direct successor at a time. Only a non-stale Head
whose Lease covers `proposed_sequence` may produce `SelectedRegistryHead`.

For such a non-authoritative direct-successor advance, validate the signed
`issuedAt < notAfter`/maximum-age shape and require `issuedAt` plus `notBefore`
to be reached, but do not reject merely because current
`PreexistingEffectiveNow > notAfter`; otherwise an expired intermediate Head
would make a later fresh Head unreachable. This rule does not inspect or assume
that a later successor exists: if none exists, the newly pinned stale Head will
still fail any later current-Head selection. Stale/`notAfter` policy is
evaluated strictly before every `SelectedRegistryHead` (including current
fallback) and can never be waived by a Release. An expired direct successor
remains only `Advanced` and cannot be used for an operation.

When and only when the exact direct successor fails solely because `issuedAt`
or `notBefore` is future, return `PendingFuture(PendingFutureSuccessor)` without
committing candidate time, Head, or replay. Do not return this proof for skew,
stale, lease-gap, signature, policy, authorization, fork, or rollback errors.
The proof is available only if the previous pinned Head still covers the
proposed sequence. Its successors are never inspected.

To continue on that still-valid predecessor, reload state, rebuild
`VerifiedTrust`, consume the pending proof through
`verify_current_head_fallback`, and run a fresh signed-time/local-time/Release
flow for the returned current-Head candidate. Final current-Head selection must
re-evaluate the bound direct successor against the new
`PreexistingEffectiveNow`: if the successor is now active, reject fallback so
the caller evaluates that successor instead. Thus callers cannot choose an old
Head while a higher applicable version exists.

If skew is Blocked, require a Release whose private bindings match this exact
candidate/local block; if skew is WithinLimit, reject an unnecessary Release;
if unprovable, reject a Release and retain the visible warning.

Every successful `SelectedRegistryHead` return must linearize through
`commit_registry_selection` at the `LocalTimeBlock`'s exact expected revision
and pinned Head. Advancing to a new Head first calls `advance_registry_floor`
with its event times, then atomically writes that floor and new Head with an
optional replay key. A normal current-Head operation and a pending-successor
current fallback use the same transaction as compare-and-affirm: Head and floor
remain identical, the revision advances, and an optional separately verified
current-Head Release replay key is inserted atomically. Thus another process
cannot select the successor between fallback recheck and returning an old-Head
proof. Consume candidate, local block, and Release by value. Return getters for
Head/version/Policy/effective range/warnings/resolver only on the `Selected`
variant and only after the required transaction succeeds. `Advanced` has only
the narrow non-authoritative getters above.

- [ ] **Step 6: Run GREEN and commit**

```bash
rtk cargo test --locked -p ea-trust --test head_selection --test state_atomicity --test registry_attacks
rtk git add -- crates/ea-trust/src/registry.rs crates/ea-trust/src/state.rs \
  crates/ea-trust/src/lib.rs crates/ea-trust/tests/registry_attacks.rs \
  crates/ea-trust/tests/state_atomicity.rs crates/ea-trust/tests/head_selection.rs
rtk git diff --cached --check
rtk git commit -m "feat(trust): select and pin registry heads atomically"
```

---

### Task 12: Close downstream resolver and proof-state boundaries

**Files:**
- Modify: `crates/ea-trust/src/resolver.rs`
- Modify: `crates/ea-trust/src/lib.rs`
- Create: `crates/ea-trust/tests/public_api.rs`
- Modify: `tests/ea-system-tests/Cargo.toml`
- Create: `tests/ea-system-tests/tests/task8_trust_time.rs`

- [ ] **Step 1: Add external public-API REDs**

From integration crates, prove a `SelectedRegistryHead` can resolve active Writer/Reader/Admin/Server/Deletion certificates for `ea-crypto`, query active Policy/capability/Binding read-only, and cannot expose mutation APIs or raw authority construction. Prove an `AdvancedRegistryHead` exposes only committed version/hash/revision and cannot resolve any certificate, Policy, Binding, role, capability, or operation authority.

- [ ] **Step 2: Add compile-fail proof barriers**

Cover every opaque type named in Global Constraints. Raw hashes/times/roles/capabilities must fail to compile as proofs.

- [ ] **Step 3: Add the end-to-end Task-8 system fixture**

In `task8_trust_time.rs`, use exact Anchor + ETBs + Receipt/Checkpoint + model store to execute:

```text
Bootstrap -> Head 1 Policy
activate non-Admin Device
activate Operator Binding
Policy transition
Root rotation
immediate lease successor
future Head blocked by independent reference
valid Clock Release selects exact Head once
same audit replay fails
```

Each Registry transition in this fixture is a separate stable proof-flow
iteration: reload the committed snapshot, rebuild `VerifiedTrust`, construct
only the direct singular successor, prepare time, select, and commit before
attempting the next transition. The fixture must never batch later Heads behind
an unselected predecessor.

Add one-byte mutations to Anchor, Admin authorization, direct target, activation event, signed time, and Clock Release. Assert exact error families and unchanged persistent state at each failure boundary.

- [ ] **Step 4: Run focused GREEN**

```bash
rtk cargo test --locked -p ea-trust --test public_api
rtk cargo test --locked -p ea-trust --doc
rtk cargo test --locked -p ea-system-tests --test task8_trust_time
```

- [ ] **Step 5: Commit proof/API closure**

```bash
rtk git add -- crates/ea-trust/src/resolver.rs crates/ea-trust/src/lib.rs \
  crates/ea-trust/tests/public_api.rs tests/ea-system-tests/Cargo.toml \
  tests/ea-system-tests/tests/task8_trust_time.rs
rtk git diff --cached --check
rtk git commit -m "test(core): close Task 8 trust time attacks"
```

---

### Task 13: Full verification, independent reviews, and Task-8 completion

**Files:**
- Review every file changed by Tasks 1–12
- Update ignored evidence: `.superpowers/sdd/2026-08-13-einsatzarchiv-stage-1-trust-core-format/task-8-report.md`
- Update ignored Stage-1 SDD ledger

- [ ] **Step 1: Run all focused and cumulative gates fresh**

```bash
rtk cargo test --locked -p ea-types -p ea-crypto -p ea-format -p ea-schema
rtk cargo test --locked -p ea-time -p ea-trust
rtk cargo test --locked -p ea-system-tests --test task8_trust_time
rtk cargo test --locked -p xtask --test workspace --test schema_validation --test spec_completeness
rtk cargo run --locked -p xtask -- validate-schemas
rtk cargo fmt --all -- --check
rtk cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
rtk cargo test --workspace --all-targets --locked
rtk pnpm test:golden
rtk pnpm test:property
rtk pnpm test:fuzz -- --smoke-seconds 60
rtk pnpm verify:quick
rtk git diff --check
```

Use one process per long gate and wait for its real exit. If only the external pnpm SQLite cache is sandbox-blocked, rerun the identical command with approved host access and record both results separately.

- [ ] **Step 2: Audit dependency, proof, safety, and error surfaces**

Confirm with Cargo tree/source search/rustdoc:

```text
ea-time has only ea-types
ea-trust has no ea-archive/server/CLI/storage-engine dependency
no unsafe code
no public raw proof constructor
VerifiedClockRelease/RegistryCandidate/LocalTimeBlock are non-Clone
no Registry candidate time feeds its own selection time
no Registry time becomes independent reference
all successful selection writes are atomic in the store port
all errors are identifier/nonce/exact-byte free
```

- [ ] **Step 3: Request independent spec and quality/security reviews**

Give reviewers the approved closure design, both implementation plans, exact commit range/diff, RED/GREEN ledger, public rustdoc, and gate log. Reviewers must falsify:

```text
Anchor bootstrap and distinct authority identities
Previous-Head resolver and historical authorization time
complete action/change/policy/sequence matrix
candidate self-time exclusion
independent-time early commit
Clock Release exact binding and replay atomicity
waiver scope
proof-state constructibility
```

Fix every confirmed Critical/Important test-first, rerun affected/full gates, and repeat review until `CLEAN`.

- [ ] **Step 4: Finalize report and ledger**

Record commits, exact test counts, every RED/GREEN, mutant/proof compile-fail evidence, environmental reruns, reviews, remaining Stage-6 TSA production-verifier boundary, and Task-9 `TrustObjectSource` adapter handoff.

- [ ] **Step 5: Verify Git state without deleting workspace data**

Verify tracked status, cached diff, and HEAD. Generated artifacts remain
unstaged and are not part of Task-8 correctness; do not remove user files.

- [ ] **Step 6: Integrate any final uncommitted correction once**

If final review fixes remain, stage only exact reviewed Task-8 files and commit with the narrow message dictated by that fix. If the linked-worktree index is blocked for a subagent, stop after one targeted attempt and hand the exact file list/command to the root controller.

## Task-8 Completion Criteria

Task 8 is complete only when:

1. Phase-A v1 contract alignment is committed and remains green.
2. Anchor/bootstrap, every Registry transition, Policy/sequence correlation, and historical Admin authorization are independently reviewed clean.
3. Candidate construction is time-independent; selection uses only preexisting floor/reference plus OS time.
4. The exact direct successor is considered before an overlapping current Head; a future successor can yield only a bound fallback proof, an active successor cannot be bypassed, and an intermediate catch-up result exposes no operation authority.
5. Independent signed time persists before candidate selection and survives later candidate failure.
6. Clock Release is exact, non-clonable, Head/Policy/reference/device-bound, and persistently one-use.
7. A valid Release cannot bypass any non-skew rule.
8. Task 9 can implement `TrustObjectSource` without a reverse dependency.
9. Full focused/workspace/golden/property/fuzz/format/clippy/quick gates pass.
10. Spec and quality/security reviews are explicitly `CLEAN`.
