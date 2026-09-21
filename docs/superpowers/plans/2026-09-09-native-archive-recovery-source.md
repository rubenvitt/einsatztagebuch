# Native Archive and Recovery Source Implementation Plan

Überholt durch `docs/superpowers/specs/2026-09-21-einsatzarchiv-controlled-network-archive-profile.md` und den DRK-320-Plan vom 2026-09-21.

> **For agentic workers:** Use superpowers:executing-plans after the shared API is agreed. Root's explicit ownership and no-staging/no-commit restrictions apply; this proposal does not authorize new agents or infrastructure.

**Goal:** Give the native Writer and Recovery one correctly bound controlled-network archive resource, including its encrypted local commit source.

**Architecture:** Share resource admission and exact source enumeration in `ea-admin`; keep filesystem/SQLCipher storage primitives in `ea-archive-fs`. Root composes the Writer, startup/publication queue and Desktop; the T9 owner composes capture/restore and the native recovery witnesses. A read source is untrusted input to the existing verifier, never Current/Writer/Admin authority.

**Tech Stack:** Existing Rust native runtime, `ControlledNetworkBackend`, `SqliteCommitStore`, SQLCipher, existing v1 profiles and archive verifier.

**Spec:** `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md` §§9.3–9.4, 11.5, 19.3; `docs/superpowers/plans/2026-09-08-drk-250-runtime-closure.md`; current Task9 brief and Global Constraints.

## Global Constraints

- No profile relabeling, new signing family, Reader private key on Writer, caller readiness boolean or fallback to a different target.
- Both exact remote archive bytes and the entire encrypted local source database are required; pending publication does not make committed local originals disappear.
- Prepared recovery, irreversible draft-key deletion, destruction custody/tombstones, current Trust/Pin/floor and exact original bytes retain their existing gates.
- Source restoration remains an isolated read-only test source. It does not activate a Writer, publish a queue or override current destruction duties.
- Do not change the frozen V4 container while Root's full Desktop run is active. Root controls any separate real network fixture; PG/S3 are not a substitute for a mounted controlled filesystem.

## Existing seams and missing behavior

`RecoveryTestRuntime::new` rejects `ControlledNetworkPath`. DRK-320 added a separate registered-component path (`RecoveryTestRuntime::with_archive_config`, backed by `NativeArchiveExistingComponent`) for Recovery; the refusal in `RecoveryTestRuntime::new` itself still stands unconditionally. At Desktop, DRK-320 Task 7 changed `WriterResources::open`: for a controlled-network profile the Desktop Writer now commits into the registered SQLCipher component (`NativeArchiveExistingComponent::open_writer`) and publishes from there, instead of refusing the profile. `ControlledNetworkBackend::open` proves at-rest encryption and binds the full policy-approved profile, but exposes two resources; it does not itself implement the local Writer `ArchiveBackend` primitives.

Ordinary `OperatorArchiveSnapshot::open` currently reads the remote filesystem before `open_resources` opens SQLCipher. A complete native offline Writer therefore also needs Root's startup source integration. An adapter that only changes the constructor's match arm would still omit locally committed, unpublished progress and fail during a real network outage.

## Proposed smallest shared API

New `crates/ea-admin/src/native_archive.rs` owns an opaque `NativeArchiveExistingComponent` and a closed configuration carrier:

```rust
pub struct NativeArchiveConfig {
    pub profile: ArchiveBackendProfileV1,
    pub local_commit_database_path: Option<PathBuf>,
}

impl NativeArchiveExistingComponent {
    pub fn open_current(runtime: &OperatorRuntime, config: NativeArchiveConfig)
        -> Result<Self, NativeArchiveOpenError>;
    pub fn open_writer(runtime: &InteractiveOperatorRuntime, config: NativeArchiveConfig)
        -> Result<Self, NativeArchiveOpenError>;
    pub fn profile_hash(&self) -> Hash32;
    pub fn local_backend(&self) -> &dyn ArchiveBackend;
}
```

The two opening methods retain the existing typed Current versus Writer-only boundaries; no conversion from StaleWriter to ordinary Current is introduced. `network()`, `snapshot_source()` und `acquire_writer_lock()` als eigene Methoden auf `NativeArchiveExistingComponent` wurden nicht gebaut, ebenso wenig die Typen `NativeArchiveSnapshot` und `NativeArchiveLock`; der Schreib-Lock kommt stattdessen aus `local_backend().acquire_writer_lock()`.

The existing `runtime.config().archive_directory` remains the single actual output/network path. Existing profile fields are unchanged. The only additional explicit location is `local_commit_database_path`: required for controlled-network and forbidden for local-path. Its canonical path must identify the very same native SQLCipher database/Arc used by the runtime; Recovery cannot silently attach a separate unsnapshotted queue database. No key handle, plaintext key, independent namespace or queue limits come from the new field.

Proposed internal namespace derivation is a domain-separated hash of the exact independent anchor hash and full canonical archive profile hash. Database identity is checked separately. Excluding installation/path and current policy version keeps an unchanged logical source restorable at another path and avoids orphaning pending data on a policy refresh. The current verified Root policy must allow the exact profile on every admission. The active profile pointer/registered component must match; capture and read-only restore never create an empty replacement namespace if the expected source is missing. Reusing the existing active-profile pointer/migration contract is required before enabling profile changes.

## Storage/source responsibilities

The shared adapter retains the complete `ControlledNetworkBackend` plus the real `SqliteCommitStore`. A narrow SQLCipher-backed `ArchiveBackend` adapter must supply transactional create-if-absent/rename, actual durability, complete managed/staging enumeration and the same exclusive local Writer lock used by capture. It must not redirect the Writer to the remote network target. These primitive mappings need focused crash/reopen evidence before Root attaches the Writer service; a no-op flush or mutex-only lock is insufficient evidence.

The committed verification source is the exact union of committed network originals and committed local originals. Same-address byte conflict, incomplete local commit or unreadable required source is an error; staging stays backup material and never becomes chain progress. Scope manifests and old reports remain immutable. Whole-DB backup includes all namespaces, local commit objects/limits, prepared journals, original identity/number sources, retained HMAC tokens and destruction sources. Restore opens that whole original database read-only under the existing migration-prefix contract and must preserve unpublished bytes and state exactly.

Root owns native startup's use of that source before Trust selection, the Writer/queue Host connection, byte-identical grants-first/EIP-last publication and no server upload before publication. T9 owns reuse of the same resource/lock/source in capture and recovery; it must not implement a second network publication path.

The target recovery test is a distinct access mode: §19.3 consumes an unchanged
archive copy, not an activated Writer output. It must use a separate read-only
copy resource with no `local_backend` or publication capability. Its guards
still require the actual native current administrator, exact source/restore
binding, measured other machine and protected source locks. SourceCapture is
unavailable from that read-only resource. The original network profile and
namespace stay inside the unchanged restored source; an empty newly created
target queue cannot stand in for them. This typed split is part of the API
agreement before implementation, not permission to bypass current report or
source admission.

## Bounded execution and witnesses

- [ ] First add a native Recovery fixture with an actual signed policy allowing the complete configured network profile. Record the current precise constructor refusal as RED. The production body remains unchanged until the shared API and fixture locations are agreed.
- [ ] Add resource tests with a real SQLCipher native database: missing/mismatched component, different DB identity, changed profile/limits, wrong namespace, tampered active pointer and policy refusal all fail. Existing private namespace bytes survive reopen and remain encrypted at rest.
- [ ] Exercise the local ArchiveBackend durability and concurrent ownership using real independent DB connections/process restart, including staging before versus committed EIP after the irreversible boundary. Do not infer these properties from trait shape.
- [ ] Root supplies a separately named actual mounted filesystem fixture with measured protocol/server/version/mount configuration and capability behavior. A local temp directory carrying an SMB/NFS profile is only a unit fixture, never the native network-positive witness.
- [ ] Native SourceCapture must include a valid locally committed EIP/Grant set not yet present at the remote target. Its signature binds the complete source inventory and whole snapshot. Drop/reopen, protected passphrase backup, actual other-machine restore and unchanged local queue/journal bytes prove restoration; excluding the local set must fail before report readiness.
- [ ] Root verifies outage/reconnect and exact publication using the same resources. T9 verifies restore/readiness without automatically publishing or activating the restored source. Run only focused locked targets, record RED/GREEN and independent review; no staging or commits by this worker.

This is the interface proposal, not a claim that a network backend or supported release row already exists. The first implementation agreement must settle the shared SQLCipher `ArchiveBackend` primitive ownership and the real network fixture boundary; source-only tuple/config changes cannot close those requirements.
