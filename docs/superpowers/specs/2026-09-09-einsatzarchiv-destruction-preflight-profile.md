# Destruction preflight report — internal job profile v1

Decision: 2026-09-09, DRK-280 / Stage 5 Task 12, controller-approved implementation profile for the signed pre-state report required by main design §16.3 step 3. This is an internal durable job record. It is not an ExactObject, `.etb` subtype, Trust Registry object or change to an existing v1 authorization, event, attestation or Stub field.

## Exact signed bytes

The report core is deterministic CBOR with exactly 16 items, no extensions or alternate versions:

```cddl
destruction-preflight-core-internal-v1 = [
  "EINSATZARCHIV-DESTRUCTION-PREFLIGHT-v1", 1,
  organization-id: bstr .size 16,
  chain-id: bstr .size 16,
  destruction-id: bstr .size 16,
  authorization-byte-hash: bstr .size 32,
  inventory-snapshot-byte-hash: bstr .size 32,
  verification-report-byte-hash: bstr .size 32,
  verification-report-exact-json: bstr,
  authorization-registry-version: uint,
  authorization-registry-head-hash: bstr .size 32,
  authorization-sequence: uint,
  execution-registry-version: uint,
  execution-registry-head-hash: bstr .size 32,
  execution-sequence: uint,
  observed-effective-now: int
]
destruction-preflight-envelope-internal-v1 = [
  exact-core: bstr,
  exact-cose-sign1: bstr
]
```

The protected COSE certificate hash identifies the exact component chosen for this job and must match the immutable job's expected signer. All byte hashes use the existing `object_hash` byte-hash function; calling that function does not claim that the JSON or inventory is an ExactObject. `verification-report-exact-json` is exactly the existing deterministic `VerificationReportV1` serialization without runtime metadata. Its bytes are not reserialized before signing or verification.

The signed payload is SHA-256 over the concatenation of UTF-8 `EINSATZARCHIV-DESTRUCTION-PREFLIGHT-v1`, one zero byte, and the exact deterministic core bytes. COSE uses the new narrowly scoped content type `application/vnd.einsatzarchiv.destruction-preflight-digest`, with normal protected key thumbprint and certificate binding. The API is a typed preflight signing/verification operation; no caller-selectable header, arbitrary digest signer, generic signature purpose or alternative arity is exposed. Format version is exactly 1 and both domain occurrences are fixed.

## Proof source and authority

The core is assembled only by the production preflight service from the opaque authorized job and verified trust/pre-state proofs. Organization, chain, authorization, target/inventory snapshot, Registry and time fields are not accepted as unverified caller claims. The report must be fully verified and refer to the complete original unchanged authorized target set before it can be signed.

The signer must be a Root-certified component/device with `deletionAttest`, active under fresh execution Registry authority and eligible under the original authorization's immutable v1 signer context. Existing v1 transition/attestation contexts remain unchanged; a newly activated component outside that original context cannot extend the operation. Current native Destruction purpose, bound Admin presence, privacy policy, audit and delivery blocking are independent required execution checks.

On verification, check deterministic encoding/arity/domain/version, hash of exact JSON bytes, the immutable job's inventory hash, exact authorization hash/ID/org/chain and both Registry bindings, protected signer certificate/key, role/capability and signature. The core's execution sequence/head is authenticated archival attribution when replayed; it does not mint current action authority or a trusted current clock.

## Durability and restart

The exact core, signature envelope, referenced inventory snapshot and exact pre-state report bytes must be durably committed and flushed before any first physical removal. The signed requested/in-progress event and local audit retain their existing meanings. `LocalAuditAction::Destruction` continues to bind only the genuine authorization hash and genuine state-event hash; neither field is overloaded with a report hash.

After restart, reverify the stored report against its exact historical execution context and original immutable job snapshot, then independently acquire fresh native/current authority for the next operation. The executor does not fabricate a new fully verified pre-state after some originals have already been replaced by Stubs. Changed, missing or unbound stored report/inventory bytes prevent further removal and completion.

## Managed-scope limitation

The append-only registered custody inventory and monotone job snapshot establish the operational denominator. The v1 two-Approver authorization itself contains no replica list or inventory commitment. The report signature authenticates the component's verified preflight and frozen operational scope, not a second invisible Approver signature. Known unreachable or revoked holders remain obligations; later discovered holdings cannot be omitted from completion. Unknown exports/screenshots and unconfirmed physical/WORM/backup deletion are never asserted removed.

## Existing replicaKind product mapping

The controller-approved internal product mapping of the existing v1 unsigned integer is `0 = Writer managed custody`, `1 = Reader managed cache`, `2 = SyncServer managed custody`. The general ExactObject decoder and signature domains remain unchanged. Execution and completion reject an unknown value. `ManagedReplicaKind` is the single core mapping consumed by native and server adapters.

A replica is the certified DeviceId, not an arbitrary directory. Success covers every registered location, profile and generation belonging to that DeviceId. Backups and WORM holdings remain obligations of their registered component; a deadline alone never proves removal. Known offline/revoked devices and locations stay in the denominator. A result-0 attestation with a retained backup deadline must have `executedAt >= backupExpiryAt`, and still requires measured actual absence of every holding. The signed claim's historical verification does not itself establish that physical fact.

The narrow crypto profile is independently accepted in `task-12-crypto-review.md`. Full executor integration and its independent review remain separate acceptance work.
