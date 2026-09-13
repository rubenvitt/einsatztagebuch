# Internal recovery source and report profile

This profile closes Stage 5 Task 9 without adding an archive object, Registry authority or key-container family. A source capture is not a successful Recovery Test. Its existing signed `RecoveryTest / Accepted` local audit action means only that a freshly authenticated OrganizationAdmin captured the exact pre-loss operational source scope. Only a separately verified complete test and durable `RecoveryTest / Completed` action can establish readiness.

The source core is deterministic CBOR, an exact 19-element array:

1. `"EINSATZARCHIV-RECOVERY-SOURCE-v1"`
2. version `1`
3. fresh source ID, 16 bytes
4. organization ID, 16 bytes
5. chain ID, 16 bytes
6. independently supplied Trust Anchor hash, 32 bytes
7. measured source OS machine fingerprint, 32 bytes
8. native source installation ID, 32 bytes
9. selected Registry version
10. selected Registry head object hash, 32 bytes
11. selected proposed sequence
12. selected preexisting `effectiveNow` in milliseconds
13. hash of the exact `ea.key-inventory/v1` bytes, 32 bytes
14. hash of the exact sorted archive object inventory, including staged archive objects, 32 bytes
15. verified archive tip `[sequence, entryHash]`
16. exact encrypted SQLCipher snapshot hash, 32 bytes
17. hash of the ordered migration versions and SQL hashes, 32 bytes
18. exact fixed backup KDF description as a byte string
19. existing Recovery probe bindings, sorted strictly by pseudonymous medium ID hash; each is `[mediumIdHash, certificateHash, KEMThumbprint, setupEntryHash, originalInitialRecoveryGrantHash]`, five 32-byte strings.

All ObjectHash values use the existing EINSATZARCHIV-OBJECT-v1 prefix before their input. The source audit context is `ObjectHash("EINSATZARCHIV-RECOVERY-SOURCE-CONTEXT-v1" || exactCore)`. The exchange envelope is deterministic CBOR `[exactCore: bstr, exactSignedLocalAuditEvent: bstr]`. The signed event must have the same organization and time, an authenticated historical OrganizationAdmin certificate and operator binding under the exact core Registry route, action `RecoveryTest` with this exact context, and outcome `Accepted`. The verifier independently checks committed signed archive/trust bytes; staged objects remain bound in the full source inventory but never advance the verified committed tip. An unverified parsed core is data only. A target context never supplies its own authority.

The fixed KDF description is `["EINSATZARCHIV-SOURCE-BACKUP-KDF-v1", 1, 65536, 3, 4, 19, 32, salt16]`: Argon2id, memory in KiB, iterations, lanes, Argon2 version 0x13, output length, fresh CSPRNG salt. Parameters cannot be negotiated. The explicitly supplied passphrase file uses the existing restrictive secret-input reader. Passphrase, KDF workspace and derived key use protected/zeroizing carriers; neither passphrase nor key appears in public output. This independently derived key protects the SQLCipher backup. It is neither an Ed25519 seed nor an X25519 key. Restore verifies the signed scope, KDF and ciphertext hash before deriving/opening the backup, exports to an exclusively new database protected by a freshly provisioned native database key, and never replaces an existing target.

Capture holds the native lifecycle, archive Writer and SQLCipher connection/write-reservation locks. The snapshot includes every table, index and trigger, including drafts and irreversible/prepared commit queues; incident-number acquisition and original-identity/publication sources; the retained HMAC key and every unlinkable tombstone; destruction request/inventory/job/event and managed custody sources; trust floors, audit, local measurements, source/report records and migrations. An HMAC token set without its original key fails closed. Archive hashes cannot recreate any of these sources. The source envelope and snapshot must be backed up together with the independently held anchor, unchanged archive, all configured key media and the exact inventory. A crash before signed publication leaves an incomplete backup, never readiness.

Every configured medium must be represented, and every required historical KEM epoch must bind an already existing immutable setup Entry and its original InitialRecoveryGrant. Capture verifies signed public membership and exact certificate/recipient binding; the target must actually open, schema-validate and verify the historical operator binding of every declared probe. Missing epochs cannot be repaired by silently issuing grants. Newer archives/inventories with an older source snapshot are diagnosed as mismatched/incomplete, not combined into an invented source state.

The complete test runs only after measuring a target OS machine identity different from the source and setup ceremony machine. Native account, watch, current authority and fresh presence are checked before and after blocking operations. Every configured signing backup signs only the existing fresh recovery-test digest; nonexportable media exercise actual provider access and native authentication without private export. Every Recovery medium decrypts its bound probe in protected memory. The full archive is verified with the authorized recipients, and deterministic minimum-sequence samples cover every discovered schema/suite/Writer epoch. The archive and grants remain byte-identical.

The final public report binds source-envelope hash, fresh test ID, target machine and installation, anchor, exact archive tip/inventory, selected time/Registry route, release/schema/suite versions, each pseudonymous medium hash and expected/observed thumbprint, exact test kind and result, deterministic sample references, and completion. The native completion additionally binds the actually restored database. Its exact deterministic six-element CBOR core is ["EINSATZARCHIV-RECOVERY-COMPLETION-v1", 1, exactReport: bstr, restoredContentHash: bstr32, completedAt: int, nextDueAt: int]. The existing signed RecoveryTest/Completed event binds ObjectHash("EINSATZARCHIV-RECOVERY-COMPLETION-CONTEXT-v1" || exactCompletionCore). The exchange envelope is [exactCompletionCore: bstr, exactSignedLocalAuditEvent: bstr]. The report has exactly the declared JSON fields, in declared serialization order. Unknown fields, reordered/noncanonical bytes, incomplete or mismatched media, unbound samples, Accepted audit or altered bytes fail closed. Signed policy fixes nextDueAt minus completedAt; Source time must not follow run time, run time must not follow completion, and completion must not follow the independently observed verification time. There is no additional total-run duration cap: every native action, provider phase and final admission retains its own current authority, lease, posture, monotonic-time and presence limits. The same native session expires after five minutes of inactivity; only a new fully verified presence with its durable Login audit may renew activity, never polling or replay. Import can verify an expired complete report as historical evidence, but expiry never becomes current readiness. The exact report, signature/audit and status are durable in the same SQLCipher transaction; any missing medium, wrong key, unverifiable source, missing epoch, failed sample, native lock or audit/store failure prevents readiness. Import independently verifies this evidence and the local source association; a caller Boolean is never a production proof.

A fresh isolated Linux instance with its own normally initialized OS machine ID provides software lifecycle evidence. It does not claim the installed second physical machine or the Stage 7 minimum/maximum platform release gates.


The target authorization database is separate from the restored recovery-test database. The source profile, claims, jobs, original identities, audit and all other snapshot contents remain unchanged. Restore never copies them into an active Writer archive. Completion proves only the independent recovery test; current target Registry/Destruction/reservation admission remains necessary for active operation and cannot be replaced by an older source pin or restored jobs.

The read-only restored-content digest uses streaming ObjectHash and a leading EINSATZARCHIV-RECOVERY-RESTORED-SOURCES-v1 domain. It includes every sqlite_schema object's type/name/table/exact SQL sorted by binary type and name, and every row of every table sorted by all column positions with binary collation. Schema row, table start, data row and table end have distinct tags. Each scalar has a type tag; integers and IEEE real bits use fixed big-endian encodings; text/blob values have an eight-byte big-endian length plus borrowed exact bytes; NULL has its own tag. Row/page ordering and encryption-key changes do not change this commitment; logical contents and schema changes do. No private row value is returned or accumulated as a Rust payload buffer. The signed native restore audit binds the digest to the verified source envelope, snapshot, migrations, actual target machine/installation and exact current Registry route.

### Native restoration receipt

Restoration itself is a separate RecoveryTest/Accepted event, never the
Completed event. Its subject context is ObjectHash of canonical CBOR array11:
["EINSATZARCHIV-RECOVERY-RESTORE-v1",1,sourceEnvelopeHash,snapshotHash,
migrationsHash,targetMachine,targetInstallation,restoredContentHash,
registryVersion,registryHead,proposedSequence]. Hashes are exact32 bstr and
Registry/sequence are unsigned integers. The existing LocalAudit signed core
binds actor, operator binding, native effective time and nonce. Target SQLCipher
commits the immutable restore association and that signed event atomically.
The restored database receives neither association nor profile rewrites.
On reopening, every association value and its signed context must be rechecked
against actual native identity, current authority and the measured restored
content before any medium is opened. Source proposed sequence is exactly
checked tip+1, never an arbitrary later sequence.
# Diagnostic failure and historical schema continuation

Guided native testing uses the same kernel as batch input. The fresh 16-byte
run identifier is the exact final signed report testId. For each expected
medium, requestId is SHA-256 over the bytes
`EINSATZARCHIV-RECOVERY-MEDIUM-REQUEST-v1 || runId16 || mediumPseudonymousHash32`.
Public requests contain only those IDs, one-based index and total, role,
certificate hash, expected public thumbprint, declared protection and test kind.
Public observations carry IDs and the actual Passed/Missing/Failed result,
observed thumbprint and diagnostic code. Source paths, medium names, passwords,
PINs and private key material never enter this progress channel.

The host supplies one optional owned medium input through a bounded cancellable
callback. No SQLCipher transaction or connection mutex is held while waiting.
After each wait and provider phase, the runtime reopens the actual authority,
checks the unchanged archive and restored source, and checks the independent
host's pure denial-only epoch guard. The guard cannot grant authority. Abort
produces neither a completed report nor a diagnostic result that would imply
the attempt reached its signed finalization. Final report/audit persistence
still requires the actual current native authority and fresh presence.

The opening runtime is retained only as the immutable sample/report snapshot.
After an input or result callback, a new action runtime is opened through the
same native session watcher. Exact configuration, independent anchor,
Registry head/version/sequence, account binding and persisted pin/time bounds
must still match the opening snapshot. Current posture and fresh native
authentication are independently required. A provider operation retains its
own action deadline: its expired context is rejected after the operation,
never renewed to rescue that operation. A legitimate wait between actions is
therefore distinct from extending an already issued proof.

A failed attempt is a separate internal document and never a completed Recovery
proof. Its canonical core has exactly five fields: domain
`EINSATZARCHIV-RECOVERY-FAILURE-v1`, version 1, exact public diagnostic report
bytes, the restored full-content hash, and actual failure time. The context hash
uses `EINSATZARCHIV-RECOVERY-FAILURE-CONTEXT-v1` followed by the exact core bytes.
The two-field envelope carries core bytes and the existing signed
`RecoveryTest/Failed` LocalAudit event. This adds no archive signature family.

The report preserves the exact source, independent anchor, target machine and
installation, archive tip, Registry route, release/schema/suite metadata and one
result per expected medium. Results distinguish passed, failed and missing;
known observed thumbprints are public, and unknown values remain absent rather
than copying the expected value. Stable error codes carry no key, passphrase,
path or decrypted payload. Failure reports make no successful sample-coverage
claim. A completed verifier rejects this domain, outcome and diagnostic fields.

Migration0022 retains the exact public envelope, context hash, source hash and
signed audit reference atomically in a separate append-only failure table. It
does not replace the latest successful report or update completedAt/nextDueAt.
The full diagnostic report must be readable after restart without reimport.

Historical encrypted proof sources use their original signed migration hash.
The hash encoding remains the ordered concatenation of each migration version
and its SQL object hash. A restore accepts only an exact known embedded prefix
starting with the original migration and reaching at least0018, and the actual
ledger must match that complete prefix in order. It rejects missing, foreign,
future or mismatched rows. Restored proof databases open read-only without
applying migrations, including on later reopen. The separate current native
authorization database follows normal migrations. Neither old source signatures
nor immutable snapshots receive newly invented migration metadata.
