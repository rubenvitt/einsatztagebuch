# Reader key escrow v1.1 profile

Status: proposed profile for independent specification/security review. No codec or production emission is authorized by the existence of this draft alone. The DRK-250 implementation remains in progress.

## Scope and fixed decisions

This profile implements the two Stage-5 additions in the main plan's Global Constraints and Web-Reader design §§6.6–7. It adds exactly two Trust subtypes: `readerKeyEscrow` and `readerKeyEscrowRecoveryAuthorization`. It preserves every existing v1 encoding, the fifteen positions and single signature of `organizationAdminAuthorization`, and its seven action codes. Old parsers continue to reject unknown subtypes; they never skip them.

The escrow is an ordinary content-addressed Root-signed `trust/` object, replicated and exported with the archive. Its only private plaintext is one 32-byte X25519 KEM key. Ed25519 device/audit keys, native instance keys, OS account material, profile salts, names and authentication credentials are excluded.

The existing Reader certificate has no Reader `authoritySubjectId`: that field is reserved for Admin and Key Approver certificates. Therefore the new escrow binds its pseudonymous Reader subject explicitly under both Admin and Root signatures. The server's credential database cannot supply this authority. The enrollment administrator verifies that subject in the same external enrollment ceremony as the certificate and bundle fingerprints.

## Publication authority and alternatives

The old blanket statement that each post-bootstrap Root ceremony references an `organizationAdminAuthorization` conflicts with a new escrow target while its old target/action table must remain frozen. A Root-only escrow exception would remove the independent exact-core approval. Widening the old action table or pretending a certificate authorization covers subsequently generated ciphertext would contradict the fixed decisions or fail to bind exact bytes.

The proposed resolution is a narrowly scoped **embedded Admin approval**, present only in the new escrow payload. It is one purpose-specific COSE signature over a fresh, exact-core-bound publication approval. Root signs the payload including that approval. It creates no third Trust subtype, no Registry change kind, and no new action in the old authorization family. Its active Admin certificate, Operator binding, native presence, validity and durable one-use checks mirror the existing Admin ceremony. The separate recovery authorization retains two distinct active Key Approvers.

Before implementation, independent review must confirm that this explicit v1.1 specialization preserves the intended Admin/Root separation. The main design and Web-Reader §7.5 must be aligned in the same profile/codec commit; no implementation chooses between contradictory normative texts.

## Exact envelopes and cryptographic contexts

Both objects retain the existing EA1 `.etb` envelope, outer format version 1 and empty critical extensions. Their body is `[subtype, payload, signatures]`.

`readerKeyEscrow` has exactly one Root signature. Its payload is exactly:

```cddl
reader-key-escrow-payload-v1 = [
  reader-key-escrow-core-v1,
  reader-key-escrow-admin-approval-core-v1,
  #6.18(COSE-Sign1)
]
reader-key-escrow-core-v1 = [
  1, organization-id: bstr .size 16,
  reader-certificate-object-hash: bstr .size 32,
  reader-subject-id: bstr .size 16,
  enrollment-registry-version: uint,
  enrollment-registry-head-hash: bstr .size 32,
  enrollment-sequence: uint,
  recovery-certificate-object-hash: bstr .size 32,
  recovery-kem-key-thumbprint: bstr .size 32,
  encapsulated-key: bstr .size 32,
  encrypted-reader-kem-key: bstr .size 48,
  issued-at: int, []
]
reader-key-escrow-admin-approval-core-v1 = [
  1, organization-id: bstr .size 16,
  registry-version: uint, registry-head-hash: bstr .size 32,
  authorization-sequence: uint,
  admin-certificate-object-hash: bstr .size 32,
  admin-operator-binding-object-hash: bstr .size 32,
  escrow-core-hash: bstr .size 32,
  issued-at: int, expires-at: int, nonce: bstr .size 32, []
]
```

These cores have respectively 13 and 12 positions. `escrow-core-hash` is SHA-256 over ASCII `EINSATZARCHIV-READER-KEY-ESCROW-CORE-v1` concatenated with the exact deterministic CBOR core. No reserialization is used during verification. The embedded Admin COSE payload is the 32-byte SHA-256 of ASCII `EINSATZARCHIV-READER-KEY-ESCROW-ADMIN-v1` concatenated with its exact deterministic CBOR approval core. Its registered content type is `application/vnd.einsatzarchiv.reader-key-escrow-admin-digest`; certificate-bound protected headers follow the existing normal Ed25519 profile. The signer must be the named active `OrganizationAdmin` certificate with `organizationAdminApprove`, paired with the named active native Operator binding and same authority subject. It cannot be substituted by a Root or Approver signature.

The Root signature uses the existing Trust digest of `["readerKeyEscrow", payload]`, including the exact embedded Admin approval and its COSE bytes. The authorizing and escrow heads, sequences and organizations must agree. Require `issuedAt <= effectiveNow < expiresAt`, `issuedAt <= escrow.issuedAt < expiresAt`, and a maximum approval lifetime of 300000 ms. Head/sequence authority comes from the selected verified Registry, not payload claims. The Root line must be valid at publication's Registry version.

The Recovery certificate must be active at enrollment, of kind `RecoveryRecipient`, carry an X25519 KEM public key whose canonical thumbprint equals the core field, and have the existing Recovery-recipient capability. The Reader certificate must be the exact already Root/Admin-authorized, Registry-activated Reader certificate with X25519 and Ed25519 public keys. Both certificate hashes resolve from the ordinary verified Trust inventory.

HPKE uses the existing Suite-1 RFC 9180 Base Mode. Its `info` is ASCII `EINSATZARCHIV-READER-KEY-ESCROW-HPKE-v1`. Its AAD is exact deterministic CBOR:

```cddl
reader-key-escrow-aad-v1 = [
  1, organization-id: bstr .size 16,
  reader-certificate-object-hash: bstr .size 32,
  reader-subject-id: bstr .size 16,
  enrollment-registry-version: uint,
  enrollment-registry-head-hash: bstr .size 32,
  recovery-certificate-object-hash: bstr .size 32,
  recovery-kem-key-thumbprint: bstr .size 32
]
```

The browser derives the public key of the private KEM it is sealing and requires equality with the verified Reader certificate before producing ciphertext. Root never receives plaintext. A complete Recovery test opens the escrow and independently repeats this public-key comparison, detecting an inconsistent escrow even if otherwise well signed.

## Separate two-Approver opening authorization

`readerKeyEscrowRecoveryAuthorization` has at least two COSE signatures with the existing total-order and duplicate-signature constraints. Its payload is a closed 17-position core:

```cddl
reader-key-escrow-recovery-authorization-v1 = [
  1, authorization-id: bstr .size 16,
  organization-id: bstr .size 16,
  registry-version: uint, registry-head-hash: bstr .size 32,
  authorization-sequence: uint,
  escrow-object-hash: bstr .size 32,
  reader-certificate-object-hash: bstr .size 32,
  reader-subject-id: bstr .size 16,
  enrollment-registry-version: uint,
  enrollment-registry-head-hash: bstr .size 32,
  target-transport-key-thumbprint: bstr .size 32,
  purpose: 0,
  issued-at: int, expires-at: int, nonce: bstr .size 32, []
]
```

Purpose 0 means replacement of all lost Reader authenticators. No free text or broader operation code exists. The Trust digest includes the new subtype and exact core. Its dedicated verification context requires `KeyApprover` and a new explicit `readerKeyEscrowApprove` capability. Two certificates for one `authoritySubjectId` are one person and do not satisfy the threshold. Existing Approver certificates gain no capability implicitly; adding it follows ordinary Admin/Root certificate and Registry activation.

Every signature must be valid and active at the current authorization sequence. Authorization requires the exact current selected head, non-stale Registry authority, `issuedAt <= effectiveNow < expiresAt`, and a lifetime at most 300000 ms. All target fields must match one fully verified escrow. The actual target transport public key must be canonical X25519 and match the authorized fingerprint before accessing the Recovery provider. Ed25519, foreign organization, changed identity, a substituted escrow, stale enrollment binding, same-person approvals, excess or duplicate unverified signatures and expired authority release nothing.

Opening uses a dedicated native `ReaderKeyEscrowRecovery` reauth purpose binding the exact authorization object hash and target transport fingerprint. The Recovery source uses the same non-exporting provider port as historical re-grant. The service verifies the decrypted X25519 key against the escrow's Reader certificate, then immediately HPKE-seals it to the new browser transport key. The only returned value is the encrypted envelope.

The output `info` is ASCII `EINSATZARCHIV-READER-KEY-ESCROW-RESTORE-v1`; AAD is exact deterministic CBOR `[1, organizationId, authorizationObjectHash, escrowObjectHash, readerCertificateObjectHash, readerSubjectId, targetTransportKeyThumbprint]`. All hashes are 32-byte byte strings and IDs are 16-byte byte strings. The response contains this public binding, a 32-byte encapsulated key and a 48-byte ciphertext. Its authenticity comes from HPKE plus the exact verified authorization; it is not a new Trust family.

## Durable state, audit and failure

Publication consumes the embedded Admin approval nonce and digest in an encrypted append-only repository, atomically with its signed audit and prepared exact escrow bytes, before returning the Root ceremony result. Exact replay can return the same already published bytes; it cannot authorize another core. Conflicting material for the same authorization fails. Independently verifiable ciphertexts may coexist for a certificate; they do not replace or overwrite earlier objects, and an opening always names one exact hash.

Opening atomically consumes `(organizationId, authorizationId)` and `(organizationId, nonce)` with a signed local audit before private-provider access. The audit action and context get their own closed additive profile carrying authorization, escrow and target-key hashes only. The service checks native-session invalidation before secret access and before output publication. No public report contains a PIN, path, private plaintext or key label.

A crash after consumption and before durable encrypted output requires a fresh two-Approver authorization; the old authorization never runs again. A durable encrypted result may be retrieved idempotently by its exact authorization after fresh native reauthentication; retrieval cannot re-encrypt to a different key. Invalid/torn audit or output state remains an explicit failure. Never reset a consumption row to make a retry succeed.

The browser opens the response only with its live transport private key, checks every AAD field and the recovered KEM public fingerprint, generates a **new Ed25519 key**, and creates a new Vault with two confirmed independent authenticators. It obtains a new normally authorized Reader certificate for the recovered KEM and new Ed25519 key. Existing old grants remain bound to their original certificates and are usable by matching the recovered KEM; new requests and audit use the new certificate. Losing the browser transport key before successful import requires a new opening authorization. All transient private values zero on success, lock and error.

Certificate continuity does not rewrite a grant's original recipient certificate. Offline verification still validates that exact certificate and, for a historical grant, its original exact authorization and expiry. Server delivery authenticates the new active Reader signing certificate, then compares its canonical KEM thumbprint against the fully verified recipient certificate of the old grant. Equal KEM public keys establish the same content capability; a different KEM, an inactive new request signer or an unresolved original grant certificate is refused. No server credential-subject row replaces this public-key proof. Acceptance must cover restored Reader access through both ordinary and historical old grants, plus different-KEM and changed-certificate substitution failures.

## Cutover and acceptance

The authoritative CDDL, codec, crypto contexts, admission verifier, offline archive verifier, CLI, server transport/replication, browser WASM and Root-signed Reader bundle must ship together before enabling escrow emission. A deployment that cannot prove the complete profile support remains explicitly enrollment-blocked. No server-only switch can waive bundle/CLI support, and no compatibility parser ignores the new subtypes. Existing golden bytes and semantic results must be unchanged.

Acceptance includes independent golden vectors and malformed/arity/context negatives for both subtypes and the embedded approval; real browser generation and import; actual native publication/opening with signed durable SQLCipher audit; actual module-backed Recovery opening; complete offline verification without server data; live server admission plus replicate/export/import; a new Reader enrolled after original entries; target-key substitution; same-person approvals under two certificates; stale/current Registry separation; replay/concurrency/restart faults; canary scans through files/reports/DOM; and the complete fresh-machine Recovery/lifecycle gate. Browser bridge fakes are UI evidence only. Physical custody and installed minimum/maximum release cases remain Stage 7.

Review must separately assess the embedded Admin specialization, pseudonymous identity authority, certificate continuity after audit-key replacement, and whether the capability/cutover gates can be bypassed through direct API or offline CLI paths.
