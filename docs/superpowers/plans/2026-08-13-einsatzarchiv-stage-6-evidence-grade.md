# Einsatzarchiv Stage 6 Evidence Grade Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add RFC-3161/RFC-9921 Evidence Grade timestamps, deterministic deadline classification, immutable evidence chaining, renewals over exact prior bytes, and offline-verifiable long-term reports without blocking offline Writer finalization.

**Architecture:** Keep TSA transport outside the evidence verifier. Build and sign checkpoint/renewal inputs in shared Rust, compute the RFC-9921 `3161-ctt` message imprint over the CBOR-encoded COSE signature field, and persist complete timestamp material as exact `.ecp` bytes. A server scheduler starts only after atomic Entry/Receipt commit; Reader/CLI classification uses the immutable Receipt deadline plus `EffectiveNow`, never queue or local job time.

**Tech Stack:** Shared Rust format/crypto/time/trust crates, RFC 3161/5816 timestamp protocol, RFC 9921 `3161-ctt`, X.509/TSA validation, Axum server scheduler/adapters, Tauri/React status presentation, golden DER/CBOR/COSE fixtures.

## Global Constraints

- Die Schlüsselwörter **MUSS**, **DARF NICHT**, **SOLL**, **SOLL NICHT** und **DARF** sind normativ zu verstehen. Ein Release darf von einer MUSS-Anforderung nicht abweichen. Eine Abweichung von SOLL erfordert eine dokumentierte Sicherheits- oder Betriebsbegründung.
- **Merker Web-Reader**, `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §12: dieser Plan bleibt unverändert. Der Merker dokumentiert, dass der Spec geprüft und keine Auswirkung festgestellt wurde. Zu beachten ist lediglich §5.4: im Datei-Modus des Web-Readers werden nur die im Bündel enthaltenen Receipts und Checkpoints geprüft; Objekte ohne Receipt sind `nicht server-bestätigt` und DÜRFEN NICHT als vollständig bestätigt dargestellt werden — das ist eine Darstellungsdimension, keine Änderung des Evidence-Verfahrens.
- **Übertrag Stufe 3 — `pnpm verify:quick` setzt laufende Dienste voraus**: Ab Stufe 3 sind `apps/server` und `crates/ea-sync-server` Mitglieder des Cargo-Arbeitsbereichs, und das Teilkommando `cargo test --workspace --all-targets --locked` aus `verify_quick_commands()` (`tools/xtask/src/main.rs`) zieht deren Integrationstestziele mit. Der Lauf `pnpm verify:quick` in Schritt 4 des Stufe-6-Gates steht in diesem Plan noch nackt; er MUSS in die von Stufe 3 eingeführte Klammer `cargo run --locked -p xtask -- integration up` … `integration down` gefasst werden, weil `#[sqlx::test]` `DATABASE_URL` zur Laufzeit liest und der Object-Store-Endpunkt ebenso gesetzt sein muss. Ohne die Klammer schlägt der Schritt fehl, ohne dass ein Evidence-Fehler vorläge. Bei der Überarbeitung dieses Plans nachzuziehen, nicht in Stufe 3 zu lösen.
- Microsoft Access is outside scope; Access Grant remains only a signed key envelope.
- Non-goals are fixed: no live incident log, dispatch/alarm/control-center integration, patient record or identifying patient data, concurrent offline Writers, normal-app mutation/deletion of finalized content, AI summarization/OCR, public links, server-side content search, unprofiled network paths, qualified personal electronic signature, TR-ESOR certification claim, screenshot/transcription prevention, or cryptographic recall of already decrypted data.
- Product invariants apply verbatim: exactly one active Writer; never-reused predecessor-bound sequences; immutable `.eip` bytes except whole-object authorized replacement by `.eds`; amendment-only corrections; one fresh CEK/ciphertext; one signed grant per recipient; exactly one active Recovery grant before commit; no Reader/Recovery/HGA/Approver private key on Writer; no retained CEK/decryptable draft key; no server decrypt/grant key; server-independent archive verification; independent schema/format/suite versions with old bytes unchanged; separate Sync/verification/Evidence/Entry/destruction statuses; no legal overclaim from a hash chain; every active Reader initially granted; external-anchor recovery; and only Root-signed OS/device-bound operator snapshots.
- Offline finalization never waits for server or TSA. Receipt and Evidence state do not change fachliche finality.
- Device finalization time, server acceptance time, and TSA `genTime` remain separate and are never presented as interchangeable.
- The immutable signed Receipt is the only deadline anchor: Standard has `evidenceDueAt = null`; Evidence Grade has `acceptedAtServer + policy.evidenceMaxDelayMs` fixed at commit.
- A qualifying token must fully cover the Entry and have `genTime <= evidenceDueAt`. A later token remains archived but can never change `überfällig` to `vollständig`.
- Evidence states are exactly `vollständig`, `ausstehend`, `überfällig`, `ungültig` and derive from cryptographic inputs plus shared `EffectiveNow`.
- `.ecp` objects and renewals are append-only, bind direct predecessor or exact prior object bytes, and never rewrite Receipt, Entry, or older Evidence.
- TSA receives only message imprint/protocol data, never incident content. Logs/reports contain no fachliche plaintext, nonce secrets, private keys, or unredacted certificate secrets.
- COSE unprotected headers remain empty except the exact RFC-9921 `3161-ctt` header for timestamped Evidence.
- Shared Rust is the sole implementation; server, Reader, Desktop, and CLI use the same builder/verifier/vectors.
- Evidence UI remains on the shared Ant Design 6 German/static-`zeroRuntime`/local-CSP token system, direct CSR `@phosphor-icons/react` imports, keyboard/screen-reader labels, visible focus, text beyond color/icon, and reduced-motion support.
- v0.1 is complete only after Stage 7 and every acceptance criterion/gate passes.

The exact formula is immutable:

```text
messageImprint = SHA-256(cborEncodeByteString(coseSign1.signatureBytes))
```

Renewal inputs are exact:

```text
renewalInputHash[i] = SHA-256(
  "EINSATZARCHIV-EVIDENCE-RENEWAL-INPUT-v1" || exactEvidenceObjectBytes[i]
)
```

---

### Task 1: RFC-9921 Signature-Field Imprint and TSA Validation Port

**Files:**
- Create: `crates/ea-evidence/Cargo.toml`
- Create: `crates/ea-evidence/src/lib.rs`
- Create: `crates/ea-evidence/src/imprint.rs`
- Create: `crates/ea-evidence/src/tsa.rs`
- Create: `crates/ea-evidence/src/x509.rs`
- Create: `crates/ea-evidence/src/error.rs`
- Test: `crates/ea-evidence/tests/imprint.rs`
- Test: `crates/ea-evidence/tests/tsa_validation.rs`

**Interfaces:**
- Consumes: exact COSE Sign1 bytes and configured TSA policy/trust material.
- Produces: `ctt_message_imprint`, `TsaClient`, `TsaValidator::verify -> VerifiedTimestamp`, and no network dependency in verification.

- [ ] **Step 1: Write exact CBOR-byte-string imprint and TSA-negative tests**

```rust
#[test]
fn imprint_hashes_cbor_encoded_signature_field_not_payload_or_raw_signature() {
    let signature = vec![0xA5; 64];
    let expected_input = [&[0x58, 0x40][..], signature.as_slice()].concat();
    assert_eq!(ctt_message_imprint(&signature), sha256(&expected_input));
    assert_ne!(ctt_message_imprint(&signature), sha256(&signature));
}

#[test]
fn wrong_nonce_policy_eku_or_imprint_is_rejected() {
    for response in [fixtures::wrong_nonce(), fixtures::wrong_policy(),
                     fixtures::missing_timestamping_eku(), fixtures::wrong_imprint()] {
        assert!(validator.verify(response, fixtures::request()).is_err());
    }
}
```

- [ ] **Step 2: Run tests and verify Evidence crate is absent**

Run: `cargo test --locked -p ea-evidence --test imprint --test tsa_validation`

Expected: FAIL because imprint and TSA validation do not exist.

- [ ] **Step 3: Implement exact imprint and offline validator**

```rust
pub fn ctt_message_imprint(signature_field_bytes: &[u8]) -> Hash32 {
    let encoded = ea_cbor::encode_byte_string(signature_field_bytes);
    ea_crypto::sha256(&encoded)
}

#[async_trait::async_trait]
pub trait TsaClient: Send + Sync {
    async fn timestamp(&self, request: TimestampRequest) -> Result<TimestampResponse, TsaTransportError>;
}
```

Build RFC-3161 requests with SHA-256 imprint, cryptographically random request nonce, configured policy OID, and certificate request. Validator accepts stored DER plus pinned trust/policy and checks response status, message imprint algorithm/value, nonce, policy, `genTime`, signer chain, `timeStamping` EKU, validity/revocation data at validation time, and signed-attribute consistency. Return verified typed fields plus exact DER; never call a live TSA during verification.

- [ ] **Step 4: Run published/local golden and malformed-DER tests**

Run: `cargo test --locked -p ea-evidence --test imprint --test tsa_validation`

Expected: PASS; truncated/oversized/malformed ASN.1 fails with bounded errors and no panic.

- [ ] **Step 5: Commit RFC-3161/RFC-9921 foundation**

```bash
git add crates/ea-evidence Cargo.toml Cargo.lock
git commit -m "feat(evidence): verify RFC 9921 timestamp imprints"
```

### Task 2: Timestamped Checkpoint Object Builder and Verifier

**Files:**
- Create: `crates/ea-evidence/src/checkpoint.rs`
- Create: `crates/ea-evidence/src/object.rs`
- Create: `crates/ea-evidence/src/verify.rs`
- Test: `crates/ea-evidence/tests/checkpoint_golden.rs`
- Test: `crates/ea-evidence/tests/checkpoint_attacks.rs`

**Interfaces:**
- Consumes: Stage 3 checkpoint core, server signer, `TsaClient`, exact Stage 1 `.ecp` format.
- Produces: `EvidenceBuilder::timestamp_checkpoint`, `VerifiedCtt`, and exact `.ecp` bytes with complete validation material.

- [ ] **Step 1: Write exact-object and CTT-header attack tests**

```rust
#[tokio::test]
async fn evidence_object_archives_complete_inputs_and_matches_golden() {
    let object = builder.timestamp_checkpoint(fixtures::checkpoint_core()).await.unwrap();
    assert_eq!(object.exact_bytes(), fixtures::expected_timestamp_evidence_bytes());
    assert_eq!(verify_ctt(object, fixtures::tsa_policy(), fixtures::trust()).unwrap().gen_time(),
               fixtures::tsa_gen_time());
}

#[test]
fn removed_replaced_or_relocated_ctt_header_fails() {
    for object in [fixtures::missing_ctt(), fixtures::changed_ctt(), fixtures::ctt_in_protected_header()] {
        assert!(verify_ctt(object, fixtures::tsa_policy(), fixtures::trust()).is_err());
    }
}

#[test]
fn complete_timestamp_response_is_never_accepted_as_the_3161_ctt_value() {
    assert_eq!(fixtures::archived_response_der(), fixtures::fixed_timestamp_response_der());
    assert_eq!(fixtures::ctt_header_token_der(), fixtures::extracted_timestamp_token_der());
    assert_ne!(fixtures::archived_response_der(), fixtures::ctt_header_token_der());
    assert!(verify_ctt(fixtures::response_der_used_as_header(), fixtures::tsa_policy(), fixtures::trust()).is_err());
}
```

- [ ] **Step 2: Run checkpoint tests and verify builder is absent**

Run: `cargo test --locked -p ea-evidence --test checkpoint_golden --test checkpoint_attacks`

Expected: FAIL because timestamped checkpoint builder/verifier do not exist.

- [ ] **Step 3: Implement COSE-then-timestamp and complete `.ecp` persistence**

Deterministically encode checkpoint payload with domain, organization, chain, covered range, head Entry, Registry head, server time, and previous Evidence hash. COSE-sign it with server checkpoint capability. Extract exact signature byte string, CBOR-encode that byte string, compute imprint, request TSA, and verify the complete DER `TimeStampResp`. Archive that complete response unchanged in `rfc3161-response-der`, but extract its complete DER `TimeStampToken` (`ContentInfo`) and insert only those token bytes as the bstr value of the sole RFC-9921 `3161-ctt` unprotected header. A complete `TimeStampResp` in label 270 is invalid even when it is a bstr and the sole map entry. Archive exact checkpoint payload, complete COSE object, SHA-256 identifier, request nonce, policy OID, certificate chain, revocation, validation data, and predecessor in the Stage 1 `.ecp` shape. Reparse and fully verify exact bytes before publication.

- [ ] **Step 4: Run golden, one-byte mutation, wrong signer, and offline verification tests**

Run: `cargo test --locked -p ea-evidence --test checkpoint_golden --test checkpoint_attacks`

Expected: PASS; a stopped TSA after object creation does not affect later verification.

- [ ] **Step 5: Commit timestamped checkpoint objects**

```bash
git add crates/ea-evidence vectors/evidence
git commit -m "feat(evidence): archive timestamped checkpoints"
```

### Task 3: Receipt-Anchored Evidence Scheduler and Deterministic Status

**Files:**
- Create: `crates/ea-evidence/src/status.rs`
- Create: `crates/ea-sync-server/src/evidence_scheduler.rs`
- Create: `apps/server/src/adapters/tsa.rs`
- Modify: `apps/server/migrations/0001_initial.sql`
- Modify: `apps/server/src/config.rs`
- Test: `crates/ea-evidence/tests/status_boundaries.rs`
- Test: `crates/ea-sync-server/tests/evidence_scheduler.rs`

**Interfaces:**
- Consumes: immutable verified Receipt, checkpoint coverage, `EffectiveNow`, TSA adapter.
- Produces: `classify_evidence`, post-commit `EvidenceScheduler`, retry state, and immutable overdue outcome.

- [ ] **Step 1: Write before/on/after deadline and late-token tests**

```rust
#[test]
fn status_boundaries_use_only_receipt_deadline() {
    let receipt = fixtures::receipt_due_at(100);
    assert_eq!(classify_evidence(receipt, &[], effective_now(99)), EvidenceStatus::Pending);
    assert_eq!(classify_evidence(receipt, &[], effective_now(100)), EvidenceStatus::Pending);
    assert_eq!(classify_evidence(receipt, &[], effective_now(101)), EvidenceStatus::Overdue);
    assert_eq!(classify_evidence(receipt, &[fixtures::valid_token_at(101)], effective_now(200)),
               EvidenceStatus::Overdue);
}

#[tokio::test]
async fn scheduler_never_starts_before_atomic_entry_receipt_commit() {
    let mut h = SchedulerHarness::fault_before_commit();
    let _ = h.accept_entry().await;
    assert_eq!(h.tsa_requests(), 0);
}
```

- [ ] **Step 2: Run status/scheduler tests and verify failure**

Run: `cargo test --locked -p ea-evidence --test status_boundaries && cargo test --locked -p ea-sync-server --test evidence_scheduler`

Expected: FAIL because classification and scheduler do not exist.

- [ ] **Step 3: Implement deterministic classification and post-commit jobs**

```rust
pub fn classify_evidence(
    receipt: &VerifiedReceipt,
    evidence_chain: &[VerifiedEvidenceObject],
    effective_now: EffectiveNow,
) -> EvidenceStatus;
```

For Standard Receipt require `evidenceDueAt = null`; it does not claim Evidence Grade. For Evidence Grade, find a fully valid checkpoint covering the Entry without gaps. `Complete` requires token `genTime <= due`; `Pending` requires no qualifying token and now <= due; `Overdue` requires no on-time qualifying token once now > due or a valid late token; `Invalid` covers invalid Receipt/checkpoint/CTT/imprint/TSA/binding. Persist a terminal “deadline missed” fact derived from immutable inputs only as a cache; recomputation must yield the same result. Scheduler creates jobs only from committed Receipt references, uses bounded retry/jitter for TSA transport, never moves deadline, and archives late responses.

- [ ] **Step 4: Run outage/retry/restart/clock-rollback boundary tests**

Run: `cargo test --locked -p ea-evidence --test status_boundaries && cargo test --locked -p ea-sync-server --test evidence_scheduler -- --test-threads=1`

Expected: PASS; clock rollback cannot rejuvenate overdue state and TSA outage never affects fachliche commit.

- [ ] **Step 5: Commit Evidence scheduling/status**

```bash
git add crates/ea-evidence crates/ea-sync-server apps/server
git commit -m "feat(evidence): classify receipt-anchored deadlines"
```

### Task 4: Linear Evidence Chain and Exact-Byte Renewals

**Files:**
- Create: `crates/ea-evidence/src/chain.rs`
- Create: `crates/ea-evidence/src/renewal.rs`
- Create: `crates/ea-sync-server/src/evidence_renewal.rs`
- Test: `crates/ea-evidence/tests/chain.rs`
- Test: `crates/ea-evidence/tests/renewal.rs`

**Interfaces:**
- Consumes: exact prior `.ecp` bytes, current Entry head, previous renewal hash, server signer, TSA client.
- Produces: `verify_evidence_chain`, `build_renewal`, sorted exact-byte input hashes, immutable renewal `.ecp`.

- [ ] **Step 1: Write divergent-head, predecessor, and exact-byte binding tests**

```rust
#[test]
fn same_coverage_with_different_head_is_security_event() {
    let err = verify_evidence_chain(&[fixtures::evidence_head_a(), fixtures::evidence_same_range_head_b()]).unwrap_err();
    assert_eq!(err.code(), "EA-EVIDENCE-DIVERGENT-HEAD");
}

#[tokio::test]
async fn renewal_changes_when_any_prior_object_byte_changes() {
    let first = build_renewal(fixtures::exact_evidence_objects(), None, signer(), tsa()).await.unwrap();
    let second = build_renewal(fixtures::one_byte_changed_evidence_objects(), None, signer(), tsa()).await.unwrap();
    assert_ne!(first.core().sorted_renewal_input_hashes, second.core().sorted_renewal_input_hashes);
}
```

- [ ] **Step 2: Run chain/renewal tests and verify failure**

Run: `cargo test --locked -p ea-evidence --test chain --test renewal`

Expected: FAIL because Evidence predecessor/renewal logic does not exist.

- [ ] **Step 3: Implement linear chain and renewal over exact bytes**

Compute each Evidence predecessor as object hash of the direct exact prior `.ecp`. Reject wrong predecessor, missing range, same covered-through sequence with different head, and CTT removal/replacement. For Renewal, hash every exact selected Evidence object's full bytes with the fixed renewal-input domain, bytewise sort unique hashes, bind organization, chain, current Entry hash, previous Renewal hash, and empty critical extensions, then COSE-sign and timestamp with the same signature-field rule. Persist as a new `.ecp`; never replace older files.

- [ ] **Step 4: Run multi-level renewal and offline-chain tests**

Run: `cargo test --locked -p ea-evidence --test chain --test renewal`

Expected: PASS for three Renewal generations after TSA shutdown; changed/missing prior bytes fail.

- [ ] **Step 5: Commit Evidence chaining and Renewal**

```bash
git add crates/ea-evidence crates/ea-sync-server
git commit -m "feat(evidence): chain and renew exact evidence bytes"
```

### Task 5: Reader, CLI, and Desktop Evidence Integration

**Files:**
- Modify: `crates/ea-reader/src/verify.rs`
- Modify: `crates/ea-verify/src/report.rs`
- Create: `apps/cli/src/commands/evidence.rs`
- Modify: `apps/desktop/src/components/integrity/EvidenceStatus.tsx`
- Modify: `apps/desktop/src/components/integrity/ChainIntegrityRail.tsx`
- Create: `apps/desktop/src/features/reader/EvidenceView.tsx`
- Test: `crates/ea-reader/tests/evidence.rs`
- Test: `apps/cli/tests/evidence.rs`
- Test: `apps/desktop/src/features/reader/EvidenceView.test.tsx`
- Test: `tests/e2e/evidence.spec.ts`

**Interfaces:**
- Consumes: verified Evidence chain/status from shared Rust.
- Produces: clear Evidence view/report/exit semantics with separated time types.

- [ ] **Step 1: Write time-label and status-copy tests**

```tsx
it('shows device server and TSA time as distinct claims', () => {
  render(<EvidenceView evidence={fixtureEvidence()} />)
  expect(screen.getByText('Gerätezeit der Finalisierung')).toBeVisible()
  expect(screen.getByText('Server-Annahmezeit')).toBeVisible()
  expect(screen.getByText('Externe TSA-Zeit')).toBeVisible()
  expect(screen.getByText('überfällig')).toBeVisible()
})
```

- [ ] **Step 2: Run integration tests and verify missing UI/report support**

Run: `cargo test --locked -p ea-reader evidence && cargo test --locked -p einsatzarchiv-cli --test evidence && pnpm --dir apps/desktop test --run EvidenceView`

Expected: FAIL because Evidence integration is incomplete.

- [ ] **Step 3: Integrate shared status without reimplementation**

Reader invokes Evidence verifier before grant/decryption when policy requires it and maps shared enum only. CLI report includes Receipt deadline, coverage, checkpoint/CTT/TSA validation, chain/renewals, and exact status; invalid/policy-overdue returns exit 13 while preserving full report. UI labels all four time types, shows status text, due/`genTime`, coverage and predecessor nodes, and explains that TSA outage/overdue does not alter finalized content. TypeScript contains no deadline arithmetic or ASN.1/COSE logic.

- [ ] **Step 4: Run status, exit-code, keyboard, and E2E tests**

Run:

```bash
cargo test --locked -p ea-reader -p einsatzarchiv-cli evidence
pnpm --dir apps/desktop test --run Evidence
pnpm --dir apps/desktop exec playwright test tests/e2e/evidence.spec.ts
```

Expected: PASS; Reader/CLI/UI agree for before/on/after deadline, invalid, late, Standard, and Renewal cases.

- [ ] **Step 5: Commit Evidence consumers**

```bash
git add crates/ea-reader crates/ea-verify apps/cli apps/desktop tests/e2e
git commit -m "feat(evidence): expose verified Evidence states"
```

### Task 6: Evidence Golden Matrix and Stage Gate

**Files:**
- Create: `tests/ea-system-tests/tests/conformance_evidence_vectors.rs`
- Create: `tests/ea-system-tests/tests/e2e_evidence_outage.rs`
- Create: `tests/ea-system-tests/tests/privacy_canaries_evidence.rs`
- Create: `docs/traceability/stage-6-gate.md`
- Modify: `docs/traceability/v0.1-requirements.csv`
- Modify: `tools/xtask/src/main.rs`
- Test: `tools/xtask/tests/stage_gate.rs`

**Interfaces:**
- Consumes: complete Stage 6 Evidence implementation.
- Produces: `xtask stage-gate 6` and evidence for primary AK 26, 27, 37 plus integrated contributions to AK 25, 35, 49, 50.

- [ ] **Step 1: Write the cumulative Evidence gate test**

```rust
#[test]
fn stage_six_gate_requires_exact_imprint_deadlines_and_renewals() {
    let gate = xtask_test::stage_gate(6);
    assert_eq!(gate.primary_acceptance_criteria, [26, 27, 37]);
    assert!(gate.scenarios.contains_all(["cbor-signature-field-imprint", "before-due", "on-due",
                                         "after-due", "late-permanently-overdue", "tsa-offline-verify",
                                         "divergent-head", "three-level-renewal"]));
}
```

- [ ] **Step 2: Run the gate and confirm missing evidence fails**

Run: `cargo test --locked -p xtask --test stage_gate stage_six`

Expected: FAIL listing absent vectors/scenarios/ledger rows.

- [ ] **Step 3: Add exhaustive Evidence vectors and privacy checks**

Fix every `esr-v1` field position/digest/signature/sorted grant hash; exact CBOR signature-field encoding; valid and wrong imprint; wrong nonce/policy/certificate/EKU/revocation; TSA failure/retry; deadline -1/0/+1 ms; late immutable overdue; pending/invalid; removed/replaced CTT; divergent head/predecessor; multi-level Renewals over exact bytes; validation without TSA network. Search TSA request/response logs, DB jobs, Object Store metadata, reports, UI, and error output for all fachliche canaries.

Update ledger to `implemented`/`integrated` only; production TSA trust, release-time certificate/revocation evidence, and full platform verification remain Stage 7.

- [ ] **Step 4: Run the complete Stage 6 gate**

Run:

```bash
pnpm test:evidence
cargo test --locked -p ea-evidence -p ea-reader -p ea-sync-server -p einsatzarchiv-cli evidence
cargo run --locked -p xtask -- test-privacy --scope evidence
cargo run --locked -p xtask -- stage-gate 6
pnpm verify:quick
```

Expected: PASS with Stage 7 external/release rows explicitly open.

- [ ] **Step 5: Commit the Stage 6 gate**

```bash
git add vectors/evidence tests docs/traceability tools/xtask
git commit -m "test(evidence): close Evidence Grade stage"
```
