# Einsatzarchiv v0.1 Program Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver Einsatzarchiv v0.1 as an offline-first, end-to-end encrypted desktop archive with a blind self-hosted sync service, independent recovery tooling, Evidence Grade support, and release evidence for every normative acceptance criterion.

**Architecture:** Build a modular Rust-first monorepo in seven cumulative vertical stages. All security- or format-critical behavior lives in shared Rust crates; the Tauri desktop, Axum server, and CLI are adapters around those crates, and the React UI receives only presentation DTOs. Each stage has its own executable plan and gate, while the requirement ledger distinguishes `implemented`, `integrated`, and `release-verified` so an early green unit test cannot be mistaken for v0.1 acceptance.

**Tech Stack:** Rust, Tauri 2, React 19, TypeScript, Ant Design 6, Axum, PostgreSQL, S3-compatible object storage, SQLite with SQLCipher or an equivalently reviewed full-database encryption solution, pnpm, OCI on Linux `amd64`.

## Global Constraints

- Die Schlüsselwörter **MUSS**, **DARF NICHT**, **SOLL**, **SOLL NICHT** und **DARF** sind normativ zu verstehen. Ein Release darf von einer MUSS-Anforderung nicht abweichen. Eine Abweichung von SOLL erfordert eine dokumentierte Sicherheits- oder Betriebsbegründung.
- `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` ist eine freigegebene Normativquelle dieses Programms. Anwendungszuordnung: **Desktop (Tauri)** trägt Writer und Administration, **Browser (installierbare PWA)** trägt den Reader. Die Stufen-Deltas stehen in §12 dieses Specs; die Stage-1-Voraussetzungen sind in `docs/superpowers/plans/2026-08-16-einsatzarchiv-web-reader-stage-1-prerequisites.md` umgesetzt. Die dort eingeführten Trust-Objektfamilien `webBundleRelease` und das Reader-Key-Escrow sind eine v1.1-Erweiterung außerhalb Stage 1.
- Microsoft Access ist vollständig außerhalb des Scopes. Es gibt keinen Access-Treiber, keine Access-Dateiverarbeitung, keine technische Inventarisierung oder Migration einer Access-Datenbank, keinen Import historischer Einsätze, keinen `legacyImport`-Eintragstyp und kein Feld `legacy-access-import`. **Access Grant/Zugriffsfreigabe** bezeichnet ausschließlich einen signierten Schlüsselumschlag.
- Nicht-Ziele sind: laufendes Einsatztagebuch, Dispositions-/Alarmierungs-/Leitstellenintegration, Patientenakte oder identifizierende Patientendaten, mehrere gleichzeitig schreibende Offline-Writer, normale Änderung/Löschung finalisierter Inhalte, KI-Zusammenfassung/OCR, öffentliche Freigabelinks, serverseitige Inhaltssuche, unprofilierte Netzlaufwerkpfade, qualifizierte persönliche elektronische Signatur, TR-ESOR-Zertifizierungsbehauptung, Screenshot-/Abschriftverhinderung und kryptografischer Rückruf bereits entschlüsselter Daten.
- Es existiert zu einem Zeitpunkt genau ein autorisierter aktiver Writer.
- Jeder Ketteneintrag besitzt eine nie wiederverwendete Sequenz und bindet den direkten Vorgänger-Hash.
- Finalisierte `.eip`-Bytes werden niemals geändert oder überschrieben. Eine autorisierte Vernichtung darf nur das vollständige Objekt entfernen und durch einen getrennten `.eds` ersetzen.
- Korrekturen sind neue signierte Nachträge; das Original bleibt sichtbar.
- Ein fachlicher Payload wird genau einmal mit einem neuen zufälligen CEK verschlüsselt.
- Jeder Empfänger erhält einen getrennten, signierten Grant für denselben CEK.
- Ein produktiver Eintrag besitzt vor dem Commit genau einen gültigen Grant für den aktiven Recovery-Empfänger.
- Auf einem Writer-Gerät existiert kein privater Reader-, Recovery-, Historical-Grant-Authority- oder Key-Approver-Schlüssel.
- Nach Finalisierung persistiert der Writer weder CEK noch entschlüsselbaren Entwurfsschlüssel.
- Der Sync-Server besitzt keine privaten Schlüssel zur Entschlüsselung von Einsätzen oder Erzeugung gültiger Grants.
- Das lokale Archiv ist ohne Server und ohne mutable Statusdatenbank verifizierbar.
- Schema-, Format- und Krypto-Version werden unabhängig geführt; alte Objekte bleiben byteidentisch.
- Die fünf v1-Payloads verwenden ausschließlich die im Payload-Wire-Nachtrag
  und `schemas/payload/v1/payload.cddl` geschlossenen 11-Positionen-CBOR-Arrays.
  Zeitzonen werden mit `jiff 0.2.35`, `jiff-tzdb 0.1.8` und eingebetteter IANA
  tzdb `2026c` reproduzierbar validiert; normale Autorenlisten bleiben geordnet
  wie erfasst und werden nicht als Report-Sets behandelt.
- Sync-, Verifikations-, Evidence-, Eintrags- und Vernichtungsprozessstatus werden getrennt dargestellt.
- Eine Hash-Kette allein wird nicht als rechtliche oder organisatorische Revisionssicherheit beworben.
- Jeder zur gebundenen Registry-Version aktive Reader erhält vor dem Commit genau einen initialen Grant.
- Authentische Offline-Recovery beginnt an einem unabhängig verwahrten Trust Anchor; ein Trust Bundle aus dem zu prüfenden Archiv allein begründet kein Vertrauen.
- Jeder `operator`-Snapshot stammt aus einem gültigen Root-signierten, geräte- und OS-kontogebundenen Operator-Binding und ist kein freies Eingabefeld.
- Writer, Reader, Administration und Recovery-/Admin-CLI müssen auf allen von Microsoft unterstützten Windows-11-Releases `x86_64`, der aktuellen und vorherigen macOS-Hauptversion auf `arm64` sowie auf `x86_64`, sofern Intel offiziell unterstützt wird, und Ubuntu 24.04 LTS `x86_64` freigegeben werden. Der Sync-Server ist ein Linux-OCI-Container auf `amd64`. Windows on Arm und Linux `arm64` sind außerhalb v0.1.
- Jedes Release enthält eine signierte, versionierte `support-matrix.json`, die je Kombination minimale und maximale OS-Version beziehungsweise Build, Architektur, Installerformat, Key-Provider und getestetes lokales Dateisystem pinnt. Jede Kombination durchläuft Krypto-/Format-Goldens sowie Key-Provider-, Dateisystem- und Installer-Smokes; vollständige E2E-Gates laufen auf den gepinnten Minimal- und Maximalversionen jeder Architektur.
- Ant Design 6 is the component base. The exact minor/patch is lockfile-pinned. Desktop uses German `ConfigProvider`, shared tokens `eaInk #172033`, `eaSurface #F5F7FA`, `eaAction #245EA8`, `eaDanger #C6352B`, `eaVerified #187255`, `eaWarning #A65F00`, `zeroRuntime: true`, statically extracted local hashed CSS from exactly those tokens, a CSP forbidding runtime style injection/external styles, Ant `App` context for overlays, and only direct CSR imports from `@phosphor-icons/react`. No Webfonts, `react-icons`, wildcard/dynamic icon catalog, color-only/icon-only status, hidden focus, or ignored `prefers-reduced-motion`.
- Kryptografische oder formatkritische Logik DARF NICHT in TypeScript oder separat im Server nachgebaut werden. Desktop, Server und CLI verwenden dieselben Rust-Crates und dieselben Testvektoren.
- Private Schlüssel, Payloads, entschlüsselte Inhalte, Nonces, Klartext-Einsatznummern, Orte, Namen und Freitexte dürfen nicht in Logs, Dumps oder unverschlüsselten Konfigurationen erscheinen. Temporäre Klartextdateien sind verboten; lokale Datenbanken sind vollständig verschlüsselt.
- Verbindliche Statusbegriffe bleiben exakt: Sync `lokal gesichert`, `Upload ausstehend`, `synchronisiert`, `Fehler`; Verifikation `verifiziert`, `Lücke`, `fehlender Grant`, `unbekannter Schlüssel`, `nicht darstellbares Schema`, `ungültig`; Evidence `vollständig`, `ausstehend`, `überfällig`, `ungültig`; Eintrag `vorhanden`, `autorisiert vernichtet`, `ungeklärte Lücke`; Vernichtung `beantragt`, `in Bearbeitung`, `wartet auf Backup-Frist`, `im verwalteten Umfang abgeschlossen`, `bekannte Replik nicht erreichbar`.
- Das Produkt behauptet weder pauschale gerichtliche Beweiskraft noch TR-ESOR-Zertifizierung noch vollständige Metadatenblindheit.
- v0.1 gilt erst nach Stufe 7 und Erfüllung aller Abnahmekriterien als fertig.

---

## Scope Decision: A Plan Suite, Not a Monolith

The 1,841-line design contains seven independently accepted vertical stages and several separately rejectable security subsystems. Execute the following plans in order; do not start a later stage until the preceding stage gate is committed and its interfaces are stable.

1. [`2026-08-13-einsatzarchiv-stage-1-trust-core-format.md`](2026-08-13-einsatzarchiv-stage-1-trust-core-format.md) — Rust trust core, all six object families, vectors, trust/registry/chain verification, and recovery CLI baseline.
2. [`2026-08-13-einsatzarchiv-stage-2-offline-writer.md`](2026-08-13-einsatzarchiv-stage-2-offline-writer.md) — encrypted draft, master data, durable local archive transaction, network profile, and Writer UI.
3. [`2026-08-13-einsatzarchiv-stage-3-blind-sync.md`](2026-08-13-einsatzarchiv-stage-3-blind-sync.md) — signed protocol, PostgreSQL/S3 persistence, atomic commit, receipts, standard checkpoints, and Writer queue.
4. [`2026-08-13-einsatzarchiv-stage-4-reader.md`](2026-08-13-einsatzarchiv-stage-4-reader.md) — incremental replication, verification-before-decryption, encrypted index, local search, export, and Reader UI.
5. [`2026-08-13-einsatzarchiv-stage-5-administration-recovery.md`](2026-08-13-einsatzarchiv-stage-5-administration-recovery.md) — bootstrap/admin/operator/registry, Writer transition, historical re-grant, recovery test, amendments, destruction, and Admin UI. Its three workstreams are reviewed independently but close one formal Stage 5 gate.
6. [`2026-08-13-einsatzarchiv-stage-6-evidence-grade.md`](2026-08-13-einsatzarchiv-stage-6-evidence-grade.md) — RFC-3161/RFC-9921 CTT, deterministic evidence states, immutable evidence chain, renewals, and reports.
7. [`2026-08-13-einsatzarchiv-stage-7-release-hardening.md`](2026-08-13-einsatzarchiv-stage-7-release-hardening.md) — signed support matrix, exhaustive platform/fault/performance gates, supply chain, backup/restore, security review, and Go-live evidence.

## Locked Repository Structure

Create this structure incrementally. Do not collapse the trust core into one crate and do not let adapters depend on one another.

```text
Cargo.toml
Cargo.lock
rust-toolchain.toml
deny.toml
package.json
pnpm-workspace.yaml
pnpm-lock.yaml
apps/
  desktop/
    src/{app,bridge,design,components,features}/
    src-tauri/src/{commands,main.rs,state.rs}
  server/
    src/{http,adapters,main.rs,config.rs,router.rs}
    migrations/
  cli/src/{commands,main.rs,args.rs,output.rs}
crates/
  ea-types/
  ea-cbor/
  ea-crypto/
  ea-format/
  ea-schema/
  ea-time/
  ea-trust/
  ea-chain/
  ea-archive/
  ea-verify/
  ea-key-provider/
  ea-operator/
  ea-local-store/
  ea-audit/
  ea-draft/
  ea-writer/
  ea-sync-protocol/
  ea-sync-client/
  ea-sync-server/
  ea-reader/
  ea-admin/
  ea-recovery/
  ea-destruction/
  ea-evidence/
  ea-ui-contracts/
  ea-testkit/
schemas/{archive,payload,reports,transformations}/
schemas/compatibility-matrix.json
vectors/{crypto,format,trust,grants,receipts,evidence}/
tests/ea-system-tests/{Cargo.toml,src,tests}/
tests/e2e/                         # Playwright specifications only
fuzz/fuzz_targets/
tools/xtask/
ops/{container,compose,monitoring,backup-restore,release,runbooks}/
docs/{adr,format,security,operations,traceability}/
```

Dependency direction is one way:

```text
ea-types
  -> ea-cbor | ea-crypto | ea-schema | ea-time
  -> ea-format
  -> ea-trust | ea-chain | ea-archive
  -> ea-verify
  -> ea-key-provider | ea-operator | ea-local-store | ea-audit
  -> ea-writer | ea-sync-* | ea-reader | ea-admin | ea-recovery | ea-destruction | ea-evidence
  -> desktop | server | cli
```

`ea-archive` does not depend on `ea-verify`; application services compose both. `ea-writer` does not depend on `ea-sync-client`; sync discovers only committed archive bytes. TypeScript consumes generated view contracts and never parses, hashes, signs, verifies, encrypts, or decrypts archive objects.

## Stable Cross-Stage Interfaces

Stage 1 owns these newtypes and validated-state boundaries. Constructors for `Verified*`, `Prepared*`, and `Committed*` types remain private to the producing crate.

```rust
pub struct OrganizationId(pub [u8; 16]);
pub struct ChainId(pub [u8; 16]);
pub struct RecordId(pub [u8; 16]);
pub struct ChainSequence(pub u64);
pub struct RegistryVersion(pub u64);
pub struct UnixMillis(pub i64);
pub struct Hash32(pub [u8; 32]);
pub struct EntryHash(pub Hash32);
pub struct ObjectHash(pub Hash32);
pub struct CertificateHash(pub ObjectHash);
pub struct KeyThumbprint(pub Hash32);
pub struct ExactObjectBytes(std::sync::Arc<[u8]>);

pub struct ParsedArchiveObject { /* private validated representation */ }
pub struct VerifiedTrust { /* private proof state */ }
pub struct SelectedRegistryHead { /* private proof state */ }
pub struct VerifiedClockRelease { /* private one-use proof state */ }
pub struct VerifiedChain { /* private proof state */ }
pub struct VerifiedEncryptedEntry { /* private proof state */ }
pub struct VerifiedGrantForRecipient { /* private proof state */ }
pub struct VerifiedSyncBatch { /* private proof state */ }
pub struct VerifiedDecryptedRecord { /* private proof state */ }
pub struct AuthenticatedDevice { /* private proof state */ }
pub struct OperatorSessionProof { /* private proof state */ }
pub struct DevicePostureReport { /* typed pass/fail/unknown evidence */ }
pub enum AuditActorProof<'a> {
    AuthenticatedDevice(&'a AuthenticatedDevice),
    OperatorSession(&'a OperatorSessionProof),
}
pub struct SignedLocalAuditEvent { /* exact verified durable bytes */ }
pub struct StaleRegistryAcknowledgement { /* private one-use proof state */ }
pub struct PreparedFinalization { /* private proof state */ }
pub struct CommittedEntry { /* private proof state */ }
```

Normative status enums live in `ea-types`; localized German copy lives in generated UI contracts:

```rust
pub enum SyncStatus { LocallySecured, UploadPending, Synchronized, Error }
pub enum VerificationStatus { Verified, Gap, MissingGrant, UnknownKey, UnsupportedSchema, Invalid }
pub enum EvidenceStatus { Complete, Pending, Overdue, Invalid }
pub enum EntryStatus { Present, AuthorizedDestroyed, UnexplainedGap }
pub enum DestructionState {
    Requested,
    InProgress,
    PendingBackupExpiry,
    CompleteManagedScope,
    IncompleteUnreachableReplica,
}
```

The stable service seams are:

```rust
pub enum RegistrySelectionOutcome {
    Selected(SelectedRegistryHead),
    Advanced(AdvancedRegistryHead),
    PendingFuture(PendingFutureSuccessor),
}

pub fn decode_exact_object(bytes: &[u8])
    -> Result<ParsedArchiveObject, FormatError>;
pub fn object_hash(bytes: &ExactObjectBytes) -> ObjectHash;
pub fn verify_trust(
    anchor: &TrustAnchorV1,
    source: &dyn TrustObjectSource,
    snapshot: TrustStateSnapshot,
) -> Result<VerifiedTrust, TrustError>;
pub fn verify_registry_candidate(
    trust: &VerifiedTrust,
    proposed_sequence: ChainSequence,
) -> Result<RegistryCandidate, RegistryError>;
pub fn verify_clock_release(
    candidate: &RegistryCandidate,
    local_time: &mut LocalTimeBlock<'_>,
    exact_audit_bytes: &[u8],
) -> Result<VerifiedClockRelease, ClockReleaseError>;
pub fn select_registry_head(
    candidate: RegistryCandidate,
    local_time: LocalTimeBlock<'_>,
    release: Option<VerifiedClockRelease>,
) -> Result<RegistrySelectionOutcome, RegistryError>;
pub fn verify_chain(objects: &ArchiveInventory, trust: &VerifiedTrust)
    -> Result<VerifiedChain, ChainError>;
pub fn verify_archive(source: &dyn ArchiveSource, anchor: &TrustAnchorV1, options: VerifyOptions)
    -> Result<VerificationReportV1, VerifyError>;

#[async_trait::async_trait]
pub trait KeyProvider: Send + Sync {
    async fn generate(&self, purpose: KeyPurpose, protection: KeyProtectionProfile)
        -> Result<KeyHandle, KeyError>;
    async fn sign(&self, handle: &KeyHandle, digest: Hash32)
        -> Result<CoseSign1Bytes, KeyError>;
    async fn hpke_open(&self, handle: &KeyHandle, input: HpkeOpenInput)
        -> Result<SecretBytes, KeyError>;
    async fn wrap_secret(&self, purpose: SecretPurpose, secret: SecretBytes)
        -> Result<WrappedSecret, KeyError>;
    async fn delete(&self, handle: &KeyHandle) -> Result<(), KeyError>;
    async fn contains(&self, handle: &KeyHandle) -> Result<bool, KeyError>;
}

#[async_trait::async_trait]
pub trait DevicePostureProvider: Send + Sync {
    async fn report(&self) -> Result<DevicePostureReport, KeyError>;
}

#[async_trait::async_trait]
pub trait LocalAuditService: Send + Sync {
    async fn record_signed(&self, actor: AuditActorProof<'_>, event: TypedLocalAuditEvent)
        -> Result<SignedLocalAuditEvent, AuditError>;
}
```

The opaque `RegistryCandidate`, `VerifiedClockRelease`,
`VerifiedAdminAuthorization`, and selected-head outcomes are created only by
their full verification paths. Selection consumes a Clock Release by value and
atomically commits Head/floor/replay state; callers cannot manufacture a waiver
or bypass candidate-bound selection through a separate clock-release shortcut. The
Task-8 prerequisite and Runtime Phase B are the exact linked plans
[`2026-08-14-einsatzarchiv-task-8-trust-time-normative-correction.md`](2026-08-14-einsatzarchiv-task-8-trust-time-normative-correction.md)
and
[`2026-08-14-einsatzarchiv-task-8-trust-time-implementation.md`](2026-08-14-einsatzarchiv-task-8-trust-time-implementation.md).

No later stage may bypass these proof-state types by accepting raw bytes where a verified type is required.

The public v1 archive seam is deliberately non-relaxable. It applies this exact
two-phase preflight before any full decode or input-sized allocation; file names
never select the family:

```text
MAX_ARCHIVE_OBJECT_BYTES_V1 = 4_194_304
FIXED_PREFIX_V1 = 85 44 45 41 31 00 TT 01 80
TT = 01..06
EIP_MAX_RAW_BYTES_V1 = 2_097_152
EAG_MAX_RAW_BYTES_V1 = 65_536
ESR_MAX_RAW_BYTES_V1 = 65_536
ECP_MAX_RAW_BYTES_V1 = 4_194_304
ETB_MAX_RAW_BYTES_V1 = 4_194_304
EDS_MAX_RAW_BYTES_V1 = 262_144
```

First require `bytes.len() <= MAX_ARCHIVE_OBJECT_BYTES_V1` without inspecting
CBOR. Then inspect only `FIXED_PREFIX_V1`, immediately enforce the selected
family raw-byte cap, and only then run full deterministic-CBOR validation plus
outer/body type correlation. `ea-cbor::ParserLimits::V1` owns structural CBOR
budgets; `ea-format` owns family raw-byte and semantic limits.

## Specification Closure Before Wire Implementation

The approved design fixes `.eip`, `.eag`, and `.esr` in sufficient positional detail, but leaves complete positional CDDL unspecified for several `.ecp`, `.eds`, `.etb`, sync cursor, destruction-report, key-inventory, and JSON-report payloads. Stage 1 Task 2 must add a normative design addendum and golden byte fixtures before implementing those encoders. The addendum must preserve the design's already fixed fields and supply exact array positions, integer tags, sorting, optionality, size limits, signature input, and unknown-field behavior. No implementer may infer a private wire representation inside production code.

Before Stage 1 Task 7 implementation, the normative payload correction closes
all five plaintext families in
`docs/superpowers/specs/2026-08-14-einsatzarchiv-v0-1-payload-wire-addendum.md`,
`schemas/payload/v1/payload.cddl`, and five literal hex fixtures. It also fixes
the canonical bundled-timezone route and the later uniqueness-key year basis.
Task 7 consumes those committed bytes and rules; it does not invent a JSON or
Rust wire, and Stage 2 alone enforces cross-record incident-number uniqueness
under the Writer/repository lock.

Tool and dependency versions not fixed by the design are selected once in Stage 1 Task 1 using current compatibility and security evidence, then written as exact pins to `rust-toolchain.toml`, workspace manifests, `packageManager`, lockfiles, the OCI base digest, and an ADR. Later plans consume those committed pins and do not silently update them.

## Requirement Ledger

Stage 1 creates `docs/traceability/v0.1-requirements.csv` with these columns:

```csv
requirement_id,spec_reference,normative_summary,primary_stage,contributing_stages,plan_task,automated_evidence,manual_or_external_evidence,status
```

Allowed status values are exactly `planned`, `implemented`, `integrated`, `release-verified`, and `blocked-external`. A task may mark only its own implementation/integration evidence. Stage 7 is the sole stage allowed to mark `release-verified`.

Primary acceptance-criterion ownership is exhaustive and non-overlapping:

| Stage | Primary AK |
|---|---|
| 1 – Trust core and format | 4, 5, 6, 9, 14, 16, 17, 20, 38, 51 |
| 2 – Offline Writer | 1, 2, 3, 15, 23, 25, 28, 34, 39, 46, 48, 54 |
| 3 – Blind Sync | 7, 8, 13, 33, 36, 45, 50 |
| 4 – Reader | 10, 42, 43 |
| 5 – Administration and Recovery | 11, 12, 18, 24, 29, 30, 35, 40, 41, 44, 47, 49, 52, 53 |
| 6 – Evidence Grade | 26, 27, 37 |
| 7 – Release hardening | 19, 21, 22, 31, 32 |

Cross-stage criteria must remain open until all named contributors are integrated:

| AK | Required stages |
|---|---|
| 14, 38 | 1 core/CLI; 3 server export; 5 anchor/recovery; 7 fresh-machine/platform proof |
| 15, 34 | 2 transaction/recovery; 7 exhaustive fault/restore matrix |
| 17 | 1 schema/suite; 4 presentation; 7 cross-version matrix |
| 23, 53 | 1 provider interface; 2/4 device use; 5 binding/reauth; 7 OS/Ubuntu negatives |
| 25 | 2 Writer block; 3 server head/receipt; 6 checkpoint; 7 restore proof |
| 30, 41, 44 | 1 formats; 3 server deletion; 4 stub state; 5 process; 7 privacy/go-live gate |
| 33 | 1 grant plan; 2 local commit; 3 atomic server commit; 4 verification |
| 35, 49 | 1 head/time evaluator; 2 Writer; 3 server; 5 registry administration; 6 signed time |
| 39 | 2 backend transaction; 3 statuses; 7 platform/backend matrix |
| 40 | 1 grant format; 3 acceptance/delivery; 4 decapsulation; 5 multi-party workflow |
| 45 | 3 technical separation/audit; 5 certificate authority; 7 operational proof |
| 48 | 2 atomic migration; 5 authorization; 7 backend/failure matrix |
| 50 | 1 receipt format; 3 one-time creation; 6 evidence qualification |
| 51 | 1 vectors; 2 generation; 3 verification; 4 decapsulation; 7 interoperability |
| 54 | 1 ID/sequence rules; 2 local commit; 3 concurrency/replay |

Unnumbered gates in §§21, 22, and 25 are ledger rows too; acceptance criteria 1–54 do not replace them.

## Stage Gates

### Stage 1 Gate

- All six object families, domain-separated digests, COSE signer resolution, trust/registry/anchor validation, chain verification, schema/suite compatibility, and parser limits are implemented once in shared Rust.
- Public CDDL/format documentation plus golden, negative, property, fuzz, and cross-version tests pass.
- CLI `verify`, `list`, `decrypt`, `report`, and encrypted `export` require an external trust anchor and have stable deterministic JSON and exit behavior.

### Stage 2 Gate

- Exactly one encrypted draft survives crashes; discard and finalization cross the irreversible boundary only at confirmed `draftDEK` deletion.
- Initial grants publish before `.eip`; prepared recovery finishes the same bytes without fresh randomness or reused sequence.
- Standard-profile stale-Registry continuation requires a non-bypassable warning, fresh re-authentication, and a durable signed one-use audit acknowledgement; strict/Evidence/lease failures remain blocked.
- Native posture reports never turn an unreportable disk-encryption, account-lock, screen-lock, or patch check into a pass.
- Local and controlled-network profiles are fail-closed, health-checkable, and atomically migratable.
- The Writer cannot decrypt committed content and returns immediately to a blank form.

### Stage 3 Gate

- RFC-9421 signed requests use single-use nonces and request IDs over TLS 1.3.
- Real PostgreSQL and S3-compatible integration tests prove all-or-nothing Entry plus grants, fork/replay protections, invisible orphans, and byte-identical Receipt replay.
- The server has no content, grant-signing, or registry authority; privileged actions are cleartext-free audited.

### Stage 4 Gate

- The §14.1 verification sequence completes before any HPKE decapsulation.
- Incremental sync advances its cursor only after durable verified storage and stops on a wrong start head, gap, or fork.
- Missing grant, unsupported schema, invalid object, and authorized destruction remain distinct technical states.
- Encrypted local search, inactivity lock, audited single export, and two-reader interoperability pass.

### Stage 5 Gate

- The full twelve-step setup, pre/final anchors, two initial admin pairs, admin authorization plus Root signature, operator binding, registry policy, revocation, and Writer transition are end-to-end complete.
- Administrative clock release is signed, exact-context, expiring, one-use, audited, and cannot lower the trusted floor or waive Registry expiry/lease.
- Historical re-grant keeps Recovery KEM, HGA signer, and two Approvers separate and enforces `expiresAt` at creation, acceptance, delivery, and opening.
- Recovery test, amendments, and the destruction state machine including `.eds`, attestations, and privacy enablement are complete.

### Stage 6 Gate

- Standard profile checkpoints and Evidence Grade RFC-9921 `3161-ctt` use the exact specified message imprint.
- Receipt times alone anchor pending/complete/overdue/invalid classification; a late token can never restore complete status.
- Evidence predecessor links and renewals over exact prior bytes verify offline without a live TSA.

### Stage 7 Gate

- Signed/versioned support matrix, minimum/maximum platform E2E, installers, key-provider/filesystem smokes, exhaustive fault injection, performance, backup/restore, privacy, supply chain, BSI review, independent security review, and §21 Go-live evidence all pass.
- Every ledger row is `release-verified` or explicitly `blocked-external`; a `blocked-external` row prevents production release.

## Program Verification Commands

Stage 1 establishes these stable root commands through `package.json` and `tools/xtask`; subsequent plans add coverage behind them without renaming them:

```bash
pnpm verify:quick
pnpm test:core
pnpm test:golden
pnpm test:property
pnpm test:fuzz
pnpm test:server
pnpm test:reader-sync
pnpm test:fault -- --matrix ops/release/support-matrix.json
pnpm test:interop -- --matrix ops/release/support-matrix.json
pnpm test:e2e -- --matrix ops/release/support-matrix.json
pnpm test:privacy
pnpm test:evidence
pnpm test:recovery
pnpm test:performance
pnpm verify:supply-chain
pnpm verify:release -- --matrix ops/release/support-matrix.json --evidence-dir ops/release/evidence/v0.1
```

`verify:quick` must run, at minimum:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --locked
pnpm --recursive typecheck
pnpm --recursive test --run
pnpm --recursive build
```

## Commit Discipline

Each numbered task in a stage plan ends with one focused commit. Never combine implementation from different stages in one commit. Before a stage gate commit, run that plan's focused tests, `pnpm verify:quick`, and the cumulative stage gate. Use commit messages shown in the stage plan; do not commit generated release evidence containing private keys, Fachklartext, host paths, or unredacted operator identity.

## Coverage Self-Review Record

This suite was checked against every normative design section before handoff:

| Spec area | Plan coverage |
|---|---|
| §§1–5 scope, invariants, platform matrix, architecture, UI system | Program constraints; Stages 1, 2, and 7 |
| §§6–7 roles, key separation, operator identity, organization policy | Stages 1, 2, 3, and 5; native/release matrix in Stage 7 |
| §§8–9 domain model, master data, draft, review, discard, atomic finalization | Stages 1 and 2; amendment/destruction evidence in Stage 5 |
| §§10–11 crypto, grants, six object families, parser limits, archive/profile health | Stage 1 exact formats and vectors; Stage 2 durable profiles; later object consumers in Stages 3–6 |
| §12 bootstrap, Trust Registry, revocation, Writer transition, key providers | Shared evaluator in Stage 1; providers in Stage 2; full lifecycle in Stage 5; OS proof in Stage 7 |
| §13 signed Sync API, commit, persistence, status | Stage 3, with historical/destruction integrations in Stage 5 and Evidence jobs in Stage 6 |
| §14 Reader verification, cache/index, amendments, export, incremental Sync | Stage 4 plus Writer amendment completion in Stage 5 |
| §§15–16 Evidence, Recovery, re-grant, destruction, guided Recovery test | Stage 1 formats/CLI baseline; Stage 5 Recovery/destruction; Stage 6 Evidence; final drills in Stage 7 |
| §§17–19 UX copy/accessibility, privacy, error/security events/reconstruction | Stage-specific Desktop tasks and privacy/fault gates in Stages 2–7 |
| §§20–22 security, offline/performance/robustness/maintenance, operations, verification | Each owning stage plus cumulative Stage 7 release verification |
| §§23–27 AK 1–54, stages, risks, standards, PRD traceability | Exhaustive ledger, primary/cross-stage map, all stage gates, and final signed release decision |

Automated red-flag scanning returned zero matches, and every numbered task has concrete file paths, test code, failure/pass expectations, implementation details, verification commands, and a focused commit. Type/interface review uses one crate/path vocabulary (`ea-verify`, `ea-sync-protocol`, `apps/server`, `tests/ea-system-tests`), one status enum set, and proof-state names consistently across all seven plans. Stage 1 deliberately closes the design's remaining `.ecp/.eds/.etb` and report wire gaps before encoding; Stage 3 does the same for every API body/cursor/error before server implementation.
