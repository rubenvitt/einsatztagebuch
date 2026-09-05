# Einsatzarchiv Stage 5 Administration and Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the complete organizational lifecycle: independently anchored bootstrap, Admin-authorized Root-signed Trust changes, OS-bound operators, Registry/Writer transitions, recovery and historical re-grant ceremonies, amendments, guided recovery tests, and controlled destruction.

**Architecture:** Treat Administration, Recovery/Re-grant, and Destruction as three independently reviewed workstreams that close one formal Stage 5 gate. Trust changes use typed authorized-core proof states so neither Admin nor Root alone can expand authority. Recovery KEM, HGA signing, and two Approver signatures remain separate ports. Destruction is an append-only resumable distributed state machine; its `.eds` and evidence never rewrite chain identity.

**Tech Stack:** Shared Rust core/Writer/Reader/Sync crates, offline key containers and PKCS#11, native OS identity/key providers, Tauri 2/React 19/Ant Design 6 Admin UI, QR/fingerprint presentation, deterministic JSON reports, real server integration tests.

## Global Constraints

- Die Schlüsselwörter **MUSS**, **DARF NICHT**, **SOLL**, **SOLL NICHT** und **DARF** sind normativ zu verstehen. Ein Release darf von einer MUSS-Anforderung nicht abweichen. Eine Abweichung von SOLL erfordert eine dokumentierte Sicherheits- oder Betriebsbegründung.
- **Merker Web-Reader**, `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §12: die 14 bestehenden Tasks bleiben unverändert. Zwei neue Tasks kommen hinzu — Escrow-Erzeugung beim Enrollment (§6.6, §7.4: das HPKE-Chiffrat bindet als AAD den Hash des Reader-Zertifikats, die pseudonyme `subjectId` und die Registry-Version) und die Zwei-Approver-Öffnungszeremonie mit Re-Encryption an den neuen Vault (§7.5). Hinterlegt wird ausschließlich der X25519-KEM-Schlüssel; der Ed25519-Geräte- und Audit-Schlüssel DARF NICHT hinterlegt werden (§7.2).

  **Beide Vorentscheidungen sind getroffen** (Pre-flight in `docs/superpowers/plans/2026-08-16-einsatzarchiv-web-reader-stage-1-prerequisites.md`): erstens die Form der Zwei-Approver-Autorisierung — ENTSCHIEDEN 2026-08-17: eigene 2-of-N-Familie als v1.1, `organizationAdminAuthorization` bleibt bei Kardinalität 1; zweitens der Ablageort des Escrow-Chiffrats — ENTSCHIEDEN 2026-08-28 (DRK-213): Root-signiertes Trust-Objekt `readerKeyEscrow` in `trust/` des Archivs, repliziert und exportiert wie jedes Trust-Objekt; der Begriff „Administrationszone" ist aus Spec §7.3 gestrichen. Begründung dort: das Chiffrat öffnet nur der Recovery-KEM-Schlüssel, der jeden replizierten Recovery-Grant ohnehin entkapselt — die Replikation schafft keine neue Fähigkeit. Beide neuen Objektarten kommen in DIESEM Stage im selben v1.1-Cutover. Reihenfolge beim Enrollment: Root signiert das Reader-Zertifikat, der Browser erhält den Zertifikat-Hash, versiegelt den X25519-Schlüssel per HPKE mit der AAD nach §7.4, und Root signiert danach das `readerKeyEscrow`-Objekt.

  **Cutover:** Das erste Enrollment, das ein Objekt einer neuen Trust-Familie in den Bestand legt, lässt jeden älteren Verifizierer am gesamten Trust-Store scheitern (`crates/ea-format/src/etb.rs:45` liefert bei unbekanntem Subtype `FormatError`, `crates/ea-trust/src/catalog.rs:50-55` propagiert das für den kompletten Katalog). Die Cutover-Regel MUSS vor diesem Stage entschieden sein.
- **Merker Stale-Registry-Quittung (Ruling R62 vom 2026-08-28)**: Die dauerhafte signierte Einmal-Quittung für die Fortsetzung unter einem veralteten Registry-Kopf gehört in DIESE Stufe. Das Gate-Bullet `docs/superpowers/plans/2026-08-13-einsatzarchiv-v0-1.md:358` hatte sie der Stufe 2 zugeschrieben; Stufe 2 hat nur die Erkennung mit fail-closed-Ausgang geliefert (`crates/ea-writer/tests/stale_registry_warning.rs::a_head_that_expires_while_bound_is_acknowledgeable_and_blocks_fail_closed`, `::an_overdue_refresh_deadline_warns_without_blocking`). Zu bauen sind hier: `WriterService::acknowledge_stale_registry` im Kern, die dauerhafte Einmal-Quittung als signiertes Auditobjekt (einmalig verwendbar, Replay abgewiesen) und die Verdrahtung des Wirtsstummels `writer_acknowledge_stale_registry`, der heute `EA-DESKTOP-STALE-ACK-UNAVAILABLE` meldet. Ledgeranker: `AK-24` `v1` auf Stufe 5, Status `planned`. Begründung und Belege: `docs/traceability/stage-2-nacharbeit-2026-08-28.md`.
- **Merker Auflösungspfade der Stufe 2 (2026-08-28)**: Zwei fail-closed-Blockaden der Stufe 2 haben ihren Auflösungspfad in DIESER Stufe, weil beide eine Administrationshandlung verlangen. Erstens eine sich selbst widersprechende Abschlussmarke: `crates/ea-writer/src/recover.rs` weist sie mit `EA-WRITER-PREPARED-FINALIZATION-INCONSISTENT` ab, und `recover_pending` scheitert für diesen Bestand danach dauerhaft (Zeugen in `crates/ea-writer/tests/prepared_recovery.rs`). Zweitens eine liegengebliebene Sperrdatei, deren Übernahme zwar automatisch gelingt, deren Diagnose aber kein Werkzeug führt. Beides ist zu streng und nicht zu lax, ohne Datenverlust, aber jeweils ein manueller Schritt.
- Microsoft Access is entirely outside scope; **Access Grant/Zugriffsfreigabe** is only the signed key envelope.
- Non-goals are fixed: no live incident log, dispatch/alarm/control-center integration, patient record or identifying patient data, concurrent offline Writers, normal-app mutation/deletion of finalized content, AI summarization/OCR, public links, server-side content search, unprofiled network paths, qualified personal electronic signature, TR-ESOR certification claim, screenshot/transcription prevention, or cryptographic recall of already decrypted data.
- Product invariants apply verbatim: exactly one active Writer; never-reused predecessor-bound sequences; immutable `.eip` bytes except whole-object authorized replacement by `.eds`; amendment-only corrections; one fresh CEK/ciphertext; one signed grant per recipient; exactly one active Recovery grant before commit; no Reader/Recovery/HGA/Approver private key on Writer; no retained CEK/decryptable draft key; no server decrypt/grant key; server-independent archive verification; independent schema/format/suite versions with old bytes unchanged; separate Sync/verification/Evidence/Entry/destruction statuses; no legal overclaim from a hash chain; every active Reader initially granted; external-anchor recovery; and only Root-signed OS/device-bound operator snapshots.
- Exactly one active Writer exists. Trust, Registry, policy, revocation, and Writer changes are append-only Root-signed objects; database/config flags cannot grant authority.
- Every post-bootstrap Root ceremony binds a valid `organizationAdminAuthorization`; Root-only and Admin-only are invalid. Initial exception is limited to the independently pinned Root certificate and at least two exactly paired Admin certificate/operator-binding pairs.
- At least two active Admin keys and two appropriate Key Approvers exist before production. An Admin cannot self-authorize its own rotation; losing every Admin has no Root-only bypass.
- Admin and Key-Approver personhood is the stable 16-byte
  `authoritySubjectId`, never certificate/device/thumbprint identity. Each Admin
  certificate must equal its correlated Binding `operatorSubjectId`; rotations
  of the same externally re-identified person preserve the ID. Distinct-person
  and self-authorization checks use that ID against the unchanged Previous-Head
  state at `preTransitionSequence`.
- Operator identity is bound to device, actual OS account, non-roaming installation key, native presence, role, and Root-signed binding; identity text is never freely entered.
- Writer stores no Reader, Recovery, HGA, or Approver private key. Server stores no content-decryption or grant-signing key. Admin alone gets no content access.
- Historical re-grant requires the original Recovery grant, Recovery KEM, separate HGA signer, and an unexpired Authorization signed by two distinct active `historicalGrantApprove` subjects.
- Destruction requires two distinct active `destructionApprove` subjects and prior documented privacy approval; it never claims deletion from unknown exports/screenshots/unreachable copies.
- Final `.eip` bytes remain immutable. Amendments are new Entries. Authorized destruction uses `.eds` plus append-only authorization/transitions/attestations and a later `destructionEvidence` Entry.
- Authentic recovery always starts with the independent pre/final Trust Anchor and explicit `--trust-anchor`; no TOFU or archive-contained anchor.
- No private key, payload, decrypted content, Recovery test plaintext, nonce, personal display data, or sensitive path enters logs/reports unless explicitly permitted runtime metadata is requested.
- UI uses exact §17.4 status language and warns about irreversibility/non-recall; it makes no general legal-evidence, TR-ESOR, or complete metadata-blindness claim.
- Admin/Recovery/Destruction UI remains on Ant Design 6 with German `ConfigProvider`, shared exact tokens, `zeroRuntime: true`, statically extracted local hashed CSS, CSP without runtime/external styles, Ant `App` overlay context, direct CSR `@phosphor-icons/react` imports only, visible focus, and reduced-motion support.
- Native Admin/Reader/Writer/recovery behavior targets the global Windows/macOS/Ubuntu matrix; Stage 7 supplies complete min/max release evidence.
- v0.1 is complete only after Stage 7 and every criterion/gate passes.

Action codes and Registry effects are exact: `0 deviceApprove` pairs a direct
non-Admin certificate with Change 0; `1 deviceRevoke` has no direct target and
uses Change 1 only for non-Admin device/binding/component revocation; `2
policyChange` pairs Policy with Change 2; `3 writerTransition` pairs the
transition with Change 3; `4 operatorBinding` pairs the Binding with Change 4;
`5 adminKeyChange` uses a direct new Admin certificate only for Change 5 Effect
0 while Effect 1 revokes an already active Admin certificate; `6 rootRotation`
pairs the Root certificate with Change 6. Change 1 never revokes Admins. Direct
target and activation event have separate IDs/nonces but bind the same Previous
Head. Destruction states are only `requested`, `inProgress`,
`pendingBackupExpiry`, `completeManagedScope`, `incompleteUnreachableReplica`.

---

## Workstream A: Bootstrap, Administration, Operators, and Registry

### Task 1: Typed Admin Authorization and Root-Signed Target Service

> **Korrektur 2026-09-05 (DRK-269), gemessen gegen `e0fc423`.** Der ursprüngliche
> Abschnitt verlangte eine Autorisierungsprüfung, die die Stufen 1–3 bereits
> ausgeliefert haben. Was wirklich fehlt, sind drei Dinge: ein **öffentlicher**
> Einstieg, der einen geprüften Autorisierungszustand herausgibt, ein
> **persistenter organisationsweiter** Einmal-Speicher statt des heutigen
> prozesslokalen, und der **erste Produktionsschreiber** der
> `adminRootCeremony`-Auditzeile. Die Nachweise stehen unter „Bereits
> ausgeliefert" und „Die reale Lücke".

**Files:**
- Modify: `crates/ea-trust/src/admin_authorization.rs`
- Modify: `crates/ea-trust/src/lib.rs`
- Modify: `crates/ea-trust/src/state.rs`
- Create: `crates/ea-admin/Cargo.toml`
- Create: `crates/ea-admin/src/lib.rs`
- Create: `crates/ea-admin/src/root_ceremony.rs`
- Create: `crates/ea-admin/src/store.rs`
- Test: `crates/ea-admin/tests/authorization.rs`
- Test: `crates/ea-admin/tests/root_ceremony.rs`
- Modify: `Cargo.toml` (`members`, `[workspace.dependencies]`)
- Modify: `tools/xtask/tests/workspace.rs` (`WORKSPACE_MEMBERS`, wasm32-Klassifizierung)

**Interfaces:**
- Consumes: `ea_trust::{VerifiedTrust, SelectedRegistryHead, VerifiedAdminAuthorization}`,
  `ea_key_provider::KeyProvider`, `ea_crypto::VerificationContext::root_trust_digest`,
  `ea_format::encode_trust`, `ea_audit::LocalAuditService`, und einen frischen
  `ea_operator::OperatorSessionProof` mit `ReauthPurpose::AdminRootCeremony`.
- Produces: `ea_trust::verify_authorized_trust_target` (neuer öffentlicher Einstieg),
  `ea_trust::TrustStateStore::admin_authorization_consumed` (persistenter Einmal-Speicher),
  und `ea_admin::RootCeremonyService::publish_authorized_target`.

#### Bereits ausgeliefert — dieser Task baut es NICHT neu

- **Die Autorisierungsprüfung.** `verify_admin_authorization`
  (`crates/ea-trust/src/admin_authorization.rs:74`) ist gebaut, aber `pub(crate)`.
  Sie nimmt **Objekthashes**, keine `Parsed<…>`-Werte, und löst sie über
  `state.catalog_object(hash)` auf:

```rust
pub(crate) fn verify_admin_authorization(
    state: &PreviousHeadState,
    authorization_object_hash: ObjectHash,
    target_object_hash: ObjectHash,
    authorization_use_time: UnixMillis,
    pre_transition_sequence: ChainSequence,
    replay: &mut AdminAuthorizationReplay,
) -> Result<VerifiedAdminAuthorization, TrustError>;
```

- **Der Beweiszustand ist nicht generisch.** `VerifiedAdminAuthorization`
  (`crates/ea-trust/src/admin_authorization.rs:25`) hat ein privates Feld und fünf
  `pub const fn`-Leser. Ein Trait `AuthorizedTrustCore` existiert nirgends; die
  Typisierung leistet die geschlossene Aufzählung `DecodedTrustPayloadV1` über
  `AuthorizedTrustCoreV1<T>` (`crates/ea-format/src/trust_view.rs:18,50`). Die
  `compile_fail`-Doctests in `crates/ea-trust/src/lib.rs:12,103,319,377` pinnen, dass
  der Zustand nicht frei konstruierbar ist. Die generische Klammer `<T>` entfällt
  ersatzlos.
- **Der Kernhash.** `ea_crypto::authorized_trust_digest`
  (`crates/ea-crypto/src/digest.rs:26,61`) trägt die Domäne
  `EINSATZARCHIV-ADMIN-AUTHORIZED-TRUST-v1`; das CBOR-Präfix
  `[targetTrustSubtype, authorizedTrustCore]` baut
  `exact_authorized_core_hash` (`crates/ea-trust/src/admin_authorization.rs:374`).
- **Die geschlossene Aktionstabelle.** Zweifach kodiert und an der Signaturgrenze
  durchgesetzt: `crates/ea-crypto/src/cose.rs:2498-2524`
  (`admin_action_permits_registry_change`, `…_device_certificate`, `…_target`) und die
  Umkehrrichtung `describe_target` (`crates/ea-trust/src/admin_authorization.rs:248`),
  samt `require_non_admin_revocation_target` (`:444`) und `admin_change_target_subject`
  (`:398`). Eine dritte Kopie wird **nicht** angelegt.
- **Die historisch-inklusive Laufzeitprüfung** beim Kopfübergang:
  `verify_bound_authorization` (`crates/ea-trust/src/registry.rs:1399`), öffentlich
  erreichbar über `verify_registry_candidate` (`:516`) und
  `verify_catalogue_admission` (`crates/ea-trust/src/admission.rs:90`).
- **`ReauthPurpose::AdminRootCeremony`** (`crates/ea-operator/src/session.rs:38`).
  Beachte: `OperatorSessionProof::is_valid_for` (`:158`) prüft die Bindung **nicht** —
  der Konsument vergleicht `binding_object_hash()` (`:196`) selbst.
- **Die Auditgrammatik.** `LocalAuditActionV1::AdminRootCeremony(AdminRootContextV1)`
  existiert seit Stufe 2 (`crates/ea-format/src/local_audit.rs:536,776`, Aktionscode 7,
  Kontextmarke 5). Der Kontext trägt genau drei Felder — Autorisierungs-Objekthash,
  Ziel-Objekthash, Aktionscode. Pseudonyme Bindung und Ausgang liegen eine Ebene höher
  in `LocalAuditEventCoreFieldsV1::operator_binding_object_hash`
  (`local_audit.rs:833`) und `TypedLocalAuditEvent::outcome`
  (`crates/ea-audit/src/event.rs:172`).

#### Die reale Lücke

1. **`VerifiedAdminAuthorization` ist von außen unerreichbar.** Der Typ ist exportiert
   (`crates/ea-trust/src/lib.rs:451`), aber **keine** öffentliche Funktion gibt ihn
   zurück: `RegistryCandidate` (`crates/ea-trust/src/registry.rs:346`) bietet nur
   `registry_version`, `registry_head_hash` und `preexisting_authority`. Ohne einen
   öffentlichen Einstieg kann kein Dienst oberhalb von `ea-trust` den Beweiszustand
   führen — der Kern der Zusicherung „nur dieser Zustand kommt in die Signierseite"
   ist damit heute nicht durchsetzbar.
2. **Der Einmal-Speicher ist prozesslokal und pro Prüflauf frisch.**
   `AdminAuthorizationReplay` (`crates/ea-trust/src/admin_authorization.rs:19`) ist ein
   `BTreeSet`-Paar, das in `registry.rs:529` und `admission.rs:317` jeweils leer neu
   entsteht — in `admission.rs` ist die Replay-Prüfung dadurch wirkungslos. Organisationsweit
   und laufübergreifend existiert der Speicher **nicht**. Vorlage ist der einzige gebaute
   Einmalspeicher, die Uhrfreigabe: Port `TrustStateStore::clock_release_consumed`
   (`crates/ea-trust/src/state.rs:231`), Schlüsseltyp `ClockReleaseReplayKey` (`:104`),
   Tabelle `clock_release_replays` (`apps/server/migrations/0001_initial.sql:437`,
   „Der Primaerschluessel IST die Sperre"). Die reservierte Tabelle `replay_nonces`
   (`0001_initial.sql:304-316`) wartet ausdrücklich auf genau diesen Gebrauch: „RESERVIERT
   … sie wird derzeit von keinem Pfad beschrieben."
3. **Es gibt keinen Produktionsschreiber für `adminRootCeremony`.** Außerhalb von
   `ea-format` konstruieren nur zwei Stellen überhaupt eine `LocalAuditActionV1`:
   `crates/ea-archive-fs/src/profile_migration.rs:624,667` und
   `crates/ea-audit/src/event.rs:186` (`Login`). `AdminRootCeremony` erscheint nur in
   Testvektoren (`crates/ea-testkit/src/lib.rs:6506`). Dieser Task liefert den ersten
   Schreiber und schließt damit den Teilbeleg AK-45 aus Stufe-3-Gate §5.2 **für die
   lokale Zeremonienzeile** — nicht für `AdminAuditRecordV1`
   (`apps/server/src/admin_audit.rs:163`), das Serververwaltungsaudit der Tabelle
   `technical_admin_audit` ist eine getrennte, hier **nicht** geschlossene Lücke.

#### Schichtung: warum eine neue Crate und nicht `ea-trust`

Der Zeremoniendienst braucht `ea-audit`. `ea-audit` trägt bewusst **keine**
`ea-trust`-Kante (`crates/ea-audit/src/repository.rs:93-95`); eine Audit-Anbindung
innerhalb von `ea-trust` kehrte die Schichtung um. `crates/ea-admin` liegt deshalb
**oberhalb** von `ea-trust`, `ea-crypto`, `ea-format`, `ea-key-provider`, `ea-audit` und
`ea-operator`. `ea-trust` selbst wächst nur um öffentliche Fläche, nicht um Abhängigkeiten.

#### Signieren: der reale Port

`DigestSigner` existiert nicht, `ExactObjectBytes::new` ist `pub(crate)`
(`crates/ea-format/src/object.rs:92`), und `async` gibt es in dieser Schicht nicht
(`crates/ea-key-provider/src/contract.rs:340-344`: Async lebt nur in
`apps/desktop/src-tauri` über `spawn_blocking`). Der produktive Signierport nimmt
**inhaltstypisierte Nutzlastbytes, keinen Digest** (`contract.rs:351-374`), und
`contract.rs:235` verbietet ausdrücklich, in Produktion `ea_crypto::CoseSigner` zu
bemühen. Die Zielbytes entstehen ausschließlich über
`ea_format::encode_trust` (`crates/ea-format/src/parser.rs:123`).

- [ ] **Step 1: Write Root-only/Admin-only/core/action/replay tests**

```rust
#[test]
fn target_requires_matching_admin_authorization_and_root_signature() {
    for object in [fixtures::root_only_target(), fixtures::admin_only_target(),
                   fixtures::wrong_core_hash(), fixtures::wrong_action_code()] {
        assert!(verify_authorized_trust_target(object, fixtures::trust()).is_err());
    }
    assert!(verify_authorized_trust_target(fixtures::valid_target(), fixtures::trust()).is_ok());
}

#[test]
fn authorization_id_and_nonce_are_organization_wide_single_use_across_runs() {
    let mut store = fixtures::persistent_store();
    let first = verify_authorized_trust_target(fixtures::valid_target(), fixtures::trust()).unwrap();
    service.publish_authorized_target(first, &mut store).unwrap();

    // Zweiter Lauf, frischer Prozesszustand, DERSELBE Speicher.
    let replayed = verify_authorized_trust_target(fixtures::valid_target(), fixtures::trust()).unwrap();
    let error = service.publish_authorized_target(replayed, &mut store).unwrap_err();
    assert_eq!(error.code(), "EA-TRUST-AUTH-REPLAY");
    assert_eq!(error.to_string(), "EA-TRUST-AUTH-REPLAY");
    assert_eq!(format!("{error:?}"), "EA-TRUST-AUTH-REPLAY");
}
```

Der Fehlercode heißt **`EA-TRUST-AUTH-REPLAY`** (`TrustError::AuthReplay`,
`crates/ea-trust/src/error.rs:16,43`), nicht `EA-ADMIN-AUTH-REPLAY`: das Präfix
`EA-ADMIN-` ist bereits als **Aktionscode**-Namensraum der acht Serverzeilen vergeben
(`apps/server/src/admin_audit.rs:112-119`, `docs/traceability/stage-3-gate.md:282`);
ein Fehlercode desselben Präfixes vermischte zwei Familien in ausgelieferten
Auditzeilen. Zusicherungen laufen über den Dreifachvergleich
`code()`/`to_string()`/`{:?}` nach dem Muster
`crates/ea-trust/tests/registry_transitions.rs:17-26`.

- [ ] **Step 2: Run tests and verify the public entry point and the ceremony are absent**

Run: `cargo test --locked -p ea-admin --test authorization --test root_ceremony`

Expected: FAIL — `ea-admin` existiert nicht, `verify_authorized_trust_target` ist
nicht öffentlich, und der Einmal-Speicher überlebt keinen Prozess.

- [ ] **Step 3: Implement the public proof entry, the persistent store, and the ceremony**

```rust
// ea-trust: der oeffentliche, zielgebundene Einstieg. Keine neue Regel — er
// bezeugt die vorhandene Pruefung und gibt den Beweiszustand heraus.
pub fn verify_authorized_trust_target(
    trust: &VerifiedTrust,
    head: &SelectedRegistryHead,
    exact_target_object_bytes: &[u8],
    now: UnixMillis,
    at_sequence: ChainSequence,
) -> Result<VerifiedAdminAuthorization, TrustError>;

// ea-trust: der persistente, organisationsweite Einmal-Speicher, nach dem
// Muster von `clock_release_consumed`.
pub struct AdminAuthorizationReplayKey { /* organization_id, authorization_id, nonce */ }
trait TrustStateStore {
    fn admin_authorization_consumed(
        &mut self,
        key: &AdminAuthorizationReplayKey,
    ) -> Result<bool, StateStoreError>;
}

// ea-admin: die Zeremonie. Synchron, ueber den produktiven Port.
impl RootCeremonyService<'_> {
    pub fn publish_authorized_target(
        &self,
        authorization: VerifiedAdminAuthorization,
        target: &TrustObjectV1,
        store: &mut dyn TrustStateStore,
        actor: AuditActorProof<'_>,
    ) -> Result<ExactObjectBytes, AdminError>;
}
```

Die Reihenfolge in `publish_authorized_target` ist die Zusicherung: Einmal-Nutzung
verbrauchen, Root-Signatur über `VerificationContext::root_trust_digest`
(`crates/ea-crypto/src/cose.rs:979`) und `KeyProvider::sign(…, ContentType::TrustDigest, …)`
erzeugen, Zielbytes über `encode_trust` kodieren, dann die
`adminRootCeremony`-Zeile über `LocalAuditService::record_signed`
(`crates/ea-audit/src/event.rs:229`) schreiben — und die Bytes **erst danach**
herausgeben. Ein separates `flush` gibt es nicht: `record_signed` kodiert, signiert,
prüft die COSE gegen den Kern zurück und bucht in **einer** Transaktion, bevor es
zurückkehrt (`crates/ea-audit/src/repository.rs:48-67,128-183`). Scheitert das Audit,
wird nach dem Muster `profile_migration.rs:641-676` eine Zeile mit
`LocalAuditOutcomeV1::Failed` gebucht, und die Zielbytes werden **nicht** freigegeben.
Der Audit-Dienst wird je Kopfauswahl gebaut, weil `SignedLocalAuditService::new`
die `effective_now` beim Bauen bindet (`repository.rs:102-118`).

Initialer Root und die zwei ankergepinnten Admin-Paare laufen über die
`Initial*`-Arme von `DecodedTrustPayloadV1` (`crates/ea-format/src/trust_view.rs:51-53`,
unterschieden per `payload_wraps_core`) und werden im signierten
Bootstrap-Transkript festgehalten, statt eine lokale Auditidentität vorzutäuschen,
die es vor dem Bootstrap nicht gab.

- [ ] **Step 4: Run the full authorization attack matrix**

Run: `cargo test --locked -p ea-admin --test authorization --test root_ceremony`
und `cargo test --locked -p ea-trust`

Expected: PASS; mixed action effects (`EA-TRUST-ACTION-MISMATCH`), wrong signer
context, expired auth (`EA-TRUST-AUTH-EXPIRED`), not-yet-valid
(`EA-TRUST-AUTH-NOT-YET-VALID`), reused nonce (`EA-TRUST-AUTH-REPLAY`), same-person
self-rotation (`EA-TRUST-SELF-AUTHORIZATION`) und capability mismatch scheitern. Die
bestehenden Zeugen in `crates/ea-trust/tests/registry_attacks.rs` bleiben grün.

- [ ] **Step 5: Commit Admin/Root proof boundary**

```bash
git add crates/ea-admin crates/ea-trust Cargo.toml Cargo.lock tools/xtask
git commit -m "feat(admin): bind Root changes to Admin authorization"
```

Die neue Crate lebt an fünf Pflichtstellen: `Cargo.toml` `members`, `Cargo.toml`
`[workspace.dependencies]`, `tools/xtask/tests/workspace.rs` `WORKSPACE_MEMBERS`, die
wasm32-Klassifizierung (Positivliste in `verify_quick_commands()` **oder**
`WASM32_EXEMPT_CRATES` mit Begründung — nie beides, nie keins,
`tools/xtask/tests/workspace.rs:163`), und `Cargo.lock`. In genau diesem Task ist
`cargo metadata --format-version 1` das eine Kommando ohne `--locked`.

### Task 2: Twelve-Step Organization Bootstrap and Independent Anchors

**Files:**
- Create: `crates/ea-admin/src/bootstrap.rs`
- Create: `crates/ea-admin/src/anchor_media.rs`
- Create: `crates/ea-admin/src/genesis.rs`
- Create: `crates/ea-admin/src/production_state.rs`
- Create: `apps/cli/src/commands/organization.rs`
- Test: `crates/ea-admin/tests/bootstrap.rs`
- Test: `crates/ea-admin/tests/anchor_integrity.rs`
- Test: `apps/cli/tests/organization_init.rs`

**Interfaces:**
- Consumes: separate Root/Admin/Recovery/HGA/Approver/Writer/Server/Reader key providers, external fingerprint confirmer, Writer finalization, recovery verifier.
- Produces: `BootstrapCoordinator`, exact `organization-trust-anchor-pre-v1`, exact final anchor, Genesis, and `ProductionState::Ready` only after fresh-machine recovery test.

- [ ] **Step 1: Write bootstrap order and immutable-anchor tests**

```rust
#[tokio::test]
async fn production_state_requires_all_twelve_steps_and_fresh_recovery() {
    let mut setup = BootstrapHarness::new();
    setup.complete_through_genesis().await.unwrap();
    assert_eq!(setup.production_state(), ProductionState::BlockedRecoveryTest);
    setup.run_fresh_machine_recovery().await.unwrap();
    assert_eq!(setup.production_state(), ProductionState::Ready);
}

#[test]
fn changing_any_pre_anchor_field_requires_new_org_and_chain_ids() {
    let pre = fixtures::pre_anchor();
    let final_anchor = fixtures::final_anchor_with_changed_admin_hash();
    assert_eq!(verify_anchor_transition(pre, final_anchor).unwrap_err().code(), "EA-ANCHOR-PRE-FIELD-CHANGED");
}
```

- [ ] **Step 2: Run bootstrap tests and verify orchestration is absent**

Run: `cargo test --locked -p ea-admin --test bootstrap --test anchor_integrity && cargo test --locked -p einsatzarchiv-cli --test organization_init`

Expected: FAIL because bootstrap coordinator and init command do not exist.

- [ ] **Step 3: Implement a persisted, forward-only twelve-step ceremony**

Implement exactly: random organization/chain IDs; offline Root; two separate Admin accounts with Admin and operator-instance keys plus direct Root-signed initial certificate/binding pairs; pre-anchor written to two write-protected media and full fingerprint confirmed over second channel; separate Recovery KEM and HGA signing keys; two Approvers; two verified backups for Root/Admin/Recovery/HGA; local Writer/server/Reader keys plus normally authorized bindings; QR/full fingerprint compare; Admin-authorized Root-signed device/operator/Approver/component certificates, initial policy and Registry; Genesis sequence 0; final anchor binding unchanged pre fields, `bootstrapAnchorHash`, and Genesis hash on both media with second-channel confirmation; fresh-machine test Entry verification and Recovery decryption. Expose this orchestration as `einsatzarchiv --trust-anchor <file> organization init ...`; Stage 1's required Recovery command grammar remains unchanged.

Persist only public ceremony state and opaque key handles. Any changed pre-anchor field invalidates the setup and requires newly generated organization/chain IDs. Do not expose a skip-to-ready switch.

- [ ] **Step 4: Run happy-path, interruption, media mismatch, and foreign-Genesis tests**

Run: `cargo test --locked -p ea-admin --test bootstrap --test anchor_integrity && cargo test --locked -p einsatzarchiv-cli --test organization_init`

Expected: PASS; restart resumes the same step, unconfirmed/mismatched media block, and a self-consistent foreign archive fails at the anchor.

- [ ] **Step 5: Commit bootstrap and anchor creation**

```bash
git add crates/ea-admin apps/cli
git commit -m "feat(admin): bootstrap independently anchored organizations"
```

### Task 3: Operator Provisioning, Session Verification, and Revocation

**Files:**
- Create: `crates/ea-admin/src/operator.rs`
- Modify: `crates/ea-operator/src/session.rs`
- Create: `apps/cli/src/commands/operator.rs`
- Test: `crates/ea-admin/tests/operator_binding.rs`
- Test: `crates/ea-operator/tests/account_recreation.rs`

**Interfaces:**
- Consumes: Admin authorization, Root signer, native account/instance-key provider, encrypted local profile, and `LocalAuditService`.
- Produces: `OperatorBindingService::{provision,verify_session,revoke}`, profile commitment, and new binding requirement after account/install/key loss.

- [ ] **Step 1: Write commitment, wrong-account, and Ubuntu UID-reuse tests**

```rust
#[tokio::test]
async fn profile_commitment_must_match_decrypted_snapshot() {
    let binding = service.provision(fixtures::profile(), fixtures::account(), fixtures::auth()).await.unwrap();
    assert!(verify_operator_snapshot(fixtures::profile(), &binding).is_ok());
    assert_eq!(verify_operator_snapshot(fixtures::renamed_profile(), &binding).unwrap_err().code(),
               "EA-OPERATOR-PROFILE-COMMITMENT");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn recreated_same_uid_and_home_cannot_reuse_binding() {
    let old = harness.provision_linux_account(1001, "instance-a").await;
    harness.delete_and_recreate_account(1001, "instance-b", true).await;
    assert!(harness.verify(old).await.is_err());
}
```

- [ ] **Step 2: Run operator tests and verify lifecycle is incomplete**

Run: `cargo test --locked -p ea-admin --test operator_binding && cargo test --locked -p ea-operator --test account_recreation`

Expected: FAIL because provisioning/revocation and account recreation rules are absent.

- [ ] **Step 3: Implement external identity-check to signed binding flow**

Generate fresh 32-byte `profileCommitmentSalt`, keep display name/function/salt only in encrypted profile, compute the exact operator-profile commitment, generate a new non-roaming installation key, derive OS account binding hash through Stage 2 provider, obtain Admin authorization with action 4, and Root-sign the fixed binding core. Verify device certificate, role, effective/revoked sequence, account hash, fresh instance challenge, profile commitment, native presence, and five-minute session expiry on every action. Revocation is Root-signed from its effective sequence. Account deletion/recreation, UID reuse, restored home/app backup, lost Secret Service collection, or missing instance key always requires external re-identification, new key/auth/binding, and revocation of old binding.

Write signed, cleartext-free local audit events for every login attempt, failed re-authentication, binding replacement, and revocation. Login success binds only the pseudonymous binding/device hashes; failure uses an allowlisted technical reason code and no entered credential/account/display value. Binding change and revocation bind old/new public object hashes and effective sequence. Audit persistence failure blocks privileged action completion and is surfaced as a local resource error.

- [ ] **Step 4: Run cross-platform contract and negative binding tests**

Run: `cargo test --locked -p ea-admin -p ea-operator operator`

Expected: PASS; free operator text, wrong device/account/role, revoked binding, stale session, and restored old instance fail.

- [ ] **Step 5: Commit operator lifecycle**

```bash
git add crates/ea-admin crates/ea-operator apps/cli
git commit -m "feat(admin): provision OS-bound operators"
```

### Task 4: Policy, Registry, Device Approval, and Revocation Workflows

**Files:**
- Create: `crates/ea-admin/src/device.rs`
- Create: `crates/ea-admin/src/policy.rs`
- Create: `crates/ea-admin/src/registry.rs`
- Create: `crates/ea-admin/src/revocation.rs`
- Create: `crates/ea-admin/src/clock_release.rs`
- Create: `apps/cli/src/commands/registry.rs`
- Create: `apps/cli/src/commands/clock_release.rs`
- Test: `crates/ea-admin/tests/registry_workflows.rs`
- Test: `crates/ea-admin/tests/clock_release.rs`
- Test: `tests/ea-system-tests/tests/e2e_registry_effectiveness.rs`

**Interfaces:**
- Consumes: pending registration, external fingerprint confirmation, Admin/Root ceremony, shared `select_registry_head`, fresh Admin operator proof, and `LocalAuditService`.
- Produces: append-only policy/Registry events, device activation/revocation, opaque `VerifiedClockRelease`, and no second local time/expiry policy.

- [ ] **Step 1: Write highest-head, lease, and revocation-boundary tests**

```rust
#[test]
fn workflow_uses_shared_highest_applicable_head() {
    let line = fixtures::heads_with_future_version();
    assert_eq!(service.selected_head(&line, ChainSequence(10), now_at(500)).unwrap().version(), RegistryVersion(3));
    assert_eq!(service.selected_head(&line, ChainSequence(12), now_at(500)).unwrap_err().code(), "EA-REGISTRY-LEASE-EXHAUSTED");
}

#[test]
fn revoked_reader_receives_no_grant_at_effective_sequence() {
    assert!(service.active_readers(ChainSequence(9)).contains(&fixtures::reader_cert()));
    assert!(!service.active_readers(ChainSequence(10)).contains(&fixtures::reader_cert()));
}

#[tokio::test]
async fn clock_release_is_exact_expiring_one_use_and_never_lowers_floor() {
    let release = service.release_future_clock(fixtures::skew_context(), fixtures::admin_reauth()).await.unwrap();
    assert!(service.apply_release(fixtures::same_skew_context(), release).is_ok());
    assert!(service.apply_release(fixtures::different_wall_clock(), fixtures::replayed_release()).is_err());
    assert!(service.apply_release(fixtures::lower_floor(), fixtures::fresh_release()).is_err());
}
```

- [ ] **Step 2: Run workflow tests and verify missing administration**

Run: `cargo test --locked -p ea-admin --test registry_workflows --test clock_release && cargo test --locked -p ea-system-tests --test e2e_registry_effectiveness`

Expected: FAIL because device/policy/Registry and clock-release workflows do not exist.

- [ ] **Step 3: Implement one-action-per-event append-only administration**

Require pending request plus external fingerprint confirmation. Admin authorization and Root signature prepare exactly one direct target; a distinct activation authorization creates exactly one matching Registry change. Both bind the same Previous Head and the event is its checked version `+1`. Head 1 uses Change 2 for the initial Policy; anchor-pinned Admin pairs are external basis state, not a second change. Initial policy explicitly fixes profile, Registry age/skew/stale behavior, sequence lease, Evidence window, Reader inactivity/history, archive profiles/network failure, backup/restore, retention/destruction, free text, suites/formats. Policy version/hash/effective sequence, direct-core effective sequence, Root effective Registry version, and `preTransitionSequence` follow the Task-8 closure exactly. Revocation explains that past grants/plaintext cannot be recalled and stops new grants only from `effectiveFromSequence`. Writer, server, Reader, Admin, and CLI consume the shared opaque `RegistryCandidate`/selection proof states; no duplicate grace period or clock calculation is allowed.

When future-clock skew exceeds the bound Guard Policy relative to a deterministically selected, fully verified Receipt/Checkpoint/TSA reference, remain blocked until a newer independent reference validates or an Admin deliberately creates a documented clock release after fresh `ReauthPurpose::ClockSkewRelease`. The signed Action-6 audit context binds organization/target device, current trusted floor, exact observed wall clock, signed policy limit, Registry version and Head hash, Guard-Policy hash, the exact independent reference, closed justification code 0..2, issued/expiry times, and random nonce. Verify the active Admin certificate/binding/capability against the candidate's pre-transition state; only Outcome 1 yields an opaque `VerifiedClockRelease`. `select_registry_head` consumes it by value and commits nonce replay, Head, and floor atomically. A mismatch, expiration, Registry/policy/reference change, clock movement, or attempted floor reduction rejects it; it never waives Registry `notAfter`, `notBefore`, sequence lease, Authorization expiry, or signature errors. Without an independent reference, report `IndependentTimeUnavailable` and do not offer a release.

- [ ] **Step 4: Run gaps/forks/future/stale/clock and server-known-newer-head E2E tests**

Run: `cargo test --locked -p ea-admin --test registry_workflows --test clock_release && cargo test --locked -p ea-system-tests --test e2e_registry_effectiveness`

Expected: PASS; rollback, same-version fork, future-only, expired strict, consumed lease, clock rollback, invalid/replayed clock release, and server-known newer applicable head block correctly.

- [ ] **Step 5: Commit Registry administration**

```bash
git add crates/ea-admin apps/cli tests/ea-system-tests
git commit -m "feat(admin): manage policy registry and revocation"
```

### Task 5: Writer Transition and Restored-Writer Blockade

**Files:**
- Create: `crates/ea-admin/src/writer_transition.rs`
- Create: `apps/cli/src/commands/writer_transition.rs`
- Test: `crates/ea-admin/tests/writer_transition.rs`
- Test: `tests/ea-system-tests/tests/e2e_writer_transition.rs`

**Interfaces:**
- Consumes: trusted external head, old/new Writer certificates, Admin/Root ceremony, Writer finalization.
- Produces: `WriterTransitionService::{prepare,activate}`, Root-signed public transition and first new-Writer `keyTransition` Entry.

- [ ] **Step 1: Write transition-hash and old-Writer rejection tests**

```rust
#[tokio::test]
async fn first_new_writer_entry_binds_exact_transition_hash() {
    let transition = service.prepare(old_writer(), new_writer(), trusted_head(), reason()).await.unwrap();
    let entry = service.activate(transition).await.unwrap();
    assert_eq!(entry.manifest().writer_transition_event_hash, Some(transition.object_hash()));
    assert_eq!(server.commit(old_writer_entry_at_same_sequence()).await.unwrap_err().code(), "EA-WRITER-REVOKED");
}
```

- [ ] **Step 2: Run transition tests and verify missing service**

Run: `cargo test --locked -p ea-admin --test writer_transition && cargo test --locked -p ea-system-tests --test e2e_writer_transition`

Expected: FAIL because Writer transition workflow does not exist.

- [ ] **Step 3: Implement public transition plus encrypted chain Entry**

Bind old/new Writer certificates, effective sequence, previous trusted chain head, Admin authorization, Root signature, and reason code/public metadata in the transition. Reconcile the incoming Writer against server, Reader, or external signed checkpoint before activation. Revoke old Writer from transition sequence. Finalize `keyTransition` through the normal Writer path with encrypted organizational reason. Require exact transition hash only on the first Entry whose Writer certificate changes; reject missing/additional/mismatched hashes.

- [ ] **Step 4: Run lost-old-Writer, restored-backup, and concurrent-old/new tests**

Run: `cargo test --locked -p ea-admin --test writer_transition && cargo test --locked -p ea-system-tests --test e2e_writer_transition -- --test-threads=1`

Expected: PASS; a restored stale Writer remains blocked and only the authorized new Writer advances the chain.

- [ ] **Step 5: Commit Writer transition**

```bash
git add crates/ea-admin apps/cli tests/ea-system-tests
git commit -m "feat(admin): transition the single active Writer"
```

### Task 6: Administration UI for Requests, Fingerprints, Policy, and Recovery Health

**Files:**
- Create: `apps/desktop/src-tauri/src/commands/admin.rs`
- Create: `apps/desktop/src/features/admin/AdminPage.tsx`
- Create: `apps/desktop/src/features/admin/DeviceRequests.tsx`
- Create: `apps/desktop/src/features/admin/FingerprintApproval.tsx`
- Create: `apps/desktop/src/features/admin/PolicyEditor.tsx`
- Create: `apps/desktop/src/features/admin/RegistryHealth.tsx`
- Create: `apps/desktop/src/features/admin/DevicePosture.tsx`
- Create: `apps/desktop/src/features/admin/ClockReleaseWizard.tsx`
- Create: `apps/desktop/src/features/admin/WriterTransitionWizard.tsx`
- Test: `apps/desktop/src/features/admin/AdminPage.test.tsx`
- Test: `tests/e2e/admin-trust.spec.ts`

**Interfaces:**
- Consumes: Admin service DTOs and native re-authentication.
- Produces: separated pending/fingerprint/authorization/Root-import steps and no Admin content access.

- [ ] **Step 1: Write separation and full-fingerprint tests**

```tsx
it('does not collapse request fingerprint approval and Root import', async () => {
  render(<AdminPage bridge={pendingDeviceBridge()} />)
  expect(screen.getByText('Anfrage ausstehend')).toBeVisible()
  await user.click(screen.getByRole('button', { name: 'Fingerprint vergleichen' }))
  expect(screen.getByTestId('full-fingerprint')).toHaveTextContent(/([0-9A-F]{2}:){31}[0-9A-F]{2}/)
  expect(screen.getByRole('img', { name: 'QR-Code des vollständigen Fingerprints' })).toBeVisible()
  expect(screen.queryByText('Gerät aktiv')).not.toBeInTheDocument()
})
```

- [ ] **Step 2: Run Admin UI tests and verify missing UI**

Run: `pnpm --dir apps/desktop test --run AdminPage`

Expected: FAIL because Admin commands/components do not exist.

- [ ] **Step 3: Implement guided, explicit ceremonies**

Separate pending request, full fingerprint plus QR/second channel, Admin authorization, offline Root signing/export/import, and resulting Registry publication. Require fresh native re-authentication before Admin/Root actions and conscious key-source selection. Show two-Admin readiness, key backup state, Registry age/lease, policy profile, Evidence policy, last Recovery test, Writer transition state, and every device-posture requirement as `bestätigt`, `nicht erfüllt`, or `nicht automatisch prüfbar` with its evidence code. Never render `Unknown` as green or production-ready; export unresolved items to the Go-live evidence checklist. When future-clock skew blocks, offer the clock-release wizard only to a verified Admin, display floor/wall clock/signed limit/expiry, require an allowlisted justification plus re-authentication, and state explicitly that the release changes neither time floor, Registry expiry, nor lease. Revocation copy states that past grants/decrypted data cannot be recalled. Do not show incident content or enable Reader functions from Admin capability.

- [ ] **Step 4: Run keyboard, wrong-role, stale-session, and E2E ceremony tests**

Run: `pnpm --dir apps/desktop test --run && pnpm --dir apps/desktop exec playwright test tests/e2e/admin-trust.spec.ts`

Expected: PASS; all ceremony steps have headings/statuses, focus restoration, accessible QR alternative, and no role escalation.

- [ ] **Step 5: Commit Administration UI workstream**

```bash
git add apps/desktop tests/e2e pnpm-lock.yaml
git commit -m "feat(desktop): add guided Trust administration"
```

## Workstream B: Recovery, Historical Re-grant, Recovery Test, and Amendments

### Task 7: Offline Key Sources and Complete Recovery CLI Grammar

**Files:**
- Create: `crates/ea-key-provider/src/encrypted_container.rs`
- Create: `crates/ea-key-provider/src/pkcs11.rs`
- Create: `crates/ea-recovery/src/key_source.rs`
- Create: `apps/cli/src/commands/grant.rs`
- Create: `apps/cli/src/commands/recovery_test.rs`
- Modify: `apps/cli/src/args.rs`
- Test: `crates/ea-key-provider/tests/offline_sources.rs`
- Test: `apps/cli/tests/full_grammar.rs`

**Interfaces:**
- Consumes: explicit external anchor, encrypted key container/PKCS#11 ports.
- Produces: full required CLI commands including `grant` and `recovery-test`; no key-source auto-discovery or plaintext export fallback.

- [ ] **Step 1: Write full grammar and key-source separation tests**

```rust
#[test]
fn grant_requires_distinct_recovery_authority_authorization_and_recipient_inputs() {
    cli().args(["--trust-anchor", anchor(), "grant", entry(),
                "--recovery-key", recovery(), "--authority-key", authority(),
                "--authorization", auth(), "--recipient-cert", recipient()])
        .assert().success();
    cli().args(["--trust-anchor", anchor(), "grant", entry(), "--recovery-key", recovery()])
        .assert().failure().code(2);
}
```

- [ ] **Step 2: Run CLI tests and verify missing commands/providers**

Run: `cargo test --locked -p ea-key-provider --test offline_sources && cargo test --locked -p einsatzarchiv-cli --test full_grammar`

Expected: FAIL because encrypted-container/PKCS#11 and full commands are absent.

- [ ] **Step 3: Implement explicit key-source adapters and complete commands**

Implement the full grammar from §16.1, always requiring `--trust-anchor`. Encrypted containers use a reviewed password-based KDF/AEAD configuration pinned in the dependency ADR and restrictive file permissions; PKCS#11 uses explicit module/token/key identifiers and user presence/PIN through non-logging secure input. Never infer a Root/Recovery/HGA/Approver key by scanning media. `verify` runs before `decrypt`, `grant`, `export`, and `recovery-test`. Output supports stable text/JSON schemas and established exit codes.

- [ ] **Step 4: Run wrong-token, missing-key, target-permission, and grammar tests**

Run: `cargo test --locked -p ea-key-provider --test offline_sources && cargo test --locked -p einsatzarchiv-cli --test full_grammar`

Expected: PASS; no command accepts the archive's own anchor as implicit trust.

- [ ] **Step 5: Commit offline key sources and full CLI**

```bash
git add crates/ea-key-provider crates/ea-recovery apps/cli Cargo.toml Cargo.lock
git commit -m "feat(recovery): add explicit offline key sources"
```

### Task 8: Two-Approver Historical Re-grant

**Files:**
- Create: `crates/ea-recovery/src/historical_grant.rs`
- Create: `crates/ea-admin/src/grant_authorization.rs`
- Test: `crates/ea-recovery/tests/historical_grant.rs`
- Test: `tests/ea-system-tests/tests/e2e_historical_grant.rs`

**Interfaces:**
- Consumes: verified Entry, original Recovery grant, Recovery `KemDecapsulator`, HGA `DigestSigner`, `VerifiedGrantAuthorization`, recipient certificate, `EffectiveNow`, fresh `OperatorSessionProof`, and `LocalAuditService`.
- Produces: `HistoricalGrantService::create -> ExactObjectBytes` with no `.eip` mutation.

- [ ] **Step 1: Write separation, explicit-target, and expiry tests**

```rust
#[tokio::test]
async fn no_single_key_or_approver_can_regrant() {
    for missing in [Missing::RecoveryKem, Missing::HistoricalAuthority, Missing::ApproverA,
                    Missing::ApproverB, Missing::RecipientCertificate, Missing::FreshOperatorProof] {
        assert!(harness.create_with_missing(missing).await.is_err());
    }
}

#[tokio::test]
async fn expiry_and_clock_rollback_block_creation_and_opening() {
    let auth = fixtures::authorization_expiring_at(100);
    assert_eq!(service.create(inputs(auth), now_at(101)).await.unwrap_err().code(), "EA-GRANT-AUTH-EXPIRED");
    assert_eq!(reader.open(fixtures::stored_grant(auth), effective_now_with_floor(101)).await.unwrap_err().code(),
               "EA-GRANT-EXPIRED");
}
```

- [ ] **Step 2: Run Re-grant tests and verify workflow is absent**

Run: `cargo test --locked -p ea-recovery --test historical_grant && cargo test --locked -p ea-system-tests --test e2e_historical_grant`

Expected: FAIL because Authorization and historical grant creation are absent.

- [ ] **Step 3: Implement separate proof-state inputs**

```rust
pub async fn create(
    &self,
    entry: &VerifiedEncryptedEntry,
    original_recovery_grant: &VerifiedRecoveryGrant,
    authorization: &VerifiedGrantAuthorization,
    recovery_kem: &dyn KemDecapsulator,
    grant_authority: &dyn DigestSigner,
    recipient: &VerifiedReaderCertificate,
    effective_now: EffectiveNow,
    operator_proof: OperatorSessionProof,
) -> Result<ExactObjectBytes, RecoveryError>;
```

Authorization binds organization, Registry head/sequence, sorted explicit Entry hashes, recipient thumbprint/certificate, purpose, and `expiresAt`, with two valid active distinct-subject `historicalGrantApprove` signatures. Require native re-authentication specifically for `ReauthPurpose::HistoricalRegrant`, matching the active bound operator and current device; no generic Admin or Recovery session proof is accepted. Recompute `effectiveNow`; decapsulate CEK only from original initial Recovery grant in protected memory; HPKE-wrap to selected Reader; sign with capability `historicalGrant`; bind original Recovery grant and Authorization hashes. Zero CEK. Preserve exact `.eip` bytes. Before releasing the new grant, flush a signed `historicalRegrant` local audit event containing only Authorization, Entry, original Recovery grant, recipient certificate, and new grant hashes plus outcome. Server and Reader Stage 3/4 checks close acceptance/delivery/open expiry.

- [ ] **Step 4: Run end-to-end create/upload/deliver/open and replay-after-expiry tests**

Run: `cargo test --locked -p ea-recovery --test historical_grant && cargo test --locked -p ea-system-tests --test e2e_historical_grant`

Expected: PASS; wrong Entry/recipient/Registry/original grant, duplicate subjects, or expired/replayed authorization fails at every boundary.

- [ ] **Step 5: Commit historical re-grant**

```bash
git add crates/ea-recovery crates/ea-admin tests/ea-system-tests
git commit -m "feat(recovery): issue authorized historical grants"
```

### Task 9: Guided Recovery Test and Key-Inventory Report

**Files:**
- Create: `crates/ea-recovery/src/recovery_test.rs`
- Create: `crates/ea-recovery/src/key_inventory.rs`
- Create: `crates/ea-recovery/src/challenge.rs`
- Create: `apps/desktop/src/features/admin/RecoveryTestWizard.tsx`
- Create: `apps/desktop/src-tauri/src/commands/recovery.rs`
- Test: `crates/ea-recovery/tests/recovery_test.rs`
- Test: `apps/desktop/src/features/admin/RecoveryTestWizard.test.tsx`
- Test: `tests/e2e/recovery-test.spec.ts`

**Interfaces:**
- Consumes: independent anchor, unchanged archive copy, `ea.key-inventory/v1`, each explicit backup source, fresh `ReauthPurpose::RecoveryTest` proof, and `LocalAuditService`.
- Produces: `RecoveryTestService::run`, per-medium results, overall success only if complete, signed or hashed cleartext-free report, and durable signed audit reference.

- [ ] **Step 1: Write incomplete-inventory and challenge-domain tests**

```rust
#[tokio::test]
async fn one_missing_or_wrong_medium_fails_the_overall_test() {
    let report = service.run(fixtures::inventory_with_one_missing_medium()).await.unwrap();
    assert_eq!(report.overall, RecoveryTestOverall::Failed);
    assert_eq!(report.media.iter().filter(|m| m.result.is_failure()).count(), 1);
}

#[tokio::test]
async fn signature_backup_signs_only_recovery_test_domain() {
    let challenge = challenge_for("EINSATZARCHIV-RECOVERY-TEST-v1", random_nonce());
    assert!(service.verify_signature_backup(fixtures::admin_key(), challenge).await.is_ok());
    assert!(service.verify_signature_backup(fixtures::admin_key(), production_trust_digest()).await.is_err());
}
```

- [ ] **Step 2: Run Recovery test tests and verify workflow is absent**

Run: `cargo test --locked -p ea-recovery --test recovery_test && pnpm --dir apps/desktop test --run RecoveryTestWizard`

Expected: FAIL because key inventory/test/report/UI do not exist.

- [ ] **Step 3: Implement read-only full-inventory verification**

Verify anchor, full archive/head/Trust/Registry, and deterministic sample from every schema/suite/Writer epoch. For each Root/Admin/Writer/Reader/Recovery/server/Approver/HGA/`deletionAttest` backup, derive public key and compare expected thumbprint/certificate. Sign only a random recovery-test domain challenge for signing keys. For every Recovery backup, open the unchanged setup test Entry in protected memory, validate it, display no plaintext, then zero CEK/plaintext/challenge. For non-exportable device/hardware keys, test provider access, native presence, and certificate binding instead of export.

Report binds test ID, anchor hash, archive head, `effectiveNow`, release/schema/suite versions, pseudonymous medium ID, expected/observed thumbprint, test kind/result, and overall result. No private key or decrypted payload. After report hash/signature verification, record and flush a signed `recoveryTest` local audit event containing only the report hash and overall outcome; bind its event ID into the encrypted local status. UI prompts one medium at a time, shows individual result, and updates last/next-due status only after complete success and audit persistence.

- [ ] **Step 4: Run all key-profile, wrong-media, cleartext, and UI E2E tests**

Run:

```bash
cargo test --locked -p ea-recovery --test recovery_test
pnpm --dir apps/desktop test --run RecoveryTestWizard
pnpm --dir apps/desktop exec playwright test tests/e2e/recovery-test.spec.ts
```

Expected: PASS; archive/Registry/grants/key status remain byte-for-byte unchanged.

- [ ] **Step 5: Commit guided Recovery testing**

```bash
git add crates/ea-recovery apps/desktop tests/e2e schemas/reports
git commit -m "feat(recovery): verify every key backup safely"
```

### Task 10: End-to-End Amendment Creation

**Files:**
- Create: `crates/ea-admin/src/amendment.rs`
- Create: `apps/desktop/src/features/writer/AmendmentDraft.tsx`
- Modify: `apps/desktop/src/features/reader/AmendmentThread.tsx`
- Create: `tests/e2e/amendment.spec.ts`
- Test: `crates/ea-admin/tests/amendment.rs`

**Interfaces:**
- Consumes: Stage 4 `CorrectionReference`, Writer draft/finalization, verified Reader thread.
- Produces: `AmendmentDraftService::create_from_reference` and a normal immutable `amendment` Entry.

- [ ] **Step 1: Write exact-reference and original-preservation tests**

```rust
#[tokio::test]
async fn amendment_finalization_preserves_original_bytes_and_links_exactly() {
    let before = archive.exact_bytes(original_hash()).await;
    let draft = service.create_from_reference(fixtures::correction_reference(), "Begründung").await.unwrap();
    let amended = writer.finalize(draft, finalize_proof()).await.unwrap();
    assert_eq!(archive.exact_bytes(original_hash()).await, before);
    assert_eq!(reader.thread(original_id()).await.amendments()[0].entry_hash(), amended.entry_hash);
}
```

- [ ] **Step 2: Run amendment tests and verify Writer half is absent**

Run: `cargo test --locked -p ea-admin --test amendment && pnpm --dir apps/desktop exec playwright test tests/e2e/amendment.spec.ts`

Expected: FAIL because correction-reference import and amendment draft UI do not exist.

- [ ] **Step 3: Implement normal Writer amendment finalization**

Accept only a verified cleartext-free reference with original ID/hash/sequence, then require Writer to enter reason and structured change text; operator snapshot is current signed binding. Validate original exists and reference matches. Use normal review, irreversibility confirmation, grant plan, encryption, commit, and sync path. Reader groups all amendments without hiding/replacing original.

- [ ] **Step 4: Run multiple-amendment, wrong-reference, and original-byte tests**

Run: `cargo test --locked -p ea-admin --test amendment && pnpm --dir apps/desktop exec playwright test tests/e2e/amendment.spec.ts`

Expected: PASS; arbitrary plain reference text cannot forge a link.

- [ ] **Step 5: Commit amendment workflow**

```bash
git add crates/ea-admin apps/desktop tests/e2e
git commit -m "feat(admin): finalize linked amendments"
```

## Workstream C: Controlled Destruction

### Task 11: Destruction Authorization and Deterministic State Machine

**Files:**
- Create: `crates/ea-destruction/Cargo.toml`
- Create: `crates/ea-destruction/src/lib.rs`
- Create: `crates/ea-destruction/src/authorization.rs`
- Create: `crates/ea-destruction/src/state.rs`
- Create: `crates/ea-destruction/src/event.rs`
- Test: `crates/ea-destruction/tests/authorization.rs`
- Test: `crates/ea-destruction/tests/transitions.rs`

**Interfaces:**
- Consumes: two active `destructionApprove` signers, Registry/time, documented privacy-enable policy, fresh `ReauthPurpose::Destruction` operator proof, and `LocalAuditService`.
- Produces: `VerifiedDestructionAuthorization`, `DestructionStateMachine::apply`, exact allowed transitions, idempotent event IDs, and signed local audit reference.

- [ ] **Step 1: Write privacy gate, two-Approver, and transition-table tests**

```rust
#[test]
fn destruction_cannot_start_without_documented_privacy_enablement() {
    assert_eq!(verify_authorization(fixtures::valid_two_approver_auth(), policy_disabled()).unwrap_err().code(),
               "EA-DESTRUCTION-PRIVACY-GATE");
}

#[test]
fn only_normative_transitions_are_accepted() {
    assert!(apply(None, event(Requested)).is_ok());
    assert!(apply(Some(Requested), event(InProgress)).is_ok());
    assert!(apply(Some(InProgress), event(CompleteManagedScope)).is_ok());
    assert!(apply(Some(Requested), event(CompleteManagedScope)).is_err());
    assert!(apply(Some(InProgress), event(Requested)).is_err());
}

#[tokio::test]
async fn requested_transition_requires_matching_reauth_and_durable_audit() {
    assert!(service.request(fixtures::authorization(), fixtures::wrong_purpose_proof()).await.is_err());
    let requested = service.request(fixtures::authorization(), fixtures::destruction_proof()).await.unwrap();
    assert!(service.audit_is_signed_and_flushed(requested.audit_event_id()).await);
}
```

- [ ] **Step 2: Run destruction-core tests and verify failure**

Run: `cargo test --locked -p ea-destruction --test authorization --test transitions`

Expected: FAIL because destruction authorization/state machine do not exist.

- [ ] **Step 3: Implement closed states and event validation**

Authorization binds destruction ID, organization, Registry head/sequence, sorted
target Entry hashes plus sequences, scope, nonfachlicher legal-reason code, and
two valid current distinct-subject Approver signatures. `sorted-targets` is
nonempty and ascending by `(entryHash bytes, chainSequence numeric)`: unsigned
bytewise hash first, then unsigned numeric sequence. Target identity is entryHash;
any repeated entryHash is invalid even with a different sequence.
`chainSequence` is a signed-manifest cross-check. Equal chainSequence values with
different entryHash values are not duplicates. Authorization tests reject
unsorted tuples, exact duplicate tuples, and repeated hashes with conflicting
sequences. Policy must contain a recorded privacy decision enabling `.eds`;
otherwise block. Events bind authorization hash, unique event ID, predecessor
event hash, from/to state, trigger code, execution time, and a Root-certified
`deletionAttest` signer.

Creating `requested` additionally requires a fresh native operator proof for `Destruction`. Before returning or allowing the executor to enter `inProgress`, record and flush a signed `destruction` local audit event binding only the authorization hash, state-event hash, and outcome. A wrong-purpose/stale proof or audit write/signature failure leaves the state machine unadvanced.

Implement only: `None→requested`; `requested→inProgress`; `inProgress→pendingBackupExpiry|completeManagedScope|incompleteUnreachableReplica`; `pendingBackupExpiry→completeManagedScope|incompleteUnreachableReplica`; `incompleteUnreachableReplica→inProgress`. After `inProgress`, there is no cancel. Duplicate identical event is idempotent; same ID/hash with different bytes is a Security Event.

- [ ] **Step 4: Run all valid/invalid/replay transition tests**

Run: `cargo test --locked -p ea-destruction --test authorization --test transitions`

Expected: PASS; one Approver, duplicate subject, wrong capability/target, stale Registry, and expired/invalid signatures fail.

- [ ] **Step 5: Commit destruction state core**

```bash
git add crates/ea-destruction Cargo.toml Cargo.lock
git commit -m "feat(destruction): authorize append-only destruction states"
```

### Task 12: Destroyed Entry Stub, Replica Attestation, and Resumable Executor

**Files:**
- Create: `crates/ea-destruction/src/stub.rs`
- Create: `crates/ea-destruction/src/attestation.rs`
- Create: `crates/ea-destruction/src/executor.rs`
- Create: `crates/ea-destruction/src/reconstruct.rs`
- Modify: `crates/ea-sync-server/src/destruction.rs`
- Modify: `crates/ea-reader/src/entry_state.rs`
- Test: `crates/ea-destruction/tests/stub.rs`
- Test: `crates/ea-destruction/tests/resume.rs`
- Test: `tests/ea-system-tests/tests/e2e_destruction.rs`

**Interfaces:**
- Consumes: verified authorization, managed replica adapters, archive transaction, server delivery block, Writer finalization.
- Produces: `DestructionExecutor::{plan,resume}`, exact `.eds`, `DeletionAttestationV1`, and later `destructionEvidence` draft.

- [ ] **Step 1: Write Stub continuity and restart tests**

```rust
#[test]
fn stub_preserves_chain_identity_without_ciphertext() {
    let stub = build_stub(fixtures::verified_entry(), fixtures::authorization()).unwrap();
    assert_eq!(stub.entry_hash(), fixtures::entry_hash());
    assert_eq!(stub.signed_manifest_bytes(), fixtures::signed_manifest_bytes());
    assert_eq!(stub.writer_signature_bytes(), fixtures::writer_signature_bytes());
    assert!(!stub.exact_bytes().windows(fixtures::ciphertext().len()).any(|w| w == fixtures::ciphertext()));
}

#[tokio::test]
async fn restart_resumes_same_destruction_id_without_duplicate_delete() {
    let mut h = DestructionHarness::fault_after_first_replica().await;
    let _ = h.run().await;
    h.restart().await.resume().await.unwrap();
    assert_eq!(h.replica_delete_count("writer"), 1);
}
```

- [ ] **Step 2: Run Stub/resume tests and verify executor is absent**

Run: `cargo test --locked -p ea-destruction --test stub --test resume && cargo test --locked -p ea-system-tests --test e2e_destruction`

Expected: FAIL because Stub/attestation/executor do not exist.

- [ ] **Step 3: Implement verify-before-delete and attested distributed execution**

Accept authorization, block server delivery/re-grant, verify full pre-state and sign report, then per managed replica remove ciphertext, all grants, plaintext cache/index or schedule immutable backup expiration. Before removing each original `.eip`, create/flush/verify exact `.eds` containing original signed manifest/signature bytes, Entry/ciphertext/original object hashes, destruction ID, and Authorization hash. Remove `.eip` only after Stub durability. Collect signed attestations with pseudonymous replica ID/type, removed object hashes, result, backup deadline, and execution time.

Reconstruct current state and next action only from authorization/events/attestations; idempotently resume the same ID. Use `pendingBackupExpiry` while immutable deadlines remain, `incompleteUnreachableReplica` for known unreachable/unattested replicas, and `completeManagedScope` only when every managed object/cache is confirmed gone and every deadline elapsed. Prepare `destructionEvidence` with successes, pending/unreachable replicas, Stub hashes, and attestations; finalize through normal Writer flow. Never claim unknown exports/screenshots removed.

- [ ] **Step 4: Run immediate, backup-expiry, unreachable, invalid-Stub, and replay tests**

Run: `cargo test --locked -p ea-destruction --test stub --test resume && cargo test --locked -p ea-system-tests --test e2e_destruction -- --test-threads=1`

Expected: PASS; unauthorized file removal is `UnexplainedGap`, not authorized destruction.

- [ ] **Step 5: Commit destruction executor**

```bash
git add crates/ea-destruction crates/ea-sync-server crates/ea-reader tests/ea-system-tests
git commit -m "feat(destruction): attest resumable archive destruction"
```

### Task 13: Destruction Administration UI

**Files:**
- Create: `apps/desktop/src/features/admin/DestructionWizard.tsx`
- Create: `apps/desktop/src/features/admin/DestructionStatus.tsx`
- Modify: `apps/desktop/src-tauri/src/commands/admin.rs`
- Test: `apps/desktop/src/features/admin/DestructionWizard.test.tsx`
- Test: `tests/e2e/destruction.spec.ts`

**Interfaces:**
- Consumes: policy privacy decision, two-Approver authorization import, destruction state/report DTOs, re-authentication.
- Produces: explicit irreversible process UI using exact German state copy.

- [ ] **Step 1: Write disabled/privacy and state-copy tests**

```tsx
it('cannot start when the documented privacy decision is absent', async () => {
  render(<DestructionWizard bridge={privacyDisabledBridge()} />)
  expect(screen.getByRole('button', { name: 'Vernichtung beantragen' })).toBeDisabled()
  expect(screen.getByText(/datenschutzrechtliche Freigabe fehlt/i)).toBeVisible()
})

it.each([
  ['requested', 'beantragt'], ['inProgress', 'in Bearbeitung'],
  ['pendingBackupExpiry', 'wartet auf Backup-Frist'],
  ['completeManagedScope', 'im verwalteten Umfang abgeschlossen'],
  ['incompleteUnreachableReplica', 'bekannte Replik nicht erreichbar'],
])('maps %s to exact copy', (state, copy) => {
  render(<DestructionStatus state={state as DestructionState} />)
  expect(screen.getByText(copy)).toBeVisible()
})
```

- [ ] **Step 2: Run UI tests and verify components are absent**

Run: `pnpm --dir apps/desktop test --run DestructionWizard`

Expected: FAIL because destruction UI does not exist.

- [ ] **Step 3: Implement deliberate, non-overclaiming workflow**

Require target hashes/sequences, scope, nonfachlicher legal-reason code, known storage locations, two Approver signature imports, fresh native re-authentication, and final irreversible confirmation. Show verified pre-report, every replica/attestation, backup deadline, unreachable status, Stub/Evidence state, and exact managed-scope limitation. After `inProgress`, offer resume only, never cancel. Do not display deleted payload or claim physical/WORM/backup deletion without a valid attestation.

- [ ] **Step 4: Run keyboard, restart, pending-backup, and unreachable E2E tests**

Run: `pnpm --dir apps/desktop test --run DestructionWizard && pnpm --dir apps/desktop exec playwright test tests/e2e/destruction.spec.ts`

Expected: PASS; UI returns to the reconstructed same process after restart.

- [ ] **Step 5: Commit destruction UI workstream**

```bash
git add apps/desktop tests/e2e pnpm-lock.yaml
git commit -m "feat(desktop): guide controlled destruction"
```

### Task 14: Stage 5 Cross-Workstream Acceptance Gate

**Files:**
- Create: `tests/ea-system-tests/tests/e2e_organization_lifecycle.rs`
- Create: `tests/ea-system-tests/tests/e2e_recovery_fresh_machine.rs`
- Create: `tests/ea-system-tests/tests/privacy_canaries_admin_recovery_destruction.rs`
- Create: `docs/traceability/stage-5-gate.md`
- Modify: `docs/traceability/v0.1-requirements.csv`
- Modify: `tools/xtask/src/main.rs`
- Test: `tools/xtask/tests/stage_gate.rs`

**Interfaces:**
- Consumes: all three Stage 5 workstreams plus Writer/Reader/server.
- Produces: `xtask stage-gate 5` and evidence for primary AK 11, 12, 18, 24, 29, 30, 35, 40, 41, 44, 47, 49, 52, 53.

- [ ] **Step 1: Write cumulative Stage 5 gate test**

```rust
#[test]
fn stage_five_gate_requires_all_workstreams_and_primary_criteria() {
    let gate = xtask_test::stage_gate(5);
    assert_eq!(gate.workstreams, ["admin-trust", "recovery-regrant-amendment", "destruction"]);
    assert_eq!(gate.primary_acceptance_criteria,
        [11, 12, 18, 24, 29, 30, 35, 40, 41, 44, 47, 49, 52, 53]);
    assert!(gate.canary_findings.is_empty());
}
```

- [ ] **Step 2: Run the gate and confirm missing evidence fails**

Run: `cargo test --locked -p xtask --test stage_gate stage_five`

Expected: FAIL listing incomplete lifecycle, Recovery, destruction, OS-binding, and ledger evidence.

- [ ] **Step 3: Add full organization-lifecycle and fresh-machine evidence**

Automate bootstrap through Recovery readiness; pending device/fingerprint/Admin/Root activation; Reader revocation boundary; Registry warn/block/lease/rollback/fork/time floor; exact, expiring, one-use administrative clock release; Writer transition; amendment; new Reader without past access; selected historical re-grant with purpose-specific re-authentication; expiry at create/accept/deliver/open; every backup Recovery test; valid/invalid anchor; privacy-disabled destruction; two-Approver destruction with immediate, backup-pending, unreachable and resume branches; valid Stub versus unexplained deletion. Verify signed durable audit events for login, failed re-authentication, binding change/revocation, every post-bootstrap Admin/Root ceremony, stale-warning acceptance, export, clock release, Recovery test, re-grant, and destruction. Exercise device-posture `Pass`, `Fail`, and `Unknown`: failure blocks a production session, unknown remains visibly unresolved for Go-live, and neither is mislabeled. Search all Admin/CLI/UI/server/local reports/logs/metadata for operator display names, profile salts, key material, Recovery plaintext, and fachliche canaries.

Update ledger only to `implemented`/`integrated`. Stage 7 retains every native minimum/maximum OS case, quarterly operational rehearsal, external privacy decision, and production key custody evidence.

- [ ] **Step 4: Run the complete Stage 5 gate**

Run:

```bash
cargo run --locked -p xtask -- integration up
pnpm test:recovery
cargo test --locked -p ea-system-tests --test e2e_organization_lifecycle --test e2e_recovery_fresh_machine --test e2e_historical_grant --test e2e_destruction -- --test-threads=1
pnpm --dir apps/desktop exec playwright test tests/e2e/admin-trust.spec.ts tests/e2e/recovery-test.spec.ts tests/e2e/amendment.spec.ts tests/e2e/destruction.spec.ts
cargo run --locked -p xtask -- test-privacy --scope admin-recovery-destruction
cargo run --locked -p xtask -- stage-gate 5
pnpm verify:quick
cargo run --locked -p xtask -- integration down
```

Expected: PASS locally; full native/release/manual evidence remains explicitly open for Stage 7.

- [ ] **Step 5: Commit the Stage 5 gate**

```bash
git add tests docs/traceability tools/xtask
git commit -m "test(admin): close administration and Recovery stage"
```
