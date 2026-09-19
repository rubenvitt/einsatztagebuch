# Einsatzarchiv Stage 5 Administration and Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the complete organizational lifecycle: independently anchored bootstrap, Admin-authorized Root-signed Trust changes, OS-bound operators, Registry/Writer transitions, recovery and historical re-grant ceremonies, amendments, guided recovery tests, and controlled destruction.

**Architecture:** Treat Administration, Recovery/Re-grant, and Destruction as three independently reviewed workstreams that close one formal Stage 5 gate. Trust changes use typed authorized-core proof states so neither Admin nor Root alone can expand authority. Recovery KEM, HGA signing, and two Approver signatures remain separate ports. Destruction is an append-only resumable distributed state machine; its `.eds` and evidence never rewrite chain identity.

**Tech Stack:** Shared Rust core/Writer/Reader/Sync crates, offline key containers and PKCS#11, native OS identity/key providers, Tauri 2/React 19/Ant Design 6 Admin UI, QR/fingerprint presentation, deterministic JSON reports, real server integration tests.

> **Fortsetzung 2026-09-08 (DRK-250), Basis `1e5e7de`.** Die Haken in Tasks
> 8–14 waren keine Implementierungsbelege: die genannten Dienste, Oberflächen
> und das Stufe-5-Gate fehlen teilweise oder vollständig. Diese Schritte sind
> wieder offen. Tasks 1–7 sind ausgeliefert; ihre realen Integrationsgrenzen
> bleiben Gegenstand des kumulativen Gates. Die normative Spezifikation und die
> Global Constraints gelten vollständig, einschließlich der zwei zusätzlichen
> v1.1-Escrow-Aufgaben. Testdoubles allein schließen keinen Produktpfad.
>
> **Abschluss 2026-09-19 (DRK-282).** Die Haken der Tasks 8–14 sind dort
> gesetzt, wo der Schritt belegt ist (Zeugen und Zahlen in
> `docs/traceability/stage-5-gate.md`). Zwei Schritte bleiben bewusst offen:
> Task 14 Step 3 und Step 4 (die bündelnden Systemziele
> `e2e_organization_lifecycle` und `e2e_recovery_fresh_machine` sind nicht
> gebaut, DRK-427). Der native Retry aus `incompleteUnreachableReplica`
> (Task 12) ist per Ruling vom 13.09.2026 an DRK-319 verschoben; die Kante
> bleibt Zusage dieses Plans.

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

- [x] **Step 1: Write Root-only/Admin-only/core/action/replay tests**

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

- [x] **Step 2: Run tests and verify the public entry point and the ceremony are absent**

Run: `cargo test --locked -p ea-admin --test authorization --test root_ceremony`

Expected: FAIL — `ea-admin` existiert nicht, `verify_authorized_trust_target` ist
nicht öffentlich, und der Einmal-Speicher überlebt keinen Prozess.

- [x] **Step 3: Implement the public proof entry, the persistent store, and the ceremony**

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

- [x] **Step 4: Run the full authorization attack matrix**

Run: `cargo test --locked -p ea-admin --test authorization --test root_ceremony`
und `cargo test --locked -p ea-trust`

Expected: PASS; mixed action effects (`EA-TRUST-ACTION-MISMATCH`), wrong signer
context, expired auth (`EA-TRUST-AUTH-EXPIRED`), not-yet-valid
(`EA-TRUST-AUTH-NOT-YET-VALID`), reused nonce (`EA-TRUST-AUTH-REPLAY`), same-person
self-rotation (`EA-TRUST-SELF-AUTHORIZATION`) und capability mismatch scheitern. Die
bestehenden Zeugen in `crates/ea-trust/tests/registry_attacks.rs` bleiben grün.

> **Der Haken bleibt offen. Gemessen am 2026-09-05 gegen `b26e7f4`, Fix-Runde 1
> zu DRK-269.** Vier der sieben genannten Angriffe haben einen Zeugen auf der
> NEUEN öffentlichen Fläche (`verify_authorized_trust_target`,
> `verify_intended_trust_target`, `RootCeremonyService::publish_authorized_target`),
> drei nicht:
>
> | Angriff | Zeuge auf der neuen Fläche |
> |---|---|
> | mixed action effects | `crates/ea-admin/tests/authorization.rs::an_authorization_for_another_action_is_refused`, `crates/ea-trust/tests/admin_authorization_target.rs::an_intended_target_for_another_action_is_refused` |
> | expired auth | `…::an_intended_target_outside_the_authorization_window_is_refused` |
> | not-yet-valid | derselbe Zeuge |
> | reused nonce | `crates/ea-admin/tests/root_ceremony.rs::the_second_publication_of_the_same_authorization_is_refused_across_runs` und `::the_lock_holds_both_dimensions_of_the_authorization` |
> | **wrong signer context** | **keiner** |
> | **same-person self-rotation** | **keiner** — es gibt nur den vorbestehenden `pub(crate)`-Unittest in `crates/ea-trust/src/admin_authorization.rs`, der die neue Fläche nicht durchläuft |
> | **capability mismatch** | **keiner im ganzen Baum auf dem Autorisierungspfad** |
>
> Die drei fehlenden gehören nach `crates/ea-trust`: die Regeln liegen dort
> (`verify_authorization_signer` prüft Signaturkontext, Capability
> `organizationAdminApprove` und Subjektgleichheit), und ihre Fixtures
> brauchen einen Bootstrap-Administrator OHNE diese Capability sowie eine
> `AdminIssue`-Autorisierung, deren Zielsubjekt das des Unterzeichners ist —
> beides baut `RegistryLineBuilder::new()` heute fest ein. Der Haken wird
> gesetzt, wenn diese drei Zeugen stehen; bis dahin behauptet er nicht, was
> nicht gemessen ist.

- [x] **Step 5: Commit Admin/Root proof boundary**

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
- Modify: `crates/ea-trust/src/anchor.rs` — der Vorstufen-Kodierer `encode_pre_anchor`
  (`crates/ea-trust/src/anchor.rs:691`) war privat, und `decode_trust_anchor`
  (`:544`) kannte nur den FINALEN Anker. Diese Aufgabe muss exakte Vorstufenbytes
  ERZEUGEN und von den Medien zurueckLESEN. Eine zweite Kodierung waere eine
  zweite Wahrheit: schon ein Byte Abweichung liesse den `bootstrapAnchorHash`
  des finalen Ankers dauerhaft nicht mehr auf die festgeschriebene Vorstufe
  passen. Der eine vorhandene Kodierer BLEIBT deshalb privat; oeffentlich sind
  zwei Funktionen darueber geworden: `encode_pre_anchor_v1`
  (`crates/ea-trust/src/anchor.rs:715`), das Hashlisten und Wurzelschluessel
  prueft und danach genau `encode_pre_anchor` ruft, und `decode_pre_anchor`
  (`:769`), das die Bytes der Medien wieder einliest. Der Umweg ueber den
  Wrapper haelt die eine Quelle der Kodierung und gibt trotzdem einen
  geprueften Typ heraus statt eines nackten `Vec<u8>`.
- Modify: `crates/ea-admin/src/error.rs`, `crates/ea-admin/src/lib.rs`,
  `crates/ea-admin/Cargo.toml`
- Modify: `apps/cli/src/args.rs`, `apps/cli/src/commands/mod.rs`, `apps/cli/src/output.rs`
- Test: `crates/ea-admin/tests/bootstrap.rs`
- Test: `crates/ea-admin/tests/anchor_integrity.rs`
- Test: `apps/cli/tests/organization_init.rs`

**Interfaces:**
- Consumes: den EINEN Schluesselport `ea_key_provider::KeyProvider`
  (`crates/ea-key-provider/src/contract.rs:351`). Getrennte Root-/Admin-/Recovery-/
  HGA-/Approver-/Writer-/Server-/Reader-Ports gibt es NICHT: `SecretPurpose` kennt
  genau vier LOKALE Zwecke eines Writer-Geraets (`contract.rs:32-51`), und ein
  Wurzelzweck fehlt dort ausdruecklich (`contract.rs:340-350`). Wie schon
  `RootCeremonyService::new` (`crates/ea-admin/src/root_ceremony.rs:55`) nimmt die
  Zeremonie die Griffe und das oeffentliche Material der ausseren Schluessel vom
  WIRT entgegen. Einen „external fingerprint confirmer" gibt es ebenfalls nicht;
  das einzige Vorbild ist das readerspezifische
  `ReaderEnrollment::confirm_fingerprints` (`crates/ea-reader/src/enrollment.rs:639`).
  Ports fuer Medien, Zweitkanalbestaetigung und Frischrechnertest entstehen hier.
- Produces: `BootstrapCoordinator`, exakte `organization-trust-anchor-pre-v1`-Bytes,
  den exakten finalen Anker, Genesis, und `ProductionState::Ready` erst nach dem
  Frischrechner-Recovery-Test.

- [x] **Step 1: Write bootstrap order and immutable-anchor tests**

Der Kern ist SYNCHRON. `ea-admin` traegt kein `tokio`
(`crates/ea-admin/Cargo.toml:45-47`), und die Regel steht geschrieben:
`crates/ea-admin/src/root_ceremony.rs:31-33` und
`crates/ea-key-provider/src/contract.rs:337-343` — Async lebt ausschliesslich in
`apps/desktop/src-tauri` ueber `spawn_blocking`. Die Zeugen sind deshalb `#[test]`:

```rust
#[test]
fn production_state_requires_all_twelve_steps_and_fresh_recovery() {
    let mut setup = BootstrapHarness::new();
    setup.complete_through_genesis().unwrap();
    assert_eq!(setup.production_state(), ProductionState::BlockedRecoveryTest);
    setup.run_fresh_machine_recovery().unwrap();
    assert_eq!(setup.production_state(), ProductionState::Ready);
}

#[test]
fn changing_any_pre_anchor_field_requires_new_org_and_chain_ids() {
    let pre = fixtures::pre_anchor();
    let final_anchor = fixtures::final_anchor_with_changed_admin_hash();
    assert_eq!(
        verify_anchor_transition(&pre, &final_anchor).unwrap_err().code(),
        "EA-ANCHOR-PRE-FIELD-CHANGED"
    );
}
```

`EA-ANCHOR-` eroeffnet eine 47. Codefamilie, und `crates/ea-admin/src/error.rs:12-25`
verlangt dafuer eine geschriebene Begruendung. Sie lautet: `EA-TRUST-ANCHOR-{SHAPE,
HASH,PIN}` (`crates/ea-trust/src/error.rs:35-37`) sprechen ueber Bytes, die man
BEREITS HAELT — Gestalt, Selbstkonsistenz, Pinnung beim Dekodieren. Der hier
gemeinte Befund ist ein anderer: die Zeremonie stellt beim BAUEN fest, dass ein
finaler Anker eine ANDERE als die auf den Medien bestaetigte Vorstufe fortschreibt.
`decode_trust_anchor` kann das nicht sehen — es rechnet die Vorstufe aus dem finalen
Anker selbst zurueck (`crates/ea-trust/src/anchor.rs:590-602`), sodass eine
nachtraeglich korrigierte Zeremonie einen vollkommen selbstkonsistenten Anker
erzeugt. Genau diese Luecke schliesst dieser Zeuge.

- [x] **Step 2: Run bootstrap tests and verify orchestration is absent**

Run: `cargo test --locked -p ea-admin --test bootstrap --test anchor_integrity && cargo test --locked -p einsatzarchiv-cli --test organization_init`

Expected: FAIL because bootstrap coordinator and init command do not exist.

- [x] **Step 3: Implement a persisted, forward-only twelve-step ceremony**

Implement exactly: random organization/chain IDs; offline Root; two separate Admin accounts with Admin and operator-instance keys plus direct Root-signed initial certificate/binding pairs; pre-anchor written to two write-protected media and full fingerprint confirmed over second channel; separate Recovery KEM and HGA signing keys; two Approvers; two verified backups for Root/Admin/Recovery/HGA; local Writer/server/Reader keys plus normally authorized bindings; QR/full fingerprint compare; Admin-authorized Root-signed device/operator/Approver/component certificates, initial policy and Registry; Genesis sequence 0; final anchor binding unchanged pre fields, `bootstrapAnchorHash`, and Genesis hash on both media with second-channel confirmation; fresh-machine test Entry verification and Recovery decryption. Expose this orchestration as `einsatzarchiv --trust-anchor <file> organization init ...`; Stage 1's required Recovery command grammar remains unchanged.

Persist only public ceremony state and opaque key handles. Any changed pre-anchor field invalidates the setup and requires newly generated organization/chain IDs. Do not expose a skip-to-ready switch.

Zwei Kanten, die der Abschnitt nicht nennt und die die Umsetzung braucht: `apps/cli`
haengt heute NICHT an `ea-admin` und traegt ausdruecklich keine Logik
(`apps/cli/src/main.rs:3-14`); ein sechstes Kommando bewegt ausserdem die
laengengepruefte Grammatik (`apps/cli/src/output.rs:50-54`,
`apps/cli/tests/commands.rs:24-25` mit `[&str; 5]`). Und die Spec-Grammatik
(`docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md:1787-1793`) fuehrt
`organization init` NICHT; sie fuehrt `verify, list, decrypt, grant, report, export,
recovery-test`. Das Kommando kommt aus diesem Plan, nicht aus der Spec.

- [x] **Step 4: Run happy-path, interruption, media mismatch, and foreign-Genesis tests**

Run: `cargo test --locked -p ea-admin --test bootstrap --test anchor_integrity && cargo test --locked -p einsatzarchiv-cli --test organization_init`

Expected: PASS; restart resumes the same step, unconfirmed/mismatched media block, and a self-consistent foreign archive fails at the anchor.

- [x] **Step 5: Commit bootstrap and anchor creation**

```bash
git add crates/ea-admin apps/cli
git commit -m "feat(admin): bootstrap independently anchored organizations"
```

### Task 3: Operator Provisioning, Session Verification, and Revocation

**Fortsetzung DRK-271, 2026-09-06:** Der Arbeitsauftrag umfasst die native
Zusammensetzung, ein funktionales CLI und die getrennte Offline-Autorität.
Die frühere Begrenzung auf den synchronen Kern ist aufgehoben. Der detaillierte
[Ergänzungsplan](2026-09-06-drk-271-native-completion.md) und
[ADR 0006](../../adr/0006-native-operator-host-and-offline-authority.md) beschreiben
diese Fortsetzung. Der Branch begann auf frisch gefetchtem `origin/main`;
der Main-Stand wird vor der PR-Aktualisierung erneut geprüft.

**Verbindliche Implementierungsgrenzen:**

- Der Kern ist synchron. Die Beispiele unten beschreiben das Verhalten; die
  realen Zeugen verwenden `#[test]`, keine Tokio-Laufzeit und kein `.await`.
- `RootCeremonyService::publish_authorized_target` ist ausgeliefert und nimmt
  `VerifiedAdminAuthorizationIntent`, `TrustPayloadV1`, exakte Autorisierungsbytes,
  `TrustStateStore` und einen frischen `OperatorSessionProof` entgegen. T03 nutzt
  diesen Dienst und `verify_intended_trust_target`; es baut weder eine zweite
  Admin-Prüfung noch einen zweiten Root-Signierer.
- `BoundOperator::resolve` und `OperatorAuthenticator::reauthenticate` existieren.
  Neu ist die erneute Prüfung einer Sitzung am aktuellen `SelectedRegistryHead`
  samt erwarteter Rolle/Gerätezertifikat und aktuellem Konto/Instanzschlüssel.
  Die obere Grenze des Fünf-Minuten-Fensters ist exklusiv.
- Das vorhandene Profil liegt in der SQLCipher-Tabelle `operator_profile`;
  `ea-draft::OperatorProfileRepository` liest es nur. Der administrative
  Schreibpfad gehört in `ea-admin`, benutzt dieselbe verschlüsselte Datenbank
  und darf keine parallele Klartext-Profildatei anlegen.
- Windows/macOS/Ubuntu erhalten echte native Konto-, Schlüssel- und Präsenz-
  Implementierungen. Der Host verifiziert das installierte Programm vor privatem
  IPC, begrenzt die Prozesslaufzeit und hält einen durchgehenden Sitzungswächter.
  Sperre oder verlorene Überwachungsabdeckung bleibt bis zur neuen Anmeldung
  verriegelt. Native Betriebssystemabnahme erfordert eingerichtete Konten,
  signierte/geschützte Pakete und reale Dialoge; Cross-Builds ersetzen sie nicht.
- Das normale CLI komponiert diese Provider mit einem vollständig geprüften
  Archiv und permanentem SQLCipher-Trust-Zustand. Ein separates Testprogramm
  verwendet ausdrücklich Test-Provider; der Produktionspfad hat keinen
  Identitäts-/Signierer-Override aus Konfiguration oder Umgebung.
- Die Offline-Autorität erhält signierte, Head-gebundene Anfragen. Profil und
  von ihr frisch erzeugtes Salz werden ausschließlich verschlüsselt zum Ziel
  übertragen. Ihre private Terminaleingabe folgt auf native Admin-Präsenz und
  den ausdrücklich bestätigten externen Identitätsabgleich.
- Der Zielrechner speichert vor dem Austausch die exakten Anfragen und ihre
  ephemeren Entschlüsselungsschlüssel in SQLCipher. Root-Autorisierung, Replay-
  Verbrauch, Audit und genaue Antwort dürfen bei Wiederaufnahme weder neue
  Nonces noch einen teilweise abgeschlossenen Freigabezustand erzeugen.
- Widerruf hat kein direktes Trust-Ziel: Bindungen werden durch
  `RegistryChangeV1::Target { target_kind: 1, object_hash }` (Action 1)
  widerrufen; ein Admin-Zertifikat durch `AdminCertificate { effect: 1, .. }`
  (Action 5). Eine freie `revocation`-Objektfamilie entsteht nicht.
- Root-signierte Binding-Bytes sind noch keine aktive Bindung. Die Aktivierung
  braucht ein separat autorisiertes Registry-Ereignis (Action 4) mit eigenem
  Bezeichner/Nonce gegen denselben Previous Head. Vorbereitung und aktive
  Bereitstellung sind verschiedene Zustände; Profil-/Schlüsselfehler dürfen
  keinen teilweise eingerichteten Operator freischalten.
  Der Host muss vorbereitete öffentliche Objekte bis zur Prüfung des exakten
  verschlüsselten Profils und nativen Schlüssels von der Veröffentlichung
  zurückhalten; ein fehlgeschlagener Profil-Commit macht bereits signierte
  Bytes nicht ungültig.
- Wirksamkeit muss an der tatsächlichen nächsten Eintragssequenz möglich sein,
  auch innerhalb eines länger gültigen Registry-Fensters. Ein verlorener
  Writer-Schlüssel kann die Folgen bis zum Lease-Ende nicht mehr erzeugen.
  Widerruf, Ersatz-Binding, Autorisierung und Audit müssen denselben gewählten
  Wirksamkeitsbeginn verwenden; die lückenlose Archivfolge bleibt unverändert.
- Ersatz muss auch nach weiteren verifizierten Registry-Änderungen möglich
  bleiben. Maßgeblich ist der am aktuellen Kopf nachgewiesene eigene Widerruf
  einer aktivierten Bindung samt Organisation und Kette. Bloße Abwesenheit,
  ein nur vorbereiteter Katalogeintrag oder alleiniger Zertifikatswiderruf
  reichen als Ersatznachweis nicht aus.
- Das eingefrorene Login-/Reauth-Audit trägt nur einen optionalen öffentlichen
  Objekthash und den Ausgang. Technische Fehlercodes werden als geschlossene
  lokale Fehler zurückgegeben, nicht in ein erfundenes Audit-Freitextfeld
  geschrieben. Binding-Änderung/Widerruf verwenden
  `BindingLifecycleContextV1`; `record_signed` persistiert vor der Rückgabe.

**Files:**
- Create: `crates/ea-admin/src/operator.rs`
- Modify: `crates/ea-operator/src/session.rs`, `account.rs`, `lib.rs`
- Modify: `crates/ea-trust/src/registry.rs` (verified revoked-binding query)
- Create: `crates/ea-admin/src/operator_profile.rs`
- Modify: `crates/ea-admin/src/lib.rs`, `crates/ea-admin/Cargo.toml`, `Cargo.lock`
- Create: `apps/cli/src/commands/operator.rs`
- Modify: `apps/cli/src/args.rs`, `commands/mod.rs`, `output.rs`
- Test: `crates/ea-admin/tests/operator_binding.rs`
- Test: `crates/ea-admin/tests/operator_audit.rs`
- Modify: lifecycle/audit fixtures in `crates/ea-admin/tests/support/` and
  public test-key accessors in `crates/ea-trust/tests/support/mod.rs`
- Test: `crates/ea-operator/tests/account_recreation.rs`
- Test: `apps/cli/tests/operator.rs`

**Interfaces:**
- Consumes: Admin authorization, Root signer, native account/instance-key provider, encrypted local profile, and `LocalAuditService`.
- Produces: `OperatorBindingService::{provision,verify_session,revoke}`, profile commitment, and new binding requirement after account/install/key loss.

- [x] **Step 1: Write commitment, wrong-account, and Ubuntu UID-reuse tests**

```rust
#[test]
fn profile_commitment_must_match_decrypted_snapshot() {
    let binding = service.provision(fixtures::profile(), fixtures::account(), fixtures::auth()).unwrap();
    assert!(verify_operator_snapshot(fixtures::profile(), &binding).is_ok());
    assert_eq!(verify_operator_snapshot(fixtures::renamed_profile(), &binding).unwrap_err().code(),
               "EA-OPERATOR-PROFILE-COMMITMENT");
}

#[test]
fn recreated_same_uid_and_home_cannot_reuse_binding() {
    let old = harness.provision_linux_account(1001, "instance-a");
    harness.delete_and_recreate_account(1001, "instance-b", true);
    assert!(harness.verify(old).is_err());
}
```

- [x] **Step 2: Run operator tests and verify lifecycle is incomplete**

Run: `cargo test --locked -p ea-admin --test operator_binding && cargo test --locked -p ea-operator --test account_recreation`

Expected: FAIL because provisioning/replacement orchestration and native account-recreation evidence are absent; existing session contract checks already cover wrong accounts, missing/replaced instance keys, challenge verification, lock invalidation and expiry.

- [x] **Step 3: Implement external identity-check to signed binding flow**

The implementation now includes the native host and the separate offline authority.
The signed binding pair and encrypted profile are committed atomically before an
activation is requested. Activation bytes remain behind fresh native/profile/audit
readiness checks; a newly verified Registry head and login complete enrollment.
This step remains open until integrated delivery and the required native acceptance
evidence exist. Reports must distinguish process fixtures from actual installed-OS
presence, signing identity, continuous lock detection and the enforced restore path.

Generate fresh 32-byte `profileCommitmentSalt`, keep display name/function/salt only in encrypted profile, compute the exact operator-profile commitment, generate a new non-roaming installation key, derive OS account binding hash through Stage 2 provider, obtain Admin authorization with action 4, and Root-sign the fixed binding core. Verify device certificate, role, effective/revoked sequence, account hash, fresh instance challenge, profile commitment, native presence, and five-minute session expiry on every action. Revocation is Root-signed from its effective sequence. Account deletion/recreation, UID reuse, restored home/app backup, lost Secret Service collection, or missing instance key always requires external re-identification, new key/auth/binding, and revocation of old binding.

Write signed, cleartext-free local audit events for every login attempt, failed re-authentication, binding replacement, and revocation. Login success binds only the pseudonymous binding/device hashes; failure returns an allowlisted technical reason code locally and persists only the frozen generic audit context and outcome, with no entered credential/account/display value. Binding change and revocation bind old/new public object hashes and effective sequence. Audit persistence failure blocks privileged action completion and is surfaced as a local resource error.

- [x] **Step 4: Run cross-platform contract and negative binding tests**

Run: `cargo test --locked -p ea-admin -p ea-operator` and `cargo test --locked -p einsatzarchiv-cli --test operator`

Expected: PASS; free operator text, wrong device/account/role, revoked binding, stale session, and restored old instance fail.

- [x] **Step 5: Commit operator lifecycle**

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

**Ausgangslage im Arbeitsbaum (gemessen 2026-09-06, DRK-272).** Der Selektions- und
Freigabekern steht bereits produktiv in `ea-trust`; dieser Task baut ihn NICHT nach, sondern
verdrahtet ihn zu Admin-Arbeitsabläufen. Vorhanden und zu verbrauchen:
`ea_trust::verify_registry_candidate` (`crates/ea-trust/src/registry.rs:571`),
`ea_trust::prepare_local_time` (`crates/ea-trust/src/time.rs:94`),
`ea_trust::verify_clock_release` (`crates/ea-trust/src/clock_release.rs:67`) und
`ea_trust::select_registry_head(candidate, local_time, Option<VerifiedClockRelease>)`
(`crates/ea-trust/src/registry.rs:687`), das `RegistrySelectionOutcome`
(`registry.rs:389`) mit den Armen `Selected(SelectedRegistryHead)` / `Advanced` /
`PendingFuture` liefert. `VerifiedClockRelease` (`clock_release.rs:63`) ist bereits opak,
nicht `Clone`, und wird von `select_registry_head` per Wert verbraucht; Nonce-Replay, Head
und Zeit-Floor committen atomar über `RegistrySelectionCommit`
(`crates/ea-trust/src/state.rs`). Die echte Lücke dieses Tasks sind daher: die
ea-admin-Fassade über diesen Dreischritt, der Erzeuger der `exact_audit_bytes` für die
Freigabe, der Aufnahmepunkt für `ReauthPurpose::ClockSkewRelease`, die CLI und der E2E-Zeuge.

- [x] **Step 1: Write highest-head, lease, and revocation-boundary tests**

Die Zeugen binden die Namen des Arbeitsbaums: der Fehlercode des erschöpften Lease heisst
`EA-TRUST-SEQUENCE-LEASE` (`crates/ea-trust/src/error.rs:144`); der Code
`EA-REGISTRY-LEASE-EXHAUSTED` existiert nirgends und DARF NICHT als zweiter Fehlerpfad
danebengebaut werden. Die Familie `EA-REGISTRY-` ist im Baum bereits belegt — die
Stale-Quittung des Writers fuehrt `EA-REGISTRY-STALE-BLOCKED` und
`EA-REGISTRY-STALE-ACK-{REQUIRED,REPLAY,PREVIEW-MISMATCH}`
(`crates/ea-writer/src/error.rs:119,137-139`) — und scheidet damit auch fuer neue
ea-admin-Fehler aus. `RegistryVersion` und `ChainSequence` haben `::new(u64)`/`.get()` und keine
Tupelkonstruktoren (`crates/ea-types/src/ids.rs`). Der Kern ist durchgehend synchron
(`crates/ea-audit/src/lib.rs:15`); `ea-admin` hat keine async-Runtime. Fixtures kommen aus
dem eingebundenen `support`-Modul (`crates/ea-admin/tests/support/mod.rs`), nicht aus einem
`fixtures::`-Namensraum.

```rust
#[test]
fn workflow_uses_shared_highest_applicable_head() {
    let line = support::ceremony_line();
    let service = RegistryWorkflowService::new(/* … */);
    let selected = service
        .select(&line, ChainSequence::new(10), support::now_at(500))
        .expect("head at sequence 10");
    let RegistrySelectionOutcome::Selected(head) = selected else {
        panic!("expected a selected head");
    };
    assert_eq!(head.registry_version(), RegistryVersion::new(3));
    assert_eq!(
        service
            .select(&line, ChainSequence::new(12), support::now_at(500))
            .unwrap_err()
            .code(),
        "EA-TRUST-SEQUENCE-LEASE",
    );
}

#[test]
fn revoked_reader_receives_no_grant_at_effective_sequence() {
    // `SelectedRegistryHead::active_certificates` iteriert an der
    // `proposed_sequence` des Kopfes; die Grenze wird darum ueber zwei
    // Koepfe gemessen, nicht ueber einen Sequenzparameter.
    let before = support::selected_head_at(ChainSequence::new(9));
    let at = support::selected_head_at(ChainSequence::new(10));
    let after = support::selected_head_at(ChainSequence::new(11));
    assert!(has_certificate(&before, support::reader_certificate_hash()));
    assert!(!has_certificate(&at, support::reader_certificate_hash()));
    assert!(!has_certificate(&after, support::reader_certificate_hash()));
}

#[test]
fn clock_release_is_exact_expiring_one_use_and_never_lowers_floor() {
    let service = ClockReleaseService::new(/* … */);
    let bytes = service
        .issue(support::skew_context(), support::admin_reauth())
        .expect("issued release");
    assert!(service.apply(support::same_skew_context(), &bytes).is_ok());
    assert_eq!(
        service
            .apply(support::different_wall_clock(), &bytes)
            .unwrap_err()
            .code(),
        "EA-TRUST-CLOCK-RELEASE-REPLAY",
    );
    assert!(service.apply(support::lower_floor(), &bytes).is_err());
}
```

- [x] **Step 2: Run workflow tests and verify missing administration**

Run: `cargo test --locked -p ea-admin --test registry_workflows --test clock_release && cargo test --locked -p ea-system-tests --test e2e_registry_effectiveness`

Expected: FAIL because device/policy/Registry and clock-release workflows do not exist.

- [x] **Step 3: Implement one-action-per-event append-only administration**

Require pending request plus external fingerprint confirmation. Admin authorization and Root signature prepare exactly one direct target; a distinct activation authorization creates exactly one matching Registry change. Both bind the same Previous Head and the event is its checked version `+1`. Head 1 uses Change 2 for the initial Policy; anchor-pinned Admin pairs are external basis state, not a second change. Initial policy explicitly fixes profile, Registry age/skew/stale behavior, sequence lease, Evidence window, Reader inactivity/history, archive profiles/network failure, backup/restore, retention/destruction, free text, suites/formats. Policy version/hash/effective sequence, direct-core effective sequence, Root effective Registry version, and `preTransitionSequence` follow the Task-8 closure exactly. Revocation explains that past grants/plaintext cannot be recalled and stops new grants only from `effectiveFromSequence`. Writer, server, Reader, Admin, and CLI consume the shared opaque `RegistryCandidate`/selection proof states; no duplicate grace period or clock calculation is allowed.

Die Aktionscodes 0..6 sind heute ein rohes `pub action_code: u8`
(`crates/ea-format/src/etb.rs:151`); die (Code, Stelligkeit)-Zuordnung lebt allein im
Dekodierer `decode_registry_change` (`crates/ea-format/src/etb.rs:1670-1710`). Die
Ereignisfabrik `OperatorBindingService::registry_event(RegistryWindow, RegistryChangeV1)`
(`crates/ea-admin/src/operator.rs:761`) ist vorhanden und wird wiederverwendet, nicht
nachgebaut. `revocation.rs` deckt ausschliesslich das ab, was `OperatorBindingService::revoke`
(`crates/ea-admin/src/operator.rs:531`, Bindungswiderruf) und `operator_revocation.rs` nicht
schon leisten; Admin-Zertifikatswiderruf (Aktion 5, Effekt 1) bleibt beim
Zertifikatslebenszyklus.

When future-clock skew exceeds the bound Guard Policy relative to a deterministically selected, fully verified Receipt/Checkpoint reference, remain blocked until a newer independent reference validates or an Admin deliberately creates a documented clock release after fresh `ReauthPurpose::ClockSkewRelease`. Die Freigabe wird als signierte lokale Auditzeile gebaut — `LocalAuditActionV1::ClockSkewRelease` ist Auditcode 6 (`crates/ea-format/src/local_audit.rs:775`) und NICHT der Registry-Change 6 `RootCertificate` (`crates/ea-format/src/etb.rs:1707`); die beiden Sechsen gehoeren zwei verschiedenen Nummernkreisen. Der Kontext `ClockReleaseContextV1` (`crates/ea-format/src/local_audit.rs:723-763`) bindet organization/target device, current trusted floor, exact observed wall clock, signed policy limit, Registry version und Head hash, Guard-Policy hash, die exakte unabhaengige Referenz, den geschlossenen Begruendungscode 0..2 (`ClockReleaseJustificationV1`, `local_audit.rs:26-30`), issued/expiry times und die Zufalls-Nonce. Die Zeile wird ueber `LocalAuditService::record_signed` (`crates/ea-audit/src/event.rs:229`) gebucht; ihre `exact_bytes()` sind der Eingang von `verify_clock_release`. Verify the active Admin certificate/binding/capability against the candidate's pre-transition state; only Outcome 1 (`LocalAuditOutcomeV1::Accepted`) yields an opaque `VerifiedClockRelease`. `select_registry_head` consumes it by value and commits nonce replay, Head, and floor atomically. A mismatch, expiration, Registry/policy/reference change, clock movement, or attempted floor reduction rejects it; it never waives Registry `notAfter`, `notBefore`, sequence lease, Authorization expiry, or signature errors.

TSA-Referenzen sind ausdruecklich NICHT freigabefaehig: `verify_clock_release` weist
`IndependentTimeKindV1::Tsa` mit `EA-TRUST-TIME-SOURCE-UNSUPPORTED` ab
(`crates/ea-trust/src/clock_release.rs:281`, Zeuge
`crates/ea-trust/tests/clock_release.rs::tsa_within_limit_and_unprovable_time_never_mint_a_release`),
und `ea_time::IndependentTimeKind` kennt nur Receipt und Checkpoint
(`crates/ea-time/src/model.rs:9`). Fehlt jede unabhaengige Referenz — also
`TrustedTimeState::independent_reference() == None` (`crates/ea-time/src/model.rs:144`) —,
darf die Bedienfuehrung gar keine Freigabe anbieten; die ea-admin-Fassade meldet dafuer
einen eigenen sprechenden Zustand statt des nichtssagenden `ClockReleaseError::Mismatch`,
den der Kern heute liefert (`crates/ea-trust/src/clock_release.rs:290`).

Der Zweck `ReauthPurpose::ClockSkewRelease` existiert (`crates/ea-operator/src/session.rs:87`),
hat aber heute keine annehmende Aufrufstelle: jeder ea-admin-Pfad, der eine
`VerifySessionRequest` annimmt, lehnt alles ausser `AdminRootCeremony` ab
(`crates/ea-admin/src/operator.rs:386`, `:538`). Dieser Task baut den Aufnahmepunkt; Muster
fuer die Zweckpruefung ist `crates/ea-writer/src/finalize.rs:1580-1598`
(`proof.is_valid_for(purpose, now)`, sonst Zweckabweichung).

Neue Fehler folgen der Hausregel `crates/ea-admin/src/error.rs:12-52`: das Praefix
`EA-ADMIN-` ist den Server-Auditcodes vorbehalten und DARF NICHT verwendet werden;
durchgereichte Arme behalten den Code ihrer Herkunft. `apps/cli` haelt heute keine
produktive `ea-trust`-Kante (`apps/cli/Cargo.toml:26-31`) und bekommt auch keine: die
Kommandos rufen die ea-admin-Fassade, weil die Fachlogik nicht im Kommandopfad wohnt
(`apps/cli/src/main.rs:1-14`). Der Parser ist handgeschrieben, nicht `clap`
(`apps/cli/src/args.rs:1-40`, ADR `docs/adr/0001-toolchain-and-cryptography-dependencies.md`).
`tests/ea-system-tests` braucht `ea-admin` als neue dev-dependency; Vorbild fuer den E2E ist
`tests/ea-system-tests/tests/task8_trust_time.rs`, der Linie, Receipt, Checkpoint und
signierte Freigabe bereits baut.

- [x] **Step 4: Run gaps/forks/future/stale/clock and server-known-newer-head E2E tests**

Run: `cargo test --locked -p ea-admin --test registry_workflows --test clock_release && cargo test --locked -p ea-system-tests --test e2e_registry_effectiveness`

Expected: PASS; rollback, same-version fork, future-only, expired strict, consumed lease, clock rollback, invalid/replayed clock release, and server-known newer applicable head block correctly.

- [x] **Step 5: Commit Registry administration**

```bash
git add crates/ea-admin apps/cli tests/ea-system-tests
git commit -m "feat(admin): manage policy registry and revocation"
```

### Task 5: Writer Transition and Restored-Writer Blockade

**Files:**
- Create: `crates/ea-admin/src/writer_transition.rs`
- Create: `apps/cli/src/commands/writer_transition.rs`
- Modify: `crates/ea-admin/src/lib.rs`, `apps/cli/src/{args,output}.rs`, `apps/cli/src/commands/mod.rs`
- Modify: `crates/ea-trust/src/{registry,resolver}.rs` (der wirksame Übergang wird lesbar), `crates/ea-trust/tests/support/mod.rs` (additiv, nur `tests/`)
- Modify: `crates/ea-writer/src/{finalize,error,lib}.rs`, Create: `crates/ea-writer/src/content.rs` (`keyTransition` durch den normalen Pfad, `EA-WRITER-REVOKED`)
- Modify: `crates/ea-sync-server/src/{validation,ports,commit}.rs` (exakte Transition-Regel statt Pauschalabweisung, `EA-COMMIT-WRITER-REVOKED`)
- Modify: `crates/ea-verify/src/{archive,entry,evidence,recipient}.rs` (Prüfung statt Quarantäne)
- Test: `crates/ea-admin/tests/writer_transition.rs`
- Test: `crates/ea-trust/tests/writer_transition_access.rs` (Zugriff auf den wirksamen Übergang), `crates/ea-writer/tests/key_transition.rs`, `crates/ea-sync-server/tests/commit_service.rs`, `crates/ea-verify/tests/*` (Transition-Regel), `apps/cli/tests/writer_transition.rs`
- Test: `tests/ea-system-tests/tests/e2e_writer_transition.rs`

**Interfaces:**
- Consumes: trusted external head, old/new Writer certificates, Admin/Root ceremony, Writer finalization.
- Produces: `WriterTransitionService::{prepare,activate}`, Root-signed public transition and first new-Writer `keyTransition` Entry.

**Ausgangslage im Arbeitsbaum (gemessen 2026-09-07, DRK-273).** Das Transitionsobjekt und
seine Registry-Wirkung sind seit Stufe 1–3 vollständig gebaut und bezeugt; dieser Task baut
sie NICHT nach. Vorhanden: `WriterTransitionFieldsV1` mit `old/new_writer_certificate_hash`,
`effective_from_sequence`, `previous_entry_hash` und `reason_code: u64`
(`crates/ea-format/src/etb.rs:238-247`, CDDL `schemas/archive/v1/trust.cddl:147-153`); der
EINE Kodierer `TrustPayloadV1::writer_transition(fields, admin_authorization_object_hash)`
(`etb.rs:467`); `RegistryActionV1::WriterTransition { transition_object_hash }` mit
Aktionscode 3 und Registry-Change 3 (`crates/ea-admin/src/registry.rs:243,264,315`); die
Kernprüfung `validate_writer_transition_target` (`crates/ea-trust/src/registry.rs:1351` —
gleiche Organisation und Kette, `effective_from_sequence` gleich der des Ereignisses, alt ≠
neu, beide Zertifikate der Art Writer, das alte an `preTransitionSequence` und das neue an
`effective_from` bereichsaktiv, das alte gleich `current_writer_certificate_hash`); und die
Anwendung `PreviousHeadState::apply_writer_transition` (`crates/ea-trust/src/resolver.rs:100`),
die den alten Writer ab `effective_from_sequence` widerruft, den neuen zum laufenden Writer
macht und den Transitionshash festhält. `active_certificate` filtert jedes Writer-Zertifikat,
das nicht der laufende Writer ist (`resolver.rs:116-135`); der laufende Writer wird beim ersten
freigegebenen Writer-Zertifikat gesetzt (`registry.rs:1513`) und danach nur noch durch Change 3
bewegt. Das Manifestfeld `writer_transition_event_hash: Option<ObjectHash>` existiert
(`crates/ea-format/src/eip.rs:23`), ebenso `PayloadV1::KeyTransition(KeyTransitionV1)` mit
`writer_transition_event_object_hash` und `organizational_reason` (`crates/ea-schema/src/model.rs:1319`).
Fixture: `ActionSpec::WriterTransition { old_writer, new_writer, effective_from }`
(`crates/ea-trust/tests/support/mod.rs:288`), das `previous_entry_hash` fest auf
`hash32(0x35)` setzt — der Writer-Zeuge braucht dafür eine additive `HeadOptions`-Überschreibung.

Die echten Lücken, gegen die der Abschnitt zu messen ist:

1. **`ea-trust` gibt den wirksamen Übergang nicht heraus.** `current_writer_certificate_hash`
   und `writer_transition_object_hash` sind `pub(crate)` (`resolver.rs:31-32`);
   `SelectedRegistryHead` hat keinen Zugriff. Genau darauf berufen sich zwei Pauschalabweisungen:
   `crates/ea-sync-server/src/validation.rs:243` weist JEDES Manifest mit gesetztem Hash mit
   `EA-COMMIT-WRITER-TRANSITION` (422) ab, und `crates/ea-verify/src/entry.rs:72`
   (`claims_unverifiable_writer_transition`) isoliert es. Beide Kommentare sagen wörtlich, dass
   die echte Prüfung an ihre Stelle tritt, „sobald `ea-trust` einen Zugriff auf die wirksamen
   Uebergaenge herausgibt". Dieser Task ist diese Stelle: `SelectedRegistryHead` bekommt
   `current_writer_certificate_hash()`, `effective_writer_transition()` (Objekthash, alter und
   neuer Writer, `effective_from_sequence`, `previous_entry_hash`) und einen Lesezugriff auf ein
   bereichsaktives, noch nicht laufendes Writer-Zertifikat — nur Lesezugriffe, keine neue Kante.
2. **Der Writer schreibt den Hash fest als `None`** (`crates/ea-writer/src/finalize.rs:852`) und
   baut ausschliesslich `PayloadV1::Incident` (`finalize.rs:726`); `FinalizationInputV1` ist
   einsatzförmig (`crates/ea-writer/src/incident.rs:21`). Ein `keyTransition` ist durch den
   normalen Pfad heute nicht erzeugbar. Der Writer prüft ausserdem nirgends, ob sein
   Bindungszertifikat der laufende Writer ist — ein zurückgespielter alter Writer finalisiert
   lokal anstandslos und scheitert erst am Server.
3. **`EA-WRITER-REVOKED` existiert nicht**, und die Familie `EA-WRITER-` gehört den LOKALEN
   Finalisierungsfehlern von `ea-writer` (`crates/ea-writer/src/error.rs:116-142`); der Server
   spricht `EA-COMMIT-`. Der Code der Skizze ist deshalb der lokale Fehler des Writers, dessen
   Bindungszertifikat nicht der laufende Writer des gewählten Kopfes ist; die Serverabsage an
   den widerrufenen Writer heisst `EA-COMMIT-WRITER-REVOKED` (409, Security Event wie
   `WriterUnauthorized`, `validation.rs:154`), unterschieden von `EA-COMMIT-WRITER-UNAUTHORIZED`
   (heute die Antwort, `crates/ea-sync-server/tests/commit_service.rs:1436`).
4. **`ea-admin` hält bewusst keine `ea-writer`-Kante** (`tests/ea-system-tests/Cargo.toml:16-27`),
   und `tests/ea-system-tests` hat keine `ea-sync-server`-Kante. `activate` liefert deshalb KEINEN
   Eintrag, sondern die Felder des Change-3-Ereignisses (`RegistryEventFieldsV1` über
   `RegistryEventFactory::plan`); den `keyTransition`-Eintrag finalisiert der NEUE Writer über
   `ea-writer`, und die Zusammenschau beider Seiten mit der Serverregel hat nur in der
   Systemtest-Crate einen Ort — sie bekommt die Dev-Kanten `ea-sync-server` und
   `ea-sync-protocol` und ruft `ea_sync_server::validate_commit` mit dem ECHTEN
   `SelectedRegistryHead` (er implementiert `ActiveRegistryHeadV1`,
   `crates/ea-sync-server/src/ports.rs:255`). Ein Datenbankserver ist dafür nicht nötig.
5. Namen der Skizze: `transition.object_hash()` gibt es nicht — `publish_authorized_target`
   liefert `ExactObjectBytes`, der Hash ist `ea_crypto::object_hash(bytes.as_bytes())`;
   `entry.manifest()` ist `entry.value().manifest().fields().writer_transition_event_hash`;
   `CommitFailure` hat kein `.code()`, der Code steht in `.error.code()`; der Kern ist synchron,
   `#[tokio::test]` übersetzt in keiner der beiden Testcrates. `reason_code` ist auf dem Draht ein
   blosser `uint` ohne Tabelle in Spec oder Baum; der Dienst reicht ihn durch und erfindet keine.

- [x] **Step 1: Write transition-hash and old-Writer rejection tests**

```rust
#[test]
fn first_new_writer_entry_binds_exact_transition_hash() {
    // ea-admin: prepare → Root ceremony → activate → commit → select the new head
    let prepared = WriterTransitionService::new(&head)
        .prepare(&request, intent.authorization_object_hash())
        .unwrap();
    let transition_bytes = ceremony.publish_authorized_target(&intent, prepared.payload(), …).unwrap();
    let transition_hash = ea_crypto::object_hash(transition_bytes.as_bytes());
    let event = service.activate(&prepared, transition_bytes.as_bytes(), &events, window).unwrap();
    // ea-writer: the NEW writer's first entry is the keyTransition
    let outcome = new_writer.finalize_key_transition(&proof, input, &confirmed, now).unwrap();
    let entry = read_entry(outcome.object_hash);
    assert_eq!(entry.value().manifest().fields().writer_transition_event_hash, Some(transition_hash));
    // the restored old writer at the same sequence: locally and at the server
    assert_eq!(old_writer.finalize(&proof, incident, &preview, now).unwrap_err().code(), "EA-WRITER-REVOKED");
    let failure = validate_commit(&request_of(old_entry), &old_entry, org, chain, old_writer_hash, &new_head).unwrap_err();
    assert_eq!(failure.code(), "EA-COMMIT-WRITER-REVOKED");
}
```

- [x] **Step 2: Run transition tests and verify missing service**

Run: `cargo test --locked -p ea-admin --test writer_transition && cargo test --locked -p ea-system-tests --test e2e_writer_transition`

Expected: FAIL because Writer transition workflow does not exist.

- [x] **Step 3: Implement public transition plus encrypted chain Entry**

Bind old/new Writer certificates, effective sequence, previous trusted chain head, Admin authorization, Root signature, and reason code/public metadata in the transition. Reconcile the incoming Writer against server, Reader, or external signed checkpoint before activation. Revoke old Writer from transition sequence. Finalize `keyTransition` through the normal Writer path with encrypted organizational reason. Require exact transition hash only on the first Entry whose Writer certificate changes; reject missing/additional/mismatched hashes.

Die Regel ist gegen den Übergang formulierbar, ohne den Vorgängereintrag zu lesen, weil der
Übergang den vertrauten Kopf selbst bindet: `effective_from_sequence` ist die Sequenz des
vertrauten Kopfes plus eins und `previous_entry_hash` sein Eintragshash. Damit gilt an jedem
Prüfpunkt (Writer, Server, `ea-verify`): der Hash ist GENAU DANN gesetzt, wenn der Eintrag an
`effective_from_sequence` liegt, den `previous_entry_hash` des Übergangs als Vorgänger nennt
und vom neuen Writer stammt; er ist dann der Objekthash des wirksamen Übergangs des gewählten
Kopfes. Jeder andere Eintrag trägt `None`. Fehlend, zusätzlich oder abweichend ist ein
Trust-Fehler (`design.md:669`). Der Writer nimmt den Hash NICHT als Eingabe entgegen, sondern
liest ihn aus seinem gewählten Kopf; an `effective_from_sequence` darf der neue Writer nur den
`keyTransition` finalisieren, nie einen Einsatz. `ea-admin` signiert weiterhin nichts —
`RootCeremonyService::publish_authorized_target` bleibt der einzige Signierweg.

- [x] **Step 4: Run lost-old-Writer, restored-backup, and concurrent-old/new tests**

Run: `cargo test --locked -p ea-admin --test writer_transition && cargo test --locked -p ea-system-tests --test e2e_writer_transition -- --test-threads=1`

Expected: PASS; a restored stale Writer remains blocked and only the authorized new Writer advances the chain.

- [x] **Step 5: Commit Writer transition**

```bash
git add crates/ea-admin crates/ea-trust crates/ea-writer crates/ea-sync-server crates/ea-verify apps/cli tests/ea-system-tests Cargo.lock
git commit -m "feat(admin): transition the single active Writer"
```

### Task 6: Administration UI for Requests, Fingerprints, Policy, and Recovery Health

> **Gegen den Arbeitsbaum vermessen (2026-09-07, DRK-274).** Der Abschnitt wurde geschrieben,
> bevor Tasks 1, 3, 4 und 5 ausgeliefert haben. Korrigiert sind: der Playwright-Pfad
> (`apps/desktop/tests/e2e/`, `playwright.config.ts:95`, gepinnt durch
> `apps/desktop/src/e2e-config.test.ts:12`; das Wurzelverzeichnis `tests/` gehört dem
> Rust-Mitglied `tests/ea-system-tests`), die fehlenden Kontrakt-, Wirt- und Schalendateien,
> die `ea-admin` nicht als „Admin service DTOs" liefert (die Dienste tragen Lebensdauern und
> brauchen je einen Port in `state.rs`), der Stufe-2-Zeuge
> `no_command_serves_a_reader_or_an_administration_surface` (`lib.rs`), der den Teilstring
> `admin` in Kommandonamen verbietet und in DIESEM Task um die Verwaltung erweitert wird,
> die Zitierung: `bestätigt` / `nicht erfüllt` / `nicht automatisch prüfbar` stehen NICHT in
> §17.4 (dort nur die sechs Vokabulare), sondern folgen §17.3 (`design.md:1922-1930`), §18.4
> (`:1974`) und §21 (`:2044-2073`); die Statuswerte werden als geschlossene Aufzählung aus
> `ea-admin` emittiert und in der Schale übersetzt, wie `SyncStatus`. Der Fingerprint hat im
> Baum keinen Erzeuger (`ea-types` kennt kein `Display` auf `ObjectHash`); der Formatierer
> entsteht in `ea-admin`. Eine aufzählbare Quelle ausstehender Anfragen gibt es nicht (der
> Server-Port `DeviceRegistrationStore` kennt nur `record_pending`); der Wirt-Port liefert
> sie, und seine Anbindung an Server oder Offline-Import bleibt wie jeder Desktop-Port eine
> benannte Abwesenheit bis zur Verdrahtung. Zwei-Admin-Bereitschaft, Schlüssel-Backup,
> Evidence-Richtlinie und letzter Recovery-Test haben kein gemeinsames Aggregat;
> `OperatorGoLiveReport` ist es nicht. Das Aggregat entsteht hier in `ea-admin::go_live`.
> `session_reauthenticate` ist ein Stumpf (`EA-DESKTOP-REAUTH-UNAVAILABLE`); er wird über
> einen Port geführt, bleibt aber unverdrahtet. Testkennungen (`data-testid`) sind im
> Baum nicht Hausstil; die Zeugen fragen über Rolle und Namen. `desktop:e2e` läuft weder
> in `verify:quick` noch in CI (`tools/xtask/src/main.rs`, `.github/workflows/ci.yml`); die
> E2E-Spezifikation ist ein manuell gefahrener Zeuge wie die von Task 16 der Stufe 2.

**Files:**
- Create: `crates/ea-admin/src/go_live.rs` (Go-live-Aggregat, tri-state, `Unknown` nie grün)
- Create: `crates/ea-admin/src/fingerprint.rs` (menschenlesbarer Fingerprint `AA:BB:…`, 32 Paare, Groß-Hex; Rückweg zum `ObjectHash`)
- Create: `crates/ea-admin/src/ceremony_steps.rs` (getrennte Schritte einer Root-Zeremonie als geschlossene Aufzählung, keine Abkürzung)
- Modify: `crates/ea-admin/src/lib.rs`, `crates/ea-admin/src/writer_transition.rs` (Phase der Transition)
- Modify: `crates/ea-ui-contracts/src/lib.rs`, `crates/ea-ui-contracts/src/emit.rs`, `crates/ea-ui-contracts/Cargo.toml`, `crates/ea-ui-contracts/tests/generated_ts_is_current.rs`
- Regenerate: `apps/desktop/src/bridge/generated-contracts.ts`, `apps/web/src/bridge/generated-contracts.ts`
- Create: `apps/desktop/src-tauri/src/commands/admin.rs`
- Modify: `apps/desktop/src-tauri/Cargo.toml` (Kante `ea-admin`), `src-tauri/src/state.rs` (Ports `AdministrationPort`, `ReauthPort`, Nähte `with_administration`, `with_reauth`), `src-tauri/src/lib.rs`, `src-tauri/src/commands/mod.rs`, `src-tauri/src/commands/session.rs` (Fähigkeit `administration`), `src-tauri/src/commands/writer.rs` (`session_reauthenticate` über den Port), `src-tauri/build.rs`, `src-tauri/tauri.conf.json`
- Modify: `apps/desktop/src-tauri/tests/writer_commands.rs`; Create: `apps/desktop/src-tauri/tests/admin_commands.rs`
- Modify: `apps/desktop/src/app/role-gate.ts`, `apps/desktop/src/app/AppShell.tsx`, `apps/desktop/src/app/AppShell.test.tsx`, `apps/desktop/src/app/RoleGate.test.tsx`, `apps/desktop/src/design/icons.tsx`, `apps/desktop/src/design/extract-static-css.tsx`, `apps/desktop/src/design/static-antd.css`
- Create: `apps/desktop/src/features/admin/AdminPage.tsx`
- Create: `apps/desktop/src/features/admin/DeviceRequests.tsx`
- Create: `apps/desktop/src/features/admin/FingerprintApproval.tsx`
- Create: `apps/desktop/src/features/admin/PolicyEditor.tsx`
- Create: `apps/desktop/src/features/admin/RegistryHealth.tsx`
- Create: `apps/desktop/src/features/admin/GoLiveChecklist.tsx`
- Create: `apps/desktop/src/features/admin/DevicePosture.tsx` (dünne Hülle um `components/integrity/DevicePosturePanel.tsx`)
- Create: `apps/desktop/src/features/admin/ClockReleaseWizard.tsx`
- Create: `apps/desktop/src/features/admin/WriterTransitionWizard.tsx`
- Create: `apps/desktop/src/features/admin/RevocationConfirm.tsx`
- Test: `apps/desktop/src/features/admin/AdminPage.test.tsx`
- Test: `apps/desktop/tests/e2e/admin-trust.spec.ts`

**Interfaces:**
- Consumes: `ea-admin` services (`RegistryWorkflowService`, `RootCeremonyService`, `ClockReleaseService`, `WriterTransitionService`, `operator_exchange`, `revocation`, `production_state`) hinter Wirt-Ports; `ReauthPurpose::{AdminRootCeremony, ClockSkewRelease, RecoveryTest}`; `DevicePostureReport` über den bestehenden Kommando `device_posture_report`.
- Produces: separated pending/fingerprint/authorization/Root-export/Root-import/publication steps and no Admin content access; a Go-live checklist whose `productionReady` is `true` only when every requirement is `Confirmed`.

- [x] **Step 1: Write separation and full-fingerprint tests**

```tsx
it('does not collapse request fingerprint approval and Root import', async () => {
  render(<AdminPage bridge={pendingDeviceBridge()} />)
  expect(screen.getByText('Anfrage ausstehend')).toBeVisible()
  await user.click(screen.getByRole('button', { name: 'Fingerprint vergleichen' }))
  expect(screen.getByLabelText('Vollständiger Fingerprint')).toHaveTextContent(/([0-9A-F]{2}:){31}[0-9A-F]{2}/)
  expect(screen.getByRole('img', { name: 'QR-Code des vollständigen Fingerprints' })).toBeVisible()
  expect(screen.queryByText('Gerät aktiv')).not.toBeInTheDocument()
})
```

- [x] **Step 2: Run Admin UI tests and verify missing UI**

Run: `pnpm --dir apps/desktop test --run AdminPage`

Expected: FAIL because Admin commands/components do not exist.

- [x] **Step 3: Implement guided, explicit ceremonies**

Separate pending request, full fingerprint plus QR/second channel, Admin authorization, offline Root signing/export/import, and resulting Registry publication as a closed step enumeration (`ea-admin::ceremony_steps`) that the host advances one step at a time. Require fresh native re-authentication (`session_reauthenticate` with the exact purpose) before Admin/Root actions. The conscious key-source selection of §17.3 belongs to the place where the Root or Recovery key is used — the offline Root station and the recovery CLI (Task 7 delivers the encrypted-container and PKCS#11 sources); the desktop Admin holds exactly one key, the OS-bound operator binding, so there is nothing to select on this surface, and the Root steps here are export and import of the exchange file only (review ruling DRK-274, 2026-09-07). Show two-Admin readiness, key backup state, Registry age/lease, policy profile, Evidence policy, last Recovery test, Writer transition state, and every device-posture requirement as `bestätigt`, `nicht erfüllt`, or `nicht automatisch prüfbar` with its evidence code — the three words are the German rendering of the closed union `GoLiveRequirementStatus` emitted from `ea-admin::go_live`, in the manner of `SyncStatus`. Never render `Unknown` as green or production-ready: `productionReady` is computed in Rust and is `false` whenever any requirement is not `Confirmed`; export unresolved items as the deterministic Go-live evidence checklist (`ea.go-live-checklist/v1`). Device posture reuses `components/integrity/DevicePosturePanel.tsx`, which already keeps pass/fail/unknown apart. When future-clock skew blocks, offer the clock-release wizard only to a verified Admin with `ClockReleaseAvailability::Offered`, display floor/wall clock/signed limit (`max_future_clock_skew_ms`)/expiry, require one of the three allowlisted `ClockReleaseJustificationV1` values plus re-authentication, and state explicitly that the release changes neither time floor, Registry expiry, nor lease — the outcome view carries these three as fields, never as prose alone. Revocation copy renders `RevocationEffect::recalls_issued_grants` and `recalls_decrypted_plaintext` (both always `false`) as the statement that past grants and decrypted data cannot be recalled. Do not show incident content or enable Reader functions from Admin capability: the administration route is enabled by role `organizationadmin` plus capability `administration`, the capture route stays bound to the Writer, and the admin session sees no capture route.

- [x] **Step 4: Run keyboard, wrong-role, stale-session, and E2E ceremony tests**

Run: `pnpm --dir apps/desktop test --run && pnpm --dir apps/desktop exec playwright test tests/e2e/admin-trust.spec.ts`

Expected: PASS; all ceremony steps have headings/statuses, focus restoration, accessible QR alternative, and no role escalation. The Playwright run is a manual witness: `desktop:e2e` is in no automated gate.

- [x] **Step 5: Commit Administration UI workstream**

```bash
git add apps/desktop apps/web/src/bridge crates/ea-admin crates/ea-ui-contracts Cargo.lock pnpm-lock.yaml
git commit -m "feat(desktop): add guided Trust administration"
```

## Workstream B: Recovery, Historical Re-grant, Recovery Test, and Amendments

### Task 7: Offline Key Sources and Complete Recovery CLI Grammar

> **Gegen den Arbeitsbaum vermessen (2026-09-07, DRK-275).** Der Abschnitt wurde geschrieben,
> bevor die Stufen 4 und 5 ausgeliefert haben. Korrigiert sind: **die Crate der
> Schlüsselquellen.** `ea-key-provider` ist die Grenze des Writers; sein Kontrakt führt bewusst
> keinen KEM-Port (`crates/ea-key-provider/src/contract.rs:347-350`), und `lib.rs:41-56` pinnt
> per `compile_fail`, dass aus `KeyPurpose::{RecoveryKem, HistoricalGrantAuthority, KeyApprover}`
> kein lokaler Zweck wird. Ein Recovery- oder HGA-Schlüsselcontainer dort kehrte diese Typzusage
> um und veraltete zugleich die Begründung der wasm32-Ausnahme
> (`tools/xtask/src/main.rs:214-222`, „Writer device"). Die Quellen entstehen deshalb in
> `ea-recovery` — der einzigen Crate, die laut ihrem Kopf Klartext in Händen hält und Zieldateien
> mit restriktiven Rechten anlegt (`crates/ea-recovery/src/lib.rs:3-7`); `ea-key-provider` bleibt
> unberührt. **Die Abhängigkeits-ADR** (`docs/adr/0001-toolchain-and-cryptography-dependencies.md`)
> ist zu Argon2, scrypt, PBKDF2 und PKCS#11 stumm — weder gepinnt noch abgelehnt; die „reviewte
> KDF/AEAD-Konfiguration" wird dort in DIESEM Task nachgetragen (Argon2id über `argon2`; die AEAD
> bleibt das gepinnte ChaCha20-Poly1305 hinter `ea_crypto::aead_seal`, es kommt keine zweite).
> **PKCS#11:** kein Modul im Baum, keines auf dem Host, kein SoftHSM im Browser-Container;
> `cryptoki` zöge über `cryptoki-sys`/`libloading` die native Toolchain-Varianz in den Graphen,
> die ADR 0001 `:75-77` für OpenSSL/`ring` abgelehnt hat. Der Task liefert die explizite Referenz
> (Modul, Token, Schlüssel-ID — alle drei Pflicht, keine Voreinstellung, kein „erstes Token") und
> den PIN-Kanal; die Bindung an ein Modul ist eine benannte Grenze mit Exitcode 21 nach dem Muster
> von `--report-signing-key` (ADR 0001, „Blocked"). **`grant` und `recovery-test`:** nichts im Baum
> erzeugt oder prüft einen historischen Grant (`crates/ea-verify/src/recipient.rs:236-238` weist
> `GrantKindV1::Historical` als `AuthorizationUnverifiable` ab); `HistoricalGrantService` ist
> Task 8, `RecoveryTestService` und die Rust-Bindung von `ea.key-inventory/v1`
> (`schemas/reports/v1/key-inventory.schema.json`, seit Stufe 1) sind Task 9. Beide Kommandos
> liefern hier die vollständige Grammatik, verify-before-use über `commands::verified`, die
> explizite Auflösung ihrer Schlüsselquellen, die Lesbarkeit ihrer Dateieingaben und die
> Exitcodes — und enden danach mit 21 und dem benannten fehlenden Dienst, nie mit einem
> Teilerfolg und nie mit einer Ausgabe auf stdout. Der Step-1-Zeuge des ursprünglichen Textes
> (`grant … .assert().success()`) ist deshalb unerreichbar und ersetzt. **Der Testrahmen:**
> `assert_cmd` gibt es nicht und kommt nicht (`apps/cli/tests/commands.rs:5-7`); Prozesszeugen
> laufen über `std::process::Command::new(env!("CARGO_BIN_EXE_einsatzarchiv"))` und die
> `live_clock_*`-Familie aus `apps/cli/tests/support`. Das Paket heißt `einsatzarchiv-cli`, die
> Binary `einsatzarchiv`. **JSON:** `schemas/` ist geschlossen (`apps/cli/src/output.rs:31-37`);
> die Kommandos emittieren weiterhin nur `ea.verification-report/v1`. **Der Geheimniskanal:**
> Passphrase und PIN kommen aus einer Datei mit restriktiven Rechten, die in der
> Quellenangabe benannt ist — nie aus argv (sichtbar in `ps`), nie aus der Umgebung, nie aus
> einem Prompt (ein echofreier Terminalprompt bräuchte `termios`, also eine weitere Kiste).
> **Ausstellen ist kein Kommando dieses Tasks:** `EncryptedKeyContainer::seal`/`write_new` sind
> Bibliotheksfunktionen, die die Zeugen nutzen; ein ausstellendes Kommando steht nicht in §16.1 und
> kommt mit der Zeremonie, die den jeweiligen Schlüssel erzeugt (Root/Recovery/HGA — Tasks 2, 8, 9
> oder die Desktop-Administration), nicht mit einem Klartext-Exportpfad.
> **Die Haken** dieses Abschnitts hatte `111d406` zusammen mit denen der Tasks 5–13 gesetzt,
> ohne dass etwas gebaut war; sie sind hier zurückgesetzt.

**Files:**
- Create: `crates/ea-recovery/src/key_source.rs` (Quellengrammatik `<path>` | `file:<path>` | `container:<path>;passphrase-file=<path>` | `pkcs11:module=<path>;token=<label>;id=<hex>;pin-file=<path>`; Auflösung zu Empfänger- oder Signierschlüssel; kein Scannen, keine Voreinstellung)
- Create: `crates/ea-recovery/src/encrypted_container.rs` (`EINSATZARCHIV-KEY-CONTAINER-v1`: deterministisches CBOR, Argon2id mit gepinnten Parametern, `ea_crypto::aead_seal`/`aead_open` mit dem Kopf als AAD, Schlüsselart im Kopf; 0600 beim Schreiben, Ablehnung offener Rechte beim Lesen)
- Create: `crates/ea-recovery/src/pkcs11.rs` (explizite Referenz, PIN-Kanal; Modulbindung als benannte Grenze)
- Create: `crates/ea-recovery/src/grant.rs`, `crates/ea-recovery/src/recovery_test.rs` (Eingabefassaden: verify-before-use, Quellenauflösung, Dateilesbarkeit — ohne Prozessstart messbar; Task 8 und 9 setzen ihre Dienste darauf)
- Modify: `crates/ea-recovery/src/lib.rs`, `crates/ea-recovery/src/error.rs`, `crates/ea-recovery/src/exit.rs`, `crates/ea-recovery/src/decrypt.rs`, `crates/ea-recovery/src/target.rs`, `crates/ea-recovery/Cargo.toml`, `Cargo.toml` (`argon2`), `Cargo.lock`
- Modify: `docs/adr/0001-toolchain-and-cryptography-dependencies.md` (Zeile `argon2`; Abschnitt „Blocked: PKCS#11 module binding")
- Create: `apps/cli/src/commands/grant.rs`
- Create: `apps/cli/src/commands/recovery_test.rs`
- Modify: `apps/cli/src/args.rs`, `apps/cli/src/commands/mod.rs`, `apps/cli/src/commands/decrypt.rs`, `apps/cli/src/output.rs`
- Test: `crates/ea-recovery/tests/offline_sources.rs`, `crates/ea-recovery/tests/grant_inputs.rs`
- Test: `apps/cli/tests/full_grammar.rs`; Modify: `apps/cli/tests/commands.rs` (Grammatikpin; `exit_codes.rs` pinnt den Textbericht, nicht die Grammatik, und bleibt unverändert)

**Interfaces:**
- Consumes: explicit external anchor (`ea_recovery::load_trust_anchor`), `ea_crypto::{aead_seal, aead_open, HpkeRecipientPrivateKey, CoseSigner, SecretBytes, SecretVec}`, the `argon2` crate pinned in ADR 0001.
- Produces: `ea_recovery::{KeySourceSpec, resolve_recipient_key, resolve_signing_key, EncryptedKeyContainer, Pkcs11KeyReference, grant_inputs, recovery_test_inputs}`; the full §16.1 grammar including `grant` and `recovery-test`; no key-source auto-discovery, no plaintext export fallback, no implicit anchor.

- [x] **Step 1: Write full grammar and key-source separation tests**

```rust
#[test]
fn grant_requires_distinct_recovery_authority_authorization_and_recipient_inputs() {
    // Drei der vier Pflichtschalter fehlen: Aufruffehler VOR jedem gelesenen Byte,
    // der fehlende Schalter steht woertlich auf stderr, stdout bleibt leer.
    let output = run(&[
        "--trust-anchor", &laid.anchor_path(), "grant", &laid.archive_path(),
        "--recovery-key", &laid.recovery_key_path(),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--authority-key"));
    assert!(output.stdout.is_empty());
}

#[test]
fn a_container_with_the_wrong_passphrase_fails_with_fourteen_and_leaks_nothing() {
    let sealed = EncryptedKeyContainer::seal(KeyKind::RecipientKem, &secret, passphrase("richtig"));
    assert!(matches!(sealed.open(passphrase("falsch")), Err(RecoveryError::ContainerOpen)));
}
```

- [x] **Step 2: Run CLI tests and verify missing commands/providers**

Run: `cargo test --locked -p ea-recovery --test offline_sources && cargo test --locked -p einsatzarchiv-cli --test full_grammar`

Expected: FAIL because the key-source grammar, the encrypted container, the PKCS#11 reference and both commands are absent.

- [x] **Step 3: Implement explicit key-source adapters and complete commands**

Implement the full grammar from §16.1, always requiring `--trust-anchor`. Key sources are named explicitly through `ea_recovery::KeySourceSpec`; a bare path keeps the Stage-4 file form (32 raw bytes or 64 hex characters). Encrypted containers use Argon2id with the parameters pinned in ADR 0001 and the already pinned ChaCha20-Poly1305 behind `ea_crypto::aead_seal`, bind the container header as AAD, carry the key kind so a recovery key can never be read as a signing key, are written with mode 0600 and refused when readable by group or others. Passphrase and PIN are read from a named file with the same restrictive-permission rule, never from argv or the environment. PKCS#11 references require module path, token label and key id; nothing is defaulted, scanned or inferred, and the unbound module ends with exit 21 naming the boundary. `verify` runs before `decrypt`, `grant`, `export`, and `recovery-test`; `grant` and `recovery-test` resolve every input and then refuse with exit 21 naming the Task-8 respectively Task-9 service. Output supports the existing text/JSON schema and the established exit codes.

- [x] **Step 4: Run wrong-passphrase, open-permissions, missing-switch, and grammar tests**

Run: `cargo test --locked -p ea-recovery --test offline_sources && cargo test --locked -p einsatzarchiv-cli --test full_grammar`

Expected: PASS; no command accepts the archive's own anchor as implicit trust; a `pkcs11:` source ends with 21 naming the unbound module; a container or secret file with open permissions is refused before it is read.

- [x] **Step 5: Commit offline key sources and full CLI**

```bash
git add crates/ea-recovery apps/cli docs/adr Cargo.toml Cargo.lock
git commit -m "feat(recovery): add explicit offline key sources"
```

### Task 8: Two-Approver Historical Re-grant

**Gemessene Korrektur DRK-250:** Die Recovery-Grundfläche lebt bereits in
`crates/ea-recovery/src/grant.rs`. `KeyProvider` signiert typisierte Payloadbytes;
ein allgemeiner `DigestSigner` ist kein Produktionsport. Die Rust-Kerne sind
synchron. Ein gemeinsam konsumierter, nicht frei konstruierbarer
`VerifiedGrantAuthorization` gehört in `ea-trust`, nicht in `ea-admin`, damit
keine Abhängigkeitsschleife entsteht. Der gemeinsame Approver-Prüfer in
`crates/ea-sync-server/src/historical_grant.rs` muss Personen über
`authoritySubjectId` unterscheiden; Task 11 konsumiert dieselbe Korrektur.
Zum Umfang gehören der tatsächliche CLI-Erzeugungspfad, Serverannahme und
-auslieferung sowie historische Auswahl und Ablaufprüfung bei jedem Öffnen in
`ea-verify`/`ea-reader`. Vorhandene Format-/Signaturprüfung wird wiederverwendet.
Die nachstehenden Signaturskizzen beschreiben Rollen und Beweisgrenzen; die
konkrete synchrone API wird an diese vorhandenen Ports angepasst.

**Nachmessung 2026-09-13 (DRK-250, HEAD `8be0a47`):** Korrigiert sind Namen,
Pfade und Signaturen; keine Zusage entfällt. Der Autorisierungsprüfer liegt in
`crates/ea-trust/src/grant_authorization.rs` (`VerifiedGrantAuthorization` :37,
`verify_grant_authorization` :53, `verify_archived_grant_authorization` :71,
`distinct_authority_subjects` :137, `EA-GRANT-AUTH-EXPIRED` :25); eine Datei
`crates/ea-admin/src/grant_authorization.rs` gibt es nicht. Die Ports heißen
`RecoveryKem` (`crates/ea-recovery/src/historical_grant.rs:63`),
`HistoricalGrantSigner` (:84), `GrantRegistrySource` (:97, wählt Kopf und
Zeitboden bei jedem Aufruf neu) und `GrantOperatorContext` (:100, trägt
Gerätezertifikat, `OperatorSessionProof` und OS-Konto).
`HistoricalGrantService::create` (:157) ist eine synchrone assoziierte Funktion
ohne `&self` mit Fehler `HistoricalGrantError`; `effectiveNow` und der frische
Operatorbeweis werden weiterhin konsumiert, nur nicht als eigene Parameter. Die
native Komposition mit der Zweckprüfung `ReauthPurpose::HistoricalRegrant` liegt in
`crates/ea-admin/src/historical_grant.rs:19-24`, der CLI-Pfad in
`apps/cli/src/commands/grant.rs`, die Serverannahme in
`crates/ea-sync-server/src/historical_grant.rs`, die historische Auswahl in
`crates/ea-verify/src/historical.rs`, `EA-GRANT-EXPIRED` in
`crates/ea-reader/src/verify.rs:124`; die Auditaktion ist
`LocalAuditActionV1::HistoricalRegrant` (`crates/ea-format/src/local_audit.rs:778`).
Die Kernzeugen in `crates/ea-recovery/tests/historical_grant.rs` sind `#[test]`; die
Testnamen in Step 1 sind Skizzen, sinngleiche Zeugen stehen dort bei :130, :210
und :264. Asynchron ist nur der Systemzeuge
`tests/ea-system-tests/tests/e2e_historical_grant.rs:32`.

**Files:**
- Create: `crates/ea-recovery/src/historical_grant.rs`
- Create: `crates/ea-trust/src/grant_authorization.rs`
- Create: `crates/ea-admin/src/historical_grant.rs`
- Create: `crates/ea-verify/src/historical.rs`
- Modify: `apps/cli/src/commands/grant.rs`, `crates/ea-sync-server/src/historical_grant.rs`, `crates/ea-reader/src/verify.rs`
- Test: `crates/ea-recovery/tests/historical_grant.rs`
- Test: `tests/ea-system-tests/tests/e2e_historical_grant.rs`
- Test: `apps/server/tests/historical_grant_api.rs`, `apps/cli/tests/operator_grant/mod.rs`

**Interfaces:**
- Consumes: verified Entry and original Recovery grant (`VerifiedRecoveryEntry`), Recovery `RecoveryKem`, HGA `HistoricalGrantSigner`, `VerifiedGrantAuthorization`, recipient certificate, `effectiveNow` via `GrantRegistrySource`, fresh `OperatorSessionProof` via `GrantOperatorContext`, and `LocalAuditService`.
- Produces: `HistoricalGrantService::create -> Result<ExactObjectBytes, HistoricalGrantError>` with no `.eip` mutation.

- [x] **Step 1: Write separation, explicit-target, and expiry tests**

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

- [x] **Step 2: Run Re-grant tests and verify workflow is absent**

Run: `cargo test --locked -p ea-recovery --test historical_grant && cargo test --locked -p ea-system-tests --test e2e_historical_grant`

Expected: FAIL because Authorization and historical grant creation are absent.

- [x] **Step 3: Implement separate proof-state inputs**

```rust
// crates/ea-recovery/src/historical_grant.rs:154-167 (gemessen 2026-09-13)
impl HistoricalGrantService {
    pub fn create(
        entry: &VerifiedRecoveryEntry,
        authorization: &VerifiedGrantAuthorization,
        recovery: &dyn RecoveryKem,
        authority: &dyn HistoricalGrantSigner,
        issuer_certificate: CertificateHash,
        recipient_certificate: &[u8],
        registry: &dyn GrantRegistrySource,
        operator: GrantOperatorContext<'_>,
        audit: &dyn LocalAuditService,
    ) -> Result<ExactObjectBytes, HistoricalGrantError>;
}
```

Authorization binds organization, Registry head/sequence, sorted explicit Entry hashes, recipient thumbprint/certificate, purpose, and `expiresAt`, with two valid active distinct-subject `historicalGrantApprove` signatures. Require native re-authentication specifically for `ReauthPurpose::HistoricalRegrant`, matching the active bound operator and current device; no generic Admin or Recovery session proof is accepted. Recompute `effectiveNow`; decapsulate CEK only from original initial Recovery grant in protected memory; HPKE-wrap to selected Reader; sign with capability `historicalGrant`; bind original Recovery grant and Authorization hashes. Zero CEK. Preserve exact `.eip` bytes. Before releasing the new grant, flush a signed `historicalRegrant` local audit event containing only Authorization, Entry, original Recovery grant, recipient certificate, and new grant hashes plus outcome. Server and Reader Stage 3/4 checks close acceptance/delivery/open expiry.

- [x] **Step 4: Run end-to-end create/upload/deliver/open and replay-after-expiry tests**

Run: `cargo test --locked -p ea-recovery --test historical_grant && cargo test --locked -p ea-system-tests --test e2e_historical_grant`

Expected: PASS; wrong Entry/recipient/Registry/original grant, duplicate subjects, or expired/replayed authorization fails at every boundary.

- [x] **Step 5: Commit historical re-grant**

```bash
git add crates/ea-recovery crates/ea-trust crates/ea-admin crates/ea-verify crates/ea-sync-server crates/ea-reader apps/cli apps/server tests/ea-system-tests
git commit -m "feat(recovery): issue authorized historical grants"
```

### Task 9: Guided Recovery Test and Key-Inventory Report

**Gemessene Korrektur DRK-250:** `recovery_test.rs` existiert als Fassade;
Inventarschema und Recovery-Test-Challenge-Kryptografie existieren ebenfalls.
Sie werden erweitert und integriert, nicht parallel neu gebaut. Der gemeinsame
Testkern muss sowohl von der wirklichen CLI als auch vom Desktop-Host erreichbar
sein. `LocalAuditService::record_signed` ist synchron. UI-Zeugen liegen unter
`apps/desktop/tests/e2e`, nicht im Rust-Testwurzelverzeichnis. Ein Fake-Bridge-Test
ersetzt keinen Nachweis der produktiven Host-Komposition oder der dauerhaften,
verschlüsselten Teststatus-Aktualisierung nach vollständig erfolgreichem Test.

**Nachmessung 2026-09-13 (DRK-250, HEAD `8be0a47`):** Einen
`RecoveryTestService::run` gibt es nicht; der Name steht nur noch im Kommentar
`crates/ea-recovery/src/recovery_test.rs:9`. Der Testkern ist `RecoveryTestRun`
(`crates/ea-recovery/src/test_run.rs:74`) mit `RecoveryRunOutcome` (:89) sowie
`VerifiedCompletedRecoveryReport`/`verify_completed_recovery_report`
(`crates/ea-recovery/src/completion.rs:105`, :182). Nativ führt ihn
`RecoveryTestRuntime` (`crates/ea-admin/src/recovery_test_runtime.rs:73`) mit
`run_restored_test`/`run_restored_test_guided`
(`recovery_test_runtime/execution.rs:204`, :236) und
`read_completed_report`/`read_failed_report` (:511, :557); die Auditaktion
`LocalAuditActionV1::RecoveryTest` schreibt `recovery_test_runtime.rs:223`/:346.
`Modify` statt `Create` gilt nur für Dateien, die an der Basis `1e5e7de` schon
bestanden (hier `recovery_test.rs`); in der Fortsetzung entstandene Dateien
bleiben `Create`. Der Browserzeuge heißt `apps/desktop/tests/e2e/recovery.spec.ts`
und ist ausdrücklich nur IPC-Zeuge (:13); `recovery-test.spec.ts` existiert nicht.
Die Kernzeugen sind `#[test]`; `one_missing_or_wrong_medium_fails_the_overall_test`
aus Step 1 hat im Ziel `--test recovery_test` noch kein Gegenstück, die Zusage
bleibt. Native CLI-Zeugen liegen in `apps/cli/tests/operator_recovery/`; die
Desktop-Module dort verlangen `--features desktop-fixture` (`mod.rs:4-7`), die
geführten Proben in `guided.rs` (:151, :197, :244, :376, :451, :514) sind
`#[ignore]` und laufen im Normalziel nicht mit.

**Files:**
- Modify: `crates/ea-recovery/src/recovery_test.rs`
- Create: `crates/ea-recovery/src/key_inventory.rs`
- Create: `crates/ea-recovery/src/challenge.rs`
- Create: `crates/ea-recovery/src/test_run.rs`, `crates/ea-recovery/src/completion.rs`
- Create: `crates/ea-admin/src/recovery_test_runtime.rs`, `crates/ea-admin/src/recovery_test_runtime/{execution,guided,import,inputs,native_medium}.rs`
- Create: `apps/desktop/src/features/admin/RecoveryTestWizard.tsx`
- Create: `apps/desktop/src-tauri/src/commands/recovery.rs`, `apps/desktop/src-tauri/src/commands/recovery/wire.rs`
- Test: `crates/ea-recovery/tests/recovery_test.rs`
- Test: `apps/desktop/src/features/admin/RecoveryTestWizard.test.tsx`
- Test: `apps/desktop/tests/e2e/recovery.spec.ts`
- Test: `apps/cli/tests/operator_recovery/` (`mod.rs`, `guided.rs`, `desktop_portable.rs`)

**Interfaces:**
- Consumes: independent anchor, unchanged archive copy, `ea.key-inventory/v1`, each explicit backup source, fresh `ReauthPurpose::RecoveryTest` proof, and `LocalAuditService`.
- Produces: `RecoveryTestRun` with `RecoveryRunOutcome` (`ea-recovery`), driven natively by `RecoveryTestRuntime` (`ea-admin`), per-medium results, overall success only if complete, signed or hashed cleartext-free report, and durable signed audit reference.

- [x] **Step 1: Write incomplete-inventory and challenge-domain tests**

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

- [x] **Step 2: Run Recovery test tests and verify workflow is absent**

Run: `cargo test --locked -p ea-recovery --test recovery_test && pnpm --dir apps/desktop test --run RecoveryTestWizard`

Expected: FAIL because key inventory/test/report/UI do not exist.

- [x] **Step 3: Implement read-only full-inventory verification**

Verify anchor, full archive/head/Trust/Registry, and deterministic sample from every schema/suite/Writer epoch. For each Root/Admin/Writer/Reader/Recovery/server/Approver/HGA/`deletionAttest` backup, derive public key and compare expected thumbprint/certificate. Sign only a random recovery-test domain challenge for signing keys. For every Recovery backup, open the unchanged setup test Entry in protected memory, validate it, display no plaintext, then zero CEK/plaintext/challenge. For non-exportable device/hardware keys, test provider access, native presence, and certificate binding instead of export.

Report binds test ID, anchor hash, archive head, `effectiveNow`, release/schema/suite versions, pseudonymous medium ID, expected/observed thumbprint, test kind/result, and overall result. No private key or decrypted payload. After report hash/signature verification, record and flush a signed `recoveryTest` local audit event containing only the report hash and overall outcome; bind its event ID into the encrypted local status. UI prompts one medium at a time, shows individual result, and updates last/next-due status only after complete success and audit persistence.

- [x] **Step 4: Run all key-profile, wrong-media, cleartext, and UI E2E tests**

Run:

```bash
cargo test --locked -p ea-recovery --test recovery_test
pnpm --dir apps/desktop test --run RecoveryTestWizard
pnpm --dir apps/desktop exec playwright test tests/e2e/recovery.spec.ts
```

Expected: PASS; archive/Registry/grants/key status remain byte-for-byte unchanged.

- [x] **Step 5: Commit guided Recovery testing**

```bash
git add crates/ea-recovery crates/ea-admin apps/desktop apps/desktop/tests/e2e apps/cli schemas/reports
git commit -m "feat(recovery): verify every key backup safely"
```

### Task 10: End-to-End Amendment Creation

**Gemessene Korrektur DRK-250:** Die Reader-Oberfläche lebt in `apps/web`.
`CorrectionReference` besitzt gegenwärtig öffentliche Felder und enthält keine
Original-Einsatznummer: der Import muss das Original anhand seiner verifizierten
Identität auflösen und exakt abgleichen, statt einen frei konstruierten DTO als
Beweis zu akzeptieren. Der normale Writer unterstützt bisher Incident und
KeyTransition; Content, Preview und Finalisierung werden um Amendment erweitert.
Task 12 erweitert dieselbe Writer-Infrastruktur später um DestructionEvidence;
die Arbeiten an diesen gemeinsamen Dateien laufen nacheinander. Browserzeugen
liegen unter `apps/desktop/tests/e2e` und gegebenenfalls `apps/web/tests/e2e`.

**Nachmessung 2026-09-13 (DRK-250, HEAD `8be0a47`):**
`AmendmentDraftService::create_from_reference(&self, reference: CorrectionReference,
content: AmendmentContentV1, observed_now: UnixMillis) -> Result<AmendmentInputV1,
WriterError>` (`crates/ea-admin/src/amendment.rs:25-30`) ist synchron und
delegiert an `WriterService::prepare_amendment`; die Skizze in Step 1 (async,
Freitext statt `AmendmentContentV1`) beschreibt nur die Rollen, der Zeuge
`crates/ea-admin/tests/amendment.rs:15` ist `#[test]`. Die Writer-Hälfte liegt in
`crates/ea-writer/src/{amendment,content,finalize}.rs` mit
`crates/ea-writer/tests/amendment.rs`. Das Verzeichnis
`apps/desktop/src/features/reader` gibt es nicht; der Thread liegt in
`apps/web/src/features/reader/AmendmentThread.tsx`. Der Browserzeuge
`apps/desktop/tests/e2e/amendment.spec.ts` ist nur UI/IPC-Zeuge (:4) mit einem Fall;
die Playwright-Zusage aus Step 4 für mehrere Nachträge und falsche Verweise bleibt.
Das Playwright-Kommando löst relativ zu `apps/desktop` korrekt auf
(`playwright.config.ts:95`); falsch waren nur die Files-Zeile und `git add tests/e2e`.

**Files:**
- Create: `crates/ea-admin/src/amendment.rs`
- Create: `crates/ea-writer/src/amendment.rs`
- Modify: `crates/ea-writer/src/content.rs`, `crates/ea-writer/src/finalize.rs`
- Create: `apps/desktop/src/features/writer/AmendmentDraft.tsx`
- Modify: `apps/web/src/features/reader/AmendmentThread.tsx`
- Create: `apps/desktop/tests/e2e/amendment.spec.ts`
- Test: `crates/ea-admin/tests/amendment.rs`
- Test: `crates/ea-writer/tests/amendment.rs`, `apps/desktop/src/features/writer/AmendmentDraft.test.tsx`, `apps/web/src/features/reader/AmendmentThread.test.tsx`

**Interfaces:**
- Consumes: Stage 4 `CorrectionReference`, Writer draft/finalization, verified Reader thread.
- Produces: `AmendmentDraftService::create_from_reference` and a normal immutable `amendment` Entry.

- [x] **Step 1: Write exact-reference and original-preservation tests**

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

- [x] **Step 2: Run amendment tests and verify Writer half is absent**

Run: `cargo test --locked -p ea-admin --test amendment && pnpm --dir apps/desktop exec playwright test tests/e2e/amendment.spec.ts`

Expected: FAIL because correction-reference import and amendment draft UI do not exist.

- [x] **Step 3: Implement normal Writer amendment finalization**

Accept only a verified cleartext-free reference with original ID/hash/sequence, then require Writer to enter reason and structured change text; operator snapshot is current signed binding. Validate original exists and reference matches. Use normal review, irreversibility confirmation, grant plan, encryption, commit, and sync path. Reader groups all amendments without hiding/replacing original.

- [x] **Step 4: Run multiple-amendment, wrong-reference, and original-byte tests**

Run: `cargo test --locked -p ea-admin --test amendment && pnpm --dir apps/desktop exec playwright test tests/e2e/amendment.spec.ts`

Expected: PASS; arbitrary plain reference text cannot forge a link.

- [x] **Step 5: Commit amendment workflow**

```bash
git add crates/ea-admin crates/ea-writer apps/desktop apps/desktop/tests/e2e apps/web
git commit -m "feat(admin): finalize linked amendments"
```

## Workstream C: Controlled Destruction

### Task 11: Destruction Authorization and Deterministic State Machine

**Gemessene Korrektur DRK-250:** Autorisierungs-, Transition- und
Attestation-Formate sowie typisierte Signaturkontexte existieren bereits in
`ea-format`/`ea-crypto`. Die acht erlaubten Übergänge existieren in `ea-verify`
und werden gemeinsam genutzt. `VerifiedDestructionAuthorization` muss exakte
Bytes, Organisation, Registry-Version/-Hash und Autorisierungssequenz binden.
Die bestehende v1-Autorisierung enthält kein `expiresAt`: abgewiesen werden
abgelaufene/widerrufene Signierer, veraltete Registry und Operatorbeweise; es wird
kein neues Wirefeld erfunden. Das Datenschutz-Gate verlangt sowohl
`retention_policy.destruction_enabled` als auch
`eds_privacy_decision_document_hash` und gilt auch am Server. Die
Personenprüfung konsumiert die gemeinsame Korrektur aus Task 8. Native
zweckspezifische Prüfung erfolgt vor synchronem, dauerhaftem Audit; der
Auditdienst allein prüft Zweck und Frische nicht.

**Nachmessung 2026-09-13 (DRK-250, HEAD `8be0a47`):** Der Antragsweg liegt in
`crates/ea-destruction/src/service.rs` (`DestructionRequestService::request` :179,
`request_guarded` :194, Zweck `ReauthPurpose::Destruction` :168/:208) und ist
synchron; die dritte Skizze in Step 1 ist entsprechend synchron gefasst. Seine
Zeugen stehen in `crates/ea-destruction/tests/requests.rs` (:333
`request_is_signed_audited_durable_and_exact_replay_survives_reopen`, :373
`wrong_purpose_stale_account_and_audit_failure_never_publish_requested`), die
Serverannahme des Datenschutz-Gates in `crates/ea-destruction/tests/server_admission.rs`.
Die Testnamen in Step 1 sind Skizzen; sinngleich sind
`authorization.rs:14` `both_signed_privacy_conditions_are_required`, :26
`two_certificates_of_one_person_are_not_two_approvers` und `transitions.rs:3`
`exactly_eight_normative_edges_and_no_cancel_are_accepted`. „expired signatures" in
Step 4 ist im Sinne der Korrektur oben zu lesen: v1 trägt kein `expiresAt`.

**Files:**
- Create: `crates/ea-destruction/Cargo.toml`
- Create: `crates/ea-destruction/src/lib.rs`
- Create: `crates/ea-destruction/src/authorization.rs`
- Create: `crates/ea-destruction/src/state.rs`
- Create: `crates/ea-destruction/src/event.rs`
- Create: `crates/ea-destruction/src/service.rs`
- Test: `crates/ea-destruction/tests/authorization.rs`
- Test: `crates/ea-destruction/tests/transitions.rs`
- Test: `crates/ea-destruction/tests/requests.rs`, `crates/ea-destruction/tests/server_admission.rs`

**Interfaces:**
- Consumes: two active `destructionApprove` signers, Registry/time, documented privacy-enable policy, fresh `ReauthPurpose::Destruction` operator proof, and `LocalAuditService`.
- Produces: `VerifiedDestructionAuthorization`, `DestructionStateMachine::apply`, exact allowed transitions, idempotent event IDs, and signed local audit reference.

- [x] **Step 1: Write privacy gate, two-Approver, and transition-table tests**

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

#[test]
fn requested_transition_requires_matching_reauth_and_durable_audit() {
    assert!(service.request(&auth, &event, &targets, &fixtures::wrong_purpose_proof()).is_err());
    let requested = service.request(&auth, &event, &targets, &fixtures::destruction_proof()).unwrap();
    assert!(fixtures::audit_is_signed_and_flushed(requested.audit_exact_bytes()));
}
```

- [x] **Step 2: Run destruction-core tests and verify failure**

Run: `cargo test --locked -p ea-destruction --test authorization --test transitions --test requests`

Expected: FAIL because destruction authorization/state machine do not exist.

- [x] **Step 3: Implement closed states and event validation**

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

- [x] **Step 4: Run all valid/invalid/replay transition tests**

Run: `cargo test --locked -p ea-destruction --test authorization --test transitions --test requests`

Expected: PASS; one Approver, duplicate subject, wrong capability/target, stale Registry, and expired/invalid signatures fail (expired meaning expired or revoked signers, since v1 carries no `expiresAt`).

- [x] **Step 5: Commit destruction state core**

```bash
git add crates/ea-destruction Cargo.toml Cargo.lock
git commit -m "feat(destruction): authorize append-only destruction states"
```

### Task 12: Destroyed Entry Stub, Replica Attestation, and Resumable Executor

**Gemessene Korrektur DRK-250:** `.eds`-Format und Teile der
Vernichtungsrekonstruktion sind vorhanden. Zum Messzeitpunkt 2026-09-08 nahm
`ea-verify` `.eds` noch nicht in die technische Kette auf; seit `de019fc` tut es
das (`crates/ea-verify/src/archive.rs:441-445`, :565-609, neu
`crates/ea-verify/src/destroyed.rs`; Nachmessung 2026-09-13). Reader-Zustände
allein beweisen keine vollständige Autorisierungsprüfung. Der Umfang schließt deshalb
`crates/ea-verify/src/{archive,destruction}.rs`, Reader-Verifikation sowie echte
Server-/Archiv-/Replikadapter ein. Server-Ports, PostgreSQL/S3-Komposition und
Aufnahme von Transition-/Attestation-Ereignissen müssen den Executor tatsächlich
tragen. Ein Trait oder In-Memory-Harness allein genügt nicht. Nach Task 10 wird
die gemeinsame normale Writer-Pipeline für DestructionEvidence ergänzt.

**Nachmessung 2026-09-13 (DRK-250, HEAD `8be0a47`):** Ein `executor.rs` und ein
`DestructionExecutor::{plan,resume}` existieren nicht. Die Ausführung ist
aufgeteilt auf `crates/ea-destruction/src/{execution,job,local,local_attestation,purge,inventory,barrier,preflight,imported_preflight,original_authority}.rs`
(Eintritt `SqliteDestructionJobs::start_execution`, `execution.rs:45`); fortgesetzt
wird über `DestructionRequestService::resume`/`resume_historical`
(`service.rs:124`, :109). Die native Orchestrierung liegt in
`crates/ea-admin/src/destruction_runtime.rs` und `destruction_runtime/`, die
Serverseite zusätzlich in `crates/ea-sync-server/src/{managed_destruction,server_destruction}.rs`.
Ein `DeletionAttestationV1` gibt es nicht; das Wireformat ist
`ea_format::DeletionAttestationFieldsV1` (`crates/ea-format/src/etb.rs:287`), geprüft
als `VerifiedDeletionAttestation` (`attestation.rs:29`,
`verify_attestation_historical` :49). Die Testziele `--test resume` und
`--test e2e_destruction` existieren nicht. Resume-Zeugen sind
`crates/ea-destruction/tests/preflight.rs:31`, `requests.rs:97` und im CLI-Ziel
`apps/cli/tests/operator_destruction/{crash.rs:24,restart.rs:3}`. Die drei
Systemziele `e2e_destruction_{policy,admission_race,catalog_race}` sind
Admissionszeugen ohne physische Entfernung (`e2e_destruction_policy.rs:1-2`); der
physische Same-Job-Zeuge ist `einsatzarchiv-cli --test operator` unter
`process_native::destruction::` (`#[cfg(unix)]`, `apps/cli/tests/operator.rs:214-215,1473-1475`).
Dessen Desktop-Untermodul verlangt `--features desktop-fixture`
(`operator_destruction/mod.rs:923-924`); ohne das Feature laufen diese Fälle still
nicht mit. Server- und Systemziele brauchen die Integrationsumgebung. Die Zusagen
aus Step 4 (sofort, Backup-Frist, unerreichbar, ungültiger Stub, Replay,
`UnexplainedGap`) bleiben; welcher Zeuge sie trägt, ist seit 2026-09-14
entschieden (siehe folgende Nachmessung). Der native Erzeuger für
`incompleteUnreachableReplica→inProgress` aus Task 11 — in
`crates/ea-admin/src/destruction_runtime/` nennt nur `failure.rs` den Zustand — ist
per Ruling vom 13.09.2026 aus dem ersten Stufe-5-PR in das Folgeticket DRK-319
verschoben; die
Kante bleibt Zusage dieses Plans.

**Nachmessung 2026-09-14 (DRK-250, HEAD `041911d`, Abnahme
`.superpowers/sdd/2026-08-13-einsatzarchiv-stage-5-administration-recovery/claude-t12-t13-acceptance.md`):** Entschieden: Ein eigenes System-E2E
`tests/ea-system-tests/tests/e2e_destruction.rs` wird nicht angelegt. Sofort,
Backup-Frist, unerreichbar und Replay trägt physisch der native CLI-Zeuge
`einsatzarchiv-cli --features desktop-fixture --test operator process_native::destruction::`
gegen TLS, PostgreSQL, S3 mit ObjectLock, SQLCipher und den Produkt-Worker mit
OPFS. Die drei `e2e_destruction_*` bleiben Admissionszeugen. Ungültiger Stub und
`UnexplainedGap` sind deterministisch in `crates/ea-destruction/tests/stub.rs`,
`crates/ea-verify/tests/destruction_stub.rs` und
`crates/ea-reader/tests/{destroyed_stub,destruction_evidence,missing_grant}.rs`
bezeugt. Neben `destruction_jobs_api` trägt `apps/server/tests/destruction_api.rs`
Liefer-/Re-Grant-Sperre und Replay (:78, :439, :650).

Die Step-4-Aussage zu `UnexplainedGap` ist gemessen genauer: `EntryStatus::UnexplainedGap`
entsteht nur an einem `.eds`-Stub ohne autorisierende Verifikation. Einziger
Erzeuger ist `classify_stub` (`crates/ea-reader/src/verify.rs:642`, Zweig :674),
aufgerufen nur für `inventory.destroyed()` (:302-303). Ein fehlendes `.eip` ohne
Stub ist eine Sequenzlücke (`ChainGapV1`) ohne Zustandszeile, weil
`ReaderEntryStateV1::new` Entry- und Objekthash verlangt
(`crates/ea-reader/src/entry_state.rs:128-130`); Zeuge
`crates/ea-reader/tests/missing_grant.rs:86`. Ein nicht autorisierter Stub trägt
zusätzlich eine Sequenzlücke (`crates/ea-verify/src/archive.rs:617-630`); eine
Sequenzlücke beweist also nicht, dass kein Stub existiert.

Der Reader-/OPFS-Zeuge `process_native::destruction::transport::server::host::reader_opfs`
startet Vite auf `apps/web` (`apps/cli/tests/operator_destruction/transport/server/host/reader_opfs.rs:25-30`,
`reader_opfs.mjs:13`). Dessen Worker importiert `./pkg/ea_reader_wasm.js`
(`apps/web/src/bridge/opfs-worker.ts:42`). Das gitignorierte Paket erzeugt erst
`cargo run --locked -p xtask -- build-wasm` (`tools/xtask/src/main.rs:530`,
`--out-dir apps/web/src/bridge/pkg`). Die Servertransportzeugen des CLI-Ziels
binden `apps/server/tests/common/mod.rs` ein (`transport/server.rs:13-14`) und
brauchen deshalb wie die Serverziele `DATABASE_URL` und `EA_OBJECT_STORE_ENDPOINT`
(`common/mod.rs:56`, :65).

Rulings vom 13.09.2026:
- „Fortsetzen" erzeugt nie Zustand 4 (`apps/desktop/src-tauri/src/runtime/destruction.rs:768`,
  `runtime/destruction_transport.rs:252`). 1/2→4 entsteht nur über die eigene
  bestätigte Aktion `destruction_mark_incomplete` (`ebb6e03`; Angebot
  `runtime/destruction.rs:889`, Servermodus `destruction_transport.rs:310`). Native
  Zeugen: `apps/cli/tests/operator_destruction/desktop/failure.rs:97`, :202, :238
  und `transport/server/host/failure.rs:78`.
- Die Bindung des Übergangssignierers an die Auftragskomponente ist DRK-321.
  `verify_event`/`verify_event_historical` entnehmen das Zertifikat dem
  Signaturheader (`crates/ea-destruction/src/event.rs:77-79`, :127-129) und prüfen am
  Signierer Rolle und Fähigkeit `deletionAttest` (`crates/ea-crypto/src/cose.rs:1274-1275`);
  eine Komponentenbindung steht dort nicht. Geprüft wird die Komponente beim
  Publizieren (`destruction_transport.rs:556`) und am Server gegen den HTTP-Principal
  (`crates/ea-sync-server/src/managed_destruction.rs:154`).
- Web-Reader-Design §3 ist präzisiert (`16167c0`,
  `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md:57-66`): Als
  verwaltete Replik entfernt der Reader auf einen geprüften, administrativ
  signierten Auftrag nur den eigenen Cache und Index. Er signiert eine eigene,
  jobgebundene Löschattestierung. Er beantragt, startet, setzt fort oder bricht
  keine Vernichtung ab und signiert weder Übergang noch Autorisierung.

**Files:**
- Create: `crates/ea-destruction/src/stub.rs`
- Create: `crates/ea-destruction/src/attestation.rs`, `crates/ea-destruction/src/local_attestation.rs`
- Create: `crates/ea-destruction/src/{execution,job,local,purge,inventory,barrier,preflight,imported_preflight,original_authority}.rs` (statt eines einzelnen `executor.rs`)
- Create: `crates/ea-destruction/src/reconstruct.rs`, `crates/ea-destruction/src/reconstruct/`
- Create: `crates/ea-admin/src/destruction_runtime.rs`, `crates/ea-admin/src/destruction_runtime/`
- Create: `crates/ea-verify/src/destroyed.rs`; Modify: `crates/ea-verify/src/archive.rs`, `crates/ea-verify/src/destruction.rs`
- Modify: `crates/ea-sync-server/src/destruction.rs`; Create: `crates/ea-sync-server/src/managed_destruction.rs`, `crates/ea-sync-server/src/server_destruction.rs`
- Modify: `crates/ea-reader/src/entry_state.rs`
- Modify: `crates/ea-writer` (DestructionEvidence über die normale Pipeline; Zeuge `crates/ea-writer/tests/destruction_evidence.rs`)
- Test: `crates/ea-destruction/tests/stub.rs`
- Test: `crates/ea-destruction/tests/preflight.rs`, `crates/ea-destruction/tests/requests.rs` (Resume; `tests/resume.rs` existiert nicht)
- Test: `apps/cli/tests/operator_destruction/` (physischer Same-Job-Zeuge)
- Test: `apps/server/tests/destruction_jobs_api.rs`, `apps/server/tests/destruction_api.rs`
- Test: `tests/ea-system-tests/tests/e2e_destruction_policy.rs`, `e2e_destruction_admission_race.rs`, `e2e_destruction_catalog_race.rs`
- Test: `tests/ea-system-tests/tests/e2e_destruction.rs` — wird nicht angelegt (Entscheidung 2026-09-14); die physischen Zweige trägt `apps/cli/tests/operator_destruction/`, siehe Nachmessung

**Interfaces:**
- Consumes: verified authorization, managed replica adapters, archive transaction, server delivery block, Writer finalization.
- Produces: `SqliteDestructionJobs::start_execution` and `DestructionRequestService::{resume,resume_historical}` (in place of `DestructionExecutor::{plan,resume}`), exact `.eds`, `ea_format::DeletionAttestationFieldsV1` verified as `VerifiedDeletionAttestation`, and later `destructionEvidence` draft.

- [x] **Step 1: Write Stub continuity and restart tests**

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

- [x] **Step 2: Run Stub/resume tests and verify executor is absent**

Run: `cargo test --locked -p ea-destruction --test stub --test preflight --test requests && cargo test --locked -p einsatzarchiv-cli --features desktop-fixture --test operator process_native::destruction:: -- --test-threads=1`

Expected: FAIL because Stub/attestation/executor do not exist.

- [x] **Step 3: Implement verify-before-delete and attested distributed execution**

Accept authorization, block server delivery/re-grant, verify full pre-state and sign report, then per managed replica remove ciphertext, all grants, plaintext cache/index or schedule immutable backup expiration. Before removing each original `.eip`, create/flush/verify exact `.eds` containing original signed manifest/signature bytes, Entry/ciphertext/original object hashes, destruction ID, and Authorization hash. Remove `.eip` only after Stub durability. Collect signed attestations with pseudonymous replica ID/type, removed object hashes, result, backup deadline, and execution time.

Reconstruct current state and next action only from authorization/events/attestations; idempotently resume the same ID. Use `pendingBackupExpiry` while immutable deadlines remain, `incompleteUnreachableReplica` for known unreachable/unattested replicas, and `completeManagedScope` only when every managed object/cache is confirmed gone and every deadline elapsed. Prepare `destructionEvidence` with successes, pending/unreachable replicas, Stub hashes, and attestations; finalize through normal Writer flow. Never claim unknown exports/screenshots removed.

- [x] **Step 4: Run immediate, backup-expiry, unreachable, invalid-Stub, and replay tests**

Run:

```bash
cargo test --locked -p ea-destruction --test stub --test preflight --test requests
cargo run --locked -p xtask -- build-wasm
cargo test --locked -p einsatzarchiv-cli --features desktop-fixture --test operator process_native::destruction:: -- --test-threads=1
cargo test --locked -p einsatzarchiv-server --test destruction_api --test destruction_jobs_api -- --test-threads=1
cargo test --locked -p ea-system-tests --test e2e_destruction_policy --test e2e_destruction_admission_race --test e2e_destruction_catalog_race -- --test-threads=1
```

Expected: PASS; unauthorized file removal is never authorized destruction: a Stub without authorizing verification is `UnexplainedGap`, and a removed `.eip` without a Stub is a sequence gap without a state row. The three system targets are admission witnesses only; the physical branches run in the CLI target, whose Reader/OPFS witness needs the `build-wasm` package first (see Nachmessung 2026-09-14).

- [x] **Step 5: Commit destruction executor**

```bash
git add crates/ea-destruction crates/ea-admin crates/ea-verify crates/ea-sync-server crates/ea-reader crates/ea-writer apps/cli apps/server tests/ea-system-tests
git commit -m "feat(destruction): attest resumable archive destruction"
```

### Task 13: Destruction Administration UI

**Gemessene Korrektur DRK-250:** Die bestehenden Administration- und
Reauthentisierungsports besitzen bisher Testimplementierungen; der Desktop
startet ohne konfigurierte Ports. Diese Oberfläche braucht die echte
Host-Komposition des autorisierten Dienstes und dauerhafte Rekonstruktion,
nicht nur eine Vorschau mit einem Fake-Port. Tests liegen unter
`apps/desktop/tests/e2e`. Die exakt vorgegebene deutsche Statuskopie bleibt
unverändert.

**Nachmessung 2026-09-13 (DRK-250, HEAD `8be0a47`):** Die Vernichtungskommandos
liegen nicht in `commands/admin.rs`, sondern in
`apps/desktop/src-tauri/src/commands/destruction.rs:294-429`
(`destruction_read`, `_prepare`, `_start`, `_resume`, `_import_progress`,
`_synchronize`, `_authenticate_custodian`, `_export_reader_delivery`) und
`commands/destruction_evidence.rs`; die Host-Komposition in
`src/runtime/destruction.rs`, `src/runtime/destruction/` und
`src/runtime/destruction_transport.rs`. Die Statuskopie steht wörtlich in
`DestructionStatus.tsx:6-12`; ihr `it.each` liegt in `DestructionStatus.test.tsx:7`,
den der Vitest-Filter `DestructionWizard` nicht erfasst. Der Browserzeuge
`apps/desktop/tests/e2e/destruction.spec.ts` ist ein Grenzdouble (:10); „Restart" ist
dort ein Neuladen. Native Restart-Zeugen liegen in
`apps/cli/tests/operator_destruction/desktop/{pending,completion}.rs` und laufen nur
mit `--features desktop-fixture`.

**Nachmessung 2026-09-14 (DRK-250, HEAD `041911d`, Abnahme
`.superpowers/sdd/2026-08-13-einsatzarchiv-stage-5-administration-recovery/claude-t12-t13-acceptance.md`):** Seit `ebb6e03` liegen die Tauri-Kommandos in
`commands/destruction.rs:307-455`. Hinzugekommen ist `destruction_mark_incomplete`
(:393, registriert in `apps/desktop/src-tauri/src/lib.rs:145` und `build.rs:53`).

Ruling vom 13.09.2026: „Fortsetzen" erzeugt nie Zustand 4
(`src/runtime/destruction.rs:768`, `src/runtime/destruction_transport.rs:252`).
Zustand 4 entsteht nur über die eigene bestätigte Aktion „Als unvollständig
abschließen" mit dem Bestätigungsknopf „Endgültig als unvollständig abschließen"
(`DestructionWizard.test.tsx:73`, :91; `destruction.spec.ts:136-155`). Das Angebot
entscheidet der Host (`mark_incomplete_job`, `src/runtime/destruction.rs:889`);
`mark-incomplete-offer.ts` steuert nur die Sichtbarkeit. „Nach `inProgress` nur
Fortsetzen, nie Abbrechen" gilt unverändert; in `commands/destruction.rs` gibt es
kein Abbruchkommando.

Der Plan-Aufruf `pnpm --dir apps/desktop test --run DestructionWizard DestructionStatus`
war nicht die gemessene Form (`apps/desktop/package.json:9` ist nur `vitest`). Er
ließ außerdem `DestructionSurface`, `DestructionEvidence`, `destruction-contract`
und `mark-incomplete-offer` aus. Step 2/4 nennen die Dateien deshalb ausdrücklich.
Host-Komposition, IPC-Registrierung und Rollentor tragen `ea-desktop --lib` und die
Kommandoziele unter `apps/desktop/src-tauri/tests/`. Die nativen Desktop-Zeugen
(`pending`, `completion`, `failure`, `custodian`, `evidence`, `reader_delivery`)
laufen unter `process_native::destruction::desktop::` mit `--features desktop-fixture`.

**Files:**
- Create: `apps/desktop/src/features/admin/DestructionWizard.tsx`
- Create: `apps/desktop/src/features/admin/DestructionStatus.tsx`
- Create: `apps/desktop/src/features/admin/DestructionSurface.tsx`, `DestructionEvidence.tsx`, `destruction-contract.ts`, `destruction-evidence-bridge.ts`, `mark-incomplete-offer.ts`
- Create: `apps/desktop/src-tauri/src/commands/destruction.rs`, `apps/desktop/src-tauri/src/commands/destruction_evidence.rs`
- Create: `apps/desktop/src-tauri/src/runtime/destruction.rs`, `apps/desktop/src-tauri/src/runtime/destruction/`, `apps/desktop/src-tauri/src/runtime/destruction_transport.rs`
- Modify: `apps/desktop/src-tauri/src/commands/admin.rs` (Verwaltungsansicht trägt `destruction_enabled`, :286)
- Test: `apps/desktop/src/features/admin/DestructionWizard.test.tsx`
- Test: `apps/desktop/src/features/admin/DestructionStatus.test.tsx`, `DestructionSurface.test.tsx`, `DestructionEvidence.test.tsx`, `destruction-contract.test.ts`, `mark-incomplete-offer.test.ts`
- Test: `apps/desktop/src-tauri/tests/{destruction_commands,destruction_evidence_commands,reader_delivery_commands,writer_commands,admin_commands}.rs`
- Test: `apps/desktop/tests/e2e/destruction.spec.ts`
- Test: `apps/cli/tests/operator_destruction/desktop/` (native Restart- und Failure-Zeugen, `--features desktop-fixture`)

**Interfaces:**
- Consumes: policy privacy decision, two-Approver authorization import, destruction state/report DTOs, re-authentication.
- Produces: explicit irreversible process UI using exact German state copy.

- [x] **Step 1: Write disabled/privacy and state-copy tests**

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

- [x] **Step 2: Run UI tests and verify components are absent**

Run: `pnpm --dir apps/desktop exec vitest run src/features/admin/DestructionWizard.test.tsx src/features/admin/DestructionStatus.test.tsx`

Expected: FAIL because destruction UI does not exist.

- [x] **Step 3: Implement deliberate, non-overclaiming workflow**

Require target hashes/sequences, scope, nonfachlicher legal-reason code, known storage locations, two Approver signature imports, fresh native re-authentication, and final irreversible confirmation. Show verified pre-report, every replica/attestation, backup deadline, unreachable status, Stub/Evidence state, and exact managed-scope limitation. After `inProgress`, offer resume only, never cancel. Do not display deleted payload or claim physical/WORM/backup deletion without a valid attestation.

- [x] **Step 4: Run keyboard, restart, pending-backup, and unreachable E2E tests**

Run:

```bash
pnpm --dir apps/desktop exec vitest run src/features/admin/DestructionWizard.test.tsx src/features/admin/DestructionStatus.test.tsx src/features/admin/DestructionSurface.test.tsx src/features/admin/DestructionEvidence.test.tsx src/features/admin/destruction-contract.test.ts src/features/admin/mark-incomplete-offer.test.ts
pnpm --dir apps/desktop exec playwright test tests/e2e/destruction.spec.ts
cargo test --locked -p ea-desktop --lib
cargo test --locked -p ea-desktop --test destruction_commands --test destruction_evidence_commands --test reader_delivery_commands --test writer_commands --test admin_commands
cargo test --locked -p einsatzarchiv-cli --features desktop-fixture --test operator process_native::destruction::desktop:: -- --test-threads=1
```

Expected: PASS; UI returns to the reconstructed same process after restart. The Playwright target is an IPC double where restart means reload; native restart runs in the CLI target (see Nachmessung).

- [x] **Step 5: Commit destruction UI workstream**

```bash
git add apps/desktop apps/desktop/tests/e2e apps/cli/tests/operator_destruction/desktop pnpm-lock.yaml
git commit -m "feat(desktop): guide controlled destruction"
```

### Task 14: Stage 5 Cross-Workstream Acceptance Gate

**Gemessene Korrektur DRK-250:** `xtask stage-gate` kennt inzwischen Stufen
1–4; Stufe 5 fehlt. Die unverändert offenen 19 Ledgerzeilen sind am vollständigen
Lauf zu belegen. Die Prüfung umfasst produktive Komposition, die seit `be2abfe`
gebaute signierte Einmal-Quittung für Stale Registry
(`crates/ea-writer/src/finalize.rs:302`,
`apps/desktop/src-tauri/src/commands/writer.rs:1294`), die administrativen Diagnosepfade
für widersprüchliche Abschlussmarken und verwaiste Sperren sowie beide
v1.1-Escrow-Familien aus den Global Constraints. Native Identity-Provider und
CLI-Komposition existieren: sie werden integriert, nicht neu erfunden. Posture
`Fail` muss eine Produktionssitzung blockieren, `Unknown` bleibt im Go-live
sichtbar ungelöst. (An HEAD `8be0a47` weicht der Baum davon ab, siehe
Nachmessung; Ruling vom 13.09.2026 bestätigt die Zusage wörtlich.) Native
Min-/Max-Release-Matrix, echte Organisationsfreigabe,
quartalsweise Übungen und Produktionsschlüssel-Custody bleiben Stufe 7; fehlende
Produktimplementierung darf nicht als reine Stufe-7-Evidenz verschoben werden.

**Nachmessung 2026-09-13 (DRK-250, HEAD `8be0a47`):** Korrigiert sind Kommandos,
Pfade und die Testskizze; keine Zusage entfällt.
- `run_stage_gate` (`tools/xtask/src/main.rs:3934-3948`) verzweigt nur für die
  Stufen 1–4 und meldet sonst „stage-gate is only defined for stages 1, 2, 3 and 4
  so far" (:3946). Vorbild ist `run_stage_four_gate` (:3730) mit den Konstanten
  `STAGE_FOUR_PRIMARY_ACCEPTANCE_CRITERIA` (:2282) und `STAGE_FOUR_REQUIRED_SCRIPTS`
  (:2318) und dem JSON-Bericht, der ergänzt und nie umbenannt wird (:3889-3905,
  Kommentar :3897-3898).
- Zwei bestehende Pins bewegen sich in diesem Task. Erstens
  `the_stage_switch_still_refuses_an_undefined_stage`
  (`tools/xtask/tests/stage_gate.rs:2010-2029`) ruft heute Stufe 5 und erwartet
  „stages 1, 2, 3 and 4"; sein Kommentar legt fest, dass er mit dem Schalter wandert
  (auf Stufe 6 und „stages 1, 2, 3, 4 and 5"). Zweitens fixiert die WR-Pin-Tabelle
  `("WR-075", "7.5", "5", "planned")` (:554); jeder Statuswechsel von WR-075 zieht dort
  mit. `stage_gate.rs` ist deshalb `Modify` (wie Ruling R44 der Stufe 2).
- `stage-gate:5` fehlt in `package.json` (vorhanden: :25, :28, :30); der Lauf ruft wie
  in Stufe 3 das Skript.
- `xtask test-privacy --scope …` gibt es nicht: Ruling R41
  (`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-2-offline-writer.md:136`)
  schließt `test-privacy` als Subkommando aus, und der `test-*`-Arm weist jedes
  Argument ab (`main.rs:4052-4057`). Die Form folgt Stufe 3
  (`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-3-blind-sync.md:1255`):
  direkter `cargo test -p ea-system-tests --test privacy_canaries_…`.
- `pnpm test:recovery` ist `cargo test --workspace --all-targets --locked`
  (`main.rs:4052-4057`, :1134-1140), also der Workspace-Lauf und kein
  Recovery-spezifischer Lauf.
- Ein Systemziel `e2e_destruction` existiert nicht; vorhanden sind drei
  Admissionszeugen `e2e_destruction_{policy,admission_race,catalog_race}`. Der
  physische Zeuge und die Entscheidung vom 14.09.2026 gegen ein eigenes
  System-E2E stehen in Task 12. Der Playwright-Zeuge heißt `recovery.spec.ts`.
- `xtask_test::stage_gate` existiert nicht, und `workstreams`/`canary_findings` sind
  keine Berichtsfelder. Die Skizze in Step 1 folgt der Prozessform der Stufe 4
  (`run_stage_gate_in_the_workspace`, `stage_gate.rs:947`;
  `stage_four_gate_requires_two_readers_the_browser_matrix_and_the_file_mode`
  :2873-2890); die beiden Felder kommen additiv hinzu.
- Von den 19 Ledgerzeilen auf (Stufe 5, `planned`) haben FR-120, FR-121, FR-123,
  FR-124 und WR-075 ein leeres `primary_acceptance_criterion`
  (`docs/traceability/v0.1-requirements.csv`, Zeilen 131, 132, 134, 135, 158). Der
  `evidenced`-Filter (`main.rs:3881-3888`) überspringt solche Zeilen. Die 14 primären
  AK belegen sie also nicht; das Gate braucht für sie eine eigene Prüfung, etwa
  über `rows_still_planned(&rows, "5", …)` (:3239).
- Die Konstante `STALE_ACK_UNAVAILABLE`
  (`apps/desktop/src-tauri/src/commands/mod.rs:59`) ist seit `be2abfe` Rest und nur
  noch im Test-Mock `apps/desktop/src/features/writer/WriterPage.test.tsx:466`
  referenziert.
- **Rulings vom 13.09.2026 (DRK-250)** — die Zusagen dieses Tasks und der Global
  Constraints bleiben unverändert; entschieden ist nur Reihenfolge und Zuschnitt:
  (1) Posture `Unknown` bleibt im Go-live nie grün, auch mit gültigem signiertem
  Go-live-Dokument. An HEAD `8be0a47` wurde es noch `Confirmed` mit
  `EA-GOLIVE-POSTURE-DOCUMENTED` (`crates/ea-admin/src/go_live.rs:562-575`); die
  Korrektur folgt als eigener Commit. Ein dokumentiertes `Unknown` darf eine Sitzung
  öffnen, `Fail` blockiert, der Stale-Writer verlangt weiter `Pass`.
  (2) Nativer Clock-Release: `ClockRepairRuntime::release`
  (`crates/ea-admin/src/operator_runtime/clock_repair.rs:235-243`) liefert nach
  `recheck()` `Expired`. Der vorbereitete Patch ist für diesen Task (DRK-282)
  freigegeben, unter RED-first-Nativzeugen, Gegenproben (Pass, Fail, Ablauf,
  Doppelverbrauch, normaler Reopen) und unabhängigem Security-Review; die
  Unknown-Erweiterung ist ein eigener Schritt.
  (3) Escrow-v1.1-Profil
  (`docs/superpowers/specs/2026-09-08-einsatzarchiv-reader-key-escrow-profile.md:3`,
  Status „proposed") ist in das Folgeticket DRK-318 verschoben (Security-Review vor
  Code). E1/E2 haben in diesem Plan keinen eigenen Task-Abschnitt; ihre Abnahme und
  die Reihenfolge „E1/E2 precede T14" stehen in
  `docs/superpowers/plans/2026-09-08-drk-250-runtime-closure.md:83-91`. Bis DRK-318
  bleibt WR-075 `planned`, und dieses Gate kann nicht vollständig schließen.
  (4) Controlled-Network-Archiv: `RecoveryTestRuntime::new` weist
  `ControlledNetworkPath` ab (`crates/ea-admin/src/recovery_test_runtime.rs:112`);
  Aufnahme in Stufe 5 oder dokumentierte Grenze wird im Folgeticket DRK-320
  entschieden.
  (5) Der erste Stufe-5-PR umfasst Task 8–13 samt dieser Plankorrektur; dieser Task
  bleibt DRK-282, der native 4→1-Retry aus Task 12 ist DRK-319.

**Files:**
- Create: `tests/ea-system-tests/tests/e2e_organization_lifecycle.rs`
- Create: `tests/ea-system-tests/tests/e2e_recovery_fresh_machine.rs`
- Create: `tests/ea-system-tests/tests/privacy_canaries_admin_recovery_destruction.rs`
- Create: `docs/traceability/stage-5-gate.md`
- Modify: `docs/traceability/v0.1-requirements.csv`
- Modify: `tools/xtask/src/main.rs` (Zweig `run_stage_five_gate`, `STAGE_FIVE_*`-Konstanten, Fehlertext :3946)
- Modify: `package.json` (Skript `stage-gate:5`)
- Modify: `tools/xtask/tests/stage_gate.rs` (neuer Stufe-5-Test; Pins :2010-2029 und :554)

**Interfaces:**
- Consumes: all three Stage 5 workstreams plus Writer/Reader/server.
- Produces: `xtask stage-gate 5` and evidence for primary AK 11, 12, 18, 24, 29, 30, 35, 40, 41, 44, 47, 49, 52, 53.

- [x] **Step 1: Write cumulative Stage 5 gate test**

```rust
// Skizze in der Prozessform der Stufe 4 (tools/xtask/tests/stage_gate.rs:2873-2890):
// `xtask stage-gate 5` als Prozess, Auswertung des JSON-Berichts. Die Schluessel
// `stage_five_workstreams` und `stage_five_canary_findings` sind NEU und additiv.
#[test]
fn stage_five_gate_requires_all_workstreams_and_primary_criteria() {
    let output = run_stage_gate_in_the_workspace("5");
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["stage"], serde_json::json!(5));
    assert_eq!(report["stage_five_workstreams"],
        serde_json::json!(["admin-trust", "recovery-regrant-amendment", "destruction"]));
    assert_eq!(report["stage_five_primary_acceptance_criteria"],
        serde_json::json!([11, 12, 18, 24, 29, 30, 35, 40, 41, 44, 47, 49, 52, 53]));
    assert_eq!(report["stage_five_canary_findings"], serde_json::json!([]));
}
```

- [x] **Step 2: Run the gate and confirm missing evidence fails**

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
cargo test --locked -p ea-system-tests --test e2e_organization_lifecycle --test e2e_recovery_fresh_machine --test e2e_historical_grant --test e2e_destruction_policy --test e2e_destruction_admission_race --test e2e_destruction_catalog_race -- --test-threads=1
cargo test --locked -p einsatzarchiv-cli --features desktop-fixture --test operator process_native::destruction:: -- --test-threads=1
pnpm --dir apps/desktop exec playwright test tests/e2e/admin-trust.spec.ts tests/e2e/recovery.spec.ts tests/e2e/amendment.spec.ts tests/e2e/destruction.spec.ts
cargo test --locked -p ea-system-tests --test privacy_canaries_admin_recovery_destruction
pnpm stage-gate:5
pnpm verify:quick
cargo run --locked -p xtask -- integration down
```

Expected: PASS locally; full native/release/manual evidence remains explicitly open for Stage 7. `pnpm test:recovery` is the full workspace test run; the physical destruction branches run in the CLI `operator` target, not in the three admission system targets.

- [x] **Step 5: Commit the Stage 5 gate**

```bash
git add tests docs/traceability tools/xtask package.json
git commit -m "test(admin): close administration and Recovery stage"
```
