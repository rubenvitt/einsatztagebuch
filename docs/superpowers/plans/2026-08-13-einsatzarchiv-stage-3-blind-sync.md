# Einsatzarchiv Stage 3 Blind Sync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a blind, signed, idempotent sync service that atomically accepts already committed archive bytes, returns immutable Receipts and standard Checkpoints, and never needs fachliche plaintext or decryption authority.

**Architecture:** Put request/response framing and RFC-9421 verification in a shared Rust protocol crate. Keep the transport-neutral commit service separate from Axum, PostgreSQL, S3, server keys, and clock adapters. Object bytes are streamed and content-addressed first; a locked PostgreSQL transaction makes Entry, complete initial grants, head, and the one-time Receipt visible together. Writer sync observes only locally committed archive bytes and persists a verified Receipt before reporting success.

**Tech Stack:** Shared Stage 1/2 Rust crates, Axum, TLS 1.3, RFC 9421 HTTP Message Signatures, RFC 9530 Digest Fields, PostgreSQL, SQL migrations, S3-compatible object storage, Tokio, OCI Linux `amd64`, integration tests against real PostgreSQL and S3-compatible services.

**Task numbering:** This plan carries twelve tasks. Former numbers map to new ones as 1→3, 2→4, 3→5, 4→6, 5→7, 6→8, 7→10, 8→12; tasks 1, 2, 9, and 11 are new. Every cross-reference in this plan cites a task by its title, never by its number.

## Global Constraints

- Die Schlüsselwörter **MUSS**, **DARF NICHT**, **SOLL**, **SOLL NICHT** und **DARF** sind normativ zu verstehen. Ein Release darf von einer MUSS-Anforderung nicht abweichen. Eine Abweichung von SOLL erfordert eine dokumentierte Sicherheits- oder Betriebsbegründung.
- **Merker Web-Reader**, `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §12: Ablage und Abruf der Wrapped-Vault-Blobs, WebAuthn-Credentials, CORS und RFC-9421-Request-Signatur aus dem Browser (Bundle-Auslieferung und -Pinning entfallen als Sync-Server-Fläche: web-reader-design.md §4.1, :70-75, verbietet sie dort; das Bundle kommt von einem getrennten Origin.); dazu §6.4.1, WebAuthn-Credentials am Sync-Server mit der pseudonymen `subjectId` als `userHandle`. Die bestehenden Tasks werden nicht umgeschrieben; die neue Fläche entsteht additiv in den Tasks „Challenges, Device Registrations, and Trust Distribution“ (ein Endpunkt) und „Web-Serverfläche: Vault-Blobs, WebAuthn-Assertion und CORS“ (zwei Endpunkte). Die bereits gebauten Lese- und Verwaltungsflächen bleiben unverändert, die Endpunktmenge wächst um genau drei Einträge. Das Web-Bundle MUSS von einem **vom Sync-Server getrennten Origin** ausgeliefert werden (§4.1); der Sync-Server ist kein Bestandteil des Vertrauenspfades für ausgeführten Code. Die Trust-Objektfamilie `webBundleRelease` (§4.2; die Stufenzuordnung steht in §1, :23-25 — §12, :443-446, nennt für Stufe 3 nur Flächen und nicht die Objektfamilie) ist eine v1.1-Erweiterung. Stufe 3 liefert genau den Umfang aus docs/superpowers/plans/2026-08-16-einsatzarchiv-web-reader-stage-1-prerequisites.md:1016 — Codec, die zwei CDDL-Arme des Release-Objekts und seines Widerrufs-Folgeobjekts, und Signaturprofil — und friert die Vektoren der Familie in dieser Stufe permanent ein. Gegenstand dieser Stufe sind ausschließlich die Wrapped-Vault-Blobs nach §6.4/§6.4.1. Das Escrow-Chiffrat nach §7.3 bleibt Stufe 5 und wird hier nicht berührt; der Ablageort dafür rückt in dieser Stufe nicht vor.
- Microsoft Access is outside scope; **Access Grant** is only a signed CEK envelope.
- Non-goals are fixed: no live incident log, dispatch/alarm/control-center integration, patient record or identifying patient data, concurrent offline Writers, normal-app mutation/deletion of finalized content, AI summarization/OCR, public links, server-side content search, unprofiled network paths, qualified personal electronic signature, TR-ESOR certification claim, screenshot/transcription prevention, or cryptographic recall of already decrypted data.
- Product invariants apply verbatim: exactly one active Writer; never-reused predecessor-bound sequences; immutable `.eip` bytes except whole-object authorized replacement by `.eds`; amendment-only corrections; one fresh CEK/ciphertext; one signed grant per recipient; exactly one active Recovery grant before commit; no Reader/Recovery/HGA/Approver private key on Writer; no retained CEK/decryptable draft key; no server decrypt/grant key; server-independent archive verification; independent schema/format/suite versions with old bytes unchanged; separate Sync/verification/Evidence/Entry/destruction statuses; no legal overclaim from a hash chain; every active Reader initially granted; external-anchor recovery; and only Root-signed OS/device-bound operator snapshots.
- Exactly one active Writer exists. Sequence increases by one and binds the predecessor. The server never “repairs” a fork or conflicting replay.
- Final `.eip` bytes remain immutable. Entry plus exact initial grant plan, one Recovery grant, and every active Reader grant form one atomic acceptance unit.
- The server holds no usable Reader/Recovery/HGA/Approver private key and cannot decrypt content, create grants, sign Writer packages, or add Registry authority. Wrapped Reader vault blobs stored server-side are opaque ciphertext that is worthless without an authenticator assertion; the server knows neither vault key nor PRF output (web-reader-design.md §6.4, §6.4.1).
- The local Writer archive commit always precedes upload. Server or TSA outage never invalidates local finalization.
- Server technical databases/lists are derived indexes, not content or Trust authority. Exact archived bytes and Root-signed Trust objects remain authoritative.
- Schema/format/suite versions and Stage 1 vectors stay immutable; server uses the same Rust parser/crypto/trust crates rather than a second implementation.
- Reichweite des Stufe-1-Freeze, gemessen und verbindlich für diese Stufe: Der einzige stufenübergreifend permanente Freeze ist docs/traceability/stage-1-gate.md Abschnitt 5 (:114-143), und er steht auf den BYTES unter `vectors/`, nicht auf der Grammatik. Die Verbotslisten in docs/superpowers/plans/2026-08-16-einsatzarchiv-web-reader-stage-1-prerequisites.md:43 und docs/superpowers/plans/2026-08-16-einsatzarchiv-task-9-phase-a-report-and-gate-order.md:44 binden wörtlich nur ihren jeweils eigenen Plan; eine additive Erweiterung von `schemas/archive/v1/trust.cddl` ist dieser Stufe nicht verboten. Der wirksame Schutz der reservierten Literale sind NICHT die Prosa-Tests — `stage_one_vector_hygiene_reserves_out_of_band_negative_literals` in `tools/xtask/tests/spec_completeness.rs` lädt ausschließlich den Stufe-1-Plan —, sondern die zwei Textscanner in `tests/ea-system-tests/tests/conformance_golden_vectors.rs` und `crates/ea-testkit/src/lib.rs`, die Bytes und nicht Prosa scannen. Die im Prerequisites-Plan formulierte Marker-Invariante DARF in diesem Plan nicht als repositoriumsweite Regel zitiert werden.
- Request bodies, Object Store keys/tags/metadata, PostgreSQL, audit, and logs contain no fachliche plaintext. Keys are type plus `objectHash` only.
- All `/v1` requests use TLS 1.3; except the rate-limited challenge endpoint and `POST /v1/vault-blobs/retrievals`, they carry RFC-9421 signatures with one-time nonce and request ID. `POST /v1/vault-blobs/retrievals` carries no RFC-9421 signature; its sole authority is a WebAuthn assertion over a discoverable credential of the requesting Reader (web-reader-design.md §6.4.1), the server releases only the opaque ciphertexts bound to that `subjectId`, and the registration grants the server no authority.
- Browserzugriffe werden über eine konfigurierte Origin-Positivliste zugelassen; ein Wildcard-`Access-Control-Allow-Origin` ist ausgeschlossen, `Access-Control-Allow-Credentials` bleibt aus, und der getrennte Bundle-Origin (§4.1) steht als einziger Eintrag der Auslieferungsseite darin. Die RFC-9421-Abdeckung von `@authority` und `@target-uri` (siehe Signaturabdeckung unten) bleibt davon unberührt: der Browser signiert über die Ziel-URI des Sync-Servers, nicht über seinen eigenen Origin. Zielorigin und Betriebsverantwortung des Bundle-Hosts sind in web-reader-design.md:485-486 selbst als offen deklariert; die konfigurierbare Positivliste ist die ableitbare Antwort und braucht keine Entscheidung.
- Writer UI exposes exactly `lokal gesichert`, `Upload ausstehend`, `synchronisiert`, `Fehler`; `synchronisiert` requires a verified Receipt persisted locally and in a configured network archive.
- Desktop UI remains on the shared Ant Design 6 German/static-`zeroRuntime`/local-CSP token system and direct CSR `@phosphor-icons/react` imports; no TypeScript security logic or nonnormative status synonyms are introduced.
- Sync server ships as Linux OCI `amd64`; exact base digest and platform proof close in Stage 7. Der `amd64`-Bau findet AUSSCHLIESSLICH im Container statt (ops/container/Dockerfile), nie als Host-Cross-Compile. rust-toolchain.toml:5 bleibt bei `targets = ["wasm32-unknown-unknown"]`; der Toolchain-Test `rust_toolchain_declares_wasm32_and_no_release_target` in tools/xtask/tests/workspace.rs verbietet x86_64-unknown-linux-gnu, x86_64-pc-windows-msvc, aarch64-apple-darwin und x86_64-apple-darwin in der gepinnten Toolchain ausdrücklich, weil sie den signierten min/max-Release-Nachweis der Stufe 7 tragen. Kein Task dieser Stufe führt einen Cross-Target-Check gegen eines dieser vier Tripel.
- **Auflegung A — Dienste als Vorbedingung.** Ab dieser Stufe setzt `pnpm verify:quick` laufende Integrationsdienste voraus, weil das Teilkommando `cargo test --workspace --all-targets --locked` (`verify_quick_commands()` in tools/xtask/src/main.rs) die Integrationstestziele von `apps/server` und `crates/ea-sync-server` mitfährt. Die Dienste werden mit `cargo run --locked -p xtask -- integration up` gestartet und mit `integration down` beendet; `DATABASE_URL` und der S3-Endpunkt werden dabei gesetzt, weil `#[sqlx::test]` `DATABASE_URL` zur Laufzeit liest. `verify-quick` prüft die Erreichbarkeit von PostgreSQL und Object Store FAIL-CLOSED vor dem betroffenen Kommando und bricht mit einer Anweisung ab, wenn sie fehlt — genau die Bauform von `ensure_wasm32_target_available()`, die den fehlenden wasm32-Target vor dem betroffenen Kommando meldet. Ein Überspringen über eine Umgebungsvariable ist AUSGESCHLOSSEN. Die erzwungenen Kanten sind zwei: `workspace_declares_exact_planned_members_and_shared_dependencies` verlangt für jede Mitglieds-Abhängigkeit einen `workspace = true`-Eintrag in der Wurzeltabelle, und `verify_quick_commands()` fährt `cargo test --workspace --all-targets --locked`.
- Die vier neuen Mitglieder (`crates/ea-sync-protocol`, `crates/ea-sync-server`, `crates/ea-sync-client`, `apps/server`) DÜRFEN KEINE `[target.'cfg(...)'.dependencies]`-Tabelle führen. Der Durchlauf über die Cargo-Manifeste in tools/xtask/tests/workspace.rs iteriert ausschließlich über `dependencies`, `dev-dependencies` und `build-dependencies`; eine target-Tabelle wäre für die Pin-Pflicht und die `workspace = true`-Pflicht unsichtbar. Jede Abhängigkeit steht exakt gepinnt in `[workspace.dependencies]` der Wurzel-`Cargo.toml` und wird mit `workspace = true` geerbt.
- Die Async-Grenze liegt an `apps/server`: die Kern-Crates unter `crates/` bleiben synchron, die Tokio-Laufzeit lebt ausschließlich in `apps/server`, `crates/ea-sync-server` exportiert `#[async_trait]`-Ports und ruft die synchronen Kernbibliotheken direkt, und `crates/ea-sync-client` kapselt jeden synchronen `ea-archive-fs`-Aufruf in `spawn_blocking`.
- v0.1 is complete only after Stage 7 and all acceptance criteria/gates pass.
- Jeder Verweis dieses Plans in `tools/xtask/`, `crates/ea-verify/`, `crates/ea-recovery/` und `crates/ea-trust/` nennt einen FUNKTIONS-, KONSTANTEN- oder TESTNAMEN, nie eine Zeilennummer. Zeilennummern in diesem Plan sind Suchhilfe, kein Vertrag.

Required endpoints are exact:

```text
POST /v1/auth/challenges
POST /v1/device-registrations
POST /v1/webauthn-credentials
PUT  /v1/vault-blobs
POST /v1/vault-blobs/retrievals
GET  /v1/trust/registry?afterVersion={n}
POST /v1/trust/events
POST /v1/chains/{chainId}/entry-commits
GET  /v1/chains/{chainId}/entries?afterSequence={n}&afterEntryHash={hash}&cursor={cursor}
GET  /v1/objects/{objectHash}
POST /v1/entries/{entryHash}/historical-grants
GET  /v1/entries/{entryHash}/grants
POST /v1/reader-acks
GET  /v1/checkpoints?after={cursor}
GET  /v1/archive-exports/current
POST /v1/destructions
GET  /v1/destructions/{destructionId}
```

Signature coverage is exact: `@method`, `@authority`, `@target-uri`, `content-type` and RFC-9530 `content-digest` when a body exists, unique request ID, `created`, `expires`, `nonce`, `keyid`, `alg=ed25519`, and an organization-bound `tag`.

---

### Task 1: Stufe-3-Workspace- und Toolchain-Vorlauf

**Files:**
- Create: `docs/adr/0004-server-runtime-and-dependency-class.md`
- Create: `ops/compose/integration.yaml`
- Create: `mise.toml`
- Modify: `.gitignore`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `deny.toml`
- Modify: `tools/xtask/src/main.rs`
- Modify: `docs/traceability/v0.1-requirements.csv`
- Test: `tools/xtask/tests/adr_gate.rs`
- Test: `tools/xtask/tests/integration_services.rs`

**Interfaces:**
- Consumes: the pinned toolchain, `[workspace.dependencies]` of the root `Cargo.toml`, the existing ADR witness `every_database_dependency_is_pinned_and_named_by_adr_0002` in `tools/xtask/tests/adr_gate.rs`, and the five-entry license allowlist of `deny.toml`.
- Produces: ADR 0004, `cargo run --locked -p xtask -- integration up|down`, `ops/compose/integration.yaml`, exact `=` pins for the server dependency class, named license exceptions with ledger anchors, and a versioned `mise.toml`.

- [ ] **Step 1: Write the ratification and integration-service witnesses**

```rust
#[test]
fn server_runtime_dependency_class_is_ratified_before_use() {
    let adr = read_adr(SERVER_ADR_PATH);
    for section in SERVER_ADR_SECTIONS { assert!(adr.contains(section)); }
    for literal in SERVER_ADR_LITERALS { assert!(adr.contains(literal)); }
    for name in SERVER_RUNTIME_DEPENDENCIES {
        let spec = shared_dependency(name);
        let version = spec.get("version").and_then(Value::as_str).unwrap();
        assert!(version.starts_with('='), "{name} must be pinned exactly");
        assert!(adr.lines().any(|line| line.contains(&format!("`{name}`")) && line.contains(version)));
        assert!(adr.contains(&reviewed_feature_ledger_line(name, spec)));
    }
}

#[test]
fn integration_up_is_idempotent_and_exports_both_endpoints() {
    run_gate(["integration", "up"]).unwrap();
    run_gate(["integration", "up"]).unwrap();
    assert!(postgres_is_reachable(env("DATABASE_URL")));
    assert!(object_store_is_reachable(env("EA_OBJECT_STORE_ENDPOINT")));
    assert_eq!(run_gate(["integration", "sideways"]).unwrap_err(), "unknown gate: integration");
}
```

- [ ] **Step 2: Run the witnesses and confirm the decision and the command are absent**

Run: `cargo test --locked -p xtask --test adr_gate --test integration_services`

Expected: FAIL because `docs/adr/0004-server-runtime-and-dependency-class.md` does not exist and the dispatcher answers `unknown gate: integration`.

- [ ] **Step 3: Ratify the server dependency class, pin it, and build the integration command**

Write `docs/adr/0004-server-runtime-and-dependency-class.md` in the shape the existing witness already enforces: every mandatory section heading, every mandatory literal, each class named with its exact pin **on the same line**, and the reviewed feature selection as one verbatim ledger line `name = ["feature", "feature"]`. Each class carries its own primary-source and RustSec review after the procedure of `docs/adr/0001-toolchain-and-cryptography-dependencies.md:152-154`. The ADR ratifies the async runtime, the HTTP server, the PostgreSQL driver, the S3 client and the TLS stack, and it additionally carries the section `OCI base image`. The reach of `docs/adr/0001-toolchain-and-cryptography-dependencies.md:75-77` (OpenSSL and `ring` as suite-wide abstractions) is settled and is not reopened here: `docs/adr/0002-local-database-encryption.md:52-64` rejects the wide reading verbatim as a rejected alternative, so the TLS stack is named and reviewed, not defended.

The ADR number is **0004**. `docs/adr/` today carries `0001-toolchain-and-cryptography-dependencies.md` and `0002-local-database-encryption.md`; the constant `ADR_PATH` in `tools/xtask/tests/adr_gate.rs` pins 0002 hard, and `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-7-release-hardening.md:371` creates `docs/adr/0003-release-supply-chain.md`.

Enter the ratified classes exactly `=`-pinned in `[workspace.dependencies]` of the root `Cargo.toml` and **name the S3 client crate by name**; `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md:121` says only "S3-kompatibler Object Store". This task deliberately registers **no workspace member** — a `members` line pointing at a directory without a manifest fails `cargo metadata` and with it every test; the tasks that create the four crates register them. No pin is entered that no member of this stage consumes. Because this task rewrites `Cargo.lock` for the first time, `cargo metadata --format-version 1` is the exactly one command it runs without `--locked`; every other command of this task carries `--locked` again, as the lockfile-progress rule inside `workspace_declares_exact_planned_members_and_shared_dependencies` in `tools/xtask/tests/workspace.rs` requires.

Add the license exceptions to the `exceptions` block of `deny.toml` in the pattern already used there (crate, license, justification, path into the graph). The allowlist stays at **five** entries — `Apache-2.0`, `BSD-3-Clause`, `BlueOak-1.0.0`, `MIT`, `Unicode-3.0` — because the comment above the block says verbatim that "eine neue Crate unter derselben Lizenz wird weiterhin abgewiesen, und das ist der Unterschied zwischen einer Ausnahme und einer stillschweigenden Erweiterung". Expected candidates from the TLS/S3 subtree are `rustls-webpki` and `untrusted` (ISC alone); no copyleft is in the plausible set. The same comment fixes the place of decision normatively: it points at the section `Gemessener Gate-Lauf` of `docs/traceability/stage-2-gate.md`, so for this stage the section of the same name in `docs/traceability/stage-3-gate.md`. Every new license exception gets a ledger anchor in `docs/traceability/v0.1-requirements.csv` after the pattern of the row `GATE-25` that carries the sixteen advisory exceptions; an exception without an anchor enforces nothing.

Version `mise.toml`: the file is untracked today because `.gitignore:12` carries the line `mise.toml`, so that line is removed first. Then replace `pnpm = "latest"` with the exact pin `pnpm = "11.20.0"`, so the file does not stand against `docs/adr/0001-toolchain-and-cryptography-dependencies.md:28` and `package.json:4` (`"packageManager": "pnpm@11.20.0"`). The same file carries the container-runtime pin below. ADR 0001 pins Rust, Node, pnpm, the fuzz nightly and cargo-fuzz exactly (:26-30) and has no line for Docker/Podman/colima to this day.

Build the subcommand `integration` with the two arguments `up` and `down` into the dispatcher (`match gate.as_str()` in `fn run` of `tools/xtask/src/main.rs`). Write the argument grammar out rather than opening it silently, gate by gate: `test-core`, `test-golden`, `test-property`, `test-recovery` and `validate-schemas` reject every argument explicitly; `stage-gate` takes exactly one numeric argument; `test-fuzz` already takes symbolic input through the two optional flags `--target <fuzz target>` (checked against the targets of `fuzz/Cargo.toml`) and `--smoke-seconds <n>`, and rejects every other word; `integration` accepts exactly one of the two words `up` and `down`, and everything else is an error. `integration up` starts the two services from `ops/compose/integration.yaml` and prints the connection data so that `DATABASE_URL` and the S3 endpoint are set for the following `cargo test` commands, because `#[sqlx::test]` reads `DATABASE_URL` at runtime. Both subcommands are idempotent. The `verify-quick` arm of the same dispatcher gets the fail-closed reachability check for PostgreSQL and the object store that the service precondition above demands, built in the form of `ensure_wasm32_target_available()`: it runs before the affected command, reports the missing service with an instruction, and offers no environment-variable bypass.

Choose and pin the container runtime (Docker/Podman/colima), the two integration images with **tag AND digest**, and the S3-compatible service **by name** in this same task. MinIO, SeaweedFS, LocalStack and Garage differ in versioning, object lock and conditional put, and the stage requires bucket versioning; an unpinned `integration up` is worthless.

- [ ] **Step 4: Prove the feature selection resolves under `--all-features` before any task enters it**

Run:

```bash
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --doc --all-features --locked
```

Expected: PASS. These are exactly the two `verify:quick` subcommands that carry `--all-features`. If backend features are mutually exclusive (typical for the sqlx drivers and the TLS providers), the feature selection is fixed VERBATIM in ADR 0004 and carried in the crate manifests with `default-features = false` plus explicitly enumerated features — the same form that `every_database_dependency_is_pinned_and_named_by_adr_0002` in `tools/xtask/tests/adr_gate.rs` already enforces.

- [ ] **Step 5: Run the ratification gate and the integration services**

Run: `cargo run --locked -p xtask -- integration up && cargo test --locked -p xtask --test adr_gate --test integration_services && cargo run --locked -p xtask -- integration down`

Expected: PASS; the ADR names every class with its pin on one line and its reviewed features verbatim, `integration up` is idempotent, both endpoints answer, and an unknown argument stays an error.

- [ ] **Step 6: Commit the toolchain and pin surface before any server code**

```bash
git add docs/adr/0004-server-runtime-and-dependency-class.md ops/compose mise.toml .gitignore deny.toml tools/xtask docs/traceability/v0.1-requirements.csv Cargo.toml Cargo.lock
git commit -m "build(sync): ratify and pin the server dependency class"
```

### Task 2: Geteilte Format- und Kryptokerne für die Serverfläche

**Files:**
- Modify: `crates/ea-format/src/eag.rs`
- Modify: `crates/ea-format/src/parser.rs`
- Modify: `crates/ea-format/src/lib.rs`
- Modify: `crates/ea-crypto/src/cose.rs`
- Modify: `crates/ea-crypto/src/lib.rs`
- Modify: `crates/ea-verify/src/report.rs`
- Test: `crates/ea-format/tests/grant_plan_codec.rs`
- Test: `crates/ea-format/tests/object_type.rs`
- Test: `crates/ea-crypto/tests/protocol_cores.rs`

**Interfaces:**
- Consumes: the frozen vectors under `vectors/grants/v1/plan/`, `schemas/protocol/v1/signed-protocol.cddl`, and the three existing unsigned-core shape validators behind `validate_unsigned_protocol_core`.
- Produces: `GrantPlanV1::exact_bytes`, `decode_grant_plan`, `encode_challenge_response_core`/`decode_challenge_response_core`, `encode_device_registration_request_core`/`decode_device_registration_request_core`, `encode_reader_ack_core`/`decode_reader_ack_core`, and one single `ObjectTypeV1` exported from `ea-format`.

- [ ] **Step 1: Write round-trip and rejection tests for the three shared cores**

```rust
#[test]
fn grant_plan_round_trips_and_rejects_a_wrong_order() {
    // Die .bin unter vectors/grants/v1/plan/ tragen rohes Elementmaterial, keine Wire-Bytes.
    let plan = GrantPlanV1::new(fixtures::plan_items("accepted-total-order")).unwrap();
    assert_eq!(plan.hash(), fixtures::frozen_grant_plan_hash());
    let decoded = decode_grant_plan(plan.exact_bytes()).unwrap();
    assert_eq!(decoded.exact_bytes(), plan.exact_bytes());
    assert_eq!(decoded.hash(), plan.hash());
    // Der Negativfall entsteht im Test, nicht als neuer eingefrorener Vektor:
    assert!(decode_grant_plan(&encode_items(&reversed(plan.items()))).is_err());
    for name in ["rejected-missing-recovery", "rejected-duplicate-recovery",
                 "rejected-duplicate-recipient-key", "rejected-duplicate-recipient-certificate"] {
        assert!(decode_grant_plan(&encode_items(&fixtures::plan_items(name))).is_err());
    }
}

#[test]
fn every_protocol_core_encodes_validates_and_decodes() {
    let bytes = encode_challenge_response_core(&fixtures::challenge_core()).unwrap();
    validate_unsigned_protocol_core(ContentType::ChallengeResponseCbor, &bytes).unwrap();
    assert_eq!(decode_challenge_response_core(&bytes).unwrap(), fixtures::challenge_core());
    assert!(decode_challenge_response_core(&fixtures::challenge_core_short_nonce()).is_err());
}

#[test]
fn object_type_v1_is_declared_once_and_re_exported() {
    assert_eq!(ea_format::ObjectTypeV1::Entry.code(), 1);
    assert_eq!(ea_format::ObjectTypeV1::Destroyed.code(), 6);
    assert_eq!(ea_verify::ObjectTypeV1::Trust, ea_format::ObjectTypeV1::Trust);
}
```

- [ ] **Step 2: Run the tests and verify the shared access does not exist**

Run: `cargo test --locked -p ea-format --test grant_plan_codec --test object_type && cargo test --locked -p ea-crypto --test protocol_cores`

Expected: FAIL because `decode_grant_plan`, `GrantPlanV1::exact_bytes`, the six core codecs, and an `ObjectTypeV1` exported from `ea-format` do not exist.

- [ ] **Step 3: Publish the existing bytes instead of choosing new ones**

There is nothing to choose here, only something to publish: the bytes are already frozen through `grant_plan_digest` with the domain `EINSATZARCHIV-GRANT-PLAN-v1` and through the positive vectors under `vectors/grants/v1/plan/`. `crates/ea-format/src/eag.rs` gets `pub fn exact_bytes(&self) -> &[u8]` on `GrantPlanV1` — today that access exists only on `GrantBodyV1`, while `GrantPlanV1::new` produces the exact bytes and drops them immediately. It also gets `pub fn decode_grant_plan(bytes: &[u8]) -> Result<GrantPlanV1, FormatError>` as the counterpart to the today-private `encode_plan_items`; `crates/ea-format/src/lib.rs` takes both names into its existing `pub use` block. The five `.bin` files under `vectors/grants/v1/plan/` carry raw item material (32-byte recipient key thumbprint, 32-byte recipient certificate hash, one purpose byte per item), not wire bytes — the frozen expectation for `accepted-total-order` is the manifest digest `grantPlanHash` `acf4ba75d7df5506cd5909d4f776ecc258b268dbd6af3ca3cf920952fa245ab8`. The negative cases are therefore built inside the test: the items of `accepted-total-order` re-encoded in a non-canonical order, and the four existing `rejected-*` materials encoded and handed to the decoder, which must refuse them with the same rules as `GrantPlanV1::new`. This stage freezes no new plan vector. The decoder MUST run the same ordering and duplicate checks as `GrantPlanV1::new` and REJECT a divergent order or a duplicate instead of re-sorting — otherwise the `initialGrantPlanHash` and with it the replay identity diverges from the Writer. This task extends `ea-format` by access and decoder ONLY: `GrantPlanV1::new`, `GrantPlanItemV1::new` and the existing `Debug` implementations stay unchanged, no new constructor appears, and no visibility on the encoder side changes. No reimplementation of the item encoding in `crates/ea-sync-protocol` is admissible afterwards; the global constraint against a second implementation forbids it.

`crates/ea-crypto/src/cose.rs` gets, beside the three existing shape validators, one encoder and one typed decoder each, all six exported through `crates/ea-crypto/src/lib.rs`: `encode_challenge_response_core`/`decode_challenge_response_core`, the same pair for `device-registration-request-core-v1`, and the same pair for `reader-ack-core-v1`. The field structure follows `schemas/protocol/v1/signed-protocol.cddl:5-13`, `:15-24` and `:26-34` character for character; the file stays UNCHANGED and is not registered again, because it already stands in `validate_schemas`. Every decoder calls the existing validator before it hands out fields, and every encoder produces bytes the existing validator accepts. `crates/ea-sync-server/src/auth.rs` must carry no encoder of its own afterwards.

`ObjectTypeV1` is NOT declared a fourth time. The closed set 1..6 lives today three times: as the prefix constants `EIP_PREFIX_V1`..`EDS_PREFIX_V1` in `crates/ea-format/src/parser.rs`, as the `match object_type { 1 => .. 6 => .. }` inside `decode_exact_object`, and as the already typed enum `ObjectTypeV1` in `crates/ea-verify/src/report.rs`. The type moves from `crates/ea-verify/src/report.rs` into `crates/ea-format/src/parser.rs` next to the six prefix constants — the name stays `ObjectTypeV1`, the variants stay `Entry`, `Grant`, `Receipt`, `Evidence`, `Trust`, `Destroyed`, and `code()` stays 1..6 —, it is exported through `crates/ea-format/src/lib.rs`, `decode_exact_object` binds its match to it, and `crates/ea-verify` re-exports it with `pub use ea_format::ObjectTypeV1;` instead of declaring it again — exactly the established pattern of `crates/ea-ui-contracts/src/lib.rs`. The direction is admissible: `crates/ea-verify/Cargo.toml` carries `ea-format.workspace = true`. This is the riskiest single change of the preludes because it alters the public API of a closed Stage 1 crate.

- [ ] **Step 4: Run the shared-core tests plus the frozen golden and property surfaces**

Run:

```bash
cargo test --locked -p ea-format --test grant_plan_codec --test object_type
cargo test --locked -p ea-crypto --test protocol_cores
cargo run --locked -p xtask -- test-golden
cargo run --locked -p xtask -- test-property
```

Expected: PASS; round trip and hash are byte-identical, a wrong item order and every core negative vector are rejected, and no frozen vector and no golden expectation changes.

- [ ] **Step 5: Commit the shared cores before the server consumes them**

```bash
git add crates/ea-format crates/ea-crypto crates/ea-verify
git commit -m "feat(format): publish the shared grant-plan, protocol-core, and object-type surface"
```

### Task 3: Normative Sync Framing and RFC-9421 Request Verification (formerly Task 1)

**Files:**
- Consume existing unchanged: `schemas/protocol/v1/signed-protocol.cddl` (34 lines, already registered in `validate_schemas`; it is neither edited nor registered again)
- Create: `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-sync-wire-addendum.md`
- Create: `schemas/protocol/v1/openapi.yaml`
- Create: `schemas/protocol/v1/entry-commit.cddl`
- Create: `schemas/protocol/v1/reader-batch.cddl`
- Create: `crates/ea-sync-protocol/Cargo.toml`
- Create: `crates/ea-sync-protocol/src/lib.rs`
- Create: `crates/ea-sync-protocol/src/http_signature.rs`
- Create: `crates/ea-sync-protocol/src/challenge.rs`
- Create: `crates/ea-sync-protocol/src/commit.rs`
- Create: `crates/ea-sync-protocol/src/reader.rs`
- Create: `crates/ea-sync-protocol/src/error.rs`
- Test: `crates/ea-sync-protocol/tests/signatures.rs`
- Test: `crates/ea-sync-protocol/tests/framing.rs`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `tools/xtask/src/main.rs`
- Modify: `tools/xtask/tests/workspace.rs`
- Modify: `tools/xtask/tests/schema_validation.rs`
- Modify: `tools/xtask/tests/spec_completeness.rs`

**Interfaces:**
- Consumes: exact object bytes, `GrantPlanV1`, device certificates, COSE/Ed25519 verifier.
- Produces: byte-stable request/response bodies, `RequestSigner`, `RequestVerifier`, `AuthenticatedDevice` including `ProofOfPossession`, `EntryCommitRequestV1`, `EntryCommitIdentity`, `ReaderBatchV1`, `TechnicalCursorV1`.

- [ ] **Step 1: Write signed-component and framing tests**

```rust
#[test]
fn body_request_requires_every_covered_component() {
    let request = fixtures::signed_commit_missing("content-digest");
    assert_eq!(RequestVerifier::verify(&request, fixtures::nonce_store()).unwrap_err().code(),
               "EA-HTTP-SIGNATURE-COVERAGE");
}

#[test]
fn commit_identity_is_independent_of_transport_order() {
    let request = EntryCommitRequestV1::new(fixtures::entry(), fixtures::plan(),
        vec![fixtures::reader_grant(), fixtures::recovery_grant()]).unwrap();
    assert_eq!(request.identity().sorted_grant_object_hashes,
               vec![fixtures::recovery_hash(), fixtures::reader_hash()]);
}
```

- [ ] **Step 2: Run tests and verify missing protocol definitions fail**

Run: `cargo metadata --format-version 1 && cargo test --locked -p ea-sync-protocol`

`cargo metadata --format-version 1` is the exactly one command of this task without `--locked`, because this task enters a new member and new foreign dependencies. The lockfile-progress rule stands verbatim in `workspace_declares_exact_planned_members_and_shared_dependencies` in `tools/xtask/tests/workspace.rs`: "Ein neues Mitglied oder eine neue Fremdabhaengigkeit schreibt Cargo.lock neu, deshalb laeuft in dem Task, der sie eintraegt, GENAU EIN Kommando ohne --locked … Alle weiteren Kommandos dieses Tasks tragen wieder --locked."

Expected: FAIL because protocol framing and verifier do not exist.

- [ ] **Step 3: Define exact non-JSON binary bodies and implement verification**

Use deterministic CBOR for bodies containing archive bytes. Define:

```cddl
entry-commit-request-v1 = [
  1, entry-bytes: bstr, grant-plan: grant-plan-v1,
  initial-grant-bytes: [+ bstr], []
]

entry-commit-response-v1 = [
  1, outcome: 0..1, ; 0 accepted, 1 idempotent replay
  receipt-bytes: bstr, checkpoint-bytes: bstr / null, []
]

reader-batch-v1 = [
  1, chain-id: bstr .size 16, requested-after-sequence: uint,
  requested-after-entry-hash: bstr .size 32,
  start-head-entry-hash: bstr .size 32,
  objects: [* [object-hash: bstr .size 32, exact-object-bytes: bstr]],
  next-cursor: bstr / null, covered-through-sequence: uint, []
]

; challenge-response-core-v1, challenge-response-v1,
; device-registration-request-core-v1 and device-registration-request-v1
; are imported unchanged from schemas/protocol/v1/signed-protocol.cddl.

trust-event-upload-v1 = [1, exact-etb-bytes: bstr, []]
trust-registry-response-v1 = [
  1, requested-after-version: uint,
  events: [* [registry-version: uint, object-hash: bstr .size 32, exact-etb-bytes: bstr]], []
]

historical-grant-upload-v1 = [1, exact-eag-bytes: bstr, []]
grant-list-response-v1 = [
  1, entry-hash: bstr .size 32,
  grants: [* [object-hash: bstr .size 32, exact-eag-bytes: bstr]], []
]

; reader-ack-core-v1 and reader-ack-v1 are imported unchanged from
; schemas/protocol/v1/signed-protocol.cddl.

checkpoint-list-response-v1 = [
  1, requested-cursor: bstr / null,
  checkpoints: [* [object-hash: bstr .size 32, exact-ecp-bytes: bstr]],
  next-cursor: bstr / null, []
]

archive-export-manifest-v1 = [
  1, organization-id: bstr .size 16,
  sorted-objects: [* [object-type: 1..6, object-hash: bstr .size 32, byte-length: uint]],
  export-cursor: bstr / null, []
]

destruction-request-v1 = [1, exact-destruction-authorization-etb-bytes: bstr, []]
destruction-status-response-v1 = [
  1, destruction-id: bstr .size 16, state: 0..4,
  authorization-object-hash: bstr .size 32,
  transitions: [* [object-hash: bstr .size 32, exact-etb-bytes: bstr]],
  attestations: [* [object-hash: bstr .size 32, exact-etb-bytes: bstr]], []
]

protocol-error-v1 = [
  1, error-code: tstr, request-id: bstr .size 16,
  retryable: bool, required-registry-version: uint / null,
  required-registry-head-hash: (bstr .size 32) / null, []
]
```

The addendum fixes media types `application/einsatzarchiv+cbor;v=1` for structured bodies, `application/einsatzarchiv-object` for raw object GETs, and a streamed sequence of exact objects plus final `archive-export-manifest-v1` for export. It defines every endpoint's request/response schema, required caller capability, status/error codes, empty-body behavior, pagination and no-content response. For `POST /v1/webauthn-credentials`, `PUT /v1/vault-blobs` and `POST /v1/vault-blobs/retrievals` it fixes URL, media type, required caller capability, and status and error codes exactly as for the other fourteen endpoints. All object/hash lists are bytewise sorted and duplicate-free. `GET /v1/objects/{objectHash}` carries no CBOR frame: the response is the raw, exactly archived byte stream with `Content-Type: application/einsatzarchiv-object`, `Content-Length` and an RFC-9530 `content-digest` over exactly those bytes — design.md:1530 says „Objektantworten liefern exakte archivierte Bytes“, and a `bstr` declaration would claim a CBOR header that is not on the wire. A `TechnicalCursorV1` is an opaque, expiring server-authenticated deterministic-CBOR token over `[1, organizationId, endpointCode, chainId-or-null, startHeadHash-or-null, lastTechnicalIndex, expiresAt, nonce]`; clients never parse or trust it, and it contains no fachliche metadata. Its authentication is a COSE-Sign1 over the server Ed25519 with its OWN domain constant `EINSATZARCHIV-TECHNICAL-CURSOR-v1` and a written-out validity window; the addendum fixes domain, signature shape and window. There is deliberately NO new `CertificateCapability` variant: design.md:221 says verbatim „Der Server besitzt einen eigenen Ed25519-Schlüssel für Receipts und Checkpoints“, so one key already carries two purposes there and the purpose binding runs through the domain rather than through the capability. `CertificateCapability` in `crates/ea-crypto/src/cose.rs:1550-1558` is closed on seven variants; an eighth would extend a frozen set and would carry its own justification duty. The 24 frozen domain constants under `vectors/crypto/suite-1/domain-string/` know no cursor today, so the new constant is additive and MUST be named as such. No HMAC: the suite knows none.

Fix v1 limits exactly in the addendum: structured request/response CBOR depth/item/string limits reuse Stage 1; entry commit accepts one `.eip`, at most 10,000 grant-plan/grant items, at most 2 KiB per `.eag`, and total body at most 24 MiB (2 MiB Entry plus 10,000 × 2 KiB grant ceiling plus bounded framing); Reader batches and export streams may contain at most 1,000 object records per page and 64 MiB of bytes; Trust pages at most 1,000 `.etb`; grant/checkpoint pages at most 10,000/1,000 objects; challenge/registration/errors at most 64 KiB. The server must enforce both count and streamed byte limit before accumulation. The addendum writes the derivation of the `.eag` ceiling down so the number cannot drift again: `grant-body-v1` is, by `schemas/archive/v1/archive.cddl:36`, a closed array of `grant-context-v1` plus `bstr .size 32` and `bstr .size 48`, and `grant-context-v1` (`schemas/archive/v1/archive.cddl:24`) consists of fixed-length hashes and identifiers plus a small number of bounded integers and one capability string; the six frozen vectors under `vectors/grants/v1/grant/` measure 641 to 710 bytes and `vectors/format/v1/valid/eag/valid.bin` measures exactly 641 bytes, so 2 KiB is just under three times the measured maximum. The 2 MiB Entry limit stays and bounds an `.eip` whose ciphertext is capped by `ciphertext-length-v1 = 16..1048592` in the same file. HTTP mapping is exact: `400` malformed framing/content digest; `401` missing/invalid/expired signature or challenge; `403` valid identity without capability/organization access; `404` unknown object/chain/Entry/destruction ID; `409` fork, head mismatch, byte conflict, non-idempotent replay, or required newer Registry head; `413` byte/count/parser limit; `422` well-formed but invalid Trust/format/grant/authorization; `429` challenge/rate limit; `503` temporary database/Object Store/TSA dependency; other internal failures `500`. Response bodies always use `protocol-error-v1`, contain no supplied payload fragment, and set `retryable=true` only for `429`, `500`, or `503` technical failures.

Stable Entry replay identity is exactly `[entryHash, entryObjectHash, initialGrantPlanHash, sortedInitialGrantObjectHashes]`. Reject duplicate object/grant hashes before service invocation. `RequestVerifier` checks signature coverage, certificate/key identity, capability, organization tag, `created < expires`, bounded validity window, request digest, single-use nonce, and globally unique request ID before routing.

Exactly one endpoint is routed differently: `POST /v1/device-registrations` accepts, after design.md:1497 and design.md:1530, the requested, not yet released device key as proof of possession. `RequestVerifier` returns `AuthenticatedDevice::ProofOfPossession { requested_key }` for it, checks signature coverage, digest, nonce, request ID and window unchanged, but neither certificate chain nor capability, and carries no organization authority. `crates/ea-sync-protocol/tests/signatures.rs` carries the negative case that the same requested key yields `401` on every other endpoint. This path is RFC-9421 signed with the requested key and is therefore NO signature exception; the only signature exception beside the rate-limited challenge endpoint stays `POST /v1/vault-blobs/retrievals`.

`RequestSigner` is the client-side counterpart and covers exactly the component list of the signature coverage fixed in the Global Constraints; `crates/ea-sync-protocol/tests/signatures.rs` runs signer and verifier against the same fixtures in a round trip, plus the negative cases enumerated in the validation step of this task. `RequestSigner` MUST come without a host operating-system dependency, because the browser signs the regular server access with the Reader's Ed25519 key (web-reader-design.md:213) — a key pair the Reader generates in the browser and whose private half never leaves it (web-reader-design.md §6.6, :255-256).

The addendum opens with the header shape that `validate_addendum_review` in `tools/xtask/src/main.rs` — called from `validate_schemas` — already enforces mechanically, built after `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-wire-format-addendum.md:3-24`. The header is written out verbatim so that nothing is chosen again during implementation:

> Status: **normativ für v0.1**. Dieses Addendum wird vor Task 3 Step 3 akzeptiert und ist damit eine Voraussetzung für jeden produktiven Encoder und jeden Serverpfad. Es schließt ausschließlich offene Serialisierungs- und Transportdetails der Designabschnitte 13.1 bis 13.5. Es darf kein dort bereits festgelegtes Feld, keine Semantik und keine Sicherheitsanforderung überschreiben. Bei einem Widerspruch gilt die Umsetzung als blockiert, bis Design und Addendum im selben Review korrigiert wurden; Produktionscode darf nicht wählen.

Below it stands the list of constituents, which names `schemas/protocol/v1/openapi.yaml`, `schemas/protocol/v1/entry-commit.cddl` and `schemas/protocol/v1/reader-batch.cddl` as „Bestandteil dieses Addendums und normativ“. The Stage 1 wire-format addendum is NOT changed and therefore carries no `Modify:` line. Then follows the section `## Feld-zu-Design-Review` with one row per endpoint and per field, every row closing with the result `bestätigt`, and the closing sentence `**Review-Ergebnis:** keine ungelöste Zeile und kein Widerspruch`.

`validate_schemas` today reads exactly one addendum path and runs `validate_addendum_review` over it; it now runs the function over BOTH addendum paths, so the new file is actually checked instead of merely well shaped. The enforcement pitfall is the mandatory-sentence set: `validate_addendum_review` MUST carry it per addendum file instead of globally, and the split is mandatory rather than stylistic, because „vor Task 3 Step 3 akzeptiert“ does not contain „vor Task 3 akzeptiert“ as a substring and a global set would fail both files at once. Only „normativ für v0.1“ and „darf kein dort bereits festgelegtes Feld“ stay common to both files; the acceptance sentence is pinned per file, so the Stage 1 addendum keeps its Stage 1 acceptance sentence unchanged while the sync wire addendum is pinned on its own. A gap deliberately left open here: `docs/superpowers/specs/2026-08-14-einsatzarchiv-v0-1-payload-wire-addendum.md` is not covered by the check at all; the per-file mapping is built so that it can take that file up later.

`openapi.yaml` is descriptive and not normative; normative are the sync wire addendum and the CDDL documents under `schemas/protocol/v1/`. Stage 3 introduces no YAML/OpenAPI validation tool. The alternative — a pinned tool in the workspace prelude plus an entry in `[workspace.dependencies]` — is deliberately rejected, because it would introduce a dependency class for an artifact that carries no byte promise. The choice stands written out here so that it is not raised again.

`validate_schemas` in `tools/xtask/src/main.rs` is a hard path list without a directory scanner, so both new CDDL documents are registered in it: after the block that reads `schemas/protocol/v1/signed-protocol.cddl` and runs it through `validate_cddl_document`, two identically built blocks for `schemas/protocol/v1/entry-commit.cddl` and `schemas/protocol/v1/reader-batch.cddl` are inserted. It is TWO new CDDL, not three — `openapi.yaml` gets no validator —, so the fixed number goes from 10 to 12 and is carried at BOTH pinned places character for character. In `tools/xtask/src/main.rs` the line `"validated 10 CDDL, 7 JSON schemas, 5 payload vectors, \` becomes `"validated 12 CDDL, 7 JSON schemas, 5 payload vectors, \`, and in `tools/xtask/tests/schema_validation.rs` the expectation of `validate_schemas_checks_payload_cddl_and_all_five_literal_vectors` becomes `"validated 12 CDDL, 7 JSON schemas, 5 payload vectors, 1 report vector, and compatibility matrix\n"`. That test pins the output with `assert_eq!` and runs inside `pnpm verify:quick` through `cargo test --workspace --all-targets --locked`, so an unregistered schema file is not a quietly wrong count but a red gate.

`entry-commit.cddl` writes the rule `grant-plan-v1` out in exactly the format that `encode_plan_items` in `crates/ea-format/src/eag.rs:504-519` produces — an array of four-element items with the 32-byte recipient key thumbprint, the 32-byte recipient certificate hash, the suite text `EINSATZARCHIV-HPKE-1` and the one-byte purpose (`0` Recovery, `1` Reader) — as a normative constituent of the sync wire addendum.

This task enters `crates/ea-sync-protocol` in `[workspace] members` of `Cargo.toml` AND in the constant `WORKSPACE_MEMBERS` (`tools/xtask/tests/workspace.rs`, 24 entries today), both in the same commit; the doc comment of the constant says verbatim: "Every task that adds a member appends its path here and nowhere else … A member added to one of the two files and forgotten in the other still fails loudly." The enforcement in `workspace_declares_exact_planned_members_and_shared_dependencies` is an exact set equality, not a counter. It further enters the pair (`"ea-sync-protocol"`, justification) in the constant `WASM32_EXEMPT_CRATES` (`tools/xtask/src/main.rs`, 10 entries today), because `every_crates_member_is_classified_for_the_wasm32_gate` demands exactly one classification for every member under `crates/`. The justification starts at the admission criterion of that list — the reason the crate cannot OR NEED NOT compile for `wasm32-unknown-unknown` — and reads: "carries the RFC-9421 request verification against a server-side nonce and request-ID store plus the streamed body limits of the sync protocol; Stage 3 ships no browser path that loads this crate, so it need not compile for wasm32-unknown-unknown. The browser access of web-reader-design.md §12 is built in Stage 4 with apps/web/ea-reader; the collision between web-reader-design.md:461 and the frozen sentence in tools/xtask/src/main.rs („wird nicht erweitert“) is noted there as a Stage 4 Vorbehalt and is not resolved here."

Extending the wasm32 positive list instead is not admissible and is not to be raised again: the comment above that list binds it character for character to the closed Stage 1 plan document and states that it is not extended, and there is no precedent for editing a closed plan document — `2907803` (2026-08-16 22:55) predates both `ba96e7e` (2026-08-17 22:32) and `638c657` (2026-08-17 23:05).

Three numeric bindings are settled here; two of them become assertions rather than comments, because a comment carrying line references produces exactly the drift class this repository has seen more than once. `tools/xtask/tests/spec_completeness.rs` gets two additional assertions: `object-type` in `archive-export-manifest-v1` covers exactly the six archive object types `.eip`, `.eag`, `.esr`, `.ecp`, `.etb`, `.eds`, and `state` in `destruction-status-response-v1` covers exactly the five values of `destruction-state-v1`. Both assertions bind their sources exclusively by rule name — `archive-object-v1` and `destruction-state-v1` — and carry no line number at all. The two rules are found in `schemas/archive/v1/archive.cddl:3` and `schemas/archive/v1/trust.cddl:173`. No second gate is introduced for this. The third binding is `requested-role`, which stays unchanged at `0..2` in the imported `device-registration-request-core-v1`, because web-reader-design.md §3 (:47-59) does not widen the role set but only changes its application mapping.

- [ ] **Step 4: Validate OpenAPI/CDDL and all positive/negative signature fixtures**

Run: `cargo test --locked -p ea-sync-protocol && cargo run --locked -p xtask -- validate-schemas`

Expected: PASS; absent/duplicate component, wrong digest/authority/URI/tag, expired request, nonce replay, request-ID replay, and wrong certificate all fail distinctly.

- [ ] **Step 5: Commit protocol definitions before server code**

```bash
git add docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-sync-wire-addendum.md schemas/protocol crates/ea-sync-protocol tools/xtask Cargo.toml Cargo.lock
git commit -m "feat(sync): define signed v1 protocol framing"
```

### Task 4: PostgreSQL Schema, Content-Addressed Object Port, and Server Key Port (formerly Task 2)

**Files:**
- Create: `crates/ea-sync-server/Cargo.toml`
- Create: `crates/ea-sync-server/src/lib.rs`
- Create: `crates/ea-sync-server/src/ports.rs`
- Create: `crates/ea-sync-server/src/models.rs`
- Create: `apps/server/Cargo.toml`
- Create: `apps/server/src/main.rs`
- Create: `apps/server/src/config.rs`
- Create: `apps/server/src/router.rs`
- Create: `apps/server/src/adapters/postgres.rs`
- Create: `apps/server/src/adapters/s3.rs`
- Create: `apps/server/src/adapters/server_keys.rs`
- Create: `apps/server/src/adapters/trust_state.rs`
- Create: `apps/server/migrations/0001_initial.sql`
- Consume existing unchanged: `ops/compose/integration.yaml`
- Test: `apps/server/tests/migrations.rs`
- Test: `apps/server/tests/object_store.rs`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `tools/xtask/src/main.rs`
- Modify: `tools/xtask/tests/workspace.rs`

**Interfaces:**
- Consumes: protocol and shared verification crates.
- Produces: `CommitRepository`, `ObjectStore`, `ServerSigner` including the cursor signing operation, `ServerClock`, a PostgreSQL-backed `TrustStateStore` adapter with an explicit concurrency statement, real PostgreSQL/S3 adapters, and technical tables with required uniqueness.

- [ ] **Step 1: Write migration and object conflict tests against real services**

```rust
#[sqlx::test(migrations = "migrations")]
async fn chain_sequence_entry_hash_object_hash_and_request_id_are_unique(pool: PgPool) {
    insert_entry(&pool, fixtures::row(1, "entry-a", "object-a", "request-a")).await.unwrap();
    for row in [
        fixtures::row(1, "entry-b", "object-b", "request-b"),
        fixtures::row(2, "entry-a", "object-c", "request-c"),
        fixtures::row(3, "entry-c", "object-a", "request-d"),
        fixtures::row(4, "entry-d", "object-d", "request-a"),
    ] { assert!(insert_entry(&pool, row).await.is_err()); }
}

#[tokio::test]
async fn same_object_key_with_different_bytes_is_security_event() {
    store.put_if_absent(ObjectTypeV1::Entry, hash, b"first").await.unwrap();
    assert_eq!(store.put_if_absent(ObjectTypeV1::Entry, hash, b"second").await.unwrap_err().code(),
               "EA-STORE-HASH-CONFLICT");
}
```

- [ ] **Step 2: Start integration services and confirm tests fail before schema/adapters**

Run: `cargo metadata --format-version 1 && cargo run --locked -p xtask -- integration up && cargo test --locked -p einsatzarchiv-server --test migrations --test object_store`

`cargo metadata --format-version 1` is the exactly one command of this task without `--locked`, because this task enters two new members and the whole server dependency tree. The lockfile-progress rule stands verbatim in `workspace_declares_exact_planned_members_and_shared_dependencies` in `tools/xtask/tests/workspace.rs`: "Ein neues Mitglied oder eine neue Fremdabhaengigkeit schreibt Cargo.lock neu, deshalb laeuft in dem Task, der sie eintraegt, GENAU EIN Kommando ohne --locked … Alle weiteren Kommandos dieses Tasks tragen wieder --locked."

Expected: FAIL because migrations and adapters do not exist.

- [ ] **Step 3: Implement technical-only persistence ports and migrations**

```rust
#[async_trait::async_trait]
pub trait ObjectStore: Send + Sync {
    async fn stage_stream(&self, kind: ObjectTypeV1, body: ByteStream, limit: u64)
        -> Result<StagedObject, StoreError>;
    async fn put_if_absent(&self, staged: StagedObject)
        -> Result<StoredObject, StoreError>;
    async fn get_exact(&self, hash: ObjectHash) -> Result<ByteStream, StoreError>;
}

#[async_trait::async_trait]
pub trait CommitRepository: Send + Sync {
    async fn commit_locked_head(&self, command: CommitDbCommand)
        -> Result<CommittedDbState, RepositoryError>;
}
```

Create tables for organizations, pending device requests, Trust/Registry events, role intervals, chain heads, Entries, object index, grants, Receipts, checkpoints, evidence jobs, Reader acknowledgements, replay nonces, request IDs, Security Events, technical admin audit, WebAuthn credentials, and wrapped Reader vault blobs. Store no incident number/time/keyword/location/person/vehicle/patient/note. Object keys are `<type>/<hex objectHash>` only; tags/custom metadata contain content type and size, never domain fields. Enable bucket versioning in integration configuration. `crates/ea-sync-server` declares no `ObjectType` enum of its own; it consumes `ea_format::ObjectTypeV1`.

The two web-surface tables are specified here so that the schema canary of the next step already covers them: the credential table carries the pseudonymous `subjectId`, the credential ID, the public key and the signature counter with a uniqueness constraint per (`organizationId`, `credentialId`); the blob table carries `subjectId` and one opaque ciphertext, keyed exclusively by `subjectId` and blob hash. The blob explicitly does NOT lie in the Object Store under `<type>/<hex objectHash>` — that namespace is reserved for archive object types by the Global Constraint on Object Store keys. Neither table carries any fachliche value (web-reader-design.md §6.4, §6.4.1).

`apps/server/src/config.rs` fixes the TLS termination: minimum version 1.3 fail-closed, a named certificate and key source, no downgrade and no negotiation of older versions; `apps/server/src/router.rs` binds exclusively the listener configured that way. Should the termination deliberately lie outside the process, the same sentence writes that out and names the enforcing component — the plan MUST NOT stay silent here, because TLS 1.3 is a Global Constraint and the first sentence of design.md:1497.

The `TrustStateStore` gets a real home: `apps/server/src/adapters/trust_state.rs` implements the trait behind PostgreSQL with an explicit concurrency statement. The way to the only public selection entry point is a writing one — `prepare_local_time` in `crates/ea-trust/src/time.rs` takes `&mut dyn TrustStateStore` and calls `commit_independent_time`, and `select_registry_head` in `crates/ea-trust/src/registry.rs` then answers with the three arms Selected, Advanced and PendingFuture —, so the adapter states which revision it expects and how a lost race is answered. The reading model is `EphemeralTrustStateStore` in `crates/ea-verify`, which the archive verification path already drives.

Stage 3 delivers exactly one migration `0001_initial.sql`; the unique constraints of design.md §13.4 (`chainId` + `sequence`, `entryHash`, `objectHash`, Registry version, request ID) come into existence in it and are not pulled in later. Migration evolution against an already delivered installation — ordering, backward compatibility, proof against an existing database — is expressly the subject of Stage 7 and MUST NOT come into existence ad hoc in Stage 3.

This task enters `crates/ea-sync-server` AND `apps/server` in `[workspace] members` of `Cargo.toml` and in `WORKSPACE_MEMBERS` (`tools/xtask/tests/workspace.rs`), both in the same commit. In `WASM32_EXEMPT_CRATES` (`tools/xtask/src/main.rs`) goes EXCLUSIVELY `ea-sync-server`; `apps/server` MUST NOT stand there, because `every_crates_member_is_classified_for_the_wasm32_gate` filters the classification duty on the prefix `crates/` and rejects every classified name that is not a workspace member under `crates/` ("the wasm32 classification in tools/xtask/src/main.rs names {classified}, which is not a workspace member under crates/"). The justification for `ea-sync-server` reads: "binds Axum, Tokio, sqlx and the S3 client and therefore reaches past `ea-verify` into the host operating system, the network stack and the process environment; web-reader-design.md §9 makes only the verification pipeline shared browser code, and that pipeline ends at `ea-verify`."

- [ ] **Step 4: Run migrations, streaming, and schema-canary tests**

Run: `cargo test --locked -p einsatzarchiv-server --test migrations --test object_store`

Expected: PASS; the S3 adapter streams and hashes without buffering a full payload and a schema inspection finds no fachliche columns.

- [ ] **Step 5: Commit server persistence ports**

```bash
git add crates/ea-sync-server apps/server tools/xtask Cargo.toml Cargo.lock
git commit -m "feat(sync): add technical server persistence"
```

### Task 5: Challenges, Device Registrations, and Trust Distribution (formerly Task 3)

**Files:**
- Create: `crates/ea-sync-server/src/auth.rs`
- Create: `crates/ea-sync-server/src/trust.rs`
- Create: `apps/server/src/http/challenges.rs`
- Create: `apps/server/src/http/device_registrations.rs`
- Create: `apps/server/src/http/trust.rs`
- Create: `apps/server/src/http/webauthn_credentials.rs`
- Modify: `apps/server/src/router.rs`
- Test: `apps/server/tests/auth_trust_api.rs`
- Test: `apps/server/tests/webauthn_credential_api.rs`

**Interfaces:**
- Consumes: `RequestVerifier`, `AuthenticatedDevice` including `ProofOfPossession`, `ServerClock`, Trust verifier/Registry line, Postgres nonce/request stores.
- Produces: rate-limited single-use challenges, pending self-signed registration requests, `POST /v1/webauthn-credentials` with the registered WebAuthn credentials carrying the pseudonymous `subjectId` as `userHandle`, and exact Root-signed Trust object distribution.

- [ ] **Step 1: Write challenge replay and pending-registration tests**

```rust
#[tokio::test]
async fn challenge_is_single_use_and_registration_remains_pending() {
    let challenge = api.issue_challenge(org).await.unwrap();
    let request = fixtures::registration_signed_with_requested_key(challenge);
    assert_eq!(api.register(request.clone()).await.unwrap().status, "pending");
    assert_eq!(api.register(request).await.unwrap_err().code(), "EA-AUTH-NONCE-REPLAY");
    assert!(!api.device_is_authorized(fixtures::device_id()).await);
}
```

- [ ] **Step 2: Run API tests and verify endpoints are absent**

Run: `cargo test --locked -p einsatzarchiv-server --test auth_trust_api`

Expected: FAIL because challenge, registration, and Trust handlers do not exist.

- [ ] **Step 3: Implement pending-only registration and signed Trust publication**

Challenge responses include random nonce, server time, expiration, and server signature; store only nonce digest and state; the same single-use challenges also bind the WebAuthn assertion of the blob retrieval in the task „Web-Serverfläche: Vault-Blobs, WebAuthn-Assertion und CORS“, so the store is written once and read by both paths. Rate limit by non-content technical identity. Registration accepts device ID, requested role, public keys, format capabilities, and self-signature only; it cannot activate authority. `POST /v1/trust/events` requires currently authorized Root/device capability as specified and validates exact `.etb` bytes before transactionally indexing them. `GET /v1/trust/registry` returns exact objects after the requested version and never synthesizes a Trust decision from database rows.

Registering a WebAuthn credential with the pseudonymous `subjectId` as `userHandle` grants the server NO role, capability or device authority (web-reader-design.md §6.4.1, :230-233); it writes exclusively into the technical credential table and creates no Trust entry.

The subtype set accepted by the Trust endpoint is the one that `TrustSubtypeV1` (`crates/ea-format/src/etb.rs`, eleven arms today) carries at the time of the run; a twelfth and thirteenth arm added later by the task „Trust-Objektfamilie webBundleRelease: Codec, CDDL-Arme und Signaturprofil“ widens it without any rebuild of this task.

- [ ] **Step 4: Run auth, capability, and Trust rollback tests**

Run: `cargo test --locked -p einsatzarchiv-server --test auth_trust_api`

Expected: PASS; pending, unpinned, revoked, wrong-organization, wrong-capability, stale, and replayed callers cannot mutate Trust.

- [ ] **Step 5: Commit auth and Trust endpoints**

```bash
git add crates/ea-sync-server apps/server
git commit -m "feat(sync): add signed device and trust endpoints"
```

### Task 6: Atomic Entry Commit, Idempotent Replay, and Immutable Receipts (formerly Task 4)

**Files:**
- Consume existing unchanged: `vectors/receipts/v1/`
- Create: `crates/ea-sync-server/src/commit.rs`
- Create: `crates/ea-sync-server/src/receipt.rs`
- Create: `crates/ea-sync-server/src/validation.rs`
- Create: `crates/ea-sync-server/src/reconcile.rs`
- Create: `apps/server/src/http/entry_commits.rs`
- Modify: `apps/server/src/router.rs`
- Test: `crates/ea-sync-server/tests/commit_service.rs`
- Test: `crates/ea-sync-server/tests/receipt_golden.rs`
- Test: `apps/server/tests/entry_commit_api.rs`
- Test: `apps/server/tests/commit_failures.rs`

**Interfaces:**
- Consumes: `AuthenticatedDevice`, `EntryCommitRequestV1`, `EntryCommitIdentity`, exact Entry/plan/grants, `ObjectStore`, `CommitRepository`, `ServerClock`, server Receipt signer, and `SelectedRegistryHead` with `active_certificates()` as the single source of the active recipient set.
- Produces: `CommitService::commit -> CommitOutcome::{Accepted,IdempotentReplay}`, exact `esr-v1` Receipt bytes built once and persisted inside the commit transaction, monotonic `acceptedAtServer`, immutable `evidenceDueAt` for Stage 6, and quarantined/reconcilable invisible orphans.

- [ ] **Step 1: Write grant-completeness, fork, replay, Receipt, and partial-failure tests**

```rust
#[tokio::test]
async fn exact_active_recipient_set_is_atomic() {
    for request in [fixtures::missing_reader_grant(), fixtures::extra_reader_grant(),
                    fixtures::wrong_recovery_grant()] {
        assert!(service.commit(writer(), request, now()).await.is_err());
        assert_eq!(repo.visible_entry_count().await, 0);
    }
}

#[tokio::test]
async fn identical_replay_returns_same_receipt_bytes() {
    let first = service.commit(writer(), fixtures::valid_commit(), now_at(1000)).await.unwrap();
    let second = service.commit(writer(), fixtures::valid_commit(), now_at(9000)).await.unwrap();
    assert_eq!(first.receipt_bytes(), second.receipt_bytes());
    assert!(matches!(second, CommitOutcome::IdempotentReplay { .. }));
}

#[test]
fn evidence_due_time_is_signed_once_from_receipt_policy() {
    let standard = build_receipt(fixtures::standard_policy(), UnixMillis(100)).unwrap();
    assert_eq!(standard.core().fields().evidence_due_at, None);
    let evidence = build_receipt(fixtures::evidence_policy(500), UnixMillis(100)).unwrap();
    assert_eq!(evidence.core().fields().evidence_due_at, Some(UnixMillis(600)));
    assert_eq!(encode_receipt(&evidence).unwrap().as_bytes(), fixtures::expected_evidence_receipt_bytes());
}

#[test]
fn accepted_time_never_precedes_prior_receipt() {
    assert_eq!(accepted_at(UnixMillis(90), Some(UnixMillis(100))).unwrap(), UnixMillis(100));
}
```

The two Receipt tests read the Evidence due time one level deeper than a first draft suggests, and they never call `exact_bytes()` on a `ReceiptV1`. `ReceiptCoreV1` hands its fields out through `pub const fn fields()` (`crates/ea-format/src/esr.rs:46`), while `ReceiptV1` carries only `core()`, `server_signature()` and a crate-private `body_bytes()` (`crates/ea-format/src/esr.rs:169-178`). `ReceiptCoreV1::exact_bytes()` (`crates/ea-format/src/esr.rs:61`) yields the CORE bytes, not the object bytes; a golden test against it would stand green and freeze the wrong bytes. The object bytes arise exclusively through `encode_receipt(&ReceiptV1) -> Result<ExactObjectBytes, FormatError>` (`crates/ea-format/src/parser.rs:59`), and `ExactObjectBytes::as_bytes() -> &[u8]` (`crates/ea-format/src/object.rs:100`) is public. The access pattern already exists in the tree: `run_evidence_gate` in `crates/ea-verify/src/evidence.rs` reads the due time as `receipt.value().core().fields().evidence_due_at`.

- [ ] **Step 2: Run commit and Receipt tests and verify failure**

Run: `cargo test --locked -p ea-sync-server --test commit_service --test receipt_golden && cargo test --locked -p einsatzarchiv-server --test entry_commit_api --test commit_failures`

Expected: FAIL because neither an atomic commit service nor a Receipt builder exists.

- [ ] **Step 3: Implement the nine-step server commit transaction**

The order of the following paragraph maps the nine server steps of design.md §13.3 (:1536-1544) one to one. Drawing in the Receipt construction (steps 5 and 7) renumbers, merges or drops NO step; the numbering stays nine positions long. No task of this plan offsets these nine steps against the thirteen steps of the Writer finalization in design.md §9.3 (:448-460), which is a different transaction.

Stream and limit each object to a temporary key while hashing; parse/verify Entry, object hash, Writer, suite, Registry line, plan, each grant signature/context, exactly one Recovery, and every active Reader. Put verified bytes content-addressed with byte-conflict detection. Lock the chain head in PostgreSQL; choose the highest server-known applicable Registry head for `acceptedAtServer` and sequence; reject an older bound head. Accept only current sequence + 1, exact predecessor, and authorized Writer. Build Receipt once, persist exact Receipt bytes, then atomically make Entry, grants, head, and Receipt hash visible. Read the Receipt back by hash and verify exact bytes before response.

Sort duplicate-free grant hashes bytewise. Compute `acceptedAtServer = max(current server UTC, predecessor acceptedAtServer)`. Standard policy sets `evidenceDueAt = null`; Evidence Grade sets exact checked addition `acceptedAtServer + policy.evidenceMaxDelayMs`. Bind policy hash, Registry head, plan hash, Entry/object/predecessor hashes, server thumbprint/certificate, and empty critical extensions. Sign the Receipt digest with capability `serverReceipt` and persist exact bytes in the same commit. The Registry-head selection of step 5 binds the head applicable for exactly this time and sequence; it computes no second acceptance time, and acceptance time, due time and signature are never recomputed for one commit.

Only the tuple `(entryHash, entryObjectHash, initialGrantPlanHash, sorted initialGrant objectHashes)` is idempotent — this is exactly `EntryCommitIdentity` from the task „Normative Sync Framing and RFC-9421 Request Verification“. This task consumes the enumeration of `SelectedRegistryHead::active_certificates` and derives no active recipient set of its own from database rows. Same Entry hash with different bytes/grants, same sequence with different Entry, wrong predecessor, or wrong Writer creates a cleartext-free Security Event. Pre-commit Object Store artifacts remain invisible and are reverified before adoption or quarantine.

The server evaluates `RegistrySelectionOutcome::Selected` and `::Advanced`, but persists no `Advanced` transition as an authority extension of its own — it indexes exclusively verified `.etb` bytes; `PendingFuture` leads to `409` with `required-registry-version`.

`checkpoint-bytes` of `entry-commit-response-v1` stays `null` in this task. The task „Standard Checkpoints and the Checkpoint Chain“ supplies that field value afterwards and changes no Receipt byte in doing so.

- [ ] **Step 4: Run real-service concurrency and failure tests**

Run: `cargo test --locked -p ea-sync-server --test commit_service --test receipt_golden && cargo test --locked -p einsatzarchiv-server --test entry_commit_api --test commit_failures -- --test-threads=1`

Expected: PASS under parallel commits, database aborts, object-store faults, response loss, and retry; a successful replay delivers byte-identical `.esr` bytes; a `TrustError::StateConflict` out of the Registry selection under parallel load is its own scenario and leaves no partially visible commit; no failure exposes a head or accepted Receipt without the full grant set.

- [ ] **Step 5: Commit atomic Entry acceptance**

```bash
git add crates/ea-sync-server apps/server
git commit -m "feat(sync): atomically accept entries, grants, and receipts"
```

### Task 7: Standard Checkpoints and the Checkpoint Chain (formerly Task 5)

**Files:**
- Consume existing unchanged: `vectors/receipts/v1/`
- Consume existing unchanged: `vectors/evidence/v1/`
- Create: `crates/ea-sync-server/src/checkpoint.rs`
- Create: `apps/server/src/http/checkpoints.rs`
- Modify: `apps/server/src/router.rs`
- Test: `crates/ea-sync-server/tests/checkpoint.rs`
- Test: `apps/server/tests/checkpoint_api.rs`

**Interfaces:**
- Consumes: `CommitOutcome` with exact `esr-v1` bytes from the task „Atomic Entry Commit, Idempotent Replay, and Immutable Receipts“, committed head, policy, `ServerClock`, server checkpoint signer, and the frozen receipts/evidence vector families read-only.
- Produces: standard `.ecp` checkpoint, the checkpoint chain with `previous-evidence-hash`, the non-null `checkpoint-bytes` value of `entry-commit-response-v1`, and golden-file evidence read from the frozen receipts/evidence vector families.

- [ ] **Step 1: Write checkpoint-chain and divergent-predecessor tests**

```rust
#[test]
fn checkpoint_chain_binds_each_predecessor_by_previous_evidence_hash() {
    let first = build_checkpoint(fixtures::head_at_sequence(1), None, UnixMillis(1_000)).unwrap();
    let second = build_checkpoint(fixtures::head_at_sequence(2), Some(first.object_hash()),
                                  UnixMillis(2_000)).unwrap();
    assert_eq!(first.core().fields().previous_evidence_hash, None);
    assert_eq!(second.core().fields().previous_evidence_hash, Some(first.object_hash()));
    assert_eq!(second.core().fields().covered_through_sequence,
               fixtures::head_at_sequence(2).sequence());
}

#[tokio::test]
async fn commit_response_carries_checkpoint_bytes_and_divergent_predecessors_are_security_events() {
    let accepted = api.commit(fixtures::valid_commit()).await.unwrap();
    assert_eq!(accepted.checkpoint_bytes(), Some(api.last_checkpoint_bytes().await));
    assert_eq!(api.publish_checkpoint(fixtures::foreign_predecessor()).await.unwrap_err().code(),
               "EA-CHECKPOINT-PREDECESSOR-CONFLICT");
}
```

- [ ] **Step 2: Run tests and verify the checkpoint chain is absent**

Run: `cargo test --locked -p ea-sync-server --test checkpoint && cargo test --locked -p einsatzarchiv-server --test checkpoint_api`

Expected: FAIL because the checkpoint builder, the checkpoint chain, and the checkpoint route do not exist.

- [ ] **Step 3: Implement standard checkpoint bytes and the checkpoint chain exactly once**

After accepted commit, build a standard checkpoint over the frozen `checkpoint-core-v1` positions: `domain: "EINSATZARCHIV-CHECKPOINT-v1"`, organization, chain, covered range, head Entry, Registry head, `issuedAtServer`, and `previous-evidence-hash`. Sign and archive it; Stage 6 adds CTT without changing historical Receipt or standard checkpoint bytes. Only here does `checkpoint-bytes` of `entry-commit-response-v1` become non-null, and the exact `esr-v1` bytes of the task „Atomic Entry Commit, Idempotent Replay, and Immutable Receipts“ stay untouched.

The seven frozen Receipt vectors and the eight Evidence vectors are consumed exclusively READING as golden files; `fixtures::expected_evidence_receipt_bytes()`, called from the Receipt golden test of the task „Atomic Entry Commit, Idempotent Replay, and Immutable Receipts“, reads the frozen bytes out of `vectors/receipts/v1/`. Stage 3 produces no new vector of these two families. Should a vector arise in this stage that evidences a new behavior, it lays a new version BESIDE the old one (`vectors/receipts/v2/`), never in its place (docs/traceability/stage-1-gate.md:116-121), and is declared with its own `Create:` line in the Files block. No `Create:`, `Modify:` or `Test:` line of this task names `vectors/` or `crates/ea-testkit` — exactly that holds the count bindings 7 and 8 and keeps the byte-identity test `grant_receipt_and_evidence_vectors_match_their_manifests` green.

- [ ] **Step 4: Run checkpoint-chain and divergence tests**

Run: `cargo test --locked -p ea-sync-server --test checkpoint && cargo test --locked -p einsatzarchiv-server --test checkpoint_api`

Expected: PASS; every checkpoint binds its predecessor through `previous-evidence-hash`, the covered range follows the committed head, divergent checkpoint predecessors become Security Events, and no historical Receipt or standard checkpoint byte changes.

- [ ] **Step 5: Commit standard checkpoints**

```bash
git add crates/ea-sync-server apps/server
git commit -m "feat(sync): issue standard checkpoints and the checkpoint chain"
```

### Task 8: Reader, Object, Export, Historical-Grant, and Destruction API Surfaces (formerly Task 6)

**Files:**
- Create: `crates/ea-sync-server/src/reader_sync.rs`
- Create: `crates/ea-sync-server/src/historical_grant.rs`
- Create: `crates/ea-sync-server/src/destruction.rs`
- Create: `crates/ea-sync-server/src/export.rs`
- Create: `apps/server/src/http/{entries,objects,grants,reader_acks,exports,destructions}.rs`
- Modify: `apps/server/src/router.rs`
- Test: `apps/server/tests/read_apis.rs`
- Test: `apps/server/tests/historical_grant_api.rs`
- Test: `apps/server/tests/destruction_api.rs`
- Test: `apps/server/tests/export_api.rs`

**Interfaces:**
- Consumes: `RequestVerifier`, `AuthenticatedDevice`, `ReaderBatchV1`, `TechnicalCursorV1` and the response frames `grant-list-response-v1`, `checkpoint-list-response-v1`, `archive-export-manifest-v1` and `destruction-status-response-v1` from the task „Normative Sync Framing and RFC-9421 Request Verification“, `ObjectStore`, `CommitRepository` and `ServerSigner` including the cursor signing operation from the task „PostgreSQL Schema, Content-Addressed Object Port, and Server Key Port“, verified Trust fixtures now; full Stage 5 authorization workflows later.
- Produces: exact-object read APIs, start-head-bound Reader batches, full encrypted export, historical grant expiry enforcement, and append-only destruction orchestration storage.

- [ ] **Step 1: Write authorization and exact-byte response tests**

```rust
#[tokio::test]
async fn historical_grant_is_not_accepted_or_delivered_after_expiry() {
    let grant = fixtures::historical_grant_expiring_at(UnixMillis(100));
    assert_eq!(api.post_grant(grant.clone(), now_at(101)).await.unwrap_err().code(), "EA-GRANT-EXPIRED");
    api.seed_before_expiry(grant).await;
    assert!(api.get_grants(entry(), reader(), now_at(101)).await.unwrap().is_empty());
}

#[tokio::test]
async fn export_contains_exact_objects_without_plaintext_transform() {
    let exported = api.export_current(admin()).await.unwrap();
    assert_eq!(inventory_hashes(exported), inventory_hashes(fixtures::server_archive()));
}
```

- [ ] **Step 2: Run read API tests and verify routes are incomplete**

Run: `cargo test --locked -p einsatzarchiv-server --test read_apis --test historical_grant_api --test destruction_api --test export_api`

Expected: FAIL because endpoints and authorization checks do not exist.

- [ ] **Step 3: Implement content-blind read and workflow surfaces**

Reader batch binds requested `afterSequence/afterEntryHash`, returns exact later `.eip/.eds`, grants, Trust, Receipts, and checkpoints plus a `TechnicalCursorV1`, and never treats a database list as verification. Object GET streams exact stored bytes. Reader acknowledgements are signed technical objects.

Historical grant POST validates HGA capability, original Recovery grant, two-Approver authorization, exact Entry/recipient, current Registry, and `effectiveNow <= expiresAt`; GET rechecks expiry before delivery. It never alters `.eip`, initial plan, or head. Destruction POST accepts only a two-Approver authorization, blocks delivery/re-grant, and persists append-only state/attestations; fixture-backed Stage 3 tests exercise validation, while Stage 5 supplies the full workflow. Export streams all encrypted originals, Stubs, grants, Receipts, Evidence, and complete Trust without plaintext conversion.

- [ ] **Step 4: Run capability, cursor, expiry, and export tests**

Run: `cargo test --locked -p einsatzarchiv-server --test read_apis --test historical_grant_api --test destruction_api --test export_api`

Expected: PASS; unauthorized roles cannot enumerate or mutate objects, and exact bytes survive every response.

- [ ] **Step 5: Commit the remaining API surfaces**

```bash
git add crates/ea-sync-server apps/server
git commit -m "feat(sync): add blind read and administration APIs"
```

### Task 9: Web-Serverfläche: Vault-Blobs, WebAuthn-Assertion und CORS

**Files:**
- Create: `crates/ea-sync-server/src/vault_blob.rs`
- Create: `apps/server/src/http/vault_blobs.rs`
- Modify: `apps/server/src/router.rs`
- Modify: `apps/server/src/config.rs`
- Modify: `docs/traceability/v0.1-requirements.csv`
- Modify: `tools/xtask/tests/stage_gate.rs`
- Test: `apps/server/tests/vault_blob_api.rs`

**Interfaces:**
- Consumes: `RequestSigner` and `RequestVerifier` from the task „Normative Sync Framing and RFC-9421 Request Verification“, the WebAuthn credential table and the wrapped Reader vault blob table of the task „PostgreSQL Schema, Content-Addressed Object Port, and Server Key Port“, the rate-limited single-use challenges and the registered WebAuthn credentials of the task „Challenges, Device Registrations, and Trust Distribution“, `ServerClock`, and `apps/server/src/router.rs`.
- Produces: `PUT /v1/vault-blobs`, `POST /v1/vault-blobs/retrievals`, the CORS layer with its configured `Origin` allowlist, and the ledger row `WR-064`.

- [ ] **Step 1: Write the assertion, enumeration, and origin witnesses**

```rust
#[tokio::test]
async fn no_ciphertext_leaves_the_server_without_a_valid_assertion() {
    let stored = api.put_blob(fixtures::signed_blob_upload(subject())).await.unwrap();
    assert_eq!(api.retrieve_blobs(fixtures::retrieval_without_assertion(subject()))
                   .await.unwrap_err().code(), "EA-WEBAUTHN-ASSERTION-INVALID");
    assert_eq!(api.retrieve_blobs(fixtures::retrieval_with_assertion(subject(),
                   api.spent_challenge().await)).await.unwrap_err().code(),
               "EA-WEBAUTHN-ASSERTION-INVALID");
    let released = api.retrieve_blobs(fixtures::retrieval_with_assertion(subject(),
        api.fresh_challenge().await)).await.unwrap();
    assert_eq!(released.ciphertexts(), [stored.exact_ciphertext()]);
}

#[tokio::test]
async fn the_retrieval_endpoint_offers_no_enumeration_surface() {
    let unknown = api.retrieve_blobs(fixtures::retrieval_with_assertion(never_enrolled_subject(),
        api.fresh_challenge().await)).await.unwrap_err();
    let foreign = api.retrieve_blobs(fixtures::assertion_of(other_subject(),
        api.fresh_challenge().await).claiming(subject())).await.unwrap_err();
    assert_eq!((unknown.code(), unknown.status()), ("EA-WEBAUTHN-ASSERTION-INVALID", 401));
    assert_eq!((foreign.code(), foreign.status()), (unknown.code(), unknown.status()));
    assert_eq!(foreign.body_bytes(), unknown.body_bytes());
}

#[tokio::test]
async fn an_unlisted_origin_receives_no_cors_headers() {
    let refused = api.preflight("https://not-listed.example", "/v1/vault-blobs/retrievals").await;
    assert!(refused.header("access-control-allow-origin").is_none());
    let allowed = api.preflight(config::bundle_origin(), "/v1/vault-blobs/retrievals").await;
    assert_eq!(allowed.header("access-control-allow-origin"), Some(config::bundle_origin()));
    assert!(allowed.header("access-control-allow-credentials").is_none());
}
```

The ledger witness is written in this step as well, not in the implementing one: `WEB_READER_MUST_ROWS` in `tools/xtask/tests/stage_gate.rs` receives the additional tuple `("WR-064", "6.4", "3", "implemented")`, so the missing ledger row is a red gate instead of a silent gap.

- [ ] **Step 2: Run the tests and verify the web surface is absent**

Run: `cargo test --locked -p einsatzarchiv-server --test vault_blob_api && cargo test --locked -p xtask --test stage_gate web_reader_must_requirements_are_recorded_as_v1_1_rows`

Expected: FAIL because neither vault-blob routes, nor the assertion check, nor the CORS layer, nor the ledger row `WR-064` exist.

- [ ] **Step 3: Implement blob storage, assertion-authenticated release, and the origin allowlist**

`PUT /v1/vault-blobs` is RFC-9421 signed and writes exactly one opaque ciphertext for the pseudonymous `subjectId` of the enrolling Reader into the wrapped vault blob table of the task „PostgreSQL Schema, Content-Addressed Object Port, and Server Key Port“: create-if-absent over (`subjectId`, blob hash), no update and no delete path in this stage. The blob deliberately does NOT lie in the Object Store under `<type>/<hex objectHash>`; that namespace belongs to the six archive object types. The server stores bytes it cannot read and knows neither vault key nor PRF output (web-reader-design.md §6.4, :206-207).

`POST /v1/vault-blobs/retrievals` carries no RFC-9421 signature. Its sole authority is a WebAuthn assertion over a discoverable credential of the requesting Reader with the pseudonymous `subjectId` as `userHandle` (web-reader-design.md §6.4.1, :218-224). The server resolves the credential over the uniqueness constraint (`organizationId`, `credentialId`) of the credential table, verifies the assertion signature against the stored public key, requires a strictly increasing signature counter, and requires the `clientDataJSON` challenge to be one that `POST /v1/auth/challenges` issued and that has not been spent — without that binding the assertion would be a capability that can be replayed forever. Only then does the server release the opaque ciphertexts bound to exactly that `subjectId`, and nothing else. The registration itself grants the server no role, capability or device authority (web-reader-design.md §6.4.1, :230-233); the two uses of the same authenticator stay separated, the assertion authenticates the transport and the PRF evaluation unlocks the vault afterwards (:226-228).

Exactly ONE additional signature exception arises here, and the reason is written out so that it is not widened later: `PUT /v1/vault-blobs` and `POST /v1/webauthn-credentials` — the latter built by the task „Challenges, Device Registrations, and Trust Distribution“, so that of the three web endpoints this task carries exactly two — are enrollment through the Reader's own device, the Reader's Ed25519 key is present at that moment, and both are therefore RFC-9421 signed like every other endpoint. Only `POST /v1/vault-blobs/retrievals` runs from a fresh browser whose vault — and with it the signing key — is still locked, which is the situation web-reader-design.md:213-216 describes. The exception list of the Global Constraints therefore stays at exactly two entries: the rate-limited challenge endpoint and this retrieval.

`apps/server/src/router.rs` gets one explicit `AuthenticatedDevice`-free routing line for the retrieval, so that `RequestVerifier` does not reject the path for a missing signature: the route is mounted in a branch that carries neither the verifier layer nor an `AuthenticatedDevice` extractor. This is NOT the differently routed device registration of the task „Normative Sync Framing and RFC-9421 Request Verification“, which is signed with the requested key and yields `AuthenticatedDevice::ProofOfPossession`; here no device identity exists at all, and `crates/ea-sync-server/src/vault_blob.rs` therefore takes the verified assertion rather than an authenticated device as its input.

The endpoint offers no enumeration surface (web-reader-design.md §6.4.1, :228). An unknown `subjectId` and a `subjectId` whose assertion does not verify answer with the identical `401`, the identical error code and an identical `protocol-error-v1` body, and both run the same work before answering; a `404` for an unknown subject would be exactly the enumeration surface the section forbids. This does not touch the `404` line of the HTTP mapping, which names unknown object, chain, Entry and destruction IDs and no `subjectId`.

`apps/server/src/config.rs` carries the `Origin` allowlist: a positive list from the configuration, never a wildcard, `Access-Control-Allow-Credentials` off, and the separate bundle origin as the only delivery-side entry. An unlisted origin does not pass the preflight and receives no `Access-Control-Allow-Origin` header at all. The reason the surface exists: web-reader-design.md §4.1 (:70-75) requires a delivery origin separate from the sync server, so cross-origin access follows necessarily. The RFC-9421 coverage of `@authority` and `@target-uri` stays untouched by this — the browser signs over the target URI of the sync server, not over its own origin; CORS decides whether the browser may issue the request, the signature decides whether the server accepts it. The browser-side signing itself is not built here but is the `RequestSigner` of the task „Normative Sync Framing and RFC-9421 Request Verification“, which this task names in its Consumes. The CORS layer is written as an own middleware layer of `apps/server` on top of the already ratified HTTP-server dependency class: no new crate enters here, because this task carries no `Cargo.toml`/`Cargo.lock` line and every one of its commands runs `--locked`, which a fresh dependency would contradict.

`docs/traceability/v0.1-requirements.csv` gains the row `WR-064` for §6.4/§6.4.1 after the schema `WR-0<Abschnitt>`: version `v1.1`, `stage = 3`, status `implemented` once this task closes, and an evidence column naming `apps/server/tests/vault_blob_api.rs`. Two shapes are fixed here because `web_reader_must_requirements_are_recorded_as_v1_1_rows` in `tools/xtask/tests/stage_gate.rs` compares them exactly: the source column MUST end on `6.4` — the assertion uses `ends_with`, so `6.4.1` or `6.4/6.4.1` would fail — and §6.4.1 is named in the title column instead. The ledger row and the tuple of the first step land in the SAME commit as the passing validation, because a tuple demanding `implemented` while the row still says `planned` would leave the gate red for every following task.

The decision on `WEB_READER_MUST_ROWS` is taken here, once, so that no later task shifts the arity a second time: the constant DOES grow, arity 7 to 8, by exactly the tuple named above. Measured: the loop iterates the CONSTANT and looks up one CSV row per tuple, so a new CSV row without a tuple would be invisible to it and would break nothing — the tuple is deliberate additional hardening and not a duty, and every later task that counts this constant counts from eight.

- [ ] **Step 4: Run the assertion, enumeration, origin, and ledger checks**

Run: `cargo test --locked -p einsatzarchiv-server --test vault_blob_api && cargo test --locked -p xtask --test stage_gate web_reader_must_requirements_are_recorded_as_v1_1_rows`

Expected: PASS; no ciphertext leaves the server without a valid, unspent assertion, unknown and unauthenticated subjects are indistinguishable, an unlisted origin receives no `Access-Control-Allow-Origin`, and the ledger carries `WR-064` in status `implemented`.

- [ ] **Step 5: Commit the web server surface**

```bash
git add crates/ea-sync-server apps/server docs/traceability/v0.1-requirements.csv tools/xtask/tests/stage_gate.rs
git commit -m "feat(sync): release wrapped vault blobs against a webauthn assertion"
```

### Task 10: Writer Sync Queue, Network-Archive Ordering, and Receipt Persistence (formerly Task 7)

**Files:**
- Create: `crates/ea-sync-client/Cargo.toml`
- Create: `crates/ea-sync-client/src/lib.rs`
- Create: `crates/ea-sync-client/src/queue.rs`
- Create: `crates/ea-sync-client/src/client.rs`
- Create: `crates/ea-sync-client/src/retry.rs`
- Create: `crates/ea-sync-client/src/receipt.rs`
- Create: `crates/ea-local-store/migrations/0004_sync_retry.sql`
- Create: `apps/desktop/src-tauri/src/commands/sync.rs`
- Modify: `apps/desktop/src/components/integrity/SyncStatus.tsx`
- Test: `crates/ea-sync-client/tests/resume.rs`
- Test: `crates/ea-sync-client/tests/status.rs`
- Test: `apps/desktop/src/components/integrity/SyncStatus.test.tsx`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `tools/xtask/src/main.rs`
- Modify: `tools/xtask/tests/workspace.rs`
- Modify: `crates/ea-archive-fs/src/publication_queue.rs`
- Modify: `crates/ea-archive-fs/src/profile_migration.rs`
- Test: `crates/ea-archive-fs/tests/publication_queue.rs`
- Test: `crates/ea-archive-fs/tests/support/mod.rs`
- Modify: `crates/ea-archive/src/backend.rs`
- Modify: `crates/ea-archive-fs/src/local_path.rs`
- Modify: `crates/ea-archive-fs/src/health.rs`
- Modify: `crates/ea-writer/src/recover.rs`
- Test: `crates/ea-writer/tests/prepared_recovery.rs`
- Modify: `crates/ea-local-store/src/migrations.rs`
- Modify: `crates/ea-types/src/status.rs`
- Modify: `crates/ea-types/src/lib.rs`
- Modify: `crates/ea-types/tests/contracts.rs`

**Interfaces:**
- Consumes: committed archive inventory, configured network archive publisher, `RequestSigner` from the task „Normative Sync Framing and RFC-9421 Request Verification“ together with its HTTP transport, `TechnicalCursorV1`, full Receipt verifier.
- Produces: `SyncClient::push_pending(limit) -> PushSummary`, reconstructible queue, a persisted bounded retry state that first constructs `DetailCause::ResumeAttemptsExhausted`, and the unchanged four-state `SyncStateView` DTO re-emitted from `ea-ui-contracts`.

- [ ] **Step 1: Write ordering, restart, and status tests**

```rust
#[tokio::test]
async fn controlled_network_publish_precedes_server_upload() {
    let mut h = SyncHarness::controlled_network_disconnected().await;
    h.push_pending().await.unwrap();
    assert_eq!(h.server.commit_calls(), 0);
    assert_eq!(h.status(), SyncStatus::UploadPending);
    assert_eq!(h.detail(), "Netzarchiv wartet");
}

#[tokio::test]
async fn synchronized_requires_locally_verified_receipt() {
    let mut h = SyncHarness::new().await;
    h.server.return_receipt(fixtures::bad_receipt());
    assert_eq!(h.push_pending().await.unwrap_err().code(), "EA-SYNC-RECEIPT-INVALID");
    assert_ne!(h.status(), SyncStatus::Synchronized);
}

#[test]
fn staging_and_grant_leftovers_fall_only_after_a_proven_outcome() {
    let mut h = RecoveryHarness::prepared_finalization_interrupted();
    let staged = |h: &RecoveryHarness| {
        h.archive().relative_paths().unwrap().iter().any(|p| ea_archive::is_staging_path(p))
    };
    assert!(staged(&h));
    h.recover_pending().unwrap();
    assert!(staged(&h), "before the irreversible boundary nothing is ever removed");
    h.reconcile_to_completion().unwrap();
    assert!(!staged(&h));
    assert!(!h.health().contains(&HealthFinding::OrphanGrantOrTemporaryFile));
}
```

- [ ] **Step 2: Run sync-client tests and verify failure**

Run: `cargo metadata --format-version 1 && cargo test --locked -p ea-sync-client && cargo test --locked -p ea-writer --test prepared_recovery && pnpm --dir apps/desktop test --run SyncStatus`

`cargo metadata --format-version 1` is the exactly one command of this task without `--locked`, because this task enters a new member and new foreign dependencies. The lockfile-progress rule stands verbatim in `workspace_declares_exact_planned_members_and_shared_dependencies` in `tools/xtask/tests/workspace.rs`: "Ein neues Mitglied oder eine neue Fremdabhaengigkeit schreibt Cargo.lock neu, deshalb laeuft in dem Task, der sie eintraegt, GENAU EIN Kommando ohne --locked … Alle weiteren Kommandos dieses Tasks tragen wieder --locked."

Expected: FAIL because queue/client/status integration does not exist and the archive port carries no delete primitive, so the staging leftovers are never cleaned.

- [ ] **Step 3: Implement queue derivation and bounded retry**

Rebuild pending Entries from committed `.eip` plus exact initial grants and absence of a valid local `.esr`. For controlled network profiles, publish exact committed grants then `.eip`, verify byte equality, and only then call server. Sign every request using a fresh challenge. Retry network/timeout/5xx with bounded exponential backoff plus jitter and persisted next attempt, and resume from the last confirmed `TechnicalCursorV1`; do not auto-retry format, signature, fork, Registry, or authorization errors as success. Verify and create-if-absent persist Receipt locally and remotely before `Synchronized`. Detail causes are nonnormative and cleartext-free; public status remains exactly four values.

This task enters `crates/ea-sync-client` in `[workspace] members` of `Cargo.toml` and in `WORKSPACE_MEMBERS` (`tools/xtask/tests/workspace.rs`, 24 entries today plus the three members the earlier tasks of this stage add), and the pair (`"ea-sync-client"`, justification) in `WASM32_EXEMPT_CRATES` (`tools/xtask/src/main.rs`), because `every_crates_member_is_classified_for_the_wasm32_gate` demands exactly one classification for every member under `crates/`. The justification reads: "drives a signed HTTP client with Tokio, bounded retry timers and persisted queue state on top of the local archive directory, so it reaches past `ea-verify` into the host operating system and the network stack."

`PublicationQueue` no longer asserts `SyncStatus::Synchronized` itself; `resume()` and `drain()` only deliver the publication outcome, and the mapping onto the four public states moves completely into `crates/ea-sync-client/src/queue.rs`, where the verified Receipt — persisted locally and, where configured, in the network archive — is the condition for `Synchronized`. The doc comment of `PublicationQueue::resume` („synchronisiert ohne veröffentlichte Bytes heißt genau eines: es lag nichts an“) is rewritten onto the new outcome in the same move. There is then exactly one truth about the state; today's second one falls away. Normative coverage: design.md:1579. The decoupling reaches exactly one production caller and its pins, which move with it in the same commit: `finish_pending` in `crates/ea-archive-fs/src/profile_migration.rs` gates the profile change today on `state.sync_status() == SyncStatus::Synchronized` and afterwards gates it on the publication outcome instead — an empty pending slot and no hard error of the target; every other outcome stays `ArchiveBackendError::PendingPublication`, so the gate keeps its exact meaning without asking a state that the queue no longer decides. The outcome pins in `crates/ea-archive-fs/tests/publication_queue.rs` and `crates/ea-archive-fs/tests/support/mod.rs` are rewritten onto the same outcome; the pin that today reads `empty.sync_status() == Synchronized` is precisely the assertion this move retires.

The applicable `SyncStatus` is the one from `crates/ea-archive-fs/src/publication_queue.rs` (`LocallySaved`, `UploadPending`, `Synchronized`, `Failed`) with `label()` as the verbatim surface copy; `crates/ea-sync-client` re-exports it with `pub use`, does not declare it again, and the dead enum in `crates/ea-types/src/status.rs` falls away in the same move. Should the dead enum be kept instead, it MUST be renamed to an unmistakably separate name in this same step — otherwise `ea-sync-client` creates the third truth. Measured, so that the removal is complete in one commit: the enum has no production caller, `crates/ea-types/src/lib.rs` re-exports it in its `pub use status::{…}` block, and `crates/ea-types/tests/contracts.rs` pins its codes in `status_is_machine_stable` and in `every_status_variant_has_an_exhaustive_stable_code`; only the `SyncStatus` lines of those two tests fall, their remaining assertions stay untouched.

Attempt counter and `nextAttemptAt` lie in an own table of the local encrypted store and are reconstructed at start together with the queue derived from committed archive bytes; `PublicationQueue::pending` is a process field and carries no persisted state. The table arrives as the next ascending migration `0004_sync_retry.sql`, appended to `MIGRATIONS` in `crates/ea-local-store/src/migrations.rs` with its own named `pub const … _MIGRATION_VERSION`, because that module owns the registry and a registered migration is never rewritten. The task constructs `DetailCause::ResumeAttemptsExhausted` when the bound is exhausted — today the label exists without an attempt counter, a backoff or a persisted next attempt, and this is where it gains all three.

`SyncStateView` in `crates/ea-ui-contracts` stays UNCHANGED: this task adds no retry or Receipt evidence field to the DTO, so neither `crates/ea-ui-contracts/src/lib.rs`, nor `crates/ea-ui-contracts/src/emit.rs`, nor `apps/desktop/src/bridge/generated-contracts.ts` is touched. Hand-written status literals in `SyncStatus.tsx` stay forbidden; the guard is `apps/desktop/src/bridge/no-hand-written-contracts.test.ts`, and the component keeps unpacking the four names out of the emitted `SYNC_STATUS_VALUES` array.

The archive port gains its first delete primitive in this task, and it is the reason `FR-043` can close in this stage at all: `ArchiveBackend` (`crates/ea-archive/src/backend.rs`) receives `remove_if_present` in the naming symmetry of `create_if_absent`, implemented by `LocalPathBackend` (`crates/ea-archive-fs/src/local_path.rs`); `recover.rs` uses it to clean staging after COMPLETE reconciliation (design.md:460, step 13) and pre-published grants without a committed `.eip` after a PROVEN abort (design.md:468), never before the irreversible boundary, where the comment „sie zu entfernen verlangt eine Loeschprimitive, die der Port bewusst nicht hat" stands today; and `crates/ea-archive-fs/src/health.rs` stops raising `HealthFinding::OrphanGrantOrTemporaryFile` for leftovers that have been cleaned, while every uncleaned one keeps raising it unchanged. This stage is where the Writer first learns of a proven outcome — a verified Receipt, or a completed reconciliation — which is exactly the precondition the cleanup was missing in Stage 2.

`SyncStatus.tsx` stays on the design-system state accepted in Stage 2: Ant Design 6, static `zeroRuntime`, local CSP, direct CSR imports from `@phosphor-icons/react`; no new tokens, no runtime CSS and no TypeScript security logic arise.

- [ ] **Step 4: Run offline/reconnect/restart/replay tests**

Run: `cargo test --locked -p ea-sync-client && cargo test --locked -p ea-archive-fs && cargo test --locked -p ea-writer && pnpm --dir apps/desktop test --run SyncStatus && pnpm --dir apps/desktop typecheck`

Expected: PASS; queue reconstruction ignores mutable queue rows, an interrupted response resumes idempotently to the same Receipt, and staging and grant leftovers fall only after a proven outcome — never before the irreversible boundary, where the existing prepared-recovery assurances stay green unchanged.

- [ ] **Step 5: Commit Writer sync**

```bash
git add crates/ea-sync-client crates/ea-archive crates/ea-archive-fs crates/ea-writer crates/ea-local-store crates/ea-types apps/desktop tools/xtask Cargo.toml Cargo.lock pnpm-lock.yaml
git commit -m "feat(sync): resume Writer uploads from archive bytes"
```

### Task 11: Trust-Objektfamilie webBundleRelease: Codec, CDDL-Arme und Signaturprofil

**Files:**
- Modify: `crates/ea-format/src/etb.rs`
- Modify: `crates/ea-format/src/trust_view.rs`
- Modify: `crates/ea-format/src/lib.rs`
- Modify: `schemas/archive/v1/trust.cddl`
- Modify: `tools/xtask/tests/spec_completeness.rs`
- Modify: `crates/ea-testkit/src/lib.rs`
- Modify: `tests/ea-system-tests/tests/conformance_golden_vectors.rs`
- Create: `vectors/web-bundle/v1/manifest.json`
- Create: `vectors/web-bundle/v1/object/` — the frozen `.etb` bytes of both subtypes
- Test: `crates/ea-format/tests/web_bundle_release.rs`

**Interfaces:**
- Consumes: the COSE/Ed25519 verifier, the Root trust anchor out of `ea-trust`, and the deterministic CBOR of Stage 1.
- Produces: `TrustSubtypeV1::WebBundleRelease` and `TrustSubtypeV1::WebBundleRevocation`, `WebBundleReleaseCoreV1` and `WebBundleRevocationCoreV1`, the twelfth and thirteenth arm of `etb-body-v1`, the signature profile of the family, and the permanently frozen vector family `vectors/web-bundle/v1/`.

- [ ] **Step 1: Write the codec, cardinality, and reference tests**

```rust
#[test]
fn the_release_object_round_trips_through_the_public_path() {
    let payload = TrustPayloadV1::web_bundle_release(fixtures::release_fields()).unwrap();
    let object = TrustObjectV1::new(payload, vec![fixtures::root_signature()]).unwrap();
    let bytes = encode_trust(&object).unwrap();
    let ParsedArchiveObject::Trust(parsed) = decode_exact_object(bytes.as_bytes()).unwrap()
        else { panic!("a release object parses as a trust object") };
    assert_eq!(parsed.value().subtype(), TrustSubtypeV1::WebBundleRelease);
    assert_eq!(TrustSubtypeV1::WebBundleRelease.as_str(), "webBundleRelease");
    assert_eq!(bytes.as_bytes(), fixtures::frozen_release_vector_bytes());
}

#[test]
fn both_wire_literals_decode_into_their_variant_instead_of_a_tag_mismatch() {
    for literal in ["webBundleRelease", "webBundleRevocation"] {
        assert!(decode_exact_object(&fixtures::hand_built_trust_object(literal)).is_ok());
    }
    assert_eq!(decode_exact_object(&fixtures::hand_built_trust_object("webBundleReleases"))
                   .unwrap_err(), FormatError::TagMismatch);
}

#[test]
fn exactly_one_root_signature_is_admissible_for_both_subtypes() {
    for payload in [fixtures::release_payload(), fixtures::revocation_payload()] {
        assert!(TrustObjectV1::new(payload.clone(), vec![fixtures::root_signature()]).is_ok());
        assert_eq!(TrustObjectV1::new(payload.clone(), Vec::new()).unwrap_err(),
                   FormatError::Shape);
        assert_eq!(TrustObjectV1::new(payload, vec![fixtures::root_signature(),
                       fixtures::second_root_signature()]).unwrap_err(), FormatError::Shape);
    }
}

#[test]
fn the_revocation_binds_the_release_it_withdraws() {
    let revocation = fixtures::decode_revocation(fixtures::frozen_revocation_vector_bytes());
    assert_eq!(revocation.release_object_hash, fixtures::frozen_release_object_hash());
    assert_eq!(revocation.effective_from_registry_version, 7);
}
```

The two new CDDL rule names are written into the fixed list of `cddl_registers_every_v1_wire_type` (`tools/xtask/tests/spec_completeness.rs`, eleven subtype rule names today) in this step as well, so that the presence of the rules is a checked assurance and not an accident. The private `from_str` is reached exclusively through `decode_exact_object`; this task does NOT widen its visibility, and the test therefore drives the same path the Trust endpoint of the task „Challenges, Device Registrations, and Trust Distribution“ drives.

- [ ] **Step 2: Run the tests and verify the family is rejected today**

Run: `cargo test --locked -p ea-format --test web_bundle_release`

Expected: FAIL because `webBundleRelease` and `webBundleRevocation` reach the fallback arm of `from_str` (`crates/ea-format/src/etb.rs:45`) and answer `FormatError::TagMismatch`.

- [ ] **Step 3: Implement the two variants, their cores, and their CDDL arms**

The norm to be edited is the alternatives block `etb-body-v1` (`schemas/archive/v1/trust.cddl:8-32`), which writes the eleven subtype literals out INLINE; it receives the twelfth and the thirteenth arm. The rule `trust-subtype-v1` (`:1-4`) is normative but referenced by no CDDL rule and no Rust path; it is carried along character-identically so that it does not become deader still, but it is NOT the enforcing place. `TrustSubtypeV1` stays closed: NO unknown fallback arises in `from_str` and NO reserved, non-issuable variant — both new variants are fully issuable and testable. `as_str` stays the exact inverse without a catch-all arm; the compiler enforces completeness in every caller through the non-exhaustive match expressions.

The two arms carry the signature cardinality `[cose-sign1-v1]` — exactly one Root signature, exactly like `organizationAdminAuthorization` (`schemas/archive/v1/trust.cddl:21-22`). The grammar alone does not enforce this: `validate_signature_count` in `crates/ea-format/src/etb.rs` closes on `count == 1` for `RootCertificate` and `OrganizationAdminAuthorization` and falls back to `_ => count >= 1` for everything else, so both new variants are taken INTO the `count == 1` arm. Without that edit the parser would accept two Root signatures while the grammar allows one, and the cardinality test of the first step is what holds the two together. `validate_payload` in the same file is exhaustive over the subtype, so the compiler already demands the two new payload validators. The second exhaustive place is `decode_payload` in `crates/ea-format/src/trust_view.rs`, which matches the subtype without a catch-all arm and hands out the public `DecodedTrustPayloadV1`: that enum gains the two arms of the family in the same commit, and the file therefore stands in the Files block. Measured, so that no further file is surprised: every other match over `DecodedTrustPayloadV1` in the tree — in `ea-trust` around `admin_authorization`, `registry` and `resolver`, in `ea-verify` around the destruction path, and in the round-trip tests of `ea-format` — closes on a catch-all arm or on a `let … else`, so the two new arms reach them as an unremarkable non-match and change no verification result.

Both payloads take the DIRECT shape like `organizationAdminAuthorization` and are not wrapped in `authorized-trust-payload-v1<…>`: a Root signature needs no administrative authorization. The digest input needs no new domain constant — `trust_digest_input` in `crates/ea-format/src/etb.rs` prefixes the subtype literal in front of the exact payload, so the two literals separate the domains by themselves.

The core arrays follow web-reader-design.md §4.2 (:79-82) and stay minimal; their field order is FROZEN by the vectors of this stage and cannot be reordered afterwards:

```cddl
web-bundle-release-core-v1 = [
  1, organization-id: bstr .size 16,
  bundle-hash: bstr .size 32, bundle-version: tstr,
  effective-from-registry-version: uint,
  issued-at: int, root-key-thumbprint: bstr .size 32, []
]

web-bundle-revocation-core-v1 = [
  1, organization-id: bstr .size 16,
  release-object-hash: bstr .size 32,
  effective-from-registry-version: uint,
  issued-at: int, root-key-thumbprint: bstr .size 32, []
]
```

Every position has a source. The leading `1`, the `organization-id` and the closing empty array are the shape every core of this family carries (`initial-root-certificate-core-v1`, `schemas/archive/v1/trust.cddl:44-49`). `bundle-hash` and `bundle-version` are the two fields §4.2 names verbatim; the hash is 32 bytes like every other hash of the family, the version is a `tstr` after the model of `rule-set-version` in `free-text-policy-v1`. `effective-from-registry-version` carries the effectiveness information of §4.2 and reuses the field name that `initial-root-certificate-core-v1` already uses. `issued-at` and `root-key-thumbprint` follow `organization-admin-authorization-v1` (`:85-95`) and `registry-event-core-v1` (`:110-117`) and bind the issuing Root key. The revocation information §4.2 also demands is carried by the follow-up object and not by a field of the release: `webBundleRevocation` is append-only, references the release exclusively by its object hash, and never rewrites the released object — that is why the release core carries no revocation field and is nonetheless complete against „bindet mindestens“.

Whether the two subtypes are admissible as the target of a `registryEvent` is classified here explicitly, because otherwise the authorization consequence would arise silently: they are NOT. Two places carry the narrower literal union and both stay character-identical. `target-trust-subtype` in `organization-admin-authorization-v1` (`schemas/archive/v1/trust.cddl:91-92`) enumerates six literals, and its Rust twin is the `matches!` guard that `crates/ea-format/src/etb.rs` runs at the encoding and at the decoding site of the admin authorization; `registry-change-v1` (`:101-108`) is a closed seven-arm union and carries no arm for a bundle release. The structural reason is the one above: both objects take the direct, Root-signed payload shape instead of `authorized-trust-payload-v1<…>`, so they never appear as the target of an administrative authorization, and an eighth registry-change arm would alter the meaning of the Registry head and with it a verification order that web-reader-design.md:20-22 declares unchanged for this v1.1 extension. The pinning activation behaviour of §4.2 (:84-87) is a Stage 4 subject and is not built here; this stage defines the family.

Vectors of this family live in an OWN family `vectors/web-bundle/v1/` and never under `vectors/trust/v1/`. Reason, measured: `tests/ea-system-tests/tests/conformance_golden_vectors.rs` carries `TRUST_RESERVED_SUBTYPE_NAMES: [&str; 2] = ["webBundleRelease", "readerKeyEscrow"]` and forbids each of these literals in the ENTIRE trust manifest text through `check_trust_hygiene`; `crates/ea-testkit/src/lib.rs` checks the same against the generator output in `every_trust_admin_authorization_states_what_it_does_not_prove`. Object bytes are recorded as hex in the manifests, so the literal reaches a manifest text through the entry NAME, and independently of that the on-disk trust manifest is pinned byte for byte against the generator output — every new entry would force the frozen Stage 1 manifest (130 entries, own measurement) to be regenerated. Both tests would run red. The hygiene rule of `docs/traceability/stage-1-gate.md:134-143` stays untouched: no negative vector of any family carries the literal `webBundleRelease`; the only subtype negative of the existing stock carries `xxUnknownxx`, the action-code negative `200`. The negatives of the new family carry their subtype literal exclusively inside their hex-recorded object bytes, and their entry names stay kebab-case, so no manifest text of any family carries the literal.

The new family brings the protection pattern of `crypto/suite-1` with it, in `tests/ea-system-tests/tests/conformance_golden_vectors.rs`: an entry-count pin after the model of `EXPECTED_ENTRY_COUNT`, a name-plus-`fileSha256` freeze list after the model of `STAGE_ONE_SUITE_ONE_ENTRIES`, and a named admission list for later stages after the model of `STAGE_TWO_SUITE_ONE_ADDITIONS`, which is empty at the end of this stage. `crates/ea-testkit/src/lib.rs` gets the generator of the family, and the manifest on disk is compared against its output exactly as for the existing families. The freeze is permanent: from the commit of this task on, these bytes are not regenerated, not resorted and not reformatted, and a later behavioural change lays `vectors/web-bundle/v2/` BESIDE them, never in their place (`docs/traceability/stage-1-gate.md:116-121`). The task „Server Administration Separation, Failure Matrix, Privacy, and Stage Gate“ names `web-bundle` as the vector family this stage freezes.

- [ ] **Step 4: Validate codec, grammar, registry, and frozen vectors**

Run:

```bash
cargo test --locked -p ea-format
cargo test --locked -p ea-testkit
cargo test --locked -p ea-system-tests --test conformance_golden_vectors
cargo run --locked -p xtask -- validate-schemas
cargo test --locked -p xtask --test spec_completeness
```

Expected: PASS; both literals round trip, two signatures and zero signatures are rejected for both subtypes, the CDDL documents validate, the two rule names are registered, every frozen vector of every other family is byte-identical, and the manifest of the new family matches its generator output.

- [ ] **Step 5: Commit the trust object family**

```bash
git add crates/ea-format schemas/archive/v1/trust.cddl tools/xtask crates/ea-testkit tests/ea-system-tests vectors/web-bundle
git commit -m "feat(format): define the webBundleRelease trust object"
```

### Task 12: Server Administration Separation, Failure Matrix, Privacy, and Stage Gate (formerly Task 8)

**Files:**
- Create: `apps/server/src/admin_audit.rs`
- Create: `ops/container/Dockerfile`
- Create: `ops/monitoring/metrics.md`
- Create: `tests/ea-system-tests/tests/privacy_canaries_server.rs`
- Create: `tests/ea-system-tests/tests/backup_restore_server_restore.rs`
- Create: `docs/traceability/stage-3-gate.md`
- Create: `docs/traceability/stage-3-fault-points.json`
- Modify: `docs/traceability/v0.1-requirements.csv`
- Modify: `tools/xtask/src/main.rs`
- Modify: `package.json`
- Modify: `tools/xtask/tests/stage_gate.rs`
- Modify: `tests/ea-system-tests/tests/conformance_golden_vectors.rs`

**Interfaces:**
- Consumes: complete server and sync client; ADR 0004 with its section `OCI base image`, `cargo run --locked -p xtask -- integration up|down` and `ops/compose/integration.yaml` from the task „Stufe-3-Workspace- und Toolchain-Vorlauf“; the permanently frozen vector family `vectors/web-bundle/v1/` from the task „Trust-Objektfamilie webBundleRelease: Codec, CDDL-Arme und Signaturprofil“; the ledger row `WR-064` together with its tuple in `WEB_READER_MUST_ROWS` from the task „Web-Serverfläche: Vault-Blobs, WebAuthn-Assertion und CORS“; and the frozen vector family `vectors/trust/v1/` read-only.
- Produces: cleartext-free privileged audit, pinned OCI build input, `xtask stage-gate 3`, primary AK 7, 8, 13, 33, 36, 45, 50 evidence, and closing evidence for the seven Stage-3 FR rows FR-004, FR-048, FR-081, FR-082, FR-087, FR-088, FR-089.

- [ ] **Step 1: Write administrative-separation and gate tests**

```rust
#[test]
fn server_admin_configuration_has_no_content_or_grant_authority() {
    let caps = ServerAdminConfig::schema_capabilities();
    assert_eq!(caps, vec![CertificateCapability::ServerReceipt]);
    assert!(!caps.iter().any(|c| matches!(c, CertificateCapability::InitialGrant
                                            | CertificateCapability::HistoricalGrant
                                            | CertificateCapability::OrganizationAdminApprove
                                            | CertificateCapability::HistoricalGrantApprove
                                            | CertificateCapability::DestructionApprove
                                            | CertificateCapability::DeletionAttest)));
}

#[test]
fn stage_three_gate_requires_real_service_failures_and_primary_ak() {
    let gate = xtask_test::stage_gate(3);
    assert_eq!(gate.primary_acceptance_criteria, [7, 8, 13, 33, 36, 45, 50]);
    assert!(gate.scenarios.contains_all(["db-before-commit", "db-after-object-put", "s3-stage",
                                         "response-loss", "parallel-fork", "nonce-replay",
                                         "tls-downgrade", "cursor-key-rotation", "restore"]));
    assert!(gate.stage_three_rows_still_planned.is_empty());
}
```

The new test `stage_three_gate_requires_real_service_failures_and_primary_ak` stands BESIDE the existing Stage-1 and Stage-2 gate tests and replaces none of them; `tools/xtask/tests/stage_gate.rs` is therefore modified and never rewritten. The nine scenario names are the exact keys of `docs/traceability/stage-3-fault-points.json`, and `"tls-downgrade"` and `"cursor-key-rotation"` are the two that this stage adds beyond the seven service-failure scenarios.

Marker for the same step: `WEB_READER_MUST_ROWS` in `tools/xtask/tests/stage_gate.rs` today pins WR-041, WR-042 and WR-043 written out to `("3","planned")` and checks it with `assert_eq!`. Every change of that expectation column is a ledger movement; it is written out in Step 3 of this task and is EXECUTED there, never decided ad hoc by an implementer. The additive extension by the tuple `("WR-064", "6.4", "3", "implemented")` from the task „Web-Serverfläche: Vault-Blobs, WebAuthn-Assertion und CORS“ is NOT affected by it: that tuple is already in place when this task starts.

- [ ] **Step 2: Run gate tests and confirm missing evidence fails**

Run: `cargo test --locked -p xtask --test stage_gate stage_three`

Expected: FAIL listing absent failure, privacy, audit, and restore evidence, `docs/traceability/stage-3-fault-points.json` as the missing declaration behind `gate.scenarios`, and every Stage-3 ledger row still on `planned` — the last of these clears only in Step 3 and is the reason the ledger assertion stands in the same test.

- [ ] **Step 3: Complete hardening evidence without claiming release readiness**

This task carries the closing role of a stage in the shape the earlier stages already used; the closing task „Stage 2 Fault Matrix and Acceptance Gate“ of `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-2-offline-writer.md` is the direct pattern: administration separation, failure matrix, privacy canaries, restore, gate tooling, gate report, and ledger maintenance in one task.

Audit privileged login, config changes, backup/restore, Object Lock changes, server-key rotation, updates, and Security Event handling with pseudonymous actor/device, action code, technical result, time, and object hashes only. Search every fachliche canary through logs, error bodies, PostgreSQL values, S3 keys/tags/metadata, metrics labels, traces, and container output. Restore PostgreSQL and bucket into a separate integration namespace and verify exact objects/head against a known checkpoint.

Server-key rotation carries one further rule, because the same Root-signed server Ed25519 also signs the technical cursor under its own domain string: an issued `TechnicalCursorV1` outlives the rotation of that key. Exactly one of two behaviours is configured and written out, never a silent third: either OVERLAPPING acceptance of both key generations for the length of the declared validity window, or FAIL-CLOSED invalidation of every cursor of the previous generation with a defined `409`. Whichever is chosen, `docs/traceability/stage-3-fault-points.json` carries it as the scenario `"cursor-key-rotation"`, and the restored client resumes from a fresh cursor without a gap in the batch sequence.

`apps/server/src/config.rs` terminates TLS at minimum version 1.3 fail-closed. The negative proof belongs to this task: a TLS-1.2 handshake against the configured listener is REJECTED and never negotiated down, and that rejection is the scenario `"tls-downgrade"` of the failure matrix.

Pin the OCI base by the digest recorded in ADR 0004 (server runtime and dependency class), section `OCI base image`, and record the exact digest verbatim in the `Gemessener Gate-Lauf` section of `docs/traceability/stage-3-gate.md`. The base image MUST carry the Rust toolchain pinned in `rust-toolchain.toml` (`1.95.0`), so that no second, unpinned compiler produces production bytes. The authoritative release digest and the platform proof close in Stage 7 (Global Constraint above). Run as non-root, read-only root filesystem, dropped capabilities, dedicated writable volumes, and external secret injection for server signer. As a marker of a foreign stage, recorded here and NOT resolved here: `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-7-release-hardening.md:42` wants to create `docs/adr/0002-support-matrix-signature.md`, although `0002` is taken by `docs/adr/0002-local-database-encryption.md` and pinned hard by `ADR_PATH` in `tools/xtask/tests/adr_gate.rs` — an independent defect of that plan.

`ServerAdminConfig::schema_capabilities()` describes the capability set of the ADMINISTRATION CONFIGURATION, not that of the receipt key; the equality on exactly `CertificateCapability::ServerReceipt` says that the server administrator can configure no authority beyond it. The three prohibitions — no decrypting, no Writer signing, no Registry authorizing — are expressed through the ABSENCE of every grant and signature capability plus that closing equality, and not through variants that do not exist: `CertificateCapability` is closed on the seven variants `InitialGrant`, `HistoricalGrant`, `OrganizationAdminApprove`, `HistoricalGrantApprove`, `DestructionApprove`, `ServerReceipt` and `DeletionAttest`. Declaring a parallel `Capability` enum in `crates/ea-sync-server` or `apps/server` is excluded. The capability set stays at seven variants: the purpose separation of the technical cursor runs over an additive domain string and not over an eighth variant, so this assurance stands without reservation.

Open the stage switch in `run_stage_gate` (`tools/xtask/src/main.rs`) by `if stage == 3 { return run_stage_three_gate(root); }` and pull its error message along. Today it reads `"stage-gate is only defined for stages 1 and 2 so far, not {stage}"`; it becomes `"stage-gate is only defined for stages 1, 2 and 3 so far, not {stage}"`. No test holds that string — `grep -rn "only defined for stages" tools/ tests/ docs/ apps/ crates/` hits exactly one code site plus one prose site in the Stage-2 plan (besides this sentence) — so the switch opens without a test repair. This is the only uncritical part of the gate extension and is named as such here so that nobody searches for a missing pin.

`run_stage_three_gate` gets the Stage-3 counterparts of the Stage-2 constants, each after its Stage-2 model, in `tools/xtask/src/main.rs`: `STAGE_THREE_FAULT_POINT_MANIFEST_PATH` (model `STAGE_TWO_FAULT_POINT_MANIFEST_PATH`) pointing at `docs/traceability/stage-3-fault-points.json`, which feeds `gate.scenarios` exactly as `stage_two_fault_points()` feeds `declared_fault_points` and carries the SAME SHAPE as `docs/traceability/stage-2-fault-points.json`: a JSON object with `"stage": 3` at the top level and one key per section, each an array of `{"name", "brackets"}` entries (an object with a `points` array is accepted in its place); `STAGE_THREE_FAULT_POINT_SECTIONS` (model `STAGE_TWO_FAULT_POINT_SECTIONS` with `["discard","finalization","precedence"]`) with the four sections that carry the nine scenarios — `["commit","replay","transport","restore"]`, where `commit` holds `db-before-commit`, `db-after-object-put`, `s3-stage` and `response-loss`, `replay` holds `parallel-fork` and `nonce-replay`, `transport` holds `tls-downgrade` and `cursor-key-rotation`, and `restore` holds the single scenario `restore` — one section with exactly one entry, which is deliberate and not an oversight: the restore proof has no sibling in this stage; `STAGE_THREE_PRIMARY_ACCEPTANCE_CRITERIA = [7, 8, 13, 33, 36, 45, 50]`; `STAGE_THREE_GATE_REPORT_PATH = "docs/traceability/stage-3-gate.md"`; `STAGE_THREE_GATE_REPORT_SECTIONS` (model: five mandatory sections); `STAGE_THREE_GATE_REPORT_LITERALS` (model: sixteen mandatory literals); `STAGE_THREE_HOST_SCOPE_CLAUSE`; `STAGE_THREE_REQUIRED_SCRIPTS` (model: five scripts); and `STAGE_THREE_STEP_SIX_COMMANDS` in `tools/xtask/tests/stage_gate.rs` (model `STAGE_TWO_STEP_SIX_COMMANDS` with ten commands). The shared paths `REQUIREMENT_LEDGER_PATH`, `DESIGN_DOCUMENT_PATH` and `PACKAGE_MANIFEST_PATH` are REUSED, never duplicated.

`STAGE_THREE_VECTOR_FAMILIES` (model `STAGE_TWO_VECTOR_FAMILIES`, there `["local-audit","reports"]`) carries the vector families frozen in this stage. It carries EXACTLY ONE entry, `web-bundle`, the family that the task „Trust-Objektfamilie webBundleRelease: Codec, CDDL-Arme und Signaturprofil“ freezes permanently under `vectors/web-bundle/v1/`. It is deliberately its own family and NOT `trust`: `vectors/trust/v1/` is a frozen Stage-1 family whose bytes this stage only reads. Receipt and evidence vectors are likewise not listed — Stage 3 freezes neither, it consumes them read-only, and an entry would claim a Stage-3 freeze that does not exist.

`run_stage_three_gate` takes over the still-planned check from `run_stage_two_gate` unchanged in shape: the filter reads `row.values[7] == "3" && row.values[8] == "planned"` and the error line reads `"stage 3 requirement ledger rows still on planned: {}"`. The filter is built unconditionally, and it is not relaxed for any row; the ledger movement below is what turns it green.

Extend `package.json` (today ELEVEN scripts, `package.json:9-21`) by exactly two keys: `"test:server": "cargo test --locked -p einsatzarchiv-server --test migrations --test object_store --test auth_trust_api --test webauthn_credential_api --test entry_commit_api --test commit_failures --test checkpoint_api --test read_apis --test historical_grant_api --test destruction_api --test export_api --test vault_blob_api"` and `"stage-gate:3": "cargo run --locked -p xtask -- stage-gate 3"`. The twelve `--test` targets are exactly the `apps/server` integration test targets that the tasks of this stage declare, in the order in which they declare them. Both keys belong in `STAGE_THREE_REQUIRED_SCRIPTS`, so that the gate enforces their existence the way it enforces the five Stage-2 scripts.

The report `docs/traceability/stage-3-gate.md` is bound in content, not only in name. It carries a section `Gemessener Gate-Lauf` with one row per command of the run in Step 4 — command, exit code, evidence text, measured runtime — machine-pinned through `STAGE_THREE_STEP_SIX_COMMANDS` after the model of `STAGE_TWO_STEP_SIX_COMMANDS`. Within it stand (a) the license ruling for every new named exception in `deny.toml` — this section is the decision place that `deny.toml` prescribes normatively; (b) the scope clause for Auflegung A after the model of `STAGE_TWO_HOST_SCOPE_CLAUSE`, writing out which services ran under which versions and image digests; (c) the verbatim OCI base digest; (d) the evidence row for `pnpm verify:quick` with measured runtime plus the statement whether it was measured on a warm or a cold `target/` — reference value: the Stage-2 run measured 125 s and left warm or cold UNSTATED, which is exactly why this stage states it; Stage 3 comes above that value and additionally requires two running containers. In that same evidence row the package count of the wasm32 positive list is BOUND TO ITS SOURCE (`verify_quick_commands()` in `tools/xtask/src/main.rs`) instead of written out as a number. Under the points that stay open the report carries (e) the migration reservation of the task „PostgreSQL Schema, Content-Addressed Object Port, and Server Key Port“ — migration evolution against an already delivered installation is Stage 7 — and (f) a named marker for Stages 4 and 6, whose gate runs today drive `pnpm verify:quick` bare (`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-4-reader.md:534`, `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-6-evidence-grade.md:408`) although `apps/server` is a workspace member from this stage on. That consequence is caused by Auflegung A and is named here, not filed away as a foreign-stage legacy defect.

Three further sections of the report hold three verified negatives, so that their silence cannot be read as "not checked". They stay SEPARATE.

`## Endpunkt- und Signaturabdeckung` with three measured statements: (a) before this stage the endpoint list of this plan was byte-identical with `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md` §13.2 (:1514-1527) — a `diff` produced no output; (b) the signature coverage of this plan covers design.md:1501-1507 position for position, with no missing and no additional position; (c) this stage adds three endpoints, so both sides carry SEVENTEEN lines once §13.2 has been pulled along, and the equality is measured again. Cost note, measured: no test, no schema and no code pins any of the seventeen paths — §13.2 carries no closing clause — so the three new endpoints cost exactly the two document pages and nothing else.

`## Serverhälften fremder Stufen` with three rows. AK-35 (design.md:2146, ledger `stage=5`) and AK-49 (design.md:2160, ledger `stage=5`) come into existence in the task „Atomic Entry Commit, Idempotent Replay, and Immutable Receipts“ („choose the highest server-known applicable Registry head … reject an older bound head“); AK-43 (design.md:2154, ledger `stage=4`) comes into existence as to its server half in the task „Reader, Object, Export, Historical-Grant, and Destruction API Surfaces“. This plan claims none of these rows and MUST NOT: their stage columns stay unchanged. The purpose is solely that Stages 4 and 5 find the server half already built. The proving test path is recorded in the same three rows as soon as it exists.

`## Nicht berührte Nachbarzeilen`: FR-100 („Desktop für Writer und Administration, Browser-Reader, signierte Rollentrennung“) and FR-103 („Reader-Index als Ganzes mit ChaCha20-Poly1305 verschlüsselt in OPFS statt SQLCipher“) carry `stage=4`, `status=planned`, are checked, and are not touched by Stage 3, because role split and index storage are Reader surface. Delimitation in the same section: the three WR rows from the same Stage-1 decision — WR-041, WR-042, WR-043 — are Stage-3 rows and are moved by the ledger movement of this task, not by silence.

The family `trust/v1` gets an entry-count pin in this stage, because Stage 3 commits itself to the immutability of exactly these bytes and builds the first distribution surface for them over `GET /v1/trust/registry` and `POST /v1/trust/events`. Beside the existing constants `GRANTS_EXPECTED_ENTRY_COUNT`, `RECEIPTS_EXPECTED_ENTRY_COUNT` and `EVIDENCE_EXPECTED_ENTRY_COUNT` in `tests/ea-system-tests/tests/conformance_golden_vectors.rs`, `const TRUST_EXPECTED_ENTRY_COUNT: usize = 130;` is created with the doc comment „Die Zahl der Trust-Eintraege. Ohne diese Schranke liefe ein truncatiertes oder still neu erzeugtes Manifest durch."; in `trust_v1_vectors_cover_every_negative_named_in_design_22_1` the line `assert_eq!(manifest.entries.len(), TRUST_EXPECTED_ENTRY_COUNT);` is inserted immediately after `assert_eq!(manifest.version, "v1");`. The gate report carries the sentence: „Die Familie `trust/v1` trägt ab dieser Stufe einen Eintragszahl-Pin (130). Damit gilt die Zusage aus docs/traceability/stage-1-gate.md:116-121 für alle fünf eingefrorenen Familien ausführbar und nicht nur als Prosa."

Ledger maintenance. Update exactly these existing Stage 3 ledger rows to `implemented`/`integrated`: AK-07, AK-08, AK-13, AK-33, AK-36, AK-45, AK-50, FR-004, FR-048, FR-081, FR-082, FR-087, FR-088, FR-089. The ledger carries today EIGHTEEN rows with `stage = 3`, all with `status = planned`; seventeen carry this plan as their evidence, FR-043 (v1.1) carries its open finding instead, which names this plan only as the closing stage; `run_stage_three_gate` takes over the filter of `run_stage_two_gate`, which rejects rows of its own stage on `planned`. FR-004 („keine Reader-/Recovery-Keys am Server") is updated in the same move in its EVIDENCE column as well, so that it matches the narrower binding wording of the Global Constraint above: wrapped Reader vault blobs stored server-side are opaque ciphertext, worthless without an authenticator assertion, and the server knows neither vault key nor PRF output. Two further movements are expressly permitted and are to be justified one by one: creating partial-evidence rows for acceptance criteria whose server half comes into existence here, and re-staging a row together with an adjusted evidence column when its building artefact demonstrably lies in a later stage. The row WR-064 is created by the task that builds its surface and is only counted along here. Stage 7 retains production backup, signed image, and full platform release verification.

Two partial-evidence rows are created in this task, each `stage=3`, `status=implemented`, after the pattern that the repository already carries for AK-19, AK-24, AK-29 and AK-53 on Stage 2: „Keine Klartextlogs - Stufe-3-Teilbeleg (Server)" for AK-19 with `tests/ea-system-tests/tests/privacy_canaries_server.rs` as evidence, and „Backup-Restore - Stufe-3-Teilbeleg (Server-Restore)" for AK-21 with `tests/ea-system-tests/tests/backup_restore_server_restore.rs`. Both full rows keep their `stage=7`.

The seven Stage-3 FR rows close against a named task and a named test path, after the pattern that WR-052 already uses with `crates/ea-archive-fs/tests/bundle_export.rs::…`. Without this mapping the gate has no way to check whether a row may be closed:

| Ledger row | Proving task | Proving test path |
|---|---|---|
| FR-004 | Web-Serverfläche: Vault-Blobs, WebAuthn-Assertion und CORS | `apps/server/tests/vault_blob_api.rs` and `tests/ea-system-tests/tests/privacy_canaries_server.rs` |
| FR-048 | Atomic Entry Commit, Idempotent Replay, and Immutable Receipts | `apps/server/tests/commit_failures.rs` |
| FR-081 | Atomic Entry Commit, Idempotent Replay, and Immutable Receipts | `apps/server/tests/entry_commit_api.rs` |
| FR-082 | Atomic Entry Commit, Idempotent Replay, and Immutable Receipts | `apps/server/tests/entry_commit_api.rs` |
| FR-087 | Atomic Entry Commit, Idempotent Replay, and Immutable Receipts | `crates/ea-sync-server/tests/commit_service.rs` and `crates/ea-sync-server/tests/receipt_golden.rs` |
| FR-088 | Writer Sync Queue, Network-Archive Ordering, and Receipt Persistence | `crates/ea-sync-client/tests/status.rs` |
| FR-089 | Writer Sync Queue, Network-Archive Ordering, and Receipt Persistence | `crates/ea-sync-client/tests/status.rs` and `tests/ea-system-tests/tests/privacy_canaries_server.rs` |

Four Stage-3 rows are left over by the fourteen closings, and the still-planned filter names every one of them. Three of them are the Web-Reader rows WR-041, WR-042 and WR-043, and they are the second permitted movement, executed here. All three are browser-side — separate delivery origin (web-reader-design.md:72), Service-Worker activation against a pinned release (:84), enforced fingerprint comparison (:117) — and their building artefact `apps/web` is introduced by web-reader-design.md §12 (:459-461), whose Stage-4 entry (:446-449) is the one that rewrites the Reader tasks. The family definition, on the other hand, is delivered by THIS stage. The ledger therefore splits:

- WR-041 moves to `stage=4` with `status=planned` and an evidence column referring to `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-4-reader.md`.
- WR-043 moves to `stage=4` in the same shape.
- WR-042 also stays on `stage=4` for the ACTIVATION behaviour of the Service Worker, likewise referring to the Stage-4 plan.
- ONE new row carries the family definition on `stage=3` and reaches `status=implemented` in this stage through the task „Trust-Objektfamilie webBundleRelease: Codec, CDDL-Arme und Signaturprofil“. The scheme `WR-0<Abschnitt>` cannot express two rows for §4.2, so this row expressly receives an identifier OUTSIDE the scheme: `WR-042D`. Version `v1.1`, source column ending on `4.2` — `web_reader_must_requirements_are_recorded_as_v1_1_rows` compares with `ends_with` — and an evidence column naming `crates/ea-format/tests/web_bundle_release.rs` and `vectors/web-bundle/v1/`.

`WEB_READER_MUST_ROWS` follows in the same commit. Its arity when this task starts is EIGHT: seven tuples in the checked-in state plus the tuple `("WR-064", "6.4", "3", "implemented")` of the task „Web-Serverfläche: Vault-Blobs, WebAuthn-Assertion und CORS“. This task adds EXACTLY ONE tuple, `("WR-042D", "4.2", "3", "implemented")`, so the arity goes from eight to nine. The three existing tuples change their stage column from `"3"` to `"4"`: `("WR-041", "4.1", "4", "planned")`, `("WR-042", "4.2", "4", "planned")`, `("WR-043", "4.3", "4", "planned")`. The shift is WRITTEN OUT in the doc comment of the constant, exactly after the pattern of the decision D-HE2 already standing there. The closed Stage-1 and Stage-2 gate reports are NOT edited for it; `docs/traceability/stage-2-gate.md:348` carries this mechanism as precedent.

The fourth left-over row is `FR-043` in version `v1.1` („Bereinigung von Staging- und Abbruchresten"), and it KEEPS `stage=3` and goes to `status=implemented`. It is named separately from the fourteen above for one reason only: its evidence is built by another task of this stage, not by this one. The task „Writer Sync Queue, Network-Archive Ordering, and Receipt Persistence“ gives the archive port its delete primitive and cleans staging after complete reconciliation (design.md:460, step 13) and pre-published grants without a committed `.eip` after a proven abort (design.md:468); the evidence column is rewritten from its open finding onto `crates/ea-writer/tests/prepared_recovery.rs::staging_and_grant_leftovers_fall_only_after_a_proven_outcome`. Its `v1` sibling row on `stage=2`, `status=integrated` stays untouched. With these fifteen closings and the Web-Reader split above, no ledger row with `stage=3` is left on `planned`.

- [ ] **Step 4: Run the complete Stage 3 gate**

Run:

```bash
cargo run --locked -p xtask -- integration up
pnpm test:server
cargo test --locked -p ea-system-tests --test privacy_canaries_server
cargo test --locked -p ea-system-tests --test backup_restore_server_restore
pnpm supply-chain
pnpm stage-gate:3
pnpm verify:quick
cargo run --locked -p xtask -- integration down
```

Three things about this run are deliberate and are not to be simplified back. `pnpm supply-chain` stands in the second-to-last position before `pnpm verify:quick`, exactly where the Stage-2 run put it (`docs/traceability/stage-2-gate.md`, section `Gemessener Gate-Lauf`); without that line `deny.toml` is completely dead for Stage 3, because no gate calls `cargo deny` by itself, and this stage pulls the largest new dependency tree of the project. The privacy and restore evidence runs as a direct `cargo test` command and not through a wrapper: gates named `test-privacy` and `test-backup-restore` do not exist in the dispatcher, AND the `test-*` gates reject every argument, so the wrapper route would be two changes, while the Stage-2 model `cargo test --locked -p ea-system-tests --test privacy_canaries_writer` is a one-change precedent. And `pnpm stage-gate:3` rather than `cargo run --locked -p xtask -- stage-gate 3`, so that the script really appears in the measured run, the way `pnpm stage-gate:2` does in Stage 2.

Expected: PASS. All commit/replay/partial-failure assertions hold, no canary appears, and the report marks production restore/release evidence open for Stage 7. Step 3 executes every ledger movement, so by the time this run happens the gate is green; the ledger is nevertheless the one place where a RED gate can be expected rather than a defect, and the boundary is exact. While any ledger movement of Step 3 is still outstanding, `pnpm stage-gate:3` reports exactly one line, and it names all four rows the filter still finds, in ledger order: `stage 3 requirement ledger rows still on planned: FR-043, WR-041, WR-042, WR-043`. Three of them — WR-041, WR-042, WR-043 — leave that line through the Web-Reader split of Step 3; the fourth, FR-043, leaves it by being closed on the evidence of the task „Writer Sync Queue, Network-Archive Ordering, and Receipt Persistence“ and is not part of that split. A red gate BEFORE those movements is therefore the expected pre-state and no implementation error; a red gate AFTER them is a defect and is to be treated as one. The line is also the exact form to compare against: any other row name in it means a Stage-3 row was forgotten, not that the movement failed.

- [ ] **Step 5: Commit the Stage 3 gate**

```bash
git add apps/server ops tests docs/traceability tools/xtask package.json
git commit -m "test(sync): close blind sync stage"
```
