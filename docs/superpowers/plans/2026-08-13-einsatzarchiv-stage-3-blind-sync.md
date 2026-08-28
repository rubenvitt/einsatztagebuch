# Einsatzarchiv Stage 3 Blind Sync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a blind, signed, idempotent sync service that atomically accepts already committed archive bytes, returns immutable Receipts and standard Checkpoints, and never needs fachliche plaintext or decryption authority.

**Architecture:** Put request/response framing and RFC-9421 verification in a shared Rust protocol crate. Keep the transport-neutral commit service separate from Axum, PostgreSQL, S3, server keys, and clock adapters. Object bytes are streamed and content-addressed first; a locked PostgreSQL transaction makes Entry, complete initial grants, head, and the one-time Receipt visible together. Writer sync observes only locally committed archive bytes and persists a verified Receipt before reporting success.

**Tech Stack:** Shared Stage 1/2 Rust crates, Axum, TLS 1.3, RFC 9421 HTTP Message Signatures, RFC 9530 Digest Fields, PostgreSQL, SQL migrations, S3-compatible object storage, Tokio, OCI Linux `amd64`, integration tests against real PostgreSQL and S3-compatible services.

**Task numbering:** This plan carries twelve tasks. Former numbers map to new ones as 1→3, 2→4, 3→5, 4→6, 5→7, 6→8, 7→10, 8→12; tasks 1, 2, 9, and 11 are new. Every cross-reference in this plan cites a task by its title, never by its number.

## Global Constraints

- Die Schlüsselwörter **MUSS**, **DARF NICHT**, **SOLL**, **SOLL NICHT** und **DARF** sind normativ zu verstehen. Ein Release darf von einer MUSS-Anforderung nicht abweichen. Eine Abweichung von SOLL erfordert eine dokumentierte Sicherheits- oder Betriebsbegründung.
- **Merker Web-Reader**, `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §12: Ablage und Abruf der Wrapped-Vault-Blobs, WebAuthn-Credentials, CORS und RFC-9421-Request-Signatur aus dem Browser (Bundle-Auslieferung und -Pinning entfallen als Sync-Server-Fläche: web-reader-design.md §4.1, :70-75, verbietet sie dort; das Bundle kommt von einem getrennten Origin.); dazu §6.4.1, WebAuthn-Credentials am Sync-Server mit der pseudonymen `subjectId` als `userHandle`. Die bestehenden Tasks werden nicht umgeschrieben; die neue Fläche entsteht additiv im Task „Web-Serverfläche: Vault-Blobs, WebAuthn-Assertion und CORS“. Die bereits gebauten Lese- und Verwaltungsflächen bleiben unverändert, die Endpunktmenge wächst um genau drei Einträge. Das Web-Bundle MUSS von einem **vom Sync-Server getrennten Origin** ausgeliefert werden (§4.1); der Sync-Server ist kein Bestandteil des Vertrauenspfades für ausgeführten Code. Die Trust-Objektfamilie `webBundleRelease` (§4.2; die Stufenzuordnung steht in §1, :23-25 — §12, :443-446, nennt für Stufe 3 nur Flächen und nicht die Objektfamilie) ist eine v1.1-Erweiterung. Stufe 3 liefert den Umfang aus docs/superpowers/plans/2026-08-16-einsatzarchiv-web-reader-stage-1-prerequisites.md:1016 — Codec, CDDL-Arm und Signaturprofil — und friert die Vektoren der Familie in dieser Stufe permanent ein. Gegenstand dieser Stufe sind ausschließlich die Wrapped-Vault-Blobs nach §6.4/§6.4.1. Das Escrow-Chiffrat nach §7.3 bleibt Stufe 5 und wird hier nicht berührt; der Ablageort dafür rückt in dieser Stufe nicht vor.
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
- Consumes: the pinned toolchain, `[workspace.dependencies]` of the root `Cargo.toml`, the existing ADR witness in `tools/xtask/tests/adr_gate.rs`, and the five-entry license allowlist of `deny.toml`.
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

Enter the ratified classes exactly `=`-pinned in `[workspace.dependencies]` of the root `Cargo.toml` and **name the S3 client crate by name**; `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md:121` says only "S3-kompatibler Object Store". This task deliberately registers **no workspace member** — a `members` line pointing at a directory without a manifest fails `cargo metadata` and with it every test; the tasks that create the four crates register them. No pin is entered that no member of this stage consumes. Because this task rewrites `Cargo.lock` for the first time, `cargo metadata --format-version 1` is the exactly one command it runs without `--locked`; every other command of this task carries `--locked` again, as the lockfile-progress rule in `tools/xtask/tests/workspace.rs` requires.

Add the license exceptions to the `exceptions` block of `deny.toml` in the pattern already used there (crate, license, justification, path into the graph). The allowlist stays at **five** entries — `Apache-2.0`, `BSD-3-Clause`, `BlueOak-1.0.0`, `MIT`, `Unicode-3.0` — because the comment above the block says verbatim that "eine neue Crate unter derselben Lizenz wird weiterhin abgewiesen, und das ist der Unterschied zwischen einer Ausnahme und einer stillschweigenden Erweiterung". Expected candidates from the TLS/S3 subtree are `rustls-webpki` and `untrusted` (ISC alone); no copyleft is in the plausible set. The same comment fixes the place of decision normatively: it points at the section `Gemessener Gate-Lauf` of `docs/traceability/stage-2-gate.md`, so for this stage the section of the same name in `docs/traceability/stage-3-gate.md`. Every new license exception gets a ledger anchor in `docs/traceability/v0.1-requirements.csv` after the pattern of the row `GATE-25` that carries the sixteen advisory exceptions; an exception without an anchor enforces nothing.

Version `mise.toml`: the file is untracked today because `.gitignore:12` carries the line `mise.toml`, so that line is removed first. Then replace `pnpm = "latest"` with the exact pin `pnpm = "11.20.0"`, so the file does not stand against `docs/adr/0001-toolchain-and-cryptography-dependencies.md:28` and `package.json:4` (`"packageManager": "pnpm@11.20.0"`). The same file carries the container-runtime pin below. ADR 0001 pins Rust, Node, pnpm, the fuzz nightly and cargo-fuzz exactly (:26-30) and has no line for Docker/Podman/colima to this day.

Build the subcommand `integration` with the two arguments `up` and `down` into the dispatcher (`match gate.as_str()` in `fn run` of `tools/xtask/src/main.rs`). Write the argument grammar out rather than opening it silently: the `test-*` gates and `validate-schemas` reject every argument explicitly, `stage-gate` takes exactly one NUMERIC argument, and `integration` is the first gate with a symbolic one — the two accepted words are `up` and `down`, everything else is an error. `integration up` starts the two services from `ops/compose/integration.yaml` and prints the connection data so that `DATABASE_URL` and the S3 endpoint are set for the following `cargo test` commands, because `#[sqlx::test]` reads `DATABASE_URL` at runtime. Both subcommands are idempotent. The `verify-quick` arm of the same dispatcher gets the fail-closed reachability check for PostgreSQL and the object store that the service precondition above demands, built in the form of `ensure_wasm32_target_available()`: it runs before the affected command, reports the missing service with an instruction, and offers no environment-variable bypass.

Choose and pin the container runtime (Docker/Podman/colima), the two integration images with **tag AND digest**, and the S3-compatible service **by name** in this same task. MinIO, SeaweedFS, LocalStack and Garage differ in versioning, object lock and conditional put, and the stage requires bucket versioning; an unpinned `integration up` is worthless.

- [ ] **Step 4: Prove the feature selection resolves under `--all-features` before any task enters it**

Run:

```bash
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --doc --all-features --locked
```

Expected: PASS. These are exactly the two `verify:quick` subcommands that carry `--all-features`. If backend features are mutually exclusive (typical for the sqlx drivers and the TLS providers), the feature selection is fixed VERBATIM in ADR 0004 and carried in the crate manifests with `default-features = false` plus explicitly enumerated features — the same form the existing witness in `tools/xtask/tests/adr_gate.rs` already enforces.

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
    let plan = GrantPlanV1::new(fixtures::plan_items()).unwrap();
    let decoded = decode_grant_plan(plan.exact_bytes()).unwrap();
    assert_eq!(decoded.exact_bytes(), plan.exact_bytes());
    assert_eq!(decoded.hash(), plan.hash());
    assert!(decode_grant_plan(&fixtures::vector("rejected-unsorted-plan-items")).is_err());
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

There is nothing to choose here, only something to publish: the bytes are already frozen through `grant_plan_digest` with the domain `EINSATZARCHIV-GRANT-PLAN-v1` and through the positive vectors under `vectors/grants/v1/plan/`. `crates/ea-format/src/eag.rs` gets `pub fn exact_bytes(&self) -> &[u8]` on `GrantPlanV1` — today that access exists only on `GrantBodyV1`, while `GrantPlanV1::new` produces the exact bytes and drops them immediately. It also gets `pub fn decode_grant_plan(bytes: &[u8]) -> Result<GrantPlanV1, FormatError>` as the counterpart to the today-private `encode_plan_items`; `crates/ea-format/src/lib.rs` takes both names into its existing `pub use` block. The decoder MUST run the same ordering and duplicate checks as `GrantPlanV1::new` and REJECT a divergent order or a duplicate instead of re-sorting — otherwise the `initialGrantPlanHash` and with it the replay identity diverges from the Writer. This task extends `ea-format` by access and decoder ONLY: `GrantPlanV1::new`, `GrantPlanItemV1::new` and the existing `Debug` implementations stay unchanged, no new constructor appears, and no visibility on the encoder side changes. No reimplementation of the item encoding in `crates/ea-sync-protocol` is admissible afterwards; the global constraint against a second implementation forbids it.

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
- Consume existing unchanged: `schemas/protocol/v1/signed-protocol.cddl`
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

**Interfaces:**
- Consumes: exact object bytes, `GrantPlanV1`, device certificates, COSE/Ed25519 verifier.
- Produces: byte-stable request/response bodies, `RequestVerifier`, `AuthenticatedDevice`, `EntryCommitRequestV1`, `EntryCommitIdentity`, `ReaderBatchV1`, `TechnicalCursorV1`.

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

Run: `cargo test --locked -p ea-sync-protocol`

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

object-response-v1 = exact-archive-object-bytes: bstr

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

The addendum fixes media types `application/einsatzarchiv+cbor;v=1` for structured bodies, `application/einsatzarchiv-object` for raw object GETs, and a streamed sequence of exact objects plus final `archive-export-manifest-v1` for export. It defines every endpoint's request/response schema, required caller capability, status/error codes, empty-body behavior, pagination and no-content response. All object/hash lists are bytewise sorted and duplicate-free. A `TechnicalCursorV1` is an opaque, expiring server-authenticated deterministic-CBOR token over `[1, organizationId, endpointCode, chainId-or-null, startHeadHash-or-null, lastTechnicalIndex, expiresAt, nonce]`; clients never parse or trust it, and it contains no fachliche metadata.

Fix v1 limits exactly in the addendum: structured request/response CBOR depth/item/string limits reuse Stage 1; entry commit accepts one `.eip`, at most 10,000 grant-plan/grant items, and total body at most 643 MiB (2 MiB Entry plus 10,000 × 64 KiB grant ceiling plus bounded framing); Reader batches and export streams may contain at most 1,000 object records per page and 64 MiB of bytes; Trust pages at most 1,000 `.etb`; grant/checkpoint pages at most 10,000/1,000 objects; challenge/registration/errors at most 64 KiB. The server must enforce both count and streamed byte limit before accumulation. HTTP mapping is exact: `400` malformed framing/content digest; `401` missing/invalid/expired signature or challenge; `403` valid identity without capability/organization access; `404` unknown object/chain/Entry/destruction ID; `409` fork, head mismatch, byte conflict, non-idempotent replay, or required newer Registry head; `413` byte/count/parser limit; `422` well-formed but invalid Trust/format/grant/authorization; `429` challenge/rate limit; `503` temporary database/Object Store/TSA dependency; other internal failures `500`. Response bodies always use `protocol-error-v1`, contain no supplied payload fragment, and set `retryable=true` only for `429`, `500`, or `503` technical failures.

Stable Entry replay identity is exactly `[entryHash, entryObjectHash, initialGrantPlanHash, sortedInitialGrantObjectHashes]`. Reject duplicate object/grant hashes before service invocation. `RequestVerifier` checks signature coverage, certificate/key identity, capability, organization tag, `created < expires`, bounded validity window, request digest, single-use nonce, and globally unique request ID before routing.

- [ ] **Step 4: Validate OpenAPI/CDDL and all positive/negative signature fixtures**

Run: `cargo test --locked -p ea-sync-protocol && cargo run --locked -p xtask -- validate-protocol`

Expected: PASS; absent/duplicate component, wrong digest/authority/URI/tag, expired request, nonce replay, request-ID replay, and wrong certificate all fail distinctly.

- [ ] **Step 5: Commit protocol definitions before server code**

```bash
git add docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-sync-wire-addendum.md schemas/protocol crates/ea-sync-protocol Cargo.toml Cargo.lock
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
- Create: `apps/server/migrations/0001_initial.sql`
- Create: `ops/compose/integration.yaml`
- Test: `apps/server/tests/migrations.rs`
- Test: `apps/server/tests/object_store.rs`

**Interfaces:**
- Consumes: protocol and shared verification crates.
- Produces: `CommitRepository`, `ObjectStore`, `ServerSigner`, `ServerClock`, real PostgreSQL/S3 adapters, and technical tables with required uniqueness.

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

Run: `cargo run --locked -p xtask -- integration up && cargo test --locked -p einsatzarchiv-server --test migrations --test object_store`

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

Create tables for organizations, pending device requests, Trust/Registry events, role intervals, chain heads, Entries, object index, grants, Receipts, checkpoints, evidence jobs, Reader acknowledgements, replay nonces, request IDs, Security Events, and technical admin audit. Store no incident number/time/keyword/location/person/vehicle/patient/note. Object keys are `<type>/<hex objectHash>` only; tags/custom metadata contain content type and size, never domain fields. Enable bucket versioning in integration configuration.

- [ ] **Step 4: Run migrations, streaming, and schema-canary tests**

Run: `cargo test --locked -p einsatzarchiv-server --test migrations --test object_store`

Expected: PASS; the S3 adapter streams and hashes without buffering a full payload and a schema inspection finds no fachliche columns.

- [ ] **Step 5: Commit server persistence ports**

```bash
git add crates/ea-sync-server apps/server ops/compose Cargo.toml Cargo.lock
git commit -m "feat(sync): add technical server persistence"
```

### Task 5: Challenges, Device Registrations, and Trust Distribution (formerly Task 3)

**Files:**
- Create: `crates/ea-sync-server/src/auth.rs`
- Create: `crates/ea-sync-server/src/trust.rs`
- Create: `apps/server/src/http/challenges.rs`
- Create: `apps/server/src/http/device_registrations.rs`
- Create: `apps/server/src/http/trust.rs`
- Modify: `apps/server/src/router.rs`
- Test: `apps/server/tests/auth_trust_api.rs`

**Interfaces:**
- Consumes: `RequestVerifier`, Trust verifier/Registry line, Postgres nonce/request stores.
- Produces: rate-limited single-use challenges, pending self-signed registration requests, and exact Root-signed Trust object distribution.

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

Challenge responses include random nonce, server time, expiration, and server signature; store only nonce digest and state. Rate limit by non-content technical identity. Registration accepts device ID, requested role, public keys, format capabilities, and self-signature only; it cannot activate authority. `POST /v1/trust/events` requires currently authorized Root/device capability as specified and validates exact `.etb` bytes before transactionally indexing them. `GET /v1/trust/registry` returns exact objects after the requested version and never synthesizes a Trust decision from database rows.

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
- Create: `crates/ea-sync-server/src/commit.rs`
- Create: `crates/ea-sync-server/src/validation.rs`
- Create: `crates/ea-sync-server/src/reconcile.rs`
- Create: `apps/server/src/http/entry_commits.rs`
- Modify: `apps/server/src/router.rs`
- Test: `crates/ea-sync-server/tests/commit_service.rs`
- Test: `apps/server/tests/entry_commit_api.rs`
- Test: `apps/server/tests/commit_failures.rs`

**Interfaces:**
- Consumes: `AuthenticatedDevice`, exact Entry/plan/grants, `ObjectStore`, `CommitRepository`, selected server-known Registry head.
- Produces: `CommitService::commit -> CommitOutcome::{Accepted,IdempotentReplay}` and quarantined/reconcilable invisible orphans.

- [ ] **Step 1: Write grant-completeness, fork, replay, and partial-failure tests**

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
```

- [ ] **Step 2: Run commit tests and verify failure**

Run: `cargo test --locked -p ea-sync-server --test commit_service && cargo test --locked -p einsatzarchiv-server --test entry_commit_api --test commit_failures`

Expected: FAIL because no atomic commit service exists.

- [ ] **Step 3: Implement the nine-step server commit transaction**

Stream and limit each object to a temporary key while hashing; parse/verify Entry, object hash, Writer, suite, Registry line, plan, each grant signature/context, exactly one Recovery, and every active Reader. Put verified bytes content-addressed with byte-conflict detection. Lock the chain head in PostgreSQL; choose the highest server-known applicable Registry head for `acceptedAtServer` and sequence; reject an older bound head. Accept only current sequence + 1, exact predecessor, and authorized Writer. Build Receipt once, persist exact Receipt bytes, then atomically make Entry, grants, head, and Receipt hash visible. Read the Receipt back by hash and verify exact bytes before response.

Only the tuple `(entryHash, entryObjectHash, initialGrantPlanHash, sorted initialGrant objectHashes)` is idempotent. Same Entry hash with different bytes/grants, same sequence with different Entry, wrong predecessor, or wrong Writer creates a cleartext-free Security Event. Pre-commit Object Store artifacts remain invisible and are reverified before adoption or quarantine.

- [ ] **Step 4: Run real-service concurrency and failure tests**

Run: `cargo test --locked -p einsatzarchiv-server --test entry_commit_api --test commit_failures -- --test-threads=1`

Expected: PASS under parallel commits, database aborts, object-store faults, response loss, and retry; no failure exposes a head or accepted Receipt without the full grant set.

- [ ] **Step 5: Commit atomic Entry acceptance**

```bash
git add crates/ea-sync-server apps/server
git commit -m "feat(sync): atomically accept entries and grants"
```

### Task 7: Standard Checkpoints and the Checkpoint Chain (formerly Task 5)

**Files:**
- Create: `crates/ea-sync-server/src/receipt.rs`
- Create: `crates/ea-sync-server/src/checkpoint.rs`
- Create: `apps/server/src/http/checkpoints.rs`
- Test: `crates/ea-sync-server/tests/receipt_golden.rs`
- Test: `crates/ea-sync-server/tests/checkpoint.rs`

**Interfaces:**
- Consumes: committed head, policy, server Receipt/checkpoint signer.
- Produces: exact `esr-v1`, standard `.ecp` checkpoint, monotonic `acceptedAtServer`, and immutable `evidenceDueAt` for Stage 6.

- [ ] **Step 1: Write exact Receipt and monotonic-time tests**

```rust
#[test]
fn evidence_due_time_is_signed_once_from_receipt_policy() {
    let standard = build_receipt(fixtures::standard_policy(), UnixMillis(100)).unwrap();
    assert_eq!(standard.core().evidence_due_at, None);
    let evidence = build_receipt(fixtures::evidence_policy(500), UnixMillis(100)).unwrap();
    assert_eq!(evidence.core().evidence_due_at, Some(UnixMillis(600)));
    assert_eq!(evidence.exact_bytes(), fixtures::expected_evidence_receipt_bytes());
}

#[test]
fn accepted_time_never_precedes_prior_receipt() {
    assert_eq!(accepted_at(UnixMillis(90), Some(UnixMillis(100))).unwrap(), UnixMillis(100));
}
```

- [ ] **Step 2: Run tests and verify exact Receipt generation is absent**

Run: `cargo test --locked -p ea-sync-server --test receipt_golden --test checkpoint`

Expected: FAIL because Receipt/checkpoint builders do not exist.

- [ ] **Step 3: Implement Receipt fields and standard checkpoint bytes exactly once**

Sort duplicate-free grant hashes bytewise. Compute `acceptedAtServer = max(current server UTC, predecessor acceptedAtServer)`. Standard policy sets `evidenceDueAt = null`; Evidence Grade sets exact checked addition `acceptedAtServer + policy.evidenceMaxDelayMs`. Bind policy hash, Registry head, plan hash, Entry/object/predecessor hashes, server thumbprint/certificate, and empty critical extensions. Sign the Receipt digest with capability `serverReceipt` and persist exact bytes in the same commit.

After accepted commit, build a standard checkpoint over organization, chain, covered range, head Entry, Registry head, `issuedAtServer`, and previous checkpoint hash. Sign and archive it; Stage 6 adds CTT without changing historical Receipt or standard checkpoint bytes.

- [ ] **Step 4: Run golden, replay, overflow, and checkpoint-chain tests**

Run: `cargo test --locked -p ea-sync-server --test receipt_golden --test checkpoint`

Expected: PASS; replay never changes Receipt time/signature/bytes, overflow fails, and divergent checkpoint predecessors become Security Events.

- [ ] **Step 5: Commit Receipts and checkpoints**

```bash
git add crates/ea-sync-server apps/server vectors/receipts vectors/evidence
git commit -m "feat(sync): issue immutable receipts and checkpoints"
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
- Consumes: verified Trust fixtures now; full Stage 5 authorization workflows later.
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

Reader batch binds requested `afterSequence/afterEntryHash`, returns exact later `.eip/.eds`, grants, Trust, Receipts, and checkpoints plus an opaque cursor, and never treats a database list as verification. Object GET streams exact stored bytes. Reader acknowledgements are signed technical objects.

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

_(written in a later editing pass)_

### Task 10: Writer Sync Queue, Network-Archive Ordering, and Receipt Persistence (formerly Task 7)

**Files:**
- Create: `crates/ea-sync-client/Cargo.toml`
- Create: `crates/ea-sync-client/src/lib.rs`
- Create: `crates/ea-sync-client/src/queue.rs`
- Create: `crates/ea-sync-client/src/client.rs`
- Create: `crates/ea-sync-client/src/retry.rs`
- Create: `crates/ea-sync-client/src/receipt.rs`
- Create: `apps/desktop/src-tauri/src/commands/sync.rs`
- Modify: `apps/desktop/src/components/integrity/SyncStatus.tsx`
- Test: `crates/ea-sync-client/tests/resume.rs`
- Test: `crates/ea-sync-client/tests/status.rs`
- Test: `apps/desktop/src/components/integrity/SyncStatus.test.tsx`

**Interfaces:**
- Consumes: committed archive inventory, configured network archive publisher, signed HTTP client, full Receipt verifier.
- Produces: `SyncClient::push_pending(limit) -> PushSummary`, reconstructible queue, bounded retry, and exact four-state UI DTO.

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
```

- [ ] **Step 2: Run sync-client tests and verify failure**

Run: `cargo test --locked -p ea-sync-client && pnpm --dir apps/desktop test --run SyncStatus`

Expected: FAIL because queue/client/status integration does not exist.

- [ ] **Step 3: Implement queue derivation and bounded retry**

Rebuild pending Entries from committed `.eip` plus exact initial grants and absence of a valid local `.esr`. For controlled network profiles, publish exact committed grants then `.eip`, verify byte equality, and only then call server. Sign every request using a fresh challenge. Retry network/timeout/5xx with bounded exponential backoff plus jitter and persisted next attempt; do not auto-retry format, signature, fork, Registry, or authorization errors as success. Verify and create-if-absent persist Receipt locally and remotely before `Synchronized`. Detail causes are nonnormative and cleartext-free; public status remains exactly four values.

- [ ] **Step 4: Run offline/reconnect/restart/replay tests**

Run: `cargo test --locked -p ea-sync-client && pnpm --dir apps/desktop test --run SyncStatus`

Expected: PASS; queue reconstruction ignores mutable queue rows and an interrupted response resumes idempotently to the same Receipt.

- [ ] **Step 5: Commit Writer sync**

```bash
git add crates/ea-sync-client apps/desktop Cargo.toml Cargo.lock pnpm-lock.yaml
git commit -m "feat(sync): resume Writer uploads from archive bytes"
```

### Task 11: Trust-Objektfamilie webBundleRelease: Codec, CDDL-Arm und Signaturprofil

_(written in a later editing pass)_

### Task 12: Server Administration Separation, Failure Matrix, Privacy, and Stage Gate (formerly Task 8)

**Files:**
- Create: `apps/server/src/admin_audit.rs`
- Create: `ops/container/Dockerfile`
- Create: `ops/monitoring/metrics.md`
- Create: `tests/ea-system-tests/tests/privacy_canaries_server.rs`
- Create: `tests/ea-system-tests/tests/backup_restore_server_restore.rs`
- Create: `docs/traceability/stage-3-gate.md`
- Modify: `docs/traceability/v0.1-requirements.csv`
- Modify: `tools/xtask/src/main.rs`
- Test: `tools/xtask/tests/stage_gate.rs`

**Interfaces:**
- Consumes: complete server and sync client.
- Produces: cleartext-free privileged audit, pinned OCI build input, `xtask stage-gate 3`, primary AK 7, 8, 13, 33, 36, 45, 50 evidence.

- [ ] **Step 1: Write administrative-separation and gate tests**

```rust
#[test]
fn server_admin_configuration_has_no_content_or_grant_authority() {
    let caps = ServerAdminConfig::schema_capabilities();
    assert!(!caps.iter().any(|c| matches!(c, Capability::Decrypt | Capability::InitialGrant |
                                             Capability::HistoricalGrant | Capability::WriterSign |
                                             Capability::RegistryAuthorize)));
}

#[test]
fn stage_three_gate_requires_real_service_failures_and_primary_ak() {
    let gate = xtask_test::stage_gate(3);
    assert_eq!(gate.primary_acceptance_criteria, [7, 8, 13, 33, 36, 45, 50]);
    assert!(gate.scenarios.contains_all(["db-before-commit", "db-after-object-put", "s3-stage",
                                         "response-loss", "parallel-fork", "nonce-replay", "restore"]));
}
```

- [ ] **Step 2: Run gate tests and confirm missing evidence fails**

Run: `cargo test --locked -p xtask --test stage_gate stage_three`

Expected: FAIL listing absent failure, privacy, audit, and restore evidence.

- [ ] **Step 3: Complete hardening evidence without claiming release readiness**

Audit privileged login, config changes, backup/restore, Object Lock changes, server-key rotation, updates, and Security Event handling with pseudonymous actor/device, action code, technical result, time, and object hashes only. Search every fachliche canary through logs, error bodies, PostgreSQL values, S3 keys/tags/metadata, metrics labels, traces, and container output. Restore PostgreSQL and bucket into a separate integration namespace and verify exact objects/head against a known checkpoint. Pin the OCI base by digest selected in ADR 0001; run as non-root, read-only root filesystem, dropped capabilities, dedicated writable volumes, and external secret injection for server signer.

Update ledger rows only to `implemented`/`integrated`; Stage 7 retains production backup, signed image, and full platform release verification.

- [ ] **Step 4: Run the complete Stage 3 gate**

Run:

```bash
cargo run --locked -p xtask -- integration up
pnpm test:server
cargo run --locked -p xtask -- test-privacy --scope server
cargo run --locked -p xtask -- test-backup-restore --scope server
cargo run --locked -p xtask -- stage-gate 3
pnpm verify:quick
cargo run --locked -p xtask -- integration down
```

Expected: PASS; all commit/replay/partial-failure assertions hold, no canary appears, and the report marks production restore/release evidence open for Stage 7.

- [ ] **Step 5: Commit the Stage 3 gate**

```bash
git add apps/server ops tests docs/traceability tools/xtask
git commit -m "test(sync): close blind sync stage"
```
