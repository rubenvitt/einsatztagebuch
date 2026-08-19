# Einsatzarchiv Stage 2 Offline Writer Implementation Plan

> **Revision 2026-08-18.** Ein achtdimensionaler Pre-flight-Audit hat diesen Plan gegen Spec, Addenda und den tatsächlichen Codebestand geprüft und dabei vier menschliche Entscheidungen, 48 Controller-Rulings, 39 Defekt-Arbeitspositionen und acht fehlende Tasks aufgedeckt. Die vier menschlichen Entscheidungen D-B01 (`importProtocolHash` bekommt ein normatives Urbild), D-B02 (die vier Hashdomains werden festgeschrieben), D-HE1 (`rusqlite` mit gebundenem SQLCipher) und D-HE2 (Ein-Datei-Bündelexport über `webBundleRelease`) sind getroffen und in diese Fassung eingearbeitet; die Tasknummerierung ist auf 1..18 durchgezogen und jede Überschrift nennt ihre alte Nummer. Alle Belege, Rulings und Ist/Soll-Wortlaute liegen in `.superpowers/sdd/2026-08-13-einsatzarchiv-stage-2-offline-writer/preflight/SYNTHESE.md`.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a cross-platform Writer that can capture, review, and irreversibly finalize exactly one encrypted draft into a durable local archive without any network dependency.

**Architecture:** Keep draft storage, native key handling, archive durability, and finalization as separate Rust modules behind proof-state interfaces. The finalization transaction prepares immutable bytes first, crosses its irreversible boundary only after confirmed `draftDEK` deletion, publishes grants before `.eip`, and reconstructs every mutable queue/head from committed archive bytes. Tauri exposes narrow commands and React renders only validated Writer view models. The eighteen tasks run in one direction — Vorlauf (1–5: Workspace, Provider, Audit-Encoder, ADR), Kern (6–8: Store, Discard, Stammdaten), Archiv (9–10: Backends und Formatbeiwerk), Finalisierung (11), Export (12), UI (13–16: Restvorlauf, Contracts, Shell, Writer-UX), Gate (17–18) — mit keiner einzigen Rücklaufkante.

**Tech Stack:** Shared Stage 1 Rust crates (`Cargo.toml:2`) on Rust 1.95.0, Edition 2024 (`rust-toolchain.toml:2`, `Cargo.toml:6-7`) with the pinned `wasm32-unknown-unknown` target (`rust-toolchain.toml:5`); `rusqlite` with bound SQLCipher for full local database encryption (D-HE1, ratified by `docs/adr/0002-*`); platform-native key/identity providers; Tauri 2, React 19, TypeScript, Ant Design 6 with `zeroRuntime: true`, `@ant-design/static-style-extract`, `@phosphor-icons/react`, Vitest, React Testing Library, Playwright. The JavaScript toolchain runs on pnpm 11.20.0 and Node 26.7.0 (`package.json:4-8`, `.node-version:1`) with `save-exact=true` and `engine-strict=true` (`.npmrc:1-2`); `apps/desktop` is already declared as a pnpm workspace package (`pnpm-workspace.yaml:2`) while `pnpm-lock.yaml:1-9` is still empty, so the exact minor/patch of every JavaScript dependency is chosen in Task 13 and frozen by the lockfile. The Rust core carries no async runtime: `[workspace.dependencies]` (`Cargo.toml:10-44`) holds neither `tokio` nor `async-trait`, and none is added.

## Global Constraints

- Die Schlüsselwörter **MUSS**, **DARF NICHT**, **SOLL**, **SOLL NICHT** und **DARF** sind normativ zu verstehen. Ein Release darf von einer MUSS-Anforderung nicht abweichen. Eine Abweichung von SOLL erfordert eine dokumentierte Sicherheits- oder Betriebsbegründung.
- **Merker Web-Reader**, `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §12: Task 15 dieses Plans schaltet **ausschließlich den Writer** frei — der Reader ist eine Browser-PWA und nicht mehr Teil der Desktopanwendung, und Administration bleibt Stufe 5 (`design.md:2177`). Der Export eines Archiv-Bündels als **eine Datei**, damit der Datei-Modus des Web-Readers (§5.2) auch in Safari und Firefox funktioniert, wo `showDirectoryPicker` fehlt, ist **Task 12** und benutzt die bereits genehmigte v1.1-Familie `webBundleRelease`. Ein siebtes Objektpräfix entsteht dabei nicht: der Formatfreeze über die sechs Präfixe (`crates/ea-format/src/lib.rs:39-45`, gepinnt in `tools/xtask/tests/spec_completeness.rs:6-8` gegen `schemas/archive/v1/archive.cddl:19-62`) bleibt unberührt.
- Microsoft Access ist vollständig außerhalb des Scopes. There is no Access import path; **Access Grant/Zugriffsfreigabe** means only a signed CEK envelope.
- Non-goals are fixed: no live incident log, dispatch/alarm/control-center integration, patient record or identifying patient data, concurrent offline Writers, normal-app mutation/deletion of finalized content, AI summarization/OCR, public links, server-side content search, unprofiled network paths, qualified personal electronic signature, TR-ESOR certification claim, screenshot/transcription prevention, or cryptographic recall of already decrypted data.
- Product invariants apply verbatim: exactly one active Writer; never-reused predecessor-bound sequences; immutable `.eip` bytes except whole-object authorized replacement by `.eds`; amendment-only corrections; one fresh CEK/ciphertext; one signed grant per recipient; exactly one active Recovery grant before commit; no Reader/Recovery/HGA/Approver private key on Writer; no retained CEK/decryptable draft key; no server decrypt/grant key; server-independent archive verification; independent schema/format/suite versions with old bytes unchanged; separate Sync/verification/Evidence/Entry/destruction statuses; no legal overclaim from a hash chain; every active Reader initially granted; external-anchor recovery; and only Root-signed OS/device-bound operator snapshots.
- Exactly one active Writer and one active draft exist. Every committed sequence is unique and binds the direct predecessor.
- `.eip` bytes are never overwritten. Corrections are later signed amendments. A payload is encrypted exactly once with a fresh CEK and nonce.
- Before local commit there is exactly one Recovery grant and one initial grant for every Reader active in the bound Registry; grants publish before `.eip`.
- A Writer device contains no private Reader, Recovery, Historical Grant Authority, or Key Approver key. After finalization it retains neither CEK nor decryptable `draftDEK`.
- The server is not required for capture or finalization. Archive bytes, not SQLite status, are authoritative.
- Schema, format, and suite versions remain independent; all Stage 1 exact bytes and vectors are immutable.
- Operator data comes from a valid Root-signed device/OS-account binding and native re-authentication, never editable identity text. Die Profilzeile wird nur **lesend** verwendet und ihr Commitment im Writer nachgerechnet; ein neues Byte-Urbild entsteht nicht, weil Präimage, Domain-Separation, Kanonisierung und Feldreihenfolge in Stufe 1 eingefroren sind (`crates/ea-schema/src/encode.rs:429-444`, `crates/ea-crypto/src/digest.rs:30`).
- **Jeder Verifikationslauf der Stufe 2 läuft unter `env -u RUSTUP_TOOLCHAIN`.** Die Entwicklungsumgebung exportiert `RUSTUP_TOOLCHAIN=1.97.1`; diese Variable hat Vorrang vor `rust-toolchain.toml` und überschreibt damit sowohl den Pin `1.95.0` als auch dessen `targets`-Deklaration. Ein grüner Lauf ohne dieses Präfix ist eine Aussage über 1.97.1 und kein Beleg für den gepinnten Compiler. Stufe 1 hat das im gemessenen Gate-Lauf schon so gehandhabt; `xtask` erkennt die Überschreibung und warnt, und Task 18 belegt den Stufe-2-Gate-Lauf ausschließlich mit Kommandos, die das Präfix tragen.
- Writer must build on supported Windows 11 `x86_64`, current/previous macOS `arm64` plus supported Intel `x86_64`, and Ubuntu 24.04 LTS `x86_64`; full signed min/max release proof belongs to Stage 7. Stufe 2 belegt Baubarkeit ausschließlich für das **Host-Target**: `rust-toolchain.toml:5` stellt nur `wasm32-unknown-unknown` bereit (gepinnt in `tools/xtask/tests/workspace.rs:290-321`), und die vier Cross-Targets `x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-apple-darwin` werden von Task 18 namentlich als offene Stufe-7-Ledgerzeilen eingetragen statt lokal behauptet.
- Cryptographic and format logic remains in shared Rust. TypeScript never creates grants, hashes, signatures, ciphertexts, Registry decisions, or archive bytes.
- **D-HE1 — lokale Datenbankverschlüsselung.** Die lokale Writer-Datenbank wird mit `rusqlite` und gebundenem SQLCipher vollständig verschlüsselt; vollständig heißt ausdrücklich auch WAL, Indizes und Temp-Spill (`design.md:1961`, `:1967`). Ratifiziert wird die Wahl gegen `docs/adr/0001-toolchain-and-cryptography-dependencies.md:75-77` durch einen neuen `docs/adr/0002-*.md` mit Primärquellen- und RustSec-Prüfung nach dem Muster `docs/adr/0001-…:152-153`; dieser ADR ist Task 5 und läuft vor Task 6, der die Datenbank anlegt. Keine Klartext-Temporärdateien, keine sensiblen Logs; Telemetrie- und Crash-Upload sind standardmäßig aus.
- **D-B01 — `importProtocolHash` hat ein normatives Urbild.** `schemas/reports/v1/import-report.cddl` wird normativ als `import-report-v1` mit fester Arrayreihenfolge übernommen, und `importProtocolHash = object_hash(exakte import-report-v1-Bytes)` nach der bestehenden Regel `crates/ea-crypto/src/digest.rs:63-66`; eine neue Domainkonstante entsteht **nicht**. Die Vektoren liegen additiv unter `vectors/reports/import-report-v1/`. Task 8 MUSS die exakten Protokollbytes lokal aufbewahren, sonst existiert kein nachprüfbares Urbild für die Provenienzzusage AK 28 (`design.md:404`).
- **D-B02 — die vier Hashdomains sind festgeschrieben.** `previewHash`, `archiveProfileHash`, `inventoryHash` und `activePointerHash` folgen der bestehenden Konvention `SHA-256(DOMAIN || deterministicCbor(core))` (`crates/ea-crypto/src/digest.rs:33-49`), und `archive-backend-profile-core-v1` wandert als geschlossene 15-Positions-CDDL ins Wire-Format-Addendum. Normativ ergänzt wird: `allowed-archive-profile-hashes` innerhalb des Root-signierten `policy-core-v1` (`schemas/archive/v1/trust.cddl:136`) trägt genau diese Werte, und eine Profilmigration mit einem Zielprofilhash außerhalb der wirksamen Policy wird fail-closed abgelehnt. Diese Festlegung bindet Stufe 7.
- **D-HE2 — Ein-Datei-Bündelexport.** WR-052 wird von Stufe 4 auf Stufe 2 gezogen und in Task 12 über die bestehende v1.1-Familie `webBundleRelease` geliefert. Ein siebtes Objektpräfix wird **nicht** eingeführt; `crates/ea-format/src/lib.rs:39-45`, `tools/xtask/tests/spec_completeness.rs:6-8` und `schemas/archive/v1/archive.cddl:19-62` bleiben unverändert. Implementierungsort ist die Host-Crate `crates/ea-archive-fs`.
- **Workspace-Buchführung im erzeugenden Task.** Jeder Task, der ein neues Workspace-Mitglied anlegt, trägt es **im selben Task** in `Cargo.toml` `[workspace]members` nach, erzeugt `Cargo.lock` neu, klassifiziert jedes neue `crates/`-Mitglied mit nichtleerer Begründung in `WASM32_EXEMPT_CRATES` (`tools/xtask/src/main.rs:102`) — niemals in die wasm32-Positivliste, die `docs/traceability/stage-1-gate.md:60-65` textuell einfriert — und hängt den Mitgliedspfad an die eine Liste `WORKSPACE_MEMBERS` in `tools/xtask/tests/workspace.rs` an und sonst nirgends: Längenzusicherung, Mengenvergleich und Abhängigkeitslauf leiten sich seit Task 1 aus dieser einen Liste ab. `apps/desktop/src-tauri` erhält keine wasm32-Klassifikation, weil der Klassifikationstest nur Mitglieder unter `crates/` einsammelt (`tools/xtask/tests/workspace.rs:152-158`) und einen klassifizierten Namen, der kein solches Mitglied ist, zurückweist; seine `tauri`-Abhängigkeiten stehen mit `workspace = true` in der Wurzeltabelle, weil `tools/xtask/tests/workspace.rs:86-101` das erzwingt.
- **Der Rust-Kern bleibt synchron.** Wie ganz Stufe 1 (`grep "async fn"` über `crates/`, `apps/`, `tools/`: null Treffer) enthalten die Stufe-2-Crates kein `async fn`, kein `.await`, kein `#[tokio::test]` und kein `#[async_trait::async_trait]`; alle Trait-Methoden von `KeyProvider`, `DraftRepository`, `MasterDataRepository`, `LocalAuditService`, `ArchiveBackend` und `WriterService` sind synchron und damit trivial dyn-fähig. Async lebt ausschließlich in `apps/desktop/src-tauri`, wo jeder `#[tauri::command]`-Handler die synchrone Kernoperation über `tauri::async_runtime::spawn_blocking` ausführt, damit die fsync-schwere Finalisierung (`design.md:446-462`) den Main-Thread nicht blockiert. Blockierendes Netz- und Datei-I/O im Controlled-Network-Backend ist unter diesem Modell korrekt und kein Grund, `tokio` in die Wurzeltabelle zu ziehen; dass `tokio` über `tauri` transitiv im Lockfile erscheint, ist erwartet.
- Alle Cargo-Kommandos laufen mit `--locked`. Die einzige Ausnahme ist der `cargo metadata --format-version 1`-Schritt, mit dem ein Task, der ein Mitglied oder eine Abhängigkeit hinzufügt, `Cargo.lock` **einmalig** erzeugt, bevor die `--locked`-Kommandos desselben Tasks laufen.
- UI uses exact Sync status copy `lokal gesichert`, `Upload ausstehend`, `synchronisiert`, `Fehler`, separates ordinary save from finalization, and never offers history or final-content access to Writer.
- v0.1 is complete only after Stage 7 and every acceptance criterion passes.

UI constraints are exact: Ant Design 6 with German `ConfigProvider`, shared tokens `eaInk #172033`, `eaSurface #F5F7FA`, `eaAction #245EA8`, `eaDanger #C6352B`, `eaVerified #187255`, `eaWarning #A65F00`, `zeroRuntime: true`, statically extracted local hashed CSS, CSP blocking runtime/external styles, Ant `App` context for overlays, direct CSR icon imports from `@phosphor-icons/react`, no `react-icons`, visible focus, semantic DOM, text in addition to color/icon, and `prefers-reduced-motion`.

## Ausfuehrungsreihenfolge und Abhaengigkeiten

Die achtzehn Tasks laufen strikt in Nummernfolge. Die zehn Tasks des Rumpfs vom 2026-08-13 stehen in unveränderter Ordnung; alle acht Ergänzungen sind Einschübe, keine Umstellungen. Dezimalnummern sind verboten, weil der Brief-Extraktor (`scripts/task-brief`) `Task 2` mit `Task 2.5` verwechselt.

| Neu | Titel | Setzt voraus | Schaltet frei |
|---|---|---|---|
| 1 | Rust-Workspace- und Toolchain-Vorlauf | Stufe-1-Bestand | Pin-Tranche 1 samt Pinning-Test, Lockfile-Regel, Klassifikationsmechanismus, synchrones Ausführungsmodell, Cross-Target-Entscheidung — Voraussetzung aller Folgetasks |
| 2 | Native Key-Provider Contract and Writer Role Guard | Task 1 | `crates/ea-key-provider`, `KeyProvider`, Signer-Port, Feature `test-support` → Tasks 3, 6, 7, 11 |
| 3 | Windows, macOS, and Ubuntu Writer Providers and Re-authentication Ports | Task 2 | `crates/ea-operator`, `OperatorSessionProof`, `ReauthPurpose`, Sperr-Invalidierung → Tasks 6, 11, 13, 15, 16 |
| 4 | `local-audit-event-v1`-Encoder in ea-format | Task 1 | exakte `local-audit-event-v1`-Bytes und Vektorfamilie `vectors/local-audit/` → Tasks 6, 9, 11, 18 |
| 5 | ADR 0002: lokale Datenbankverschluesselung | Task 1, D-HE1 | `docs/adr/0002-*`, Pin-Tranche 2 (`rusqlite`), Kopplungstest → Tasks 6, 9, 11 |
| 6 | Encrypted Local Store and Single-Draft Autosave | Tasks 2, 3, 4, 5 | `crates/ea-local-store`, `crates/ea-audit`, `crates/ea-draft`, Migration 0001, Einsatznummern-Register → Tasks 7, 8, 11, 16 |
| 7 | Irreversible Draft Discard and Crash Resume | Task 6 | Discard-Zustandsmaschine, `resume_discard`, Migration 0002 → Tasks 11, 16, 17, 18 |
| 8 | Master Data, CSV Dry Run, and Immutable Snapshots | Task 6, D-B01 | Snapshot-Typen aus `ea-schema`, `import-report-v1`-Bytes, `revision`-Spalte, Migration 0003 → Tasks 11, 16 |
| 9 | Durable Archive Backends, Health Check, and Atomic Profile Migration | Tasks 3, 4, 5, 6, D-B02 | `crates/ea-archive-fs`, `ArchiveBackend`, `ArchiveBackendError`, `WriterLock`, Publikations-Queue mit `SyncStatus`/`DetailCause` → Tasks 10, 11, 12, 14, 17, 18 |
| 10 | Formatbeiwerk beim Anlegen eines Archivs materialisieren | Task 9 | `format/schemas/`, `format/transformations/`, `format/compatibility-matrix.json`, `recovery-reports/`, `README-FORMAT.txt` → Tasks 11, 12, 18 |
| 11 | Prepared Finalization State Machine | Tasks 2, 4, 6, 7, 8, 9, 10, D-B02 (`previewHash`) | `crates/ea-writer`, `PreparedFinalization`, `CommittedFinalization`, `FinalizeOutcome`, `FinalizationPreview`, Fault-Punkt-Manifest → Tasks 12, 14, 15, 16, 17, 18 |
| 12 | Export eines Archiv-Buendels als EINE Datei | Tasks 9, 10, 11, D-HE2 | Ein-Datei-`webBundleRelease` für den Datei-Modus des Web-Readers → Tasks 16, 18 |
| 13 | Frontend- und Tauri-Restvorlauf | Tasks 1, 3 | `apps/desktop/playwright.config.ts`, Vitest-DOM-Umgebung samt Setup und `userEvent`, `.gitignore`-Einträge, Mitglied `apps/desktop/src-tauri` als `ea-desktop`, Pin-Tranche 3, Sperrereignis-Verdrahtung → Tasks 15, 16, 18 |
| 14 | `ea-ui-contracts` samt Generator und Determinismustest | Tasks 11, 13 | `crates/ea-ui-contracts`, `emit-ts`, `apps/desktop/src/bridge/generated-contracts.ts` mit Drift-Test → Tasks 15, 16 |
| 15 | Tauri Bridge, Static Ant Design Foundation, and Role-Gated Shell | Tasks 3, 11, 13, 14 | Bridge, benannte `ea*`-Tokens, statisch extrahiertes CSS, CSP, rollengetrennte Shell ohne Reader- und Administrationsfläche, Host-Build `ea-desktop` → Task 16 |
| 16 | Writer Form, Review, Discard, and Finalization UX | Tasks 7, 8, 11, 12, 15 | Erfassungsmaske, Prüfansicht, Verwerfen- und Finalisierungs-UX, Command-Allowlist-Ankertest, vier Domänenkomponenten → Task 18 |
| 17 | xtask-Gate-Werkzeug fuer Stufe 2 | Tasks 1, 7, 9, 11, 13, 15, 16 | `xtask stage-gate 2`, Stufe-2-Berichtszweig, `docs/traceability/stage-2-gate.md`-Vertrag, `stage-gate:2`-Skript → Task 18 |
| 18 | Stage 2 Fault Matrix and Acceptance Gate | Tasks 1–17 | Fault-Matrix, Privacy-Canaries, Ledgerzeilen, gemessener Gate-Lauf — Stufenabnahme |

Umsetzung der alten Nummerierung auf die neue:

| neu | alt (SYNTHESE.md) | Titel | Herkunft |
|---|---|---|---|
| 1 | 0.5 | Rust-Workspace- und Toolchain-Vorlauf | neu |
| 2 | 1 | Native Key-Provider Contract and Writer Role Guard | bestehend |
| 3 | 2 | Windows, macOS, and Ubuntu Writer Providers and Re-authentication Ports | bestehend |
| 4 | 2.5 | `local-audit-event-v1`-Encoder in ea-format | neu |
| 5 | 2.6 | ADR 0002: lokale Datenbankverschluesselung | neu |
| 6 | 3 | Encrypted Local Store and Single-Draft Autosave | bestehend |
| 7 | 4 | Irreversible Draft Discard and Crash Resume | bestehend |
| 8 | 5 | Master Data, CSV Dry Run, and Immutable Snapshots | bestehend (D-B01) |
| 9 | 6 | Durable Archive Backends, Health Check, and Atomic Profile Migration | bestehend (D-B02) |
| 10 | 6.5 | Formatbeiwerk beim Anlegen eines Archivs materialisieren | neu |
| 11 | 7 | Prepared Finalization State Machine | bestehend (D-B02: previewHash) |
| 12 | 7.5 | Export eines Archiv-Buendels als EINE Datei | neu (D-HE2) |
| 13 | 7.6 | Frontend- und Tauri-Restvorlauf | neu |
| 14 | 7.7 | `ea-ui-contracts` samt Generator und Determinismustest | neu |
| 15 | 8 | Tauri Bridge, Static Ant Design Foundation, and Role-Gated Shell | bestehend |
| 16 | 9 | Writer Form, Review, Discard, and Finalization UX | bestehend |
| 17 | 9.5 | xtask-Gate-Werkzeug fuer Stufe 2 | neu |
| 18 | 10 | Stage 2 Fault Matrix and Acceptance Gate | bestehend |

## Eingearbeitete Entscheidungen

Die achtundvierzig Entscheidungen des Pre-flight-Audits sind in den Tasktext eingearbeitet und werden dort nicht erneut aufgerollt. Die Tabelle ist die Brücke zu `SYNTHESE.md`, wo jede Entscheidung mit Belegen, Harmonisierung und Fehlerkosten steht; die Taskspalte nennt die **neue** Nummerierung.

| ID | Entscheidung | Tasks (neu) |
|---|---|---|
| R1 | Jeder erzeugende Task trägt sein neues Workspace-Mitglied, dessen wasm32-Ausnahmeklassifikation und die Längenzusicherung im selben Task nach; im Plantext steht keine Zahl. | 1, 2, 3, 6, 9, 11, 13, 14 |
| R2 | Die `=`-Pins in `[workspace.dependencies]` entstehen in drei Tranchen (Pfade und `serde`; `rusqlite`; `tauri`/`tauri-build`), begleitet von einem Test, der jedes Versionsliteral auf führendes `=` prüft. | 1, 2, 5, 6, 9, 11, 13, 14, 15 |
| R3 | Jeder Task, der Mitglieder oder Abhängigkeiten hinzufügt, erzeugt `Cargo.lock` in einem vorangestellten Step einmalig mit `cargo metadata --format-version 1` ohne `--locked`. | 2, 3, 4, 5, 6, 7, 8, 9, 11, 13, 14, 15, 18 |
| R4 | Der Rust-Kern bleibt synchron; Async existiert ausschließlich in `apps/desktop/src-tauri` über `tauri::async_runtime::spawn_blocking`. | 2, 3, 6, 7, 8, 9, 11, 15, 16 |
| R5 | Der deterministische In-Memory-`KeyProvider` steht hinter dem nicht-default Feature `test-support` und wird von den Testcrates als `dev-dependency` eingeschaltet. | 2, 6, 7, 11, 18 |
| R6 | `hpke_open` und `HpkeOpenInput` entfallen aus dem Stufe-2-Provider-Kontrakt. | 2 |
| R7 | Der Signer-Port nimmt content-typisierte Payload-Bytes, nicht einen Digest. | 2, 6 |
| R8 | `SecretBytes` ist längengeneriert (`SecretBytes<32>`) und besitzt nur `new`; `SecretBytes::from` existiert nicht. | 2, 6, 7 |
| R9 | `KeyProtectionProfileV1` wird unverändert verwendet, der Abgleich ist fail-closed, und `hardwareNonExportable` ist mit explizit unterstütztem Provider zulässig. | 2, 3, 15 |
| R10 | `CertificateCapability` wird additiv aus `ea-crypto` exportiert statt neu deklariert. | 2, 3, 15 |
| R11 | Der Datenbankschlüssel reist als `SecretVec` über das vorhandene `with_exposed`; ein neuer `ea-crypto`-Accessor entsteht nicht. | 6, 7, 8 |
| R12 | `SecretPurpose` wird gegen `KeyPurpose` abgegrenzt; eine Umbenennung auf `SignerRole` findet nicht statt. | 2, 3, 6 |
| R13 | Zeitwert- und Trust-Typnamen werden auf den Bestand zurückgenommen. | 3, 6, 11 |
| R14 | Eine OS-Sperre invalidiert den `OperatorSessionProof`; das Sperrereignis wird verdrahtet. | 3, 13, 15, 16 |
| R15 | Die vier Cross-Target-Checks entfallen; Baubarkeit auf den vier Zielen wird als offene Stufe-7-Ledgerzeile eingetragen statt lokal behauptet. | 3, 18 |
| R16 | ADR 0002 zur lokalen Datenbankverschlüsselung ist ein eigener Vorlauf-Task unmittelbar vor dem Store-Task und trägt den `rusqlite`-Pin samt Kopplungstest. | 1, 5, 6, 9, 11 |
| R17 | Der `local-audit-event-v1`-Encoder entsteht additiv in `ea-format` mit geschlossener Aktion/Kontext-Kopplung, CDDL-Konformitätstest und Vektorfamilie; `ea-audit` behält den Dienst. | 4, 6, 9, 11, 18 |
| R18 | Die `DraftRepository`-Fläche wird vollständig im Store-Task deklariert; Entwurfssperre und Writer-Archivsperre sind zwei verschiedene Sperren. | 6, 7, 11 |
| R19 | Ein Register der verbrauchten Einsatznummern ist Erfassungsquelle und wird geführt. | 6, 11, 16, 18 |
| R20 | Die Discard-Zustandsmaschine ist ein eigener Dienst und verlangt einen frischen Re-Auth-Proof. | 7 |
| R21 | Beim Neustart hat eine vorhandene `PreparedFinalization` Vorrang vor `resume_discard`. | 7, 11, 18 |
| R22 | Snapshot-Typen kommen ausschließlich aus `ea-schema`; ein zweiter Typensatz entsteht nicht. | 8, 11, 16 |
| R23 | Die `revision`-Spalte ist monoton; der Wire-Arm von `master-data-revision-v1` ist Tag 0. | 8, 11 |
| R24 | Die Migrationskette ist 0001/0002/0003; eine registrierte Migration wird nie geändert. | 6, 7, 8 |
| R25 | Die Operator-Profil-Zeile wird nur lesend verwendet und ihr Commitment im Writer nachgerechnet. | 3, 6, 11 |
| R26 | Die Host-Anbindung zieht in die neue Crate `crates/ea-archive-fs`; `ea-archive` bleibt `std::fs`-frei und wasm32-fähig. | 3, 6, 9, 11, 12, 18 |
| R27 | Das Archivprofil wird fail-closed gegen `allowed_archive_profile_hashes` geprüft. | 9, 11 |
| R28 | Spec-Schritt 12 (Netzarchiv-Publikation) wird an vier Orten nachgetragen: Publikations-Queue, eigene `FinalizationPhase`, Detailursache `Netzarchiv wartet` in der UI, Injektionspunkt in der Fault-Matrix. | 9, 11, 16, 18 |
| R29 | Das Formatbeiwerk wird beim Anlegen eines Archivs materialisiert (eigener Task hinter dem Archiv-Task). | 9, 10, 11, 18 |
| R30 | Tests serialisieren sich selbst; `-- --test-threads=1` entfällt aus allen Stufe-2-Kommandos. | 7, 9, 11, 18 |
| R31 | Die Fault-Point-Abdeckung wird gegen die literale Punktliste geprüft, nicht gegen sich selbst. | 11, 18 |
| R32 | `recover_pending` bekommt Konsumenten in Shell und UI. | 11, 15, 16 |
| R33 | Trust-Alter und `readerTrustRefreshMs` erscheinen in Preview und UI. | 11, 15, 16 |
| R34 | `crates/ea-ui-contracts` wird als eigener Task angelegt, mit `emit-ts`-Binary und byteweisem Determinismustest gegen die eingecheckte DTO-Datei. | 11, 14, 15, 16 |
| R35 | Der Merker wird korrigiert: die Desktop-Shell gated ausschließlich den Writer, Administration bleibt Stufe 5, und ein Negativtest belegt die Abwesenheit jeder Reader-Fläche. | 15 |
| R36 | Es gibt genau einen Host-Build des Tauri-Pakets; der Paketname ist `ea-desktop`, und der Rust-Testträger wird mit `--test` adressiert. | 13, 15, 16, 18 |
| R37 | Die sechs benannten `ea*`-Tokens sind die Quelle der Wahrheit; jeder Ant-Alias wird daraus abgeleitet und nie literal gesetzt. | 15 |
| R38 | Ein Ankertest vergleicht die registrierte Tauri-Command-Menge und die Capabilities gegen eine literal notierte Sollmenge. | 16 |
| R39 | Vier fehlende Domänenkomponenten (`VerificationBadge`, `EvidenceStatus`, `FingerprintBlock`, `ChainIntegrityRail`) kommen in den Files-Block der Writer-UX. | 16 |
| R40 | Der Eingabevertrag des Incident-Bodys wird vollständig ausgeschrieben. | 16 |
| R41 | `xtask stage-gate 2` wird angelegt — mit Stufenzweig, vier additiven Berichtsfeldern, Manifest-basierter Fault-Point-Abdeckung, prozessgetriebenem Test und Frontend-Spur; `test-fault` und `test-privacy` werden **keine** Subkommandos. | 7, 9, 11, 15, 16, 17, 18 |
| R42 | AK-Teilbelege werden als zusätzliche v1.1-Ledgerzeilen geführt, ohne bestehende Zeilen zu ändern. | 2, 3, 11, 15, 16, 18 |
| R43 | Das Traceability-Ledger schreibt ausschließlich der Abnahme-Task, mit vollständiger Zeilenliste und Gate-Assertion. | 3, 18 |
| R44 | `tools/xtask/tests/stage_gate.rs` ist `Modify`, nicht `Test`. | 17, 18 |
| R45 | Die Canary-Prüfung benutzt `ea_testkit::contains_canary`; `contains_subslice` existiert nicht. | 6, 18 |
| R46 | `ExactObjectBytes` entstehen nur über die öffentliche `encode_*`-Fläche, und Adressen reisen als `&ArchivePath` statt `&str`. | 9 |
| R47 | Das Archiv-Backend bekommt einen eigenen Schreibfehlertyp `ArchiveBackendError`; `ArchivePath` ist Transportadresse, kein Dateisystempfad. | 9, 11, 18 |
| R48 | Playwright lebt vollständig unter `apps/desktop`: `tests/e2e` relativ zum Paket, `playwright.config.ts` mit `testDir`, `webServer` und abgeschaltetem Netzzugang. | 13, 16, 18 |

---
### Task 1: Rust Workspace and Toolchain Prelude (SYNTHESE.md: Task 0.5)

**Files:**
- Modify: `tools/xtask/tests/workspace.rs`
- Modify: `tools/xtask/src/main.rs`
- Modify: `Cargo.toml`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: the Stage 1 gate machinery unchanged — `verify_quick_commands()` and its character-exact unit pin (`tools/xtask/src/main.rs:25-87`, `:2378-2432`), the wasm32 positive list (`main.rs:63-85`), `WASM32_EXEMPT_CRATES` (`main.rs:101-120`), and the pinned toolchain targets (`rust-toolchain.toml:5`).
- Produces: `WORKSPACE_MEMBERS` as the one maintained member list, an exact-pin guard over `[workspace.dependencies]`, `WASM32_EXEMPT_CRATES` as an append-only slice, the shared `serde` pin, the cross-target decision, and the registration and lockfile duties that every later member-adding task of this plan repeats.

This task creates no crate and waits for none: every assertion it installs is green against today's workspace, and every later task adds its member by appending to a list instead of editing a number.

- [ ] **Step 0: Ignore the operating-system artefacts before the first directory-wide `git add`**

Extend `.gitignore` — which today holds only `.superpowers/` and `.worktrees/` (`.gitignore:1-2`) — by exactly this line:

```
.DS_Store
```

This lands here rather than in Task 13 because the commit step of this task is the last one that names every file individually: from Task 2 on, the commit steps stage whole directories (`git add crates/ea-key-provider crates/ea-crypto tools/xtask …`), and the working tree carries untracked `.DS_Store` files below `crates/`, so the first such command would check one of them in. A pattern without a slash matches at every depth, which is what `crates/.DS_Store` and `crates/ea-crypto/.DS_Store` need. The three build directories `node_modules/`, `dist/` and `target/` stay in Task 13, where they must be in place before the first `pnpm` command runs; no entry is written twice.

- [ ] **Step 1: Write the workspace bookkeeping tests**

The member set is stated three times today — as a count in `tools/xtask/tests/workspace.rs:14-18` (`assert_eq!(member_array.len(), 15, "workspace members must not be duplicated or omitted")`), as a `BTreeSet` literal in `:23-42`, and as the dependency-walk list in `:64-79`. Collapse the three into one maintained list and derive the length from it.

```rust
/// The workspace members, maintained as a set rather than as a count.
///
/// Every task that adds a member appends its path here and nowhere else: the
/// duplicate check, the comparison against `Cargo.toml` and the dependency walk
/// all read this list, so no task has to know how many members the workspace
/// has. A member added to one of the two files and forgotten in the other still
/// fails loudly.
const WORKSPACE_MEMBERS: &[&str] = &[
    "tools/xtask",
    "tests/ea-system-tests",
    "crates/ea-types",
    "crates/ea-cbor",
    "crates/ea-crypto",
    "crates/ea-format",
    "crates/ea-schema",
    "crates/ea-time",
    "crates/ea-trust",
    "crates/ea-archive",
    "crates/ea-chain",
    "crates/ea-verify",
    "crates/ea-recovery",
    "crates/ea-testkit",
    "apps/cli",
];
```

Replace `workspace.rs:14-18` and `:23-42` with the derived form, keeping the message that names the failure mode:

```rust
    let expected_members = WORKSPACE_MEMBERS.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(
        WORKSPACE_MEMBERS.len(),
        expected_members.len(),
        "WORKSPACE_MEMBERS must not list a member twice"
    );
    assert_eq!(
        member_array.len(),
        WORKSPACE_MEMBERS.len(),
        "workspace members must not be duplicated or omitted"
    );
    assert_eq!(members, expected_members);
```

Replace the second literal list in `workspace.rs:64-79` with `for &member in WORKSPACE_MEMBERS {`, leaving the per-member walk over `dependencies`, `dev-dependencies` and `build-dependencies` (`:86-101`) and the `crates/ea-types` exemption (`:105-110`) untouched.

Add the exact-pin guard. `docs/adr/0001-toolchain-and-cryptography-dependencies.md:15` promises that all version requirements in `[workspace.dependencies]` are exact, and all 22 version-bearing entries keep that promise today (`Cargo.toml:11-17`, `:30-44`), but nothing enforces it: `workspace.rs:90-101` checks presence and `workspace = true` only, `:296-312` checks one version literal, and `deny.toml:6` denies wildcards without any gate invoking cargo-deny. A later `serde = "1"` would break the ADR promise silently.

```rust
/// Pins that every shared dependency is exact.
///
/// `docs/adr/0001-toolchain-and-cryptography-dependencies.md:15` states that all
/// version requirements in `[workspace.dependencies]` are exact; `deny.toml:6`
/// denies wildcards but no gate invokes cargo-deny. An entry may omit a version
/// only when it is a path member of this workspace, so a `git` or registry entry
/// cannot slip through the hole between the two shapes.
#[test]
fn every_workspace_dependency_is_pinned_exactly() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest: Value = fs::read_to_string(root.join("Cargo.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let dependencies = manifest["workspace"]["dependencies"].as_table().unwrap();
    for (name, entry) in dependencies {
        let requirement = match entry {
            Value::String(requirement) => Some(requirement.as_str()),
            Value::Table(spec) => spec.get("version").and_then(Value::as_str),
            _ => panic!("workspace dependency {name} must be a version string or a table"),
        };
        match requirement {
            Some(requirement) => assert!(
                requirement.starts_with('='),
                "workspace dependency {name} must pin an exact version (=x.y.z), found \
                 {requirement}"
            ),
            None => assert!(
                entry
                    .as_table()
                    .is_some_and(|spec| spec.contains_key("path")),
                "workspace dependency {name} declares no version; only path members of this \
                 workspace may do that"
            ),
        }
    }
}
```

Add the `serde` assertion after the pattern of `workspace_getrandom_enables_the_wasm_js_feature` (`workspace.rs:296-312`), because the derive macro is what the desktop DTO surface inherits:

```rust
#[test]
fn workspace_serde_is_pinned_with_derive() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest: Value = fs::read_to_string(root.join("Cargo.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let serde = &manifest["workspace"]["dependencies"]["serde"];
    assert_eq!(serde["version"].as_str(), Some("=1.0.229"));
    let features = serde["features"]
        .as_array()
        .expect("serde must declare features so members inherit the derive macro");
    assert!(
        features.iter().any(|feature| feature.as_str() == Some("derive")),
        "serde must enable derive; the desktop DTO surface has no other source for it"
    );
}
```

Anchor the exception-list parser on the slice declaration, replacing `workspace.rs:194-204`. The exception list is the only side of the classification that Stage 2 may grow, so it must grow without an arity edit:

```rust
    // Ausnahmeliste: Paare aus Crate-Name und Begruendung, gelesen aus der
    // Deklaration selbst. Der Anker verlangt die Slice-Form: eine Liste mit
    // fester Arity zwingt jeden Task, der eine Ausnahme ergaenzt, zu einer
    // Zahlenaenderung, und genau die soll niemand mehr anfassen muessen.
    const EXEMPT_DECLARATION: &str = "const WASM32_EXEMPT_CRATES: &[(&str, &str)] = &[";
    let declaration_at = main_rs.find(EXEMPT_DECLARATION).expect(
        "tools/xtask/src/main.rs must declare WASM32_EXEMPT_CRATES as a slice literal so that a \
         new exception needs no arity edit",
    );
    let body_at = declaration_at + EXEMPT_DECLARATION.len();
    let body_end = body_at
        + main_rs[body_at..]
            .find("];")
            .expect("WASM32_EXEMPT_CRATES must be terminated with `];`");
    let entries = quoted_literals(&main_rs[body_at..body_end]);
    assert!(
        !entries.is_empty(),
        "WASM32_EXEMPT_CRATES must list at least one justified exception"
    );
    let mut exempt_list = BTreeSet::new();
```

The pair count, the non-empty justification and the duplicate check (`workspace.rs:205-219`), the exactly-one-classification assertions (`:226-237`) and the reverse check that no list names a non-member (`:239-245`) stay as they are. Record in the same comment block that the positive-list anchor above it is the **first quoted** `"wasm32-unknown-unknown"` and must remain the one inside `verify_quick_commands()`; `main.rs:196` and `:200` carry the same literal in the rustup message of `ensure_wasm32_target_available()`.

Extend the toolchain test with the cross-target decision, replacing `workspace.rs:278-294`:

```rust
#[test]
fn rust_toolchain_declares_wasm32_and_no_release_target() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let toolchain: Value = fs::read_to_string(root.join("rust-toolchain.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let targets = toolchain["toolchain"]["targets"]
        .as_array()
        .expect("rust-toolchain.toml must declare targets so a fresh checkout provisions wasm32");
    assert!(
        targets
            .iter()
            .any(|target| target.as_str() == Some("wasm32-unknown-unknown")),
        "wasm32-unknown-unknown must be provisioned by the pinned toolchain"
    );
    for release_target in [
        "x86_64-pc-windows-msvc",
        "x86_64-unknown-linux-gnu",
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
    ] {
        assert!(
            !targets
                .iter()
                .any(|target| target.as_str() == Some(release_target)),
            "{release_target} carries the signed min/max release proof of Stage 7. This stage \
             proves buildability for the host target only, so the pinned toolchain must not \
             provision it and no task may run a cross-target check against it."
        );
    }
}
```

- [ ] **Step 2: Run the bookkeeping tests and watch them fail**

Run: `cargo test --locked -p xtask --test workspace`

Expected: FAIL because `tools/xtask/src/main.rs:102` still declares `const WASM32_EXEMPT_CRATES: [(&str, &str); 2] = [`, which the slice anchor rejects, and because `[workspace.dependencies]` carries no `serde` entry at all (`Cargo.toml:10-44`).

- [ ] **Step 3: Make the wasm32 exception list append-only**

Change the declaration at `main.rs:101-120` to a slice and leave both existing entries and their justifications byte-identical:

```rust
/// A slice rather than a fixed-arity array: a later task appends an entry
/// without touching a count, and `tools/xtask/tests/workspace.rs` anchors on
/// exactly this declaration.
#[allow(dead_code)]
const WASM32_EXEMPT_CRATES: &[(&str, &str)] = &[
    (
        "ea-recovery",
        "carries the filesystem-backed archive source, plaintext handling and \
         restrictive target permissions on top of `std::fs`, so it is not shared \
         browser code: `web-reader-design.md` §9 makes only the verification \
         pipeline shared Rust, and that pipeline ends at `ea-verify`, which stays \
         on the positive list. `apps/cli` depends on this crate, never the other \
         way round.",
    ),
    (
        "ea-testkit",
        "owns the deterministic vector file and manifest emission over `std::fs` \
         and is therefore host-side generator code, not shared browser code: \
         `web-reader-design.md` §9 makes only the verification pipeline shared \
         Rust, and that pipeline ends at `ea-verify`, which stays on the positive \
         list. Test targets depend on this crate, never the other way round.",
    ),
];
```

Replace the invitation in `main.rs:54-56`, which currently reads „Jede neue Bibliotheks-Crate MUSS hier oder in WASM32_EXEMPT_CRATES stehen", with the decision:

```rust
    // Diese Positivliste ist zeichengleich an die Kommandozeile des
    // abgeschlossenen Stufe-1-Plans gebunden (tools/xtask/tests/workspace.rs:247-275)
    // und wird nicht erweitert. Jede neue Crate unter crates/ gehoert mit
    // nicht-leerer Begruendung in WASM32_EXEMPT_CRATES; workspace.rs erzwingt
    // genau eine Zuordnung je Mitglied unter crates/.
```

Every Stage 2 crate reaches into the host operating system past the shared verification pipeline, which ends at `ea-verify` (`main.rs:89-100`), so the exception list is its only correct home. The positive list is closed for a second reason that no later task may re-litigate: `workspace.rs:247-275` compares it character-for-character against the gate command printed in the completed Stage 1 plan, and `docs/traceability/stage-1-gate.md:60-65` repeats the same ten crate names, so putting one Stage 2 crate on the positive list would mean editing a gated historical document. `apps/desktop/src-tauri` receives no wasm32 classification at all: the classification test collects members under `crates/` only (`workspace.rs:152-158`) and rejects any classified name that is not such a member (`:239-245`).

- [ ] **Step 4: Pin the shared `serde` dependency**

Insert into `[workspace.dependencies]` in alphabetical order, directly above `serde_json` (`Cargo.toml:38`), following the exact-pin form of `Cargo.toml:11-12`:

```toml
serde = { version = "=1.0.229", features = ["derive"] }
```

This is the only foreign dependency this task pins. Predeclaring a shared dependency before a member inherits it is the established pattern of the workspace (`docs/adr/0001-toolchain-and-cryptography-dependencies.md:15-20`: a dependency is inherited by a member only when that member has real code that uses it), and it leaves `Cargo.lock` untouched here because `serde 1.0.229` and `serde_derive 1.0.229` are already resolved transitively (`Cargo.lock:1986-1987`, `:2016-2017`) — which is why this task neither modifies nor commits the lockfile. The path entries of the new crates are not pinned ahead of time: a `[workspace]members` entry pointing at a directory that does not exist yet breaks every cargo command, so each crate arrives together with its own path entry. The local-database dependency arrives with the ADR that justifies it, `tauri` and `tauri-build` arrive with the desktop prelude, and neither `tokio` nor `async-trait` ever enters this table: the Stage 2 crates are synchronous exactly like all of Stage 1 (`grep "async fn"` over `crates/`, `apps/` and `tools/` has no hit today), async exists only in `apps/desktop/src-tauri`, where each `#[tauri::command]` runs the synchronous core operation through `tauri::async_runtime::spawn_blocking`, and that `tokio` appears transitively through `tauri` in `Cargo.lock` is expected rather than an entry here.

- [ ] **Step 5: Record the lockfile prelude and the registration duties**

Put the rule where an implementer meets the error, above the lockfile assertion in `workspace.rs:112-119`:

```rust
    // Lockfile-Vorschritt: --locked beweist, dass Cargo.lock zum Manifest passt.
    // Ein neues Mitglied oder eine neue Fremdabhaengigkeit schreibt Cargo.lock
    // neu, deshalb laeuft in dem Task, der sie eintraegt, GENAU EIN Kommando
    // ohne --locked: `cargo metadata --format-version 1`. Alle weiteren
    // Kommandos dieses Tasks tragen wieder --locked.
    assert!(
        Command::new("cargo")
            .args(["metadata", "--locked", "--no-deps"])
            .current_dir(root)
            .status()
            .unwrap()
            .success()
    );
```

Every later task of this plan that adds a workspace member carries all five duties below, and none of them may be left out:

1. `Files:` lists `- Modify: Cargo.toml`, `- Modify: Cargo.lock`, `- Modify: tools/xtask/tests/workspace.rs` and, **for a member under `crates/`**, `- Modify: tools/xtask/src/main.rs`.
2. Its first step writes the manifest entries — the member under `[workspace]members`, the crate's own path entry and any new foreign dependency with an exact version (`=x.y.z`) after the pattern of `Cargo.toml:11-12` — and creates the lockfile entries once with `Run: cargo metadata --format-version 1 > /dev/null` (without `--locked`), `Expected: PASS; Cargo.lock now contains the new packages`. Every further cargo command of that task carries `--locked`.
3. It appends the member path to `WORKSPACE_MEMBERS` in `tools/xtask/tests/workspace.rs`, so that the member count, the set comparison and the dependency walk move together.
4. For a member under `crates/` it appends one `(name, justification)` pair with a non-empty justification to `WASM32_EXEMPT_CRATES` in `tools/xtask/src/main.rs` and never touches the positive list. `apps/desktop/src-tauri` gets no wasm32 entry, but every one of its `tauri` dependencies must appear in the root `[workspace.dependencies]` table and be inherited with `workspace = true`, because the walk in `workspace.rs:86-101` covers `dependencies`, `dev-dependencies` and `build-dependencies` alike.
5. Its commit step stages `tools/xtask` next to `Cargo.toml` and `Cargo.lock`.

The four release triples `x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin` and `x86_64-apple-darwin` stay unprovisioned. No task of this plan runs `cargo check --target` against them — with only `wasm32-unknown-unknown` in `rust-toolchain.toml:5`, such a command reports `can't find crate for 'core'` rather than a portability result, and a run that happens to pass on one machine is a statement about that machine. Buildability is proven for the host target, the four triples are carried as an open Stage 7 ledger row by the acceptance task, and `ensure_wasm32_target_available()` (`main.rs:186-205`) stays limited to the one gate target it serves.

- [ ] **Step 6: Prove the exact-pin guard bites**

Temporarily drop the `=` from the entry just added, so that `Cargo.toml` reads `serde = { version = "1.0.229", features = ["derive"] }`.

Run: `cargo test --locked -p xtask --test workspace`

Expected: FAIL because `every_workspace_dependency_is_pinned_exactly` reports `workspace dependency serde must pin an exact version (=x.y.z), found 1.0.229`. A guard that has never failed is not evidence.

Restore `=1.0.229` and run again.

Run: `cargo test --locked -p xtask --test workspace`

Expected: PASS.

- [ ] **Step 7: Run the workspace and toolchain gate green**

Run: `cargo test --locked -p xtask --test workspace && pnpm verify:quick`

Expected: PASS; the member set is maintained in one place, every shared dependency is exactly pinned, the wasm32 classification grows by appending, and `verify_quick_commands()` plus its character-exact unit pin (`main.rs:2378-2432`) are unchanged.

- [ ] **Step 8: Commit the workspace and toolchain prelude**

```bash
git add .gitignore Cargo.toml tools/xtask/src/main.rs tools/xtask/tests/workspace.rs
git commit -m "feat(xtask): gate workspace growth, exact pins, and toolchain targets"
```

### Task 2: Native Key-Provider Contract and Writer Role Guard (SYNTHESE.md: Task 1)

**Files:**
- Create: `crates/ea-key-provider/Cargo.toml`
- Create: `crates/ea-key-provider/src/lib.rs`
- Create: `crates/ea-key-provider/src/contract.rs`
- Create: `crates/ea-key-provider/src/in_memory.rs`
- Create: `crates/ea-key-provider/src/profile.rs`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `tools/xtask/src/main.rs`
- Modify: `tools/xtask/tests/workspace.rs`
- Modify: `crates/ea-crypto/src/cose.rs`
- Modify: `crates/ea-crypto/src/lib.rs`
- Test: `crates/ea-key-provider/tests/provider_contract.rs`
- Test: `crates/ea-key-provider/tests/writer_role_guard.rs`

**Interfaces:**
- Consumes: Stage 1 identifiers and hashes from `ea-types`; `SecretBytes<N>` and `SecretVec` (`crates/ea-crypto/src/secret.rs:29-30`, `:63-66`, `:143`); the public COSE encoding surface `ContentType` (`crates/ea-crypto/src/cose.rs:25-37`), `ProtectedHeader::normal` (`crates/ea-crypto/src/cose.rs:117-125`) and `ProtectedHeader::sig_structure_bytes` (`crates/ea-crypto/src/cose.rs:181`); `ea_format::KeyProtectionProfileV1` (`crates/ea-format/src/etb.rs:82-90`, re-export `crates/ea-format/src/lib.rs:28`) and the profile a device certificate claims (`crates/ea-format/src/etb.rs:117`).
- Produces: the synchronous `KeyProvider` trait, opaque `KeyHandle`, `KeyError`, `CoseSign1Bytes`, the two disjoint purpose enums `SecretPurpose` and `KeyPurpose`, `WriterKeyProfile::{validate, validate_local}`, `require_claimed_protection_profile`, and the deterministic `InMemoryKeyProvider` behind the non-default Cargo feature `test-support`. Additively from `ea-crypto`: `CertificateCapability` plus its string parser.

`SecretPurpose` names only locally wrapped secrets of this device (`WriterSigningKey`, `OperatorInstanceKey`, `DraftDek`, `LocalDatabaseKey`). `KeyPurpose` names purposes of foreign key material that is **never** privately present on a Writer device (`ReaderKem`, `RecoveryKem`, `HistoricalGrantAuthority`, `KeyApprover`); `WriterKeyProfile::validate` rejects every `KeyPurpose` as not privately holdable. The two enums are disjoint and not convertible into one another. `WriterKeyProfile::validate` is therefore the negative half of the guard and can only ever reject — that is the point, it is the compiled form of the product invariant; `WriterKeyProfile::validate_local` is the positive half and admits exactly the four local purposes.

- [ ] **Step 0: Register the workspace member and create the lockfile once**

Create `crates/ea-key-provider/Cargo.toml` and an empty `crates/ea-key-provider/src/lib.rs` so that the member path resolves. Modify `Cargo.toml`: add `crates/ea-key-provider` under `[workspace]members` and add the path entry `ea-key-provider = { path = "crates/ea-key-provider" }` under `[workspace.dependencies]` — a path entry carries no version literal, following the twelve existing `ea-*` entries (`Cargo.toml:18-29`). The crate manifest declares `[features] test-support = []`, carries `toml` under `[dev-dependencies]` for the feature-default negative test, and references every workspace dependency with `workspace = true`, which `tools/xtask/tests/workspace.rs:90-101` enforces for dependencies, dev-dependencies and build-dependencies alike (`:86`).

Modify `tools/xtask/src/main.rs`: append one `(name, justification)` pair for `ea-key-provider` with a non-empty justification to the `WASM32_EXEMPT_CRATES` slice (`tools/xtask/src/main.rs:102`, a slice since Task 1, so no arity edit exists to make), following the `ea-recovery` precedent (`tools/xtask/src/main.rs:103-111`). **Never** the wasm32 positive list: the crate reaches past `ea-verify` into the operating-system keystore and is therefore not shared browser code, and the positive list is textually frozen by the closed Stage 1 gate (`docs/traceability/stage-1-gate.md:60-65`). Modify `tools/xtask/tests/workspace.rs`: append the member path to `WORKSPACE_MEMBERS` (Task 1) and nowhere else — the length assertion, the set comparison and the dependency walk all derive from that one list.

Run: `cargo metadata --format-version 1 > /dev/null` (without `--locked`)

Expected: PASS; `Cargo.lock` now contains the new package. Only after this step do the `--locked` commands of this task run.

- [ ] **Step 1: Write provider and role-separation tests**

`crates/ea-key-provider/tests/provider_contract.rs`:

```rust
#[test]
fn deleted_secret_cannot_be_unwrapped_or_restored() {
    let provider = InMemoryKeyProvider::new_for_test([7; 32]);
    let handle = provider
        .wrap_secret(SecretPurpose::DraftDek, SecretBytes::<32>::new([3; 32]))
        .unwrap();
    provider.delete(&handle).unwrap();
    assert!(!provider.contains(&handle).unwrap());
    assert_eq!(
        provider.unwrap_secret(&handle).unwrap_err().code(),
        "EA-KEY-NOT-FOUND"
    );
}

#[test]
fn a_handle_never_serves_a_second_purpose() {
    let provider = InMemoryKeyProvider::new_for_test([11; 32]);
    let handle = provider
        .wrap_secret(SecretPurpose::DraftDek, SecretBytes::<32>::new([4; 32]))
        .unwrap();
    assert_eq!(
        provider.unwrap_database_key(&handle).unwrap_err().code(),
        "EA-KEY-PURPOSE-MISMATCH"
    );
}
```

`crates/ea-key-provider/tests/writer_role_guard.rs`:

```rust
#[test]
fn writer_profile_rejects_forbidden_private_key_purposes() {
    for purpose in [
        KeyPurpose::ReaderKem,
        KeyPurpose::RecoveryKem,
        KeyPurpose::HistoricalGrantAuthority,
        KeyPurpose::KeyApprover,
    ] {
        assert!(WriterKeyProfile::validate(&[purpose]).is_err());
    }
}

#[test]
fn writer_profile_admits_only_the_four_local_purposes() {
    assert!(
        WriterKeyProfile::validate_local(&[
            SecretPurpose::WriterSigningKey,
            SecretPurpose::OperatorInstanceKey,
            SecretPurpose::DraftDek,
            SecretPurpose::LocalDatabaseKey,
        ])
        .is_ok()
    );
}

#[test]
fn a_claimed_hardware_profile_never_falls_back_silently() {
    let provider = InMemoryKeyProvider::new_for_test([9; 32]);
    let handle = provider
        .generate(
            SecretPurpose::OperatorInstanceKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    let reached = provider.reached_protection_profile(&handle).unwrap();
    assert_eq!(reached, KeyProtectionProfileV1::OsWrapped);
    assert_eq!(
        require_claimed_protection_profile(
            reached,
            KeyProtectionProfileV1::HardwareNonExportable,
        )
        .unwrap_err()
        .code(),
        "EA-KEY-PROTECTION-PROFILE-MISMATCH"
    );
}

#[test]
fn the_default_feature_set_omits_the_in_memory_provider() {
    let manifest: toml::Value = toml::from_str(include_str!("../Cargo.toml")).unwrap();
    let default = manifest["features"].get("default");
    assert!(
        default.is_none()
            || !default
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .any(|feature| feature.as_str() == Some("test-support")),
        "test-support must never be a default feature"
    );
}
```

- [ ] **Step 2: Run tests and verify the provider contract is absent**

Run: `cargo test --locked -p ea-key-provider --features test-support`

Expected: FAIL because the provider trait, the handle, the purpose enums and the in-memory provider do not exist yet.

- [ ] **Step 3: Implement capability-scoped opaque handles**

Declare every module in `crates/ea-key-provider/src/lib.rs` — a Rust module without a `mod` line is not compiled, following `crates/ea-format/src/lib.rs:3-12` — and gate `in_memory` on `#[cfg(feature = "test-support")]`.

```rust
pub struct CoseSign1Bytes(Vec<u8>);

pub trait KeyProvider: Send + Sync {
    fn generate(&self, purpose: SecretPurpose, protection: KeyProtectionProfileV1)
        -> Result<KeyHandle, KeyError>;
    fn sign(&self, handle: &KeyHandle, content_type: ContentType,
            certificate_hash: CertificateHash, payload: &[u8])
        -> Result<CoseSign1Bytes, KeyError>;
    fn wrap_secret(&self, purpose: SecretPurpose, secret: SecretBytes<32>)
        -> Result<KeyHandle, KeyError>;
    fn unwrap_secret(&self, handle: &KeyHandle) -> Result<SecretBytes<32>, KeyError>;
    fn unwrap_database_key(&self, handle: &KeyHandle) -> Result<SecretVec, KeyError>;
    fn delete(&self, handle: &KeyHandle) -> Result<(), KeyError>;
    fn contains(&self, handle: &KeyHandle) -> Result<bool, KeyError>;
    fn reached_protection_profile(&self, handle: &KeyHandle)
        -> Result<KeyProtectionProfileV1, KeyError>;
}
```

Every method is synchronous, exactly as all of Stage 1 is, so `Arc<dyn KeyProvider>` is trivially constructible; async exists only in `apps/desktop/src-tauri`, where each `#[tauri::command]` handler runs the synchronous core operation through `tauri::async_runtime::spawn_blocking`.

The signer port takes content-typed payload bytes, not a digest, because the six non-digest content types are checked against their full CBOR core (`crates/ea-crypto/src/cose.rs:60-70`, `:3415`) and the Writer has to sign `local-audit-event-v1` CBOR through this port. It composes the exact signature bytes over the public `ProtectedHeader::normal` (`crates/ea-crypto/src/cose.rs:117-125`) and `ProtectedHeader::sig_structure_bytes` (`crates/ea-crypto/src/cose.rs:181`); it does not delegate to `CoseSigner`, whose `sign_normal` is private (`crates/ea-crypto/src/cose.rs:324`) and whose only constructor `from_secret` (`crates/ea-crypto/src/cose.rs:320`) requires exporting the private key — which the in-memory test provider may do and no native provider ever does. `CoseSign1Bytes` is a newtype over `Vec<u8>` **in this crate**; no signer or KEM port is introduced into `ea-crypto`, and the change is byte-neutral. The Writer provider exposes exactly Writer signing, `draftDEK` wrapping and unwrapping, the local database key and operator instance signing — no HPKE decapsulation port, because a KEM recipient purpose on a Writer would contradict the product invariant that no private Reader or Recovery key exists there; HPKE decapsulation arises in Stages 4 and 5 against the existing `crates/ea-crypto/src/hpke.rs:188-192`.

Make `KeyHandle` opaque and bind it to provider, application, account instance, purpose and non-roaming policy; reject a purpose mismatch before the provider is invoked. Keystore entries for `draftDEK`s and operator instance keys are non-roaming, non-cloud-synchronising and excluded from ordinary application and system backup (`design.md:1491`).

Use `ea_format::KeyProtectionProfileV1` unchanged (`crates/ea-format/src/etb.rs:82-90`) and define **no** second protection-profile enum; Stage 2 productively reaches only `OsWrapped` and `HardwareNonExportable`, which is a deliberate, spec-covered subset, and variants 2 to 4 arrive with the Stage 5 plan. `require_claimed_protection_profile` compares the profile actually reached against the profile the device certificate claims (`crates/ea-format/src/etb.rs:117`) **fail-closed**: only equality passes, `HardwareNonExportable` is admissible only with an explicitly supported, suite-encoded provider, and every deviation aborts. There is no silent fallback to unprotected key files (`design.md:1489`).

Export `CertificateCapability` (`crates/ea-crypto/src/cose.rs:1542-1551`, today private) plus a string parser additively from `crates/ea-crypto/src/lib.rs:15-22`, and decide the purpose match against parsed capabilities rather than against the raw strings a device certificate carries (`crates/ea-format/src/etb.rs:116`, decoded without an allowlist at `crates/ea-format/src/etb.rs:1376`). The capability allowlist is not duplicated in Stage 2.

Add a `compile_fail` doctest to `crates/ea-key-provider/src/lib.rs`, following the pattern in `crates/ea-crypto/src/secret.rs:13-19`, that proves the public API exports no private key material — for example that `KeyHandle` has no accessor yielding bytes and that `CoseSign1Bytes` cannot be turned back into a signing key. This doctest is the only proof for that promise: `verify-quick` runs Clippy with `--all-features` (`tools/xtask/src/main.rs:27-39`), so `--no-default-features` alone does not carry it, and the workspace test command uses `--all-targets` (`tools/xtask/src/main.rs:40-43`), which excludes doctests.

- [ ] **Step 4: Run contract, doctest and compile-feature checks**

Run: `cargo test --locked -p ea-key-provider --features test-support && cargo test --locked -p ea-key-provider --features test-support --doc && cargo check --locked -p ea-key-provider --no-default-features && cargo test --locked -p ea-crypto && cargo test --locked -p xtask --test workspace`

Expected: PASS; the production build does not compile the in-memory provider, the `compile_fail` doctest holds, and the workspace member count, member set and wasm32 classification match the state after this task.

- [ ] **Step 5: Commit the provider boundary**

```bash
git add crates/ea-key-provider crates/ea-crypto tools/xtask Cargo.toml Cargo.lock
git commit -m "feat(writer): define native key provider boundary"
```

### Task 3: Windows, macOS, and Ubuntu Writer Providers and Re-authentication Ports (SYNTHESE.md: Task 2)

**Files:**
- Create: `crates/ea-key-provider/src/windows.rs`
- Create: `crates/ea-key-provider/src/macos.rs`
- Create: `crates/ea-key-provider/src/linux.rs`
- Create: `crates/ea-key-provider/src/posture.rs`
- Create: `crates/ea-operator/Cargo.toml`
- Create: `crates/ea-operator/src/lib.rs`
- Create: `crates/ea-operator/src/account.rs`
- Create: `crates/ea-operator/src/session.rs`
- Create: `crates/ea-operator/src/windows.rs`
- Create: `crates/ea-operator/src/macos.rs`
- Create: `crates/ea-operator/src/linux.rs`
- Modify: `crates/ea-key-provider/src/lib.rs`
- Modify: `crates/ea-key-provider/Cargo.toml`
- Modify: `tests/ea-system-tests/Cargo.toml`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `tools/xtask/src/main.rs`
- Modify: `tools/xtask/tests/workspace.rs`
- Test: `crates/ea-operator/tests/session_contract.rs`
- Test: `crates/ea-key-provider/tests/device_posture.rs`
- Test: `tests/ea-system-tests/tests/cross_platform_key_provider_smoke.rs`

**Interfaces:**
- Consumes: `KeyProvider` from Task 2; a verified `AuthorizedTrustCoreV1<OperatorBindingFieldsV1>` (`crates/ea-format/src/trust_view.rs:16`, instantiated at `crates/ea-format/src/trust_view.rs:51`, fields at `crates/ea-format/src/etb.rs:124-134`), reachable as active binding fields through `SelectedRegistryHead::active_operator_binding_fields` (`crates/ea-trust/src/registry.rs:154-160`); the `PreexistingEffectiveNow` that `SelectedRegistryHead::preexisting_effective_now()` yields (`crates/ea-trust/src/registry.rs:32-40`, `:165`), whose wire field type is `ea_types::UnixMillis` (`crates/ea-types/src/ids.rs:167`); the three OS-account binding-hash functions of `ea-crypto` (`crates/ea-crypto/src/os_account.rs:207`, `:223`, `:239`, re-exported at `crates/ea-crypto/src/lib.rs:36-38`).
- Produces: closed `ReauthPurpose`, `OsAccountProvider`, `OperatorAuthenticator::reauthenticate`, `OperatorSessionProof` with a five-minute maximum inactivity default and invalidation on a native lock/session event, `DevicePostureProvider`, `DevicePostureReport` with the four named checks, `PostureCheck::{Pass,Fail,Unknown}` each carrying an `evidence_code`, `PostureRequirement`, `DevicePostureReport::is_production_ready`, and `DevicePostureReport::go_live_follow_up`.

Stage 2 consumes operator identity; it does not issue it. The Root-signed device and OS-account binding, the salted operator profile and the profile commitment are issued by Stage 5 Task 3 (`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-5-administration-recovery.md:194`, `:205`, `:235`), and AK-53 stays a Stage 5 row (`docs/traceability/v0.1-requirements.csv:54`). This task therefore has **no** provisioning, writing or editing API for bindings or profiles; it verifies against a binding that already exists, and everything it needs for that is a fixture: the frozen operator snapshot in `vectors/format/payload-v1/incident.hex` and the binding builders `crates/ea-testkit/src/lib.rs:2687-2696` and `crates/ea-trust/tests/support/mod.rs:1077-1086`. The encrypted `operator_profile` row, the read-only `OperatorProfileRepository::load` and the recomputation of `operatorProfileCommitment` belong to Task 6 and Task 11 of this plan and must not be pulled forward.

- [ ] **Step 0: Register the workspace member and create the lockfile once**

Create `crates/ea-operator/Cargo.toml` and an empty `crates/ea-operator/src/lib.rs`. Modify `Cargo.toml`: add `crates/ea-operator` under `[workspace]members` and the path entry `ea-operator = { path = "crates/ea-operator" }` under `[workspace.dependencies]`, without a version literal, following `Cargo.toml:18-29`. Modify `tools/xtask/src/main.rs`: append one `(name, justification)` pair for `ea-operator` with a non-empty justification to the `WASM32_EXEMPT_CRATES` slice (`tools/xtask/src/main.rs:102`, a slice since Task 1, so no arity edit exists to make) — it reads native account, presence and posture signals from the host operating system and is therefore not shared browser code; never the wasm32 positive list. Modify `tools/xtask/tests/workspace.rs`: append the member path to `WORKSPACE_MEMBERS` (Task 1) and nowhere else — the length assertion, the set comparison and the dependency walk all derive from that one list. Modify `tests/ea-system-tests/Cargo.toml`: add `ea-key-provider` with `features = ["test-support"]` and `ea-operator` to `[dev-dependencies]`, each with `workspace = true`, so that the cross-platform smoke test compiles at all — the manifest knows no Stage 2 crate today (`tests/ea-system-tests/Cargo.toml:15-43`).

Run: `cargo metadata --format-version 1 > /dev/null` (without `--locked`)

Expected: PASS; `Cargo.lock` now contains the new package. Only after this step do the `--locked` commands of this task run.

- [ ] **Step 1: Write account-binding, lock-event and posture contract tests**

`crates/ea-operator/tests/session_contract.rs`:

```rust
#[test]
fn finalization_requires_matching_account_instance_key_and_fresh_presence() {
    let head = fixtures::selected_registry_head();
    let auth = FakeAuthenticator::new(fixtures::binding(&head));
    assert_eq!(
        auth.reauthenticate(fixtures::wrong_account(), ReauthPurpose::Finalize)
            .unwrap_err()
            .code(),
        "EA-OPERATOR-ACCOUNT-MISMATCH"
    );
    assert_eq!(
        auth.reauthenticate(fixtures::missing_instance_key(), ReauthPurpose::Finalize)
            .unwrap_err()
            .code(),
        "EA-OPERATOR-INSTANCE-KEY-MISSING"
    );
    let proof = auth
        .reauthenticate(fixtures::valid_account(), ReauthPurpose::Finalize)
        .unwrap();
    assert!(proof.is_valid_for(
        ReauthPurpose::Finalize,
        head.preexisting_effective_now()
    ));
}

#[test]
fn a_proof_authorizes_only_its_own_purpose() {
    let head = fixtures::selected_registry_head();
    let auth = FakeAuthenticator::new(fixtures::binding(&head));
    let proof = auth
        .reauthenticate(fixtures::valid_account(), ReauthPurpose::Finalize)
        .unwrap();
    assert!(!proof.is_valid_for(
        ReauthPurpose::DiscardDraft,
        head.preexisting_effective_now()
    ));
}

#[test]
fn an_os_lock_event_invalidates_the_proof() {
    let head = fixtures::selected_registry_head();
    let auth = FakeAuthenticator::new(fixtures::binding(&head));
    let proof = auth
        .reauthenticate(fixtures::valid_account(), ReauthPurpose::Finalize)
        .unwrap();
    let proof = proof.invalidate_on_lock();
    assert!(!proof.is_valid_for(
        ReauthPurpose::Finalize,
        head.preexisting_effective_now()
    ));
}
```

`crates/ea-key-provider/tests/device_posture.rs`:

```rust
#[test]
fn an_unreportable_posture_requirement_is_never_claimed_as_passed() {
    let provider = DevicePostureProviderFake::unreportable();
    let report = provider.report().unwrap();
    assert_eq!(
        report.full_disk_encryption,
        PostureCheck::Unknown {
            evidence_code: "EA-POSTURE-FDE-UNREPORTABLE"
        }
    );
    assert!(!report.is_production_ready());
    assert!(
        report
            .go_live_follow_up()
            .contains(&PostureRequirement::FullDiskEncryption)
    );
}

#[test]
fn a_failed_posture_check_blocks_a_production_role_session() {
    let provider = DevicePostureProviderFake::failing_screen_lock();
    let report = provider.report().unwrap();
    assert!(!report.is_production_ready());
    assert!(report.go_live_follow_up().is_empty());
}
```

Write `tests/ea-system-tests/tests/cross_platform_key_provider_smoke.rs` with at least one assertion about the provider resolved for the current platform — that the resolved provider reports its own platform row of the support matrix and that `reached_protection_profile` returns a variant of `KeyProtectionProfileV1` rather than a Stage 2 enum of its own.

- [ ] **Step 2: Run tests and verify native adapters are missing**

Run: `cargo test --locked -p ea-operator --test session_contract ; cargo test --locked -p ea-key-provider --features test-support --test device_posture`

Expected: FAIL because account binding, re-authentication, lock invalidation and posture reporting are not implemented. The two commands are separated by `;` so that the second one still runs after the expected failure of the first and both gaps are evidenced.

- [ ] **Step 3: Implement OS-specific account and presence adapters**

Do **not** recompute the OS-account binding hash and do **not** introduce a second domain constant. Stage 1 already owns the domain string, the closed canonical union and the deterministic context (`crates/ea-crypto/src/os_account.rs:10`, context assembly `:257-268`), and it exposes exactly three entry points, which this task calls:

```rust
ea_crypto::windows_os_account_binding_hash(
    organization_id, device_id, sid, identifier_authority, subauthorities)
ea_crypto::macos_os_account_binding_hash(
    organization_id, device_id, guid_values, unique_id_values, actual_uid)
ea_crypto::linux_os_account_binding_hash(
    organization_id, device_id, machine_id_file, uid)
```

`CanonicalOsAccountId` and its `to_deterministic_cbor` are private, and the `compile_fail` doctest at `crates/ea-crypto/src/os_account.rs:195-206` pins that; `ea-operator` can obtain only the resulting `Hash32`. The adapters' whole job is therefore to harvest the **raw** platform inputs those signatures demand and hand them across: the validated binary `TokenUser` SID together with identifier authority and subauthorities on Windows, the sixteen decoded network-byte-order octets of the Open Directory GUID plus the numeric UID on macOS, and the `machine-id` file bytes plus the numeric UID on Ubuntu. Platform strings, names, self-chosen separators, textual UIDs and normalised runtime values are not admissible input (`design.md:233`), and the `ea-crypto` signatures enforce that.

Compare the resulting hash against `os_account_binding_hash` of the bound operator binding (`crates/ea-format/src/etb.rs:130`), and the presence of the operator instance key against `operator_instance_key_thumbprint` (`crates/ea-format/src/etb.rs:131`).

Use Windows SID with CNG/DPAPI and Windows Hello/Credential UI; the macOS directory identifier plus UID with Keychain and Secure Enclave where supported and LocalAuthentication; Ubuntu machine ID plus UID with PAM/Polkit and a PAM-unlocked Secret Service collection carrying a random account-instance identifier. Operator instance keys are app-installation-bound, non-roaming, excluded from ordinary backup, and challenged with a fresh domain-separated signature at login and at re-authentication (`design.md:235`). That challenge proof never enters archive bytes and never leaves the device, so it needs no frozen encoding and gets none: nonce, purpose and the thumbprint check live inside the opaque `OperatorSessionProof`. Explicitly excluded are a new `ContentType` variant — `crates/ea-crypto/src/cose.rs:25-37` and the eleven media strings it accepts (`crates/ea-crypto/src/cose.rs:41-57`, `:80-95`) are frozen Stage 1 surface — a new domain constant, and any reuse of `challenge-response-core-v1`, which is the server-issued Sync challenge and carries a `server-certificate-hash` (`schemas/protocol/v1/signed-protocol.cddl:5-9`, bound to `SignerRole::ServerReceipt` at `crates/ea-crypto/src/cose.rs:1163-1180`). Production code stores no OS password and never accepts account identity from the UI.

```rust
pub enum ReauthPurpose {
    Finalize,
    DiscardDraft,
    RegistryStaleFinalize,
    PlaintextExport,
    AdminRootCeremony,
    RecoveryTest,
    HistoricalRegrant,
    Destruction,
    ClockSkewRelease,
    ArchiveProfileMigration,
}
```

Bind the purpose, organization, device, operator binding, random challenge, issued time and expiry into the opaque `OperatorSessionProof`; a proof is one-purpose and cannot authorize a different action. Validity is evaluated against the `PreexistingEffectiveNow` that the selected Registry head yields (`crates/ea-trust/src/registry.rs:165`), never against a free time value — Stage 1 forbids assembling one (`crates/ea-trust/src/lib.rs:50-54`), and a self-built substitute would bypass the time-status evaluation that carries the sequence lease and head selection in Task 11. Beyond the five-minute inactivity default, a native lock or session event of each platform invalidates the proof (`design.md:256`); the platform event is wired into the shell in Tasks 13 and 15, and Task 16 treats the return from a lock as a re-authentication obligation. All methods are synchronous.

Implement `DevicePostureReport` with separate `PostureCheck::{Pass { evidence_code }, Fail { evidence_code }, Unknown { evidence_code }}` values for full-disk encryption, locked and non-shared account, automatic screen lock, and supported OS patch level. Each native adapter uses only documented OS signals that are reliable on its exact support-matrix row. A reported `Fail` blocks production-role session creation; `Unknown` is shown as unresolved and creates a mandatory Go-live evidence row that Task 18 enters into `docs/traceability/v0.1-requirements.csv`, never an automatic pass. Do not collect recovery keys, usernames, installed-software inventories or other posture data.

- [ ] **Step 4: Run host contract tests and the cross-platform smoke test**

Run:

```bash
cargo test --locked -p ea-operator && \
cargo test --locked -p ea-key-provider --features test-support --test device_posture && \
cargo test --locked -p ea-system-tests --test cross_platform_key_provider_smoke && \
cargo test --locked -p xtask --test workspace
```

Expected: PASS. Cross-target compile checks and native smoke runs for x86_64-pc-windows-msvc, x86_64-unknown-linux-gnu, aarch64-apple-darwin and x86_64-apple-darwin are not asserted locally; Task 18 records them as an open Stage 7 ledger row. `rust-toolchain.toml:3-5` provisions only `wasm32-unknown-unknown`, and that toolchain contract is pinned by `tools/xtask/tests/workspace.rs:290-321`; Stage 2 evidences buildability for the host target only.

- [ ] **Step 5: Commit native provider adapters**

```bash
git add crates/ea-key-provider crates/ea-operator tests/ea-system-tests Cargo.toml Cargo.lock tools/xtask
git commit -m "feat(writer): bind keys and sessions to native accounts"
```

### Task 4: local-audit-event-v1 Wire Encoder in ea-format (SYNTHESE.md: Task 2.5)

**Files:**
- Modify: `crates/ea-format/src/local_audit.rs`
- Modify: `crates/ea-format/src/lib.rs`
- Modify: `crates/ea-testkit/src/lib.rs`
- Modify: `tools/xtask/Cargo.toml`
- Modify: `tools/xtask/tests/spec_completeness.rs`
- Modify: `tests/ea-system-tests/tests/conformance_golden_vectors.rs`
- Modify: `Cargo.lock`
- Create: `vectors/local-audit/v1/manifest.json`
- Create: `vectors/local-audit/v1/event/` — the frozen `.bin` files of this family
- Test: `crates/ea-format/tests/local_audit_encoder.rs`

**Interfaces:**
- Consumes: the frozen grammar `schemas/reports/v1/local-audit.cddl` — action range `:3`, outcome range `:4`, the eight typed context payloads `:6-46`, the degenerate generic context `:47`, the nine tagged context arms `:47-55`, the twelve closed action/context branches `:63-75`, the twelve core positions `:77-85` and the outer pair `:86`; the decode-side types already in the crate, `LocalAuditOutcomeV1` (`crates/ea-format/src/local_audit.rs:26-32`), `ClockReleaseContextV1` (`:57-68`), `IndependentTimeReferenceV1` (`:34-38`) and `IndependentTimeKindV1`/`ClockReleaseJustificationV1` (`:10-24`); the private decoding and framing helpers of the crate boundary (`crates/ea-format/src/object.rs:156-223`); `ea_crypto::validate_unsigned_protocol_core` (`crates/ea-crypto/src/cose.rs:3425`, re-exported `crates/ea-crypto/src/lib.rs:20`) with the closed action-to-context-tag table it already carries (`crates/ea-crypto/src/cose.rs:3676-3695`) and its per-context field shapes (`:3699-3725`); `ea_crypto::parse_cose_sign1` and `ContentType::LocalAuditCbor` (`crates/ea-crypto/src/cose.rs:32`, `:49`); `CoseSigner::sign_local_audit` (`crates/ea-crypto/src/cose.rs:511-516`) and the declared test entropy of `ea-testkit` (`crates/ea-testkit/src/lib.rs:181`, `:209`); the identifier and hash newtypes of `ea-types` (`crates/ea-types/src/ids.rs:54-57`, `:65`, `:116`, `:167`).
- Produces: `LocalAuditActionV1` as a closed twelve-variant enum in which every variant **carries** its typed context; the eight context structs `StaleRegistryContextV1`, `ExportContextV1`, `BindingLifecycleContextV1`, `AdminRootContextV1`, `HistoricalRegrantContextV1`, `DestructionContextV1`, `ArchiveProfileMigrationContextV1` and the existing `ClockReleaseContextV1`, plus `GenericAuditContextV1` with its infallible constructor `GenericAuditContextV1::new(Option<ObjectHash>) -> Self`, which Task 6 calls when it builds its typed events; `LocalAuditEventCoreFieldsV1`; `encode_local_audit_core`, `encode_local_audit_event`, `decode_local_audit_event` and `LocalAuditEventV1` with `exact_core()`/`exact_bytes()`; the frozen vector family `vectors/local-audit/v1` through `ea_testkit::local_audit_v1_manifest`.

The action and its context are **one** value, not two fields. `schemas/reports/v1/local-audit.cddl:63-75` binds each of the twelve actions to exactly one context arm, `tools/xtask/tests/spec_completeness.rs:2134-2176` already proves that the grammar rejects a wrong pair, and `crates/ea-crypto/src/cose.rs:3684-3695` already refuses one at the COSE core boundary. A type with an independent `action` field and an independent `context` field would offer the free product of twelve actions and nine contexts, of which most members are bytes that three existing gates reject — so the encoder makes an invalid pair unconstructible instead of merely rejecting it. For the same reason `LocalAuditOutcomeV1` is reused unchanged (`crates/ea-format/src/local_audit.rs:28-32`, `Failed = 0`, `Accepted = 1`, `Completed = 2`): a second outcome enum written in the reading order "accepted, failed, completed" would encode `Accepted = 0` and swap two permanent audit verdicts without any diagnostic.

This task carries the four D-B02 hash slots as typed 32-byte fields and computes **none** of them. `stale-registry-context-v1` (`schemas/reports/v1/local-audit.cddl:6-10`) holds `preview-hash` at its sixth position, and `archive-profile-migration-context-v1` (`:43-46`) holds `source-profile-hash`, `target-profile-hash`, `inventory-hash` and `active-pointer-hash`. Their preimages, the four `EINSATZARCHIV-…` domain constants next to `crates/ea-crypto/src/digest.rs:18-31` and the additional `vectors/crypto/suite-1/domain-string/` and `domain-digest/` entries with their raised counts (`tests/ea-system-tests/tests/conformance_golden_vectors.rs:84`, `:89`) are produced additively by Task 9 for the three archive hashes and by Task 11 for `previewHash`. Adding them there rather than here keeps `check_every_domain_string_is_frozen` (`tests/ea-system-tests/tests/conformance_golden_vectors.rs:968`) green, because a new domain string is only lawful together with its own new vector.

`crates/ea-audit` is not anticipated here. The `LocalAuditService`, its closed context allowlist, the provider signature, the COSE check before commit, the missing update/delete API and the append-only repository stay in Task 6, which consumes this encoder instead of building a second set of types.

- [ ] **Step 0: Add the single dev-dependency edge and refresh the lockfile once**

This task registers no new workspace member; the member count and the wasm32 classification are untouched. It adds exactly one dependency edge, and that edge alone rewrites `Cargo.lock`. Modify `tools/xtask/Cargo.toml`: add `ea-format.workspace = true` under `[dev-dependencies]` so that `tools/xtask/tests/spec_completeness.rs` can call the new encoder. `ea-format` already stands in the workspace table (`Cargo.toml:22`), so `tools/xtask/tests/workspace.rs:90-101` is satisfied without a second entry, and `:86` covers dev-dependencies explicitly.

Run: `cargo metadata --format-version 1 > /dev/null` (without `--locked`)

Expected: PASS; `Cargo.lock` now records `ea-format` as a dependency of `xtask`. Only after this step do the `--locked` commands of this task run.

- [ ] **Step 1: Write encoder, grammar and vector tests**

`crates/ea-format/tests/local_audit_encoder.rs`:

```rust
#[test]
fn every_action_encodes_the_twelve_frozen_core_positions() {
    for event in fixtures::one_event_per_action() {
        let core = encode_local_audit_core(&event).unwrap();
        let mut decoder = minicbor::Decoder::new(&core);
        assert_eq!(decoder.array().unwrap(), Some(12));
        assert_eq!(decoder.u64().unwrap(), 1);
        // Regressionsanker: der Encoder ruft diese Pruefung selbst auf. Der Test
        // haelt sie fest, damit ihre Entfernung sichtbar wird.
        ea_crypto::validate_unsigned_protocol_core(
            ea_crypto::ContentType::LocalAuditCbor,
            &core,
        )
        .unwrap();
    }
}

#[test]
fn the_action_code_and_the_context_tag_never_drift_apart() {
    for (event, action_code, context_tag) in fixtures::action_and_tag_expectations() {
        let core = encode_local_audit_core(&event).unwrap();
        assert_eq!(event.action.code(), action_code);
        assert_eq!(event.action.context_tag(), context_tag);
        assert_eq!(core[fixtures::ACTION_CODE_OFFSET], action_code);
        assert_eq!(core[fixtures::CONTEXT_TAG_OFFSET], context_tag);
    }
}

#[test]
fn the_general_decoder_agrees_with_the_frozen_clock_release_decoder() {
    let signed = fixtures::signed_clock_skew_release_event();
    let general = decode_local_audit_event(&signed).unwrap();
    let frozen = decode_clock_release_audit(&signed).unwrap();
    assert_eq!(general.exact_core(), frozen.exact_core());
    assert_eq!(general.exact_bytes(), signed.as_slice());
    assert_eq!(general.outcome(), frozen.outcome());
}

#[test]
fn a_cose_payload_that_does_not_carry_the_core_is_refused() {
    let signed = fixtures::signed_plaintext_export_event();
    let mut tampered = signed.clone();
    let offset = fixtures::nonce_offset(&signed);
    tampered[offset] ^= 0x01;
    assert_eq!(
        decode_local_audit_event(&tampered).unwrap_err(),
        FormatError::Cose
    );
}

#[test]
fn an_outcome_outside_the_frozen_range_is_refused() {
    let signed = fixtures::signed_plaintext_export_event();
    let mut tampered = signed.clone();
    tampered[fixtures::OUTCOME_OFFSET] = 3;
    assert!(decode_local_audit_event(&tampered).is_err());
}
```

`tools/xtask/tests/spec_completeness.rs` — two additive tests next to `local_audit_cddl_correlates_action_and_context_tag` (`:2134-2176`), reusing the existing `validate_cbor` helper (`:72-80`), whose `#6.18(COSE-Sign1)` normalisation is load-bearing and must not be duplicated elsewhere:

```rust
#[test]
fn every_encoded_local_audit_core_satisfies_the_frozen_grammar() {
    let cddl = include_str!("../../../schemas/reports/v1/local-audit.cddl");
    for core in local_audit_cores_for_every_action() {
        assert!(validate_cbor("local-audit-event-core-v1", cddl, &core));
    }
}

/// Die vier Vektoren, deren Ablehnung GRAMMATISCH ist. Jeder andere Vektor der
/// Familie — auch `rejected-flipped-nonce-byte` — ist von der CDDL akzeptiert
/// und wird erst vom Decoder abgelehnt.
const GRAMMATICALLY_REJECTED: [&str; 4] = [
    "event/rejected-flipped-action-code.bin",
    "event/rejected-flipped-context-tag.bin",
    "event/rejected-flipped-outcome.bin",
    "event/rejected-unknown-action-code-200.bin",
];

#[test]
fn the_frozen_local_audit_vectors_match_the_grammar() {
    let cddl = include_str!("../../../schemas/reports/v1/local-audit.cddl");
    for file in local_audit_vector_files() {
        let expected = !GRAMMATICALLY_REJECTED.contains(&file.name.as_str());
        assert_eq!(
            validate_cbor("local-audit-event-v1", cddl, &file.bytes),
            expected,
            "{} must be {} by local-audit-event-v1",
            file.name,
            if expected { "accepted" } else { "rejected" }
        );
    }
}
```

Two verdicts are deliberately kept apart here. The manifest's `expectedOutcome` is the **decoder** verdict — what `decode_local_audit_event` does with the bytes — and the literal list above is the **grammar** verdict. They differ for exactly one vector: `rejected-flipped-nonce-byte` is well-formed under the CDDL and is refused only because its COSE payload no longer equals the core. Keying the grammar test off `expectedOutcome` would therefore make it fail on the one vector that carries the most interesting statement of the family.

`tests/ea-system-tests/tests/conformance_golden_vectors.rs` — a `local-audit` family check following `load_frozen_family` (`:2313`) and the shape of `grant_receipt_and_evidence_vectors_match_their_manifests` (`:2255-2300`), with its own entry-count bound so a truncated manifest cannot pass silently:

```rust
const LOCAL_AUDIT_MANIFEST_PATH: &str = "vectors/local-audit/v1/manifest.json";
const LOCAL_AUDIT_VECTOR_ROOT: &str = "vectors/local-audit/v1";
const LOCAL_AUDIT_EXPECTED_ENTRY_COUNT: usize = 17;

#[test]
fn local_audit_vectors_match_their_manifest() {
    let root = workspace_root();
    let family = load_frozen_family(
        &root,
        LOCAL_AUDIT_MANIFEST_PATH,
        LOCAL_AUDIT_VECTOR_ROOT,
        "local-audit",
        LOCAL_AUDIT_EXPECTED_ENTRY_COUNT,
    );
    for vector in family.entries.iter() {
        assert_eq!(vector.suite_id, ARCHIVE_FROZEN_SUITE_ID);
        assert_eq!(vector.schema_id, "local-audit-event-v1");
    }
    assert_eq!(
        check_local_audit_vectors(&family.entries),
        family.entries.len()
    );
}
```

- [ ] **Step 2: Run the encoder and grammar tests and confirm the encoder is absent**

Run: `cargo test --locked -p ea-format --test local_audit_encoder ; cargo test --locked -p xtask --test spec_completeness`

Expected: FAIL because `encode_local_audit_core`, `encode_local_audit_event`, `decode_local_audit_event`, the twelve-variant action enum and the eight context structs do not exist, and because the vector family `vectors/local-audit/v1` is not on disk. The two commands are separated by `;` so that the grammar surface still reports its own gap after the expected failure of the first command.

- [ ] **Step 3: Implement the closed event type and its deterministic encoder**

Extend `crates/ea-format/src/local_audit.rs`; do not create a second module and do not renumber anything. The action enum is closed and carries its context, and its two accessors are the single source of both frozen numbers:

```rust
pub enum LocalAuditActionV1 {
    Login(GenericAuditContextV1),
    ReauthFailure(GenericAuditContextV1),
    BindingChange(BindingLifecycleContextV1),
    Revocation(BindingLifecycleContextV1),
    RegistryStaleWarnAcceptance(StaleRegistryContextV1),
    PlaintextExport(ExportContextV1),
    ClockSkewRelease(ClockReleaseContextV1),
    AdminRootCeremony(AdminRootContextV1),
    RecoveryTest(GenericAuditContextV1),
    HistoricalRegrant(HistoricalRegrantContextV1),
    Destruction(DestructionContextV1),
    ArchiveProfileMigration(ArchiveProfileMigrationContextV1),
}
```

`code()` yields `0..11` in exactly this order (`schemas/reports/v1/local-audit.cddl:3`, `:63-75`), and `context_tag()` yields the mapping that `crates/ea-crypto/src/cose.rs:3684-3695` already enforces: actions 0, 1 and 8 use tag 0, actions 2 and 3 use tag 4, action 4 uses tag 1, action 5 uses tag 3, action 6 uses tag 2, action 7 uses tag 5, action 9 uses tag 6, action 10 uses tag 7, action 11 uses tag 8. The eight typed context structs mirror their CDDL arities field for field — stale registry six positions (`:6-10`), clock release ten (`:15-22`), export two (`:23`), binding lifecycle three with two nullable hashes (`:24-28`), admin root three (`:29-32`), historical regrant five (`:33-38`), destruction two (`:39-42`), archive profile migration four (`:43-46`) — and the generic context carries a single `Option<ObjectHash>` (`:47`) together with the infallible constructor `GenericAuditContextV1::new(subject: Option<ObjectHash>) -> Self`, which takes that one position and returns the value directly, without a `Result`, because a degenerate one-position context has nothing to reject; Task 6 constructs every generic-context action through it. The four D-B02 slots are plain `Hash32` fields on the stale-registry and archive-profile-migration structs; this crate stores them and never computes them.

```rust
pub struct LocalAuditEventCoreFieldsV1 {
    pub event_id: EventId,
    pub organization_id: OrganizationId,
    pub device_id: DeviceId,
    pub operator_binding_object_hash: Option<ObjectHash>,
    pub signer_certificate_object_hash: ObjectHash,
    pub action: LocalAuditActionV1,
    pub outcome: LocalAuditOutcomeV1,
    pub effective_now: UnixMillis,
    pub nonce: [u8; 32],
}
```

`encode_local_audit_core` writes the twelve positions of `schemas/reports/v1/local-audit.cddl:77-85` in one pass with `minicbor::Encoder` over a preallocated `Vec<u8>`, following the deterministic encoder already in the crate, `encode_receipt_core` (`crates/ea-format/src/esr.rs:226-267`): one definite-length `array(12)`, the version literal `1` first, every optional position written as an explicit `null()` exactly as `encode_optional_entry_hash` does (`crates/ea-format/src/esr.rs:269-281`), the context as `array(2)` carrying the tag and the typed payload, then the 32-byte nonce and the closing empty `array(0)`. No map, no indefinite length, no field reordering — the positions are the contract. The last act of the function is `ea_crypto::validate_unsigned_protocol_core(ContentType::LocalAuditCbor, &core)`, so the encoder is measured against the same boundary that will later accept or refuse the signature, and a divergence surfaces at encode time instead of in permanent audit rows.

`encode_local_audit_event(core: &[u8], cose_sign1: &[u8])` concatenates a definite `array(2)` with the two exact items, byte for byte as `encode_receipt_wrapper` does (`crates/ea-format/src/esr.rs:283-292`), and refuses the pair unless `parse_cose_sign1` reports `ContentType::LocalAuditCbor`, a payload identical to `core` and a certificate hash equal to the core's `signer-certificate-object-hash` — the same three conditions the existing decoder applies (`crates/ea-format/src/local_audit.rs:208-216`). `decode_local_audit_event` is the general counterpart of `decode_clock_release_audit`; the frozen clock-release decoder and its exported type stay exactly as they are, and the general decoder is added beside them in `crates/ea-format/src/lib.rs:34-37`.

The encoder produces no archive object: local audit rows carry none of the six object prefixes (`crates/ea-format/src/parser.rs:21-26`), so `encode_local_audit_event` returns `Vec<u8>` and not `ExactObjectBytes`, and no seventh prefix, no seventh raw-size constant and no change to `decode_exact_object` arises. Task 6 wraps these bytes in its own `SignedLocalAuditEvent` with a read-only `exact_bytes` accessor and a private constructor.

- [ ] **Step 4: Freeze the vector family**

Add `local_audit_v1_manifest()` to `crates/ea-testkit/src/lib.rs` following the receipts family (`crates/ea-testkit/src/lib.rs:4186-4323`): named constants for every field, `LOCAL_AUDIT_FAMILY = "local-audit"`, `LOCAL_AUDIT_V1_ROOT = "vectors/local-audit/v1"`, generator `ea-testkit::local_audit_v1_manifest`, suite `EINSATZARCHIV-SUITE-1`, schema `local-audit-event-v1`. Signing is deterministic and needs no new dependency: `format_signer` over the declared device seed (`crates/ea-testkit/src/lib.rs:181`, `:1633`) plus `CoseSigner::sign_local_audit` (`crates/ea-crypto/src/cose.rs:511-516`), which derives the certificate hash from the core itself.

Twelve accepted vectors, one per action, so that all nine context tags and both nullable positions appear at least once. Five rejected vectors, four of them single-byte edits produced with the existing `unique_offset` helper (`crates/ea-testkit/src/lib.rs:4006`, used at `:4327-4330`):

| Vector | Edit | Why it is rejected |
|---|---|---|
| `event/rejected-flipped-action-code` | action byte of the `plaintextExport` event from `5` to `0` | the grammar binds action 0 to the generic context (`schemas/reports/v1/local-audit.cddl:64`), the case `tools/xtask/tests/spec_completeness.rs:2153-2157` already pins |
| `event/rejected-flipped-context-tag` | context tag of the same event from `3` to `0` | tag and action must agree (`schemas/reports/v1/local-audit.cddl:69`) |
| `event/rejected-flipped-outcome` | outcome byte from `2` to `3` | outside `local-audit-outcome-v1 = 0..2` (`schemas/reports/v1/local-audit.cddl:4`) |
| `event/rejected-flipped-nonce-byte` | one nonce byte, length unchanged | the grammar still accepts the shape; `parse_cose_sign1` refuses because the payload is no longer the core — the vector is the proof that the CDDL is not the acceptance boundary |
| `event/rejected-unknown-action-code-200` | action encoded as `200` | the frozen vector-hygiene rule (`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md:1713`) reserves `200` for an inadmissible action code, so a later v1.1 extension can never turn this vector from rejected into accepted. It is deliberately **not** a single-byte edit: `200` needs a two-byte CBOR head, and a neighbouring one-byte value would violate that rule |

Every entry records `scope_note` where a reader would otherwise over-read the vector — in particular that the four D-B02 hash slots contain declared test constants and prove nothing about how those hashes are computed. Write the family once with `VectorManifest::emit` (`crates/ea-testkit/src/lib.rs:536`) into `vectors/local-audit/v1`, commit the emitted bytes, and never regenerate them; from then on the checked-in bytes are the authority and the tests recompute against them.

`STAGE_ONE_VECTOR_FAMILIES` (`tools/xtask/src/main.rs:866-868`) stays untouched — it is the closed Stage 1 gate contract. Registering `local-audit` as a Stage 2 vector family in the gate report belongs to Task 17.

- [ ] **Step 5: Run encoder, grammar and vector gates**

Run:

```bash
cargo test --locked -p ea-format && \
cargo test --locked -p ea-testkit && \
cargo test --locked -p xtask --test spec_completeness && \
cargo test --locked -p ea-system-tests --test conformance_golden_vectors
```

Expected: PASS. Every encoded core satisfies `local-audit-event-core-v1`, every accepted vector satisfies `local-audit-event-v1`, every rejected vector is refused for the reason its manifest names, the general decoder and the frozen clock-release decoder agree byte for byte, and the six Stage 1 vector families are unchanged.

- [ ] **Step 6: Commit the local audit encoder and its frozen vectors**

```bash
git add crates/ea-format crates/ea-testkit tests/ea-system-tests tools/xtask vectors/local-audit Cargo.lock
git commit -m "feat(format): encode the twelve local audit events"
```

### Task 5: ADR 0002 — Local Database Encryption (SYNTHESE.md: Task 2.6)

**Files:**
- Create: `docs/adr/0002-local-database-encryption.md`
- Modify: `Cargo.toml`
- Modify: `deny.toml`
- Test: `tools/xtask/tests/adr_gate.rs`

**Interfaces:**
- Consumes: the accepted decision this one has to face, `docs/adr/0001-toolchain-and-cryptography-dependencies.md:75-77` (OpenSSL and `ring` rejected as suite-wide abstractions) and its amendment rule `:152-153` (a new ADR, fresh primary-source and RustSec review, lockfile update, vectors and compatibility analysis); the inheritance rule `docs/adr/0001-…:15-20`; the review form of the existing dependency table `docs/adr/0001-…:49-61`, in particular the direct pin of a data-carrying transitive crate (`:61`); the spec requirement `design.md:1961` (full database encryption, plus per-draft keys) and `:1965` (no temporary plaintext files); the exact-pin convention `Cargo.toml:11-44` and the license allowlist `deny.toml:8-15`.
- Produces: `docs/adr/0002-local-database-encryption.md` in the form of ADR 0001; pin tranche 2 in `[workspace.dependencies]` — `rusqlite` and `libsqlite3-sys`, each with a leading `=` and an explicit feature selection; the extended license allowlist; and `tools/xtask/tests/adr_gate.rs`, the first test in the repository that couples an ADR to the dependency inventory.

This task produces documentation and pins. It writes no application code, creates no crate and creates no database; `crates/ea-local-store` and the first `PRAGMA key` are Task 6. The order is the point: `docs/adr/0001-…:75-77` rejects the class of dependency that Task 6 needs, so the decision has to be ratified before the dependency lands, not explained afterwards.

- [ ] **Step 0: Enter the database pins and confirm the lockfile stays untouched**

Resolve the currently published, non-yanked release of `rusqlite` and of `libsqlite3-sys` from their crates.io records, the sparse index and the upstream projects, and keep the three links per crate — Step 3 turns them into the ADR review table. This plan quotes no version literal on purpose: a pin invented at planning time is an unreviewed pin, and it would be copied forward as if it had been checked.

Modify `Cargo.toml`: add both crates under `[workspace.dependencies]` with those resolved literals and an explicit feature selection, following the pattern of the thirty existing entries (`Cargo.toml:11-44`). The literals are written in **this** step, not later — `cargo metadata` cannot parse a placeholder, so the Run below is the first proof that both pins are real semver requirements with a leading `=`. The feature name is read out of the published manifest of the resolved release in the same movement, never from memory: the bundled-SQLCipher feature families of `rusqlite` partly exclude one another, and Step 3 records the evidence for the name chosen here.

```toml
# `<resolved>` steht fuer den in diesem Step ermittelten Versionsliteral;
# das fuehrende `=` ist Pflicht, `default-features = false` ebenso.
libsqlite3-sys = { version = "=<resolved>", default-features = false, features = ["bundled-sqlcipher-vendored-openssl"] }
rusqlite = { version = "=<resolved>", default-features = false, features = ["bundled-sqlcipher-vendored-openssl"] }
```

`libsqlite3-sys` is pinned **directly** although `rusqlite` already depends on it, following the precedent of the direct `jiff-tzdb` pin (`docs/adr/0001-…:61`): it carries the bundled SQLCipher C sources, and without a direct pin those sources drift inside `rusqlite`'s compatible range without any review. `default-features = false` is the house rule of every reviewed entry; every additional feature Task 6 turns out to need is added with its own justification row in the ADR, never silently.

`<resolved>` is a plan artifact and must not survive this step. The pin test only checks the leading `=`, so a left-over `"=<resolved>"` would satisfy it while pinning nothing — but `cargo metadata` refuses it outright, which is why the Run stands here and not after Step 3.

Run: `cargo metadata --format-version 1 > /dev/null` (without `--locked`)

Expected: PASS, and `git diff --stat Cargo.lock` is empty. A shared dependency that no member inherits does not enter the lockfile (`docs/adr/0001-…:15-20`); the lockfile edge that `docs/adr/0001-…:152-153` demands lands in Task 6, when `crates/ea-local-store` references these entries with `workspace = true`. The ADR names Task 6 as the owner of that obligation, so the review is not asserted here and delivered nowhere.

- [ ] **Step 1: Write the ADR gate test**

`tools/xtask/tests/adr_gate.rs` reads the workspace root exactly as `tools/xtask/tests/workspace.rs:6` does and needs no new dependency: `toml` and `std::fs` are already available to the test targets of this package (`tools/xtask/Cargo.toml:16`, `:20`).

```rust
const ADR_PATH: &str = "docs/adr/0002-local-database-encryption.md";

const ADR_SECTIONS: [&str; 6] = [
    "## Context",
    "## Decision",
    "## Rejected alternatives",
    "## Primary-source and RustSec review",
    "## Full-encryption scope",
    "## Consequences",
];

const ADR_LITERALS: [&str; 5] = [
    "OpenSSL and `ring` as suite-wide abstractions",
    "RustSec advisory database",
    "write-ahead log, all indexes, and every temporary spill file",
    "no plaintext temporary file",
    "docs/adr/0001-toolchain-and-cryptography-dependencies.md",
];

const DATABASE_DEPENDENCIES: [&str; 2] = ["rusqlite", "libsqlite3-sys"];

#[test]
fn adr_0002_exists_and_carries_its_mandatory_sections() {
    let adr = fs::read_to_string(workspace_root().join(ADR_PATH))
        .expect("ADR 0002 must exist before any database dependency is pinned");
    for section in ADR_SECTIONS {
        assert!(adr.contains(section), "ADR 0002 is missing {section}");
    }
    for literal in ADR_LITERALS {
        assert!(adr.contains(literal), "ADR 0002 is missing the literal {literal}");
    }
}

#[test]
fn every_database_dependency_is_pinned_and_named_by_adr_0002() {
    let root = workspace_root();
    let adr = fs::read_to_string(root.join(ADR_PATH)).unwrap();
    let manifest: Value = fs::read_to_string(root.join("Cargo.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let shared = manifest["workspace"]["dependencies"].as_table().unwrap();
    for name in DATABASE_DEPENDENCIES {
        let spec = shared
            .get(name)
            .unwrap_or_else(|| panic!("{name} must be a shared workspace dependency"));
        let version = spec.get("version").and_then(Value::as_str).unwrap();
        assert!(version.starts_with('='), "{name} must be pinned exactly");
        assert!(
            adr.contains(&format!("`{name}`")) && adr.contains(version),
            "ADR 0002 must name {name} with the pinned version {version}"
        );
        for feature in spec["features"].as_array().unwrap() {
            let feature = feature.as_str().unwrap();
            assert!(
                adr.contains(feature),
                "ADR 0002 must justify the {name} feature {feature}"
            );
        }
    }
}
```

The literal-and-section shape mirrors the only document gate the repository has, `require_document_literals` over `FORMAT_PACKAGE_SECTIONS` and `FORMAT_PACKAGE_LITERALS` (`tools/xtask/src/main.rs:913-921`, `:1425`, applied at `:1539-1550`). It is deliberately a separate test target and touches neither `stage_one_documents` (`tools/xtask/src/main.rs:1535-1565`) nor any `STAGE_ONE_*` constant: the Stage 1 gate is closed, and Stage 2 gate content belongs to Task 17. The second test is what makes the ADR load-bearing rather than decorative — before this task, `grep -rn "0001-toolchain\|docs/adr" tools/xtask/` returns nothing, so no test connected an ADR to the dependency inventory at all.

- [ ] **Step 2: Run the ADR gate and confirm the decision is unratified**

Run: `cargo test --locked -p xtask --test adr_gate`

Expected: FAIL because `docs/adr/0002-local-database-encryption.md` does not exist, so a database dependency stands in `[workspace.dependencies]` without a ratifying decision.

- [ ] **Step 3: Conduct the primary-source and RustSec review and write ADR 0002**

Write `docs/adr/0002-local-database-encryption.md` in the form of ADR 0001: a `Status`/`Decision date`/`Evidence retrieved` header (`docs/adr/0001-…:3-5`), then the six mandatory sections.

**Primary-source and RustSec review** — the section `docs/adr/0001-…:152-153` demands, carried out with the same rigour as the existing dependency table (`docs/adr/0001-…:49-61`) and recorded as one row per crate:

1. Record, as links, the three primary sources per crate that Step 0 already resolved — the crates.io record, the sparse-index record and the upstream project — together with the pinned release, exactly as `docs/adr/0001-…:51-61` does for every existing dependency.
2. Read the published manifest of the resolved release (`Cargo.toml.orig` on docs.rs, exactly the evidence form used for `jiff` at `docs/adr/0001-…:60`) and record the **verified** names of the enabled features. The bundled-SQLCipher feature families of `rusqlite` partly exclude one another, so the selected name is quoted from the manifest, never from memory.
3. Record the MSRV each crate reports and confirm it admits Rust 1.95 (`rust-toolchain.toml:2`, `Cargo.toml:7`).
4. Query the [RustSec advisory database](https://github.com/RustSec/advisory-db) for `rusqlite`, `libsqlite3-sys` and the vendored OpenSSL crate, and record the result including the query date — an empty result is a finding and is written down as one.
5. Record the SPDX license of every crate the pinned tree adds and compare it against the five entries of `deny.toml:8-15`.
6. Record the native build requirement each supported platform inherits — a C toolchain on Windows 11 `x86_64`, macOS `arm64`/`x86_64` and Ubuntu 24.04 LTS `x86_64` — because that is precisely the "native toolchain variance" `docs/adr/0001-…:75-77` warned about, and it is now accepted knowingly rather than by omission.

**Rejected alternatives**, with the ADR 0001 clause addressed head-on. `docs/adr/0001-…:75-77` rejects OpenSSL and `ring` **as suite-wide abstractions**, to keep Suite 1's algorithm selection explicit and pure-Rust. SQLCipher is not a suite-wide abstraction and does not touch Suite 1: it produces no archive byte, no COSE signature, no grant, no hash-chain link and no object of the six frozen families; deterministic CBOR, SHA-256, Ed25519, ChaCha20-Poly1305 and HPKE remain exactly where ADR 0001 put them. Its scope is one local file at rest on the operator's device, and the vendored-OpenSSL feature family is chosen precisely so that this crypto does **not** vary with whatever OpenSSL a host happens to carry — the variance ADR 0001 objected to is reduced by the choice, not introduced by it. Also record the alternatives that were rejected:

- Plain SQLite with per-record AEAD, rejected because `design.md:1961` requires full database encryption; per-record AEAD leaves the write-ahead log, all indexes and every temporary spill file readable, and the additional per-draft keys of the same sentence are a supplement to full encryption, not a substitute for it.
- A hand-rolled page-level encryption layer over plain SQLite, rejected for the same reason ADR 0001 rejects hand-written CBOR and COSE (`docs/adr/0001-…:65-67`): storage-format cryptography is high-risk code.
- Loading SQLCipher as a runtime SQLite extension or from a system library, rejected because the encryption of the local database would then depend on a component the lockfile does not pin and the gate cannot reproduce.

**Full-encryption scope**, verbatim in the ADR so that Task 6 has no interpretation left: full encryption covers the write-ahead log, all indexes, and every temporary spill file; the journal mode and the temp-store setting are configured accordingly at open time and are checked by a test in Task 6; no plaintext temporary file is created at any point (`design.md:1965`), and the database key travels as a `SecretVec` from the native key provider — never through a file, an environment variable or a log line. Record the Reader exception explicitly: the browser Reader's cache and search index are **not** covered by this ADR and use a ChaCha20-Poly1305-encrypted Rust index in OPFS (`design.md:1963`).

**Consequences**, in the form of `docs/adr/0001-…:150-160`: the lockfile update that `docs/adr/0001-…:152-153` requires is completed in Task 6, when `crates/ea-local-store` inherits both entries with `workspace = true` and the packages actually enter `Cargo.lock`; no wire format, vector or compatibility file is affected, because no byte of the archive format touches this dependency; and `cargo deny` is invoked by no gate today, so the license allowlist below is a reviewed record and not yet an enforced control — wiring the invocation into `xtask stage-gate 2` is Task 17's obligation and is named here so it cannot be silently dropped.

Modify `deny.toml`: add exactly those SPDX identifiers that this review found in the pinned tree and that the five-entry allowlist (`deny.toml:8-15`) does not yet contain, each with a comment naming the crate that requires it. Add nothing speculatively — an allowlist entry without a crate behind it weakens the very control it belongs to.

- [ ] **Step 4: Run the ADR gate and the workspace pin checks**

Run: `cargo test --locked -p xtask --test adr_gate && cargo test --locked -p xtask --test workspace`

Expected: PASS. ADR 0002 exists and carries its six sections and five mandatory literals, `rusqlite` and `libsqlite3-sys` are pinned with a leading `=` and named in the ADR with exactly those version literals and feature names, and the workspace pin test from Task 1 confirms that every version literal in `[workspace.dependencies]` still begins with `=`.

- [ ] **Step 5: Commit the ratified database decision**

```bash
git add docs/adr/0002-local-database-encryption.md Cargo.toml deny.toml tools/xtask
git commit -m "docs(adr): ratify local database encryption"
```

### Task 6: Encrypted Local Store and Single-Draft Autosave (SYNTHESE.md: Task 3)

**Files:**
- Create: `crates/ea-local-store/Cargo.toml`
- Create: `crates/ea-local-store/src/lib.rs`
- Create: `crates/ea-local-store/src/database.rs`
- Create: `crates/ea-local-store/src/migrations.rs`
- Create: `crates/ea-local-store/migrations/0001_writer.sql`
- Create: `crates/ea-audit/Cargo.toml`
- Create: `crates/ea-audit/src/lib.rs`
- Create: `crates/ea-audit/src/event.rs`
- Create: `crates/ea-audit/src/repository.rs`
- Create: `crates/ea-draft/Cargo.toml`
- Create: `crates/ea-draft/src/lib.rs`
- Create: `crates/ea-draft/src/model.rs`
- Create: `crates/ea-draft/src/repository.rs`
- Create: `crates/ea-draft/src/autosave.rs`
- Create: `crates/ea-draft/src/lock.rs`
- Create: `crates/ea-draft/src/incident_number.rs`
- Create: `crates/ea-draft/src/operator_profile.rs`
- Create: `crates/ea-draft/tests/support/mod.rs`
- Create: `crates/ea-audit/tests/support/mod.rs`
- Modify: `crates/ea-testkit/src/lib.rs`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `tools/xtask/src/main.rs`
- Modify: `tools/xtask/tests/workspace.rs`
- Test: `crates/ea-local-store/tests/encrypted_open.rs`
- Test: `crates/ea-draft/tests/single_draft.rs`
- Test: `crates/ea-draft/tests/autosave_cas.rs`
- Test: `crates/ea-draft/tests/register_and_profile.rs`
- Test: `crates/ea-audit/tests/redaction.rs`

**Interfaces:**
- Consumes: from Task 2 the synchronous `KeyProvider` with exactly the ports it declares — `unwrap_database_key(&KeyHandle) -> Result<SecretVec, KeyError>` for the database key, `wrap_secret(SecretPurpose::DraftDek, SecretBytes<CEK_SIZE>) -> Result<KeyHandle, KeyError>`, `unwrap_secret`, `delete`, `contains` for the `draftDEK`, and `sign(&KeyHandle, ContentType, CertificateHash, &[u8]) -> Result<CoseSign1Bytes, KeyError>` for the audit signature, plus `InMemoryKeyProvider` behind the non-default feature `test-support`. From Task 3: `OperatorSessionProof`, `ReauthPurpose` and the active operator binding fields reachable through `SelectedRegistryHead::active_operator_binding_fields` (`crates/ea-trust/src/registry.rs:154-160`), whose `operator_profile_commitment` sits at `crates/ea-format/src/etb.rs:127`. From Task 4: `ea_format::encode_local_audit_core`, `ea_format::encode_local_audit_event`, `ea_format::LocalAuditActionV1` with the pinned discriminants of `schemas/reports/v1/local-audit.cddl:3`, the wire context types of the families that grammar already fixes, and `ea_format::LocalAuditOutcomeV1` unchanged (`crates/ea-format/src/local_audit.rs:26-32`, re-export `crates/ea-format/src/lib.rs:34-37`). From Task 5: the `rusqlite` pin with bound SQLCipher and its feature selection; this task adds no feature of its own. From Stage 1: `ea_crypto::{aead_seal, aead_open, CEK_SIZE, AEAD_NONCE_SIZE, SecretBytes, SecretVec, object_hash}` (`crates/ea-crypto/src/aead.rs:9-11`, `:19-43`, `:45-75`, `crates/ea-crypto/src/digest.rs:63-66`, re-exports `crates/ea-crypto/src/lib.rs:12-14`, `:23-29`, `:39`) and the identifier newtypes `Id16`, `EventId`, `ObjectHash`, `CertificateHash` (`crates/ea-types/src/ids.rs:3-24`, `:57`, `:87-112`, `:116`, `:120`, re-export `crates/ea-types/src/lib.rs:14`).
- Produces: `EncryptedDatabase::open`, the migration registry `crates/ea-local-store/src/migrations.rs` and migration `0001_writer.sql`; the full `DraftRepository` surface `{load_or_create, save, draft_dek_handle, commit_discard_intent, pending_discard, replace_with_blank, remove_ciphertext_and_intent_create_blank, prepared_finalization_marker, replace_prepared_finalization_marker, acquire_draft_lock}` together with `DraftLock`; an autosave service that permits exactly one active draft; `IncidentNumberRegister::{claim, contains}`; the read-only `OperatorProfileRepository::load`; `LocalAuditService::record_signed` with the closed `AuditActorProof`, `AuthenticatedDevice` and `TypedLocalAuditEvent`, plus `SignedLocalAuditEvent::exact_bytes(&self) -> &[u8]` and `SignedLocalAuditEvent::id(&self) -> EventId` — read-only, the constructor stays private. The three error types `StoreError`, `DraftError` and `AuditError` each carry a stable `code()` and a `Display` that prints the code, following `ArchiveError` (`crates/ea-archive/src/error.rs:10`, `:22-46`); the model types `Draft`, `SavedDraft`, `DiscardIntent`, `DiscardOutcome` and `PreparedFinalizationMarker` live in `crates/ea-draft/src/model.rs`, so that Task 7 adds only the service beside them. Additively in `ea-testkit`: `contains_canary`.

The exclusive **draft** lock produced here is `DraftLock`, and it is a different lock from the archive-side `acquire_writer_lock` of Task 9. Both are named separately wherever a later task consumes them, so that discard resumption and finalization resumption never end up sharing one guard by accident.

`DraftRepository` is declared here in full, including the arms that only Task 7 and Task 11 call. The trait is gated by this task; changing it afterwards would reopen a gated interface, so the discard and finalization arms — read **and** write — are part of the declaration from the start, even though their bodies touch the `draft_transition` table that migration `0002_discard.sql` creates.

The store owns the schema, the migration registry and the migration chain; the retention table for the exact `import-report-v1` bytes is **not** part of it. Those bytes arrive with the master data in Task 8 and therefore live in `0003_master_data.sql`, because a registered migration is never rewritten afterwards. `0001_writer.sql` carries the draft, audit, incident-number and operator-profile tables; every further schema change is a new, ascending file.

- [ ] **Step 0: Register the three workspace members and create the lockfile once**

Create `crates/ea-local-store/Cargo.toml`, `crates/ea-audit/Cargo.toml`, `crates/ea-draft/Cargo.toml` and an empty `src/lib.rs` beside each, so the member paths resolve. Modify `Cargo.toml`: add `crates/ea-local-store`, `crates/ea-audit` and `crates/ea-draft` under `[workspace]members` and their path entries under `[workspace.dependencies]` without a version literal, following the existing `ea-*` entries (`Cargo.toml:18-29`). The dependency edges are: `ea-local-store` on `ea-crypto`, `ea-key-provider` and `rusqlite`; `ea-draft` on `ea-types`, `ea-crypto`, `ea-key-provider`, `ea-local-store`, `getrandom` (`Cargo.toml:31`) for the fresh `draftDEK` and nonce, and `unicode-normalization` (`Cargo.toml:41`) for the register key; `ea-audit` on `ea-types`, `ea-crypto`, `ea-format`, `ea-key-provider`, `ea-operator` and `ea-local-store`. `ea-draft` deliberately gets **no** `ea-format` edge: all deterministic audit encoding runs through `ea-audit`. Each crate carries `ea-testkit` and `ea-key-provider` with `features = ["test-support"]` under `[dev-dependencies]`, `ea-audit` additionally `cddl-cat` (`Cargo.toml:12`); every one of them is referenced with `workspace = true`, which `tools/xtask/tests/workspace.rs:90-101` enforces for dependencies and dev-dependencies alike (`:86`).

Modify `tools/xtask/src/main.rs`: append one `(name, justification)` pair with a non-empty justification per crate to the `WASM32_EXEMPT_CRATES` slice (`tools/xtask/src/main.rs:102`, a slice since Task 1, so no arity edit exists to make), following the `ea-recovery` precedent (`tools/xtask/src/main.rs:103-111`) — `ea-local-store` binds a native SQLCipher build and opens files on the host filesystem, `ea-audit` signs through the host keystore provider, `ea-draft` reaches the same host store and provider. **Never** the wasm32 positive list, which the closed Stage 1 gate freezes textually (`docs/traceability/stage-1-gate.md:60-65`). Modify `tools/xtask/tests/workspace.rs`: append the three member paths to `WORKSPACE_MEMBERS` (Task 1) and nowhere else — the length assertion, the set comparison and the dependency walk all derive from that one list.

Run: `cargo metadata --format-version 1 > /dev/null` (without `--locked`)

Expected: PASS; `Cargo.lock` now contains the three new packages and `rusqlite`. Only after this step do the `--locked` commands of this task run.

- [ ] **Step 1: Write single-draft, autosave-CAS, encryption, register and typed-audit tests**

Add to `crates/ea-testkit/src/lib.rs`, next to the existing small helpers (`crates/ea-testkit/src/lib.rs:232-238`):

```rust
/// Sucht eine Bytefolge in einer Bytefolge. Kein Kanary-Treffer heisst: nicht enthalten.
#[must_use]
pub fn contains_canary(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
}
```

Write `crates/ea-draft/tests/support/mod.rs` with `DraftHarness`, whose contract the tests below rely on: `DraftHarness::new()` creates its own temporary root and takes a process-wide lock following `tools/xtask/tests/stage_gate.rs:29-44`, so the tests serialize themselves and need no `--test-threads` flag; `close_repo(self) -> ClosedDraftHarness` closes the repository without moving the field out of the harness, because dropping a field of a still-used value is not possible here; `ClosedDraftHarness::reopen(&mut self) -> &DraftHarness` reopens the same database on the same root; `active_draft_row_count(&self) -> u64` counts the rows of the draft table; `raw_database_bytes(&self) -> &[u8]` returns the untouched main database file; `incident_number_register()`, `organization_id()`, `operator_profile_repo()` and `bound_operator_binding_object_hash()` reach the register and the profile row, and `with_seeded_operator_profile()` is the variant that seeds one profile row from the frozen operator snapshot fixture. Write `crates/ea-audit/tests/support/mod.rs` with `AuditHarness`, offering `audit_service()`, `operator_session()` built from a selected Registry head, and `reopen_audit(&self) -> &dyn LocalAuditRepository`.

`crates/ea-draft/tests/single_draft.rs`:

```rust
#[test]
fn exactly_one_encrypted_draft_is_restored_after_restart() {
    let harness = DraftHarness::new();
    let draft = harness.repo.load_or_create().unwrap();
    harness.repo.save(draft.with_notes("CANARY-DRAFT")).unwrap();
    let mut harness = harness.close_repo();
    let reopened = harness.reopen().repo.load_or_create().unwrap();
    assert_eq!(reopened.notes(), "CANARY-DRAFT");
    assert_eq!(harness.active_draft_row_count(), 1);
    assert!(!ea_testkit::contains_canary(
        harness.raw_database_bytes(),
        b"CANARY-DRAFT"
    ));
}
```

`crates/ea-draft/tests/autosave_cas.rs`:

```rust
#[test]
fn overlapping_autosaves_never_resurrect_old_content() {
    let harness = DraftHarness::new();
    let first = harness.repo.load_or_create().unwrap();
    let second = harness.repo.load_or_create().unwrap();
    let winner = harness.repo.save(first.with_notes("NEU")).unwrap();
    assert_eq!(
        harness.repo.save(second.with_notes("ALT")).unwrap_err().code(),
        "EA-DRAFT-REVISION-CONFLICT"
    );
    let reread = harness.repo.load_or_create().unwrap();
    assert_eq!(reread.notes(), "NEU");
    assert_eq!(reread.revision(), winner.revision());
    assert_eq!(harness.active_draft_row_count(), 1);
}
```

`crates/ea-draft/tests/register_and_profile.rs`:

```rust
#[test]
fn the_register_rejects_a_second_claim_of_the_same_key_and_accepts_another_year() {
    let harness = DraftHarness::new();
    let register = harness.incident_number_register();
    register.claim(harness.organization_id(), 2026, "2026-0001").unwrap();
    assert_eq!(
        register
            .claim(harness.organization_id(), 2026, "2026-0001")
            .unwrap_err()
            .code(),
        "EA-DRAFT-INCIDENT-NUMBER-TAKEN"
    );
    register.claim(harness.organization_id(), 2027, "2026-0001").unwrap();
    assert!(register.contains(harness.organization_id(), 2026, "2026-0001").unwrap());
}

#[test]
fn the_operator_profile_row_is_readable_and_has_no_write_path() {
    let harness = DraftHarness::with_seeded_operator_profile();
    let profile = harness.operator_profile_repo().load().unwrap().unwrap();
    assert_eq!(profile.display_name(), "Ada Lovelace");
    assert_eq!(
        profile.operator_binding_object_hash(),
        harness.bound_operator_binding_object_hash()
    );
}
```

The second test compiles only as long as `OperatorProfileRepository` exposes nothing but `load`; a write or provisioning arm added later would make the promise "Stage 2 consumes operator identity, it does not issue it" untrue, and Task 11 recomputes the commitment against exactly this row.

`crates/ea-local-store/tests/encrypted_open.rs` — `StoreHarness` offers `open_without_key()`, `save_draft_notes(&str)`, `raw_database_files() -> Vec<RawFile>` over the main file and every sidecar the database created, and `pragma(&str) -> String`:

```rust
#[test]
fn the_database_does_not_open_without_the_provider_key() {
    let harness = StoreHarness::new();
    assert_eq!(
        harness.open_without_key().unwrap_err().code(),
        "EA-STORE-KEY-REQUIRED"
    );
}

#[test]
fn every_database_file_including_the_wal_is_encrypted_and_no_temp_spill_is_allowed() {
    let harness = StoreHarness::new();
    harness.save_draft_notes("CANARY-DRAFT");
    let files = harness.raw_database_files();
    assert!(files.iter().any(|file| file.name.ends_with("-wal")));
    for file in &files {
        assert!(
            !ea_testkit::contains_canary(&file.bytes, b"CANARY-DRAFT"),
            "Klartext in {}",
            file.name
        );
    }
    assert_eq!(harness.pragma("journal_mode"), "wal");
    assert_eq!(harness.pragma("temp_store"), "2");
}
```

`crates/ea-audit/tests/redaction.rs`:

```rust
#[test]
fn typed_audit_never_carries_fachliche_bytes_and_never_leaks_in_errors() {
    let harness = AuditHarness::new();
    let audit = harness.audit_service();
    let session = harness.operator_session();
    let canary_hash = ObjectHash::try_from([0xCA; 32].as_slice()).unwrap();
    let event = audit
        .record_signed(
            AuditActorProof::OperatorSession(&session),
            TypedLocalAuditEvent {
                action: LocalAuditActionV1::Login(
                    ea_format::GenericAuditContextV1::new(Some(canary_hash)),
                ),
                outcome: LocalAuditOutcomeV1::Accepted,
            },
        )
        .unwrap();
    assert!(ea_testkit::contains_canary(
        event.exact_bytes(),
        canary_hash.as_bytes()
    ));
    cddl_cat::validate_cbor_bytes(
        "local-audit-event-v1",
        include_str!("../../../schemas/reports/v1/local-audit.cddl"),
        event.exact_bytes(),
    )
    .unwrap();
    let error = audit
        .record_signed(AuditActorProof::Expired, TypedLocalAuditEvent::login_failed())
        .unwrap_err();
    assert!(!ea_testkit::contains_canary(
        error.to_string().as_bytes(),
        canary_hash.as_bytes()
    ));
    assert_eq!(
        harness.reopen_audit().event(event.id()).unwrap().exact_bytes(),
        event.exact_bytes()
    );
}
```

The canary travels through the one typed position the contract permits — an object hash — because the input model carries no string at all; the assertion is therefore that the permitted value **is** in the bytes and is **not** in a formatted error. The claim "no plaintext" belongs where plaintext actually passes through, and that is the draft and the raw database files above.

- [ ] **Step 2: Run the new tests and verify the encrypted store is absent**

Run: `cargo test --locked -p ea-local-store --test encrypted_open ; cargo test --locked -p ea-draft ; cargo test --locked -p ea-audit --test redaction`

Expected: FAIL because the encrypted database, the migration registry, the draft repository, the incident-number register, the operator-profile row and the audit repository do not exist. The three commands are separated by `;` so that every gap is evidenced instead of only the first one.

- [ ] **Step 3: Implement the encrypted database and migration `0001_writer.sql`**

`EncryptedDatabase::open(path: &Path, provider: &dyn KeyProvider, database_key: &KeyHandle)` retrieves the key through the native provider before SQLite is opened; there is no constructor that takes a path alone, which is what makes the promise structural rather than procedural. The key travels as `SecretVec` and reaches the SQLCipher pragma through the already public `SecretVec::with_exposed` (`crates/ea-crypto/src/secret.rs:143`, export `crates/ea-crypto/src/lib.rs:39`), exactly as Stage 1 already leads private key material out of the crate (`crates/ea-recovery/src/decrypt.rs:210-213`); `ea-crypto` gains no new accessor.

Full database encryption means every file the database writes, not only the main file: `PRAGMA journal_mode = WAL` with SQLCipher-encrypted WAL pages, encrypted indices, and `PRAGMA temp_store = MEMORY` so no temp spill ever reaches the disk in plaintext (`design.md:1961`, `:1965`). Opening without the key fails fail-closed with `EA-STORE-KEY-REQUIRED`; there is no read-only or recovery path around it.

`crates/ea-local-store/src/migrations.rs` is the single registry of ascending migration files and applies them in order inside one transaction. A migration that has been registered is never changed afterwards; each further schema change is a new, ascending file. `0001_writer.sql` creates:

1. the singleton draft table with `draft_id` (sixteen CSPRNG bytes carried as `ea_types::Id16`, `crates/ea-types/src/ids.rs:3-24` — no new identifier type is declared), the AEAD ciphertext of the payload, the AEAD nonce, the reference to the wrapped `draftDEK` handle, a monotone `save_revision` and technical timestamps, and no fachliche column;
2. the append-only audit table keyed by `event_id`, storing the exact `local-audit-event-v1` bytes, their `object_hash` (`crates/ea-crypto/src/digest.rs:63-66`) and a monotone insertion sequence, with no update and no delete path;
3. the register of consumed incident numbers with a `UNIQUE` constraint over `(organization_id, local_civil_year, NFC-UTF-8 bytes of human_incident_number)` — the key exactly as `design.md:361-373` fixes it. The register is a **capture source**, not a derived state, so the reconstruction-from-archive-bytes obligation of `design.md` §19.3 does not apply to it and no salted commitment is required. It lives inside the encrypted database, which is what `design.md:1955` demands: cleartext incident numbers are forbidden in logs, dumps and unencrypted configuration, not in the encrypted local store. This task creates the table and `IncidentNumberRegister::{claim, contains}`; `claim` NFC-normalizes the number itself and stores the exact normalized UTF-8 bytes, so no caller can weaken the key by handing in a decomposed form. Deriving `local_civil_year` from `incidentOccurredAt.start` in `timezone` against the pinned tzdb and enforcing the claim under the exclusive Writer lock before validate-and-serialize is Task 11;
4. the encrypted singleton row `operator_profile` with exactly `[organizationId, operatorSubjectId, displayName, functionLabel, profileCommitmentSalt, operatorBindingObjectHash]` — the five commitment inputs plus the binding hash, in the order Stage 1 already encodes them (`crates/ea-schema/src/model.rs:86-93`, encoder `crates/ea-schema/src/encode.rs:429-445`). Stage 2 **consumes** this row and never issues it: `OperatorProfileRepository::load` is read-only and there is no write or provisioning API, because issuing the profile and the Root-signed binding is Stage 5 work. No new byte preimage arises — preimage, domain separation, canonicalization and field order are frozen (`crates/ea-crypto/src/digest.rs:30`, `:61`). Task 11 recomputes `operatorProfileCommitment` from this row and compares it against the bound binding (`crates/ea-format/src/etb.rs:127`).

- [ ] **Step 4: Implement single-draft autosave with per-draft AEAD and revision compare-and-swap**

Exactly one active draft exists (`design.md:426`). Generate a fresh random `draftDEK` per new draft from the CSPRNG, wrap it through `KeyProvider::wrap_secret(SecretPurpose::DraftDek, SecretBytes<CEK_SIZE>)` and store only the handle reference in the row; the keystore entry itself is device-bound, non-roaming, non-cloud-synchronising and excluded from ordinary application and system backup (`design.md:428`, `:1491`). Encrypt the application payload with `ea_crypto::aead_seal` under that `draftDEK` and a fresh `SecretBytes<AEAD_NONCE_SIZE>` per save — a nonce is never reused across two revisions of the same key — before the row reaches SQLCipher, so old database pages stay unreadable once the key is gone. The associated data of this AEAD is formed from the local row identity, `draft_id` and target revision; these bytes are local, never archived and never verified by a second implementation, so they get no frozen encoding and introduce no new domain constant.

```rust
pub trait DraftRepository: Send + Sync {
    fn load_or_create(&self) -> Result<Draft, DraftError>;
    fn save(&self, draft: Draft) -> Result<SavedDraft, DraftError>;
    fn draft_dek_handle(&self, draft: &SavedDraft) -> Result<KeyHandle, DraftError>;
    fn commit_discard_intent(&self, draft: &SavedDraft) -> Result<DiscardIntent, DraftError>;
    fn pending_discard(&self) -> Result<Option<DiscardIntent>, DraftError>;
    fn replace_with_blank(&self) -> Result<SavedDraft, DraftError>;
    fn remove_ciphertext_and_intent_create_blank(
        &self,
        intent: &DiscardIntent,
    ) -> Result<DiscardOutcome, DraftError>;
    fn prepared_finalization_marker(&self)
        -> Result<Option<PreparedFinalizationMarker>, DraftError>;
    fn replace_prepared_finalization_marker(
        &self,
        marker: Option<PreparedFinalizationMarker>,
    ) -> Result<(), DraftError>;
    fn acquire_draft_lock(&self) -> Result<DraftLock, DraftError>;
}
```

The trait carries a write arm for both transition states, so neither Task 7 nor Task 11 has to amend a gated interface: `commit_discard_intent` is the durable step Task 7 crosses, and `replace_prepared_finalization_marker` is the single call site through which Task 11 sets and clears its marker — one call, so the mutual exclusion of the two states can never be split across two writes.

Every method is synchronous, exactly as all of Stage 1 is, so `Arc<dyn DraftRepository>` is trivially constructible; async exists only in `apps/desktop/src-tauri`, where each `#[tauri::command]` handler runs the synchronous core operation through `tauri::async_runtime::spawn_blocking`. `PreparedFinalizationMarker` is an opaque marker on the draft row: `ea-draft` never learns what a prepared finalization contains, and `ea-writer` therefore never becomes a dependency of the store layer. `DraftLock` is a RAII guard whose `Drop` releases the exclusive draft lock.

`save` is a revision compare-and-swap inside one transaction: it accepts only a draft whose read revision still matches the stored one, otherwise it returns `EA-DRAFT-REVISION-CONFLICT` and writes nothing. Two overlapping autosaves therefore cannot resurrect older content, and the reader always sees the winner.

- [ ] **Step 5: Implement the typed local audit service**

`LocalAuditService::record_signed` resolves the signer certificate and the operator binding from the verified session, encodes the core through `ea_format::encode_local_audit_core`, signs those exact bytes through the native provider with `ContentType::LocalAuditCbor` (`crates/ea-crypto/src/cose.rs:31`), wraps core and signature with `ea_format::encode_local_audit_event`, verifies the finished COSE before the commit, and flushes the transaction before returning. It has no free-text metadata API, no update and no delete API, and it formats errors without any event context.

The action enumeration is **not** redeclared here: `ea_format::LocalAuditActionV1` carries the twelve pinned discriminants of `schemas/reports/v1/local-audit.cddl:3`, and `ea_format::LocalAuditOutcomeV1` keeps `Failed = 0`, `Accepted = 1`, `Completed = 2` unchanged (`crates/ea-format/src/local_audit.rs:26-32`). A second type set is exactly how wrong bytes come into existence, and `tools/xtask/tests/spec_completeness.rs:31-37` rejects an action/context pair the grammar does not couple.

```rust
pub enum AuditActorProof<'a> {
    OperatorSession(&'a OperatorSessionProof),
    AuthenticatedDevice(&'a AuthenticatedDevice),
    Expired,
}

pub struct TypedLocalAuditEvent {
    pub action: ea_format::LocalAuditActionV1,
    pub outcome: ea_format::LocalAuditOutcomeV1,
}

pub trait LocalAuditService: Send + Sync {
    fn record_signed(
        &self,
        actor: AuditActorProof<'_>,
        event: TypedLocalAuditEvent,
    ) -> Result<SignedLocalAuditEvent, AuditError>;
}
```

Der Kontext reist in der Aktion: `ea_format::LocalAuditActionV1` bindet ihn variantenweise, und `ea-audit` deklariert keinen zweiten Kontexttyp. Die zwei Familien, deren Hashregeln erst spaeter berechenbar werden, binden ihre Aktionsvariante additiv in die Signatur- und Flush-Wege des Dienstes ein: `ArchiveProfileMigration` in Task 9 und `StaleRegistry` in Task 11, which is why both tasks carry `crates/ea-audit/src/event.rs` as `Modify`. The mapping from a variant to its wire tag is total and closed; there is no fallback arm, because Task 4 fixes it in `context_tag()`.

`AuditActorProof::OperatorSession` is required for successful privileged actions. `AuditActorProof::AuthenticatedDevice` exists only so that login and failed re-authentication can be recorded when no new operator proof is issued; it carries the verified device signer and an optional already-known binding hash, never an unchecked account value. `AuditActorProof::Expired` is the arm that a lapsed or lock-invalidated session collapses into, and it is refused with an error that names no event content — `TypedLocalAuditEvent::login_failed()` is the constructor the test uses for that path. `SignedLocalAuditEvent` exposes `exact_bytes` and `id` as read-only accessors; its constructor stays private, following the Stage 1 pattern of private constructors for proof-carrying types.

- [ ] **Step 6: Run restart, autosave-CAS, encryption, register and audit tests**

Run:

```bash
cargo test --locked -p ea-local-store && \
cargo test --locked -p ea-draft && \
cargo test --locked -p ea-audit && \
cargo test --locked -p ea-testkit && \
cargo test --locked -p xtask --test workspace
```

Expected: PASS; one draft survives restart, overlapping autosaves never resurrect old content, neither the main database file nor its WAL sidecar contains the canary, temp spill is confined to memory, the incident-number register refuses a second claim of the same key, the operator-profile row is readable and has no write path, the signed audit bytes validate against `schemas/reports/v1/local-audit.cddl`, and the workspace member count, member set and wasm32 classification match the state after this task.

- [ ] **Step 7: Commit encrypted draft storage**

```bash
git add crates/ea-local-store crates/ea-audit crates/ea-draft crates/ea-testkit tools/xtask Cargo.toml Cargo.lock
git commit -m "feat(writer): persist one encrypted autosaved draft"
```

### Task 7: Irreversible Draft Discard and Crash Resume (SYNTHESE.md: Task 4)

**Files:**
- Create: `crates/ea-draft/src/discard.rs`
- Create: `crates/ea-draft/src/fault.rs`
- Create: `crates/ea-local-store/migrations/0002_discard.sql`
- Create: `docs/traceability/stage-2-fault-points.json`
- Modify: `crates/ea-draft/src/lib.rs`
- Modify: `crates/ea-draft/src/repository.rs`
- Modify: `crates/ea-draft/Cargo.toml`
- Modify: `crates/ea-draft/tests/support/mod.rs`
- Modify: `crates/ea-local-store/src/migrations.rs`
- Modify: `Cargo.lock`
- Test: `crates/ea-draft/tests/discard_faults.rs`
- Test: `crates/ea-draft/tests/fault_point_manifest.rs`

**Interfaces:**
- Consumes: from Task 3 a fresh `OperatorSessionProof` for `ReauthPurpose::DiscardDraft`; from Task 2 `KeyProvider::{delete, contains}`; from Task 6 the exclusive `DraftLock` through `DraftRepository::acquire_draft_lock`, the trait arms `pending_discard`, `draft_dek_handle`, `remove_ciphertext_and_intent_create_blank`, `replace_with_blank` and `prepared_finalization_marker`, plus the migration registry.
- Produces: the discard service `DiscardService::{begin_discard, resume_discard}` in `crates/ea-draft/src/discard.rs`, `DiscardPhase` with its `ALL` array, `DiscardFaultPoint::ALL` and `RestartState::{OriginalDraftUnchanged, NewBlankDraft, PreparedFinalizationPending}` deriving `Debug`, `Eq` and `PartialEq` in `crates/ea-draft/src/fault.rs`, the three `DraftError` codes `EA-DRAFT-REAUTH-REQUIRED`, `EA-DRAFT-REAUTH-PURPOSE-MISMATCH` and `EA-DRAFT-PREPARED-FINALIZATION-PRESENT`, migration `0002_discard.sql` with the mutually exclusive draft-transition row, and, in the Stage 2 fault-point manifest `docs/traceability/stage-2-fault-points.json`, both the generated `discard` section and the hand-written `precedence` array carrying `PreparedFinalizationBeatsDiscardIntent`.

The discard state machine is a **service**, not a method of `DraftRepository`: it holds the repository and the key provider and orchestrates both. `begin_discard` and `resume_discard` each take a fresh `OperatorSessionProof` with `ReauthPurpose::DiscardDraft`; a proof of a different purpose is refused, because discard is irreversible on an unattended device exactly as finalization is (`design.md:256`, `:432`).

Discarding a draft is **not** an audit action. `local-audit-action-v1 = 0..11` is closed (`schemas/reports/v1/local-audit.cddl:3`) and carries no discard entry, so no thirteenth action is added and this task writes no audit row.

- [ ] **Step 0: Register the operator dependency and create the lockfile once**

Modify `crates/ea-draft/Cargo.toml`: add `ea-operator.workspace = true`. No new `[workspace.dependencies]` entry is required — `ea-operator = { path = "crates/ea-operator" }` already exists from Task 3. Adding the edge alone rewrites `Cargo.lock`.

Run: `cargo metadata --format-version 1 > /dev/null` (without `--locked`)

Expected: PASS; `Cargo.lock` afterwards records `ea-operator` as a dependency of `ea-draft`. Only then do the `--locked` commands of this task run.

- [ ] **Step 1: Write fault, re-authentication and precedence tests**

Extend `crates/ea-draft/tests/support/mod.rs`: `DraftHarness::with_nonempty_draft()` seeds one saved draft with content and keeps a copy of the database files as a simulated backup; `discard_with_fault(point)` runs a discard that aborts at exactly this fault point; `discard_up_to(phase)` runs a clean discard that stops after exactly this phase; `restart_and_resume()` reopens the store and runs the restart path; `restore_captured_backup()` puts the captured files back and reruns it; `discard_service()` hands out the service under test; `proof_for(purpose)` and `expired_proof()` mint the session proofs; `set_prepared_finalization_marker()` writes the marker through `DraftRepository`; `draft_dek_is_present()` and `pending_discard_is_absent()` read the two states the assertions need. Every harness keeps its own temporary root and takes the process-wide lock, following `tools/xtask/tests/stage_gate.rs:29-44`, so the tests serialize themselves and no `--test-threads` flag is needed.

`crates/ea-draft/tests/discard_faults.rs`:

```rust
#[test]
fn every_discard_fault_yields_old_draft_or_permanent_blank_draft() {
    for point in DiscardFaultPoint::ALL.iter().copied() {
        let mut h = DraftHarness::with_nonempty_draft();
        let _ = h.discard_with_fault(point);
        let first = h.restart_and_resume().unwrap();
        assert!(matches!(
            first,
            RestartState::OriginalDraftUnchanged | RestartState::NewBlankDraft
        ));
        let second = h.restart_and_resume().unwrap();
        assert_eq!(second, first, "ein zweites resume ist ein no-op: {point:?}");
        let restored = h.restore_captured_backup().unwrap();
        assert!(matches!(
            restored,
            RestartState::OriginalDraftUnchanged | RestartState::NewBlankDraft
        ));
    }
}

#[test]
fn every_discard_phase_has_its_own_restart_outcome() {
    for phase in DiscardPhase::ALL.iter().copied() {
        let mut h = DraftHarness::with_nonempty_draft();
        h.discard_up_to(phase).unwrap();
        let state = h.restart_and_resume().unwrap();
        let expected = match phase {
            DiscardPhase::Editable => RestartState::OriginalDraftUnchanged,
            DiscardPhase::IntentDurable
            | DiscardPhase::KeyAbsent
            | DiscardPhase::DraftRemoved => RestartState::NewBlankDraft,
        };
        assert_eq!(state, expected, "{phase:?}");
        assert!(!h.draft_dek_is_present() || phase == DiscardPhase::Editable);
    }
}

#[test]
fn discard_without_a_fresh_proof_is_rejected() {
    let h = DraftHarness::with_nonempty_draft();
    assert_eq!(
        h.discard_service().begin_discard(h.expired_proof()).unwrap_err().code(),
        "EA-DRAFT-REAUTH-REQUIRED"
    );
    assert_eq!(h.restart_and_resume().unwrap(), RestartState::OriginalDraftUnchanged);
}

#[test]
fn a_proof_of_another_purpose_never_authorizes_a_discard() {
    let h = DraftHarness::with_nonempty_draft();
    assert_eq!(
        h.discard_service()
            .begin_discard(h.proof_for(ReauthPurpose::Finalize))
            .unwrap_err()
            .code(),
        "EA-DRAFT-REAUTH-PURPOSE-MISMATCH"
    );
}

#[test]
fn a_prepared_finalization_takes_precedence_over_resume_discard() {
    let mut h = DraftHarness::with_nonempty_draft();
    h.set_prepared_finalization_marker();
    assert_eq!(
        h.discard_service()
            .begin_discard(h.proof_for(ReauthPurpose::DiscardDraft))
            .unwrap_err()
            .code(),
        "EA-DRAFT-PREPARED-FINALIZATION-PRESENT"
    );
    assert_eq!(
        h.restart_and_resume().unwrap(),
        RestartState::PreparedFinalizationPending
    );
    assert!(h.pending_discard_is_absent());
}
```

`crates/ea-draft/tests/fault_point_manifest.rs` regenerates the discard section of `docs/traceability/stage-2-fault-points.json` into a temporary buffer from `DiscardFaultPoint::ALL` and compares it byte for byte against the **`discard` array** of the checked-in file, so a new or renamed fault point that nobody declared fails `cargo test --workspace`; the `precedence` array is out of the generator's scope and is asserted by `a_prepared_finalization_takes_precedence_over_resume_discard`.

- [ ] **Step 2: Run the discard tests and verify intent and resumable deletion are absent**

Run: `cargo test --locked -p ea-draft --test discard_faults ; cargo test --locked -p ea-draft --test fault_point_manifest`

Expected: FAIL because the discard service, the durable discard intent, the fault points, the restart states and the fault-point manifest do not exist. The two commands are separated by `;` so that both gaps are evidenced.

- [ ] **Step 3: Add migration `0002_discard.sql`**

`0002_discard.sql` is a **new** migration file registered in `crates/ea-local-store/src/migrations.rs`; `0001_writer.sql` is already registered and is therefore not touched. It adds **one** table `draft_transition`, keyed by `draft_id`, with a `kind` column that is either the discard intent or the prepared-finalization marker, the captured `draftDEK` handle reference, and a `CHECK` constraint that admits exactly these two kinds. Because both states are rows of the same singleton table, at most one of them exists at any moment and the mutual exclusion of `discardIntent` and `PreparedFinalization` is declarative: it survives an implementer who forgets the lock, instead of resting on the transaction alone. `DraftRepository::commit_discard_intent` writes the first kind and `replace_prepared_finalization_marker` the second, which is why Task 11 needs no migration of its own for this.

- [ ] **Step 4: Implement the exact discard state machine**

```rust
pub enum DiscardPhase { Editable, IntentDurable, KeyAbsent, DraftRemoved }

pub fn resume_discard(&self, proof: &OperatorSessionProof) -> Result<DiscardOutcome, DraftError> {
    let _lock = self.repo.acquire_draft_lock()?;
    require_fresh_proof(proof, ReauthPurpose::DiscardDraft)?;
    if self.repo.prepared_finalization_marker()?.is_some() {
        return Err(DraftError::PreparedFinalizationPresent);
    }
    let intent = self.repo.pending_discard()?.ok_or(DraftError::NoPendingDiscard)?;
    let handle = intent.draft_dek_handle();
    self.key_provider.delete(handle)?;
    if self.key_provider.contains(handle)? {
        return Err(DraftError::KeyDeletionNotConfirmed);
    }
    self.repo.remove_ciphertext_and_intent_create_blank(&intent)
}
```

Under the exclusive draft lock, `begin_discard` durably commits the `discardIntent` with the draft ID **first**. Before that commit a crash changes nothing; after it, a restart no longer offers the draft for editing but continues the same operation (`design.md:432`). Then clear the UI and Rust buffers as far as possible, delete the `draftDEK` and confirm its absence, and transactionally remove ciphertext and intent and create a blank draft with a new ID and a new key. No sequence, no chain entry and no recoverable trash copy is allocated, and old database pages stay unreadable without the `draftDEK`.

A durable `PreparedFinalization` wins over discard at every entry point. `discardIntent` and the prepared-finalization marker exclude each other under the same exclusive draft lock, and on restart the prepared transaction has precedence: `resume_discard` runs only if no marker exists, because after the irreversible step the transaction MUST be completed from the prepared bytes (`design.md:456`, `:467`). The restart path reports that case as `RestartState::PreparedFinalizationPending`, and the named point of this rule is `PreparedFinalizationBeatsDiscardIntent`. `begin_discard` refuses with `EA-DRAFT-PREPARED-FINALIZATION-PRESENT` while a marker exists, a stale or lock-invalidated proof yields `EA-DRAFT-REAUTH-REQUIRED`, and a proof of any other purpose yields `EA-DRAFT-REAUTH-PURPOSE-MISMATCH`.

`crates/ea-draft/src/fault.rs` carries `DiscardFaultPoint::ALL` with one named variant before and after every durable step of the sequence above — intent commit, keystore delete, absence confirmation, ciphertext removal, blank-draft creation — plus `BackupRestoreAfterKeyDeletion`, mirroring the injection points the robustness promise enumerates (`design.md:2024`). `PreparedFinalizationBeatsDiscardIntent` is deliberately **not** a member of `DiscardFaultPoint::ALL`: every point of that array must restart into an unchanged draft or a permanent blank draft, while the precedence point restarts into `PreparedFinalizationPending` by design. It is a named point of the manifest carried by `a_prepared_finalization_takes_precedence_over_resume_discard`, and Task 11 and Task 18 refer to it by exactly that name. `RestartState` derives `Debug`, `Eq` and `PartialEq` so a second resume can be compared against the first. A restored Writer backup never yields a readable discarded draft: the `draftDEK` lives in a device-bound keystore entry that ordinary application and system backup excludes (`design.md:428`, `:1491`), so a restored database file finds no key.

- [ ] **Step 5: Declare the discard fault points in the Stage 2 manifest**

Write `docs/traceability/stage-2-fault-points.json` with the discard section generated from `DiscardFaultPoint::ALL` — each entry with its stable name and the durable step it brackets — **and a third array `precedence` carrying the single entry `PreparedFinalizationBeatsDiscardIntent` with the durable step it brackets; that entry is written by hand because it is deliberately not a member of `DiscardFaultPoint::ALL`.** The file is a checked-in artefact at a fixed repository-relative path, following the pattern of the format package (`tools/xtask/src/main.rs:907`), so that the Stage 2 gate of Task 17 can read the declared fault points without `tools/xtask/Cargo.toml` gaining a dependency on any Stage 2 crate. Task 11 extends the same file with the finalization section.

- [ ] **Step 6: Run all discard fault points, the proof tests and the precedence test**

Run: `cargo test --locked -p ea-draft && cargo test --locked -p ea-local-store`

Expected: PASS; a second resume is a no-op for every fault point, no discarded key becomes readable after a simulated backup restore, a discard without a fresh purpose-matching proof never begins, a durable prepared finalization always wins over a pending discard intent, and the checked-in fault-point manifest matches the declared points byte for byte.

- [ ] **Step 7: Commit discard recovery**

```bash
git add crates/ea-draft crates/ea-local-store docs/traceability/stage-2-fault-points.json Cargo.lock
git commit -m "feat(writer): make draft discard irreversible and resumable"
```

### Task 8: Master Data, CSV Dry Run, and Immutable Snapshots (SYNTHESE.md: Task 5)

**Files:**
- Create: `schemas/reports/v1/import-report.cddl`
- Create: `crates/ea-format/src/import_report.rs`
- Create: `crates/ea-draft/src/master_data.rs`
- Create: `crates/ea-draft/src/csv_import.rs`
- Create: `crates/ea-local-store/migrations/0003_master_data.sql`
- Create: `vectors/reports/import-report-v1/manifest.json`
- Create: `vectors/reports/import-report-v1/import-report/persons-two-issues-in-one-row.bin`
- Modify: `crates/ea-format/src/lib.rs`
- Modify: `crates/ea-draft/src/lib.rs`
- Modify: `crates/ea-draft/Cargo.toml`
- Modify: `crates/ea-draft/tests/support/mod.rs`
- Modify: `crates/ea-local-store/src/migrations.rs`
- Modify: `tools/xtask/src/main.rs`
- Modify: `tools/xtask/tests/spec_completeness.rs`
- Modify: `docs/superpowers/specs/2026-08-14-einsatzarchiv-v0-1-payload-wire-addendum.md`
- Modify: `Cargo.lock`
- Test: `crates/ea-format/tests/import_report_bytes.rs`
- Test: `crates/ea-draft/tests/csv_import.rs`
- Test: `crates/ea-draft/tests/snapshots.rs`

`tools/xtask/src/main.rs` appears here only to register the new normative grammar in `validate_schemas` — `validate_schemas` is a hardcoded path list (`tools/xtask/src/main.rs:780-846`) with no directory scanner, so an unregistered `.cddl` file is inert. This task adds no workspace member and therefore touches neither the wasm32 lists nor `tools/xtask/tests/workspace.rs`. `crates/ea-format` stays on the wasm32 positive list (`tools/xtask/src/main.rs:57-84`): `import_report.rs` is pure deterministic CBOR with no `std::fs` and no host API.

**Interfaces:**
- Consumes: `ea_schema::{PersonnelSnapshotV1, VehicleSnapshotV1, MasterDataRevisionV1, ImportedProvenanceV1}` — the closed Stage 1 unions stay unchanged and are never re-declared (`crates/ea-schema/src/model.rs:847-859`, `:943-957`, `:789-810`, `:812-829`); the encrypted local store and its migration registry from Task 6; `ea_crypto::object_hash` (`crates/ea-crypto/src/digest.rs:63-66`); `ea_cbor::{canonical_reencode, ParserLimits}` (`crates/ea-cbor/src/lib.rs:9-11`).
- Produces: `MasterDataRepository`, `CsvImporter::{dry_run,commit}`, `ImportReportV1` with the read-only accessors `exact_bytes(&self) -> &[u8]` and `import_protocol_hash(&self) -> ObjectHash` (constructor stays private), the closed `ImportIssueCodeV1`, `ImportSourceKindV1`, and `ea_format::encode_import_report`. Ad-hoc entries are produced as `PersonnelSnapshotV1::AdHoc` and `VehicleSnapshotV1::AdHoc`, never as a type of their own.

The `importProtocolHash` at the mandatory position `imported-provenance-v1` (`schemas/payload/v1/payload.cddl:125-129`, `schemas/payload/v1/incident.schema.json:152-160`) needs a canonical preimage, otherwise a guessed 32-byte value is sealed irreversibly in Task 11. This task creates that preimage as `import-report-v1` and reuses the existing object convention `SHA-256("EINSATZARCHIV-OBJECT-v1" || exactObjectBytes)` (`crates/ea-crypto/src/digest.rs:21`, `:63-66`); **no new domain constant is introduced**, so the frozen domain-string family and every existing vector stay untouched.

Incident-number uniqueness sits on three clearly separated levels and none of them is this task's: the **store** level owns the register with the `UNIQUE` constraint over `(organizationId, localCivilYear, NFC-UTF-8 bytes of humanIncidentNumber)` in `0001_writer.sql` from Task 6 — a registered migration is never rewritten, which is why `0003_master_data.sql` must not host it; the **snapshot** level never carries an incident number at all (`personnel-snapshot-v1` and `vehicle-snapshot-v1` have no such position, `schemas/payload/v1/payload.cddl:131-142`); and **finalization** claims the key under the exclusive Writer lock before validate-and-serialize in Task 11 (`docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md:373`, `docs/superpowers/specs/2026-08-14-einsatzarchiv-v0-1-payload-wire-addendum.md:289`). What this task owes is the negative: the import path can neither mint nor transport an incident number, and Step 1 asserts it.

- [ ] **Step 0: Register the workspace dependency and create the lockfile once**

Modify: `crates/ea-draft/Cargo.toml` — add `ea-format.workspace = true`. No new `[workspace.dependencies]` entry is required: `ea-format = { path = "crates/ea-format" }` already exists (`Cargo.toml:23`). Adding the edge alone rewrites `Cargo.lock`.

Run: `cargo metadata --format-version 1 > /dev/null` (without `--locked`)

Expected: PASS; `Cargo.lock` afterwards records `ea-format` as a dependency of `ea-draft`. Only then do the `--locked` commands of this task run.

- [ ] **Step 1: Write the preimage, CSV transaction, and snapshot immutability tests**

`crates/ea-format/tests/import_report_bytes.rs`:

```rust
#[test]
fn import_report_bytes_are_canonical_and_hash_over_the_object_domain() {
    let report = support::persons_report_with_two_issues_in_one_row();
    let bytes = ea_format::encode_import_report(&report).unwrap();
    assert_eq!(bytes, ea_format::encode_import_report(&report).unwrap());
    assert_eq!(
        ea_cbor::canonical_reencode(&bytes, ea_cbor::ParserLimits::V1).unwrap(),
        bytes
    );
    assert_eq!(report.import_protocol_hash(), ea_crypto::object_hash(&bytes));
}

#[test]
fn issue_lists_sort_by_row_then_column_then_code_with_null_column_first() {
    let report = support::persons_report_with_shuffled_issues();
    let issues = report.errors_on_the_wire();
    let keys: Vec<(u64, Option<&str>, u32)> =
        issues.iter().map(|i| (i.row(), i.column(), i.code() as u32)).collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
    assert_eq!(keys[0], (0, None, 0));
}

#[test]
fn issue_codes_keep_their_pinned_discriminants() {
    let discriminants: Vec<u32> =
        ImportIssueCodeV1::ALL.iter().map(|code| *code as u32).collect();
    assert_eq!(discriminants, (0..=12).collect::<Vec<u32>>());
}
```

`crates/ea-draft/tests/csv_import.rs`:

```rust
#[test]
fn dry_run_does_not_write_and_commit_is_all_or_nothing() {
    let harness = ImportHarness::new();
    let (importer, repo) = (harness.importer(), harness.master_data_repo());
    let csv = b"id,display_name,role,active\np1,Ada,Fuehrung,true\nbad,,X,true\n";
    let report = importer.dry_run(ImportSourceKindV1::Persons, csv).unwrap();
    assert_eq!((report.accepted(), report.errors().len()), (1, 1));
    assert_eq!(repo.person_count().unwrap(), 0);
    assert!(importer.commit(&report, csv).is_err());
    assert_eq!(repo.person_count().unwrap(), 0);
}

#[test]
fn vehicle_csv_accepts_its_own_header_and_rejects_the_person_header() {
    let harness = ImportHarness::new();
    let importer = harness.importer();
    let vehicles = b"id,display_name,radio_call_sign,license_plate,active\n\
                     v1,MTW,Rotkreuz 1,HH-DRK 1,true\n";
    assert_eq!(
        importer.dry_run(ImportSourceKindV1::Vehicles, vehicles).unwrap().accepted(),
        1
    );
    let persons_header = b"id,display_name,role,active\np1,Ada,Fuehrung,true\n";
    assert!(matches!(
        importer.dry_run(ImportSourceKindV1::Vehicles, persons_header).unwrap_err(),
        ImportError::UnknownHeader { .. }
    ));
}

#[test]
fn commit_rejects_a_mutated_dry_run_hash() {
    let harness = ImportHarness::new();
    let (importer, repo) = (harness.importer(), harness.master_data_repo());
    let mut csv = b"id,display_name,role,active\np1,Ada,Fuehrung,true\n".to_vec();
    let first = importer.dry_run(ImportSourceKindV1::Persons, &csv).unwrap();
    csv[29] = b'B';
    let second = importer.dry_run(ImportSourceKindV1::Persons, &csv).unwrap();
    assert_ne!(first.input_file_hash(), second.input_file_hash());
    assert!(importer.commit(&first, &csv).is_err());
    assert_eq!(repo.person_count().unwrap(), 0);
}

#[test]
fn retained_protocol_bytes_reproduce_the_snapshot_hash() {
    let harness = ImportHarness::new();
    let (importer, repo) = (harness.importer(), harness.master_data_repo());
    let csv = b"id,display_name,role,active\np1,Ada,Fuehrung,true\n";
    let report = importer.dry_run(ImportSourceKindV1::Persons, csv).unwrap();
    importer.commit(&report, csv).unwrap();
    let snapshot = repo.snapshot_person("p1").unwrap();
    let hash = snapshot.imported_provenance().unwrap().import_protocol_hash();
    let retained = repo.import_report_bytes(&hash).unwrap().unwrap();
    assert_eq!(retained, report.exact_bytes());
    assert_eq!(ea_crypto::object_hash(&retained), hash);
}

#[test]
fn csv_import_can_neither_mint_nor_carry_an_incident_number() {
    let harness = ImportHarness::new();
    let (importer, repo) = (harness.importer(), harness.master_data_repo());
    let persons = b"id,display_name,role,active\np1,Ada,Fuehrung,true\n";
    let vehicles = b"id,display_name,radio_call_sign,license_plate,active\n\
                     v1,MTW,Rotkreuz 1,HH-DRK 1,true\n";
    importer.commit(&importer.dry_run(ImportSourceKindV1::Persons, persons).unwrap(), persons).unwrap();
    importer.commit(&importer.dry_run(ImportSourceKindV1::Vehicles, vehicles).unwrap(), vehicles).unwrap();
    assert_eq!(harness.consumed_incident_number_count(), 0);
    assert_eq!(
        CsvImporter::ACCEPTED_HEADERS,
        [
            "id,display_name,role,active",
            "id,display_name,radio_call_sign,license_plate,active"
        ]
    );
    assert_eq!(repo.person_count().unwrap(), 1);
}
```

`crates/ea-draft/tests/snapshots.rs`:

```rust
#[test]
fn later_master_change_does_not_modify_captured_snapshot() {
    let harness = ImportHarness::new();
    let repo = harness.master_data_repo();
    harness.import_persons(b"id,display_name,role,active\np1,Ada,Fuehrung,true\n");
    let captured = repo.snapshot_person("p1").unwrap();
    assert_eq!(captured.display_name(), "Ada");
    assert_eq!(captured.revision().unwrap().revision_number(), Some(1));
    repo.rename_person("p1", "Neue Anzeige").unwrap();
    let reread = repo.snapshot_person("p1").unwrap();
    assert_ne!(captured.display_name(), reread.display_name());
    assert_eq!(reread.revision().unwrap().revision_number(), Some(2));
}

#[test]
fn imported_snapshot_carries_full_provenance_and_adhoc_carries_none() {
    let harness = ImportHarness::new();
    let repo = harness.master_data_repo();
    let report = harness.import_persons(b"id,display_name,role,active\np1,Ada,Fuehrung,true\n");
    let imported = repo.snapshot_person("p1").unwrap();
    let provenance = imported.imported_provenance().unwrap();
    assert_eq!(provenance.source_id(), "csv-persons");
    assert_eq!(provenance.source_format_version(), 1);
    assert_eq!(provenance.import_protocol_hash(), report.import_protocol_hash());

    let adhoc = repo.ad_hoc_person("Externer Helfer", None).unwrap();
    assert!(matches!(adhoc, PersonnelSnapshotV1::AdHoc { .. }));
    assert!(adhoc.revision().is_none());
    assert!(adhoc.imported_provenance().is_none());
    assert_eq!(repo.person_count().unwrap(), 1);
}
```

- [ ] **Step 2: Run the new tests and verify grammar, encoder, and master data are absent**

Run: `cargo test --locked -p ea-format --test import_report_bytes ; cargo test --locked -p ea-draft --test csv_import --test snapshots`

Expected: FAIL because `import-report-v1`, `encode_import_report`, `MasterDataRepository`, and the import reports do not exist. Both commands are separated by `;`, not `&&`, so the second failure is observed as well.

- [ ] **Step 3: Freeze `import-report-v1` as the normative preimage**

Write `schemas/reports/v1/import-report.cddl` with a fixed array order, deterministic CBOR only (no indefinite-length items, no floats, no duplicate map keys):

```cddl
; Kanonisches Urbild des importProtocolHash. Bleibt lokal, wird nie archiviert.
import-report-v1 = [
  1,                                 ; report-version, fest
  source-kind: 0 / 1,                ; 0 = persons, 1 = vehicles
  source-id: tstr,                   ; identisch mit provenance.sourceId
  source-format-version: uint,       ; identisch mit provenance.sourceFormatVersion
  input-file-hash: bstr .size 32,    ; SHA-256 der EXAKTEN Eingabebytes, ohne Domain
  header-line: tstr,                 ; exakte akzeptierte Headerzeile
  imported-at: int,                  ; Epoch-Millis, i64
  row-count-total: uint,
  row-count-accepted: uint,
  row-count-rejected: uint,
  warnings: [* import-issue-v1],
  errors:   [* import-issue-v1]
]

import-issue-v1 = [
  row: uint,                         ; 1-basiert, 0 = dateiweit
  column: tstr / null,               ; exakter Headername oder null
  code: import-issue-code-v1
]

import-issue-code-v1 = 0..12
```

Writing `code: import-issue-code-v1` with `import-issue-code-v1 = 0..12` is a deliberate precision, not a deviation from the preimage taken over verbatim: `blocker-import-protokoll-hash.md:241` writes `code: uint` and calls it a closed error code only in its comment; naming the closed range in the grammar moves that closure from the comment into the validated contract, so `cddl_cat::validate_cbor_bytes` and not only the encoder rejects an unpinned code. The closed code space is pinned with explicit discriminants in `crates/ea-format/src/import_report.rs`, exactly as `local-audit-event-v1` pins `0..11`; without pinned codes the hash is not reproducible and the whole preimage is pointless. Errors are `0` `byte-order-mark-present`, `1` `input-not-utf8`, `2` `unknown-header`, `3` `duplicate-header-column`, `4` `access-format-detected`, `5` `field-count-mismatch`, `6` `empty-required-value`, `7` `invalid-boolean`, `8` `duplicate-master-id`, `9` `value-not-in-closed-set`, `10` `value-too-long`; warnings are `11` `inactive-row-imported` and `12` `trailing-empty-line-skipped`. The classification error-versus-warning is fixed per code and never per call site. Codes `0..4` are file-wide and carry `row = 0` and `column = null`.

Canonicalization rules, so that two implementations produce the same bytes:

1. Fixed array order as above; no position is optional and none may be omitted.
2. `warnings` and `errors` sort ascending by `(row, column, code)`, with a `null` column before every `tstr` and byte-wise `column` comparison. This is the single deviation from author order and exists for reproducibility.
3. `input-file-hash` is a raw, domain-free `SHA-256` over the exact input bytes — the same value the dry run reports, so commit equality and protocol content use one number.
4. `header-line` carries no BOM and no line terminator; the BOM rejection of Step 4 stays in force.
5. Text positions are NFC-normalized like `normalize_text` (`crates/ea-schema/src/model.rs:1524-1526`).
6. `source-id` is `"csv-persons"` or `"csv-vehicles"` and `source-format-version` is `1`. The source ID names the import source, not a master row — the frozen vector `vectors/format/payload-v1/incident.hex` carries `["csv-vehicles", 1, h'81…81']` in exactly this position.

Add `encode_import_report(&ImportReportV1) -> Result<Vec<u8>, FormatError>` in `crates/ea-format/src/import_report.rs`, exported next to the six existing `encode_*` functions (`crates/ea-format/src/lib.rs:39-46`). The encoder lives in `ea-format` and not in `ea-draft` because `ea-format` already owns the deterministic encoders and the frozen wire types; a second type set is precisely how wrong bytes come into existence. `ImportReportV1::import_protocol_hash` is defined as `ea_crypto::object_hash(exact import-report-v1 bytes)` and is computed nowhere else.

Register the grammar and the vector in the existing gate machinery: `validate_schemas` reads and validates `schemas/reports/v1/import-report.cddl` following the pattern of the audit grammar (`tools/xtask/src/main.rs:805-808`), and drives `vectors/reports/import-report-v1/` through `ea_cbor::validate` plus `cddl_cat::validate_cbor_bytes("import-report-v1", …)` following the payload-vector path (`tools/xtask/src/main.rs:772-776`). `tools/xtask/tests/spec_completeness.rs` gets a test that the grammar carries all twelve positions in this order and rejects a report with a thirteenth position or an unpinned code.

Write the additive vector family `vectors/reports/import-report-v1/` after the model of `vectors/receipts/v1/manifest.json` plus `vectors/receipts/v1/receipt/*.bin`: one `.bin` with the exact bytes and a `manifest.json` entry with `name`, `file`, `fileSha256`, `objectBytes`, `intermediateDigests.objectHash` (the expected `importProtocolHash`) and `expectedOutcome`. Nothing under `vectors/` is regenerated, re-sorted, or reformatted and no existing manifest expectation is touched — the family is new next to the existing ones, which is what `docs/traceability/stage-1-gate.md:115-121` provides for. `STAGE_ONE_VECTOR_FAMILIES` (`tools/xtask/src/main.rs:866-868`) stays unchanged; Task 17 registers `reports` as a Stage 2 family, and `family_carries_a_manifest` finds the manifest at depth 2 (`tools/xtask/src/main.rs:1372-1394`).

Finally add two normative lines to `docs/superpowers/specs/2026-08-14-einsatzarchiv-v0-1-payload-wire-addendum.md`: `schemas/reports/v1/import-report.cddl` joins the machine-readable parts of the contract next to `schemas/payload/v1/payload.cddl` (addendum `:8-9`), and the computation rule joins the `importedProvenance` paragraph (addendum `:151-153`):

```text
importProtocolHash = SHA-256("EINSATZARCHIV-OBJECT-v1" || exactImportReportV1Bytes)
```

- [ ] **Step 4: Implement documented UTF-8 imports, retained protocol bytes, and snapshot provenance**

`0003_master_data.sql` is a **new** migration file registered in `crates/ea-local-store/src/migrations.rs`; an already registered migration is never rewritten afterwards, so neither `0001_writer.sql` nor `0002_discard.sql` is touched. It creates the person and vehicle master tables, each with `revision INTEGER NOT NULL`, and the retention table for the preimage:

```sql
CREATE TABLE import_report (
  import_protocol_hash BLOB PRIMARY KEY NOT NULL,
  exact_bytes          BLOB NOT NULL,
  source_kind          INTEGER NOT NULL,
  imported_at          INTEGER NOT NULL
) STRICT;
```

The exact `import-report-v1` bytes are kept inside the encrypted local database, never as a file next to it, so no plaintext temp file is created; `MasterDataRepository::import_report_bytes(&ObjectHash) -> Result<Option<Vec<u8>>, MasterDataError>` is the only read path. Without this retention the hash in a sealed snapshot has no verifiable preimage and the provenance promise cannot be honoured even with the rule defined.

Accept exactly `id,display_name,role,active` for people and `id,display_name,radio_call_sign,license_plate,active` for vehicles. Reject BOM ambiguity, invalid UTF-8, duplicate and unknown headers, duplicate IDs, invalid booleans, empty required values, and Access formats. Dry run hashes the exact input and returns format version, row counts, warnings, and errors without writing. `errors()` contains exactly one entry per faulty row and enumerates every violation of that row inside this entry; on the wire, `errors` carries one `import-issue-v1` per violation, which is what the fixed `(row, column, code)` triple and its sort key require — the row-grouped view and the per-violation bytes are two projections of one list, and `errors_on_the_wire()` exposes the second one for the byte tests. Commit accepts only an unchanged, error-free dry-run hash and writes one transaction.

The mandatory `revision` position of a master snapshot (`crates/ea-schema/src/model.rs:852`, constructor `:862-868`, vehicles `:949`) is produced from the monotone `revision` column of the master table, never from the CSV: the spec freezes both headers without a revision column, so the value cannot be read from the file. A committed import sets `revision = 1` for every newly inserted row, and every mutation — `rename_person` among them — increments the column by exactly one and returns the new value. The wire arm is `[0, revision-number]`, tag `0` (`schemas/payload/v1/payload.cddl:121-123`), so `MasterDataRevisionV1::RevisionNumber` is used and `MasterDataRevisionV1::ChangedAt` never appears in Writer-produced snapshots.

Captured imported snapshots carry source ID, import format version, import protocol hash, and revision as `PersonnelSnapshotV1::Master` and `VehicleSnapshotV1::Master`. Ad-hoc entries are `PersonnelSnapshotV1::AdHoc` and `VehicleSnapshotV1::AdHoc`, create no master row, and are structurally recognizable rather than flagged by a boolean: `revision()` and `imported_provenance()` both return `None` for them (`crates/ea-schema/src/model.rs:924-928`, `:931-937`), which fully carries the visible marking Task 16 renders.

- [ ] **Step 5: Run the preimage, grammar, and vector checks**

Run: `cargo test --locked -p ea-format --test import_report_bytes && cargo run --locked -p xtask -- validate-schemas && cargo test --locked -p xtask --test spec_completeness`

Expected: PASS; the encoded bytes are canonical, satisfy `import-report-v1`, match the committed vector byte for byte, and the recomputed `objectHash` equals the manifest expectation. No existing vector file and no existing manifest expectation changed.

- [ ] **Step 6: Run import, rollback, provenance, and immutability tests**

Run: `cargo test --locked -p ea-draft --test csv_import --test snapshots`

Expected: PASS; the APIs offer no way to import a completed incident history — `CsvImporter` accepts only the two master-data headers from Step 4, mints no incident number, and leaves the incident-number register untouched. The retained protocol bytes reproduce the hash stored in the snapshot.

- [ ] **Step 7: Commit master data, CSV import, and the import-report preimage**

```bash
git add schemas/reports/v1/import-report.cddl \
        vectors/reports/import-report-v1/manifest.json \
        vectors/reports/import-report-v1/import-report/persons-two-issues-in-one-row.bin \
        crates/ea-format/src/import_report.rs \
        crates/ea-format/src/lib.rs \
        crates/ea-format/tests/import_report_bytes.rs \
        crates/ea-draft/src/master_data.rs \
        crates/ea-draft/src/csv_import.rs \
        crates/ea-draft/src/lib.rs \
        crates/ea-draft/Cargo.toml \
        crates/ea-draft/tests/support/mod.rs \
        crates/ea-draft/tests/csv_import.rs \
        crates/ea-draft/tests/snapshots.rs \
        crates/ea-local-store/migrations/0003_master_data.sql \
        crates/ea-local-store/src/migrations.rs \
        tools/xtask/src/main.rs \
        tools/xtask/tests/spec_completeness.rs \
        docs/superpowers/specs/2026-08-14-einsatzarchiv-v0-1-payload-wire-addendum.md \
        Cargo.lock
git commit -m "feat(writer): add master data, transactional CSV import, and the import-report preimage"
```

After this task AK 28 (`docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md:2139`, provenance promise `:404`) is evidenced by four artefacts: `retained_protocol_bytes_reproduce_the_snapshot_hash` and `imported_snapshot_carries_full_provenance_and_adhoc_carries_none` bind a sealed snapshot back to its retained preimage; `dry_run_does_not_write_and_commit_is_all_or_nothing` plus `commit_rejects_a_mutated_dry_run_hash` cover dry run, hash, and transaction; `csv_import_can_neither_mint_nor_carry_an_incident_number` covers "no historical incidents"; and `vectors/reports/import-report-v1/manifest.json` fixes the byte shape against which any second implementation can recompute. The ledger row `docs/traceability/v0.1-requirements.csv:29` is written by Task 18 alone; this task changes no traceability file.

### Task 9: Durable Archive Backends, Health Check, and Atomic Profile Migration (SYNTHESE.md: Task 6)

**Files:**
- Create: `crates/ea-archive-fs/Cargo.toml`
- Create: `crates/ea-archive-fs/src/lib.rs`
- Create: `crates/ea-archive-fs/src/local_path.rs`
- Create: `crates/ea-archive-fs/src/controlled_network.rs`
- Create: `crates/ea-archive-fs/src/publication_queue.rs`
- Create: `crates/ea-archive-fs/src/health.rs`
- Create: `crates/ea-archive-fs/src/profile_migration.rs`
- Create: `crates/ea-archive/src/backend.rs`
- Create: `crates/ea-archive/src/backend_error.rs`
- Create: `crates/ea-archive/src/path.rs`
- Create: `crates/ea-archive/src/lock.rs`
- Create: `crates/ea-archive/src/transaction.rs`
- Create: `crates/ea-archive/src/profile.rs`
- Create: `crates/ea-format/src/archive_profile.rs`
- Create: `schemas/archive/v1/archive-profile.cddl`
- Modify: `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-wire-format-addendum.md`
- Modify: `crates/ea-crypto/src/digest.rs`
- Modify: `crates/ea-crypto/src/lib.rs`
- Modify: `crates/ea-format/src/local_audit.rs`
- Modify: `crates/ea-format/src/object.rs`
- Modify: `crates/ea-format/src/lib.rs`
- Modify: `crates/ea-archive/src/lib.rs`
- Modify: `crates/ea-archive/Cargo.toml`
- Modify: `crates/ea-archive/tests/support/mod.rs`
- Modify: `crates/ea-audit/src/event.rs`
- Modify: `crates/ea-testkit/src/lib.rs`
- Modify: `tools/xtask/src/main.rs`
- Modify: `tools/xtask/tests/schema_validation.rs`
- Modify: `tools/xtask/tests/spec_completeness.rs`
- Modify: `tools/xtask/tests/workspace.rs`
- Modify: `tests/ea-system-tests/tests/conformance_golden_vectors.rs`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `crates/ea-archive-fs/tests/support/mod.rs`
- Test: `crates/ea-format/tests/archive_profile.rs`
- Test: `crates/ea-archive/tests/transaction_stages.rs`
- Test: `crates/ea-archive-fs/tests/backend_capabilities.rs`
- Test: `crates/ea-archive-fs/tests/health_report.rs`
- Test: `crates/ea-archive-fs/tests/controlled_network_profile.rs`
- Test: `crates/ea-archive-fs/tests/publication_queue.rs`
- Test: `crates/ea-archive-fs/tests/profile_migration.rs`

**Interfaces:**
- Consumes: Stage 1 exact bytes through the public `encode_*` surface (`crates/ea-format/src/lib.rs:39-45`); the read port `ArchiveSource` and the inventory `ArchiveInventory` (`crates/ea-archive/src/source.rs:67-72`, `crates/ea-archive/src/inventory.rs:220-301`, re-exports `crates/ea-archive/src/lib.rs:46-47`); the offline verifier `ea-verify`; `object_hash` (`crates/ea-crypto/src/digest.rs:63-66`); the bound policy field `allowed_archive_profile_hashes` (`crates/ea-format/src/etb.rs:222`, sorting enforced `:1616`) reached through the selected Registry head of Task 3; a fresh `OperatorSessionProof` for `ReauthPurpose::ArchiveProfileMigration` from Task 3; `LocalAuditService::record_signed` from Task 6; and the `local-audit-event-v1` encoder from Task 4.
- Produces: `ArchiveBackend`, `ArchiveBackendError`, `ArchivePath`, `WriterLock`, `ArchiveTransaction` and `ArchiveBackendProfileV1::{LocalPath,ControlledNetworkPath}` in `crates/ea-archive`; `LocalPathBackend`, `ControlledNetworkBackend`, `ArchiveHealthReport` and `ProfileMigrator` in `crates/ea-archive-fs`; `PublicationQueue` together with the two closed enums `SyncStatus` — carrying the four normative states `lokal gesichert`, `Upload ausstehend`, `synchronisiert`, `Fehler` — and `DetailCause`, both defined in `crates/ea-archive-fs/src/publication_queue.rs` and re-used unchanged by `ea-writer` and `ea-ui-contracts`; `MigrationFaultPoint::ALL` in `crates/ea-archive-fs/src/profile_migration.rs`, mit einer benannten Variante vor und nach jedem dauerhaften Schritt der Migration; plus die `#[cfg(any(test, feature = "test-support"))]`-Leseflaeche von `LocalPathBackend`: `exists_for_test`, `directory_exists_for_test`, `read_for_test`, `relative_paths_below_for_test`, `overwrite_for_test` und `as_archive_source`, die Task 10 und Task 12 als Beobachtungsflaeche benutzen; the three deterministic-CBOR preimages `ArchiveBackendProfileCoreV1`, `ArchiveInventoryListV1`, `ActiveProfilePointerCoreV1` plus the encoder `encode_archive_profile_migration_context` for the Task 4 audit context `ArchiveProfileMigrationContextV1` in `ea-format`, together with the two additional `FormatError` codes `EA-FORMAT-INVENTORY-DUPLICATE` and `EA-FORMAT-INVENTORY-PATH` on the closed error enum (`crates/ea-format/src/object.rs:11-33`, `:37`); and the three domain-separated digests `archive_profile_digest`, `archive_inventory_digest`, `active_profile_pointer_digest` in `ea-crypto`.

`crates/ea-archive` keeps only target-independent ports and touches no `std::fs`, exactly as its own module contract already states (`crates/ea-archive/src/source.rs:65-66`); it therefore stays on the wasm32 positive list (`tools/xtask/src/main.rs:78-79`), whose text is frozen by the closed Stage 1 gate (`docs/traceability/stage-1-gate.md:60-65`). Every host implementation lives in the new crate `crates/ea-archive-fs`, which alone depends on `ea-verify`; the reverse direction stays forbidden because `crates/ea-verify/Cargo.toml:9` already depends on `ea-archive` and a dependency from `ea-archive` on `ea-verify` would be a Cargo cycle.

- [ ] **Step 0: Register the workspace member and create the lockfile once**

Create `crates/ea-archive-fs/Cargo.toml` and an empty `crates/ea-archive-fs/src/lib.rs` so that the member path resolves. Modify `Cargo.toml`: add `crates/ea-archive-fs` under `[workspace]members` and the path entry `ea-archive-fs = { path = "crates/ea-archive-fs" }` under `[workspace.dependencies]`, following the existing `ea-*` path entries (`Cargo.toml:18-29`). The crate manifest references `ea-archive`, `ea-format`, `ea-crypto`, `ea-types`, `ea-trust` and `ea-verify` with `workspace = true`, which `tools/xtask/tests/workspace.rs:90-101` enforces.

Modify `tools/xtask/src/main.rs`: append one `(name, justification)` pair for `ea-archive-fs` with a non-empty justification to the `WASM32_EXEMPT_CRATES` slice (`tools/xtask/src/main.rs:102`, a slice since Task 1, so no arity edit exists to make), following the `ea-recovery` precedent (`tools/xtask/src/main.rs:103-111`). The justification is the same one the exception list already documents in prose (`tools/xtask/src/main.rs:89-96`): this crate carries filesystem-backed create-if-absent, flush, same-filesystem rename and exclusive locking on top of `std::fs`, so it reaches past `ea-verify` and is not shared browser code. **Never** the wasm32 positive list. Modify `tools/xtask/tests/workspace.rs`: append the member path to `WORKSPACE_MEMBERS` (Task 1) and nowhere else — the length assertion, the set comparison and the dependency walk all derive from that one list; the classification test (`:220-245`) then holds without further change.

Run: `cargo metadata --format-version 1 > /dev/null` (without `--locked`)

Expected: PASS; `Cargo.lock` afterwards contains the new package. Only then do the `--locked` commands of this task run.

- [ ] **Step 1: Write the profile, inventory, and pointer preimage tests**

`crates/ea-format/tests/archive_profile.rs` pins the three preimages and the migration audit context; the digest values are compared against the freshly computed digest of the encoded bytes, never against a literal, so the test states the rule and not a transcription of it.

```rust
#[test]
fn a_local_path_profile_hashes_over_the_fifteen_positions_and_never_over_a_path() {
    let core = support::local_path_profile_core();
    let bytes = ea_format::encode_archive_backend_profile_core(&core).unwrap();
    assert_eq!(
        ea_crypto::archive_profile_digest(&bytes),
        support::expected_profile_digest(&bytes)
    );
    assert!(!ea_testkit::contains_canary(&bytes, b"CANARY-OUTPUT-PATH"));
    assert!(!ea_testkit::contains_canary(&bytes, b"CANARY-HOSTNAME"));
    assert!(!ea_testkit::contains_canary(&bytes, b"CANARY-ACCOUNT"));
}

#[test]
fn a_controlled_network_profile_differs_from_the_local_profile_in_its_hash() {
    let local = ea_format::encode_archive_backend_profile_core(&support::local_path_profile_core()).unwrap();
    let network = ea_format::encode_archive_backend_profile_core(&support::controlled_network_profile_core()).unwrap();
    assert_ne!(
        ea_crypto::archive_profile_digest(&local),
        ea_crypto::archive_profile_digest(&network)
    );
}

#[test]
fn the_inventory_list_is_root_relative_sorted_and_duplicate_free() {
    let unsorted = support::inventory_entries_in_reverse_order();
    let list = ea_format::ArchiveInventoryListV1::new(unsorted).unwrap();
    let bytes = ea_format::encode_archive_inventory_list(&list).unwrap();
    assert_eq!(
        ea_crypto::archive_inventory_digest(&bytes),
        ea_crypto::archive_inventory_digest(
            &ea_format::encode_archive_inventory_list(
                &ea_format::ArchiveInventoryListV1::new(support::inventory_entries_sorted()).unwrap()
            )
            .unwrap()
        )
    );
    assert_eq!(
        ea_format::ArchiveInventoryListV1::new(support::inventory_entries_with_duplicate())
            .unwrap_err()
            .code(),
        "EA-FORMAT-INVENTORY-DUPLICATE"
    );
    assert_eq!(
        ea_format::ArchiveInventoryListV1::new(support::inventory_entries_with_absolute_path())
            .unwrap_err()
            .code(),
        "EA-FORMAT-INVENTORY-PATH"
    );
}

#[test]
fn the_active_pointer_hash_changes_with_every_generation() {
    let first = support::active_pointer_core(support::TARGET_PROFILE_HASH, 1);
    let second = support::active_pointer_core(support::TARGET_PROFILE_HASH, 2);
    assert_ne!(
        ea_crypto::active_profile_pointer_digest(&ea_format::encode_active_profile_pointer_core(&first).unwrap()),
        ea_crypto::active_profile_pointer_digest(&ea_format::encode_active_profile_pointer_core(&second).unwrap())
    );
}

#[test]
fn the_migration_audit_context_carries_only_the_four_digests() {
    let context = ea_format::ArchiveProfileMigrationContextV1::new(
        support::SOURCE_PROFILE_HASH,
        support::TARGET_PROFILE_HASH,
        support::INVENTORY_HASH,
        support::ACTIVE_POINTER_HASH,
    );
    let bytes = ea_format::encode_archive_profile_migration_context(&context).unwrap();
    assert!(ea_cbor::validate(&bytes, ea_cbor::ParserLimits::V1).is_ok());
    assert!(!ea_testkit::contains_canary(&bytes, b"CANARY-OUTPUT-PATH"));
    assert!(!ea_testkit::contains_canary(&bytes, b"CANARY-ORGANIZATION-NAME"));
}
```

In `tools/xtask/tests/spec_completeness.rs`, append an arity pin for `archive-backend-profile-core-v1` following the pattern of `trust_cddl_enforces_the_exact_twenty_two_positions_of_policy_core_v1` (`tools/xtask/tests/spec_completeness.rs:914-1031`): a shape enum with `Exact`, one position missing and one position too many (`:923-932`), a fixture encoder that writes a concrete type at every position (`:933-977`), and the three `validate_cbor` assertions plus the by-name assertion so that a rename is as loud as a deletion (`:1024-1030`). Extend the wire-type registration list of `cddl_registers_every_v1_wire_type` (`:1-45`) by `archive-backend-profile-core-v1`, `archive-inventory-list-v1` and `active-profile-pointer-core-v1` read from the new schema file, and extend the local-audit list (`:31-37`) by `archive-profile-migration-context-v1`.

- [ ] **Step 2: Run the preimage tests and verify no rule exists yet**

Run:

```bash
cargo test --locked -p ea-format --test archive_profile
cargo test --locked -p xtask --test spec_completeness
```

Expected: FAIL because `archive-backend-profile-core-v1`, the inventory list, the active-profile pointer and their three domain-separated digests do not exist: the domain list in `crates/ea-crypto/src/digest.rs:18-31` is closed and contains none of them, and `crates/ea-format/src/local_audit.rs` implements only the clock-release context.

- [ ] **Step 3: Write the three hash rules into the addendum and implement them**

Create `schemas/archive/v1/archive-profile.cddl` with the closed profile core, the inventory list and the pointer core; the file is self-contained and references nothing outside itself:

```cddl
archive-backend-profile-core-v1 = [
  1,                                  ; Strukturversion
  profile-kind: 0..1,                 ; 0 = localPath, 1 = controlledNetworkPath
  filesystem-row-id: tstr,            ; Zeilen-ID der support-matrix, nie ein Pfad
  protocol-id: tstr,                  ; "" bei localPath
  server-product: tstr,               ; "" bei localPath
  server-version: tstr,               ; "" bei localPath
  mount-options: [* tstr],            ; byteweise aufsteigend, duplikatfrei
  failover-config-id: tstr,           ; "" bei localPath
  capability-test-vector-id: tstr,
  queue-max-objects: uint,            ; 0 bei localPath
  queue-max-bytes: uint,              ; 0 bei localPath
  resume-backoff-initial-ms: uint,    ; 0 bei localPath
  resume-backoff-max-ms: uint,        ; 0 bei localPath
  resume-max-attempts: uint,          ; 0 bei localPath
  []                                  ; kritische Erweiterungen
]
archive-inventory-entry-v1 = [relative-path: tstr, content-hash: bstr .size 32]
archive-inventory-list-v1 = [1, count: uint, * archive-inventory-entry-v1]
active-profile-pointer-core-v1 = [
  1, active-profile-hash: bstr .size 32, generation: uint
]
```

Register the file in the normative list of the addendum (`docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-wire-format-addendum.md:10-20`) and add the three rules in the existing convention `SHA-256(DOMAIN || deterministicCbor(core))` (`crates/ea-crypto/src/digest.rs:33-49`), with `DOMAIN` as ASCII bytes without separator and the version marker as the first array position, following `recovery_test_digest_ref` (`crates/ea-crypto/src/digest.rs:104-117`):

```text
archiveProfileHash = SHA-256("EINSATZARCHIV-ARCHIVE-PROFILE-v1" || deterministicCbor(archive-backend-profile-core-v1))
inventoryHash      = SHA-256("EINSATZARCHIV-ARCHIVE-INVENTORY-v1" || deterministicCbor(archive-inventory-list-v1))
activePointerHash  = SHA-256("EINSATZARCHIV-ACTIVE-PROFILE-POINTER-v1" || deterministicCbor(active-profile-pointer-core-v1))
```

The addendum states these five sentences normatively, because each of them is the reason a later stage must not reopen the rule. **First:** no output path, no host name and no account name enters any of the three preimages, so the digests are portable and reproducible across organizational boundaries. **Second:** `contentHash` of an inventory entry is `object_hash` over the exact file bytes (`crates/ea-crypto/src/digest.rs:63-66`) for **every** inventoried file, format package included, although that package carries no exact-object prefix (`design.md:1288`) — otherwise the schema and report bytes that `design.md:1307` demands inside the inventory would have no identity at all; the relative path is root-relative with `/` as separator in UTF-8 NFC, entries are sorted bytewise ascending and duplicate-free, and the path appears only in the preimage, never in the audit event, which carries the thirty-two digest bytes alone. **Third:** `generation` rises monotonically by exactly one per successful switch, so a rollback to an earlier profile yields a new, higher generation and therefore a different pointer hash; after the switch `active-profile-hash` equals `target-profile-hash`, and on outcome `failed` (`schemas/reports/v1/local-audit.cddl:4`, value 0) it equals `source-profile-hash`. **Fourth:** `allowed-archive-profile-hashes` inside the Root-signed `policy-core-v1` (`schemas/archive/v1/trust.cddl:136`) carries exactly these values computed by exactly this rule, and a profile migration whose target profile hash is not in the effective policy is rejected fail-closed — without that sentence `schemas/archive/v1/trust.cddl:136` stays a dead letter. **Fifth:** the values of `filesystem-row-id`, `capability-test-vector-id` and `failover-config-id` come from the Stage 7 `support-matrix.json` (`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-7-release-hardening.md:38`, `:41`), but their **structure** is fixed here; Stage 7 supplies values and adapts its row-ID schema to this core, it does not redefine it. Stage 2 signs durable audit evidence with these digests, so the direction of adaptation cannot be the other way round.

Add the three domain constants next to the fourteen existing ones (`crates/ea-crypto/src/digest.rs:18-31`) and derive `archive_profile_digest`, `archive_inventory_digest` and `active_profile_pointer_digest` with the existing `digest_fn!` macro (`crates/ea-crypto/src/digest.rs:41-49`); export them from `crates/ea-crypto/src/lib.rs:23-29`. Implement `ArchiveBackendProfileCoreV1`, `ArchiveInventoryEntryV1`, `ArchiveInventoryListV1`, `ActiveProfilePointerCoreV1` and their `encode_*` functions in `crates/ea-format/src/archive_profile.rs`, and implement `encode_archive_profile_migration_context` additively in `crates/ea-format/src/local_audit.rs` next to the clock-release encoder; der Typ `ArchiveProfileMigrationContextV1` selbst stammt aus Task 4, und erst die drei Hashregeln dieses Steps machen seine vier Positionen berechenbar. Export all of them from `crates/ea-format/src/lib.rs`. `ArchiveInventoryListV1::new` sorts, rejects duplicates, rejects `..`, an absolute root and a non-NFC path with the stable codes asserted in Step 1, and `count` is the entry count it actually carries. `crates/ea-audit/src/event.rs` binds `ea_format::ArchiveProfileMigrationContextV1` into the signing and flush paths of `LocalAuditService`, so a migration event travels as `ea_format::LocalAuditActionV1::ArchiveProfileMigration(context)` and `ea-audit` declares no context type of its own; the byte shape of that context becomes computable only with the three rules of this task.

Freeze the three domain strings additively: extend `CRYPTO_DOMAIN_STRINGS` (`crates/ea-testkit/src/lib.rs:710-731`) and `CRYPTO_DOMAIN_DIGESTS` (`:734-771`) by the three new domains and regenerate the family with the documented emitter run (`crates/ea-testkit/src/lib.rs:6378-6384`); then raise `EXPECTED_ENTRY_COUNT` (`tests/ea-system-tests/tests/conformance_golden_vectors.rs:84`) and `EA_CRYPTO_DOMAIN_STRING_COUNT` (`:89`) by the entries added. No existing vector byte changes: `docs/traceability/stage-1-gate.md:115-121` forbids regenerating, reordering or reformatting existing vectors and expected values, while `tests/ea-system-tests/tests/conformance_golden_vectors.rs:1002-1011` demands one **additional** vector per new domain. A `suite-2` is therefore not required.

Add `schemas/archive/v1/archive-profile.cddl` to `validate_schemas` following the standalone-document precedent (`tools/xtask/src/main.rs:800-808`) and raise the count in the summary line (`tools/xtask/src/main.rs:860`) together with its character-exact expectation (`tools/xtask/tests/schema_validation.rs:16`).

Run:

```bash
cargo test --locked -p ea-testkit -- --ignored emit_crypto_suite_one_vectors
git status --porcelain vectors/crypto/suite-1
```

Expected: PASS, and `git status` lists only new `.bin` files plus `vectors/crypto/suite-1/manifest.json`. A run that rewrites the bytes of an existing vector is a finding, not a regeneration (`crates/ea-testkit/src/lib.rs:6375-6377`).

- [ ] **Step 4: Run the preimage tests green**

Run:

```bash
cargo test --locked -p ea-format --test archive_profile
cargo test --locked -p xtask --test spec_completeness --test schema_validation
cargo test --locked -p ea-system-tests --test conformance_golden_vectors
cargo run --locked -p xtask -- validate-schemas
```

Expected: PASS on all four; the arity pin rejects both the deletion of a position and an extra position, and every new domain string is frozen by its own vector.

- [ ] **Step 5: Write create-if-absent, health, queue, and migration rollback tests**

Every test of this task serializes itself: a process-wide lock plus its own temp root per test, following `tools/xtask/tests/stage_gate.rs:29-44`. `crates/ea-archive-fs/tests/support/mod.rs` builds the two signed grant fixtures over the same `signer()` construction that `crates/ea-archive/tests/support/mod.rs:344` and `:361` already use for `signed_entry_package()`; they must differ in at least one byte, because `GrantV1::new` validates the issuer signature (`crates/ea-format/src/eag.rs:209-211`) and a literal therefore does not suffice.

`backend_capabilities.rs`:

```rust
#[test]
fn create_if_absent_is_idempotent_for_equal_bytes_and_rejects_a_byte_conflict() {
    let backend = LocalPathBackend::in_temp_dir();
    let path = ArchivePath::in_dir(ea_archive::GRANTS_DIR_V1, "x.eag").unwrap();
    let first = ea_format::encode_grant(&support::signed_grant_a()).unwrap();
    let second = ea_format::encode_grant(&support::signed_grant_b()).unwrap();
    backend.create_if_absent(&path, &first).unwrap();
    backend.create_if_absent(&path, &first).unwrap();
    assert_eq!(
        backend.create_if_absent(&path, &second).unwrap_err().code(),
        "EA-ARCHIVE-BYTE-CONFLICT"
    );
}

#[test]
fn every_declared_capability_is_proven_on_the_host_filesystem() {
    let backend = LocalPathBackend::in_temp_dir();
    let report = backend.run_capability_test(support::capability_test_vector()).unwrap();
    assert!(report.exclusive_create_without_overwrite());
    assert!(report.byte_conflict_detection());
    assert!(report.same_filesystem_atomic_rename());
    assert!(report.file_flush() && report.directory_flush());
    assert!(report.exclusive_writer_lock());
    assert!(report.disconnect_and_resume_keeps_exact_bytes());
}

#[test]
fn a_second_writer_lock_is_refused_and_released_on_drop() {
    let backend = LocalPathBackend::in_temp_dir();
    let held = backend.acquire_writer_lock().unwrap();
    assert_eq!(backend.acquire_writer_lock().unwrap_err().code(), "EA-ARCHIVE-ALREADY-LOCKED");
    drop(held);
    assert!(backend.acquire_writer_lock().is_ok());
}

#[test]
fn a_rename_across_filesystems_is_refused_instead_of_copied() {
    let backend = LocalPathBackend::in_temp_dir();
    assert_eq!(
        backend.atomic_rename_same_fs(&support::staged_path(), &support::path_on_another_filesystem())
            .unwrap_err()
            .code(),
        "EA-ARCHIVE-NOT-SAME-FILESYSTEM"
    );
}
```

`health_report.rs`: `every_health_finding_has_its_own_detection` — each one of the ten findings of Step 7 is produced artificially and evidenced individually in the `ArchiveHealthReport`; an intact archive yields an empty report.

`transaction_stages.rs`: `transaction_never_publishes_after_a_failed_flush` — a failed flush leaves no target path in existence. The test runs against a deterministic in-memory `ArchiveBackend` fake in `crates/ea-archive/tests/support/mod.rs`, so `crates/ea-archive` needs no filesystem to prove the staging contract.

`controlled_network_profile.rs`: `controlled_network_requires_a_local_commit_component_and_rejects_a_generic_share` — a profile without an encrypted local commit component is refused, and so is a generic UNC/SMB/NFS/WebDAV path; `an_unknown_profile_hash_blocks_before_any_archive_path_is_used` — a profile whose `archiveProfileHash` is not in `allowed_archive_profile_hashes` of the bound policy is rejected fail-closed, and the test asserts that no path of the target was opened.

`publication_queue.rs`:

```rust
#[test]
fn a_lost_network_capability_keeps_upload_pending_with_its_own_detail_cause() {
    let queue = support::queue_with_disconnecting_adapter();
    let state = queue.publish(support::two_grants_and_one_entry()).unwrap();
    assert_eq!(state.sync_status(), SyncStatus::UploadPending);
    assert_eq!(state.detail_cause(), Some(DetailCause::NetworkArchiveWaiting));
    assert!(!state.fell_back_to_another_target());
}

#[test]
fn resumption_publishes_byte_identical_objects_in_the_same_order() {
    let queue = support::queue_with_disconnecting_adapter();
    let planned = support::two_grants_and_one_entry();
    queue.publish(planned.clone()).unwrap();
    let resumed = queue.reconnect().resume().unwrap();
    assert_eq!(resumed.published_bytes(), planned.exact_bytes());
    assert_eq!(resumed.published_order(), planned.order());
}
```

`profile_migration.rs`:

```rust
#[test]
fn migration_failure_leaves_only_the_old_profile_active() {
    let migrator = support::migrator();
    let result = migrator.with_fault(MigrationFaultPoint::BeforePointerSwap).run();
    assert!(result.is_err());
    assert_eq!(migrator.active_profile_hash(), support::SOURCE_PROFILE_HASH);
    assert!(migrator.finalization_lock().is_available());
}

#[test]
fn migration_requires_matching_reauth_and_audits_the_pointer_result() {
    let migrator = support::migrator();
    assert!(migrator.run_with(support::finalize_proof()).is_err());
    let result = migrator.run_with(support::profile_migration_proof()).unwrap();
    let event = support::audit().signed_event(result.audit_event_id()).unwrap();
    let decoded = ea_format::decode_archive_profile_migration_audit(event.exact_bytes()).unwrap();
    assert_eq!(decoded.context().source_profile_hash(), support::SOURCE_PROFILE_HASH);
    assert_eq!(decoded.context().target_profile_hash(), migrator.active_profile_hash());
    assert_eq!(decoded.context().inventory_hash(), result.inventory_hash());
    assert_eq!(decoded.context().active_pointer_hash(), result.active_pointer_hash());
    assert!(support::audit().is_flushed(result.audit_event_id()));
}

#[test]
fn a_target_profile_outside_the_effective_policy_is_refused_before_any_copy() {
    let migrator = support::migrator_with_unlisted_target_profile();
    assert_eq!(
        migrator.run_with(support::profile_migration_proof()).unwrap_err().code(),
        "EA-ARCHIVE-PROFILE-NOT-ALLOWED"
    );
    assert_eq!(migrator.staged_object_count(), 0);
}

#[test]
fn the_inventory_hash_is_equal_on_both_profiles_after_a_successful_switch() {
    let migrator = support::migrator();
    let result = migrator.run_with(support::profile_migration_proof()).unwrap();
    assert_eq!(result.source_inventory_hash(), result.target_inventory_hash());
    assert_eq!(result.active_pointer_generation(), migrator.previous_generation() + 1);
}
```

- [ ] **Step 6: Run the backend tests and verify the durability ports are absent**

Run:

```bash
cargo test --locked -p ea-archive --test transaction_stages
cargo test --locked -p ea-archive-fs --test backend_capabilities --test health_report --test controlled_network_profile --test publication_queue --test profile_migration
```

Expected: FAIL because the durable backend ports, the publication queue, the health report and the migration do not exist; `ArchivePath`, `WriterLock` and `ArchiveBackendError` have no occurrence under `crates/` today, and `ArchiveError` carries exactly three codes (`crates/ea-archive/src/error.rs:26-32`).

- [ ] **Step 7: Implement explicit durability primitives and fail-closed profiles**

```rust
pub trait ArchiveBackend: Send + Sync {
    fn create_if_absent(&self, relative: &ArchivePath, bytes: &ExactObjectBytes) -> Result<(), ArchiveBackendError>;
    fn create_non_object_if_absent(&self, relative: &ArchivePath, bytes: &[u8]) -> Result<(), ArchiveBackendError>;
    fn sync_file(&self, relative: &ArchivePath) -> Result<(), ArchiveBackendError>;
    fn sync_directory(&self, relative: &ArchivePath) -> Result<(), ArchiveBackendError>;
    fn atomic_rename_same_fs(&self, from: &ArchivePath, to: &ArchivePath) -> Result<(), ArchiveBackendError>;
    fn acquire_writer_lock(&self) -> Result<WriterLock, ArchiveBackendError>;
}
```

`ArchiveBackendError` follows the pattern of `ArchiveError` — stable `code()`, `Display` prints the code, `#[non_exhaustive]` (`crates/ea-archive/src/error.rs:22-46`) — and carries at least `ByteConflict` as `"EA-ARCHIVE-BYTE-CONFLICT"`, `AlreadyLocked`, `NotSameFilesystem` and `FlushFailed`. `ArchiveError` stays unchanged the **read** error of `ArchiveSource`, exactly as its own contract states (`crates/ea-archive/src/error.rs:3-8`): a byte conflict is a single-object finding and would break that contract. `create_non_object_if_absent` exists as its own method with identical create-if-absent semantics because the format package carries no exact-object prefix (`design.md:1288`) and `ExactObjectBytes::new` is `pub(crate)` in `ea-format` (`crates/ea-format/src/object.rs:68-70`), so those bytes cannot travel as `ExactObjectBytes` at all; `ea-archive-fs` calls it exclusively from `materialize_format_package` (Task 10).

`ArchivePath` ist eine validierte **Transportadresse** innerhalb eines Bestands: relativ, ohne `..`, ohne absolute Wurzel, ausschliesslich unterhalb eines Verzeichnisses aus `LAYOUT_PATHS_V1` (`crates/ea-archive/src/layout.rs:62`), und sie entscheidet **nie** darueber, ob Bytes ein Archivobjekt sind — das entscheidet weiterhin allein das 9-Byte-Exact-Object-Praefix (`crates/ea-archive/src/source.rs:5-9`). `ArchivePath` fuegt `LAYOUT_PATHS_V1` keinen Pfad hinzu; `tools/xtask/tests/spec_completeness.rs:2717-2750` haelt diese Liste in beiden Richtungen gepinnt. `WriterLock` ist ein RAII-Waechter, dessen `Drop` die exklusive Sperre freigibt. Der Staging-Bereich gehoert zur lokalen Archiv-Commit-Komponente (`design.md:1308`) und wird **nicht** in `LAYOUT_PATHS_V1` eingetragen.

`ArchivePath` therefore offers exactly two constructors: `in_dir(directory_constant, relative_below_it)` for everything under a directory of `LAYOUT_PATHS_V1` — the second argument may itself contain `/`, as the destruction subdirectories already require (`crates/ea-archive/src/layout.rs:33-39`) — and `at_layout_file(file_constant)` for the two fixed root files of the list.

`LocalPathBackend` pins a tested filesystem profile. `ControlledNetworkBackend` contains an encrypted durable local commit component plus a separately pinned network target, queue bounds and retry parameters. Never accept a generic UNC/SMB/NFS/WebDAV path. Before any archive path of a profile is used, the backend recomputes `archiveProfileHash` over the concretely versioned profile and compares it against `allowed_archive_profile_hashes` of the bound policy (`crates/ea-format/src/etb.rs:222`); any deviation is refused fail-closed with `EA-ARCHIVE-PROFILE-NOT-ALLOWED` (`design.md:1328`, `:462`). Task 11 repeats the same check against the same bound policy version inside the finalization.

The health report detects missing or modified files; hash, signature and chain errors; absent mandatory grants; invalid or unauthorized stubs; incomplete Trust data; orphan grants and temporary files; unexpected sequence, fork and rollback; insufficient free space; and unsuitable filesystem semantics (`design.md:1315-1324`). Capability checks prove exclusive create, byte-conflict detection, same-filesystem atomic rename, file and directory flush, exclusive lock, disconnect and reconnect, and exact bytes (`design.md:1326`).

The publication queue carries the four normative Sync states and the detail cause as a **separate** text, never as a fifth state: while a released network backend has lost an assured capability, the state stays `Upload ausstehend` with the detail cause `Netzarchiv wartet`, publication resumes byte-identically after reconnection, and the application never silently falls back to another target (`design.md:1328`, `:459`). The queue preserves the publication order it was handed; grants before `.eip` is decided by Task 11, and Task 16 renders the state and its detail cause.

Migration requires its exact fresh re-authentication purpose, locks finalization, profile changes and cleanup, finishes pending old-profile publications, inventories every Trust, schema, object and report byte, copies create-if-absent into the staging area, verifies the target fully offline, compares exact object set plus chain and Trust heads, flushes every directory, and only then atomically swaps the local profile pointer; any error leaves only the old profile active (`design.md:1304-1313`). Before returning, it flushes a signed local audit event whose `archive-profile-migration-context-v1` binds source and target profile hash, inventory hash and active-pointer hash computed by the three rules of Step 3; no path and no fachliche name enters the audit, only the thirty-two digest bytes each. The old profile remains read-only or is separately controlled by retention policy and is never auto-deleted.

- [ ] **Step 8: Run backend, queue, and migration matrices**

Run:

```bash
cargo test --locked -p ea-archive --test transaction_stages
cargo test --locked -p ea-archive-fs --test backend_capabilities --test health_report --test controlled_network_profile --test publication_queue --test profile_migration
cargo test --locked -p xtask --test workspace
cargo run --locked -p xtask -- verify-quick
```

Expected: PASS on the host test filesystem; controlled-network contract tests use a deterministic disconnecting adapter and leave native backend certification open to Stage 7. The tests carry no `--test-threads=1`: they serialize themselves, and the character-exact command list of `verify_quick_commands()` (`tools/xtask/src/main.rs:41-44`, pinned `:2400-2402`) runs the same binaries in parallel immediately afterwards.

- [ ] **Step 9: Commit archive durability and the profile hash rules**

```bash
git add crates/ea-archive crates/ea-archive-fs crates/ea-format crates/ea-crypto crates/ea-audit crates/ea-testkit schemas/archive/v1/archive-profile.cddl docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-wire-format-addendum.md vectors/crypto/suite-1 tests/ea-system-tests tools/xtask Cargo.toml Cargo.lock
git commit -m "feat(archive): add durable backends, health check, and audited profile migration"
```

### Task 10: Materialize the Format Package When an Archive Is Created (SYNTHESE.md: Task 6.5)

**Files:**
- Create: `crates/ea-archive-fs/src/format_package.rs`
- Modify: `crates/ea-archive-fs/src/lib.rs`
- Modify: `crates/ea-archive-fs/src/local_path.rs`
- Modify: `crates/ea-archive-fs/src/controlled_network.rs`
- Modify: `crates/ea-archive-fs/tests/support/mod.rs`
- Test: `crates/ea-archive-fs/tests/format_package.rs`

**Interfaces:**
- Consumes: the six layout constants of the format package (`crates/ea-archive/src/layout.rs:41-51`, re-exported `crates/ea-archive/src/lib.rs:48-56`), `ArchivePath`, `ArchiveBackend::{create_non_object_if_absent, sync_file, sync_directory}` and the `#[cfg(any(test, feature = "test-support"))]` read surface of `LocalPathBackend` — `exists_for_test`, `directory_exists_for_test`, `read_for_test`, `relative_paths_below_for_test`, `overwrite_for_test` and `as_archive_source` — from Task 9.
- Produces: `FORMAT_PACKAGE_FILES_V1`, `materialize_format_package(&dyn ArchiveBackend) -> Result<FormatPackageReport, ArchiveBackendError>`, called from the archive-creation path of both `ea-archive-fs` backends, which this task wires, and by Task 12 when a bundle is assembled.

`design.md:1252-1288` carries `README-FORMAT.txt`, `format/schemas/`, `format/transformations/`, `format/compatibility-matrix.json` and `recovery-reports/` as an obligation of every archive, and Stage 2 is the first stage that creates archives. Today no production code writes them: outside `crates/ea-archive/src/layout.rs` and `crates/ea-archive/src/lib.rs` the constants appear only in the test fixture `tests/ea-system-tests/tests/task9_verification_report.rs:112`.

- [ ] **Step 1: Write the completeness and byte-stability tests**

```rust
#[test]
fn a_fresh_archive_carries_every_path_of_the_format_package() {
    let backend = LocalPathBackend::in_temp_dir();
    materialize_format_package(&backend).unwrap();
    for relative in [
        ea_archive::README_FORMAT_FILE_V1,
        ea_archive::COMPATIBILITY_MATRIX_FILE_V1,
    ] {
        assert!(backend.exists_for_test(&ArchivePath::at_layout_file(relative).unwrap()));
    }
    for directory in [
        ea_archive::FORMAT_DIR_V1,
        ea_archive::FORMAT_SCHEMAS_DIR_V1,
        ea_archive::FORMAT_TRANSFORMATIONS_DIR_V1,
        ea_archive::RECOVERY_REPORTS_DIR_V1,
    ] {
        assert!(backend.directory_exists_for_test(directory));
    }
}

#[test]
fn the_written_readme_is_byte_identical_to_the_published_format_package() {
    let backend = LocalPathBackend::in_temp_dir();
    materialize_format_package(&backend).unwrap();
    let written = backend
        .read_for_test(&ArchivePath::at_layout_file(ea_archive::README_FORMAT_FILE_V1).unwrap());
    assert_eq!(written, support::repository_bytes("docs/format/README-FORMAT.txt"));
}

#[test]
fn every_schema_file_of_the_repository_is_mirrored_byte_identically() {
    let backend = LocalPathBackend::in_temp_dir();
    materialize_format_package(&backend).unwrap();
    let mirrored = backend.relative_paths_below_for_test(ea_archive::FORMAT_SCHEMAS_DIR_V1);
    assert_eq!(mirrored, support::repository_schema_paths());
    for relative in mirrored {
        let path = ArchivePath::in_dir(ea_archive::FORMAT_SCHEMAS_DIR_V1, &relative).unwrap();
        assert_eq!(
            backend.read_for_test(&path),
            support::repository_bytes(&format!("schemas/{relative}"))
        );
    }
    assert_eq!(
        backend.read_for_test(
            &ArchivePath::at_layout_file(ea_archive::COMPATIBILITY_MATRIX_FILE_V1).unwrap()
        ),
        support::repository_bytes("schemas/compatibility-matrix.json")
    );
}

#[test]
fn the_format_package_is_never_an_archive_object_and_never_quarantined() {
    let backend = LocalPathBackend::in_temp_dir();
    let report = materialize_format_package(&backend).unwrap();
    let inventory = ArchiveInventory::build(&backend.as_archive_source()).unwrap();
    assert_eq!(inventory.archive_object_count(), 0);
    assert_eq!(inventory.non_object_file_count(), report.written_file_count());
    assert!(inventory.quarantined().is_empty());
    assert!(inventory.format_errors().is_empty());
}

#[test]
fn a_backend_that_creates_an_archive_materializes_the_format_package_without_a_separate_call() {
    let backend = LocalPathBackend::in_temp_dir();
    for file in FORMAT_PACKAGE_FILES_V1 {
        let path = ArchivePath::at_layout_file(file).unwrap();
        assert!(backend.exists_for_test(&path), "creation path left {file} unwritten");
    }
}

#[test]
fn materializing_twice_is_idempotent_and_a_changed_beiwerk_byte_conflicts() {
    let backend = LocalPathBackend::in_temp_dir();
    materialize_format_package(&backend).unwrap();
    materialize_format_package(&backend).unwrap();
    let path = ArchivePath::at_layout_file(ea_archive::README_FORMAT_FILE_V1).unwrap();
    backend.overwrite_for_test(&path, b"tampered");
    assert_eq!(
        materialize_format_package(&backend).unwrap_err().code(),
        "EA-ARCHIVE-BYTE-CONFLICT"
    );
}
```

`support::repository_bytes` and `support::repository_schema_paths` read the working tree relative to `env!("CARGO_MANIFEST_DIR")`, following the workspace-root helper of the existing gate tests (`tools/xtask/tests/stage_gate.rs:46-51`). `repository_schema_paths` walks `schemas/` at test time and returns the paths below it except `compatibility-matrix.json`, so a schema file added later fails this test instead of silently missing from every new archive.

- [ ] **Step 2: Run the tests and verify no code writes the format package**

Run: `cargo test --locked -p ea-archive-fs --test format_package`

Expected: FAIL because no production code writes the format package; a fresh archive today carries the six layout constants only as `&str` in `crates/ea-archive/src/layout.rs:41-51`.

- [ ] **Step 3: Materialize the format package when an archive is created**

`crates/ea-archive-fs/src/format_package.rs` embeds `docs/format/README-FORMAT.txt`, the seven CDDL and JSON schema documents named as normative by the addendum (`docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-wire-format-addendum.md:10-20`) plus the five payload JSON schemas, and `schemas/compatibility-matrix.json` with `include_bytes!`, so the archive bytes are the repository bytes by construction and cannot drift; the tests of Step 1 pin the equality against the working tree in addition, so that an accidentally changed include path is loud. `FORMAT_PACKAGE_FILES_V1` is the closed list of `(ArchivePath, &'static [u8])` pairs, and every entry addresses its target through `ArchivePath::in_dir(FORMAT_SCHEMAS_DIR_V1, …)` or `ArchivePath::at_layout_file(…)` — the function adds no path to `LAYOUT_PATHS_V1`.

`materialize_format_package` writes every entry with `create_non_object_if_absent`, then `sync_file` on each written file and `sync_directory` on each touched directory, and returns a `FormatPackageReport` with the written file count and the directories created. `format/transformations/` and `recovery-reports/` are created and stay empty: every view of v0.1 is `identity` with `preservesSourceBytes` (`schemas/compatibility-matrix.json`), so there is no derivation to describe, and a recovery report only comes into existence with an actual recovery run. Both directories exist nonetheless, because `design.md:1252-1288` lists them and a reader must be able to tell an empty obligation from a missing one.

The bytes carry no exact-object prefix and are therefore never an archive object: the inventory classifies exclusively by the 9-byte prefix (`crates/ea-archive/src/lib.rs:22-39`), counts them as `nonObjectFileCount` and never quarantines them (`design.md:1290-1291`, `:1296`). That is the reason `create_non_object_if_absent` and not `create_if_absent` is the write path here. `LocalPathBackend` and `ControlledNetworkBackend` call `materialize_format_package` as the last step of their creation path, before the first archive path is used; the function is idempotent, so a second call on an existing archive is a no-op. Task 11 therefore creates no format package of its own.

- [ ] **Step 4: Run the format package tests green**

Run:

```bash
cargo test --locked -p ea-archive-fs --test format_package
cargo run --locked -p xtask -- validate-schemas
cargo test --locked -p xtask --test spec_completeness
```

Expected: PASS; `archive_layout_paths_match_design_section_11_4` (`tools/xtask/tests/spec_completeness.rs:2717-2750`) stays green in both directions, because this task introduces no new layout path and changes none.

- [ ] **Step 5: Commit the archive-side format package**

```bash
git add crates/ea-archive-fs
git commit -m "feat(archive): materialize the format package when creating an archive"
```

### Task 11: Prepared Finalization State Machine (SYNTHESE.md: Task 7)

**Files:**
- Create: `crates/ea-writer/Cargo.toml`
- Create: `crates/ea-writer/src/lib.rs`
- Create: `crates/ea-writer/src/preview.rs`
- Create: `crates/ea-writer/src/grant_plan.rs`
- Create: `crates/ea-writer/src/stale_registry.rs`
- Create: `crates/ea-writer/src/finalize.rs`
- Create: `crates/ea-writer/src/recover.rs`
- Create: `crates/ea-writer/src/fault.rs`
- Create: `crates/ea-writer/tests/support/mod.rs`
- Create: `crates/ea-format/src/finalization_preview.rs`
- Create: `schemas/reports/v1/finalization-preview.cddl`
- Modify: `crates/ea-audit/src/event.rs`
- Modify: `crates/ea-crypto/src/digest.rs`
- Modify: `crates/ea-crypto/src/lib.rs`
- Modify: `crates/ea-format/src/eag.rs`
- Modify: `crates/ea-format/src/lib.rs`
- Modify: `crates/ea-verify/src/recipient.rs`
- Modify: `crates/ea-testkit/src/lib.rs`
- Modify: `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-wire-format-addendum.md`
- Modify: `docs/traceability/stage-2-fault-points.json`
- Modify: `tools/xtask/src/main.rs`
- Modify: `tools/xtask/tests/schema_validation.rs`
- Modify: `tools/xtask/tests/spec_completeness.rs`
- Modify: `tools/xtask/tests/workspace.rs`
- Modify: `tests/ea-system-tests/tests/conformance_golden_vectors.rs`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Test: `crates/ea-format/tests/finalization_preview.rs`
- Test: `crates/ea-writer/tests/offline_finalize.rs`
- Test: `crates/ea-writer/tests/prepared_recovery.rs`
- Test: `crates/ea-writer/tests/grant_completeness.rs`
- Test: `crates/ea-writer/tests/sequence_id.rs`
- Test: `crates/ea-writer/tests/stale_registry_warning.rs`
- Test: `crates/ea-writer/tests/orphan_and_restored_backup.rs`
- Test: `crates/ea-writer/tests/fault_point_manifest.rs`

**Interfaces:**
- Consumes: the read path over all archive bytes, `ea_archive::{ArchiveSource, ArchiveInventory}` (`crates/ea-archive/src/source.rs:67-72`, `crates/ea-archive/src/inventory.rs:220-301`, re-exports `crates/ea-archive/src/lib.rs:46-47`), and the value-based chain logic `ea_chain::{ChainNode, build_chain, VerifiedChain, ChainHead, CheckpointClaim, assess_rollback, RollbackAssessment}` (`crates/ea-chain/src/lib.rs:43-49`); the write path `ea_archive::ArchiveTransaction` with `ArchiveBackend`, `ArchivePath`, `WriterLock` and `ArchiveBackendError` plus the `ea-archive-fs` backends, the publication queue and its `SyncStatus`/`DetailCause` from Task 9; `SelectedRegistryHead` with `proposed_sequence`, `registry_version`, `registry_head_hash`, `policy_object_hash`, `policy_fields`, `valid_through_sequence`, `active_certificates`, `active_operator_binding_fields` and `preexisting_effective_now` (`crates/ea-trust/src/registry.rs:71-171`); the validated payload and the closed snapshot unions of `ea-schema`; a fresh `OperatorSessionProof` for `ReauthPurpose::{Finalize, RegistryStaleFinalize}` from Task 3; the Writer signer port `KeyProvider::sign` plus `KeyProvider::{delete, contains}` from Task 2; the exclusive `DraftLock`, `DraftRepository::{draft_dek_handle, prepared_finalization_marker, replace_prepared_finalization_marker, replace_with_blank}`, `IncidentNumberRegister::{claim, contains}` and the read-only `OperatorProfileRepository::load` from Task 6; `LocalAuditService::record_signed` with `SignedLocalAuditEvent::exact_bytes` from Task 6 and `ea_format::{StaleRegistryContextV1, encode_local_audit_event}` from Task 4; `ea_format::GrantPlanV1::new` (`crates/ea-format/src/eag.rs:106-129`, Hash-Zugriff `:137-140`), `ea_format::{ManifestCoreV1, SignedManifestV1, EntryPackageV1, GrantBodyV1, GrantV1, encode_entry_package, encode_grant}`; `ea_crypto::{aead_seal, payload_aad, hpke_seal, hpke_info, hpke_aad, record_digest, object_hash, CEK_SIZE, AEAD_NONCE_SIZE, SecretBytes, SecretVec}`; and `getrandom::fill` (`Cargo.toml:31`) as the single entropy source. Trust, Registry, Policy and Genesis of every harness are synthesized from `ea-testkit`; the Writer never creates a Genesis.
- Produces: `WriterService::{preview, acknowledge_stale_registry, finalize, recover_pending}`; `FinalizationPreview` including the age of the bound trust holding and the policy deadline `reader_trust_refresh_ms`; the opaque one-use `StaleRegistryAcknowledgement`; `PreparedFinalization` and `CommittedFinalization`, each with `exact_bytes(&self) -> &[u8]` — read-only, the constructors stay private; `FinalizeOutcome { sequence, entry_hash, object_hash, sync_status }` without any payload; `FinalizationStep::ALL` with the thirteen named steps, `FinalizationPhase` with its seven states and `FinalizationFaultPoint::ALL` in `crates/ea-writer/src/fault.rs`; the `WriterError` codes with stable `code()`; and the finalization section of the Stage 2 fault-point manifest `docs/traceability/stage-2-fault-points.json`. Additively in `ea-format`: `FinalizationPreviewCoreV1`, `encode_finalization_preview_core` and the public accessor `GrantBodyV1::exact_grant_context`. Additively in `ea-crypto`: `finalization_preview_digest`.

**Die Reihenfolge der Finalisierung ist durch die eingefrorenen Stufe-1-Konstruktoren erzwungen und wird nicht umgebaut.** `entryHash` wird nicht vom Writer „ermittelt", sondern entsteht als Nebenprodukt von `EntryPackageV1::new`, das aus `signedManifest`, Ciphertext und Writer-Signatur zuerst den `recordDigest` und daraus den `entryHash` bildet (`crates/ea-format/src/eip.rs:191-205`, Zugriff `:228-230`); vorher existiert der Wert nicht. Der `.eag`-Rumpf verlangt ihn als Pflichtfeld ohne Default (`crates/ea-format/src/eag.rs:153`, kodiert `:396`), also ist kein `.eag` ohne vorher konstruiertes `EntryPackageV1` baubar — Spec-Schritt 7 (`design.md:454`) ist damit die einzige konstruierbare Reihenfolge und nicht eine von zweien. Umgekehrt bindet `ManifestCoreFieldsV1` die Grants ausschliesslich ueber `initial_grant_plan_hash` (`crates/ea-format/src/eip.rs:17-29`, Feld `:26`, kodiert `:300-338`, Position `:333`) und **nie** ueber eine Liste erzeugter Grant-`objectHash`-Werte; die finalen `.eip`-Bytes haengen deshalb an keinem einzigen `.eag`, und die Ordnung zwischen `.eip`-Bytes und `.eag` ist innerhalb von Schritt 7 frei. `initialGrantPlanHash` wiederum ist kein Implementierungsspielraum: `GrantPlanV1::new` sortiert die Planitems in die normative Totalordnung, serialisiert sie und hasht sie selbst (`crates/ea-format/src/eag.rs:106-129`, `grant_plan_digest` mit der Domain `EINSATZARCHIV-GRANT-PLAN-v1`, `crates/ea-crypto/src/digest.rs:22`, `:53`), und derselbe Konstruktor erzwingt genau ein Recovery und verbietet doppelte Empfaenger (`crates/ea-format/src/eag.rs:106-124`). Es entsteht **kein** zweiter Hashpfad und **keine** nachgebaute Negativregel.

- [ ] **Step 0: Register the workspace member and create the lockfile once**

Create `crates/ea-writer/Cargo.toml` and an empty `crates/ea-writer/src/lib.rs` so that the member path resolves. Modify `Cargo.toml`: add `crates/ea-writer` under `[workspace]members` and the path entry `ea-writer = { path = "crates/ea-writer" }` under `[workspace.dependencies]`, following the existing `ea-*` path entries (`Cargo.toml:18-29`). The crate manifest references `ea-types`, `ea-cbor`, `ea-crypto`, `ea-format`, `ea-schema`, `ea-time`, `ea-trust`, `ea-chain`, `ea-verify`, `ea-archive`, `ea-archive-fs`, `ea-local-store`, `ea-draft`, `ea-audit`, `ea-operator`, `ea-key-provider`, `zeroize` and `getrandom` with `workspace = true`, which `tools/xtask/tests/workspace.rs:90-101` enforces; `[dev-dependencies]` adds `ea-testkit.workspace = true` and `ea-key-provider = { workspace = true, features = ["test-support"] }`, because the deterministic in-memory provider sits behind that non-default feature.

Modify `tools/xtask/src/main.rs`: append one `(name, justification)` pair for `ea-writer` with a non-empty justification to the `WASM32_EXEMPT_CRATES` slice (`tools/xtask/src/main.rs:102`, a slice since Task 1, so no arity edit exists to make), following the `ea-recovery` precedent (`tools/xtask/src/main.rs:103-111`). The justification: this crate composes the filesystem-backed durability primitives of `ea-archive-fs` and the SQLCipher-backed local store, so it reaches past `ea-verify` and is not shared browser code. **Never** the positive list. Modify `tools/xtask/tests/workspace.rs`: append the member path to `WORKSPACE_MEMBERS` (Task 1) and nowhere else — the length assertion, the set comparison and the dependency walk all derive from that one list.

Run: `cargo metadata --format-version 1 > /dev/null` (without `--locked`)

Expected: PASS; `Cargo.lock` afterwards contains the new package. Only then do the `--locked` commands of this task run.

- [ ] **Step 1: Write the preview-preimage tests**

`crates/ea-format/tests/finalization_preview.rs` pins the fourth and last of the hash rules that Stage 2 fixes. Digests are compared against the freshly computed digest of the encoded bytes, never against a literal, so the test states the rule and not a transcription of it.

```rust
#[test]
fn the_preview_core_carries_the_thirteen_positions_and_the_extension_slot() {
    let core = support::preview_core();
    let bytes = ea_format::encode_finalization_preview_core(&core).unwrap();
    assert!(ea_cbor::validate(&bytes, ea_cbor::ParserLimits::V1).is_ok());
    assert_eq!(support::array_length(&bytes), 13);
    assert!(support::last_position_is_an_empty_array(&bytes));
}

#[test]
fn every_position_of_the_preview_core_changes_the_preview_hash() {
    let base = ea_crypto::finalization_preview_digest(
        &ea_format::encode_finalization_preview_core(&support::preview_core()).unwrap(),
    );
    for mutated in support::preview_core_with_one_position_changed() {
        assert_ne!(
            ea_crypto::finalization_preview_digest(
                &ea_format::encode_finalization_preview_core(&mutated).unwrap()
            ),
            base,
            "eine Position ohne Wirkung waere eine Luecke in der Bestaetigung"
        );
    }
}

#[test]
fn a_null_predecessor_and_a_present_predecessor_are_distinguishable() {
    let genesis = ea_format::encode_finalization_preview_core(&support::preview_core_genesis()).unwrap();
    let successor = ea_format::encode_finalization_preview_core(&support::preview_core()).unwrap();
    assert_ne!(
        ea_crypto::finalization_preview_digest(&genesis),
        ea_crypto::finalization_preview_digest(&successor)
    );
}

#[test]
fn the_preview_core_carries_no_content_and_no_path() {
    let bytes = ea_format::encode_finalization_preview_core(&support::preview_core()).unwrap();
    assert!(!ea_testkit::contains_canary(&bytes, b"CANARY-INCIDENT-TEXT"));
    assert!(!ea_testkit::contains_canary(&bytes, b"CANARY-OUTPUT-PATH"));
    assert!(!ea_testkit::contains_canary(&bytes, b"CANARY-OPERATOR-NAME"));
}
```

In `tools/xtask/tests/spec_completeness.rs`, extend the wire-type registration list of `cddl_registers_every_v1_wire_type` (`tools/xtask/tests/spec_completeness.rs:1-45`) by `finalization-preview-core-v1` read from the new schema file, and append an arity pin for it following the pattern of `trust_cddl_enforces_the_exact_twenty_two_positions_of_policy_core_v1` (`:914-1031`): a shape enum with `Exact`, one position missing and one position too many (`:923-932`), a fixture encoder that writes a concrete type at every position (`:933-977`), and the three `validate_cbor` assertions plus the by-name assertion so that a rename is as loud as a deletion (`:1024-1030`).

- [ ] **Step 2: Run the preimage tests and verify no preview rule exists**

Run:

```bash
cargo test --locked -p ea-format --test finalization_preview
cargo test --locked -p xtask --test spec_completeness
```

Expected: FAIL because `finalization-preview-core-v1` and its domain-separated digest do not exist: the domain list in `crates/ea-crypto/src/digest.rs:18-31` is closed and contains no preview domain, and a workspace-wide grep for `preview_hash`/`previewHash` finds nothing. `schemas/reports/v1/local-audit.cddl:6-11` demands `preview-hash: bstr .size 32` at position 6 of `stale-registry-context-v1` and states only its type and size.

- [ ] **Step 3: Write the preview hash rule into the addendum and implement it**

Create `schemas/reports/v1/finalization-preview.cddl`. The field list **is** the security decision here: the promise that `finalize` rejects a different or rebuilt preview and every replay holds only if the preimage covers everything `finalize` acts on.

```cddl
finalization-preview-core-v1 = [
  1,
  organization-id: bstr .size 16,
  chain-id: bstr .size 16,
  registry-head-hash: bstr .size 32,
  registry-version: uint,
  registry-not-after: int,
  policy-object-hash: bstr .size 32,
  proposed-sequence: uint,
  previous-entry-hash: (bstr .size 32) / null,
  record-digest: bstr .size 32,
  grant-plan-digest: bstr .size 32,
  effective-now: int,
  []
]
```

Register the file in the normative list of the addendum (`docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-wire-format-addendum.md:10-20`) and add the rule in the existing convention `SHA-256(DOMAIN || deterministicCbor(core))` (`crates/ea-crypto/src/digest.rs:33-49`), with `DOMAIN` as ASCII bytes without separator and the version marker as the first array position:

```text
previewHash = SHA-256("EINSATZARCHIV-FINALIZATION-PREVIEW-v1" || deterministicCbor(finalization-preview-core-v1))
```

The addendum states four sentences normatively, because each of them is the reason a later stage must not reopen the rule. **First:** `record-digest` and `grant-plan-digest` follow the existing digest functions `record_digest` and `grant_plan_digest` (`crates/ea-crypto/src/digest.rs:52-53`); `grant-plan-digest` is exactly the `initialGrantPlanHash` that `GrantPlanV1::new` computes (`crates/ea-format/src/eag.rs:127-129`), and `record-digest` is taken over the exact deterministically serialized payload record of Spec step 4 (`design.md:451`) — **not** over the `signedManifest`. That distinction is forced, not chosen: the `recordDigest` of an entry package is defined over `signedManifest` (`design.md:686-687`) and therefore exists only after step 6, whose sequence, UUIDv7, CEK and AEAD nonce are drawn once from a CSPRNG (`design.md:453`); a preview that produced them would have to hold a live CEK across an open confirmation dialog, and a `finalize` that redrew them could never recompute the confirmed value. The preview value never enters archive bytes and is never compared against an entry package. **Second:** `previewHash` is computed at the end of Spec step 5, over material that steps 1 to 5 produce and that no CSPRNG touches, so `finalize` can recompute it byte for byte under the Writer lock. **Third:** `finalize` recomputes `previewHash` under the lock and refuses every deviation fail-closed; a changed head, a changed policy, an advanced `effectiveNow`, a changed proposed sequence or changed content produce a different value, which means a new preview and a new confirmation rather than a bypass. **Fourth:** the acknowledgement is consumable exactly once.

Add the domain constant next to the existing ones (`crates/ea-crypto/src/digest.rs:18-31`, extended by Task 9) and derive `finalization_preview_digest` with the existing `digest_fn!` macro (`crates/ea-crypto/src/digest.rs:41-49`); export it from `crates/ea-crypto/src/lib.rs:23-29`. Implement `FinalizationPreviewCoreV1` and `encode_finalization_preview_core` in `crates/ea-format/src/finalization_preview.rs` and export both from `crates/ea-format/src/lib.rs`.

Move the proven grant-context cut instead of copying it a third time: `crates/ea-verify/src/recipient.rs:282-323` carries the guard that reconstructs the fixed 84-byte tail of `grant-body-v1` from the decoded fields and only then treats everything before it as `grant-context-v1`, with the explicit reasoning that the cut is proven and not guessed. That cut becomes the public accessor `GrantBodyV1::exact_grant_context(&self) -> Option<&[u8]>` in `crates/ea-format/src/eag.rs`, exported from `crates/ea-format/src/lib.rs`, and `crates/ea-verify/src/recipient.rs:237` calls it in place of its private copy. The guard, the `Option` and the `None` on a mismatch stay exactly as they are, because the decode path is handed adversarial bytes. The change is byte-neutral: no encoder, no vector and no expected value moves; only a private function becomes public in the crate that owns the type, so that `hpke_info` and `hpke_aad` (`crates/ea-crypto/src/digest.rs:132-139`) are fed the same bytes on the sealing side as on the opening side.

Freeze the new domain string additively: extend `CRYPTO_DOMAIN_STRINGS` (`crates/ea-testkit/src/lib.rs:710-731`) and `CRYPTO_DOMAIN_DIGESTS` (`:734-771`), regenerate the family with the documented emitter run (`crates/ea-testkit/src/lib.rs:6378-6384`), and raise `EXPECTED_ENTRY_COUNT` (`tests/ea-system-tests/tests/conformance_golden_vectors.rs:84`) and `EA_CRYPTO_DOMAIN_STRING_COUNT` (`:89`) by the entries added. No existing vector byte changes: `docs/traceability/stage-1-gate.md:115-121` forbids regenerating, reordering or reformatting existing vectors, while `tests/ea-system-tests/tests/conformance_golden_vectors.rs:1002-1011` demands one **additional** vector per new domain. Add `schemas/reports/v1/finalization-preview.cddl` to `validate_schemas` following the standalone-document precedent (`tools/xtask/src/main.rs:800-808`) and raise the count in the summary line (`tools/xtask/src/main.rs:860`) together with its character-exact expectation (`tools/xtask/tests/schema_validation.rs:16`).

- [ ] **Step 4: Run the preimage tests green**

Run:

```bash
cargo test --locked -p ea-format --test finalization_preview
cargo test --locked -p ea-verify
cargo test --locked -p xtask --test spec_completeness --test schema_validation
cargo test --locked -p ea-system-tests --test conformance_golden_vectors
cargo run --locked -p xtask -- validate-schemas
```

Expected: PASS on all five; the arity pin rejects both the deletion of a position and an extra position, `ea-verify` stays green because the grant-context cut only changed its visibility, and the new domain string is frozen by its own vector.

- [ ] **Step 5: Write the step, fault, grant-set, sequence, stale-registry, and recovery tests**

Every test of this task serializes itself: a process-wide lock plus its own temp root per test, following `tools/xtask/tests/stage_gate.rs:29-44`. `crates/ea-writer/tests/support/mod.rs` builds the `WriterHarness`: `new()` synthesizes Root, Registry, Policy, Genesis, one Writer certificate, one Recovery recipient and two Reader certificates from `ea-testkit` and opens an empty archive on a `LocalPathBackend`; `with_incident(valid_incident())` seeds the encrypted draft; `finalize_up_to(step)` runs a clean finalization that stops after exactly that step; `finalize_with_fault(point)` aborts at exactly that fault point; `capture_prepared_bytes()`, `restart_and_recover()`, `writer_keys_cannot_decrypt(entry_hash)`, `current_draft()`, `archive.publish_order()`, `audit_is_signed_and_flushed(id)`, `reuse_ack(ack)`, `expected_grant_count()` — one Recovery plus every active Reader certificate, derived from the synthesized Registry so that no test restates the number — and `restore_captured_backup()` supply the observations the assertions need.

`crates/ea-writer/tests/offline_finalize.rs` — the happy path, the thirteen steps, and the checks that block before any byte is staged:

```rust
#[test]
fn offline_finalize_commits_grants_then_entry_and_returns_no_content() {
    let mut harness = WriterHarness::with_incident(valid_incident());
    let out = harness.offline_finalize().unwrap();
    assert_eq!(out.sync_status, SyncStatus::LocallySecured);
    let order = harness.archive.publish_order();
    let entry_index = order.iter().position(|p| p.ends_with(".eip")).unwrap();
    assert_eq!(entry_index, order.len() - 1, "das .eip wird zuletzt veroeffentlicht");
    assert_eq!(order.iter().filter(|p| p.ends_with(".eag")).count(), harness.expected_grant_count());
    assert!(order[entry_index].starts_with("entries/000000000001_"));
    assert!(order.iter().filter(|p| p.ends_with(".eag")).all(|p| p.starts_with("grants/")));
    assert!(harness.writer_keys_cannot_decrypt(out.entry_hash));
    assert!(harness.current_draft().is_blank());
}

#[test]
fn each_of_the_thirteen_steps_has_its_own_observable_postcondition() {
    for step in FinalizationStep::ALL.iter().copied() {
        let mut h = WriterHarness::with_incident(valid_incident());
        let reached = h.finalize_up_to(step).unwrap();
        match step {
            FinalizationStep::RebuildLocalHead => assert_eq!(reached.head_source(), HeadSource::CommittedArchiveBytes),
            FinalizationStep::CompareServerCheckpoint => assert!(reached.rollback_assessment().is_some()),
            FinalizationStep::SelectRegistryHeadAndOperator => {
                assert_eq!(reached.selected_registry_version(), h.expected_registry_version());
                assert!(reached.active_recovery_recipient_count() >= 1);
            }
            FinalizationStep::ValidateAndSerialize => assert!(!reached.draft_record_bytes().is_empty()),
            FinalizationStep::BuildAndHashGrantPlan => {
                assert_eq!(reached.initial_grant_plan_hash(), h.expected_grant_plan_hash());
                assert_eq!(reached.preview_hash(), h.expected_preview_hash());
            }
            FinalizationStep::DrawSecretsAndBuildEntryHash => {
                assert_eq!(reached.manifest_core().fields().initial_grant_plan_hash, h.expected_grant_plan_hash().into());
                assert!(reached.signed_manifest_bytes().len() > 0);
                assert!(reached.writer_signature().len() > 0);
                assert_eq!(reached.entry_hash(), reached.entry_package().entry_hash());
            }
            FinalizationStep::ProduceGrantsAndEntryBytes => {
                assert_eq!(reached.grants().len(), reached.grant_plan().items().len());
                assert_eq!(reached.object_hash(), ea_crypto::object_hash(reached.entry_bytes()));
            }
            FinalizationStep::StageAndFlush => {
                assert_eq!(reached.phase(), FinalizationPhase::PreparedAndFlushed);
                assert_eq!(h.archive.published_object_count(), 0);
            }
            FinalizationStep::ZeroAndDeleteDraftKey => {
                assert_eq!(reached.phase(), FinalizationPhase::DraftKeyAbsent);
                assert!(!h.draft_dek_is_present());
            }
            FinalizationStep::PublishGrants => {
                assert_eq!(reached.phase(), FinalizationPhase::GrantsPublished);
                assert!(h.archive.published_order().iter().all(|p| p.ends_with(".eag")));
            }
            FinalizationStep::PublishEntryLast => {
                assert_eq!(reached.phase(), FinalizationPhase::EntryCommitted);
                assert_eq!(reached.sync_status(), SyncStatus::LocallySecured);
            }
            FinalizationStep::PublishToNetworkArchive => {
                assert_eq!(reached.phase(), FinalizationPhase::NetworkArchivePublished);
                assert!(!reached.server_upload_eligible() || reached.network_archive_published());
            }
            FinalizationStep::ReconcileAndOpenBlankDraft => {
                assert_eq!(reached.phase(), FinalizationPhase::Reconciled);
                assert!(h.staging_is_empty());
                assert!(h.current_draft().is_blank());
            }
        }
    }
}

#[test]
fn a_reused_incident_number_is_refused_under_the_writer_lock_before_serialization() {
    let mut harness = WriterHarness::with_incident(valid_incident());
    harness.offline_finalize().unwrap();
    let mut second = harness.with_same_incident_number();
    assert_eq!(second.finalize_now().unwrap_err().code(), "EA-WRITER-INCIDENT-NUMBER-TAKEN");
    assert_eq!(second.archive.published_object_count_since_mark(), 0);
}

#[test]
fn a_changed_display_name_against_an_unchanged_binding_is_refused() {
    let mut harness = WriterHarness::with_incident(valid_incident());
    harness.change_operator_display_name_only();
    assert_eq!(harness.finalize_now().unwrap_err().code(), "EA-OPERATOR-PROFILE-COMMITMENT");
}

#[test]
fn the_operator_header_position_equals_the_frozen_payload_vector() {
    let harness = WriterHarness::with_incident(valid_incident());
    assert_eq!(
        harness.serialized_payload_header_position_seven(),
        support::frozen_position_seven_of("vectors/format/payload-v1/incident.hex")
    );
}

#[test]
fn an_unknown_archive_profile_hash_blocks_before_any_byte_is_staged() {
    let mut harness = WriterHarness::with_unlisted_archive_profile();
    assert_eq!(harness.finalize_now().unwrap_err().code(), "EA-ARCHIVE-PROFILE-NOT-ALLOWED");
    assert_eq!(harness.archive.staged_object_count(), 0);
}

#[test]
fn a_controlled_network_profile_publishes_the_same_bytes_grants_first_and_entry_last() {
    let mut harness = WriterHarness::with_controlled_network_profile();
    let out = harness.offline_finalize().unwrap();
    assert_eq!(out.sync_status, SyncStatus::Synchronized);
    assert_eq!(harness.network.published_bytes(), harness.archive.published_bytes());
    assert_eq!(harness.network.published_order(), harness.archive.published_order());
}

#[test]
fn an_unreachable_network_archive_keeps_upload_pending_and_blocks_the_server_upload() {
    let mut harness = WriterHarness::with_disconnected_network_profile();
    let out = harness.offline_finalize().unwrap();
    assert_eq!(out.sync_status, SyncStatus::UploadPending);
    assert_eq!(harness.detail_cause(), Some(DetailCause::NetworkArchiveWaiting));
    assert!(!harness.server_upload_eligible());
    assert!(harness.archive.entry_is_committed());
}
```

`crates/ea-writer/tests/grant_completeness.rs`:

```rust
#[test]
fn the_plan_holds_exactly_one_recovery_and_every_active_reader() {
    let harness = WriterHarness::with_incident(valid_incident());
    let plan = harness.build_grant_plan().unwrap();
    assert_eq!(plan.items().iter().filter(|i| i.purpose() == GrantPurposeV1::Recovery).count(), 1);
    assert_eq!(
        plan.items().len(),
        1 + harness.active_reader_certificates_at_proposed_sequence().count()
    );
}

#[test]
fn a_reader_certificate_without_a_kem_thumbprint_is_refused_instead_of_silently_skipped() {
    let harness = WriterHarness::with_reader_certificate_without_kem_key();
    assert_eq!(
        harness.build_grant_plan().unwrap_err().code(),
        "EA-WRITER-READER-WITHOUT-KEM-KEY"
    );
}

#[test]
fn a_second_recovery_recipient_is_refused_by_the_stage_one_constructor() {
    let harness = WriterHarness::with_two_active_recovery_recipients();
    assert!(harness.build_grant_plan().is_err());
}

#[test]
fn every_planned_grant_exists_as_an_eag_before_the_entry_is_published() {
    let mut harness = WriterHarness::with_incident(valid_incident());
    let prepared = harness.finalize_up_to(FinalizationStep::ProduceGrantsAndEntryBytes).unwrap();
    for item in prepared.grant_plan().items() {
        assert!(prepared.grant_for(item.recipient_key_thumbprint()).is_some());
    }
    assert_eq!(
        prepared.manifest_core().fields().initial_grant_plan_hash,
        *prepared.grant_plan().hash().as_bytes()
    );
}
```

`crates/ea-writer/tests/sequence_id.rs`:

```rust
#[test]
fn sequence_uuid_cek_and_nonce_are_drawn_exactly_once() {
    let mut harness = WriterHarness::with_incident(valid_incident()).counting_entropy();
    harness.offline_finalize().unwrap();
    assert_eq!(harness.entropy_draws(), EntropyDraws { cek: 1, nonce: 1, uuid: 1 });
}

#[test]
fn the_new_entry_binds_the_direct_predecessor_and_the_uuid_is_version_seven() {
    let mut harness = WriterHarness::with_committed_predecessor();
    let out = harness.offline_finalize().unwrap();
    assert_eq!(out.sequence, harness.predecessor_sequence().next());
    assert_eq!(
        harness.committed_manifest().fields().previous_entry_hash,
        Some(harness.predecessor_entry_hash())
    );
    let uuid = harness.committed_entry_uuid();
    assert_eq!(uuid[6] >> 4, 0x7);
    assert_eq!(uuid[8] >> 6, 0b10);
}

#[test]
fn an_aborted_finalization_never_lets_the_same_sequence_be_used_twice() {
    let mut harness = WriterHarness::with_incident(valid_incident());
    let _ = harness.finalize_with_fault(FinalizationFaultPoint::AfterKeystoreDelete);
    harness.restart_and_recover().unwrap();
    let second = harness.finalize_now();
    assert!(second.is_err() || second.unwrap().sequence != harness.committed_sequence());
    assert_eq!(harness.archive.committed_entry_count(), 1);
}
```

`crates/ea-writer/tests/stale_registry_warning.rs`:

```rust
#[test]
fn stale_standard_warn_requires_a_durable_signed_one_use_acknowledgement() {
    let mut harness = WriterHarness::with_stale_warn_registry();
    let preview = harness.preview().unwrap();
    assert_eq!(harness.finalize(preview.clone(), None).unwrap_err().code(), "EA-REGISTRY-STALE-ACK-REQUIRED");
    let ack = harness.acknowledge_after_reauth(&preview).unwrap();
    assert!(harness.audit_is_signed_and_flushed(ack.audit_event_id()));
    assert_eq!(harness.audit_context_preview_hash(ack.audit_event_id()), preview.preview_hash());
    harness.finalize(preview, Some(ack.clone())).unwrap();
    assert_eq!(harness.reuse_ack(ack).unwrap_err().code(), "EA-REGISTRY-STALE-ACK-REPLAY");
}

#[test]
fn evidence_grade_block_and_an_exhausted_lease_never_reach_an_acknowledgement() {
    for harness in [
        WriterHarness::with_evidence_grade_stale_registry(),
        WriterHarness::with_signed_block_expiry_behavior(),
        WriterHarness::with_exhausted_sequence_lease(),
    ] {
        let preview = harness.preview().unwrap();
        assert!(preview.decision().is_hard_block());
        assert!(harness.acknowledge_after_reauth(&preview).is_err());
    }
}

#[test]
fn finalize_recomputes_the_preview_hash_under_the_lock_and_refuses_a_rebuilt_preview() {
    let mut harness = WriterHarness::with_stale_warn_registry();
    let preview = harness.preview().unwrap();
    let ack = harness.acknowledge_after_reauth(&preview).unwrap();
    harness.advance_committed_registry_head();
    assert_eq!(
        harness.finalize(preview, Some(ack)).unwrap_err().code(),
        "EA-REGISTRY-STALE-ACK-PREVIEW-MISMATCH"
    );
    assert_eq!(harness.archive.staged_object_count(), 0);
}

#[test]
fn the_preview_shows_the_trust_age_and_the_policy_refresh_deadline() {
    let harness = WriterHarness::with_incident(valid_incident());
    let preview = harness.preview().unwrap();
    assert_eq!(preview.trust_age_ms(), harness.expected_trust_age_ms());
    assert_eq!(
        preview.reader_trust_refresh_ms(),
        harness.selected_head().policy_fields().reader_trust_refresh_ms
    );
    assert!(!preview.trust_refresh_overdue());
    let stale = WriterHarness::with_trust_older_than_refresh_deadline();
    assert!(stale.preview().unwrap().trust_refresh_overdue());
}
```

`crates/ea-writer/tests/prepared_recovery.rs`:

```rust
#[test]
fn every_fault_recovers_the_original_draft_or_the_same_prepared_bytes() {
    for point in FinalizationFaultPoint::ALL.iter().copied() {
        let mut h = WriterHarness::with_incident(valid_incident());
        let prepared = h.capture_prepared_bytes();
        let _ = h.finalize_with_fault(point);
        let recovered = h.restart_and_recover().unwrap();
        assert!(
            recovered.is_original_draft() || recovered.committed_bytes() == prepared,
            "{point:?}"
        );
        let again = h.restart_and_recover().unwrap();
        assert_eq!(again.summary(), recovered.summary(), "ein zweites recover ist ein no-op: {point:?}");
    }
}

#[test]
fn no_fault_leaves_a_committed_entry_and_a_usable_draft_key_at_the_same_time() {
    for point in FinalizationFaultPoint::ALL.iter().copied() {
        let mut h = WriterHarness::with_incident(valid_incident());
        let _ = h.finalize_with_fault(point);
        h.restart_and_recover().unwrap();
        assert!(!(h.archive.entry_is_committed() && h.draft_dek_is_present()), "{point:?}");
        assert_eq!(h.archive.committed_entry_count(), h.archive.distinct_sequence_count());
    }
}

#[test]
fn after_the_key_boundary_recovery_reserializes_nothing_and_draws_no_randomness() {
    let mut h = WriterHarness::with_incident(valid_incident()).counting_entropy();
    let prepared = h.capture_prepared_bytes();
    let _ = h.finalize_with_fault(FinalizationFaultPoint::AfterKeystoreDelete);
    let draws_before = h.entropy_draws();
    let recovered = h.restart_and_recover().unwrap();
    assert_eq!(recovered.committed_bytes(), prepared);
    assert_eq!(h.entropy_draws(), draws_before);
    assert_eq!(h.serializations_since_mark(), 0);
}

#[test]
fn a_prepared_finalization_wins_over_a_pending_discard_intent() {
    let mut h = WriterHarness::with_incident(valid_incident());
    h.finalize_up_to(FinalizationStep::StageAndFlush).unwrap();
    assert_eq!(
        h.discard_service().begin_discard(h.proof_for(ReauthPurpose::DiscardDraft)).unwrap_err().code(),
        "EA-DRAFT-PREPARED-FINALIZATION-PRESENT"
    );
    assert_eq!(h.restart_state(), RestartState::PreparedFinalizationPending);
}
```

`crates/ea-writer/tests/orphan_and_restored_backup.rs`:

```rust
#[test]
fn orphan_grant_stays_quarantined_until_its_prepared_transaction_is_proven() {
    let mut h = WriterHarness::with_incident(valid_incident());
    let _ = h.finalize_with_fault(FinalizationFaultPoint::AfterGrantPublishBeforeEntryRename);
    assert!(h.archive.quarantined_grants().len() > 0);
    assert!(!h.archive.entry_is_committed());
    let recovered = h.restart_and_recover().unwrap();
    assert!(recovered.adopted_quarantined_grants());
    assert!(h.archive.quarantined_grants().is_empty());

    let mut orphaned = WriterHarness::with_orphan_grant_without_prepared_transaction();
    assert!(orphaned.restart_and_recover().unwrap().adopted_quarantined_grants() == false);
    assert_eq!(orphaned.archive.quarantined_grants().len(), 1);
}

#[test]
fn restored_writer_backup_blocks_finalization_until_external_head_reconciliation() {
    let mut h = WriterHarness::with_incident(valid_incident());
    h.capture_backup();
    h.offline_finalize().unwrap();
    h.restore_captured_backup();
    assert_eq!(h.finalize_now().unwrap_err().code(), "EA-WRITER-HEAD-RECONCILIATION-REQUIRED");
    assert!(h.recover_pending().unwrap().is_blocked_pending_external_head_reconciliation());
    h.reconcile_head_against_committed_archive().unwrap();
    assert!(h.finalize_now().is_ok());
}
```

`crates/ea-writer/tests/fault_point_manifest.rs` regenerates the finalization section of `docs/traceability/stage-2-fault-points.json` into a temporary buffer from `FinalizationStep::ALL` and `FinalizationFaultPoint::ALL` and compares it byte for byte against the `finalization` array of the checked-in file. It additionally asserts the coverage against **literal** lists written in the test itself, never against the enums: the thirteen step names of `design.md:448-460` and one point per class of the normative injection list `design.md:2024` — before and after every file flush, every directory flush, every create-if-absent, every rename, every keystore delete, every database step and every object-store step. Comparing an enum with itself would let a single-variant enum satisfy both promises and report green.

- [ ] **Step 6: Run the finalization tests and verify the state machine is absent**

Run:

```bash
cargo test --locked -p ea-writer
```

Expected: FAIL because preview, the acknowledgement, the finalization sequence, the fault points, the recovery path and the manifest section do not exist; `crates/ea-writer/src/lib.rs` is still the empty file of Step 0.

- [ ] **Step 7: Implement the thirteen-step finalization sequence literally**

```rust
pub enum FinalizationStep {
    RebuildLocalHead,
    CompareServerCheckpoint,
    SelectRegistryHeadAndOperator,
    ValidateAndSerialize,
    BuildAndHashGrantPlan,
    DrawSecretsAndBuildEntryHash,
    ProduceGrantsAndEntryBytes,
    StageAndFlush,
    ZeroAndDeleteDraftKey,
    PublishGrants,
    PublishEntryLast,
    PublishToNetworkArchive,
    ReconcileAndOpenBlankDraft,
}

pub enum FinalizationPhase {
    ReversibleDraft,
    PreparedAndFlushed,
    DraftKeyAbsent,
    GrantsPublished,
    EntryCommitted,
    NetworkArchivePublished,
    Reconciled,
}
```

All four public methods take `&self` and reach their state through the two locks, exactly as the discard service of Task 7 does (`DiscardService::resume_discard(&self, …)`); the finalization does not model progress as a mutable field on the service, because the only durable progress marker is `PreparedFinalization` in the encrypted store. The whole sequence runs under **one** exclusive Writer lock (`ArchiveBackend::acquire_writer_lock`), held together with the exclusive draft lock of `crates/ea-draft`; the two are different locks and both are named. Each of the thirteen steps below is one of the `FinalizationStep` variants above, in this order, with its named intermediate result.

**1. Rebuild the trusted local chain head from archive objects.** Walk every object with `ArchiveSource`, build the inventory with `ArchiveInventory`, map the entry packages to `ChainNode` values and derive the head with `ea_chain::build_chain`. The head comes from committed archive bytes only, never from the SQLite status.

**2. Compare a reachable signed server checkpoint.** Hand the authenticated checkpoint claims to `ea_chain::assess_rollback`; a rollback finding or a divergent head blocks. Without a claim the answer is `RollbackAssessment::NotAssessable`, which is not consent to continue but a state the preview reports.

**3. Select the applicable Registry head and verify the operator.** Take the highest applicable head per §12.3 through `SelectedRegistryHead`, check its time status against `preexisting_effective_now()` and the sequence lease against `valid_through_sequence()`, verify the fresh native re-authentication with `ReauthPurpose::Finalize` and the `operatorBinding` effective for OS account, device and role, and require at least one active Recovery recipient. Recompute the `archiveProfileHash` of the configured backend profile against `allowed_archive_profile_hashes` of this same bound policy version (`crates/ea-format/src/etb.rs:222`) and refuse any deviation fail-closed with `EA-ARCHIVE-PROFILE-NOT-ALLOWED` — the same check Task 9 already performs before an archive path is used, repeated here against the head that this finalization binds.

**4. Validate payload and snapshots and serialize deterministically.** Claim the incident number in `IncidentNumberRegister` under this lock, keyed by organization, local civil year and the NFC-normalized UTF-8 bytes of the `humanIncidentNumber`, and refuse a taken number with `EA-WRITER-INCIDENT-NUMBER-TAKEN` before serializing. Capture the device time zone and canonicalize it against the pinned tzdb (`jiff = 0.2.35`, `jiff-tzdb = 0.1.8`, `schemas/payload/v1/incident.schema.json:11-12`). Build header position 7 from the verified session plus the read-only operator profile row, recompute `operatorProfileCommitment` by the pinned formula (`design.md:242-252`) and compare it against `operator_profile_commitment` of the bound `operatorBinding` (`crates/ea-format/src/etb.rs:127`); a deviation is a hard abort with `EA-OPERATOR-PROFILE-COMMITMENT`. The result is the named intermediate `draftRecordBytes`.

**5. Build the initial grant plan and hash it.** Take every certificate active at the proposed sequence through `SelectedRegistryHead::active_certificates` (`crates/ea-trust/src/registry.rs:138-146`, Vertrag `:116-137`), keep every `CertificateKindV1::Reader` plus the one active `RecoveryRecipient`, and refuse with `EA-WRITER-READER-WITHOUT-KEM-KEY` if any of them carries `kem_key_thumbprint: None` — that accessor documents in its own contract that the recipient decision belongs to the caller and that nothing enforces it, and a silently skipped Reader would break the product invariant that every active Reader is granted initially. Hand the items to `ea_format::GrantPlanV1::new`, which sorts them into the normative total order over `recipientKeyThumbprint`, `recipientCertificateHash`, the UTF-8 bytes of `grantSuiteId` and `grantPurpose` (`design.md:733`), rejects duplicates and more than one Recovery, and hashes the serialized plan itself. Its `hash()` is the named intermediate `initialGrantPlanHash`. At the end of this step compute `previewHash` over `finalization-preview-core-v1` — every one of its positions exists now and none of them depends on a CSPRNG.

**6. Draw the secrets once and build the entry hash.** Draw sequence, UUIDv7, CEK and AEAD nonce **once** from the CSPRNG: `getrandom::fill` (`Cargo.toml:31`) is the same operating-system entropy that `ea-crypto` uses internally (`crates/ea-crypto/src/hpke.rs:29-34`), and the UUIDv7 is composed from the millisecond timestamp and those random bits per RFC 9562 §5.7 without a new dependency, so no ADR amendment is triggered (`docs/adr/0001-toolchain-and-cryptography-dependencies.md:152-153`). Build `manifestCore` as `ManifestCoreV1::new` with the drawn nonce and `initialGrantPlanHash` at its fixed position (`crates/ea-format/src/eip.rs:17-29`); encrypt `draftRecordBytes` with `aead_seal` under the CEK and the nonce with `payload_aad(manifestCore.exact_bytes())` as associated data; build `signedManifest` as `SignedManifestV1::new(manifestCore, ciphertext)`, which appends the `ciphertextHash`; obtain the **Writer signature** by handing `ContentType::RecordDigest`, the Writer certificate hash and `signedManifest.exact_bytes()` to the native `KeyProvider::sign`, which forms `recordDigest` and the COSE_Sign1 exactly as `CoseSigner::sign_record` does (`crates/ea-crypto/src/cose.rs:344-351`); and construct `EntryPackageV1::new(signedManifest, ciphertext, writerSignature)`, whose constructor yields **`entryHash`** (`crates/ea-format/src/eip.rs:191-205`, read at `:228-230`).

**7. Produce every `.eag` and then the final `.eip` bytes.** Only now, with `entryHash` in hand, produce every grant the plan requires. For each item build a draft `GrantBodyV1` with zero-filled encapsulation and wrapped CEK, take its `exact_grant_context()`, seal the CEK with `hpke_seal(recipientPublicKey, cek, hpke_info(context), hpke_aad(context))`, rebuild the body with the real encapsulation and assert that the context is unchanged, sign it with `KeyProvider::sign` for `ContentType::GrantDigest`, and encode it with `ea_format::encode_grant` — the two-pass construction follows the existing precedent `crates/ea-recovery/tests/support/live.rs:650-668`. Then form the final `.eip` bytes with `ea_format::encode_entry_package` and their **`objectHash`** with `ea_crypto::object_hash` (`crates/ea-crypto/src/digest.rs:63-66`). File names follow §11.4: `entries/<12-stellige-nullgepolsterte-Sequenz>_<entry-hash>.eip` (`design.md:1263`) and `grants/<entry-hash>_<grant-object-hash>.eag` (`design.md:1267`). The order **among** the grants is free; normative is only the total order of the grant **plan**, because `initialGrantPlanHash` depends on it and the published grant objects do not.

**8. Stage every byte and flush.** Write `.eip`, the grant plan, every `.eag` and a hashed transaction descriptor byte-exact into the staging area of the local archive commit component, reread and re-verify every file, fsync each of them and then fsync the staging directory. The staging area belongs to the local commit component and is **not** entered into `LAYOUT_PATHS_V1`. A controlled network profile MUST own an encrypted, durable local offline commit component inside the same configured archive profile. `PreparedFinalization` becomes durable here through `DraftRepository::replace_prepared_finalization_marker`; it and the `discardIntent` of Task 7 are two kinds of the same singleton row and therefore mutually exclusive by construction.

**9. Zero, clear, and delete the draft key — the irreversible boundary.** Zero the CEK and the serialization buffers as far as possible, clear the fachliche UI state, then delete the `draftDEK` from the keystore and confirm its absence. Only after that confirmation does the transaction cross into irreversibility and MUST be completed from the prepared bytes. From this point the Writer holds neither the CEK nor a decryptable `draftDEK` of this entry, and a committed `.eip` and a usable draft key never exist at the same time.

**10. Publish the grants create-if-absent.** An already present target name is admissible only for a byte-identical object; then fsync the grants directory.

**11. Publish the `.eip` last.** Create-if-absent plus atomic same-filesystem rename as the local archive commit marker, then fsync the entries directory. Only after this step may the application report the business completion as `lokal gesichert`.

**12. Publish to the controlled network archive.** Publish exactly the same committed bytes in the same order, grants first and `.eip` last. If the target is unreachable, the state stays `Upload ausstehend` with the separate detail cause `Netzarchiv wartet`, and **no** sync-server upload of this entry happens before the network archive publication succeeded. The four normative Sync states carry exactly the texts `lokal gesichert`, `Upload ausstehend`, `synchronisiert` and `Fehler`; the detail cause is a separate text and never a fifth state.

**13. Reconcile and open a blank draft.** Derive chain head and queues exclusively from the local committed archive component, clean up the staging area after complete reconciliation, and open a new empty form with a new `draftDEK`.

`preview` returns a typed decision for a stale head instead of silently continuing, and it carries the age of the bound trust holding together with the policy deadline `reader_trust_refresh_ms` (`schemas/archive/v1/trust.cddl:134`) so that Task 15 and Task 16 can show the refresh prompt as a visible warning and never as a block. Evidence Grade, a signed `block` and an exhausted sequence lease always return a hard error (`design.md:1447`). Only Standard plus a signed `warn` may call `acknowledge_stale_registry`, and only after a non-bypassable visible warning, a fresh `ReauthPurpose::RegistryStaleFinalize` and an explicit confirmation. The signed audit context is `stale-registry-context-v1` from Task 4 and binds `registryHeadHash`, `policyObjectHash`, the proposed sequence, `notAfter`, `acknowledgedAt` and the `previewHash` at its position 6 (`schemas/reports/v1/local-audit.cddl:6-11`); it is durably flushed **before** the acknowledgement proof is returned. `finalize` consumes that proof atomically, recomputes `previewHash` under the Writer lock, refuses a different or rebuilt preview and any replay, and re-evaluates Registry and time before crossing the `draftDEK` boundary.

`recover_pending` is the counterpart. Before the confirmed `draftDEK` deletion it restores the draft and may discard incomplete staging; the sequence then counts as unused. After the deletion it completes the transaction from the stored exact prepared bytes only — it re-serializes nothing, draws no randomness, mints no new identifier and never reuses the sequence elsewhere. Published grants without a committed `.eip` are not valid releases: they stay quarantined and are adopted only by their own proven prepared transaction, or cleaned up after a proven abort. After the `.eip` rename the archive package is the truth: a restart reconstructs head, queue and interface from it and creates no duplicate. A restored Writer backup blocks finalization with `EA-WRITER-HEAD-RECONCILIATION-REQUIRED` until the external head reconciliation has run, and `recover_pending` reports exactly that state.

- [ ] **Step 8: Declare the finalization fault points in the Stage 2 manifest**

Extend `docs/traceability/stage-2-fault-points.json`, created by Task 7 with the discard section, by the finalization section generated from `FinalizationStep::ALL` and `FinalizationFaultPoint::ALL` — each entry with its stable name and the durable step it brackets. Neither the generated `discard` array nor the hand-written `precedence` array of Task 7 is changed or removed; the precedence point keeps its exact name `PreparedFinalizationBeatsDiscardIntent` in that `precedence` array and is never duplicated into the finalization section. The file stays a checked-in artefact at a fixed repository-relative path, following the pattern of the format package (`tools/xtask/src/main.rs:907`), so that the Stage 2 gate of Task 17 reads the declared points without `tools/xtask/Cargo.toml` gaining a dependency on any Stage 2 crate.

- [ ] **Step 9: Run finalization, fault, crash, and replay tests**

Run:

```bash
cargo test --locked -p ea-writer
cargo test --locked -p ea-draft --test discard_faults
cargo test --locked -p xtask --test workspace
cargo run --locked -p xtask -- verify-quick
```

Expected: PASS on all four; no fault produces both a committed `.eip` and a usable draft key, no duplicate UUIDv7, no reused sequence, no partial valid grant set and no invalid head; the declared fault points cover the thirteen steps of `design.md:448-460` and every point class of `design.md:2024`; and the checked-in fault-point manifest matches the declared points byte for byte. The tests carry no `--test-threads=1`: they serialize themselves, and the character-exact command list of `verify_quick_commands()` (`tools/xtask/src/main.rs:41-44`, pinned `:2400-2402`) runs the same binaries in parallel immediately afterwards.

- [ ] **Step 10: Commit Writer finalization**

```bash
git add crates/ea-writer crates/ea-format crates/ea-crypto crates/ea-verify crates/ea-testkit crates/ea-audit schemas/reports/v1/finalization-preview.cddl docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-wire-format-addendum.md docs/traceability/stage-2-fault-points.json vectors/crypto/suite-1 tests/ea-system-tests tools/xtask Cargo.toml Cargo.lock
git commit -m "feat(writer): finalize immutable archives offline"
```

### Task 12: Single-File Archive Bundle Export (SYNTHESE.md: Task 7.5)

**Files:**
- Create: `crates/ea-archive-fs/src/bundle.rs`
- Create: `crates/ea-archive-fs/src/bundle_error.rs`
- Modify: `crates/ea-archive-fs/src/lib.rs`
- Modify: `crates/ea-archive-fs/tests/support/mod.rs`
- Test: `crates/ea-archive-fs/tests/bundle_export.rs`
- Test: `crates/ea-archive-fs/tests/bundle_reader.rs`

**Interfaces:**
- Consumes: `ArchiveBackend`, `ArchivePath` and `ArchiveBackendError` plus `LocalPathBackend` from Task 9; `materialize_format_package` from Task 10; the read port `ArchiveSource` and the inventory `ArchiveInventory` (`crates/ea-archive/src/source.rs:67-72`, `crates/ea-archive/src/inventory.rs:220-301`); the offline verifier `ea_verify::verify_archive` (`crates/ea-verify/src/archive.rs:244-250`) with `VerificationReportV1::{report_hash, is_fully_verified, to_canonical_json}` (`crates/ea-verify/src/report.rs:742`, `:758`, `:774`); the blob and byte caps `MAX_ARCHIVE_BLOBS_V1` and `MAX_TOTAL_ARCHIVE_BYTES_V1` (`crates/ea-archive/src/lib.rs:48-56`); a finalized archive from Task 11.
- Produces: `write_archive_bundle(&dyn ArchiveBackend, &TrustAnchorV1, &Path) -> Result<BundleExportReport, BundleError>`, the container reader `ArchiveBundleSource` implementing `ArchiveSource`, `BundleError`, and the container constants `BUNDLE_MAGIC_V1`, `BUNDLE_HEADER_BYTES_V1`, `BUNDLE_FILE_EXTENSION_V1` — all in `crates/ea-archive-fs`. `BundleError` never reaches the trait boundary: `ArchiveSource::visit_blobs` stays fixed on `Result<(), ArchiveError>` (`crates/ea-archive/src/source.rs:68-72`), and every `BundleError` case arises in `write_archive_bundle`, `ArchiveBundleSource::open` or `ArchiveBundleSource::from_bytes` and ends there.

The file mode of the Web Reader has two ways in, and only one of them works everywhere: `showDirectoryPicker` is missing in Safari and Firefox, so the universal way — one exported file, chosen through the ordinary file dialog — **MUST** always be offered (`docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md:139-145`). §12 of the same document assigns exactly this export to Stage 2 (`:441-442`). That is what this task delivers.

The container is carried inside the v1.1 scope already approved for `webBundleRelease` (`docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md:23`, `:427`; scope confirmed in `docs/superpowers/plans/2026-08-16-einsatzarchiv-web-reader-stage-1-prerequisites.md:311`), and **no seventh object family is minted**. Concretely: the container carries no exact-object prefix at all, so the six prefixes and their encoders (`crates/ea-format/src/lib.rs:39-45`), the pin that holds them against the grammar (`tools/xtask/tests/spec_completeness.rs:6-8`) and `schemas/archive/v1/archive.cddl:19-62` stay byte-for-byte untouched, and this task adds no CDDL, no vector family and no `TrustSubtypeV1` variant. Nothing signed is issued either: the signed release object of that family — its codec, its CDDL and its signature profile — is deliberately Stage 3 (`docs/superpowers/plans/2026-08-16-einsatzarchiv-web-reader-stage-1-prerequisites.md:1016`) and needs a Root ceremony that Stage 2 does not hold (`docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md:122-124`). Two frozen tests keep the name from becoming a real trust object family before then — `tools/xtask/tests/spec_completeness.rs:2405-2410` and `crates/ea-testkit/src/lib.rs:6639-6644` — and this task keeps both green because it touches neither the trust vector manifest nor the Stage 1 plan text. This paragraph exists so no later task re-opens the container question.

The container needs no signature of its own for a second, independent reason: verification in file mode always runs against the Root anchor pinned in the Reader's vault, and trust objects delivered inside the opened file justify no trust by themselves (`docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md:147-156`). A bundle is therefore a transport shell over bytes that already carry their own signatures, never a new authority.

Implementation home is `crates/ea-archive-fs` (Task 9). `crates/ea-archive` stays `std::fs`-free and stays on the wasm32 positive list, exactly as its own module contract states (`crates/ea-archive/src/source.rs:65-66`). Making `ArchiveBundleSource` shared browser code belongs to Stage 4 together with the rest of the Reader; Stage 2 needs it in `ea-archive-fs` because that is where the round-trip proof runs.

This task adds no workspace member and no new dependency — `crates/ea-archive-fs` already references `ea-archive`, `ea-format`, `ea-crypto`, `ea-types`, `ea-trust` and `ea-verify` after Task 9 — and therefore has no lockfile step: every command runs with `--locked`.

WR-052 („universeller Datei-Weg immer angeboten") moves from Stage 4 to Stage 2 with this task. The ledger row is named here and entered by Task 18, which is the only task that writes `docs/traceability/v0.1-requirements.csv`: row `docs/traceability/v0.1-requirements.csv:131` keeps `requirement_id` `WR-052`, `version` `v1.1`, `source` and `title`, changes `stage` from `4` to `2` and `status` from `planned` to `integrated`, and carries as non-empty `evidence` the two tests `bundle_is_byte_preserving_under_the_same_relative_paths` and `bundle_verifies_to_the_same_report_as_the_directory` together with the Task 12 reference. The closed Stage 1 gate table (`docs/traceability/stage-1-gate.md:97`) is **not** edited — it records the state at the Stage 1 gate; the move is documented in the Stage 2 gate report of Task 17.

- [ ] **Step 1: Write the byte-preservation, report-equality, determinism, and rejection tests**

`crates/ea-archive-fs/tests/bundle_export.rs` mirrors the two assertions that already carry the directory export (`apps/cli/tests/export.rs:249-267` and `:284-307`) — a byte map under identical relative paths, and the **whole** report rather than only its last line, because the counters `archiveObjectCount` and `nonObjectFileCount` are part of the same statement:

```rust
#[test]
fn bundle_is_byte_preserving_under_the_same_relative_paths() {
    let harness = BundleHarness::finalized_archive();
    let before = harness.digest_map();

    let report = write_archive_bundle(harness.backend(), harness.anchor(), &harness.bundle_path())
        .expect("der Export muss gelingen");

    let reopened = ArchiveBundleSource::open(&harness.bundle_path()).unwrap();
    assert_eq!(digest_map_of(&reopened), before);
    assert_eq!(harness.digest_map(), before, "die Quelle wird nur gelesen");
    assert_eq!(report.blob_count(), before.len());
}

#[test]
fn bundle_verifies_to_the_same_report_as_the_directory() {
    let harness = BundleHarness::finalized_archive();
    write_archive_bundle(harness.backend(), harness.anchor(), &harness.bundle_path()).unwrap();

    let from_directory =
        ea_verify::verify_archive(&harness.directory_source(), harness.anchor(), harness.options())
            .unwrap();
    let bundle = ArchiveBundleSource::open(&harness.bundle_path()).unwrap();
    let from_bundle = ea_verify::verify_archive(&bundle, harness.anchor(), harness.options()).unwrap();

    assert!(from_directory.is_fully_verified(), "eine stumme Quelle belegt nichts");
    assert!(from_bundle.is_fully_verified());
    assert_eq!(from_bundle.report_hash(), from_directory.report_hash());
    assert_eq!(
        from_bundle.to_canonical_json().unwrap(),
        from_directory.to_canonical_json().unwrap()
    );
}

#[test]
fn two_exports_of_the_same_archive_are_byte_identical() {
    let harness = BundleHarness::finalized_archive();
    let first = harness.bundle_path_named("first");
    let second = harness.bundle_path_named("second");
    write_archive_bundle(harness.backend(), harness.anchor(), &first).unwrap();
    write_archive_bundle(harness.backend(), harness.anchor(), &second).unwrap();
    assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
}

#[test]
fn a_bundle_carries_no_exact_object_prefix_and_adds_no_seventh_family() {
    let harness = BundleHarness::finalized_archive();
    write_archive_bundle(harness.backend(), harness.anchor(), &harness.bundle_path()).unwrap();
    let bytes = fs::read(harness.bundle_path()).unwrap();

    assert_eq!(&bytes[..BUNDLE_MAGIC_V1.len()], &BUNDLE_MAGIC_V1);
    assert_ne!(bytes[0], 0x85, "der Container traegt kein Exact-Object-Praefix");
    assert!(matches!(
        ea_format::decode_exact_object(&bytes),
        Err(ea_format::FormatError::Prefix)
    ));
}

#[test]
fn export_refuses_an_archive_that_does_not_fully_verify() {
    let harness = BundleHarness::finalized_archive().with_truncated_entry();
    assert!(matches!(
        write_archive_bundle(harness.backend(), harness.anchor(), &harness.bundle_path()),
        Err(BundleError::SourceNotFullyVerified { .. })
    ));
    assert!(!harness.bundle_path().exists(), "ein Befund erzeugt kein Ziel");
}

#[test]
fn export_refuses_an_occupied_target_without_touching_it() {
    let harness = BundleHarness::finalized_archive();
    fs::write(harness.bundle_path(), b"CANARY-EXISTING").unwrap();
    assert!(matches!(
        write_archive_bundle(harness.backend(), harness.anchor(), &harness.bundle_path()),
        Err(BundleError::TargetOccupied { .. })
    ));
    assert_eq!(fs::read(harness.bundle_path()).unwrap(), b"CANARY-EXISTING");
}
```

`BundleHarness` lives in `crates/ea-archive-fs/tests/support/mod.rs` and builds both sides from Task 9's `LocalPathBackend` over a per-test temporary root: `digest_map()` walks the backend and maps every relative path to the SHA-256 of its bytes, and `directory_source()` returns the read side of that same backend as an `ArchiveSource`. It does **not** reach for `FsArchiveSource` — that type lives in `ea-recovery` (`crates/ea-recovery/src/source.rs:14-16`), and the dependency direction is `apps/cli` → `ea-recovery`, never `ea-archive-fs` → `ea-recovery`.

`crates/ea-archive-fs/tests/bundle_reader.rs` proves that the reader is strict rather than forgiving, because a lenient container reader would let a manipulated bundle present a different byte set than the one the index describes:

```rust
#[test]
fn the_reader_rejects_a_wrong_magic_a_gap_and_an_unsorted_index() {
    for (name, mutate) in [
        ("magic", flip_first_magic_byte as fn(&mut Vec<u8>)),
        ("gap", insert_one_padding_byte_between_two_blobs),
        ("order", swap_two_index_entries),
        ("duplicate", duplicate_one_index_path),
        ("truncated", drop_the_last_payload_byte),
    ] {
        let mut bytes = BundleHarness::finalized_archive().exported_bytes();
        mutate(&mut bytes);
        assert!(
            ArchiveBundleSource::from_bytes(bytes).is_err(),
            "{name} muss abgewiesen werden"
        );
    }
}

#[test]
fn the_reader_enforces_the_same_caps_as_the_directory_reader() {
    let bytes = BundleHarness::synthetic_index_claiming(MAX_ARCHIVE_BLOBS_V1 + 1);
    assert!(matches!(
        ArchiveBundleSource::from_bytes(bytes),
        Err(BundleError::BlobLimit)
    ));
}

#[test]
fn the_bundle_carries_the_format_package_and_every_non_object_file() {
    let harness = BundleHarness::finalized_archive();
    write_archive_bundle(harness.backend(), harness.anchor(), &harness.bundle_path()).unwrap();
    let bundle = ArchiveBundleSource::open(&harness.bundle_path()).unwrap();
    let paths = path_hints_of(&bundle);
    for expected in FORMAT_PACKAGE_FILES_V1 {
        assert!(paths.contains(expected), "{expected} fehlt im Buendel");
    }
    assert!(paths.contains(&README_FORMAT_FILE_V1.to_owned()));
}
```

- [ ] **Step 2: Run the bundle tests and verify the container is absent**

Run: `cargo test --locked -p ea-archive-fs --test bundle_export ; cargo test --locked -p ea-archive-fs --test bundle_reader`

Expected: FAIL because `write_archive_bundle`, `ArchiveBundleSource`, `BundleError` and the container constants do not exist. The two commands are separated by `;` and not by `&&` so that both failures are reported: the writer and the reader are two different absent surfaces.

- [ ] **Step 3: Implement the container, the writer, and the reader**

The container is deterministic, uncompressed, and self-describing, and it exists exactly to carry bytes that already carry their own signatures:

```text
[0 ..32)        BUNDLE_MAGIC_V1 = b"EINSATZARCHIV-ARCHIVE-BUNDLE-v1\n"   (32 ASCII bytes)
[32..40)        u64 big-endian: blob count
[40..48)        u64 big-endian: byte length n of the index region
[48..48+n)      index region: one record per blob, in index order
                  u16 big-endian: byte length p of the path
                  p bytes:        the relative path as NFC-UTF-8
                  u64 big-endian: offset into the payload region
                  u64 big-endian: byte length of the blob
[48+n.. )       payload region: the blobs, verbatim, in index order
```

`BUNDLE_HEADER_BYTES_V1 = 48` and `BUNDLE_FILE_EXTENSION_V1 = "eabundle"`. Every header and index field is an unsigned big-endian integer of fixed width; there is no CBOR, no length-prefix ambiguity and no self-describing type layer, and therefore no new dependency: `crates/ea-archive-fs` keeps exactly the six workspace edges Task 9 gave it, `Cargo.lock` stays as it is, and every command of this task runs with `--locked`. Index records are sorted strictly ascending over the NFC-UTF-8 path bytes, no path occurs twice, and `offset` is relative to the start of the payload region. Offsets are contiguous and start at zero: the first blob begins at `0`, every following blob begins exactly where its predecessor ended, and the payload region ends exactly at the end of the file. There is no padding, no alignment and no free space, so two exports of the same archive are the same file and any inserted byte is a rejection rather than a silently tolerated difference.

The magic deliberately begins with `0x45` (`b'E'`) and therefore can never be mistaken for an exact-object prefix, whose first two bytes are `0x85 0x44` (`crates/ea-format/src/parser.rs:21-26`). Should a bundle ever be dropped into an archive directory, the inventory classifies it at the prefix and counts it under `nonObjectFileCount` (`crates/ea-archive/src/lib.rs:22-38`) — the class is not selectable by renaming, which is the property that lets this container exist beside the frozen format instead of inside it.

`write_archive_bundle` follows the order that the directory export already established (`crates/ea-recovery/src/export.rs:26-42`), and for the same reason: an export is a copy, not a re-issue, and nothing is copied that has not been judged first.

1. Read the archive **once** through `ArchiveBackend` into the buffer, capped by `MAX_ARCHIVE_BLOBS_V1` and `MAX_TOTAL_ARCHIVE_BYTES_V1` — the same caps and the same inclusive bounds the directory reader uses (`crates/ea-recovery/src/source.rs:30-41`), never a second set of numbers.
2. Verify that buffer completely with `ea_verify::verify_archive` against the externally supplied `TrustAnchorV1`. A report that is not fully verified ends the run with `BundleError::SourceNotFullyVerified` and creates no target.
3. Materialize the format package through `materialize_format_package` (Task 10) if the archive is missing it, so that a bundle is never a less complete holding than the directory it came from — `nonObjectFileCount` is part of the report, and a bundle without `README-FORMAT.txt` would verify to a different report.
4. Refuse an occupied target with `BundleError::TargetOccupied` before writing a single byte, following the free-target rule that `crates/ea-recovery/src/target.rs` already states once rather than inventing a second one.
5. Write magic, index length, index and payload from the **same** buffer that was judged, then `fsync` the file and its directory.

Nothing is decrypted, re-encoded, re-sorted or omitted. There is no `--key`, no recipient key and no plaintext anywhere in this path; a bundle is encrypted because its objects are, which is what makes it verifiable offline against an external anchor alone.

`ArchiveBundleSource::{open, from_bytes}` parses magic, index length and index, checks every structural rule of the container — sorted, duplicate-free, contiguous, in-bounds, within both caps — and only then exposes `visit_blobs`, handing each blob out with its recorded path as `path_hint` and its bytes untouched. A structural violation is an error, never a skipped entry: silently dropping a blob would mean losing archive bytes without saying so.

`BundleError` is the export's own error type — `SourceNotFullyVerified`, `TargetOccupied`, `Malformed`, `BlobLimit`, `TotalByteLimit`, `Io` — and never `Debug`-prints archive bytes or host paths, following the reasoning already written down for `FsArchiveSource` (`crates/ea-recovery/src/source.rs:42-48`).

- [ ] **Step 4: Run the bundle tests green**

Run: `cargo test --locked -p ea-archive-fs --test bundle_export && cargo test --locked -p ea-archive-fs --test bundle_reader && cargo test --locked -p ea-verify`

Expected: PASS. Every byte of the holding travels under the same relative path, the bundle verifies to the identical report and identical `reportHash` as the directory, two exports are the same file, the container carries no exact-object prefix, and `ea-verify` is unchanged — it verifies a bundle through the same `ArchiveSource` port it already had.

- [ ] **Step 5: Commit the single-file bundle export**

```bash
git add crates/ea-archive-fs
git commit -m "feat(archive): export an archive holding as a single verifiable bundle file"
```


### Task 13: Frontend and Tauri Prelude (SYNTHESE.md: Task 7.6)

**Files:**
- Create: `apps/desktop/package.json`
- Create: `apps/desktop/vite.config.ts`
- Create: `apps/desktop/src/test-setup.ts`
- Create: `apps/desktop/playwright.config.ts`
- Create: `apps/desktop/src-tauri/Cargo.toml`
- Create: `apps/desktop/src-tauri/build.rs`
- Create: `apps/desktop/src-tauri/src/main.rs`
- Modify: `.gitignore`
- Modify: `package.json`
- Modify: `pnpm-lock.yaml`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `tools/xtask/tests/workspace.rs`
- Test: `apps/desktop/src/test-environment.test.tsx`
- Test: `apps/desktop/src/e2e-config.test.ts`

**Interfaces:**
- Consumes: the tranche-1 pinning rule and the pinning test from Task 1; the platform lock/session event of Task 3.
- Produces: the `apps/desktop` package with its exact dependency selection frozen in `pnpm-lock.yaml`, the Vitest DOM environment with its matcher setup and `userEvent` fixture, `apps/desktop/playwright.config.ts`, the `.gitignore` entries, the workspace member `apps/desktop/src-tauri` as package `ea-desktop`, the tranche-3 pins `tauri` and `tauri-build`, and the three frontend scripts in the root `package.json`.

This is a **prelude, not a scaffold task.** The scaffold itself belongs to Task 15, whose Files block creates `tsconfig.json`, `index.html`, `src/main.tsx`, `src-tauri/tauri.conf.json`, `src-tauri/src/lib.rs` and the shell sources; `pnpm-workspace.yaml:2` has declared `apps/desktop` since Stage 1, and `package.json:4-8` pins pnpm 11.20.0 and Node 26.7.0. What is missing is everything the Stage 2 UI commands call and no Files block names: a runner with a DOM environment, the matchers, the `userEvent` fixture, a Playwright configuration, ignore rules, and the Rust member entry with its pins. One artefact, one home — this task creates exactly those, and Task 15 and Task 16 create nothing that appears here.

- [ ] **Step 0: Extend `.gitignore`, register the workspace member, and create both lockfiles once**

Extend `.gitignore` — which Task 1 has already extended by `.DS_Store` — by exactly these lines, **before any `pnpm` command runs**, because otherwise the first `git add apps/desktop` checks in `node_modules`, `dist` and `src-tauri/target`:

```
node_modules/
dist/
target/
```

Create `apps/desktop/package.json` with the package name, the `type: "module"` marker and the scripts `typecheck`, `build`, `test` and `e2e` that Task 15 and Task 16 call by name; choose the exact minor/patch of every dependency here, since `.npmrc:1-2` sets `save-exact=true` and `engine-strict=true` and `design.md:147` demands lockfile pinning of the released Ant minor/patch. Runtime: `react`, `react-dom`, `antd`, `@ant-design/static-style-extract`, `@phosphor-icons/react`, `@tauri-apps/api`. Development: `typescript`, `vite`, `@vitejs/plugin-react`, `vitest`, `jsdom`, `@testing-library/react`, `@testing-library/jest-dom`, `@testing-library/user-event`, `@playwright/test`, `@tauri-apps/cli`. `react-icons` is not a dependency and must not become one.

Create `apps/desktop/src-tauri/Cargo.toml` with `name = "ea-desktop"` — every library crate follows the `ea-` prefix and no other name is defined anywhere — plus `apps/desktop/src-tauri/build.rs` and a minimal `apps/desktop/src-tauri/src/main.rs`. The manifest declares the Stage 2 dependency set of `ea-desktop` so that only one further dependency edge remains for Task 15 and every command there keeps `--locked`: `tauri`, `serde`, `serde_json` under `[dependencies]`, `tauri-build` under `[build-dependencies]`, plus every Stage 2 core crate that already exists at this point — `ea-types`, `ea-schema`, `ea-format`, `ea-archive`, `ea-archive-fs`, `ea-key-provider`, `ea-operator`, `ea-local-store`, `ea-audit`, `ea-draft`, `ea-writer` — each with `workspace = true`, which `tools/xtask/tests/workspace.rs:86-101` enforces across all three dependency tables. `build.rs` and `main.rs` stay empty stubs in this task: `tauri_build::build()` and `tauri::generate_context!` both read `src-tauri/tauri.conf.json`, and that file is created by Task 15, which fills both stubs in the same step.

Modify `Cargo.toml`: add `apps/desktop/src-tauri` under `[workspace]members` and the tranche-3 pins `tauri` and `tauri-build` under `[workspace.dependencies]`, each with a leading `=` after the pattern `Cargo.toml:11-12`, which the pinning test from Task 1 then checks. `serde` entered the table in Task 1 and `serde_json` has been there since Stage 1; neither is added again. `tokio` and `async-trait` do **not** appear: that `tokio` shows up transitively through `tauri` in `Cargo.lock` is expected and is not a `[workspace.dependencies]` entry.

Modify `tools/xtask/tests/workspace.rs`: append the member path to `WORKSPACE_MEMBERS` (Task 1) and nowhere else — the length assertion, the set comparison and the dependency walk all derive from that one list. `apps/desktop/src-tauri` receives **no** wasm32 classification at all: the classification test collects members under `crates/` only (`tools/xtask/tests/workspace.rs:152-158`), and a classified name that is not such a member is rejected.

Run: `cargo metadata --format-version 1 > /dev/null` (without `--locked`) && `pnpm install` (without `--frozen-lockfile`)

Expected: PASS; `Cargo.lock` afterwards contains `ea-desktop`, `tauri` and `tauri-build`, and `pnpm-lock.yaml` — nine lines with an empty importer today (`pnpm-lock.yaml:1-9`) — afterwards records the `apps/desktop` importer with every resolved version. Only then do the `--locked` and `--frozen-lockfile` commands of the following tasks run.

- [ ] **Step 1: Write the runner-environment and E2E-configuration tests**

`apps/desktop/src/test-environment.test.tsx` proves that the three things Task 15 and Task 16 use without ever declaring them actually resolve — a DOM, the extended matchers, and the `userEvent` fixture:

```tsx
it('provides a DOM, localStorage, and the extended matchers', () => {
  render(<button type="button" disabled>Finalisieren</button>)
  expect(screen.getByRole('button', { name: 'Finalisieren' })).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Finalisieren' })).toBeDisabled()
  localStorage.setItem('probe', 'value')
  expect(localStorage.getItem('probe')).toBe('value')
})

it('provides a userEvent fixture that types and clicks', async () => {
  const user = userEvent.setup()
  render(<input aria-label="Freitext" />)
  await user.type(screen.getByLabelText('Freitext'), 'Ada')
  expect(screen.getByLabelText('Freitext')).toHaveValue('Ada')
})
```

`apps/desktop/src/e2e-config.test.ts` reads `apps/desktop/playwright.config.ts` and asserts its three load-bearing keys without starting a browser:

```ts
it('runs the e2e suite from the package, against the built app, with the network off', async () => {
  const config = (await import('../playwright.config')).default
  expect(config.testDir).toBe('tests/e2e')
  expect(config.webServer?.command).toContain('vite preview')
  expect(config.use?.offline).toBe(true)
})
```

- [ ] **Step 2: Run the frontend tests and verify the environment is absent**

Run: `pnpm --dir apps/desktop test --run`

Expected: FAIL because `vite.config.ts` declares no `test.environment` and no `test.setupFiles`, so `document` is undefined and `toBeInTheDocument` is not a matcher, and because `playwright.config.ts` does not exist. This is a red test run and not a package-manager abort: `apps/desktop/package.json` and `node_modules` exist since Step 0, which is precisely why Step 0 comes first.

- [ ] **Step 3: Implement the runner configuration, the E2E configuration, and the command chain**

`apps/desktop/vite.config.ts` carries the React plugin and, under `test`, `environment: 'jsdom'` and `setupFiles: ['./src/test-setup.ts']`. `apps/desktop/src/test-setup.ts` imports `@testing-library/jest-dom/vitest` and re-exports the `userEvent` fixture, so no test file sets up matchers of its own. Task 15 extends only the build entry and the hashed-asset configuration of this file and leaves both `test` keys as written here.

`apps/desktop/playwright.config.ts` sets `testDir: 'tests/e2e'` — relative to the package, which is what makes `pnpm --dir apps/desktop exec playwright test tests/e2e/writer-offline.spec.ts` resolve, while `<repo>/tests/` stays reserved for the Rust member `tests/ea-system-tests` (`Cargo.toml:2`) — starts the built application as `webServer`, and switches the browser context offline through `use: { offline: true }` plus `context.route('**', route => route.abort())`, so the Task 16 promise "PASS with network disabled" has a carrier instead of a hope.

Modify the root `package.json`: add `"desktop:typecheck"`, `"desktop:test"` and `"desktop:e2e"` next to the six existing xtask scripts (`package.json:9-16`), each delegating to the matching `pnpm --dir apps/desktop` command. This is the named chain the Stage 2 gate branch of Task 17 records; `verify_quick_commands()` (`tools/xtask/src/main.rs:25-60`) and its character-exact pin stay untouched, because that list is frozen by the closed Stage 1 gate.

R14 needs two things from this task and nothing else: the `tauri` feature selection in `apps/desktop/src-tauri/Cargo.toml` that makes the platform lock/session event observable on Windows, macOS and Ubuntu, and `@tauri-apps/api` as a pinned frontend dependency so that `apps/desktop/src/app/session-lock.ts` (Task 15) has an event API to subscribe to. The subscription itself and the invalidation of the `OperatorSessionProof` are written in Task 15 and are not anticipated here.

- [ ] **Step 4: Run the frontend environment and the workspace bookkeeping green**

Run:

```bash
pnpm --dir apps/desktop test --run
cargo test --locked -p xtask --test workspace
```

Expected: PASS. The DOM environment, the matchers and the `userEvent` fixture resolve, `playwright.config.ts` carries `testDir`, `webServer` and the offline context, and the workspace test accepts the new member count, the new member set and the two `=`-pinned tranche-3 entries. The single host build of `ea-desktop` is not run here — it belongs to Task 15 Step 4, and the three-operating-system matrix belongs to Stage 7.

- [ ] **Step 5: Commit the frontend and Tauri prelude**

```bash
git add apps/desktop .gitignore package.json pnpm-lock.yaml Cargo.toml Cargo.lock tools/xtask
git commit -m "build(desktop): pin the frontend toolchain and register the Tauri package"
```


### Task 14: `ea-ui-contracts` with Generator and Determinism Test (SYNTHESE.md: Task 7.7)

**Files:**
- Create: `crates/ea-ui-contracts/Cargo.toml`
- Create: `crates/ea-ui-contracts/src/lib.rs`
- Create: `crates/ea-ui-contracts/src/emit.rs`
- Create: `crates/ea-ui-contracts/src/bin/emit-ts.rs`
- Create: `apps/desktop/src/bridge/generated-contracts.ts`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `tools/xtask/src/main.rs`
- Modify: `tools/xtask/tests/workspace.rs`
- Test: `crates/ea-ui-contracts/tests/generated_ts_is_current.rs`
- Test: `apps/desktop/src/bridge/no-hand-written-contracts.test.ts`

**Interfaces:**
- Consumes: `FinalizeOutcome` and `FinalizationPreview` from Task 11; `SyncStatus` and `DetailCause` from Task 9 (`crates/ea-archive-fs`); the closed snapshot and incident types of `ea-schema`; the identifier and time types of `ea-types`; and the security enums that stay where they were defined — `LocalAuditOutcomeV1` (`crates/ea-format/src/local_audit.rs:26-32`), `KeyProtectionProfileV1` (`crates/ea-format/src/etb.rs:82-90`), `OperatorRoleV1` (`crates/ea-format/src/etb.rs:92-98`), `QuarantineReason` (`crates/ea-archive/src/inventory.rs:75`) and `SignerRole` (`crates/ea-crypto/src/cose.rs:815-826`); and from Task 13 the Vitest DOM runner with its setup file and the installed `node_modules` of `apps/desktop`, without which `pnpm --dir apps/desktop test --run src/bridge` in Step 2 and Step 4 cannot run.
- Produces: the crate `crates/ea-ui-contracts` with the Writer view models, the emitter binary `emit-ts`, the checked-in emitter output `apps/desktop/src/bridge/generated-contracts.ts`, and the drift gate `generated_ts_is_current.rs`.

Global Constraint: TypeScript never creates grants, hashes, signatures, ciphertexts, Registry decisions or archive bytes. That line only holds if the DTO surface has a single named source, which today it has not: `crates/ea-ui-contracts` is named exactly once in the Stage 2 material and does not exist (`Cargo.toml:2` does not list it; the name appears otherwise only in the directory sketch `docs/superpowers/plans/2026-08-13-einsatzarchiv-v0-1.md:107`). This task creates it.

The crate lives under `crates/` and not as a module of `apps/desktop/src-tauri`, and the reason is worth one sentence so it is not re-litigated: an emitter inside the desktop package would have to run as `cargo run -p ea-desktop`, which drags the entire Tauri build stack — WebView2, Xcode Command Line Tools, webkit2gtk — into the act of writing one TypeScript file, while Stage 2 deliberately allows exactly one host build of that package, in Task 15.

Its dependency contract is likewise fixed here. `ea-ui-contracts` performs **no** cryptographic operation and produces no bytes; it takes type-only dependencies on `ea-types`, `ea-schema`, `ea-writer` and on those crates whose security enums it re-exports — `ea-format`, `ea-crypto`, `ea-archive`, `ea-archive-fs` — because re-export is the whole point: a security enum is generated from its one definition and never hand-copied. Re-export beats a shorter dependency list.

- [ ] **Step 0: Register the workspace member and create the lockfile once**

Create `crates/ea-ui-contracts/Cargo.toml` and an empty `crates/ea-ui-contracts/src/lib.rs` so that the member path resolves. Modify `Cargo.toml`: add `crates/ea-ui-contracts` under `[workspace]members` and the path entry `ea-ui-contracts = { path = "crates/ea-ui-contracts" }` under `[workspace.dependencies]`, following the existing `ea-*` path entries (`Cargo.toml:18-29`). The crate manifest references `ea-types`, `ea-schema`, `ea-format`, `ea-crypto`, `ea-archive`, `ea-archive-fs` and `ea-writer` with `workspace = true`, which `tools/xtask/tests/workspace.rs:90-101` enforces.

Modify `tools/xtask/src/main.rs`: append one `(name, justification)` pair for `ea-ui-contracts` with a non-empty justification to the `WASM32_EXEMPT_CRATES` slice (`tools/xtask/src/main.rs:102`, a slice since Task 1, so no arity edit exists to make), following the `ea-recovery` precedent (`tools/xtask/src/main.rs:103-111`). The justification to record verbatim: this crate carries a file-writing binary in `src/bin/emit-ts.rs`, and `cargo check --target wasm32-unknown-unknown -p …` checks binaries too, so the positive list would turn the wasm32 command red. **Never** the positive list, whose text the closed Stage 1 gate freezes (`docs/traceability/stage-1-gate.md:60-65`). Modify `tools/xtask/tests/workspace.rs`: append the member path to `WORKSPACE_MEMBERS` (Task 1) and nowhere else — the length assertion, the set comparison and the dependency walk all derive from that one list; the classification test (`:220-245`) then holds without further change.

Run: `cargo metadata --format-version 1 > /dev/null` (without `--locked`)

Expected: PASS; `Cargo.lock` afterwards contains the new package. Only then do the `--locked` commands of this task run.

- [ ] **Step 1: Write the drift, determinism, enum-derivation, and no-computation tests**

`crates/ea-ui-contracts/tests/generated_ts_is_current.rs`:

```rust
#[test]
fn the_checked_in_file_is_exactly_what_the_emitter_writes() {
    let generated = ea_ui_contracts::emit_typescript();
    let checked_in = fs::read_to_string(generated_contracts_path()).unwrap();
    assert_eq!(
        generated, checked_in,
        "run `cargo run --locked -p ea-ui-contracts --bin emit-ts` and commit the result"
    );
}

#[test]
fn two_emitter_runs_are_byte_identical() {
    assert_eq!(
        ea_ui_contracts::emit_typescript().into_bytes(),
        ea_ui_contracts::emit_typescript().into_bytes()
    );
}

#[test]
fn every_security_enum_is_derived_from_its_rust_definition() {
    let emitted = ea_ui_contracts::emit_typescript();
    for (name, variants) in ea_ui_contracts::SECURITY_ENUMS_V1 {
        let block = named_union_block(&emitted, name);
        assert_eq!(
            union_members(&block),
            variants.to_vec(),
            "{name} must be emitted from its Rust definition, in declaration order"
        );
    }
    assert_eq!(
        union_members(&named_union_block(&emitted, "SyncStatus")),
        vec!["lokal gesichert", "Upload ausstehend", "synchronisiert", "Fehler"]
    );
}

#[test]
fn the_emitted_file_declares_types_and_computes_nothing() {
    let emitted = ea_ui_contracts::emit_typescript();
    for forbidden in [
        "function", "=>", "class", "import(", "require(", "crypto", "subtle", "sha", "sign",
    ] {
        assert!(
            !emitted.to_ascii_lowercase().contains(forbidden),
            "the generated contracts must contain no {forbidden}"
        );
    }
    for line in emitted.lines().filter(|line| !line.trim().is_empty()) {
        assert!(
            line.starts_with("//")
                || line.starts_with("export type")
                || line.starts_with("export const")
                || line.starts_with(' ')
                || line == "}"
                || line == "] as const",
            "unexpected construct in a generated declaration file: {line}"
        );
    }
}
```

`apps/desktop/src/bridge/no-hand-written-contracts.test.ts` carries the half a Rust test cannot see: a Rust test can assert over the string it emitted, but only a TypeScript test can read the tree that consumes it. It scans every file under `apps/desktop/src` except `generated-contracts.ts` itself **and except `*.test.ts`/`*.test.tsx`, whose assertions must be able to name the rendered string**. At this point that tree holds only the two Task 13 environment tests and `test-setup.ts`, so its green run here proves nothing yet — the file is created in this task rather than in Task 15 because it must already be in place when Task 15 and Task 16 write the first shell and feature sources, and its value is every later run, not this one:

```ts
it('declares no security enum outside the generated contracts', async () => {
  const sources = await handWrittenSources()
  for (const literal of securityEnumLiterals) {
    for (const [path, text] of sources) {
      expect(text, `${path} duplicates the security literal ${literal}`).not.toContain(literal)
    }
  }
})

it('creates no grant, hash, signature, ciphertext, or archive byte in TypeScript', async () => {
  const sources = await handWrittenSources()
  for (const [path, text] of sources) {
    expect(text, path).not.toMatch(/crypto\.subtle|createHash|Ed25519|X25519|ChaCha20|new Uint8Array\(32\)/)
  }
})
```

- [ ] **Step 2: Run the contract tests and verify the crate and its output are absent**

Run: `cargo test --locked -p ea-ui-contracts ; pnpm --dir apps/desktop test --run src/bridge`

Expected: FAIL because `emit_typescript`, `SECURITY_ENUMS_V1` and `apps/desktop/src/bridge/generated-contracts.ts` do not exist. The two commands are separated by `;` and not by `&&` so that the missing TypeScript side is reported as well as the missing Rust side.

- [ ] **Step 3: Implement the contracts, the emitter, and the generated file**

`crates/ea-ui-contracts/src/lib.rs` declares the Writer view models as plain Rust structs and enums over `ea-types` and `ea-schema` values — the finalization preview with the bound trust age and the policy deadline, the finalize outcome without any content, the archive health summary, the device posture summary and the pending-finalization resume model — and re-exports the security enums listed under **Interfaces** unchanged from their defining crates, `SyncStatus` and `DetailCause` from `ea-archive-fs` included. Not one of them is re-declared here: a second declaration is exactly the duplication the drift gate is meant to prevent, and the enum-derivation test compares the emitted variants against `SECURITY_ENUMS_V1`, which is built from the re-exported definitions rather than from a literal list.

`crates/ea-ui-contracts/src/emit.rs` exposes `pub fn emit_typescript() -> String` and writes a **declaration-only** file: a fixed header comment naming the generating command, then `export type` unions and `export const … as const` arrays, in a fixed order, with `\n` line endings, two-space indentation and a trailing newline. Order comes from a declared list and never from a `HashMap`, sets are sorted, and nothing formats a timestamp, a path or a version read from the environment — those are the four usual sources of a byte difference between two runs, and the determinism test exists to catch them.

`crates/ea-ui-contracts/src/bin/emit-ts.rs` writes that string to `apps/desktop/src/bridge/generated-contracts.ts`, resolved relative to the workspace root, and prints nothing else. It is the only writer of that file: Task 15 imports it and never edits it, and Task 16 extends `crates/ea-ui-contracts/src/lib.rs` with the Writer DTOs and re-runs the emitter rather than editing the output.

Run `cargo run --locked -p ea-ui-contracts --bin emit-ts` and commit the result; the drift gate then fails `cargo test --workspace` for any later edit of the generated file, which is what closes the hole that all four verify-quick commands leave open for a checked-in generated artefact.

- [ ] **Step 4: Run the generator and both drift gates green**

Run:

```bash
cargo run --locked -p ea-ui-contracts --bin emit-ts
cargo test --locked -p ea-ui-contracts
pnpm --dir apps/desktop test --run src/bridge
cargo test --locked -p xtask --test workspace
```

Expected: PASS. `the_checked_in_file_is_exactly_what_the_emitter_writes` proves that the committed file is exactly what the emitter run just produced. Two emitter runs are byte-identical, every emitted security union matches the variants of its Rust definition in declaration order, the generated file contains no function and no cryptographic identifier, no hand-written TypeScript duplicates a security literal, and the workspace test accepts the new member together with its wasm32 exception entry.

- [ ] **Step 5: Commit the contract crate and its generated output**

```bash
git add crates/ea-ui-contracts apps/desktop/src/bridge tools/xtask Cargo.toml Cargo.lock
git commit -m "feat(ui-contracts): generate TypeScript DTOs from Rust with a determinism gate"
```
### Task 15: Tauri Bridge, Static Ant Design Foundation, and Role-Gated Shell (SYNTHESE.md: Task 8)

**Files:**
- Create: `apps/desktop/tsconfig.json`
- Create: `apps/desktop/index.html`
- Create: `apps/desktop/src/main.tsx`
- Create: `apps/desktop/src/app/AppShell.tsx`
- Create: `apps/desktop/src/app/role-gate.ts`
- Create: `apps/desktop/src/app/session-lock.ts`
- Create: `apps/desktop/src/app/StartupRecovery.tsx`
- Create: `apps/desktop/src/app/TrustAgeStatus.tsx`
- Create: `apps/desktop/src/design/tokens.ts`
- Create: `apps/desktop/src/design/icons.tsx`
- Create: `apps/desktop/src/design/extract-static-css.tsx`
- Create: `apps/desktop/src/design/static-antd.css`
- Create: `apps/desktop/src-tauri/tauri.conf.json`
- Create: `apps/desktop/src-tauri/src/lib.rs`
- Create: `apps/desktop/src-tauri/src/state.rs`
- Create: `apps/desktop/src-tauri/src/commands/mod.rs`
- Create: `apps/desktop/src-tauri/src/commands/session.rs`
- Create: `apps/desktop/src-tauri/src/commands/master_data.rs`
- Modify: `apps/desktop/package.json`
- Modify: `apps/desktop/vite.config.ts`
- Modify: `apps/desktop/src-tauri/src/main.rs`
- Modify: `apps/desktop/src-tauri/Cargo.toml`
- Modify: `Cargo.lock`
- Test: `apps/desktop/src/app/AppShell.test.tsx`
- Test: `apps/desktop/src/app/csp.test.ts`
- Test: `apps/desktop/src/design/static-css.test.ts`
- Test: `apps/desktop/src/design/icons.test.tsx`
- Test: `apps/desktop/src/design/bundle.test.ts`

**Interfaces:**
- Consumes: the verified device role/session DTO from Rust only; `apps/desktop/src/bridge/generated-contracts.ts` as emitted by `ea-ui-contracts` (Task 14); `WriterService::recover_pending`; `OperatorAuthenticator::reauthenticate` with `ReauthPurpose` and the opaque `OperatorSessionProof` (Task 3) together with the native lock/session event; `MasterDataRepository` read surface; the runner, DOM environment, `playwright.config.ts`, `.gitignore` entries, the `ea-desktop` member entry and the `tauri`/`tauri-build` pins from Task 13 plus the `serde` and `serde_json` entries of the root table (Task 1 and Stage 1 respectively).
- Produces: local-only CSP-hardened shell with exact tokens, `commands/mod.rs` as the single command registration site, the automatic pending-finalization startup path, the trust-age status surface, and no local role escalation.

Task 15 gates the Writer only. Administration is Stage 5 (`design.md:2177`), and the Reader is the browser PWA (`2026-08-15-einsatzarchiv-web-reader-design.md:51-56`, `:466`) — the desktop shell therefore carries no Reader route, no Reader view, and no Reader command, and the role-gate test asserts that absence positively. This sentence exists so no later task re-adds either surface.

- [ ] **Step 0: Add the one remaining dependency edge and refresh the lockfile once**

Modify `apps/desktop/src-tauri/Cargo.toml`: add `ea-ui-contracts.workspace = true` under `[dependencies]`. This is the single Stage 2 dependency edge Task 13 could not declare, because `crates/ea-ui-contracts` is created only in Task 14; every other dependency of `ea-desktop` — `tauri`, `serde`, `serde_json`, `tauri-build` and the Stage 2 core crates — stands in the manifest since Task 13 Step 0 and is not touched again. The root `Cargo.toml` needs no edit: the path entry `ea-ui-contracts = { path = "crates/ea-ui-contracts" }` under `[workspace.dependencies]` was written by Task 14 Step 0, and `tools/xtask/tests/workspace.rs:90-101` then accepts the new `workspace = true` reference without a change to the member bookkeeping, because this task adds no member.

Run: `cargo metadata --format-version 1 > /dev/null` (without `--locked`)

Expected: PASS; `Cargo.lock` afterwards records `ea-ui-contracts` as a dependency of `ea-desktop`. Only then do the `--locked` commands of this task run.

- [ ] **Step 1: Write role-gate, static-style, CSP, and bundle tests**

```tsx
it('enables the Writer link only from the verified session, never from local configuration', async () => {
  const { rerender } = render(<AppShell session={{ role: 'reader', capabilities: [] }} />)
  expect(screen.queryByRole('link', { name: /einsatz erfassen/i })).not.toBeInTheDocument()
  localStorage.setItem('role', 'writer')
  rerender(<AppShell session={{ role: 'reader', capabilities: [] }} />)
  expect(screen.queryByRole('link', { name: /einsatz erfassen/i })).not.toBeInTheDocument()
  rerender(<AppShell session={{ role: 'writer', capabilities: ['capture'] }} />)
  expect(screen.getByRole('link', { name: /einsatz erfassen/i })).toBeVisible()
})

it('offers no Reader and no Administration surface at all', () => {
  render(<AppShell session={{ role: 'writer', capabilities: ['capture'] }} />)
  expect(screen.queryByRole('link', { name: /archiv (lesen|öffnen)/i })).not.toBeInTheDocument()
  expect(screen.queryByRole('link', { name: /verwaltung|administration/i })).not.toBeInTheDocument()
  expect(routeTable().map((route) => route.path)).toEqual(['/', '/einsatz'])
})

it('ships extracted styles and creates no runtime style tags', () => {
  render(<AppShell session={writerSession} />)
  expect(loadedStaticCss()).toContain('--ea-ink')
  expect(document.querySelectorAll('style[data-ant-cssinjs]').length).toBe(0)
})

it('extracts byte-identical css twice', () => {
  expect(extractStaticCss()).toBe(extractStaticCss())
})
```

`csp.test.ts` reads `apps/desktop/src-tauri/tauri.conf.json` and compares the directive list position by position against the target value pinned in Step 3. `bundle.test.ts` reads the files under `apps/desktop/dist` and proves that no `http:`/`https:` URL for a font or a style and no `react-icons` identifier occurs in them. `icons.test.tsx` proves that every icon import resolves to a per-icon module path of `@phosphor-icons/react` and that no wildcard or dynamic full-catalog import exists.

- [ ] **Step 2: Run the UI tests and verify the shell is absent**

Run: `pnpm --dir apps/desktop test --run`

Expected: FAIL because `AppShell`, the role gate, the token module, and the static style pipeline do not exist; the runner, the DOM environment, and the matchers come from Task 13 and resolve, so this is a red test run and not a package-manager abort.

- [ ] **Step 3: Implement the shell, the token source, and the static style pipeline**

The six tokens named by `design.md:163-170` are the source of truth. They stand as named constants and every Ant alias is derived from them; no alias is ever set from a literal:

```ts
export const eaInk = '#172033'
export const eaSurface = '#F5F7FA'
export const eaAction = '#245EA8'
export const eaDanger = '#C6352B'
export const eaVerified = '#187255'
export const eaWarning = '#A65F00'

export const eaTokens = {
  colorText: eaInk,
  colorBgLayout: eaSurface,
  colorPrimary: eaAction,
  colorError: eaDanger,
  colorSuccess: eaVerified,
  colorWarning: eaWarning,
  colorInfo: eaAction,
  colorLink: eaAction,
  fontFamilyCode: 'ui-monospace, SFMono-Regular, Consolas, monospace',
} as const
```

`colorInfo` and `colorLink` take `eaAction` because `Alert`, `Tag`, and `Result` (`design.md:151`) resolve them and the frozen color contract has no seventh value; this introduces no seventh hex literal. `eaTokens` is the single input of `ConfigProvider` and of `apps/desktop/src/design/extract-static-css.tsx`. A shared package for `apps/web` is created only once `apps/web` exists in `pnpm-workspace.yaml:2`.

`extract-static-css.tsx` emits, from the same six constants and before the Ant output, the custom-property block that `static-css.test.ts` checks positively:

```css
:root{--ea-ink:#172033;--ea-surface:#F5F7FA;--ea-action:#245EA8;--ea-danger:#C6352B;--ea-verified:#187255;--ea-warning:#A65F00}
```

Use `ConfigProvider` with the German locale, `theme={{ zeroRuntime: true, token: eaTokens }}`, and the Ant `App` context for overlays. Call `@ant-design/static-style-extract` in the **explicit component form** `extractStyle((node) => …)` and pass `Modal`, `message`, and `notification` in addition to the components used by the shell. The argument-free form omits popup components; under `zeroRuntime: true` plus a CSP that forbids runtime style injection, the unstyled result would hit exactly the irreversible confirmations of Task 16, so the extraction scope is pinned here and not left to the default. Assign the emitted file to its own cascade layer and import it as `@import url(static-antd.css) layer(antd);` so downgraded Ant rules cannot outrank application rules. Hash `static-antd.css` and bundle it as a local resource; load no webfont.

`apps/desktop/src-tauri/tauri.conf.json` carries exactly this directive list, and `csp.test.ts` compares it position by position:

```
default-src 'none'; script-src 'self'; style-src 'self'; style-src-elem 'self'; style-src-attr 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' ipc: http://ipc.localhost; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'
```

`style-src` and `style-src-elem` at `'self'` are what forbids runtime and external styles: no injected `<style>` element and no remote stylesheet can load. `style-src-attr` stays at `'unsafe-inline'` because React and Ant Design set element `style` attributes for layout, and a style attribute loads nothing and injects no rule set — this split is the decision, so it is not reopened later. `connect-src` carries `ipc:` and `http://ipc.localhost` because Tauri 2 routes its command channel through them.

`apps/desktop/src/bridge/generated-contracts.ts` is the emitter output of `crates/ea-ui-contracts` (Task 14) and is only imported here, never hand-edited and never regenerated by this task. Routing derives exclusively from the verified Rust session response; `role-gate.ts` reads no `localStorage`, no configuration file, and no environment variable.

`commands/mod.rs` declares every command module (`mod session; mod master_data;` here, `mod writer;` added by Task 16) and is the single registration site; `src-tauri/src/lib.rs` builds the `invoke_handler` from that list and exposes `pub fn registered_command_names() -> &'static [&'static str]`, while `src-tauri/src/main.rs` shrinks to the thin binary that calls `ea_desktop::run()`. Every `#[tauri::command]` handler runs its synchronous core operation through `tauri::async_runtime::spawn_blocking`, so the fsync-heavy finalization of Task 11 never blocks the main thread; async exists only in this layer.

`StartupRecovery.tsx` runs `WriterService::recover_pending` as the automatic startup path before any Writer route resolves and hands on a validated view model; the shell renders no Writer route until that call returns. `session-lock.ts` subscribes to the native lock/session event of each platform and invalidates the `OperatorSessionProof` immediately, in addition to the five-minute inactivity default, so a return from the lock is a re-authentication obligation. `TrustAgeStatus.tsx` is the status surface of the shell for the age of the bound trust holding and the policy deadline `readerTrustRefreshMs` (`schemas/archive/v1/trust.cddl:134`, `crates/ea-format/src/etb.rs:220`); Task 16 fills it with the preview values.

Use the native UI sans-serif stack for prose and the declared local monospace stack only for hashes, fingerprints, and technical IDs. Import each Phosphor icon per icon from `@phosphor-icons/react` with `weight="regular"` by default and `weight="fill"` only for an active or positively confirmed state; `react-icons` is not a dependency. Decorative icons carry `aria-hidden="true"`; every icon-only button has an accessible name and a tooltip. Security, integrity, Evidence, and destruction state always include exact text and never rely on icon or color alone. Disable or shorten nonessential transitions under `prefers-reduced-motion` and keep visible keyboard focus on every interactive control.

`apps/desktop/package.json` gains only the scripts `typecheck`, `build`, and `test` that Steps 2 and 4 call by name; the dependency selection and the exact Ant minor/patch pin (`design.md:147`, mechanical through `save-exact=true` in `.npmrc:1`) belong to Task 13 together with `pnpm-lock.yaml`. `apps/desktop/vite.config.ts` gains the build entry and the hashed-asset configuration only; its `test.environment` and `test.setupFiles` keys stay as Task 13 wrote them. `apps/desktop/src-tauri/Cargo.toml` is touched in Step 0 and only there, for the one `ea-ui-contracts` edge: Task 13 declares every other Stage-2 dependency of `ea-desktop`, so `Cargo.lock` is final after that one prelude step and every command from here on keeps `--locked`.

- [ ] **Step 4: Run typecheck, host build, style determinism, CSP, and component tests**

Run:

```bash
pnpm --dir apps/desktop typecheck
pnpm --dir apps/desktop build
pnpm --dir apps/desktop test --run
cargo build --locked -p ea-desktop
```

Expected: PASS. The build precedes the test run because `bundle.test.ts` reads `apps/desktop/dist`. Two style extractions are byte-identical, the production bundle carries no external font or style URL and no `react-icons` import, the CSP directive list matches position by position, and `ea-desktop` compiles for the host target — the three-operating-system matrix and the signed release build remain Stage 7.

- [ ] **Step 5: Commit the desktop foundation**

```bash
git add apps/desktop Cargo.lock
git commit -m "feat(desktop): add role-gated static UI foundation"
```

### Task 16: Writer Form, Review, Discard, and Finalization UX (SYNTHESE.md: Task 9)

**Files:**
- Create: `apps/desktop/src/features/writer/WriterPage.tsx`
- Create: `apps/desktop/src/features/writer/IncidentForm.tsx`
- Create: `apps/desktop/src/features/writer/MasterDataSelect.tsx`
- Create: `apps/desktop/src/features/writer/ReviewStep.tsx`
- Create: `apps/desktop/src/features/writer/FinalizeStep.tsx`
- Create: `apps/desktop/src/features/writer/StaleRegistryWarning.tsx`
- Create: `apps/desktop/src/features/writer/DiscardDraftAction.tsx`
- Create: `apps/desktop/src/features/writer/PendingFinalizationResume.tsx`
- Create: `apps/desktop/src/features/writer/ArchiveBundleExport.tsx`
- Create: `apps/desktop/src/components/integrity/SyncStatus.tsx`
- Create: `apps/desktop/src/components/integrity/IrreversibleActionConfirm.tsx`
- Create: `apps/desktop/src/components/integrity/PatientDataWarning.tsx`
- Create: `apps/desktop/src/components/integrity/VerificationBadge.tsx`
- Create: `apps/desktop/src/components/integrity/EvidenceStatus.tsx`
- Create: `apps/desktop/src/components/integrity/FingerprintBlock.tsx`
- Create: `apps/desktop/src/components/integrity/ChainIntegrityRail.tsx`
- Create: `apps/desktop/src/components/integrity/ArchiveHealthPanel.tsx`
- Create: `apps/desktop/src/components/integrity/DevicePosturePanel.tsx`
- Create: `apps/desktop/src-tauri/src/commands/writer.rs`
- Modify: `crates/ea-ui-contracts/src/lib.rs`
- Modify: `apps/desktop/src/bridge/generated-contracts.ts`
- Modify: `apps/desktop/src-tauri/src/lib.rs`
- Modify: `apps/desktop/src-tauri/src/main.rs`
- Modify: `apps/desktop/src-tauri/src/state.rs`
- Modify: `apps/desktop/src-tauri/src/commands/mod.rs`
- Modify: `apps/desktop/src-tauri/tauri.conf.json`
- Modify: `apps/desktop/src/app/AppShell.tsx`
- Modify: `apps/desktop/src/app/role-gate.ts`
- Test: `apps/desktop/src/features/writer/WriterPage.test.tsx`
- Test: `apps/desktop/tests/e2e/writer-offline.spec.ts`
- Test: `apps/desktop/src-tauri/tests/writer_commands.rs`

**Interfaces:**
- Consumes: `WriterService::{preview,acknowledge_stale_registry,finalize,recover_pending}`, `FinalizationPreview`, `ArchiveHealthReport`, `DevicePostureReport`, draft/master-data services, re-authentication, the single-file archive bundle export of Task 12 in `crates/ea-archive-fs`, and `FinalizeOutcome` without content.
- Produces: exact Writer UX contract, the Tauri command allowlist anchored by a literal expected set, and no route and no command for opening final content.

The seven domain components over the Ant building blocks carry the names of `design.md:151-159`; `FingerprintBlock` uses the monospace family `ui-monospace` (`design.md:172`). `crates/ea-ui-contracts/src/lib.rs` gains the Writer DTOs and is re-emitted, so `apps/desktop/src/bridge/generated-contracts.ts` changes as generator output and never by hand. `apps/desktop/src-tauri/Cargo.toml` stays untouched in this task: Task 13 declares the dependency set of `ea-desktop` and Task 15 Step 0 added the one remaining `ea-ui-contracts` edge, so nothing is left for this task to declare, and re-touching the manifest here would invalidate `Cargo.lock` and break `--locked` for every command of this task.

- [ ] **Step 1: Write workflow, input-contract, recovery, and allowlist tests**

The patient count is an Ant `Radio.Group`, not a native `<select>`: Ant Design 6 renders a `Select` as `role="combobox"` with a popup, so the tests address radios by their accessible name and the same strings appear in the implementation.

```tsx
it('distinguishes known zero from unknown and blocks finalize before review confirmation', async () => {
  render(<WriterPage bridge={fakeWriterBridge()} />)
  await user.click(screen.getByRole('radio', { name: 'bekannt' }))
  await user.clear(screen.getByLabelText('Anzahl'))
  await user.type(screen.getByLabelText('Anzahl'), '0')
  await user.click(screen.getByRole('button', { name: 'Prüfen' }))
  expect(screen.getByText('0 Patienten')).toBeVisible()
  expect(screen.getByRole('button', { name: 'Unwiderruflich finalisieren' })).toBeDisabled()
  await user.click(screen.getByRole('checkbox', { name: /unwiderruflich/i }))
  expect(screen.getByRole('button', { name: 'Unwiderruflich finalisieren' })).toBeEnabled()
  await user.click(screen.getByRole('button', { name: 'Zurück zur Erfassung' }))
  await user.click(screen.getByRole('radio', { name: 'unbekannt' }))
  await user.click(screen.getByRole('button', { name: 'Prüfen' }))
  expect(screen.queryByText('0 Patienten')).not.toBeInTheDocument()
  expect(screen.getByText('Patientenzahl unbekannt')).toBeVisible()
})

it('finalizes an incident without vehicles when a reason is given and rejects the empty list without one', async () => {
  const bridge = fakeWriterBridge()
  render(<WriterPage bridge={bridge} />)
  await fillMinimalIncident()
  await user.click(screen.getByRole('button', { name: 'Prüfen' }))
  expect(screen.getByRole('alert')).toHaveTextContent(/Begründung/i)
  expect(screen.getByRole('button', { name: 'Unwiderruflich finalisieren' })).toBeDisabled()
  await user.type(screen.getByLabelText('Begründung für leere Fahrzeugliste'), 'kein Fahrzeug alarmiert')
  await user.click(screen.getByRole('button', { name: 'Prüfen' }))
  expect(bridge.preview).toHaveBeenLastCalledWith(
    expect.objectContaining({ vehicles: [], vehiclesEmptyReason: 'kein Fahrzeug alarmiert' }),
  )
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()
})

it('never offers a bypass for stale Registry and obtains a signed acknowledgement only after re-auth', async () => {
  const bridge = staleWarnBridge()
  render(<WriterPage bridge={bridge} />)
  await advanceToFinalize()
  expect(screen.getByRole('alert')).toHaveTextContent(/Registry.*abgelaufen/i)
  expect(screen.queryByRole('button', { name: /trotzdem ohne bestätigung/i })).not.toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Warnung bestätigen und erneut authentisieren' }))
  expect(bridge.acknowledgeStaleRegistry).toHaveBeenCalledTimes(1)
  expect(screen.getByText(/signierte Bestätigung erfasst/i)).toBeVisible()
})

it('shows trust age and refresh deadline as a warning without blocking finalization', async () => {
  render(<WriterPage bridge={overdueTrustBridge()} />)
  await advanceToFinalize()
  const warning = screen.getByRole('status', { name: 'Vertrauensbestand' })
  expect(warning).toHaveTextContent('Trust-Bestand 9 Tage alt')
  expect(warning).toHaveTextContent('Frist 7 Tage')
  expect(warning).toHaveTextContent('Aktualisierung erforderlich')
  expect(screen.getByRole('button', { name: 'Unwiderruflich finalisieren' })).toBeEnabled()
})

it('resumes a prepared finalization and blocks a restored backup without any finalize control', async () => {
  const { rerender } = render(<WriterPage bridge={preparedPendingBridge()} />)
  expect(screen.getByRole('progressbar', { name: 'Fertigstellung läuft' })).toBeVisible()
  expect(screen.getByText('Upload ausstehend')).toBeVisible()
  expect(screen.getByText('Netzarchiv wartet')).toBeVisible()
  rerender(<WriterPage bridge={restoredBackupBridge()} />)
  expect(screen.getByRole('alert')).toHaveTextContent(/externe Head-Reconciliation ausstehend/i)
  expect(screen.queryByRole('button', { name: 'Unwiderruflich finalisieren' })).not.toBeInTheDocument()
})
```

The Rust anchor test stays synchronous, like the whole core:

```rust
#[test]
fn registered_commands_match_the_literal_writer_allowlist() {
    const EXPECTED: &[&str] = &[
        "session_current",
        "session_reauthenticate",
        "master_data_search",
        "draft_load_active",
        "draft_save",
        "draft_discard_begin",
        "draft_discard_resume",
        "writer_preview",
        "writer_acknowledge_stale_registry",
        "writer_finalize",
        "writer_recover_pending",
        "archive_health_report",
        "device_posture_report",
        "archive_export_bundle_file",
    ];
    assert_eq!(ea_desktop::registered_command_names(), EXPECTED);
    let conf = include_str!("../tauri.conf.json");
    let mut from_capabilities: Vec<&str> = capability_command_names(conf);
    from_capabilities.sort_unstable();
    let mut expected_sorted = EXPECTED.to_vec();
    expected_sorted.sort_unstable();
    assert_eq!(from_capabilities, expected_sorted);
    for name in EXPECTED {
        assert!(!name.contains("decrypt"));
        assert!(!name.contains("history"));
        assert!(!name.contains("entry_content"));
    }
}
```

- [ ] **Step 2: Run the Writer tests and verify the workflow is absent**

Run: `pnpm --dir apps/desktop test --run WriterPage`

Expected: FAIL because the Writer page, the domain components, and the Writer commands do not exist.

- [ ] **Step 3: Implement exact Writer behavior**

Start always on the active or blank draft, unless the startup path of Task 15 reports a pending finalization — then `PendingFinalizationResume.tsx` renders exactly two visible outcomes and nothing else: the continued completion of a prepared transaction with progress, and the blocked state after a backup restore with the text of the pending external head reconciliation and **no** finalize control at all.

The input contract of the incident body is complete and matches the wire positions `payload-wire-addendum.md:102-118`: `humanIncidentNumber`; `occurredAt` with start and optional end; the keyword as either free text or reference plus display text; the location as free text or structured address, each with optional coordinates as integer E7 pairs; `personnel` and `vehicles` as snapshot lists; `personnelEmptyReason` and `vehiclesEmptyReason`; `patientCountStatus` with `patientCount`; `notes`; and `externalOrganizations`. The two reason fields follow the biconditional Stage 1 rule enforced by `crates/ea-schema/src/model.rs:1612-1622` with error code `EA-SCHEMA-LIST-REASON`: visible only while the matching list is empty, mandatory then, and never set otherwise. The patient count uses the labels `bekannt` and `unbekannt`; `unknown` renders as `Patientenzahl unbekannt` and never as a zero.

Suggest `YYYY-NNNN` but allow controlled editing until finalization. The organization/year uniqueness check in the interface is a preview without authority; the register with its `UNIQUE` constraint and the enforcement under the exclusive Writer lock live in Rust, and the interface never decides the case. Support searchable, favorite, multi-select people and vehicles and highlighted ad-hoc snapshots. Show the autosave state and a local-only patient-data warning on all free text.

Review displays every field and snapshot plus archive health (`ArchiveHealthPanel.tsx` over `ArchiveHealthReport`), device posture with `Unknown` as unresolved (`DevicePosturePanel.tsx` over `DevicePostureReport`), Recovery recipient, Registry, and head; `VerificationBadge` and `ChainIntegrityRail` carry the verified states, `EvidenceStatus` the Evidence grade. It also shows the age of the bound trust holding and the policy deadline from `readerTrustRefreshMs`, and on exceedance a visible prompt to refresh — as a warning with text and icon, never as a block on finalization. `commands/writer.rs` exposes one read command each for the health report and the posture report.

For Standard `warn`, show the stale Registry version and head, the expiry, the consequence, and the offline limitation in a persistent `role="alert"`; enable the acknowledgement only after the separate native re-authentication action returns the Rust-issued signed proof. Offer no close icon, no keyboard escape, no "remember", and no generic continue path. Evidence Grade, `block`, and an exhausted lease show a blocking state with no finalize control.

Finalize and discard each require native re-authentication and a separate irreversible confirmation through `IrreversibleActionConfirm`; ordinary saving stays a different action with a different control and never triggers either. A return from the operating-system lock invalidates the session proof, so the next finalize or discard attempt demands re-authentication again.

`SyncStatus.tsx` renders exactly the four normative states, and does so exclusively through the `SyncStatus` union imported from `apps/desktop/src/bridge/generated-contracts.ts` and the `as const` list emitted there; no literal is written in the component. The detail cause `Netzarchiv wartet` is a separate text next to `Upload ausstehend` and never a fifth state. After commit, clear UI state, show only hashes and sequence through `FingerprintBlock` plus `lokal gesichert`, then open a blank form. Provide no history, no "last incident", no decrypt, no delete-final, and no content-bearing sync queue interface.

`ArchiveBundleExport.tsx` offers the single-file archive bundle export of Task 12 permanently and not behind a condition: `showDirectoryPicker` is unavailable in Safari and Firefox, so the universal file path of the Web Reader MUST always be offered. The export copies sealed archive bytes through `crates/ea-archive-fs`, decrypts nothing, renders no entry content, and opens no browsable history; its command `archive_export_bundle_file` therefore stands in the literal expected set of `writer_commands.rs` and does not weaken the promise that the Writer reaches neither history nor final content.

All controls are reachable by keyboard with named screen-reader labels, keep visible focus, and state security-relevant conditions as text in addition to color and icon.

- [ ] **Step 4: Run unit, keyboard, offline E2E, and command-allowlist tests**

Run:

```bash
cargo run --locked -p ea-ui-contracts --bin emit-ts
cargo test --locked -p ea-ui-contracts
pnpm --dir apps/desktop test --run
pnpm --dir apps/desktop exec playwright test tests/e2e/writer-offline.spec.ts
cargo test --locked -p ea-desktop --test writer_commands
```

Expected: PASS with network disabled. The emitter run writes the Writer DTOs into `apps/desktop/src/bridge/generated-contracts.ts`, and `the_checked_in_file_is_exactly_what_the_emitter_writes` confirms the checked-in version. The E2E run resolves `tests/e2e/writer-offline.spec.ts` relative to `apps/desktop` and uses the `playwright.config.ts` from Task 13, which sets `testDir: 'tests/e2e'`, starts the built application as `webServer`, and aborts network access in the context. The test finalizes, sees a blank form, verifies that no content-opening command exists, and completes all controls by keyboard with named screen-reader labels; `--test writer_commands` makes a missing test carrier a hard error instead of a silent "0 passed".

- [ ] **Step 5: Commit Writer UX**

```bash
git add apps/desktop crates/ea-ui-contracts
git commit -m "feat(desktop): deliver offline Writer workflow"
```

### Task 17: Stage 2 Gate Tooling in xtask (SYNTHESE.md: Task 9.5)

**Files:**
- Modify: `tools/xtask/src/main.rs`
- Modify: `tools/xtask/tests/stage_gate.rs`
- Modify: `package.json`

**Interfaces:**
- Consumes: the checked-in fault-point manifest `docs/traceability/stage-2-fault-points.json` (discard section from Task 7, finalization section from Task 11); the requirement ledger `docs/traceability/v0.1-requirements.csv`; the three frontend scripts `desktop:typecheck`, `desktop:test` and `desktop:e2e` in the root `package.json` (Task 13); the frozen Stage 1 gate machinery in `tools/xtask/src/main.rs`.
- Produces: the executable gate `cargo run --locked -p xtask -- stage-gate 2`; the four additive report fields `declared_fault_points`, `stage_two_primary_acceptance_criteria`, `host_evidence_rows` and `stage_two_rows_still_planned`; the machine-checked content contract of `docs/traceability/stage-2-gate.md`, which Task 18 then writes; the root scripts `stage-gate:2` and `supply-chain`.

Today `run_stage_gate` refuses every stage but one — `tools/xtask/src/main.rs:1587-1592` returns `"stage-gate is only defined for stage 1 so far"` — and everything behind that guard hangs on Stage 1 constants: the vector families (`main.rs:866-868`), the ten primary acceptance criteria (`main.rs:878`), the report path (`main.rs:910`), the five mandatory sections (`main.rs:1026-1032`), the fifteen mandatory literals (`main.rs:1035-1051`) and the verbatim scope clause (`main.rs:1059-1065`). This task opens the switch and gives Stage 2 its own constants of every one of those kinds. Nothing of Stage 1 is weakened: `gate_report_acceptance_criteria` (`main.rs:1482-1531`) merely takes the expected criteria as a parameter and the Stage 1 caller passes `&STAGE_ONE_PRIMARY_ACCEPTANCE_CRITERIA`, the Stage 1 branch keeps every check it has, and every existing test function in `tools/xtask/tests/stage_gate.rs` stays exactly as it is — the Stage 2 tests are **appended**. That file carries the closed Stage 1 gate including decision D3 (`tools/xtask/tests/stage_gate.rs:604`) and the measured Stage 1 run (`:1010-1058`); it is modified, never rewritten.

**The gate checks the declaration, not the run.** That is the existing contract, stated at `main.rs:1400-1401` for the fuzz surfaces, and Stage 2 keeps it. Consequences that must not be re-litigated: the fault-point coverage is read from the checked-in manifest `docs/traceability/stage-2-fault-points.json` instead of from Rust types, so `tools/xtask/Cargo.toml:10-17` gains **no** dependency on a Stage 2 crate and the gate tool never pulls SQLCipher or the host backends into its own graph; and the supply-chain check promised by `docs/adr/0001-toolchain-and-cryptography-dependencies.md:44-45` and by the consequences section of ADR 0002 is wired as the script `supply-chain` plus a mandatory measured row in the gate report — enforced by the Stage 2 measured-run test of Task 18 — and **not** as a `cargo deny` shell-out from inside the gate. A red supply chain then has only two possible shapes: a missing row, which the gate rejects, or a false row, which is fraud — while the gate itself stays hermetic and runnable without `cargo-deny` installed.

Two more decisions are settled here so no later task reopens them. `xtask` gains **no** `test-fault` and **no** `test-privacy` subcommand: both would be wrappers around `cargo test` with no checking logic of their own, and `--scope writer` would invent a flag grammar for a single value, while the dispatcher (`main.rs:1676-1717`) deliberately knows exactly eight gates and ends in `unknown gate` otherwise. And the Stage 2 branch collects **every** unmet condition and fails with all of them at once, following the collecting shape of `parse_requirement_ledger` (`tools/xtask/src/main.rs:1246`, `:1321`); a missing `docs/traceability/stage-2-gate.md` is therefore a collected problem and not an IO abort, exactly as a missing ledger is deliberately an empty ledger rather than an IO error (`main.rs:1340-1348`). Without that, the failure Task 18 expects in its RED step would name one missing file instead of naming what is actually uncovered.

This task adds no workspace member and no dependency: `serde_json` is already a dependency of `xtask` (`tools/xtask/Cargo.toml:10-17`). It therefore has **no** lockfile step, and every command runs with `--locked`.

- [ ] **Step 1: Write the Stage 2 gate fixture tests**

Append to `tools/xtask/tests/stage_gate.rs`. The tests are fixture-driven under `EA_STAGE_GATE_ROOT` (`tools/xtask/tests/stage_gate.rs:29-44`, `:169-175`) and each holds a FEHLERzustand at exactly one place, following the pattern the file already documents; the ZIELzustand against the real working tree is Task 18's test, because the real gate report and the real ledger rows do not exist before that task.

`stage_two_fixture(label)` builds a green Stage 2 baseline in a fresh temp root named from PID and nanoseconds, following `fixture_with_the_checked_in_documents` (`tools/xtask/tests/stage_gate.rs:885-897`): it writes the two vector family manifests `local-audit` and `reports`, copies the checked-in design document, requirement ledger, format package and fuzz manifest, then rewrites the copied ledger so that every Stage 2 row carries `implemented` and four appended rows name the four Stage 7 host targets — copying the real ledger is what keeps the required-identifier coverage satisfied without restating it. It further writes a synthetic `docs/traceability/stage-2-fault-points.json` with a non-empty `discard`, `finalization` and `precedence` array and exactly one occurrence of `PreparedFinalizationBeatsDiscardIntent`, a synthetic `package.json` carrying the five required scripts, and a synthetic `docs/traceability/stage-2-gate.md` that satisfies the content contract. Each phase below removes or breaks exactly one of those.

```rust
/// Die beiden Vektorfamilien, die Stufe 2 additiv anlegt.
const STAGE_TWO_FAMILIES: [&str; 2] = ["local-audit", "reports"];

/// Die zwoelf primaeren Abnahmekriterien der Stufe 2.
const STAGE_TWO_PRIMARY_ACCEPTANCE_CRITERIA: [u32; 12] =
    [1, 2, 3, 15, 23, 25, 28, 34, 39, 46, 48, 54];

/// Die vier Zielarchitekturen, fuer die Stufe 2 keine lokale Behauptung
/// aufstellt und deren Nachweis als offene Stufe-7-Ledgerzeile steht.
const STAGE_TWO_HOST_TARGETS: [&str; 4] = [
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
];

#[test]
fn stage_two_gate_names_every_missing_declaration_at_once() {
    // Phase 1: die gruene Grundlage. Der Gate beendet mit 0 und liefert die
    // vier additiven Berichtsfelder.
    let root = stage_two_fixture("baseline");
    let output = run_stage_gate(&root, "2");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        output.status.success(),
        "stage-gate 2 must accept the complete fixture; stderr: {stderr}"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let report: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("stdout must be JSON: {error}; stdout: {stdout}"));
    assert_eq!(report["stage"], serde_json::json!(2));
    assert_eq!(
        report["vector_families"],
        serde_json::json!(STAGE_TWO_FAMILIES)
    );
    assert_eq!(
        report["stage_two_primary_acceptance_criteria"],
        serde_json::json!(STAGE_TWO_PRIMARY_ACCEPTANCE_CRITERIA)
    );
    assert!(
        report["declared_fault_points"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "PreparedFinalizationBeatsDiscardIntent"),
        "the declared points carry the precedence point; stdout: {stdout}"
    );
    assert!(!report["host_evidence_rows"].as_array().unwrap().is_empty());
    assert!(
        report["stage_two_rows_still_planned"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    // Phase 2: der Gate-Bericht fehlt, ein Stufe-2-Ledgereintrag steht auf
    // `planned`, und eine Host-Zielarchitektur wird von keiner Zeile genannt.
    // Der Gate nennt ALLE DREI in EINER Fehlermeldung — sonst begruendet der
    // RED-Schritt der Stufenabnahme nur den ersten Mangel.
    let root = stage_two_fixture("three-gaps");
    fs::remove_file(root.join("docs/traceability/stage-2-gate.md")).unwrap();
    write_stage_two_ledger(
        &root,
        LedgerDefect::OneRowPlannedAndOneHostTargetUnnamed("FR-043", "x86_64-pc-windows-msvc"),
    );
    let output = run_stage_gate(&root, "2");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2));
    for expected in ["docs/traceability/stage-2-gate.md", "FR-043"] {
        assert!(
            stderr.contains(expected),
            "stage-gate 2 must name {expected} in the same failure; stderr: {stderr}"
        );
    }
    for target in STAGE_TWO_HOST_TARGETS {
        assert_eq!(
            stderr.contains(target),
            target == "x86_64-pc-windows-msvc",
            "stage-gate 2 must name exactly the unnamed host target; stderr: {stderr}"
        );
    }

    // Phase 3: das Fault-Punkt-Manifest verliert seinen Finalisierungsteil.
    let root = stage_two_fixture("manifest");
    write_fault_point_manifest(&root, FaultManifestDefect::NoFinalizationSection);
    let output = run_stage_gate(&root, "2");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("finalization"),
        "stage-gate 2 must name the empty manifest section; stderr: {stderr}"
    );

    // Phase 4: eine Abnahmekriteriumszeile ohne Eintrag in der Spalte
    // `Offen in spaeterer Stufe`. Eine leere Spalte ist genau die
    // Scheinzusage, die dieser Bericht ausschliesst.
    let root = stage_two_fixture("empty-open-column");
    write_stage_two_report(&root, ReportDefect::EmptyOpenColumn(46));
    let output = run_stage_gate(&root, "2");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("AK 46"),
        "stage-gate 2 must name the incomplete row; stderr: {stderr}"
    );

    // Phase 5: die drei Frontend-Skripte fehlen in der Wurzel-`package.json`.
    // Ohne sie hat die Stufe keine UI-Spur, und jede exakte UI-Zusage waere
    // nach Stufe 2 unbelegt.
    let root = stage_two_fixture("scripts");
    write_package_manifest(&root, &["stage-gate:2", "supply-chain"]);
    let output = run_stage_gate(&root, "2");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("desktop:e2e"),
        "stage-gate 2 must name the missing frontend script; stderr: {stderr}"
    );
}

#[test]
fn the_stage_switch_still_refuses_an_undefined_stage() {
    let root = stage_two_fixture("stage-three");
    let output = run_stage_gate(&root, "3");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("stages 1 and 2"),
        "the switch must name the stages it defines; stderr: {stderr}"
    );
}
```

`LedgerDefect`, `FaultManifestDefect` and `ReportDefect` are small test-local enums with one variant per phase plus a `None` variant that the baseline builder uses — `LedgerDefect::OneRowPlannedAndOneHostTargetUnnamed` puts the named row back on `planned` and drops the row that named the given target, so phase 2 really produces all three gaps at once; `write_stage_two_ledger`, `write_fault_point_manifest`, `write_stage_two_report` and `write_package_manifest` write the corresponding fixture file. They live in `tools/xtask/tests/stage_gate.rs` next to the existing `write_ledger` (`:153-157`), `write_family_manifest` (`:159-167`) and `write_design_document` (`:98-129`) and follow their shape.

- [ ] **Step 2: Run the new tests against the closed stage switch**

Run: `cargo test --locked -p xtask --test stage_gate stage_two ; cargo test --locked -p xtask --test stage_gate the_stage_switch`

Expected: FAIL because `run_stage_gate` rejects every stage but 1 (`tools/xtask/src/main.rs:1588-1592`), so all five phases receive the same message `stage-gate is only defined for stage 1 so far, not 2`; no Stage 2 constant, no fault-point manifest reader, no Stage 2 report contract and no script check exists. The two commands are separated by `;` and not by `&&`, because the second command must run even after the first has failed as intended.

- [ ] **Step 3: Open the stage switch and declare the Stage 2 constants**

`run_stage_gate` dispatches on the stage: `1` keeps the existing body unchanged, `2` calls the new `run_stage_two_gate`, and every other value keeps a refusal — reworded to `"stage-gate is only defined for stages 1 and 2 so far, not {stage}"`. No test pins the old wording; the message exists only at `main.rs:1590`.

The Stage 2 constants stand next to their Stage 1 counterparts and follow their naming and their sorting rule — lexicographic or in document order, so that report and failure line are byte-reproducible:

```rust
/// Die Vektorfamilien, die Stufe 2 additiv anlegt: der lokale Audit-Encoder
/// (Task 4) und das Importprotokoll (Task 8).
const STAGE_TWO_VECTOR_FAMILIES: [&str; 2] = ["local-audit", "reports"];

/// Die primaeren Abnahmekriterien der Stufe 2 nach `design.md` Abschnitt 23.
const STAGE_TWO_PRIMARY_ACCEPTANCE_CRITERIA: [u32; 12] =
    [1, 2, 3, 15, 23, 25, 28, 34, 39, 46, 48, 54];

/// Der Stufe-2-Gate-Bericht, relativ zur Gate-Wurzel.
const STAGE_TWO_GATE_REPORT_PATH: &str = "docs/traceability/stage-2-gate.md";

/// Das Manifest der deklarierten Abbruchpunkte, relativ zur Gate-Wurzel.
///
/// Ein eingechecktes Artefakt an festem Pfad, nach dem Muster des
/// Formatpakets (`FORMAT_PACKAGE_PATH`): der Gate liest die DEKLARATION und
/// braucht dafuer keine Abhaengigkeit auf `ea-writer` oder `ea-draft`.
const STAGE_TWO_FAULT_POINT_MANIFEST_PATH: &str = "docs/traceability/stage-2-fault-points.json";

/// Die Wurzel-`package.json`, relativ zur Gate-Wurzel.
const PACKAGE_MANIFEST_PATH: &str = "package.json";

/// Der Abbruchpunkt, der nicht in `DiscardFaultPoint::ALL` liegt und den der
/// Gate dennoch namentlich verlangt: er startet planmaessig in
/// `PreparedFinalizationPending` und nicht in einen unveraenderten Entwurf.
const DISCARD_PRECEDENCE_FAULT_POINT: &str = "PreparedFinalizationBeatsDiscardIntent";

/// Die vier Zielarchitekturen, deren native Ausfuehrung Stufe 2 NICHT
/// behauptet. Jede MUSS von mindestens einer Ledgerzeile namentlich als
/// offener Stufe-7-Nachweis gefuehrt werden.
const STAGE_TWO_HOST_TARGETS: [&str; 4] = [
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
];

/// Die Skripte, die die Wurzel-`package.json` fuehren MUSS.
const STAGE_TWO_REQUIRED_SCRIPTS: [&str; 5] = [
    "desktop:e2e",
    "desktop:test",
    "desktop:typecheck",
    "stage-gate:2",
    "supply-chain",
];

/// Die Pflichtabschnitte des Stufe-2-Gate-Berichts, in Dokumentreihenfolge.
const STAGE_TWO_GATE_REPORT_SECTIONS: [&str; 5] = [
    "## 1. Primaere Abnahmekriterien und ihre Belege",
    "## 2. Reichweite der Stufe-2-Abnahme",
    "## 3. Fehlermatrix und deklarierte Abbruchpunkte",
    "## 4. Die vier Entscheidungen vom 2026-08-18",
    "## 5. Unwiderruflichkeit, Schluesselvernichtung und Kanarienvoegel",
];

/// Die Literale, die der Stufe-2-Gate-Bericht nennen MUSS.
///
/// Der Gate prueft Literale, keine Prosa: ein Abnahmebericht, der eine der
/// vier festgeschriebenen Hashdomains, das Urbild des Importprotokolls, den
/// vorgezogenen Datei-Weg oder die fail-closed abgelehnte Profilmigration
/// verschweigt, belegt die Stufe nicht. Die vier Zielarchitekturen stehen
/// hier NICHT: sie stehen bereits in der woertlich verlangten
/// Reichweitenklausel, und ein zweites Mal geprueft belegen sie nichts.
const STAGE_TWO_GATE_REPORT_LITERALS: [&str; 15] = [
    "previewHash",
    "archiveProfileHash",
    "inventoryHash",
    "activePointerHash",
    "allowed-archive-profile-hashes",
    "importProtocolHash",
    "import-report-v1",
    "local-audit-event-v1",
    "draftDEK",
    "SQLCipher",
    "webBundleRelease",
    "WR-052",
    "PreparedFinalizationBeatsDiscardIntent",
    "EA-ARCHIVE-PROFILE-NOT-ALLOWED",
    "docs/traceability/stage-2-fault-points.json",
];

/// Die Reichweitenklausel der Stufe 2: die Global Constraint zur
/// Host-Baubarkeit, Wort fuer Wort, in der umlaut- und auszeichnungsfreien
/// Umschrift, die diese Datei durchgehend verwendet (Muster:
/// [`WASM32_SCOPE_CLAUSE`]).
///
/// Der Gate-Bericht MUSS sie woertlich tragen. Ohne sie liest sich ein
/// gruener Stufe-2-Gate als Plattformnachweis, den er nicht erbringt.
const STAGE_TWO_HOST_SCOPE_CLAUSE: &str = concat!(
    "Stufe 2 belegt Baubarkeit ausschliesslich fuer das Host-Target: ",
    "rust-toolchain.toml:5 stellt nur wasm32-unknown-unknown bereit (gepinnt in ",
    "tools/xtask/tests/workspace.rs, rust_toolchain_declares_wasm32_and_no_release_target), "
    "und die vier Cross-Targets ",
    "x86_64-pc-windows-msvc, x86_64-unknown-linux-gnu, aarch64-apple-darwin, ",
    "x86_64-apple-darwin werden von Task 18 namentlich als offene ",
    "Stufe-7-Ledgerzeilen eingetragen statt lokal behauptet."
);

```

`gate_report_acceptance_criteria` (`main.rs:1482-1531`) gains a third parameter `expected: &[u32]` and compares against it instead of against `STAGE_ONE_PRIMARY_ACCEPTANCE_CRITERIA`; `stage_one_documents` (`main.rs:1535-1560`) passes `&STAGE_ONE_PRIMARY_ACCEPTANCE_CRITERIA`. Behaviour, error wording and the four-column row shape stay identical, so the Stage 1 tests do not move. `reject_legal_overclaim` stays applied to the format package only, exactly as today: it demands a `NICHT BEHAUPTET:`-line for each of its four terms (`main.rs:1466-1471`), which is the contract of the public format package and not of a gate report.

- [ ] **Step 4: Implement the Stage 2 gate branch**

`run_stage_two_gate(gate_root)` collects problems into one vector and returns them together, joined with `"; "`, following `parse_requirement_ledger` (`main.rs:1246`, `:1321`). It performs, in this order:

1. **Vector families.** Each family of `STAGE_TWO_VECTOR_FAMILIES` must carry a readable manifest under `vectors/<family>/…`, using the existing `family_carries_a_manifest` (`main.rs:1373`).
2. **Ledger.** `read_requirement_ledger` (`main.rs:1340-1348`) parses the ledger; a missing file is an empty ledger and produces named problems instead of an IO abort. `stage_two_rows_still_planned` is every row whose `stage` column is exactly `2` and whose `status` is `planned` — derived from the columns, never from a literal list, so a row that Stage 2 forgot cannot hide and WR-052 is picked up automatically once its stage column moves. A non-empty result is a problem that names every such `requirement_id`.
3. **Host evidence.** `host_evidence_rows` are the `requirement_id` values of every row whose `evidence` column names one of `STAGE_TWO_HOST_TARGETS`. A target that no row names is a problem that names the target.
4. **Fault points.** The manifest at `STAGE_TWO_FAULT_POINT_MANIFEST_PATH` is parsed as a JSON object of arrays; every entry contributes its `name` and must carry a non-empty `name` and a non-empty bracketed step. The arrays `discard`, `finalization` and `precedence` MUST exist and MUST be non-empty, and `DISCARD_PRECEDENCE_FAULT_POINT` MUST occur exactly once across the whole manifest — it is deliberately not a member of `DiscardFaultPoint::ALL`, because every member of that array restarts into an unchanged draft or a permanent blank draft while this point restarts into `PreparedFinalizationPending`. `declared_fault_points` is the lexicographically sorted union of all names, duplicates being a problem.
5. **Scripts.** The root `package.json` MUST declare every script of `STAGE_TWO_REQUIRED_SCRIPTS`. This is what anchors the frontend lane and the supply-chain lane in the gate: `verify_quick_commands()` (`main.rs:25-87`) is pure Rust and character-exactly pinned (`main.rs:2379-2431`), so it is not touched.
6. **Gate report.** `require_document_literals` (`main.rs:1425`) checks `STAGE_TWO_GATE_REPORT_SECTIONS` and `STAGE_TWO_GATE_REPORT_LITERALS`; the report must contain `STAGE_TWO_HOST_SCOPE_CLAUSE` verbatim; and `gate_report_acceptance_criteria` reads the `| AK <nummer> | … |` rows against `STAGE_TWO_PRIMARY_ACCEPTANCE_CRITERIA`. The measured run is deliberately **not** checked here but by a named test, exactly as in Stage 1 (`tools/xtask/tests/stage_gate.rs:940-1058`): a gate that demanded its own measured row could never be green on the run that produces it, and Stage 1 has no such bootstrap because the check lives in the test suite. That test belongs to Task 18, because it reads the real report.

The JSON report keeps the Stage 1 schema and extends it by exactly the four positions of the contract — keys are added, never renamed:

```json
{
  "stage": 2,
  "vector_families": ["local-audit", "reports"],
  "primary_acceptance_criteria": [1, 2, 3, 15, 23, 25, 28, 34, 39, 46, 48, 54],
  "evidenced_acceptance_criteria": [],
  "rows": [],
  "format_package": "docs/format/README-FORMAT.txt",
  "gate_report": "docs/traceability/stage-2-gate.md",
  "gate_report_acceptance_criteria": [],
  "declared_fault_points": [],
  "stage_two_primary_acceptance_criteria": [1, 2, 3, 15, 23, 25, 28, 34, 39, 46, 48, 54],
  "host_evidence_rows": [],
  "stage_two_rows_still_planned": []
}
```

- [ ] **Step 5: Add the Stage 2 gate scripts to the root package.json**

Add to the six existing scripts (`package.json:9-16`), next to the three frontend scripts of Task 13:

```json
    "stage-gate:2": "cargo run --locked -p xtask -- stage-gate 2",
    "supply-chain": "cargo deny check"
```

`cargo deny check` reads the checked-in policy `deny.toml:2-21` — yanked crates, wildcards, the five-entry licence allowlist, unknown registries and Git sources — which no gate has invoked so far. It needs `cargo install --locked cargo-deny` on the running machine; the gate itself never invokes it and stays runnable without it.

- [ ] **Step 6: Run the Stage 2 gate tests and the frozen Stage 1 gate**

Run:

```bash
cargo test --locked -p xtask --test stage_gate
cargo test --locked -p xtask
pnpm verify:quick
```

Expected: PASS on all three. The five phases of `stage_two_gate_names_every_missing_declaration_at_once` are green against their fixtures, the undefined-stage test names both defined stages, and every Stage 1 test — the vector families, the ledger, the fuzz surfaces, the format package, the report contract, decision D1, decision D3 and the measured Stage 1 run — is unchanged and still green. `cargo run --locked -p xtask -- stage-gate 2` against the real working tree still fails at this point, and correctly so: `docs/traceability/stage-2-gate.md` does not exist and the Stage 2 ledger rows still stand on `planned`. Both are Task 18's work.

- [ ] **Step 7: Commit the Stage 2 gate tooling**

```bash
git add tools/xtask/src/main.rs tools/xtask/tests/stage_gate.rs package.json
git commit -m "feat(xtask): open the stage gate for stage 2"
```

### Task 18: Stage 2 Fault Matrix and Acceptance Gate (SYNTHESE.md: Task 10)

**Files:**
- Create: `docs/traceability/stage-2-gate.md`
- Modify: `tests/ea-system-tests/Cargo.toml`
- Modify: `docs/traceability/v0.1-requirements.csv`
- Modify: `tools/xtask/tests/stage_gate.rs`
- Modify: `deny.toml`
- Modify: `Cargo.lock`
- Test: `tests/ea-system-tests/tests/fault_injection_writer_matrix.rs`
- Test: `tests/ea-system-tests/tests/privacy_canaries_writer.rs`
- Test: `tests/ea-system-tests/tests/e2e_writer_archive.rs`

**Interfaces:**
- Consumes: every Stage 2 service and host capability — `DiscardService` and `DiscardFaultPoint::ALL` (Task 7); `MasterDataRepository` and the exact `import-report-v1` bytes (Task 8); `LocalPathBackend`, `ControlledNetworkBackend`, `ArchiveHealthReport`, `ProfileMigrator`, `MigrationFaultPoint::ALL` and `ArchiveBackendError` (Task 9); `materialize_format_package` (Task 10); `WriterService`, `FinalizationFaultPoint::ALL`, `PreparedFinalization::exact_bytes` and `CommittedFinalization::exact_bytes` (Task 11); `write_archive_bundle` and `ArchiveBundleSource` (Task 12); `ea_testkit::contains_canary` (Task 6); `ea-key-provider` with the non-default feature `test-support` (Task 2); the gate `xtask stage-gate 2` with its four report fields and the report contract (Task 17).
- Produces: the Stage 2 fault matrix, the Writer privacy canaries, the end-to-end archive proof, the gate report `docs/traceability/stage-2-gate.md`, the Stage 2 end state of `docs/traceability/v0.1-requirements.csv` including the four open Stage 7 host rows and the Go-live row, and the cumulative gate test in `tools/xtask/tests/stage_gate.rs`.

This is the only task that writes `docs/traceability/v0.1-requirements.csv`. Two tasks writing the same sorted CSV — with an enforced sort (`tools/xtask/src/main.rs:1324-1330`), an enforced non-empty `evidence` column (`main.rs:1082`, `:1283-1290`) and an enforced trailing line feed (`main.rs:1315-1317`) — produces merge conflicts and a red ledger gate, so every earlier task names its ledger row in its own text and this task enters all of them.

`tools/xtask/tests/stage_gate.rs` is modified, never rewritten: the cumulative test is **appended**, and no existing test function is changed or removed — the file carries the closed Stage 1 gate including decision D3 (`tools/xtask/tests/stage_gate.rs:604`) and the measured Stage 1 run (`:1010-1058`). The one existing datum that does move is the WR-052 row of `WEB_READER_MUST_ROWS` (`tools/xtask/tests/stage_gate.rs:477-485`), because decision D-HE2 of 2026-08-18 supersedes D3's stage assignment for that single row; the constant keeps a per-row literal expectation and is widened by an expected-status column instead of being loosened, so the sharpness of the other six rows is untouched. The closed Stage 1 gate report (`docs/traceability/stage-1-gate.md:97`) is **not** edited — it records the state at the Stage 1 gate; the move is recorded in the Stage 2 report written here.

- [ ] **Step 0: Create the lockfile once for the new test dependencies**

`tests/ea-system-tests/Cargo.toml` gains `ea-writer`, `ea-draft`, `ea-archive-fs`, `ea-local-store` and `ea-audit` under `[dev-dependencies]`, each with `workspace = true`, which `tools/xtask/tests/workspace.rs:86-101` enforces. `ea-operator` and `ea-key-provider = { workspace = true, features = ["test-support"] }` have stood there since Task 3 and are not entered again. Adding dependencies rewrites `Cargo.lock`.

Run: `cargo metadata --format-version 1 > /dev/null` (without `--locked`)

Expected: PASS, without `--locked`, exactly once in this task; `Cargo.lock` now contains the new edges and every following command of this task carries `--locked`.

- [ ] **Step 1: Write the fault matrix, privacy canary, end-to-end, and cumulative gate tests**

Every test of this task serializes itself: a process-wide lock plus its own temp root per test, following `tools/xtask/tests/stage_gate.rs:29-44`. No command of this task carries `-- --test-threads=1`, because `cargo test --workspace --all-targets --locked` runs the same binaries in parallel immediately afterwards inside `pnpm verify:quick` (`tools/xtask/src/main.rs:40-43`, character-exactly pinned at `:2400-2402`); a matrix that needs serialization from the outside is already broken.

`tests/ea-system-tests/tests/fault_injection_writer_matrix.rs` drives every declared abort point of Stage 2 and asserts exactly one of two outcomes per point — an unchanged readable draft before the irreversible boundary, or a byte-identical completion after it:

```rust
#[test]
fn every_declared_stage_two_fault_point_has_exactly_one_survivable_outcome() {
    for point in FinalizationFaultPoint::ALL.iter().copied() {
        let mut h = WriterMatrixHarness::with_incident();
        let prepared = h.capture_prepared_bytes();
        let _ = h.finalize_with_fault(point);
        let resumed = h.restart_from_disk();
        match resumed {
            MatrixOutcome::DraftUnchanged(draft) => {
                assert_eq!(draft.notes(), "CANARY-DRAFT");
                assert!(h.archive_has_no_entry());
            }
            MatrixOutcome::Committed(committed) => {
                assert_eq!(committed.exact_bytes(), prepared.exact_bytes());
                assert!(h.draft_key_is_gone());
            }
        }
    }
}

#[test]
fn every_declared_discard_fault_point_restarts_into_one_of_two_states() {
    for point in DiscardFaultPoint::ALL.iter().copied() {
        let mut h = WriterMatrixHarness::with_incident();
        let _ = h.discard_with_fault(point);
        let state = h.restart_from_disk_into_restart_state();
        assert!(
            state == RestartState::OriginalDraftUnchanged || state == RestartState::NewBlankDraft,
            "{point:?} restarted into {state:?}"
        );
    }
}

#[test]
fn a_media_failure_at_any_durable_step_never_produces_a_half_written_archive() {
    for point in FinalizationFaultPoint::ALL.iter().copied() {
        let mut h = WriterMatrixHarness::with_incident();
        h.fail_the_medium_at(point, MediumFailure::NoSpaceLeft);
        let _ = h.finalize();
        let report = h.reopen_and_check_health();
        assert!(report.findings().is_empty(), "{point:?} left {report:?}");
        h.fail_the_medium_at(point, MediumFailure::ReadOnlyMount);
        let _ = h.finalize();
        assert!(h.reopen_and_check_health().findings().is_empty());
    }
}

#[test]
fn an_interrupted_profile_migration_leaves_exactly_one_active_pointer() {
    for point in ea_archive_fs::MigrationFaultPoint::ALL.iter().copied() {
        let mut h = WriterMatrixHarness::with_finalized_archive();
        let _ = h.migrate_profile_with_fault(point);
        let reopened = h.restart_from_disk();
        assert_eq!(reopened.active_profile_count(), 1);
        assert!(reopened.every_archive_object_is_readable());
    }
}

#[test]
fn a_prepared_finalization_survives_a_crash_and_beats_a_pending_discard() {
    let mut h = WriterMatrixHarness::with_incident();
    let prepared = h.capture_prepared_bytes();
    h.begin_discard_after_preparing();
    h.hard_stop();
    let state = h.restart_from_disk_into_restart_state();
    assert_eq!(state, RestartState::PreparedFinalizationPending);
    let committed = h.recover_pending().expect("die Wiederaufnahme muss gelingen");
    assert_eq!(committed.exact_bytes(), prepared.exact_bytes());
}
```

`tests/ea-system-tests/tests/privacy_canaries_writer.rs` seeds a canary into every fachliche field of the incident body — keyword, location, personnel, vehicles, external organizations, patient count, human incident number, free text and both empty reasons — finalizes, and then searches for each canary in the raw database bytes including WAL and journal, in every log line, in every file and directory name, in the staging descriptors, in the UI trace and in the crash output. The search uses `ea_testkit::contains_canary`; a plain `contains_subslice` does not exist on `&[u8]`.

```rust
#[test]
fn no_fachliche_canary_survives_finalization_anywhere_on_disk() {
    let harness = CanaryHarness::with_one_canary_per_field();
    harness.finalize().expect("die Finalisierung muss gelingen");
    for canary in harness.canaries() {
        for (place, bytes) in harness.every_observable_byte_stream() {
            assert!(
                !ea_testkit::contains_canary(&bytes, canary),
                "{canary:?} steht in {place}"
            );
        }
    }
}

#[test]
fn a_restored_backup_never_returns_a_finalized_or_discarded_key() {
    let harness = CanaryHarness::with_one_canary_per_field();
    let before = harness.capture_backup();
    harness.finalize().expect("die Finalisierung muss gelingen");
    let after = harness.capture_backup();
    for backup in [before, after] {
        let restored = harness.restore(backup);
        assert!(restored.draft_key().is_none());
        assert!(restored.open_finalized_content().is_err());
    }
}
```

`tests/ea-system-tests/tests/e2e_writer_archive.rs` runs one incident from the empty mask to a verified archive without any network: capture, review, finalize, then `ea_verify::verify_archive` over the resulting directory and over the single-file bundle of Task 12, asserting the same report hash for both and a blank mask afterwards.

The cumulative gate test is appended to `tools/xtask/tests/stage_gate.rs`. It is the only Stage 2 gate test that reads the REAL working tree and holds a ZIELzustand; it cannot invert through a later task:

```rust
#[test]
fn stage_two_gate_declares_every_irreversible_boundary() {
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["stage-gate", "2"])
        .env_remove("EA_STAGE_GATE_ROOT")
        .output()
        .expect("xtask stage-gate must start");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let declared = report["declared_fault_points"].as_array().unwrap();
    for point in FINALIZATION_FAULT_POINT_NAMES
        .iter()
        .chain(DISCARD_FAULT_POINT_NAMES)
    {
        assert!(
            declared.iter().any(|value| value == point),
            "der Stufe-2-Gate deklariert {point} nicht"
        );
    }
    assert_eq!(
        report["stage_two_primary_acceptance_criteria"],
        serde_json::json!([1, 2, 3, 15, 23, 25, 28, 34, 39, 46, 48, 54])
    );
    assert!(!report["host_evidence_rows"].as_array().unwrap().is_empty());
    let planned = report["stage_two_rows_still_planned"].as_array().unwrap();
    assert!(
        planned.is_empty(),
        "Stufe-2-Ledgerzeilen stehen noch auf planned: {planned:?}"
    );
}
```

`FINALIZATION_FAULT_POINT_NAMES` and `DISCARD_FAULT_POINT_NAMES` are `&[&str]` constants **in this test file**, textually equal to the Rust variants in `crates/ea-writer/src/fault.rs` and `crates/ea-draft/src/fault.rs`. Written as literals, they keep `tools/xtask/Cargo.toml:10-17` free of any Stage 2 dependency and they compare the declaration against an independent list instead of against itself — an enum compared with itself would let a single-variant enum satisfy both promises and report green. The canary assertion is deliberately **not** part of this test: whether a canary was found is a statement about a run, and it is carried by `privacy_canaries_writer.rs`.

A second appended test holds the measured run, mirroring `stage_one_gate_report_records_the_measured_full_gate_run` (`tools/xtask/tests/stage_gate.rs:1010-1058`) and reusing the existing row reader `measured_run_rows` (`:967-995`):

```rust
/// Die zehn Kommandos der Schritt-6-Folge dieses Plans, in genau der
/// Reihenfolge, in der der Plan sie vorschreibt.
///
/// Das erste Kommando steht mit seinem Praefix, nicht mit seiner vollen
/// Paketliste: die Belegzeile MUSS es nennen, soll die zehn `-p`-Namen aber
/// nicht ein zweites Mal woertlich abschreiben.
const STAGE_TWO_STEP_SIX_COMMANDS: [&str; 10] = [
    "cargo test --locked -p ea-writer",
    "cargo test --locked -p ea-system-tests --test fault_injection_writer_matrix",
    "cargo test --locked -p ea-system-tests --test privacy_canaries_writer",
    "cargo test --locked -p ea-system-tests --test e2e_writer_archive",
    "pnpm desktop:typecheck",
    "pnpm desktop:test",
    "pnpm desktop:e2e",
    "pnpm supply-chain",
    "pnpm stage-gate:2",
    "pnpm verify:quick",
];

#[test]
fn stage_two_gate_report_records_the_measured_full_gate_run() {
    let report = fs::read_to_string(workspace_root().join("docs/traceability/stage-2-gate.md"))
        .expect("the stage 2 gate report must be readable");
    let rows = measured_run_rows(&report);
    for command in STAGE_TWO_STEP_SIX_COMMANDS {
        let matching: Vec<&Vec<String>> =
            rows.iter().filter(|row| row[0].contains(command)).collect();
        assert_eq!(
            matching.len(),
            1,
            "stage-2-gate.md must record the measured run for `{command}` exactly once"
        );
        let row = matching[0];
        assert!(row.len() >= 3, "{row:?}");
        assert_eq!(row[1], "0", "`{command}` must have ended with exit code 0: {row:?}");
        assert!(!row[2].is_empty(), "{row:?}");
        assert!(
            !row[2].contains("0 passed"),
            "`0 passed; N filtered out` is a broken filter, not a result: {row:?}"
        );
    }
    assert_eq!(rows.len(), STAGE_TWO_STEP_SIX_COMMANDS.len() + 1);
}
```

This test lives here and not inside the gate for the reason Stage 1 already settled: the recorded run contains `pnpm stage-gate:2` and `pnpm verify:quick` themselves, so a gate that demanded its own measured row could never be green on the run that writes it. As a test it is simply red until the section is complete and green from the confirming pass on.

- [ ] **Step 2: Run the new tests and confirm that missing evidence fails**

Run:

```bash
cargo test --locked -p ea-system-tests --test fault_injection_writer_matrix ; cargo test --locked -p ea-system-tests --test privacy_canaries_writer ; cargo test --locked -p ea-system-tests --test e2e_writer_archive ; cargo test --locked -p xtask --test stage_gate stage_two_gate_declares
```

Expected: FAIL on all four. The three system tests fail because no harness, no medium-failure injection and no backup capture exist yet. `stage_two_gate_declares_every_irreversible_boundary` fails listing uncovered declared fault points, missing Stage-2 AK rows, and missing Stage-7 host-evidence rows — one message naming all of them, because the Stage 2 branch collects its problems (Task 17, Step 4) instead of aborting at the first. The commands are separated by `;` and not by `&&`, so each of the four failures is actually observed.

- [ ] **Step 3: Build the exhaustive fault and privacy evidence**

Inject before and after every durable step: every file flush, every directory flush, every create-if-absent, every rename, the `discardIntent` commit, the `draftDEK` delete, every SQLite transaction, every staging transition, the publication-queue handover of Spec step 12, and the active profile pointer swap. Hard-stop and reopen from disk for each point and verify exactly one outcome — an unchanged readable draft before the irreversible boundary, or a byte-identical completion after it. Add the two medium failures `NoSpaceLeft` and `ReadOnlyMount` at each of the same points and assert that the reopened archive produces an empty `ArchiveHealthReport`, never a half-written object: an archive object exists with all of its bytes or not at all. Drive the profile migration from Task 9 through its own abort points and assert a single active pointer plus a fully readable archive after each. Restore both a pre-finalization and a post-finalization backup and prove that no finalized and no discarded key returns — the `draftDEK` lives in a device-bound keystore entry that ordinary application and system backup excludes, so a restored database file finds no key.

For the canaries, seed one distinct marker per fachliches field and search the raw SQLite bytes including WAL, journal and temp spill, every log line, every file and directory name, the staging descriptors, the UI trace and the crash output. Production crash dumps are off and telemetry and crash upload are off by default; the test asserts that the crash output it can produce carries no marker.

- [ ] **Step 4: Write the Stage 2 gate report**

`docs/traceability/stage-2-gate.md` follows the shape of `docs/traceability/stage-1-gate.md` and satisfies the contract that Task 17 checks. Its preamble names the gate that reads it and its machine counterparts, as `stage-1-gate.md:3-13` does. It carries the five mandatory sections, the fifteen mandatory literals and the host scope clause verbatim.

Section 1 maps the twelve primary acceptance criteria of Stage 2, one row each, in the four-column shape of `docs/traceability/stage-1-gate.md:22-33`: `| AK <nummer> | <Gegenstand> | <Beleg> | <Offen in spaeterer Stufe> |`. Neither the evidence column nor the open column may be empty — an empty evidence column is exactly the hollow promise this report excludes, and an empty open column would silently claim the whole criterion. Example rows, in the register of `stage-1-gate.md:24-33`: AK 39 cites `tests/ea-system-tests/tests/fault_injection_writer_matrix.rs::every_declared_stage_two_fault_point_has_exactly_one_survivable_outcome` and leaves the signed OS matrix open for Stage 7; AK 2 cites the canary test and leaves the Reader-side proof open for Stage 4; AK 48 cites the offline end-to-end test and leaves the controlled-network path open for Stage 3.

The four criteria to which Stage 2 contributes only a **part** — AK 19, AK 24, AK 29 and AK 53 — are listed **below** that table in rows beginning `| Teilbeleg AK 19 |`, never with the prefix `| AK `: the row parser scans the whole document for `| AK ` and requires the found numbers to be exactly the twelve primary criteria, so a partial row in that shape would be reported as unexpected and turn the gate red.

Section 2 carries `STAGE_TWO_HOST_SCOPE_CLAUSE` verbatim — copied from the constant in `tools/xtask/src/main.rs`, never retyped from the Global Constraint, whose markup and umlauts would fail the byte comparison — and names the four architectures that Stage 2 does not claim, together with the ledger rows that hold them open. It also records one consequence of the shared report schema, so nobody later reads it as drift: `evidenced_acceptance_criteria` is computed stage-independently over all ledger rows (`tools/xtask/src/main.rs:1642-1649`), so `stage-gate 1` now also lists the Stage 2 criteria, while the measured line of `docs/traceability/stage-1-gate.md:164` remains the record of its own measurement and is not rewritten.

Section 3 lists the declared abort points from `docs/traceability/stage-2-fault-points.json` by name, groups them by the durable step they bracket, names the two medium failures and the profile-migration points, and states which single outcome each point is allowed to produce. `PreparedFinalizationBeatsDiscardIntent` appears here by that exact name.

Section 4 records the four decisions of 2026-08-18 with their consequences for later stages: D-B01 with `importProtocolHash` over the exact `import-report-v1` bytes; D-B02 with `previewHash`, `archiveProfileHash`, `inventoryHash`, `activePointerHash` and the fail-closed check against `allowed-archive-profile-hashes`, which binds Stage 7; D-HE1 with SQLCipher and its ADR 0002; and D-HE2 with `webBundleRelease`, which moves WR-052 from Stage 4 to Stage 2 without minting a seventh object prefix.

Section 5 records the irreversibility chain, the `draftDEK` deletion, the backup-restore blockade and the canary result over every observable byte stream.

The section `## Gemessener Gate-Lauf` carries a preamble in the register of `docs/traceability/stage-1-gate.md:147-155` — naming the date, the exact toolchain, `env -u RUSTUP_TOOLCHAIN` where the shell overrides the pin, and `cargo install --locked cargo-deny` as the prerequisite of `pnpm supply-chain` — followed by one row per command of the sequence in Step 6, each with exit code `0`, a read-off result and a runtime. Step 4 writes the preamble and the empty table; the ten rows are filled in from the measuring pass of Step 6. The numbers are read off, never estimated; `0 passed; N filtered out` is a broken filter and not a result. Should `cargo deny check` report a licence outside the five-entry allowlist `deny.toml:8-15`, the allowlist is never silently widened: the crate, its licence and the decision are recorded in this section, and only then does `deny.toml` receive the entry — **in this task**, which is why `deny.toml` stands in this Files block and in the `git add` of Step 7. Task 5's allowlist review covers only the database tranche it pins; `pnpm supply-chain` here is the first `cargo deny check` over the whole tree, including the Tauri subtree of Task 13, so a licence surfacing now could not have been seen at Task 5.

- [ ] **Step 5: Bring the requirement ledger to its Stage 2 end state**

In `docs/traceability/v0.1-requirements.csv`, set these 22 FR rows from `planned` to `implemented` or `integrated`: FR-003, FR-020, FR-021, FR-022, FR-023, FR-024, FR-030, FR-031, FR-032, FR-036, FR-037, FR-043, FR-044, FR-045, FR-046, FR-047, FR-049, FR-050, FR-060, FR-061, FR-062, FR-080 — and the 12 AK rows AK-01, AK-02, AK-03, AK-15, AK-23, AK-25, AK-28, AK-34, AK-39, AK-46, AK-48, AK-54. Move the WR-052 row (`docs/traceability/v0.1-requirements.csv:131`) from stage `4` to stage `2` and from `planned` to `integrated`, keeping `requirement_id`, `version` `v1.1`, `source` and `title`, with the two tests `bundle_is_byte_preserving_under_the_same_relative_paths` and `bundle_verifies_to_the_same_report_as_the_directory` plus the Task 12 reference as evidence. Every changed row carries a non-empty `evidence` column that names the test or the artefact, never a task number alone (`tools/xtask/src/main.rs:1082`, `:1283-1290`); the sort by `requirement_id` (`:1324-1330`) and the trailing line feed (`:1315-1317`) stay intact. The vocabulary is limited to `implemented`, `integrated` and `planned` (`main.rs:1085`), so a value such as `release-verified` is already technically impossible and needs no prohibition. After this step, no row with stage column `2` stands on `planned` — that is precisely what the gate assertion `stage_two_rows_still_planned.is_empty()` measures.

Add, without touching a single existing row, these additional rows:

- Four `v1.1` rows with `requirement_id` `AK-23`, stage `7`, status `planned`, one per architecture — `x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-apple-darwin` — whose evidence names the architecture and states that native execution and the signed release proof belong to Stage 7. These are the rows that `host_evidence_rows` reports and that replace the four cross-target compile checks Stage 2 does not run.
- One `v1.1` row with `requirement_id` `GATE-21`, stage `7`, status `planned`, for the mandatory Go-live evidence of an `Unknown` posture result: an unresolved posture check is shown as unresolved and is never an automatic pass.
- Four `v1.1` rows for the partial contributions of Stage 2 to AK-19, AK-24, AK-29 and AK-53, each with `requirement_id` equal to the existing one, stage `2`, status `implemented`, and the Stage 2 evidence — the canary test for AK-19, the stale-registry acknowledgement for AK-24, the command-allowlist anchor test for AK-29, the operator binding for AK-53. The `v1` rows of these four keep their later stage and their `planned` status unchanged: later stages only add rows (`main.rs:1067`), and the sort check tolerates equal consecutive `requirement_id` values (`:1324-1330`).

In `tools/xtask/tests/stage_gate.rs`, `WEB_READER_MUST_ROWS` (`:477-485`) gains an expected-status column and its WR-052 entry becomes stage `2` with status `integrated`; the other six entries keep stage and `planned`. The comment above the constant records that decision D-HE2 of 2026-08-18 supersedes the stage assignment D3 gave that one row, so the change reads as what it is and not as an erosion of D3.

- [ ] **Step 6: Run the complete Stage 2 gate**

Run:

```bash
cargo test --locked -p ea-writer -p ea-draft -p ea-archive -p ea-archive-fs -p ea-key-provider -p ea-operator -p ea-local-store -p ea-audit -p ea-ui-contracts -p ea-desktop
cargo test --locked -p ea-system-tests --test fault_injection_writer_matrix
cargo test --locked -p ea-system-tests --test privacy_canaries_writer
cargo test --locked -p ea-system-tests --test e2e_writer_archive
pnpm desktop:typecheck
pnpm desktop:test
pnpm desktop:e2e
pnpm supply-chain
pnpm stage-gate:2
pnpm verify:quick
```

Expected: PASS locally on all ten in the confirming pass. `-p ea-system-tests` is deliberately absent from the first command: the three system test runs follow by name, each with its own evidence row, and running the same package twice lengthens the gate without adding a statement. No command carries `-- --test-threads=1`: the Stage 2 tests serialize themselves, and `pnpm verify:quick` runs the same binaries in parallel two lines later. `pnpm stage-gate:2` prints the JSON report on stdout with `stage_two_rows_still_planned` empty, `host_evidence_rows` non-empty and every declared abort point listed; the report distinguishes completed implementation and integration from the still-open signed OS matrix, which stays a Stage 7 obligation. The sequence is run **twice**, as Stage 1 was: the measuring pass produces the ten rows of `## Gemessener Gate-Lauf` — exit code, read-off numbers, runtime — and its last two commands are red on that pass only, because the section they read is still empty; the confirming pass, with the section written, is green on all ten, and any number that moved between the passes is corrected to the confirming pass before the commit. Nothing is estimated and nothing is carried over unread.

- [ ] **Step 7: Commit the Stage 2 gate**

```bash
git add tests/ea-system-tests docs/traceability/stage-2-gate.md docs/traceability/v0.1-requirements.csv tools/xtask/tests/stage_gate.rs deny.toml Cargo.lock
git commit -m "test(writer): close offline Writer stage"
```
