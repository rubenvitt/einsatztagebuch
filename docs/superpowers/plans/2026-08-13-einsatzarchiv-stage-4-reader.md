# Einsatzarchiv Stage 4 Reader Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the Reader as a browser application that enrolls against two independent authenticators, replicates exact archive objects incrementally or opens them straight from a file, verifies every object completely before any local decryption, keeps an encrypted local index in OPFS, and presents content and technical integrity without ever conflating missing access with corruption.

**Architecture:** The Reader is a browser PWA served from an origin the sync server does not own; its service worker activates only a bundle whose hash resolves against a pinned, Root-signed `webBundleRelease`. Every security decision runs in shared Rust compiled to `wasm32-unknown-unknown` behind one `wasm-bindgen` bridge — trust chain, the nine verification gates, HPKE, AEAD, the inverted index and the local audit — while TypeScript receives generated view and status DTOs and nothing else. Keys live in a browser vault: one random 32-byte vault key under ChaCha20-Poly1305 over the X25519 KEM key, the Ed25519 device/audit key, the pinned Root anchor and the last verified Registry state, wrapped once per authenticator as `KEK_i = HKDF(PRF_i(fixed app salt), info = "ea-reader-vault-v1")`. Two operating modes share one archive-source port and one verification pipeline: the server mode advances a cursor only after every object byte is durable in OPFS and the chain verifies through batch end, the file mode carries no cursor at all and re-checks every object on every open. Only `VerifiedEncryptedEntry` together with `VerifiedGrantForRecipient` reaches the HPKE decapsulator; decrypted records enter an inverted index that is ChaCha20-Poly1305-encrypted as a whole in OPFS, while technical entries without a grant stay visible outside the fachliche index.

**Tech Stack:** Shared Rust trust/format/schema/sync/verify crates compiled to `wasm32-unknown-unknown`, `wasm-bindgen` `=0.2.126` with the CLI pinned to the identical version, `js-sys` and an enumerated `web-sys` feature list, `getrandom 0.4.3` with the Cargo feature `wasm_js` over `globalThis.crypto.getRandomValues`, WebAuthn with the `prf` extension, OPFS with synchronous access handles inside a dedicated Worker, a new inverted index crate with ChaCha20-Poly1305 blob sealing, React 19, TypeScript, Vite, Ant Design 6 with statically extracted local hashed CSS and `zeroRuntime: true`, Vitest/React Testing Library, Playwright with the projects `chromium`, `firefox` and `webkit`, `wasm-bindgen-test` in headless Chromium. `apps/desktop` stays — it carries Writer and Administration with Tauri 2 and SQLCipher unchanged — but SQLCipher, Tauri 2 and the native Reader key provider are gone from the READER path: `web-reader-design.md` §8.1 replaces the Reader index, §11.3 removes the native Reader key provider without replacement, and §11.2 removes the OS-lock session end.

**Task numbering:** This plan carries fourteen tasks. Former numbers map to new ones as 1→4, 2→7, 3→8, 4→10, 5→11, 6→12, 7→13, 8→14; tasks 1, 2, 3, 5, 6 and 9 are new. Every cross-reference in this plan cites a task by its title, never by its number.

## Global Constraints

- Die Schlüsselwörter **MUSS**, **DARF NICHT**, **SOLL**, **SOLL NICHT** und **DARF** sind normativ zu verstehen. Ein Release darf von einer MUSS-Anforderung nicht abweichen. Eine Abweichung von SOLL erfordert eine dokumentierte Sicherheits- oder Betriebsbegründung.
- **Umschreibungsauftrag Web-Reader**, `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §12, wörtlich: „Stufe 4: Tasks 1, 2, 4 und 7 werden neu geschrieben. Task 3 behält seinen Rust-Kern und erhält neue Bindungen sowie den gepinnten Anchor im Datei-Modus. Task 5 bleibt unverändert. Task 6 wird angepasst. Task 8 wird um Browser-Matrix und Datei-Modus erweitert." Dazu: „Repositoriumsstruktur: `apps/web/` kommt hinzu. `apps/desktop/` umfasst Writer und Administration. Neu sind eine `wasm-bindgen`-Brücke und ein Index-Crate; `ea-reader` wird `wasm32`-fähig." Diese Überarbeitung führt den Auftrag aus. Was die Vorfassung an SQLCipher, Tauri 2 und nativem Reader-Key-Provider festschrieb, ist durch §8.1, §11.2 und §11.3 widerlegt und in dieser Fassung ersetzt; `apps/desktop` bleibt für Writer und Administration bestehen und wird NICHT entfernt.

<!-- web-reader-stage-4-block -->
**BLOCKIERT — Laufzeitnachweis nach `web-reader-design.md` §14.1.** *(Historisch: dieser Satz stand als Sperre über der Überarbeitung dieses Plans. Er bleibt zeichengleich als AUFZEICHNUNG stehen — das Repositorium fälscht keine Ausführungsaufzeichnungen, dieselbe Konvention, die `docs/superpowers/plans/2026-08-16-einsatzarchiv-web-reader-stage-1-prerequisites.md` mit seiner `Historisch:`-Fußnote führt. Er ist seit dem 2026-08-30 nicht mehr wirksam.)* Die Sperre verlangte, dass die Überarbeitung dieses Plans erst beginnen darf, wenn ein ausführbarer Spike vorliegt: `wasm-bindgen`-Schicht, `getrandom` mit `wasm_js` in einer echten JS-Umgebung, eine HPKE-Entkapselung und eine Signaturprüfung gegen einen bestehenden Testvektor.

**AUFGEHOBEN am 2026-08-30 — Laufzeitnachweis nach `web-reader-design.md` §14.1 erbracht.** Der Nachweis liegt unter `spikes/wasm-runtime-proof/` und läuft über `spikes/wasm-runtime-proof/spike.sh` mit Exit 0, wiederholt aus gelöschtem `target/` und `pkg/`. Alle vier von §14.1 verlangten Elemente werden AUSGEFÜHRT und nicht nur übersetzt:

1. **wasm-bindgen-Schicht.** Zeichenkettenargumente überqueren die Grenze in BEIDE Richtungen; jede Ausfuhr steht unter `cfg(target_arch = "wasm32")`.
2. **`getrandom 0.4.3` mit dem Merkmal `wasm_js` in Node v26.8.1.** Die Entropie kommt über die erzeugte Glue-Schicht aus `globalThis.crypto.getRandomValues`; zwei Ziehungen unterscheiden sich, eine Ziehung über 100 000 Byte überquert den 65 536-Byte-Chunker von `getrandom`, und zwei echte `ea_crypto`-`hpke_seal`-Aufrufe zogen verschiedene ephemere Schlüssel.
3. **HPKE-Entkapselung** von `vectors/crypto/suite-1/hpke/base-mode-wrapped-cek.bin` mit `ea_crypto::hpke_open`, die den eingefrorenen CEK `0xc0`×32 zurückgewinnt.
4. **Ed25519-Prüfung** von `vectors/crypto/suite-1/ed25519/rfc8032-test1.bin` über `CanonicalPublicCoseKey::verify_ed25519_strict`, MIT Negativfall: `flipped-signature.bin` wird als `EA-TRUST-SIGNATURE-INVALID` abgewiesen, beide verfälschten HPKE-Vektoren als `EA-CRYPTO-HPKE-OPEN`.

Adversarial gegengeprüft: fünf Erwartungen wurden einzeln mutiert, und jede Mutation färbte den Spike rot. Die entscheidende setzte einen falschen Empfängerseed UND flickte die Thumbprint-Konstante passend nach, umging also die billige Vorprüfung — der CEK wird von echtem X25519 + HKDF-SHA-256 + ChaCha20-Poly1305 zurückgewonnen und ist keine einkompilierte Konstante. Eine Gegenkontrolle (`js/negative-control-no-webcrypto.mjs`, `globalThis.crypto` gelöscht) läuft im Ausgangspfad von `spike.sh` und meldet „Web Crypto API is unavailable". GEMESSENE Werkzeugstände: rustc 1.95.0, cargo 1.95.0, node v26.8.1, `wasm-bindgen` Crate UND CLI 0.2.126 (zeichengleich zum `Cargo.lock` des Repositoriums), `getrandom 0.4.3` mit `wasm_js`. KEINE `RUSTFLAGS`: das Flag `--cfg getrandom_backend` gehört zu `getrandom 0.3`, ist für 0.4.x FALSCH und würde das Merkmal überstimmen; `spike.sh` baut mit `env -u RUSTFLAGS`. Das bestätigt `web-reader-design.md` §10. EINE Abweichung wird hier ausgewiesen statt geglättet, weil dieser Plan gemessene Werkzeugstände als vertraglich behandelt: der Nachweis lief auf **node v26.8.1**, während `.node-version` und die `engines`-Zeile von `package.json` Node auf **26.7.0** pinnen. Die Aufgabe „Stufe-4-Vorlauf: ADR 0005, wasm-Werkzeugpins und die aufgehobene Blockade" wiederholt `spike.sh` unter dem GEPINNTEN Stand und trägt das dort gemessene Ergebnis nach; bis dahin ist der Nachweis auf einer NEUEREN Node-Fassung erbracht und nicht auf der gepinnten.

Die fünf benannten GRENZEN des Nachweises sind normativ und werden von keiner Aufgabe dieses Plans beschönigt oder als erbracht behauptet:

1. **Node v26.8.1 ist eine echte JS-Umgebung, aber kein Browser.** Ein Headless-Browser-Lauf hat im Spike nicht stattgefunden; die einzige berührte Wirtsschnittstelle ist `globalThis.crypto.getRandomValues`, die im Browser dieselbe ist.
2. **nur `debug`, kein `--release` und kein `wasm-opt`.** Größe und Verhalten unter Release-Profil und Optimierer sind ungemessen.
3. **nur `ea-crypto` wird AUSGEFÜHRT.** `ea-verify`, `ea-archive`, `ea-chain`, `ea-format` und `ea-trust` ÜBERSETZEN für wasm32 und laufen dort nicht.
4. **keine COSE-Kette.** Geprüft ist `verify_ed25519_strict` auf einem rohen RFC-8032-Vektor, nicht `parse_cose_sign1` gegen ein echtes Archiv.
5. **keine RNG-Statistik, nur Anwesenheitsproben.** „Zwei Ziehungen unterscheiden sich" ist eine Lebendigkeitsprobe und kein statistischer Test.

Dazu die sechste Tatsache, die keine Grenze des Nachweises ist, sondern seine Lage: der Spike liegt AUSSERHALB jedes Gates dieses Repositoriums — nicht unter `crates/`, nicht in `cargo deny`, nicht in `tools/xtask/tests/workspace.rs`. Die Aufgabe „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate" holt ihn in zwei gegatterte Zeugen herein und löst dabei GENAU EINE der fünf Grenzen ein, die Grenze 1: den Headless-Browser-Lauf. Grenze 4 — die COSE-Kette — löst die Aufgabe „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert" ein, weil `parse_cose_sign1` erst dort gegen ein echtes Archiv läuft. Bis dahin ist der Spike Beleg und nicht Schranke.

*Historisch, nicht mehr anwendbar:* Die Rücknahmeliste für den Fall des gescheiterten Spikes, erzeugt von `docs/superpowers/plans/2026-08-16-einsatzarchiv-web-reader-stage-1-prerequisites.md`, bleibt als Aufzeichnung dessen stehen, was zurückzunehmen gewesen wäre. Sie ist mit der Aufhebung gegenstandslos und DARF NICHT ausgeführt werden: (1) `targets = ["wasm32-unknown-unknown"]` in `rust-toolchain.toml`; (2) das Feature `wasm_js` in `Cargo.toml` samt dem 2-Zeilen-Delta in `Cargo.lock` und der `getrandom`-Zeile in `docs/adr/0001-toolchain-and-cryptography-dependencies.md`; (3) der vierte Eintrag in `verify_quick_commands()` samt Pin-Test, `ensure_wasm32_target_available()`, dem normativen Codeblock und der Gate-Kommandoliste im Stage-1-Plan; (4) die Merker-Zeilen in den Stage-Plänen 2 bis 7; (5) die Normativkorrekturen an `design.md` (§5.1, §5.2, §5.3, §7, §14.2, §17.4, §18.3, Support-Matrix) und an den Global Constraints des Stage-1-Plans; (6) die Ledgerzeilen `WR-041`, `WR-042` und `WR-043` in `docs/traceability/v0.1-requirements.csv` samt ihrem laufenden Pin in `tools/xtask/tests/stage_gate.rs` (Konstante `WEB_READER_MUST_ROWS`).

Die Aufgabe „Stufe-4-Vorlauf: ADR 0005, wasm-Werkzeugpins und die aufgehobene Blockade" erweitert `later_stage_plans_reference_the_web_reader_spec` in `tools/xtask/tests/spec_completeness.rs` so, dass der Test zusätzlich zum Blockadesatz den Auflösungsmarker, den Spikepfad und jede der fünf benannten Grenzen verlangt. Ab dann erzwingt das Gate den BELEG statt der Sperre.
<!-- /web-reader-stage-4-block -->

- **ENTSCHIEDEN — `ea-reader` steht auf der wasm32-Positivliste und NICHT in `WASM32_EXEMPT_CRATES`.** Der Satz „Diese Positivliste ist zeichengleich an die Kommandozeile des abgeschlossenen Stufe-1-Plans gebunden … und wird nicht erweitert" steht AUSSCHLIESSLICH als Codekommentar über dem wasm32-Block in `tools/xtask/src/main.rs`; kein Test erzwingt ihn. Erzwungen sind zwei andere Zusicherungen, und beide bleiben wahr — aber sie binden VERSCHIEDEN streng, und die Unterscheidung ist tragend. `verify_quick_block_in_stage_one_plan_matches_the_gate` in `tools/xtask/tests/spec_completeness.rs` assertiert nur PRÄFIXE — `"check", "--target", "wasm32-unknown-unknown", "--locked"` und `cargo check --target wasm32-unknown-unknown --locked -p ea-types` —, die das Anhängen weiterer `-p`-Paare am Ende unberührt lassen. `every_crates_member_is_classified_for_the_wasm32_gate` in `tools/xtask/tests/workspace.rs` verlangt dagegen für jedes Mitglied unter `crates/` GENAU EINE Zuordnung, weist eine Zuordnung ab, die kein Mitglied benennt — Mitgliedseintrag und Klassifikation MÜSSEN deshalb in derselben Aufgabe fallen —, und schliesst mit `assert_eq!(planned, positive_list)` gegen die `-p`-Tokens der Gate-Kommandozeile des abgeschlossenen Stufe-1-Plans (Block `G2`). Das ist eine MENGENGLEICHHEIT und kein Präfix: wer die Positivliste erweitert, MUSS dieselbe Zeile im Stufe-1-Plan mitziehen. Das fälscht kein Ausführungsprotokoll — die Zeile ist ein Vertrag, den der Test mit dem Code synchron hält, und ihr Nachziehen ist der VORGESEHENE Mechanismus. Ein Plan, der behauptete, der Stufe-1-Plan bliebe unangetastet, oder es sei nur ein Präfix gepinnt, wäre an dieser Stelle falsch. Der Doc-Kommentar von `WASM32_EXEMPT_CRATES` nennt sein eigenes Kriterium („A crate that reaches past `ea-verify` into the host operating system is not shared browser code and belongs here instead"); `ea-reader` ist nach §12 das genaue Gegenteil, eine Ausnahme widerspräche also dem Kriterium der Liste selbst. Der Eintrag von `ea-sync-protocol` in derselben Liste hat diese Kollision bereits benannt und ausdrücklich auf Stufe 4 vertagt. Folge: der eingefrorene Kommentar über dem wasm32-Block wird von der Aufgabe „wasm32-Reichweite: `ea-reader`, die Brücken-Crate und die geteilten Browserkerne" EINMAL für die ganze Stufe umgeschrieben, und diese Aufgabe fährt beide genannten Tests.
- **ENTSCHIEDEN — die verbindliche Größenschwelle des Index nach §8.1 steht bei 50 000 PAKETEN.** §8.1 sagt „trägt bis in den Bereich einiger zehntausend Einsätze" und verschiebt die Zahl in diese Überarbeitung; frei wählbar ist sie nicht. `design.md` fordert unter `NFR-PERF-003` / Abnahmekriterium 31 „Ein Reader verifiziert und indiziert mindestens 50.000 Pakete", und Stufe 7 misst genau diese Zahl in `tests/ea-system-tests/tests/performance_reader_50000.rs`. Eine Schwelle UNTERHALB davon lieferte eine Stufe-4-Indexarchitektur, die ihr eigenes Stufe-7-Gate nachweislich nicht bestehen kann. „Einsatz" und „Paket" sind NICHT dieselbe Einheit — ein Einsatz trägt ein Original plus seine Nachträge —, deshalb steht die Schwelle in PAKETEN, in derselben Einheit, die das Stufe-7-Gate misst. Der monolithische Einzelblob-Index MUSS mindestens 50 000 indizierte Pakete tragen; ab dieser Zahl ist die Segmentierung in einzeln verschlüsselte Indexblöcke die von §8.1 vorab genehmigte Maßnahme. Stufe 4 MISST Blobgröße, Entsperrlatenz und Spitzenspeicher bei 50 000 Paketen, statt sie zu behaupten, damit Stufe 7 keine Wand findet, die sie nicht mehr verschieben kann.
- **Auflegung A — Dienste als Vorbedingung, in dieser Stufe als Klammer ausgeschrieben.** `apps/server` und `crates/ea-sync-server` sind seit Stufe 3 Mitglieder des Arbeitsbereichs, und das Teilkommando `cargo test --workspace --all-targets --locked` aus `verify_quick_commands()` (`tools/xtask/src/main.rs`) zieht ihre Integrationstestziele mit, die `DATABASE_URL` zur Laufzeit lesen. Die Vorbedingung ist bereits IMPLEMENTIERT: `ensure_integration_services_available()` in `tools/xtask/src/main.rs` prüft PostgreSQL und Object Store FAIL-CLOSED vor dem betroffenen Kommando, in derselben Bauform wie `ensure_wasm32_target_available()`, und ein Überspringen über eine Umgebungsvariable ist AUSGESCHLOSSEN. Was diesem Plan fehlte, war allein die Klammer in seiner eigenen Kommandoliste: jedes `pnpm verify:quick` dieses Plans steht in `cargo run --locked -p xtask -- integration up` … `integration down`.
- **Der gepinnte Ledgerblock wächst und bewegt sich in genau zwei Aufgaben.** `WEB_READER_MUST_ROWS` in `tools/xtask/tests/stage_gate.rs` ist eine Konstante fester Stelligkeit, und `web_reader_must_requirements_are_recorded_as_v1_1_rows` verlangt je Tupel eine vorhandene `v1.1`-Zeile in `docs/traceability/v0.1-requirements.csv` mit passender Quellensektion, Stufe und Status. Die Aufgabe „Stufe-4-Vorlauf: ADR 0005, wasm-Werkzeugpins und die aufgehobene Blockade" hebt die Stelligkeit von NEUN auf ELF und legt `WR-053` (§5.3) und `WR-054` (§5.4) im SELBEN Commit als CSV-Zeilen an. Die Aufgabe „Reader-Interoperabilität, Browser-Matrix, Datei-Modus, Privatheit und das Stufe-4-Gate" lässt die Stelligkeit unverändert und bewegt SIEBEN Statusspalten aus `planned` heraus: `WR-041`, `WR-042`, `WR-043`, `WR-053`, `WR-054`, `WR-063` und `WR-082`. `WR-042D` (Stufe 3, `implemented`), `WR-052` (Stufe 2, `integrated`), `WR-064` (Stufe 3, `implemented`) und `WR-075` (Stufe 5, `planned`) bleiben unangetastet. Fünfzehn Ledgerzeilen sind auf Stufe 4 fällig — `AK-10`, `AK-42`, `AK-43`, `FR-085`, `FR-100`, `FR-103`, `FR-104`, `FR-105`, `FR-106`, `FR-122`, `WR-041`, `WR-042`, `WR-043`, `WR-063`, `WR-082` —, plus die zwei neuen Zeilen `WR-053` und `WR-054` sind es siebzehn, und sie kippen alle am Stufengate.
- **Der Browser-Vault ersetzt den nativen Reader-Key-Provider ERSATZLOS** (§11.3). Es gibt keinen `KemDecapsulator`-Trait, keinen Betriebssystem-Keystore und kein `crates/ea-local-store/migrations/0002_reader.sql` im Reader-Pfad. Der X25519-KEM-Schlüssel, der Ed25519-Geräte- und Auditschlüssel, der gepinnte Root-Anchor und der zuletzt verifizierte Registry-Stand liegen ausschließlich im ChaCha20-Poly1305-versiegelten Vault, je Authenticator einmal umschlossen als `KEK_i = HKDF(PRF_i(festes App-Salt), info = "ea-reader-vault-v1")`. Die PRF-Ausgabe selbst DARF NICHT der Wrapping-Schlüssel sein. Die Zusagen des nativen Providers zu Nicht-Roaming und Backup-Ausschluss gelten sinngemäß weiter: Wrapped-Blobs sind ohne Authenticator wertlos, Klartextschlüssel werden nie persistiert. `docs/adr/0002-local-database-encryption.md` bleibt unberührt — der Writer behält SQLCipher.
- **Enrollment verlangt MINDESTENS ZWEI unabhängige Authenticators** (§6.3), bevor je ein Vault geschrieben wird; ein einzelner registrierter Authenticator ist eine harte Ablehnung und keine Warnung. Der Fingerprintvergleich beim Erstaufruf auf einem Gerät ohne gepinnten Trust-Store MUSS erzwungen werden und DARF NICHT überspringbar sein (§4.3); eine Abweichung bricht das Enrollment ab. Der Cross-Device-QR-Flow wird als Entsperrpfad ABGEWIESEN, weil Safari darin keine PRF-Ausgabe liefert (§6.4.1, §13).
- **Der OS-Lock als Sitzungsende entfällt ersatzlos** und wird als dokumentierte SOLL-Abweichung nach §11.2 geführt: der Browser hat keine Entsprechung. An seine Stelle tritt §6.5 — `zeroize` beim Sperren, fünf Minuten Inaktivität als sicherer Vorgabewert, eine VERKÜRZTE Frist, sobald der Tab in den Hintergrund wechselt, und nach jeder Sperrung eine FRISCHE Authenticator-Bestätigung. Die native Re-Authentisierung des Einzelexports wird nach §8.2 durch eine Authenticator-Bestätigung ersetzt.
- **Das Web-Bundle wird von einem vom Sync-Server GETRENNTEN Origin ausgeliefert** (§4.1); der Sync-Server ist kein Bestandteil des Vertrauenspfades für ausgeführten Code. Ein Service Worker DARF eine Kandidatenversion nur aktivieren, wenn ihr Hash gegen eine gepinnte, Root-signierte `webBundleRelease` im lokalen Trust-Store aufgeht; ein unsigniertes oder widerrufenes Bundle wird verworfen und die zuletzt gültige Version bleibt aktiv (§4.2). Das Alter des zuletzt bezogenen Trust-Standes wird über das bereits eingefrorene Feld `reader-trust-refresh-ms` ausgewiesen; eine Überschreitung ist eine Aufforderung zur Aktualisierung und keine Sperre.
- **Im Datei-Modus ist der im Vault gepinnte Root-Anchor die EINZIGE Vertrauensquelle** (§5.3). Trust-Objekte, die in der geöffneten Datei mitliegen, begründen für sich kein Vertrauen; ein untergeschobenes Archiv mit vollständiger eigener Kette MUSS durchfallen. Der Cursor-Mechanismus entfällt ersatzlos, jedes Objekt wird bei jedem Öffnen vollständig geprüft, und Objekte ohne Quittung erscheinen als `nicht server-bestätigt` — eine EIGENE Dimension neben dem Verifikationsstatus, die DARF NICHT als vollständig bestätigt und ebenso wenig als `Lücke` oder `ungültig` dargestellt werden (§5.4, `design.md` §17.4). Der universelle Weg über den gewöhnlichen Dateidialog MUSS immer angeboten werden, weil `showDirectoryPicker` in Safari und Firefox fehlt.
- Microsoft Access is outside scope; **Access Grant** means only the signed key envelope.
- Non-goals are fixed: no live incident log, dispatch/alarm/control-center integration, patient record or identifying patient data, concurrent offline Writers, normal-app mutation/deletion of finalized content, AI summarization/OCR, public links, server-side content search, unprofiled network paths, qualified personal electronic signature, TR-ESOR certification claim, screenshot/transcription prevention, or cryptographic recall of already decrypted data.
- Product invariants apply verbatim: exactly one active Writer; never-reused predecessor-bound sequences; immutable `.eip` bytes except whole-object authorized replacement by `.eds`; amendment-only corrections; one fresh CEK/ciphertext; one signed grant per recipient; exactly one active Recovery grant before commit; no Reader/Recovery/HGA/Approver private key on Writer; no retained CEK/decryptable draft key; no server decrypt/grant key; server-independent archive verification; independent schema/format/suite versions with old bytes unchanged; separate Sync/verification/Evidence/Entry/destruction statuses; no legal overclaim from a hash chain; every active Reader initially granted; external-anchor recovery; and only Root-signed OS/device-bound operator snapshots.
- Archive and Trust bytes remain immutable and server-independent. Schema, format, and suite versions stay independent. Stufe 4 friert KEINE Vektorfamilie ein; `vectors/crypto/suite-1/`, `vectors/trust/v1/` und `vectors/web-bundle/v1/` werden ausschließlich gelesen.
- Verification always precedes HPKE decapsulation and decryption, wortgleich in beiden Betriebsmodi. Unknown/invalid/incomplete objects are isolated, not indexed, and never shown as an empty incident.
- Missing own grant is exactly `fehlender Grant`: the valid technical chain entry stays visible but is neither decrypted nor fachlich indexed. It is never a `Lücke`, never `unbekannter Schlüssel` and never `ungültig`.
- A valid `.eds` with its full authorization/evidence chain is exactly `autorisiert vernichtet`; an incomplete Stub is an `ungeklärte Lücke`. Neither ever calls HPKE.
- Reader has separate X25519 KEM and Ed25519 device/audit keys. Admin role grants no content access; local configuration cannot expand a signed role. `apps/web` carries no Writer, Administration, Root-ceremony, provisioning, re-grant or destruction surface, and the role-gated shell of `apps/desktop` exposes no Reader route.
- Reader vault, cache, index, audit, and keys are encrypted or protected. No decrypted content enters OPFS bytes in the clear, the service-worker cache, clipboard automations, crash dumps, logs, filenames, server metadata, or telemetry.
- Unencrypted bulk export is disabled: no method taking `all records` or a search result exists. A single export requires deliberate target choice, a fresh authenticator confirmation, and a signed local audit that carries pseudonymous operator binding hash, entry hash, target kind, `EffectiveNow`, action code and outcome — never payload, never a clear filename.
- UI uses exact verification/evidence/entry language, text in addition to color/icon, keyboard and screen-reader access, and keeps invalid objects in `Prüfprobleme`.
- UI remains on Ant Design 6 with German `ConfigProvider`, shared exact tokens, `zeroRuntime: true`, statically extracted local hashed CSS, CSP without runtime/external styles, Ant `App` overlay context, direct CSR `@phosphor-icons/react` imports only, visible focus, and reduced-motion support. Die CSP-Grundlinie von `apps/web` erweitert die des Desktops um genau `'wasm-unsafe-eval'` in `script-src` und `worker-src 'self'`.
- Für den Reader ersetzt `web-reader-design.md` §11.4 die Achsen Architektur, Installerformat und Key-Provider durch Engine, Version und Plattform; für Writer, Administration und CLI bleibt die globale Stufe-7-Matrix unverändert gültig. Mindestversionen je Engine sind offen und gehören Stufe 7 (§14.3).
- Crypto/format/Trust/Index remains shared Rust; TypeScript receives only view/status DTOs and executes no security decision.
- v0.1 is complete only after Stage 7 and every acceptance criterion/gate passes.
- Jeder Verweis dieses Plans in `tools/xtask/`, `crates/ea-verify/`, `crates/ea-recovery/` und `crates/ea-trust/` nennt einen FUNKTIONS-, KONSTANTEN- oder TESTNAMEN, nie eine Zeilennummer. Zeilennummern in diesem Plan sind Suchhilfe, kein Vertrag.

The decryption gate order is exact: (1) format/limits, (2) Root and Trust chain, (3) bound Registry/lease/Writer, (4) manifest/signature/Entry/object/ciphertext hashes, (5) sequence/predecessor/Writer transition, (6) grant plan and Recovery grant, (7) Receipt/checkpoints if present, (8) required Evidence, (9) own grant including issuer capability, authorization, `effectiveNow <= expiresAt`, and Entry hash; only then HPKE-open and AEAD-open.

---

### Task 1: Stufe-4-Vorlauf: ADR 0005, wasm-Werkzeugpins und die aufgehobene Blockade

**Files:**
- Create: `docs/adr/0005-browser-runtime-and-wasm-dependency-class.md`
- Create: `tools/xtask/tests/wasm_toolchain.rs`
- Test: `spikes/wasm-runtime-proof/spike.sh` — NUR gefahren, nicht geaendert; siehe Schritt 4
- Modify: `spikes/wasm-runtime-proof/README.md` (die gemessene Wiederholung unter dem gepinnten Node)
- Modify: `Cargo.toml`
- Modify: `.cargo/config.toml`
- Modify: `.gitignore`
- Modify: `mise.toml`
- Modify: `deny.toml`
- Modify: `package.json`
- Modify: `tools/xtask/src/main.rs`
- Modify: `docs/traceability/v0.1-requirements.csv`
- Test: `tools/xtask/tests/adr_gate.rs`
- Test: `tools/xtask/tests/spec_completeness.rs`
- Test: `tools/xtask/tests/stage_gate.rs`
- Test: `tools/xtask/tests/workspace.rs` — NUR gefahren, nicht geaendert; siehe Schritt 4

**Interfaces:**
- Consumes: der gepinnte Compilerstand aus `rust-toolchain.toml`, die Tabelle `[workspace.dependencies]` der Wurzel-`Cargo.toml`, die beiden bestehenden ADR-Zeugen `every_database_dependency_is_pinned_and_named_by_adr_0002` und `server_runtime_dependency_class_is_ratified_before_use` samt ihrer geteilten Hilfsfunktionen `shared_dependencies` und `reviewed_feature_ledger_line` in `tools/xtask/tests/adr_gate.rs`, die Fünf-Einträge-Allowlist von `deny.toml`, `ensure_wasm32_target_available()` als Bauform des fail-closed Vorlaufs, und der ausgeführte Laufzeitnachweis `spikes/wasm-runtime-proof/spike.sh`.
- Produces: ADR 0005, exakte `=`-Pins der Browser-Laufzeitklasse in `[workspace.dependencies]`, der Werkzeugpin `cargo:wasm-bindgen-cli` in `mise.toml`, das Unterkommando `cargo run --locked -p xtask -- build-wasm` mit `ensure_wasm_bindgen_cli_matches_lockfile()`, der Abschnitt `[target.wasm32-unknown-unknown]` in `.cargo/config.toml` mit `runner = "wasm-bindgen-test-runner"` und AUSDRÜCKLICH ohne `rustflags`, die Zeile `pkg/` in `.gitignore`, der VERSIONIERTE Laufzeitnachweis unter `spikes/wasm-runtime-proof/`, der im Test verankerte Auflösungsmarker über dem bereits aufgehobenen Blockadeblock dieses Plans, die zwei neuen Ledgerzeilen `WR-053` und `WR-054`, und die von neun auf elf gewachsene Konstante `WEB_READER_MUST_ROWS`.

Diese Aufgabe registriert AUSDRÜCKLICH kein Cargo-Mitglied, trägt keinen Eintrag in `pnpm-workspace.yaml` und fügt `verify_quick_commands()` kein Kommando hinzu. Das ist die Lehre aus dem Stufe-3-Vorlauf, dort wörtlich notiert: eine `members`-Zeile auf ein Verzeichnis ohne Manifest lässt `cargo metadata` und mit ihm jeden Test scheitern, und ein `verify:quick`-Eintrag auf ein Paket ohne `package.json` färbt jeden Schnelllauf rot, bevor das Artefakt existiert. `crates/ea-reader`, `crates/ea-reader-wasm` und `crates/ea-index` entstehen in ihren eigenen Aufgaben, `apps/web` in der Aufgabe „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate". Diese Aufgabe liefert kein Rust-Verhalten, keinen Browsercode und keine Crate.

- [ ] **Step 1: Write the ratification, the tool-pin parity and the lifted-blockade witnesses**

```rust
// tools/xtask/tests/adr_gate.rs — dritte Instanz desselben Gates, keine
// Verallgemeinerung der ersten beiden: ADR 0002, 0004 und 0005 ratifizieren
// verschiedene Klassen und muessen trennbar bleiben.
const BROWSER_ADR_PATH: &str = "docs/adr/0005-browser-runtime-and-wasm-dependency-class.md";

const BROWSER_ADR_SECTIONS: [&str; 8] = [
    "## Context",
    "## Decision",
    "## Rejected alternatives",
    "## Primary-source and RustSec review",
    "## wasm-bindgen crate and CLI parity",
    "## Enumerated web-sys features",
    "## Browser provisioning",
    "## Consequences",
];

const BROWSER_ADR_LITERALS: [&str; 7] = [
    "docs/adr/0001-toolchain-and-cryptography-dependencies.md",
    "docs/adr/0004-server-runtime-and-dependency-class.md",
    "RustSec advisory database",
    "getrandom 0.4.3 selects its wasm backend through the Cargo feature `wasm_js`",
    "--cfg getrandom_backend",
    "spikes/wasm-runtime-proof/spike.sh",
    "no member of this stage consumes",
];

const BROWSER_RUNTIME_DEPENDENCIES: [&str; 5] = [
    "js-sys",
    "wasm-bindgen",
    "wasm-bindgen-futures",
    "wasm-bindgen-test",
    "web-sys",
];

#[test]
fn browser_runtime_dependency_class_is_ratified_before_use() {
    let adr = fs::read_to_string(workspace_root().join(BROWSER_ADR_PATH))
        .expect("ADR 0005 must exist before any browser dependency is pinned");
    for section in BROWSER_ADR_SECTIONS {
        assert!(adr.contains(section), "ADR 0005 is missing {section}");
    }
    for literal in BROWSER_ADR_LITERALS {
        assert!(adr.contains(literal), "ADR 0005 is missing the literal {literal}");
    }
    let shared = shared_dependencies();
    for name in BROWSER_RUNTIME_DEPENDENCIES {
        let spec = shared
            .get(name)
            .unwrap_or_else(|| panic!("{name} must be a shared workspace dependency"));
        let version = spec
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{name} must carry an explicit version"));
        assert!(version.starts_with('='), "{name} must be pinned exactly");
        assert!(
            adr.lines()
                .any(|line| line.contains(&format!("`{name}`")) && line.contains(version)),
            "ADR 0005 must carry {name} and its pin {version} on one line"
        );
        let ledger = reviewed_feature_ledger_line(name, spec);
        assert!(
            adr.contains(&ledger),
            "ADR 0005 must carry the reviewed feature selection verbatim: {ledger}"
        );
    }
}
```

```rust
// tools/xtask/tests/wasm_toolchain.rs — die drei Orte, an denen dieselbe
// wasm-bindgen-Fassung steht, muessen zeichengleich sein. Der Spike hat genau
// diesen Bruch gemessen: ein frei aufgeloestes Lockfile lief auf 0.2.127,
// waehrend die CLI 0.2.126 war, und `wasm-bindgen` bricht dann mit einem
// Schema-Mismatch ab statt mit einer Codeaussage.
#[test]
fn the_wasm_bindgen_cli_pin_equals_the_locked_crate_version() {
    let root = workspace_root();
    let locked = locked_version(&root, "wasm-bindgen");
    assert_eq!(
        locked,
        shared_dependency_pin(&root, "wasm-bindgen"),
        "Cargo.lock and [workspace.dependencies] must agree on wasm-bindgen"
    );
    assert_eq!(
        locked,
        mise_cargo_tool_pin(&root, "wasm-bindgen-cli"),
        "mise.toml must pin wasm-bindgen-cli to the locked wasm-bindgen version"
    );
}

#[test]
fn build_wasm_rejects_every_argument_and_reports_the_missing_bridge_crate() {
    assert_eq!(
        run_gate(["build-wasm", "reader"]).unwrap_err(),
        "build-wasm does not accept arguments"
    );
    assert_eq!(run_gate(["build-wasmm"]).unwrap_err(), "unknown gate: build-wasmm");
    // Solange `crates/ea-reader-wasm/Cargo.toml` fehlt, meldet der Vorlauf das
    // FEHLENDE ARTEFAKT mit einer Anweisung statt einen cargo-Fehler
    // durchzureichen. Kein Ueberspringen ueber eine Umgebungsvariable.
    assert!(
        run_gate(["build-wasm"])
            .unwrap_err()
            .contains("crates/ea-reader-wasm"),
        "build-wasm must name the missing bridge crate"
    );
}

#[test]
fn build_wasm_builds_without_inherited_rustflags() {
    // getrandom 0.4.3 waehlt sein wasm-Backend ueber das Cargo-Feature
    // `wasm_js`; ein geerbtes `--cfg getrandom_backend=...` aus 0.3 wuerde das
    // Feature ueberstimmen. Der Bau laeuft deshalb mit entferntem RUSTFLAGS.
    assert!(
        build_wasm_command_source().contains("env_remove(\"RUSTFLAGS\")"),
        "build-wasm must strip RUSTFLAGS before it invokes cargo"
    );
}
```

```rust
// tools/xtask/tests/spec_completeness.rs — Erweiterung von
// `later_stage_plans_reference_the_web_reader_spec`. Der Blockadesatz bleibt
// als AUFZEICHNUNG stehen; zusaetzlich verlangt der Test den Auflösungsmarker,
// den Spikepfad und jede der fuenf benannten Grenzen. Damit erzwingt das Gate
// den BELEG und nicht mehr die Sperre.
const STAGE_FOUR_SPIKE_MARKERS: [&str; 3] = [
    "BLOCKIERT — Laufzeitnachweis nach `web-reader-design.md` §14.1",
    "AUFGEHOBEN am 2026-08-30 — Laufzeitnachweis nach `web-reader-design.md` §14.1 erbracht",
    "spikes/wasm-runtime-proof/spike.sh",
];

const STAGE_FOUR_SPIKE_LIMITS: [&str; 5] = [
    "Node v26.8.1 ist eine echte JS-Umgebung, aber kein Browser",
    "nur `debug`, kein `--release` und kein `wasm-opt`",
    "nur `ea-crypto` wird AUSGEFÜHRT",
    "keine COSE-Kette",
    "keine RNG-Statistik, nur Anwesenheitsproben",
];

#[test]
fn later_stage_plans_reference_the_web_reader_spec() {
    // ... die sechs bestehenden Plaene bleiben unveraendert ...
    let stage_four =
        include_str!("../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-4-reader.md");
    for marker in STAGE_FOUR_SPIKE_MARKERS {
        assert!(stage_four.contains(marker), "stage 4 is missing: {marker}");
    }
    for limit in STAGE_FOUR_SPIKE_LIMITS {
        assert!(
            stage_four.contains(limit),
            "the lifted blockade must reproduce the named limit: {limit}"
        );
    }
}
```

```rust
// tools/xtask/tests/stage_gate.rs — die gepinnte Konstante waechst von neun auf
// elf Tupel. `web_reader_must_requirements_are_recorded_as_v1_1_rows` verlangt
// je Tupel eine vorhandene Zeile, also entstehen CSV-Zeile und Tupel im
// SELBEN Commit.
const WEB_READER_MUST_ROWS: [(&str, &str, &str, &str); 11] = [
    ("WR-041", "4.1", "4", "planned"),
    ("WR-042", "4.2", "4", "planned"),
    ("WR-042D", "4.2", "3", "implemented"),
    ("WR-043", "4.3", "4", "planned"),
    ("WR-052", "5.2", "2", "integrated"),
    ("WR-053", "5.3", "4", "planned"),
    ("WR-054", "5.4", "4", "planned"),
    ("WR-063", "6.3", "4", "planned"),
    ("WR-064", "6.4", "3", "implemented"),
    ("WR-075", "7.5", "5", "planned"),
    ("WR-082", "8.2", "4", "planned"),
];
```

- [ ] **Step 2: Run the witnesses and confirm the decision, the command and the two rows are absent**

Run: `cargo test --locked -p xtask --test adr_gate --test wasm_toolchain --test spec_completeness --test stage_gate`

Expected: FAIL, und zwar an vier trennbaren Stellen. `browser_runtime_dependency_class_is_ratified_before_use` bricht beim Lesen von `docs/adr/0005-browser-runtime-and-wasm-dependency-class.md` ab, weil die Datei nicht existiert. `the_wasm_bindgen_cli_pin_equals_the_locked_crate_version` findet `wasm-bindgen` nicht in `[workspace.dependencies]` — die Crate steht heute NUR transitiv in `Cargo.lock` (gemessen: `wasm-bindgen 0.2.126`, `js-sys 0.3.103`, `web-sys 0.3.103`, `wasm-bindgen-futures 0.4.76`, `wasm-bindgen-test 0.3.76`) und ist an keiner Wurzelkante genannt. `build_wasm_rejects_every_argument_and_reports_the_missing_bridge_crate` bekommt vom Verteiler `unknown gate: build-wasm`, weil `fn run` in `tools/xtask/src/main.rs` keinen solchen Arm führt. `later_stage_plans_reference_the_web_reader_spec` fällt am Auflösungsmarker, `web_reader_must_requirements_are_recorded_as_v1_1_rows` an der fehlenden Zeile `WR-053`.

- [ ] **Step 3: Ratify the browser runtime class, pin its tools, and turn the blockade into a record**

Die ADR-Nummer ist **0005**. `docs/adr/` trägt heute 0001, 0002 und 0004; 0003 ist von `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-7-release-hardening.md` für die Lieferkette der Releasehärtung belegt. ADR 0005 folgt der Gestalt, die `every_database_dependency_is_pinned_and_named_by_adr_0002` etabliert und `server_runtime_dependency_class_is_ratified_before_use` wiederholt hat: jede Klasse exakt gepinnt, der Pin auf DERSELBEN Zeile wie der Crate-Name, und die geprüfte Merkmalsauswahl als eine wörtliche Ledgerzeile `name = ["feature", "feature"]`, die der Test aus dem Manifest neu baut. Jede Klasse trägt ihre Primärquellen- und RustSec-Prüfung nach dem Verfahren von `docs/adr/0001-toolchain-and-cryptography-dependencies.md`.

Die Klasse besteht aus fünf Crates, und sie sind alle bereits im Graphen — das ist eine Messung und die tragende Begründung dieses Schritts: `Cargo.lock` führt `wasm-bindgen 0.2.126`, `js-sys 0.3.103`, `web-sys 0.3.103`, `wasm-bindgen-futures 0.4.76` und `wasm-bindgen-test 0.3.76` heute schon transitiv. Sie zu pinnen fügt dem Abhängigkeitsgraphen KEINE Crate hinzu, verändert `cargo deny check licenses` also nicht, und `deny.toml` bekommt deshalb KEINE neue `[licenses]`-Ausnahme und der Ledger folglich KEINEN neuen `GATE-*`-Anker nach dem Muster der `v1.2`-Zeile `GATE-25`. Was `deny.toml` bekommt, ist genau ein Kommentar an der `exceptions`-Liste, der diese Messung festhält, damit die Abwesenheit einer Ausnahme eine Aussage ist und kein Versehen; die Allowlist bleibt bei FÜNF Einträgen. Der Gate-Bericht der Stufe hält im Abschnitt `Gemessener Gate-Lauf` denselben Befund fest — der Teilbaum der Browser-Laufzeitklasse hat keine Lizenzausnahme eingeführt.

`getrandom` steht AUSDRÜCKLICH NICHT in `BROWSER_RUNTIME_DEPENDENCIES`. Sein `=0.4.3`-Pin und das Feature `wasm_js` sind seit dem Web-Reader-Vorlauf der Stufe 1 in `docs/adr/0001-toolchain-and-cryptography-dependencies.md` ratifiziert und werden von `workspace_getrandom_enables_the_wasm_js_feature` in `tools/xtask/tests/workspace.rs` erzwungen. Zwei ADRs, die denselben Pin beanspruchen, driften; ADR 0005 nennt die Entscheidung als Verweis und nicht als zweite Quelle. Der Abschnitt `Decision` schreibt dafür den Satz aus, den `BROWSER_ADR_LITERALS` pinnt: `getrandom 0.4.3 selects its wasm backend through the Cargo feature `wasm_js``, und der Abschnitt `Rejected alternatives` verwirft `--cfg getrandom_backend` mit der gemessenen Begründung des Spikes — in 0.4.3 steht `"wasm_js"` nicht einmal mehr in der erlaubten Werteliste von `cfg(getrandom_backend, values(...))`, und ein gesetzter Wert würde das Feature laut CHANGELOG überstimmen. `.cargo/config.toml` bekommt dafür GENAU EINEN neuen Abschnitt, und was er NICHT enthält, ist die eigentliche Aussage:

```toml
[target.wasm32-unknown-unknown]
runner = "wasm-bindgen-test-runner"
```

Er setzt einen LÄUFER und AUSDRÜCKLICH KEIN `rustflags`. Ein `rustflags = ["--cfg", "getrandom_backend=\"wasm_js\""]` wäre doppelt falsch: `getrandom 0.4.3` wählt sein Backend über das Cargo-Merkmal `wasm_js`, der Schalter gehört zu `0.3` und steht in `0.4.3` nicht einmal mehr in der erlaubten Werteliste von `cfg(getrandom_backend, values(...))`; und ein `rustflags`-Eintrag in `.cargo/config.toml` wird von einem gesetzten `RUSTFLAGS` der Umgebung STILL überstimmt, wäre also selbst dann keine Zusage, wenn er richtig wäre. Der Läufer ist der Grund, aus dem dieser Plan `wasm-pack` NICHT benutzt: `cargo test --locked -p ea-reader-wasm --target wasm32-unknown-unknown` fährt die `wasm-bindgen-test`-Ziele über die EINE gepinnte CLI aus `mise.toml`, während `wasm-pack` einen zweiten, ungepinnten Träger derselben `wasm-bindgen`-Schemafassung samt eigenem `chromedriver` mitbrächte und damit genau den Pin unterliefe, für den diese Aufgabe existiert.

Die Pins werden `=`-genau in `[workspace.dependencies]` der Wurzel-`Cargo.toml` eingetragen, jeweils mit `default-features = false` und aufgezählten Merkmalen, damit die Ledgerzeile eine Auswahl beschreibt und keine Vorgabe:

```toml
js-sys = { version = "=0.3.103", default-features = false, features = ["std"] }
wasm-bindgen = { version = "=0.2.126", default-features = false, features = ["std"] }
wasm-bindgen-futures = { version = "=0.4.76", default-features = false }
wasm-bindgen-test = { version = "=0.3.76", default-features = false }
web-sys = { version = "=0.3.103", default-features = false, features = [
  "Blob", "Crypto", "DedicatedWorkerGlobalScope", "Document", "Event",
  "File", "FileSystemDirectoryHandle", "FileSystemFileHandle",
  "FileSystemGetDirectoryOptions", "FileSystemGetFileOptions",
  "FileSystemReadWriteOptions", "FileSystemSyncAccessHandle", "Headers",
  "MessageEvent", "Navigator", "Request", "RequestInit", "Response",
  "ServiceWorkerGlobalScope", "StorageManager", "SubtleCrypto",
  "VisibilityState", "Window", "Worker", "WorkerGlobalScope",
  "WorkerNavigator",
] }
```

**Der Abschnitt `Browser provisioning` ist der ACHTE, und die Stelligkeit von `BROWSER_ADR_SECTIONS` waechst dabei von sieben auf acht** — dieselbe Behandlung, die dieser Plan `WEB_READER_MUST_ROWS` und `BROWSER_RUNTIME_DEPENDENCIES` gibt. Er entscheidet, WOHER die Browser-Engines und der Webdriver kommen, und diese Frage war bis zur Ueberarbeitung vom 2026-08-31 unbeantwortet: der Stufe-4-Gate-Bericht haelt in `STAGE_FOUR_HOST_SCOPE_CLAUSE` die drei Engine-Baus mit ihren Revisionsnummern fest, aber kein Task sagte, wie sie auf die Maschine kommen. Ein ausfuehrender Agent landete damit bei `playwright install` und, fuer WebKit, bei `playwright install-deps` mit Root-Rechten — eine Voraussetzung, die kein Files-Block deklariert.

Die Entscheidung: **Engines und Webdriver kommen aus einem gepinnten Containerabbild, nicht aus einer Installation auf dem Wirt.** Drei gemessene Gruende, jeder fuer sich ausreichend. Erstens gibt es KEINE CI — weder `.github/workflows` noch `.forgejo` existieren, und der Web-Reader-Vorlauf der Stufe 1 nennt genau das als Grund, warum `verify_quick_commands()` der einzige immer laufende Pfad ist; was die Browsermatrix faehrt, faehrt auf genau einer Maschine, und dieser Plan behandelt gemessene Werkzeugstaende als vertraglich. Zweitens traegt der Entwicklungswirt heute NUR Chromium: `~/.cache/ms-playwright` fuehrt `chromium-1234` und `chromium_headless_shell-1234` und weder `firefox` noch `webkit`, waehrend der Gate-Task alle drei verlangt. Drittens verlangt WebKit unter Linux Systembibliotheken, die `playwright install-deps` mit Root-Rechten nachzieht — ein Eingriff in den Wirt, den ein Testlauf nicht vornehmen darf.

Die Bauform ist die, die dieses Repositorium fuer Dienste bereits fuehrt, und ausdruecklich KEIN `.devcontainer/`: eine Compose-Datei neben `ops/compose/integration.yaml`, ein `xtask`-Unterkommando in der Gestalt von `integration up`/`down`, die Laufzeit gepinnt ueber `EA_CONTAINER_RUNTIME` in `mise.toml` und begruendet in `docs/adr/0004-server-runtime-and-dependency-class.md`. Ein Entwicklungscontainer zoege die ganze Toolchain hinein und stuende gegen die Wirtspinnung aus `rust-toolchain.toml`, `.node-version` und `mise.toml`; ausserdem braucht der Tauri-Bau von `apps/desktop` Wirtsbibliotheken. Der Container ist auf `apps/web` und `crates/ea-reader-wasm` beschraenkt, und die Playwright-Suite von `apps/desktop` bleibt unangetastet auf dem Wirt — ihre gemessenen Befunde zur IPv4-Schleife und zu `offline: true` stehen als Wirtsmessungen in ihrer eigenen Konfiguration.

ZWEI Traeger, nicht einer, und der Abschnitt sagt es ausdruecklich: `pnpm web:e2e` braucht Playwrights eigene Engine-Baus, `pnpm web:browser-test` braucht einen `chromedriver` fuer `wasm-bindgen-test-runner`. Ein reines Playwright-Abbild liefert das erste und nicht das zweite; das Abbild MUSS beide fuehren, und der Abschnitt haelt fest, welches Programm woher kommt.

Die Abbildfassung ist an den `@playwright/test`-Pin von `apps/web/package.json` GEBUNDEN — Playwright weist Engine-Baus fremder Fassung zurueck —, und dieser Pin entsteht erst in der Aufgabe „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate". Deshalb ratifiziert ADR 0005 hier die REGEL und die Bindung, und die Compose-Datei samt gemessenem Abbilddigest entsteht dort. Der Digest wird GEMESSEN und nicht behauptet, wie Stufe 3 ihre zwei Bilddigests gemessen hat.

Was der Container NICHT loest, und der Abschnitt schreibt es aus, damit er keine falsche Sicherheit erzeugt: Playwrights `webkit` ist nicht Safari, und `WebAuthn.addVirtualAuthenticator` bleibt eine CDP-Methode, das Enrollment-E2E also chromium-only — beides steht bereits als offene Zeile im Stufe-4-Gate-Bericht und wird durch ein Abbild nicht wahr.

Der Abschnitt `Enumerated web-sys features` von ADR 0005 nennt je Merkmal die Browser-API, die es freischaltet, und den Abschnitt des Web-Reader-Specs, der sie verlangt: die OPFS-Familie `FileSystem*` samt `StorageManager` trägt §8.1 und den Bytespeicher, `Worker`/`DedicatedWorkerGlobalScope`/`MessageEvent` tragen den Zwang, dass synchrone Zugriffshandles NUR in einem Worker existieren, `ServiceWorkerGlobalScope` trägt §4.2, `Crypto`/`SubtleCrypto` die Entropie und die WebAuthn-Seite von §6.2, `Request`/`RequestInit`/`Response`/`Headers` den Server-Modus von §5.1, und `Document`/`VisibilityState`/`Event` die verkürzte Sperrfrist bei Wechsel des Tabs in den Hintergrund nach §6.5. `web-sys` ist merkmalsgetorte Codegenerierung: ohne Aufzählung wäre die Fläche entweder leer oder unbegrenzt, und beides wäre ungeprüft. Ein sechsundzwanzigstes Merkmal MUSS durch dieses Gate.

`mise.toml` bekommt den Werkzeugpin über das cargo-Backend:

```toml
[tools]
pnpm = "11.20.0"
"cargo:wasm-bindgen-cli" = "0.2.126"
```

Dieser Pin ist die eine Zeile, an der der Spike gescheitert wäre: `wasm-bindgen-cli` und die Crate `wasm-bindgen` MÜSSEN zeichengleich sein, sonst bricht der Generator mit einem Schema-Mismatch ab, und ein grüner Lauf hätte etwas belegt, das im Repo so nicht gebaut wird. Dasselbe Paket liefert BEIDE Programme, die diese Stufe braucht — `wasm-bindgen` für `build-wasm` und `wasm-bindgen-test-runner` für den Browserlauf —, und genau deshalb reicht EIN Pin: ein zweites Werkzeug mit eigener Fassung wäre ein zweiter Träger derselben Schemafassung. Rust bleibt weiterhin AUSSCHLIESSLICH in `rust-toolchain.toml` und Node in `.node-version`; `mise.toml` sagt über beide nichts, und das bleibt so.

**Der Laufzeitnachweis liegt bereits im Repositorium; diese Aufgabe PINNT ihn und legt ihn nicht an.** Er wurde am 2026-08-31 mit dem Commit `2ed2b91` eingestellt, neun Quelldateien unter `spikes/wasm-runtime-proof/`. Das war die Vorbedingung fuer die Ueberarbeitung dieses Plans: der aufgehobene Blockadeblock, die Konstante `STAGE_FOUR_SPIKE_MARKERS`, ADR 0005 und dieser Schritt zitieren `spikes/wasm-runtime-proof/spike.sh` alle als Beleg des Repositoriums, und ein Beleg, der nicht im Repositorium liegt, ist keiner. Diese Aufgabe fasst die neun Dateien inhaltlich NICHT an; sie faehrt den Nachweis in Schritt 4 unter dem GEPINNTEN Node erneut und schreibt das gemessene Ergebnis in `spikes/wasm-runtime-proof/README.md` fort.

**`.gitignore` bekommt `pkg/` trotzdem, aber aus einem anderen Grund als dem urspruenglich angenommenen.** Die Annahme, ohne diese Zeile zoege ein `git add spikes/wasm-runtime-proof` die erzeugten `wasm-bindgen`-Bindungen mit ein, ist GEMESSEN FALSCH: der Spike traegt ein eigenes `spikes/wasm-runtime-proof/.gitignore` mit `/target` und `/pkg`, git beachtet es, und der Commit `2ed2b91` staged entsprechend genau neun Quelldateien und kein Artefakt. Die Wurzel-`.gitignore` braucht die Zeile dennoch, und zwar fuer den SPAETEREN Ausgang von `build-wasm` unter `apps/web/src/bridge/pkg/`, den kein lokales `.gitignore` deckt — die Aufgabe „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate" verlaesst sich darauf.

**Der Nachweis wird unter dem GEPINNTEN Node wiederholt.** Der aufgehobene Blockadeblock protokolliert `node v26.8.1`, während `.node-version` und die `engines`-Zeile von `package.json` auf `26.7.0` stehen. Dieser Plan behandelt gemessene Werkzeugstände als vertraglich, also wird die Abweichung nicht durch Anheben des Pins beseitigt — ein Versionssprung des Repositoriums wäre eine Entscheidung über alle Pakete und keine Stufe-4-Frage. Stattdessen fährt diese Aufgabe `spikes/wasm-runtime-proof/spike.sh` ein zweites Mal mit `NODE_BIN` auf der gepinnten Fassung `26.7.0` und trägt das GEMESSENE Ergebnis — Exitcode und die vier ausgeführten Elemente aus §14.1 — in `spikes/wasm-runtime-proof/README.md` ein. Weicht das Ergebnis ab, ist das ein Befund dieser Aufgabe und keine Fussnote.

Der Verteiler `match gate.as_str()` in `fn run` (`tools/xtask/src/main.rs`) bekommt den Arm `build-wasm`. Die Argumentgrammatik wird ausgeschrieben und nicht still geöffnet: `build-wasm` nimmt wie `test-core` und `validate-schemas` KEIN Argument und antwortet sonst mit `build-wasm does not accept arguments`. Der Arm fährt vier Schritte in dieser Reihenfolge, jeder fail-closed, keiner über eine Umgebungsvariable überspringbar:

```rust
fn ensure_wasm_bindgen_cli_matches_lockfile(root: &Path) -> Result<(), String>;

fn ensure_bridge_crate_exists(root: &Path) -> Result<(), String>;

fn run_process_without_rustflags(
    root: &Path,
    program: &str,
    args: &[impl AsRef<std::ffi::OsStr>],
) -> io::Result<()>;

fn run_build_wasm(root: &Path) -> Result<(), String>;
```

**Die vier Helfer stehen UNTERHALB von `verify_quick_commands()`, direkt neben `ensure_wasm32_target_available()`, und das ist eine Platzierungsauflage und keine Ordnungsfrage.** `run_process_without_rustflags` fährt `cargo build --locked --target wasm32-unknown-unknown …` und trägt damit ein ZWEITES Vorkommen der Zeichenkette `"wasm32-unknown-unknown"` in `tools/xtask/src/main.rs` ein. `every_crates_member_is_classified_for_the_wasm32_gate` in `tools/xtask/tests/workspace.rs` verankert die Positivliste am ERSTEN zitierten Vorkommen dieses Literals in `main.rs` und schreibt die Regel in seinem eigenen Kommentar aus: dieses erste Vorkommen MUSS das in `verify_quick_commands()` bleiben, und genau deshalb liegt `ensure_wasm32_target_available()` — das dasselbe Literal in seiner Zielprüfung und in seiner `rustup`-Meldung ein zweites und drittes Mal führt — bereits heute UNTERHALB von `verify_quick_commands()`. Ein Helfer dieser Aufgabe oberhalb davon verschöbe den Anker auf sein eigenes Kommando und ließe `every_crates_member_is_classified_for_the_wasm32_gate` an einer leeren Positivliste fallen. Deshalb fährt Schritt 4 `--test workspace` mit.

`ensure_wasm32_target_available()` läuft zuerst und unverändert. `ensure_wasm_bindgen_cli_matches_lockfile()` ist nach seinem Vorbild gebaut: es liest die aufgelöste Fassung von `wasm-bindgen` aus `Cargo.lock`, ruft `wasm-bindgen --version`, und meldet bei Abweichung die Fassung, die installiert werden MUSS, statt einen Schema-Mismatch tief im Generatorprotokoll entstehen zu lassen. Fehlt die CLI ganz, ist das derselbe Fehler mit derselben Anweisung. `ensure_bridge_crate_exists()` prüft die Anwesenheit von `crates/ea-reader-wasm/Cargo.toml` und meldet, dass die Brücke erst in der Aufgabe „wasm32-Reichweite: `ea-reader`, die Brücken-Crate und die geteilten Browserkerne" entsteht — bis dahin ist `build-wasm` ein vollständig gebautes, vollständig getestetes Kommando ohne Artefakt, und genau das ist beabsichtigt: das Kommando entsteht VOR seinem Gegenstand, wie `integration up` in Stufe 3 vor `apps/server` entstand. Erst danach fährt `run_process_without_rustflags` den Bau `cargo build --locked --target wasm32-unknown-unknown -p ea-reader-wasm --lib` und den Generatorlauf `wasm-bindgen --target web`. Der eigene Prozessläufer existiert, weil `run_process` die Umgebung unverändert erbt; `Command::env_remove("RUSTFLAGS")` ist die einzige Abweichung und trägt die Messung aus ADR 0005.

`tools/xtask/tests/wasm_toolchain.rs` ist ein EIGENES Testziel und kein Anhang an `integration_services.rs`: die beiden prüfen verschiedene Vorbedingungen und müssen einzeln fahrbar bleiben. Der Prozessläufer `run_gate` wird dabei in der Gestalt übernommen, die `tools/xtask/tests/integration_services.rs` bereits führt — Start über `env!("CARGO_BIN_EXE_xtask")`, Fehlermeldung aus der `xtask: `-Zeile auf stderr —, weil ein Integrationstestziel keine Hilfsfunktion eines anderen Ziels sehen kann; die Wiederholung ist eine Sprachgrenze und keine Duplikation einer Entscheidung.

`package.json` bekommt dazu das Wurzelskript `"build:wasm": "cargo run --locked -p xtask -- build-wasm"`. Es steht in KEINER Kommandoliste dieser Aufgabe und in KEINEM Eintrag von `verify_quick_commands()`; die Aufgabe „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate" ist die erste, die `build-wasm` in den Schnelllauf hängt, und zwar vor `pnpm --dir apps/web build`, spiegelbildlich zur Stellung des Desktopbaus vor den Cargo-Kommandos.

Die Region zwischen `<!-- web-reader-stage-4-block -->` und `<!-- /web-reader-stage-4-block -->` TRÄGT die Aufzeichnung bereits: sie ist mit der Überarbeitung dieses Plans vom 2026-08-30 von einer Sperre zu einer AUFZEICHNUNG geworden, und diese Aufgabe ändert an ihrem Text NICHTS — sie PINNT ihn. Zur Erinnerung an die Form, die der erweiterte Test verlangt: Der Blockadesatz bleibt zeichengleich stehen — er ist in `later_stage_plans_reference_the_web_reader_spec` gepinnt, und das Repositorium fälscht keine Ausführungsaufzeichnungen; die Konvention dafür ist die `Historisch:`-Fußnote aus `docs/superpowers/plans/2026-08-16-einsatzarchiv-web-reader-stage-1-prerequisites.md`. Unter ihm stehen der Auflösungsmarker `AUFGEHOBEN am 2026-08-30 — Laufzeitnachweis nach `web-reader-design.md` §14.1 erbracht`, der Pfad `spikes/wasm-runtime-proof/spike.sh` (Exit 0, wiederholt aus gelöschtem `target/` und `pkg/`), die gemessenen Werkzeugstände (rustc 1.95.0, cargo 1.95.0, node v26.8.1, `wasm-bindgen` Crate UND CLI 0.2.126, `getrandom 0.4.3` mit `wasm_js`), die vier ausgeführten Elemente aus §14.1, die adversariale Gegenprobe — fünf einzeln mutierte Erwartungen, jede färbte den Spike rot, die entscheidende mit falschem Empfängerseed UND nachgeflickter Thumbprint-Konstante — und die fünf benannten Grenzen. `STAGE_FOUR_SPIKE_LIMITS` pinnt genau diese fünf Grenzen wörtlich; sie stehen in den Global Constraints dieses Plans und werden hier nicht ein zweites Mal ausgeschrieben, weil zwei Fassungen desselben Satzes die erste sind, die still driftet.

Die Rücknahmeliste der sechs Punkte steht dort als historische Aufzeichnung und ist als „nicht mehr anwendbar" gekennzeichnet; sie beschreibt den Fall, der nicht eingetreten ist. Die fünf Grenzen binden die Arbeit späterer Aufgaben und werden von keiner beschönigt.

Dazu die sechste Tatsache, die keine Grenze des Nachweises ist, sondern seine Lage: der Spike liegt AUSSERHALB jedes Gates dieses Repositoriums — nicht unter `crates/`, nicht in `cargo deny`, nicht in `tools/xtask/tests/workspace.rs`. Er belegt und erzwingt nichts. Die Aufgabe „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate" holt ihn in zwei gegatterte Zeugen herein; bis dahin ist er Beleg und nicht Schranke. Die Global Constraints dieses Plans tragen die zwei zugehörigen Entscheidungen bereits ausgeschrieben: die Klammer `cargo run --locked -p xtask -- integration up` … `integration down` um jedes `pnpm verify:quick` dieses Plans, und die Auflösung der wasm32-Kollision zugunsten der Positivliste. Diese Aufgabe fasst die Positivliste NICHT an — das tut die Aufgabe „wasm32-Reichweite: `ea-reader`, die Brücken-Crate und die geteilten Browserkerne".

`docs/traceability/v0.1-requirements.csv` bekommt die zwei neuen `v1.1`-Zeilen. Sie entstehen HIER und nicht in der Datei-Modus-Aufgabe, weil `web_reader_must_requirements_are_recorded_as_v1_1_rows` je Tupel eine vorhandene Zeile verlangt und die gewachsene Konstante sonst rot stünde, bevor die Aufgabe läuft, die sie füllt:

```csv
"WR-053","v1.1","docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md 5.3","Gepinnter Root-Anchor ist im Datei-Modus die einzige Vertrauensquelle","","","Stufe 4, docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-4-reader.md; Trust-Objekte aus der geoeffneten Datei begruenden kein Vertrauen, ein untergeschobenes Archiv mit eigener Kette faellt an dieser Pruefung durch","4","planned"
"WR-054","v1.1","docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md 5.4","Objekte ohne Receipt sichtbar als nicht server-bestaetigt; Cursor entfaellt im Datei-Modus ersatzlos","","","Stufe 4, docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-4-reader.md; nicht server-bestaetigt DARF NICHT als vollstaendig bestaetigt dargestellt werden und ist weder Luecke noch ungueltig; jedes Objekt wird bei jedem Oeffnen vollstaendig geprueft","4","planned"
```

Beide Zeilen folgen der Neun-Felder-Form, die `ledger_fields` in `tools/xtask/tests/stage_gate.rs` erzwingt, tragen KEIN Anführungszeichen im Freitext und stehen mit `v1.1` außerhalb der v1-Zählungen von `stage_one_gate_covers_every_functional_requirement_and_acceptance_criterion`. Die Statusspalte bleibt `planned`; sie kippt erst am Stufengate.

- [ ] **Step 4: Run the ratification gate, the tool parity, and both plan pins**

Run:

```bash
cargo test --locked -p xtask --test adr_gate --test wasm_toolchain --test spec_completeness --test stage_gate --test workspace
cargo run --locked -p xtask -- build-wasm
cargo deny check
NODE_BIN="$(mise where node 2>/dev/null || command -v node)" spikes/wasm-runtime-proof/spike.sh
```

Expected: PASS bis auf `build-wasm`, das mit Exit 2 und der Anweisung auf `crates/ea-reader-wasm` abbricht — das ist der erwartete Ausgang und wird als solcher notiert, nicht als Fehlschlag. **JEDES Kommando dieser Aufgabe trägt `--locked`, und sie führt KEIN `cargo metadata`.** Das ist die Regel und nicht ihre Ausnahme: `workspace_declares_exact_planned_members_and_shared_dependencies` verlangt das eine `--locked`-freie Kommando ausschliesslich in dem Task, der ein Mitglied oder eine Fremdabhaengigkeit EINTRAEGT, und diese Aufgabe traegt per Entwurf keins ein. `Cargo.lock` ändert sich hier NICHT, und das ist gemessen und nicht angenommen — in einem Wegwerf-Arbeitsbereich blieb `Cargo.lock` byteweise identisch, nachdem `[workspace.dependencies]` um `wasm-bindgen` und `js-sys` gewachsen war, weil eine Zeile dieser Tabelle eine VORLAGE ist und erst über ein `workspace = true` eines Mitglieds in den Auflösungsgraphen tritt. Eine Wohlgeformtheitsprobe der neuen Wurzeltabelle braucht es dafür nicht: `--locked` selbst faellt laut, wenn die Tabelle den Lockfile ueberholt hat, und ein zweites Kommando, das nichts fortschreibt, machte die Regel unscharf, an der die sechs eintragenden Aufgaben dieser Stufe haengen. Der erste echte Lockfile-Fortschritt der Stufe fällt in der Aufgabe „wasm32-Reichweite: `ea-reader`, die Brücken-Crate und die geteilten Browserkerne", die die zwei Mitglieder anlegt. `--test workspace` steht in derselben Zeile, weil dieser Schritt die Helfer aus Schritt 3 zum ersten Mal übersetzt: `every_crates_member_is_classified_for_the_wasm32_gate` ist der EINZIGE Zeuge, der bemerkt, wenn das neue `"wasm32-unknown-unknown"` von `run_process_without_rustflags` den Anker der Positivliste vor `verify_quick_commands()` gezogen hat. `cargo deny check` steht hier, weil die Behauptung „der Teilbaum führt keine Lizenzausnahme ein" gemessen und nicht angenommen wird. Die letzte Zeile wiederholt den Laufzeitnachweis unter der GEPINNTEN Node-Fassung `26.7.0` aus `.node-version`; der aufgehobene Blockadeblock protokolliert `node v26.8.1`, und dieser Plan behandelt gemessene Werkzeugstände als vertraglich. Erwartet ist Exit 0 mit denselben vier ausgeführten Elementen aus §14.1; das GEMESSENE Ergebnis — Exitcode, Node-Fassung, die vier Elemente — wird in `spikes/wasm-runtime-proof/README.md` festgeschrieben. Weicht es ab, ist das ein Befund dieser Aufgabe und keine Fußnote, und der Pin wird NICHT angehoben, um ihn verschwinden zu lassen.

Die adversarialen Fälle laufen alle: eine Vertauschung der Pins zweier ratifizierter Crates lässt beide Teilzeichenketten im ADR stehen und fällt trotzdem, weil `adr.lines().any(...)` Name und Pin auf DERSELBEN Zeile verlangt; ein zusätzliches, entferntes oder umsortiertes `web-sys`-Merkmal bricht die wörtliche Ledgerzeile; ein `mise.toml`, das die CLI auf 0.2.127 zieht, bricht `the_wasm_bindgen_cli_pin_equals_the_locked_crate_version` an der dritten Gleichheit; ein `build-wasm reader` bekommt den Argumentfehler statt eines stillschweigend geöffneten Kommandos; eine aus den Global Constraints gelöschte Grenze bricht `later_stage_plans_reference_the_web_reader_spec`; und ein entfernter Blockadesatz bricht denselben Test, weil er BEIDE Marker verlangt.

- [ ] **Step 5: Commit the decision and the tool surface before any browser code**

```bash
git add .gitignore
git add docs/adr/0005-browser-runtime-and-wasm-dependency-class.md \
        Cargo.toml .cargo/config.toml mise.toml deny.toml package.json \
        tools/xtask docs/traceability/v0.1-requirements.csv \
        spikes/wasm-runtime-proof/README.md
git commit -m "build(reader): ratify and pin the browser runtime dependency class"
```

### Task 2: wasm32-Reichweite: `ea-reader`, die Brücken-Crate und die geteilten Browserkerne

**Files:**
- Create: `crates/ea-reader/Cargo.toml`
- Create: `crates/ea-reader/src/lib.rs`
- Create: `crates/ea-reader/src/mode.rs`
- Create: `crates/ea-reader-wasm/Cargo.toml`
- Create: `crates/ea-reader-wasm/src/lib.rs`
- Create: `crates/ea-archive/src/bundle.rs`
- Create: `crates/ea-archive/src/bundle_error.rs`
- Test: `crates/ea-reader-wasm/tests/bridge_boundary.rs`
- Test: `crates/ea-archive/tests/bundle_reader.rs`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `crates/ea-archive/src/lib.rs`
- Modify: `crates/ea-archive-fs/src/bundle.rs`
- Modify: `crates/ea-archive-fs/src/lib.rs`
- Delete: `crates/ea-archive-fs/src/bundle_error.rs`
- Modify: `crates/ea-archive-fs/tests/bundle_reader.rs`
- Modify: `crates/ea-archive-fs/tests/bundle_export.rs`
- Modify: `tests/ea-system-tests/tests/e2e_writer_archive.rs`
- Modify: `tools/xtask/src/main.rs`
- Modify: `tools/xtask/tests/workspace.rs`
- Modify: `tools/xtask/tests/stage_gate.rs`
- Test: `tools/xtask/tests/spec_completeness.rs` — NUR gefahren, nicht geaendert; seine zwei Praefixe ueberleben das Anhaengen der drei `-p`-Paare, siehe Schritt 4
- Modify: `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md`

`tools/xtask/tests/stage_gate.rs` steht nicht in der Grobzuordnung dieses Tasks und gehoert trotzdem hierher: er ist der erste Task der Stufe, der `wasm32_positive_list_count()` bewegt, und dieser LIVE gezaehlte Wert wird heute gegen die ausgeschriebene Zahl in zwei ABGESCHLOSSENEN Gate-Berichten gestellt. Wer die Positivliste erweitert und diese Datei nicht anfasst, laesst zwei gruene Tests rot zurueck, ohne dass eine Aufgabe den Bruch besitzt. Schritt 3 loest ihn.

`tests/ea-system-tests/tests/e2e_writer_archive.rs` steht nicht in der Grobzuordnung dieses Tasks und gehoert trotzdem hierher: es ist der EINZIGE Aufrufer von `ArchiveBundleSource::open` ausserhalb von `crates/ea-archive-fs` (`:188`), und diese Methode verliert in diesem Task ihre Form als inhaerente Methode. Ein Task, der eine Signatur aendert und ihren Aufrufer stehen laesst, ist rot, bevor er etwas belegt. Die Zeilennummer ist Suchhilfe, kein Vertrag.

**Interfaces:**
- Consumes: `ea_verify::GATE_ORDER_V1`; `ea_archive::{ArchiveSource, ArchiveBlob, ArchiveError, MAX_ARCHIVE_BLOBS_V1, MAX_TOTAL_ARCHIVE_BYTES_V1}`; den in ADR 0005 ratifizierten `=`-Pin `wasm-bindgen = "=0.2.126"` aus `[workspace.dependencies]`, den der Task „Stufe-4-Vorlauf: ADR 0005, wasm-Werkzeugpins und die aufgehobene Blockade" eintraegt; die Positivliste des wasm32-Blocks in `verify_quick_commands()`; die Zeugen `every_crates_member_is_classified_for_the_wasm32_gate` und `workspace_declares_exact_planned_members_and_shared_dependencies` in `tools/xtask/tests/workspace.rs`; die Konstante `WORKSPACE_MEMBERS` ebendort.
- Produces: `crates/ea-reader` mit `ReaderMode` und dem Re-Export von `GATE_ORDER_V1`; `crates/ea-reader-wasm` als `cdylib`+`rlib` mit `bridge_echo` und seinem `cfg(target_arch = "wasm32")`-Export; `ea_archive::{ArchiveBundleSource, BundleError, BUNDLE_MAGIC_V1, BUNDLE_HEADER_BYTES_V1, BUNDLE_FILE_EXTENSION_V1}`; `ea_archive_fs::open_archive_bundle`; drei neue Namen auf der wasm32-Positivliste (`ea-sync-protocol`, `ea-reader`, `ea-reader-wasm`) und den einmal fuer die ganze Stufe umgeschriebenen Kommentar ueber dem wasm32-Block.

Dieser Task aendert KEIN Wireformat, friert KEINEN Vektor ein und liefert KEINE Reader-Funktion. Die Bruecken-Crate ist hier ein Skelett; der echte Uebergang — OPFS, Vektorzeugen im Gate, headless-Chromium — gehoert dem Task „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate".

- [ ] **Step 1: Write the reachability, bridge-boundary and no-`std::fs` witnesses**

```rust
// crates/ea-reader-wasm/tests/bridge_boundary.rs
//
// WIRTSZEUGE, und der cfg-Kopf sagt es. Ohne ihn zoege der Browserlauf
// `cargo test --locked -p ea-reader-wasm --target wasm32-unknown-unknown`
// dieses Ziel mit, uebersetzte es fuer wasm32 und uebergaebe es dem
// `wasm-bindgen-test-runner` — der findet in einem Ziel ohne
// `#[wasm_bindgen_test]` keinen einzigen Fall. Das Spiegelbild steht ueber
// `crates/ea-reader-wasm/tests/opfs_browser.rs`, das aus dem umgekehrten Grund
// `#![cfg(target_arch = "wasm32")]` traegt.
#![cfg(not(target_arch = "wasm32"))]

use ea_reader::{GATE_ORDER_V1, ReaderMode};
use ea_reader_wasm::bridge_echo;

/// Der Rundlauf in BEIDE Richtungen: ein Argument geht hinein, ein anderer
/// Wert kommt heraus. Ein Export, der nur einen Rueckgabewert liefert, belegt
/// nicht, dass Argumente die Grenze ueberhaupt erreichen — genau die Luecke,
/// die `echo_from_js` im Spike `spikes/wasm-runtime-proof/src/lib.rs` schliesst.
#[test]
fn the_bridge_returns_what_its_caller_hands_it() {
    assert_eq!(bridge_echo("Datei-Modus"), "ea-reader-wasm: Datei-Modus");
    assert_ne!(bridge_echo("a"), bridge_echo("b"));
}

/// Das wasm-Ziel wird in diesem Task NICHT ausgefuehrt. Belegbar ist hier
/// deshalb nur die LAGE des Exports, und die wird als Text gelesen — dieselbe
/// Bauform, mit der `every_crates_member_is_classified_for_the_wasm32_gate`
/// den wasm32-Block aus `tools/xtask/src/main.rs` liest.
#[test]
fn every_wasm_bindgen_export_sits_behind_the_wasm32_cfg() {
    // Der Zeuge laeuft ueber JEDE Quelle der Bruecke und ueber BEIDE
    // Schreibweisen des Attributs. Acht spaetere Module — `bridge.rs`,
    // `opfs_worker.rs`, `vault_bridge.rs`, `webauthn.rs`, `fetch.rs`,
    // `file_access.rs`, `visibility.rs`, `view.rs` — legen Ausfuhren an, und
    // sie schreiben `#[wasm_bindgen(js_name = …)]` nach einem
    // `use wasm_bindgen::prelude::*;`. Ein Zeuge, der nur `src/lib.rs` liest
    // und nur die voll qualifizierte Form kennt, saehe keine davon.
    let mut sources: Vec<PathBuf> = fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("src"))
        .expect("the bridge crate must have a src directory")
        .map(|entry| entry.expect("readable directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .collect();
    sources.sort();
    assert!(!sources.is_empty(), "the bridge must carry at least one source file");

    let mut exports = 0_usize;
    for path in &sources {
        // Die qualifizierte Form wird auf die kurze zurueckgefuehrt, damit
        // GENAU EIN Muster gesucht wird und keine Schreibweise durchrutscht.
        let source = fs::read_to_string(path)
            .expect("bridge sources must be readable")
            .replace("#[wasm_bindgen::prelude::wasm_bindgen", "#[wasm_bindgen");
        for (index, _) in source.match_indices("#[wasm_bindgen") {
            // `#[wasm_bindgen_test]` ist kein Export und wird nicht gezaehlt.
            if source[index..].starts_with("#[wasm_bindgen_test") {
                continue;
            }
            exports += 1;
            assert!(
                source[..index].trim_end().ends_with("#[cfg(target_arch = \"wasm32\")]"),
                "a wasm_bindgen export without the wasm32 cfg breaks the host build of \
                 `cargo test --workspace --all-targets --locked`: {}",
                path.display()
            );
        }
    }
    assert!(exports > 0, "the bridge must export at least once");
}

/// `ea-reader` traegt in diesem Task KEINE Rechnung. Die zwei Zusicherungen
/// sind: der Modus ist geschlossen und zweiwertig, und die Gate-Reihenfolge
/// kommt aus `ea-verify` und wird hier nicht ein zweites Mal geschrieben.
#[test]
fn the_reader_crate_reexports_the_gate_order_instead_of_redeclaring_it() {
    assert_eq!(GATE_ORDER_V1, ea_verify::GATE_ORDER_V1);
    assert_eq!(ReaderMode::ALL.len(), 2);
    assert_eq!(ReaderMode::Server.code(), "server");
    assert_eq!(ReaderMode::File.code(), "file");
}
```

```rust
// crates/ea-archive/tests/bundle_reader.rs
use ea_archive::{
    ArchiveBlob, ArchiveBundleSource, ArchiveSource, BUNDLE_HEADER_BYTES_V1, BUNDLE_MAGIC_V1,
    BundleError, MAX_ARCHIVE_BLOBS_V1,
};

/// Positivkontrolle ZUERST — die Regel, die `crates/ea-archive-fs/tests/bundle_reader.rs`
/// in seinem Kopf schon aufschreibt: Negativfaelle, die nur `is_err()` behaupten,
/// waeren auch dann gruen, wenn der Leser jeden Container abwiese.
#[test]
fn a_hand_built_container_hands_out_its_blobs_without_touching_the_filesystem() {
    let bytes = hand_built_container(&[("trust/root.etb", b"AAAA"), ("trust/z.etb", b"BB")]);
    let bundle = ArchiveBundleSource::from_bytes(bytes).unwrap();
    let mut seen: Vec<(String, Vec<u8>)> = Vec::new();
    bundle
        .visit_blobs(&mut |blob: ArchiveBlob<'_>| {
            seen.push((blob.path_hint().to_owned(), blob.bytes().to_vec()));
            Ok(())
        })
        .unwrap();
    assert_eq!(seen[0].0, "trust/root.etb");
    assert_eq!(seen[1].1, b"BB".to_vec());
}

/// Die Blobzahl wird aus dem KOPF durchgesetzt, bevor ein Indexsatz angefasst
/// wird. Der Zeuge misst genau diese Reihenfolge: der Kopf luegt, der Index ist
/// leer, und der Befund muss trotzdem `BlobLimit` sein und nicht `Malformed`.
#[test]
fn the_blob_count_is_refused_from_the_header_before_any_index_record() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&BUNDLE_MAGIC_V1);
    bytes.extend_from_slice(&(MAX_ARCHIVE_BLOBS_V1 as u64 + 1).to_be_bytes());
    bytes.extend_from_slice(&0u64.to_be_bytes());
    assert_eq!(bytes.len(), BUNDLE_HEADER_BYTES_V1);
    assert_eq!(ArchiveBundleSource::from_bytes(bytes), Err(BundleError::BlobLimit));
}

/// Die Fehlercodes reisen mit dem Typ. Sie sind Fehlercodes eines Containers
/// und keine Fehlercodes eines Dateisystems, und `EA-BUNDLE-IO` bleibt in der
/// Liste, obwohl diese Crate kein `std::fs` beruehrt: die Variante wird
/// ausschliesslich in `crates/ea-archive-fs` konstruiert, und eine zweite
/// Fehleraufzaehlung neben dieser waere der Weg, auf dem zwei Codes fuer
/// denselben Befund entstehen.
#[test]
fn every_bundle_error_code_survives_the_move() {
    for (error, code) in [
        (BundleError::SourceNotFullyVerified, "EA-BUNDLE-SOURCE-NOT-FULLY-VERIFIED"),
        (BundleError::TargetOccupied, "EA-BUNDLE-TARGET-OCCUPIED"),
        (BundleError::Malformed, "EA-BUNDLE-MALFORMED"),
        (BundleError::BlobLimit, "EA-BUNDLE-BLOB-LIMIT"),
        (BundleError::TotalByteLimit, "EA-BUNDLE-TOTAL-BYTE-LIMIT"),
        (BundleError::Io, "EA-BUNDLE-IO"),
    ] {
        assert_eq!(error.code(), code);
    }
}
```

- [ ] **Step 2: Run the witnesses and confirm both crates and the shared reader are absent**

Run: `cargo test --locked -p ea-reader-wasm --test bridge_boundary; cargo test --locked -p ea-archive --test bundle_reader; cargo test --locked -p xtask --test workspace`

Alle drei Kommandos tragen `--locked`, und das ist richtig herum: in diesem Schritt ist NOCH NICHTS registriert, `Cargo.lock` steht also unveraendert und `--locked` ist erfuellbar. Das eine Kommando ohne `--locked` — `cargo metadata --format-version 1` — gehoert an den ANFANG von Schritt 4, unmittelbar nachdem Schritt 3 die zwei Mitglieder und die zwei Pfadkanten eingetragen hat, und nicht hierher; stuende es hier, schriebe es nichts fort und die `--locked`-Kommandos DANACH fielen an einem Lockfile, das der Mitgliedseintrag inzwischen ueberholt hat. Die Regel steht woertlich in `workspace_declares_exact_planned_members_and_shared_dependencies` (`tools/xtask/tests/workspace.rs`): „Ein neues Mitglied oder eine neue Fremdabhaengigkeit schreibt Cargo.lock neu, deshalb laeuft in dem Task, der sie eintraegt, GENAU EIN Kommando ohne --locked". Die drei Kommandos sind mit `;` getrennt und nicht mit `&&`, weil drei verschiedene Abwesenheiten gemeldet werden sollen.

Expected: FAIL ZWEIFACH und aus zwei verschiedenen Gruenden, dazu ein DRITTER Lauf, der GRUEN ist — und seine Gruenheit ist die Aussage, nicht sein Mangel. `-p ea-reader-wasm` und `-p ea-reader` sind unbekannte Pakete — `cargo` meldet `package ID specification 'ea-reader-wasm' did not match any packages`. `crates/ea-archive/tests/bundle_reader.rs` findet `ArchiveBundleSource` nicht, weil der Typ heute in `crates/ea-archive-fs/src/bundle.rs` steht. `--test workspace` faellt in `every_crates_member_is_classified_for_the_wasm32_gate`, sobald Schritt 3 die zwei Mitglieder eintraegt: solange sie fehlen, ist dieser Lauf GRUEN, und das ist kein Mangel dieses Schritts, sondern seine Aussage — die Doppelbindung des Zeugen wird erst durch den Mitgliedseintrag scharf. Genau deshalb muessen Mitgliedseintrag und Klassifikation in DIESEM Task zusammenfallen: derselbe Zeuge weist ein unklassifiziertes Mitglied unter `crates/` ab („is neither on the wasm32 positive list nor on the justified exception list") UND eine Klassifikation, die kein Mitglied benennt, UND eine Positivliste, die von der Kommandozeile des Stufe-1-Plans abweicht.

- [ ] **Step 3: Move the pure bundle reader, register both crates and grow the positive list once**

```rust
// crates/ea-reader/src/mode.rs — die einzige Aussage dieser Crate in dieser Stufe.
pub enum ReaderMode { Server, File }

impl ReaderMode {
    pub const ALL: [Self; 2] = [Self::Server, Self::File];
    pub const fn code(self) -> &'static str;
}

// crates/ea-reader/src/lib.rs
pub use ea_verify::GATE_ORDER_V1;
pub use mode::ReaderMode;

// crates/ea-reader-wasm/src/lib.rs — reine Funktion, duenner cfg-Export darueber.
#[must_use]
pub fn bridge_echo(value: &str) -> String;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(js_name = bridgeEcho)]
#[must_use]
pub fn bridge_echo_js(value: &str) -> String { bridge_echo(value) }

// crates/ea-archive/src/bundle.rs — verschoben, Signaturen unveraendert.
pub const BUNDLE_MAGIC_V1: [u8; 32];
pub const BUNDLE_HEADER_BYTES_V1: usize;
pub const BUNDLE_FILE_EXTENSION_V1: &str;
pub struct ArchiveBundleSource { /* bytes, index, payload_start */ }
impl ArchiveBundleSource {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, BundleError>;
    /// Frueher `pub(crate) fn bytes`. Der Zugriff WIRD oeffentlich, weil
    /// `write_archive_bundle` in `crates/ea-archive-fs` durch diesen Typ
    /// hindurch verifiziert und danach genau diese Bytes schreibt; ein zweiter
    /// Puffer daneben waere bei einem Bestand an der Obergrenze ein zweites
    /// Gigabyte und koennte abweichen. Er gibt nichts preis, was der Port nicht
    /// ohnehin herausgibt: `visit_blobs` liefert dieselben Nutzlastbytes
    /// stueckweise, und darueber liegen 48 Kopfbytes und ein Index aus Pfaden,
    /// Offsets und Laengen.
    pub fn container_bytes(&self) -> &[u8];
}
impl ArchiveSource for ArchiveBundleSource { /* unveraendert */ }

// crates/ea-archive-fs/src/bundle.rs — bleibt, wird zur freien Funktion.
pub fn open_archive_bundle(path: &Path) -> Result<ArchiveBundleSource, BundleError>;
fn open_archive_bundle_capped(path: &Path, cap: u64) -> Result<ArchiveBundleSource, BundleError>;
pub fn write_archive_bundle(
    source: &LocalPathBackend,
    anchor: &TrustAnchorV1,
    os_wall_clock: UnixMillis,
    target: &Path,
) -> Result<BundleExportReport, BundleError>;
```

Verschoben werden GENAU die Teile ohne Wirtsberuehrung: die drei Konstanten, `INDEX_RECORD_FIXED_BYTES`, `BundleIndexEntry`, `validate_bundle_path`, `read_u64`, `read_u64_raw`, `ArchiveBundleSource` samt `from_bytes` und `ArchiveSource`-Impl, und die vollstaendige `BundleError`-Aufzaehlung mit `code()`, `Display` und `Debug`. Zurueck bleiben in `crates/ea-archive-fs`: `MAX_BUNDLE_FILE_BYTES_V1`, die Laengenpruefung VOR dem Lesen, `write_archive_bundle`, `BundleExportReport`, `encode_bundle`, `sync_parent_directory` und `target_belongs_to_holding` — alles, was `std::fs::{metadata, read, File, OpenOptions}` anfasst. Die Reihenfolgenzusage von `open_archive_bundle_capped` — Deckel VOR dem Lesen, sonst legte eine uebergrosse Datei ihren Puffer vollstaendig an, bevor eine Regel sie abwiese — bleibt woertlich erhalten, samt ihrem privaten Einheitentest mit den zwei Deckeln 99 und 100.

`ArchiveBundleSource::open` verliert seine Form als inhaerente Methode, weil eine fremde Crate einem fremden Typ keine inhaerente Methode anhaengen kann. Der Ersatz ist die freie Funktion `open_archive_bundle` in derselben Crate, in der der Dateizugriff ohnehin lebt; die vier Aufrufstellen — `crates/ea-archive-fs/tests/bundle_reader.rs`, zweimal `crates/ea-archive-fs/tests/bundle_export.rs` und `tests/ea-system-tests/tests/e2e_writer_archive.rs` — ziehen mit. Ein Erweiterungstrait waere die Alternative und ist die schlechtere: er machte aus einer Funktion einen Import, den jeder Aufrufer zusaetzlich fuehren muesste, ohne eine einzige Zusage hinzuzufuegen.

`crates/ea-archive-fs/src/lib.rs` deklariert die fuenf Namen nicht neu, sondern re-exportiert sie: `pub use ea_archive::{ArchiveBundleSource, BUNDLE_FILE_EXTENSION_V1, BUNDLE_HEADER_BYTES_V1, BUNDLE_MAGIC_V1, BundleError};`. Das ist dieselbe Entscheidung, die `crates/ea-sync-client/src/lib.rs` mit `pub use ea_archive_fs::{DetailCause, SyncStatus};` schon getroffen hat und die der Ausnahmeeintrag von `ea-ui-contracts` in `WASM32_EXEMPT_CRATES` ausdruecklich als Muster nennt („re-exports the security enums … instead of re-declaring them"). Damit bleiben `apps/desktop/src-tauri/src/state.rs`, `apps/desktop/src-tauri/src/commands/writer.rs` und `crates/ea-archive-fs/tests/support/mod.rs` unveraendert: es entsteht EINE Deklaration mit zwei Pfaden und keine zweite Wahrheit. Der Stufe-2-Plan wird NICHT angefasst — er ist ein Ausfuehrungsprotokoll und beschreibt, wo Stufe 2 den Container abgelegt hat; seine eigene Schuldzeile („Making `ArchiveBundleSource` shared browser code belongs to Stage 4 together with the rest of the Reader") ist genau die Ermaechtigung fuer diesen Zug und wird durch ihn eingeloest.

`crates/ea-archive/Cargo.toml` gewinnt dabei KEINE Abhaengigkeit: `from_bytes` benutzt ausser `core` nur `MAX_ARCHIVE_BLOBS_V1` und `MAX_TOTAL_ARCHIVE_BYTES_V1` derselben Crate. `ea-archive` bleibt `std::fs`-frei; der Modulvertrag in `crates/ea-archive/src/source.rs` („Diese Crate enthaelt bewusst KEINE dateisystemgestuetzte Implementierung und kein `std::fs`") gilt nach dem Zug unveraendert und wird um den Container erweitert, nicht aufgeweicht.

Die drei Zuwaechse der Positivliste in `verify_quick_commands()` sind `ea-sync-protocol`, `ea-reader` und `ea-reader-wasm`. `ea-sync-protocol` verlaesst dabei `WASM32_EXEMPT_CRATES`; sein Eintrag hat den Vorbehalt selbst benannt („die Kollision zwischen web-reader-design.md:469 und dem eingefrorenen Satz … ist dort als Stage 4 Vorbehalt vermerkt und wird hier nicht aufgeloest"), und die Aufloesung ist gemessen und nicht argumentiert: `env -u RUSTFLAGS cargo check --target wasm32-unknown-unknown --locked -p ea-sync-protocol` endet ohne eine einzige Quelltextaenderung mit 0. `ea-reader` gehoert auf die Positivliste und DARF NICHT in die Ausnahmeliste: deren Doc-Kommentar nennt ihr Kriterium selbst — „A crate that reaches past `ea-verify` into the host operating system is not shared browser code and belongs here instead" —, und `ea-reader` ist nach web-reader-design.md §12 das genaue Gegenteil davon.

Der Kommentar ueber dem wasm32-Block wird EINMAL fuer die ganze Stufe umgeschrieben, und zwar nur sein zweiter Absatz. Der Satz „Diese Positivliste ist zeichengleich an die Kommandozeile des abgeschlossenen Stufe-1-Plans gebunden … und wird nicht erweitert" wird ersetzt durch: die Bindung an die Kommandozeile des Stufe-1-Plans BLEIBT und ist eine Mengengleichheit, durchgesetzt von `every_crates_member_is_classified_for_the_wasm32_gate`; die Liste WAECHST, wenn Browsercode dazukommt, weil web-reader-design.md §12 `ea-reader` wasm32-faehig macht; das Kriterium der Ausnahmeliste steht in deren eigenem Doc-Kommentar und schliesst Browsercode aus; und der Zuwachs geschieht in genau dem Task, der die Crate anlegt. Der ERSTE Absatz — die Reichweitenklausel „Belegt ausschliesslich UEBERSETZBARKEIT … steht aus" — wird hier NICHT angefasst: sie liegt zeichengleich als `WASM32_SCOPE_CLAUSE` in `tools/xtask/src/main.rs` und wird von `stage_one_documents` woertlich gegen `docs/traceability/stage-1-gate.md` geprueft, ein abgeschlossenes Ausfuehrungsprotokoll. Die Aufhebung der Blockade steht im Stufe-4-Plan und im Task „Stufe-4-Vorlauf: ADR 0005, wasm-Werkzeugpins und die aufgehobene Blockade", nicht in einem Stufe-1-Bericht.

Weil `assert_eq!(planned, positive_list)` im Block `G2` von `every_crates_member_is_classified_for_the_wasm32_gate` eine MENGENGLEICHHEIT ist und kein Praefix, wandert dieselbe Dreiergruppe in einem Zug in die Kommandozeile des Stufe-1-Plans (`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md`, die Zeile, die mit `cargo check --target wasm32-unknown-unknown --locked` beginnt). Diese Zeile MUSS also editiert werden; sie unberuehrt zu lassen ist keine Option und waere ein roter Zeuge. Das falscht auch kein Ausfuehrungsprotokoll, und die ehrliche Fassung dieses Satzes ist die folgende: die Zeile ist ein VERTRAG, den der Test mit der Quelle synchron haelt, kein Messwert eines gelaufenen Kommandos, und ihr Nachziehen ist der vorgesehene Mechanismus. Was in diesem Plan an Messwerten des Stufe-1-Laufs steht, wird davon nicht beruehrt: `verify_quick_block_in_stage_one_plan_matches_the_gate` in `tools/xtask/tests/spec_completeness.rs` assertiert zwei PRAEFIXE — das Argumentfragment `"check", "--target", "wasm32-unknown-unknown", "--locked"` und den Prosa-Praefix `cargo check --target wasm32-unknown-unknown --locked -p ea-types` —, und beide bleiben unter dem Anhaengen von drei `-p`-Paaren am Ende wahr. Die Bruecken-Crate traegt `crate-type = ["cdylib", "rlib"]`; sie darf auf die Positivliste, weil sie KEINEN Binaerzielpunkt hat — genau der Grund, aus dem `ea-ui-contracts` mit seinem `src/bin/emit-ts.rs` dort nicht stehen kann.

**Der zeichengenaue Pin von `verify_quick_commands()` wird MITGEZOGEN.** Die drei `-p`-Paare wandern nicht nur in die Funktion, sondern zeichengleich in den `assert_eq!`-Block des Unit-Tests `verify_quick_uses_the_required_locked_commands` in der `mod tests` von `tools/xtask/src/main.rs`. Dieser Test vergleicht den GANZEN Vektor und nicht ein Praefix; er faellt sofort, wenn nur eine der beiden Stellen waechst. Er liegt in einem BINAERZIEL — `tools/xtask` hat kein `[lib]`, `cargo test -p xtask --lib` antwortet gemessen mit `no library targets found in package \`xtask\`` —, also fahrt ihn `cargo test --locked -p xtask --bins` und KEIN `--test`-Ziel. Genau deshalb steht dieses Kommando in Schritt 4; ohne es liefe die Aufgabe gruen durch `--test workspace` und `--test spec_completeness` und liesse den Pin rot zurueck.

**Die Zaehlerkollision der abgeschlossenen Gate-Berichte wird HIER besessen und aufgeloest.** `wasm32_positive_list_count()` in `tools/xtask/tests/stage_gate.rs` zaehlt die `-p`-Paare am Pin LIVE, und `stage_three_gate_report_records_the_measured_full_gate_run` stellt diesen Wert gegen die ausgeschriebene Zahl in der Belegzeile `pnpm verify:quick` von `docs/traceability/stage-3-gate.md`; `verify_quick_subcommand_count()` tut dasselbe fuer `docs/traceability/stage-2-gate.md`. Beide Berichte sind ABGESCHLOSSENE Ausfuehrungsaufzeichnungen und DUERFEN NICHT umgeschrieben werden: `stage-2-gate.md` protokolliert `ACHT Teilkommandos gruen` und `stage-3-gate.md` `ACHT Teilkommandos` sowie `der wasm32-Check ueber die ZEHN Pakete der Positivliste`. Die Erweiterung der Positivliste von ZEHN auf DREIZEHN traefe zusaetzlich eine harte Grenze: die Nachschlagetabelle `const GERMAN_COUNT_WORDS: [&str; 13]` deckt die Indizes `0..=12`, und `GERMAN_COUNT_WORDS.get(13)` ist `None` — der Test PANIKT dann mit „13 is covered by no spelled-out number in GERMAN_COUNT_WORDS" statt eine Aussage zu treffen.

Aufgeloest wird das durch HISTORISCHE LITERALE und nicht durch eine gewachsene Tabelle: in `stage_two_gate_report_records_the_measured_full_gate_run` und `stage_three_gate_report_records_the_measured_full_gate_run` tritt an die Stelle des LIVE gezaehlten Wertes die Zahl, die der jeweilige Bericht TATSAECHLICH protokolliert — `"ACHT"` fuer die Teilkommandos beider Berichte, `"ZEHN"` fuer die wasm32-Pakete des Stufe-3-Berichts — mit einem Doc-Kommentar, der die Begruendung traegt: eine historische Messung ist eine Aussage ueber den Lauf, der sie erzeugt hat, und keine Aussage ueber eine spaetere Quelle; ein Bericht, den eine spaetere Stufe rot faerbt, misst nicht mehr sich selbst. Damit verlieren `verify_quick_subcommand_count()`, `wasm32_positive_list_count()` und `GERMAN_COUNT_WORDS` ihre einzigen Aufrufstellen; sie werden in DIESEM Task mitgeloescht, weil ein ungenutzter Helfer in einem Integrationstestziel `dead_code` meldet und `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` aus `verify_quick_commands()` daran rot wird. Die LIVE-Deckung uebernimmt der Stufe-4-Bericht: die Aufgabe „Reader-Interoperabilität, Browser-Matrix, Datei-Modus, Privatheit und das Stufe-4-Gate" legt beide Zaehler und die Zahlwortliste dort neu an, wo sie gegen einen Bericht DIESER Stufe stehen, und dimensioniert die Liste fuer die Stufe-4-Zahlen.

`Cargo.toml` gewinnt die zwei Mitglieder und die zwei Pfadkanten `ea-reader` und `ea-reader-wasm` in `[workspace.dependencies]`; `WORKSPACE_MEMBERS` in `tools/xtask/tests/workspace.rs` gewinnt dieselben zwei Pfade. Ein `=`-Pin wird hier NICHT erfunden: `wasm-bindgen = "=0.2.126"` steht bereits ratifiziert in der Wurzeltabelle, weil ADR 0005 vor der Benutzung ratifiziert und `tools/xtask/tests/adr_gate.rs` das erzwingt. Fehlt der Pin, ist dieser Task blockiert und nicht ermaechtigt, ihn beilaeufig einzutragen. Beide neuen Mitglieder fuehren KEINE `[target.'cfg(...)'.dependencies]`-Tabelle — der Manifestdurchlauf in `tools/xtask/tests/workspace.rs` iteriert nur ueber `dependencies`, `dev-dependencies` und `build-dependencies`, eine target-Tabelle bliebe fuer die Pin- und die `workspace = true`-Pflicht unsichtbar. Dev-Dependencies sind unbedenklich: die wasm32-Zeile faehrt ohne `--all-targets` und zieht sie nie in den Graphen, wie der Kommentar an `ea-archive`s `hex`-Dev-Kante bereits festhaelt.

- [ ] **Step 4: Run the grown wasm32 gate, the moved reader and every host consumer**

Run:

```bash
cargo metadata --format-version 1
cargo check --target wasm32-unknown-unknown --locked -p ea-types -p ea-cbor -p ea-crypto -p ea-format -p ea-schema -p ea-time -p ea-trust -p ea-archive -p ea-chain -p ea-verify -p ea-sync-protocol -p ea-reader -p ea-reader-wasm
cargo test --locked -p ea-archive -p ea-archive-fs -p ea-reader -p ea-reader-wasm
cargo test --locked -p xtask --bins --test workspace --test spec_completeness --test stage_gate
cargo test --locked -p ea-system-tests --test e2e_writer_archive
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

`cargo metadata --format-version 1` steht als ERSTE Zeile und ist das GENAU EINE Kommando dieses Tasks ohne `--locked`. Es steht hier und nicht in Schritt 2, weil erst Schritt 3 die zwei Mitglieder und die zwei Pfadkanten eingetragen hat: der Lockfile-Fortschritt MUSS nach der Registrierung und VOR den `--locked`-Kommandos laufen, sonst faellt jedes von ihnen an einem ueberholten `Cargo.lock`. `--bins` faehrt die `mod tests` von `tools/xtask/src/main.rs` und damit `verify_quick_uses_the_required_locked_commands`, den zeichengenauen Pin der drei angehaengten `-p`-Paare; `--test stage_gate` faehrt die zwei Berichtszeugen, deren LIVE-Zaehler dieser Task auf historische Literale umstellt.

Die zweite Zeile steht ohne `env -u RUSTFLAGS`, und das ist Absicht: sie ist zeichengleich das Gate-Kommando, und `env -u` gehoert an `build-wasm` des Vorlauf-Tasks, wo ein stehengebliebenes `--cfg getrandom_backend` aus `getrandom 0.3` das Merkmal `wasm_js` von `getrandom 0.4.3` ueberstimmen wuerde.

Expected: PASS. Dreizehn statt zehn Pakete uebersetzen fuer `wasm32-unknown-unknown`. Die Gegenprobe ist die eigentliche Aussage und laeuft ADVERSARIAL in sechs Zuegen: (1) `ea-reader` aus der Positivliste entfernen, ohne es in `WASM32_EXEMPT_CRATES` einzutragen — `every_crates_member_is_classified_for_the_wasm32_gate` faellt mit „is neither on the wasm32 positive list nor on the justified exception list"; (2) es in BEIDE Listen eintragen — derselbe Test faellt mit „exactly one classification is allowed"; (3) die Dreiergruppe nur in `tools/xtask/src/main.rs` und nicht in der Kommandozeile des Stufe-1-Plans nachfuehren — derselbe Test faellt an `assert_eq!(planned, positive_list)`; (4) `#[cfg(target_arch = "wasm32")]` ueber `bridge_echo_js` entfernen — `every_wasm_bindgen_export_sits_behind_the_wasm32_cfg` faellt, und er ist dabei die EINZIGE Instanz, die es merkt: der Wirtsbau faellt NICHT. Hier stand die Annahme „ohne den Zeugen faellt stattdessen der Wirtsbau von `cargo test --workspace --all-targets --locked`, also spaeter und unklarer“; sie ist in DIESEM Task WIDERLEGT und durch die Messung ersetzt. Mit entferntem cfg und sonst unveraendertem Baum enden `cargo build --locked -p ea-reader-wasm --lib`, `cargo test --locked -p ea-reader-wasm --all-targets --no-run` und `cargo clippy --locked -p ea-reader-wasm --all-targets --all-features -- -D warnings` alle drei mit 0 und ohne eine einzige Diagnose — `wasm-bindgen 0.2.126` uebersetzt sein Attribut auf einem Nicht-wasm-Ziel klaglos, sogar unter `#![forbid(unsafe_code)]`; nur der Zeuge selbst faellt (Exitcode 101). Fuer die acht Bruecken-Module der Aufgabe „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate“ heisst das: der Compiler warnt NICHT mit, ein vergessenes cfg faellt an diesem Zeugen oder gar nicht; (5) die drei `-p`-Paare nur in `verify_quick_commands()` und nicht im `assert_eq!`-Block daneben nachfuehren — `verify_quick_uses_the_required_locked_commands` faellt unter `--bins`, und ohne dieses Kommando bliebe der Bruch bis zum naechsten `pnpm verify:quick` unsichtbar; (6) die LIVE-Zaehler in den zwei Berichtszeugen stehen lassen — `--test stage_gate` faellt, und zwar `stage_three_gate_report_records_the_measured_full_gate_run` mit einer PANIK aus `GERMAN_COUNT_WORDS.get(13)` und `stage_two_gate_report_records_the_measured_full_gate_run` spaetestens, sobald die Aufgabe „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate" die Teilkommandos von acht auf zwoelf hebt. Der Umzug selbst ist gruen, wenn `crates/ea-archive-fs/tests/bundle_reader.rs` mit seinen fuenf Strukturmutationen unveraendert durchlaeuft — es mutiert einen ECHTEN Export aus `write_archive_bundle` und ist damit der Zeuge, den `crates/ea-archive` mangels Schreiber nicht fuehren kann.

- [ ] **Step 5: Commit the wasm32 reach before any Reader feature**

```bash
git add crates/ea-reader crates/ea-reader-wasm crates/ea-archive crates/ea-archive-fs tests/ea-system-tests tools/xtask docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md Cargo.toml Cargo.lock
git commit -m "feat(reader): make the shared browser cores reachable from wasm32"
```

### Task 3: `apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate

**Files:**
- Create: `apps/web/package.json`
- Create: `apps/web/index.html`
- Create: `apps/web/tsconfig.json`
- Create: `apps/web/vite.config.ts`
- Create: `apps/web/src/main.tsx`
- Create: `apps/web/src/test-setup.ts`
- Create: `apps/web/src/design/tokens.ts`
- Create: `apps/web/src/design/extract-static-css.tsx`
- Create: `apps/web/src/design/static-antd.css`
- Create: `apps/web/src/design/app.css`
- Create: `apps/web/src/design/icons.tsx`
- Create: `apps/web/src/bridge/generated-contracts.ts`
- Create: `apps/web/src/bridge/opfs-worker.ts`
- Create: `crates/ea-reader/src/blob_store.rs`
- Create: `crates/ea-reader-wasm/src/bridge.rs`
- Create: `crates/ea-reader-wasm/src/opfs_worker.rs`
- Create: `ops/compose/browsers.yaml`
- Modify: `crates/ea-reader/src/lib.rs`
- Modify: `crates/ea-reader/Cargo.toml`
- Modify: `crates/ea-reader-wasm/src/lib.rs`
- Modify: `crates/ea-reader-wasm/Cargo.toml`
- Modify: `crates/ea-types/src/status.rs`
- Modify: `crates/ea-verify/src/report.rs`
- Modify: `crates/ea-ui-contracts/src/lib.rs`
- Modify: `crates/ea-ui-contracts/src/emit.rs`
- Modify: `crates/ea-ui-contracts/src/bin/emit-ts.rs`
- Modify: `crates/ea-ui-contracts/Cargo.toml`
- Modify: `tools/xtask/src/main.rs`
- Modify: `pnpm-workspace.yaml`
- Modify: `package.json`
- Modify: `pnpm-lock.yaml`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `tools/xtask/tests/stage_gate.rs` — NUR gefahren, nicht geaendert; siehe Schritt 4
- Modify: `spikes/wasm-runtime-proof/README.md`
- Test: `apps/web/src/app/csp.test.ts`
- Test: `apps/web/src/bridge/no-hand-written-contracts.test.ts`
- Test: `apps/web/src/bridge/wasm-runtime.test.ts`
- Test: `apps/web/src/design/static-css.test.ts`
- Test: `crates/ea-reader/tests/blob_store.rs`
- Test: `crates/ea-reader-wasm/tests/opfs_browser.rs`
- Test: `crates/ea-ui-contracts/tests/generated_ts_is_current.rs`

**Interfaces:**
- Consumes: die Werkzeugpins und das Subkommando `build-wasm` samt seiner Vorpruefung `ensure_wasm_bindgen_cli_matches_lockfile()` aus dem Task „Stufe-4-Vorlauf: ADR 0005, wasm-Werkzeugpins und die aufgehobene Blockade"; die Crates `crates/ea-reader` und `crates/ea-reader-wasm` samt ihrer beiden wasm32-Positivlisteneintraege aus dem Task „wasm32-Reichweite: `ea-reader`, die Brücken-Crate und die geteilten Browserkerne"; `ea_crypto::{hpke_open, HpkeSealed, HpkeRecipientPrivateKey, SecretBytes, CanonicalPublicCoseKey}` und die eingefrorenen Bytes unter `vectors/crypto/suite-1/`; `ea_ui_contracts::emit_typescript` und die Driftschranke `the_checked_in_file_is_exactly_what_the_emitter_writes`.
- Produces: das pnpm-Paket `apps/web` mit gepinntem Lockfile-Eintrag, die CSP-Grundlinie mit `'wasm-unsafe-eval'`, `ReaderBlobStore` samt `InMemoryReaderBlobStore`, die OPFS-Implementierung im dedizierten Worker, `ea_ui_contracts::emit_reader_typescript` mit `apps/web/src/bridge/generated-contracts.ts` als zweitem Emitterausdruck, die zwei GEGATETEN Zeugen des Laufzeitnachweises und die vier neuen `apps/web`-Arme in `verify_quick_commands()`.

Dieser Task legt das Fundament und **keine Reader-Funktion**. Er liefert keine Verschluesselung, keinen Vault, keinen Service Worker, keinen `--release`-Bau und kein `wasm-opt` — jedes davon hat seinen benannten Besitzer weiter unten. Sein einziger inhaltlicher Ertrag ist, dass der Laufzeitnachweis aus `spikes/wasm-runtime-proof/` aufhoert, ausserhalb jedes Gates zu liegen: der Spike steht unter keinem `crates/`-Pfad, wird von `cargo deny` nicht erfasst und von `tools/xtask/tests/workspace.rs` nicht klassifiziert. Ein Nachweis, den kein Lauf faehrt, verfaellt still.

- [ ] **Step 1: Write the CSP, contract, static-CSS, blob-store, and runtime-witness tests**

`apps/web/src/app/csp.test.ts` pinnt die Richtlinie Position fuer Position, in genau der Bauform, die `apps/desktop/src/app/csp.test.ts` schon traegt — nur liest sie kein `tauri.conf.json`, sondern das `<meta http-equiv="Content-Security-Policy">` aus `apps/web/index.html`, weil der Browser-Reader keine Wirtkonfiguration hat:

```ts
const EXPECTED_DIRECTIVES = [
  "default-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self'",
  "style-src-elem 'self'",
  "style-src-attr 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "worker-src 'self'",
  "frame-src 'none'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
]

it('adds exactly one directive value beyond the desktop policy, and it is wasm-unsafe-eval', () => {
  const script = directives().find((directive) => directive.startsWith('script-src '))
  expect(script).toBe("script-src 'self' 'wasm-unsafe-eval'")
  expect(directives().join('; ')).not.toContain('unsafe-eval;')
  expect(directives().join('; ')).not.toContain("'unsafe-inline'; script")
})

it('keeps the OPFS worker reachable and admits no remote origin', () => {
  expect(directives()).toContain("worker-src 'self'")
  expect(directives().join('; ')).not.toMatch(/https?:/)
})
```

`apps/web/src/bridge/wasm-runtime.test.ts` ist der erste der zwei gegateten Zeugen. Er laedt das von `build-wasm` erzeugte Node-Ziel und fuehrt die vier Elemente aus `web-reader-design.md` §14.1 aus, die der Spike heute ausserhalb jedes Gates faehrt:

```ts
it('opens the frozen HPKE encapsulation and rejects both tampered vectors', async () => {
  const { readerRuntimeWitness } = await import('./pkg/ea_reader_wasm.js')
  const witness = JSON.parse(readerRuntimeWitness()) as RuntimeWitness
  expect(witness.targetTriple).toBe('wasm32-unknown-unknown')
  expect(witness.hpke.vectorFile).toBe('vectors/crypto/suite-1/hpke/base-mode-wrapped-cek.bin')
  expect(witness.hpke.recoveredContentEncryptionKey).toBe('c0'.repeat(32))
  expect(witness.hpke.rejectedTamperedVectors.flippedEncapsulatedKey).toBe('EA-CRYPTO-HPKE-OPEN')
  expect(witness.hpke.rejectedTamperedVectors.flippedWrappedCek).toBe('EA-CRYPTO-HPKE-OPEN')
})

it('verifies RFC 8032 test 1 and rejects the flipped signature', async () => {
  const { readerRuntimeWitness } = await import('./pkg/ea_reader_wasm.js')
  const witness = JSON.parse(readerRuntimeWitness()) as RuntimeWitness
  expect(witness.ed25519.acceptedValidSignature).toBe(true)
  expect(witness.ed25519.tamperedRejectionCode).toBe('EA-TRUST-SIGNATURE-INVALID')
})

it('draws entropy from the host and not from the module', async () => {
  const { readerRuntimeWitness } = await import('./pkg/ea_reader_wasm.js')
  const witness = JSON.parse(readerRuntimeWitness()) as RuntimeWitness
  expect(witness.getrandom.draw1).not.toBe(witness.getrandom.draw2)
  expect(witness.getrandom.freshSealsUsedDistinctEphemeralKeys).toBe(true)
  expect(witness.getrandom.largeDrawLength).toBe(100_000)
})

// Die Gegenkontrolle des Spikes, hier als Testfall statt als Ausgangswert eines
// Skripts: ohne Web Crypto MUSS getrandom scheitern. Sie traegt den staerksten
// Teil des Nachweises fuer Element 2.
it('fails closed when the host has no Web Crypto API', async () => {
  const saved = globalThis.crypto
  Reflect.deleteProperty(globalThis, 'crypto')
  try {
    const { readerRuntimeWitness } = await import('./pkg/ea_reader_wasm.js?no-webcrypto')
    expect(() => readerRuntimeWitness()).toThrow()
  } finally {
    Object.defineProperty(globalThis, 'crypto', { value: saved, configurable: true })
  }
})
```

`crates/ea-reader/tests/blob_store.rs` haelt den Port auf OPAKE Bytes fest — der Speicher darf nie erfahren, was in einem Blob steht:

```rust
#[test]
fn the_blob_store_round_trips_opaque_bytes_and_lists_its_keys() {
    let mut store = InMemoryReaderBlobStore::new();
    let key = ReaderBlobKey::new("vault/envelope-0").expect("a bounded ASCII key");
    assert_eq!(store.get(&key).unwrap(), None);
    store.put(&key, b"\x00\xff\x00opaque").unwrap();
    assert_eq!(store.get(&key).unwrap().as_deref(), Some(&b"\x00\xff\x00opaque"[..]));
    assert_eq!(store.keys().unwrap(), vec![key.clone()]);
    store.delete(&key).unwrap();
    assert_eq!(store.get(&key).unwrap(), None);
}

#[test]
fn a_blob_key_is_a_bounded_ascii_path_and_never_a_traversal() {
    for rejected in ["", "../escape", "vault/../../etc", "vault/\u{00e9}", &"a".repeat(129)] {
        assert!(ReaderBlobKey::new(rejected).is_err(), "{rejected} must be refused");
    }
}

// Der Port kennt keine Struktur. Waere er typisiert, waere er eine zweite Stelle,
// an der ueber Klartext entschieden wird.
//
// Die Verbotsliste nennt die FACHLICHEN Typnamen und nicht das blosse Wort
// `Entry`: die Ablage des Doppels ist eine `BTreeMap`, und deren idiomatische
// Einfuegeform heisst `std::collections::btree_map::Entry`. Ein Verbot auf
// `Entry` faerbte den Zeugen an einem Namen der Standardbibliothek rot, der
// mit Opazitaet nichts zu tun hat — ein Fehlalarm, der die Zusicherung
// entwertet, weil die naechste Person sie abschaltet statt sie zu lesen.
#[test]
fn the_port_exposes_no_typed_accessor() {
    let source = include_str!("../src/blob_store.rs");
    for forbidden in ["EntryHash", "EntryPackage", "EntryStatus", "Grant", "TrustAnchor", "Cek", "plaintext"] {
        assert!(!source.contains(forbidden), "blob_store.rs must stay opaque: {forbidden}");
    }
}
```

`crates/ea-reader-wasm/tests/opfs_browser.rs` ist der zweite gegatete Zeuge und der erste `wasm-bindgen-test` des Repositoriums. Er traegt `#![cfg(target_arch = "wasm32")]` in der ERSTEN Zeile — ohne das zoege `cargo test --workspace --all-targets --locked` dieses Ziel auf dem Wirt mit und faende dort weder `FileSystemSyncAccessHandle` noch einen Testlaeufer. **Diese Kopfzeile ist ab hier fuer JEDES `crates/ea-reader-wasm/tests/*_browser.rs` dieses Plans verbindlich**, also auch fuer `verify_browser.rs` aus der Aufgabe „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert" und `index_browser.rs` aus der Aufgabe „Verschlüsselter invertierter Index in OPFS, Suche, Schemakompatibilität und die GEMESSENE 50.000-Paket-Schwelle". Der Zeuge `every_wasm_bindgen_export_sits_behind_the_wasm32_cfg` durchlaeuft nur `src/` und faengt das NICHT; eine fehlende Kopfzeile faellt stattdessen im `pnpm verify:quick` des Gate-Tasks auf — an der spaetesten und teuersten Stelle:

```rust
#![cfg(target_arch = "wasm32")]

use ea_reader::{ReaderBlobKey, ReaderBlobStore};
use ea_reader_wasm::opfs_worker::OpfsBlobStore;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

// IM DEDIZIERTEN WORKER und nirgends sonst: `FileSystemSyncAccessHandle`
// existiert auf dem Hauptthread nicht. Eine Implementierung dort bestuende jeden
// Wirtstest und fiele erst im Browser.
wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[wasm_bindgen_test]
fn opfs_round_trips_the_same_bytes_the_in_memory_double_does() {
    let mut store = OpfsBlobStore::open("ea-reader-test").expect("OPFS must be reachable");
    let key = ReaderBlobKey::new("probe/opaque").unwrap();
    store.put(&key, b"\x00\xff\x00opaque").unwrap();
    assert_eq!(store.get(&key).unwrap().as_deref(), Some(&b"\x00\xff\x00opaque"[..]));
    store.delete(&key).unwrap();
    assert_eq!(store.get(&key).unwrap(), None);
}
```

`apps/web/src/bridge/no-hand-written-contracts.test.ts` ist die Portierung der gleichnamigen Desktop-Datei, Zeile fuer Zeile, mit `sourceRoot` auf `apps/web/src` und `generatedContracts` auf `apps/web/src/bridge/generated-contracts.ts`. Sie entsteht **vor der ersten Merkmalsquelle**: ihr Wert ist jeder spaetere Lauf, nicht dieser. `apps/web/src/design/static-css.test.ts` ist die Portierung von `apps/desktop/src/design/static-css.test.ts` und bekommt genau eine zusaetzliche Zusicherung, die die Desktop-Fassung nicht haben kann:

```ts
// Die sechs eingefrorenen Farben haben EINE Quelle, und sie liegt heute im
// Desktop-Paket. Ein pnpm-Kantenzug dorthin zoege den ganzen Tauri-Baustack in
// das Web-Paket, also wird die Gleichheit GELESEN statt importiert.
it('carries byte-identical colour literals to the desktop token file', () => {
  const web = readFileSync(path.join(sourceRoot, 'design/tokens.ts'), 'utf8')
  const desktop = readFileSync(
    path.resolve(sourceRoot, '../../desktop/src/design/tokens.ts'), 'utf8')
  const hexes = (text: string) => [...new Set(text.match(/#[0-9A-Fa-f]{6}/g) ?? [])].sort()
  expect(hexes(web)).toEqual(hexes(desktop))
  expect(hexes(web)).toHaveLength(6)
})
```

- [ ] **Step 2: Run the tests and verify that `apps/web`, the bridge, and the blob store are absent**

Run:

```bash
cargo test --locked -p ea-reader --test blob_store
cargo test --locked -p ea-ui-contracts --test generated_ts_is_current
pnpm --dir apps/web test --run
```

Expected: FAIL, und zwar dreifach verschieden. `ea-reader` kennt weder `ReaderBlobStore` noch `ReaderBlobKey` noch `InMemoryReaderBlobStore` — der Task „wasm32-Reichweite: `ea-reader`, die Brücken-Crate und die geteilten Browserkerne" hat die Crate mit `ReaderMode` und dem Re-Export von `ea_verify::GATE_ORDER_V1` angelegt und ausdruecklich ohne Rechnung. `generated_ts_is_current` kennt `emit_reader_typescript` nicht. Der dritte Lauf bricht ab, bevor er einen Test findet: `apps/web` steht nicht in `pnpm-workspace.yaml` und hat kein `package.json`. Genau deshalb faellt der Paketaufbau in Schritt 3 vor die Zeugen und nicht dahinter — der pnpm-Abbruch ist kein roter Test, sondern gar keiner.

- [ ] **Step 3: Build the package, the bridge, the opaque byte store, and the second emitter output**

**Das Paket.** `pnpm-workspace.yaml` bekommt `- apps/web` als zweiten Eintrag. `apps/web/package.json` waehlt jede Abhaengigkeit exakt, weil `.npmrc` `save-exact=true` und `engine-strict=true` setzt; die Auswahl ist die des Desktops MINUS `@tauri-apps/api` und `@tauri-apps/cli` — `react`, `react-dom`, `antd`, `@ant-design/static-style-extract`, `@phosphor-icons/react` zur Laufzeit, `typescript`, `vite`, `@vitejs/plugin-react`, `vitest`, `jsdom`, `@testing-library/*`, `@playwright/test`, `@types/*` zur Entwicklung. Die Skripte heissen `typecheck`, `build`, `test` und `e2e`, damit die Wurzelskripte dieselbe Form haben wie die des Desktops. `package.json` der Wurzel bekommt in diesem Task GENAU DREI Skripte — `"web:typecheck"`, `"web:test"` und `"web:browser-test"`. Letzteres faehrt `cargo test --locked -p ea-reader-wasm --target wasm32-unknown-unknown` und AUSDRUECKLICH KEIN `wasm-pack`: der Laeufer steht als `runner = "wasm-bindgen-test-runner"` unter `[target.wasm32-unknown-unknown]` in `.cargo/config.toml`, eingetragen von der Aufgabe „Stufe-4-Vorlauf: ADR 0005, wasm-Werkzeugpins und die aufgehobene Blockade". `wasm-pack` waere ein DRITTER, ungepinnter Traeger derselben `wasm-bindgen`-Schemafassung neben Crate und CLI und braechte einen eigenen `chromedriver` mit — es unterliefe genau den Pin, fuer den `the_wasm_bindgen_cli_pin_equals_the_locked_crate_version` und der Werkzeugpin in `mise.toml` existieren. Die `wasm-bindgen-test`-Ziele der Bruecke laufen deshalb ueber dieselbe EINE gepinnte CLI wie `build-wasm`; `"build:wasm"` steht seit dem Task „Stufe-4-Vorlauf: ADR 0005, wasm-Werkzeugpins und die aufgehobene Blockade" darin, und `"web:e2e"` entsteht im Task „Browser-Enrollment: zwei Pflicht-Authenticators und das nicht überspringbare Fingerprint-Gate", der als erster Playwright fahrt. `apps/web/vite.config.ts` kommt aus `vitest/config` und nicht aus `vite` — nur dieser Einstieg kennt den `test`-Schluessel, sonst faellt `pnpm --dir apps/web typecheck` mit TS2769 —, traegt `environment: 'jsdom'`, `setupFiles: ['./src/test-setup.ts']`, `include: ['src/**/*.test.{ts,tsx}']` und `execArgv: ['--no-experimental-webstorage']` aus demselben gemessenen Grund wie das Desktop-Pendant, und setzt `build.target: 'es2022'`, `assetsInlineLimit: 0`, `sourcemap: false`.

**Die Routentabelle entsteht HIER, und jede spaetere Flaeche haengt sich an sie.** `apps/web/src/main.tsx` liefert von Anfang an eine Routentabelle samt der Schale, die sie montiert — heute mit genau einem Eintrag `/`, der die leere Reader-Schale zeigt. Jede spaetere Aufgabe dieses Plans, die eine eigene Flaeche baut, HAENGT ihren Eintrag an diese Tabelle an und fuehrt `apps/web/src/main.tsx` deshalb als `Modify` in ihrem eigenen Files-Block: „Browser-Enrollment: zwei Pflicht-Authenticators und das nicht überspringbare Fingerprint-Gate" (`/enrollment`), „Web-Bundle: getrennter Origin, Service Worker, gepinnte `webBundleRelease` und das Alter des Trust-Standes" (der Trust-Alter-Streifen und die Registrierung des Service Workers), „Datei-Modus: Einzeldatei-Bündel, Verzeichnis-Handle, kein Cursor, `nicht server-bestätigt`" (`/datei`), „Sitzungssperre, Zeroize, authenticator-bestätigter Einzelexport und signiertes lokales Audit" (die Sichtbarkeits- und Eingabehaken der Sitzung) und „Integritätszentrierte Reader-Oberfläche in `apps/web` und die Rollengrenze zum Desktop" (`/` als volle Reader-Flaeche). Die Besitzverhaeltnisse sind damit ausgeschrieben und nicht stillschweigend: ohne den Eintrag laeuft der Playwright-Lauf der jeweiligen Aufgabe gegen eine Route, die niemand montiert hat.

**Die Richtlinie.** Der Desktop pinnt `script-src 'self'`; der Browser-Reader MUSS `'wasm-unsafe-eval'` dazunehmen, weil `WebAssembly.instantiate` sonst unter `default-src 'none'` blockiert. Das ist die EINZIGE Erweiterung gegenueber der Desktop-Grundlinie, und `worker-src 'self'` ist keine Erweiterung, sondern die Voraussetzung des OPFS-Workers. `connect-src` bleibt in diesem Task auf `'self'`, und der Task „Web-Bundle: getrennter Origin, Service Worker, gepinnte `webBundleRelease` und das Alter des Trust-Standes" ist der EINZIGE, der diesen Wert bewegt: er traegt die Herkunft des Sync-Servers ein UND zieht den Pin in `apps/web/src/app/csp.test.ts` im selben Commit nach. `apps/web/index.html` und `apps/web/src/app/csp.test.ts` stehen deshalb in SEINEM Files-Block; der Task „Inkrementeller Reader-Sync und verifizierter Cursor-Fortschritt in OPFS" fasst weder die Richtlinie noch ihren Pin an, obwohl er der erste Nutzer der Herkunft ist. Zwei Aufgaben, die denselben Richtlinienwert bewegen, waeren zwei Wahrheiten, und die zweite faerbte den Vitest-Lauf der ersten rot. Die Richtlinie steht als `<meta http-equiv>` und ist damit im gebauten Artefakt selbst nachlesbar; dass ein Header sie spaeter zusaetzlich traegt, entscheidet der Bundle-Task und nicht dieser.

**Der Bytespeicher.** `crates/ea-reader/src/blob_store.rs` traegt genau einen Port und ein Doppel:

```rust
/// Der Schluessel eines Blobs: ein beschraenkter ASCII-Pfad ohne Traversierung.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReaderBlobKey(String);

impl ReaderBlobKey {
    /// # Errors
    /// `EA-READER-BLOB-KEY` fuer leer, laenger als 128 Byte, nicht-ASCII,
    /// fuehrenden `/` oder ein `..`-Segment.
    pub fn new(value: &str) -> Result<Self, ReaderBlobError>;
    #[must_use]
    pub fn as_str(&self) -> &str;
}

/// Der Port ueber OPAKE Bytes.
///
/// Er kennt WEDER Struktur NOCH Bedeutung: jeder Aufrufer legt Chiffrat ab und
/// holt Chiffrat. Waere hier ein typisierter Zugriff, gaebe es eine zweite
/// Stelle, an der ueber Klartext entschieden wird — und `web-reader-design.md`
/// §9 laesst Kryptographie ausschliesslich in geteiltem Rust zu.
pub trait ReaderBlobStore {
    /// # Errors
    /// Jeder Fehlschlag des Wirtspeichers, ohne den Schluesselinhalt zu nennen.
    fn put(&mut self, key: &ReaderBlobKey, bytes: &[u8]) -> Result<(), ReaderBlobError>;
    /// # Errors
    /// Wie [`ReaderBlobStore::put`]. Ein fehlender Blob ist `Ok(None)`.
    fn get(&self, key: &ReaderBlobKey) -> Result<Option<Vec<u8>>, ReaderBlobError>;
    /// # Errors
    /// Wie [`ReaderBlobStore::put`]. Ein fehlender Blob ist kein Fehler.
    fn delete(&mut self, key: &ReaderBlobKey) -> Result<(), ReaderBlobError>;
    /// # Errors
    /// Wie [`ReaderBlobStore::put`]. Die Reihenfolge ist die Schluesselordnung.
    fn keys(&self) -> Result<Vec<ReaderBlobKey>, ReaderBlobError>;
}

/// Das Doppel, mit dem jeder spaetere `cargo test -p ea-reader` ohne Browser laeuft.
///
/// Bewusst NICHT hinter `cfg(test)` — dieselbe Entscheidung wie bei
/// `ea_verify::RecordingObserver`: die Integrationstests von `ea-reader` und die
/// Systemtests unter `tests/ea-system-tests` greifen darauf zu.
#[derive(Debug, Default)]
pub struct InMemoryReaderBlobStore { blobs: BTreeMap<ReaderBlobKey, Vec<u8>> }
```

Die Ablage ist eine `BTreeMap` und keine `HashMap`: `keys()` ist Teil des Contracts, und eine Streuordnung faellt in Unit-Tests nicht auf und kippt spaeter den Wiederaufbau des Index sporadisch — dieselbe Begruendung, die `crates/ea-verify/src/lib.rs` fuer seine Sammlungen ausschreibt.

**Der Worker.** `crates/ea-reader-wasm/src/opfs_worker.rs` implementiert `ReaderBlobStore` als `OpfsBlobStore` ueber `navigator.storage.getDirectory()`, `getFileHandle(name, { create: true })` und `createSyncAccessHandle()`. Der Zugriff ist SYNCHRON und existiert deshalb NUR im dedizierten Worker; eine Implementierung auf dem Hauptthread bestuende jeden Wirtstest und fiele erst im Browser. `apps/web/src/bridge/opfs-worker.ts` ist der Worker-Einstieg, der das wasm-Modul laedt und die drei Nachrichten `put`, `get`, `delete` an die Bruecke reicht; er enthaelt keine Entscheidung, nur Zustellung. Die dafuer benoetigten `web-sys`-Merkmale — `Navigator`, `WorkerNavigator`, `WorkerGlobalScope`, `StorageManager`, `FileSystemDirectoryHandle`, `FileSystemFileHandle`, `FileSystemSyncAccessHandle` — stehen in der aufgezaehlten Merkmalsliste von ADR 0005 und werden hier nicht zusaetzlich begruendet; steht eines nicht darin, ist das ein Fehlschlag des Tasks „Stufe-4-Vorlauf: ADR 0005, wasm-Werkzeugpins und die aufgehobene Blockade" und wird DORT nachgezogen, nicht hier still ergaenzt.

**Die Bruecke.** `crates/ea-reader-wasm/src/bridge.rs` ersetzt den Zeichenketten-Rundlauf des Vorgaengertasks durch die echte Flaeche. Alle Ausfuhren stehen unter `#[cfg(target_arch = "wasm32")]`, und jede gibt JSON heraus statt eines strukturierten Werts — TypeScript bekommt Ansichts- und Status-DTOs und nie ein Rechenobjekt:

```rust
/// Der Laufzeitzeuge nach `web-reader-design.md` §14.1, als JSON-Bericht.
///
/// Er ist die AUS dem Spike gehobene Fassung von
/// `spikes/wasm-runtime-proof/src/lib.rs::runtime_proof_json` und rechnet
/// unveraendert mit `ea_crypto::hpke_open` gegen
/// `vectors/crypto/suite-1/hpke/base-mode-wrapped-cek.bin` und mit
/// `CanonicalPublicCoseKey::verify_ed25519_strict` gegen
/// `vectors/crypto/suite-1/ed25519/rfc8032-test1.bin`. Die Vektoren sind per
/// `include_bytes!` einkompiliert: das Modul braucht kein Dateisystem.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerRuntimeWitness")]
#[must_use]
pub fn reader_runtime_witness() -> String;

/// Legt einen OPAKEN Blob ab. Wird ausschliesslich aus dem Worker gerufen.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "blobPut")]
pub fn blob_put(key: &str, bytes: &[u8]) -> Result<(), JsValue>;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "blobGet")]
pub fn blob_get(key: &str) -> Result<Option<Box<[u8]>>, JsValue>;
```

Die Erwartungswerte des Zeugen sind NICHT neu hergeleitet: sie stammen aus `vectors/crypto/suite-1/manifest.json` und aus den Konstanten von `ea-testkit`, die der native Test `tests/ea-system-tests/tests/conformance_golden_vectors.rs` benutzt. `ea-testkit` bleibt kein Abhaengiger — es steht in `WASM32_EXEMPT_CRATES` wegen seiner `std::fs`-Vektorausgabe —, also stehen die Konstanten woertlich mit Fundstellenangabe im Modul, genau wie im Spike.

**Die deutschen Begriffe entstehen in Rust, nicht in TypeScript.** `ea_types::VerificationStatus`, `ea_types::EntryStatus` und `ea_types::EvidenceStatus` fuehren heute ausschliesslich `code()` mit den Schemaliteralen `verified`, `gap`, `missingGrant`, `unknownKey`, `unsupportedSchema`, `invalid` beziehungsweise `present`, `authorizedDestroyed`, `unexplainedGap`; `ea_verify::ServerConfirmationV1` fuehrt `as_str()` mit `serverConfirmed`/`notServerConfirmed`. Die verbindlichen Oberflaechenbegriffe aus `design.md` §17.4 — `verifiziert`, `Lücke`, `fehlender Grant`, `unbekannter Schlüssel`, `nicht darstellbares Schema`, `ungültig`; `vorhanden`, `autorisiert vernichtet`, `ungeklärte Lücke`; `vollständig`, `ausstehend`, `überfällig`, `ungültig`; `server-bestätigt`, `nicht server-bestätigt` — existieren im Rust bisher NIRGENDS. Sie werden hier ADDITIV als `label()` an genau diese vier Aufzaehlungen gehaengt, in der Bauform, die `ea_archive_fs::SyncStatus::label()` seit Stufe 2 traegt. `code()` und `as_str()` bleiben zeichengleich, weil sie die JSON-Schemata unter `schemas/reports/v1/` tragen und `verification_report_expresses_quarantine_and_server_confirmation` in `tools/xtask/tests/spec_completeness.rs` gegen sie steht. Ohne diesen Schritt haette die Oberflaeche keine Quelle fuer ihre Statuswoerter ausser einer handgeschriebenen TypeScript-Liste — und genau die verbietet `no-hand-written-contracts.test.ts`.

**Der zweite Emitterausdruck.** `crates/ea-ui-contracts/src/lib.rs` bekommt `READER_ENUMS_V1` und die vier Re-Exporte, die es traegt — `ea_types::{VerificationStatus, EntryStatus, EvidenceStatus}` und `ea_verify::ServerConfirmationV1` —, plus die dafuer noetige Kante `ea-verify.workspace = true` in `crates/ea-ui-contracts/Cargo.toml`. Jede Variantenzuordnung ist ein `match` OHNE Sammelarm und ruft `label()`, sodass eine neue Variante in `ea-types` diese Crate nicht mehr uebersetzen laesst — dieselbe Uebersetzungszeitschranke, die `sync_status_literal` schon traegt. Die Richtung ist zulaessig und einseitig: `ea-ui-contracts` steht in `WASM32_EXEMPT_CRATES`, weil `src/bin/emit-ts.rs` Dateien schreibt, `ea-verify` steht auf der Positivliste, und keine Kante laeuft zurueck. `SECURITY_ENUMS_V1` und `WRITER_ENUMS_V1` bleiben UNVERAENDERT, und `emit_typescript()` schreibt Byte fuer Byte dieselbe Datei wie heute — `apps/desktop/src/bridge/generated-contracts.ts` aendert sich in diesem Task nicht. Der Grund ist gemessen und kein Geschmack: `apps/desktop/src/bridge/no-hand-written-contracts.test.ts` verbietet jeder handgeschriebenen Desktop-Quelle jedes Literal JEDER emittierten Vereinigung, und `ungueltig`, `vorhanden` oder `ausstehend` in die Desktop-Datei zu heben faerbte den Desktop-Zeugen rot, ohne dass eine Reader-Entscheidung dahinterstuende. `emit.rs` bekommt deshalb `pub fn emit_reader_typescript() -> String` mit demselben Kopf, derselben Determinismuszusage und denselben vier Formregeln, und `src/bin/emit-ts.rs` schreibt beide Ziele in einem Lauf.

`crates/ea-ui-contracts/tests/generated_ts_is_current.rs` bekommt die vier Zusagen ein zweites Mal ueber der Reader-Datei: sie IST der Emitterausdruck, zwei Laeufe sind byteidentisch, jede Vereinigung traegt die Varianten ihrer Rustdefinition in Deklarationsreihenfolge, und die Datei deklariert und rechnet nicht. Der EINE nicht zirkulaere Anker der Reader-Haelfte sind die sechs Verifikationsbegriffe aus `design.md` §17.4, hier als Text gepinnt: `verifiziert`, `Lücke`, `fehlender Grant`, `unbekannter Schlüssel`, `nicht darstellbares Schema`, `ungültig`.

**Die vier Arme.** `verify_quick_commands()` in `tools/xtask/src/main.rs` bekommt, unmittelbar hinter dem Block `pnpm desktop:test` und VOR den langen Cargo-Kommandos, in dieser Reihenfolge:

```rust
("cargo", vec!["run", "--locked", "-p", "xtask", "--", "build-wasm"]),
("pnpm", vec!["--dir", "apps/web", "build"]),
("pnpm", vec!["web:typecheck"]),
("pnpm", vec!["web:test"]),
```

**Der Browsercontainer entsteht HIER, weil hier der `@playwright/test`-Pin entsteht, an den seine Abbildfassung gebunden ist.** `ops/compose/browsers.yaml` folgt `ops/compose/integration.yaml` Zeile fuer Zeile: ein Dienst, das Abbild mit Tag UND gemessenem Digest, die Laufzeit gepinnt ueber `EA_CONTAINER_RUNTIME` aus `mise.toml`. Es fuehrt BEIDE Traeger, die diese Stufe braucht — die drei Playwright-Engine-Baus fuer `pnpm web:e2e` und einen `chromedriver` fuer `wasm-bindgen-test-runner` —, weil ein reines Playwright-Abbild nur das erste liefert. `tools/xtask/src/main.rs` bekommt dazu `browsers up` und `browsers down` in der Gestalt von `integration up`/`down`, samt `ensure_browser_services_available()` nach dem Muster von `ensure_integration_services_available()`: FAIL-CLOSED vor dem betroffenen Kommando, mit einer Anweisung statt eines Folgefehlers tief im Treiberprotokoll. Ein Ueberspringen ueber eine Umgebungsvariable ist AUSGESCHLOSSEN, wie bei den Integrationsdiensten.

Der Digest wird in Schritt 4 GEMESSEN und nicht behauptet — `docker image inspect` auf das gezogene Abbild —, genau wie Stufe 3 ihre zwei Bilddigests gemessen hat; der Plan traegt die QUELLE der Zahl und nicht die Zahl. Die Abbildfassung MUSS zur `@playwright/test`-Fassung aus `apps/web/package.json` passen: Playwright weist Engine-Baus fremder Fassung zurueck, und zwei Fassungen derselben Sache sind die erste, die still driftet — dieselbe Begruendung, aus der `wasm-bindgen` Crate und CLI zeichengleich gepinnt sind.

Weder `browsers up` noch `browsers down` treten in `verify_quick_commands()` ein. Der Schnelllauf bleibt frei von Containervoraussetzungen fuer den Browser, aus demselben Grund, aus dem `desktop:e2e` seit Stufe 2 draussen steht; `pnpm verify:quick` braucht seine eigene Klammer `integration up` … `integration down` und keine zweite.

`build-wasm` steht zuerst, weil `apps/web/src/bridge/pkg/` sein Ausgang ist und sowohl der Vite-Bau als auch `wasm-runtime.test.ts` daraus importieren; ohne den Vorlauf bricht der Bau mit einem nicht aufloesbaren Modul ab, statt zu pruefen — dieselbe Ordnungsentscheidung, die den Desktop-Bau schon vor die Cargo-Kommandos setzt. `pnpm web:browser-test` und das spaeter entstehende `pnpm web:e2e` stehen hier AUSDRUECKLICH NICHT: Playwright verlangt installierte Browser, und der `wasm-bindgen-test` verlangt einen `chromedriver` — beides waere eine neue Voraussetzung fuer jeden Schnelllauf, und es ist genau die Begruendung, aus der `desktop:e2e` seit Stufe 2 draussen steht. Ihre benannte Folge ist die Kommandoliste des Tasks „Reader-Interoperabilität, Browser-Matrix, Datei-Modus, Privatheit und das Stufe-4-Gate". Der Unit-Test `verify_quick_uses_the_required_locked_commands` in der `mod tests` desselben `main.rs` wird zeichengleich nachgezogen — er vergleicht den GANZEN Kommandovektor und faellt sofort, wenn nur eine der beiden Stellen waechst; gefahren wird er ueber `cargo test --locked -p xtask --bins`, weil `tools/xtask` kein `[lib]` hat. Er ist zugleich der zeichengenaue Pin, an dem die Zaehler des Stufe-4-Gate-Berichts spaeter Teilkommandos und wasm32-Pakete abzaehlen; in den abgeschlossenen Berichten der Stufen 2 und 3 stehen an dieser Stelle seit der Aufgabe „wasm32-Reichweite: `ea-reader`, die Brücken-Crate und die geteilten Browserkerne" historische Literale.

**Die Zaehlerkollision, benannt und bereits besessen.** Die Zahl der Teilkommandos steigt durch diesen Task von ACHT auf ZWOELF. `stage_two_gate_report_records_the_measured_full_gate_run` und `stage_three_gate_report_records_the_measured_full_gate_run` in `tools/xtask/tests/stage_gate.rs` verglichen diese Zahl bis zur Aufgabe „wasm32-Reichweite: `ea-reader`, die Brücken-Crate und die geteilten Browserkerne" LIVE gegen die ausgeschriebene Zahl in der Belegzeile `pnpm verify:quick` von `docs/traceability/stage-2-gate.md` beziehungsweise `stage-3-gate.md`; beide Zeilen tragen `ACHT Teilkommandos` und sind GEMESSENE Laeufe mit Exitcode, Ergebniszeilen und Laufzeit. Die Berichte werden NICHT umgeschrieben — das waere die Faelschung eines Ausfuehrungsprotokolls, und das Repositorium tut das nicht. Der Bruch ist deshalb DORT aufgeloest worden und nicht hier: jene Aufgabe hat die LIVE-Vergleiche gegen die historischen Literale `"ACHT"` und `"ZEHN"` getauscht und die drei ungenutzt gewordenen Helfer entfernt. Dieser Task aendert `tools/xtask/tests/stage_gate.rs` deshalb NICHT; er FAEHRT das Ziel in Schritt 4 mit, damit die Anhebung von acht auf zwoelf nicht doch eine Zusicherung trifft, die niemand vorhergesehen hat. Die Live-Deckung der Zahlen uebernimmt der Stufe-4-Bericht in der Aufgabe „Reader-Interoperabilität, Browser-Matrix, Datei-Modus, Privatheit und das Stufe-4-Gate".

**Der Spike wird zur Fussnote, und die Bilanz der fuenf Grenzen wird EXAKT gezogen.** `spikes/wasm-runtime-proof/README.md` bekommt einen Abschnitt „Abgeloest": der Nachweis lebt ab diesem Task in `crates/ea-reader-wasm/src/bridge.rs` und in den zwei gegateten Zeugen; `spike.sh` bleibt als HISTORISCHER Beleg des Laufs vom 2026-08-30 stehen und wird nicht geloescht.

GENAU EINE der fuenf benannten Grenzen faellt hier, die Grenze 1: `pnpm web:browser-test` faehrt `opfs_browser.rs` in Headless-Chromium, es gibt also einen Browserlauf. Grenze 3 faellt NICHT, sie VERSCHIEBT sich, und der Unterschied ist der ganze Punkt: ab diesem Task fuehrt neben `ea-crypto` auch `crates/ea-reader-wasm` selbst etwas aus — die Bruecke und der OPFS-Zeuge laufen im Browser. `ea-verify`, `ea-archive`, `ea-chain`, `ea-format` und `ea-trust` uebersetzen weiterhin nur und laufen nirgends; der Satz „ausser `ea-crypto` fuehrt keine Crate etwas aus" ist ab diesem Task FALSCH und wird deshalb hier nicht wiederholt. Drei Grenzen bleiben offen und werden ausdruecklich NICHT behauptet: Grenze 2 — kein `--release`-Bau und kein `wasm-opt` — bleibt bis Stufe 7 offen und steht dort in der Spalte `offen in spaeterer Stufe` des Stufe-4-Gate-Berichts; Grenze 4 — keine COSE-Kette — loest der Task „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert" ein, wo `parse_cose_sign1` erstmals gegen ein echtes Archiv laeuft; Grenze 5 — keine RNG-Statistik, nur Anwesenheitsproben — bleibt in dieser Stufe UNBERUEHRT: `wasm-runtime.test.ts` wiederholt die Lebendigkeitsproben des Spikes und fuegt keinen statistischen Test hinzu.

Die SECHSTE Tatsache ist keine Grenze, sondern die Lage des Nachweises, und sie aendert sich hier separat: der Spike lag ausserhalb jedes Gates; ab diesem Task steht das ausgefuehrte Modul unter `crates/` und wird von einem Lauf gefahren. Das loest keine der fuenf Grenzen ein und wird nicht als solche gezaehlt.

`.gitignore` traegt die Zeile `pkg/` bereits seit der Aufgabe „Stufe-4-Vorlauf: ADR 0005, wasm-Werkzeugpins und die aufgehobene Blockade" — sie musste DORT fallen, weil dieselbe Aufgabe den Spike samt seinem `pkg/`-Verzeichnis erstmals versioniert; dieser Task ergaenzt sie nicht ein zweites Mal, und der Ausgang von `build-wasm` unter `apps/web/src/bridge/pkg/` ist von derselben Zeile gedeckt. `Cargo.toml` und `Cargo.lock` wachsen um die Merkmale, die `crates/ea-reader-wasm` fuer `web-sys` und `wasm-bindgen-test` braucht; weil dieser Task `Cargo.lock` fortschreibt, laeuft GENAU EIN Kommando ohne `--locked` — `cargo metadata --format-version 1` —, jedes andere traegt es weiter, wie die Lockfile-Regel in `workspace_declares_exact_planned_members_and_shared_dependencies` es verlangt. `wasm-bindgen-test` MUSS als Entwicklungsabhaengigkeit exakt in `[workspace.dependencies]` stehen und in ADR 0005 ratifiziert sein: `workspace_declares_exact_planned_members_and_shared_dependencies` durchlaeuft `dev-dependencies` mit derselben Strenge wie `dependencies`.

- [ ] **Step 4: Run the two gated witnesses, the browser run, and the whole quick gate**

Run:

```bash
cargo metadata --format-version 1
cargo run --locked -p xtask -- build-wasm
cargo test --locked -p ea-types -p ea-verify
cargo test --locked -p ea-reader --test blob_store
cargo test --locked -p ea-ui-contracts --test generated_ts_is_current
cargo test --locked -p xtask --bins --test stage_gate
pnpm --dir apps/web typecheck
pnpm --dir apps/web test --run
cargo run --locked -p xtask -- browsers up
pnpm web:browser-test
cargo run --locked -p xtask -- browsers down
cargo run --locked -p xtask -- integration up
pnpm verify:quick
cargo run --locked -p xtask -- integration down
```

`cargo metadata --format-version 1` steht als ERSTE Zeile und ist das GENAU EINE Kommando dieses Tasks ohne `--locked`: Schritt 3 hat `crates/ea-reader-wasm` neue Merkmale fuer `web-sys` und die Entwicklungskante `wasm-bindgen-test` gegeben, und `Cargo.lock` schreibt darauf fort. Es steht VOR jedem `--locked`-Kommando, sonst faellt das erste von ihnen an einem ueberholten Lockfile. `cargo test --locked -p xtask --bins --test stage_gate` faehrt den zeichengenauen Pin `verify_quick_uses_the_required_locked_commands` — er liegt in der `mod tests` des BINAERZIELS `tools/xtask/src/main.rs`, weshalb `--bins` und nicht `--lib` (`tools/xtask` hat kein `[lib]`) — und die zwei Berichtszeugen, deren LIVE-Zaehler die Aufgabe „wasm32-Reichweite: `ea-reader`, die Brücken-Crate und die geteilten Browserkerne" bereits auf historische Literale umgestellt hat. Diese Aufgabe hebt die Teilkommandos von acht auf zwoelf; ohne diesen Lauf bliebe unbelegt, dass die Umstellung traegt.

Expected: PASS. `readerRuntimeWitness()` gewinnt in Node den eingefrorenen CEK `0xc0`×32 aus `base-mode-wrapped-cek.bin` zurueck, weist beide verfaelschten HPKE-Vektoren mit `EA-CRYPTO-HPKE-OPEN` ab, nimmt RFC 8032 §7.1 TEST 1 an und weist `flipped-signature.bin` mit `EA-TRUST-SIGNATURE-INVALID` ab; ohne `globalThis.crypto` wirft derselbe Aufruf. `pnpm web:browser-test` faehrt `opfs_browser.rs` in Headless-Chromium: derselbe Bytesatz, den das Doppel im Speicher liefert, ueberlebt Schreiben und Lesen ueber einen `FileSystemSyncAccessHandle`. Es steht in der Klammer `browsers up` … `browsers down`, weil der `wasm-bindgen-test-runner` einen `chromedriver` voraussetzt und dieser Plan ihn nach ADR 0005 aus dem gepinnten Abbild bezieht und nicht vom Wirt. Die adversariellen Faelle, die in diesem Lauf rot werden MUESSEN und einzeln zu pruefen sind: ein `script-src` ohne `'wasm-unsafe-eval'` laesst `WebAssembly.instantiate` unter `default-src 'none'` scheitern; ein `OpfsBlobStore`, der auf dem Hauptthread gebaut wird, faellt an `createSyncAccessHandle`; eine handgeschriebene `apps/web`-Quelle, die eines der sechs Verifikationsliterale wiederholt, faellt in `no-hand-written-contracts.test.ts`; ein von Hand editiertes `apps/web/src/bridge/generated-contracts.ts` faellt in `generated_ts_is_current.rs`; und ein `wasm-bindgen-cli`, dessen Version vom Repo-`Cargo.lock` abweicht, bricht schon in `ensure_wasm_bindgen_cli_matches_lockfile()` ab, bevor irgendetwas gebaut wird. Das Kommando `pnpm verify:quick` steht in der Klammer `integration up` … `integration down`, weil `cargo test --workspace --all-targets --locked` die Integrationstestziele von `apps/server` und `crates/ea-sync-server` mitzieht und `#[sqlx::test]` `DATABASE_URL` zur Laufzeit liest.

- [ ] **Step 5: Commit the web package, the bridge, and the gated runtime proof**

```bash
git add apps/web ops/compose/browsers.yaml crates/ea-reader crates/ea-reader-wasm crates/ea-ui-contracts \
        crates/ea-types crates/ea-verify \
        tools/xtask pnpm-workspace.yaml package.json pnpm-lock.yaml \
        Cargo.toml Cargo.lock spikes/wasm-runtime-proof/README.md
git commit -m "feat(web): add the apps/web package, the wasm-bindgen bridge, and the gated runtime proof"
```

### Task 4: Browser-Vault: PRF-Envelopes, Schlüsselprofil und die Verwahrung von Anchor und KEM-Schlüssel (formerly Task 1)

**Files:**
- Create: `crates/ea-reader/src/vault.rs`
- Create: `crates/ea-reader/src/envelope.rs`
- Create: `crates/ea-reader/src/key_profile.rs`
- Create: `crates/ea-reader/src/cache.rs`
- Create: `crates/ea-reader/src/entry_state.rs`
- Create: `crates/ea-reader-wasm/src/vault_bridge.rs`
- Test: `crates/ea-reader/tests/vault_envelope.rs`
- Test: `crates/ea-reader/tests/key_profile.rs`
- Test: `crates/ea-reader/tests/cache_canaries.rs`
- Modify: `crates/ea-reader/src/lib.rs`
- Modify: `crates/ea-reader-wasm/src/lib.rs`
- Modify: `crates/ea-reader/Cargo.toml`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `docs/adr/0005-browser-runtime-and-wasm-dependency-class.md`
- Modify: `tools/xtask/tests/adr_gate.rs`
- Modify: `tools/xtask/tests/workspace.rs`

**Interfaces:**
- Consumes: der opake Byteport `ReaderBlobStore` mit `ReaderBlobKey`, `ReaderBlobError` und dem Doppel `InMemoryReaderBlobStore` aus der Aufgabe „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate"; `ea_crypto::{aead_seal, aead_open, SecretBytes, SecretVec, CEK_SIZE, AEAD_NONCE_SIZE, AEAD_OVERHEAD, CanonicalPublicCoseKey, HpkeRecipientPrivateKey, CryptoError}`; `ea_trust::{TrustAnchorV1, decode_trust_anchor, RegistryHeadPin, TrustError}`; `ea_format::{DeviceCertificateFieldsV1, CertificateKindV1}`; `ea_types::{ObjectHash, EntryHash, ChainSequence, KeyThumbprint, RegistryVersion, VerificationStatus, EntryStatus}`; `ea_verify::ServerConfirmationV1`; ADR 0005 und sein `ratified before use`-Gate aus der Aufgabe „Stufe-4-Vorlauf: ADR 0005, wasm-Werkzeugpins und die aufgehobene Blockade".
- Produces: `ReaderVault::{seal, unlock}`, `derive_kek_v1`, `VAULT_KEK_INFO_V1`, `VAULT_INDEX_INFO_V1`, `AuthenticatorPrfV1`, `VaultEnvelopeV1::{wrap, unwrap}`, `VaultEnvelopeV1`, `SealedVaultV1`, `VaultContentsV1`, `UnlockedVault::{kem_private_key, kem_key_thumbprint, audit_signing_key, sign_audit_digest, pinned_anchor, pinned_anchor_bytes, last_registry_pin, index_key}`, `ReaderKeyProfile::validate` mit `EA-KEY-ROLE-COLLISION`, `ReaderObjectCache::{put_exact_object, get_exact_object}`, `ReaderEntryStateStore::{put_entry_state, get_entry_state}` und die DEKLARATION von `ReaderEntryStateV1`.

Diese Aufgabe ersetzt den nativen Reader-Key-Provider und die SQLCipher-Ablage der Vorfassung durch den Browser-Tresor aus `web-reader-design.md` §6.1/§6.2. §11.3 streicht den nativen Reader-Key-Provider ERSATZLOS: die Zusagen an Nicht-Roaming und Backup-Ausschluss gelten sinngemaess fuer den Tresor — Wrapped-Blobs sind ohne Authenticator wertlos, Klartextschluessel werden nie persistiert. `docs/adr/0002-local-database-encryption.md` wird NICHT angefasst; der Writer bleibt auf SQLCipher, und `crates/ea-local-store/migrations/0002_reader.sql` aus der Vorfassung entsteht in dieser Stufe ueberhaupt nicht.

Diese Aufgabe steht VOR jeder Verifikation, und das ist eine Reihenfolge, keine Bequemlichkeit: sie besitzt die EINGABEN von Gate `trust` (den gepinnten Anchor) und von Gate `recipient-grant` samt der nachfolgenden Entkapselung (den privaten X25519-Empfaengerschluessel). `ea_verify::VerifyOptions::with_recipient` nimmt `&HpkeRecipientPrivateKey`, und `ea_verify::verify_archive_observed` nimmt `&TrustAnchorV1` als Parameter — beide Werte entstehen ausschliesslich hier.

Nicht Gegenstand: WebAuthn selbst (die PRF-Zeremonie und die Zwei-Authenticator-Pflicht aus §6.3 gehoeren der Aufgabe „Browser-Enrollment: zwei Pflicht-Authenticators und das nicht überspringbare Fingerprint-Gate"), Sperrfristen und `zeroize`-Zeitpunkte (Aufgabe „Sitzungssperre, Zeroize, authenticator-bestätigter Einzelexport und signiertes lokales Audit"), und die Klassifikation eines Eintrags (Aufgabe „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert"). Hier entsteht der SPEICHER des Zustands, nicht sein Urteil.

- [x] **Step 1: Write the role-collision, envelope, and cache-canary witnesses**

```rust
// crates/ea-reader/tests/key_profile.rs
#[test]
fn reader_requires_distinct_kem_and_authentication_keys() {
    let collided = fixtures::reader_certificate_with_one_key_in_both_roles();
    assert_eq!(
        ReaderKeyProfile::validate(&collided).unwrap_err().code(),
        "EA-KEY-ROLE-COLLISION"
    );

    let profile = ReaderKeyProfile::validate(&fixtures::reader_certificate()).unwrap();
    assert!(matches!(
        profile.kem_public_key(),
        CanonicalPublicCoseKey::X25519(_)
    ));
    assert!(matches!(
        profile.signing_public_key(),
        CanonicalPublicCoseKey::Ed25519(_)
    ));
    assert_ne!(profile.kem_key_thumbprint(), profile.signing_key_thumbprint());

    for wrong in [
        fixtures::reader_certificate_without_kem_key(),
        fixtures::reader_certificate_without_signing_key(),
        fixtures::writer_certificate(),
    ] {
        assert!(ReaderKeyProfile::validate(&wrong).is_err());
    }
}
```

```rust
// crates/ea-reader/tests/vault_envelope.rs
#[test]
fn the_prf_output_never_wraps_the_vault_and_each_authenticator_opens_it_alone() {
    let first = [0xa1_u8; 32];
    let second = [0xb2_u8; 32];
    let sealed = ReaderVault::seal(
        fixtures::vault_contents(),
        &[
            AuthenticatorPrfV1::new(fixtures::credential_id(1), SecretBytes::new(first)),
            AuthenticatorPrfV1::new(fixtures::credential_id(2), SecretBytes::new(second)),
        ],
    )
    .unwrap();

    assert_eq!(sealed.envelopes().len(), 2);
    for envelope in sealed.envelopes() {
        for raw in [first, second] {
            assert!(
                !ea_testkit::contains_canary(envelope.wrapped_vault_key(), &raw),
                "die PRF-Ausgabe DARF NICHT selbst der Wrapping-Schluessel sein"
            );
        }
    }

    for (index, raw) in [(1_u8, first), (2, second)] {
        let unlocked = ReaderVault::unlock(
            &sealed,
            &AuthenticatorPrfV1::new(fixtures::credential_id(index), SecretBytes::new(raw)),
        )
        .unwrap();
        assert_eq!(
            unlocked.pinned_anchor().trust_anchor_hash(),
            fixtures::pinned_anchor().trust_anchor_hash()
        );
        assert_eq!(
            unlocked.kem_private_key().public_key().as_bytes(),
            fixtures::reader_kem_public_key().as_bytes()
        );
        assert_eq!(
            unlocked.last_registry_pin().map(RegistryHeadPin::registry_version),
            Some(RegistryVersion::new(7))
        );
    }

    // Ein geloeschter Passkey kostet einen Entsperrweg und nie die Daten.
    let reduced = sealed.without_credential(fixtures::credential_id(1)).unwrap();
    assert_eq!(reduced.envelopes().len(), 1);
    assert!(
        ReaderVault::unlock(
            &reduced,
            &AuthenticatorPrfV1::new(fixtures::credential_id(2), SecretBytes::new(second)),
        )
        .is_ok()
    );
    assert_eq!(
        ReaderVault::unlock(
            &reduced,
            &AuthenticatorPrfV1::new(fixtures::credential_id(1), SecretBytes::new(first)),
        )
        .unwrap_err()
        .code(),
        "EA-READER-VAULT-NO-ENVELOPE"
    );
}

#[test]
fn a_flipped_envelope_byte_and_a_substituted_anchor_both_refuse() {
    let sealed = fixtures::sealed_vault();
    let prf = fixtures::authenticator(1);

    let mut tampered = sealed.clone();
    tampered.flip_one_wrapped_key_byte_for_test(fixtures::credential_id(1));
    assert_eq!(
        ReaderVault::unlock(&tampered, &prf).unwrap_err().code(),
        "EA-CRYPTO-AEAD-OPEN"
    );

    // Der Anchor wird beim Entsperren NEU dekodiert, nicht geglaubt.
    let mut foreign = sealed.clone();
    foreign.replace_sealed_anchor_bytes_for_test(fixtures::foreign_anchor_exact_bytes());
    assert_eq!(
        ReaderVault::unlock(&foreign, &prf).unwrap_err().code(),
        "EA-TRUST-ANCHOR-HASH"
    );

    assert_eq!(
        ReaderVault::seal(fixtures::vault_contents(), &[])
            .unwrap_err()
            .code(),
        "EA-READER-VAULT-NO-AUTHENTICATOR"
    );
}
```

```rust
// crates/ea-reader/tests/cache_canaries.rs
#[test]
fn exact_objects_and_entry_states_are_never_plaintext_in_the_blob_store() {
    let mut store = InMemoryReaderBlobStore::default();
    let unlocked = fixtures::unlocked_vault();
    let cache = ReaderObjectCache::open(&unlocked);
    let states = ReaderEntryStateStore::open(&unlocked);

    let bytes = fixtures::entry_package_bytes_carrying(b"CANARY-PERSON");
    let object_hash = cache.put_exact_object(&mut store, &bytes).unwrap();
    states
        .put_entry_state(&mut store, &fixtures::missing_grant_state())
        .unwrap();

    for key in store.keys().unwrap() {
        let raw = store.get(&key).unwrap().unwrap();
        assert!(!ea_testkit::contains_canary(&raw, &bytes));
        assert!(!ea_testkit::contains_canary(&raw, b"CANARY-PERSON"));
        assert!(!ea_testkit::contains_canary(&raw, b"missingGrant"));
        assert!(!ea_testkit::contains_canary(&raw, b"fehlender Grant"));
    }

    // Positivkontrolle: der Marker war wirklich im System.
    assert_eq!(cache.get_exact_object(&store, object_hash).unwrap(), Some(bytes));
    assert_eq!(
        states.get_entry_state(&store, fixtures::entry_hash()).unwrap(),
        Some(fixtures::missing_grant_state())
    );

    // Ein zweiter Tresor oeffnet denselben Speicher nicht.
    let other = ReaderObjectCache::open(&fixtures::second_unlocked_vault());
    assert_eq!(
        other.get_exact_object(&store, object_hash).unwrap_err().code(),
        "EA-CRYPTO-AEAD-OPEN"
    );
}
```

Die Kanarienzeile `b"missingGrant"` steht neben `b"fehlender Grant"` und ist kein Doppel: die erste ist das Schemaliteral, das `ea_types::VerificationStatus::code()` gemessen ausgibt, und faende jede Serde- oder Debug-Darstellung des Zustands; die zweite ist die Oberflaechenschreibweise aus `design.md` §17.4. Beide DUERFEN im Bytespeicher nicht auftauchen, und ein einziger Marker liesse offen, welche der beiden geleckt hat — dieselbe Regel, die `tests/ea-system-tests/tests/privacy_canaries_writer.rs` mit einem Marker JE FELD schon durchsetzt.

- [x] **Step 2: Run the witnesses and confirm the vault does not exist**

Run: `cargo test --locked -p ea-reader --test key_profile --test vault_envelope --test cache_canaries && cargo test --locked -p xtask --test adr_gate`

Beide Kommandos tragen `--locked`, und das ist in diesem Schritt richtig: `hkdf` ist noch nicht eingetragen, `Cargo.lock` steht also unveraendert. Das GENAU EINE Kommando dieses Tasks ohne `--locked` — `cargo metadata --format-version 1` — steht als erste Zeile von Schritt 4, unmittelbar nachdem Schritt 3 die neue Fremdabhaengigkeit in `[workspace.dependencies]` eingetragen und in `crates/ea-reader/Cargo.toml` geerbt hat. Die Regel steht woertlich in `workspace_declares_exact_planned_members_and_shared_dependencies` (`tools/xtask/tests/workspace.rs`): „Ein neues Mitglied oder eine neue Fremdabhaengigkeit schreibt Cargo.lock neu, deshalb laeuft in dem Task, der sie eintraegt, GENAU EIN Kommando ohne --locked … Alle weiteren Kommandos dieses Tasks tragen wieder --locked."

Expected: FAIL because `crates/ea-reader` carries only `ReaderMode` and the re-export of `ea_verify::GATE_ORDER_V1` from the task „wasm32-Reichweite: `ea-reader`, die Brücken-Crate und die geteilten Browserkerne"; there is no vault, no envelope, no key profile, no cache and no entry-state store, and `hkdf` is not yet a shared dependency, so `adr_gate` reports the unratified pin.

- [x] **Step 3: Implement the vault, its envelopes, the key profile, and the encrypted stores**

```rust
// crates/ea-reader/src/envelope.rs
/// Der Info-String aus `web-reader-design.md` §6.2, zeichengleich.
pub const VAULT_KEK_INFO_V1: &[u8] = b"ea-reader-vault-v1";
const VAULT_CACHE_INFO_V1: &[u8] = b"ea-reader-cache-v1";
const VAULT_STATE_INFO_V1: &[u8] = b"ea-reader-entry-state-v1";
/// Der Ableitungskontext des Indexblobs. Er entsteht HIER, damit alle vier
/// abgeleiteten Schluessel EINEN Ort haben.
///
/// OEFFENTLICH, anders als die Kontexte von Cache und Zustandsspeicher: die
/// Aufgabe „Verschlüsselter invertierter Index in OPFS, Suche,
/// Schemakompatibilität und die GEMESSENE 50.000-Paket-Schwelle" liegt in einer
/// EIGENEN Crate und kann `derive_key` nicht rufen — sie bekommt den fertigen
/// Schluessel ueber [`UnlockedVault::index_key`] und leitet nichts selbst ab.
/// Die Konstante bleibt trotzdem sichtbar, weil sie der Ableitungsvertrag ist,
/// den ADR 0005 und `web-reader-design.md` §6.2 benennen.
pub const VAULT_INDEX_INFO_V1: &[u8] = b"ea-reader-index-v1";
const VAULT_ENVELOPE_AAD_V1: &[u8] = b"EINSATZARCHIV-READER-VAULT-ENVELOPE-v1";
const VAULT_BLOB_AAD_V1: &[u8] = b"EINSATZARCHIV-READER-VAULT-BLOB-v1";

pub struct AuthenticatorPrfV1 {
    credential_id: Vec<u8>,
    prf_output: SecretBytes<32>,
}

pub struct VaultEnvelopeV1 {
    credential_id: Vec<u8>,
    nonce: [u8; AEAD_NONCE_SIZE],
    wrapped_vault_key: [u8; CEK_SIZE + AEAD_OVERHEAD],
}

impl VaultEnvelopeV1 {
    /// Umschliesst den Tresorschluessel unter `KEK_i`.
    pub fn wrap(
        kek: &SecretBytes<CEK_SIZE>,
        vault_key: &SecretBytes<CEK_SIZE>,
        nonce: &[u8; AEAD_NONCE_SIZE],
    ) -> Result<Self, ReaderVaultError>;

    /// # Errors
    /// `EA-CRYPTO-AEAD-OPEN`, wenn `kek` nicht der ist, der umschlossen hat.
    pub fn unwrap(&self, kek: &SecretBytes<CEK_SIZE>)
        -> Result<SecretBytes<CEK_SIZE>, ReaderVaultError>;

    #[must_use]
    pub fn wrapped_vault_key(&self) -> &[u8];
}

/// Der EINE oeffentliche Ableitungsweg der PRF-Ausgabe zum Wrapping-Schluessel.
/// Die Aufgabe „Browser-Enrollment: zwei Pflicht-Authenticators und das nicht
/// überspringbare Fingerprint-Gate" ruft genau diese Funktion; sie schreibt
/// weder HKDF noch den Info-String ein zweites Mal.
pub fn derive_kek_v1(prf: &AuthenticatorPrfV1) -> Result<SecretBytes<CEK_SIZE>, ReaderVaultError>;

fn derive_key(ikm: &SecretBytes<32>, info: &[u8]) -> Result<SecretBytes<CEK_SIZE>, ReaderVaultError> {
    let mut derived = [0_u8; CEK_SIZE];
    ikm.with_exposed(|bytes| Hkdf::<Sha256>::new(None, bytes).expand(info, &mut derived))
        .map_err(|_| ReaderVaultError::KekDerivation)?;
    Ok(SecretBytes::new(derived))
}
```

```rust
// crates/ea-reader/src/vault.rs
pub struct VaultContentsV1 {
    kem_private_key: SecretBytes<32>,
    audit_private_key: SecretBytes<32>,
    pinned_anchor_exact_bytes: Vec<u8>,
    last_registry_pin: Option<RegistryHeadPin>,
}

pub struct SealedVaultV1 {
    nonce: [u8; AEAD_NONCE_SIZE],
    ciphertext: Vec<u8>,
    envelopes: Vec<VaultEnvelopeV1>,
}

pub struct UnlockedVault { /* private */ }

impl ReaderVault {
    pub fn seal(
        contents: VaultContentsV1,
        authenticators: &[AuthenticatorPrfV1],
    ) -> Result<SealedVaultV1, ReaderVaultError>;

    pub fn unlock(
        sealed: &SealedVaultV1,
        authenticator: &AuthenticatorPrfV1,
    ) -> Result<UnlockedVault, ReaderVaultError>;
}

impl UnlockedVault {
    pub const fn kem_private_key(&self) -> &HpkeRecipientPrivateKey;
    pub const fn kem_key_thumbprint(&self) -> KeyThumbprint;
    pub const fn pinned_anchor(&self) -> &TrustAnchorV1;
    pub fn pinned_anchor_bytes(&self) -> &[u8];
    pub const fn last_registry_pin(&self) -> Option<&RegistryHeadPin>;
    pub fn sign_audit_digest(&self, digest: &[u8; 32]) -> [u8; 64];

    /// Der Indexschluessel `HKDF-SHA-256(vault_key, info = VAULT_INDEX_INFO_V1)`.
    ///
    /// Der EINZIGE Weg des Indexschluessels aus dem Tresor heraus, und er gibt
    /// AUSSCHLIESSLICH den abgeleiteten Schluessel heraus, nie den
    /// Tresorschluessel: `crates/ea-index` ist eine fremde Crate, `derive_key`
    /// ist modulprivat, und ohne diesen Zugang haette der Index gar keine
    /// deklarierte Quelle. Der Rueckgabewert liegt in `SecretBytes<CEK_SIZE>`
    /// und damit unter `ZeroizeOnDrop`; er wird bei jedem Aufruf NEU abgeleitet
    /// und nirgends zwischengehalten.
    pub fn index_key(&self) -> SecretBytes<CEK_SIZE>;
}
```

`seal` zieht EINEN zufaelligen 32-Byte-Tresorschluessel und je Envelope einen frischen 12-Byte-Nonce ueber `getrandom::fill`, also ueber genau die Quelle, die der Laufzeitnachweis in `spikes/wasm-runtime-proof/` als `globalThis.crypto.getRandomValues` im Browserwirt gemessen hat. Verschluesselt wird ausschliesslich ueber `ea_crypto::aead_seal`/`aead_open`: `chacha20poly1305` steht heute in genau EINEM Manifest (`crates/ea-crypto/Cargo.toml`, gemessen), und diese Aufgabe legt kein zweites AEAD daneben. Der Tresorinhalt geht als CBOR-Wert unter `VAULT_BLOB_AAD_V1`; jedes Envelope umschliesst den Tresorschluessel unter `KEK_i` mit `VAULT_ENVELOPE_AAD_V1` samt der `credentialId` als gebundenem Zusatz, sodass ein Envelope nicht auf einen fremden Authenticator umhaengbar ist.

`KEK_i = derive_kek_v1(PRF_i) = HKDF-SHA-256(ikm = PRF_i(festes App-Salt), info = VAULT_KEK_INFO_V1)`, und `VAULT_KEK_INFO_V1` ist zeichengleich `b"ea-reader-vault-v1"` aus §6.2. Die PRF-Ausgabe DARF NICHT direkt als Verschluesselungsschluessel dienen (§6.2), und der Grund steht als Zeuge und nicht als Kommentar: `the_prf_output_never_wraps_the_vault_and_each_authenticator_opens_it_alone` sucht die rohe PRF-Ausgabe im Chiffrat und entfernt danach EIN Envelope, ohne dass der Tresor unerreichbar wird. Das feste App-Salt ist die Eingabe der PRF-Erweiterung und wird von der Aufgabe „Browser-Enrollment: zwei Pflicht-Authenticators und das nicht überspringbare Fingerprint-Gate" gesetzt; hier tritt ausschliesslich ihre AUSGABE ein.

`hkdf` tritt in `[workspace.dependencies]` der Wurzel-`Cargo.toml` mit dem exakten Pin `hkdf = { version = "=0.13.0", default-features = false }` ein und wird von `crates/ea-reader/Cargo.toml` mit `workspace = true` geerbt. Drei Messungen tragen die Entscheidung: `hkdf 0.13.0` liegt BEREITS in `Cargo.lock`, gezogen von `hpke 0.14.0` (der HPKE-Kante von `ea-crypto`) und von `sqlx-postgres` — der Lockfile-Delta ist eine KANTE, kein Paket; seine Lizenz ist `MIT OR Apache-2.0` und damit von der fuenf Eintraege langen Allowlist in `deny.toml` gedeckt, also entsteht KEINE neue `exceptions`-Zeile und kein neuer `GATE-*`-Anker; und die Alternative, `hpke::kdf::Kdf::extract_and_expand` zu benutzen, scheidet aus, weil diese Methode `#[doc(hidden)]` ist und ihre Ausgabe mit `HPKE-v1` und einer Suite-ID gelabelt ist — sie waere NICHT das HKDF, das §6.2 vorschreibt. `sha2` und `getrandom` stehen bereits exakt gepinnt in der Wurzeltabelle und in `docs/adr/0001-toolchain-and-cryptography-dependencies.md`; `ed25519-dalek` ebenfalls, und es tritt hier fuer den Audit-Signaturschluessel ein, den `sign_audit_digest` bedient.

Die Ratifikation folgt der Regel, die `docs/adr/0001-toolchain-and-cryptography-dependencies.md` in seinem Abschnitt `Consequences` selbst aufstellt: eine Aenderung an der Kryptografieklasse verlangt eine ADR-Zeile mit Primaerquellen- und RustSec-Pruefung. Sie geht in `docs/adr/0005-browser-runtime-and-wasm-dependency-class.md`, das die Aufgabe „Stufe-4-Vorlauf: ADR 0005, wasm-Werkzeugpins und die aufgehobene Blockade" anlegt, und `BROWSER_RUNTIME_DEPENDENCIES` in `tools/xtask/tests/adr_gate.rs` waechst dabei um genau den Eintrag `"hkdf"`. Das ist eine STELLIGKEITSAENDERUNG und wird hier so benannt, wie dieser Plan sie fuer `WEB_READER_MUST_ROWS` benennt: die Konstante ist `[&str; 5]`, angelegt von der Aufgabe „Stufe-4-Vorlauf: ADR 0005, wasm-Werkzeugpins und die aufgehobene Blockade", und wird in DIESER Aufgabe auf `[&str; 6]` gehoben — an genau einer Stelle, in genau diesem Commit, gemeinsam mit der ADR-Zeile, die der Test dann verlangt. Ein Eintrag ohne Stelligkeitsanhebung uebersetzt nicht, und das ist beabsichtigt — nach dem Muster, das `SERVER_RUNTIME_DEPENDENCIES` und `server_runtime_dependency_class_is_ratified_before_use` bereits vorgeben: exakter `=`-Pin auf DERSELBEN Zeile wie der Cratename und die gepruefte Merkmalsauswahl als woertliche Ledgerzeile. ADR 0001 wird dafuer NICHT umgeschrieben; die neue Klasse steht dort, wo die uebrigen Browserpins stehen.

`ReaderKeyProfile::validate` nimmt `&DeviceCertificateFieldsV1` und entscheidet gegen die GEPARSTEN Felder, nie gegen rohe Zeichenketten — dieselbe Regel, die `WriterKeyProfile::validate_capabilities` in `crates/ea-key-provider/src/profile.rs` aufschreibt. Fail-closed in vier Richtungen: `certificate_kind` MUSS `CertificateKindV1::Reader` sein; `kem_public_cose_key` und `signing_public_cose_key` MUESSEN beide vorliegen und ueber `CanonicalPublicCoseKey::from_deterministic_cbor` als `X25519` beziehungsweise `Ed25519` aufgehen; die beiden `KeyThumbprint`-Felder MUESSEN mit `CanonicalPublicCoseKey::thumbprint()` der jeweiligen Schluessel uebereinstimmen; und die 32 rohen Schluesselbytes der beiden Rollen MUESSEN verschieden sein — das ist `EA-KEY-ROLE-COLLISION`. Die vierte Klausel ist die einzige, die ohne sie durchginge: dieselben 32 Bytes sind einmal als `crv 4` und einmal als `crv 6` kodierbar, tragen dann zwei verschiedene Abdruecke und passierten jede Prueferei, die nur Abdruecke vergleicht. `crates/ea-key-provider` wird nicht angefasst: es steht auf `WASM32_EXEMPT_CRATES`, weil es in den Betriebssystem-Keystore greift, und ein Reader haelt gar keinen Writer-Schluessel.

`ReaderObjectCache` und `ReaderEntryStateStore` liegen UEBER dem opaken Bytespeicher der vorangehenden Aufgabe und kennen weder OPFS noch einen Worker: beide nehmen den Speicher als `&dyn ReaderBlobStore` beziehungsweise `&mut dyn ReaderBlobStore` je Aufruf entgegen und halten keinen. Beide leiten ihren Schluessel aus dem Tresorschluessel ab — `derive_key(vault_key, VAULT_CACHE_INFO_V1)` beziehungsweise `VAULT_STATE_INFO_V1` —, sodass ein zweiter Tresor denselben Speicher nicht oeffnet und eine Schluesselrotation genau einen Ort hat. Adressiert wird ueber `ReaderBlobKey::new("cache/<hex objectHash>")` und `ReaderBlobKey::new("entry-state/<hex entryHash>")`; der Schluessel ist ein Hexwert und nie ein fachliches Zeichen, weil `ReaderBlobStore::keys()` ihn im Klartext herausgibt. Der Cache speichert die EXAKTEN Objektbytes; er kodiert nichts um, sortiert nichts und laesst nichts aus, weil die spaetere Neuindizierung („Verschlüsselter invertierter Index in OPFS, Suche, Schemakompatibilität und die GEMESSENE 50.000-Paket-Schwelle") genau diese Bytes erneut verifiziert. Der Zustandsspeicher haelt je `EntryHash` genau einen `ReaderEntryStateV1` und keinen fachlichen Wert.

```rust
// crates/ea-reader/src/entry_state.rs
/// Der technische Zustand GENAU EINES Eintrags, drei orthogonale Dimensionen.
///
/// DEKLARIERT hier, weil die Zerlegung dieser Aufgabe `entry_state.rs` gibt;
/// GEFUELLT wird der Typ von `ReaderVerifier::classify` der Aufgabe
/// „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der
/// Anchor, den nur der Vault liefert", die ihn ausdruecklich NICHT ein zweites
/// Mal deklariert. Ein Speicher braucht seinen Werttyp, bevor der Klassifizierer
/// existiert; ein zweiter Typ daneben waere die zweite Wahrheit.
pub struct ReaderEntryStateV1 {
    entry_hash: EntryHash,
    object_hash: ObjectHash,
    sequence: ChainSequence,
    verification: VerificationStatus,          // ea_types, die sechs Begriffe aus §17.4
    entry_state: EntryStatus,                  // ea_types, die drei Begriffe aus §17.4
    server_confirmation: ServerConfirmationV1, // ea_verify, EIGENE Dimension
    detail_code: Option<&'static str>,         // ein STABILER Code, nie Prosa
}
```

KEIN Literal der drei Aufzaehlungen entsteht hier. `VerificationStatus` traegt seit Stufe 1 in `crates/ea-types/src/status.rs` GENAU die sechs Verifikationsbegriffe aus `design.md` §17.4 — `verified`, `gap`, `missingGrant`, `unknownKey`, `unsupportedSchema`, `invalid` —, `EntryStatus` die drei Eintragszustaende, und `ServerConfirmationV1` steht in `crates/ea-verify/src/report.rs`. Die Vorfassung dieses Tasks fuehrte hier eine eigene fuenfvariantige Aufzaehlung; sie ware eine ZWEITE Statussprache neben §17.4 gewesen und faellt ersatzlos. Die Server-Bestaetigung bleibt eine EIGENE Spalte und DARF NICHT in die Verifikation gefaltet werden — §17.4 verbietet die Vermischung ausdruecklich, und der Datei-Modus macht `notServerConfirmed` zum Regelfall. `detail_code` traegt ausschliesslich `ObjectErrorV1::code()`-Werte wie `EA-VERIFY-DECRYPT-CEK-UNWRAP-FAILED`; ein Prosafeld waere derselbe Fehler in klein.

`crates/ea-reader-wasm/src/vault_bridge.rs` exportiert unter `cfg(target_arch = "wasm32")` genau zwei Funktionen: `reader_vault_seal(contents_handle, credential_ids, prf_outputs) -> Vec<u8>` und `reader_vault_unlock(sealed: &[u8], credential_id: &[u8], prf_output: &[u8]) -> u32`, wobei der Rueckgabewert eine Sitzungskennung in einer prozessinternen Tabelle ist. Die Richtung ist die Zusage: die PRF-Ausgabe geht HINEIN, weil ihre Erzeugung eine Browser-API ist und nirgends sonst stattfinden kann; sie wird unmittelbar nach `derive_key` zeroisiert. Tresorschluessel, X25519-Rohschluessel und Ed25519-Rohschluessel gehen NIE zurueck ueber die Bruecke — TypeScript erhaelt Sitzungskennung, Fingerabdruecke und Statuswerte, nie Schluesselmaterial (`web-reader-design.md` §9). Der Rohschluessel liegt waehrend einer entsperrten Sitzung im WASM-Speicher, und das ist die in §6.5 benannte, bewusst getragene Folge der HPKE-Entkapselung im Modul; die Gegenmassnahmen dazu baut die Aufgabe „Sitzungssperre, Zeroize, authenticator-bestätigter Einzelexport und signiertes lokales Audit".

`SealedVaultV1::without_credential` ist PRODUKTIVE Flaeche und kein Testhelfer: das Loeschen eines Passkeys ist der Regelfall, den §6.2 mit der Envelope-Konstruktion ueberhaupt erst ueberlebbar macht. Die zwei beschaedigenden Zeugenhilfen daneben — `SealedVaultV1::{flip_one_wrapped_key_byte_for_test, replace_sealed_anchor_bytes_for_test}` — liegen hinter dem Merkmal `test-support` von `crates/ea-reader/Cargo.toml`, nach dem Muster, das `crates/ea-archive-fs` mit `overwrite_for_test`, `materialize_for_test` und `remove_for_test` bereits fuehrt, und die Wurzelkante `ea-reader = { path = "crates/ea-reader", default-features = false }` schaltet es AB. Ohne diesen Schalter laege eine Flaeche, die ein Chiffrat gezielt beschaedigt, in jedem Wirt, der die Crate zieht; ein `--no-default-features` am ausgewaehlten Paket wirkt nicht auf Default-Merkmale seiner Abhaengigkeiten, deshalb steht der Schalter an der GETEILTEN Kante und nicht am Mitglied.

Die Zwei-Authenticator-Pflicht aus §6.3 wird hier NICHT ein zweites Mal gewacht. `seal` weist ausschliesslich die leere Liste ab (`EA-READER-VAULT-NO-AUTHENTICATOR`), weil ein Tresor ohne Envelope unoeffenbar waere; die Zaehlung „mindestens zwei" gehoert an die Enrollmentgrenze und steht dort als harte Ablehnung. Zwei Waechter fuer dieselbe Zusage waeren zwei Wahrheiten, und die zweite verschiebt sich beim naechsten Umbau still.

- [x] **Step 4: Run the profile, envelope, cache, and ratification checks**

Run:

```bash
cargo metadata --format-version 1
cargo test --locked -p ea-reader --test key_profile --test vault_envelope --test cache_canaries
cargo test --locked -p xtask --test adr_gate
cargo test --locked -p ea-reader --doc
cargo run --locked -p xtask -- build-wasm
cargo test --locked -p xtask --test workspace
```

`cargo metadata --format-version 1` steht als ERSTE Zeile und ist das GENAU EINE Kommando dieses Tasks ohne `--locked`: Schritt 3 hat `hkdf` in `[workspace.dependencies]` eingetragen UND in `crates/ea-reader/Cargo.toml` mit `workspace = true` geerbt, und erst dieses Erben laesst die Kante in den Aufloesungsgraphen treten und `Cargo.lock` fortschreiben. Es steht VOR den `--locked`-Kommandos, sonst faellt das erste von ihnen an einem ueberholten Lockfile.

Expected: PASS. Adversarisch gedeckt sind fuenf Faelle, jeder mit seinem eigenen Zeugen: dieselben 32 Bytes in beiden Rollen fallen mit `EA-KEY-ROLE-COLLISION` und nicht mit einem Abdruckvergleich; die rohe PRF-Ausgabe erscheint in KEINEM Envelope; das Entfernen eines Envelopes kostet einen Entsperrweg und nie die Daten, waehrend das entfernte Credential `EA-READER-VAULT-NO-ENVELOPE` bekommt; ein gekipptes Byte im umschlossenen Tresorschluessel liefert `EA-CRYPTO-AEAD-OPEN` aus `ea_crypto::aead_open` und keinen eigenen zweiten Code; und ein im Tresor UNTERGESCHOBENER Anker faellt mit `EA-TRUST-ANCHOR-HASH`, weil `unlock` die Ankerbytes durch `ea_trust::decode_trust_anchor` schickt und diese Funktion `bootstrap_anchor_hash` ueber die Vorstufenbytes und den finalen Ankerhash ueber das Ganze NEU rechnet — der Anker gilt also nicht, weil er im Tresor lag, sondern weil er sich selbst traegt. Dazu die Kanarienzeile: weder die Objektbytes noch `CANARY-PERSON` noch die beiden Zustandsschreibweisen stehen im Bytespeicher, und die Positivkontrolle liest beides ueber den Tresor zurueck. `build-wasm` belegt, dass der neue Code samt `hkdf` fuer `wasm32-unknown-unknown` uebersetzt; es laeuft unter `env -u RUSTFLAGS`, weil `--cfg getrandom_backend` zu `getrandom 0.3` gehoert und fuer `0.4.3` das Merkmal `wasm_js` allein genuegt.

`cargo test --locked -p xtask --test workspace` steht dazu, weil der Releaseausschluss der zwei beschaedigenden Zeugenhilfen sonst an EINEM Schalter ohne Waechter haengt: `ea-reader = { path = "crates/ea-reader", default-features = false }` schaltet das Default-Merkmal `test-support` ab, und ohne Zeugen liefe ein spaeterer Commit, der den Schalter streicht, durch jede andere Zeile dieser Liste gruen — waehrend `SealedVaultV1::flip_one_wrapped_key_byte_for_test` und `SealedVaultV1::replace_sealed_anchor_bytes_for_test` im ausgelieferten wasm-Modul laegen. `no_non_test_edge_carries_the_ea_reader_test_surface` pinnt die Wurzelkante genauso, wie `no_non_test_edge_carries_the_ea_archive_fs_test_surface` die von `ea-archive-fs` pinnt, und liest den AUFGELOESTEN Merkmalsgraphen von `ea-reader-wasm` statt Manifestprosa. Seine Positivkontrolle ist NICHT die des Vorbilds: keine Dev-Kante fordert `ea-reader/test-support` an, `dev_edges > 0` waere sofort rot. Stattdessen faehrt derselbe `cargo tree`-Aufruf ein zweites Mal mit `-F ea-reader/test-support` und MUSS das Merkmal dann enthalten — erst damit ist die Abwesenheit im ersten Baum ein Befund und kein Artefakt eines leeren Baums.

- [x] **Step 5: Commit the browser vault**

```bash
git add crates/ea-reader crates/ea-reader-wasm docs/adr/0005-browser-runtime-and-wasm-dependency-class.md tools/xtask/tests/adr_gate.rs Cargo.toml Cargo.lock
git commit -m "feat(reader): unlock the browser vault through prf envelopes"
```

### Task 5: Browser-Enrollment: zwei Pflicht-Authenticators und das nicht überspringbare Fingerprint-Gate

**Files:**
- Create: `crates/ea-reader/src/enrollment.rs`
- Create: `crates/ea-reader-wasm/src/webauthn.rs`
- Create: `apps/web/src/vault/webauthn-prf.ts`
- Create: `apps/web/src/features/enrollment/EnrollmentPage.tsx`
- Create: `apps/web/src/features/enrollment/AuthenticatorRegistration.tsx`
- Create: `apps/web/src/features/enrollment/FingerprintGate.tsx`
- Create: `apps/web/playwright.config.ts`
- Modify: `crates/ea-reader/src/lib.rs`
- Modify: `crates/ea-reader/Cargo.toml`
- Modify: `crates/ea-reader-wasm/src/lib.rs`
- Modify: `apps/web/src/main.tsx`
- Modify: `package.json`
- Modify: `.gitignore`
- Modify: `Cargo.lock`
- Test: `crates/ea-reader/tests/enrollment_two_authenticators.rs`
- Test: `crates/ea-reader/tests/fingerprint_gate.rs`
- Test: `apps/web/src/features/enrollment/EnrollmentPage.test.tsx`
- Test: `apps/web/tests/e2e/enrollment.spec.ts`

**Interfaces:**
- Consumes: `ReaderVault`, `VaultEnvelopeV1::{wrap, unwrap}`, `derive_kek_v1` und die Konstante `VAULT_KEK_INFO_V1` aus dem Task „Browser-Vault: PRF-Envelopes, Schlüsselprofil und die Verwahrung von Anchor und KEM-Schlüssel"; `ReaderBlobStore` und seine In-Memory-Doppelung aus dem Task „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate"; `ea_sync_protocol::{ChallengeRequestV1, WebauthnCredentialRegistrationV1, VaultBlobUploadV1, VaultBlobRetrievalRequestV1, VaultBlobRetrievalResponseV1, RequestSigner, SIGNATURE_ALGORITHM_V1}`; `ea_crypto::{CanonicalPublicCoseKey, HpkeRecipientPrivateKey, SecretBytes, SecretVec, CEK_SIZE, AEAD_NONCE_SIZE}`; `ea_trust::{TrustAnchorV1, decode_trust_anchor}`; `ea_types::{KeyThumbprint, OrganizationId, SubjectId}`.
- Produces: `ReaderEnrollment::{begin, register_authenticator, fingerprints, confirm_fingerprints, finish}`, `EnrolledReaderV1`, `AuthenticatorRecordV1`, `EnrollmentFingerprintsV1`, `FingerprintConfirmationV1`, `EnrollmentError`, die Brückenexporte `ea_reader_wasm::webauthn::{prf_kek_bytes, enrollment_fingerprints, register_authenticator}` und die drei Aufrufe der Stufe-3-Endpunkte `POST /v1/webauthn-credentials`, `PUT /v1/vault-blobs`, `POST /v1/vault-blobs/retrievals`.

`crates/ea-reader/Cargo.toml` und `Cargo.lock` stehen im Files-Block, weil DIESE Aufgabe die Kante `ea-sync-protocol.workspace = true` von `crates/ea-reader` aus zieht: `EnrollmentError::Protocol(ea_sync_protocol::SyncProtocolError)` steht in `crates/ea-reader/src/enrollment.rs`, und die drei Stufe-3-Endpunkte reisen ueber `WebauthnCredentialRegistrationV1`, `VaultBlobUploadV1`, `VaultBlobRetrievalRequestV1`, `VaultBlobRetrievalResponseV1` und `RequestSigner`. Es ist die ERSTE Aufgabe dieses Plans, die diese Kante braucht — die Aufgabe „Inkrementeller Reader-Sync und verifizierter Cursor-Fortschritt in OPFS" findet sie bereits vor —, und eine neue Kante zwischen zwei Mitgliedern schreibt `Cargo.lock` fort. Deshalb faehrt Schritt 4 GENAU EIN Kommando ohne `--locked`, und `crates/ea-reader/src/lib.rs` nimmt im selben Zug `mod enrollment;` samt seinem `pub use`-Block auf, wie `crates/ea-reader-wasm/src/lib.rs` `mod webauthn;` — ohne diese zwei Zeilen uebersetzt der Commit nicht, und der Zeuge, der `ea_reader::enrollment::VAULT_PRF_SALT_V1` nennt, faende das Modul nicht.

`apps/web/src/main.tsx` steht ebenfalls im Files-Block: die Route `/enrollment`, die `apps/web/tests/e2e/enrollment.spec.ts` mit `page.goto('/enrollment')` anfaehrt, wird an die Routentabelle angehaengt, die die Aufgabe „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate" von Anfang an ausliefert. Ohne den Eintrag laeuft der Playwright-Lauf gegen eine nicht montierte Route und faellt aus dem falschen Grund.

Diese Aufgabe baut `web-reader-design.md` §6.3, §6.6 und §4.3 und sonst nichts. Ausdrücklich NICHT hier: das Objekt `readerKeyEscrow` und die Zwei-Approver-Öffnungszeremonie (§7.3/§7.5, Stufe 5, Ledgerzeile `WR-075`), die Administrationshälfte des Enrollments, die den erwarteten Fingerprint in der Desktop-Anwendung anzeigt und die Root-Signatur des Reader-Zertifikats auslöst (§6.6 Schritt 4, Stufe 5), und der Historical Re-grant für Einträge vor dem Enrollment (§6.6 Schritt 6, `design.md` §6.5). Der Cross-Device-QR-Flow wird hier als Entsperrpfad ABGEWIESEN und nicht implementiert: `web-reader-design.md` §6.4.1 letzter Absatz und §13 letzter Spiegelstrich nennen ihn beide, weil Safari in diesem Flow keine PRF-Ausgabe liefert.

- [ ] **Step 1: Write the two-authenticator, fixture-parity, and unskippable-fingerprint witnesses**

`crates/ea-reader/tests/enrollment_two_authenticators.rs` hält die Kardinalität und die Envelope-Konstruktion. Der erste Test ist der WICHTIGSTE dieser Aufgabe und steht deshalb zuerst: er stellt die Rust-Fixture, mit der die Tasks „Browser-Vault: PRF-Envelopes, Schlüsselprofil und die Verwahrung von Anchor und KEM-Schlüssel", „Inkrementeller Reader-Sync und verifizierter Cursor-Fortschritt in OPFS", „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert", „Datei-Modus: Einzeldatei-Bündel, Verzeichnis-Handle, kein Cursor, `nicht server-bestätigt`" und „Verschlüsselter invertierter Index in OPFS, Suche, Schemakompatibilität und die GEMESSENE 50.000-Paket-Schwelle" ihre entsperrte Sitzung bauen, gegen die ECHTE PRF-Auswertung desselben Authenticators. Ohne ihn ist die Fixture eine Annahme, und jeder Test, der auf ihr steht, misst am Ende nur sich selbst.

```rust
#[test]
fn the_rust_fixture_and_the_live_prf_ceremony_derive_the_same_kek() {
    let salt = ea_reader::enrollment::VAULT_PRF_SALT_V1;
    let fixture = ea_reader::enrollment::fixture_prf_output(fixtures::AUTHENTICATOR_ONE, &salt);
    let ceremony = fixtures::recorded_prf_output(fixtures::AUTHENTICATOR_ONE, &salt);
    assert!(fixture.with_exposed(|bytes| ceremony.matches(bytes)),
        "the fixture must reproduce the recorded PRF output byte for byte");
    let from_fixture = derive_kek_v1(&fixture);
    let from_ceremony = derive_kek_v1(&ceremony);
    let vault_key = SecretBytes::new([0x11; CEK_SIZE]);
    let envelope = VaultEnvelopeV1::wrap(&from_fixture, &vault_key, &fixtures::nonce(1)).unwrap();
    assert!(envelope.unwrap(&from_ceremony).unwrap().matches(&[0x11; CEK_SIZE]));
}

#[test]
fn a_single_authenticator_is_a_refusal_and_writes_no_blob() {
    let store = InMemoryReaderBlobStore::new();
    let mut enrollment = ReaderEnrollment::begin(fixtures::organization(), fixtures::subject(),
        fixtures::pinned_anchor(), &store).unwrap();
    enrollment.register_authenticator(fixtures::authenticator_one()).unwrap();
    let confirmation = fixtures::confirm(&enrollment);
    let refused = enrollment.finish(confirmation).unwrap_err();
    assert_eq!(refused.code(), "EA-READER-ENROLLMENT-SINGLE-AUTHENTICATOR");
    assert!(store.is_empty(), "a refused enrollment must leave no vault blob behind");
}

#[test]
fn each_authenticator_yields_one_envelope_over_the_same_vault_key() {
    let enrolled = fixtures::two_authenticator_enrollment();
    assert_eq!(enrolled.envelopes().len(), 2);
    for envelope in enrolled.envelopes() {
        assert_ne!(envelope.wrapped_bytes(), enrolled.vault_key_probe_bytes());
    }
    let first = enrolled.unlock_with(fixtures::AUTHENTICATOR_ONE).unwrap();
    let second = enrolled.unlock_with(fixtures::AUTHENTICATOR_TWO).unwrap();
    assert_eq!(first.kem_public_key().as_bytes(), second.kem_public_key().as_bytes());
    assert_eq!(first.pinned_anchor().trust_anchor_hash(),
               fixtures::pinned_anchor().trust_anchor_hash());
}

#[test]
fn the_prf_output_is_never_the_wrapping_key_and_deleting_one_passkey_keeps_the_vault_open() {
    let enrolled = fixtures::two_authenticator_enrollment();
    let raw = fixtures::recorded_prf_output(fixtures::AUTHENTICATOR_ONE, &VAULT_PRF_SALT_V1);
    let direct = VaultEnvelopeV1::from_wrapped(enrolled.envelopes()[0].wrapped_bytes().to_vec())
        .unwrap()
        .unwrap(&fixtures::kek_from_raw_prf(&raw));
    assert_eq!(direct.unwrap_err().code(), "EA-CRYPTO-AEAD-OPEN");
    // `without_authenticator` reicht auf `SealedVaultV1::without_credential`
    // durch und legt keine zweite Envelope-Verwaltung daneben.
    let surviving = enrolled.without_authenticator(fixtures::AUTHENTICATOR_ONE);
    assert!(surviving.unlock_with(fixtures::AUTHENTICATOR_TWO).is_ok());
}

#[test]
fn the_cross_device_qr_flow_is_not_an_unlock_path() {
    let refused = ReaderEnrollment::begin(fixtures::organization(), fixtures::subject(),
        fixtures::pinned_anchor(), &InMemoryReaderBlobStore::new())
        .unwrap()
        .register_authenticator(fixtures::cross_device_authenticator())
        .unwrap_err();
    assert_eq!(refused.code(), "EA-READER-ENROLLMENT-TRANSPORT-REFUSED");
}
```

`crates/ea-reader/tests/fingerprint_gate.rs` hält §4.3. Die Zusicherung ist nicht „es gibt eine Prüfung", sondern „es gibt keinen Weg daran vorbei": `finish` nimmt eine `FingerprintConfirmationV1`, und dieser Typ ist AUSSCHLIESSLICH aus `ReaderEnrollment::confirm_fingerprints` mit übereinstimmenden Werten konstruierbar — dieselbe Bauform, mit der `VerifiedEncryptedEntry` im Task „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert" den HPKE-Entkapseler bewacht.

```rust
#[test]
fn a_diverging_fingerprint_aborts_the_enrollment() {
    let mut enrollment = fixtures::enrollment_with_two_authenticators();
    let shown = enrollment.fingerprints();
    let wrong = fixtures::flip_one_hex_digit(shown.bundle_fingerprint());
    let refused = enrollment.confirm_fingerprints(shown.key_fingerprint(), &wrong).unwrap_err();
    assert_eq!(refused.code(), "EA-READER-ENROLLMENT-FINGERPRINT-MISMATCH");
    let refused_key = enrollment
        .confirm_fingerprints(&fixtures::flip_one_hex_digit(shown.key_fingerprint()),
                              shown.bundle_fingerprint())
        .unwrap_err();
    assert_eq!(refused_key.code(), "EA-READER-ENROLLMENT-FINGERPRINT-MISMATCH");
}

#[test]
fn the_confirmation_has_no_construction_path_outside_a_match() {
    // Der Beweis ist die ABWESENHEIT einer Konstruktion, nicht ihr Ergebnis.
    let source = include_str!("../src/enrollment.rs");
    assert_eq!(source.matches("FingerprintConfirmationV1 {").count(), 1,
        "FingerprintConfirmationV1 must be constructed in exactly one place");
    assert!(!source.contains("pub fn skip"), "no skip path may exist");
    assert!(!source.contains("Default for FingerprintConfirmationV1"));
}

#[test]
fn the_gate_fires_on_every_first_call_without_a_pinned_trust_store() {
    let store = InMemoryReaderBlobStore::new();
    let known = ReaderEnrollment::device_state(&store);
    assert!(matches!(known, DeviceTrustStateV1::NoPinnedAnchor));
    assert!(ReaderEnrollment::fingerprint_gate_required(&known));
    let enrolled = fixtures::two_authenticator_enrollment_into(&store);
    assert!(!ReaderEnrollment::fingerprint_gate_required(
        &ReaderEnrollment::device_state(&store)));
    drop(enrolled);
}
```

`apps/web/src/features/enrollment/EnrollmentPage.test.tsx` prüft dieselben zwei Zusagen auf der Oberfläche und NICHTS darüber hinaus: das Abschlusselement bleibt gesperrt, solange ein Authenticator fehlt oder der Fingerprintvergleich nicht bestätigt ist, und die Bestätigung ist kein Häkchen, sondern die Eingabe der unabhängig verteilten Referenz.

```tsx
it('keeps the enrollment closed until two authenticators and both fingerprints agree', async () => {
  render(<EnrollmentPage bridge={stubBridge({ fingerprints: SHOWN })} />)
  expect(screen.getByRole('button', { name: 'Enrollment abschließen' })).toBeDisabled()
  await user.click(screen.getByRole('button', { name: 'Authenticator registrieren' }))
  expect(screen.getByText('Ein zweiter Authenticator ist erforderlich.')).toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Authenticator registrieren' }))
  expect(screen.getByRole('button', { name: 'Enrollment abschließen' })).toBeDisabled()
  await user.type(screen.getByLabelText('Erwarteter Bundle-Fingerprint'), WRONG)
  expect(screen.getByRole('alert')).toHaveTextContent('EA-READER-ENROLLMENT-FINGERPRINT-MISMATCH')
  expect(screen.getByRole('button', { name: 'Enrollment abschließen' })).toBeDisabled()
  await user.clear(screen.getByLabelText('Erwarteter Bundle-Fingerprint'))
  await user.type(screen.getByLabelText('Erwarteter Bundle-Fingerprint'), SHOWN.bundleFingerprint)
  await user.type(screen.getByLabelText('Erwarteter Schlüssel-Fingerprint'), SHOWN.keyFingerprint)
  expect(screen.getByRole('button', { name: 'Enrollment abschließen' })).toBeEnabled()
})

it('derives no key and compares no fingerprint in TypeScript', async () => {
  const bridge = stubBridge({ fingerprints: SHOWN })
  render(<EnrollmentPage bridge={bridge} />)
  await user.type(screen.getByLabelText('Erwarteter Bundle-Fingerprint'), SHOWN.bundleFingerprint)
  await user.type(screen.getByLabelText('Erwarteter Schlüssel-Fingerprint'), SHOWN.keyFingerprint)
  expect(bridge.confirmFingerprints).toHaveBeenCalledWith({
    expectedKeyFingerprint: SHOWN.keyFingerprint,
    expectedBundleFingerprint: SHOWN.bundleFingerprint,
  })
})
```

`apps/web/playwright.config.ts` entsteht in DIESEM Task, weil er der erste ist, der Playwright fährt; die späteren E2E-Läufe der Tasks „Web-Bundle: getrennter Origin, Service Worker, gepinnte `webBundleRelease` und das Alter des Trust-Standes", „Datei-Modus: Einzeldatei-Bündel, Verzeichnis-Handle, kein Cursor, `nicht server-bestätigt`", „Sitzungssperre, Zeroize, authenticator-bestätigter Einzelexport und signiertes lokales Audit" und „Integritätszentrierte Reader-Oberfläche in `apps/web` und die Rollengrenze zum Desktop" benutzen sie unverändert. Die Konfiguration folgt der Desktop-Vorlage: `testDir: 'tests/e2e'`, `webServer` mit `pnpm exec vite build && pnpm exec vite preview --host 127.0.0.1 --port 4174 --strictPort` — ein ANDERER Port als die 4173 des Desktops, damit beide Suiten nebeneinander laufen —, `use.baseURL` auf dieselbe IPv4-Schleife und `use.offline: false`, weil `offline: true` auf Kontextebene in Chromium den GESAMTEN Netzstapel einschließlich `127.0.0.1` abschneidet und die Anwendung dann nie lädt. Sie trägt in diesem Task GENAU EIN `projects`-Element, `chromium`; die Matrix aus `chromium`, `firefox` und `webkit` entsteht im Task „Reader-Interoperabilität, Browser-Matrix, Datei-Modus, Privatheit und das Stufe-4-Gate". `package.json` der Wurzel bekommt dazu das Skript `"web:e2e": "pnpm --dir apps/web e2e"`; es steht wie `desktop:e2e` AUSDRÜCKLICH NICHT in `verify_quick_commands()`, weil Playwright installierte Browser voraussetzt.

`.gitignore` bekommt im selben Zug die zwei Zeilen `apps/web/test-results/` und `apps/web/playwright-report/`. Sie sind das Spiegelbild der bereits vorhandenen `apps/desktop/test-results/` und `apps/desktop/playwright-report/` und fallen in DIESEM Task, weil er der erste ist, der Playwright fährt und damit als erster diese Verzeichnisse erzeugt. Ohne sie zögen die späteren `git add apps/web` der Tasks „Web-Bundle: getrennter Origin, Service Worker, gepinnte `webBundleRelease` und das Alter des Trust-Standes", „Datei-Modus: Einzeldatei-Bündel, Verzeichnis-Handle, kein Cursor, `nicht server-bestätigt`" und „Integritätszentrierte Reader-Oberfläche in `apps/web` und die Rollengrenze zum Desktop" den kompletten Lauf-Ausgang samt Traces und Screenshots in das Repositorium — genau der Grund, aus dem die Desktop-Zeilen dort stehen.

`apps/web/tests/e2e/enrollment.spec.ts` fährt denselben Ablauf gegen einen virtuellen Authenticator. Der Lauf ist AUSDRÜCKLICH auf das Playwright-Projekt `chromium` beschränkt und trägt das dazu: `WebAuthn.addVirtualAuthenticator` ist eine CDP-Methode, Firefox und WebKit bieten kein Gegenstück, und die Browser-Matrix des Tasks „Reader-Interoperabilität, Browser-Matrix, Datei-Modus, Privatheit und das Stufe-4-Gate" führt diese Einschränkung als benannte Lücke statt sie zu verschweigen. Die Beschränkung braucht einen MECHANISMUS und nicht nur einen Satz: solange `apps/web/playwright.config.ts` ein einziges `projects`-Element trägt, ist sie folgenlos, aber der Gate-Task stellt drei Projekte daneben und fährt `pnpm web:e2e` über alle Spezifikationen. Deshalb steht in der ersten Zeile jeder CDP-benutzenden Spezifikation dieses Plans `test.skip(({ browserName }) => browserName !== 'chromium')`, und `enrollment.spec.ts` ist die erste, die sie trägt. Ohne diese Zeile stirbt der Enrollment-Lauf im Matrixlauf des Gates an `WebAuthn.enable` — an der spätestmöglichen Stelle und mit der unklarsten Meldung.

```ts
test('a second authenticator is required and a wrong fingerprint aborts', async ({ page }) => {
  const cdp = await page.context().newCDPSession(page)
  await cdp.send('WebAuthn.enable')
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true },
  })
  await page.goto('/enrollment')
  await page.getByRole('button', { name: 'Authenticator registrieren' }).click()
  await expect(page.getByRole('button', { name: 'Enrollment abschließen' })).toBeDisabled()
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true } })
  await page.getByRole('button', { name: 'Authenticator registrieren' }).click()
  await page.getByLabel('Erwarteter Bundle-Fingerprint').fill('0'.repeat(64))
  await expect(page.getByRole('alert')).toContainText('EA-READER-ENROLLMENT-FINGERPRINT-MISMATCH')
  await expect(page.getByRole('button', { name: 'Enrollment abschließen' })).toBeDisabled()
  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId })
})
```

- [ ] **Step 2: Run the witnesses and confirm no enrollment surface exists**

Run: `cargo test --locked -p ea-reader --test enrollment_two_authenticators --test fingerprint_gate && pnpm --dir apps/web test --run src/features/enrollment`

Beide Kommandos tragen `--locked`, und das ist in diesem Schritt richtig: die Kante auf `ea-sync-protocol` ist noch nicht eingetragen, `Cargo.lock` steht also unveraendert. Das GENAU EINE Kommando dieses Tasks ohne `--locked` steht als erste Zeile von Schritt 4.

Expected: FAIL. `crates/ea-reader/src/enrollment.rs` existiert nicht, also fehlen `ReaderEnrollment`, `EnrollmentFingerprintsV1`, `FingerprintConfirmationV1` und `VAULT_PRF_SALT_V1`, und der `include_str!("../src/enrollment.rs")` des Konstruktions-Zeugen bricht bereits beim Übersetzen ab — das ist der beabsichtigte erste rote Punkt und keine Panne, denn ein Zeuge, der eine Abwesenheit über eine Datei behauptet, muss an der fehlenden Datei scheitern und nicht still bestehen. Auf der Webseite fehlen alle drei Komponenten; `pnpm --dir apps/web test` selbst LÄUFT, weil das Paket, sein Vitest-Runner und `src/bridge/generated-contracts.ts` seit dem Task „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate" existieren. Ein Paketmanagerabbruch wäre hier kein roter Test, sondern eine falsche Reihenfolge.

- [ ] **Step 3: Implement browser key generation, two mandatory authenticators, blob transport, and the fingerprint gate**

```rust
/// Das FESTE App-Salt der PRF-Auswertung (`web-reader-design.md` §6.2).
///
/// Fest und nicht je Gerät zufällig: §6.4.1 verlangt, dass synchronisierte
/// Passkeys bei GLEICHEM Salt über die Geräte des Nutzers dieselbe Ausgabe
/// liefern. Ein geräteabhängiges Salt machte genau den Fall aus §6.4 — Blob
/// beziehen, Authenticator bestätigen, weiterarbeiten — unmöglich.
pub const VAULT_PRF_SALT_V1: [u8; 32] = *b"EINSATZARCHIV-READER-VAULT-PRF-1";

/// Die zwingende Untergrenze aus `web-reader-design.md` §6.3.
pub const MIN_ENROLLED_AUTHENTICATORS_V1: usize = 2;

pub enum EnrollmentError {
    SingleAuthenticator,
    DuplicateAuthenticator,
    TransportRefused,
    FingerprintMismatch,
    AnchorUnpinned,
    Protocol(ea_sync_protocol::SyncProtocolError),
    Crypto(ea_crypto::CryptoError),
}

pub struct ReaderEnrollment<'store, S: ReaderBlobStore> { /* private */ }

impl<'store, S: ReaderBlobStore> ReaderEnrollment<'store, S> {
    pub fn begin(organization_id: OrganizationId, subject_id: SubjectId,
                 pinned_anchor: TrustAnchorV1, store: &'store S)
        -> Result<Self, EnrollmentError>;

    pub fn register_authenticator(&mut self, attested: AttestedAuthenticatorV1)
        -> Result<&AuthenticatorRecordV1, EnrollmentError>;

    #[must_use]
    pub fn fingerprints(&self) -> EnrollmentFingerprintsV1;

    pub fn confirm_fingerprints(&self, expected_key: &str, expected_bundle: &str)
        -> Result<FingerprintConfirmationV1, EnrollmentError>;

    pub fn finish(self, confirmation: FingerprintConfirmationV1)
        -> Result<EnrolledReaderV1, EnrollmentError>;
}

pub struct EnrollmentFingerprintsV1 {
    key_fingerprint: KeyThumbprint,
    bundle_fingerprint: Hash32,
}

/// Konstruierbar AUSSCHLIESSLICH in `confirm_fingerprints`, und dort nur nach
/// einem konstantzeitigen Vergleich BEIDER Werte.
pub struct FingerprintConfirmationV1 { /* private, kein Default, kein Clone */ }
```

Die Schlüsselerzeugung läuft im Browser und die privaten Schlüssel verlassen ihn nie (§6.6 Schritt 1). `begin` zieht 64 Byte Entropie über `getrandom::fill` — im Browser `globalThis.crypto.getRandomValues` über das Feature `wasm_js`, ausführbar nachgewiesen in `spikes/wasm-runtime-proof/spike.sh` — und baut daraus den X25519-KEM-Schlüssel über `HpkeRecipientPrivateKey::from_bytes` und den Ed25519-Geräte- und Audit-Schlüssel. Beide liegen als `SecretBytes<32>` und damit unter `ZeroizeOnDrop`. Der gepinnte Root-Anchor kommt als PARAMETER aus `decode_trust_anchor` und niemals aus einer Serverantwort; ohne ihn gibt `begin` `AnchorUnpinned` zurück, denn ein Vault ohne Anchor wäre im Datei-Modus wertlos (§5.3).

`register_authenticator` nimmt eine `AttestedAuthenticatorV1` — `credentialId`, der auf `CanonicalPublicCoseKey::Ed25519` normalisierte `credentialPublicKey`, das Transportprofil und die 32 PRF-Bytes zu `VAULT_PRF_SALT_V1`. Vier Prüfungen laufen hier und nirgends sonst: der öffentliche Schlüssel muss `CanonicalPublicCoseKey::from_deterministic_cbor` als Ed25519-Arm überstehen (dieselbe Prüfung, die `WebauthnCredentialRegistrationV1::new` serverseitig ein zweites Mal fährt, weshalb ein hier akzeptierter Schlüssel dort nie scheitert); die `credentialId` muss zwischen `MIN_WEBAUTHN_CREDENTIAL_ID_BYTES_V1` und `MAX_WEBAUTHN_CREDENTIAL_ID_BYTES_V1` liegen; eine bereits registrierte `credentialId` ist `DuplicateAuthenticator`, weil zwei Envelopes desselben Authenticators die Zwei-aus-§6.3 vortäuschten, ohne sie zu erfüllen; und ein Credential, dessen Transport der Cross-Device-Flow ist, ist `TransportRefused`. Danach entsteht der Envelope: `KEK_i = derive_kek_v1(PRF_i)` — HKDF-SHA256 mit `info = VAULT_KEK_INFO_V1` aus dem Task „Browser-Vault: PRF-Envelopes, Schlüsselprofil und die Verwahrung von Anchor und KEM-Schlüssel" —, und mit `KEK_i` wird der 32-Byte-Vault-Key gewrappt, NIE mit der PRF-Ausgabe selbst. Die Begründung steht in §6.2 und ist betrieblich: mit direkter Verwendung machte das Löschen eines Passkeys die Daten dauerhaft unerreichbar, weil jeder Authenticator dann sein EIGENES Chiffrat trüge statt eines Umschlags um denselben Vault-Key.

`fingerprints` gibt den Schlüssel-Fingerprint als `CanonicalPublicCoseKey::thumbprint()` über den X25519-KEM-Schlüssel und den Bundle-Fingerprint als den Hash des geladenen Bundles zurück, den die Brücke aus dem Bauartefakt des Tasks „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate" bekommt. `confirm_fingerprints` vergleicht BEIDE gegen die eingegebene, unabhängig verteilte Referenz und gibt nur bei Übereinstimmung eine `FingerprintConfirmationV1` zurück. Der Vergleich läuft byteweise konstantzeitig über die dekodierten Hex-Werte und nicht über die Zeichenketten, damit Groß-/Kleinschreibung und Trennzeichen der Anzeige keine falsche Abweichung erzeugen. `finish` nimmt diesen Typ als Parameter und prüft ZUSÄTZLICH `MIN_ENROLLED_AUTHENTICATORS_V1`. Es gibt keinen `skip`, kein `force`, kein `Default` und keine zweite Konstruktionsstelle — genau das misst der Zeuge `the_confirmation_has_no_construction_path_outside_a_match`, und genau deshalb ist der Vergleich „bei jedem Erstaufruf auf einem Gerät ohne gepinnten Trust-Store erzwungen und nicht überspringbar" (§4.3 letzter Absatz) eine Typaussage und keine Bildschirmaussage.

`finish` schreibt danach in dieser Reihenfolge und nicht anders: erst je Authenticator ein `WebauthnCredentialRegistrationV1` über `POST /v1/webauthn-credentials` mit der pseudonymen `subjectId` als `userHandle` (§6.4.1), dann je Envelope ein `VaultBlobUploadV1` über `PUT /v1/vault-blobs`, beide RFC-9421-signiert mit dem gerade erzeugten Ed25519-Schlüssel über `RequestSigner` — der Schlüssel ist in diesem Moment im Klartext im WASM-Speicher, was diese beiden Endpunkte gerade NICHT zur Signaturausnahme macht (Stufe-3-Task „Web-Serverfläche: Vault-Blobs, WebAuthn-Assertion und CORS", zweiter Absatz seines Schritts 3) —, und erst danach lokal in OPFS über `ReaderBlobStore`. Die Reihenfolge ist fail-closed: ein lokal geschriebener Vault ohne serverseitige Kopie überstünde kein geräumtes Browserprofil, und §6.4 verlangt genau, dass dieser Fall ohne Administrationsvorgang gelöst wird. Bricht ein Upload ab, bleibt gar nichts geschrieben; der Zeuge `a_single_authenticator_is_a_refusal_and_writes_no_blob` misst dieselbe Eigenschaft am anderen Ende.

Der Abruf auf einem Gerät ohne Vault läuft über `POST /v1/vault-blobs/retrievals` und trägt als einziger Aufruf dieses Tasks KEINE RFC-9421-Signatur, weil der Signaturschlüssel im noch verschlossenen Vault liegt (§6.4.1, `design.md` §13.1). Alleinige Autorität ist die WebAuthn-Assertion über ein auffindbares Credential dieses Readers; `VaultBlobRetrievalRequestV1::new` nimmt `organizationId`, den behaupteten `userHandle`, `credentialId`, Challenge, `authenticatorData`, `clientDataJSON` und Signatur, und die Antwort `VaultBlobRetrievalResponseV1` liefert bis zu `MAX_VAULT_BLOBS_PER_SUBJECT_V1` opake Chiffrate. Der Reader probiert sie der Reihe nach gegen seinen `KEK_i`; genau eines öffnet. Die beiden Verwendungen desselben Authenticators bleiben getrennt: die Assertion authentisiert den Transport, die PRF-Ausgabe entsperrt den Vault, und keine der beiden verleiht dem Server Autorität (§6.4.1 vorletzter Absatz).

`crates/ea-reader-wasm/src/webauthn.rs` exportiert unter `cfg(target_arch = "wasm32")` genau drei Funktionen und keine vierte: `register_authenticator` nimmt die vom Browser gelieferten Bytes und gibt eine Status-DTO zurück, `enrollment_fingerprints` gibt die beiden Hex-Zeichenketten zur ANZEIGE zurück, und `prf_kek_bytes` existiert nur `cfg(test)` als Prüfpunkt der Fixture-Parität. Die PRF-Ausgabe überquert die Grenze als `Uint8Array` und wird in Rust sofort in `SecretBytes<32>` überführt; sie wird auf der TypeScript-Seite in keiner Variablen gehalten, die einen Namen überlebt, und niemals geloggt.

`apps/web/src/vault/webauthn-prf.ts` ist die einzige Datei, die `navigator.credentials.create` und `navigator.credentials.get` mit der Erweiterung `prf` aufruft. Sie enthält KEINE Sicherheitslogik: sie leitet keinen Schlüssel ab, vergleicht keinen Fingerprint, kodiert kein Chiffrat und trifft keine Entscheidung — sie reicht Bytes an die Brücke und bekommt Status-DTOs zurück (§9). `authenticatorSelection` verlangt `residentKey: 'required'` und `userVerification: 'required'`, weil §6.4.1 die Auflösung über ein AUFFINDBARES Credential voraussetzt. `hints: ['client-device']` und der abgewiesene Cross-Device-Transport stehen hier, damit der QR-Flow gar nicht erst angeboten wird; die harte Abweisung bleibt trotzdem in Rust, weil eine UI-Auswahl kein Gate ist.

`EnrollmentPage.tsx` führt die drei Schritte in einer Ant-Design-6-Oberfläche mit deutschem `ConfigProvider` und statisch extrahiertem lokalem gehashtem CSS, `zeroRuntime: true`, direkten CSR-Importen aus `@phosphor-icons/react`, sichtbarem Fokus und `prefers-reduced-motion`. `AuthenticatorRegistration.tsx` zählt registrierte Authenticators als Text und nicht nur als Symbol und nennt die fehlende Zahl beim Namen. `FingerprintGate.tsx` zeigt beide Fingerprints im Monospace-Block nach dem Muster von `apps/desktop/src/components/integrity/FingerprintBlock.tsx` und verlangt die Eingabe der Referenz; das Abschlusselement ist gesperrt, solange die Brücke keine Bestätigung geliefert hat.

**Offener Punkt, hier benannt und nicht aufgelöst:** `web-reader-design.md` §14 Punkt 5 erklärt Referenzquelle und Verteilweg der Fingerprint-Bekanntgabe ausdrücklich für OFFEN. Dieser Task baut deshalb den VERGLEICH und seine Unumgehbarkeit, nicht den Bezugsweg der Referenz: die erwarteten Werte werden eingegeben. Die Administrationshälfte, die den erwarteten Fingerprint in der Desktop-Anwendung anzeigt (§6.6 Schritt 4), liegt in Stufe 5 und wird hier weder gebaut noch behauptet.

- [ ] **Step 4: Run the enrollment, fingerprint, and browser witnesses**

Run:

```bash
cargo metadata --format-version 1
cargo test --locked -p ea-reader --test enrollment_two_authenticators --test fingerprint_gate
pnpm --dir apps/web test --run src/features/enrollment
pnpm --dir apps/web exec playwright test tests/e2e/enrollment.spec.ts --project=chromium
```

`cargo metadata --format-version 1` steht als ERSTE Zeile und ist das GENAU EINE Kommando dieses Tasks ohne `--locked`: Schritt 3 gibt `crates/ea-reader/Cargo.toml` die Kante `ea-sync-protocol.workspace = true`, und eine neue Kante zwischen zwei Mitgliedern schreibt `Cargo.lock` fort. Es steht NACH der Registrierung und VOR jedem `--locked`-Kommando; stuende es in Schritt 2, schriebe es nichts fort und die `--locked`-Laeufe danach fielen an einem ueberholten Lockfile. Die Regel steht woertlich in `workspace_declares_exact_planned_members_and_shared_dependencies` (`tools/xtask/tests/workspace.rs`).

Expected: PASS. Belegt sind fünf Negative und zwei Positive. Die Negative: ein einzelner Authenticator ist `EA-READER-ENROLLMENT-SINGLE-AUTHENTICATOR` und hinterlässt keinen Blob; dieselbe `credentialId` zweimal ist `EA-READER-ENROLLMENT-DUPLICATE-AUTHENTICATOR`; ein Cross-Device-Credential ist `EA-READER-ENROLLMENT-TRANSPORT-REFUSED`; ein abweichender Bundle- ODER Schlüssel-Fingerprint ist `EA-READER-ENROLLMENT-FINGERPRINT-MISMATCH` und liefert keine `FingerprintConfirmationV1`, weshalb `finish` nicht einmal aufrufbar ist; und ein Envelope, der direkt mit der rohen PRF-Ausgabe statt mit `KEK_i` geöffnet wird, ist `EA-CRYPTO-AEAD-OPEN`. Die Positive: beide Envelopes öffnen denselben Vault-Key und liefern denselben KEM-Public-Key und denselben gepinnten Anchor, und das Entfernen eines Authenticators lässt den Vault über den zweiten offen — genau die Eigenschaft, die §6.2 als Zweck der Envelope-Konstruktion nennt. Die Fixture-Parität ist der Zeuge, der alle folgenden Tasks trägt: `fixture_prf_output` reproduziert die aufgezeichnete PRF-Ausgabe byteweise, also ist die entsperrte Sitzung, mit der die Tasks „Browser-Vault: PRF-Envelopes, Schlüsselprofil und die Verwahrung von Anchor und KEM-Schlüssel", „Inkrementeller Reader-Sync und verifizierter Cursor-Fortschritt in OPFS", „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert", „Datei-Modus: Einzeldatei-Bündel, Verzeichnis-Handle, kein Cursor, `nicht server-bestätigt`" und „Verschlüsselter invertierter Index in OPFS, Suche, Schemakompatibilität und die GEMESSENE 50.000-Paket-Schwelle" arbeiten, ein GEMESSENER Stellvertreter und keine Annahme.

Nicht belegt und hier benannt: der E2E-Lauf deckt ausschließlich das Projekt `chromium` ab, weil `WebAuthn.addVirtualAuthenticator` eine CDP-Methode ist und Firefox und WebKit kein Gegenstück anbieten. Die Rust-Zeugen laufen plattformunabhängig auf dem Host und sind der Träger jeder normativen Aussage dieses Tasks; der Browserlauf ist der zusätzliche Beleg, dass die Kette aus echtem Authenticator, echter PRF-Auswertung und der Brücke zusammenpasst. Der Task „Reader-Interoperabilität, Browser-Matrix, Datei-Modus, Privatheit und das Stufe-4-Gate" trägt diese Einschränkung in die Spalte `offen in späterer Stufe` seines Berichts.

Die Ledgerzeilen `WR-063` (Enrollment registriert mindestens zwei unabhängige Authenticators) und `WR-043` (erzwungener, nicht überspringbarer Fingerprint-Vergleich beim Erstaufruf) bekommen hier ihre Belege, werden aber NICHT hier umgestellt: der gepinnte Konstantenblock `WEB_READER_MUST_ROWS` in `tools/xtask/tests/stage_gate.rs` und die Statusspalte in `docs/traceability/v0.1-requirements.csv` werden ausschließlich im Task „Reader-Interoperabilität, Browser-Matrix, Datei-Modus, Privatheit und das Stufe-4-Gate" angefasst, damit die Stelligkeit dieser Konstante in dieser Stufe genau einmal wandert.

- [ ] **Step 5: Commit browser enrollment**

```bash
git add .gitignore
git add crates/ea-reader/src/enrollment.rs crates/ea-reader/src/lib.rs crates/ea-reader/Cargo.toml crates/ea-reader/tests/enrollment_two_authenticators.rs crates/ea-reader/tests/fingerprint_gate.rs crates/ea-reader-wasm/src/webauthn.rs crates/ea-reader-wasm/src/lib.rs apps/web/src/vault apps/web/src/features/enrollment apps/web/src/main.tsx apps/web/tests/e2e/enrollment.spec.ts apps/web/playwright.config.ts package.json Cargo.lock
git commit -m "feat(reader): enroll two authenticators behind an unskippable fingerprint gate"
```

### Task 6: Web-Bundle: getrennter Origin, Service Worker, gepinnte `webBundleRelease` und das Alter des Trust-Standes

**Files:**
- Create: `crates/ea-reader/src/bundle_release.rs`
- Create: `crates/ea-reader/tests/bundle_release_pinning.rs`
- Create: `apps/web/src/sw/service-worker.ts`
- Create: `apps/web/src/sw/bundle-pinning.ts`
- Create: `apps/web/src/sw/service-worker.test.ts`
- Create: `apps/web/src/features/trust-age/TrustAgeBanner.tsx`
- Create: `apps/web/tests/e2e/bundle-activation.spec.ts`
- Create: `docs/traceability/stage-4-fault-points.json`
- Modify: `apps/web/vite.config.ts`
- Modify: `apps/web/index.html`
- Modify: `apps/web/src/app/csp.test.ts`
- Modify: `apps/web/src/main.tsx`
- Modify: `crates/ea-crypto/src/cose.rs`
- Modify: `crates/ea-crypto/src/lib.rs`
- Modify: `crates/ea-reader/src/lib.rs`
- Modify: `crates/ea-reader-wasm/src/bridge.rs`
- Modify: `crates/ea-ui-contracts/src/lib.rs`
- Modify: `crates/ea-ui-contracts/src/emit.rs`
- Modify: `crates/ea-ui-contracts/Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `apps/web/src/bridge/generated-contracts.ts` — Emitterausdruck, von Hand unangetastet

**Interfaces:**
- Consumes: die in Stufe 3 dauerhaft eingefrorene Objektfamilie — `TrustSubtypeV1::WebBundleRelease`, `TrustSubtypeV1::WebBundleRevocation`, `WebBundleReleaseCoreV1`, `WebBundleRevocationCoreV1`, `DecodedTrustPayloadV1::WebBundleRelease`, `TrustObjectV1::{subtype, signatures, exact_digest_input, decoded_payload}`, `ea_format::decode_exact_object`, die beiden CDDL-Arme `web-bundle-release-core-v1` und `web-bundle-revocation-core-v1` und die Vektoren unter `vectors/web-bundle/v1/object/`; dazu `TrustAnchorV1::{root_public_cose_key, root_key_thumbprint, root_certificate_object_hash, organization_id}` aus dem entsperrten Vault der Aufgabe „Browser-Vault: PRF-Envelopes, Schlüsselprofil und die Verwahrung von Anchor und KEM-Schlüssel", `PolicyFieldsV1::reader_trust_refresh_ms` über `SelectedRegistryHead::policy_fields`, und die Brücke aus der Aufgabe „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate".
- Produces: `ea_crypto::verify_web_bundle_trust_signature`, `ReaderBundlePin::{from_trust_objects, evaluate, active_bundle_hash}`, `BundleActivationDecisionV1`, `BundleRejectionCodeV1`, `ReaderTrustAgeView`, `BundleActivationView`, der Service Worker von `apps/web` mit seiner Aktivierungsentscheidung, der Abschnitt `bundle-activation` in `docs/traceability/stage-4-fault-points.json`.

Diese Aufgabe wählt und betreibt den getrennten Bundle-Host NICHT — Zielorigin und Betriebsverantwortung sind in `web-reader-design.md` §14, offener Punkt 4, selbst als offen erklärt; sie baut ausschließlich die Trennung selbst und die Positivliste, gegen die sie geprüft wird. Sie behauptet keine PWA-Installation und kein Gate über die Ablehnung eines nicht Root-signierten Bundles: beides weist §12 der Stufe 7 zu. Sie friert keinen Vektor ein und legt keinen neuen an; die Familie ist seit Stufe 3 permanent eingefroren.

- [ ] **Step 1: Write the pinning, revocation and activation witnesses**

```rust
// crates/ea-reader/tests/bundle_release_pinning.rs
//
// Die eingefrorenen Bytes stammen aus `vectors/web-bundle/v1/object/`. Der
// Test baut KEINE neuen Vektoren: die Familie ist seit Stufe 3 eingefroren,
// und die Negativfaelle entstehen im Test, indem einzelne Bytes des positiven
// Vektors gekippt oder Anker ausgetauscht werden.

#[test]
fn a_root_signed_release_pins_its_bundle_hash_against_the_vault_anchor() {
    let pin = ReaderBundlePin::from_trust_objects(
        &fixtures::vault_anchor(),
        &[fixtures::frozen_release_object()],
        RegistryVersion::new(6),
    )
    .unwrap();
    assert_eq!(pin.active_bundle_hash(), Some(fixtures::frozen_bundle_hash()));
    assert!(matches!(
        pin.evaluate(fixtures::frozen_bundle_hash()),
        BundleActivationDecisionV1::Activate { .. }
    ));
    assert_eq!(
        pin.evaluate(fixtures::other_bundle_hash()),
        BundleActivationDecisionV1::KeepActive {
            code: BundleRejectionCodeV1::HashMismatch
        }
    );
}

#[test]
fn an_unsigned_or_foreign_signed_release_never_pins_anything() {
    for (bytes, code) in [
        (fixtures::release_without_signature(), BundleRejectionCodeV1::Unsigned),
        (fixtures::release_signed_by_another_root(), BundleRejectionCodeV1::WrongRoot),
        (fixtures::release_with_one_flipped_signature_byte(), BundleRejectionCodeV1::Unsigned),
    ] {
        let error = ReaderBundlePin::from_trust_objects(
            &fixtures::vault_anchor(),
            &[bytes],
            RegistryVersion::new(6),
        )
        .unwrap_err();
        assert_eq!(error.code(), code);
    }
}

#[test]
fn a_revocation_withdraws_its_release_and_the_last_valid_version_stays_active() {
    let pin = ReaderBundlePin::from_trust_objects(
        &fixtures::vault_anchor(),
        &[
            fixtures::previous_release_object(),
            fixtures::frozen_release_object(),
            fixtures::frozen_revocation_object(),
        ],
        RegistryVersion::new(7),
    )
    .unwrap();
    // Der Widerruf nennt die Freigabe ausschliesslich ueber ihren Objekthash
    // und schreibt sie nie um; wirksam wird er ab seiner eigenen
    // Registry-Version.
    assert_eq!(pin.active_bundle_hash(), Some(fixtures::previous_bundle_hash()));
    assert_eq!(
        pin.evaluate(fixtures::frozen_bundle_hash()),
        BundleActivationDecisionV1::KeepActive {
            code: BundleRejectionCodeV1::Revoked
        }
    );
    // Vor der Wirksamkeit des Widerrufs bleibt die Freigabe gepinnt.
    let earlier = ReaderBundlePin::from_trust_objects(
        &fixtures::vault_anchor(),
        &[fixtures::frozen_release_object(), fixtures::frozen_revocation_object()],
        RegistryVersion::new(6),
    )
    .unwrap();
    assert_eq!(earlier.active_bundle_hash(), Some(fixtures::frozen_bundle_hash()));
}

#[test]
fn an_empty_trust_store_activates_nothing_and_says_so() {
    let pin = ReaderBundlePin::from_trust_objects(
        &fixtures::vault_anchor(),
        &[],
        RegistryVersion::new(6),
    )
    .unwrap();
    assert_eq!(pin.active_bundle_hash(), None);
    assert_eq!(
        pin.evaluate(fixtures::frozen_bundle_hash()),
        BundleActivationDecisionV1::KeepActive {
            code: BundleRejectionCodeV1::NoPinnedRelease
        }
    );
}

#[test]
fn the_age_of_the_last_fetched_trust_state_is_reported_against_the_policy_deadline() {
    let view = reader_trust_age_view(
        UnixMillis::new(1_700_000_000_000),
        UnixMillis::new(1_700_000_600_000),
        fixtures::policy_fields().reader_trust_refresh_ms,
    );
    assert_eq!(view.trust_age_ms, 600_000);
    assert_eq!(view.reader_trust_refresh_ms, fixtures::policy_fields().reader_trust_refresh_ms);
    assert!(view.trust_refresh_overdue);
    // 0 = unset (`schemas/archive/v1/trust.cddl`, Feld `reader-trust-refresh-ms`):
    // ohne Frist gibt es kein Ueberschreiten, aber weiterhin ein ausgewiesenes Alter.
    let unset = reader_trust_age_view(
        UnixMillis::new(1_700_000_000_000),
        UnixMillis::new(1_799_000_000_000),
        0,
    );
    assert!(!unset.trust_refresh_overdue);
    assert_eq!(unset.trust_age_ms, 99_000_000_000);
}
```

```ts
// apps/web/src/sw/service-worker.test.ts
//
// Der Test treibt den Worker ueber seine EXPORTIERTE Entscheidungsfunktion und
// eine Doppelgaengerbruecke. Er rechnet selbst keinen Hash und prueft keine
// Signatur — genau das ist die Aussage.
import { describe, expect, it, vi } from 'vitest'

import { activateCandidate, type BridgePort } from './bundle-pinning'

function bridge(decision: BundleActivationView): BridgePort {
  return { evaluateBundleCandidate: vi.fn().mockResolvedValue(decision) }
}

describe('service worker activation', () => {
  it('activates a candidate only when the bridge answers Activate', async () => {
    const port = bridge({ decision: 'Activate', rejectionCode: null, bundleVersion: '2026.3.1' })
    const result = await activateCandidate(port, { candidateBytes: new Uint8Array([1, 2, 3]) })
    expect(result.activated).toBe(true)
    expect(port.evaluateBundleCandidate).toHaveBeenCalledTimes(1)
  })

  it('discards an unsigned or revoked candidate and keeps the last valid version', async () => {
    for (const rejectionCode of ['Unsigned', 'WrongRoot', 'Revoked', 'HashMismatch'] as const) {
      const port = bridge({ decision: 'KeepActive', rejectionCode, bundleVersion: null })
      const result = await activateCandidate(port, { candidateBytes: new Uint8Array([9]) })
      expect(result.activated).toBe(false)
      expect(result.rejectionCode).toBe(rejectionCode)
    }
  })

  it('carries no hash, signature or trust arithmetic of its own', () => {
    const source = readFileSync(path.join(packageRoot, 'src/sw/service-worker.ts'), 'utf8')
    for (const forbidden of ['crypto.subtle', 'sha', 'Signature', 'verify', 'ed25519']) {
      expect(source.toLowerCase()).not.toContain(forbidden.toLowerCase())
    }
  })
})

// Was dieser Zeuge belegen KANN, und was nicht. Er belegt die CODE-Seite der
// Trennung: das gebaute Buendel adressiert nichts absolut, es laedt jedes
// Beiwerk relativ, und `connect-src` nennt den Sync-Server als KONFIGURIERTEN
// Wert und den Bundle-Origin NICHT. Er belegt NICHT, dass Buendel und
// Sync-Server tatsaechlich auf zwei Hosts liegen — das ist eine Betriebs-
// entscheidung, und dieser Task waehlt und betreibt den Host ausdruecklich
// nicht. Der Bau LAEUFT vor diesem Zeugen (Schritt 2 und Schritt 4 stellen ihn
// voran); ohne ihn laese `readFileSync` auf ein nicht existierendes `dist/`.
it('builds a bundle that addresses nothing absolutely and names no bundle origin', () => {
  const built = readFileSync(path.join(packageRoot, 'dist/index.html'), 'utf8')
  expect(built).not.toMatch(/https?:\/\/[^"']*\/v1\//)
  // Jedes Beiwerk relativ: ein absoluter Beiwerkspfad band das Buendel an
  // genau einen Origin und machte die Trennung unbenutzbar.
  for (const reference of [...built.matchAll(/(?:src|href)="([^"]+)"/g)]) {
    expect(reference[1]).not.toMatch(/^https?:\/\//)
  }
  // Genau EIN entfernter Origin steht in `connect-src`, und es ist der
  // konfigurierte Sync-Server. Der Bundle-Origin steht dort NICHT: ausgefuehrter
  // Code kommt ueber `script-src 'self'` und nie ueber eine Netzverbindung.
  const connect = cspDirectives().find((directive) => directive.startsWith('connect-src '))
  expect(connect).toBeDefined()
  const remotes = connect!.split(/\s+/).filter((value) => /^https?:\/\//.test(value))
  expect(remotes).toEqual([SYNC_SERVER_ORIGIN])
  expect(cspDirectives()).toContain("script-src 'self' 'wasm-unsafe-eval'")
  expect(cspDirectives()).toContain("worker-src 'self'")
})

// Der zweite Teil desselben Belegs liest die QUELLE des Baus statt sein
// Ergebnis: `base: './'` und der ungehashte, eigenstaendige Service-Worker-
// Einstieg sind die zwei Entscheidungen, aus denen die Relativitaet folgt.
it('pins the vite configuration that makes the separation possible', () => {
  const config = readFileSync(path.join(packageRoot, 'vite.config.ts'), 'utf8')
  expect(config).toContain("base: './'")
  expect(config).toMatch(/format:\s*'iife'/)
  expect(config).toMatch(/entryFileNames:\s*'service-worker\.js'/)
})
```

- [ ] **Step 2: Run the witnesses and verify no activation rule exists**

Run:

```bash
cargo test --locked -p ea-reader --test bundle_release_pinning
pnpm --dir apps/web build
pnpm --dir apps/web test --run service-worker
```

`pnpm --dir apps/web build` steht VOR dem Vitest-Lauf und nicht dahinter: zwei der Zusicherungen lesen `apps/web/dist/index.html`, und ohne einen vorangehenden Bau faellt `readFileSync` mit `ENOENT` statt mit einer Aussage ueber die Auslieferung. Ein roter Test aus dem falschen Grund belegt nichts. Derselbe Vorlauf steht aus demselben Grund in Schritt 4.

Expected: FAIL, und die beiden Fehlerbilder sind verschieden. Rustseitig existieren `ReaderBundlePin`, `BundleActivationDecisionV1` und `BundleRejectionCodeV1` nicht, und der tiefere Grund ist gemessen: die Familie hat heute KEINEN Prüfweg. `verify_catalogue_admission` in `crates/ea-trust/src/admission.rs` beantwortet `DecodedTrustPayloadV1::WebBundleRelease` und `::WebBundleRevocation` ausdrücklich mit `TrustError::ActionMismatch`, weil beide die direkte, wurzelsignierte Gestalt tragen und kein zulässiges Ziel einer Admin-Autorisierung sind; und `VerificationContext::root_trust_digest` ist über `root_trust_bindings` auf genau sechs Subtype-Literale geschlossen — `registryEvent`, `deviceCertificate`, `operatorBinding`, `policy`, `writerTransition`, `rootCertificate` — von denen keines dieses ist. Stufe 3 hat Codec, CDDL-Arme und Signaturprofil geliefert und das Aktivierungsverhalten ausdrücklich dieser Stufe überlassen. TypeScript-seitig fehlen `bundle-pinning.ts` und `service-worker.ts` ganz.

- [ ] **Step 3: Implement the root-signature check in Rust and the activation in the worker**

**Umfangsvermerk, ausgeschrieben statt still.** Diese Aufgabe erweitert mit `ea_crypto::verify_web_bundle_trust_signature` eine ABGESCHLOSSENE Stufe-1-Crate um einen neuen öffentlichen Einstieg. Das ist die einzige Stelle der Stufe, an der das geschieht, und es geschieht mit Begründung statt beiläufig: die Signaturprüfung einer Bundle-Freigabe ist eine Kryptooperation, `web-reader-design.md` §9 lässt Kryptographie ausschließlich in geteiltem Rust zu, und `ParsedCoseSign1::verify_with_key` bleibt `pub(crate)` — ein Prüfweg außerhalb von `ea-crypto` müsste entweder diesen rohen Weg öffnen oder COSE ein zweites Mal parsen, und beides wäre schlechter als ein benannter Einstieg. `crates/ea-crypto/src/cose.rs` und `crates/ea-crypto/src/lib.rs` stehen deshalb im Files-Block dieser Aufgabe; kein anderer Task dieser Stufe fasst `crates/ea-crypto` an. Die eingefrorenen Vektoren, die Gate-Reihenfolge und jede bestehende Signatur der Crate bleiben unberührt — es kommt ein Name hinzu, es ändert sich keiner.

Der Prüfweg entsteht in `crates/ea-crypto/src/cose.rs` als EIN neuer, benannter Einstieg — nicht als siebtes Literal in `root_trust_bindings`. Die Begründung ist die Bauform, die dort schon steht: `verify_technical_cursor` prüft bewusst OHNE `VerificationContext` und ohne Zertifikatsauflösung, weil ein technischer Cursor keine Archivaussage ist, sondern die Frage „ist dieses Token meines?". Die Bundle-Freigabe stellt dieselbe Art Frage — „ist dieser Code der, den meine Wurzel freigegeben hat?" —, und sie stellt sie an einem Ort, an dem es keinen Registrierungskopf gibt: der Datei-Modus und der allererste Aufruf haben genau den gepinnten Anker und sonst nichts. `root_trust_bindings` zu erweitern hieße dagegen, die Familie in die Registrierungssemantik zu ziehen, die `verify_catalogue_admission` ihr mit Begründung verweigert, und damit eine Verifikationsreihenfolge zu berühren, die `web-reader-design.md` §1 für diese v1.1-Erweiterung ausdrücklich unverändert lässt.

```rust
/// Prueft die EINE Wurzelsignatur einer Bundle-Freigabe oder ihres Widerrufs
/// gegen den gepinnten Anker.
///
/// Bewusst ohne [`VerificationContext`] und ohne Katalog: die Familie ist kein
/// Gegenstand des Registrierungsabschlusses (`verify_catalogue_admission`
/// antwortet fuer sie `TrustError::ActionMismatch`), und der Datei-Modus hat
/// keinen Registrierungskopf, gegen den ein Zertifikat aufloesbar waere.
pub fn verify_web_bundle_trust_signature(
    bytes: &[u8],
    root_public_key: &CanonicalPublicCoseKey,
    expected_certificate_hash: CertificateHash,
    exact_trust_digest_input: &[u8],
) -> Result<(), CryptoError>;
```

Er parst mit `parse_cose_sign1`, verlangt das Normalprofil und `ContentType::TrustDigest`, vergleicht den Nutzinhalt gegen `trust_digest(exact_trust_digest_input)`, verlangt `certificate_hash == expected_certificate_hash` und `key_thumbprint == root_public_key.thumbprint()`, und prüft dann die Signatur gegen genau diesen Schlüssel. Der Digest-Eingang trägt das Subtype-Literal vor dem Nutzinhalt — `trust_digest_input` in `crates/ea-format/src/etb.rs` setzt es davor —, also trägt eine Signatur über die Freigabe den Widerruf NICHT, und die beiden Domänen trennen sich ohne neue Konstante. `crates/ea-crypto/src/lib.rs` exportiert den Namen; `ParsedCoseSign1::verify_with_key` bleibt `pub(crate)`, und keine Crate außerhalb von `ea-crypto` gewinnt einen rohen Signaturweg.

`crates/ea-reader/src/bundle_release.rs` legt die Regel von §4.2 darüber:

```rust
pub struct ReaderBundlePin { /* opak: nur ueber from_trust_objects konstruierbar */ }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundleRejectionCodeV1 {
    NoPinnedRelease,
    Unsigned,
    WrongRoot,
    WrongOrganization,
    Revoked,
    NotYetEffective,
    HashMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BundleActivationDecisionV1 {
    Activate { bundle_version: String },
    KeepActive { code: BundleRejectionCodeV1 },
}

/// Ein Objekt, das sich als wurzelsignierte Freigabe AUSGIBT und die Pruefung
/// nicht besteht, ist ein Angriff und kein Rauschen: es wird abgewiesen und
/// nicht uebersprungen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReaderBundleError { /* opak */ }

impl ReaderBundleError {
    #[must_use]
    pub fn code(&self) -> BundleRejectionCodeV1;
}

impl ReaderBundlePin {
    pub fn from_trust_objects(
        anchor: &TrustAnchorV1,
        exact_trust_objects: &[&[u8]],
        at_registry_version: RegistryVersion,
    ) -> Result<Self, ReaderBundleError>;

    #[must_use]
    pub fn active_bundle_hash(&self) -> Option<Hash32>;

    #[must_use]
    pub fn evaluate(&self, candidate_bundle_hash: Hash32) -> BundleActivationDecisionV1;
}
```

`from_trust_objects` dekodiert jedes Objekt über `ea_format::decode_exact_object` und den Arm `ParsedArchiveObject::Trust`, nimmt ausschließlich die Subtypen `WebBundleRelease` und `WebBundleRevocation` (alles andere ist kein Fehler, sondern gehört einem anderen Prüfweg), verlangt je Objekt GENAU EINE Signatur — die Kardinalität steht seit Stufe 3 in `validate_signature_count` und wird hier nicht ein zweites Mal erfunden, sondern als bereits geprüft vorausgesetzt und dennoch bezeugt —, prüft sie mit `verify_web_bundle_trust_signature` gegen `anchor.root_public_cose_key()` und `CertificateHash::from(anchor.root_certificate_object_hash())`, und WEIST AB — mit `Err(ReaderBundleError)` und nicht durch Überspringen —, was diese Prüfung nicht besteht oder eine fremde `organization_id` trägt. Der Unterschied ist normativ: ein Objekt eines anderen Subtyps gehört einem anderen Prüfweg und wird still übergangen, ein Objekt DIESER Familie, das seine Wurzelsignatur nicht belegt, ist der Angriff, gegen den §4.1 gebaut ist, und darf nicht als abwesend gelten. Danach gilt: eine Freigabe ist wirksam, wenn `effective_from_registry_version <= at_registry_version`; ein Widerruf ist wirksam unter derselben Bedingung und entfernt die Freigabe, deren `object_hash` — gerechnet mit `ea_crypto::object_hash` über die exakten Objektbytes — seinem `release_object_hash` gleicht. Aktiv bleibt unter den verbleibenden wirksamen Freigaben die mit der höchsten `effective_from_registry_version`; bei Gleichstand die mit dem höheren `issued_at`, und bei erneutem Gleichstand keine, weil zwei gleichzeitig wirksame Freigaben desselben Standes eine Aussage der Wurzel wären, die niemand auflösen darf. Der Verzicht auf ein Widerrufsfeld IM Release ist die Append-only-Entscheidung der Stufe 3 und wird hier ausgenutzt statt umgangen.

`evaluate` ist rein und trifft die Aussage von §4.2 wörtlich: der Service Worker DARF eine neue Bundle-Version nur aktivieren, wenn deren Hash gegen eine gepinnte, Root-signierte `webBundleRelease` aufgeht. Jeder andere Ausgang ist `KeepActive` mit Code, und die zuletzt gültige Version bleibt aktiv. Es gibt keinen Rückgabewert, der „aktivieren, aber mit Warnung" bedeutet.

Ein Punkt bleibt hier ausdrücklich OFFEN und wird nicht stillschweigend entschieden: die WURZELROTATION. `TrustAnchorV1` nennt über `root_certificate_object_hash()` das INITIALE Wurzelzertifikat, und eine Freigabe, die eine rotierte Wurzel unterschrieben hat, geht gegen diesen Anker nicht auf. Solange keine Rotation stattgefunden hat — der Stand dieser Stufe —, ist das Verhalten korrekt und fail-closed: eine solche Freigabe fällt mit `WrongRoot` und die zuletzt gültige Version bleibt aktiv, also verliert niemand Zugriff. Die Auflösung gehört dorthin, wo die Rotation selbst gebaut wird: die Aufgaben der Stufe 5 führen die Wurzelrotationszeremonie, und erst dort steht der aktive Wurzelstand als Kette aus `rootCertificate`-Objekten fest, gegen die eine Freigabe aufgelöst werden könnte. Diese Aufgabe nennt die Lücke, prüft gegen den Anker und erfindet keine Rotationsauflösung.

Die Alterung des Trust-Standes wird nicht erfunden, sondern über das bereits eingefrorene Feld ausgewiesen. `reader_trust_age_view` rechnet `trust_age_ms` als Differenz zwischen dem Zeitpunkt des letzten bezogenen Trust-Standes und dem geprüften `EffectiveNow`, liest die Frist als `PolicyFieldsV1::reader_trust_refresh_ms` aus `SelectedRegistryHead::policy_fields()` und setzt `trust_refresh_overdue` genau dann, wenn die Frist ungleich null ist UND überschritten wurde — `0` heißt „unset", so steht es im Kommentar des CDDL-Felds `reader-trust-refresh-ms`. Die Überschreitung ist eine AUFFORDERUNG zur Aktualisierung und keine Sperre; §4.2 nennt genau diesen Unterschied, weil ein dauerhaft im Datei-Modus betriebenes Gerät einen Widerruf erst beim nächsten Bezug des Trust-Bestandes sieht.

Die beiden Kontrakttypen entstehen in `crates/ea-ui-contracts`, und zwar AUSSCHLIESSLICH im Reader-Ausdruck: `BundleRejectionCodeV1` tritt in `READER_ENUMS_V1` ein, `BundleActivationView` und `ReaderTrustAgeView` bilden den ersten Eintrag der hier angelegten Liste `READER_VIEW_MODELS_V1` (`crates/ea-ui-contracts/src/emit.rs`), die der Task „Integritätszentrierte Reader-Oberfläche in `apps/web` und die Rollengrenze zum Desktop" später erweitert. `SECURITY_ENUMS_V1`, `WRITER_ENUMS_V1` und `VIEW_MODELS_V1` bleiben UNVERÄNDERT, und `apps/desktop/src/bridge/generated-contracts.ts` ändert sich in diesem Task nicht — ein neues Literal dort färbte `apps/desktop/src/bridge/no-hand-written-contracts.test.ts` rot, ohne dass eine Desktop-Entscheidung dahinterstünde; und `crates/ea-ui-contracts/src/lib.rs` re-exportiert die Aufzählung aus der Crate, in der sie definiert ist, statt sie ein zweites Mal zu erklären — dieselbe Regel, die dort für `QuarantineReason`, `SignerRole` und `LocalAuditOutcomeV1` gilt. `BundleRejectionCodeV1` ist in `crates/ea-reader/src/bundle_release.rs` definiert, also bekommt `crates/ea-ui-contracts/Cargo.toml` dafür die Kante `ea-reader.workspace = true`; sie steht mit `Cargo.lock` im Files-Block, weil eine neue Kante zwischen zwei Mitgliedern das Lockfile fortschreibt. Die Richtung ist dieselbe einseitige wie bei `ea-verify` im Task „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate": `ea-ui-contracts` steht in `WASM32_EXEMPT_CRATES`, weil `src/bin/emit-ts.rs` Dateien schreibt, `ea-reader` steht auf der Positivliste, und keine Kante läuft zurück. Die Wurzelkante trägt `default-features = false`, das Merkmal `test-support` von `crates/ea-reader` bleibt damit AUS. Danach läuft `cargo run --locked -p ea-ui-contracts --bin emit-ts` und schreibt `apps/web/src/bridge/generated-contracts.ts` neu; `the_checked_in_file_is_exactly_what_the_emitter_writes` hält den Ausdruck. `apps/web/src/sw/bundle-pinning.ts` und `service-worker.ts` importieren die Literale ausschließlich von dort und wiederholen keines als Zeichenkette, sonst schlägt der aus `apps/desktop` portierte `no-hand-written-contracts.test.ts` an.

Der Worker selbst enthält KEINE Sicherheitslogik. `bundle-pinning.ts` exportiert `activateCandidate(port, candidate)`, reicht die Kandidatenbytes über die wasm-bindgen-Brücke (`crates/ea-reader-wasm/src/bridge.rs`, neue Ausfuhr `evaluate_bundle_candidate` unter `cfg(target_arch = "wasm32")`) an `ReaderBundlePin::evaluate` und wendet auf die Antwort genau zwei Wirkungen an: bei `Activate` `skipWaiting`/`clients.claim` und das Umschalten des Cache-Namens auf die neue `bundleVersion`, bei `KeepActive` das Verwerfen des Kandidaten und das Behalten des bestehenden Caches. Hash und Signatur werden in Rust gerechnet; TypeScript sieht das DTO. Der Quelltextscan im ersten Schritt ist der Wächter dieser Grenze und keine Stilregel.

**Die Richtlinie bewegt sich HIER und nirgends sonst, und ihr Pin zieht im selben Commit nach.** `apps/web/index.html` trägt seit der Aufgabe „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate" die Richtlinie als `<meta http-equiv="Content-Security-Policy">` mit `connect-src 'self'`, und `apps/web/src/app/csp.test.ts` pinnt sie Position für Position. Diese Aufgabe bewegt GENAU EINE Position: `connect-src` bekommt neben `'self'` die KONFIGURIERTE Herkunft des Sync-Servers. Zwei Stellen von `csp.test.ts` ziehen zeichengleich mit: der Eintrag `"connect-src 'self'"` in `EXPECTED_DIRECTIVES` wird zu `connect-src 'self'` gefolgt von genau diesem Origin, und die Zusicherung `expect(directives().join('; ')).not.toMatch(/https?:/)` des Zeugen `keeps the OPFS worker reachable and admits no remote origin` wird durch die schärfere ersetzt, die dieser Task wirklich meint — GENAU EINE entfernte Herkunft steht in der ganzen Richtlinie, sie steht in `connect-src`, und sie ist NICHT der Bundle-Origin. Beide Dateien stehen deshalb im Files-Block dieser Aufgabe und in keinem anderen: `apps/web/src/sw/service-worker.test.ts` verlangt mit `expect(remotes).toEqual([SYNC_SERVER_ORIGIN])` das Gegenteil dessen, was der alte Pin behauptet, und beide laufen in DEMSELBEN `pnpm --dir apps/web test --run`. Die Aufgabe „Inkrementeller Reader-Sync und verifizierter Cursor-Fortschritt in OPFS" ist der erste NUTZER dieser Herkunft und fasst weder die Richtlinie noch ihren Pin an.

`apps/web/src/main.tsx` steht aus dem zweiten Grund im Files-Block: der Trust-Alter-Streifen `TrustAgeBanner.tsx` und die Registrierung des Service Workers werden an die Routentabelle und die Schale gehängt, die dieselbe Aufgabe von Anfang an ausliefert. `apps/web/tests/e2e/bundle-activation.spec.ts` fährt genau diese montierte Schale an.

`apps/web/vite.config.ts` trägt die Trennung des Auslieferungswegs nach §4.1: `base: './'` erzwingt ausschließlich relative Beiwerkspfade — ein absoluter Pfad bände das Bündel an genau einen Origin und machte die Trennung unbenutzbar —, der Service Worker wird als eigener Rollup-Einstieg mit `format: 'iife'` und `entryFileNames: 'service-worker.js'`, also stabilem Dateinamen ohne Hash, gebaut — ein gehashter Workername wäre bei jedem Bau ein anderer Registrierungspfad und damit ein Aktivierungspfad, den die Pinnung nicht sieht —, und die CSP-Grundlinie ergänzt gegenüber dem Desktop genau zwei Positionen: `script-src 'self' 'wasm-unsafe-eval'`, weil `WebAssembly.instantiate` ohne dieses Schlüsselwort blockiert, und `worker-src 'self'`. `connect-src` nennt den Sync-Server-Origin als konfigurierten Wert und den Bundle-Origin NICHT; das ist die Umkehrung derselben Aussage, die serverseitig als Origin-Positivliste in Stufe 3 steht. Der Sync-Server ist damit kein Bestandteil des Vertrauenspfades für ausgeführten Code.

`docs/traceability/stage-4-fault-points.json` entsteht hier — diese Aufgabe ist in der Reihenfolge dieses Plans die erste, die das Manifest anfasst — mit `"stage": 4` und genau dem Abschnitt `bundle-activation`, in der Gestalt von `docs/traceability/stage-3-fault-points.json`: je Punkt `name`, `brackets` und `witness`, und jeder `witness` nennt einen Test, der existiert und läuft. Die vier Punkte sind `unsigned-candidate`, `foreign-root-candidate`, `revoked-release` und `stale-trust-state`. Die Aufgabe „Inkrementeller Reader-Sync und verifizierter Cursor-Fortschritt in OPFS" ERGÄNZT dieselbe Datei um ihren Abschnitt `sync-cursor` und schreibt sie nicht neu; die Aufgabe „Reader-Interoperabilität, Browser-Matrix, Datei-Modus, Privatheit und das Stufe-4-Gate" schließt sie, indem sie jeden Zeugen auflöst.

- [ ] **Step 4: Run the pinning, the worker and the activation end to end**

Run:

```bash
cargo metadata --format-version 1
cargo test --locked -p ea-crypto
cargo test --locked -p ea-reader --test bundle_release_pinning
cargo test --locked -p ea-ui-contracts
cargo run --locked -p ea-ui-contracts --bin emit-ts
pnpm --dir apps/web build
pnpm --dir apps/web test --run
pnpm --dir apps/web exec playwright test tests/e2e/bundle-activation.spec.ts
```

`cargo metadata --format-version 1` steht als ERSTE Zeile und ist das GENAU EINE Kommando dieses Tasks ohne `--locked`: Schritt 3 gibt `crates/ea-ui-contracts/Cargo.toml` die Kante `ea-reader.workspace = true`, und eine neue Kante zwischen zwei Mitgliedern schreibt `Cargo.lock` fort. Es steht NACH der Registrierung und VOR jedem `--locked`-Kommando; in Schritt 2 stuende es vor seinem Gegenstand.

`pnpm --dir apps/web build` steht VOR `pnpm --dir apps/web test --run`, weil die zwei Zeugen der Auslieferungstrennung `apps/web/dist/index.html` lesen; in der umgekehrten Reihenfolge pruefen sie den Ausgang des VORIGEN Laufs oder gar keinen.

Expected: PASS. Die adversarialen Fälle sind die tragenden: ein Release mit gekipptem Signaturbyte fällt mit `Unsigned`; ein Release, das eine ANDERE, für sich wohlgeformte Wurzel unterschrieben hat, fällt mit `WrongRoot` und nicht mit `HashMismatch` — die Unterscheidung ist der ganze Punkt von §4.1, weil ein kompromittierter Sync-Server genau diesen Tausch versuchen würde; ein Release mit fremder `organization_id` fällt mit `WrongOrganization`, obwohl seine Signatur trägt; der eingefrorene Widerruf entzieht ab seiner eigenen Registry-Version genau die Freigabe, deren Objekthash er nennt, und lässt die vorherige aktiv, statt gar nichts aktiv zu lassen; ein leerer Trust-Store aktiviert NICHTS und sagt `NoPinnedRelease`, statt in einen Vorgabefall zu fallen; und der Playwright-Lauf serviert Bundle und Sync-Server auf zwei verschiedenen Origins, schiebt dem Worker nacheinander ein signiertes, ein unsigniertes und ein widerrufenes Kandidatenbundle unter und weist nach, dass nach den beiden Ablehnungen dieselbe Version aktiv ist wie davor und das Banner das Alter des zuletzt bezogenen Trust-Standes samt Frist als TEXT ausweist, nicht als Farbe oder Symbol.

- [ ] **Step 5: Commit the bundle pinning and its activation gate**

```bash
git add crates/ea-crypto crates/ea-reader crates/ea-reader-wasm crates/ea-ui-contracts \
        apps/web docs/traceability/stage-4-fault-points.json Cargo.lock
git commit -m "feat(reader): activate only pinned root-signed web bundles"
```

### Task 7: Inkrementeller Reader-Sync und verifizierter Cursor-Fortschritt in OPFS (formerly Task 2)

**Files:**
- Create: `crates/ea-reader/src/sync.rs`
- Create: `crates/ea-reader/src/cursor.rs`
- Create: `crates/ea-reader/src/batch.rs`
- Create: `crates/ea-reader/src/http.rs`
- Create: `crates/ea-reader-wasm/src/fetch.rs`
- Create: `apps/web/src/sync/transport.ts`
- Create: `apps/web/src/sync/transport.test.ts`
- Modify: `docs/traceability/stage-4-fault-points.json`
- Test: `crates/ea-reader/tests/sync_resume.rs`
- Test: `crates/ea-reader/tests/sync_attacks.rs`
- Modify: `crates/ea-reader/src/lib.rs`
- Modify: `crates/ea-reader-wasm/src/lib.rs`
- Modify: `crates/ea-reader/Cargo.toml`
- Modify: `Cargo.lock`

Dieser Task zieht GENAU EINE neue Kante, `ea-archive`, und deshalb stehen `crates/ea-reader/Cargo.toml` und `Cargo.lock` im Files-Block. Der Grund ist gemessen: `ea_verify::verify_archive_observed` nimmt als erstes Argument `&dyn ArchiveSource` (`crates/ea-verify/src/archive.rs`), und `crates/ea-verify/src/lib.rs` re-exportiert aus `ea-archive` NICHTS — die einzige Fremd-Wiederausfuhr dort ist `ea_format::ObjectTypeV1`, der `pub use archive::{…}` daneben meint das GLEICHNAMIGE eigene Modul von `ea-verify` und nicht die Crate `ea-archive`. Dieser Task muss den Typ also selbst benennen, um dem Verifizierer den Objektcache als Quelle zu reichen; ohne die Kante uebersetzt Schritt 3 nicht. `ea-sync-protocol` traegt `crates/ea-reader/Cargo.toml` bereits seit dem Task „Browser-Enrollment: zwei Pflicht-Authenticators und das nicht überspringbare Fingerprint-Gate", `ea-verify`, `ea-trust` und `ea-types` seit den Tasks „wasm32-Reichweite: `ea-reader`, die Brücken-Crate und die geteilten Browserkerne" und „Browser-Vault: PRF-Envelopes, Schlüsselprofil und die Verwahrung von Anchor und KEM-Schlüssel"; neu ist hier ausschliesslich `ea-archive`.

`docs/traceability/stage-4-fault-points.json` wird vom Task „Web-Bundle: getrennter Origin, Service Worker, gepinnte `webBundleRelease` und das Alter des Trust-Standes" ANGELEGT — er ist in der Reihenfolge dieses Plans der erste, der sie anfasst — und von diesem Task sowie von zwei spaeteren um weitere Abschnitte ERGAENZT. Wer nach dem Ersten kommt, fuegt seinen Abschnitt hinzu und ueberschreibt die Datei nie; `docs/traceability/stage-3-fault-points.json` traegt aus demselben Grund fuenf getrennte Abschnittsschluessel statt einer flachen Liste. `apps/web/src/sync/transport.test.ts` steht nicht in der Grobzuordnung und gehoert hierher: `apps/web/src/bridge/no-hand-written-contracts.test.ts` (angelegt im Task „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate") laesst eine Zusicherung ueber die gerenderte Zeichenkette nur in einer `.test.ts` zu, und die Zusage „TypeScript baut keinen Signaturheader" braucht einen TypeScript-Zeugen.

**Interfaces:**
- Consumes: `ea_sync_protocol::{ReaderBatchV1, ObjectRecordV1, EndpointV1, RequestSigner, RequestParts, SignatureParametersV1, RequestIdV1, HttpMethod, SIGNATURE_LABEL_V1, REQUEST_ID_HEADER_V1, body_digest, content_digest_header, organization_tag, MAX_READER_PAGE_OBJECTS_V1, MAX_READER_PAGE_BYTES_V1}` — seit dem Task „wasm32-Reichweite: `ea-reader`, die Brücken-Crate und die geteilten Browserkerne" von wasm32 aus erreichbar; `ea_verify::{verify_archive_observed, VerifyOptions, VerificationReportV1, ChainHeadV1, ChainGapV1}`; `ea_trust::TrustAnchorV1` und den Ed25519-Geraeteschluessel, beide ausschliesslich aus der entsperrten Vault-Sitzung des Tasks „Browser-Vault: PRF-Envelopes, Schlüsselprofil und die Verwahrung von Anchor und KEM-Schlüssel"; `ReaderBlobStore` und seine In-Memory-Doppelung; `ReaderObjectCache` fuer die verschluesselte Ablage exakter Objektbytes; `ea_archive::{ArchiveSource, ArchiveBlob, ArchiveError}` — die NEUE Kante dieses Tasks. `ReaderObjectCache` implementiert `ArchiveSource` ueber die dauerhaft abgelegten exakten Bytes: `visit_blobs` reicht jedes entschluesselte Objekt als `ArchiveBlob<'_>` an den Besucher weiter, und genau diese Implementierung bekommt `verify_archive_observed` als `&dyn ArchiveSource`. Die Datei-Modus-Varianten sind eine ZWEITE, getrennte Implementierung derselben Eigenschaft und entstehen erst im Task „Datei-Modus: Einzeldatei-Bündel, Verzeichnis-Handle, kein Cursor, `nicht server-bestätigt`" als `ReaderArchiveSourceV1`; hier entsteht kein Vorgriff darauf.
- Produces: `ConfirmedCursor`, `VerifiedSyncBatch`, `ReaderSyncService::{next_request, accept_batch, confirm, rebuild_from_genesis}`, `ReaderSyncError` mit seinen stabilen Codes, `ReaderSyncFaultPoint::ALL`, den Abschnitt `sync-cursor` in `docs/traceability/stage-4-fault-points.json` und den Bruecken-Export `readerSyncNextRequest`/`readerSyncAcceptBatch`.

Der Vertrag der frueheren Fassung gilt WOERTLICH weiter: Kettenkennung, hoechste zusammenhaengend verifizierte Sequenz, deren Entry-Hash und der undurchsichtige Cursor gehen hinaus; die Antwort MUSS genau diesen Startkopf binden; der naechste Cursor wird erst persistiert, wenn jedes Objektbyte dauerhaft ist UND die Kette bis zum Batchende verifiziert; Abbruch bei fehlendem Objekt, Luecke, Fork oder falschem Startkopf; nach Cacheverlust Wiederaufbau ab Genesis oder ab einem LOKAL verifizierten Checkpoint. Ersetzt werden nur Ablage und Transport: SQLCipher weicht dem verschluesselten OPFS-Speicher (§8.1), der Tokio-HTTP-Klient dem Browser-`fetch` hinter einem Rust-Port. Dieser Task deckt AUSSCHLIESSLICH den Server-Modus ab; im Datei-Modus entfaellt der Cursor-Mechanismus nach §5.4 ersatzlos, und der Task „Datei-Modus: Einzeldatei-Bündel, Verzeichnis-Handle, kein Cursor, `nicht server-bestätigt`" fasst ihn deshalb nicht an.

- [ ] **Step 1: Write interruption, start-head and fault-point tests**

```rust
// crates/ea-reader/tests/sync_resume.rs
use ea_reader::{ConfirmedCursor, ReaderSyncFaultPoint, ReaderSyncService};

/// Jeder Abbruchpunkt einzeln, und nach jedem ein NEU GEOEFFNETER Speicher.
/// Der Wiederaufbau aus denselben Bytes ist die Aussage — ein Dienst, der
/// seinen Cursor im Prozessspeicher haelt, waere hier gruen und im Browser rot,
/// sobald ein Tab schliesst.
#[test]
fn the_cursor_moves_only_after_every_object_is_durable_and_the_chain_verifies() {
    for fault in ReaderSyncFaultPoint::ALL {
        let mut harness = ReaderSyncHarness::with_two_batches();
        let before = harness.confirmed_cursor();
        let _ = harness.pull_with_fault(fault);
        let reopened = harness.reopen_store();
        assert_eq!(
            reopened.confirmed_cursor(),
            before,
            "{} advanced the cursor across an interruption",
            fault.name()
        );
        reopened.pull().unwrap();
        assert_eq!(reopened.confirmed_head(), fixtures::batch_end_head());
    }
}

/// Wiederholen ist idempotent: derselbe Batch ein zweites Mal legt keine
/// zweiten Bytes ab und bewegt den Cursor nicht weiter.
#[test]
fn a_repeated_batch_writes_no_second_byte_and_moves_nothing() {
    let mut harness = ReaderSyncHarness::with_two_batches();
    let first = harness.pull().unwrap();
    let bytes_after_first = harness.blob_store_byte_count();
    let second = harness.pull_same_batch_again().unwrap();
    assert_eq!(first, second);
    assert_eq!(harness.blob_store_byte_count(), bytes_after_first);
}

/// Cacheverlust: der Speicher ist leer, der gepinnte Anchor ist es nicht. Der
/// Wiederaufbau laeuft ab Genesis und endet auf DEMSELBEN Kopf.
#[test]
fn a_lost_cache_rebuilds_from_genesis_to_the_same_head() {
    let mut harness = ReaderSyncHarness::with_two_batches();
    harness.pull().unwrap();
    let head = harness.confirmed_head();
    let rebuilt = harness.erase_blob_store().rebuild_from_genesis().unwrap();
    assert_eq!(rebuilt.entry_hash(), head.entry_hash());
    assert_eq!(rebuilt.sequence(), head.sequence());
}
```

```rust
// crates/ea-reader/tests/sync_attacks.rs
use ea_reader::ReaderSyncError;

/// Die vier Abbruchgruende, jeder mit seinem eigenen Code und jeder OHNE
/// Cursorfortschritt. Ein gemeinsamer Sammelcode waere hier der Defekt: eine
/// Luecke ist eine Aussage ueber den Bestand, ein Fork eine ueber den Server.
#[test]
fn every_refusal_carries_its_own_code_and_leaves_the_cursor_where_it_was() {
    for (batch, code) in [
        (fixtures::batch_for_a_different_start_head(), "EA-READER-START-HEAD-MISMATCH"),
        (fixtures::batch_with_a_missing_object(), "EA-READER-MISSING-OBJECT"),
        (fixtures::batch_with_a_sequence_gap(), "EA-READER-CHAIN-GAP"),
        (fixtures::batch_forking_at_the_head(), "EA-READER-CHAIN-FORK"),
    ] {
        let mut harness = ReaderSyncHarness::with_two_batches();
        let before = harness.confirmed_cursor();
        assert_eq!(harness.accept(batch).unwrap_err().code(), code);
        assert_eq!(harness.confirmed_cursor(), before);
        assert_eq!(harness.reopen_store().confirmed_cursor(), before);
    }
}

/// Der Startkopf wird gegen den EIGENEN bestaetigten Cursor geprueft und nicht
/// gegen das, was die Antwort ueber sich selbst sagt. Deshalb ist ein Batch,
/// der in sich stimmig ist und an einem fremden Kopf ansetzt, eine Abweisung.
#[test]
fn a_self_consistent_batch_at_a_foreign_head_is_still_refused() {
    let harness = ReaderSyncHarness::with_two_batches();
    let foreign = fixtures::internally_valid_batch_at_sequence(41);
    assert_eq!(
        harness.accept(foreign).unwrap_err().code(),
        "EA-READER-START-HEAD-MISMATCH"
    );
}

/// Kein Signaturheader entsteht ausserhalb von `RequestSigner`. Der Zeuge liest
/// den Request, den die Bruecke herausgibt, und verlangt beide Kopfzeilen samt
/// dem Label `ea1` und der Nonce, die in `signature-input` steht.
#[test]
fn the_pull_request_is_signed_with_the_vault_ed25519_key() {
    let harness = ReaderSyncHarness::with_two_batches();
    let request = harness.next_request().unwrap();
    let header = |name: &str| request.headers.iter().find(|(key, _)| *key == name).unwrap().1.clone();
    assert!(header("signature-input").starts_with("ea1=("));
    assert!(header("signature").starts_with("ea1=:"));
    assert!(request.target.starts_with("/v1/chains/"));
    assert_eq!(request.method, ea_sync_protocol::HttpMethod::Get);
}
```

- [ ] **Step 2: Run the sync tests and verify the service is absent**

Run: `cargo test --locked -p ea-reader --test sync_resume --test sync_attacks`

Expected: FAIL. `ReaderSyncService`, `ConfirmedCursor`, `VerifiedSyncBatch` und `ReaderSyncFaultPoint` existieren nicht; `crates/ea-reader` traegt nach dem Vault-Task nur Tresor, Schluesselprofil, Cache und technischen Eintragszustand. Kein Test in dieser Datei kann ueberhaupt uebersetzen, und das ist die richtige Form des Fehlschlags: eine Fassung, die schon uebersetzte und nur falsch antwortete, haette bereits eine Cursorentscheidung getroffen.

- [ ] **Step 3: Implement durable batch processing over the encrypted blob store**

```rust
// crates/ea-reader/src/cursor.rs
pub struct ConfirmedCursor {
    chain_id: ChainId,
    sequence: ChainSequence,
    entry_hash: EntryHash,
    technical_cursor: Option<Vec<u8>>,
}
impl ConfirmedCursor {
    #[must_use] pub fn genesis(anchor: &TrustAnchorV1) -> Self;
    #[must_use] pub const fn sequence(&self) -> ChainSequence;
    #[must_use] pub const fn entry_hash(&self) -> EntryHash;
    #[must_use] pub fn technical_cursor(&self) -> Option<&[u8]>;
}

// crates/ea-reader/src/batch.rs — Konstruktor bewusst pub(crate).
pub struct VerifiedSyncBatch { /* head, next_cursor, object_hashes, report */ }
impl VerifiedSyncBatch {
    #[must_use] pub const fn head(&self) -> ChainHeadV1;
    #[must_use] pub fn next_cursor(&self) -> Option<&[u8]>;
    #[must_use] pub fn object_hashes(&self) -> &[ObjectHash];
    #[must_use] pub const fn report(&self) -> &VerificationReportV1;
}

// crates/ea-reader/src/http.rs — der Request, den TypeScript nur noch abschickt.
pub struct ReaderRequestV1 {
    pub method: HttpMethod,
    pub authority: String,
    pub target: String,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

// crates/ea-reader/src/sync.rs — SYNCHRON, in zwei Haelften geschnitten.
pub enum ReaderSyncError {
    StartHeadMismatch, MissingObject, ChainGap, ChainFork,
    Protocol, Store, Verification, Transport,
}
impl ReaderSyncError { #[must_use] pub const fn code(self) -> &'static str; }

pub struct ReaderSyncService<'a> { /* anchor, signer, cache, blob store, clock */ }
impl ReaderSyncService<'_> {
    pub fn next_request(&self, cursor: &ConfirmedCursor)
        -> Result<ReaderRequestV1, ReaderSyncError>;
    pub fn accept_batch(&self, cursor: &ConfirmedCursor, response_body: &[u8])
        -> Result<VerifiedSyncBatch, ReaderSyncError>;
    pub fn confirm(&self, batch: VerifiedSyncBatch)
        -> Result<ConfirmedCursor, ReaderSyncError>;
    pub fn rebuild_from_genesis(&self) -> Result<ConfirmedCursor, ReaderSyncError>;
}

pub enum ReaderSyncFaultPoint { /* zwoelf Varianten */ }
impl ReaderSyncFaultPoint {
    pub const ALL: [Self; 12];
    #[must_use] pub const fn name(self) -> &'static str;
}
```

Der Schnitt in `next_request` / `accept_batch` / `confirm` ist die tragende Entscheidung dieses Tasks und keine Bequemlichkeit. `crates/ea-sync-client` loest dieselbe Aufgabe mit `#[async_trait] SyncTransportV1` ueber Tokio und steht genau deshalb in `WASM32_EXEMPT_CRATES` („drives a signed HTTP client with Tokio … on top of the local archive directory"); eine Kante von `ea-reader` dorthin waere eine Kante von der Positivliste auf die Ausnahmeliste und faellt sofort. Im Browser ist `fetch` ein Promise, und ein async-Rust-Kern zoege eine zweite Laufzeit in das WASM-Modul. Stattdessen bleibt `crates/ea-reader` synchron wie der ganze Rust-Kern, gibt einen FERTIG SIGNIERTEN `ReaderRequestV1` heraus und nimmt die Antwortbytes zurueck. `apps/web/src/sync/transport.ts` ruft `fetch` und reicht `Uint8Array` durch; es baut keine Kopfzeile, liest keinen Status als Vertrauensaussage und trifft keine Entscheidung — §9 woertlich.

Der Startkopf wird gegen den EIGENEN `ConfirmedCursor` geprueft, nie gegen die Selbstauskunft der Antwort: `ReaderBatchV1::requested_after_sequence`, `::requested_after_entry_hash` und `::start_head_entry_hash` muessen alle drei zu `cursor.sequence()` und `cursor.entry_hash()` passen, sonst `EA-READER-START-HEAD-MISMATCH`, und zwar BEVOR ein einziges Objektbyte den Speicher erreicht. Die Zaehl- und Bytegrenzen des Rahmens (`MAX_READER_PAGE_OBJECTS_V1`, `MAX_READER_PAGE_BYTES_V1`) setzt `ReaderBatchV1::decode` bereits durch; sie werden hier nicht ein zweites Mal geschrieben.

Danach in dieser Reihenfolge: jedes `ObjectRecordV1` unter seinem `object_hash` in den verschluesselten Objektcache legen und den Blobspeicher flushen; dann `verify_archive_observed` gegen den Vault-gepinnten `TrustAnchorV1` ueber den GESAMTEN lokalen Bestand laufen lassen, nicht nur ueber die neuen Bytes — eine Kette verifiziert an ihrem Kopf und nicht an einer Seite; erst wenn `report.gaps().len() == 0` gilt und `report.chain_head()` die Endsequenz des Batches traegt, den naechsten Cursor schreiben. Eine nichtleere `gaps()`-Menge ist `EA-READER-CHAIN-GAP`, ein Kopf, der auf einer schon bestaetigten Sequenz einen anderen Entry-Hash traegt, ist `EA-READER-CHAIN-FORK`, ein im Rahmen angekuendigtes und im Cache fehlendes Objekt ist `EA-READER-MISSING-OBJECT`. Fehlender eigener Grant ist HIER kein Fehler und wird hier auch nicht bewertet; die Klassifikation gehoert dem Task „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert". Es wird in diesem Task NICHTS entschluesselt: `VerifyOptions::new(os_wall_clock)` ohne Empfaengerschluessel ist der Lauf, den dieser Task fuehrt.

`ReaderSyncFaultPoint::ALL` traegt zwoelf Punkte in Ablaufreihenfolge, gebaut wie `MigrationFaultPoint::ALL` in `crates/ea-archive-fs/src/profile_migration.rs` (dort vierzehn): `BeforeBatchRequest`, `AfterBatchRequest`, `BeforeStartHeadCheck`, `AfterStartHeadCheck`, `BeforeObjectWrite`, `AfterFirstObjectWrite`, `BeforeBlobStoreFlush`, `AfterBlobStoreFlush`, `BeforeChainVerification`, `AfterChainVerification`, `BeforeCursorPersist`, `AfterCursorPersist`. Dazu kommen die zwei browser-eigenen Punkte, die es auf dem Desktop nicht gab und die in `docs/traceability/stage-4-fault-points.json` unter `sync-cursor` je einen benannten Zeugen bekommen: ein Tab, der MITTEN im Batch schliesst — modelliert als Fallenlassen des Dienstes zwischen `AfterFirstObjectWrite` und `BeforeCursorPersist` —, und ein OPFS-Schreibvorgang, den die Speicherbereinigung des Browsers abbricht, modelliert als `ReaderBlobStore`-Doppel, das ab dem n-ten Byte `QuotaExceeded` liefert. Beide MUESSEN denselben Ausgang haben wie jeder andere Abbruch: der Cursor steht danach dort, wo er vorher stand, und der naechste Lauf holt den Batch erneut.

Der Abschnitt `sync-cursor` folgt zeichenweise der Form von `docs/traceability/stage-3-fault-points.json` — je Eintrag `name`, `brackets`, `witness`, und `witness` nennt eine Testfunktion mit vollem Pfad, etwa `crates/ea-reader/tests/sync_resume.rs::the_cursor_moves_only_after_every_object_is_durable_and_the_chain_verifies`. Der Gate-Task assertiert spaeter, dass jeder genannte Zeuge existiert und gruen ist; ein Eintrag ohne Zeugen ist genau die Zeile, die dort faellt.

Der RFC-9421-Signaturschluessel ist der Ed25519-Geraete- und Auditschluessel aus §6.1 und kommt AUSSCHLIESSLICH aus der entsperrten Vault-Sitzung. `RequestSigner::from_secret(SecretBytes<32>)` nimmt ihn entgegen; die Abdeckung bleibt die des Stufe-3-Profils — `@method`, `@authority`, `@target-uri`, `content-type` und `content-digest` nur bei vorhandenem Koerper, `ea-request-id`, `created`, `expires`, `nonce`, `keyid`, `alg=ed25519` und der organisationsgebundene `tag` aus `organization_tag`. Der Pfad kommt aus `EndpointV1::ChainEntries::path_template()` (`/v1/chains/{chainId}/entries`) mit den drei Abfrageparametern `afterSequence`, `afterEntryHash` und `cursor`; er wird nicht als Literal ein zweites Mal geschrieben. Ist der Tresor gesperrt, entsteht GAR KEIN Request: `next_request` liefert dann `EA-READER-STORE`, und ein Sync im gesperrten Zustand ist damit keine Netzanfrage ohne Signatur, sondern gar keine Anfrage.

`crates/ea-reader-wasm/src/fetch.rs` exportiert genau zwei Funktionen ueber die Bruecke, beide unter `cfg(target_arch = "wasm32")`: `readerSyncNextRequest` liefert den serialisierten `ReaderRequestV1`, `readerSyncAcceptBatch` nimmt die Antwortbytes und liefert das Ergebnis-DTO. Es entsteht kein dritter Export, der Bytes ohne Cursorpruefung annaehme.

- [ ] **Step 4: Run every fault point, both attack files and the transport witness**

Run:

```bash
cargo metadata --format-version 1
cargo test --locked -p ea-reader --test sync_resume --test sync_attacks -- --test-threads=1
cargo test --locked -p ea-reader
pnpm --dir apps/web test --run transport
```

`cargo metadata --format-version 1` steht als ERSTE Zeile und ist das GENAU EINE Kommando dieses Tasks ohne `--locked`: Schritt 3 gibt `crates/ea-reader/Cargo.toml` die Kante auf `ea-archive`, eine neue Kante zwischen zwei Mitgliedern schreibt `Cargo.lock` fort, und jedes `--locked`-Kommando davor stuerbe an „the lock file needs to be updated but --locked was passed". Es steht NACH der Registrierung und VOR jedem `--locked`-Kommando, genau wie es `workspace_declares_exact_planned_members_and_shared_dependencies` (`tools/xtask/tests/workspace.rs`) fuer den eintragenden Task verlangt.

Expected: PASS. Alle zwoelf Abbruchpunkte lassen den Cursor stehen, der Wiederholversuch ist idempotent, und keiner der vier Abweisungsgruende bewegt Zustand. Die adversariale Gegenprobe ist dreiteilig und MUSS jedes Mal rot werden: (1) die Cursorpersistenz VOR `verify_archive_observed` ziehen — `the_cursor_moves_only_after_every_object_is_durable_and_the_chain_verifies` faellt an `BeforeChainVerification` und `AfterChainVerification`, weil ein wiedereroeffneter Speicher dann einen Cursor traegt, dessen Kette nie geprueft wurde; (2) den Startkopfvergleich gegen `ReaderBatchV1::start_head_entry_hash` statt gegen den eigenen `ConfirmedCursor` fuehren — `a_self_consistent_batch_at_a_foreign_head_is_still_refused` faellt, und genau dieser Fehler waere in einer Fassung, die nur den fremden Batch gegen sich selbst prueft, unsichtbar; (3) den Signaturheader in `apps/web/src/sync/transport.ts` bauen statt ihn aus `ReaderRequestV1` zu uebernehmen — `the_pull_request_is_signed_with_the_vault_ed25519_key` bleibt gruen, `apps/web/src/bridge/no-hand-written-contracts.test.ts` faellt, und deshalb steht der zweite Zeuge auf der TypeScript-Seite und nicht in Rust.

- [ ] **Step 5: Commit incremental Reader sync**

```bash
git add crates/ea-reader crates/ea-reader-wasm apps/web/src/sync docs/traceability/stage-4-fault-points.json Cargo.lock
git commit -m "feat(reader): verify incremental sync before the OPFS cursor advances"
```

### Task 8: Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert (formerly Task 3)

**Files:**
- Create: `crates/ea-reader/src/anchor.rs`
- Create: `crates/ea-reader/src/verify.rs`
- Create: `crates/ea-reader/src/grant.rs`
- Create: `crates/ea-reader/src/decrypt.rs`
- Modify: `crates/ea-reader/src/lib.rs`
- Modify: `crates/ea-reader/Cargo.toml`
- Modify: `crates/ea-reader-wasm/Cargo.toml`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `docs/traceability/stage-4-fault-points.json`
- Test: `crates/ea-reader/tests/verification_order.rs`
- Test: `crates/ea-reader/tests/missing_grant.rs`
- Test: `crates/ea-reader/tests/historical_expiry.rs`
- Test: `crates/ea-reader/tests/destroyed_stub.rs`
- Test: `crates/ea-reader/tests/pinned_anchor.rs`
- Test: `crates/ea-reader-wasm/tests/verify_browser.rs`

**Interfaces:**
- Consumes: `ea_verify::{verify_archive_observed, VerifyOptions, RecipientKeyV1, GATE_ORDER_V1, DECAPSULATION_EVENT_V1, GateObserver, RecordingObserver, VerificationReportV1, ObjectResultKindV1, ServerConfirmationV1, ObjectErrorV1}`; `ea_trust::{TrustAnchorV1, decode_trust_anchor}`; `ea_archive::ArchiveSource`; `ea_crypto::{HpkeRecipientPrivateKey, HpkeSealed, SecretBytes, SecretVec, CEK_SIZE, AEAD_NONCE_SIZE, hpke_open, aead_open, hpke_info, hpke_aad, payload_aad}`; `ea_format::{decode_exact_object, ParsedArchiveObject, EntryPackageV1, GrantV1, GrantKindV1}`; `ea_schema::SchemaRegistry`; `ea_types::{VerificationStatus, EntryStatus, EntryHash, ChainSequence, KeyThumbprint, UnixMillis}`; `ReaderMode` aus dem Task „wasm32-Reichweite: `ea-reader`, die Brücken-Crate und die geteilten Browserkerne"; die entsperrte Sitzung des Tasks „Browser-Vault: PRF-Envelopes, Schlüsselprofil und die Verwahrung von Anchor und KEM-Schlüssel".
- Produces: `PinnedTrustAnchor`, `ReaderVerifier::classify`, `ReaderClassification`, die gefuellten `ReaderEntryStateV1`-Werte (der Typ selbst wird im Vault-Task deklariert), `VerifiedEncryptedEntry`, `VerifiedGrantForRecipient`, `decrypt_verified`, `VerifiedDecryptedRecord` samt seiner VOLLSTAENDIGEN, ausschliesslich AUSLEIHENDEN Klartextflaeche `with_plaintext`/`with_payload` und den Abschnitt `verification` in `docs/traceability/stage-4-fault-points.json`.

Der Rustkern des frueheren Tasks bleibt unveraendert; `web-reader-design.md` §12 fordert fuer ihn ausdruecklich nur neue BINDUNGEN. Die zwei Bindungen sind: der Entkapseler nimmt den X25519-Schluessel aus der Vault-Sitzung statt aus einem nativen `KemDecapsulator`, und der `TrustAnchorV1`, der an `verify_archive_observed` geht, kommt ausschliesslich aus dem Vault und nie aus Trust-Objekten, die in einer geoeffneten Datei mitliegen. **Dieser Task implementiert kein Gate neu.** `crates/ea-verify` besitzt alle neun, `GATE_ORDER_V1` ist ihre einzige Quelle, und kein Gate-Bezeichner wird hier ein zweites Mal als Literal geschrieben. Er faehrt kein OPFS-I/O, keinen Netzaufruf und keine Indizierung.

- [ ] **Step 1: Write the order, missing-grant, expiry, stub, and pinned-anchor tests**

```rust
// crates/ea-reader/tests/verification_order.rs
#[test]
fn the_protocol_is_a_prefix_of_the_nine_gates_and_then_at_most_one_decapsulation() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let mut observer = RecordingObserver::new();
    let classification = ReaderVerifier::new(ReaderMode::Server, fixtures::EFFECTIVE_NOW)
        .classify(&fixtures::complete_archive(), &vault, &mut observer)
        .expect("a complete archive must classify");
    let events = observer.events();
    let split = events
        .iter()
        .position(|event| *event == DECAPSULATION_EVENT_V1)
        .unwrap_or(events.len());
    assert_eq!(events[..split], GATE_ORDER_V1[..split]);
    assert!(events[split..].len() <= 1);
    assert!(classification.report().is_fully_verified());
}

#[test]
fn no_decapsulation_event_precedes_any_public_gate_failure() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    for broken in fixtures::each_public_verification_failure() {
        let mut observer = RecordingObserver::new();
        let classification = ReaderVerifier::new(ReaderMode::Server, fixtures::EFFECTIVE_NOW)
            .classify(&broken.source, &vault, &mut observer)
            .expect("a finding about one object is never an Err");
        assert!(!observer.events().contains(&DECAPSULATION_EVENT_V1), "{}", broken.label);
        assert!(classification.verified_entry(broken.entry_hash).is_none(), "{}", broken.label);
    }
}

// Der Modusparameter aendert an der Reihenfolge NICHTS: web-reader-design.md
// §5.4 sagt „wortgleich in beiden Modi". Er aendert genau zwei Dinge, und beide
// stehen woanders — kein Netzaufruf im Datei-Modus, und `nicht server-bestaetigt`
// als Regelfall statt als Ausnahme.
#[test]
fn both_reader_modes_produce_the_same_gate_protocol_over_the_same_bytes() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let source = fixtures::complete_archive();
    let mut server = RecordingObserver::new();
    let mut file = RecordingObserver::new();
    ReaderVerifier::new(ReaderMode::Server, fixtures::EFFECTIVE_NOW)
        .classify(&source, &vault, &mut server).unwrap();
    ReaderVerifier::new(ReaderMode::File, fixtures::EFFECTIVE_NOW)
        .classify(&source, &vault, &mut file).unwrap();
    assert_eq!(server.events(), file.events());
}
```

```rust
// crates/ea-reader/tests/missing_grant.rs
#[test]
fn a_valid_entry_without_an_own_grant_is_exactly_missing_grant() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let classification = fixtures::classify(&fixtures::entry_without_own_grant(), &vault);
    let state = classification.state_of(fixtures::ENTRY_HASH).expect("the entry stays visible");
    assert_eq!(state.verification(), VerificationStatus::MissingGrant);
    assert_eq!(state.entry_state(), EntryStatus::Present);
    assert_eq!(state.sequence(), ChainSequence::new(12));
    // Kein Befund: fehlender Grant ist KEINE Beschaedigung.
    assert_eq!(classification.report().decryption_errors().len(), 0);
    assert_eq!(classification.report().gaps().len(), 0);
    assert!(classification.report().is_fully_verified());
    // Und kein Zeuge, also ist die Entschluesselung nicht formulierbar.
    assert!(classification.verified_grant(fixtures::ENTRY_HASH, &vault).is_none());
}

// Die vier Zustaende, die design.md §17.4 auseinanderhaelt, an vier Bestaenden.
#[test]
fn missing_grant_gap_unknown_key_and_invalid_never_collapse() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    for (label, source, expected, expected_code) in [
        ("fehlender Grant", fixtures::entry_without_own_grant(), VerificationStatus::MissingGrant, None),
        ("Luecke", fixtures::archive_with_a_sequence_gap(), VerificationStatus::Gap, None),
        ("unbekannter Schluessel", fixtures::grant_on_own_thumbprint_wrong_material(),
         VerificationStatus::UnknownKey, Some("EA-VERIFY-DECRYPT-CEK-UNWRAP-FAILED")),
        ("ungueltig", fixtures::entry_with_a_flipped_manifest_byte(), VerificationStatus::Invalid, None),
    ] {
        let classification = fixtures::classify(&source, &vault);
        let state = classification.state_of(fixtures::ENTRY_HASH).expect(label);
        assert_eq!(state.verification(), expected, "{label}");
        assert_eq!(state.detail_code(), expected_code, "{label}");
    }
}
```

```rust
// crates/ea-reader/tests/pinned_anchor.rs
#[test]
fn a_substituted_archive_with_its_own_complete_trust_chain_fails_here() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    // Der Bestand ist in sich vollstaendig: eigener Root, eigene Registry,
    // eigene Writer-Zertifikate, eigene Signaturen. Er ist nur nicht UNSERER.
    let classification = fixtures::classify(&fixtures::foreign_but_self_consistent_archive(), &vault);
    assert!(!classification.report().is_fully_verified());
    assert_eq!(classification.report().object_results().len(), 0);
    assert!(classification.states().is_empty());
}

#[test]
fn the_anchor_used_is_the_vault_anchor_and_not_the_one_in_the_archive() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let anchor = PinnedTrustAnchor::from_vault(&vault).unwrap();
    assert_eq!(anchor.as_trust_anchor().trust_anchor_hash(), fixtures::PINNED_ANCHOR_HASH);
    assert_ne!(fixtures::foreign_archive_anchor_hash(), fixtures::PINNED_ANCHOR_HASH);
}
```

`historical_expiry.rs` haelt zwei Zusagen fest: ein Zeuge ist an den Zeitpunkt gebunden, an dem er entstand, und ein historischer Grant bleibt bis Stufe 5 unbenutzbar. `destroyed_stub.rs` haelt fest, dass ein `.eds` niemals HPKE ruft — weder als `autorisiert vernichtet` noch als `ungeklaerte Luecke`.

```rust
// crates/ea-reader/tests/destroyed_stub.rs
#[test]
fn a_stub_never_calls_hpke_in_either_outcome() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    for (label, source, entry_state) in [
        ("autorisiert vernichtet", fixtures::stub_with_resolvable_authorization(),
         EntryStatus::AuthorizedDestroyed),
        ("ungeklaerte Luecke", fixtures::stub_without_resolvable_authorization(),
         EntryStatus::UnexplainedGap),
    ] {
        let mut observer = RecordingObserver::new();
        let classification = ReaderVerifier::new(ReaderMode::Server, fixtures::EFFECTIVE_NOW)
            .classify(&source, &vault, &mut observer).unwrap();
        assert!(!observer.events().contains(&DECAPSULATION_EVENT_V1), "{label}");
        assert_eq!(classification.state_of(fixtures::ENTRY_HASH).unwrap().entry_state(),
                   entry_state, "{label}");
        assert!(classification.verified_entry(fixtures::ENTRY_HASH).is_none(), "{label}");
    }
}
```

- [ ] **Step 2: Run the tests and verify that classification and decryption do not exist**

Run: `cargo test --locked -p ea-reader --test verification_order --test missing_grant --test historical_expiry --test destroyed_stub --test pinned_anchor`

Expected: FAIL. `crates/ea-reader` traegt nach dem Task „wasm32-Reichweite: `ea-reader`, die Brücken-Crate und die geteilten Browserkerne" ausschliesslich `ReaderMode` und den Re-Export von `ea_verify::GATE_ORDER_V1` und nach dem Task „Browser-Vault: PRF-Envelopes, Schlüsselprofil und die Verwahrung von Anchor und KEM-Schlüssel" die Vault-Flaeche; `PinnedTrustAnchor`, `ReaderVerifier`, `ReaderClassification`, `VerifiedEncryptedEntry`, `VerifiedGrantForRecipient` und `decrypt_verified` existieren nicht. Das ist ein roter Uebersetzungslauf und keine fehlende Crate — die Crate steht seit dem Reichweiten-Task im Arbeitsbereich, weshalb dieser Task hier und nicht davor liegt.

- [ ] **Step 3: Bind the vault anchor, the vault key, and the typed decryption witnesses**

**Der Anker ist ein Typ und keine Uebergabe.** `crates/ea-reader/src/anchor.rs` traegt genau einen Wert, der nur EINEN Weg in die Welt hat:

```rust
/// Der beim Enrollment im Vault gepinnte Root-Anchor.
///
/// Es gibt KEINEN Konstruktor aus rohen Bytes und KEINEN aus einer
/// [`ea_archive::ArchiveSource`]. Das ist die ganze Zusage von
/// `web-reader-design.md` §5.3: Trust-Objekte, die in der geoeffneten Datei
/// mitgeliefert werden, begruenden fuer sich kein Vertrauen. Waere hier ein
/// `from_bytes`, waere §5.3 eine Bitte statt einer Schranke.
pub struct PinnedTrustAnchor(TrustAnchorV1);

impl PinnedTrustAnchor {
    /// # Errors
    /// `EA-READER-ANCHOR-MISSING`, wenn die Sitzung keinen Anker fuehrt, und
    /// der Code von [`ea_trust::decode_trust_anchor`], wenn die verwahrten
    /// Bytes nicht mehr die eines Ankers sind.
    pub fn from_vault(session: &UnlockedVault) -> Result<Self, ReaderError>;

    #[must_use]
    pub const fn as_trust_anchor(&self) -> &TrustAnchorV1;
}
```

Die Bytes kommen aus der Vault-Sitzung und laufen durch `ea_trust::decode_trust_anchor` — kein zweiter Parser, keine zweite Ankerform. Der Beweis, dass es keinen anderen Weg gibt, ist ein `compile_fail`-Doctest an der Struktur, in derselben Bauform, in der `crates/ea-key-provider/src/lib.rs` und `crates/ea-crypto/src/secret.rs` ihre Nichtexportierbarkeit belegen; er faehrt in `cargo test --workspace --doc --all-features --locked`, dem einzigen Kommando aus `verify_quick_commands()`, das Doctests ueberhaupt anfasst.

**Die Klassifikation ruft die Pipeline und baut sie nicht nach.**

```rust
pub struct ReaderVerifier { mode: ReaderMode, effective_now: UnixMillis }

impl ReaderVerifier {
    #[must_use]
    pub const fn new(mode: ReaderMode, effective_now: UnixMillis) -> Self;

    /// Faehrt die neun Gates aus `design.md` §14.1 UEBER `ea_verify::verify_archive_observed`
    /// und uebersetzt den Bericht in die Zustandssprache aus §17.4.
    ///
    /// # Errors
    /// Nur der Fehler von [`ea_verify::verify_archive_observed`]. Ein Befund
    /// ueber ein EINZELNES Objekt ist nie ein `Err` — dieselbe Regel, die
    /// `crates/ea-verify/src/lib.rs` ausschreibt.
    pub fn classify(
        &self,
        source: &dyn ArchiveSource,
        session: &UnlockedVault,
        observer: &mut dyn GateObserver,
    ) -> Result<ReaderClassification, ReaderError>;
}
```

`classify` baut `VerifyOptions::new(self.effective_now).with_recipient(session.kem_key_thumbprint(), session.kem_private_key())` — und das ist die erste der zwei geforderten Bindungen. `session.kem_private_key()` liefert `&HpkeRecipientPrivateKey` aus dem WASM-Speicher der entsperrten Sitzung; es gibt keinen `KemDecapsulator`-Trait und keinen nativen Schluesselspeicher mehr, weil `web-reader-design.md` §11.3 den nativen Reader-Key-Provider ersatzlos streicht. Der Anker ist `PinnedTrustAnchor::from_vault(session)?.as_trust_anchor()` — die zweite Bindung.

**Die Zustandssprache ist eine TOTALE Abbildung und keine Kette von `if`.** `ReaderEntryStateV1` ist im Task „Browser-Vault: PRF-Envelopes, Schlüsselprofil und die Verwahrung von Anchor und KEM-Schlüssel" in `crates/ea-reader/src/entry_state.rs` DEKLARIERT worden, weil der Zustandsspeicher seinen Werttyp vor dem Klassifizierer braucht; dieser Task deklariert ihn NICHT ein zweites Mal, er FUELLT ihn. Der Typ steht hier nur zur Ansicht, mit seinen drei orthogonalen Dimensionen und nie einer zusammengefalteten:

```rust
pub struct ReaderEntryStateV1 {
    entry_hash: EntryHash,
    object_hash: ObjectHash,
    sequence: ChainSequence,
    verification: VerificationStatus,          // ea_types, die sechs Begriffe aus §17.4
    entry_state: EntryStatus,                  // ea_types, die drei Begriffe aus §17.4
    server_confirmation: ServerConfirmationV1, // ea_verify, EIGENE Dimension
    detail_code: Option<&'static str>,         // ein STABILER Code, nie Prosa
}
```

Kein Literal dieser drei Aufzaehlungen wird hier geschrieben: `VerificationStatus` und `EntryStatus` stehen seit Stufe 1 in `crates/ea-types/src/status.rs` mit genau den sechs beziehungsweise drei Begriffen des §17.4, `ServerConfirmationV1` in `crates/ea-verify/src/report.rs`. `detail_code` traegt ausschliesslich `ObjectErrorV1::code()`-Werte, also `EA-VERIFY-DECRYPT-CEK-UNWRAP-FAILED`, `EA-VERIFY-GRANT-ISSUER-UNVERIFIABLE` und ihresgleichen; ein Prosafeld waere eine zweite Statussprache neben §17.4.

Die Abbildung liest den Bericht in fester Vorrangordnung und ist damit nachvollziehbar statt geraten: ein Objekt in `format_errors`, `quarantined_objects`, `signature_errors` oder `evidence_errors` ist `Invalid`; ein `gaps`-Eintrag ueber seiner Sequenz ist `Gap`; ein `decryption_errors`-Eintrag auf seinem Grant ist `UnknownKey`; ein `ObjectResultV1` mit `ObjectResultKindV1::Valid`, zu dem kein eigener Grant gehoert, ist `MissingGrant`; alles uebrige ist `Verified`. Die Vorrangordnung ist erzwingbar, weil `ea-verify` seinerseits zusichert, dass ein Objekt in GENAU EINEM Feld erscheint — ohne diese Zusage waere die Abbildung mehrdeutig, und sie ist im Kopfkommentar von `crates/ea-verify/src/lib.rs` ausgeschrieben. `ObjectResultKindV1::AuthorizedDestroyed` setzt `EntryStatus::AuthorizedDestroyed`; ein `.eds` ohne aufloesbare `destructionAuthorization` erreicht diesen Zweig NICHT, sondern erscheint als `gaps`-Eintrag und damit als `EntryStatus::UnexplainedGap` — genau das, was `design.md`:1597 fordert und was `crates/ea-verify/src/archive.rs` fail-closed erzwingt, weil `ea-trust` fuer diese Aufloesung nichts exportiert. Der Reader schreibt diese Grenze auf und verschiebt sie nicht; die Aufloesung ist Stufe 5.

**Die zwei Zeugen sind nirgendwo sonst konstruierbar.** `crates/ea-reader/src/grant.rs`:

```rust
/// Ein Eintrag, der alle neun Gates getragen hat.
///
/// Der einzige Konstruktor ist privat und wird ausschliesslich von
/// [`ReaderClassification::verified_entry`] gerufen. Er traegt die EXAKTEN
/// Objektbytes und nicht eine Ableitung: `decrypt_verified` parst sie mit
/// `ea_format::decode_exact_object` erneut, statt einen `Parsed<T>` zu halten,
/// dessen Konstruktor `ea-format` nicht herausgibt.
pub struct VerifiedEncryptedEntry {
    exact_entry_bytes: Vec<u8>,
    entry_hash: EntryHash,
    sequence: ChainSequence,
    minted_at: UnixMillis,
}

/// Der eigene, gegen den gewaehlten Registrierungskopf geprueft befundene Grant.
pub struct VerifiedGrantForRecipient {
    exact_grant_bytes: Vec<u8>,
    entry_hash: EntryHash,
    recipient_key_thumbprint: KeyThumbprint,
    minted_at: UnixMillis,
}
```

`verified_entry` und `verified_grant` geben einen Zeugen NUR heraus, wenn der Bericht fuer dieses Objekt `ObjectResultKindV1::Valid` fuehrt, kein Fehlerfeld es nennt und `decryption_errors` seinen Grant nicht traegt. Damit ist die Aussage „nur `VerifiedEncryptedEntry` zusammen mit `VerifiedGrantForRecipient` erreicht den HPKE-Entkapseler" aus `web-reader-design.md` §9 eine TYPZUSAGE und keine Disziplin.

**`effectiveNow` wird vor jeder Entkapselung neu berechnet, und das ist mechanisch.** `minted_at` ist der `effective_now` des Laufs, der den Zeugen erzeugt hat. `decrypt_verified` nimmt einen FRISCHEN Wert und verweigert bei jeder Abweichung:

```rust
/// Oeffnet GENAU EINEN Eintrag.
///
/// # Errors
/// `EA-READER-WITNESS-STALE`, wenn `effective_now` von dem Zeitpunkt abweicht,
/// an dem die Zeugen entstanden. Eine Toleranz gaebe es hier NICHT: sie waere
/// eine zweite, schwaechere Frist neben der des Registrierungskopfes, den
/// `ea_trust::select_registry_head` gegen genau diesen Wert misst.
/// Ausserdem `EA-VERIFY-DECRYPT-CEK-UNWRAP-FAILED` und
/// `EA-VERIFY-DECRYPT-PAYLOAD-OPEN-FAILED` als durchgereichte Codes.
pub fn decrypt_verified(
    entry: &VerifiedEncryptedEntry,
    grant: &VerifiedGrantForRecipient,
    session: &UnlockedVault,
    schemas: &SchemaRegistry,
    effective_now: UnixMillis,
    observer: &mut dyn GateObserver,
) -> Result<VerifiedDecryptedRecord, ReaderError>;
```

Die Rechnung ist die von `crates/ea-verify/src/recipient.rs::open_entry`, Schritt fuer Schritt: `HpkeSealed::from_parts(fields.encapsulated_key, fields.wrapped_cek)`, `hpke_open(session.kem_private_key(), &sealed, &hpke_info(context), &hpke_aad(context))`, dann `aead_open(&cek, &nonce, entry.ciphertext(), &payload_aad(manifest.exact_bytes()))`. Der Unterschied zu `open_entry` ist der EINZIGE, den der Reader braucht: `open_entry` verwirft den Klartext beim Verlassen des Rahmens, weil `ea-verify` ihn nie herausgeben darf, und der Reader muss ihn anzeigen. Danach ruft `observer.on_decapsulation()` — genau einmal, hinter Gate `recipient-grant` und ausdruecklich als kein zehntes Gate.

**Zwei Entkapselungen je ANGEZEIGTEM Eintrag, gemessen und benannt.** Weil `verify_archive_observed` mit Empfaengerschluessel laeuft, oeffnet `ea-verify` seinerseits jeden Eintrag, fuer den ein eigener Grant vorliegt, und verwirft das Ergebnis. Der Reader oeffnet danach nur den EINEN Eintrag, den die Oberflaeche anfordert. Die Verdopplung ist damit nicht archivweit, sondern je angezeigtem Eintrag, und sie ist der Preis dafuer, dass der Klartext die Grenze von `ea-verify` nicht ueberschreitet. Die billigere Alternative — `ea-verify` den Klartext herausgeben zu lassen — waere eine Erweiterung einer abgeschlossenen Stufe-1-Crate um genau die Faehigkeit, deren Fehlen ihr Sicherheitsargument ist, und wird hier ausdruecklich nicht gewaehlt.

**Der historische Grant bleibt Stufe 5, und das steht im Test statt im Kopf.** `ea_verify::own_grant` waehlt ausschliesslich `GrantKindV1::Initial`; ein historischer Grant fuehrt in `verify_own_grant` zu `RecipientGrantErrorV1::AuthorizationUnverifiable` mit dem Code `EA-VERIFY-GRANT-AUTHORIZATION-UNVERIFIABLE`, weil `ea-trust` die Aufloesung einer `grantAuthorization` nicht exportiert. Der Reader stellt den betroffenen Eintrag deshalb als `MissingGrant` dar und NICHT als `Invalid` — der Eintrag ist gueltig, es fehlt nur ein benutzbarer eigener Grant — und `historical_expiry.rs` haelt genau diesen Code und das Ausbleiben des Entkapselungsereignisses fest. FR-145 loest das in Stufe 5.

**Der Klartext liegt in `SecretVec`, und die VOLLSTAENDIGE Zugriffsflaeche steht HIER.** `VerifiedDecryptedRecord` haelt den entschluesselten Payload in `ea_crypto::SecretVec`, der beim Verlassen ueberschreibt. Diese Aufgabe deklariert den Typ, und sie deklariert damit auch, WIE an seinen Klartext heranzukommen ist — abschliessend, fuer jede spaetere Aufgabe dieses Plans:

```rust
// crates/ea-reader/src/decrypt.rs
pub struct VerifiedDecryptedRecord { /* private: SecretVec-Payload, Herkunftsspalten */ }

impl VerifiedDecryptedRecord {
    #[must_use] pub const fn entry_hash(&self) -> EntryHash;
    #[must_use] pub const fn chain_sequence(&self) -> ChainSequence;
    #[must_use] pub const fn object_hash(&self) -> ObjectHash;
    /// Der Zeitpunkt, an dem die Zeugen entstanden — die Frischepruefung von
    /// `decrypt_verified` misst gegen genau diesen Wert.
    #[must_use] pub const fn minted_at(&self) -> UnixMillis;
    /// Schema-Kennung und -Fassung des QUELLDATENSATZES.
    #[must_use] pub fn source_schema(&self) -> (&'static str, u64);
    /// Schema-Kennung und -Fassung der ABGELEITETEN Ansicht. In v1 ist die
    /// Ableitung die Identitaet, und beide Paare sind gleich; die Spalte steht
    /// trotzdem getrennt, weil sie es ab v2 nicht mehr ist.
    #[must_use] pub fn target_schema(&self) -> (&'static str, u64);

    /// Der EINE Weg an die Klartextbytes: AUSGELIEHEN, nie herausgegeben.
    pub fn with_plaintext<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R;

    /// Der EINE Weg an die geparste Nutzlast. `PayloadV1` wird bei JEDEM Aufruf
    /// INNERHALB der Ausleihe neu dekodiert und faellt mit ihr; der Typ haelt
    /// ihn nicht in einem Feld. Das ist die Schranke, die die weitergereichte
    /// Restfrage zu `ea_schema::ValidatedPayload` klein haelt.
    pub fn with_payload<R>(&self, f: impl FnOnce(&PayloadV1) -> R) -> R;
}
```

Es gibt AUSDRUECKLICH KEIN `exact_plaintext_bytes() -> &[u8]` und KEIN `payload() -> &PayloadV1`. Ein Zugriff, der eine Ausleihe auf die Bytes ODER auf die geparste Nutzlast HERAUSGIBT, ist ein Klartext-Fluchtweg aus einem `SecretVec`: der Aufrufer kann ihn beliebig lange halten, kopieren, in ein `Vec` heben und in eine Ablage schreiben, und `ZeroizeOnDrop` greift auf die Kopie nie. Genau das verbieten `WR-082` (keine Zwischenablage-, Log- oder Telemetriewege fuer entschluesselte Inhalte), `FR-105` (Einzelexport mit bewusster Zielwahl statt beliebiger Herausgabe) und die Produktinvariante „no decrypted content enters OPFS bytes in the clear". Die Ausleihform macht die Reichweite des Klartexts zu einer TYPAUSSAGE: er lebt genau so lange wie der Aufruf. Es gibt aus demselben Grund weder `Deref` noch `Clone` noch ein abgeleitetes `Debug` auf diesem Typ; `Debug` gibt den Eintragshash und die Schemaspalten aus und nie eine Nutzlast. Jede spaetere Aufgabe dieses Plans — „Verschlüsselter invertierter Index in OPFS, Suche, Schemakompatibilität und die GEMESSENE 50.000-Paket-Schwelle", „Nachtragsreferenzen und Original/Nachtrag-Projektion", „Sitzungssperre, Zeroize, authenticator-bestätigter Einzelexport und signiertes lokales Audit" — benutzt AUSSCHLIESSLICH diese acht Zugriffe.

`SchemaRegistry::validate` laeuft INNERHALB von `decrypt_verified` ueber eine Ausleihe, und der dabei entstehende `ValidatedPayload` faellt dort. **Benannte Restfrage:** `ea_schema::ValidatedPayload` und `ea_schema::DerivedView` besitzen einen gewoehnlichen `Vec<u8>` und ueberschreiben ihn beim Fallen nicht; sie zeroize-faehig zu machen hiesse, eine abgeschlossene Stufe-1-Crate anzufassen. Dieser Task tut das nicht, er schreibt die Luecke auf, und der Task „Sitzungssperre, Zeroize, authenticator-bestätigter Einzelexport und signiertes lokales Audit" besitzt die Zeroize-Zusage der Sitzung und entscheidet dort, ob die Luecke geschlossen oder als dokumentierte SOLL-Abweichung gefuehrt wird.

**Der Modusparameter.** `ReaderMode` aendert die Gate-Reihenfolge nicht — `web-reader-design.md` §5.4 sagt „wortgleich in beiden Modi" — und aendert an Gate `receipt` nichts: `ea-verify` bestimmt `ServerConfirmationV1` ohnehin aus den VORHANDENEN Quittungen, also ist der Datei-Modus fuer die Pipeline schlicht ein Bestand ohne `.esr`. Der Parameter traegt zwei Zusagen und sonst nichts: `ReaderMode::File` verbietet jeden Netzaufruf dieses Laufs, und `NotServerConfirmed` ist dort der Regelfall statt der Ausnahme. Die Oberflaechenwirkung besitzt der Task „Datei-Modus: Einzeldatei-Bündel, Verzeichnis-Handle, kein Cursor, `nicht server-bestätigt`"; hier wird nur festgehalten, dass beide Modi dasselbe Protokoll erzeugen.

`docs/traceability/stage-4-fault-points.json` — vom Task „Web-Bundle: getrennter Origin, Service Worker, gepinnte `webBundleRelease` und das Alter des Trust-Standes" angelegt — bekommt den Abschnitt `verification` mit einem benannten Zeugen je Fehlerpunkt, in der Form von `docs/traceability/stage-3-fault-points.json`: `substituted-archive-own-trust-chain` → `pinned_anchor.rs`, `missing-own-grant` → `missing_grant.rs`, `own-thumbprint-wrong-material` → `missing_grant.rs`, `stub-without-authorization` → `destroyed_stub.rs`, `stale-witness` → `historical_expiry.rs`, `historical-grant-unresolvable` → `historical_expiry.rs`.

- [ ] **Step 4: Run the classification, the browser witness, and the frozen surfaces**

Run:

```bash
cargo metadata --format-version 1
cargo test --locked -p ea-reader
cargo test --locked -p ea-reader --doc
pnpm web:browser-test
cargo run --locked -p xtask -- test-golden
```

`cargo metadata --format-version 1` steht als ERSTE Zeile und ist das GENAU EINE Kommando dieses Tasks ohne `--locked`: Schritt 3 gibt `crates/ea-reader` und `crates/ea-reader-wasm` die Kante auf `ea-schema`, und `Cargo.toml` sowie `Cargo.lock` stehen aus genau diesem Grund im Files-Block. `ea-archive` steht seit dem Task „Inkrementeller Reader-Sync und verifizierter Cursor-Fortschritt in OPFS" in `crates/ea-reader/Cargo.toml` — `ea_verify::verify_archive_observed` nimmt dort bereits `&dyn ArchiveSource` —, `ea-format` seit dem Task „Browser-Vault: PRF-Envelopes, Schlüsselprofil und die Verwahrung von Anchor und KEM-Schlüssel", der `DeviceCertificateFieldsV1` benennt; beide werden hier geerbt und nicht neu gezogen. Es steht NACH der Registrierung und VOR jedem `--locked`-Kommando.

Expected: PASS. Das Protokoll ist in beiden Modi ein Praefix von `GATE_ORDER_V1` gefolgt von hoechstens einem `hpke-open`; ein vollstaendiger Bestand ist `is_fully_verified()`; `crates/ea-reader-wasm/tests/verify_browser.rs` fuehrt dieselbe Klassifikation in Headless-Chromium ueber eine `ArchiveSource` im Speicher und schliesst damit eine der fuenf benannten Grenzen des Spikes — hier laeuft `parse_cose_sign1` zum ersten Mal gegen eine ECHTE COSE-Kette im Browser statt gegen einen rohen RFC-8032-Vektor. Die adversariellen Faelle, die rot werden MUESSEN und einzeln zu pruefen sind: ein untergeschobener, in sich vollstaendiger Fremdbestand faellt an Gate `trust` und liefert NULL `objectResults` statt einer stillen Teilverifikation; ein `PinnedTrustAnchor`, der aus Archivbytes gebaut werden soll, uebersetzt nicht (`compile_fail`-Doctest); ein `decrypt_verified` mit einem Zeugen aus einem frueheren `classify` bricht mit `EA-READER-WITNESS-STALE` ab; ein `.eds` erzeugt in keinem seiner beiden Ausgaenge ein `hpke-open`; ein Eintrag ohne eigenen Grant erzeugt weder einen `decryptionErrors`-Eintrag noch eine `gaps`-Zeile und senkt `is_fully_verified()` nicht; und ein Grant auf den eigenen Abdruck mit falschem Material erzeugt `EA-VERIFY-DECRYPT-CEK-UNWRAP-FAILED` und wird als `unbekannter Schluessel` und nie als `fehlender Grant` gefuehrt. `test-golden` belegt, dass kein eingefrorener Vektor und keine Golden-Erwartung sich bewegt hat: dieser Task erzeugt kein Archivbyte.

- [ ] **Step 5: Commit the verification binding**

```bash
git add crates/ea-reader crates/ea-reader-wasm docs/traceability/stage-4-fault-points.json \
        Cargo.toml Cargo.lock
git commit -m "feat(reader): decrypt only fully verified entries against the vault-pinned anchor"
```

### Task 9: Datei-Modus: Einzeldatei-Bündel, Verzeichnis-Handle, kein Cursor, `nicht server-bestätigt`

**Files:**
- Create: `crates/ea-reader/src/file_mode.rs`
- Create: `crates/ea-reader/src/archive_source.rs`
- Create: `crates/ea-reader-wasm/src/file_access.rs`
- Create: `apps/web/src/features/file-mode/OpenArchivePanel.tsx`
- Create: `apps/web/src/features/file-mode/DirectoryHandle.ts`
- Test: `crates/ea-reader/tests/file_mode.rs`
- Test: `crates/ea-reader/tests/file_mode_anchor.rs`
- Test: `apps/web/src/features/file-mode/OpenArchivePanel.test.tsx`
- Test: `apps/web/tests/e2e/file-mode.spec.ts`
- Modify: `crates/ea-reader/src/lib.rs`
- Modify: `crates/ea-reader-wasm/src/lib.rs`
- Modify: `apps/web/src/main.tsx`
- Modify: `docs/traceability/stage-4-fault-points.json`

**Interfaces:**
- Consumes: `ea_archive::{ArchiveBundleSource, ArchiveBlob, ArchiveError, ArchiveSource, BundleError, BUNDLE_FILE_EXTENSION_V1, BUNDLE_MAGIC_V1, BUNDLE_HEADER_BYTES_V1, MAX_ARCHIVE_BLOBS_V1, MAX_TOTAL_ARCHIVE_BYTES_V1}` — der reine Buendelleser, den die Aufgabe „wasm32-Reichweite: `ea-reader`, die Brücken-Crate und die geteilten Browserkerne" aus dem wirtsgebundenen `ea-archive-fs` nach `ea-archive` bewegt; `ea_verify::{verify_archive_observed, VerifyOptions, RecordingObserver, VerificationReportV1, ObjectResultKindV1, ServerConfirmationV1, GATE_ORDER_V1}`; `UnlockedVault` aus der Aufgabe „Browser-Vault: PRF-Envelopes, Schlüsselprofil und die Verwahrung von Anchor und KEM-Schlüssel"; `ReaderVerifier::classify`, `ReaderClassification`, `ReaderEntryStateV1` und `PinnedTrustAnchor::from_vault` aus der Aufgabe „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert"; `ReaderMode::File` aus der Aufgabe „wasm32-Reichweite: `ea-reader`, die Brücken-Crate und die geteilten Browserkerne"; `docs/traceability/stage-4-fault-points.json` aus der Aufgabe „Web-Bundle: getrennter Origin, Service Worker, gepinnte `webBundleRelease` und das Alter des Trust-Standes".
- Produces: `ReaderFileMode::{open_bundle, open_bundle_observed, open_directory}`, `ReaderArchiveSourceV1`, `DirectoryHandleSource::{push_blob, blob_count}`, `OpenedArchiveV1::{classification, report, mode}`, der Abschnitt `file-mode` des Szenarienmanifests, und die Belegspalten der Ledgerzeilen `WR-053` und `WR-054`.

`crates/ea-reader/src/lib.rs` nimmt `mod file_mode;` und `mod archive_source;` samt ihren `pub use`-Bloecken auf, `crates/ea-reader-wasm/src/lib.rs` nimmt `mod file_access;` auf; ohne diese Zeilen uebersetzt der Commit nicht. `apps/web/src/main.tsx` bekommt die Route `/datei`, angehaengt an die Routentabelle aus der Aufgabe „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate"; `apps/web/tests/e2e/file-mode.spec.ts` faehrt genau diese Route an.

Dies ist der zweite Betriebsmodus aus `web-reader-design.md` §5.2 bis §5.4: die Anwendung oeffnet Archivobjekte direkt aus dem Dateisystem, OHNE jede Serverbeteiligung. Zwei Wege hinein, und nur einer davon funktioniert ueberall. Der universelle Weg nimmt die EINE exportierte Datei durch den gewoehnlichen Dateidialog; er MUSS immer angeboten werden, weil `showDirectoryPicker` in Safari und Firefox fehlt. Der Chromium-Komfortweg bindet ueber `showDirectoryPicker` einen Archivordner oder ein profiliertes Netzlaufwerk dauerhaft an.

Drei Nicht-Ziele, jedes mit seinem Grund. Es entsteht KEIN zweiter Archivparser: beide Wege muenden in `ea_archive::ArchiveSource`, und die Klassifikation entscheidet weiterhin ausschliesslich das 9-Byte-Exact-Object-Praefix, nie ein Dateiname. Es entsteht KEIN Serveraufruf irgendeiner Art — der Modus ist definiert durch seine Abwesenheit. Und die Ankerbindung wird NICHT neu implementiert: sie kommt fertig aus der Aufgabe „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert", die sie mit ihrem eigenen Zeugen traegt; hier wird belegt, dass der EINSTIEGSPUNKT dieses Modus keinen zweiten Weg zu einem Anker oeffnet.

- [ ] **Step 1: Write the two-way, no-cursor, and not-server-confirmed witnesses**

```rust
// crates/ea-reader/tests/file_mode.rs
#[test]
fn the_bundle_and_the_same_directory_produce_byte_identical_reports() {
    let vault = fixtures::unlocked_vault();
    let clock = fixtures::os_wall_clock();

    let from_file = ReaderFileMode::open_bundle(fixtures::exported_bundle_bytes(), &vault, clock)
        .unwrap();
    let mut directory = DirectoryHandleSource::new();
    for (path_hint, bytes) in fixtures::directory_blobs() {
        directory.push_blob(path_hint, bytes).unwrap();
    }
    let from_directory = ReaderFileMode::open_directory(directory, &vault, clock).unwrap();

    assert_eq!(
        from_file.report().report_hash(),
        from_directory.report().report_hash()
    );
    assert!(from_file.report().is_fully_verified());
    assert_eq!(
        from_file.report().archive_object_count(),
        from_directory.report().archive_object_count()
    );
}

#[test]
fn every_object_without_a_receipt_is_not_server_confirmed_and_never_a_gap() {
    let opened = ReaderFileMode::open_bundle(
        fixtures::bundle_without_receipts(),
        &fixtures::unlocked_vault(),
        fixtures::os_wall_clock(),
    )
    .unwrap();
    let report = opened.report();

    assert!(report.object_results().len() > 0);
    assert!(
        report
            .object_results()
            .all(|result| result.server_confirmation() == ServerConfirmationV1::NotServerConfirmed)
    );
    assert!(
        report
            .object_results()
            .any(|result| result.result() == ObjectResultKindV1::Valid)
    );
    assert_eq!(report.gaps().len(), 0);
    assert_eq!(report.quarantined_objects().len(), 0);
    assert_eq!(report.format_errors().len(), 0);
    // Das ist die Zusage von design.md 17.4: eigene Dimension, kein Mangel.
    assert!(report.is_fully_verified());
}

#[test]
fn the_directory_source_enforces_both_caps_before_the_buffer_exists() {
    let mut source = DirectoryHandleSource::new();
    for index in 0..MAX_ARCHIVE_BLOBS_V1 {
        source.push_blob(format!("entries/{index}.eip"), Vec::new()).unwrap();
    }
    assert_eq!(
        source.push_blob("entries/one-too-many.eip".to_owned(), Vec::new()),
        Err(ArchiveError::BlobLimit)
    );

    let mut wide = DirectoryHandleSource::new();
    assert_eq!(
        wide.push_blob("entries/a.eip".to_owned(), vec![0; MAX_TOTAL_ARCHIVE_BYTES_V1 + 1]),
        Err(ArchiveError::TotalByteLimit)
    );
}

#[test]
fn a_truncated_or_wrongly_magicked_container_reports_the_bundle_code_and_no_report() {
    let mut truncated = fixtures::exported_bundle_bytes();
    truncated.truncate(truncated.len() - 1);
    assert_eq!(
        ReaderFileMode::open_bundle(truncated, &fixtures::unlocked_vault(), fixtures::os_wall_clock())
            .unwrap_err()
            .code(),
        "EA-BUNDLE-MALFORMED"
    );

    let mut foreign = fixtures::exported_bundle_bytes();
    foreign[0] ^= 0x01;
    assert_ne!(&foreign[..BUNDLE_MAGIC_V1.len()], &BUNDLE_MAGIC_V1[..]);
    assert_eq!(
        ReaderFileMode::open_bundle(foreign, &fixtures::unlocked_vault(), fixtures::os_wall_clock())
            .unwrap_err()
            .code(),
        "EA-BUNDLE-MALFORMED"
    );
}
```

Der Beleg fuer „der Cursor entfaellt ersatzlos" ist eine UEBERSETZUNGSGRENZE und keine Zusicherung ueber einen Namen. Die Form ist die, die `crates/ea-key-provider/src/lib.rs` und `crates/ea-crypto/src/secret.rs` fuer ihre API-Flaechenverbote schon fuehren, und `verify_quick_commands()` faehrt sie mit `cargo test --workspace --doc --all-features --locked`:

```rust
// crates/ea-reader/src/file_mode.rs — Modul-Doc
//! Im Datei-Modus gibt es keinen Cursor. Jedes Objekt wird bei jedem Oeffnen
//! vollstaendig geprueft (`web-reader-design.md` §5.4).
//!
//! ```compile_fail
//! use ea_reader::{ConfirmedCursor, OpenedArchiveV1};
//! fn reject(opened: &OpenedArchiveV1) -> ConfirmedCursor { opened.confirmed_cursor() }
//! ```
//!
//! ```compile_fail
//! use ea_reader::{ReaderFileMode, ReaderSyncService};
//! fn reject(mode: &ReaderFileMode) -> &ReaderSyncService<'_> { mode.sync_service() }
//! ```
```

```rust
// crates/ea-reader/tests/file_mode_anchor.rs
#[test]
fn a_substituted_archive_with_its_own_trust_chain_says_nothing_about_any_entry() {
    let vault = fixtures::unlocked_vault();
    let clock = fixtures::os_wall_clock();

    // Positivkontrolle: DASSELBE Buendel gegen SEINEN eigenen Anker traegt.
    let own = ReaderFileMode::open_bundle_observed(
        fixtures::foreign_root_bundle_bytes(),
        &fixtures::vault_pinned_to(fixtures::foreign_anchor()),
        clock,
        &mut RecordingObserver::new(),
    )
    .unwrap();
    assert!(own.report().is_fully_verified());

    // Und gegen den im Tresor GEPINNTEN Anker faellt es durch.
    let mut observer = RecordingObserver::new();
    let opened = ReaderFileMode::open_bundle_observed(
        fixtures::foreign_root_bundle_bytes(),
        &vault,
        clock,
        &mut observer,
    )
    .unwrap();
    let report = opened.report();

    let anchor = PinnedTrustAnchor::from_vault(&vault).unwrap();
    assert_eq!(observer.events(), &GATE_ORDER_V1[..2]);
    assert!(!report.is_fully_verified());
    assert_eq!(report.object_results().len(), 0);
    assert_eq!(report.public_key_thumbprints().len(), 0);
    assert_eq!(report.chain_head().sequence(), ChainSequence::new(0));
    assert_ne!(
        report.chain_head().entry_hash(),
        anchor.as_trust_anchor().genesis_entry_hash()
    );
    assert_eq!(
        report.chain_head().chain_id(),
        anchor.as_trust_anchor().chain_id()
    );
}
```

```tsx
// apps/web/src/features/file-mode/OpenArchivePanel.test.tsx
it('offers the universal file path even when showDirectoryPicker is absent', async () => {
  const withoutPicker = { ...windowDouble(), showDirectoryPicker: undefined }
  render(<OpenArchivePanel host={withoutPicker} bridge={bridgeDouble()} />)
  expect(screen.getByRole('button', { name: 'Archivdatei öffnen' })).toBeEnabled()
  expect(screen.queryByRole('button', { name: 'Archivordner verbinden' })).not.toBeInTheDocument()
})

it('marks every object as nicht server-bestätigt without calling it a defect', async () => {
  render(<OpenArchivePanel host={windowDouble()} bridge={bridgeWithoutReceipts()} />)
  await user.click(screen.getByRole('button', { name: 'Archivdatei öffnen' }))
  const status = await screen.findByTestId('server-confirmation')
  expect(status).toHaveTextContent('nicht server-bestätigt')
  expect(status).toHaveTextContent('verifiziert')
  expect(screen.queryByText('Lücke')).not.toBeInTheDocument()
  expect(screen.queryByText('ungültig')).not.toBeInTheDocument()
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()
})
```

- [ ] **Step 2: Run the witnesses and confirm the file mode is absent**

Run: `cargo test --locked -p ea-reader --test file_mode --test file_mode_anchor && cargo test --locked -p ea-reader --doc && pnpm --dir apps/web test --run OpenArchivePanel`

Expected: FAIL because `ReaderFileMode`, `ReaderArchiveSourceV1` and `DirectoryHandleSource` do not exist, the two `compile_fail` doctests pass vacuously against absent types instead of against an absent METHOD, and `apps/web/src/features/file-mode/` is empty. Die zwei Doctests sind in diesem Schritt AUSDRUECKLICH kein Beleg: ein `compile_fail` gegen einen nicht existierenden Typ ist gruen aus dem falschen Grund und wird erst in Schritt 4 aussagekraeftig, wenn `OpenedArchiveV1` und `ReaderFileMode` da sind und die verlangten Methoden trotzdem fehlen.

- [ ] **Step 3: Implement one port over both ways, verified against the pinned anchor**

```rust
// crates/ea-reader/src/archive_source.rs
pub enum ReaderArchiveSourceV1 {
    Bundle(ArchiveBundleSource),
    Directory(DirectoryHandleSource),
}

impl ArchiveSource for ReaderArchiveSourceV1 {
    fn visit_blobs(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError>;
}

pub struct DirectoryHandleSource { /* private */ }

impl DirectoryHandleSource {
    pub const fn new() -> Self;
    pub fn push_blob(&mut self, path_hint: String, bytes: Vec<u8>) -> Result<(), ArchiveError>;
    pub fn blob_count(&self) -> usize;
}
```

```rust
// crates/ea-reader/src/file_mode.rs
pub struct ReaderFileMode;

impl ReaderFileMode {
    pub fn open_bundle(
        bytes: Vec<u8>,
        vault: &UnlockedVault,
        os_wall_clock: UnixMillis,
    ) -> Result<OpenedArchiveV1, FileModeError>;

    pub fn open_bundle_observed(
        bytes: Vec<u8>,
        vault: &UnlockedVault,
        os_wall_clock: UnixMillis,
        observer: &mut dyn GateObserver,
    ) -> Result<OpenedArchiveV1, FileModeError>;

    pub fn open_directory(
        source: DirectoryHandleSource,
        vault: &UnlockedVault,
        os_wall_clock: UnixMillis,
    ) -> Result<OpenedArchiveV1, FileModeError>;
}

pub struct OpenedArchiveV1 { /* private */ }

impl OpenedArchiveV1 {
    pub const fn classification(&self) -> &ReaderClassification;
    pub const fn report(&self) -> &VerificationReportV1;
    pub const fn mode(&self) -> ReaderMode;
}
```

KEINER der drei Eingaenge nimmt einen `TrustAnchorV1` oder einen `PinnedTrustAnchor`. Das ist der eigene Zeuge dieser Aufgabe fuer §5.3: der Anker entsteht INNERHALB des Aufrufs aus `PinnedTrustAnchor::from_vault(vault)` und sonst nirgendher, und Trust-Objekte, die IN der geoeffneten Datei liegen, begruenden von sich aus kein Vertrauen. Ein Aufrufer kann keinen zweiten Anker anbieten, weil die Signatur keinen Platz dafuer hat — das ist dieselbe Konstruktionsregel, mit der `ea_trust` seine Beweistypen schuetzt. Die BINDUNG selbst, also dass die Sitzung ihren Anker ausschliesslich aus dem Tresor bezieht, gehoert der Aufgabe „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert" und wird hier weder wiederholt noch neu gerechnet.

Verifiziert wird ueber `ReaderVerifier::new(ReaderMode::File, os_wall_clock).classify(&source, vault, observer)` aus der Aufgabe „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert". Damit gibt es GENAU EINEN Weg in die Pipeline, und der Modusparameter ist das einzige, was dieser Task daran setzt: `ReaderVerifier` baut selbst `VerifyOptions::new(effective_now).with_recipient(session.kem_key_thumbprint(), session.kem_private_key())` und nimmt den Anker aus `PinnedTrustAnchor::from_vault(session)`. Diese Aufgabe ruft `ea_verify::verify_archive_observed` NICHT direkt und implementiert kein Gate ein zweites Mal; die Gate-Reihenfolge aus `design.md` §14.1 gilt in beiden Modi WORTGLEICH. Der einzige Unterschied ist Schritt 7: geprueft werden nur die im Buendel beziehungsweise Ordner enthaltenen Receipts und Checkpoints. Genau das tut `ea-verify` bereits von sich aus — es liest ausschliesslich, was der Port liefert —, und es setzt fuer jedes Objekt ohne passende Quittung `ServerConfirmationV1::NotServerConfirmed`, ohne `is_fully_verified()` zu senken. Diese Aufgabe FUEGT dafuer nichts hinzu; sie belegt es und traegt es in die Oberflaeche.

`ArchiveBundleSource::from_bytes` prueft den Container vollstaendig, BEVOR ein einziger Blob herausgegeben wird — Magie, Blobzahl aus dem Kopf, sortierter und duplikatfreier Index ohne Luecke und ohne Ueberlappung, beide Deckel. Die Datei ist unvertraut, weil sie durch den gewoehnlichen Dateidialog kommt; deshalb wird sie AUSSCHLIESSLICH ueber `from_bytes` gelesen und nie ueber `ea_archive_fs::open_archive_bundle`/`open_archive_bundle_capped`, die auf `std::fs` sitzen und in `ea-archive-fs` zurueckbleiben. `FileModeError::Bundle(BundleError)` reicht den bereits stabilen Code durch — `EA-BUNDLE-MALFORMED`, `EA-BUNDLE-BLOB-LIMIT`, `EA-BUNDLE-TOTAL-BYTE-LIMIT` —, und `DirectoryHandleSource::push_blob` gibt `ea_archive::ArchiveError` unveraendert zurueck: `EA-ARCHIVE-BLOB-LIMIT` und `EA-ARCHIVE-TOTAL-BYTE-LIMIT`. Kein zweiter Satz Zahlen und kein zweiter Satz Codes fuer dieselbe Tatsache.

Die Deckel werden in RUST durchgesetzt und nicht in TypeScript, und das ist der Grund fuer die Push-Form von `DirectoryHandleSource`: `apps/web/src/features/file-mode/DirectoryHandle.ts` laeuft den `FileSystemDirectoryHandle` rekursiv ab, je Ebene lexikografisch aufsteigend nach Namen sortiert — `entries()` gibt keine Ordnung, und ohne eine festgelegte haengen `nonObjectFileCount`, die Fehlerreihenfolge und damit jeder Berichtsvergleich am Zufall der Browserimplementierung —, und reicht jede Bytesequenz EINZELN ueber die Bruecke. Die Grenze faellt damit an derselben inklusiven Schranke wie beim Verzeichnisleser der Wiederherstellung, und TypeScript entscheidet nichts: es zaehlt nicht, es vergleicht nicht, es bricht auf den durchgereichten Fehlercode ab.

`crates/ea-reader-wasm/src/file_access.rs` traegt unter `cfg(target_arch = "wasm32")` genau drei Ausfuhren: `file_mode_open_bundle(bytes: &[u8]) -> u32`, `file_mode_begin_directory() -> u32` und `file_mode_push_blob(handle: u32, path_hint: &str, bytes: &[u8]) -> Result<(), JsValue>`. Ueber die Bruecke gehen Bytes und Pfadhinweise hinein und ein Sitzungsgriff plus die generierten Status-DTOs heraus — nie ein Bericht als freier Text, nie Schluesselmaterial, nie ein entschluesselter Wert.

`apps/web/src/features/file-mode/OpenArchivePanel.tsx` bietet BEIDE Wege an, und der universelle IMMER. Die Erkennung ist eine Faehigkeitsabfrage auf dem uebergebenen Wirtsobjekt (`'showDirectoryPicker' in host`) und keine Browserkennung: eine Kennungsliste veraltet still, eine Faehigkeitsabfrage nicht. Fehlt `showDirectoryPicker` — Safari und Firefox —, erscheint der Komfortweg gar nicht erst, statt als abgeblendete Schaltflaeche eine Faehigkeit zu behaupten, die es nicht gibt. Der Dateidialog filtert auf `BUNDLE_FILE_EXTENSION_V1` (`eabundle`), aber die Endung ist ein HINWEIS: die Klassifikation entscheidet `BUNDLE_MAGIC_V1`, und eine umbenannte Datei faellt am Magiebyte und nicht am Namen.

Die Oberflaeche haelt die zwei orthogonalen Dimensionen aus `design.md` §17.4 auseinander. Jedes Objekt traegt gleichzeitig einen Verifikationsbegriff und einen Server-Bestaetigungsbegriff; im Datei-Modus ist `nicht server-bestätigt` der REGELFALL. Die Begriffe DUERFEN NICHT zusammengefasst werden, und `nicht server-bestätigt` DARF NICHT als `Lücke` oder `ungültig` dargestellt werden und ebenso wenig als vollstaendig bestaetigt. Praktisch heisst das: kein `alert`-Rollenelement, keine Fehlerfarbe, kein Ausrufezeichen-Icon; der Status steht als TEXT neben dem Verifikationsstatus, mit einem erklaerenden Zusatz, dass im Datei-Modus keine Serverquittungen bezogen werden. Ant Design 6 bleibt mit deutschem `ConfigProvider`, statisch extrahiertem lokalem gehashtem CSS, `zeroRuntime: true`, direkten CSR-Importen aus `@phosphor-icons/react`, sichtbarem Fokus und Reduced-Motion-Unterstuetzung; es entsteht kein neues Token und keine Laufzeit-CSS.

`docs/traceability/stage-4-fault-points.json` bekommt seinen Abschnitt `file-mode` in genau der Form, die `docs/traceability/stage-3-fault-points.json` vorgibt — ein Array aus `{"name", "brackets", "witness"}`, jeder `witness` als `<pfad>::<funktion>`, weil der Gate ihn spaeter auf eine wirklich vorhandene Testfunktion aufloest.

**Jeder `witness` dieses Manifests MUSS eine RUST-Testfunktion sein, und das ist eine gemessene Auflage und kein Stil.** `witness_resolves` in `tools/xtask/src/main.rs` — derselbe Aufloeser, den der Gate-Task Punkt fuer Punkt wiederverwendet — sucht die Zeichenkette `fn <name>(` und akzeptiert sie erst, wenn unmittelbar davor `#[test]` oder `#[tokio::test` steht. Ein Playwright-Zeuge in einer `.spec.ts` traegt weder das eine noch das andere; er wuerde mit „declares no function" abgewiesen und liesse den Stufe-4-Gate rot stehen, ohne dass ein Reader-Fehler vorlaege. Alle neun Zeugen von `docs/traceability/stage-3-fault-points.json` sind aus demselben Grund Rust-Testfunktionen. Browserlaeufe bleiben als ZUSAETZLICHER Beleg willkommen — sie stehen in der Prosa des jeweiligen Schritts, nie in der Spalte `witness`:

| Szenario | Klammer | Zeuge |
|---|---|---|
| `bundle-truncated` | eine im Transport abgeschnittene oder umbenannte Containerdatei: `EA-BUNDLE-MALFORMED`, und es entsteht KEIN Teilbericht | `crates/ea-reader/tests/file_mode.rs::a_truncated_or_wrongly_magicked_container_reports_the_bundle_code_and_no_report` |
| `directory-permission-revoked` | ein dauerhaft angebundener Ordner verliert zwischen zwei Oeffnungen seine Berechtigung: der Oeffnungsversuch bricht ab und der universelle Weg bleibt angeboten | `crates/ea-reader/tests/file_mode.rs::a_directory_source_that_stops_yielding_blobs_leaves_the_universal_path_available` |
| `substituted-archive` | ein untergeschobenes Archiv mit vollstaendiger EIGENER Vertrauenskette: der Lauf endet fail-closed an Gate `trust` und sagt ueber keinen Eintrag etwas aus | `crates/ea-reader/tests/file_mode_anchor.rs::a_substituted_archive_with_its_own_trust_chain_says_nothing_about_any_entry` |

Ledger. `WR-053` und `WR-054` sind die zwei `v1.1`-Zeilen, die die Aufgabe „Stufe-4-Vorlauf: ADR 0005, wasm-Werkzeugpins und die aufgehobene Blockade" bereits als `planned` angelegt hat, damit `WEB_READER_MUST_ROWS` in `tools/xtask/tests/stage_gate.rs` sie von Anfang an haelt; diese Aufgabe fuellt ihre Belegspalte mit den Testpfaden oben, den Statuswechsel vollzieht die Stufenabnahme. Zwei Formregeln sind dabei bindend, weil `web_reader_must_requirements_are_recorded_as_v1_1_rows` sie exakt vergleicht: die Quellspalte MUSS auf `5.3` beziehungsweise `5.4` ENDEN — die Zusicherung benutzt `ends_with` —, und die Version bleibt `v1.1`. `WR-052` bleibt unberuehrt auf Stufe `2` und Status `integrated`: der Ein-Datei-Buendelexport ist Stufe-2-Arbeit (Entscheidung D-HE2), diese Aufgabe VERBRAUCHT ihn und beansprucht ihn nicht ein zweites Mal.

- [ ] **Step 4: Run both ways, both caps, and the substituted archive**

Run: `cargo test --locked -p ea-reader --test file_mode --test file_mode_anchor && cargo test --locked -p ea-reader --doc && pnpm --dir apps/web test --run && pnpm --dir apps/web exec playwright test tests/e2e/file-mode.spec.ts && cargo run --locked -p xtask -- build-wasm`

Expected: PASS. Beleg fuer Beleg: Buendel und Verzeichnis liefern denselben `reportHash`, also ist der Komfortweg wirklich derselbe Bestand und keine zweite Lesart; jedes Objekt ohne Quittung steht auf `notServerConfirmed` UND `valid`, `gaps()` ist leer und `is_fully_verified()` bleibt wahr — die orthogonale Dimension senkt nichts; beide Deckel fallen am `push_blob`, das den Puffer noch nicht angelegt hat; die abgeschnittene und die umbenannte Datei liefern denselben stabilen `EA-BUNDLE-MALFORMED` und keinen Teilbericht. Die zwei `compile_fail`-Doctests belegen jetzt, was sie behaupten: `OpenedArchiveV1` und `ReaderFileMode` EXISTIEREN, und weder `confirmed_cursor()` noch `sync_service()` laesst sich an ihnen aufrufen — der Cursor entfaellt ersatzlos, jedes Objekt wird bei jedem Oeffnen vollstaendig geprueft. Der untergeschobene Bestand ist adversarisch gepaart: gegen SEINEN eigenen Anker traegt dasselbe Byte-fuer-Byte gleiche Buendel vollstaendig, gegen den gepinnten faellt es — das Protokoll endet nach `["format", "trust"]`, `objectResults` ist leer, `publicKeyThumbprints` ist leer, weil `ea-verify` diesen Nachweis erst HINTER dem fail-closed-Ausstieg eintraegt, und `chainHead` ist das Sentinel mit Sequenz null und ausdruecklich NICHT der `genesisEntryHash` des Ankers, der einen verifizierten Genesis-Eintrag behaupten wuerde. Ohne die Positivkontrolle waere der Fehlschlag von einer kaputten Fixture nicht zu unterscheiden.

- [ ] **Step 5: Commit the file mode**

```bash
git add crates/ea-reader crates/ea-reader-wasm apps/web docs/traceability/stage-4-fault-points.json
git commit -m "feat(reader): open archives from files against the pinned anchor"
```

### Task 10: Verschlüsselter invertierter Index in OPFS, Suche, Schemakompatibilität und die GEMESSENE 50.000-Paket-Schwelle (formerly Task 4)

**Files:**
- Create: `crates/ea-index/Cargo.toml`
- Create: `crates/ea-index/src/lib.rs`
- Create: `crates/ea-index/src/inverted.rs`
- Create: `crates/ea-index/src/blob.rs`
- Create: `crates/ea-index/src/schema_view.rs`
- Create: `crates/ea-reader/src/search.rs`
- Test: `crates/ea-index/tests/search.rs`
- Test: `crates/ea-index/tests/schema_compatibility.rs`
- Test: `crates/ea-index/tests/reindex.rs`
- Test: `crates/ea-index/tests/scale_50000.rs`
- Test: `crates/ea-reader-wasm/tests/index_browser.rs`
- Modify: `crates/ea-reader/src/lib.rs`
- Modify: `crates/ea-reader/Cargo.toml`
- Modify: `crates/ea-reader-wasm/Cargo.toml`
- Modify: `tools/xtask/src/main.rs`
- Modify: `tools/xtask/tests/workspace.rs`
- Test: `tools/xtask/tests/spec_completeness.rs` — NUR gefahren, nicht geaendert; seine zwei Praefixe ueberleben das angehaengte `-p ea-index`, siehe Schritt 4
- Modify: `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `package.json`

**Interfaces:**
- Consumes: `ea_schema::{SchemaError, SCHEMA_VERSION_V1}` für die eine Fehlerform des nicht unterstützten Schemas; `ea_crypto::{aead_seal, aead_open, SecretBytes, CEK_SIZE, AEAD_NONCE_SIZE, AEAD_OVERHEAD}`; `ea_types::{EntryHash, ChainSequence, RecordId, UnixMillis}`; `unicode-normalization`; den Indexschlüssel `UnlockedVault::index_key()` und den `ReaderBlobStore` über OPAKE Bytes aus den Tasks „Browser-Vault: PRF-Envelopes, Schlüsselprofil und die Verwahrung von Anchor und KEM-Schlüssel" und „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate". `crates/ea-index` konsumiert AUSDRÜCKLICH KEINEN Typ aus `crates/ea-reader`; die Richtung der Kante ist `ea-reader → ea-index` und läuft nie zurück.
- Produces: `crates/ea-index` mit `IndexableRecordV1`, `InvertedIndexV1`, `IndexBlobV1`, `ReaderQueryV1`, `ReaderSearchHitV1`, `SchemaViewV1`, `IndexPressureV1`, `IndexError`, den Konstanten `INDEX_BLOB_MAGIC_V1`, `INDEX_BLOB_HEADER_BYTES_V1`, `INDEX_FORMAT_VERSION_V1` und `MONOLITHIC_INDEX_MAX_PACKAGES_V1`; `ea_reader::search::{ReaderSearch, indexable_record}` als die EINE Umwandlung von `VerifiedDecryptedRecord` nach `IndexableRecordV1`; das Unterkommando `cargo run --locked -p xtask -- index-scale <n>` und das Wurzelskript `index:scale`; den vierzehnten Eintrag der wasm32-Positivliste.

Diese Aufgabe ersetzt den SQLCipher-Index des ursprünglichen Tasks 4 durch die Index-Crate, die `web-reader-design.md` §12 verlangt („Neu sind eine `wasm-bindgen`-Brücke und ein Index-Crate"). Was §8.1 widerlegt, wird ersetzt; was der ursprüngliche Task richtig hatte, bleibt WÖRTLICH: indiziert wird ausschließlich, was aus einem `VerifiedDecryptedRecord` hervorgegangen ist, Quell-Entry-Hash, Sequenz und Quellschema stehen an jeder Zeile, technische Einträge ohne Grant, ungültige Objekte, Stubs und nicht unterstützte Schemata erzeugen NIE eine erfundene Einsatzzeile, und ein Rebuild löscht ausschließlich abgeleitete Zeilen und rechnet aus den exakt zwischengespeicherten Archivbytes neu. Nicht gebaut werden hier: ein segmentierter Index, ein verschlüsselndes SQLite-VFS im Browser und ein zweiter Index in TypeScript (§8.1 zweiter Absatz verbietet die letzten beiden ausdrücklich).

- [ ] **Step 1: Write the search, schema, rebuild, and scale witnesses**

`crates/ea-index/tests/search.rs` hält die vier Filter und die Eintrittsgrenze. Die Eintrittsgrenze wird NICHT über einen Aufruf geprüft, den es nicht geben darf, sondern über die Abwesenheit einer zweiten Aufnahmemethode und über die Abwesenheit jeder Erwähnung von `VerifiedDecryptedRecord` in dieser Crate — dieselbe Form, mit der der Task „Sitzungssperre, Zeroize, authenticator-bestätigter Einzelexport und signiertes lokales Audit" die Abwesenheit eines Massenexports belegt.

```rust
#[test]
fn the_four_filters_run_locally_over_decrypted_field_values() {
    let mut index = InvertedIndexV1::empty();
    index.upsert(&fixtures::indexable_incident("2026-0001", "Brand", "LF 10", "Ada Lovelace",
        UnixMillis::new(1_771_000_000_000))).unwrap();
    index.upsert(&fixtures::indexable_incident("2026-0002", "Verkehrsunfall", "RTW 1", "Grace Hopper",
        UnixMillis::new(1_772_000_000_000))).unwrap();

    for (query, expected) in [
        (ReaderQueryV1::vehicle("LF 10"), "2026-0001"),
        (ReaderQueryV1::person("Ada Lovelace"), "2026-0001"),
        (ReaderQueryV1::keyword("Verkehrsunfall"), "2026-0002"),
        (ReaderQueryV1::period(UnixMillis::new(1_771_500_000_000),
                               UnixMillis::new(1_773_000_000_000)), "2026-0002"),
    ] {
        let hits = index.search(&query).unwrap();
        assert_eq!(hits.len(), 1, "query {query:?} must match exactly one record");
        assert_eq!(hits[0].human_incident_number(), expected);
        assert_eq!(hits[0].source_schema(), ("ea.incident", SCHEMA_VERSION_V1));
    }
    let combined = index.search(&ReaderQueryV1::keyword("Brand").and_vehicle("RTW 1")).unwrap();
    assert!(combined.is_empty(), "filters combine conjunctively, not disjunctively");
}

#[test]
fn exactly_one_ingestion_method_exists_and_it_never_names_a_reader_type() {
    let source = include_str!("../src/inverted.rs");
    assert_eq!(source.matches("pub fn upsert").count(), 1,
        "exactly one ingestion method may exist");
    assert_eq!(source.matches("pub fn rebuild_from").count(), 1);
    for forbidden in ["record_technical_state", "MissingGrant", "Quarantined", "pub fn upsert_raw"] {
        assert!(!source.contains(forbidden),
            "{forbidden} must not exist: technical state lives in ea-reader, never in the index");
    }
    // Die Kantenrichtung als Quelltextzusage: diese Crate kennt weder den
    // Zeugentyp noch den Geheimniswrapper. Waere hier ein
    // `VerifiedDecryptedRecord`, waere `ea-index` eine Abhaengigkeit von
    // `ea-reader` UND umgekehrt, und `cargo metadata` wiese den Arbeitsbereich
    // als Ganzes ab.
    for name in ["VerifiedDecryptedRecord", "SecretVec", "ea_reader"] {
        assert!(!source.contains(name),
            "{name} must not appear in ea-index: the edge runs ea-reader -> ea-index only");
    }
}

#[test]
fn search_terms_are_nfc_normalized_and_case_folded_but_never_stemmed() {
    let mut index = InvertedIndexV1::empty();
    index.upsert(&fixtures::indexable_incident("2026-0003", "Ölspur", "MTW", "Käthe Paulus",
        UnixMillis::new(1_771_000_000_000))).unwrap();
    assert_eq!(index.search(&ReaderQueryV1::keyword("o\u{0308}lspur")).unwrap().len(), 1);
    assert_eq!(index.search(&ReaderQueryV1::keyword("ÖLSPUR")).unwrap().len(), 1);
    assert!(index.search(&ReaderQueryV1::keyword("Ölspuren")).unwrap().is_empty());
}
```

`crates/ea-index/tests/schema_compatibility.rs` hält die Beschriftung beider Schemata und die Isolation des Unbekannten.

```rust
#[test]
fn every_view_labels_its_source_and_its_target_schema() {
    let view = SchemaViewV1::derive(&fixtures::indexable_incident_v1()).unwrap();
    assert_eq!(view.source_schema(), ("ea.incident", 1));
    assert_eq!(view.target_schema(), ("ea.incident", 1));
    // Die Ansicht traegt die BESCHRIFTUNG und die abgeleiteten Werte, nie die
    // exakten Nutzlastbytes: `IndexableRecordV1` bekommt sie gar nicht erst.
    assert_eq!(view.human_incident_number(), "2026-0001");
    let source = include_str!("../src/schema_view.rs");
    assert!(!source.contains("exact_source_bytes"),
        "the index never carries the exact payload bytes of a decrypted record");
}

#[test]
fn an_unsupported_schema_is_isolated_and_never_becomes_a_row() {
    let mut index = InvertedIndexV1::empty();
    let refused = SchemaViewV1::derive(&fixtures::indexable_record_with_schema("ea.unknown", 1));
    assert!(matches!(refused, Err(IndexError::Schema(SchemaError::Unsupported { .. }))));
    assert_eq!(index.upsert(&fixtures::indexable_record_with_schema("ea.incident", 99))
                   .unwrap_err().code(), "EA-SCHEMA-UNSUPPORTED");
    assert_eq!(index.indexed_packages(), 0);
    assert!(index.search(&ReaderQueryV1::keyword("Brand")).unwrap().is_empty());
}
```

`crates/ea-index/tests/reindex.rs` hält die Blob-Runde und den Rebuild. Die Zusage ist stärker als „es geht wieder auf": derselbe Bestand unter derselben Nonce muss den BYTEGLEICHEN Blob liefern, sonst ist der Rebuild keine Rekonstruktion, sondern eine zweite Wahrheit.

```rust
#[test]
fn the_blob_round_trips_through_chacha20poly1305_and_carries_no_plaintext() {
    let index = fixtures::index_over(&fixtures::three_records());
    let key = SecretBytes::new([0x33; CEK_SIZE]);
    let blob = IndexBlobV1::seal(&index, &key, &SecretBytes::new([0x07; AEAD_NONCE_SIZE])).unwrap();
    assert_eq!(&blob.bytes()[..INDEX_BLOB_MAGIC_V1.len()], &INDEX_BLOB_MAGIC_V1);
    for canary in [b"CANARY-PERSON".as_slice(), b"2026-0001".as_slice(), b"LF 10".as_slice()] {
        assert!(!fixtures::contains_subslice(blob.bytes(), canary),
            "no decrypted field value may appear in the sealed index blob");
    }
    let reopened = IndexBlobV1::open(blob.bytes(), &key).unwrap();
    assert_eq!(reopened.indexed_packages(), index.indexed_packages());
    assert_eq!(reopened.search(&ReaderQueryV1::vehicle("LF 10")).unwrap().len(), 1);
    assert_eq!(IndexBlobV1::open(blob.bytes(), &SecretBytes::new([0x34; CEK_SIZE]))
                   .unwrap_err().code(), "EA-CRYPTO-AEAD-OPEN");
    let mut tampered = blob.bytes().to_vec();
    *tampered.last_mut().unwrap() ^= 0x01;
    assert_eq!(IndexBlobV1::open(&tampered, &key).unwrap_err().code(), "EA-CRYPTO-AEAD-OPEN");
}

#[test]
fn a_rebuild_from_the_exact_cached_bytes_is_byte_identical() {
    let records = fixtures::three_records();
    let key = SecretBytes::new([0x33; CEK_SIZE]);
    let nonce = SecretBytes::new([0x07; AEAD_NONCE_SIZE]);
    let first = IndexBlobV1::seal(&fixtures::index_over(&records), &key, &nonce).unwrap();
    let rebuilt = InvertedIndexV1::rebuild_from(records.iter().rev()).unwrap();
    let second = IndexBlobV1::seal(&rebuilt, &key, &nonce).unwrap();
    assert_eq!(first.bytes(), second.bytes(),
        "insertion order must not reach the sealed bytes; the index is a BTreeMap");
}
```

`crates/ea-index/tests/scale_50000.rs` ist der GEMESSENE Zeuge der Schwelle. Er trägt `#[ignore]`, weil 50.000 Pakete kein Schnelllaufbudget sind, und wird ausschließlich über `cargo run --locked -p xtask -- index-scale 50000` gefahren.

```rust
#[test]
#[ignore = "run through `cargo run --locked -p xtask -- index-scale 50000`"]
fn fifty_thousand_packages_fit_the_monolithic_blob_and_report_their_cost() {
    assert_eq!(MONOLITHIC_INDEX_MAX_PACKAGES_V1, 50_000);
    let key = SecretBytes::new([0x33; CEK_SIZE]);
    let mut index = InvertedIndexV1::empty();
    let mut pressure = IndexPressureV1::Nominal;
    for package in 0..MONOLITHIC_INDEX_MAX_PACKAGES_V1 {
        pressure = index.upsert(&fixtures::synthetic_package(package)).unwrap();
    }
    assert_eq!(index.indexed_packages(), MONOLITHIC_INDEX_MAX_PACKAGES_V1);
    assert!(matches!(pressure, IndexPressureV1::SegmentationRequired { .. }),
        "the threshold package itself must raise the pre-authorized signal");

    let sealed_at = Instant::now();
    let blob = IndexBlobV1::seal(&index, &key, &SecretBytes::new([0x07; AEAD_NONCE_SIZE])).unwrap();
    let seal_ms = sealed_at.elapsed().as_millis();
    let unlock_at = Instant::now();
    let reopened = IndexBlobV1::open(blob.bytes(), &key).unwrap();
    let unlock_ms = unlock_at.elapsed().as_millis();
    let search_at = Instant::now();
    let hits = reopened.search(&ReaderQueryV1::vehicle("LF 49999")).unwrap();
    let search_us = search_at.elapsed().as_micros();
    assert_eq!(hits.len(), 1);

    // Gemessen, nicht behauptet. Die Zahlen gehen in den Stufe-4-Gate-Bericht.
    println!("ea-index scale packages={} blob_bytes={} seal_ms={} unlock_ms={} search_us={}",
        MONOLITHIC_INDEX_MAX_PACKAGES_V1, blob.bytes().len(), seal_ms, unlock_ms, search_us);

    let beyond = index.upsert(&fixtures::synthetic_package(MONOLITHIC_INDEX_MAX_PACKAGES_V1)).unwrap();
    assert!(matches!(beyond, IndexPressureV1::SegmentationRequired { indexed_packages: 50_001 }));
    assert_eq!(index.search(&ReaderQueryV1::vehicle("LF 50000")).unwrap().len(), 1,
        "past the threshold the index must still answer; the signal is not a refusal");
}
```

`crates/ea-reader-wasm/tests/index_browser.rs` fährt dieselbe Runde als `wasm-bindgen-test` in headless Chromium über den OPFS-Bytespeicher: versiegeln, in OPFS schreiben, Seite frisch laden, entsperren, suchen. Der Bestand ist klein (drei Pakete); der Zeuge belegt den WEG durch OPFS und die Brücke, nicht die Größenordnung.

- [ ] **Step 2: Run the witnesses and confirm the index crate is absent**

Run: `cargo test --locked -p ea-index --test search --test schema_compatibility --test reindex`

Expected: FAIL, und zwar bereits an der Paketauflösung: `cargo` meldet `package ID specification 'ea-index' did not match any packages`, weil `crates/ea-index` weder als Verzeichnis noch als Mitglied existiert. Das ist der beabsichtigte erste rote Punkt. Erst nach Schritt 3 laufen die Zeugen als Tests und scheitern dann inhaltlich; die Reihenfolge ist unvermeidbar, weil `workspace_declares_exact_planned_members_and_shared_dependencies` in `tools/xtask/tests/workspace.rs` eine `members`-Zeile ohne Manifest ohnehin rot färbte und `cargo metadata` gar nicht mehr aufginge.

- [ ] **Step 3: Implement the inverted index, its sealed blob, and the measured scale command**

```rust
/// Das Präfix des versiegelten Indexblobs, nach dem Muster von
/// `BUNDLE_MAGIC_V1` in `ea-archive`.
pub const INDEX_BLOB_MAGIC_V1: [u8; 30] = *b"EINSATZARCHIV-READER-INDEX-v1\n";
pub const INDEX_FORMAT_VERSION_V1: u32 = 1;
/// 30 Byte Magic + 4 Byte Formatversion (big-endian) + 12 Byte Nonce.
pub const INDEX_BLOB_HEADER_BYTES_V1: usize = INDEX_BLOB_MAGIC_V1.len() + 4 + AEAD_NONCE_SIZE;

/// Die VERBINDLICHE Schwelle des monolithischen Einzelblob-Index
/// (`web-reader-design.md` §8.1, dort offen gelassen und hier festgelegt).
pub const MONOLITHIC_INDEX_MAX_PACKAGES_V1: usize = 50_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IndexPressureV1 {
    Nominal,
    SegmentationRequired { indexed_packages: usize },
}

/// Die EINGABE des Index — deklariert HIER und nicht in `crates/ea-reader`.
///
/// Sie traegt AUSSCHLIESSLICH bereits normalisierte abgeleitete Werte plus die
/// Herkunftsspalten, die an jeder Indexzeile haengen muessen. Keine
/// Nutzlastbytes, kein `SecretVec`, kein Zeugentyp: `IndexableRecordV1` ist ein
/// gewoehnlicher Wert, den diese Crate ohne jede Kenntnis des Readers bauen,
/// pruefen und ablegen kann.
pub struct IndexableRecordV1 {
    // Herkunft — an jeder Zeile, in jeder Suche, in jedem Treffer.
    pub source_entry_hash: EntryHash,
    pub chain_sequence: ChainSequence,
    pub record_id: RecordId,
    pub source_schema_id: String,
    pub source_schema_version: u64,
    pub target_schema_id: String,
    pub target_schema_version: u64,
    // Abgeleitete, bereits NFC-normalisierte und klein gefaltete Werte.
    pub human_incident_number: String,
    pub occurred_at_start: UnixMillis,
    pub occurred_at_end: Option<UnixMillis>,
    pub keyword_terms: Vec<String>,
    pub vehicle_terms: Vec<String>,
    pub person_terms: Vec<String>,
}

pub struct InvertedIndexV1 { /* BTreeMap<TermKey, BTreeSet<PackageOrdinal>>, Vec<IndexedPackageV1> */ }

impl InvertedIndexV1 {
    #[must_use] pub fn empty() -> Self;
    pub fn upsert(&mut self, record: &IndexableRecordV1) -> Result<IndexPressureV1, IndexError>;
    pub fn rebuild_from<'a>(records: impl IntoIterator<Item = &'a IndexableRecordV1>)
        -> Result<Self, IndexError>;
    pub fn search(&self, query: &ReaderQueryV1) -> Result<Vec<ReaderSearchHitV1>, IndexError>;
    #[must_use] pub fn indexed_packages(&self) -> usize;
    /// Der Weg zurueck an einen Treffer laeuft ueber die HERKUNFTSKENNUNG und
    /// nie ueber einen Readertyp.
    pub fn hit_for(&self, entry_hash: EntryHash) -> Option<&ReaderSearchHitV1>;
}

pub struct IndexBlobV1 { /* private */ }

impl IndexBlobV1 {
    /// Die Nonce ist ein PARAMETER und keine Eigenleistung dieser Crate.
    pub fn seal(index: &InvertedIndexV1, key: &SecretBytes<CEK_SIZE>,
                nonce: &SecretBytes<AEAD_NONCE_SIZE>) -> Result<Self, IndexError>;
    pub fn open(bytes: &[u8], key: &SecretBytes<CEK_SIZE>) -> Result<InvertedIndexV1, IndexError>;
    #[must_use] pub fn bytes(&self) -> &[u8];
}
```

**Warum die Eingabe `IndexableRecordV1` heisst und nicht `VerifiedDecryptedRecord`.** Der Zeugentyp `VerifiedDecryptedRecord` entsteht in `crates/ea-reader` und ist dort — mit voller Absicht — nirgendwo sonst konstruierbar. Naehme `upsert` ihn entgegen, brauchte `crates/ea-index` eine Kante auf `crates/ea-reader`, waehrend `crates/ea-reader` gleichzeitig eine Kante auf `crates/ea-index` braucht, um zu suchen. `cargo metadata` weist einen solchen Kreis ab, und mit ihm faellt der GANZE Arbeitsbereich: jedes Kommando ab dieser Aufgabe waere tot. Die Kante laeuft deshalb EINSEITIG, `ea-reader → ea-index`, und `crates/ea-index` deklariert seine eigene Eingabe.

Dieselbe Entscheidung traegt die Klartextdisziplin, und das ist kein zweiter Grund, sondern derselbe. `VerifiedDecryptedRecord` haelt seine Nutzlast in `ea_crypto::SecretVec` und gibt sie ausschliesslich AUSLEIHEND heraus (`with_plaintext`, `with_payload`) — die Flaeche, die die Aufgabe „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert" abschliessend deklariert. `crates/ea-index` DARF deshalb einen `SecretVec` gar nicht anfassen: eine Crate, die ihn hielte, muesste ihn ueber eine Crategrenze weiterreichen, und genau das verbieten `WR-082`, `FR-105` und die Produktinvariante, dass kein entschluesselter Inhalt im Klartext in OPFS-Bytes, Caches, Protokolle oder Telemetrie gelangt. Der Kreisbruch und die Klartextdisziplin sind EINE Entscheidung.

Die Umwandlung besitzt `crates/ea-reader`, und sie geschieht INNERHALB der ausleihenden Zugriffe: `ea_reader::search::indexable_record(&VerifiedDecryptedRecord) -> Result<IndexableRecordV1, ReaderError>` ruft `with_payload`, projiziert im Rumpf der Ausleihe die vier Filterfelder und die Einsatznummer, normalisiert sie und gibt einen `IndexableRecordV1` zurueck. Weder der Geheimniswrapper noch eine Ausleihe auf Klartextbytes ueberquert dabei die Crategrenze; was hinuebergeht, sind fertige, normalisierte Zeichenketten und Herkunftsspalten. `crates/ea-reader/Cargo.toml` bekommt dafuer die Kante `ea-index.workspace = true`, und `crates/ea-index/Cargo.toml` bekommt KEINE Gegenkante — der Quelltextzeuge `exactly_one_ingestion_method_exists_and_it_never_names_a_reader_type` haelt das fest. `crates/ea-reader/src/lib.rs` nimmt im selben Zug `mod search;` samt seinem `pub use`-Block auf; ohne diese Zeile uebersetzt der Commit nicht.

`crates/ea-reader-wasm/Cargo.toml` bekommt `ea-index.workspace = true` als DEV-Kante, und diese Zeile ist die Voraussetzung des Browserzeugen. `crates/ea-reader-wasm` haengt heute an `ea-reader` und NICHT an `ea-index`; `crates/ea-reader-wasm/tests/index_browser.rs` benennt aber `IndexBlobV1`, `InvertedIndexV1` und `ReaderQueryV1` unmittelbar, weil es die Blobrunde versiegelt, in OPFS schreibt und wieder oeffnet. Ein Re-Export durch `ea-reader` waere die schlechtere Alternative: er machte aus einer Testkante eine BIBLIOTHEKSflaeche, die jeder Wirt der Bruecke mittraegt, und stellte neben `crates/ea-index` eine zweite Nennung derselben Typen. Die Kante ist DEV und keine Bibliothekskante — die wasm32-Zeile faehrt ohne `--all-targets` —, und weil `ea-index` in diesem Commit selbst auf die Positivliste tritt, uebersetzt der Browserzeuge fuer `wasm32-unknown-unknown`.

Auch die SCHEMAABLEITUNG bleibt damit auf der Readerseite: `SchemaRegistry::v1().derive_view(schema_id, schema_version, exact_bytes)` braucht die exakten Nutzlastbytes und laeuft deshalb in `indexable_record` innerhalb der Ausleihe. `IndexableRecordV1` traegt danach nur noch die vier Beschriftungsspalten. `SchemaViewV1::derive` in dieser Crate liest sie und weist ein Zielschema ab, das sie nicht projizieren kann — mit `IndexError::Schema(SchemaError::Unsupported { .. })` und damit dem bereits stabilen Code `EA-SCHEMA-UNSUPPORTED`, weil ein zweiter Code fuer dieselbe Tatsache genau die zweite Wahrheit waere, die dieser Plan sonst ueberall vermeidet. `ea-schema` bleibt dafuer eine Kante von `ea-index`, aber ausschliesslich fuer diese Fehlerform und `SCHEMA_VERSION_V1`; ein `PayloadV1` betritt die Crate nicht.

**Die Schwelle und warum sie genau 50.000 PAKETE ist.** `web-reader-design.md` §8.1 sagt „einige zehntausend Einsätze" und verschiebt die verbindliche Zahl in diese Überarbeitung. Sie ist nicht frei wählbar: `design.md` §20.3 fordert „Ein Reader verifiziert und indiziert mindestens 50.000 Pakete", die Kriterienliste führt sie als AK 31 und die Anforderungstabelle als `NFR-PERF-003`, und Stufe 7 misst sie in `tests/ea-system-tests/tests/performance_reader_50000.rs` mit genau dieser Zahl. Eine Schwelle UNTER 50.000 lieferte eine Stufe-4-Indexarchitektur, die ihr eigenes Stufe-7-Gate nachweislich nicht bestehen kann. Die Einheit ist ausdrücklich das PAKET und nicht der Einsatz: ein Einsatz trägt ein Original plus seine Nachträge, die beide je ein eigenes Paket sind, und die Stufe-7-Messung zählt Pakete. Oberhalb der Schwelle ist der Wechsel auf segmentierte, einzeln verschlüsselte Indexblöcke die von §8.1 als lokaler Eingriff ohne Architekturänderung VORAB genehmigte Maßnahme; sie wird hier nicht gebaut.

`upsert` verweigert oberhalb der Schwelle NICHT. Eine Verweigerung nähme einem Reader den Zugriff auf Inhalte, für die er einen gültigen Grant besitzt, und das widerspräche der Produktinvariante, dass fehlender Zugriff nur aus fehlendem Grant folgt und nie aus einer Ressourcengrenze. Stattdessen liefert `upsert` ab dem Paket, das die Schwelle erreicht, `IndexPressureV1::SegmentationRequired { indexed_packages }`; die Suche bleibt vollständig korrekt, und `ea_reader::search::ReaderSearch` reicht das Signal als technischen Zustand an die Oberfläche des Tasks „Integritätszentrierte Reader-Oberfläche in `apps/web` und die Rollengrenze zum Desktop" weiter. Das Signal ist damit ein gemessener Auslöser für die vorab genehmigte Segmentierung und keine stille Grenze, die erst in Stufe 7 auffällt.

**Der Blob.** Der Kopf sind `INDEX_BLOB_HEADER_BYTES_V1` Klartextbytes: Magic, Formatversion, Nonce. Danach folgt genau ein ChaCha20-Poly1305-Chiffrat über den deterministisch minicbor-kodierten Indexkörper, mit dem KOPF als AAD — damit sind Formatversion und Nonce authentisiert und ein Rückspielen eines älteren Blobs unter neuem Kopf fällt an `aead_open` durch. Gesiegelt wird über `ea_crypto::aead_seal`, geöffnet über `aead_open`; diese Crate baut keine zweite AEAD-Bindung. Der Schlüssel wird dieser Crate GEREICHT und von ihr niemals abgeleitet: sie EMPFÄNGT ein `&SecretBytes<CEK_SIZE>`, das der Aufrufer aus `UnlockedVault::index_key()` bezieht — der öffentlichen Methode, die der Task „Browser-Vault: PRF-Envelopes, Schlüsselprofil und die Verwahrung von Anchor und KEM-Schlüssel" auf `impl UnlockedVault` deklariert und die intern `HKDF-SHA-256(vault_key, info = VAULT_INDEX_INFO_V1)` rechnet, also denselben Ableitungsweg wie Cache und Zustandsspeicher. `derive_key` ist in `crates/ea-reader/src/envelope.rs` modulprivat und für eine fremde Crate unerreichbar; ein zweiter Ableitungspfad hier wäre eine zweite Wahrheit über denselben Schlüssel. Der empfangene Wert liegt unter `ZeroizeOnDrop` und wird hier nie kopiert, nie formatiert und nie persistiert.

`ea-index` erzeugt KEINE Entropie: Die Nonce ist ein Parameter, genau wie Uhr, Trust Anchor und Empfängerschlüssel in `ea-verify` Parameter sind. Das hat drei messbare Folgen: die Crate zieht `getrandom` nicht in ihren Graphen, sie ist im Test byteweise reproduzierbar — was `a_rebuild_from_the_exact_cached_bytes_is_byte_identical` überhaupt erst prüfbar macht —, und die Wahl einer frischen Nonce je Versiegelung bleibt eine Entscheidung von `ea-reader`, wo sie hingehört. Ebenso verboten sind hier `std::fs`, `std::time` und `HashMap`/`HashSet`: der Bestand liegt in `BTreeMap`/`BTreeSet` über den normalisierten Termschlüssel, weil eine Streuordnung die Bytegleichheit des Rebuilds sporadisch kippte und in Unit-Tests unauffällig bliebe. Das ist dieselbe Begründung, mit der `crates/ea-verify/src/lib.rs` `HashMap` und `HashSet` ausschließt.

**Normalisierung.** Termschlüssel entstehen aus NFC-normalisierten, klein gefalteten Feldwerten über `unicode-normalization`, dieselbe Kante, die `ea-schema`, `ea-cbor` und `ea-format` bereits führen; eine neue Abhängigkeit entsteht dadurch nicht. Es wird NICHT gestemmt und nicht sprachabhängig zerlegt: eine Stemming-Regel wäre eine fachliche Entscheidung über Einsatzsprache, die dieses Projekt nirgends getroffen hat, und ihr stiller Einbau machte die Suche zwischen zwei Releases inkompatibel, ohne dass ein Byte des Archivs sich änderte.

**Die vier Filter.** `ReaderQueryV1` trägt Zeitraum, Stichwort, Fahrzeug und Person und verknüpft gesetzte Filter KONJUNKTIV. Der Zeitraum läuft über `IncidentV1::occurred_at()` — `OccurredAtV1::start()` und `end()` —, das Stichwort über `KeywordV1::as_free_text()` und den Anzeigetext des Referenzarms `as_reference()`, das Fahrzeug über `VehicleSnapshotV1::{display_name, radio_call_sign, license_plate}` und die Person über `PersonnelSnapshotV1::display_name()`. Alles läuft LOKAL; eine serverseitige Inhaltssuche ist ein festes Nicht-Ziel (`design.md` Nichtziele, `web-reader-design.md` §13).

**Was an jeder Zeile hängt.** `ReaderSearchHitV1` trägt `entry_hash`, `chain_sequence`, `record_id`, die menschliche Einsatznummer, den Beginn des Zeitraums sowie Quell- UND Zielschema. Beide Beschriftungen kommen als FERTIGE Spalten aus `IndexableRecordV1` — `ea_reader::search::indexable_record` hat sie dort aus `SchemaRegistry::v1().derive_view(schema_id, schema_version, exact_bytes)` und dessen `DerivedView::{source_schema_id, source_schema_version, target_schema_id, target_schema_version}` eingetragen, INNERHALB der Ausleihe auf den Klartext —, und `SchemaViewV1::derive` liest sie hier nur noch. Ein nicht unterstütztes Schema liefert `SchemaError::Unsupported` und wird ISOLIERT: es entsteht keine Zeile, `indexed_packages()` steigt nicht, und der Datensatz erscheint im technischen Zustandsspeicher des Tasks „Browser-Vault: PRF-Envelopes, Schlüsselprofil und die Verwahrung von Anchor und KEM-Schlüssel", nicht hier. Spätere Regeln des jeweils aktuellen Schemas entwerten v1-Payloads nicht, weil `DerivedView` in v1 die Identitätsansicht ist und die exakten Quellbytes mitführt.

**Der Rebuild.** `rebuild_from` nimmt die exakt zwischengespeicherten, bereits verifizierten und entschlüsselten Datensätze und baut den Index vollständig neu. Kein veränderlicher Indexzustand ist maßgeblich: maßgeblich sind die exakten Archivbytes im Cache, und der Index ist ihre ableitbare Projektion. Deshalb ist Einfügereihenfolge in den versiegelten Bytes unsichtbar, und deshalb ist der Verlust des Blobs kein Datenverlust.

**Registrierung im Arbeitsbereich, alles in DIESEM Commit.** `Cargo.toml` bekommt `crates/ea-index` unter `[workspace]members` und `ea-index = { path = "crates/ea-index" }` unter `[workspace.dependencies]`; `crates/ea-reader/Cargo.toml` erbt es mit `workspace = true`, wie `workspace_declares_exact_planned_members_and_shared_dependencies` es für jede Mitgliedskante verlangt. `tools/xtask/tests/workspace.rs` bekommt `"crates/ea-index"` in `WORKSPACE_MEMBERS`. `tools/xtask/src/main.rs` bekommt `"-p", "ea-index"` ans ENDE des wasm32-Argumentvektors in `verify_quick_commands()`, und `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md` bekommt dasselbe `-p ea-index` ans Ende seiner Gate-Kommandozeile. Beides zusammen und nicht einzeln, denn `every_crates_member_is_classified_for_the_wasm32_gate` vergleicht die `-p`-Namen des Plans mit `assert_eq!` gegen die Positivliste und weist zusätzlich jedes unklassifizierte Mitglied unter `crates/` ab. `verify_quick_block_in_stage_one_plan_matches_the_gate` in `tools/xtask/tests/spec_completeness.rs` bleibt davon unberührt: es prüft die PRÄFIXE `"check", "--target", "wasm32-unknown-unknown", "--locked"` und `cargo check --target wasm32-unknown-unknown --locked -p ea-types`, und Anhängen lässt beide stehen. Der eingefrorene Kommentar über dem wasm32-Block ist bereits im Task „wasm32-Reichweite: `ea-reader`, die Brücken-Crate und die geteilten Browserkerne" für die ganze Stufe umgeschrieben worden; dieser Task fasst ihn NICHT ein zweites Mal an. `ea-index` gehört auf die Positivliste und nicht in `WASM32_EXEMPT_CRATES`: dessen Doc-Kommentar nennt als Kriterium „A crate that reaches past `ea-verify` into the host operating system", und diese Crate greift auf nichts zu — kein Dateisystem, keine Uhr, keine Entropie, kein Netz —, sie ist der Index, den §8.1 in den WASM-Speicher lädt.

**Das Messkommando.** `tools/xtask/src/main.rs` bekommt den Arm `index-scale` im Dispatcher `match gate.as_str()`. Die Argumentgrammatik wird ausgeschrieben wie bei `stage-gate` und `integration`: `index-scale` nimmt genau ein numerisches Argument und weist jedes weitere Wort und jedes nicht-numerische Argument ab. Der Arm fährt `cargo test --locked -p ea-index --test scale_50000 -- --ignored --nocapture` und schreibt die gemessenen Werte — Blobgröße in Byte, Versiegelungs- und Entsperrdauer in Millisekunden, Suchdauer in Mikrosekunden, Spitzenspeicher des Testprozesses — als eine Zeile auf `stdout`. `package.json` bekommt das Wurzelskript `"index:scale": "cargo run --locked -p xtask -- index-scale 50000"` neben den bestehenden xtask-Skripten; `STAGE_TWO_REQUIRED_SCRIPTS` und `STAGE_THREE_REQUIRED_SCRIPTS` prüfen VORHANDENSEIN und nicht Vollständigkeit, ein zusätzliches Skript färbt also nichts rot. `verify_quick_commands()` bekommt dieses Kommando AUSDRÜCKLICH NICHT: 50.000 Pakete sind kein Schnelllaufbudget, und die Liste trägt seit Stufe 1 die Reihenfolge billig vor teuer.

- [ ] **Step 4: Run the index, schema, rebuild, browser, and scale witnesses**

Run:

```bash
cargo metadata --format-version 1
cargo test --locked -p ea-index --test search --test schema_compatibility --test reindex
cargo test --locked -p xtask --bins --test workspace --test spec_completeness
cargo run --locked -p xtask -- index-scale 50000
pnpm web:browser-test
```

`cargo metadata --format-version 1` steht als ERSTE Zeile und ist das GENAU EINE Kommando dieses Tasks ohne `--locked`: Schritt 3 registriert `crates/ea-index` als Mitglied UND traegt die Kante `ea-index.workspace = true` in `crates/ea-reader/Cargo.toml` ein, und beides schreibt `Cargo.lock` fort. Es steht NACH der Registrierung und VOR jedem `--locked`-Kommando; stuende es in Schritt 2, faende es das Mitglied noch nicht und jedes `--locked`-Kommando danach fiele an einem ueberholten Lockfile. `--bins` faehrt den zeichengenauen Pin `verify_quick_uses_the_required_locked_commands` in der `mod tests` von `tools/xtask/src/main.rs`, den das angehaengte `-p ea-index` mitzieht; `tools/xtask` hat kein `[lib]`, `--lib` waere hier gemessen `no library targets found`.

Expected: PASS. Belegt sind die Positive: alle vier Filter treffen lokal und konjunktiv, NFC-zerlegte und großgeschriebene Eingaben finden denselben Datensatz, jede Zeile trägt Quell- und Zielschema, der versiegelte Blob geht unter demselben Schlüssel wieder auf und trägt in seinen Bytes keinen Kanarienvogel, ein Rebuild aus derselben Menge in umgekehrter Reihenfolge liefert BYTEGLEICHE Bytes, und derselbe Weg läuft in headless Chromium durch OPFS. Belegt sind ebenso die Adversarien: ein falscher Schlüssel ist `EA-CRYPTO-AEAD-OPEN`, ein um ein Bit verändertes Chiffrat ist `EA-CRYPTO-AEAD-OPEN`, ein unbekanntes Schema und eine unbekannte Schemaversion sind `EA-SCHEMA-UNSUPPORTED` und erhöhen `indexed_packages()` nicht, `Ölspuren` findet `Ölspur` NICHT, und der Quelltextzeuge belegt beides zusammen: es existiert GENAU EINE Aufnahmemethode, sie nimmt ausschließlich `&IndexableRecordV1`, und die Crate benennt KEINEN Readertyp — weder `VerifiedDecryptedRecord` noch `SecretVec` noch `ea_reader` stehen in `crates/ea-index/src/inverted.rs`. Die Umwandlung aus dem Zeugentyp besitzt `ea_reader::search::indexable_record` und läuft innerhalb der ausleihenden Klartextzugriffe.

`index-scale 50000` liefert die GEMESSENEN Zahlen — Blobgröße, Versiegelungs- und Entsperrdauer, Suchdauer, Spitzenspeicher — und die Zusicherung, dass das 50.000ste Paket das Signal `IndexPressureV1::SegmentationRequired` auslöst und das 50.001ste weiterhin gefunden wird. Diese Zahlen sind die Übergabe an Stufe 7: `tests/ea-system-tests/tests/performance_reader_50000.rs` misst dieselbe Größenordnung gegen `NFR-PERF-003` / AK 31, und weil sie hier bereits stehen, findet Stufe 7 keine Wand, die sie nicht mehr verschieben kann. Dieser Task BEANSPRUCHT die Ledgerzeile `AK-31` ausdrücklich NICHT; sie bleibt Stufe 7. `NFR-PERF-003` ist kein Ledgerbezeichner, sondern eine Zeile der Anforderungstabelle in `design.md`, und wird hier nur als Herkunft der Zahl genannt.

Die Ledgerzeile `FR-103` (Reader-Index als Ganzes mit ChaCha20-Poly1305 verschlüsselt in OPFS statt SQLCipher) bekommt hier ihren Beleg. Umgestellt wird sie NICHT hier: Statusspalte und Belegspalte in `docs/traceability/v0.1-requirements.csv` fasst ausschließlich der Task „Reader-Interoperabilität, Browser-Matrix, Datei-Modus, Privatheit und das Stufe-4-Gate" an, gemeinsam mit den übrigen sechzehn Zeilen, die diese Stufe bewegt. `docs/adr/0002-local-database-encryption.md` wird NICHT angefasst: SQLCipher entfällt im READER-Pfad, der Writer behält es unverändert (`web-reader-design.md` §8.1 erster Satz, §2 Punkt 6), und `crates/ea-local-store` bleibt aus demselben Grund auf `WASM32_EXEMPT_CRATES`.

- [ ] **Step 5: Commit the encrypted inverted index**

```bash
git add crates/ea-index crates/ea-reader/src/search.rs crates/ea-reader/src/lib.rs crates/ea-reader/Cargo.toml crates/ea-reader-wasm/Cargo.toml crates/ea-reader-wasm/tests/index_browser.rs tools/xtask/src/main.rs tools/xtask/tests/workspace.rs docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md package.json Cargo.toml Cargo.lock
git commit -m "feat(reader): index verified records in an encrypted opfs blob"
```

### Task 11: Nachtragsreferenzen und Original/Nachtrag-Projektion (formerly Task 5)

**Files:**
- Create: `crates/ea-reader/src/amendment.rs`
- Modify: `crates/ea-reader/src/lib.rs`
- Test: `crates/ea-reader/tests/amendments.rs`

**Interfaces:**
- Consumes: `VerifiedDecryptedRecord` aus der Aufgabe „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert", und zwar über genau vier Zugriffe ihrer dort abschließend deklarierten Fläche: `entry_hash() -> EntryHash`, `chain_sequence() -> ChainSequence`, `with_payload<R>(&self, f: impl FnOnce(&PayloadV1) -> R) -> R` und `with_plaintext<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R`. Beide Klartextwege sind AUSLEIHEND und geben nichts heraus; ein `exact_plaintext_bytes() -> &[u8]` existiert nicht und wird hier auch nicht angefordert. Dazu `ea_schema::{PayloadV1, AmendmentV1, IncidentV1}` mit `AmendmentV1::{original_record_id, original_entry_hash, original_sequence, original_incident_number}`, `IncidentV1::human_incident_number`, `CommonHeaderV1::record_id`, und `ea_types::{RecordId, EntryHash, ChainSequence, VerificationStatus}`.
- Produces: `ReaderEntryThread::{build, original, amendments, rejected, correction_reference}`, `CorrectionReference`, `RejectedAmendment` und `AmendmentJoinErrorV1`.

Diese Aufgabe wird nach `web-reader-design.md` §12 UNVERÄNDERT übernommen — §12 nennt sie als die eine, die bleibt. Der Spec widerlegt an ihr nichts: sie kennt kein SQLCipher, keinen Tauri-Befehl, keinen nativen Key-Provider und keinen OS-Lock. Geändert hat sich ausschließlich ihr Crate-Zuhause, das seit der Aufgabe „wasm32-Reichweite: `ea-reader`, die Brücken-Crate und die geteilten Browserkerne" wasm32-fähig ist; die Verbindung erhält deshalb KEINE eigene Browserbindung und erreicht die Oberfläche über die DTOs der Aufgabe „Integritätszentrierte Reader-Oberfläche in `apps/web` und die Rollengrenze zum Desktop". Sie führt keine Kryptooperation aus, öffnet keine Datei, macht keinen Netzaufruf und indiziert nichts.

- [ ] **Step 1: Write multi-amendment, ordering and no-replacement tests**

```rust
// crates/ea-reader/tests/amendments.rs

#[test]
fn amendments_join_without_replacing_the_original() {
    let thread = ReaderEntryThread::build(
        fixtures::original(),
        vec![fixtures::amendment_b(), fixtures::amendment_a()],
    )
    .unwrap();

    thread.original().with_payload(|payload| {
        let PayloadV1::Incident(incident) = payload else {
            panic!("the original of a thread is an incident record")
        };
        assert_eq!(incident.header().record_id(), fixtures::original_record_id());
        assert_eq!(incident.human_incident_number(), "2026-0001");
    });
    // Sortiert nach Kettensequenz, nicht nach Eingabereihenfolge: `amendment_b`
    // steht vorn und traegt die HOEHERE Sequenz.
    assert_eq!(
        thread.amendments().iter().map(|a| a.chain_sequence()).collect::<Vec<_>>(),
        vec![ChainSequence::new(7), ChainSequence::new(9)]
    );
    // Das Original bleibt vollstaendig sichtbar: dieselben Bytes, derselbe
    // Eintragshash, kein Kennzeichen `ueberholt` und keine Verdeckung.
    thread
        .original()
        .with_plaintext(|bytes| assert_eq!(bytes, fixtures::original_plaintext()));
    assert_eq!(thread.original().entry_hash(), fixtures::original_entry_hash());
    for amendment in thread.amendments() {
        assert_ne!(amendment.entry_hash(), thread.original().entry_hash());
        assert!(amendment.with_payload(|payload| matches!(payload, PayloadV1::Amendment(_))));
        assert!(amendment.with_plaintext(|bytes| !bytes.is_empty()));
    }

    // Die Korrekturreferenz ist klartextfrei und traegt GENAU drei Felder. Das
    // erschoepfende Strukturliteral ist die Zusicherung: ein viertes Feld
    // uebersetzt hier nicht mehr, und die Einsatznummer waere genau dieses
    // vierte Feld.
    assert_eq!(
        thread.correction_reference(),
        CorrectionReference {
            original_record_id: fixtures::original_record_id(),
            original_sequence: ChainSequence::new(4),
            original_entry_hash: fixtures::original_entry_hash(),
        }
    );
}

#[test]
fn a_mismatched_reference_stays_a_verification_problem_instead_of_joining() {
    for (candidate, reason) in [
        (fixtures::amendment_with_foreign_record_id(), AmendmentJoinErrorV1::OriginalRecordIdMismatch),
        (fixtures::amendment_with_flipped_entry_hash(), AmendmentJoinErrorV1::OriginalEntryHashMismatch),
        (fixtures::amendment_with_wrong_sequence(), AmendmentJoinErrorV1::OriginalSequenceMismatch),
        (fixtures::amendment_with_other_incident_number(), AmendmentJoinErrorV1::IncidentNumberMismatch),
        (fixtures::an_incident_record(), AmendmentJoinErrorV1::NotAnAmendment),
    ] {
        let thread = ReaderEntryThread::build(fixtures::original(), vec![candidate]).unwrap();
        assert!(thread.amendments().is_empty(), "{reason:?} must not join the thread");
        assert_eq!(thread.rejected().len(), 1);
        assert_eq!(thread.rejected()[0].reason, reason);
        // Ein abgewiesener Nachtrag ist ein PRUEFPROBLEM, kein leerer Einsatz und
        // keine Luecke: er behaelt seinen Eintragshash und seinen Status.
        assert_eq!(thread.rejected()[0].status, VerificationStatus::Invalid);
        // Und er aendert am Original nichts.
        assert_eq!(thread.original().entry_hash(), fixtures::original_entry_hash());
    }
}

#[test]
fn the_thread_refuses_an_original_that_is_not_an_incident_and_a_duplicate_sequence() {
    assert_eq!(
        ReaderEntryThread::build(fixtures::a_genesis_record(), Vec::new()).unwrap_err(),
        AmendmentJoinErrorV1::NotAnIncident
    );
    let thread = ReaderEntryThread::build(
        fixtures::original(),
        vec![fixtures::amendment_a(), fixtures::amendment_a_again_at_the_same_sequence()],
    )
    .unwrap();
    assert_eq!(thread.amendments().len(), 1);
    assert_eq!(thread.rejected()[0].reason, AmendmentJoinErrorV1::DuplicateSequence);
}
```

- [ ] **Step 2: Run the amendment tests and verify the projection is missing**

Run: `cargo test --locked -p ea-reader --test amendments`

Expected: FAIL, weil `ReaderEntryThread`, `CorrectionReference`, `RejectedAmendment` und `AmendmentJoinErrorV1` nicht existieren. Der Baustoff dagegen existiert vollständig und wird NICHT neu erfunden: `crates/ea-schema/src/model.rs` führt `AmendmentV1` mit den vier Referenzfeldern `original_incident_number`, `original_record_id`, `original_entry_hash` und `original_sequence` seit Stufe 1, ihre Wireform steht als `amendment-body-v1` in `schemas/payload/v1/payload.cddl`, und `AmendmentV1::validate` prüft dort bereits UUIDv7-Gestalt und Zeichenzahlen. Was fehlt, ist ausschließlich der VERGLEICH dieser Felder gegen das verifizierte Original und die stabile Ordnung.

- [ ] **Step 3: Implement exact references and stable ordering**

```rust
/// Die klartextfreie Korrekturreferenz fuer die Writer-Uebergabe der Stufe 5.
///
/// Genau drei Felder. Die Einsatznummer steht AUSDRUECKLICH nicht darin: sie ist
/// ein fachlicher Klartextwert, und diese Struktur reist zum Writer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CorrectionReference {
    pub original_record_id: RecordId,
    pub original_sequence: ChainSequence,
    pub original_entry_hash: EntryHash,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AmendmentJoinErrorV1 {
    NotAnIncident,
    NotAnAmendment,
    OriginalRecordIdMismatch,
    OriginalEntryHashMismatch,
    OriginalSequenceMismatch,
    IncidentNumberMismatch,
    DuplicateSequence,
}

pub struct RejectedAmendment {
    pub entry_hash: EntryHash,
    pub chain_sequence: ChainSequence,
    pub reason: AmendmentJoinErrorV1,
    pub status: VerificationStatus,
}

pub struct ReaderEntryThread { /* opak: nur ueber build konstruierbar */ }

impl ReaderEntryThread {
    pub fn build(
        original: VerifiedDecryptedRecord,
        amendments: Vec<VerifiedDecryptedRecord>,
    ) -> Result<Self, AmendmentJoinErrorV1>;

    #[must_use]
    pub fn original(&self) -> &VerifiedDecryptedRecord;

    #[must_use]
    pub fn amendments(&self) -> &[VerifiedDecryptedRecord];

    #[must_use]
    pub fn rejected(&self) -> &[RejectedAmendment];

    #[must_use]
    pub fn correction_reference(&self) -> CorrectionReference;
}
```

`build` nimmt ausschließlich `VerifiedDecryptedRecord`. Damit ist die Reihenfolge „Verifikation vor Entschlüsselung" schon durch die Typen erzwungen: ein Objekt, das die neun Gates nicht durchlaufen hat, kann diesen Faden nicht erreichen, weil `VerifiedDecryptedRecord` nirgendwo sonst konstruierbar ist. Das Original MUSS `PayloadV1::Incident` sein, sonst `NotAnIncident` — Genesis, Key-Transition und Destruction-Evidence tragen keine Einsatznummer und können kein Original eines Nachtrags sein. Jeder Kandidat MUSS `PayloadV1::Amendment` sein, sonst `NotAnAmendment`.

Für jeden Kandidaten laufen vier Vergleiche, jeder gegen das VERIFIZIERTE Original und nie gegen einen zweiten Nachtrag: `AmendmentV1::original_record_id()` gegen `CommonHeaderV1::record_id()` des Originals, `AmendmentV1::original_entry_hash()` gegen `VerifiedDecryptedRecord::entry_hash()` des Originals, `AmendmentV1::original_sequence()` gegen dessen `chain_sequence()`, und `AmendmentV1::original_incident_number()` gegen `IncidentV1::human_incident_number()`. Der Textvergleich läuft über die bereits NFC-normalisierten Werte — `ea-schema` normalisiert in `AmendmentV1::new` und `IncidentV1::new` und lehnt Nicht-NFC mit `EA-SCHEMA-NON-NFC` ab —, also wird hier keine zweite Normalisierung eingeführt.

Eine Abweichung ist ein PRÜFPROBLEM und kein Fehlschlag des ganzen Fadens: der Kandidat wandert nach `rejected()` mit seinem Eintragshash, seiner Sequenz, dem Grund und `VerificationStatus::Invalid`, und die Oberfläche zeigt ihn unter `Prüfprobleme`. `build` gibt nur dann `Err` zurück, wenn das ORIGINAL untauglich ist; ein einzelner kaputter Nachtrag darf die Anzeige des Originals und seiner gültigen Nachträge nicht nehmen. Genau das trennt „Verifikationsproblem" von „Lücke": ein abgewiesener Nachtrag ist ein vorhandenes, technisch sichtbares Objekt mit falscher Referenz, kein fehlendes.

Die Ordnung ist die Kettensequenz und nichts anderes — nicht `finalized_at_device`, das ein Gerätezeitwert ist, und nicht die Eingabereihenfolge, die vom Abrufweg abhängt. Zwei Nachträge mit derselben Sequenz sind ein Widerspruch, den der Faden nicht auflöst: der erste in Sequenzordnung bleibt, der zweite geht mit `DuplicateSequence` nach `rejected()`. Ein Sortierschlüssel aus `(chain_sequence, entry_hash)` macht die Ordnung total und den Ausdruck reproduzierbar.

Jedes Original- und jedes Nachtragsbyte samt Hash bleibt erhalten: `original()` und `amendments()` geben die vollständigen `VerifiedDecryptedRecord` heraus, ihr Klartext bleibt über `with_plaintext` und `with_payload` erreichbar — ausgeliehen und nicht herausgegeben, nach der Fläche, die die Aufgabe „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert" abschließend deklariert —, und es gibt AUSDRÜCKLICH keine Methode, die ein Original als `überholt`, `ersetzt` oder `verborgen` kennzeichnet, und keine, die einen zusammengeführten „aktuellen Stand" berechnet. Der Nachtrag ist die Korrektur, das Original bleibt der Eintrag; §12 der v0.1 und die Produktinvariante „amendment-only corrections" lassen dazu keinen zweiten Weg zu. `correction_reference()` liest seine drei Felder aus dem Original und nie aus einem Nachtrag — ein Nachtrag, der behauptet, ein anderes Original zu meinen, hat den Faden zu diesem Zeitpunkt bereits verlassen —, und ist damit die klartextfreie Übergabe an den Writer-Import der Stufe 5.

`crates/ea-reader/src/lib.rs` nimmt `mod amendment;` und den `pub use`-Block der fünf Namen auf. Die Crate bleibt auf der wasm32-Positivliste, und diese Aufgabe fügt ihr keine Abhängigkeit hinzu: `ea-schema` und `ea-types` sind bereits Kanten, `std::fs` wird nicht berührt.

- [ ] **Step 4: Run malformed-reference, ordering and retention tests**

Run: `cargo test --locked -p ea-reader --test amendments && cargo test --locked -p ea-reader`

Expected: PASS. Die adversarialen Fälle laufen alle: ein Nachtrag mit einem einzigen gekippten Byte im `original_entry_hash` tritt dem Faden NICHT bei und bleibt als `Invalid` sichtbar, statt still zu verschwinden; ein Nachtrag mit richtiger Referenz, aber fremder Einsatznummer fällt ebenso, weil sonst zwei verschiedene Einsätze über eine gemeinsame Sequenz zusammenwüchsen; zwei Nachträge auf derselben Sequenz ergeben genau einen Faden mit einem angenommenen und einem abgewiesenen Eintrag; die Eingabereihenfolge `[b, a]` liefert dieselbe Ausgabe wie `[a, b]`; das Original behält nach jedem dieser Fälle Bytes, Eintragshash und Sichtbarkeit; und `CorrectionReference` trägt nach wie vor genau drei Felder — ein hinzugefügtes viertes bricht das erschöpfende Strukturliteral des ersten Schritts zur Übersetzungszeit, nicht erst zur Laufzeit.

- [ ] **Step 5: Commit the amendment projection**

```bash
git add crates/ea-reader
git commit -m "feat(reader): link originals and amendments without replacing either"
```

### Task 12: Sitzungssperre, Zeroize, authenticator-bestätigter Einzelexport und signiertes lokales Audit (formerly Task 6)

**Files:**
- Create: `crates/ea-reader/src/session.rs`
- Create: `crates/ea-reader/src/export.rs`
- Create: `crates/ea-reader/src/audit.rs`
- Create: `crates/ea-reader-wasm/src/visibility.rs`
- Create: `apps/web/src/features/export/SingleExport.tsx`
- Test: `crates/ea-reader/tests/session_lock.rs`
- Test: `crates/ea-reader/tests/export.rs`
- Test: `crates/ea-reader/tests/audit_redaction.rs`
- Test: `apps/web/src/features/export/SingleExport.test.tsx`
- Test: `apps/web/tests/e2e/lock-and-export.spec.ts`
- Modify: `crates/ea-reader/src/lib.rs`
- Modify: `crates/ea-reader/Cargo.toml`
- Modify: `crates/ea-reader-wasm/src/lib.rs`
- Modify: `apps/web/src/main.tsx`
- Modify: `Cargo.lock`
- Modify: `docs/traceability/stage-4-fault-points.json`

`crates/ea-reader/Cargo.toml` und `Cargo.lock` stehen zusammen im Files-Block: dieser Task zieht `ea-operator` als DEV-Kante von `crates/ea-reader` aus — `the_reader_inactivity_default_is_the_same_five_minutes_as_the_desktop` misst `READER_INACTIVITY_MS_V1` gegen `ea_operator::MAX_INACTIVITY_MS` —, und eine neue Kante zwischen zwei Mitgliedern schreibt `Cargo.lock` fort. Deshalb faehrt Schritt 4 GENAU EIN Kommando ohne `--locked`. Die Kante ist ausdruecklich eine ENTWICKLUNGSkante und keine Bibliothekskante: `ea-operator` steht in `WASM32_EXEMPT_CRATES`, und die wasm32-Zeile faehrt ohne `--all-targets` und zieht Dev-Dependencies deshalb nie in den Graphen. `apps/web/src/main.tsx` bekommt die Sichtbarkeits- und Eingabehaken (`visibilitychange`, `pointerdown`, `keydown`) und die Einhaengung der Einzelexportflaeche, angehaengt an die Routentabelle aus der Aufgabe „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate"; `apps/web/tests/e2e/lock-and-export.spec.ts` faehrt genau diese montierte Schale an.

`crates/ea-audit` wird AUSDRUECKLICH NICHT angefasst. Die Crate steht in `WASM32_EXEMPT_CRATES`, und ihre Begruendung nennt beide Gruende namentlich: sie signiert jede Zeile durch den Wirtschluesselspeicher und haengt sie an die verschluesselte Wirtdatenbank an. Ihr `AuditActorProof` traegt ausserdem einen `&OperatorSessionProof` und zieht damit `ea-operator` mit, das ebenfalls ausgenommen ist — und dessen Eintrag woertlich sagt, der Browser habe „neither a native key provider (§11.3) nor an OS-lock event (§11.2)". Der Reader-Auditschreiber lebt deshalb in `crates/ea-reader` ueber den bereits eingefrorenen Kodierern von `crates/ea-format/src/local_audit.rs`.

**Interfaces:**
- Consumes: `ea_format::{LocalAuditActionV1, LocalAuditEventCoreFieldsV1, LocalAuditOutcomeV1, ExportContextV1, encode_local_audit_core, encode_local_audit_event, decode_local_audit_event}`; `ea_crypto::{CoseSigner, ContentType, SecretBytes, SecretVec}`; `ea_types::{DeviceId, EntryHash, EventId, ObjectHash, OrganizationId, UnixMillis}`; die entsperrte Vault-Sitzung mit ihrem Ed25519-Geraete- und Auditschluessel und ihrem X25519-KEM-Schluessel aus dem Task „Browser-Vault: PRF-Envelopes, Schlüsselprofil und die Verwahrung von Anchor und KEM-Schlüssel"; die verifizierte WebAuthn-Assertion aus dem Task „Browser-Enrollment: zwei Pflicht-Authenticators und das nicht überspringbare Fingerprint-Gate"; `VerifiedDecryptedRecord` aus dem Task „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert".
- Produces: `ReaderSession` mit `READER_INACTIVITY_MS_V1` und `READER_BACKGROUND_INACTIVITY_MS_V1`, `ReaderConfirmationPurpose`, `ReaderAuthenticatorConfirmation`, `ReaderExportService::export_one`, `ReaderExportTargetKindV1`, `ReaderAuditWriter::record`, den Bruecken-Export `readerSessionStateAt`/`readerNoteVisibility` und den Abschnitt `session-and-export` in `docs/traceability/stage-4-fault-points.json`.

Was aus der frueheren Fassung UNVERAENDERT bleibt: es existiert keine Methode, die „alle Datensaetze" oder ein Suchergebnis nimmt; ein Einzelexport verlangt bewusste Zielwahl; der signierte Auditabzug traegt pseudonymen Bedienerbindungshash, Entry-Hash, Zielart (nicht den Pfad), `EffectiveNow`, Aktionscode und Ausgang und niemals Nutzlast oder Klartextdateinamen. Ersetzt werden genau zwei Dinge, beide von der Spezifikation erzwungen: „OS-Lock beendet die Sitzung" faellt ersatzlos weg — §11.2 fuehrt das als dokumentierte SOLL-Abweichung mit sicherheitstechnischer Begruendung, weil der Browser keine Entsprechung hat, und §6.5 setzt an seine Stelle Zeroize beim Sperren, den Fuenfminutenvorgabewert, die VERKUERZTE Frist im Hintergrundtab und die erneute Authenticator-Bestaetigung nach jeder Sperrung —, und die native Re-Authentisierung des Einzelexports wird nach §8.2 durch eine Authenticator-Bestaetigung ersetzt.

- [ ] **Step 1: Write lock, zeroize, export-authorization and redaction tests**

```rust
// crates/ea-reader/tests/session_lock.rs
use ea_reader::{
    READER_BACKGROUND_INACTIVITY_MS_V1, READER_INACTIVITY_MS_V1, ReaderConfirmationPurpose,
    ReaderSession, ReaderSessionState, TabVisibility,
};
use ea_types::UnixMillis;

/// Der Fuenfminutenvorgabewert ist KEINE zweite Zahl. `ea-operator` haelt ihn
/// als `MAX_INACTIVITY_MS`, ist aber wasm32-ausgenommen und darf keine
/// Bibliothekskante des Readers werden; deshalb steht er hier ein zweites Mal
/// als Literal und wird HIER gegen das Original gemessen. `ea-operator` ist
/// dafuer eine DEV-Kante: die wasm32-Zeile faehrt ohne `--all-targets`, und
/// genau das haelt Dev-Dependencies aus dem wasm-Graphen — der Kommentar ueber
/// dem wasm32-Block in `tools/xtask/src/main.rs` sagt es woertlich.
#[test]
fn the_reader_inactivity_default_is_the_same_five_minutes_as_the_desktop() {
    assert_eq!(READER_INACTIVITY_MS_V1, ea_operator::MAX_INACTIVITY_MS);
    assert!(READER_BACKGROUND_INACTIVITY_MS_V1 < READER_INACTIVITY_MS_V1);
}

/// Sperren heisst zeroize. Der Zeuge misst nicht „is_locked", sondern dass der
/// Rohschluessel nach der Sperre nicht mehr herausgegeben wird und die
/// entschluesselten Datensaetze fort sind.
#[test]
fn locking_zeroizes_the_key_material_and_drops_every_open_record() {
    let mut session = ReaderSession::unlock(fixtures::confirmation(ReaderConfirmationPurpose::Unlock), t(0));
    session.open_record(fixtures::decrypted_record());
    assert!(session.vault(t(1)).is_some());
    session.lock();
    assert!(session.vault(t(2)).is_none());
    assert!(session.open_records().is_empty());
    assert_eq!(session.state_at(t(2)), ReaderSessionState::Locked);
}

/// Die verkuerzte Frist gilt AB dem Wechsel in den Hintergrund und nicht ab der
/// letzten Eingabe. Der zweite Teil ist der wichtigere: die Entscheidung faellt
/// beim naechsten Zugriff und haengt an keinem Timer — Hintergrundtabs werden
/// in allen Engines gedrosselt, auf Mobilgeraeten ganz angehalten, und ein
/// Sperrmechanismus, der auf ein `setTimeout` wartet, sperrt dort nie.
#[test]
fn a_backgrounded_tab_locks_on_the_shortened_deadline_without_any_timer() {
    let mut session = ReaderSession::unlock(fixtures::confirmation(ReaderConfirmationPurpose::Unlock), t(0));
    session.note_visibility(TabVisibility::Hidden, t(1_000));
    let just_before = t(1_000 + READER_BACKGROUND_INACTIVITY_MS_V1 - 1);
    assert_eq!(session.state_at(just_before), ReaderSessionState::Unlocked);
    let just_after = t(1_000 + READER_BACKGROUND_INACTIVITY_MS_V1);
    assert_eq!(session.state_at(just_after), ReaderSessionState::Locked);
}

/// Eine Uhr, die zurueckspringt, verlaengert keine Sitzung. Die Zeit kommt als
/// Parameter herein, wie ueberall in diesem Kern, und deshalb MUSS die Sitzung
/// eine monotone Untergrenze halten.
#[test]
fn a_clock_that_jumps_backwards_never_extends_a_session() {
    let mut session = ReaderSession::unlock(fixtures::confirmation(ReaderConfirmationPurpose::Unlock), t(0));
    assert_eq!(session.state_at(t(READER_INACTIVITY_MS_V1)), ReaderSessionState::Locked);
    assert_eq!(session.state_at(t(1)), ReaderSessionState::Locked);
}

/// Die Sitzung haelt KEIN Schema-Zwischenprodukt. `ea_schema::ValidatedPayload`
/// und `ea_schema::DerivedView` besitzen einen gewoehnlichen `Vec<u8>` und
/// ueberschreiben ihn beim Fallen nicht — die Restfrage, die der Task
/// „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert" hierher weitergibt. Die Antwort ist
/// eine SCHRANKE und keine Behauptung: was die Sitzung offen haelt, ist
/// ausschliesslich `VerifiedDecryptedRecord`, und dessen Nutzlast liegt in
/// `ea_crypto::SecretVec`.
///
/// ```compile_fail
/// # use ea_reader::ReaderSession;
/// # fn hold(session: &ReaderSession) -> &ea_schema::ValidatedPayload {
/// session.validated_payload()
/// # }
/// ```
#[test]
fn the_session_holds_no_schema_payload_beyond_a_single_decryption() {
    let mut session = ReaderSession::unlock(fixtures::confirmation(ReaderConfirmationPurpose::Unlock), t(0));
    session.open_record(fixtures::decrypted_record());
    for record in session.open_records() {
        // Die EINE ausleihende Klartextflaeche aus dem Task „Verifikation vor
        // Entschluesselung …". Es gibt keinen Zugriff, der die Bytes oder die
        // geparste Nutzlast HERAUSGIBT, also kann die Schleife nichts halten.
        record.with_plaintext(|bytes| assert!(!bytes.is_empty()));
    }
    session.lock();
    assert!(session.open_records().is_empty());
}

/// Nach jeder Sperrung eine FRISCHE Bestaetigung. Die alte gilt nicht wieder,
/// und die Bestaetigung fuer den Export entsperrt keine Sitzung.
#[test]
fn a_reused_or_wrongly_purposed_confirmation_does_not_reopen_a_locked_session() {
    let confirmation = fixtures::confirmation(ReaderConfirmationPurpose::Unlock);
    let mut session = ReaderSession::unlock(confirmation, t(0));
    session.lock();
    let export_purposed = fixtures::confirmation(ReaderConfirmationPurpose::SingleExport);
    assert!(ReaderSession::reopen(&mut session, export_purposed, t(3)).is_err());
}
```

```rust
// crates/ea-reader/tests/export.rs
use ea_reader::{ReaderConfirmationPurpose, ReaderExportError, ReaderExportTargetKindV1};

/// Vier Abweisungen, jede mit eigenem Code: kein Ziel, besetztes Ziel,
/// fehlende Bestaetigung, Bestaetigung mit falschem Zweck. Ein gemeinsamer
/// Sammelcode waere hier der Defekt — „der Nutzer hat abgebrochen" und „der
/// Nachweis passt nicht zu dieser Handlung" sind verschiedene Aussagen.
#[test]
fn a_single_export_refuses_without_a_deliberate_target_and_a_fresh_confirmation() {
    let service = fixtures::export_service();
    for (target, confirmation, code) in [
        (fixtures::no_target(), fixtures::confirmation(ReaderConfirmationPurpose::SingleExport), "EA-READER-EXPORT-NO-TARGET"),
        (fixtures::occupied_target(), fixtures::confirmation(ReaderConfirmationPurpose::SingleExport), "EA-READER-EXPORT-TARGET-OCCUPIED"),
        (fixtures::new_target(), fixtures::expired_confirmation(), "EA-READER-EXPORT-CONFIRMATION-STALE"),
        (fixtures::new_target(), fixtures::confirmation(ReaderConfirmationPurpose::Unlock), "EA-READER-EXPORT-CONFIRMATION-PURPOSE"),
    ] {
        assert_eq!(
            service.export_one(fixtures::record(), target, confirmation).unwrap_err().code(),
            code
        );
    }
}

/// Die Flaeche selbst ist die Zusage. Ein `compile_fail`-Doctest ist hier der
/// einzige wirksame Zeuge: eine Laufzeitzusicherung koennte eine
/// Massenexportmethode nicht verbieten, die es GIBT.
///
/// ```compile_fail
/// # use ea_reader::ReaderExportService;
/// # fn call(service: &ReaderExportService, records: Vec<ea_reader::VerifiedDecryptedRecord>) {
/// service.export_one(records, /* ... */);
/// # }
/// ```
#[test]
fn the_export_surface_carries_exactly_one_record_per_call() {
    let service = fixtures::export_service();
    let report = service
        .export_one(fixtures::record(), fixtures::new_target(), fixtures::confirmation(ReaderConfirmationPurpose::SingleExport))
        .unwrap();
    assert_eq!(report.exported_entry_hashes().len(), 1);
}

/// Zwei Zeilen je Versuch, und der Grund ist der Abbruch dazwischen: ein
/// Export, der nach der Bestaetigung und vor dem Schreiben stirbt, hinterliesse
/// sonst keine Spur. `LocalAuditOutcomeV1` traegt dafuer bereits drei Werte;
/// es entsteht kein vierter.
#[test]
fn an_export_records_accepted_at_the_boundary_and_then_completed_or_failed() {
    let service = fixtures::export_service();
    service.export_one(fixtures::record(), fixtures::new_target(), fixtures::confirmation(ReaderConfirmationPurpose::SingleExport)).unwrap();
    let outcomes = fixtures::recorded_outcomes();
    assert_eq!(outcomes, vec![LocalAuditOutcomeV1::Accepted, LocalAuditOutcomeV1::Completed]);
    for event in fixtures::recorded_events() {
        assert_eq!(decode_local_audit_event(&event).unwrap().action().code(), 5);
    }
}
```

```rust
// crates/ea-reader/tests/audit_redaction.rs
use ea_testkit::contains_canary;

/// Kein Kanarienvogel in den Auditbytes, in keiner Fehlerformatierung und in
/// keinem `Debug`-Abzug. Der Zeuge nimmt die EXAKTEN Bytes, die geschrieben
/// werden, nicht eine Zusammenfassung darueber.
#[test]
fn no_cleartext_and_no_filename_reaches_the_signed_audit_bytes() {
    let bytes = fixtures::export_audit_bytes_for("CANARY-PERSON", "Einsatz-2026-08-30.json");
    for needle in [b"CANARY-PERSON".as_slice(), b"Einsatz-2026-08-30.json".as_slice(), b".json".as_slice()] {
        assert!(!contains_canary(&bytes, needle));
    }
    let event = decode_local_audit_event(&bytes).unwrap();
    assert_eq!(format!("{event:?}"), "LocalAuditEventV1(<bound>)");
    assert_eq!(format!("{:?}", ReaderExportError::TargetOccupied), "EA-READER-EXPORT-TARGET-OCCUPIED");
}
```

- [ ] **Step 2: Run session, export and redaction tests and verify the controls are absent**

Run: `cargo test --locked -p ea-reader --test session_lock --test export --test audit_redaction && cargo test --locked -p ea-reader --doc`

Expected: FAIL. `ReaderSession`, `ReaderExportService` und `ReaderAuditWriter` existieren nicht; die Sitzungssteuerung des Desktops ist kein Ersatz, weil `ea-operator` als Bibliothekskante ausgeschlossen ist und `ea-audit` durch den Wirtschluesselspeicher signiert. Der `--doc`-Lauf faellt zusaetzlich, weil ein `compile_fail`-Doctest an einem nicht existierenden Typ nicht als bestanden zaehlt, sondern als fehlendes Ziel.

- [ ] **Step 3: Implement lock-on-inactivity, authenticator-confirmed single export and the signed Reader audit**

```rust
// crates/ea-reader/src/session.rs
/// Fuenf Minuten, zeichengleich zu `ea_operator::MAX_INACTIVITY_MS`.
pub const READER_INACTIVITY_MS_V1: i64 = 5 * 60 * 1_000;
/// Die verkuerzte Frist des Hintergrundtabs nach web-reader-design.md §6.5.
pub const READER_BACKGROUND_INACTIVITY_MS_V1: i64 = 30 * 1_000;

pub enum TabVisibility { Visible, Hidden }
pub enum ReaderSessionState { Unlocked, Locked }

/// Der Zweck einer Authenticator-Bestaetigung — GESCHLOSSEN und zweiwertig.
/// Gebaut wie `ea_operator::ReauthPurpose`, aber hier deklariert, weil jene
/// Crate wasm32-ausgenommen ist; eine Bestaetigung fuer einen Zweck
/// autorisiert den anderen nie.
pub enum ReaderConfirmationPurpose { Unlock, SingleExport }

/// Der Nachweis einer FRISCHEN Authenticator-Bestaetigung. Der Konstruktor
/// bleibt `pub(crate)` nach dem Stufe-1-Muster fuer nachweisende Typen; er
/// entsteht ausschliesslich auf dem gepruefte-Assertion-Pfad des Enrollments.
/// Weder `Clone` noch `Copy`: ein kopierbarer Nachweis machte den Verbrauch
/// wirkungslos — dieselbe Begruendung, die `OperatorSessionProof` traegt.
pub struct ReaderAuthenticatorConfirmation { /* purpose, issued_at, expires_at, credential_id_hash */ }

pub struct ReaderSession { /* vault, open_records, last_activity_at, hidden_since, monotonic_floor, locked */ }
impl ReaderSession {
    pub fn unlock(confirmation: ReaderAuthenticatorConfirmation, now: UnixMillis) -> Result<Self, ReaderSessionError>;
    pub fn reopen(&mut self, confirmation: ReaderAuthenticatorConfirmation, now: UnixMillis) -> Result<(), ReaderSessionError>;
    pub fn note_activity(&mut self, now: UnixMillis);
    pub fn note_visibility(&mut self, visibility: TabVisibility, now: UnixMillis);
    pub fn state_at(&mut self, now: UnixMillis) -> ReaderSessionState;
    pub fn vault(&mut self, now: UnixMillis) -> Option<&UnlockedVault>;
    pub fn lock(&mut self);
}

// crates/ea-reader/src/export.rs
/// Die Zielarten des Browsers, kodiert als `target-kind` von
/// `export-context-v1`. Zwei Arme, und der zweite ist keine Bequemlichkeit:
/// `showSaveFilePicker` fehlt in Safari und Firefox — dieselbe Luecke, aus der
/// §5.2 den universellen Dateiweg erzwingt —, also MUSS der Download-Weg
/// existieren, und beide muessen im Audit unterscheidbar sein.
#[repr(u64)]
pub enum ReaderExportTargetKindV1 { UserChosenFile = 1, UserInitiatedDownload = 2 }

pub struct ReaderExportService<'a> { /* audit writer, session, clock */ }
impl ReaderExportService<'_> {
    pub fn export_one(
        &self,
        record: VerifiedDecryptedRecord,
        target: ReaderExportTarget,
        confirmation: ReaderAuthenticatorConfirmation,
    ) -> Result<ReaderExportReport, ReaderExportError>;
}

// crates/ea-reader/src/audit.rs — drei eingefrorene Aufrufe, kein vierter.
pub struct ReaderAuditWriter<'a> { signer: &'a CoseSigner, /* device, organization, certificate hash */ }
impl ReaderAuditWriter<'_> {
    pub fn record(&self, fields: LocalAuditEventCoreFieldsV1) -> Result<Vec<u8>, ReaderAuditError>;
}
```

`ReaderAuditWriter::record` ist `encode_local_audit_core(&fields)?`, dann `CoseSigner::sign_local_audit(&core)?`, dann `encode_local_audit_event(&core, &cose)?` — mehr nicht. Es entsteht KEIN dreizehnter Aktionscode: `schemas/reports/v1/local-audit.cddl` friert `local-audit-action-v1 = 0..11` ein, `LocalAuditActionV1::code()` bildet genau diese zwoelf ab, und der Reader-Einzelexport ist Code `5` mit `context_tag` `3` — `PlaintextExport(ExportContextV1)`. Der Kontext traegt exakt zwei Positionen, `entry-hash` und `target-kind: uint`; der Wirtpfad HAT dort keinen Platz, und das ist der Grund, aus dem die Zusage „nie der Klartextdateiname" nicht durch Disziplin, sondern durch die Grammatik gehalten wird. `ReaderExportTargetKindV1::UserChosenFile` bekommt den Wert `1`, weil der eingefrorene Vektor `event/accepted-plaintext-export` (`crates/ea-testkit/src/lib.rs`, Konstante `LOCAL_AUDIT_EXPORT_TARGET_KIND`) diese Zahl bereits traegt; die Zuordnung ist so gewaehlt, dass KEIN Vektor neu eingefroren wird.

Die Sperrentscheidung faellt in `state_at` und haengt an KEINEM Timer. Gemessen: Hintergrundtabs werden in Chromium und Firefox auf etwa ein Timerereignis je Sekunde gedrosselt und auf Mobilgeraeten beim Wechsel der Anwendung ganz angehalten; ein `setTimeout`, das die Sperre ausloest, sperrt dort nie. Der Timer bleibt trotzdem eingehaengt — er beschleunigt das Zeroize —, aber die Zusage steht in Rust: jeder Zugriff auf den Tresor rechnet die verstrichene Zeit nach und sperrt, bevor er etwas herausgibt. `READER_BACKGROUND_INACTIVITY_MS_V1` wird HIER auf 30 000 ms festgelegt, weil §6.5 die Frist als „verkuerzt" fordert, ohne eine Zahl zu nennen: sie liegt eine Groessenordnung unter dem Fuenfminutenvorgabewert und deutlich ueber der Drosselungsschwelle, unterhalb derer eine Frist nicht mehr beobachtbar waere. Die Zeit kommt als Parameter herein — dieselbe Regel, die im Stufe-1-Plan als „Zeit wird als Parameter uebergeben statt ueber `SystemTime::now()` bezogen" steht und die `VerifyOptions::new(os_wall_clock)` durchhaelt. Weil der Aufrufer im Browser sitzt, haelt die Sitzung eine monotone Untergrenze: ein `now` unterhalb des zuletzt gesehenen Wertes verlaengert nichts. Eine vorwaerts luegende Uhr sperrt frueher und ist deshalb kein Angriff.

`lock()` ist die einzige Stelle, an der Schluesselmaterial verschwindet, und sie tut es ueber `SecretBytes`/`SecretVec`, die `ZeroizeOnDrop` bereits tragen; der Reader baut keinen eigenen Loeschpfad. Fallengelassen werden im selben Zug die entschluesselten Datensaetze der Sitzung; die Ansichtszustaende in `apps/web` werden zusaetzlich und best-effort geleert, was ausdruecklich die schwaechere Zusage ist und deshalb neben der Rust-Zusage steht und nicht an ihrer Stelle.

**Die weitergereichte Restfrage wird HIER entschieden, und die Entscheidung ist eine Schranke.** Der Task „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert" schreibt auf, dass `ea_schema::ValidatedPayload` und `ea_schema::DerivedView` einen gewoehnlichen `Vec<u8>` besitzen und ihn beim Fallen nicht ueberschreiben — nachgemessen: `crates/ea-schema/src/model.rs` fuehrt `exact_bytes: Vec<u8>`, `crates/ea-schema/Cargo.toml` traegt `zeroize` ueberhaupt nicht. `crates/ea-schema` wird in diesem Task NICHT angefasst: es ist eine abgeschlossene Stufe-1-Crate auf der wasm32-Positivliste, und `PayloadV1` zeroize-faehig zu machen hiesse, `Zeroize` durch jeden Feldtyp der Nutzlast zu derivieren — das ist eine Formaenderung und keine Sitzungsentscheidung. Die MUSS-Anforderung von §6.5 ist damit trotzdem vollstaendig erfuellt: sie steht unter der Ueberschrift „Schluesselmaterial zur Laufzeit" und nennt als Gegenmassnahme `zeroize` beim Sperren; der X25519-KEM-Schluessel und der Ed25519-Auditschluessel liegen in `SecretBytes`/`SecretVec`, die `ZeroizeOnDrop` bereits tragen. Was bleibt, ist Klartext EINES Datensatzes in einer freigegebenen Allokation, und es bleibt messbar begrenzt, weil `ReaderSession` weder `ValidatedPayload` noch `DerivedView` in einem Feld haelt und beide nur innerhalb eines einzigen `decrypt_verified`-Aufrufs existieren. Der Rest wird BENANNT statt weggeredet: WASM-Linearspeicher wird dem Wirt nie zurueckgegeben, eine freigegebene Allokation ist also auch nicht durch das Betriebssystem genullt. Die Zeile geht als dokumentierte SOLL-Abweichung mit dieser Begruendung in die Spalte `offen in spaeterer Stufe` von `docs/traceability/stage-4-gate.md` und benennt die Zeroize-Faehigkeit von `ea-schema` als Haertungskandidaten der Stufe 7; dieser Task BEHAUPTET sie nicht.

`export_one` nimmt GENAU EINEN `VerifiedDecryptedRecord`. Es gibt keine Methode ueber `Vec`, `&[_]`, ein Suchergebnis oder einen Iterator, und das ist mit einem `compile_fail`-Doctest belegt statt behauptet — dieselbe Bauform, mit der `crates/ea-key-provider/src/lib.rs`, `crates/ea-crypto/src/secret.rs`, `crates/ea-trust/src/registry.rs` und `crates/ea-operator/src/lib.rs` ihre Nichtherausgabe belegen, und `cargo test --workspace --doc --all-features --locked` ist der Eintrag in `verify_quick_commands()`, der solche Doctests ueberhaupt faehrt. Die Reihenfolge im Inneren ist die Zusage: Zweck und Frische der Bestaetigung pruefen, Ziel als frei pruefen, dann die Auditzeile mit `LocalAuditOutcomeV1::Accepted` schreiben — sie steht an der unwiderruflichen Grenze, unmittelbar bevor Klartext den WASM-Speicher verlaesst —, dann die Bytes an das Ziel geben, dann `Completed` oder `Failed`. Die Bestaetigung wird dabei VERBRAUCHT: sie geht per Wert herein und ist danach nicht mehr da.

`crates/ea-reader-wasm/src/visibility.rs` exportiert unter `cfg(target_arch = "wasm32")` genau zwei Funktionen, `readerNoteVisibility(hidden: bool, nowMs: f64)` und `readerSessionStateAt(nowMs: f64) -> String`, beide duenne Huellen ueber die reinen Rustfunktionen. `apps/web` haengt `visibilitychange`, `pointerdown` und `keydown` daran; es entscheidet nichts. `SingleExport.tsx` bleibt auf Ant Design 6 mit deutschem `ConfigProvider`, statisch extrahiertem lokalem gehashtem CSS, `zeroRuntime: true` und direkten CSR-Importen aus `@phosphor-icons/react`; es rendert die Zielwahl, ruft die Bestaetigung und zeigt Entry-Hash und Zielart aus dem generierten DTO — nie den Pfad, nie den Inhalt.

Die Verbote aus WR-082 stehen als Code und nicht als Vorsatz: `apps/web/src/features/export/SingleExport.test.tsx` durchsucht jede handgeschriebene Quelle unter `apps/web/src` — dieselbe Sammelfunktion, die `no-hand-written-contracts.test.ts` benutzt — nach `navigator.clipboard`, `document.execCommand('copy')`, `navigator.sendBeacon` und jedem `console.`-Aufruf mit einem entschluesselten DTO als Argument und weist jeden Treffer ab. Auf der Rustseite formatiert `ReaderExportError` wie `BundleError` und `AuditError` ausschliesslich seinen stabilen Code; ein abgeleitetes `Debug` waere hier der Weg, auf dem ein Entry-Hash in einen Fehlerbericht gerät. Der Nachweis ueber OPFS-Bytes, Service-Worker-Cache, Protokolle und Servermetadaten schliesst nicht hier, sondern im Task „Reader-Interoperabilität, Browser-Matrix, Datei-Modus, Privatheit und das Stufe-4-Gate".

Der Abschnitt `session-and-export` in `docs/traceability/stage-4-fault-points.json` wird ERGAENZT, nicht neu angelegt — die Datei entsteht im Task „Web-Bundle: getrennter Origin, Service Worker, gepinnte `webBundleRelease` und das Alter des Trust-Standes". Er traegt vier Punkte in der Form von `docs/traceability/stage-3-fault-points.json` (`name`, `brackets`, `witness`): die Sperre waehrend der offenen Zielwahl, der Wechsel in den Hintergrundtab zwischen `Accepted` und dem Schreiben, die abgebrochene Authenticator-Bestaetigung, und der Fehlschlag der zweiten Auditzeile nach bereits geschriebenen Bytes. Jeder der vier `witness`-Eintraege benennt eine RUST-Testfunktion aus `crates/ea-reader/tests/` und KEINE `.spec.ts`, aus dem Grund, den die Aufgabe „Datei-Modus: Einzeldatei-Bündel, Verzeichnis-Handle, kein Cursor, `nicht server-bestätigt`" ausschreibt: `witness_resolves` loest nur `fn`-Definitionen mit `#[test]` oder `#[tokio::test]` auf. Die ersten zwei Punkte lesen sich wie Playwright-Szenarien und sind es auch — der Browserlauf `lock-and-export.spec.ts` belegt sie ZUSAETZLICH —, aber die Spalte `witness` traegt in beiden Faellen den Rust-Zeugen ueber `ReaderSession::state_at`. Der letzte ist der unangenehme und deshalb der wichtigste: die Bytes sind draussen, also MUSS die Zeile `Failed` entstehen und darf nicht verschluckt werden.

- [ ] **Step 4: Run the lock, export, redaction and surface witnesses**

Run:

```bash
cargo metadata --format-version 1
cargo test --locked -p ea-reader --test session_lock --test export --test audit_redaction
cargo test --locked -p ea-reader --doc
cargo test --locked -p ea-format --test local_audit_encoder
pnpm --dir apps/web test --run SingleExport
pnpm --dir apps/web exec playwright test tests/e2e/lock-and-export.spec.ts
```

`cargo metadata --format-version 1` steht als ERSTE Zeile und ist das GENAU EINE Kommando dieses Tasks ohne `--locked`: Schritt 3 traegt die Dev-Kante `ea-operator` in `crates/ea-reader/Cargo.toml` ein, und `Cargo.lock` schreibt darauf fort. Es steht NACH der Registrierung und VOR jedem `--locked`-Kommando; `cargo test --locked -p ea-format --test local_audit_encoder` faehrt die zwoelf eingefrorenen Aktionskodierer NUR mit und aendert an dieser Crate nichts.

Expected: PASS. Der Fuenfminutenwert ist gegen `ea_operator::MAX_INACTIVITY_MS` gemessen und nicht abgeschrieben, die verkuerzte Frist greift ohne Timer, ein Ruecksprung der Uhr verlaengert nichts, und die zwoelf eingefrorenen Aktionskodierer sind unveraendert gruen. Die adversarialen Faelle, die JEDER rot werden muss: (1) `READER_BACKGROUND_INACTIVITY_MS_V1` auf `READER_INACTIVITY_MS_V1` heben — `a_backgrounded_tab_locks_on_the_shortened_deadline_without_any_timer` faellt, und die SOLL-Abweichung aus §11.2 waere unbelegt; (2) die Sperrpruefung aus `state_at` in einen Timer verlegen — der Playwright-Lauf `lock-and-export.spec.ts` faellt, weil er den Tab tatsaechlich in den Hintergrund schickt, waehrend der reine Rusttest gruen bliebe; genau deshalb steht der zweite Zeuge im Browser; (3) `export_one` eine `Vec<VerifiedDecryptedRecord>`-Ueberladung danebenstellen — der `compile_fail`-Doctest wird bestanden statt zu scheitern und meldet das; (4) den Zielpfad in `ExportContextV1` schmuggeln wollen — es gibt keine Position dafuer, und `encode_local_audit_core` weist ueber `validate_unsigned_protocol_core` ab, bevor eine Zeile entsteht; (5) die `Accepted`-Zeile hinter das Schreiben verlegen — `an_export_records_accepted_at_the_boundary_and_then_completed_or_failed` faellt an der Reihenfolge, und der Abbruchpunkt „Bytes draussen, Audit fehlt" waere unbezeugt; (6) `ReaderSession` einen `ValidatedPayload` in einem Feld halten lassen und ihn herausgeben — der `compile_fail`-Doctest an `the_session_holds_no_schema_payload_beyond_a_single_decryption` wird bestanden statt zu scheitern, und die Schranke der weitergereichten Restfrage waere still gefallen.

- [ ] **Step 5: Commit the Reader session and export controls**

```bash
git add crates/ea-reader crates/ea-reader-wasm apps/web/src/features/export apps/web/src/main.tsx apps/web/tests/e2e/lock-and-export.spec.ts docs/traceability/stage-4-fault-points.json Cargo.lock
git commit -m "feat(reader): lock on inactivity and audit authenticator-confirmed single exports"
```

### Task 13: Integritätszentrierte Reader-Oberfläche in `apps/web` und die Rollengrenze zum Desktop (formerly Task 7)

**Files:**
- Create: `apps/web/src/features/reader/ReaderPage.tsx`
- Create: `apps/web/src/features/reader/SearchPanel.tsx`
- Create: `apps/web/src/features/reader/EntryView.tsx`
- Create: `apps/web/src/features/reader/TechnicalView.tsx`
- Create: `apps/web/src/features/reader/VerificationProblems.tsx`
- Create: `apps/web/src/features/reader/AmendmentThread.tsx`
- Create: `apps/web/src/components/integrity/VerificationBadge.tsx`
- Create: `apps/web/src/components/integrity/EvidenceStatus.tsx`
- Create: `apps/web/src/components/integrity/FingerprintBlock.tsx`
- Create: `apps/web/src/components/integrity/ChainIntegrityRail.tsx`
- Create: `apps/web/src/bridge/reader-bridge.ts`
- Create: `crates/ea-reader-wasm/src/view.rs`
- Modify: `crates/ea-reader-wasm/src/lib.rs`
- Modify: `crates/ea-ui-contracts/src/lib.rs`
- Modify: `crates/ea-ui-contracts/src/emit.rs`
- Modify: `apps/web/src/bridge/generated-contracts.ts`
- Modify: `apps/web/src/main.tsx`
- Test: `apps/web/src/features/reader/ReaderPage.test.tsx`
- Test: `apps/web/tests/e2e/reader.spec.ts`
- Test: `apps/desktop/src/app/RoleGate.test.tsx`
- Test: `crates/ea-ui-contracts/tests/generated_ts_is_current.rs`

**Interfaces:**
- Consumes: die vier Reader-Statusaufzaehlungen und den zweiten Emitterausdruck aus dem Task „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate"; `ReaderEntryStateV1` aus dem Task „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert"; `ReaderEntryThread` aus dem Task „Nachtragsreferenzen und Original/Nachtrag-Projektion"; die Suche aus dem Task „Verschlüsselter invertierter Index in OPFS, Suche, Schemakompatibilität und die GEMESSENE 50.000-Paket-Schwelle"; die Einzelexportflaeche aus dem Task „Sitzungssperre, Zeroize, authenticator-bestätigter Einzelexport und signiertes lokales Audit".
- Produces: die Reader-Ansichtsmodelle in `ea-ui-contracts`, die Brueckenausfuhr `readerView` in `crates/ea-reader-wasm/src/view.rs`, `apps/web/src/bridge/reader-bridge.ts` als einzige Brueckenanbindung der Oberflaeche, die sechs Reader-Flaechen, die vier Integritaetsbausteine und den Rollengrenz-Zeugen im Desktop. `apps/web/playwright.config.ts` und das Wurzelskript `web:e2e` bestehen seit dem Task „Browser-Enrollment: zwei Pflicht-Authenticators und das nicht überspringbare Fingerprint-Gate" und werden hier nur BENUTZT.

`crates/ea-reader-wasm/src/lib.rs` nimmt `mod view;` auf — ohne diese Zeile uebersetzt der Commit nicht. `crates/ea-ui-contracts/Cargo.toml` steht dagegen NICHT im Files-Block: `READER_VIEW_MODELS_V1` ist eine Tabelle aus Zeichenketten, sie zieht keinen Typ und keine Kante, und die eine Kante, die die Reader-Haelfte des Emitters braucht — `ea-reader` fuer `BundleRejectionCodeV1` —, traegt das Manifest seit der Aufgabe „Web-Bundle: getrennter Origin, Service Worker, gepinnte `webBundleRelease` und das Alter des Trust-Standes". Dieser Task bewegt `Cargo.lock` deshalb nicht und faehrt jedes Kommando mit `--locked`.

Der frueher hier stehende Tauri-Kommandoblock wird nicht portiert. `apps/desktop/src-tauri/src/commands/` fuehrt heute `writer.rs`, `master_data.rs`, `session.rs` und `sync.rs` und KEIN `reader.rs`: die Datei ist nie entstanden, weil die Stufe blockiert war. „Geloescht statt portiert" heisst hier deshalb nicht ein `git rm`, sondern eine erzwungene Abwesenheit — `apps/desktop/src/app/RoleGate.test.tsx` liest den Kommandobaum und die Routentabelle und faellt, sobald eine Reader-Flaeche dort einzieht. Dieser Task enthaelt KEINE Sicherheitslogik in TypeScript: nur erzeugte Ansichts- und Status-DTOs ueberqueren die Grenze.

- [ ] **Step 1: Write the state-separation, orthogonality, and role-boundary tests**

```tsx
// apps/web/src/features/reader/ReaderPage.test.tsx
it('shows missing grant technically without rendering an empty incident', async () => {
  render(<ReaderPage bridge={bridgeWithMissingGrant()} />)
  expect(await screen.findByText(VERIFICATION_STATUS_VALUES[2])).toBeVisible() // 'fehlender Grant'
  expect(screen.getByText(/Sequenz 12/)).toBeVisible()
  expect(screen.getByText(/[0-9a-f]{16}/)).toBeVisible()
  expect(screen.queryByRole('heading', { name: /Einsatznummer/ })).not.toBeInTheDocument()
  expect(screen.queryByRole('article', { name: /Einsatz/ })).not.toBeInTheDocument()
})

it('keeps invalid objects in Prüfprobleme and opens none of them as an incident', async () => {
  const user = userEvent.setup()
  render(<ReaderPage bridge={bridgeWithInvalidObject()} />)
  expect(screen.queryByText(VERIFICATION_STATUS_VALUES[5])).not.toBeInTheDocument() // 'ungültig'
  await user.click(screen.getByRole('tab', { name: 'Prüfprobleme' }))
  expect(screen.getByText(VERIFICATION_STATUS_VALUES[5])).toBeVisible()
  expect(screen.getByText('EA-VERIFY-DECRYPT-CEK-UNWRAP-FAILED')).toBeVisible()
})

// Die zwei Dimensionen aus design.md §17.4. Der Regelfall des Datei-Modus ist
// `verifiziert` UND `nicht server-bestätigt`; wer sie zusammenfaltet, macht aus
// dem Regelfall einen Mangel.
it('renders verification and server confirmation as two independent dimensions', async () => {
  render(<ReaderPage bridge={bridgeInFileMode()} />)
  const entry = await screen.findByRole('article', { name: /Einsatz 2026-0007/ })
  expect(within(entry).getByText(VERIFICATION_STATUS_VALUES[0])).toBeVisible()      // 'verifiziert'
  expect(within(entry).getByText(SERVER_CONFIRMATION_V1_VALUES[1])).toBeVisible()   // 'nicht server-bestätigt'
  for (const defect of [VERIFICATION_STATUS_VALUES[1], VERIFICATION_STATUS_VALUES[5]]) {
    expect(within(entry).queryByText(defect)).not.toBeInTheDocument()
  }
  expect(within(entry).getByRole('status')).toHaveAccessibleDescription(
    expect.stringContaining('kein Mangel'),
  )
})

// Die Leiste ist kein Fortschrittsbalken. Ein Knoten, den niemand gemeldet hat,
// wird nicht erfunden.
it('renders only the chain nodes the bridge actually reported', async () => {
  render(<ReaderPage bridge={bridgeWithFourVerifiedNodes()} />)
  const rail = await screen.findByRole('region', { name: 'Integritätskette' })
  expect(within(rail).getAllByRole('listitem')).toHaveLength(4)
  expect(within(rail).queryByText('nicht geprüft')).not.toBeInTheDocument()
})

it('carries every status in text and not in colour or icon alone', async () => {
  render(<ReaderPage bridge={bridgeWithMissingGrant()} />)
  for (const node of await screen.findAllByRole('status')) {
    expect(node.textContent?.trim().length ?? 0).toBeGreaterThan(0)
  }
})
```

```ts
// apps/desktop/src/app/RoleGate.test.tsx
it('exposes no Reader route in the desktop shell', () => {
  expect(routeTable().map((route) => route.path)).toEqual(['/', '/einsatz'])
  expect(routeTable().some((route) => /reader|lese/i.test(route.label))).toBe(false)
})

it('declares no Reader command in src-tauri', async () => {
  const commands = await readdir(path.join(packageRoot, 'src-tauri/src/commands'))
  expect(commands.sort()).toEqual(['master_data.rs', 'mod.rs', 'session.rs', 'sync.rs', 'writer.rs'])
})

// Die andere Richtung derselben Grenze: kein Writer, keine Administration, keine
// Root-Zeremonie, keine Provisionierung, kein Re-grant, keine Vernichtung im Web.
it('exposes no writer or administration surface in apps/web', async () => {
  const sources = await webSources()
  expect(sources.length).toBeGreaterThan(0)
  for (const [file, text] of sources) {
    expect(text, file).not.toMatch(
      /finaliz|Root-Zeremonie|rootCeremony|provision|historicalRegrant|destruction|Entwurf verwerfen/i,
    )
  }
})
```

- [ ] **Step 2: Run the UI tests and verify the Reader surface is absent**

Run:

```bash
pnpm --dir apps/web test --run
pnpm --dir apps/desktop test --run RoleGate
```

Expected: FAIL. `apps/web/src` traegt nach dem Task „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate" die Schale, die Gestaltungsgrundlage und die Bruecke, aber keine `features/reader`-Quelle und keinen Integritaetsbaustein; `ReaderPage` ist kein Modul, und `VERIFICATION_STATUS_VALUES` steht noch nicht in `apps/web/src/bridge/generated-contracts.ts`, weil dieser Task die Ansichtsmodelle erst emittiert. `RoleGate.test.tsx` faellt an seinem eigenen Fehlen, nicht am Desktop: die drei Zusagen sind heute inhaltlich wahr — `role-gate.ts` fuehrt genau zwei Routen und `src-tauri/src/commands/` genau fuenf Dateien —, aber nichts haelt sie fest.

- [ ] **Step 3: Emit the view models, then build the presentation over them**

**Die Ansichtsmodelle entstehen in Rust.** `crates/ea-ui-contracts/src/lib.rs` ERWEITERT `READER_VIEW_MODELS_V1` — angelegt im Task „Web-Bundle: getrennter Origin, Service Worker, gepinnte `webBundleRelease` und das Alter des Trust-Standes" mit `BundleActivationView` und `ReaderTrustAgeView` — um die sechs Reader-Ansichten; `VIEW_MODELS_V1` des Writers bleibt unangetastet, und `emit_reader_typescript()` gibt beide Gruppen in derselben Form aus: fester Kopfkommentar, `export type`-Vereinigungen, `export type`-Objekttypen, `export const … as const`-Arrays, keine Funktion, kein Pfeil, kein Import. Die Felder sind exakt die, die `design.md` §17.2 fordert, und keines mehr:

```rust
const READER_VIEW_MODELS_V1: &[(&str, &[(&str, &str)])] = &[
    // Der TECHNISCHE Zustand eines Eintrags — er existiert auch dann, wenn
    // nichts entschluesselt wurde. Die drei Dimensionen stehen NEBENEINANDER;
    // eine zusammengefaltete waere §17.4 zuwider.
    ("ReaderEntryStateView", &[
        ("entryHash", "string"),
        ("objectHash", "string"),
        ("sequence", "number"),
        ("verification", "VerificationStatus"),
        ("entryState", "EntryStatus"),
        ("serverConfirmation", "ServerConfirmationV1"),
        ("detailCode", "string | null"),
    ]),
    // Der FACHLICHE Inhalt — und der entsteht ausschliesslich aus einem
    // entschluesselten Datensatz. `null` ist hier kein leerer Einsatz, sondern
    // die Aussage, dass nicht entschluesselt wurde.
    ("ReaderIncidentView", &[
        ("incidentNumber", "string"),
        ("occurredAtLocal", "string"),
        ("timezone", "string"),
        ("keyword", "string"),
    ]),
    ("ReaderEntryView", &[
        ("state", "ReaderEntryStateView"),
        ("incident", "ReaderIncidentView | null"),
    ]),
    // Die technische Ansicht aus §17.2, Feld fuer Feld: Sequenz, Hash,
    // Writer-Key, Registry, Receipt und Evidence.
    ("ReaderTechnicalView", &[
        ("sequence", "number"),
        ("previousEntryHash", "string | null"),
        ("entryHash", "string"),
        ("ciphertextHash", "string"),
        ("writerCertificateHash", "string"),
        ("writerKeyThumbprint", "string"),
        ("registryVersion", "number"),
        ("registryHeadHash", "string"),
        ("serverConfirmation", "ServerConfirmationV1"),
        ("evidence", "EvidenceStatus"),
    ]),
    // Ein Knoten der Integritaetsleiste. Er entsteht nur fuer eine Aussage, die
    // tatsaechlich geprueft wurde.
    ("ChainIntegrityNodeView", &[
        ("label", "string"),
        ("verified", "boolean"),
        ("detail", "string | null"),
    ]),
    ("VerificationProblemView", &[
        ("objectHash", "string"),
        ("verification", "VerificationStatus"),
        ("detailCode", "string"),
    ]),
];
```

`crates/ea-reader-wasm/src/view.rs` ist der einzige Ort, an dem ein `ReaderEntryStateV1` in diese DTOs faellt, und die Ausfuhr gibt JSON heraus:

```rust
/// Die Ansicht EINES Eintrags als JSON-DTO.
///
/// `incident` ist `null`, solange nichts entschluesselt wurde — und das ist die
/// Zusage aus `design.md` §17.2: Einsatznummer, Einsatzzeit und Stichwort
/// erscheinen ERST nach erfolgreicher lokaler Entschluesselung. Ein leeres
/// Objekt statt `null` waere genau der leere Einsatz, den §17.2 verbietet.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerEntryView")]
pub fn reader_entry_view(entry_hash: &str) -> Result<String, JsValue>;
```

`apps/web/src/bridge/reader-bridge.ts` ist die EINZIGE Datei, die diese Ausfuhren importiert; sie parst das JSON in die generierten Typen und rechnet nichts. `ReaderPage` bekommt die Bruecke als Eigenschaft, damit `ReaderPage.test.tsx` sie ohne WASM ersetzen kann — dieselbe Bauform, in der `WriterPage.test.tsx` seine Bruecke stellt.

**Die sechs Flaechen.** `ReaderPage` traegt drei Reiter — Einsaetze, Prueferprobleme, Technik — und den permanent sichtbaren Verifikationsstatus. `EntryView` rendert Einsatznummer, Einsatzzeit und Stichwort AUSSCHLIESSLICH aus `state.incident`, das nur ein entschluesselter Datensatz fuellt; ist es `null`, zeigt die Flaeche den technischen Zustand und keine leere Einsatzmaske. `SearchPanel` fuehrt die vier Filter Zeitraum, Stichwort, Fahrzeug und Person und gibt sie unveraendert an die Suche des Tasks „Verschlüsselter invertierter Index in OPFS, Suche, Schemakompatibilität und die GEMESSENE 50.000-Paket-Schwelle"; es filtert nichts selbst, sortiert nichts selbst und kennt keinen Feldwert, den es nicht angezeigt bekommen hat. `TechnicalView` erklaert Sequenz, Hashes, Writer-Key, Registry, Receipt und Evidence in verstaendlicher Sprache und liest jeden Wert aus `ReaderTechnicalView`. `VerificationProblems` ist der EINZIGE Ort, an dem ein Objekt mit `VerificationStatus` `ungültig` erscheint; es oeffnet keines davon als Einsatz. `AmendmentThread` zeigt Original und Nachtraege als getrennte Ansichten desselben Zusammenhangs, gespeist aus dem Task „Nachtragsreferenzen und Original/Nachtrag-Projektion"; kein Original wird als ueberholt markiert oder ausgeblendet.

**Die vier Integritaetsbausteine** sind die Portierung der gleichnamigen Desktop-Dateien und keine zweite Erfindung: `VerificationBadge` bleibt dreiwertig mit `nicht geprüft` als eigenem Wert, weil eine ungepruefte Aussage kein Nein ist; `ChainIntegrityRail` rendert AUS der uebergebenen Knotenliste und hat keine feste Laenge, also kann sie nur so lang sein, wie es gepruefte Aussagen gibt; `EvidenceStatus` und `FingerprintBlock` uebernehmen Wortlaut und ARIA-Struktur ihrer Desktop-Vorlagen. Jeder Zustand steht als TEXT neben Zeichen und Farbe — `design.md` §17.5 laesst Farbe als alleinigen Traeger eines Sicherheitszustands nicht zu.

**Die zwei Dimensionen bleiben getrennt.** `nicht server-bestätigt` wird als eigener `role="status"` mit der zugaenglichen Beschreibung „kein Mangel" gerendert und nie in dasselbe Zeichen wie der Verifikationsstatus gefaltet. Im Datei-Modus ist das der Regelfall (`web-reader-design.md` §5.4), im Server-Modus die Ausnahme; die Darstellung unterscheidet die beiden Modi nicht, weil der Zustand derselbe ist.

**Die Gestaltung bleibt die der Stufe 2.** Ant Design 6 mit deutschem `ConfigProvider`, den sechs eingefrorenen Farben aus `apps/web/src/design/tokens.ts`, `zeroRuntime: true`, statisch extrahiertem lokal gehashtem CSS und der CSP ohne Laufzeit- und Fremdstile. Jede neu importierte Ant-Komponente wird in `EXTRACTED_COMPONENTS` eingetragen, sonst hat sie unter `zeroRuntime: true` keine einzige Regel und `static-css.test.ts` faellt. Icons kommen als direkte CSR-Importe aus `@phosphor-icons/react`. Fokus ist sichtbar, `prefers-reduced-motion` wird respektiert, jede Bedienung ist per Tastatur erreichbar.

**Die Rollengrenze in beide Richtungen.** `apps/web` enthaelt keinen Code fuer Writer-Finalisierung, Root-Zeremonien, Operator-Provisionierung, Historical Re-grant oder Vernichtungsausfuehrung — `web-reader-design.md` §3 verbietet ihn, und der dritte Zeuge in `RoleGate.test.tsx` liest die Quellen und nicht die Absicht. `apps/desktop` bekommt keine Reader-Route und kein `reader.rs`; die rollengebundene Schale schaltet weiterhin ausschliesslich anhand gueltiger signierter Geraetezertifikate frei, und `isRouteEnabled` in `apps/desktop/src/app/role-gate.ts` bleibt unveraendert.

**Playwright.** `apps/web/playwright.config.ts` und das Wurzelskript `web:e2e` bestehen seit dem Task „Browser-Enrollment: zwei Pflicht-Authenticators und das nicht überspringbare Fingerprint-Gate" — `testDir: 'tests/e2e'`, `webServer` ueber `vite preview` auf 127.0.0.1:4174, `use.offline: false`, ein einziges `projects`-Element `chromium`. Dieser Task legt `apps/web/tests/e2e/reader.spec.ts` darunter und aendert an der Konfiguration NICHTS; der Matrix-Eintrag mit `chromium`, `firefox` und `webkit` entsteht im Task „Reader-Interoperabilität, Browser-Matrix, Datei-Modus, Privatheit und das Stufe-4-Gate", und dieser Task behauptet keine Matrix.

- [ ] **Step 4: Run the component, keyboard, contract, and end-to-end surfaces**

Run:

```bash
cargo test --locked -p ea-ui-contracts --test generated_ts_is_current
pnpm --dir apps/web typecheck
pnpm --dir apps/web test --run
pnpm --dir apps/desktop test --run
pnpm --dir apps/web build
pnpm web:e2e
```

Expected: PASS. Die adversariellen Faelle, die rot werden MUESSEN und einzeln zu pruefen sind: ein Eintrag mit `fehlender Grant`, der eine Einsatzmaske rendert, faellt am Fehlen von `Einsatznummer`; ein `ungültig`, das ausserhalb von `Prüfprobleme` erscheint, faellt am ersten `queryByText`; ein `nicht server-bestätigt`, das als `Lücke` oder `ungültig` gerendert wird, faellt an der Orthogonalitaetszusicherung; eine Integritaetsleiste, die einen nicht gemeldeten Knoten erfindet, faellt an der Knotenzahl; ein handgeschriebenes deutsches Statuswort in einer `apps/web`-Quelle faellt in `no-hand-written-contracts.test.ts`, weil dieselbe Zeichenkette in `generated-contracts.ts` steht; ein von Hand editiertes `apps/web/src/bridge/generated-contracts.ts` faellt in `generated_ts_is_current.rs`; eine Reader-Route in `apps/desktop/src/app/role-gate.ts` und eine `reader.rs` unter `src-tauri/src/commands/` fallen beide in `RoleGate.test.tsx`; und eine `apps/web`-Quelle, die `crypto.subtle`, `createHash`, `Ed25519`, `X25519` oder `ChaCha20` nennt, faellt an der dritten Zusicherung derselben Datei. `pnpm web:e2e` faehrt die gebaute Anwendung und belegt, dass die Oberflaeche waehrend eines simulierten Sync bedienbar bleibt und dass jede Bedienung per Tastatur mit sichtbarem Fokus erreichbar ist. NICHT behauptet und ausdruecklich offen: Mindestversionen je Engine (`web-reader-design.md` §14 Punkt 3, Stufe 7), PWA-Installation und das Gate ueber die Ablehnung eines nicht Root-signierten Bundles (`web-reader-design.md` §12, Stufe 7).

- [ ] **Step 5: Commit the Reader presentation and the role boundary**

```bash
git add apps/web crates/ea-reader-wasm crates/ea-ui-contracts \
        apps/desktop/src/app/RoleGate.test.tsx
git commit -m "feat(web): deliver the integrity-centered Reader surface and pin the role boundary"
```

### Task 14: Reader-Interoperabilität, Browser-Matrix, Datei-Modus, Privatheit und das Stufe-4-Gate (formerly Task 8)

**Files:**
- Create: `tests/ea-system-tests/tests/cross_platform_two_readers.rs`
- Create: `tests/ea-system-tests/tests/e2e_reader_sync_interruptions.rs`
- Create: `tests/ea-system-tests/tests/reader_file_mode_interop.rs`
- Create: `tests/ea-system-tests/tests/privacy_canaries_reader.rs`
- Create: `apps/web/tests/e2e/browser-matrix.spec.ts`
- Create: `docs/traceability/stage-4-gate.md`
- Modify: `apps/web/playwright.config.ts`
- Modify: `docs/traceability/stage-4-fault-points.json`
- Modify: `docs/traceability/v0.1-requirements.csv`
- Modify: `tools/xtask/src/main.rs`
- Modify: `tools/xtask/tests/stage_gate.rs`
- Modify: `tests/ea-system-tests/Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `package.json`

`tests/ea-system-tests/Cargo.toml` und `Cargo.lock` gehoeren zusammen und stehen hier, weil die vier neuen Systemtests `ea_reader::{ReaderMode, ReaderVerifier, ReaderClassification, ReaderFileMode, ReaderSyncFaultPoint}` unmittelbar benennen: das Manifest fuehrt heute (gemessen) `ea-archive`, `ea-archive-fs`, `ea-audit`, `ea-cbor`, `ea-chain`, `ea-crypto`, `ea-draft`, `ea-format`, `ea-key-provider`, `ea-local-store`, `ea-operator`, `ea-schema`, `ea-testkit`, `ea-time`, `ea-trust`, `ea-types`, `ea-verify` und `ea-writer` als Dev-Kanten und KEIN `ea-reader`. Die Zeile `ea-reader.workspace = true` tritt hier unter `[dev-dependencies]` ein — mit `default-features = false` aus der Wurzeltabelle, das Merkmal `test-support` von `crates/ea-reader` bleibt also AUS —, und eine neue Kante zwischen zwei Mitgliedern schreibt `Cargo.lock` fort. Deshalb faehrt Schritt 4 GENAU EIN Kommando ohne `--locked`, und es steht VOR `integration up`, das selbst `--locked` traegt.

**Interfaces:**
- Consumes: der vollstaendige Stufe-4-Reader; `ea_verify::{verify_archive_observed, VerifyOptions, RecordingObserver, SilentObserver, VerificationReportV1, ServerConfirmationV1, ObjectResultKindV1, GATE_ORDER_V1, DECAPSULATION_EVENT_V1}`; `ea_types::VerificationStatus`; `ea_crypto::{HpkeRecipientPrivateKey, CanonicalPublicCoseKey}`; `ea_reader::{ReaderMode, ReaderVerifier, ReaderClassification, ReaderFileMode, ReaderSyncFaultPoint}`; `ea_testkit::contains_canary` und die eingefrorenen Vektorfamilien `vectors/crypto/suite-1/`, `vectors/trust/v1/` und `vectors/web-bundle/v1/` NUR LESEND; `cargo run --locked -p xtask -- integration up|down` und `ops/compose/integration.yaml` aus der Stufe 3; die Abschnitte `bundle-activation`, `sync-cursor`, `verification`, `file-mode` und `session-and-export` von `docs/traceability/stage-4-fault-points.json` aus den Aufgaben „Web-Bundle: getrennter Origin, Service Worker, gepinnte `webBundleRelease` und das Alter des Trust-Standes", „Inkrementeller Reader-Sync und verifizierter Cursor-Fortschritt in OPFS", „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert", „Datei-Modus: Einzeldatei-Bündel, Verzeichnis-Handle, kein Cursor, `nicht server-bestätigt`" und „Sitzungssperre, Zeroize, authenticator-bestätigter Einzelexport und signiertes lokales Audit"; die zwei `v1.1`-Zeilen `WR-053` und `WR-054` samt ihrer Tupel in `WEB_READER_MUST_ROWS` aus der Aufgabe „Stufe-4-Vorlauf: ADR 0005, wasm-Werkzeugpins und die aufgehobene Blockade".
- Produces: `xtask stage-gate 4` ueber `run_stage_four_gate` mit seinen `STAGE_FOUR_*`-Konstanten, `docs/traceability/stage-4-gate.md`, die Browsermatrix als Playwright-Projekte, der Beleg fuer die primaeren Abnahmekriterien AK 10, 42 und 43 und die Schliessung von siebzehn Ledgerzeilen.

- [ ] **Step 1: Write the two-reader, browser-matrix, and gate witnesses**

```rust
// tests/ea-system-tests/tests/cross_platform_two_readers.rs
#[test]
fn one_ciphertext_opens_under_two_distinct_reader_kem_keys_through_separate_grants() {
    let archive = fixtures::archive_with_grants_for_both_readers();
    let mut opened = Vec::new();
    for reader in [fixtures::reader_a(), fixtures::reader_b()] {
        let mut observer = RecordingObserver::new();
        let report = verify_archive_observed(
            &archive.source(),
            fixtures::anchor(),
            VerifyOptions::new(fixtures::os_wall_clock())
                .with_recipient(reader.key_thumbprint(), reader.private_key()),
            &mut observer,
        )
        .unwrap();
        assert!(report.is_fully_verified());
        assert_eq!(report.decryption_errors().len(), 0);
        assert_eq!(observer.events().last(), Some(&DECAPSULATION_EVENT_V1));
        assert_eq!(&observer.events()[..GATE_ORDER_V1.len()], &GATE_ORDER_V1[..]);
        // Der Klartext wird AUSGELIEHEN und kopiert erst hier, im Test, aus
        // dem `with_plaintext` heraus — die Flaeche von
        // `VerifiedDecryptedRecord` gibt keine Bytes heraus.
        opened.push(archive.decrypted_record_for(&reader).with_plaintext(<[u8]>::to_vec));
    }
    assert_ne!(fixtures::reader_a().key_thumbprint(), fixtures::reader_b().key_thumbprint());
    assert_eq!(opened[0], opened[1], "derselbe Klartext aus zwei verschiedenen Grants");

    // Wird EINEM der beiden sein Grant genommen, sieht NUR dieser `fehlender Grant`.
    let without_b = archive.without_grant_for(&fixtures::reader_b());
    let verifier = ReaderVerifier::new(ReaderMode::Server, fixtures::os_wall_clock());
    let for_b = verifier
        .classify(&without_b.source(), &fixtures::vault_of(&fixtures::reader_b()), &mut SilentObserver)
        .unwrap();
    let for_a = verifier
        .classify(&without_b.source(), &fixtures::vault_of(&fixtures::reader_a()), &mut SilentObserver)
        .unwrap();
    assert_eq!(
        for_b.state_of(fixtures::entry_hash()).unwrap().verification(),
        VerificationStatus::MissingGrant
    );
    assert_eq!(
        for_a.state_of(fixtures::entry_hash()).unwrap().verification(),
        VerificationStatus::Verified
    );
    // Und ein fehlender Grant ist NIE eine Luecke und nie ein Mangel.
    assert_eq!(for_b.report().gaps().len(), 0);
    assert!(for_b.report().is_fully_verified());
}
```

```rust
// tools/xtask/tests/stage_gate.rs
#[test]
fn stage_four_gate_requires_two_readers_the_browser_matrix_and_the_file_mode() {
    // Phase 1: der echte Arbeitsbaum.
    let output = run_stage_gate_in_the_workspace("4");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "stage-gate 4 must accept the checked-in tree; stderr: {stderr}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(report["stage"], serde_json::json!(4));
    assert_eq!(
        report["stage_four_primary_acceptance_criteria"],
        serde_json::json!(STAGE_FOUR_PRIMARY_ACCEPTANCE_CRITERIA)
    );
    assert_eq!(report["vector_families"], serde_json::json!(STAGE_FOUR_FAMILIES));

    let declared = report["declared_fault_points"].as_array().unwrap();
    for scenario in STAGE_FOUR_SCENARIOS {
        assert!(declared.iter().any(|value| value == scenario),
            "the declared scenarios must carry {scenario}; stdout: {stdout}");
    }
    assert_eq!(declared.len(), STAGE_FOUR_SCENARIOS.len());
    assert_eq!(
        report["stage_four_fault_point_witnesses"].as_array().unwrap().len(),
        STAGE_FOUR_SCENARIOS.len(),
        "every declared scenario resolves to exactly one witness; stdout: {stdout}"
    );
    assert!(
        report["stage_four_rows_still_planned"].as_array().unwrap().is_empty(),
        "no stage 4 ledger row may still be planned; stdout: {stdout}"
    );

    // Phase 2: der Gate-Bericht fehlt UND eine Stufe-4-Zeile steht wieder auf `planned`.
    let root = stage_four_fixture("stage-four-two-gaps");
    fs::remove_file(root.join(STAGE_FOUR_GATE_REPORT_PATH)).unwrap();
    write_stage_four_ledger(&root, Some("FR-103"));
    let output = run_stage_gate(&root, "4");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    for expected in [
        STAGE_FOUR_GATE_REPORT_PATH,
        "stage 4 requirement ledger rows still on planned: FR-103",
    ] {
        assert!(stderr.contains(expected), "stage-gate 4 must name {expected}; stderr: {stderr}");
    }

    // Phase 3: das Szenarienmanifest verliert seinen Datei-Modus-Abschnitt `file-mode`.
    let root = stage_four_fixture("stage-four-manifest");
    remove_fault_point_section(&root, STAGE_FOUR_FAULT_POINTS_PATH, "file-mode");
    let output = run_stage_gate(&root, "4");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8(output.stderr).unwrap().contains("file-mode"));
}
```

```ts
// apps/web/tests/e2e/browser-matrix.spec.ts
test('the same archive verifies identically on every engine of the matrix', async ({ page, browserName }) => {
  await openPinnedBundle(page)
  await expect(page.getByTestId('report-hash')).toHaveText(FROZEN_REPORT_HASH)
  await expect(page.getByTestId('server-confirmation')).toHaveText(/nicht server-bestätigt/)
  await expect(page.getByTestId('verification-status')).toHaveText('verifiziert')
  expect(['chromium', 'firefox', 'webkit']).toContain(browserName)
})
```

Der Marker fuer `WEB_READER_MUST_ROWS` wird in DIESEM Schritt gesetzt und in Schritt 3 AUSGEFUEHRT, nie ad hoc von einer implementierenden Person entschieden. Die Stelligkeit der Konstante ist beim Start dieser Aufgabe ELF — neun im eingecheckten Stand plus die zwei Tupel `("WR-053", "5.3", "4", "planned")` und `("WR-054", "5.4", "4", "planned")`, die die Aufgabe „Stufe-4-Vorlauf: ADR 0005, wasm-Werkzeugpins und die aufgehobene Blockade" eintraegt. Sie bleibt ELF: diese Aufgabe fuegt kein Tupel hinzu und entfernt keines, sie aendert SIEBEN Statusspalten. Jede Aenderung dieser Erwartungsspalte ist eine Ledgerbewegung und steht unten ausgeschrieben.

- [ ] **Step 2: Run the gate and confirm the missing evidence fails**

Run: `cargo test --locked -p xtask --test stage_gate stage_four && cargo test --locked -p ea-system-tests --test cross_platform_two_readers`

Expected: FAIL. Der Dispatcher antwortet `stage-gate is only defined for stages 1, 2 and 3 so far, not 4`; `docs/traceability/stage-4-gate.md` existiert nicht; `docs/traceability/stage-4-fault-points.json` fuehrt noch keinen vollstaendigen Abschnittssatz mit aufloesbaren Zeugen; und jede Stufe-4-Ledgerzeile steht auf `planned`, was die Zeile `stage 4 requirement ledger rows still on planned: …` mit allen siebzehn Kennungen in Ledgerreihenfolge erzeugt. Der letzte dieser Punkte klaert sich ausschliesslich in Schritt 3, und genau deshalb steht die Ledgerzusicherung im selben Test: ein Gate, der seine eigene Bewegung nicht verlangt, belegt die Stufe nicht.

- [ ] **Step 3: Close the fault matrix, the browser matrix, the privacy proof, and the ledger**

Diese Aufgabe traegt die Schliessungsrolle der Stufe in der Form, die die abgeschlossene Aufgabe „Server Administration Separation, Failure Matrix, Privacy, and Stage Gate" des Stufe-3-Plans vorgibt: Fehlermatrix, Interoperabilitaet, Kanarienvoegel, Gate-Werkzeug, Gate-Bericht und Ledgerpflege in einer Aufgabe.

**Die zwei Achsen, die `web-reader-design.md` §12 fuer diese Stufe zusaetzlich verlangt.**

*Browsermatrix.* `web-reader-design.md` §11.4 ersetzt fuer den Reader die Achsen Architektur, Installerformat und Key-Provider durch Engine, Version und Plattform; fuer Writer, Administration und CLI bleiben sie unveraendert gueltig. `apps/web/playwright.config.ts` bekommt deshalb drei `projects` — `chromium`, `firefox`, `webkit` —, und `browser-matrix.spec.ts` faehrt in jedem denselben eingefrorenen Bestand und vergleicht den `reportHash` gegen EINEN Literalwert. Die Gleichheit ist die Aussage: der Verifikationskern ist geteilter Rust-Code, uebersetzt nach `wasm32-unknown-unknown`, also DARF sich sein Bericht zwischen den Engines nicht unterscheiden; taete er es, waere Wirtsverhalten in den Kern gelaufen. `webkit` ist Playwrights WebKit-Bau und nicht Safari; die Unterscheidung steht im Bericht, weil sie sonst als Safari-Nachweis gelesen wuerde. Die Matrix deckt AUSDRUECKLICH NICHT alle E2E-Laeufe dieser Stufe ab, und der Bericht sagt es an dieser Stelle ein zweites Mal: `apps/web/tests/e2e/enrollment.spec.ts` laeuft ausschliesslich im Projekt `chromium`, weil `WebAuthn.addVirtualAuthenticator` eine CDP-Methode ist und Firefox und WebKit kein Gegenstueck anbieten. Der Enrollment- und der Fingerprintnachweis auf `firefox` und `webkit` stehen deshalb in der Spalte `offen in spaeterer Stufe`; die Rust-Zeugen `crates/ea-reader/tests/enrollment_two_authenticators.rs` und `crates/ea-reader/tests/fingerprint_gate.rs` laufen plattformunabhaengig und tragen jede normative Aussage, der Browserlauf ist der zusaetzliche Beleg. Mindestversionen je Plattform werden hier AUSDRUECKLICH NICHT gepinnt — `web-reader-design.md` §14.3 fuehrt sie als offenen Punkt und weist sie der Stufe-7-Ueberarbeitung zu.

*Datei-Modus.* `reader_file_mode_interop.rs` faehrt DENSELBEN Bestand DREIMAL, und die Aufteilung ist gemessen und nicht angenommen. Gemessen wurde `write_archive_bundle` in `crates/ea-archive-fs/src/bundle.rs`: es packt JEDEN relativen Pfad des Bestands ein, Quittungen eingeschlossen, und `bundle_is_byte_preserving_under_the_same_relative_paths` haelt genau das fest. Ein Buendel aus einem quittungstragenden Bestand traegt seine `.esr`-Objekte also MIT, und `web-reader-design.md` §5.4 sagt dazu woertlich, im Datei-Modus wuerden „nur die im Buendel enthaltenen Receipts und Checkpoints geprueft" — enthaltene Quittungen werden also AUSGEWERTET. `notServerConfirmed` ist im Datei-Modus der REGELFALL, aber keine Invariante, und die Vorfassung dieses Absatzes, die „genau eine abweichende Spalte" behauptete, war gegen den eingecheckten Exporteur falsch.

Lauf (a): Server-Modus ueber den quittungstragenden Bestand. Lauf (b): dasselbe, exportierte Ein-Datei-Buendel dieses Bestands. Verglichen werden `archiveObjectCount`, `chainHead`, die Menge der `objectResults` UND die Spalte `serverConfirmation` — sie ist in (b) IDENTISCH zu (a), und genau das belegt, dass Gate-Schritt 7 die mitgereisten Quittungen wirklich auswertet statt sie zu ignorieren. Lauf (c): ein Buendel, das aus einem Bestand exportiert wurde, dem die `.esr`-Objekte VORENTHALTEN wurden; dort steht jedes Objekt auf `notServerConfirmed` UND `ObjectResultKindV1::Valid`, `gaps()` ist leer und `is_fully_verified()` bleibt wahr — die orthogonale Dimension senkt nichts. NUR Lauf (c) traegt die Ledgerzeile des Datei-Modus; (a) und (b) belegen die Interoperabilitaet, nicht die Ausweisung. Der Negativfall daneben ist das untergeschobene Archiv mit vollstaendiger eigener Vertrauenskette: gegen den gepinnten Anker endet der Lauf fail-closed an Gate `trust`, `objectResults` bleibt leer und `publicKeyThumbprints` bleibt leer. Beide Zeugen sind hier die SYSTEMweite Wiederholung; ihr primaerer Beleg liegt in den Aufgaben „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert" und „Datei-Modus: Einzeldatei-Bündel, Verzeichnis-Handle, kein Cursor, `nicht server-bestätigt`", und dieser Bericht verweist darauf, statt die Aussage ein zweites Mal zu erheben.

**Die drei Achsen, die aus der Vorfassung unveraendert bleiben.**

Ein Writer-Chiffrat mit Grants fuer zwei verschiedene Reader-Zertifikate und -KEM-Schluessel wird repliziert und von beiden unabhaengig verifiziert und entschluesselt; wird einem der beiden sein Grant genommen, sieht NUR dieser `fehlender Grant`, und der Befund ist nie eine `Lücke`. `e2e_reader_sync_interruptions.rs` unterbricht jeden Punkt des Abschnitts `sync-cursor`, einschliesslich der zwei nur im Browser moeglichen — ein waehrend eines Batches geschlossener Tab und ein durch Storage-Eviction abgebrochener OPFS-Schreibvorgang — und belegt, dass der bestaetigte Cursor nach jedem Abbruch unveraendert bleibt und der Wiederholversuch idempotent auf denselben Kopf laeuft. `privacy_canaries_reader.rs` sucht je fachlichem Feld GENAU EINEN Marker — ein gemeinsamer Marker fuer zwei Felder liesse offen, welches geleckt hat, dieselbe Regel, die `tests/ea-system-tests/tests/privacy_canaries_writer.rs` schon durchsetzt — mit `ea_testkit::contains_canary` in sieben Stroemen: den rohen OPFS-Bytes (Tresor, Cache, Zustandsspeicher, Indexblob), dem Service-Worker-Cache, den Zwischenablage-Haken, den strukturierten Logs, den Fehlerberichten, den Servermetadaten und der Telemetrie. Dazu die Positivkontrolle, ohne die die ganze Datei auch dann gruen waere, wenn die Marker nie ins System gelangt sind: derselbe Marker ist ueber den entsperrten Tresor lesbar, und die Suche findet ihn in einem absichtlich unverschluesselt abgelegten Kontrollstrom.

**Das Gate-Werkzeug.**

Der Stufenschalter in `run_stage_gate` (`tools/xtask/src/main.rs`) oeffnet mit `if stage == 4 { return run_stage_four_gate(root); }`, und seine Fehlermeldung zieht mit: heute `"stage-gate is only defined for stages 1, 2 and 3 so far, not {stage}"`, danach `"stage-gate is only defined for stages 1, 2, 3 and 4 so far, not {stage}"`. Kein Test haelt diese Zeichenkette — `grep -rn "only defined for stages" tools/ tests/ docs/ apps/ crates/` trifft genau eine Codestelle und zwei Prosastellen in den Stufenplaenen 2 und 3 —, der Schalter oeffnet also ohne Testreparatur. Das ist der einzige unkritische Teil der Gate-Erweiterung und steht hier als solcher, damit niemand nach einem fehlenden Pin sucht.

`run_stage_four_gate` entsteht NEBEN `run_stage_three_gate` und ersetzt es nicht; es uebernimmt dessen Aufbau Punkt fuer Punkt. Die geteilten Pfade `REQUIREMENT_LEDGER_PATH`, `DESIGN_DOCUMENT_PATH` und `PACKAGE_MANIFEST_PATH` werden WIEDERVERWENDET, nie dupliziert. Neu sind:

- `STAGE_FOUR_VECTOR_FAMILIES: [&str; 0] = []`. LEER, und das ist die Aussage: Stufe 4 friert KEINE Vektorfamilie ein. `vectors/crypto/suite-1/`, `vectors/trust/v1/` und `vectors/web-bundle/v1/` werden ausschliesslich GELESEN — die ersten beiden sind Stufe-1-Familien, die dritte hat die Stufe 3 eingefroren —, und ein Eintrag behauptete ein Einfrieren, das es nicht gibt. Die Begruendung ist dieselbe, die `STAGE_THREE_VECTOR_FAMILIES` fuer Quittungs- und Nachweisvektoren aufschreibt.
- `STAGE_FOUR_PRIMARY_ACCEPTANCE_CRITERIA: [u32; 3] = [10, 42, 43]`.
- `STAGE_FOUR_GATE_REPORT_PATH = "docs/traceability/stage-4-gate.md"`.
- `STAGE_FOUR_FAULT_POINT_MANIFEST_PATH = "docs/traceability/stage-4-fault-points.json"`, in derselben Form wie `docs/traceability/stage-3-fault-points.json`: ein JSON-Objekt mit `"stage": 4` und je Abschnitt ein Array aus `{"name", "brackets", "witness"}`.
- `STAGE_FOUR_FAULT_POINT_SECTIONS: [&str; 5] = ["bundle-activation", "sync-cursor", "verification", "file-mode", "session-and-export"]`, in der Reihenfolge der Aufgaben, die sie schreiben. Die Stelligkeit wird HIER einmal festgelegt, damit keine spaetere Aufgabe sie ein zweites Mal verschiebt.
- `STAGE_FOUR_REQUIRED_SCRIPTS: [&str; 6] = ["stage-gate:4", "supply-chain", "test:reader", "verify:quick", "web:browser-test", "web:e2e"]` — lexikografisch, und die Auswahlregel ist die der Stufe 3: GENAU die Skripte, die der gemessene Lauf aus Schritt 4 selbst aufruft. Die Skripte frueherer Stufen stehen nicht hier; sie werden bereits von `STAGE_TWO_REQUIRED_SCRIPTS` und `STAGE_THREE_REQUIRED_SCRIPTS` gehalten, und ein zweites Mal geprueft belegen sie nichts.
- `STAGE_FOUR_GATE_REPORT_SECTIONS: [&str; 8]` und `STAGE_FOUR_GATE_REPORT_LITERALS: [&str; 16]`, umlautfrei wie alle drei bereits geschlossenen Gate-Berichte, weil der Gate Literale vergleicht.
- `STAGE_FOUR_HOST_SCOPE_CLAUSE`, nach dem Muster von `STAGE_THREE_HOST_SCOPE_CLAUSE`. Sie nennt den Abbilddigest aus `ops/compose/browsers.yaml` als HERKUNFT der Engines — nicht den Wirt —, dazu den exakten `@playwright/test`-Pin und die drei Engine-Baus MIT ihren Revisionsnummern, dazu die gemessene Node-Version und den `wasm-bindgen`-Pin `0.2.126` fuer Crate UND CLI. Die Zahlen stehen im Plan nicht, sondern ihre QUELLE: `pnpm --dir apps/web exec playwright --version` und `pnpm --dir apps/web exec playwright install --dry-run`, abgelesen im Lauf aus Schritt 4 — genau so, wie Stufe 3 ihre zwei Bilddigests gemessen und nicht behauptet hat.
- `STAGE_FOUR_STEP_SIX_COMMANDS: [&str; 15]` in `tools/xtask/tests/stage_gate.rs`, nach dem Muster `STAGE_THREE_STEP_SIX_COMMANDS`: die Kommandofolge aus Schritt 4, Wort fuer Wort und in Reihenfolge, mit `cargo metadata --format-version 1` an erster, `integration up` an zweiter und `integration down` an letzter Stelle. Die Dreizehn statt der Zwoelf war der Lockfile-Fortschritt dieses Tasks: die Dev-Kante `ea-reader` in `tests/ea-system-tests/Cargo.toml` schreibt `Cargo.lock` fort, und `integration up` traegt selbst `--locked`, kann also nicht davorstehen. Die Fuenfzehn statt der Dreizehn sind `browsers up` und `browsers down` aus ADR 0005 — dieser Lauf faehrt mit `pnpm web:browser-test` und `pnpm web:e2e` die zwei einzigen Kommandos der Stufe, die Engine-Baus und einen `chromedriver` voraussetzen, und beide beziehen sie aus dem gepinnten Abbild statt vom Wirt. Die Stelligkeit waechst also aus ZWEI Gruenden in zwei Ueberarbeitungen, und beide stehen hier.
- Die LIVE-Zaehler kehren HIER zurueck, und nur hier. Die Aufgabe „wasm32-Reichweite: `ea-reader`, die Brücken-Crate und die geteilten Browserkerne" hat `verify_quick_subcommand_count()`, `wasm32_positive_list_count()` und `GERMAN_COUNT_WORDS` aus `tools/xtask/tests/stage_gate.rs` entfernt, weil ihre einzigen Aufrufstellen — die zwei ABGESCHLOSSENEN Berichte der Stufen 2 und 3 — auf historische Literale umgestellt wurden und ein ungenutzter Helfer `dead_code` und damit `cargo clippy … -- -D warnings` rot macht. `stage_four_gate_report_records_the_measured_full_gate_run` legt beide Zaehler unveraendert wieder an — Zaehlung am zeichengenauen Pin `super::verify_quick_commands(),`, Teilkommandos ueber die Klammerbilanz, wasm32-Pakete ueber die `"-p"`-Vorkommen — und stellt sie gegen die Belegzeile `pnpm verify:quick` von `docs/traceability/stage-4-gate.md`. Die Zahlwortliste waechst dabei mit und wird HIER bemessen: die Stufe faehrt ZWOELF Teilkommandos und VIERZEHN wasm32-Pakete, der hoechste gebrauchte Index ist also 14, und die Liste ist `[&str; 15]` von `"NULL"` bis `"VIERZEHN"`. Die alte `[&str; 13]` deckte nur `0..=12` und haette an `get(13)` mit `None` PANIKT statt zu urteilen; wer sie spaeter weiter treibt, hebt die Stelligkeit in derselben Aufgabe, die den Zaehler treibt.

`run_stage_four_gate` uebernimmt den Noch-offen-Filter unveraendert in Form: `rows_still_planned(&rows, "4", &mut problems)` liefert die Fehlerzeile `stage 4 requirement ledger rows still on planned: {}`. Der Filter wird bedingungslos gebaut und fuer keine Zeile gelockert.

`package.json` waechst um GENAU ZWEI Schluessel: `"test:reader": "cargo test --locked -p ea-reader -p ea-index"` und `"stage-gate:4": "cargo run --locked -p xtask -- stage-gate 4"`. `supply-chain` und `verify:quick` bestehen seit den Stufen 2 und 3, `web:browser-test` seit dem Task „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate", `web:e2e` seit dem Task „Browser-Enrollment: zwei Pflicht-Authenticators und das nicht überspringbare Fingerprint-Gate". Die vier Systemtests laufen im gemessenen Lauf als direkte `cargo test`-Kommandos und nicht durch einen Wrapper: ein `test-system`-Gate existiert im Dispatcher nicht, und die `test-*`-Gates weisen jedes Argument ab — der Wrapper waere zwei Aenderungen, das direkte Kommando ist null, und `cargo test --locked -p ea-system-tests --test privacy_canaries_writer` aus der Stufe 2 ist der Praezedenzfall.

**Der Gate-Bericht.**

`docs/traceability/stage-4-gate.md` ist inhaltlich gebunden, nicht nur namentlich. Abschnitt 1 traegt je primaerem Abnahmekriterium EINE Zeile mit vier Spalten `| Kriterium | Gegenstand | Beleg | Offen in spaeterer Stufe |`; die vierte Spalte DARF NICHT leer sein, `gate_report_acceptance_criteria` weist eine leere Zelle ab, und die Zeile MUSS mit `| AK ` beginnen und mit `|` enden. Teilbelege fremder Kriterien stehen deshalb in einem eigenen Unterabschnitt mit dem Zeilenpraefix `| Teilbeleg AK `, exakt wie im Stufe-3-Bericht — eine Zeile `| AK 19 | …` wuerde die Gleichheit gegen `STAGE_FOUR_PRIMARY_ACCEPTANCE_CRITERIA` brechen.

Ein Abschnitt `## Gemessene Indexschwelle` traegt die Zahlen, die die Aufgabe „Verschlüsselter invertierter Index in OPFS, Suche, Schemakompatibilität und die GEMESSENE 50.000-Paket-Schwelle" erzeugt hat: Blobgroesse, Entsperrlatenz und Spitzenspeicher bei 50000 indizierten PAKETEN. Die Zahl ist gebunden und nicht erfunden: `design.md` fordert in NFR-PERF-003 und Abnahmekriterium 31 „Ein Reader verifiziert und indiziert mindestens 50.000 Pakete", und die Stufe 7 misst genau diese Schwelle in `tests/ea-system-tests/tests/performance_reader_50000.rs`. Ein monolithischer Einzelblob unterhalb dieser Schwelle waere eine Stufe-4-Architektur, die ihr eigenes Stufe-7-Gate nicht bestehen kann. „Einsatz" und „Paket" sind dabei NICHT dieselbe Einheit — ein Einsatz traegt ein Original plus Nachtraege —, deshalb steht die Schwelle in Paketen, in derselben Einheit, die das Stufe-7-Gate misst. Der Bericht MISST und beansprucht nicht: die LEDGERZEILE `AK-31` behaelt `stage=7` und `status=planned`, und der Abschnitt sagt das ausdruecklich. `NFR-PERF-003` ist dabei ausdruecklich KEINE Ledgerzeile — der Bezeichner steht allein in der Anforderungstabelle von `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md` und hat in `docs/traceability/v0.1-requirements.csv` keinen Eintrag; wer ihn dort zu drehen versucht, dreht nichts.

Drei weitere Abschnitte halten drei gepruefte Negative, damit ihr Schweigen nicht als „nicht geprueft" gelesen wird, und sie bleiben GETRENNT: `## Browsermatrix und Datei-Modus` mit den drei Engine-Baus und der Aussage, dass `webkit` nicht Safari ist; `## Rollengrenze` mit dem gemessenen Befund, dass `apps/web` keine Writer-, Administrations-, Root-Zeremonie-, Provisionierungs-, Re-Grant- oder Vernichtungsflaeche traegt und die rollengeschaltete Huelle von `apps/desktop` keine Reader-Route freigibt; und `## Nicht beruehrte Nachbarzeilen` mit den Zeilen, die diese Stufe absichtlich nicht bewegt.

`## Offen in spaeterer Stufe` nennt jeden nicht erbrachten Nachweis samt besitzender Stufe, und keiner davon wird hier behauptet:

| Offen | Warum nicht hier | Stufe |
|---|---|---|
| Gepinnte Browser-Mindestversionen je Plattform | `web-reader-design.md` §14.3 fuehrt sie als offenen Punkt und weist sie ausdruecklich der Stufe-7-Ueberarbeitung zu | 7 |
| Enrollment- und Fingerprint-E2E auf `firefox` und `webkit` | `WebAuthn.addVirtualAuthenticator` ist eine CDP-Methode; Firefox und WebKit bieten kein Gegenstueck, `apps/web/tests/e2e/enrollment.spec.ts` laeuft deshalb nur im Projekt `chromium`. Die Rust-Zeugen `enrollment_two_authenticators.rs` und `fingerprint_gate.rs` laufen plattformunabhaengig und tragen die normative Aussage; was fehlt, ist der Browserbeleg auf zwei Engines | 7 |
| Betriebliche Haelfte der Origin-Trennung (`WR-041`): getrennter Host, Auslieferung, DNS und Zertifikate | Diese Stufe belegt die CODE-Seite — relative Beiwerkspfade, `base: './'`, `connect-src` ohne Bundle-Origin, ungehashter Service-Worker-Einstieg. Die Aufgabe „Web-Bundle: getrennter Origin, Service Worker, gepinnte `webBundleRelease` und das Alter des Trust-Standes" waehlt und betreibt den Host ausdruecklich NICHT; `web-reader-design.md` §14 offener Punkt 4 erklaert ihn fuer offen | offen, betrieblich |
| `--release`-Bau mit `wasm-opt` | Der Laufzeitnachweis und `build-wasm` fahren das Debug-Profil; ein optimierter Bau ist ein Releasenachweis | 7 |
| PWA-Installation und Service-Worker-Aktualisierung unter Pinning | `web-reader-design.md` §12 weist beides der Stufe 7 zu | 7 |
| Gate, das die Ablehnung eines nicht Root-signierten Bundles nachweist | Ebenda, Stufe 7; diese Stufe baut die Aktivierungspruefung, nicht ihr Releasegate | 7 |
| 50.000-Paket-Zielwerte als ABNAHME (AK 31, NFR-PERF-003) | Hier gemessen, dort verlangt | 7 |
| Administrationshaelfte des Enrollments (Anzeige des erwarteten Fingerprints, Root-Signatur des Reader-Zertifikats) | `web-reader-design.md` §6.6 Schritt 4; die Desktop-Administration entsteht in Stufe 5 | 5 |
| `readerKeyEscrow` und die Zwei-Approver-Oeffnungszeremonie | `web-reader-design.md` §7.3 nennt Stufe 5 als Entstehungsstufe der Objektart; `WR-075` bleibt dort | 5 |
| Zielorigin und Betriebsverantwortung des getrennten Bundle-Hosts | `web-reader-design.md` §14 offener Punkt 4; die konfigurierbare Origin-Positivliste der Stufe 3 ist die technische Antwort, der Betrieb bleibt eine Entscheidung | offen, betrieblich |
| Referenzquelle und Verteilweg der Fingerprint-Bekanntgabe | `web-reader-design.md` §14 offener Punkt 5 | offen, betrieblich |

Der Abschnitt `## Gemessener Gate-Lauf` traegt je Kommando des Laufs aus Schritt 4 eine Zeile mit Kommando, Exitcode, Belegtext und gemessener Laufzeit, maschinell gepinnt ueber `STAGE_FOUR_STEP_SIX_COMMANDS`. Darin stehen (a) die Lizenzentscheidung fuer jede neue benannte Ausnahme in `deny.toml` — oder die Feststellung, dass der `wasm-bindgen`-Teilbaum keine erzeugt hat; (b) die Reichweitenklausel woertlich; (c) die Belegzeile fuer `pnpm verify:quick` mit gemessener Laufzeit UND der Angabe, ob warm oder kalt gemessen wurde — Referenzwerte: die Stufe 2 mass 125 s ohne diese Angabe, die Stufe 3 kam darueber und brauchte zwei laufende Container, die Stufe 4 kommt darueber und faehrt zusaetzlich `build-wasm` und den `apps/web`-Bau. In derselben Belegzeile wird die Paketzahl der wasm32-Positivliste AN IHRE QUELLE gebunden — `verify_quick_commands()` in `tools/xtask/src/main.rs` — statt als Zahl ausgeschrieben.

**Die Klammer um `pnpm verify:quick`.**

Der Lauf in Schritt 4 fasst `pnpm verify:quick` in `cargo run --locked -p xtask -- integration up` … `integration down`. Der Grund ist gemessen und keine Vorsicht: `apps/server` und `crates/ea-sync-server` sind seit Stufe 3 Mitglieder des Arbeitsbereichs, das Teilkommando `cargo test --workspace --all-targets --locked` aus `verify_quick_commands()` zieht ihre Integrationstestziele mit, und `#[sqlx::test]` liest `DATABASE_URL` zur Laufzeit. Die Vorbedingung selbst ist bereits IMPLEMENTIERT — `ensure_integration_services_available()` in `tools/xtask/src/main.rs` prueft PostgreSQL und Object Store fail-closed vor dem betroffenen Kommando, in derselben Bauform wie `ensure_wasm32_target_available()`, und ein Ueberspringen ueber eine Umgebungsvariable ist ausgeschlossen. Was der Stufe-4-Plan bis zu dieser Ueberarbeitung nicht hatte, war allein die Klammer in seiner eigenen Kommandoliste; hier steht sie.

**Ledgerpflege.**

Siebzehn Zeilen werden bewegt, jede gegen eine benannte Aufgabe und einen benannten Testpfad. Ohne diese Zuordnung hat der Gate keine Moeglichkeit zu pruefen, ob eine Zeile geschlossen werden darf; das Muster steht bereits an `WR-052`. **Die Spalte `Neuer Status` traegt AUSSCHLIESSLICH ein Literal aus `LEDGER_STATUSES` in `tools/xtask/src/main.rs` — `implemented`, `integrated` oder `planned` — und keinen Zusatz in Klammern.** Der Gate liest die neunte Spalte der CSV-Zeile woertlich und weist jeden anderen Wert mit `status … is outside the vocabulary` ab, und `web_reader_must_requirements_are_recorded_as_v1_1_rows` vergleicht sie zusaetzlich mit `assert_eq!` gegen die Statusspalte des gepinnten Tupels. Ein Vorbehalt gehoert deshalb in die Belegspalte oder in `## Offen in spaeterer Stufe`, nie in die Statusspalte.

| Ledgerzeile | Neuer Status | Beweisende Aufgabe | Beweisender Testpfad |
|---|---|---|---|
| `AK-10` | integrated | Diese Aufgabe | `tests/ea-system-tests/tests/cross_platform_two_readers.rs::one_ciphertext_opens_under_two_distinct_reader_kem_keys_through_separate_grants` |
| `AK-42` | integrated | Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert | `crates/ea-reader/tests/missing_grant.rs`; `tests/ea-system-tests/tests/cross_platform_two_readers.rs` |
| `AK-43` | integrated | Inkrementeller Reader-Sync und verifizierter Cursor-Fortschritt in OPFS | `crates/ea-reader/tests/sync_resume.rs`; `tests/ea-system-tests/tests/e2e_reader_sync_interruptions.rs` |
| `FR-085` | implemented | Inkrementeller Reader-Sync und verifizierter Cursor-Fortschritt in OPFS | `crates/ea-reader/tests/sync_attacks.rs` |
| `FR-100` | implemented | Integritätszentrierte Reader-Oberfläche in `apps/web` und die Rollengrenze zum Desktop | `apps/desktop/src/app/RoleGate.test.tsx`; `apps/web/src/features/reader/ReaderPage.test.tsx` |
| `FR-103` | implemented | Verschlüsselter invertierter Index in OPFS, Suche, Schemakompatibilität und die GEMESSENE 50.000-Paket-Schwelle | `crates/ea-index/tests/search.rs`; `crates/ea-index/tests/reindex.rs`; `crates/ea-reader/tests/cache_canaries.rs` |
| `FR-104` | implemented | Sitzungssperre, Zeroize, authenticator-bestätigter Einzelexport und signiertes lokales Audit | `crates/ea-reader/tests/session_lock.rs` |
| `FR-105` | implemented | Sitzungssperre, Zeroize, authenticator-bestätigter Einzelexport und signiertes lokales Audit | `crates/ea-reader/tests/export.rs` |
| `FR-106` | implemented | Sitzungssperre, Zeroize, authenticator-bestätigter Einzelexport und signiertes lokales Audit | `crates/ea-reader/tests/audit_redaction.rs` |
| `FR-122` | implemented | Nachtragsreferenzen und Original/Nachtrag-Projektion | `crates/ea-reader/tests/amendments.rs` |
| `WR-041` | implemented | Web-Bundle: getrennter Origin, Service Worker, gepinnte `webBundleRelease` und das Alter des Trust-Standes | CODE-Seite; die betriebliche Haelfte steht in `## Offen in spaeterer Stufe`. `apps/web/src/sw/service-worker.test.ts::builds_a_bundle_that_addresses_nothing_absolutely_and_names_no_bundle_origin` (relative Beiwerkspfade, `connect-src` ohne Bundle-Origin); `apps/web/src/sw/service-worker.test.ts::pins_the_vite_configuration_that_makes_the_separation_possible` (`base: './'`, ungehashter Service-Worker-Einstieg) |
| `WR-042` | implemented | Web-Bundle: getrennter Origin, Service Worker, gepinnte `webBundleRelease` und das Alter des Trust-Standes | `crates/ea-reader/tests/bundle_release_pinning.rs`; `apps/web/tests/e2e/bundle-activation.spec.ts` |
| `WR-043` | integrated | Browser-Enrollment: zwei Pflicht-Authenticators und das nicht überspringbare Fingerprint-Gate | `crates/ea-reader/tests/fingerprint_gate.rs`; `apps/web/tests/e2e/enrollment.spec.ts` |
| `WR-053` | integrated | Datei-Modus: Einzeldatei-Bündel, Verzeichnis-Handle, kein Cursor, `nicht server-bestätigt` | `crates/ea-reader/tests/file_mode_anchor.rs::a_substituted_archive_with_its_own_trust_chain_says_nothing_about_any_entry`; `tests/ea-system-tests/tests/reader_file_mode_interop.rs` |
| `WR-054` | integrated | Datei-Modus: Einzeldatei-Bündel, Verzeichnis-Handle, kein Cursor, `nicht server-bestätigt` | `crates/ea-reader/tests/file_mode.rs::every_object_without_a_receipt_is_not_server_confirmed_and_never_a_gap`; `tests/ea-system-tests/tests/reader_file_mode_interop.rs` |
| `WR-063` | implemented | Browser-Enrollment: zwei Pflicht-Authenticators und das nicht überspringbare Fingerprint-Gate | `crates/ea-reader/tests/enrollment_two_authenticators.rs` |
| `WR-082` | integrated | Sitzungssperre, Zeroize, authenticator-bestätigter Einzelexport und signiertes lokales Audit + diese Aufgabe | `tests/ea-system-tests/tests/privacy_canaries_reader.rs` |

`WEB_READER_MUST_ROWS` in `tools/xtask/tests/stage_gate.rs` folgt im DEMSELBEN Commit. Die Stelligkeit bleibt ELF; sieben Tupel wechseln ihre Statusspalte von `"planned"` auf den Wert der Tabelle oben: `WR-041`, `WR-042`, `WR-043`, `WR-053`, `WR-054`, `WR-063`, `WR-082`. Die Verschiebung wird im Doc-Kommentar der Konstante AUSGESCHRIEBEN, genau nach dem Muster, das die Entscheidungen D-HE2 und die Stufe-3-Abnahme dort bereits verwenden. `WR-042D` (Stufe 3, `implemented`), `WR-052` (Stufe 2, `integrated`), `WR-064` (Stufe 3, `implemented`) und `WR-075` (Stufe 5, `planned`) bleiben unangetastet. Die geschlossenen Gate-Berichte der Stufen 1 bis 3 werden dafuer NICHT angefasst; `docs/traceability/stage-2-gate.md` traegt diesen Mechanismus als Praezedenz.

Zwei Teilbelegzeilen entstehen nach dem Muster, das das Repositorium fuer `AK-19` und `AK-21` bereits fuehrt, jede `v1.1`, `stage=4`, `status=implemented`: „Keine Klartextlogs — Stufe-4-Teilbeleg (Reader)" fuer `AK-19` mit `tests/ea-system-tests/tests/privacy_canaries_reader.rs` als Beleg, und „Schema und Suite v1/v2 — Stufe-4-Teilbeleg (Reader-Altansicht)" fuer `AK-17` mit `crates/ea-index/tests/schema_compatibility.rs`. Beide VOLLEN Zeilen behalten ihre bisherige Stufe. `AK-23` wird ausdruecklich NICHT beruehrt: der Plattform-Key-Provider ist Writer-Flaeche, und `web-reader-design.md` §11.4 nimmt die Achse Key-Provider fuer den Reader heraus, statt sie zu erfuellen.

- [ ] **Step 4: Run the complete Stage 4 gate**

Run:

```bash
cargo metadata --format-version 1
cargo run --locked -p xtask -- integration up
cargo run --locked -p xtask -- browsers up
pnpm test:reader
pnpm web:browser-test
cargo test --locked -p ea-system-tests --test cross_platform_two_readers
cargo test --locked -p ea-system-tests --test e2e_reader_sync_interruptions
cargo test --locked -p ea-system-tests --test reader_file_mode_interop
cargo test --locked -p ea-system-tests --test privacy_canaries_reader
pnpm web:e2e
pnpm supply-chain
pnpm stage-gate:4
pnpm verify:quick
cargo run --locked -p xtask -- browsers down
cargo run --locked -p xtask -- integration down
```

Fuenf Dinge an diesem Lauf sind Absicht und nicht zurueckzuvereinfachen. `cargo metadata --format-version 1` steht ganz vorn und ist das GENAU EINE Kommando dieses Tasks ohne `--locked`: Schritt 3 traegt die Dev-Kante `ea-reader` in `tests/ea-system-tests/Cargo.toml` ein, und jedes Kommando danach — `integration up` eingeschlossen — faellt sonst an einem ueberholten `Cargo.lock`. `integration up` steht danach zuerst und `integration down` zuletzt, weil dies die einzige Aufgabe der Stufe ist, die die Dienste wieder abraeumt, und die Belegzeile beides festhaelt. `pnpm supply-chain` steht an vorletzter Stelle vor `pnpm verify:quick`, exakt wo die Stufen 2 und 3 es hingestellt haben; ohne diese Zeile ist `deny.toml` fuer Stufe 4 vollstaendig tot, weil kein Gate `cargo deny` von sich aus ruft, und diese Stufe zieht mit dem `wasm-bindgen`-Teilbaum den ersten neuen Abhaengigkeitsbaum seit Stufe 3. Die vier Systemtests laufen als direkte `cargo test`-Kommandos statt durch einen Wrapper, aus dem oben genannten Grund; `pnpm web:browser-test` faehrt die `wasm-bindgen-test`-Ziele von `crates/ea-reader-wasm` in headless Chromium und ist das einzige Kommando des Laufs, das einen `chromedriver` voraussetzt; zusammen mit `pnpm web:e2e`, das die drei Engine-Baus braucht, steht es in der Klammer `browsers up` … `browsers down` aus ADR 0005. Die Engines kommen damit aus dem gepinnten Abbild und nicht aus einem `playwright install` auf dem Wirt — der Bericht kann seine drei Engine-Revisionen nur dann als gemessen ausweisen, wenn ihre Herkunft selbst gepinnt ist. Und `pnpm stage-gate:4` statt `cargo run --locked -p xtask -- stage-gate 4`, damit das Skript wirklich im gemessenen Lauf erscheint, wie es `pnpm stage-gate:2` und `pnpm stage-gate:3` in ihren Stufen tun.

Expected: PASS mit ausdruecklich offen ausgewiesenen Stufe-5- und Stufe-7-Zeilen. Ein Chiffrat oeffnet unter zwei verschiedenen Reader-KEM-Schluesseln, und das Protokoll ist in beiden Laeufen die vollstaendige Neunerfolge aus `GATE_ORDER_V1`, gefolgt von genau einem `hpke-open`; der entzogene Grant erzeugt bei genau einem der beiden `fehlender Grant` und bei keinem eine `Lücke`; jeder Punkt der fuenf Abschnitte des Szenarienmanifests loest auf eine wirklich vorhandene, gruene Testfunktion auf; kein Kanarienvogel steht in einem der sieben Stroeme, waehrend die Positivkontrolle denselben Marker findet, wo er liegen soll; und derselbe Bestand liefert auf `chromium`, `firefox` und `webkit` denselben `reportHash`.

Der Ledger ist die eine Stelle, an der ein ROTER Gate erwartbar und kein Mangel ist, und die Grenze ist exakt. Solange irgendeine Bewegung aus Schritt 3 aussteht, meldet `pnpm stage-gate:4` genau eine Zeile, und sie nennt alle noch gefundenen Zeilen in Ledgerreihenfolge: `stage 4 requirement ledger rows still on planned: AK-10, AK-42, AK-43, FR-085, FR-100, FR-103, FR-104, FR-105, FR-106, FR-122, WR-041, WR-042, WR-043, WR-053, WR-054, WR-063, WR-082`. Ein roter Gate VOR den Bewegungen ist der erwartete Vorzustand; ein roter Gate DANACH ist ein Mangel und als solcher zu behandeln. Ein anderer Zeilenname in dieser Meldung heisst, dass eine Stufe-4-Zeile vergessen wurde, nicht dass die Bewegung fehlgeschlagen ist.

- [ ] **Step 5: Commit the Stage 4 gate**

```bash
git add tests apps/web docs/traceability tools/xtask package.json Cargo.lock
git commit -m "test(reader): close the browser reader stage"
```

