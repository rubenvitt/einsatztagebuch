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
- Create: `crates/ea-reader/src/enrollment_endpoints.rs`
- Create: `crates/ea-reader-wasm/src/webauthn.rs`
- Create: `apps/web/src/vault/webauthn-prf.ts`
- Create: `apps/web/src/features/enrollment/EnrollmentPage.tsx`
- Create: `apps/web/src/features/enrollment/AuthenticatorRegistration.tsx`
- Create: `apps/web/src/features/enrollment/FingerprintGate.tsx`
- Create: `apps/web/playwright.config.ts`
- Modify: `crates/ea-reader/src/lib.rs`
- Modify: `crates/ea-reader/Cargo.toml`
- Modify: `crates/ea-reader/tests/fixtures/mod.rs`
- Modify: `crates/ea-reader-wasm/src/lib.rs`
- Modify: `apps/web/src/bridge/opfs-worker.ts`
- Modify: `apps/web/src/main.tsx`
- Modify: `apps/web/tsconfig.json`
- Modify: `package.json`
- Modify: `.gitignore`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `docs/adr/0005-browser-runtime-and-wasm-dependency-class.md`
- Modify: `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-4-reader.md`
- Test: `crates/ea-reader/tests/enrollment_two_authenticators.rs`
- Test: `crates/ea-reader/tests/fingerprint_gate.rs`
- Test: `apps/web/src/features/enrollment/EnrollmentPage.test.tsx`
- Test: `apps/web/src/e2e-config.test.ts`
- Test: `apps/web/tests/e2e/enrollment.spec.ts`

**Interfaces:**
- Consumes: `ReaderVault::{seal, unlock}`, `ReaderVaultError`, `SealedVaultV1::{envelopes, without_credential, to_deterministic_cbor, from_deterministic_cbor}`, `VaultContentsV1::new`, `UnlockedVault::{kem_private_key, kem_key_thumbprint, pinned_anchor}`, `AuthenticatorPrfV1::new`, `VaultEnvelopeV1::{unwrap, credential_id, wrapped_vault_key}`, `derive_kek_v1` und `VAULT_KEK_INFO_V1` aus dem Task „Browser-Vault: PRF-Envelopes, Schlüsselprofil und die Verwahrung von Anchor und KEM-Schlüssel"; `ReaderBlobStore` mit `put`/`get`/`delete`/`keys`, `ReaderBlobKey::new`, `ReaderBlobError` und `InMemoryReaderBlobStore` aus dem Task „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate"; `ea_reader_wasm::vault_bridge::register_vault_contents` aus demselben Task; `ea_sync_protocol::{WebauthnCredentialRegistrationV1, VaultBlobUploadV1, VaultBlobRetrievalRequestV1, VaultBlobRetrievalResponseV1, RequestSigner, RequestParts, SignatureParametersV1, RequestIdV1, HttpMethod, SignatureComponent, body_digest, content_digest_header, organization_tag, SIGNATURE_ALGORITHM_V1, MAX_SIGNATURE_WINDOW_SECONDS_V1, MIN_WEBAUTHN_CREDENTIAL_ID_BYTES_V1, MAX_WEBAUTHN_CREDENTIAL_ID_BYTES_V1, MAX_VAULT_BLOB_CIPHERTEXT_BYTES_V1, MAX_VAULT_BLOBS_PER_SUBJECT_V1, SyncProtocolError}`; `ea_crypto::{CanonicalPublicCoseKey, HpkeRecipientPrivateKey, SecretBytes, SecretBytes::with_exposed, CryptoError, CEK_SIZE}`; `ea_trust::{TrustAnchorV1, decode_trust_anchor}`; `ea_types::{Hash32, KeyThumbprint, OrganizationId, SubjectId}`.
- Produces: `ReaderEnrollment::{begin(&dyn ReaderBlobStore, …), register_authenticator, registered_authenticator_count, registered_credential_ids, fingerprints, confirm_fingerprints, finish, device_state, fingerprint_gate_required}`, `recover_and_unlock_vault`, `EnrolledReaderV1::{envelopes, unlock_with, without_authenticator, blob_key}`, `AttestedAuthenticatorV1::new`, `AuthenticatorTransportProfileV1`, `AuthenticatorRecordV1`, `EnrollmentFingerprintsV1::{key_fingerprint, bundle_fingerprint, key_fingerprint_hex, bundle_fingerprint_hex}`, `FingerprintConfirmationV1`, `DeviceTrustStateV1`, `EnrollmentError::code`, `EnrollmentRequestContextV1::new`, `VAULT_PRF_SALT_V1`, `MIN_ENROLLED_AUTHENTICATORS_V1`, `ENROLLMENT_SIGNATURE_WINDOW_SECONDS_V1`, `READER_VAULT_BLOB_KEY_V1`; der Port `EnrollmentEndpoints` mit `EnrollmentRequestV1`, `EnrollmentCallV1`, `EnrollmentEndpointError` und der In-Memory-Doppelung `InMemoryEnrollmentEndpoints`; die fünf Brückenexporte `ea_reader_wasm::webauthn::{enrollment_begin, enrollment_register_authenticator, enrollment_fingerprints, enrollment_confirm_fingerprints, enrollment_finish}` — die Rust-Namen; auf der JS-Seite heissen sie über `js_name` `enrollmentBegin`, `enrollmentRegisterAuthenticator`, `enrollmentFingerprints`, `enrollmentConfirmFingerprints` und `enrollmentFinish`, wie `bridge_echo_js`/`bridgeEcho` und `reader_vault_unlock`/`readerVaultUnlock` es in dieser Crate schon halten; der TypeScript-Typ `EnrollmentBridge` in `apps/web/src/vault/webauthn-prf.ts`, der genau diese fünf Aufrufe samt ihrer Status-DTOs beschreibt; und die drei Stufe-3-Endpunkte `POST /v1/webauthn-credentials`, `PUT /v1/vault-blobs`, `POST /v1/vault-blobs/retrievals`.

`crates/ea-reader/Cargo.toml` und `Cargo.lock` stehen im Files-Block, weil DIESE Aufgabe die Kante `ea-sync-protocol.workspace = true` von `crates/ea-reader` aus zieht: `EnrollmentError::Protocol(ea_sync_protocol::SyncProtocolError)` steht in `crates/ea-reader/src/enrollment.rs`, und die drei Stufe-3-Endpunkte reisen über `WebauthnCredentialRegistrationV1`, `VaultBlobUploadV1`, `VaultBlobRetrievalRequestV1`, `VaultBlobRetrievalResponseV1` und `RequestSigner`. Es ist die ERSTE Aufgabe dieses Plans, die diese Kante braucht — die Aufgabe „Inkrementeller Reader-Sync und verifizierter Cursor-Fortschritt in OPFS" findet sie bereits vor —, und eine neue Kante zwischen zwei Mitgliedern schreibt `Cargo.lock` fort. Deshalb fährt diese Aufgabe GENAU EIN Kommando ohne `--locked`, und es steht am ENDE des Implementierungsschritts und nicht am Anfang des Prüfschritts; die Begründung dieser Stelle steht dort. `crates/ea-reader/src/lib.rs` nimmt im selben Zug `mod enrollment;` und `mod enrollment_endpoints;` samt ihren `pub use`-Blöcken auf, wie `crates/ea-reader-wasm/src/lib.rs` `pub mod webauthn;` — ohne diese Zeilen übersetzt der Commit nicht. Die WURZEL-`Cargo.toml` steht aus einem anderen Grund daneben: sie trägt die aufgezählte `web-sys`-Merkmalsliste, und die Browserfassung des Endpunktports braucht dort `XmlHttpRequest`; `docs/adr/0005-browser-runtime-and-wasm-dependency-class.md` zieht die wortgleiche Ledgerzeile im selben Commit nach, sonst fällt `browser_runtime_dependency_class_is_ratified_before_use`. Die Begründung dieser beiden Einträge steht zwei Absätze weiter unten, beim Transport. Eine Merkmalsänderung schreibt `Cargo.lock` NICHT fort — dort stehen Pakete und Versionen, keine Merkmale —, das GENAU EINE Kommando ohne `--locked` hängt also allein an der neuen Mitgliedskante und nicht hieran.

**Die Module bleiben PRIVAT, die Namen kommen über den flachen `pub use`.** `crates/ea-reader/src/lib.rs` deklariert heute jedes Modul privat (`mod blob_store; mod cache; mod entry_state; mod envelope; mod key_profile; mod mode; mod vault;`) und stellt einen flachen `pub use`-Block darunter; kein einziger Name dieser Crate ist über einen Modulpfad erreichbar. `mod enrollment;` und `mod enrollment_endpoints;` fügen sich alphabetisch zwischen `cache` und `entry_state` ein — `enrollment` < `enrollment_endpoints` < `entry_state`, das dritte Zeichen entscheidet (`r` vor `t`) —, und ihre `pub use`-Zeilen zwischen der `ea_verify`- und der `entry_state`-Zeile desselben Blocks. Folge für jeden Zeugen dieser Aufgabe: seine Einfuhr lautet `use ea_reader::{DeviceTrustStateV1, EnrollmentCallV1, InMemoryEnrollmentEndpoints, ReaderEnrollment, recover_and_unlock_vault, …}` und niemals `use ea_reader::enrollment::{…}`. Ein `pub mod enrollment;` wäre die einzige Ausnahme in einer sonst durchgehaltenen Anordnung, und eine Ausnahme, die nur entsteht, weil ein Testschnipsel einen Pfad falsch geschrieben hat, ist die schlechteste Art, eine Anordnung zu brechen.

**Der Transport ist ein SYNCHRONER Port in `ea-reader` und keine HTTP-Bibliothek.** `crates/ea-reader/Cargo.toml` trägt keine Wirtsabhängigkeit, und das ist keine Zufälligkeit: `ea-reader` steht auf der wasm32-Positivliste in `tools/xtask/src/main.rs`, und `tokio`, `hyper` oder `reqwest` nähmen es von dort herunter. `ea-sync-client` scheidet aus demselben Grund aus — es steht in `WASM32_EXEMPT_CRATES`. `crates/ea-reader/src/enrollment_endpoints.rs` baut deshalb dieselbe Bauform wie `crates/ea-reader/src/blob_store.rs`: EIN Trait mit `&mut self`, EINE In-Memory-Doppelung daneben, EIN Fehlertyp mit stabilem `code()`. Rust BAUT und SIGNIERT die drei Anfragen und gibt sie als fertige Bytes samt Kopfzeilen heraus; der Aufrufer — im Browser die Brücke, im Wirtstest die Doppelung — FÜHRT sie aus. Damit hält §9 wörtlich: TypeScript trifft keine Sicherheitsentscheidung, es trägt Bytes.

**Was dieser synchrone Port im Browser kostet, ausgeschrieben statt vorausgesetzt.** Die Analogie zu `blob_store.rs` trägt bei der BAUFORM und nicht von selbst bei der Ausführung, und `crates/ea-reader-wasm/src/opfs_worker.rs` schreibt in seinem eigenen Kopf aus, warum: OPFS hat nach EINEM asynchronen Vorlauf ein wirklich synchrones Handle (`FileSystemSyncAccessHandle`), HTTP hat kein Gegenstück — `fetch` gibt ein Promise, und blockierend darauf warten hielte genau den Faden an, dessen Ereignisschleife es erfüllen müsste. Die einzige synchrone Transportfläche, die ein Browser überhaupt anbietet, ist ein synchrones `XMLHttpRequest`, und die gibt es ausschliesslich in einem DEDIZIERTEN Worker. Die Browserfassung von `EnrollmentEndpoints` steht deshalb genau dort, wo `OpfsBlobStore` schon steht, und aus demselben Grund. Das kostet zwei Einträge, und beide stehen im Files-Block dieser Aufgabe: `XmlHttpRequest` tritt in die aufgezählte `web-sys`-Merkmalsliste der Wurzel-`Cargo.toml` ein, und weil `BROWSER_RUNTIME_DEPENDENCIES` in `tools/xtask/tests/adr_gate.rs` `web-sys` führt und `browser_runtime_dependency_class_is_ratified_before_use` die geprüfte Merkmalsauswahl als EINE wortgleiche Ledgerzeile in `docs/adr/0005-browser-runtime-and-wasm-dependency-class.md` verlangt, zieht diese Zeile im selben Commit nach. Ohne sie fällt `adr_gate` rot, und die Meldung nennt die ADR statt den Transport.

**Daraus folgt die zweite Hälfte, die genauso wenig vorausgesetzt werden darf: `enrollmentFinish` ist ASYNCHRON.** `finish` schreibt am Ende über denselben synchronen `ReaderBlobStore`, und `OpfsBlobStore::open` verlangt die Schlüssel VOR dem Vorlauf — ein Zugriff auf einen nicht vorgelaufenen Schlüssel fällt mit `EA-READER-BLOB-HOST`. Der Export macht deshalb, was `blob_put` und `blob_get` schon machen: EIN asynchroner Vorlauf öffnet `READER_VAULT_BLOB_KEY_V1`, danach läuft `finish` vollständig synchron durch, Endpunkte eingeschlossen. Die drei mittleren Ausfuhren berühren keinen Wirtsspeicher und bleiben synchron. **`enrollmentBegin` ist die ZWEITE asynchrone Ausfuhr**, und zwar aus demselben Grund: `ReaderEnrollment::begin` liest denselben Bytespeicher, weil es sich auf einem Gerät mit bereits versiegeltem Tresor weigert — die Begründung steht unten im Absatz über das Tor in `begin`.

**Und die dritte Folge, die aus den ersten beiden zwingend fällt: die fünf Ausfuhren laufen IM WORKER, `webauthn-prf.ts` auf dem Hauptthread.** Der Enrollment-Zustand liegt in einem `thread_local!`, also müssen alle fünf Aufrufe denselben Faden sehen; OPFS und das synchrone `XMLHttpRequest` gibt es nur im dedizierten Worker; und `navigator.credentials` gibt es nur auf dem Hauptthread. Die Naht dazwischen ist die, die `apps/web/src/bridge/opfs-worker.ts` schon führt: eine schmale, ausgeschriebene Nachrichtenform mit `id` und Antwort-Code, KEINE Fallunterscheidung über Bytes. `webauthn-prf.ts` führt die WebAuthn-Zeremonien und schickt ihre Ergebnisse als Bytes hinüber; der Worker trifft die Entscheidungen, weil dort Rust liegt. **Deshalb steht `apps/web/src/bridge/opfs-worker.ts` im Files-Block:** seine `EaOpfsRequest`/`EaOpfsResponse`-Vereinigung wächst um die fünf Enrollment-Nachrichten, und ein zweiter, eigener Worker wäre die falsche Antwort — zwei Worker öffneten dieselbe OPFS-Datei mit zwei `FileSystemSyncAccessHandle`s, und der zweite bekäme sie gar nicht. Wer die fünf Ausfuhren stattdessen auf dem Hauptthread aufriefe, bekäme eine Fassung, die JEDEN Wirtstest besteht und erst im Browser an OPFS scheitert — dieselbe Warnung, die der Kopf von `crates/ea-reader-wasm/src/opfs_worker.rs` für seinen eigenen Fall schon ausschreibt.

**Und die GRENZE des Browserzeugen, benannt statt geglättet: er läuft SAME-ORIGIN.** `apps/web/index.html` trägt `connect-src 'self'`, `EXPECTED_DIRECTIVES` in `apps/web/src/app/csp.test.ts` pinnt den Wert Position für Position, und der Task „Web-Bundle: getrennter Origin, Service Worker, gepinnte `webBundleRelease` und das Alter des Trust-Standes" ist der EINZIGE, der ihn bewegt — beide Dateien stehen in SEINEM Files-Block und dürfen hier nicht angefasst werden, sonst gäbe es zwei Aufgaben mit demselben Richtlinienwert und die zweite färbte den Vitest-Lauf der ersten rot. Chromium setzt `connect-src` im Renderer durch, BEVOR die Anfrage den Prozess verlässt; ein `page.route`-Abfangjäger auf eine fremde Herkunft käme also nie zum Zug. `stubEnrollmentEndpoints` fängt deshalb den PFAD aus `EnrollmentRequestV1::target_uri` auf dem Bundle-Origin ab. Gemessen ist damit die Zeremonie und die REIHENFOLGE der drei Aufrufe, NICHT der echte herkunftsübergreifende Transport. Die signierte `@authority` bleibt davon unberührt: sie kommt aus `EnrollmentRequestContextV1` und nennt den Sync-Server, weshalb `EnrollmentRequestV1` neben `target_uri()` auch `authority()` herausgibt — der Aufrufer, der die Herkunft später wirklich adressiert, findet sie dort und muss sie nicht erraten. Dass Bundle-Origin und signierte Autorität in DIESEM Lauf auseinanderfallen, ist die benannte Lücke; sie schliesst der Bundle-Task, wenn `connect-src` die Herkunft des Sync-Servers aufnimmt.

`apps/web/src/main.tsx` steht im Files-Block, und die Änderung dort ist GRÖSSER als ein Tabelleneintrag. `EA_WEB_ROUTES` trägt heute `[{ path: '/', label: 'Reader' }]`, `EaWebRoute` hat genau die zwei Felder `path` und `label`, `EaWebApp` rendert für JEDE Route denselben Platzhalterkörper, und `initialPath` steht fest auf `'/'` — nichts liest `window.location.pathname`. Ein `page.goto('/enrollment')` fände also die Route nicht montiert, selbst wenn sie in der Tabelle stünde. Zwei Änderungen fallen deshalb hier: `EaWebRoute` bekommt einen dritten, OPTIONALEN Platz `render?: () => ReactElement` — der Typ ist exportiert, das ist eine öffentliche Formänderung und wird als solche benannt —, und der Montagepunkt am Dateiende übergibt `initialPath={window.location.pathname}`. Der Vorgabewert im Bauteil bleibt `'/'`: nur die Montage liest die Adresse, das Bauteil selbst bleibt für `vitest` deterministisch und ohne Wirtsbezug.

`apps/web/tsconfig.json` steht im Files-Block, weil sein `include` heute `["src", "index.html", "vite.config.ts"]` ist. `apps/web/playwright.config.ts` und `apps/web/tests/e2e/enrollment.spec.ts` entstehen in diesem Task und lägen damit AUSSERHALB von `pnpm web:typecheck` — keine Typprüfung, kein Gate, kein Signal. Der Desktop schliesst genau diese Lücke halb, und zwar in seiner `apps/desktop/tsconfig.json`: deren `include` führt `"playwright.config.ts"` ausdrücklich mit auf, weshalb die Konfiguration dort im Programm liegt; `apps/desktop/src/e2e-config.test.ts` zieht sie daneben über `await import('../playwright.config')` und behauptet ihre tragenden Schlüssel, was ein zweiter, unabhängiger Grund ist. Ungeprüft bleiben auf dem Desktop allein die Spezifikationen unter `tests`. Diese Aufgabe schliesst BEIDE Hälften und ist damit die erste, die `"tests"` überhaupt einträgt: `apps/web/src/e2e-config.test.ts` spiegelt den Desktop-Zeugen, und `include` wächst um `"playwright.config.ts"` und `"tests"`. Der zweite Teil kostet zwei Einträge in einem Feld und ist jetzt billig; nach vier weiteren E2E-Suiten dieses Plans wäre er eine Nachrüstung über vier Dateien, die jemand dann nicht mehr macht. `apps/web/vite.config.ts` bleibt UNBERÜHRT: sein `include: ['src/**/*.test.{ts,tsx}']` hält `tests/e2e` schon heute aus dem Vitest-Lauf heraus.

Diese Aufgabe baut `web-reader-design.md` §6.3, §6.6 und §4.3 und sonst nichts. Ausdrücklich NICHT hier: das Objekt `readerKeyEscrow` und die Zwei-Approver-Öffnungszeremonie (§7.3/§7.5, Stufe 5, Ledgerzeile `WR-075`), die Administrationshälfte des Enrollments, die den erwarteten Fingerprint in der Desktop-Anwendung anzeigt und die Root-Signatur des Reader-Zertifikats auslöst (§6.6 Schritt 4, Stufe 5), und der Historical Re-grant für Einträge vor dem Enrollment (§6.6 Schritt 6, `design.md` §6.5). Der Cross-Device-QR-Flow wird hier als Entsperrpfad ABGEWIESEN und nicht implementiert: `web-reader-design.md` §6.4.1 und §13 nennen ihn beide, weil Safari in diesem Flow keine PRF-Ausgabe liefert.

- [x] **Step 1: Build the wasm bridge output the web suite imports**

Run: `cargo run --locked -p xtask -- build-wasm`

`apps/web/src/bridge/pkg/` ist über die generische Zeile `pkg/` in `.gitignore` gehalten und liegt in einem frischen Checkout NICHT vor. `apps/web/src/bridge/wasm-runtime.test.ts` und `apps/web/src/bridge/opfs-worker.ts` führen beide `./pkg/ea_reader_wasm.js`; ohne das Verzeichnis fallen `pnpm web:test` und `pnpm web:typecheck` aus einem Grund, der mit dieser Aufgabe nichts zu tun hat, und wer den roten Punkt für den eigenen sieht, sucht ihn eine Stunde lang an der falschen Stelle. Der Schritt steht deshalb VOR dem Schreiben der Zeugen und nicht als Fussnote daneben. `build-wasm` nimmt ausdrücklich kein Argument (`tools/xtask/src/main.rs`, Zweig `"build-wasm"`), und der Lauf ist idempotent; wer ihn in seinem Arbeitsbaum schon gefahren hat, fährt ihn hier folgenlos erneut.

Expected: Exit 0, und `apps/web/src/bridge/pkg/ea_reader_wasm.d.ts` führt danach die SECHS heutigen Ausfuhren `blobGet`, `blobPut`, `bridgeEcho`, `readerRuntimeWitness`, `readerVaultSeal`, `readerVaultUnlock`. Die fünf Ausfuhren dieser Aufgabe kommen erst im Implementierungsschritt dazu; wer sie hier schon sucht, hat den Schritt falsch gelesen.

- [x] **Step 2: Write the cardinality, transport-order, and unskippable-fingerprint witnesses**

`crates/ea-reader/tests/enrollment_two_authenticators.rs` und `crates/ea-reader/tests/fingerprint_gate.rs` beginnen beide mit `mod fixtures;` — die Anordnung jedes bestehenden Integrationstestziels dieser Crate, siehe `crates/ea-reader/tests/vault_envelope.rs`.

`crates/ea-reader/tests/fixtures/mod.rs` steht mit einer `Modify:`-Zeile im Files-Block, weil die Zeugen dieser Aufgabe DREIZEHN neue Posten dort brauchen und die Datei sie heute nicht hat. Vorhanden sind `credential_id(index)`, `prf_output(index)`, `authenticator(index)`, `pinned_anchor()`, `pinned_anchor_exact_bytes()`, `foreign_anchor_exact_bytes()`, `reader_kem_public_key()`, die fünf Zertifikatsbauer, `last_registry_pin()`, `vault_contents()`, `sealed_vault()`, `unlocked_vault()`, `second_unlocked_vault()`, `entry_hash()`, `entry_package_bytes_carrying(marker)` und `missing_grant_state()`. Neu kommen dazu, und keiner davon existiert heute: `organization() -> OrganizationId`, `subject() -> SubjectId`, `bundle_fingerprint() -> Hash32`, `credential_public_cose_key(index: u8) -> Vec<u8>`, `attested(index: u8) -> AttestedAuthenticatorV1`, `attested_with_short_credential_id() -> AttestedAuthenticatorV1`, `cross_device_attested() -> AttestedAuthenticatorV1`, `request_context() -> EnrollmentRequestContextV1`, `retrieval_request() -> VaultBlobRetrievalRequestV1`, `enrollment_with_two_authenticators() -> ReaderEnrollment` nebst `enrollment_with_two_authenticators_on(store: &dyn ReaderBlobStore) -> ReaderEnrollment` — der Speicher tritt als Parameter ein, weil `begin` ihn liest und ein intern gebautes, immer leeres Doppel jeden Zeugen an der Weigerung aus `begin` vorbeilaufen liesse —, `two_authenticator_enrollment_into(endpoints: &mut dyn EnrollmentEndpoints, store: &mut dyn ReaderBlobStore) -> EnrolledReaderV1`, `seven_foreign_ciphertexts_and(stored: Vec<u8>) -> Vec<Vec<u8>>` und `flip_one_hex_digit(value: &str) -> String`. Fünf Dinge sind dabei GEMESSEN und nicht angenommen: `credential_id(index)` liefert `b"ea-reader-passkey-"` plus eine Ziffer, also 19 Byte, und liegt damit über `MIN_WEBAUTHN_CREDENTIAL_ID_BYTES_V1` von 16 — die bestehenden Fixture-Kennungen sind für `WebauthnCredentialRegistrationV1::new` bereits gültig und werden NICHT geändert, während `attested_with_short_credential_id()` mit acht Byte bewusst DARUNTER liegt und den einzigen Zweck hat, `CredentialIdLength` auszulösen; `credential_public_cose_key(index)` entsteht über `CanonicalPublicCoseKey::ed25519(ea_testkit::ed25519_public_key(&seed))` und `to_deterministic_cbor()`, damit die Kartenform genau die ist, die `WebauthnCredentialRegistrationV1::new` beim Bauen der Anfrage ein zweites Mal parst; `seven_foreign_ciphertexts_and(stored)` liefert ACHT Elemente und damit genau `MAX_VAULT_BLOBS_PER_SUBJECT_V1`, jedes nichtleer und unter den 4 KB aus `MAX_VAULT_BLOB_CIPHERTEXT_BYTES_V1`, die `VaultBlobRetrievalResponseV1::new` durchlässt; `two_authenticator_enrollment_into` nimmt den ENDPUNKTPORT UND den Bytespeicher, weil `finish` beide braucht und ein intern gebautes Doppel die Aufrufe an einer Stelle aufzeichnete, an der kein Zeuge sie sieht — eine store-only Fassung wäre genau der Fehler, den `finish_calls_three_endpoints_in_order_and_only_then_writes_locally` messen soll; und `AUTHENTICATOR_ONE`/`AUTHENTICATOR_TWO` gibt es NICHT als `const`, weil eine `credentialId` ein `Vec<u8>` ist und eine Heapallokation nicht `const`-auswertbar ist — die Zeugen nennen `fixtures::credential_id(1)` und `fixtures::authenticator(1)`, also die Funktionen, die die Datei heute schon führt. `retrieval_request()` schliesslich baut eine `VaultBlobRetrievalRequestV1` mit `organization()`, `subject()`, `credential_id(2)`, einer festen 32-Byte-Challenge, `authenticatorData`, `clientDataJSON` und einer 64-Byte-Signatur; die Assertion ist auf dem Wirt GESTELLT und nicht echt, und das ist zulässig, weil `recover_and_unlock_vault` sie nicht prüft — sie ist die Autorität des SERVERS, und den misst `pnpm test:server`.

`crates/ea-reader/tests/enrollment_two_authenticators.rs` hält die Kardinalität, die Envelope-Konstruktion und die REIHENFOLGE der drei Endpunktaufrufe. **Eine Weigerung, deren OK-Typ kein `Debug` trägt, wird über `.err().expect("…")` geprüft und NICHT über `.unwrap_err()`, und das ist keine Geschmacksfrage:** `Result::unwrap_err` ist auf `T: Debug` beschränkt, und drei OK-Typen dieser Aufgabe haben es nicht — `&AuthenticatorRecordV1` (er hält eine `SecretBytes<32>`), `EnrolledReaderV1` und `FingerprintConfirmationV1`, das es ausdrücklich nicht bekommt. Dieselbe Schreibweise steht aus demselben Grund schon in `crates/ea-reader/tests/vault_envelope.rs`. Wo der OK-Typ ein `Debug` HAT — `UnlockedVault` etwa, mit seiner handgeschriebenen Ausgabe in `crates/ea-reader/src/vault.rs` —, bleibt `.unwrap_err()` stehen, und wo nur der Fehlertyp zählt, `.unwrap()`: das verlangt `Debug` allein auf dem FEHLER, und `EnrollmentError` leitet es ab.

```rust
#[test]
fn a_single_authenticator_is_a_refusal_and_writes_no_blob() {
    let mut store = InMemoryReaderBlobStore::new();
    let mut endpoints = InMemoryEnrollmentEndpoints::new();
    let mut enrollment = ReaderEnrollment::begin(
        &store,
        fixtures::organization(),
        fixtures::subject(),
        fixtures::pinned_anchor(),
        fixtures::bundle_fingerprint(),
    )
    .unwrap();
    enrollment.register_authenticator(fixtures::attested(1)).unwrap();
    let shown = enrollment.fingerprints();
    let confirmation = enrollment
        .confirm_fingerprints(&shown.key_fingerprint_hex(), &shown.bundle_fingerprint_hex())
        .unwrap();
    let refused = enrollment
        .finish(confirmation, fixtures::request_context(), &mut endpoints, &mut store)
        .err()
        .expect("ein einzelner Authenticator ist eine Weigerung");
    assert_eq!(refused.code(), "EA-READER-ENROLLMENT-SINGLE-AUTHENTICATOR");
    assert!(
        store.keys().unwrap().is_empty(),
        "a refused enrollment must leave no vault blob behind"
    );
    assert!(
        endpoints.calls().is_empty(),
        "a refused enrollment must not reach a single endpoint"
    );
}

#[test]
fn finish_calls_three_endpoints_in_order_and_only_then_writes_locally() {
    let mut store = InMemoryReaderBlobStore::new();
    let mut endpoints = InMemoryEnrollmentEndpoints::new();
    let enrolled = fixtures::two_authenticator_enrollment_into(&mut endpoints, &mut store);
    // Die Reihenfolge IST die Zusage, deshalb steht sie als ganze Liste da und
    // nicht als drei Einzelproben.
    assert_eq!(
        endpoints.calls(),
        &[
            EnrollmentCallV1 { method: HttpMethod::Post, target_uri: "/v1/webauthn-credentials".to_owned(), signed: true },
            EnrollmentCallV1 { method: HttpMethod::Post, target_uri: "/v1/webauthn-credentials".to_owned(), signed: true },
            EnrollmentCallV1 { method: HttpMethod::Put, target_uri: "/v1/vault-blobs".to_owned(), signed: true },
        ]
    );
    assert_eq!(store.keys().unwrap(), vec![enrolled.blob_key().clone()]);
}

#[test]
fn a_failing_upload_leaves_nothing_written_at_all() {
    let mut store = InMemoryReaderBlobStore::new();
    let mut endpoints = InMemoryEnrollmentEndpoints::new();
    // Der DRITTE Aufruf ist das `PUT /v1/vault-blobs`; er faellt, nachdem beide
    // Credentials schon angelegt sind. Genau dieser Zeitpunkt ist der Punkt,
    // an dem ein nicht fail-closed gebautes `finish` lokal schriebe.
    endpoints.fail_call(3, EnrollmentEndpointError::Status(503));
    let enrollment = fixtures::enrollment_with_two_authenticators();
    let shown = enrollment.fingerprints();
    let confirmation = enrollment
        .confirm_fingerprints(&shown.key_fingerprint_hex(), &shown.bundle_fingerprint_hex())
        .unwrap();
    let refused = enrollment
        .finish(confirmation, fixtures::request_context(), &mut endpoints, &mut store)
        .err()
        .expect("ein gefallener Upload ist eine Weigerung");
    assert_eq!(refused.code(), "EA-READER-ENROLLMENT-ENDPOINT-STATUS");
    assert!(store.keys().unwrap().is_empty());
}

#[test]
fn each_authenticator_yields_one_envelope_over_the_same_vault_key() {
    let mut store = InMemoryReaderBlobStore::new();
    let mut endpoints = InMemoryEnrollmentEndpoints::new();
    let enrolled = fixtures::two_authenticator_enrollment_into(&mut endpoints, &mut store);
    assert_eq!(enrolled.envelopes().len(), 2);
    let first = enrolled.unlock_with(&fixtures::authenticator(1)).unwrap();
    let second = enrolled.unlock_with(&fixtures::authenticator(2)).unwrap();
    // Ueber `as_bytes()`, weil `KeyThumbprint` und `Hash32` kein `Debug`
    // ableiten (`crates/ea-types/src/ids.rs`, `hash_newtype!`) — dieselbe
    // Schreibweise wie in `crates/ea-reader/tests/vault_envelope.rs`.
    assert_eq!(
        first.kem_key_thumbprint().as_bytes(),
        second.kem_key_thumbprint().as_bytes()
    );
    assert_eq!(
        first.pinned_anchor().trust_anchor_hash().as_bytes(),
        fixtures::pinned_anchor().trust_anchor_hash().as_bytes()
    );
}

#[test]
fn the_prf_output_is_never_the_wrapping_key_and_deleting_one_passkey_keeps_the_vault_open() {
    let mut store = InMemoryReaderBlobStore::new();
    let mut endpoints = InMemoryEnrollmentEndpoints::new();
    let enrolled = fixtures::two_authenticator_enrollment_into(&mut endpoints, &mut store);
    // Die ROHE PRF-Ausgabe DIREKT als Wrapping-Schluessel vorgelegt. `unwrap_err`
    // scheidet aus: sein Ok-Typ ist `SecretBytes<CEK_SIZE>`, und `SecretBytes`
    // traegt bewusst kein `Debug`.
    let refused = enrolled.envelopes()[0]
        .unwrap(&SecretBytes::new(fixtures::prf_output(1)))
        .err()
        .expect("die rohe PRF-Ausgabe ist nicht der Wrapping-Schluessel");
    assert_eq!(refused.code(), "EA-CRYPTO-AEAD-OPEN");
    // `without_authenticator` reicht auf `SealedVaultV1::without_credential`
    // durch — und das gibt ein `Result` zurueck, weil das Entfernen des LETZTEN
    // Entsperrweges `EA-READER-VAULT-NO-AUTHENTICATOR` ist.
    let surviving = enrolled
        .without_authenticator(fixtures::credential_id(1))
        .unwrap();
    assert_eq!(surviving.envelopes().len(), 1);
    assert!(surviving.unlock_with(&fixtures::authenticator(2)).is_ok());
    let closed = surviving.unlock_with(&fixtures::authenticator(1)).unwrap_err();
    assert_eq!(closed.code(), "EA-READER-VAULT-NO-ENVELOPE");
}

#[test]
fn a_duplicate_credential_id_does_not_count_twice() {
    let store = InMemoryReaderBlobStore::new();
    let mut enrollment = ReaderEnrollment::begin(
        &store,
        fixtures::organization(),
        fixtures::subject(),
        fixtures::pinned_anchor(),
        fixtures::bundle_fingerprint(),
    )
    .unwrap();
    enrollment.register_authenticator(fixtures::attested(1)).unwrap();
    let refused = enrollment
        .register_authenticator(fixtures::attested(1))
        .err()
        .expect("dieselbe credentialId zaehlt kein zweites Mal");
    assert_eq!(refused.code(), "EA-READER-ENROLLMENT-DUPLICATE-AUTHENTICATOR");
    assert_eq!(enrollment.registered_authenticator_count(), 1);
}

#[test]
fn a_credential_id_below_the_protocol_minimum_is_refused_here_and_not_at_the_endpoint() {
    let store = InMemoryReaderBlobStore::new();
    let mut enrollment = ReaderEnrollment::begin(
        &store,
        fixtures::organization(),
        fixtures::subject(),
        fixtures::pinned_anchor(),
        fixtures::bundle_fingerprint(),
    )
    .unwrap();
    let refused = enrollment
        .register_authenticator(fixtures::attested_with_short_credential_id())
        .err()
        .expect("acht Byte liegen unter MIN_WEBAUTHN_CREDENTIAL_ID_BYTES_V1");
    assert_eq!(refused.code(), "EA-READER-ENROLLMENT-CREDENTIAL-ID-LENGTH");
    assert_eq!(enrollment.registered_authenticator_count(), 0);
}

#[test]
fn the_cross_device_qr_flow_is_not_an_unlock_path() {
    let store = InMemoryReaderBlobStore::new();
    let mut enrollment = ReaderEnrollment::begin(
        &store,
        fixtures::organization(),
        fixtures::subject(),
        fixtures::pinned_anchor(),
        fixtures::bundle_fingerprint(),
    )
    .unwrap();
    let refused = enrollment
        .register_authenticator(fixtures::cross_device_attested())
        .err()
        .expect("der QR-Flow ist kein Entsperrpfad");
    assert_eq!(refused.code(), "EA-READER-ENROLLMENT-TRANSPORT-REFUSED");
}

#[test]
fn the_retrieval_carries_no_signature_and_exactly_one_ciphertext_opens() {
    let mut store = InMemoryReaderBlobStore::new();
    let mut enrolling = InMemoryEnrollmentEndpoints::new();
    let enrolled = fixtures::two_authenticator_enrollment_into(&mut enrolling, &mut store);
    let stored = store.get(enrolled.blob_key()).unwrap().unwrap();
    // Acht Chiffrate, wie `MAX_VAULT_BLOBS_PER_SUBJECT_V1` sie zulaesst, und
    // GENAU EINES gehoert diesem Reader. Die sieben anderen sind Rauschen.
    // Ein FRISCHES Doppel, damit `calls()` nur den Abruf zeigt und nicht die
    // drei Aufrufe, mit denen das Enrollment vorher fertig wurde.
    let mut endpoints = InMemoryEnrollmentEndpoints::new();
    endpoints.answer_retrieval_with(fixtures::seven_foreign_ciphertexts_and(stored));
    let unlocked = recover_and_unlock_vault(
        &fixtures::retrieval_request(),
        &fixtures::authenticator(2),
        &mut endpoints,
    )
    .unwrap();
    assert_eq!(
        unlocked.pinned_anchor().trust_anchor_hash().as_bytes(),
        fixtures::pinned_anchor().trust_anchor_hash().as_bytes()
    );
    assert_eq!(
        endpoints.calls(),
        &[EnrollmentCallV1 {
            method: HttpMethod::Post,
            target_uri: "/v1/vault-blobs/retrievals".to_owned(),
            signed: false,
        }]
    );
}

#[test]
fn a_reader_without_an_envelope_in_any_ciphertext_gets_no_vault_for_credential() {
    let mut store = InMemoryReaderBlobStore::new();
    let mut enrolling = InMemoryEnrollmentEndpoints::new();
    let enrolled = fixtures::two_authenticator_enrollment_into(&mut enrolling, &mut store);
    let stored = store.get(enrolled.blob_key()).unwrap().unwrap();
    let mut endpoints = InMemoryEnrollmentEndpoints::new();
    endpoints.answer_retrieval_with(fixtures::seven_foreign_ciphertexts_and(stored));
    // Derselbe Antwortsatz, aber ein dritter Authenticator, fuer den in KEINEM
    // der acht Chiffrate ein Envelope liegt. Der Unterschied zu
    // `EA-READER-VAULT-NO-ENVELOPE` ist die Reichweite: dort scheitert EIN
    // bekannter Tresor, hier scheitert der ganze Abruf.
    let refused = recover_and_unlock_vault(
        &fixtures::retrieval_request(),
        &fixtures::authenticator(3),
        &mut endpoints,
    )
    .unwrap_err();
    assert_eq!(refused.code(), "EA-READER-ENROLLMENT-NO-VAULT");
    assert_eq!(endpoints.calls().len(), 1);
}
```

`crates/ea-reader/tests/fingerprint_gate.rs` hält §4.3. Die Zusicherung ist nicht „es gibt eine Prüfung", sondern „es gibt keinen Weg daran vorbei": `finish` nimmt eine `FingerprintConfirmationV1`, und dieser Typ ist AUSSCHLIESSLICH aus `ReaderEnrollment::confirm_fingerprints` mit übereinstimmenden Werten konstruierbar — dieselbe Bauform, mit der `VerifiedEncryptedEntry` im Task „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert" den HPKE-Entkapseler bewacht.

```rust
#[test]
fn a_diverging_fingerprint_aborts_the_enrollment() {
    let enrollment = fixtures::enrollment_with_two_authenticators();
    let shown = enrollment.fingerprints();
    // Beide Seiten sind HEXZEICHENKETTEN, und das ist die entschiedene Form:
    // die ANGEZEIGTEN Werte sind typisiert (`KeyThumbprint`, `Hash32`), die
    // ERWARTETEN kommen aus einer Tastatur.
    let wrong_bundle = fixtures::flip_one_hex_digit(&shown.bundle_fingerprint_hex());
    // `.err().expect(…)` und nicht `.unwrap_err()`: der OK-Typ ist
    // `FingerprintConfirmationV1`, und der traegt bewusst kein `Debug`.
    let refused = enrollment
        .confirm_fingerprints(&shown.key_fingerprint_hex(), &wrong_bundle)
        .err()
        .expect("ein abweichender Bundle-Fingerprint bestaetigt nichts");
    assert_eq!(refused.code(), "EA-READER-ENROLLMENT-FINGERPRINT-MISMATCH");
    let wrong_key = fixtures::flip_one_hex_digit(&shown.key_fingerprint_hex());
    let refused_key = enrollment
        .confirm_fingerprints(&wrong_key, &shown.bundle_fingerprint_hex())
        .err()
        .expect("ein abweichender Schluessel-Fingerprint bestaetigt nichts");
    assert_eq!(refused_key.code(), "EA-READER-ENROLLMENT-FINGERPRINT-MISMATCH");
    let malformed = enrollment
        .confirm_fingerprints("nicht hexadezimal", &shown.bundle_fingerprint_hex())
        .err()
        .expect("eine nicht-hexadezimale Eingabe bestaetigt nichts");
    assert_eq!(malformed.code(), "EA-READER-ENROLLMENT-FINGERPRINT-ENCODING");
}

#[test]
fn the_shown_values_are_the_kem_thumbprint_and_the_bundle_hash() {
    let enrollment = fixtures::enrollment_with_two_authenticators();
    let shown = enrollment.fingerprints();
    assert_eq!(
        shown.bundle_fingerprint().as_bytes(),
        fixtures::bundle_fingerprint().as_bytes()
    );
    assert_eq!(shown.key_fingerprint_hex(), hex::encode(shown.key_fingerprint().as_bytes()));
    assert_eq!(shown.key_fingerprint_hex().len(), 64);
}

#[test]
fn the_confirmation_has_no_construction_path_outside_a_match() {
    // Der Beweis ist die ABWESENHEIT einer Konstruktion, nicht ihr Ergebnis.
    // Die Arithmetik steht ausgeschrieben da, weil eine nackte Zahl hier nicht
    // pruefbar waere: die DEKLARATION enthaelt dieselbe Zeichenfolge wie eine
    // Konstruktion, und ein `impl`-Kopf ebenfalls.
    let source = include_str!("../src/enrollment.rs");
    assert_eq!(
        source.matches("pub struct FingerprintConfirmationV1 {").count(),
        1,
        "genau eine Deklaration"
    );
    assert_eq!(
        source.matches("FingerprintConfirmationV1 {").count(),
        2,
        "die Deklaration und GENAU EIN Strukturausdruck in confirm_fingerprints"
    );
    assert_eq!(
        source.matches("impl FingerprintConfirmationV1").count(),
        0,
        "kein inhaerenter impl-Block: er koennte eine zweite Konstruktionsstelle \
         hinter einer assoziierten Funktion verstecken, und sein Kopf zaehlte \
         oben mit"
    );
    assert!(!source.contains("pub fn skip"), "no skip path may exist");
    assert!(!source.contains("Default for FingerprintConfirmationV1"));
    assert!(!source.contains("Clone for FingerprintConfirmationV1"));
    assert!(
        !source.contains("AnchorUnpinned"),
        "der fehlende Anker ist im Typ ausgeschlossen und braucht keinen Laufzeitfall"
    );
}

#[test]
fn the_gate_fires_on_every_first_call_without_a_pinned_trust_store() {
    let mut store = InMemoryReaderBlobStore::new();
    let mut endpoints = InMemoryEnrollmentEndpoints::new();
    let known = ReaderEnrollment::device_state(&store).unwrap();
    assert!(matches!(known, DeviceTrustStateV1::NoPinnedAnchor));
    assert!(ReaderEnrollment::fingerprint_gate_required(&known));
    let enrolled = fixtures::two_authenticator_enrollment_into(&mut endpoints, &mut store);
    let after = ReaderEnrollment::device_state(&store).unwrap();
    assert!(matches!(after, DeviceTrustStateV1::Pinned));
    assert!(!ReaderEnrollment::fingerprint_gate_required(&after));
    drop(enrolled);
}
```

`apps/web/src/features/enrollment/EnrollmentPage.test.tsx` prüft dieselben zwei Zusagen auf der Oberfläche und NICHTS darüber hinaus: das Abschlusselement bleibt gesperrt, solange ein Authenticator fehlt oder der Fingerprintvergleich nicht bestätigt ist, und die Bestätigung ist kein Häkchen, sondern die Eingabe der unabhängig verteilten Referenz. `stubBridge`, `SHOWN` und `WRONG` stehen im KOPF DIESER DATEI und in keinem gemeinsamen Hilfsmodul: eine Testdatei ist von beiden Quelltextscans des Pakets ausgenommen (`apps/web/src/bridge/no-hand-written-contracts.test.ts` und `apps/web/src/design/static-css.test.ts` filtern `.test.tsx?` heraus), ein Hilfsmodul daneben wäre es nicht und schleppte die Fingerprint-Literale in den gescannten Bestand. Der Typ `EnrollmentBridge`, gegen den beide Zeugen geschrieben sind, steht dagegen NICHT hier, sondern in `apps/web/src/vault/webauthn-prf.ts` neben den fünf Aufrufen, die er beschreibt — er ist die Form der Brücke und keine Testhilfe. **Sein Bestätigungs-DTO schreibt `code?: string | undefined` und nicht `code?: string`,** und das ist gemessen: `apps/web/tsconfig.json` setzt `exactOptionalPropertyTypes: true`, unter dem ein ausgeschriebenes `code: … ? undefined : '…'` mit TS2322 an einem `code?: string` scheitert. `EaOpfsResponse` in `apps/web/src/bridge/opfs-worker.ts` schreibt `bytes?: Uint8Array | undefined` aus genau diesem Grund; die Schreibweise ist die des Hauses und keine Erfindung dieser Aufgabe.

```tsx
const user = userEvent.setup()

const SHOWN = { keyFingerprint: 'a'.repeat(64), bundleFingerprint: 'b'.repeat(64) }
const WRONG = 'c'.repeat(64)

function stubBridge(overrides: Partial<EnrollmentBridge> = {}): EnrollmentBridge {
  // Der Zaehler ist ZUSTAND und keine Konstante: die Seite nimmt die Zahl der
  // registrierten Authenticators aus der Bruecke und zaehlt keine Klicks selbst
  // (§9). Ein Doppel, das immer `registered: 1` meldet, liesse das
  // Abschlusselement fuer immer gesperrt und der Zeuge waere rot.
  let registered = 0
  return {
    begin: vi.fn(async () => ({ handle: 1, prfSalt: new Uint8Array(0), publicKeyAlgorithms: [-8] })),
    registerAuthenticator: vi.fn(async () => ({ registered: (registered += 1), required: 2 })),
    fingerprints: vi.fn(async () => SHOWN),
    confirmFingerprints: vi.fn(async ({ expectedBundleFingerprint }) => ({
      confirmed: expectedBundleFingerprint === SHOWN.bundleFingerprint,
      code: expectedBundleFingerprint === SHOWN.bundleFingerprint
        ? undefined
        : 'EA-READER-ENROLLMENT-FINGERPRINT-MISMATCH',
    })),
    finish: vi.fn(async () => ({ finished: true })),
    ...overrides,
  }
}

it('keeps the enrollment closed until two authenticators and both fingerprints agree', async () => {
  render(<EnrollmentPage bridge={stubBridge()} />)
  expect(screen.getByRole('button', { name: 'Enrollment abschließen' })).toBeDisabled()
  await user.click(screen.getByRole('button', { name: 'Authenticator registrieren' }))
  expect(screen.getByText('Ein zweiter Authenticator ist erforderlich.')).toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Authenticator registrieren' }))
  expect(screen.getByText('2 von 2 Authenticators registriert.')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Enrollment abschließen' })).toBeDisabled()
  await user.type(screen.getByLabelText('Erwarteter Bundle-Fingerprint'), WRONG)
  await user.type(screen.getByLabelText('Erwarteter Schlüssel-Fingerprint'), SHOWN.keyFingerprint)
  expect(screen.getByRole('alert')).toHaveTextContent('EA-READER-ENROLLMENT-FINGERPRINT-MISMATCH')
  expect(screen.getByRole('button', { name: 'Enrollment abschließen' })).toBeDisabled()
  await user.clear(screen.getByLabelText('Erwarteter Bundle-Fingerprint'))
  await user.type(screen.getByLabelText('Erwarteter Bundle-Fingerprint'), SHOWN.bundleFingerprint)
  expect(screen.getByRole('button', { name: 'Enrollment abschließen' })).toBeEnabled()
})

it('derives no key and compares no fingerprint in TypeScript', async () => {
  const bridge = stubBridge()
  render(<EnrollmentPage bridge={bridge} />)
  await user.type(screen.getByLabelText('Erwarteter Bundle-Fingerprint'), SHOWN.bundleFingerprint)
  await user.type(screen.getByLabelText('Erwarteter Schlüssel-Fingerprint'), SHOWN.keyFingerprint)
  expect(bridge.confirmFingerprints).toHaveBeenCalledWith({
    handle: 1,
    expectedKeyFingerprint: SHOWN.keyFingerprint,
    expectedBundleFingerprint: SHOWN.bundleFingerprint,
  })
})
```

`apps/web/playwright.config.ts` entsteht in DIESEM Task, weil er der erste ist, der Playwright fährt; die späteren E2E-Läufe der Tasks „Web-Bundle: getrennter Origin, Service Worker, gepinnte `webBundleRelease` und das Alter des Trust-Standes", „Datei-Modus: Einzeldatei-Bündel, Verzeichnis-Handle, kein Cursor, `nicht server-bestätigt`", „Sitzungssperre, Zeroize, authenticator-bestätigter Einzelexport und signiertes lokales Audit" und „Integritätszentrierte Reader-Oberfläche in `apps/web` und die Rollengrenze zum Desktop" benutzen sie unverändert. Die Konfiguration folgt der Desktop-Vorlage einschliesslich ihrer Ausdrucksform: der Default-Export steht unter `satisfies PlaywrightTestConfig` und nicht unter `defineConfig`, weil `defineConfig` `webServer` zu `TestConfigWebServer | TestConfigWebServer[]` weitet und `config.webServer?.command` im Zeugen dann mit TS2339 fällt — der Desktop schreibt genau diese Messung in seinen eigenen Kopf. Inhalt: `testDir: 'tests/e2e'`, `webServer` mit `pnpm exec vite build && pnpm exec vite preview --host 127.0.0.1 --port 4174 --strictPort` — ein ANDERER Port als die 4173 des Desktops, damit beide Suiten nebeneinander laufen —, `webServer.timeout: 180_000` wie dort, weil ein kalter Vite-Bau samt Ant Design die Vorgabe von 60 s nicht zuverlässig deckt, `webServer.url: 'http://127.0.0.1:4174'`, `use.baseURL` auf denselben Wert und `use.offline: false`, weil `offline: true` auf Kontextebene in Chromium den GESAMTEN Netzstapel einschliesslich `127.0.0.1` abschneidet und die Anwendung dann nie lädt. Sie trägt in diesem Task GENAU EIN `projects`-Element, `chromium` — der Desktop hat gar keinen `projects`-Schlüssel, das ist hier also die erste Fassung und keine Kopie —; die Matrix aus `chromium`, `firefox` und `webkit` entsteht im Task „Reader-Interoperabilität, Browser-Matrix, Datei-Modus, Privatheit und das Stufe-4-Gate". `package.json` der Wurzel bekommt dazu das Skript `"web:e2e": "pnpm --dir apps/web e2e"` — `apps/web/package.json` führt `"e2e": "playwright test"` bereits —; es steht wie `desktop:e2e` AUSDRÜCKLICH NICHT in `verify_quick_commands()`, weil Playwright installierte Browser voraussetzt. Ein `cargo run --locked -p xtask -- browsers up` ist NICHT nötig: dieses Compose-File bedient `web:browser-test` und chromedriver, während Playwright seinen eigenen Browser aus `~/.cache/ms-playwright` nimmt.

`apps/web/src/e2e-config.test.ts` spiegelt `apps/desktop/src/e2e-config.test.ts`: es zieht die Konfiguration über `await import('../playwright.config')` — womit `tsc` sie überhaupt erst sieht — und behauptet `testDir`, die Reihenfolge `vite build` vor `vite preview`, `--host 127.0.0.1`, `webServer.url === 'http://127.0.0.1:4174'`, `use.baseURL === webServer.url`, `use.offline === false` und dass genau ein `projects`-Eintrag mit dem Namen `chromium` darin steht. Der letzte Punkt hat einen eigenen Zweck: der Gate-Task stellt zwei weitere Projekte daneben, und dieser Zeuge macht die Erweiterung zu einer bewussten Änderung statt zu einem Nebeneffekt.

`.gitignore` bekommt im selben Zug die zwei Zeilen `apps/web/test-results/` und `apps/web/playwright-report/`, eingefügt hinter `apps/desktop/playwright-report/`. Sie sind das Spiegelbild der bereits vorhandenen Desktop-Zeilen und fallen in DIESEM Task, weil er der erste ist, der Playwright fährt und damit als erster diese Verzeichnisse erzeugt. Ohne sie zögen die späteren `git add apps/web` der Tasks „Web-Bundle: getrennter Origin, Service Worker, gepinnte `webBundleRelease` und das Alter des Trust-Standes", „Datei-Modus: Einzeldatei-Bündel, Verzeichnis-Handle, kein Cursor, `nicht server-bestätigt`" und „Integritätszentrierte Reader-Oberfläche in `apps/web` und die Rollengrenze zum Desktop" den kompletten Lauf-Ausgang samt Traces und Screenshots in das Repositorium — genau der Grund, aus dem die Desktop-Zeilen dort stehen.

`apps/web/tests/e2e/enrollment.spec.ts` fährt denselben Ablauf gegen einen virtuellen Authenticator UND ist der einzige Zeuge dieses Plans, der eine ECHTE PRF-Ausgabe berührt. Der Lauf ist AUSDRÜCKLICH auf das Playwright-Projekt `chromium` beschränkt und trägt das dazu: `WebAuthn.addVirtualAuthenticator` ist eine CDP-Methode, Firefox und WebKit bieten kein Gegenstück, und die Browser-Matrix des Tasks „Reader-Interoperabilität, Browser-Matrix, Datei-Modus, Privatheit und das Stufe-4-Gate" führt diese Einschränkung als benannte Lücke statt sie zu verschweigen. Die Beschränkung braucht einen MECHANISMUS und nicht nur einen Satz: solange `apps/web/playwright.config.ts` ein einziges `projects`-Element trägt, ist sie folgenlos, aber der Gate-Task stellt zwei Projekte daneben und fährt `pnpm web:e2e` über alle Spezifikationen. Deshalb steht in der ersten Zeile jeder CDP-benutzenden Spezifikation dieses Plans `test.skip(({ browserName }) => browserName !== 'chromium')`, und `enrollment.spec.ts` ist die erste, die sie trägt.

Der virtuelle Authenticator wird mit `hasPrf: true` erzeugt. Das ist GEMESSEN und keine Hoffnung: `node_modules/.pnpm/playwright-core@1.62.1/…/types/protocol.d.ts` führt `hasPrf?: boolean` in `WebAuthn.VirtualAuthenticatorOptions` mit dem Kommentar „If set to true, the authenticator will support the prf extension." Der Server wird nicht gebraucht und nicht gestartet: `stubEnrollmentEndpoints(page)` — es steht im KOPF von `enrollment.spec.ts` und in keinem gemeinsamen Hilfsmodul, aus demselben Grund wie `stubBridge` in der vitest-Datei — setzt `page.route('**/v1/**', …)` und beantwortet damit die drei Endpunkte auf dem Bundle-Origin; was der Server mit ihnen macht, misst `pnpm test:server` mit `--test webauthn_credential_api --test vault_blob_api`. Dieser Lauf misst die BROWSERHÄLFTE.

Der letzte Abschnitt des Zeugen, die lebende Paritätsprüfung, hängt an einem Bedienelement „Tresor entsperren", das `EnrollmentPage.tsx` nach dem Abschluss zeigt. Es ruft KEINE sechste Ausfuhr aus `webauthn.rs` auf, sondern den Weg, den diese Crate schon hat: `webauthn-prf.ts` holt über ein zweites `navigator.credentials.get` mit der `prf`-Erweiterung eine frische PRF-Ausgabe, `blobGet` liest den versiegelten Tresor unter `READER_VAULT_BLOB_KEY_V1` aus OPFS, und `readerVaultUnlock` aus `crate::vault_bridge` öffnet ihn. Damit bleibt „genau fünf Ausfuhren und keine sechste" wahr, und die Parität misst genau das, was sie messen soll — dass der Tresor, den dieser Lauf gebaut hat, sich mit dem öffnet, was derselbe Authenticator ein zweites Mal liefert.

```ts
test.skip(({ browserName }) => browserName !== 'chromium')

const VIRTUAL = {
  protocol: 'ctap2',
  transport: 'internal',
  hasResidentKey: true,
  hasUserVerification: true,
  hasPrf: true,
  isUserVerified: true,
  automaticPresenceSimulation: true,
} as const

test('two authenticators are required, a wrong fingerprint aborts, and a real PRF output opens the vault this run built', async ({ page }) => {
  const cdp = await page.context().newCDPSession(page)
  await cdp.send('WebAuthn.enable')
  const first = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: VIRTUAL })
  const second = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: VIRTUAL })
  await stubEnrollmentEndpoints(page)

  await page.goto('/enrollment')
  await page.getByRole('button', { name: 'Authenticator registrieren' }).click()
  await expect(page.getByText('Ein zweiter Authenticator ist erforderlich.')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Enrollment abschließen' })).toBeDisabled()
  await page.getByRole('button', { name: 'Authenticator registrieren' }).click()
  await expect(page.getByText('2 von 2 Authenticators registriert.')).toBeVisible()

  const shownKey = await page.getByTestId('schluessel-fingerprint').innerText()
  await page.getByLabel('Erwarteter Schlüssel-Fingerprint').fill(shownKey)
  await page.getByLabel('Erwarteter Bundle-Fingerprint').fill('0'.repeat(64))
  await expect(page.getByRole('alert')).toContainText('EA-READER-ENROLLMENT-FINGERPRINT-MISMATCH')
  await expect(page.getByRole('button', { name: 'Enrollment abschließen' })).toBeDisabled()

  const shownBundle = await page.getByTestId('bundle-fingerprint').innerText()
  await page.getByLabel('Erwarteter Bundle-Fingerprint').fill(shownBundle)
  await page.getByRole('button', { name: 'Enrollment abschließen' }).click()
  await expect(page.getByText('Enrollment abgeschlossen.')).toBeVisible()

  // DIE LEBENDE PARITAET. Bis hierher ist der Tresor mit PRF-Ausgaben gebaut,
  // die der virtuelle Authenticator SELBST gezogen hat und die niemand kennt.
  // Jetzt wird derselbe Authenticator ein zweites Mal befragt, und der Tresor
  // muss sich mit dem oeffnen, was dabei herauskommt.
  await page.getByRole('button', { name: 'Tresor entsperren' }).click()
  await expect(page.getByText('Tresor entsperrt.')).toBeVisible()

  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: first.authenticatorId })
  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: second.authenticatorId })
})
```

**W22, ausgeschrieben: was dieser Lauf beweist und was er NICHT beweist — und warum die Vorfassung dieses Tasks es nicht beweisen konnte.** Die Vorfassung stellte `ea_reader::enrollment::fixture_prf_output` gegen `fixtures::recorded_prf_output` und nannte das den wichtigsten Zeugen der Aufgabe. Beide Seiten wären im selben Commit geschrieben worden, und NICHTS in dieser Aufgabe zeichnet je eine echte PRF-Ausgabe auf; der Zeuge hätte sich selbst gemessen — genau das Versagen, vor dem der Absatz darüber warnte. Aufzeichnen ginge auch gar nicht: `WebAuthn.VirtualAuthenticatorOptions` kennt `hasPrf`, `hasHmacSecret` und `hasHmacSecretMc`, aber KEIN Feld für den CredRandom des Authenticators. Der wird beim Anlegen des Credentials in Chromium gezogen, ist über CDP weder setzbar noch auslesbar, und eine „aufgezeichnete" PRF-Ausgabe wäre in keinem zweiten Lauf reproduzierbar. Ein eingefrorener Byteweg dafür ist ausserdem ausgeschlossen: Stufe 4 friert KEINE Vektorfamilie ein, `vectors/…` wird ausschliesslich gelesen. `fixture_prf_output` und `recorded_prf_output` entfallen deshalb ersatzlos — ein Funktionsname, der eine Aufzeichnung behauptet, die es nicht gibt, ist schlimmer als keine Funktion.

An ihre Stelle tritt die LEBENDE Paritätsprüfung oben, und ihre Aussage ist präzise: gemessen wird die volle Kette aus echter WebAuthn-`prf`-Erweiterung, echten 32 Byte aus dem Authenticator, `derive_kek_v1`, `VaultEnvelopeV1::wrap`, `SealedVaultV1::to_deterministic_cbor`, OPFS und `ReaderVault::unlock`. NICHT gemessen wird irgendein Byte-WERT: welche 32 Byte der Authenticator liefert, weiss der Test nicht und darf er nicht wissen. Daraus folgt die zweite Ehrlichkeit, und sie betrifft alle Folgeaufgaben: `fixtures::prf_output(index)` mit seinen Werten `[0xa1; 32]` und `[0xb2; 32]` ist ein FREI GEWÄHLTER Stellvertreter und kein gemessener. Seine einzige tragende Eigenschaft ist, dass er 32 Byte lang und innerhalb eines Laufs stabil ist. Die Sicherheitsaussage von §6.2 hängt nicht an ihm, sondern an der Ableitung, und die misst `the_prf_output_never_wraps_the_vault_and_each_authenticator_opens_it_alone` in `crates/ea-reader/tests/vault_envelope.rs` bereits DIREKT gegen `Hkdf::<Sha256>::new(None, prf).expand(VAULT_KEK_INFO_V1, …)`. Jede Aufgabe dieses Plans, die auf `fixtures::unlocked_vault()` steht, steht also auf einer geprüften ABLEITUNG und einem beliebigen EINGABEWERT — und das ist genug, solange es dasteht und nicht zu „gemessen" umgeschrieben wird.

Zwei weitere Grenzen dieses Laufs, benannt statt geglättet. **Erstens:** zwei virtuelle Authenticators belegen nicht ihre UNABHÄNGIGKEIT. CDP bietet keinen Weg, einen bestimmten Authenticator für einen `create`-Aufruf zu erzwingen; beide Credentials könnten auf demselben virtuellen Gerät entstehen. Gemessen ist damit der KARDINALITÄTSPFAD — zwei verschiedene `credentialId`s, zwei Envelopes, `finish` erst danach —, nicht die physische Unabhängigkeit, die §6.3 meint. **Zweitens:** liefert Chromiums virtueller Authenticator wider Erwarten keine PRF-Ausgabe, MUSS der Lauf laut fallen. `apps/web/src/vault/webauthn-prf.ts` prüft deshalb die Länge der Ausgabe und wirft; ein Rückfall auf einen erzeugten Puffer ist AUSGESCHLOSSEN, weil er den Test grün färbte, ohne die Kette gemessen zu haben.

- [x] **Step 3: Run the witnesses and confirm no enrollment surface exists**

Run, als ZWEI Kommandos und nicht als `&&`-Kette:

```bash
cargo test --locked -p ea-reader --test enrollment_two_authenticators --test fingerprint_gate
pnpm --dir apps/web test --run src/features/enrollment
```

Die Trennung ist keine Formsache. Das cargo-Kommando fällt beim ÜBERSETZEN, weil `crates/ea-reader/src/enrollment.rs` noch nicht existiert; eine `&&`-Kette kürzte danach ab und der vitest-Lauf, dessen roter Punkt dieser Schritt zeigen soll, liefe nie. Beide Kommandos tragen `--locked` beziehungsweise brauchen keins, und das ist hier richtig: die Kante auf `ea-sync-protocol` ist noch nicht eingetragen, `Cargo.lock` steht also unverändert. Das GENAU EINE Kommando dieses Tasks ohne `--locked` steht am Ende von Schritt 4.

Expected: FAIL, und zwar zweimal getrennt sichtbar. Auf der Rust-Seite fehlen `ReaderEnrollment`, `EnrollmentFingerprintsV1`, `FingerprintConfirmationV1`, `DeviceTrustStateV1`, `InMemoryEnrollmentEndpoints`, `EnrollmentCallV1`, `EnrollmentEndpointError` und `recover_and_unlock_vault`, und der `include_str!("../src/enrollment.rs")` des Konstruktions-Zeugen bricht bereits beim Übersetzen ab — das ist der beabsichtigte erste rote Punkt und keine Panne, denn ein Zeuge, der eine Abwesenheit über eine Datei behauptet, muss an der fehlenden Datei scheitern und nicht still bestehen. Auf der Webseite fehlen alle drei Komponenten; `pnpm --dir apps/web test` selbst LÄUFT, weil das Paket, sein Vitest-Runner, `src/bridge/generated-contracts.ts` und — nach Schritt 1 — `src/bridge/pkg/` vorhanden sind. Ein Paketmanagerabbruch oder ein Fehlschlag in `wasm-runtime.test.ts` wäre hier kein roter Test, sondern eine falsche Reihenfolge.

- [x] **Step 4: Implement browser key generation, two mandatory authenticators, the endpoint port, and the fingerprint gate**

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

/// Die Gültigkeitsspanne der drei signierten Anfragen, in Sekunden.
///
/// Sie liegt UNTER `ea_sync_protocol::MAX_SIGNATURE_WINDOW_SECONDS_V1` (300)
/// und wird nicht daraus abgeleitet: der Server nennt seine Obergrenze, der
/// Klient wählt darunter.
pub const ENROLLMENT_SIGNATURE_WINDOW_SECONDS_V1: i64 = 60;

/// Der Schlüssel, unter dem der versiegelte Tresor lokal liegt.
pub const READER_VAULT_BLOB_KEY_V1: &str = "vault/reader-vault-v1";

/// Das Transportprofil eines Credentials, so wie der Browser es meldet.
///
/// ZWEI Werte und nicht die volle `AuthenticatorTransport`-Liste: die einzige
/// Unterscheidung, die diese Aufgabe trifft, ist „Cross-Device-Flow oder
/// nicht". Eine getreue Nachbildung der Browserliste legte vier weitere Werte
/// an, über die niemand entscheidet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatorTransportProfileV1 {
    /// `internal`, `usb`, `nfc`, `ble` — ein Authenticator an diesem Gerät.
    ClientDevice,
    /// `hybrid`/`cable` — der QR-Flow, in Safari ohne PRF-Ausgabe (§6.4.1).
    CrossDevice,
}

#[derive(Debug)]
pub enum EnrollmentError {
    SingleAuthenticator,
    /// Dieses Gerät trägt bereits einen versiegelten Reader-Tresor.
    VaultAlreadyOnDevice,
    DuplicateAuthenticator,
    CredentialIdLength,
    TransportRefused,
    FingerprintEncoding,
    FingerprintMismatch,
    NoVaultForCredential,
    Endpoint(EnrollmentEndpointError),
    Blob(ReaderBlobError),
    Vault(ReaderVaultError),
    Crypto(CryptoError),
    Protocol(SyncProtocolError),
}

impl EnrollmentError {
    /// Der stabile Code des Fehlschlags — dieselbe Regel wie bei
    /// [`ReaderVaultError::code`]: Zusicherungen stehen gegen ihn und nie gegen
    /// eine Formatierung. Die eigenen Varianten tragen ihren Code
    /// ausgeschrieben — `EA-READER-ENROLLMENT-SINGLE-AUTHENTICATOR`,
    /// `-DUPLICATE-AUTHENTICATOR`, `-CREDENTIAL-ID-LENGTH`,
    /// `-TRANSPORT-REFUSED`, `-FINGERPRINT-ENCODING`, `-FINGERPRINT-MISMATCH`
    /// und `-NO-VAULT` —, die fünf durchreichenden Varianten geben den Code
    /// ihrer Quelle DURCH und erfinden keinen zweiten Namen für einen fremden
    /// Befund.
    #[must_use]
    pub const fn code(&self) -> &'static str;
}

pub struct ReaderEnrollment { /* private */ }

impl ReaderEnrollment {
    /// # Errors
    /// `EA-LOCAL-CRYPTO-RNG` über [`EnrollmentError::Vault`], wenn der Wirt
    /// keine Entropie liefert, und `EA-CRYPTO-INVALID-PUBLIC-KEY` über
    /// [`EnrollmentError::Crypto`], wenn der gezogene KEM-Punkt keinen
    /// Thumbprint hergibt — der wird HIER einmal gerechnet und festgehalten,
    /// nicht bei jedem `fingerprints`.
    /// Der Bytespeicher steht VORNE, weil die Weigerung vor jeder
    /// Schlüsselerzeugung fällt: `EA-READER-ENROLLMENT-VAULT-PRESENT`, wenn
    /// unter `READER_VAULT_BLOB_KEY_V1` lokal schon ein Tresor liegt.
    pub fn begin(
        store: &dyn ReaderBlobStore,
        organization_id: OrganizationId,
        subject_id: SubjectId,
        pinned_anchor: TrustAnchorV1,
        bundle_fingerprint: Hash32,
    ) -> Result<Self, EnrollmentError>;

    pub fn register_authenticator(&mut self, attested: AttestedAuthenticatorV1)
        -> Result<&AuthenticatorRecordV1, EnrollmentError>;

    #[must_use]
    pub fn registered_authenticator_count(&self) -> usize;

    /// Gibt den in `begin` GERECHNETEN Thumbprint und den dort übergebenen
    /// `Hash32` heraus und rechnet selbst nichts — deshalb `-> …V1` und kein
    /// `Result`.
    #[must_use]
    pub fn fingerprints(&self) -> EnrollmentFingerprintsV1;

    pub fn confirm_fingerprints(&self, expected_key: &str, expected_bundle: &str)
        -> Result<FingerprintConfirmationV1, EnrollmentError>;

    pub fn finish(
        self,
        confirmation: FingerprintConfirmationV1,
        context: EnrollmentRequestContextV1,
        endpoints: &mut dyn EnrollmentEndpoints,
        store: &mut dyn ReaderBlobStore,
    ) -> Result<EnrolledReaderV1, EnrollmentError>;

    /// # Errors
    /// Die durchgereichten Codes des Bytespeichers.
    pub fn device_state(store: &dyn ReaderBlobStore)
        -> Result<DeviceTrustStateV1, EnrollmentError>;

    #[must_use]
    pub const fn fingerprint_gate_required(state: &DeviceTrustStateV1) -> bool;
}

/// Holt den versiegelten Tresor auf einem Gerät OHNE lokalen Vault zurück und
/// öffnet ihn mit dem vorgelegten Authenticator.
///
/// Der Name sagt beides, weil die Funktion beides tut: sie schickt den EINEN
/// signaturfreien Abruf über den Port und gibt einen [`UnlockedVault`] heraus.
///
/// # Errors
/// `EA-READER-ENROLLMENT-NO-VAULT`, wenn KEINES der zurückgegebenen Chiffrate
/// einen Envelope für diesen Authenticator trägt; daneben die durchgereichten
/// Codes des Ports und des Tresors.
pub fn recover_and_unlock_vault(
    request: &VaultBlobRetrievalRequestV1,
    authenticator: &AuthenticatorPrfV1,
    endpoints: &mut dyn EnrollmentEndpoints,
) -> Result<UnlockedVault, EnrollmentError>;

pub struct EnrollmentFingerprintsV1 {
    key_fingerprint: KeyThumbprint,
    bundle_fingerprint: Hash32,
}

impl EnrollmentFingerprintsV1 {
    #[must_use] pub const fn key_fingerprint(&self) -> KeyThumbprint;
    #[must_use] pub const fn bundle_fingerprint(&self) -> Hash32;
    #[must_use] pub fn key_fingerprint_hex(&self) -> String;
    #[must_use] pub fn bundle_fingerprint_hex(&self) -> String;
}

/// Konstruierbar AUSSCHLIESSLICH in `confirm_fingerprints`, und dort nur nach
/// einem konstantzeitigen Vergleich BEIDER Werte. Kein `Default`, kein `Clone`,
/// kein `Debug`, und ausdrücklich kein inhärenter `impl`-Block.
pub struct FingerprintConfirmationV1 {
    confirmed_key: KeyThumbprint,
    confirmed_bundle: Hash32,
}
```

**W11 entschieden: die ANGEZEIGTEN Werte sind typisiert, die ERWARTETEN sind Zeichenketten.** `EnrollmentFingerprintsV1` behält `KeyThumbprint` und `Hash32` als Felder — beide sind `Copy` und beide bieten `as_bytes() -> &[u8; 32]` —, und daneben stehen zwei Hex-Zugriffe, die eine `String` bauen. `confirm_fingerprints` nimmt zwei `&str`, weil sein Argument aus einer TASTATUR kommt und nicht aus dem Programm: die Referenz ist unabhängig verteilt, ein Mensch tippt sie ab. Die Asymmetrie ist die Aussage, keine Unsauberkeit. Sie ist ausserdem die einzige Form, die überhaupt übersetzt: `KeyThumbprint` und `Hash32` haben kein `Display`, kein `Debug` und kein `to_hex`, ein `&str`-Zugriff auf ein typisiertes Feld verlangte also ein `String`-Feld daneben — zwei Quellen derselben Wahrheit. `hex` ist bereits reguläre Abhängigkeit von `ea-reader` und braucht keine Manifestzeile.

**W10 entschieden: `FingerprintConfirmationV1` ist eine geklammerte Struktur OHNE inhärenten `impl`-Block, und der Anti-Konstruktions-Zeuge rechnet ausgeschrieben.** Der Grund ist textlicher Natur und deshalb erklärungsbedürftig. In Rust teilt jede Konstruktion den Präfix mit ihrer Deklaration, und `impl FingerprintConfirmationV1 {` teilt ihn ebenfalls; die Vorfassung suchte `"FingerprintConfirmationV1 {"` und verlangte GENAU EINS, was schon die Deklaration allein erfüllt und die Konstruktion daneben unmöglich macht — der Zeuge wäre in jeder korrekten Implementierung rot gewesen. Die gewählte Form macht die Zahl nachrechenbar statt magisch: eine Deklaration (`pub struct …`), ein Strukturausdruck in `confirm_fingerprints`, zusammen zwei, und NULL `impl`-Köpfe. Der dritte Zähler trägt die eigentliche Last: ohne inhärenten `impl`-Block kann niemand eine zweite Konstruktionsstelle hinter `FingerprintConfirmationV1::new` verstecken, und `Default` und `Clone` bleiben ebenfalls draussen. Der Doc-Kommentar über dem Typ schreibt aus demselben Grund „kein `Default`" und NICHT „`Default for FingerprintConfirmationV1`": der Zeuge liest Text und unterschiede eine Erklärung nicht von einer Implementierung — dieselbe Falle, die `crates/ea-reader-wasm/src/lib.rs` für sein `#[cfg(target_arch = "wasm32")]` im Fliesstext bereits ausgeschrieben hat.

**W12 entschieden: `EnrollmentError::AnchorUnpinned` entfällt, der Anchor bleibt ein nicht-optionaler Parameter.** Die Vorfassung nahm `pinned_anchor: TrustAnchorV1` besitzend und ohne `Option` und behauptete daneben, `begin` gebe „ohne ihn `AnchorUnpinned` zurück" — die Variante war aus der eigenen Signatur unerreichbar. Aufgelöst wird zugunsten des Typs: ein Enrollment ohne gepinnten Anker ist nach §5.3 nicht ein Fehlerfall, sondern ein Zustand, den es nicht geben darf, und ein nicht darstellbarer Zustand ist stärker als eine Laufzeitweigerung — dieselbe Entscheidung wie beim Fingerprint-Gate zwei Absätze weiter oben. Die Variante wird deshalb ersatzlos gestrichen, und `the_confirmation_has_no_construction_path_outside_a_match` deckt sie mit `assert!(!source.contains("AnchorUnpinned"))` ab: ein Wiederauftauchen färbt rot. Nicht verwechseln mit `DeviceTrustStateV1::NoPinnedAnchor` — das beschreibt ein GERÄT, dessen Bytespeicher noch keinen Tresor trägt, und ist die Bedingung des §4.3-Gates. Zwei verschiedene Sachen dürfen nicht denselben Namen tragen; die überflüssige der beiden geht.

**W13 entschieden: ein handgeschriebener byteweiser Vergleich in `ea-reader`, KEIN `subtle`.** Im ganzen Arbeitsbereich gibt es heute keine konstantzeitige Vergleichsfunktion — `SecretBytes::matches` ist ein gewöhnliches `==`, und `subtle` steht nur transitiv im `Cargo.lock`. Drei Gründe entscheiden gegen die Crate. Erstens die Sache selbst: verglichen werden zwei ÖFFENTLICHE 32-Byte-Fingerabdrücke, kein Schlüsselmaterial; die Konstantzeitigkeit schützt hier nicht ein Geheimnis, sondern verhindert ein Orakel, das einem Angreifer verriete, wie viele führende Stellen seiner untergeschobenen Referenz schon stimmen. Zweitens die Kosten: `subtle` in `[workspace.dependencies]` wäre eine NEUE Abhängigkeitsklasse und verlangte in `docs/adr/0005-browser-runtime-and-wasm-dependency-class.md` einen eigenen Abschnitt samt Pin und Begründung — nicht dasselbe wie die eine Merkmalszeile, um die dieselbe Datei in dieser Aufgabe für `web-sys` ohnehin wächst. Ein Merkmal an einer schon ratifizierten Crate ist eine Fortschreibung; eine zusätzliche Crate ist eine Entscheidung über die Angriffsfläche des Browserbündels, und die gehört nicht als Nebenwirkung in eine Enrollment-Aufgabe. Drittens die Lage: `ea-reader` steht auf der wasm32-Positivliste, und jede zusätzliche Crate ist zusätzliche wasm32-Fläche. Die Funktion heisst `fingerprints_match(expected: &[u8; 32], shown: &[u8; 32]) -> bool`, verodert die XOR-Differenz über ALLE 32 Byte und vergleicht den Akkumulator erst danach mit null, mit `core::hint::black_box` auf dem Akkumulator gegen ein Kurzschliessen des Optimierers. **Und die GRENZE dazu, benannt statt geglättet: das ist eine QUELLTEXTAUSSAGE über Konstantzeitigkeit und keine gemessene.** Weder `cargo test` noch `cargo clippy` prüfen die erzeugten Instruktionen, `black_box` ist ausdrücklich keine Garantie des Compilers, und die vorgeschaltete `hex::decode` der Eingabe ist ohnehin nicht konstantzeitig. Was hier steht, ist der Verzicht auf einen frühen Ausstieg im Vergleich selbst — nicht mehr, und der Plan behauptet nicht mehr.

Die Schlüsselerzeugung läuft im Browser und die privaten Schlüssel verlassen ihn nie (§6.6 Schritt 1). `begin` zieht 64 Byte Entropie über `getrandom::fill` — im Browser `globalThis.crypto.getRandomValues` über das Feature `wasm_js`, ausführbar nachgewiesen in `spikes/wasm-runtime-proof/spike.sh` — und baut daraus den X25519-KEM-Schlüssel über `HpkeRecipientPrivateKey::from_bytes` und den Ed25519-Geräte- und Auditschlüssel. Beide liegen als `SecretBytes<32>` und damit unter `ZeroizeOnDrop`.

**Und genau daraus folgt eine Stelle, die nicht übersehen werden darf: `SecretBytes` hat KEIN `Clone`, und beide Schlüssel haben ZWEI Abnehmer.** `HpkeRecipientPrivateKey::from_bytes(bytes: SecretBytes<32>)`, `RequestSigner::from_secret(secret: SecretBytes<32>)` und `VaultContentsV1::new(kem_private_key: SecretBytes<32>, audit_private_key: SecretBytes<32>, …)` nehmen alle drei BESITZEND, und `HpkeRecipientPrivateKey` gibt nichts zurück ausser `public_key()`. Der KEM-Schlüssel wird deshalb in `begin` genau EINMAL für den Thumbprint benutzt — `CanonicalPublicCoseKey::x25519(*private.public_key().as_bytes())?.thumbprint()`, das Ergebnis wird als `KeyThumbprint` festgehalten —, und die 32 Byte selbst wandern über `SecretBytes::with_exposed(|bytes| SecretBytes::new(*bytes))` in die Kopie, die `finish` später an `VaultContentsV1::new` gibt. Der Ed25519-Schlüssel geht denselben Weg: eine Kopie an `RequestSigner::from_secret`, das Original an `VaultContentsV1::new`. `with_exposed` ist der einzige Weg an die Bytes, den die Crate anbietet, und er hält den Zeroize-Vertrag: die Kopie ist selbst wieder ein `SecretBytes` und löscht sich beim Fallen. Ohne diesen Schritt sind es zwei `E0382` — und `typecheck` findet sie nicht, weil sie in Rust liegen.

Der gepinnte Root-Anchor kommt als PARAMETER und niemals aus einer Serverantwort; die Brücke reicht ihn über `decode_trust_anchor` herein, und das ist der ganze Punkt: der Anker gilt nicht, weil er im Tresor lag, sondern weil `decode_trust_anchor` seinen Bootstrap-Hash beim Dekodieren NEU rechnet — die Begründung steht wörtlich im Abhängigkeitskommentar von `crates/ea-reader/Cargo.toml`. Der Bundle-Fingerprint kommt aus demselben Grund als PARAMETER: `ea-reader` hat keinen Weg, das geladene Bündel zu lesen, und die Brücke bekommt den Hash aus dem Bauartefakt des Tasks „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate".

`register_authenticator` nimmt eine `AttestedAuthenticatorV1`, die `AttestedAuthenticatorV1::new` aus vier Bestandteilen baut — `credential_id: Vec<u8>`, `credential_public_cose_key: Vec<u8>`, `transport_profile: AuthenticatorTransportProfileV1` und `prf_output: SecretBytes<32>`. Weil dieser vierte Bestandteil ein `SecretBytes` ist, tragen weder `AttestedAuthenticatorV1` noch der daraus entstehende `AuthenticatorRecordV1` ein `Debug` oder ein `Clone`; die Regel ist dieselbe, die `AuthenticatorPrfV1` in `crates/ea-reader/src/envelope.rs` in seinem eigenen Doc-Kommentar schon ausschreibt, und sie ist der Grund für die `.err().expect(…)`-Schreibweise der Zeugen. `EnrolledReaderV1` bekommt aus demselben Grund ebenfalls kein `Debug` — nicht weil es ein Geheimnis trüge, sondern weil kein Zeuge eines braucht und ein abgeleitetes `Debug` auf einem Tresortyp eine Einladung ist. Vier Prüfungen laufen hier und nirgends sonst: die `credentialId` muss zwischen `MIN_WEBAUTHN_CREDENTIAL_ID_BYTES_V1` und `MAX_WEBAUTHN_CREDENTIAL_ID_BYTES_V1` liegen, sonst `CredentialIdLength`; der öffentliche Schlüssel muss `CanonicalPublicCoseKey::from_deterministic_cbor` als `Ed25519`-Arm überstehen — dieselbe Prüfung, die `WebauthnCredentialRegistrationV1::new` beim Bauen der Anfrage ein zweites Mal fährt, weshalb ein hier akzeptierter Schlüssel dort nie scheitert; eine bereits registrierte `credentialId` ist `DuplicateAuthenticator`, weil zwei Envelopes desselben Authenticators die Zwei-aus-§6.3 vortäuschten, ohne sie zu erfüllen; und `AuthenticatorTransportProfileV1::CrossDevice` ist `TransportRefused`. Der Envelope entsteht NICHT hier, sondern erst in `finish` über `ReaderVault::seal`, das seinen Tresorschlüssel selbst zieht, je Authenticator einmal `derive_kek_v1` ruft und `VaultEnvelopeV1::wrap(kek, vault_key, nonce, credential_id)` mit allen VIER Argumenten aufruft — das vierte ist das zusätzliche authentifizierte Datum und macht ein Envelope auf einen fremden Authenticator unumhängbar. Die PRF-Ausgabe ist NIE selbst der Wrapping-Schlüssel; die Begründung steht in §6.2 und ist betrieblich: mit direkter Verwendung machte das Löschen eines Passkeys die Daten dauerhaft unerreichbar, weil jeder Authenticator dann sein EIGENES Chiffrat trüge statt eines Umschlags um denselben Vault-Key.

**Die FÜNFTE Absicherung liegt NICHT in `register_authenticator`, und sie kann dort auch nicht liegen: `excludeCredentials`.** Die vier Prüfungen oben laufen sämtlich NACH der Zeremonie, und keine von ihnen sieht GERÄTEIDENTITÄT: `AttestedAuthenticatorV1` trägt weder AAGUID noch ein anderes gerätunterscheidendes Feld, und die Doppelungsprüfung de-dupliziert auf der `credentialId`. Genau daran scheitert sie in dem Fall, um den es §6.3 überhaupt geht. Beide Zeremonien tragen dieselbe `rp.id` und dasselbe `user.id`, und ein `authenticatorMakeCredential` mit `rk=true` auf ein bereits vorhandenes Paar (rpId, userHandle) ERSETZT nach CTAP 2.1 das auffindbare Credential — der Ersatz bekommt eine FRISCHE Kennung, kommt hier also als vollwertiger zweiter Authenticator an und wird aufgenommen. `hints: ['client-device']` steuert dabei geradewegs auf das eine Gerät, auf dem das passiert: Touch ID, Windows Hello, ein einzelner Resident-Key-Stick. Das Ergebnis wäre der natürliche Ablauf „zweimal auf `Authenticator registrieren` klicken", zwei versiegelte und hochgeladene Envelopes, ein Bildschirm, der „2 von 2 Authenticators registriert." meldet — und GENAU EIN Envelope, der noch aufgeht, weil das CredRandom des ersten mit dem ersetzten Credential gestorben ist. §6.3 ist ein MUSS und eine harte Weigerung, keine Warnung; ohne diese fünfte Absicherung wäre sie gezählt und nicht durchgesetzt, und der Betreiber verlöre den Tresor mit dem einen Gerät, dessen Verlust §6.3 gerade abfangen soll. **Die mildere Hälfte desselben Befunds gehört dazu:** ein Passkey-Verwalter, der statt still zu ersetzen NACHFRAGT, richtet keinen Schaden an — beide Envelopes lägen aber trotzdem auf EINEM Gerät, und die Unabhängigkeit wäre genauso verletzt.

Durchsetzen kann das nur der BROWSER, und zwar VOR der Zeremonie. `ReaderEnrollment::registered_credential_ids` gibt die bisher aufgenommenen Kennungen heraus; die Brücke reicht sie als `registeredCredentialIds` in den Status-DTOs von `enrollmentBegin` UND `enrollmentRegisterAuthenticator` mit, hexadezimal wie `prfSalt`. Eine SECHSTE Ausfuhr entsteht dafür NICHT: beide kennen den aktuellen Satz ohnehin — `begin` legt ihn an, `registerAuthenticator` ist die einzige Stelle, an der er wächst —, und die Fünf ist oben als Grenze begründet. `webauthn-prf.ts` setzt die Liste unverändert als `excludeCredentials` in `navigator.credentials.create` und FÜHRT sie nicht: es ergänzt insbesondere nicht die Kennung, die eine gerade gelaufene Zeremonie geliefert hat, und hält keinen `useState` in der Oberfläche. §9 lässt in TypeScript keine Sicherheitsentscheidung zu, und eine dort geführte Liste könnte leer sein, wo Rust zwei Einträge hält — der Ausschluss fiele still aus. Die Deskriptoren tragen KEIN `transports`: ohne das Feld berücksichtigt der Client jeden Transport, der Ausschluss ist also der weitere von beiden, und Rust gibt gar kein Transportprofil heraus, weil `AuthenticatorRecordV1` es bei der Aufnahme bewusst fallen lässt. Ein hier gesetzter Wert wäre geraten.

**Und die Messung dazu, weil dieser Absatz sonst eine Behauptung wäre.** Auf Chromiums virtuellem Authenticator — GENAU EINEM, `internal`, `ctap2`, `hasPrf`, `hasResidentKey` —, gezählt über `WebAuthn.getCredentials`: ohne `excludeCredentials` legt die zweite Zeremonie klaglos ein Credential mit NEUER Kennung an, und danach liegt auf dem Gerät GENAU EINES; der erste Passkey ist fort. Mit `excludeCredentials` fällt sie mit `InvalidStateError`, und es bleibt bei dem ersten. Beide Schreibweisen des Deskriptors weisen ab, mit und ohne `transports`. Chromiums virtueller Authenticator honoriert den Ausschluss also, und ein Zeuge darauf misst etwas. Nebenbefund derselben Messung: `getPublicKeyAlgorithm()` des erzeugten Credentials ist `-8`, die oben als RISIKOLAGE benannte Ed25519-Frage ist damit für Chromium beantwortet.

**Eine Folge für den ERSTEN Browserzeugen, die keine Kosmetik ist und deshalb hier steht.** `CTAP2_ERR_CREDENTIAL_EXCLUDED` ist im WebAuthn-Algorithmus TERMINAL: antwortet ein Authenticator damit, bricht der Client die ganze Zeremonie mit `InvalidStateError` ab, statt die übrigen weiterzufragen. Vor einem ECHTEN Gerätepaar stellt sich die Lage nicht, weil die Auswahl dort beim Menschen liegt — er berührt genau EINES, und nur das antwortet. `automaticPresenceSimulation: true` lässt dagegen BEIDE virtuellen Geräte sofort antworten, und der ausgeschlossene gewinnt das Rennen; gemessen für `internal`+`usb`, `usb`+`nfc` und `usb`+`internal` enden alle drei Reihen auf `InvalidStateError`. Der erste Zeuge legt deshalb für die zweite Zeremonie das Gerät still, auf dem die erste gelandet ist (`WebAuthn.setAutomaticPresenceSimulation`, danach wieder an, weil die lebende Parität beide braucht), und er FRAGT über `WebAuthn.getCredentials`, welches das ist, statt es anzunehmen: gemessen bevorzugt Chromium in allen drei Reihen den abnehmbaren Authenticator, das erste Credential liegt also auf dem ZWEITEN angelegten. Ein Zielgerät für `create` bietet CDP nicht an — dieselbe Grenze, die der Absatz „Was der Browserlauf beweist" unten ohnehin nennt. Das ist keine Glättung: was stillgelegt wird, ist die Simulation einer Berührung, und genau die trifft am echten Gerät der Mensch.

**Das Bedienelement der Registrierung ist während einer laufenden Zeremonie GESPERRT.** Der Spiegel der aufgenommenen Kennungen in `webauthn-prf.ts` wird erst aus der ANTWORT von `enrollmentRegisterAuthenticator` gestellt — richtig so, denn eine vorab ergänzte Kennung schlösse ein Gerät aus, das dieses Enrollment gar nicht hält. Solange die Antwort aussteht, ist der Satz aber der alte, und ein zweiter Anlauf ginge mit einem zu kurzen `excludeCredentials` los. Chromiums Regel „höchstens eine ausstehende `credentials.create`-Anfrage" schliesst das in der Praxis, aber dieser Schutz gehört dem BROWSER und nicht dieser Anwendung; `EnrollmentPage.tsx` führt deshalb einen eigenen Zustand, gibt ihn als `busy` an `AuthenticatorRegistration` und prüft ihn ZUSÄTZLICH im Aufrufzweig — ein gesperrter Knopf ist die Höflichkeit, der Zweig ist die Bedingung. Der Zeuge ist `locks the registration control while a ceremony is in flight` in `apps/web/src/features/enrollment/EnrollmentPage.test.tsx`; daneben hält `says in German that this device already carries a vault instead of showing the bare code` fest, dass die Fläche den Code aus `begin` übersetzt statt ihn blank zu zeigen.

**Das Tor in `begin`: `excludeCredentials` schliesst die Lücke INNERHALB eines Enrollments und nicht über seine Lebensdauer hinaus.** Der Ausschlusssatz speist sich aus dem Zustand EINES laufenden `ReaderEnrollment`, und `ReaderEnrollment::begin` fängt mit einem leeren Vektor an. `/enrollment` ist aber eine gewöhnliche, anfahrbare Route, die Fläche ruft `begin` bei JEDER Montage, und `user.id` ist stets dieselbe pseudonyme `subjectId` aus dem Freigabekontext. Ein ZWEITER Besuch nach einem abgeschlossenen Enrollment schickte also wieder `excludeCredentials: []` — und ein einziger Klick auf „Authenticator registrieren" ersetzte auf demselben Plattform-Authenticator den Passkey des bereits versiegelten UND hochgeladenen Tresors. Das ist derselbe Defekt wie oben, gegen einen LEBENDEN Tresor statt gegen einen halb gebauten, und damit strikt schlimmer. **`ReaderEnrollment::begin` weigert sich deshalb FAIL-CLOSED auf einem Gerät, das schon einen versiegelten Tresor trägt.** Der Zustand kommt über `DeviceTrustStateV1` und `ReaderEnrollment::device_state`, also über genau denselben Weg, den das Fingerprint-Gate aus §4.3 ohnehin nimmt; eine zweite Lesart desselben Bytespeichers entsteht nicht. Der Bytespeicher tritt als ERSTER Parameter ein, weil die Weigerung VOR jeder Schlüsselerzeugung fällt: ein abgewiesener Anlauf zieht keine Entropie, schreibt nichts und erreicht keinen Endpunkt. Der Code ist `EA-READER-ENROLLMENT-VAULT-PRESENT`, in der Hausform und mit einer eigenen Variante `EnrollmentError::VaultAlreadyOnDevice`.

**Das ist keine Verengung des Umfangs, sondern die Grenze, die dieser Task ohnehin gezogen hat.** §6.4 beantwortet ein Gerät MIT Tresor nicht mit einem zweiten Enrollment, sondern mit `recover_and_unlock_vault`; das Wieder-Enrollment und der historische Re-grant stehen ausdrücklich ausserhalb dieses Tasks. Was bisher als Annahme galt („auf `/enrollment` kommt nur, wer noch keinen Tresor hat"), ist damit durchgesetzt statt vorausgesetzt. Der Wirtszeuge ist `begin_refuses_on_a_device_that_already_carries_a_sealed_vault` in `crates/ea-reader/tests/enrollment_two_authenticators.rs`: er zeigt zuerst, dass `begin` auf einem LEEREN Speicher gelingt — sonst mässe die Weigerung nur eine Funktion, die immer fällt —, führt dann ein vollständiges Enrollment durch, weist den zweiten Anlauf unter dem neuen Code ab und assertiert BEIDES, den unveränderten Schlüsselsatz UND die byteweise unveränderten Tresorbytes; ohne den letzten Punkt bliebe er grün, wenn `begin` den vorhandenen Tresor überschriebe und erst danach abbräche. Auf der Brücke wird `enrollmentBegin` dadurch ASYNCHRON — es trägt jetzt denselben OPFS-Vorlauf auf `READER_VAULT_BLOB_KEY_V1` wie `enrollmentFinish` —, und `apps/web/src/bridge/opfs-worker.ts` `await`et es. Die Fläche übersetzt den Code in einen deutschen Satz statt ihn blank zu zeigen: `EnrollmentPage.tsx` führt dafür GENAU EINEN Anschriftschlüssel, jeder andere Fehlschlag bleibt der unveränderte Text. Beide Browserzeugen bleiben unberührt, weil Playwright je Test einen frischen Kontext und damit ein leeres OPFS gibt — der erste Zeuge baut seinen Tresor NACH `begin` und entsperrt ihn im selben Lauf.

**Und die GRENZE, die `excludeCredentials` auch mit diesem Tor behält — als Klasse benannt, nicht als Einzelfall.** Der Ausschluss wird JE AUTHENTICATOR durchgesetzt: der Client legt die Liste jedem befragten Authenticator vor, und der antwortet mit `CTAP2_ERR_CREDENTIAL_EXCLUDED`, wenn er eine der Kennungen SELBST hält. Über zwei getrennte Credential-Speicher auf EINEM physischen Rechner sagt das nichts, und das ist der ganze Punkt: die Passkeys eines Chrome-Profils, die von Firefox, die einer Safari-/iCloud-Schlüsselbundkette und ein Sicherheitsschlüssel, der den Steckplatz nie verlässt, sind wechselseitig unsichtbar. Beide Zeremonien gelingen klaglos, beide Envelopes landen auf demselben Gerät, und geht dieses Gerät verloren, ist der Tresor verloren — genau der Ausgang, den §6.3 abwenden soll. Die mildere Ausprägung derselben Klasse ist die oben schon genannte: ein Passkey-Verwalter, der statt still zu ersetzen NACHFRAGT, richtet keinen Schaden an, und beide Envelopes liegen trotzdem auf einem Gerät. **Was `excludeCredentials` verhindert, ist die ZERSTÖRUNG des ersten Passkeys; was es nicht verhindert, ist die KONZENTRATION beider Envelopes auf einer Maschine.** Diese Klasse ist mit diesem Task NICHT geschlossen und wird hier weder geglättet noch als erledigt behauptet; die physische Unabhängigkeit aus §6.3 bleibt in Stufe 4 organisatorisch getragen und nicht technisch erzwungen.

**OFFENER PUNKT für eine spätere Stufe — der Hebel, den bis heute niemand gezogen hat: BE/BS.** Die Aussage „`ea-reader` kann gar nicht sehen, dass beide Envelopes auf demselben Gerät liegen" war zu stark und ist auf „sieht es HEUTE nicht" korrigiert, in `crates/ea-reader/src/enrollment.rs` und hier. Richtig bleibt, dass das AAGUID unter `attestation: "none"` nicht zu haben ist — der Client nullt es. Die Flagbits in `authData` überleben das dagegen, und darunter stehen BE (Backup Eligibility) und BS (Backup State); ein synchronisierter Passkey trägt BE gesetzt. `attested_credential` in `crates/ea-reader-wasm/src/webauthn.rs` LIEST dieses Byte bereits, um Bit 6 zu prüfen, und verwirft den Rest — der Weg an die Information ist also offen und kostet keine neue Quelle. Eine Regel wie „höchstens ein backup-fähiges Credential" fasste damit genau den Fall, den `excludeCredentials` prinzipiell nicht sehen kann. **Sie wird in diesem Task NICHT gebaut**, und die Begründung ist keine Bequemlichkeit: ob zwei synchronisierte Passkeys eine gemeinsame Ausfalldomäne oder der gedachte Normalfall sind, ist eine Frage an `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` und nicht an eine Implementierung — §6.4.1 verlässt sich für den Gerätewechsel gerade darauf, dass ein synchronisierter Passkey bei gleichem Salt dieselbe PRF-Ausgabe liefert. Der Punkt steht hier als OFFEN und als nichts weiter.

**Zwei neue Zeugen gehören dazu, einer je Hälfte.** Wirtsseitig hält `the_registered_credential_ids_are_exactly_the_ones_the_next_ceremony_must_exclude` in `crates/ea-reader/tests/enrollment_two_authenticators.rs` fest, dass der herausgegebene Satz VOR der ersten Aufnahme leer ist, nach jeder erfolgreichen Aufnahme genau um deren Kennung wächst, bei einer ABGEWIESENEN unverändert bleibt und stets so lang ist wie `registered_authenticator_count` — mehr wäre ein Ausschluss auf ein Gerät, das dieses Enrollment gar nicht hält, weniger ist die Lücke selbst. Browserseitig misst `a second ceremony on the same authenticator is refused instead of silently replacing the first passkey` in `apps/web/tests/e2e/enrollment.spec.ts` die Lage, die der erste Browserzeuge ausdrücklich nicht misst: EIN virtueller Authenticator, zweimal `Authenticator registrieren`, und dann drei Zusicherungen — das Enrollment steht NICHT auf zwei, die Fläche sagt es IN WORTEN statt still hochzuzählen, und auf dem Gerät liegt danach noch derselbe erste Passkey. **Der Satz nennt die URSACHE und nicht eine Handlung, und das ist gemessen und nicht Geschmack:** „Der zweite Authenticator muss ein ANDERES Gerät sein" wäre in der zweiten Lage FALSCH. `CTAP2_ERR_CREDENTIAL_EXCLUDED` ist terminal, also trifft dieselbe Abweisung auch jemanden, der sehr wohl ein zweites, unbenutztes Gerät vorgehalten hat und dessen Zeremonie ein dritter, ausgeschlossener Authenticator zuerst beantwortet. Die Rückmeldung lautet deshalb, dass ein Authenticator geantwortet hat, der bereits einen Passkey dieses Readers trägt, und dass der nächste Versuch von einem Gerät beantwortet werden muss, das noch keinen hält — wahr in beiden Lagen. Der Zeuge pinnt beide Hälften des Satzes. Ohne die dritte Zusicherung bliebe der Zeuge auch dann grün, wenn die Zeremonie den ersten Passkey zerstörte und erst danach abbräche. Die deutsche Rückmeldung entsteht in `webauthn-prf.ts` aus dem `InvalidStateError` des Browsers und ist eine ÜBERSETZUNG, keine Entscheidung: abgewiesen hat der Browser, und ohne `excludeCredentials` gäbe es diesen Zweig gar nicht. **Der Zeuge BEISST, und das ist gefahren worden:** mit entferntem `excludeCredentials` und sonst unverändertem Baum meldet die Fläche „2 von 2 Authenticators registriert." ohne einen einzigen `alert`, und der Zeuge fällt.

`fingerprints` gibt den in `begin` gerechneten Schlüssel-Thumbprint und den dort übergebenen Bundle-`Hash32` heraus und rechnet selbst nichts — `CanonicalPublicCoseKey::x25519` gibt ein `Result`, es gibt kein `thumbprint()` auf einem `Result`, und ein fallibles `fingerprints` wäre ein zweiter Fehlerpfad an einer Stelle, an der nichts mehr fehlschlagen kann. Der Vorbildaufruf steht in `crates/ea-reader/src/vault.rs`, wo derselbe Ausdruck mit `?` in einer falliblen Funktion steht. `confirm_fingerprints` dekodiert beide eingegebenen Hexzeichenketten — `FingerprintEncoding`, wenn das misslingt — und vergleicht die 32 Byte gegen `as_bytes()` über `fingerprints_match`; der Vergleich läuft über die DEKODIERTEN Werte und nicht über die Zeichenketten, damit Gross-/Kleinschreibung der Anzeige keine falsche Abweichung erzeugt. **Trennzeichen deckt das ausdrücklich NICHT ab**: `hex::decode` weist jedes Leer- und Bindezeichen mit `InvalidHexCharacter` ab, eine gruppierte Anzeige liefe also in `FINGERPRINT-ENCODING` statt in eine Übereinstimmung — und sie bräche zusätzlich das `fill(shownKey)` des Browserzeugen, das wörtlich einsetzt, was `innerText()` gelesen hat. Die Anzeige ist deshalb UNGRUPPIERT, genau wie `apps/desktop/src/components/integrity/FingerprintBlock.tsx` sie heute setzt. Nur bei Übereinstimmung entsteht die `FingerprintConfirmationV1`. `finish` nimmt diesen Typ als Parameter und prüft ZUSÄTZLICH `MIN_ENROLLED_AUTHENTICATORS_V1`. Es gibt keinen `skip`, kein `force`, kein `Default` und keine zweite Konstruktionsstelle — genau das misst `the_confirmation_has_no_construction_path_outside_a_match`, und genau deshalb ist der Vergleich „bei jedem Erstaufruf auf einem Gerät ohne gepinnten Trust-Store erzwungen und nicht überspringbar" (§4.3) eine Typaussage und keine Bildschirmaussage.

`crates/ea-reader/src/enrollment_endpoints.rs` trägt den Port und seine Doppelung, gebaut nach `crates/ea-reader/src/blob_store.rs`:

```rust
/// Ein fertig gebauter Aufruf: Bytes und Kopfzeilen, sonst nichts.
///
/// Der Port kennt WEDER Struktur NOCH Bedeutung des Körpers — dieselbe Regel
/// wie bei [`crate::ReaderBlobStore`]. Wer hier typisiert zugriffe, hätte eine
/// zweite Stelle, an der über Protokollform entschieden wird.
pub struct EnrollmentRequestV1 { /* private */ }

impl EnrollmentRequestV1 {
    #[must_use] pub const fn method(&self) -> HttpMethod;
    #[must_use] pub fn target_uri(&self) -> &str;
    /// Die Herkunft, die die Signatur als `@authority` BINDET.
    ///
    /// Sie steht hier, weil der Aufrufer sonst raten müsste, wohin die Bytes
    /// gehören: `target_uri` ist ein Pfad, und ein Pfad allein adressiert
    /// nichts. Sie kommt aus [`EnrollmentRequestContextV1`].
    #[must_use] pub fn authority(&self) -> &str;
    #[must_use] pub fn body(&self) -> &[u8];
    /// `content-type`, `content-digest`, `ea-request-id`, `signature-input`,
    /// `signature` — je nach Aufruf. Der Abruf trägt die letzten beiden nicht.
    #[must_use] pub fn headers(&self) -> &[(String, String)];
    #[must_use] pub const fn is_signed(&self) -> bool;
}

/// Der AUFGEZEICHNETE Aufruf, den die Doppelung herausgibt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentCallV1 {
    pub method: HttpMethod,
    pub target_uri: String,
    pub signed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnrollmentEndpointError {
    /// Der Wirt kam nicht durch; der Text kommt von ihm.
    Host(String),
    /// Der Server hat geantwortet, aber nicht mit 2xx.
    Status(u16),
    /// Die Antwort ist keine gültige `VaultBlobRetrievalResponseV1`.
    ResponseShape,
}

impl EnrollmentEndpointError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Host(_) => "EA-READER-ENROLLMENT-ENDPOINT-HOST",
            Self::Status(_) => "EA-READER-ENROLLMENT-ENDPOINT-STATUS",
            Self::ResponseShape => "EA-READER-ENROLLMENT-ENDPOINT-RESPONSE",
        }
    }
}

/// Der Port über FERTIGE Anfragen.
///
/// EINE Methode und nicht drei: die REIHENFOLGE der drei Endpunkte ist eine
/// Eigenschaft von `finish` und keine des Ports, und drei benannte Methoden
/// verschöben sie in eine Schnittstelle, in der kein Zeuge sie sieht.
pub trait EnrollmentEndpoints {
    /// # Errors
    /// Jeder Fehlschlag des Wirts, ohne den Körper zu nennen.
    fn send(&mut self, request: &EnrollmentRequestV1) -> Result<Vec<u8>, EnrollmentEndpointError>;
}

/// Das Doppel, mit dem jeder `cargo test -p ea-reader` ohne Netz läuft.
///
/// Bewusst NICHT hinter `cfg(test)` — dieselbe Entscheidung wie bei
/// [`crate::InMemoryReaderBlobStore`]: die Integrationstests von `ea-reader`
/// und die Systemtests unter `tests/ea-system-tests` greifen darauf zu.
#[derive(Debug, Default)]
pub struct InMemoryEnrollmentEndpoints { /* private */ }

impl InMemoryEnrollmentEndpoints {
    #[must_use] pub fn new() -> Self;
    /// Die aufgezeichneten Aufrufe in der Reihenfolge, in der sie kamen.
    #[must_use] pub fn calls(&self) -> &[EnrollmentCallV1];
    /// Lässt den `ordinal`-ten Aufruf (1-basiert) mit DIESEM Fehler fallen.
    ///
    /// Der Fehler und nicht sein Code: `code()` ist einwegig — es gibt keine
    /// Abbildung von `"EA-READER-ENROLLMENT-ENDPOINT-STATUS"` zurück auf ein
    /// `Status(u16)`, und eine Doppelung, die aus einer Zeichenkette eine
    /// Variante raten müsste, wäre eine zweite Stelle mit Protokollwissen.
    pub fn fail_call(&mut self, ordinal: usize, error: EnrollmentEndpointError);
    /// Die Chiffrate, die `POST /v1/vault-blobs/retrievals` zurückgibt.
    pub fn answer_retrieval_with(&mut self, ciphertexts: Vec<Vec<u8>>);
}
```

`finish` baut und schickt danach in dieser Reihenfolge und nicht anders: je Authenticator ein `WebauthnCredentialRegistrationV1` über `POST /v1/webauthn-credentials` mit der pseudonymen `subjectId` als `userHandle` (§6.4.1), dann GENAU EIN `VaultBlobUploadV1` über `PUT /v1/vault-blobs`, und erst danach der lokale `store.put` unter `READER_VAULT_BLOB_KEY_V1`. **Ein PUT und nicht eines je Envelope**, und das ist eine BENANNTE ABWEICHUNG von der Wortwahl in §6.2 („Es entsteht ein Wrapped-Blob je Authenticator") und §6.4 („Die Wrapped-Blobs liegen … zusätzlich als opake Chiffrate beim Sync-Server") — sie steht hier als Abweichung, damit ein späterer Leser der Spezifikation sie findet und nicht für ein Versehen hält. Die Begründung ist sicherheitlich und betrieblich zugleich: `SealedVaultV1::to_deterministic_cbor` ist EIN Objekt, das Körperchiffrat, Nonces und ALLE Envelopes trägt; `MAX_VAULT_BLOBS_PER_SUBJECT_V1` zählt Tresore je Subjekt und nicht Entsperrwege, und ein Upload je Envelope verriete dem Server nebenbei die Zahl der Authenticators. Die 4 KB aus `MAX_VAULT_BLOB_CIPHERTEXT_BYTES_V1` genügen mit Abstand: zwei 32-Byte-Schlüssel, die Ankerbytes, der Registry-Pin und zwei Envelopes zu je `credentialId` plus 12 Byte Nonce plus 48 Byte umschlossener Schlüssel. Beide signierten Aufrufe entstehen über `RequestSigner::from_secret` mit dem gerade erzeugten Ed25519-Schlüssel — der liegt in diesem Moment im Klartext im WASM-Speicher, was diese beiden Endpunkte gerade NICHT zur Signaturausnahme macht (Stufe-3-Task „Web-Serverfläche: Vault-Blobs, WebAuthn-Assertion und CORS", zweiter Absatz seines Schritts 3). Die Reihenfolge ist fail-closed: ein lokal geschriebener Vault ohne serverseitige Kopie überstünde kein geräumtes Browserprofil, und §6.4 verlangt genau, dass dieser Fall ohne Administrationsvorgang gelöst wird. Bricht ein Aufruf ab, bleibt gar nichts geschrieben; `a_failing_upload_leaves_nothing_written_at_all` misst genau diesen Punkt, und `a_single_authenticator_is_a_refusal_and_writes_no_blob` misst dieselbe Eigenschaft am anderen Ende.

**Uhr und Einmalwerte treten als WERTE ein und werden nicht beschafft.** `RequestSigner::sign(&self, parts: &RequestParts, parameters: &SignatureParametersV1)` nimmt `created`, `expires`, `nonce` und die `RequestIdV1` von aussen — der Modulkopf von `crates/ea-sync-protocol/src/http_signature.rs` schreibt das als Absicht aus („der Schluessel kommt herein, die Zeit und die Einmalwerte kommen herein, und nichts davon wird hier beschafft"). `ea-reader` erbt diese Lage aus einem harten Grund: auf `wasm32-unknown-unknown` gibt es für `std::time::SystemTime::now()` keinen Wirt. `EnrollmentRequestContextV1::new(authority: String, created_unix_seconds: i64)` trägt deshalb beides herein; `expires` ist `created + ENROLLMENT_SIGNATURE_WINDOW_SECONDS_V1`, der 32-Byte-Nonce und die 16 Byte der `RequestIdV1` kommen aus `getrandom::fill`, und `tag` aus `ea_sync_protocol::organization_tag`.

**Die `authority` ist dabei die eine GRENZE dieses Absatzes, und sie ist keine Uhrfrage.** Die Zeit kommt von aussen, weil `wasm32-unknown-unknown` keinen Wirt für `SystemTime::now()` hat — das ist eine Unmöglichkeit. Die Herkunft des Sync-Servers kommt von aussen, weil `ea-reader` keine Konfiguration liest, und das ist eine ENTSCHEIDUNG: TypeScript wählt damit, an welche Autorität die RFC-9421-Signatur bindet. Das bleibt innerhalb von §9 — die Herkunft ist eine Betriebskonfiguration und kein kryptografischer Schritt, Rust rechnet die Signatur weiterhin allein —, aber es ist der einzige Wert dieses Tasks, den die Brücke bestimmt statt zu tragen, und deshalb steht er hier. Wer ihn später festnageln will, tut das im Bundle-Task zusammen mit `connect-src`: dieselbe Herkunft, dieselbe Konfigurationsquelle, ein Ort.

Der Abruf auf einem Gerät ohne Vault läuft über `recover_and_unlock_vault` und `POST /v1/vault-blobs/retrievals` und trägt als einziger Aufruf dieses Tasks KEINE RFC-9421-Signatur, weil der Signaturschlüssel im noch verschlossenen Vault liegt (§6.4.1, `design.md` §13.1). Alleinige Autorität ist die WebAuthn-Assertion über ein auffindbares Credential dieses Readers; `VaultBlobRetrievalRequestV1::new` nimmt `organizationId`, `subjectId`, `credentialId`, eine 32-Byte-Challenge, `authenticatorData`, `clientDataJSON` und die 64-Byte-Signatur, und die Antwort `VaultBlobRetrievalResponseV1` liefert bis zu `MAX_VAULT_BLOBS_PER_SUBJECT_V1` opake Chiffrate. `recover_and_unlock_vault` probiert sie der Reihe nach: `SealedVaultV1::from_deterministic_cbor` und dann `ReaderVault::unlock` mit dem vorgelegten Authenticator; genau eines öffnet, keines ist `NoVaultForCredential` mit dem Code `EA-READER-ENROLLMENT-NO-VAULT`. Die beiden Verwendungen desselben Authenticators bleiben getrennt: die Assertion authentisiert den Transport, die PRF-Ausgabe entsperrt den Vault, und keine der beiden verleiht dem Server Autorität (§6.4.1).

**Die Challenge dieses Abrufs kommt NICHT aus dieser Aufgabe, und das steht hier, damit sie nicht stillschweigend verschwindet.** §11 Punkt 7 der Spezifikation zählt sie als ZWEITE Signaturausnahme neben dem rate-limitierten Challenge-Endpunkt aus `design.md` §13.1; wer die Challenge holt und die Assertion darüber zieht, ist der Browser, und in dieser Aufgabe hat er keinen Weg dorthin: `recover_and_unlock_vault` bekommt eine FERTIGE `VaultBlobRetrievalRequestV1` samt Challenge, `authenticatorData` und Signatur herein, und keine der fünf Brückenausfuhren ruft sie auf. Der Abrufpfad ist in diesem Task also RUST-SEITIG gebaut und wirtsseitig bezeugt, aber nicht verdrahtet. `ea_sync_protocol::ChallengeRequestV1` steht deshalb bewusst NICHT im Consumes-Block — kein Aufruf dieser Aufgabe holt eine Challenge —, und die Verdrahtung samt Challenge-Abruf gehört in die Aufgabe, die den Wiederherstellungsweg auf einem leeren Gerät als OBERFLÄCHE baut. Das ist eine benannte Lücke und kein Versehen; sie stillschweigend in TypeScript zu schliessen, wäre der Fall, den §9 verbietet.

`crates/ea-reader-wasm/src/webauthn.rs` exportiert unter `cfg(target_arch = "wasm32")` **genau fünf Funktionen und keine sechste**. Sie tragen ZWEI Namen, wie jede Ausfuhr dieser Crate: `enrollment_begin` in Rust unter `#[wasm_bindgen(js_name = "enrollmentBegin")]`, und ebenso `enrollment_register_authenticator`/`enrollmentRegisterAuthenticator`, `enrollment_fingerprints`/`enrollmentFingerprints`, `enrollment_confirm_fingerprints`/`enrollmentConfirmFingerprints` und `enrollment_finish`/`enrollmentFinish`. `crates/ea-reader-wasm/src/lib.rs` schreibt die Regel über `bridge_echo_js` bereits aus — „`js_name` in lowerCamelCase, weil der Name auf der JS-Seite gelesen wird" —, und `vault_bridge.rs` hält sie mit `reader_vault_unlock`/`readerVaultUnlock` durch. Ein Zeuge, der einen der beiden Namen nennt, meint immer die Seite, auf der er steht. Die Zahl ist gegenüber der Vorfassung von drei auf fünf korrigiert, und beide Korrekturen sind belegt. `prf_kek_bytes` ENTFÄLLT: es war als Brückenexport UND als `cfg(test)`-Prüfpunkt zugleich beschrieben, und ein `cfg(test)`-Item exportiert an keinen JS-Aufrufer irgendetwas; sein Zweck, die Fixture-Parität, ist mit W22 ohnehin entfallen. Dafür kommen `enrollmentBegin` — jemand muss das Enrollment anlegen und seine Kennung herausgeben — und `enrollmentFinish` dazu, und `enrollmentConfirmFingerprints` ist der Export, den der vitest-Zeuge als `bridge.confirmFingerprints` aufruft; die Vorfassung deckelte bei drei und rief daneben eine vierte, was so nicht beides wahr sein konnte. Der Zustand liegt wie bei `crate::vault_bridge` in einem `thread_local!` mit `RefCell<BTreeMap<u32, ReaderEnrollment>>` und einer monoton wachsenden Kennung; `ReaderEnrollment` trägt dafür WEDER Lebenszeit- NOCH Typparameter, weil Bytespeicher und Endpunktport erst an `finish` übergeben werden — dieselbe Anordnung wie `ReaderObjectCache::put_exact_object(&self, store: &mut dyn ReaderBlobStore, …)`, die den Speicher je Aufruf nimmt und nicht festhält. **Jede der fünf Ausfuhren trägt `#[cfg(target_arch = "wasm32")]` UNMITTELBAR über ihrem `#[wasm_bindgen…]`-Attribut, auf der Zeile direkt darüber**; `every_wasm_bindgen_export_sits_behind_the_wasm32_cfg` in `crates/ea-reader-wasm/tests/bridge_boundary.rs` liest das als Text, folgt keinem `mod` und nennt `webauthn.rs` in seinem eigenen Doc-Kommentar bereits als eines der acht erwarteten Module. Ein cfg an der `mod`-Zeile übersetzt korrekt und fällt trotzdem durch. Die PRF-Ausgabe überquert die Grenze als besitzender `Vec<u8>` und wird nach der Übernahme in `SecretBytes<32>` in BEIDEN Klartextkopien gelöscht — dem `Vec<u8>` von der Grenze und dem `[u8; 32]`, über das `SecretBytes::new` gebaut wird —, wortgleich zu `take_authenticators` in `crate::vault_bridge`. **Auf der TypeScript-Seite wird sie in KEINER Variablen gehalten, die einen Namensraum überlebt, und NIEMALS geloggt** — `webauthn-prf.ts` reicht das `ArrayBuffer` aus dem `prf`-Ergebnis unmittelbar an die Brücke weiter, hält keine Kopie und schreibt es an keine Konsole; die Globale Randbedingung dieses Plans nennt Protokolle und Telemetrie ausdrücklich neben OPFS und dem Service-Worker-Cache, und diese Datei ist die EINZIGE Stelle des Web-Bündels, an der ein Klartextschlüsselbaustein überhaupt durch JavaScript läuft. `enrollmentRegisterAuthenticator` bekommt ausserdem den rohen `attestationObject`, hebt daraus `authData` und die attestierten Credentialdaten und reicht die COSE-Schlüsselbytes an `CanonicalPublicCoseKey::from_deterministic_cbor`; eine nicht-kanonische Karte scheitert dort an der Rückprobe gegen die eigenen Bytes und wird laut abgewiesen statt still übernommen. Eine Attestation-AUSSAGE wird NICHT geprüft — §6.6 verlangt sie nicht, und sie hier zu behaupten wäre eine Überzusage.

**Eine RISIKOLAGE, hier benannt und in dieser Aufgabe NICHT aufgelöst: der Credential-Schlüssel MUSS Ed25519 sein.** `WebauthnCredentialRegistrationV1::new` in `crates/ea-sync-protocol/src/enrollment.rs` weist jeden öffentlichen Schlüssel ab, den `CanonicalPublicCoseKey::from_deterministic_cbor` nicht als `Ed25519`-Arm zurückgibt; die Prüfung ist auf Stufe 3 eingefroren und wird hier nicht angefasst. Daraus folgt zwingend, dass `publicKeyAlgorithms` aus `enrollmentBegin` genau `[-8]` trägt und `webauthn-prf.ts` nichts anderes anbietet. GEMESSEN ist das nicht: ob Chromiums virtueller Authenticator unter `protocol: 'ctap2'` ein Ed25519-Credential erzeugt, steht in `WebAuthn.VirtualAuthenticatorOptions` nirgends, und ein Authenticator, der nur ES256 kann, liefert für `[-8]` gar kein Credential. Der erste Lauf des Browserzeugen entscheidet diese Frage. Fällt er daran, ist das ein Befund über die Stufe-3-Fläche und kein Fehler dieser Aufgabe: die Antwort wäre dann eine Erweiterung von `WebauthnCredentialRegistrationV1` um einen zweiten COSE-Arm, und die gehört in einen eigenen Vorgang mit eigenem Ledgereintrag. Was hier ausdrücklich NICHT passieren darf, ist ein stiller Rückfall auf ES256 im Browser, denn der liefe in `EA-SYNC-PROTOCOL-FRAME-SHAPE` an einer Stelle auf, an der niemand die Ursache sucht.

`apps/web/src/vault/webauthn-prf.ts` ist die einzige Datei, die `navigator.credentials.create` und `navigator.credentials.get` mit der Erweiterung `prf` aufruft. Sie enthält KEINE Sicherheitslogik: sie leitet keinen Schlüssel ab, vergleicht keinen Fingerprint, kodiert kein Chiffrat und trifft keine Entscheidung — sie reicht Bytes an die Brücke und bekommt Status-DTOs zurück (§9). `authenticatorSelection` verlangt `residentKey: 'required'` und `userVerification: 'required'`, weil §6.4.1 die Auflösung über ein AUFFINDBARES Credential voraussetzt. `hints: ['client-device']` steht daneben, damit der QR-Flow gar nicht erst angeboten wird; die harte Abweisung bleibt trotzdem in Rust, weil eine UI-Auswahl kein Gate ist. `excludeCredentials` trägt die Kennungen, die `enrollmentBegin` und `enrollmentRegisterAuthenticator` herausgeben — die vollständige Begründung samt Messung steht oben bei der FÜNFTEN Absicherung; hier gilt nur, dass die Liste DURCHGEREICHT und nicht in dieser Datei geführt wird. Die PRF-Ausgabe wird über `credentials.get` geholt und nicht über `credentials.create`: `hmac-secret` bei der Erzeugung ist als `hmac-secret-mc` ein eigenes, optionales Authenticator-Merkmal, und der Weg über `get` ist derselbe, den §6.4 für jeden späteren Zugriff ohnehin beschreibt. Genau deshalb bedient dieselbe Datei auch das Entsperren nach dem Abschluss: ein ZWEITES `credentials.get` mit derselben Erweiterung, dessen Ausgabe zusammen mit dem über `blobGet` gelesenen versiegelten Tresor an `readerVaultUnlock` aus `crate::vault_bridge` geht. Hier steht ausserdem der exportierte Typ `EnrollmentBridge`: die fünf Aufrufe und ihre Status-DTOs, `code?: string | undefined` in der Bestätigung, und sonst nichts. Er gehört hierher und nicht in eine Testdatei, weil er die FORM der Brücke ist; `EnrollmentPage.tsx` nimmt ihn als Eigenschaft `bridge`, deren Vorgabewert die echte Umsetzung aus dieser Datei ist — sonst montierte `page.goto('/enrollment')` eine Seite ohne Brücke.

**W18 aufgelöst — die Datei bleibt INNERHALB der Regel, und der Wächter wird NICHT angepasst.** `apps/web/src/bridge/no-hand-written-contracts.test.ts` scannt jede nicht-Test-`.ts(x)` unter `apps/web/src` ausser den zwei Generatorausgängen und weist `/crypto\.subtle|createHash|Ed25519|X25519|ChaCha20|new Uint8Array\(32\)/` zurück; `webauthn-prf.ts` fällt in diesen Kreis. Zwei Dinge müssten dort normalerweise stehen und stehen deshalb hier NICHT. Das PRF-Salt und die Liste der COSE-Algorithmen kommen als DATEN aus `enrollmentBegin` zurück — `{ handle, prfSalt, publicKeyAlgorithms }` —, also aus `VAULT_PRF_SALT_V1` in geteiltem Rust; die Datei schreibt keine einzige kryptografische Konstante hin. Und die Challenge kommt vom Server über den Challenge-Endpunkt (`apps/server/src/http/challenges.rs`) und nicht aus einem lokal erzeugten Puffer, weshalb `new Uint8Array(32)` nirgends vorkommt. Das ist keine Umgehung des Zeugen, sondern genau seine Aussage: eine Datei, die keine Sicherheitsentscheidung trifft, braucht keinen dieser Ausdrücke. Ein Tiefenimport, eine andere Schreibweise des Literals oder eine erweiterte Ausnahme im Zeugen wären alle drei die falsche Antwort — einen Wächter zu lockern ist eine Entscheidung, die man begründen muss, und hier gibt es nichts zu begründen, weil es nichts zu lockern gibt. Dasselbe gilt für die fünf neuen Nachrichten in `apps/web/src/bridge/opfs-worker.ts`: sie tragen Bytes und Kennungen, keinen Algorithmennamen und keine 32-Byte-Konstante, und die Datei bleibt damit ebenfalls innerhalb der Regel.

`EnrollmentPage.tsx` führt die drei Schritte in einer Ant-Design-6-Oberfläche mit deutschem `ConfigProvider` und statisch extrahiertem lokalem gehashtem CSS, `zeroRuntime: true`, direkten CSR-Importen aus `@phosphor-icons/react`, sichtbarem Fokus und `prefers-reduced-motion`. **Die Fläche benutzt AUSSCHLIESSLICH Ant-Komponenten, die `EXTRACTED_COMPONENTS` in `apps/web/src/design/extract-static-css.tsx` bereits führt: `Alert`, `Button`, `Descriptions`, `Input`, `Space`, `Tag` und `Typography`.** Das ist eine bewusste Wahl und der Grund, warum `extract-static-css.tsx` und `apps/web/src/design/static-antd.css` NICHT im Files-Block stehen. `Form` und `Steps` stehen NICHT auf der Liste der siebzehn extrahierten Namen; `extracts every Ant component the hand written sources import` in `apps/web/src/design/static-css.test.ts` fiele bei ihrem Import rot, und die Reparatur zöge eine Erweiterung der Liste plus ein neu erzeugtes `static-antd.css` (`pnpm --dir apps/web test --run -u`) in eine Aufgabe, deren Gegenstand das Enrollment ist. Die drei Schritte werden als `Typography.Title`/`Typography.Text` und `Tag` ausgezeichnet, die zwei Eingaben sind `Input` mit einem echten `<label htmlFor>` — was der `getByLabelText`-Zugriff beider Zeugen ohnehin verlangt —, und die Weigerung ist ein `Alert` mit `role="alert"`. `AuthenticatorRegistration.tsx` zählt registrierte Authenticators als TEXT und nicht nur als Symbol und nennt die fehlende Zahl beim Namen. `FingerprintGate.tsx` zeigt beide Fingerprints im Monospace-Block nach dem Muster von `apps/desktop/src/components/integrity/FingerprintBlock.tsx` — UNGRUPPIERT und ohne Trennzeichen, siehe oben — und verlangt die Eingabe der Referenz; das Abschlusselement ist gesperrt, solange die Brücke keine Bestätigung geliefert hat. **Die zwei Wertknoten tragen `data-testid="schluessel-fingerprint"` und `data-testid="bundle-fingerprint"`, und zwar der WERT und nicht seine Umhüllung.** Das ist die einzige Stelle, an der der Browserzeuge einen Wert liest, den der Lauf selbst erzeugt hat; sässe die Kennung auf einem Kasten, der die Beschriftung mitträgt, käme sie über `innerText()` mit in die Zeichenkette, das anschliessende `fill` schriebe Beschriftung plus Wert in das Feld, und das Enrollment antwortete mit `FINGERPRINT-ENCODING` an einer Stelle, an der niemand einen Testaufbaufehler vermutet. Nach dem Abschluss zeigt `EnrollmentPage.tsx` ausserdem das Bedienelement „Tresor entsperren" samt der Rückmeldung „Tresor entsperrt." — es fährt den oben beschriebenen Weg über `credentials.get`, `blobGet` und `readerVaultUnlock` und ist der sichtbare Teil der lebenden Paritätsprüfung.

`apps/web/src/main.tsx` wird HIER angefasst und nicht nur oben begründet: `EaWebRoute` bekommt den dritten, optionalen Platz `render?: () => ReactElement`, `EA_WEB_ROUTES` den Eintrag für `/enrollment`, und der Montagepunkt am Dateiende übergibt `initialPath={window.location.pathname}`. Die Begründung samt der Feststellung, dass `EaWebRoute` exportiert ist und die Erweiterung deshalb eine öffentliche Formänderung ist, steht im Kopf dieser Aufgabe.

**Offener Punkt, hier benannt und nicht aufgelöst:** `web-reader-design.md` §14 Punkt 5 erklärt Referenzquelle und Verteilweg der Fingerprint-Bekanntgabe ausdrücklich für OFFEN. Dieser Task baut deshalb den VERGLEICH und seine Unumgehbarkeit, nicht den Bezugsweg der Referenz: die erwarteten Werte werden eingegeben. Die Administrationshälfte, die den erwarteten Fingerprint in der Desktop-Anwendung anzeigt (§6.6 Schritt 4), liegt in Stufe 5 und wird hier weder gebaut noch behauptet.

Zum Abschluss dieses Schrittes, als LETZTE Zeile und nicht als erste des nächsten:

Run: `cargo metadata --format-version 1`

Das ist das GENAU EINE Kommando dieses Tasks ohne `--locked`. Dieser Schritt gibt `crates/ea-reader/Cargo.toml` die Kante `ea-sync-protocol.workspace = true` — alphabetisch zwischen `ea-format` und `ea-trust`, mit dem einen erklärenden Kommentar je Abhängigkeit, den die Datei durchhält —, und eine neue Kante zwischen zwei Mitgliedern schreibt `Cargo.lock` fort: der `ea-reader`-Eintrag muss `"ea-sync-protocol"` gewinnen. **Es steht am ENDE der Implementierung und nicht am Anfang der Prüfung, und die Verschiebung ist strikt sicherer.** Die bindende Bedingung lautet „nach der Manifeständerung, vor JEDEM `--locked`-Kommando"; steht das Kommando erst im Prüfschritt, fällt jedes `cargo check` und jedes `cargo clippy`, das jemand mitten in der Implementierung fährt, vorher an einem überholten Lockfile — und die Meldung weist dann auf das Lockfile statt auf den Code, an dem gerade gearbeitet wird. Sechs `--locked`-Läufe hängen daran, und ZWEI davon stehen INNERHALB von Tests, beide in `tools/xtask/tests/workspace.rs`: `no_non_test_edge_carries_the_ea_reader_test_surface` ruft zweimal `cargo tree --locked -p ea-reader-wasm`, und `workspace_declares_exact_planned_members_and_shared_dependencies` fährt selbst ein `cargo metadata --locked --no-deps` — es ist der Zeuge, der genau die Manifestzeile liest, die dieser Schritt einträgt, und deshalb der wahrscheinlichste, der zuerst rot wird. Die Regel steht wörtlich in seinem eigenen Kommentar.

- [x] **Step 5: Run the enrollment, fingerprint, and browser witnesses**

Run:

```bash
cargo test --locked -p ea-reader --test enrollment_two_authenticators --test fingerprint_gate
cargo test --locked -p ea-reader-wasm --test bridge_boundary
pnpm --dir apps/web test --run src/features/enrollment src/e2e-config.test.ts
pnpm --dir apps/web typecheck
pnpm --dir apps/web exec playwright test tests/e2e/enrollment.spec.ts --project=chromium
```

Alle Kommandos tragen jetzt `--locked` beziehungsweise brauchen keins: `cargo metadata --format-version 1` ist am Ende von Schritt 4 gelaufen und `Cargo.lock` steht wieder. `bridge_boundary` läuft ausdrücklich mit, weil die fünf neuen Ausfuhren dort und NUR dort geprüft werden — mit fehlendem cfg enden Übersetzung, Testbau und Clippy-Gate alle drei mit 0 und ohne eine einzige Diagnose. `pnpm --dir apps/web typecheck` läuft, weil `apps/web/tsconfig.json` in diesem Task um `playwright.config.ts` und `tests` gewachsen ist und diese beiden Flächen sonst von nichts geprüft würden. Ein Lauf von `pnpm verify:quick` ist hier NICHT vorgesehen und wäre auch nicht harmlos: er zieht `cargo test --workspace --all-targets --locked` mit, und dessen Integrationsziele lesen `DATABASE_URL` — er stünde also in `cargo run --locked -p xtask -- integration up` … `integration down`, wie jedes `verify:quick` dieses Plans.

Expected: PASS. Belegt sind ZEHN Negative und ACHT Positive. Die Negative: ein einzelner Authenticator ist `EA-READER-ENROLLMENT-SINGLE-AUTHENTICATOR`, hinterlässt keinen Blob UND erreicht keinen Endpunkt; dieselbe `credentialId` zweimal ist `EA-READER-ENROLLMENT-DUPLICATE-AUTHENTICATOR` und erhöht den Zähler nicht; eine `credentialId` unter `MIN_WEBAUTHN_CREDENTIAL_ID_BYTES_V1` ist `EA-READER-ENROLLMENT-CREDENTIAL-ID-LENGTH` und wird HIER abgewiesen und nicht erst am Endpunkt; ein Cross-Device-Credential ist `EA-READER-ENROLLMENT-TRANSPORT-REFUSED`; ein abweichender Bundle- ODER Schlüssel-Fingerprint ist `EA-READER-ENROLLMENT-FINGERPRINT-MISMATCH` und liefert keine `FingerprintConfirmationV1`, weshalb `finish` nicht einmal aufrufbar ist; eine nicht-hexadezimale Eingabe ist `EA-READER-ENROLLMENT-FINGERPRINT-ENCODING` und nicht dasselbe wie eine Abweichung; ein gefallener dritter Aufruf ist `EA-READER-ENROLLMENT-ENDPOINT-STATUS` und lässt den Bytespeicher leer; ein Abruf, in dessen acht Chiffraten kein Envelope für den vorgelegten Authenticator liegt, ist `EA-READER-ENROLLMENT-NO-VAULT`; und ein Envelope, der direkt mit der rohen PRF-Ausgabe statt mit `KEK_i` geöffnet wird, ist `EA-CRYPTO-AEAD-OPEN` — ein durchgereichter Code aus `ea_crypto::aead_open` und kein eigener zweiter. Die Positive: beide Envelopes öffnen denselben Vault-Key und liefern denselben KEM-Thumbprint und denselben gepinnten Anchor; das Entfernen eines Authenticators lässt den Vault über den zweiten offen, während das entfernte Credential `EA-READER-VAULT-NO-ENVELOPE` bekommt; `finish` fährt GENAU DREI Endpunktaufrufe in der Reihenfolge `POST /v1/webauthn-credentials`, `POST /v1/webauthn-credentials`, `PUT /v1/vault-blobs`, alle drei signiert, und schreibt erst danach lokal; `recover_and_unlock_vault` fährt GENAU EINEN Aufruf, `POST /v1/vault-blobs/retrievals`, OHNE Signatur, und öffnet aus acht Chiffraten genau das eine, das diesem Reader gehört; die angezeigten Werte SIND der KEM-Thumbprint und der Bundle-Hash, und ihre Hexform ist 64 Zeichen lang; `FingerprintConfirmationV1` hat genau eine Konstruktionsstelle, keinen inhärenten `impl`-Block, kein `Default`, kein `Clone` und keine wiederauferstandene `AnchorUnpinned`-Variante; und das §4.3-Gate schlägt auf einem Gerät ohne gepinnten Tresor an (`DeviceTrustStateV1::NoPinnedAnchor` → `fingerprint_gate_required` wahr) und danach nicht mehr (`Pinned` → falsch). Und der Satz, den `registered_credential_ids` herausgibt, ist genau der der bisher aufgenommenen Authenticators: leer vor der ersten Aufnahme, um genau eine Kennung länger nach jeder erfolgreichen, unverändert nach einer abgewiesenen — er ist das Argument der nächsten `excludeCredentials`, und mehr oder weniger als dieser Satz wäre beides eine falsche Zeremonie. Zehntes Negativ ist der Browserfall daneben: eine zweite Zeremonie auf DEMSELBEN Gerät ist `InvalidStateError`, das Enrollment steht danach nicht auf zwei, und der erste Passkey liegt unverändert auf dem Gerät. NICHT belegt sind `EA-READER-ENROLLMENT-ENDPOINT-HOST` und `EA-READER-ENROLLMENT-ENDPOINT-RESPONSE`: beide entstehen in diesem Task, beide werden von keinem Zeugen ausgelöst, und das steht hier, weil eine unbezeugte Fehlerform, die niemand nennt, später als bezeugt gilt. Ihr erster Zeuge fällt an, sobald ein Task die Browserfassung des Ports gegen einen echten Server fährt.

**Was der Browserlauf beweist und was er ausdrücklich nicht beweist.** Bewiesen ist die volle lebende Kette: ein echter virtueller CTAP2-Authenticator mit `hasPrf`, eine echte `navigator.credentials.get`-Zeremonie mit der `prf`-Erweiterung, 32 Byte, die der Test nicht kennt und nicht setzen kann, ihr Weg über die Brücke nach Rust, `derive_kek_v1`, der Envelope, den derselbe Lauf gebaut hat, und ein `ReaderVault::unlock`, das ihn öffnet. NICHT bewiesen ist irgendein Byte-WERT: Chromiums virtueller Authenticator zieht seinen CredRandom selbst, `WebAuthn.VirtualAuthenticatorOptions` hat kein Feld dafür, und eine „aufgezeichnete" PRF-Ausgabe ist deshalb in keinem zweiten Lauf reproduzierbar — Stufe 4 friert dafür auch nichts unter `vectors/` ein. Die UNABHÄNGIGKEIT der zwei Authenticators ist seit dem zweiten Browserzeugen NEGATIV belegt und positiv weiterhin nicht: gemessen ist, dass eine zweite Zeremonie auf DEMSELBEN Gerät abgewiesen wird und den ersten Passkey stehen lässt — nicht, dass zwei erfolgreiche Zeremonien auf zwei verschiedenen Geräten gelandet sind, denn CDP erzwingt für einen `create`-Aufruf kein Zielgerät. Der erste Zeuge nähert die Auswahl deshalb über `WebAuthn.setAutomaticPresenceSimulation` an, und das ist eine Simulation der BERÜHRUNG und keine Zuweisung eines Ziels. NICHT bewiesen ist die Serverhälfte: die drei Endpunkte beantwortet `page.route`, und was `apps/server` mit ihnen macht, misst `pnpm test:server` mit `--test webauthn_credential_api --test vault_blob_api`. Und NICHT bewiesen ist irgendetwas ausserhalb von Chromium: `WebAuthn.addVirtualAuthenticator` ist eine CDP-Methode, Firefox und WebKit bieten kein Gegenstück, und der Task „Reader-Interoperabilität, Browser-Matrix, Datei-Modus, Privatheit und das Stufe-4-Gate" trägt diese Einschränkung in die Spalte `offen in späterer Stufe` seines Berichts. Die Rust-Zeugen laufen plattformunabhängig auf dem Wirt und sind der Träger jeder normativen Aussage dieses Tasks. **Und eine letzte Grenze, die zur Ehrlichkeit dieses Absatzes gehört: die lebende Parität läuft in KEINEM Tor dieses Repositoriums.** `web:e2e` steht wie `desktop:e2e` ausdrücklich nicht in `verify_quick_commands()`, weil Playwright installierte Browser voraussetzt, und eine CI, die es unabhängig davon führte, gibt es hier nicht. Mit dem Wegfall von `fixture_prf_output`/`recorded_prf_output` (W22) ist damit KEIN durchgesetzter Zeuge übrig, der die echte PRF-Kette anfasst — sie wird gefahren, wenn jemand sie fährt, wie `spikes/wasm-runtime-proof/spike.sh`. Das ist der Preis dafür, keinen Zeugen zu behalten, der sich selbst misst, und er wird hier genannt und nicht weggeschrieben.

Die Ledgerzeilen `WR-063` (Enrollment registriert mindestens zwei unabhängige Authenticators) und `WR-043` (erzwungener, nicht überspringbarer Fingerprint-Vergleich beim Erstaufruf) bekommen hier ihre Belege, werden aber NICHT hier umgestellt: der gepinnte Konstantenblock `WEB_READER_MUST_ROWS` in `tools/xtask/tests/stage_gate.rs` und die Statusspalte in `docs/traceability/v0.1-requirements.csv` werden ausschliesslich im Task „Reader-Interoperabilität, Browser-Matrix, Datei-Modus, Privatheit und das Stufe-4-Gate" angefasst, damit die Stelligkeit dieser Konstante in dieser Stufe genau einmal wandert.

- [x] **Step 6: Commit browser enrollment**

```bash
git add .gitignore package.json Cargo.toml Cargo.lock docs/adr/0005-browser-runtime-and-wasm-dependency-class.md
git add crates/ea-reader/src/enrollment.rs crates/ea-reader/src/enrollment_endpoints.rs crates/ea-reader/src/lib.rs crates/ea-reader/Cargo.toml crates/ea-reader/tests/enrollment_two_authenticators.rs crates/ea-reader/tests/fingerprint_gate.rs crates/ea-reader/tests/fixtures/mod.rs
git add crates/ea-reader-wasm/src/webauthn.rs crates/ea-reader-wasm/src/lib.rs
git add apps/web/src/vault apps/web/src/features/enrollment apps/web/src/bridge/opfs-worker.ts apps/web/src/main.tsx apps/web/src/e2e-config.test.ts apps/web/tests/e2e/enrollment.spec.ts apps/web/playwright.config.ts apps/web/tsconfig.json
git add docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-4-reader.md
git commit -m "feat(reader): enroll two authenticators behind an unskippable fingerprint gate"
```

`crates/ea-reader/tests/fixtures/mod.rs` und `apps/web/tsconfig.json` stehen ausdrücklich in der Liste — beide werden geändert und beide fehlten in der Vorfassung, und eine nicht mitkommittierte Fixture lässt den Commit auf jedem anderen Rechner nicht übersetzen. Die Wurzel-`Cargo.toml` und ADR 0005 stehen aus demselben Grund zusammen in einer Zeile: die Merkmalszeile und ihre Ledgerzeile müssen sich zeichengleich decken, und getrennt kommittiert fällt `adr_gate` zwischen den beiden Commits. Der Planfile-Eintrag reitet im SELBEN Commit mit, weil die sechs Checkboxen dieses Tasks dort umschlagen; das ist die Anordnung des DRK-256-Vorläufers und keine Ausnahme. `apps/web/src/bridge/pkg/` wird NICHT hinzugefügt: es ist ein Generatorausgang und über `pkg/` in `.gitignore` gehalten.

### Task 6: Web-Bundle: getrennter Origin, Service Worker, gepinnte `webBundleRelease` und das Alter des Trust-Standes

**Files:**
- Create: `crates/ea-reader/src/bundle_release.rs`
- Create: `crates/ea-reader/tests/bundle_release_pinning.rs`
- Create: `crates/ea-reader/src/trust_state.rs` — der Speicher des Trust-Standes; siehe Entscheidung 6
- Create: `crates/ea-reader/tests/trust_age.rs`
- Modify: `crates/ea-reader/src/envelope.rs` — der FUENFTE abgeleitete Schluessel
- Modify: `crates/ea-reader/src/vault.rs` — sein Zugang; der Tresorkoerper bleibt UNVERAENDERT
- Modify: `crates/ea-crypto/src/digest.rs` — `web_bundle_hash`; siehe Entscheidung 7
- Modify: `crates/ea-crypto/tests/suite_v1.rs` — sein Zeuge
- Create: `apps/web/src/sw/service-worker.ts`
- Create: `apps/web/src/sw/bundle-pinning.ts`
- Create: `apps/web/src/sw/service-worker.test.ts`
- Create: `apps/web/src/features/trust-age/TrustAgeBanner.tsx`
- Create: `apps/web/tests/e2e/bundle-activation.spec.ts`
- Create: `apps/web/tests/e2e/fixtures/*.hex` — die vier gepinnten Browserfixtures; siehe Entscheidung 9
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
- Modify: `crates/ea-ui-contracts/tests/generated_ts_is_current.rs` — der Maskierungshaken der Reader-Haelfte; siehe Korrektur 3
- Modify: `crates/ea-reader/tests/fixtures/mod.rs` — der ZWEITE Anker der Web-Bundle-Vektorfamilie; siehe Korrektur 4
- Modify: `Cargo.lock`
- Modify: `apps/web/src/bridge/generated-contracts.ts` — Emitterausdruck, von Hand unangetastet

**Interfaces:**
- Consumes: die in Stufe 3 dauerhaft eingefrorene Objektfamilie — `TrustSubtypeV1::WebBundleRelease`, `TrustSubtypeV1::WebBundleRevocation`, `WebBundleReleaseCoreV1`, `WebBundleRevocationCoreV1`, `DecodedTrustPayloadV1::WebBundleRelease`, `TrustObjectV1::{subtype, signatures, exact_digest_input, decoded_payload}`, `ea_format::decode_exact_object`, die beiden CDDL-Arme `web-bundle-release-core-v1` und `web-bundle-revocation-core-v1` und die Vektoren unter `vectors/web-bundle/v1/object/`; dazu `TrustAnchorV1::{root_public_cose_key, root_key_thumbprint, root_certificate_object_hash, organization_id}` aus dem entsperrten Vault der Aufgabe „Browser-Vault: PRF-Envelopes, Schlüsselprofil und die Verwahrung von Anchor und KEM-Schlüssel", `PolicyFieldsV1::reader_trust_refresh_ms` über `SelectedRegistryHead::policy_fields`, und die Brücke aus der Aufgabe „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate".
- Produces: `ea_crypto::verify_web_bundle_trust_signature`, `ReaderBundlePin::{from_trust_objects, evaluate, active_bundle_hash}`, `BundleActivationDecisionV1`, `BundleRejectionCodeV1`, `ReaderTrustAgeView`, `BundleActivationView`, der Service Worker von `apps/web` mit seiner Aktivierungsentscheidung, der Abschnitt `bundle-activation` in `docs/traceability/stage-4-fault-points.json`.

Diese Aufgabe wählt und betreibt den getrennten Bundle-Host NICHT — Zielorigin und Betriebsverantwortung sind in `web-reader-design.md` §14, offener Punkt 4, selbst als offen erklärt; sie baut ausschließlich die Trennung selbst und die Positivliste, gegen die sie geprüft wird. Sie behauptet keine PWA-Installation und kein Gate über die Ablehnung eines nicht Root-signierten Bundles: beides weist §12 der Stufe 7 zu. Sie friert keinen Vektor ein und legt keinen neuen an; die Familie ist seit Stufe 3 permanent eingefroren.

**GEMESSEN am 2026-09-01 und in diesem Abschnitt korrigiert — fuenf Aussagen gingen gegen den
AUSGELIEFERTEN Stand nicht auf.** Dieser Abschnitt entstand, bevor die ersten fuenf Aufgaben der
Stufe 4 auslieferten; dieselbe Nachbesserung hat die Aufgabe „Browser-Enrollment: zwei
Pflicht-Authenticators und das nicht ueberspringbare Fingerprint-Gate" vor ihrer Umsetzung gefahren.
Die Korrekturen stehen unten im Text und werden hier aufgezaehlt, damit keine still bleibt:

1. **`Hash32` traegt kein `Debug`.** `assert_eq!` auf `Option<Hash32>` UEBERSETZT NICHT — der Fehler
   waere ein Kompilierfehler in der Zusicherungsmaschinerie und keine Aussage ueber
   `ReaderBundlePin`. Die vier betroffenen Zusicherungen vergleichen jetzt ueber `as_bytes()`, der
   Leerfall ueber `is_none()`. Derselbe Verzicht auf `Debug` steht in diesem Plan bereits zweimal
   ausgeschrieben; Task 6 hat ihn gebrochen. `crates/ea-types` wird NICHT angefasst: das fehlende
   `Debug` ist eine Datensparsamkeitsentscheidung und kein Versehen.
2. **`format: 'iife'` ist gar nicht waehlbar, und der Worker ist ein MODULWORKER.** Gemessen
   gegen die installierte Werkzeugkette (Vite 8.2.1 auf rolldown 1.2.5): zwei Einstiege mit
   `output.format: 'iife'` brechen mit
   `[INVALID_OPTION] ... multiple inputs are not supported when "output.codeSplitting" is false` ab,
   und mit erzwungenem `codeSplitting: true` mit `UMD and IIFE are not supported for code-splitting
   builds`. Der ENTSCHEIDENDE Grund ist aber ein anderer und wurde erst beim Bau des Browserzeugen
   sichtbar: die von `wasm-bindgen` erzeugte Glue ist ein ES-MODUL. Ein klassischer Worker koennte
   sie nicht importieren, muesste die fertige Entscheidung entgegennehmen — und erzwaenge dann
   nichts mehr, sondern gehorchte. §4.2 sagt aber, dass DER SERVICE WORKER die Aktivierung prueft.
   Er wird deshalb als eigener Einstieg IM SELBEN Durchgang gebaut, mit `type: 'module'`
   registriert, und `entryFileNames` haelt allein SEINEN Namen ungehasht, waehrend jedes andere
   Beiwerk seinen Hash behaelt. Ueber `postMessage` gehen ausschliesslich BYTES: Anker,
   Trust-Bestand, Registry-Stand und Kandidatenbytes sind strukturiert klonbar, eine Funktion
   waere es nicht. Die Textpins auf `vite.config.ts` ziehen entsprechend mit — `'service-worker'`
   als Einstieg und `'service-worker.js'` als Name, dazu die Zusicherung, dass KEIN
   iife-Ausgang konfiguriert ist.
3. **Die Zeichenfolge `sign` ist im Reader-Ausdruck verboten.**
   `the_emitted_reader_file_declares_types_and_computes_nothing` verbietet neun Zeichenfolgen
   ungemaskiert, darunter `sign`; `Unsigned` enthaelt sie, also faerbte
   `cargo test --locked -p ea-ui-contracts` in Schritt 4 rot, obwohl dort „Expected: PASS" steht.
   Die Aufzaehlung wird NICHT umbenannt — §4.2 sagt „nicht signiert", und die Domaenensprache
   gegen einen Kunstnamen zu tauschen waere der schlechtere Handel. Stattdessen bekommt die
   Reader-Haelfte denselben Maskierungshaken, den die Desktop-Haelfte fuer `signerrole` und den
   Gesundheitscode bereits fuehrt.
4. **`fixtures::vault_anchor()` ist ein ZWEITER Anker und nicht der vorhandene.**
   `fixtures::pinned_anchor()` traegt Wurzelseed `0x11`, `organization_id` `0x12` und
   Zertifikatshash `0x14` und wird von fuenf bestehenden Testdateien auf genau dieser Identitaet
   verbraucht. Die eingefrorenen Vektoren unter `vectors/web-bundle/v1/object/` sind mit Seed
   `0xa0` unterschrieben und tragen `organization_id` `0x90` und Zertifikatshash `0x92` — gegen
   `pinned_anchor()` fiele JEDE positive Zusicherung mit `WrongRoot` beziehungsweise
   `WrongOrganization`. `vault_anchor()` entsteht deshalb NEBEN `pinned_anchor()` in derselben
   Datei und ersetzt ihn nicht. `crates/ea-testkit` wird dafuer NICHT geoeffnet.
5. **Der in Schritt 3 genannte Zeuge haelt die falsche Datei.**
   `the_checked_in_file_is_exactly_what_the_emitter_writes` vergleicht gegen
   `apps/desktop/src/bridge/generated-contracts.ts`. Den Web-Ausdruck haelt
   `the_checked_in_reader_file_is_exactly_what_the_reader_emitter_writes`. Die Verwechslung waere
   teuer geworden, weil `docs/traceability/stage-4-fault-points.json` jeden `witness` bei Namen
   nennt und der Stufengate ihn aufloest.

**VIER LUECKEN, die dieser Abschnitt offen liess und die hier geschlossen werden.** Sie sind
keine Abweichung vom ausgelieferten Stand, sondern Stellen, an denen der Plan eine Quelle nannte,
die es nicht gibt:

6. **Das Trust-Alter hatte keine Laufzeitquelle.** Der Abschnitt liest die Frist ueber
   `SelectedRegistryHead::policy_fields()` — aber KEIN Readercode baut einen
   `SelectedRegistryHead`, und `VaultContentsV1` speichert keinen Zeitpunkt. Beide Eingaben von
   `trust_age_ms` fehlten. `reader_trust_age_view` ist deshalb eine REINE Funktion ueber drei
   Eingaben, und der Zeitpunkt liegt in einem EIGENEN, unter dem Tresorschluessel
   verschluesselten OPFS-Speicher — dem dritten seiner Bauform neben `ReaderObjectCache` und
   `ReaderEntryStateStore`, mit einem FUENFTEN Ableitungskontext. Der TRESORKOERPER wird
   ausdruecklich NICHT erweitert: `web-reader-design.md` §6.1 zaehlt seine vier Werte normativ
   auf, und ein fuenfter zwaenge jeden versiegelten Tresor zum Neuversiegeln.
   `at_registry_version` dagegen war schon da und wird auch so bezogen:
   `RegistryHeadPin::registry_version()` aus dem entsperrten Tresor.
7. **Der Hash eines Kandidatenbuendels hatte keine Rechnung.** `bundle_hash` ist an JEDER Stelle
   des Repositoriums eine Konstante, `ea-crypto` fuehrt siebzehn Digest-Domaenen und keine fuer
   Buendel, und §4.2 sagt nur, dass der Hash aufgenommen wird. Der Hash MUSS aber ueber die
   tatsaechlichen Kandidatenbytes gerechnet werden — gaebe ihn der Kandidat mit, waere die
   Pruefung wertlos. `ea_crypto::web_bundle_hash` ist deshalb NACKTES SHA-256. Eine eigene
   Domaene ist GEMESSEN nicht baubar:
   `crypto_suite_one_vectors_reproduce_every_primitive_and_domain_string` faellt mit 26 gegen 25
   und verlangt fuer jede `EINSATZARCHIV-`-Zeichenkette dieser Crate einen eingefrorenen Vektor
   unter `vectors/crypto/suite-1/` — und Stufe 4 friert keine Vektorfamilie ein. Der Verzicht ist
   ausserdem sachlich richtig: der Wert muss von einem Releaseprozess AUSSERHALB dieses
   Repositoriums reproduzierbar sein, und er wird an genau einer Stelle gelesen.
8. **Die Bruecke braucht zwei Namen mehr.** `crates/ea-reader-wasm` traegt bewusst keine Kante
   nach `ea-types`. `ReaderBundlePin::from_trust_objects` nimmt eine `RegistryVersion` und
   `reader_trust_age_view` zwei `UnixMillis`, also RE-EXPORTIERT `ea-reader` beide — dieselbe
   Regel, die es in seinem Kopfkommentar fuer `OrganizationId`, `SubjectId` und `Hash32` bereits
   ausschreibt.

9. **Die eingefrorene Freigabe taugt fuer keine echte Aktivierung.**
   `vectors/web-bundle/v1/object/accepted-release.bin` nennt `bundle_hash = 0x91…91` — eine
   erfundene Konstante. KEIN reales Buendel hasht darauf, ohne SHA-256 umzukehren. Die Familie
   traegt damit die Ablehnungsfaelle, aber keinen Positivfall, der Bytes und Hash verbindet. Der
   Browserzeuge bekommt deshalb eine EIGENE, wurzelsignierte Freigabe ueber den TATSAECHLICHEN
   Hash seiner Kandidatenfassung; sie entsteht in `crates/ea-reader/tests/fixtures/mod.rs` und
   liegt als Hex unter `apps/web/tests/e2e/fixtures/`.
   `the_browser_fixtures_are_pinned_to_what_the_rust_witnesses_run` haelt beide Seiten
   zeichengleich — ohne diesen Pin maesse der Browserlauf still etwas anderes als die Rust-Zeugen,
   und beide blieben fuer sich gruen. Eingefroren wird dabei nichts: die Dateien unter `vectors/`
   bleiben unberuehrt.

Zwei kleinere Folgen stehen in den Zeugen selbst: die Schleife ueber die abgewiesenen Freigaben
zerfaellt in ZWEI benannte Tests, weil `unsigned-candidate` und `foreign-root-candidate` zwei
Abschnitte von `docs/traceability/stage-4-fault-points.json` sind und der Stufengate je einen
aufloesbaren Zeugennamen braucht; und `unwrap_err()` ist unbenutzbar, weil es `Debug` auf dem
ERFOLGSTYP verlangt — aus demselben Grund, aus dem Korrektur 1 steht.

- [ ] **Step 1: Write the pinning, revocation and activation witnesses**

```rust
// crates/ea-reader/tests/bundle_release_pinning.rs
//
// Die eingefrorenen Bytes stammen aus `vectors/web-bundle/v1/object/`. Der
// Test baut KEINE neuen Vektoren: die Familie ist seit Stufe 3 eingefroren,
// und die Negativfaelle entstehen im Test, indem einzelne Bytes des positiven
// Vektors gekippt oder Anker ausgetauscht werden.
//
// Der aktive Buendelhash wird ueber `as_bytes()` verglichen und nie direkt:
// `Hash32` traegt bewusst KEIN `Debug` (`crates/ea-types/src/ids.rs`), also
// uebersetzt `assert_eq!` auf `Option<Hash32>` nicht. Dieselbe Regel steht in
// den Aufgaben „Browser-Enrollment: zwei Pflicht-Authenticators und das nicht
// ueberspringbare Fingerprint-Gate" und „Inkrementeller Reader-Sync und
// verifizierter Cursor-Fortschritt in OPFS" bereits ausgeschrieben.

#[test]
fn a_root_signed_release_pins_its_bundle_hash_against_the_vault_anchor() {
    let pin = ReaderBundlePin::from_trust_objects(
        &fixtures::vault_anchor(),
        &[fixtures::frozen_release_object()],
        RegistryVersion::new(6),
    )
    .unwrap();
    assert_eq!(
        pin.active_bundle_hash().map(|hash| *hash.as_bytes()),
        Some(*fixtures::frozen_bundle_hash().as_bytes())
    );
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
    assert_eq!(
        pin.active_bundle_hash().map(|hash| *hash.as_bytes()),
        Some(*fixtures::previous_bundle_hash().as_bytes())
    );
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
    assert_eq!(
        earlier.active_bundle_hash().map(|hash| *hash.as_bytes()),
        Some(*fixtures::frozen_bundle_hash().as_bytes())
    );
}

#[test]
fn an_empty_trust_store_activates_nothing_and_says_so() {
    let pin = ReaderBundlePin::from_trust_objects(
        &fixtures::vault_anchor(),
        &[],
        RegistryVersion::new(6),
    )
    .unwrap();
    assert!(pin.active_bundle_hash().is_none());
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
  // Der Worker entsteht in einem ZWEITEN, einlaeufigen Durchgang: unter
  // rolldown-Vite schliessen sich `iife` und mehrere Einstiege aus, und ein
  // Modulworker waere eine Engine-Wette, die erst die Browser-Matrix einloest.
  expect(config).toMatch(/closeBundle/)
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

`crates/ea-reader/tests/fixtures/mod.rs` bekommt dafür `vault_anchor()` als ZWEITEN Anker NEBEN dem bestehenden `pinned_anchor()`, gebaut mit derselben Pre-Anchor-Rezeptur, aber auf der Identität der eingefrorenen Vektorfamilie: Wurzelseed `0xa0`, `organization_id` `0x90`, Zertifikatshash `0x92`. `pinned_anchor()` bleibt unverändert — fünf bestehende Testdateien verbrauchen ihn auf `0x11`/`0x12`/`0x14`, und ihn umzuschreiben hieße, fremde Zeugen für die Bequemlichkeit dieses Tasks zu bewegen. Die beiden Anker tragen je einen Doc-Kommentar, der ihre Identität und ihren Verbraucherkreis nennt, damit der nächste Task nicht rät.

`from_trust_objects` dekodiert jedes Objekt über `ea_format::decode_exact_object` und den Arm `ParsedArchiveObject::Trust`, nimmt ausschließlich die Subtypen `WebBundleRelease` und `WebBundleRevocation` (alles andere ist kein Fehler, sondern gehört einem anderen Prüfweg), verlangt je Objekt GENAU EINE Signatur — die Kardinalität steht seit Stufe 3 in `validate_signature_count` und wird hier nicht ein zweites Mal erfunden, sondern als bereits geprüft vorausgesetzt und dennoch bezeugt —, prüft sie mit `verify_web_bundle_trust_signature` gegen `anchor.root_public_cose_key()` und `CertificateHash::from(anchor.root_certificate_object_hash())`, und WEIST AB — mit `Err(ReaderBundleError)` und nicht durch Überspringen —, was diese Prüfung nicht besteht oder eine fremde `organization_id` trägt. Der Unterschied ist normativ: ein Objekt eines anderen Subtyps gehört einem anderen Prüfweg und wird still übergangen, ein Objekt DIESER Familie, das seine Wurzelsignatur nicht belegt, ist der Angriff, gegen den §4.1 gebaut ist, und darf nicht als abwesend gelten. Danach gilt: eine Freigabe ist wirksam, wenn `effective_from_registry_version <= at_registry_version`; ein Widerruf ist wirksam unter derselben Bedingung und entfernt die Freigabe, deren `object_hash` — gerechnet mit `ea_crypto::object_hash` über die exakten Objektbytes — seinem `release_object_hash` gleicht. Aktiv bleibt unter den verbleibenden wirksamen Freigaben die mit der höchsten `effective_from_registry_version`; bei Gleichstand die mit dem höheren `issued_at`, und bei erneutem Gleichstand keine, weil zwei gleichzeitig wirksame Freigaben desselben Standes eine Aussage der Wurzel wären, die niemand auflösen darf. Der Verzicht auf ein Widerrufsfeld IM Release ist die Append-only-Entscheidung der Stufe 3 und wird hier ausgenutzt statt umgangen.

`evaluate` ist rein und trifft die Aussage von §4.2 wörtlich: der Service Worker DARF eine neue Bundle-Version nur aktivieren, wenn deren Hash gegen eine gepinnte, Root-signierte `webBundleRelease` aufgeht. Jeder andere Ausgang ist `KeepActive` mit Code, und die zuletzt gültige Version bleibt aktiv. Es gibt keinen Rückgabewert, der „aktivieren, aber mit Warnung" bedeutet.

Ein Punkt bleibt hier ausdrücklich OFFEN und wird nicht stillschweigend entschieden: die WURZELROTATION. `TrustAnchorV1` nennt über `root_certificate_object_hash()` das INITIALE Wurzelzertifikat, und eine Freigabe, die eine rotierte Wurzel unterschrieben hat, geht gegen diesen Anker nicht auf. Solange keine Rotation stattgefunden hat — der Stand dieser Stufe —, ist das Verhalten korrekt und fail-closed: eine solche Freigabe fällt mit `WrongRoot` und die zuletzt gültige Version bleibt aktiv, also verliert niemand Zugriff. Die Auflösung gehört dorthin, wo die Rotation selbst gebaut wird: die Aufgaben der Stufe 5 führen die Wurzelrotationszeremonie, und erst dort steht der aktive Wurzelstand als Kette aus `rootCertificate`-Objekten fest, gegen die eine Freigabe aufgelöst werden könnte. Diese Aufgabe nennt die Lücke, prüft gegen den Anker und erfindet keine Rotationsauflösung.

Die Alterung des Trust-Standes wird nicht erfunden, sondern über das bereits eingefrorene Feld ausgewiesen. `reader_trust_age_view` rechnet `trust_age_ms` als Differenz zwischen dem Zeitpunkt des letzten bezogenen Trust-Standes und dem geprüften `EffectiveNow`, liest die Frist als `PolicyFieldsV1::reader_trust_refresh_ms` aus `SelectedRegistryHead::policy_fields()` und setzt `trust_refresh_overdue` genau dann, wenn die Frist ungleich null ist UND überschritten wurde — `0` heißt „unset", so steht es im Kommentar des CDDL-Felds `reader-trust-refresh-ms`. Die Überschreitung ist eine AUFFORDERUNG zur Aktualisierung und keine Sperre; §4.2 nennt genau diesen Unterschied, weil ein dauerhaft im Datei-Modus betriebenes Gerät einen Widerruf erst beim nächsten Bezug des Trust-Bestandes sieht.

Die beiden Kontrakttypen entstehen in `crates/ea-ui-contracts`, und zwar AUSSCHLIESSLICH im Reader-Ausdruck: `BundleRejectionCodeV1` tritt in `READER_ENUMS_V1` ein, `BundleActivationView` und `ReaderTrustAgeView` bilden den ersten Eintrag der hier angelegten Liste `READER_VIEW_MODELS_V1` (`crates/ea-ui-contracts/src/emit.rs`), die der Task „Integritätszentrierte Reader-Oberfläche in `apps/web` und die Rollengrenze zum Desktop" später erweitert. `SECURITY_ENUMS_V1`, `WRITER_ENUMS_V1` und `VIEW_MODELS_V1` bleiben UNVERÄNDERT, und `apps/desktop/src/bridge/generated-contracts.ts` ändert sich in diesem Task nicht — ein neues Literal dort färbte `apps/desktop/src/bridge/no-hand-written-contracts.test.ts` rot, ohne dass eine Desktop-Entscheidung dahinterstünde; und `crates/ea-ui-contracts/src/lib.rs` re-exportiert die Aufzählung aus der Crate, in der sie definiert ist, statt sie ein zweites Mal zu erklären — dieselbe Regel, die dort für `QuarantineReason`, `SignerRole` und `LocalAuditOutcomeV1` gilt. `BundleRejectionCodeV1` ist in `crates/ea-reader/src/bundle_release.rs` definiert, also bekommt `crates/ea-ui-contracts/Cargo.toml` dafür die Kante `ea-reader.workspace = true`; sie steht mit `Cargo.lock` im Files-Block, weil eine neue Kante zwischen zwei Mitgliedern das Lockfile fortschreibt. Die Richtung ist dieselbe einseitige wie bei `ea-verify` im Task „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate": `ea-ui-contracts` steht in `WASM32_EXEMPT_CRATES`, weil `src/bin/emit-ts.rs` Dateien schreibt, `ea-reader` steht auf der Positivliste, und keine Kante läuft zurück. Die Wurzelkante trägt `default-features = false`, das Merkmal `test-support` von `crates/ea-reader` bleibt damit AUS. Danach läuft `cargo run --locked -p ea-ui-contracts --bin emit-ts` und schreibt `apps/web/src/bridge/generated-contracts.ts` neu; `the_checked_in_reader_file_is_exactly_what_the_reader_emitter_writes` hält den Ausdruck — NICHT `the_checked_in_file_is_exactly_what_the_emitter_writes`, der über `generated_contracts_path()` die DESKTOP-Datei hält und von einer Handänderung an der Web-Datei nichts merkte. `apps/web/src/sw/bundle-pinning.ts` und `service-worker.ts` importieren die Literale ausschließlich von dort und wiederholen keines als Zeichenkette, sonst schlägt der aus `apps/desktop` portierte `no-hand-written-contracts.test.ts` an.

Eine Zeile von `crates/ea-ui-contracts/tests/generated_ts_is_current.rs` zieht dabei mit, und sie steht deshalb im Files-Block: `the_emitted_reader_file_declares_types_and_computes_nothing` verbietet neun Zeichenfolgen im GANZEN Reader-Ausdruck, darunter `sign`, und die Variante `Unsigned` enthält sie. Die Reader-Hälfte bekommt denselben Maskierungshaken, den die Desktop-Hälfte für `signerrole` und `ea-archive-health-hash-signature-chain` bereits führt, und maskiert damit genau `unsigned` — nicht `sign` selbst, sonst verlöre das Verbot seinen Zweck. Der Kommentar über der Reader-Hälfte, der heute „keine Maskierung" behauptet, wird im selben Zug richtiggestellt: er beschrieb einen Stand, keine Regel. Umbenannt wird NICHTS — `web-reader-design.md` §4.2 sagt „nicht signiert", und die deutschen Ausweichnamen tragen dieselbe Zeichenfolge.

Der Worker selbst enthält KEINE Sicherheitslogik. `bundle-pinning.ts` exportiert `activateCandidate(port, candidate)`, reicht die Kandidatenbytes über die wasm-bindgen-Brücke (`crates/ea-reader-wasm/src/bridge.rs`, neue Ausfuhr `evaluate_bundle_candidate` unter `cfg(target_arch = "wasm32")`) an `ReaderBundlePin::evaluate` und wendet auf die Antwort genau zwei Wirkungen an: bei `Activate` `skipWaiting`/`clients.claim` und das Umschalten des Cache-Namens auf die neue `bundleVersion`, bei `KeepActive` das Verwerfen des Kandidaten und das Behalten des bestehenden Caches. Hash und Signatur werden in Rust gerechnet; TypeScript sieht das DTO. Der Quelltextscan im ersten Schritt ist der Wächter dieser Grenze und keine Stilregel.

**Die Richtlinie bewegt sich HIER und nirgends sonst, und ihr Pin zieht im selben Commit nach.** `apps/web/index.html` trägt seit der Aufgabe „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate" die Richtlinie als `<meta http-equiv="Content-Security-Policy">` mit `connect-src 'self'`, und `apps/web/src/app/csp.test.ts` pinnt sie Position für Position. Diese Aufgabe bewegt GENAU EINE Position: `connect-src` bekommt neben `'self'` die KONFIGURIERTE Herkunft des Sync-Servers. Zwei Stellen von `csp.test.ts` ziehen zeichengleich mit: der Eintrag `"connect-src 'self'"` in `EXPECTED_DIRECTIVES` wird zu `connect-src 'self'` gefolgt von genau diesem Origin, und die Zusicherung `expect(directives().join('; ')).not.toMatch(/https?:/)` des Zeugen `keeps the OPFS worker reachable and admits no remote origin` wird durch die schärfere ersetzt, die dieser Task wirklich meint — GENAU EINE entfernte Herkunft steht in der ganzen Richtlinie, sie steht in `connect-src`, und sie ist NICHT der Bundle-Origin. Beide Dateien stehen deshalb im Files-Block dieser Aufgabe und in keinem anderen: `apps/web/src/sw/service-worker.test.ts` verlangt mit `expect(remotes).toEqual([SYNC_SERVER_ORIGIN])` das Gegenteil dessen, was der alte Pin behauptet, und beide laufen in DEMSELBEN `pnpm --dir apps/web test --run`. Die Aufgabe „Inkrementeller Reader-Sync und verifizierter Cursor-Fortschritt in OPFS" ist der erste NUTZER dieser Herkunft und fasst weder die Richtlinie noch ihren Pin an.

`apps/web/src/main.tsx` steht aus dem zweiten Grund im Files-Block: der Trust-Alter-Streifen `TrustAgeBanner.tsx` und die Registrierung des Service Workers werden an die Routentabelle und die Schale gehängt, die dieselbe Aufgabe von Anfang an ausliefert. `apps/web/tests/e2e/bundle-activation.spec.ts` fährt genau diese montierte Schale an.

`apps/web/vite.config.ts` trägt die Trennung des Auslieferungswegs nach §4.1: `base: './'` erzwingt ausschließlich relative Beiwerkspfade — ein absoluter Pfad bände das Bündel an genau einen Origin und machte die Trennung unbenutzbar —, der Service Worker wird in einem ZWEITEN, einläufigen Bau-Durchgang mit `format: 'iife'` und `entryFileNames: 'service-worker.js'`, also stabilem Dateinamen ohne Hash, gebaut — ein gehashter Workername wäre bei jedem Bau ein anderer Registrierungspfad und damit ein Aktivierungspfad, den die Pinnung nicht sieht —, und dieser zweite Durchgang läuft als `closeBundle`-Haken INNERHALB von `apps/web/vite.config.ts`, damit `pnpm --dir apps/web build` ein einziges Kommando bleibt und `apps/web/package.json` unangetastet, und die CSP-Grundlinie ergänzt gegenüber dem Desktop genau zwei Positionen: `script-src 'self' 'wasm-unsafe-eval'`, weil `WebAssembly.instantiate` ohne dieses Schlüsselwort blockiert, und `worker-src 'self'`. `connect-src` nennt den Sync-Server-Origin als konfigurierten Wert und den Bundle-Origin NICHT; das ist die Umkehrung derselben Aussage, die serverseitig als Origin-Positivliste in Stufe 3 steht. Der Sync-Server ist damit kein Bestandteil des Vertrauenspfades für ausgeführten Code.

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

`crates/ea-reader-wasm/src/fetch.rs` exportiert genau zwei Funktionen ueber die Bruecke, beide unter `cfg(target_arch = "wasm32")`: `readerSyncNextRequest` liefert den serialisierten `ReaderRequestV1`, `readerSyncAcceptBatch` nimmt die Antwortbytes und liefert das Ergebnis-DTO. Es entsteht kein dritter Export, der Bytes ohne Cursorpruefung annaehme. Diese Zwei-Export-Bindung hat eine FOLGE, die dieser Task nicht aufloest und nicht aufloesen darf: `ReaderSyncService::rebuild_from_genesis` ist implementiert und bezeugt, hat aber damit KEINEN Browsereinstieg. Wer den dritten Export anlegt, loest die Blockade, die der Task „Integritaetszentrierte Reader-Oberflaeche in `apps/web` und die Rollengrenze zum Desktop“ unter dem Stichwort TEILVERLUST beschreibt; bis dahin steht die Zwei-Export-Grenze und der Ausweg ist nur aus Rust erreichbar.

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
- Create: `crates/ea-reader/tests/verify_fixtures/mod.rs`
- Create: `crates/ea-reader/tests/verify_fixtures/fixtures.rs`
- Modify: `crates/ea-reader/src/lib.rs`
- Modify: `crates/ea-reader/Cargo.toml`
- Modify: `crates/ea-reader-wasm/Cargo.toml`
- Modify: `crates/ea-verify/tests/support/mod.rs`
- Modify: `Cargo.lock`
- Modify: `docs/traceability/stage-4-fault-points.json`
- Modify: `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-4-reader.md`
- Test: `crates/ea-reader/tests/verification_order.rs`
- Test: `crates/ea-reader/tests/missing_grant.rs`
- Test: `crates/ea-reader/tests/historical_expiry.rs`
- Test: `crates/ea-reader/tests/destroyed_stub.rs`
- Test: `crates/ea-reader/tests/pinned_anchor.rs`
- Test: `crates/ea-reader-wasm/tests/verify_browser.rs`

**Interfaces:**
- Consumes: `ea_verify::{verify_archive_observed, VerifyOptions, GATE_ORDER_V1, DECAPSULATION_EVENT_V1, Gate, GateObserver, RecordingObserver, SilentObserver, VerificationReportV1, ObjectResultV1, ObjectResultKindV1, ObjectErrorV1, ChainGapV1, QuarantinedObjectV1, AuthorizedDestructionV1, DestructionStateV1, ServerConfirmationV1, VerifyError}`; `ea_trust::TrustAnchorV1`; `ea_archive::{ArchiveSource, ArchiveInventory, QuarantineReason}`; `ea_crypto::{HpkeRecipientPrivateKey, HpkeSealed, SecretBytes, SecretVec, CEK_SIZE, AEAD_NONCE_SIZE, hpke_open, aead_open, hpke_info, hpke_aad, payload_aad}`; `ea_format::{decode_exact_object, EntryPackageV1, GrantV1, GrantKindV1, DestroyedEntryStubV1, DecodedTrustPayloadV1, FormatError, Parsed}`; `ea_schema::{SchemaRegistry, SchemaDescriptor, DerivedView, PayloadV1}`; `ea_types::{VerificationStatus, EntryStatus, EntryHash, ObjectHash, ChainSequence, KeyThumbprint, DestructionId, UnixMillis}`; `ReaderMode` aus dem Task „wasm32-Reichweite: `ea-reader`, die Brücken-Crate und die geteilten Browserkerne"; die entsperrte Sitzung des Tasks „Browser-Vault: PRF-Envelopes, Schlüsselprofil und die Verwahrung von Anchor und KEM-Schlüssel".
- Produces: `ReaderError` samt seinem `code()`, `PinnedTrustAnchor<'a>`, `ReaderVerifier::classify`, `ReaderClassification` mit `report`, `inventory`, `states`, `state_of`, `gaps`, `verified_entry`, `verified_grant`, die gefüllten `ReaderEntryStateV1`-Werte (der Typ selbst wird im Vault-Task deklariert), `VerifiedEncryptedEntry`, `VerifiedGrantForRecipient`, `decrypt_verified`, `VerifiedDecryptedRecord` samt seiner VOLLSTÄNDIGEN, ausschliesslich AUSLEIHENDEN Klartextfläche `with_plaintext`/`with_payload` und den Abschnitt `verification` in `docs/traceability/stage-4-fault-points.json`.

**`RecipientKeyV1` steht NICHT mehr in der Consumes-Liste, und das ist gemessen.** `crates/ea-verify/src/archive.rs` exportiert den Typ zwar über `pub use archive::{EvidenceRequirementV1, RecipientKeyV1, VerifyOptions, …}`, gibt aber KEINEN öffentlichen Konstruktor heraus: der einzige Weg zu einem Wert führt über `VerifyOptions::with_recipient`, und `VerifyOptions::recipient()` gibt ihn nur als `Option<RecipientKeyV1<'a>>` zurück. Dieser Task nennt den Namen an keiner Stelle einer Signatur, und ein `use ea_verify::RecipientKeyV1` wäre unter `-D warnings` ein unbenutzter Import, also ein roter Clippy-Lauf.

**Die WURZEL-`Cargo.toml` steht NICHT im Files-Block, und die frühere Fassung dieses Blocks irrte darin.** `ea-schema = { path = "crates/ea-schema" }` steht bereits in `[workspace.dependencies]`; die Kante, die dieser Task zieht, ist ausschliesslich `ea-schema.workspace = true` in `crates/ea-reader/Cargo.toml`, und sie schreibt `Cargo.lock` fort. `crates/ea-reader-wasm/Cargo.toml` bekommt dagegen KEINE `ea-schema`-Kante: die Brücke benennt in keiner Signatur einen `ea_schema`-Typ. Was es dort braucht, sind die ENTWICKLUNGSkanten des Browserzeugen — `ea-archive`, `ea-format`, `ea-trust`, `ea-types`, `ea-time`, `ed25519-dalek`, `hex`, `minicbor` —, weil die per `#[path]` eingebundene Fixturekette diese Namen selbst nennt und `crates/ea-reader-wasm/Cargo.toml` heute unter `[dev-dependencies]` nur `ea-verify`, `serde_json` und `wasm-bindgen-test` führt. Jede der acht Zeilen trägt `workspace = true` und eine Begründungszeile, weil `workspace_declares_exact_planned_members_and_shared_dependencies` in `tools/xtask/tests/workspace.rs` die `dev-dependencies` mit derselben Strenge durchläuft wie die `dependencies`. Die wasm32-Positivliste in `verify_quick_commands()` bleibt unberührt: sie führt `ea-schema` in ihrer gemessenen Reihenfolge (`ea-types ea-cbor ea-crypto ea-format ea-schema ea-time ea-trust ea-archive ea-chain ea-verify ea-sync-protocol ea-reader ea-reader-wasm`) bereits, und `every_crates_member_is_classified_for_the_wasm32_gate` vergleicht Mengen und keine Kanten. `tools/xtask/src/main.rs` wird deshalb in diesem Task nicht angefasst.

**`crates/ea-verify/tests/support/mod.rs` steht im Files-Block, und die Änderung ist REIN ADDITIV.** Zwei Ausgänge dieses Tasks sind ohne sie nicht formulierbar. Erstens der Stummel mit auflösbarer Autorisierung: `push_destroyed_stub_for` verdrahtet heute `DestructionId::try_from(&[0x43_u8; 16][..])` und `ObjectHash::try_from(&[0x44_u8; 32][..])` FEST, während `push_destruction` seine Kennung aus `REPORT_DESTRUCTION_MARKER_V1` (`0x91`) ableitet — der Join Stummel → `authorizedDestructions` trifft in `complete_report_archive()` also NICHT, und der Ausgang `autorisiert vernichtet` fiele ersatzlos aus dem Task. Zweitens der Erfolgspfad von `decrypt_verified`: `build_complete_entry` verschlüsselt `COMPLETE_PLAINTEXT_V1 = b"einsatzarchiv-fixture-payload"`, und darauf scheitert `SchemaRegistry` in jedem Fall. Beide Funktionen sind MODULPRIVAT — `push_destroyed_stub_for` hat zwei Aufrufstellen in derselben Datei, `build_complete_entry` vier, `complete_archive_for` drei —, sodass ein zusätzlicher Parameter samt neuen öffentlichen Bauern daneben keine einzige bestehende öffentliche Signatur bewegt. GEBAUT sind: `push_destroyed_stub_authorized_by` als parametrisierter Kern hinter dem unveränderten `push_destroyed_stub_for`; an `DestructionSpec` das Feld `targets: Option<Vec<DestructionTargetV1>>` samt Bauer `targeting(EntryHash, u64)`, weil eine Autorisierung, die den Stummel-Eintrag NICHT nennt, die Prüfkette des Readers (unten) gar nicht schliessen kann; die vier Berichtsbestände `complete_report_archive()`, `report_archive_with_a_resolvable_stub()`, `report_archive_with_a_stub_naming_a_forged_authorization_hash()` und `report_archive_with_a_stub_of_an_authorization_targeting_another_entry()`; und `complete_valid_archive_with_plaintext(&[u8])` neben dem unveränderten `complete_valid_archive()`, mit `COMPLETE_PLAINTEXT_V1` als nun öffentlicher Konstante. Der Zeuge dafür, dass es additiv blieb, sind drei grüne Läufe: `cargo test --locked -p ea-verify`, `-p ea-recovery` und `-p ea-archive-fs` — die drei anderen Crates, die dieselbe Datei per `#[path]` einbinden. Eine geteilte TESTHILFE additiv zu erweitern ist kein Anfassen einer abgeschlossenen Produktionscrate; die Grenze, die dieser Task sich selbst zieht, verläuft an `crates/ea-verify/src/`.

**Die Fixtures dieses Tasks liegen in einem EIGENEN Verzeichnis.** `crates/ea-reader/tests/fixtures/mod.rs` wird NICHT angefasst: sieben Testziele hängen daran, sein Anker steht bewusst auf dem Wurzelseed `[0x11; 32]` und sein `entry_hash()` ist mit einem anderen Wert belegt. `crates/ea-reader/tests/verify_fixtures/mod.rs` bindet stattdessen `#[path = "../../../ea-verify/tests/support/mod.rs"] pub mod verify_support;` ein, in der Bauform, die `crates/ea-reader/tests/sync_support/mod.rs` bereits hält. Jede Fixture-Funktion, deren Rückgabe zweimal gegen denselben Objekthash gehalten wird, läuft über ein `static OnceLock` — der gemessene Grund steht im Kopf von `crates/ea-reader/tests/sync_support/fixtures.rs`: `hpke_seal` zieht seinen ephemeren Schlüssel je Aufruf neu, zwei Aufrufe derselben Fixture liefern verschiedene Grantbytes unter verschiedenen Objekthashes.

Der Rustkern des frueheren Tasks bleibt unveraendert; `web-reader-design.md` §12 fordert fuer ihn ausdruecklich nur neue BINDUNGEN. Die zwei Bindungen sind: der Entkapseler nimmt den X25519-Schluessel aus der Vault-Sitzung statt aus einem nativen `KemDecapsulator`, und der `TrustAnchorV1`, der an `verify_archive_observed` geht, kommt ausschliesslich aus dem Vault und nie aus Trust-Objekten, die in einer geoeffneten Datei mitliegen. **Dieser Task implementiert kein Gate neu.** `crates/ea-verify` besitzt alle neun, `GATE_ORDER_V1` ist ihre einzige Quelle, und kein Gate-Bezeichner wird hier ein zweites Mal als Literal geschrieben. Er faehrt kein OPFS-I/O, keinen Netzaufruf und keine Indizierung.

**`ReaderError` existiert im Arbeitsbaum NICHT und wird hier angelegt.** `grep -rn ReaderError crates/` trifft ausschliesslich `crates/ea-sync-server/src/reader_sync.rs`; `crates/ea-reader` führt heute sechs modulweise Fehlertypen (`ReaderVaultError`, `ReaderBlobError`, `ReaderBundleError`, `EnrollmentError`, `ReaderKeyProfileError`, `ReaderSyncError`), alle in derselben Bauform. `crates/ea-reader/src/verify.rs` legt `ReaderError` in genau dieser Bauform an: `#[derive(Clone, Eq, PartialEq)]`, flaches Enum, `pub const fn code(&self) -> &'static str`, Fremdcodes DURCHGEREICHT, `Display` schreibt AUSSCHLIESSLICH den Code, `Debug` delegiert an `Display`, `impl std::error::Error`, dazu `From` für `VerifyError`, `ea_format::FormatError` und `ea_verify::DecryptionErrorV1` — und NICHT für `ea_trust::TrustError` oder `ea_schema::SchemaError`, wie eine frühere Fassung schrieb: `decrypt_verified` fasst keinen `TrustError` an (der Anker ist bereits dekodiert), und ein `SchemaError` wird nie durchgereicht, weil das Scheitern ALLER Bestimmungen zusammengefaltet `EA-READER-SCHEMA-UNSUPPORTED` ist; `FormatError` entsteht aus `decode_exact_object` über die exakten Zeugenbytes und `DecryptionErrorV1` aus der nachgebauten Rechnung. Zwei eigene Codes kommen dazu und sonst keiner: `EA-READER-WITNESS-STALE` und `EA-READER-SCHEMA-UNSUPPORTED`. `EA-READER-VERIFICATION` ist AUSGESCHLOSSEN — `ReaderSyncError::Verification` belegt ihn bereits (`crates/ea-reader/src/sync.rs`), und ein zweiter Träger desselben Codes wäre genau die Doppelschreibung, die dieses Repositorium verbietet. Der Name kollidiert mit `ea_sync_server::ReaderError`; jede Datei, die beide sieht, aliast, und keine der beiden Crates hängt an der anderen.

- [ ] **Step 1: Write the order, missing-grant, expiry, stub, and pinned-anchor tests**

**Jeder Vergleich über `Hash32`, `EntryHash`, `ObjectHash` oder `KeyThumbprint` läuft als `assert!(a == b)` und niemals als `assert_eq!`/`assert_ne!`.** `hash_newtype!` in `crates/ea-types/src/ids.rs` leitet `Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash` ab — KEIN `Debug` —, und `assert_eq!` verlangt `Debug`, übersetzt also gar nicht erst. Aus demselben Grund sind `fixtures::entry_hash(..)` und `fixtures::pinned_anchor_hash()` FUNKTIONEN und keine Konstanten: es gibt für diese Typen kein `const fn new`. `ChainSequence` ist der Gegenfall und darf `assert_eq!` tragen — `integer_newtype!` leitet `Debug` ab und gibt `pub const fn new` heraus.

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
    // MISST DIE FORM DES PROTOKOLLS, NICHT DIE ZAHL DER ENTKAPSELUNGEN:
    // `protocol.decapsulated()` laeuft je Lauf hoechstens einmal, unabhaengig
    // davon, wie viele Eintraege geoeffnet wurden. Die Zusicherung ist damit
    // trivial wahr und steht nur da, damit ein spaeteres zehntes Ereignis
    // hinter dem neunten Gate auffaellt.
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
// §5.4 sagt „wortgleich in beiden Modi". `classify` LIEST den Modus gar nicht;
// dieser Zeuge pinnt genau diese Nicht-Abhaengigkeit.
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

`each_public_verification_failure()` liefert ausschliesslich Bestände OHNE öffenbaren eigenen Grant, und das ist eine gemessene Auswahl und keine Bequemlichkeit: `archive_with_one_mutated_entry(MUTATED_EIP_SIGNATURE_OFFSET_V1)`, `archive_with_one_mutated_entry(MUTATED_EIP_KEY_THUMBPRINT_OFFSET_V1)`, `archive_with_swapped_predecessors()`, `archive_with_a_missing_middle_entry()`, `archive_with_an_orphan_grant()`, `archive_with_a_mismatched_grant_plan_hash()`, `archive_without_a_recovery_grant()`, `archive_with_one_unknown_writer()` und `eip_with_one_mutated_body_byte()` aus der Fixturekette von `ea-archive`. Die Grants dieser Familie adressieren `recovery_recipient_key_thumbprint()` und können den Tresorabdruck nie treffen, es gibt also garantiert kein `hpke-open`. AUSDRÜCKLICH NICHT dabei ist `isolation_archive(..)`: dieser Bestand trägt drei Einträge, von denen zwei unversehrt bleiben und mit eigenem Grant erfolgreich öffnen — die Abwesenheitszusage würde dort aus einem unbeteiligten Eintrag heraus rot.

```rust
// crates/ea-reader/tests/missing_grant.rs
#[test]
fn a_valid_entry_without_an_own_grant_is_exactly_missing_grant() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let source = fixtures::entry_without_own_grant();
    let classification = fixtures::classify(&source, &vault);
    let entry_hash = fixtures::entry_hash(&source);
    let state = classification.state_of(entry_hash).expect("the entry stays visible");
    assert_eq!(state.verification(), VerificationStatus::MissingGrant);
    assert_eq!(state.entry_state(), EntryStatus::Present);
    // GEMESSEN, nicht gewaehlt: `archive_without_the_own_grant()` ruft
    // `complete_archive_for(.., 1)` auf der Linie mit
    // COMPLETE_GENESIS_SEQUENCE_V1 == 0. Der Bestand hat GENAU EINEN Eintrag.
    assert_eq!(
        state.sequence(),
        ChainSequence::new(verify_support::COMPLETE_GENESIS_SEQUENCE_V1),
    );
    // Kein Befund: fehlender Grant ist KEINE Beschaedigung.
    assert_eq!(classification.report().decryption_errors().len(), 0);
    assert_eq!(classification.report().gaps().len(), 0);
    assert!(classification.report().is_fully_verified());
    // Und kein Zeuge, also ist die Entschluesselung nicht formulierbar.
    assert!(classification.verified_grant(entry_hash).is_none());
}

// Die Zustaende, die design.md §17.4 auseinanderhaelt, an je einem Bestand.
// `Gap` steht hier ueber einem `.eds`-STUMMEL, weil eine Luecke ohne Traeger
// keinen EntryHash hat — siehe die getrennte Lueckenliste unten.
// `UnsupportedSchema` FEHLT in der Tabelle, gemessen: `classify`
// entschluesselt nichts, der Zustand entsteht erst am Rueckgabecode von
// `decrypt_verified` (historical_expiry.rs). `Invalid` steht ZWEIMAL, mit und
// ohne persistierbaren Detailcode.
#[test]
fn missing_grant_gap_unknown_key_and_invalid_never_collapse() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let cases = fixtures::the_measured_states();
    assert!(cases.len() >= 5);
    for case in cases {
        let classification = fixtures::classify(case.source, &vault);
        let state = classification.state_of(case.key).expect(case.label);
        assert_eq!(state.verification(), case.expected, "{}", case.label);
        assert_eq!(state.detail_code(), case.expected_code, "{}", case.label);
        // DAS ZEUGENPAAR GIBT ES GENAU FUER `verifiziert` — auch `unbekannter
        // Schluessel`, dessen Eintrag sein objectResult behaelt, bekommt keins.
        let witnessed = case.expected == VerificationStatus::Verified;
        assert_eq!(classification.verified_entry(case.key).is_some(), witnessed, "{}", case.label);
        assert_eq!(classification.verified_grant(case.key).is_some(), witnessed, "{}", case.label);
    }
}

// Eine Luecke OHNE Traeger ist KEINE Zustandszeile, sondern eine
// SEQUENZadressierte Zeile. `archive_with_a_missing_middle_entry()` laesst
// MISSING_MIDDLE_SEQUENCE_V1 aus; zu dieser Sequenz existiert per Definition
// kein Objekt und damit weder EntryHash noch ObjectHash. ZWEI Luecken, gemessen:
// die Kettenfamilie beginnt auf FIRST_ENTRY_SEQUENCE_V1 == 1, Sequenz NULL
// fehlt ihr ohnehin (GENESIS_GAP_SEQUENCE_V1).
#[test]
fn a_gap_without_a_stub_is_reported_by_sequence_and_never_as_an_entry_row() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let source = fixtures::archive_with_a_gap_without_a_stub();
    let classification = fixtures::classify(source, &vault);
    let sequences: Vec<ChainSequence> =
        classification.gaps().map(|gap| gap.from_sequence()).collect();
    assert_eq!(
        sequences,
        vec![
            ChainSequence::new(verify_support::GENESIS_GAP_SEQUENCE_V1),
            ChainSequence::new(verify_support::MISSING_MIDDLE_SEQUENCE_V1),
        ],
    );
}
```

```rust
// crates/ea-reader/tests/pinned_anchor.rs
#[test]
fn a_substituted_archive_with_its_own_complete_trust_chain_fails_here() {
    // Der Bestand ist in sich vollstaendig: eigener Root, eigene Registry,
    // eigene Writer-Zertifikate, eigene Signaturen. Er ist nur nicht UNSERER.
    // INVERTIERT gebaut: nicht der Bestand ist fremd, sondern der TRESOR --
    // `RegistryLineBuilder` haelt ROOT_SECRET, organization() und chain_id()
    // als Konstanten, ein zweiter eigenstaendiger Anker ist aus der geteilten
    // Kette nicht zu bekommen.
    let vault = fixtures::foreign_pinned_vault();
    let classification = fixtures::classify(&fixtures::complete_archive(), &vault);
    assert!(!classification.report().is_fully_verified());
    assert_eq!(classification.report().object_results().len(), 0);
    assert!(classification.states().is_empty());
    // ACHTUNG, GEMESSEN: alle sechs Mangelfelder sind LEER. Der Lauf steigt
    // nach `protocol.enter(Gate::Trust)` mit `return report.seal()` aus, das
    // Protokoll ist exakt ["format", "trust"], und `pipeline_completed` ist
    // falsch. Eine Zusicherung auf ein NICHT leeres Fehlerfeld waere rot.
    assert_eq!(classification.report().signature_errors().len(), 0);
}

#[test]
fn the_anchor_used_is_the_vault_anchor_and_not_the_one_in_the_archive() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let anchor = PinnedTrustAnchor::from_vault(&vault);
    assert!(anchor.as_trust_anchor().trust_anchor_hash() == fixtures::pinned_anchor_hash());
    assert!(fixtures::foreign_anchor_hash() != fixtures::pinned_anchor_hash());
}
```

`historical_expiry.rs` hält drei Zusagen fest: ein Zeuge ist an den Lauf gebunden, in dem er entstand; ein gefälschter historischer Grant hinterlässt bis Stufe 5 NICHTS — der Eintrag bleibt `Verified`, sein initialer Grant entkapselt, und WELCHER Grant der Zeuge ist, entscheidet der Artfilter von `own_grant`; und `decrypt_verified` trägt seine Ausgänge `EA-READER-SCHEMA-UNSUPPORTED` und den vollen Erfolg über dem Genesis-Vektor (Schritt 3). `destroyed_stub.rs` hält fest, dass für einen `.eds` `decrypt_verified` in keinem seiner Ausgänge FORMULIERBAR ist — er bekommt kein `objectResult`, kein Grant nennt seinen `entryHash`, kein Zeuge entsteht — und dass `autorisiert vernichtet` nur über die volle dreigliedrige Prüfkette erreicht wird. Eine Zusage auf die ABWESENHEIT von `hpke-open` ist über dem Berichtsbestand NICHT formulierbar: er trägt vier Einträge mit eigenem Grant, `claim_own_grants` öffnet sie, und das archivweite Protokoll enthält `hpke-open` in jedem Ausgang.

```rust
// crates/ea-reader/tests/historical_expiry.rs
#[test]
fn a_forged_historical_grant_leaves_no_trace_at_all() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let source = fixtures::archive_with_a_forged_historical_grant();
    let mut observer = RecordingObserver::new();
    let classification = ReaderVerifier::new(ReaderMode::Server, fixtures::EFFECTIVE_NOW)
        .classify(&source, &vault, &mut observer).unwrap();
    let entry_hash = fixtures::entry_hash(&source);
    let state = classification.state_of(entry_hash).unwrap();
    // ANTI-LEERLAUF: der gefaelschte Grant liegt WIRKLICH im Bestand —
    // ZWEI Grants auf dem Genesis-Eintrag, der initiale bleibt liegen.
    assert_eq!(classification.inventory().grants().len(), 2);
    // KEIN Code, KEIN Befund, KEIN Unterschied: `own_grant` filtert auf
    // GrantKindV1::Initial und sieht den historischen Grant nie. Der Eintrag
    // ist deshalb `Verified` und NICHT `MissingGrant`.
    assert_eq!(state.verification(), VerificationStatus::Verified);
    assert_eq!(state.detail_code(), None);
    assert_eq!(classification.report().decryption_errors().len(), 0);
    assert_eq!(classification.report().signature_errors().len(), 0);
    assert!(classification.report().is_fully_verified());
    // Das Protokoll ist woertlich dasselbe wie ueber `complete_archive()`.
    let mut untouched = RecordingObserver::new();
    ReaderVerifier::new(ReaderMode::Server, fixtures::EFFECTIVE_NOW)
        .classify(&fixtures::complete_archive(), &vault, &mut untouched).unwrap();
    assert_eq!(observer.events(), untouched.events());
    // WELCHER Grant der Zeuge ist: die Faelschung liegt unter dem KLEINEREN
    // Objekthash und steht in `inventory.grants()` VOR dem initialen. Liesse
    // `own_grant` den Artfilter fallen, bliebe alles oben gruen und der Zeuge
    // truege die Faelschung — sie kapselt auf nichts und fiele mit
    // EA-VERIFY-DECRYPT-CEK-UNWRAP-FAILED; der initiale Grant entkapselt bis
    // zur Schemabestimmung.
    assert!(classification.inventory().grants()[0].object_hash()
        == fixtures::forged_historical_grant_object_hash());
    let entry = classification.verified_entry(entry_hash).unwrap();
    let grant = classification.verified_grant(entry_hash).unwrap();
    let refused = decrypt_verified(entry, grant, &vault, &SchemaRegistry::v1(),
        fixtures::EFFECTIVE_NOW, &mut SilentObserver).expect_err("kein Schema");
    assert_eq!(refused.code(), "EA-READER-SCHEMA-UNSUPPORTED");
}

#[test]
fn a_witness_from_an_earlier_run_is_refused() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let source = fixtures::complete_archive();
    let first = fixtures::classify_at(&source, &vault, fixtures::EFFECTIVE_NOW);
    let entry_hash = fixtures::entry_hash(&source);
    let entry = first.verified_entry(entry_hash).expect("der Bestand traegt einen Zeugen");
    let grant = first.verified_grant(entry_hash).expect("und einen eigenen Grant");
    let refused = decrypt_verified(
        entry,
        grant,
        &vault,
        &SchemaRegistry::v1(),
        fixtures::LATER_EFFECTIVE_NOW,
        &mut SilentObserver,
    )
    .err()
    .expect("ein Zeuge gilt fuer den Lauf, in dem er entstand");
    assert_eq!(refused.code(), "EA-READER-WITNESS-STALE");
}
```

```rust
// crates/ea-reader/tests/destroyed_stub.rs
#[test]
fn a_stub_reaches_no_decapsulation_in_either_outcome() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    for (label, source, entry_state) in [
        ("autorisiert vernichtet", fixtures::stub_with_resolvable_authorization(),
         EntryStatus::AuthorizedDestroyed),
        ("ungeklaerte Luecke: Kennung zeigt auf nichts",
         fixtures::stub_without_resolvable_authorization(), EntryStatus::UnexplainedGap),
        ("ungeklaerte Luecke: gefaelschter Autorisierungshash",
         fixtures::stub_naming_a_forged_authorization_hash(), EntryStatus::UnexplainedGap),
        ("ungeklaerte Luecke: Autorisierung nennt einen anderen Eintrag",
         fixtures::stub_of_an_authorization_targeting_another_entry(),
         EntryStatus::UnexplainedGap),
    ] {
        let mut observer = RecordingObserver::new();
        let classification = ReaderVerifier::new(ReaderMode::Server, fixtures::EFFECTIVE_NOW)
            .classify(source, &vault, &mut observer).unwrap();
        let key = fixtures::stub_entry_hash(source);
        // ANTI-LEERLAUF: der Lauf FAEHRT durch die Entkapselung — die vier
        // Eintraege mit eigenem Grant werden von `claim_own_grants` geoeffnet.
        assert!(observer.events().contains(&DECAPSULATION_EVENT_V1), "{label}");
        // Was der Stummel zusagt: kein objectResult, kein Grant auf seinen
        // entryHash, kein Zeuge — `decrypt_verified` ist fuer ihn nicht
        // formulierbar.
        let stub_object_hash = classification.inventory().destroyed()[0].object_hash();
        assert!(classification.report().object_results()
            .all(|result| result.object_hash() != stub_object_hash), "{label}");
        assert!(classification.inventory().grants().iter()
            .all(|grant| grant.value().grant_body().fields().entry_hash != key), "{label}");
        assert!(classification.verified_entry(key).is_none(), "{label}");
        assert!(classification.verified_grant(key).is_none(), "{label}");
        let state = classification.state_of(key).unwrap();
        assert_eq!(state.entry_state(), entry_state, "{label}");
        // BEIDE Dimensionen bleiben getrennt (design.md §17.4): auch der
        // autorisiert vernichtete Stummel hat KEIN objectResult und steht in
        // einem gaps-Intervall, ist in der Verifikationsdimension also `Gap`.
        assert_eq!(state.verification(), VerificationStatus::Gap, "{label}");
    }
}

// Die PRUEFKETTE, aus der `autorisiert vernichtet` entsteht: alle vier
// Bestaende fuehren DENSELBEN Vorgang, der Bericht traegt ueber keinen einen
// zusaetzlichen Befund, und jeder Luecken-Bestand bricht GENAU EIN Glied.
#[test]
fn the_authorized_destruction_is_reached_only_through_the_full_chain() {
    // links_of(..) -> [Kennung trifft, Hash trifft, Autorisierung nennt den
    // Stummel-Eintrag]; gemessen: aufloesbar [true, true, true], Kennung auf
    // nichts [false, false, true], gefaelschter Hash [true, false, true],
    // anderer Eintrag [true, true, false].
}
```

- [ ] **Step 2: Run the tests and verify that classification and decryption do not exist**

Run: `cargo test --locked -p ea-reader --test verification_order --test missing_grant --test historical_expiry --test destroyed_stub --test pinned_anchor`

Expected: FAIL. `crates/ea-reader` traegt nach dem Task „wasm32-Reichweite: `ea-reader`, die Brücken-Crate und die geteilten Browserkerne" ausschliesslich `ReaderMode` und den Re-Export von `ea_verify::GATE_ORDER_V1` und nach dem Task „Browser-Vault: PRF-Envelopes, Schlüsselprofil und die Verwahrung von Anchor und KEM-Schlüssel" die Vault-Flaeche; `ReaderError`, `PinnedTrustAnchor`, `ReaderVerifier`, `ReaderClassification`, `VerifiedEncryptedEntry`, `VerifiedGrantForRecipient` und `decrypt_verified` existieren nicht. Das ist ein roter Uebersetzungslauf und keine fehlende Crate — die Crate steht seit dem Reichweiten-Task im Arbeitsbereich, weshalb dieser Task hier und nicht davor liegt.

- [ ] **Step 3: Bind the vault anchor, the vault key, and the typed decryption witnesses**

**Der Anker ist ein Typ und keine Uebergabe — und er FEHLT NIE.** `crates/ea-reader/src/anchor.rs` traegt genau einen Wert, der nur EINEN Weg in die Welt hat:

```rust
/// Der beim Enrollment im Vault gepinnte Root-Anchor.
///
/// Es gibt KEINEN Konstruktor aus rohen Bytes und KEINEN aus einer
/// [`ea_archive::ArchiveSource`]. Das ist die ganze Zusage von
/// `web-reader-design.md` §5.3: Trust-Objekte, die in der geoeffneten Datei
/// mitgeliefert werden, begruenden fuer sich kein Vertrauen. Waere hier ein
/// `from_bytes`, waere §5.3 eine Bitte statt einer Schranke.
///
/// AUSLEIHEND und INFALLIBEL, beides gemessen: [`UnlockedVault`] fuehrt
/// `pinned_anchor` als PFLICHTFELD, `ReaderVault::unlock` baut es unbedingt
/// aus `decode_trust_anchor(&contents.pinned_anchor_exact_bytes)?`. Eine
/// entsperrte Sitzung ohne Anker ist nicht konstruierbar. Und
/// [`ea_trust::TrustAnchorV1`] traegt kein einziges `derive`; ein besitzender
/// Wert waere nur ueber einen ZWEITEN vollstaendigen Dekodierlauf je
/// `classify` zu haben — Kosten ohne Gegenwert.
pub struct PinnedTrustAnchor<'a>(&'a TrustAnchorV1);

impl<'a> PinnedTrustAnchor<'a> {
    #[must_use]
    pub const fn from_vault(session: &'a UnlockedVault) -> Self;

    #[must_use]
    pub const fn as_trust_anchor(&self) -> &'a TrustAnchorV1;
}
```

**`EA-READER-ANCHOR-MISSING` entfällt ersatzlos, und die frühere Fassung dieses Tasks irrte darin.** Sie schrieb `from_vault` als `Result` mit zwei Fehlerarmen — „die Sitzung führt keinen Anker" und „der durchgereichte Code von `decode_trust_anchor`" —, und beide sind DURCH KONSTRUKTION unerreichbar: `crates/ea-reader/src/vault.rs` deklariert `pinned_anchor: TrustAnchorV1` ohne `Option`, und `pinned_anchor_bytes()` gibt die `exact_bytes()` eines bereits ERFOLGREICH dekodierten Ankers zurück. Ein Fehlerarm, den kein Zeuge färben kann, ist kein fail-closed-Verhalten, sondern ein unbelegter Zweig, den die Oberfläche später behandeln müsste, ohne ihn je zu sehen. Der Lebensdauerparameter bleibt lokal in `classify` und erscheint in KEINER anderen öffentlichen Signatur — `ReaderClassification` trägt keinen. Fällt die Ausleihform später, ist ein besitzender Typ über `decode_trust_anchor(session.pinned_anchor_bytes())?` jederzeit nachrüstbar, und die `compile_fail`-Zusage ändert sich dabei nicht.

Der Beweis, dass es keinen anderen Weg gibt, ist ein `compile_fail`-Doctest an der Struktur, in derselben Bauform, in der `crates/ea-key-provider/src/lib.rs` und `crates/ea-crypto/src/secret.rs` ihre Nichtexportierbarkeit belegen; er faehrt in `cargo test --workspace --doc --all-features --locked`, dem einzigen Kommando aus `verify_quick_commands()`, das Doctests ueberhaupt anfasst. **Daneben steht EIN positiver ```-Doctest, der jeden dort benutzten Pfad einmal erfolgreich auflöst.** Ohne ihn belegen die drei Negativblöcke (`from_bytes`, `from_source`, `Clone`) nur, dass ein Import kaputt ist — ein `compile_fail`, der aus dem falschen Grund nicht übersetzt, ist der Musterfall des Zeugen, der grün ist, weil er nichts misst.

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
    /// Der Fehler von [`ea_verify::verify_archive_observed`] und der von
    /// `ea_archive::ArchiveInventory::build`. Ein Befund ueber ein EINZELNES
    /// Objekt ist nie ein `Err` — dieselbe Regel, die
    /// `crates/ea-verify/src/lib.rs` ausschreibt.
    pub fn classify(
        &self,
        source: &dyn ArchiveSource,
        session: &UnlockedVault,
        observer: &mut dyn GateObserver,
    ) -> Result<ReaderClassification, ReaderError>;
}
```

`classify` baut `VerifyOptions::new(self.effective_now).with_recipient(session.kem_key_thumbprint(), session.kem_private_key())` — und das ist die erste der zwei geforderten Bindungen. `session.kem_private_key()` liefert `&HpkeRecipientPrivateKey` aus dem WASM-Speicher der entsperrten Sitzung; es gibt keinen `KemDecapsulator`-Trait und keinen nativen Schluesselspeicher mehr, weil `web-reader-design.md` §11.3 den nativen Reader-Key-Provider ersatzlos streicht. Der Anker ist `PinnedTrustAnchor::from_vault(session).as_trust_anchor()` — die zweite Bindung.

**`ReaderClassification` BESITZT ein eigenes `ArchiveInventory`, und das ist eine benannte Kosten­entscheidung.** Der Bericht kennt über Objekte NUR den `ObjectHash`: `ObjectResultV1` hat genau vier Zugriffe — `object_hash`, `object_type`, `result`, `server_confirmation` — und weder `entry_hash` noch `chain_sequence`; `ObjectErrorV1` trägt `object_hash` und `code`; `ChainGapV1` trägt `chain_id` und ein Sequenzintervall. Es gibt in `crates/ea-verify` keinen Accessor, der einen `ObjectHash` auf einen `EntryHash` abbildet. `classify` baut deshalb selbst `ea_archive::ArchiveInventory::build(source)` — öffentlich, aus `ea-reader` erreichbar, weil `ea-archive` seit dem Sync-Task in `crates/ea-reader/Cargo.toml` steht — und behält es. Daraus entstehen drei Dinge auf einmal: der Join `ObjectHash → (EntryHash, ChainSequence)` je `.eip` und je `.eds`, der Join eigener Grant → Eintrag, und die EXAKTEN Bytes für `verified_entry`/`verified_grant`, also ohne eine dritte Kopie. Der Preis ist ein zweiter voller Parserlauf über denselben Bestand je `classify` — Rechenzeit und Spitzenspeicher, die in der 50.000-Paket-Messung des Tasks „Verschlüsselter invertierter Index in OPFS, Suche, Schemakompatibilität und die GEMESSENE 50.000-Paket-Schwelle" sichtbar werden. Die billigere Alternative wäre, `ea-verify` sein Inventar herausgeben zu lassen; das ist eine Erweiterung einer abgeschlossenen Stufe-1-Crate und hier ausgeschlossen. Weil `ReaderClassification` das Inventar BESITZT, trägt es keinen Lebensdauerparameter und ist an `source` nicht gebunden.

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

Kein Literal dieser drei Aufzaehlungen wird hier geschrieben: `VerificationStatus` und `EntryStatus` stehen seit Stufe 1 in `crates/ea-types/src/status.rs` mit genau den sechs beziehungsweise drei Begriffen des §17.4, `ServerConfirmationV1` in `crates/ea-verify/src/report.rs`.

**Die Vorrangordnung trennt nach OBJEKTART, und das ist die wichtigste Korrektur dieses Tasks.** Die frühere Fassung schrieb: „ein Objekt in `format_errors`, `quarantined_objects`, `signature_errors` oder `evidence_errors` ist `Invalid`". Das ist über `signature_errors` und `decryption_errors` FALSCH, und zwar gemessen: `claim_own_grants` in `crates/ea-verify/src/archive.rs` schreibt `report.signature_errors.insert(ObjectErrorV1::new(grant.object_hash(), error.code()))`, und `record_decapsulation` in `crates/ea-verify/src/recipient.rs` schreibt `report.decryption_errors.insert(ObjectErrorV1::new(grant.object_hash(), error.code()))` — beide unter dem Objekthash des GRANTS, während der Eintrag selbst sein `ObjectResultKindV1::Valid` behält. Ein gültiger Eintrag mit unbrauchbarem eigenem Grant erschiene unter der alten Regel als `ungültig`; das verbietet `design.md` §17.4 ausdrücklich (`fehlender Grant` und `unbekannter Schlüssel` sind eigene Begriffe NEBEN `ungültig`) und `web-reader-design.md` §9 wörtlich: „Fehlender eigener Grant bleibt exakt `fehlender Grant` und wird nicht als Beschädigung dargestellt". `signature_errors` hat allein in `crates/ea-verify` sieben Einfügestellen über Einträge, Grants, Quittungen und Vernichtungen — die Objektart ist ohne den Join über das Inventar aus dem Feld nicht ablesbar.

Die Abbildung wertet deshalb ZWEI Adressräume getrennt aus, in dieser Ordnung:

1. Über dem EINTRAGS-Objekthash: `format_errors` → `Invalid`; `quarantined_objects` → `Invalid`; `signature_errors` → `Invalid`; `evidence_errors` → `Invalid`.
2. Über dem GRANT-Objekthash des EIGENEN Grants: `decryption_errors` → `UnknownKey` mit `detail_code = code()`; `signature_errors` → `MissingGrant` mit `detail_code = code()` — der Eintrag ist gültig, nur der Grant unbrauchbar.
3. Danach erst: `.eds`-Stummel, dessen Sequenz in einem `gaps`-Intervall liegt → `Gap`; ein `ObjectResultV1` mit `ObjectResultKindV1::Valid` ohne eigenen Grant → `MissingGrant` mit `detail_code = None`; ein Eintrag ganz ohne `ObjectResultV1` → `Invalid` mit `detail_code = None`; alles Übrige → `Verified`. `UnsupportedSchema` steht NICHT in dieser Ordnung — siehe die Schemabestimmung unten.

`server_confirmation` kommt in JEDEM Zweig aus `object_results[..].server_confirmation()`, ersatzweise `NotServerConfirmed`. Die Zusage, auf der die Ordnung steht, ist SCHWÄCHER als die frühere Fassung behauptete: der Kopfkommentar von `crates/ea-verify/src/lib.rs` sagt „Ein Objekt erscheint ENTWEDER in `objectResults` ODER in genau einem Fehler-/Quarantänearray, niemals in beidem" — für den malformed-Fall stehen `format_errors` UND `quarantined_objects` paarweise über demselben Hash, wie der Doc-Kommentar von `VerificationReportV1::format_errors` selbst ausschreibt. Praktisch folgenlos, weil ein `format_errors`-Objekt gar keinen `EntryHash` trägt und deshalb überhaupt keine Zustandszeile erzeugt — aber die Ordnung darf sich nicht auf die stärkere Fassung berufen.

**`detail_code` trägt ausschliesslich Werte der persistierbaren Tabelle.** `crates/ea-reader/src/entry_state.rs` führt `const PERSISTED_DETAIL_CODES_V1: [&str; 25]` mit fester Stelligkeit und ausschliesslich `EA-VERIFY-*`-Codes, und `put_entry_state` weist jeden anderen Code mit `ReaderVaultError::Contents` / `EA-READER-VAULT-CONTENTS` ab. Daraus folgen zwei Schranken, die hier und nicht erst im Persistenz-Task fallen: für `quarantined_objects` bleibt `detail_code == None`, weil `QuarantinedObjectV1` einen `QuarantineReason` trägt und keinen Code — `QuarantineReason::as_str()` liefert `"malformed"|"duplicate"|"conflicting"|"unattributable"`, ein Schemaliteral und KEIN EA-Code. Und kein `EA-READER-*`-Code gelangt je in `detail_code`; `EA-READER-SCHEMA-UNSUPPORTED` ist der Rückgabecode von `decrypt_verified` und die spätere Begründung für `VerificationStatus::UnsupportedSchema` im Index-Task, nicht dessen Detailgrund. Ein Zustand, den die Tasks „Verschlüsselter invertierter Index in OPFS …" und „Sitzungssperre, Zeroize, authenticator-bestätigter Einzelexport und signiertes lokales Audit" nicht ablegen könnten, wäre wertlos.

**`ObjectResultKindV1::AuthorizedDestroyed` ist ein TOTER Zweig, und die frühere Fassung stützte sich darauf.** Sie schrieb: „`ObjectResultKindV1::AuthorizedDestroyed` setzt `EntryStatus::AuthorizedDestroyed`". Gemessen wird diese Variante workspaceweit NIRGENDS konstruiert: `confirm_entries` in `crates/ea-verify/src/archive.rs` ist der einzige Erzeuger von `report.object_results` — sein eigener Doc-Kommentar sagt „HIER UND NUR HIER entstehen die `objectResults`" — und setzt ausnahmslos `ObjectResultKindV1::Valid`; der einzige LESER der Variante ist ein Filter in `crates/ea-archive-fs/src/health.rs`. Ein `.eds` wird ausserdem gar kein Kettenknoten, was der Kommentarblock vor `protocol.enter(Gate::ChainPosition)` fail-closed ausschreibt.

Die Abbildung leitet `EntryStatus::AuthorizedDestroyed` deshalb aus einer PRÜFKETTE ab und nicht aus dem Ergebnisfeld — `stub_destruction_is_authorized` in `crates/ea-reader/src/verify.rs`, drei Glieder, jedes fail-closed: (1) `DestroyedEntryStubV1::destruction_id()` trifft einen Eintrag von `report.authorized_destructions()` (läuft als `impl ExactSizeIterator<Item = &AuthorizedDestructionV1>`); (2) `stub.destruction_authorization_object_hash()` ist GLEICH dem `authorization_object_hash()` dieses Eintrags — dem Hash, den die signierte Transitionskette in `ea_verify::destruction::resolve` authentifiziert hat; (3) das Trust-Objekt unter diesem Hash dekodiert (`inventory.trust()` liegt aufsteigend nach Objekthash, `binary_search_by_key` über `Parsed::object_hash`) zu `DecodedTrustPayloadV1::DestructionAuthorization`, dessen `destruction_id` die des Stummels ist und dessen `targets` den `entry_hash()` des Stummels unter GENAU seiner `chain_sequence` nennen. Schliesst sich die Kette, ist der Zustand `AuthorizedDestroyed`; bricht ein Glied, `UnexplainedGap`. **Ein Join allein über die `destructionId` — so schrieb es eine frühere Fassung — TRÄGT NICHT, und das ist gemessen:** `ea-verify` liest weder die Ziele einer Autorisierung noch die zwei Felder des Stummels; ein `.eds`, der die echte Kennung eines abgelegten Vorgangs mit einem erfundenen Autorisierungshash oder auf einem Eintrag nennt, den die Autorisierung nie meinte, passiert die neun Gates OHNE Befund (`the_authorized_destruction_is_reached_only_through_the_full_chain` hält fest, dass die Befundzahlen über allen vier Berichtsbeständen gleich sind). Über die Kennung allein erschiene ein solcher Stummel als `autorisiert vernichtet` — die Verfälschung in die LAXERE Richtung, die ein fail-closed-Reader gerade nicht zulassen darf. Dass `report.authorized_destructions` überhaupt befüllbar ist, ist ebenfalls gemessen: `record_destructions` aus `crates/ea-verify/src/destruction.rs` wird aus `archive.rs` gerufen und schreibt mit `report.authorized_destructions.insert(destruction_id, entry)` hinein. Die Kette verletzt die Zusage dieses Tasks nicht, kein Gate neu zu bauen — sie liest den Bericht gegen das Inventar, das `classify` ohnehin besitzt, und prüft keine Signatur nach. Wäre sie zu streng, erschiene jeder Stummel als `ungeklärte Lücke`: sichtbar falsch in der Oberfläche des Tasks „Integritätszentrierte Reader-Oberfläche in `apps/web` und die Rollengrenze zum Desktop", aber ohne Sicherheitswirkung. Die kryptographische Auflösung der `destructionAuthorization` gegen ihre Signaturkette bleibt Stufe 5; `ea-trust` exportiert dafür nichts.

**`VerificationStatus::Gap` ist an einem `EntryHash` nur über einen `.eds`-Stummel formulierbar.** `crates/ea-chain/src/chain.rs` definiert `ChainGap` als Intervall FEHLENDER Sequenzen; zu einer solchen Sequenz existiert per Definition kein Objekt und damit weder ein `EntryHash` noch ein `ObjectHash`. `ReaderEntryStateV1::new` verlangt aber `entry_hash`, `object_hash` UND `sequence` — eine Lücke ohne Träger ist als Zustandszeile schlicht nicht schreibbar. `Gap` wird deshalb ausschliesslich für Zeilen gesetzt, deren Träger ein `.eds`-Stummel ist: `DestroyedEntryStubV1` führt `entry_hash()` und über sein `signed_manifest()` die `chain_sequence` selbst, und weil `ea-verify` ihn ausdrücklich NICHT als Kettenknoten führt, liegt seine Sequenz garantiert in einem `gaps`-Intervall — in der Fixture gemessen als `REPORT_GAP_FROM_V1 == REPORT_GAP_THROUGH_V1 == REPORT_DESTROYED_STUB_SEQUENCE_V1`. Für eine Lücke OHNE Stummel gibt `ReaderClassification` eine getrennte, SEQUENZadressierte Liste `gaps()` heraus und KEINE `ReaderEntryStateV1`-Zeile. Diese zweite Zugriffsform ist keine Zugabe: die Oberfläche des Tasks „Integritätszentrierte Reader-Oberfläche …" muss trägerlose Lücken anzeigen, und fiele sie hier weg, wanderte sie unverändert dorthin.

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
    object_hash: ObjectHash,
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

`verified_entry` und `verified_grant` geben einen Zeugen NUR heraus, wenn der Bericht fuer dieses Objekt `ObjectResultKindV1::Valid` fuehrt, kein Fehlerfeld es nennt und `decryption_errors` seinen Grant nicht traegt. Damit ist die Aussage „nur `VerifiedEncryptedEntry` zusammen mit `VerifiedGrantForRecipient` erreicht den HPKE-Entkapseler" aus `web-reader-design.md` §9 eine TYPZUSAGE und keine Disziplin. Die Grantauswahl baut das Prädikat von `ea_verify::own_grant` ZEICHENGLEICH nach — `fields.kind == GrantKindV1::Initial && fields.entry_hash == entry_hash && fields.recipient_key_thumbprint == key_thumbprint`, als `find` über `inventory.grants()` in aufsteigender Objekthashordnung —, weil `own_grant` `pub(crate)` ist und aus `ea-reader` nicht gerufen werden kann. Läuft die Auswahl hier anders als dort, gäbe `classify` einen Zeugen über einen Grant heraus, den die Pipeline gar nicht geprüft hat.

**`effectiveNow` ist der Wert DES LAUFS, und die frühere Begründung dieser Prüfung trug nicht.** Sie schrieb, eine Toleranz „wäre eine zweite, schwächere Frist neben der des Registrierungskopfes". Das kehrt das Verhältnis um: `ea_trust::select_registry_head` misst gegen ein not-before/not-after-INTERVALL und ist damit selbst eine Toleranz. Die tragende Begründung ist eine andere und steht ab jetzt dort: ein Zeuge gilt für den Lauf, in dem er entstand, weil Gate `recipient-grant` seine Nutzungsfrist gegen genau diesen Wert gemessen hat. Der Wert existiert genau einmal je Lauf — `VerifyOptions::effective_now()` ist wortgleich `os_wall_clock()`, mit dem Doc-Kommentar „GLEICH der uebergebenen Uhr, und das ist der einzige erreichbare Wert" —, und die Sitzung reicht denselben Wert an `decrypt_verified` weiter, statt ihn je Entkapselung neu aus der Wirtsuhr zu lesen. Ein je Entkapselung frisch gelesener Wert wäre in Millisekundenauflösung praktisch nie gleich und machte die Entschlüsselung unmöglich. Der Zeuge ist folglich der LAUFÜBERGREIFENDE Fall: `classify` mit T1, `classify` mit T2, Zeuge aus T1 gegen T2 → `EA-READER-WITNESS-STALE`. Die Kehrseite ist benannt und gehört woanders hin: friert eine lange Sitzung ihren `effective_now` ein, bemerkt sie das Ablaufen eines Registrierungskopfes nicht; die Neuklassifikation bei Sitzungsalter besitzt der Task „Integritätszentrierte Reader-Oberfläche in `apps/web` und die Rollengrenze zum Desktop".

```rust
/// Oeffnet GENAU EINEN Eintrag.
///
/// # Errors
/// `EA-READER-WITNESS-STALE`, wenn `effective_now` von dem Lauf abweicht, in
/// dem die Zeugen entstanden. `EA-READER-SCHEMA-UNSUPPORTED`, wenn keine der
/// Schemabestimmungen den Klartext traegt. Ausserdem
/// `EA-VERIFY-DECRYPT-CEK-UNWRAP-FAILED` und
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

Die Rechnung ist die von `crates/ea-verify/src/recipient.rs::open_entry`, Schritt fuer Schritt — einschliesslich des ERSTEN Schrittes, den die frühere Fassung übersprang: `body.exact_grant_context().ok_or(CekUnwrapFailed)?`, dann `HpkeSealed::from_parts(fields.encapsulated_key, fields.wrapped_cek)`, `hpke_open(session.kem_private_key(), &sealed, &hpke_info(context), &hpke_aad(context))`, dann `aead_open(&cek, &nonce, entry.ciphertext(), &payload_aad(manifest.exact_bytes()))`. Vier Einzelheiten sind gemessen und nicht wählbar: `hpke_info` und `hpke_aad` laufen über DIESELBEN Kontextbytes; `payload_aad` läuft über `manifest().exact_bytes()`, also über den Manifest-KERN und nicht über `signed_manifest()`; der Nonce kommt aus `manifest().fields().nonce`; und es entsteht KEIN drittes Duplikat der Kontextrekonstruktion — das private in `crates/ea-recovery/src/decrypt.rs` ist veraltet, und `ea-format` gibt `exact_grant_context` öffentlich heraus. Der Unterschied zu `open_entry` ist der EINZIGE, den der Reader braucht: `open_entry` verwirft den Klartext mit `drop(plaintext)`, weil `ea-verify` ihn nie herausgeben darf, und der Reader muss ihn anzeigen. Danach ruft `observer.on_decapsulation()` direkt auf dem Trait — genau einmal, hinter Gate `recipient-grant` und ausdruecklich als kein zehntes Gate; ein frischer `RecordingObserver` enthält danach NUR `["hpke-open"]` ohne Gate-Präfix.

**Die Schemabestimmung läuft durch PROBIEREN, weil `ea-schema` keinen Schnüffelweg herausgibt.** `SchemaRegistry::validate` und `::derive_view` nehmen `schema_id: &str, schema_version: u64` als EINGABE; `decode_common_header` in `crates/ea-schema/src/decode.rs` ist `pub(crate)`, `DerivedView::identity` ebenfalls, und weder `ManifestCoreFieldsV1` noch `GrantBodyFieldsV1` trägt ein Schemafeld. `decrypt_verified` läuft deshalb `SchemaRegistry::schemas()` in der gelieferten Reihenfolge durch und ruft je Deskriptor `derive_view(descriptor.schema_id(), descriptor.schema_version(), plaintext)`; der erste Erfolg gewinnt. Das ist deterministisch, weil `schemas()` ein `&'static [SchemaDescriptor]` fester Reihenfolge liefert, und es kostet bis zu fünf verworfene Validierungsläufe je geöffnetem Eintrag. Eine `sniff`-Funktion in `ea-schema` wäre billiger, hiesse aber eine abgeschlossene Stufe-1-Crate anzufassen — das verbietet dieser Task sich selbst. Es entsteht KEIN zweiter CBOR-Parser in `ea-reader`. Scheitern alle fünf, liefert `decrypt_verified` `EA-READER-SCHEMA-UNSUPPORTED`. **`classify` setzt `VerificationStatus::UnsupportedSchema` dagegen NIE, und die frühere Fassung irrte darin:** `classify` entschlüsselt nichts, der Zustand ist erst am Klartext feststellbar, und der ist erst nach `decrypt_verified` vorhanden. Die sechste Variante aus `crates/ea-types/src/status.rs` bleibt in der Zustandsabbildung dieses Tasks unbelegt; ihr Träger ist der Rückgabecode von `decrypt_verified`, gemessen in `historical_expiry.rs`, und erst der Task „Verschlüsselter invertierter Index in OPFS …" — der als erster Klartext je Eintrag in der Hand hält — schreibt sie in den Zustandsspeicher.

**N Entkapselungen ARCHIVWEIT plus eine je angezeigtem Eintrag — die frühere Kostenaussage untertrieb.** Sie schrieb, die Verdopplung sei „nicht archivweit, sondern je angezeigtem Eintrag". Gemessen läuft `claim_own_grants` über ALLE platzierten Einträge mit `objectResult` und ruft für jeden mit eigenem Grant `open_entry`; bei N eigenen Grants fährt allein `classify` also N HPKE-Entkapselungen und N AEAD-Öffnungen, deren Klartext mit `drop(plaintext)` verworfen wird. Dazu kommt eine je angezeigtem Eintrag. Das ist der Preis dafür, dass der Klartext die Grenze von `ea-verify` nicht überschreitet. Die billigere Alternative — `ea-verify` den Klartext herausgeben zu lassen — wäre eine Erweiterung einer abgeschlossenen Stufe-1-Crate um genau die Fähigkeit, deren Fehlen ihr Sicherheitsargument ist, und wird hier ausdrücklich nicht gewählt. Der Task „Verschlüsselter invertierter Index in OPFS …" erbt diese Zahl und muss sie in seiner 50.000-Paket-Messung mitführen.

**Der historische Grant bleibt Stufe 5, und der Zeuge misst seine ABWESENHEIT statt eines Codes.** Die frühere Fassung schrieb: „ein historischer Grant führt in `verify_own_grant` zu `RecipientGrantErrorV1::AuthorizationUnverifiable` mit dem Code `EA-VERIFY-GRANT-AUTHORIZATION-UNVERIFIABLE`". Über die Pipeline ist dieser Code unerreichbar: `own_grant` filtert auf `fields.kind == GrantKindV1::Initial`, und der `GrantKindV1::Historical`-Arm in `verify_own_grant` trägt wörtlich den Quelltextkommentar „UNERREICHBAR DURCH KONSTRUKTION: [`own_grant`] gibt nur initiale Grants heraus, und das ist der einzige Weg hierher". Beide Funktionen sind `pub(crate)` und stehen nicht im `pub use recipient::{DecryptionErrorV1, RecipientGrantErrorV1}` von `crates/ea-verify/src/lib.rs`; ein direkter Aufruf aus `ea-reader` ist ausgeschlossen. Die Fixture `complete_archive_with_a_forged_historical_grant()` erzeugt genau diesen Zustand, und sie erzeugt ihn als NICHTS: kein Befund, `is_fully_verified()` bleibt wahr. **Und der Bestand trägt den INITIALEN eigenen Grant weiterhin — die frühere Fassung dieses Absatzes irrte darin, aus dem Nichts einen `MissingGrant` zu machen.** Gemessen: ZWEI Grants auf dem Genesis-Eintrag, der Eintrag ist `VerificationStatus::Verified`, `detail_code() == None`, `decryption_errors` wie `signature_errors` leer, und das Protokoll ist WÖRTLICH dasselbe wie über `complete_archive()` — einschliesslich `hpke-open`, weil der initiale Grant entkapselt. Das ist die Aussage, die der ausgelieferte Code trägt. Die scharfe Frage ist WELCHER Grant der Zeuge ist: die Fälschung liegt unter dem kleineren Objekthash und steht in `inventory.grants()` VOR dem initialen; ein `own_grant`, das den Artfilter fallen liesse, fände sie zuerst und liesse jede Abwesenheitszusage grün. `a_forged_historical_grant_leaves_no_trace_at_all` fährt das Zeugenpaar deshalb durch `decrypt_verified` und erwartet `EA-READER-SCHEMA-UNSUPPORTED` — die Fälschung kapselt auf nichts und fiele früher, mit `EA-VERIFY-DECRYPT-CEK-UNWRAP-FAILED`. Nachzuschärfen ist der Zeuge erst, wenn Stufe 5 (FR-145) die `grantAuthorization` auflöst; der Fehlerpunkt heisst deshalb `historical-grant-unresolvable` und beschreibt eine Abwesenheit.

**Der Klartext liegt in `SecretVec`, und die VOLLSTAENDIGE Zugriffsflaeche steht HIER.** `VerifiedDecryptedRecord` haelt den entschluesselten Payload in `ea_crypto::SecretVec`, der beim Verlassen ueberschreibt. Diese Aufgabe deklariert den Typ, und sie deklariert damit auch, WIE an seinen Klartext heranzukommen ist — abschliessend, fuer jede spaetere Aufgabe dieses Plans:

```rust
// crates/ea-reader/src/decrypt.rs
pub struct VerifiedDecryptedRecord { /* private: SecretVec-Payload, Herkunftsspalten */ }

impl VerifiedDecryptedRecord {
    #[must_use] pub const fn entry_hash(&self) -> EntryHash;
    #[must_use] pub const fn chain_sequence(&self) -> ChainSequence;
    #[must_use] pub const fn object_hash(&self) -> ObjectHash;
    /// Der Lauf, in dem die Zeugen entstanden — die Frischepruefung von
    /// `decrypt_verified` misst gegen genau diesen Wert.
    #[must_use] pub const fn minted_at(&self) -> UnixMillis;
    /// Schema-Kennung und -Fassung des QUELLDATENSATZES, aus
    /// `DerivedView::source_schema_id`/`::source_schema_version`.
    #[must_use] pub fn source_schema(&self) -> (&'static str, u64);
    /// Schema-Kennung und -Fassung der ABGELEITETEN Ansicht, aus
    /// `DerivedView::target_schema_id`/`::target_schema_version`. In v1 ist die
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

Es gibt AUSDRUECKLICH KEIN `exact_plaintext_bytes() -> &[u8]` und KEIN `payload() -> &PayloadV1`. Ein Zugriff, der eine Ausleihe auf die Bytes ODER auf die geparste Nutzlast HERAUSGIBT, ist ein Klartext-Fluchtweg aus einem `SecretVec`: der Aufrufer kann ihn beliebig lange halten, kopieren, in ein `Vec` heben und in eine Ablage schreiben, und `ZeroizeOnDrop` greift auf die Kopie nie. Genau das verbieten `WR-082` (keine Zwischenablage-, Log- oder Telemetriewege fuer entschluesselte Inhalte), `FR-105` (Einzelexport mit bewusster Zielwahl statt beliebiger Herausgabe) und die Produktinvariante „no decrypted content enters OPFS bytes in the clear". Was die Ausleihform ZUSAGT, ist genau das, was `SecretVec::with_exposed` zusagt, und nicht mehr: die Ausleihe endet mit dem Aufruf, niemand bekommt aus Versehen einen Puffer in die Hand. Sie macht Kopien NICHT unmöglich — `with_plaintext(<[u8]>::to_vec)` übersetzt; die frühere Fassung nannte das eine „Typaussage über die Lebensdauer", und das war zu viel behauptet. Eine solche Kopie ist eine BEWUSSTE Entscheidung des Aufrufers, sichtbar an der Aufrufstelle, gehört ihm samt der Pflicht, sie zu überschreiben oder gar nicht anzulegen; der Task „Sitzungssperre, Zeroize, authenticator-bestätigter Einzelexport und signiertes lokales Audit" ist der einzige, der eine braucht. Es gibt aus demselben Grund weder `Deref` noch `Clone` noch ein abgeleitetes `Debug` auf diesem Typ; `Debug` gibt den Eintragshash und die Schemaspalten aus und nie eine Nutzlast. Jede spaetere Aufgabe dieses Plans — „Verschlüsselter invertierter Index in OPFS, Suche, Schemakompatibilität und die GEMESSENE 50.000-Paket-Schwelle", „Nachtragsreferenzen und Original/Nachtrag-Projektion", „Sitzungssperre, Zeroize, authenticator-bestätigter Einzelexport und signiertes lokales Audit" — benutzt AUSSCHLIESSLICH diese acht Zugriffe.

**Der Erfolgspfad wird BEZEUGT, und zwar zweimal getrennt.** Die acht Zugriffe wären sonst eine unbefahrene Fläche. Der ERSTE Zeuge fährt `decrypt_verified` über die vorhandene Fixture VOLLSTÄNDIG durch die HPKE-Entkapselung UND die AEAD-Öffnung und endet erwartungsgemäss an der Schemabestimmung mit `EA-READER-SCHEMA-UNSUPPORTED`, weil der Klartext von `complete_valid_archive()` `b"einsatzarchiv-fixture-payload"` ist. Genau dieser Ausgang beweist, dass die aus `open_entry` nachgebaute Kryptorechnung stimmt: wäre sie falsch, fiele der Lauf FRÜHER mit `EA-VERIFY-DECRYPT-CEK-UNWRAP-FAILED` oder `EA-VERIFY-DECRYPT-PAYLOAD-OPEN-FAILED`. Derselbe Zeuge beobachtet `observer.on_decapsulation()` genau einmal auf einem frischen `RecordingObserver`. Der ZWEITE Zeuge, `a_genesis_plaintext_is_opened_in_full_and_never_escapes_the_record` in `historical_expiry.rs`, fährt den vollen Weg bis `with_plaintext`, `with_payload`, `source_schema` und `target_schema`: der Klartext ist der eingefrorene Vektor `vectors/format/payload-v1/genesis.hex` — gemessen wird gegen etwas, das der Reader NICHT selbst erzeugt hat, weshalb `ea_schema::encode_payload` hier ungenutzt bleibt —, die Bytes kommen BYTEGLEICH zurück, die Nutzlast dekodiert zu `PayloadV1::Genesis`, Quell- und Zielpaar sind das des einzigen Deskriptors, dessen `validate` den Vektor trägt, die Herkunftsspalten sind die des Zeugen, ein frischer `RecordingObserver` sieht genau `["hpke-open"]`, und `Debug` enthält weder den Klartext noch eine seiner Zeichenketten. Die Fixture `fixtures::complete_archive_with_a_genesis_plaintext()` entsteht durch dieselbe rein additive Erweiterung wie in der Stummelfrage: ein `plaintext: &[u8]`-Parameter an den MODULPRIVATEN `build_complete_entry` und `complete_archive_for` (vier beziehungsweise drei Aufrufstellen in derselben Datei; alle bestehenden Bauer reichen `COMPLETE_PLAINTEXT_V1` durch) und das öffentliche `complete_valid_archive_with_plaintext(&[u8])` neben dem unveränderten `complete_valid_archive()`. **Gemessene Nebenbedingung:** die Offsetkonstanten `SIGNED_EIP_LENGTH_V1 = 535`, `MUTATED_EIP_SIGNATURE_OFFSET_V1` und `MUTATED_EIP_KEY_THUMBPRINT_OFFSET_V1` hängen an der LÄNGE des Klartexts. Sie bleiben nur deshalb gültig, weil der Vorgabepfad `COMPLETE_PLAINTEXT_V1` behält; ein Bestand mit schemagültigem Klartext darf in keiner der Mutationsfixturen auftauchen.

`SchemaRegistry::validate` laeuft INNERHALB von `decrypt_verified` ueber eine Ausleihe, und der dabei entstehende `ValidatedPayload` faellt dort. **Benannte Restfrage, gegen den Arbeitsbaum nachgemessen und anders formuliert als zuvor:** die frühere Fassung schrieb, `ea_schema::ValidatedPayload` UND `ea_schema::DerivedView` besässen je einen gewöhnlichen `Vec<u8>`. `DerivedView` besitzt keinen eigenen Puffer — er hält ein `ValidatedPayload`. Betroffen sind tatsächlich `ValidatedPayload.exact_bytes: Vec<u8>`, die Rückprobe-Kopie in `SchemaRegistry::validate` und die dekodierten Zeichenketten in `PayloadV1`; keines davon wird beim Fallen überschrieben. Sie zeroize-fähig zu machen hiesse, eine abgeschlossene Stufe-1-Crate anzufassen. Dieser Task tut das nicht, er schreibt die Lücke auf, und der Task „Sitzungssperre, Zeroize, authenticator-bestätigter Einzelexport und signiertes lokales Audit" besitzt die Zeroize-Zusage der Sitzung und entscheidet dort, ob die Lücke geschlossen oder als dokumentierte SOLL-Abweichung geführt wird.

**Der Modusparameter wird von `classify` NICHT GELESEN.** `ReaderVerifier` trägt ihn, faltet ihn aber nirgends in `VerifyOptions`; `both_reader_modes_produce_the_same_gate_protocol_over_the_same_bytes` pinnt genau das. `web-reader-design.md` §5.4 lautet wörtlich „Die Reihenfolge aus Design §14.1 gilt in beiden Modi wortgleich", `verify_archive_observed` kennt keinen Modusparameter, und `confirm_entries` bestimmt `ServerConfirmationV1` ohnehin aus den VORHANDENEN Quittungen — der Datei-Modus ist für die Pipeline schlicht ein Bestand ohne `.esr`. Der Satz der früheren Fassung, „`ReaderMode::File` verbietet jeden Netzaufruf dieses Laufs", ist hier GESTRICHEN: `crates/ea-reader` hat gar keine Netzfähigkeit — sein Manifest führt keinen HTTP-Klienten, und `src/http.rs` baut ausschliesslich das DTO `ReaderRequestV1` —, die Quelle stellt der Aufrufer, und die Zusage gehört in den Task „Datei-Modus: Einzeldatei-Bündel, Verzeichnis-Handle, kein Cursor, `nicht server-bestätigt`" beziehungsweise an `crates/ea-reader-wasm/src/fetch.rs`. Es bleibt die eine Zusage, die hier gemessen wird: beide Modi erzeugen dasselbe Protokoll. Dass dieser Zeuge damit per Konstruktion grün ist, ist gewollt — er pinnt eine NICHT-Abhängigkeit und schützt gegen ein späteres Einfalten des Modus in die Pipeline.

**Die Re-Exporte in `crates/ea-reader/src/lib.rs` wachsen mit den Signaturen.** Der Modulkopf dieser Datei schreibt die Regel aus: was in einer SIGNATUR steht, wird ebenfalls RE-EXPORTIERT — sonst kann `crates/ea-reader-wasm` die Fläche nicht bedienen, ohne eigene Kanten zu ziehen, und ein zweiter Weg an dieselben Typen wäre genau das, was die Tasks 9 und 13 dann fortschrieben. Heute re-exportiert `ea-reader` aus `ea_verify` NUR `GATE_ORDER_V1` und aus `ea_types` nur `Hash32, OrganizationId, RegistryVersion, SubjectId, UnixMillis`. Dazu kommen: aus `ea_verify` `DECAPSULATION_EVENT_V1`, `Gate`, `GateObserver`, `RecordingObserver`, `SilentObserver`, `VerificationReportV1`, `ObjectResultKindV1`, `ObjectResultV1`, `ObjectErrorV1`, `ChainGapV1`, `QuarantinedObjectV1`, `AuthorizedDestructionV1`, `DestructionStateV1`, `ServerConfirmationV1`, `VerifyError`; aus `ea_types` `ChainSequence`, `EntryHash`, `ObjectHash`, `KeyThumbprint`, `DestructionId`, `VerificationStatus`, `EntryStatus`; aus `ea_archive` `ArchiveSource`; aus `ea_trust` `TrustAnchorV1`; aus `ea_schema` `SchemaRegistry` und `PayloadV1`; aus `ea_crypto` `HpkeRecipientPrivateKey`. Die `mod`- und `pub use`-Listen bleiben je alphabetisch sortiert: `anchor` vor `batch`, `decrypt` zwischen `cursor` und `enrollment`, `grant` zwischen `envelope` und `http`, `verify` zwischen `trust_state` und `vault`.

`docs/traceability/stage-4-fault-points.json` — vom Task „Web-Bundle: getrennter Origin, Service Worker, gepinnte `webBundleRelease` und das Alter des Trust-Standes" angelegt — bekommt den Abschnitt `verification` in derselben Dreifeldform `{name, brackets, witness}` wie `docs/traceability/stage-3-fault-points.json`, mit `witness` als `pfad::testname` und EINEM eigenen `#[test]` je Fehlerpunkt: `substituted-archive-own-trust-chain` → `pinned_anchor.rs`, `missing-own-grant` → `missing_grant.rs`, `own-thumbprint-wrong-material` → `missing_grant.rs`, `stub-without-authorization` → `destroyed_stub.rs`, `stale-witness` → `historical_expiry.rs`, `historical-grant-unresolvable` → `historical_expiry.rs`. **Kein Gate liest dieses Manifest für Stufe 4**: `tools/xtask/src/main.rs` pinnt nur `STAGE_TWO_…` und `STAGE_THREE_FAULT_POINT_MANIFEST_PATH`, und `run_stage_gate` fällt für Stufe 4 mit „stage-gate is only defined for stages 1, 2 and 3 so far". Die Stufe-2/3-Regeln — nichtleere `name`/`brackets`, kein Name doppelt, auflösbarer Zeuge mit `#[test]` unmittelbar davor — werden trotzdem eingehalten, weil ein späteres Stufe-4-Gate dieselben Funktionen wiederverwenden wird.

**Die Testquelle kommt aus der Fixturekette und nicht aus einer neuen Produktionsfläche.** `ReaderCacheSourceV1` in `crates/ea-reader/src/batch.rs` bleibt `pub(crate)`: `crates/ea-archive/tests/support/mod.rs` trägt `impl ArchiveSource for ArchiveFixture`, die Zeugen bringen ihre `ArchiveSource` also selbst mit, ein Testdouble ist überflüssig, und die Produktionsfläche wächst nicht. Die Frage einer öffentlichen Reader-Quelle gehört zum Task „Datei-Modus: Einzeldatei-Bündel, Verzeichnis-Handle, kein Cursor, `nicht server-bestätigt`".

- [ ] **Step 4: Run the classification, the browser witness, and the frozen surfaces**

Run:

```bash
cargo metadata --format-version 1
cargo test --locked -p ea-reader
cargo test --locked -p ea-reader --doc
cargo test --locked -p ea-verify
cargo test --locked -p ea-recovery
cargo test --locked -p ea-archive-fs
cargo check --target wasm32-unknown-unknown --locked -p ea-reader-wasm --tests
pnpm web:browser-test
cargo run --locked -p xtask -- test-golden
```

`cargo metadata --format-version 1` steht als ERSTE Zeile und ist das GENAU EINE Kommando dieses Tasks ohne `--locked`: Schritt 3 gibt `crates/ea-reader` die Kante auf `ea-schema` und `crates/ea-reader-wasm` acht Entwicklungskanten, und `Cargo.lock` steht aus genau diesem Grund im Files-Block. Die WURZEL-`Cargo.toml` steht dort NICHT, weil `ea-schema` bereits in `[workspace.dependencies]` deklariert ist. `ea-archive` steht seit dem Task „Inkrementeller Reader-Sync und verifizierter Cursor-Fortschritt in OPFS" in `crates/ea-reader/Cargo.toml` — `ea_verify::verify_archive_observed` nimmt dort bereits `&dyn ArchiveSource` —, `ea-format` seit dem Task „Browser-Vault: PRF-Envelopes, Schlüsselprofil und die Verwahrung von Anchor und KEM-Schlüssel", der `DeviceCertificateFieldsV1` benennt; beide werden hier geerbt und nicht neu gezogen. Es steht NACH der Registrierung und VOR jedem `--locked`-Kommando.

Die drei Zeilen `-p ea-verify`, `-p ea-recovery` und `-p ea-archive-fs` sind der ZEUGE DAFÜR, dass die Erweiterung von `crates/ea-verify/tests/support/mod.rs` additiv blieb: das sind genau die drei anderen Crates, die dieselbe Datei per `#[path]` einbinden. Bewegte sich eine bestehende Signatur, fiele mindestens eine von ihnen. `cargo check --target wasm32-unknown-unknown --locked -p ea-reader-wasm --tests` steht daneben, weil `pnpm web:browser-test` wörtlich `cargo test --locked -p ea-reader-wasm --target wasm32-unknown-unknown` ist — ein rohes cargo-Kommando OHNE xtask-Vorschaltung, dessen Übersetzungsfehler erst nach dem Browserstart aufträten. Die fail-closed-Prüfung des WebDrivers läuft ausschliesslich in `cargo run --locked -p xtask -- browsers up`, und die Umgebungsvariable heisst `CHROMEDRIVER_REMOTE`.

`crates/ea-reader-wasm/tests/verify_browser.rs` trägt `#![cfg(target_arch = "wasm32")]` in ZEILE 1 — sonst zöge `cargo test --workspace --all-targets --locked` das Ziel auf den Wirt — und `wasm_bindgen_test_configure!(run_in_browser);`: ohne diese Zeile führe der Läufer in Node, und der Zeuge schlösse die Spike-Grenze zur COSE-Kette gerade NICHT. Kein `run_in_dedicated_worker`, weil kein OPFS im Spiel ist. Der Bestand kommt über dieselbe `#[path]`-Kette, `ArchiveFixture` implementiert `ArchiveSource` selbst, `getrandom` trägt workspaceweit `wasm_js`, und `ReaderVault::seal`/`unlock` ist reines Rust. Ein einträgiger Bestand genügt.

Expected: PASS. Das Protokoll ist in beiden Modi ein Praefix von `GATE_ORDER_V1` gefolgt von hoechstens einem `hpke-open`; ein vollstaendiger Bestand ist `is_fully_verified()`; `crates/ea-reader-wasm/tests/verify_browser.rs` fuehrt dieselbe Klassifikation in Headless-Chromium ueber eine `ArchiveSource` im Speicher und schliesst damit eine der fuenf benannten Grenzen des Spikes — hier laeuft `parse_cose_sign1` zum ersten Mal gegen eine ECHTE COSE-Kette im Browser statt gegen einen rohen RFC-8032-Vektor. Die adversariellen Faelle, die rot werden MUESSEN und einzeln zu pruefen sind: ein untergeschobener, in sich vollstaendiger Fremdbestand faellt an Gate `trust` und liefert NULL `objectResults` statt einer stillen Teilverifikation; ein `PinnedTrustAnchor`, der aus Archivbytes gebaut werden soll, uebersetzt nicht (`compile_fail`-Doctest); ein `decrypt_verified` mit einem Zeugen aus einem frueheren `classify` bricht mit `EA-READER-WITNESS-STALE` ab; fuer ein `.eds` ist `decrypt_verified` in keinem seiner Ausgaenge formulierbar, und `autorisiert vernichtet` entsteht nur ueber die volle dreigliedrige Pruefkette — ein Stummel mit echter Kennung und gefaelschtem Autorisierungshash oder auf einem Eintrag, den die Autorisierung nie nannte, bleibt `ungeklaerte Luecke`; ein Eintrag ohne eigenen Grant erzeugt weder einen `decryptionErrors`-Eintrag noch eine `gaps`-Zeile und senkt `is_fully_verified()` nicht; und ein Grant auf den eigenen Abdruck mit falschem Material erzeugt `EA-VERIFY-DECRYPT-CEK-UNWRAP-FAILED` und wird als `unbekannter Schluessel` und nie als `fehlender Grant` gefuehrt. `test-golden` belegt, dass kein eingefrorener Vektor und keine Golden-Erwartung sich bewegt hat: dieser Task erzeugt kein Archivbyte.

- [ ] **Step 5: Commit the verification binding**

```bash
git add crates/ea-reader crates/ea-reader-wasm crates/ea-verify/tests/support/mod.rs \
        docs/traceability/stage-4-fault-points.json Cargo.lock
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
- Test: `apps/web/src/features/file-mode/DirectoryHandle.test.ts`
- Test: `apps/web/tests/e2e/file-mode.spec.ts`
- Modify: `crates/ea-reader/src/lib.rs`
- Modify: `crates/ea-reader/tests/verify_fixtures/fixtures.rs`
- Modify: `crates/ea-reader-wasm/src/lib.rs`
- Modify: `crates/ea-ui-contracts/src/emit.rs`
- Modify: `apps/web/src/bridge/generated-contracts.ts` (GENERIERT — geschrieben von `cargo run --locked -p ea-ui-contracts --bin emit-ts`, nie von Hand)
- Modify: `apps/web/src/main.tsx`
- Modify: `docs/traceability/stage-4-fault-points.json`
- Modify: `docs/traceability/v0.1-requirements.csv`

**Der Files-Block der ersten Fassung war an fünf Stellen falsch, und jede ist gemessen.** `crates/ea-ui-contracts/src/emit.rs` und `apps/web/src/bridge/generated-contracts.ts` fehlten, obwohl die Aufgabe ein Status-DTO über die Brücke schickt: `crates/ea-ui-contracts/src/bin/emit-ts.rs` ist der EINZIGE Schreiber der zwei Kontraktdateien, `apps/web/src/bridge/no-hand-written-contracts.test.ts` verbannt jedes Literal jeder emittierten Vereinigung aus jeder handgeschriebenen Web-Quelle, und `crates/ea-ui-contracts/tests/generated_ts_is_current.rs::the_checked_in_reader_file_is_exactly_what_the_reader_emitter_writes` vergleicht die eingecheckte Datei zeichengleich mit dem Emitterausgang. `docs/traceability/v0.1-requirements.csv` fehlte, obwohl der Task in seinem eigenen Ledgerabsatz zusagt, zwei Belegspalten zu füllen. `crates/ea-reader/tests/verify_fixtures/fixtures.rs` fehlte, obwohl jede der drei neuen Kulissen dort entsteht. `apps/web/src/features/file-mode/DirectoryHandle.test.ts` fehlte, obwohl der Verzeichnisdurchlauf die einzige Stelle ist, an der TypeScript in dieser Aufgabe überhaupt etwas ausrechnet. Und `crates/ea-reader/Cargo.toml` steht AUSDRÜCKLICH NICHT hier: `ea-archive.workspace = true` liegt bereits in `[dependencies]` von `crates/ea-reader/Cargo.toml`, und Cargo stellt die `dependencies` eines Pakets seinen Integrationstestzielen ohnehin bereit — `crates/ea-reader/tests/verify_fixtures/fixtures.rs` benennt `ea_archive::{ArchiveInventory, ArchiveSource}` heute schon.

**Interfaces:**
- Consumes: `ea_archive::{ArchiveBlob, ArchiveBundleSource, ArchiveError, ArchiveSource, BundleError, BUNDLE_FILE_EXTENSION_V1, BUNDLE_HEADER_BYTES_V1, BUNDLE_MAGIC_V1, MAX_ARCHIVE_BLOBS_V1, MAX_TOTAL_ARCHIVE_BYTES_V1}` — der reine Bündelleser, den die Aufgabe „wasm32-Reichweite: `ea-reader`, die Brücken-Crate und die geteilten Browserkerne" aus dem wirtsgebundenen `ea-archive-fs` nach `ea-archive` bewegt hat; `ea_verify::{ObjectResultKindV1, ServerConfirmationV1, GateObserver, RecordingObserver, SilentObserver, VerificationReportV1, GATE_ORDER_V1}` — ALLE über die vorhandenen Re-Exporte von `crates/ea-reader/src/lib.rs` und keine einzige über eine neue Kante; `UnlockedVault` aus der Aufgabe „Browser-Vault: PRF-Envelopes, Schlüsselprofil und die Verwahrung von Anchor und KEM-Schlüssel"; `ReaderVerifier::classify`, `ReaderClassification`, `ReaderError` und `PinnedTrustAnchor::from_vault` aus der Aufgabe „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert"; `ReaderMode::File` aus der Aufgabe „wasm32-Reichweite"; `docs/traceability/stage-4-fault-points.json` aus der Aufgabe „Web-Bundle: getrennter Origin, Service Worker, gepinnte `webBundleRelease` und das Alter des Trust-Standes".
- Produces: `ReaderFileMode::{open_bundle, open_bundle_observed, open_directory, open_directory_observed}`, `ReaderArchiveSourceV1`, `DirectoryHandleSource::{new, push_blob, blob_count, total_bytes, mark_unavailable}`, `ReaderFileModeError`, `OpenedArchiveV1::{classification, report, mode}`, `file_mode_archive_json`, die sechs Brückenausfuhren von `crates/ea-reader-wasm/src/file_access.rs`, das View-Modell `FileModeArchiveView` in `READER_VIEW_MODELS_V1`, der Abschnitt `file-mode` des Szenarienmanifests, und die Belegspalten der Ledgerzeilen `WR-053` und `WR-054`.

`crates/ea-reader/src/lib.rs` nimmt `mod file_mode;` und `mod archive_source;` samt ihren `pub use`-Blöcken auf, `crates/ea-reader-wasm/src/lib.rs` nimmt `pub mod file_access;` auf; ohne diese Zeilen übersetzt der Commit nicht. `apps/web/src/main.tsx` bekommt die Route `/datei`, angehängt an `EA_WEB_ROUTES` aus der Aufgabe „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate" — die Tabelle führt heute `{ path: '/', label: 'Reader' }` und `{ path: '/enrollment', label: 'Enrollment', render: () => <EnrollmentPage /> }`, und der dritte Eintrag trägt sein `render` genauso; `apps/web/tests/e2e/file-mode.spec.ts` fährt genau diese Route an.

Dies ist der zweite Betriebsmodus aus `web-reader-design.md` §5.2 bis §5.4: die Anwendung öffnet Archivobjekte direkt aus dem Dateisystem, OHNE jede Serverbeteiligung. Zwei Wege hinein, und nur einer davon funktioniert überall. Der universelle Weg nimmt die EINE exportierte Datei durch den gewöhnlichen Dateidialog; er MUSS immer angeboten werden, weil `showDirectoryPicker` in Safari und Firefox fehlt. Der Chromium-Komfortweg bindet über `showDirectoryPicker` einen Archivordner oder ein profiliertes Netzlaufwerk dauerhaft an.

Drei Nicht-Ziele, jedes mit seinem Grund. Es entsteht KEIN zweiter Archivparser: beide Wege münden in `ea_archive::ArchiveSource`, und die Klassifikation entscheidet weiterhin ausschliesslich das 9-Byte-Exact-Object-Präfix, nie ein Dateiname. Es entsteht KEIN Serveraufruf irgendeiner Art — der Modus ist definiert durch seine Abwesenheit. Und die Ankerbindung wird NICHT neu implementiert: sie kommt fertig aus der Aufgabe „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert", die sie mit ihrem eigenen Zeugen trägt; hier wird belegt, dass der EINSTIEGSPUNKT dieses Modus keinen zweiten Weg zu einem Anker öffnet.

#### Die zwölf Stellen, an denen die erste Fassung dieses Tasks gegen den Arbeitsbaum falsch war

**1. `PinnedTrustAnchor::from_vault` gibt KEIN `Result`.** `crates/ea-reader/src/anchor.rs` deklariert `pub const fn from_vault(session: &'a UnlockedVault) -> Self` als seinen EINZIGEN Konstruktor; `UnlockedVault.pinned_anchor` ist ein Pflichtfeld, `EA-READER-ANCHOR-MISSING` ist in der Aufgabe davor ersatzlos entfallen. Die Zeile `PinnedTrustAnchor::from_vault(&vault).unwrap()` aus der ersten Fassung übersetzt nicht. Sie steht unten ohne `unwrap`, wie `crates/ea-reader/tests/pinned_anchor.rs::the_anchor_used_is_the_vault_anchor_and_not_the_one_in_the_archive` sie bereits schreibt.

**2. Acht der neun benutzten Kulissenfunktionen existieren nicht.** GEMESSEN in `crates/ea-reader/tests/verify_fixtures/fixtures.rs`: es gibt `unlocked_vault_with_pinned_anchor()`, `vault_pinning(Vec<u8>)`, `complete_archive()`, `complete_archive_anchor_bytes()`, `pinned_anchor_hash()`, `classify()`, `classify_at()`, `EFFECTIVE_NOW` und den Rest der in der Aufgabe davor angelegten Familie. Es gibt NICHT `unlocked_vault()`, `os_wall_clock()`, `exported_bundle_bytes()`, `directory_blobs()`, `bundle_without_receipts()`, `foreign_root_bundle_bytes()`, `vault_pinned_to()` und `foreign_anchor()`. Welche davon ersatzlos entfallen und welche drei neu entstehen, steht in den Punkten 3, 4 und 7.

**3. Die Bündelbytes entstehen VON HAND in der Kulisse, und `ea-archive-fs` wird KEINE Entwicklungskante.** Das ist die teuerste Messung dieses Tasks, und sie hat zwei Hälften. Erstens: `crates/ea-archive` besitzt KEINEN Kodierer. `encode_bundle` liegt modulprivat in `crates/ea-archive-fs/src/bundle.rs`, und der einzige öffentliche Weg zu Containerbytes ist `write_archive_bundle`, das einen `LocalPathBackend` und eine Zieladresse auf der Platte verlangt. Zweitens, und das entscheidet: `crates/ea-reader-wasm/tests/verify_browser.rs` bindet `crates/ea-reader/tests/verify_fixtures/mod.rs` per `#[path]` ein und übersetzt sie für wasm32; jeder Name, den die Kulisse nennt, muss in `[dev-dependencies]` von `crates/ea-reader-wasm/Cargo.toml` stehen, und dort stehen genau `ea-archive`, `ea-format`, `ea-time`, `ea-trust`, `ea-types`, `ed25519-dalek`, `minicbor`, `ea-verify`, `serde_json` und `wasm-bindgen-test`. `ea-archive-fs` steht auf `WASM32_EXEMPT_CRATES` in `tools/xtask/src/main.rs` — sein Eintrag begründet das mit `std::fs`, Verzeichnis-Flush, Rename und Schreibsperren —, und `every_crates_member_is_classified_for_the_wasm32_gate` in `tools/xtask/tests/workspace.rs` erzwingt genau EINE Zuordnung je Mitglied. Eine Dev-Kante von `ea-reader` auf `ea-archive-fs` wäre auf dem Wirt zulässig und im Browserzeugen unübersetzbar.

Der Weg ist deshalb der, den `crates/ea-archive/tests/bundle_reader.rs` schon geht: seine Funktion `hand_built_container(entries: &[(&str, &[u8])]) -> Vec<u8>` baut den Container nach der Moduldoku von `crates/ea-archive/src/bundle.rs` und nach nichts sonst, und ihr Doc-Kommentar schreibt die Begründung bereits aus — ein zweiter Kodierer NEBEN dem Leser wäre ohnehin der schwächere Zeuge, weil beide dieselbe Abweichung trügen und beide grün blieben. Die Kulisse dieses Tasks baut denselben Container über denselben `core`-Mitteln und `ea_archive::BUNDLE_MAGIC_V1`.

EINE Regel kommt dabei hinzu, die `hand_built_container` bewusst dem Aufrufer überlässt: der Index MUSS STRENG aufsteigend über die Adressbytes sortiert sein, sonst weist `ArchiveBundleSource::from_bytes` mit `BundleError::Malformed` ab. `ArchiveFixture` legt seine Blobs in BAUREIHENFOLGE ab (`push_trust_objects` zuerst, dann `.eip`, dann `.eag`), und die Trust-Adressen tragen einen Objekthash im Namen — die Reihenfolge ist also weder sortiert noch vorhersagbar. `exported_bundle_bytes()` sortiert deshalb selbst und behauptet die Duplikatfreiheit mit einer eigenen Zusicherung; ohne diese zwei Zeilen wäre die Kulisse an einem Tag grün und am nächsten rot, je nachdem, welche Hashes die Linie zieht.

**4. Es gibt keine Kulisse „ohne Quittungen", weil es keine MIT gibt — jedenfalls nicht auf dieser Linie.** `fixtures::complete_archive()` ruft `verify_support::complete_valid_archive()`, und `complete_archive_with` legt Trust-Objekte, `.eip` und `.eag` ab und KEINE einzige `.esr`. Der lückenlose Bestand IST also der Bestand ohne Quittungen; `bundle_without_receipts()` entfällt ersatzlos, und die Zusagen über `notServerConfirmed`, `gaps().len() == 0` und `is_fully_verified()` stehen über `complete_archive()`.

Die Gegenkontrolle MIT Quittungen ist `verify_support::receipt_archive(verify_support::ReceiptArchiveSpec::bare().with_receipts())`, und sie trägt eine gemessene Fussangel: JEDER Bestand der Quittungslinie hat die Lücke `0..=1`. Der Grund steht im Doc-Kommentar von `RECEIPT_PRE_ENTRY_GAP_THROUGH_V1` — die Linie braucht drei Köpfe (Policy, Serverzertifikat, Schreiberzertifikat), die ersten beiden verbrauchen die Sequenzfächer null und eins, ein `.eip` darauf ist nicht herstellbar, und `ea_chain::build_chain` meldet das Fehlen zu Recht als Lücke. `is_fully_verified()` prüft `gaps.is_empty()` mit (`crates/ea-verify/src/report.rs`), also ist dieser Bestand NICHT vollständig verifiziert. Eine Zusicherung, die `serverConfirmed` UND `is_fully_verified()` am selben Bestand verlangte, wäre rot — und zwar aus einem Grund, der mit dem Datei-Modus nichts zu tun hat.

Die Gegenkontrolle misst deshalb GENAU EINE Grösse: dass `ServerConfirmationV1::ServerConfirmed` über denselben Weg überhaupt erreichbar ist. `crates/ea-verify/tests/receipt_checkpoint.rs::receipts_confirm_checkpoints_bound_rollback_and_a_stub_stays_a_gap` hält beide Hälften bereits gegeneinander; der Zeuge dieses Tasks ist die Wiederholung dieser einen Spalte durch den DATEI-Eingang, nicht eine zweite Messung von Gate `receipt`.

Und woher der Wert kommt, ist gemessen und keine Vermutung: `confirm_entries` in `crates/ea-verify/src/archive.rs` ist der EINZIGE Erzeuger von `objectResults` — sein Doc-Kommentar sagt „HIER UND NUR HIER" —, es setzt `let mut confirmation = ServerConfirmationV1::NotServerConfirmed;` und hebt den Wert ausschliesslich dann auf `ServerConfirmed`, wenn `receipt_for` eine nicht isolierte `.esr` findet UND `confirm_receipt` sie trägt. Fehlt die Quittung, entsteht kein Eintrag in einem der sechs Mangelfelder. Diese Aufgabe fügt dafür nichts hinzu; sie belegt es und trägt es in die Oberfläche.

**5. Der Bericht ist ordnungsUNabhängig, und das ist der Grund, warum der Buendel- und der Verzeichnisweg denselben `reportHash` liefern KOENNEN.** GEMESSEN an den Feldern von `VerificationReportV1` in `crates/ea-verify/src/report.rs`: `object_results`, `authorized_destructions`, `gaps`, `format_errors` und `quarantined_objects` sind `BTreeMap` über Objekthash beziehungsweise Sequenz, `registry_versions`, `signature_errors`, `evidence_errors`, `decryption_errors` und `public_key_thumbprints` sind `BTreeSet`, und die fünf Zählfelder sind Summen. Die Reihenfolge, in der `visit_blobs` seine Blobs herausgibt, geht in KEINES dieser Felder ein; `crates/ea-verify/src/archive.rs` sortiert seine Eintragsschleife ohnehin selbst nach `(chain_sequence, object_hash)` und schreibt den Grund daneben.

Das ist wichtig, weil der Container sortiert IST und der Verzeichnisdurchlauf es nicht sein kann: `apps/web/src/features/file-mode/DirectoryHandle.ts` läuft rekursiv und je Ebene lexikografisch, und eine ebenenweise Ordnung ist nicht dieselbe wie die globale Ordnung über die vollen Adressbytes — `a-b.txt` steht global vor `a/z.txt` (`0x2D` < `0x2F`), ebenenweise aber dahinter. Wäre der Bericht ordnungsabhängig, wäre die Gleichheit der zwei Wege eine Zufallsaussage über Dateinamen. `DirectoryHandleSource` sortiert deshalb AUSDRÜCKLICH NICHT: eine Sortierung dort wäre eine Regel, die nichts durchsetzt, und sie verstellte den Blick auf die Eigenschaft, die die Gleichheit wirklich trägt.

Was der gleiche `reportHash` damit belegt und was nicht, gehört daneben: er belegt, dass beide Wege DIESELBEN Objektbytes tragen. Er belegt NICHT, dass sie unter denselben Adressen liegen — Pfadhinweise stehen in keinem Berichtsfeld. Der Zeuge sagt das in seinem Namen und nicht nur in einem Kommentar.

**6. `OpenedArchiveV1` trägt die Quelle NICHT und hat keinen Lebensdauerparameter.** `ReaderClassification` (`crates/ea-reader/src/verify.rs`) besitzt `VerificationReportV1`, `ArchiveInventory`, die Zustandszeilen und die Zeugenkarte und hat AUSDRÜCKLICH keinen Lebensdauerparameter — der Typkommentar begründet es mit dem Besitz des Inventars. Nach `classify` borgt also nichts mehr von der Quelle. Sie zu halten kostete an der Obergrenze ein zweites Mal 2 GiB, denn `ArchiveBundleSource` hält den vollständigen Container in `bytes` und das Inventar hält die geparsten Objekte daneben; es ist dasselbe Argument, mit dem `write_archive_bundle` in `crates/ea-archive-fs/src/bundle.rs` sein `drop(blobs)` begründet. Die Quelle FÄLLT am Ende des Aufrufs, und `OpenedArchiveV1` hält genau zwei Werte: die Klassifikation und den Modus.

**7. Der untergeschobene Bestand wird INVERTIERT gebaut, weil ein zweiter Anker aus der geteilten Kette nicht zu bekommen ist.** `trust_support::RegistryLineBuilder::new()` hält `ROOT_SECRET`, `organization()` und `chain_id()` als Konstanten, und `exact_anchor_bytes()` hängt allein an dieser Wurzel — der Modulkopf von `crates/ea-reader/tests/verify_fixtures/fixtures.rs` schreibt es aus, und `crates/ea-reader/tests/pinned_anchor.rs` zieht daraus bereits die Konsequenz: nicht der BESTAND ist fremd, sondern der TRESOR. Der fremde Anker kommt aus der Nachbarkulisse `crates/ea-reader/tests/fixtures/mod.rs::pinned_anchor_exact_bytes()` (Wurzelseed `[0x11; 32]`, Organisation `[0x12; 16]`), und der Einschluss steht IM TESTZIEL und nicht in `verify_fixtures/mod.rs`, weil `crates/ea-reader-wasm` dieselbe `#[path]`-Kette benutzt und die Kanten der Nachbarkulisse (`ea-testkit`, `ea-sync-protocol`) dort nicht liegen. `foreign_root_bundle_bytes()`, `vault_pinned_to()` und `foreign_anchor()` entfallen damit ersatzlos.

**8. `FileModeError` heisst `ReaderFileModeError`, weil der kürzere Name doppelt belegt wäre.** `crates/ea-reader/src/bundle_release.rs` führt bereits `ReaderBundleError` — über das WEB-Bundle und seine Freigabe, mit dem Archivbündel dieses Tasks hat er nichts zu tun. Die Crate führt heute sieben modulweise Fehlertypen (`ReaderVaultError`, `ReaderBlobError`, `ReaderBundleError`, `EnrollmentError`, `ReaderKeyProfileError`, `ReaderSyncError`, `ReaderError`) in derselben Bauform: flaches Enum, `pub const fn code(&self) -> &'static str`, Fremdcodes DURCHGEREICHT, `Display` schreibt ausschliesslich den Code, `Debug` delegiert an `Display`. `ReaderFileModeError` erbt diese Form und führt KEINEN eigenen Code: `Bundle(BundleError)` reicht `EA-BUNDLE-MALFORMED`, `EA-BUNDLE-BLOB-LIMIT` und `EA-BUNDLE-TOTAL-BYTE-LIMIT` durch, `Archive(ArchiveError)` reicht `EA-ARCHIVE-UNAVAILABLE`, `EA-ARCHIVE-BLOB-LIMIT` und `EA-ARCHIVE-TOTAL-BYTE-LIMIT` durch, und `Classification(ReaderError)` reicht durch, was die Aufgabe davor schon stabilisiert hat.

**9. `ea-reader` re-exportiert heute aus `ea-archive` NUR `ArchiveSource`, und die Brücke kommt damit nicht aus.** GEMESSEN am `pub use`-Block von `crates/ea-reader/src/lib.rs`: `ArchiveBundleSource`, `ArchiveBlob`, `ArchiveError`, `BundleError`, `BUNDLE_FILE_EXTENSION_V1`, `BUNDLE_MAGIC_V1` und die zwei Deckel stehen dort NICHT. Für `crates/ea-reader/tests/` ist das folgenlos — die Tests sehen die `[dependencies]` ihres eigenen Pakets. Für `crates/ea-reader-wasm/src/file_access.rs` ist es entscheidend: `ea-archive` steht dort ausschliesslich in `[dev-dependencies]`, eine Produktionsquelle der Brücke kann `ea_archive::` also gar nicht schreiben. Dieser Task erweitert deshalb den `pub use ea_archive::{..}`-Block von `ea-reader` um genau die acht Namen und zieht KEINE neue Kante in `crates/ea-reader-wasm/Cargo.toml`. Das ist auch die billigere Hälfte: eine Kante ginge in den wasm32-Lib-Graphen, ein Re-Export nicht.

**10. Beide Deckel sind zu gross, um sie mit ihrem echten Wert zu bezeugen.** GEMESSEN in `crates/ea-archive/src/layout.rs`: `MAX_ARCHIVE_BLOBS_V1 = 1_048_576` und `MAX_TOTAL_ARCHIVE_BYTES_V1 = 2_147_483_648`. Ein `vec![0; MAX_TOTAL_ARCHIVE_BYTES_V1 + 1]` ist eine Zuteilung von zwei Gibibyte in einem Wirtstest, und der Zeuge liest davon kein einziges Byte. Der Ausweg ist der, den `crates/ea-archive-fs/src/bundle.rs` bereits aufschreibt: `open_archive_bundle_capped` nimmt seine Schranke als Parameter, und sein Doc-Kommentar sagt warum — „Ein Zeuge mit der echten Schranke bräuchte eine Datei von zig Gigabyte, und das ist kein Test."

`DirectoryHandleSource` bekommt deshalb `with_caps_for_test(max_blobs: usize, max_total_bytes: usize)` hinter dem VORHANDENEN Merkmalstor `test-support` von `crates/ea-reader/Cargo.toml` — demselben Tor, hinter dem `SealedVaultV1::flip_one_wrapped_key_byte_for_test` und `::replace_sealed_anchor_bytes_for_test` stehen, und aus demselben Grund: `default = ["test-support"]`, weil ein Integrationstest das Merkmal SEINER EIGENEN Crate nicht einschalten kann, und abgeschaltet an der geteilten Wurzelkante `ea-reader = { path = "crates/ea-reader", default-features = false }`, sodass `crates/ea-reader-wasm` und das ausgelieferte wasm-Modul die Funktion NICHT sehen. `no_non_test_edge_carries_the_ea_reader_test_surface` in `tools/xtask/tests/workspace.rs` bewacht genau diese Kante und läuft ohne Änderung mit.

Der BLOB-Deckel wird zusätzlich mit seinem ECHTEN Wert bezeugt, und das ist bezahlbar: eine Million `push_blob` mit leerem `Vec` kostet eine Million Adress-`String`s und keine einzige Nutzlastzuteilung. Ohne diesen zweiten Zeugen bewiese die Kappenprüfung nur, dass `with_caps_for_test` funktioniert, und nichts darüber, welche Zahlen `new()` verdrahtet.

**11. `push_blob` prüft VOR der Kopie, aber nicht vor der Zuteilung des Aufrufers — und die erste Fassung behauptete das Falsche.** Die Zusage „beide Deckel fallen am `push_blob`, das den Puffer noch nicht angelegt hat" ist mit der Signatur `push_blob(&mut self, path_hint: String, bytes: Vec<u8>)` unhaltbar: wer ein `Vec<u8>` übergibt, hat es bereits zugeteilt. Die Signatur wird deshalb `push_blob(&mut self, path_hint: &str, bytes: &[u8]) -> Result<(), ArchiveError>`, und die richtige, kleinere Zusage lautet: die Quelle legt IHRE Kopie erst an, wenn beide Deckel geprüft sind. Über den Puffer des Aufrufers sagt sie nichts, und über den Browser sagt sie es erst recht nicht — `wasm_bindgen` kopiert ein `&[u8]` ohnehin in den linearen Speicher, bevor die Funktion beginnt.

`DirectoryHandleSource` braucht ausserdem `impl Default`, weil `clippy::new_without_default` unter `-D warnings` sonst bricht; `ArchiveFixture` in `crates/ea-archive/tests/support/mod.rs` trägt aus demselben Grund `#[derive(Default)]` neben seinem `new()`.

**12. Drei Zusicherungsformen der ersten Fassung übersetzen nicht.** Erstens: `hash_newtype!` in `crates/ea-types/src/ids.rs` leitet KEIN `Debug` ab, also läuft jeder Vergleich über `Hash32`, `EntryHash`, `ObjectHash` und `KeyThumbprint` als `assert!(a == b)` und niemals als `assert_eq!`/`assert_ne!`. Zweitens: `Result::unwrap_err` verlangt `T: Debug`, und `ReaderClassification` — und damit `OpenedArchiveV1` — trägt keines; die Fehlerprüfungen laufen über `.err().expect(..)`. Drittens: `assert!(report.object_results().len() > 0)` ist ein Zeuge, der nichts über die ERWARTETE Zahl sagt; `complete_archive()` trägt genau einen Eintrag (`crates/ea-reader-wasm/tests/verify_browser.rs` pinnt das als `ENTRIES_IN_THE_COMPLETE_ARCHIVE_V1`), also steht dort eine Gleichheit.

- [ ] **Step 1: Write the two-way, no-cursor, and not-server-confirmed witnesses**

Zuerst die drei neuen Kulissenfunktionen. Sie stehen in `crates/ea-reader/tests/verify_fixtures/fixtures.rs`, weil sie über die `#[path]`-Kette auch der Browserzeuge braucht, und sie nennen ausschliesslich `core`, `ea_archive` und `verify_support`:

```rust
// crates/ea-reader/tests/verify_fixtures/fixtures.rs — Ergaenzung

/// Die Blobs eines Bestands als Paare, in der Reihenfolge, in der die Kulisse
/// sie abgelegt hat.
///
/// Sie ist AUSDRUECKLICH nicht sortiert: der Verzeichnisdurchlauf des Browsers
/// ist es auch nicht, und die Gleichheit der zwei Wege haengt nach der Messung
/// oben nicht an der Reihenfolge, sondern an den Bytes.
#[must_use]
pub fn directory_blobs(source: &ArchiveFixture) -> &[(String, Vec<u8>)];

/// Dieselben Blobs als EIN Container, von Hand kodiert.
///
/// Von Hand, weil `encode_bundle` modulprivat in `crates/ea-archive-fs` liegt
/// und diese Kette per `#[path]` auch fuer wasm32 uebersetzt; die Form ist die
/// von `crates/ea-archive/tests/bundle_reader.rs::hand_built_container`. Die
/// Saetze werden VOR dem Kodieren streng aufsteigend ueber die Adressbytes
/// sortiert und auf Duplikatfreiheit geprueft — `ArchiveFixture` legt in
/// Baureihenfolge ab, und `ArchiveBundleSource::from_bytes` weist alles andere
/// mit `BundleError::Malformed` ab.
///
/// # Panics
///
/// Wenn zwei Blobs dieselbe Adresse tragen. Dann ist die Kulisse kaputt und
/// muss es laut sagen, statt einen Container zu bauen, den niemand liest.
#[must_use]
pub fn exported_bundle_bytes(source: &ArchiveFixture) -> Vec<u8>;

/// Der lueckenlose Bestand MIT gueltigen Serverquittungen.
///
/// Die Gegenkontrolle zu `complete_archive()`, und NUR fuer die eine Spalte
/// `serverConfirmation`. Der Bestand traegt die Vorlauf-Luecke `0..=1` der
/// Quittungslinie (`verify_support::RECEIPT_PRE_ENTRY_GAP_THROUGH_V1`) und ist
/// deshalb NICHT `is_fully_verified()`; wer hier eine Zusage ueber Maengel
/// aufschreibt, misst die Quittungslinie und nicht den Datei-Modus.
#[must_use]
pub fn archive_with_receipts() -> &'static ArchiveFixture;
```

```rust
// crates/ea-reader/tests/file_mode.rs
#[test]
fn the_bundle_and_the_same_blobs_produce_byte_identical_reports() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let archive = fixtures::complete_archive();

    let from_file = ReaderFileMode::open_bundle(
        fixtures::exported_bundle_bytes(archive),
        &vault,
        fixtures::EFFECTIVE_NOW,
    )
    .expect("das Buendel der Kulisse muss oeffnen");

    let mut directory = DirectoryHandleSource::new();
    for (path_hint, bytes) in fixtures::directory_blobs(archive) {
        directory.push_blob(path_hint, bytes).expect("beide Deckel liegen weit darueber");
    }
    // ANTI-LEERLAUF: ein leerer Ordner verifizierte ebenfalls, und beide
    // Berichte waeren dann aus dem falschen Grund gleich.
    assert_eq!(directory.blob_count(), fixtures::directory_blobs(archive).len());
    assert!(directory.blob_count() > 0);

    let from_directory = ReaderFileMode::open_directory(directory, &vault, fixtures::EFFECTIVE_NOW)
        .expect("dieselben Blobs muessen dasselbe ergeben");

    // KEIN `assert_eq!`: `Hash32` leitet kein `Debug` ab.
    assert!(from_file.report().report_hash() == from_directory.report().report_hash());
    assert!(from_file.report().is_fully_verified());
    assert_eq!(
        from_file.report().archive_object_count(),
        from_directory.report().archive_object_count(),
    );
    assert_eq!(from_file.mode(), ReaderMode::File);
    assert_eq!(from_directory.mode(), ReaderMode::File);
}

#[test]
fn every_object_without_a_receipt_is_not_server_confirmed_and_never_a_gap() {
    let opened = ReaderFileMode::open_bundle(
        fixtures::exported_bundle_bytes(fixtures::complete_archive()),
        &fixtures::unlocked_vault_with_pinned_anchor(),
        fixtures::EFFECTIVE_NOW,
    )
    .expect("der lueckenlose Bestand muss oeffnen");
    let report = opened.report();

    // GEMESSEN und nicht gewaehlt: `complete_valid_archive` legt GENAU EINEN
    // Eintrag ab, und `confirm_entries` gibt genau den Eintraegen ein Ergebnis.
    assert_eq!(report.object_results().len(), ENTRIES_IN_THE_COMPLETE_ARCHIVE_V1);
    assert!(
        report
            .object_results()
            .all(|result| result.server_confirmation() == ServerConfirmationV1::NotServerConfirmed)
    );
    assert!(
        report
            .object_results()
            .all(|result| result.result() == ObjectResultKindV1::Valid)
    );
    assert_eq!(report.gaps().len(), 0);
    assert_eq!(report.quarantined_objects().len(), 0);
    assert_eq!(report.format_errors().len(), 0);
    // Das ist die Zusage von design.md 17.4: eigene Dimension, kein Mangel.
    assert!(report.is_fully_verified());
}

/// Die Gegenkontrolle, und NUR ueber der einen Spalte.
///
/// Ohne sie waere die Zusicherung darueber auch dann gruen, wenn
/// `serverConfirmation` gar keinen zweiten Wert annehmen koennte. Ueber
/// Maengel sagt dieser Bestand ausdruecklich nichts: er traegt die
/// Vorlauf-Luecke der Quittungslinie.
#[test]
fn the_same_entry_point_reports_server_confirmed_when_the_receipts_travel_along() {
    let opened = ReaderFileMode::open_bundle(
        fixtures::exported_bundle_bytes(fixtures::archive_with_receipts()),
        &fixtures::unlocked_vault_with_pinned_anchor(),
        fixtures::EFFECTIVE_NOW,
    )
    .expect("auch der Quittungsbestand muss oeffnen");
    let report = opened.report();

    assert!(report.object_results().len() > 0);
    assert!(
        report
            .object_results()
            .all(|result| result.server_confirmation() == ServerConfirmationV1::ServerConfirmed)
    );
}

#[test]
fn the_directory_source_enforces_the_blob_cap_it_was_built_with() {
    // Der ECHTE Deckel, mit leeren Nutzlasten: er belegt, welche Zahl `new()`
    // verdrahtet, und kostet keine einzige Nutzlastzuteilung.
    let mut source = DirectoryHandleSource::new();
    for index in 0..MAX_ARCHIVE_BLOBS_V1 {
        source
            .push_blob(&format!("entries/{index}.eip"), &[])
            .expect("bis zur inklusiven Grenze traegt die Quelle");
    }
    assert_eq!(source.blob_count(), MAX_ARCHIVE_BLOBS_V1);
    assert_eq!(
        source.push_blob("entries/one-too-many.eip", &[]),
        Err(ArchiveError::BlobLimit),
    );
    // Und die Quelle hat den abgewiesenen Blob NICHT uebernommen.
    assert_eq!(source.blob_count(), MAX_ARCHIVE_BLOBS_V1);
}

/// Der Bytedeckel gegen eine EINSTELLBARE Schranke.
///
/// Dieselbe Bauform und derselbe Grund wie `open_archive_bundle_capped` in
/// `crates/ea-archive-fs/src/bundle.rs`: mit dem echten Wert braeuchte der
/// Zeuge zwei Gibibyte, die er nie liest. Gemessen wird die REIHENFOLGE — die
/// Summe faellt, bevor die Quelle ihre Kopie anlegt.
#[test]
fn the_directory_source_enforces_the_byte_cap_before_it_copies() {
    let mut source = DirectoryHandleSource::with_caps_for_test(8, 4);
    source.push_blob("entries/a.eip", &[0; 4]).expect("genau die Grenze traegt");
    assert_eq!(source.total_bytes(), 4);
    assert_eq!(
        source.push_blob("entries/b.eip", &[0]),
        Err(ArchiveError::TotalByteLimit),
    );
    assert_eq!(source.blob_count(), 1);
    assert_eq!(source.total_bytes(), 4);
}

#[test]
fn a_truncated_or_wrongly_magicked_container_reports_the_bundle_code_and_no_report() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();

    let mut truncated = fixtures::exported_bundle_bytes(fixtures::complete_archive());
    truncated.truncate(truncated.len() - 1);
    // `.err()` und nicht `.unwrap_err()`: `OpenedArchiveV1` traegt kein `Debug`.
    assert_eq!(
        ReaderFileMode::open_bundle(truncated, &vault, fixtures::EFFECTIVE_NOW)
            .err()
            .expect("ein angeschnittener Container ist kein Bestand")
            .code(),
        "EA-BUNDLE-MALFORMED",
    );

    let mut renamed = fixtures::exported_bundle_bytes(fixtures::complete_archive());
    renamed[0] ^= 0x01;
    assert_ne!(&renamed[..BUNDLE_MAGIC_V1.len()], &BUNDLE_MAGIC_V1[..]);
    assert_eq!(
        ReaderFileMode::open_bundle(renamed, &vault, fixtures::EFFECTIVE_NOW)
            .err()
            .expect("eine umbenannte Datei ist kein Bestand")
            .code(),
        "EA-BUNDLE-MALFORMED",
    );
}

/// Der dauerhaft angebundene Ordner verliert zwischen zwei Oeffnungen seine
/// Berechtigung.
///
/// Der Zeuge braucht dafuer [`DirectoryHandleSource::mark_unavailable`], und
/// die Methode ist keine Testhilfe, sondern die einzige ehrliche Abbildung
/// eines gemessenen Browserverhaltens: `FileSystemDirectoryHandle` gibt eine
/// entzogene Berechtigung beim NAECHSTEN Zugriff heraus, mitten im Durchlauf.
/// `apps/web/src/features/file-mode/DirectoryHandle.ts` ruft sie ueber
/// `fileModeDirectoryUnavailable`, sobald `queryPermission`/`requestPermission`
/// nicht mehr `granted` liefert. Ohne sie waere `ArchiveError::Unavailable`
/// ueber diesen Eingang gar nicht erreichbar — eine Quelle aus besessenen
/// Bytes kann das Liefern nicht verweigern.
#[test]
fn a_directory_whose_permission_was_revoked_reports_the_archive_code_and_no_report() {
    let archive = fixtures::complete_archive();
    let mut source = DirectoryHandleSource::new();
    for (path_hint, bytes) in fixtures::directory_blobs(archive) {
        source.push_blob(path_hint, bytes).expect("der Vorlauf traegt");
    }
    source.mark_unavailable();

    assert_eq!(
        ReaderFileMode::open_directory(
            source,
            &fixtures::unlocked_vault_with_pinned_anchor(),
            fixtures::EFFECTIVE_NOW,
        )
        .err()
        .expect("ein Ordner ohne Berechtigung ist kein Bestand")
        .code(),
        "EA-ARCHIVE-UNAVAILABLE",
    );
}
```

Der Beleg für „der Cursor entfällt ersatzlos" ist eine ÜBERSETZUNGSGRENZE und keine Zusicherung über einen Namen. Die Form ist die, die `crates/ea-key-provider/src/lib.rs` und `crates/ea-crypto/src/secret.rs` für ihre API-Flächenverbote schon führen, und `verify_quick_commands()` fährt sie mit `cargo test --workspace --doc --all-features --locked`:

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

`ReaderSyncService<'a>` trägt seinen Lebensdauerparameter wirklich (`crates/ea-reader/src/sync.rs`), das `<'_>` im zweiten Doctest ist also kein Schmuck; ohne ihn schlüge der Doctest aus dem falschen Grund fehl.

```rust
// crates/ea-reader/tests/file_mode_anchor.rs

// INVERTIERT gebaut, wie `crates/ea-reader/tests/pinned_anchor.rs`: nicht der
// Bestand ist fremd, sondern der TRESOR. Der Einschluss der Nachbarkulisse
// steht HIER und nicht in `verify_fixtures/mod.rs`, weil `crates/ea-reader-wasm`
// dieselbe `#[path]`-Kette benutzt und deren Kanten dort nicht liegen.
#[path = "fixtures/mod.rs"]
mod reader_fixtures;

#[test]
fn a_substituted_archive_says_nothing_about_any_entry_in_file_mode() {
    let bundle = fixtures::exported_bundle_bytes(fixtures::complete_archive());

    // Positivkontrolle ZUERST: DASSELBE Buendel gegen SEINEN eigenen Anker
    // traegt vollstaendig. Ohne sie waere der Fehlschlag unten von einer
    // kaputten Kulisse nicht zu unterscheiden.
    let own_vault = fixtures::unlocked_vault_with_pinned_anchor();
    let own = ReaderFileMode::open_bundle(bundle.clone(), &own_vault, fixtures::EFFECTIVE_NOW)
        .expect("der eigene Bestand muss oeffnen");
    assert!(own.report().is_fully_verified());

    // Und gegen einen FREMDEN gepinnten Anker faellt es.
    let foreign_vault = fixtures::vault_pinning(reader_fixtures::pinned_anchor_exact_bytes());
    let mut observer = RecordingObserver::new();
    let opened = ReaderFileMode::open_bundle_observed(
        bundle,
        &foreign_vault,
        fixtures::EFFECTIVE_NOW,
        &mut observer,
    )
    .expect("ein Befund ueber die Vertrauenskette ist nie ein Err");
    let report = opened.report();

    // KEIN `unwrap`: `PinnedTrustAnchor::from_vault` ist infallibel.
    let anchor = PinnedTrustAnchor::from_vault(&foreign_vault);
    assert_eq!(observer.events(), &GATE_ORDER_V1[..2]);
    assert!(!report.is_fully_verified());
    assert_eq!(report.object_results().len(), 0);
    assert_eq!(report.public_key_thumbprints().len(), 0);
    // GEMESSEN: alle sechs Mangelfelder bleiben LEER — der Lauf steigt nach
    // `protocol.enter(Gate::Trust)` mit `return report.seal()` aus. Eine
    // Zusicherung auf ein NICHT leeres Fehlerfeld waere rot.
    assert_eq!(report.gaps().len(), 0);
    assert_eq!(report.signature_errors().len(), 0);
    // Der Kopf ist das Sentinel aus `ChainHeadV1::sentinel(anchor.chain_id())`
    // (`crates/ea-verify/src/archive.rs`): Sequenz null, Nullhash, und die
    // Kettenkennung des GEPINNTEN Ankers.
    assert_eq!(report.chain_head().sequence(), ChainSequence::new(0));
    // `assert!` und nicht `assert_ne!`: `EntryHash` leitet kein `Debug` ab.
    assert!(report.chain_head().entry_hash() != anchor.as_trust_anchor().genesis_entry_hash());
    assert!(report.chain_head().chain_id() == anchor.as_trust_anchor().chain_id());
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

// Die zwei Dimensionen aus design.md 17.4, an ZWEI getrennten Traegern und
// nicht an einem: `toHaveTextContent` auf einem gemeinsamen Knoten waere auch
// dann gruen, wenn die Flaeche die Begriffe zusammenzoege.
it('marks every object as not server confirmed without calling it a defect', async () => {
  render(<OpenArchivePanel host={windowDouble()} bridge={bridgeWithoutReceipts()} />)
  await user.click(screen.getByRole('button', { name: 'Archivdatei öffnen' }))
  // Der Wortlaut kommt aus SERVER_CONFIRMATION_V1_VALUES der generierten
  // Kontraktdatei — der TEST darf ihn nennen, die Flaeche nicht (siehe unten).
  expect(await screen.findByTestId('server-confirmation')).toHaveTextContent(
    SERVER_CONFIRMATION_V1_VALUES[1],
  )
  expect(screen.getByTestId('verification-summary')).toHaveTextContent('Alle Objekte geprüft')
  expect(screen.queryByText('Lücke')).not.toBeInTheDocument()
  expect(screen.queryByText('ungültig')).not.toBeInTheDocument()
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()
})
```

- [ ] **Step 2: Run the witnesses and confirm the file mode is absent**

Run: `cargo test --locked -p ea-reader --test file_mode --test file_mode_anchor && cargo test --locked -p ea-reader --doc && pnpm --dir apps/web test --run OpenArchivePanel`

Expected: FAIL, weil `ReaderFileMode`, `ReaderArchiveSourceV1`, `DirectoryHandleSource`, `OpenedArchiveV1` und `ReaderFileModeError` nicht existieren, weil die drei neuen Kulissenfunktionen nicht existieren, und weil `apps/web/src/features/file-mode/` leer ist. Die zwei `compile_fail`-Doctests sind in diesem Schritt AUSDRÜCKLICH kein Beleg: ein `compile_fail` gegen einen nicht existierenden Typ ist grün aus dem falschen Grund und wird erst in Schritt 4 aussagekräftig, wenn `OpenedArchiveV1` und `ReaderFileMode` da sind und die verlangten Methoden trotzdem fehlen.

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

impl Default for DirectoryHandleSource { /* clippy::new_without_default */ }

impl DirectoryHandleSource {
    #[must_use]
    pub const fn new() -> Self;

    /// Dieselbe Quelle mit EINSTELLBAREN Deckeln, hinter `test-support`.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub const fn with_caps_for_test(max_blobs: usize, max_total_bytes: usize) -> Self;

    /// Uebernimmt eine Bytefolge, NACHDEM beide Deckel getragen haben.
    pub fn push_blob(&mut self, path_hint: &str, bytes: &[u8]) -> Result<(), ArchiveError>;

    /// Der Ordner liefert keine Bytes mehr — die Berechtigung wurde entzogen.
    pub const fn mark_unavailable(&mut self);

    #[must_use]
    pub const fn blob_count(&self) -> usize;

    #[must_use]
    pub const fn total_bytes(&self) -> usize;
}
```

```rust
// crates/ea-reader/src/file_mode.rs
pub struct ReaderFileMode;

impl ReaderFileMode {
    pub fn open_bundle(
        bytes: Vec<u8>,
        vault: &UnlockedVault,
        effective_now: UnixMillis,
    ) -> Result<OpenedArchiveV1, ReaderFileModeError>;

    pub fn open_bundle_observed(
        bytes: Vec<u8>,
        vault: &UnlockedVault,
        effective_now: UnixMillis,
        observer: &mut dyn GateObserver,
    ) -> Result<OpenedArchiveV1, ReaderFileModeError>;

    pub fn open_directory(
        source: DirectoryHandleSource,
        vault: &UnlockedVault,
        effective_now: UnixMillis,
    ) -> Result<OpenedArchiveV1, ReaderFileModeError>;

    pub fn open_directory_observed(
        source: DirectoryHandleSource,
        vault: &UnlockedVault,
        effective_now: UnixMillis,
        observer: &mut dyn GateObserver,
    ) -> Result<OpenedArchiveV1, ReaderFileModeError>;
}

/// OHNE Lebensdauerparameter und OHNE die Quelle: `ReaderClassification`
/// besitzt Bericht und Inventar, nach `classify` borgt nichts mehr.
pub struct OpenedArchiveV1 { /* private: classification, mode */ }

impl OpenedArchiveV1 {
    pub const fn classification(&self) -> &ReaderClassification;
    pub const fn report(&self) -> &VerificationReportV1;
    pub const fn mode(&self) -> ReaderMode;
}

/// Das Status-DTO als JSON — die REINE Funktion, ueber der die Bruecke liegt.
///
/// Sie steht hier und nicht in `crates/ea-reader-wasm`, damit ein gewoehnlicher
/// Wirtstest sie fahren kann; dieselbe Bauform wie `bundle_activation_json`.
pub fn file_mode_archive_json(opened: &OpenedArchiveV1) -> Result<String, ReaderFileModeError>;
```

**Vier Eingänge und nicht drei, und der vierte ist kein Komfort.** `open_directory_observed` fehlte in der ersten Fassung, obwohl der Ankerzeuge für den Verzeichnisweg dasselbe Protokoll braucht wie für den Bündelweg; ohne ihn wäre `GATE_ORDER_V1[..2]` nur über eine Datei messbar und der Komfortweg bliebe an dieser Stelle unbezeugt. Alle vier sind dünn über EINEM privaten Weg, der `ReaderArchiveSourceV1` baut und `ReaderVerifier::new(ReaderMode::File, effective_now).classify(&source, vault, observer)` ruft.

**Der Zeitparameter heisst `effective_now` und nicht `os_wall_clock`.** Beide Namen existieren im Arbeitsbaum und meinen denselben `UnixMillis`-Wert: `ReaderSyncService` führt das Feld `os_wall_clock` (`crates/ea-reader/src/sync.rs`), `ea_verify::VerifyOptions::new` und `write_archive_bundle` nennen ihn ebenso, `ReaderVerifier::new(mode, effective_now)` nennt ihn anders (`crates/ea-reader/src/verify.rs`), und die Kulisse verdrahtet beide über `pub const EFFECTIVE_NOW: UnixMillis = UnixMillis::new(verify_support::FIXTURE_OS_WALL_CLOCK_V1);`. Für DIESE Aufgabe entscheidet der einzige Verbraucher: der Wert wird wortwörtlich an `ReaderVerifier::new` durchgereicht und an nichts sonst. Ein zweiter Name an einer Ein-Sprung-Durchreichung wäre der zweite Name für dieselbe Tatsache. `fixtures::os_wall_clock()` gibt es nicht und entsteht auch nicht; die Zeugen nennen `fixtures::EFFECTIVE_NOW`.

KEINER der vier Eingänge nimmt einen `TrustAnchorV1` oder einen `PinnedTrustAnchor`. Das ist der eigene Zeuge dieser Aufgabe für §5.3: der Anker entsteht INNERHALB des Aufrufs aus `PinnedTrustAnchor::from_vault(vault)` und sonst nirgendher, und Trust-Objekte, die IN der geöffneten Datei liegen, begründen von sich aus kein Vertrauen. Ein Aufrufer kann keinen zweiten Anker anbieten, weil die Signatur keinen Platz dafür hat — dieselbe Konstruktionsregel, mit der `ea_trust` seine Beweistypen schützt. Die BINDUNG selbst gehört der Aufgabe „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der Anchor, den nur der Vault liefert" und wird hier weder wiederholt noch neu gerechnet.

Verifiziert wird über `ReaderVerifier::new(ReaderMode::File, effective_now).classify(&source, vault, observer)`. Damit gibt es GENAU EINEN Weg in die Pipeline. `ReaderVerifier` baut selbst `VerifyOptions::new(effective_now).with_recipient(session.kem_key_thumbprint(), session.kem_private_key())` und nimmt den Anker aus `PinnedTrustAnchor::from_vault(session)`. Diese Aufgabe ruft `ea_verify::verify_archive_observed` NICHT direkt und implementiert kein Gate ein zweites Mal; die Gate-Reihenfolge aus `design.md` §14.1 gilt in beiden Modi WORTGLEICH — `classify` LIEST den Modus ohnehin nicht, und `both_reader_modes_produce_the_same_gate_protocol_over_the_same_bytes` in `crates/ea-reader/tests/verification_order.rs` pinnt genau diese Nicht-Abhängigkeit bereits. Der einzige Unterschied ist Schritt 7: geprüft werden nur die im Bündel beziehungsweise Ordner enthaltenen Receipts und Checkpoints. Genau das tut `ea-verify` bereits von sich aus.

`ArchiveBundleSource::from_bytes` prüft den Container vollständig, BEVOR ein einziger Blob herausgegeben wird — Magie, Blobzahl aus dem Kopf, sortierter und duplikatfreier Index ohne Lücke und ohne Überlappung, beide Deckel. Die Datei ist unvertraut, weil sie durch den gewöhnlichen Dateidialog kommt; deshalb wird sie AUSSCHLIESSLICH über `from_bytes` gelesen und nie über `ea_archive_fs::open_archive_bundle`, das auf `std::fs` sitzt und in `ea-archive-fs` zurückbleibt. Kein zweiter Satz Zahlen und kein zweiter Satz Codes für dieselbe Tatsache: `ReaderFileModeError` führt keinen eigenen Code.

Die Deckel werden in RUST durchgesetzt und nicht in TypeScript, und das ist der Grund für die Push-Form von `DirectoryHandleSource`: `apps/web/src/features/file-mode/DirectoryHandle.ts` läuft den `FileSystemDirectoryHandle` rekursiv ab, je Ebene lexikografisch aufsteigend nach Namen sortiert — `entries()` gibt keine Ordnung, und eine unbestimmte Reihenfolge machte den Ablauf des Durchlaufs und damit jede Fehlermeldung vom Zufall der Browserimplementierung abhängig —, und reicht jede Bytesequenz EINZELN über die Brücke. Die Grenze fällt damit an derselben inklusiven Schranke wie beim Verzeichnisleser der Wiederherstellung, und TypeScript entscheidet nichts: es zählt nicht, es vergleicht nicht, es bricht auf den durchgereichten Fehlercode ab. Was der Durchlauf ausdrücklich NICHT herstellt, ist die globale Sortierung des Containers — die Messung oben zeigt, dass der Bericht sie nicht braucht.

`crates/ea-reader-wasm/src/file_access.rs` trägt SECHS Ausfuhren und nicht drei. Die erste Fassung nannte drei, und die Liste war in sich unvollständig: `file_mode_push_blob` allein öffnet nichts, `file_mode_open_bundle(bytes) -> u32` nannte keine Tresorsitzung, obwohl `ReaderFileMode::open_bundle` einen `&UnlockedVault` verlangt, und ein `u32` als Rückgabe wäre ein Griff auf ein Ergebnis, das niemand abholt. Die gemessene Form steht in `crates/ea-reader-wasm/src/vault_bridge.rs`: eine Sitzungskennung ist ein `u32` ohne Bedeutung ausserhalb ihres Moduls, die Tabelle ist ein `thread_local!` mit `RefCell<BTreeMap<..>>` und `Cell<u32>` für den Zähler, und `with_unlocked_vault(session, |vault| ..)` ist der einzige Zugriff. Die sechs Ausfuhren, jede mit `#[cfg(target_arch = "wasm32")]` am ITEM und nicht an der `mod`-Zeile — `every_wasm_bindgen_export_sits_behind_the_wasm32_cfg` in `crates/ea-reader-wasm/tests/bridge_boundary.rs` ist die EINZIGE Instanz, die das bemerkt:

| Ausfuhr | Signatur | Wofür |
|---|---|---|
| `fileModeBundleExtension` | `() -> String` | `BUNDLE_FILE_EXTENSION_V1`, damit `eabundle` nirgends in TypeScript steht |
| `fileModeOpenBundle` | `(session: u32, bytes: &[u8]) -> Result<String, JsValue>` | der universelle Weg, DTO als JSON |
| `fileModeBeginDirectory` | `() -> u32` | eine leere `DirectoryHandleSource` in der Tabelle |
| `fileModePushBlob` | `(handle: u32, path_hint: &str, bytes: &[u8]) -> Result<(), JsValue>` | eine Bytefolge, beide Deckel in Rust |
| `fileModeDirectoryUnavailable` | `(handle: u32) -> Result<(), JsValue>` | die entzogene Berechtigung |
| `fileModeOpenDirectory` | `(session: u32, handle: u32) -> Result<String, JsValue>` | der Komfortweg, DTO als JSON |

Über die Brücke gehen Bytes und Pfadhinweise hinein und ein Sitzungsgriff plus das generierte Status-DTO heraus — nie ein Bericht als freier Text, nie Schlüsselmaterial, nie ein entschlüsselter Wert. Der Fehlerweg ist der der Nachbarausfuhren: `JsValue::from_str(error.code())` und sonst nichts.

**Das Status-DTO entsteht in `crates/ea-ui-contracts` und trägt AUSDRÜCKLICH keine Modus-Vereinigung.** Der gemessene Weg ist: ein Eintrag in `READER_VIEW_MODELS_V1` in `crates/ea-ui-contracts/src/emit.rs`, dann `cargo run --locked -p ea-ui-contracts --bin emit-ts` — der EINZIGE Schreiber beider Kontraktdateien —, und `crates/ea-ui-contracts/tests/generated_ts_is_current.rs` hält die eingecheckte Datei danach zeichengleich gegen den Emitterausgang. Handgeschriebene Verträge sind durch `apps/web/src/bridge/no-hand-written-contracts.test.ts` verboten.

```rust
// crates/ea-ui-contracts/src/emit.rs — Ergaenzung von READER_VIEW_MODELS_V1
(
    "FileModeArchiveView",
    &[
        ("archiveObjectCount", "number"),
        ("entryPackageCount", "number"),
        ("fullyVerified", "boolean"),
        ("gapCount", "number"),
        ("serverConfirmedCount", "number"),
        ("notServerConfirmedCount", "number"),
        // Der archivweite Wert: `ServerConfirmed` NUR, wenn JEDES Objektergebnis
        // ihn traegt. Die Flaeche bekommt den Wortlaut damit aus Rust und
        // schreibt ihn nie selbst.
        ("serverConfirmation", "ServerConfirmationV1"),
    ],
),
```

`ServerConfirmationV1` steht in `READER_ENUMS_V1` bereits und wird NICHT ein zweites Mal deklariert; seine zwei Literale `server-bestätigt` und `nicht server-bestätigt` kommen aus `ServerConfirmationV1::label()` in `crates/ea-verify/src/report.rs` und aus keiner zweiten Quelle.

Eine Modus-Vereinigung `'server' | 'file'` wäre dagegen ein Fehler, und der Grund ist gemessen und im Emitter schon aufgeschrieben: `no-hand-written-contracts.test.ts` verbannt JEDES Literal JEDER emittierten Vereinigung aus jeder handgeschriebenen Web-Quelle, in den drei zitierten Formen — und `<input type="file">` in `OpenArchivePanel.tsx` ist genau `"file"`. Die Datei würde mit „duplicates the security literal file" rot, und zwar an einer Stelle, an der nichts falsch ist. `crates/ea-ui-contracts/src/emit.rs` trägt dieselbe Überlegung bereits für `'Activate' | 'KeepActive'` aus und hat sie dort zugunsten eines `boolean` entschieden. Der Modus bleibt deshalb ein reiner Rust-Begriff: `OpenedArchiveV1::mode()` gibt ihn heraus, das DTO nennt ihn nicht, und die Route `/datei` sagt ohnehin, wo man ist.

Aus derselben Schranke folgt die Wortwahl der Fläche. `apps/web/src/features/file-mode/OpenArchivePanel.tsx` DARF `nicht server-bestätigt` nicht schreiben — es rendert `view.serverConfirmation`. Es darf aus demselben Grund auch `verifiziert`, `Lücke`, `ungültig`, `vorhanden` und `vollständig` nicht schreiben — alle fünf sind Literale emittierter Vereinigungen, und die naheliegende Formulierung `vollständig geprüft` fiele an `vollständig` aus `EVIDENCE_STATUS_VALUES`. Der Wortlaut der Verifikationszusammenfassung lautet deshalb `Alle Objekte geprüft` beziehungsweise `Nicht alle Objekte geprüft`, und `OpenArchivePanel.test.tsx` prüft ihn über `data-testid="verification-summary"`. Wer hier einen anderen deutschen Satz wählt, prüft ihn vorher gegen `SERVER_CONFIRMATION_V1_VALUES`, `VERIFICATION_STATUS_VALUES`, `ENTRY_STATUS_VALUES` und `EVIDENCE_STATUS_VALUES` der generierten Datei.

`apps/web/src/features/file-mode/OpenArchivePanel.tsx` bietet BEIDE Wege an, und den universellen IMMER. Die Erkennung ist eine Fähigkeitsabfrage auf dem übergebenen Wirtsobjekt (`'showDirectoryPicker' in host`) und keine Browserkennung: eine Kennungsliste veraltet still, eine Fähigkeitsabfrage nicht. Fehlt `showDirectoryPicker` — Safari und Firefox —, erscheint der Komfortweg gar nicht erst, statt als abgeblendete Schaltfläche eine Fähigkeit zu behaupten, die es nicht gibt. Der Dateidialog filtert auf die Endung aus `fileModeBundleExtension()`, aber die Endung ist ein HINWEIS: die Klassifikation entscheidet `BUNDLE_MAGIC_V1`, und eine umbenannte Datei fällt am Magiebyte und nicht am Namen.

Die Oberfläche hält die zwei orthogonalen Dimensionen aus `design.md` §17.4 auseinander. Jedes Objekt trägt gleichzeitig einen Verifikationsbegriff und einen Server-Bestätigungsbegriff; im Datei-Modus ist `nicht server-bestätigt` der REGELFALL. Die Begriffe DÜRFEN NICHT zusammengefasst werden, und `nicht server-bestätigt` DARF NICHT als `Lücke` oder `ungültig` dargestellt werden und ebenso wenig als vollständig bestätigt. Praktisch heisst das: kein `alert`-Rollenelement, keine Fehlerfarbe, kein Ausrufezeichen-Icon; der Status steht als TEXT neben dem Verifikationsstatus, mit einem erklärenden Zusatz, dass im Datei-Modus keine Serverquittungen bezogen werden. Die ZEILENWEISE Darstellung je Eintrag entsteht hier ausdrücklich NICHT — sie gehört der Aufgabe „Integritätszentrierte Reader-Oberfläche in `apps/web` und die Rollengrenze zum Desktop"; diese Aufgabe zeigt das Ergebnis EINES Öffnens. Ant Design 6 bleibt mit deutschem `ConfigProvider`, statisch extrahiertem lokalem gehashtem CSS, `zeroRuntime: true`, direkten CSR-Importen aus `@phosphor-icons/react`, sichtbarem Fokus und Reduced-Motion-Unterstützung; es entsteht kein neues Token und keine Laufzeit-CSS.

`docs/traceability/stage-4-fault-points.json` bekommt seinen Abschnitt `file-mode` in genau der Form, die die drei vorhandenen Abschnitte `bundle-activation`, `sync-cursor` und `verification` derselben Datei bereits tragen — ein Array aus `{"name", "brackets", "witness"}`, jeder `witness` als `<pfad>::<funktion>`.

**Jeder `witness` dieses Manifests MUSS eine RUST-Testfunktion sein, und das ist eine gemessene Auflage und kein Stil.** `witness_resolves` in `tools/xtask/src/main.rs` sucht die Zeichenkette `fn <name>(` und akzeptiert sie erst, wenn — durch Attribute, Kommentare und Leerzeilen hindurch rückwärts — `#[test]` oder `#[tokio::test` unmittelbar davor steht. Ein Playwright-Zeuge in einer `.spec.ts` trägt weder das eine noch das andere; er würde mit „declares no function" abgewiesen. Browserläufe bleiben als ZUSÄTZLICHER Beleg willkommen — sie stehen in der Prosa des jeweiligen Schritts, nie in der Spalte `witness`. Ergänzend gemessen: `docs/traceability/stage-4-fault-points.json` wird von `tools/xtask/src/main.rs` heute noch von KEINEM Gate-Arm gelesen — der Auflöser läuft dort über `STAGE_THREE_FAULT_POINT_MANIFEST_PATH`. Der Stufe-4-Arm entsteht in der Aufgabe „Reader-Interoperabilität, Browser-Matrix, Datei-Modus, Privatheit und das Stufe-4-Gate"; wer die Zeugennamen hier falsch schreibt, merkt es erst dort. Deshalb stehen sie unten zeichengleich zu den Testfunktionen aus Schritt 1.

| Szenario | Klammer | Zeuge |
|---|---|---|
| `bundle-truncated` | eine im Transport abgeschnittene oder umbenannte Containerdatei: `EA-BUNDLE-MALFORMED`, und es entsteht KEIN Teilbericht | `crates/ea-reader/tests/file_mode.rs::a_truncated_or_wrongly_magicked_container_reports_the_bundle_code_and_no_report` |
| `directory-permission-revoked` | ein dauerhaft angebundener Ordner verliert zwischen zwei Öffnungen seine Berechtigung: der Öffnungsversuch bricht mit `EA-ARCHIVE-UNAVAILABLE` ab und der universelle Weg bleibt angeboten | `crates/ea-reader/tests/file_mode.rs::a_directory_whose_permission_was_revoked_reports_the_archive_code_and_no_report` |
| `substituted-archive` | ein untergeschobenes Archiv mit vollständiger EIGENER Vertrauenskette: der Lauf endet fail-closed an Gate `trust` und sagt über keinen Eintrag etwas aus | `crates/ea-reader/tests/file_mode_anchor.rs::a_substituted_archive_says_nothing_about_any_entry_in_file_mode` |

Ledger. `WR-053` und `WR-054` liegen als Zeilen in `docs/traceability/v0.1-requirements.csv` und sind von der Aufgabe „Stufe-4-Vorlauf: ADR 0005, wasm-Werkzeugpins und die aufgehobene Blockade" bereits als `planned` angelegt worden, damit `WEB_READER_MUST_ROWS` in `tools/xtask/tests/stage_gate.rs` sie von Anfang an hält. Diese Aufgabe füllt ihre BELEGSPALTE mit den Testpfaden oben; den Statuswechsel vollzieht die Stufenabnahme. Gemessen an `web_reader_must_requirements_are_recorded_as_v1_1_rows`: `ledger_fields` zerlegt jede Zeile in GENAU NEUN gequotete Felder und weist ein Anführungszeichen im Freitext laut zurück; verglichen werden `row[1] == "v1.1"`, `row[2]` enthält `2026-08-15-einsatzarchiv-web-reader-design.md` UND endet mit `5.3` beziehungsweise `5.4` (`ends_with`, nicht `contains`), `row[3]` ist nicht leer, `row[7] == "4"` und `row[8] == "planned"`. Die BELEGSPALTE ist `row[6]`, und sie wird für diese zwei Zeilen von KEINER Zusicherung geprüft — nur `WR-042` hat eine eigene Belegprüfung. Das ist kein Freibrief, sondern die Begründung dafür, die Zeugennamen dort zeichengleich zu den Funktionen zu schreiben: kein Gate fängt einen Tippfehler. `row[7]` und `row[8]` bleiben unberührt; wer hier den Status auf `implemented` zöge, machte `stage_gate` rot. `WR-052` bleibt unberührt auf Stufe `2` und Status `integrated`: der Ein-Datei-Bündelexport ist Stufe-2-Arbeit (Entscheidung D-HE2), diese Aufgabe VERBRAUCHT ihn und beansprucht ihn nicht ein zweites Mal.

- [ ] **Step 4: Run both ways, both caps, and the substituted archive**

Run: `cargo run --locked -p ea-ui-contracts --bin emit-ts && cargo test --locked -p ea-ui-contracts && cargo test --locked -p ea-reader --test file_mode --test file_mode_anchor && cargo test --locked -p ea-reader --doc && cargo run --locked -p xtask -- build-wasm && pnpm --dir apps/web test --run && pnpm --dir apps/web exec playwright test tests/e2e/file-mode.spec.ts`

**Die Reihenfolge dieses Kommandos ist gemessen und nicht kosmetisch.** Der Emitter läuft ZUERST, weil `generated_ts_is_current.rs` sonst gegen eine veraltete eingecheckte Datei vergleicht und `pnpm --dir apps/web test --run` gegen ein DTO läuft, das es noch nicht gibt. `xtask build-wasm` steht VOR den zwei `pnpm`-Armen, weil `apps/web/src/bridge/pkg/` sein Ausgang ist und `web:typecheck` und `web:test` ohne ihn mit TS2307 abbrechen — dieselbe Ordnungsmessung, die `verify_quick_commands()` in `tools/xtask/src/main.rs` bereits ausschreibt.

Expected: PASS. Beleg für Beleg: Bündel und Verzeichnis liefern denselben `reportHash`, also trägt der Komfortweg wirklich denselben Bestand und keine zweite Lesart — und der Zeuge sagt in seinem Namen, dass er die BYTES vergleicht und nicht die Adressen; jedes Objekt ohne Quittung steht auf `notServerConfirmed` UND `valid`, `gaps()` ist leer und `is_fully_verified()` bleibt wahr — die orthogonale Dimension senkt nichts —, und die Gegenkontrolle mit Quittungen belegt, dass die Spalte überhaupt zwei Werte annehmen kann; der Blob-Deckel fällt an seinem ECHTEN Wert und der Byte-Deckel an einer einstellbaren Schranke, beide bevor die Quelle ihre Kopie anlegt; die abgeschnittene und die umbenannte Datei liefern denselben stabilen `EA-BUNDLE-MALFORMED` und keinen Teilbericht; der Ordner ohne Berechtigung liefert `EA-ARCHIVE-UNAVAILABLE` und ebenfalls keinen. Die zwei `compile_fail`-Doctests belegen jetzt, was sie behaupten: `OpenedArchiveV1` und `ReaderFileMode` EXISTIEREN, und weder `confirmed_cursor()` noch `sync_service()` lässt sich an ihnen aufrufen — der Cursor entfällt ersatzlos, jedes Objekt wird bei jedem Öffnen vollständig geprüft. Der untergeschobene Bestand ist adversarisch gepaart: DASSELBE Byte-für-Byte gleiche Bündel trägt gegen den eigenen gepinnten Anker vollständig und fällt gegen den fremden — das Protokoll endet nach `["format", "trust"]`, `objectResults` ist leer, `publicKeyThumbprints` ist leer, weil `ea-verify` diesen Nachweis erst HINTER dem fail-closed-Ausstieg einträgt, und `chainHead` ist das Sentinel mit Sequenz null und ausdrücklich NICHT der `genesisEntryHash` des Ankers. Ohne die Positivkontrolle wäre der Fehlschlag von einer kaputten Kulisse nicht zu unterscheiden.

**Der Browserlauf deckt genau EINE Engine ab, und das ist eine benannte Grenze.** `apps/web/playwright.config.ts` existiert seit der Enrollment-Aufgabe, `apps/web/tests/e2e/` trägt bereits `enrollment.spec.ts` und `bundle-activation.spec.ts`, und `apps/web/src/e2e-config.test.ts` pinnt `config.projects.length === 1` mit dem Namen `chromium`. In diesem Task entsteht also KEIN Playwright-Gerüst, sondern eine dritte Spec darin — und ausgerechnet die Eigenschaft, die den universellen Weg überhaupt nötig macht (`showDirectoryPicker` fehlt in Safari und Firefox), lässt sich in Chromium nicht bezeugen. Sie hängt an zwei anderen Zeugen: an der Fähigkeitsabfrage in `OpenArchivePanel.test.tsx`, die den Wirt ohne `showDirectoryPicker` doubelt, und an der Browsermatrix der Aufgabe „Reader-Interoperabilität, Browser-Matrix, Datei-Modus, Privatheit und das Stufe-4-Gate", die `projects` erweitert und dabei `e2e-config.test.ts` mitzieht. `web:e2e` bleibt weiterhin AUSSERHALB von `verify:quick`, aus dem Grund, den `verify_quick_commands()` bereits notiert: Playwright verlangt installierte Engine-Baus und der wasm-bindgen-test-runner einen chromedriver, beides wäre eine neue Containervoraussetzung für JEDEN Schnelllauf; die benannte Klammer ist `browsers up` … `browsers down`.

- [ ] **Step 5: Commit the file mode**

```bash
git add crates/ea-reader crates/ea-reader-wasm crates/ea-ui-contracts apps/web \
        docs/traceability/stage-4-fault-points.json docs/traceability/v0.1-requirements.csv
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

**GEERBTE GRENZE aus dem Task „Inkrementeller Reader-Sync und verifizierter Cursor-Fortschritt in OPFS": das dauerhafte Objektmanifest traegt 32 768 Objekte, und diese Aufgabe MUSS 50 000 Pakete messen.** `MAX_CACHED_OBJECTS_V1` in `crates/ea-reader/src/cursor.rs` ist GERECHNET und nicht gewaehlt: die Adressliste des Objektcaches reist als EIN `bstr` durch `ea_cbor::validate(.., ParserLimits::V1)`, dessen `max_text_or_bytes` 1 048 592 Byte misst, und bei 32 Byte je Objekthash sind das 32 768 Eintraege. Ein Paket ist MINDESTENS ein Objekt, also traegt ein Reader unter dieser Grenze keine 50 000 Pakete — die Schwelle dieser Aufgabe ist mit dem heutigen Manifest nicht erreichbar, und `crates/ea-index/tests/scale_50000.rs` laeuft in eine Weigerung, bevor es irgendetwas misst.

Die Grenze ist fail-closed und keine stille Kuerzung: oberhalb von `MAX_CACHED_OBJECTS_V1` weigert sich `ConfirmedCursor` mit `EA-READER-VAULT-CONTENTS`. Sie ist damit ein sichtbares Hindernis und kein Datenverlust, und genau deshalb steht sie hier statt in einem Gate-Bericht.

Sie wurde in jenem Task BEWUSST stehen gelassen und nicht dort gehoben: das Manifest entstand erst als Antwort auf einen Reviewbefund („Rust besitzt den verifizierten Bestand, nicht JavaScript") und stand in keiner Zeile seines eigenen Files-Blocks; ein ungeblaettertes Blaetter-Subsystem waere dort gegen einen Brief gepruft worden, der es nicht kennt. Diese Aufgabe ist die erste, die die Zahl BRAUCHT, und deshalb die richtige, die sie aufloest.

Zwei Wege stehen offen, und die Wahl gehoert dieser Aufgabe: eine GEBLAETTERTE Adressliste ueber mehrere Blobs unter je einer eigenen Adresse — dieselbe Bauform, die §8.1 fuer den Index selbst ab 50 000 Paketen vorab genehmigt —, oder eine VERZEICHNISAUFZAEHLUNG im OPFS-Wirt, die den Bestand gar nicht erst zweitschreibt. Die zweite ist die kleinere Datenmenge und die groessere Vertragsaenderung: sie fasst `OpfsBlobStore::open` aus dem Task „`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der Laufzeitnachweis im Gate" an. Was diese Aufgabe auch waehlt, sie MIGRIERT ein bereits geschriebenes lokales Blobformat; das ist reader-lokaler Zustand und beruehrt die Produktinvariante „Archivbytes bleiben unveraendert" NICHT.

Was hier NICHT gilt: die Schwelle nach unten zu korrigieren. `design.md` `NFR-PERF-003` / Abnahmekriterium 31 und `tests/ea-system-tests/tests/performance_reader_50000.rs` der Stufe 7 messen 50 000, und eine Stufe-4-Architektur unterhalb davon waere genau die Wand, die die Global Constraints dieses Plans zu vermeiden vorgeben („damit Stufe 7 keine Wand findet, die sie nicht mehr verschieben kann").

Zwei GEMESSENE Folgen dieser Grenze gehoeren mit ihr zusammen aufgeloest, weil sie dieselbe Ursache haben. Erstens ist die Weigerung bei `MAX_CACHED_OBJECTS_V1` ein DAUERHAFTER Stillstand und kein sanftes Nachlassen: sie faellt in `ReaderSyncService::confirm`, also NACHDEM `accept_batch` die Objektbytes der Seite bereits dauerhaft gemacht hat. Ein Reader an der Grenze holt die Seite bei jedem Versuch erneut, schreibt sie erneut und weigert sich erneut. Zweitens versiegelt und schreibt `confirm` das VOLLSTAENDIGE Manifest bei JEDER Seite neu; der Aufwand ist O(n) in der Zahl der gehaltenen Objekte und steht damit quer zu einer Schwelle, die in Zehntausenden zaehlt. Wer hier blaettert, loest beide mit — wer nur die Zahl anhebt, keines von beiden.

Zwei Praezisierungen, ohne die eine Aufwandsschaetzung aus diesem Absatz zu klein ausfaellt. ERSTENS ist der Aufwand je Seite nicht EIN O(n)-Durchgang, sondern DREI: `required_blob_keys` gibt das vollstaendige Manifest zurueck, `OpfsBlobStore::open` nimmt je Schluessel einen Warteschlangenplatz und oeffnet ein `FileSystemSyncAccessHandle` NACHEINANDER; danach oeffnet und kopiert die Verifikation jedes zwischengespeicherte Objekt erneut; danach versiegelt `confirm` das ganze Manifest neu. Der erste dieser drei Durchgaenge ist ueberdies durch das Handle-Budget des Browsers begrenzt, eine Schranke, die keine der Zahlen oben nennt. ZWEITENS ist der Stillstand an der Grenze operativ eine SCHLEIFE und nicht bloss ein Halt: der Reader laedt dieselbe Seite bei jedem Versuch neu herunter und schreibt sie neu, bevor er sie ablehnt. Das ist, was ein Betreiber sieht, und es ist der Grund, warum der Stillstand teuer ist und nicht nur laestig.

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
- Produces: die Reader-Ansichtsmodelle in `ea-ui-contracts`, die Brueckenausfuhr `readerView` in `crates/ea-reader-wasm/src/view.rs`, `apps/web/src/bridge/reader-bridge.ts` als einzige Brueckenanbindung der Oberflaeche, die sechs Reader-Flaechen, die vier Integritaetsbausteine und den Rollengrenz-Zeugen im Desktop.

**TEILVERLUST des OPFS-Bestandes: heute ein DAUERHAFTES Feststecken, und der Ausweg hat keinen Browsereinstieg.** Der Task „Inkrementeller Reader-Sync und verifizierter Cursor-Fortschritt in OPFS“ weist mit `EA-READER-CHAIN-FORK` ab, sobald der verifizierte Kopf UNTER der bestaetigten Sequenz liegt. Diese Bedingung erreicht nicht nur ein gabelnder Server, sondern JEDE lokale Schrumpfung des Bestandes: ein verdraengter oder abgeschnittener `cache/`-Blob, oder ein verlorenes `sync/objects-v1` bei ueberlebendem `sync/cursor-v1` — es sind zwei UNABHAENGIGE Blobs, und nichts zwingt sie, zusammen zu verschwinden. Der VOLLSTAENDIGE Cacheverlust ist harmlos: der fehlende Cursor liest sich als Genesis und der gewoehnliche Pfad baut neu auf. Der TEILVERLUST hat keinen Ausgang — jeder weitere `readerSyncAcceptBatch` schreibt die Seite erneut und weist erneut ab.

Das steht gegen den Satz, den derselbe Task zwei Bildschirme weiter oben selbst aufstellt („Wer einen Abbruch als Luecke oder Fork ausgaebe, machte aus einem geschlossenen Tab einen Angriffsverdacht“): ein verlorener Blob wird hier eines gabelnden Servers beschuldigt. Das Mittel EXISTIERT und ist bezeugt — `ReaderSyncService::rebuild_from_genesis` —, aber `crates/ea-reader-wasm/src/fetch.rs` ist dort auf GENAU ZWEI Ausfuhren gepinnt, und keine davon ist diese. Ueberschreiben von `sync/cursor-v1` ueber die allgemeine `blobPut`-Ausfuhr hilft nicht: ein kurzer oder fremder Blob faellt in `get_sealed` durch und liefert `EA-READER-STORE`.

Wer hier die dritte Bruecken-Ausfuhr anlegt oder eine Wiederherstellungsflaeche baut, MUSS beides zusammen aufloesen: den Einstieg in `rebuild_from_genesis` UND die Anzeige, die den Teilverlust als das benennt, was er ist — ein lokaler Bestandsschaden und kein Angriffsbefund. Ein Fork und ein verdraengter Blob duerfen dem Betreiber nicht denselben Satz zeigen.

Dazu ein zweiter, kleinerer Befund derselben Herkunft: `required_blob_keys` leitet die Cache-Adressen aus dem NOCH UNGEPRUEFTEN Antwortkoerper ab, bevor der Startkopfvergleich laeuft, und `OpfsBlobStore::open` legt je Schluessel eine Datei an. Ein boesartiger oder fehlerhafter Server kann damit je Antwort bis zu `MAX_READER_PAGE_OBJECTS_V1` = 1 000 LEERE Verzeichniseintraege unter `ea-reader/cache/` entstehen lassen, fuer eine Seite, die danach abgewiesen wird. Fuer die Korrektheit sind sie folgenlos — Groesse 0 liest sich als abwesend, und `keys()` ueberspringt sie —, aber NICHTS raeumt sie je weg; `delete` laesst den leeren Eintrag ausdruecklich stehen. Der Aufraeumlauf gehoert in dieselbe Hand wie der Wiederherstellungseinstieg. `apps/web/playwright.config.ts` und das Wurzelskript `web:e2e` bestehen seit dem Task „Browser-Enrollment: zwei Pflicht-Authenticators und das nicht überspringbare Fingerprint-Gate" und werden hier nur BENUTZT.

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

