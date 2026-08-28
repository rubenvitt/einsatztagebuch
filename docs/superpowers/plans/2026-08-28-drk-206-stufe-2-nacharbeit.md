# DRK-206 — Stufe-2-Nacharbeit vor Start Stufe 3

**Goal:** Die elf Posten des ClickUp-Epics DRK-206 (B.1–B.11) so abarbeiten, dass `main` den Stufe-2-Stand mit nachgemessenem Gate trägt und Stufe 3 gegen stabile Schnittstellen starten kann.

**Spec (bindend):** `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md`. Stufe-2-Plan: `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-2-offline-writer.md`. Gate-Bericht: `docs/traceability/stage-2-gate.md`. Befundquellen (git-ignoriert, nur lesen): `.superpowers/sdd/2026-08-13-einsatzarchiv-stage-2-offline-writer/{progress.md,final/ABSCHLUSSREVIEW.md,fix-residuals-report.md}`.

## Global Constraints

- `#![forbid(unsafe_code)]` in jeder Crate; keine `libc`-Kante im eigenen Code. Neue Abhängigkeiten nur über `deny.toml`-konforme Lizenzen; `pnpm supply-chain` muss grün bleiben.
- Kryptografische oder formatkritische Logik nie in TypeScript. TypeScript erzeugt keine Grants, Hashes, Signaturen, Chiffrate, Registry-Entscheidungen oder Archivbytes.
- Keine fachlichen Klartexte (Einsatznummer, Ort, Namen, Freitext, Schlüssel, Nonces) in Logs, Fehlertexten, Dateinamen oder Panics.
- Fail-closed: jede neue Fehlerklasse hat einen stabilen `EA-…`-Code und einen Zeugen, der den Code pinnt (Codevergleich, nicht `is_err()`).
- Toolchain: jedes Cargo-Kommando mit `env -u RUSTUP_TOOLCHAIN` (die Shell überschreibt sonst den Pin `1.95.0`). Immer `--locked`.
- Tests: kein bestehender Test wird entfernt oder aufgeweicht. Neue Zeugen leben nach Möglichkeit in bestehenden Testzielen (die Zahl der Testbinaries ist im Gate-Bericht zitiert).
- Geschlossene Dokumente bleiben unangetastet: `docs/traceability/stage-1-gate.md`, `final/testqualitaet.md` und alle anderen `final/*.md`. Korrekturen dazu stehen in NEUEN Dokumenten oder als datierte Nachträge.
- Ledger `docs/traceability/v0.1-requirements.csv`: nur additive Zeilen; `v1`-Zeilen bleiben unverändert; Sortierung und nichtleere Belegspalte werden von `xtask` geprüft.
- Gate-Literale (`STAGE_TWO_HOST_SCOPE_CLAUSE`, `STAGE_TWO_GATE_REPORT_LITERALS` in `tools/xtask/src/main.rs`) werden nicht verändert.
- Commit-Format: `<type>(<scope>): <imperative>` wie in `git log`; ein Commit pro Task (oder wenige, thematisch getrennte).
- Sprache der Kommentare/Docs: Deutsch mit Umlauten wie im umgebenden Code (bestehende Dateien mit `ue`-Schreibweise behalten ihre Schreibweise).

## Reihenfolge und Abhängigkeiten

Tasks 1–4 sind Code, 5 ist Aufräumen, 6 ist Doku/Ledger, 7 ist die Messung. 7 läuft ZULETZT, weil sie den HEAD misst, der alle anderen Tasks enthält. Task 6 läuft nach 1–4, weil er deren Zeugen im Gate-Bericht/Ledger nennt.

---

### Task 1: B.6 — `receipt_for` bekommt die Quarantäneschranke

**Files:** `crates/ea-verify/src/entry.rs` (um Zeile 185, `receipt_for`), `crates/ea-verify/src/archive.rs` (Vorbild: Quarantäneschranke bei `own_grant`, ~Zeilen 565–575, Commit `3ff5f86`), Test in einer bestehenden Testdatei von `crates/ea-verify/tests/` (bevorzugt die, die `3ff5f86` für `own_grant` erweitert hat).

**Befund:** `receipt_for` wählt über dieselbe hashsortierte Sammlung wie `own_grant`, aber OHNE die Quarantäneschranke. Zweite gefälschte `.ecr` auf denselben `entry_object_hash` mit kleinerem Objekthash → beide isoliert, `receipt_for` liefert trotzdem die Fälschung; sie steht in `quarantinedObjects` UND `signatureErrors`, und ein echt serverbestätigter Eintrag fällt auf `NotServerConfirmed`.

**Soll:** `receipt_for` überspringt isolierte Objekte genauso wie `own_grant`; ein echter, nicht isolierter Receipt gewinnt, unabhängig von der Hashordnung. Ein Objekt erscheint nie gleichzeitig in `quarantinedObjects` und als gewählter Receipt.

**Test (zuerst rot):** Aufbau wie der `own_grant`-Zeuge aus `3ff5f86`, nur für Receipts: echter Receipt + gefälschter Receipt mit kleinerem Objekthash → Bericht `serverConfirmed` (oder das Äquivalent im Report), Fälschung in `quarantinedObjects`, kein `NotServerConfirmed`.

**Verify:** `env -u RUSTUP_TOOLCHAIN cargo test --locked -p ea-verify`, `cargo fmt --all --check`, `cargo clippy -p ea-verify --all-targets --all-features --locked -- -D warnings`.

---

### Task 2: B.7-Code — Abschlussmarke, Einsatznummer, Zeroize, N3, F7

**Files:** `crates/ea-writer/src/{marker.rs,finalize.rs,recover.rs,incident_number.rs,error.rs}`, `crates/ea-draft/src/{model.rs,discard.rs}`, Tests in `crates/ea-writer/tests/{prepared_recovery.rs,sequence_id.rs,…}` und `crates/ea-draft/tests/…`, ggf. `docs/traceability/stage-2-fault-points.json` (nur wenn ein Abbruchpunkt hinzukommt — dann auch `tests/ea-system-tests/tests/fault_injection_writer_matrix.rs`).

Fünf Posten aus dem Abschlussreview, jeder mit eigenem Zeugen (Test zuerst rot):

1. **PI-04** — Die Abschlussmarke wird beim Wiederaufnehmen (`recover.rs`) gegen ihre eigenen Bytes und gegen `grant_plan_hash` nachgerechnet; `grant_plan_hash` bekommt seinen Leser (`marker.rs:122-166`, `finalize.rs` um `:1187,:1205`). Eine Marke mit `grant_count = 0` oder abweichendem Grant-Plan-Hash wird fail-closed abgewiesen (bestehender Code `PreparedFinalizationUnreadable` oder neuer stabiler Code, Entscheidung begründen). Zeuge: manipulierte Marke → Code gepinnt, nichts veröffentlicht.
2. **PI-05** — Eine Finalisierung, die VOR der unwiderruflichen Grenze (Schritt 9, `draftDEK`-Löschung) scheitert, gibt die beanspruchte Einsatznummer wieder frei (`finalize.rs:727-739` beansprucht; `incident_number.rs:48,:81` hat keine Freigabe). Nach der Grenze bleibt sie verbraucht. Zeuge: Abbruch an einem `ReversibleDraft`-Punkt → dieselbe Einsatznummer ist erneut finalisierbar; Abbruch nach der Grenze → nicht.
3. **PI-06** — Der Entwurfsklartext (`crates/ea-draft/src/model.rs:144-149,:186-191`) trägt `Zeroize`/`ZeroizeOnDrop` (Crate `zeroize` ist bereits im Workspace, siehe `ea-crypto`). Zeuge: Typ implementiert `ZeroizeOnDrop` (Compile-Zeuge über `static_assertions`-artigen Trait-Bound-Test oder Doctest), und Schritt 9 nullt den Klartext, nicht nur den Serialisierungspuffer.
4. **N3** — Rollback in Schritt 13 hinterlässt keinen verwaisten Schlüsselspeichereintrag: beim Rollback wird der für den neuen leeren Entwurf angelegte `draftDEK`-Eintrag wieder gelöscht oder gar nicht erst angelegt. Zeuge: Fehlerinjektion in Schritt 13 → `KeyProvider::contains` für den neuen Eintrag ist `false`.
5. **F7** — Zwei unbezeugte Fail-closed-Klauseln des Wiederaufnahmepfads bezeugen: `PreparedFinalizationUnreadable` (`recover.rs:98`) und „jeder andere Schlüsselfehler bricht ab" (`recover.rs:110-116`); Zwilling `crates/ea-draft/src/discard.rs:220-225`. Dazu die Einzeiler-Schärfung `crates/ea-writer/tests/prepared_recovery.rs:95-97`: `!draft_dek_is_present()` → `draft_dek_entry_is_absent()` (der Leser existiert seit Bündel C).

**Verify:** `env -u RUSTUP_TOOLCHAIN cargo test --locked -p ea-writer -p ea-draft`, `cargo test --locked -p ea-system-tests --test fault_injection_writer_matrix`, fmt, clippy.

---

### Task 3: B.4 — Echte Betriebssystemsperre statt `create_new` + `Drop`

**Files:** `Cargo.toml` (Workspace-Dependency `fs4` mit Feature `sync`, oder `fd-lock`; Lizenz MIT/Apache), `crates/ea-archive-fs/Cargo.toml`, `crates/ea-archive-fs/src/local_path.rs` (`create_new` an `:475`, `:615`, `:758` — nur die Stellen, die eine SPERRE sind, nicht die, die Objekte atomar anlegen), `crates/ea-draft/Cargo.toml`, `crates/ea-draft/src/lock.rs:34`, `deny.toml` nur falls nötig, Tests in `crates/ea-archive-fs/tests/` und `crates/ea-draft/tests/`.

**Soll:** Die Sperrdatei wird mit `create(true)` (nicht `create_new`) geöffnet und mit `try_lock_exclusive` (flock/LockFileEx über die Crate) belegt. Eine liegengebliebene Datei eines toten Prozesses blockiert damit NICHT mehr: das Betriebssystem gibt die Sperre beim Prozessende frei. Fehlercodes bleiben: belegt → `EA-ARCHIVE-ALREADY-LOCKED` bzw. `DraftError::LockHeld`. Die Sperre wird im `Drop` gelöst (unlock + Datei darf liegen bleiben, sie ist jetzt harmlos). Das Gesundheits-/Inventarverhalten (`CONTROL_FILES_V1` ausgeblendet) bleibt unverändert.

**Zeugen (zuerst rot):** (a) eine vorbestehende Sperrdatei ohne lebende Sperre → die Sperre wird genommen (heute: Fehler). (b) zwei gleichzeitige Halter im selben Prozess (zwei `File`-Handles) → der zweite bekommt den gepinnten Code. (c) nach `drop` ist die Sperre wieder frei. Für beide Crates. `recover.rs` nach hartem Abbruch: der Neustartpfad ist damit erreichbar — bestehende Tests müssen grün bleiben.

**Nicht in diesem Task:** Plattform-Sperrbeobachter (Bildschirmsperre, R59 Teil 2) — bleibt Stufe 7, wird in Task 6 dokumentiert. Kein Reaper, keine PID-Prüfung (durch die OS-Sperre überflüssig; begründen im Doc-Kommentar).

**Verify:** `env -u RUSTUP_TOOLCHAIN cargo test --locked -p ea-archive-fs -p ea-draft -p ea-writer`, `cargo test --locked -p ea-system-tests --test fault_injection_writer_matrix`, `pnpm supply-chain`, fmt, clippy. Wasm32-Positivliste ist nicht betroffen (weder Crate steht darauf) — prüfen mit `pnpm verify:quick`-Teilschritt oder `cargo check --target wasm32-unknown-unknown` für die elf Pakete der Positivliste, falls schnell.

---

### Task 4: B.3 — Drei Tauri-Wirtsstummel verdrahten

**Files:** `apps/desktop/src-tauri/src/commands/writer.rs` (`draft_discard_begin` `:910`, `draft_discard_resume` `:920`, `archive_export_bundle_file` `:1019`), `apps/desktop/src-tauri/src/state.rs`, `apps/desktop/src-tauri/src/commands/mod.rs`, Tests in `writer.rs` (Muster: `a_refused_startup_path_becomes_a_blocked_outcome_with_its_code`), TypeScript-Seite nur, wenn die Bridge-Typen (`apps/desktop/src/bridge/`) bereits diese Kommandos deklarieren und ein Test die Antwortform prüft.

**Soll:**
- `draft_discard_begin(proof)` → `ea_draft::DiscardService::begin_discard` (`crates/ea-draft/src/discard.rs:130`); `draft_discard_resume` → `resume_discard`/`resume_after_restart` (`:143`, `:182`). Verlangt einen `OperatorSessionProof` mit `ReauthPurpose` für das Verwerfen, wie `draft_load_core` es tut. Ohne Nachweis: `NO_VERIFIED_SESSION`. Ohne Ablage: `DRAFTS_UNAVAILABLE`. Der heilende Arm `discard.rs:220-224` wird damit erreichbar (VM-11).
- `archive_export_bundle_file(target_path)` → `ea_archive_fs::write_archive_bundle` (`crates/ea-archive-fs/src/bundle.rs:422`). Ein Bestand, der nicht vollständig verifiziert, wird abgewiesen (bestehende Fail-closed-Grenze, Code aus `bundle_error.rs`), niemals still exportiert.
- `writer_acknowledge_stale_registry` BLEIBT Stummel mit `STALE_ACK_UNAVAILABLE` — der Kern (`WriterService::acknowledge_stale_registry`) existiert nicht; Ruling in Task 6 (B.2). Doc-Kommentar des Stummels nennt das Ruling.
- Für jedes verdrahtete Kommando ein Zeuge je Erfolgspfad und je Fehlercode; der Verwerfenspfad zusätzlich mit dem Muster „abgelehnter Startpfad wird Blockade, nicht Fehler".

**Verify:** `env -u RUSTUP_TOOLCHAIN cargo test --locked -p einsatzarchiv-desktop` (Paketname aus `apps/desktop/src-tauri/Cargo.toml`), `pnpm desktop:typecheck`, `pnpm desktop:test`, fmt, clippy.

---

### Task 5: B.10 + redaktionelle `note`-Posten (Batch)

**Files:** `.gitignore`, `tests/ea-system-tests/tests/conformance_golden_vectors.rs:204`, `crates/ea-writer/tests/grant_completeness.rs:23`, `crates/ea-writer/src/fault.rs:215,:218`, `crates/ea-writer/tests/prepared_recovery.rs:176-181`, `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-2-offline-writer.md` (Files-Block Tasks 9 und 11).

1. **B.10** — `fuzz/corpus/` in `.gitignore` (generierter Fuzz-Korpus); `mise.toml` in `.gitignore` (lokale Tool-Pins; `pnpm = "latest"` widerspricht dem `packageManager`-Pin und gehört nicht ins Repo). Kein Löschen von Dateien.
2. **QS-10** — `apps/desktop/playwright-report/` in `.gitignore`.
3. **S2** — `conformance_golden_vectors.rs:204`: Kommentar „23“ → „24“ Domain-Trennungszeichenketten (Array ist `[&str; 24]`).
4. **QS-09** — Files-Block-Zeile `vectors/crypto/suite-1` in den Taskabschnitten 9 und 11 des Stufe-2-Plans nachtragen.
5. **F10 (nur die mechanischen Teile)** — `grant_completeness.rs:23`: Erwartungswert als Literal statt abgeleitet; `prepared_recovery.rs:176-181`: `single_offset`/exakte Position statt `windows().any()`; `fault.rs:215,:218`: Doc-Kommentar, dass die zwei Punkte auf der Platte deckungsgleich sind und warum beide bleiben. Die zwei nicht-mechanischen F10-Teile (Verwerfensmatrix ohne Produktpfad, Harnesswurzel ohne Zähler) werden NICHT gemacht — sie gehen als Merker in Task 6.
6. **G5** — keine Änderung an `progress.md` (git-ignoriert); die Zahl wird in Task 6 im Nachtrag richtiggestellt.

**Verify:** `env -u RUSTUP_TOOLCHAIN cargo test --locked -p ea-writer -p ea-system-tests --test conformance_golden_vectors`, `rtk git status` zeigt keine untracked Dateien mehr außer `.superpowers/`-Artefakten.

---

### Task 6: B.2, B.5, B.7-Doku, B.8, B.9, B.11 — Rulings, Ledger, Gate-Bericht, Stufe-7-Überträge

**Files:** `docs/traceability/stage-2-gate.md`, `docs/traceability/v0.1-requirements.csv`, `docs/superpowers/plans/2026-08-13-einsatzarchiv-v0-1.md` (nur datierte Fußnote), `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-7-release-hardening.md`, `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-5-administration-recovery.md`, NEU `docs/traceability/stage-2-nacharbeit-2026-08-28.md`, `tools/xtask/tests/stage_gate.rs` nur falls eine Zusicherung gegen den Bericht angepasst werden muss (dann nur additiv/schärfer).

1. **B.2 — Ruling R62 (Stale-Registry-Quittung):** Das Gate-Bullet `2026-08-13-einsatzarchiv-v0-1.md:358` verlangt für Stufe 2 die dauerhafte signierte Einmal-Quittung. Stufe 2 liefert nur die Erkennung mit fail-closed-Ausgang; `WriterService::acknowledge_stale_registry` ist nicht gebaut (QS-06). Ruling: die Quittung wandert AUSDRÜCKLICH nach Stufe 5 (dort steht die Administrationsseite von AK 24). Festhalten: (a) datierte Fußnote unter dem Bullet in `v0-1.md` (den Wortlaut nicht ändern), (b) Abschnitt in der neuen Nacharbeitsdatei, (c) Merker im Stufe-5-Plan unter Global Constraints, (d) Ledger: bestehende `AK-24 v1.1`-Belegspalte NICHT ändern; additive Zeile nur, wenn `xtask` eine verlangt (prüfen).
2. **B.5 — Teilbelege AK 19/24/29/53 und Cross-Targets (G4):** Gegenstandsspalte aller zwölf `| AK `-Zeilen und der vier `| Teilbeleg AK `-Zeilen gegen den Wortlaut von `design.md` §23 prüfen und angleichen (AK 46 heißt dort „Entwurf und Eingabevertrag"); für AK 23, AK 39, AK 46 den nicht belegten Rest in der Offen-Spalte ausdrücklich nennen. Cross-Targets: EIN Messversuch `env -u RUSTUP_TOOLCHAIN cargo check --locked --workspace --target x86_64-apple-darwin` (nach `rustup target add`, falls der Pin es erlaubt); Ergebnis — gleich ob grün, rot oder nicht ausführbar — als eigener Abschnitt „Nachmessung x86_64-apple-darwin" in der Nacharbeitsdatei, OHNE die Reichweitenklausel oder die vier `planned`-Ledgerzeilen zu ändern.
3. **B.7-Doku:** QS-07 — zwei additive `v1.1`-Zeilen für `FR-064` und `FR-142` (Stufe 2, `implemented`, Beleg `local_path.rs:291`, `tests/format_package.rs:149` mit Testnamen). PI-09 — Pflicht-Ledgerzeile (Stufe 3, `planned`) für die Bereinigung von Staging-/Abbruchresten, Beleg nennt `recover.rs`/`health.rs` und `design.md:468`. N4 — Nachtrag im Gate-Bericht: der B-Zwischenschritt 942/943 ist aus den Berichten nicht rekonstruierbar; die Endzahl 955 stimmt. G5 — Richtigstellung „Stufe 1 endete bei 75 Zielen / 636 Tests (`stage-1-gate.md:160-167`)". Die nicht gemachten F10-Teile als Merker.
4. **Stufe-7-Überträge:** im Stufe-7-Plan unter Global Constraints je eine Zeile für R57(b) (native Keystore- und Re-Auth-API-Familien plus ADR 0003), R59 Teil 2 (Plattform-Sperrbeobachter, `is_valid_for`/`MAX_INACTIVITY_MS` im Wirt auswerten), R60 (nach Task 3 dieser Nacharbeit: die OS-Sperre IST gebaut; offen bleibt der Nachweis auf drei Betriebssystemen — Ledgerzeile `AK-39 v1.1` Stufe 7 entsprechend umformulieren, additiv oder in der Belegspalte der Stufe-7-Zeile), QS-12 (`cargo deny` als Pflicht-Ausführung), QS-11 (COSE-Prüfung kryptografisch vor dem Commit).
5. **B.8 — Korrekturanträge zu `final/testqualitaet.md` §9b:** die acht Stellen aus `progress.md` „Nachtrag 2026-08-27" als nummerierte Liste in der Nacharbeitsdatei, mit Commit-Belegen `66a3934`, `475f38a` und Task 2 dieser Nacharbeit; Schlusssatz „rund 21 statt rund 25". `testqualitaet.md` bleibt unangetastet.
6. **B.9 — Web-Reader-Prerequisites:** Status der Pre-flight-Konflikte 1 und 3 aus `docs/superpowers/plans/2026-08-16-einsatzarchiv-web-reader-stage-1-prerequisites.md:95-118` und der „offenen Flanke" `deny.toml` (:1018 — durch `pnpm supply-chain`/GATE-25 geschlossen) in einem Abschnitt der Nacharbeitsdatei festhalten; Konflikt 3 blockiert Stufe 5, nicht Stufe 3 — so benennen.
7. **B.11 — Merker Key-Provider ohne native Aufrufe:** prüfen, dass `AK-23 v1.1` Stufe 7 `planned` mit dem Literal „Ein gruener Stufe-2-Gate ist ausdruecklich kein Beleg fuer hardwaregebundene Schluessel." existiert; nur einen Verweis in der Nacharbeitsdatei, keine Änderung.
8. Gate-Bericht: neue Zeugen aus Tasks 1–4 in den passenden Belegzeilen/Abschnitten nennen (2.2: Sperrdateien-Zeile umschreiben — OS-Sperre gebaut, Reaper überflüssig, Nachweis auf drei OS bleibt Stufe 7).

**Verify:** `env -u RUSTUP_TOOLCHAIN cargo run --locked -p xtask -- stage-gate 2` (exit 0), `cargo test --locked -p xtask --test stage_gate`.

---

### Task 7: B.1 — Gate-Messung auf HEAD

**Files:** `docs/traceability/stage-2-gate.md` (Abschnitt „Gemessener Gate-Lauf" — Tabelle und Vorspann), `tools/xtask/tests/stage_gate.rs` nur lesen.

Die zehn Kommandos der Tabelle in genau der protokollierten Reihenfolge fahren, jedes mit `env -u RUSTUP_TOOLCHAIN` und `--locked`, Zahlen ABLESEN (Testbinaries, bestanden, fehlgeschlagen, ignoriert, gefiltert, Laufzeit, Exitcode), Tabelle und Vorspann (Testzahl, Ledgerzeilenzahl, Datum 2026-08-28, HEAD-Commit) aktualisieren, dann ein datierter Nachtrag „Nachmessung DRK-206" unter der Tabelle mit: welche Tasks die Zahlen bewegt haben. `pnpm verify:quick` dauert ~10 min. Wenn ein Kommando rot ist: NICHT die Tabelle schönschreiben — Status BLOCKED mit Ausgabe zurückmelden. Danach `cargo test --locked -p xtask --test stage_gate` (die Driftbindung liest die Tabelle).

**Verify:** alle zehn Exitcodes 0; `stage_two_gate_report_records_the_measured_full_gate_run` grün.
