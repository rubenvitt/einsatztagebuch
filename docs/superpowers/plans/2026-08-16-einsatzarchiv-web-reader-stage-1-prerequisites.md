# Einsatzarchiv Web-Reader Stage-1-Voraussetzungen Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Den am 2026-08-15 freigegebenen Web-Reader-Spec so weit in den Stage-1-Bestand einhängen, dass `wasm32-unknown-unknown` ab sofort in jedem Verifikationslauf geprüft wird und alle Entscheidungen, die nach dem Einfrieren in Task 11 irreversibel würden, entweder getroffen oder blockierend sichtbar sind — ohne eine einzige Wirestruktur, Objektfamilie oder Signaturregel zu ändern.

**Architecture:** Der Plan ist eine Normativkorrektur nach dem Muster der Task-8-Phase-A (`docs/superpowers/plans/2026-08-14-einsatzarchiv-task-8-trust-time-normative-correction.md`): ein ausführbarer RED zuerst, danach die Angleichung der Normativquellen, danach die Bauvoraussetzung, danach das Gate, danach die Absicherungen gegen den kommenden Freeze, abgeschlossen durch genau EINEN atomaren Commit nach vollständigen Gates und unabhängigen Reviews. Anders als das Muster ändert dieser Plan **kein CDDL, keinen Codec und keinen Parser** — die Musterschritte für Wireformat-Repin entfallen daher ersatzlos und bewusst.

**Tech Stack:** Rust 1.95.0 (`rust-toolchain.toml`), `cargo check --target wasm32-unknown-unknown`, `getrandom 0.4.3` Feature `wasm_js`, `xtask` als einzige Gate-Oberfläche (es existiert keine CI), `spec_completeness`-Tests als Prosa-gegen-Code-Zusicherung.

**Spec:** `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` (freigegeben 2026-08-15), zusammen mit `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md` als der Normativquelle, die dieser Plan angleicht.

---

## Pre-flight: Blockierende Entscheidungen

Diese vier Konflikte MÜSSEN vor Task 1 im Ledger stehen und menschlich freigegeben sein — nach dem Muster `.superpowers/sdd/2026-08-13-einsatzarchiv-stage-1-trust-core-format/progress.md:3` (`Pre-flight scan: human approved all recommended corrections on 2026-08-13`). Keine davon darf ein Implementierer selbst entscheiden; die Präzedenzklausel des Wire-Format-Addendums (`docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-wire-format-addendum.md:3-8`) sagt ausdrücklich: bei Widerspruch gilt die Umsetzung als blockiert, „Produktionscode darf nicht wählen".

**Konflikt 1 — Selbstwiderspruch des Web-Reader-Specs. Blockierend vor Task 2.**
`2026-08-15-einsatzarchiv-web-reader-design.md:20-24` sagt wörtlich: „Sie ändert keine Wireformate, keine Objektfamilien, keine Verifikationsreihenfolge und keine Signaturregeln." `:420-421` (§11.5/11.6) führt zwei neue Objektfamilien ein: `webBundleRelease` und das Escrow-Objekt.
Vorgeschlagene Korrekturrichtung: §1 gibt nach, die beiden Familien werden ausdrücklich als **v1.1-Erweiterung außerhalb Stage 1** geführt. Zu bestätigen ist, dass diese Richtung stimmt und nicht umgekehrt.

**Konflikt 2 — Form der Zwei-Approver-Autorisierung. Blockierend vor Task 11 des Stage-1-Plans.**
Spec §7.5 (`:311-313`) verlangt eine `organizationAdminAuthorization`, „signiert von zwei verschiedenen Approvern", plus die Bindung des Ziel-Transport-Public-Key-Fingerprints. Der Bestand pinnt das Gegenteil an vier Stellen: `crates/ea-trust/src/admin_authorization.rs:142-144` (`signatures().len() != 1`) mit hart indiziertem `signatures()[0]` in `:149`, `schemas/archive/v1/trust.cddl:22` (`[cose-sign1-v1]`), sowie die 15-Feld-Arity in `crates/ea-format/src/etb.rs:661/1454` und `crates/ea-crypto/src/cose.rs:2732`. Für den Transport-Key-Fingerprint existiert kein Feld; Position 15 ist ein an drei Stellen auf Länge 0 geprüftes leeres Extension-Array (`etb.rs:676/1489`, `cose.rs:2781`).
Zwei Ausgänge: **(a) universell** — die Kardinalität von `organizationAdminAuthorization` wird aufgeweitet, was jede bereits ausgestellte Autorisierung entwertet und alle sieben `action_code`-Werte berührt; **(b) eigene 2-of-N-Familie** nach dem Vorbild von `grantAuthorization`/`destructionAuthorization` (`trust.cddl:28-30`, `[2* cose-sign1-v1]`), rein additiv und byte-neutral für den Bestand.
Empfehlung aus zwei Panel-Linsen und der Synthese: **(b)**. Die Entscheidung gehört dem Spec-Autor.

**Konflikt 3 — Ablageort des Escrow-Chiffrats. Blockierend vor Stage 5.**
Spec §7.3 (`:292-295`) legt das Chiffrat in den „Root-signierten, append-only Trust-Bestand der Administrationszone". Der Begriff *Administrationszone* ist im normativen Design nicht definiert (`grep` über `2026-08-13-einsatzarchiv-v0-1-design.md` liefert null Treffer). Der einzige normativ definierte Root-signierte append-only Bestand ist `trust/` im Archiv (`design.md:1239-1273`), und der wird an jeden Reader repliziert — dort läge der umschlossene private KEM-Schlüssel jedes Readers bei jedem anderen Reader. Das ist eine Bedrohungsentscheidung, die der Spec nicht getroffen hat.

**Konflikt 4 — Zuordnung der Policy-Frist aus Spec §4.2. Blockierend vor Task 11 des Stage-1-Plans.**
Spec §4.2 (`:88-90`) fordert: „Die Anwendung MUSS deshalb das Alter des zuletzt bezogenen Trust-Standes sichtbar ausweisen und ab einer in der Policy konfigurierten Frist zur Aktualisierung auffordern." Keines der beiden Kandidatenfelder deckt das: `max_registry_age_ms` (`crates/ea-format/src/etb.rs:215`) ist laut `design.md:1347` eine Ausstellungsschranke am Registry-Ereignis (`notAfter - issuedAt <= policy.maxRegistryAgeMs`), keine geräteseitige Aktualisierungsfrist; `registry_expiry_behavior` (`etb.rs:217`) ist laut `design.md:1426` normativ an die **Finalisierung** gebunden — eine Operation, die der Reader nicht ausführt.
Zwei Ausgänge: **(a)** der bestehende Stale-Head-Mechanismus genügt für den Reader — dann reicht eine Klarstellung in `design.md` und dieser Plan bleibt wirestrukturfrei; **(b)** es wird eine eigene geräteseitige Frist gebraucht — dann ist `policy-core-v1` betroffen (`schemas/archive/v1/trust.cddl:127-141`, `crates/ea-format/src/etb.rs:210-229`), ein geschlossenes Array fester Positionen, das Task 11 mit dauerhaften Positivvektoren einfriert.
**Solange dieser Konflikt offen ist, ist die Prämisse „dieser Plan ändert keine Wirestruktur" für den Reader-Pfad unbewiesen, und Task 11 darf keine Policy-Positivvektoren einfrieren.**

---

## Global Constraints

Die Global Constraints des Stage-1-Plans (`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md:11-30`) gelten für diesen Plan vollständig und unverändert. Zusätzlich gilt:

- **Arbeitsumgebung:** Arbeite ausschließlich auf `main` im Hauptverzeichnis `/Users/rubeen/dev/personal/drk/einsatztagebuch`. Es existiert kein Worktree und kein Branch `codex/einsatzarchiv-v0-1` (verifiziert: `git branch -a` liefert nur `main`; `git worktree list` nur das Hauptverzeichnis). Lies und befolge `/Users/rubeen/.claude/RTK.md`; führe Repository-Kommandos durch `rtk` aus.
- **Geltungsbereich, geschlossene Verbotsliste.** Dieser Plan DARF NICHT: eine neue Trust-Objektfamilie einführen; eine reservierte Variante in `TrustSubtypeV1` (`crates/ea-format/src/etb.rs:17-29`) anlegen; einen Unknown-Fallback in `TrustSubtypeV1::from_str` (`etb.rs:45`) einbauen; `schemas/archive/v1/*.cddl` ändern; einen v2- oder Legacy-Trust-Parser anlegen; die Signatur-Kardinalität oder Feld-Arity von `organizationAdminAuthorization` ändern; einen Kryptopfad für `wasm32` aufweichen; einen Eintrag in `.cargo/config.toml` anlegen; einen anderen Stage-Plan als durch die in Task 6 benannten Merker- und Blockade-Zeilen ändern.
- **RED-Beweisregel.** Ein RED-Protokoll zählt nur, wenn die Ausgabe `1 failed` (bzw. den exakt erwarteten Compile-Fehler) zeigt. `0 passed; N filtered out` ist **kein** RED, sondern ein defekter Testfilter. Das gilt spiegelbildlich für GREEN: `0 passed; N filtered out` ist kein Grünnachweis.
- **RED-Protokollpfad.** `rtk` ersetzt die libtest-Ausgabe durch eine Zusammenfassung (gemessen: `cargo test: 1 passed, 33 filtered out`). Exit-Codes propagiert `rtk` korrekt (gemessen: 101). Gates laufen daher über `rtk`; **RED-/GREEN-Protokolle für die Berichtspflicht werden mit `rtk proxy cargo test …` oder rohem `cargo` erzeugt.**
- **Toolchain-Nachweis.** Vor jedem als Nachweis geltenden Gate-Lauf MUSS `rustup show active-toolchain` `1.95.0` melden. Ist `RUSTUP_TOOLCHAIN` in der Shell gesetzt, übersteuert es `rust-toolchain.toml` vollständig — dann gilt der Lauf nicht als Nachweis. `rust-toolchain.toml` DARF dafür NICHT geändert werden; die Shell ist zu bereinigen (`env -u RUSTUP_TOOLCHAIN …` als Minimallösung).
- **Reichweite.** Dieser Plan sichert ausschließlich **Übersetzbarkeit** für `wasm32-unknown-unknown`, nicht Lauffähigkeit. Der Laufzeitnachweis nach Spec §14.1 (`:460-464`) steht aus und ist nicht Gegenstand dieses Plans.
- **Ein Commit.** Zwischenzeitliche Commits sind verboten. Zwischen Task 3 und Task 4 fordert das Manifest ein Ziel ein, das das Gate noch nicht prüft; kein Zwischenstand beschreibt einen gültigen Zustand.

---

## File Structure

| Datei | Verantwortung in diesem Plan |
|---|---|
| `tools/xtask/tests/spec_completeness.rs` | Prosa-gegen-Code-Zusicherungen: Normativquellen-Marker, Vektor-Hygiene, Plan-Merker, Branch-Hygiene |
| `tools/xtask/tests/workspace.rs` | Manifest-Zusicherungen: Toolchain-Ziel, `getrandom`-Feature |
| `tools/xtask/src/main.rs` | `verify_quick_commands()` (`:25-46`) plus der byte-genaue Pin-Test (`:1269-1293`) |
| `rust-toolchain.toml` | Bereitstellung des `wasm32`-Ziels auf frischem Checkout |
| `Cargo.toml`, `Cargo.lock` | `getrandom`-Feature `wasm_js` und die eine dokumentierte Lockfile-Neuauflösung |
| `docs/adr/0001-toolchain-and-cryptography-dependencies.md` | Die heute fehlende `getrandom`-Zeile |
| `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` | Auflösung des Selbstwiderspruchs, Korrektur zweier empirisch widerlegter Aussagen |
| `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md` | §5.1, §5.2, §5.3, §7, §14.2, §17.4, §18.3 und die Support-Matrix-Zeile |
| `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md` | Global Constraints, Gate-Codeblock, Task-9-Pflicht, Task-11-Blockaden und Vektor-Hygiene |
| `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-{2..7}-*.md` | Je eine Merker-Zeile nach Spec §12; Stage 4 zusätzlich eine Blockade auf Spec §14.1 |
| `docs/superpowers/plans/2026-08-14-einsatzarchiv-task-8-*.md` | Datierte Fußnote zur historischen Arbeitsumgebung, Korrektur des RTK-Pfades |
| `.superpowers/sdd/2026-08-16-einsatzarchiv-web-reader-stage-1-prerequisites/progress.md` | Plan-eigenes Ledger (ungetrackt) |

---

### Task 0: Ledger anlegen und Pre-flight-Freigabe einholen

**Files:**
- Create: `.superpowers/sdd/2026-08-16-einsatzarchiv-web-reader-stage-1-prerequisites/progress.md`

**Interfaces:**
- Consumes: nichts.
- Produces: das Ledger, in das jede folgende Task ihre Abschlusszeile schreibt.

- [ ] **Step 1: Baseline messen**

Run:

```bash
rtk git rev-parse HEAD
rustup show active-toolchain
rtk cargo test --workspace --all-targets --locked
```

Erwartet: HEAD ist `05c2a4e`. `rustup show active-toolchain` MUSS `1.95.0-…` melden — meldet es etwas anderes oder enthält es `overridden by environment variable`, ist die Shell vor dem Weiterarbeiten zu bereinigen. Der Testlauf ist grün; die exakte Testzahl wird protokolliert.

- [ ] **Step 2: Ledger schreiben**

```markdown
# SDD ledger — plan: docs/superpowers/plans/2026-08-16-einsatzarchiv-web-reader-stage-1-prerequisites.md

Baseline: 05c2a4e
Baseline gate: `rtk cargo test --workspace --all-targets --locked` — <Exit-Code>, <n> passed, <m> suites.
Baseline toolchain: <Ausgabe von rustup show active-toolchain>
Pre-flight conflict 1: Web-Reader-Spec §1 (:20-24) bestreitet Objektfamilien-Änderungen, §11.5/11.6 (:420-421) führt zwei ein. — offen
Pre-flight conflict 2: Spec §7.5 Zwei-Approver — universelle Arity-Aufweitung vs. eigene 2-of-N-Familie. — ENTSCHIEDEN am 2026-08-17: eigene 2-of-N-Familie in Stage 5 als v1.1, `organizationAdminAuthorization` bleibt bei Kardinalität 1 und 15 Feldern. Wortlaut in `2026-08-13-einsatzarchiv-stage-1-trust-core-format.md` (Block `web-reader-blockers`). Task 11 nicht mehr blockiert; die Vektoren sind eingefroren.
Pre-flight conflict 3: Ablageort des Escrow-Chiffrats; „Administrationszone" ist im Design nicht definiert. Blockiert Stage 5. — offen
Pre-flight conflict 4: Policy-Frist nach Spec §4.2 (:88-90) ist keinem Feld von policy-core-v1 zuzuordnen. — ENTSCHIEDEN am 2026-08-17: `policy-core-v1` bekommt ein eigenes Feld `reader-trust-refresh-ms` unmittelbar nach `reader-inactivity-ms`; das geschlossene Array hat damit 22 statt 21 Positionen, und `parse_policy_core` zieht positionsgleich mit. Wortlaut in `2026-08-13-einsatzarchiv-stage-1-trust-core-format.md` (Block `web-reader-blockers`). Task 11 nicht mehr blockiert; die Positivvektoren sind eingefroren (`vectors/trust/v1/manifest.json`). Die Aritaet ist seit dem Stage-1-Review auch gegen die CDDL gepinnt (`tools/xtask/tests/spec_completeness.rs`, `trust_cddl_enforces_the_exact_twenty_two_positions_of_policy_core_v1`).
Pre-flight defect: Stage-1-Plan:1710 nennt `pnpm test:fuzz -- --smoke-seconds 60` (in cfd5a65 für den Task-8-Plan bereits als fehlerhaft korrigiert; korrekt ist die Form ohne freistehendes `--`). Gehört in Task 11.
Pre-flight defect: Stage-1-Plan:1711 nennt `cargo run --locked -p xtask -- stage-gate 1`; `stage-gate` ist kein Subcommand des Dispatchers (tools/xtask/src/main.rs:701-724). Gehört in Task 11.
Pre-flight defect: schemas/reports/v1/verification-report.schema.json kennt kein formatErrors und kein Quarantäne-Array, während Stage-1-Plan:1533 Quarantäne erzeugt. Gehört in Task 9.
```

- [ ] **Step 3: Menschliche Freigabe einholen**

Lege die vier Pre-flight-Konflikte dem Menschen vor. Ohne dokumentierte Freigabe DARF Task 1 nicht beginnen. Trage die Freigabe als Zeile ein: `Pre-flight scan: human approved <Aufzählung> on <Datum>`.

- [ ] **Step 4: Kein Commit**

Das Ledger liegt unter `.superpowers/` und wird nicht gestaged.

---

### Task 1: Ausführbarer normativer RED

**Files:**
- Modify: `tools/xtask/tests/spec_completeness.rs` (anhängen)
- Modify: `tools/xtask/tests/workspace.rs` (anhängen)

**Interfaces:**
- Consumes: die Pre-flight-Freigabe aus Task 0.
- Produces: `web_reader_stage_one_scope_is_closed_across_normative_sources`, `verify_quick_block_in_stage_one_plan_matches_the_gate`, `rust_toolchain_declares_the_wasm32_target`, `workspace_getrandom_enables_the_wasm_js_feature`. Task 2 macht den ersten grün, Task 3 die letzten beiden, Task 4 den zweiten.

**Wichtig:** Dieser Test prüft **nicht** die Vektor-Hygiene und **nicht** die §7.5-Blockade. Beide gehören ausschließlich zu `stage_one_vector_hygiene_reserves_out_of_band_negative_literals` in Task 5, damit jede Task genau einen RED-Verantwortlichen behält.

- [ ] **Step 1: Den Normativquellen-Test schreiben**

An `tools/xtask/tests/spec_completeness.rs` anhängen:

```rust
#[test]
fn web_reader_stage_one_scope_is_closed_across_normative_sources() {
    let web_reader =
        include_str!("../../../docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md");
    let design =
        include_str!("../../../docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md");
    let stage_one = include_str!(
        "../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md"
    );

    // Der Selbstwiderspruch des Specs ist aufgelöst.
    assert!(
        !web_reader.contains("Sie ändert keine Wireformate, keine Objektfamilien"),
        "spec §1 still denies the object-family change introduced in §11.5/11.6"
    );
    assert!(
        web_reader.contains("v1.1-Erweiterung außerhalb Stage 1"),
        "spec must classify webBundleRelease and readerKeyEscrow as v1.1 outside stage 1"
    );
    // getrandom 0.4.3 braucht kein --cfg getrandom_backend. Positiv geprueft, nicht
    // per Abwesenheit: der korrigierte Text MUSS den entfallenen Mechanismus benennen
    // und enthaelt das Literal daher zwangslaeufig.
    assert!(
        web_reader.contains("ist für 0.4.3 **nicht** erforderlich"),
        "spec §10 must record that getrandom 0.4.3 needs no cfg flag"
    );
    assert!(
        !web_reader.contains("und `--cfg getrandom_backend=\"wasm_js\"`"),
        "spec §10 still demands the getrandom 0.3 cfg flag as a requirement"
    );

    // Design: Browser-Zone ergänzt, Reader aus der Desktopzone entfernt.
    assert!(
        design.contains("Browser-Zone"),
        "design §5.3 must carry the fifth trust zone from spec §3"
    );
    assert!(
        !design.contains("**Desktop-/Archivzone:** Writer, Reader, Admin"),
        "design §5.3 zone 2 must no longer list the Reader"
    );
    // Design: der neue Verifikationsstatus aus spec §5.4.
    assert!(
        design.contains("nicht server-bestätigt"),
        "design §17.4 must carry the status term required by spec §5.4"
    );
    // Design: die fünf weiteren durch den Spec widerlegten Fundstellen.
    for marker in [
        "web-reader-design",   // Verweis auf den Spec an jeder korrigierten Stelle
        "apps/web",            // §5.1 Komponentenmodell
    ] {
        assert!(design.contains(marker), "design must reference {marker}");
    }
    assert!(
        !design.contains("gemeinsame Binär- und UI-Basis für Writer, Reader und Administration"),
        "design §5.1 must split desktop (Writer, Administration) from the web reader"
    );

    // Stage-1-Plan: die zwei kollidierenden Global-Constraint-Zeilen.
    assert!(
        stage_one.contains("Reader läuft im Browser"),
        "stage 1 global constraints must exempt the Reader from the desktop platform list"
    );
    assert!(
        stage_one.contains("Ant Design 6") && stage_one.contains("Writer und Administration"),
        "stage 1 global constraints must scope the Ant Design chain to Writer and Administration"
    );
}
```

- [ ] **Step 2: Den Korrelationstest zwischen Plan-Prosa und Gate schreiben**

Heute prüft nichts, dass der normative Rust-Block im Stage-1-Plan (`:143-154`) und `verify_quick_commands()` dieselben Kommandos beschreiben (`grep` nach `verify_quick|verify-quick|verify:quick` in `tools/xtask/tests/spec_completeness.rs` liefert null Treffer). An `spec_completeness.rs` anhängen:

```rust
#[test]
fn verify_quick_block_in_stage_one_plan_matches_the_gate() {
    let stage_one = include_str!(
        "../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md"
    );
    for command in [
        r#"("cargo", vec!["fmt", "--all", "--check"])"#,
        r#""clippy", "--workspace", "--all-targets", "--all-features", "--locked""#,
        r#"("cargo", vec!["test", "--workspace", "--all-targets", "--locked"])"#,
        r#""check", "--target", "wasm32-unknown-unknown", "--locked""#,
    ] {
        assert!(
            stage_one.contains(command),
            "stage 1 plan verify-quick block is missing {command}"
        );
    }
    // Die Stage-1-Gate-Kommandoliste nennt das Ziel ebenfalls.
    assert!(
        stage_one.contains("cargo check --target wasm32-unknown-unknown --locked -p ea-types"),
        "stage 1 gate command list must run the wasm32 check"
    );
}
```

- [ ] **Step 3: Die zwei Manifest-Tests schreiben**

An `tools/xtask/tests/workspace.rs` anhängen:

```rust
#[test]
fn rust_toolchain_declares_the_wasm32_target() {
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
}

#[test]
fn workspace_getrandom_enables_the_wasm_js_feature() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest: Value = fs::read_to_string(root.join("Cargo.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let getrandom = &manifest["workspace"]["dependencies"]["getrandom"];
    assert_eq!(getrandom["version"].as_str(), Some("=0.4.3"));
    let features = getrandom["features"]
        .as_array()
        .expect("getrandom must declare features so wasm32 resolves a backend");
    assert!(
        features.iter().any(|f| f.as_str() == Some("wasm_js")),
        "getrandom must enable wasm_js; getrandom 0.4.3 needs no --cfg getrandom_backend"
    );
}
```

- [ ] **Step 4: RED protokollieren**

Run (roh, nicht durch `rtk`, damit die libtest-Ausgabe erhalten bleibt):

```bash
rtk proxy cargo test --locked -p xtask --test spec_completeness web_reader_stage_one_scope_is_closed_across_normative_sources -- --exact --nocapture
rtk proxy cargo test --locked -p xtask --test spec_completeness verify_quick_block_in_stage_one_plan_matches_the_gate -- --exact --nocapture
rtk proxy cargo test --locked -p xtask --test workspace rust_toolchain_declares_the_wasm32_target -- --exact --nocapture
rtk proxy cargo test --locked -p xtask --test workspace workspace_getrandom_enables_the_wasm_js_feature -- --exact --nocapture
```

Erwartet: jeweils Exit 101 mit `1 failed`. Ein `0 passed; N filtered out` ist ein defekter Filter und kein RED — dann ist der Testname oder das Target falsch. Konkret erwartete Ursachen: der Web-Reader-Spec ist heute in keiner anderen Datei verankert (`grep -rn "web-reader-design" docs/superpowers/plans schemas crates tools tests` liefert null Treffer), `rust-toolchain.toml` hat kein `targets`-Feld, `Cargo.toml:26` lautet `getrandom = "=0.4.3"` ohne Features.

- [ ] **Step 5: Kein Commit**

Trage im Ledger ein: `Task 1: complete — vier RED protokolliert (Exit 101, je 1 failed).`

---

### Task 2: Normativprosa angleichen

**Files:**
- Modify: `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md:20-24`, `:387-405`, `:425-426`
- Modify: `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md:102`, `:113`, `:122-126` (§5.2), `:128-135` (§5.3), `:248`, `:1573`, `:1889`, `:1916`
- Modify: `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md:23-24`
- Modify: `docs/superpowers/plans/2026-08-13-einsatzarchiv-v0-1.md`

**Interfaces:**
- Consumes: Freigabe von Pre-flight-Konflikt 1.
- Produces: `web_reader_stage_one_scope_is_closed_across_normative_sources` wird grün.

- [ ] **Step 1: Den Selbstwiderspruch des Specs auflösen**

In `2026-08-15-einsatzarchiv-web-reader-design.md` §1 den Satz in `:20-24` ersetzen:

> Diese Spezifikation legt fest, wie der Reader im Browser betrieben wird, ohne die kryptografischen Invarianten der v0.1 zu schwächen. Sie ändert keine bestehenden Wireformate, keine Verifikationsreihenfolge und keine Signaturregeln bestehender Objekte. Sie führt zwei neue Trust-Objektfamilien ein — `webBundleRelease` (§4.2) und das Reader-Key-Escrow (§7) —; beide sind ausdrücklich eine **v1.1-Erweiterung außerhalb Stage 1** und werden nach §12 in Stage 3 beziehungsweise Stage 5 gebaut. Sie ändert die Ausführungsumgebung des Readers, die Verwahrung der Reader-Schlüssel, die Auslieferung des Reader-Codes und die Wiederherstellung nach Schlüsselverlust.

- [ ] **Step 2: Die zwei empirisch widerlegten Spec-Aussagen korrigieren**

In §10 (`:394-395`) entfällt die Forderung nach dem cfg-Flag. Neue Fassung des Aufzählungspunktes:

> - Einzige erforderliche Anpassung: `getrandom 0.4.3` benötigt das Feature `wasm_js`. Das aus `getrandom 0.3` stammende `--cfg getrandom_backend="wasm_js"` ist für 0.4.3 **nicht** erforderlich; gemessen am 2026-08-16 genügt das Feature allein.

In §12 (`:425-426`) den Stage-1-Punkt präzisieren:

> - **Stage 1:** `wasm32-unknown-unknown` als vierter Eintrag in `verify_quick_commands()` (`tools/xtask/src/main.rs`), als Positivliste über die sieben Bibliotheks-Crates; `targets` in `rust-toolchain.toml`; `getrandom`-Feature `wasm_js`. Das Gate belegt ausschließlich Übersetzbarkeit, nicht Lauffähigkeit. Sonst unverändert.

- [ ] **Step 3: design.md §5.3 um die Browser-Zone ergänzen**

`design.md:131` verliert den Reader, und nach `:133` kommt Punkt 5 im Wortlaut von Spec §3 (`:60-63`):

```markdown
2. **Desktop-/Archivzone:** Writer, Admin, verschlüsselte lokale Datenbanken und lokales Archiv.
3. **Serverzone:** Axum, PostgreSQL, Object Store und Server-Belegschlüssel.
4. **Externe Evidence-Zone:** RFC-3161-Time-Stamp-Authority; sie erhält nur Hashwerte.
5. **Browser-Zone:** installierte Web-Anwendung, Reader-Vault, verschlüsselter lokaler Index, gepinnter Root-Anchor. Sie ist gegenüber der Serverzone misstrauisch; sie akzeptiert weder Code noch Vertrauensmaterial allein auf Aussage des Servers. Siehe `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §3.
```

- [ ] **Step 4: design.md §17.4 um den Status aus Spec §5.4 ergänzen**

Spec §5.4 (`:157-160`) fordert einen sichtbaren Zustand *nicht server-bestätigt*; `design.md:1889` friert die Verifikations-Statussprache ohne ihn ein, und Stage-1-Plan `:27` macht daraus eine Stage-1-Invariante. `design.md:1889` wird zu:

```markdown
- Verifikation: `verifiziert`, `Lücke`, `fehlender Grant`, `unbekannter Schlüssel`, `nicht darstellbares Schema`, `ungültig`
- Server-Bestätigung (orthogonal zur Verifikation, kein Fehlerzustand): `server-bestätigt`, `nicht server-bestätigt`
```

Ergänze unmittelbar darunter:

**Verifiziert vor dem Schreiben:** Kein Test pinnt die sechs Verifikationsbegriffe heute als abschließende Menge — `grep -rn "nicht darstellbares Schema\|fehlender Grant\|unbekannter Schlüssel" tools/xtask/tests crates tests --include='*.rs'` liefert am 2026-08-16 null Treffer. Diese Ergänzung ist daher rein additiv und erzeugt keinen zweiten RED. Ändert sich das bis zur Ausführung, ist der pinnende Test in Task 1 als zusätzlicher RED aufzunehmen.

> Die Server-Bestätigung ist eine eigene Dimension. Ein Objekt kann `verifiziert` und zugleich `nicht server-bestätigt` sein; im Datei-Modus des Web-Readers (`web-reader-design.md` §5.4) ist genau das der Regelfall. Die beiden Dimensionen DÜRFEN NICHT zusammengefasst und `nicht server-bestätigt` DARF NICHT als `Lücke` oder `ungültig` dargestellt werden.

- [ ] **Step 5: Die fünf weiteren widerlegten design.md-Fundstellen korrigieren**

| Zeile | Heute | Korrektur |
|---|---|---|
| `:102` | `support-matrix.json` pinnt je Kombination „Architektur, Installerformat, Key-Provider" | Reader-Vorbehalt: für den Reader treten nach `web-reader-design.md` §11.4 Engine, Version und Plattform an deren Stelle |
| `:113` | „**Tauri-2-Desktopanwendung:** gemeinsame Binär- und UI-Basis für Writer, Reader und Administration." | Aufteilen: „**Tauri-2-Desktopanwendung (`apps/desktop/`):** gemeinsame Binär- und UI-Basis für Writer und Administration." plus neuer Punkt „**Installierbare Web-Anwendung (`apps/web/`):** Reader als PWA mit `wasm32`-fähigem Rust-Kern; siehe `web-reader-design.md` §3." |
| `:122-126` (§5.2) | Rollenzuordnung der gemeinsamen Desktopanwendung | Ersetzen durch die Rollenzuordnung aus Spec §3 (`:46-56`), inklusive des Satzes, dass die Web-Anwendung keinen Code für Writer-Finalisierung, Root-Zeremonien, Operator-Provisionierung, Historical Re-grant oder Vernichtungsausführung enthält |
| `:248` | „nach fünf Minuten Inaktivität oder OS-Sperre endet die Sitzung" | Vermerk anfügen: für den Web-Reader hat die OS-Sperre keine Entsprechung; es gilt die dokumentierte SOLL-Abweichung nach `web-reader-design.md` §11.2 mit Ersatz nach §6.5 |
| `:1573` (§14.2) | „Reader-Cache und Suchindex liegen in einer verschlüsselten SQLite-Datenbank. Der Datenbankschlüssel wird durch den Plattform-Key-Provider geschützt." | Reader-Vorbehalt: im Web-Reader entfällt SQLCipher; der Index ist ein invertierter Rust-Index, als Ganzes mit ChaCha20-Poly1305 verschlüsselt in OPFS (`web-reader-design.md` §8.1). Der native Reader-Key-Provider entfällt (§11.3) |
| `:1916` (§18.3) | nennt Reader-Cache und Suchindex unter SQLCipher | Denselben Vorbehalt setzen |

- [ ] **Step 6: Die zwei kollidierenden Global-Constraint-Zeilen des Stage-1-Plans korrigieren**

`stage-1-trust-core-format.md:23` — der Reader gehört nicht mehr in die Desktop-Zielplattformliste:

> Writer, Administration und CLI target supported Windows 11 `x86_64`, current/previous macOS on `arm64` and supported Intel `x86_64`, and Ubuntu 24.04 LTS `x86_64`; server target is Linux OCI `amd64`. Der **Reader läuft im Browser** als installierbare PWA (`web-reader-design.md` §3); seine Support-Achsen sind Engine, Version und Plattform (§11.4). Release proof is deferred to Stage 7 but Stage 1 code must remain portable and must compile for `wasm32-unknown-unknown`.

`:24` — die Ant-Design-Kette gilt nur noch für Desktop:

> Die **Desktop-UI für Writer und Administration** uses Ant Design 6 with German `ConfigProvider`, … (Rest unverändert). Der Web-Reader ist von dieser Kette nicht erfasst; seine UI-Grundlage wird in der Stage-4-Überarbeitung festgelegt.

- [ ] **Step 7: Programmplan nachziehen**

In `2026-08-13-einsatzarchiv-v0-1.md` eine Zeile unter den Programm-Constraints ergänzen, die den Web-Reader-Spec als Normativquelle nennt und die Rollenaufteilung Desktop/Browser festhält.

- [ ] **Step 8: GREEN prüfen**

Run:

```bash
rtk proxy cargo test --locked -p xtask --test spec_completeness web_reader_stage_one_scope_is_closed_across_normative_sources -- --exact --nocapture
rtk cargo test --locked -p xtask --test spec_completeness
```

Erwartet: `1 passed` beim fokussierten Lauf, danach die volle Suite grün. `verify_quick_block_in_stage_one_plan_matches_the_gate` bleibt planmäßig rot bis Task 4.

- [ ] **Step 9: Kein Commit**

Ledger: `Task 2: complete — Normativquellen angeglichen, Spec-Selbstwiderspruch aufgelöst.`

---

### Task 3: Toolchain-Ziel, getrandom-Feature, Lockfile und ADR

**Files:**
- Modify: `rust-toolchain.toml`
- Modify: `Cargo.toml:26`
- Modify: `Cargo.lock`
- Modify: `docs/adr/0001-toolchain-and-cryptography-dependencies.md`

**Interfaces:**
- Consumes: nichts aus Task 2.
- Produces: `rust_toolchain_declares_the_wasm32_target` und `workspace_getrandom_enables_the_wasm_js_feature` werden grün; das Ziel übersetzt.

**Warum Workspace-Scope und nicht `[target.'cfg(…)'.dependencies]` in `crates/ea-crypto/Cargo.toml`:** `wasm-bindgen` und `js-sys` sind in `getrandom 0.4.3` upstream bereits auf `cfg(all(target_family = "wasm", …))` gated, das Feature ist auf dem Host ein No-op. Eine target-Tabelle würde zusätzlich die Scope-Prüfung in `tools/xtask/tests/workspace.rs:74` still umgehen, die nur über `dependencies`, `dev-dependencies` und `build-dependencies` iteriert.

- [ ] **Step 1: RED für das Ziel protokollieren**

Run:

```bash
rtk proxy cargo check --target wasm32-unknown-unknown --locked -p ea-types -p ea-cbor -p ea-crypto -p ea-format -p ea-schema -p ea-time -p ea-trust
```

Erwartet: FAIL mit `getrandom`-`compile_error`: „The wasm32/64-unknown-unknown are not supported by default". Protokolliere die Ausgabe.

- [ ] **Step 2: Toolchain-Ziel deklarieren**

`rust-toolchain.toml`:

```toml
[toolchain]
channel = "1.95.0"
profile = "minimal"
components = ["clippy", "rustfmt"]
targets = ["wasm32-unknown-unknown"]
```

- [ ] **Step 3: getrandom-Feature setzen**

`Cargo.toml:26`:

```toml
getrandom = { version = "=0.4.3", features = ["wasm_js"] }
```

- [ ] **Step 4: Lockfile-Bootstrap — die einzige dokumentierte Ausnahme von `--locked`**

Stage-1-Plan `:133` erlaubt die Bootstrap-Auflösung ausdrücklich als Ausnahme. Genau ein Lauf **ohne** `--locked`:

```bash
rtk cargo check --target wasm32-unknown-unknown -p ea-types -p ea-cbor -p ea-crypto -p ea-format -p ea-schema -p ea-time -p ea-trust
rtk git diff Cargo.lock
```

Erwartet: `Finished`, und ein Lock-Delta von **exakt 2 Zeilen** (`js-sys` und `wasm-bindgen` als Dependency-Einträge von `getrandom`), **keine neuen Package-Stanzas** — beide Pakete sind bereits im Lock. Jeder größere Delta ist ein Abbruchgrund und muss untersucht werden, bevor weitergearbeitet wird.

- [ ] **Step 5: Denselben Lauf mit `--locked` wiederholen**

```bash
rtk cargo check --target wasm32-unknown-unknown --locked -p ea-types -p ea-cbor -p ea-crypto -p ea-format -p ea-schema -p ea-time -p ea-trust
```

Erwartet: `Finished`. Ab hier gilt die `--locked`-Disziplin wieder ausnahmslos.

- [ ] **Step 6: ADR 0001 um die fehlende getrandom-Zeile ergänzen**

`getrandom` ist eine direkte Workspace-Dependency mit produktivem Aufruf (`crates/ea-crypto/src/hpke.rs:32`), hat aber heute keine eigene Zeile in ADR 0001 — es erscheint nur als Feature-Name fremder Crates (`:55`, `:56`). Das ist bereits jetzt eine Lücke gegen Stage-1-Plan `:133`, das die Dokumentation der aktivierten Features je Krypto-Dependency fordert, und wird mit dem Feature zwingend. Zeile im Format der bestehenden Tabelle ergänzen: Upstream, Maintained-Status, exakte Version `=0.4.3`, aktivierte Features `wasm_js`, Begründung („Backend-Auswahl für `wasm32-unknown-unknown`; auf dem Host ein No-op, weil `wasm-bindgen`/`js-sys` upstream target-gated sind. `--cfg getrandom_backend` ist ein `getrandom`-0.3-Mechanismus und für 0.4.3 nicht erforderlich.").

- [ ] **Step 7: GREEN prüfen**

```bash
rtk proxy cargo test --locked -p xtask --test workspace rust_toolchain_declares_the_wasm32_target -- --exact --nocapture
rtk proxy cargo test --locked -p xtask --test workspace workspace_getrandom_enables_the_wasm_js_feature -- --exact --nocapture
rtk cargo test --locked -p xtask --test workspace
rtk cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

Erwartet: je `1 passed`, Suite grün, Clippy ohne Warnung.

- [ ] **Step 8: Kein Commit**

Ledger: `Task 3: complete — Ziel deklariert, Feature gesetzt, Lock-Delta <n> Zeilen, ADR ergänzt.`

---

### Task 4: wasm32 in `verify_quick_commands` einhängen und repinnen

**Files:**
- Modify: `tools/xtask/src/main.rs:25-46` und `:1269-1293`
- Modify: `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md:143-154` und `:1708-1716`

**Interfaces:**
- Consumes: das übersetzbare Ziel aus Task 3.
- Produces: das dauerhaft laufende Gate; `verify_quick_block_in_stage_one_plan_matches_the_gate` wird grün.

**Warum hier und nirgends sonst:** Es existiert keine CI (kein `.github/` im Repo). `verify_quick_commands()` ist damit der einzige immer laufende Pfad; ein eigener Subcommand außerhalb von `verify:quick` würde nie ausgeführt und Spec §10 (`:404`, „verbindliches Ziel im Verifikations-Gate") nicht erfüllen. Das Ziel wird **nicht** an `test-fuzz` gehängt: die gepinnte Nightly `nightly-2026-08-13` hat `wasm32-unknown-unknown` nicht (verifiziert).

**Warum Positivliste:** `--workspace` scheitert zwingend an `tools/xtask` (zieht `jsonschema`, `cddl` und `std::process::Command`), `--all-targets` zöge Dev-Dependencies und Integrationstests in den wasm-Graph.

- [ ] **Step 1: Die erwartete Liste im Pin-Test ergänzen (RED zuerst)**

In `tools/xtask/src/main.rs`, `mod tests`, den Test `verify_quick_uses_the_required_locked_commands` (`:1269`) um einen vierten erwarteten Eintrag erweitern:

```rust
                (
                    "cargo",
                    vec![
                        "check",
                        "--target",
                        "wasm32-unknown-unknown",
                        "--locked",
                        "-p",
                        "ea-types",
                        "-p",
                        "ea-cbor",
                        "-p",
                        "ea-crypto",
                        "-p",
                        "ea-format",
                        "-p",
                        "ea-schema",
                        "-p",
                        "ea-time",
                        "-p",
                        "ea-trust",
                    ],
                ),
```

- [ ] **Step 2: RED protokollieren — mit dem korrekten Testpfad**

Der Test ist ein **Unit-Test im Binary-Crate**, kein Integrationstest. Sein libtest-Pfad lautet `tests::verify_quick_uses_the_required_locked_commands`. Mit `--exact` und dem bloßen Namen matcht der Filter null Tests und liefert Exit 0 — ein vakuum-wahrer Nichtnachweis.

Run:

```bash
rtk proxy cargo test --locked -p xtask --bin xtask tests::verify_quick_uses_the_required_locked_commands -- --exact --nocapture
```

Erwartet: Exit 101, `1 failed`, mit einem `assert_eq!`-Diff, der den fehlenden vierten Eintrag zeigt. Zeigt die Ausgabe `0 passed; N filtered out`, ist der Filter defekt und der Lauf zählt nicht. `--test-threads` gehört, falls überhaupt, hinter `--`; hier ist es unnötig, der Test ist zustandslos.

- [ ] **Step 3: Die Produktionsfunktion ergänzen**

In `verify_quick_commands()` (`:25-46`) denselben vierten Eintrag anhängen, und unmittelbar darüber die Reichweitenaussage als Kommentar ablegen — sie muss an einem dauerhaften Ort stehen, weil das Kommando dauerhaft sichtbar bleibt und sonst als Laufzeitnachweis missverstanden wird (Spec §10 `:397-402` warnt genau davor):

```rust
        // Belegt ausschliesslich UEBERSETZBARKEIT fuer wasm32-unknown-unknown, nicht
        // Lauffaehigkeit. Der Laufzeitnachweis nach web-reader-design.md §14.1
        // (wasm-bindgen, getrandom/wasm_js in einer JS-Umgebung, HPKE-Entkapselung,
        // Signaturpruefung gegen einen Testvektor) steht aus.
        // Positivliste, nicht --workspace: xtask ist nicht wasm-tauglich.
        // Jede neue Bibliotheks-Crate MUSS hier ergaenzt werden.
        (
            "cargo",
            vec![
                "check",
                "--target",
                "wasm32-unknown-unknown",
                "--locked",
                "-p",
                "ea-types",
                "-p",
                "ea-cbor",
                "-p",
                "ea-crypto",
                "-p",
                "ea-format",
                "-p",
                "ea-schema",
                "-p",
                "ea-time",
                "-p",
                "ea-trust",
            ],
        ),
```

- [ ] **Step 4: Preflight-Fehlermeldung für ein fehlendes Ziel**

`targets` in `rust-toolchain.toml` wird von rustup vollständig ignoriert, sobald `RUSTUP_TOOLCHAIN` gesetzt ist — genau der Zustand auf dem Entwicklerrechner. Ohne Vorprüfung endet der Nutzer bei `can't find crate for 'core'`. In `run_verify_quick` vor der Schleife:

```rust
    let installed = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output();
    if let Ok(output) = installed {
        let listed = String::from_utf8_lossy(&output.stdout);
        if !listed.contains("wasm32-unknown-unknown") {
            eprintln!(
                "wasm32-unknown-unknown is not installed for the active toolchain. \
                 Run `rustup target add wasm32-unknown-unknown`. \
                 Note: RUSTUP_TOOLCHAIN in the environment overrides rust-toolchain.toml."
            );
            std::process::exit(1);
        }
    }
```

- [ ] **Step 5: Den normativen Plan-Codeblock nachziehen**

`stage-1-trust-core-format.md:143-154` — der Plan-Block verwendet die **kompakte Einzeilenform**, `verify_quick_commands()` dagegen die von rustfmt umgebrochene. Übernimm nicht die rustfmt-Form: der Korrelationstest aus Task 1 Step 2 prüft die kompakte Schreibweise. Genau diese Zeile als vierten Eintrag in den Plan-Block einfügen:

```rust
    ("cargo", vec!["check", "--target", "wasm32-unknown-unknown", "--locked", "-p", "ea-types", "-p", "ea-cbor", "-p", "ea-crypto", "-p", "ea-format", "-p", "ea-schema", "-p", "ea-time", "-p", "ea-trust"]),
```

`:1708-1716` — die Stage-1-Gate-Kommandoliste um diese Zeile ergänzen:

```bash
cargo check --target wasm32-unknown-unknown --locked -p ea-types -p ea-cbor -p ea-crypto -p ea-format -p ea-schema -p ea-time -p ea-trust
```

- [ ] **Step 6: GREEN prüfen**

```bash
rtk proxy cargo test --locked -p xtask --bin xtask tests::verify_quick_uses_the_required_locked_commands -- --exact --nocapture
rtk proxy cargo test --locked -p xtask --test spec_completeness verify_quick_block_in_stage_one_plan_matches_the_gate -- --exact --nocapture
rtk cargo test --locked -p xtask
rtk pnpm verify:quick
```

Erwartet: je `1 passed`, `xtask` grün, `verify:quick` grün — jetzt inklusive des wasm32-Checks. Notiere die Wandzeit von `verify:quick`; der erste Lauf baut den kompletten wasm32-Graph neu.

- [ ] **Step 7: Kein Commit**

Ledger: `Task 4: complete — wasm32 als vierter Gate-Eintrag, Pin-Test und Plan-Codeblock angeglichen, verify:quick <Sekunden>.`

---

### Task 5: Den Stage-1-Plan gegen den Freeze absichern

**Files:**
- Modify: `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md` (Task-9-Abschnitt `:1471-1546`, Task-10-Abschnitt `:1548-1636`, Task-11-Abschnitt `:1638-1702`)
- Modify: `tools/xtask/tests/spec_completeness.rs` (anhängen)

**Interfaces:**
- Consumes: Freigabe der Pre-flight-Konflikte 2 und 4.
- Produces: `stage_one_vector_hygiene_reserves_out_of_band_negative_literals`.

Dies sind die Lücken, die nach Task 11 irreversibel werden und die nur Stage 1 schließen kann. Der Plan **trifft** die Entscheidungen nicht — er macht sie blockierend sichtbar.

- [ ] **Step 1: Die Vektor-Hygieneregel in den Task-11-Abschnitt schreiben**

Der Block wird mit HTML-Kommentaren geklammert, damit der Test in Step 4 die Abwesenheitsprüfung ausführen kann, ohne an der Verbotsklausel selbst zu scheitern. In `:1638-1702` einfügen:

```markdown
<!-- vector-hygiene-rule -->
**Vektor-Hygiene, verbindlich.** Negativvektoren, die einen unzulässigen `action_code`
kodieren, MÜSSEN den Wert `200` verwenden. Erzeugt dieser Task zusätzlich einen
Negativvektor für einen unbekannten Trust-Subtype, MUSS er das Literal `xxUnknownxx`
verwenden. Nächstliegende Nachbarwerte des heutigen Bestands — insbesondere der
`action_code` 7 und jeder Name, der später eine echte Trust-Objektfamilie werden
könnte — sind verboten. Grund: ein dauerhaft eingefrorener Negativvektor, der einen
nachbarschaftlichen Wert benutzt, dreht sich bei einer späteren v1.1-Erweiterung von
`abgelehnt` nach `akzeptiert`. Das wäre der einzige echte Bruch des
Permanenzversprechens dieses Tasks — die Byte-Unveränderlichkeit selbst ist davon
nicht betroffen.
<!-- /vector-hygiene-rule -->
```

- [ ] **Step 2: Die drei Blockaden in den Task-11-Abschnitt schreiben**

> **ÜBERHOLT — Stand nach der Entscheidung vom 2026-08-17.** Der Textbaustein unten ist
> die Fassung VOR der menschlichen Entscheidung; alle drei Blockaden sind aufgelöst
> (Konflikt 2 und 4 siehe Step 1, Traceability: die sieben MUSS-Anforderungen des
> Web-Reader-Specs sind als v1.1-Zeilen ins Requirement-Ledger aufgenommen). Die
> EINGESETZTE Fassung steht im Block `web-reader-blockers` von
> `2026-08-13-einsatzarchiv-stage-1-trust-core-format.md` und lautet dort auf
> ENTSCHIEDEN statt auf BLOCKIERT. Der Baustein bleibt als Beleg des Planungsstands
> stehen und ist KEINE Weisung mehr — insbesondere gilt das „DARF … nicht einfrieren"
> beider Familien nicht mehr.

**Invariante:** Jede Prosa, die einen künftigen Trust-Subtype beim Namen nennen MUSS, liegt innerhalb eines markierten Blocks. Der Abwesenheitstest in Step 4 entfernt **alle** markierten Blöcke, bevor er prüft. Ein Kandidatenname außerhalb eines markierten Blocks ist ein Fehler — er könnte in einen eingefrorenen Vektor wandern.

````markdown
<!-- web-reader-blockers -->
**BLOCKIERT — Formentscheidung nach `web-reader-design.md` §7.5.** Dieser Task friert
`organizationAdminAuthorization` mit Positiv- UND Negativvektoren ein, während
`crates/ea-trust/src/admin_authorization.rs:142-149` die Kardinalität 1 samt
`signatures()[0]` und `schemas/archive/v1/trust.cddl:22` `[cose-sign1-v1]` pinnen.
Spec §7.5 verlangt zwei verschiedene Approver plus die Bindung eines
Transport-Public-Key-Fingerprints, für den es kein Feld gibt. Solange nicht entschieden
ist, ob die Kardinalität aufgeweitet oder eine eigene 2-of-N-Familie angelegt wird,
DARF dieser Task keine Vektoren für `organizationAdminAuthorization` einfrieren.

**BLOCKIERT — Zuordnung der Policy-Frist nach `web-reader-design.md` §4.2.** Spec
§4.2 fordert eine in der Policy konfigurierte Aktualisierungsfrist für das Alter des
zuletzt bezogenen Trust-Standes. Weder `max_registry_age_ms` (Ausstellungsschranke,
`design.md:1347`) noch `registry_expiry_behavior` (an die Finalisierung gebunden,
`design.md:1426`) deckt das. Ist eine eigene Frist erforderlich, ist `policy-core-v1`
betroffen (`trust.cddl:127-141`, `crates/ea-format/src/etb.rs:210-229`). Solange das
offen ist, DARF dieser Task keine Positivvektoren für `policy-core-v1` einfrieren.

**BLOCKIERT — Traceability der Web-Reader-Anforderungen.** Dieser Task füllt das
Requirement-Ledger „for every normative paragraph". Der Web-Reader-Spec ist eine
freigegebene Normativquelle mit eigenen MUSS-Anforderungen (§4.1 getrennter Origin,
§4.2 Aktivierung nur gegen gepinnte `webBundleRelease`, §4.3 nicht überspringbarer
Fingerprint-Vergleich, §5.2 universeller Weg immer angeboten, §6.3 zwei
Authenticators, §7.5 Verweigerung bei abweichendem Transport-Fingerprint, §8.2 kein
Klartext in Telemetrie). Zusätzlich sind `design.md:2240` (FR-100) und `:2243`
(FR-103) inhaltlich überholt. Vor dem Einfrieren ist zu entscheiden, ob diese
Anforderungen als v1.1-Zeilen aufgenommen oder ausdrücklich zurückgestellt werden.
Schweigen ist die einzige Variante, die nach dem Einfrieren teuer wird.

**Reichweite des wasm32-Gates.** `docs/traceability/stage-1-gate.md` MUSS ausdrücklich
festhalten: das `wasm32-unknown-unknown`-Kommando in `verify_quick_commands()` belegt
Übersetzbarkeit, nicht Lauffähigkeit. Der Laufzeitnachweis nach
`web-reader-design.md` §14.1 steht aus.
<!-- /web-reader-blockers -->
````

- [ ] **Step 3: Die wasm32-Pflicht in den Task-9-Abschnitt schreiben**

Der Plan-Text von Task 9 (`:1471-1546`) trägt diese Pflicht heute nirgends — sie stünde sonst nur in der Begründung dieses Plans und wäre genau die Art toter Regel, die dieser Plan an anderer Stelle als Ausschlussgrund anführt. Einfügen:

```markdown
**wasm32-Pflicht.** `ea-chain`, `ea-archive` und `ea-verify` MÜSSEN in die Positivliste
des wasm32-Gates in `tools/xtask/src/main.rs` aufgenommen werden, und dieser Task MUSS
`tools/xtask/tests/workspace.rs` um eine Klassifikationszusicherung erweitern: jedes
Mitglied unter `crates/` steht entweder in der wasm32-Positivliste oder in einer
ausdrücklich begründeten Ausnahmeliste; ein neues Mitglied ohne Zuordnung lässt den Test
fehlschlagen. Grund: `web-reader-design.md` §9 macht die Verifikationspipeline zu
geteiltem Rust-Code, der im Browser läuft.
Drei konkrete Fallen: die dateisystemgestützte `ArchiveSource` gehört hinter ein
Nicht-Default-Feature oder außerhalb der Crate; Zeit wird als Parameter übergeben, nicht
über `SystemTime::now()` bezogen; JSON-Schema-Validierung des Reports gehört NICHT in
`ea-verify`, weil `jsonschema` `getrandom 0.3.4` (`Cargo.lock:912`) in den wasm-Graph
zieht — und 0.3.4 benötigt auf `wasm32` zusätzlich das `--cfg getrandom_backend`, das in
diesem Plan bewusst nicht gesetzt wird.
```

- [ ] **Step 4: Den Hygiene-Test schreiben**

An `tools/xtask/tests/spec_completeness.rs` anhängen:

```rust
#[test]
fn stage_one_vector_hygiene_reserves_out_of_band_negative_literals() {
    let stage_one = include_str!(
        "../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md"
    );
    // Jeder Block, der einen kuenftigen Subtype-Namen nennen darf, ist markiert.
    // Die Abwesenheitspruefung entfernt ALLE markierten Blocke, sonst schluege sie
    // an der eigenen Verbotsklausel bzw. an den Blockadetexten fehl.
    fn extract<'a>(text: &'a str, open: &str, close: &str) -> (&'a str, usize, usize) {
        let start = text.find(open).unwrap_or_else(|| panic!("missing {open}"));
        let end = text.find(close).unwrap_or_else(|| panic!("unterminated {open}"));
        assert!(start < end, "markers out of order: {open}");
        (&text[start..end], start, end + close.len())
    }

    let (rule, hygiene_start, hygiene_end) = extract(
        stage_one,
        "<!-- vector-hygiene-rule -->",
        "<!-- /vector-hygiene-rule -->",
    );
    for literal in ["200", "xxUnknownxx"] {
        assert!(rule.contains(literal), "hygiene rule must pin {literal}");
    }

    let (_, blockers_start, blockers_end) = extract(
        stage_one,
        "<!-- web-reader-blockers -->",
        "<!-- /web-reader-blockers -->",
    );

    let mut regions = [
        (hygiene_start, hygiene_end),
        (blockers_start, blockers_end),
    ];
    regions.sort_unstable();
    let mut stripped = String::with_capacity(stage_one.len());
    let mut cursor = 0usize;
    for (start, end) in regions {
        assert!(cursor <= start, "marked regions must not overlap");
        stripped.push_str(&stage_one[cursor..start]);
        cursor = end;
    }
    stripped.push_str(&stage_one[cursor..]);

    for candidate in ["webBundleRelease", "readerKeyEscrow"] {
        assert!(
            !stripped.contains(candidate),
            "{candidate} must only appear inside a marked block"
        );
    }

    for marker in [
        "BLOCKIERT — Formentscheidung nach `web-reader-design.md` §7.5",
        "BLOCKIERT — Zuordnung der Policy-Frist nach `web-reader-design.md` §4.2",
        "BLOCKIERT — Traceability der Web-Reader-Anforderungen",
        "**wasm32-Pflicht.**",
    ] {
        assert!(stage_one.contains(marker), "stage 1 plan is missing: {marker}");
    }
}
```

- [ ] **Step 5: RED und GREEN protokollieren**

Schreibe den Test **vor** den Plan-Änderungen aus Step 1–3, protokolliere Exit 101 mit `1 failed`, führe dann die Plan-Änderungen aus und protokolliere `1 passed`:

```bash
rtk proxy cargo test --locked -p xtask --test spec_completeness stage_one_vector_hygiene_reserves_out_of_band_negative_literals -- --exact --nocapture
rtk cargo test --locked -p xtask --test spec_completeness
```

- [ ] **Step 6: Kein Commit**

Ledger: `Task 5: complete — Vektor-Hygiene, drei Task-11-Blockaden und die Task-9-wasm32-Pflicht verankert.`

---

### Task 6: Merker in den Folgestufen, Branch-Hygiene, Rücknahmeliste

**Files:**
- Modify: `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-2-offline-writer.md`
- Modify: `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-3-blind-sync.md`
- Modify: `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-4-reader.md`
- Modify: `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-5-administration-recovery.md`
- Modify: `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-6-evidence-grade.md`
- Modify: `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-7-release-hardening.md`
- Modify: `docs/superpowers/plans/2026-08-14-einsatzarchiv-task-8-trust-time-normative-correction.md:13-14`
- Modify: `docs/superpowers/plans/2026-08-14-einsatzarchiv-task-8-trust-time-implementation.md:48`
- Modify: `tools/xtask/tests/spec_completeness.rs` (anhängen)

**Interfaces:**
- Consumes: nichts.
- Produces: `later_stage_plans_reference_the_web_reader_spec`.

Heute liefert `grep -rn "web-reader\|wasm32\|PWA\|Browser" docs/superpowers/plans/` null Treffer. Ohne mechanischen Schutz gehen die Deltas aus Spec §12 beim nächsten Planlauf verloren.

- [ ] **Step 1: Je eine Merker-Zeile setzen**

In jeden der sechs Stage-Pläne unter *Global Constraints* eine Zeile mit dem Spec-Pfad und dem betroffenen Abschnitt:

| Plan | Merker |
|---|---|
| Stage 2 | `web-reader-design.md` §12 (`:427-428`): Task 8 schaltet nur noch Writer und Administration frei; neuer Task für den Export eines Archiv-Bündels als Einzeldatei nach §5.2 (`:136-138`). |
| Stage 3 | §12 (`:429-431`): neue Fläche für Bundle-Auslieferung und -Pinning, Ablage der Wrapped-Blobs, CORS und RFC-9421-Request-Signatur aus dem Browser; zusätzlich §6.4.1 (`:215-221`), WebAuthn-Credentials am Sync-Server mit pseudonymer `subjectId` als `userHandle`. Die acht bestehenden Tasks und die API-Flächen aus Task 6 bleiben. |
| Stage 4 | §12 (`:432-435`): Tasks 1, 2, 4 und 7 werden neu geschrieben, Task 3 behält den Rust-Kern, Task 5 bleibt, Task 6 wird angepasst, Task 8 wird um Browser-Matrix und Datei-Modus erweitert. **Achtung:** `:9` und `:88` dieses Plans schreiben heute noch SQLCipher, Tauri 2 und den nativen Key-Provider fest — beides ist durch §8.1 und §11.3 widerlegt. |
| Stage 5 | §12 (`:436-438`): die 14 bestehenden Tasks bleiben; zwei neue Tasks für Escrow-Erzeugung beim Enrollment und die Zwei-Approver-Öffnungszeremonie mit Re-Encryption. Blockiert auf Pre-flight-Konflikte 2 und 3. |
| Stage 6 | §12 (`:439`): unverändert; Merker nur zur Nachweisbarkeit, dass der Spec geprüft wurde. |
| Stage 7 | §12 (`:440-443`) und §11.4 (`:416-419`): Support-Matrix bekommt für den Reader eine Browser-Achse aus Engine, Version und Plattform; Architektur, Installerformat und Key-Provider entfallen für den Reader. Reader-Installer und native Key-Provider-Smokes entfallen. Neu: PWA-Installation, Service-Worker-Update unter Pinning, und ein Gate, das die Ablehnung eines nicht Root-signierten Bundles nachweist. Browser-Mindestversionen nach §14.3 pinnen. |

- [ ] **Step 2: Die Stage-4-Blockade setzen**

Zusätzlich zur Merker-Zeile in `stage-4-reader.md` eine Blockade — analog zu den Task-11-Blockaden aus Task 5:

```markdown
**BLOCKIERT — Laufzeitnachweis nach `web-reader-design.md` §14.1 (`:460-464`).** Die
Überarbeitung dieses Plans darf erst beginnen, wenn ein ausführbarer Spike vorliegt:
`wasm-bindgen`-Schicht, `getrandom` mit `wasm_js` in einer echten JS-Umgebung, eine
HPKE-Entkapselung und eine Signaturprüfung gegen einen bestehenden Testvektor.
Scheitert er, fällt die Browser-Entscheidung aus §2 Punkt 1 in sich zusammen.
Rücknahmeliste für diesen Fall: `targets` in `rust-toolchain.toml`; das
`wasm_js`-Feature in `Cargo.toml` samt Lock-Delta und ADR-Zeile; der vierte Eintrag in
`verify_quick_commands()` samt Pin-Test, Plan-Codeblock und Gate-Kommandoliste; die
Merker-Zeilen in diesen sechs Plänen; die Normativkorrekturen aus Task 2 dieses Plans.
```

- [ ] **Step 3: Branch- und Worktree-Angaben historisch korrekt behandeln**

Die beiden Task-8-Pläne sind **abgeschlossen und committet** (`f50ec03`, `9f6073e`). Ihre Global Constraints inhaltlich auf `main` umzuschreiben würde die Ausführungsaufzeichnung fälschen. Stattdessen je eine datierte Fußnote unmittelbar unter der betroffenen Zeile:

> *Historisch: ausgeführt in `.worktrees/einsatzarchiv-v0-1` auf `codex/einsatzarchiv-v0-1`. Seit 2026-08-16 arbeitet das Repository ausschließlich auf `main`; ein Worktree und der Branch existieren nicht mehr.*

Der veraltete RTK-Pfad `/Users/rubeen/.codex/RTK.md` (`normative-correction.md:14`, `implementation.md:48`) ist dagegen eine ausführbare Anweisung und keine Tatsachenbehauptung — er wird direkt auf `/Users/rubeen/.claude/RTK.md` korrigiert.

- [ ] **Step 4: Den Merker-Test schreiben**

An `tools/xtask/tests/spec_completeness.rs` anhängen. Der Test sperrt **nicht** global das Literal `.worktrees/` — das würde jeden künftigen, legitim per Worktree ausgeführten Plan am Gate scheitern lassen.

```rust
#[test]
fn later_stage_plans_reference_the_web_reader_spec() {
    for (name, plan) in [
        ("stage-2", include_str!("../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-2-offline-writer.md")),
        ("stage-3", include_str!("../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-3-blind-sync.md")),
        ("stage-4", include_str!("../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-4-reader.md")),
        ("stage-5", include_str!("../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-5-administration-recovery.md")),
        ("stage-6", include_str!("../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-6-evidence-grade.md")),
        ("stage-7", include_str!("../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-7-release-hardening.md")),
    ] {
        assert!(
            plan.contains("2026-08-15-einsatzarchiv-web-reader-design.md"),
            "{name} plan must carry a marker for the web reader spec"
        );
    }

    let stage_four = include_str!(
        "../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-4-reader.md"
    );
    assert!(
        stage_four.contains("BLOCKIERT — Laufzeitnachweis nach `web-reader-design.md` §14.1"),
        "stage 4 must be blocked on the runtime spike"
    );

    // Ausfuehrbare Anweisungen zeigen auf existierende Pfade. Historische
    // Tatsachenbehauptungen ueber Worktrees bleiben unangetastet.
    for (name, plan) in [
        ("task-8-normative-correction", include_str!("../../../docs/superpowers/plans/2026-08-14-einsatzarchiv-task-8-trust-time-normative-correction.md")),
        ("task-8-implementation", include_str!("../../../docs/superpowers/plans/2026-08-14-einsatzarchiv-task-8-trust-time-implementation.md")),
    ] {
        assert!(
            !plan.contains("/Users/rubeen/.codex/"),
            "{name} still points at the stale RTK path"
        );
        assert!(
            plan.contains("Historisch:"),
            "{name} must mark its worktree line as a historical record"
        );
    }
}
```

- [ ] **Step 5: RED und GREEN protokollieren**

```bash
rtk proxy cargo test --locked -p xtask --test spec_completeness later_stage_plans_reference_the_web_reader_spec -- --exact --nocapture
```

Erwartet: zuerst Exit 101 mit `1 failed`, nach den Änderungen `1 passed`.

- [ ] **Step 6: Kein Commit**

Ledger: `Task 6: complete — sechs Merker, Stage-4-Blockade mit Rücknahmeliste, Branch-Fußnoten, RTK-Pfad korrigiert.`

---

### Task 7: Scope-Audit, vollständige Gates, unabhängige Reviews, EIN atomarer Commit

**Files:**
- Create: `.superpowers/sdd/2026-08-13-einsatzarchiv-stage-1-trust-core-format/web-reader-stage-1-prerequisites-report.md` (ungetrackt, Evidenz)
- Modify: `.superpowers/sdd/2026-08-13-einsatzarchiv-stage-1-trust-core-format/progress.md` (Roll-up-Zeile oberhalb von `Task 9: pending`)

**Interfaces:**
- Consumes: alles aus den Tasks 1–6.
- Produces: genau einen Commit auf `main`.

- [ ] **Step 1: Scope-Audit gegen die geschlossene Verbotsliste**

Prüfe den vollständigen Diff gegen jede Zeile der Verbotsliste aus den Global Constraints dieses Plans:

```bash
rtk git diff --stat
rtk git diff -- crates schemas
```

Erwartet: `crates/` und `schemas/` sind **unverändert**. Jeder Treffer dort ist ein Scope-Bruch und muss zurückgenommen werden.

- [ ] **Step 2: Toolchain verifizieren**

```bash
rustup show active-toolchain
```

Erwartet: `1.95.0-…` ohne `overridden by environment variable`. Andernfalls gilt der folgende Gate-Satz nicht als Nachweis.

- [ ] **Step 3: Vollständigen Gate-Satz fahren**

```bash
rtk cargo test --locked -p xtask --bin xtask --test spec_completeness --test schema_validation --test workspace
rtk cargo run --locked -p xtask -- validate-schemas
rtk cargo check --target wasm32-unknown-unknown --locked -p ea-types -p ea-cbor -p ea-crypto -p ea-format -p ea-schema -p ea-time -p ea-trust
rtk pnpm test:golden
rtk cargo fmt --all -- --check
rtk cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
rtk cargo test --workspace --all-targets --locked
rtk pnpm verify:quick
rtk git diff --check
rtk git diff --cached --check
```

Das erste Kommando MUSS `--bin xtask` enthalten — `tests::verify_quick_uses_the_required_locked_commands` liegt im Binary-Crate und wäre sonst nur indirekt über den Workspace-Lauf abgedeckt.

**Bewusste Abweichung vom Phase-B-Mustersatz:** `pnpm test:property` und `pnpm test:fuzz --smoke-seconds 60` laufen hier **nicht**. Begründung: dieser Plan ändert keinen Codec, keinen Parser und keine Wirestruktur; `xtask` ist kein ausgeliefertes Artefakt, und `cargo test --workspace --all-targets --locked` deckt es vollständig ab. Zusätzlich hat die gepinnte Fuzz-Nightly `nightly-2026-08-13` das `wasm32`-Ziel nicht — das neue Kommando darf niemals an `test-fuzz` hängen. Die korrekte Fuzz-Syntax lautet im Übrigen `rtk pnpm test:fuzz --smoke-seconds 60`, **ohne** freistehendes `--` (Korrektur aus `cfd5a65`).

- [ ] **Step 4: Die sechs benannten Tests im vollen Lauf bestätigen**

Alle sechs müssen grün sein: `web_reader_stage_one_scope_is_closed_across_normative_sources`, `verify_quick_block_in_stage_one_plan_matches_the_gate`, `rust_toolchain_declares_the_wasm32_target`, `workspace_getrandom_enables_the_wasm_js_feature`, `tests::verify_quick_uses_the_required_locked_commands`, `stage_one_vector_hygiene_reserves_out_of_band_negative_literals`, `later_stage_plans_reference_the_web_reader_spec` — das sind sieben; jeder mit `1 passed` im fokussierten Protokoll.

- [ ] **Step 5: Drei unabhängige Reviews**

Specification-/API-Review, Quality-/Security-Review und ein strukturierter Security-Diff-Scan mit protokollierter Scan-ID — nach dem Muster aus `.superpowers/sdd/2026-08-14-einsatzarchiv-task-8-trust-time-normative-correction/progress.md`. Bestätigte Findings werden test-first behoben; danach werden **alle** betroffenen Gates und Reviews wiederholt.

- [ ] **Step 6: Genau einen Commit erzeugen**

Explizite Dateiliste, kein `git add -A`. Der Plan selbst wird mitgelistet.

```bash
rtk git add \
  rust-toolchain.toml \
  Cargo.toml \
  Cargo.lock \
  tools/xtask/src/main.rs \
  tools/xtask/tests/spec_completeness.rs \
  tools/xtask/tests/workspace.rs \
  docs/adr/0001-toolchain-and-cryptography-dependencies.md \
  docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md \
  docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md \
  docs/superpowers/plans/2026-08-16-einsatzarchiv-web-reader-stage-1-prerequisites.md \
  docs/superpowers/plans/2026-08-13-einsatzarchiv-v0-1.md \
  docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md \
  docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-2-offline-writer.md \
  docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-3-blind-sync.md \
  docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-4-reader.md \
  docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-5-administration-recovery.md \
  docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-6-evidence-grade.md \
  docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-7-release-hardening.md \
  docs/superpowers/plans/2026-08-14-einsatzarchiv-task-8-trust-time-normative-correction.md \
  docs/superpowers/plans/2026-08-14-einsatzarchiv-task-8-trust-time-implementation.md
rtk git diff --cached --check
rtk git commit -m "build(wasm): pin wasm32 verification target and align stage-1 web-reader scope"
```

- [ ] **Step 7: Abschlussbericht und Ledger**

Bericht nach der Sechs-Abschnitts-Gliederung des Task-8-Musters (Auftrag, RED-Protokolle, Änderungen je Datei, Gate-Ergebnisse, Review-Ergebnisse mit Scan-ID, verbleibende Blockaden) als ungetrackte Evidenz. Roll-up-Zeile in das Stage-1-Ledger oberhalb von `Task 9: pending` schreiben, mit Commit-SHA und den vier weitergetragenen Pre-flight-Konflikten.

---

## Self-Review

**Spec-Abdeckung mit Stage-1-Bezug.** §1 Selbstwiderspruch → Task 2 Step 1. §3 Rollenzuordnung und Browser-Zone → Task 2 Steps 3, 5. §5.4 Status *nicht server-bestätigt* → Task 2 Step 4. §8.1 SQLCipher entfällt → Task 2 Step 5 (`:1573`, `:1916`). §9 geteilte Rust-Pipeline → Task 5 Step 3 (wasm32-Pflicht für `ea-verify`). §10 Machbarkeit und Gate-Ziel → Tasks 3 und 4, Korrektur der cfg-Forderung in Task 2 Step 2. §11.1–11.4 → Task 2 Steps 3, 5. §11.5/11.6 neue Familien → bewusst nicht gebaut, als v1.1 geführt (Task 2 Step 1), gegen den Freeze abgesichert (Task 5). §12 Stufen-Deltas → Task 6. §14.1 Laufzeitnachweis → Task 6 Step 2 als Stage-4-Blockade mit Rücknahmeliste. §14.3 Browser-Mindestversionen → Stage-7-Merker.

**Bewusst nicht in diesem Plan.** Codec, CDDL und Signaturprofil für `webBundleRelease` und das Reader-Key-Escrow (Stage 3 bzw. 5). Die Zwei-Approver-Öffnungszeremonie (Stage 5). Eine reservierte, nicht ausstellbare `TrustSubtypeV1`-Variante — sie reproduziert das tote-Regel-Muster von `trust-subtype-v1` (`schemas/archive/v1/trust.cddl:1-4`), das definiert ist und nirgends referenziert wird, und erforderte den Unknown-Fallback, den `etb.rs:45` bewusst nicht hat. Der Quarantäne-/`formatErrors`-Zustand im Report-Schema — realer Defekt, aber unabhängig vom Web-Reader-Spec und Sache von Task 9 (im Ledger als Pre-flight-defect vermerkt). Die Erweiterung von `tools/xtask/tests/workspace.rs:74` um target-cfg-Tabellen — entfällt, weil dieser Plan keine target-Tabelle einführt; das Loch bleibt, wird aber nicht vergrößert. FR-Zeilen und Traceability — Task 11, hier nur als Blockade verankert.

**Bekannte offene Flanke.** `deny.toml` existiert (338 B), wird aber von keinem Gate aufgerufen (kein Treffer in `package.json` und `tools/xtask/src/main.rs`). Die neuen `wasm-bindgen`- und `js-sys`-Kanten im Lock durchlaufen daher keine `licenses`/`bans`-Prüfung. Kein Blocker für diesen Plan.

**Typkonsistenz.** Die vierte Gate-Zeile erscheint an vier Orten und muss wortgleich sein: `verify_quick_commands()` (Task 4 Step 3), der Pin-Test (Task 4 Step 1), der normative Plan-Codeblock `:143-154` (Task 4 Step 5) und der Korrelationstest (Task 1 Step 2). Die Testnamen sind über die Tasks 1, 4, 5, 6 und 7 hinweg identisch geführt.
