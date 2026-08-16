# Einsatzarchiv Task 9 Phase A: Report-Repräsentation und Gate-Reihenfolge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Alle normativen und Schema-Fragen schließen, die `crates/ea-verify/src/report.rs` und `schemas/reports/v1/verification-report.schema.json` gemeinsam betreffen — bevor `ea-chain`, `ea-archive` und `ea-verify` entstehen und bevor Task 10 byteidentische CLI-Baselines einfriert.

**Architecture:** Reine Normativ- und Schemakorrektur nach dem Muster der Task-8-Phase-A (`2026-08-14-einsatzarchiv-task-8-trust-time-normative-correction.md`). Es entsteht **keine neue Crate und kein Produktionscode**; geändert werden das Report-JSON-Schema, das normative Design, der Stage-1-Plan und die ausführbaren Vollständigkeitszusicherungen in `xtask`. Die drei Crates folgen in Phase B.

**Tech Stack:** JSON Schema 2020-12 mit den repo-eigenen `x-ea-sort-key`/`x-ea-unique-key`-Konventionen, `xtask validate-schemas`, `spec_completeness`-Tests als Prosa-gegen-Schema-Zusicherung.

**Spec:** `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md` §11.4, §14.1, §17.4 und `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §5.4, §9.

---

## Warum Phase A getrennt läuft

Drei Dinge treffen sich in derselben Datei und derselben Frist:

1. Der Stage-1-Plan lässt Task 9 „malformed/duplicate/conflicting objects" quarantänisieren (`:1533`), aber `verification-report.schema.json` hat kein `formatErrors` und kein Quarantäne-Array, `objectResult.result` ist ein geschlossenes Enum `["valid","authorizedDestroyed"]`, und das gesamte Schema ist `additionalProperties: false`. Der Zustand ist heute nicht ausdrückbar.
2. Commit `219cc63` hat `nicht server-bestätigt` in `design.md` §17.4 aufgenommen, weil Web-Reader-Spec §5.4 es fordert. Stage-1 Global Constraint `:27` macht die Statussprache zur Stage-1-Invariante. Ob der **CLI-Report** diese Dimension trägt, ist unentschieden.
3. Task 10 friert den Report byteidentisch ein (`report_is_byte_identical_without_runtime_metadata`, Stage-1-Plan `:1580`). Danach ist jede Ergänzung eine Formatänderung.

Dazu kommen zwei Widersprüche, die ein Implementierer nicht selbst entscheiden darf und die den Zuschnitt der drei Crates bestimmen — Gate-Event-Vokabular und `verify_archive`-Signatur.

## Getroffene Entscheidungen

Beide unter Automode am 2026-08-16 entschieden, mit benannter Begründung; sie sind vom Menschen zu bestätigen.

**Entscheidung A — Der Report bekommt einen ausdrückbaren Quarantänezustand.**
Begründung: Der Stage-1-Plan erzeugt Quarantäne, und `design.md:812` ist für die Trust-Ebene eindeutig („Unbekannte kritische Erweiterungen oder Suites werden abgelehnt"). Ein Zustand, den der Report nicht ausdrücken kann, wird entweder verschwiegen — das wäre fail-open — oder in einen falschen Zustand gefaltet. Beides ist schlechter als ein eigenes Feld. **Fail-closed bleibt unangetastet:** ein quarantänisiertes Objekt DARF NIEMALS zu einem Archivergebnis führen, das den Bestand als vollständig verifiziert darstellt.

**Entscheidung B — Der Report trägt die Server-Bestätigung als eigene, orthogonale Dimension.**
Begründung: `design.md` §17.4 führt sie in der Fassung aus `219cc63` ausdrücklich als eigene Dimension, die nicht mit `Lücke` oder `ungültig` zusammengefasst werden darf. Die Recovery-CLI arbeitet im selben Datei-Modus wie der Web-Reader und trifft dieselbe Lage: Objekte ohne Receipt. Sie NICHT abzubilden hieße, dass CLI und Reader denselben Bestand unterschiedlich beschreiben. Umgesetzt wird sie **nicht** als dritter Wert im `result`-Enum — das würde genau die Vermischung erzeugen, die §17.4 verbietet — sondern als eigenes Pflichtfeld an `objectResult`.

---

## Global Constraints

Die Global Constraints des Stage-1-Plans (`2026-08-13-einsatzarchiv-stage-1-trust-core-format.md:11-30`) gelten vollständig. Zusätzlich:

- **Arbeitsumgebung:** ausschließlich `main` im Hauptverzeichnis. Lies und befolge `/Users/rubeen/.claude/RTK.md`; führe Repository-Kommandos durch `rtk` aus.
- **Toolchain-Nachweis:** Vor jedem als Nachweis geltenden Lauf MUSS die aktive Toolchain `1.95.0` sein. `verify-quick` warnt seit `22bce49` selbst, wenn sie es nicht ist; die Warnung macht einen Lauf ungültig, nicht bloß auffällig. `env -u RUSTUP_TOOLCHAIN` ist die Minimallösung, solange `RUSTUP_TOOLCHAIN` in der Shell steht.
- **RED-Beweisregel:** Ein RED zählt nur bei `1 failed` bzw. dem exakt erwarteten Compile-Fehler. `0 passed; N filtered out` ist ein defekter Filter, kein RED. Unit-Tests im Binary-Crate brauchen den Pfad `--bin xtask tests::<name>`. Protokolle mit `rtk proxy cargo test …` oder rohem `cargo` erzeugen, weil `rtk` die libtest-Ausgabe ersetzt.
- **Geltungsbereich, geschlossene Verbotsliste.** Dieser Plan DARF NICHT: eine Crate anlegen; `crates/` überhaupt ändern; `schemas/archive/v1/*.cddl` ändern; eine Trust-Objektfamilie einführen; die Signatur-Kardinalität von `organizationAdminAuthorization` ändern; `jsonschema` zu einer Bibliotheks-Crate hinzufügen; die wasm32-Positivliste ändern (dort ändert sich erst in Phase B etwas).
- **Ein Commit.** Kein Zwischenstand ist gültig: zwischen Schema- und Design-Änderung widersprechen sich die Normativquellen.

---

## File Structure

| Datei | Verantwortung |
|---|---|
| `schemas/reports/v1/verification-report.schema.json` | Quarantäne-/Formatfehler-Darstellung und die Server-Bestätigungsdimension |
| `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md` | §14.1 Event-Vokabular normativ benennen; §17.4 auf den Report anwenden |
| `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md` | Task 9 präzisieren: Signatur, Event-Namen, Adapterverhältnis, Report-Felder; Task 10 auf die neue Reportform verweisen |
| `tools/xtask/tests/spec_completeness.rs` | Ausführbare Zusicherung, dass Schema und Design dasselbe sagen |

---

### Task 1: RED — Report-Schema und Gate-Vokabular sind unvollständig

**Files:**
- Modify: `tools/xtask/tests/spec_completeness.rs` (anhängen)

**Interfaces:**
- Consumes: nichts.
- Produces: `verification_report_expresses_quarantine_and_server_confirmation`, `gate_order_event_vocabulary_is_pinned_across_design_and_plan`.

- [ ] **Step 1: Den Schema-Test schreiben**

```rust
#[test]
fn verification_report_expresses_quarantine_and_server_confirmation() {
    let raw = include_str!("../../../schemas/reports/v1/verification-report.schema.json");
    let schema: serde_json::Value = serde_json::from_str(raw).unwrap();
    jsonschema::meta::validate(&schema).unwrap();

    let required = schema["required"].as_array().unwrap();
    let required: Vec<&str> = required.iter().map(|value| value.as_str().unwrap()).collect();
    for field in ["formatErrors", "quarantinedObjects"] {
        assert!(
            required.contains(&field),
            "verification report must require {field}"
        );
    }

    // Server-Bestaetigung ist eine eigene Dimension, KEIN dritter result-Wert.
    let object_result = &schema["$defs"]["objectResult"];
    let result_values = object_result["properties"]["result"]["enum"]
        .as_array()
        .unwrap();
    let result_values: Vec<&str> = result_values
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(
        result_values,
        ["valid", "authorizedDestroyed"],
        "server confirmation must not be folded into the verification result"
    );
    let confirmation = object_result["properties"]["serverConfirmation"]["enum"]
        .as_array()
        .expect("objectResult must carry the server confirmation dimension");
    let confirmation: Vec<&str> = confirmation
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(confirmation, ["serverConfirmed", "notServerConfirmed"]);
    assert!(
        object_result["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value.as_str() == Some("serverConfirmation")),
        "serverConfirmation must be mandatory so it cannot be silently omitted"
    );

    // Quarantaene ist fail-closed: das Schema erzwingt einen Grund je Objekt.
    let quarantined = &schema["$defs"]["quarantinedObject"];
    for field in ["objectHash", "reason"] {
        assert!(
            quarantined["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value.as_str() == Some(field)),
            "quarantinedObject must require {field}"
        );
    }
}
```

- [ ] **Step 2: Den Vokabular-Test schreiben**

Design §14.1 hat **neun** nummerierte Schritte; der Stage-1-Plan nennt in seinem RED nur den Vierer-Präfix `["format", "trust", "registry", "manifest-signature"]`. Web-Reader-Spec §9 übernimmt die Reihenfolge unverändert für den Browser. Die vollständige Abbildung MUSS gepinnt sein, sonst erfindet der Implementierer die Namen 5 bis 9.

```rust
#[test]
fn gate_order_event_vocabulary_is_pinned_across_design_and_plan() {
    const GATE_EVENTS: [&str; 9] = [
        "format",
        "trust",
        "registry",
        "manifest-signature",
        "chain-position",
        "grant-plan",
        "receipt",
        "evidence",
        "recipient-grant",
    ];
    let design =
        include_str!("../../../docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md");
    let stage_one = include_str!(
        "../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md"
    );
    for event in GATE_EVENTS {
        assert!(
            design.contains(&format!("`{event}`")),
            "design §14.1 must name the gate event {event}"
        );
        assert!(
            stage_one.contains(&format!("\"{event}\"")),
            "stage 1 task 9 must pin the gate event {event}"
        );
    }
    // Die Entkapselung liegt hinter dem letzten Gate und ist selbst kein Gate.
    assert!(
        design.contains("`hpke-open`"),
        "design must name the decapsulation step that follows the nine gates"
    );
}
```

- [ ] **Step 3: RED protokollieren**

Run:

```bash
rtk proxy cargo test --locked -p xtask --test spec_completeness verification_report_expresses_quarantine_and_server_confirmation -- --exact --nocapture
rtk proxy cargo test --locked -p xtask --test spec_completeness gate_order_event_vocabulary_is_pinned_across_design_and_plan -- --exact --nocapture
```

Erwartet: je Exit 101 mit `1 failed`. Ursachen: `required` des Reports enthält heute genau 14 Felder ohne `formatErrors`/`quarantinedObjects`; `$defs.objectResult` hat kein `serverConfirmation`; `$defs.quarantinedObject` existiert nicht; Design §14.1 nennt die Schritte in Prosa ohne Event-Bezeichner.

- [ ] **Step 4: Kein Commit**

Ledger: `Task 1: complete — zwei RED protokolliert.`

---

### Task 2: Report-Schema um Quarantäne und Server-Bestätigung erweitern

**Files:**
- Modify: `schemas/reports/v1/verification-report.schema.json`

**Interfaces:**
- Consumes: nichts.
- Produces: `formatErrors`, `quarantinedObjects`, `objectResult.serverConfirmation`; `verification_report_expresses_quarantine_and_server_confirmation` wird grün.

Das Schema ist durchgängig `additionalProperties: false` und sortiert jedes Array über `x-ea-sort-key`/`x-ea-unique-key`. Beide Konventionen gelten für die neuen Felder unverändert — der Report bleibt deterministisch und damit byteidentisch einfrierbar.

- [ ] **Step 1: Die zwei neuen Top-Level-Arrays ergänzen**

`required` wächst um `formatErrors` und `quarantinedObjects`. Die Eigenschaften, im Stil der bestehenden Fehlerarrays:

```json
    "formatErrors": {
      "description": "Unique format errors sorted by objectHash bytewise ascending.",
      "type": "array",
      "uniqueItems": true,
      "x-ea-sort-key": [{ "path": "objectHash", "encoding": "hex-bytes" }],
      "x-ea-unique-key": ["objectHash"],
      "items": { "$ref": "#/$defs/formatError" }
    },
    "quarantinedObjects": {
      "description": "Unique quarantined objects sorted by objectHash bytewise ascending.",
      "type": "array",
      "uniqueItems": true,
      "x-ea-sort-key": [{ "path": "objectHash", "encoding": "hex-bytes" }],
      "x-ea-unique-key": ["objectHash"],
      "items": { "$ref": "#/$defs/quarantinedObject" }
    },
```

- [ ] **Step 2: Die zwei neuen `$defs` ergänzen**

`reason` ist ein geschlossenes Enum — genau die drei Fälle, die der Stage-1-Plan `:1533` benennt, plus der Fall, dass die Bytes zwar dekodieren, aber keiner Kettenposition zuzuordnen sind. Kein Freitext: der Report darf keine unkontrollierten Zeichenketten tragen.

```json
    "formatError": {
      "type": "object",
      "additionalProperties": false,
      "required": ["objectHash", "code"],
      "properties": {
        "objectHash": { "$ref": "#/$defs/sha256" },
        "code": { "type": "string", "pattern": "^EA-FORMAT-[A-Z0-9-]+$" }
      }
    },
    "quarantinedObject": {
      "type": "object",
      "additionalProperties": false,
      "required": ["objectHash", "reason"],
      "properties": {
        "objectHash": { "$ref": "#/$defs/sha256" },
        "reason": {
          "enum": ["malformed", "duplicate", "conflicting", "unattributable"]
        }
      }
    },
```

- [ ] **Step 3: `objectResult` um die orthogonale Dimension erweitern**

`result` bleibt exakt `["valid", "authorizedDestroyed"]` — die Server-Bestätigung wird ausdrücklich NICHT hineingefaltet, weil `design.md` §17.4 das verbietet.

```json
      "required": ["objectHash", "objectType", "result", "serverConfirmation"],
      "properties": {
        "objectHash": { "$ref": "#/$defs/sha256" },
        "objectType": { "type": "integer", "minimum": 1, "maximum": 6 },
        "result": { "enum": ["valid", "authorizedDestroyed"] },
        "serverConfirmation": { "enum": ["serverConfirmed", "notServerConfirmed"] }
      }
```

- [ ] **Step 4: Schema validieren und GREEN prüfen**

```bash
rtk cargo run --locked -p xtask -- validate-schemas
rtk proxy cargo test --locked -p xtask --test spec_completeness verification_report_expresses_quarantine_and_server_confirmation -- --exact --nocapture
rtk cargo test --locked -p xtask --test schema_validation
```

Erwartet: `validate-schemas` meldet unverändert 7 CDDL und 7 JSON-Schemas; der fokussierte Test `1 passed`.

- [ ] **Step 5: Kein Commit**

Ledger: `Task 2: complete — Report-Schema erweitert.`

---

### Task 3: Gate-Event-Vokabular in `design.md` §14.1 normativ benennen

**Files:**
- Modify: `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md` §14.1

**Interfaces:**
- Consumes: nichts.
- Produces: die Hälfte von `gate_order_event_vocabulary_is_pinned_across_design_and_plan`.

- [ ] **Step 1: Jedem der neun Schritte seinen Bezeichner geben**

Die Reihenfolge und der Wortlaut der Schritte bleiben unverändert; ergänzt wird je Schritt der Event-Bezeichner in Rückwärts-Anführungszeichen, den die Verifikationspipeline protokolliert:

| Schritt | Bezeichner |
|---|---|
| 1 Format und Parserlimits | `format` |
| 2 Organisations-Root und Trust-Event-Kette | `trust` |
| 3 Registry-Head, Sequenz-Lease, Writer-Zertifikat | `registry` |
| 4 `signedManifest`, COSE-Signatur, Hashes | `manifest-signature` |
| 5 Sequenz, Vorgänger-Hash, Writer-Transition | `chain-position` |
| 6 initialer Grant-Plan und Recovery-Grant | `grant-plan` |
| 7 Server-Receipt und Checkpoints | `receipt` |
| 8 Evidence-Objekte und Zeitstempel | `evidence` |
| 9 eigener Grant samt Capability, Authorization, Frist | `recipient-grant` |

- [ ] **Step 2: Die Entkapselung als Nicht-Gate kennzeichnen**

Unter die Liste, angrenzend an den bestehenden Satz „Erst danach entkapselt er den CEK":

> Die Entkapselung wird als `hpke-open` protokolliert. Sie ist **kein** Gate: sie folgt auf das neunte, und keine Verifikationsentscheidung hängt an ihr. Ein Protokoll, in dem `hpke-open` vor einem der neun Bezeichner erscheint oder in dem ein Bezeichner fehlt, ist ein Implementierungsfehler und MUSS als Testfehlschlag sichtbar werden.
>
> Diese Bezeichner sind normativ und gelten unverändert im Browser (`2026-08-15-einsatzarchiv-web-reader-design.md` §9). Sie sind Protokollnamen für Tests und Fehlerberichte, nicht Teil der Statussprache aus §17.4 und nicht in der Oberfläche darzustellen.

- [ ] **Step 3: Den Reportzustand aus §17.4 auf den Bericht anwenden**

Ebenfalls in §14.1, weil hier Schritt 7 beschrieben wird:

> Findet Schritt 7 für ein ansonsten gültiges Objekt kein Receipt, ist das Objekt `verifiziert` und zugleich `nicht server-bestätigt` (§17.4). Der Verifikationsbericht führt beide Dimensionen getrennt: `result` bleibt das Verifikationsergebnis, `serverConfirmation` die Bestätigungsdimension. Im Datei-Modus ist `notServerConfirmed` der Regelfall und DARF NICHT als Mangel dargestellt werden.

- [ ] **Step 4: Kein Commit**

Ledger: `Task 3: complete — neun Gate-Bezeichner und die Reportanwendung normativ verankert.`

---

### Task 4: Stage-1-Plan Task 9 präzisieren

**Files:**
- Modify: `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md` Task-9-Abschnitt und Task-10-Abschnitt

**Interfaces:**
- Consumes: Tasks 2 und 3.
- Produces: `gate_order_event_vocabulary_is_pinned_across_design_and_plan` wird grün.

- [ ] **Step 1: Den Signaturwiderspruch auflösen**

Task 9 deklariert `verify_archive(source: &dyn ArchiveSource, …)`, aber sein eigener Test ruft `verify_archive(&fixtures::canonical_paths(), …)` mit einer Pfadsammlung auf. Verbindlich ist die Trait-Objekt-Fassung; der Test wird angeglichen:

```rust
#[test]
fn renamed_objects_rebuild_the_same_chain() {
    let canonical = fixtures::canonical_paths();
    let randomized = fixtures::randomized_paths();
    let a = verify_archive(&canonical, fixtures::anchor(), VerifyOptions::default()).unwrap();
    let b = verify_archive(&randomized, fixtures::anchor(), VerifyOptions::default()).unwrap();
    assert_eq!(a.chain_head(), b.chain_head());
}
```

Dazu die Festlegung: `fixtures::canonical_paths()` und `fixtures::randomized_paths()` liefern jeweils einen Typ, der `ArchiveSource` implementiert — nicht eine `Vec<PathBuf>`. Der Aufruf `&canonical` ist damit die Unsize-Coercion auf `&dyn ArchiveSource`, kein Typwechsel.

- [ ] **Step 2: Den vollständigen Event-Präfix in den RED aufnehmen**

Der bestehende RED prüft nur den Vierer-Präfix. Er wird um die vollständige Erwartung ergänzt, damit die Namen 5 bis 9 nicht erfunden werden:

```rust
#[test]
fn verification_stops_before_grant_or_decryption_on_bad_signature() {
    let events = RecordingVerifier::run(fixtures::bad_writer_signature()).unwrap_err().events;
    assert_eq!(events, ["format", "trust", "registry", "manifest-signature"]);
    assert!(!events.contains(&"hpke-open"));
}

#[test]
fn a_fully_valid_entry_records_every_gate_in_order_before_decryption() {
    let events = RecordingVerifier::run(fixtures::complete_valid_entry()).unwrap().events;
    assert_eq!(
        events,
        [
            "format",
            "trust",
            "registry",
            "manifest-signature",
            "chain-position",
            "grant-plan",
            "receipt",
            "evidence",
            "recipient-grant",
            "hpke-open",
        ]
    );
}
```

- [ ] **Step 3: Das Adapterverhältnis festschreiben**

Der Task-8-Plan hat den Port bewusst offen gelassen: „`TrustObjectSource` is read-only and archive-agnostic; Task 9 supplies its `ArchiveInventory` adapter from a higher crate" (`:7`), und `:615-624` beschreibt das Verhalten des offiziellen Adapters bereits vollständig. In den Task-9-Abschnitt:

> **Adapterverhältnis, verbindlich.** `ArchiveSource` ist der neue, breitere Port über **alle** Archivbytes; `TrustObjectSource` (`crates/ea-trust/src/source.rs`) bleibt unverändert der schmale, archiv-agnostische Trust-Port. `ea-archive` liefert den offiziellen `ArchiveInventory`-Adapter, der `TrustObjectSource` **implementiert** — es wird nichts dupliziert und `ea-trust` erfährt nichts über Archivlayout. Der Adapter ruft den Visitor direkt beim Durchlaufen seines beschränkten Trust-Index auf, hält vor dem nächsten Element an, sobald der Visitor einen Fehler liefert, und baut ausdrücklich **keinen** zwischenzeitlichen unbeschränkten `Vec` von Hashes (Task-8-Plan `:614-617`). Die Schranken `MAX_TRUST_OBJECTS_V1` und `MAX_TOTAL_TRUST_OBJECT_BYTES_V1` gelten unverändert und werden nicht neu definiert.

- [ ] **Step 4: Die neuen Reportfelder in Task 9 und Task 10 benennen**

In Task 9, an die Stelle des bisherigen Hinweises auf den bekannten Defekt:

> **Reportform, verbindlich.** `VerificationReportV1` trägt `formatErrors` und `quarantinedObjects` (Grund aus dem geschlossenen Enum `malformed`/`duplicate`/`conflicting`/`unattributable`) sowie je Objektergebnis `serverConfirmation` als eigene Dimension neben `result`. Fail-closed bleibt unangetastet: ein quarantänisiertes Objekt DARF NIEMALS dazu führen, dass der Bestand als vollständig verifiziert dargestellt wird, und `notServerConfirmed` ist kein Mangel. Die JSON-Schema-Validierung des Reports gehört NICHT in `ea-verify` — `jsonschema` zöge `getrandom 0.3.4` in den wasm-Graph — sondern in `xtask` und die Tests.

In Task 10, beim byteidentischen Baseline-Test:

> Die eingefrorene Baseline enthält `formatErrors`, `quarantinedObjects` und `serverConfirmation`. Sie wird erst eingefroren, nachdem Phase A dieser Felder wegen abgeschlossen ist.

- [ ] **Step 5: GREEN prüfen**

```bash
rtk proxy cargo test --locked -p xtask --test spec_completeness gate_order_event_vocabulary_is_pinned_across_design_and_plan -- --exact --nocapture
rtk cargo test --locked -p xtask --test spec_completeness
```

- [ ] **Step 6: Kein Commit**

Ledger: `Task 4: complete — Signatur, Event-Präfix, Adapterverhältnis und Reportfelder im Stage-1-Plan verankert.`

---

### Task 5: Vollständige Gates und EIN atomarer Commit

**Files:**
- Modify: `.superpowers/sdd/2026-08-16-einsatzarchiv-task-9-phase-a/progress.md` (ungetrackt)

- [ ] **Step 1: Scope-Audit**

```bash
rtk git diff --stat
rtk git diff -- crates
```

Erwartet: `crates/` ist **unverändert**. Jeder Treffer dort ist ein Scope-Bruch.

- [ ] **Step 2: Toolchain prüfen**

```bash
rustup show active-toolchain
```

Erwartet `1.95.0-…` ohne `overridden by environment variable`.

- [ ] **Step 3: Gate-Satz**

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

`test:property` und `test:fuzz` laufen nicht: dieser Plan ändert keinen Codec und keinen Parser, und `cargo test --workspace --all-targets --locked` deckt `xtask` vollständig ab. Bewusste, hier begründete Abweichung vom Phase-B-Mustersatz.

- [ ] **Step 4: Commit**

```bash
rtk git add \
  schemas/reports/v1/verification-report.schema.json \
  docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md \
  docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md \
  docs/superpowers/plans/2026-08-16-einsatzarchiv-task-9-phase-a-report-and-gate-order.md \
  tools/xtask/tests/spec_completeness.rs
rtk git diff --cached --check
rtk git commit -m "docs(core): close task 9 report representation and gate order"
```

- [ ] **Step 5: Ledger und Übergabe an Phase B**

Roll-up ins Stage-1-Ledger oberhalb von `Task 9: pending`. Phase B kann beginnen; sie legt `ea-chain`, `ea-archive` und `ea-verify` an, nimmt die drei Crates in die wasm32-Positivliste auf und ergänzt die Klassifikationszusicherung in `tools/xtask/tests/workspace.rs`.

---

## Self-Review

**Abdeckung.** Quarantäne (Stage-1-Plan `:1533`) → Tasks 1, 2, 4. Server-Bestätigung (Web-Reader-Spec §5.4, `design.md` §17.4) → Tasks 1, 2, 3, 4. Neun-Schritt-Gate-Reihenfolge (`design.md` §14.1, Web-Reader-Spec §9) → Tasks 1, 3, 4. `verify_archive`-Signaturwiderspruch → Task 4 Step 1. Adapterverhältnis zu `TrustObjectSource` (Task-8-Plan `:7`, `:614-624`) → Task 4 Step 3. `jsonschema`-Verbot in `ea-verify` → Task 4 Step 4.

**Bewusst nicht hier.** Die drei Crates selbst, das Archivlayout, die Chain-Rekonstruktion, die `.eds`/`UnexplainedGap`-Semantik und die Positivlisten-Erweiterung — alles Phase B. Die Task-11-Blockaden aus `219cc63` (§7.5-Form, §4.2-Policy-Frist, Traceability) bleiben unberührt; Task 9 berührt keine davon.

**Typkonsistenz.** Die neun Event-Bezeichner erscheinen in Task 1 Step 2 (Testkonstante), Task 3 Step 1 (Designtabelle) und Task 4 Step 2 (Plan-RED) und müssen dort zeichengleich sein. `serverConfirmation` mit den Werten `serverConfirmed`/`notServerConfirmed` erscheint in Task 1 Step 1, Task 2 Step 3 und Task 4 Step 4. Die vier Quarantänegründe erscheinen in Task 2 Step 2 und Task 4 Step 4.
