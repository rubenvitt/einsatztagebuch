# Stufe-2-Nacharbeit vom 2026-08-28 (DRK-206)

Stand: Branch `drk-206-stufe-2-nacharbeit`, Basis `42cbfaf`.

Dieses Dokument ist der Ort für die Korrekturen, die die Stufe 2 nach ihrem
Abschluss noch braucht. Es entsteht neu und ändert keine geschlossene Quelle:
`docs/traceability/stage-1-gate.md`, `final/testqualitaet.md` und die übrigen
`final/*.md` bleiben unangetastet. Wo eine geschlossene Aussage unrichtig ist,
steht hier der Korrekturantrag und nicht die Überschreibung.

Jede Aussage in diesem Dokument nennt ihren Beleg: einen Commit dieses
Branches, eine Stelle `Datei:Zeile` oder einen Testnamen. Wo etwas nicht
belegbar ist, steht das ausdrücklich da.

Die Schreibweise: dieses Dokument verwendet durchgehend echte Umlaute. Der
Gate-Bericht `docs/traceability/stage-2-gate.md` und das Ledger
`docs/traceability/v0.1-requirements.csv` behalten ihre umlautfreie Umschrift
(`ue`/`ae`), weil `xtask` Literale gegen sie hält.

---

## 1. Ruling R62 — die Stale-Registry-Quittung wandert nach Stufe 5

**Der Widerspruch.** Das Gate-Bullet
`docs/superpowers/plans/2026-08-13-einsatzarchiv-v0-1.md:358` verlangt für
Stufe 2 wörtlich eine „durable signed one-use audit acknowledgement" für die
Fortsetzung unter einem veralteten Registry-Kopf im Standardprofil.

**Was Stufe 2 tatsächlich hat.** Die ERKENNUNG samt fail-closed-Ausgang, und
nur die: `crates/ea-writer/tests/stale_registry_warning.rs::a_head_that_expires_while_bound_is_acknowledgeable_and_blocks_fail_closed`
und `::an_overdue_refresh_deadline_warns_without_blocking`. Der
Bestätigungspfad selbst ist NICHT gebaut —
`WriterService::acknowledge_stale_registry` existiert nicht — die Crate sagt es
selbst (`crates/ea-writer/src/lib.rs:37-39`: „Der Bestaetigungspfad eines
VERALTETEN Registry-Head … ist nicht gebaut. Die ERKENNUNG ist es"), und der
Baum trägt keine Definition dieses Namens —, und der Wirtsstummel
`writer_acknowledge_stale_registry` meldet
`EA-DESKTOP-STALE-ACK-UNAVAILABLE`
(`apps/desktop/src-tauri/src/commands/mod.rs:52`, Doku am Stummel in
`apps/desktop/src-tauri/src/commands/writer.rs:1148`). Task 4 dieser Nacharbeit
hat den Stummel bewusst stehen lassen (Commits `6b7cedc..625761a`).

**Ruling R62.** Die dauerhafte signierte Einmal-Quittung gehört AUSDRÜCKLICH zur
Stufe 5, wo auch die Administrationsseite von AK 24 steht. Stufe 2 liefert
Erkennung und Blockade, nicht die Quittung. Das Gate-Bullet wird nicht
umgeschrieben; sein Wortlaut bleibt stehen und trägt seit dem 2026-08-28 eine
datierte Fußnote (`docs/superpowers/plans/2026-08-13-einsatzarchiv-v0-1.md`,
unmittelbar unter dem Bullet).

**Wo das Ruling festgehalten ist.**

1. Fußnote unter dem Bullet in
   `docs/superpowers/plans/2026-08-13-einsatzarchiv-v0-1.md` (Wortlaut des
   Bullets unverändert).
2. Dieser Abschnitt.
3. Merker im Stufe-5-Plan
   (`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-5-administration-recovery.md`,
   Global Constraints, „Merker Stale-Registry-Quittung").
4. Gate-Bericht: die Zeile `| Teilbeleg AK 24 |` in
   `docs/traceability/stage-2-gate.md` nennt das Ruling in ihrer
   Fälligkeitsspalte.

**Ledger.** Die Belegspalte von `AK-24` `v1.1` (Stufe 2, `implemented`) bleibt
UNVERÄNDERT — sie beschreibt bereits genau die Erkennung und schreibt den
Bestätigungspfad der Stufe 5 zu. Eine zusätzliche Zeile wurde geprüft und ist
nicht nötig: `xtask stage-gate 2` verlangt Ledgerzeilen nur für die aus
`design.md` abgeleitete Pflichtmenge, und `AK-24` ist mit seiner `v1`-Zeile
(Stufe 5, `planned`) darin abgedeckt. Der Ledgeranker des Rulings ist damit
`AK-24` `v1`, Stufe 5, `planned`.

---

## 2. Die Gegenstandsspalten des Gate-Berichts gegen `design.md` §23

Geprüft wurden alle zwölf `| AK `-Zeilen und alle vier `| Teilbeleg AK `-Zeilen
in `docs/traceability/stage-2-gate.md` Abschnitt 1 gegen den Wortlaut von
`docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md` Abschnitt 23
(`:2108` bis `:2165`, die vierundfünfzig nummerierten Kriterien).

**Ergebnis: genau eine Abweichung.** AK 46 hieß im Gate-Bericht
„Entwurfsverwaltung"; in `design.md` §23 heißt Kriterium 46 „Entwurf und
Eingabevertrag". Der Bericht ist angeglichen. Bestätigend: die Ledgerzeile
`AK-46` `v1` trug den Entwurfswortlaut schon vorher — der Bericht war der
Ausreißer, nicht das Ledger.

Die übrigen fünfzehn Gegenstandsspalten decken sich mit dem Entwurfstext
(Offline-Abschluss, Kein Writer-Zugriff, Neue Maske, Stromausfall,
Plattform-Key-Provider, Writer-Restore, CSV-Stammdatenimport, Prepared
Recovery, Durable Backend, Archivprofilwechsel, Record-ID und Sequenz sowie die
vier Teilbelege Keine Klartextlogs, Registry-Überalterung, Rollentrennung,
Operator-Identität).

**Der nicht belegte Rest, jetzt ausdrücklich in der Offen-Spalte.** Für drei
Kriterien deckt der Stufe-2-Beleg nicht den ganzen Wortlaut des Entwurfstextes.
Das steht seit dem 2026-08-28 in der letzten Spalte der jeweiligen Zeile:

- **AK 23.** Der Teilsatz „nach Sperre nicht ohne Re-Authentisierung verwendet"
  ist NICHT belegt: die Plattformbeobachter des Sperrereignisses fehlen und
  `is_valid_for`/`MAX_INACTIVITY_MS` werden im Wirt nicht ausgewertet (Ruling
  R59 Teil 2). Zusätzlich offen bleibt die native BINDUNG selbst (Ruling R57).
- **AK 39.** Der Teilsatz „Jede Plattform beweist …" ist nur für das
  Host-Target belegt. Die advisory-lock-Semantik der jetzt gebauten
  Betriebssystemsperre ist auf genau einem Betriebssystem gemessen.
- **AK 46.** Das Kriterium ist am KERN belegt. Der Desktop-Wirt konstruiert bis
  heute keinen Entwurfsdienst (`apps/desktop/src-tauri/src/lib.rs:77-85`), und
  das Verwerfen ist im Wirt strukturell vorbereitet, nicht erreicht (VM-11).

---

## 3. Nachmessung x86_64-apple-darwin

Ein einziger Messversuch, damit die Reichweitenklausel der Stufe 2 nicht länger
ungemessen dasteht.

**Ausgangslage.** `env -u RUSTUP_TOOLCHAIN rustup show active-toolchain` meldet
`1.95.0-aarch64-apple-darwin (overridden by … rust-toolchain.toml)`.
`rustup target list --installed` meldete vor der Messung genau zwei Ziele:
`aarch64-apple-darwin` und `wasm32-unknown-unknown`.

**Durchgeführt.**

```
env -u RUSTUP_TOOLCHAIN rustup target add x86_64-apple-darwin
env -u RUSTUP_TOOLCHAIN cargo check --locked --workspace --target x86_64-apple-darwin
```

**Ergebnis: GRÜN.** Exitcode `0`. Erstlauf am 2026-08-28 von 13:38:40Z bis
13:39:40Z, gemessen `Finished dev profile … in 1m 00s`; ein Bestätigungslauf auf
warmem `target/` meldete erneut Exitcode `0`. Übersetzt wurde der GANZE
Workspace einschließlich `apps/desktop/src-tauri` (`ea-desktop`),
`einsatzarchiv-cli`, `tools/xtask`, `tests/ea-system-tests` und aller
Bibliotheks-Crates.

**Was diese Messung belegt — und was nicht.** Belegt ist die
ÜBERSETZBARKEIT des Workspace für `x86_64-apple-darwin` unter dem gepinnten
Toolchain-Stand `1.95.0`. NICHT belegt ist die native AUSFÜHRUNG: kein Test
lief auf diesem Ziel, kein Key-Provider wurde dort angesprochen, kein
Dateisystemverhalten dort gemessen. Genau die Ausführung ist es, die die vier
`AK-23`-`v1.1`-Ledgerzeilen offen halten — nicht die Übersetzung.

**Was deshalb ausdrücklich NICHT geändert wurde.** Die Reichweitenklausel
(`STAGE_TWO_HOST_SCOPE_CLAUSE`) bleibt Wort für Wort stehen, und keine der vier
`planned`-Ledgerzeilen ändert ihren Status. Der Zusatz `rustup target add` liegt
außerhalb des Pins in `rust-toolchain.toml`, der weiterhin nur
`wasm32-unknown-unknown` bereitstellt; die Klausel beschreibt also weiterhin
richtig, was der eingecheckte Stand ohne lokalen Handgriff hergibt. Die drei
übrigen Ziele (`x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`,
`aarch64-apple-darwin`) wurden nicht gemessen; für das Host-Target
`aarch64-apple-darwin` misst der Gate-Lauf ohnehin laufend mit.

---

## 4. Ledgeränderungen dieser Nacharbeit

Alle Änderungen sind additiv, bis auf eine ausdrücklich begründete Umschrift
einer Belegspalte. Keine `v1`-Zeile ist angefasst. Das Ledger wächst von 146 auf
149 Zeilen; `xtask stage-gate 2` meldet `149` Zeilen, `4` `host_evidence_rows`
und ein leeres `stage_two_rows_still_planned`.

### 4.1 QS-07 — zwei neue `v1.1`-Zeilen für das öffentliche Formatpaket

| Zeile | Stufe | Status | Beleg |
|---|---|---|---|
| `FR-064` `v1.1` „Trust-Daten und Formatdokumentation - Stufe-2-Teilbeleg" | 2 | `implemented` | `crates/ea-archive-fs/tests/format_package.rs:149::a_backend_that_creates_an_archive_materializes_the_format_package_without_a_separate_call`; Anlagepfad `crates/ea-archive-fs/src/local_path.rs:291` mit `materialize_format_package_under_lock` an `:318` |
| `FR-142` `v1.1` „oeffentliches, versioniertes Format - Stufe-2-Teilbeleg" | 2 | `implemented` | derselbe Zeuge; `FORMAT_PACKAGE_FILES_V1` wird beim Anlegen eines Bestands materialisiert |

Der Befund dahinter: beide `v1`-Zeilen standen auf Stufe 1 mit Status
`planned`, obwohl Stufe 2 einen echten Teilbeleg erbracht hat — jeder von
`ea-archive-fs` angelegte Bestand trägt das öffentliche Formatpaket samt
`README-FORMAT.txt`, ohne dass ein zweiter Aufruf nötig wäre. Die `v1`-Zeilen
bleiben unverändert auf Stufe 1 und `planned`; die Veröffentlichung des Formats
außerhalb des Bestands und seine Releaseprovenienz bleiben offen.

### 4.2 PI-09 — Pflichtzeile für die Bereinigung von Staging- und Abbruchresten

| Zeile | Stufe | Status |
|---|---|---|
| `FR-043` `v1.1` „Bereinigung von Staging- und Abbruchresten" | 3 | `planned` |

**Warum `FR-043`.** Der Befund hängt an `design.md` §9.4, und `FR-043` ist die
einzige Ledgerzeile, deren `source`-Spalte diesen Abschnitt bereits führt
(„Normative Spec: 9.3–9.4; 11.5"). Die beiden anderen Zeilen mit `9.4`-Bezug
treffen ihn nicht: `FR-032` ist die Entwurfswiederherstellung, `FR-050` der
Kopfabgleich beim Writer-Restore.

**Der Befund.** `design.md:460` (Schritt 13) verlangt, Staging nach
vollständiger Reconciliation zu bereinigen; `design.md:468` verlangt, vorab
veröffentlichte Grants ohne committed `.eip` „nach nachgewiesenem Abbruch"
zu bereinigen. Stufe 2 tut beides nicht:
`crates/ea-writer/src/recover.rs:136-139` lässt die Staging-Dateien vor der
unwiderruflichen Grenze bewusst liegen, weil der Archivport keine
Löschprimitive hat, und `crates/ea-archive-fs/src/health.rs:180-196` meldet sie
lediglich als `HealthFinding::OrphanGrantOrTemporaryFile`. Das ist fail-closed
und ohne Datenverlust, aber der Bestand wächst mit jedem Abbruch, und der
Gesundheitsbericht wird mit jedem Abbruch lauter.

### 4.3 Umschrift der Belegspalte von `AK-39` `v1.1` (Stufe 7, `planned`)

Die einzige nicht rein additive Änderung, und die einzige, die sein muss: der
alte Text beschrieb die Sperre als „per `create_new` genommen und nur im `Drop`
freigegeben" und leitete daraus ab, dass eine liegengebliebene Sperrdatei
dauerhaft blockiert. Beides ist seit Task 3 dieser Nacharbeit
(Commits `bee2cfa..c7e789d`) SACHLICH FALSCH — eine stehen gelassene
Belegspalte wäre also nicht konservativ, sondern unwahr. Geprüft vor der
Umschrift: `tools/xtask/tests/stage_gate.rs` enthält keinen Treffer auf
`AK-39`, pinnt den Zeilentext also nicht; die Escape-Regel „dann additiv statt
umschreiben" greift nicht.

Der neue Text nennt: die gebaute Betriebssystemsperre über
`std::fs::File::try_lock`, ihre vier Zeugen, das Fehlen von Reaper und
PID-Prüfung als Folge — und als einzigen offenen Rest den Nachweis auf drei
Betriebssystemen samt Netzdateisystemen. `requirement_id`, `version`,
`primary_acceptance_criterion`, `stage` und `status` sind unverändert; nur
`title` und `evidence` sind neu geschrieben.

---

## 5. Nachträge im Gate-Bericht (N4, G5, F10-Merker)

Sie stehen im Gate-Bericht selbst, unter der neuen Überschrift
`## Nachtraege der Nacharbeit DRK-206 (2026-08-28)`, und bewusst HINTER dem
Abschnitt `Gemessener Gate-Lauf`: dessen Tabelle wird von
`tools/xtask/tests/stage_gate.rs::stage_two_gate_report_records_the_measured_full_gate_run`
zeilengenau gelesen, und eine weitere Tabellenzeile dort wäre ein Messwert, den
niemand gemessen hat.

- **N4.** Der Zwischenschritt 942/943 im Vorspann der Messtabelle ist aus den
  vorliegenden Berichten nicht rekonstruierbar. Die Endzahl 955 bestandene
  Tests in 125 Testbinaries stimmt und ist gemessen.
- **G5.** Richtigstellung: **Stufe 1 endete bei 75 Testzielen und 636
  bestandenen Tests**, protokolliert in
  `docs/traceability/stage-1-gate.md:160-167`. Das git-ignorierte
  Fortschrittsprotokoll der Stufe 2 nennt „82 Ziele / 688 Tests" — das ist
  unrichtig. Der geschlossene Stufe-1-Gate-Bericht wird dafür nicht bearbeitet;
  er ist die Quelle, nicht der Fehler.
- **F10-Merker.** Die mechanischen Teile sind erledigt (Commit `2a076dc`). Nicht
  gemacht und offen bleiben die zwei nicht-mechanischen: die Verwerfensmatrix
  prüft ohne Produktpfad, und die Harnesswurzel trägt keinen Zähler. Beides ist
  Testqualität, kein Produktbefund.

Die Messzahlen der Tabelle selbst rührt diese Nacharbeit nicht an; sie werden
in Task 7 des Plans `docs/superpowers/plans/2026-08-28-drk-206-stufe-2-nacharbeit.md`
auf dem dann gültigen HEAD neu gemessen.

---

## 6. Die Überträge nach Stufe 7

Fünf Zeilen sind am 2026-08-28 in die Global Constraints von
`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-7-release-hardening.md`
eingetragen worden. Sie stehen dort, weil ein Übertrag, der nur in einem
Gate-Bericht steht, nichts erzwingt.

| Übertrag | Was Stufe 7 liefern muss | Ledgeranker |
|---|---|---|
| R57(b) | native Key-Provider- und Re-Auth-API-Familien je Plattform plus ADR 0003, Nachweis auf echter Hardware | `AK-23` `v1.1`, Stufe 7, `planned` |
| R59 Teil 2 | Plattform-Sperrbeobachter je Betriebssystem UND Auswertung von `is_valid_for`/`MAX_INACTIVITY_MS` im Wirt | `AK-53` `v1.1`, Stufe 7, `planned` |
| R60 (Rest) | Nachweis der advisory-lock-Semantik auf drei Betriebssystemen und auf Netzdateisystemen; die Sperre selbst ist gebaut | `AK-39` `v1.1`, Stufe 7, `planned` |
| QS-12 | `cargo deny` als Pflichtausführung des Releaselaufs, erneute Bewertung der sechzehn `ignore`-Einträge | `GATE-25` `v1.1`, Stufe 7, `planned` |
| QS-11 | COSE-Prüfung der Releaseartefakte kryptografisch und VOR dem Commit, nicht strukturell und nicht danach | — (neu, ohne eigene Ledgerzeile) |

Zu R60 gehört ein Nebenbefund, der mit übergeht: `ea-recovery`
(`FsArchiveSource`) zählt die Sperrdatei `.ea-writer.lock` als
`nonObjectFile` (+1), und `ea-recovery export` kopiert sie mit:
`crates/ea-recovery/src/source.rs:125-175` liest jede reguläre Datei unter der
Wurzel ein, und `CONTROL_FILES_V1` kommt in `crates/ea-recovery/src/` an keiner
Stelle vor. Die Präzedenz ist `.ea-active-profile`, das sich seit je genauso
verhält.

QS-11 hat bewusst keine eigene Ledgerzeile bekommen: der Punkt betrifft die
Releasezeremonie und keine nummerierte Anforderung des Entwurfs, und eine
erfundene Kennung im Ledger wäre schlechter als ein benannter Merker im Plan.

---

## 7. Korrekturanträge zu `final/testqualitaet.md` §9b

`final/testqualitaet.md` ist ein abgeschlossenes Reviewdokument und bleibt
unangetastet. **Es liegt nicht in diesem Arbeitsbaum** — `final/` existiert hier
nicht. Was folgt, ist deshalb kein Abgleich mit dem Dokument selbst, sondern die
Nachmessung der acht Positionen, mit denen die F9-Runde §9b widersprochen hat.
Jede Position ist am 2026-08-28 gegen HEAD neu gemessen; wo die Nachmessung von
der überlieferten Fassung abweicht, steht die Abweichung ausdrücklich da. Die
Commitbelege der Runde: `66a3934`, `475f38a` und Task 2 dieser Nacharbeit
(`594b20a..5373288`).

1. **Zwei tote Varianten mit behaupteter Erhebungsstelle — HÄLT.**
   `WriterError::NoPreparedFinalization` (`crates/ea-writer/src/error.rs:67`,
   Code `EA-WRITER-NO-PREPARED-FINALIZATION` an `:132`) und
   `WriterError::StaleAckReplay` (`:89`, Code `EA-REGISTRY-STALE-ACK-REPLAY` an
   `:139`). Nachgemessen über `crates/`, `apps/` und `tests/`: für beide Namen
   ausschließlich Deklaration und Codearm, keine Erhebungsstelle, kein Test.

2. **„Vier strukturell unerreichbare Codes" — nachgemessen halten ZWEI.** Das
   ist die zweite Korrektur an der überlieferten Fassung.
   - `EA-MASTER-REVISION-OVERFLOW`: **hält.** Einzige Erhebungsstelle
     `crates/ea-draft/src/master_data.rs:334` verlangt eine negative
     Revisionsspalte, die `CHECK (revision >= 1)` ausschließt
     (`crates/ea-local-store/migrations/0003_master_data.sql:55` und `:70`). Der Code ist gepinnt
     (`crates/ea-draft/tests/snapshots.rs:122`), und die Begründung steht dort
     an `:115-118`.
   - `EA-OPERATOR-DEVICE-CERTIFICATE-NOT-ACTIVE`: **hält.** Erhebungsstelle
     `crates/ea-operator/src/account.rs:231`; über `SelectedRegistryHead` nicht
     erreichbar, weil `PreviousHeadState::active_operator_binding`
     (`crates/ea-trust/src/resolver.rs:151-168`) die Zertifikatsprüfung selbst
     führt und schon der erste Zugriff `None` meldet. Bewacht von
     `crates/ea-operator/tests/session_contract.rs::a_revoked_device_certificate_already_stops_the_binding_lookup`
     — ein Test, der nicht den Code bezeugt, sondern die Aussage, dass keiner
     nötig ist.
   - `EA-WRITER-SEQUENCE-LEASE-EXHAUSTED`: **hält NICHT.**
     `crates/ea-writer/src/finalize.rs:631` ist eine gewöhnliche
     Bereichsprüfung gegen `effective_from_sequence`/`valid_through_sequence`,
     und der Baum trägt keine Begründung für Unerreichbarkeit. Kein Test pinnt
     den Code; der einzige Berührungspunkt ist
     `apps/desktop/src-tauri/src/commands/writer.rs::the_blocked_code_is_the_code_of_the_core_error`,
     der den Fehlerwert durch die Naht reicht, statt die Prüfung auszulösen.
     Richtig ist: **erreichbar und ungepinnt** — ein echtes Versäumnis.
   - `EA-WRITER-NO-DRAFT-CONTENT`: **hält NICHT.**
     `crates/ea-writer/src/finalize.rs:252` und `:273` sind `ok_or`-Tiefenschutz
     auf `reached.preview` beziehungsweise `reached.outcome`, die der interne
     Ablauf auf dem vollständigen Weg füllt. Anders als bei den zwei ersten
     trägt der Baum dafür KEINE Unerreichbarkeitsbegründung, und kein Test pinnt
     den Code. Richtig ist: **erreichbar aus dem Aufrufvertrag heraus,
     ungepinnt, ohne Nachweis der Unerreichbarkeit.**

3. **Falscher Erhebungsort der Archivcodes — HÄLT, aber es sind SECHS und nicht
   vier.** Deklariert in `crates/ea-archive/src/backend_error.rs:77-82`, erhoben
   ausnahmslos in `crates/ea-archive-fs/src/profile_migration.rs`:
   `ReauthMismatch` (`:413`), `MigrationFault` (`:381`, `:528`),
   `PendingPublication` (`:79`), `InventoryMismatch` (`:502`, `:509`),
   `VerificationFailed` (`:484`, `:490`, `:496`) und `AuditFailed` (`:619`).
   `ea-archive` kann sie ohne Cargo-Zyklus gar nicht bezeugen.

4. **Drei Codes waren erreicht, aber nur ungepinnt** (`is_err()` statt
   Codevergleich) — **HÄLT, und alle drei sind inzwischen gepinnt**:
   `EA-ARCHIVE-MIGRATION-FAULT` (`crates/ea-archive/src/backend_error.rs:78`,
   gepinnt in `crates/ea-archive-fs/tests/profile_migration.rs:45`, Test
   `every_fault_point_leaves_only_the_old_profile_active`),
   `EA-IMPORT-REPORT-HAS-ERRORS` (`crates/ea-draft/src/csv_import.rs:102`,
   gepinnt in `crates/ea-draft/tests/csv_import.rs:30`, Test
   `dry_run_does_not_write_and_commit_is_all_or_nothing`) und
   `EA-IMPORT-INPUT-CHANGED` (`csv_import.rs:103`, gepinnt in
   `crates/ea-draft/tests/csv_import.rs:75`, Test
   `commit_rejects_a_mutated_dry_run_hash`). Gepinnt in `475f38a`.

5. **`EA-MASTER-UNKNOWN-ID` war bereits bezeugt — HÄLT.**
   `crates/ea-draft/src/master_data.rs:70`, gepinnt in
   `crates/ea-draft/tests/snapshots.rs:112`, Test
   `an_unknown_master_id_is_a_named_absence_and_not_an_empty_snapshot`.

6. **`EA-MASTER-SNAPSHOT` — diese Position KEHRT SICH UM.** Die überlieferte
   Fassung sagte „toter Code, keine Validierungslücke": die fünf
   `map_err`-Stellen (`crates/ea-draft/src/master_data.rs:198`, `:232`, `:247`,
   `:266`, `:483`) hingen an Konstruktoren ohne einen einzigen `Err`-Zweig. Zum
   Zeitpunkt von §9b stimmte das. **Auf diesem Branch stimmt es nicht mehr.**
   Der Basis-Commit dieser Nacharbeit, `42cbfaf` („validate snapshot texts and
   make EA-MASTER-SNAPSHOT reachable"), hat `value.validate()?` in die
   Konstruktoren gelegt — `crates/ea-schema/src/model.rs:891`
   (`PersonnelSnapshotV1::master`) und `:903` (`::ad_hoc`) —, und
   `crates/ea-draft/tests/snapshots.rs:128::a_snapshot_that_breaks_the_stage_1_text_rule_is_named`
   erzwingt den Code auf sechs Wegen. Nachgemessen am 2026-08-28:
   `cargo test --locked -p ea-draft --test snapshots` → 6 passed, 0 failed.
   **Richtig ist deshalb:** der Code war zum Zeitpunkt von §9b eine tote
   Variante, ist seit `42cbfaf` erhoben UND bezeugt, und er ist heute weder tot
   noch eine offene Testlücke. Warum die alte Fassung sich hielt: ihr Beleg war
   „null `Err(`-Zweige im ganzen Bereich", und ein `grep` auf das Literal
   `Err(` findet `value.validate()?` nicht.

7. **Die Blob-Schranke bleibt unbezeugt, und das ist keine Nachlässigkeit —
   HÄLT.** Ein Zeuge bräuchte 1 048 577 Dateien, und `FsArchiveSource` bietet
   keine Naht. Nachgemessen: `RecoveryError::ArchiveTooLarge`
   (`crates/ea-recovery/src/error.rs:34`) wird an fünf Stellen von
   `crates/ea-recovery/src/source.rs` erhoben (`:147`, `:175`, `:177`, `:185`,
   `:192`)
   und bildet auf `ExitCode::Integrity` ab
   (`crates/ea-recovery/src/exit.rs:168`) — dieselbe Klasse wie ihre
   vorbestehenden Schwestern `ArchiveError::BlobLimit` und `TotalByteLimit`
   (`exit.rs:200`). Ob `Integrity` für eine überschrittene Blobanzahl die
   richtige Klasse ist, ist eine vorbestehende Frage, die dieser Diff weder
   schafft noch verschärft.

8. **Der Zeuge von `EA-ARCHIVE-MIGRATION-FAULT` ist eingeschränkt
   falsifizierbar — HÄLT.** Gegen den Wächter als Ganzes ja, gegen die
   Einzelklausel nein: mit nur
   `crates/ea-archive-fs/src/profile_migration.rs:502` ausgehebelt bleibt er
   grün, weil `:509` denselben `ArchiveBackendError::InventoryMismatch` meldet.
   Das steht so im Testkommentar und gehört in die Bewertung.

**Schlusssatz — die gemessene Zahl.** Die Zahl „rund 25 Versäumnisse" trägt
nicht; die Richtung der F9-Runde stimmt. Ihre Zahl „rund 21" trägt nach dieser
Nachmessung aber ebenfalls nicht mehr: Position 2 gibt zwei Posten zurück
(`EA-WRITER-SEQUENCE-LEASE-EXHAUSTED` und `EA-WRITER-NO-DRAFT-CONTENT` sind
erreichbar und ungepinnt, also echte Versäumnisse), während Position 6 ihren
Posten weiterhin abzieht — nur aus dem stärkeren Grund, dass der Code seit
`42cbfaf` bezeugt ist statt tot. **Gemessen sind es damit rund 23 statt rund
25.**

Und die Grenze dieser Zahl ausdrücklich, weil sie sonst genauer klänge, als sie
ist: `final/testqualitaet.md` liegt nicht in diesem Arbeitsbaum, die
Grundgesamtheit der 25 ist hier also nicht nachzählbar. „Rund 23" ist die um
die acht nachgemessenen Positionen korrigierte Fassung derselben Schätzung und
keine unabhängig neu gerechnete Summe. Nachzählbar ist allein, was oben je
Position steht.

## 8. Web-Reader-Prerequisites (B.9)

Stand der drei offenen Punkte aus
`docs/superpowers/plans/2026-08-16-einsatzarchiv-web-reader-stage-1-prerequisites.md`.

**Pre-flight-Konflikt 1 (`:100`) — Objektfamilien: im Ledgereintrag „offen", in
der Sache GELÖST.** Der Eintrag lautet: Web-Reader-Spec §1 (`:20-24`) bestreitet
Änderungen an den Objektfamilien, §11.5/11.6 (`:420-421`) führt zwei neue ein.
Die Auflösung schreibt Task 2 Step 1 desselben Plans vor (`:295-313`, der
Ersatztext an `:311`), und sie ist AUSGEFÜHRT: die genannte Stelle
`docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md:20-24`
trägt heute den Ersatztext, der die zwei Familien benennt und sie
ausdrücklich zu einer „v1.1-Erweiterung außerhalb Stage 1" erklärt, gebaut
in Stufe 3 (`webBundleRelease`) beziehungsweise Stufe 5 (Reader-Key-Escrow).
Der Selbstwiderspruch besteht also nicht mehr; nur die Statuszeile des
git-ignorierten SDD-Ledgers wurde nicht nachgezogen.

Nachgemessen am 2026-08-28: im Ledger `docs/traceability/v0.1-requirements.csv`
steht KEINE Zeile, deren `source`-Spalte `web-reader-design.md 11` nennt — die
zwei Familien sind dort also noch nicht als `v1.1`-Zeilen verankert. Für
`webBundleRelease` trägt `WR-052` `v1.1` den Dateiweg bereits auf Stufe 2
(Entscheidung D-HE2); die Familie selbst hat keine eigene Zeile. Stufe 3 ist
davon nicht blockiert.

**Pre-flight-Konflikt 3 (`:102`) — Ablageort des Escrow-Chiffrats.** Offen. Der
Begriff „Administrationszone" aus Web-Reader-Spec §7.3 ist im Design nicht
definiert, und der einzige normativ definierte Root-signierte append-only
Bestand ist `trust/` im Archiv, das an jeden Reader repliziert wird. **Dieser
Konflikt blockiert Stufe 5, nicht Stufe 3.** So steht er auch im Stufe-5-Plan
(`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-5-administration-recovery.md`,
Global Constraints, „Blockiert auf zwei offene Entscheidungen"). Stufe 3 darf
ohne diese Entscheidung starten.

**Die „offene Flanke" `deny.toml` (`:1018`) — GESCHLOSSEN.** Der Vermerk sagte:
`deny.toml` existiere, werde aber von keinem Gate aufgerufen, und die neuen
`wasm-bindgen`- und `js-sys`-Kanten durchliefen daher keine
`licenses`/`bans`-Prüfung. Das gilt nicht mehr. Stufe 2 hat `cargo deny` als
`pnpm supply-chain` verdrahtet; das Skript ist eine der fünf
Pflichtdeklarationen, die `xtask stage-gate 2` in der Wurzel-`package.json`
erzwingt (`STAGE_TWO_REQUIRED_SCRIPTS` in `tools/xtask/src/main.rs`), und der
gemessene Lauf steht im Gate-Bericht mit `advisories ok, bans ok, licenses ok,
sources ok` unter `cargo-deny 0.20.2`. Die Restschuld ist benannt und
verankert: `GATE-25` `v1.1`, Stufe 7, `planned`, mit allen sechzehn
RUSTSEC-Kennungen.

---

## 9. Merker: der Key-Provider ohne native Aufrufe (B.11)

Nur ein Verweis, keine Änderung. Geprüft am 2026-08-28: die Ledgerzeile
`AK-23` `v1.1` „Plattform-Key-Provider - native Bindung statt Portschicht"
steht auf Stufe 7 mit Status `planned` und trägt in ihrer Belegspalte wörtlich
den Satz

> Ein gruener Stufe-2-Gate ist ausdruecklich kein Beleg fuer hardwaregebundene Schluessel.

Derselbe Satz ist ein vom Gate erzwungenes Pflichtliteral des Berichts
(`STAGE_TWO_GATE_REPORT_LITERALS`, sechzehnter Eintrag) und steht in
`docs/traceability/stage-2-gate.md` Abschnitt 2.1 in einer eigenen, nicht
umbrochenen Zeile. Beide Stellen sind unverändert geblieben.

---

## 10. Was diese Nacharbeit ausdrücklich NICHT getan hat

- Keine Zeile in `docs/traceability/stage-1-gate.md`, `final/testqualitaet.md`
  oder einem anderen `final/*.md` geändert.
- Die Reichweitenklausel `STAGE_TWO_HOST_SCOPE_CLAUSE` und die sechzehn
  Pflichtliterale des Gate-Berichts nicht angefasst.
- Keinen Status im Ledger von `planned` auf etwas anderes gehoben; insbesondere
  bleiben die vier `AK-23`-`v1.1`-Zielarchitekturzeilen `planned`, obwohl die
  Übersetzung für `x86_64-apple-darwin` grün gemessen wurde (Abschnitt 3).
- Die gemessenen Zahlen im Abschnitt `Gemessener Gate-Lauf` nicht verändert; sie
  gehören Task 7.
- Den Wortlaut der Gate-Bullets in
  `docs/superpowers/plans/2026-08-13-einsatzarchiv-v0-1.md` nicht umgeschrieben
  — dort steht nur eine datierte Fußnote darunter.
