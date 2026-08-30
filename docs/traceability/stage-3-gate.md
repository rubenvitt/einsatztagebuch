# Stufe-3-Gate-Bericht — Blind Sync

Dieser Bericht schliesst die Stufe 3 des Einsatzarchivs ab. Er haelt fest, was
die Stufe BELEGT, und — mit demselben Gewicht — was sie NICHT belegt. Ein
gruener `stage-gate 3` ist der Beleg fuer die Zusagen, die hier ausgeschrieben
stehen, und fuer keine darueber hinaus.

Die Stufe baut den blinden Sync-Server: er bewegt Chiffrat, das er nicht lesen
kann, bucht Eintraege unteilbar, stellt Quittungen aus und verteilt den
Vertrauensstand. Er entschluesselt nichts, signiert nichts als Writer und
autorisiert nichts als Registry.

Ein gruener Stufe-3-Gate ist ausdruecklich kein Beleg fuer eine produktionsreife Sicherung, ein signiertes Bild oder einen Plattformnachweis. Alle drei
schliessen in Stufe 7.

## 1. Primaere Abnahmekriterien und ihre Belege

Die sieben primaeren Abnahmekriterien der Stufe 3 nach `design.md`
Abschnitt 23. Die vierte Spalte ist keine Formsache: eine leere Zelle waere
genau die Scheinzusage, die dieser Bericht ausschliesst, und
`run_stage_three_gate` weist sie ab.

| Kriterium | Gegenstand | Beleg | Offen in spaeterer Stufe |
|---|---|---|---|
| AK 7 | Fork | `apps/server/tests/commit_failures.rs::a_fork_on_the_same_sequence_is_refused_and_recorded`; `crates/ea-sync-server/tests/commit_service.rs::a_fork_on_the_same_sequence_is_a_security_event`; die Gabel wird abgewiesen UND als Security Event gebucht, Szenario `parallel-fork` | Die AUSWERTUNG des Security Events durch eine Administrationsrolle bleibt Stufe 5; die organisationsweite Aufloesung eines Forks ueber Geraetegrenzen hinweg ebenfalls |
| AK 8 | Replay | `apps/server/tests/entry_commit_api.rs::identical_replay_returns_byte_identical_receipt_bytes`; `crates/ea-sync-server/tests/commit_service.rs::identical_replay_returns_same_receipt_bytes`; `apps/server/tests/entry_commit_api.rs::the_receipt_discarded_by_a_replay_stays_an_invisible_orphan`, Szenario `response-loss` | Der Kehraus der unsichtbaren Waisen (Orphan-Akkumulation) hat einen Klassifizierer und keinen Sweeper; er bleibt Stufe 7 |
| AK 13 | Server kompromittiert | `apps/server/tests/privacy_canaries_server.rs`; `apps/server/tests/vault_blob_api.rs`; der Server haelt weder Reader- noch Recovery-Schluessel, und die wrapped Vault-Blobs sind ohne WebAuthn-Assertion und ohne PRF-Ausgabe wertlos | Der Nachweis gegen ein Releasepaket mit abgeschalteter Telemetrie bleibt Stufe 7; die Lesesicht eines berechtigten Readers entsteht in Stufe 4 |
| AK 33 | Unteilbarer Entry-Commit | `apps/server/tests/entry_commit_api.rs::a_complete_commit_is_accepted_and_becomes_visible_together`; `crates/ea-sync-server/tests/commit_service.rs::exact_active_recipient_set_is_atomic`; `apps/server/tests/commit_failures.rs::an_incomplete_recipient_set_is_refused_atomically` | Die Wahl des hoechsten serverbekannten anwendbaren Registry-Kopfes (AK 35, AK 49) wird hier GEBAUT, aber von Stufe 5 beansprucht; siehe `## Serverhaelften fremder Stufen` |
| AK 36 | Server-Teilfehler | `crates/ea-sync-server/tests/commit_service.rs::a_database_abort_leaves_nothing_visible`; `::an_object_store_fault_before_the_commit_leaves_nothing_visible`; `::an_object_store_fault_after_the_commit_withholds_the_receipt`; `::a_receipt_that_does_not_read_back_is_never_delivered`; die vier Szenarien des Abschnitts `commit` in `docs/traceability/stage-3-fault-points.json` | Der Nachweis auf echter Hardware und gegen eine andere als die hier gemessene Auflegung bleibt Stufe 7 |
| AK 45 | Sync-Server-Administration | `apps/server/src/admin_audit.rs::server_admin_configuration_has_no_content_or_grant_authority` (`ServerAdminConfig::schema_capabilities()` ist GENAU `serverReceipt`); `::the_subject_key_carries_only_technical_characters`; `ops/container/Dockerfile`; `ops/monitoring/metrics.md`; `apps/server/tests/backup_restore_server_restore.rs` | Die Administrationsflaeche selbst — Anmeldung, Konfigurationsdialog, Rollenverwaltung — ist Stufe 5. Die produktionsreife Sicherung, das signierte Bild und der Plattformnachweis sind Stufe 7. `ops/monitoring/metrics.md` ist eine VORABFESTLEGUNG des Labelsatzes; eine laufende Metrikflaeche gibt es in dieser Stufe nicht. UND: das Auditmodul hat in dieser Stufe KEINEN Schreiber — nichts konstruiert `AdminAuditRecordV1`, nichts schreibt in `technical_admin_audit`; die Schreiber entstehen mit den Stufe-5-Administrationsflaechen (Abschnitt 5.2). Die Zeile steht deshalb auf `implemented`, nicht auf `integrated` |
| AK 50 | Receipt-Fristanker | `crates/ea-sync-server/tests/receipt_golden.rs::evidence_due_time_is_signed_once_from_receipt_policy`; `::the_built_receipt_is_byte_identical_to_the_frozen_vector`; `::an_overflowing_evidence_delay_is_rejected_instead_of_saturated` | Die Einloesung der Frist — der Evidence-Grade-Nachweis selbst — ist Stufe 6 |

### 1.1 Teilbelege dieser Stufe

Zwei Kriterien bekommen in dieser Stufe einen TEILbeleg. Ihre vollen Zeilen
behalten `stage=7`; die Teilzeilen stehen als eigene `v1.1`-Ledgerzeilen, nach
dem Muster, das die Stufe 2 fuer AK-19, AK-24, AK-29 und AK-53 bereits
verwendet.

| Teilbeitrag | Gegenstand | Stufe-3-Anteil | Wo das Kriterium faellig wird |
|---|---|---|---|
| Teilbeleg AK 19 | Keine Klartextlogs (Server) | `apps/server/tests/privacy_canaries_server.rs` ueber Logs, Fehlerkoerper, PostgreSQL-Werte, S3-Schluessel/Tags/Metadaten, den Labelsatz aus `ops/monitoring/metrics.md` und die Containerausgabe | Stufe 7 — der Nachweis ueber ein Releasepaket mit abgeschalteten Absturzberichten und abgeschalteter Telemetrie |
| Teilbeleg AK 21 | Backup-Restore (Server-Restore) | `apps/server/tests/backup_restore_server_restore.rs` — PostgreSQL und Bucket in einen GETRENNTEN Integrationsnamensraum zurueckgespielt, exakte Objektmenge und exakter Kopf gegen einen bekannten Checkpoint | Stufe 7 — die produktionsreife Sicherung samt Aufbewahrungsfristen und Wiederanlaufzeit |

## 2. Reichweite der Stufe-3-Abnahme

Stufe 3 belegt ihre Serverabnahme ausschliesslich gegen die zwei Integrationsdienste der Auflegung A, gestartet ueber cargo run --locked -p xtask -- integration up: postgres:18.6-bookworm@sha256:1c59e2c3c818eaa0f0628f695b36e7c9e362d6b219b36a54a32df645cbd7e1af und minio/minio:RELEASE.2025-09-07T16-13-09Z@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e. Ein Betrieb gegen ein anderes PostgreSQL, einen anderen S3-kompatiblen Dienst oder eine verwaltete Auflegung ist damit NICHT belegt und bleibt Stufe 7.

### 2.1 Die Migrationsreservierung

`apps/server/migrations/` traegt GENAU EINE Migration, und
`apps/server/tests/migrations.rs::the_single_migration_creates_every_planned_table`
haelt das fest. Die Fortschreibung des Schemas gegen eine BEREITS
AUSGELIEFERTE Installation — Migrationsevolution, Rueckwaertsvertraeglichkeit,
Wiederanlauf nach einer halb angewandten Migration — ist ausdruecklich Stufe 7
und in dieser Stufe weder gebaut noch behauptet.

Eine Folge davon steht im Administrationsaudit: `technical_admin_audit` fuehrt
genau eine technische Spalte (`subject_key`), also setzt
`AdminAuditRecordV1::subject_key()` Geraetepseudonym, Ergebnis und Objekthash
zu einer kanonischen technischen Zeichenkette zusammen, statt drei Spalten zu
verlangen, die diese Stufe nicht mehr anlegen darf.

### 2.2 Der OCI-Basisdigest, woertlich

`ops/container/Dockerfile` pinnt das Laufzeitbild auf den Digest, den
`docs/adr/0004-server-runtime-and-dependency-class.md`, Abschnitt
`OCI base image`, festhaelt:

```text
gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
```

Gemessen am 2026-08-30: dieser Digest ist ein Multi-Arch-INDEX ueber fuenf
Plattformen (`amd64`, `arm64/v8`, `arm/v7`, `s390x`, `ppc64le`). Ohne eine
Plattformangabe waehlte der Bau die Architektur des Bauwirts; das Dockerfile
setzt deshalb `--platform=${BUILD_PLATFORM}` mit der Vorgabe `linux/amd64` an
beiden Stufen.

Der Builder traegt die Toolchain aus `rust-toolchain.toml` bereits im Bild —
`docker.io/library/rust:1.95.0-bookworm@sha256:4c2fd73ef19c5ef9d54bee03b06b2839a392604fbfcd578ed948b71b37c1d7fb`,
der amd64-Manifestdigest, aufgeloest am 2026-08-30. Damit erzeugt kein
zweiter, ungepinnter Compiler Produktionsbytes.

WAS HIER NICHT GESCHEHEN IST: das Bild wurde auf diesem Wirt NICHT gebaut. Ein
vollstaendiger Release-Bau des Arbeitsbereichs im Container ueberschreitet die
Kommandodecke dieses Tasks. Gemessen wurde stattdessen der BauEINGABE-Vertrag:
`docker build --check --platform=linux/amd64 -f ops/container/Dockerfile .`
endet mit Exitcode 0 und der Zeile `Check complete, no warnings found.`
(BuildKit-Linter, Docker-CLI 29.7.2 / Engine 29.4.0). `hadolint` ist auf
diesem Wirt nicht installiert und wurde nicht ausgefuehrt. Der signierte,
reproduzierbare Bau und der Plattformnachweis schliessen in Stufe 7.

### 2.3 Auflegung A und ihre Folge fuer fremde Stufen

`apps/server` ist ab dieser Stufe ein Mitglied des Arbeitsbereichs. Damit
zieht `cargo test --workspace --all-targets --locked` — und ueber
`verify_quick_commands()` also `pnpm verify:quick` — die Serverintegrationsziele
mit, und die brauchen die zwei laufenden Dienste. Die Erreichbarkeitspruefung
ist fail-closed und kennt keine Umgehung ueber eine Umgebungsvariable.

Dieselbe Bindung gilt fuer die zwei Nachweisziele dieser Stufe:
`apps/server/tests/privacy_canaries_server.rs` und
`apps/server/tests/backup_restore_server_restore.rs` fahren gegen die
laufenden Dienste der Auflegung A und sind ohne sie nicht ausfuehrbar — ein
nicht durchfuehrbarer Test ist ein nicht bestandener Test, und eine Umgehung
ueber eine Umgebungsvariable existiert nicht. Die drei Stufengates selbst
brauchen sie NICHT (Abschnitt (b) unter dem gemessenen Lauf).

Das ist eine benannte Folge und kein weggelegter Fremdstufenmangel: die
Gate-Laeufe der Stufen 4 und 6 treiben `pnpm verify:quick` heute blank
(`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-4-reader.md:537`,
`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-6-evidence-grade.md:409`).
Beide Stufen MUESSEN ihrem Lauf `cargo run --locked -p xtask -- integration up`
voranstellen, sonst ist ihr `verify:quick` fail-closed rot. Diese Stufe traegt
den Befund ein; sie repariert die beiden fremden Plaene nicht.

Ein zweiter Marker derselben Art, hier festgehalten und hier NICHT aufgeloest:
`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-7-release-hardening.md:43`
will `docs/adr/0002-support-matrix-signature.md` anlegen, obwohl `0002` von
`docs/adr/0002-local-database-encryption.md` belegt und durch `ADR_PATH` in
`tools/xtask/tests/adr_gate.rs` hart gepinnt ist. Ein eigenstaendiger Mangel
jenes Plans.

## 3. Fehlermatrix und deklarierte Szenarien

`docs/traceability/stage-3-fault-points.json` deklariert NEUN Szenarien in
VIER Abschnitten. Der Gate liest die Deklaration; die Tabelle unten nennt zu
jedem Szenario den Zeugen, der es wirklich faehrt.

### 3.1 Abschnitt `commit` — vier Szenarien

| Szenario | Geklammerter dauerhafter Schritt | Zeuge |
|---|---|---|
| `db-before-commit` | vor dem Buchen der Commit-Transaktion; nichts wird sichtbar, und der Abbruch ist keine Aussage ueber den Aufrufer (`503`, retryable, kein Security Event) | `crates/ea-sync-server/tests/commit_service.rs::a_database_abort_leaves_nothing_visible` |
| `db-after-object-put` | nach dem Ablegen eines Objekts unter seiner content-addressed Adresse und vor dem Sichtbarwerden der Transaktion; das Objekt bleibt ein unsichtbarer Waise | `apps/server/tests/entry_commit_api.rs::the_receipt_discarded_by_a_replay_stays_an_invisible_orphan` |
| `s3-stage` | waehrend des Stagings der Objekte, vor der Commit-Transaktion | `crates/ea-sync-server/tests/commit_service.rs::an_object_store_fault_before_the_commit_leaves_nothing_visible` |
| `response-loss` | nach dem sichtbaren Commit und vor dem Eintreffen der Quittung beim Klienten; der Wiederholversuch liefert BYTEGLEICH dieselbe Quittung | `apps/server/tests/entry_commit_api.rs::identical_replay_returns_byte_identical_receipt_bytes` |

### 3.2 Abschnitt `replay` — zwei Szenarien

| Szenario | Geklammerter dauerhafter Schritt | Zeuge |
|---|---|---|
| `parallel-fork` | zwei Commits auf derselben Sequenz derselben Kette; der zweite wird abgewiesen und als Security Event gebucht | `apps/server/tests/commit_failures.rs::a_fork_on_the_same_sequence_is_refused_and_recorded` |
| `nonce-replay` | derselbe Antrag mit derselben verbrauchten Challenge ein zweites Mal; `EA-AUTH-NONCE-REPLAY` und `401` | `apps/server/tests/auth_trust_api.rs::challenge_is_single_use_and_registration_remains_pending` |

### 3.3 Abschnitt `transport` — zwei Szenarien

| Szenario | Geklammerter dauerhafter Schritt | Zeuge |
|---|---|---|
| `tls-downgrade` | ein ClientHello, der ausschliesslich TLS 1.2 anbietet; der Lauscher weist ab und handelt NIE herunter | `apps/server/tests/fault_scenarios.rs::a_tls12_only_client_handshake_is_rejected`, mit `::the_same_listener_completes_a_tls13_handshake` als Positivkontrolle |
| `cursor-key-rotation` | ein technischer Cursor der VORIGEN Serverschluesselgeneration nach der Rotation | `apps/server/tests/fault_scenarios.rs::a_cursor_signed_under_the_previous_key_generation_fails_to_open` |

Die Rotationsentscheidung ist AUSGESCHRIEBEN und nicht offen: von den zwei
zulaessigen Verhalten ist FAIL-CLOSED gebaut. Ein `TechnicalCursorV1`, der
unter der vorigen Generation ausgestellt wurde, oeffnet nach der Rotation
nicht mehr, und der Befund ist der stabile Code `EA-SYNC-CURSOR-INVALID`. Es
gibt KEINE ueberlappende Annahme zweier Generationen. Der Code verraet dem
Klienten nichts ueber die Rotation — er soll den Cursor ohnehin nicht deuten
—, und der Klient blaettert von einem frischen Cursor neu an, ohne Luecke in
der Batchfolge: die Positivkontrolle im selben Test belegt, dass derselbe
Cursor unter DERSELBEN Generation oeffnet und seinen `last_technical_index`
unveraendert herausgibt.

### 3.4 Abschnitt `restore` — ein Szenario

| Szenario | Geklammerter dauerhafter Schritt | Zeuge |
|---|---|---|
| `restore` | PostgreSQL und Bucket in einen getrennten Integrationsnamensraum zurueckgespielt; exakte Objektmenge und exakter Kopf gegen einen bekannten Checkpoint | `apps/server/tests/backup_restore_server_restore.rs` |

EIN Abschnitt mit genau einem Eintrag ist Absicht und kein Versehen: der
Rueckspielnachweis hat in dieser Stufe kein Geschwister.

## 4. Entscheidungen dieser Stufe

Die Entscheidungen, an denen der Plan und die Normativquellen auseinandergingen
oder an denen die Stufe eine Wahl getroffen hat. Jede steht mit ihrer Quelle,
damit eine spaetere Stufe sie wiederfindet statt sie neu zu treffen.

- **`evidence_due_at` ist nullable.** Der Spec (`design.md`:929, :1699) laesst
  die Frist offen, wo die Richtlinie keine setzt; die Quittung traegt das Feld
  dann leer statt eine Frist zu erfinden.
- **Das `.eip` eines Vernichtungsziels bleibt lesbar.** Blockiert wird die
  GRANT-Auslieferung, nicht das Objekt. Einen `.eds`-Stummel gibt es in Stufe 3
  ausdruecklich nicht.
- **`reader_vault_blobs.organization_id`** folgt dem Spec und nicht dem
  Planwortlaut.
- **WebAuthn-Credentials sind EdDSA-only.** Weder §6.4.1 noch der
  Sync-Wire-Nachtrag nennen einen Algorithmus; die Registrierung weist andere
  mit einem stabilen Code ab. Ein Stufe-4-Vorbehalt steht im Nachtrag.
- **Die `grantAuthorization` wird an `POST /v1/trust/events` ANGENOMMEN** —
  als Katalogstoff, der keine Autoritaet traegt: geprueft werden
  Organisationsbindung, der gebundene Registry-Kopf, die Frist und ZWEI
  UNTERSCHIEDLICHE `historicalGrantApprove`-Approver, alles ueber die geteilten
  `ea-crypto`-Kontexte (`crates/ea-trust/src/admission.rs`). Ohne diesen Weg
  waere `POST /v1/entries/{entryHash}/historical-grants` gegen einen echten
  Server unerreichbar: der Endpunkt loest die Autorisierung content-addressed
  auf und nimmt sie nicht entgegen.
- **Fuenf Trust-Subtypen bleiben an `POST /v1/trust/events` abgewiesen**
  (`EA-TRUST-EVENT-UNVERIFIABLE`), weil `ea-trust` fuer sie im
  Registrierungsabschluss keine Signiererregel fuehrt:
  `destructionAuthorization`, `destructionTransition`, `deletionAttestation`,
  `webBundleRelease` und `webBundleRevocation`. Die drei Vernichtungsarten
  reisen ueber `POST /v1/destructions`; die beiden Bundle-Arten haben in dieser
  Stufe ueberhaupt keinen Aufnahmeendpunkt — sie sind hier NUR als Format
  definiert (Abschnitt „Serverhaelften fremder Stufen").
- **Der Registry-Kopf eines Commits ist verpflichtend, wenn der Server einen
  neueren kennt** — `EA-COMMIT-REGISTRY-HEAD-REQUIRED`. Ein gebundener
  aelterer Kopf zeigt nie rueckwaerts.
- **Die Ratenbegrenzung rechnet mit dem Peer-IP-Digest**, nicht mit der
  Adresse (Sync-Wire-Nachtrag, Abschnitt „Identitaet der Ratenbegrenzung").
- **Die Cursorrotation ist fail-closed** (Abschnitt 3.3).
- **`ServerAdminConfig::schema_capabilities()` ist GENAU `serverReceipt`.**
  Keine parallele Faehigkeitsaufzaehlung in `apps/server` oder
  `crates/ea-sync-server`; `CertificateCapability` bleibt auf sieben Varianten
  geschlossen, und die Zweckbindung des technischen Cursors laeuft ueber eine
  additive Domaenenzeichenkette statt ueber eine achte Variante.
- **Die zwei neuen Nachweisziele liegen in `apps/server/tests/` und nicht in
  `tests/ea-system-tests/tests/`.** Abweichung von den Dateipfaden des Plans,
  gemessen begruendet: beide Ziele brauchen einen ANGENOMMENEN Commit gegen den
  echten Server, und der einzige Weg dorthin ist `apps/server/tests/common/`
  (`trust_closure.rs`, `archive_objects.rs`) — ein `mod common;` INNERHALB
  eines Integrationstestziels, von einem anderen Paket aus nicht erreichbar.
  `apps/server/tests/writer_sync_e2e.rs` schreibt in seiner Kopfnote aus, warum
  nichts anderes traegt: die Stufe-2-Writer-Fixture steht auf dem
  Genesis-Eintrag der Sequenz null, deren Kopf kein Schreiberzertifikat traegt.
  Der Weg ueber `tests/ea-system-tests/` haette sechs Abhaengigkeitskanten
  gekostet — und JEDE neue Kante dort bricht `--locked`, weil `Cargo.lock` die
  Kantenliste je Pfadmitglied fuehrt (gemessen: `cargo metadata --locked` endet
  mit 101). Der gewaehlte Weg kostet keine Abhaengigkeit, keine
  `Cargo.lock`-Aenderung und kein Kommando ohne `--locked`. Die zwei Ziele
  tragen ihre EIGENEN Kommandos der Schritt-4-Folge und stehen NICHT in
  `test:server`, das damit exakt VIERZEHN Ziele fuehrt.
- **Der Stufenschalter brauchte eine Testreparatur.** Der Plan sagt, er oeffne
  „ohne Testreparatur". Gemessen falsch:
  `tools/xtask/tests/stage_gate.rs::the_stage_switch_still_refuses_an_undefined_stage`
  hielt das Literal `"stages 1 and 2"` und trieb Stufe `"3"`. Er treibt jetzt
  Stufe `"4"` und erwartet `"stages 1, 2 and 3"` — dieselbe Zusicherung, eine
  Stufe weiter: eine undefinierte Stufe wird abgewiesen, und die Fehlerzeile
  nennt die definierten.
- **`STAGE_THREE_GATE_REPORT_SECTIONS` fuehrt ACHT Abschnitte, nicht fuenf.**
  Fuenf ist die Stelligkeit des Stufe-2-VORBILDS. Die drei weiteren sind die
  Abschnitte mit den geprueften Negativen, die der Plan ausdruecklich GETRENNT
  verlangt. Ein Abschnitt, den kein Gate haelt, verschwindet in der naechsten
  Stufe still.
- **Der Stufe-3-Gate-Bericht ist umlautfrei.** Beide bereits geschlossenen
  Gate-Berichte fuehren zusammen NULL Umlaute (gemessen), und der Gate
  vergleicht Literale; eine Ueberschrift mit Umlaut hier und ohne Umlaut in der
  Gate-Quelle waere ein Mangel ohne Sache. Die Abschnittsnamen
  `## Serverhaelften fremder Stufen` und `## Nicht beruehrte Nachbarzeilen`
  stehen deshalb in der Umschrift.

## 5. Blindheit des Servers, Administrationstrennung und Kanarienvoegel

### 5.1 Was der Server nicht kann

Die drei Verbote — nicht entschluesseln, nicht als Writer signieren, nicht als
Registry autorisieren — stehen nicht als eigene Aufzaehlungsvarianten da,
sondern als ABWESENHEIT jeder Grant- und Signaturfaehigkeit plus einer
schliessenden Gleichheit: `ServerAdminConfig::schema_capabilities()` ist
`[serverReceipt]` und nichts sonst. `CertificateCapability` ist auf sieben
Varianten geschlossen (`initialGrant`, `historicalGrant`,
`organizationAdminApprove`, `historicalGrantApprove`, `destructionApprove`,
`serverReceipt`, `deletionAttest`), und keine achte entsteht.

Dazu kommt eine vierte Grenze, und sie ist eine Einschraenkung und kein
Verbot: **der Server nimmt keinen Eintrag NACH einem Schreiberwechsel an.**
`crates/ea-sync-server/src/validation.rs` weist einen Commit, dessen Manifest
einen `writerTransitionEventHash` nennt, fail-closed mit
`EA-COMMIT-WRITER-TRANSITION` (422) ab. Der Grund ist Zurueckhaltung und nicht
Nachlaessigkeit: `ea-trust` gibt die wirksamen Schreiberwechsel heute nicht
heraus, `crates/ea-verify/src/entry.rs` zieht an derselben Stelle dieselbe
Grenze, und eine hier erfundene zweite Aufloesung waere genau die zweite
Umsetzung, die es nicht geben darf. Eine Kette, deren Schreiber gewechselt
hat, laesst sich in Stufe 3 also nicht fortschreiben. Gehoben wird das mit der
Administration und der Schreiberrotation in **Stufe 5**.

### 5.2 Das privilegierte Administrationsaudit

`apps/server/src/admin_audit.rs` gibt der Tabelle `technical_admin_audit` ihre
typisierte Flaeche: pseudonymer Handelnder, pseudonymes Geraet, geschlossener
Handlungscode (acht `EA-ADMIN-`-Codes), geschlossenes technisches Ergebnis,
Zeit und HOECHSTENS ein Objekthash. Ein Freitextfeld gibt es nicht, und es
gibt keinen Konstruktor, der eines annehmen koennte.

OFFENLEGUNG, in derselben Form wie die zu `ops/monitoring/metrics.md` in
Abschnitt 5.3: Modul und Tabelle EXISTIEREN und sind bezeugt, aber KEIN
privilegierter Pfad der Stufe 3 schreibt eine Zeile. Nichts konstruiert
`AdminAuditRecordV1`, und nichts schreibt in `technical_admin_audit`. Der
Grund ist keine Luecke, sondern die Stufenteilung: die schreibenden Flaechen —
privilegierte Anmeldung, Konfigurationsdialog, Rollenverwaltung,
Schluesselrotation — sind Stufe 5, die Sicherung ist Stufe 7. Was diese Stufe
belegt, ist die FORM, in der spaeter geschrieben wird, und die Grenze, die
dabei nicht ueberschritten werden kann. Genau deshalb steht die Ledgerzeile
`AK-45` auf `implemented` und NICHT auf `integrated`.

### 5.3 Der Labelsatz

`ops/monitoring/metrics.md` legt den Labelsatz NORMATIV fest, bevor eine
Metrikflaeche existiert: ein Label traegt ausschliesslich einen Wert aus einer
im Voraus aufgezaehlten, geschlossenen Menge, und ein Wert aus einer Anfrage
ist niemals ein Label. `apps/server/tests/privacy_canaries_server.rs`
sucht die Kanarienvoegel auch gegen diese Tabelle.

### 5.4 Das Ergebnis der Kanarienvoegel

`apps/server/tests/privacy_canaries_server.rs` saet je fachlichem
Feld GENAU EINEN Marker, treibt einen vollstaendigen Push ueber den echten
Sync-Weg und sucht danach jeden Marker durch Logs, Fehlerkoerper,
PostgreSQL-Werte, S3-Schluessel, S3-Tags, S3-Metadaten, den Labelsatz und die
Containerausgabe. Kein Marker wurde gefunden. Die Gegenkontrolle im selben
Ziel belegt, dass die Suche einen wirklich vorhandenen Marker findet — ohne
sie waere die Abwesenheitszusage auch dann gruen, wenn die Stromsammlung leer
liefe.

## Endpunkt- und Signaturabdeckung

Drei GEMESSENE Aussagen. Sie stehen als eigener Abschnitt, damit ihr Schweigen
nicht als „nicht geprueft" gelesen wird.

**(a) Die Endpunktliste ist byteidentisch.** Die Liste dieses Plans
(`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-3-blind-sync.md`:42-58)
und `design.md` §13.2 (:1516-1532) tragen SIEBZEHN Zeilen auf jeder Seite, und
`diff` ueber die beiden Ausschnitte erzeugt KEINE Ausgabe. Gemessen am
2026-08-30.

**(b) Die Signaturabdeckung deckt sich Position fuer Position.** `design.md`
:1501-1507 fuehrt sieben Positionen — `@method`, `@authority`, `@target-uri`,
`content-type` bei vorhandenem Body, RFC-9530-`content-digest` bei vorhandenem
Body, eindeutige Request-ID und die Menge `created`/`expires`/`nonce`/`keyid`/
`alg=ed25519`/organisationsgebundenes `tag`. Der Plan (:61) nennt genau diese
sieben, keine fehlt und keine kommt hinzu.

**(c) Die drei Endpunkte dieser Stufe stehen bereits in §13.2.**
`POST /v1/webauthn-credentials`, `PUT /v1/vault-blobs` und
`POST /v1/vault-blobs/retrievals` sind exakt die drei, die §13.2 schon fuehrt.
Der Gate misst hier eine Gleichheit NACH, die bereits gilt, statt sie
herzustellen.

Kostennotiz, gemessen: KEIN Test, KEIN Schema und KEIN Code pinnt eine der
siebzehn Pfadzeilen — §13.2 traegt keine schliessende Klausel. Die drei neuen
Endpunkte kosten deshalb genau die zwei Dokumentseiten und nichts weiter.

## Serverhaelften fremder Stufen

Drei Ledgerzeilen, deren SERVERhaelfte in dieser Stufe entsteht und die diese
Stufe ausdruecklich NICHT beansprucht. Ihre Stufenspalten bleiben unveraendert.
Der Zweck dieses Abschnitts ist allein, dass die Stufen 4 und 5 die Serverseite
bereits gebaut vorfinden.

| Ledgerzeile | Wo sie entsteht | Was diese Stufe davon gebaut hat | Stufenspalte |
|---|---|---|---|
| AK-35 (`design.md`:2151) | Task „Atomic Entry Commit, Idempotent Replay, and Immutable Receipts" | Die Wahl des hoechsten serverbekannten anwendbaren Registry-Kopfes und die Abweisung eines gebundenen aelteren Kopfes; Zeuge `apps/server/tests/commit_failures.rs::a_package_binding_an_older_head_names_the_required_head` und `crates/ea-sync-server/tests/commit_service.rs::a_pending_future_head_names_the_required_registry_version` | `stage=5`, UNVERAENDERT |
| AK-49 (`design.md`:2165) | dieselbe Task | dieselbe Serverhaelfte; zusaetzlich `crates/ea-sync-server/tests/commit_service.rs::a_bound_head_newer_than_the_server_knows_never_points_backwards` beziehungsweise `apps/server/tests/commit_failures.rs::a_bound_head_newer_than_the_server_knows_never_points_backwards` | `stage=5`, UNVERAENDERT |
| AK-43 (`design.md`:2159) | Task „Reader, Object, Export, Historical-Grant, and Destruction API Surfaces" | Die Serverhaelfte der Leseflaechen: `apps/server/tests/read_apis.rs`, `apps/server/tests/export_api.rs`, `apps/server/tests/historical_grant_api.rs`, `apps/server/tests/destruction_api.rs` | `stage=4`, UNVERAENDERT |

## Nicht beruehrte Nachbarzeilen

FR-100 („Desktop fuer Writer und Administration, Browser-Reader, signierte
Rollentrennung") und FR-103 („Reader-Index als Ganzes mit ChaCha20-Poly1305
verschluesselt in OPFS statt SQLCipher") tragen `stage=4` und
`status=planned`. Beide sind GEPRUEFT und von dieser Stufe NICHT beruehrt:
Rollenaufteilung und Indexablage sind Readerflaeche.

Abgrenzung in demselben Abschnitt: die drei WR-Zeilen aus derselben
Stufe-1-Entscheidung — WR-041, WR-042 und WR-043 — sind Stufe-3-Zeilen
GEWESEN und werden von der Ledgerbewegung dieses Tasks bewegt, nicht durch
Schweigen. Alle drei sind browserseitig (getrennter Auslieferungsursprung,
web-reader-design.md:72; Service-Worker-Aktivierung gegen ein gepinntes
Release, :84; erzwungener Fingerprint-Vergleich, :117), und ihr Bauartefakt
`apps/web` fuehrt web-reader-design.md Abschnitt 12 (:467-469) ein. Sie wandern
deshalb auf `stage=4` und behalten `planned`.

Die FAMILIENDEFINITION der Trust-Objektfamilie `webBundleRelease` dagegen
liefert DIESE Stufe — Codec, CDDL-Arme und Signaturprofil, dauerhaft
eingefroren unter `vectors/web-bundle/v1/` —, und dafuer entsteht genau
eine neue Zeile: `WR-042D`, `v1.1`, Quellspalte auf `4.2` endend, `stage=3`,
`status=implemented`, Beleg `crates/ea-format/tests/web_bundle_release.rs` und
`vectors/web-bundle/v1/`. Das Schema `WR-0<Abschnitt>` kann fuer Abschnitt 4.2
keine zweite Zeile ausdruecken, deshalb traegt sie ausdruecklich einen
Identifikator AUSSERHALB des Schemas.

WR-042 bekommt in derselben Bewegung seine Belegspalte korrigiert,
unabhaengig vom Split: sie zitierte eine Task DIESES Plans, die es nicht gibt.
Das Traegerfeld `reader-trust-refresh-ms` existiert nach Entscheidung D2 in
`policy-core-v1` und ist bereits in Stufe 1 POSITIV eingefroren — die beiden
angenommenen Vektoren
`vectors/trust/v1/object/accepted-policy-core-reader-trust-refresh-set/` und
`vectors/trust/v1/object/accepted-policy-core-reader-trust-refresh-disabled/`,
je ein Verzeichnis mit genau einer `policy.bin`, gepinnt gegen die CDDL durch
`tools/xtask/tests/spec_completeness.rs::trust_cddl_enforces_the_exact_twenty_two_positions_of_policy_core_v1`.
Die Stufe-3-Zusage der Zeile schrumpft damit auf das, was wirklich offen ist:
die Service-Worker-Pinnung, und die wandert mit dem Split auf Stufe 4. Der Pin
wandert MIT dem Ledger in demselben Commit: in
`web_reader_must_requirements_are_recorded_as_v1_1_rows` verlangt die
`refresh`-Zusicherung nicht mehr `contains("Task 10")`, sondern
`contains("accepted-policy-core-reader-trust-refresh")`.

`WEB_READER_MUST_ROWS` geht in demselben Commit von ACHT auf NEUN Tupel, und
die Verschiebung steht im Dokumentkommentar der Konstante ausgeschrieben, nach
dem Muster der dort bereits stehenden Entscheidung D-HE2. Die geschlossenen
Gate-Berichte der Stufen 1 und 2 werden dafuer NICHT angefasst;
`docs/traceability/stage-2-gate.md:348` traegt diesen Mechanismus als
Praezedenz.

### Der Eintragszahl-Pin der Familie `trust/v1`

Die Familie `trust/v1` traegt ab dieser Stufe einen Eintragszahl-Pin (130).
Damit gilt die Zusage aus `docs/traceability/stage-1-gate.md`:116-121 fuer alle
fuenf eingefrorenen Familien ausfuehrbar und nicht nur als Prosa. Der Grund
liegt in dieser Stufe: sie verpflichtet sich auf die Unveraenderlichkeit genau
dieser Bytes und baut mit `GET /v1/trust/registry` und
`POST /v1/trust/events` die erste Verteilflaeche fuer sie.

## Gemessener Gate-Lauf

Der vollstaendige Lauf nach Schritt 4 des Stufe-3-Plans
(`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-3-blind-sync.md`), in
der hier protokollierten Reihenfolge ausgefuehrt am 2026-08-30 auf dem Zweig
`worktree-drk-208-stufe-3`. Jedes Kommando lief mit
`RUSTUP_TOOLCHAIN=1.95.0`, weil die Shell die Variable sonst auf eine neuere
Toolchain setzt und damit den Pin aus `rust-toolchain.toml` uebersteuern
wuerde. Die Zahlen sind abgelesen, nicht geschaetzt: `0 passed; N filtered out`
waere kein Ergebnis, sondern ein defekter Filter, und kommt in keiner Zeile
vor.

Die Serverziele brauchen die zwei Dienste der Auflegung A UND ihre zwei
Umgebungswerte; der Lauf exportierte `DATABASE_URL` und
`EA_OBJECT_STORE_ENDPOINT` genau so, wie `integration up` sie druckt. Dieser
Task ist der einzige der Stufe, der `integration down` faehrt, und die letzte
Zeile haelt das fest.

| Kommando | Exitcode | Gemessenes Ergebnis | Laufzeit |
|---|---|---|---|
| `cargo run --locked -p xtask -- integration up` | 0 | beide Dienste gesund; Bucket `einsatzarchiv-objects` angelegt und versioniert; die zwei `export`-Zeilen `DATABASE_URL` und `EA_OBJECT_STORE_ENDPOINT` gedruckt | 14 s |
| `pnpm test:server` | 0 | 14 Integrationsziele, 115 bestanden, 0 fehlgeschlagen, 0 ignoriert, 0 gefiltert | 133 s |
| `cargo test --locked -p einsatzarchiv-server --test privacy_canaries_server` | 0 | 4 bestanden, 0 fehlgeschlagen, 0 ignoriert, 0 gefiltert; kein Kanarienvogel auf einer serverbeobachtbaren Flaeche, und die drei Positivkontrollen greifen | 11 s |
| `cargo test --locked -p einsatzarchiv-server --test backup_restore_server_restore` | 0 | 1 bestanden, 0 fehlgeschlagen, 0 ignoriert, 0 gefiltert; exakte Objektmenge, byteidentische Objekte und identischer Kettenkopf im getrennten Namensraum | 15 s |
| `pnpm supply-chain` | 0 | `advisories ok, bans ok, licenses ok, sources ok`; kein einziges `error[...]`; 40 `duplicate`-Warnungen, die `multiple-versions = warn` bewusst nur warnt; KEINE einzige `license-exception-not-encountered`-Warnung; `cargo-deny 0.20.2` | 4 s |
| `pnpm stage-gate:3` | 0 | JSON auf stdout: 9 deklarierte Szenarien, 154 Ledgerzeilen, `stage_three_rows_still_planned` leer, `vector_families` = `[web-bundle]`, `stage_three_primary_acceptance_criteria` = `[7, 8, 13, 33, 36, 45, 50]` | 1 s |
| `pnpm verify:quick` | 0 | ACHT Teilkommandos gruen, in dieser Reihenfolge: `cargo fmt --all --check`; `pnpm --dir apps/desktop build`; `pnpm desktop:typecheck` (`tsc --noEmit` ohne eine einzige Diagnose); `pnpm desktop:test` (10 Testdateien, 92 Tests bestanden); `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` ohne eine einzige Warnung; `cargo test --workspace --all-targets --locked`; `cargo test --workspace --doc --all-features --locked`; und der wasm32-Check ueber die ZEHN Pakete der Positivliste. Ueber beide `cargo test`-Teilkommandos ZUSAMMENGEZAEHLT: 190 Ergebniszeilen, 1365 bestanden, 0 fehlgeschlagen, 7 ignoriert, 0 gefiltert. Die Aufteilung in Testbinaries und Doctest-Ziele, die der Stufe-2-Bericht getrennt ausweist, ist hier NICHT angegeben: der `verify-quick`-Treiber reicht die `Running <ziel>`- und `Doc-tests`-Zeilen von cargo nicht durch, und die Trennung war aus dem Lauf nicht rekonstruierbar. Eine erfundene Aufteilung waere schlechter als diese Offenlegung. Gemessen auf WARMEM `target/` — der Lauf folgt unmittelbar auf die sechs Kommandos darueber, die denselben Baum uebersetzt haben; ein kalter `target/` liegt deutlich darueber und ist hier NICHT gemessen | 562 s |
| `cargo run --locked -p xtask -- integration down` | 0 | beide Container angehalten und entfernt, die zwei benannten Volumes mit `--volumes` abgeraeumt | 6 s |

### (a) Die Lizenzentscheidung zu jeder benannten Ausnahme in `deny.toml`

`deny.toml` schreibt vor, dass die Entscheidung an dieser Stelle faellt. Sie
faellt hier, und sie faellt fuer JEDE der vierzehn benannten Ausnahmen, mit
der gemessenen Aussage, ob die Crate am Kopf dieser Stufe im Graphen liegt:

| Ausnahme | Lizenz | Entscheidung | Am Kopf angetroffen |
|---|---|---|---|
| `base16` | `CC0-1.0` | Public-Domain-Widmung, keine Copyleft-Wirkung | ja |
| `hexf-parse` | `CC0-1.0` | dieselbe Begruendung | ja |
| `borrow-or-share` | `MIT-0` | MIT ohne Namensnennungspflicht | ja |
| `foldhash` | `Zlib` | permissiv | ja |
| `target-lexicon` | `Apache-2.0 WITH LLVM-exception` | permissiver als Apache-2.0 allein | ja |
| `cssparser` | `MPL-2.0` | DATEIWEISES Copyleft; kommt unveraendert und ausschliesslich als Abhaengigkeit des Tauri-Teilbaums, keine Offenlegungspflicht fuer eigenen Code | ja |
| `cssparser-macros` | `MPL-2.0` | dieselbe Begruendung | ja |
| `dtoa-short` | `MPL-2.0` | dieselbe Begruendung | ja |
| `option-ext` | `MPL-2.0` | dieselbe Begruendung | ja |
| `selectors` | `MPL-2.0` | dieselbe Begruendung | ja |
| `ring` | `ISC` | `Apache-2.0 AND ISC` — die UND-Verknuepfung verlangt beide; ISC ist permissiv, ohne Copyleft | ja |
| `rustls-webpki` | `ISC` | dieselbe Begruendung; Weg: `rustls`/`sqlx` -> `rustls-webpki` | ja |
| `untrusted` | `ISC` | dieselbe Begruendung; Weg: `rustls`/`ring` -> `untrusted` | ja |
| `webpki-roots` | `CDLA-Permissive-2.0` | eine permissive DATENlizenz ueber den gebuendelten Mozilla-Wurzelzertifikatssatz, kein Quellcode; Weg: `sqlx` mit `tls-rustls-ring-webpki` | ja |

GEMESSEN und ausdruecklich festgehalten: `cargo deny check` gab in diesem Lauf
KEINE `license-exception-not-encountered`-Warnung aus. Damit ist die Folge
erledigt, die `docs/adr/0004-server-runtime-and-dependency-class.md` unter
`Consequences` dem Task zuschreibt, der `apps/server` und die drei
`ea-sync-*`-Crates anlegt: die vier TLS-Ausnahmen liegen jetzt wirklich im
Graphen, fuer den sie eingetragen wurden. Der Ledgeranker der Zeile bleibt
`GATE-25` `v1.2`, `stage=7`, `planned`.

### (b) Die Reichweitenklausel der Auflegung A

Sie steht woertlich in Abschnitt 2 und wird von `run_stage_three_gate`
zeichengenau geprueft. Gemessene Wirtwerkzeuge: Docker-CLI 29.7.2, Engine
29.4.0.

Nach dem letzten Kommando der Folge, also mit ABGERAEUMTEN Containern, wurde
nachgemessen: `stage-gate 1`, `stage-gate 2` und `stage-gate 3` enden alle
drei mit Exitcode 0, und `cargo test --locked -p xtask --test stage_gate`
meldet 16 bestanden, 0 fehlgeschlagen. Die drei Stufengates lesen Dokumente,
das Ledger und ein Manifest; sie oeffnen weder Datenbank noch Object Store.

### (c) Der OCI-Basisdigest

Woertlich in Abschnitt 2.2, samt der Messung, dass er ein Multi-Arch-Index
ueber fuenf Plattformen ist, und samt dem Digest des Builders.

### (d) `pnpm verify:quick`

Die Belegzeile oben nennt die Zahl der Teilkommandos UND die Zahl der Pakete
auf der wasm32-Positivliste ausgeschrieben. Beide sind an ihre Quelle
gebunden: `stage_three_gate_report_records_the_measured_full_gate_run`
(`tools/xtask/tests/stage_gate.rs`) zaehlt sie am zeichengenauen Pin von
`verify_quick_commands()` in `tools/xtask/src/main.rs` und vergleicht gegen
diese Zelle. Eine der beiden Zahlen von Hand fortzuschreiben und die Quelle
nicht, wird deshalb rot — die Stufe 2 hat genau diesen Drift erlebt (SIEBEN
statt ACHT), und kein Gate hat ihn gefangen, weil kein Literal die Zahl hielt.
Der Warm-/Kaltzustand des `target/` steht in derselben Zelle; die Stufe 2 hat
ihn UNGESAGT gelassen, und genau deshalb sagt ihn diese Stufe.

### (e) Die Migrationsreservierung

Abschnitt 2.1. Stufe 3 liefert GENAU EINE Migration; die Fortschreibung gegen
eine bereits ausgelieferte Installation ist Stufe 7.

### (f) Der Marker fuer die Stufen 4 und 6

Abschnitt 2.3. Beide Stufen treiben `pnpm verify:quick` heute blank und
MUESSEN ihm `integration up` voranstellen, seit `apps/server` ein
Arbeitsbereichsmitglied ist.

### Offene Punkte, die diese Stufe NICHT schliesst

- Die vier Klientenzeilen aus `docs/adr/0004-server-runtime-and-dependency-class.md`
  (`hyper`, `hyper-util`, `http`, `http-body-util`) tragen in ihren Kopfzeilen
  `not retrieved` fuer Veroeffentlichungsdatum und RustSec-Historie. Die
  Primaerquellenpruefung dieser vier steht aus.
- Die Wire-Codes dieser Stufe sind im Sync-Wire-Nachtrag gefuehrt:
  `EA-TRUST-EVENT-UNVERIFIABLE`, `EA-TRUST-EVENT-NOT-APPLICABLE`,
  `EA-TRUST-EVENT-NOT-VALID-NOW`, `EA-TRUST-STATE-CONFLICT`,
  `EA-READER-ACK-SIGNATURE`, `EA-WEBAUTHN-ASSERTION-INVALID` und die
  Vault-Codes. Fuer die `EA-COMMIT-*`-Familie einschliesslich
  `EA-COMMIT-REGISTRY-HEAD-REQUIRED` ist entschieden, dass sie KEINE
  Nachtragszeile braucht: die Codetabelle des Nachtrags ist trust-only.
- Der Rueckspielnachweis belegt die MECHANIK, nicht die produktionsreife
  Sicherung: Aufbewahrungsfristen, Verschluesselung der Sicherung,
  Wiederanlaufzeit und Object Lock gegen den Betreiber selbst bleiben Stufe 7.
- Das Releasebild wurde NICHT gebaut (Abschnitt 2.2); gemessen ist der
  Baueingabevertrag.
- **Der Schreiberwechsel bleibt unbedienbar.** `EA-COMMIT-WRITER-TRANSITION`
  (422) weist jeden Eintrag ab, dessen Manifest einen
  `writerTransitionEventHash` nennt (Abschnitt 5.1). Die Ledgerzeile FR-082
  fuehrt die Einschraenkung mit; gehoben wird sie in Stufe 5 (Administration,
  Schreiberrotation).
- **Die Vertrauensschliessung wird je signiertem Request neu geladen.**
  `apps/server/src/adapters/trust_authority.rs::trust_catalog` holt fuer JEDEN
  `/v1`-Request mit Signatur den VOLLSTAENDIGEN `.etb`-Katalog der
  Organisation aus dem Object Store — ein `get_object` je indiziertem
  Trust-Objekt — und laeuft danach `verify_trust` samt Kopfkette auf einem
  fluechtigen Zustandsspeicher. Gemessene Kosten sind damit O(Zahl der
  Trust-Objekte) S3-Umlaeufe plus eine volle Trust-Pruefung PRO REQUEST. Die
  Stufe-3-Zusagen bleiben davon unberuehrt — die Aufloesung ist korrekt, nur
  teuer —, aber jenseits einer Handvoll Geraete ist das nicht betreibbar. Die
  vorgesehene Abhilfe ist zweiteilig: der persistente Pin als BODEN (in dieser
  Stufe bereits umgesetzt, Abschnitt 4) und ein prozessinterner Cache der
  geprueften Schliessung, geschluesselt auf den Registry-Kopf und die
  Katalog-Hashmenge, den `advance_pinned_head` entwertet. Folgeticket:
  **DRK-248** (<https://app.clickup.com/t/123zgebztur>).
