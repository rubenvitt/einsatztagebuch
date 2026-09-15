# Stufe-5-Gate-Bericht — Administration, Recovery und Vernichtung

Dieser Bericht schliesst die Stufe 5 des Einsatzarchivs ab. Er haelt fest, was
die Stufe BELEGT, und — mit demselben Gewicht — was sie NICHT belegt. Ein
gruener `stage-gate 5` ist der Beleg fuer die Zusagen, die hier ausgeschrieben
stehen, und fuer keine darueber hinaus.

Die Stufe schliesst DREI Workstreams zugleich ab: `admin-trust` (Organisations-
und Rootzeremonien, Operator-Identitaet, Registry-Wirksamkeit),
`recovery-regrant-amendment` (gefuehrter Recovery-Test, historischer Re-Grant,
Nachtrag) und `destruction` (kontrollierte Vernichtung, Stub, Attestierungen).
Sie ist damit die erste Stufe, deren Gate KUMULATIV prueft: nicht nur, dass die
eigenen Belege vorliegen, sondern dass keine der neunzehn Ledgerzeilen ohne
Beleg gewandert ist.

Ein gruener Stufe-5-Gate ist ausdruecklich kein Beleg fuer die nativen Minimal- und Maximalfaelle, fuer die quartalsweise Uebung, fuer die externe Datenschutzentscheidung und fuer die Custody der Produktionsschluessel; alle vier bleiben Stufe 7. Alle vier stehen unten in `## Dokumentierte Grenzen` mit ihrer besitzenden Stufe.

**Stand dieses Berichts.** Der Bericht ist mit dem Gate zusammen angelegt und
fuehrt die Nachweisfuehrung, bevor sie vollstaendig gemessen ist. Jede Zelle,
die eine Messung noch nicht hat, sagt das mit dem Wort `Messung offen` und
nennt den Zeugen, der sie erbringen wird. Das ist kein Formfehler, sondern der
Zweck: die neunzehn Ledgerzeilen stehen bis zur Messung auf `planned`, und
`stage-gate 5` bleibt deshalb rot. Der Ledger ist der Riegel, nicht dieser Text.

## 1. Primaere Abnahmekriterien und ihre Belege

Die vierzehn primaeren Abnahmekriterien der Stufe 5 nach `design.md` Abschnitt
23. Die vierte Spalte ist keine Formsache: eine leere Zelle waere genau die
Scheinzusage, die dieser Bericht ausschliesst, und `run_stage_five_gate` weist
sie ab.

| Kriterium | Gegenstand | Beleg | Offen in spaeterer Stufe |
|---|---|---|---|
| AK 11 | Widerruf | Messung offen; Zeuge `crates/ea-admin/tests/operator_revocation_recovery.rs` — ein widerrufener Reader erhaelt nach Registry-Empfang keine neuen Grants | Die quartalsweise Uebung des Widerrufs bleibt Stufe 7 |
| AK 12 | Historischer Zugriff | Messung offen; Zeuge `tests/ea-system-tests/tests/e2e_historical_grant.rs` — ausgewaehlte alte Eintraege erst nach Recovery-Re-Grant lesbar, `.eip` bleibt byteidentisch | Die Custody der Produktionsschluessel fuer den Re-Grant bleibt Stufe 7 |
| AK 18 | Nachtrag | Messung offen; Zeuge `crates/ea-admin/tests/amendment.rs` — der Nachtrag referenziert das Original und aendert keine Originalbytes | Die Anzeige mehrerer verketteter Nachtraege im Browser-Reader liegt in Stufe 4 und wird hier nicht erneut belegt |
| AK 24 | Registry-Ueberalterung | Messung offen; Zeugen `crates/ea-admin/tests/registry_workflows.rs` und `apps/cli/tests/registry_workflows.rs` — Pflichtfelder, Standard-`warn`, Standard-`block` und die verbrauchte Sequenz-Lease | Die Betriebsentscheidung ueber die Altersrichtlinie einer echten Organisation bleibt Stufe 7 |
| AK 29 | Rollentrennung | Messung offen; Zeugen `tests/ea-system-tests/tests/privacy_canaries_writer.rs` und `crates/ea-admin/tests/operator_trust_store.rs` — Writer-Geraete tragen keine Reader-, Recovery-, Historical-Grant-Authority- oder Key-Approver-Privatschluessel | Die installierte OS-Praesenz auf einem Produktionsgeraet bleibt Stufe 7 |
| AK 30 | Kontrollierte Vernichtung | Messung offen; Zeugen `apps/cli/tests/operator_destruction/completion.rs`, `::custodian.rs`, `::evidence_writer.rs` — zwei Approver, alle bekannten Speicherorte, Backupfristen, unerreichbare Replikate | Die externe Datenschutzentscheidung zum Restnachweis bleibt Stufe 7 |
| AK 35 | Registry-Angriffe | Messung offen; Zeuge `tests/ea-system-tests/tests/e2e_registry_effectiveness.rs` — Rollback und gleiche Version mit anderem Hash fail-closed, `trustedTimeFloor` bleibt monoton | Das nicht erkennbare Offline-Fenster ist eine dokumentierte Grenze des Designs, keine Stufenluecke |
| AK 40 | Historische Grant-Autoritaet | Messung offen; Zeugen `crates/ea-recovery/tests/historical_grant.rs` und `tests/ea-system-tests/tests/e2e_historical_grant.rs` — Recovery-KEM, Grant-Signatur und Mehr-Augen-Authorization getrennt erforderlich | Die Custody der Produktionsschluessel bleibt Stufe 7 |
| AK 41 | Destroyed Entry Stub | Messung offen; Zeugen `apps/cli/tests/operator_destruction/writer_evidence.rs` und `::audit_repair.rs` — gueltiger `.eds` mit Writer-Signatur, `entryHash` und Kettenkontinuitaet; eine nicht autorisierte Entfernung bleibt sichtbare Luecke | Die nativen Minimal- und Maximalfaelle des Stubs bleiben Stufe 7 |
| AK 44 | Datenschutz-Gate | Messung offen; Zeugen `tests/ea-system-tests/tests/e2e_destruction_policy.rs` und `crates/ea-admin/tests/go_live.rs` — ohne dokumentierte Freigabe startet kein `.eds`-basierter Vernichtungsprozess | Die externe Datenschutzentscheidung selbst bleibt Stufe 7; das Gate belegt nur, dass ohne sie nichts startet |
| AK 47 | Organisationsadministration | Messung offen; Zeugen `crates/ea-admin/tests/authorization.rs`, `::root_ceremony.rs`, `::ceremony_steps.rs`, `apps/cli/tests/organization_certify_root.rs` — Admin-Autorisierung, Action-Code, Einmaligkeit und Root-Signatur exakt pruefbar; Root-only, Admin-only, falscher Core und Selbstrotation scheitern | Der Transport-Fingerprint-Anteil haengt an `WR-075` und bleibt bis DRK-318 offen |
| AK 49 | Registry-Wirksamkeit | Messung offen; Zeuge `tests/ea-system-tests/tests/e2e_registry_effectiveness.rs` — stets der hoechste anwendbare Head, Luecken, Forks und future-only Heads blockiert | Die unvermeidbare Offline-Grenze ist dokumentiert und bleibt bestehen |
| AK 52 | Gefuehrter Recovery-Test | Messung offen; Zeugen `crates/ea-admin/tests/recovery_input_profiles.rs`, `crates/ea-recovery/tests/backup_key.rs`, `::offline_sources.rs` — jede inventarisierte Schluesselsicherung gegen Anchor und Zertifikat geprueft; fehlende oder falsche Medien verhindern den Gesamtbericht | Die quartalsweise Uebung des Recovery-Tests bleibt Stufe 7 |
| AK 53 | Operator-Identitaet | Messung offen; Zeugen `crates/ea-admin/tests/operator_binding.rs`, `::operator_host.rs`, `::operator_audit.rs`, `apps/cli/tests/operator_administration/host.rs` — Bindung an Root-signiertes `operatorBinding`, tatsaechliches OS-Konto und native Re-Authentisierung; Widerruf und abgelaufene Sitzung werden klartextfrei auditiert | Der Ubuntu-UID-Wiederverwendungsfall auf einer installierten OS-Praesenz bleibt Stufe 7; der Transport-Fingerprint-Anteil haengt an `WR-075` |

## 2. Reichweite der Stufe-5-Abnahme

Stufe 5 belegt ihre nativen Zeugen auf zwei Plattformen: macOS als Entwicklungsplattform und ubuntu-24.04 als Gate-Laeufer, beide unter der Toolchain 1.95.0. Die Plattformmatrix, eine installierte OS-Praesenz und ein tatsaechlich gemounteter Netz-Positivzeuge sind damit NICHT belegt und bleiben Stufe 7.

Die Klausel nennt die PLATTFORM und nicht bloss die Toolchain, und das ist
gemessen: bis `d9b2645` liefen ALLE nativen Messungen dieser Stufe
ausschliesslich auf macOS. Der erste Linux-Lauf brachte vierzehn Fehlschlaege,
und keiner davon war ein Produktfehler — es war ein unoptimiertes Test-Setup
gegen feste Produktfristen (300 s Praesenznachweis, 40 s Antwortfrist). Eine
Reichweitenklausel, die nur die Toolchain nennt, haette diesen Befund nicht
ausgeschlossen.

Belastbare Gate-Zahlen aus den beiden gruenen Laeufen auf `db08333`
(Lauf 34936505876): vollstaendiger Gate-Durchlauf 50 min 26 s beim ersten
vollstaendigen Lauf, 29 min 49 s mit vollstaendig warmen Caches, beide unter
der 90-Minuten-Frist. Das Target `einsatzarchiv-cli --test operator` liest
213 bestanden, 0 fehlgeschlagen, 25 ignoriert.

## 3. Die drei Workstreams

Der Gate verlangt die Belege KUMULATIV. Ein Workstream, dessen Belege fehlen,
wird namentlich gemeldet.

**`admin-trust`** — Organisations- und Rootzeremonien, Operator-Identitaet,
Registry-Wirksamkeit und -Ueberalterung. Primaere Kriterien: AK 24, AK 29,
AK 35, AK 47, AK 49, AK 53. Zeugenflaeche: `crates/ea-admin/tests/`,
`apps/cli/tests/operator_administration/`,
`tests/ea-system-tests/tests/e2e_registry_effectiveness.rs`.

**`recovery-regrant-amendment`** — gefuehrter Recovery-Test, historischer
Re-Grant, Nachtrag, Widerruf. Primaere Kriterien: AK 11, AK 12, AK 18, AK 40,
AK 52. Zeugenflaeche: `crates/ea-recovery/tests/`,
`crates/ea-admin/tests/amendment.rs`,
`tests/ea-system-tests/tests/e2e_historical_grant.rs`. Der Workspace-Lauf ist
`pnpm test:recovery` und nicht ein Teillauf — eine Plankorrektur aus `c832acd`.

**`destruction`** — kontrollierte Vernichtung, Destroyed Entry Stub,
Attestierungen, Datenschutz-Gate. Primaere Kriterien: AK 30, AK 41, AK 44.
Zeugenflaeche: `apps/cli/tests/operator_destruction/`,
`tests/ea-system-tests/tests/e2e_destruction_policy.rs`,
`::e2e_destruction_admission_race.rs`, `::e2e_destruction_catalog_race.rs`.

## 4. Entscheidungen dieser Stufe

**Posture, Ruling „Plan woertlich" vom 2026-09-14.** Die Geraete-Posture wird
in allen drei Zustaenden geprueft. `Fail` blockiert eine Produktionssitzung.
`Unknown` bleibt fuer den Go-live sichtbar ungeloest, auch mit signiertem
Dokument; ein dokumentiertes `Unknown` darf aber eine Sitzung oeffnen. Der
Stale-Writer verlangt ein striktes Pass. Umgesetzt in `cd538bb`.

**Der Name `production_ready`.** `OperatorGoLiveReport.production_ready =
admission.is_some()` in `crates/ea-admin/src/operator_runtime.rs` ist aus
PR #22 zur Pruefung an dieses Gate uebergeben. Befund: der Name sagt
„produktionsbereit", der Wert sagt „eine Sitzung darf oeffnen". Bei einem
dokumentierten `Unknown` fallen die beiden Aussagen AUSEINANDER — die Sitzung
darf oeffnen, produktionsbereit ist der Go-live nicht. Der Name ist damit die
Falschetikettierung, die das Posture-Ruling ausdruecklich verbietet.
Entscheidung: umbenennen, bevor die Ledgerzeilen zu AK 44 und AK 53 wandern.
Messung offen.

**Testflaeche ueber `desktop-fixture`.** Das CLI-Merkmal zieht ueber eine
optionale normale Kante `ea-desktop/test-support` → `ea-admin/test-support`.
Normale CLI-Builds sind nicht betroffen (belegt mit `cargo check -p
einsatzarchiv-cli`). Kein Gate prueft aber, dass diese `ea-admin`-Testflaeche
nie in einem Release-Build landet; das archive-fs-Gate schuetzt seit `82f29b1`
nur `ea-archive-fs` und nur dessen Wirtsgraphen ohne Dev-Kanten.
Entscheidung: ein Release-Build-Check auf `desktop-fixture` gehoert in dieses
Gate. Messung offen.

**Nativer Clock-Release.** Freigegeben per Ruling vom 2026-09-13 unter
Auflagen: RED-first, Gegenproben fuer Pass, Fail, Ablauf, Doppelverbrauch und
Reopen, unabhaengiges Security-Review, die `Unknown`-Erweiterung separat. Der
native RED in `apps/cli/tests/operator_administration/clock_repair.rs` ist mit
`#[ignore = "DRK-282: …"]` geparkt (`8bdf548`), weil
`ClockRepairRuntime::release` weiter am geschlossenen `RuntimeExpired`-Stub
endet. Beim Anwenden des Patches muss der Ignore entfernt werden.

## 5. Signierte Auditereignisse

Nachzuweisen sind signierte, dauerhafte Auditereignisse fuer: Login,
fehlgeschlagene Reauthentisierung, Bindungsaenderung, Bindungswiderruf, jede
Admin- und Rootzeremonie, die Stale-Registry-Quittung, den Export, den
Clock-Release, den Recovery-Test, den Re-Grant und die Vernichtung.

Zeugenflaeche: `crates/ea-admin/tests/operator_audit.rs`,
`crates/ea-admin/tests/clock_release.rs`,
`apps/cli/tests/operator_destruction/audit_repair.rs`,
`apps/cli/tests/safety_audit.rs`. Jedes Ereignis ist klartextfrei zu
auditieren — der Nachweis darueber laeuft ueber
`tests/ea-system-tests/tests/privacy_canaries_writer.rs`.

Messung offen. Der Clock-Release-Beleg haengt zusaetzlich an der Anwendung des
unter Abschnitt 4 genannten Patches.

## 6. Geraete-Posture in drei Zustaenden

| Zustand | Zusage | Zeuge | Stand |
|---|---|---|---|
| Pass | Oeffnet eine Produktionssitzung; der Stale-Writer verlangt genau dieses strikte Pass | `crates/ea-admin/tests/go_live.rs` | Messung offen |
| Fail | Blockiert eine Produktionssitzung, ausnahmslos | `apps/cli/tests/operator_administration/host.rs` — der Host-Zeuge misst echt und belegt auf einem FAIL-Host die Verweigerung: Exit 12, `EA-OPERATOR-POSTURE`, kein `target.json` | Auf dem Gate-Laeufer belegt (Diag-Lauf 34876674848): `/` ist dort `/dev/sda1` mit der Kette `part`, `disk`, ohne `crypt`, also FDE gemessen FAIL |
| Unknown | Bleibt fuer den Go-live sichtbar ungeloest, auch mit signiertem Dokument; darf aber eine Sitzung oeffnen | `crates/ea-admin/tests/go_live.rs` mit `DevicePostureProviderFake::unknown(FullDiskEncryption)` | Messung offen; haengt am Namen `production_ready` aus Abschnitt 4 |

Keiner der beiden Zustaende `Fail` und `Unknown` DARF falsch etikettiert
werden. Das ist die Zusage, an der dieser Abschnitt haengt, und der Grund, aus
dem der Gate beide Namen woertlich im Bericht verlangt: ein Bericht, der nur
den blockierenden Fall nennt, belegt die Haelfte.

## Ledgerpflege

Diese Stufe fuehrt neunzehn Zeilen in
`docs/traceability/v0.1-requirements.csv` fort: AK-11, AK-12, AK-18, AK-24,
AK-29, AK-30, AK-35, AK-40, AK-41, AK-44, AK-47, AK-49, AK-52, AK-53 sowie
FR-120, FR-121, FR-123, FR-124 und WR-075.

**Hier und nur hier** bewegt sich der Ledger, ausschliesslich nach
`implemented` oder `integrated`. Ein frueherer Wechsel macht das Stufengate
rot; PR #22 hat deshalb keine Zeile bewegt.

**Die fuenf Zeilen ohne primaeres Abnahmekriterium.** FR-120, FR-121, FR-123,
FR-124 und WR-075 haengen an keinem Kriterium aus Abschnitt 1 und brauchen
eigene Gate-Logik. Der Grund ist gemessen: die Belegrechnung der Stufen 2 bis 4
filtert ueber `!row.primary_acceptance_criterion.is_empty()` und zaehlt eine
Zeile ohne Kriterium WEDER als belegt NOCH als Mangel — sie faellt lautlos aus
der Rechnung. `run_stage_five_gate` verlangt sie deshalb namentlich in diesem
Bericht.

| Zeile | Gegenstand | Beleg |
|---|---|---|
| FR-120 | Nachtrag als neuer Ketteneintrag | Messung offen; Zeuge `crates/ea-admin/tests/amendment.rs`, verwandt mit AK 18 |
| FR-121 | Nachtragskette und gemeinsame Anzeige | Messung offen; Zeuge `crates/ea-admin/tests/amendment.rs` |
| FR-123 | Vernichtungszustaende und ihre Uebergaenge | Messung offen; Zeuge `apps/cli/tests/operator_destruction/completion.rs`; Zustand 4 entsteht nie implizit, sondern nur ueber die bestaetigte Aktion `destruction_mark_incomplete` (`ebb6e03`) |
| FR-124 | Signierte Loeschattestierung je Replik | Messung offen; Zeuge `apps/cli/tests/operator_destruction/custodian.rs` |
| WR-075 | Re-Encryption nur bei Uebereinstimmung mit dem gebundenen Transport-Key-Fingerprint | Dokumentierte Grenze, siehe unten |

## Dokumentierte Grenzen

Diese Stufe schliesst als erste mit einer offenen Ledgerzeile. Beide Grenzen
haben ein besitzendes Ticket; eine Grenze ohne Besitzer waere keine Grenze,
sondern eine Luecke.

**WR-075 bleibt `planned` — besitzendes Ticket DRK-318.** Die Zeile verlangt
die Re-Encryption gegen den gebundenen Transport-Key-Fingerprint. Die
zugehoerige v1.1-Objektfamilie (`readerKeyEscrow` und
`readerKeyEscrowRecoveryAuthorization`) entsteht erst in DRK-318, und vor
dessen normativem und Security-Review gibt es nichts zu belegen. Ruling Ruben
vom 2026-09-15: das Gate schliesst mit dokumentierter Grenze, statt auf
DRK-318 zu warten. Die Transport-Fingerprint-Anteile von AK 47 und AK 53
bleiben damit ebenfalls offen und sind in Abschnitt 1 so ausgewiesen.
`run_stage_five_gate` laesst genau diese eine Zeile auf `planned` durch — aber
nur gegen einen Bericht, der sie samt Ticket nennt. Jede andere Stufe-5-Zeile
auf `planned` bleibt ein Mangel.

**DRK-320 (Controlled-Network-Archiv) ist eine dokumentierte Grenze und
bekommt KEINE eigene Ledgerzeile.** Ruling Ruben vom 2026-09-15. Begruendung:
keine der neunzehn Stufe-5-Zeilen verlangt ein Netzprofil, und FR-061 mit
AK-48 stehen auf Stufe 2 `integrated` und decken nur die Profilzulassung in
`archive-fs` ab. Die vier REDs aus `f39c56f` bleiben mit
`#[ignore = "DRK-320: …"]` geparkt, ebenso der offene RED
`cargo test -p ea-recovery --test fs_source_union`. Der tatsaechlich gemountete
Netz-Positivzeuge bleibt Stufe-7-Evidenz.

**Der Stufe 7 vorbehalten.** Vier Dinge bleiben ausdruecklich ausserhalb dieser
Stufe: die nativen Minimal- und Maximalfaelle, die quartalsweise Uebung, die
externe Datenschutzentscheidung und die Custody der Produktionsschluessel.

**Nicht blockierend, hier aber benannt.** DRK-326 fuehrt das macOS-Watch-
Protokoll mit 100 ms Spielraum (`WatchTests.swift` schlaeft 1,1 s gegen ein
Prueffenster von 1 s; der Test kann auf einem ausgelasteten Laeufer
strukturell rot werden). DRK-324 fuehrt die Haertung der Reader-`ActionClock`
als P3. DRK-323 ist mit `db08333` behoben und auf dem echten Laeufer belegt
(RED `954fc7d` 28 von 30 Laeufen rot, GREEN `db08333` 0 von 30); dieses Gate
fuehrt `bootstrap_root` deshalb NICHT mehr als lastabhaengig.
