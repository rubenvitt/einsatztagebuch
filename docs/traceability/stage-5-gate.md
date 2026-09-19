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

**Stand dieses Berichts (2026-09-19).** Jede Zelle nennt den Zeugen, der die
Zusage WOERTLICH prueft, und die Zahl, die er auf `4fe094b` gemessen hat
(macOS, Toolchain 1.95.0, `bestanden/fehlgeschlagen/ignoriert` je Testziel).
Eine Zeugenpruefung vom selben Tag hat gezeigt, dass die erste Fassung bei
rund der Haelfte der Zellen einen Zeugen nannte, der die Zusage nicht oder nur
teilweise prueft; diese Zellen sind korrigiert, der fruehere Zeuge steht
jeweils mit dem, was er tatsaechlich belegt, dabei. Drei Zusagen hatten gar
keinen Test und haben ihn mit `8444a83` bekommen, die Klartextsuche ueber die
Stufe-5-Audits mit `4fe094b`.

Der Ledger bleibt trotzdem der Riegel: die neunzehn Zeilen stehen auf
`planned`, und `stage-gate 5` bleibt rot, bis die zwei in `## Dokumentierte
Grenzen` genannten Produktluecken dieser Stufe geschlossen sind — der native
Clock-Release und das Audit der abgelaufenen Sitzung. Wo eine Zelle `Offen`
sagt, ist das eine dieser beiden Luecken und keine fehlende Messung.

## 1. Primaere Abnahmekriterien und ihre Belege

Die vierzehn primaeren Abnahmekriterien der Stufe 5 nach `design.md` Abschnitt
23. Die vierte Spalte ist keine Formsache: eine leere Zelle waere genau die
Scheinzusage, die dieser Bericht ausschliesst, und `run_stage_five_gate` weist
sie ab.

| Kriterium | Gegenstand | Beleg | Offen in spaeterer Stufe |
|---|---|---|---|
| AK 11 | Widerruf | `tests/ea-system-tests/tests/e2e_registry_effectiveness.rs::a_revocation_stops_new_grants_from_its_effective_sequence_and_leaves_the_earlier_grant_intact` (6/0/0) und `crates/ea-admin/tests/registry_workflows.rs::a_revocation_recalls_nothing_and_stops_only_new_grants` (19/0/0) — ein widerrufener Reader erhaelt ab der wirksamen Sequenz keine neuen Grants, der fruehere bleibt unberuehrt. Korrigiert: `operator_revocation_recovery.rs` (2/0/0) belegt nur den eingefrorenen Widerrufsauftrag | Die quartalsweise Uebung des Widerrufs bleibt Stufe 7 |
| AK 12 | Historischer Zugriff | `crates/ea-recovery/tests/historical_grant.rs::a_new_reader_opens_the_selected_old_entry_only_after_the_recovery_regrant` (7/0/0, neu mit `8444a83`) — vor dem Re-Grant weder Grant noch Entkapselung, danach genau einer, gespeicherte `.eip`-Bytes vorher und nachher identisch; Mutation `crates/ea-verify/src/recipient.rs:198` macht ihn rot. Gegen den Server: `tests/ea-system-tests/tests/e2e_historical_grant.rs` (1/0/0, mit `xtask integration up`) | Die Custody der Produktionsschluessel fuer den Re-Grant bleibt Stufe 7 |
| AK 18 | Nachtrag | `crates/ea-admin/tests/amendment.rs::amendment_finalization_preserves_original_bytes_and_reader_keeps_multiple_amendments` (1/0/0) — der Nachtrag referenziert das Original und aendert keine Originalbytes | Die Anzeige mehrerer verketteter Nachtraege im Browser-Reader liegt in Stufe 4 und wird hier nicht erneut belegt |
| AK 24 | Registry-Ueberalterung | `crates/ea-admin/tests/registry_workflows.rs` (19/0/0: Pflichtfelder, `the_sequence_lease_boundary_is_exact`, `an_expired_head_blocks_fail_closed`) und fuer Standard-`warn` `crates/ea-writer/tests/stale_registry_acknowledgement.rs::standard_warn_persists_a_signed_receipt_before_finalizing_once` (19/0/0) mit `stale_registry_warning.rs` (4/0/0). Korrigiert: `apps/cli/tests/registry_workflows.rs` (56/0/0) belegt Widerrufsplan und Clock-Release-Grammatik, nicht warn/block | Die Betriebsentscheidung ueber die Altersrichtlinie einer echten Organisation bleibt Stufe 7 |
| AK 29 | Rollentrennung | `crates/ea-key-provider/tests/writer_role_guard.rs::writer_profile_rejects_forbidden_private_key_purposes` (8/0/0) — Writer-Profile verweigern Reader-, Recovery-, Historical-Grant-Authority- und Key-Approver-Privatschluessel. Korrigiert: `privacy_canaries_writer.rs` und `operator_trust_store.rs` pruefen keine Schluesselrollen | Die installierte OS-Praesenz auf einem Produktionsgeraet bleibt Stufe 7 |
| AK 30 | Kontrollierte Vernichtung | Zwei Approver: `crates/ea-destruction/tests/authorization.rs` (10/0/0). Alle bekannten Speicherorte und Backupfristen: `process_native::destruction::completion::` (4 Tests), unerreichbare Replikate: `::failure::` (7 Tests); das Ziel `einsatzarchiv-cli --test operator process_native::destruction::` liest 52/0/0 in 1335 s seriell | Die externe Datenschutzentscheidung zum Restnachweis bleibt Stufe 7 |
| AK 35 | Registry-Angriffe | `tests/ea-system-tests/tests/e2e_registry_effectiveness.rs::a_rollback_a_same_version_fork_and_an_expired_head_block_the_line` (6/0/0) — Rollback und gleiche Version mit anderem Hash fail-closed, `trustedTimeFloor` bleibt monoton | Das nicht erkennbare Offline-Fenster ist eine dokumentierte Grenze des Designs, keine Stufenluecke |
| AK 40 | Historische Grant-Autoritaet | `crates/ea-recovery/tests/historical_grant.rs::separate_key_roles_recipient_native_presence_and_durable_audit_are_required` (7/0/0) fuer getrennte Recovery-KEM und Grant-Signatur, `crates/ea-trust/tests/grant_authorization.rs` (5/0/0) fuer die Mehr-Augen-Authorization; Server-Pfad `e2e_historical_grant.rs` (1/0/0) | Die Custody der Produktionsschluessel bleibt Stufe 7 |
| AK 41 | Destroyed Entry Stub | `process_native::destruction::writer_evidence::native_writer_evidence_reopens_as_real_reader_authorized_destruction` (in 52/0/0) — gueltiger `.eds` mit Writer-Signatur, `entryHash` und Kettenkontinuitaet; die nicht autorisierte Entfernung als sichtbare Luecke: `crates/ea-verify/tests/destruction_stub.rs` (8/0/0) und `receipt_checkpoint.rs` (3/0/0) | Die nativen Minimal- und Maximalfaelle des Stubs bleiben Stufe 7 |
| AK 44 | Datenschutz-Gate | `tests/ea-system-tests/tests/e2e_destruction_policy.rs::real_current_progress_privacy_gate_exact_replay_and_transaction_fence` (1/0/0, `EA-DESTRUCTION-PRIVACY-GATE`), dazu `e2e_destruction_admission_race.rs` (4/0/0) und `e2e_destruction_catalog_race.rs` (1/0/0), alle mit `xtask integration up` — ohne dokumentierte Freigabe startet kein `.eds`-basierter Vernichtungsprozess. Korrigiert: `go_live.rs` enthaelt keine Datenschutzanforderung | Die externe Datenschutzentscheidung selbst bleibt Stufe 7; das Gate belegt nur, dass ohne sie nichts startet |
| AK 47 | Organisationsadministration | `crates/ea-admin/tests/authorization.rs` (16/0/0: Root-only, Admin-only, falscher Core und — neu mit `8444a83` — `a_self_rotation_of_the_signing_admin_never_reaches_the_key_port` mit `EA-TRUST-SELF-AUTHORIZATION`), `::root_ceremony.rs` (7/0/0, Einmaligkeit), `::ceremony_steps.rs` (7/0/0), `apps/cli/tests/organization_certify_root.rs` (4/0/0) | Der Transport-Fingerprint-Anteil haengt an `WR-075` und bleibt bis DRK-318 offen |
| AK 49 | Registry-Wirksamkeit | `crates/ea-admin/tests/registry_workflows.rs::the_workflow_selects_the_highest_applicable_head` und `::a_wrong_previous_head_blocks` (19/0/0), fuer Forks und future-only Heads `e2e_registry_effectiveness.rs` (6/0/0) | Die unvermeidbare Offline-Grenze ist dokumentiert und bleibt bestehen |
| AK 52 | Gefuehrter Recovery-Test | `crates/ea-admin/tests/bootstrap.rs::a_partial_recovery_test_never_becomes_a_successful_one` (53/0/0, `EA-CEREMONY-RECOVERY-TEST-FAILED` bei einem fehlenden Medium) und `crates/ea-recovery/tests/recovery_test.rs::real_backup_challenges_are_fresh_bound_to_the_signed_certificate_and_never_productive` (6/0/0). Die sechs nativen Zeugen `process_native::recovery::guided::` sind `#[ignore]`, weil sie eine echte Fremdmaschine verlangen (0/0/6). Korrigiert: `recovery_input_profiles.rs`, `backup_key.rs`, `offline_sources.rs` belegen Eingabeprofile, KDF und Parser | Die Fremdmaschine der nativen guided-Zeugen und die quartalsweise Uebung bleiben Stufe 7 |
| AK 53 | Operator-Identitaet | `crates/ea-admin/tests/operator_binding.rs` (21/0/0), `::operator_host.rs` (17/0/0), `::operator_audit.rs` (8/0/1) mit `the_revocation_audit_carries_no_operator_plaintext` (neu, `8444a83`), nativ `process_native::administration::host::` (2/0/0 in 163 s, nur mit `--features desktop-fixture` uebersetzt). Offen: eine abgelaufene Sitzung wird abgelehnt, aber NICHT auditiert — der Zeuge `an_expired_operator_session_is_refused_and_audited_without_plaintext` ist als RED geparkt, siehe `## Dokumentierte Grenzen` | Der Ubuntu-UID-Wiederverwendungsfall auf einer installierten OS-Praesenz bleibt Stufe 7; der Transport-Fingerprint-Anteil haengt an `WR-075` |

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

Die Messung vom 2026-09-19 fuer diesen Bericht lief auf macOS. Die
Linux-Zahlen oben stammen aus dem CI-Gate; die Ziele dieses Berichts laufen
dort in `pnpm verify:quick` erneut.

## 3. Die drei Workstreams

Der Gate verlangt die Belege KUMULATIV. Ein Workstream, dessen Belege fehlen,
wird namentlich gemeldet.

**`admin-trust`** — Organisations- und Rootzeremonien, Operator-Identitaet,
Registry-Wirksamkeit und -Ueberalterung. Primaere Kriterien: AK 24, AK 29,
AK 35, AK 47, AK 49, AK 53. Zeugenflaeche: `crates/ea-admin/tests/`,
`crates/ea-key-provider/tests/writer_role_guard.rs`,
`crates/ea-writer/tests/stale_registry_*.rs`,
`apps/cli/tests/operator_administration/`,
`tests/ea-system-tests/tests/e2e_registry_effectiveness.rs`.

**`recovery-regrant-amendment`** — gefuehrter Recovery-Test, historischer
Re-Grant, Nachtrag, Widerruf. Primaere Kriterien: AK 11, AK 12, AK 18, AK 40,
AK 52. Zeugenflaeche: `crates/ea-recovery/tests/`,
`crates/ea-admin/tests/amendment.rs`, `crates/ea-admin/tests/bootstrap.rs`,
`crates/ea-trust/tests/grant_authorization.rs`,
`tests/ea-system-tests/tests/e2e_historical_grant.rs`. Der Workspace-Lauf ist
`pnpm test:recovery` und nicht ein Teillauf — eine Plankorrektur aus `c832acd`.

**`destruction`** — kontrollierte Vernichtung, Destroyed Entry Stub,
Attestierungen, Datenschutz-Gate. Primaere Kriterien: AK 30, AK 41, AK 44.
Zeugenflaeche: `apps/cli/tests/operator_destruction/`,
`crates/ea-destruction/tests/authorization.rs`,
`crates/ea-verify/tests/destruction_stub.rs`,
`apps/desktop/src-tauri/tests/destruction_commands.rs`,
`tests/ea-system-tests/tests/e2e_destruction_policy.rs`,
`::e2e_destruction_admission_race.rs`, `::e2e_destruction_catalog_race.rs`.

**Nicht gebaut: zwei Systemziele aus Plan Task 14.**
`tests/ea-system-tests/tests/e2e_organization_lifecycle.rs` und
`e2e_recovery_fresh_machine.rs` stehen im Plan unter `Create:`, existieren
aber nicht; die Zusagen, die sie buendeln sollten, sind oben einzeln belegt.
Ob sie vor dem Schliessen des Gates noch als eigene Ziele entstehen, ist
offen und in `## Dokumentierte Grenzen` gefuehrt. Das dritte Ziel aus dem
Plan, `privacy_canaries_admin_recovery_destruction.rs`, gibt es seit
`4fe094b`.

## 4. Entscheidungen dieser Stufe

**Posture, Ruling „Plan woertlich" vom 2026-09-14.** Die Geraete-Posture wird
in allen drei Zustaenden geprueft. `Fail` blockiert eine Produktionssitzung.
`Unknown` bleibt fuer den Go-live sichtbar ungeloest, auch mit signiertem
Dokument; ein dokumentiertes `Unknown` darf aber eine Sitzung oeffnen. Der
Stale-Writer verlangt ein striktes Pass. Umgesetzt in `cd538bb`.

**Der Name `production_ready` — erledigt mit `a123cf8`.**
`OperatorGoLiveReport.production_ready = admission.is_some()` in
`crates/ea-admin/src/operator_runtime.rs` sagte „produktionsbereit", der Wert
sagte „eine Sitzung darf oeffnen". Bei einem dokumentierten `Unknown` fielen
beide auseinander — genau die Falschetikettierung, die das Posture-Ruling
verbietet. Das Feld heisst jetzt `session_admitted`, der Wert ist
unveraendert; Produktionsreife rechnet allein
`GoLiveChecklist::production_ready` in `crates/ea-admin/src/go_live.rs`, das
den Namen zu Recht behaelt. Zeuge:
`process_native::posture_document::signed_native_posture_document_allows_admission_after_real_reopen_without_relabeling_unknown`
prueft im JSON-Bericht `session_admitted == true` und das Fehlen des
Schluessels `production_ready` (RED vorher: `left: Null`).

**Testflaeche ueber `desktop-fixture` — erledigt mit `e76c4e6`.** Das
CLI-Merkmal zieht ueber eine optionale normale Kante `ea-desktop/test-support`
→ `ea-admin/test-support`. Der neue Zeuge
`tools/xtask/tests/workspace.rs::no_production_build_carries_the_ea_admin_test_surface`
prueft die Manifeste und den aufgeloesten Graphen ohne Dev-Kanten fuer
`einsatzarchiv-cli` und `ea-desktop`, mit zwei Gegenproben, die die Kante
finden (`--features desktop-fixture`, Dev-Kanten der CLI). Er laeuft ueber
`pnpm verify:quick` und nicht aus `run_stage_five_gate`, weil kein Stufengate
selbst Prozesse startet (dieselbe Form wie das archive-fs-Gate aus `82f29b1`).
Befund: ea-desktops eigener Release-Build traegt die Kante nicht.

**Nativer Clock-Release.** Freigegeben per Ruling vom 2026-09-13 unter
Auflagen: RED-first, Gegenproben fuer Pass, Fail, Ablauf, Doppelverbrauch und
Reopen, unabhaengiges Security-Review, die `Unknown`-Erweiterung separat. Der
native RED in `apps/cli/tests/operator_administration/clock_repair.rs` ist mit
`#[ignore = "DRK-282: …"]` geparkt (`8bdf548`), weil
`ClockRepairRuntime::release` weiter am geschlossenen `RuntimeExpired`-Stub
endet. Der Patch liegt unangewendet im Archiv der Stufe-5-Belege (SHA256
`08f09b2b…`) und laesst sich am 2026-09-19 sauber auf `main` anwenden. Er wird
erst nach erneuter ausdruecklicher Freigabe angewendet; beim Anwenden muss der
Ignore entfernt werden.

## 5. Signierte Auditereignisse

Nachzuweisen sind signierte, dauerhafte Auditereignisse fuer: Login,
fehlgeschlagene Reauthentisierung, Bindungsaenderung, Bindungswiderruf, jede
Admin- und Rootzeremonie, die Stale-Registry-Quittung, den Export, den
Clock-Release, den Recovery-Test, den Re-Grant und die Vernichtung.

| Ereignis | Zeuge | Messung |
|---|---|---|
| Login, fehlgeschlagene Reauthentisierung | `crates/ea-admin/tests/operator_audit.rs::failed_login_and_reauth_have_valid_device_signatures_…`, `operator_host.rs::unknown_requested_certificate_still_records_signed_failed_login` | 8/0/1 und 17/0/0 |
| Bindungsaenderung und -widerruf | `operator_audit.rs::binding_and_revocation_audits_verify_…`, `operator_binding.rs::revocation_signs_the_exact_binding_registry_change_…` | 8/0/1 und 21/0/0 |
| Admin- und Rootzeremonien | `crates/ea-admin/tests/root_ceremony.rs`, `ceremony_steps.rs` | 7/0/0 und 7/0/0 |
| Stale-Registry-Quittung | `crates/ea-writer/tests/stale_registry_acknowledgement.rs` | 19/0/0 |
| Export | `crates/ea-reader/tests/export.rs`, `audit_redaction.rs` (`PlaintextExport`) | 9/0/0 und 5/0/0 |
| Clock-Release | `crates/ea-admin/tests/clock_release.rs::a_release_is_issued_once_consumed_once_and_replayed_never` (in-process) | 18/0/0; der native Pfad ist offen, siehe Abschnitt 4 |
| Recovery-Test | `crates/ea-recovery/tests/recovery_test.rs`, `crates/ea-admin/tests/bootstrap.rs` | 6/0/0 und 53/0/0 |
| Re-Grant | `crates/ea-recovery/tests/historical_grant.rs` | 7/0/0 |
| Vernichtung | `process_native::destruction::audit_repair::` und der Start-Audit in `process_native::destruction::` | 52/0/0 |

Klartextfreiheit: `tests/ea-system-tests/tests/privacy_canaries_admin_recovery_destruction.rs`
(7/0/0, neu mit `4fe094b`) erzeugt Login, Stale-Quittung, Re-Grant samt
Recovery-Probe, Clock-Release und Vernichtungsanfrage mit gesetzten Canaries
und durchsucht jede Datei, jede signierte Auditzeile und jede Diagnoseausgabe
roh, hex und base64 — ohne Fund. Nicht in-process erzeugbar und im Dateikopf
benannt: Bindungs-/Widerrufs- und Zeremonie-Audits (fuer den Widerruf traegt
`the_revocation_audit_carries_no_operator_plaintext` die Klartextpruefung),
die `recoveryTest`-Zeile der nativen Laufzeit, die Vernichtung nach der
Anfrage, Operator-Identitaet im Export-Audit sowie CLI-, UI- und
Serverprotokolle. Korrigiert: `privacy_canaries_writer.rs` (4/0/0) prueft nur
fachliche Writer-Canaries, und `apps/cli/tests/safety_audit.rs` ist kein
signiertes Auditereignis.

Offen: das Audit der abgelaufenen Sitzung (Abschnitt 1, AK 53) und das native
Clock-Release-Audit (Abschnitt 4).

## 6. Geraete-Posture in drei Zustaenden

| Zustand | Zusage | Zeuge | Stand |
|---|---|---|---|
| Pass | Oeffnet eine Produktionssitzung; der Stale-Writer verlangt genau dieses strikte Pass | `crates/ea-trust/tests/stale_writer_registry.rs` und nativ `process_native::posture::` | 5/0/0; `process_native::posture` (Filter schliesst `posture_document` ein) 16/0/0 in 26 s |
| Fail | Blockiert eine Produktionssitzung, ausnahmslos | `apps/cli/tests/operator_posture_document/mod.rs::actual_cli_target_issue_import_uses_native_admin_and_real_host_measurements` — misst den Host echt und belegt auf einem FAIL-Host die Verweigerung: Exit 12, `EA-OPERATOR-POSTURE`, kein `target.json`. Korrigiert: `apps/cli/tests/operator_administration/host.rs` enthaelt diesen Pfad nicht | Auf dem Gate-Laeufer belegt (Diag-Lauf 34876674848): `/` ist dort `/dev/sda1` mit der Kette `part`, `disk`, ohne `crypt`, also FDE gemessen FAIL; auf macOS (FDE an) laeuft derselbe Zeuge den Positivpfad |
| Unknown | Bleibt fuer den Go-live sichtbar ungeloest, auch mit signiertem Dokument; darf aber eine Sitzung oeffnen | `process_native::posture_document::signed_native_posture_document_allows_admission_after_real_reopen_without_relabeling_unknown` (Sitzung oeffnet, `session_admitted`), `crates/ea-admin/src/go_live.rs::a_documented_unknown_posture_row_stays_unresolved_and_blocks_production_ready` und `crates/ea-key-provider/tests/device_posture.rs` (`DevicePostureProviderFake::unknown`) | in 16/0/0; `ea-admin --lib` 83/0/0; 7/0/0 |

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
| FR-120 | Nachtrag als neuer Ketteneintrag | `crates/ea-admin/tests/amendment.rs` (1/0/0), verwandt mit AK 18 |
| FR-121 | Nachtragskette und gemeinsame Anzeige | `crates/ea-admin/tests/amendment.rs::amendment_finalization_preserves_original_bytes_and_reader_keeps_multiple_amendments` (1/0/0) |
| FR-123 | Vernichtungszustaende und ihre Uebergaenge | `process_native::destruction::completion::` und `::pending::` (in 52/0/0); Zustand 4 entsteht nie implizit, sondern nur ueber die bestaetigte Aktion `destruction_mark_incomplete` (`ebb6e03`), Zeuge `apps/desktop/src-tauri/tests/destruction_commands.rs` (9/0/0) |
| FR-124 | Signierte Loeschattestierung je Replik | `process_native::destruction::completion::native_completion_accepts_backup_only_after_expiry_and_attested_removal` (in 52/0/0). Korrigiert: `custodian.rs` belegt nur die unabhaengige Custodian-Praesenz |
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
**Audit der abgelaufenen Sitzung fehlt im Produkt — Entscheidung offen.**
`design.md` Zeile 2169 verlangt, dass eine abgelaufene Sitzung abgelehnt UND
klartextfrei auditiert wird. Gemessen wird sie nur abgelehnt:
`crates/ea-admin/src/root_ceremony.rs:279` bricht mit `ReauthMismatch` ab,
bevor `book_failure` erreicht wird, `validate_freshness` in
`crates/ea-admin/src/operator_runtime.rs` liefert `EA-OPERATOR-RUNTIME-EXPIRED`
ohne Audit, und `LocalAuditActionV1` kennt keine Aktion dafuer. Der Zeuge
`crates/ea-admin/tests/operator_audit.rs::an_expired_operator_session_is_refused_and_audited_without_plaintext`
ist mit `#[ignore = "DRK-282: …"]` geparkt. Bis zur Entscheidung — Auditaktion
nachruesten oder Zusage auf den Widerruf beschraenken — kann AK-53 nicht
wandern.

**Nativer Clock-Release — Anwendung offen.** Siehe Abschnitt 4. Bis dahin
fehlt das native Clock-Release-Audit aus Abschnitt 5.

**Zwei Systemziele aus Plan Task 14 nicht gebaut.**
`e2e_organization_lifecycle.rs` und `e2e_recovery_fresh_machine.rs` (siehe
Abschnitt 3). Ihre Einzelzusagen sind in Abschnitt 1 belegt; ob die beiden
buendelnden Ziele vor dem Schliessen noch entstehen, ist offen.

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
