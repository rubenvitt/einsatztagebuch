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
Zusage WOERTLICH prueft, und die Zahl, die er auf dem Endstand dieses PRs
gemessen hat (macOS, Toolchain 1.95.0, `bestanden/fehlgeschlagen/ignoriert`
je Testziel; Zeiten sind Testzeit ohne Build).
Eine Zeugenpruefung vom selben Tag hat gezeigt, dass die erste Fassung bei
rund der Haelfte der Zellen einen Zeugen nannte, der die Zusage nicht oder nur
teilweise prueft; diese Zellen sind korrigiert, der fruehere Zeuge steht
jeweils mit dem, was er tatsaechlich belegt, dabei. Zusagen ohne jeden Test
haben ihn in diesem PR bekommen (`8444a83`, `9d3716f`, `fad9c7a`,
`37a3301`), die Klartextsuche ueber die Stufe-5-Audits mit `4fe094b`.
Die Einzelzusagen aus Plan Task 14 Step 3 stehen zusaetzlich in Abschnitt 3.

Der Ledger bleibt trotzdem der Riegel: die neunzehn Zeilen stehen auf
`planned`, und `stage-gate 5` bleibt rot, bis die drei in `## Dokumentierte
Grenzen` genannten Produktluecken dieser Stufe geschlossen sind — der native
Clock-Release, das Audit der abgelaufenen Sitzung und die Einstufung zum
Restnachweis im Go-live-Bericht. Wo eine Zelle `Offen` sagt, ist das eine
dieser drei Luecken und keine fehlende Messung.

## 1. Primaere Abnahmekriterien und ihre Belege

Die vierzehn primaeren Abnahmekriterien der Stufe 5 nach `design.md` Abschnitt
23. Die vierte Spalte ist keine Formsache: eine leere Zelle waere genau die
Scheinzusage, die dieser Bericht ausschliesst, und `run_stage_five_gate` weist
sie ab.

| Kriterium | Gegenstand | Beleg | Offen in spaeterer Stufe |
|---|---|---|---|
| AK 11 | Widerruf | `tests/ea-system-tests/tests/e2e_registry_effectiveness.rs::a_revocation_stops_new_grants_from_its_effective_sequence_and_leaves_the_earlier_grant_intact` (7/0/0) und `crates/ea-admin/tests/registry_workflows.rs::a_revocation_recalls_nothing_and_stops_only_new_grants` (20/0/0) — ein widerrufener Reader erhaelt ab der wirksamen Sequenz keine neuen Grants, der fruehere bleibt unberuehrt. Korrigiert: `operator_revocation_recovery.rs` (2/0/0) belegt nur den eingefrorenen Widerrufsauftrag | Die quartalsweise Uebung des Widerrufs bleibt Stufe 7 |
| AK 12 | Historischer Zugriff | `crates/ea-recovery/tests/historical_grant.rs::of_two_old_entries_only_the_selected_one_opens_for_the_new_reader_after_the_regrant` (neu mit `fad9c7a`) — zwei alte Eintraege, der Re-Grant nennt nur einen: danach genau ein Grant fuer ihn, keiner fuer den anderen, ein dritter Schluessel bekommt nichts, beide `.eip` byte-gleich; die Mutationen an den Filtern `crates/ea-verify/src/archive.rs:686/687` machen nur ihn rot. Dazu `a_new_reader_opens_the_selected_old_entry_only_after_the_recovery_regrant` (`8444a83`). Ziel 8/0/0. Gegen den Server: `tests/ea-system-tests/tests/e2e_historical_grant.rs` (1/0/0, mit `xtask integration up`) | Die Custody der Produktionsschluessel fuer den Re-Grant bleibt Stufe 7 |
| AK 18 | Nachtrag | `crates/ea-admin/tests/amendment.rs::amendment_finalization_preserves_original_bytes_and_reader_keeps_multiple_amendments` (1/0/0) — der Nachtrag referenziert das Original und aendert keine Originalbytes | Die Anzeige mehrerer verketteter Nachtraege im Browser-Reader liegt in Stufe 4 und wird hier nicht erneut belegt |
| AK 24 | Registry-Ueberalterung | `crates/ea-admin/tests/registry_workflows.rs` (20/0/0: Pflichtfelder ueber `a_head_without_issued_at_not_before_or_not_after_is_refused_by_the_decoder` mit `EA-FORMAT-SHAPE`, neu mit `9d3716f`; `the_sequence_lease_boundary_is_exact`, `an_expired_head_blocks_fail_closed`) und fuer Standard-`warn` `crates/ea-writer/tests/stale_registry_acknowledgement.rs::standard_warn_persists_a_signed_receipt_before_finalizing_once` (19/0/0) mit `stale_registry_warning.rs` (4/0/0). Korrigiert: `apps/cli/tests/registry_workflows.rs` (56/0/0) belegt Widerrufsplan und Clock-Release-Grammatik, nicht warn/block | Die Betriebsentscheidung ueber die Altersrichtlinie einer echten Organisation bleibt Stufe 7 |
| AK 29 | Rollentrennung | `crates/ea-key-provider/tests/writer_role_guard.rs::writer_profile_rejects_forbidden_private_key_purposes` (8/0/0) — Writer-Profile verweigern Reader-, Recovery-, Historical-Grant-Authority- und Key-Approver-Privatschluessel; dass lokal genannte Faehigkeiten keine Rolle erweitern, belegt `::a_writer_certificate_capability_is_decided_against_the_parsed_allowlist` (`EA-KEY-FORBIDDEN-CAPABILITY` fuer jede Nicht-Writer-Faehigkeit). Korrigiert: `privacy_canaries_writer.rs` und `operator_trust_store.rs` pruefen keine Schluesselrollen | Die installierte OS-Praesenz auf einem Produktionsgeraet bleibt Stufe 7 |
| AK 30 | Kontrollierte Vernichtung | Zwei Approver: `crates/ea-destruction/tests/authorization.rs` (10/0/0). Alle bekannten Speicherorte und Backupfristen: `process_native::destruction::completion::` (4 Tests), unerreichbare Replikate: `::failure::` (7 Tests), backup-pending: `::pending::` (8 Tests), sofortiger Abschluss: `::completion::native_completion_requires_every_duty_then_persists_exact_signed_transition_and_replays`, Fortsetzen: `native_destruction_local_resume_removes_real_eip_grants_and_reopens_measured_attestation`; das Ziel `einsatzarchiv-cli --test operator process_native::destruction::` liest 52/0/0 in 1335 s seriell | Die externe Datenschutzentscheidung zum Restnachweis bleibt Stufe 7 |
| AK 35 | Registry-Angriffe | `tests/ea-system-tests/tests/e2e_registry_effectiveness.rs::a_rollback_a_same_version_fork_and_an_expired_head_block_the_line` — Rollback und gleiche Version mit anderem Hash fail-closed; `::the_trusted_time_floor_rises_with_an_accepted_head_and_neither_a_clock_rollback_nor_an_older_head_lowers_it` (neu mit `fad9c7a`) — der Floor steigt auf das `issuedAt` des angenommenen Kopfes und sinkt weder bei Uhrruecklauf noch mit einem neueren Kopf aelterer Zeit; Ziel 7/0/0. Upload-Ablehnung bei einem zurueckgehaltenen, dem Server bekannten Kopf: `apps/server/tests/commit_failures.rs::a_package_binding_an_older_head_names_the_required_head` (17/0/0, mit `xtask integration up`) | Das nicht erkennbare Offline-Fenster ist eine dokumentierte Grenze des Designs, keine Stufenluecke |
| AK 40 | Historische Grant-Autoritaet | `crates/ea-recovery/tests/historical_grant.rs::separate_key_roles_recipient_native_presence_and_durable_audit_are_required` (8/0/0) fuer getrennte Recovery-KEM und Grant-Signatur, `crates/ea-trust/tests/grant_authorization.rs` (5/0/0) fuer die Mehr-Augen-Authorization; Server-Pfad `e2e_historical_grant.rs` (1/0/0) | Die Custody der Produktionsschluessel bleibt Stufe 7 |
| AK 41 | Destroyed Entry Stub | `process_native::destruction::writer_evidence::native_writer_evidence_reopens_as_real_reader_authorized_destruction` (in 52/0/0) — gueltiger `.eds` mit Writer-Signatur, `entryHash` und Kettenkontinuitaet; die nicht autorisierte Entfernung als sichtbare Luecke: `crates/ea-verify/tests/destruction_stub.rs` (8/0/0) und `receipt_checkpoint.rs` (3/0/0) | Die nativen Minimal- und Maximalfaelle des Stubs bleiben Stufe 7 |
| AK 44 | Datenschutz-Gate | `tests/ea-system-tests/tests/e2e_destruction_policy.rs::real_current_progress_privacy_gate_exact_replay_and_transaction_fence` (1/0/0, `EA-DESTRUCTION-PRIVACY-GATE`), dazu `e2e_destruction_admission_race.rs` (4/0/0) und `e2e_destruction_catalog_race.rs` (1/0/0), alle mit `xtask integration up` — ohne dokumentierte Freigabe startet kein `.eds`-basierter Vernichtungsprozess. Go-live-Bericht mit Einstufung und Entscheidung zum Restnachweis: `crates/ea-admin/tests/go_live.rs::the_eds_privacy_row_classifies_the_signed_retention_policy` (Anforderung `EA-GOLIVE-EDS-PRIVACY-DECISION` aus `retention_policy.destruction_enabled` und `.eds_privacy_decision_document_hash` des gewählten Kopfes — dieselben signierten Felder wie das Gate; „Restnachweis freigegeben" mit Dokumenthash, „Vernichtung deaktiviert", aktiviert ohne Freigabe `NotMet`), `::flipping_any_single_requirement_flips_production_ready_to_false` und `::the_decision_document_hash_never_enters_the_unresolved_report` (Ziel 12/0/0) | Die externe Datenschutzentscheidung selbst bleibt Stufe 7; das Gate belegt nur, dass ohne sie nichts startet |
| AK 47 | Organisationsadministration | `crates/ea-admin/tests/authorization.rs` (16/0/0: Root-only, Admin-only, falscher Core und — neu mit `8444a83` — `a_self_rotation_of_the_signing_admin_never_reaches_the_key_port` mit `EA-TRUST-SELF-AUTHORIZATION`), `::root_ceremony.rs` (7/0/0, Einmaligkeit), `::ceremony_steps.rs` (7/0/0), `apps/cli/tests/organization_certify_root.rs` (4/0/0). Nullkontext (gepinntes Admin-Paar vor der Registry, finaler Anchor bindet dieselben Felder, danach keine weitere Nutzung): `crates/ea-trust/tests/bootstrap.rs` (8/0/0), `::certificate_attacks.rs` (14/0/0), `::registry_attacks.rs` (12/0/0), `crates/ea-admin/tests/bootstrap.rs` (53/0/0) | Der Transport-Fingerprint-Anteil haengt an `WR-075` und bleibt bis DRK-318 offen |
| AK 49 | Registry-Wirksamkeit | `crates/ea-admin/tests/registry_workflows.rs::the_workflow_selects_the_highest_applicable_head` und `::a_wrong_previous_head_blocks` (20/0/0), fuer Forks und future-only Heads `e2e_registry_effectiveness.rs` (7/0/0); den neueren wirksamen Head am Server erzwingen `apps/server/tests/auth_trust_api.rs::a_registry_event_that_is_not_the_next_head_names_the_head_that_is`, `::a_selected_head_behind_the_persisted_pin_is_refused` (13/0/0) und `commit_failures.rs::a_package_binding_an_older_head_names_the_required_head` (17/0/0), beide mit `xtask integration up` | Die unvermeidbare Offline-Grenze ist dokumentiert und bleibt bestehen |
| AK 52 | Gefuehrter Recovery-Test | `crates/ea-admin/tests/bootstrap.rs::a_partial_recovery_test_never_becomes_a_successful_one` (53/0/0, `EA-CEREMONY-RECOVERY-TEST-FAILED` bei einem fehlenden Medium) und `crates/ea-recovery/tests/recovery_test.rs::real_backup_challenges_are_fresh_bound_to_the_signed_certificate_and_never_productive` (6/0/0). Nativ bindet `process_native::recovery::native_source_capture_binds_real_snapshot_machine_inventory_and_signed_audit_without_readiness` Inventar und signiertes Audit (1/0/0). Die sechs nativen Zeugen `process_native::recovery::guided::` sind `#[ignore]`, weil sie eine echte Fremdmaschine verlangen (0/0/6). Korrigiert: `recovery_input_profiles.rs`, `backup_key.rs`, `offline_sources.rs` belegen Eingabeprofile, KDF und Parser | Die Fremdmaschine der nativen guided-Zeugen und die quartalsweise Uebung bleiben Stufe 7 |
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
`apps/cli/tests/operator_administration/`, `apps/cli/tests/operator_desktop/`,
`apps/cli/tests/operator_posture/`,
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

**Einzelzusagen aus Plan Task 14 Step 3.** Der Plan buendelt sie in zwei
Systemzielen, `tests/ea-system-tests/tests/e2e_organization_lifecycle.rs` und
`e2e_recovery_fresh_machine.rs`, die es NICHT gibt (siehe `## Dokumentierte
Grenzen`). Die Einzelzusagen haben folgende Zeugen:

| Zusage aus Step 3 | Zeuge | Messung |
|---|---|---|
| Bootstrap bis zur Recovery-Bereitschaft | `crates/ea-admin/tests/bootstrap.rs::production_state_requires_all_twelve_steps_and_fresh_recovery` | 53/0/0 |
| Ausstehende Aktivierung von Geraet, Fingerprint, Admin, Root | `crates/ea-admin/tests/registry_workflows.rs`, `::fingerprint.rs`, `::ceremony_steps.rs::device_approve_walks_all_six_steps_in_order` | 20/0/0, 5/0/0, 7/0/0 |
| Widerrufsgrenze des Readers | AK 11 | siehe Abschnitt 1 |
| Registry warn/block/Lease/Rollback/Fork/Zeitboden | AK 24, AK 35, AK 49 | siehe Abschnitt 1 |
| Exakte, ablaufende, einmalige Clock-Freigabe | `crates/ea-admin/tests/clock_release.rs::a_release_is_issued_once_consumed_once_and_replayed_never` (in-process); nativ offen | 18/0/0 |
| Writer-Uebergang | `crates/ea-admin/tests/writer_transition.rs` | 15/0/0 |
| Nachtrag | AK 18, FR-120 bis FR-124 | siehe Abschnitt 1 und Ledgerpflege |
| Neuer Reader ohne vergangenen Zugriff, ausgewaehlter Re-Grant | AK 12 | siehe Abschnitt 1 |
| Ablauf bei Erzeugung, Annahme, Auslieferung, Oeffnen | `tests/ea-system-tests/tests/e2e_historical_grant.rs::create_upload_deliver_open_and_replay_after_expiry` und `crates/ea-recovery/tests/historical_grant.rs` | 1/0/0 (mit `integration up`), 8/0/0 |
| Jede Backup-Probe im Recovery-Test | AK 52 | siehe Abschnitt 1 |
| Gueltiger und ungueltiger Anchor | `crates/ea-admin/tests/anchor_integrity.rs` | 33/0/0 |
| Vernichtung ohne Datenschutzfreigabe | AK 44 | siehe Abschnitt 1 |
| Zwei Approver; sofort, backup-pending, unerreichbar, Fortsetzen | AK 30 | siehe Abschnitt 1 |
| Gueltiger Stub gegen unerklaerte Loeschung | AK 41 | siehe Abschnitt 1 |
| Signierte Auditereignisse | Abschnitt 5 | — |
| Posture Pass, Fail, Unknown | Abschnitt 6 | — |
| Klartextsuche ueber Admin/CLI/UI/Server | `privacy_canaries_admin_recovery_destruction.rs` mit den dort benannten Luecken | 7/0/0 |

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
| Admin- und Rootzeremonien | `crates/ea-admin/tests/root_ceremony.rs` (Audit je Veroeffentlichung; `ceremony_steps.rs` prueft nur die Schrittfolge) | 7/0/0 |
| Stale-Registry-Quittung | `crates/ea-writer/tests/stale_registry_acknowledgement.rs` | 19/0/0 |
| Export | `crates/ea-reader/tests/export.rs`, `audit_redaction.rs` (`PlaintextExport`) | 9/0/0 und 5/0/0 |
| Clock-Release | `crates/ea-admin/tests/clock_release.rs::a_release_is_issued_once_consumed_once_and_replayed_never` (in-process) | 18/0/0; der native Pfad ist offen, siehe Abschnitt 4 |
| Recovery-Test | `process_native::recovery::native_source_capture_binds_real_snapshot_machine_inventory_and_signed_audit_without_readiness` — die signierte `recoveryTest`-Zeile schreibt nur die native Laufzeit | 1/0/0 |
| Re-Grant | `crates/ea-recovery/tests/historical_grant.rs` | 8/0/0 |
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
| Pass | Oeffnet eine Produktionssitzung; der Stale-Writer verlangt genau dieses strikte Pass | `process_native::desktop::stale_writer_opens_only_on_measured_pass_never_on_unknown_or_fail` (nur mit `--features desktop-fixture`, neu mit `37a3301`) — echte Installation mit abgelaufener Registry: Pass oeffnet genau den Stale-Writer, jede der vier Anforderungen auf Unknown oder Fail endet mit `EA-OPERATOR-POSTURE`; die gewoehnliche Sitzung oeffnet bei Pass in `process_native::posture::` | 1/0/0 (1,9 s); 16/0/0 (25 s) |
| Fail | Blockiert eine Produktionssitzung, ausnahmslos | `process_native::posture::each_failed_or_unresolved_posture_denies_a_real_native_session` — jede Anforderung auf Fail (und auf Unknown ohne Dokument) verweigert die native Sitzung mit `EA-OPERATOR-POSTURE`, `session_admitted == false`, Belegcode unveraendert. Dass Fail sich nicht dokumentieren laesst, belegt `process_native::posture_document::actual_cli_target_issue_import_uses_native_admin_and_real_host_measurements` auf dem Gate-Laeufer (Diag-Lauf 34876674848: `/dev/sda1` ohne `crypt`, FDE FAIL, Exit 12, kein `target.json`). Korrigiert: `operator_administration/host.rs` enthaelt keinen dieser Pfade | in 16/0/0 (25 s) |
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
FR-124 und WR-075 haben kein primaeres Kriterium (FR-120 bis FR-124 nennen
AK 18 nur als verwandtes Kriterium) und brauchen
eigene Gate-Logik. Der Grund ist gemessen: die Belegrechnung der Stufen 2 bis 4
filtert ueber `!row.primary_acceptance_criterion.is_empty()` und zaehlt eine
Zeile ohne Kriterium WEDER als belegt NOCH als Mangel — sie faellt lautlos aus
der Rechnung. `run_stage_five_gate` verlangt sie deshalb namentlich in diesem
Bericht.

| Zeile | Gegenstand | Beleg |
|---|---|---|
| FR-120 | Nachtrag als neuer Ketteneintrag | `crates/ea-admin/tests/amendment.rs` (1/0/0), verwandt mit AK 18 |
| FR-121 | Original-ID/-Hash, Grund, Ersteller | `crates/ea-admin/tests/amendment.rs::amendment_finalization_preserves_original_bytes_and_reader_keeps_multiple_amendments` (1/0/0) liest Original-ID, Original-Hash, Sequenz, Grund und Ersteller aus den verifizierten und entschluesselten Bytes (`9d3716f`) |
| FR-123 | Original nicht aendern/verbergen | `crates/ea-admin/tests/amendment.rs` (1/0/0) — Originalbytes vor und nach dem Nachtrag identisch, der Reader zeigt Original und Nachtraege gemeinsam |
| FR-124 | Mehrere Nachtraege unterstuetzen | `crates/ea-admin/tests/amendment.rs` (1/0/0) — zwei Nachtraege auf dasselbe Original, der Reader haelt beide (`amendments().len() == 2`) |
| WR-075 | Re-Encryption nur bei Uebereinstimmung mit dem gebundenen Transport-Key-Fingerprint | Dokumentierte Grenze, siehe unten |

## Dokumentierte Grenzen

Diese Stufe schliesst als erste mit einer offenen Ledgerzeile. Jede Grenze
hat ein besitzendes Ticket; eine Grenze ohne Besitzer waere keine Grenze,
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
**Audit der abgelaufenen Sitzung fehlt im Produkt — besitzendes Ticket
DRK-282, Entscheidung offen.**
`design.md` Zeile 2169 verlangt, dass eine abgelaufene Sitzung abgelehnt UND
klartextfrei auditiert wird. Gemessen wird sie nur abgelehnt:
`crates/ea-admin/src/root_ceremony.rs:279` bricht mit `ReauthMismatch` ab,
bevor `book_failure` erreicht wird, `reauthenticate_with_context` prueft
ueber `ensure_current()` (`crates/ea-admin/src/operator_runtime.rs:742`) die
Frische vor dem auditierten Abschnitt und liefert
`EA-OPERATOR-RUNTIME-EXPIRED` ohne Audit (nur ein Ablauf WAEHREND der
Praesenzabfrage bucht Login(Failed) und ReauthFailure, nicht als Ablauf), und `LocalAuditActionV1` kennt keine Aktion dafuer. Der Zeuge
`crates/ea-admin/tests/operator_audit.rs::an_expired_operator_session_is_refused_and_audited_without_plaintext`
ist mit `#[ignore = "DRK-282: …"]` geparkt. Bis zur Entscheidung — Auditaktion
nachruesten oder Zusage auf den Widerruf beschraenken — kann AK-53 nicht
wandern.

**Nativer Clock-Release — besitzendes Ticket DRK-282, Anwendung offen.**
Siehe Abschnitt 4. Bis dahin
fehlt das native Clock-Release-Audit aus Abschnitt 5.

**Zwei Systemziele aus Plan Task 14 nicht gebaut — besitzendes Ticket
DRK-282.** `e2e_organization_lifecycle.rs` und `e2e_recovery_fresh_machine.rs`
(siehe Abschnitt 3). Ihre Einzelzusagen haben die dort aufgefuehrten Zeugen;
ob die beiden buendelnden Ziele vor dem Schliessen noch entstehen, ist offen.

**Go-live-Bericht mit Einstufung zum Restnachweis — erledigt in DRK-282
(Branch `drk-282-golive-privacy`).** `GoLiveChecklist` führt als sechzehnte
Anforderung `EA-GOLIVE-EDS-PRIVACY-DECISION`, abgeleitet ausschließlich aus der
Root-signierten `retention_policy` des gewählten Kopfes — denselben Feldern, die
das Vernichtungs-Gate liest; Bericht und Gate können nicht auseinanderlaufen.
Einstufung als Belegcode (`EA-GOLIVE-EVIDENCE-EDS-RESIDUAL-RELEASED`,
`…-EDS-DESTRUCTION-DISABLED`, `…-EDS-PRIVACY-DECISION-MISSING`), Entscheidung als
signierter Dokumenthash in der Zeile. Aktivierte Vernichtung ohne Freigabe hält
`production_ready` auf `false`. Die externe Datenschutzentscheidung selbst und
ihre rechtliche Bewertung bleiben Stufe 7.

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
