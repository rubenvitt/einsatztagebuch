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

**Das Gate schliesst (DRK-282, 2026-09-19).** Die drei Produktluecken, an
denen der Ledger bis hierher als Riegel hing — der native Clock-Release
(`5e055d0`, `59b08ac`, `8dae049`), das Audit der abgelaufenen Sitzung
(`96e0c3c`) und die Einstufung zum Restnachweis im Go-live-Bericht
(`2d52b5e`) —, sind geschlossen. Achtzehn der neunzehn Zeilen stehen jetzt
auf `implemented` oder `integrated` (Begruendung je Zeile in `## Ledgerpflege`),
WR-075 bleibt als dokumentierte Grenze auf `planned`, und
`cargo run --locked -p xtask -- stage-gate 5` endet mit Exit 0. Keine Zelle
dieses Berichts sagt mehr `Offen`; was offen bleibt, steht mit Besitzer in
`## Dokumentierte Grenzen` oder in der Spalte „Offen in spaeterer Stufe".

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
| AK 30 | Kontrollierte Vernichtung | Zwei Approver: `crates/ea-destruction/tests/authorization.rs` (10/0/0). Alle bekannten Speicherorte und Backupfristen: `process_native::destruction::completion::` (4 Tests), unerreichbare Replikate: `::failure::` (7 Tests), backup-pending: `::pending::` (8 Tests), sofortiger Abschluss: `::completion::native_completion_requires_every_duty_then_persists_exact_signed_transition_and_replays`, Fortsetzen: `native_destruction_local_resume_removes_real_eip_grants_and_reopens_measured_attestation`; das Ziel `einsatzarchiv-cli --test operator process_native::destruction::` liest 52/0/0 in 1335 s seriell (Messung vor dem nativen Retry). Retry aus Zustand 4 nach 1 fuer servergebundene Pflichten (DRK-319, Erzeuger `crates/ea-admin/src/destruction_runtime/retry.rs`): `process_native::destruction::retry::native_retry_resumes_a_server_bound_incomplete_once_every_duty_is_confirmed`, verweigernd `::retry::native_retry_refuses_when_the_open_duty_was_a_reader` und `::retry::native_retry_refuses_an_open_server_duty_missing_server_and_failed_reservation`; gegen denselben neu gestarteten TLS-Server mit PostgreSQL und S3 `::transport::server::retry::native_retry_survives_a_listener_loss_between_its_reads_and_resumes_once_after_the_same_server_restarts`, `::transport::server::retry::native_retry_replays_the_committed_4_to_1_over_tls_after_its_publication_failed` und ueber den Desktop-Pfad `::transport::server::host::retry::native_desktop_resume_in_state4_chains_the_retry_and_completes_against_the_restarted_server` (die `transport::server::`-Zeugen nur mit `--features desktop-fixture`); mit diesem Merkmal las das Ziel in der Messung des Folge-PRs vor dem Rebase 99/0/1 seriell | Die externe Datenschutzentscheidung zum Restnachweis bleibt Stufe 7; Reader-Faelle bleiben nach Ruling G1 in v0.1 dauerhaft in `incompleteUnreachableReplica` (`## Dokumentierte Grenzen`) |
| AK 35 | Registry-Angriffe | `tests/ea-system-tests/tests/e2e_registry_effectiveness.rs::a_rollback_a_same_version_fork_and_an_expired_head_block_the_line` — Rollback und gleiche Version mit anderem Hash fail-closed; `::the_trusted_time_floor_rises_with_an_accepted_head_and_neither_a_clock_rollback_nor_an_older_head_lowers_it` (neu mit `fad9c7a`) — der Floor steigt auf das `issuedAt` des angenommenen Kopfes und sinkt weder bei Uhrruecklauf noch mit einem neueren Kopf aelterer Zeit; Ziel 7/0/0. Upload-Ablehnung bei einem zurueckgehaltenen, dem Server bekannten Kopf: `apps/server/tests/commit_failures.rs::a_package_binding_an_older_head_names_the_required_head` (17/0/0, mit `xtask integration up`) | Das nicht erkennbare Offline-Fenster ist eine dokumentierte Grenze des Designs, keine Stufenluecke |
| AK 40 | Historische Grant-Autoritaet | `crates/ea-recovery/tests/historical_grant.rs::separate_key_roles_recipient_native_presence_and_durable_audit_are_required` (8/0/0) fuer getrennte Recovery-KEM und Grant-Signatur, `crates/ea-trust/tests/grant_authorization.rs` (5/0/0) fuer die Mehr-Augen-Authorization; Server-Pfad `e2e_historical_grant.rs` (1/0/0) | Die Custody der Produktionsschluessel bleibt Stufe 7 |
| AK 41 | Destroyed Entry Stub | `process_native::destruction::writer_evidence::native_writer_evidence_reopens_as_real_reader_authorized_destruction` (in 52/0/0) — gueltiger `.eds` mit Writer-Signatur, `entryHash` und Kettenkontinuitaet; die nicht autorisierte Entfernung als sichtbare Luecke: `crates/ea-verify/tests/destruction_stub.rs` (8/0/0) und `receipt_checkpoint.rs` (3/0/0) | Die nativen Minimal- und Maximalfaelle des Stubs bleiben Stufe 7 |
| AK 44 | Datenschutz-Gate | `tests/ea-system-tests/tests/e2e_destruction_policy.rs::real_current_progress_privacy_gate_exact_replay_and_transaction_fence` (1/0/0, `EA-DESTRUCTION-PRIVACY-GATE`), dazu `e2e_destruction_admission_race.rs` (4/0/0) und `e2e_destruction_catalog_race.rs` (1/0/0), alle mit `xtask integration up` — ohne dokumentierte Freigabe startet kein `.eds`-basierter Vernichtungsprozess. Go-live-Bericht mit Einstufung und Entscheidung zum Restnachweis: `crates/ea-admin/tests/go_live.rs::the_eds_privacy_row_classifies_the_signed_retention_policy` (Anforderung `EA-GOLIVE-EDS-PRIVACY-DECISION` aus `retention_policy.destruction_enabled` und `.eds_privacy_decision_document_hash` des gewählten Kopfes — dieselben signierten Felder wie das Gate; „Restnachweis freigegeben" mit Dokumenthash, „Vernichtung deaktiviert", aktiviert ohne Freigabe `NotMet`), `::flipping_any_single_requirement_flips_production_ready_to_false` und `::the_decision_document_hash_never_enters_the_unresolved_report` (Ziel 12/0/0) | Die externe Datenschutzentscheidung selbst bleibt Stufe 7; das Gate belegt nur, dass ohne sie nichts startet |
| AK 47 | Organisationsadministration | `crates/ea-admin/tests/authorization.rs` (16/0/0: Root-only, Admin-only, falscher Core und — neu mit `8444a83` — `a_self_rotation_of_the_signing_admin_never_reaches_the_key_port` mit `EA-TRUST-SELF-AUTHORIZATION`), `::root_ceremony.rs` (7/0/0, Einmaligkeit), `::ceremony_steps.rs` (7/0/0), `apps/cli/tests/organization_certify_root.rs` (4/0/0). Nullkontext (gepinntes Admin-Paar vor der Registry, finaler Anchor bindet dieselben Felder, danach keine weitere Nutzung): `crates/ea-trust/tests/bootstrap.rs` (8/0/0), `::certificate_attacks.rs` (14/0/0), `::registry_attacks.rs` (12/0/0), `crates/ea-admin/tests/bootstrap.rs` (53/0/0) | Der Transport-Fingerprint-Anteil haengt an `WR-075` und bleibt bis DRK-318 offen |
| AK 49 | Registry-Wirksamkeit | `crates/ea-admin/tests/registry_workflows.rs::the_workflow_selects_the_highest_applicable_head` und `::a_wrong_previous_head_blocks` (20/0/0), fuer Forks und future-only Heads `e2e_registry_effectiveness.rs` (7/0/0); den neueren wirksamen Head am Server erzwingen `apps/server/tests/auth_trust_api.rs::a_registry_event_that_is_not_the_next_head_names_the_head_that_is`, `::a_selected_head_behind_the_persisted_pin_is_refused` (13/0/0) und `commit_failures.rs::a_package_binding_an_older_head_names_the_required_head` (17/0/0), beide mit `xtask integration up` | Die unvermeidbare Offline-Grenze ist dokumentiert und bleibt bestehen |
| AK 52 | Gefuehrter Recovery-Test | `crates/ea-admin/tests/bootstrap.rs::a_partial_recovery_test_never_becomes_a_successful_one` (53/0/0, `EA-CEREMONY-RECOVERY-TEST-FAILED` bei einem fehlenden Medium) und `crates/ea-recovery/tests/recovery_test.rs::real_backup_challenges_are_fresh_bound_to_the_signed_certificate_and_never_productive` (6/0/0). Nativ bindet `process_native::recovery::native_source_capture_binds_real_snapshot_machine_inventory_and_signed_audit_without_readiness` Inventar und signiertes Audit (1/0/0). Die sechs nativen Zeugen `process_native::recovery::guided::` sind `#[ignore]`, weil sie eine echte Fremdmaschine verlangen (0/0/6). Korrigiert: `recovery_input_profiles.rs`, `backup_key.rs`, `offline_sources.rs` belegen Eingabeprofile, KDF und Parser | Die Fremdmaschine der nativen guided-Zeugen und die quartalsweise Uebung bleiben Stufe 7 |
| AK 53 | Operator-Identitaet | `crates/ea-admin/tests/operator_binding.rs` (21/0/0), `::operator_host.rs` (17/0/0), `::operator_audit.rs` (12/0/0) mit `the_revocation_audit_carries_no_operator_plaintext` (neu, `8444a83`), nativ `process_native::administration::host::` (2/0/0 in 163 s, nur mit `--features desktop-fixture` uebersetzt). Abgelaufene Sitzung (DRK-282): abgelehnt UND als `sessionExpired` (Aktionscode 12, Ausgang `failed`) klartextfrei gebucht — Zeremonie `an_expired_operator_session_is_refused_and_audited_without_plaintext` (entparkt), Gegenproben `a_foreign_purpose_proof_is_refused_without_an_expiry_row` und `an_expired_session_stays_refused_when_its_audit_cannot_be_booked`, Laufzeit `the_runtime_expiry_row_is_device_signed_and_names_only_the_known_binding` und der Modultest `operator_runtime::tests::only_an_expiry_is_booked_once_before_the_unchanged_refusal` (`--lib` 84/0/0); Grenze siehe `## Dokumentierte Grenzen` | Der Ubuntu-UID-Wiederverwendungsfall auf einer installierten OS-Praesenz bleibt Stufe 7; der Transport-Fingerprint-Anteil haengt an `WR-075` |

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
der 90-Minuten-Frist. Das Target `einsatzarchiv-cli --test operator` las auf
`db08333` 213 bestanden, 0 fehlgeschlagen, 25 ignoriert — vor dem nativen
Clock-Release; die Zahlen dieses Endstands stehen in den Abschnitten 1 bis 6.

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
`e2e_recovery_fresh_machine.rs`. Beide sind mit DRK-427 gebaut und lesen je
1/0/0 (0,4 s beziehungsweise 1,0 s Testzeit, ohne Netzdienste). Sie fuehren
KEINE neue Zusage ein: jeder ihrer Abschnitte ruft dieselbe Fassade wie der
Einzelzeuge in der Tabelle unten, und was sie nicht buendeln koennen, steht in
`## Dokumentierte Grenzen`. Die Einzelzusagen haben folgende Zeugen:

| Zusage aus Step 3 | Zeuge | Messung |
|---|---|---|
| Bootstrap bis zur Recovery-Bereitschaft | `crates/ea-admin/tests/bootstrap.rs::production_state_requires_all_twelve_steps_and_fresh_recovery` | 53/0/0 |
| Ausstehende Aktivierung von Geraet, Fingerprint, Admin, Root | `crates/ea-admin/tests/registry_workflows.rs`, `::fingerprint.rs`, `::ceremony_steps.rs::device_approve_walks_all_six_steps_in_order` | 20/0/0, 5/0/0, 7/0/0 |
| Widerrufsgrenze des Readers | AK 11 | siehe Abschnitt 1 |
| Registry warn/block/Lease/Rollback/Fork/Zeitboden | AK 24, AK 35, AK 49 | siehe Abschnitt 1 |
| Exakte, ablaufende, einmalige Clock-Freigabe | `crates/ea-admin/tests/clock_release.rs::a_release_is_issued_once_consumed_once_and_replayed_never` (in-process); nativ `apps/cli/tests/operator_administration/clock_repair.rs` unter `process_native::administration::clock_repair::` (Abschnitt 4) | 18/0/0; nativ 13/0/0 (19 s seriell) |
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

**Nativer Clock-Release — angewendet mit `5e055d0`, `59b08ac` und
`8dae049`.** Freigegeben per Ruling vom 2026-09-13, erneut bestaetigt am
2026-09-19, unter Auflagen: RED-first, Gegenproben fuer Pass, Fail, Ablauf,
Doppelverbrauch und Reopen, unabhaengiges Security-Review, die
`Unknown`-Erweiterung separat. Der gepruefte Patch (SHA256 `08f09b2b…`) ist
unveraendert uebernommen; der native RED in
`apps/cli/tests/operator_administration/clock_repair.rs` ist entparkt (vorher
0/1 am `RuntimeExpired`-Stub, danach gruen). `ClockRepairRuntime::release`
oeffnet die einmalige Freigabe nur bei gemessenem Pass jeder
`PostureRequirement`; Fail und Unknown enden vor jedem Dialog mit
`EA-OPERATOR-POSTURE`. Die `Unknown`-Erweiterung bleibt ausdruecklich
DRAUSSEN: ein dokumentiertes `Unknown` darf nach dem Posture-Ruling eine
gewoehnliche Sitzung oeffnen, den Clock-Pfad oeffnet es nicht.

Das Security-Review hat den Stand `5e055d0`/`59b08ac` als „mit Auflagen
freigabefaehig" bewertet; beide Auflagen setzt `8dae049` um. Erstens: nach dem
dauerhaften Consume (Revision, Replay-Nonce, beide Audits) endet `release`
nicht mehr mit einem Fehler — die Nachpruefungen liegen vollstaendig in
`recheck()` direkt davor. Zweitens: eine wiederholte Freigabe fuer DIESELBE
blockierende Referenz und DENSELBEN gepinnten Head wird beim Oeffnen und am
Anfang von `release` fail-closed mit `EA-SKEW-ALREADY-RELEASED` verweigert,
vor Praesenz und Audit. Ein neuer, weiterhin zu alter Zeitbeleg erlaubt genau
eine weitere, jeweils signiert auditierte Freigabe; dieselben Bytes bleiben
`EA-TRUST-CLOCK-RELEASE-REPLAY`, und der gewoehnliche Reopen mit der alten
Referenz bleibt nach jedem Zyklus `EA-TRUST-FUTURE-SKEW`. Zeuge:
`cargo test --locked -p einsatzarchiv-cli --test operator process_native::administration::clock_repair:: -- --test-threads=1`
13/0/0 in 19 s seriell auf dem Endstand; in-process `ea-admin --test
clock_release` 18/0/0 und `--lib` 84/0/0.

Der aeltere Zeuge `native_clock_repair_after_actual_restart_gap`
(`apps/cli/tests/operator_administration/mod.rs`, aus `f5aec07`) bleibt
`#[ignore]`: er erwartet, dass der GEWOEHNLICHE Reopen nach dem Neustart
gelingt, und widerspricht damit genau der FutureSkew-Grenze, die
`clock_repair.rs` festhaelt. Sein Ignore-Grund nennt das jetzt und verweist
auf den Ersatz.

## 5. Signierte Auditereignisse

Nachzuweisen sind signierte, dauerhafte Auditereignisse fuer: Login,
fehlgeschlagene Reauthentisierung, Bindungsaenderung, Bindungswiderruf, jede
Admin- und Rootzeremonie, die Stale-Registry-Quittung, den Export, den
Clock-Release, den Recovery-Test, den Re-Grant und die Vernichtung.

| Ereignis | Zeuge | Messung |
|---|---|---|
| Login, fehlgeschlagene Reauthentisierung | `crates/ea-admin/tests/operator_audit.rs::failed_login_and_reauth_have_valid_device_signatures_…`, `operator_host.rs::unknown_requested_certificate_still_records_signed_failed_login` | 12/0/0 und 17/0/0 |
| Abgelaufene Sitzung (`sessionExpired`, Code 12, DRK-282) | `operator_audit.rs::an_expired_operator_session_is_refused_and_audited_without_plaintext` (Zeremonie), `::the_runtime_expiry_row_is_device_signed_and_names_only_the_known_binding` (Laufzeit), Vektor `vectors/local-audit/v1/event/accepted-session-expired.bin` | 12/0/0 |
| Bindungsaenderung und -widerruf | `operator_audit.rs::binding_and_revocation_audits_verify_…`, `operator_binding.rs::revocation_signs_the_exact_binding_registry_change_…` | 12/0/0 und 21/0/0 |
| Admin- und Rootzeremonien | `crates/ea-admin/tests/root_ceremony.rs` (Audit je Veroeffentlichung; `ceremony_steps.rs` prueft nur die Schrittfolge) | 7/0/0 |
| Stale-Registry-Quittung | `crates/ea-writer/tests/stale_registry_acknowledgement.rs` | 19/0/0 |
| Export | `crates/ea-reader/tests/export.rs`, `audit_redaction.rs` (`PlaintextExport`) | 9/0/0 und 5/0/0 |
| Clock-Release | `crates/ea-admin/tests/clock_release.rs::a_release_is_issued_once_consumed_once_and_replayed_never` (in-process); nativ `process_native::administration::clock_repair::native_clock_only_restart_persists_audits_consumes_once_and_old_reference_still_blocks_normal_reopen` — `Login`/`Completed` und `ClockSkewRelease`/`Accepted` dauerhaft signiert gebucht, genau ein Consume; die Gegenproben `native_clock_repair_failed_login_audit_transaction_records_no_presence_and_releases_no_bytes` und `native_clock_repair_failed_release_audit_transaction_releases_no_bytes_and_no_consume` belegen, dass ohne dauerhaftes Audit nichts freigegeben wird | 18/0/0; nativ 13/0/0 |
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

## 6. Geraete-Posture in drei Zustaenden

| Zustand | Zusage | Zeuge | Stand |
|---|---|---|---|
| Pass | Oeffnet eine Produktionssitzung; der Stale-Writer verlangt genau dieses strikte Pass | `process_native::desktop::stale_writer_opens_only_on_measured_pass_never_on_unknown_or_fail` (nur mit `--features desktop-fixture`, neu mit `37a3301`) — echte Installation mit abgelaufener Registry: Pass oeffnet genau den Stale-Writer, jede der vier Anforderungen auf Unknown oder Fail endet mit `EA-OPERATOR-POSTURE`; die gewoehnliche Sitzung oeffnet bei Pass in `process_native::posture::` | 1/0/0 (1,9 s); 16/0/0 (25 s) |
| Fail | Blockiert eine Produktionssitzung, ausnahmslos | `process_native::posture::each_failed_or_unresolved_posture_denies_a_real_native_session` — jede Anforderung auf Fail (und auf Unknown ohne Dokument) verweigert die native Sitzung mit `EA-OPERATOR-POSTURE`, `session_admitted == false`, Belegcode unveraendert. Dass Fail sich nicht dokumentieren laesst, belegt `process_native::posture_document::actual_cli_target_issue_import_uses_native_admin_and_real_host_measurements` auf dem Gate-Laeufer (Diag-Lauf 34876674848: `/dev/sda1` ohne `crypt`, FDE FAIL, Exit 12, kein `target.json`). Korrigiert: `operator_administration/host.rs` enthaelt keinen dieser Pfade | in 16/0/0 (25 s) |
| Unknown | Bleibt fuer den Go-live sichtbar ungeloest, auch mit signiertem Dokument; darf aber eine Sitzung oeffnen | `process_native::posture_document::signed_native_posture_document_allows_admission_after_real_reopen_without_relabeling_unknown` (Sitzung oeffnet, `session_admitted`), `crates/ea-admin/src/go_live.rs::a_documented_unknown_posture_row_stays_unresolved_and_blocks_production_ready` und `crates/ea-key-provider/tests/device_posture.rs` (`DevicePostureProviderFake::unknown`) | in 16/0/0; `ea-admin --lib` 84/0/0; 7/0/0 |

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
rot; PR #22 hat deshalb keine Zeile bewegt. DRK-282 bewegt achtzehn Zeilen;
WR-075 bleibt `planned` (siehe `## Dokumentierte Grenzen`).

**Die Regel `implemented` gegen `integrated`.** Sie folgt den Stufen 3 und 4
und nicht einer eigenen Lesart: `integrated` heisst, der Beleg laeuft ueber
einen KOMPONIERTEN Pfad — ein Systemziel unter `tests/ea-system-tests/`, ein
Serverziel mit `xtask integration up` oder ein nativer Prozesszeuge
`process_native::…` — UND keine benannte Produkthaelfte der Zeile ist offen
(Stufe 4: AK-10, AK-42, WR-043, WR-053, WR-054, WR-082). `implemented` heisst,
der Beleg ist ein Crate- oder In-Process-Zeuge, ODER eine benannte Haelfte
bleibt offen (Stufe 3: AK-45 ohne Schreiber; Stufe 4: WR-041 nur die
CODE-Seite, FR-085, FR-100, WR-063). Was global der Stufe 7 vorbehalten ist —
native Minimal-/Maximalfaelle, quartalsweise Uebung, externe
Datenschutzentscheidung, Custody der Produktionsschluessel — ist keine
Produkthaelfte dieser Zeilen und senkt keine auf `implemented`.

| Ledgerzeile | Neuer Status | Begruendung |
|---|---|---|
| `AK-11` | integrated | Systemziel `e2e_registry_effectiveness.rs` traegt die Widerrufsgrenze; offen ist nur die Stufe-7-Uebung |
| `AK-12` | integrated | `e2e_historical_grant.rs` gegen den echten Server neben dem Crate-Zeugen der Auswahl |
| `AK-18` | implemented | Einziger Produktzeuge ist `crates/ea-admin/tests/amendment.rs` in-process; `amendment.spec.ts` ist UI/IPC-Double |
| `AK-24` | implemented | `registry_workflows.rs` und `stale_registry_acknowledgement.rs` sind Crate-Zeugen; kein komponierter Lauf traegt warn/block |
| `AK-29` | implemented | `writer_role_guard.rs` ist Crate-Zeuge; kein nativer Profilzeuge |
| `AK-30` | integrated | `process_native::destruction::` gegen TLS, PostgreSQL, S3 mit ObjectLock und SQLCipher, 52/0/0; den nativen Retry aus Zustand 4 fuer servergebundene Pflichten liefert DRK-319 mit eigenen Zeugen im selben Ziel, Reader-Faelle bleiben nach Ruling G1 dauerhaft in Zustand 4 — beides sind erlaubte, korrekt abgebildete Zustaende |
| `AK-35` | integrated | Systemziel `e2e_registry_effectiveness.rs` und Serverziel `commit_failures.rs` mit `integration up` |
| `AK-40` | integrated | Serverpfad `e2e_historical_grant.rs` neben `historical_grant.rs` und `grant_authorization.rs` |
| `AK-41` | integrated | Nativer Zeuge `writer_evidence::native_writer_evidence_reopens_as_real_reader_authorized_destruction` oeffnet den echten `.eds` im Reader; die nativen Min-/Max-Faelle sind Stufe-7-Vorbehalt, keine offene Produkthaelfte |
| `AK-44` | integrated | Drei Systemziele mit `integration up` fuer das Datenschutz-Gate, dazu die Go-live-Zeile aus denselben signierten Feldern (`2d52b5e`); die externe Entscheidung selbst ist Stufe-7-Vorbehalt |
| `AK-47` | implemented | Die Transport-Fingerprint-Bindung haengt an WR-075 und bleibt bis DRK-318 offen — das WR-041-Muster |
| `AK-49` | integrated | Systemziel plus `auth_trust_api.rs` und `commit_failures.rs` mit `integration up` |
| `AK-52` | implemented | Die sechs nativen `process_native::recovery::guided::` sind `#[ignore]` (Fremdmaschine); der gefuehrte Pfad ist nativ nicht bezeugt |
| `AK-53` | implemented | Transport-Fingerprint-Anteil an WR-075 (DRK-318) offen; `sessionExpired` (`96e0c3c`) ist geschlossen |
| `FR-120` | implemented | `crates/ea-admin/tests/amendment.rs` in-process, wie AK 18 |
| `FR-121` | implemented | Derselbe Zeuge liest Original-ID, -Hash, Sequenz, Grund und Ersteller aus verifizierten Bytes; in-process |
| `FR-123` | implemented | Derselbe Zeuge, Originalbytes identisch; in-process |
| `FR-124` | implemented | Derselbe Zeuge, zwei Nachtraege; in-process |

Die Belegspalte jeder bewegten Zeile nennt die Zeugen aus Abschnitt 1 bzw. der
Tabelle unten im Stil der Stufe-4-Zeilen (`Datei::Test; kurze Aussage`);
`source`, `title` und die Kriteriumsspalten sind unveraendert. Mitgezogene
Pins: KEINE. Die WR-Pin-Tabelle `WEB_READER_MUST_ROWS` in
`tools/xtask/tests/stage_gate.rs` fuehrt `("WR-075", "7.5", "5", "planned")`,
und das bleibt richtig; der D1-Pin auf die WR-075-Belegspalte
(`organizationAdminAuthorization`, `2-of-N`) bleibt unberuehrt, weil die Zeile
unberuehrt bleibt. Kein anderer xtask-Test pinnt Status oder Beleg einer der
achtzehn Zeilen. Invertiert ist der Zeuge des eingecheckten Baums:
`stage_five_gate_passes_the_checked_in_tree_with_wr_075_as_the_only_open_row`
verlangt jetzt Exit 0 statt Exit 2.

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
`archive-fs` ab. Die vier aus `f39c56f` geparkten REDs sind entparkt: die
drei Zeugen in `crates/ea-recovery/tests/fs_source_union.rs` seit `1e7f835`
(`FsArchiveSource::with_exact_component`), der letzte,
`apps/cli/tests/operator_recovery/native_archive.rs`, mit DRK-320. Der
tatsächlich gemountete Netz-Positivzeuge bleibt Stufe-7-Evidenz. Ein
Kaltstart einer Controlled-Network-Laufzeit braucht einen lesbaren
Remote-Pfad; ein Offline-Kaltstart bräuchte eine verifizierte lokale Kopie
des Remote (siehe die Spezifikation
`docs/superpowers/specs/2026-09-21-einsatzarchiv-controlled-network-archive-profile.md`).

**Geschlossen mit DRK-282: die drei Produktluecken dieser Stufe.** Das Audit
der abgelaufenen Sitzung als eigene Aktion `sessionExpired` (`96e0c3c`, Ruling
vom 2026-09-19), der native Clock-Release samt beiden Auflagen des
Security-Reviews (`5e055d0`, `59b08ac`, `8dae049`, Abschnitt 4) und die
Go-live-Anforderung `EA-GOLIVE-EDS-PRIVACY-DECISION` aus der signierten
`retention_policy` (`2d52b5e`, AK 44, aktivierte Vernichtung ohne Freigabe haelt
`production_ready` auf `false`) sind umgesetzt und in den Abschnitten 1, 4 und 5
bezeugt; sie sind keine Grenzen mehr.

Zur Reichweite von `sessionExpired` bleibt festzuhalten, was KEIN Ablauf ist:
ein durch eine OS-Sperre entwerteter, aber noch nicht abgelaufener Nachweis
wird an der Zeremonie weiterhin nur abgelehnt — es gibt keinen oeffentlichen
Leser fuer das Sperrbit. `administration_runtime/authorization.rs:118/:310`
verwerfen Autorisierungsfenster, keine Bedienersitzung, und buchen deshalb
keinen Ablauf.

**Geschlossen mit DRK-427: die zwei buendelnden Systemziele aus Plan Task
14.** `tests/ea-system-tests/tests/e2e_organization_lifecycle.rs` (Einrichtung
bis zur Recovery-Bereitschaft, ausstehende Geraeteaktivierung, Widerrufsgrenze,
Lease/Rueckrollen/Gabelung/Ueberalterung, Uhrfreigabe, Writer-Uebergang,
Nachtrag, Vernichtung) und `e2e_recovery_fresh_machine.rs`
(Offline-Schluesselquelle, Recovery auf frischer Maschine, Urteil des
gefuehrten Recovery-Tests ueber genau diese Messung, Schluesselinventar,
Re-Grant) laufen je 1/0/0, rein dateisystem- und prozessintern und ohne
`xtask integration up`.

Was sie AUSDRUECKLICH nicht buendeln, und warum:

- Beide laufen ueber mehrere Kulissen, nicht ueber eine. Die
  Einrichtungszeremonie lebt vor der Registrierungslinie, der
  Writer-Uebergang verlangt zwei Geraete mit eigenem Schluesselspeicher, die
  Vernichtung eine Policy mit `destructionEnabled` und zwei
  `destructionApprove`-Zertifikate, und die Bestandsfixture hat keine
  Zeremonie. Jede Naht ist im jeweiligen Zeugen benannt.
- Schritt 12 der Zeremonie und die gemessene Recovery-Probe laufen auf zwei
  Organisationen. Gebuendelt ist das URTEIL:
  `ea_admin::verify_fresh_machine_recovery_test` bewertet die WIRKLICH
  gemessene Probe (Medien, Anker, Abdruck, Lesbarkeit, Sample kommen aus dem
  Lauf), und dieselbe Funktion fuehrt die Organisation der Zeremonie nach
  `Ready`.
- Die Reader-Haelfte des Nachtragszeugen (mehrere verkettete Nachtraege an
  einem Faden) bleibt bei
  `crates/ea-admin/tests/amendment.rs`; die Uebergangskulisse fuehrt den
  oeffenbaren Wiederherstellungsempfaenger statt eines oeffenbaren Readers.
- Die physischen Vernichtungszweige (sofort, backup-pending, unerreichbar,
  Fortsetzen) und der NATIVE gefuehrte Recovery-Test bleiben bei ihren
  nativen Zeugen in `apps/cli`; sie verlangen einen gemessenen Wirt
  beziehungsweise eine echte Fremdmaschine (AK 30, AK 52).

Im Plan sind Task 14 Step 3 und Step 4 damit im Umfang dieser beiden Ziele
belegt; die nativen und dienstgebundenen Teile von Step 4 bleiben bei den
Kommandos, die der Plan dort nennt.

**Geschlossen mit den Folgetickets DRK-319, DRK-321, DRK-324 und DRK-326.**
Den nativen Erzeuger der Kante `incompleteUnreachableReplica` nach
`inProgress` (`crates/ea-destruction/tests/transitions.rs`), den das Ruling vom
2026-09-13 aus dem ersten Stufe-5-PR verschoben hatte, liefert DRK-319 in
`crates/ea-admin/src/destruction_runtime/retry.rs` (`0fd03cf`, `ca48589`) —
aber nur fuer servergebundene Pflichten: der Retry entsteht erst, wenn zu
`now` keine Pflicht mehr fehlt, die Serverreservierung wird vor dem Signieren
und nach der blockierenden Arbeit erneut gelesen, und eine Reader-Pflicht wird
vor jedem Netzzugriff mit `EA-DESTRUCTION-RETRY-READER-DUTY` verweigert.
„Vernichtung fortsetzen" im Desktop verkettet den Retry in Zustand 4
(`7e4f757`). Zeugen: `apps/cli/tests/operator_destruction/retry.rs`,
`.../transport/server/retry.rs` (Neustart desselben TLS-Servers mit PostgreSQL
und S3, Replay nach gescheitertem `publish`) und
`.../transport/server/host/retry.rs` (Desktop-Pfad), siehe AK 30 in
Abschnitt 1. DRK-321 (`d290a4b`, Regel R1): ein Vernichtungsuebergang, den ein
Geraet mit Reader-Zertifikat signiert, wird lokal mit
`EA-DESTRUCTION-SIGNATURE` verweigert, auch bei widerrufenem
Reader-Zertifikat — Zeugen
`crates/ea-destruction/tests/transitions.rs::a_transition_signed_by_a_reader_deletion_attest_key_is_refused_locally`
und `::a_revoked_reader_certificate_still_marks_its_device_as_a_reader`,
im Reader `crates/ea-reader/tests/destruction_cache.rs::an_initiating_event_signed_from_a_reader_device_is_not_a_removal_capability`;
die Reader-Grenze pinnen Faehigkeits-Allowlists (`c849d84`, `79f4d99`).
DRK-324 und DRK-326 stehen unten bei den nicht blockierenden Punkten.

**Reader-Faelle bleiben in Zustand 4 — Ruling G1 (Ruben, 2026-09-19).** In
v0.1 fuehrt kein Weg einen Job mit unbestaetigter Reader-Pflicht aus
`incompleteUnreachableReplica` zurueck; der Zustand ist fuer Lesegeraete
endgueltig und korrekt abgebildet. Das ist eine Umfangsentscheidung und keine
offene Produkthaelfte; AK 30 bleibt davon unberuehrt, weil alle erlaubten
Zustaende korrekt abgebildet sind.

**Server-Mehrfachausfuehrung — besitzendes Ticket DRK-430, erledigt.** Der
Server fuehrte bei jedem erneuten Job-POST neu aus und attestierte neu; das
war vorbestehend und nicht durch den Retry entstanden. Seit DRK-430 fuehrt
`execute_server` nur noch aus, solange die eigene dauerhafte Messung dieses
Servers die physische Pflicht noch nicht erfuellt meldet — genau das
Praedikat, das die Vollendung ohnehin verlangt. Der Replay-Zeuge in
`.../transport/server/retry.rs` pinnt jetzt genau eine Messung statt fuenf,
und `repeated_job_post_in_state_one_returns_the_single_existing_attestation`
in `apps/server/tests/destruction_jobs_api.rs` haelt die Grenze fest.

**Reichweite von R1 — DRK-431 geschlossen, besitzendes Ticket DRK-432.** R1
wirkt lokal in `ea-destruction` und `ea-reader` und seit DRK-431 auch im
Offline-Bericht von `ea-verify`: ein Vernichtungsuebergang, dessen
Signierergeraet am Autorisierungskopf ein Reader-Zertifikat traegt — auch ein
widerrufenes —, ist ein `signatureErrors`-Eintrag mit
`EA-VERIFY-DESTRUCTION-READER-DEVICE-SIGNER` und nimmt an der Kettenauswertung
gar nicht teil. Zeugen: `crates/ea-verify/tests/destruction_reader_signer.rs`.
Die Loeschattestierung DESSELBEN Geraets bleibt zulaessig (Web-Reader-Design
§3, Ruling 2026-09-13, DRK-250); die Regel greift ausschliesslich an der
Unterart `destructionTransition`.

**Einordnung offen — Entscheidung Ruben.** Der neue Befund ist als
VERSCHAERFUNG INNERHALB VON v1 umgesetzt, ohne Profil-Versionssprung, und das
ruht auf genau einem Befund: kein Konformitaetsvektor unter `vectors/`
enthaelt ueberhaupt einen Vernichtungsuebergang (die Familien sind crypto,
evidence, grants, local-audit, receipts, reports/import-report-v1, trust,
web-bundle; `accepted-destruction.bin` ist eine lokale Auditzeile,
`destruction-evidence.hex` eine Payload), und der einzige Systemtest mit
Uebergaengen — `tests/ea-system-tests/tests/task9_verification_report.rs`
ueber die Fixtures in `crates/ea-verify/tests/support/mod.rs` — fuehrt in
seinen Registrierungslinien kein einziges Reader-Zertifikat. Es bricht also
kein eingefrorenes v1-Artefakt. Was sich sehr wohl aendert: der signierte
Preflight-Kern verlangt leere `signatureErrors`
(`crates/ea-verify/src/preflight_report.rs`:36-47), also laesst sich ueber
einem Bestand mit einem solchen Uebergang kein Preflight-Kern mehr bilden —
fail-closed und gewollt, aber eine Verhaltensaenderung an v1-Archiven. Ob das
eine Profilrevision waere, bleibt Rubens Entscheidung; die Umsetzung hat sie
nur vorbereitet, nicht getroffen.

R1 setzt weiter voraus, dass kein Controller-, Writer- oder Admin-Geraet ein
Reader-Zertifikat traegt; diese Registry-Invariante erzwingt heute niemand
(DRK-432, Prioritaet hoch).

**Der Stufe 7 vorbehalten.** Vier Dinge bleiben ausdruecklich ausserhalb dieser
Stufe: die nativen Minimal- und Maximalfaelle, die quartalsweise Uebung, die
externe Datenschutzentscheidung und die Custody der Produktionsschluessel.

**Nicht blockierend, hier aber benannt.** Die beiden P3-Risiken der ersten
Fassung sind geschlossen. DRK-326 (`d600996`): `WatchTests.swift` wartet auf
den gestauten Callback nicht mehr mit einem Schlaf von 1,1 s gegen ein
Prueffenster von 1 s, sondern an einer Barriere direkt vor dem ACK; bis zur
Challenge bleibt ein wanduhrabhaengiges Restbudget von rund 1 s, dessen Riss
den Test rot macht und nie falsch gruen. DRK-324 (`786746c`): die
Reader-`ActionClock` laeuft nie rueckwaerts, setzt nach dem Anheben des
Mindestwerts neu an und holt einen Suspend auf. DRK-323 ist mit `db08333` behoben und auf dem echten Laeufer belegt
(RED `954fc7d` 28 von 30 Laeufen rot, GREEN `db08333` 0 von 30); dieses Gate
fuehrt `bootstrap_root` deshalb NICHT mehr als lastabhaengig.
Beim Nachmessen fuer diesen Bericht war der ERSTE Lauf von
`cargo test --locked -p ea-admin --lib` rot: 83/1/0,
`operator_exchange::tests::exchange_files_resume_exactly_and_never_replace_a_conflicting_reply`
brach an `crates/ea-admin/src/operator_exchange.rs:686` mit `Err(Io)` ab
(zweites, identisches `write_exchange_file`). Einzeln und in drei vollen
Wiederholungen danach 84/0/0. Die Ursache ist NICHT geklaert; der Verdacht
ist der nicht blockierende `try_lock` auf die Sperrdatei im gemeinsamen
`temp_dir` unter paralleler Last. Ein gruener Wiederholungslauf belegt keinen
Flake; der Befund steht hier, damit die Zahl 84/0/0 nicht mehr sagt, als
gemessen ist.
