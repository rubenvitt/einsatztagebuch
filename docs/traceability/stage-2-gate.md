# Stufe-2-Gate-Bericht — Offline Writer

Stand: Abschluss der Stufe 2 von v0.1. Dieser Bericht ist ein vom Gate
geprueftes Artefakt: `xtask stage-gate 2` liest ihn, verlangt die fuenf
Abschnitte dieses Dokuments, die Belegzeile jedes der zwoelf primaeren
Abnahmekriterien und die Reichweitenklausel aus Abschnitt 2 als Literal. Der
angehaengte Abschnitt `Gemessener Gate-Lauf` haelt zusaetzlich den tatsaechlich
gelaufenen Abschlusslauf fest;
`tools/xtask/tests/stage_gate.rs::stage_two_gate_report_records_the_measured_full_gate_run`
verlangt fuer jedes Kommando der vorgeschriebenen Folge eine eigene Belegzeile.
Der Gate prueft diesen Abschnitt AUSDRUECKLICH nicht: ein Gate, der seine
eigene Messzeile verlangte, koennte auf dem Lauf, der sie erzeugt, nie gruen
sein.

Maschinelle Gegenstuecke: `docs/traceability/v0.1-requirements.csv` (Ledger,
maschinell auf Vollstaendigkeit, Sortierung und nichtleere Belegspalte
geprueft), `docs/traceability/stage-2-fault-points.json` (die deklarierten
Abbruchpunkte, die der Gate namentlich verlangt) und der JSON-Bericht von
`cargo run --locked -p xtask -- stage-gate 2`.

## 1. Primaere Abnahmekriterien und ihre Belege

Die zwoelf primaeren Abnahmekriterien der Stufe 2 nach `design.md` Abschnitt
23. Die letzte Spalte nennt ausdruecklich, welcher Beitrag desselben Kriteriums
in spaeteren Stufen offen bleibt — ein gruener Stufe-2-Gate belegt den
Stufe-2-Anteil, nie das ganze Kriterium.

| Kriterium | Gegenstand | Beleg | Offen in spaeterer Stufe |
|---|---|---|---|
| AK 1 | Offline-Abschluss | `tests/ea-system-tests/tests/e2e_writer_archive.rs::one_incident_goes_from_the_blank_mask_to_a_committed_archive_without_a_network`; `crates/ea-writer/tests/offline_finalize.rs::offline_finalize_commits_grants_then_entry_and_returns_no_content` | Serverabgleich und unteilbarer Entry-Commit auf dem Sync-Weg (Stufe 3); der hier erzeugte Bestand traegt KEINE archivresidente Vertrauenslinie, `is_fully_verified` ist damit `false`, und die Berichtsgleichheit von Verzeichnis und Ein-Datei-Buendel steht in `crates/ea-archive-fs/tests/bundle_export.rs::bundle_verifies_to_the_same_report_as_the_directory`; der Buendelexport des Wirts ist seit dem 2026-08-28 als Naht gebaut, der Wirt aber nicht verdrahtet (`apps/desktop/src-tauri/src/state.rs::ArchiveBundleExportPort`, Abschnitt 2.4) |
| AK 2 | Kein Writer-Zugriff | `tests/ea-system-tests/tests/privacy_canaries_writer.rs::no_fachliche_canary_survives_finalization_anywhere_on_disk`; `tests/ea-system-tests/tests/privacy_canaries_writer.rs::a_restored_backup_never_returns_a_finalized_or_discarded_key` | Der Nachweis der Lesesicht — dass ein berechtigter Reader denselben Eintrag oeffnet — steht in Stufe 4 aus. Seit dem 2026-08-28 nullt sich der Entwurfsklartext zusaetzlich selbst (`crates/ea-draft/tests/single_draft.rs::the_draft_plaintext_zeroizes_itself_when_it_is_dropped`); fachlicher Klartext AUSSERHALB von `ea_draft::Draft` bleibt ungenullt (Abschnitt 2.4) |
| AK 3 | Neue Maske | `tests/ea-system-tests/tests/e2e_writer_archive.rs::one_incident_goes_from_the_blank_mask_to_a_committed_archive_without_a_network`; `apps/desktop/src/features/writer/WriterPage.test.tsx::clears the surface after the commit and offers no history and no final content` | Die Historienansicht, die es hier NICHT gibt, entsteht als Lesesicht in Stufe 4 |
| AK 15 | Stromausfall | `tests/ea-system-tests/tests/fault_injection_writer_matrix.rs::every_declared_stage_two_fault_point_has_exactly_one_survivable_outcome`; `tests/ea-system-tests/tests/fault_injection_writer_matrix.rs::a_media_failure_at_any_durable_step_never_produces_a_half_written_archive` | Der Nachweis auf echter Hardware und auf den vier Zielarchitekturen steht in Stufe 7 aus |
| AK 23 | Plattform-Key-Provider | `crates/ea-key-provider/tests/writer_role_guard.rs::a_claimed_hardware_profile_never_falls_back_silently`; `crates/ea-key-provider/tests/device_posture.rs::every_support_matrix_row_reaches_only_the_os_wrapped_floor`; `tests/ea-system-tests/tests/cross_platform_key_provider_smoke.rs` | Die native Ausfuehrung auf `x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin` und `x86_64-apple-darwin` steht in Stufe 7 aus und wird von vier eigenen `AK-23`-`v1.1`-Ledgerzeilen offen gefuehrt. NICHT belegter Rest des Wortlauts von `design.md` Abschnitt 23, Kriterium 23: „nach Sperre nicht ohne Re-Authentisierung verwendet" — die Plattformbeobachter des Sperrereignisses fehlen, und `is_valid_for`/`MAX_INACTIVITY_MS` werden im Wirt nicht ausgewertet (Ruling R59 Teil 2, Abschnitt 2.2). Ebenfalls offen die native BINDUNG selbst (Ruling R57, Abschnitt 2.1) |
| AK 25 | Writer-Restore | `crates/ea-writer/tests/prepared_recovery.rs::a_prepared_finalization_beats_a_second_finalization_attempt`; `tests/ea-system-tests/tests/privacy_canaries_writer.rs::a_restored_backup_never_returns_a_finalized_or_discarded_key`; die BLOCKADE selbst, in der Kette Kern - Naht - Oberflaeche: `crates/ea-writer/tests/sequence_id.rs::a_second_finalization_against_a_consumed_sequence_blocks` (`EA-WRITER-HEAD-RECONCILIATION-REQUIRED`), `apps/desktop/src-tauri/src/commands/writer.rs::a_refused_startup_path_becomes_a_blocked_outcome_with_its_code` (durchgereicht statt in einen Fehler verwandelt) und `apps/desktop/src/features/writer/WriterPage.test.tsx::resumes a prepared finalization and blocks a restored backup without any finalize control` (kein Finalisierungsknopf) | Der Kopfabgleich gegen einen erreichbaren signierten Server-Checkpoint steht in Stufe 3 aus; Stufe 2 blockiert fail-closed, sie loest nicht auf. Die Auswahl der Quittung ist seit dem 2026-08-28 gegen eine zweite, isolierte Quittung gehaertet (`crates/ea-verify/tests/receipt_checkpoint.rs::a_forged_second_receipt_with_a_smaller_object_hash_is_never_the_chosen_one`) |
| AK 28 | CSV-Stammdatenimport | `crates/ea-draft/tests/csv_import.rs::dry_run_does_not_write_and_commit_is_all_or_nothing`; `crates/ea-draft/tests/csv_import.rs::retained_protocol_bytes_reproduce_the_snapshot_hash`; `vectors/reports/` | Die Verwaltung der Stammdaten durch eine Administrationsrolle bleibt Stufe 5 |
| AK 34 | Prepared Recovery | `crates/ea-writer/tests/prepared_recovery.rs::after_the_key_boundary_recovery_completes_the_exact_prepared_bytes`; `tests/ea-system-tests/tests/fault_injection_writer_matrix.rs::a_prepared_finalization_survives_a_crash_and_beats_a_pending_discard`; die Abschlussmarke wird seit dem 2026-08-28 bei der Wiederaufnahme gegen ihre eigenen Bytes nachgerechnet und fail-closed mit `EA-WRITER-PREPARED-FINALIZATION-INCONSISTENT` abgewiesen (`crates/ea-writer/tests/prepared_recovery.rs::a_marker_without_a_single_grant_is_refused`, `::a_marker_whose_grant_plan_hash_contradicts_the_entry_is_refused`, `::a_marker_whose_sequence_contradicts_the_entry_is_refused`, `::a_marker_that_does_not_decode_stops_the_recovery`, `::a_transient_key_failure_stops_the_recovery_and_completes_nothing`) | Die Wiederaufnahme einer im Netz haengenden Publikation gehoert Stufe 3. Eine sich selbst widersprechende Abschlussmarke laesst die Wiederaufnahme dauerhaft scheitern und bleibt liegen — zu STRENG, nicht zu lax; der Aufloesungspfad ist Stufe 5 (Abschnitt 2.4) |
| AK 39 | Durable Backend | `tests/ea-system-tests/tests/fault_injection_writer_matrix.rs::every_declared_stage_two_fault_point_has_exactly_one_survivable_outcome`; `tests/ea-system-tests/tests/fault_injection_writer_matrix.rs::a_media_failure_at_any_durable_step_never_produces_a_half_written_archive`; `crates/ea-archive-fs/tests/backend_capabilities.rs::every_declared_capability_is_proven_on_the_host_filesystem`; `crates/ea-archive-fs/tests/controlled_network_profile.rs::controlled_network_requires_a_local_commit_component_and_rejects_a_generic_share` | Die signierte Betriebssystem- und Dateisystemmatrix steht in Stufe 7 aus; der Weg ueber ein tatsaechlich erreichbares kontrolliertes Netz steht in Stufe 3 aus; liegengebliebene Sperrdateien nach einem harten Prozessabbruch blockieren seit dem 2026-08-28 NICHT mehr — die Sperre ist eine echte Betriebssystemsperre ueber `std::fs::File::try_lock` (`crates/ea-archive-fs/tests/backend_capabilities.rs::a_leftover_lock_file_without_a_live_lock_is_reclaimed`, `::two_backends_on_the_same_root_admit_exactly_one_writer`, `crates/ea-writer/tests/prepared_recovery.rs::a_hard_crash_under_both_locks_still_lets_the_restart_complete`); NICHT belegter Rest des Wortlauts von `design.md` Abschnitt 23, Kriterium 39: „Jede Plattform beweist" — die advisory-lock-Semantik ist nur auf dem Host-Target bewiesen, der Nachweis auf drei Betriebssystemen und auf Netzdateisystemen bleibt Stufe 7 (Abschnitt 2.2) |
| AK 46 | Entwurf und Eingabevertrag | `crates/ea-draft/tests/single_draft.rs::exactly_one_encrypted_draft_is_restored_after_restart`; `crates/ea-draft/tests/discard_faults.rs::every_discard_fault_yields_old_draft_or_permanent_blank_draft`; `tests/ea-system-tests/tests/fault_injection_writer_matrix.rs::every_declared_discard_fault_point_restarts_into_one_of_two_states`; seit dem 2026-08-28 hinterlaesst auch der Rollback des frischen leeren Entwurfs keinen verwaisten Schluesselspeichereintrag (`crates/ea-draft/tests/repository_guards.rs::a_rolled_back_blank_draft_leaves_no_orphaned_keystore_entry`) | Der Nachweis ueber ein Releasepaket mit abgeschalteten Absturzberichten bleibt Stufe 7. NICHT belegter Rest: das Kriterium heisst in `design.md` Abschnitt 23 „Entwurf und Eingabevertrag" und ist hier am KERN belegt; der Desktop-Wirt konstruiert bis heute keinen Entwurfsdienst (`apps/desktop/src-tauri/src/lib.rs:77-85`), das Verwerfen ist im Wirt strukturell vorbereitet, nicht erreicht (VM-11, Abschnitt 2.4) |
| AK 48 | Archivprofilwechsel | `crates/ea-archive-fs/tests/profile_migration.rs::the_inventory_hash_is_equal_on_both_profiles_after_a_successful_switch`; `tests/ea-system-tests/tests/fault_injection_writer_matrix.rs::an_interrupted_profile_migration_leaves_exactly_one_active_pointer` | Die Freigabe eines neuen `archiveProfileHash` gegen `allowed-archive-profile-hashes` bindet Stufe 7; der hier erzeugte Bestand verifiziert NICHT vollstaendig (keine archivresidente Vertrauenslinie), ist deshalb nicht als Buendel exportierbar, und `tests/ea-system-tests/tests/e2e_writer_archive.rs::the_single_file_bundle_refuses_a_committed_archive_that_does_not_fully_verify` haelt genau diese fail-closed-Grenze fest |
| AK 54 | Record-ID und Sequenz | `crates/ea-writer/tests/sequence_id.rs::the_entry_uuid_is_version_seven_and_variant_two` (UUIDv7 nach RFC 9562); `crates/ea-writer/tests/sequence_id.rs::the_first_entry_binds_no_predecessor_and_claims_sequence_zero`; `crates/ea-writer/tests/sequence_id.rs::a_taken_incident_number_is_refused_before_anything_is_staged`; `crates/ea-writer/tests/sequence_id.rs::a_second_finalization_against_a_consumed_sequence_blocks` (eine verbrauchte Sequenz wird nie zweimal benutzt) | Die ORGANISATIONSWEITE Eindeutigkeit der `recordId` und ein echter PARALLELITAETSTEST sind hier NICHT belegt und stehen in Stufe 3 aus: Stufe 2 hat genau einen Writer und genau einen Entwurf, Eindeutigkeit ueber Geraetegrenzen entsteht erst am Serverabgleich. Der Crash- und Replayanteil ist gedeckt (`tests/ea-system-tests/tests/fault_injection_writer_matrix.rs::a_prepared_finalization_survives_a_crash_and_beats_a_pending_discard`). Seit dem 2026-08-28 wird eine VOR der unwiderruflichen Grenze gescheiterte Finalisierung ihre Einsatznummer wieder los (`crates/ea-writer/tests/prepared_recovery.rs::a_finalization_that_fails_before_the_boundary_releases_the_incident_number`), nach der Grenze bleibt sie verbraucht (`::a_finalization_that_fails_after_the_boundary_keeps_the_incident_number`); die Freigabe ist best effort — scheitert das Loeschen, bleibt die Nummer verbraucht |

Vier weitere Kriterien bekommen von Stufe 2 nur einen TEIL ihres Belegs. Sie
stehen bewusst UNTER der Tabelle und mit dem Praefix `| Teilbeleg AK `: der
Zeilenleser des Gates durchsucht das ganze Dokument nach `| AK ` und verlangt,
dass die gefundenen Nummern genau die zwoelf primaeren sind — eine Teilzeile in
jener Gestalt waere ein unerwartetes Kriterium und faerbte den Gate rot.

| Teilbeitrag | Gegenstand | Stufe-2-Anteil | Wo das Kriterium faellig wird |
|---|---|---|---|
| Teilbeleg AK 19 | Keine Klartextlogs | `tests/ea-system-tests/tests/privacy_canaries_writer.rs::no_fachliche_canary_survives_finalization_anywhere_on_disk` ueber jeden beobachtbaren Bytestrom, `tests/ea-system-tests/tests/privacy_canaries_writer.rs::the_search_finds_a_marker_that_really_lies_on_disk` als Gegenkontrolle, und `crates/ea-audit/tests/redaction.rs::typed_audit_never_carries_fachliche_bytes_and_never_leaks_in_errors` | Stufe 7 — der Nachweis ueber ein Releasepaket mit abgeschalteten Absturzberichten und abgeschalteter Telemetrie |
| Teilbeleg AK 24 | Registry-Ueberalterung | `crates/ea-writer/tests/stale_registry_warning.rs::a_head_that_expires_while_bound_is_acknowledgeable_and_blocks_fail_closed` und `::an_overdue_refresh_deadline_warns_without_blocking` — die ERKENNUNG samt fail-closed-Ausgang | Stufe 5 — der Bestaetigungspfad eines veralteten Kopfes selbst, ausdruecklich festgeschrieben durch Ruling R62 vom 2026-08-28 (`docs/traceability/stage-2-nacharbeit-2026-08-28.md`) |
| Teilbeleg AK 29 | Rollentrennung | `crates/ea-key-provider/tests/writer_role_guard.rs::writer_profile_rejects_forbidden_private_key_purposes` und `apps/desktop/src/app/csp.test.ts` fuer die Kommandoerlaubnisliste der Wirtsseite | Stufe 5 — die Administrationsseite der Rollentrennung |
| Teilbeleg AK 53 | Operator-Identitaet | `crates/ea-operator/tests/session_contract.rs::finalization_requires_matching_account_instance_key_and_fresh_presence` und `crates/ea-draft/tests/discard_faults.rs::a_proof_of_another_operator_binding_never_authorizes_a_discard` — die Bindung des Bedieners an jede unwiderrufliche Handlung | Stufe 5 — die Ausstellung der Bindung und die Transport-Fingerprint-Bindung |

Jede dieser vier fuehrt im Ledger eine EIGENE `v1.1`-Zeile auf Stufe `2` mit
Status `implemented`; die `v1`-Zeile behaelt ihre spaetere Stufe und ihr
`planned` unveraendert. Spaetere Stufen ergaenzen nur Zeilen.

## 2. Reichweite der Stufe-2-Abnahme

Die Klausel, Wort fuer Wort, wie `tools/xtask/src/main.rs` sie als
`STAGE_TWO_HOST_SCOPE_CLAUSE` fuehrt und wie der Gate sie hier als Literal
verlangt:

Stufe 2 belegt Baubarkeit ausschliesslich fuer das Host-Target: rust-toolchain.toml:5 stellt nur wasm32-unknown-unknown bereit (gepinnt in tools/xtask/tests/workspace.rs, rust_toolchain_declares_wasm32_and_no_release_target), und die vier Cross-Targets x86_64-pc-windows-msvc, x86_64-unknown-linux-gnu, aarch64-apple-darwin, x86_64-apple-darwin werden von Task 18 namentlich als offene Stufe-7-Ledgerzeilen eingetragen statt lokal behauptet.

Die vier Architekturen, die Stufe 2 NICHT behauptet, und die Ledgerzeilen, die
sie offen halten:

| Zielarchitektur | Ledgerzeile | Status |
|---|---|---|
| `x86_64-pc-windows-msvc` | `AK-23` `v1.1`, Stufe 7 | `planned` |
| `x86_64-unknown-linux-gnu` | `AK-23` `v1.1`, Stufe 7 | `planned` |
| `aarch64-apple-darwin` | `AK-23` `v1.1`, Stufe 7 | `planned` |
| `x86_64-apple-darwin` | `AK-23` `v1.1`, Stufe 7 | `planned` |

Diese vier Zeilen sind die, die `host_evidence_rows` im JSON-Bericht meldet,
und sie ERSETZEN die vier Cross-Target-Uebersetzungspruefungen, die Stufe 2
nicht faehrt. Dazu kommt `GATE-21` `v1.1` auf Stufe 7: der Go-live-Bericht MUSS
ein unaufgeloestes Postureergebnis (`Unknown`) als unaufgeloest zeigen und nie
als automatisches Bestehen.

### 2.1 Der Key-Provider steht als PORTSCHICHT — Offenlegung aus Ruling R57

Diese Zeile ist Pflicht und keine Hoeflichkeit: ohne sie waere Ruling R57 ein
Verschweigen. Der ihm zugehoerige Satz ist zugleich ein vom Gate geprueftes
Pflichtliteral (`STAGE_TWO_GATE_REPORT_LITERALS`), damit ein spaeterer
Berichtsumbau ihn nicht verlieren kann.

- Die Key-Provider-Schicht der Stufe 2 ist eine PORTSCHICHT OHNE NATIVE
  AUFRUFE. Keine der von Step 3 namentlich verlangten API-Familien ist
  aufgerufen — nicht CNG/DPAPI, nicht Windows Hello, nicht Keychain oder Secure
  Enclave, nicht LocalAuthentication, nicht PAM/Polkit, nicht Secret Service,
  nicht BitLocker/FileVault/LUKS. `HARDWARE_CAPABLE_PROVIDERS`
  (`crates/ea-key-provider/src/profile.rs`) ist deshalb LEER und fail-closed:
  ein behauptetes Hardwareprofil bricht, statt still auf `osWrapped`
  zurueckzufallen.
- VIER Posture-Werte bleiben `Unknown` (`crates/ea-key-provider/src/posture.rs`,
  bezeugt von
  `apps/desktop/src-tauri/src/commands/writer.rs::the_host_posture_reports_four_unresolved_requirements_and_is_not_production_ready`).
  `production_ready` ist damit `false`, und das ist die WAHRE Aussage ueber ein
  Geraet, dessen Haltung niemand gelesen hat.
- Der plattformuebergreifende Rauchtest
  (`tests/ea-system-tests/tests/cross_platform_key_provider_smoke.rs`) belegt
  sein Schutzprofil gegen den `InMemoryKeyProvider` und gegen keinen nativen
  Speicher.
- Die schliessende Stufe ist 7: native API-Familien je Plattform plus ADR 0003,
  Nachweis auf echter Hardware je Betriebssystem.

Und deshalb, in einer eigenen Zeile, weil der Gate sie als UNGEBROCHENES Literal
verlangt und ein Zeilenumbruch mitten im Satz sie unfindbar machen wuerde:

**Ein gruener Stufe-2-Gate ist ausdruecklich kein Beleg fuer hardwaregebundene Schluessel.**

Ledgeranker: `AK-23` `v1.1` auf Stufe 7, Status `planned`, mit genau diesem
Wortlaut. Die vier Zielarchitekturzeilen daneben halten die AUSFUEHRUNG offen,
diese Zeile die native BINDUNG selbst — zwei verschiedene Luecken.

### 2.2 Zwei weitere offene Zeilen, die Stufe 2 NICHT belegt

Jede steht hier, damit sie nicht als geprueft gilt, und jede hat ihren
Ledgeranker auf Stufe 7 mit Status `planned`.

| Offene Zeile | Was Stufe 2 hat | Was fehlt | Ledgeranker |
|---|---|---|---|
| Sperrnachweis auf drei Betriebssystemen (Ruling R60, Rest nach dem 2026-08-28) | Die echte Betriebssystemsperre IST gebaut: `crates/ea-archive-fs/src/local_path.rs::acquire_writer_lock` und `crates/ea-draft/src/lock.rs` nehmen die Sperrdatei per `std::fs::File::try_lock` (`flock` bzw. `LockFileEx`, ohne neue Abhaengigkeit). Eine liegengebliebene Sperrdatei eines toten Prozesses wird uebernommen (`crates/ea-archive-fs/tests/backend_capabilities.rs::a_leftover_lock_file_without_a_live_lock_is_reclaimed`, `crates/ea-draft/tests/repository_guards.rs::a_leftover_draft_lock_file_without_a_live_lock_is_reclaimed`), zwei Halter auf derselben Wurzel schliessen sich weiterhin aus (`crates/ea-archive-fs/tests/backend_capabilities.rs::two_backends_on_the_same_root_admit_exactly_one_writer`), und der Neustartpfad nach hartem Abbruch ist erreichbar (`crates/ea-writer/tests/prepared_recovery.rs::a_hard_crash_under_both_locks_still_lets_the_restart_complete`). Kein Reaper und keine PID-Pruefung — die OS-Sperre macht beide ueberfluessig. `Drop` unlinkt die Sperrdatei NICHT (Unlink-nach-Unlock-Race); `.ea-writer.lock` bleibt dauerhaft in jeder Archivwurzel und ist per `CONTROL_FILES_V1` aus Inventar und Gesundheitsbericht ausgeblendet | Die advisory-lock-Semantik ist NUR auf dem Host-Target bewiesen. Offen bleiben der Nachweis auf drei Betriebssystemen und auf Netzdateisystemen sowie die signierte Betriebssystem- und Dateisystemmatrix. Ebenfalls offen: `ea-recovery` (`FsArchiveSource`) zaehlt die Sperrdatei als `nonObjectFile` (+1) und `ea-recovery export` kopiert sie mit — dieselbe Praezedenz wie `.ea-active-profile` (Abschnitt 2.4) | `AK-39` `v1.1`, Stufe 7, `planned` (Belegspalte am 2026-08-28 umgeschrieben) |
| Bildschirmsperre und Frischepruefung, Teil 2 (Ruling R59) | Teil 1 ist gebaut: `draft_load_core` gibt den Entwurfsklartext nur gegen einen `OperatorSessionProof` heraus, bezeugt von `apps/desktop/src-tauri/src/commands/writer.rs::loading_the_active_draft_without_a_session_proof_never_reads_the_payload`; die Frist reist im Nachweis | Die PLATTFORMBEOBACHTER je Betriebssystem fuer das Sperrereignis sind nicht gebaut, und `is_valid_for`/`MAX_INACTIVITY_MS` werden im Wirt nicht ausgewertet. Die Inaktivitaetssperre wirkt in v0.1 also nur ueber die Frist im Nachweis, nicht ueber ein Betriebssystemereignis. Native Plattform-APIs, ADR-pflichtig, auf diesem Host nicht belegbar — dieselbe Begruendung wie Ruling R57 | `AK-53` `v1.1`, Stufe 7, `planned` |

### 2.3 Was Stufe 2 an der eingefrorenen Vektorfamilie `vectors/crypto/suite-1` getan hat

Eine Stufe-2-TAT an einem Stufe-1-Artefakt, festgehalten wie die Verschiebung
von `WR-052` in Abschnitt 4: die Familie `vectors/crypto/suite-1` ist von 66 auf
74 Eintraege gewachsen — ADDITIV, mit 0 geaenderten und 0 entfernten
Eintraegen. Die acht neuen sind die vier Domainzeichenketten und die vier
Domain-Digests der in dieser Stufe entstandenen Hashdomains
`einsatzarchiv-finalization-preview-v1`, `einsatzarchiv-archive-profile-v1`,
`einsatzarchiv-archive-inventory-v1` und
`einsatzarchiv-active-profile-pointer-v1`.

Die Unveraenderlichkeit der 66 Stufe-1-Eintraege ist GETRENNT von der Summe
gepinnt, und zwar an Namen UND Bytes:
`tests/ea-system-tests/tests/conformance_golden_vectors.rs::the_sixty_six_stage_one_vectors_are_unchanged_and_stage_two_only_added_eight`
fuehrt die 66 Paare aus Eintragsname und `fileSha256` als Literaltabelle und
verlangt zusaetzlich, dass die Restmenge des Manifests GENAU die acht benannten
Neuzugaenge ist. Ohne diese Trennung waere mit dem Anheben von
`EXPECTED_ENTRY_COUNT` von 66 auf 74 der Waechter der Unveraenderlichkeit
ersatzlos entfallen: eine Summe allein laesst einen geaenderten Alteintrag neben
einem neuen durch.

Und die Spannung ausdruecklich, statt sie zu verschweigen: der Wortlaut
„nie an ihrer Stelle“ in `docs/traceability/stage-1-gate.md:115-121` ist von
dieser additiven Erweiterung BERUEHRT. In der Sache ist kein Stufe-1-Byte
veraendert (0 geaendert, 0 entfernt, nachgemessen), im Wortlaut ist die Familie
sehr wohl an ihrer Stelle gewachsen. `docs/traceability/stage-1-gate.md` wird
dafuer NICHT umgeschrieben — Stufe 1 ist geschlossen und haelt den Stand an
ihrem eigenen Gate fest. Die Erzwingung steht stattdessen hier und in
`the_sixty_six_stage_one_vectors_are_unchanged_and_stage_two_only_added_eight`.

Eine Folge des GETEILTEN Berichtsschemas, damit sie niemand spaeter als Drift
liest: `evidenced_acceptance_criteria` wird stufenUNabhaengig ueber alle
Ledgerzeilen gerechnet — die Berechnung steht in `tools/xtask/src/main.rs` in
`run_stage_two_gate` (Stufe-2-Pfad) und in `run_stage_gate` (Stufe-1-Pfad),
beide Male als derselbe Filter `implemented | integrated` mit nichtleerem
`primary_acceptance_criterion` ueber ALLE Ledgerzeilen. Benannt statt mit
Zeilenbereich zitiert, aus demselben Grund, den Ruling R52 fuer die
Reichweitenklausel gibt: ein Zeilenverweis bricht bei jeder spaeteren
Aenderung an dieser Datei, und der Verweis wird von keinem Gate nachgelesen.
`stage-gate 1` listet seit diesem Task deshalb AUCH die Stufe-2-Kriterien; die
gemessene Zeile in `docs/traceability/stage-1-gate.md:164` bleibt der Beleg
IHRER eigenen Messung und wird nicht umgeschrieben. Der geschlossene
Stufe-1-Gate-Bericht ist in diesem Task nicht angefasst.

### 2.4 Offenlegungen der Nacharbeit vom 2026-08-28

Vier Befunde aus der Nacharbeit DRK-206, die den Stufe-2-Stand praeziser machen
statt ihn zu verbessern. Sie stehen hier, weil ein gruener Gate sonst mehr
behauptete, als er belegt. Der vollstaendige Bericht der Nacharbeit steht in
`docs/traceability/stage-2-nacharbeit-2026-08-28.md`.

1. **Der Wirt konstruiert heute keinen einzigen Dienst.**
   `apps/desktop/src-tauri/src/lib.rs:77-85` uebergibt
   `state::SessionState::new(None, None)` und danach fuenfmal `None`. Jedes
   Tauri-Kommando ist damit eine NAHT: uebersetzt, typgeprueft und mit Zeugen
   belegt, aber ohne Backend, ohne `WriterService` und ohne Vertrauensanker
   hinter sich. Der Bootstrap des Wirts ist eine offene Zeile fuer Stufe 3
   beziehungsweise Stufe 5.
2. **Der Buendelexport ist eine Naht, der Wirt ist nicht verdrahtet.**
   `archive_export_bundle_file` haengt seit dem 2026-08-28 am Port
   `apps/desktop/src-tauri/src/state.rs::ArchiveBundleExportPort` mit dem
   Fehlertyp `ea_archive_fs::BundleError`. Verdrahtet ist er NICHT: der Wirt
   haelt keinen `TrustAnchorV1` (`apps/desktop/src-tauri/src/state.rs:134`,
   `apps/desktop/src-tauri/src/commands/writer.rs:1207`, keine Kante auf
   `ea-trust`), und das Kommando bleibt bei
   `EA-DESKTOP-BUNDLE-EXPORT-UNAVAILABLE`
   (`apps/desktop/src-tauri/src/commands/mod.rs:66`, erhoben in
   `apps/desktop/src-tauri/src/commands/writer.rs:962`). Ebenso ist das Verwerfen im Wirt
   STRUKTURELL VORBEREITET, NICHT ERREICHT: `state::BoundDiscard::new` hat im
   Wirt keine Aufrufstelle, und damit bleibt VM-11 unerreicht. Zeuge fuer die
   Phasenbenennung der Schale:
   `apps/desktop/src-tauri/src/lib.rs::the_shell_names_every_discard_phase_without_a_continuation`.
3. **Eine sich selbst widersprechende Abschlussmarke bleibt liegen.** Die
   Nachrechnung der Marke (`crates/ea-writer/src/recover.rs`, Einstieg
   `recover_pending` an `:100`) weist eine Marke
   mit `grant_count = 0`, abweichendem `grant_plan_hash` oder einer der
   Eintragssequenz widersprechenden Sequenz fail-closed mit
   `EA-WRITER-PREPARED-FINALIZATION-INCONSISTENT` ab. Folge: `recover_pending`
   scheitert fuer diesen Bestand DAUERHAFT, und die Marke bleibt liegen. Das
   ist zu STRENG und nicht zu lax, es entsteht kein Datenverlust, aber die
   Aufloesung ist ein manueller Schritt — dieselbe Klasse wie Ruling R60 und
   derselbe Aufloesungspfad: Stufe 5.
4. **Die Sperrdatei reist im Recovery-Export mit.** `ea-recovery`
   (`FsArchiveSource`) zaehlt `.ea-writer.lock` als `nonObjectFile` (+1), und
   `ea-recovery export` kopiert sie mit: `crates/ea-recovery/src/source.rs:125-175`
   liest JEDE regulaere Datei unter der Wurzel ein, und `CONTROL_FILES_V1` — die
   Ausblendung, die Inventar und Gesundheitsbericht anwenden — kommt in
   `crates/ea-recovery/src/` an keiner Stelle vor. Praezedenz ist `.ea-active-profile`,
   das sich seit je genauso verhaelt. Kein Vertraulichkeits- und kein
   Integritaetsbefund — die Datei ist leer und traegt keine fachlichen Bytes —,
   aber eine Abweichung von der Erwartung, ein Export enthalte nur Bestand.

Und eine Grenze der Schluesselvernichtung, damit Abschnitt 5.1 nicht mehr
verspricht, als er haelt: `ea_draft::Draft` nullt seinen Klartext seit dem
2026-08-28 selbst (`ZeroizeOnDrop`, Zeuge
`crates/ea-draft/tests/single_draft.rs::the_draft_plaintext_zeroizes_itself_when_it_is_dropped`).
Fachlicher Klartext AUSSERHALB dieses Typs bleibt ungenullt — genannt seien
`FinalizationInputV1`, die `ea-schema`-Nutzlast und
`apps/desktop/src-tauri/src/state.rs`, dessen `notes()` einen `String`
zurueckgibt. Die Kanarienvogelmessung in Abschnitt 5.3 misst die PLATTE und ist
davon unberuehrt; der Arbeitsspeicher ist keine von ihr belegte Flaeche.

## 3. Fehlermatrix und deklarierte Abbruchpunkte

Die Abbruchpunkte stehen eingecheckt in
`docs/traceability/stage-2-fault-points.json`; der Gate liest sie von dort und
braucht dafuer keine Kante auf eine Stufe-2-Crate. Gruppiert nach dem
dauerhaften Schritt, den sie klammern, und mit dem EINEN Ausgang, den jeder
erzeugen darf.

### 3.1 Verwerfen — sechs Punkte

| Abbruchpunkt | Geklammerter dauerhafter Schritt | Erlaubter Ausgang |
|---|---|---|
| `BeforeIntentCommit` | vor dem Buchen der Verwerfensabsicht | `OriginalDraftUnchanged` |
| `AfterIntentCommit` | nach dem Buchen der Verwerfensabsicht | `OriginalDraftUnchanged` oder `NewBlankDraft` |
| `AfterKeystoreDelete` | nach dem Loeschen des `draftDEK`, vor der Abwesenheitsbestaetigung | `NewBlankDraft` |
| `AfterAbsenceConfirmation` | nach der bestaetigten Abwesenheit des `draftDEK` | `NewBlankDraft` |
| `AfterDraftRemoval` | nach der Transaktion, die Chiffrat und Absicht entfernt und den leeren Entwurf anlegt | `NewBlankDraft` |
| `BackupRestoreAfterKeyDeletion` | nach dem Loeschen des `draftDEK`, mit zurueckgespielten Datenbankdateien | `NewBlankDraft` — der Schluessel kehrt NICHT mit den Dateien zurueck |

### 3.2 Abschluss — zwoelf Punkte um die dreizehn Schritte

| Abbruchpunkt | Phase | Erlaubter Ausgang |
|---|---|---|
| `BeforeStagingCreate` | `ReversibleDraft` | unveraenderter, lesbarer Entwurf |
| `AfterStagingCreateBeforeFileFlush` | `ReversibleDraft` | unveraenderter, lesbarer Entwurf |
| `AfterStagingFileFlushBeforeDirectoryFlush` | `ReversibleDraft` | unveraenderter, lesbarer Entwurf |
| `AfterStagingDirectoryFlushBeforeMarker` | `ReversibleDraft` | unveraenderter, lesbarer Entwurf |
| `AfterPreparedMarkerCommit` | `PreparedAndFlushed` | byteidentische Vollendung aus der Abschlussmarke |
| `AfterKeystoreDelete` | `DraftKeyAbsent` | byteidentische Vollendung aus der Abschlussmarke |
| `AfterAbsenceConfirmation` | `DraftKeyAbsent` | byteidentische Vollendung aus der Abschlussmarke |
| `AfterGrantPublishBeforeEntryRename` | `GrantsPublished` | byteidentische Vollendung aus der Abschlussmarke |
| `AfterEntryRenameBeforeDirectoryFlush` | `EntryCommitted` | byteidentische Vollendung aus der Abschlussmarke |
| `AfterEntryDirectoryFlush` | `EntryCommitted` | byteidentische Vollendung aus der Abschlussmarke |
| `AfterReconciliationBeforeBlankDraft` | `NetworkArchivePublished` | byteidentische Vollendung aus der Abschlussmarke |
| `BackupRestoreAfterKeyDeletion` | `DraftKeyAbsent` | KEINE Vollendung und kein halber Bestand: die Rueckspielung nimmt die vorbereiteten Bytes mit, der Bestand bleibt unberuehrt, der `draftDEK` bleibt fort |

### 3.3 Vorrang — ein Punkt

`PreparedFinalizationBeatsDiscardIntent` ist kein Punkt der Reihenfolge,
sondern die Regel an JEDEM Eingang: solange eine vorbereitete Abschlussmarke
liegt, wird kein Verwerfen begonnen und keines fortgesetzt. Der Neustart meldet
`PreparedFinalizationPending`. Belegt von `tests/ea-system-tests/tests/fault_injection_writer_matrix.rs::a_prepared_finalization_survives_a_crash_and_beats_a_pending_discard`
und `crates/ea-draft/tests/discard_faults.rs::a_prepared_finalization_marker_displaces_a_booked_discard_intent`.

### 3.4 Die zwei Medienverweigerungen

An JEDEM der zwoelf Abschlusspunkte wird zusaetzlich das Medium verweigert, in
zwei Auspraegungen: `NoSpaceLeft` — nur die zwei Veroeffentlichungsverzeichnisse
nehmen nichts mehr an, waehrend die Wurzel beschreibbar bleibt — und
`ReadOnlyMount` — kein Verzeichnis des Bestands nimmt noch etwas an. Erlaubter
Ausgang in beiden Faellen: der Bestand ist BYTEIDENTISCH zu dem Zustand vor der
Verweigerung, der Gesundheitscheck meldet weder `MissingFile` noch
`ModifiedFile` noch `HashSignatureOrChainError`, und jedes veroeffentlichte
Archivobjekt traegt alle seine Bytes. Was NICHT reproduziert wird, ist die
`errno`: `ENOSPC` liesse sich portabel nur ueber ein eigenes Dateisystem oder
`setrlimit` herstellen, und beides steht diesem Workspace nicht zur Verfuegung
(`#![forbid(unsafe_code)]`, keine `libc`-Kante). Reproduziert wird die Aussage
„das Medium nimmt die Bytes nicht an", und zwar an zwei verschiedenen
Adressen; eine Positivkontrolle im Aufbau belegt, dass die Verweigerung
wirklich greift. Belegt von `tests/ea-system-tests/tests/fault_injection_writer_matrix.rs::a_media_failure_at_any_durable_step_never_produces_a_half_written_archive`.

### 3.5 Die vierzehn Punkte der Profilmigration

`ea_archive_fs::MigrationFaultPoint::ALL` traegt vierzehn Punkte vor und nach
jedem dauerhaften Schritt des Profilwechsels. Erlaubter Ausgang an jedem: GENAU
EIN aktiver Zeiger, und zwar der des ALTEN Profils; die Finalisierungssperre
ist wieder frei; jedes Archivobjekt des Quellprofils ist vollstaendig lesbar.
Belegt von `tests/ea-system-tests/tests/fault_injection_writer_matrix.rs::an_interrupted_profile_migration_leaves_exactly_one_active_pointer`
und `crates/ea-archive-fs/tests/profile_migration.rs::every_durable_step_has_a_named_fault_point_before_and_after_it`.

## 4. Die vier Entscheidungen vom 2026-08-18

### D-B01 — `importProtocolHash` ueber die exakten `import-report-v1`-Bytes

Das Importprotokoll ist ein eingefrorenes Urbild: `importProtocolHash` wird
ueber die EXAKTEN Bytes des `import-report-v1`-Objekts gerechnet und nicht ueber
eine nachgebildete Struktur. Die Vektorfamilie `vectors/reports/` haelt sie
fest; `crates/ea-draft/tests/csv_import.rs::a_forged_report_over_the_same_bytes_is_refused`
belegt, dass ein nachgebauter Bericht ueber dieselben Bytes abgewiesen wird.
Folge fuer spaetere Stufen: jede Stufe, die einen Importbericht weitergibt,
gibt die exakten Bytes weiter — eine Neuserialisierung bricht den Hash.

### D-B02 — vier Hashdomains und die fail-closed-Profilpruefung

`previewHash` bindet die bestaetigte Pruefansicht an den Abschluss und wird
unter der Sperre NACHGERECHNET. `archiveProfileHash` bindet das konfigurierte
Bestandsprofil und wird gegen `allowed-archive-profile-hashes` DESSELBEN
gebundenen Registrierungskopfes geprueft; ein Profil, das dort nicht steht,
blockiert mit `EA-ARCHIVE-PROFILE-NOT-ALLOWED`, bevor eine einzige Archivadresse
benutzt wird. `inventoryHash` und `activePointerHash` binden Bestand und
aktiven Zeiger des Profilwechsels. Folge fuer Stufe 7: die Freigabe eines neuen
`archiveProfileHash` ist eine Aenderung an der signierten Policy und keine
Konfigurationsaenderung — sie BINDET Stufe 7.

### D-HE1 — SQLCipher und ADR 0002

Die lokale Ablage ist vollstaendig verschluesselt: SQLCipher, aus Rust ueber
`rusqlite` mit gebundelter Amalgamation, entschieden und begruendet in
`docs/adr/0002-local-database-encryption.md`. Jede Datenbankdatei einschliesslich
WAL ist verschluesselt, und ein Temporaerueberlauf ist verboten;
`crates/ea-local-store/tests/encrypted_open.rs::every_database_file_including_the_wal_is_encrypted_and_no_temp_spill_is_allowed`
belegt es. Der lokale Auditstrom nutzt dieselbe Ablage und sein eigenes
eingefrorenes Objekt `local-audit-event-v1` mit der Vektorfamilie
`vectors/local-audit/`. Folge fuer Stufe 7: die Bereitstellung der
SQLCipher-Amalgamation gehoert zur Releaseprovenienz.

### D-HE2 — `webBundleRelease` und die Verschiebung von `WR-052`

Der universelle Datei-Weg des Web-Readers wird von Stufe 2 geliefert und nicht
von Stufe 4: Task 12 baut den Ein-Datei-Buendelexport `webBundleRelease`, OHNE
ein siebtes Objektpraefix zu praegen
(`crates/ea-archive-fs/tests/bundle_export.rs::a_bundle_carries_no_exact_object_prefix_and_adds_no_seventh_family`).
`WR-052` wandert deshalb im Ledger von Stufe `4` auf Stufe `2` und von
`planned` auf `integrated`; `requirement_id`, `version` `v1.1`, `source` und
`title` bleiben unveraendert. Diese Entscheidung UEBERSCHREIBT die
Stufenzuordnung, die Entscheidung D3 vom 2026-08-17 dieser EINEN Zeile gegeben
hat. Der geschlossene Stufe-1-Gate-Bericht wird dafuer NICHT bearbeitet — er
haelt den Stand am Stufe-1-Gate fest; die Verschiebung ist hier und in
`tools/xtask/tests/stage_gate.rs` an `WEB_READER_MUST_ROWS` festgehalten, dessen
Erwartungsspalte sie AUSGESCHRIEBEN traegt statt die Zusicherung fuer die
anderen sechs Zeilen aufzuweichen.

## 5. Unwiderruflichkeit, Schluesselvernichtung und Kanarienvoegel

### 5.1 Die Kette

Die Reihenfolge der Finalisierung ist ERZWUNGEN und hat GENAU EINE
unwiderrufliche Grenze: Schritt 9 nullt, leert und loescht den `draftDEK`.
Davor ist jeder Abbruch reversibel und die Sequenz unverbraucht; danach MUSS
aus den vorbereiteten Bytes vollendet werden, und es wird nichts neu
serialisiert. Ein committed `.eip` und ein nutzbarer `draftDEK` existieren NIE
gleichzeitig: der Schluessel geht in Schritt 9, seine Abwesenheit wird
zurueckgefragt, und erst danach wird veroeffentlicht.

### 5.2 Die Sicherungsblockade

Der `draftDEK` liegt in einem geraetegebundenen Schluesselspeichereintrag, den
die gewoehnliche Anwendungs- und Systemsicherung ausnimmt
(`crates/ea-key-provider/tests/provider_contract.rs::a_keystore_entry_of_this_product_never_roams_and_is_never_backed_up`).
Eine zurueckgespielte Datenbankdatei findet deshalb keinen Schluessel — weder
fuer einen abgeschlossenen noch fuer einen verworfenen Entwurf. Gemessen an
einer Sicherung von VOR und am Zustand NACH der Finalisierung sowie an der
Rueckspielung nach einem Verwerfen:
`tests/ea-system-tests/tests/privacy_canaries_writer.rs::a_restored_backup_never_returns_a_finalized_or_discarded_key`.

### 5.3 Das Ergebnis der Kanarienvoegel

Je fachliches Feld GENAU EIN eigener Marker — Stichwort, Ort, Personal,
Fahrzeuge, Fremdorganisationen, menschliche Einsatznummer, Freitext und beide
Leergruende. Gesucht wird nach der Finalisierung in JEDEM beobachtbaren
Bytestrom: der Datenbankdatei samt WAL und Journal, jeder Datei des Bestands
einschliesslich der Staging-Deskriptoren, jedem Datei- und Verzeichnisnamen und
jeder Debug-Ausgabe, die der Kern in eine Panik oder eine Fehlerzeile legen
kann. ERGEBNIS: kein Marker ueberlebt, in keinem Strom. Eine Gegenkontrolle
belegt, dass die Suche greift — ein Marker, der wirklich auf der Platte liegt,
wird gefunden. `patient_count` traegt AUSDRUECKLICH keinen Marker: der Typ ist
`Known(u32) | Unknown` und fuehrt keinen Bedienertext, eine kleine Zahl als
Marker waere in jedem Bytestrom zufaellig zu finden, und eine Zusicherung, die
nicht fehlschlagen KANN, ist ein Defekt. Produktionsseitige Absturzberichte und
Telemetrie sind vorgabegemaess abgeschaltet; geprueft wird die Absturzausgabe,
die dieser Kern erzeugen KANN.
Belegt von `tests/ea-system-tests/tests/privacy_canaries_writer.rs::no_fachliche_canary_survives_finalization_anywhere_on_disk`.

## Gemessener Gate-Lauf

Der vollstaendige Lauf nach Schritt 6 des Stufe-2-Plans
(`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-2-offline-writer.md`),
zuletzt frisch ausgefuehrt am 2026-08-28 in der hier protokollierten
Reihenfolge, auf dem Kopf `a82b593` des Zweiges `drk-206-stufe-2-nacharbeit`.
Jedes Kommando lief mit `env -u RUSTUP_TOOLCHAIN`, weil die Shell
`RUSTUP_TOOLCHAIN` auf `1.98.0` setzt und damit den Pin `1.95.0` aus
`rust-toolchain.toml` uebersteuern wuerde; die aktive Toolchain war gemessen
`1.95.0-aarch64-apple-darwin`. `pnpm supply-chain` setzt
`cargo install --locked cargo-deny` voraus; installiert und gemessen war
`cargo-deny 0.20.2`. Die Zahlen sind abgelesen, nicht geschaetzt:
`0 passed; N filtered out` waere kein Ergebnis, sondern ein defekter Filter, und
kommt in keiner Zeile vor. Der Ausgangsstand vor Task 18 waren 122
Testbinaries mit 930 bestandenen Tests; am Ende der Stufe 2 stand
`cargo test --workspace --all-targets --locked` bei 125 Testbinaries mit 943
bestandenen Tests, nach der Fix-Welle des Abschlussreviews bei 125
Testbinaries mit 955. Gemessen am 2026-08-28 steht derselbe Lauf bei
127 Testbinaries mit 1005 bestandenen Tests (siehe den Nachtrag
`Nachmessung DRK-206` unter der Tabelle) — keine bestehende Zusicherung
entfernt oder aufgeweicht. Die sechs ignorierten Tests sind der Bestand aus
frueheren Stufen und auch dieser Lauf aendert nichts an ihnen.

| Kommando | Exitcode | Gemessenes Ergebnis | Laufzeit |
|---|---|---|---|
| `cargo test --locked -p ea-writer` mit den zehn `-p`-Namen der Schritt-6-Folge | 0 | 47 Testbinaries und die zehn Doctest-Ziele der zehn Pakete, 321 bestanden, 0 fehlgeschlagen, 0 ignoriert, 0 gefiltert | 94 s |
| `cargo test --locked -p ea-system-tests --test fault_injection_writer_matrix` | 0 | 6 bestanden, 0 fehlgeschlagen, 0 ignoriert, 0 gefiltert | 14 s |
| `cargo test --locked -p ea-system-tests --test privacy_canaries_writer` | 0 | 4 bestanden, 0 fehlgeschlagen, 0 ignoriert, 0 gefiltert | 2 s |
| `cargo test --locked -p ea-system-tests --test e2e_writer_archive` | 0 | 2 bestanden, 0 fehlgeschlagen, 0 ignoriert, 0 gefiltert | 2 s |
| `pnpm desktop:typecheck` | 0 | `tsc --noEmit` ohne eine einzige Diagnose | 2 s |
| `pnpm desktop:test` | 0 | 9 Testdateien, 83 Tests bestanden, 0 fehlgeschlagen | 12 s |
| `pnpm desktop:e2e` | 0 | 3 Playwright-Tests bestanden, 1 Worker, Netz abgeschaltet | 6 s |
| `pnpm supply-chain` | 0 | `advisories ok, bans ok, licenses ok, sources ok`; kein einziges `error[...]`; 37 `duplicate`-Warnungen aus dem Tauri-Teilbaum, die `multiple-versions = warn` bewusst nur warnt; `cargo-deny 0.20.2` | 3 s |
| `pnpm stage-gate:2` | 0 | JSON auf stdout: 16 deklarierte Abbruchpunkte, 149 Ledgerzeilen, 4 `host_evidence_rows`, `stage_two_rows_still_planned` leer, `vector_families` = `[local-audit, reports]` | 2 s |
| `pnpm verify:quick` | 0 | ACHT Teilkommandos gruen, in dieser Reihenfolge: `cargo fmt --all --check`; `pnpm --dir apps/desktop build`; `pnpm desktop:typecheck` (`tsc --noEmit` ohne Diagnose); `pnpm desktop:test` (9 Testdateien, 83 Tests bestanden); `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` ohne eine einzige Warnung; `cargo test --workspace --all-targets --locked` mit 127 Testbinaries, 1005 bestanden, 0 fehlgeschlagen, 6 ignoriert, 0 gefiltert; `cargo test --workspace --doc --all-features --locked` mit 24 Ergebniszeilen ueber 22 Doctest-Ziele, 93 bestanden, 0 fehlgeschlagen (darunter die `compile_fail`-Doctests aus Ruling R55, die als zweiter Block eines Ziels laufen); und der wasm32-Check ueber die zehn Pakete der Positivliste | 125 s |

Nachmessung DRK-206 (2026-08-28): die Zahlen dieser Tabelle sind auf dem Kopf
`a82b593` des Zweiges `drk-206-stufe-2-nacharbeit` neu gemessen, nachdem die
Nacharbeit DRK-206 (`docs/traceability/stage-2-nacharbeit-2026-08-28.md`) sie
bewegt hat. Vorher standen hier 955 bestandene Tests und 146 Ledgerzeilen.
Bewegt haben sie die Tasks der Nacharbeit: Task 1 `+1` in `ea-verify`, Task 2
`+9` in `ea-writer` und `ea-draft`, Task 3 `+4`, Task 4 `+11` in `ea-desktop`,
Task 5 `±0`. Die drei zusaetzlichen Ledgerzeilen kommen aus denselben Tasks.

Diese Deltas sind ausdruecklich KEINE Rechnung, sondern eine Zuordnung: sie
summieren sich auf `+25`, gemessen sind aber `+50` bestandene Tests und `+2`
Testbinaries gegenueber dem Lauf vom 2026-08-21. Der Unterschied liegt nicht in
diesem Zweig — `git diff --name-status main..HEAD` fuehrt keine einzige neu
angelegte Testdatei, die Nacharbeit hat also kein neues Testbinary erzeugt. Die
zwei zusaetzlichen Binaries und die restlichen Tests sind zwischen dem
Gate-Lauf vom 2026-08-21 und dem Abzweigpunkt `42cbfaf` auf `main` gelandet.
Autoritaet ist deshalb die GEMESSENE Endzahl 127 Testbinaries mit 1005
bestandenen Tests, nicht die fortgeschriebene Reihe — dieselbe Konvention, die
der Abschnitt `N4` weiter unten schon festhaelt.

Ein Kommando war auf dem ersten Anlauf dieser Nachmessung rot, und zwar ohne
Zutun des Baumes: `pnpm supply-chain` meldete
`error[yanked]: detected yanked crate chacha20 0.10.1` und
`advisories FAILED`. `deny.toml` fuehrt `[advisories] yanked = "deny"`, und
crates.io hatte `chacha20 0.10.1` nach dem 2026-08-21 zurueckgezogen; dieselbe
Version stand unveraendert auch auf `main`. Aufgeloest wurde das mit dem
Patchsprung `chacha20 0.10.1 -> 0.10.2` (Commit `a82b593`), der genau einen
Eintrag der Sperrdatei bewegt — Version und Pruefsumme, sonst nichts. Der
ADR-0001-Pin `chacha20poly1305 = "=0.11.0"` bleibt unberuehrt; `chacha20` haengt
transitiv darunter. Verhaltensnachweis ist
`tests/ea-system-tests/tests/conformance_golden_vectors.rs`, gefahren als
`cargo test --locked -p ea-system-tests --test conformance_golden_vectors`,
Exitcode 0, 7 bestanden: die goldenen Vektoren rechnen nach dem Sprung
byteidentisch. Danach meldet `pnpm supply-chain` wieder
`advisories ok, bans ok, licenses ok, sources ok` und kein einziges `error`.

Nach dem Sprung wurden die Kommandos 1 bis 4, 8, 9 und 10 auf `a82b593`
VOLLSTAENDIG NEU gefahren; ihre abgelesenen Zahlen sind mit denen vor dem
Sprung identisch. Die Zeilen `pnpm desktop:typecheck`, `pnpm desktop:test` und
`pnpm desktop:e2e` tragen die Zahlen des Laufs von demselben Tag VOR dem
Sprung: keines der drei Kommandos liest `Cargo.lock` — sie fahren `tsc`,
Vitest und Playwright.

Zwei Angaben der Tabelle waren beim Nachmessen sachlich falsch und sind
richtiggestellt, ohne dass sich ein Kommando geaendert haette. Erstens faehrt
`cargo test --workspace --doc --all-features --locked` 22 `Doc-tests`-Ziele mit
24 Ergebniszeilen und nicht 24 Ziele: `ea_key_provider` und `ea_operator` fahren
ihre `compile_fail`-Doctests als zweiten Block desselben Ziels. Zweitens zaehlt
die wasm32-Positivliste ZEHN Pakete und nicht elf — nachgezaehlt an den
`-p`-Namen des wasm32-Blocks von `verify_quick_commands()`; dieselbe Zahl fuehrt
`docs/traceability/stage-1-gate.md:165` seit Stufe 1 und ebenso der Kommentar in
`tools/xtask/tests/stage_gate.rs:960`.

Die Laufzeiten dieser Nachmessung sind volle Wanduhrsekunden und keine
Harnesszeiten; das Kriterium bleibt der Exitcode und das abgelesene Ergebnis.
Die Umgebung hat sich seit dem 2026-08-21 in einem Punkt verschoben, der im
Vorspann steht: die Shell setzt `RUSTUP_TOOLCHAIN` inzwischen auf `1.98.0`
statt `1.97.1`, weshalb `env -u RUSTUP_TOOLCHAIN` vor jedem Kommando noch
noetiger ist als vorher; die aktive Toolchain bleibt gemessen
`1.95.0-aarch64-apple-darwin`.

Ablauf der Messung, damit sie nachvollziehbar bleibt: der Test
`stage_two_gate_report_records_the_measured_full_gate_run` entstand VOR der
Messung und schlug fehl, weil dieser Abschnitt leer war — gemessen mit
`left: 0 / right: 1` fuer das erste Kommando. Der Messlauf war deshalb an
seinen letzten zwei Kommandos rot: `pnpm verify:quick` faehrt
`cargo test --workspace --all-targets --locked` und damit genau diesen Test
mit. `pnpm stage-gate:2` selbst war schon auf dem Messlauf gruen, weil der Gate
diesen Abschnitt AUSDRUECKLICH nicht liest. Danach wurde die Tabelle aus den
abgelesenen Zahlen gefuellt und die Folge ein zweites Mal gefahren; die Zahlen
dieser Tabelle sind die des BESTAETIGENDEN Laufs.

Nachtrag der Fix-Welle des Abschlussreviews (2026-08-21): das Abschlussreview
ueber sechs Dimensionen hat keinen Merge-Blocker, aber siebzehn Positionen
gefunden, die in VIER thematischen Buendeln behoben wurden (Ruling R61,
Reihenfolge B - C - D - A). Vier Wirkungen dieser Welle stehen in DIESER
Tabelle, und deshalb wurden alle zehn Kommandos VOLLSTAENDIG NEU gefahren:

1. `verify_quick_commands()` fuehrt jetzt ACHT statt fuenf Teilkommandos.
   Neu sind `cargo test --workspace --doc --all-features --locked` (Ruling R55:
   die `compile_fail`-Doctests waren der einzige Beleg dafuer, dass die
   oeffentliche API kein privates Schluesselmaterial exportiert, und liefen in
   keinem Gate-Kommando, weil `--all-targets` Doctests gerade AUSSCHLIESST) und
   die zwei deklarierten Frontendskripte `pnpm desktop:typecheck` und
   `pnpm desktop:test`. Damit laeuft der einzige Waechter der Produktinvariante
   „TypeScript erzeugt nie Grants, Hashes, Signaturen, Chiffrate,
   Registry-Entscheidungen oder Archivbytes" auf der TypeScript-Seite
   (`apps/desktop/src/bridge/no-hand-written-contracts.test.ts`) erstmals in
   einer automatisierten Folge und nicht nur als Handmessung. `pnpm desktop:e2e`
   steht bewusst NICHT in `verify_quick_commands()` — Playwright verlangt
   installierte Browser und einen gebauten Wirt; seine benannte Folge ist
   `STAGE_TWO_STEP_SIX_COMMANDS` samt der Belegzeile in dieser Tabelle.
2. Die Suite ist von 943 auf 955 bestandene Tests gewachsen, bei
   UNVERAENDERTEN 125 Testbinaries — jeder neue Zeuge lebt in einem bestehenden
   Testziel. Die zwoelf sind buendelweise abgerechnet: Buendel B `+7`,
   Buendel C `+2`, Buendel D `+2` und Buendel A `+1`. Der dritte Zeuge des
   Buendels D ist ein TypeScript-Test und zaehlt nicht hier, sondern in
   `pnpm desktop:test`, das im selben Zug von 82 auf 83 Tests gestiegen ist.
   Gemessen im ARBEITSBAUM, also einschliesslich der zwoelf vor Stufe 2
   geaenderten und nicht committeten Dateien; Buendel B hat seinen Commit allein
   in einem eigenen `git worktree` isoliert gemessen und dort `+7` gegen
   `37c4d14` bestaetigt.
3. Das Ledger ist von 143 auf 146 Zeilen gewachsen: drei neue `v1.1`-Zeilen auf
   Stufe 7 mit Status `planned`, die die drei offenen Zeilen aus Abschnitt 2.1
   und 2.2 verankern (`AK-23` fuer Ruling R57, `AK-39` fuer Ruling R60, `AK-53`
   fuer Ruling R59 Teil 2). `stage_two_rows_still_planned` bleibt leer — keine
   dieser Zeilen steht auf Stufe 2.
4. `cargo fmt --all --check` war am Kopf der Welle an vier Stellen rot
   (`apps/desktop/src-tauri/src/commands/writer.rs`,
   `crates/ea-draft/tests/discard_faults.rs`,
   `crates/ea-writer/src/finalize.rs`, `tools/xtask/tests/workspace.rs` — reine
   Umbrueche aus den Buendeln B, C und D). Ohne das waere `pnpm verify:quick` an
   seinem ERSTEN Teilkommando gefallen; das Gate-Buendel hat die vier Stellen
   formatiert, damit diese Zeile eine gemessene und keine behauptete ist.

Die Laufzeiten dieser Tabelle sind die des bestaetigenden Laufs auf einem WARMEN
`target/`-Verzeichnis und deshalb kuerzer als die des Erstlaufs; das Kriterium
dieser Tabelle ist der Exitcode und das abgelesene Ergebnis, nicht die Dauer.

Nachtrag der Reviewrunde 1 (2026-08-21): die Befunde I1 bis I5 haben
`tests/ea-system-tests/tests/{support/mod.rs, fault_injection_writer_matrix.rs,
e2e_writer_archive.rs}`, diesen Bericht und eine Ledgerzeile geaendert. Die
zehn Kommandos wurden deshalb VOLLSTAENDIG NEU gefahren, und die Zahlen dieser
Tabelle sind die dieses Laufs — die Zahl der Tests blieb gleich (keine neue
Testfunktion, nur schaerfere Zusicherungen in den bestehenden fuenf), die
Ledgerzeilen stiegen von 142 auf 143 (die neue `GATE-25`-`v1.1`-Zeile), und die
Laufzeiten sind die neu abgelesenen.

Zur Zeile `pnpm supply-chain`: sie ist der erste `cargo deny check` ueber den
GANZEN Baum, einschliesslich des Tauri-Teilbaums. Er hat drei Befundklassen
gebracht, die Task 5 an seiner Datenbanktranche nicht sehen konnte. Jede ist
NAMENTLICH in `deny.toml` entschieden und keine durch eine Aufweichung der
Politik erledigt:

1. **Zehn Lizenzen ausserhalb der fuenf-Eintrags-Allowlist.** Die Allowlist
   selbst bleibt bei fuenf Eintraegen; die zehn Crates stehen als
   `[[licenses.exceptions]]` je Crate. Eine NEUE Crate unter derselben Lizenz
   wird weiterhin abgewiesen — das ist der Unterschied zwischen einer Ausnahme
   und einer stillschweigenden Erweiterung. Es sind: `base16` und `hexf-parse`
   (`CC0-1.0`, Public-Domain-Widmung), `borrow-or-share` (`MIT-0`), `foldhash`
   (`Zlib`), `target-lexicon` (`Apache-2.0 WITH LLVM-exception`, permissiver als
   `Apache-2.0` allein) und `cssparser`, `cssparser-macros`, `dtoa-short`,
   `option-ext`, `selectors` (`MPL-2.0`, DATEIWEISES Copyleft; alle fuenf reisen
   unveraendert als Abhaengigkeit des Tauri-Teilbaums mit, keine ihrer Dateien
   wird geaendert, es entsteht also keine Offenlegungspflicht fuer eigenen Code).
2. **Sechzehn `unmaintained`-Advisories.** Keine Verwundbarkeit und kein
   `unsound`; jede wird ausschliesslich ueber den Tauri-Teilbaum erreicht, und
   fuer keine gibt es ein sicheres Upgrade. Sie stehen als
   `[advisories] ignore` mit `id` UND `reason` je Eintrag —
   `unmaintained = "allow"` waere die Aufweichung und steht nicht da: eine neue
   unbetreute Crate faellt weiterhin auf. Es sind die zehn gtk-rs-GTK3-Bindings
   (`RUSTSEC-2024-0411` bis `-0420`, der Linux-Fensterpfad von `tauri`, auf dem
   Host-Target dieser Stufe nicht gebaut), `proc-macro-error 1.0.4`
   (`RUSTSEC-2024-0370`, Bauzeit ueber `glib-macros`) und die fuenf
   `unic-*`-Crates (`RUSTSEC-2025-0075`, `-0080`, `-0081`, `-0098`, `-0100`,
   ueber `urlpattern` in `tauri-utils`).

   Diese Schuld hat jetzt einen LEDGERANKER: die `v1.1`-Zeile `GATE-25` auf
   Stufe 7 mit Status `planned` nennt alle sechzehn RUSTSEC-Kennungen und macht
   die erneute Bewertung zur Releasepflicht. Ohne sie stuende die Ausnahme nur
   in diesem Bericht und erzwaenge nichts.

   Die Gegenoption `unmaintained = "workspace"` wurde GEMESSEN und nicht
   vermutet: mit ihr statt der sechzehn Eintraege meldet
   `cargo deny --config <kopie> check advisories` unter `cargo-deny 0.20.2`
   `advisories ok` — sie loest also alle sechzehn Befunde auf, weil jeder
   transitiv ueber den Tauri-Teilbaum kommt. Sie wurde ABGELEHNT: eine
   Reichweiteneinschraenkung nimmt JEDE kuenftige transitive unbetreute Crate
   stillschweigend mit, waehrend die sechzehn namentlichen Eintraege genau
   diese sechzehn erlauben und eine neue rot werden lassen.
3. **`wildcards = "deny"` gegen die Pfadkanten dieses Workspace.** `cargo deny`
   liest jede Kante zwischen zwei Mitgliedern als Wildcard, weil eine
   Pfadabhaengigkeit keine Version traegt; gemessen waren es 19 Fehler ueber
   praktisch jede Bibliotheks-Crate. `wildcards = "deny"` BLEIBT stehen. Gesetzt
   wurde `allow-wildcard-paths = true`, und weil diese Option nach der eigenen
   Meldung von `cargo deny` nur fuer PRIVATE Crates greift, tragen die zwanzig
   `crates/*/Cargo.toml` jetzt `publish = false` — was sachlich richtig ist
   (nichts davon wird veroeffentlicht) und was die vier Nichtbibliotheks-
   mitglieder `apps/cli`, `apps/desktop/src-tauri`, `tools/xtask` und
   `tests/ea-system-tests` seit je fuehren. Gemessen: mit
   `allow-wildcard-paths` allein blieben 19 Fehler, mit `publish = false` dazu
   meldet der Lauf `bans ok`. Die Gegenoption — `wildcards = "allow"` — wurde
   ABGELEHNT: sie haette eine echte Registry-Wildcard nicht mehr gefunden.

## Nachtraege der Nacharbeit DRK-206 (2026-08-28)

Dieser Abschnitt steht ABSICHTLICH hinter `Gemessener Gate-Lauf` und traegt
keine Tabellenzeile: `tools/xtask/tests/stage_gate.rs::measured_run_rows` liest
jede mit `|` beginnende Zeile jenes Abschnitts bis zur naechsten
`##`-Ueberschrift als Belegzeile, und eine weitere waere dort ein Messwert, der
nie gemessen wurde. Die gemessenen Zahlen der Tabelle selbst ruehrt dieser
Abschnitt nicht an.

**N4 — der Zwischenschritt 942/943 ist nicht rekonstruierbar.** Der Vorspann der
Tabelle nennt fuer den Stand vor Task 18 „930 bestandene Tests" und fuer das
Ende der Stufe 2 „943". Die Buendelbilanz der Fix-Welle (`+7`, `+2`, `+2`, `+1`)
rechnet gegen 943 auf 955. Der Schritt von 942 auf 943 ist aus den vorliegenden
Berichten NICHT rekonstruierbar — er steht in keinem Taskbericht und in keiner
Messzeile. Richtiggestellt wird deshalb nur, was belegbar ist: die ENDZAHL 955
in 125 Testbinaries ist gemessen und stimmt; der Zwischenwert 943 ist
uebernommen und nicht nachgemessen. Wer die Reihe nachrechnen will, misst die
Zahl neu, statt sich auf die Zwischenschritte zu stuetzen.

**G5 — die Stufe-1-Endzahl im Fortschrittsprotokoll war falsch.** Das
git-ignorierte Fortschrittsprotokoll der Stufe 2 fuehrt die Reihe als
„Stufe-1-Abschluss 82 Ziele / 688 Tests". Das ist unrichtig. Richtig ist:
**Stufe 1 endete bei 75 Testzielen und 636 bestandenen Tests**, gemessen und
protokolliert in `docs/traceability/stage-1-gate.md:160-167`
(`stage-1-gate.md:166`, `pnpm verify:quick`, Exitcode 0, woertlich „75
Testbinaries und 636 bestandenen Tests"; `:160`, `:161` und `:163` nennen
dieselben Zahlen).
Der geschlossene Stufe-1-Gate-Bericht wird dafuer NICHT bearbeitet; er ist die
Quelle, nicht der Fehler.

**Merker: zwei nicht ausgefuehrte Teile des Befundes F10.** Die mechanischen
Teile von F10 sind am 2026-08-28 erledigt (Commit `2a076dc`:
`crates/ea-writer/tests/grant_completeness.rs` mit abgeleitetem statt
literalem Erwartungswert, `crates/ea-writer/tests/prepared_recovery.rs` mit der
exakten Einzelposition statt `windows().any()`, `crates/ea-writer/src/fault.rs`
mit dem Doc-Kommentar zu den zwei auf der Platte deckungsgleichen Punkten).
NICHT gemacht und ausdruecklich offen sind die zwei nicht-mechanischen Teile:
die Verwerfensmatrix prueft ohne Produktpfad, und die Harnesswurzel traegt
keinen Zaehler. Beide sind Testqualitaet, kein Produktbefund, und keiner der
beiden schwaecht eine bestehende Zusicherung.

**Ruling R62 — die Quittung der Registry-Ueberalterung wandert nach Stufe 5.**
Das Gate-Bullet
`docs/superpowers/plans/2026-08-13-einsatzarchiv-v0-1.md:358` verlangt fuer
Stufe 2 eine dauerhafte signierte Einmal-Quittung. Stufe 2 liefert die
ERKENNUNG mit fail-closed-Ausgang und nicht die Quittung;
`WriterService::acknowledge_stale_registry` ist nicht gebaut — die Crate sagt
es selbst (`crates/ea-writer/src/lib.rs:37-39`), und der Baum traegt keine
Definition dieses Namens —, und `writer_acknowledge_stale_registry` bleibt im
Wirt ein benannter Stummel. Die
Quittung gehoert AUSDRUECKLICH zur Stufe 5, wo auch die Administrationsseite
von AK 24 steht. Begruendung und Belege in
`docs/traceability/stage-2-nacharbeit-2026-08-28.md`.
