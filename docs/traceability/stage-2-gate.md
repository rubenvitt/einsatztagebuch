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
| AK 1 | Offline-Abschluss | `tests/ea-system-tests/tests/e2e_writer_archive.rs::one_incident_goes_from_the_blank_mask_to_a_committed_archive_without_a_network`; `crates/ea-writer/tests/offline_finalize.rs::offline_finalize_commits_grants_then_entry_and_returns_no_content` | Serverabgleich und unteilbarer Entry-Commit auf dem Sync-Weg (Stufe 3) |
| AK 2 | Kein Writer-Zugriff | `tests/ea-system-tests/tests/privacy_canaries_writer.rs::no_fachliche_canary_survives_finalization_anywhere_on_disk`; `tests/ea-system-tests/tests/privacy_canaries_writer.rs::a_restored_backup_never_returns_a_finalized_or_discarded_key` | Der Nachweis der Lesesicht — dass ein berechtigter Reader denselben Eintrag oeffnet — steht in Stufe 4 aus |
| AK 3 | Neue Maske | `tests/ea-system-tests/tests/e2e_writer_archive.rs::one_incident_goes_from_the_blank_mask_to_a_committed_archive_without_a_network`; `apps/desktop/src/features/writer/WriterPage.test.tsx::clears the surface after the commit and offers no history and no final content` | Die Historienansicht, die es hier NICHT gibt, entsteht als Lesesicht in Stufe 4 |
| AK 15 | Stromausfall | `tests/ea-system-tests/tests/fault_injection_writer_matrix.rs::every_declared_stage_two_fault_point_has_exactly_one_survivable_outcome`; `tests/ea-system-tests/tests/fault_injection_writer_matrix.rs::a_media_failure_at_any_durable_step_never_produces_a_half_written_archive` | Der Nachweis auf echter Hardware und auf den vier Zielarchitekturen steht in Stufe 7 aus |
| AK 23 | Plattform-Key-Provider | `crates/ea-key-provider/tests/writer_role_guard.rs::a_claimed_hardware_profile_never_falls_back_silently`; `crates/ea-key-provider/tests/device_posture.rs::every_support_matrix_row_reaches_only_the_os_wrapped_floor`; `tests/ea-system-tests/tests/cross_platform_key_provider_smoke.rs` | Die native Ausfuehrung auf `x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin` und `x86_64-apple-darwin` steht in Stufe 7 aus und wird von vier eigenen `AK-23`-`v1.1`-Ledgerzeilen offen gefuehrt |
| AK 25 | Writer-Restore | `crates/ea-writer/tests/prepared_recovery.rs::a_prepared_finalization_beats_a_second_finalization_attempt`; `tests/ea-system-tests/tests/privacy_canaries_writer.rs::a_restored_backup_never_returns_a_finalized_or_discarded_key` | Der Kopfabgleich gegen einen erreichbaren signierten Server-Checkpoint steht in Stufe 3 aus |
| AK 28 | CSV-Stammdatenimport | `crates/ea-draft/tests/csv_import.rs::dry_run_does_not_write_and_commit_is_all_or_nothing`; `crates/ea-draft/tests/csv_import.rs::retained_protocol_bytes_reproduce_the_snapshot_hash`; `vectors/reports/` | Die Verwaltung der Stammdaten durch eine Administrationsrolle bleibt Stufe 5 |
| AK 34 | Prepared Recovery | `crates/ea-writer/tests/prepared_recovery.rs::after_the_key_boundary_recovery_completes_the_exact_prepared_bytes`; `tests/ea-system-tests/tests/fault_injection_writer_matrix.rs::a_prepared_finalization_survives_a_crash_and_beats_a_pending_discard` | Die Wiederaufnahme einer im Netz haengenden Publikation gehoert Stufe 3 |
| AK 39 | Durable Backend | `tests/ea-system-tests/tests/fault_injection_writer_matrix.rs::every_declared_stage_two_fault_point_has_exactly_one_survivable_outcome`; `tests/ea-system-tests/tests/fault_injection_writer_matrix.rs::a_media_failure_at_any_durable_step_never_produces_a_half_written_archive`; `crates/ea-archive-fs/tests/backend_capabilities.rs::every_declared_capability_is_proven_on_the_host_filesystem` | Die signierte Betriebssystem- und Dateisystemmatrix steht in Stufe 7 aus |
| AK 46 | Entwurfsverwaltung | `crates/ea-draft/tests/single_draft.rs::exactly_one_encrypted_draft_is_restored_after_restart`; `crates/ea-draft/tests/discard_faults.rs::every_discard_fault_yields_old_draft_or_permanent_blank_draft`; `tests/ea-system-tests/tests/fault_injection_writer_matrix.rs::every_declared_discard_fault_point_restarts_into_one_of_two_states` | Der Nachweis ueber ein Releasepaket mit abgeschalteten Absturzberichten bleibt Stufe 7 |
| AK 48 | Bestandsprofile | `tests/ea-system-tests/tests/e2e_writer_archive.rs::one_incident_goes_from_the_blank_mask_to_a_committed_archive_without_a_network`; `crates/ea-archive-fs/tests/controlled_network_profile.rs::controlled_network_requires_a_local_commit_component_and_rejects_a_generic_share` | Der Weg ueber ein tatsaechlich erreichbares kontrolliertes Netz steht in Stufe 3 aus |
| AK 54 | Profilwechsel | `crates/ea-archive-fs/tests/profile_migration.rs::the_inventory_hash_is_equal_on_both_profiles_after_a_successful_switch`; `tests/ea-system-tests/tests/fault_injection_writer_matrix.rs::an_interrupted_profile_migration_leaves_exactly_one_active_pointer` | Die Freigabe eines neuen `archiveProfileHash` gegen `allowed-archive-profile-hashes` bindet Stufe 7 |

Vier weitere Kriterien bekommen von Stufe 2 nur einen TEIL ihres Belegs. Sie
stehen bewusst UNTER der Tabelle und mit dem Praefix `| Teilbeleg AK `: der
Zeilenleser des Gates durchsucht das ganze Dokument nach `| AK ` und verlangt,
dass die gefundenen Nummern genau die zwoelf primaeren sind — eine Teilzeile in
jener Gestalt waere ein unerwartetes Kriterium und faerbte den Gate rot.

| Teilbeitrag | Gegenstand | Stufe-2-Anteil | Wo das Kriterium faellig wird |
|---|---|---|---|
| Teilbeleg AK 19 | Keine Klartextlogs | `tests/ea-system-tests/tests/privacy_canaries_writer.rs::no_fachliche_canary_survives_finalization_anywhere_on_disk` ueber jeden beobachtbaren Bytestrom, `tests/ea-system-tests/tests/privacy_canaries_writer.rs::the_search_finds_a_marker_that_really_lies_on_disk` als Gegenkontrolle, und `crates/ea-audit/tests/redaction.rs::typed_audit_never_carries_fachliche_bytes_and_never_leaks_in_errors` | Stufe 7 — der Nachweis ueber ein Releasepaket mit abgeschalteten Absturzberichten und abgeschalteter Telemetrie |
| Teilbeleg AK 24 | Registry-Ueberalterung | `crates/ea-writer/tests/stale_registry_warning.rs::a_head_that_expires_while_bound_is_acknowledgeable_and_blocks_fail_closed` und `::an_overdue_refresh_deadline_warns_without_blocking` — die ERKENNUNG samt fail-closed-Ausgang | Stufe 5 — der Bestaetigungspfad eines veralteten Kopfes selbst |
| Teilbeleg AK 29 | Rollentrennung | `crates/ea-key-provider/tests/writer_role_guard.rs::writer_profile_rejects_forbidden_private_key_purposes` und `apps/desktop/src/app/csp.test.ts` fuer die Kommandoerlaubnisliste der Wirtsseite | Stufe 5 — die Administrationsseite der Rollentrennung |
| Teilbeleg AK 53 | Operator-Identitaet | `crates/ea-operator/tests/session_contract.rs::finalization_requires_matching_account_instance_key_and_fresh_presence` und `crates/ea-draft/tests/discard_faults.rs::a_proof_of_another_operator_binding_never_authorizes_a_discard` — die Bindung des Bedieners an jede unwiderrufliche Handlung | Stufe 5 — die Ausstellung der Bindung und die Transport-Fingerprint-Bindung |

Jede dieser vier fuehrt im Ledger eine EIGENE `v1.1`-Zeile auf Stufe `2` mit
Status `implemented`; die `v1`-Zeile behaelt ihre spaetere Stufe und ihr
`planned` unveraendert. Spaetere Stufen ergaenzen nur Zeilen.

## 2. Reichweite der Stufe-2-Abnahme

Die Klausel, Wort fuer Wort, wie `tools/xtask/src/main.rs` sie als
`STAGE_TWO_HOST_SCOPE_CLAUSE` fuehrt und wie der Gate sie hier als Literal
verlangt:

Stufe 2 belegt Baubarkeit ausschliesslich fuer das Host-Target: rust-toolchain.toml:5 stellt nur wasm32-unknown-unknown bereit (gepinnt in tools/xtask/tests/workspace.rs:278-294), und die vier Cross-Targets x86_64-pc-windows-msvc, x86_64-unknown-linux-gnu, aarch64-apple-darwin, x86_64-apple-darwin werden von Task 18 namentlich als offene Stufe-7-Ledgerzeilen eingetragen statt lokal behauptet.

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

Eine Folge des GETEILTEN Berichtsschemas, damit sie niemand spaeter als Drift
liest: `evidenced_acceptance_criteria` wird stufenUNabhaengig ueber alle
Ledgerzeilen gerechnet (`tools/xtask/src/main.rs:1642-1649`). `stage-gate 1`
listet seit diesem Task deshalb AUCH die Stufe-2-Kriterien; die gemessene Zeile
in `docs/traceability/stage-1-gate.md:164` bleibt der Beleg IHRER eigenen
Messung und wird nicht umgeschrieben. Der geschlossene Stufe-1-Gate-Bericht ist
in diesem Task nicht angefasst.

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
frisch ausgefuehrt am 2026-08-21 in der hier protokollierten Reihenfolge. Jedes
Kommando lief mit `env -u RUSTUP_TOOLCHAIN`, weil die Shell `RUSTUP_TOOLCHAIN`
auf `1.97.1` setzt und damit den Pin `1.95.0` aus `rust-toolchain.toml`
uebersteuern wuerde; die aktive Toolchain war gemessen
`1.95.0-aarch64-apple-darwin`. `pnpm supply-chain` setzt
`cargo install --locked cargo-deny` voraus; installiert und gemessen war
`cargo-deny 0.20.2`. Die Zahlen sind abgelesen, nicht geschaetzt:
`0 passed; N filtered out` waere kein Ergebnis, sondern ein defekter Filter, und
kommt in keiner Zeile vor. Der Ausgangsstand vor diesem Task waren 122
Testbinaries mit 930 bestandenen Tests; am Ende der Stufe 2 steht
`cargo test --workspace --all-targets --locked` gemessen bei 125 Testbinaries
mit 943 bestandenen Tests — die dreizehn Tests dieses Tasks in drei neuen
Testbinaries, keine bestehende Zusicherung entfernt oder aufgeweicht. Die sechs
ignorierten Tests sind der Bestand aus frueheren Stufen und dieser Lauf aendert
nichts an ihnen.

| Kommando | Exitcode | Gemessenes Ergebnis | Laufzeit |
|---|---|---|---|
| `cargo test --locked -p ea-writer` mit den zehn `-p`-Namen der Schritt-6-Folge | 0 | 45 Testbinaries und die Doctest-Ziele der zehn Pakete, 265 bestanden, 0 fehlgeschlagen, 0 ignoriert, 0 gefiltert | 222,31 s |
| `cargo test --locked -p ea-system-tests --test fault_injection_writer_matrix` | 0 | 5 bestanden, 0 fehlgeschlagen, 0 ignoriert, 0 gefiltert | 18,63 s |
| `cargo test --locked -p ea-system-tests --test privacy_canaries_writer` | 0 | 4 bestanden, 0 fehlgeschlagen, 0 ignoriert, 0 gefiltert | 5,14 s |
| `cargo test --locked -p ea-system-tests --test e2e_writer_archive` | 0 | 2 bestanden, 0 fehlgeschlagen, 0 ignoriert, 0 gefiltert | 4,44 s |
| `pnpm desktop:typecheck` | 0 | `tsc --noEmit` ohne eine einzige Diagnose | 1,90 s |
| `pnpm desktop:test` | 0 | 9 Testdateien, 82 Tests bestanden, 0 fehlgeschlagen | 12,52 s |
| `pnpm desktop:e2e` | 0 | 3 Playwright-Tests bestanden, 1 Worker, Netz abgeschaltet | 4,92 s |
| `pnpm supply-chain` | 0 | `advisories ok, bans ok, licenses ok, sources ok`; 37 `duplicate`-Warnungen aus dem Tauri-Teilbaum, die `multiple-versions = warn` bewusst nur warnt; `cargo-deny 0.20.2` | 2,53 s |
| `pnpm stage-gate:2` | 0 | JSON auf stdout: 16 deklarierte Abbruchpunkte, 142 Ledgerzeilen, 4 `host_evidence_rows`, `stage_two_rows_still_planned` leer, `vector_families` = `[local-audit, reports]` | 1,50 s |
| `pnpm verify:quick` | 0 | fuenf Teilkommandos gruen: `cargo fmt --all --check`, `pnpm --dir apps/desktop build`, `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` ohne Warnung, `cargo test --workspace --all-targets --locked` und der wasm32-Check; `cargo test --workspace --all-targets --locked` mit 125 Testbinaries, 943 bestanden, 0 fehlgeschlagen, 6 ignoriert, 0 gefiltert | 380,60 s |

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
