# Stufe-1-Gate-Bericht — Vertrauenskern, Format, Vektoren

Stand: Abschluss der Stufe 1 von v0.1. Dieser Bericht ist ein vom Gate
geprueftes Artefakt: `xtask stage-gate 1` liest ihn, verlangt die fuenf
Abschnitte dieses Dokuments, die Belegzeile jedes primaeren Abnahmekriteriums
und die Reichweitenklausel aus Abschnitt 2 als Literal. Der angehaengte
Abschnitt `Gemessener Gate-Lauf` haelt zusaetzlich den tatsaechlich gelaufenen
Abschlusslauf fest; `tools/xtask/tests/stage_gate.rs::stage_one_gate_report_records_the_measured_full_gate_run`
verlangt fuer jedes Kommando der vorgeschriebenen Folge eine eigene Belegzeile.

Maschinelle Gegenstuecke: `docs/traceability/v0.1-requirements.csv` (Ledger,
maschinell auf Vollstaendigkeit geprueft) und der JSON-Bericht von
`cargo run --locked -p xtask -- stage-gate 1`.

## 1. Primaere Abnahmekriterien und ihre Belege

Die zehn primaeren Abnahmekriterien der Stufe 1 nach `design.md` Abschnitt 23.
Die letzte Spalte nennt ausdruecklich, welcher Beitrag desselben Kriteriums in
spaeteren Stufen offen bleibt — ein gruener Stufe-1-Gate belegt den Stufe-1-
Anteil, nie das ganze Kriterium.

| Kriterium | Gegenstand | Beleg | Offen in spaeterer Stufe |
|---|---|---|---|
| AK 4 | Byte-Manipulation | `crates/ea-format/tests/negative.rs::one_byte_prefix_mutations_have_exact_fail_closed_errors`; `crates/ea-verify/tests/manifest_signature.rs::each_reachable_manifest_signature_binding_fails_on_its_own_one_byte_mutation`; `vectors/format/v1/invalid/manifest.json` ueber `tests/ea-system-tests/tests/conformance_golden_vectors.rs::format_v1_valid_objects_and_single_byte_mutations_match_their_manifests` | Manipulation auf dem Sync-Weg (Stufe 3) und im Reader (Stufe 4) |
| AK 5 | Kettenluecke | `crates/ea-chain/tests/chain_core.rs::missing_sequences_collapse_into_maximal_intervals_and_a_stub_fills_its_own`; `crates/ea-recovery/tests/live_clock.rs::a_missing_middle_entry_is_the_only_finding_at_the_real_os_clock` | Darstellung der Luecke im Reader (Stufe 4); Betriebsnachweis (Stufe 7) |
| AK 6 | Vertauschung | `crates/ea-chain/tests/chain_core.rs::genesis_is_sequence_zero_and_each_successor_binds_its_predecessor`; `crates/ea-verify/tests/chain_position_grant_plan.rs::swap_gap_orphan_grant_and_plan_hash_have_distinct_outcomes`; Eigenschaft Kettenbildung in `tests/ea-system-tests/tests/conformance_properties.rs::deterministic_encoding_chain_and_parser_properties_hold` | Fork-Aufloesung beim Sync (Stufe 3) |
| AK 9 | Boesartiger Server-Key | `crates/ea-trust/tests/certificate_attacks.rs::every_direct_initial_bootstrap_object_must_be_anchor_pinned`; `crates/ea-verify/tests/trust_registry.rs::an_entry_with_an_unknown_writer_certificate_is_unattributable_not_a_gap`; `vectors/trust/v1/manifest.json` | Anker- und Schluesselverwaltung (Stufe 5); Frischrechner-Nachweis (Stufe 7) |
| AK 14 | Server dauerhaft weg | `apps/cli/tests/exit_codes.rs::a_live_archive_verifies_with_zero`; `apps/cli/tests/exit_codes.rs::a_foreign_but_self_consistent_anchor_fails_with_twelve`; `crates/ea-recovery/tests/fs_source.rs::the_report_over_the_file_system_equals_the_report_in_memory` | Serverexport (Stufe 3); Anker- und Recovery-Verwaltung (Stufe 5); Nachweis auf frischem Rechner (Stufe 7) |
| AK 16 | Falsche Geraetezeit | `crates/ea-time/tests/effective_now.rs::os_clock_below_floor_uses_floor_and_reports_clock_rollback`; `crates/ea-trust/tests/head_selection.rs::os_clock_rollback_keeps_the_persisted_floor_and_warning`; `crates/ea-recovery/tests/live_clock.rs::the_inherited_fixture_says_nothing_at_the_real_os_clock` | TSA-Zeit und Evidence-Erneuerung (Stufe 6) |
| AK 17 | Schema und Suite v1/v2 | Eigenschaft 6 (`check_cross_version_and_compatibility`) in `tests/ea-system-tests/tests/conformance_properties.rs::deterministic_encoding_chain_and_parser_properties_hold`; die Negativvektoren fuer unbekannte Objektversion, kritische Erweiterung und fremdes Objekttyp-Tag in `vectors/format/v1/invalid/manifest.json` | Gekennzeichnete Altansicht im Reader (Stufe 4); Cross-Version-Matrix (Stufe 7) |
| AK 20 | Recovery-Bericht | `apps/cli/tests/determinism.rs::report_is_byte_identical_without_runtime_metadata`; `apps/cli/tests/determinism.rs::report_hash_is_unaffected_by_runtime_metadata`; `crates/ea-recovery/tests/exit_codes.rs::every_finding_maps_to_its_normative_exit_code` | Recovery-Verwaltung und Berichtsablage (Stufe 5) |
| AK 38 | CLI und Export | `apps/cli/tests/exit_codes.rs::every_reachable_live_finding_maps_to_its_normative_exit_code`; `apps/cli/tests/export.rs::export_preserves_every_original_byte`; `apps/cli/tests/export.rs::the_exported_archive_verifies_to_the_same_report_hash`; `apps/cli/tests/commands.rs::trust_commands_require_external_anchor` | Serverexport (Stufe 3); Anker-Bereitstellung (Stufe 5); Plattformnachweis (Stufe 7) |
| AK 51 | Grant-Interoperabilitaet | `vectors/grants/v1/manifest.json` (Plan-Sortierung, Duplikatverbote, `eag-v1`, HPKE-Info/AAD, Kapselungswert, umschlossener CEK, Signaturdigest, Ein-Byte-Negative) ueber `tests/ea-system-tests/tests/conformance_golden_vectors.rs::grant_receipt_and_evidence_vectors_match_their_manifests` | Gegenprobe mit einer fremden Implementierung (Stufe 7) |

Die zuletzt nachhinkenden Ledgerzeilen sind nachgezogen. `AK-17` und `AK-51`
tragen in `docs/traceability/v0.1-requirements.csv` den Status `implemented` und
nennen die Belege dieser Tabelle statt der Tasks, die sie liefern sollten; der
JSON-Bericht des Gates zaehlt in `evidenced_acceptance_criteria` seither
gemessen `[4, 5, 6, 9, 14, 16, 17, 20, 38, 51]` — alle zehn primaeren
Abnahmekriterien der Stufe 1. Die Spalte ganz rechts bleibt dabei tragend: ein
belegter Stufe-1-Anteil ist kein erfuelltes Kriterium.

Die Belegpflicht selbst — jedes primaere Abnahmekriterium braucht eine
Ledgerzeile im Status `implemented` oder `integrated` — bleibt im Gate dennoch
bewusst NICHT scharf geschaltet: sie waere eine Bedingung, die eine spaetere
Stufe mit einer legitimen Statusaenderung brechen koennte, ohne dass an Stufe 1
etwas falsch waere. Der Gate prueft an dieser Stelle die
Belegtabelle dieses Berichts: jede der zehn Zeilen existiert, nennt einen
konkreten Beleg und nennt den offenen Beitrag.

## 2. Reichweite des wasm32-Gates

Die folgende Klausel steht woertlich so im Kommentar ueber dem
`wasm32-unknown-unknown`-Kommando in `verify_quick_commands()`
(`tools/xtask/src/main.rs`):

> Belegt ausschliesslich UEBERSETZBARKEIT fuer wasm32-unknown-unknown, nicht Lauffaehigkeit. Der Laufzeitnachweis nach docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md §14.1 (wasm-bindgen-Schicht, getrandom/wasm_js in einer echten JS-Umgebung, eine HPKE-Entkapselung, eine Signaturpruefung gegen einen Testvektor) steht aus.

Ein gruener Stufe-1-Gate ist damit kein Nachweis, dass der Browser-Reader
laeuft. Er belegt, dass die geteilte Verifikationspipeline — `ea-types`,
`ea-cbor`, `ea-crypto`, `ea-format`, `ea-schema`, `ea-time`, `ea-trust`,
`ea-archive`, `ea-chain`, `ea-verify` — fuer `wasm32-unknown-unknown`
uebersetzt. `ea-recovery` und `ea-testkit` stehen begruendet in
`WASM32_EXEMPT_CRATES`, weil sie ueber `std::fs` hinausgreifen und kein
geteilter Browsercode sind.

## 3. Entscheidung D1: organizationAdminAuthorization

Menschliche Entscheidung vom 2026-08-17. `organizationAdminAuthorization`
bleibt eingefroren: Kardinalitaet 1 (`schemas/archive/v1/trust.cddl`,
`[cose-sign1-v1]`, hart indiziertes `signatures()[0]` in
`crates/ea-trust/src/admin_authorization.rs`) und das 15-Feld-Array in
`crates/ea-format/src/etb.rs`. Die in Stufe 1 eingefrorenen Positiv- und
Negativvektoren dieser Familie (`vectors/trust/v1/manifest.json`) gelten
unveraendert.

Ausdruecklich festgehalten: die Bindung eines Ziel-Transport-Public-Key-
Fingerprints aus `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` Abschnitt 7.5
wird von dieser Familie NICHT ausgedrueckt — Position 15 ist ein an drei
Stellen auf Laenge 0 geprueftes leeres Extension-Array. Die hier eingefrorenen
Vektoren sind deshalb KEIN Beleg fuer Abschnitt 7.5. Der Beleg entsteht mit
einer eigenen 2-of-N-Trust-Objektfamilie nach dem Vorbild von
`grantAuthorization`/`destructionAuthorization` (`[2* cose-sign1-v1]`), gebaut
in Stufe 5 als v1.1.

## 4. Entscheidung D3: Web-Reader-Zeilen und FR-100/FR-103

Menschliche Entscheidung vom 2026-08-17. Die sieben MUSS-Anforderungen des
Web-Reader-Specs stehen als `v1.1`-Zeilen im Requirement-Ledger, jede im Status
`planned` mit der Stufe, die sie baut:

| Zeile | Spec | Gegenstand | Faellig |
|---|---|---|---|
| WR-041 | 4.1 | getrennter Origin | Stufe 3 |
| WR-042 | 4.2 | Aktivierung nur gegen eine gepinnte, Root-signierte `webBundleRelease` | Stufe 3 |
| WR-043 | 4.3 | nicht ueberspringbarer Fingerprint-Vergleich | Stufe 3 |
| WR-052 | 5.2 | universeller Datei-Weg immer angeboten | Stufe 4 |
| WR-063 | 6.3 | zwei Pflicht-Authenticators | Stufe 4 |
| WR-075 | 7.5 | Verweigerung der Re-Encryption bei abweichendem Transport-Fingerprint | Stufe 5 |
| WR-082 | 8.2 | kein Klartext in Telemetrie | Stufe 4 |

`design.md` Abschnitt 27.1 ist auf die neue Rollenaufteilung nachgezogen:
FR-100 beschreibt Writer und Administration auf dem Desktop und den
Browser-Reader als getrennte Rollen statt einer gemeinsamen App; FR-103
beschreibt den verschluesselten Rust-Index in OPFS unter ChaCha20-Poly1305
statt eines SQLCipher-Caches. Beide Zeilen zitieren den Web-Reader-Spec.

Die geraeteseitige Aktualisierungsfrist aus Spec Abschnitt 4.2 traegt das
eigene Policy-Feld `reader-trust-refresh-ms` in `policy-core-v1`; der
Positivvektor dazu steht in `vectors/trust/v1/manifest.json` und wird von
`tests/ea-system-tests/tests/conformance_golden_vectors.rs::policy_core_v1_positive_vectors_pin_the_device_side_trust_refresh_deadline`
nachgerechnet.

## 5. Unveraenderlichkeit der Vektoren und Vektor-Hygiene

Ab diesem Commit ist jeder eingefrorene Vektor unveraenderlich. Die Dateien
unter `vectors/` und die Erwartungswerte in ihren Manifesten werden nicht mehr
neu erzeugt, nicht umsortiert und nicht neu formatiert. Aendert sich ein
Verhalten, entsteht eine neue Fassung neben der alten
(`vectors/<familie>/<version>/`), nie an ihrer Stelle. Ein geaenderter Vektor
waere kein Test mehr, sondern eine Abschrift des jeweils aktuellen Codes.

Zwei Richtungen sind zu unterscheiden. Deterministisch regenerierbar sind
`.eip`, `.esr`, `.ecp`, `.etb` und `.eds`: `aead_seal` nimmt die Nonce als
expliziten Parameter, die COSE-Signierer bauen aus festen Schluesselbytes, und
Ed25519 ist deterministisch. NICHT regenerierbar ist `.eag` und jedes Objekt,
das einen Kapselungswert oder einen umschlossenen CEK traegt: `hpke_seal` zieht
bei jedem Aufruf frische Entropie des Betriebssystems, und der injizierende
Pfad ist absichtlich privat. Diese Bytes wurden einmal erzeugt und eingefroren;
ihre Nachpruefung laeuft ausschliesslich in der entkapselnden Richtung ueber
`hpke_open`, und die Ein-Byte-Negativvektoren auf Kapselungswert und
umschlossenen CEK liefern deterministisch `CryptoError::HpkeOpen`.

Hygieneregel, verbindlich fuer jeden Negativvektor dieses Bestands: ein
unzulaessiger Handlungscode MUSS `action_code` `200` verwenden, und ein unbekannter
Trust-Subtype MUSS das Literal `xxUnknownxx` verwenden. Nachbarwerte des
heutigen Bestands — insbesondere der `action_code` `7` und jeder Name, der
spaeter eine echte Trust-Objektfamilie werden koennte — sind verboten.
Begruendung: ein dauerhaft eingefrorener Negativvektor mit nachbarschaftlichem
Wert dreht sich bei einer spaeteren v1.1-Erweiterung von `abgelehnt` nach
`akzeptiert` und behauptet dann das Gegenteil dessen, was er festhalten soll.
Das waere der einzige echte Bruch des Permanenzversprechens; die
Byte-Unveraenderlichkeit selbst ist davon nicht betroffen.

## Gemessener Gate-Lauf

Der vollstaendige Lauf nach Schritt 4 des Stufe-1-Plans
(`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md`),
frisch ausgefuehrt am 2026-08-17 in der hier protokollierten Reihenfolge. Jedes
Kommando lief mit `env -u RUSTUP_TOOLCHAIN`, weil die Shell `RUSTUP_TOOLCHAIN`
auf `1.97.1` setzt und damit den Pin `1.95.0` aus `rust-toolchain.toml`
uebersteuern wuerde; die aktive Toolchain war gemessen
`1.95.0-aarch64-apple-darwin`. Die Zahlen sind abgelesen, nicht geschaetzt:
`0 passed; N filtered out` waere kein Ergebnis, sondern ein defekter Filter, und
kommt in keiner Zeile vor.

| Kommando | Exitcode | Gemessenes Ergebnis | Laufzeit |
|---|---|---|---|
| `pnpm test:core` | 0 | 75 Testbinaries, 636 bestanden, 0 fehlgeschlagen, 5 ignoriert, 0 gefiltert | 17,49 s |
| `pnpm test:golden` | 0 | 75 Testbinaries, 636 bestanden, 0 fehlgeschlagen, 5 ignoriert, 0 gefiltert | 15,07 s |
| `pnpm test:property` | 0 | 75 Testbinaries, 636 bestanden, 0 fehlgeschlagen, 5 ignoriert, 0 gefiltert | 14,89 s |
| `pnpm test:fuzz --smoke-seconds 60` | 0 | 4 Ziele ohne `--target`, je 61 s Smoke, zusammen 9 114 330 Laeufe: `cbor_object` 5 866 417, `cose_sign1` 1 747 705, `hpke_grant` 138 440, `object_bounds` 1 361 768; kein Absturz, keine geschriebene Testeinheit | 248,21 s |
| `pnpm test:recovery` | 0 | 75 Testbinaries, 636 bestanden, 0 fehlgeschlagen, 5 ignoriert, 0 gefiltert | 16,24 s |
| `cargo run --locked -p xtask -- stage-gate 1` | 0 | JSON auf stdout, byteidentisch zum Vorlauf: 6 Vektorfamilien, 133 Ledgerzeilen, 4 Fuzz-Ziele fuer 5 Flaechen, `evidenced_acceptance_criteria` = `[4, 5, 6, 9, 14, 16, 17, 20, 38, 51]` | 0,40 s |
| `cargo check --target wasm32-unknown-unknown --locked -p ea-types -p ea-cbor -p ea-crypto -p ea-format -p ea-schema -p ea-time -p ea-trust -p ea-archive -p ea-chain -p ea-verify` | 0 | die zehn Crates der Positivliste uebersetzen fehlerfrei, keine Warnung; warmer Build-Cache; Reichweite nach Abschnitt 2 | 0,10 s |
| `pnpm verify:quick` | 0 | vier Teilkommandos gruen: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` ohne Warnung, `cargo test --workspace --all-targets --locked` mit 75 Testbinaries und 636 bestandenen Tests, der wasm32-Check | 18,71 s |

Der Ausgangsstand vor diesem Vorhaben waren 596 bestandene Tests im Workspace;
`cargo test --workspace --all-targets --locked` steht am Ende der Stufe 1
gemessen bei 636 in 75 Testbinaries. Die fuenf ignorierten Tests sind der
Bestand aus frueheren Stufen und dieser Lauf aendert nichts an ihnen.

Ablauf der Messung, damit sie nachvollziehbar bleibt: der Test
`stage_one_gate_report_records_the_measured_full_gate_run` entstand vor der
Messung und schlug fehl, weil dieser Abschnitt fehlte. Danach lief die Folge
oben frisch durch, und erst danach sind ihre Zahlen hier eingetragen worden. Die
einzige Aenderung am Arbeitsbaum nach dem protokollierten Lauf ist dieses
Eintragen selbst; die abschliessende Wiederholung von `cargo fmt --all --check`,
`cargo clippy`, `cargo test --workspace --all-targets --locked` und
`xtask verify-quick` bestaetigt, dass sie nichts verschoben hat.

Reichweite dieses Laufs: eine Maschine, `aarch64-apple-darwin`, eine Toolchain.
Der Lauf belegt den Zustand dieses Arbeitsbaums zum genannten Zeitpunkt, keine
Plattformmatrix — die steht nach `design.md` Abschnitt 23 in Stufe 7 aus.
