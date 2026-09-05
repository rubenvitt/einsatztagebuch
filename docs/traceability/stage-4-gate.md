# Stufe-4-Gate-Bericht — Browser-Reader

Dieser Bericht schliesst die Stufe 4 des Einsatzarchivs ab. Er haelt fest, was
die Stufe BELEGT, und — mit demselben Gewicht — was sie NICHT belegt. Ein
gruener `stage-gate 4` ist der Beleg fuer die Zusagen, die hier ausgeschrieben
stehen, und fuer keine darueber hinaus.

Die Stufe baut den Browser-Reader: ein Web-Buendel von getrenntem Origin, einen
Service Worker, der nur ein gepinntes, Root-signiertes Release aktiviert, den
inkrementellen Sync mit verifiziertem Cursor in OPFS, den verschluesselten
invertierten Index, die Verifikation VOR jeder Entschluesselung, den
Datei-Modus ohne Cursor, die Sitzungssperre und den authenticator-bestaetigten
Einzelexport mit signiertem lokalem Audit. Er schreibt nichts, administriert
nichts und autorisiert nichts.

Ein gruener Stufe-4-Gate ist ausdruecklich kein Beleg fuer einen betriebenen getrennten Bundle-Host, fuer Safari, fuer eine gepinnte Browser-Mindestversion je Plattform und fuer die 50.000-Paket-Abnahme aus Abnahmekriterium 31. Alle vier stehen unten
in `## Offen in spaeterer Stufe` mit ihrer besitzenden Stufe.

## 1. Primaere Abnahmekriterien und ihre Belege

Die drei primaeren Abnahmekriterien der Stufe 4 nach `design.md` Abschnitt 23.
Die vierte Spalte ist keine Formsache: eine leere Zelle waere genau die
Scheinzusage, die dieser Bericht ausschliesst, und `run_stage_four_gate` weist
sie ab.

| Kriterium | Gegenstand | Beleg | Offen in spaeterer Stufe |
|---|---|---|---|
| AK 10 | Mehrere Reader | `tests/ea-system-tests/tests/cross_platform_two_readers.rs::one_ciphertext_opens_under_two_distinct_reader_kem_keys_through_separate_grants`; EIN Chiffrat oeffnet unter zwei verschiedenen Reader-KEM-Schluesseln durch getrennte Grants, in beiden Laeufen mit der vollstaendigen Neunerfolge aus `GATE_ORDER_V1` und genau einem `hpke-open`; derselbe Klartext kommt aus beiden Grants | Die Ausstellung und der Entzug von Reader-Grants durch eine Administrationsrolle sind Stufe 5; `readerKeyEscrow` und die Zwei-Approver-Oeffnungszeremonie ebenfalls (`WR-075`) |
| AK 42 | Fehlender Reader-Grant | `crates/ea-reader/tests/missing_grant.rs::a_valid_entry_without_an_own_grant_is_exactly_missing_grant`; `::missing_grant_gap_unknown_key_and_invalid_never_collapse`; `tests/ea-system-tests/tests/cross_platform_two_readers.rs` als systemweite Wiederholung; der Befund ist exakt `fehlender Grant` — nie eine Luecke, nie ein Mangel, und `is_fully_verified()` bleibt wahr | Die Aufloesung eines historischen Grants ueber `grantAuthorization` bleibt Stufe 5; bis dahin misst `historical-grant-unresolvable` eine ABWESENHEIT (Abschnitt 3.3) |
| AK 43 | Inkrementeller Reader-Sync | `crates/ea-reader/tests/sync_resume.rs::the_cursor_moves_only_after_every_object_is_durable_and_the_chain_verifies`; `tests/ea-system-tests/tests/e2e_reader_sync_interruptions.rs`; der bestaetigte Cursor bleibt nach JEDEM der fuenfzehn Abbruchpunkte unveraendert, und der Wiederholversuch laeuft idempotent auf denselben Kopf | Die Raeumung `conflicting` quarantaenisierter Objekte aus dem Objektcache ist eine Entscheidung ausserhalb dieser Stufe (Abschnitt 3.2); die Serverhaelfte der Leseflaechen liegt bereits in Stufe 3 |

### 1.1 Teilbelege dieser Stufe

Zwei Kriterien bekommen in dieser Stufe einen TEILbeleg. Ihre vollen Zeilen
behalten ihre bisherige Stufe; die Teilzeilen stehen als eigene
`v1.1`-Ledgerzeilen, nach dem Muster, das die Stufen 2 und 3 fuer AK-19, AK-21,
AK-24, AK-29 und AK-53 bereits verwenden. Sie tragen ausdruecklich das
Zeilenpraefix `| Teilbeleg AK ` und nicht `| AK `: eine Zeile `| AK 19 |`
braeche die Gleichheit gegen `STAGE_FOUR_PRIMARY_ACCEPTANCE_CRITERIA`.

| Teilbeitrag | Gegenstand | Stufe-4-Anteil | Wo das Kriterium faellig wird |
|---|---|---|---|
| Teilbeleg AK 19 | Keine Klartextlogs (Reader) | `tests/ea-system-tests/tests/privacy_canaries_reader.rs` — je fachlichem Feld GENAU EIN Marker, gesucht in sieben Stroemen: den rohen OPFS-Bytes (Tresor, Objektcache, Zustandsspeicher, Indexblob), dem Service-Worker-Cache, den Zwischenablage-Haken, den strukturierten Logs, den Fehlerberichten, den Servermetadaten und der Telemetrie, samt Positivkontrolle ueber einen absichtlich unverschluesselt abgelegten Kontrollstrom. DREI der sieben Stroeme sind dabei QUELLENSCANS und keine Laufzeitmessung — Service-Worker-Cache, Zwischenablage und Telemetrie —, weil sie in diesem Baum keine Rust-Darstellung haben; der Zeuge schreibt das in seinem eigenen Kopf aus und behauptet die andere Aussage nicht | Stufe 7 — der Nachweis ueber ein Releasepaket mit abgeschalteten Absturzberichten und abgeschalteter Telemetrie |
| Teilbeleg AK 17 | Schema und Suite v1/v2 (Reader-Altansicht) | `crates/ea-index/tests/schema_compatibility.rs` — der Reader STELLT eine frueheres Schema tragende Altansicht dar, ohne sie zu schreiben | Stufe 7 — die Cross-Version-Matrix; die volle Zeile bleibt bei ihrer Stufe |

## 2. Reichweite der Stufe-4-Abnahme

Stufe 4 belegt ihre Browserabnahme ausschliesslich gegen die drei Engine-Baus, deren Herkunft das gepinnte Abbild aus ops/compose/browsers.yaml ist: mcr.microsoft.com/playwright:v1.62.1-noble@sha256:dcc5531e97840b9b5e794f2814476b21571c5124a3fca2267d73041f56e7580e, gefahren unter dem Pin @playwright/test 1.62.1 und den Baus chromium-1234 (Chrome for Testing 151.0.7922.34), firefox-1538 (Firefox 153.0) und webkit-2336 (WebKit 26.5), auf node 26.7.0 und mit wasm-bindgen 0.2.126 als Crate UND als CLI. Ein Betrieb gegen Safari, gegen eine andere Engine-Revision, gegen eine andere Node-Fassung oder gegen eine gepinnte Browser-Mindestversion je Plattform ist damit NICHT belegt und bleibt Stufe 7.

### 2.1 Wo die Engines wirklich herkommen — gemessen

Die Klausel nennt die HERKUNFT und nicht den Wirt, und der Unterschied ist
gemessen. `cargo run --locked -p xtask -- browsers up` exportiert allein
`CHROMEDRIVER_REMOTE` (`run_browsers_up` in `tools/xtask/src/main.rs`) und
keinen Pfad, unter dem Playwright auf dem Wirt Engine-Baus faende;
`pnpm web:e2e` laeuft auf dem WIRT. `chromium-1234` und `firefox-1538` laufen
dort aus dem Playwright-Cache, revisionsgleich zum gepinnten Abbild.
`webkit-2336` startet auf einem Wirt ohne die WebKit-Systembibliotheken nicht
(gemessen: `libevent-2.1.so.7` fehlt); der Zeuge faehrt WebKit deshalb ueber
einen `playwright run-server` IM gepinnten Abbild, und
`apps/web/playwright.config.ts` haengt das Projekt `webkit` GENAU DANN ueber
`connectOptions` an `EA_WEBKIT_WS_ENDPOINT`, wenn die Variable gesetzt ist.
Ohne sie startet WebKit lokal — die CI-Form.

Ob `browsers up` diesen Dienst kuenftig selbst startet und die Variable
druckt, ist eine offene Zeile und steht unten in
`## Offen in spaeterer Stufe`.

### 2.2 Die Klammer um `pnpm verify:quick`

Seit Stufe 3 sind `apps/server` und `crates/ea-sync-server` Mitglieder des
Arbeitsbereichs; das Teilkommando `cargo test --workspace --all-targets
--locked` aus `verify_quick_commands()` zieht ihre Integrationstestziele mit,
und `#[sqlx::test]` liest `DATABASE_URL` zur Laufzeit. Der gemessene Lauf
dieser Stufe fasst `pnpm verify:quick` deshalb in
`cargo run --locked -p xtask -- integration up` … `integration down`. Die
Vorbedingung selbst ist bereits gebaut:
`ensure_integration_services_available()` prueft PostgreSQL und Object Store
fail-closed vor dem betroffenen Kommando, und ein Ueberspringen ueber eine
Umgebungsvariable ist ausgeschlossen. Der Stufe-3-Bericht hat genau diesen
Marker fuer diese Stufe hinterlassen; hier ist er eingeloest.

## 3. Fehlermatrix und deklarierte Szenarien

`docs/traceability/stage-4-fault-points.json` deklariert ZWEIUNDDREISSIG
Szenarien in FUENF Abschnitten. Der Gate liest die Deklaration UND loest jeden
`witness` auf eine wirklich vorhandene, attributierte Testfunktion auf; die
Tabellen unten nennen zu jedem Szenario den Zeugen, der es wirklich faehrt.

Eine Zahl steht dabei ausdruecklich NICHT gleich: der Gate weist 21
VERSCHIEDENE Zeugen aus und nicht 32. Zwoelf Abbruchpunkte des Abschnitts
`sync-cursor` rahmen DENSELBEN Durchlauf, und ein eigener Zeuge je Rahmen waere
zwoelfmal dieselbe Aussage. `resolved_fault_point_witnesses` sammelt deshalb in
ein `BTreeSet`, und der Stufe-4-Test vergleicht gegen die Zahl der
verschiedenen Zeugen des Manifests statt gegen die Zahl der Szenarien.

### 3.1 Abschnitt `bundle-activation` — vier Szenarien

| Szenario | Geklammerter dauerhafter Schritt | Zeuge |
|---|---|---|
| `unsigned-candidate` | eine Freigabe, die keine tragende Wurzelsignatur belegt — sei es, dass sie gar keine traegt, sei es ein gekipptes Byte in der rohen Signatur: `ReaderBundlePin::from_trust_objects` gibt fuer BEIDE Gestalten einen Fehler mit dem Code Unsigned zurueck und pinnt nichts. Mehr sagt dieser Zeuge nicht; dass an ihrer Stelle die zuletzt gueltige Fassung aktiv BLEIBT, misst der Nachbar `a_revocation_withdraws_its_release_and_the_last_valid_version_stays_active` in derselben Datei | `crates/ea-reader/tests/bundle_release_pinning.rs::an_unsigned_release_never_pins_anything` |
| `foreign-root-candidate` | eine fuer sich wohlgeformte Freigabe unter einer FREMDEN Wurzel: der Tausch, den ein kompromittierter Sync-Server versuchte. Sie faellt mit WrongRoot und ausdruecklich nicht als blosse Hashabweichung | `crates/ea-reader/tests/bundle_release_pinning.rs::a_release_under_a_foreign_root_never_pins_anything` |
| `revoked-release` | ein wirksamer Widerruf entzieht genau die Freigabe, deren Objekthash er nennt: die VORHERIGE Fassung bleibt aktiv, statt dass gar nichts aktiv bleibt, und vor seiner eigenen Registry-Version wirkt er nicht | `crates/ea-reader/tests/bundle_release_pinning.rs::a_revocation_withdraws_its_release_and_the_last_valid_version_stays_active` |
| `stale-trust-state` | der Fall, den das Alter des Trust-Bestandes sichtbar machen soll: ein dauerhaft im Datei-Modus betriebenes Geraet sieht einen Widerruf erst beim naechsten Bezug. Was der Zeuge davon WIRKLICH misst, ist die Rechnung und nur sie — `reader_trust_age_view` weist ueber einer um einen Tag und eine Millisekunde zurueckliegenden Bezugszeit `trust_age_ms` genau so aus und setzt `trust_refresh_overdue`. Ein Widerruf, der Datei-Modus und eine Sperre kommen darin NICHT vor; dass die Ueberschreitung eine Aufforderung und nie eine Sperre ist, folgt aus der Gestalt der Sicht, die kein Sperrfeld fuehrt, und ist keine Zusicherung dieses Zeugen | `crates/ea-reader/tests/trust_age.rs::an_exceeded_deadline_asks_for_a_refresh` |

### 3.2 Abschnitt `sync-cursor` — fuenfzehn Szenarien

| Szenario | Geklammerter dauerhafter Schritt | Zeuge |
|---|---|---|
| `before-batch-request` | vor dem Bilden und Signieren der Stapelanfrage: es entsteht kein Request, der Cursor steht | `crates/ea-reader/tests/sync_resume.rs::the_cursor_moves_only_after_every_object_is_durable_and_the_chain_verifies` |
| `after-batch-request` | nach dem Signieren und vor dem Absenden: der Request hat den Wirt nie verlassen, und der naechste Lauf bildet ihn neu | `crates/ea-reader/tests/sync_resume.rs::the_cursor_moves_only_after_every_object_is_durable_and_the_chain_verifies` |
| `before-start-head-check` | vor dem Vergleich des Startkopfs mit dem EIGENEN bestaetigten Cursor: kein Objektbyte hat den Speicher erreicht | `crates/ea-reader/tests/sync_resume.rs::the_cursor_moves_only_after_every_object_is_durable_and_the_chain_verifies` |
| `after-start-head-check` | nach dem Startkopfvergleich und vor dem ersten Schreibvorgang | `crates/ea-reader/tests/sync_resume.rs::the_cursor_moves_only_after_every_object_is_durable_and_the_chain_verifies` |
| `before-object-write` | vor dem ersten Objektbyte im verschluesselten Objektcache | `crates/ea-reader/tests/sync_resume.rs::the_cursor_moves_only_after_every_object_is_durable_and_the_chain_verifies` |
| `after-first-object-write` | nach dem ERSTEN und vor dem zweiten Objekt: der Batch liegt halb im Cache, der bestaetigte Cursor steht auch nach dem Wiederoeffnen des Speichers, und der Wiederholversuch landet auf demselben Kopf. Dass die Wiederholung dabei kein zweites Byte kostet, misst dieser Zeuge NICHT — das ist die Aussage des Nachbarn `a_repeated_batch_writes_no_second_byte_and_moves_nothing` in derselben Datei | `crates/ea-reader/tests/sync_resume.rs::the_cursor_moves_only_after_every_object_is_durable_and_the_chain_verifies` |
| `before-blob-store-flush` | vor der Rueckleseprobe, mit der die Dauerhaftigkeit GEMESSEN statt angeordnet wird — der Port kennt kein flush | `crates/ea-reader/tests/sync_resume.rs::the_cursor_moves_only_after_every_object_is_durable_and_the_chain_verifies` |
| `after-blob-store-flush` | jedes angekuendigte Objekt ist aus dem Speicher zurueckgekommen, die Kette ist noch ungeprueft: ein hier gesetzter Cursor traege eine nie verifizierte Kette | `crates/ea-reader/tests/sync_resume.rs::the_cursor_moves_only_after_every_object_is_durable_and_the_chain_verifies` |
| `before-chain-verification` | vor dem Verifikationslauf ueber den GESAMTEN lokalen Bestand gegen den Vault-gepinnten Anchor | `crates/ea-reader/tests/sync_resume.rs::the_cursor_moves_only_after_every_object_is_durable_and_the_chain_verifies` |
| `after-chain-verification` | der Bericht liegt vor, der Cursor steht noch: erst das Schreiben macht die Aussage dauerhaft | `crates/ea-reader/tests/sync_resume.rs::the_cursor_moves_only_after_every_object_is_durable_and_the_chain_verifies` |
| `before-cursor-persist` | vor dem Schreiben des naechsten Cursors — die letzte Stelle, an der ein Abbruch gar nichts kostet | `crates/ea-reader/tests/sync_resume.rs::the_cursor_moves_only_after_every_object_is_durable_and_the_chain_verifies` |
| `after-cursor-persist` | hinter der einzigen dauerhaften Wirkung von confirm: der Schreibvorgang wird ZURUECKGENOMMEN, damit auch dieser Punkt den Cursor stehen laesst | `crates/ea-reader/tests/sync_resume.rs::the_cursor_moves_only_after_every_object_is_durable_and_the_chain_verifies` |
| `tab-closed-mid-batch` | browser-eigen und auf dem Desktop unbekannt: ein Tab schliesst zwischen after-first-object-write und before-cursor-persist, der Dienst wird fallen gelassen und confirm laeuft nie — der Cursor steht, und der naechste Lauf holt den Batch erneut | `crates/ea-reader/tests/sync_resume.rs::a_tab_that_closes_mid_batch_leaves_the_cursor_where_it_was` |
| `opfs-write-aborted-by-storage-pressure` | browser-eigen und auf dem Desktop unbekannt: die Speicherbereinigung bricht einen OPFS-Schreibvorgang ab, der Speicher liefert ab dem n-ten Objekt QuotaExceeded — EA-READER-STORE, und der Cursor DIESES Speichers steht danach dort, wo er vorher stand | `crates/ea-reader/tests/sync_resume.rs::an_opfs_write_the_browser_aborts_leaves_the_cursor_where_it_was` |
| `refusal-leaves-the-cursor` | keiner der vier Abweisungsgruende — falscher Startkopf, fehlendes Objekt, Luecke, Fork — bewegt den CURSOR, und jeder traegt seinen EIGENEN Code statt eines Sammelcodes; der CACHE dagegen wird nicht geraeumt: accept_batch legt jedes hashkonsistente Objekt VOR classify ab und ReaderObjectCache kennt kein Entfernen, also bleibt nach dem abgewiesenen Fork der konkurrierende, gueltig signierte Eintrag liegen, und jeder ehrliche Wiederholversuch endet erneut in EA-READER-CHAIN-FORK, bis der Cache geraeumt ist (gemessen von tests/ea-system-tests/tests/e2e_reader_sync_interruptions.rs::every_retry_after_an_interruption_lands_idempotently_on_the_same_head) | `crates/ea-reader/tests/sync_attacks.rs::every_refusal_carries_its_own_code_and_leaves_the_cursor_where_it_was` |

### 3.3 Abschnitt `verification` — sechs Szenarien

| Szenario | Geklammerter dauerhafter Schritt | Zeuge |
|---|---|---|
| `substituted-archive-own-trust-chain` | ein untergeschobener, in sich VOLLSTAENDIGER Fremdbestand — eigener Root, eigene Registry, eigene Schreiberzertifikate, eigene Signaturen — gegen den Anker, den nur der Tresor liefert: NULL objectResults, keine einzige Zustandszeile und alle sechs Mangelfelder leer, statt still teilzuverifizieren; derselbe Bestand gegen den eigenen Anker ist vollstaendig verifiziert. Dass der Lauf dabei wirklich an Gate trust stehenbleibt, steht hier nur als Kommentar und wird beobachtend zugesichert vom Nachbarn `crates/ea-reader/tests/file_mode_anchor.rs::a_substituted_archive_says_nothing_about_any_entry_in_file_mode`, der das Protokoll gegen GATE_ORDER_V1[..2] haelt | `crates/ea-reader/tests/pinned_anchor.rs::a_substituted_archive_with_its_own_complete_trust_chain_fails_here` |
| `missing-own-grant` | ein gueltiger Eintrag, dessen einziger Grant einen fremden Empfaenger nennt: exakt fehlender Grant, Present, ohne Detailgrund, ohne decryptionErrors-Eintrag, ohne gaps-Zeile, is_fully_verified bleibt wahr — und ohne Zeugenpaar, sodass decrypt_verified gar nicht erst formulierbar ist | `crates/ea-reader/tests/missing_grant.rs::a_valid_entry_without_an_own_grant_is_exactly_missing_grant` |
| `own-thumbprint-wrong-material` | ein Grant auf den EIGENEN Abdruck, gekapselt auf fremdes Material: EA-VERIFY-DECRYPT-CEK-UNWRAP-FAILED unter dem Objekthash des GRANTS, und der Eintrag wird als unbekannter Schluessel gefuehrt — nie als fehlender Grant und nie als ungueltig, weil die Vorrangordnung nach Objektart trennt | `crates/ea-reader/tests/missing_grant.rs::missing_grant_gap_unknown_key_and_invalid_never_collapse` |
| `stub-without-authorization` | ein .eds-Stummel, dessen Pruefkette an EINEM Glied bricht — destructionId auf keine autorisierte Vernichtung des Bestands, destructionAuthorizationObjectHash ungleich dem von den Transitionen authentifizierten Hash, oder Autorisierung ohne den entryHash und die Sequenz des Stummels unter targets —: ungeklaerte Luecke in der Eintragsdimension, Gap in der Verifikationsdimension, kein objectResult, kein Grant nennt seinen entryHash, kein Zeugenpaar; dass der Bericht ueber keinen der drei Brueche einen ZUSAETZLICHEN Befund traegt, misst dieser Zeuge nicht, sondern der Nachbar `the_authorized_destruction_is_reached_only_through_the_full_chain`, der die Befundzahlen aller vier Bestaende gegeneinander stellt; nur der Zwilling mit geschlossener Kette ist autorisiert vernichtet bei sonst gleichem Ausgang; die Entkapselung, die der Bestand ueber seine anderen Eintraege erreicht, ist fuer den Stummel in keinem der beiden Ausgaenge formulierbar | `crates/ea-reader/tests/destroyed_stub.rs::a_stub_reaches_no_decapsulation_in_either_outcome` |
| `stale-witness` | ein Zeugenpaar aus einem FRUEHEREN classify-Lauf an decrypt_verified mit dem effectiveNow eines spaeteren: EA-READER-WITNESS-STALE vor jeder Entkapselung, weil Gate recipient-grant die Nutzungsfrist gegen genau den Wert des Laufs gemessen hat, in dem der Zeuge entstand — exakt und ohne Toleranz | `crates/ea-reader/tests/historical_expiry.rs::a_witness_from_an_earlier_run_is_refused` |
| `historical-grant-unresolvable` | ein gefaelschter historischer Grant neben dem initialen eigenen: er hinterlaesst NICHTS — keinen signatureErrors- und keinen decryptionErrors-Eintrag, keinen Detailgrund, ein wortgleiches Protokoll —, weil own_grant nur initiale Grants sieht und EA-VERIFY-GRANT-AUTHORIZATION-UNVERIFIABLE ueber die Pipeline unerreichbar ist; der Zeuge misst diese Abwesenheit und ist erst nachzuschaerfen, wenn Stufe 5 die grantAuthorization aufloest | `crates/ea-reader/tests/historical_expiry.rs::a_forged_historical_grant_leaves_no_trace_at_all` |

### 3.4 Abschnitt `file-mode` — drei Szenarien

| Szenario | Geklammerter dauerhafter Schritt | Zeuge |
|---|---|---|
| `bundle-truncated` | eine im Transport abgeschnittene oder umbenannte Containerdatei: EA-BUNDLE-MALFORMED, und es entsteht KEIN Teilbericht — die Endung ist ein HINWEIS, entschieden wird an BUNDLE_MAGIC_V1 | `crates/ea-reader/tests/file_mode.rs::a_truncated_or_wrongly_magicked_container_reports_the_bundle_code_and_no_report` |
| `directory-permission-revoked` | ein dauerhaft angebundener Ordner verliert zwischen zwei Oeffnungen seine Berechtigung: der Oeffnungsversuch bricht mit EA-ARCHIVE-UNAVAILABLE ab, es entsteht kein Teilbericht, und der universelle Weg ueber den gewoehnlichen Dateidialog bleibt angeboten — derselbe Bestand als EINE Datei oeffnet weiterhin vollstaendig | `crates/ea-reader/tests/file_mode.rs::a_directory_whose_permission_was_revoked_reports_the_archive_code_and_no_report` |
| `substituted-archive` | ein untergeschobenes Archiv mit vollstaendiger EIGENER Vertrauenskette, byteweise dasselbe Buendel: gegen den fremden Anker endet der Lauf fail-closed an Gate trust und sagt ueber keinen Eintrag etwas aus, gegen den eigenen gepinnten Anker traegt es vollstaendig — der Datei-Modus oeffnet keinen zweiten Weg zu einem Anker | `crates/ea-reader/tests/file_mode_anchor.rs::a_substituted_archive_says_nothing_about_any_entry_in_file_mode` |

### 3.5 Abschnitt `session-and-export` — vier Szenarien

| Szenario | Geklammerter dauerhafter Schritt | Zeuge |
|---|---|---|
| `lock-during-target-choice` | die Sitzung laeuft ab, waehrend der Dateidialog offen steht: der Export wird mit EA-READER-EXPORT-SESSION-LOCKED abgewiesen, es entsteht KEINE Auditzeile — es gibt keinen Tresor mehr, der sie signieren koennte —, das Ziel sieht kein Byte, und die offenen Datensaetze sind mit der Sperre gefallen | `crates/ea-reader/tests/export.rs::a_session_that_locked_while_the_target_was_being_chosen_refuses_without_an_audit_line` |
| `background-tab-before-write` | der Tab geht zwischen Bestaetigung und Schreiben in den Hintergrund und bleibt dort laenger als die verkuerzte Frist: die Bestaetigung ist noch frisch, die Sperre gewinnt trotzdem — ohne Timer, beim naechsten Zugriff —, kein Byte verlaesst den Speicher, keine Zeile entsteht; eine Millisekunde vor der Frist gelingt derselbe Export | `crates/ea-reader/tests/export.rs::a_tab_hidden_past_the_shortened_deadline_locks_before_the_bytes_leave` |
| `aborted-authenticator-confirmation` | ZWEI Faelle mit zwei VERSCHIEDENEN Mechanismen, und der Zeuge trennt sie statt sie zu einem Satz zu glaetten: eine fremde PRF-Ausgabe zu einer BEKANNTEN credentialId faellt an der AEAD-Umschliessung des Envelopes mit EA-CRYPTO-AEAD-OPEN; eine UNBEKANNTE credentialId mit einwandfreiem PRF-Geheimnis faellt schon DAVOR mit EA-READER-VAULT-NO-ENVELOPE, weil es zu ihr gar kein Envelope gibt, das sich umschliessen liesse — es wird also keine AEAD geoeffnet und keine verworfen. In beiden Faellen ENTSTEHT keine Bestaetigung, und ohne den per Wert genommenen Typ gibt es weder Sitzung noch Export | `crates/ea-reader/tests/session_lock.rs::a_confirmation_that_the_authenticator_did_not_prove_never_exists` |
| `audit-failure-after-bytes-left` | die Bytes sind draussen und die zweite Zeile laesst sich nicht schreiben: der Fehler MUSS entstehen und darf nicht verschluckt werden — EA-READER-EXPORT-AUDIT-AFTER-WRITE mit erreichbarem Auditbefund, plaintext_left() wahr, die Accepted-Zeile steht; weist die Senke schon die ERSTE Zeile ab, verlaesst kein Byte den Speicher | `crates/ea-reader/tests/export.rs::a_failing_completed_line_after_the_bytes_left_surfaces_instead_of_being_swallowed` |

Zum Abschnitt `sync-cursor` gehoert EINE benannte Ausnahme, die dieser Bericht
festhaelt statt sie zu glaetten: nach dem abgewiesenen Fork
(`refusal-leaves-the-cursor`, Rahmen `fork-at-the-head`) steht der Cursor, aber
der konkurrierende, gueltig signierte Genesis-Eintrag liegt bereits im
inhaltsadressierten Cache — `accept_batch` legt jedes hashkonsistente Objekt
VOR `classify` ab, und `ReaderObjectCache` kennt kein Entfernen —, und jeder
ehrliche Wiederholversuch endet erneut mit `EA-READER-CHAIN-FORK`; erst
Cacheverlust plus `rebuild_from_genesis` erreicht den Referenzkopf. Ob
`ea-reader` als `conflicting` quarantaenisierte Objekte kuenftig aus dem Cache
nimmt, ist eine Entscheidung ausserhalb dieser Stufe und steht unten in
`## Offen in spaeterer Stufe`.

## 4. Entscheidungen dieser Stufe

Die Entscheidungen, an denen der Plan und der Arbeitsbaum auseinandergingen
oder an denen die Stufe eine Wahl getroffen hat. Jede steht mit ihrer Quelle,
damit eine spaetere Stufe sie wiederfindet statt sie neu zu treffen.

- **Stufe 4 friert KEINE Vektorfamilie ein.** `STAGE_FOUR_VECTOR_FAMILIES` ist
  leer, und das ist die Aussage: `vectors/crypto/suite-1/`,
  `vectors/trust/v1/` und `vectors/web-bundle/v1/` werden ausschliesslich
  GELESEN. Der Bericht weist `vector_families` trotzdem aus, als leeres Array —
  ein weggelassener Schluessel waere von einem Bericht ohne Vektorabschnitt
  nicht zu unterscheiden.
- **Der entzogene Grant ist ein zweiter BAU und kein geloeschtes `.eag`.**
  Gemessen: der Hash des initialen Grantplans ist in das signierte Manifest
  gebunden, Gate `grant-plan` rekonstruiert den Plan aus den vorhandenen
  Grantobjekten und haelt ihn dagegen. Wird ein `.eag` physisch entfernt, endet
  der Eintrag fuer BEIDE Reader als ungueltig mit
  `EA-VERIFY-GRANT-PLAN-MISMATCH` — auch fuer den, dessen Grant noch da ist.
  `fehlender Grant` entsteht nur aus einem Bestand, dessen Plan den Empfaenger
  nie genannt hat.
- **Die Browsermatrix laeuft NICHT durch die Oberflaeche.** Gemessen: der
  Oeffnungsweg der Flaeche laeuft ueber `readerSession()` in
  `apps/web/src/features/file-mode/DirectoryHandle.ts`, also ueber eine
  WebAuthn-PRF-Zeremonie, und `WebAuthn.addVirtualAuthenticator` ist eine
  CDP-Methode — auf `firefox` und `webkit` gibt es damit KEINEN
  Oberflaechenweg zu einem Bericht. `apps/web/tests/e2e/browser-matrix.spec.ts`
  spricht deshalb den GEBAUTEN Modul-Worker der Anwendung direkt an. Die
  Testkennungen `report-hash` und `verification-status` aus der Planskizze gibt
  es im Baum nicht, und kein DTO fuehrt ein Feld `reportHash`.
- **Der „reportHash" ist der SHA-256 ueber das `ReaderStandView`-JSON**, weil
  der Kern keinen anderen ausgibt (Abschnitt `## Browsermatrix und
  Datei-Modus`).
- **Im Datei-Modus ist `notServerConfirmed` der REGELFALL, aber keine
  Invariante.** Gemessen an `write_archive_bundle` in
  `crates/ea-archive-fs/src/bundle.rs`: ein Buendel packt JEDEN relativen Pfad
  des Bestands ein, Quittungen eingeschlossen, und `web-reader-design.md` §5.4
  sagt woertlich, im Datei-Modus wuerden „nur die im Buendel enthaltenen
  Receipts und Checkpoints geprueft" — enthaltene Quittungen werden also
  AUSGEWERTET.
- **Das Fixture-Buendel kommt aus dem Containerkodierer und nicht aus dem
  Exporteur.** `write_archive_bundle` weist jeden Bestand ab, der nicht
  `is_fully_verified()` ist, und JEDER quittungstragende Fixture-Bestand traegt
  absichtlich die Vorlauf-Luecke `0..=1`. Die Weigerung ist als eigener Zeuge
  gepinnt, damit ein spaeterer lueckenfreier Quittungsbestand den Lauf auf den
  echten Exporteur zurueckhaengt.
- **Der Fingerprint-Vergleich ist nicht ueberspringbar.** Ein Abweichen endet
  mit `EA-READER-ENROLLMENT-FINGERPRINT-MISMATCH`, und das Enrollment wird
  nicht abgeschlossen. Der Browserbeleg laeuft nur im Projekt `chromium`; die
  Rust-Zeugen `crates/ea-reader/tests/fingerprint_gate.rs` und
  `crates/ea-reader/tests/enrollment_two_authenticators.rs` laufen
  plattformunabhaengig und tragen die normative Aussage.
- **Browser-Mindestversionen je Plattform werden HIER ausdruecklich NICHT
  gepinnt.** `web-reader-design.md` §14, offener Punkt 3, fuehrt sie als
  offenen Punkt und weist sie der Stufe-7-Ueberarbeitung zu. Gemessen: einen
  Abschnitt „§14.3" gibt es in der Spec nicht — §14 ist eine nummerierte Liste
  ohne Unterabschnitte.
- **Der Stufenschalter brauchte eine Testreparatur, und der Plan sagte es
  richtig.** `tools/xtask/tests/stage_gate.rs::the_stage_switch_still_refuses_an_undefined_stage`
  trieb Stufe `"4"` und hielt den Teilstring `"stages 1, 2 and 3"`. Er treibt
  jetzt Stufe `"5"` und erwartet `"stages 1, 2, 3 and 4"` — dieselbe
  Zusicherung, eine Stufe weiter. Der Grund, aus dem der Pin uebersehen werden
  KANN, steht in seinem eigenen Kommentar: `grep -rn "only defined for stages"`
  trifft ihn nicht, weil er den kuerzeren Teilstring haelt.
- **Die LIVE-Zaehler kehren HIER zurueck.** Die wasm32-Aufgabe hatte
  `verify_quick_subcommand_count()`, `wasm32_positive_list_count()` und
  `GERMAN_COUNT_WORDS` entfernt, weil ihre einzigen Aufrufstellen — die
  ABGESCHLOSSENEN Berichte der Stufen 2 und 3 — auf historische Literale
  umgestellt wurden und ein ungenutzter Helfer `dead_code` erzeugt.
  `stage_four_gate_report_records_the_measured_full_gate_run` legt beide
  Zaehler unveraendert wieder an und stellt sie gegen die
  `pnpm verify:quick`-Belegzeile DIESES Berichts. Die Zahlwortliste waechst
  dabei auf `[&str; 15]` von `"NULL"` bis `"VIERZEHN"`: gemessen faehrt die
  Stufe ZWOELF Teilkommandos und VIERZEHN wasm32-Pakete, der hoechste
  gebrauchte Index ist also 14, und die alte `[&str; 13]` haette an `get(14)`
  mit `None` PANIKT statt zu urteilen.
- **Der wasm32-Zaehler bekam einen Schnitt, und das ist eine Korrektur.** Die
  bis Stufe 3 gefahrene Fassung zaehlte `"-p"` ueber den GANZEN Pin von
  `verify_quick_commands()` und begruendete das damit, die Positivliste sei
  „die einzige Stelle der Liste, die `-p` fuehrt". Gemessen am 2026-09-05 ist
  das nicht mehr wahr: das Teilkommando
  `cargo run --locked -p xtask -- build-wasm` steht seit der wasm-Aufgabe in
  derselben Liste und traegt sein eigenes `-p`. Die alte Zaehlung ergaebe heute
  15 statt 14 und wiese ein VIERZEHN ab, das richtig ist.
  `wasm32_positive_list_count()` schneidet deshalb am Zielliteral
  `wasm32-unknown-unknown`.
- **Die Sitzungssperre gewinnt gegen eine noch frische Bestaetigung.** Eine
  Bestaetigung aus einem frueheren Sitzungslauf wird an
  `EA-READER-SESSION-CONFIRMATION-STALE` abgewiesen, und der Export einer
  waehrend der Zielwahl gesperrten Sitzung an
  `EA-READER-EXPORT-SESSION-LOCKED` — ohne Auditzeile, weil es keinen Tresor
  mehr gibt, der sie signieren koennte.
- **Der Stufe-4-Gate-Bericht ist umlautfrei**, aus dem Grund, den der
  Stufe-3-Bericht ausschreibt: der Gate vergleicht Literale.

## 5. Gemessene Indexschwelle

`design.md` fordert in NFR-PERF-003 und Abnahmekriterium 31 „Ein Reader
verifiziert und indiziert mindestens 50.000 Pakete". Die Aufgabe, die den
verschluesselten invertierten Index gebaut hat, hat das MESSWERKZEUG
ausgeliefert (`crates/ea-index/tests/scale_50000.rs`, `#[ignore]`, gefahren
ueber `xtask index-scale 50000`), aber KEINE Messung in den
Traceability-Bestand persistiert — gemessen am 2026-09-05 nannte ausser diesem
Bericht kein Dokument unter `docs/traceability/` einen Wert fuer `blob_bytes`, `unlock_ms` oder
`peak_rss_kib`. AUSSERHALB der Traceability tut es eines, und das gehoert
hierher statt in eine Fussnote: `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-4-reader.md`
nennt in seinem Task-10-Abschnitt alle drei Werte, und zwar fuer BEIDE Profile.
Dieser Abschnitt schliesst die Luecke im Traceability-Bestand.

Gemessen am 2026-09-05 auf diesem Wirt ueber `pnpm index:scale`:

| Groesse | Wert |
|---|---|
| Pakete | 50000 |
| `blob_bytes` | 7566455 |
| `seal_ms` | 4419 |
| `unlock_ms` | 6114 |
| `search_us` | 48 |
| `broad_search_us` | 84667 |
| `peak_rss_kib` | 357484 |

**Profil und Zustand, ausdruecklich:** das Messwerkzeug lief im
DEBUG-Profil — nicht `--release` — und auf WARMEM `target/`. Ein
`--release`-Bau liegt deutlich darunter und ist in DIESEM Lauf nicht gemessen
— der Plan dagegen hat ihn gemessen und schreibt ihn aus
(`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-4-reader.md`,
Task-10-Abschnitt, Stand `10f561b`): bei denselben 50 000 Paketen und demselben
`blob_bytes=7566455` ergab `--release` `seal_ms=230 unlock_ms=574 search_us=13
broad_search_us=17007 peak_rss_kib=356592`. Ein kalter `target/` aendert nur die
Bauzeit und keine der Zahlen oben.

Der Bericht MISST und beansprucht nicht. Die Ledgerzeile `AK-31` behaelt
ausdruecklich `stage=7` und `status=planned`: die ABNAHME dieser Schwelle
verlangt Stufe 7 und misst sie in
`tests/ea-system-tests/tests/performance_reader_50000.rs`. `NFR-PERF-003` hat
in `docs/traceability/v0.1-requirements.csv` UEBERHAUPT KEINE Zeile — der
Bezeichner steht allein in der Anforderungstabelle von
`docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md`; wer ihn im
Ledger zu drehen versucht, dreht nichts.

„Einsatz" und „Paket" sind dabei NICHT dieselbe Einheit — ein Einsatz traegt
ein Original plus Nachtraege —, deshalb steht die Schwelle in Paketen, in
derselben Einheit, die das Stufe-7-Gate misst. Ein monolithischer Einzelblob
unterhalb dieser Schwelle waere eine Stufe-4-Architektur, die ihr eigenes
Stufe-7-Gate nicht bestehen kann; die Zahlen oben zeigen, dass sie es nicht
ist.

## Browsermatrix und Datei-Modus

Ein GEPRUEFTES Negativ und eine gemessene Gleichheit. Sie stehen als eigener
Abschnitt, damit ihr Schweigen nicht als „nicht geprueft" gelesen wird.

**Die drei Engine-Baus.** `apps/web/playwright.config.ts` fuehrt drei
`projects` — `chromium`, `firefox`, `webkit` —, und
`apps/web/tests/e2e/browser-matrix.spec.ts` faehrt in jedem denselben
eingefrorenen Bestand. Die Baus kommen aus dem gepinnten Abbild
`mcr.microsoft.com/playwright:v1.62.1-noble@sha256:dcc5531e97840b9b5e794f2814476b21571c5124a3fca2267d73041f56e7580e`
und nicht aus einem `playwright install` auf dem Wirt: der Bericht kann seine
drei Engine-Revisionen nur dann als gemessen ausweisen, wenn ihre Herkunft
selbst gepinnt ist.

**Wie die drei Revisionen gemessen wurden, und was von ihnen wirklich gepinnt
ist.** Sie sind nicht abgeschrieben: `pnpm --dir apps/web exec playwright
--version` druckt auf diesem Wirt am 2026-09-05 `Version 1.62.1`, und
`pnpm --dir apps/web exec playwright install --dry-run` druckt ebendort
`Chrome for Testing 151.0.7922.34 (playwright chromium v1234)`,
`Firefox 153.0 (playwright firefox v1538)` und
`WebKit 26.5 (playwright webkit v2336)`. GEPINNT ist davon allerdings nur
EINE: `chromium-1234` steht zusaetzlich in `ops/compose/browsers.yaml`
(Symlink auf `/ms-playwright/chromium-1234/chrome-linux64/chrome`, und die
Treiberfassung 151.0.7922.34 haengt zeichengleich daran). Fuer `firefox-1538`
und `webkit-2336` gibt es im ganzen Baum KEINE Betriebs- oder
Werkzeugdatei, die die Revision festhaelt — sie stehen ausserhalb dieses
Berichts allein in der Reichweitenklausel, die der Gate von ihm verlangt, und
in der Planaufgabe. Ihre Bindung ist also die Abbildfassung `v1.62.1-noble`
und ihr Digest, nicht die Revisionsnummer selbst.

**`webkit` ist NICHT Safari.** Es ist Playwrights WebKit-Bau. Die
Unterscheidung steht hier, weil sie sonst als Safari-Nachweis gelesen wuerde.
Ein Safari-Nachweis ist in dieser Stufe weder gebaut noch behauptet.

**Die Matrix deckt AUSDRUECKLICH NICHT alle E2E-Laeufe dieser Stufe ab.**
DREI Specs tragen dasselbe dateiweite
`test.skip(({ browserName }) => browserName !== 'chromium')`, und die Gruende
sind GEMESSEN nicht dieselben — jeder steht im Kopf seiner eigenen Datei:

- `apps/web/tests/e2e/enrollment.spec.ts` (Zeile 47), weil
  `WebAuthn.addVirtualAuthenticator` eine CDP-Methode ist und Firefox und
  WebKit kein Gegenstueck anbieten.
- `apps/web/tests/e2e/lock-and-export.spec.ts` (Zeile 79), weil der Lauf ein
  Enrollment DIESES Seitenlaufs voraussetzt und dafuer ueber
  `apps/web/tests/e2e/support/enrollment.ts` denselben virtuellen
  CTAP2-Authenticator aufsetzt. Die CDP-Abhaengigkeit gilt hier also MITTELBAR
  und nicht, weil die Sitzungssperre selbst CDP braeuchte.
- `apps/web/tests/e2e/file-mode.spec.ts` (Zeile 32) aus einem GANZ ANDEREN
  Grund, und deshalb traegt die CDP-Begruendung ihn nicht: seine
  Anti-Leerlauf-Zeile misst die ANWESENHEIT von `showDirectoryPicker`, die es
  nur in Chromium gibt — auf `firefox` und `webkit` fiele der Lauf an genau
  dieser Zeile. Die ABWESENHEIT der Faehigkeit bezeugen stattdessen
  `apps/web/src/features/file-mode/OpenArchivePanel.test.tsx` und
  `apps/web/tests/e2e/browser-matrix.spec.ts`.

Gemessen im Lauf unten: 36 Tests, 27 bestanden, 9 uebersprungen — viermal
`enrollment.spec.ts` (je zwei auf `firefox` und `webkit`), zweimal
`lock-and-export.spec.ts`, zweimal `file-mode.spec.ts` und einmal der
Tastaturlauf aus `reader.spec.ts` auf `firefox`.

**Die Folge, ausgeschrieben statt verschwiegen:** die BROWSERHAELFTE der
Sitzungssperre und des authenticator-bestaetigten Einzelexports (`FR-104` und
`FR-105`, beide jetzt `implemented`) und die BROWSERHAELFTE des Datei-Modus
(`WR-053` und `WR-054`, beide jetzt `integrated`) ruht damit allein auf
`chromium`. Die normative Aussage tragen in allen vier Faellen die
plattformunabhaengigen Rust-Zeugen — `crates/ea-reader/tests/session_lock.rs`,
`crates/ea-reader/tests/export.rs`, `crates/ea-reader/tests/file_mode.rs` und
`crates/ea-reader/tests/file_mode_anchor.rs` —, was fehlt, ist der
Browserbeleg auf zwei weiteren Engines. Der Enrollment- und der
Fingerprintnachweis auf `firefox` und `webkit` und die drei chromium-only
gefahrenen Specs stehen deshalb unten in `## Offen in spaeterer Stufe`.

**Die Gleichheit ist die Aussage.** Der Verifikationskern ist geteilter
Rust-Code, uebersetzt nach `wasm32-unknown-unknown`; sein Bericht DARF sich
zwischen den Engines nicht unterscheiden. Der Zeuge instanziiert auf `/datei`
im GEBAUTEN Buendel unter der CSP den eigenen Modul-Worker der Anwendung,
sendet `vault-unlock` (reines Rust, ohne WebAuthn) ueber eine eingefrorene
versiegelte Tresordatei, dann `file-mode-open-bundle` ueber ein eingefrorenes
Archivbuendel und `reader-stand-view`, und vergleicht die `ReaderStandView`
BYTEGLEICH mit der eingefrorenen Datei UND ihren SHA-256 mit EINEM Literal.
Anti-Leerlauf: ein gekipptes Byte in der Mitte von
`entries/000000000000_entry.eip` — der Offset kommt aus dem Containerindex und
ist nicht fest verdrahtet — ergibt einen ANDEREN Bericht, der selbst als
Literal gepinnt ist (`EA-FORMAT-SHAPE` an Gate `format`); der Kern liest die
Bytes also nachweislich und faellt auf jeder Engine gleich.

**Der Datei-Modus, dreimal derselbe Bestand.** Lauf (a) faehrt den
quittungstragenden Bestand im Server-Modus. Lauf (b) faehrt dasselbe
Ein-Datei-Buendel dieses Bestands; verglichen werden `archiveObjectCount`,
`chainHead`, die Menge der `objectResults` UND die Spalte
`serverConfirmation` — sie ist in (b) IDENTISCH zu (a), und genau das belegt,
dass Gate-Schritt 7 die mitgereisten Quittungen wirklich auswertet statt sie zu
ignorieren. Lauf (c) zerfaellt in zwei Zeugen: ueber DEMSELBEN Bestand mit
vorenthaltenen `.esr` kippt allein die Spalte `serverConfirmation`, `gaps()`
und `is_fully_verified()` bleiben mit (a) identisch; und ueber dem
lueckenfreien Bestand durch den ECHTEN Exporteur auf einem echten
`LocalPathBackend` steht jedes Objekt auf `notServerConfirmed` UND
`ObjectResultKindV1::Valid`, `gaps()` ist leer und `is_fully_verified()` bleibt
wahr — die orthogonale Dimension senkt nichts. NUR Lauf (c) traegt die
Ledgerzeile des Datei-Modus; (a) und (b) belegen die Interoperabilitaet, nicht
die Ausweisung.

**Der Negativfall daneben** ist das untergeschobene Archiv mit vollstaendiger
eigener Vertrauenskette: gegen den gepinnten Anker endet der Lauf fail-closed
an Gate `trust`, `objectResults` bleibt leer und `publicKeyThumbprints` bleibt
leer. Beide Zeugen sind hier die SYSTEMweite Wiederholung; ihr primaerer Beleg
liegt in den Reader-Aufgaben dieser Stufe.

## Rollengrenze

Ein GEMESSENES Negativ, und es steht getrennt, weil es die zweite Haelfte von
FR-100 ist.

`apps/web` traegt KEINE Writer-, Administrations-, Root-Zeremonie-,
Provisionierungs-, Re-Grant- und keine Vernichtungsflaeche. Die
rollengeschaltete Huelle von `apps/desktop` gibt umgekehrt KEINE Reader-Route
frei. Bezeugt ist beides von `apps/desktop/src/app/RoleGate.test.tsx`, und
zwar von ihm ALLEIN: GEMESSEN am 2026-09-05 fuehrt diese Datei GENAU DREI
Zeugen, und alle drei messen die Grenze, waehrend
`apps/web/src/features/reader/ReaderPage.test.tsx` VIERZEHN Zeugen fuehrt, von
denen KEINER sie beruehrt. Eine fruehere Fassung dieses Abschnitts nannte
beide; die zweite Nennung war falsch. Die Ledgerzeile FR-100 steht auf
`implemented`.

Was der Zeuge WIRKLICH misst, Haelfte fuer Haelfte. Die Desktophaelfte laeuft
ueber `routeTable()` — genau `/` und `/einsatz`, und kein Label, auf das
`reader` oder `lese` passt — und ueber die Dateiliste von
`apps/desktop/src-tauri/src/commands`, die genau `master_data.rs`, `mod.rs`,
`session.rs`, `sync.rs` und `writer.rs` fuehrt. Die Webhaelfte ist ein
QUELLENSCAN und keine Laufzeitmessung: sie liest jede HANDGESCHRIEBENE
`.ts`/`.tsx`-Datei unter `apps/web/src` — ohne die zwei Generatorausgaenge und
ohne die Testdateien — und weist jede ab, auf die das Muster
`/finaliz|Root-Zeremonie|rootCeremony|provision|historicalRegrant|destruction|Entwurf verwerfen/i`
passt. Was dieses Muster nicht traegt, steht damit auch nicht unter
Zusicherung, und das ist hier ausgeschrieben statt weggelassen: es gibt KEINE
Nadel fuer eine allgemeine Schreiber- oder Administrationsflaeche, und
„Re-Grant" ist ausschliesslich als camelCase-Bezeichner `historicalRegrant`
abgedeckt.

Eine Klausel gehoert daneben, weil sie sonst wie ein Widerspruch aussaehe:
`apps/web` fuehrt GENAU EINE bewusste Datenausgangsroute, `/export`
(`apps/web/src/main.tsx`, neben `/`, `/enrollment` und `/datei`). Sie ist die
FR-105-Faehigkeit des Readers selbst — der Einzelexport hinter einer frischen
Authenticator-Bestaetigung — und keine der sechs abgewiesenen Flaechen.

Was die Rollengrenze NICHT belegt: die Administrationshaelfte des Enrollments —
Anzeige des erwarteten Fingerprints und Root-Signatur des Reader-Zertifikats,
`web-reader-design.md` §6.6 Schritt 4 — entsteht mit der
Desktop-Administration in Stufe 5 und steht unten.

## Nicht beruehrte Nachbarzeilen

Drei Ledgerzeilen tragen `stage=4` oder grenzen unmittelbar an diese Stufe und
werden von ihr ausdruecklich NICHT bewegt:

| Ledgerzeile | Warum nicht hier | Stufenspalte |
|---|---|---|
| `AK-23` | Der Plattform-Key-Provider ist WRITER-Flaeche, und `web-reader-design.md` §11.4 nimmt die Achse Key-Provider fuer den Reader HERAUS, statt sie zu erfuellen. Diese Stufe erfuellt sie also nicht und behauptet es nicht | UNVERAENDERT |
| `AK-31` | Hier GEMESSEN (Abschnitt 5) und dort verlangt. Die Messung ist keine Abnahme | `stage=7`, `planned`, UNVERAENDERT |
| `WR-075` | `readerKeyEscrow` und die Zwei-Approver-Oeffnungszeremonie: `web-reader-design.md` §7.3 nennt Stufe 5 als Entstehungsstufe der Objektart | `stage=5`, `planned`, UNVERAENDERT |

`NFR-PERF-003` steht hier ausdruecklich NICHT, weil es im Ledger gar keine
Zeile hat (Abschnitt 5).

Die drei Stufe-1-bis-3-Zeilen `WR-042D` (Stufe 3, `implemented`), `WR-052`
(Stufe 2, `integrated`) und `WR-064` (Stufe 3, `implemented`) bleiben
ebenfalls unangetastet; die geschlossenen Gate-Berichte der Stufen 1 bis 3
werden nicht angefasst.

## Ledgerpflege

Siebzehn Zeilen werden bewegt, jede gegen eine benannte Aufgabe und einen
benannten Testpfad. Die Spalte `Neuer Status` traegt AUSSCHLIESSLICH ein
Literal aus `LEDGER_STATUSES` — `implemented`, `integrated` oder `planned` —
und keinen Zusatz in Klammern: der Gate liest die neunte Spalte woertlich und
weist jeden anderen Wert mit `status … is outside the vocabulary` ab. Ein
Vorbehalt gehoert in die Belegspalte oder in `## Offen in spaeterer Stufe`, nie
in die Statusspalte.

| Ledgerzeile | Neuer Status | Beweisende Aufgabe | Beweisender Testpfad |
|---|---|---|---|
| `AK-10` | integrated | Diese Aufgabe | `tests/ea-system-tests/tests/cross_platform_two_readers.rs::one_ciphertext_opens_under_two_distinct_reader_kem_keys_through_separate_grants` |
| `AK-42` | integrated | Verifikation vor Entschluesselung, fehlender Grant, Modusparameter und der Anchor | `crates/ea-reader/tests/missing_grant.rs`; `tests/ea-system-tests/tests/cross_platform_two_readers.rs` |
| `AK-43` | integrated | Inkrementeller Reader-Sync und verifizierter Cursor-Fortschritt in OPFS | `crates/ea-reader/tests/sync_resume.rs`; `tests/ea-system-tests/tests/e2e_reader_sync_interruptions.rs` |
| `FR-085` | implemented | Inkrementeller Reader-Sync und verifizierter Cursor-Fortschritt in OPFS | `crates/ea-reader/tests/sync_attacks.rs` |
| `FR-100` | implemented | Integritaetszentrierte Reader-Oberflaeche in `apps/web` und die Rollengrenze zum Desktop | `apps/desktop/src/app/RoleGate.test.tsx`; `apps/web/src/features/reader/ReaderPage.test.tsx` |
| `FR-103` | implemented | Verschluesselter invertierter Index in OPFS, Suche, Schemakompatibilitaet und die gemessene 50.000-Paket-Schwelle | `crates/ea-index/tests/search.rs`; `crates/ea-index/tests/reindex.rs`; `crates/ea-reader/tests/cache_canaries.rs` |
| `FR-104` | implemented | Sitzungssperre, Zeroize, authenticator-bestaetigter Einzelexport und signiertes lokales Audit | `crates/ea-reader/tests/session_lock.rs` |
| `FR-105` | implemented | Sitzungssperre, Zeroize, authenticator-bestaetigter Einzelexport und signiertes lokales Audit | `crates/ea-reader/tests/export.rs` |
| `FR-106` | implemented | Sitzungssperre, Zeroize, authenticator-bestaetigter Einzelexport und signiertes lokales Audit | `crates/ea-reader/tests/audit_redaction.rs` |
| `FR-122` | implemented | Nachtragsreferenzen und Original/Nachtrag-Projektion | `crates/ea-reader/tests/amendments.rs` |
| `WR-041` | implemented | Web-Bundle: getrennter Origin, Service Worker, gepinnte `webBundleRelease` und das Alter des Trust-Standes | CODE-Seite; die betriebliche Haelfte steht in `## Offen in spaeterer Stufe`. `apps/web/src/sw/service-worker.test.ts` > „builds a bundle that addresses nothing absolutely and names no bundle origin"; ebenda > „pins the vite configuration that makes the separation possible" — VITEST-Titel mit Leerzeichen, keine Rust-Pfade |
| `WR-042` | implemented | Web-Bundle: getrennter Origin, Service Worker, gepinnte `webBundleRelease` und das Alter des Trust-Standes | `crates/ea-reader/tests/bundle_release_pinning.rs`; `apps/web/tests/e2e/bundle-activation.spec.ts` |
| `WR-043` | integrated | Browser-Enrollment: zwei Pflicht-Authenticators und das nicht ueberspringbare Fingerprint-Gate | `crates/ea-reader/tests/fingerprint_gate.rs`; `apps/web/tests/e2e/enrollment.spec.ts` |
| `WR-053` | integrated | Datei-Modus: Einzeldatei-Buendel, Verzeichnis-Handle, kein Cursor, `notServerConfirmed` | `crates/ea-reader/tests/file_mode_anchor.rs::a_substituted_archive_says_nothing_about_any_entry_in_file_mode`; `tests/ea-system-tests/tests/reader_file_mode_interop.rs` |
| `WR-054` | integrated | Datei-Modus: Einzeldatei-Buendel, Verzeichnis-Handle, kein Cursor, `notServerConfirmed` | `crates/ea-reader/tests/file_mode.rs::every_object_without_a_receipt_is_not_server_confirmed_and_never_a_gap`; `tests/ea-system-tests/tests/reader_file_mode_interop.rs` |
| `WR-063` | implemented | Browser-Enrollment: zwei Pflicht-Authenticators und das nicht ueberspringbare Fingerprint-Gate | `crates/ea-reader/tests/enrollment_two_authenticators.rs` |
| `WR-082` | integrated | Sitzungssperre, Zeroize, authenticator-bestaetigter Einzelexport und signiertes lokales Audit + diese Aufgabe | `tests/ea-system-tests/tests/privacy_canaries_reader.rs` |

Dazu ZWEI neue Teilbelegzeilen, jede `v1.1`, `stage=4`, `status=implemented`:
`AK-19` „Keine Klartextlogs - Stufe-4-Teilbeleg (Reader)" und `AK-17` „Schema
und Suite v1/v2 - Stufe-4-Teilbeleg (Reader-Altansicht)". Beide VOLLEN Zeilen
behalten ihre bisherige Stufe.

`WEB_READER_MUST_ROWS` in `tools/xtask/tests/stage_gate.rs` folgt in DEMSELBEN
Commit: die Stelligkeit bleibt ELF, sieben Tupel wechseln ihre Statusspalte,
und die Verschiebung ist im Dokumentkommentar der Konstante ausgeschrieben.

## Offen in spaeterer Stufe

Jeder nicht erbrachte Nachweis samt besitzender Stufe. Keiner davon wird hier
behauptet.

| Offen | Warum nicht hier | Stufe |
|---|---|---|
| Gepinnte Browser-Mindestversionen je Plattform | `web-reader-design.md` §14, offener Punkt 3, fuehrt sie als offenen Punkt und weist sie ausdruecklich der Stufe-7-Ueberarbeitung zu | 7 |
| Enrollment- und Fingerprint-E2E auf `firefox` und `webkit` | `WebAuthn.addVirtualAuthenticator` ist eine CDP-Methode; Firefox und WebKit bieten kein Gegenstueck, `apps/web/tests/e2e/enrollment.spec.ts` laeuft deshalb nur im Projekt `chromium`. Die Rust-Zeugen `enrollment_two_authenticators.rs` und `fingerprint_gate.rs` laufen plattformunabhaengig und tragen die normative Aussage; was fehlt, ist der Browserbeleg auf zwei Engines | 7 |
| Betriebliche Haelfte der Origin-Trennung (`WR-041`): getrennter Host, Auslieferung, DNS und Zertifikate | Diese Stufe belegt die CODE-Seite — relative Beiwerkspfade, `base: './'`, `connect-src` ohne Bundle-Origin, ungehashter Service-Worker-Einstieg. Die Aufgabe „Web-Bundle: getrennter Origin, Service Worker, gepinnte `webBundleRelease` und das Alter des Trust-Standes" waehlt und betreibt den Host ausdruecklich NICHT; `web-reader-design.md` §14 offener Punkt 4 erklaert ihn fuer offen | offen, betrieblich |
| `--release`-Bau mit `wasm-opt` | Der Laufzeitnachweis und `build-wasm` fahren das Debug-Profil; ein optimierter Bau ist ein Releasenachweis | 7 |
| PWA-Installation und Service-Worker-Aktualisierung unter Pinning | `web-reader-design.md` §12 weist beides der Stufe 7 zu | 7 |
| Gate, das die Ablehnung eines nicht Root-signierten Bundles nachweist | Ebenda, Stufe 7; diese Stufe baut die Aktivierungspruefung, nicht ihr Releasegate | 7 |
| 50.000-Paket-Zielwerte als ABNAHME (AK 31, NFR-PERF-003) | Hier gemessen, dort verlangt | 7 |
| Administrationshaelfte des Enrollments (Anzeige des erwarteten Fingerprints, Root-Signatur des Reader-Zertifikats) | `web-reader-design.md` §6.6 Schritt 4; die Desktop-Administration entsteht in Stufe 5 | 5 |
| `readerKeyEscrow` und die Zwei-Approver-Oeffnungszeremonie | `web-reader-design.md` §7.3 nennt Stufe 5 als Entstehungsstufe der Objektart; `WR-075` bleibt dort | 5 |
| Zielorigin und Betriebsverantwortung des getrennten Bundle-Hosts | `web-reader-design.md` §14 offener Punkt 4; die konfigurierbare Origin-Positivliste der Stufe 3 ist die technische Antwort, der Betrieb bleibt eine Entscheidung | offen, betrieblich |
| Referenzquelle und Verteilweg der Fingerprint-Bekanntgabe | `web-reader-design.md` §14 offener Punkt 5 | offen, betrieblich |
| Raeumung `conflicting` quarantaenisierter Objekte aus dem `ReaderObjectCache` | Nach dem abgewiesenen Fork bleibt der konkurrierende Eintrag im inhaltsadressierten Cache liegen (Abschnitt 3.2); ob `ea-reader` ihn kuenftig entfernt, ist eine Entscheidung ausserhalb dieser Aufgabe | offen |
| `browsers up` startet den WebKit-`run-server` und druckt `EA_WEBKIT_WS_ENDPOINT` | Heute exportiert `browsers up` allein `CHROMEDRIVER_REMOTE` (Abschnitt 2.1); der WebKit-Dienst wird von Hand gestartet | offen |
| Safari als Engine | `webkit-2336` ist Playwrights WebKit-Bau und NICHT Safari — die Stufe faehrt keinen Safari, und der Abschnitt `## Browsermatrix und Datei-Modus` sagt das ausdruecklich. Der sechzehnte gepinnte Pflichtsatz dieses Berichts nennt Safari als eines der vier Dinge, die ein gruener Stufe-4-Gate nicht belegt, und verweist fuer alle vier auf diese Tabelle; ohne diese Zeile zeigte der Verweis ins Leere | 7 |
| Browserbeleg fuer Sitzungssperre, Einzelexport und Datei-Modus auf `firefox` und `webkit` | `apps/web/tests/e2e/lock-and-export.spec.ts` (Zeile 79) und `apps/web/tests/e2e/file-mode.spec.ts` (Zeile 32) tragen dasselbe dateiweite `test.skip` wie `enrollment.spec.ts` und laufen deshalb nur im Projekt `chromium` — der erste MITTELBAR ueber die CDP-Zeremonie des Enrollments, der zweite aus einem ganz anderen Grund: seine Anti-Leerlauf-Zeile setzt `showDirectoryPicker` voraus. Die BROWSERHAELFTE von `FR-104`, `FR-105`, `WR-053` und `WR-054` ruht damit auf EINER Engine; die normative Aussage tragen die plattformunabhaengigen Rust-Zeugen (Abschnitt `## Browsermatrix und Datei-Modus`) | 7 |
| Laufzeitzeuge fuer den Service-Worker-Cache in `apps/web` | Die Laufzeithaelfte des Stroms „Service-Worker-Cache" ist unbezeugt: `apps/web/src/sw/service-worker.test.ts` prueft ausschliesslich die Buendelpinnung (acht Zeugen, null Vorkommen von `fetch`, `addEventListener`, `respondWith`, `cache.put`, gemessen 2026-09-05), sodass nur der Quellenscan von `privacy_canaries_reader.rs` gilt — es fehlt ein Laufzeitzeuge in `apps/web`, der nach einer `fetch`-Anfrage zusichert, dass kein `caches`-Namensraum eine Antwort traegt | 7 |
| Sperre und Verifikation lesen eine zurueckgesprungene Uhr VERSCHIEDEN | GEMESSEN im DRK-264-Rebase: `ReaderSession::observe` (`crates/ea-reader/src/session.rs`) hebt jeden `now` unterhalb des hoechsten je gesehenen Wertes auf diese monotone Untergrenze, und die Sitzungssperre rechnet gegen sie. Der Verifikationspfad nimmt denselben Zeitwert dagegen ROH: `ReaderVerifier::new(mode, effective_now)` haelt ihn unveraendert, und Gate `recipient-grant` misst die Nutzungsfrist gegen ihn. Dieselbe zurueckgestellte Uhr wird von den beiden Haelften also verschieden gelesen; welche Haelfte nachzieht, ist eine Entscheidung ausserhalb dieser Stufe | offen |
| Das Auditpseudonym des Readers ist ungesalzen und ohne Domaenentrennung | GEMESSEN im DRK-264-Rebase: `ReaderAuthenticatorConfirmation::prove` bildet es als `Sha256(credential_id)` (`crates/ea-reader/src/session.rs:274`) — kein Salz, kein Domaenenpraefix —, waehrend `OperatorSnapshotV1::new` auf der Desktopseite (`crates/ea-schema/src/model.rs`) ein 32-Byte-Salz entgegennimmt. Wer die Liste der `credentialId` haelt, invertiert das Pseudonym durch Nachrechnen. Die Angleichung ist ein Formatschritt und keine Zeile dieser Stufe | offen |

## Gemessener Gate-Lauf

Der vollstaendige Lauf nach Schritt 4 des Stufe-4-Plans
(`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-4-reader.md`), in der
dort vorgeschriebenen Reihenfolge, mit `cargo metadata --format-version 1` an
erster, `cargo run --locked -p xtask -- integration up` an zweiter und
`cargo run --locked -p xtask -- integration down` an letzter Stelle. Die
siebzehn Zeilen mit Exitcode, gemessenem Ergebnis und gemessener Laufzeit
stehen unten und sind EINGETRAGEN: sechzehn davon tragen die Zahlen des
Bootstraplaufs, die siebzehnte — die Zeile `pnpm verify:quick` — die des
Bestaetigungslaufs. Warum der Lauf zweipassig ist und warum trotzdem keine
Zeile geschaetzt wurde, schreibt der Unterabschnitt „Warum dieser Lauf
zweipassig ist" unten aus.

Zwei Angaben sind dabei gebunden und nicht frei: die Belegzeile von
`pnpm verify:quick` MUSS die Zahl ihrer Teilkommandos und die Zahl der Pakete
auf der wasm32-Positivliste AUSGESCHRIEBEN nennen — gemessen ZWOELF und
VIERZEHN —, und sie MUSS sagen, ob auf warmem oder kaltem `target/` gemessen
wurde. `stage_four_gate_report_records_the_measured_full_gate_run` zaehlt beide
Zahlen LIVE am zeichengenauen Pin von `verify_quick_commands()` in
`tools/xtask/src/main.rs` und stellt sie gegen genau diese Zelle; die
abgeschlossenen Berichte der Stufen 2 und 3 tragen dafuer historische Literale
und werden nicht umgeschrieben.

| Kommando | Exitcode | Gemessenes Ergebnis | Laufzeit |
|---|---|---|---|
| `cargo metadata --format-version 1` | 0 | 3 586 479 Byte JSON auf stdout; `Cargo.lock` bleibt unveraendert — dieser Teil zieht keine neue Arbeitsbereichskante, und das eine Kommando ohne `--locked` belegt es, statt es anzunehmen | 0 s |
| `cargo run --locked -p xtask -- integration up` | 0 | beide Dienste gesund; die zwei Zeilen `export DATABASE_URL=postgres://…@127.0.0.1:55432/einsatzarchiv` und `export EA_OBJECT_STORE_ENDPOINT=http://127.0.0.1:59000` gedruckt und per `eval` uebernommen | 7 s |
| `cargo run --locked -p xtask -- browsers up` | 0 | Dienst gesund; gedruckt wird GENAU EINE Zeile, `export CHROMEDRIVER_REMOTE=http://127.0.0.1:59515` — kein Pfad zu Engine-Baus, siehe Abschnitt 2.1 | 6 s |
| `pnpm build:wasm` | 0 | `apps/web/src/bridge/pkg/ea_reader_wasm.js` erzeugt. Ohne diesen Schritt faellt `pnpm web:e2e` — in der Liste OHNE `build:wasm`, und die ist der Gegenfall, das ELFTE Kommando; in der Liste unten das zwoelfte — mit `[UNRESOLVED_IMPORT] Could not resolve './pkg/ea_reader_wasm.js'`, bevor ein Browser startet — gemessen im Bootstraplauf ohne diese Zeile, Exit 1 nach 3 s | 2 s |
| `pnpm test:reader` | 0 | `ea-reader` und `ea-index` zusammen: 31 Ergebniszeilen, 145 bestanden, 0 fehlgeschlagen, 1 ignoriert — der ignorierte ist der Skalenlauf, den das Kommando darunter faehrt | 59 s |
| `pnpm index:scale` | 0 | `ea-index scale packages=50000 blob_bytes=7566455 seal_ms=4419 unlock_ms=6114 search_us=48 broad_search_us=84667 peak_rss_kib=357484`; ausgewertet in Abschnitt 5 | 13 s |
| `pnpm web:browser-test` | 0 | die `wasm-bindgen-test`-Ziele von `crates/ea-reader-wasm` in headless Chromium ueber den `chromedriver` aus Kommando drei: VIER Ziele tragen Tests — `export_browser` 2, `index_browser` 1, `opfs_browser` 5, `verify_browser` 2 —, zusammen 10 bestanden, 0 fehlgeschlagen; die uebrigen fuenf Ziele melden `no tests to run!` | 25 s |
| `cargo test --locked -p ea-system-tests --test cross_platform_two_readers` | 0 | 2 bestanden: ein Chiffrat unter zwei Reader-KEM-Schluesseln, und der entfernte Grant als Planabgleichsfehler fuer beide | 3 s |
| `cargo test --locked -p ea-system-tests --test e2e_reader_sync_interruptions` | 0 | 3 bestanden: Mengengleichheit von Manifest und `ReaderSyncFaultPoint`, Cursor nach jedem der fuenfzehn Abbrueche unveraendert, Wiederholversuch idempotent | 22 s |
| `cargo test --locked -p ea-system-tests --test reader_file_mode_interop` | 0 | 5 bestanden: (a) und (b) bytegleich samt `serverConfirmation`, (c) zweifach, das untergeschobene Archiv an Gate `trust` | 5 s |
| `cargo test --locked -p ea-system-tests --test privacy_canaries_reader` | 0 | 9 bestanden: kein Marker in einem der sieben Stroeme, und die Positivkontrolle findet denselben Marker dort, wo er liegen soll; DREI der sieben Stroeme — Service-Worker-Cache, Zwischenablage und Telemetrie — sind QUELLENSCANS und keine Laufzeitmessung | 1 s |
| `pnpm web:e2e` | 0 | 36 Tests ueber `chromium`, `firefox` und `webkit`: 27 bestanden, 9 uebersprungen, 0 fehlgeschlagen; WebKit ueber den `run-server` im gepinnten Abbild (Abschnitt 2.1) | 18 s |
| `pnpm supply-chain` | 0 | advisories ok, bans ok, licenses ok, sources ok; der `wasm-bindgen`-Teilbaum hat KEINE neue benannte Ausnahme in `deny.toml` erzeugt, die Datei fuehrt weiterhin keinen `name =`-Schluessel | 2 s |
| `pnpm stage-gate:4` | 0 | JSON auf stdout: `stage` 4, `vector_families` LEER, `stage_four_primary_acceptance_criteria` `[10, 42, 43]`, 32 deklarierte Szenarien, 21 aufgeloeste Zeugen (zwoelf `sync-cursor`-Punkte teilen einen), `stage_four_rows_still_planned` LEER, 158 Ledgerzeilen | 0 s |
| `pnpm verify:quick` | 0 | ZWOELF Teilkommandos gruen, darunter `cargo run --locked -p xtask -- build-wasm`, der `apps/web`-Bau und der wasm32-Check ueber die VIERZEHN Pakete der Positivliste, deren Zahl `verify_quick_commands()` in `tools/xtask/src/main.rs` haelt. Ueber beide `cargo test`-Teilkommandos zusammengezaehlt: 238 Ergebniszeilen, 1586 bestanden, 0 fehlgeschlagen, 8 ignoriert. Gemessen auf WARMEM `target/` — der Lauf folgt unmittelbar auf die vierzehn Kommandos darueber, die denselben Baum uebersetzt haben; ein kalter `target/` liegt deutlich darueber und ist hier NICHT gemessen. Diese Zeile allein stammt aus dem BESTAETIGUNGSLAUF und nicht aus dem Bootstraplauf, aus dem Grund, den der Unterabschnitt darunter ausschreibt | 1004 s |
| `cargo run --locked -p xtask -- browsers down` | 0 | Dienst und Netz entfernt, mit `--volumes` wie `integration down`, obwohl der Dienst keinen Zustand fuehrt | 11 s |
| `cargo run --locked -p xtask -- integration down` | 0 | beide Dienste entfernt, beide Volumes (`postgres-data`, `objectstore-data`) geloescht | 2 s |

### Warum dieser Lauf zweipassig ist

Die Zeile `pnpm verify:quick` oben stammt als EINZIGE aus einem zweiten Lauf,
und der Grund ist eine Selbstbezueglichkeit des Vertrags, keine Nachlaessigkeit.
`pnpm verify:quick` faehrt `cargo test --workspace --all-targets --locked`, und
darin liegt `stage_four_gate_report_records_the_measured_full_gate_run` — der
Test, der GENAU DIESE Tabelle liest. Solange sie leer ist, ist `verify:quick`
rot.

GEMESSEN, und deshalb hier ausgeschrieben statt geglaettet: der Bootstraplauf
vom 2026-09-05 fuhr die siebzehn Kommandos mit leerer Tabelle. Sechzehn endeten
mit Exitcode 0; `pnpm verify:quick` endete nach 990 s mit Exitcode 101, und der
einzige Fehlschlag im gesamten Arbeitsbereich war

```text
stage-4-gate.md must record the measured run for `cargo metadata --format-version 1` exactly once
```

Danach wurden die sechzehn Zeilen eingetragen und `pnpm verify:quick` in
derselben `integration up` … `down`-Klammer wiederholt: Exitcode 0 nach 1004 s,
238 Ergebniszeilen, 1586 bestanden. Die sechzehn uebrigen Zeilen dieser Tabelle
tragen die Zahlen des Bootstraplaufs, die siebzehnte die des
Bestaetigungslaufs. Die Zahl der Ergebniszeilen unterscheidet sich zwischen
beiden Laeufen aus einem gemessenen Grund: `cargo test --workspace` bricht nach
dem ersten roten Testbinary ab, der Bootstraplauf kam also gar nicht bis zum
Ende der Liste.

Eine Zeile, die den Bootstraplauf als gruen ausgaebe, waere die Faelschung, die
dieses Repositorium nicht schreibt — und ein Bericht, der die zwei Paesse
verschwiege, waere dieselbe Faelschung, nur leiser.
