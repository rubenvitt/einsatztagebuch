# DRK-250 – Umsetzung und Verifikation

## 13.09.2026, 14:57 Uhr – neue native Ressourcenarbeit mit tatsächlichem RED

Prepared-Diagnose: sauberer API-RED nurE0599 und tatsächlicher Host-Verhaltens-RED **0/1 in13,99s** (native-prepared-resource-behavior-red-native.log). Der echte Writer stoppt nach Prepared-Markercommit; fehlendes Adminlogin wird bereits verweigert, die positive eingeloggte Diagnose scheitert an der bisher nicht verfügbaren Anbindung. Snapshot- und dokumentierte-Posture-No-Write-Proben werden vor Abnahme ergänzt. Aktuelle geteilte Profil-/Marker-Lesefassung dient ausschließlich einem gezielten Snapshot-RED; sie ist kein abgenommener atomarer Port. Der vorhandene Posture-Prüfer kann mit record=true Zeitbounds schreiben; derselbe Verifier wird für den Diagnosekörper mit record=false und strikter Ergebnisprüfung verwendet. Keine neue Clockfreigabe.

Ein-Teilnehmer-Bootstrapdesign nach unabhängigen Befunden revidiert und nun Design-PASS: interne tatsächliche SQLCipher-Öffnung über denselben Nativeprovider/LocalDatabaseKey statt beliebiger ArcDB; NFC/SecretText aus vorhandenem Schemakern vor DB/Intent/Generate. Keine Ersatzdatenbank oder Generatefallback bei fehlendem/falschem DBkey, korrekte Mutation/Migrationsgrenzen des bestehenden Openers ausdrücklich behalten. Implementierung mit eigenen API-/Native-REDs freigegeben, noch keine Implementierungsgates oder Step3-/Backup-/Zweikonten-Abnahme.

Root hat daneben restliche native Vernichtungs-Erzeuger1→2,1→4,2→4,4→1 separat inventarisiert (native-destruction-remaining-state-producers.md). Zwei historische Semantikzeugen werden vorbereitet; noch kein zusätzlicher Produktionsfix oder neuer Fullretry. Bisheriger erfolgreicher1→3-Reader-Gesamtnachweis bleibt begrenzt abgenommen.

Testharness-Konsolidierung unabhängig PASS (test-harness-consolidation-review.md): reguläre Testregistrierungen und alle sechs Guidednamen erhalten, Hashes der archivierten Kopien bestätigt, keine neueRuntimebehauptung aus0ausgeführt/6ignoriert. Keine Produktion/Commit/Push/PRwirkung dieser Testpflege.

## 13.09.2026, 14:46 Uhr – vollständiger Same-Job-Readerabschluss unabhängig PASS

Tatsächlicher kompletter Reader-/OPFS-/TLS-/Evidence-Lauf **1/1 GREEN in372,29s**, unveränderliche Copy331bce12c70d1292bd1c119289a1aedcd2cf77aab6e42f2d393df57dcd87c55e. Root hat finalen Testkörper, Log und Ownerbericht unabhängig gelesen und native-reader-opfs-completion-root-review.md mit begrenztem PASS erstellt. Tatsächliche Reader-Worker-Löschung und ETB, unabhängige historische Nativeprüfung, exakter Importreplay, TLSResume→Complete319,14s, echter Hostrestart/TLSSync338,76s, originale ServerETB/Jobbytes und vollständige Originalversionen-Abwesenheit340,98s, gewöhnlicher Evidence-Preview/Finalize und erneuter Hostreopen bis372,29s. Keine zweite Resumealternative nötig, keine neue TTL oder Retryschleife.

Die Evidence-Endassertion dieser konkreten Probe kontrolliert den persistierten normalen Entrybezug nach Reopen; keine zusätzliche unabhängige Entschlüsselung aller Evidence-Tabellen behauptet. Synthetischer Nativeprozess mit echten Produkt-/Browser-/Serverdiensten, kein installierter OS-KeyStore oder GUI-Klicknachweis. Frühere fehlgeschlagene Läufe bleiben als solche dokumentiert.

Neue unabhängige Arbeitsstränge: Prepared-Diagnose-Ressourcenvertrag durch Root geprüft; Umsetzung mit echten API-/Behavior-REDs freigegeben, CurrentAdmin und bereits gebundener Writer, keine Reopen-/Recoveryabkürzung. Ein-Teilnehmer-Bootstrapvertrag liegt read-only vor und wird unabhängig geprüft; keine neue Schrit3-/Kontentrennungs-/Backupbehauptung. Gesamt bleibt in Arbeit.

## 13.09.2026, 14:40 Uhr – alte Testharnesses dauerhaft eingeordnet

Die breitere Parserprüfung reproduzierte den Grant-Output-Widerspruch auch in der unveränderlichen früheren Step2-v4-Copy vor certify-root. Root entfernte ausschließlich die obsolete negative --output-Assertion und korrigierte den Kommentar; die vorhandene positive Grantprobe und Pflichtschalterprüfung bleiben bestehen. Kein Parserverhalten geändert. Finale Parserprüfung **42/42**, native-bootstrap-root-cli-args-green.log.

Breiter CLIbin/Tests-Clippy deckte danach alte temporäre Reviewtargets auf: root_t9_review.rs referenzierte einen nicht mehr vorhandenen /tmp-Probe-Body; task9_guided_probe.rs duplizierte eine veraltete Operatorfixture. Der ursprüngliche Rootreview kennzeichnet den ersten Harness explizit als temporär; Task9bericht plante bereits das Einfalten des zweiten. Beide vollständigen Quellen wurden reversibel und mit SHA256 nach SDD/historical-test-harnesses/*.snapshot archiviert. Der fehlende externe Probe-Body wurde nicht erfunden. Die sechs vorhandenen Guided-Proben sind nun direkt im normalen operator_recovery-Modul registriert, mit unveränderten tatsächlichen Fremdmaschinen-/Medienvoraussetzungen und Ignore-Grenzen. Ein boolassert wurde semantisch identisch korrigiert. Keine Produktquelle, kein NativeHelper und kein Reader-Testkörper geändert.

Anschließender breiter CLIbin/Tests-Clippy **Exit0 in3,09s**, Release-Operator-no-run **Exit0 in9,65s**. Tatsächliche Liste enthält alle sechs Guided-Proben; normaler gefilterter Lauf bestätigt **0 ausgeführt,6 bewusst ignoriert**. Dies ist Build-/Registrierungsnachweis, kein neuer Ubuntu-/Runtime-GREEN. ArchiveREADME enthält Pfade/Hashes/Begründung. Die aktuelle vollständige Readerprobe läuft unverändert aus ihrer früheren Copy331bce12 und erreicht tatsächliches TLSResume bei319,14s mit completeManagedScope; verbleibende Server-/S3-/Evidenceprüfungen sind noch offen.

## 13.09.2026, 14:33 Uhr – nativer Completion-Kern und Desktop-Anbindung begrenzt abgenommen

Finale native Kernprobe aus unveränderlicher Copy07bb36563d26f68dbb7c2d95a4e9f3e6e03f8f3a039e36ccfb32ff8f9b7c90c0 **4/4 in 369,07 s**, einschließlich beider historischer Korrekturen und tatsächlich zurückgekehrter freigegebener Auditbarriere. Erwartete konkrete Refusals: konkurrierende Historie SecurityConflict, wiedergekehrte Holdings Target, beobachteter Watchverlust NativeSession und injizierte atomare Persistenzverweigerung Storage. Bestehende Importregressionen **3/3 in 68,65 s**; gesamter Destruction-Kern zuvor40/40, finaler scoped Clippy26,21s. Atomic-/History-Reviews PASS. Root hat finale Logs gelesen; der begrenzte native Abschlussservice ist abgenommen, keine pauschale Gesamtzustandsmaschinenabnahme.

Desktop-NoServer tatsächlicher RED0/1 in36,05s → **GREEN1/1 in70,45s**. Exakter Abschluss nach Host-Reopen, idempotente erneute Fortsetzung ohne neuen Importbatch und weiterhin getrennte normale Writer-Evidence-Finalisierung. Bestehende ausstehende Reader-/signierte Backup-Importregressionen **2/2 in64,32s**; Desktoplib/destruction **3/3**, Build27,42s. Beide neuen Produktdateien explizit im gemeinsamen Admin-/Desktop-/CLI-Clippy7,88s geprüft, Source-Review ohne Finding. Copy331bce12c70d1292bd1c119289a1aedcd2cf77aab6e42f2d393df57dcd87c55e enthält finale Kern- und Desktopquellen. Root hat den vollständigen Same-Job-Reader-/OPFS-/TLS-/Evidence-Lauf aus genau dieser Copy freigegeben; noch kein Endergebnis. Synchronize bleibt ohne Job-/Eventpublikation und erzeugt keine Completion.

Bootstrap certify-root begrenzt unabhängig PASS: native24/24 plus expliziter ignorierter Fixtureentry, sichere ausgelieferte CLI4/4, Init16/16, gemeinsame und finale betroffene Clippys grün. Keine Behauptung positiver installierter OS-KeyStore-Ausführung oder vollständigem Bootstrap. Nachträgliche breitere reine Parserregression meldet41/42 an einem Grant-Output-Vertrag; Owner prüft denselben Fall in älterer Copy als Baseline. Das wird getrennt untersucht und nicht als grüne Gesamtgrammatik ausgegeben.

Keine Commits, kein Staging/Push/neuer PR. Nächster Bootstrap-Teilnehmervertrag wird read-only vorbereitet; vollständiger Schritt3 und echter Admin-Backupweg bleiben offen.

## 13.09.2026, 14:23 Uhr – Completion-Kernregression grün; CLI-Anbindung in Prüfung

Korrigierte native Completion-Probe aus unveränderlicher v2-Copy: **4/4 GREEN in 364,25 s**, einschließlich gültigem 2→3 nach tatsächlich abgelaufener historischer Backupfrist. Diese Copy enthält noch nicht den anschließenden Claim-Order-Fix. Dessen sauberer signierter RED ist jetzt **0/1 in 2,45 s** (native-completion-claim-order-red-clean.log): jüngster Claim zuerst versteckte zwei unterschiedliche ältere Claims mit gleichem Replik-/Zeitpaar. Prüfung exakter Bytes pro authentisiertem (device, executed_at) erfolgt nun vor dem Latest-Skip; identischer Replay bleibt erlaubt. Gesamte ea-destruction-Testmenge mit diesem Fix **40/40 GREEN** (native-completion-destruction-regression.log). Unabhängiger Re-Review läuft; finale native Copy mit allen Korrekturen und explizitem Rückkehrmarker der freigegebenen Auditbarriere folgt. Kein vollständiger Reader-Abschluss behauptet.

Bootstrap-CLI: tatsächlicher API-RED nur E0432; Verhaltens-RED **0/1 in 0,41 s** am zuvor unbekannten Schalter statt erwarteter Missing-State-Verweigerung. Implementierung des verzögerten nativen Openers, Parser/Handler und getrennten Fixtureprozesses liegt vor; fokussierter Build läuft, Root prüft Quellen. Installierter Produktentry bleibt open_installed(false), keine Schlüsselgenerierung oder spätere Bootstrapstufe. Desktop-Produktintegration wartet auf Kernabnahme; tatsächlicher Desktop-RED bleibt dokumentiert.

## 13.09.2026, 14:15 Uhr – historische Frist korrigiert; benachbarter Ordnungsbefund offen

Root hat den sauberen historischen RED direkt gelesen: native-completion-backup-deadline-red-clean.log,0/1 in1,65s an fälschlich akzeptiertem Complete bei früherer Pendingfrist2000 und späterem gültigem Erfolgsclaim1999 ohne Fristfeld. Das unsuffigierte red.log enthält die frühere ungültige Fixture, die bereits intrinsisch verweigert wurde; es ist nicht der maßgebliche RED. GREEN1/1 in2,04s. Bekannte Maxfrist pro authentisierter Replik bleibt über die ganze verifizierte Historie erhalten; erfolgreiche Entfernung muss sie selbst erreicht haben. Pending-Status zeigt dieselbe historische Maxfrist ohne neue DTOform.

Der erste native3/3-Lauf in283,13s wird ausdrücklich nicht als korrekter Backup-/Kernabschluss akzeptiert, weil seine2→3-Erwartung den gefundenen Fehler enthielt. Seine übrigen tatsächlichen Konkurrenz-/Holdings-/Watch-/Tx-Rollback- und1→3/Reopenbelege bleiben als Vorfixnachweise erhalten. Korrigierter nativer Vier-Fälle-Lauf aus unveränderlicher v2-Copy läuft. Keine Uhrmanipulation oder60s-Schlaf; gültiger2→3-Fall verwendet bereits abgelaufene attestierte Fixturefrist und tatsächlich spätere lokale Entfernung.

Unabhängiger Reviewer fand daneben einen älteren Reihenfolgenfehler: gleichzeitige unterschiedliche ältere Claims werden beim latest-Skip unter bestimmter Inputreihenfolge nicht mehr gegeneinander verglichen. Root hat gezielten signierten Historical-RED und engen seen(device,time)/Exactbytes-Konfliktcheck vor dem Skip beauftragt; identischer Replay bleibt idempotent. Noch keine Ausführung/Schließung dieses zweiten Befunds behauptet.

Bootstrap-CLI-Owner bereitet meanwhile tatsächliche API-/CLI-REDs für den expliziten certify-root-Entry vor. Bestehender Step2-Kern erhält einen verzögerten Native-Opener statt duplizierter Admission; ausgelieferter Main bleibt installed(false), positive Fixture-Executable getrennt. Gesamter Zwölf-Schritt-Bootstrap und normative JSON-Ausgabe bleiben offen.

## 13.09.2026, 14:08 Uhr – Desktop-RED und zusätzliche historische Backupgrenze

Root-Desktop-IPC-Zeuge registriert, optimierter no-run10,50s, immutable Copy SHA256 d5216ee179ba16c9910eb157acf99c0d44d7bc637c2dd855d2a0c321da2ca0ad. Tatsächlicher NoServerlauf0/1 FAIL in36,05s an inProgress statt completeManagedScope; beide bisherigen Readerpfade stehen damit als getrennte Belege für fehlende Integration. Noch keine Desktop-Produktänderung.

Zusätzliches Root-Semantikfinding am Completion-Backupfall: Die neue Probe erwartet sofort2→3, obwohl eine frühere verifizierte Pending-Attestation eine Frist60s später benennt und der nachfolgende Erfolgsclaim nur1ms später ausgeführt ist. Die bestehende Projektion wählt nur den neuesten Resultcode und berücksichtigt frühere Backupfristen nicht. Primärspec §16.3 verlangt abgelaufene Fristen plus attestierte Entfernung. Reader-Agent untersucht gezielten historischen RED und engen Korrekturschnitt; kein Uhranheben/60s-Schlaf als Ersatz, keine pauschale Kernabnahme aus bisherigen Atomic-Source-PASS oder laufenden Tests. Root hält Desktopintegration bis zur fachlichen Korrektur zurück.

## 13.09.2026, 14:03 Uhr – PreAnchor-Prüfung akzeptiert; Completion-Verhaltens-RED belegt

Neue reine `verify_pre_anchor_bootstrap_objects`-API unabhängig PASS: dieselbe private Initial-Root-/Admin-/Binding-/Pairprüfung wie der bestehende finale Trustpfad, Rückgabe nur Result<(),TrustError>. API-RED nurE0432; finale Bootstrap8/8 und certificate_attacks14/14, Clippy6,65s. Root hat diese finalen Logs gelesen, separater Reviewer hat Quelle und Logs geprüft. Der neue positive Test erzeugt tatsächlich keinen finalen Anchor und keine Genesis. Unterschiedliche Account-Binding-Hashes sind weiterhin kein Beweis real getrennter Konten.

Completion-Service: sauberer API-RED nurE0599, danach tatsächlicher fail-closed Behavior-RED0/1 in25,71s am positiven Abschluss nach realem Native-Prepare/Start/Writerabbau und ausdrücklich synthetischem historisch verifiziertem Readerclaim. Root hat Log und Testgrenze gelesen. Das ersetzt nicht den echten OPFS-Reader. Implementierung liegt vor; Root-Semantikreview und unabhängiger Atomic-Source-Re-Review bisher ohne Findings, optimierter Build/erste Kerngates laufen. Neue Negative beobachten gehaltene tatsächliche Destruction-Auditsignatur und konkurrierende Historie, wiedergekehrte lokale Originalbytes, Watchverlust oder Tx-Persistenzverweigerung. Noch kein grüner Completion-Kern und kein neuer Fullrun.

Root besitzt die nächste Desktop-Resume-Komposition; ein tatsächlicher NoServer-IPC-Zeuge ist vorbereitet und noch unregistriert. Nur explizites Resume soll nach vollständig verifizierten Pflichten den nativen Service aufrufen und bei Servern die exakten Abschlussbytes tatsächlich publizieren/importieren. Synchronize bleibt GET/import-only. Core-Service überprüft sämtliche Autoritäts-/Historien-/Abwesenheitsgrenzen erneut; Statusdaten dienen ausschließlich der Routingentscheidung.

## 13.09.2026, 13:54 Uhr – dauerhafter nativer Schritt2 unabhängig abgenommen

Finale v4-Quelle und Logs durch Root unabhängig geprüft: **20/20 native Tests in8,42s**, Bootstrap53/53 in0,20s, Lease5/5 in0,06s plus separater ignorierter Childentry, Clippy8,35s Exit0. Beide Reviewbefunde mit tatsächlichem RED/GREEN geschlossen: erneuter gemeinsamer Parentflush nach unklarem Rename und Ablehnung späterer Felder im frühen State. Neues Prädikat verwendet fresh-Statebild plus ausschließlich erlaubte step/root-Felder, ohne globalen Decoderumbau. Rootreview PASS, keine offenen Findings im begrenzten Schnitt; gesamter diffcheck Exit0 vor folgenden Änderungen.

Keine Root-Schlüsselgenerierung, keine neue Signierfamilie/CLI-Option, kein Archivprofilwechsel oder produktive Freigabe. Original wird vor Statecommit gehalten, auf Resume exakt wiederverwendet und erneut synchronisiert; BlockedRecoveryTest bleibt bestehen. Detailbericht und Rootreview: native-bootstrap-root-step-two-report.md / native-bootstrap-root-step-two-review.md.

Reader übernimmt Cargo und hat den sauberen Completion-API-RED (nur E0599) gemeldet; tatsächlicher Verhaltens-RED mit fail-closed Stumpf folgt vor Implementierung. Atomic-Reviewer bestätigt den begrenzten Reuse-Entwurf, noch keinen Implementierungs-PASS. Bootstrap-Agent arbeitet danach unabhängig an Wiederverwendung der bestehenden ea-trust-Bootstrapprüfungen für echte PreAnchor-Originale; kein erfundener finaler Anchor oder Registry-/Produktivnachweis.

## 13.09.2026, 13:51 Uhr – zweiter konkreter Bootstrap-RED und produktiver Completion-Schnitt

Root hat den tatsächlichen späten Flush-RED und v3-Logs unabhängig gelesen: native Root/Prepare/Step2 insgesamt19/19 in7,67s; Bootstrap53/53 in0,20s, Lease5/5 in0,06s (separater Child-Entrypoint absichtlich ignoriert), Operator/desktop-fixture-Clippy23,27s. Diese Gates decken den gemeinsamen Parentflushfix ab. Der injizierte AfterRename-Fehler und die tatsächliche Alias-Parentverweigerung sind getrennt dokumentierte Grenzen. Kein Hardware-/Crashnachweis.

Root-Review findet zusätzlich, dass der bestehende State-Decoder zwar die Byteform, aber keine stufengerechte Feldbelegung prüft. Der neue frühe Host akzeptierte ein späteres fingerprints_compared-Flag. Tatsächlicher RED0/1 in0,70s laut Owner; Korrektur über frisches bestehendes Stateabbild plus ausschließlich erlaubte step/root-Felder und vollständigen Bytevergleich. Derselbe enge Prädikatport wird in Prepare und Commit genutzt; keine globale Decoderänderung. Finale v4-Gates laufen, daher noch keine Step2-Abnahme.

Reader-Quelleninventur bestätigt fehlenden produktiven Complete-Erzeuger. Root hat die Primärspec §16.3 unabhängig gelesen; der neue Service muss ein existierendes deletionAttest-signiertes append-only Ereignis erzeugen, alle ursprünglichen Pflichten zur tatsächlichen Ereigniszeit erfüllen und den aktuellen Vorgänger atomar binden. Die vorhandene Importpersistenz soll mit vor Signierung erfasstem Snapshot sowie gemeinsamen Holderlocks bei abschließender lokaler Abwesenheitsprüfung wiederverwendet werden. Unabhängiger Atomic-Reviewer prüft den Schnitt. Der erste fokussierte API-/Service-RED ist vorbereitet; noch kein Produktions-GREEN oder erneuter Fullrun.

Schritt3-Inventur ist dokumentiert: reine Admin-Hashpaare belegen weder getrennte tatsächliche OS-Konten noch Admin-Backup. Vorhandene Operator-Instanzprovisionierung darf beim Resume nicht blind ersetzen. Kein Schritt3-Abschluss wird daraus abgeleitet.

## 13.09.2026, 13:43 Uhr – Reader erreicht neue Abschlussgrenze; Step2 mit Reviewbefund

Vollständiger Same-Job-Reader-/OPFS-/TLS-/Evidence-Lauf aus der unveränderten Releasecopy **FAIL 0/1 in 338,13 s**. Tatsächliche Rückgaben: Resume 236,06 s und Synchronize 257,56 s; der vorhandene zweite explizite Resume kehrt ebenfalls zurück, aber die anschließende Rekonstruktionsassertion sieht `inProgress` statt `completeManagedScope`. Root hat finalen Testvertrag und vollständiges kompaktes Runlog unabhängig gelesen. Diesmal kein NativeSession-Abbruch; die späteren S3-Original-/Versionen- und Evidence-Abschlussprüfungen wurden noch nicht erreicht. Log `.superpowers/native-reader-opfs-release-run-v1.log`. Der Reader-Agent lokalisiert die fehlende Pflicht ohne zusätzliche Fullruns oder Resume-Schleifen.

Native Bootstrap-Schritt2 erstmals 10/10 in 5,30 s laut Worker; weitere negative Veröffentlichung-/Rootbindungsproben folgen. Unabhängiger Datei-Review meldet einen angenommenen P2: Nach erfolgreich umbenanntem State und fehlgeschlagenem Parentflush darf Wiederaufnahme nicht allein nach Reload Erfolg quittieren. Engster Fix bestätigt den gemeinsamen Parent von State und Original erneut durch den vorhandenen Original-Sync, auch bei bereits gespeichertem Schritt2. Eine eng begrenzte test-support-Injektion soll genau den späten Fehler deterministisch bezeugen; dies wird nicht als realer OS-Crash behauptet. Noch keine endgültige Step2-Abnahme.

Gesamtstatus bleibt in Arbeit; kein Commit, Push oder neuer PR.

## 13.09.2026, 13:34 Uhr – Releasevergleich bestanden, vollständige Probe gestartet

Release-no-run mit identischen CLI/desktop-fixture-Features in1m38s bestanden. Reader meldet identischen relevanten Quellhashsatz vor/nach Build. Unveränderliche Kopie: `.superpowers/native-reader-release-operator-v1`, SHA25619c33f30a0b62702b80cdd599da7048a258d098559a0a7cc5bcd8a61dd5b3d9a (Root hat SHA-Datei und Buildlog gelesen).

Identische isolierte ActualReservation-Probe **1/1 GREEN in124,79s**, Transport110,93s gegenüber203,33s des unoptimierten Profilinglaufs. Root-/Workerauswertung stimmen erneut überein:233Acquires,228Reopens,3523Nicht-Watch-Helpercalls,0unvollständige Spans im ausgewerteten Fenster. Disjunkte Snapshotzeit5,875s statt59,449s; select_current2,081s statt20,330s. DBopen10,759s und Identitätsabschluss21,256s sind hingegen nicht schneller als im Vergleichslauf. Dies ist eine konkrete Fixture-/Buildprofilbeobachtung, kein kontrollierter allgemeiner Performancebenchmark und keine installierte OS-KeyStore-Abnahme.

Keine Guard-, TTL-, Key-/Trust-Prüfung oder Featureauswahl wurde für diesen Erfolg geändert. Root hat darauf die vollständige Same-Job-Reader-/OPFS-/TLS-/Evidence-Probe aus derselben bereits kopierten Releasebinary autorisiert; sie läuft jetzt ohne neuen Fixtureumbau oder Retryloop. Erst ihr tatsächliches Endergebnis entscheidet über diesen Gesamtnachweis.

Sourcefreeze ist aufgehoben. Der Bootstrap-Agent integriert jetzt den neuen echten Step2-Host nach dem bereits belegten API-RED. Öffentliche Original-PoP auf Resume wird erneut verifiziert und an die aktuelle native Session/Account/Installation/Rootauswahl gebunden; es wird dabei keine neue Root-Präsenz oder Ersatzsignatur behauptet. Neuer Schritt1 ohne Original behält den vorhandenen presence=true-Signaturpfad. Noch kein Step2-GREEN.

## 13.09.2026, 13:30 Uhr – Lease abgenommen, echte Custodian-Reauth und Releasevergleich

FileBootstrapStore-Lease unabhängig PASS. Der konkrete P2 ist mit echtem Ersatzinode-RED/GREEN geschlossen. Final: Lock 5/5 in0,05s, Bootstrap 53/53, CLI 16/16; Admin-Clippy12,71s und CLI-Clippy13,88s grün. Sporadische Interferenz zwischen unabhängigen Lock-Testfällen bleibt ursächlich nicht lokalisiert; ein lokaler Fixture-Mutex isoliert diese Fälle, die tatsächlichen konkurrierenden Childprozesse innerhalb jedes Falls bleiben unverändert. Kein Parallel-Stresstest- oder plattformübergreifender Lease-Nachweis.

Reader-Custodian-Reauth auf DEMSELBEN Host tatsächlich **1/1 in84,83s**: Prepared16,99s, tatsächlicher Writer-TTLexit und exakt NativeSession64,82s, vorhandene explizite Writer-/Admin-Reauth erfolgreich84,81s. Alter Provider bleibt nach Entfernen des Testknopfs ungültig; neuer Provider verwendet unverändert Standard300s. Process/Hash/Denominator/Config/Archivbytes bleiben gleich. Root hat Test und Log unabhängig gelesen; eigener CLI-Operator/desktop-fixture-Clippy **grün27,24s** deckt neue Reauth- und Profilingquelle ab. Die frühere fixed-provider/general-login-Probe ist kein allgemeiner Produktcachefehler.

Root hat fünf neue Step2-Tests registriert und den sauberen tatsächlichen API-RED erhalten: `.superpowers/native-bootstrap-root-step-two-api-red-clean.log`, ausschließlich E0432 für `complete_native_root_step`. Die erste RED-Datei bewahrt einen inzwischen entfernten doppelten Traitimport-Warnhinweis. Für den isolierten Releasevergleich ist nur diese temporäre Testregistrierung wieder entfernt; die Testdatei bleibt erhalten und ist noch kein Laufnachweis. Der Bootstrap-Agent besitzt jetzt Step2-Implementierung/Tests, arbeitet bis Freigabe aber ausschließlich in neuen unregistrierten Dateien. Es gab noch keinen Step2-GREEN.

Reader startet Release-no-run mit identischer CLI/desktop-fixture-Konfiguration aus eingefrorenen bisherigen Produktions-/registrierten Testinputs. Danach zunächst dieselbe isolierte Resume-Probe, kein sofortiger vollständiger E2E und keine TTL-/Guardänderung. Log `.superpowers/native-reader-release-build-v1.log`. Tatsächlicher Releasegewinn ist noch offen. Gesamter Root-diffcheck vor Freeze Exit0.

## 13.09.2026, 13:18 Uhr – konkreter Lease-Reviewbefund und nächste echte Hostprobe

Erste Lease-Gates: reale Prozess-/Crash-/Dateiformtests 4/4, bestehender Bootstrap 53/53 mit test-support und organization_init 16/16. Noch keine endgültige Abnahme: unabhängiger Review-P2 verlangt erneute tatsächliche Namens-/Inodevalidierung auch vor geleastem load und erneutem acquire_lease. store prüft bereits; ein nach Erwerb ersetzter Lockname darf über die beiden anderen Methoden nicht weiter als gültige Lease erscheinen. Owner implementiert gezielten tatsächlichen Ersatzinode-/Child-Lock-RED und Korrektur. Keine neue Userfreigabe erforderlich; keine Behauptung gegen beliebige gleichzeitige Elternverzeichniswechsel.

Root-Vertrag für den folgenden tatsächlichen Schritt 2: `native-bootstrap-root-step-two-contract.md`, vom unabhängigen Bootstrap-Reviewer auf offensichtliche Vertragslücken geprüft. Public-Original unter eindeutig vom Statepfad abgeleitetem Suffix; Original vor State, Readback und Abschlussvalidierung; Wiederaufnahme aus Original ohne Ersatzsignatur; keine globale Atomarität aus zwei Dateien. Umsetzung folgt erst nach Lease-Abnahme.

Reader-Agent ergänzt den vorhandenen echten Custodian-Reopen-Pfad in seiner Fixture. Danach ist ein Release-Profilvergleich des unveränderten Ablaufs vorgesehen; aktueller freier Speicher wurde mit 74 GiB gemessen. Keine Release-Binary gebaut und kein Performancegewinn bereits behauptet. ClickUp aktualisiert: Kommentar1200650000076919.

## 13.09.2026, 13:09 Uhr – Runtime-Kosten unabhängig nachgerechnet

Identische isolierte ActualReservation-Probe mit zusätzlicher opt-in Runtimeprofilierung **1/1 GREEN in262,21s**, Transport203,325s. Root und Worker haben unabhängig denselben Abschnitt nach tatsächlicher Reservierung bis Desktopreturn ausgewertet:233 vollständige Acquires (129Admin/104Writer),228 Reopens. Disjunkte Binnenzeiten: Snapshot59,449s; DBopen8,660s; Truststore0,043s; select_current20,330s; Identitätsabschluss16,463s. Die überlagernde Acquiretotal105,021s wird nicht nochmals addiert. Eine dominierende DB-KDF-Ursache ist damit widerlegt für diesen Diagnosezustand; keine Rechtfertigung eines Guard-/Key-Caches.

Artefakte: `.superpowers/native-reader-runtime-profile-run-v1.log`, unabhängige `native-reader-runtime-profile-summary-v1.json` und `native-reader-runtime-profile-worker-summary-v1.json`. Rootparser `summarize-native-runtime-profile.py --resume-window` weist vollständiges Fenster und0unvollständige Spans aus. BinarySHA29991faa656bbd10e167bf8db323377e106809d37a615b99b026a7ccc1623e04 laut Worker; reine Laufnachweise weiterhin Reader-pending, keine vollständige Same-Job-Abnahme.

Nächster begrenzter Schritt ist die Quellenprüfung des tatsächlichen expliziten Wiederaufnahmewegs nach Sessionverlust: neue Host-/Custodian-Präsenz, derselbe dauerhaft gespeicherte Job, beobachteter Fehlercode und kontrollierter Restfortschritt. Weder unbeschränkte automatische Retries noch TTL-/Schutzabschwächung werden daraus abgeleitet.

## 13.09.2026, 13:00 Uhr – isolierter Resume-Lauf ausgewertet

Tatsächliche separate Reservierung und frischer DesktopHost: **1/1 GREEN in 258,22 s**, Transport-Resume 219,91 s. Root hat das Runlog unabhängig kompakt geparst: Admin129 + Writer104 = 233 Unwraps; insgesamt3523 zurückgekehrte Nicht-Watch-Aufrufe, maximal9ms zwischen Helperentry/return. Zwei erwartete Watchprozesse ohne Return im Snapshot. Diese Messung umfasst nicht Spawn/IPC-EOF/SQLCipher-KDF und ist kein Beweis gegen alle einzelnen Prozessblockaden. Keine TTLexit beobachtet.

Lange Phasen: publish1 41,78s, local30,38s, publish2 68,01s, import47,60s. Isolierter Zustand bleibt Reader-pending und unterscheidet sich von der fehlgeschlagenen v5-Same-Job-Gesamtprobe. Nächste unabhängige Untersuchungen: tatsächliche Runtime-/DB-Reopen-Kette und Prozesslauncher-/IPC-Kosten. Keine Schutzprüfung abgeschwächt und kein kompletter E2E erneut gestartet. ClickUp-Kommentar1200650000076848 dokumentiert Fortschritt und diese Grenzen. Gesamtes aktuelles `git diff --check` Exit0.

## 13.09.2026, 12:57 Uhr – Root-PoP akzeptiert, Resume gezielt diagnostiziert

Nativer Initial-Root-PoP-Adapter unabhängig geprüft: PASS im begrenzten Schnitt, native 4/4 (0,37 s), Bootstrap 53/53 (0,34 s), finaler Clippy grün (9,03 s). Bericht und Root-Review: `native-bootstrap-root-report.md`, `native-bootstrap-root-review.md`. Keine Schlüsselerzeugung, keine persistierte Bootstrap-Fortschaltung oder Produktionsabnahme. Ein Subagent inventarisiert den nächsten vorhandenen Hostvertrag.

Reader-Gesamtprobe v5 blieb nach 663,13 s innerhalb Resume erfolglos (Import/Replay bereits bei 361,99 s). Die frühere Synchronize-Lokalisierung ist zurückgezogen. Eine isolierte native Resume-Probe mit tatsächlicher Reservierung, fest begrenzten opt-in Phasen- und Helperereignissen sowie unveränderlicher Testbinary läuft. Kein TTL-Anheben und kein Erfolg aus Teilmarkern abgeleitet; Root hat bestehende HTTP-Zeitgrenzen separat untersucht, ohne daraus Netzwerkstillstände als ausgeschlossen darzustellen.

Stand: 2026-09-13, in Bearbeitung. Dieses Artefakt ist noch keine Stufe-5-Abnahme.

Korrektur nach Reader-v5: FAIL0/1 in663,13s. Zusätzliche kompilierte Stufenmarker
lokalisieren den Fehler innerhalb Resume, vor dessen Rückgabe und vor Synchronize.
Import/Replay361,99s→Fehler663,13s entspricht etwa301,14s. Die frühere v4-Zuordnung
„Resume erfolgreich, Synchronize verweigert“ ist nicht bestätigt und gilt nicht als
Nachweis. Kein vollständiger Reader-/TLS-/Evidence-Abschluss; gezielte Diagnose läuft.

Aktualisierung 12:38 Uhr: Reproduzierter Konkurrenzfehler im bestehenden Markergetter
behoben: Routingprüfung/Migration/Markerbytes in derselben Transaktion. Snapshot2/2,
Repository6/6, Transition4/4, aktuelle Writer-Root-Verbraucher2/2 und Clippy grün;
unabhängiger Root-Review PASS. Der weiterhin laufende native Reader-E2E stammt aus
einer zuvor kopierten Binary und ersetzt keinen nativen Nachweis dieses späteren Fixes.

Aktualisierung 12:26 Uhr: RTK-Ausnahme ausdrücklich erlaubt. Finale Writer-Root-Proben
2/2 und breiter Clippy grün, Root-Review PASS. Strikter Archivzeiger mit tatsächlichem
ACL-RED→GREEN1/1 plus Filesystem5/5, Decoder3/3, Profilregression5/5 und Clippy;
unabhängiger Root-Review PASS. Korrigierter SMB-Negativtest1/1 in0,54s plus Clippy
grün; eigener Mount ausgehängt und eigener Testserver nachprüfbar gestoppt.
Reader-Sitzungsdiagnose1/1 in87,10s bestätigt die separate Writer-TTL-Grenze und
Erholung durch tatsächlichen Host-Neustart. Vollständiger Same-Job-E2E wird mit
expliziten Neustarts zwischen langen Schritten erneut gebaut; Abschluss steht aus.

Aktualisierung 12:08 Uhr: Tatsächliches Mac-SMB-Backend verweigert den benötigten
Rust-Fullsync. Der ausdrücklich negative Nachweis besteht 1/1 in 0,85 s: kein
veröffentlichtes Grant, 633 lokale Originalbytes nach SQLCipher-Reopen identisch;
Scoped Clippy grün. Keine positive Netzarchivfreigabe. Letzte Writer-Root-Proben,
Archivzeiger-ACL-Regression und Reader-Sitzungsdiagnose warten aktuell auf die
Klärung des plötzlich fehlenden RTK-Werkzeugs. Statische Subagent-Arbeit läuft weiter.
Nachtrag zum SMB-Test: Unabhängiger Review beanstandete die drei `exists()`-Prüfungen,
die I/O-Fehler als Abwesenheit behandeln. Auf `try_exists().expect(...)` korrigiert;
erneuter Lauf und Clippy stehen aus. Die genannten grünen Gates gelten dem Vorfixstand.

Aktualisierung 11:43 Uhr: Gleicher nativer Auftrag erreicht inzwischen tatsächliche
Produkt-Worker-/OPFS-Löschung, exakten Beleg, Vault-Wiederöffnung und nativen
Import/Replay (353,78 s). Der Gesamtlauf scheitert danach an NativeSession
(657,94 s); vollständiger TLS-/Complete-/Evidence-Pfad bleibt offen.
Reader-Web-UI unabhängig PASS; reine Markerdiagnose mit 23 Tests, fokussiertem
Clippy und unabhängigem Source-Review PASS. Echter isolierter Mac-SMB3.1.1-Mount
mit Datei-/Directory-Fsync und Prozesssperre belegt. Tatsächlicher Serverausfall
liefert ENOTCONN nach 64,76 s und entfernt den Mount; nach explizitem Remount
sind Originalbytes identisch. Kein transparenter Reconnect oder bereits
integrierter nativer Writer-/SQLCipher-Queue-/Recovery-Nachweis.


Aktualisierung 11:28 Uhr: Native Reader-Desktop-Ausgabe und Bootstrap-Maschinenkorrektur
haben jeweils unabhängiges **PASS**. Reader-Weboberfläche: **53/53 und Typecheck
grün** nach reproduzierten Session-/Bridgewechsel- und verspäteten Antwortfehlern;
Browser und Review stehen noch aus. Der gleiche native Job erreicht tatsächliches
Started und den Servereffekt. Zwei anschließende Sessionfehler im Testaufbau
(152,52 s / 188,81 s) erfordern die bereits bestehende explizite Read-/Unlock-Sequenz
vor dem Export. Korrektur ist vorbereitet; noch kein vollständiger OPFS-/TLS-Rückweg.
Rein strukturelle Prepared-Markerdiagnose nach API-/Verhaltens-RED in Prüfung;
keine Reparatur- oder Abschlussautorität.


Aktueller zusätzlicher Servernachweis: Der reale native TLS-/Postgres-/S3-Test
mit Evidence-Vorschau, Abschluss und dauerhaftem Hash nach Host-Wiederöffnung
besteht **1/1 in 535,61 s** (`.superpowers/t13-native-server-evidence-host-final.log`).
Der zusätzlich geforderte vollständige Vergleich beider Eventtabellen besteht
inzwischen **1/1 in 535,83 s**, unabhängiger Re-Review **PASS**
(`.superpowers/t13-native-server-evidence-isolated-binary.log`). Zuvor endete ein
Lauf vor den neuen Assertions bei Resume mit `EA-DESTRUCTION-NATIVE-SESSION`
(333,17 s). Der erfolgreiche Gegenlauf verwendet eine separat kopierte Binary,
damit paralleles Cargo-Neulinken den erneut gestarteten Fixturehelfer nicht
verändern kann. Die alleinige Fehlerursache ist damit nicht bewiesen.
Die Reader-Pflicht bleibt offen; der Lauf ist kein vollständiger
Managed-Scope-Abschluss. Die eigens signierte Langlauf-Fixture ist kein Nachweis
unveränderter Standard-Zeitlimits.

Reader-Komponentensignierung inzwischen unabhängig akzeptiert: **29/29 Core,
2/2 echtes Chromium/OPFS, Reader-/WASM-Clippy, Build-WASM und Web-Typecheck grün**.
Vorher reproduzierte Flushbestätigungs- und Zwei-Zertifikatsfehler sind korrigiert;
der Re-Review der Zertifikatsbindung ist PASS. Exakte historische ETB-/AEAD-Bytes
bleiben bei erlaubtem Retry/Reopen erhalten. Dies beweist noch keine Zustellung
eines nativen Jobs in den Reader oder den Rückweg dieser Bytes über den Server.

Native Admin-Sperrdiagnose: **1/1 nativer Host in 35,70 s**, Desktop 116+4,
DTO-Drift 9, UI 43+3, TypeScript und Scoped Clippy grün. Aktuelle Admin-/Session-/
Policybindung, LocalPath-only und tatsächliche Kernel-Sperre sind geprüft; keine
Lockdateilöschung oder Reparaturbefugnis. Unabhängiger Schnittreview **PASS**.

Aktualisierung 10:53 Uhr: Die Aufnahme vorhandener nativer Archivkomponenten
besteht **3/3 native Tests in 41,35 s**, 13 weitere fokussierte Prüfungen und
beide Clippy-Gates; unabhängiger Review **PASS**. Dies ist exakte vorhandene
Komponentenbindung, keine Erstregistrierung, Aktivierung oder vollständige
Offline-/Netzmount-/Recovery-Integration. Nativer Reader-Originalexport besteht
**3/3 in 78,62 s** und beide Clippy-Gates; unabhängiger Review läuft. Der
zugehörige Reader-WASM-Adapter ist in Arbeit. Noch kein tatsächlich vollständiger
Desktop→Reader→Server-Pfad.

Aktualisierung 11:07 Uhr: Nativer Reader-Export unabhängig **PASS**. Neuer
WASM-Dateiadapter **2/2 Decoder, 1/1 echtes OPFS (12,27 s), 1/1 Routing,
Clippy, Build-WASM und Web-Typecheck grün**. Root-Desktop-Dateioberfläche
**45/45 UI/Bridge/Wizard (2,92 s)** und **1/1 Chromiumdownload (2,9 s)** mit
bytegenauem Vergleich aller drei Dateien grün. Der Browser verwendet ein
IPC-Double; keine tatsächliche Tauri-WebView-Speicherung oder native Autorität
wird daraus abgeleitet. Transportreview läuft; native Desktop-IPC sowie
separater tatsächlicher Same-Job-Reader/OPFS/TLS-Test in Arbeit.

Aktualisierung 11:17 Uhr: Native Desktop-Readerübergabe **2/2 Host in117,66s**,
IPC3, AltDestruction7, Registrierung5, DTO9 und Clippy grün; unabhängiger
Review läuft. Der zuvor ausstehende Desktop-Typecheck ist nach Emitter Exit0.
WASM-/UI-Transportreview ohne Finding. Echter Same-Job-OPFS/TLS-Durchlauf
läuft, noch kein positives Gesamtergebnis. Bootstrap-Maschinenmessung als
actualMac-RED0/1 reproduziert und auf bestehenden nativen Adapter umgestellt:
CLI16/16 + Clippy grün, Review ausstehend. Keine nachträgliche Identitätsbindung
alter Zeremonien; Hostschritte2–12 bleiben offen.

Die Arbeit wurde am 09.09. durch das Nutzungslimit der drei Subagents
unterbrochen. Root hat sie am 13.09. wieder aufgenommen. Die letzten beiden
TypeScript-Fehler der UI-Test-Doubles sind behoben; 85 fokussierte UI-Tests und
TypeScript bestehen erneut (`.superpowers/t13-evidence-writer-ui-review-final.log`).
Enthalten sind die Korrekturen der Evidence-Erfolgsanzeige bei nachgelagertem
Lesefehler, des Besitzes der Aktionssperre bei Bridge-Wechsel sowie der
Admin-Fläche ohne unzutreffenden Writer-Startup-Aufruf. Der zuletzt vollständig
beendete Evidence-Draft-Kernlauf besteht 6/6 in 60,88 s
(`.superpowers/evidence-draft-boundaries-green.log`). Native Evidence-Host- und
Netzarchivintegration sowie Gesamtprüfung und PR bleiben offen. Der aktuelle
Wiederaufnahmestand wird in [Progress.md](../../Progress.md) geführt.
Am 13.09. bestehen außerdem 130/130 Desktop-Lib-/IPC-/Registrierungsprüfungen
(`.superpowers/t13-evidence-writer-command-final.log`) und 5/5 Recovery-
Browserprüfungen in 4,9 s (`.superpowers/t13-recovery-native-capture-browser-green.log`).
Letztere zeigen die exakten gespeicherten öffentlichen V4-Berichtsdaten über
ein IPC-Double, einschließlich Wiederladen; sie ersetzen keinen nativen Lauf.

Zusätzliche native Evidence-Nachweise am 13.09.: Adapter zunächst 2/2 in
100,12 s (`.superpowers/native-evidence-adapter-green.log`); tatsächlicher
konfigurierter Desktop-Host 2/2 in 88,66 s inklusive Wiederöffnung und
Settingsänderungsverweigerung (`.superpowers/t13-native-evidence-host-first.log`).
Die fehlende 0021-Publikationsbindung bei reserviertem Evidence-Entwurf wurde
als fehlerhafte Recovery reproduziert und korrigiert. Die erweiterte
Job-/Autorisierungs-/Preflightbindung besteht 2/2 in 21,08 s, byteidentische
Prepared-Recovery 1/1 in 11,71 s (`.superpowers/native-evidence-recovery-green.log`,
`.superpowers/native-evidence-recovery-regression.log`). Scoped Clippy für
ea-admin/ea-writer/ea-destruction ist grün. Das unabhängige Hostreview fand
einen P2 zur Wiederverwendbarkeit nach abgewiesener Evidence-Aktion; Korrektur
und native Regression laufen. Erweiterte acht Native-Adapterproben und
Adapter-/Core-Review waren zu diesem Zwischenstand noch offen.

Aktualisierung 09:43 Uhr: Native-Adapter **8/8 in 403,72 s** abgeschlossen,
unabhängiges statisches Adapter-/Core-Review **PASS**. Host-P2 als echte
Regression reproduziert (**0/1 in 70,78 s**), Cache-Fix im Re-Review akzeptiert,
Host **3/3 in 167,05 s** grün (`.superpowers/t13-native-evidence-host-retry-green.log`).
Desktop erneut **130/130**, gemeinsamer Desktop-/Storage-Clippy grün in 29,68 s.
Der lokale Netzarchiv-Storage-Schnitt besteht **4 neue + 28 Regressionstests**,
unabhängiges Review PASS. Native Komponentenaktivierung, tatsächlicher Netzmount,
vollständiger Readerabschluss und Gesamtgate bleiben davon getrennt offen.

Read-only Writer-Lockdiagnose ebenfalls unabhängig mit PASS geprüft: finale
Projekttoolchain Rust 1.95, 15 Tests bestanden und ein gezielt im Unterprozess
gestarteter Hilfstest regulär ignoriert; Clippy Exit0. Kein Unlink, keine
Reparaturbefugnis und noch keine native Verwaltungsanbindung. Linux-ABIwerte
quellgeprüft, tatsächlicher Prozesslauf auf macOS; Windows nicht als unterstützt
abgenommen. Außerdem Verwaltungs-UI 133/133 in 7,94 s grün
(`.superpowers/t13-administration-ui-regression.log`). Tatsächlicher Serverhost
mit zusätzlichem Evidence-Abschluss läuft; Reader-Komponentenattestierung in
Arbeit. Beide sind noch keine neuen positiven End-to-End-Nachweise.

Auftrag: alle Unteraufgaben von [DRK-250](https://app.clickup.com/t/123zgebzv1k),
isolierter Worktree, Umsetzung und unabhängige Reviews mit Subagents, neuer PR.
Verbindlicher Vertrag ist der
[Stufe-5-Plan](../superpowers/plans/2026-08-13-einsatzarchiv-stage-5-administration-recovery.md)
mit seinen Global Constraints und den referenzierten Spezifikationen.

## Arbeitsstand

- Branch: `drk-250-stage-five`.
- Worktree: `.worktrees/drk-250-stage-five`.
- Frisch geholte Basis: `1e5e7deeeed661ad8b82b7213d5a3d6a4c147329`.
- Plankorrektur: `a141639`; unbelegte Haken in Tasks 8–14 entfernt und
  fehlende Integrationsflächen gegen den ausgelieferten Baum benannt.
- Der ursprüngliche Checkout und bestehende fremde Worktrees bleiben erhalten.

## Anforderungsnachweise

| Ticket | Umfang | Aktueller Nachweis |
|---|---|---|
| DRK-269 / T01 | Admin-Autorisierung, Root-Ziel, Einmaligkeit und Audit | Bestehende Lieferung; Gesamtprüfung offen |
| DRK-270 / T02 | Bootstrap, unabhängige Anchor, Recovery-Sperre | Bestehende Lieferung; Gesamtprüfung offen |
| DRK-271 / T03 | Operator, tatsächliches OS-Konto, Sitzung und Widerruf | Native Desktop-Sitzung/Entwurf/Writer/Wiederanlauf: 8 Prozesstests; Posture-Nachweisweg unabhängig akzeptiert, native16 +Krypto2 erneut grün; gesamte Desktop-Komposition läuft |
| DRK-272 / T04 | Policy, Registry, Widerruf, Lease und Clock Release | Bestehende Lieferung; Gesamtprüfung offen |
| DRK-273 / T05 | Writer-Wechsel und Restore-Blockade | Bestehende Lieferung; Gesamtprüfung offen |
| DRK-274 / T06 | Administration, Fingerprints, Policy, Go-live | UI vorhanden; produktive Host-Komposition offen |
| DRK-275 / T07 | Offline-Schlüsselquellen und CLI-Grammatik | PKCS#11-Sicherheits-/Operationsschnitt im dokumentierten OID-Profil unabhängig akzeptiert; nativer Grant-Pfad grün; Containerbau und echte Modulinitialisierung grün, Linux-Krypto-Endlauf noch offen |
| DRK-276 / T08 | Zwei-Personen-Re-grant bis zum erneuten Öffnen | Nachfolgergrenze und Zeitpersistenz vor HPKE korrigiert; unabhängiger Re-Review akzeptiert; Recovery67, Reader13, native CLI, PostgreSQL/S3 und echter OPFS-Browserlauf grün |
| DRK-277 / T09 | Vollständiger Recovery-Test, Inventar, dauerhafter Status | Tatsächlicher Ubuntu-Restore, CLI-Lauf und neuer 13-Medien-Lauf grün; Source-Import/Reopen/Go-live mit aktuellem Zeitfloor unabhängig geprüft; dauerhafte Fehlerberichte und Guided-/Batch-Medienvergleich geprüft; Produktassistent in Arbeit |
| DRK-278 / T10 | Nachtrag durch normale Writer-Pipeline | Zugewiesener Implementierungsschnitt unabhängig akzeptiert, 13 Writer-/Reader-Tests durch Root erneut grün; vollständige Quellsicherung und native Startkomposition bleiben Integrationsaufgaben |
| DRK-279 / T11 | Vernichtungsautorisierung, Datenschutz-Gate und Zustände | 42 fokussierte Tests; unabhängiger Re-Review der aktuellen Registry-/Katalog-/Zeitgrenzen akzeptiert; physische Ausführung gehört zu T12 |
| DRK-280 / T12 | Dauerhafte Stubs, Replikattestierungen, Resume und Evidence | Lokaler Executor/Purge und Server in Arbeit; Reader-Review fand wiederverwendbaren abgelaufenen Proof, korrigiert: 20 Cache- und 2 echte OPFS-Tests grün; Gesamtattestierung offen |
| DRK-281 / T13 | Produktiver Vernichtungsassistent mit exakter Statussprache | Echter nativer Desktop-Port mit separaten Admin-/Writer-Identitäten: Import/Start/Resume nach Wiederöffnung grün; 5 Browserprüfungen, Stub-/Nachweisanzeige und TypeScript grün; externer Transport und Gesamtabnahme offen |
| DRK-282 / T14 | Kumulatives Stufe-5-Gate und 19 Ledgerzeilen | Umsetzung und Abnahme offen |

Zusätzliche verbindliche Global Constraints bleiben Bestandteil der Lieferung:
Reader-KEM-Escrow beim Enrollment, getrennte Zwei-Approver-Öffnungszeremonie mit
gebundenem Transport-Key, gemeinsamer v1.1-Cutover, signierte dauerhafte
Einmal-Quittung für Stale Registry sowie administrative Auflösung/Diagnose der
widersprüchlichen Abschlussmarke und verwaister Sperren.

Die Stale-Registry-Quittung besitzt einen dauerhaften, atomaren Einmalverbrauch
und einen tatsächlichen Desktop-Adapter. Zwei unabhängige Review-Proben wurden
korrigiert und erneut bestanden, ebenso alle 18 Stale-Tests; Slice-Commit
`be2abfe`. Die Desktop-Startkomposition verbindet jetzt explizite öffentliche
Konfiguration und unabhängigen Anchor mit nativer Anmeldung, aktueller
Rollenprüfung und Sperrbeobachtung. Entwurf, Verwerfen und Stammdaten sind
angebunden. Der native Writer schließt einen bestätigten Eintrag im echten
Dateiarchiv ab, veröffentlicht eine normale Berichtigung unter Erhalt des
Originals und verweigert geänderte Eingaben. Öffentlicher Kettenfortschritt
nach authentischen Stubs ist separat vom Vernichtungsabschluss angebunden.
Eine dauerhafte SQLCipher-Commitablage ist geprüft; ihre vollständige native
Netzbackend-Anbindung steht noch aus. Verwaltungs-, Sync-, Export-
und weitere Wege bleiben offen. Die native Stale-Registry-Auswahl verwendet
inzwischen einen getrennten, auf Writer begrenzten Kontext. Dreizehn native Tests
belegen Eintrag und Nachtrag nach Ablauf mit getrennter Bestätigung sowie
Sperrregeln, Widerruf während der Präsenzabfrage und eine neu verifizierte
Zeitgrenze bei offener Vorschau. Der unabhängige Review fand den Zeitfehler;
die unveränderten Gegenproben sind nach dem Fix grün. Auch die zusätzliche
Prüfung einer Zeitänderung während des Dialogs ist für aktuelle und abgelaufene
Writer-Kontexte grün; der unabhängige Re-Review akzeptiert diesen Schnitt.

Der reale Posture-Messadapter bestätigt auf diesem Host FileVault. Nicht
automatisch belegbare Voraussetzungen bleiben in den Rohwerten `Unknown`.
Ein eng gebundener Admin-Nachweis kann diese Voraussetzungen dokumentieren;
Installation, Konto, Gerät, OS-Build, aktueller HEAD und Ablauf werden geprüft.
Gemessene Fehler bleiben zwingende Sperren. Der unabhängige Review dieses
Schnitts ist abgeschlossen; dies ist keine produktive Plattformabnahme.

Das konkrete neue Escrow-Profil liegt unter
`docs/superpowers/specs/2026-09-08-einsatzarchiv-reader-key-escrow-profile.md`.
Die angefragte Profilfreigabe ist noch ausstehend; die neuen Signaturfamilien
sind deshalb noch nicht implementiert. Die übrige Umsetzung läuft weiter.

## Bisher ausgeführte Prüfungen

Diese Baseline-Prüfungen belegen vorhandene Funktionen, nicht die vollständige
Umsetzung der oben offenen Anforderungen.

| Befehl | Ergebnis | Rohbeleg im Worktree |
|---|---|---|
| `pnpm install --frozen-lockfile --store-dir .superpowers/pnpm-store` | Exit 0; 7,6 s | Tool-Ausgabe dieser Sitzung |
| `cargo test --locked -p xtask --test stage_gate` | 18 bestanden, 0 fehlgeschlagen, 0 ignoriert | `.superpowers/baseline-stage-gate.log` |
| `cargo test --locked -p ea-recovery` | 61 bestanden, 0 fehlgeschlagen, 0 ignoriert | `.superpowers/baseline-recovery.log` |
| `cargo test --locked -p xtask` nach Plankorrektur | 114 bestanden, 0 fehlgeschlagen, 0 ignoriert | `.superpowers/plan-correction-xtask.log` |
| `cargo test --locked -p einsatzarchiv-cli --test operator process_native::posture` | 2 bestanden, 0 fehlgeschlagen/ignoriert, 67 gefiltert; jede Fail-/Unknown-Anforderung, Providerfehler und Änderung nach nativer Präsenz sperren tatsächliche Sitzung | `.superpowers/posture-runtime-green.log` |
| `cargo test --locked -p einsatzarchiv-cli --test operator process_native::fixture_cli_native_login_succeeds_and_persists_a_real_signed_login_across_restart -- --exact` | 1 bestanden, 0 fehlgeschlagen/ignoriert, 68 gefiltert; bestehender nativer Login samt signiertem Audit und Neustart | `.superpowers/posture-native-control-green.log` |
| `cargo test --locked -p ea-key-provider --test device_posture -- --nocapture` | 7 bestanden; tatsächlicher Hostzustand samt Unknown-Feldern | `.superpowers/posture-host-measurement.log` |
| `cargo test --locked -p ea-crypto` nach Token-Kryptoanschlüssen | 83 Tests und 5 Doctests bestanden; vor späterer Empfänger-Trait-Generalisierung | `.superpowers/token-crypto-regression.log` |
| `cargo test --locked -p ea-recovery --features pkcs11-fixture --test pkcs11_provider` mit frisch gebauter Fixture | 4 bestanden, 0 ignoriert; echte HPKE-/Signatur-/Resolver-/Archivpfade, Nicht-Exportierbarkeit, fremde Anmeldung, Mehrdeutigkeit und veränderte Public-Key-Zuordnung | `.superpowers/pkcs11-fresh-product-green.log` |
| `cargo test --locked -p einsatzarchiv-cli --features pkcs11-fixture --test operator actual_grant_command_uses_nonexporting_pkcs11_recovery_and_hga_keys -- --nocapture` | 1 bestanden, 70 gefiltert; getrennte Tokenkeys, native Admin-Sitzung, Audit, unverändertes Original und Reader-Prüfung | `.superpowers/pkcs11-native-cli.log` |
| `bash scripts/prepare-pkcs11-fixture.sh` | Frischer isolierter SoftHSM-2.7-Bau und Testvektor-Provisionierung bestanden; kein Systeminstall | `.superpowers/pkcs11-fresh-fixture.log` |
| `cargo test --locked -p einsatzarchiv-cli --features desktop-fixture --test operator native_desktop_` vor Writer-Anschluss | 5 bestanden; native Anmeldung/Audit, Widerruf, Sperre während Dialog, verspätet erfolgreicher Dialog, Entwurf/Reopen/Verwerfen | `.superpowers/desktop-native-green.log` |
| `cargo test --locked -p einsatzarchiv-cli --features desktop-fixture --test operator native_desktop_writer_publishes` | 1 bestanden; exakte Vorschau nach erneuter Präsenz, normale signierte Veröffentlichung, geänderte Eingabe verweigert | `.superpowers/desktop-native-writer-green.log` |
| Derselbe native Writer-Test mit Berichtigung erweitert | 1 bestanden; Incident seq1, Amendment seq2, Vollverifikation und byteidentisches Original | `.superpowers/desktop-native-amendment.log` |
| `cargo test --locked -p ea-admin --test operator_runtime` | 12 bestanden; enger öffentlicher Kettenfortschritt mit recipientlosem Stub, getrennt von dessen Abschlussstatus; getrennte Lücke verweigert | `.superpowers/operator-public-progress-green.log` |
| `cargo test --locked -p ea-archive-fs --test sqlcipher_commit --lib --test controlled_network_profile` | 2 +3 +4 bestanden; tatsächliche SQLCipher-Ablage, Neustart, konkurrierende Verbindungen, Grenzen und Ruheortmessung | `.superpowers/sqlcipher-commit-green.log` |
| `cargo clippy --locked -p ea-archive-fs --lib --tests -- -D warnings` | Exit 0 nach Commitablage | `.superpowers/sqlcipher-commit-clippy.log` |
| `cargo test --locked -p einsatzarchiv-cli --features desktop-fixture --test operator native_key_provider_distinguishes` | 1 bestanden; vorübergehender Fehler und fehlerhafte Metadaten sind keine Schlüssellöschung; bestätigtes Fehlen separat | `.superpowers/native-key-absence-green.log` |
| `cargo test --locked -p einsatzarchiv-cli --features desktop-fixture --test operator process_native::desktop` | 8 bestanden, 84 gefiltert; native Sperren, Draft, Incident/Berichtigung und exakter Wiederanlauf nach tatsächlicher/unklarer Schlüssellöschung | `.superpowers/native-desktop-combined-final.log` |
| `cargo test --locked -p ea-recovery --test fs_source` | 7 bestanden; operative Quelle schließt Staging aus, forensische Quelle erhält es | `.superpowers/committed-source-final.log` |
| `cargo test --locked -p ea-reader --test destruction_cache` nach unabhängigem Reviewfix | 20 bestanden; erneut aktuelle Autorität vor Löschung, bekannte Zeit und neue Sperrung berücksichtigt | `.superpowers/reader-destruction-expiry-green.log` |
| `cargo test --locked -p ea-reader-wasm --target wasm32-unknown-unknown --test destruction_cache_browser` | 2 bestanden im echten Chromium/OPFS; produktive Exporte, tatsächliches Entfernen und Wiederöffnen | `.superpowers/reader-destruction-review-browser.log` |
| `cargo test --locked -p ea-desktop --lib --test writer_commands` nach Entwurfs-/Stammdatentor | 94 +5 bestanden; weitere Writer-Integration danach noch separat zu prüfen | `.superpowers/desktop-session-regression.log` |
| Unabhängiger Posture-Review: natives `process_native::posture` und `posture_crypto` | 16 +2 bestanden; dokumentierte Unknown-Werte, echte getrennte Testgeräte, HEAD-Wechsel, Ablauf und Manipulationen | `.superpowers/posture-root-review-native.log`, `.superpowers/posture-root-review-crypto.log` |
| `pnpm --dir apps/desktop exec vitest run src/app/AppShell.test.tsx` | 23 bestanden; explizite native Anmeldung und Sperrereignis während ausstehender Loginantwort | `.superpowers/desktop-login-ui-green.log` |
| `pnpm --dir apps/desktop exec tsc --noEmit` | Exit 0 nach Loginanschluss | `.superpowers/desktop-login-typecheck.log` |
| `cargo test --locked -p einsatzarchiv-cli --features desktop-fixture --test operator process_native::desktop` nach Stale-Auswahl und Dialogrennen | 11 bestanden, 0 fehlgeschlagen/ignoriert, 90 gefiltert; 16,19 s | `.superpowers/native-stale-presence-green.log` |
| `cargo test --locked -p ea-trust --test stale_writer_registry` | 5 bestanden; aktueller Pin, Policy, Sequenzgrenze, Nachfolger und fehlgeschlagener CAS | `.superpowers/stale-writer-context-guards.log` |
| `cargo test --locked -p ea-operator --test session_contract` | 17 bestanden; Writer-Purpose-/Konto-/Rollenbindung | `.superpowers/stale-writer-operator-green.log` |
| Writer R62 sowie Amendment/Grant/Offline nach versiegelter Writer-Sicht | 19 +20 bestanden | `.superpowers/stale-writer-pipeline-green.log`, `.superpowers/stale-writer-pipeline-regression.log` |
| Offline-Attestation und Reader-Cache nach Zeit-/Geräteprüfung | 16 +22 bestanden; tatsächliche Entfernung nach Backupfrist akzeptiert, zukünftige Ausführung verweigert | `.superpowers/destruction-backup-expiry-green.log`, `.superpowers/destruction-backup-expiry-reader.log` |
| Reader-Custody nach Prüfung der kanonischen Hashreihenfolge | 21 bestanden; falsche Reihenfolge und Duplikate verweigert | `.superpowers/reader-custody-order-green.log` |
| Tatsächlicher Ubuntu24.04-Zielkontext im isolierten Container | 1 bestanden, 89 gefiltert; 0,63 s; eigene native Schlüssel-/Maschinenidentität; Debian wurde zuvor korrekt von OS-Build-Zulassung verweigert | `.superpowers/t9-ubuntu-context-export.log` |

Die beiden nativen Prozessprüfungen liefen nach bestätigter Freigabe außerhalb
der Dateisandbox: ihr bestehender isolierter Testhelfer benötigt Schreibzugriff
auf die geerbte Pipe `/dev/fd/3`. Produktive Schlüssel und OS-Einstellungen wurden
dabei nicht verwendet oder geändert. Die Zwischenläufe enthalten drei
Dead-Code-Warnungen aus der parallel umgebauten Grant-CLI; die strikten Endgates
sind noch offen.

Die bestehende native Posture-Suite ist nach erneuter Präsenzprüfung mit
16/16 grün (`.superpowers/native-stale-posture-regression.log`), ebenso die
95 Trust-/Operator-Doctests und NativeHost/CLI-Clippy mit `-D warnings`
(`.superpowers/stale-writer-doc-guards.log`, `.superpowers/native-stale-clippy.log`).
Der unabhängige T12-Review bestätigte einen Staging-Fehler: Ein erneut
eingeschleustes Original sperrte weder Evidence-Vorschau noch Prepared-Recovery.
Die korrigierte Prüfung erfasst jetzt den tatsächlichen verwalteten Dateibestand
einschließlich Staging. Root hat die Änderung gelesen und beide Gegenproben
erneut bestanden (2/2,11,55s, `.superpowers/t12-root-staging-final-green.log`).
Der lokale Executor-/Evidence-Schnitt ist damit begrenzt akzeptiert; die gesamte
T12-Integration bleibt offen.

Der echte Ubuntu-Restoretest ist nach reproduziertem
`EA-RECOVERY-TEST-INCOMPLETE` grün (1/1,24,75s,
`.superpowers/t9-ubuntu-portable-restore-green.log`). Der vollständige
Recovery-Lebenszyklus hat 12 Medien aus allen 9 Rollen geprüft und den
dauerhaften Abschluss bytegleich wieder geöffnet (1/1,198,42s,
`.superpowers/t9-ubuntu-full-recovery-final.log`). Root hat anschließend einen
Zeitfehler im signierten Ergebnis bestätigt: Abschlusszeit und Laufstart waren
identisch. Der Fix wählt nach dem Medienlauf erneut aktuelle Autorität und Zeit.
Die Wiederholung mit expliziter Abschlusszeit-Prüfung ist grün (1/1,191,10s,
`.superpowers/t9-ubuntu-full-recovery-timing-green.log`). Root hat die Metadaten
des neu exportierten signierten Berichts unabhängig gelesen: Laufzeitpunkt
1788937215506, Abschluss 1788937373733, Differenz 158227 ms. Das Artefakt
`.superpowers/t9-ubuntu-completed-recovery-v2.cbor` hat SHA256
`e7e6b2660eb14451006ed2dd239c3ab15c81ec3ba9cc3145541df2d21d01d5b9`.
Alte Berichte bleiben erhalten. Source-Import und aktuelle Freigabe sind noch
in Arbeit. Native Zeitgrenzen-Gegenproben2/2, Desktop13/13 und
Posture16/16 sind nach dem Vorschau-Fix grün
(`.superpowers/native-time-floor-root-green.log`,
`.superpowers/native-time-floor-regression.log`,
`.superpowers/native-time-floor-posture.log`).

Die vollständigen Endstand-Gates, adversariellen Reviews und PR-/CI-Belege
werden nach der Umsetzung ergänzt. `verify:quick` ersetzt weder Browser-E2E
noch das separate Stufe-5-Gate.

## Abgrenzung zu Stufe 7

Native Minimum-/Maximum-Releasefälle, quartalsweise organisatorische Übungen,
die tatsächliche externe Datenschutzfreigabe und die Verwahrung produktiver
Schlüssel bleiben Stufe 7. Fehlende Softwareimplementierung wird dadurch nicht
aus dem Stufe-5-Auftrag entfernt. Ledgerstatus wird erst nach vollständiger
Stufe-5-Evidenz auf `implemented` oder `integrated` gesetzt.

## Ergänzte Statusanzeige

Die T13-Statuskomponente übernimmt die fünf Werte aus dem Rust-Kern und zeigt
die vorgegebene deutsche Kopie sowie die Grenze des verwalteten Umfangs.
Status, Assistent, IPC-Brücke, Kontraktdisziplin und Shell bestanden zusammen89
Prüfungen sowie TypeScript. Auswahl gespeicherter Vorgänge, genaue Autorisierungsbytes,
Vorbericht, zwei Approver, Repliken/Attestierungen/UTC-Backupfristen und explizite
Startbestätigung sind umgesetzt. Host-Rollen-/IPC-/Registrierungsprüfungen:
106 GREEN vor der neuesten Stub-Erweiterung. Der tatsächliche native Desktop-Port
bestand Import, Start, vollständige Wiederöffnung, Resume und signierte lokale
Attestierung in52,70s (`.superpowers/t13-real-native-port-green.log`). Nicht
bestätigte Repliken bleiben offen. Fünf Browserprüfungen bestanden einschließlich
gemessener Header-/Tabellengrenzen bei640 Pixeln
(`.superpowers/t13-header-overlap-green.log`); ihre IPC-Antworten sind Testdoubles.
Die ergänzte Anzeige tatsächlich verifizierter Stub-/Evidence-Hashes hatte fünf
fachliche REDs und besteht danach37 fokussierte UI-/Vertragsprüfungen sowie
TypeScript (`.superpowers/t13-stub-evidence-view-{red,green}.log`). Ein vollständiger
Vernichtungsstatus ersetzt keinen finalisierten Writer-Nachweis. Produktiver
Servertransport, Writer-Finalisierung und unabhängige gesamte
Desktop-Abnahme bleiben offen.

## Zusätzliche native Recovery-Evidenz

Der vollständige tatsächliche Ubuntu-CLI-Restore bestand in204,25s; signierte
Ausgabe `.superpowers/t9-ubuntu-completed-cli-recovery.cbor`, SHA-256
`db2de6492d841455c0130eb08db881c5a3e2c72104942c036aa0ca0f2ebcc3a0`.
Der danach separat erzeugte v3-Kontext absolvierte13 getrennte Medien
(zwölf private Backupmedien plus echter nativer Admin-Slot) in226,19s;
signierter Bericht `.superpowers/t9-ubuntu-completed-recovery-v3.cbor`, SHA-256
`5d4144f6ac52eec1a71c7cc2a46bd7d7fa45f5768c955d5d7af62a5fa326ea5d`.
Beide Dateien sind mit0600 gesichert; bisherige v2-Artefakte bleiben unverändert.

Der unabhängige T9-Review reproduzierte einen gehaltenen Proof, der einen neu
persistierten, authentisch signierten Zeitfloor ignorierte. Derselbe Gegenbeleg
ist nach enger Wiederöffnungskorrektur unabhängig GREEN16,44s; die volle native
Source-/Import-/Reopen-/CLI-/GoLive-Positivkontrolle ist GREEN27,22s.
Begrenzter Review: `.superpowers/sdd/2026-08-13-einsatzarchiv-stage-5-administration-recovery/task-9-source-completion-root-review.md`.

Der v3-Bericht mit13 Medien wurde unter der erweiterten Datenbankversion erneut
eingelesen und für die frisch erzeugte Go-live-Sicht verwendet:1/1 GREEN36,69s,
`.superpowers/task-9-source-import-v3-callback-green.log`. Die signierte historische
Source bleibt unverändert; bekannte Migrationspräfixe werden beim Restore
schreibgeschützt geprüft. Sechs Präfix-/Schema-Gegenproben bestanden in1,02s.
Der PKCS11-Medienkernel bestand echte Signatur-/KEM-Prüfungen und falsche PINs
in2,87s; dies belegt noch keinen vollständigen nativen CLI-PKCS11-Recovery-Lauf.


## Native Import- und Administrationsergänzung

Der externe Import signierter Repliknachweise erreicht jetzt den tatsächlichen
Desktop-Port und denselben nativen Kern. Ein echter Prozesslauf bestätigt
`pendingBackupExpiry`, bytegleiche Wiederöffnung und Ablehnung veränderter
Signaturen ohne Änderung des zuletzt verifizierten Zustands:1/1 GREEN65,77s,
`.superpowers/t13-native-progress-import-green.log`. Der Host prüft Rolle,
ID/Preflighthash und vor jeder Kernarbeit höchstens256 Dateien, je4MiB und
insgesamt16MiB; doppelte Eingaben zählen zur Eingangsgrenze. Neue
Registrierungsprüfungen zeigten vorher2/5 RED. Der anschließende Hostlauf
besteht97 Lib-,4 Admin-,5 Destruction- und5 Registrierungsprüfungen
(`.superpowers/t13-progress-import-host-final-green.log`). Desktop und
UI-Kontrakte bestehen Clippy mit `-D warnings`
(`.superpowers/t13-progress-import-clippy.log`).

Der Import und die erneute Autorisierung sind im tatsächlichen Browser mit
exakten Dateibytes bedienbar. Sechs Browserfälle bestanden in4,6s
(`.superpowers/t13-progress-browser-green.log`); die Browser-IPC-Antworten
bleiben Testdoubles. Ein nachfolgender unabhängiger UI-Vertragsreview fand
zu enge Grenzen für Sequenz0, mindestens2 Approver und verschiedene Zielhashes
mit gleicher Sequenz. Vier Produkt-Regressionstests bestätigen diese Fehler
(`.superpowers/t13-review-contract-red.log`); die unveränderten Fälle und
übrigen fokussierten Prüfungen sind danach47/47 samt TypeScript grün
(`.superpowers/t13-review-contract-green.log`). Die tatsächliche native
JSON-Ausgabe wurde zusätzlich direkt vom unveränderten TS-Validator angenommen
(1/1,115ms, `.superpowers/t13-native-typescript-contract-green.log`);
Erzeugerprozess1/1 GREEN66,02s (`.superpowers/t13-native-wire-artifact-green.log`).
Öffentliche Rohantwort: `.superpowers/t13-native-view.json`. Der native Rust-Prozessbeleg allein hatte diese TS-Abweichung nicht erfasst.

Die Administration zeigt jetzt getrennt die Zielausgabe und die spätere
Registry-Aktivierung, einschließlich des jeweils tatsächlich verglichenen
Fingerprints und einer exakten gespeicherten Verknüpfung. `TargetPublished`
behauptet keine Registry-Aktivierung. Die gesamte Desktop-UI-Suite bestand
188 Prüfungen (`.superpowers/administration-desktop-ui-suite.log`, vor den
nachfolgenden Import-Reviewkorrekturen). Der getrennte native Root-Transport
ist durch den Agenten mit8/8 Prüfungen belegt
(`.superpowers/administration-transport-green.log`), einschließlich tatsächlicher
Dateischreibfehler, Restart und unverändertem Replay. Vollständige native
Publikation, Host-Konfiguration und die übrigen Verwaltungsmethoden bleiben offen.

## Recovery-Fehler und geführte Medien

Ein tatsächlicher Ubuntu-Lauf mit13 fehlenden Medien schreibt einen signierten
dauerhaften Fehlerbericht, erhält den bisherigen erfolgreichen Bericht und
öffnet beide bytegleich wieder:1/1 GREEN39,68s nach fachlichem RED22,10s
(`.superpowers/t9-ubuntu-native-failure-{red,green}.log`). Der Vergleich von
geführter Eingabe und Stapellauf bestätigt identische Medienfakten und die
Bindung der tatsächlichen RunID als signierte testId. Der zweite Fall dieses
Zwischenlaufs scheiterte zunächst an einer nicht erreichten Provider-Testpause
(`.superpowers/t9-ubuntu-guided-green.log`,1/2 bestanden). Der Testhelfer las
textuelle COSE-Headerlabels falsch; seine direkte Gegenprobe ist RED/GREEN.
Danach besteht der unveränderte tatsächliche Abbruchfall sowohl während des
Wartens als auch während der Provider-Signatur:1/1 GREEN101,47s
(`.superpowers/t9-ubuntu-guided-abort-final.log`). Dabei wird kein Ergebnisbericht
und keine Erfolgsmeldung dauerhaft erzeugt. Langlauf, übrige Fehlerfälle und
vollständige Desktop-Komposition sind noch in Arbeit.

Die CLI-Fehlerexporte sind nun mit tatsächlichen Prozessen nachgewiesen:
`FailureStatus` las den signierten Fehler zunächst ohne Export (RED8,66s),
exportiert ihn jetzt nach Reopen (GREEN14,54s). `RestoreRun` exportiert auch
bei tatsächlich fehlenden Medien seinen signierten Failed-Bericht
(RED102,25s → GREEN95,98s); der Exit bleibt `Incomplete`. Logs:
`.superpowers/t9-ubuntu-cli-failure-status-{red,green}.log` und
`.superpowers/t9-ubuntu-cli-failure-export-{red,green}.log`.

Die Aktionsablauf-Gegenprobe bleibt grün36,06s
(`.superpowers/t9-ubuntu-guided-action-expiry.log`). Ein tatsächlicher
305s-Eingabewait scheiterte zuerst an `EA-OPERATOR-RUNTIME-EXPIRED`331,50s
und nach frischem Runtime-Reopen an `EA-OPERATOR-NATIVE-LOCKED`335,48s.
Dies sind zwei getrennte Befunde, kein Nachweis zur noch unveränderten
Completion-Gesamtzeitgrenze. Die Spezifikation (`v0-1-design.md`:256)
verlangt fünf Minuten **Inaktivität**. Eine einzelne inaktive305s-Wartephase
bleibt daher negativ; die nächste positive Langlaufprobe trennt zwei155s-
Wartephasen durch tatsächliche neue native Reauth. Coverage/Polling darf
Inaktivität nicht zurücksetzen, alte Proof-/Aktionsfristen bleiben unverändert.

Desktop-Recovery-Komposition ist begonnen: öffentliche DTOs und generierter
TS-Kontrakt, geschlossene Konfiguration, ein mit Operation/Run/Request
gebundener Eingabeplatz, separate öffentliche Beobachtungen und terminale
Ergebnisse. Acht Warte-/Cancel-/Epoch-/Konfigurationsprüfungen sind grün
(0,11s, `.superpowers/t13-recovery-host-progress-green.log`), drei Rollen-
und Eingabeprüfungen nach jeweils beobachtetem RED ebenfalls
(`.superpowers/t13-recovery-commands-green.log`). Diese Proben belegen die
Hostgrenzen; native Ressourcen, IPC-Registrierung und fertige GUI sind hiermit
noch nicht als geliefert ausgewiesen. Die tatsächliche native Workerprobe
wird separat ergänzt.


## Recovery-Desktop: Worker, IPC und Bedienung (2026-09-09)

Die native Recovery-Konfiguration wird tatsächlich beim Start geladen. Ein
separater Worker besitzt den wiedergeöffneten OperatorRuntime und verwendet den
bestehenden Source-Restore/Guided-Test. Nach erfolgreichem Commit übernimmt er
das verifizierte dauerhafte Ergebnis; späteres unabhängiges Lesen öffnet die
signierte Ablage unter frischen Zulassungsprüfungen erneut. Vier Recovery-Kommandos sind in Handler, Namensliste,
ACL und Buildmanifest registriert; ihre Eingabe enthält nur korrelierte IDs und
die ausdrückliche Medienwahl. Die Rolle wird vor Eingabevalidierung und Ressourcen
geprüft. Relative private Medienpfade werden gegen die Mediendatei aufgelöst,
absolute Pfade und Tokenidentität bleiben unverändert.

Der tatsächliche native SameMachine-Negativlauf ist nach dem fehlenden
Launch-Konfigurationspfad RED9,57s jetzt GREEN17,54s (Build26,48s,
`.superpowers/t13-recovery-native-wire-green.log`). Der native Kern verweigert
mit `EA-RECOVERY-TEST-MACHINE`; keine Wiederherstellungsdatei, Observation,
Erfolgs- oder Fehlerbericht wird erzeugt. Die tatsächlich produzierte öffentliche
JSON-Antwort in `.superpowers/t13-native-recovery-view.json` besteht zusätzlich
den Produktions-TS-Validator (1/1,124ms,
`.superpowers/t13-native-recovery-typescript-green.log`). Dies ist ein nativer
Negativnachweis, kein positiver Restore auf einer fremden Maschine.

Zehn Runtime-/Mailbox-/Pfadtests bestehen nach ihren jeweiligen RED-Proben;
Abbruch hält den Workerplatz bis zur tatsächlichen Rückkehr besetzt. Der gesamte
Desktop-Host besteht108 Lib-,4 Admin-,5 Destruction-,3 Recovery- und5
Registrierungsprüfungen (`.superpowers/t13-recovery-host-full-green.log`).
Clippy für Desktop/UI-Kontrakte besteht mit `-D warnings` in13,09s
(`.superpowers/t13-recovery-host-clippy.log`, vor der anschließenden reinen
DTO-Testergänzung). Die vollständige Desktop-UI-Suite besteht211 Tests und
TypeScript (`.superpowers/t13-recovery-ui-full.log`). Zwei zusätzliche
RED→GREEN-Fälle sichern die ausdrückliche neue native Anmeldung bei abgelaufenem
Host-Lesenachweis; weder alte Proof-Frist noch bestehende RunID werden verändert.

Der gebaute Browser besteht3/3 in3,5s
(`.superpowers/t13-recovery-browser.log`): Tastaturwahl genau eines Mediums,
Wiederladen, explizit fehlendes Medium,640px-Darstellung und erreichbarer Abbruch
bei ausstehender Antwort. Späte Antworten öffnen die Eingabe nicht erneut.
Diese Browser-IPC-Antworten sind Testdoubles. Bild:
`apps/desktop/test-results/recovery-missing-medium-st-faf44-s-input-within-the-viewport/recovery-narrow.png`.

Die fehlende feste Gesamtzeitgrenze ist inzwischen getrennt reproduziert:
Nach dem Watch-Inaktivitätsfix läuft der aktive Zwei-mal155s-Test mit frischen
nativen Anmeldungen bis `EA-RECOVERY-TEST-SOURCE` nach717,31s
(`.superpowers/t9-ubuntu-active-long-completion-cap-red.log`). Die separate echte
305s-Inaktivitätsprobe besteht333,39s, erhält Berichte unverändert und verhindert
Wiederbelebung der alten Watch (`.superpowers/t9-ubuntu-inactive-wait-green.log`).
Nur die beiden pauschalen Gesamtdauer-Prädikate in Completion/Failure wurden
anschließend entfernt; der unveränderte aktive Gegenlauf besteht in714,81s
(`.superpowers/t9-ubuntu-active-long-green.log`) mit allen Medien und dauerhaft
signiertem Abschluss. Export: `.superpowers/t9-completed-recovery-long.cbor`.

Offen bleiben der vollständige native positive Desktop-/Fremdmaschinenlauf,
seine Persistenz-/Cancel-Grenzen und der tatsächliche lange Host-Anmeldewechsel.
Die zusätzliche Race zwischen Report-Commit und nachfolgender Abbruchprüfung
ist inzwischen tatsächlich reproduziert: native SQLCipher-WAL-Gegenprobe RED
nach122,98s (`.superpowers/t9-ubuntu-commit-cancel-red.log`). Eine unabhängige
Verbindung sieht den dauerhaft gespeicherten Fehlerbericht, während der Aufruf
anschließend `EA-RECOVERY-TEST-CANCELLED` meldet. Der korrigierte Gegenlauf besteht
131,08s einschließlich bytegleichem Reopen
(`.superpowers/t9-ubuntu-commit-cancel-green.log`). Zulassungsprüfungen vor und
innerhalb der Transaktion bleiben bestehen; ein erfolgreicher Commit wird durch
nachfolgenden Abbruch nicht in ein anderes Ergebnis umgedeutet.

Der Host zeigt während einer Abbruchanforderung ausdrücklich Zwischenphase7
(„Abbruch wird abgeschlossen“), hält den Workerplatz belegt und pollt weiter.
Erst die tatsächliche Rückkehr liefert Cancelled oder den bereits dauerhaft
geschriebenen Bericht. Runtime-RED→12/12 GREEN, UI-/Vertrags-RED→13/13 GREEN
mit TypeScript; gebauter Browser4/4 in4,6s. Logs:
`.superpowers/t13-recovery-terminal-mailbox-green.log`,
`.superpowers/t13-recovery-cancel-pending-ui-green.log` und
`.superpowers/t13-recovery-terminal-browser.log`. Browserdaten stammen aus einem
IPC-Testadapter. Die native positive Desktop-Gesamtprobe steht weiterhin aus;
kein Gesamtabschluss von Task13/14 oder DRK-250 wird daraus abgeleitet.

## Fortschrittsübersicht und Writer-Runden (2026-09-09)

Die zentrale [Progress.md](../../Progress.md) enthält den live geprüften Stand
aller14 ClickUp-Tasks, Ownership, native Nachweise und offene Liefergrenzen.
Root aktualisiert sie nach relevanten Ergebnissen; laufende oder gescheiterte
Prüfungen werden nicht als bestanden geführt.

WriterTransitionView trägt nun die optionale native `ceremonyId` im Rust-DTO
und generierten TypeScript-Vertrag. Die Oberfläche öffnet ausschließlich diese
gespeicherte Runde und liest nach Veröffentlichung den nativen Writer-Stand
neu. `Activated` bezeichnet den bereits signierten Registry-Stand und beginnt
keine weitere Runde aus einem Writer-Hash. Drei UI-Regressionen und eine
Vertragsprüfung zunächst RED; der anschließende vollständige UI-Lauf besteht
215/215 samt TypeScript (`.superpowers/t13-writer-round-ui-full.log`,12,01s).
Die native Ressourcen-/Portanbindung ist damit noch nicht abgenommen.

Der gesonderte tatsächliche PKCS11-CLI-Pfad Linux-Source→Mac-Target besteht
83,26s (`.superpowers/task-9-pkcs11-reverse-cli-native-final.log`): alle12
expliziten Medien, vorhandene c1-/d1-Schlüssel, Completed-Export und bytegleiches
Readback über eine neue SQLCipher-Verbindung. Die Token wurden nicht verändert;
dieser Nachweis behauptet keine Hardware-/HSM-Eigenschaft.

## Historische V4-Recovery und gespeicherte Root-Runden (2026-09-09)

Die tatsächliche Mac-Source→Ubuntu-Target-Gesamtprobe besteht1105,47s
(`.superpowers/t9-ubuntu-v4-guided-green.log`): 15/16 Medien ergeben den
signierten Incomplete-Bericht mit genau einem fehlenden Medium, anschließend
ergeben16/16 Medien Completed mit beiden historischen EIP-/Grant-Samples und
bytegleichem Reopen. Frische native Posture wird interaktiv je Medium erneuert;
der begrenzte Fixture-Watcher läuft1800s, die produktive Inaktivitätsgrenze
bleibt unverändert. Vorläufe scheiterten116,14s an Posture beziehungsweise300,16s
am pauschalen Fixture-Watcher. Kein positiver Batch-Langlauf wird behauptet.
Der exportierte Bericht `.superpowers/t9-completed-recovery-v4.cbor` ist auf
Container und Host hashgleich:
`20fc603f822625ecfbe7c18395cda2e54634cb95d044023d762b8ddbdb2f4051`.
Der tatsächliche Rückimport auf der Mac-Quellmaschine besteht109,83s
(`.superpowers/task-9-source-import-v4.log`): Signaturmanipulation verweigert,
dauerhafter Import und bytegleicher Drop/Reopen, tatsächliche CLI-import/status,
anschließende Rücknahme der aktuellen Go-live-Zulassung nach EIP-Mutation.

Der erste echte Desktoplauf dieses historischen Targets scheitert92,17s nach
Build2m35 im Status-Polling nach erfolgreichem Workerstart mit
`EA-TRUST-STATE-CONFLICT` (`.superpowers/t13-ubuntu-desktop-v4-positive.log`).
Die frühere Zuordnung zur initialen Lesezeile war falsch: tatsächliche
Zeilenprüfung unterscheidet initiales Lesen, Start und nachfolgenden Poll.
Weitere Diagnoseproben verweigern nach75,15s beziehungsweise106,57s ebenfalls
beim Poll. Die letzte lokalisiert `prepare_local_time` der frischen Hostrolle;
Host und aktiver Worker können denselben dauerhaften Zustand konkurrierend
auswählen. Eine weitere Probe erreicht tatsächlich nur das initiale Lesen und
verweigert nach43,69s alte Fixture-Posture. Vor der nächsten Diagnose wird echte
neue Posture mit unveränderter Frist erstellt. Noch keine Zulassungsprüfung,
Effektwiederholung oder produktive Retrylogik geändert; kein Desktopabschluss.

Der letzte tatsächliche CAS-Diagnoselauf liefert nach146,05s den konkreten
Konflikt: erwartet941, tatsächlich942, `time_match=true`, `pin_match=true`
(`.superpowers/t13-ubuntu-desktop-v4-cas-diagnostic.log`). Der Worker erreicht
Refused/Phase6. Die reine Kontextaufnahme derselben kanonischen lokalen DB
wird deshalb privat serialisiert; Presence/Audit/Fachaktionen werden nicht
unter diese Grenze verschoben. Externe Prozesskonflikte bleiben verweigert.
Die Umsetzung und der native Gegenlauf stehen noch aus; temporäre Root-
Recovery-Diagnosen sind bereits entfernt.

Der lesende `admin_open_ceremonies`-Vertrag liefert die gespeicherten offenen
Runden aller vier Workflowarten. Die Oberfläche öffnet ausschließlich ihre
native ID, zeigt Fehler beim erneuten Lesen und beginnt keine Ersatzrunde.
UI-RED→43/43 plus TypeScript GREEN7,11s
(`.superpowers/t13-open-rounds-ui-green.log`); gebauter Administrationsbrowser
5/5 GREEN4,3s mit Wiederladen und exaktem Öffnen ohne Begin/Autorisierung
(`.superpowers/t13-open-rounds-browser-green.log`, IPC-Testadapter).
Der erste tatsächliche Administrationshostlauf besteht29,28s mit Anmeldung,
Inbox, Policy/Registry, Go-live-Unresolved, Widerrufsgrenze und Invalidation
(`.superpowers/administration-host-green.log`). Die native Open-Rounds-Prüfung
besteht2/2 in14,23s (`.superpowers/administration-open-rounds-green.log`),
Kommandos/Administration-Launch/Registrierung25/25
(`.superpowers/administration-commands-green.log`). Der vollständige zweirundige
Host-Reopen besteht inzwischen96,21s
(`.superpowers/administration-host-rounds-green.log`): Fingerprintpflicht in
beiden Runden, exakte gespeicherte Activate-ID über OpenRounds, falscher
Aktivierungsfingerprint verweigert, tatsächliche Registry-Veröffentlichung und
aktiver Reader; Reopen erhält beide Runden und liefert eine leere OpenRounds-Liste.
Der tatsächliche Writer-Wechsel mit zwei Root-Runden/Reopen besteht78,08s
(`.superpowers/administration-transition-green.log`). Der Compilerstand für Ubuntu-Desktop-Recovery ist
vor der neuen Clock-Reparatur als1574-Dateien-Archiv gesichert
(`.superpowers/t13-desktop-v4-stable-source.tar.gz`, SHA256
`65b3c682afc38eba6b8368aa1e1436676e611cbe424b0c6b8b5eee7952674bbd`).

## Vollständiger Vernichtungswiederanlauf mit expliziter Testpolicy (2026-09-09)

Der tatsächliche TLS/PostgreSQL/S3-Effektlauf besteht444,25s
(`.superpowers/destruction-transport-explicit-policy-effect-green.log`):
Serverjob/Attestierung, Entfernung aller geprüften S3-EIP-/Grant-Versionen und
exaktes EDS-Readback, Drop/Reopen, erste lokale Entfernung und Attestierung,
erneuter Drop/Reopen und anschließend ausschließlich lesender Abgleich.
Dieser Nachweis verwendet ausdrücklich eine signierte1800s-Testpolicy.
Bei regulärer300s-Policy und alter unabhängiger Zeitreferenz bleibt
`EA-TRUST-FUTURE-SKEW` erhalten (authentische Negativprobe2,64s); eine neue
Provideranmeldung erneuert die Referenz nicht. Produktive Hostanbindung und
Referenzerneuerung bleiben offen. Reader ist weiterhin InProgress; ein
endgültiger Writer-Evidence-Eintrag ist nicht belegt.

Der Nativeexport-Negativsatz besteht28,27s
(`.superpowers/destruction-transport-native-export-final.log`): nicht signierter
Abschluss, fremde ID/Autorisierung, falscher Recordhash, veränderte Signatur und
falscher Komponentenschlüssel werden verweigert.

## Hostanbindung des authentifizierten Transports (2026-09-09, in Arbeit)

Die native Konfiguration unterstützt jetzt zusätzlich `authenticated-server`.
Sie verlangt explizite öffentliche DeviceId, Socketadresse, TLS-Name, Authority,
CA-Datei und ServerReceipt-Zertifikat. Leere oder doppelte Serverlisten und bei
`no-registered-server` dennoch konfigurierte Server werden verweigert. Der
geschützte Komponentenschlüssel bleibt eine ausdrücklich gewählte Container-
Quelle. Start/Resume rufen den separat verifizierten Transport unter bestehender
Hostepoch auf; kein zusätzlicher Publish-Schritt liegt vor dem nativen Start.
Konfigurations-RED→2/2 GREEN, Build6,18s
(`.superpowers/t13-destruction-server-config-green.log`).

`destruction_synchronize` führt über einen eigenen Hostport und blockierenden
IPC-Worker nur authentifizierte Server-GETs sowie lokalen signaturgeprüften Import
aus. Rendererparameter enthalten ausschließlich Vorgangs-ID und erwarteten
Vorberichtshash. Normales Statuslesen bleibt lokal. Die UI öffnet einen separaten
Serverabgleich und bewahrt bei Verweigerung den letzten Bericht. UI-RED→25/25
plus TypeScript GREEN3,48s (`.superpowers/t13-destruction-synchronize-ui-final.log`).
Ein unzulässiger Testwert für die Replikenzahl wurde dabei ausdrücklich korrigiert;
der Produktionsvalidator blieb unverändert. Vollständige native Hostabnahme,
Custodian-Neuanmeldung und reguläre unabhängige Zeitreferenzerneuerung sind noch offen.

Der anschließende Desktop-Hostlauf besteht121/121 (115 Lib und6 Kommandos),
Clippy mit `-D warnings`15,18s grün
(`.superpowers/t13-destruction-synchronize-host-gates.log`). Gebauter Browser7/7
in4,8s grün (`.superpowers/t13-destruction-synchronize-browser.log`, IPC-Testadapter).

Ein tatsächlicher NativeWriter→Reader-Gesamtlauf mit bestehenden Kern-APIs
besteht69,57s (`.superpowers/native-writer-evidence-initial.log`): eigenständige
Writer-Präsenz, normale Preview/Finalize des projizierten Vernichtungsvorgangs,
erneut geöffnete dauerhafte Evidence-Bindung und Reader-KEM-Verifikation des
Stubs und verschlüsselten Nachweises. Der fehlende Reader bleibt weiterhin
InProgress. Dieser Lauf benötigt keine neue Kernkorrektur und ersetzt noch
keine produktive Desktop-Writeranbindung.

Der vollständige UI-Zwischenstand vor dieser Serveraktion besteht220/220 samt
TypeScript in24,60s (`.superpowers/t13-open-rounds-and-terminal-ui-full.log`).

Der neue tatsächliche Serverhost-Test kompiliert7,54s
(`.superpowers/t13-server-host-compile.log`) und läuft aus genau diesem Binary
gegen die isolierten nativen Identitäten und TLS/PG/S3-Fixtures.
Er endet **RED nach593,39s** bei `destruction_resume_core` in
`transport/server/host.rs:176` mit `EA-DESTRUCTION-NATIVE-SESSION`
(`.superpowers/t13-server-host-native.log`). Tatsächlicher Start, PG-Job,
signierte Serverattestierung sowie Drop/Reopen und gesonderter Abgleich sind
vorher im selben Lauf bestanden. Lokale Entfernung und abschließender
Reopen sind noch nicht erreicht; die konkrete Sitzungsgrenze wird diagnostiziert.

Der unveränderte Diagnosefall endet erneut nach **593,27s**. Der konkrete
Unterfehler ist `EA-OPERATOR-NATIVE-LOCKED` beim Controller-Reopen in
`NativeDestructionExchange::fresh`; die direkt vorher geprüfte Custodian-
Autorität war noch gültig (`.superpowers/destruction-custodian-host-diagnostic.log`).
Der Testhelfer beendet seine Subscription nach absolut300s unabhängig von
neuer echter Presence. Ein gesonderter Kontrollschnitt nutzt nur für den
Controller den vorhandenen längeren Testsubscriber. Produktive Inaktivität
bleibt300s; die neue Custodian-Anmeldung wird nicht als Fix dieser Ursache
behauptet. Temporäre Diagnoselogger wurden aus den Quellen entfernt.
Ein unabhängiger lesender Review der neuen Root-Konfiguration, Hostdispatch,
Synchronize-Kommandos und UI fand keine bestätigten Findings. Der Review
begrenzt ausdrücklich: unveränderte Jobanzahl allein beweist kein GET-only;
der gelesene separate Aufrufpfad liefert die zusätzliche Evidenz. Der native
Test und der vom Reviewer selbst implementierte Transportkern sind damit
nicht unabhängig abgenommen.

## Explizite Custodian-Anmeldung und Recovery-Kontextaufnahme (2026-09-09)

Die zusätzliche Oberfläche fordert die Anmeldung des separaten ausführenden
Writer-Geräts nur durch eine ausdrückliche Handlung an. Sie bindet diese an
Vorgangs-ID und Vorberichtshash, bewahrt bei Verweigerung den letzten Bericht
und setzt den Vorgang erst nach einem weiteren Klick fort. Drei Regressionen
zunächst RED, dann **28/28 UI-Tests und TypeScript grün in5,71s**
(`.superpowers/t13-custodian-login-ui-green.log`). Gebauter Browser **8/8 in7,3s**
(`.superpowers/t13-custodian-login-browser.log`), einschließlich Wiederladen
ohne automatische erneute Anmeldung. Native Anbindung noch in Arbeit;
der Browser verwendet einen IPC-Testadapter.

Der neue separate Kommandopfad besteht **7/7 IPC-Prüfungen**, Build33,38s
(`.superpowers/t13-custodian-login-command-green.log`), nach Missing-API-RED.
Native Hostwirkung ist damit noch nicht belegt. Der Host öffnet ausschließlich
für diese ausdrückliche Handlung dieselbe konfigurierte Custodian-Identität
neu; geänderte Konfiguration wird vor dem Präsenzdialog verweigert. Er prüft
Vorgangs-ID und Vorberichtshash, erhält einen eigenen Writer-Präsenzbeleg und
fordert danach getrennte Admin-Präsenz für den Status an. Ein normaler Start,
Abgleich oder Wiederanlauf erneuert den Custodian nicht automatisch.

Der getrennte Recovery-Fix serialisiert die reine Kontextaufnahme derselben
kanonischen lokalen Datenbank. Presence, Audit und Fachaktionen bleiben
außerhalb. Explizite Zeitargumente bleiben unverändert; private Reopens lesen
die aktuelle Uhrzeit erst innerhalb des Zugriffsschutzes. Es gibt keinen
Retry; externe Zustandskonflikte bleiben verweigert. Verhaltens-RED2/3 führt
zu **3/3 grün in0,21s**, Abschlussbuild22,10s und ea-admin Lib-Clippy25,28s.
Root hat den konkreten Patch unabhängig gelesen, ohne bestätigte Findings.
Der unveränderte native V4-Desktop-Gegenlauf auf dem bereinigten Ubuntu-Stand
endet nach **330,02s** mit `EA-DESKTOP-ADMINISTRATION-FORBIDDEN` im Status-Polling
(`.superpowers/t13-ubuntu-desktop-v4-acquisition-green.log`); kein Zustandskonflikt
in diesem Lauf, aber weiterhin kein bestandener Gesamtlauf. Der anfängliche
Admin-Präsenzbeleg des Hosts läuft ab; tatsächliche neue Recovery-Präsenzbelege
des Workers werden bisher nicht an dessen Rollenprüfung übergeben. Diese
Hostgrenze wird gesondert korrigiert, ohne Zeitgrenzen zu verlängern.

Die tatsächliche V4-Desktop-Abbruchprobe am ersten Medien-Wartepunkt besteht
**1/1 in256,84s**, Build3,71s,173 gefiltert
(`.superpowers/t13-ubuntu-desktop-v4-first-wait-cancel.log`). Der zuvor
gespeicherte Bericht und sein Reopen bleiben erhalten. Dies ersetzt den noch
offenen langen Positivlauf nicht.

## Native Gegenproben und Tauri-Berechtigungen (2026-09-09, 15:20)

Der isolierte Serverhost-Kontrolllauf besteht **1/1 in463,41s**, einschließlich
lokaler Entfernung und abschließendem Reopen
(`.superpowers/t13-server-host-controller-watch-control.log`). Nur der
Controller-Fixture-Subscriber bleibt länger als absolut300s geöffnet; der
produktive Inaktivitätswächter bleibt unverändert. Die signierte1800s-Testpolicy
war bereits vorhanden. Dieser Lauf belegt weder eine Reparatur durch neue
Custodian-Anmeldung noch reguläre Zeitreferenzerneuerung der300s-Policy.

Die explizite Custodian-Kernanmeldung besteht **3/3 in14,58s**, Build8,27s,
nach tatsächlichem Native-RED. Geprüft: eigene Writer-/Finalize-Präsenz samt
signiertem Login-Audit, Epochsperre während des Dialogs, entwerteter Watch und
ausdrücklich neu geöffnete Ressourcen. Kein Admin-Beleg wird daraus erzeugt.
Admin-/CLI-Clippy bestehen14,48/25,98s. Log:
`.superpowers/destruction-custodian-presence-green.log`. Root hat Kern und
Tests unabhängig gelesen; keine bestätigten Findings. Der neue tatsächliche
Desktop-Host-Gegenlauf besteht inzwischen **1/1 in57,16s**, Build35,89s,
nach RED33,86s (`.superpowers/t13-custodian-login-native-green.log`): Die
Anmeldung erhält den Vorgang ohne Entfernung, verweigert falschen Hash,
geänderte Operator-Konfiguration und gesperrte Hostepoch; abschließender
dauerhafter Reopen bestanden.

Die Recovery-Belegübergabe besteht **0/2 RED →2/2 GREEN in223,01s**, Build25,13s
(`.superpowers/t13-ubuntu-recovery-observer-green.log`). Der Kern übergibt
denselben bereits tatsächlich erzeugten und auditierten nativen Beleg als
privates Arc; es gibt keine Verlängerung, Renderer-Autorität oder Konvertierung
in andere Aktionszwecke. Zwei echte Challenge-Belege vor/nach dem Medium,
Signatur, aktuelle Verifikation, falscher Zweck/Frist und Hostdenial vor dem
Medienergebnis sind geprüft. Beide gespeicherten Berichtshistorien bleiben
im Denialfall nach Reopen unverändert. Die terminalen Callbackkanten sind
mit diesen beiden Proben nicht separat abgedeckt. Der Root-Host prüft die
Belege nach frischer Kontextaufnahme mit dem gewöhnlichen RecoveryTest-Verifier
und derselben Hostepoch. Unabhängiger lesender Review: keine bestätigten
Findings. Der vollständige V4-Host-Gegenlauf läuft auf dem zuvor bereinigten
Ubuntu-Stand mit ausschließlich dieser Hostergänzung.

Die gemeinsame Desktopprüfung fand zusätzlich eine reale Tauri-ACL-Lücke:
Die aktiven Berechtigungen fehlten für `destruction_synchronize`,
`destruction_authenticate_custodian` und `admin_open_ceremonies`; das Buildmanifest
fehlte für den letzten Befehl. Alle drei Berechtigungen und das Manifest sind
ergänzt, die exakte Befehlsliste und ihre Anzahlen aktualisiert. Die vorherigen
Browser-IPC-Adapter und direkten Coreaufrufe hatten diese Grenze nicht geprüft.
Nun **115 Host-,7 Vernichtungs-,3 Recovery- und5 Registrierungsprüfungen grün**;
Clippy mit `-D warnings` **31,44s grün**. Belege:
`.superpowers/t13-custodian-recovery-role-host-gates-green.log` (Zwischenlauf
mit noch veralteter Literalanzahl) und
`.superpowers/t13-custodian-recovery-role-host-registration-final.log` (5/5
und vollständiger Clippyabschluss). Der ursprüngliche fehlschlagende Lauf
bleibt unter `.superpowers/t13-custodian-recovery-role-host-gates.log` erhalten.

## Vollständiger nativer Desktop-Recovery-Gegenlauf

Der unveränderte V4-Hostfall
`portable_native_desktop_recovery_completes_each_medium_and_reopens_signed_status`
besteht mit der schmalen privaten Belegübergabe **1/1 in822,41s**, Build15,29s,
175 gefiltert (`.superpowers/t13-ubuntu-desktop-v4-observer-positive.log`).
Alle16 echten Medien werden einzeln gewählt und geprüft; beide historischen
Writer-Samples bestehen. Der neue signierte Abschluss hat eine nächste
Fälligkeit, die bisherige Fehlerberichtshistorie bleibt erhalten, und der
neu geöffnete Desktophost liest exakt dieselben dauerhaften Berichte.
Die ursprünglichen300s-Präsenz-/Aktionsfristen bleiben unverändert; nur der
Test-OS-Subscriber hat den zuvor dokumentierten längeren Lebenszyklus.

[Öffentliche Hostansicht](artifacts/drk-250-native-desktop-recovery-v4.json):
40701Bytes, SHA256
`dd4fd0b87f50313ff936c9773e7e08b14ecb70cb9c6459c77fdb973e1d142988`.
Die gesicherte Ansicht enthält16 abgeschlossene Medienbeobachtungen,2 Samples
und Phase3 sowie die erhaltene frühere Fehleransicht. Es handelt sich um die
öffentliche DTO-Projektion, nicht um einen eigenständig signierten COSE-Umschlag;
Signatur und dauerhafter Reopen sind im nativen Test geprüft. Der Lauf basiert
auf der LocalPath-V4-Quelle und ersetzt keinen ControlledNetwork-Quellnachweis.
Auch die zugehörigen lokalen Admin-/CLI-Clippy-Gates bestehen mit `-D warnings`
in8,17/29,70s.

## Angehaltener Clock-Release-Schritt

Die automatische Freigabeprüfung hat die nächste native Release-Komposition
vor Ausführung abgelehnt: Die besondere Anmeldung trotz Zeitblockade sei
durch das allgemeine „weiter“ nicht hinreichend autorisiert. Kein Edit dieses
Aufrufs wurde angewendet. Der Release-Stub bleibt geschlossen; Root hat den
konkreten noch nicht angewendeten Patch gelesen und die ausdrückliche
Benutzerfreigabe angefragt. Diese Anfrage ist noch offen. Reviewgrundlage:
`.superpowers/sdd/2026-08-13-einsatzarchiv-stage-5-administration-recovery/native-clock-release-approval-handoff.md`,
Patch-SHA256 `08f09b2b6368cf0326bed9bdd168a2e3389b034ad7e37fdd89da3026a05a9c24`.
Die vorherigen geprüften Teilschritte bleiben davon getrennt: checked Audit
RED0/2 →GREEN4/4 sowie Clippy; native Clock-Aufnahme erreicht den ausdrücklich
geschlossenen Release-Stub (RED1,39s). Es wird kein bestandener nativer
Clock-Release behauptet.

## Prepared-Diagnose: sauberer Snapshot-RED und laufende Abnahme

13.09.2026. Root hat `native-prepared-resource-snapshot-red-clean.log` direkt geprüft: 0/1 in6,24s, tatsächlich `Some(Unreadable)` statt `None`. Eine zweite SQLCipher-Verbindung konnte zwischen alter Profilprüfung und späterem Markerread den vollständigen Wechsel committen. Der korrigierte Port führt Profilprüfung, Evidence-Routing, Migration und Markerread in einer gemeinsamen Transaktion aus. Native Identität und streng geprüfte bestehende Posture ohne Persistierung laufen außerhalb; CurrentAdmin-Session und Epoch bleiben in der vorhandenen Host-Schale. Unabhängiger Quellreview läuft, finale native Ergebnisse noch nicht abgenommen. Bootstrap-Teilnehmerimplementierung und zwei signierte historische Zustandsproben laufen separat; kein Gesamtabschluss.

## Weitere begrenzte Abschlüsse: Prepared-Ressource und Ziel2

13.09.2026. Prepared finalv3 nach Decoder-vor-Nachcheck:6/6 in51,07s, SHAbe17092a6305687d878d8e28393f4ecf2988d7ed539abae28522962cf8e10a1d unabhängig geprüft. Draft28/28, WriterPrepared19/19, scopedClippy4,60s grün. `native-prepared-diagnosis-resource-root-review.md` FINALPASS. Tatsächlicher Writer unter vorhandener CurrentAdmin-Schale, keine Repair-/IPCautorität.

Bestätigter Ziel2-Fehler eng behoben: Pending UND keine Unreachable-Pflicht; derselbe originale Nenner. SignierterRED→GREEN1/1 in1,59s, voller Kern41passed/0failed/1ignored in11Targets; Root unabhängig nachgezählt und `native-destruction-pending-duty-root-review.md` PASS. Test-Clippy bleibt an zwei new_without_default-Warnungen in unveränderten Testhelfern rot, keine pauschale statische Freigabe. Der ignorierte LateOriginal-Zeuge bleibt eigenständige offene Vertragsfrage. Native Pendingproducer zunächst eigener Vertrag; Bootstrapteilnehmer weiter in Umsetzung. Kein Gesamtabschluss/Commit/Push/PR.

## Historische4/4→1-Korrektur unabhängig abgenommen

13.09.2026. Eigener LateOriginal-RED0/1 in1,66s→GREEN1/1 in1,88s, voller Destructionkern42/42 ohne Ignored, LibClippy17,03s grün. Root hat Quelle/Report/Gates gelesen und Summen/Quellhash unabhängig geprüft: `native-destruction-late-original-root-review.md` FINALPASS. Die bestehende signierte konservative Fehler- und Retryhistorie bleibt erhalten; fehlende Reader-/Serverclaims bleiben Unreachable, Complete/Targets/Stubs/Replays/Forks/IDs/Vorgänger weiterhin geprüft. Reine historische Annahme erteilt keine aktuelle physische Ausführung oder Auslieferungsfreigabe. TestClippy weiterhin exakt zwei unveränderte Supportwarnungen; kein pauschaler statischer PASS.

Die zusätzlichen Ziel2-Fristproben sind vorbereitet und noch nicht ausgeführt. Nativer Pendingproducer zuerst unabhängiger Vertragsreview. Bootstrapteilnehmer erster37/37-Lauf grün; finale14Teilnehmer+24Root/CLI-Copy mit verschärftemDBkey- und Accountwechseltest in Abnahme. Kein Gesamtabschluss, Commit, Push oder PR.

## Einzelner Bootstrapteilnehmer FINALPASS, Testhelfergate geschlossen

13.09.2026. Root hat finalenTeilnehmercode, tatsächlichev2Copy/SHA4141315d1a969856ec5032c1ebdbeff8c6b3344ad6b2ebbfc2086d35c698aa07 und alleGates unabhängig geprüft: native38+1Fixtureignored (14Teilnehmer), Schema34, Storage4, Bootstrap53+Lease5; Admin/CLIClippy34,84s und Schema/StoreClippy13,45s grün. `native-bootstrap-admin-participant-root-review.md` FINALPASS. V2 enthält präzisenDBunwrap/Signature/Cipherfehlernachweis und tatsächlichenAccountwechsel. Danach ausschließlich zwei äquivalenteIf-let-Formen korrigiert; final statisch geprüft, kein weitererNativelauf behauptet. KeineBootstrap-Gesamt-/Backups-/ZweiKonten-/Schritt3-Abnahme.

Root ergänzte separat zwei reineTesthelferDefaults, jeweilsSelf::new. BisherroterPreflightClippy jetztExit0 in4,27s (`native-destruction-test-support-default-clippy.log`); frühereRots bleiben historisch korrekt.

ZusätzlicherhistorischerFristzeuge tatsächlich0/2 in1,70s:1→2 bei/kurz nach Fristablauf wurde akzeptiert, auchneben weiterlaufenderandererFrist. Produktionshash davor/danach unverändert. EngerFix freigegeben. NativerPendingdienst nachunabhängigemReview mitprivatemPreSignFence/AllHolderCommit und zusätzlicherfrischerrefusal-onlyCutoffprüfung aufbestehendemZeitguard inUmsetzung. NativeAdmin/RootBackup-Portinventur benennt bestehendenSigningcontainer, aber fehlendenstrengtypisiertenHelperport; dazu zunächstDesign, keineBenutzerkeys/neueEscrowwire.


## Historische Pendingfristen FINALPASS; nativer Producer in Abnahme

13.09.2026. Root prüfte den engen historischen Fristfix unabhängig: signierter RED0/2 in1,70s, danach GREEN2/2 in2,01s, vollständige Kernregression44/44 ohne Ignored und Preflight-Clippy5,40s grün. Finale Quelle und Logsummen unabhängig bestätigt; `native-destruction-pending-deadline-root-review.md` FINALPASS. Jede Pendingpflicht benötigt zur Ereigniszeit eine noch laufende historische Maximalfrist; spätere Originale und kürzere neue Fristen umgehen dies nicht.

Nativer1→2-Dienst separat: tatsächlicher BehaviorRED0/1 in21,53s, erster GREEN1/1 in46,98s mit tatsächlichem lokalem Cleanup, synthetisch zertifiziertem Readerpending, nativem Event-/Auditcommit und Reopen-Replay. Zusätzliche Konkurrenz-/Frist-/Refusalproben und unabhängige Abnahme stehen aus; noch kein finaler Runtime-PASS. Root bereitet Desktopanbindung testseitig vor. NativeRoot/Admin-Backupvertrag liegt als Design vor und wird unabhängig geprüft, keine Schlüssel-/Medien-/Bootstrapabschlussbehauptung. Kein Commit, Push oder PR.


## Signing-Backup-Port: Designreview PASS, getrennte Umsetzung begonnen

13.09.2026. Der einzige unabhängige P2 ist im Vertrag geschlossen: letzter privater Snapshot-/Watchcheck unmittelbar nach sämtlichen blockierenden Rechecks, einschließlich letztem Admin-DB-Unwrap/Journalconfirm, vor Containerreturn. `native-bootstrap-signing-backup-port-design-review.md` PASS für den Entwurf. Root las die Revision ebenfalls.

Zwei abgegrenzte Owner: native dreiOS-Parser/Provider/Framezweige und Rustprivattransport/Root-/Adminhosts/Recovery-Seal-Komposition/read-only Journalport. Bestehender Signing-v1-Container, separater geschlossener106Byte-Erfolgsframe, kein öffentlicher Seed und keine Änderung von generischem unwrap-secret. Nur Testfixturekeys. NativePresence-/Copy-/Zeroize-/OSruntimegrenzen bleiben explizit; keine Medienquittung/Step3/RecoveryReady. Cargo und gemeinsame Inputs weiterhin serialisiert.

DesktopPending inzwischen tatsächlicher RED0/1 in36,93s nach erfolgreichen Import-/Reopenvorbedingungen; noch keine Produktanbindung oder GREENbehauptung. Nativer Pendingproducer zusätzliche acht Fälle noch im Lauf. Gesamt bleibt in Arbeit, kein Commit/Push/PR.

## 13.09.2026 – Pending-Runtime und Signing-Helper abgeschlossen, Rustbackup weiter offen

NativePendingfinal8/8 in615,17s; vier korrigierte positive Completion-/Importverbraucher4/4 in205,76s. DesktopNoServer1/1 in75,54s, bestehende Complete-/Readerproben und korrigierter Import grün. Tatsächlicher TLS/Postgres/S3-DesktopPendinglauf1/1 in332,32s; exaktes Postgres-/lokales Übergangsoriginal, alle Ereignistabellen nach Reopen/Synchronize unverändert. Appliedsource-Review PASS. Gemeinsamer Test-Clippy nach Fixturekorrektur noch offen; keine pauschale Vollgatebehauptung.

Signingbackup-Helfer: Rootreview FINALPASS für begrenzten Parser-/Provider-/Binärtransport;75Quellhashes unabhängig ohne Abweichung. Mac/Linux-Gates und Windowsportable/Parser-/Crossbuilds grün, kein ausgeführter Windows-OS-Provider. Rustbackup-Host/-Transport bleibt in Umsetzung; revidierter Unix-only-Pipeentwurf unabhängig PASS nach Auslagerung blockierender Watch-/Prozesschecks in public-onlyWorker ohne Secretzugriff. Echte Timeout-/Wipeproben und finaler Host-/Journalreview folgen.

Failure-only1/2→4 als nächster begrenzter Vertrag dokumentiert; universeller Retry mangels vollständigem aktuellem Reader-Reacquisition-Port offen. Gesamt-DRK-250 bleibt aktiv. Kein Staging/Commit/Push/neuer PR; bestehende Clock-/Escrowfreigabegrenzen unverändert.

## 13.09.2026 – Pending begrenzt FINAL PASS

Abschließender gemeinsamer Admin-/Operator-Test-Clippy nach sämtlichen positiven Fixturekorrekturen tatsächlichExit0,1m41s: `cargo +1.95.0 clippy --locked -p ea-admin -p einsatzarchiv-cli --lib --test operator --features desktop-fixture -- -D warnings`; native-signing-backup-admin-operator-clippy-v1.log. Zusammen mit nativen8/8, Consumer4/4 und tatsächlichen NoServer-/TLS-/PG-/S3-Desktopproben schließt dies den begrenzten Pending-Schnitt. Beide Rootberichte FINALPASS, keine Vollstagebehauptung.

Rust-Signingbackup: echte finaleHostmatrix7/7 in13,55s nach gezieltemLease-RED6/7; immutableHostcopy SHA77f9494fdc7a5f7a3ef5a5107a5f65816f9fc71868d9c5df6c4f974441d4657c vonRootunabhängiggehasht. Runnerfinal3/3 in0,58s, Recoveryfinal2/2 in0,31s. Abschließender unabhängigerReview/Quellmanifest noch separat. Failure-only-DesignPASS, neueTests/Stubvorbereitet; tatsächlicheREDs folgen im freigegebenenCargofenster.

## 13.09.2026 – Nativer Signing-v1-Containerexport begrenzt FINAL PASS

Unabhängiger Rustreview und Root-Integrationsabnahme abgeschlossen: konkreterFinallease-P2 RED6/7→Fix→GREEN7/7 in13,55s, Runnerfinal3/3 in0,58s, Recoveryfinal2/2 in0,31s, gemeinsamerAdmin-/OperatorClippy1m41s undRecoveryClippy24,29s Exit0. Root undReviewer prüften19Quell-/Integrationshashes undHostcopy unabhängig ohneAbweichung. ImmutableSHA77f9494fdc7a5f7a3ef5a5107a5f65816f9fc71868d9c5df6c4f974441d4657c. DreiOS-Helper separatbegrenztabgenommen.

KeineMedien-/Restore-/WindowsOS-/ZweiKonten-/Step3/7/Ready-Abnahme. NächsterMedienvertrag undsichereFileportinventur laufenread-only; Failure-only-Worker besitztCargo fürtatsächlichenAPI/Pure/BehaviorRED. DRK-250weiteraktiv, keineGitveröffentlichung.
