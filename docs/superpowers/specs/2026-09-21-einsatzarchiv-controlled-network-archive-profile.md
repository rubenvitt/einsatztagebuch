# Controlled-Network-Archiv: Komponente, Registrierung, Writer, Queue und Recovery-Quelle

Normativer Vertrag für DRK-320. Er konkretisiert §§9.3, 9.4, 11.5 und 19.3 von
`2026-08-13-einsatzarchiv-v0-1-design.md` für das Profil
`controlledNetworkPath` und ersetzt die Schnittstellenskizze
`docs/superpowers/plans/2026-09-09-native-archive-recovery-source.md`, soweit
beide sich widersprechen. Er führt kein Archivobjekt, keine Signaturfamilie,
keinen Audit-Aktionscode, keine Domänenzeichenkette und keine Migration ein. Er
ändert weder den aktiven Profilzeiger noch den `ProfileMigrator`. LocalPath
bleibt in jedem Punkt unverändert. Jede Regel trägt eine ID, die Tests zitieren.

## 1. Begriffe

Ein **Netzprofil** ist ein `ArchiveBackendProfileV1::ControlledNetworkPath`.
Das **Netzziel** ist `OperatorRuntimeConfig::archive_directory` einer
Installation mit Netzprofil. Die **lokale Komponente** ist der Namensraum in
der SQLCipher-Datenbank dieser Installation (Tabellen aus Migration 0016),
gelesen und beschrieben über `SqliteCommitStore` und
`SqlcipherArchiveBackend`. **Committed** heißt: eine Adresse außerhalb des
Staging-Bereichs (`ea_archive::is_staging_path` ist falsch). Die
**Registrierung** ist die Zeile in `native_archive_component` (Migration 0026)
samt zugehöriger Zeile in `local_commit_scope`.

## 2. Namensraum (beschreibend, eingefroren)

**EA-CNA-NS-1.** Der Namensraum ist
`SHA-256("EINSATZARCHIV-NATIVE-ARCHIVE-COMPONENT-v1" || 0x00 || anchorHash32 || profileHash32)`,
berechnet von `ea_crypto::native_archive_component_namespace`. Es ist ein
einfacher SHA-256 über die Verkettung, kein `ObjectHash` und kein
`EINSATZARCHIV-OBJECT-v1`-Präfix. Die Domänenzeichenkette ist durch den
Vektor `domain-string/einsatzarchiv-native-archive-component-v1` in
`vectors/crypto/suite-1/manifest.json` eingefroren. DRK-320 ändert weder
Zeichenkette, Trennbyte noch Reihenfolge.

**EA-CNA-NS-2.** `anchorHash32` ist `TrustAnchorV1::trust_anchor_hash()` des
unabhängig geladenen Ankers. `profileHash32` ist
`ea_crypto::archive_profile_digest` über die kanonischen
`encode_archive_backend_profile_core`-Bytes des vollständigen Profils
einschließlich Queuegrenzen und Wiederaufnahmeparametern. Pfad,
Installation und Policy-Version gehen nicht ein: dieselbe logische Quelle
bleibt an anderem Pfad wiederherstellbar, und eine Policy-Erneuerung
verwaist keine ausstehenden Bytes.

**EA-CNA-NS-3.** Je Anker gibt es höchstens eine Registrierung
(`native_archive_component.anchor_hash` ist Primärschlüssel). Ein geändertes
Profil ergibt einen anderen Namensraum und ist deshalb ein Profilwechsel nach
§11.5, keine Registrierung (EA-CNA-REG-9).

## 3. Registrierung und Aktivierung

**EA-CNA-REG-1 (Wer).** Registrieren darf ausschließlich eine
`OperatorRuntime` mit Rolle `OrganizationAdmin` unter Current-Autorität
(`ensure_current` vor jeder Prüfung und unmittelbar vor dem Schreiben). Ein
Writer, ein StaleWriter-Kontext oder eine Recovery-Zielinstallation
registriert nie. Die Runtime muss dieselbe native Installation und dieselbe
SQLCipher-Datei nutzen wie der spätere Writer: der kanonische Pfad von
`NativeArchiveConfig::local_commit_database_path` ist gleich dem kanonischen
`runtime.database().path()`.

Rolle und Datenbank widersprechen sich nicht: der SQLCipher-Schlüssel ist je
nativer Installation ein einziger (`SecretPurpose::LocalDatabaseKey`, Slot
`database-key`, unabhängig vom Signierslot der Rolle), sodass eine
Admin- und eine Writer-Konfiguration derselben Installation denselben
`database_path` öffnen.

**EA-CNA-REG-2 (Vorbedingungen, lesend, in dieser Reihenfolge).** (a) Das
Profil ist ein Netzprofil und `local_commit_database_path` ist gesetzt;
(b) `profile.core()` ist wohlgeformt und die Queuegrenzen sind positiv und
passen in `i64`; (c) die gewählte Registry-Policy enthält den exakten
`profileHash32`; (d) Migrationen 16 und 26 sind angewandt; (e) das Netzziel
existiert als Verzeichnis und öffnet mit `LocalPathBackend::open_existing`,
das weder Wurzel noch Vorfahren anlegt; (f) der Capability-Test des Profils
(`run_capability_test` mit `capability_test_vector_id`) beweist alle sieben
Eigenschaften (`all_proven`); (g) ein vorhandener aktiver Profilzeiger im
Netzziel (`read_active_profile_pointer`) nennt genau `profileHash32`, oder
es gibt keinen; (h) für den Anker existiert keine abweichende Registrierung
und keine abweichende Scope-Zeile für den Namensraum. Jede verletzte
Vorbedingung lehnt ohne jeden Schreibzugriff auf die Datenbank ab.

**EA-CNA-REG-3 (Frische Präsenz).** Nach den Vorbedingungen verlangt die
Registrierung eine frische native Re-Authentisierung mit
`ReauthPurpose::ArchiveProfileMigration`. Der Nachweis gilt nur für diese
eine Registrierung.

**EA-CNA-REG-4 (Audit).** Die Registrierung erzeugt genau ein signiertes
`LocalAuditActionV1::ArchiveProfileMigration` mit Ausgang `Accepted`. Sein
Kontext `ArchiveProfileMigrationContextV1` trägt `sourceProfileHash =
targetProfileHash = profileHash32` (gleiche Hashes kennzeichnen die
Erstregistrierung ohne Wechsel des aktiven Profils), `inventoryHash =
archive_inventory_digest(encode_archive_inventory_list(netzziel.inventory()))`
zum Registrierungszeitpunkt und `activePointerHash =
active_profile_pointer_digest(exakte Zeigerbytes)`, wenn ein Zeiger nach
EA-CNA-REG-2(g) existiert, sonst 32 Nullbytes. 32 Nullbytes bedeuten „kein
Zeiger gelesen, keiner geschrieben“ und nie einen Zeiger der Generation 0.
Es entsteht kein neuer Aktionscode und keine neue Kontextform.

**EA-CNA-REG-5 (Atomar, einmalig).** Scope-Zeile, Komponentenzeile und
Auditzeile werden in genau einer SQLCipher-Transaktion geschrieben. Der
Fremdschlüssel `native_archive_component.namespace → local_commit_scope`
verlangt die Scope-Zeile zuerst; zwei Transaktionen könnten nach einem Absturz
eine verwaiste, durch Trigger unlöschbare Scope-Zeile hinterlassen. Deshalb
ist `SqliteCommitStore::new`, das eine eigene Transaktion öffnet, für die
Registrierung verboten. Eine bereits vorhandene Scope-Zeile mit exakt
denselben Grenzen wird wiederverwendet, eine mit abweichenden Grenzen lehnt
ab.

**EA-CNA-REG-6 (Idempotenz und Konflikt).** Existiert für den Anker bereits
eine Zeile mit exakt demselben `profile_hash`, `namespace` und
`exact_profile`, endet die Registrierung ohne Präsenz, ohne Audit und ohne
Schreibzugriff mit dem Ergebnis „bereits registriert“. Jede abweichende
vorhandene Zeile lehnt mit `EA-NATIVE-ARCHIVE-REGISTRATION-CONFLICT` ab und
bleibt unverändert; die Unveränderlichkeitstrigger aus 0016/0026 bleiben die
letzte Schranke.

**EA-CNA-REG-7 (Messung nach dem Schreiben).** Unmittelbar nach dem Commit
öffnet die Registrierung die Komponente über denselben Weg wie jeder spätere
Verbraucher (`NativeArchiveExistingComponent::open_current`), einschließlich
der Ruheort-Messung (`local_commit_probe`). Scheitert die Messung, meldet die
Registrierung den Fehler; die Zeilen bleiben bestehen, und jede spätere
Öffnung scheitert gleich (fail-closed). Die Messung kann nicht vor dem
Schreiben laufen, weil `local_commit_probe` die Scope-Zeile voraussetzt.

**EA-CNA-REG-8 (Verhältnis zum Profilzeiger).** Die Registrierung liest den
aktiven Profilzeiger höchstens (EA-CNA-REG-2(g)) und schreibt ihn nie. Sie
definiert weder dessen Format, Generation, Ort noch den `ProfileMigrator`
neu. Der Zeiger bleibt die Wahrheit des Profilwechsels nach §11.5 Schritt 5.

**EA-CNA-REG-9 (Grenze).** Ein Wechsel des Netzprofils oder zwischen
LocalPath und Netzprofil nach einer Registrierung ist nicht Teil von DRK-320.
Er bleibt die auditierte Sechs-Schritt-Migration aus §11.5 und braucht eine
eigene Integration, die Komponente, Namensraum und Zeiger gemeinsam
überführt. Bis dahin ist die Registrierung für ihren Anker endgültig.

**EA-CNA-REG-10 (Konsequenz für LocalPath-Konfiguration).** Existiert für den
Anker eine Registrierung, lehnt `NativeArchiveExistingComponent` eine
LocalPath-Konfiguration mit `EA-NATIVE-ARCHIVE-PROFILE-MISMATCH` ab. Ein
registriertes Netzziel wird nie als lokaler Pfad umetikettiert. Ohne
Registrierung bleibt LocalPath exakt wie bisher.

## 4. Startquelle

**EA-CNA-SRC-1 (Reihenfolge).** `open_resources` öffnet für jede Rolle zuerst
den unabhängigen Anker, dann den nativen Anbieter und die SQLCipher-Datenbank,
liest dann in einer Lesetransaktion die Registrierung für den Anker und baut
erst danach den Archiv-Snapshot. Erst auf diesem Snapshot werden Zertifikat,
Gerät, Trust und Registry-Head gewählt.

**EA-CNA-SRC-2 (Vereinigung nur für Netzprofile).** Ohne Registrierung ist
der Snapshot wie bisher `FsArchiveSource::open_committed(archive_directory)`.
Mit Registrierung ist er
`FsArchiveSource::open_committed(archive_directory)?.with_exact_component(&lokal)`,
wobei `lokal` die committed Sicht der lokalen Komponente ist
(`SqlcipherArchiveBackend` als `ArchiveSource`, ohne Staging). Das Profil
kommt aus `native_archive_component.exact_profile`, nicht aus der
Konfiguration. Byte-Konflikt, ungültige Adresse oder unvollständige
Aufzählung lehnen die ganze Vereinigung ab
(`EA-OPERATOR-NETWORK-ARCHIVE-CONFLICT`); es gibt keinen Vorrang einer Seite.
Die Vereinigung beim Start prüft die Policy bewusst nicht: vor der Trust-Wahl
gibt es noch keinen Registry-Head. Das ist sicher, weil die lokalen Bytes nur
untrusted Eingabe des ankergebundenen Verifiers sind und weder Trust noch
Autorität erzeugen können. Folge: Entfernt eine spätere Policy den
Profilhash, liest der Start die unveränderliche Komponente weiter; jeder
Schreib- oder Publikationsweg (Writer, Publikation, Recovery) verlangt die
Policy dagegen erneut und blockiert mit `EA-ARCHIVE-PROFILE-NOT-ALLOWED`.

**EA-CNA-SRC-3 (Verifikation).** Die Vereinigung ist untrusted Eingabe für
denselben Verifier (`verify_archive`) wie bisher. Sie ersetzt weder Anker
noch Trust-Wahl noch Registry-Frische. Nächste Sequenz, Kettenkopf, Inventar
und Trust-Auswahl kommen ausschließlich aus dem verifizierten Snapshot der
Vereinigung.

**EA-CNA-SRC-4 (Nicht lesbares Netzziel).** Ist das Netzziel beim Öffnen nicht
lesbar, scheitert ein Kaltstart mit `EA-OPERATOR-NETWORK-ARCHIVE-UNAVAILABLE`.
Ein `reopened_for_action` desselben Prozesses darf stattdessen die zuletzt
live gelesene, unveränderte committed Sicht des Netzziels (Grundlinie) mit der
aktuellen lokalen Komponente vereinigen. Die Grundlinie lebt nur im Speicher,
stammt aus demselben kanonischen `archive_directory` und demselben Anker und
durchläuft erneut die volle Verifikation. Für LocalPath gibt es keine
Grundlinie. Das ist kein Ausweichen auf ein anderes Ziel: gelesen wird
dieselbe Quelle, geschrieben wird nur lokal.

**EA-CNA-SRC-5 (Bereinigung).** Nur beim Öffnen mit live gelesenem Netzziel
und nur unter dem per `try_lock` erlangten SQLCipher-Writer-Lock entfernt die
Runtime committed lokale Objekte, deren Adresse im live gelesenen Netzziel
byte-identisch vorliegt. Staging-Adressen, Verzeichniszeilen und die Sonde
werden nie entfernt. Ist der Lock belegt, entfällt die Bereinigung ohne
Fehler. Weil die Grundlinie dieser Öffnung jedes bereinigte Objekt enthält,
bleibt die Vereinigung durch die Bereinigung unverändert.

## 5. Writer auf der lokalen Komponente

**EA-CNA-WRT-1.** Der Desktop-Writer mit Netzprofil schreibt ausschließlich in
die lokale Komponente (`NativeArchiveExistingComponent::local_backend`), nie
direkt in das Netzziel. Schritte 8 bis 11 aus §9.3 laufen unverändert gegen
dieses `ArchiveBackend`; der Writer-Lock ist die OS-Dateisperre
`<db>.archive-writer.lock`.

**EA-CNA-WRT-2 (Konfiguration).** Die Writer-Einstellungen nennen für ein
Netzprofil `local_commit_database_path`; für LocalPath ist das Feld verboten.
Der kanonische Pfad muss die Datenbank der Writer-Runtime sein
(EA-CNA-REG-1). Das Feld liefert keinen Schlüssel, keinen Namensraum und keine
Grenzen.

**EA-CNA-WRT-3 (Freigabe).** Vor dem ersten Writer-Dienst misst der Host
(a) die Ruheort-Verschlüsselung (beim Öffnen), (b) den SQLCipher-Capability-
Test (EA-CNA-WRT-4) und (c) den Capability-Test des Netzziels. Fehlt eine
Eigenschaft, blockiert die Konfiguration mit
`EA-ARCHIVE-HEALTH-FILESYSTEM-SEMANTICS`.

**EA-CNA-WRT-4 (SQLCipher-Capability).** Gemessen werden, an genau der
Datenbank des Writers: WAL-Journal und `synchronous=FULL` in einer
schreibenden Transaktion, erfolgreicher physischer Flush von Datenbank,
WAL-Datei und Elternverzeichnis und die Exklusivität des Writer-Locks über zwei
unabhängige Datei-Handles (der zweite `try_lock` scheitert, nach Freigabe
gelingt er). Create-if-absent, Byte-Konflikt und atomarer Rename sind
Eigenschaften derselben SQL-Transaktionen und werden durch die Tests von
`SqlcipherArchiveBackend` belegt, nicht durch Schreibproben in den
produktiven Namensraum.

**EA-CNA-WRT-5 (Lesesicht).** Die Lesequelle des Writers ist die Vereinigung
aus dem verifizierten Snapshot der aktuellen Aktion (EA-CNA-SRC-2/4) und der
live gelesenen committed lokalen Komponente, bei jedem Besuch neu gebildet.
So sieht Schritt 1 den vollständigen Kettenkopf und die Publikationsprüfung
der Schritte 10/11 die eigenen lokalen Commits.

**EA-CNA-WRT-6 (Queuegrenze).** Die Grenzen `queue_max_objects` und
`queue_max_bytes` begrenzen alle Zeilen des Namensraums einschließlich
Staging. Eine Überschreitung beim Staging (Schritt 8) ist ein lokaler
Ressourcenfehler vor Schritt 9: der Entwurf bleibt, die Finalisierung
blockiert, die Detailursache ist `Queuegrenze erreicht`.

**EA-CNA-WRT-7 (Verwahrung).** Die Beobachtung nach
`observe_writer_archive` erfasst für ein Netzprofil die lokale Komponente als
Bestand. Ihr Ort ist der kanonische Datenbankpfad, eingesetzt in die
unveränderte Domäne `EINSATZARCHIV-MANAGED-ARCHIVE-LOCATION-v1`. Das
Netzziel wird unmittelbar vor jeder Publikation mit seinem kanonischen
Wurzelpfad beobachtet. Vernichtung auf Netzprofilen bleibt außerhalb von
DRK-320 (`destruction_runtime.rs` bleibt LocalPath-only).

## 6. Publikation und abgeleitete Queue

**EA-CNA-PUB-1 (Ableitung).** Die Queue wird nie gespeichert. Ausstehend ist
jedes committed Objekt der lokalen Komponente, dessen Adresse im live
gelesenen Netzziel fehlt. Liegt dort an derselben Adresse ein anderes Byte,
ist das ein Byte-Konflikt: keine Publikation, kein Überschreiben,
Sicherheitsereignis nach §19.2.

**EA-CNA-PUB-2 (Reihenfolge).** Der Plan ordnet nach Sequenz (die
zwölfstellige Dezimalzahl vor dem ersten `_` des Dateinamens) aufsteigend;
Objekte ohne Sequenzpräfix stehen vor allen Einträgen in binärer
Adressordnung. Innerhalb einer Sequenz kommen alle Nicht-`.eip`-Objekte in
binärer Adressordnung und das `.eip` zuletzt. Grants liegen damit immer vor
ihrem Eintrag.

**EA-CNA-PUB-3 (Byte-Identität).** Publiziert wird mit Create-if-absent und
anschließendem Datei- und Verzeichnis-Flush genau die lokal committed
Bytefolge. Ein Objekt gilt erst als publiziert, wenn ein erneutes Lesen des
Netzziels dieselben Bytes liefert.

**EA-CNA-PUB-4 (Zustand).** Ist das Netzziel nicht erreichbar oder verliert es
eine zugesicherte Eigenschaft, bleibt der Sync-Zustand `Upload ausstehend`
mit Detailursache `Netzarchiv wartet`. Ist die Queue leer und kein Server
konfiguriert, ist der Zustand `lokal gesichert`. `synchronisiert` setzt
weiterhin die verifizierte Serverquittung voraus. Es gibt keinen fünften
Zustand.

**EA-CNA-PUB-5 (Kein Server-Upload vorher).** Ein Eintrag wird erst dann zum
Sync-Server übertragen, wenn seine Grants und sein `.eip` nach
EA-CNA-PUB-3 im Netzziel liegen. `SyncClient` prüft das vor dem
Server-Commit; seine lokale Archivquelle ist für Netzprofile die Vereinigung
aus EA-CNA-SRC-2, nicht ein `LocalPathBackend` des Netzziels.

**EA-CNA-PUB-6 (Nie Fallback).** Es gibt kein Ausweichen auf ein anderes
Ziel, keinen Teilwechsel und keine Umetikettierung.
`fell_back_to_another_target()` bleibt `false`.

**EA-CNA-PUB-7 (Prozess-Warteschlange).** `PublicationQueue` hält höchstens
einen Prozessplan. Ein neuer Plan verdrängt nie einen ausstehenden:
`publish` vereinigt den ausstehenden und den neuen Plan (byte-identische
Adressen einmal, abweichende Bytes lehnen mit Byte-Konflikt ab, Reihenfolge:
erst der ausstehende, dann neue Adressen) und prüft die Queuegrenze gegen die
Vereinigung. Nach einem Neustart entsteht der Plan wieder aus
EA-CNA-PUB-1; Dauerhaftigkeit kommt aus der Ableitung, nicht aus dem Slot.

**EA-CNA-PUB-8 (Auslöser und Wiederaufnahme).** Publiziert wird (a) in
Schritt 12 unmittelbar nach dem lokalen Commit, (b) nach der
Start-Wiederherstellung und (c) durch einen Hostlauf mit dem Backoff des
Profils (`resume_backoff_initial_ms`, verdoppelnd bis `resume_backoff_max_ms`,
höchstens `resume_max_attempts` Versuche je Prozess; danach Detailursache
`Wiederaufnahme erschöpft` bis zum nächsten Start). Schritt 12 lässt die
Finalisierung nie scheitern: der fachliche Abschluss ist nach Schritt 11
`lokal gesichert`.

## 7. Recovery-Quelle

**EA-CNA-REC-1 (Quelle).** Eine Netzprofil-Recovery-Laufzeit entsteht nur über
`RecoveryTestRuntime::with_archive_config` mit registrierter Komponente
(`open_current`), erfolgreicher SQLCipher-Capability (EA-CNA-WRT-4) und
erfolgreichem Capability-Test des Netzziels. `RecoveryTestRuntime::new` lehnt
Netzprofile weiter mit `EA-RECOVERY-TEST-SOURCE` ab.

**EA-CNA-REC-2 (Locks).** Capture, Restore-Bindung, Test und Import halten
zuerst den SQLCipher-Writer-Lock, dann den Writer-Lock des Netzziels. Der
Publikationslauf hält nur den Lock des Netzziels, die Bereinigung nur den
SQLCipher-Lock (per `try_lock`). Diese feste Reihenfolge schließt Deadlocks aus.

**EA-CNA-REC-3 (Capture).** Die Quelle ist die Vereinigung aus
`FsArchiveSource::open(netzziel)` und einem Export der lokalen Komponente.
Die Capture schreibt alle verwalteten Objekte der Komponente (committed und
Staging, `visit_managed_blobs`) mit exklusivem Anlegen in ein neues
Exportverzeichnis, flusht Dateien und Verzeichnisse, liest den Export zurück,
vergleicht ihn byte-genau mit der Komponente und bildet Inventarhash,
Kettenkopf und Signaturbindung über die Vereinigung aus Netzziel und
zurückgelesenem Export. Das Exportverzeichnis darf weder das Netzziel noch
ein Pfad darin sein. Ein bereits existierendes Exportverzeichnis lehnt ab.
Lokal committed, noch nicht publizierte `.eip`/`.eag` sind damit Teil der
signierten Quelle; eine Quelle ohne sie scheitert an Inventar oder Kettenkopf.
Die CLI verlangt dafür bei einem Netzprofil `--component-export <Verzeichnis>`
und lehnt den Schalter für LocalPath ab; ihre Vorprüfung liest nie das
Netzziel allein, die Sonde prüft die Capture über dieselbe Vereinigung. Die
Sonden der Inventar-Capture werden erst nach dem Export aus der Vereinigung
gewählt. Scheitert der Export mittendrin, bleibt ein Teilverzeichnis liegen,
das der Betreiber löschen muss; ein neuer Versuch lehnt es als vorhanden ab.
`capture_source_with_component_export` übernimmt die Sonden des Aufrufers
unverändert und wählt keine aus der Vereinigung; das tut nur die
Inventar-Capture. Der Desktop hat keinen Capture-Ablauf und bietet deshalb
keinen Export an.

**EA-CNA-REC-4 (Schnappschuss).** Der SQLCipher-Schnappschuss umfasst wie
bisher die ganze Datenbank, also auch Registrierung, Scope, lokale Objekte,
Staging und Sonde. Der Export ersetzt den Schnappschuss nicht; beide gehören
zum Sicherungssatz zusammen mit Anker, unveränderter Kopie des Netzziels,
Medien und Inventar.

**EA-CNA-REC-5 (Zielkopie).** Das Ziel erhält die unveränderte committete
Vereinigung: `materialize_network_archive_copy(kopie, export, ziel)` legt im
fehlenden oder leeren Zielordner jede Datei der Kopie des Netzziels und des
Exports exklusiv an, flusht Dateien und Verzeichnisse und prüft den
zurückgelesenen Baum byte-genau gegen die Vereinigung. Die Objekte sind
unveränderlich und inhaltsadressiert; bytegleiche Adressen fallen zusammen,
abweichende, ein nicht leerer Zielordner und ein Zielordner innerhalb der
Kopie oder des Exports lehnen mit `EA-RECOVERY-TEST-SOURCE` ab. Scheitert das
Anlegen mittendrin, bleibt ein Teilverzeichnis liegen, das der Betreiber
löschen muss. Die Zielinstallation öffnet dieses Verzeichnis
ohne Registrierung und ohne eigenen Startmodus. Der §19.3-Zieltest nutzt eine
eigene Nur-Lese-Ressource: `RecoveryTestRuntime::for_archive_copy` mit dieser
Vereinigung als `archive_directory` und dem Exportverzeichnis. Sie hat weder
`local_backend` noch Publikationsfähigkeit noch Registrierung und führt keinen
Capability-Test aus. Ihre Quelle ist
`FsArchiveSource::open(archive_directory)?.with_exact_component(&FsArchiveSource::open(export)?)`;
eine Zielkopie ohne die exportierten lokalen Objekte scheitert vor jedem
Restore. Die CLI verlangt in den Zielmodi (`restore-run`, `import`,
`status`, `failure-status`) für ein Netzprofil `--component-export` und
öffnet dann `for_archive_copy`; ohne den Schalter lehnt sie mit
`EA-RECOVERY-TEST-SOURCE` ab, für LocalPath bleibt der Weg unverändert und
der Schalter abgelehnt. Der Desktop bindet `for_archive_copy` nicht an: sein
Restore über `with_archive_config` lehnt ein unregistriertes Netzziel ab.
Capture ist dort mit `EA-RECOVERY-TEST-SOURCE` gesperrt. Die aktuelle
Autorität, der gemessene andere Rechner, die exakte Quell- und
Restore-Bindung und die Schutz-Locks gelten unverändert.

**EA-CNA-REC-6 (Keine Aktivierung).** Restore publiziert nichts, aktiviert
keinen Writer, legt keine Registrierung in der Zieldatenbank an und schreibt
nichts in die wiederhergestellte Quelle. Eine leere neue Queue am Ziel ersetzt
nie die wiederhergestellte.

## 8. Fehlercodes

| Code | Bedeutung |
|---|---|
| `EA-NATIVE-ARCHIVE-CONFIG` | Form: Netzprofil ohne DB-Pfad, LocalPath mit DB-Pfad, abweichende Datenbank |
| `EA-NATIVE-ARCHIVE-ROLE` | Registrierung ohne `OrganizationAdmin` |
| `EA-NATIVE-ARCHIVE-REGISTRATION-CONFLICT` | abweichende vorhandene Registrierung oder Scope-Zeile |
| `EA-NATIVE-ARCHIVE-POINTER-CONFLICT` | Profilzeiger im Netzziel nennt ein anderes Profil |
| `EA-NATIVE-ARCHIVE-PROFILE-MISMATCH` | LocalPath-Konfiguration trotz Registrierung |
| `EA-NATIVE-ARCHIVE-AUDIT` | Auditzeile nicht vorbereitbar oder nicht schreibbar |
| `EA-ARCHIVE-HEALTH-FILESYSTEM-SEMANTICS` | Capability-Test unvollständig (bestehender Code) |
| `EA-ARCHIVE-MISSING-LOCAL-COMMIT` | Komponente fehlt oder Ruheort-Messung scheitert (bestehend) |
| `EA-ARCHIVE-PENDING-PUBLICATION` | Queuegrenze der Komponente erreicht (bestehend) |
| `EA-ARCHIVE-BYTE-CONFLICT` | abweichende Bytes an derselben Adresse (bestehend) |
| `EA-OPERATOR-NETWORK-ARCHIVE-UNAVAILABLE` | Netzziel beim Kaltstart nicht lesbar |
| `EA-OPERATOR-NETWORK-ARCHIVE-CONFLICT` | Vereinigung beim Start abgelehnt |
| `EA-RECOVERY-TEST-SOURCE` | Recovery-Quelle unzulässig (bestehend) |

Kein Code und keine Diagnose nennt Pfade, Schlüssel oder Klartext.

## 9. Grenzen und Stufe-7-Evidenz

**EA-CNA-S7-1.** Der tatsächlich gemountete Netz-Positivzeuge (Protokoll,
Serverprodukt, Version, Mountoptionen, Failover, Disconnect/Remount auf jeder
Clientplattform) bleibt Stufe-7-Evidenz. Ein temporäres lokales Verzeichnis
mit Netzprofil ist nur ein Komponentenfixture.
`ea-archive-fs/tests/mac_smb_mount.rs` bleibt hinter `EA_TEST_MAC_SMB_MOUNT`.

**EA-CNA-S7-2.** Ein Kaltstart bei vollständig nicht lesbarem Netzziel ist
nicht abgedeckt (EA-CNA-SRC-4). AK 39 („finalisiert ohne Netz“) gilt für eine
laufende Sitzung, deren Netzziel nach dem Start wegfällt. Ein vollständiger
Offline-Kaltstart braucht eine verifizierte lokale Grundlinie und ist ein
eigener Auftrag.

**EA-CNA-S7-3.** Nicht in DRK-320: Profilwechsel nach Registrierung
(EA-CNA-REG-9), Vernichtung auf Netzprofilen, Trust-Publikation der
Administration über eine lokale Queue (sie schreibt weiter direkt in ein
erreichbares Netzziel) und eine produktive Sync-Server-Anbindung des Desktops.
