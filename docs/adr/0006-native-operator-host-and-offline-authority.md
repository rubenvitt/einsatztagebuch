# ADR 0006 — Native Operator-Hosts und getrennte Offline-Autorität

## Status

Implementierungsentscheidung für DRK-271, 2026-09-06. Plattformabnahme,
signierte Release-Pakete und Schlüsselverwahrung benötigen eigene Nachweise;
portable Tests oder Cross-Builds sind keine native Betriebsfreigabe.

Konfiguration, Aufrufe und Wiederaufnahme beschreibt die
[Operator-Anleitung](../operator-ceremony.md). Der separate Workflow
[`native-operator.yml`](../../.github/workflows/native-operator.yml) führt die
nativen Build- und Fixture-Prüfungen zusätzlich zum kanonischen Rust-/JS-Gate aus.

## Kontext

§6.8 verlangt eine Bindung an das tatsächliche Betriebssystemkonto, einen
frischen kontogeschützten Instanzschlüssel, echte Benutzerpräsenz und das Ende
einer Sitzung nach Sperre oder fünf Minuten Inaktivität. Der bisherige
synchrone Kern und seine Vertragstests liefern keine nativen Implementierungen.
Ein dauerhaftes `Unsupported` im CLI erfüllt den Arbeitsauftrag nicht.

Die Bereitstellung enthält zwei getrennte Rechner: Der Zielrechner hält seine
Geräte-/Instanzschlüssel und das verschlüsselte lokale Profil. Die dedizierte
Offline-Autorität führt den externen Identitätsabgleich, die Admin-Autorisierung
und die Root-Zeremonie aus. Private Admin-/Root-Schlüssel werden nicht an den
Zielrechner übergeben.

## Entscheidung

Der Rust-Kern bleibt frei von `unsafe` und verwendet kleine installierte native
Helper über anonyme Pipes. Der Produktionspfad prüft deren ausführbare Identität
vor der Übergabe von Anfragen. Der Dateiname allein gilt nicht als Nachweis.
Eine separate Fixture-Konstruktion existiert ausschließlich hinter
`test-support`; das normale CLI benutzt sie auch bei Cargo-Feature-Vereinigung
nicht. Testprogramme können damit denselben Parser, dieselben Signaturprüfungen
und denselben Sitzungswächter ohne produktive Schlüssel testen.

| Plattform | Native Oberfläche | Zusätzliche Laufzeit / Abnahme |
| --- | --- | --- |
| macOS | OpenDirectory, Data-Protection-Keychain, LocalAuthentication, CryptoKit; Apple-signierte Team-/Programmidentität | Signierter App-Verbund und passende Keychain-Entitlements. Für lückenlose Sperrereignisse: separater, lesender EndpointSecurity-Monitor mit eingeschränktem ES-Entitlement; der Konto-/Keychain-Helper bleibt beim tatsächlichen Benutzer. |
| Windows 11 ab Build 22000, x64/ARM64 | Binäre TokenUser-SID, Windows-Hello-Desktop-Interop, WTS, Benutzer-DPAPI, Credential Manager | .NET 10, exakt gepinnte NSec-/libsodium-Abhängigkeiten, passendes VC++-Runtime-Paket und geschütztes signiertes Installationsverzeichnis. |
| Ubuntu/GNOME | Tatsächliche Machine-ID/UID, logind, Polkit `auth_self` ohne Retention, PAM-entsperrte Login-Collection über libsecret | Distribuierte GLib/GIO-, JSON-GLib-, libsecret-, Polkit- und OpenSSL-Bibliotheken; reales PAM-/Polkit-/logind-Desktop-Szenario. |

Die konkreten Paketversionen, Hashes, Lizenzen und Buildbefehle liegen bei den
nativen Implementierungen. Insbesondere benennt
[`windows/DEPENDENCIES.md`](../../crates/ea-admin/native/windows/DEPENDENCIES.md)
NSec.Cryptography `[26.4.0]`, die aufgelösten nativen Bibliotheken, das exakte
Windows-SDK-Projektionspaket und die Release-Voraussetzungen. NuGet-Lockdateien
sind verbindlich; eine Versionserhöhung braucht eine erneute Prüfung. Die
Ubuntu-Systembibliotheken werden durch die Distribution gewartet und nicht
durch einen erfundenen Cargo-Pin ersetzt.

Der Rust-Abhängigkeitsgraph ergänzt vorhandene Workspace-Familien für
Archivprüfung, Trust-Zustand, HPKE/AEAD, JSON und Zeroisierung. Es entsteht
keine zweite Ed25519-/COSE-/CBOR-Implementierung im Rust-Host. Windows benutzt
die dokumentierte [NSec-Ed25519-Implementierung](https://nsec.rocks/docs/api/nsec.cryptography),
weil die gewählte native Windows-Kryptooberfläche keine entsprechende
Ed25519-Implementierung bereitstellt. Ubuntu benutzt die vorhandene
[OpenSSL-Ed25519-Oberfläche](https://docs.openssl.org/3.0/man7/EVP_SIGNATURE-ED25519/)
mit dem dafür vorgesehenen Digest-Modus. Native Schlüsseldateien, frei
eingetragene OS-Kennungen und Klartext-Passwortsammlung sind keine Fallbacks.

## Prozesse und Sitzungen

Jeder normale Aufruf hat ein gemeinsames Zeit- und Ausgabelimit. Der Host
übernimmt nur eine explizite kleine Menge von Desktop-Umgebungsvariablen;
Laufzeit-Start-Hooks, Profiling, Bibliotheksinjektion und ein alternativer
Systembus werden nicht vererbt. Die zurückgegebene Signatur muss unter genau
dem Schlüssel gültig sein, den der erzeugte COSE-Header nennt.

Ein separater `watch-session`-Prozess bestätigt erst nach Anmeldung seiner
nativen Ereignisquelle die Bereitschaft. Sperre, Abmeldung, Benutzerwechsel,
abgelaufene Überwachung, Verbindungsabbruch und unbekannte Abdeckung verriegeln
diese Provider-Instanz. Entsperren hebt die Verriegelung nicht auf. Die
Registry-Aktualisierung behält dieselbe Provider-Instanz und kann die Sperre
nicht durch einen neuen Wächter umgehen. macOS-Sitzungswechselmeldungen allein
sind kein Nachweis für jedes Bildschirm-Sperrereignis; dafür gehört der
EndpointSecurity-Monitor zum vorgesehenen Release-Paket.

Vor und nach jedem sensiblen Helper-Aufruf muss der laufende Wächter eine
neue zufällige Challenge innerhalb einer Sekunde bestätigen. Die Bestätigung
kommt aus seiner tatsächlichen nativen Ereignisschleife nach der Prüfung
ausstehender Ereignisse und ihrer Aktualität. Alte gepufferte Antworten,
unvollständige Meldungen oder ein angehaltener Wächter erneuern keinen Nachweis.
Diese Rückfrage verlängert die ursprüngliche Sitzungsgrenze nicht.

## Offline-Austausch und Wiederaufnahme

Der Dateiaustausch ist ein lokales Transportformat, keine neue Suite-v1-
Objektfamilie. Anfragen sind mit dem aktiven Geräteschlüssel signiert und an
Organisation, Kette, aktuellen Head, tatsächliche nächste Sequenz sowie die
konfigurierte Autorität gebunden. Genau eine kanonische äußere Darstellung
verhindert, dass Umformatieren einer signierten Anfrage eine neue Replay-ID
erzeugt. Antworten sind zusätzlich an einen frischen HPKE-Empfängerschlüssel
des Zielrechners verschlüsselt und vom aktiven Admin signiert.

Namen, Funktion und Commitment-Salz verlassen die geschützte lokale Eingabe
und SQLCipher nur in dieser verschlüsselten Antwort. Die Autorität erzeugt
das Salz selbst und prüft das daraus berechnete Commitment gegen ihre
kurzlebige Identitätsbestätigung. Ein Zielrechner kann seine behaupteten
Identitätsdaten nicht als Beweis in einer öffentlichen Anfrage mitsenden.

Der Zielrechner persistiert Anfrage und ephemeren Antwortschlüssel vor der
Veröffentlichung in SQLCipher. Bei Wiederaufnahme werden dieselben Bytes und
dieselbe Autorisierung verwendet. Ein gesperrtes/fehlendes natives Schlüssel-
oder Datenbankmaterial wird nicht durch eine leere Neuinitialisierung ersetzt.
Temporäre Dateien werden vollständig geschrieben und synchronisiert, bevor
ein Rename unter einer Betriebssystem-Dateisperre sie sichtbar macht.
Vorhandene abweichende Bytes werden nicht überschrieben. Das Verfahren
benötigt keine Hardlinks auf dem Austauschmedium.

Das Binding-Profil und das Vorbereitungsjournal bilden einen gemeinsamen
lokalen Commit. Aktivierung braucht eine eigene Autorisierung gegen denselben
Previous Head und bleibt bis zur erneuten Prüfung von Konto, Instanzschlüssel,
Profil und Audit zurückgehalten. Fertig ist die Bereitstellung erst nach
erneutem vollständigem Registry-Check und erfolgreicher nativer Anmeldung.
Für die Offline-Autorität müssen beide Replay-Dimensionen, das signierte Audit
und die genaue Antwort atomar persistiert werden. Ein unklarer Altzustand
darf keine neue Autorisierung mit anderer Nonce auslösen.

Auch ein Widerruf persistiert seinen exakten Registry-Entwurf vor der ersten
Autorisierungsanfrage. Ein späterer Prozess übernimmt dessen ursprüngliche
Zeitfelder; ein anderer Head, Admin oder Wirksamkeitsbereich wird abgewiesen.
Auf dem Zielrechner werden beide Replay-Dimensionen, Root- und Widerrufs-Audit,
die genaue Autorisierung und das Ergebnis gemeinsam gebucht. Schlägt eine
dieser Buchungen fehl, bleiben alle diese Änderungen aus; die gespeicherte
öffentliche Root-Signatur erlaubt denselben Versuch nach Wiederaufnahme.

Bereits vollständig abgeschlossene Austauschdateien dürfen auf dem Medium
bleiben. Die Authority prüft deren exakte gespeicherte Anfrage und Signatur,
bevor sie die schon festgeschriebene Antwort erneut ausgibt. Neue und noch
unvollständige Anfragen müssen weiterhin zum aktuell gewählten Head passen.

## Restore-Grenze

Die öffentliche Installations-ID ist kein Geheimnis. Ein unabhängiger geheimer
Marker außerhalb des vorgesehenen Backups und der native Kontospeicher werden
gemeinsam zur Entschlüsselung benötigt. Installations-/Restore-Werkzeuge müssen
den alten Namensraum beim tatsächlichen Neuaufsetzen ungültig machen und
anschließend Widerruf und externe Neuzuordnung verlangen.

Diese Konstruktion beweist keine absolute Unwiederherstellbarkeit einer
unverwalteten vollständigen Kopie aller beteiligten Speicherorte auf demselben
Gerät. Ebenso ist ein beibehaltener Marker bei einem unkontrollierten
In-place-Restore kein automatisch erkanntes neues Gerät. Solange diese
normative Grenze nicht durch den tatsächlich abgenommenen Installations-/
Restore-Pfad geschlossen ist, darf §6.8 nicht als vollständig abgenommen
ausgewiesen werden. Backup-Flags und portable Testdaten allein schließen sie
nicht.

## Prüfnachweise

Rust-Gates prüfen den realen Trust-/SQLCipher-/Audit-Pfad einschließlich
Abbrüchen, Replay, Identitätswechsel, verlorenem Instanzschlüssel und
Reader-Commitments. Native Unterverzeichnisse behalten eigene Protokoll-,
Krypto-, Paket- und Buildtests. Die Betriebsabnahme muss zusätzlich die
signierten installierten Programme, echte Konten und Präsenzdialoge,
Sperre/Entsperre, Kontowechsel und den tatsächlichen Restore-Pfad einschließen.
