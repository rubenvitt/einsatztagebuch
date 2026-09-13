# Geräteprüfung

`OperatorRuntime` liest den tatsächlichen `DevicePostureProvider` vor und nach
der nativen Benutzerbestätigung sowie beim erneuten Prüfen einer privilegierten
Sitzung. Vier belegte `Pass` erlauben diese Sitzung. Für nicht automatisch
belegbare Voraussetzungen kann ein aktiver OrganizationAdmin einen engen
signierten Go-live-Nachweis ausstellen. Erst sein verifizierter dauerhafter Import
am exakten Ziel erlaubt die dokumentierten `Unknown`-Voraussetzungen. Ein
gemessenes `Fail` und ein Providerfehler verweigern die Sitzung weiterhin.
Konfiguration und Umgebungsvariablen können keinen Testanbieter oder Pass-Wert
auswählen. Rohmessungen und dokumentierte Bestätigung bleiben getrennt sichtbar.

Der Adapter startet ausschließlich feste Systemprogramme ohne Shell-Eingaben,
Profile oder geerbte Start-Hooks. Jeder Aufruf hat zwei Sekunden Zeit und maximal
4096 Byte Standardausgabe. Fehler, Zeitüberschreitung, unbekannte Ausgabe und
ein Aufruf auf der falschen Plattform ergeben `Unknown`. Standardfehler werden
verworfen. Nur die zwölf bestehenden Beweiscodes verlassen den Messadapter;
Kontonamen, Pfade und Inventare gelangen nicht in Bericht oder Audit.

| Signal | Gemessener Umfang | Grenze |
| --- | --- | --- |
| macOS FileVault | `/usr/bin/fdesetup status`, ausschließlich abgeschlossener On-/Off-Status | System-/Startvolume. Weitere Datenträger und laufende Konvertierung sind damit nicht belegt. |
| Ubuntu Root-Dateisystem | `findmnt` ermittelt das Blockgerät; `lsblk --inverse` liefert dessen Abstammung | Nur eine eindeutige einfache Disk-/Partition-/LVM-/Crypt-Kette. RAID, Multipath, Subvolumes und andere Topologien bleiben offen. Weitere Datenträger sind nicht belegt. |
| Windows BitLocker | Explizites Systemmodul prüft Schutz und vollständige Verschlüsselung aller gemeldeten OS-/FixedData-Volumes | Ein ungeschütztes Volume ergibt Fail; fehlende Privilegien/Module oder unbekannte Eigenschaften bleiben Unknown. |
| Windows automatische Sperre | Positive gültige `InactivityTimeoutSecs`-Maschinenrichtlinie | Eine fehlende oder deaktivierte Richtlinie bleibt Unknown: andere Sperrmechanismen könnten aktiv sein. |
| Kontoexklusivität | Keine automatische positive Behauptung | Eine SID, UID oder ein Kontoname beweist keine ausschließliche menschliche Nutzung. |
| Unterstützter Patchstand | Keine automatische positive Behauptung | Eine Versionsnummer beweist keine aktuelle Wartungs-/Patchkonformität. |
| macOS/Ubuntu automatische Sperre | Unknown | Einzelne Preferences beweisen ohne wirksame Sitzungs-/Richtlinienauflösung keine erzwungene Sperre. |

Die Messung allein ist keine produktive Gerätefreigabe. Kontoexklusivität und
Patchkonformität bleiben auf allen Zeilen automatisch unbelegt. §18.4 erlaubt
ihre nachvollziehbare Dokumentation; hierfür gilt das interne
[Go-live-Dokumentprofil](superpowers/specs/2026-09-09-einsatzarchiv-go-live-posture-profile.md).
Der Nachweis bindet Installation, natives Konto, Gerät, Zertifikat/Bindung,
Organisation/Kette, zuverlässig gemessenen OS-Build und exakten Registry-Kopf.
Er gilt höchstens 24 Stunden und höchstens bis zum Registry-notAfter;
die Endzeit ist exklusiv. Jeder Kopf- oder OS-Build-Wechsel verlangt einen
neuen Nachweis. Ausstellen erfordert frische native Admin-Präsenz. Normale
Wiederanmeldung und produktive Dienste akzeptieren diesen Dokumentationszweck
nicht als Ersatz für ihren eigenen Zweck.

Das öffentliche Belegdokument muss die tatsächlich geprüften Voraussetzungen,
ihre Prüfung und den Speicherort produktiver Daten nachvollziehbar benennen.
Die Anwendung speichert nur dessen Hash, nicht den Inhalt. Admin und Betreiber
bewahren den öffentlichen Beleg separat auf. Der Nachweis sagt nicht, dass eine
automatische Messung erfolgreich war.

Am Ziel wird der öffentliche Kontext exportiert, beim Admin der Nachweis
ausgestellt und am Ziel importiert:

```sh
einsatzarchiv --trust-anchor anchor.etb posture target --operator-config target.json --output target-context.json
einsatzarchiv --trust-anchor anchor.etb posture issue --operator-config admin.json --posture-target target-context.json --evidence-reference public-evidence.txt --valid-for-ms 86400000 --output posture.cbor
einsatzarchiv --trust-anchor anchor.etb posture import --operator-config target.json --posture-document posture.cbor
```

Ausgabedateien müssen neu sein. Der Zielkontext ist nur ein Transport von
Behauptungen: der Import vergleicht ihn mit den eigenen nativen Fakten und
verlangt die genaue aktuelle Unknown-Maske. Spätere Zulassungen prüfen die
Messung erneut, erlauben neu messbare Pass-Werte und verweigern jede zusätzlich
unbelegte, nicht dokumentierte Voraussetzung. Signaturfehler, Providerfehler,
gemessenes Fail, abgelaufene oder manipulierte Daten sperren weiter. Der
SQLCipher-Speicher führt die exakten Dokumentbytes und einen eigenen dauerhaften
Wall-Clock-Rückdrehschutz; er verändert keinen signierten Trust-Zeitboden.

Die Rust-Auswertung des Go-live-Aggregats nimmt hierfür ausschließlich eine
opaque, an die Runtime gebundene `VerifiedPostureAdmission` entgegen und prüft
sie bei der Auswertung erneut. Dokumentierte Zeilen erhalten
`EA-GOLIVE-POSTURE-DOCUMENTED`; der Betriebsbericht führt Rohmesscodes und
Dokument-/Beleghash sowie Frist getrennt. Dies bestätigt keine sonstige offene
Go-live-Anforderung und ist keine Plattformabnahme.

Die tragenden Plattformbeschreibungen sind Apples
[FileVault-Verwaltung](https://support.apple.com/en-gb/guide/deployment/dep0a2cb7686/web),
Microsofts [Get-BitLockerVolume](https://learn.microsoft.com/en-us/powershell/module/bitlocker/get-bitlockervolume?view=windowsserver2025-ps)
und [Machine inactivity limit](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-machine-inactivity-limit)
sowie die [lsblk-Dokumentation](https://man7.org/linux/man-pages/man8/lsblk.8.html).
Der Windows-Systempfad verwendet denselben Object-Manager-Systemroot wie
ADR-0006. Es entsteht keine neue Cargo-Abhängigkeit oder FFI-Ausnahme.

Tests prüfen die Ausgabegrenzen, Zeitüberschreitung, Fehler, mehrdeutige
Topologien und den Erhalt unbekannter Voraussetzungen. Der native Hosttest
berichtet nur tatsächlich gemessene Beweiscodes. Parser-/Fixture-Tests auf
macOS belegen keinen realen Windows-/Ubuntu-Betrieb; deren installierte
Plattformabnahme bleibt separat erforderlich.
