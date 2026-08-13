# Einsatzarchiv v0.1 – Technische Design-Spezifikation

**Status:** Reviewfassung nach freigegebenem Lösungsdesign
**Datum:** 13. August 2026
**Ausgangsbasis:** PRD „Einsatzarchiv“, Version 0.1
**Produkt:** Offline-first Desktopanwendung mit selbst gehostetem Blind-Sync-Server

## 1. Zweck und normative Sprache

Diese Spezifikation übersetzt das PRD in ein implementierbares Systemdesign. Sie beschreibt Produktgrenzen, Vertrauensmodell, Daten- und Dateiformate, Zustandsübergänge, Protokolle, Fehlerverhalten, Plattformen und Abnahmekriterien.

Die Schlüsselwörter **MUSS**, **DARF NICHT**, **SOLL**, **SOLL NICHT** und **DARF** sind normativ zu verstehen. Ein Release darf von einer MUSS-Anforderung nicht abweichen. Eine Abweichung von SOLL erfordert eine dokumentierte Sicherheits- oder Betriebsbegründung.

### 1.1 Bewusste Abweichung vom Ausgangs-PRD

Microsoft Access ist vollständig außerhalb des Scopes. Insbesondere gibt es in v0.1:

- keinen Access-Treiber und keine Access-Dateiverarbeitung,
- keine technische Inventarisierung einer Access-Datenbank,
- keinen Import historischer Einsätze,
- keinen `legacyImport`-Eintragstyp,
- kein Feld `legacy-access-import`,
- keinen Migrationsbericht und kein Access-Abnahmekriterium,
- keine Access-bezogenen Go-live-Aufgaben oder Risiken.

Der kryptografische Begriff **Access Grant** beziehungsweise **Zugriffsfreigabe** bleibt erhalten. Er bezeichnet einen signierten Schlüsselumschlag und hat keinen Bezug zu Microsoft Access. Dies ist die einzige bewusste Scope-Abweichung vom Ausgangs-PRD.

## 2. Zielbild und Scope

Einsatzarchiv dokumentiert Einsätze nach deren Abschluss. Ein berechtigter Writer erfasst einen Entwurf, prüft ihn und finalisiert ihn unwiderruflich. Die Finalisierung erzeugt zuerst ein dauerhaftes lokales, verschlüsseltes und signiertes Archivpaket. Erst danach wird es asynchron an einen Server übertragen, der keine fachlichen Inhalte entschlüsseln kann.

Reader replizieren verschlüsselte Objekte, prüfen Trust, Signaturen, Hash-Kette, Vollständigkeit und Evidence und entschlüsseln ausschließlich lokal. Ein eigenständiges Recovery-Werkzeug kann das Archiv auf einem frischen Rechner ohne Server prüfen und entschlüsseln.

### 2.1 Enthalten

- Offline-Erfassung und absturzsichere Entwürfe
- unveränderliche Finalisierung mit genau einem aktiven Writer
- lokales, offenes und serverunabhängiges Archiv
- Ende-zu-Ende-Verschlüsselung mit einem Ciphertext und Empfänger-Grants
- Reader-, Writer-, Admin-, Recovery-, Historical-Grant-Authority-, Sync-Server-Admin- und Server-Schlüsselrollen
- blinder Sync, idempotente Übertragung, Receipts und Fork-Schutz
- lokale Reader-Suche, Nachträge und kontrollierte Exporte
- Standard- und Evidence-Grade-Profil
- RFC-3161-Zeitstempel und additive Evidence Renewals
- Writer-Wechsel, Reader-Freigabe, Widerruf und historischer Re-Grant
- kontrollierter Vernichtungsprozess mit Nachweis
- Stammdatenpflege und dokumentierter CSV-Import für Personen und Fahrzeuge
- plattformübergreifende Desktop-, Admin- und Recovery-Funktionen

### 2.2 Nicht-Ziele

- laufendes Einsatztagebuch während eines Einsatzes
- Dispositions-, Alarmierungs- oder Leitstellenintegration
- Patientenakte oder medizinische Behandlungsdokumentation
- identifizierende Patientendaten
- mehrere gleichzeitig schreibende Offline-Writer
- Änderung oder Löschung finalisierter Inhalte in der normalen Anwendung
- KI-Zusammenfassung oder automatische Texterkennung
- öffentliche Freigabelinks
- serverseitige Suche in Einsatzinhalten
- Netzlaufwerkpfade ohne freigegebenes, versioniertes Archiv-Backendprofil
- qualifizierte elektronische Signatur einer natürlichen Person
- Zertifizierung der Gesamtlösung nach BSI TR-ESOR
- Verhinderung von Screenshots oder Abschriften durch autorisierte Reader
- kryptografischer Rückruf bereits entschlüsselter Daten
- Microsoft-Access-Anbindung oder Migration historischer Einsätze

## 3. Verbindliche Produktgarantien

Bei korrekter Einrichtung und korrektem Betrieb gelten folgende Invarianten:

1. Es existiert zu einem Zeitpunkt genau ein autorisierter aktiver Writer.
2. Jeder Ketteneintrag besitzt eine nie wiederverwendete Sequenz und bindet den direkten Vorgänger-Hash.
3. Finalisierte `.eip`-Bytes werden niemals geändert oder überschrieben. Eine autorisierte Vernichtung darf nur das vollständige Objekt entfernen und durch einen getrennten `.eds` ersetzen.
4. Korrekturen sind neue signierte Nachträge; das Original bleibt sichtbar.
5. Ein fachlicher Payload wird genau einmal mit einem neuen zufälligen CEK verschlüsselt.
6. Jeder Empfänger erhält einen getrennten, signierten Grant für denselben CEK.
7. Ein produktiver Eintrag besitzt vor dem Commit genau einen gültigen Grant für den aktiven Recovery-Empfänger.
8. Auf einem Writer-Gerät existiert kein privater Reader-, Recovery-, Historical-Grant-Authority- oder Key-Approver-Schlüssel.
9. Nach Finalisierung persistiert der Writer weder CEK noch entschlüsselbaren Entwurfsschlüssel.
10. Der Sync-Server besitzt keine privaten Schlüssel zur Entschlüsselung von Einsätzen oder Erzeugung gültiger Grants.
11. Das lokale Archiv ist ohne Server und ohne mutable Statusdatenbank verifizierbar.
12. Schema-, Format- und Krypto-Version werden unabhängig geführt; alte Objekte bleiben byteidentisch.
13. Sync-, Verifikations-, Evidence-, Eintrags- und Vernichtungsprozessstatus werden getrennt dargestellt.
14. Eine Hash-Kette allein wird nicht als rechtliche oder organisatorische Revisionssicherheit beworben.
15. Jeder zur gebundenen Registry-Version aktive Reader erhält vor dem Commit genau einen initialen Grant.
16. Authentische Offline-Recovery beginnt an einem unabhängig verwahrten Trust Anchor; ein Trust Bundle aus dem zu prüfenden Archiv allein begründet kein Vertrauen.
17. Jeder `operator`-Snapshot stammt aus einem gültigen Root-signierten, geräte- und OS-kontogebundenen Operator-Binding und ist kein freies Eingabefeld.

## 4. Plattform- und Release-Matrix

Folgende Plattformen sind für v0.1 echte Release-Gates:

| Komponente | Verbindliche Plattformen |
|---|---|
| Writer | von Microsoft unterstützte Windows-11-Releases `x86_64`; zur Release-Freigabe aktuelle und vorherige macOS-Hauptversion auf `arm64`, zusätzlich `x86_64`, sofern diese macOS-Version Intel offiziell unterstützt; Ubuntu 24.04 LTS `x86_64` |
| Reader | dieselben OS-/Architekturkombinationen |
| Administration | dieselben OS-/Architekturkombinationen |
| Recovery-/Admin-CLI | dieselben OS-/Architekturkombinationen |
| Sync-Server | Linux-OCI-Container auf `amd64` |

Jedes Release enthält eine signierte, versionierte `support-matrix.json`. Sie friert die zuvor dynamisch beschriebenen Plattformgruppen ein und pinnt pro Kombination die minimale und maximale freigegebene OS-Version beziehungsweise den Build, Architektur, Installerformat, Key-Provider und getestetes lokales Dateisystem. CI und manueller Release-Nachweis verwenden genau diese Datei; Änderungen daran sind Releaseänderungen. Auf jeder Kombination laufen Kryptografie-/Format-Golden-Tests, Key-Provider-, Dateisystem- und Installer-Smokes. Vollständige Writer-, Reader-, Admin- und CLI-Ende-zu-Ende-Tests laufen mindestens auf der jeweils minimalen und höchsten gepinnten OS-Version jeder Architektur.

Eine Funktion gilt nicht als plattformübergreifend, nur weil sie durch Tauri oder Rust kompiliert. Atomare Dateisystemoperationen, Keystore-Verhalten, Sperren, Crash-Recovery, Paketsignierung, Installer und Ende-zu-Ende-Abläufe MÜSSEN gemäß der gepinnten Matrix geprüft werden. Weitere Architekturen, insbesondere Windows on Arm und Linux `arm64`, sind außerhalb v0.1 und dürfen später nur durch eine erweiterte Release-Matrix aufgenommen werden.

## 5. Systemarchitektur

### 5.1 Repository- und Komponentenmodell

Das Produkt wird als modulares Monorepo umgesetzt:

- **Rust-Vertrauenskern:** Format, deterministisches CBOR, COSE, Kryptografie, Trust Registry, Hash-Kette, Archivtransaktionen, Verifikation und Recovery.
- **Tauri-2-Desktopanwendung:** gemeinsame Binär- und UI-Basis für Writer, Reader und Administration.
- **React-19-/TypeScript-Oberfläche:** rollenabhängige Ansichten, Eingabe, lokale Suche und technische Statusdarstellung auf Basis von Ant Design 6.
- **Axum-Sync-Server:** Geräteanfragen, Trust-Verteilung, Objektannahme, Kettenprüfung, Receipts, Checkpoints und Evidence-Aufträge.
- **Recovery-/Admin-CLI:** Initialisierung, Prüfung, Entschlüsselung, Re-Grant, Berichte, Schlüsselzeremonien und kontrollierte Vernichtung.
- **PostgreSQL:** ausschließlich technische Indizes und transaktionale Serverzustände.
- **S3-kompatibler Object Store:** content-addressed Binärobjekte ohne fachliche Metadaten.

Kryptografische oder formatkritische Logik DARF NICHT in TypeScript oder separat im Server nachgebaut werden. Desktop, Server und CLI verwenden dieselben Rust-Crates und dieselben Testvektoren.

### 5.2 Rollenzuordnung der Desktopanwendung

Die gemeinsame Desktopanwendung schaltet Funktionen ausschließlich anhand gültiger signierter Gerätezertifikate frei. Ein lokaler Konfigurationswert oder UI-Schalter DARF keine Rolle hinzufügen oder erweitern.

Ein Writer-Gerät DARF niemals zugleich einen privaten Reader-, Recovery- oder Historical-Grant-Authority-Schlüssel besitzen. Admin und Reader dürfen auf demselben physischen Gerät nur als getrennt zertifizierte Rollen mit getrennten Schlüsseln existieren. Die Admin-Rolle allein verleiht keinen Inhaltszugriff.

### 5.3 Vertrauenszonen

1. **Offline-Vertrauenszone:** Organisations-Root, Recovery- und Historical-Grant-Authority-Schlüssel samt Sicherungsmedien.
2. **Desktop-/Archivzone:** Writer, Reader, Admin, verschlüsselte lokale Datenbanken und lokales Archiv.
3. **Serverzone:** Axum, PostgreSQL, Object Store und Server-Belegschlüssel.
4. **Externe Evidence-Zone:** RFC-3161-Time-Stamp-Authority; sie erhält nur Hashwerte.

Kein Vertrauensübergang darf allein durch einen Server-Datenbankeintrag erfolgen. Geräteautorität, Widerrufe, Writer-Wechsel und Richtlinien leiten sich aus Root-signierten append-only Trust-Objekten ab.

### 5.4 UI-Designsystem

Ant Design 6 ist die verbindliche Komponentenbasis. Die konkret freigegebene Minor- und Patch-Version wird im Lockfile fixiert und nur nach visuellen, funktionalen und Accessibility-Regressionstests aktualisiert.

Die Anwendung verwendet `ConfigProvider` mit deutscher Locale, zentralen Design Tokens und `zeroRuntime: true`. Ein gepinntes Build-Skript erzeugt mit `@ant-design/static-style-extract` aus exakt derselben Token-Konfiguration eine statische CSS-Datei, die als lokale, gehashte Ressource in das Tauri-Paket eingeht. Runtime-Style-Injection und externe Styles sind durch die Content-Security-Policy verboten. Modals, Messages und Notifications werden über den Ant-`App`-Kontext und nicht über kontextlose statische Methoden erzeugt.

Ant-Komponenten liefern Form, Select/Autocomplete, Table, Descriptions, Steps, Alert, Result, Modal/Drawer, QRCode, Tags und Tooltips. Darauf liegen kleine domänenspezifische Komponenten:

- `VerificationBadge`
- `SyncStatus`
- `EvidenceStatus`
- `FingerprintBlock`
- `ChainIntegrityRail`
- `IrreversibleActionConfirm`
- `PatientDataWarning`

Die visuelle Sprache ist bewusst operativ und nicht dashboardhaft:

| Token | Wert | Verwendung |
|---|---:|---|
| `eaInk` | `#172033` | Haupttext und App-Rahmen |
| `eaSurface` | `#F5F7FA` | ruhige Arbeitsfläche |
| `eaAction` | `#245EA8` | normale Interaktionen |
| `eaDanger` | `#C6352B` | unwiderrufliche oder ungültige Zustände |
| `eaVerified` | `#187255` | vollständig verifizierte Zustände |
| `eaWarning` | `#A65F00` | ausstehende oder überfällige Zustände |

Normale Oberflächen verwenden die plattformeigene UI-Schriftfamilie; Hashes, Sequenzen und Fingerprints verwenden `ui-monospace`. Es werden keine Webfonts geladen. Der Writer nutzt komfortable Formdichte, Reader und Admin dürfen Ants Compact-Algorithmus gezielt für Tabellen und technische Daten verwenden.

Das charakteristische Element ist die **Integritätskette**: eine zurückhaltende Leiste aus tatsächlich vorhandenen Sequenz-, Signatur-, Receipt- und Evidence-Knoten. Sie visualisiert reale Prüfschritte und ist keine dekorative Fortschrittsanzeige.

Anwendungseigene Icons stammen ausschließlich direkt aus `@phosphor-icons/react`, nicht aus dem `react-icons`-Sammelpaket. Imports erfolgen pro Icon aus dem CSR-Pfad; Wildcard- oder dynamische Vollkatalogimporte sind verboten. Standardgewicht ist `regular`, `fill` bleibt aktiven oder bestätigten Zuständen vorbehalten. Dekorative Icons erhalten `aria-hidden`; Icon-only-Buttons benötigen einen zugänglichen Namen und Tooltip. Ein Icon darf niemals allein einen Sicherheitsstatus vermitteln.

Bewegung wird sparsam auf bestätigte Zustandsübergänge begrenzt. `prefers-reduced-motion` wird respektiert. Die Oberfläche verwendet sichtbare Fokusrahmen, semantisches DOM und Text zusätzlich zu Farbe und Icon.

## 6. Rollen und Schlüssel

### 6.1 Schreibnutzer und Writer-Gerät

Der Schreibnutzer darf Stammdaten pflegen, einen Entwurf bearbeiten, ihn verwerfen, prüfen und finalisieren sowie technische Sync-Zustände sehen. Er darf finalisierte Inhalte nicht öffnen, entschlüsseln, ändern oder über die Anwendung löschen.

Das Writer-Gerät besitzt einen Ed25519-Signaturschlüssel. Dieser signiert Einsatzpakete und initiale Grants. Er dient nicht zur Inhaltsentschlüsselung.

### 6.2 Reader-Nutzer und Reader-Gerät

Ein Reader besitzt zwei getrennte Schlüsselpaare:

- X25519 für HPKE-Entkapselung von CEKs,
- Ed25519 für Geräteauthentisierung, Acknowledgements und lokale Audit-Ereignisse.

Der Reader prüft jedes Objekt vollständig vor der Entschlüsselung. Standardmäßig bietet er keinen unverschlüsselten Massenexport.

### 6.3 Organisationsadministrator / Key Approver

Der Organisationsadministrator vergleicht Fingerprints und ist die menschliche Autorität für Gerätefreigaben, Reader-Widerrufe, Schlüsselrotationen, Richtlinien und Writer-Wechsel. Er autorisiert diese Vorgänge mit einem getrennten Ed25519-Administratorschlüssel und der Root-zertifizierten Capability `organizationAdminApprove`. Die Person mit physischem Zugriff auf die Offline-Root-Schlüsselquelle prüft anschließend die Admin-Autorisierung und führt die Root-Signatur aus; dies kann organisatorisch dieselbe Person sein, bleibt aber ein getrennter technischer Schritt. Das resultierende Gerätezertifikat, Registry-, Policy- oder Transition-Ereignis MUSS zusätzlich vom Organisations-Root signiert sein; die Admin-Signatur allein erweitert keine Geräteautorität.

Der Administrator darf Anträge ablehnen, Root-Signaturen kontrolliert einspielen und die resultierenden Trust-Objekte verteilen. Seine Rolle enthält keine automatische Inhaltsentschlüsselung, Writer-, Grant- oder Server-Belegsignatur. Jede Root-Zeremonie nach dem Bootstrap bindet den Hash des in Abschnitt 11.1 definierten `organizationAdminAuthorization`-Objekts und wird lokal auditiert. Einzige Ausnahme sind initiales Root-Zertifikat und mindestens zwei initiale Admin-Zertifikat-/Operator-Binding-Paare; ihre exakten Hashes und Paarungen werden vor der ersten Admin-Autorisierung im unabhängigen Recovery-Trust-Anchor aus Abschnitt 16.1 gepinnt.

Vor Produktivbetrieb existieren mindestens zwei getrennt gehaltene aktive Administratorschlüssel samt verifizierter Sicherung. Die Freigabe oder Rotation eines Administratorschlüssels muss durch einen anderen aktiven Administrator autorisiert und danach Root-signiert werden. Geht ein Schlüssel verloren, autorisiert der zweite Administrator seinen Widerruf und Ersatz. Sind alle aktiven Administratorschlüssel und ihre Sicherungen verloren, gibt es keinen Root-only-Bypass; die Organisation blockiert administrative Änderungen und muss kontrolliert aus einem verifizierten Backup wiederhergestellt oder als neue Organisation initialisiert werden.

Für Mehr-Augen-Aktionen besitzt ein **Key Approver** ein eigenes Ed25519-Schlüsselpaar und ein Root-signiertes Zertifikat mit einer oder beiden Capabilities `historicalGrantApprove` und `destructionApprove`. Eine Autorisierung benötigt in v0.1 COSE-Signaturen von mindestens zwei unterschiedlichen, zur Ausführungssequenz aktiven Approver-Zertifikaten mit der passenden Capability und unterschiedlichen pseudonymen `subjectId`-Werten. Eine einzelne Root-, Admin-, Recovery- oder Grant-Authority-Signatur ersetzt diese zwei Freigaben nicht.

### 6.4 Organisations-Root

Der Organisations-Root ist ein offline verwahrtes Ed25519-Schlüsselpaar. Er signiert Gerätezertifikate, Registry-Versionen, Widerrufe, Richtlinien und Schlüsselübergänge. Er entschlüsselt keine Einsätze und wird nicht dauerhaft auf dem Server gespeichert.

### 6.5 Recovery Custodian und Historical Grant Authority

Der Recovery Custodian verwahrt ausschließlich einen X25519-KEM-Schlüssel zum Entkapseln historischer CEKs. Dieser Schlüssel besitzt keine Signaturbefugnis.

Historische Grants werden von einer getrennten **Historical Grant Authority** mit einem Ed25519-Signaturschlüssel und der ausdrücklich zertifizierten Capability `historicalGrant` signiert. Initiale Grants signiert ausschließlich der aktive Writer mit der Capability `initialGrant`. Eine Person darf beide Offline-Funktionen organisatorisch wahrnehmen; Schlüssel, Capabilities und Freigabeschritte bleiben dennoch technisch getrennt.

Jeder historische Grant benötigt zusätzlich ein von zwei `historicalGrantApprove`-Schlüsseln signiertes `GrantAuthorization` über die expliziten Ziel-Entry-Hashes, den neuen Empfänger und den Zweck. Private Recovery- und Grant-Authority-Schlüssel dürfen weder auf dem Writer noch auf dem Sync-Server liegen. Sie werden mindestens auf zwei getrennten, verschlüsselten Medien oder geeigneten Hardware-Token gesichert.

### 6.6 Server-Belegschlüssel

Der Server besitzt einen eigenen Ed25519-Schlüssel für Receipts und Checkpoints. Sein Public Key und jede Rotation müssen Root-signiert sein. Der Schlüssel kann keine fachlichen Inhalte entschlüsseln.

### 6.7 Sync-Server-Administrator

Der Sync-Server-Administrator betreibt Linux-Container, PostgreSQL, Object Store, Backups, Restore, Monitoring und signierte Softwareupdates. Er darf technische Zustände, Kapazitäten und Security Events einsehen, aber keine Einsatzinhalte entschlüsseln, CEKs entkapseln, Grants erzeugen, Writer-Signaturen leisten, Registry-Autorität hinzufügen oder fachliche Objekte verändern.

Administrative Serverzugänge und der Server-Belegschlüssel sind getrennt. Ein Serveradministrator erhält keine Geräte-Capability aus der Organisationsregistry. Mindestens privilegierte Anmeldung, Konfigurationsänderung, Backup/Restore, Object-Lock-Änderung, Schlüsselrotation und Security-Event-Bearbeitung werden technisch auditiert; das Audit enthält keine fachlichen Klartexte.

### 6.8 Menschliche Nutzeridentität

v0.1 verwendet verbindlich eine **geräte- und OS-kontogebundene Operator-Identität**. Gemeinsame oder frei eingegebene Funktionskennungen sind unzulässig. Ein Root-signiertes `operatorBinding` bindet eine pseudonyme `operatorSubjectId`, ein gesalzenes Operator-Profil-Commitment, Gerätezertifikat-Hash, erlaubte Rolle, einen Hash des stabilen lokalen OS-Kontobezeichners, den Thumbprint eines getrennten Operator-Instanzschlüssels sowie Wirksamkeits- und Widerrufsinformationen. Seine Ausstellung oder Änderung benötigt eine `organizationAdminAuthorization`. Einzige Ausnahme sind die mindestens zwei initialen Admin-Bindings aus dem Pre-Registry-Bootstrap: Sie werden einmalig unmittelbar vom Root signiert und mitsamt ihren Zertifikaten in der unabhängigen Anchor-Vorstufe gepinnt; danach gilt die normale Autorisierungspflicht ausnahmslos.

Der stabile Kontobezeichner ist gerätelokal Windows-SID, macOS-Verzeichnis-ID plus UID oder Linux-Machine-ID plus UID; archiviert wird ausschließlich `SHA-256("EINSATZARCHIV-OS-ACCOUNT-v1" || deterministicCbor([organizationId, deviceId, canonicalOsAccountId]))`. Die Anwendung liest ihn über den Plattform-Key-Provider und darf ihn nicht durch ein editierbares Profilfeld ersetzen.

Zusätzlich erzeugt die Anwendung bei jeder Operator-Provisionierung ein neues Ed25519-Operator-Instanzschlüsselpaar im nativen, kontogeschützten Provider. Der private Schlüssel ist nicht roamingfähig, nicht cloud-synchronisierend, vom System-/Anwendungsbackup ausgeschlossen und an diese App-Installation gebunden; gespeichert wird nur sein gemäß RFC 9679 berechneter Public-Key-Thumbprint im Binding. Unter Ubuntu liegt er in einer durch PAM entsperrten Secret-Service-Collection mit eigener zufälliger Account-Instanz und nicht in einer allein durch UID-Dateirechte geschützten Datei. Jeder Sitzungsaufbau und jede Re-Authentisierung prüft sowohl den OS-Kontobezeichner als auch eine frische domain-separierte Challenge-Signatur dieses Instanzschlüssels.

Löschen/Neuanlegen eines Kontos, UID-Wiederverwendung, Verlust/Restore der Installation oder Verlust des Instanzschlüssels darf die alte Bindung nicht wiederbeleben. Es erzwingt neuen externen Identitätsabgleich, neuen Instanzschlüssel, neue Admin-Autorisierung und neues Root-signiertes `operatorBinding`; ein altes Binding wird widerrufen. Ein Restore darf den privaten Instanzschlüssel ausdrücklich nicht zurückbringen.

Anzeigename, Funktionsbezeichnung und ein zufälliges 32-Byte-`profileCommitmentSalt` liegen nur im verschlüsselten lokalen Operator-Profil und später im verschlüsselten Payload. Das öffentliche Binding enthält ausschließlich:

```text
operatorProfileCommitment = SHA-256(
  "EINSATZARCHIV-OPERATOR-PROFILE-v1" ||
  deterministicCbor([
    organizationId,
    operatorSubjectId,
    displayName,
    functionLabel,
    profileCommitmentSalt
  ])
)
```

Der `operator`-Snapshot besteht aus diesen fünf Commitment-Eingaben plus `operatorBindingObjectHash`. Writer und Reader berechnen das Commitment nach der Entschlüsselung neu; eine Abweichung ist ein Trust-/Payloadfehler. Dadurch enthält das öffentliche Trust Bundle weder Anzeigenamen noch Funktionsbezeichnungen.

App-Entsperrung und Re-Authentisierung verwenden ausschließlich den nativen OS-Identitätsprovider: Windows Hello/Credential UI, macOS LocalAuthentication und Ubuntu PAM/Polkit für das gebundene Konto, jeweils kombiniert mit dem Operator-Instanzschlüssel. Das Produkt speichert keine OS-Passwörter. Re-Authentisierung ist mindestens vor Finalisierung, Klartextexport, Admin-/Root-Zeremonie, Recovery-Test, Re-Grant und Vernichtung erforderlich; nach fünf Minuten Inaktivität oder OS-Sperre endet die Sitzung. Kann der Provider Konto, erfolgreiche Benutzerpräsenz und Instanzschlüsselbesitz nicht gemeinsam bestätigen, bleibt die Aktion gesperrt.

Provisionierung erfordert externen Identitätsabgleich durch einen Organisationsadministrator, Admin-Autorisierung und Root-signiertes Binding. Ein Root-signierter Widerruf beendet neue Sitzungen und Aktionen ab seiner Wirksamkeitssequenz; historische `operator`-Snapshots bleiben als damalige, nicht frei behauptete Zuordnung erhalten. Login, fehlgeschlagene Re-Authentisierung, Binding-Wechsel und Widerruf werden ohne fachliche Klartexte lokal auditiert. Der Go-live-Bericht listet jedes produktive Binding, das verantwortliche Konto und den Widerrufsprozess.

## 7. Organisationsrichtlinie

Eine Root-signierte, versionierte Organisationsrichtlinie ist Teil des Trust Bundles. Vor der Genesis müssen mindestens folgende Werte explizit festgelegt werden:

- Betriebsprofil: `standard` oder `evidence-grade`,
- maximale Registry-Altersgrenze `maxRegistryAgeMs`,
- maximal tolerierte zukünftige lokale Uhrenabweichung `maxFutureClockSkewMs`,
- Verhalten bei abgelaufener Registry als `registryExpiryBehavior: warn | block`; Evidence Grade MUSS unabhängig vom gespeicherten Wert blockieren,
- maximale Sequenz-Lease `validThroughSequence`; nach deren Verbrauch MUSS jedes Profil blockieren,
- maximales Evidence-Zeitfenster `evidenceMaxDelayMs`,
- Reader-Inaktivitätszeit; sicherer Default sind fünf Minuten,
- erlaubte Reader-Historienfreigabe,
- zulässige lokale und kontrollierte Netzlaufwerk-Archivprofile,
- Verhalten bei Netzarchiv-Ausfall; v0.1 verwendet immer lokalen Commit und verzögerte byteidentische Publikation vor Server-Sync,
- Backupfrequenz und Restore-Testintervall,
- Aufbewahrungs- und Vernichtungsregeln,
- zulässige Freitextinhalte,
- erlaubte Krypto-Suites und Formatversionen.

Richtlinienänderungen sind append-only Registry-Ereignisse mit Version, Vorgänger-Hash, Gültigkeitsbeginn und Root-Signatur. Der Writer bindet die verwendete Registry-Version und deren exakten Head-Hash in jeden Eintrag und jeden initialen Grant.

## 8. Fachliches Datenmodell

### 8.1 Eintragstypen

Der verschlüsselte Payload ist eine typisierte Variante. `recordType` darf in v0.1 nur folgende Werte besitzen:

- `genesis`
- `incident`
- `amendment`
- `keyTransition`
- `destructionEvidence`

`legacyImport` existiert nicht.

### 8.2 Gemeinsame Felder

Jeder Ketteneintrag enthält:

- `recordType`
- `recordId` als UUIDv7
- `schemaId`
- `schemaVersion`
- `finalizedAtDevice` als UTC-Zeitwert
- `timezone` als IANA-Zeitzone der Erfassung
- `operator` als nicht frei editierbarer Snapshot `[organizationId, operatorSubjectId, displayName, functionLabel, profileCommitmentSalt, operatorBindingObjectHash]`; Binding, Gerät, OS-Konto, Rolle, Sequenz und Profil-Commitment werden gemäß Abschnitt 6.8 geprüft
- `source` als typisiertes Herkunftsobjekt mit `kind`, Quellen-ID, Formatversion und optionalem Importprotokoll-Hash
- `registryVersion`
- versionierte `extensionData` nur in registrierten Namespaces

Fließkommazahlen sind im normativen Payload nicht zulässig. Zeitwerte werden als ganzzahlige Millisekunden seit Unix Epoch plus IANA-Zeitzone serialisiert. Texte werden vor der Validierung in Unicode NFC normalisiert.

`source.kind` ist für alle in v0.1 erzeugten Ketteneinträge `native`. Die Provenienz importierter Stammdaten wird innerhalb des jeweiligen Snapshots über Quellen-ID, Importformatversion und Importprotokoll-Hash festgehalten; sie macht den Einsatz selbst nicht zu einem Import. `legacy-access-import` und andere historische Einsatzimportarten sind ungültig. Weitere kontrollierte Eintragsursprünge benötigen später eine neue dokumentierte Schemaversion.

### 8.3 Incident-Payload

Ein `incident` enthält mindestens:

| Feld | Typ | Regel |
|---|---|---|
| `humanIncidentNumber` | String | 1–64 Zeichen, innerhalb Organisation und Kalenderjahr eindeutig |
| `incidentOccurredAt` | Intervall | Start erforderlich, Ende optional und nicht vor Start |
| `incidentKeyword` | String/Referenz | 1–128 Zeichen |
| `location` | Objekt | Freitext oder strukturierte Anschrift; Koordinaten optional |
| `personnel` | Snapshot-Liste | maximal 200; leere Liste benötigt Begründung |
| `vehicles` | Snapshot-Liste | maximal 100; leere Liste benötigt Begründung |
| `patientCountStatus` | Enum | `known` oder `unknown` |
| `patientCount` | Integer/null | nichtnegativ bei `known`, sonst `null` |
| `notes` | String/null | maximal 20.000 Zeichen, keine identifizierenden Patientendaten |
| `externalOrganizations` | Liste | maximal 100 Einträge |

Der deterministisch serialisierte Klartext-Payload darf 1 MiB nicht überschreiten.

### 8.4 Nachtrag

Ein `amendment` enthält die Einsatznummer des Originals, `originalRecordId`, `originalEntryHash`, `originalSequence`, einen Grund, strukturierten Änderungstext und den Ersteller-Snapshot. Mehrere Nachträge zum selben Original sind erlaubt. Ein Nachtrag ersetzt oder verbirgt das Original nicht.

### 8.5 Genesis, Writer-Wechsel und Vernichtungsnachweis

- `genesis` bindet Organisation, Ketten-ID, initialen Writer, Format, Suite und initiale Richtlinie.
- `keyTransition` referenziert das Root-signierte Trust-Ereignis für den Writer-Wechsel und enthält die organisatorische Begründung verschlüsselt.
- `destructionEvidence` referenziert Ziel-Hashes, Autorisierung, Umfang, Ausführungsergebnisse, Destroyed Entry Stubs und Löschattestierungen. Es behauptet keine Löschung, die nicht technisch oder organisatorisch bestätigt wurde.

### 8.6 Stammdaten und Snapshots

Personen und Fahrzeuge werden lokal verwaltet. Jeder Einsatz kopiert die verwendeten Werte als Snapshot in den verschlüsselten Payload. Ein Personen-Snapshot enthält mindestens stabile interne ID, Anzeigename, optionale Rolle/Funktion und Stammdatenversion oder Änderungszeitpunkt. Ein Fahrzeug-Snapshot enthält mindestens stabile interne ID, Bezeichnung, optional Funkrufname/Kennzeichen und Stammdatenversion oder Änderungszeitpunkt. Bei importierten Stammdaten enthält der Snapshot zusätzlich Quellen-ID, Importformatversion und Importprotokoll-Hash. Spätere Stammdatenänderungen dürfen alte Einträge nicht beeinflussen.

Ist ein benötigter Wert nicht in den Stammdaten vorhanden, darf er als eindeutig gekennzeichneter Ad-hoc-Freitext-Snapshot erfasst werden. Ein solcher Snapshot erzeugt keinen Stammdatensatz, wird in der Prüfansicht hervorgehoben und bleibt unverändert Teil dieses Einsatzes.

Der CSV-Import akzeptiert ausschließlich UTF-8-Dateien mit dokumentiertem Header:

- Personen: `id,display_name,role,active`
- Fahrzeuge: `id,display_name,radio_call_sign,license_plate,active`

Der Import läuft zuerst als Dry Run, ist anschließend transaktional und protokolliert Dateihash, Zeitpunkt, Formatversion, Zeilenzahlen, Warnungen und Fehler. Er importiert keine Einsätze und unterstützt kein Access-Format.

## 9. Entwurfszustand und Writer-Lebenszyklus

### 9.1 Entwurf

Die Anwendung unterstützt genau einen aktiven Entwurf. Der Entwurf wird automatisch gespeichert und nach einem Absturz wiederhergestellt.

Die lokale SQLite-Datenbank ist verschlüsselt. Zusätzlich besitzt jeder Entwurf einen eigenen zufälligen `draftDEK`. Der Payload wird damit anwendungsseitig per AEAD verschlüsselt; nur der umschlossene `draftDEK` liegt in einem gerätegebundenen, nicht synchronisierenden und vom normalen Anwendungsbackup ausgeschlossenen Keystore-Eintrag. Nach Finalisierung wird dieser Schlüssel gelöscht. Dadurch bleiben auch alte SQLite-Seiten ohne persistierten Schlüssel unlesbar.

Während der Bearbeitung liegt Klartext zwangsläufig in kontrolliertem UI- und Rust-Prozessspeicher. Die Anwendung minimiert dessen Lebensdauer, deaktiviert produktive Crash-Dumps und leert fachliche UI-Zustände sowie Rust-Puffer vor dem Commit bestmöglich. Sie behauptet keine technisch unmögliche garantierte Speicher-Nullung für Browser-/Betriebssystemkopien.

**Entwurf verwerfen** ist ein eigener irreversibler lokaler Ablauf. Nach Re-Authentisierung und ausdrücklicher Bestätigung hält die Anwendung unter dem exklusiven Draft-Lock zuerst einen `discardIntent` mit Draft-ID dauerhaft in der verschlüsselten Datenbank fest. Ab diesem Commit stellt ein Neustart den Entwurf nicht mehr zur Bearbeitung her, sondern setzt dieselbe Operation fort. Danach leert die Anwendung UI-/Prozesspuffer bestmöglich, löscht den zugehörigen `draftDEK` aus dem Keystore und bestätigt dessen Abwesenheit, entfernt Draft-Ciphertext und Intent transaktional und öffnet eine neue leere Maske mit neuer Draft-ID und neuem Schlüssel. Ein Absturz vor dem `discardIntent` verändert nichts; danach endet jede Wiederaufnahme entweder bei der bestätigten Schlüssellöschung oder setzt sie fort. Alte SQLite-Seiten bleiben ohne `draftDEK` unlesbar. Das Verwerfen erzeugt keinen Ketteneintrag, keine wiederverwendete Sequenz und keinen wiederherstellbaren Papierkorb.

### 9.2 Prüfansicht

Vor der Finalisierung MUSS die Anwendung:

1. alle Pflichtfelder und Fachregeln prüfen,
2. die verwendeten Stammdaten-Snapshots vollständig anzeigen,
3. auf das Verbot identifizierender Patientendaten hinweisen,
4. Archivzustand, Recovery-Empfänger, Registry und Kettenkopf prüfen,
5. eine ausdrückliche Bestätigung der Unwiderruflichkeit verlangen.

### 9.3 Atomare Finalisierung

Die Finalisierung läuft unter einem exklusiven Writer-Lock:

1. Vertrauenswürdigen lokalen Kettenkopf aus Archivobjekten rekonstruieren.
2. Bei erreichbarem Server den letzten signierten Checkpoint vergleichen; Rollback oder abweichender Kopf blockiert.
3. Für die neue Sequenz den gemäß Abschnitt 12.3 höchsten anwendbaren Registry-Head auswählen, dessen Zeitstatus und Sequenz-Lease prüfen, die native Re-Authentisierung und das für OS-Konto/Gerät/Rolle wirksame `operatorBinding` prüfen und mindestens einen aktiven Recovery-Empfänger verlangen.
4. Payload und Snapshots validieren und deterministisch serialisieren.
5. Den initialen Grant-Plan aus genau einem aktiven Recovery-Empfänger und ausnahmslos jedem zur gebundenen Registry-Version und neuen Eintragssequenz aktiven Reader-Zertifikat bilden und hashen.
6. Neue Sequenz, UUIDv7, CEK und AEAD-Nonce aus einem CSPRNG erzeugen; `manifestCore`, Ciphertext, `signedManifest`, Writer-Signatur und `entryHash` gemäß Abschnitt 10 bilden.
7. Erst nach Ermittlung des `entryHash` sämtliche im Grant-Plan geforderten initialen `.eag` erzeugen und die finalen `.eip`-Bytes samt `objectHash` bilden.
8. `.eip`, Grant-Plan, alle `.eag` und einen gehashten Transaktionsdeskriptor bytegenau in einen Staging-Bereich der lokalen Archiv-Commit-Komponente schreiben. Bei lokalem Ausgabepfad ist dies dessen Filesystem; ein kontrolliertes Netzlaufwerkprofil MUSS dafür eine verschlüsselte, dauerhafte lokale Offline-Commit-Komponente als Teil desselben konfigurierten Archivprofils besitzen. Alle Dateien lesen, erneut prüfen und dauerhaft synchronisieren; anschließend das Staging-Verzeichnis synchronisieren.
9. CEK und Serialisierungspuffer bestmöglich nullen, fachlichen UI-Zustand leeren und den `draftDEK` aus dem Keystore löschen. Ab diesem dauerhaften Schritt ist die Transaktion irreversibel und MUSS aus den vorbereiteten Bytes fertiggestellt werden.
10. Initiale Grants mit Create-if-absent veröffentlichen. Bereits vorhandene Zielnamen sind nur bei bytegleichem Objekt zulässig; danach das Grant-Verzeichnis dauerhaft synchronisieren.
11. `.eip` als letzten lokalen Archiv-Commit-Marker mit Create-if-absent und atomarem Same-Filesystem-Rename veröffentlichen; danach das Entries-Verzeichnis dauerhaft synchronisieren.
12. Bei einem kontrollierten Netzlaufwerkprofil exakt dieselben committed Bytes in gleicher Reihenfolge veröffentlichen: Grants zuerst, `.eip` zuletzt. Ist das Ziel nicht erreichbar, bleibt der Sync-Zustand `Upload ausstehend`; die Detailursache lautet `Netzarchiv wartet`. Vor erfolgreicher Netzarchiv-Publikation findet kein Sync-Server-Upload dieses Eintrags statt.
13. Kettenkopf und Queues ausschließlich aus der lokalen committed Archivkomponente ableiten, Staging nach vollständiger Reconciliation bereinigen und eine neue leere Maske mit neuem `draftDEK` öffnen.

Die Anwendung darf den fachlichen Abschluss erst nach Schritt 11 als `lokal gesichert` melden. Der konfigurierte Writer-Ausgabepfad darf ein lokales Laufwerk oder ein kontrolliertes Netzlaufwerk sein; das Netzprofil umfasst zwingend die lokale Offline-Commit-Komponente und das entfernte Archivziel. Ein Netzlaufwerk ist nur freigegeben, wenn sein konkret versioniertes Backendprofil auf jeder vorgesehenen Clientplattform sämtliche Publikationsgarantien aus Abschnitt 11.5 nachweislich erfüllt; andernfalls blockiert die Konfiguration fail-closed.

### 9.4 Abbruchverhalten

- Vor der dauerhaften Löschung des `draftDEK` darf unvollständiges Staging verworfen und der Entwurf wiederhergestellt werden; die Sequenz gilt dann als nicht verbraucht.
- Nach der Löschung des `draftDEK` MUSS ein Neustart exakt die vollständig geprüften Staging-Bytes fertigstellen. Er darf weder neu serialisieren noch neue Zufallswerte erzeugen oder dieselbe Sequenz anderweitig verwenden.
- Vorab veröffentlichte Grants ohne committed `.eip` sind keine gültigen Freigaben. Sie werden quarantänisiert und nur von der zugehörigen vorbereiteten Transaktion übernommen oder nach nachgewiesenem Abbruch bereinigt.
- Nach dem `.eip`-Rename ist das Archivpaket die Wahrheit. Ein Neustart rekonstruiert Kettenkopf, Queue und UI daraus und erzeugt kein Duplikat.
- Zu keinem Zeitpunkt darf gleichzeitig ein committed `.eip` und ein nutzbarer `draftDEK` dieses Eintrags existieren.
- Ein wiederhergestelltes Writer-Backup darf keine neue Finalisierung ausführen, bevor sein Kopf gegen Server, Reader oder vertrauenswürdigen Checkpoint geprüft wurde.

## 10. Kryptografisches Profil

### 10.1 Suite v1

`EINSATZARCHIV-SUITE-1` besteht aus:

- Deterministic CBOR gemäß RFC 8949 Core Deterministic Encoding Requirements (§4.2.1)
- COSE Sign1 gemäß RFC 9052/9053
- SHA-256 mit expliziter Domain Separation
- Ed25519 für Signaturen
- ChaCha20-Poly1305 für Payload-Verschlüsselung
- HPKE Base Mode mit X25519, HKDF-SHA-256 und ChaCha20-Poly1305
- TLS 1.3 für den Transport

Es werden keine eigenen kryptografischen Primitive implementiert. Vor jedem Produktivrelease MUSS die Suite gegen die dann aktuelle BSI TR-02102-1 und durch ein unabhängiges Security Review geprüft werden. Falls die Freigabe scheitert, wird eine neue Suite-ID definiert; vorhandene Objekte und Testvektoren werden nicht umgeschrieben.

Für alle operativen Signaturen ist die Signeridentität eindeutig. `certificateHash` bedeutet stets den `objectHash` der exakten, Root-zertifizierten `.etb`-Zertifikatsbytes; `keyThumbprint` ist der RFC-9679-SHA-256-Thumbprint des tatsächlich zur Signaturprüfung verwendeten kanonischen COSE-Public-Key aus genau diesem Zertifikat. Ein Validator löst beide Werte auf **dasselbe** Zertifikat auf, berechnet den Thumbprint selbst neu und prüft Rolle, Capability, Organisation, Wirksamkeitssequenz und Widerruf ausschließlich gegen dieses Zertifikat. Mehrdeutige Auflösung oder jede Abweichung ist ein Trust-Fehler.

Zusätzlich gelten zwingend:

- Writer-COSE-`certificateHash = manifestCore.writerCertificateHash`; sein `keyThumbprint` entspricht dem Writer-Public-Key dieses Zertifikats.
- Grant-COSE-`keyThumbprint = grantContext.issuerKeyThumbprint` und `certificateHash = grantContext.issuerCertificateHash`.
- Receipt-COSE-`keyThumbprint = receiptCore.serverKeyThumbprint` und `certificateHash = receiptCore.serverCertificateHash`.
- Jede `.etb`-Signatur nennt entsprechend das Zertifikat des tatsächlich prüfenden Root-, Admin-, Approver-, Komponenten- oder Geräteschlüssels; Capability-Prüfung und Signaturprüfung dürfen nie gegen verschiedene Zertifikate erfolgen.

Das initiale Root-Public-Key-Material wird nicht zirkulär durch einen Hash seines eigenen Containers vertrauenswürdig, sondern ausschließlich durch den unabhängigen Trust Anchor aus Abschnitt 16.1. Seine Proof-of-Possession-Signatur enthält im geschützten Header `alg`, den aus dem eingebetteten Public Key berechneten `keyThumbprint`, `contentType` und `critical`, aber kein `certificateHash`; der Anchor pinnt stattdessen Public Key und exakten `rootCertificate`-`objectHash`. Dies ist die einzige Header-Ausnahme. Spätere Root-Rotationen werden von der vorherigen Root-Linie signiert, referenzieren deren Zertifikat gemäß den normalen Regeln und sind admin-autorisiert.

### 10.2 Payload-Verschlüsselung

Für jeden Eintrag werden ein neuer 32-Byte-CEK und eine neue 12-Byte-Nonce erzeugt. Vor der Verschlüsselung wird folgender deterministisch kodierter Kern gebildet:

```text
manifestCore = {
  objectType: 1,              / entryPackage /
  formatVersion,
  objectVersion,
  organizationId,
  chainId,
  chainSequence,
  previousEntryHash,
  writerCertificateHash,
  writerTransitionEventHash,
  registryVersion,
  registryHeadHash,
  initialGrantPlanHash,
  cryptoSuiteId,
  nonce,
  ciphertextLength,
  criticalExtensions
}

ciphertext = AEAD_Encrypt(
  CEK,
  nonce,
  deterministicCbor(payload),
  aad = "EINSATZARCHIV-AAD-v1" || deterministicCbor(manifestCore)
)
```

Für Suite v1 sind `formatVersion = 1`, `objectVersion = 1`, `cryptoSuiteId = "EINSATZARCHIV-SUITE-1"` und `criticalExtensions = []`. `writerTransitionEventHash` ist exakt dann 32 Byte lang, wenn sich das Writer-Zertifikat gegenüber dem direkten Vorgänger ändert; es enthält dann den `objectHash` des wirksamen Root-signierten `writerTransition`-Ereignisses. Bei Genesis und unverändertem Writer ist es `null`. Ein fehlender, zusätzlicher oder unpassender Transition-Hash ist ein Format-/Trust-Fehler.

`ciphertextLength` ist vorab aus der bekannten Klartextlänge und dem festen AEAD-Overhead ableitbar. `entryHash`, `ciphertextHash` und `objectHash` stehen nicht in `manifestCore` und können daher keinen Zirkel erzeugen.

Der Writer DARF keinen Grant für einen auf dem Writer vorhandenen privaten Schlüssel erzeugen.

### 10.3 Digest, Signatur und Kette

```text
ciphertextHash = SHA-256(
  "EINSATZARCHIV-CIPHERTEXT-v1" || ciphertext
)

signedManifest = [manifestCore, ciphertextHash]

recordDigest = SHA-256(
  "EINSATZARCHIV-RECORD-v1" || deterministicCbor(signedManifest)
)

writerSignature = COSE_Sign1(
  protected = { alg, keyThumbprint, certificateHash, contentType, critical },
  unprotected = {},
  payload = recordDigest
)

entryHash = SHA-256(
  "EINSATZARCHIV-PACKAGE-v1" ||
  recordDigest ||
  deterministicCbor(writerSignature)
)

eipBytes = deterministicCbor([
  h'45413100',           / Magic "EA1\\0" /
  1,                     / objectType entryPackage /
  1,                     / formatVersion /
  criticalExtensions,
  [signedManifest, ciphertext, writerSignature]
])

objectHash = SHA-256(
  "EINSATZARCHIV-OBJECT-v1" || exactEipBytes
)

manifestCore[n+1].previousEntryHash = entryHash[n]
manifestCore[n+1].chainSequence = manifestCore[n].chainSequence + 1
```

`entryHash` ist die stabile Kettenidentität. `objectHash` dient ausschließlich Content-Addressing, Upload-Idempotenz und dem Nachweis der exakten `.eip`-Bytes. Keiner der beiden Werte steht im signierten Manifest. Top-Level-`objectType`, `formatVersion` und `criticalExtensions` MÜSSEN den Werten in `manifestCore` entsprechen; eine Abweichung ist ein Formatfehler. COSE-Unprotected-Header sind leer; alle sicherheitsrelevanten Parameter stehen in geschützten Headern. Die exakten archivierten Bytes sind maßgeblich.

### 10.4 Grants

Vor der Paketbildung wird der initiale Grant-Plan als exakte Liste folgender Tupel gebildet:

```cddl
grant-plan-item-v1 = [
  recipient-key-thumbprint: bstr .size 32,
  recipient-certificate-hash: bstr .size 32,
  grant-suite-id: "EINSATZARCHIV-HPKE-1",
  grant-purpose: 0..1              ; 0 recovery, 1 reader
]
```

Die Liste ist total und aufsteigend nach dem Tupel `recipientKeyThumbprint`, `recipientCertificateHash`, UTF-8-Bytes von `grantSuiteId`, `grantPurpose` sortiert. Doppelte Empfänger-Key-Thumbprints, doppelte Zertifikat-Hashes oder mehrere Recovery-Empfänger sind Formatfehler und blockieren die Finalisierung. Registrierte Reader müssen deshalb unterschiedliche KEM-Schlüssel besitzen.

```text
initialGrantPlanHash = SHA-256(
  "EINSATZARCHIV-GRANT-PLAN-v1" ||
  deterministicCbor(sortedGrantPlanItems)
)
```

Der Plan enthält genau den aktiven Recovery-Empfänger sowie genau jedes Reader-Zertifikat, das gemäß gebundener Registry für die neue Eintragssequenz aktiv ist. Es gibt in v0.1 keine Richtlinienausnahme, mit der ein aktiver Reader ausgelassen werden kann. Historische Grants gehören nie zu diesem Plan.

Jeder Grant verwendet exakt folgende Struktur:

```cddl
grant-context-v1 = [
  object-version: 1,
  organization-id: bstr .size 16,
  chain-id: bstr .size 16,
  entry-hash: bstr .size 32,
  grant-kind: 0..1,                ; 0 initial, 1 historical
  grant-purpose: 0..1,             ; 0 recovery, 1 reader
  recipient-key-thumbprint: bstr .size 32,
  recipient-certificate-hash: bstr .size 32,
  issuer-key-thumbprint: bstr .size 32,
  issuer-certificate-hash: bstr .size 32,
  issuer-capability: tstr,
  registry-version: uint,
  registry-head-hash: bstr .size 32,
  grant-suite-id: "EINSATZARCHIV-HPKE-1",
  created-at-device: int,
  original-recovery-grant-object-hash: (bstr .size 32) / null,
  grant-authorization-object-hash: (bstr .size 32) / null
]

grant-body-v1 = [
  context: grant-context-v1,
  encapsulated-key: bstr .size 32,
  wrapped-cek: bstr .size 48
]

eag-v1 = [
  h'45413100', 2, 1, [],
  [
    grant-body: grant-body-v1,
    issuer-signature: #6.18(COSE-Sign1)
  ]
]
```

Der Empfänger-Thumbprint ist ein RFC-9679-SHA-256-Thumbprint. `created-at-device` ist reine Protokollinformation und keine unabhängige Zeitaussage. Für einen initialen Grant sind beide letzten Hashfelder `null`, `grant-kind = 0` und die Capability exakt `initialGrant`; Aussteller ist der aktive Writer. Für einen historischen Grant sind beide Hashfelder 32 Byte lang, `grant-kind = 1`, `grant-purpose = 1` und die Capability exakt `historicalGrant`; Aussteller ist die Historical Grant Authority. Der referenzierte ursprüngliche Grant MUSS ein gültiger initialer Recovery-Grant desselben `entryHash` sein, und die Authorization MUSS Entry und Empfänger exakt abdecken.

Die Kapselung und Signatur sind ohne implizite Felder definiert:

```text
hpkeInfo =
  "EINSATZARCHIV-HPKE-INFO-v1" || deterministicCbor(grantContext)

hpkeAad =
  "EINSATZARCHIV-HPKE-AAD-v1" || deterministicCbor(grantContext)

(encapsulatedKey, wrappedCek) = HPKE.Seal(
  recipientPublicKey,
  info = hpkeInfo,
  aad = hpkeAad,
  plaintext = CEK
)

grantBody = [grantContext, encapsulatedKey, wrappedCek]

grantDigest = SHA-256(
  "EINSATZARCHIV-GRANT-v1" || deterministicCbor(grantBody)
)

issuerSignature = COSE_Sign1(
  protected = { alg, keyThumbprint, certificateHash, contentType, critical },
  unprotected = {},
  payload = grantDigest
)
```

Damit sind Kontext, Kapselungswert und CEK-Ciphertext signiert. Der Recovery-KEM-Schlüssel signiert nichts; der Server besitzt keine Grant-Signaturrolle. Die exakten `eag-v1`-Bytes sind maßgeblich.

### 10.5 Krypto-Agilität

Jedes Objekt nennt Objektart, Formatversion und die darauf anwendbare Krypto-Suite explizit. Fachliche Ketteneinträge nennen zusätzlich `schemaId` und `schemaVersion` im verschlüsselten Payload. Unbekannte kritische Erweiterungen oder Suites werden abgelehnt. Neue Suites gelten nur für neue Pakete, Grants oder Evidence. Alte Bytes werden niemals stillschweigend neu serialisiert.

### 10.6 Schemaentwicklung und Kompatibilität

Jede veröffentlichte Kombination aus `schemaId` und `schemaVersion` besitzt eine versionierte, maschinenlesbare Schemadefinition, Pflichtfeldregeln, Testvektoren und – falls benötigt – eine reine Transformation in die aktuelle abgeleitete Reader-Ansicht. Diese Artefakte werden gemeinsam mit Desktop, Rust-Kern und Recovery-CLI ausgeliefert und zusätzlich im öffentlichen Formatpaket des Archivs versioniert.

Es gelten folgende Regeln:

- Neue optionale oder verpflichtende Felder werden ausschließlich in einer dokumentierten neuen Schemaversion eingeführt.
- Ein historischer Payload wird stets nach der Pflichtfelddefinition seiner eigenen Schemaversion validiert; heutige Regeln machen ihn nicht nachträglich ungültig.
- Originalbytes werden niemals migriert oder neu serialisiert. Eine abgeleitete Altansicht ist flüchtig, nennt Quell- und Zielschema und verändert den Verifikationsgegenstand nicht.
- Ein unbekanntes Schema wird als `nicht darstellbares Schema` isoliert und niemals als leerer oder scheinbar vollständiger Einsatz angezeigt.
- `extensionData` ist nur in registrierten, versionierten Namespaces zulässig; unbekannte kritische Namespaces blockieren die Darstellung.
- Reader und Recovery-CLI unterstützen alle noch freigegebenen Schema- und Krypto-Suites parallel. Ist eine gebundene Suite nicht implementiert oder gesperrt, endet die Verarbeitung vor Entschlüsselung mit einem eindeutigen Unsupported-Fehler.
- Eine versionierte Kompatibilitätsmatrix nennt für jedes Release lesbare Schemata, Suites, Transformationspfade und den sicheren Fehlerzustand. Entfernen alter Unterstützung ist eine explizite Format-/Betriebsentscheidung und kein stilles Update.

## 11. Archivobjekte und Parser

### 11.1 Objektarten

| Endung | Typ-Tag | Objekt | Inhalt |
|---|---:|---|---|
| `.eip` | `1` | Einsatzpaket | öffentliches Manifest, Ciphertext, Writer-COSE-Signatur |
| `.eag` | `2` | Access Grant | HPKE-gekapselter CEK und Ausstellersignatur |
| `.esr` | `3` | Server Receipt | signierter Annahmebeleg |
| `.ecp` | `4` | Checkpoint/Evidence | Kettenkopf, RFC-3161-Token oder Renewal |
| `.etb` | `5` | Trust Bundle/Event | öffentliche Root-, Geräte-, Registry-, Autorisierungs- und Attestierungsdaten |
| `.eds` | `6` | Destroyed Entry Stub | kryptografisch prüfbarer Ersatz eines autorisiert vernichteten Ciphertexts |

Jedes Archivobjekt verwendet exakt diese Deterministic-CBOR-Hülle:

```cddl
archive-object-v1 = [
  magic: h'45413100',             ; ASCII "EA1\\0"
  object-type: 1..6,
  format-version: 1,
  critical-extensions: [],
  body: any
]

eip-v1 = [
  h'45413100', 1, 1, critical-extensions: [],
  [
    signed-manifest: [manifest-core-v1, ciphertext-hash: bstr .size 32],
    ciphertext: bstr,
    writer-signature: #6.18(COSE-Sign1)
  ]
]

manifest-core-v1 = [
  object-type: 1,
  format-version: 1,
  object-version: 1,
  organization-id: bstr .size 16,
  chain-id: bstr .size 16,
  chain-sequence: uint,
  previous-entry-hash: (bstr .size 32) / null,
  writer-certificate-hash: bstr .size 32,
  writer-transition-event-hash: (bstr .size 32) / null,
  registry-version: uint,
  registry-head-hash: bstr .size 32,
  initial-grant-plan-hash: bstr .size 32,
  crypto-suite-id: "EINSATZARCHIV-SUITE-1",
  nonce: bstr .size 12,
  ciphertext-length: uint,
  critical-extensions: []
]

receipt-core-v1 = [
  object-version: 1,
  organization-id: bstr .size 16,
  chain-id: bstr .size 16,
  chain-sequence: uint,
  entry-hash: bstr .size 32,
  entry-object-hash: bstr .size 32,
  previous-entry-hash: (bstr .size 32) / null,
  registry-version: uint,
  registry-head-hash: bstr .size 32,
  policy-object-hash: bstr .size 32,
  initial-grant-plan-hash: bstr .size 32,
  initial-grant-object-hashes: [+ bstr .size 32],
  accepted-at-server: int,
  evidence-due-at: int / null,
  server-key-thumbprint: bstr .size 32,
  server-certificate-hash: bstr .size 32,
  critical-extensions: []
]

esr-v1 = [
  h'45413100', 3, 1, critical-extensions: [],
  [
    receipt-core: receipt-core-v1,
    server-signature: #6.18(COSE-Sign1)
  ]
]
```

Die symbolischen Feldnamen dokumentieren die feste Arrayposition und werden nicht als zusätzliche CBOR-Map-Keys serialisiert. Format v1 registriert keine generischen Manifest-Erweiterungen; `critical-extensions` MUSS daher in Hülle und Manifest leer sein. Ein nicht leerer, unbekannter, wiederholter oder nicht mit einem definierten Wert versehener kritischer Eintrag wird abgelehnt. Für Genesis ist `previous-entry-hash = null`; danach sind exakt 32 Bytes erforderlich. `eipBytes` in Abschnitt 10.3 sind genau die Bytes von `eip-v1`, nicht eine zweite innere Darstellung.

Im `receipt-core-v1` sind `initial-grant-object-hashes` byteweise aufsteigend sortiert, frei von Duplikaten und exakt die Hashes des unteilbar angenommenen initialen Grant-Satzes. `accepted-at-server` ist die vom Server beim Commit einmalig festgelegte UTC-Zeit in Millisekunden und darf je Kette nicht unter der des vorherigen Receipts liegen. Im Standardprofil ist `evidence-due-at = null`. Im Evidence-Grade-Profil gilt exakt `evidence-due-at = accepted-at-server + policy.evidenceMaxDelayMs`; `policy-object-hash` bezeichnet die für diesen Commit validierte, Root-signierte Richtlinie. Abweichende oder überlaufende Werte sind ungültig.

Die Receipt-Signatur ist ohne implizite Felder definiert:

```text
receiptDigest = SHA-256(
  "EINSATZARCHIV-RECEIPT-v1" || deterministicCbor(receiptCore)
)

serverSignature = COSE_Sign1(
  protected = { alg, keyThumbprint, certificateHash, contentType, critical },
  unprotected = {},
  payload = receiptDigest
)

receiptObjectHash = SHA-256(
  "EINSATZARCHIV-OBJECT-v1" || exactEsrBytes
)
```

Die geschützten Werte `keyThumbprint` und `certificateHash` entsprechen `server-key-thumbprint` und `server-certificate-hash`; Identitätsauflösung folgt Abschnitt 10.1, und das Zertifikat muss für die gebundene Registry-Version die Capability `serverReceipt` besitzen. `exactEsrBytes` sind exakt die Deterministic-CBOR-Bytes von `esr-v1`. Ein idempotenter Replay liefert dieselben gespeicherten Bytes und erzeugt weder eine neue Annahmezeit noch eine neue Signatur.

Der `objectHash` jedes Objekts ist `SHA-256("EINSATZARCHIV-OBJECT-v1" || exactObjectBytes)`. Indefinite-length-Elemente, Fließkommazahlen und doppelte Map-Keys sind unzulässig. Sicherheitsrelevante COSE-Parameter stehen in geschützten Headern; nur der durch RFC 9921 ausdrücklich vorgesehene `3161-ctt`-Header darf bei Evidence ungeschützt sein.

`.etb` besitzt die signierten Subtypen `rootCertificate`, `deviceCertificate`, `operatorBinding`, `organizationAdminAuthorization`, `registryEvent`, `policy`, `writerTransition`, `grantAuthorization`, `destructionAuthorization`, `destructionTransition` und `deletionAttestation`. Der gemeinsame Signaturinput lautet:

```cddl
etb-v1 = [
  h'45413100', 5, 1, critical-extensions: [],
  [
    trust-subtype: tstr,
    trust-payload: any,
    signatures: [+ #6.18(COSE-Sign1)]
  ]
]

organization-admin-authorization-v1 = [
  object-version: 1,
  authorization-id: bstr .size 16,
  organization-id: bstr .size 16,
  registry-version: uint,
  registry-head-hash: bstr .size 32,
  admin-key-thumbprint: bstr .size 32,
  admin-certificate-hash: bstr .size 32,
  admin-operator-binding-object-hash: bstr .size 32,
  action-code: 0..6,
  target-trust-subtype: "deviceCertificate" / "operatorBinding" /
                        "registryEvent" / "policy" /
                        "writerTransition" / "rootCertificate",
  authorized-trust-core-hash: bstr .size 32,
  issued-at: int,
  expires-at: int,
  nonce: bstr .size 32,
  critical-extensions: []
]

operator-binding-core-v1 = [
  object-version: 1,
  organization-id: bstr .size 16,
  operator-subject-id: bstr .size 16,
  operator-profile-commitment: bstr .size 32,
  device-certificate-hash: bstr .size 32,
  operator-role: 0..2,              ; 0 writer, 1 reader, 2 organization admin
  os-account-binding-hash: bstr .size 32,
  operator-instance-key-thumbprint: bstr .size 32,
  effective-from-sequence: uint,
  revoked-from-sequence: uint / null,
  critical-extensions: []
]
```

```text
trustDigest = SHA-256(
  "EINSATZARCHIV-TRUST-OBJECT-v1" ||
  deterministicCbor([trustSubtype, trustPayload])
)
```

Jede Signatur ist ein `COSE_Sign1` über `trustDigest`; Signerauflösung folgt Abschnitt 10.1, und mehrere Signaturen sind kanonisch nach Signer-Zertifikat-Hash sortiert.

`organizationAdminAuthorization` verwendet exakt `organization-admin-authorization-v1` als Trust-Payload und genau eine Admin-Signatur. `action-code` bedeutet `0 deviceApprove`, `1 deviceRevoke`, `2 policyChange`, `3 writerTransition`, `4 operatorBinding`, `5 adminKeyChange`, `6 rootRotation`. Die erlaubten Zielsubtypen und Zielwirkungen sind exakt:

| Code | Zielsubtyp | Einzige zulässige Wirkung |
|---:|---|---|
| 0 | `deviceCertificate` oder `registryEvent` | ein Nicht-Admin-Gerätezertifikat ausstellen beziehungsweise aktivieren |
| 1 | `registryEvent` | genau ein Gerät, Operator-Binding oder Komponenten-Zertifikat widerrufen |
| 2 | `policy` oder `registryEvent` | genau eine Policy ausstellen beziehungsweise als einzige Policy aktivieren |
| 3 | `writerTransition` oder `registryEvent` | genau den gebundenen Writer-Wechsel ausstellen beziehungsweise aktivieren |
| 4 | `operatorBinding` | genau ein Operator-Binding ausstellen oder ersetzen |
| 5 | `deviceCertificate` oder `registryEvent` | einen Adminschlüssel ausstellen, aktivieren oder widerrufen; im Pre-Registry-Kontext exakt das gepinnte initiale Admin-Set aktivieren |
| 6 | `rootCertificate` | genau die gebundene Root-Rotation ausstellen |

Jede andere Kombination oder zusätzliche Wirkung ist ungültig. Es gilt `issued-at < expires-at`, die Autorisierungs-ID und Nonce dürfen organisationsweit nur einmal verwendet werden. `admin-operator-binding-object-hash` bezeichnet exakt die bei Ausstellung verwendete menschliche Admin-Bindung. Nach Existenz des initialen Registry-Heads müssen Signer-Zertifikat und Binding zur gebundenen Registry aktiv sein, Binding/Gerät/Rolle/OS-Konto/Instanzschlüssel nach Abschnitt 6.8 übereinstimmen und das Zertifikat die Capability `organizationAdminApprove` besitzen. `effectiveNow` aus Abschnitt 12.3 muss bei Root-Signatur innerhalb des Intervalls liegen.

Nur vor Erzeugung des initialen Registry-Heads gelten `registry-version = 0` und `registry-head-hash = h'0000000000000000000000000000000000000000000000000000000000000000'` als eindeutiger **Pre-Registry-Kontext**. Während der Einrichtung ist dessen unabhängige Vertrauensquelle die bereits bestätigte `organization-trust-anchor-pre-v1`; bei jeder späteren Archivprüfung ist es der finale Anchor, der deren Hash und unveränderte Felder bindet. Darin ist ein Admin-Signer genau dann aktiv und berechtigt, wenn:

1. sein `admin-certificate-hash` in `initial-admin-certificate-object-hashes` und sein `admin-operator-binding-object-hash` in `initial-admin-operator-binding-object-hashes` der extern bereitgestellten Vorstufe beziehungsweise des daraus gebildeten finalen Anchors stehen,
2. die exakten `deviceCertificate`- und `operatorBinding`-Bytes unter diesen Hashes gegen den im Anchor enthaltenen Root-Public-Key gültig sind,
3. Binding, Zertifikat und Authorization dieselbe `organization-id`, denselben Gerätezertifikat-Hash, Admin-Key-Thumbprint sowie die Admin-Rolle binden und das Zertifikat die Capability `organizationAdminApprove` besitzt,
4. Zertifikat und Binding in der Anchor-Vorstufe eine eindeutige Eins-zu-eins-Paarung bilden,
5. der Thumbprint aus dem tatsächlich prüfenden Admin-Public-Key nach RFC 9679 neu berechnet wurde,
6. OS-Konto, native Re-Authentisierung und frische Challenge des im Binding gepinnten Operator-Instanzschlüssels bei Ausstellung erfolgreich geprüft wurden und
7. die Authorization ausschließlich ein Objekt des definierten Bootstrap-Sets autorisiert.

Nur diese im Anchor gepinnten Zertifikat-/Binding-Paare sind im Nullkontext aktiv; ein anderes, lediglich Root-signiertes Admin-Zertifikat oder Binding ist dort unzulässig. Das Bootstrap-Set besteht aus initialer Policy, erstem Registry-Head, Genesis-vorbereitenden Geräte-/Komponentenzertifikaten und deren `operatorBinding`-Objekten. Der erste Registry-Head nimmt neben den technischen Basisfeldern und dem Hash der bereits autorisierten initialen Policy exakt alle und nur die gepinnten initialen Admin-Zertifikat-/Binding-Paare als aktiv mit `organizationAdminApprove` auf; andere Geräte oder Rollen aktiviert er nicht. Nach seinem Commit ist der Nullkontext dauerhaft geschlossen. Alle vorbereiteten Nicht-Admin-Zertifikate und Bindings werden danach durch getrennte, normal an diesen Head gebundene Registry-Ereignisse einzeln aktiviert; jede weitere Authorization muss den gemäß Abschnitt 12.3 höchsten anwendbaren Registry-Head binden. Genesis bindet den so entstandenen letzten Head.

Mit Ausnahme des initialen Root-Zertifikats, der mindestens zwei initialen Admin-Zertifikate und deren genau zugeordneten initialen Admin-`operatorBinding`-Objekte hat für jedes `deviceCertificate`, `operatorBinding`, `registryEvent`, `policy`, `writerTransition` und jede Root-Rotation der Root-signierte `trust-payload` exakt die Form `[authorizedTrustCore, organizationAdminAuthorizationObjectHash]`. Das gilt ausdrücklich auch für initiale Policy, initialen Registry-Head und alle übrigen Genesis-vorbereitenden Bootstrap-Ziele. Dabei gilt:

```text
authorizedTrustCoreHash = SHA-256(
  "EINSATZARCHIV-ADMIN-AUTHORIZED-TRUST-v1" ||
  deterministicCbor([targetTrustSubtype, authorizedTrustCore])
)
```

Der Validator löst das referenzierte Admin-Objekt anhand seines `objectHash` auf, prüft Organisation, Registry-Head, Action, Zielsubtyp, Core-Hash, Einmaligkeit, Zeit, Signeridentität, Admin-Operator-Binding und Capability und prüft erst danach die Root-Signatur über das vollständige Zielobjekt. Root-only oder Admin-only ist ungültig. Ausschließlich `rootCertificate`, die mindestens zwei initialen Admin-`deviceCertificate`-Objekte und deren genau zugeordnete initiale Admin-`operatorBinding`-Objekte dürfen ohne diese Referenz vorliegen; ihre exakten Objekt-Hashes und Paarungen sind in Vorstufe und finalem Trust Anchor gepinnt. Die Bindings müssen Admin-Rolle, jeweiliges Zertifikat, OS-Kontobindung und Instanzschlüssel enthalten. Ab dann gibt es keine Ausnahme.

Bei einem solchen initialen Admin-Binding ist `trust-payload` direkt `operator-binding-core-v1`; beim initialen Admin-Zertifikat ist es direkt dessen versionierter Zertifikats-Core. Beide tragen genau eine Root-Signatur, keine Admin-Signatur und keinen Null-Hash-Platzhalter. Jeder spätere Gegenstand verwendet dagegen ausnahmslos die autorisierte Zweierstruktur.

Ein autorisiertes Zielobjekt darf nur eine Action-Klasse verändern. Insbesondere mischt ein `registryEvent` nicht Gerätefreigabe, Widerruf, Adminschlüsseländerung und Richtlinienänderung; kombinierte Verwaltungsaktionen werden als mehrere direkt aufeinanderfolgende Ereignisse mit je eigener Autorisierung serialisiert. Dadurch ist die Zuordnung zwischen `action-code`, Ziel-Core und UI-Bestätigung eindeutig.

`operatorBinding` verwendet `operator-binding-core-v1` als `authorizedTrustCore`. Anzeigename und nichtleere Funktionsbezeichnung besitzen im verschlüsselten Profil jeweils 1–128 Unicode-NFC-Zeichen; `function-label` darf dort auch `null` sein. `revoked-from-sequence` ist entweder `null` oder größer als `effective-from-sequence`. Gerätezertifikat, Rolle, OS-Kontobindung, per Challenge nachgewiesener Operator-Instanzschlüssel und neu berechnetes Profil-Commitment müssen beim Sitzungsaufbau exakt übereinstimmen.

`grantAuthorization` bindet Autorisierungs-ID, Organisation, Registry-Head und Autorisierungssequenz, sortierte Ziel-Entry-Hashes, Empfänger-Key-Thumbprint und -Zertifikat-Hash, Zweck und `expiresAt`. `expiresAt` ist die verbindliche **Nutzungsgrenze** jedes daraus erzeugten historischen Grants, nicht nur eine Ausstellungsfrist: Historical Grant Authority bei Erzeugung, Server bei Annahme und Auslieferung sowie Reader vor jeder Entkapselung verlangen `effectiveNow <= expiresAt`. `created-at-device` darf für diese Entscheidung niemals verwendet werden. Nach Ablauf bleibt das Objekt archiviert, ist aber nicht mehr nutzbar; der Reader zeigt Verifikationsstatus `ungültig` mit Detail `historische Freigabe abgelaufen`. Ein erneutes Einreichen oder eine zurückgestellte Uhr verlängert die Frist nicht.

`destructionAuthorization` bindet `destructionId`, Organisation, Registry-Head und Autorisierungssequenz, Ziel-Entry-Hashes samt Sequenzen, Umfang und einen nichtfachlichen Rechtsgrund-Code. Grant- und Destruction-Authorization erfordern zwei gültige Approver-Signaturen gemäß Abschnitt 6.3.

`destructionTransition` bindet `destructionId`, Authorization-Hash, eindeutige Ereignis-ID, Vorgänger-Ereignis-Hash, Von-/Nach-Zustand, Auslöser-Code und Ausführungszeit. `deletionAttestation` bindet Destruction-Authorization-Hash, pseudonyme Replik-ID und -Art, entfernte Objekt-Hashes, Ergebnis, etwaige Backup-Ablauffrist und Ausführungszeit. Transition und Attestierung werden von einem Root-zertifizierten Komponenten- oder Geräteschlüssel mit Capability `deletionAttest` signiert.

### 11.2 Öffentliches `.eip`-Manifest

Das Manifest enthält ausschließlich:

- Format- und Objektversion
- Objektart `entryPackage`
- `cryptoSuiteId`
- pseudonyme Organisations-ID
- Ketten-ID
- Kettensequenz
- Vorgänger-Hash
- Ciphertext-Hash
- Writer-Zertifikat-Hash
- Writer-Transition-Ereignis-Hash oder `null`
- Registry-Version und `registryHeadHash`
- `initialGrantPlanHash`
- AEAD-Nonce und Ciphertext-Länge
- Liste kritischer Erweiterungen

Es enthält keine Einsatznummer, Einsatzzeit, Stichwörter, Orte, Personen, Fahrzeuge, Patientenzahlen, Notizen oder Reader-Namen.

Auch öffentliche `operatorBinding`-Trust-Objekte enthalten nur pseudonyme Subject-ID und gesalzenes Profil-Commitment, niemals Anzeigename, Funktionsbezeichnung oder OS-Kontobezeichner im Klartext.

Der Server sieht unvermeidbar Uploadzeit, Quell-IP, Objektanzahl, Größen und Abrufmuster. Das Produkt bezeichnet ihn daher als blind gegenüber **Einsatzinhalten**, nicht gegenüber sämtlichen Metadaten.

### 11.3 Parserlimits

Für Formatversion 1 gelten folgende harte Limits:

- `.eip`: 2 MiB
- `.eag` und `.esr`: je 64 KiB
- `.eds`: 256 KiB
- `.ecp` und `.etb`: je 4 MiB
- maximale CBOR-Verschachtelung: 16
- maximale Zahl von Array- oder Map-Elementen je Container: 10.000
- maximale einzelne Text- oder Bytefolge: 1 MiB

Die Prüfung erfolgt beim Streamen vor jeder großen Allokation. Überschreitung, Integer-Overflow, unbekannte kritische Erweiterungen oder nichtdeterministische Kodierung führen zu einem fail-closed Formatfehler.

### 11.4 Verzeichnisstruktur

```text
Einsatzarchiv/
  trust/
    organization.etb
    registry-events/
    operator-bindings/
    authorizations/
      admin_<authorization-object-hash>.etb
      grant_<authorization-object-hash>.etb
      destruction_<authorization-object-hash>.etb
  entries/
    000000000001_<entry-hash>.eip
  destroyed-entries/
    000000000001_<entry-hash>.eds
  grants/
    <entry-hash>_<grant-object-hash>.eag
  receipts/
    <entry-hash>.esr
  checkpoints/
    <sequence>_<checkpoint-id>.ecp
  destructions/
    <destruction-id>/
      events/
        <transition-object-hash>.etb
      attestations/
        <attestation-object-hash>.etb
  format/
    schemas/
    transformations/
    compatibility-matrix.json
  recovery-reports/
  README-FORMAT.txt
```

Dateinamen sind Hinweise, keine Vertrauensquelle. Verifikation und Wiederaufbau leiten Objektart, Identität und Beziehungen aus den Bytes, Hashes und Signaturen ab.

Ein `.eds` enthält die exakten ursprünglichen `signedManifest`- und Writer-Signaturbytes, `entryHash`, `ciphertextHash`, ursprünglichen `.eip`-`objectHash`, `destructionId` und den Hash der `DestructionAuthorization`. Der Stub enthält weder Ciphertext noch CEK/Grants und verändert keine Kettenidentität. Das spätere `destructionEvidence` referenziert den `objectHash` des Stubs; der Stub referenziert dieses spätere Objekt bewusst nicht, damit kein Hash-Zirkel entsteht. Er macht den Zustand **autorisiert vernichtet** prüfbar; ein fehlendes `.eip` ohne gültigen Stub bleibt eine ungeklärte Kettenlücke.

### 11.5 Archivgesundheit

Ein Writer konfiguriert genau ein `archiveBackendProfile` des Typs `localPath` oder `controlledNetworkPath`. `localPath` nennt den lokalen Ausgabepfad. `controlledNetworkPath` nennt den entfernten Ausgabepfad sowie die verschlüsselte lokale Offline-Commit-Komponente, Queuegrenzen und Wiederaufnahmeparameter.

Ein Profilwechsel ist eine administrative, auditierte Archivtransaktion:

1. Finalisierung, Profiländerungen und Objektbereinigung exklusiv sperren.
2. Alle ausstehenden Publikationen des alten Profils beenden und aus dessen Bytes ein vollständiges Objektinventar bilden; es umfasst Trust- und Schemaartefakte, `.eip`, `.eag`, `.esr`, `.ecp`, `.etb`, `.eds`, Autorisierungen, Transitionen, Attestierungen und Berichte.
3. Sämtliche inventarisierten Originalbytes per Create-if-absent in einen Staging-Bereich der neuen lokalen Commit-Komponente und gegebenenfalls des neuen Netzarchivs übernehmen; bestehende Zielobjekte müssen bytegleich sein.
4. Das neue Archiv vollständig offline verifizieren und Objektmenge, Kettenkopf, Trust-Head, Grants, Receipts, Evidence und Destroyed Entry Stubs mit dem alten Profil vergleichen.
5. Erst bei vollständiger Gleichheit und dauerhafter Synchronisierung aller Verzeichnisse einen lokalen, atomaren Profilzeiger auf das neue Profil umschalten und die Finalisierung wieder freigeben.
6. Das alte Profil nach signiertem Übergabebericht gemäß Aufbewahrungsrichtlinie schreibgeschützt behalten oder kontrolliert stilllegen; die Anwendung löscht es nicht automatisch.

Bei jedem Fehler bleibt ausschließlich das alte Profil aktiv. Es gibt keinen Teilwechsel, keine neue Finalisierung während der Übernahme und keinen Kettenkopf, der nur in einem der beiden Profile existiert.

Der Gesundheitscheck erkennt:

- fehlende oder unerwartet geänderte Dateien,
- Hash-, Signatur- und Kettenfehler,
- fehlende Pflicht-Grants,
- ungültige oder nicht autorisierte Destroyed Entry Stubs,
- unvollständige Trust-Daten,
- Orphan-Grants und temporäre Dateien,
- unerwartete Sequenzen, Forks und Rollbacks,
- zu wenig freien Speicher und ungeeignete Dateisystemsemantik.

Ein Produktionspfad MUSS vor Freigabe einen plattform- und backendprofilspezifischen Capability-Test für exklusives Create ohne Überschreiben, atomaren Rename innerhalb desselben Filesystems, dauerhafte Datei- und Verzeichnis-Flush-Operationen, exklusiven Writer-Lock, Verbindungsabbruch und Wiederanlauf bestehen. Der Test schreibt Zufallsobjekte, erzwingt Flush/Disconnect/Remount und prüft deren exakte Bytes sowie Create-if-absent-Semantik nach Wiederverbindung.

Für lokale Laufwerke wird das konkrete Dateisystem in `support-matrix.json` gepinnt. Ein kontrolliertes Netzlaufwerk wird zusätzlich durch Protokoll, Serverprodukt/-version, Mountoptionen, Failoverkonfiguration und Capability-Testvektor als `archiveBackendProfile` gepinnt. Ein generischer UNC-, SMB-, NFS- oder WebDAV-Pfad ohne freigegebenes Profil ist unzulässig. Verliert ein freigegebenes Netzbackend während der Publikation eine zugesicherte Fähigkeit, bleibt `Upload ausstehend` mit Detailursache `Netzarchiv wartet`; die byteidentische Publikation wird nach Wiederverbindung fortgesetzt. Die Anwendung fällt niemals still auf ein anderes Ziel zurück. Nicht unterstützte lokale oder entfernte Backends werden fail-closed abgelehnt.

## 12. Einrichtung, Trust Registry und Schlüsselhaltung

### 12.1 Ersteinrichtung

Der geführte Prozess umfasst:

1. zufällige Organisations- und Ketten-ID erzeugen,
2. Organisations-Root offline erzeugen,
3. mindestens zwei Organisationsadministratoren an getrennten produktiven OS-Konten ihre Admin- und Operator-Instanzschlüssel lokal erzeugen lassen, ihre getrennten Adminschlüssel sichern und je ein initiales Admin-`deviceCertificate` samt direkt Root-signiertem `operatorBinding` als einziges menschliches Bootstrap-Paar erzeugen,
4. vor der ersten Admin-Autorisierung `organization-trust-anchor-pre-v1` aus Abschnitt 16.1 auf mindestens zwei Recovery-Medien dauerhaft festschreiben und dessen Fingerprint über den zweiten Kanal bestätigen,
5. getrennten Recovery-KEM-Schlüssel und Historical-Grant-Authority-Signaturschlüssel erzeugen,
6. mindestens zwei Key Approver ihre getrennten Schlüssel lokal erzeugen lassen und Capabilities zuweisen,
7. mindestens zwei getrennte Sicherungen für Root-, Admin-, Recovery- und Historical-Grant-Authority-Schlüssel verifizieren,
8. Writer, Server und erste Reader ihre Schlüssel lokal erzeugen lassen und die menschlichen Writer-/Reader-OS-Konten samt Operator-Instanzschlüssel als normal admin-autorisierte `operatorBinding`-Objekte provisionieren,
9. Fingerprints über QR-Code oder zweiten Kanal vergleichen,
10. nach Admin-Autorisierung Geräte-, Operator-, Approver- und Komponenten-Zertifikate, initiale Registry und Richtlinie Root-signieren,
11. Genesis als Sequenz 0 erzeugen, Trust Bundle archivieren und `organization-trust-anchor-v1` aus unveränderten Vorstufenfeldern, `bootstrap-anchor-hash` und `genesis-entry-hash` bilden; die finalen Anchor-Bytes auf beiden Medien sowie ihr voller Fingerprint werden erneut über den zweiten Kanal bestätigt,
12. Testeintrag finalisieren, auf einem frischen Rechner mit explizitem finalem Trust Anchor offline verifizieren und per Recovery entschlüsseln.

Jede Änderung eines bereits in Schritt 4 festgeschriebenen Feldes bricht das Setup ab und beginnt mit neuen Organisations-/Ketten-IDs. Der finale Anchor MUSS den Hash und alle Felder der Vorstufe bytegenau binden; hinzu kommen nur finale Domain, `bootstrap-anchor-hash` und `genesis-entry-hash`. Ohne erfolgreichen Schritt 12 darf die Organisation nicht in den Produktivzustand wechseln.

### 12.2 Geräteregistrierung

Eine Registrierungsanfrage enthält nur Geräte-ID, beantragte Rolle, Public Keys, Formatfähigkeiten und Self-Signature. Der Server speichert sie als `pending`. Aktiv wird ein Gerät erst durch ein Root-signiertes Registry-Ereignis nach externem Fingerprint-Abgleich.

Neue Reader erhalten standardmäßig nur Grants für nach ihrer Freigabe finalisierte Einträge. Historischer Zugriff erfordert eine separate Recovery-Aktion für explizit ausgewählte Entry-Hashes.

### 12.3 Registry-Struktur und Rollback-Schutz

Jedes Root-signierte Registry-Ereignis enthält mindestens:

- `organizationId`, `registryVersion` und `previousRegistryHash`,
- `effectiveFromSequence` und die harte Lease `validThroughSequence`,
- die signierten UTC-Millisekunden `issuedAt`, `notBefore` und `notAfter`,
- den `policyObjectHash` der Alters-, Lease- und Clock-Skew-Richtlinie,
- Geräte-, Rollen-, Capability-, Richtlinien- und Widerrufsänderungen,
- Root-Key-Thumbprint und Root-Signatur.

Für jedes Ereignis gelten fail-closed `notBefore <= issuedAt < notAfter`, `notAfter - issuedAt <= policy.maxRegistryAgeMs`, `effectiveFromSequence <= validThroughSequence`, eine um exakt eins steigende `registryVersion` und – außer beim initialen Ereignis – die Referenz auf den direkten Vorgänger. Die Altersgrenze ist damit Bestandteil der Root-signierten Bytes und nicht nur lokale Konfiguration.

Der `registryHeadHash` ist der `objectHash` des akzeptierten Registry-Ereignisses. Der Writer bewahrt die gesamte validierte Ereignislinie auf, pinnt dauerhaft die höchste akzeptierte Version samt Hash und lehnt niedrigere Versionen sowie dieselbe Version mit einem anderen Hash als Rollback beziehungsweise Registry-Fork ab. Das Empfangen eines für die Zukunft geplanten Heads entfernt seinen Vorgänger nicht. Für eine vorgeschlagene Eintragssequenz `s` wählt der Writer aus der gepinnten Linie exakt den Head mit der höchsten `registryVersion`, für den `effectiveFromSequence <= s <= validThroughSequence` und `notBefore <= effectiveNow` gelten. Gibt es keinen solchen Head, blockiert die Finalisierung. Manifest und initiale Grants binden genau dessen `registryVersion` und `registryHeadHash`.

`effectiveNow` wird ohne Verjüngung durch Uhrenrückstellung gebildet:

```text
trustedTimeFloor = max(
  bisher dauerhaft gespeicherter trustedTimeFloor,
  acceptedAtServer aus jedem vollständig verifizierten Receipt,
  issuedAtServer aus jedem vollständig verifizierten Checkpoint,
  genTime aus jedem vollständig verifizierten TSA-Token,
  issuedAt und notBefore jedes akzeptierten Registry-Ereignisses
)

effectiveNow = max(OS-Wanduhr, trustedTimeFloor)
```

Nur bereits vollständig gegen Root, Signatur, Kette und Richtlinie geprüfte Zeitquellen dürfen den Floor anheben. Writer, Reader, Admin-/Recovery-CLI und Server verwenden denselben Algorithmus. Der jeweilige Floor wird monoton und transaktional im Plattform-Key-Provider-geschützten lokalen Zustand beziehungsweise in der transaktionalen Serverdatenbank gespeichert und zusätzlich aus Archivobjekten rekonstruierbar gemacht. Liegt die OS-Wanduhr unter dem Floor, wird `clockRollback` gemeldet; sie kann dadurch weder `notBefore` zurücknehmen noch einen abgelaufenen Head oder eine Autorisierung verjüngen. Ein Sprung der OS-Wanduhr weiter als `policy.maxFutureClockSkewMs` über die jüngste unabhängig signierte Server-/TSA-Zeit blockiert, bis eine neue signierte Zeitquelle oder eine dokumentierte administrative Uhrenfreigabe vorliegt.

Ein Registry-Head ist `stale`, sobald `effectiveNow > notAfter`. Evidence Grade oder `policy.registryExpiryBehavior = block` blockieren dann die Finalisierung. Nur im Standardprofil mit dem explizit signierten Wert `warn` bleibt sie nach nicht übergehbarer sichtbarer Warnung, erneuter Benutzerbestätigung und signiertem lokalem Audit-Ereignis erlaubt. `s > validThroughSequence` blockiert in beiden Profilen immer. Ein Angreifer, der sowohl Registry-Updates als auch neue unabhängige Zeitquellen von einem dauerhaft offline gehaltenen Writer fernhält, kann den realen Zeitablauf vor Fortschritt des `trustedTimeFloor` nicht allein durch die Software beweisbar machen; die harte Sequenz-Lease begrenzt dieses unvermeidbare Offline-Fenster.

### 12.4 Widerruf

Ein Root-signierter Widerruf verhindert neue Grants ab seiner `effectiveFromSequence`, sobald der entsprechende Head nach Abschnitt 12.3 anwendbar ist. Die Reader-Autorisierung wird gegen die im Paket gebundene Registry und Sequenz ausgewertet; ein späterer Widerruf macht historische Grants nicht rückwirkend ungültig. Bereits vorhandene Grants und bereits entschlüsselte Inhalte können nicht zurückgerufen werden. Die UI muss diese Grenze vor dem Widerruf nennen. Ein offline zurückgehaltenes Widerrufsereignis ist bis zum nächsten Kontakt oder bis zum Ablauf der alten Sequenz-Lease nicht erkennbar; der Server MUSS es bei Kontakt nach Abschnitt 13.3 erzwingen.

### 12.5 Writer-Wechsel

Ein Writer-Wechsel benötigt:

- öffentliches Root-signiertes Transition-Ereignis mit altem und neuem Writer-Zertifikat, `effectiveFromSequence` und vorherigem Kettenkopf,
- letzten vertrauenswürdigen Kettenkopf,
- `keyTransition`-Eintrag in derselben Kette,
- Sperre des alten Writer-Zertifikats ab der Transition-Sequenz.

Das erste Paket des neuen Writers bindet den Hash des öffentlichen Transition-Ereignisses in einem kritischen Manifestfeld. Ist der alte Writer verloren, autorisiert der Root den Übergang mit dokumentierter Begründung. Der neue Writer darf erst nach Abgleich mit Server-, Reader- oder externem Checkpoint finalisieren.

### 12.6 Registry-Frische

Frische, Zeitquellen, Warn-/Blockierverhalten und die unvermeidbare Offline-Grenze sind abschließend in Abschnitt 12.3 definiert. Die Implementierung DARF daneben keine zweite lokale Ablaufkonfiguration oder stillschweigende Grace Period verwenden.

### 12.7 Plattform-Key-Provider

Der Rust-Kern verwendet eine Key-Provider-Schnittstelle mit folgenden produktiven Backends:

- Windows: CNG/DPAPI und hardwaregestützte Provider, soweit verfügbar
- macOS: Keychain und Secure Enclave, soweit für den Algorithmus verfügbar
- Ubuntu: Secret Service plus geschützter lokaler Schlüsselcontainer
- Offline-/Recovery-CLI: verschlüsselter Schlüsselcontainer und PKCS#11-Token
- Server: Secret Store oder HSM-Provider für den Belegschlüssel

Jedes Gerätezertifikat nennt ein `keyProtectionProfile`: mindestens `osWrapped` oder `hardwareNonExportable`. Es gibt keinen stillen Fallback auf ungeschützte Schlüsseldateien. `osWrapped` darf weder Hardwarebindung noch Nicht-Exportierbarkeit behaupten; `hardwareNonExportable` ist nur mit einem explizit unterstützten und in der Suite kodierten Provider zulässig.

Keystore-Einträge für `draftDEK`s und Operator-Instanzschlüssel sind nicht roamingfähig, nicht cloud-synchronisierend und vom normalen Anwendungs-/Systembackup ausgeschlossen. Ein Writer-Geräteprofil darf keine Reader-, Recovery-, Historical-Grant-Authority- oder Key-Approver-Privatschlüssel enthalten. Ein Rollenwechsel erfordert Löschung des alten Schlüsselprofils und erneute Registrierung statt einer lokalen UI-Umschaltung. Produktivgeräte benötigen zusätzlich vollständige Datenträgerverschlüsselung und gesperrte Benutzerkonten.

## 13. Sync-Protokoll

### 13.1 Transport und Request-Signaturen

Alle `/v1`-Requests laufen über TLS 1.3. Mit Ausnahme des rate-limitierten Challenge-Endpunkts werden sie zusätzlich gemäß RFC 9421 signiert. Eine initiale Geräteregistrierung verwendet den beantragten Geräteschlüssel als Proof of Possession; alle übrigen Endpunkte verlangen einen bereits autorisierten Geräte-, Server- oder Root-Schlüssel.

Das Einsatzarchiv-Profil deckt zwingend ab:

- `@method`
- `@authority`
- `@target-uri`
- `content-type`, sofern ein Body vorhanden ist
- `content-digest` gemäß RFC 9530, sofern ein Body vorhanden ist
- eindeutige Request-ID
- `created`, `expires`, `nonce`, `keyid`, `alg=ed25519` und organisationsgebundenes `tag`

Der Server stellt über einen rate-limitierten Challenge-Endpunkt Single-Use-Nonces und seine aktuelle Zeit bereit. Nonces und Request-IDs werden nur einmal akzeptiert. Falsche Gerätezeit darf nicht durch ein unbegrenzt großes Replay-Fenster kompensiert werden.

### 13.2 API

```text
POST /v1/auth/challenges
POST /v1/device-registrations
GET  /v1/trust/registry?afterVersion={n}
POST /v1/trust/events
POST /v1/chains/{chainId}/entry-commits
GET  /v1/chains/{chainId}/entries?afterSequence={n}&afterEntryHash={hash}&cursor={cursor}
GET  /v1/objects/{objectHash}
POST /v1/entries/{entryHash}/historical-grants
GET  /v1/entries/{entryHash}/grants
POST /v1/reader-acks
GET  /v1/checkpoints?after={cursor}
GET  /v1/archive-exports/current
POST /v1/destructions
GET  /v1/destructions/{destructionId}
```

Mutierende Requests benötigen eine gültige aktuelle Geräte- oder Root-Autorität; allein die initiale Geräteregistrierung verwendet stattdessen den noch nicht freigegebenen Antragsschlüssel als Proof of Possession. Objektantworten liefern exakte archivierte Bytes. Technische Listen sind nicht autoritativ; Reader prüfen stets die Objekte selbst.

### 13.3 Upload-Batch

Ein `entry-commits`-Request enthält die exakten `.eip`-Bytes, den initialen Grant-Plan und sämtliche darin geforderten `.eag`-Bytes. Entry und initiale Grants sind eine unteilbare fachliche Transaktion. Der Server:

1. streamt jedes Objekt größenbegrenzt in einen temporären Object-Store-Key und hasht dabei,
2. prüft Format, `entryHash`, `objectHash`, Writer-Zertifikat, Signatur, Suite, Registry-Linie, Grant-Plan, Grant-Signaturen, genau den verpflichtenden Recovery-Grant und genau einen initialen Grant für jedes zur Eintragssequenz aktive Reader-Zertifikat,
3. speichert verifizierte Objekte dauerhaft content-addressed per Put-if-absent; gleiche Keys mit anderen Bytes sind ein Security Event,
4. sperrt den PostgreSQL-Kettenkopf in einer Transaktion,
5. legt `acceptedAtServer` einmalig als Maximum aus aktueller UTC-Serverzeit und Annahmezeit des direkten Vorgängers fest und bestimmt den nach Abschnitt 12.3 für diese Zeit und Sequenz höchsten dem Server bekannten anwendbaren Registry-Head; bindet das Paket einen älteren Head, wird es mit dem erforderlichen `registryVersion`/`registryHeadHash` abgelehnt,
6. akzeptiert ausschließlich `currentSequence + 1`, den aktuellen Entry-Hash als Vorgänger, den so bestimmten Registry-Head und den dafür autorisierten Writer,
7. bildet `receipt-core-v1` samt `evidence-due-at`, sortiert und prüft die Grant-Hashes, signiert ihn und speichert die exakten `esr-v1`-Bytes dauerhaft content-addressed; Annahmezeit, Due-Zeit und Signatur werden bei einem Commit nie neu berechnet,
8. schaltet Entry, initiale Grants, neuen Kettenkopf und den `receiptObjectHash` gemeinsam in derselben Datenbanktransaktion sichtbar,
9. liest den Receipt nach erfolgreichem Commit anhand seines Hashes zurück, verifiziert seine exakten Bytes und liefert ihn aus.

Nur dieselbe Commit-Identität aus `entryHash`, `.eip`-`objectHash`, `initialGrantPlanHash` und derselben sortierten Liste initialer Grant-`objectHash`-Werte ist ein erfolgreicher idempotenter Replay und liefert denselben gespeicherten Receipt. Derselbe `entryHash` mit anderen Objektbytes oder Grants, gleiche Sequenz mit anderem `entryHash`, falscher Vorgänger oder unzulässiger Writer erzeugen ein Security Event und werden nicht automatisch repariert.

Ein Absturz vor dem Datenbank-Commit hinterlässt höchstens content-addressed, nicht sichtbare Entry-, Grant- oder Receipt-Orphans. Eine Reconciliation darf sie nur nach erneuter vollständiger Prüfung übernehmen oder quarantänisieren; sie darf einen Receipt nicht als angenommen ausgeben, solange keine atomare Commit-Referenz existiert. Nach dem Commit kann ein Retry ausschließlich die gespeicherten Receipt-Bytes wieder ausliefern.

Historische Grants werden ausschließlich über den getrennten Endpunkt angenommen. Er prüft Historical-Grant-Authority-Capability, ursprünglichen Recovery-Grant, `GrantAuthorization`, Ziel-Entry und Empfänger sowie `effectiveNow <= GrantAuthorization.expiresAt`; abgelaufene Grants werden weder angenommen noch ausgeliefert. Er verändert weder `.eip`, initialen Grant-Plan noch Kettenkopf. Der Archivexport streamt alle verschlüsselten Originalobjekte, Stubs, Receipts, Evidence und ein vollständiges Trust Bundle ohne Klartexttransformation.

Der Destruction-Endpunkt akzeptiert nur eine gültige Mehr-Augen-`DestructionAuthorization`, blockiert zunächst neue Auslieferungen/Re-Grants und führt den in Abschnitt 16 definierten Zustandsautomaten. Attestierungen werden append-only gespeichert. Der Server darf `completeManagedScope` erst ausgeben, wenn alle von ihm verwalteten Objekte und Caches bestätigt entfernt sowie unveränderliche Backupfristen abgelaufen sind.

### 13.4 Serverpersistenz

PostgreSQL enthält mindestens:

- Organisationen und Geräteanfragen
- Registry-Ereignisse und Rollenintervalle
- Kettenköpfe und Entries
- Objektindizes und Grants
- Receipts, Checkpoints und Evidence-Aufträge
- Reader-Acknowledgements
- Replay-Nonces und Security Events

Eindeutige Constraints gelten mindestens für `chainId + sequence`, `entryHash`, `objectHash`, Registry-Version und Request-ID.

Der Object Store adressiert Objekte ausschließlich anhand Typ und `objectHash`. Versioning ist aktiv; Object Lock kann gemäß Organisationsrichtlinie aktiviert werden. Keine fachlichen Werte dürfen in Object Keys, Tags oder benutzerdefinierten Metadaten stehen.

### 13.5 Sync-Zustände

Der Writer zeigt ausschließlich folgende Sync-Zustände:

- `lokal gesichert`
- `Upload ausstehend`
- `synchronisiert`
- `Fehler`

`Upload ausstehend` umfasst sowohl die noch ausstehende Netzarchiv-Publikation als auch den anschließenden Server-Upload; eine getrennte nichtnormative Detailursache erklärt den aktuellen Schritt. `synchronisiert` ist erst zulässig, wenn der Server-Receipt in der lokalen Archivkomponente und – sofern konfiguriert – im Netzarchiv liegt. Netzwerk- und 5xx-Fehler werden mit begrenztem exponentiellem Backoff und Jitter erneut versucht. Format-, Signatur-, Fork- und Autorisierungsfehler werden nicht automatisch übergangen.

## 14. Reader

### 14.1 Verifikationsreihenfolge

Vor der Entschlüsselung prüft der Reader:

1. Format und Parserlimits,
2. Organisations-Root und Trust-Event-Kette,
3. gebundenen Registry-Head, Sequenz-Lease und Writer-Zertifikat zur Eintragssequenz,
4. `signedManifest`, COSE-Signatur, `entryHash`, `.eip`-`objectHash` und Ciphertext-Hash,
5. Sequenz, Vorgänger-Hash und gegebenenfalls Writer-Transition-Ereignis,
6. initialen Grant-Plan und verpflichtenden Recovery-Grant,
7. Server-Receipt und Checkpoints, sofern vorhanden,
8. Evidence-Objekte und Zeitstempel, sofern gefordert,
9. eigenen Grant, dessen Aussteller-Capability, Authorization, Nutzungsfrist gemäß `effectiveNow` und `entryHash`.

Erst danach entkapselt er den CEK und entschlüsselt lokal. Ein unbekanntes, ungültiges oder unvollständiges Objekt wird isoliert, nicht indiziert und nicht als normaler Einsatz geöffnet.

Fehlt der eigene Grant bei ansonsten gültigem Paket, lautet der sichtbare Verifikationszustand `fehlender Grant`. Der Eintrag bleibt in der technischen Kettenansicht sichtbar, wird nicht entschlüsselt oder fachlich indiziert und darf nicht mit `unbekannter Schlüssel` oder einer Kettenlücke zusammengefasst werden.

Liegt statt einer `.eip` ein `.eds` vor, prüft der Reader ursprüngliches signiertes Manifest, Writer-Signatur, `entryHash`, Authorization, Destruction Evidence und Kettenposition. Er versucht keine Entschlüsselung und zeigt ausschließlich **autorisiert vernichtet**. Ein Stub ohne vollständige Prüfkette bleibt eine Lücke.

### 14.2 Lokaler Speicher

Reader-Cache und Suchindex liegen in einer verschlüsselten SQLite-Datenbank. Der Datenbankschlüssel wird durch den Plattform-Key-Provider geschützt. Entschlüsselte Inhalte dürfen nicht in temporäre Betriebssystemdateien, Zwischenablagen oder Crash-Dumps geschrieben werden.

Filter nach Zeitraum, Stichwort, Fahrzeug und Person arbeiten ausschließlich lokal. Nach konfigurierbarer Inaktivität sperrt sich der Reader; der sichere Default beträgt fünf Minuten.

### 14.3 Nachträge

Der Reader kann einen klartextfreien Korrekturverweis mit Original-ID, Sequenz und Entry-Hash erzeugen. Der Writer übernimmt diesen Verweis in einen neuen `amendment`-Entwurf. Reader stellen Original und sämtliche Nachträge gemeinsam dar, ohne das Original zu ersetzen.

### 14.4 Exporte

Unverschlüsselte Massendatenexporte sind im Standardumfang deaktiviert. Ein autorisierter Einzelexport erfordert bewusste Zielwahl, lokale Re-Authentisierung und ein signiertes lokales Audit-Ereignis. Bereits exportierte Klartexte können nicht kryptografisch zurückgerufen werden.

### 14.5 Inkrementeller Reader-Sync

Der Reader synchronisiert ab seinem höchsten lückenlos verifizierten Kettenkopf. Er sendet `chainId`, `afterSequence`, den zugehörigen `entryHash` und einen technischen Objektcursor. Der Server liefert nur spätere Entry-Indizes sowie die dazugehörigen `.eip`/`.eds`, Grants, Trust-, Receipt- und Evidence-Objekte; jeder Batch bindet den angefragten Startkopf.

Der Reader speichert den neuen Cursor erst, nachdem sämtliche Bytes dauerhaft abgelegt und die Kette bis zum Batchende verifiziert wurden. Ein Abbruch setzt beim letzten bestätigten Cursor idempotent fort. Abweichender Startkopf, fehlende Sequenz, fehlendes Objekt oder Fork stoppen den Cursorfortschritt und werden sichtbar gemeldet. Ein Cacheverlust darf durch erneuten Sync ab Genesis oder einem lokal verifizierten Checkpoint ohne Vertrauen in Serverlisten rekonstruiert werden.

## 15. Evidence und Zeit

### 15.1 Zeitarten

Das Produkt unterscheidet:

1. fachliche Einsatzzeit im verschlüsselten Payload,
2. lokale Gerätezeit der Finalisierung,
3. Server-Annahmezeit,
4. externe TSA-Zeit.

Keine dieser Zeiten darf stillschweigend als eine andere dargestellt werden. Gerätezeit allein ist kein unabhängiger Existenznachweis.

### 15.2 Standardprofil

Nach Annahme erzeugt der Server den in Abschnitt 11.1 exakt definierten Receipt und einen signierten Checkpoint über Organisation, Kette, abgedeckten Sequenzbereich, Entry-Hash, Registry-Head, `issuedAtServer` und Vorgänger-Checkpoint. Writer und Reader replizieren diese Objekte. Ein weiter fortgeschrittener oder abweichender vertrauenswürdiger Checkpoint blockiert den Writer.

### 15.3 Evidence-Grade-Profil

Der Server bildet exakt folgenden Checkpoint-Payload:

```text
checkpointPayload = deterministicCbor({
  domain: "EINSATZARCHIV-CHECKPOINT-v1",
  organizationId,
  chainId,
  coveredFromSequence,
  coveredThroughSequence,
  headEntryHash,
  registryHeadHash,
  issuedAtServer,
  previousEvidenceHash
})
```

In der normativen Arraydarstellung `checkpoint-core-v1` steht
`object-version = 1` an Position 0 und die feste Domain
`"EINSATZARCHIV-CHECKPOINT-v1"` unmittelbar danach an Position 1; die übrigen
oben genannten Felder folgen in der dort gezeigten Reihenfolge.

Er signiert diesen Payload als `COSE_Sign1` und lässt die Signatur gemäß RFC 9921 im Modus **COSE, Then Timestamp (`3161-ctt`)** durch eine RFC-3161-TSA zeitstempeln. Für Suite v1 gilt exakt:

```text
messageImprint = SHA-256(
  cborEncodeByteString(coseSign1.signatureBytes)
)
```

Der Hash umfasst damit das vollständig CBOR-kodierte Signaturfeld einschließlich dessen Byte-String-Header, nicht den Checkpoint-Payload. Das DER-kodierte Token wird gemäß RFC 9921 als `3161-ctt`-Unprotected-Header in das COSE-Objekt eingesetzt. Der Zeitstempel belegt damit die Existenz der Signatur und nicht nur eines unsignierten Payloads.

Ein Evidence-Objekt archiviert den exakten Checkpoint-Payload, das vollständige COSE-Objekt, die vollständige RFC-3161-Antwort, Hashalgorithmus, Request-Nonce, Policy-OID, TSA-Zertifikatskette, Revocation- und weitere Validierungsdaten sowie `previousEvidenceHash`. Die TSA erhält den Message Imprint sowie Protokollparameter und sieht Transportmetadaten, aber keinen Einsatzinhalt. Der Validator prüft mindestens COSE-Signatur, Imprint, TSA-Zertifikatskette, `timeStamping`-EKU, Policy, Nonce, `genTime` und Zertifikatsstatus.

Offline-Finalisierung hängt nicht von der TSA ab. Der verbindliche Beginn der Evidence-Frist ist ausschließlich `accepted-at-server` im verifizierten `esr-v1`; ihr verbindliches Ende ist dessen signiertes `evidence-due-at`. Der Server darf den TSA-Auftrag erst nach atomarem Entry-/Receipt-Commit starten. Ein Evidence-Token qualifiziert für einen Entry genau dann, wenn sein verifizierter Checkpoint diesen Entry lückenlos abdeckt und `genTime <= evidence-due-at` seines Receipts gilt. Eine lokale Jobzeit, Queuezeit oder unbestätigte Serveruhr darf die Frist weder beginnen noch verlängern.

Für ein Evidence-Grade-Receipt gelten folgende Zustände deterministisch:

- `ausstehend`: noch kein qualifizierendes Token und `effectiveNow <= evidence-due-at`,
- `vollständig`: ein vollständig gültiges, abdeckendes Token mit `genTime <= evidence-due-at`,
- `überfällig`: kein qualifizierendes Token bei `effectiveNow > evidence-due-at` oder ein ansonsten gültiges Token mit `genTime > evidence-due-at`,
- `ungültig`: Receipt, Checkpoint, CTT-Struktur, Imprint, TSA-Token oder deren Bindungen sind kryptografisch ungültig.

`effectiveNow` folgt Abschnitt 12.3. Ein verspätetes Token bleibt archiviert, ändert den Status jedoch dauerhaft nicht von `überfällig` zu `vollständig`. Ein Standardprofil-Receipt MUSS `evidence-due-at = null` enthalten und erzeugt ohne separate Richtlinienänderung keine Evidence-Grade-Konformität. Der Eintrag bleibt in allen Fällen fachlich final.

Evidence-Objekte bilden über `previousEvidenceHash`, den `objectHash` des direkten vorherigen `.ecp`, eine lineare, unveränderliche Kette. Gleiche `coveredThroughSequence` mit unterschiedlichem `headEntryHash`, ein falscher Vorgänger oder eine nachträglich entfernte CTT-Headerstruktur sind Security Events.

### 15.4 Evidence Renewal

Ein Renewal bindet den aktuellen Kettenkopf, den vorherigen Renewal-Hash und die exakten Bytes sämtlicher erneuerter Evidence-Objekte einschließlich Tokens, Zertifikatsketten und Validierungsdaten. Für jedes Objekt wird gebildet:

```text
renewalInputHash[i] = SHA-256(
  "EINSATZARCHIV-EVIDENCE-RENEWAL-INPUT-v1" ||
  exactEvidenceObjectBytes[i]
)

renewalPayload = deterministicCbor({
  domain: "EINSATZARCHIV-EVIDENCE-RENEWAL-v1",
  organizationId,
  chainId,
  currentEntryHash,
  previousRenewalHash,
  sortedRenewalInputHashes
})
```

In der normativen Arraydarstellung `renewal-core-v1` steht
`object-version = 1` an Position 0 und die feste Domain
`"EINSATZARCHIV-EVIDENCE-RENEWAL-v1"` unmittelbar danach an Position 1; die
übrigen oben genannten Felder folgen in der dort gezeigten Reihenfolge.

Der Payload wird serverseitig COSE-signiert und nach derselben Signaturfeld-Regel im `3161-ctt`-Modus zeitgestempelt. Renewals werden als neue `.ecp`-Objekte angefügt und verändern keine älteren Dateien.

## 16. Recovery und kontrollierte Vernichtung

### 16.1 Recovery-CLI

Ein Archiv ist auf einem frischen Rechner nur dann **authentisch** verifizierbar, wenn der Trust-Root aus einer unabhängigen Quelle stammt. Setup erzeugt deshalb außerhalb des Archivs exakt folgenden kleinen Trust Anchor:

```cddl
organization-trust-anchor-pre-v1 = [
  domain: "EINSATZARCHIV-TRUST-ANCHOR-PRE-v1",
  object-version: 1,
  organization-id: bstr .size 16,
  chain-id: bstr .size 16,
  root-public-cose-key: bstr,
  root-key-thumbprint: bstr .size 32,
  root-certificate-object-hash: bstr .size 32,
  initial-admin-certificate-object-hashes: [+ bstr .size 32],
  initial-admin-operator-binding-object-hashes: [+ bstr .size 32],
  critical-extensions: []
]

organization-trust-anchor-v1 = [
  domain: "EINSATZARCHIV-TRUST-ANCHOR-v1",
  object-version: 1,
  bootstrap-anchor-hash: bstr .size 32,
  organization-id: bstr .size 16,
  chain-id: bstr .size 16,
  root-public-cose-key: bstr,
  root-key-thumbprint: bstr .size 32,
  root-certificate-object-hash: bstr .size 32,
  initial-admin-certificate-object-hashes: [+ bstr .size 32],
  initial-admin-operator-binding-object-hashes: [+ bstr .size 32],
  genesis-entry-hash: bstr .size 32,
  critical-extensions: []
]
```

`root-public-cose-key` enthält die exakten Deterministic-CBOR-Bytes des kanonischen COSE_Key; sein Thumbprint wird gemäß RFC 9679 neu berechnet. Die initialen Admin-Zertifikat- und Binding-Hashlisten sind je byteweise sortiert, duplikatfrei, enthalten dieselbe Anzahl von mindestens zwei Werten und bilden über `operatorBinding.deviceCertificateHash` eine vollständige Eins-zu-eins-Paarung. Es gelten:

```text
bootstrapAnchorHash = SHA-256(
  "EINSATZARCHIV-TRUST-ANCHOR-PRE-v1" ||
  deterministicCbor(organizationTrustAnchorPre)
)

trustAnchorHash = SHA-256(
  "EINSATZARCHIV-TRUST-ANCHOR-v1" ||
  deterministicCbor(organizationTrustAnchor)
)
```

`bootstrap-anchor-hash` MUSS `bootstrapAnchorHash` entsprechen; Organisation, Kette, Root-Felder, sortierte Admin-Zertifikat-/Binding-Hashes, deren Paarungen und kritische Erweiterungen MÜSSEN in Vorstufe und finalem Anchor bytegleich sein. Vorstufe und finaler Hash werden jeweils als voller Fingerprint und QR-Code über einen zweiten Kanal bestätigt. Mindestens zwei schreibgeschützte Recovery-Medien erhalten zuerst die exakten Vorstufen- und vor Go-live die finalen Anchor-Bytes; eine optionale Archivkopie ist nur informativ und niemals Vertrauensquelle.

Die CLI verlangt bei jedem vertrauensrelevanten Befehl `--trust-anchor <file>`. Sie akzeptiert weder Trust-on-first-use noch einen Anchor aus dem zu prüfenden Archiv. Zuerst müssen Root-Public-Key, Root-Zertifikats-`objectHash`, initiale Admin-Zertifikat-/Binding-Paare, Organisation, Kette und Genesis exakt zum Anchor passen; danach werden Root-Rotationen ausschließlich entlang der signierten und admin-autorisierten Trust-Linie verfolgt. Jede Abweichung endet mit Exitcode `12`. Das Recovery-Medium kann Anchor und privaten Recovery-Schlüssel gemeinsam tragen, aber die CLI behandelt sie als getrennte Eingaben.

Die CLI stellt mindestens bereit:

```text
einsatzarchiv --trust-anchor <file> verify <archive-path>
einsatzarchiv --trust-anchor <file> list <archive-path>
einsatzarchiv --trust-anchor <file> decrypt <archive-path> --key <key-source> --output <target>
einsatzarchiv --trust-anchor <file> grant <entry-or-archive> --recovery-key <source> --authority-key <source> --authorization <file> --recipient-cert <file>
einsatzarchiv --trust-anchor <file> report <archive-path> --output <report-file>
einsatzarchiv --trust-anchor <file> export <archive-or-server> --output <new-target>
einsatzarchiv --trust-anchor <file> recovery-test <archive-path> --key-inventory <file> --output <report-file>
```

Jeder Befehl unterstützt `--format text|json`; JSON enthält eine versionierte Schema-ID und stabil sortierte Ergebnisse. `verify` läuft immer vor `decrypt`, `grant` oder `export`. Entschlüsselung und Export schreiben ausschließlich in ein neues oder leeres Ziel mit restriktiven Rechten. Originalobjekte bleiben unverändert. `export` erzeugt ein vollständiges verschlüsseltes Archiv mit allen Originalobjekten, Destroyed Entry Stubs, Grants, Receipts, Evidence und einem zur Offlineprüfung ausreichenden Trust Bundle.

Der Bericht nennt Paketanzahl, Kettenkopf, Registry-Versionen, gültige Objekte, autorisierte Vernichtungen, Lücken, Signatur-, Evidence- und Entschlüsselungsfehler sowie verwendete Public-Key-Thumbprints. Er enthält keine privaten Schlüssel und wird gehasht und, sofern eine autorisierte Signaturrolle verfügbar ist, signiert. Ohne `--include-runtime-metadata` enthält er weder Laufzeit noch Hostpfade oder aktuelle Uhrzeit und ist für identische Eingabebytes byteidentisch.

Stabile Prozess-Exitcodes sind:

| Code | Bedeutung |
|---:|---|
| `0` | vollständig erfolgreich |
| `2` | Aufruf- oder Konfigurationsfehler |
| `10` | Format-, Hash- oder Signaturfehler |
| `11` | Kettenlücke, Fork oder Rollback |
| `12` | Trust-, Registry- oder Autorisierungsfehler |
| `13` | Evidence ungültig oder richtlinienwidrig überfällig |
| `14` | Schlüssel fehlt oder Entschlüsselung fehlgeschlagen |
| `15` | Ergebnis vollständig geprüft, aber fachlich unvollständig oder teilweise vernichtet |
| `20` | I/O-, Speicher- oder Transportfehler |
| `21` | nicht unterstützte Format-, Suite-, Plattform- oder Providerfähigkeit |

Bei mehreren Fehlern gilt deterministisch der kleinste spezifische Fehlercode; vollständige Details stehen weiterhin in der strukturierten Ausgabe.

### 16.2 Historischer Re-Grant

Der Recovery Custodian entkapselt nur den historischen CEK aus dem ursprünglichen Recovery-Grant. Die getrennte Historical Grant Authority signiert den neuen Grant für einen explizit ausgewählten Reader. Das von zwei unterschiedlichen `historicalGrantApprove`-Schlüsseln signierte `GrantAuthorization` muss Ziel-Entry-Hashes, Empfängerzertifikat, Zweck und `expiresAt` exakt abdecken. Erzeugung, Annahme, Auslieferung und jede Entkapselung sind nur bei `effectiveNow <= expiresAt` erlaubt; eine neue Nutzungsfrist erfordert eine neue Mehr-Augen-Authorization und einen neuen Grant. Der `.eip`-Ciphertext bleibt unverändert. Der neue Grant bindet Entry-Hash, Empfängerzertifikat-Hash, ursprünglichen Recovery-Grant-Hash, Authorization-Hash, Authority-Zertifikat und aktuelle Registry.

### 16.3 Kontrollierte Vernichtung

Die normale Oberfläche bietet keine Löschung finalisierter Objekte. Vor Aktivierung dieses Prozesses MUSS die Organisation dokumentiert datenschutzrechtlich prüfen und freigeben, ob und wie lange die im `.eds` verbleibenden Manifest-, Hash-, Signatur- und Autorisierungsdaten für ihren konkreten Zweck zulässig sind. Ohne diese Freigabe bleibt die Vernichtungsfunktion deaktiviert; die Software trifft keine eigene Aussage über die rechtliche Zulässigkeit eines Restnachweises.

Eine rechtlich erforderliche Vernichtung ist eine ausdrücklich modellierte Ausnahme und erfolgt ausschließlich über einen separaten Administratorprozess:

1. Ziel-`entryHash`, Sequenz, Rechtsgrund, Umfang und bekannte Speicherorte in einer `DestructionAuthorization` erfassen und durch zwei unterschiedliche, aktuell berechtigte Approver signieren lassen.
2. Neue Auslieferungen und historische Re-Grants für die Ziele serverseitig blockieren.
3. Vorzustand vollständig verifizieren und signierten Bericht erstellen.
4. Auf jeder verwalteten Replik Ciphertext, sämtliche Grants, Klartext-Caches und Suchindizes löschen oder betroffene unveränderliche Backupgenerationen zur fristgerechten Löschung markieren.
5. Pro Replik eine signierte Löschattestierung mit Ergebnis und verbleibender Bindung sammeln.
6. Vor Entfernen eines Original-Ciphertexts einen `.eds` gemäß Abschnitt 11 dauerhaft ablegen; anschließend die unveränderte `.eip` entfernen. Writer-Signatur, `entryHash` und Kettenkontinuität bleiben über den Stub prüfbar.
7. `destructionEvidence` mit Authorization, Original-Hashes, Stub-`objectHash`, Attestierungen, erfolgreichen, ausstehenden und unerreichbaren Replikaten als neuen Writer-Entwurf vorbereiten und über die reguläre Finalisierung als neuen Ketteneintrag versiegeln. Bis zu dessen Commit bleiben Authorization, Stubs, Zustandsereignisse und Attestierungen die technische Wahrheit des laufenden Prozesses.

Der Prozess besitzt ausschließlich die Zustände `requested`, `inProgress`, `pendingBackupExpiry`, `completeManagedScope` und `incompleteUnreachableReplica`. Er beginnt mit `requested`; `completeManagedScope` ist der einzige erfolgreiche Endzustand. Jeder Übergang ist ein append-only, vom ausführenden Root-zertifizierten Komponenten- oder Geräteschlüssel mit Capability `deletionAttest` signiertes Ereignis:

| Von | Nach | Zulässiger Auslöser |
|---|---|---|
| – | `requested` | gültige `DestructionAuthorization` mit zwei Approver-Signaturen angenommen |
| `requested` | `inProgress` | Zielbestand verifiziert, neue Auslieferung/Re-Grants blockiert, erster Löschschritt startet |
| `inProgress` | `pendingBackupExpiry` | alle unmittelbar löschbaren verwalteten Repliken attestiert; mindestens eine unveränderliche Frist läuft |
| `inProgress` | `completeManagedScope` | sämtliche verwalteten Repliken attestiert, keine Frist und kein unerreichbares Ziel verbleibt |
| `inProgress` | `incompleteUnreachableReplica` | bekannte Replik ist unerreichbar oder liefert keine gültige Attestierung |
| `pendingBackupExpiry` | `completeManagedScope` | alle Fristen abgelaufen und Entfernung jeweils attestiert |
| `pendingBackupExpiry` | `incompleteUnreachableReplica` | fristgerechte Entfernung kann nicht bestätigt werden |
| `incompleteUnreachableReplica` | `inProgress` | dieselbe autorisierte Operation wird nach Wiedererreichbarkeit fortgesetzt |

Nach Eintritt in `inProgress` gibt es in v0.1 keinen Rückweg oder stillen Abbruch. Ein Neustart rekonstruiert Zustand und nächsten ausstehenden Schritt aus Authorization, Transition-Events und Attestierungen und setzt dieselbe `destructionId` idempotent fort. Kein Schritt darf für ein bloß erneut gesendetes Ereignis zweimal ausgeführt oder als neu autorisierte Operation gewertet werden.

Das Produkt darf sichere physische Löschung, WORM-Löschung oder Backupvernichtung nur als erfolgreich melden, wenn der jeweilige Speicher dies bestätigt. `completeManagedScope` ist keine Behauptung über unbekannte Exporte, Screenshots oder dauerhaft unerreichbare Reader. Solange Object Lock, WORM oder Backupfristen laufen, bleibt der Zustand `pendingBackupExpiry`; unerreichbare bekannte Replikate erzwingen `incompleteUnreachableReplica`.

Nach autorisierter Vernichtung wird der Einsatzinhalt nicht mehr als vorhanden oder vollständig erneut prüfbar dargestellt. Die noch prüfbare Aussage lautet: Der damalige Writer hat einen Ciphertext mit dem signierten Hash in diese Kettenposition aufgenommen, und seine Entfernung wurde autorisiert dokumentiert. Ein Entfernen ohne gültige Authorization, Stub und Evidence bleibt dagegen eine Sicherheitslücke.

### 16.4 Geführter Recovery-Test und Schlüsselbackup-Check

Admin-Oberfläche und `recovery-test`-CLI führen denselben read-only Testkern aus. Der Ablauf verlangt Re-Authentisierung, den unabhängigen Trust Anchor, eine unveränderte Archivkopie und ein versioniertes `keyInventory` mit pseudonymen Medien-IDs und erwarteten Public-Key-Thumbprints. Jede konfigurierte Sicherung wird einzeln eingelegt oder verbunden; die Anwendung speichert keine privaten Schlüssel aus dem Test.

Der Test:

1. verifiziert Trust Anchor, vollständiges Archiv, aktuellen Kettenkopf, Trust-/Registry-Linie und ein deterministisches Sample aus jeder vorhandenen Schema-/Suite-/Writer-Epoche,
2. leitet von jedem Root-, Admin-, Writer-, Reader-, Recovery-, Server-, Approver-, Historical-Grant-Authority- und `deletionAttest`-Backup den Public Key ab und vergleicht Thumbprint sowie Zertifikat,
3. signiert mit jedem Signaturschlüssel eine zufällige, domain-separierte `EINSATZARCHIV-RECOVERY-TEST-v1`-Challenge und prüft sie, ohne ein produktives Trust-Objekt zu erzeugen,
4. entkapselt mit jeder Recovery-Sicherung den CEK eines beim Setup erzeugten und danach unveränderten Testeintrags, entschlüsselt und validiert ihn ausschließlich im geschützten Speicher und zeigt keinen Fachklartext an,
5. prüft bei nicht exportierbaren Geräte-/Hardwarekeys Providerzugriff, Benutzerpräsenz und Zertifikatsbindung statt eines Schlüsselexports,
6. leert Test-CEKs, Klartext und Challenges bestmöglich und erzeugt einen signierten oder mindestens gehashten Bericht.

Der Bericht bindet Test-ID, Trust-Anchor-Hash, Archivkopf, Testzeit gemäß `effectiveNow`, Release-/Schema-/Suite-Versionen, jede pseudonyme Medien-ID, erwarteten und beobachteten Thumbprint, Testart und Ergebnis. Er enthält weder private Schlüssel noch entschlüsselte Payloads. Ein fehlendes Medium, falscher Key, abweichender Anchor, nicht lesbarer Testeintrag oder unvollständiges Sample macht den Gesamttest fehlgeschlagen; Teilerfolg darf nicht als erfolgreicher Recovery-Test erscheinen. Die Admin-Ansicht zeigt letzten vollständigen Test, nächste Fälligkeit und offene Fehler. Der Ablauf ändert weder Archiv, Registry, Grants noch Schlüsselstatus.

## 17. UX-Verträge

### 17.1 Writer

- Startansicht ist immer der aktive oder ein neuer leerer Entwurf.
- Es gibt keine Historiennavigation und keinen Link „letzten Einsatz öffnen“.
- Einsatznummern werden im Muster `YYYY-NNNN` vorgeschlagen, bleiben bis zur Finalisierung kontrolliert editierbar und werden lokal auf Eindeutigkeit geprüft.
- Personen und Fahrzeuge sind per Suche, Favoriten und Mehrfachauswahl bedienbar.
- Autosave-Zustand ist sichtbar.
- `Entwurf verwerfen` ist vom Finalisieren getrennt, verlangt bei nicht leerem Entwurf Re-Authentisierung und Bestätigung und endet ohne Papierkorb in einer neuen leeren Maske.
- Finalisieren ist visuell und sprachlich klar von normalem Speichern getrennt.
- Nach erfolgreichem Commit erscheint sofort eine leere Maske.
- Die Sync-Warteschlange zeigt keine fachlichen Inhalte.

### 17.2 Reader

- Einsatznummer, Einsatzzeit und Stichwort erscheinen erst nach erfolgreicher lokaler Entschlüsselung.
- Jeder Eintrag besitzt einen permanent sichtbaren Verifikationsstatus.
- Ein fehlender eigener Grant erscheint ausdrücklich als `fehlender Grant`; der Eintrag bleibt technisch sichtbar und wird nicht als leerer Einsatz dargestellt.
- Original, Nachträge und Beweisinformationen sind getrennte Ansichten desselben Zusammenhangs.
- Eine technische Ansicht erklärt Sequenz, Hash, Writer-Key, Registry, Receipt und Evidence in verständlicher Sprache.
- Ungültige Objekte erscheinen ausschließlich in einem getrennten Bereich „Prüfprobleme“ und werden nicht als Einsätze geöffnet.

### 17.3 Administration

- Pending-Anfrage, externer Fingerprint-Abgleich, Freigabe und historischer Zugriff sind getrennte Schritte.
- QR-Code und vollständiger menschenlesbarer Fingerprint werden gleichzeitig angeboten.
- Ein Widerruf warnt vor der Unmöglichkeit, bereits übertragene Daten zurückzurufen.
- Schlüsselbackup, Registry-Alter, Evidence-Richtlinie und letzter Recovery-Test sind sichtbar.
- Der geführte Recovery-Test zeigt Inventar, einzulegendes pseudonymes Medium, Einzelergebnis und erst nach vollständigem Erfolg den neuen Gesamtstatus; er zeigt keinen entschlüsselten Fachinhalt.
- Root- oder Recovery-Aktionen verlangen bewusste Auswahl der Schlüsselquelle und Re-Authentisierung.

### 17.4 Statussprache

Verbindliche Begriffe sind:

- Sync: `lokal gesichert`, `Upload ausstehend`, `synchronisiert`, `Fehler`
- Verifikation: `verifiziert`, `Lücke`, `fehlender Grant`, `unbekannter Schlüssel`, `nicht darstellbares Schema`, `ungültig`
- Evidence: `vollständig`, `ausstehend`, `überfällig`, `ungültig`
- Eintragszustand: `vorhanden`, `autorisiert vernichtet`, `ungeklärte Lücke`
- Vernichtungsprozess: `beantragt`, `in Bearbeitung`, `wartet auf Backup-Frist`, `im verwalteten Umfang abgeschlossen`, `bekannte Replik nicht erreichbar`

Die Anwendung darf keine pauschale gerichtliche Beweiskraft, TR-ESOR-Zertifizierung oder vollständige Metadatenblindheit behaupten.

### 17.5 Bedienbarkeit und Barrierearmut

Alle Kernabläufe sind vollständig per Tastatur bedienbar. Fokus, Fehlerzusammenfassungen, Labels und Statusinformationen müssen für Screenreader verfügbar sein. Sicherheitszustände dürfen nicht ausschließlich über Farbe kommuniziert werden. Die UI bleibt bei laufendem Sync responsiv.

## 18. Datenschutz und lokale Sicherheit

### 18.1 Datenminimierung

Einsatzdaten und insbesondere Personaleinsatz-Snapshots werden mindestens als personenbezogene beziehungsweise vertrauliche Organisationsdaten behandelt. Diese Einstufung gilt für Payloads, Entwürfe, Reader-Caches, Exporte, lokale Auditdaten und alle daraus ableitbaren Ansichten.

Version 0.1 bietet keine Felder für Patientennamen, Geburtsdaten, Diagnosen oder Behandlungsdetails. `patientCount` ist ausschließlich aggregiert. Jedes Freitextfeld zeigt eine sichtbare Warnung; eine optionale Musterwarnung arbeitet rein lokal und überträgt keinen Text.

### 18.2 Logging

Writer, Reader, Server und CLI verwenden eine technische Allowlist für strukturierte Logs. Zulässig sind `objectHash`, pseudonyme Organisations-ID, Sequenz, technische Fehlercodes, Größen, Dauer und nichtsprechende Geräte-IDs. Verboten sind Payloads, entschlüsselte Inhalte, Schlüsselmaterial, Nonces, Klartext-Einsatznummern, Orte, Namen und Freitexte.

Telemetrie und automatische Crash-Uploads sind standardmäßig deaktiviert. Wenn ein Betrieb Crash-Dumps aktiviert, müssen Secrets und fachliche Speicherbereiche nachweisbar ausgeschlossen oder redigiert werden; andernfalls ist der Produktivbetrieb unzulässig.

### 18.3 Lokale Datenbanken und Schlüssel

SQLite-Datenbanken für Entwürfe, Stammdaten, Reader-Cache, Suchindex und Audit werden mit SQLCipher oder einer gleichwertig geprüften vollständigen Datenbankverschlüsselung geschützt. Zusätzliche per-Draft-Schlüssel verhindern die Wiederlesbarkeit finalisierter Entwürfe aus freien Datenbankseiten.

Private Schlüssel dürfen nicht in unverschlüsselten Konfigurationsdateien, Environment Dumps oder Anwendungslogs erscheinen. Temporäre Klartextdateien sind verboten.

### 18.4 Betriebsabhängige Endgerätesicherheit

Produktivgeräte müssen vollständige Datenträgerverschlüsselung, gesperrte Benutzerkonten, automatische Bildschirmsperre und einen unterstützten Patchstand verwenden. Die Anwendung prüft, was das Betriebssystem zuverlässig meldet, und dokumentiert nicht automatisch prüfbare Voraussetzungen im Go-live-Bericht.

## 19. Fehlerbehandlung und robuste Wiederaufnahme

### 19.1 Fehlerklassen

| Klasse | Beispiele | Verhalten |
|---|---|---|
| Fachfehler | Pflichtfeld, ungültige Patientenanzahl | inline anzeigen; Finalisierung nicht starten |
| Lokaler Ressourcenfehler | Speicher voll, Archiv nicht schreibbar | Entwurf behalten; Finalisierung blockieren |
| Temporärer Transportfehler | offline, Timeout, 5xx | lokal gültig lassen; begrenzt wiederholen |
| Trust-/Security-Fehler | Fork, falsche Signatur, stale strict registry | fail-closed; keine automatische Wiederholung als Erfolg |
| Formatfehler | unbekannte kritische Erweiterung, Limit überschritten | Objekt isolieren; nicht entschlüsseln |
| Evidence-Fehler | TSA nicht erreichbar, falscher Imprint | fachlichen Eintrag nicht ändern; Status ausstehend/ungültig |
| Recovery-/Vernichtungsfehler | Schlüssel fehlt, Speicherort nicht bestätigt | Teilzustand exakt berichten; keine Erfolgsaussage |

### 19.2 Security Events

Forks, Rollbacks, ungültige Root-Ereignisse, unbekannte Writer, Replay mit abweichendem Inhalt, wiederholte Signaturfehler und unerwartete Kettenköpfe werden als Security Events gespeichert. Ein Security Event enthält keine fachlichen Inhalte und kann nur durch einen dokumentierten, signierten Wiederherstellungsprozess geschlossen werden.

### 19.3 Rekonstruktion statt mutable Wahrheit

Lokaler Kettenkopf, Sync-Queue, Reader-Index und technische Statusdatenbanken sind abgeleitete Zustände. Sie müssen aus Archivobjekten und Trust-Daten vollständig rekonstruierbar sein. Ein Widerspruch wird zugunsten der verifizierten Archivobjekte aufgelöst und sichtbar protokolliert.

## 20. Nichtfunktionale Anforderungen

### 20.1 Sicherheit

- Kritische Kryptografie liegt in kleinen, testbaren Rust-Crates.
- Parser werden kontinuierlich gefuzzt und gegen Ressourcenerschöpfung geprüft.
- Abhängigkeiten werden automatisiert auf bekannte Schwachstellen, unzulässige Lizenzen und kompromittierte Quellen geprüft.
- Releases enthalten SBOM, Prüfsummen und Signaturen.
- Release-Builds sind reproduzierbar oder dokumentieren reproduzierbar überprüfbare Provenienz.
- Vor Produktivbetrieb ist ein unabhängiges Security Review erforderlich.

### 20.2 Offline-Fähigkeit und Verfügbarkeit

- Erfassung und Finalisierung funktionieren ohne Netzwerk.
- Serverausfall verursacht keinen Verlust lokal finalisierter Einträge.
- Archivcommit ist Voraussetzung für Erfolg.
- Sync setzt nach Netzwiederkehr selbstständig fort.
- Ein TSA-Ausfall blockiert die Offline-Finalisierung nicht.

### 20.3 Performance

- Finalisierung eines 1-MiB-Payloads dauert auf einem Arbeitsplatzgerät mit mindestens vier CPU-Kernen, 8 GiB RAM und SSD höchstens drei Sekunden.
- Eingabe und Autosave bleiben unabhängig vom Sync flüssig.
- Ein Reader verifiziert und indiziert mindestens 50.000 Pakete.
- Serverannahme streamt Objekte und benötigt keine vollständige Payload-Kopie im Arbeitsspeicher.

### 20.4 Robustheit

- Fault Injection vor und nach jedem Datei-/Verzeichnis-Flush, Create-if-absent, Rename, Keystore-Delete, Datenbank- und Object-Store-Schritt erzeugt entweder einen wiederherstellbaren Entwurf oder die Fertigstellung exakt derselben vorbereiteten Transaktion.
- Temporäre Dateien sind eindeutig markiert und werden nur nach Inhalts- und Commit-Prüfung bereinigt.
- Wiederherstellung vertraut nicht auf Dateinamen.
- Rollbacks eines Writers werden gegen externe Checkpoints erkannt.
- Nichtkritische unbekannte Erweiterungen bleiben bytegetreu erhalten; sie werden nicht stillschweigend verworfen.

### 20.5 Wartbarkeit

- Fachschema, Format und Krypto-Suite werden getrennt versioniert.
- Testvektoren für Serialisierung, Hashes, Signaturen, AEAD, HPKE, Grants, Receipts und Evidence sind Repository-Bestandteil.
- Alte Testvektoren bleiben dauerhaft in CI.
- Recovery-CLI wird bei jeder Format- oder Suite-Änderung getestet.
- Versionierte Schemadefinitionen, historische Validatoren und abgeleitete Transformationslogik werden mit Desktop und Recovery-CLI ausgeliefert und bleiben mit alten Golden Files in CI.
- Öffentliche CDDL-/Formatdokumentation und `README-FORMAT.txt` werden mit dem Code versioniert.

## 21. Betrieb und Go-live

Vor Produktivbetrieb müssen benannt und dokumentiert sein:

- Verantwortlicher für Einsatzdaten und Stellvertretung
- Organisationsadministrator und Stellvertretung
- mindestens zwei getrennte aktive Organisationsadmin-Schlüssel, deren Sicherungen und Rotationsprozess
- jedes produktive `operatorBinding`, zugehöriges OS-Konto, Re-Authentisierungsprovider und Widerrufsprozess
- Sync-Server-Administrator und Stellvertretung mit dokumentierter Rollentrennung
- mindestens zwei Recovery Custodians oder gleichwertiges Mehr-Augen-Verfahren
- mindestens zwei namentlich verantwortete Key Approver mit Zuordnung der Capabilities `historicalGrantApprove` und `destructionApprove`
- Historical Grant Authorities und deren Freigabeverfahren
- physische Aufbewahrungsorte der Root-, Recovery- und Grant-Authority-Sicherungen
- mindestens zwei unabhängige Kopien des Recovery-Trust-Anchors samt bestätigtem Fingerprint
- Reader-Freigabe- und Geräteverlustprozess
- Writer-Verlust- und Writer-Wechselprozess
- maximale Registry-Altersgrenze und Stale-Verhalten
- Standard- oder Evidence-Grade-Profil
- TSA-Vertrauen, Evidence-Zeitfenster und Renewal-Intervall
- zulässiger Freitextinhalt
- Aufbewahrungs- und Vernichtungsfristen
- dokumentierte datenschutzrechtliche Freigabe oder Deaktivierung des `.eds`-Restnachweises
- Backupfrequenz und Restore-Testintervall
- Archivziel und nachgewiesene Dateisystemsemantik
- Software-Update- und Rollbackprozess
- Monitoring- und Security-Event-Verantwortung

Ein vollständiger geführter Recovery-Test nach Abschnitt 16.4 ist mindestens quartalsweise sowie nach jeder Änderung an irgendeinem Root-, Admin-, Writer-, Reader-, Recovery-, Server-, Approver-, Historical-Grant-Authority- oder `deletionAttest`-Schlüssel, am Trust Anchor, an Paketformat, Suite oder Backupverfahren durchzuführen. Serverbackups werden regelmäßig in einer getrennten Umgebung restauriert und gegen einen bekannten Checkpoint verifiziert.

Der Go-live-Bericht hält ausdrücklich fest, dass technische Integrität und organisatorische Revisionssicherheit unterschiedliche Aussagen sind.

## 22. Verifikationsstrategie

### 22.1 Rust-Vertrauenskern

- Known-answer-Tests und veröffentlichte Vektoren für jede Primitive
- Golden Files für jedes Archivobjekt
- plattformübergreifende Grant-Vektoren für totale Plan-Sortierung, HPKE-Info/AAD, Kapselungswert, umschlossenen CEK und den vollständigen Grant-Signaturinput
- Cross-Version-Tests für Format und Schema
- Kompatibilitätstests für historische Pflichtfeldregeln, abgeleitete Altansichten, unbekannte Schemata und parallele alte/neue Krypto-Suites
- Property-Tests für deterministische Kodierung, Kettenbildung und Parser
- Fuzzing für CBOR, COSE, HPKE, Objektgrenzen und Ressourcenlimits
- negative Vektoren mit Ein-Byte-Manipulationen, doppelten Keys, Überläufen und unbekannten kritischen Feldern
- Trust-Vektoren für Admin-Authorization/Core-Hash, Root-only, Admin-only, falschen Action-Code, wiederverwendete ID/Nonce, Signer-Kontext-Abweichung, Adminrotation sowie positiven Pre-Registry-Signer mit gepaartem Zertifikat/Operator-Binding aus der bestätigten Anchor-Vorstufe und dem daraus gebildeten finalen Anchor; veränderte Vorstufenfelder, falscher `bootstrap-anchor-hash`, unpinned/hashabweichende oder falsch gepaarte Admin-Zertifikate/-Bindings, fehlende OS-/Instanzschlüssel-Prüfung oder erneute Nullkontext-Nutzung nach erstem Head müssen scheitern

### 22.2 Dateisystem und Stromausfall

Jede unterstützte Desktop-Plattform führt Fault-Injection-Tests vor und nach jedem File-Flush, Directory-Flush, Create-if-absent, Rename, `discardIntent`-Commit und `draftDEK`-Delete aus. Getestet werden die freigegebenen lokalen Standarddateisysteme, jedes freigegebene kontrollierte Netzlaufwerkprofil mit Disconnect/Remount/Failover und lokaler Offline-Commit-Komponente sowie die fail-closed Ablehnung eines nicht profilierten Netzwerk- oder Volume-Backends. Der Testprozess beendet den Writer hart, startet ihn neu und prüft Archiv, Entwurf, Verwerfungswiederaufnahme, Staging, Kettenkopf, Orphans, Queues, byteidentische Netzpublikation und die Nichtrückholbarkeit eines finalisierten oder verworfenen Draft-Schlüssels auch nach Backup-Restore.

### 22.3 Server und Protokoll

Integrationstests verwenden echtes PostgreSQL und einen S3-kompatiblen Testserver. Sie prüfen Parallelität, Unique Constraints, fehlende/falsche/zusätzliche Initial-Grants gegenüber der vollständigen aktiven Reader-Menge, Replay, Fork, Rollback, Registry-Fork, zeit- und sequenzabhängige Head-Auswahl, Ablehnung eines älteren Heads bei dem Server bekanntem wirksamem Nachfolger, abgelaufene und erneut eingereichte historische Grant-Authorizations, abweichende Hashes, Object-Store-Ausfall, Datenbankausfall, unsichtbare Orphans, atomare Sichtbarkeit von Entry plus Grants, byteidentische Receipt-Wiederaufnahme, monotone Annahmezeit, Nonce-Replay und Restore. Reader-Sync-Tests unterbrechen jeden Batchschritt und prüfen Cursor-Wiederaufnahme, abweichenden Startkopf, Lücke und Rekonstruktion ab Genesis/Checkpoint.

### 22.4 Desktop-Ende-zu-Ende

Writer-, Reader-, Admin- und CLI-Gates folgen exakt der signierten `support-matrix.json` des Releases. Golden-Archive werden auf jeder freigegebenen Architektur erzeugt und auf allen anderen bytegleich verifiziert, entschlüsselt und berichtet. Pro OS-/Architekturkombination werden `osWrapped` und jedes freigegebene `hardwareNonExportable`-Profil auf Erzeugung, Re-Authentisierung, falschen OS-Nutzer, Provider-Ausfall, Löschung und Backup-Restore geprüft; OS-Kontobindung, Operator-Instanzschlüssel, Provisionierung/Widerruf und die verpflichtenden Re-Authentisierungspunkte werden negativ und positiv getestet. Unter Ubuntu gehören Löschen des Kontos, Neuanlage eines anderen Kontos mit identischer UID, wiederverwendetes Home, verlorene Secret-Service-Instanz und Backup-Restore zwingend dazu; keiner dieser Fälle darf den alten Instanzschlüsselbesitz ersetzen. Vollständige Ende-zu-Ende-Flows laufen auf den in Abschnitt 4 festgelegten Minimum-/Maximum-Versionen. Writer-Tests stellen die Uhr vor und zurück, rekonstruieren und persistieren den `trustedTimeFloor`, prüfen Standard-`warn`, Standard-`block`, Evidence-Blockade sowie jede Grenze von `effectiveFromSequence`, `validThroughSequence`, `notBefore` und `notAfter`.

### 22.5 Privacy und Supply Chain

Canary-Daten in allen fachlichen Feldern müssen automatisiert in Logs, Dateinamen, Crash-Ausgaben, Serverdatenbank und Object-Store-Metadaten gesucht werden. CI prüft SBOM, Dependency Advisories, Lizenzen, Secrets, Release-Signaturen und Prüfsummen. Der Go-live-Test weist außerdem nach, dass Vernichtung und `.eds` ohne dokumentierte datenschutzrechtliche Freigabe technisch deaktiviert bleiben.

### 22.6 Evidence

Tests umfassen Golden Files für jedes Feld von `esr-v1`, Receipt-Digest und -Signatur, den exakten RFC-9921-Hash des CBOR-kodierten Signaturfelds, gültige und falsche Imprints, falsche Nonce/TSA-Policy, unzulässige Zertifikate, TSA-Ausfall, Retry, die Grenzen unmittelbar vor/auf/nach `evidence-due-at`, verspätete Tokens mit dauerhaftem `überfällig`, pending/overdue Status, entfernte oder ersetzte CTT-Header, divergierende Evidence-Heads, mehrstufige Renewals über exakte Vorobjektbytes und Prüfung ohne laufende TSA.

### 22.7 Recovery, Export und Vernichtung

Die CLI-Tests prüfen alle stabilen Exitcodes, versioniertes JSON, byteidentische Berichte, vollständige verschlüsselte Exporte und die OS-Matrix. Ein ersetztes Archiv samt konsistent falschem Root/Genesis muss am unabhängigen Trust Anchor scheitern; fehlender, falscher und rotierter Anchor werden separat getestet. Historische Grants scheitern ohne Recovery-KEM-Key, Historical-Grant-Authority-Key, passende Authorization, innerhalb der Nutzungsfrist liegendes `effectiveNow` oder bei Replay nach Ablauf. Der geführte Recovery-Test deckt jedes Schlüssel-/Backupprofil, falsche Medien, unvollständige Inventare, Challenge-Signaturen, Testeintragsentschlüsselung und einen klartextfreien Bericht ab. Vernichtungstests unterscheiden einen gültigen `.eds` mit vollständiger Attestierung von einer ungeklärten Entfernung und decken ausstehende Backups sowie unerreichbare Reader ab.

## 23. Abnahmekriterien

v0.1 ist erst abnahmefähig, wenn alle folgenden Kriterien auf den jeweils betroffenen Plattformen bestanden sind:

1. **Offline-Abschluss:** `.eip` und gültiger Recovery-Grant liegen ohne Netzwerk lokal vor.
2. **Kein Writer-Zugriff:** Der Writer kann nach jedem Fault-Injection-Punkt, Neustart und Backup-Restore mit allen auf ihm vorhandenen Schlüsseln weder `.eip` noch verbliebene Draft-Artefakte entschlüsseln.
3. **Neue Maske:** Nach Commit erscheint eine leere Maske ohne Link oder Zugriff auf den alten Inhalt.
4. **Byte-Manipulation:** Änderungen an Manifest, Ciphertext, COSE-Signatur oder Sidecars werden erkannt.
5. **Kettenlücke:** Entfernen eines mittleren Pakets erzeugt einen sichtbaren Lückenfehler.
6. **Vertauschung:** Vertauschte Pakete werden aufgrund Sequenz und Vorgänger-Hash abgelehnt.
7. **Fork:** Zwei verschiedene Pakete derselben Sequenz werden nicht beide angenommen.
8. **Replay:** Derselbe Hash ist idempotent und liefert denselben Receipt.
9. **Bösartiger Server-Key:** Ein nicht Root-signierter Reader-Key wird ignoriert.
10. **Mehrere Reader:** Ein Ciphertext wird über unterschiedliche Grants von mindestens zwei Readern entschlüsselt.
11. **Widerruf:** Ein widerrufener Reader erhält nach Registry-Empfang keine neuen Grants.
12. **Historischer Zugriff:** Ein neuer Reader kann ausgewählte alte Einträge erst nach Recovery-Re-Grant lesen; `.eip` bleibt byteidentisch.
13. **Server kompromittiert:** Vollständige Serverdaten enthalten ohne Reader-/Recovery-Key keinen entschlüsselbaren Einsatzinhalt.
14. **Server dauerhaft weg:** Ein lokales Archiv wird auf einem frischen Rechner mit einem unabhängig bereitgestellten Trust Anchor offline verifiziert und per Recovery entschlüsselt; ein konsistent ersetztes Archiv mit fremdem Root/Genesis wird abgelehnt.
15. **Stromausfall:** Abbruch an jedem Finalisierungsschritt ergibt einen wiederherstellbaren Entwurf oder die exakte Fertigstellung des vorbereiteten Commits, nie Neuserialisierung, Schlüsselleck oder ungültigen Kettenkopf.
16. **Falsche Gerätezeit:** Zurückgestellte Uhr ändert nicht die Kettenlogik; Geräte-, Server- und TSA-Zeit bleiben unterscheidbar.
17. **Schema und Suite v1/v2:** Neuer Reader validiert alte Pflichtfeldregeln, bildet eine gekennzeichnete Altansicht und verarbeitet alte/neue Suites parallel; alter Reader lehnt unbekannte Schemata, kritische Erweiterungen oder Suites sicher und ohne leeren Scheineintrag ab.
18. **Nachtrag:** Nachtrag referenziert das Original und wird gemeinsam angezeigt, ohne Originalbytes zu ändern.
19. **Keine Klartextlogs:** Canary-Fachwerte fehlen in Writer-, Reader-, Server- und CLI-Logs sowie Servermetadaten.
20. **Recovery-Bericht:** Die CLI erzeugt einen reproduzierbaren Bericht über Objektzahlen, Kettenkopf und Fehler.
21. **Backup-Restore:** Getrennter Restore stellt Datenbank und Objekte konsistent wieder her und verifiziert sie gegen einen Checkpoint.
22. **Cross-Platform Writer:** Auf jeder Desktop-Plattform erzeugte Archive werden auf allen anderen Plattformen bytegleich geprüft und entschlüsselt.
23. **Plattform-Key-Provider:** Schlüssel werden pro Plattform geschützt, nicht versehentlich exportiert und nach Sperre nicht ohne Re-Authentisierung verwendet.
24. **Registry-Überalterung:** Pflichtfelder `issuedAt`/`notBefore`/`notAfter`, Standard-`warn`, Standard-`block` und zwingendes Evidence-Grade-`block` entsprechen der Root-signierten Altersrichtlinie; eine verbrauchte Sequenz-Lease blockiert jedes Profil.
25. **Writer-Restore:** Ein veraltetes Writer-Backup blockiert bis zum vertrauenswürdigen Kettenkopf-Abgleich.
26. **Evidence Grade:** RFC-3161-CTT, TSA-Ausfall, Retry und ungültige Tokens werden korrekt behandelt; `ausstehend`/ `überfällig` beginnen ausschließlich am signierten Receipt-Zeitfenster, und ein Token nach `evidenceDueAt` bleibt dauerhaft überfällig.
27. **Evidence Renewal:** Mehrere Renewals bleiben ohne Umschreiben alter Dateien vollständig verifizierbar.
28. **CSV-Stammdatenimport:** Dry Run, Hash, Transaktion, Fehlerbericht und Snapshots funktionieren; historische Einsätze werden nicht importiert.
29. **Rollentrennung:** Lokale Konfiguration kann keine Rolle erweitern; Writer-Geräte enthalten keine Reader-, Recovery-, Historical-Grant-Authority- oder Key-Approver-Privatschlüssel.
30. **Kontrollierte Vernichtung:** Zwei Approver, alle bekannten Speicherorte, Backupfristen, unerreichbare Replikate, signierte Attestierungen und die erlaubten Zustände werden korrekt abgebildet.
31. **Performance:** 1-MiB-Finalisierung und 50.000-Paket-Reader erfüllen die Zielwerte.
32. **Release-Provenienz:** Artefakte, SBOM, Signaturen, Prüfsummen, aktuelle BSI-Prüfung und unabhängiges Review liegen vor.
33. **Unteilbarer Entry-Commit:** Fehlender, zusätzlicher oder falscher initialer Grant gegenüber genau einem Recovery-Empfänger und allen aktiven Reader-Zertifikaten verhindert lokalen und serverseitigen Commit; Entry und initiale Grants werden nie teilweise sichtbar.
34. **Prepared Recovery:** Vollständig synchronisiertes Staging ohne `draftDEK` wird nach Neustart exakt einmal und byteidentisch fertiggestellt.
35. **Registry-Angriffe:** Registry-Rollback und gleiche Version mit anderem Hash werden fail-closed behandelt. Eine zurückgehaltene, dem Server bekannte und für die Sequenz wirksame Aktualisierung führt zur Upload-Ablehnung; offline endet das nicht erkennbare Fenster spätestens an der harten Sequenz-Lease. Uhr-Rollback kann den monotonen `trustedTimeFloor` nicht senken.
36. **Server-Teilfehler:** Object-Store- oder Datenbankfehler erzeugen weder sichtbaren Kettenkopf noch als angenommen sichtbaren Receipt; Orphans werden geprüft übernommen oder quarantänisiert, und ein erfolgreicher Replay liefert byteidentische `.esr`-Bytes.
37. **Evidence-Verkettung:** Falsches CTT-Signaturfeld, falscher Vorgänger und gleiche Evidence-Sequenz mit anderem Head werden erkannt; Renewal bindet exakte Vorobjektbytes.
38. **CLI und Export:** Exitcodes, versioniertes JSON und Berichte sind deterministisch; ein vollständiger verschlüsselter Export lässt sich ohne Server, aber nur mit explizitem externem Trust Anchor authentisch verifizieren.
39. **Durable Backend:** Jede Plattform beweist exklusive Erstellung, File-/Directory-Flush, atomaren Same-Filesystem-Rename und Wiederanlauf. Ein freigegebenes kontrolliertes Netzlaufwerkprofil finalisiert ohne Netz in seine lokale Commit-Komponente und publiziert nach Wiederverbindung byteidentisch; nicht profilierte oder ungeeignete Pfade werden abgelehnt, und die UI bleibt bei exakt den vier normativen Sync-Zuständen.
40. **Historische Grant-Autorität:** Recovery-KEM, Grant-Signatur und Mehr-Augen-Authorization sind getrennt erforderlich; kein einzelner Recovery-KEM-Key kann allein re-granten, und Ablauf, Uhr-Rollback sowie Replay nach `expiresAt` blockieren Erzeugung, Annahme, Auslieferung und Entkapselung.
41. **Destroyed Entry Stub:** Ein gültiger `.eds` erhält Writer-Signatur, `entryHash` und Kettenkontinuität; eine nicht autorisierte Entfernung bleibt eine sichtbare Lücke.
42. **Fehlender Reader-Grant:** Ein gültiges Paket ohne eigenen Grant bleibt in der technischen Kette sichtbar, wird nicht entschlüsselt und zeigt eindeutig `fehlender Grant`.
43. **Inkrementeller Reader-Sync:** Sync ab bekanntem Kettenkopf ist idempotent, nimmt nach Abbruch am letzten bestätigten Cursor wieder auf und stoppt bei Startkopfabweichung, Lücke oder Fork.
44. **Datenschutz-Gate:** Ohne dokumentierte Freigabe kann kein `.eds`-basierter Vernichtungsprozess gestartet werden; der Go-live-Bericht enthält Einstufung und Entscheidung zum Restnachweis.
45. **Sync-Server-Administration:** Serveradministration kann Betrieb, Backup und Updates ausführen, aber weder Inhalte entschlüsseln noch Grants, Writer-Signaturen oder Registry-Autorität erzeugen; privilegierte Aktionen sind klartextfrei auditiert.
46. **Entwurf und Eingabevertrag:** Genau ein aktiver verschlüsselter Entwurf wird nach Absturz wiederhergestellt; `known: 0`, `known: n` und `unknown` für Patientenzahlen bleiben unterscheidbar; vollständige Prüfansicht und ausdrückliche Unwiderruflichkeitsbestätigung sind vor Finalisierung zwingend. Fault Injection am `discardIntent` und an der `draftDEK`-Löschung ergibt entweder den unveränderten Entwurf oder dauerhaft eine neue leere Maske, nie einen verworfenen wiederlesbaren Entwurf.
47. **Organisationsadministration:** Admin-Autorisierung, autorisierter Trust-Core, Action-Code, Einmaligkeit und Root-Signatur sind für Gerät, Operator, Registry, Policy, Writer- und Root-Wechsel exakt prüfbar; Root-only, Admin-only, falscher Core und Selbstrotation ohne zweiten Admin scheitern. Im Pre-Registry-Nullkontext ist nur ein von der extern bestätigten Anchor-Vorstufe gepinntes und eindeutig gepaartes Admin-Zertifikat-/Operator-Binding mit erfolgreicher OS-/Instanzschlüssel-Prüfung berechtigt; der finale Anchor bindet dieselben Felder. Nach erstem Registry-Head scheitert jede weitere Nullkontext-Nutzung. Re-Grant und Vernichtung bleiben getrennt an zwei passende Key Approver gebunden.
48. **Archivprofilwechsel:** Während des Profilwechsels ist Finalisierung gesperrt; erst ein vollständiges, bytegleiches, offline verifiziertes Ziel mit identischer Objektmenge und identischem Ketten-/Trust-Head wird atomar aktiviert. Jeder Fehler lässt ausschließlich das alte Profil aktiv.
49. **Registry-Wirksamkeit:** Golden- und Negativtests wählen für Zeit und Sequenz stets den höchsten anwendbaren Head, blockieren Lücken/Forks/future-only Heads, erzwingen den neueren wirksamen Head am Server und dokumentieren die unvermeidbare Offline-Grenze.
50. **Receipt-Fristanker:** Golden Files fixieren alle `esr-v1`-Feldpositionen, den Receipt-Digest, die sortierten Grant-Hashes und die Signatur. `acceptedAtServer`/`evidenceDueAt` werden beim Commit genau einmal signiert und ein Replay darf weder Zeit noch Bytes ändern.
51. **Grant-Interoperabilität:** Plattformübergreifende Golden Files fixieren Plan-Sortierung, Duplikatverbote, `eag-v1`, HPKE-Info/AAD sowie den Signatur-Digest einschließlich Kapselungswert und umschlossenem CEK; jede Ein-Byte-Abweichung wird abgelehnt.
52. **Geführter Recovery-Test:** Jede inventarisierte Schlüsselsicherung wird gegen Anchor und Zertifikat geprüft, Signaturschlüssel beantworten nur die Test-Domain-Challenge, jede Recovery-Sicherung entschlüsselt den Testeintrag im Speicher, und fehlende/falsche Medien verhindern einen erfolgreichen Gesamtbericht.
53. **Operator-Identität:** Writer-, Reader- und Admin-Aktionen sind an Root-signiertes `operatorBinding`, tatsächliches OS-Konto, nicht roamingfähigen Operator-Instanzschlüssel und native Re-Authentisierung gebunden; freier Operator-Text, falsches Konto, Widerruf und abgelaufene Sitzung werden abgelehnt und klartextfrei auditiert. Die initialen Admin-Bindings entstehen vor der ersten Admin-Autorisierung nur als Root-signierte, extern im Anchor gepinnte Paare; unpinned oder falsch gepaarte Bindings scheitern. Unter Ubuntu darf Löschen und Neuanlegen eines Kontos mit derselben UID selbst bei wiederverwendetem Home oder Restore das alte Binding nicht aktivieren.
54. **Record-ID und Sequenz:** UUIDv7-`recordId` ist organisationsweit eindeutig, jede committed Sequenz steigt exakt um eins, und Parallelitäts-, Crash- und Replaytests erzeugen weder doppelte IDs noch wiederverwendete Sequenzen.

Das Access-Import-Kriterium des Ausgangs-PRD ist ersatzlos gestrichen.

## 24. Interne Lieferstufen

Die Implementierung erfolgt in sieben intern abnehmbaren vertikalen Stufen. Keine Stufe reduziert den finalen v0.1-Scope.

1. **Vertrauenskern und Format:** Rust-Crates, Objektformate, Vektoren, Trust, Kette und Recovery-Grundbefehle.
2. **Offline-Writer:** verschlüsselter Entwurf, Stammdaten, atomare Finalisierung und lokales Archiv auf allen Plattformen.
3. **Blind-Sync:** signierte API, PostgreSQL, Object Store, Kettenannahme, Receipts und Offline-Queue.
4. **Reader:** Sync, Verifikation, lokale Entschlüsselung, verschlüsselter Index und plattformübergreifende UI.
5. **Administration und Recovery:** Einrichtung, Operator-Bindings, QR/Fingerprints, Registry, Widerruf, Writer-Wechsel, Re-Grant, geführter Recovery-Test, Nachträge und Vernichtung.
6. **Evidence Grade:** RFC-3161-CTT, Checkpoints, pending/overdue, Renewals und langfristige Prüfberichte.
7. **Release-Härtung:** vollständige OS-Matrix, Fault Injection, Performance, Backup-Restore, Supply Chain, Security Review und Betriebsdokumentation.

v0.1 gilt erst nach Stufe 7 und Erfüllung aller Abnahmekriterien als fertig.

## 25. Hauptrisiken und Grenzen

| Risiko oder Grenze | Behandlung |
|---|---|
| Recovery-Key verloren | zwei getrennte Backups, Mehr-Augen-Verfahren, quartalsweise Probe |
| Recovery-Trust-Anchor ersetzt oder verloren | mindestens zwei schreibgeschützte unabhängige Kopien und separat bestätigter Fingerprint; kein Trust-on-first-use |
| alle Adminschlüssel verloren | mindestens zwei aktive Administratoren und verifizierte Sicherungen; kein Root-only-Bypass |
| Recovery-Key kompromittiert | Offline-/Token-Verwahrung; historische Vertraulichkeit bleibt betroffen |
| Server löscht Daten | Writer-Archiv, Reader-Replikate, Backups, Checkpoints, optional Object Lock |
| Writer-Datenträger fällt vor Sync aus | Abschluss nur nach lokalem Commit; zusätzliches Backupziel |
| Writer aus altem Backup | Blockade bis Checkpoint-Abgleich |
| Server hält Widerruf zurück | signierte Registry mit kurzer Sequenz-Lease; Altersgrenze zusätzlich, Evidence Grade fail-closed |
| Server schleust Key ein | Root-signierte Registry ist alleinige Autorität |
| Reader gestohlen | FDE, App-Sperre, Widerruf; alte Grants bleiben Risiko |
| gemeinsames oder falsch gebundenes OS-Konto | produktiv verboten; Root-signiertes Operator-Binding, native Re-Authentisierung und Go-live-Inventar |
| Patientendaten im Freitext | UI-Warnung, Schulung, optionale lokale Musterwarnung |
| Gerätezeit manipuliert | getrennte Zeitarten, Receipts und TSA-Zeit |
| Algorithmus altert | Suite-Versionierung, neue Grants, Evidence Renewal |
| lokaler Administrator kompromittiert | Erkennung durch Signaturen/Checkpoints; keine absolute Verhinderung |
| alle Kopien gelöscht | nicht technisch verhinderbar; unabhängige Speicherorte erforderlich |
| autorisierter Reader fertigt Kopie an | nicht kryptografisch verhinderbar und nicht rückrufbar |
| Netzlaufwerk oder Volume ohne harte Semantik | nicht profiliertes Ziel wird abgelehnt; freigegebenes Netzprofil nutzt lokalen Offline-Commit und geprüfte byteidentische Publikation vor Server-Sync |

## 26. Normative und fachliche Grundlagen

- [BSI TR-02102-1 – Kryptographische Verfahren](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR02102/BSI-TR-02102.html), jeweils zum Release aktuelle Fassung
- BSI TR-03125 TR-ESOR als fachliche Orientierung, ohne Zertifizierungsbehauptung
- [DSGVO](https://eur-lex.europa.eu/eli/reg/2016/679/oj)
- [RFC 8949 – CBOR](https://www.rfc-editor.org/rfc/rfc8949.html)
- [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html) und [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053.html) – COSE
- [RFC 9180 – HPKE](https://www.rfc-editor.org/rfc/rfc9180.html)
- [RFC 8032 – Ed25519](https://www.rfc-editor.org/rfc/rfc8032.html)
- [RFC 8439 – ChaCha20-Poly1305](https://www.rfc-editor.org/rfc/rfc8439.html)
- [RFC 9421 – HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html)
- [RFC 9530 – Digest Fields](https://www.rfc-editor.org/rfc/rfc9530.html)
- [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html) und [RFC 5816](https://www.rfc-editor.org/rfc/rfc5816.html) – Time-Stamp Protocol
- [RFC 9921 – RFC-3161-Tokens in COSE](https://www.rfc-editor.org/rfc/rfc9921.html)
- [RFC 4998 – Evidence Record Syntax](https://www.rfc-editor.org/rfc/rfc4998.html)
- [RFC 9562 – UUIDs](https://www.rfc-editor.org/rfc/rfc9562.html)
- [RFC 9679 – COSE Key Thumbprints](https://www.rfc-editor.org/rfc/rfc9679.html)
- [Ant Design 6 – Migration und Design Tokens](https://ant.design/docs/react/migration-v6/)
- [Ant Design – Internationalisierung](https://ant.design/docs/react/i18n/)
- [Phosphor Icons for React](https://github.com/phosphor-icons/react)
- NIST FIPS 203 als Grundlage für spätere Post-Quantum-Suites

## 27. Rückverfolgbarkeit zum PRD

`AK n` bezeichnet ein nummeriertes Abnahmekriterium aus Abschnitt 23. `Gate §x` bezeichnet einen verbindlichen Test- oder Go-live-Nachweis im genannten Abschnitt, wenn kein eigenes nummeriertes AK sinnvoll ist. Die Matrix ist Navigationshilfe; normativ bleiben die vollständigen PRD-Anforderungen und die referenzierten Spec-Abschnitte. Numerische Lücken zwischen IDs sind im PRD nicht belegt.

### 27.1 Funktionale Anforderungen

| PRD-ID | Kurzanforderung | Normative Spec | Nachweis |
|---|---|---|---|
| FR-001 | Organisation, ID, Genesis | 8.5; 12.1 | Gate §12.1 |
| FR-002 | getrennte Schlüsselrollen | 6; 12.7 | AK 29, 40, 45, 47 |
| FR-003 | lokale Schlüsselerzeugung | 12.1; 12.7 | AK 23, 29 |
| FR-004 | keine Reader-/Recovery-Keys am Server | 3; 5.2–5.3; 6.5–6.7 | AK 13, 29, 45 |
| FR-005 | Root-signierte Freigaben/Widerrufe | 6.3–6.4; 12.2–12.4 | AK 9, 11, 35, 47 |
| FR-006 | Fingerprints und QR-Codes | 12.1; 17.3 | Gate §22.4 |
| FR-007 | ohne Recovery-Key kein Commit | 3; 9.2–9.3; 10.4; 13.3 | AK 1, 33, 51 |
| FR-008 | Schlüsselwechsel append-only/signiert | 8.5; 11.1; 12.3; 12.5 | AK 25, 35, 47 |
| FR-009 | Registry-Version, Frist, Vorgänger | 7; 12.3; 12.6 | AK 24, 35, 49 |
| FR-020 | Personen/Fahrzeuge pflegen/importieren | 8.6; 17.1 | AK 28; Gate §22.4 |
| FR-021 | verwendete Stammdaten als Snapshot | 8.3; 8.6; 9.2–9.3 | AK 28; Gate §22.4 |
| FR-022 | spätere Änderungen wirken nicht zurück | 3; 8.6; 10.6 | Gate §22.1 |
| FR-023 | Importherkunft und Ergebnis protokollieren | 8.6 | AK 28 |
| FR-024 | gekennzeichnete Ad-hoc-Snapshots | 8.6 | Gate §22.4 |
| FR-030 | genau ein aktiver Entwurf | 9.1; 17.1 | AK 46 |
| FR-031 | Entwurf lokal verschlüsselt | 9.1; 18.3 | AK 2, 23, 46 |
| FR-032 | Entwurf nach Absturz wiederherstellen | 9.1; 9.4 | AK 15, 34, 46 |
| FR-033 | Pflichtfelder und Plausibilität | 8.3; 9.2–9.3; 19.1 | AK 46; Gate §22.4 |
| FR-034 | Patientenzahl 0/n/unbekannt | 8.3 | AK 46 |
| FR-035 | keine identifizierenden Patientenfelder | 8.3; 18.1 | Gate §22.4–22.5 |
| FR-036 | vollständige Prüfansicht | 9.2; 17.1 | AK 46 |
| FR-037 | Unwiderruflichkeitswarnung | 9.2; 17.1 | AK 46 |
| FR-040 | eindeutige ID, steigende Sequenz | 8.2; 9.3; 10.3 | AK 6, 7, 15, 54 |
| FR-041 | direkter Vorgänger-Hash | 10.3; 11.2; 14.1 | AK 5–7 |
| FR-042 | Signatur des autorisierten Writers | 6.1; 10.3; 12.5; 13.3 | AK 4, 7, 35 |
| FR-043 | dauerhaft schreiben vor Kettenzustand | 9.3–9.4; 11.5 | AK 1, 15, 34, 39 |
| FR-044 | Writer zeigt finalisierten Inhalt nicht | 6.1; 17.1 | AK 2, 3 |
| FR-045 | Writer kann final nicht entschlüsseln | 3; 5.2; 9.3; 10.4; 12.7 | AK 2, 29 |
| FR-046 | anschließend neue leere Maske | 9.3; 17.1 | AK 3 |
| FR-047 | Paketdateien nie überschreiben | 3; 9.3; 11.4–11.5 | AK 39 |
| FR-048 | Sequenzkonflikt als Security Event | 13.3; 19.2 | AK 7; Gate §22.3 |
| FR-049 | Checkpoint-Abgleich vor Finalisierung | 9.3; 15.2; 19.2 | AK 25, 35 |
| FR-050 | Writer-Restore blockiert bis Kopfabgleich | 9.4; 15.2; 19.3 | AK 25 |
| FR-060 | lokal committed vor Upload | 9.3; 13.5 | AK 1, 39 |
| FR-061 | lokales oder kontrolliertes Netzprofil | 7; 9.3; 11.5 | AK 39, 48 |
| FR-062 | Schreibbarkeit, Platz, Atomizität prüfen | 9.2; 11.5; 19.1 | AK 15, 39, 48 |
| FR-063 | Archiv-Gesundheitscheck | 11.5; 19.3 | AK 4, 5; Gate §22.2 |
| FR-064 | Trust-Daten und Formatdokumentation | 11.4; 20.5 | AK 14, 38 |
| FR-065 | ohne DB-/Sync-Server verifizierbar | 3; 11; 16.1 | AK 14, 38 |
| FR-066 | Backupziel und getesteter Restore | 7; 21 | AK 21, 25 |
| FR-080 | vollständig offline finalisieren | 9; 20.2 | AK 1, 15, 39 |
| FR-081 | Upload idempotent | 13.3 | AK 8, 36, 50 |
| FR-082 | nur erwarteten Nachfolger annehmen | 13.3 | AK 7, 36 |
| FR-083 | blind Signatur/Kette prüfen | 10.3; 11.2; 13.3 | AK 4, 7, 13, 33; Gate §22.3 |
| FR-084 | signierter Serverbeleg | 6.6; 11.1; 13.3; 15.2 | AK 8, 36, 50 |
| FR-085 | inkrementeller Reader-Sync | 13.2; 14.5 | AK 43 |
| FR-086 | content-addressed Objekte | 11.1; 13.3–13.4 | AK 8, 36; Gate §22.3 |
| FR-087 | Replay erzeugt kein Duplikat | 13.3 | AK 8, 36, 50 |
| FR-088 | synchron erst nach lokalem Receipt | 13.5 | AK 8, 50; Gate §22.3 |
| FR-089 | Syncstatus ohne Fachklartext | 13.5; 17.4; 18.2 | AK 19, 39 |
| FR-100 | gemeinsame App, signierte Rollentrennung | 5.1–5.2; 6 | AK 29 |
| FR-101 | vollständig prüfen vor Entschlüsselung | 14.1 | AK 4–6, 9, 13, 17, 42 |
| FR-102 | Lücke/Signatur/Key/Grant sichtbar | 14.1; 17.2; 17.4 | AK 4, 5, 9, 42 |
| FR-103 | Reader-Cache und Index verschlüsselt | 14.2; 18.3 | AK 23; Gate §22.4–22.5 |
| FR-104 | automatische Inaktivitätssperre | 7; 14.2 | Gate §22.4 |
| FR-105 | kein Klartext-Massenexport als Default | 14.4 | Gate §22.4 |
| FR-106 | Einzelexport lokal auditieren | 14.4; 18.3 | Gate §22.4–22.5 |
| FR-107 | mehrere Schemata/Suites oder sicherer Abbruch | 10.5–10.6; 14.1 | AK 17 |
| FR-120 | Nachtrag als neuer Ketteneintrag | 8.1; 8.4; 14.3 | AK 18 |
| FR-121 | Original-ID/-Hash, Grund, Ersteller | 8.4 | AK 18; Gate §22.4 |
| FR-122 | Original und Nachtrag gemeinsam anzeigen | 14.3; 17.2 | AK 18 |
| FR-123 | Original nicht ändern/verbergen | 3; 8.4; 14.3 | AK 18 |
| FR-124 | mehrere Nachträge unterstützen | 8.4 | AK 18; Gate §22.4 |
| FR-140 | separates Offline-Recovery-Werkzeug | 5.1; 16.1 | AK 14, 20, 38 |
| FR-141 | ohne proprietären Onlinedienst | 2; 16.1 | AK 14, 38 |
| FR-142 | öffentliches, versioniertes Format | 10.5–10.6; 11; 20.5 | AK 17, 32, 38 |
| FR-143 | vollständiger verschlüsselter Export | 13.2; 16.1 | AK 38 |
| FR-144 | vollständiger Recovery-Prüfbericht | 16.1 | AK 20 |
| FR-145 | historische Grants nur autorisiert signiert | 6.5; 10.4; 16.2 | AK 12, 40, 51 |

### 27.2 Nichtfunktionale Anforderungen

| PRD-ID | Kurzanforderung | Normative Spec | Nachweis |
|---|---|---|---|
| NFR-SEC-001 | keine Eigenbau-Kryptografie | 10.1; 20.1 | AK 32 |
| NFR-SEC-002 | kleiner testbarer Kryptokern | 5.1; 20.1 | Gate §22.1 |
| NFR-SEC-003 | Keys nicht in Logs/Dumps/Konfiguration | 18.2–18.3; 20.1 | AK 19, 23 |
| NFR-SEC-004 | automatisierte Schwachstellenprüfung | 20.1; 22.5 | AK 32 |
| NFR-SEC-005 | gehärtete Archivparser | 11.3; 20.1; 22.1 | AK 4; Gate §22.1 |
| NFR-SEC-006 | unabhängiges Security Review | 10.1; 20.1; 21 | AK 32 |
| NFR-SEC-007 | reproduzierbare/signierte Releases | 20.1; 22.5 | AK 32 |
| NFR-OFF-001 | Erfassung/Finalisierung ohne Netz | 9; 20.2 | AK 1, 15, 39 |
| NFR-OFF-002 | Serverausfall ohne Datenverlust | 9.3; 13.5; 20.2 | AK 14, 21 |
| NFR-OFF-003 | lokaler Archivcommit vor Erfolg | 9.3; 20.2 | AK 1, 15, 39 |
| NFR-OFF-004 | automatische Sync-Wiederaufnahme | 13.3; 13.5; 20.2 | AK 8, 43 |
| NFR-PERF-001 | 1 MiB in höchstens 3 Sekunden | 20.3 | AK 31 |
| NFR-PERF-002 | Eingabe unabhängig vom Sync flüssig | 17.5; 20.3 | Gate §22.4 |
| NFR-PERF-003 | mindestens 50.000 Reader-Pakete | 20.3 | AK 31 |
| NFR-ROB-001 | Stromausfall ohne falschen Commit | 9.3–9.4; 20.4; 22.2 | AK 15, 34 |
| NFR-ROB-002 | temporäre Dateien sicher bereinigen | 9.4; 20.4 | AK 15, 34 |
| NFR-ROB-003 | Kettenkopf aus Archiv rekonstruierbar | 3; 9.4; 19.3; 20.4 | AK 15, 25, 34 |
| NFR-ROB-004 | Recovery ohne Vertrauen in Dateinamen | 11.4–11.5; 19.3; 20.4 | AK 14, 20, 38 |
| NFR-ROB-005 | Writer-Rollback über Checkpoints erkennen | 9.3–9.4; 15.2; 20.4 | AK 25, 35 |
| NFR-MAIN-001 | Schema, Format, Suite getrennt versionieren | 3; 10.5–10.6; 20.5 | AK 17, 27, 32 |
| NFR-MAIN-002 | Krypto-/Format-Testvektoren im Repository | 5.1; 20.5; 22.1 | Gate §22.1 |
| NFR-MAIN-003 | alte Vektoren dauerhaft in CI | 20.5; 22.1 | Gate §22.1 |
| NFR-MAIN-004 | Recovery bei jeder Formatänderung testen | 16.1; 20.5; 22.7 | AK 17, 38; Gate §22.7 |

### 27.3 Nicht nummerierte PRD-Inhalte und ursprüngliche Abnahme

| PRD-Abschnitt | Umsetzung in dieser Spec | Verifikation |
|---|---|---|
| 0 Architekturentscheidungen | 4, 5, 10–16, 20–22 | AK 22, 23, 32, 38, 45 |
| 1–5 Vision, Ausgangslage, Ziele, Nicht-Ziele, Begriffe | 1–3 sowie die jeweils normativen Fachabschnitte | Scope-Review; Access-Abweichung in 1.1 |
| 6 Rollen und Berechtigungen | 5.2; 6; 12.7; 21 | AK 29, 40, 45, 47, 53 |
| 7 zentrale Nutzerabläufe | 9; 12–17 | AK 1–18, 25, 30, 33–54 je Ablauf |
| 9 fachliches Datenmodell | 8; 10.6; 11.2 | AK 17, 18, 28, 46 |
| 10 kryptografische Architektur | 3; 6; 10; 12.3; 15 | AK 2, 4, 9–14, 24–27, 33, 35, 37, 40, 47, 49–52 |
| 11 technische Bedeutung von Revisionssicherheit | 3; 17.4; 21; 25 | Go-live-Bericht und Kommunikationsreview |
| 12 Sync-Server | 6.6–6.7; 13 | AK 7, 8, 13, 33, 35, 36, 43, 45, 50 |
| 13 Dateiformat/Archivstruktur | 10; 11 | AK 4, 14, 38, 41, 50, 51 |
| 14 Schemaentwicklung | 10.5–10.6; 20.5 | AK 17 |
| 15 Access-Migration | gemäß 1.1 ersatzlos ausgeschlossen | kein Gate und kein AK |
| 16 Datenschutz/Aufbewahrung | 16.3; 18; 21 | AK 19, 30, 41, 44 |
| 17 UX | 5.4; 17 | AK 3, 39, 42, 46, 47, 52, 53; Gate §22.4 |
| 18 Nichtfunktionales | 20; 22; Einzelmatrix 27.2 | AK/Gates gemäß 27.2 |
| 19 Referenzarchitektur | 4; 5; 12.7; 13.4 | AK 22, 23, 32, 45 |
| 20 ursprüngliche Abnahmekriterien | 23 | Zuordnung im Folgeabsatz |
| 21 Betriebsanforderungen | 21; 22 | AK 21, 32, 44, 47, 52, 53 |
| 22 Risiken | 25 sowie jeweilige normative Gegenmaßnahmen | Risiko-Review vor Go-live |
| 23 Grundlagen | 26 | Release-Security-/Compliance-Review |

Die ursprünglichen PRD-Abnahmekriterien 1–18 entsprechen den AK 1–18 dieser Spec. Das allein Access betreffende PRD-Kriterium 19 ist gemäß Abschnitt 1.1 ersatzlos ausgeschlossen. PRD-Kriterium 20 ist AK 19, PRD-Kriterium 21 ist AK 20 und PRD-Kriterium 22 ist AK 21. AK 22–54 sind konkretisierende plattform-, sicherheits-, betriebs- und formatbezogene Erweiterungen; sie ersetzen keine PRD-Anforderung.
