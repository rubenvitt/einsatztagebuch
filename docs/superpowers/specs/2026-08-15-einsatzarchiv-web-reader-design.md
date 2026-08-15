# Einsatzarchiv: Web-Reader und Rollenaufteilung der Anwendungen

**Status:** freigegeben am 2026-08-15
**Entscheidung:** Der Reader wird eine Browser-Anwendung. Writer und Administration bleiben Desktop.

## 1. Ziel und Geltungsbereich

Diese Korrektur ändert die Anwendungszuordnung der v0.1-Rollen. Bisher lieferte
eine gemeinsame Tauri-Desktopanwendung Writer, Reader und Administration
(Design §5.2). Neu gilt:

- **Desktop (Tauri):** Writer und Administration.
- **Browser (installierbare PWA):** Reader.

Der Auslöser ist betrieblich: Auf Lesegeräten soll nichts installiert werden
müssen. Lesende arbeiten auf eigenen, aber nicht von der Organisation
verwalteten Geräten.

Diese Spezifikation legt fest, wie der Reader im Browser betrieben wird, ohne
die kryptografischen Invarianten der v0.1 zu schwächen. Sie ändert keine
Wireformate, keine Objektfamilien, keine Verifikationsreihenfolge und keine
Signaturregeln. Sie ändert die Ausführungsumgebung des Readers, die Verwahrung
der Reader-Schlüssel, die Auslieferung des Reader-Codes und die Wiederherstellung
nach Schlüsselverlust.

Nicht Bestandteil: Writer-Verhalten, Administrationsworkflows, Serverprotokoll
außer der unten benannten Ergänzungen, Evidence-Verfahren, Vernichtung.

## 2. Getroffene Entscheidungen

1. Der Reader läuft im Browser; Administration bleibt Desktop-Anwendung.
2. Der Web-Reader arbeitet in zwei Modi: über den blinden Sync-Server und
   direkt aus Dateien ohne jede Serverbeteiligung.
3. Das Web-Bundle wird Root-signiert und gepinnt; ein Service Worker aktiviert
   nur signierte Versionen.
4. Reader-Schlüssel werden im Browser erzeugt, in einem lokalen Vault verwahrt
   und über WebAuthn-PRF-Envelopes entsperrt. Zwei Authenticators sind Pflicht.
5. Der X25519-KEM-Schlüssel eines Readers wird zusätzlich an den
   Recovery-Public-Key verschlüsselt hinterlegt (Escrow), damit Schlüsselverlust
   keinen Historical Re-grant über den gesamten Bestand auslöst.
6. Der verschlüsselte lokale Index wird als Rust-Datenstruktur in OPFS geführt;
   SQLCipher entfällt im Reader-Pfad.

## 3. Rollen- und Anwendungszuordnung

Design §5.2 wird ersetzt:

- Die **Desktopanwendung** schaltet Writer- und Administrationsfunktionen
  ausschließlich anhand gültiger signierter Gerätezertifikate frei. Ein lokaler
  Konfigurationswert oder UI-Schalter DARF keine Rolle hinzufügen oder erweitern.
- Die **Web-Anwendung** stellt ausschließlich Reader-Funktionen bereit. Sie
  enthält keinen Code für Writer-Finalisierung, Root-Zeremonien,
  Operator-Provisionierung, Historical Re-grant oder Vernichtungsausführung.
- Ein Writer-Gerät DARF weiterhin niemals einen privaten Reader-, Recovery- oder
  Historical-Grant-Authority-Schlüssel besitzen.
- Die Administrationsrolle verleiht weiterhin keinen Inhaltszugriff.

Die Vertrauenszonen aus Design §5.3 werden um eine Zone ergänzt:

5. **Browser-Zone:** installierte Web-Anwendung, Reader-Vault, verschlüsselter
   lokaler Index, gepinnter Root-Anchor. Sie ist gegenüber der Serverzone
   misstrauisch; sie akzeptiert weder Code noch Vertrauensmaterial allein auf
   Aussage des Servers.

## 4. Auslieferung und Pinning des Web-Bundles

### 4.1 Getrennter Verteilweg

Das Web-Bundle MUSS von einem Origin ausgeliefert werden, der vom Sync-Server
getrennt ist. Der Sync-Server ist damit nicht Bestandteil des Vertrauenspfades
für ausgeführten Code. Eine Kompromittierung des Sync-Servers allein kann keinen
manipulierten Reader-Code an Daten bringen.

### 4.2 Bundle-Freigabe als Trust-Objekt

Ein Release erzeugt ein reproduzierbares Bundle. Sein Hash wird in ein
Root-signiertes, append-only Trust-Objekt `webBundleRelease` aufgenommen. Das
Objekt bindet mindestens Bundle-Hash, Bundle-Version, Wirksamkeits- und
Widerrufsinformationen und folgt den Regeln der übrigen Trust-Objekte.

Der Service Worker DARF eine neue Bundle-Version nur aktivieren, wenn deren Hash
gegen eine im lokalen Trust-Store gepinnte, Root-signierte `webBundleRelease`
aufgeht. Ein nicht signiertes oder widerrufenes Bundle wird verworfen; die zuletzt
gültige Version bleibt aktiv.

Ein Widerruf erreicht ein Gerät erst beim nächsten Bezug des Trust-Bestandes. Ein
dauerhaft im Datei-Modus betriebenes Gerät kann daher eine widerrufene
Bundle-Version weiter ausführen. Die Anwendung MUSS deshalb das Alter des zuletzt
bezogenen Trust-Standes sichtbar ausweisen und ab einer in der Policy
konfigurierten Frist zur Aktualisierung auffordern.

### 4.3 Bootstrap des ersten Aufrufs

Der erste Aufruf besitzt noch keinen Trust-Store und kann sich nicht selbst
verifizieren. Er wird über den bereits bestehenden Fingerprint-Vergleich des
Enrollments abgesichert: Die Web-Anwendung zeigt ihren Bundle-Fingerprint, die
Administrations-Desktopanwendung zeigt den erwarteten Fingerprint, und der
Administrator vergleicht beide gemeinsam mit dem Schlüssel-Fingerprint des
Readers, bevor er die Gerätefreigabe autorisiert.

Ein Enrollment DARF NICHT abgeschlossen werden, wenn die Fingerprints abweichen.

Dasselbe Bootstrap-Problem tritt erneut auf, wenn ein bereits registrierter Reader
die Anwendung auf einem **neuen Gerät** erstmals aufruft: Der lokale Trust-Store
ist leer, das Bundle kann sich nicht selbst verifizieren, und der Vault-Blob wird
erst durch den bereits ausgeführten Code entschlüsselt. Dieser Fall wird nicht
technisch aufgelöst, sondern organisatorisch: Die Anwendung zeigt vor der ersten
Entsperrung ihren Bundle-Fingerprint, und der Reader vergleicht ihn gegen eine
unabhängig verteilte Referenz. Als Referenzquellen gelten die
Administrations-Desktopanwendung und die mit dem Release verteilte
Fingerprint-Bekanntgabe. Ein abweichender Fingerprint bedeutet Abbruch und Meldung
an die Administration.

Die Web-Anwendung MUSS diesen Vergleich bei jedem Erstaufruf auf einem Gerät ohne
gepinnten Trust-Store erzwingen und DARF ihn nicht überspringbar gestalten.

### 4.4 Folge für den Releaseprozess

Eine neue Reader-Version erfordert eine Root-Zeremonie. Spontane Web-Deployments
sind ausgeschlossen. Dies ist beabsichtigt und entspricht dem Aufwand, der für
Gerätezertifikate ohnehin gilt.

## 5. Betriebsmodi

### 5.1 Server-Modus

Normalbetrieb. Inkrementelle Replikation exakter Objektbytes über den blinden
Sync-Server, Receipts und Checkpoints verfügbar, verifizierter Cursor persistent
in OPFS. Funktional entspricht dieser Modus dem bisherigen Desktop-Reader.

### 5.2 Datei-Modus

Die Web-Anwendung öffnet Archivobjekte direkt aus dem Dateisystem, ohne jede
Serverbeteiligung. Zwei Wege:

- **Universell:** Die Desktop-Anwendung exportiert ein Archiv-Bündel als eine
  Datei. Der Reader wählt sie über den normalen Dateidialog. Dieser Weg
  funktioniert in allen unterstützten Browsern.
- **Chromium-Komfortweg:** `showDirectoryPicker` bindet einen Archivordner oder
  ein profiliertes Netzlaufwerk dauerhaft an. `showDirectoryPicker` ist in Safari
  und Firefox nicht verfügbar; der universelle Weg MUSS daher immer angeboten
  werden.

### 5.3 Vertrauensanker im Datei-Modus

Verifiziert wird IMMER gegen den beim Enrollment im Vault gepinnten Root-Anchor.
Trust-Objekte, die in der geöffneten Datei mitgeliefert werden, begründen für
sich kein Vertrauen. Ein untergeschobenes Archiv mit eigener Vertrauenskette
fällt an dieser Prüfung durch.

Damit gilt die bestehende Invariante „Authentische Offline-Recovery beginnt an
einem unabhängig verwahrten Trust Anchor" unverändert auch im Browser.

### 5.4 Unterschiede der Gate-Reihenfolge

Die Reihenfolge aus Design §14.1 gilt in beiden Modi wortgleich. Einziger
Unterschied ist Schritt 7: Im Datei-Modus werden nur die im Bündel enthaltenen
Receipts und Checkpoints geprüft. Objekte ohne Receipt werden in der Oberfläche
sichtbar als *nicht server-bestätigt* ausgewiesen und DÜRFEN NICHT als
vollständig bestätigt dargestellt werden.

Der Cursor-Mechanismus entfällt im Datei-Modus ersatzlos. Jedes Objekt wird bei
jedem Öffnen vollständig geprüft.

## 6. Schlüsselverwahrung im Browser

### 6.1 Vault

Ein zufälliger 32-Byte-Vault-Key verschlüsselt mit ChaCha20-Poly1305 ein Bündel
aus:

- X25519-KEM-Schlüssel des Readers,
- Ed25519-Geräte- und Audit-Schlüssel des Readers,
- gepinntem Root-Anchor,
- zuletzt verifiziertem Registry-Stand.

Das Chiffrat liegt in OPFS.

### 6.2 Envelope über WebAuthn-PRF

Für jeden registrierten Authenticator wird ein Key-Encryption-Key abgeleitet:

```text
KEK_i = HKDF(PRF_i(festes App-Salt), info = "ea-reader-vault-v1")
```

Mit `KEK_i` wird der Vault-Key gewrappt. Es entsteht ein Wrapped-Blob je
Authenticator.

Die PRF-Ausgabe DARF NICHT direkt als Verschlüsselungsschlüssel verwendet werden.
Andernfalls macht das Löschen eines Passkeys die Daten dauerhaft unerreichbar.
Die Envelope-Konstruktion macht jeden Authenticator zu einem Entsperrweg unter
mehreren.

### 6.3 Zwei Authenticators sind Pflicht

Ein Enrollment MUSS mindestens zwei unabhängige Authenticators registrieren.
Damit ist der Escrow-Pfad aus Abschnitt 7 der seltene Ausnahmefall und nicht der
Regelweg.

### 6.4 Ablage der Wrapped-Blobs

Die Wrapped-Blobs liegen lokal in OPFS und zusätzlich als opake Chiffrate beim
Sync-Server. Der Server kennt weder Vault-Key noch PRF-Ausgaben. Ein geräumtes
Browserprofil oder ein Gerätewechsel wird damit ohne Administrationsvorgang
gelöst: Blob beziehen, Authenticator bestätigen, weiterarbeiten.

### 6.4.1 Abruf des Blobs auf einem Gerät ohne Vault

Der reguläre Serverzugriff wird nach RFC 9421 mit dem Ed25519-Schlüssel des
Readers signiert. Dieser Schlüssel liegt jedoch im Vault, der ohne Blob nicht
entsperrt werden kann. Der Blob-Abruf DARF deshalb nicht über den regulären
signierten Pfad laufen.

Festlegung: Beim Enrollment werden dieselben Authenticators zusätzlich als
WebAuthn-Credentials beim Sync-Server registriert, mit der pseudonymen
`subjectId` als `userHandle`. Der Abruf eines Wrapped-Blobs erfordert eine
gültige WebAuthn-Assertion über ein auffindbares Credential dieses Readers. Der
Server gibt daraufhin ausschließlich die zu dieser `subjectId` gehörenden opaken
Chiffrate heraus. Danach entsperrt die PRF-Auswertung desselben Authenticators
den Vault; ab diesem Punkt läuft jede weitere Anfrage RFC-9421-signiert.

Damit werden beide Verwendungen desselben Authenticators sauber getrennt: die
Assertion authentisiert den Transport, die PRF-Ausgabe entsperrt den Vault. Der
Endpunkt ist nicht unauthentisiert und bietet keine Enumerationsfläche.

Diese Registrierung verleiht dem Server KEINE Autorität: Rollen, Capabilities und
Geräteautorität leiten sich unverändert ausschließlich aus Root-signierten
Trust-Objekten ab. Der Server entscheidet allein, wem er ein Chiffrat aushändigt,
das ohne Authenticator wertlos ist.

Bei synchronisierten Passkeys ist die PRF-Ausgabe bei gleichem Salt über die
Geräte des Nutzers stabil. Der Cross-Device-Flow per QR-Code liefert in Safari
keine PRF-Ausgabe; dieser Weg wird nicht als Entsperrpfad angeboten.

### 6.5 Schlüsselmaterial zur Laufzeit

Der X25519-Schlüssel kann nicht als nicht-exportierbarer WebCrypto-Schlüssel
gehalten werden, weil die HPKE-Entkapselung im WASM-Modul erfolgt und den
Rohschlüssel benötigt. Er liegt daher während einer entsperrten Sitzung im
WASM-Speicher.

Verpflichtende Gegenmaßnahmen:

- `zeroize` beim Sperren der Sitzung,
- Sperrung nach der im Design geforderten Inaktivität, Standard fünf Minuten,
- verkürzte Frist bei Wechsel des Tabs in den Hintergrund,
- erneute Authenticator-Bestätigung nach jeder Sperrung.

### 6.6 Enrollment

1. Der Reader erzeugt X25519- und Ed25519-Schlüsselpaar im Browser. Private
   Schlüssel verlassen den Browser nie.
2. Der Reader registriert zwei Authenticators; der Vault wird gewrappt.
3. Die Anwendung zeigt Schlüssel-Fingerprint und Bundle-Fingerprint.
4. Der Administrator vergleicht beide in der Desktop-Anwendung und autorisiert.
   Root signiert das Reader-Zertifikat.
5. Im selben Vorgang entsteht das Escrow-Objekt nach Abschnitt 7.
6. Für Einträge vor dem Enrollment greift unverändert der reguläre Historical
   Re-grant nach Design §6.5.

## 7. Reader-Key-Escrow

### 7.1 Begründung

Der Recovery Custodian verwahrt nach Design §6.5 bereits einen X25519-KEM-
Schlüssel ohne Signaturbefugnis und kann per Invariante jeden CEK entkapseln, da
jeder Eintrag einen Recovery-Grant trägt. Ein an genau diesen Public Key
verschlüsselter Reader-KEM-Schlüssel verleiht ihm daher keine Fähigkeit, die er
nicht bereits besitzt.

Kein Reader-Schlüssel muss überleben: Verlust kostet Zugriffskomfort, niemals
Daten. Das zu lösende Problem ist ausschließlich der Preis der Wiederherstellung.
Ohne Escrow erfordert ein neuer Reader-Schlüssel einen Historical Re-grant über
den gesamten Altbestand, also je Eintrag eine Recovery-Entkapselung, eine
HGA-Signatur und ein neues Grant-Objekt. Mit Escrow ist es ein Vorgang mit einer
Autorisierung, und alle bestehenden Grants bleiben gültig, weil der
Empfängerschlüssel derselbe bleibt.

### 7.2 Umfang

Hinterlegt wird ausschließlich der **X25519-KEM-Schlüssel**.

Der Ed25519-Geräte- und Audit-Schlüssel DARF NICHT hinterlegt werden. Andernfalls
könnte Recovery Acknowledgements und Audit-Ereignisse im Namen eines Readers
erzeugen; das wäre eine neue Fähigkeit und keine Wiederholung einer bestehenden.
Nach einer Wiederherstellung wird der Audit-Schlüssel neu erzeugt und neu
zertifiziert.

### 7.3 Getrennte Verwahrung

Das Escrow-Chiffrat liegt im Root-signierten, append-only Trust-Bestand der
Administrationszone. Es liegt NICHT beim Recovery Custodian. Der Custodian hält
den Schlüssel ohne Chiffrat, die Administrationszone das Chiffrat ohne Schlüssel.
Ein einzelner kompromittierter Verwahrort genügt nicht.

### 7.4 Bindung

Das HPKE-Chiffrat bindet als AAD:

- Hash des Reader-Zertifikats,
- pseudonyme `subjectId` des Readers,
- Registry-Version zum Zeitpunkt des Enrollments.

Damit ist ein Escrow-Blob weder auf eine andere Identität umhängbar noch in einen
älteren Registry-Stand zurückspielbar.

### 7.5 Öffnungszeremonie

Die Öffnung erfordert:

- physischen Zugriff auf den Recovery-KEM-Schlüssel,
- eine `organizationAdminAuthorization`, signiert von zwei verschiedenen
  Approvern, über die konkrete Ziel-Identität, den Zweck **und den Fingerprint
  des Ziel-Transport-Public-Keys**,
- ein lokales Audit-Ereignis.

Die Bindung des Transport-Public-Keys ist verpflichtend und folgt derselben Logik
wie die Bindung expliziter Ziel-Entry-Hashes beim Historical Re-grant. Ohne sie
attestieren die Approver nur das Subjekt, nicht das Ziel; die ausführende Person
könnte im Moment der Re-Encryption ihren eigenen Transport-Schlüssel einsetzen und
den Reader-Schlüssel allein übernehmen. Das Werkzeug MUSS die Re-Encryption
verweigern, wenn der vorgelegte Transport-Public-Key nicht dem in der
Autorisierung gebundenen Fingerprint entspricht.

Der wiederhergestellte Schlüssel wird niemandem angezeigt und nirgends
persistiert. Der Reader erzeugt im Browser einen frischen Transport-Public-Key
und zeigt dessen Fingerprint; dieser wird den Approvern vor der Signatur
vorgelegt. Das Recovery-Werkzeug verschlüsselt den KEM-Schlüssel unmittelbar an
diesen neuen Vault. Der Klartext existiert nur im Arbeitsspeicher des Werkzeugs.

Die Zeremonie greift ausschließlich, wenn alle Authenticators eines Readers
verloren sind. Der häufige Fall aus Abschnitt 6.4 läuft ohne Administration.

### 7.6 Benanntes Restrisiko

Während der Zeremonie liegt der Klartextschlüssel im Speicher des Werkzeugs. Ein
böswilliger Custodian mit zwei kooperierenden Approvern könnte ihn kopieren und
hätte danach stillen Dauerzugang zu allen Inhalten, für die dieser Reader Grants
besitzt. Technisch ist das nicht ausschließbar. Die Bindung des
Transport-Public-Keys aus Abschnitt 7.5 stellt jedoch sicher, dass dafür
tatsächlich alle Beteiligten kooperieren müssen und die ausführende Person allein
nicht genügt. Darüber hinaus gelten die organisatorischen Maßnahmen, die das
Design ohnehin fordert: getrennte Personen, physisch kontrollierte
Schlüsselmedien, Audit, geführter Recovery-Test.

## 8. Lokaler Index, Suche und Export

### 8.1 Index

SQLCipher entfällt im Reader-Pfad. Der lokale Index ist ein invertierter Index
über entschlüsselte Feldwerte, implementiert in Rust, als Ganzes mit
ChaCha20-Poly1305 verschlüsselt in OPFS abgelegt und beim Entsperren in den
WASM-Speicher geladen.

Damit entsteht keine zweite Indeximplementierung in TypeScript und kein
verschlüsselndes SQLite-VFS im Browser.

Der Ansatz trägt bis in den Bereich einiger zehntausend Einsätze. Wird diese
Größenordnung überschritten, ist der Wechsel auf segmentierte, einzeln
verschlüsselte Indexblöcke ein lokaler Eingriff ohne Architekturänderung. Die
verbindliche Schwelle wird in der Stage-4-Überarbeitung festgelegt.

### 8.2 Export

Unverschlüsselter Massenexport bleibt deaktiviert. Ein Einzelexport erfordert
bewusste Zielwahl, erneute Authenticator-Bestätigung und ein signiertes lokales
Audit-Ereignis. Die Authenticator-Bestätigung ersetzt die native
Re-Authentisierung des Desktops.

Entschlüsselte Inhalte DÜRFEN NICHT in Zwischenablage-Automatismen, Telemetrie,
Servermetadaten oder Fehlerberichte gelangen.

## 9. Verifikation im Browser

Die Verifikationspipeline bleibt geteilter Rust-Code. Kryptografische oder
formatkritische Logik DARF NICHT in TypeScript nachgebaut werden. TypeScript
erhält ausschließlich Ansichts- und Status-DTOs.

Der Gate-Ablauf aus Design §14.1 wird unverändert übernommen. Nur
`VerifiedEncryptedEntry` zusammen mit `VerifiedGrantForRecipient` erreicht den
HPKE-Entkapseler. Fehlender eigener Grant bleibt exakt `fehlender Grant` und wird
nicht als Beschädigung dargestellt.

## 10. Machbarkeitsnachweis

Geprüft am 2026-08-15 mit `cargo check --target wasm32-unknown-unknown` gegen
`ea-types`, `ea-cbor`, `ea-crypto`, `ea-format`, `ea-schema`, `ea-time` und
`ea-trust`:

- Der Check ist erfolgreich, einschließlich `ed25519-dalek 3.0`,
  `x25519-dalek 3.0`, `hpke 0.14`, `chacha20poly1305 0.11`, `sha2 0.11`,
  `minicbor 2.3` sowie `jiff 0.2.35` mit gebundelter tzdb.
- Einzige erforderliche Anpassung: `getrandom 0.4.3` benötigt das Feature
  `wasm_js` und `--cfg getrandom_backend="wasm_js"`.

**Reichweite dieses Nachweises:** Belegt ist ausschließlich, dass die Crates für
`wasm32-unknown-unknown` übersetzen. Nicht belegt sind Ausführung, die
`wasm-bindgen`-Schicht, das tatsächliche Verhalten des `wasm_js`-Backends in einer
JS-Umgebung, die HPKE-Entkapselung zur Laufzeit sowie `ea-reader`, das noch nicht
existiert. Der Laufzeitnachweis steht aus und ist als Voraussetzung in
Abschnitt 14 geführt.

`wasm32-unknown-unknown` wird verbindliches Ziel im Verifikations-Gate, damit
spätere Crate-Änderungen die Browser-Fähigkeit nicht unbemerkt zerstören.

## 11. Abweichungen und Ergänzungen zu bestehenden Normen

1. **Design §5.2** wird durch Abschnitt 3 ersetzt.
2. **„OS-Lock beendet die Sitzung"** hat im Browser keine Entsprechung. Ersatz
   ist Abschnitt 6.5. Dokumentierte SOLL-Abweichung mit sicherheitstechnischer
   Begründung.
3. **Nativer Reader-Key-Provider** entfällt. Die Anforderungen an Nicht-Roaming
   und Backup-Ausschluss gelten sinngemäß für den Vault: Wrapped-Blobs sind ohne
   Authenticator wertlos, Klartextschlüssel werden nie persistiert.
4. **Support-Matrix (Stage 7)** erhält für den Reader eine Browser-Achse aus
   Engine, Version und Plattform. Die Achsen Architektur, Installerformat und
   Key-Provider entfallen für den Reader und gelten weiterhin für Writer,
   Administration und CLI.
5. **Neue Trust-Objektfamilie** `webBundleRelease` nach Abschnitt 4.2.
6. **Neues Escrow-Objekt** nach Abschnitt 7.

## 12. Auswirkungen auf die Stufenpläne

- **Stage 1:** `wasm32`-Ziel im Verifikations-Gate, `getrandom`-Feature. Sonst
  unverändert.
- **Stage 2:** Task 8 schaltet nur noch Writer und Administration frei. Neuer
  Task: Export eines Archiv-Bündels als Einzeldatei für den Datei-Modus.
- **Stage 3:** Neue Fläche für Bundle-Auslieferung und -Pinning, Ablage der
  Wrapped-Blobs, CORS und RFC-9421-Request-Signatur aus dem Browser. Die
  bestehenden acht Tasks bleiben; die API-Flächen aus Task 6 ändern sich nicht.
- **Stage 4:** Tasks 1, 2, 4 und 7 werden neu geschrieben. Task 3 behält seinen
  Rust-Kern und erhält neue Bindungen sowie den gepinnten Anchor im Datei-Modus.
  Task 5 bleibt unverändert. Task 6 wird angepasst. Task 8 wird um Browser-Matrix
  und Datei-Modus erweitert.
- **Stage 5:** Die 14 bestehenden Tasks bleiben unverändert. Zwei neue Tasks:
  Escrow-Erzeugung beim Enrollment und Zwei-Approver-Öffnungszeremonie mit
  Re-Encryption an den neuen Vault.
- **Stage 6:** unverändert.
- **Stage 7:** Support-Matrix nach Abschnitt 11.4. Reader-Installer und native
  Key-Provider-Smokes des Readers entfallen. Neu: PWA-Installation,
  Service-Worker-Update unter Pinning und ein Gate, das die Ablehnung eines nicht
  Root-signierten Bundles nachweist.

**Repositoriumsstruktur:** `apps/web/` kommt hinzu. `apps/desktop/` umfasst
Writer und Administration. Neu sind eine `wasm-bindgen`-Brücke und ein
Index-Crate; `ea-reader` wird `wasm32`-fähig.

## 13. Nicht-Ziele

- Keine Administration im Browser.
- Kein Writer im Browser.
- Keine Root-, Recovery- oder Historical-Grant-Authority-Schlüssel im Browser.
- Keine serverseitige Inhaltssuche.
- Keine Entschlüsselung ohne vorherige vollständige Verifikation.
- Kein Entsperrpfad über den Cross-Device-QR-Flow.

## 14. Offene Punkte für die Planüberarbeitung

1. **Laufzeitnachweis WASM.** Vor Beginn der Stage-4-Überarbeitung ist ein
   ausführbarer Spike erforderlich: `wasm-bindgen`-Schicht, `getrandom` mit
   `wasm_js` in einer echten JS-Umgebung, eine HPKE-Entkapselung und eine
   Signaturprüfung gegen einen bestehenden Testvektor. Scheitert dieser Nachweis,
   fällt die Entscheidung aus Abschnitt 2, Punkt 1 in sich zusammen.
2. Verbindliche Größenschwelle des Index nach Abschnitt 8.1.
3. **Browser-Mindestversionen.** Ausgangslage nach Recherche vom 2026-08-15:
   Firefox unterstützt PRF ab 148 vollständig, Chrome ab 147 einschließlich
   PRF-on-create, Safari ab 18 mit iCloud-Passkeys. Ein Ausschluss von Firefox ist
   damit nicht erforderlich. Die exakten Mindestversionen je Plattform werden in
   der Stage-7-Überarbeitung gepinnt und gegen die dann aktuelle Lage geprüft.
4. Zielorigin und Betriebsverantwortung des getrennten Bundle-Hosts.
5. Referenzquelle und Verteilweg der Fingerprint-Bekanntgabe aus Abschnitt 4.3.
