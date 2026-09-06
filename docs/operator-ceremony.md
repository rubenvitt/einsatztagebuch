# Operator-Bereitstellung mit separater Offline-Autorität

Diese Anleitung beschreibt die implementierten CLI-Wege von DRK-271. Die
Freigabe für echte Konten setzt die native Plattformabnahme aus
[ADR 0006](adr/0006-native-operator-host-and-offline-authority.md) voraus.

## Voraussetzungen

Zielrechner und Offline-Autorität besitzen getrennte native Schlüsselspeicher,
SQLCipher-Datenbanken und lokale Archivkopien. Beide prüfen dasselbe aktuelle
Archiv gegen einen unabhängig erhaltenen Trust Anchor. Die Anchor-Datei liegt
außerhalb des Archivverzeichnisses. Geräte- und Admin-Zertifikate sowie das
Binding der bestehenden Admin-Bedienperson müssen bereits gültig sein. Der
Gerätesignaturschlüssel des Zielrechners muss zu seinem Zertifikat passen.
Diese Zeremonie ersetzt die vorherige Geräte-/Organisationsaufnahme nicht.

Die Offline-Autorität verfügt über ihre eigenen nativen Admin- und
Root-Schlüssel. Auf dem Zielrechner werden diese Schlüssel weder importiert
noch durch Konfigurationsdateien bereitgestellt. Die ausführbaren Programme
und ihre festen nativen Helper müssen über den jeweiligen geschützten
Installationsweg bereitgestellt sein. Ein kopierter unsignierter Helper neben
einem Entwicklungs-Binary genügt dem Produktionspfad nicht.

## Öffentliche Konfiguration

Die folgende Vorlage enthält ausschließlich öffentliche Referenzen. Die
Platzhalter müssen durch die verifizierten Hashes ersetzt werden. Relative
Pfade werden relativ zur JSON-Datei aufgelöst. Das Austauschverzeichnis muss
vorher existieren und ein reguläres Verzeichnis sein.

```json
{
  "archive_directory": "archive",
  "database_path": "operator.sqlite",
  "device_certificate_hash": "<64 Hexzeichen: Zielzertifikat>",
  "binding_object_hash": "<64 Hexzeichen: aktuelles Binding oder initial Nullhash>",
  "role": "writer",
  "purpose": "finalize",
  "admin_certificate_hash": "<64 Hexzeichen: Admin-Zertifikat>",
  "admin_binding_object_hash": "<64 Hexzeichen: aktives Admin-Binding>",
  "ceremony_exchange_directory": "exchange"
}
```

Bei der Erstbereitstellung besteht der Nullhash aus genau 64 Nullen. Er ist
kein gültiges Login-Binding. Nach erfolgreicher Bereitstellung wird der
ausgegebene produktive Binding-Hash für spätere Anmeldungen eingetragen.
Für einen nativen Admin-Zielrechner lautet `role` `organization-admin`.
Namen, Funktion, Kontokennung und private Schlüssel sind keine unterstützten
Konfigurationsfelder. Unbekannte Felder werden abgewiesen.

Die getrennte Authority-Konfiguration verwendet ihr eigenes Archiv und ihre
eigene Datenbank. `device_certificate_hash` und `binding_object_hash` nennen
ihre bereits aufgenommene Admin-Identität; zusätzlich gelten:

```json
{
  "role": "organization-admin",
  "purpose": "admin-root-ceremony",
  "authority": true,
  "target_certificate_hash": "<64 Hexzeichen: genau dieses Zielzertifikat>",
  "ceremony_exchange_directory": "exchange"
}
```

Dieser Ausschnitt ergänzt die Pflichtfelder der vollständigen Konfiguration.
Die Zielreferenz beschränkt die Authority auf den vereinbarten Rechner.

## Durchführung

1. Auf der Offline-Autorität den begrenzten Anfragedienst starten:

   ```sh
   einsatzarchiv --trust-anchor anchor.etbanchor --operator-config authority.json operator provision
   ```

2. Auf dem Zielrechner die Bereitstellung starten:

   ```sh
   einsatzarchiv --trust-anchor anchor.etbanchor --operator-config target.json operator provision
   ```

3. Vollständige `request-<Hash>.json`-Dateien zum Austauschverzeichnis der
   Authority und deren `reply-<Hash>.json`-Dateien zurück zum Ziel übertragen.
   Dateien werden unverändert übertragen. Unvollständige `.partial`-Dateien
   werden nicht verwendet. Der Transport benötigt keine Online-Root-API;
   beide lokalen Verzeichnisse und der Transfer müssen während der begrenzten
   Sitzung verfügbar sein.

4. Die bestehende Admin-Bedienperson bestätigt ihre native Anwesenheit und
   prüft die Person unabhängig anhand verlässlicher Organisationsunterlagen.
   Nur danach bestätigt sie im privaten Terminal `extern-geprueft` und gibt
   die bestehende stabile 16-Byte-Subject-ID, Namen und Funktion ein. Die
   Eingabe wird nicht angezeigt; das Commitment-Salz erzeugt die Authority.
   Freie Angaben des Zielrechners sind kein Identitätsnachweis.

5. Der Zielrechner veröffentlicht erst nach persistiertem Profil, Prüfung
   seines tatsächlichen Kontos und Instanzschlüssels sowie signiertem Audit.
   Auf die Veröffentlichung folgen ein vollständiger neuer Registry-Check
   und eine frische native Anmeldung. Erst die erfolgreiche CLI-Ausgabe mit
   `binding_state=active` belegt diesen lokalen Abschluss.

Der Authority-Dienst läuft bis zur Sitzungsgrenze oder bis er beendet wird;
sein Ablauf ist kein Abschlussnachweis für den Zielrechner. Eine Sperre,
Abmeldung oder unzuverlässige Überwachung beendet die Gültigkeit der Sitzung.
Entsperren verlängert eine alte Sitzung nicht. Nach spätestens fünf Minuten
ist ein neuer Aufruf mit neuer nativer Anmeldung nötig.

## Anmeldung, Widerruf und Wiederaufnahme

```sh
einsatzarchiv --trust-anchor anchor.etbanchor --operator-config target.json operator verify-session
einsatzarchiv --trust-anchor anchor.etbanchor --operator-config target.json operator revoke
```

`verify-session` benötigt ein aktives Binding, die vorhandene verschlüsselte
Datenbank und die dazu passenden nativen Schlüssel. Es legt keine fehlende
Login-Datenbank neu an. Für `revoke` wird die separate Authority wie oben
gestartet; auf ihr kann dafür ebenfalls `operator revoke` verwendet werden.
Nach Veröffentlichung muss die neue Registry den Widerruf enthalten. Der
Bericht nennt produktive und widerrufene Bindings, Gerät, Rolle, Konto-Hash,
Head und nächste Sequenz, ohne Namen oder Funktion auszugeben.

Nach einem Abbruch denselben Aufruf mit derselben Konfiguration, Datenbank
und denselben Austauschdateien wiederholen. Das verschlüsselte Journal hält
die ursprüngliche Anfrage und den zugehörigen Antwortschlüssel fest. Bereits
bereitgestellte Antworten und signierte Objekte werden bytegenau übernommen;
abweichende Dateien werden nicht überschrieben. Eine unklare Veröffentlichung
wird nicht durch eine neue Autorisierung mit anderer Nonce ersetzt.

Für einen Ersatz nach Widerruf bleibt die bisherige Zuordnung nachvollziehbar.
Die Person wird extern erneut geprüft; ein frisches Commitment-Salz und ein
neuer nativer Instanzschlüssel sind erforderlich. Ein Restore alter Dateien
ist keine erneute Aufnahme. Die unterstützten Installations-/Restore-Wege und
die verbleibende Grenze unverwalteter vollständiger Rücksicherungen stehen in
den nativen Plattformberichten und ADR 0006.
