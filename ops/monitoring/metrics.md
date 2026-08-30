# Metriken und ihr Labelsatz — Sync-Server der Stufe 3

Dieses Dokument ist NORMATIV und maschinenlesbar. Es legt fest, welche
Metriken der Sync-Server fuehren darf und — wichtiger — welche Labels sie
tragen duerfen. `apps/server/tests/privacy_canaries_server.rs` liest
die Tabelle `Erlaubte Labels` und sucht jeden fachlichen Kanarienvogel gegen
sie; ohne diese Datei haette die Kanariensuche fuer die Labelflaeche keine
Quelle und muesste sie erraten.

## Der Grundsatz

Ein Label ist ein Wert mit BESCHRAENKTER Kardinalitaet, der in jedem
Zeitreihennamen mitreist und in jedem Scrape, jedem Dashboard und jedem Alert
auftaucht. Genau deshalb ist die Labelflaeche der gefaehrlichste Kanal des
Servers: ein fachlicher Wert, der einmal als Label gesetzt wird, steht danach
in Systemen, die dieses Projekt nicht kontrolliert.

Die Regel ist deshalb nicht „keine Klarnamen", sondern haerter:

> Ein Label traegt AUSSCHLIESSLICH einen Wert aus einer im Voraus
> aufgezaehlten, geschlossenen Menge. Ein Wert, der aus einer Anfrage stammt,
> ist niemals ein Label.

Damit kann ein fachlicher Wert eine Labelflaeche nicht einmal versehentlich
erreichen: er stuende in keiner der geschlossenen Mengen unten.

## Stufe 3 fuehrt KEINE Metrikflaeche

Gemessen am Kopf dieser Stufe: `apps/server` und `crates/ea-sync-server`
enthalten keinen Metrik-Registrar, keinen `/metrics`-Endpunkt und keine
Abhaengigkeit auf eine Metrikbibliothek. `design.md` §13.2 zaehlt siebzehn
`/v1`-Pfade auf, und keiner davon ist `/metrics`.

Diese Datei ist deshalb eine VORABFESTLEGUNG und keine Beschreibung eines
Bestands. Sie steht hier und nicht in Stufe 7, weil der Labelsatz die
Entscheidung ist, die spaeter am teuersten zurueckzunehmen waere — und weil
die Kanariensuche dieser Stufe eine Quelle braucht, gegen die sie die
Labelflaeche pruefen kann. Der Betrieb der Flaeche selbst, ihre
Authentisierung und ihre Ausbringung schliessen in Stufe 7.

## Erlaubte Labels

Jede Zeile: der Labelschluessel, seine geschlossene Wertemenge und die
Herkunft dieser Menge. Ein Labelschluessel, der hier nicht steht, ist nicht
erlaubt.

| Label | Geschlossene Wertemenge | Herkunft der Menge |
|---|---|---|
| `endpoint` | die siebzehn `/v1`-Pfadschablonen | `EndpointV1` (`crates/ea-sync-protocol`), `design.md` §13.2 |
| `method` | `GET`, `POST`, `PUT` | `EndpointV1::method()` |
| `status` | `200`, `201`, `202`, `204`, `400`, `401`, `403`, `404`, `409`, `413`, `415`, `422`, `429`, `500`, `503` | die HTTP-Statuszuordnung in `apps/server/src/http/mod.rs` |
| `error_code` | die `EA-`-Wire-Codes des Sync-Wire-Nachtrags | der Codekatalog des Nachtrags |
| `outcome` | `succeeded`, `refused`, `failed` | `AdminActionOutcomeV1` (`apps/server/src/admin_audit.rs`) |
| `admin_action` | die acht `EA-ADMIN-`-Codes | `AdminActionCodeV1::ALL` (`apps/server/src/admin_audit.rs`) |
| `security_event` | die `SecurityEventKindV1`-Varianten | `crates/ea-sync-server/src/models.rs` |
| `dependency` | `postgres`, `objectstore` | die zwei Dienste aus `ops/compose/integration.yaml` |

## Verbotene Labels

Ausgeschrieben, damit die Abwesenheit nicht als „nicht geprueft" gelesen wird.
KEIN Label traegt jemals einen dieser Werte, auch nicht gehasht und auch nicht
gekuerzt:

- `organizationId`, `deviceId`, `subjectId`, `chainId`, `recordId` — sie sind
  zwar technisch, aber unbeschraenkt in der Kardinalitaet, und eine
  Organisationskennung in einem Dashboard ist eine Zuordnung, die dieses
  Projekt nicht anbietet.
- jeder Objekthash, jeder Eintragshash, jede Sequenz — dieselbe Begruendung,
  und sie stehen bereits als technische Kennung im Security Event und im
  Administrationsaudit, wo sie hingehoeren.
- jedes fachliche Feld des Einsatzes: Stichwort, Ort, Personal, Fahrzeuge,
  Fremdorganisationen, Einsatznummer, Freitext und die beiden Leergruende. Der
  Server sieht sie ohnehin nie im Klartext — er bewegt Chiffrat —, und diese
  Zeile schreibt die Zusage aus, statt sie aus der Blindheit des Servers
  abzuleiten.
- die Peer-IP. Die Ratenbegrenzung rechnet mit ihrem Digest (Sync-Wire-Nachtrag,
  Abschnitt „Identitaet der Ratenbegrenzung"); der Digest ist ein
  Zaehlerschluessel und kein Label.

## Was NICHT als Metrik existiert

Kein Zaehler, kein Histogramm und kein Gauge fuehrt eine Groesse, aus der sich
ein fachlicher Inhalt rekonstruieren liesse. Insbesondere gibt es keine
Metrik ueber Nutzlastgroessen je Eintrag: eine Groessenverteilung je Kette
waere ein Seitenkanal auf den Umfang eines Einsatzes.

## Offen fuer Stufe 7

- Die Ausbringung der Flaeche selbst: Endpunkt, Authentisierung, Netzgrenze.
- Die Bindung dieses Dokuments an eine ausfuehrbare Registrierung — heute
  prueft `privacy_canaries_server.rs` die Tabelle, nicht einen laufenden
  Registrar, weil es keinen gibt.
- Traces. Stufe 3 erzeugt keine; der Labelsatz eines Spans faellt unter
  dieselbe Regel wie der eines Zaehlers und wird hier fortgeschrieben, sobald
  eine Spanflaeche entsteht.
