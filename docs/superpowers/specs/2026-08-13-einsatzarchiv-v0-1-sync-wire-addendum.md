# Einsatzarchiv v0.1 Sync-Wire-Addendum

Status: **normativ für v0.1**. Dieses Addendum wird vor Task 3 Step 3 akzeptiert
und ist damit eine Voraussetzung für jeden produktiven Encoder und jeden
Serverpfad. Es schließt ausschließlich offene Serialisierungs- und
Transportdetails der Designabschnitte 13.1 bis 13.5. Es darf kein dort bereits
festgelegtes Feld, keine Semantik und keine Sicherheitsanforderung
überschreiben. Bei einem Widerspruch gilt die Umsetzung als blockiert, bis
Design und Addendum im selben Review korrigiert wurden; Produktionscode darf
nicht wählen.

Die folgenden versionierten Dateien sind Bestandteil dieses Addendums und
normativ:

- `schemas/protocol/v1/entry-commit.cddl`: der Grant-Plan auf der Leitung, der
  Entry-Commit samt Antwort, die drei Einzelobjekt-Uploads und der einzige
  Fehlerkörper,
- `schemas/protocol/v1/reader-batch.cddl`: Lesestapel, Trust-, Grant- und
  Checkpoint-Seiten, Exportmanifest und Vernichtungsstatus,
- `schemas/protocol/v1/openapi.yaml`: die beschreibende Übersicht derselben
  siebzehn Endpunkte.

`schemas/protocol/v1/openapi.yaml` ist **beschreibend und nicht normativ**.
Normativ sind dieses Addendum und die beiden CDDL-Dokumente. Stufe 3 führt
bewusst kein YAML- oder OpenAPI-Prüfwerkzeug ein: die Alternative — ein
gepinntes Werkzeug im Workspace-Vorlauf plus ein Eintrag in
`[workspace.dependencies]` — wird abgelehnt, weil sie eine Abhängigkeitsklasse
für ein Artefakt einführte, das kein Byteversprechen trägt. Diese Wahl steht
hier ausgeschrieben, damit sie nicht erneut aufgeworfen wird.

`schemas/protocol/v1/signed-protocol.cddl` bleibt **unverändert** und ist
weiterhin Bestandteil des Stufe-1-Wire-Format-Addendums.
`challenge-response-core-v1`, `challenge-response-v1`,
`device-registration-request-core-v1`, `device-registration-request-v1`,
`reader-ack-core-v1` und `reader-ack-v1` werden von dort unverändert
übernommen; insbesondere bleibt `requested-role` bei `0..2`, weil
`2026-08-15-einsatzarchiv-web-reader-design.md` §3 die Rollenmenge nicht
erweitert, sondern nur ihre Anwendungszuordnung ändert.

Symbolische CDDL-Namen dokumentieren Arraypositionen; sie werden nicht als
CBOR-Map-Keys serialisiert. Alle CBOR-Objekte werden deterministisch gemäß
Design §10.1 kodiert. Die letzte Position jedes Rahmens ist ein leeres Array
als geschlossener Erweiterungsplatz.

## Medientypen

- `application/einsatzarchiv+cbor;v=1` für jeden strukturierten Körper,
- `application/einsatzarchiv-object` für den rohen Objektabruf.

`GET /v1/objects/{objectHash}` trägt **keinen CBOR-Rahmen**: die Antwort ist
der exakt archivierte Bytestrom mit `Content-Type:
application/einsatzarchiv-object`, `Content-Length` und einem
RFC-9530-`content-digest` über genau diese Bytes. Design §13.2 sagt
„Objektantworten liefern exakte archivierte Bytes“, und eine `bstr`-Deklaration
behauptete einen CBOR-Kopf, der nicht auf der Leitung steht.

Der Archivexport streamt eine Folge exakter Objektbytes und schließt mit genau
einem `archive-export-manifest-v1`.

Alle Objekt- und Hashlisten sind **bytweise sortiert und duplikatfrei**. Die
einzige Ausnahme ist `trust-registry-response-v1.events`: sie ist nach
`registry-version` aufsteigend geordnet, weil die Registry eine Kette und keine
Menge ist; ihre `object-hash`-Werte bleiben trotzdem duplikatfrei.

## Signaturabdeckung und Requestprüfung

Alle `/v1`-Requests laufen über TLS 1.3. Signaturausnahmen sind genau zwei: der
ratenbegrenzte Challenge-Endpunkt und `POST /v1/vault-blobs/retrievals`.
`POST /v1/device-registrations` ist **keine** Ausnahme: der Request ist
RFC-9421-signiert, nur eben mit dem beantragten, noch nicht freigegebenen
Geräteschlüssel.

Die Signatur steht unter dem Label `ea1`. Abgedeckt sind, in dieser Reihenfolge:
`@method`, `@authority`, `@target-uri`, bei vorhandenem Körper `content-type`
und `content-digest`, und `ea-request-id`. Die Signaturparameter sind `created`,
`expires`, `nonce`, `keyid`, `alg="ed25519"` und `tag`.

- `ea-request-id` trägt die global eindeutige, 16 Byte lange Request-ID als 32
  Kleinbuchstaben-Hexziffern.
- `nonce` trägt die 32 Byte einer Single-Use-Nonce des Challenge-Endpunkts als
  64 Kleinbuchstaben-Hexziffern.
- `keyid` trägt den RFC-9679-SHA-256-Thumbprint des kanonischen öffentlichen
  COSE-Schlüssels als 64 Kleinbuchstaben-Hexziffern.
- `tag` trägt die 16-Byte-`organizationId` als 32 Kleinbuchstaben-Hexziffern und
  bindet die Signatur damit an genau eine Organisation. Es trägt keinen
  fachlichen Wert.
- `content-digest` ist RFC-9530 mit genau einem Digest, genau `sha-256` und ohne
  Parameter: `sha-256=:<base64>:` über exakt die übertragenen Körperbytes.

Das Gültigkeitsfenster ist begrenzt: `created < expires` und
`expires - created <= 300` Sekunden. Design §13.1 verlangt, dass eine falsche
Gerätezeit nicht durch ein unbegrenzt großes Replay-Fenster kompensiert wird.

Der Prüfer arbeitet in dieser Reihenfolge: Signaturabdeckung und Doppelnennung,
Autorität, Ziel-URI, `tag` und Medientyp, Gültigkeitsfenster, Requestdigest,
Zertifikats- beziehungsweise Schlüsselidentität, Signatur, Einmalverbrauch von
Nonce und Request-ID, zuletzt Organisationsbindung und Capability. Ein
Einmalwert wird **erst nach** gültiger Signatur verbraucht.

`POST /v1/device-registrations` gibt `AuthenticatedDevice::ProofOfPossession`
zurück. Der Pfad prüft Abdeckung, Digest, Nonce, Request-ID und Fenster
unverändert, aber weder Zertifikatskette noch Capability, und trägt **keine
Organisationsautorität**. Der beantragte öffentliche Schlüssel stammt aus
`device-registration-request-core-v1` des Körpers und wird dem Prüfer
ausdrücklich übergeben; ohne ihn scheitert der Pfad mit
`EA-HTTP-KEY-UNRESOLVED`. Derselbe beantragte Schlüssel ergibt auf **jedem
anderen** Endpunkt `401`.

Der klientenseitige Signierer bezieht `created`, `expires`, `nonce` und die
Request-ID als Parameter und greift weder auf eine Uhr noch auf eine
Zufallsquelle zu. Er ist damit ohne Wirtsbetriebssystem lauffähig, weil der
Leser im Browser mit einem Schlüsselpaar signiert, dessen privater Teil den
Browser nie verlässt (`2026-08-15-einsatzarchiv-web-reader-design.md` §6.6).

## Stabile Commit-Identität

Die Wiedergabeidentität eines Entry-Commits ist genau
`[entryHash, entryObjectHash, initialGrantPlanHash, sortedInitialGrantObjectHashes]`.
Doppelte Objekt- oder Grant-Hashes werden **vor** dem Dienstaufruf abgewiesen.
Die initialen Grants stehen auf der Leitung in derselben bytweisen
`objectHash`-Ordnung wie in der Identität, damit dieselbe fachliche Transaktion
dieselben Bytes ergibt.

## Grenzen der Version 1

Tiefe und Containerbreite der strukturierten Rahmen sind die der Stufe 1
(`ea_cbor::ParserLimits::V1`): Tiefe 16, höchstens 10 000 Elemente je Container.
Zwei Werte sind angehoben, und zwar begründet: die größte Zeichen- oder
Bytefolge trägt ein vollständiges Archivobjekt als **einen** `bstr` und ist
deshalb `MAX_ARCHIVE_OBJECT_BYTES_V1`, und die Gesamtzahl der Elemente trägt
eine volle Seite aus Containerbreite mal Satzbreite und ist deshalb 100 000.
Beide Anhebungen weiten die Stufe-1-Grenzen **nicht**. Wo ein eingebettetes
Archivobjekt tatsächlich geparst wird, greift zusätzlich `ea-format` unter
`ea_cbor::ParserLimits::V1`, und die engere Grenze gewinnt. Welcher Rahmen das
ist, steht hier ausgeschrieben, damit die Aussage nicht mehr verspricht, als sie
hält:

- **Erneut geparst** wird auf dem Schreibpfad: `entry-bytes` und jedes Element
  von `initial-grant-bytes` in `entry-commit-request-v1` laufen durch
  `decode_exact_object`, der eingebettete `grant-plan-v1` durch
  `decode_grant_plan`, und beide arbeiten unter `ParserLimits::V1`. Ein Plan mit
  10 000 Elementen erreicht diese engere Grenze also, bevor er die
  Protokolldecke erreicht; das ist fail-closed und nicht umgekehrt.
- **Nur auf ihre Objektfamilie geprüft**, nicht vollständig geparst, werden die
  drei Einzelobjekt-Uploads `trust-event-upload-v1`,
  `historical-grant-upload-v1` und `destruction-request-v1`: die Rahmenschicht
  weist ein Objekt der falschen Familie an seinem Exact-Object-Präfix ab, die
  vollständige Prüfung von Signatur, Trust und Autorisierung bleibt beim Dienst.
- **Opak durchgereicht** werden die exakten Objektbytes jeder Leseantwort —
  `reader-batch-v1`, `trust-registry-response-v1`, `grant-list-response-v1`,
  `checkpoint-list-response-v1` und `destruction-status-response-v1`. Der
  Empfänger prüft die Objekte selbst (Design §13.2: technische Listen sind nicht
  autoritativ). Ihre Sicherheitsgrenze ist deshalb **keine** Parsergrenze,
  sondern die Satz- und die Bytedecke ihrer Seite.

Die Decken der Version 1:

- Entry-Commit: genau ein `.eip`, höchstens 10 000 Grant-Plan- beziehungsweise
  Grant-Elemente, höchstens 2 KiB je `.eag`, Körper insgesamt höchstens 24 MiB.
  Die 2-KiB-Decke gilt für die **Objektbytes**; der Rahmenaufschlag eines
  Einzelobjekt-Uploads wird getrennt begrenzt, damit derselbe Wert nicht einmal
  auf das Objekt und einmal auf den Rahmen gemessen wird.
- Lesestapel und Exportstrom: höchstens 1 000 Objektsätze je Seite und
  höchstens 64 MiB Bytes.
- Trust-Seiten: höchstens 1 000 `.etb` **und** dieselbe Bytedecke von 64 MiB je
  Seite.
- Grant-Seiten: höchstens 10 000 Objekte. Checkpoint-Seiten: höchstens 1 000.
  Beide tragen dieselbe Bytedecke von 64 MiB je Seite.
- Challenge-, Registrierungs- und Fehlerkörper: höchstens 64 KiB.

Der Server setzt **sowohl** die Zähl- **als auch** die gestreamte Bytegrenze
durch, bevor er akkumuliert. Jede Seitenantwort prüft die Bytedecke zweimal: vor
dem Parsen an der Länge des empfangenen Körpers und danach an der Summe der
gelieferten Objektbytes.

Die Herleitung der `.eag`-Decke steht hier, damit die Zahl nicht erneut
abdriftet: `grant-body-v1` ist nach `schemas/archive/v1/archive.cddl` ein
geschlossenes Array aus `grant-context-v1` plus `bstr .size 32` und
`bstr .size 48`, und `grant-context-v1` besteht aus Hashes und Bezeichnern
fester Länge plus einer kleinen Zahl begrenzter Ganzzahlen und einer
Capability-Zeichenkette. Die sechs eingefrorenen Vektoren unter
`vectors/grants/v1/grant/` messen 641 bis 710 Byte, und
`vectors/format/v1/valid/eag/valid.bin` misst genau 641 Byte; 2 KiB liegt damit
knapp unter dem Dreifachen des gemessenen Maximums. Die 2-MiB-Grenze des Entry
bleibt und begrenzt ein `.eip`, dessen Chiffrat durch
`ciphertext-length-v1 = 16..1048592` in derselben Datei gedeckelt ist. Die
24 MiB des Commitkörpers sind 2 MiB Entry plus 10 000 mal 2 KiB Grant-Decke plus
begrenzter Rahmen.

## Die beiden ergänzten Aufnahmerahmen

`schemas/protocol/v1/openapi.yaml` nennt für den Körper von
`POST /v1/auth/challenges` und für den von `POST /v1/webauthn-credentials` nur
den Medientyp und ein leeres Schema, und keines der beiden CDDL-Dokumente trug
bisher eine Produktion dafür. Das ist eine **Lücke** und kein Widerspruch: die
Blockade dieses Addendums gilt dem Fall, in dem Design und Addendum einander
widersprechen. Die beiden Produktionen `challenge-request-v1` und
`webauthn-credential-registration-v1` stehen deshalb seither normativ in
`schemas/protocol/v1/entry-commit.cddl`, in derselben Form wie jeder andere
v1-Rahmen und unter derselben 64-KiB-Decke.

`challenge-request-v1` trägt die `organizationId`, weil der Challenge-Endpunkt
die eine Signaturausnahme ohne WebAuthn-Assertion ist und es dort kein
`tag` gibt, aus dem die Organisation käme, `challenge-response-core-v1` sie aber
an Position 2 führt.

## Die drei Rahmen der Vault-Blob-Fläche

Dieselbe **Lücke** und dieselbe Auflösung: `openapi.yaml` nennt für
`PUT /v1/vault-blobs` und `POST /v1/vault-blobs/retrievals` nur den Medientyp
und ein leeres Schema. Die Produktionen `vault-blob-upload-v1`,
`vault-blob-retrieval-request-v1` und `vault-blob-retrieval-response-v1` stehen
deshalb ebenfalls normativ in `schemas/protocol/v1/entry-commit.cddl`.

`vault-blob-upload-v1` trägt **keinen** Blobhash. Der Server rechnet ihn als
SHA-256 über die exakten Chiffratbytes und schreibt create-if-absent über
(`organizationId`, `subjectId`, Blobhash); ein vom Aufrufer behaupteter Hash
wäre eine Adresse, die nicht auf ihren Inhalt zeigen muss. Die
`organizationId` steht ebenfalls **nicht** im Rahmen: sie kommt aus der
geprüften RFC-9421-Identität des Aufrufers. Die `subjectId` darf der Aufrufer
wählen, die Organisation nicht — und weil §6.4.1 die Herausgabe auf „die zu
dieser `subjectId` gehörenden opaken Chiffrate" begrenzt und die
Credentialauflösung ohnehin über (`organizationId`, `credentialId`) läuft, ist
auch die **Ablage und die Herausgabe** organisationsgebunden. Ohne diese
Bindung könnte ein freigegebenes Gerät der Organisation A unter einer in
Organisation B belegten `subjectId` ablegen und abholen; die Opazität des
Chiffrats fängt das ab, aber die Grenze ruht nicht auf ihr allein. Eine `subjectId` hält höchstens acht
Blobs von je höchstens 4 KiB — §6.3 verlangt mindestens zwei Authenticators, und
die Decke hält zugleich ein freigegebenes Gerät davon ab, die Tabelle unter
einer fremden `subjectId` unbegrenzt zu füllen. Ihr Reißen ist
`EA-VAULT-BLOB-LIMIT` mit `413`, die Byte-, Zähl- und Parsergrenzenzeile der
HTTP-Abbildung.

`vault-blob-retrieval-request-v1` trägt die `organizationId` aus demselben Grund
wie `challenge-request-v1`: der Abruf ist die zweite Signaturausnahme, es gibt
kein `tag`, und die Credentialauflösung läuft über den Eindeutigkeitszwang
(`organizationId`, `credentialId`). Die `subjectId` steht darin als
**Behauptung** und wird gegen den `userHandle` des aufgelösten Credentials
gestellt.

Die `clientDataJSON` steht auf dem Draht, weil die Assertion über genau diese
Bytes signiert. Der Server **parst** sie nicht: ADR 0004 hat `json` an Axum
abgeschaltet, damit neben dem deterministischen CBOR kein zweiter, ungeprüfter
Dekodierweg in den Server führt. Er serialisiert stattdessen die
Pflichtglieder der `CollectedClientData` nach WebAuthn Level 2 §5.8.1.1 aus
Challenge und Bundle-Origin und verlangt nach dem **Limited Verification
Algorithm** (§5.8.1.2), dass die gelieferten Bytes damit **beginnen**. Das
pinnt `type`, `challenge`, `origin` und `crossOrigin` in einem Zug und lässt
zugleich zu, was §5.8.1.1 ausdrücklich vorsieht: weitere Glieder hinter
`crossOrigin` (Level 3 ergänzt etwa `topOrigin`). Ein Gleichheitstest wiese
einen regelkonformen Browser ab, der irgendetwas anhängt. Strenger als die
Spezifikation an genau einer Stelle: hinter dem Präfix MUSS `}` oder `,`
stehen — beides sind die einzigen Fortsetzungen, die §5.8.1.1 erzeugt.

**Der Signaturalgorithmus.** `credential-public-cose-key` ist die kanonische
COSE-Karte dieses Arbeitsbereichs — `{1: 1 (OKP), -1: 6 (Ed25519), -2: x}`, ohne
`alg` an Label 3 — und darin genau der Ed25519-Arm. `web-reader-design.md`
§6.4.1 nennt keinen Algorithmus, und die Suite ist durchgehend Ed25519 (Design
§13.1, `alg="ed25519"`); ES256 verlangte einen P-256-Prüfer, den dieser Baum
nicht enthält. Der Web-Reader normalisiert den `credentialPublicKey` seines
Authenticators vor der Registrierung in diese Form. Geprüft wird
`authenticatorData ‖ SHA-256(clientDataJSON)` (WebAuthn Level 2, §6.3.3), dazu
`rpIdHash` gegen die konfigurierte `rpId`, das `UP`-Flag und ein **streng
steigender** `signCount` — mit der einen Ausnahme, die WebAuthn Level 2 §6.1.3
selbst benennt: sind gespeicherter und gelieferter Zähler beide null, führt der
Authenticator keinen, und der synchronisierte Passkey aus §6.4.1 bliebe sonst
dauerhaft ausgesperrt.

**Ein einziger Ablehnungscode.** Unbekanntes Credential, fremde `subjectId`,
falscher Origin, falsche `rpIdHash`, fehlendes `UP`, nicht steigender Zähler,
verbrauchte Challenge und nicht tragende Signatur antworten alle mit `401` und
`EA-WEBAUTHN-ASSERTION-INVALID`, mit identischem `protocol-error-v1` bis auf die
global eindeutige `request-id`. Beide Wege verbrauchen dabei die Challenge —
bliebe sie auf einem stehen, unterschiede ein Angreifer die Fälle daran, ob er
seine Nonce wiederverwenden kann. Ein `404` für eine unbekannte `subjectId` gibt
es ausdrücklich nicht; die `404`-Zeile der HTTP-Abbildung nennt unbekanntes
Objekt, unbekannte Kette, unbekannten Eintrag und unbekannte Vernichtungs-ID und
keine `subjectId`.

## Vorbehalt: EdDSA-only bei `POST /v1/webauthn-credentials`

**Festlegung.** `POST /v1/webauthn-credentials` nimmt **ausschließlich** ein
Credential mit einem Ed25519-Schlüssel in der kanonischen COSE-Form dieses
Arbeitsbereichs an. Ein Schlüssel in einer anderen Form oder über einer anderen
Kurve wird **bei der Registrierung** abgewiesen — `EA-SYNC-FRAME-SHAPE`, `400`,
bevor eine Zeile entsteht —, nicht erst still beim Abruf. Zulässig ist die
Beschränkung, weil `web-reader-design.md` §6.4.1 keinen Algorithmus nennt,
`webauthn-credential-registration-v1` kein Algorithmusfeld führt und die Suite
durchgehend `alg="ed25519"` ist (Design §13.1).

**Der Vorbehalt.** Plattform-Authenticators — Touch ID, Windows Hello — und die
meisten synchronisierten Passkeys bieten heute **nur ES256** (COSE `alg = -7`,
ECDSA über P-256) an. Ein Web-Reader gegen diese Fläche kann auf einem
typischen Plattform-Authenticator deshalb **überhaupt kein** Credential
registrieren. Das ist keine Randbedingung, sondern der Regelfall der Geräte,
auf denen §6.4.1 den Blob-Abruf vorsieht.

**Was Stufe 4 entscheiden MUSS, bevor der Browser-Reader ausgeliefert wird.**
Ob ein ES256-Prüfer aufgenommen wird. Der Baum enthält heute keinen: `p256`,
`ecdsa`, `elliptic-curve` und `sec1` stehen nicht in `Cargo.lock`, und `ring`
liegt nur als transitive Kante unter `rustls`. Der Weg ist benannt und
kostenpflichtig: ein `p256`-Pin oder eine direkte `ring`-Kante unter dem
Verfahren aus `docs/adr/0004-server-runtime-and-dependency-class.md`, danach ein
zweiter Arm an `ea_crypto::CanonicalPublicCoseKey` und ein zweiter
Prüfzweig in `release_vault_blobs`. Der Rahmen selbst bleibt unverändert: er
trägt den öffentlichen Schlüssel als Bytes und kennt den Algorithmus nicht.

## Die CORS-Positivliste

`web-reader-design.md` §4.1 verlangt einen Auslieferungs-Origin, der vom
Sync-Server getrennt ist; jeder Zugriff des Bundles ist damit cross-origin. Der
Server führt deshalb eine **Positivliste** aus der Konfiguration, niemals einen
Platzhalter, mit dem getrennten Bundle-Origin als einzigem lieferseitigem
Eintrag. `Access-Control-Allow-Credentials` bleibt aus — der Abruf trägt seine
Autorität im Körper und nicht in einem umgebenden Cookie —, und ein nicht
gelisteter Origin erhält **überhaupt keinen** `Access-Control-Allow-Origin`.

Die RFC-9421-Abdeckung von `@authority` und `@target-uri` bleibt davon
unberührt: der Browser signiert über die Ziel-URI des Sync-Servers und nicht
über seinen eigenen Origin. CORS entscheidet, ob der Browser fragen darf; die
Signatur entscheidet, ob der Server antwortet.

## Die Identität der Ratenbegrenzung

Der ratenbegrenzte Challenge-Endpunkt zählt je **Gegenstellenadresse** des
Aufrufers, als SHA-256 über die Adressbytes **ohne Port**. Er zählt
ausdrücklich **nicht** je `organizationId`.

Die Begründung ist eine Sicherheitsaussage und keine Geschmacksfrage: die
`organizationId` steht bei genau diesem Endpunkt im **unsignierten** Körper.
Ein Wert, den der Aufrufer frei behauptet, ist keine Identität. Wäre die
Begrenzung darauf gestützt, könnte jeder Fremde eine Organisation mit deren
eigener, in jedem `tag` öffentlich mitgereister Kennung aussperren — und weil
die `nonce` jedes signierten Requests eine Nonce dieses Endpunkts ist, wäre das
der Totalausfall dieser Organisation. Die Adresse dagegen entsteht aus dem
TCP-Handschlag und ist das Einzige, was ein unsignierter Request mitbringt,
ohne es behaupten zu können. Der Port bleibt außen vor: er wechselt mit jeder
Verbindung.

Gespeichert wird nur der **Digest**; eine Adresse steht damit nirgends im
Klartext im Bestand.

Diese Identität ist genau so gut, wie die Verbindung sie hergibt, und das steht
hier ausgeschrieben statt in einer Fußnote:

- Der Server terminiert TLS **selbst und im Prozess** (§13.1, Design `:1497`),
  also ist die gesehene Adresse die des tatsächlichen Gegenübers.
- Steht später ein Reverse Proxy oder ein NAT davor, kollabieren alle Aufrufer
  dahinter auf **eine** Identität und teilen sich ein Fenster.
- Stufe 3 wertet **kein** `Forwarded` und kein `X-Forwarded-For` aus. Ein
  Header ist wieder eine Behauptung des Aufrufers, und ihn ungeprüft zur
  Identität zu erheben, holte genau die Lücke zurück, die diese Festlegung
  schließt. Wer hinter einem Proxy betreibt, muss dessen Adressweitergabe
  vertrauenswürdig anbinden; das ist eine Betriebs- und keine Protokollfrage
  und ist hier bewusst nicht offengelassen, sondern benannt.

## HTTP-Abbildung

| Status | Auslöser |
| --- | --- |
| 400 | fehlerhafte Rahmung oder fehlerhafter Content-Digest, unlesbarer oder fremder technischer Cursor |
| 401 | fehlende, ungültige oder abgelaufene Signatur oder Challenge |
| 403 | gültige Identität ohne Capability oder ohne Organisationszugriff |
| 404 | unbekanntes Objekt, unbekannte Kette, unbekannter Eintrag, unbekannte Vernichtungs-ID |
| 409 | Fork, Kopfabweichung, Bytekonflikt, nicht idempotenter Replay oder erforderlicher neuerer Registry-Head |
| 413 | Byte-, Zähl- oder Parsergrenze |
| 422 | wohlgeformt, aber ungültig in Trust, Format, Grant oder Autorisierung |
| 429 | Challenge- oder Ratenlimit |
| 503 | vorübergehender Ausfall von Datenbank, Object Store oder TSA |
| 500 | jeder andere interne Fehler |

Fehlerantworten verwenden immer `protocol-error-v1`, enthalten **kein** Fragment
der gelieferten Nutzdaten und setzen `retryable=true` ausschließlich bei den
technischen Fehlern 429, 500 und 503.

Die Codes der Trust-Annahme, mit ihrer Abbildung:

| Code | Status | Bedeutung |
| --- | --- | --- |
| `EA-TRUST-EVENT-UNVERIFIABLE` | 422 | Über diese Objektart trifft die geteilte `ea-trust`-Prüfung heute keine Aussage; fail-closed abgewiesen statt ungeprüft aufgenommen |
| `EA-TRUST-EVENT-NOT-VALID-NOW` | 422 | Das Objekt trägt, gilt aber jetzt nicht: veraltet, in der Zukunft oder außerhalb seiner Sequenzleihe |
| `EA-TRUST-EVENT-NOT-APPLICABLE` | 409 | Ein `registryEvent`, das nicht der nächste Kopf ist — die Zeile „erforderlicher neuerer Registry-Head“. Der Körper führt `required-registry-version` und `required-registry-head-hash` |
| `EA-TRUST-STATE-CONFLICT` | 503 | Der persistente Vertrauenszustand hat sich unter dem Aufrufer bewegt; `retryable=true`, und ausdrücklich keine Aussage über seine Autorität |

Die Codes der Vault-Blob-Fläche, mit ihrer Abbildung:

| Code | Status | Bedeutung |
| --- | --- | --- |
| `EA-WEBAUTHN-ASSERTION-INVALID` | 401 | Die WebAuthn-Assertion trägt nicht — aus jedem Grund derselbe Code, damit der Endpunkt keine Enumerationsfläche bietet |
| `EA-VAULT-BLOB-LIMIT` | 413 | Diese `subjectId` hält bereits so viele Wrapped-Blobs, wie sie halten darf |
| `EA-VAULT-DEPENDENCY-UNAVAILABLE` | 503 | Die Datenbank antwortet nicht; `retryable=true` |
| `EA-VAULT-INTERNAL` | 500 | Interner Fehler ohne fachliche Ursache |

Antworten ohne Inhalt: `POST /v1/reader-acks` antwortet mit `204` und ohne
Körper; `POST /v1/webauthn-credentials`, `PUT /v1/vault-blobs`,
`POST /v1/trust/events` und `POST /v1/entries/{entryHash}/historical-grants`
antworten mit `201` und ohne Körper; `POST /v1/device-registrations` antwortet
mit `202` und ohne Körper. Eine leere Seite ist **kein** `204`, sondern ein
`200` mit einer leeren Objektliste und `next-cursor = null`.

Blätterung: jede Seitenantwort trägt `next-cursor`. `null` heißt „keine weitere
Seite“; jeder andere Wert wird unverändert als Abfrageparameter
zurückgeschickt.

## Technischer Cursor

Ein `technical-cursor-v1` ist ein opakes, ablaufendes, serverauthentisiertes
Token über die deterministisch kodierte Folge
`[1, organizationId, endpointCode, chainId-or-null, startHeadHash-or-null,
lastTechnicalIndex, expiresAt, nonce]`. Klienten parsen ihn nicht und vertrauen
ihm nicht; er enthält keine fachlichen Metadaten.

Seine Authentisierung ist eine COSE-Sign1 über den Server-Ed25519-Schlüssel mit
seiner **eigenen** Domänenkonstante `EINSATZARCHIV-TECHNICAL-CURSOR-v1`. Das
Token ist `[core, signatur]`; signiert wird der SHA-256 über
Domänenkonstante ‖ Core-Bytes. Das Gültigkeitsfenster steht im Token selbst:
`expiresAt` ist eine absolute Serverzeit, und ein Cursor mit
`expiresAt < jetzt` wird abgewiesen, bevor seine Bindung geprüft wird.

Die Domänenkonstante ist **additiv**: die 24 eingefrorenen Domänenkonstanten
unter `vectors/crypto/suite-1/domain-string/` kennen heute keinen Cursor, und
keine von ihnen wird durch diese Ergänzung berührt.

Es entsteht **keine** neue `CertificateCapability`. Design §13 sagt wörtlich
„Der Server besitzt einen eigenen Ed25519-Schlüssel für Receipts und
Checkpoints“, also trägt ein Schlüssel dort bereits zwei Zwecke, und die
Zweckbindung läuft über die Domäne statt über die Capability.
`CertificateCapability` in `crates/ea-crypto/src/cose.rs` ist auf sieben Werte
geschlossen; ein achter erweiterte eine eingefrorene Menge und trüge eine eigene
Begründungspflicht. Ein HMAC kommt nicht in Frage: die Suite kennt keinen.

**Vorbehalt für den Serverschlüssel-Port.** `ContentType` in
`crates/ea-crypto/src/cose.rs` ist heute auf elf Werte geschlossen und kennt
keinen Cursor-Content-Type. `crates/ea-sync-protocol` legt deshalb ausschließlich
Domäne, Digest und Tokenrahmen fest und nimmt Signierer und Prüfer als
übergebene Schnittstellen entgegen; der Task, der den Serverschlüssel-Port baut,
ergänzt den Content-Type gemeinsam mit der zugehörigen Signaturmethode. Diese
Stelle ist damit benannt und nicht stillschweigend offen.

## Feld-zu-Design-Review

| Artefakt / Felder | Designquelle | Status |
| --- | --- | --- |
| `POST /v1/auth/challenges` — Aufrufer: ohne Signatur, ratenbegrenzt; Request: leerer bzw. kleiner CBOR-Rahmen; Response: challenge-response-v1; Status: 200; 400, 413, 429, 500, 503 | §13.1, §13.2 | bestätigt |
| `POST /v1/device-registrations` — Aufrufer: Proof of Possession, keine Capability; Request: device-registration-request-v1; Response: kein Inhalt; Status: 202; 400, 401, 409, 413, 422, 429, 500, 503 | §13.1, §13.2 | bestätigt |
| `POST /v1/webauthn-credentials` — Aufrufer: jedes freigegebene Gerät der Organisation; Request: application/einsatzarchiv+cbor;v=1; Response: kein Inhalt; Status: 201; 400, 401, 403, 409, 413, 422, 500, 503 | web-reader-design.md §6.4.1 | bestätigt |
| `PUT /v1/vault-blobs` — Aufrufer: jedes freigegebene Gerät der Organisation; Request: application/einsatzarchiv+cbor;v=1; Response: kein Inhalt; Status: 201; 400, 401, 403, 409, 413, 422, 500, 503 | web-reader-design.md §6.4 | bestätigt |
| `POST /v1/vault-blobs/retrievals` — Aufrufer: ohne Signatur, WebAuthn-Assertion; Request: application/einsatzarchiv+cbor;v=1; Response: application/einsatzarchiv+cbor;v=1; Status: 200; 400, 401, 404, 413, 422, 429, 500, 503 | §13.1 Reader-Vorbehalt | bestätigt |
| `GET /v1/trust/registry?afterVersion={n}` — Aufrufer: jedes freigegebene Gerät der Organisation; Request: kein Körper; Response: trust-registry-response-v1; Status: 200; 400, 401, 403, 413, 500, 503 | §13.2 | bestätigt |
| `POST /v1/trust/events` — Aufrufer: organizationAdminApprove; Request: trust-event-upload-v1; Response: kein Inhalt; Status: 201; 400, 401, 403, 409, 413, 422, 500, 503 | §13.2 | bestätigt |
| `POST /v1/chains/{chainId}/entry-commits` — Aufrufer: initialGrant; Request: entry-commit-request-v1; Response: entry-commit-response-v1; Status: 200; 400, 401, 403, 404, 409, 413, 422, 500, 503 | §13.3 | bestätigt |
| `GET /v1/chains/{chainId}/entries?afterSequence={n}&afterEntryHash={hash}&cursor={cursor}` — Aufrufer: jedes freigegebene Gerät der Organisation; Request: kein Körper; Response: reader-batch-v1; Status: 200; 400, 401, 403, 404, 409, 413, 500, 503 | §13.2, §14 | bestätigt |
| `GET /v1/objects/{objectHash}` — Aufrufer: jedes freigegebene Gerät der Organisation; Request: kein Körper; Response: roher Bytestrom, application/einsatzarchiv-object; Status: 200; 400, 401, 403, 404, 500, 503 | §13.2 | bestätigt |
| `POST /v1/entries/{entryHash}/historical-grants` — Aufrufer: historicalGrant; Request: historical-grant-upload-v1; Response: kein Inhalt; Status: 201; 400, 401, 403, 404, 409, 413, 422, 500, 503 | §13.3 | bestätigt |
| `GET /v1/entries/{entryHash}/grants` — Aufrufer: jedes freigegebene Gerät der Organisation; Request: kein Körper; Response: grant-list-response-v1; Status: 200; 400, 401, 403, 404, 413, 500, 503 | §13.3 | bestätigt |
| `POST /v1/reader-acks` — Aufrufer: jedes freigegebene Gerät der Organisation; Request: reader-ack-v1; Response: kein Inhalt; Status: 204; 400, 401, 403, 404, 409, 413, 422, 500, 503 | §13.2 | bestätigt |
| `GET /v1/checkpoints?after={cursor}` — Aufrufer: jedes freigegebene Gerät der Organisation; Request: kein Körper; Response: checkpoint-list-response-v1; Status: 200; 400, 401, 403, 413, 500, 503 | §13.2, §15 | bestätigt |
| `GET /v1/archive-exports/current` — Aufrufer: jedes freigegebene Gerät der Organisation; Request: kein Körper; Response: Objektfolge plus archive-export-manifest-v1; Status: 200; 400, 401, 403, 413, 500, 503 | §13.3 | bestätigt |
| `POST /v1/destructions` — Aufrufer: destructionApprove; Request: destruction-request-v1; Response: destruction-status-response-v1; Status: 202; 400, 401, 403, 404, 409, 413, 422, 500, 503 | §13.3, §16 | bestätigt |
| `GET /v1/destructions/{destructionId}` — Aufrufer: jedes freigegebene Gerät der Organisation; Request: kein Körper; Response: destruction-status-response-v1; Status: 200; 400, 401, 403, 404, 500, 503 | §16 | bestätigt |
| `challenge-request-v1` / organization-id | §13.1, ratenbegrenzter Challenge-Endpunkt ohne `tag` | bestätigt |
| Ratenbegrenzung / Zählschlüssel = SHA-256 der Gegenstellenadresse ohne Port | §13.1, ratenbegrenzter Challenge-Endpunkt | bestätigt |
| `webauthn-credential-registration-v1` / subject-id, credential-id, credential-public-cose-key | web-reader-design.md §6.4.1 | bestätigt |
| `webauthn-credential-registration-v1` / credential-public-cose-key auf den Ed25519-Arm der kanonischen COSE-Karte beschränkt, mit Stufe-4-Vorbehalt ES256 | web-reader-design.md §6.4.1 | bestätigt |
| `vault-blob-upload-v1`, `vault-blob-retrieval-request-v1`, `vault-blob-retrieval-response-v1`; Ablage und Herausgabe organisationsgebunden | web-reader-design.md §6.4, §6.4.1 | bestätigt |
| grant-plan-v1 / recipient-key-thumbprint | encode_plan_items in crates/ea-format/src/eag.rs | bestätigt |
| grant-plan-v1 / recipient-certificate-hash | encode_plan_items in crates/ea-format/src/eag.rs | bestätigt |
| grant-plan-v1 / "EINSATZARCHIV-HPKE-1" | GRANT_SUITE_ID in crates/ea-crypto/src/digest.rs | bestätigt |
| grant-plan-v1 / grant-purpose | grant-context-v1 in schemas/archive/v1/archive.cddl | bestätigt |
| entry-commit-request-v1 / version | Design §10.1 | bestätigt |
| entry-commit-request-v1 / entry-bytes | Design §13.3 | bestätigt |
| entry-commit-request-v1 / grant-plan | Design §13.3 | bestätigt |
| entry-commit-request-v1 / initial-grant-bytes | Design §13.3 | bestätigt |
| entry-commit-request-v1 / Erweiterungsplatz | Design §10.1 | bestätigt |
| entry-commit-response-v1 / version | Design §10.1 | bestätigt |
| entry-commit-response-v1 / outcome | Design §13.3, idempotenter Replay | bestätigt |
| entry-commit-response-v1 / receipt-bytes | Design §13.3 Schritt 9 | bestätigt |
| entry-commit-response-v1 / checkpoint-bytes | Design §15.2 | bestätigt |
| entry-commit-response-v1 / Erweiterungsplatz | Design §10.1 | bestätigt |
| trust-event-upload-v1 / exact-etb-bytes | Design §12 | bestätigt |
| historical-grant-upload-v1 / exact-eag-bytes | Design §13.3 | bestätigt |
| destruction-request-v1 / exact-destruction-authorization-etb-bytes | Design §16 | bestätigt |
| protocol-error-v1 / error-code | Design §13.5 | bestätigt |
| protocol-error-v1 / request-id | Design §13.1, global eindeutige Request-ID | bestätigt |
| protocol-error-v1 / retryable | Design §13.5 | bestätigt |
| protocol-error-v1 / required-registry-version | Design §13.3 Schritt 5 | bestätigt |
| protocol-error-v1 / required-registry-head-hash | Design §13.3 Schritt 5 | bestätigt |
| reader-batch-v1 / chain-id | Design §13.2 | bestätigt |
| reader-batch-v1 / requested-after-sequence | Design §13.2 | bestätigt |
| reader-batch-v1 / requested-after-entry-hash | Design §13.2 | bestätigt |
| reader-batch-v1 / start-head-entry-hash | Design §14.1 | bestätigt |
| reader-batch-v1 / objects | Design §13.2, exakte archivierte Bytes | bestätigt |
| reader-batch-v1 / next-cursor | Design §13.2, technische Liste | bestätigt |
| reader-batch-v1 / covered-through-sequence | Design §14.1 | bestätigt |
| trust-registry-response-v1 / requested-after-version | Design §12.3 | bestätigt |
| trust-registry-response-v1 / events | Design §12 | bestätigt |
| grant-list-response-v1 / entry-hash | Design §13.3 | bestätigt |
| grant-list-response-v1 / grants | Design §13.3 | bestätigt |
| checkpoint-list-response-v1 / requested-cursor | Design §15.2 | bestätigt |
| checkpoint-list-response-v1 / checkpoints | Design §15.2 | bestätigt |
| checkpoint-list-response-v1 / next-cursor | Design §13.2, technische Liste | bestätigt |
| archive-export-manifest-v1 / organization-id | Design §13.3 | bestätigt |
| archive-export-manifest-v1 / sorted-objects.object-type | archive-object-v1 in schemas/archive/v1/archive.cddl | bestätigt |
| archive-export-manifest-v1 / sorted-objects.object-hash | Design §10.2 | bestätigt |
| archive-export-manifest-v1 / sorted-objects.byte-length | Design §13.3 | bestätigt |
| archive-export-manifest-v1 / export-cursor | Design §13.2, technische Liste | bestätigt |
| destruction-status-response-v1 / destruction-id | Design §16 | bestätigt |
| destruction-status-response-v1 / state | destruction-state-v1 in schemas/archive/v1/trust.cddl | bestätigt |
| destruction-status-response-v1 / authorization-object-hash | Design §16 | bestätigt |
| destruction-status-response-v1 / transitions | Design §16 | bestätigt |
| destruction-status-response-v1 / attestations | Design §16 | bestätigt |
| technical-cursor-v1 / organizationId | Design §13.2, technische Liste ohne Autorität | bestätigt |
| technical-cursor-v1 / endpointCode | Design §13.2 | bestätigt |
| technical-cursor-v1 / chainId | Design §13.2 | bestätigt |
| technical-cursor-v1 / startHeadHash | Design §14.1 | bestätigt |
| technical-cursor-v1 / lastTechnicalIndex | Design §13.2 | bestätigt |
| technical-cursor-v1 / expiresAt | Design §13.1, begrenztes Fenster | bestätigt |
| technical-cursor-v1 / nonce | Design §13.1 | bestätigt |
| Signaturabdeckung / @method | Design §13.1 | bestätigt |
| Signaturabdeckung / @authority | Design §13.1 | bestätigt |
| Signaturabdeckung / @target-uri | Design §13.1 | bestätigt |
| Signaturabdeckung / content-type | Design §13.1 | bestätigt |
| Signaturabdeckung / content-digest | Design §13.1, RFC 9530 | bestätigt |
| Signaturabdeckung / ea-request-id | Design §13.1, eindeutige Request-ID | bestätigt |
| Signaturabdeckung / created | Design §13.1 | bestätigt |
| Signaturabdeckung / expires | Design §13.1 | bestätigt |
| Signaturabdeckung / nonce | Design §13.1, Single-Use | bestätigt |
| Signaturabdeckung / keyid | Design §13.1, RFC-9679-Thumbprint | bestätigt |
| Signaturabdeckung / alg=ed25519 | Design §13.1 | bestätigt |
| Signaturabdeckung / tag | Design §13.1, organisationsgebunden | bestätigt |

**Review-Ergebnis:** keine ungelöste Zeile und kein Widerspruch
