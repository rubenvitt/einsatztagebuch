# Einsatzarchiv Task 8: Trust- und Zeit-Closure

**Status:** freigegeben am 2026-08-14  
**Entscheidung:** aktivierungsgebundene Korrektur der noch unveröffentlichten v1-Wireverträge

## 1. Ziel und Geltungsbereich

Diese Korrektur schließt die normativen Voraussetzungen für Task 8
„Trust Anchors, Admin Authorization, Registry Selection, and Monotonic Time“.
Sie beseitigt fünf Widersprüche, die sich mit den bisherigen v1-Bytes nicht
fail-closed prüfen lassen:

1. Eine Admin-Autorisierung bindet den vorherigen Registry-Head, während das
   autorisierte Registry-Ereignis dessen direkte Folge ist.
2. Operator-Binding- und Root-Aktivierungen besitzen Registry-Change-Tags,
   waren aber nicht als Ziele der zugehörigen Admin-Aktionen zugelassen.
3. Die historische Nutzung einer Admin-Autorisierung benötigt einen dauerhaft
   signierten Prüfzeitpunkt.
4. Eine Clock-Release muss exakt an Registry-Head und Policy gebunden sein.
5. Zwei Key Approver müssen über eine stabile pseudonyme Personenidentität
   unterscheidbar sein.

Die Korrektur ändert ausschließlich zwei Wire-Strukturen: den
`device-certificate-core-v1` und den `clock-release-context-v1`. Die bestehende
Form `authorized-trust-payload-v1 = [core, authorizationObjectHash]`, die elf
Trust-Subtypen und die Registry-Change-Union bleiben erhalten.

Nicht Bestandteil dieser Korrektur sind UI-Workflows, private
Schlüsselverwaltung, Server-Synchronisation, Archivinventarisierung,
Inhaltsentschlüsselung oder die Laufzeittransaktion der Stage-5-Zeremonien.

## 2. Registry-Transition und Admin-Autorisierung

### 2.1 Gebundener vorheriger Head

Eine `organizationAdminAuthorization` bindet immer den bereits ausgewählten
vorherigen Registry-Head:

```text
authorization.registryVersion = previousHead.registryVersion
authorization.registryHeadHash = previousHead.objectHash
```

Für das erste Registry-Ereignis gilt der einzige Pre-Registry-Kontext:

```text
authorization.registryVersion = 0
authorization.registryHeadHash = zero32
```

Das autorisierte Registry-Ereignis muss die direkte Folge sein:

```text
event.registryVersion = checked_add(authorization.registryVersion, 1)
```

Für Version 1 ist `event.previousRegistryHash = null`. Ab Version 2 muss
`event.previousRegistryHash = authorization.registryHeadHash` gelten. Eine
gleiche Ziel- und Autorisierungsversion, ein Versionssprung, Überlauf oder ein
anderer Vorgängerhash ist ungültig.

Der `authorizedTrustCoreHash` der Autorisierung bleibt der Hash des vollständigen
neuen Ziel-Cores. Ein Registry-Ereignis wird durch den Root signiert, der am
gebundenen vorherigen Head aktiv ist. Das erste Ereignis verwendet den im Anchor
gepinnten Root. Bei einer Root-Rotation signiert der bisher aktive Root das
Aktivierungsereignis; der neue Root wird erst durch dieses Ereignis aktiv.

### 2.2 Direkte Objekte und Aktivierungsereignis

Ein direkt autorisiertes Objekt wie Policy, Zertifikat, Operator-Binding,
Writer-Transition oder Root-Rotation erweitert allein keine Autorität. Es wird
erst durch ein Registry-Ereignis aktiv, dessen Change-Variante exakt dessen
`objectHash` enthält.

Direktes Objekt und Aktivierungsereignis besitzen jeweils eine eigene
`organizationAdminAuthorization`. Beide Autorisierungen müssen denselben
vorherigen Registry-Head binden. Das Aktivierungsereignis ist dessen direkte
Version `+1`. Dadurch bilden Vorbereitung und Aktivierung eine eindeutige
Registry-Transition; ein unter einem älteren Head vorbereitetes Objekt darf
nicht unter einem späteren, nicht direkt folgenden Head aktiviert werden.

Der erste Head ist Version 1, hat `previousRegistryHash = null`, verwendet
Change-Tag 2 für die bereits autorisierte initiale Policy und bindet denselben
Policy-Hash im Feld `policyObjectHash`. Die im Anchor gepinnten
Admin-Zertifikat-/Binding-Paare sind kein zusätzlicher Registry-Change: Sie
bilden den extern gepinnten Registry-Basiszustand, unter dem Head 1 geprüft wird.
Dieser Basiszustand wird nur dann übernommen, wenn Head 1 vollständig akzeptiert
ist. Andere Identitäten werden dadurch nicht aktiv. Vorbereitete
Nicht-Admin-Identitäten benötigen nach dem ersten Head eigene
Aktivierungsereignisse. So ändert auch Head 1 mit Change 2 genau eine
Action-Klasse.

Jedes gepinnte initiale Admin-Zertifikat muss über
`authoritySubjectId = operatorBinding.operatorSubjectId` exakt seinem ebenfalls
gepinnten Binding zugeordnet sein. Das Set enthält mindestens zwei paarweise
verschiedene `authoritySubjectId`-Werte. Mehrere Zertifikate oder Bindings mit
derselben ID zählen als eine Admin-Person und erfüllen die Zwei-Admin-Bedingung
nicht.

### 2.3 Geschlossene Action-/Change-Matrix

Die zulässigen Kombinationen lauten vollständig:

| Action | Direkter Zielsubtyp | Registry-Ziel |
|---:|---|---|
| 0 `deviceApprove` | `deviceCertificate` mit Nicht-Admin-Kind | `registryEvent` mit Change 0 und demselben Zertifikat-Hash |
| 1 `deviceRevoke` | – | `registryEvent` mit Change 1 für Nicht-Admin-Gerät, Operator-Binding oder Komponenten-Zertifikat |
| 2 `policyChange` | `policy` | `registryEvent` mit Change 2 und demselben Policy-Hash |
| 3 `writerTransition` | `writerTransition` | `registryEvent` mit Change 3 und demselben Transition-Hash |
| 4 `operatorBinding` | `operatorBinding` | `registryEvent` mit Change 4 und demselben Binding-Hash |
| 5 `adminKeyChange` | neues `deviceCertificate` mit Kind `organizationAdmin` nur für Effect 0 | `registryEvent` mit Change 5; Effect 0 aktiviert das neue Zertifikat, Effect 1 widerruft ein bereits aktives Zertifikat |
| 6 `rootRotation` | `rootCertificate` | `registryEvent` mit Change 6 und demselben Root-Zertifikat-Hash |

Jede andere Kombination ist ungültig. Direktes Objekt und Aktivierungsereignis
sind zwei verschiedene Ziele und benötigen zwei verschiedene, einmalige
Autorisierungs-IDs und Nonces. Ein Registry-Ereignis verändert weiterhin genau
eine Action-Klasse.

Change 5 ist zusätzlich geschlossen:

- Effect 0 verlangt ein neues direkt autorisiertes Admin-Zertifikat und dessen
  exakten Hash im Aktivierungsereignis.
- Effect 1 referenziert ausschließlich ein im Previous-Head aktives
  Admin-Zertifikat. Es gibt dafür kein neues direktes Zielobjekt.
- Change 1 darf niemals ein Admin-Zertifikat widerrufen; der gesamte
  Admin-Zertifikatslebenszyklus verwendet Change 5.

Ausstellung und Widerruf eines Admin-Zertifikats werden von einer anderen, im
Previous-Head aktiven Admin-Person autorisiert. Der
`authoritySubjectId` des Signer-Zertifikats beziehungsweise dessen exakt
korrelierter Admin-Bindung muss vom `authoritySubjectId` des Zielzertifikats
abweichen. Signer-Zertifikat, Signer-Binding, Rollen, Capability und
Wirksamkeit werden ausschließlich gegen den unveränderten Pre-Transition-State
am gemäß Abschnitt 2.4 abgeleiteten `preTransitionSequence` geprüft; das Ziel
darf sich nicht selbst autorisieren.

Bei Root-Rotation muss zusätzlich
`previousRootCertificateObjectHash` dem bisher aktiven Root-Zertifikat und
`effectiveFromRegistryVersion` exakt der Version des aktivierenden Ereignisses
entsprechen.

### 2.4 Policy- und Sequenzkorrelation

Die Policy-Linie ist für jedes Ereignis eindeutig:

- Bei Change 2 gilt
  `event.policyObjectHash = change.policyObjectHash = exactNewPolicyObjectHash`.
- Die neue Policy hat `policyVersion = checked_add(previousPolicyVersion, 1)`,
  `previousPolicyObjectHash = previousHead.policyObjectHash` und
  `effectiveFromSequence = event.effectiveFromSequence`.
- Im Bootstrap hat die initiale Policy Version 1,
  `previousPolicyObjectHash = null` und dieselbe
  `effectiveFromSequence` wie Head 1.
- Bei jedem anderen Change bleibt
  `event.policyObjectHash = previousHead.policyObjectHash`.

Für aktivierende Changes müssen die Sequenzfelder des direkten Cores exakt dem
Ereignis entsprechen:

- Change 0 und Change 5/Effect 0: Zertifikat-`effectiveFromSequence`,
- Change 2: Policy-`effectiveFromSequence`,
- Change 3: Writer-Transition-`effectiveFromSequence`,
- Change 4: Operator-Binding-`effectiveFromSequence`.

Bei Change 6 ersetzt die bereits definierte Gleichheit
`root.effectiveFromRegistryVersion = event.registryVersion` die
Sequenzkorrelation. Widerrufs-Changes verwenden dagegen die
`event.effectiveFromSequence` als Widerrufsgrenze und verlangen kein neues
direktes Core-Objekt.

Für den Sequenzübergang gilt:

```text
transitionSequence = event.effectiveFromSequence
preTransitionSequence =
  transitionSequence,
    wenn previousHead.effectiveFromSequence <= transitionSequence
      <= previousHead.validThroughSequence
  previousHead.validThroughSequence,
    wenn transitionSequence == checked_add(previousHead.validThroughSequence, 1)
  ungültig,
    sonst
```

Damit darf der Previous-Head sowohl einen innerhalb seiner Lease wirksamen
Nachfolger als auch den lückenlosen unmittelbaren Lease-Nachfolger autorisieren.
Ein größerer Sprung oder Überlauf ist ungültig. Alle
Admin-Signer-Zertifikate und -Bindings werden am `preTransitionSequence` gegen
den unveränderten Previous-Head-/Pre-Transition-State geprüft. Die Lease
begrenzt fachliche Finalisierung; sie beseitigt nicht die Recovery- und
Erneuerungsautorität für exakt den unmittelbaren Nachfolger.

## 3. Historische Gültigkeit von Admin-Autorisierungen

Die Root-Signatur selbst enthält keinen unabhängigen Signaturzeitpunkt. Deshalb
wird die dauerhafte Gültigkeit nicht gegen das heutige `effectiveNow` und nicht
gegen einen erfundenen Root-Signaturzeitpunkt geprüft.

Der signierte Aktivierungszeitpunkt ist verbindlich:

- Für die Autorisierung eines Registry-Ereignisses ist
  `authorizationUseTime = event.issuedAt`.
- Für die Autorisierung eines direkten Zielobjekts ist
  `authorizationUseTime = issuedAt` des Registry-Ereignisses, das exakt dessen
  `objectHash` aktiviert.
- Für beide gilt inklusiv
  `authorization.issuedAt <= authorizationUseTime <= authorization.expiresAt`.

Jede Autorisierung verlangt weiterhin strikt
`authorization.issuedAt < authorization.expiresAt`.

Ein direktes Ziel ohne passendes Aktivierungsereignis bleibt inaktiv. Bei einer
Transition müssen sowohl die Autorisierung des Zielobjekts als auch die
Autorisierung des Aktivierungsereignisses am gemeinsamen `event.issuedAt`
gültig sein. Ein späterer Prüfzeitpunkt macht eine damals gültige Transition
nicht nachträglich ungültig.

Stage 5 prüft beim Erzeugen zusätzlich live und transaktional gegen das damalige
`EffectiveNow`. Diese Laufzeitprüfung ergänzt die dauerhaft offline prüfbare
Aktivierungsregel, ersetzt sie aber nicht.

## 4. Admin- und Key-Approver-Identität

`device-certificate-core-v1` wächst unmittelbar vor
`criticalExtensions` um:

```cddl
authority-subject-id: (bstr .size 16) / null
```

Damit hat der Core 14 Arrayelemente. Die Nullbarkeitsmatrix ist geschlossen:

- `certificate-kind = 2` (`organizationAdmin`) und `certificate-kind = 3`
  (`keyApprover`) verlangen einen nicht-null `authoritySubjectId`.
- Alle anderen Certificate-Kinds verlangen `null`.

Beim Organisationsadministrator muss `authoritySubjectId` exakt dem
`operatorSubjectId` des korrelierten Admin-Operator-Bindings entsprechen. Die
Zwei-Personen-Prüfung für Key Approver vergleicht ebenfalls
`authoritySubjectId`. Zertifikat-Hash,
Schlüssel-Thumbprint oder `deviceId` dürfen nicht als Personenidentität
umgedeutet werden. Zwei Zertifikate derselben `authoritySubjectId` zählen als
eine Person; zwei verschiedene IDs bleiben auch bei identischem Gerät
verschiedene pseudonyme Personen.

Bei einer Zertifikatsrotation derselben realen Person muss die bestehende
`authoritySubjectId` unverändert übernommen werden. Stage 5 verlangt dafür eine
erneute externe Identitätsprüfung und vergleicht die bisherige Zuordnung, bevor
es die neue Zertifikatsautorisierung signiert. Task 8 kann die reale Person und
eine nicht wire-seitig deklarierte Rotation nicht aus Bytes ableiten; seine
kryptografische Grenze ist die exakte ID-Korrelation mit Admin-Bindings sowie
die Verwendung dieser ID für Selbstautorisierungs- und Mehr-Augen-Prüfungen.
Die externe Zuordnung einer realen Person zu genau einer stabilen ID ist deshalb
eine ausdrücklich nicht automatisierbare Stage-5-Zeremonienbedingung und muss
im signierten Admin-/Root-Audit nachweisbar sein.

## 5. Clock-Release

Die freizugebende Future-Skew-Entscheidung bindet eine unabhängige Zeitreferenz:

```cddl
independent-time-reference-v1 =
  [0, receipt-object-hash: bstr .size 32, verified-time: int] /
  [1, checkpoint-object-hash: bstr .size 32, verified-time: int] /
  [2, tsa-evidence-object-hash: bstr .size 32, verified-time: int]
```

Unter mehreren Quellen wird deterministisch zuerst die größte `verifiedTime`
gewählt; bei Gleichstand die kleinste Kombination aus numerischem Tag und
anschließend byteweise kleinstem `objectHash`. Existiert keine unabhängig
verifizierte Quelle, existiert auch kein `independent-time-reference-v1`-Wert
und keine Clock-Release kann behaupten, einen messbaren Future-Skew freizugeben.

`clock-release-context-v1` wächst von sechs auf zehn Elemente:

```cddl
clock-release-context-v1 = [
  trusted-time-floor: int,
  observed-os-wall-clock: int,
  max-future-clock-skew-ms: uint,
  registry-version: uint,
  registry-head-hash: bstr .size 32,
  guard-policy-object-hash: bstr .size 32,
  independent-time-reference: independent-time-reference-v1,
  justification-code: uint,
  issued-at: int,
  expires-at: int
]
```

Organisation, Gerät, Signer-Zertifikat, Admin-Binding und Nonce bleiben im
äußeren `local-audit-event-core-v1` und werden nicht dupliziert. Eine verifizierte
Clock-Release verlangt gleichzeitig:

- Action 6 `clockRelease` und Outcome 1 `accepted`,
- ein nicht-null Admin-Operator-Binding,
- exakt die kryptografisch und historisch geprüfte Registry-Kandidatenversion
  und deren Head-Hash,
- exakt den Hash der Policy, deren `maxFutureClockSkewMs` die Transition oder
  Operation sperrt,
- die aus den vollständig verifizierten Zeitbeweisen deterministisch neu
  abgeleitete unabhängige Referenz,
- exakt den gesperrten Floor, die beobachtete OS-Wanduhr und den zugehörigen
  `maxFutureClockSkewMs`,
- einen geschlossenen Justification-Code: 0 `operatorVerifiedWallClock`,
  1 `platformTimeSourceRecovery` oder 2 `hardwareClockMaintenance`,
- `issuedAt <= EffectiveNow <= expiresAt`,
- strikt `issuedAt < expiresAt`,
- `localAuditCore.effectiveNow = max(observedOsWallClock, trustedTimeFloor)`,
- `localAuditCore.deviceId` als Zielgerät; Signer-Zertifikat und nicht-null
  Admin-Binding müssen für genau dieses Gerät im Pre-Transition-State aktiv sein,
- eine atomar einmalige Nonce unter
  `(organizationId, targetDeviceId, nonce)`.

Eine Clock-Release hebt ausschließlich den Future-Wallclock-Skew-Block für
diesen gebundenen Head und diese Policy auf. Sie senkt niemals den Floor und
hebt weder Registry-`notAfter`, Sequenz-Lease, Admin-Ablauf, Stale-Block,
Signaturfehler noch andere Trust-Prüfungen auf. Eine neue Registry-Version oder
Policy mit identischem Zahlenwert invalidiert die alte Release wegen der
abweichenden Hashbindung.

Der Replay-Verbrauch wird mit der Head-/Floor-Transition in derselben
Transaktion persistiert. `VerifiedClockRelease` ist nicht `Clone` und wird von
der freigebenden Auswahlfunktion by value konsumiert. Eine bereits persistierte
Replay-ID, ein zweiter Verbrauch desselben Proof-State oder eine nur im Speicher
geführte Einmaligkeitsprüfung ist ungültig.

Für eine Registry-Transition ist die Guard-Policy die Policy des Previous-Head;
dadurch darf eine neue Policy ihr eigenes Skew-Limit nicht zur Aktivierung
verwenden. Nur beim Bootstrap ist die vollständig geprüfte initiale Policy die
Guard-Policy. Für eine Operation auf einem bereits ausgewählten Head ist dessen
aktuelle Policy die Guard-Policy.

## 6. Phasige Zeit- und Head-Auswertung

Die Auswertung vermeidet zirkuläres Vertrauen und Selbstaktivierung:

```text
independentReference = deterministicLatest(
  persistierte unabhängige Referenz,
  neu vollständig verifizierte Receipt-/Checkpoint-/TSA-Zeiten
)
preexistingTrustedTimeFloor = max(
  persistedTrustedTimeFloor,
  Zeiten bereits zuvor aktivierter Registry-Ereignisse,
  independentReference.verifiedTime, falls vorhanden
)
rawNow = max(osWallClock, preexistingTrustedTimeFloor)
```

Zeitwerte des gerade geprüften Registry-Kandidaten stehen ausdrücklich nicht
in dieser Berechnung.

Der geschützte monotone Zustand persistiert getrennt den allgemeinen
`trustedTimeFloor` und die zuletzt deterministisch ausgewählte
`independentTimeReference` samt Kind und Objekt-Hash. Nur ein vollständig
verifizierter Receipt-, Checkpoint- oder TSA-Beweis darf die unabhängige
Referenz ersetzen; ihr Zeitwert erhöht zugleich den allgemeinen Floor.
Registry-Zeiten dürfen ausschließlich den allgemeinen Floor erhöhen. Referenz,
allgemeiner Floor und zugehöriger Proof-Hash werden atomar und monoton
persistiert, sobald der unabhängige Beweis vollständig verifiziert ist; ein
späterer Fehler des Registry-Kandidaten rollt diesen bereits bewiesenen
Zeitfortschritt nicht zurück. Schritt 8 betrifft davon getrennt ausschließlich
die Candidate-Zeiten und einen gegebenenfalls konsumierten Clock-Release.

1. Anchor, Objektformen, Hashbindungen und Signaturen werden geprüft, ohne
   Registry-Zeiten bereits als vertrauenswürdige Zeitquellen zu verwenden.
2. Registry-Kette, Admin-Autorisierungen, Action-/Change-Korrelationen,
   Aktivierungen und Policy-Verknüpfungen werden historisch geprüft.
   Das Ergebnis ist ein opaquer `RegistryCandidate` mit vollständig aufgelöster
   Ziel- und Guard-Policy, aber noch ohne zeitliche Aktivierung.
3. Bevor `osWallClock` zur Kandidatenaktivierung oder Floor-Persistenz verwendet
   werden darf, wird der Future-Skew unter der Guard-Policy entschieden:
   - Ist eine unabhängige Referenz vorhanden, ist die OS-Zeit nur ohne Release
     zulässig, wenn
     `osWallClock <= checked_add(referenceTime, maxFutureClockSkewMs)`.
   - Fehlt eine unabhängige Referenz, ist Future-Skew softwareseitig nicht
     beweisbar. Es erfolgt kein Skew-Block und keine Clock-Release; die
     unvermeidbare Offline-Grenze wird sichtbar als
     `IndependentTimeUnavailable` gemeldet und ausschließlich durch
     Registry-Stale- und Sequenz-Lease-Regeln begrenzt.
   - Eine OS-Zeit unterhalb des Floors erzeugt `ClockRollback`; `rawNow` bleibt
     der Floor.
4. Bei einem anhand einer vorhandenen unabhängigen Referenz beweisbaren
   Future-Skew-Block wird eine optionale Clock-Release gegen den
   `RegistryCandidate`, dessen Guard-Policy, den lokalen Zeitblock und die
   deterministische unabhängige Referenz geprüft. Die Release darf den Block
   lösen, erzeugt aber noch keinen ausgewählten Head.
5. Erst nach erfolgreicher Skew-Entscheidung entsteht ein opaques
   `PreexistingEffectiveNow = rawNow`. Ein Event wird zeitlich nur aktiv, wenn
   `issuedAt <= PreexistingEffectiveNow` und
   `notBefore <= PreexistingEffectiveNow` gelten.
6. Zukünftige Ereignisse bleiben `PendingFuture`; ihre eigenen Zeitwerte dürfen
   sie nicht selbst aktivieren. Eine Clock-Release hebt `notBefore` nicht auf.
7. Aus einem strukturell, historisch, sequenzseitig und zeitlich anwendbaren
   Kandidaten entsteht erst jetzt `SelectedRegistryHead`.
8. Erst dessen `issuedAt` und `notBefore` dürfen den persistenten Floor erhöhen.
   Floor-Update, Head-Pin und gegebenenfalls Clock-Release-Replay-Verbrauch
   erfolgen atomar. Bei jedem vorherigen Candidate-Fehler bleiben
   Candidate-Zeiten, Head-Pin und Clock-Release-Replay-Zustand unverändert. Eine
   bereits nach vollständiger Verifikation atomar persistierte unabhängige
   Referenz und ihre Floor-Erhöhung bleiben gemäß der obigen Regel erhalten.

Die zweistufige API-Reihenfolge ist damit verbindlich:

```text
verify_registry_candidate(...) -> RegistryCandidate
verify_clock_release(candidate, localTimeBlock, exactAuditBytes)
  -> VerifiedClockRelease
select_registry_head(candidate, localTimeBlock, Option<VerifiedClockRelease>)
  -> SelectedRegistryHead
```

`select_registry_head` konsumiert die optionale Release by value. Ein bereits
ausgewählter Head wird für normale Operationen als eigener Candidate mit seiner
aktuellen Policy geprüft; es gibt keinen Rückweg von `SelectedRegistryHead` zu
einem ungeprüften Rohzustand.

`VerifiedSignedTime`, `RegistryCandidate`, `VerifiedClockRelease`,
`VerifiedAdminAuthorization` und `SelectedRegistryHead` sind opaque
Proof-State-Typen. Es gibt keinen öffentlichen
Konstruktor aus freien `(kind, UnixMillis)`-, Hash-, Rollen- oder Capability-
Parametern. Proof-State entsteht ausschließlich in den jeweiligen vollständigen
Verifikationspfaden. Zukunfts-Heads bleiben gespeichert, sind aber erst nach
erfolgreicher Skew-Entscheidung und Erreichen von `issuedAt` sowie `notBefore`
durch das vorbestehende EffectiveNow auswählbar und floor-anhebend.

## 7. Fehler- und API-Grenzen

Fehler bleiben code-only und enthalten keine Zertifikatsbytes, Identifikatoren,
Schlüssel, Nonces oder Freitextbegründungen. Getrennte stabile Fehlerklassen
müssen mindestens unterscheiden:

- Registry-Gap, Fork, Rollback, Versionsüberlauf und falscher Vorgänger,
- Action-/Change-/Ziel-Mismatch,
- fehlende Aktivierung und unpassender Aktivierungs-Head,
- Autorisierung vor Ausstellung oder nach Ablauf,
- falsche `authoritySubjectId`-Nullbarkeit, Admin-Selbstautorisierung und nicht
  verschiedene Approver,
- Pending-Future, Stale, verbrauchte Lease und Future-Skew,
- Clock-Release-Head-/Policy-/Outcome-/Binding-/Replay-/Ablauf-Mismatch.

Task 8 stellt eine schmale read-only `TrustObjectSource`-Abstraktion über exakte
Trust-Bytes bereit. Task 9 implementiert sie später mit dem `ArchiveInventory`;
dadurch entsteht keine Rückwärtsabhängigkeit `ea-trust -> ea-archive`.

## 8. Kompatibilität und Migration

v0.1 ist noch nicht veröffentlicht. Deshalb wird v1 jetzt korrigiert; es gibt
keinen parallelen v2-Parser und keinen permissiven Legacy-Modus. Alle bisherigen
betroffenen Testbytes, Objekt-Hashes, COSE-Signaturen und KATs sind provisorisch
und werden deterministisch neu erzeugt beziehungsweise als neue Literale
gepinnt.

Betroffen sind mindestens:

- Trust-CDDL und Wire-Addendum,
- lokales Audit-CDDL und zugehörige Reportverträge,
- Zertifikats- und Trust-Parser in `ea-format` und `ea-crypto`,
- deren exakte Byte-, Hash-, Signatur- und Negativvektoren,
- Task-8-Verträge in `ea-time` und `ea-trust`.

Unbetroffene v1-Familien behalten ihre Bytes. Der Validator akzeptiert keine
alte 13-elementige Device-Certificate-Form und keine alte 6-elementige
Clock-Release-Form.

## 9. Verifikation und Akzeptanz

Die Korrektur wird testgetrieben abgesichert. Zwingende Gegenbeispiele sind:

- Auth `v0/zero32` → Event v1/null und Auth `vN/headN` → Event
  `vN+1/previous=headN` positiv,
- gleiche Version, Sprung, Überlauf und falscher Previous-Hash negativ,
- Immediate-Lease-Nachfolger bei `previous.validThroughSequence + 1` positiv,
  größere Sequenzlücke, Rückdatierung vor `previous.effectiveFromSequence` und
  Überlauf negativ; Admin-State wird beim Immediate Successor am letzten
  Previous-Head-Sequenzpunkt geprüft,
- Actions 4/6 direkt und über passende Changes positiv, gekreuzt negativ,
- Action 5/Effect 0 mit neuem Zertifikat und Effect 1 ohne neues Ziel positiv;
  Admin-Widerruf über Change 1 und Selbstautorisierung negativ,
- direkte Ziele ohne Aktivierung und Aktivierungen unter anderem Head negativ,
- falsche Policy-Fortschreibung, abweichender Event-Policy-Hash und abweichende
  `effectiveFromSequence` negativ,
- Autorisierungszeit vor, an und nach beiden Grenzen; historisch gültige
  Transition bleibt bei späterer Prüfung gültig,
- Admin/Key-Approver mit null ID und andere Kinds mit nicht-null ID negativ,
- Admin-Zertifikat und Admin-Binding mit verschiedener Subject-ID negativ,
- initiales Anchor-Set mit weniger als zwei verschiedenen Authority-IDs negativ,
- zwei Zertifikate derselben `authoritySubjectId` zählen nicht als zwei Personen,
- Clock-Release mit falscher Version, Head, Guard-Policy, unabhängiger
  Zeitreferenz, Outcome, Zielgerät, Binding, Nonce oder Ablauf negativ,
- Replay-Verbrauch ist atomar und ein zweiter by-value- oder persistenter
  Verbrauch negativ,
- Release hebt weder Stale noch Lease oder Autorisierungsablauf auf,
- Future-Head und neue Policy können sich weder zeitlich noch durch ein neues
  Skew-Limit selbst aktivieren; nach unabhängigem Zeitfortschritt werden sie
  aktiv,
- neue unabhängige Zeit erhöht Referenz und allgemeinen Floor atomar; ohne
  unabhängige Referenz wird kein beweisbarer Future-Skew behauptet und die
  Lease-Grenze bleibt wirksam,
- OS-Rollback senkt den Floor nicht,
- Registry-Zeit zählt nicht als unabhängige Future-Skew-Referenz.

Neben fokussierten Tests müssen die vollständigen `ea-crypto`-, `ea-format`-,
Schema-, Workspace-, Format-, Clippy- und Quick-Verify-Gates grün bleiben.

## 10. Verworfene Alternativen

Ein zusätzliches `authorizationUsedAt` in jedem autorisierten Trust-Payload
wurde verworfen: Es dupliziert den bereits Root-signierten Event-Zeitpunkt,
ändert sämtliche autorisierten Trust-Wireformen und benötigt eine weitere
Gleichheitsregel, ohne stärkeren Zeitbeweis zu liefern.

Eine neue v2-Wirefamilie wurde ebenfalls verworfen: Vor dem ersten Release
würden zwei Parser-, Schema- und Negativpfade entstehen, obwohl die bisherigen
v1-Bytes die geforderten Garantien nicht erfüllen und sicherheitsseitig ohnehin
abgelehnt werden müssten.
