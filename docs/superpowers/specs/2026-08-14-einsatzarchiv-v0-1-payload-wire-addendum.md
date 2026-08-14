# Einsatzarchiv v0.1 — normativer Payload-Wire-Nachtrag

Datum: 2026-08-14

Dieser Nachtrag ist normativ für v0.1. Er schließt die Klartext-Payload-Wire-
Repräsentation, die reproduzierbare Zeitzonenbasis und die fachliche Basis der
Einsatznummern-Eindeutigkeit vor der Implementierung von `ea-schema`. Die
CBOR-Grammatik in `schemas/payload/v1/payload.cddl` und die fünf unveränderlichen
Hex-Vektoren sind maschinenlesbare Bestandteile dieses Vertrags.

## 1. Autorität und Fail-closed-Grenze

Deterministische CBOR-Arrays sind die einzige Byte-Autorität. Spätere JSON
Schemas sind geschlossene logische Projektionen und keine zweite
Wire-Repräsentation. Ein v1-Decoder MUSS vor jeder input-proportionalen
Allokation und vor dem vollständigen Decode exakt prüfen:

```text
MAX_PLAINTEXT_BYTES_V1 = 1_048_576
```

Danach gelten die Suite-v1-Regeln von `ea-cbor`: genau ein vollständiges Item,
RFC-8949-Core-Deterministic-Encoding, minimale Integer-/Längenrepräsentation,
definite Container, Unicode-NFC und bytegleiche kanonische Re-Kodierung. Maps,
Floats, indefinite Items, nachlaufende Bytes, zusätzliche Arraypositionen und
unbekannte kritische Erweiterungs-Namespaces werden fail-closed abgelehnt.

Alle Epoch-Millisekunden sind CBOR-`int` im inklusiven Rust-`i64`-Bereich
`-9223372036854775808..9223372036854775807`. Das CDDL benennt diesen Bereich;
die Rust-Semantik erzwingt ihn, weil `cddl-cat` den negativen `i64`-Minimalwert
nicht als Range-Endpunkt darstellen kann.

## 2. Gemeinsamer 11-Positionen-Header

Jeder Top-Level-Payload ist exakt dieses 11-Item-Array:

```text
[
  recordType: tstr literal,
  recordId: bstr .size 16,
  schemaId: tstr literal,
  schemaVersion: 1,
  finalizedAtDevice: int,
  timezone: tstr,
  operatorSnapshot,
  source,
  registryVersion: uint,
  extensionData: [],
  body
]
```

Nur diese geschlossenen Paare sind v1:

| `recordType` | `schemaId` |
| --- | --- |
| `genesis` | `ea.genesis` |
| `incident` | `ea.incident` |
| `amendment` | `ea.amendment` |
| `keyTransition` | `ea.key-transition` |
| `destructionEvidence` | `ea.destruction-evidence` |

`recordId` ist semantisch UUIDv7: Versionsnibble `7`, RFC-Variantbits `10`.
`schemaVersion` ist exakt `1`. v1 registriert keinen Extension-Namespace;
Position 9 ist deshalb exakt das leere Array `[]`.

Der Operator-Snapshot ist exakt:

```text
operatorSnapshot = [
  organizationId: bstr .size 16,
  operatorSubjectId: bstr .size 16,
  displayName: tstr,
  functionLabel: tstr,
  salt: bstr .size 32,
  operatorBindingObjectHash: bstr .size 32
]
```

Die Quelle ist exakt `[0, sourceId: tstr, sourceFormatVersion: uint, null]`.
Tag `0` bedeutet `native` und ist die einzige v1-Quelle. Die Literale
`legacyImport`, `legacy-access-import` und jeder andere Quelltag werden später
von der Rust-Validierung mit getrennten Fehlern abgelehnt. Importierte
Stammdatenprovenienz bleibt ausschließlich im jeweiligen Snapshot.

## 3. Exakte Body-Arrays

### 3.1 Genesis

```text
[
  organizationId: bstr .size 16,
  chainId: bstr .size 16,
  initialWriterCertificateObjectHash: bstr .size 32,
  formatVersion: uint,
  "EINSATZARCHIV-SUITE-1",
  initialPolicyObjectHash: bstr .size 32
]
```

### 3.2 Incident

```text
[
  humanIncidentNumber: tstr,
  occurredAt: [start: int, end: int / null],
  keyword: [0, text: tstr]
         / [1, referenceId: tstr, displayText: tstr],
  location: [0, freeText: tstr, coordinates / null]
          / [1, structuredAddress, coordinates / null],
  personnel: [* personnelSnapshot],
  personnelEmptyReason: tstr / null,
  vehicles: [* vehicleSnapshot],
  vehiclesEmptyReason: tstr / null,
  patientCountStatus: 0..1,
  patientCount: uint / null,
  notes: tstr / null,
  externalOrganizations: [* [id: tstr / null, displayName: tstr]]
]
```

`patientCountStatus = 0` bedeutet `unknown` und verlangt `patientCount = null`.
`patientCountStatus = 1` bedeutet `known` und verlangt einen `uint`, wobei die
Zahl `0` als bekannter Wert zulässig ist. Das CDDL korreliert beide Positionen.

Koordinaten sind ausschließlich
`[latE7: -900000000..900000000, lonE7: -1800000000..1800000000]`.
Eine Float-Koordinate existiert nicht. `structuredAddress` ist exakt
`[street/null, houseNumber/null, postalCode/null, locality/null,
adminArea/null, countryCode/null]`; mindestens ein Wert MUSS semantisch
nicht-null sein.

Personen-Snapshots sind geschlossen:

```text
[0, masterPersonnelId, displayName, roleOrFunction/null,
    revision, importedProvenance/null]
/
[1, adHocDisplayName, roleOrFunction/null]
```

Fahrzeug-Snapshots sind geschlossen:

```text
[0, masterVehicleId, displayName, radioCallSign/null, licensePlate/null,
    revision, importedProvenance/null]
/
[1, adHocDisplayName, radioCallSign/null, licensePlate/null]
```

Dabei ist `revision` exakt `[0, revisionNumber:uint] / [1, changedAt:int]` und
`importedProvenance` exakt
`[sourceId:tstr, sourceFormatVersion:uint, importProtocolHash:bstr .size 32]`.
Patientenidentifizierende Felder sind nicht registriert.

Die Rust-Semantik von Task 7 erzwingt zusätzlich: Einsatznummer 1..64 Zeichen,
Keyword/Referenz 1..128 Zeichen, höchstens 200 Personen und 100 Fahrzeuge,
eine nichtleere Begründung für jede leere der beiden Listen, maximal 20.000
Zeichen Notizen, höchstens 100 externe Organisationen und `end >= start`.
Personen, Fahrzeuge und externe Organisationen bewahren die Autorenreihenfolge;
deterministisches CBOR sortiert diese normalen Listen DARF NICHT.

### 3.3 Amendment

```text
[
  originalIncidentNumber: tstr,
  originalRecordId: bstr .size 16,
  originalEntryHash: bstr .size 32,
  originalSequence: uint,
  reason: tstr,
  changes: [+ [fieldPath: tstr, changeText: tstr]]
]
```

Der gemeinsame `operatorSnapshot` ist der Ersteller-Snapshot. Im Body wird die
Identität nicht ein zweites Mal serialisiert.

### 3.4 Key transition

```text
[
  writerTransitionEventObjectHash: bstr .size 32,
  organizationalReason: tstr
]
```

Die organisatorische Begründung liegt im verschlüsselten Payload und ist keine
öffentliche Archivmetadatenposition.

### 3.5 Destruction evidence

```text
[
  destructionId: bstr .size 16,
  authorizationObjectHash: bstr .size 32,
  scopeCode: uint,
  targets: [+ [entryHash: bstr .size 32, chainSequence: uint]],
  executionResults: [+ [entryHash: bstr .size 32, confirmed: bool,
                         resultCode: uint]],
  stubBindings: [* [entryHash: bstr .size 32,
                     stubObjectHash: bstr .size 32]],
  replicaResults: [+ [replicaId: bstr .size 16, state: 0..2,
                       deletionAttestationObjectHash: bstr .size 32 / null]]
]
```

Replica-State `0` bedeutet successful und verlangt einen Attestierungs-Hash;
`1` pending und `2` unreachable verlangen `null`. Targets sind aufsteigend nach
unsigned `(entryHash bytes, chainSequence)` sortiert; jede wiederholte
`entryHash` ist auch bei anderer Sequenz ungültig. Execution Results und Stub
Bindings sind nach `entryHash`, Replica Results nach `replicaId` sortiert und
bezüglich dieses Schlüssels eindeutig. Vertrauensentscheidung,
Autorisierungsabdeckung und tatsächliche Löschbestätigung bleiben Tasks 8/9.

## 4. Unveränderliche v1-Vektoren

Die fünf unabhängig konstruierten Literaldateien liegen unter
`vectors/format/payload-v1/`:

- `genesis.hex`
- `incident.hex`
- `amendment.hex`
- `key-transition.hex`
- `destruction-evidence.hex`

Jede Datei enthält genau eine Zeile lowercase Hex plus abschließenden Newline.
Tests pinnen das vollständige Hexliteral, dekodieren genau ein Item, prüfen das
11-Positionen-Headerpaar und validieren den jeweiligen CDDL-Root. Append,
Truncate sowie Family-/Schema-/Versionsmutationen müssen fehlschlagen. Der
Incident-Vektor hält bewusst `Zulu` vor `Alpha` in einer Autorenliste und bleibt
gültig; eine Float-Mutation der E7-Koordinate wird abgelehnt. Jeder Vektor ist
unter `ea-cbor` kanonisch und bytegleich zu seiner Re-Kodierung.

## 5. Reproduzierbare Zeitzonenbasis

Die überprüften exakten Pins sind `jiff = 0.2.35` und
`jiff-tzdb = 0.1.8`. Jiff wird mit deaktivierten Defaults und ausschließlich
`std` plus `tzdb-bundle-always` eingebunden. Beide Releases haben MSRV 1.70 und
sind mit dem produktiven Rust 1.95 kompatibel. Die eingebettete Datenbasis ist
exakt `IANA tzdb 2026c`.

Task 7 MUSS eine explizite `TimeZoneDatabase::bundled()` verwenden. Die
Payload-Zeitzone wird zuerst über `jiff_tzdb::get` nachgeschlagen; der
zurückgegebene `canonical name` MUSS bytegleich zum Payload-Text sein. Dadurch
werden ASCII-case-Varianten abgelehnt, obwohl der Lookup sie finden kann.
`Etc/Unknown` wird unabhängig davon abgelehnt. Danach wird ausschließlich aus
der gebündelten Datenbank geparst. `/usr/share/zoneinfo`, `TZ`, `TZDIR`, die
Systemzeitzone und Jiffs globale Datenbank dürfen diesen Pfad nicht beeinflussen.

Primärquellen: [Jiff 0.2.35](https://docs.rs/crate/jiff/0.2.35),
[Jiff-Featuremanifest](https://docs.rs/crate/jiff/0.2.35/source/Cargo.toml.orig),
[jiff-tzdb 0.1.8](https://docs.rs/crate/jiff-tzdb/0.1.8),
[`jiff_tzdb::get`](https://docs.rs/jiff-tzdb/0.1.8/jiff_tzdb/fn.get.html) und
[Jiff-Changelog zu 2026c](https://docs.rs/jiff/0.2.35/jiff/_documentation/changelog/index.html#0232-2026-07-08).

## 6. Lokales Kalenderjahr der Einsatznummer

Task 7 leitet für genau einen Payload diesen Schlüssel ab:

```text
(
  operatorSnapshot.organizationId,
  local civil year of occurredAt.start in payload.timezone using pinned tzdb 2026c,
  NFC UTF-8 bytes of humanIncidentNumber
)
```

Die Grenzbeispiele sind unveränderlich:

```text
1798763400000 in America/New_York -> 2026
1798759800000 in Europe/Berlin -> 2027
```

`finalizedAtDevice`, das UTC-Jahr und ein UI-artiges `YYYY-`-Präfix bestimmen
die abgeleitete lokale Jahreskomponente nicht. Präfix-Stripping, Case-Folding
und Locale-Folding finden nicht statt. Jede Änderung der NFC-UTF-8-Bytes von
`humanIncidentNumber` ändert Tupelkomponente 3; dies gilt auch für ein Präfix
oder geänderte Groß-/Kleinschreibung. Task 7 gibt den Schlüssel nur zurück. Erst
Stage 2 erzwingt recordübergreifende Eindeutigkeit unter dem
Writer-/Repository-Lock.

## 7. JSON-Schema-Profile

`xtask` unterscheidet explizit
`JsonSchemaProfile::DeterministicReport` und
`JsonSchemaProfile::PayloadProjection`. Beide Profile kompilieren Draft 2020-12
und verlangen rekursiv `additionalProperties:false` für jedes Objekt. Nur
`DeterministicReport` verlangt für jedes Array `uniqueItems:true`,
`x-ea-sort-key` und `x-ea-unique-key`. Eine Payload-Projektion darf deshalb
normale geordnete Autorenlisten ohne Sortiervertrag enthalten. Die bestehenden
Report-Sortierungs- und Duplicate-Key-Regeln bleiben unverändert.

## 8. Bewusst zurückgestellt

Dieser Nachtrag erzeugt weder `ea-schema` noch JSON-Payload-Schemas oder eine
`schemas/compatibility-matrix.json`. Er implementiert keine Transformation,
keine archivweite Einsatznummern-Eindeutigkeit und keine Trust-, Operator-
Binding-, Writer-Transition-, Vernichtungsautorisierungs- oder
Patienteninhaltsprüfung. Diese Semantiken bleiben in den im Stufenplan genannten
Tasks.
