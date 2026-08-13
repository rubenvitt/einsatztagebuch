# Einsatzarchiv v0.1 Wire-Format-Addendum

Status: **normativ für v0.1**. Dieses Addendum wird vor Task 3 akzeptiert und ist
damit eine Voraussetzung für jeden produktiven Encoder. Es schließt ausschließlich
offene Serialisierungsdetails der Designabschnitte 10 bis 16. Es darf kein dort
bereits festgelegtes Feld, keine Semantik und keine Sicherheitsanforderung
überschreiben. Bei einem Widerspruch gilt die Umsetzung als blockiert, bis Design
und Addendum im selben Review korrigiert wurden; Produktionscode darf nicht wählen.

Die folgenden versionierten Dateien sind Bestandteil dieses Addendums und normativ:

- `schemas/archive/v1/archive.cddl`: gemeinsame Hülle und alle sechs Archivobjekte,
- `schemas/archive/v1/trust.cddl`: Trust-Subtypen und deren feste Core-Arrays,
- `schemas/archive/v1/evidence.cddl`: Checkpoint-, Timestamp- und Renewal-Arrays,
- `schemas/protocol/v1/signed-protocol.cddl`: Challenge-, Enrollment- und
  Reader-Ack-Cores samt nichtzirkulären Signaturhüllen,
- `schemas/identity/v1/os-account.cddl`: der geschlossene OS-Kontokontext,
- `schemas/reports/v1/local-audit.cddl`: signiertes, klartextfreies lokales Audit,
- `schemas/reports/v1/verification-report.schema.json` und
  `key-inventory.schema.json`: geschlossene JSON-Schemata.

Symbolische CDDL-Namen dokumentieren Arraypositionen; sie werden nicht als CBOR-Map-
Keys serialisiert. Alle CBOR-Objekte werden deterministisch gemäß Design §10.1
kodiert. `COSE-Sign1 = any` ist nur der CDDL-Anker für das extern durch RFC 9052/9053
definierte, zusätzlich semantisch geprüfte COSE-Objekt.

## Suite-v1-COSE-Wire-Profil

Die geschützten Standardheader verwenden ausschließlich die RFC-9052-Labels
`alg = 1`, `crit = 2`, `content type = 3` und `kid = 4`. `alg` ist der durch
RFC 9864 vollständig spezifizierte COSE-Ed25519-Wert `-19`. Der ältere
polymorphe RFC-9053-EdDSA-Wert `-8` ist deprecated und wird fail-closed
abgelehnt. `kid` ist eine bstr von exakt 32 Byte und enthält exakt
den RFC-9679-SHA-256-Thumbprint des tatsächlich verwendeten kanonischen
COSE-Public-Key. Das in Design und Implementierungsinterfaces verwendete
`keyThumbprint` bezeichnet semantisch diesen `kid`-Wert und ist kein zusätzliches
Wire-Label.

Das einzige anwendungseigene geschützte Label ist der tstr
`"certificateHash"`; sein Wert ist eine bstr von exakt 32 Byte mit dem
`objectHash` der exakten `.etb`-Zertifikatsbytes. Es ist ausdrücklich nicht der
RFC-9360-Header `x5t`, weil `.etb`-Zertifikate keine DER-X.509-Zertifikate sind.

Jede normale Suite-v1-Signatur verwendet exakt diese Protected-Map:

```cbor-diag
{
  1: -19,
  2: [3, 4, "certificateHash"],
  3: <exakter intern registrierter content-type-tstr>,
  4: h'<32-byte-rfc-9679-sha-256-key-thumbprint>',
  "certificateHash": h'<32-byte-etb-object-hash>'
}
```

Die initiale Root-Proof-of-Possession verwendet exakt:

```cbor-diag
{
  1: -19,
  2: [3, 4],
  3: "application/vnd.einsatzarchiv.trust-digest",
  4: h'<32-byte-rfc-9679-sha-256-key-thumbprint>'
}
```

Die getrennte Enrollment-Proof-of-Possession für einen noch nicht ausgestellten
`device-registration-request-v1` verwendet exakt:

```cbor-diag
{
  1: -19,
  2: [3, 4],
  3: "application/vnd.einsatzarchiv.device-registration-request+cbor",
  4: h'<32-byte-rfc-9679-sha-256-request-key-thumbprint>'
}
```

Der COSE-Payload sind exakt die deterministischen CBOR-Bytes eines unsigned
`device-registration-request-core-v1`, der alle Requestfelder außer
`self-signature` enthält. Die finale, nichtzirkuläre Request-Hülle ist exakt
`[device-registration-request-core-v1, #6.18(COSE-Sign1)]`; weder Hülle noch
Signatur dürfen Teil des signierten Payloads sein. Die PoP beweist nur den Besitz
des im Core enthaltenen Signing-Key, verleiht keine
Autorität, ist keine Trust-Signatur und wird nicht durch den normalen
`SignerCertificateResolver` verarbeitet. Autorität entsteht erst durch die
getrennte Admin-Autorisierung und Root-signierte Zertifikats-/Registry-Aktivierung.
Unter autorisierten operativen und archivierten Signaturen bleibt die initiale
Root-PoP die einzige `certificateHash`-Ausnahme.

Die Protected-Map wird gemäß RFC 8949 Core Deterministic Encoding Requirements
kodiert und als bstr eingebettet. `external_aad` ist exakt die leere bstr `h''`;
die RFC-9052-`Sig_structure` ist exakt
`["Signature1", protected, h'', payload]`. `COSE_Sign1` ist mit CBOR-Tag 18
kodiert, enthält den Payload und trägt eine Ed25519-Signatur von exakt 64 Byte.
Detached Payloads, ein anderes `external_aad`, ungetaggte Strukturen oder andere
Protected-Map-Bytes sind ungültig.

Die normale Unprotected-Map ist exakt leer. Einzige spätere Suite-v1-Ausnahme ist
bei Checkpoint- und Renewal-Evidence der RFC-9921-Header `3161-ctt` mit Label 270
und ausschließlich dem aus der RFC-3161-`TimeStampResp` extrahierten vollständigen
DER-`TimeStampToken` (`ContentInfo`) als bstr; er ist dann der einzige
Unprotected-Eintrag. Die vollständige `TimeStampResp` wird separat im
`rfc3161-response-der`-Feld der `.ecp` archiviert und ist als Headerwert
ungültig. Alle
anderen Labels und Unprotected-Kombinationen werden fail-closed abgelehnt.

Label 3 ist ein tstr aus dieser geschlossenen einsatzarchiv-internen
Suite-v1-Registry; damit wird keine IANA-Registrierung der folgenden Werte
behauptet:

- `application/vnd.einsatzarchiv.record-digest`
- `application/vnd.einsatzarchiv.grant-digest`
- `application/vnd.einsatzarchiv.receipt-digest`
- `application/vnd.einsatzarchiv.trust-digest`
- `application/vnd.einsatzarchiv.checkpoint+cbor`
- `application/vnd.einsatzarchiv.evidence-renewal+cbor`
- `application/vnd.einsatzarchiv.local-audit+cbor`
- `application/vnd.einsatzarchiv.challenge-response+cbor`
- `application/vnd.einsatzarchiv.device-registration-request+cbor`
- `application/vnd.einsatzarchiv.reader-ack+cbor`
- `application/vnd.einsatzarchiv.recovery-test-digest`

Die Digest-Werte bezeichnen jeweils exakt den zugehörigen 32-Byte-Digest. Die
`+cbor`-Werte bezeichnen ausschließlich die exakten RFC-8949-core-deterministischen
Bytes des jeweiligen versionierten unsigned Core. Challenge Response, Device
Registration Request und Reader Acknowledgement sind jeweils exakt
`[...-core-v1, #6.18(COSE-Sign1)]`; ihre COSE-Payloads sind nur
`challenge-response-core-v1`, `device-registration-request-core-v1` beziehungsweise
`reader-ack-core-v1`, niemals die signaturhaltige Hülle. Unregistrierte oder frei gebildete
Laufzeitwerte sind unzulässig. Eine Implementierung prüft zusätzlich die exakte
Zuordnung von Content Type, Payloadart, Signerrolle und Zertifikat-Capability.

Die bytegenauen Arraypositionen der drei Protokoll-Cores und ihrer Hüllen stehen
ausschließlich in `schemas/protocol/v1/signed-protocol.cddl`. Dieses versionierte
CDDL ist die normative Quelle für Golden Bytes; Implementierungspläne dürfen
diese Layouts nicht neu definieren.

## Kanonischer OS-Kontokontext

Der CBOR-Input von `EINSATZARCHIV-OS-ACCOUNT-v1` ist exakt das in
`schemas/identity/v1/os-account.cddl` definierte `os-account-context-v1`.
`canonical-os-account-id-v1` ist eine geschlossene, selbstversionierende Union;
tstr, CBOR-Tags, Trennzeichen und plattformspezifische Anzeigeschreibweisen sind
im Hashinput unzulässig:

- Windows ist `[1, 0, sid-bstr]`. `sid-bstr` ist die exakte binäre SID aus
  `TokenUser`, nach `IsValidSid` und `GetLengthSid`: `revision = 0x01`,
  `subAuthorityCount = 1..15`, sechs Identifier-Authority-Oktette in
  Netzwerkreihenfolge und anschließend genau `count` SubAuthorities als je vier
  Little-Endian-Oktette. Die Gesamtlänge ist exakt `8 + 4 * count` und damit
  `12..68`; zusätzliche Oktette, SDDL-Text oder eine SID aus einem anderen Token
  werden abgelehnt.
- macOS ist `[1, 1, directory-guid-bstr16, uid]`. Es wird genau ein
  `kODAttributeTypeGUID` (`GeneratedUID`) des aktuellen Nutzerrecords akzeptiert.
  Die 36 Zeichen `8-4-4-4-12` werden nach RFC 9562 case-insensitiv validiert und
  ohne COM-GUID-Feldumsortierung in die 16 Oktette der Netzwerkreihenfolge
  dekodiert; die Null-GUID ist unzulässig. `uid` ist der zum selben Record
  gehörende `UniqueID`/`getuid()` als
  CBOR-uint `0..4294967294`; Mehrfachwerte, `0xffffffff` und Text-UIDs scheitern.
- Linux ist `[1, 2, machine-id-bstr16, uid]`. Bevorzugte Quelle ist
  `sd_id128_get_machine()`. Ein Dateifallback akzeptiert ausschließlich 32
  kleingeschriebene Hexzeichen und genau ein abschließendes LF aus
  `/etc/machine-id`, dekodiert zu 16 Oktetten. Leer-, `uninitialized`-, Null-,
  Großbuchstaben- oder abweichende Formen scheitern. `uid` ist `getuid()` als
  CBOR-uint `0..4294967294`; `0xffffffff` und Text-UIDs scheitern.

Alle Arrays werden RFC-8949-core-deterministisch kodiert. Es gibt keine Unicode-
Normalisierung und keine Groß-/Kleinschreibungsentscheidung im resultierenden
CBOR, weil alle stabilen Plattformkennungen als bstr und alle UIDs als uint
vorliegen.
Das rohe `canonical-os-account-id-v1` und seine Plattformquellen dürfen weder
persistiert noch geloggt oder exportiert werden; dauerhaft gespeichert wird nur
der domain-separierte 32-Byte-Hash. Die in §6.8 festgelegte Linux-Machine-ID
bleibt für v0.1 literal; ein Wechsel auf eine systemd-app-spezifische Ableitung
wäre eine eigene normative Designänderung und darf nicht still erfolgen. Der
separate, installationsgebundene Operator-Instanzschlüssel bleibt zwingend, weil
Machine-ID plus UID allein eine Linux-UID-Löschung und -Neuanlage nicht erkennt.

## Suite-v1-AEAD- und HPKE-Größen

Die Payload-AEAD verwendet einen 32-Byte-CEK, eine 12-Byte-Nonce und einen
16-Byte-ChaCha20-Poly1305-Tag. Daher gilt exakt
`ciphertextLength = plaintextLength + 16`; die Addition wird vor Allokation und
Verschlüsselung overflow-sicher geprüft. Ein nicht darstellbarer oder ein
Formatlimit überschreitender Wert wird fail-closed abgelehnt.

`EINSATZARCHIV-HPKE-1` ist RFC 9180 Base Mode `0` mit
`DHKEM(X25519, HKDF-SHA256) = 0x0020`, `HKDF-SHA256 = 0x0001` und
`ChaCha20Poly1305 = 0x0003`. `encapsulated-key` (`enc`) ist exakt 32 Byte lang;
der Ciphertext des 32-Byte-CEK ist einschließlich 16-Byte-Tag exakt 48 Byte lang.

## Recovery-Test-Signaturinput

Ein Signaturschlüssel im geführten Recovery-Test signiert als COSE-Payload
ausschließlich folgenden 32-Byte-Digest:

```text
SHA-256(
  "EINSATZARCHIV-RECOVERY-TEST-v1" ||
  deterministicCbor([
    1,
    random-challenge: bstr .size 32,
    key-thumbprint: bstr .size 32
  ])
)
```

Der Keypfad für Recovery-Tests darf weder rohe produktive Payloadbytes noch einen
produktiven Trust-Digest signieren. Der Content Type ist exakt
`application/vnd.einsatzarchiv.recovery-test-digest`.

## Archiv-, Evidence- und Stub-Discriminators

Die Design-Typ-Tags 1 bis 6 bleiben unverändert. Für die bisher offenen Typen gelten
exakt diese Hüllen und Varianten:

```cddl
ecp-v1 = [h'45413100', 4, 1, [],
  ([0, standard-checkpoint-v1] /
   [1, timestamp-evidence-v1] /
   [2, renewal-evidence-v1])
]

checkpoint-core-v1 = [
  1, domain: "EINSATZARCHIV-CHECKPOINT-v1",
  organization-id: bstr .size 16, chain-id: bstr .size 16,
  covered-from-sequence: uint, covered-through-sequence: uint,
  head-entry-hash: bstr .size 32, registry-head-hash: bstr .size 32,
  issued-at-server: int, previous-evidence-hash: (bstr .size 32) / null, []
]
standard-checkpoint-v1 = [checkpoint-core-v1, #6.18(COSE-Sign1)]
timestamp-evidence-v1 = [
  checkpoint-core-v1, #6.18(COSE-Sign1),
  rfc3161-response-der: bstr, hash-algorithm: 0,
  request-nonce: bstr, policy-oid-der: bstr,
  tsa-certificate-chain-der: [+ bstr], revocation-data-der: [* bstr],
  validation-data-der: [* bstr]
]

renewal-core-v1 = [
  1, domain: "EINSATZARCHIV-EVIDENCE-RENEWAL-v1",
  organization-id: bstr .size 16, chain-id: bstr .size 16,
  current-entry-hash: bstr .size 32,
  previous-renewal-hash: (bstr .size 32) / null,
  sorted-renewal-input-hashes: [+ bstr .size 32], []
]
renewal-evidence-v1 = [
  renewal-core-v1, #6.18(COSE-Sign1), rfc3161-response-der: bstr,
  hash-algorithm: 0, request-nonce: bstr, policy-oid-der: bstr,
  tsa-certificate-chain-der: [+ bstr], revocation-data-der: [* bstr],
  validation-data-der: [* bstr]
]

eds-v1 = [h'45413100', 6, 1, [], [
  1, signed-manifest: [manifest-core-v1, bstr .size 32],
  writer-signature: #6.18(COSE-Sign1), entry-hash: bstr .size 32,
  ciphertext-hash: bstr .size 32, original-eip-object-hash: bstr .size 32,
  destruction-id: bstr .size 16,
  destruction-authorization-object-hash: bstr .size 32, []
]]
```

In beiden Core-Arrays steht die feste Domain unmittelbar nach `object-version` an
Arrayposition 1. `hash-algorithm = 0` bedeutet ausschließlich SHA-256. Die TSA-Zertifikatskette ist
nicht leer. `sorted-renewal-input-hashes` ist byteweise aufsteigend und
duplikatfrei. Evidence folgt der CTT-Imprint-, Frist- und Vorgängerkettendefinition
aus Design §§15.2–15.4. Der Stub enthält exakt die in Design §§11.4 und 16.3
erlaubten öffentlichen Bindungen und keinen Ciphertext, CEK oder Grant.

## Trust Bundle

Die `.etb`-Hülle und ihre stabilen Textdiscriminators lauten:

```cddl
etb-v1 = [h'45413100', 5, 1, [], etb-body-v1]
trust-subtype-v1 = "rootCertificate" / "deviceCertificate" / "operatorBinding" /
  "organizationAdminAuthorization" / "registryEvent" / "policy" /
  "writerTransition" / "grantAuthorization" / "destructionAuthorization" /
  "destructionTransition" / "deletionAttestation"

authorized-trust-payload-v1<T> = [
  authorized-trust-core: T,
  organization-admin-authorization-object-hash: bstr .size 32
]

cose-sign1-v1 = #6.18(COSE-Sign1)
etb-body-v1 =
  ["rootCertificate", (initial-root-certificate-core-v1 /
    authorized-trust-payload-v1<root-rotation-certificate-core-v1>),
    [cose-sign1-v1]] /
  ["deviceCertificate", (initial-admin-device-certificate-core-v1 /
    authorized-trust-payload-v1<device-certificate-core-v1>), [+ cose-sign1-v1]] /
  ["operatorBinding", (initial-admin-operator-binding-core-v1 /
    authorized-trust-payload-v1<operator-binding-core-v1>), [+ cose-sign1-v1]] /
  ["organizationAdminAuthorization", organization-admin-authorization-v1,
    [cose-sign1-v1]] /
  ["registryEvent", authorized-trust-payload-v1<registry-event-core-v1>, [+ cose-sign1-v1]] /
  ["policy", authorized-trust-payload-v1<policy-core-v1>, [+ cose-sign1-v1]] /
  ["writerTransition", authorized-trust-payload-v1<writer-transition-core-v1>, [+ cose-sign1-v1]] /
  ["grantAuthorization", grant-authorization-core-v1, [2* cose-sign1-v1]] /
  ["destructionAuthorization", destruction-authorization-core-v1, [2* cose-sign1-v1]] /
  ["destructionTransition", destruction-transition-core-v1, [+ cose-sign1-v1]] /
  ["deletionAttestation", deletion-attestation-core-v1, [+ cose-sign1-v1]]
```

`schemas/archive/v1/trust.cddl` fixiert die Arraypositionen aller elf Core-Typen
und wird hier vollständig normativ einbezogen. Die Integerregister sind:

- `certificate-kind-v1`: 0 writer, 1 reader, 2 organizationAdmin,
  3 keyApprover, 4 recoveryRecipient, 5 historicalGrantAuthority,
  6 serverReceipt, 7 deletionAttest.
- `key-protection-profile-v1`: 0 osWrapped, 1 hardwareNonExportable,
  2 offlineEncryptedContainer, 3 pkcs11, 4 serverSecretStoreOrHsm.
- `destruction-state-v1`: 0 requested, 1 inProgress, 2 pendingBackupExpiry,
  3 completeManagedScope, 4 incompleteUnreachableReplica.

Ein Public Key oder Thumbprint darf nur dann `null` sein, wenn der jeweilige
`certificate-kind` den Algorithmus nicht verwendet. Capability-Strings werden
nach ihren UTF-8-Bytes, Hashlisten byteweise sortiert; beide sind duplikatfrei.
Jede `registry-change-v1`-Variante ändert genau eine Action-Klasse.

`etb-body-v1` koppelt jeden Subtype-Literal strukturell an genau seinen zulässigen
Payload. Initiale Root-/Admin-Ausnahmen tragen den Core direkt; direkte
Admin-Gerätezertifikate verlangen `certificate-kind = 2`, direkte Admin-Bindings
`operator-role = 2`. Ob sie tatsächlich zum extern gepinnten initialen Set gehören,
prüft die Trust-Verifikation. Jedes andere admin-
autorisierte Ziel trägt exakt den Hash des Admin-Authorization-Objekts als zweites
Element. Für `grantAuthorization` und `destructionAuthorization` enthält die äußere
Signaturliste mindestens zwei Signaturen, nach Signer-Zertifikat-Hash sortiert, von
unterschiedlichen aktiven Subject-IDs mit passender Approver-Capability. Das
initiale Root-Zertifikat trägt exakt eine äußere Signatur: die Proof-of-Possession
seines eingebetteten Root-Schlüssels. Eine Root-Rotation trägt ebenfalls exakt eine
äußere Signatur, und zwar von der vorherigen akzeptierten Root-Linie. Ihre
Admin-Autorisierung ist durch den
`organization-admin-authorization-object-hash` im autorisierten Payload gebunden
und ist keine zweite äußere Signatur. Die initiale Root-Proof-of-Possession ist die
einzige `certificateHash`-Ausnahme unter autorisierten operativen und archivierten
Signaturen. Die getrennte Enrollment-PoP aus Design §10.1 ist pre-authorization
und keine Trust-Signatur. CDDL erzwingt
Payload-Korrelation und Signaturanzahl;
Signeridentität, Capability, unterschiedliche Subject-IDs, Sortierung und die
vorherige Root-Autorität werden in den Trust-/COSE-Gates der Tasks 5 und 8 geprüft.

## Lokales Audit

`local-audit-event-v1` ist Deterministic CBOR und trägt eine identitätsbindende
COSE-Signatur. Deren Payload sind exakt die Bytes von
`local-audit-event-core-v1`; geschützte Header lösen den Signer zum genannten
aktiven Geräte- oder Admin-Zertifikat auf. Es gibt kein Freitext-Detailfeld.

Action 0..11 bedeutet login, reauthFailure, bindingChange, revocation,
registryStaleWarnAcceptance, plaintextExport, clockSkewRelease,
adminRootCeremony, recoveryTest, historicalRegrant, destruction und
archiveProfileMigration. Outcome 0..2 bedeutet failed, accepted und completed.
Die Kontext-Tags 0..8 bedeuten generic, staleRegistry, clockRelease, export,
bindingLifecycle, adminRoot, historicalRegrant, destruction und
archiveProfileMigration.

Die Action-zu-Kontext-Zuordnung ist geschlossen: login, reauthFailure und
recoveryTest verwenden generic; bindingChange und revocation verwenden
bindingLifecycle; alle übrigen Actions verwenden nur ihren gleichnamigen typisierten
Kontext. Generic enthält nur einen Object Hash oder `null`. Export enthält nur
Entry Hash und Target Kind, nie einen Pfad. Der Stale-Kontext ist die einmalige
Finalisierungsbestätigung. Der Clock-Release-Kontext ist ein ablaufender Admin-
Nachweis und autorisiert nur den exakt aufgezeichneten Skew. Kein Kontext darf
`trustedTimeFloor` absenken.

Die Korrelation ist Teil der CDDL-Struktur, nicht nur eine semantische Tabelle:

```cddl
local-audit-event-core-v1 =
  local-audit-event-core-for-v1<0, generic-audit-context-v1> /
  local-audit-event-core-for-v1<1, generic-audit-context-v1> /
  local-audit-event-core-for-v1<2, binding-audit-context-v1> /
  local-audit-event-core-for-v1<3, binding-audit-context-v1> /
  local-audit-event-core-for-v1<4, stale-audit-context-v1> /
  local-audit-event-core-for-v1<5, export-audit-context-v1> /
  local-audit-event-core-for-v1<6, clock-release-audit-context-v1> /
  local-audit-event-core-for-v1<7, admin-root-audit-context-v1> /
  local-audit-event-core-for-v1<8, generic-audit-context-v1> /
  local-audit-event-core-for-v1<9, historical-regrant-audit-context-v1> /
  local-audit-event-core-for-v1<10, destruction-audit-context-v1> /
  local-audit-event-core-for-v1<11, archive-profile-migration-audit-context-v1>
```

## JSON-Berichte

`ea.verification-report/v1` verlangt exakt `schemaId`, `archiveObjectCount`,
`entryPackageCount`, `destroyedEntryCount`, `chainHead`, `registryVersions`,
`objectResults`, `authorizedDestructions`, `gaps`, `signatureErrors`,
`evidenceErrors`, `decryptionErrors`, `publicKeyThumbprints` und `reportHash`.
Nur `reportSignature` und `runtimeMetadata` sind optional. Laufzeit-, Host- und
Pfadfelder sind ausschließlich innerhalb `runtimeMetadata` zulässig.

`ea.key-inventory/v1` verlangt exakt `schemaId`, `inventoryId` und die
duplikatfreie Liste `media`. Jedes Medium verlangt exakt `mediumId`, `keyRole`,
`expectedKeyThumbprint`, `certificateObjectHash`, `protectionProfile` und
`testKind`; letzteres ist `signatureChallenge`, `recoveryDecrypt` oder
`providerPresence`. Jede Arraybeschreibung im Schema nennt ihren stabilen
Sortierschlüssel. Zusätzlich tragen alle Arrays die maschinenlesbaren Annotationen
`x-ea-sort-key` (geordnetes Array aus Feldpfad und Kodierung) und
`x-ea-unique-key` (der vollständige Duplicate-Key). Der `xtask`-Schema-Gate weist
unsortierte Instanzen und gleiche vollständige Keys auch bei abweichenden
Nicht-Key-Feldern ab. Die produktiven Serializer in Tasks 9/10 und Stage 5 müssen
denselben Vertrag implementieren. Jedes JSON-Objekt, auch jedes geschachtelte, setzt
`additionalProperties: false`.

## Feld-zu-Design-Review

Die Gruppen führen jedes hinzugefügte Feld mindestens einmal auf. Status
`bestätigt` bedeutet: kein Widerspruch zum angegebenen Designabsatz.

| Artefakt / Felder | Designquelle | Status |
|---|---|---|
| signed protocol: Challenge-, Enrollment- und Reader-Ack-Core sowie jeweils getrennte `[core, COSE-Sign1]`-Hülle | §§10.1, 10.5, 12.7 | bestätigt |
| OS account: organization-id, device-id, geschlossene selbstversionierende Windows-SID-/macOS-GUID+UID-/Linux-Machine-ID+UID-Union | §§6.8, 10.1, 12.2 | bestätigt |
| `.ecp`: magic, object-type, format-version, critical-extensions, variant tag | §11.1 Typ-Tags und Hülle | bestätigt |
| checkpoint: object-version, domain `EINSATZARCHIV-CHECKPOINT-v1`, organization-id, chain-id, covered-from-sequence, covered-through-sequence, head-entry-hash, registry-head-hash, issued-at-server, previous-evidence-hash, critical-extensions | §§15.2–15.3 | bestätigt |
| timestamp: checkpoint-core, COSE-Sign1, rfc3161-response-der, hash-algorithm, request-nonce, policy-oid-der, tsa-certificate-chain-der, revocation-data-der, validation-data-der | §15.3 | bestätigt |
| renewal: object-version, domain `EINSATZARCHIV-EVIDENCE-RENEWAL-v1`, organization-id, chain-id, current-entry-hash, previous-renewal-hash, sorted-renewal-input-hashes, critical-extensions, COSE-Sign1 und alle Timestamp-Felder | §15.4 mit §15.3 | bestätigt |
| `.eds`: magic, object-type, format-version, outer/body critical-extensions, object-version, signed-manifest, writer-signature, entry-hash, ciphertext-hash, original-eip-object-hash, destruction-id, destruction-authorization-object-hash | §§11.1, 11.4, 16.3 | bestätigt |
| `.etb`: magic, object-type, format-version, critical-extensions, strukturell korrelierter trust-subtype/trust-payload, subtype-spezifische Signatur-Mindestanzahl | §11.1 | bestätigt |
| Root: object-version, organization-id, root-public-cose-key, root-key-thumbprint, previous-root-certificate-object-hash, effective-from-registry-version, critical-extensions | §§10.1, 12.1–12.3, 16.1 | bestätigt |
| Device certificate: object-version, organization-id, device-id, certificate-kind, signing-public-cose-key, kem-public-cose-key, signing-key-thumbprint, kem-key-thumbprint, capabilities, key-protection-profile, effective-from-sequence, revoked-from-sequence, critical-extensions | §§10.1, 12.2–12.4, 12.7, 16.4 | bestätigt |
| Operator binding: object-version, organization-id, operator-subject-id, operator-profile-commitment, device-certificate-hash, operator-role, os-account-binding-hash, operator-instance-key-thumbprint, effective-from-sequence, revoked-from-sequence, critical-extensions | §§11.1–11.2, 12.2–12.4 | bestätigt |
| Admin authorization: object-version, authorization-id, organization-id, registry-version, registry-head-hash, admin-key-thumbprint, admin-certificate-hash, admin-operator-binding-object-hash, action-code, target-trust-subtype, authorized-trust-core-hash, issued-at, expires-at, nonce, critical-extensions | §§11.1, 12.1–12.3 | bestätigt |
| Registry change variants and registry event: action tag plus certificate/target/policy/writer-transition/operator-binding/admin/root object hashes, target-kind, effect; object-version, organization-id, registry-version, previous-registry-hash, effective-from-sequence, valid-through-sequence, issued-at, not-before, not-after, policy-object-hash, change, root-key-thumbprint, critical-extensions | §§11.1, 12.3–12.6 | bestätigt |
| Retention/free-text/policy: minimum-retention-ms, destruction-enabled, eds-privacy-decision-document-hash, free-text-allowed, rule-set-version, local-pattern-warning-enabled, object-version, organization-id, policy-version, previous-policy-object-hash, operating-profile, max-registry-age-ms, max-future-clock-skew-ms, registry-expiry-behavior, evidence-max-delay-ms, reader-inactivity-ms, reader-history-access-allowed, allowed-archive-profile-hashes, network-outage-behavior, backup-frequency-ms, restore-test-interval-ms, allowed-crypto-suite-ids, allowed-format-versions, effective-from-sequence, critical-extensions | §§10.5–10.6, 11.5, 12.3, 12.6, 14.2, 15.3, 16.3 | bestätigt |
| Writer transition: object-version, organization-id, chain-id, old/new-writer-certificate-hash, effective-from-sequence, previous-entry-hash, reason-code, critical-extensions | §§10.2, 12.5 | bestätigt |
| Grant authorization: object-version, authorization-id, organization-id, registry-version, registry-head-hash, authorization-sequence, sorted-entry-hashes, recipient-key-thumbprint, recipient-certificate-hash, purpose, expires-at, critical-extensions | §§10.4, 11.1, 16.2 | bestätigt |
| Destruction authorization: object-version, destruction-id, organization-id, registry-version, registry-head-hash, authorization-sequence, sorted-targets(entry-hash, chain-sequence), scope-code, legal-reason-code, critical-extensions | §§11.1, 16.3 | bestätigt |
| Destruction transition: object-version, destruction-id, destruction-authorization-object-hash, event-id, previous-event-object-hash, from-state, to-state, trigger-code, executed-at, critical-extensions | §§11.1, 16.3 | bestätigt |
| Deletion attestation: object-version, destruction-id, destruction-authorization-object-hash, replica-id, replica-kind, sorted-removed-object-hashes, result, backup-expiry-at, executed-at, critical-extensions | §§11.1, 16.3 | bestätigt |
| Authorized trust wrapper: authorized-trust-core, organization-admin-authorization-object-hash | §11.1 Admin-Autorisierung | bestätigt |
| Audit core: object-version, event-id, organization-id, device-id, operator-binding-object-hash, signer-certificate-object-hash, strukturell gekoppeltes action/context-Paar, outcome, effective-now, nonce, critical-extensions, COSE-Sign1 | §§12.2–12.3, 14.4, 16.2–16.4 | bestätigt |
| Audit contexts: subject-object-hash; registry-head-hash, policy-object-hash, proposed-sequence, registry-not-after, acknowledged-at, preview-hash; trusted-time-floor, observed-os-wall-clock, max-future-clock-skew-ms, justification-code, issued-at, expires-at; entry-hash, target-kind; old/new-binding-object-hash, effective-from-sequence; authorization-object-hash, target-object-hash, action-code; original-recovery-grant-object-hash, recipient-certificate-object-hash, new-grant-object-hash; destruction-authorization-object-hash, state-event-object-hash; source/target-profile-hash, inventory-hash, active-pointer-hash | §§11.5, 12.2–12.3, 12.6, 14.4, 16.2–16.4 | bestätigt |
| Verification report required fields plus reportSignature/runtimeMetadata; nested chain/result/destruction/gap/error/runtime fields; maschinenlesbare Sort-/Unique-Keys für registryVersions, objectResults, authorizedDestructions, gaps, alle drei Fehlerarrays und publicKeyThumbprints | §16.1 Bericht und deterministische JSON-Ausgabe; §16.3 Vernichtungszustände | bestätigt |
| Key inventory: schemaId, inventoryId, media; mediumId, keyRole, expectedKeyThumbprint, certificateObjectHash, protectionProfile, testKind; maschinenlesbarer Sort-/Unique-Key mediumId | §16.4 | bestätigt |

**Review-Ergebnis:** keine ungelöste Zeile und kein Widerspruch zu Design §§10–16.
