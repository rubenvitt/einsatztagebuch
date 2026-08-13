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
- `schemas/reports/v1/local-audit.cddl`: signiertes, klartextfreies lokales Audit,
- `schemas/reports/v1/verification-report.schema.json` und
  `key-inventory.schema.json`: geschlossene JSON-Schemata.

Symbolische CDDL-Namen dokumentieren Arraypositionen; sie werden nicht als CBOR-Map-
Keys serialisiert. Alle CBOR-Objekte werden deterministisch gemäß Design §10.1
kodiert. `COSE-Sign1 = any` ist nur der CDDL-Anker für das extern durch RFC 9052/9053
definierte, zusätzlich semantisch geprüfte COSE-Objekt.

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
  1, organization-id: bstr .size 16, chain-id: bstr .size 16,
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
  1, organization-id: bstr .size 16, chain-id: bstr .size 16,
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

`hash-algorithm = 0` bedeutet ausschließlich SHA-256. Die TSA-Zertifikatskette ist
nicht leer. `sorted-renewal-input-hashes` ist byteweise aufsteigend und
duplikatfrei. Evidence folgt der CTT-Imprint-, Frist- und Vorgängerkettendefinition
aus Design §§15.2–15.4. Der Stub enthält exakt die in Design §§11.4 und 16.3
erlaubten öffentlichen Bindungen und keinen Ciphertext, CEK oder Grant.

## Trust Bundle

Die `.etb`-Hülle und ihre stabilen Textdiscriminators lauten:

```cddl
etb-v1 = [h'45413100', 5, 1, [], [trust-subtype-v1, trust-payload-v1, [+ #6.18(COSE-Sign1)]]]
trust-subtype-v1 = "rootCertificate" / "deviceCertificate" / "operatorBinding" /
  "organizationAdminAuthorization" / "registryEvent" / "policy" /
  "writerTransition" / "grantAuthorization" / "destructionAuthorization" /
  "destructionTransition" / "deletionAttestation"

authorized-trust-payload-v1<T> = [
  authorized-trust-core: T,
  organization-admin-authorization-object-hash: bstr .size 32
]
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

Initiale Root-/Admin-Ausnahmen tragen den Core direkt. Jedes andere admin-
autorisierte Ziel trägt exakt den Hash des Admin-Authorization-Objekts als zweites
Element. Für `grantAuthorization` und `destructionAuthorization` enthält die äußere
Signaturliste mindestens zwei Signaturen, nach Signer-Zertifikat-Hash sortiert, von
unterschiedlichen aktiven Subject-IDs mit passender Approver-Capability. Eine Root-
Rotation trägt zusätzlich eine Signatur der vorherigen akzeptierten Root-Linie. Die
initiale Root-Proof-of-Possession ist die einzige in Design §10.1 definierte
COSE-Identity-Header-Ausnahme.

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
Sortierschlüssel. Jedes JSON-Objekt, auch jedes geschachtelte, setzt
`additionalProperties: false`.

## Feld-zu-Design-Review

Die Gruppen führen jedes hinzugefügte Feld mindestens einmal auf. Status
`bestätigt` bedeutet: kein Widerspruch zum angegebenen Designabsatz.

| Artefakt / Felder | Designquelle | Status |
|---|---|---|
| `.ecp`: magic, object-type, format-version, critical-extensions, variant tag | §11.1 Typ-Tags und Hülle | bestätigt |
| checkpoint: object-version, organization-id, chain-id, covered-from-sequence, covered-through-sequence, head-entry-hash, registry-head-hash, issued-at-server, previous-evidence-hash, critical-extensions | §§15.2–15.3 | bestätigt |
| timestamp: checkpoint-core, COSE-Sign1, rfc3161-response-der, hash-algorithm, request-nonce, policy-oid-der, tsa-certificate-chain-der, revocation-data-der, validation-data-der | §15.3 | bestätigt |
| renewal: object-version, organization-id, chain-id, current-entry-hash, previous-renewal-hash, sorted-renewal-input-hashes, critical-extensions, COSE-Sign1 und alle Timestamp-Felder | §15.4 mit §15.3 | bestätigt |
| `.eds`: magic, object-type, format-version, outer/body critical-extensions, object-version, signed-manifest, writer-signature, entry-hash, ciphertext-hash, original-eip-object-hash, destruction-id, destruction-authorization-object-hash | §§11.1, 11.4, 16.3 | bestätigt |
| `.etb`: magic, object-type, format-version, critical-extensions, trust-subtype, trust-payload, signatures | §11.1 | bestätigt |
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
| Audit core: object-version, event-id, organization-id, device-id, operator-binding-object-hash, signer-certificate-object-hash, action, outcome, effective-now, context, nonce, critical-extensions, COSE-Sign1 | §§12.2–12.3, 14.4, 16.2–16.4 | bestätigt |
| Audit contexts: subject-object-hash; registry-head-hash, policy-object-hash, proposed-sequence, registry-not-after, acknowledged-at, preview-hash; trusted-time-floor, observed-os-wall-clock, max-future-clock-skew-ms, justification-code, issued-at, expires-at; entry-hash, target-kind; old/new-binding-object-hash, effective-from-sequence; authorization-object-hash, target-object-hash, action-code; original-recovery-grant-object-hash, recipient-certificate-object-hash, new-grant-object-hash; destruction-authorization-object-hash, state-event-object-hash; source/target-profile-hash, inventory-hash, active-pointer-hash | §§11.5, 12.2–12.3, 12.6, 14.4, 16.2–16.4 | bestätigt |
| Verification report required fields plus reportSignature/runtimeMetadata; nested chain/result/destruction/gap/error/runtime fields | §16.1 Bericht und deterministische JSON-Ausgabe; §16.3 Vernichtungszustände | bestätigt |
| Key inventory: schemaId, inventoryId, media; mediumId, keyRole, expectedKeyThumbprint, certificateObjectHash, protectionProfile, testKind | §16.4 | bestätigt |

**Review-Ergebnis:** keine ungelöste Zeile und kein Widerspruch zu Design §§10–16.
