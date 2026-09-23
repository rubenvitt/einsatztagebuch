# Reader-Key-Escrow — das v1.1-Profil

**Status: verbindlich.** Ruling vom 2026-09-22 (DRK-318). Dieses Profil löst den Entwurf vom
2026-09-08 (Status „proposed") ab. Grundlage ist das unabhängige normative und Security-Review
gegen HEAD `3257385` (Anhang `drk-318-escrow-review.md` an DRK-318); die zwölf offenen Fragen sind
in Abschnitt 1 entschieden. Die Umsetzung folgt TDD und dem Cutover aus Abschnitt 9; die Existenz
dieses Profils autorisiert für sich genommen keine Emission. Die Rulings vom 2026-09-23, die vier
Lücken der Umsetzung schließen, stehen in Abschnitt 1.3 und sind in die betroffenen Abschnitte
eingearbeitet.

Kurzformen: `PLAN5` = `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-5-administration-recovery.md`,
`WEBREADER` = `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md`,
`DESIGN` = `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md`,
`ADDENDUM` = `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-wire-format-addendum.md`.

## 1. Die zwölf Entscheidungen

| # | Frage | Entscheidung |
| --- | --- | --- |
| 1 | GC:33 | `PLAN5:42` und `DESIGN:201` werden korrigiert. Wortlaut in Abschnitt 2. |
| 2 | Publikationsfreigabe | **Eigene dritte Trust-Familie** `readerKeyEscrowApproval`, nicht eingebettet, nicht Aktion 7, nicht Root-only. |
| 3 | `reader-subject-id` | **(a) Erzwungene Eindeutigkeit** von `(organizationId, readerSubjectId)` über alle gültigen Escrows. |
| 4 | Öffnungsfrist | **Getrennt:** Publikationsfreigabe 300 000 ms, Öffnungsautorisierung 900 000 ms. |
| 5 | Zweitescrow | **Verboten.** Genau ein gültiges Escrow je Reader-Zertifikat. Ersatz ist ein benannter Vorgang. |
| 6 | Dauerhaftes Ergebnis | **Löschung nach der ersten erfolgreichen Abholung**, zusätzlich harte Höchsthaltedauer 86 400 000 ms. |
| 7 | Transport-Schlüssel | **Flüchtig in geteiltem Rust** (WASM-Speicher), nie persistiert, keine WebCrypto-Ablage. |
| 8 | Capability | **Wiederverwendung von `historicalGrantApprove`.** Keine achte Capability. |
| 9 | Cutover-Vorbedingung | **Ja.** Aktive `webBundleRelease` eines v1.1-Bundles ist Vorbedingung der ersten Publikation. |
| 10 | Randsemantik | **Inklusiv** wie der Bestand: abgelaufen ist `now > expiresAt`. |
| 11 | Vektorort | **Eigene Vektorfamilien** außerhalb `vectors/trust/v1/`. |
| 12 | HPKE-Kontexte | **Hausform** `hpke_info`/`hpke_aad`, Suite-Literal im CBOR, Extension-Slot in der AAD. |

### 1.1 Warum Entscheidung 2 so und nicht anders

Der Escrow-Gegenstand verleiht für sich genommen keine Fähigkeit: Root allein kann kein gültiges
Chiffrat erzeugen (dafür braucht es den privaten Reader-KEM im Browser), ein gefälschtes scheitert
beim Öffnen an der Gegenprobe des abgeleiteten Public Keys, ein umgehängtes an der AEAD-AAD. Die
Freigabe trägt deshalb **nicht** das Argument „zwei Schlüssel sind besser als einer", sondern ein
anderes: das Escrow ist das einzige Objekt im gesamten Bestand, das eine **Person** an ein
Reader-Zertifikat bindet (Feld `reader-subject-id`), und zwei Approver entscheiden später genau
über diese Bindung. Eine Behauptung, auf der eine Zweipersonenfreigabe fußt, darf nicht von einem
einzelnen Schlüssel stammen — und sie gehört in ein eigenes, einzeln auffindbares, einzeln
auditierbares Objekt statt als COSE-Struktur in eine fremde Nutzlast.

Verworfen:

- **Eingebettete Freigabe** (der Entwurf): zahlt den höchsten Preis aller Varianten — dritte
  Payload-Gestalt, zweite Fassung des Einmal-Speichers, neuer `ContentType`, und eine
  Schichtumkehr, weil `ea-format` im Payload-Validator COSE prüfen müsste
  (`validate_trust_signature` behandelt heute ausschließlich die Einträge des Signaturarrays,
  `crates/ea-format/src/etb.rs:670-711`).
- **Aktion 7**: die Golden Vectors stehen dem *nicht* entgegen — der Aktionscode-Negativvektor
  trägt bewusst `200`. Im Weg steht die Paarung Aktion ↔ Registry-Wirkung
  (`schemas/archive/v1/trust.cddl:100-111`, `crates/ea-trust/src/admin_authorization.rs:445-452`,
  `PLAN5:62-72`). Ein Escrow hat keine Registry-Wirkung; eine Aktion ohne Registry-Wirkung ist in
  `verify_authorized_trust_target` eine neue Gestalt.
- **Root-only**: gäbe die Zweischlüssel-Kontrolle über die Subjektbehauptung auf. Das wäre nur
  unter Entscheidung 3(b) richtig gewesen.

### 1.2 Eine Korrektur am Review selbst

Das Review schlug vor, das Escrow in der bestehenden Zwei-Element-Gestalt
`authorized-trust-payload-v1<T>` zu führen und `root_trust_bindings` nur um Allowlist-Einträge zu
erweitern. **Am Baum trägt das nicht.** `authorized-trust-payload-v1<T>` ist
`[core, organization-admin-authorization-object-hash]` (`schemas/archive/v1/trust.cddl:216-219`),
und `root_trust_bindings` verlangt das Autorisierungsobjekt unbedingt, löst es auf und prüft
`authorization_bindings.target_subtype != subtype` (`crates/ea-crypto/src/cose.rs:2481-2589`);
`target-trust-subtype` ist eine geschlossene Sechserliste (`trust.cddl:94-95`). Ein zusätzlicher
Allowlist-Eintrag ohne Erweiterung dieser Liste ist also nicht implementierbar — und ihre
Erweiterung *wäre* Aktion 7.

Daraus folgt die tatsächliche Gestalt: **alle drei Familien sind direkte Familien** nach dem
Vorbild `webBundleRelease` (`crates/ea-crypto/src/cose.rs:1612-1659`,
`schemas/archive/v1/trust.cddl:195-199`). `root_trust_bindings` wird **nicht angefasst**.

### 1.3 Rulings zur Umsetzung (2026-09-23)

Die Vermessung der sechs Umsetzungsscheiben gegen den Baum fand vier Stellen, die dieses Profil
offen ließ. Entschieden (Ruben, 2026-09-23):

| # | Frage | Entscheidung |
| --- | --- | --- |
| U1 | Serverannahme | Der Ausschluss aus dem Registrierungsabschluss bleibt (`ActionMismatch`, Abschnitt 3.1). Die drei Familien haben einen **eigenen** Prüfeinstieg im Trust-Kern, den der Server je Subtyp aufruft; es gibt genau eine Umsetzung der Regeln. |
| U2 | Gültigkeit nach Widerruf | **Widerrufsbewusst.** Ein Escrow, dessen Reader-Zertifikat im gewählten Kopf widerrufen ist, zählt nicht zur Eindeutigkeit und ist nicht zu öffnen. Ersatz ist Widerruf des alten Zertifikats und danach eine normale Publikation mit eigener Freigabe. |
| U3 | Übergabe Browser ↔ nativ | **Datei über die Admin-Inbox** nach dem Muster der Registrierungsanträge. Kein Serverendpunkt. |
| U4 | Cutover-Vorbedingung | Eine minimale native Root-Zeremonie für `webBundleRelease` samt Serverannahme wird gebaut. „v1.1-fähig" heißt `bundle-version` nicht kleiner als die gepinnte Mindestversion. Der Auditkontext trägt den Objekthash der Freigabe (Abschnitt 8). |

Technische Festlegungen der Umsetzung, die aus diesen Rulings folgen:

- Ein einziges ungültiges Objekt einer der drei Familien lässt die **ganze** Escrow-Menge
  scheitern; zwei widersprüchliche gültige Escrows ebenso (Abschnitt 9: kein Überspringen).
- Die Freigabe eines Escrows wird historisch zum wurzelsignierten `issued-at` des Escrows bewertet.
- Die Sequenz einer Autorisierung liegt im Lease des gewählten Kopfes; eine **frische** Annahme
  verlangt zusätzlich, dass jeder Signierer zum aktuellen Kopf noch aktiv ist.
- Die Totalordnung der Öffnungssignaturen ist streng aufsteigend nach Zertifikatshash ohne Duplikat.

## 2. Der korrigierte Satz zur Root-Zeremonie (Entscheidung 1)

`PLAN5:42` und `DESIGN:201` sind seit `webBundleRelease` unzutreffend, unabhängig vom Escrow.
Beide lauten künftig:

> Jede Root-Zeremonie, die **registrywirksamen** Trust-Zustand ändert, bindet eine gültige
> `organizationAdminAuthorization`; Root-only und Admin-only sind dort ungültig. Direkte,
> wurzelsignierte Objektarten **ohne** Registry-Wirkung sind abschließend aufgezählt:
> `webBundleRelease`, `webBundleRevocation`, `readerKeyEscrow`. Sie sind kein zulässiges
> `target-trust-subtype`, tragen keinen Arm in `registry-change-v1` und sind kein Gegenstand des
> Registrierungsabschlusses. Die Anfangsausnahme bleibt auf das unabhängig gepinnte
> Root-Zertifikat und mindestens zwei exakt gepaarte Admin-Zertifikat/Operator-Bindungs-Paare
> beschränkt.

## 3. Die drei Trust-Familien

Alle drei behalten die bestehende EA1-`.etb`-Hülle, äußere Formatversion 1 und leere kritische
Erweiterungen. Ihr Körper ist `[subtype, payload, signatures]`. Keine bestehende v1-Kodierung
ändert sich; `organizationAdminAuthorization` bleibt bei fünfzehn Positionen, einer Signatur und
sieben Aktionscodes.

```cddl
; Ergänzung zu trust-subtype-v1 (heute dreizehn Arme):
;   / "readerKeyEscrow" / "readerKeyEscrowApproval"
;   / "readerKeyEscrowRecoveryAuthorization"

; Ergänzung zu etb-body-v1:
;   ["readerKeyEscrow", reader-key-escrow-payload-v1, [cose-sign1-v1]] /
;   ["readerKeyEscrowApproval", reader-key-escrow-approval-core-v1,
;    [cose-sign1-v1]] /
;   ["readerKeyEscrowRecoveryAuthorization",
;    reader-key-escrow-recovery-authorization-core-v1, [2* cose-sign1-v1]]

; Die Nutzlast ist zweielementig, aber NICHT authorized-trust-payload-v1<T>:
; das zweite Element nennt die Publikationsfreigabe dieses Profils, nicht eine
; organizationAdminAuthorization. Die Trennung ist beabsichtigt — sie hält
; root_trust_bindings und die eingefrorene Aktionstabelle unberührt.
reader-key-escrow-payload-v1 = [
  reader-key-escrow-core-v1,
  reader-key-escrow-approval-object-hash: bstr .size 32
]

reader-key-escrow-core-v1 = [
  1, organization-id: bstr .size 16,
  reader-certificate-object-hash: bstr .size 32,
  reader-subject-id: bstr .size 16,
  enrollment-registry-version: uint,
  enrollment-registry-head-hash: bstr .size 32,
  enrollment-sequence: uint,
  recovery-certificate-object-hash: bstr .size 32,
  recovery-kem-key-thumbprint: bstr .size 32,
  encapsulated-key: bstr .size 32,
  encrypted-reader-kem-key: bstr .size 48,
  issued-at: int, root-key-thumbprint: bstr .size 32, []
]

reader-key-escrow-approval-core-v1 = [
  1, authorization-id: bstr .size 16, organization-id: bstr .size 16,
  registry-version: uint, registry-head-hash: bstr .size 32,
  authorization-sequence: uint,
  admin-key-thumbprint: bstr .size 32,
  admin-certificate-object-hash: bstr .size 32,
  admin-operator-binding-object-hash: bstr .size 32,
  escrow-core-hash: bstr .size 32,
  reader-certificate-object-hash: bstr .size 32,
  reader-subject-id: bstr .size 16,
  issued-at: int, expires-at: int, nonce: bstr .size 32, []
]

reader-key-escrow-recovery-authorization-core-v1 = [
  1, authorization-id: bstr .size 16, organization-id: bstr .size 16,
  registry-version: uint, registry-head-hash: bstr .size 32,
  authorization-sequence: uint,
  escrow-object-hash: bstr .size 32,
  reader-certificate-object-hash: bstr .size 32,
  reader-subject-id: bstr .size 16,
  enrollment-registry-version: uint,
  enrollment-registry-head-hash: bstr .size 32,
  target-transport-key-thumbprint: bstr .size 32,
  purpose: 0,
  issued-at: int, expires-at: int, nonce: bstr .size 32, []
]
```

Die Arität ist Vertrag: 14, 16 und 17 Positionen. `encrypted-reader-kem-key` ist 32 Byte
Schlüssel plus 16 Byte AEAD-Tag. `purpose: 0` bedeutet Ersatz aller verlorenen
Reader-Authenticators; ein Freitext- oder breiterer Operationscode existiert nicht.

**Keine Zirkularität.** Die Freigabe bindet `escrow-core-hash` — den Hash über den **Core**, nicht
über die Nutzlast. Die Nutzlast bindet danach den Objekthash der Freigabe. Die Reihenfolge ist
damit eindeutig: Core → Freigabe → Root-Signatur über die Nutzlast.

### 3.1 Prüfregeln je Familie

**`readerKeyEscrow`** — genau eine Root-Signatur. Geprüft wird sie durch eine eigene Funktion nach
dem Vorbild `verify_web_bundle_trust_signature`: eine Signatur, ein gepinnter Anker, keine
Kettenauflösung, kein `VerificationContext`, kein Katalog. Zusätzlich MUSS gelten:

- `reader-key-escrow-approval-object-hash` löst auf ein vollständig geprüftes
  `readerKeyEscrowApproval` desselben `organization-id` auf, dessen `escrow-core-hash` exakt dem
  Hash dieses Cores entspricht, und dessen `reader-certificate-object-hash` und
  `reader-subject-id` feldgleich sind.
- Das Reader-Zertifikat ist das exakte, bereits Root/Admin-autorisierte, Registry-aktivierte
  Zertifikat mit X25519- und Ed25519-Public-Key.
- Das Recovery-Zertifikat ist zum Enrollment aktiv, von der Art `RecoveryRecipient` und trägt einen
  X25519-KEM-Public-Key, dessen kanonischer Abdruck dem Corefeld gleicht. (Eine eigene
  Recovery-Recipient-Capability gibt es in der Capability-Allowlist nicht; die Art ist die Bindung.)
- **Enrollment-Bindung (MUSS):** `enrollment-registry-version`, `enrollment-registry-head-hash`
  und `enrollment-sequence` sind gleich dem Registry-Zustand, in dem das genannte
  Reader-Zertifikat aktiv wurde. Eine selbst gewählte Zahl in der AAD verhindert kein
  Zurückspielen, sie dokumentiert es nur.
- **Eindeutigkeit (MUSS, Entscheidung 3a):** `(organization-id, reader-subject-id)` ist über alle
  gültigen Escrows eindeutig. Ein zweites Escrow zu derselben Subject-ID mit abweichendem
  Reader-Zertifikat ist ungültig, ebenso ein zweites Escrow zu demselben Reader-Zertifikat mit
  abweichender Subject-ID.
- **Kein Zweitescrow (MUSS, Entscheidung 5):** zu einem Reader-Zertifikat existiert höchstens ein
  gültiges Escrow. Ein exakt byte-gleiches Objekt ist idempotent. Ein Ersatz nach erneutem
  Enrollment ist ein eigener, benannter Vorgang mit eigener Freigabe; er schreibt das alte Objekt
  nie um (append-only).
- **Gültigkeit nach Widerruf (MUSS, U2):** „gültig" heißt in den beiden vorigen Regeln: vollständig
  geprüft und mit einem Reader-Zertifikat, das im gewählten Kopf nicht widerrufen ist. Ein Escrow
  zu einem widerrufenen Reader-Zertifikat zählt nicht zur Eindeutigkeit und ist nicht zu öffnen.
  Der Ersatz aus der vorigen Regel ist damit: Widerruf des alten Reader-Zertifikats (ein bestehender
  Registry-Vorgang mit eigener Admin-Autorisierung), danach eine normale Publikation mit eigener
  `readerKeyEscrowApproval`.

**`readerKeyEscrowApproval`** — genau eine Signatur des benannten aktiven
`OrganizationAdmin`-Zertifikats mit `organizationAdminApprove`, gepaart mit der benannten aktiven
nativen Operator-Bindung und demselben Autoritätssubjekt. Eine Root- oder Approver-Signatur
ersetzt sie nicht. Kopf, Sequenz und Organisation kommen aus der gewählten geprüften Registry, nie
aus Nutzlastbehauptungen. Höchstdauer 300 000 ms; abgelaufen ist `now > expires-at`
(Entscheidung 10). `authorization-id` und `nonce` gehen unverändert in den bestehenden
zweidimensionalen Einmal-Speicher (`crates/ea-trust/src/state.rs:165-203`), `authorization-id`
zuerst.

**`readerKeyEscrowRecoveryAuthorization`** — mindestens zwei COSE-Signaturen mit den bestehenden
Totalordnungs- und Duplikatsregeln, gezählt über `distinct_authority_subjects` mit Schwelle 2
nach dem Vorbild `crates/ea-trust/src/grant_authorization.rs:100-130`. Verlangt werden
`KeyApprover`-Zertifikate mit **`historicalGrantApprove`** (Entscheidung 8). Zwei Zertifikate zu
einer `authoritySubjectId` sind eine Person und erfüllen die Schwelle nicht. Höchstdauer
900 000 ms (Entscheidung 4); abgelaufen ist `now > expires-at`. Alle Zielfelder müssen zu **einem**
vollständig geprüften Escrow passen. Der tatsächliche Ziel-Transport-Public-Key MUSS kanonisches
X25519 sein und dem autorisierten Abdruck gleichen, **bevor** der Recovery-Provider angesprochen
wird.

Alle drei Familien sind vom Registrierungsabschluss ausgenommen
(`crates/ea-trust/src/admission.rs:230-240`, künftig fünf statt zwei Arme mit
`TrustError::ActionMismatch`), sind kein zulässiges `target-trust-subtype` und tragen keinen Arm
in `registry-change-v1`. Angenommen werden sie über einen **eigenen** Prüfeinstieg des Trust-Kerns,
den der Server je Subtyp aufruft (U1); dieser Einstieg prüft dieselben Regeln wie die
Bestandsprüfung. `organization_of` im Server MUSS alle drei kennen
(`crates/ea-sync-server/src/trust.rs:416-439`); heute antwortet es für unbekannte Subtypen `None`
und würde ein Escrow ohne Organisationsprüfung indizieren.

### 3.2 Warum `historicalGrantApprove` und keine achte Capability

`CertificateCapability` ist eine geschlossene Siebener-Allowlist, und `TryFrom<&str>` ist
fail-closed (`crates/ea-crypto/src/cose.rs:1811-1856`); angewandt wird sie beim Parsen **jedes**
Signiererzertifikats (`:1962-1972`). Ein `KeyApprover`-Zertifikat mit einem neuen Literal würde von
jedem v1-Konsumenten als Ganzes mit `SignerMismatch` abgewiesen — die Capability zöge also
`deviceCertificate`, eine v1-Familie, in den Cutover. Der Baum kennt die Regel bereits in
umgekehrter Richtung: ein neuer Content-Type erzeugt ausdrücklich **keine** achte Capability
(`crates/ea-crypto/src/cose.rs:48-50`). Inhaltlich passt die bestehende: `PLAN5:52` weist
`historicalGrantApprove` denselben Personen zu, und `WEBREADER:287-291` nennt das Escrow selbst
als Ersatz des Historical Re-grant. Eine achte Capability wäre teurer und begründete nichts.

## 4. Kryptografische Kontexte

`escrow-core-hash` ist SHA-256 über ASCII `EINSATZARCHIV-READER-KEY-ESCROW-CORE-v1` gefolgt vom
exakten deterministischen CBOR des Cores. Bei der Prüfung wird nie reserialisiert.

HPKE bleibt Suite 1, RFC 9180 Base Mode. `info` und AAD werden **beide** in der Hausform gebildet
— `hpke_info(cbor)` und `hpke_aad(cbor)` aus `crates/ea-crypto/src/digest.rs:263-276` — und der
Familienunterschied steht als Suite-Literal **im CBOR**, genau wie bei `grant-context-v1`
(`schemas/archive/v1/archive.cddl:24-35`). Es entsteht keine neue Domänenkonstante.

```cddl
reader-key-escrow-hpke-context-v1 = [
  1, organization-id: bstr .size 16,
  reader-certificate-object-hash: bstr .size 32,
  reader-subject-id: bstr .size 16,
  enrollment-registry-version: uint,
  enrollment-registry-head-hash: bstr .size 32,
  recovery-certificate-object-hash: bstr .size 32,
  recovery-kem-key-thumbprint: bstr .size 32,
  "EINSATZARCHIV-READER-KEY-ESCROW-1", []
]

reader-key-escrow-restore-context-v1 = [
  1, organization-id: bstr .size 16,
  authorization-object-hash: bstr .size 32,
  escrow-object-hash: bstr .size 32,
  reader-certificate-object-hash: bstr .size 32,
  reader-subject-id: bstr .size 16,
  target-transport-key-thumbprint: bstr .size 32,
  "EINSATZARCHIV-READER-KEY-ESCROW-RESTORE-1", []
]
```

Der leere Extension-Slot ist Pflicht: eine AAD ohne ihn ist bei der nächsten Feldergänzung ein
Bruch. Die Antwort der Öffnung trägt diese öffentliche Bindung, einen 32-Byte-Encapsulated-Key und
ein 48-Byte-Chiffrat. Ihre Echtheit kommt aus HPKE plus der exakt geprüften Autorisierung; sie ist
**keine** neue Trust-Familie.

## 5. Zeremonie A — Publikation beim Enrollment

Reihenfolge, als Ergänzung von `WEBREADER` §6.6 Schritt 5:

1. Root signiert das Reader-Zertifikat; der Browser erhält den Zertifikatshash.
2. Der Browser leitet den Public Key des privaten KEM ab, den er versiegelt, und verlangt
   Gleichheit mit dem geprüften Reader-Zertifikat, **bevor** er ein Chiffrat erzeugt. Root erhält
   nie Klartext.
3. Der Browser bildet den Core und legt `escrow-core-hash` vor.
4. Der Administrator signiert die `readerKeyEscrowApproval` über genau diesen Corehash.
5. Root signiert die Escrow-Nutzlast, die den Objekthash der Freigabe nennt.

**Übergabe (U3).** Der Browser übergibt Core, Encapsulated Key und Chiffrat als Datei, die die
native Administration aus ihrem Inbox-Verzeichnis liest — nach dem Muster der
Registrierungsanträge. Die Datei trägt kein Geheimnis, das nicht ohnehin im Escrow steht; ihre
Echtheit kommt aus der Gegenprobe gegen das geprüfte Reader-Zertifikat und aus Freigabe und
Root-Signatur, nicht aus dem Transportweg.

Die Publikation verbraucht `authorization-id` und `nonce` der Freigabe in einem verschlüsselten
append-only Repository, atomar mit ihrem signierten Audit und den vorbereiteten exakten
Escrow-Bytes, bevor das Ergebnis der Root-Zeremonie zurückkehrt. Ein exakter Wiedereinspielversuch
darf dieselben bereits publizierten Bytes zurückgeben; er darf keinen anderen Core autorisieren.
Widersprüchliches Material zu derselben Autorisierung scheitert.

**Cutover-Vorbedingung (MUSS, Entscheidung 9):** Vor der ersten Escrow-Publikation einer
Organisation MUSS eine aktive `webBundleRelease` eines v1.1-fähigen Bundles gelten, deren
`effective-from-registry-version` nicht größer ist als die Registry-Version der Publikation. Die
Zeremonie hält diese Vorbedingung im Audit fest (Feld `bundle-release-object-hash`, Abschnitt 8).
„v1.1-fähig" heißt: `bundle-version` ist nicht kleiner als die gepinnte Mindestversion, die die
drei Familien trägt (U4). Die Freigabe erzeugt eine minimale native Root-Zeremonie; der Server nimmt
sie über den Weg der direkten Familien an. Die Prüfhälfte liegt fertig da
(`schemas/archive/v1/trust.cddl:200-205`, `crates/ea-reader/src/bundle_release.rs`,
`WEBREADER` §4.2); ohne ihn ist das erste Escrow ein Verfügbarkeitskliff für jeden älteren
Verifizierer, der am gesamten Trust-Store scheitert.

## 6. Zeremonie B — Öffnung mit zwei Approvern

Voraussetzung ist der Verlust **aller** Authenticators eines Readers (`WEBREADER` §7.5).

1. Der Browser erzeugt ein flüchtiges X25519-Transport-Schlüsselpaar (Abschnitt 7) und zeigt
   dessen Fingerprint.
2. Zwei verschiedene Key Approver signieren die `readerKeyEscrowRecoveryAuthorization` über
   Ziel-Identität, Zweck und diesen Fingerprint.
3. Die Öffnung verlangt eine frische native Reauthentifizierung mit dem eigenen Zweck
   `ReaderKeyEscrowRecovery`, gebunden an den exakten Autorisierungs-Objekthash und den
   Transport-Fingerprint.
4. Die Öffnung verbraucht `(organizationId, authorizationId)` und `(organizationId, nonce)` atomar
   mit einem signierten lokalen Audit, **bevor** der private Provider angesprochen wird.
5. Der Recovery-Schlüssel entkapselt das Escrow. Der Dienst prüft den entschlüsselten X25519-
   Schlüssel gegen das Reader-Zertifikat des Escrows und versiegelt ihn unmittelbar per HPKE an
   den Ziel-Transport-Key. Der einzige Rückgabewert ist der verschlüsselte Umschlag. Der
   Transport-Public-Key geht als Datei über die Admin-Inbox hinein, der Umschlag samt öffentlicher
   Bindung als Datei zurück (U3); der Browser importiert ihn.
6. Der Browser öffnet die Antwort nur mit seinem lebenden privaten Transport-Schlüssel, prüft
   jedes AAD-Feld und den wiederhergestellten KEM-Fingerprint, erzeugt einen **neuen
   Ed25519-Schlüssel** und einen neuen Vault mit zwei bestätigten unabhängigen Authenticators.

Der Recovery-Port braucht dafür eine **zweite getypte Operation**: `RecoveryKem` ist heute auf
`GrantV1` typisiert (`crates/ea-recovery/src/historical_grant.rs:62-66`), und ein Escrow ist kein
`GrantV1`. Der PKCS#11-Unterbau trägt bereits generisch
(`crates/ea-recovery/src/pkcs11_provider.rs:100-119`), das Routing liegt an einer Stelle
(`crates/ea-recovery/src/resolved_key.rs:40`).

Ed25519 statt X25519, fremde Organisation, geänderte Identität, ein ausgetauschtes Escrow, eine
veraltete Enrollment-Bindung, Freigaben derselben Person, überzählige oder doppelte ungeprüfte
Signaturen und abgelaufene Autorität geben nichts heraus.

## 7. Der Transport-Schlüssel (Entscheidung 7)

Die Zeremonie setzt voraus, dass alle Authenticators verloren sind. Der Vault-Wrap über
WebAuthn-PRF (`WEBREADER` §6.2) steht damit **per Definition** nicht zur Verfügung. Das Review
schlug einen nicht-extrahierbaren WebCrypto-Schlüssel vor; **am Baum trägt das nicht**: der
Web-Reader benutzt `crypto.subtle` nirgends, jede Schlüsseloperation liegt in geteiltem Rust, und
`apps/web/src/vault/webauthn-prf.ts` ist ausdrücklich die einzige Stelle des Bündels, durch die
überhaupt ein Klartext-Schlüsselbaustein durch JavaScript läuft. Ein WebCrypto-Schlüssel wäre
entweder nicht benutzbar (HPKE öffnet in WASM) oder verlangte eine neue Krypto-Naht an der
sensibelsten Stelle des Systems.

Normativ gilt deshalb:

- Das Transport-Schlüsselpaar entsteht in geteiltem Rust und lebt als `SecretBytes<32>` im
  linearen WASM-Speicher — dieselbe Ablage wie der Reader-KEM selbst
  (`crates/ea-reader/src/vault.rs`).
- Es wird **nie** persistiert: kein OPFS, kein IndexedDB, kein `localStorage`, kein Vault.
- Es gilt für **genau eine** Zeremonie. Ein Neuladen der Seite vernichtet es und erzwingt eine
  neue Autorisierung. Das ist kein Mangel, sondern die Frist.
- Es wird bei Erfolg, Sperrung und Fehler genullt (`zeroize`), wie jeder andere flüchtige
  Geheimwert des Readers.
- Sein Fingerprint wird angezeigt und den Approvern vor der Signatur außerhalb des Systems
  vorgelegt.
- Es entsteht ausschließlich im aktivierten, Root-signierten, gepinnten Bundle (`WEBREADER` §4.2).

Daraus folgt die Frist aus Entscheidung 4: 300 s zwingen zwei Menschen an Offline-Schlüsselmedien
innerhalb von fünf Minuten zur Signatur, während die Seite offen bleiben muss. 900 s sind
durchführbar, und die Replay-Härte kommt ohnehin aus dem dauerhaften Verbrauch, der
Fingerprint-Bindung und der nativen Reauthentifizierung, nicht aus der Frist.

## 8. Dauerhafter Zustand, Audit und Fehlerfälle

Das Auditprofil ist keine additive Kleinigkeit, sondern eine Erweiterung dreier gekoppelter
Stellen (`schemas/reports/v1/local-audit.cddl:3`, `:47-61`, `:64-76`, Kopie in `ADDENDUM:518-531`,
Rust-Typ `crates/ea-format/src/local_audit.rs:772-789`). Festgeschrieben:

```cddl
local-audit-action-v1 = 0..14          ; 13 Publikation, 14 Öffnung

reader-key-escrow-context-v1 = [
  escrow-object-hash: bstr .size 32,
  authorization-object-hash: bstr .size 32,
  target-transport-key-thumbprint: (bstr .size 32) / null,
  bundle-release-object-hash: (bstr .size 32) / null
]
reader-key-escrow-audit-context-v1 = [9, reader-key-escrow-context-v1]

; local-audit-event-core-v1 wächst um:
;   local-audit-event-core-for-v1<13, reader-key-escrow-audit-context-v1> /
;   local-audit-event-core-for-v1<14, reader-key-escrow-audit-context-v1>
```

Aktion 13 trägt bei `target-transport-key-thumbprint` `null` und bei `bundle-release-object-hash`
den Objekthash der aktiven `webBundleRelease`, die die Cutover-Vorbedingung erfüllt (Abschnitt 5,
U4); Aktion 14 trägt den Abdruck und bei `bundle-release-object-hash` `null`. Der
Kontext trägt ausschließlich Hashes — kein PIN, kein Pfad, kein Klartext, kein Schlüssellabel.

**Ergebnis und Verfall (Entscheidung 6).** Ein dauerhaftes verschlüsseltes Ergebnis darf durch
seine exakte Autorisierung nach frischer nativer Reauthentifizierung idempotent abgeholt werden.
Es wird nach der **ersten erfolgreichen Abholung gelöscht**; unabhängig davon verfällt es
spätestens nach 86 400 000 ms. Beides steht im Audit. Ohne diese Regel ist die Idempotenz ein
dauerhafter Nebenspeicher für Schlüsselmaterial.

Ein Absturz nach dem Verbrauch und vor dem dauerhaften verschlüsselten Ergebnis verlangt eine
frische Zwei-Approver-Autorisierung; die alte läuft nie wieder. Eine Abholung darf nie an einen
anderen Schlüssel umverschlüsseln. Ungültiger oder zerrissener Audit- oder Ausgabezustand bleibt
ein ausdrücklicher Fehlschlag. Eine Verbrauchszeile wird **nie** zurückgesetzt, damit ein Versuch
gelingt.

## 9. Cutover (GC:26)

Gemeinsam umzuschalten sind Grammatik, Codec, Kryptokontexte, Admission-Verifizierer, Offline-
Archivverifizierer, CLI, Server-Transport und -Replikation, Browser-WASM und das Root-signierte
Reader-Bundle. Ein Deployment, das die vollständige Unterstützung nicht nachweisen kann, bleibt
ausdrücklich enrollment-blockiert. Kein Server-Schalter hebt die Bundle- oder CLI-Unterstützung
auf, und kein Kompatibilitätsparser überspringt die neuen Subtypen. Bestehende Golden Bytes und
semantische Ergebnisse bleiben unverändert.

Die vollständige Stellenliste steht im Review-Anhang von DRK-318, Abschnitt D. Über den Entwurf
hinaus gehören ausdrücklich dazu:

- `deviceCertificate` **nicht** — Entscheidung 8 hält die Capability-Allowlist unberührt.
- `crates/ea-operator/src/session.rs:93-145`: zwölfter `ReauthPurpose`, `ALL: [Self; 12]`, Label.
  Der Doc-Kommentar dort spricht heute von „elf Zwecke" und „ein elfter Zweck"; er zieht mit.
- `crates/ea-sync-server/src/trust.rs:15-20`: der Kopfkommentar zählt „heute elf Arme", der Baum
  hat dreizehn und bekommt sechzehn.
- `DESIGN:953` (elf signierte Subtypen) und `ADDENDUM:301-304` (`trust-subtype-v1` mit elf Armen)
  sind **schon vor diesem Ticket falsch** und werden unabhängig vom Escrow korrigiert.
- `WEBREADER:339-341` verlangt für die Öffnung eine „`organizationAdminAuthorization`, signiert
  von zwei verschiedenen Approvern". Das ist seit der Entscheidung vom 2026-08-17 überholt und
  mit der Kardinalität 1 unvereinbar; der Satz wird auf die eigene Familie umgestellt.
- `WEBREADER:325-329` nennt eine AAD aus drei Feldern; verbindlich sind die sieben aus
  Abschnitt 4.
- `WEBREADER` §6.6 Schritt 5 und §7.6 ziehen mit (Zweitescrow-Verbot, zweites Restrisiko).

**Vektoren (Entscheidung 11).** Die Reserved-Pins sind Substring-Prüfungen über den gesamten
Manifesttext (`tests/ea-system-tests/tests/conformance_golden_vectors.rs:2033`, `:2439-2446`;
`crates/ea-testkit/src/lib.rs:7605-7612`), und alle drei neuen Namen enthalten das Literal
`readerKeyEscrow`. Jeder Eintrag unter `vectors/trust/v1/` dreht beide Tests rot. Die
Vektorfamilien liegen deshalb daneben — `vectors/reader-key-escrow/v1/`,
`vectors/reader-key-escrow-approval/v1/` und `vectors/reader-key-escrow-recovery/v1/` — nach dem
gebauten Vorbild `vectors/web-bundle/v1/` (`tools/xtask/src/main.rs:2135-2142`, `:2234`).
Eintragsnamen kebab-case ohne die Literale; die Literale stehen ausschließlich in den hex-kodierten
Objektbytes.

## 10. Benannte Restrisiken

1. **Zielgerät während der Zeremonie** (neu, ergänzt `WEBREADER` §7.6): der private
   Transport-Schlüssel liegt ohne Authenticator-Schutz im Browser, weil der Vault per Definition
   der Zeremonie nicht zur Verfügung steht. Ein in diesem Fenster kompromittiertes Browsergerät
   erhält den privaten Reader-KEM und damit dauerhaften stillen Zugriff auf jeden Inhalt, für den
   dieser Reader je einen Grant hatte. Gemindert durch Flüchtigkeit (Abschnitt 7), die
   Ergebnislöschung (Entscheidung 6) und das gepinnte Bundle; technisch nicht ausschließbar.
2. **Zurechenbarkeit nach der Wiederherstellung**: Zertifikatskontinuität läuft über Gleichheit
   der KEM-Public-Keys. Ein Zugriffsangriff trägt darüber nicht — die Grants sind an diesen Public
   Key gekapselt, und offline ordnet der Verifizierer ohnehin ausschließlich über den KEM-Abdruck
   zu (`crates/ea-verify/src/recipient.rs:1-35`). Was bleibt, ist eine Auditlücke: der neue Reader
   ist für den Altbestand nicht von der alten Person unterscheidbar. Das Öffnungsaudit ist die
   einzige Brücke.
3. **Böswilliger Custodian mit zwei kooperierenden Approvern** — unverändert `WEBREADER` §7.6.

## 11. Abnahme

Unabhängige Golden Vectors sowie Negativvektoren für Fehlform, Arität und Kontext für alle drei
Subtypen; echte Browser-Erzeugung und -Einfuhr; echte native Publikation und Öffnung mit
signiertem dauerhaftem SQLCipher-Audit; echte modulgestützte Recovery-Öffnung; vollständige
Offline-Verifikation ohne Serverdaten; Live-Server-Admission samt Replikation, Export und Import;
ein nach den ersten Einträgen neu enrollter Reader; Ziel-Schlüssel-Austausch; Freigaben derselben
Person unter zwei Zertifikaten; Trennung veralteter und aktueller Registry; Replay-, Nebenläufigkeits-
und Neustartfehler; Kanarienvogelsuche durch Dateien, Berichte und DOM; und das vollständige
Fresh-Machine-Recovery-/Lebenszyklus-Gate. Zusätzlich verlangt dieses Profil ausdrücklich
Negativzeugen für: eine abweichende Enrollment-Version, ein zweites Escrow zu derselben
Subject-ID, ein zweites Escrow zu demselben Reader-Zertifikat, eine Publikation ohne aktive
v1.1-`webBundleRelease`, eine Freigabe genau auf dem Randwert `expiresAt`, und ein Escrow mit
fremder `organizationId` gegen `organization_of`.

Browser-Bridge-Fakes sind ausschließlich UI-Beleg. Physische Verwahrung sowie installierte
Mindest- und Höchstversionsfälle bleiben Stufe 7.

## 12. Ledger

`WR-075` (`docs/traceability/v0.1-requirements.csv:158`) bewegt sich erst, wenn die
Fingerprint-Bindung aus Abschnitt 6 mit Zeugen steht; bis dahin bleibt die Zeile `planned` und
wird im Stufe-5-Gate als dokumentierte Grenze geführt. Die Transport-Fingerprint-Anteile
von `AK-47` und `AK-53` hängen an derselben Zusage.

**Stand nach der Umsetzung (DRK-456 … DRK-461):** `WR-075` ist `integrated`; die dokumentierte
Grenze ist entfallen, der Grenzmechanismus des Stufe-5-Gates ist weiter synthetisch bezeugt.
`AK-47` und `AK-53` bleiben `implemented`. Belege und verbliebene benannte Grenzen stehen in
`docs/traceability/stage-5-gate.md`, Abschnitt „Geschlossen mit DRK-318“.
