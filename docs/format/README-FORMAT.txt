EINSATZARCHIV - OEFFENTLICHES FORMATPAKET, SUITE 1
==================================================

Stand: Stufe 1 von v0.1. Dieses Paket beschreibt den Objektrahmen, das
Verzeichnislayout, die Hash- und Domaintrennung und die Parsergrenzen. Zusammen
mit den mitgelieferten Schemata unter format/schemas/, die die Rumpfform jeder
Objektfamilie festlegen, kann ein fremdes Werkzeug ohne Zugriff auf diese
Quelltexte ein Archiv lesen, seine Hashes nachrechnen und seine Signaturen
pruefen.

Normativ sind der Entwurf
docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md, das
Wire-Format-Addendum vom selben Datum und die Schemata unter schemas/ bzw.
format/schemas/ im Bestand. Dieses Dokument fasst zusammen und widerspricht
ihnen nicht; im Konfliktfall gilt der Entwurf.

Fassungen sind unabhaengig: formatVersion, objectVersion, schemaVersion und
cryptoSuiteId entwickeln sich getrennt, und bereits geschriebene Bytes bleiben
unveraendert. Suite 1 ist festgelegt auf formatVersion = 1, objectVersion = 1,
cryptoSuiteId = "EINSATZARCHIV-SUITE-1" und Grant-Suite
"EINSATZARCHIV-HPKE-1".

Grundlagen: deterministisches CBOR nach RFC 8949, COSE_Sign1 nach RFC 9052,
vollstaendig spezifiziertes Ed25519 nach RFC 9864, SHA-256, ChaCha20-Poly1305,
HPKE Base Mode nach RFC 9180 mit X25519 / HKDF-SHA-256 / ChaCha20-Poly1305,
UUIDv7 nach RFC 9562 und Schluessel-Thumbprints nach RFC 9679.


1. OBJEKTTYPEN, MAGIC UND EXACT-OBJECT-PRAEFIX
----------------------------------------------

Jedes Archivobjekt ist genau ein deterministisch kodiertes CBOR-Array mit fuenf
Positionen:

  [ magic, objectType, objectVersion, criticalExtensions, body ]

  magic               h'45413100'   - die drei Zeichen "EA1" und 0x00
  objectType          1 bis 6       - siehe Tabelle unten
  objectVersion       1
  criticalExtensions  []            - leer; ein nichtleeres Array wird
                                      abgelehnt (EA-FORMAT-CRITICAL-EXTENSION)
  body                objekttypeigenes Array

Daraus ergeben sich die ersten neun Bytes jedes Objekts als festes Praefix:

  0x85 0x44 0x45 0x41 0x31 0x00 <tag> 0x01 0x80

  0x85   CBOR-Array mit fuenf Positionen
  0x44   CBOR-Byte-String der Laenge 4
  0x45 0x41 0x31 0x00   das Magic h'45413100'
  <tag>  Objekttyp-Tag, 0x01 bis 0x06
  0x01   objectVersion 1
  0x80   leeres Array kritischer Erweiterungen

Die sechs Objekttyp-Tags:

  .eip=1   Eintragspaket mit signiertem Manifest und Ciphertext
  .eag=2   Zugriffsfreigabe: ein signierter Schluesselumschlag je Empfaenger
  .esr=3   Serverquittung
  .ecp=4   Checkpoint- und Evidence-Objekt
  .etb=5   Trust-Objekt (Organisation, Registry, Bindungen, Autorisierungen)
  .eds=6   Stummel eines autorisiert vernichteten Eintrags

Das Praefix entscheidet die Klasse eines Bytestroms, nie der Dateiname und nie
das Verzeichnis. Bytes mit diesem Praefix sind ein Archivobjekt und werden
vollstaendig geprueft; schlaegt das Parsen fehl, werden sie mit einem Grund aus
der geschlossenen Menge malformed, duplicate, conflicting, unattributable
isoliert. Bytes ohne dieses Praefix sind kein Archivobjekt und werden nur
gezaehlt (nonObjectFileCount).

Fehlercodes des Rahmens: EA-FORMAT-PREFIX, EA-FORMAT-UNKNOWN-VERSION,
EA-FORMAT-CRITICAL-EXTENSION, EA-FORMAT-TAG-MISMATCH, EA-FORMAT-SHAPE,
EA-FORMAT-GLOBAL-RAW-LIMIT und die sechs familieneigenen Grenzcodes
EA-FORMAT-EIP-RAW-LIMIT bis EA-FORMAT-EDS-RAW-LIMIT.


2. VERZEICHNISLAYOUT
--------------------

Ein Bestand ist ein Verzeichnisbaum. Die Pfade sind Hinweise fuer Erzeuger,
keine Vertrauensquelle: Objektart, Identitaet und Beziehungen leitet die
Verifikation ausschliesslich aus Bytes, Hashes und Signaturen ab.

  <bestand>/
    trust/organization.etb            Organisationsstand als Trust-Objekt
    trust/registry-events/            Registrierungsereignisse
    trust/operator-bindings/          Bedien- und Geraetebindungen
    trust/authorizations/             Admin-, Freigabe- und
                                      Vernichtungsautorisierungen
    entries/                          Eintragspakete (.eip)
    destroyed-entries/                Stummel vernichteter Eintraege (.eds)
    grants/                           Zugriffsfreigaben (.eag)
    receipts/                         Serverquittungen (.esr)
    checkpoints/                      Checkpoints und Evidence (.ecp)
    destructions/<vorgang>/events/        Uebergangsereignisse (.etb)
    destructions/<vorgang>/attestations/  Loeschbestaetigungen (.etb)
    format/schemas/
    format/transformations/
    format/compatibility-matrix.json
    recovery-reports/
    README-FORMAT.txt

Beiwerk ohne Objektpraefix: README-FORMAT.txt, format/schemas/,
format/transformations/, format/compatibility-matrix.json und
recovery-reports/. Es traegt keine Vertrauensaussage und kann keine
vortaeuschen.


3. UNABHAENGIGER TRUST ANCHOR
-----------------------------

Authentische Recovery beginnt an einem unabhaengig verwahrten Trust Anchor; archivinternes Vertrauen ist nie TOFU.

Der Anker ist nie Teil der Inventarklassifikation. Er wird ausserhalb des
Bestands verwahrt und der Verifikation als Parameter uebergeben. Ein Archiv,
das seinen eigenen Anker mitbringt, ist damit kein verifizierbares Archiv,
sondern ein selbstbezuegliches: es bewiese nur, dass es zu sich selbst passt.
Ein in sich stimmiger Bestand mit fremdem Root oder fremdem Genesis wird gegen
den unabhaengig bereitgestellten Anker abgelehnt.

Bedienerbezogene Momentaufnahmen stammen ausschliesslich aus gueltigen,
Root-signierten Bindungen an OS-Konto und Geraet.


4. HASH- UND DOMAINTRENNUNG DER SUITE 1
---------------------------------------

Jede Hashformel der Suite 1 haengt ein festes Domain-Praefix vor das Urbild.
"||" bezeichnet die Verkettung von Bytes; die Domain steht als ASCII ohne
Laengenpraefix vorn.

  objectHash          = SHA-256(EINSATZARCHIV-OBJECT-v1 || exakte Objektbytes)
  ciphertextHash      = SHA-256(EINSATZARCHIV-CIPHERTEXT-v1 || Ciphertext)
  recordDigest        = SHA-256(EINSATZARCHIV-RECORD-v1 || CBOR des Manifests)
  entryHash           = SHA-256(EINSATZARCHIV-PACKAGE-v1 || recordDigest
                                || exakte Writer-COSE_Sign1-Bytes)
  grantPlanDigest     = SHA-256(EINSATZARCHIV-GRANT-PLAN-v1 || CBOR des Plans)
  grantDigest         = SHA-256(EINSATZARCHIV-GRANT-v1 || CBOR des Grants)
  receiptDigest       = SHA-256(EINSATZARCHIV-RECEIPT-v1 || CBOR der Quittung)
  trustDigest         = SHA-256(EINSATZARCHIV-TRUST-OBJECT-v1 || CBOR des
                                Trust-Objekts)
  authorizedTrustDigest
                      = SHA-256(EINSATZARCHIV-ADMIN-AUTHORIZED-TRUST-v1
                                || CBOR des autorisierten Inhalts)
  renewalInputDigest  = SHA-256(EINSATZARCHIV-EVIDENCE-RENEWAL-INPUT-v1
                                || CBOR der Erneuerungseingabe)
  bootstrapAnchorHash = SHA-256(EINSATZARCHIV-TRUST-ANCHOR-PRE-v1
                                || CBOR des Bootstrap-Ankers)
  trustAnchorHash     = SHA-256(EINSATZARCHIV-TRUST-ANCHOR-v1 || CBOR des
                                Ankers)
  operatorProfileDigest
                      = SHA-256(EINSATZARCHIV-OPERATOR-PROFILE-v1 || CBOR des
                                Profils)
  recoveryTestDigest  = SHA-256(EINSATZARCHIV-RECOVERY-TEST-v1
                                || CBOR([1, challenge, keyThumbprint]))
  osAccountBindingHash
                      = SHA-256(EINSATZARCHIV-OS-ACCOUNT-v1
                                || CBOR des os-account-context-v1)

Der letzte Wert ist der einzige, der einen Bezug zu einem Betriebssystemkonto
archiviert: gespeichert wird ausschliesslich dieser Hash, nie der Kontoname und
nie ein Plattformstring. Die geschlossene Form von os-account-context-v1 steht
in schemas/identity/v1/os-account.cddl.

Zwei weitere Trennzeichenketten sind keine Hashdomaenen, sondern die Typkennung
an Position 2 der signierten Protokollkerne im .ecp. Sie gehen als Text in die
signierten Bytes ein und trennen die beiden Kernarten voneinander:

  EINSATZARCHIV-CHECKPOINT-v1         Checkpoint-Kern
  EINSATZARCHIV-EVIDENCE-RENEWAL-v1   Kern der Evidence-Erneuerung

Drei Kontextformeln sind keine Hashes, sondern Praefixe. Sie gehen unveraendert
als AAD bzw. als HPKE-info in die Primitive ein:

  payloadAad = EINSATZARCHIV-AAD-v1 || CBOR des Manifestkerns
  hpkeInfo   = EINSATZARCHIV-HPKE-INFO-v1 || CBOR des Grant-Kontexts
  hpkeAad    = EINSATZARCHIV-HPKE-AAD-v1 || CBOR des Grant-Kontexts

Genau eine Formel der Suite 1 traegt bewusst KEINE Domaintrennung:

  reportHash = SHA-256(canonical report bytes)

Sie hasht die kanonischen Bytes eines Verifikationsberichts ohne die Felder
reportHash und signature. Der Grund ist die Nachrechenbarkeit ausserhalb dieses
Formats: der Bericht ist ein JSON-Dokument, das mit
{"schemaId":"ea.verification-report/v1" beginnt, und ein fremdes Werkzeug soll
den Wert mit einem blanken SHA-256 bestaetigen koennen. Die Trennung entsteht
hier aus der Gestalt des Urbilds - jedes andere Urbild dieses Formats ist CBOR
mit vorangestellter Domain. Diese Formel darf ausschliesslich auf
Berichtsbytes angewandt werden.

Signaturen sind COSE_Sign1 ueber diese Digests mit Ed25519 nach RFC 9864;
Schluessel werden ueber Thumbprints nach RFC 9679 benannt. Der Nutzinhalt wird
mit ChaCha20-Poly1305 unter einem frischen Inhaltsschluessel (CEK) je Eintrag
verschluesselt; jeder Empfaenger erhaelt den CEK in einem eigenen, signierten
.eag, gekapselt mit HPKE Base Mode nach RFC 9180.


5. PARSERGRENZEN
----------------

Alle Grenzen sind harte Ablehnungsgrenzen und gelten vor jeder inhaltlichen
Pruefung. Ein Objekt, das eine von ihnen ueberschreitet, wird nie geparst.

Rohgrenzen je Objektfamilie, in Bytes einschliesslich des Neun-Byte-Praefixes:

  MAX_ARCHIVE_OBJECT_BYTES_V1 = 4_194_304   globale Objektgrenze
  EIP_MAX_RAW_BYTES_V1 = 2_097_152
  EAG_MAX_RAW_BYTES_V1 = 65_536
  ESR_MAX_RAW_BYTES_V1 = 65_536
  ECP_MAX_RAW_BYTES_V1 = 4_194_304
  ETB_MAX_RAW_BYTES_V1 = 4_194_304
  EDS_MAX_RAW_BYTES_V1 = 262_144

Wert- und Arbeitsgrenzen des CBOR-Parsers:

  MAX_PLAINTEXT_BYTES_V1 = 1_048_576        Klartext eines Nutzinhalts
  MAX_CBOR_TEXT_OR_BYTES_V1 = 1_048_592     laengster Text- oder Byte-String
  MAX_CIPHERTEXT_BYTES_V1 = 1_048_592       Ciphertext einschliesslich Tag
  MAX_NESTING_DEPTH_V1 = 16                 maximale Schachtelungstiefe
  MAX_CONTAINER_ITEMS_V1 = 10_000           Elemente je Container
  MAX_TOTAL_ITEMS_V1 = 10_000               Token je Element oberster Ebene

Zusaetzlich gilt die deterministische Kodierung nach RFC 8949 verbindlich:
kuerzeste Laengenform, sortierte Map-Schluessel, keine unbestimmten Laengen,
keine ungenutzten Bytes hinter dem Objekt. Jede Abweichung ist ein Parsefehler,
keine Auslegungsfrage.


6. KOMPATIBILITAETSDATEIEN
--------------------------

Drei Beiwerksorte machen die Fassungslage eines Bestands lesbar, ohne selbst
Vertrauen zu tragen:

  format/schemas/                   die versionierten Schemata (CDDL und JSON
                                    Schema), mit denen der Bestand geschrieben
                                    wurde
  format/transformations/           die beschriebenen Ableitungen zwischen
                                    Schemafassungen, aus denen ein neuerer
                                    Leser eine gekennzeichnete Altansicht
                                    bildet
  format/compatibility-matrix.json  die Zuordnung von Schema-, Format- und
                                    Suite-Fassungen zu den Lesern, die sie
                                    unterstuetzen

Ein Leser, der ein Schema, eine kritische Erweiterung oder eine Suite nicht
kennt, lehnt das Objekt benannt ab (EA-SCHEMA-UNSUPPORTED bzw.
EA-FORMAT-CRITICAL-EXTENSION). Es gibt keinen dritten Ausgang: ein leerer
Scheineintrag entsteht nie.


7. NICHT BEHAUPTET
------------------

Dieses Format sichert technische Eigenschaften zu - Unveraenderlichkeit
geschriebener Bytes, nachrechenbare Hashketten, pruefbare Signaturen,
serverunabhaengige Verifikation. Daraus folgt ausdruecklich nichts Rechtliches:

NICHT BEHAUPTET: ein rechtlicher Beweiswert. Eine Hashkette belegt technische
  Unversehrtheit, sie ersetzt keine rechtliche Wuerdigung.
NICHT BEHAUPTET: allgemeine Gerichtsverwertbarkeit in irgendeiner
  Rechtsordnung.
NICHT BEHAUPTET: eine TR-ESOR-Zertifizierung oder die Konformitaet zu einer
  solchen.
NICHT BEHAUPTET: vollstaendige Metadatenblindheit. Objektzahlen, Groessen,
  Zeitpunkte und Beziehungen bleiben sichtbar; verschluesselt ist der Inhalt,
  nicht die Existenz.
