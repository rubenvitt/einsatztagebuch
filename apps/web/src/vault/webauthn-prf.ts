// Die EINE Stelle des Web-Buendels, an der `navigator.credentials` gerufen
// wird — und die EINZIGE, durch die ein Klartext-Schluesselbaustein ueberhaupt
// durch JavaScript laeuft.
//
// Sie enthaelt KEINE Sicherheitslogik (`web-reader-design.md` §9): sie leitet
// keinen Schluessel ab, vergleicht keinen Fingerprint, kodiert kein Chiffrat
// und entscheidet keine Weigerung. Jede Entscheidung faellt in geteiltem Rust;
// hier werden Bytes getragen und Status-DTOs zurueckgereicht.
//
// # Warum die Bruecke im WORKER liegt und diese Datei auf dem Hauptthread
//
// Der Enrollment-Zustand liegt in Rust in einem `thread_local!`, also muessen
// alle fuenf Aufrufe denselben Faden sehen; OPFS und das synchrone
// `XMLHttpRequest` des Endpunktports gibt es ausschliesslich in einem
// dedizierten Worker; und `navigator.credentials` gibt es ausschliesslich auf
// dem Hauptthread. Die Naht dazwischen ist die schmale, ausgeschriebene
// Nachrichtenform aus `../bridge/opfs-worker.ts` — ein ZWEITER Worker waere
// die falsche Antwort, weil zwei Worker dieselbe OPFS-Datei mit zwei
// `FileSystemSyncAccessHandle`s oeffneten und der zweite sie nicht bekaeme.
//
// # Die PRF-Ausgabe
//
// Sie wird in KEINER Variablen gehalten, die einen Namensraum ueberlebt, und
// NIEMALS geloggt: das Ergebnis der `prf`-Erweiterung geht unmittelbar als
// `Uint8Array` in die Nachricht an den Worker und wird danach nicht mehr
// angefasst. Rust loescht nach der Uebernahme in `SecretBytes<32>` beide
// Klartextkopien im linearen Speicher.
//
// # Was diese Datei ausdruecklich NICHT hinschreibt
//
// Kein PRF-Salz, keine Algorithmenliste, keine Schluessellaenge als Literal.
// Beides kommt als DATEN aus `enrollmentBegin` zurueck, also aus
// `VAULT_PRF_SALT_V1` in geteiltem Rust. Die Regel dahinter steht in
// `../bridge/no-hand-written-contracts.test.ts`; sie wird hier eingehalten und
// nicht umgangen — eine Datei, die keine Sicherheitsentscheidung trifft,
// braucht keinen ihrer Ausdruecke.

import type { EaOpfsRequest, EaOpfsResponse } from '../bridge/opfs-worker'

declare global {
  // `hints` steht in der WebAuthn-Level-3-Fassung der Optionen, in
  // `lib.dom.d.ts` (TypeScript 7.0.2) aber nur an der JSON-Form
  // (`PublicKeyCredentialCreationOptionsJSON`). Die Erweiterung deklariert
  // genau dieses eine Feld nach und erfindet keine weitere Flaeche.
  interface PublicKeyCredentialCreationOptions {
    hints?: string[]
  }
}

/**
 * Bytes, deren Puffer ein `ArrayBuffer` IST und kein `SharedArrayBuffer` sein
 * kann.
 *
 * `Uint8Array` allein ist in TypeScript 7 `Uint8Array<ArrayBufferLike>`, und
 * `BufferSource` — der Argumenttyp jeder WebAuthn-Option — laesst das nicht zu.
 * Der Alias steht deshalb ueberall dort, wo Bytes eine Zeremonie erreichen;
 * gegen `Uint8Array` bleibt er zuweisbar, die Nachrichtenform des Workers
 * bleibt also unberuehrt.
 */
export type EnrollmentBytes = Uint8Array<ArrayBuffer>

/**
 * Der Ruecklauf von `enrollmentBegin`.
 *
 * `prfSalt` und `registeredCredentialIds` reisen ueber die Bruecke als Hex und
 * kommen hier als Bytes an; die Umrechnung ist Transportform und keine
 * Entscheidung.
 */
export type EnrollmentBeginStatusV1 = {
  readonly handle: number
  readonly prfSalt: EnrollmentBytes
  readonly publicKeyAlgorithms: readonly number[]
  readonly registeredCredentialIds: readonly EnrollmentBytes[]
}

/**
 * Der Ruecklauf von `enrollmentRegisterAuthenticator`.
 *
 * `registeredCredentialIds` sind die Kennungen, die RUST bisher aufgenommen
 * hat, und sie sind das Argument der naechsten Zeremonie: sie gehen
 * unveraendert als `excludeCredentials` in `navigator.credentials.create`.
 * Sie stehen deshalb im DTO und nicht in einem Zaehler dieser Datei oder gar in
 * einem `useState` der Oberflaeche — dieselbe Regel wie bei `registered` und
 * `required` (§9): eine Liste, die hier entstuende, koennte leer sein, wo das
 * Enrollment in Rust zwei Eintraege haelt, und der Ausschluss fiele still aus.
 */
export type AuthenticatorCountStatusV1 = {
  readonly registered: number
  readonly required: number
  readonly registeredCredentialIds: readonly EnrollmentBytes[]
}

/** Der Ruecklauf von `enrollmentFingerprints` — beide Werte 64 Hexzeichen. */
export type EnrollmentFingerprintsStatusV1 = {
  readonly keyFingerprint: string
  readonly bundleFingerprint: string
}

/**
 * Der Ruecklauf von `enrollmentConfirmFingerprints`.
 *
 * Eine ABWEICHUNG ist kein Ausnahmefall, sondern ein Ergebnis — sie kommt als
 * `confirmed: false` samt stabilem Code zurueck, damit die Oberflaeche sie
 * anzeigen kann, ohne einen Fehlerpfad zu bauen.
 *
 * `code?: string | undefined` und nicht `code?: string`: `tsconfig.json` setzt
 * `exactOptionalPropertyTypes`, unter dem ein ausgeschriebenes
 * `code: … ? undefined : '…'` an einem `code?: string` mit TS2322 scheitert.
 * Dieselbe Schreibweise traegt `EaOpfsResponse` aus demselben Grund.
 */
export type FingerprintConfirmationStatusV1 = {
  readonly confirmed: boolean
  readonly code?: string | undefined
}

/** Der Ruecklauf von `enrollmentFinish`. */
export type EnrollmentFinishStatusV1 = {
  readonly finished: boolean
}

/**
 * Die FORM der Bruecke: genau die fuenf Ausfuhren aus
 * `crates/ea-reader-wasm/src/webauthn.rs` samt ihren Status-DTOs.
 *
 * Der Typ steht hier und nicht in einer Testdatei, weil er die Form der
 * Bruecke ist und keine Testhilfe. `EnrollmentPage` nimmt ihn als Eigenschaft
 * `bridge`, deren Vorgabewert die echte Umsetzung aus dieser Datei ist.
 *
 * Die WebAuthn-Zeremonien liegen INNERHALB dieser Umsetzung und nicht in der
 * Oberflaeche: die Seite reicht keine Bytes durch, die sie nicht selbst
 * anzeigen wuerde, und sieht damit weder Attestation noch PRF-Ausgabe.
 */
export type EnrollmentBridge = {
  readonly begin: () => Promise<EnrollmentBeginStatusV1>
  readonly registerAuthenticator: (request: {
    readonly handle: number
  }) => Promise<AuthenticatorCountStatusV1>
  readonly fingerprints: (request: {
    readonly handle: number
  }) => Promise<EnrollmentFingerprintsStatusV1>
  readonly confirmFingerprints: (request: {
    readonly handle: number
    readonly expectedKeyFingerprint: string
    readonly expectedBundleFingerprint: string
  }) => Promise<FingerprintConfirmationStatusV1>
  readonly finish: (request: { readonly handle: number }) => Promise<EnrollmentFinishStatusV1>
}

/**
 * Die Werte, die `enrollmentBegin` und `enrollmentFinish` von aussen bekommen.
 *
 * Sie werden von aussen GESTELLT und hier weder erfunden noch erraten:
 * `organizationId`, `subjectId`, `pinnedAnchor` und `bundleFingerprint`
 * gehoeren zur Buendelfreigabe und zum gepinnten Trust-Stand, `authority` nennt
 * den Sync-Server. Ohne sie faellt der erste Aufruf LAUT, statt still mit
 * ausgedachten Bytes weiterzulaufen — der gepinnte Anker gilt gerade deshalb,
 * weil `decode_trust_anchor` in Rust seinen Bootstrap-Hash neu rechnet, und ein
 * hier zusammengesetzter Anker haette nichts, wogegen er sich rechnen liesse.
 *
 * ZWEI Wege stellen sie: [`provideEnrollmentContext`] fuer einen Aufrufer, der
 * die Bytes schon hat, und der globale Name [`RELEASE_CONTEXT_GLOBAL`] fuer
 * eine Freigabe, die ihren Kontext vor dem Buendel ablegt. BENANNTE GRENZE: das
 * dauerhafte Zuhause dieser Werte ist die Freigabe selbst, und die legt der
 * Task „Web-Bundle: getrennter Origin, Service Worker, gepinnte
 * `webBundleRelease` und das Alter des Trust-Standes" an — dieselbe Herkunft,
 * dieselbe Konfigurationsquelle, ein Ort. Bis dahin stellt sie, wer das Buendel
 * ausliefert; im Browserzeugen dieser Aufgabe ist das der Zeuge selbst, genau
 * wie er auch den Server stellt.
 */
export type EnrollmentContextV1 = {
  readonly organizationId: EnrollmentBytes
  readonly subjectId: EnrollmentBytes
  readonly pinnedAnchor: EnrollmentBytes
  readonly bundleFingerprint: EnrollmentBytes
  readonly authority: string
}

/**
 * Dieselben fuenf Werte in ihrer TRANSPORTFORM: vier Hexzeichenketten und ein
 * Name.
 *
 * Sie ist die Form, in der eine FREIGABE ihren Kontext stellt — eine
 * Zeichenkette ueberlebt den Weg durch ein Startskript, ein `Uint8Array` nicht.
 * Hexadezimal, weil das die Schreibweise dieser Bruecke ist: `enrollmentBegin`
 * gibt sein Salz genauso heraus, und `bytesFromHex` ist die Umrechnung, die
 * diese Datei dafuer ohnehin schon fuehrt.
 */
export type EnrollmentReleaseContextV1 = {
  readonly organizationId: string
  readonly subjectId: string
  readonly pinnedAnchor: string
  readonly bundleFingerprint: string
  readonly authority: string
}

/**
 * Der Name, unter dem eine Freigabe ihren Kontext im globalen Objekt ablegt.
 *
 * Ein globaler Name und kein Bauzeitwert, und das ist eine ENTSCHEIDUNG mit
 * einer Begruendung: ein ueber `import.meta.env` eingebackener Kontext laege in
 * JEDEM gebauten `dist/`, also auch dort, wo ihn niemand gestellt hat. So
 * traegt das Buendel gar keinen — es bekommt seinen Kontext von der Freigabe,
 * die es ausliefert, und ohne sie faellt der erste Aufruf LAUT.
 */
const RELEASE_CONTEXT_GLOBAL = '__eaReaderEnrollmentContext'

let providedContext: EnrollmentContextV1 | undefined

/**
 * Stellt die fuenf Werte bereit, die diese Datei nicht selbst kennt.
 *
 * Der zweite Weg dorthin ist [`RELEASE_CONTEXT_GLOBAL`]; dieser hier ist der
 * programmatische, den ein Aufrufer nimmt, der die Bytes schon hat.
 */
export function provideEnrollmentContext(context: EnrollmentContextV1): void {
  providedContext = context
}

/** Ist `value` eine Hexzeichenkette gerader Laenge? */
function isHex(value: unknown): value is string {
  return typeof value === 'string' && value.length % 2 === 0 && /^[0-9a-fA-F]*$/.test(value)
}

/**
 * Der von der Freigabe gestellte Kontext, oder `undefined`.
 *
 * Die Probe ist VOLLSTAENDIG und nicht hoeflich: ein halb gestellter Kontext
 * ist kein Kontext, und ein stillschweigend ergaenztes Feld waere ein
 * ausgedachter Wert an einer Stelle, an der `decode_trust_anchor` und
 * `OrganizationId::try_from` die Wahrheit sagen sollen. Was hier durchkommt,
 * hat die richtige FORM; ob es der richtige Anker ist, entscheidet Rust.
 */
function releaseContext(): EnrollmentContextV1 | undefined {
  const staged: unknown = (globalThis as Record<string, unknown>)[RELEASE_CONTEXT_GLOBAL]
  if (staged === null || typeof staged !== 'object') {
    return undefined
  }
  const candidate = staged as Partial<EnrollmentReleaseContextV1>
  if (
    !isHex(candidate.organizationId) ||
    !isHex(candidate.subjectId) ||
    !isHex(candidate.pinnedAnchor) ||
    !isHex(candidate.bundleFingerprint) ||
    typeof candidate.authority !== 'string' ||
    candidate.authority.length === 0
  ) {
    throw new Error(
      `Der unter \`${RELEASE_CONTEXT_GLOBAL}\` gestellte Enrollment-Kontext hat nicht die erwartete Form.`,
    )
  }
  return {
    organizationId: bytesFromHex(candidate.organizationId),
    subjectId: bytesFromHex(candidate.subjectId),
    pinnedAnchor: bytesFromHex(candidate.pinnedAnchor),
    bundleFingerprint: bytesFromHex(candidate.bundleFingerprint),
    authority: candidate.authority,
  }
}

function enrollmentContext(): EnrollmentContextV1 {
  providedContext ??= releaseContext()
  if (providedContext === undefined) {
    throw new Error(
      'Fuer dieses Buendel ist kein Enrollment-Kontext gestellt: Organisation, Subjekt, gepinnter Anker, Buendel-Fingerprint und Autoritaet fehlen.',
    )
  }
  return providedContext
}

/**
 * Der Schluessel, unter dem `finish` den versiegelten Tresor lokal ablegt.
 *
 * Zeichengleich zu `READER_VAULT_BLOB_KEY_V1` in
 * `crates/ea-reader/src/enrollment.rs`. Er steht hier ZWEITMALS, und das ist
 * eine benannte Schwaeche: keine der fuenf Ausfuhren gibt ihn heraus, und
 * `blobGet` braucht ihn. Er ist ein Ablagepfad und kein Sicherheitswert — wer
 * ihn falsch schreibt, bekommt einen fehlenden Blob und keine stille
 * Fehlentsperrung.
 */
const READER_VAULT_BLOB_KEY = 'vault/reader-vault-v1'

/** Der Name, unter dem der Browser die Passkeys dieses Readers fuehrt. */
const READER_RELYING_PARTY_NAME = 'Einsatzarchiv'

/** Die Bezeichnung des Kontos in der Passkey-Auswahl des Browsers. */
const READER_ACCOUNT_LABEL = 'Einsatzarchiv-Reader'

type PendingCall = {
  readonly settle: (response: EaOpfsResponse) => void
  readonly fail: (reason: unknown) => void
}

const pending = new Map<number, PendingCall>()
let nextRequestId = 0
let workerHandle: Worker | undefined

/**
 * Der Worker, LAZY erzeugt.
 *
 * Nicht auf Modulebene: ein `new Worker(...)` beim Import zoege den Worker in
 * jeden Lauf, der diese Datei nur wegen ihrer Typen laedt — und in einer
 * DOM-Attrappe gibt es ihn nicht.
 */
function worker(): Worker {
  if (workerHandle === undefined) {
    const created = new Worker(new URL('../bridge/opfs-worker.ts', import.meta.url), {
      type: 'module',
    })
    created.addEventListener('message', (event: MessageEvent<EaOpfsResponse>) => {
      const response = event.data
      const waiting = pending.get(response.id)
      pending.delete(response.id)
      waiting?.settle(response)
    })
    created.addEventListener('error', (event: ErrorEvent) => {
      for (const [id, waiting] of pending) {
        pending.delete(id)
        waiting.fail(new Error(event.message))
      }
    })
    workerHandle = created
  }
  return workerHandle
}

/** Eine Nachricht ohne ihre Kennung — die vergibt der Aufruf. */
type WithoutId<T> = T extends unknown ? Omit<T, 'id'> : never

/**
 * Eine Nachricht an den EINEN Worker dieses Buendels, von aussen gestellt.
 *
 * Der Typ ist verteilend (`T extends unknown ? …`) und nicht `Omit` ueber der
 * ganzen Vereinigung: `Omit` verschmilzt die Arme zu einem Gemeinsamen, und
 * `kind` waere danach keine Weiche mehr.
 */
export type ReaderWorkerMessage = WithoutId<EaOpfsRequest>

async function call(request: WithoutId<EaOpfsRequest>): Promise<EaOpfsResponse> {
  nextRequestId += 1
  const id = nextRequestId
  return new Promise<EaOpfsResponse>((settle, fail) => {
    pending.set(id, { settle, fail })
    worker().postMessage({ ...request, id })
  })
}

/**
 * Derselbe Aufruf, fuer Module ausserhalb des Tresors.
 *
 * Er steht HIER und nicht in einer eigenen Transportdatei, weil der Worker
 * selbst hier liegt — und es darf GENAU EINEN geben: die entsperrten
 * Tresorsitzungen und die angefangenen Verzeichnisquellen liegen in Rust in
 * `thread_local!`-Tabellen, ein zweiter Worker saehe keine von beiden. Wer
 * eine zweite Instanz erzeugte, bekaeme fuer jede Sitzungskennung
 * `EA-READER-SESSION-UNKNOWN` (und fuer jede Ordnerkennung
 * `EA-READER-FILE-MODE-BRIDGE-ARGUMENT`) und wuesste nicht, warum.
 */
export async function callReaderWorker(request: ReaderWorkerMessage): Promise<EaOpfsResponse> {
  return call(request)
}

/**
 * Ein Aufruf, dessen Antwort ein Status-DTO traegt.
 *
 * Ein Fehlschlag kommt als STABILER CODE zurueck und wird als solcher
 * geworfen; ein Wirtstext wird nie erfunden.
 */
async function callForStatus<T>(request: WithoutId<EaOpfsRequest>): Promise<T> {
  const response = await call(request)
  if (!response.ok) {
    throw new Error(response.code)
  }
  if (response.status === undefined) {
    throw new Error('Der Worker hat auf eine Enrollment-Nachricht keinen Status geliefert.')
  }
  return JSON.parse(response.status) as T
}

/**
 * Hex nach Bytes — die Transportform der Bruecke, keine Entscheidung.
 *
 * Exportiert, weil der Einzelexport den Eintragshash aus dem
 * `ReaderSessionView` in derselben Schreibweise zurueckreicht; eine zweite
 * Umrechnung in `features/session` waere dieselbe Zeile ein zweites Mal.
 */
export function bytesFromHex(value: string): EnrollmentBytes {
  const bytes = new Uint8Array(value.length / 2)
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}

/**
 * Eine `BufferSource` als Bytes, OHNE Kopie.
 *
 * Ohne Kopie und nicht aus Sparsamkeit: durch diese Funktion laeuft die
 * PRF-Ausgabe, und jede Kopie waere eine zweite Klartextstelle, die niemand
 * mehr einsammelt. Die Zusicherung `as ArrayBuffer` ist eng: `ArrayBufferView`
 * traegt formal ein `ArrayBufferLike`, und ein `SharedArrayBuffer` entsteht in
 * einem Dokument ohne Cross-Origin-Isolation gar nicht — WebAuthn liefert
 * ohnehin immer ein `ArrayBuffer`.
 */
function bytesOf(source: BufferSource): EnrollmentBytes {
  if (source instanceof ArrayBuffer) {
    return new Uint8Array(source)
  }
  return new Uint8Array(source.buffer as ArrayBuffer, source.byteOffset, source.byteLength)
}

function assertPublicKeyCredential(credential: Credential | null): PublicKeyCredential {
  if (credential === null || !(credential instanceof PublicKeyCredential)) {
    throw new Error('Der Browser hat die Zeremonie ohne Passkey beendet.')
  }
  return credential
}

/**
 * Die PRF-Auswertung ueber `credentials.get`.
 *
 * NICHT ueber `credentials.create`: `hmac-secret` bei der Erzeugung ist als
 * `hmac-secret-mc` ein eigenes, optionales Authenticator-Merkmal, und der Weg
 * ueber `get` ist derselbe, den §6.4 fuer jeden spaeteren Zugriff ohnehin
 * beschreibt.
 *
 * Liefert der Authenticator keine Ausgabe der erwarteten Laenge, WIRFT diese
 * Funktion. Ein Rueckfall auf einen erzeugten Puffer ist ausgeschlossen: er
 * faerbte jeden Lauf gruen, ohne die Kette gemessen zu haben. Die erwartete
 * Laenge kommt aus dem Salz der Bruecke und steht hier nicht als Zahl.
 */
async function evaluatePrf(
  salt: EnrollmentBytes,
  allowCredentials: PublicKeyCredentialDescriptor[],
): Promise<{ readonly credentialId: EnrollmentBytes; readonly prfOutput: EnrollmentBytes }> {
  const assertion = assertPublicKeyCredential(
    await navigator.credentials.get({
      publicKey: {
        challenge: salt,
        allowCredentials,
        userVerification: 'required',
        extensions: { prf: { eval: { first: salt } } },
      },
    }),
  )
  const first = assertion.getClientExtensionResults().prf?.results?.first
  if (first === undefined) {
    throw new Error('Der Authenticator hat keine PRF-Ausgabe geliefert.')
  }
  const prfOutput = bytesOf(first)
  if (prfOutput.byteLength !== salt.byteLength) {
    throw new Error('Die PRF-Ausgabe des Authenticators hat nicht die erwartete Laenge.')
  }
  return { credentialId: bytesOf(assertion.rawId), prfOutput }
}

/**
 * Die Erzeugungszeremonie.
 *
 * `residentKey: 'required'` und `userVerification: 'required'`, weil §6.4.1 die
 * Aufloesung ueber ein AUFFINDBARES Credential voraussetzt. `hints:
 * ['client-device']` sorgt dafuer, dass der QR-Flow gar nicht erst angeboten
 * wird; die harte Abweisung bleibt trotzdem in Rust, weil eine Auswahl in der
 * Oberflaeche kein Gate ist.
 *
 * `pubKeyCredParams` traegt AUSSCHLIESSLICH, was die Bruecke herausgibt — heute
 * genau EINEN Algorithmus. `WebauthnCredentialRegistrationV1` weist auf Stufe 3
 * jeden oeffentlichen Schluessel ab, den `CanonicalPublicCoseKey::
 * from_deterministic_cbor` nicht als den einen zugelassenen Arm zurueckgibt;
 * ein stiller Rueckfall auf einen zweiten Algorithmus liefe deshalb erst in
 * `EA-SYNC-PROTOCOL-FRAME-SHAPE` auf, an einer Stelle, an der niemand die
 * Ursache sucht. Die Liste steht darum NICHT hier: sie ist ein Datum aus
 * geteiltem Rust, und der Name des Verfahrens kommt in dieser Datei bewusst
 * nicht vor — `no-hand-written-contracts.test.ts` haelt genau das fern.
 *
 * `excludeCredentials` traegt die Kennungen, die RUST bisher aufgenommen hat,
 * und diese Liste ist der GRUND, aus dem §6.3 hier ueberhaupt eingehalten
 * werden kann. Ohne sie tragen BEIDE Zeremonien dasselbe Paar aus `rp.id` und
 * `user.id`, und ein `authenticatorMakeCredential` mit `rk=true` auf ein
 * bereits vorhandenes Paar ERSETZT das auffindbare Credential — auf genau dem
 * Geraet, auf das `hints: ['client-device']` steuert. GEMESSEN an Chromiums
 * virtuellem Authenticator (ein einziger, `internal`): ohne die Liste legt die
 * zweite Zeremonie klaglos ein Credential mit NEUER Kennung an, und danach
 * liegt auf dem Geraet GENAU EINES; mit der Liste faellt sie mit
 * `InvalidStateError`, und es bleibt bei dem ersten. Rust kann das nicht
 * nachholen: seine Doppelungspruefung de-dupliziert auf der `credentialId`, und
 * die ist neu.
 *
 * Die Liste wird hier NICHT gefuehrt und NICHT ergaenzt — sie kommt aus
 * `enrollmentBegin` und `enrollmentRegisterAuthenticator`, also aus dem
 * Enrollment-Zustand in geteiltem Rust (§9). Eine hier gefuehrte Liste waere
 * genau die Sicherheitsentscheidung, die diese Datei nicht treffen darf.
 *
 * Die Deskriptoren tragen KEIN `transports`, und das ist eine Entscheidung mit
 * Begruendung: ohne das Feld beruecksichtigt der Client jeden Transport, der
 * Ausschluss ist also der WEITERE von beiden. Rust gibt daneben gar kein
 * Transportprofil heraus — `AuthenticatorRecordV1` laesst es bei der Aufnahme
 * bewusst fallen —, ein hier gesetzter Wert waere also geraten. Gemessen weist
 * Chromium in beiden Schreibweisen ab. Dieselbe Deskriptorform steht schon in
 * [`evaluatePrf`].
 *
 * BEFUND zur `challenge`, hier sichtbar statt still geglaettet: sie kommt in
 * diesem Stand NICHT vom Server. `POST /v1/auth/challenges` nimmt einen
 * CBOR-Koerper (`ChallengeRequestV1`), und keine der fuenf Ausfuhren baut ihn;
 * ihn in TypeScript zu bauen waere genau der Nachbau formatkritischer Logik,
 * den §9 verbietet. Erzeugt wird sie hier ebenfalls nicht — ein lokal
 * gezogener Puffer waere die Konstante, die `no-hand-written-contracts.test.ts`
 * fernhaelt. Bis der Endpunkt eine Bruecke hat, traegt die Zeremonie die
 * Bytes, die `enrollmentBegin` herausgibt: sie sind oeffentlich, und geprueft
 * werden sie von NICHTS — weder vom Browser, noch von `ea-reader`, noch vom
 * Server, dem sie nie vorgelegt werden.
 */
async function createAuthenticator(
  context: EnrollmentContextV1,
  begin: EnrollmentBeginStatusV1,
  registeredCredentialIds: readonly EnrollmentBytes[],
): Promise<{
  readonly attestationObject: EnrollmentBytes
  readonly transport: string
  readonly credentialId: EnrollmentBytes
}> {
  const pubKeyCredParams: PublicKeyCredentialParameters[] = begin.publicKeyAlgorithms.map(
    (alg) => ({ type: 'public-key', alg }),
  )
  const excludeCredentials: PublicKeyCredentialDescriptor[] = registeredCredentialIds.map((id) => ({
    type: 'public-key',
    id,
  }))
  const created = await navigator.credentials
    .create({
      publicKey: {
        challenge: begin.prfSalt,
        rp: { name: READER_RELYING_PARTY_NAME },
        user: {
          id: context.subjectId,
          name: READER_ACCOUNT_LABEL,
          displayName: READER_ACCOUNT_LABEL,
        },
        pubKeyCredParams,
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        hints: ['client-device'],
        excludeCredentials,
        extensions: { prf: { eval: { first: begin.prfSalt } } },
      },
    })
    .catch((reason: unknown) => {
      // Die EINE Abweisung, die dieser Ablauf erwartet und benennen kann.
      // `InvalidStateError` heisst genau eines: EIN Authenticator, der bereits
      // einen Passkey dieses Readers haelt, hat geantwortet.
      //
      // Der Satz sagt deshalb DAS und nicht „nimm ein anderes Geraet". Beides
      // waere in der einen Lage richtig und in der anderen falsch:
      // `CTAP2_ERR_CREDENTIAL_EXCLUDED` ist im WebAuthn-Algorithmus TERMINAL —
      // antwortet ein ausgeschlossener Authenticator, bricht der Client die
      // ganze Zeremonie ab, statt die uebrigen weiterzufragen. Wer also
      // durchaus ein ZWEITES, noch unbenutztes Geraet vorgehalten hat, bekommt
      // dieselbe Abweisung, sobald ein dritter, ausgeschlossener Authenticator
      // schneller war; die Aufforderung „nimm ein anderes Geraet" waere dann
      // eine falsche Anweisung. Genannt wird darum die Ursache samt der
      // Bedingung, die fuer den naechsten Versuch gelten muss.
      //
      // Uebersetzt wird eine Rueckmeldung, entschieden wird nichts: die
      // Zeremonie hat der BROWSER abgewiesen, und ohne `excludeCredentials`
      // gaebe es diesen Zweig gar nicht.
      if (reason instanceof DOMException && reason.name === 'InvalidStateError') {
        throw new Error(
          'Die Zeremonie wurde von einem Authenticator beantwortet, der bereits einen Passkey dieses Readers traegt, und damit abgebrochen. Den zweiten Authenticator muss ein Geraet beantworten, das noch keinen Passkey dieses Readers haelt.',
        )
      }
      throw reason
    })
  const credential = assertPublicKeyCredential(created)
  const response = credential.response
  if (!(response instanceof AuthenticatorAttestationResponse)) {
    throw new Error('Der Browser hat auf die Erzeugung keine Attestation geliefert.')
  }
  // Der ERSTE gemeldete Transport, und keiner ersatzweise: ein unbekannter
  // Name ist in Rust bewusst weder `ClientDevice` noch `CrossDevice`, und eine
  // leere Meldung hier auf `internal` abzubilden hiesse, einen Entsperrpfad
  // zuzulassen, ueber den niemand entschieden hat.
  const transport = response.getTransports()[0] ?? ''
  return {
    attestationObject: bytesOf(response.attestationObject),
    transport,
    credentialId: bytesOf(credential.rawId),
  }
}

/**
 * Der zuletzt von `enrollmentBegin` herausgegebene Stand.
 *
 * Er liegt hier, weil die Zeremonien Salz und Algorithmenliste brauchen und
 * die Oberflaeche beides nicht anfassen soll, und weil
 * [`unlockReaderVaultSession`] dasselbe Salz fuer die zweite PRF-Auswertung
 * braucht — keine Ausfuhr gibt es
 * ein zweites Mal heraus. Nach einem Neuladen der Seite ist er fort; der Weg
 * dafuer ist `recover_and_unlock_vault`, und der ist in diesem Stand nicht
 * verdrahtet.
 */
let lastBegin: EnrollmentBeginStatusV1 | undefined

function beganEnrollment(): EnrollmentBeginStatusV1 {
  if (lastBegin === undefined) {
    throw new Error('Dieses Enrollment ist nicht begonnen worden.')
  }
  return lastBegin
}

/**
 * Der zuletzt von RUST GEMELDETE Satz aufgenommener `credentialId`s.
 *
 * Ein SPIEGEL und keine eigene Buchfuehrung, und der Unterschied ist die ganze
 * Zusage: geschrieben wird er ausschliesslich aus einer Brueckenantwort — aus
 * `begin` und aus `registerAuthenticator`, und das sind zusammen alle Stellen,
 * an denen sich der Satz in Rust ueberhaupt aendert. Diese Datei fuegt nichts
 * hinzu, entfernt nichts und leitet nichts ab; insbesondere traegt sie NICHT
 * die Kennung nach, die eine gerade gelaufene Zeremonie geliefert hat. Waere
 * das anders, gaebe es zwei Quellen derselben Wahrheit, und die Oberflaeche
 * entschiede mit ueber einen Ausschluss (§9).
 *
 * Er liegt neben [`lastBegin`] und aus demselben Grund: die Zeremonie braucht
 * ihn, die Oberflaeche soll ihn nicht anfassen.
 */
let registeredCredentialIds: readonly EnrollmentBytes[] = []

/** Die echte Bruecke: fuenf Aufrufe, jeder eine Nachricht an den Worker. */
export const enrollmentBridge: EnrollmentBridge = {
  begin: async () => {
    const context = enrollmentContext()
    const status = await callForStatus<{
      handle: number
      prfSalt: string
      publicKeyAlgorithms: number[]
      registeredCredentialIds: string[]
    }>({
      kind: 'enrollment-begin',
      organizationId: context.organizationId,
      subjectId: context.subjectId,
      pinnedAnchor: context.pinnedAnchor,
      bundleFingerprint: context.bundleFingerprint,
    })
    const began: EnrollmentBeginStatusV1 = {
      handle: status.handle,
      prfSalt: bytesFromHex(status.prfSalt),
      publicKeyAlgorithms: status.publicKeyAlgorithms,
      registeredCredentialIds: status.registeredCredentialIds.map(bytesFromHex),
    }
    lastBegin = began
    registeredCredentialIds = began.registeredCredentialIds
    return began
  },

  registerAuthenticator: async ({ handle }) => {
    const context = enrollmentContext()
    const begin = beganEnrollment()
    const created = await createAuthenticator(context, begin, registeredCredentialIds)
    const { prfOutput } = await evaluatePrf(begin.prfSalt, [
      { type: 'public-key', id: created.credentialId },
    ])
    const status = await callForStatus<{
      registered: number
      required: number
      registeredCredentialIds: string[]
    }>({
      kind: 'enrollment-register-authenticator',
      handle,
      attestationObject: created.attestationObject,
      transport: created.transport,
      prfOutput,
    })
    const counted: AuthenticatorCountStatusV1 = {
      registered: status.registered,
      required: status.required,
      registeredCredentialIds: status.registeredCredentialIds.map(bytesFromHex),
    }
    // Der Spiegel wird NACH der Aufnahme gestellt und nur aus der Antwort:
    // haette Rust die Kennung abgewiesen — Laenge, Transportprofil, COSE-Karte,
    // Doppelung —, waere `callForStatus` mit dem stabilen Code geworfen und der
    // Satz stuende unveraendert. Ein hier vorab ergaenzter Eintrag schloesse
    // dagegen einen Authenticator aus, den dieses Enrollment gar nicht haelt.
    registeredCredentialIds = counted.registeredCredentialIds
    return counted
  },

  fingerprints: async ({ handle }) =>
    callForStatus<EnrollmentFingerprintsStatusV1>({ kind: 'enrollment-fingerprints', handle }),

  confirmFingerprints: async ({ handle, expectedKeyFingerprint, expectedBundleFingerprint }) =>
    callForStatus<FingerprintConfirmationStatusV1>({
      kind: 'enrollment-confirm-fingerprints',
      handle,
      expectedKeyFingerprint,
      expectedBundleFingerprint,
    }),

  finish: async ({ handle }) =>
    callForStatus<EnrollmentFinishStatusV1>({
      kind: 'enrollment-finish',
      handle,
      authority: enrollmentContext().authority,
      // Die Uhr tritt als WERT ein: `wasm32-unknown-unknown` hat keinen Wirt
      // fuer `SystemTime::now()`. `BigInt`, weil `wasm_bindgen` `i64` so
      // abbildet.
      createdUnixSeconds: BigInt(Math.floor(Date.now() / 1000)),
    }),
}


/**
 * Eine FRISCHE PRF-Auswertung fuer eine Bestaetigung — Entsperren oder
 * Einzelexport.
 *
 * Derselbe Aufruf wie beim Entsperren, ausdruecklich KEIN zwischengehaltener
 * Wert: `web-reader-design.md` §6.5 verlangt nach jeder Sperre eine erneute
 * Authenticator-Bestaetigung, und §8.2 eine je Export. Eine PRF-Ausgabe, die
 * diese Datei fuer den naechsten Aufruf aufhoebe, waere genau die
 * Klartextstelle, die der Kopf dieser Datei ausschliesst. Rust belegt mit der
 * Ausgabe die Bestaetigung gegen den versiegelten Tresor
 * (`ReaderAuthenticatorConfirmation::prove`) und loescht sie danach.
 *
 * BENANNTE GRENZE, dieselbe wie bei [`unlockReaderVaultSession`]: das Salz
 * kommt aus [`beganEnrollment`], also aus einem Enrollment DIESES Seitenlaufs.
 */
export async function freshPrfForConfirmation(): Promise<{
  readonly credentialId: Uint8Array
  readonly prfOutput: Uint8Array
}> {
  return evaluatePrf(beganEnrollment().prfSalt, [])
}

/**
 * Der versiegelte Tresor, wie er lokal unter [`READER_VAULT_BLOB_KEY`] liegt.
 *
 * Er ist Chiffrat samt Envelopes und kein Klartext — deshalb darf er ueber
 * den Hauptthread reisen. Gebraucht wird er von JEDEM Aufruf, der eine
 * Bestaetigung belegt: `readerVaultUnlock` und `readerExportOne` nehmen ihn
 * beide als Argument, weil die Bruecke keinen Tresor haelt, nur Sitzungen.
 */
export async function readSealedReaderVault(): Promise<Uint8Array> {
  const stored = await call({ kind: 'get', key: READER_VAULT_BLOB_KEY })
  if (!stored.ok) {
    throw new Error(stored.code)
  }
  if (stored.bytes === undefined) {
    throw new Error('Unter dem Tresorschluessel liegt lokal nichts.')
  }
  return stored.bytes
}

/**
 * Das Entsperren: derselbe Authenticator ein zweites Mal, und die
 * SITZUNGSKENNUNG als Ergebnis.
 *
 * Keine sechste Ausfuhr aus `webauthn.rs`, sondern der Weg, den die Crate
 * schon hat — eine frische PRF-Auswertung ueber `credentials.get`, der
 * versiegelte Tresor aus OPFS und `readerVaultUnlock` aus `vault_bridge`.
 * Die Kennung wird gebraucht, sobald ein Aufrufer nach dem Entsperren noch
 * etwas mit dem Tresor tut — der Datei-Modus etwa, dessen Brueckenausfuhren
 * alle einen entsperrten Tresor verlangen. Sie ist ein `u32` ohne Bedeutung
 * ausserhalb der Bruecke; sie ist KEIN Schluesselmaterial und ihre Herausgabe
 * ist genau die, die `web-reader-design.md` §9 vorsieht.
 *
 * GEHALTEN wird sie NICHT hier, sondern in
 * `../features/session/reader-session.ts`, dem einen Halter der Kennung; wer
 * eine Sitzung will, geht dorthin und ruft diese Funktion nicht selbst — eine
 * hier eroeffnete und fallengelassene Kennung waere eine entsperrte Sitzung,
 * an die niemand meldet.
 *
 * `nowMs` ist die Uhr der Seite und tritt als WERT ein: Rust liest keine Uhr
 * (`wasm32-unknown-unknown` hat keinen Wirt dafuer), und die Sitzung rechnet
 * ihre Fristen von hier an gegen genau diesen Wert. Der Aufrufer liest sie,
 * damit ein Zeuge mit gefaelschter Seitenuhr dieselbe Zahl sieht wie die
 * Sitzung.
 *
 * BENANNTE GRENZE, und sie gehoert nicht diesem Modus: der Weg fuehrt ueber
 * [`beganEnrollment`], also ueber ein Enrollment, das in DIESEM Seitenlauf
 * begonnen wurde. Nach einem Neuladen der Seite ist das Salz fort, und dieser
 * Aufruf faellt laut. Der Weg dafuer ist `recover_and_unlock_vault` in
 * `ea-reader`, und der ist in diesem Stand an keine Ausfuhr verdrahtet.
 */
export async function unlockReaderVaultSession(nowMs: number): Promise<number> {
  const { credentialId, prfOutput } = await freshPrfForConfirmation()
  const sealed = await readSealedReaderVault()
  const response = await call({
    kind: 'vault-unlock',
    sealed,
    credentialId,
    prfOutput,
    nowMs,
  })
  if (!response.ok) {
    throw new Error(response.code)
  }
  if (response.status === undefined) {
    throw new Error('Der Worker hat auf die Entsperrung keine Sitzungskennung geliefert.')
  }
  return Number(response.status)
}
