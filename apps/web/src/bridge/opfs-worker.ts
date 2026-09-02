// Der Einstieg des DEDIZIERTEN Workers.
//
// Er enthaelt KEINE Entscheidung, nur Zustellung: er laedt das wasm-Modul und
// reicht jede Nachricht an die Bruecke weiter. Der Grund, warum es diese Datei
// ueberhaupt gibt, liegt in Rust: `FileSystemSyncAccessHandle` existiert auf
// dem Hauptthread nicht, also lebt `OpfsBlobStore` nur hier. Waere hier eine
// Fallunterscheidung ueber Bytes, gaebe es eine zweite Stelle, an der ueber
// Klartext entschieden wird — und `web-reader-design.md` §9 laesst
// Kryptographie ausschliesslich in geteiltem Rust zu.

import init, {
  blobGet,
  blobPut,
  enrollmentBegin,
  enrollmentConfirmFingerprints,
  enrollmentFingerprints,
  enrollmentFinish,
  enrollmentRegisterAuthenticator,
  fileModeBeginDirectory,
  fileModeBundleExtension,
  fileModeDirectoryUnavailable,
  fileModeOpenBundle,
  fileModeOpenDirectory,
  fileModePushBlob,
  readerVaultUnlock,
} from './pkg/ea_reader_wasm.js'

/**
 * Die Nachrichten, die dieser Worker kennt.
 *
 * Die drei ersten sind der Bytespeicher. Die fuenf Enrollment-Nachrichten
 * darunter stehen HIER und nicht in einem zweiten Worker: der
 * Enrollment-Zustand liegt in Rust in einem `thread_local!`, alle fuenf
 * Aufrufe muessen also denselben Faden sehen, und zwei Worker oeffneten
 * dieselbe OPFS-Datei mit zwei `FileSystemSyncAccessHandle`s — der zweite
 * bekaeme sie gar nicht.
 *
 * `vault-unlock` ist die einzige Nachricht, die WEDER Speicher NOCH Enrollment
 * ist. Sie traegt die lebende Paritaetsprobe der Oberflaeche: sie oeffnet
 * einen bereits versiegelten Tresor mit einer frisch gezogenen PRF-Ausgabe
 * ueber `readerVaultUnlock` aus `crate::vault_bridge` — eine Ausfuhr, die
 * diese Bruecke laengst fuehrt. Sie ist deshalb KEINE sechste
 * Enrollment-Ausfuhr; sie liegt nur, wie alles wasm-Gebundene, im Worker.
 */
export type EaOpfsRequest =
  | { readonly id: number; readonly kind: 'put'; readonly key: string; readonly bytes: Uint8Array }
  | { readonly id: number; readonly kind: 'get'; readonly key: string }
  | { readonly id: number; readonly kind: 'delete'; readonly key: string }
  | {
      readonly id: number
      readonly kind: 'enrollment-begin'
      readonly organizationId: Uint8Array
      readonly subjectId: Uint8Array
      readonly pinnedAnchor: Uint8Array
      readonly bundleFingerprint: Uint8Array
    }
  | {
      readonly id: number
      readonly kind: 'enrollment-register-authenticator'
      readonly handle: number
      readonly attestationObject: Uint8Array
      readonly transport: string
      readonly prfOutput: Uint8Array
    }
  | { readonly id: number; readonly kind: 'enrollment-fingerprints'; readonly handle: number }
  | {
      readonly id: number
      readonly kind: 'enrollment-confirm-fingerprints'
      readonly handle: number
      readonly expectedKeyFingerprint: string
      readonly expectedBundleFingerprint: string
    }
  | {
      readonly id: number
      readonly kind: 'enrollment-finish'
      readonly handle: number
      readonly authority: string
      readonly createdUnixSeconds: bigint
    }
  | {
      readonly id: number
      readonly kind: 'vault-unlock'
      readonly sealed: Uint8Array
      readonly credentialId: Uint8Array
      readonly prfOutput: Uint8Array
    }
  // Die sechs Nachrichten des Datei-Modus. Sie stehen HIER und nicht in einem
  // eigenen Worker, und der Grund ist derselbe wie beim Enrollment: die
  // entsperrten Tresorsitzungen liegen in Rust in einem `thread_local!`, also
  // muss der Aufruf, der eine Sitzung nennt, denselben Faden sehen wie der
  // Aufruf, der sie geoeffnet hat. Der `FileSystemDirectoryHandle` selbst
  // wird auf dem Hauptthread abgelaufen — er ist ein Objekt der Seite, und
  // jede Bytefolge reist einzeln hierher.
  | { readonly id: number; readonly kind: 'file-mode-bundle-extension' }
  | {
      readonly id: number
      readonly kind: 'file-mode-open-bundle'
      readonly session: number
      readonly bytes: Uint8Array
      readonly effectiveNowMs: bigint
    }
  | { readonly id: number; readonly kind: 'file-mode-begin-directory' }
  | {
      readonly id: number
      readonly kind: 'file-mode-push-blob'
      readonly handle: number
      readonly pathHint: string
      readonly bytes: Uint8Array
    }
  | { readonly id: number; readonly kind: 'file-mode-directory-unavailable'; readonly handle: number }
  | {
      readonly id: number
      readonly kind: 'file-mode-open-directory'
      readonly session: number
      readonly handle: number
      readonly effectiveNowMs: bigint
    }

/**
 * Die Antwort — der Wert oder der STABILE CODE des Fehlschlags.
 *
 * Nie der Wirtstext: `EA-READER-BLOB-HOST` nennt die Lage, ein durchgereichter
 * Wirtstext naennte womoeglich einen Ablagepfad.
 */
export type EaOpfsResponse =
  | {
      readonly id: number
      readonly ok: true
      readonly bytes?: Uint8Array | undefined
      readonly status?: string | undefined
    }
  | { readonly id: number; readonly ok: false; readonly code: string }

/**
 * Der Umfang des Workers, so schmal wie er ihn braucht.
 *
 * `lib.webworker` ist nicht geladen — es widerspraeche `lib.dom`, das die
 * Oberflaeche braucht —, also steht die benutzte Flaeche hier ausgeschrieben
 * statt als Typzusicherung auf `any`.
 */
type EaWorkerScope = {
  addEventListener: (
    type: 'message',
    listener: (event: MessageEvent<EaOpfsRequest>) => void,
  ) => void
  postMessage: (message: EaOpfsResponse) => void
}

const scope = globalThis as unknown as EaWorkerScope

// EIN Ladevorgang je Worker, und jede Nachricht wartet auf ihn. Der Ausgang von
// `build-wasm` traegt `--target web`: die benannten Ausfuhren stehen erst nach
// dem Aufruf des Vorgabeeinstiegs bereit, und ein Aufruf davor faellt mit einem
// Zugriff auf `undefined` statt mit einem Fehlercode.
const ready = init()

/**
 * Der stabile Code eines Fehlschlags.
 *
 * Die Bruecke wirft eine JS-Zeichenkette mit genau diesem Code; alles andere
 * ist ein Fehlschlag des Wirts und bekommt denselben Code wie ein Fehlschlag
 * des Speichers, weil der Aufrufer beides nicht unterscheiden kann.
 */
function failureCode(error: unknown): string {
  return typeof error === 'string' ? error : 'EA-READER-BLOB-HOST'
}

/**
 * Die Zustellung je Nachricht.
 *
 * `async`, weil `blobPut` und `blobGet` seit dem OPFS-Vorlauf ein `Promise`
 * zurueckgeben: ein `FileSystemSyncAccessHandle` liest und schreibt synchron,
 * sein OEFFNEN tut es nicht — die Begruendung steht vollstaendig in
 * `crates/ea-reader-wasm/src/opfs_worker.rs`.
 *
 * Ueber die FORM des Protokolls aendert das nichts: dieselben drei
 * Nachrichten, dieselbe eine Antwort je Nachricht, KEIN zusaetzlicher Schritt.
 *
 * Ueber die NEBENLAEUFIGKEIT aendert es alles, und das steht hier, weil eine
 * Zusicherung, die nicht stimmt, schlimmer ist als keine. Der Rumpf ist
 * `async`: jedes `message`-Ereignis haengt ein EIGENES `ready.then(...)` an,
 * ohne Kette zum vorigen. Zwei Nachrichten KOENNEN sich deshalb verschraenken
 * — die zweite laeuft an, waehrend die erste noch in ihrem OPFS-Vorlauf
 * steht. Vor dem `async`-Umbau war der Rumpf hinter `ready.then(...)`
 * vollstaendig synchron und Ueberlappung strukturell ausgeschlossen.
 *
 * Die Ordnung JE SCHLUESSEL liegt darum nicht hier, sondern in Rust:
 * `OpfsBlobStore::open` in `crates/ea-reader-wasm/src/opfs_worker.rs` nimmt
 * je Schluessel einen Platz in einer Warteschlange (`take_turn`, Abschnitt
 * „Warum ein zweiter Zugriff auf DENSELBEN Schluessel WARTET"), bevor es ein
 * Handle oeffnet. Zwei ueberlappende Nachrichten auf denselben Schluessel
 * weisen einander deshalb nicht ab — die zweite WARTET. Der gegatete Zeuge
 * dafuer ist `crates/ea-reader-wasm/tests/opfs_browser.rs`,
 * `a_second_request_on_the_same_key_waits_instead_of_being_refused`.
 *
 * Dass die Regel dort und nicht hier steht, ist die Auflage des Plans: dieser
 * Einstieg „enthaelt keine Entscheidung, nur Zustellung", und eine
 * Serialisierungsregel IST eine Entscheidung. Eine Kette in dieser Datei
 * faenge ausserdem kein Zeuge dieser Stufe.
 */
scope.addEventListener('message', (event) => {
  const request = event.data
  void ready
    .then(async () => {
      switch (request.kind) {
        case 'put':
          await blobPut(request.key, request.bytes)
          scope.postMessage({ id: request.id, ok: true })
          return
        case 'get':
          scope.postMessage({ id: request.id, ok: true, bytes: await blobGet(request.key) })
          return
        case 'delete':
          // BEFUND, hier sichtbar statt still geglaettet: die Bruecke fuehrt
          // heute `blobPut` und `blobGet` und KEIN `blobDelete` — der
          // Planblock von `crates/ea-reader-wasm/src/bridge.rs` zaehlt genau
          // zwei Ausfuhren auf, waehrend seine Prosa drei Nachrichten nennt.
          // Die Nachricht steht deshalb im Protokoll, ihre Zustellung fehlt,
          // und sie faellt geschlossen, statt einen Blob liegen zu lassen und
          // Erfolg zu melden. Der Task, dem die Bruecke gehoert, ersetzt
          // diese Zeile durch den Aufruf.
          scope.postMessage({ id: request.id, ok: false, code: 'EA-READER-BLOB-HOST' })
          return
        // Die fuenf Enrollment-Nachrichten reichen ihr Status-DTO UNVERAENDERT
        // durch: die Bruecke gibt eine JSON-Zeichenkette heraus, und wer sie
        // hier zerlegte, traefe eine Entscheidung ueber ihre Form. Zerlegt
        // wird sie auf dem Hauptthread, in `../vault/webauthn-prf.ts`.
        case 'enrollment-begin':
          // ASYNCHRON wie `enrollment-finish`, und aus demselben Grund: das Tor
          // in `ReaderEnrollment::begin` liest den lokalen Tresorplatz, und
          // `OpfsBlobStore::open` verlangt seinen Schluessel VOR dem Vorlauf.
          scope.postMessage({
            id: request.id,
            ok: true,
            status: await enrollmentBegin(
              request.organizationId,
              request.subjectId,
              request.pinnedAnchor,
              request.bundleFingerprint,
            ),
          })
          return
        case 'enrollment-register-authenticator':
          scope.postMessage({
            id: request.id,
            ok: true,
            status: enrollmentRegisterAuthenticator(
              request.handle,
              request.attestationObject,
              request.transport,
              request.prfOutput,
            ),
          })
          return
        case 'enrollment-fingerprints':
          scope.postMessage({
            id: request.id,
            ok: true,
            status: enrollmentFingerprints(request.handle),
          })
          return
        case 'enrollment-confirm-fingerprints':
          scope.postMessage({
            id: request.id,
            ok: true,
            status: enrollmentConfirmFingerprints(
              request.handle,
              request.expectedKeyFingerprint,
              request.expectedBundleFingerprint,
            ),
          })
          return
        case 'enrollment-finish':
          // Die zweite asynchrone Enrollment-Ausfuhr neben `enrollment-begin`:
          // `finish` schreibt am Ende ueber den synchronen `ReaderBlobStore`,
          // und `OpfsBlobStore::open` verlangt die Schluessel VOR dem Vorlauf.
          scope.postMessage({
            id: request.id,
            ok: true,
            status: await enrollmentFinish(
              request.handle,
              request.authority,
              request.createdUnixSeconds,
            ),
          })
          return
        case 'vault-unlock':
          // Die Sitzungskennung ist eine ZAHL und kein DTO; sie reist als Text
          // im selben Feld, damit die Antwortform eine bleibt. Die
          // Oberflaeche liest sie nicht — sie braucht nur, DASS der Tresor
          // aufging.
          scope.postMessage({
            id: request.id,
            ok: true,
            status: String(readerVaultUnlock(request.sealed, request.credentialId, request.prfOutput)),
          })
          return
        // Die sechs Datei-Modus-Nachrichten reichen ihr Ergebnis UNVERAENDERT
        // durch. Zerlegt wird das DTO auf dem Hauptthread, in
        // `../features/file-mode/DirectoryHandle.ts`; wer es hier zerlegte,
        // traefe eine Entscheidung ueber seine Form.
        case 'file-mode-bundle-extension':
          scope.postMessage({ id: request.id, ok: true, status: fileModeBundleExtension() })
          return
        case 'file-mode-open-bundle':
          scope.postMessage({
            id: request.id,
            ok: true,
            status: fileModeOpenBundle(request.session, request.bytes, request.effectiveNowMs),
          })
          return
        case 'file-mode-begin-directory':
          // Die Ordnerkennung ist eine ZAHL und kein DTO; sie reist als Text im
          // selben Feld, damit die Antwortform eine bleibt — dieselbe
          // Ueberlegung wie bei `vault-unlock`.
          scope.postMessage({
            id: request.id,
            ok: true,
            status: String(fileModeBeginDirectory()),
          })
          return
        case 'file-mode-push-blob':
          // EINE Bytefolge je Nachricht. Die zwei Deckel fallen in Rust, in
          // `DirectoryHandleSource::push_blob`; hier wird nichts gezaehlt und
          // nichts verglichen.
          fileModePushBlob(request.handle, request.pathHint, request.bytes)
          scope.postMessage({ id: request.id, ok: true })
          return
        case 'file-mode-directory-unavailable':
          fileModeDirectoryUnavailable(request.handle)
          scope.postMessage({ id: request.id, ok: true })
          return
        case 'file-mode-open-directory':
          scope.postMessage({
            id: request.id,
            ok: true,
            status: fileModeOpenDirectory(request.session, request.handle, request.effectiveNowMs),
          })
          return
      }
    })
    // EIN Auffangarm statt der frueheren zwei: mit `await` in der Zustellung
    // faellt ein abgewiesenes Promise der Bruecke in denselben Zweig wie ein
    // geworfener Fehler, und ein `try`/`catch` um den Rumpf faenge das
    // abgewiesene Promise nicht.
    .catch((error: unknown) => {
      scope.postMessage({ id: request.id, ok: false, code: failureCode(error) })
    })
})
