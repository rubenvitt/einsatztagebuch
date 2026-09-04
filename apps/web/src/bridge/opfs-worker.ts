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
  readerAmendmentThread,
  readerEntryView,
  readerExportOne,
  readerNoteActivity,
  readerNoteVisibility,
  readerSearch,
  readerSessionLock,
  readerSessionStateAt,
  readerStandClose,
  readerStandView,
  readerTechnicalView,
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
 * `vault-unlock` war die erste Nachricht, die WEDER Speicher NOCH Enrollment
 * ist; die Sitzungs- und Exportnachrichten unten stehen seit der
 * Sitzungssperre daneben. Sie traegt die lebende Paritaetsprobe der Oberflaeche: sie oeffnet
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
      // Die Uhr der Seite, als WERT: sie eroeffnet die Sitzung und setzt die
      // monotone Untergrenze, gegen die `ReaderSession::state_at` von da an
      // rechnet. Rust liest keine eigene Uhr.
      readonly nowMs: number
    }
  // Die fuenf Nachrichten der Sitzungssperre und des Einzelexports
  // (`web-reader-design.md` §6.5 und §8.2). Sie stehen HIER, weil die
  // Sitzung, die sie nennen, in Rust in demselben `thread_local!` liegt wie
  // die des Datei-Modus. Vier tragen `nowMs`, und keine entscheidet hier
  // etwas: die Fristen rechnet `ReaderSession::state_at` nach, und der
  // Worker reicht nur den Zeitwert durch, den der Hauptthread gelesen hat.
  // `session-lock` traegt keine Uhr, weil es keine Frist prueft: es sperrt
  // SOFORT — die eine Stelle, die die Kennung haelt, ersetzt eine Sitzung
  // durch eine neue und laesst die alte nicht ohne Melder offen stehen.
  | {
      readonly id: number
      readonly kind: 'session-note-visibility'
      readonly session: number
      readonly hidden: boolean
      readonly nowMs: number
    }
  | {
      readonly id: number
      readonly kind: 'session-note-activity'
      readonly session: number
      readonly nowMs: number
    }
  | { readonly id: number; readonly kind: 'session-state'; readonly session: number; readonly nowMs: number }
  | { readonly id: number; readonly kind: 'session-lock'; readonly session: number }
  | {
      readonly id: number
      readonly kind: 'export-one'
      readonly session: number
      readonly nowMs: number
      readonly sealed: Uint8Array
      readonly credentialId: Uint8Array
      readonly prfOutput: Uint8Array
      readonly entryHash: Uint8Array
      readonly targetKind: number
      readonly targetOccupied: boolean
      readonly organizationId: Uint8Array
      readonly deviceId: Uint8Array
      readonly signerCertificateObjectHash: Uint8Array
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
  // Die sechs Nachrichten der Reader-Ansicht. Wieder derselbe Grund fuer
  // denselben Worker: der geoeffnete Bestand liegt in Rust in einem
  // `thread_local!` (`crates/ea-reader-wasm/src/view.rs`), und die zwei
  // Oeffnungsausfuhren des Datei-Modus installieren ihn dort — eine Ansicht
  // aus einem zweiten Worker saehe keinen Bestand. Die zwei Zeitgrenzen der
  // Suche reisen als `bigint`, weil `wasm_bindgen` `Option<i64>` so abbildet;
  // `null` ist „keine Grenze".
  | { readonly id: number; readonly kind: 'reader-stand-view' }
  | { readonly id: number; readonly kind: 'reader-entry-view'; readonly entryHash: string }
  | { readonly id: number; readonly kind: 'reader-technical-view'; readonly entryHash: string }
  | { readonly id: number; readonly kind: 'reader-amendment-thread'; readonly entryHash: string }
  | {
      readonly id: number
      readonly kind: 'reader-search'
      readonly fromMs: bigint | null
      readonly toMs: bigint | null
      readonly keyword: string
      readonly vehicle: string
      readonly person: string
    }
  | { readonly id: number; readonly kind: 'reader-stand-close' }

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
  // Die Uebertragungsliste ist OPTIONAL und wird an genau einer Stelle
  // benutzt: `export-one` reicht den Klartextpuffer ab, statt ihn zu
  // kopieren, damit im Worker keine Kopie zurueckbleibt (WR-082).
  postMessage: (message: EaOpfsResponse, transfer?: readonly Transferable[]) => void
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
            status: String(
              readerVaultUnlock(
                request.sealed,
                request.credentialId,
                request.prfOutput,
                request.nowMs,
              ),
            ),
          })
          return
        case 'session-note-visibility':
          readerNoteVisibility(request.session, request.hidden, request.nowMs)
          scope.postMessage({ id: request.id, ok: true })
          return
        case 'session-note-activity':
          readerNoteActivity(request.session, request.nowMs)
          scope.postMessage({ id: request.id, ok: true })
          return
        case 'session-state':
          // Der Aufruf IST die Sperrentscheidung — `state_at` rechnet die
          // Frist nach und sperrt, wenn sie erreicht ist. Das DTO reist
          // UNVERAENDERT; zerlegt wird es auf dem Hauptthread, in
          // `../features/session/reader-session.ts`.
          scope.postMessage({
            id: request.id,
            ok: true,
            status: readerSessionStateAt(request.session, request.nowMs),
          })
          return
        case 'session-lock':
          // Sperrt SOFORT und ohne Frist; eine unbekannte Kennung faellt mit
          // `EA-READER-SESSION-UNKNOWN`, und ob das ein Fehler ist,
          // entscheidet der Aufrufer — fuer den einen Halter der Kennung ist
          // eine Sitzung, die es nicht mehr gibt, bereits das Ziel.
          readerSessionLock(request.session)
          scope.postMessage({ id: request.id, ok: true })
          return
        case 'export-one': {
          // Die Senke, die Rust GENAU EINMAL mit dem Klartext ruft. Sie
          // kopiert die Bytes und sagt `true` — mehr nicht. Dass die Bytes
          // danach zum Hauptthread reisen, ist keine Entscheidung dieser
          // Datei, sondern die Lage des Wirts: `showSaveFilePicker` und ein
          // Download gibt es nur dort. Die Grenze, die die `Accepted`-Zeile
          // bezeugt, ist der Aufruf dieser Senke hier im Worker; was der
          // Wirt danach tut, bezeugt die `Completed`-Zeile NICHT — die Zeile
          // bezeugt die Uebergabe, nicht die Platte
          // (`crates/ea-reader-wasm/src/export_bridge.rs`).
          //
          // KOPIERT und nicht referenziert: das `Uint8Array`, das Rust
          // herueberreicht, entsteht mit `Uint8Array::from` bereits im
          // JS-Heap, aber die Kopie macht die Uebergabe unabhaengig davon,
          // ob wasm-bindgen den Puffer nach dem Aufruf wiederverwendet.
          //
          // NULL KLARTEXTKOPIEN im Worker (WR-082): das Original wird nach
          // der Kopie genullt — Rust nullt seine eigenen Puffer, dieses
          // `Uint8Array` ist der Puffer des WIRTS —, und die Kopie reist
          // unten mit einer Uebertragungsliste, also als ABGABE des Puffers
          // und nicht als zweite Kopie, die hier liegen bliebe.
          let plaintext: Uint8Array<ArrayBuffer> | undefined
          const report = await readerExportOne(
            request.session,
            request.nowMs,
            request.sealed,
            request.credentialId,
            request.prfOutput,
            request.entryHash,
            request.targetKind,
            request.targetOccupied,
            request.organizationId,
            request.deviceId,
            request.signerCertificateObjectHash,
            (bytes: Uint8Array): boolean => {
              plaintext = new Uint8Array(bytes)
              bytes.fill(0)
              return true
            },
          )
          if (plaintext === undefined) {
            scope.postMessage({ id: request.id, ok: true, status: report })
            return
          }
          scope.postMessage(
            { id: request.id, ok: true, status: report, bytes: plaintext },
            [plaintext.buffer],
          )
          return
        }
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
        // Die sechs Reader-Nachrichten reichen ihr JSON UNVERAENDERT durch —
        // auch das `null` eines fehlenden Bestandes. Zerlegt wird auf dem
        // Hauptthread, in `./reader-bridge.ts`, und nur dort; ein Fehlschlag
        // (`EA-READER-VIEW-NO-STAND`, `-UNKNOWN-ENTRY`, `-NO-THREAD`,
        // `-NO-MANIFEST`) faellt in den Auffangarm und reist als Code.
        case 'reader-stand-view':
          scope.postMessage({ id: request.id, ok: true, status: readerStandView() })
          return
        case 'reader-entry-view':
          scope.postMessage({ id: request.id, ok: true, status: readerEntryView(request.entryHash) })
          return
        case 'reader-technical-view':
          scope.postMessage({
            id: request.id,
            ok: true,
            status: readerTechnicalView(request.entryHash),
          })
          return
        case 'reader-amendment-thread':
          scope.postMessage({
            id: request.id,
            ok: true,
            status: readerAmendmentThread(request.entryHash),
          })
          return
        case 'reader-search':
          scope.postMessage({
            id: request.id,
            ok: true,
            status: readerSearch(
              request.fromMs,
              request.toMs,
              request.keyword,
              request.vehicle,
              request.person,
            ),
          })
          return
        case 'reader-stand-close':
          readerStandClose()
          scope.postMessage({ id: request.id, ok: true })
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
