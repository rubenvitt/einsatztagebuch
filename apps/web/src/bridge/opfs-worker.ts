// Der Einstieg des DEDIZIERTEN Workers.
//
// Er enthaelt KEINE Entscheidung, nur Zustellung: er laedt das wasm-Modul und
// reicht jede Nachricht an die Bruecke weiter. Der Grund, warum es diese Datei
// ueberhaupt gibt, liegt in Rust: `FileSystemSyncAccessHandle` existiert auf
// dem Hauptthread nicht, also lebt `OpfsBlobStore` nur hier. Waere hier eine
// Fallunterscheidung ueber Bytes, gaebe es eine zweite Stelle, an der ueber
// Klartext entschieden wird — und `web-reader-design.md` §9 laesst
// Kryptographie ausschliesslich in geteiltem Rust zu.

import init, { blobGet, blobPut } from './pkg/ea_reader_wasm.js'

/** Die drei Nachrichten, die der Speicher kennt. */
export type EaOpfsRequest =
  | { readonly id: number; readonly kind: 'put'; readonly key: string; readonly bytes: Uint8Array }
  | { readonly id: number; readonly kind: 'get'; readonly key: string }
  | { readonly id: number; readonly kind: 'delete'; readonly key: string }

/**
 * Die Antwort — der Wert oder der STABILE CODE des Fehlschlags.
 *
 * Nie der Wirtstext: `EA-READER-BLOB-HOST` nennt die Lage, ein durchgereichter
 * Wirtstext naennte womoeglich einen Ablagepfad.
 */
export type EaOpfsResponse =
  | { readonly id: number; readonly ok: true; readonly bytes?: Uint8Array | undefined }
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
 * `crates/ea-reader-wasm/src/opfs_worker.rs`. Das Protokoll zwischen
 * Hauptthread und Worker bleibt davon Zeile fuer Zeile unberuehrt: dieselben
 * drei Nachrichten, dieselbe eine Antwort je Nachricht, KEIN zusaetzlicher
 * Schritt. Abgewartet wird nur der Aufruf dahinter, und auch das ist weiterhin
 * keine Entscheidung, sondern Zustellung.
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
