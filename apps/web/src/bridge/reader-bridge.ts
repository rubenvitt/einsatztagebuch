// Die EINZIGE Anbindung der Reader-Oberflaeche an die sechs Ansichtsausfuhren
// von `crates/ea-reader-wasm/src/view.rs`.
//
// Diese Datei ENTSCHEIDET nichts (`web-reader-design.md` §9): sie traegt
// Nachrichten zum Worker, zerlegt das JSON, das zurueckkommt, in die
// generierten Typen und rechnet, filtert und sortiert nichts. Was ein
// Eintrag ist, ob er verifiziert ist, ob ein Objekt ein Problem ist und
// welcher Treffer zu einer Suche gehoert, hat Rust entschieden, bevor die
// Zeichenkette hier ankommt.
//
// Warum ueber den Worker: der geoeffnete Bestand liegt in Rust in einem
// `thread_local!`, installiert von den zwei Oeffnungsausfuhren des
// Datei-Modus. Ein Aufruf auf dem Hauptthread saehe ein zweites, leeres
// wasm-Modul und antwortete immer mit „kein Bestand".

import type {
  ReaderAmendmentThreadView,
  ReaderEntryView,
  ReaderSearchHitView,
  ReaderStandView,
  ReaderTechnicalView,
} from './generated-contracts'
import type { EaOpfsResponse } from './opfs-worker'
import type { ReaderWorkerMessage } from '../vault/webauthn-prf'
import { callReaderWorker } from '../vault/webauthn-prf'

/**
 * Die vier Filter der Suche, so wie die Flaeche sie getippt bekommt.
 *
 * Eine ANFRAGEFORM und kein Sicherheits-DTO — sie reist in eine Richtung, und
 * deshalb ist sie von Hand geschrieben. Ein fehlendes Feld ist „kein Filter",
 * genau wie die leere Zeichenkette und die fehlende Zeitgrenze in
 * `view::query_from`; die Deutung liegt dort, nicht hier.
 */
export type ReaderSearchFilters = {
  readonly fromMs?: number
  readonly toMs?: number
  readonly keyword?: string
  readonly vehicle?: string
  readonly person?: string
}

/**
 * Die FORM der Reader-Bruecke — sechs Glieder, je Ausfuhr eines.
 *
 * `standView` liefert `null`, wenn kein Bestand offen ist, und das ist ein
 * WERT: die Flaeche zeigt dann den technischen Zustand und keinen leeren
 * Einsatz. `amendmentThread` liefert `null` fuer einen Eintrag, der in
 * keinem Original/Nachtrag-Faden steht — die Bruecke wirft dafuer
 * `EA-READER-VIEW-NO-THREAD`, aber „kein Faden" ist keine Stoerung, sondern
 * der haeufigste Fall, und die Flaeche soll ihn nicht als Fehler lesen. Jeder
 * ANDERE Code reist unveraendert weiter.
 */
export type ReaderBridge = {
  readonly standView: () => Promise<ReaderStandView | null>
  readonly entryView: (entryHash: string) => Promise<ReaderEntryView>
  readonly technicalView: (entryHash: string) => Promise<ReaderTechnicalView>
  readonly amendmentThread: (entryHash: string) => Promise<ReaderAmendmentThreadView | null>
  readonly search: (filters: ReaderSearchFilters) => Promise<readonly ReaderSearchHitView[]>
  readonly closeStand: () => Promise<void>
}

/** Der Code, den Rust fuer einen Eintrag ohne Faden wirft. */
const NO_THREAD = 'EA-READER-VIEW-NO-THREAD'

/**
 * Der stabile Code eines Fehlschlags, unveraendert geworfen — kein Wirtstext,
 * keine eigene Uebersetzung, dieselbe Bauform wie in `DirectoryHandle.ts`.
 */
function raise(response: EaOpfsResponse): Extract<EaOpfsResponse, { ok: true }> {
  if (!response.ok) {
    throw new Error(response.code)
  }
  return response
}

/** Der Wert einer Antwort, die einen tragen MUSS — JSON-DTO oder `null`-Text. */
function statusOf(response: EaOpfsResponse): string {
  const status = raise(response).status
  if (status === undefined) {
    throw new Error('Der Worker hat auf eine Reader-Nachricht keinen Wert geliefert.')
  }
  return status
}

/** Eine Nachricht, deren Antwort ein JSON-DTO traegt. */
async function callForJson(request: ReaderWorkerMessage): Promise<string> {
  return statusOf(await callReaderWorker(request))
}

/**
 * Eine Zeitgrenze an der Grenze zu `wasm_bindgen`: `Option<i64>` ist dort
 * `bigint | null`. Umgeformt wird der WERT, nicht seine Bedeutung — dieselbe
 * Stelle, an der `DirectoryHandle.ts` `effectiveNowMs` in ein `BigInt` hebt.
 */
function bound(ms: number | undefined): bigint | null {
  return ms === undefined ? null : BigInt(ms)
}

/** Die echte Bruecke: sechs Glieder, jedes eine Nachricht an den EINEN Worker. */
export const readerBridge: ReaderBridge = {
  standView: async () =>
    JSON.parse(await callForJson({ kind: 'reader-stand-view' })) as ReaderStandView | null,

  entryView: async entryHash =>
    JSON.parse(await callForJson({ kind: 'reader-entry-view', entryHash })) as ReaderEntryView,

  technicalView: async entryHash =>
    JSON.parse(
      await callForJson({ kind: 'reader-technical-view', entryHash }),
    ) as ReaderTechnicalView,

  amendmentThread: async entryHash => {
    const response = await callReaderWorker({ kind: 'reader-amendment-thread', entryHash })
    if (!response.ok && response.code === NO_THREAD) {
      return null
    }
    return JSON.parse(statusOf(response)) as ReaderAmendmentThreadView
  },

  search: async filters =>
    JSON.parse(
      await callForJson({
        kind: 'reader-search',
        fromMs: bound(filters.fromMs),
        toMs: bound(filters.toMs),
        keyword: filters.keyword ?? '',
        vehicle: filters.vehicle ?? '',
        person: filters.person ?? '',
      }),
    ) as readonly ReaderSearchHitView[],

  closeStand: async () => {
    raise(await callReaderWorker({ kind: 'reader-stand-close' }))
  },
}
