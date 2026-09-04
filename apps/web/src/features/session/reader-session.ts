// Die EINE Stelle des Hauptthreads, die die Sitzungskennung haelt — und die
// Bruecke, die die Einzelexportflaeche verbraucht.
//
// Diese Datei ENTSCHEIDET nichts (`web-reader-design.md` §9). Sie rechnet
// keine Frist, vergleicht keine Uhr, prueft keinen Hash und sieht keinen
// Klartext, bevor Rust ihn herausgegeben hat: die Sperrentscheidung faellt in
// `ReaderSession::state_at`, die Bestaetigung belegt
// `ReaderAuthenticatorConfirmation::prove`, und die Auditzeilen schreibt
// `ReaderExportService::export_one`. Was hier geschieht, ist Werte tragen —
// den Zeitwert der Seite, die Kennung, die frische PRF-Ausgabe — und die
// Bytes des Exports an das Ziel reichen, das der Leser gewaehlt hat.
//
// # Warum es GENAU EINEN Halter der Kennung gibt
//
// Die Sichtbarkeits- und Eingabehaken in `src/main.tsx` melden an DIE
// Sitzung, die gerade offen ist. Hielte der Datei-Modus daneben eine eigene,
// bekaeme sie keine Meldung, liefe fuenf Minuten nach ihrem Entsperren in die
// Untaetigkeitsfrist und sperrte, waehrend der Leser tippt. Deshalb holt auch
// `DirectoryHandle.ts` seine Kennung ueber [`ensureReaderSession`] von hier,
// und deshalb entsperrt auch die Enrollment-Flaeche ueber
// [`readerSessionBridge.unlock`] statt ueber einen eigenen Weg.
//
// Aus demselben Grund gibt es hier zu jeder Zeit HOECHSTENS EINE entsperrte
// Sitzung in Rust: zwei sich ueberlappende Entsperrungen teilen sich eine
// Zeremonie ([`unlocking`]), und wer eine bestehende Kennung durch eine neue
// ersetzt, sperrt die alte VORHER ueber `session-lock`. Eine entsperrte
// Sitzung, deren Kennung niemand mehr haelt, bekaeme keine Meldung — und
// waere genau die Sitzung, die §6.5 nicht dulden will.
//
// # Der Zielpfad kommt hier NICHT vor
//
// `showSaveFilePicker` gibt ein Handle heraus, und dieses Handle traegt einen
// Namen. Er wird weder an die Bruecke gereicht — `export-context-v1` hat keine
// Position fuer ihn — noch gerendert noch gehalten: die Flaeche bekommt die
// ZIELART als Zahl und nichts sonst.

import type { ReaderSessionView, SingleExportReportView } from '../../bridge/generated-contracts'
import type { EaOpfsResponse } from '../../bridge/opfs-worker'
import type { ReaderWorkerMessage } from '../../vault/webauthn-prf'
import {
  bytesFromHex,
  callReaderWorker,
  freshPrfForConfirmation,
  readSealedReaderVault,
  unlockReaderVaultSession,
} from '../../vault/webauthn-prf'

declare global {
  // `showSaveFilePicker` steht wie `showDirectoryPicker` in der
  // File-System-Access-Fassung des Fensters und in `lib.dom.d.ts`
  // (TypeScript 7.0.2) ueberhaupt nicht. Die Erweiterung deklariert das eine
  // Feld nach, OPTIONAL, damit die Faehigkeitsabfrage etwas zu fragen hat:
  // Safari und Firefox haben es nicht, und genau deshalb gibt es die zweite
  // Zielart.
  interface Window {
    showSaveFilePicker?: (options?: SaveFilePickerOptionsV1) => Promise<ExportFileHandleV1>
  }
}

/** Die von dieser Datei benutzten Optionen von `showSaveFilePicker`. */
type SaveFilePickerOptionsV1 = {
  readonly suggestedName?: string
}

/**
 * Die von dieser Datei benutzte Flaeche eines `FileSystemFileHandle`.
 *
 * Ausgeschrieben aus demselben Grund wie `FileModeDirectoryHandleV1`: die
 * Methoden liegen in `lib.dom.d.ts` nicht in dieser Form, und ein struktureller
 * Ausschnitt benennt genau, was angefasst wird — `getFile` fuer die Frage, ob
 * das Ziel besetzt ist, `createWritable` fuer das Schreiben. Den Namen des
 * Handles nennt der Typ AUSDRUECKLICH nicht.
 *
 * `abort` ist OPTIONAL, weil der Typ ein Ausschnitt ist und ein Doppel im
 * Zeugen ihn nicht fuehren muss; im Browser traegt jeder
 * `FileSystemWritableFileStream` ihn, und `write` unten ruft ihn, wenn das
 * Schreiben faellt — sonst bliebe die Swap-Datei des Streams liegen und ein
 * `close` schriebe halbe Bytes an den gewaehlten Ort (§8.2).
 */
export type ExportFileHandleV1 = {
  readonly getFile: () => Promise<{ readonly size: number }>
  readonly createWritable: () => Promise<{
    readonly write: (data: Uint8Array) => Promise<void>
    readonly close: () => Promise<void>
    readonly abort?: () => Promise<void>
  }>
}

/**
 * Das Wirtsobjekt, an dem die Zielwahl ihre Faehigkeitsabfrage stellt.
 *
 * `showSaveFilePicker` ist OPTIONAL, und das ist die ganze Aussage des Typs.
 * Uebergeben und nicht aus `globalThis` gelesen, damit ein Zeuge die
 * Abwesenheit doubeln kann.
 */
export type ExportHost = {
  readonly showSaveFilePicker?: (options?: SaveFilePickerOptionsV1) => Promise<ExportFileHandleV1>
}

/**
 * Die drei Identitaetsfelder der Auditzeile
 * (`LocalAuditEventCoreFieldsV1`): Organisation, Geraet, Objekthash des
 * signierenden Zertifikats.
 */
export type ReaderAuditIdentity = {
  readonly organizationId: Uint8Array
  readonly deviceId: Uint8Array
  readonly signerCertificateObjectHash: Uint8Array
}

/**
 * Das gewaehlte Ziel: seine ART als Zahl aus `ReaderExportTargetKindV1`
 * (1 = vom Leser gewaehlte Datei, 2 = vom Leser ausgeloester Download), ob es
 * schon Bytes traegt, und der Weg, die Bytes hineinzuschreiben.
 *
 * `occupied` wird HIER gemessen und in Rust ENTSCHIEDEN: die Bruecke weist ein
 * besetztes Ziel mit `EA-READER-EXPORT-TARGET-OCCUPIED` ab, bevor eine
 * Auditzeile entsteht. Diese Datei sagt nur, was sie gesehen hat.
 */
export type ExportTargetChoice = {
  readonly kind: 1 | 2
  readonly occupied: boolean
  readonly write: (bytes: Uint8Array) => Promise<void>
}

/**
 * Die FORM der Sitzungsbruecke, die `SingleExport.tsx` verbraucht.
 *
 * Jeder Aufruf traegt `nowMs` als WERT hinein, weil Rust keine Uhr liest —
 * und weil ein Zeuge mit gefaelschter Seitenuhr genau dieselbe Zahl sehen
 * soll wie die Sitzung.
 */
export type ReaderSessionBridge = {
  /**
   * Eine frische Bestaetigung, wenn keine Sitzung offen ist; die Kennung der
   * neuen Sitzung wird gemerkt. Ist die Sitzung zu `nowMs` noch offen, ein
   * Leerlauf — siehe die Umsetzung.
   */
  readonly unlock: (nowMs: number) => Promise<void>
  /**
   * Der Zustand zu `nowMs`, oder `undefined`, wenn nie eine Sitzung eroeffnet
   * wurde. Der Aufruf IST die Sperrentscheidung — in Rust.
   */
  readonly stateAt: (nowMs: number) => Promise<ReaderSessionView | undefined>
  /** Meldet die Sichtbarkeit des Tabs; ohne Sitzung ein Leerlauf. */
  readonly noteVisibility: (hidden: boolean, nowMs: number) => Promise<void>
  /** Meldet eine Eingabe; ohne Sitzung ein Leerlauf. */
  readonly noteActivity: (nowMs: number) => Promise<void>
  /**
   * Exportiert GENAU EINEN Datensatz: frische PRF-Zeremonie, versiegelter
   * Tresor, `export-one` an den Worker, dann `target.write` mit den Bytes,
   * die Rust herausgegeben hat. Eine Weigerung kommt als `Error(code)`.
   */
  readonly exportOne: (request: {
    readonly entryHashHex: string
    readonly target: ExportTargetChoice
    readonly identity: ReaderAuditIdentity
    readonly nowMs: number
  }) => Promise<SingleExportReportView>
  /**
   * Die Identitaet der Auditzeile — oder `undefined`, wenn dieses Geraet
   * keine traegt. Siehe die benannte Grenze an der Umsetzung.
   */
  readonly auditIdentity: () => ReaderAuditIdentity | undefined
}

/**
 * Der Dateiname, den der Dialog beziehungsweise der Download VORSCHLAEGT.
 *
 * Ein Vorschlag und kein Pfad: was der Leser daraus macht, sieht diese Datei
 * nicht, und die Bruecke bekommt es nie.
 */
const EXPORT_SUGGESTED_NAME = 'einsatzarchiv-export.cbor'

/** Ein Aufruf ohne Antwortwert; ein Fehlschlag reist als stabiler Code. */
async function callVoid(request: ReaderWorkerMessage): Promise<void> {
  raise(await callReaderWorker(request))
}

/**
 * Der stabile Code eines Fehlschlags, unveraendert geworfen.
 *
 * `EA-READER-SESSION-LOCKED`, `EA-READER-SESSION-UNKNOWN`,
 * `EA-READER-EXPORT-TARGET-OCCUPIED` und die uebrigen sind Aussagen von
 * Rust; die Flaeche zeigt genau diese und keinen erfundenen Satz.
 */
function raise(response: EaOpfsResponse): Extract<EaOpfsResponse, { ok: true }> {
  if (!response.ok) {
    throw new Error(response.code)
  }
  return response
}

/**
 * Die Kennung der Sitzung dieses Seitenlaufs.
 *
 * Sie bleibt auch nach einer Sperre stehen: eine gesperrte Sitzung ist in
 * Rust eine Kennung, deren `state_at` `locked: true` liefert, und die Flaeche
 * soll GENAU DAS anzeigen koennen. Erst [`readerSessionBridge.unlock`] ersetzt
 * sie durch eine neue.
 */
let sessionHandle: number | undefined

/**
 * Die Zeremonie, die gerade LAEUFT — oder `undefined`.
 *
 * Zwei Aufrufer, die sich ueberlappen — der Datei-Modus ueber
 * [`ensureReaderSession`] und die Flaeche ueber [`readerSessionBridge.unlock`],
 * oder ein Doppelklick —, starteten sonst zwei Zeremonien und liessen zwei
 * Sitzungen aufgehen, von denen nur eine gehalten und gemeldet wuerde. Sie
 * teilen sich stattdessen die eine laufende und bekommen dieselbe Kennung.
 */
let unlocking: Promise<number> | undefined

/**
 * Die Kennung, ohne Sitzung ein Fehlschlag mit dem Code, den Rust fuer eine
 * Kennung gibt, die es nicht gibt — eine nie eroeffnete ist genau das.
 */
function requireSession(): number {
  if (sessionHandle === undefined) {
    throw new Error('EA-READER-SESSION-UNKNOWN')
  }
  return sessionHandle
}

/**
 * Sperrt eine Sitzung SOFORT, deren Kennung gleich ersetzt wird.
 *
 * `EA-READER-SESSION-UNKNOWN` ist hier kein Fehlschlag: eine Sitzung, die es
 * nicht mehr gibt, ist bereits das, was die Sperre herstellen soll. Jeder
 * andere Code reist unveraendert.
 */
async function lockSession(session: number): Promise<void> {
  const response = await callReaderWorker({ kind: 'session-lock', session })
  if (!response.ok && response.code !== 'EA-READER-SESSION-UNKNOWN') {
    throw new Error(response.code)
  }
}

/**
 * EINE Zeremonie, geteilt von allen, die sie gleichzeitig verlangen.
 *
 * Reihenfolge: erst die alte Sitzung sperren, dann die Zeremonie, dann die
 * Kennung ersetzen. Die alte VORHER, weil so zu keinem Zeitpunkt zwei
 * entsperrte Sitzungen nebeneinander stehen — faellt die Zeremonie, ist die
 * alte gesperrt, und das war sie nach der Vorbedingung von `unlock` ohnehin;
 * faellt die Sperre, entsteht gar keine neue.
 */
function openSession(nowMs: number): Promise<number> {
  if (unlocking !== undefined) {
    return unlocking
  }
  const ceremony = (async () => {
    const previous = sessionHandle
    if (previous !== undefined) {
      await lockSession(previous)
    }
    const created = await unlockReaderVaultSession(nowMs)
    sessionHandle = created
    return created
  })()
  unlocking = ceremony
  return ceremony.finally(() => {
    unlocking = undefined
  })
}

/**
 * Die Sitzung dieses Seitenlaufs, EINMAL entsperrt und danach wiederverwendet.
 *
 * Der Weg des Datei-Modus: er braucht eine Kennung und keine frische
 * Zeremonie je Oeffnen. Ist die Sitzung inzwischen gesperrt, bekommt er sie
 * TROTZDEM zurueck und laeuft in `EA-READER-SESSION-LOCKED` — die erneute
 * Bestaetigung nach §6.5 ist eine Handlung des Lesers ueber
 * [`readerSessionBridge.unlock`], nicht ein stiller Nebeneffekt eines
 * Dateidialogs. Laeuft gerade eine Zeremonie, wartet er auf DEREN Kennung
 * statt eine zweite Sitzung daneben zu eroeffnen.
 */
export async function ensureReaderSession(nowMs: number): Promise<number> {
  if (unlocking !== undefined) {
    return unlocking
  }
  return sessionHandle ?? openSession(nowMs)
}

/**
 * Die Zielwahl: Dateidialog, wo es ihn gibt, sonst Download.
 *
 * Erkannt wird die FAEHIGKEIT am uebergebenen Wirt und nie eine
 * Browserkennung. `undefined` heisst: der Leser hat den Dialog abgebrochen —
 * das ist keine Weigerung und kein Fehler, also auch kein Code.
 *
 * `occupied` ist die Groesse der gewaehlten Datei VOR dem Schreiben. Der
 * Dialog laesst den Leser eine vorhandene Datei waehlen, und ob das zulaessig
 * ist, entscheidet Rust (`EA-READER-EXPORT-TARGET-OCCUPIED`), nicht der Dialog.
 */
export async function chooseExportTarget(host: ExportHost): Promise<ExportTargetChoice | undefined> {
  const picker = host.showSaveFilePicker
  if (picker !== undefined) {
    let handle: ExportFileHandleV1
    try {
      handle = await picker.call(host, { suggestedName: EXPORT_SUGGESTED_NAME })
    } catch (reason) {
      if (reason instanceof DOMException && reason.name === 'AbortError') {
        return undefined
      }
      throw reason
    }
    const occupied = (await handle.getFile()).size > 0
    return {
      kind: 1,
      occupied,
      write: async bytes => {
        const writable = await handle.createWritable()
        try {
          await writable.write(bytes)
          await writable.close()
        } catch (reason) {
          // Abbrechen statt schliessen: `close` schriebe den Teilstand der
          // Swap-Datei an den gewaehlten Ort, `abort` verwirft ihn. Der
          // Grund des Fehlschlags reist danach unveraendert weiter.
          await writable.abort?.()
          throw reason
        }
      },
    }
  }
  // Der Download-Weg, Safari und Firefox. Ein `<a download>` auf eine
  // `blob:`-URL ist eine NAVIGATION, die der Browser als Download behandelt;
  // die Fetch-Direktiven der CSP in `index.html` (`default-src 'none'` und
  // die einzelnen `*-src`) regeln Fetches und keine Navigationen, und die
  // einzige Navigationsdirektive dort, `form-action`, betrifft Formulare.
  // BENANNTE GRENZE: der Browserzeuge laeuft nur in Chromium, und dort gibt es
  // `showSaveFilePicker` — dieser Zweig ist also in keinem Lauf dieses Standes
  // gegen die CSP gemessen. Ein Ziel, das es noch nicht gibt, ist nie besetzt.
  return {
    kind: 2,
    occupied: false,
    write: async bytes => {
      // `slice()` statt `bytes` selbst: `Blob` verlangt einen Puffer, der ein
      // `ArrayBuffer` IST, und `Uint8Array` allein traegt in TypeScript 7
      // `ArrayBufferLike`. Die Kopie ist die eine, die der Download ohnehin
      // anlegt.
      const url = URL.createObjectURL(new Blob([bytes.slice()], { type: 'application/cbor' }))
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = EXPORT_SUGGESTED_NAME
      anchor.click()
      // Nicht sofort widerrufen: der Klick stoesst die Navigation an, und ob
      // sie die URL noch in derselben Aufgabe aufloest, sagt keine Engine zu.
      // Eine Aufgabe spaeter ist sie aufgeloest oder gescheitert — beides
      // ohne diese URL. Das ist Aufraeumen und kein Fristmechanismus.
      setTimeout(() => {
        URL.revokeObjectURL(url)
      }, 0)
    },
  }
}

/** Die echte Bruecke: jeder Aufruf eine Nachricht an den EINEN Worker. */
export const readerSessionBridge: ReaderSessionBridge = {
  unlock: async nowMs => {
    // Nach einer SPERRE eine frische Zeremonie und eine neue Kennung: §6.5
    // verlangt nach jeder Sperre eine erneute Bestaetigung, und eine
    // gesperrte Sitzung geht in Rust nicht wieder auf — ihr
    // Schluesselmaterial ist genullt. Aber §6.5 verlangt die Bestaetigung
    // nach einer SPERRE und keine zweite Sitzung neben einer offenen: ist
    // die Sitzung zu `nowMs` noch offen, geschieht nichts. Der Aufruf von
    // `stateAt` ist dabei selbst die Sperrentscheidung — meldet er
    // `locked: false`, ist die Frist zu genau diesem Zeitwert nicht erreicht.
    const current = await readerSessionBridge.stateAt(nowMs)
    if (current !== undefined && !current.locked) {
      return
    }
    await openSession(nowMs)
  },

  stateAt: async nowMs => {
    if (sessionHandle === undefined) {
      return undefined
    }
    const response = raise(
      await callReaderWorker({ kind: 'session-state', session: sessionHandle, nowMs }),
    )
    if (response.status === undefined) {
      throw new Error('Der Worker hat auf die Zustandsfrage keinen Sitzungszustand geliefert.')
    }
    return JSON.parse(response.status) as ReaderSessionView
  },

  noteVisibility: async (hidden, nowMs) => {
    if (sessionHandle === undefined) {
      return
    }
    await callVoid({ kind: 'session-note-visibility', session: sessionHandle, hidden, nowMs })
  },

  noteActivity: async nowMs => {
    if (sessionHandle === undefined) {
      return
    }
    await callVoid({ kind: 'session-note-activity', session: sessionHandle, nowMs })
  },

  exportOne: async ({ entryHashHex, target, identity, nowMs }) => {
    const session = requireSession()
    // Die Zeremonie ZUERST, dann der Tresor, dann die Nachricht: die
    // PRF-Ausgabe geht unmittelbar in die Nachricht und wird danach nicht
    // mehr angefasst — dieselbe Regel wie beim Entsperren.
    const { credentialId, prfOutput } = await freshPrfForConfirmation()
    const sealed = await readSealedReaderVault()
    const response = raise(
      await callReaderWorker({
        kind: 'export-one',
        session,
        nowMs,
        sealed,
        credentialId,
        prfOutput,
        entryHash: bytesFromHex(entryHashHex),
        targetKind: target.kind,
        targetOccupied: target.occupied,
        organizationId: identity.organizationId,
        deviceId: identity.deviceId,
        signerCertificateObjectHash: identity.signerCertificateObjectHash,
      }),
    )
    if (response.status === undefined || response.bytes === undefined) {
      throw new Error('Der Worker hat auf den Einzelexport keinen Bericht geliefert.')
    }
    // Die Bytes sind DRAUSSEN, und Rust hat das laengst festgehalten: die
    // `Completed`-Zeile bezeugt die Uebergabe an die Senke im Worker, nicht
    // die Platte. Faellt das Schreiben hier, sagt der Fehlschlag genau das
    // und erfindet keinen Rust-Code dafuer.
    //
    // GENULLT danach, ob das Schreiben gelang oder nicht (WR-082): Rust nullt
    // seine eigenen Kopien, und der Worker hat seine abgegeben statt kopiert
    // — dieser Puffer ist die eine Kopie des Hauptthreads, und sie soll nach
    // der Uebergabe an das Ziel nirgends mehr lesbar liegen.
    try {
      await target.write(response.bytes).catch(() => {
        throw new Error(
          'Das gewählte Ziel hat die Bytes nicht angenommen. Das Audit führt die Übergabe bereits als abgeschlossen.',
        )
      })
    } finally {
      response.bytes.fill(0)
    }
    return JSON.parse(response.status) as SingleExportReportView
  },

  // BENANNTE GRENZE: der Browser-Reader traegt in diesem Stand KEIN
  // Reader-Zertifikat — das stellt die Administrationsstufe (Stufe 5) aus, und
  // mit ihm kommen Geraetekennung und Objekthash des Signierers. Ohne sie
  // gibt es keine Auditzeile, und ohne Auditzeile keinen Export: die Flaeche
  // sperrt die Bestaetigung und sagt warum. Erfundene Bytes an dieser Stelle
  // waeren eine Auditzeile, die eine Identitaet behauptet, die niemand
  // ausgestellt hat.
  auditIdentity: () => undefined,
}
