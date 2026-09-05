import { readFile, readdir } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { render, screen, waitFor } from '@testing-library/react'
import { expect, it, vi } from 'vitest'

import type { ReaderSessionView, SingleExportReportView } from '../../bridge/generated-contracts'
import { userEvent } from '../../test-setup'
import type {
  ExportHost,
  ExportTargetChoice,
  ReaderAuditIdentity,
  ReaderSessionBridge,
} from '../session/reader-session'
import { chooseExportTarget } from '../session/reader-session'
import { SingleExport } from './SingleExport'

const user = userEvent.setup()

// Zwei Eintragshashes in der Schreibweise der Bruecke — 64 Hexzeichen. Sie
// sind Doppelwerte und keine Rechnung: welcher Datensatz offen ist, sagt Rust
// ueber `ReaderSessionView`, und der Zeuge liest die Liste, er baut sie nicht.
const FIRST_HASH = 'a1'.repeat(32)
const SECOND_HASH = 'b2'.repeat(32)

// Ein kurzer Poll, damit `findBy*` den ersten Lesezyklus nicht abwartet, als
// waere er eine Sekunde lang. Der Poll ist der Beschleuniger der Anzeige und
// nicht der Sperrmechanismus; kein Zeuge hier misst eine Frist.
const POLL_MS = 20

function unlockedWith(hashes: readonly string[]): ReaderSessionView {
  return { locked: false, openEntryHashes: hashes }
}

/** Eine Identitaet mit Bytes der richtigen LAENGE — Doppelwerte, keine Zertifikatsdaten. */
function someIdentity(): ReaderAuditIdentity {
  return {
    organizationId: new Uint8Array(16).fill(0x12),
    deviceId: new Uint8Array(16).fill(0x34),
    signerCertificateObjectHash: new Uint8Array(32).fill(0x56),
  }
}

/**
 * Ein Wirt MIT Dateidialog, dessen Handle eine LEERE Datei nennt.
 *
 * Der Name des Handles kommt hier ausdruecklich nicht vor: die Flaeche darf
 * ihn nicht sehen, also gibt das Doppel auch keinen heraus.
 */
function hostWithSavePicker(): ExportHost {
  return {
    showSaveFilePicker: vi.fn(async () => ({
      getFile: async () => ({ size: 0 }),
      createWritable: async () => ({ write: async () => undefined, close: async () => undefined }),
    })),
  }
}

/** Das Bruecken-Doppel: jedes Glied ein `vi.fn()`, der Zustand ein fester Wert. */
function bridgeWith(options: {
  readonly view: ReaderSessionView | undefined
  readonly identity: ReaderAuditIdentity | undefined
  readonly exportOne?: ReaderSessionBridge['exportOne']
}): ReaderSessionBridge {
  return {
    unlock: vi.fn(async () => undefined),
    stateAt: vi.fn(async () => options.view),
    noteVisibility: vi.fn(async () => undefined),
    noteActivity: vi.fn(async () => undefined),
    exportOne:
      options.exportOne ??
      vi.fn(async () => {
        throw new Error('exportOne darf in diesem Zeugen nicht gerufen werden.')
      }),
    auditIdentity: vi.fn(() => options.identity),
  }
}

function exportButton(): HTMLElement {
  return screen.getByRole('button', { name: 'Export bestätigen' })
}

function unlockButton(): HTMLElement {
  return screen.getByRole('button', { name: 'Sitzung entsperren' })
}

/**
 * Ohne Sitzung sagt die Flaeche genau das, und die Bestaetigung ist gesperrt.
 *
 * `stateAt` liefert `undefined` — „nie eroeffnet" —, und das ist nicht
 * dasselbe wie „gesperrt": der Leser soll wissen, dass er entsperren muss,
 * und nicht, dass eine Frist abgelaufen ist.
 */
it('reports no session and keeps the confirmation disabled', async () => {
  const bridge = bridgeWith({ view: undefined, identity: someIdentity() })
  render(<SingleExport bridge={bridge} host={hostWithSavePicker()} pollIntervalMs={POLL_MS} />)

  expect(await screen.findByTestId('session-state')).toHaveTextContent('Keine Sitzung')
  expect(exportButton()).toBeDisabled()
  expect(screen.getByText('Kein Datensatz geöffnet.')).toBeInTheDocument()
  // ANTI-LEERLAUF: die Flaeche hat den Zustand tatsaechlich GELESEN — sonst
  // waere „Keine Sitzung" der Anfangswert und keine Aussage.
  expect(bridge.stateAt).toHaveBeenCalled()
})

/**
 * Entsperrt mit zwei Datensaetzen: beide stehen zur Wahl, und die Bestaetigung
 * geht erst an, wenn Datensatz UND Ziel gewaehlt sind.
 *
 * Die Reihenfolge der Zusicherungen ist die Aussage: nach der Wahl des
 * Datensatzes allein bleibt die Bestaetigung gesperrt, nach der Zielwahl
 * allein ebenso — beides muss bewusst geschehen sein (§8.2).
 */
it('renders one radio option per open record and enables the export only after record and target are chosen', async () => {
  const bridge = bridgeWith({ view: unlockedWith([FIRST_HASH, SECOND_HASH]), identity: someIdentity() })
  render(<SingleExport bridge={bridge} host={hostWithSavePicker()} pollIntervalMs={POLL_MS} />)

  expect(await screen.findByTestId('session-state')).toHaveTextContent('Sitzung entsperrt')
  // Offen heisst: keine zweite Zeremonie neben der offenen Sitzung (§6.5
  // verlangt sie nach einer SPERRE), also ist das Entsperren gesperrt.
  expect(unlockButton()).toBeDisabled()
  const first = await screen.findByRole('radio', { name: FIRST_HASH })
  expect(screen.getByRole('radio', { name: SECOND_HASH })).toBeInTheDocument()
  expect(exportButton()).toBeDisabled()

  await user.click(first)
  expect(exportButton()).toBeDisabled()

  await user.click(screen.getByRole('button', { name: 'Ziel wählen' }))
  expect(await screen.findByTestId('target-kind')).toHaveTextContent('Ziel: Datei')
  expect(exportButton()).toBeEnabled()
})

/**
 * Ohne Reader-Zertifikat gibt es keine Auditzeile und deshalb keinen Export.
 *
 * Die Flaeche SAGT das und sperrt; sie erfindet keine Identitaet. Der
 * Anti-Leerlauf ist der Aufruf, der NICHT stattfand: eine Flaeche, die trotz
 * fehlender Identitaet exportierte, riefe `exportOne`.
 */
it('warns about the missing reader certificate and never calls exportOne without an identity', async () => {
  const bridge = bridgeWith({ view: unlockedWith([FIRST_HASH]), identity: undefined })
  render(<SingleExport bridge={bridge} host={hostWithSavePicker()} pollIntervalMs={POLL_MS} />)

  expect(await screen.findByText('Kein Reader-Zertifikat auf diesem Gerät')).toBeInTheDocument()
  await user.click(await screen.findByRole('radio', { name: FIRST_HASH }))
  await user.click(screen.getByRole('button', { name: 'Ziel wählen' }))
  expect(await screen.findByTestId('target-kind')).toHaveTextContent('Ziel: Datei')

  expect(exportButton()).toBeDisabled()
  await user.click(exportButton())
  expect(bridge.exportOne).not.toHaveBeenCalled()
  expect(screen.queryByTestId('export-report')).not.toBeInTheDocument()
})

/**
 * Gesperrt: der Wortlaut sagt es, die Liste ist leer, die Bestaetigung ist
 * gesperrt.
 *
 * Die leere Liste kommt aus Rust — nach der Sperre sind die Datensaetze mit
 * dem Tresor gefallen — und die Flaeche zeigt sie so, wie sie kommt.
 */
it('reports a locked session with no records and keeps the confirmation disabled', async () => {
  const bridge = bridgeWith({ view: { locked: true, openEntryHashes: [] }, identity: someIdentity() })
  render(<SingleExport bridge={bridge} host={hostWithSavePicker()} pollIntervalMs={POLL_MS} />)

  expect(await screen.findByTestId('session-state')).toHaveTextContent('Sitzung gesperrt')
  expect(screen.getByText('Kein Datensatz geöffnet.')).toBeInTheDocument()
  expect(screen.queryByRole('radio')).not.toBeInTheDocument()
  expect(exportButton()).toBeDisabled()
  // Nach der Sperre ist die erneute Bestaetigung die Handlung des Lesers.
  expect(unlockButton()).toBeEnabled()
})

// Zwei feste Zeitwerte der Seitenuhr, dreissig Sekunden auseinander. Feste
// Werte und kein `Date.now()` des Zeugen, damit der erwartete Wortlaut eine
// Konstante ist und nicht dieselbe Rechnung wie in der Flaeche.
const FIRST_READ_MS = Date.UTC(2026, 8, 4, 10, 0, 0)
const SECOND_READ_MS = FIRST_READ_MS + 30_000

/**
 * Der Stand des letzten gelungenen Lesens ist die UHR DER SEITE zum Zeitpunkt
 * des Lesens — nicht der Zeitpunkt des Renderns und nicht ein Anfangswert.
 *
 * Nur `Date` wird gefaelscht, die Timer bleiben echt: der Poll soll wirklich
 * laufen und mit der gesprungenen Uhr lesen. ANTI-LEERLAUF in zwei Formen:
 * die zwei Wortlaute sind verschieden, und die Bruecke bekam BEIDE Zeitwerte
 * als Argument — der Text ist also das Echo des Lesens und keine zweite Uhr.
 */
it('renders the page clock of the last successful state read and follows it when the clock jumps', async () => {
  vi.useFakeTimers({ now: FIRST_READ_MS, toFake: ['Date'] })
  try {
    const bridge = bridgeWith({ view: unlockedWith([FIRST_HASH]), identity: someIdentity() })
    render(<SingleExport bridge={bridge} host={hostWithSavePicker()} pollIntervalMs={POLL_MS} />)

    const readAt = await screen.findByTestId('session-read-at')
    expect(readAt).toHaveTextContent(`Stand: ${new Date(FIRST_READ_MS).toISOString()}`)
    expect(bridge.stateAt).toHaveBeenCalledWith(FIRST_READ_MS)

    vi.setSystemTime(SECOND_READ_MS)
    await waitFor(() => {
      expect(readAt).toHaveTextContent(`Stand: ${new Date(SECOND_READ_MS).toISOString()}`)
    })
    expect(bridge.stateAt).toHaveBeenCalledWith(SECOND_READ_MS)
    expect(new Date(FIRST_READ_MS).toISOString()).not.toBe(new Date(SECOND_READ_MS).toISOString())
  } finally {
    vi.useRealTimers()
  }
})

/**
 * Ein Fehlschlag des Polls wird vom naechsten gelungenen Lesen aufgehoben;
 * eine Weigerung des Exports bleibt daneben stehen.
 *
 * Zwei Felder und nicht eines: der Poll liest jede Sekunde, und ein
 * gemeinsames Feld wischte den Code der Weigerung nach einem Zyklus weg.
 */
it('clears a failed state read on the next successful poll and keeps an export refusal standing', async () => {
  let reads = 0
  const stateAt = vi.fn(async (): Promise<ReaderSessionView> => {
    reads += 1
    if (reads === 1) {
      throw new Error('EA-READER-BLOB-HOST')
    }
    return unlockedWith([FIRST_HASH])
  })
  const bridge = {
    ...bridgeWith({
      view: undefined,
      identity: someIdentity(),
      exportOne: vi.fn(async () => {
        throw new Error('EA-READER-EXPORT-TARGET-OCCUPIED')
      }),
    }),
    stateAt,
  }
  render(<SingleExport bridge={bridge} host={hostWithSavePicker()} pollIntervalMs={POLL_MS} />)

  expect(await screen.findByText('EA-READER-BLOB-HOST')).toBeInTheDocument()
  await waitFor(() => {
    expect(screen.queryByText('EA-READER-BLOB-HOST')).not.toBeInTheDocument()
  })
  expect(stateAt.mock.calls.length).toBeGreaterThan(1)

  await user.click(await screen.findByRole('radio', { name: FIRST_HASH }))
  await user.click(screen.getByRole('button', { name: 'Ziel wählen' }))
  await screen.findByText('Ziel: Datei')
  await user.click(exportButton())
  const refusal = await screen.findByText('EA-READER-EXPORT-TARGET-OCCUPIED')
  // Mehrere Polls spaeter steht die Weigerung noch.
  const readsAtRefusal = stateAt.mock.calls.length
  await waitFor(() => {
    expect(stateAt.mock.calls.length).toBeGreaterThan(readsAtRefusal + 2)
  })
  expect(refusal).toBeInTheDocument()
})

/**
 * Eine Zielart, die das DTO nicht kennt, heisst „unbekannt" — und nicht
 * „Download", nur weil sie nicht die Datei ist.
 */
it('renders an unknown target kind as unknown instead of as a download', async () => {
  const bridge = bridgeWith({
    view: unlockedWith([FIRST_HASH]),
    identity: someIdentity(),
    exportOne: vi.fn(async (): Promise<SingleExportReportView> => ({ entryHash: FIRST_HASH, targetKind: 7 })),
  })
  render(<SingleExport bridge={bridge} host={hostWithSavePicker()} pollIntervalMs={POLL_MS} />)

  await user.click(await screen.findByRole('radio', { name: FIRST_HASH }))
  await user.click(screen.getByRole('button', { name: 'Ziel wählen' }))
  await screen.findByText('Ziel: Datei')
  await user.click(exportButton())

  const reportNode = await screen.findByTestId('export-report')
  expect(reportNode).toHaveTextContent('Zielart: unbekannt')
  expect(reportNode).not.toHaveTextContent('Download')
})

/**
 * Ein gelungener Export: der Bericht traegt Entry-Hash und Zielart aus dem
 * DTO, und die Bruecke bekam den GEWAEHLTEN Datensatz und die GEWAEHLTE
 * Zielart — nicht den ersten der Liste und nicht eine Vorgabe.
 */
it('renders the report of a successful export and passes the chosen record and target kind to the bridge', async () => {
  const exportOne = vi.fn(
    async (request: {
      readonly entryHashHex: string
      readonly target: ExportTargetChoice
    }): Promise<SingleExportReportView> => ({
      entryHash: request.entryHashHex,
      targetKind: request.target.kind,
    }),
  )
  const bridge = bridgeWith({
    view: unlockedWith([FIRST_HASH, SECOND_HASH]),
    identity: someIdentity(),
    exportOne,
  })
  render(<SingleExport bridge={bridge} host={hostWithSavePicker()} pollIntervalMs={POLL_MS} />)

  await user.click(await screen.findByRole('radio', { name: SECOND_HASH }))
  await user.click(screen.getByRole('button', { name: 'Ziel wählen' }))
  await screen.findByText('Ziel: Datei')
  await user.click(exportButton())

  const reportNode = await screen.findByTestId('export-report')
  expect(reportNode).toHaveTextContent(`Entry-Hash: ${SECOND_HASH}`)
  expect(reportNode).toHaveTextContent('Zielart: Datei')
  expect(exportOne).toHaveBeenCalledTimes(1)
  const request = exportOne.mock.calls[0]?.[0]
  expect(request?.entryHashHex).toBe(SECOND_HASH)
  expect(request?.target.kind).toBe(1)
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()
})

/**
 * Eine Weigerung erscheint als der ROHE Code und ohne Bericht.
 *
 * `EA-READER-EXPORT-TARGET-OCCUPIED` ist eine Aussage von Rust; die Flaeche
 * uebersetzt sie nicht und legt keinen Bericht daneben, der zu einem Export
 * gehoerte, den es nicht gab.
 */
it('renders the raw refusal code and no report when the bridge refuses', async () => {
  const bridge = bridgeWith({
    view: unlockedWith([FIRST_HASH]),
    identity: someIdentity(),
    exportOne: vi.fn(async () => {
      throw new Error('EA-READER-EXPORT-TARGET-OCCUPIED')
    }),
  })
  render(<SingleExport bridge={bridge} host={hostWithSavePicker()} pollIntervalMs={POLL_MS} />)

  await user.click(await screen.findByRole('radio', { name: FIRST_HASH }))
  await user.click(screen.getByRole('button', { name: 'Ziel wählen' }))
  await screen.findByText('Ziel: Datei')
  await user.click(exportButton())

  expect(await screen.findByText('EA-READER-EXPORT-TARGET-OCCUPIED')).toBeInTheDocument()
  expect(screen.queryByTestId('export-report')).not.toBeInTheDocument()
  expect(bridge.exportOne).toHaveBeenCalledTimes(1)
})

/**
 * Die Zielwahl ohne Dateidialog ist der Download, und ein abgebrochener
 * Dialog ist KEIN Ziel.
 *
 * Der Schluessel FEHLT im Wirt ohne Dialog und steht nicht auf `undefined` —
 * dieselbe Sorgfalt wie bei `hostWithoutPicker` im Datei-Modus. Der
 * Abbruch ist ein `AbortError`, so wie der Browser ihn wirft; er ist keine
 * Weigerung und bekommt keinen Code.
 */
it('falls back to the download target without a save picker and treats a cancelled picker as no choice', async () => {
  const withoutPicker: ExportHost = {}
  expect('showSaveFilePicker' in withoutPicker).toBe(false)
  const download = await chooseExportTarget(withoutPicker)
  expect(download?.kind).toBe(2)
  expect(download?.occupied).toBe(false)

  const cancelled: ExportHost = {
    showSaveFilePicker: vi.fn(async () => {
      throw new DOMException('abgebrochen', 'AbortError')
    }),
  }
  expect(await chooseExportTarget(cancelled)).toBeUndefined()

  // Und ein Handle auf eine Datei MIT Inhalt wird als besetzt gemeldet —
  // gemeldet, nicht abgewiesen: die Weigerung gehoert Rust.
  const occupied: ExportHost = {
    showSaveFilePicker: vi.fn(async () => ({
      getFile: async () => ({ size: 1 }),
      createWritable: async () => ({ write: async () => undefined, close: async () => undefined }),
    })),
  }
  expect((await chooseExportTarget(occupied))?.occupied).toBe(true)
})

/**
 * Das Dateiziel schreibt und schliesst in dieser Reihenfolge — und bricht den
 * Stream ab, wenn das Schreiben faellt, statt ihn zu schliessen.
 *
 * `close` nach einem gefallenen `write` schriebe den Teilstand der Swap-Datei
 * an den gewaehlten Ort; `abort` verwirft ihn (§8.2). Der Grund des
 * Fehlschlags reist unveraendert weiter.
 */
it('writes then closes the chosen file and aborts the writable instead of closing it when the write fails', async () => {
  const order: string[] = []
  const succeeding: ExportHost = {
    showSaveFilePicker: vi.fn(async () => ({
      getFile: async () => ({ size: 0 }),
      createWritable: async () => ({
        write: async () => {
          order.push('write')
        },
        close: async () => {
          order.push('close')
        },
        abort: async () => {
          order.push('abort')
        },
      }),
    })),
  }
  const target = await chooseExportTarget(succeeding)
  await target?.write(new Uint8Array([1, 2, 3]))
  expect(order).toEqual(['write', 'close'])

  const abort = vi.fn(async () => undefined)
  const close = vi.fn(async () => undefined)
  const failing: ExportHost = {
    showSaveFilePicker: vi.fn(async () => ({
      getFile: async () => ({ size: 0 }),
      createWritable: async () => ({
        write: async () => {
          throw new Error('kein Platz')
        },
        close,
        abort,
      }),
    })),
  }
  const failingTarget = await chooseExportTarget(failing)
  await expect(failingTarget?.write(new Uint8Array([1, 2, 3]))).rejects.toThrow('kein Platz')
  expect(abort).toHaveBeenCalledTimes(1)
  expect(close).not.toHaveBeenCalled()
})

// ---------------------------------------------------------------------------
// WR-082 als Code und nicht als Vorsatz
// ---------------------------------------------------------------------------

const exportDirectory = path.dirname(fileURLToPath(import.meta.url))
const sourceRoot = path.resolve(exportDirectory, '../..')
const generatedContracts = path.join(sourceRoot, 'bridge', 'generated-contracts.ts')
const generatedWasmGlue = path.join(sourceRoot, 'bridge', 'pkg')

/**
 * Jede HANDGESCHRIEBENE Quelle unter `src` — dieselbe Sammelregel wie in
 * `bridge/no-hand-written-contracts.test.ts`: ohne die zwei
 * Generatorausgaenge und ohne die Testdateien, deren Zusicherungen die
 * verbotenen Namen nennen MUESSEN.
 */
async function handWrittenSources(): Promise<[string, string][]> {
  const entries = await readdir(sourceRoot, { recursive: true, withFileTypes: true })
  const files = entries
    .filter(entry => entry.isFile())
    .map(entry => path.join(entry.parentPath, entry.name))
    .filter(file => /\.tsx?$/.test(file))
    .filter(file => file !== generatedContracts)
    .filter(file => !file.startsWith(`${generatedWasmGlue}${path.sep}`))
    .filter(file => !/\.test\.tsx?$/.test(file))
    .sort()
  return Promise.all(
    files.map(
      async file =>
        [path.relative(sourceRoot, file), await readFile(file, 'utf8')] as [string, string],
    ),
  )
}

/**
 * Das Praedikat, EINMAL geschrieben und zweimal benutzt: ueber jeder Quelle
 * und ueber der Positivkontrolle.
 *
 * `console.` ohne Einschraenkung: WR-082 verbietet den Konsolenaufruf mit
 * einem entschluesselten DTO als Argument, und ob ein Argument ein solches
 * ist, kann eine Textsuche nicht sagen. „Kein Konsolenaufruf ueberhaupt" ist
 * die STAERKERE, mechanisch pruefbare Form derselben Zusage.
 */
function forbiddenLeakCall(text: string): string | undefined {
  return ['navigator.clipboard', 'execCommand(', 'sendBeacon', 'console.'].find(needle =>
    text.includes(needle),
  )
}

it('keeps every hand written source free of clipboard, beacon and console calls', async () => {
  const sources = await handWrittenSources()
  // ANTI-LEERLAUF ueber der Quellenmenge: ein falscher Wurzelpfad liefert
  // eine leere Menge, und die Schleife darunter iteriert ueber nichts.
  expect(sources.length).toBeGreaterThan(0)
  expect(sources.map(([file]) => file)).toContain(path.join('features', 'export', 'SingleExport.tsx'))
  for (const [file, text] of sources) {
    expect(forbiddenLeakCall(text), file).toBeUndefined()
  }
  // POSITIVKONTROLLE: dasselbe Praedikat FINDET einen Treffer, wenn es einen
  // gibt. Ohne sie waere ein Praedikat, das nie trifft, von einem Baum ohne
  // Treffer nicht zu unterscheiden.
  expect(forbiddenLeakCall("await navigator.clipboard.writeText(hash)")).toBe('navigator.clipboard')
  expect(forbiddenLeakCall("console.log(view)")).toBe('console.')
})
