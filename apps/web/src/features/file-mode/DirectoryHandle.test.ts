import { expect, it } from 'vitest'

import type { FileModeArchiveView } from '../../bridge/generated-contracts'
import { SERVER_CONFIRMATION_V1_VALUES } from '../../bridge/generated-contracts'
import type { ReaderWorkerMessage } from '../../vault/webauthn-prf'
import type {
  FileModeDirectoryHandleV1,
  FileModeEntryV1,
  FileModeWorkerPort,
} from './DirectoryHandle'
import { openDirectoryOverPort, walkDirectoryHandle } from './DirectoryHandle'

/**
 * Eine Datei, deren Inhalt ihr eigener Name in Bytes ist.
 *
 * So misst der Zeuge unten nicht nur die REIHENFOLGE der Aufrufe, sondern auch
 * die Zuordnung von Pfadhinweis und Bytefolge: eine Vertauschung faellt an der
 * Gleichheit der zwei Spalten auf und nicht erst irgendwo in Rust.
 */
function file(name: string): FileModeEntryV1 {
  return {
    kind: 'file',
    getFile: async () => ({
      arrayBuffer: async () => new TextEncoder().encode(name).buffer as ArrayBuffer,
    }),
  }
}

/**
 * Ein Ordner, dessen `entries()` in der ANGEGEBENEN Reihenfolge liefert.
 *
 * Das Doppel gibt die Eintraege AUSDRUECKLICH unsortiert heraus, denn genau das
 * ist die Lage im Browser: `FileSystemDirectoryHandle.entries()` sagt keine
 * Ordnung zu. Ein Doppel, das schon sortiert liefert, machte den Zeugen gruen,
 * ohne dass der Durchlauf je etwas sortiert haette.
 */
function directory(entries: readonly (readonly [string, FileModeEntryV1])[]): FileModeDirectoryHandleV1 {
  return {
    kind: 'directory',
    entries: () => ({
      [Symbol.asyncIterator]: async function* iterate() {
        for (const entry of entries) {
          yield entry
        }
      },
    }),
  }
}

/**
 * Die einzige Ordnung, die der Durchlauf herstellt: je Ebene aufsteigend, und
 * an Ort und Stelle abgestiegen.
 *
 * Die erwartete Liste steht ausgeschrieben und wird nicht aus der Eingabe
 * gerechnet — eine berechnete Erwartung wiederholte die Umsetzung und waere
 * gegen denselben Denkfehler blind. Sie enthaelt AUSDRUECKLICH den Fall, der
 * die ebenenweise Ordnung von der globalen unterscheidet: `objekte-a.eip`
 * steht ueber die vollen Adressbytes VOR `objekte/b.eip` (`0x2D` vor `0x2F`),
 * ebenenweise aber DAHINTER. Der Durchlauf stellt die globale Ordnung
 * ausdruecklich nicht her, und dieser Zeuge schreibt das fest, statt es
 * offenzulassen.
 */
it('yields every level in ascending name order and descends in place', async () => {
  const tree = directory([
    ['zuletzt.eip', file('zuletzt.eip')],
    [
      'objekte',
      directory([
        ['b.eip', file('objekte/b.eip')],
        ['a.eip', file('objekte/a.eip')],
      ]),
    ],
    ['objekte-a.eip', file('objekte-a.eip')],
    ['anfang.eag', file('anfang.eag')],
  ])

  const seen: string[] = []
  const carried: string[] = []
  await walkDirectoryHandle(tree, async (pathHint, bytes) => {
    seen.push(pathHint)
    carried.push(new TextDecoder().decode(bytes))
  })

  expect(seen).toEqual([
    'anfang.eag',
    'objekte/a.eip',
    'objekte/b.eip',
    'objekte-a.eip',
    'zuletzt.eip',
  ])
  // Die Bytes gehoeren zu ihrem Pfadhinweis und nicht zu irgendeinem.
  expect(carried).toEqual(seen)
})

/**
 * Jede Bytefolge geht EINZELN hinueber, und der Durchlauf wartet auf jede.
 *
 * Ohne diese Zusicherung koennte die Umsetzung alle Dateien nebenlaeufig
 * anstossen; die Reihenfolge oben bliebe zufaellig richtig, und die zwei
 * Deckel in Rust faenden einen Bestand vor, den sie in der falschen Reihenfolge
 * abweisen.
 */
it('hands over one byte sequence at a time and waits for each', async () => {
  const tree = directory([
    ['zweite.eip', file('zweite.eip')],
    ['erste.eip', file('erste.eip')],
  ])

  let inFlight = 0
  let overlapped = false
  const pushes: string[] = []
  await walkDirectoryHandle(tree, async pathHint => {
    inFlight += 1
    overlapped ||= inFlight > 1
    await Promise.resolve()
    pushes.push(pathHint)
    inFlight -= 1
  })

  expect(overlapped).toBe(false)
  expect(pushes).toEqual(['erste.eip', 'zweite.eip'])
})

// ---------------------------------------------------------------------------
// Der GANZE Zug des Komfortweges: anfangen, durchlaufen, vermerken, öffnen
// ---------------------------------------------------------------------------

/**
 * Die Ordnerkennung, die das Worker-Doppel herausgibt.
 *
 * Sie steht EINMAL und ist ausdrücklich nicht die Sitzungskennung darunter:
 * beide reisen als Zahl, und eine Verwechslung der zwei träfe in Rust auf
 * `EA-READER-FILE-MODE-BRIDGE-ARGUMENT` — eine Meldung, der niemand ansieht,
 * welche der zwei Kennungen falsch war.
 */
const DIRECTORY_FROM_THE_WORKER = 7
const VAULT_SESSION = 42

/** Der Wortlaut kommt aus der GENERIERTEN Datei und wird nie abgeschrieben. */
const OPENED_VIEW: FileModeArchiveView = {
  archiveObjectCount: 4,
  entryPackageCount: 1,
  fullyVerified: true,
  gapCount: 0,
  serverConfirmedCount: 0,
  notServerConfirmedCount: 1,
  serverConfirmation: SERVER_CONFIRMATION_V1_VALUES[1],
}

/**
 * Ein Ordner, der seinen Berechtigungsstand NACHEINANDER so beantwortet, wie
 * die Antworten übergeben werden.
 *
 * Nacheinander und nicht einmal für immer, weil genau das die Lage ist, gegen
 * die die zweite Frage steht: der Entzug fällt dem Handle erst beim nächsten
 * Zugriff auf, also mitten im Durchlauf. Die letzte Antwort gilt fort, damit
 * ein Zeuge nicht zählen muss, wie oft gefragt wird — das wäre eine Zusage
 * über die Umsetzung und nicht über ihre Wirkung.
 */
function answering(
  handle: FileModeDirectoryHandleV1,
  ...answers: readonly string[]
): FileModeDirectoryHandleV1 {
  let asked = 0
  return {
    ...handle,
    queryPermission: async () => {
      const answer = answers[Math.min(asked, answers.length - 1)] ?? 'granted'
      asked += 1
      return answer
    },
  }
}

/**
 * Der Worker als Doppel: er merkt sich JEDE Nachricht und antwortet ohne
 * Befund.
 *
 * Er entscheidet ausdrücklich nichts — kein Deckel, keine Magie, kein
 * Bestätigungswert. Was dieser Zeuge misst, ist WELCHE Nachrichten in welcher
 * Reihenfolge über die Brücke gehen; was aus ihnen wird, messen die
 * Rust-Zeugen in `crates/ea-reader/tests/file_mode.rs`.
 */
function workerDouble(): {
  readonly sent: ReaderWorkerMessage[]
  readonly port: FileModeWorkerPort
} {
  const sent: ReaderWorkerMessage[] = []
  const port: FileModeWorkerPort = async request => {
    sent.push(request)
    if (request.kind === 'file-mode-begin-directory') {
      return { id: 0, ok: true, status: String(DIRECTORY_FROM_THE_WORKER) }
    }
    if (request.kind === 'file-mode-open-directory') {
      return { id: 0, ok: true, status: JSON.stringify(OPENED_VIEW) }
    }
    return { id: 0, ok: true }
  }
  return { sent, port }
}

/** Die Nachrichtenarten in der Reihenfolge ihres Absendens. */
function kinds(sent: readonly ReaderWorkerMessage[]): string[] {
  return sent.map(message => message.kind)
}

/**
 * Der vollständige Zug über einem Ordner, der die ganze Zeit liefert.
 *
 * Die Zusicherung über die AUSBLEIBENDE Ausfallmeldung ist die Positivkontrolle
 * zum Zeugen darunter: ohne sie wäre der dortige Nachweis auch dann grün, wenn
 * der Ausfall bedingungslos gemeldet würde — und dann stünde über jedem
 * geöffneten Ordner `EA-ARCHIVE-UNAVAILABLE`.
 */
it('carries every file to the worker and then opens the directory it began', async () => {
  const tree = answering(
    directory([
      ['zweite.eip', file('zweite.eip')],
      ['erste.eip', file('erste.eip')],
    ]),
    'granted',
  )
  const { sent, port } = workerDouble()

  const view = await openDirectoryOverPort(tree, VAULT_SESSION, port)

  expect(kinds(sent)).toEqual([
    'file-mode-begin-directory',
    'file-mode-push-blob',
    'file-mode-push-blob',
    'file-mode-open-directory',
  ])
  // Die Bytes werden ENTZIFFERT verglichen und nicht als `Uint8Array`: in jsdom
  // stammt der `TextEncoder` aus einem anderen Realm als das globale
  // `Uint8Array`, und `toEqual` zweier Ansichten mit verschiedenem Prototyp
  // scheitert mit „no visual difference" — ein Fehlschlag, der nichts über die
  // Brücke sagt. Die Kulisse legt den Namen als Inhalt ab, also fällt eine
  // vertauschte Zuordnung an der Gleichheit der zwei Spalten auf.
  expect(sent.filter(message => message.kind === 'file-mode-push-blob')).toMatchObject([
    { handle: DIRECTORY_FROM_THE_WORKER, pathHint: 'erste.eip' },
    { handle: DIRECTORY_FROM_THE_WORKER, pathHint: 'zweite.eip' },
  ])
  expect(
    sent
      .filter(message => message.kind === 'file-mode-push-blob')
      .map(message => new TextDecoder().decode(message.bytes)),
  ).toEqual(['erste.eip', 'zweite.eip'])
  // Geöffnet wird der Ordner, den derselbe Zug angefangen hat, unter der
  // Sitzung, die ihm übergeben wurde — die zwei Zahlen sind nicht dieselbe.
  expect(sent.at(-1)).toMatchObject({
    kind: 'file-mode-open-directory',
    session: VAULT_SESSION,
    handle: DIRECTORY_FROM_THE_WORKER,
  })
  expect(view).toEqual(OPENED_VIEW)
})

/**
 * Der Entzug MITTEN im Durchlauf wird vermerkt, bevor geöffnet wird.
 *
 * Das ist die Zusicherung, an der ohne diesen Zeugen ein halbes Archiv als
 * ganzes durchginge: die gelieferten Dateien sind für sich gültig, eine
 * Abschneidung am Kettenende erzeugt keine Lücke, und der Bericht stünde auf
 * `fullyVerified`. Der Vermerk ist der einzige Zug, der Rust
 * `EA-ARCHIVE-UNAVAILABLE` sagen lässt — TypeScript erfindet den Code nicht.
 */
it('marks the folder unavailable when the permission is withdrawn during the walk', async () => {
  const tree = answering(directory([['erste.eip', file('erste.eip')]]), 'granted', 'denied')
  const { sent, port } = workerDouble()

  await openDirectoryOverPort(tree, VAULT_SESSION, port)

  expect(kinds(sent)).toEqual([
    'file-mode-begin-directory',
    'file-mode-push-blob',
    'file-mode-directory-unavailable',
    'file-mode-open-directory',
  ])
  expect(sent[2]).toEqual({
    kind: 'file-mode-directory-unavailable',
    handle: DIRECTORY_FROM_THE_WORKER,
  })
})

/**
 * Ein Ordner, der schon vor dem ersten Zugriff nicht mehr liefert, gibt KEINE
 * einzige Bytefolge ab.
 *
 * Der angefangene Griff wird trotzdem eingelöst: er ist der einzige Zug, der
 * die Quelle aus der Tabelle des Workers nimmt, und ein Teilbestand, der dort
 * liegen bliebe, wäre genau der halbe Bestand, den dieser Modus nicht
 * beurteilen darf.
 */
it('hands over not a single byte when the folder is already closed', async () => {
  const tree = answering(directory([['erste.eip', file('erste.eip')]]), 'denied')
  const { sent, port } = workerDouble()

  await openDirectoryOverPort(tree, VAULT_SESSION, port)

  expect(kinds(sent)).toEqual([
    'file-mode-begin-directory',
    'file-mode-directory-unavailable',
    'file-mode-open-directory',
  ])
})
