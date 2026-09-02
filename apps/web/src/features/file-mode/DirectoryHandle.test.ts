import { expect, it } from 'vitest'

import type { FileModeDirectoryHandleV1, FileModeEntryV1 } from './DirectoryHandle'
import { walkDirectoryHandle } from './DirectoryHandle'

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
