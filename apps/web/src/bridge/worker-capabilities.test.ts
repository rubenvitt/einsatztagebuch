import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { expect, it } from 'vitest'
import type { EaOpfsRequest } from './opfs-worker'

// DRK-321: Die Reader-Grenze des Workers wird nach FÄHIGKEITEN geprüft, nicht
// nach Wörtern. Jede Nachrichtenart des einzigen Workers (`EaOpfsRequest`, der
// Hauptthread schickt `WithoutId<EaOpfsRequest>`) trägt hier genau eine
// Fähigkeit. Eine neue Art ist erst grün, wenn sie hier eingetragen ist.
//
// Die Tabelle steht bewusst NUR in dieser Testdatei: der Wortscan in
// `apps/desktop/src/app/RoleGate.test.tsx` nimmt Tests aus, eine Quelldatei mit
// den fünf `reader-destruction-*`-Strings müsste dort Ausnahmen bekommen.
//
// Es gibt keine Fähigkeit „Zustandsübergang", „Autorisierung" oder
// „Vernichtung starten/fortsetzen/abbrechen" (Web-Reader-Design §3).
type WorkerCapability =
  | 'storage'
  | 'enrollment'
  | 'vault'
  | 'session'
  | 'export'
  | 'file-mode'
  | 'view'
  | 'replica-cache-removal'
  | 'replica-attestation'
  // Die zwei Escrow-Zeremonien (Escrow-Profil §5–§7, DRK-460 Ruling Q3),
  // einschließlich der Entnahme des wiederhergestellten KEM ins Enrollment.
  | 'reader-key-escrow'

// Zwei Netze, die sich ergänzen:
// - Typzeit (`pnpm typecheck`): `satisfies Record<…>` macht eine fehlende Art
//   zum Typfehler, der Überschuss-Eigenschaftscheck eine erfundene.
// - Laufzeit (vitest, auch ohne Typprüfung): Union-Arten, `case`-Labels und
//   Tabellenschlüssel werden als Text gelesen und müssen gleich sein. Gelesen
//   wird JEDER Zeichenkettenwert in einfachen, doppelten oder Backtick-
//   Anführungszeichen, nicht nur `[a-z-]` — sonst fiele eine Art wie
//   `'…-resume2'` aus beiden Mengen heraus und bliebe unbemerkt (DRK-321, M9).
//   Zusätzlich muss jedes `kind`-Vorkommen der Union und jedes `case` des
//   Dispatchers von diesen Mustern erfasst werden.
const WORKER_CAPABILITIES = {
  put: 'storage',
  get: 'storage',
  delete: 'storage',
  'enrollment-begin': 'enrollment',
  'enrollment-register-authenticator': 'enrollment',
  'enrollment-fingerprints': 'enrollment',
  'enrollment-confirm-fingerprints': 'enrollment',
  'enrollment-finish': 'enrollment',
  'enrollment-begin-restored': 'reader-key-escrow',
  'enrollment-finish-restored': 'enrollment',
  'reader-registration-request': 'enrollment',
  'reader-key-escrow-seal-package': 'reader-key-escrow',
  'reader-key-escrow-transport-begin': 'reader-key-escrow',
  'reader-key-escrow-transport-open': 'reader-key-escrow',
  'reader-key-escrow-transport-abort': 'reader-key-escrow',
  'vault-unlock': 'vault',
  'session-note-visibility': 'session',
  'session-note-activity': 'session',
  'session-state': 'session',
  'session-lock': 'session',
  'export-one': 'export',
  'file-mode-bundle-extension': 'file-mode',
  'file-mode-open-bundle': 'file-mode',
  'file-mode-begin-directory': 'file-mode',
  'file-mode-push-blob': 'file-mode',
  'file-mode-directory-unavailable': 'file-mode',
  'file-mode-open-directory': 'file-mode',
  'reader-stand-view': 'view',
  'reader-entry-view': 'view',
  'reader-technical-view': 'view',
  'reader-amendment-thread': 'view',
  'reader-search': 'view',
  'reader-stand-close': 'view',
  'reader-destruction-apply': 'replica-cache-removal',
  'reader-destruction-apply-delivery': 'replica-cache-removal',
  'reader-destruction-receipt': 'replica-cache-removal',
  'reader-destruction-attest': 'replica-attestation',
  'reader-destruction-attestation': 'replica-attestation',
} as const satisfies Record<EaOpfsRequest['kind'], WorkerCapability>

const here = path.dirname(fileURLToPath(import.meta.url))
const read = (relative: string) => readFileSync(path.join(here, relative), 'utf8')
const sorted = (values: Iterable<string>) => [...new Set(values)].sort()

const worker = read('opfs-worker.ts')

function requestUnion(source: string): string {
  const start = source.indexOf('export type EaOpfsRequest =')
  const end = source.indexOf('export type EaOpfsResponse =')
  expect(start, 'EaOpfsRequest union in opfs-worker.ts').toBeGreaterThan(-1)
  expect(end, 'EaOpfsResponse follows the request union').toBeGreaterThan(start)
  return source.slice(start, end)
}

function wasmImports(source: string): string[] {
  const match = /import init, \{([^}]*)\} from '\.\.?\/(?:bridge\/)?pkg\/ea_reader_wasm\.js'/.exec(source)
  expect(match, 'wasm glue import').not.toBeNull()
  return (match?.[1] ?? '')
    .split(',')
    .map(name => name.trim())
    .filter(name => name.length > 0)
}

// Ein Zeichenkettenwert in '…', "…" oder `…`; Gruppe 2 ist sein Inhalt.
const quoted = "(['\"`])((?:(?!\\1).)+)\\1"

it('every worker message kind has exactly one capability, in both directions', () => {
  const union = requestUnion(worker)
  const kindPattern = new RegExp('\\bkind\\??\\s*:\\s*' + quoted, 'g')
  const casePattern = new RegExp('\\bcase\\s+' + quoted + '\\s*:', 'g')
  const declaredMatches = [...union.matchAll(kindPattern)]
  const dispatchedMatches = [...worker.matchAll(casePattern)]
  // Jedes `kind:` der Union und jedes `case` des Workers muss erfasst sein:
  // eine Form, die die Muster nicht lesen, ist rot statt unsichtbar.
  expect(declaredMatches.length, 'every kind in EaOpfsRequest is read').toBe(
    [...union.matchAll(/\bkind\??\s*:/g)].length,
  )
  expect(dispatchedMatches.length, 'every case label in opfs-worker.ts is read').toBe(
    [...worker.matchAll(/\bcase\b/g)].length,
  )
  const declared = sorted(declaredMatches.map(m => m[2] ?? ''))
  const dispatched = sorted(dispatchedMatches.map(m => m[2] ?? ''))
  const listed = sorted(Object.keys(WORKER_CAPABILITIES))
  expect(declared).toEqual(listed)
  expect(dispatched).toEqual(listed)
})

it('only the two replica capabilities touch destruction', () => {
  const byCapability = (wanted: WorkerCapability) =>
    sorted(
      Object.entries(WORKER_CAPABILITIES)
        .filter(([, capability]) => capability === wanted)
        .map(([kind]) => kind),
    )
  expect(byCapability('replica-attestation')).toEqual([
    'reader-destruction-attest',
    'reader-destruction-attestation',
  ])
  expect(byCapability('replica-cache-removal')).toEqual([
    'reader-destruction-apply',
    'reader-destruction-apply-delivery',
    'reader-destruction-receipt',
  ])
  for (const [kind, capability] of Object.entries(WORKER_CAPABILITIES)) {
    if (kind.includes('destruction')) {
      expect(['replica-attestation', 'replica-cache-removal']).toContain(capability)
    }
  }
})

// review-e F3: der Beginn des Enrollments um den wiederhergestellten KEM
// entnimmt fremdes Schluesselmaterial und steht deshalb unter der
// Escrow-Faehigkeit, nicht unter `enrollment`.
it('the escrow capability holds every message that touches escrowed key material', () => {
  expect(
    sorted(
      Object.entries(WORKER_CAPABILITIES)
        .filter(([, capability]) => capability === 'reader-key-escrow')
        .map(([kind]) => kind),
    ),
  ).toEqual([
    'enrollment-begin-restored',
    'reader-key-escrow-seal-package',
    'reader-key-escrow-transport-abort',
    'reader-key-escrow-transport-begin',
    'reader-key-escrow-transport-open',
  ])
})

it('the web imports only wasm exports pinned by the Rust capability allowlist', () => {
  const boundary = readFileSync(
    path.join(here, '../../../../crates/ea-reader-wasm/tests/bridge_boundary.rs'),
    'utf8',
  )
  const table = boundary.slice(boundary.indexOf('const WASM_EXPORTS'))
  const pinned = new Set(
    [...table.slice(0, table.indexOf('];')).matchAll(/\(\s*"([A-Za-z]+)",\s*Capability::/g)].map(
      m => m[1] ?? '',
    ),
  )
  expect(pinned.size, 'every WASM_EXPORTS row parsed').toBe(
    table.slice(0, table.indexOf('];')).split('Capability::').length - 1,
  )
  const imported = [...wasmImports(worker), ...wasmImports(read('../sw/service-worker.ts'))]
  expect(imported.filter(name => !pinned.has(name))).toEqual([])
})
