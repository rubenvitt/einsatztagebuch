import { readFile, readdir } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { expect, it } from 'vitest'

import { routeTable } from './role-gate'

// Die Rollengrenze zwischen Desktop und Browser, in BEIDE Richtungen gemessen.
//
// `apps/desktop` traegt den Writer und sonst nichts: keine Reader-Route, kein
// Reader-Kommando. `apps/web` traegt den Reader und sonst nichts: keine
// Finalisierung, keine Root-Zeremonie, keine Provisionierung, kein Re-grant,
// keine Vernichtung. Beide Zusagen stehen in `web-reader-design.md` §3 und in
// `role-gate.ts`; dieser Zeuge liest die QUELLEN und nicht die Absicht.
//
// `packageRoot` ist `apps/desktop` — dieselbe Aufloesung wie in
// `design/bundle.test.ts`, nur eine Ebene tiefer.
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const webSourceRoot = path.resolve(packageRoot, '../web/src')
const webBridgeDirectory = path.join(webSourceRoot, 'bridge')
const webGeneratedContracts = path.join(webBridgeDirectory, 'generated-contracts.ts')
// Der Ausgang von `xtask build-wasm` — unter `src`, per `.gitignore` gehalten,
// von niemandem geschrieben. Dieselbe Grenze zieht
// `apps/web/src/bridge/no-hand-written-contracts.test.ts`.
const webGeneratedWasmGlue = path.join(webBridgeDirectory, 'pkg')

/**
 * Jede HANDGESCHRIEBENE Quelle unter `apps/web/src`: ohne die beiden
 * Generatorausgaenge und ohne die Testdateien — deren Zusicherungen duerfen
 * die verbotenen Woerter benennen, sonst koennten sie sie nicht pruefen.
 */
async function webSources(): Promise<[string, string][]> {
  const entries = await readdir(webSourceRoot, { recursive: true, withFileTypes: true })
  const files = entries
    .filter((entry) => entry.isFile())
    .map((entry) => path.join(entry.parentPath, entry.name))
    .filter((file) => /\.tsx?$/.test(file))
    .filter((file) => file !== webGeneratedContracts)
    .filter((file) => !file.startsWith(`${webGeneratedWasmGlue}${path.sep}`))
    .filter((file) => !/\.test\.tsx?$/.test(file))
    .sort()
  return Promise.all(
    files.map(
      async (file) =>
        [path.relative(webSourceRoot, file), await readFile(file, 'utf8')] as [string, string],
    ),
  )
}

it('exposes no Reader route in the desktop shell', () => {
  expect(routeTable().map((route) => route.path)).toEqual(['/', '/einsatz'])
  expect(routeTable().some((route) => /reader|lese/i.test(route.label))).toBe(false)
})

// „Geloescht statt portiert" heisst hier eine ERZWUNGENE Abwesenheit: ein
// `reader.rs` ist nie entstanden, und dieser Zeuge faellt, sobald eines
// einzieht.
it('declares no Reader command in src-tauri', async () => {
  const commands = await readdir(path.join(packageRoot, 'src-tauri/src/commands'))
  expect(commands.sort()).toEqual(['master_data.rs', 'mod.rs', 'session.rs', 'sync.rs', 'writer.rs'])
})

// Die andere Richtung derselben Grenze: kein Writer, keine Administration, keine
// Root-Zeremonie, keine Provisionierung, kein Re-grant, keine Vernichtung im Web.
it('exposes no writer or administration surface in apps/web', async () => {
  const sources = await webSources()
  // Ohne diesen Zeugen laeuft die Schleife darunter ueber die leere Menge und
  // bleibt gruen — ein falscher Wurzelpfad saehe aus wie ein sauberes Web.
  expect(sources.length).toBeGreaterThan(0)
  expect(sources.map(([file]) => file)).toContain('main.tsx')
  for (const [file, text] of sources) {
    expect(text, file).not.toMatch(
      /finaliz|Root-Zeremonie|rootCeremony|provision|historicalRegrant|destruction|Entwurf verwerfen/i,
    )
  }
})
