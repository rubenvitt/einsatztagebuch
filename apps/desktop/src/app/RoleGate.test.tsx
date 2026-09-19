import { readFile, readdir } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { expect, it } from 'vitest'

import { enabledRoutes, routeTable } from './role-gate'
import type { VerifiedSession } from './role-gate'

// Die Rollengrenze zwischen Desktop und Browser, in BEIDE Richtungen gemessen.
//
// `apps/desktop` traegt den Writer und die Verwaltung und sonst nichts: keine
// Reader-Route, kein Reader-Kommando. `apps/web` traegt den Reader und sonst
// nichts: keine Finalisierung, keine Root-Zeremonie, keine Provisionierung,
// kein Re-grant, keine Vernichtung. Beide Zusagen stehen in `web-reader-design.md` §3 und in
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

// Die EINZIGE Ausnahme vom Wort „destruction" im Web: die Reader-lokale
// Cacheentfernung aus Stufe 5, Task 12 („per managed replica remove … plaintext
// cache/index … collect signed attestations"). Der Reader verbraucht eine
// bereits nativ autorisierte und gestartete Anweisung (Autorisierung,
// Startnachweis, Jobdatei — Rust prueft sie vollstaendig), entfernt NUR seinen
// eigenen OPFS-Cache, liest die Messquittung und gibt seinen eigenen jobgebundenen
// Loeschbeleg aus. Er beantragt, startet, setzt fort oder bricht keinen Auftrag
// ab, signiert keine Transition und keine Autorisierung und erreicht kein
// Admin-Kommando; den Gesamtauftrag fuehrt die Desktop-Administration.
//
// GRENZE: `readerDestructionAttest` signiert frisch mit dem Vault-Ed25519 unter
// einem eigenen `deletionAttest`-Zertifikat. §3 der Web-Reader-Spec (Zeilen
// 54–56) verbietet Webcode fuer „Vernichtungsausfuehrung"; die enge Ausnahme
// fuer genau diese Mitwirkung als verwaltete Replik steht seit dem Ruling vom
// 13.09.2026 ausdruecklich in §3 (Zeilen 57–66). Dieser Zeuge prueft Woerter und
// die Methodenmenge von `ReaderDestructionBridge`. Die Faehigkeiten pruefen seit
// DRK-321 eigene Allowlists: die WASM-Exporte in
// `crates/ea-reader-wasm/tests/bridge_boundary.rs`, die Signieraufrufe der
// Reader-Crates in `crates/ea-reader/tests/signing_capability_boundary.rs` und
// die Worker-Nachrichten in `apps/web/src/bridge/worker-capabilities.test.ts`.
// Kryptographisch verweigern `ea-destruction` und `ea-reader` jeden Uebergang,
// dessen Signierer auf einem Geraet mit Reader-Zertifikat sitzt (Regel R1).
//
// Ausgenommen werden nur diese vollen Namen in genau diesen Dateien, als ganze
// Bezeichner oder als exakte Zeichenkette samt Anfuehrungszeichen. Jeder andere
// Name mit „destruction" und jedes andere verbotene Wort faellt weiter, auch in
// diesen Dateien. Ein hier gefuehrter Name, der aus seiner Datei verschwindet,
// laesst den Zeugen ebenfalls fallen, damit die Ausnahme nicht still veraltet.
const readerCacheDestructionNames: Readonly<Record<string, readonly string[]>> = {
  'bridge/opfs-worker.ts': [
    'readerDestructionApply',
    'readerDestructionApplyDelivery',
    'readerDestructionReceipt',
    'readerDestructionAttest',
    'readerDestructionAttestation',
    "'reader-destruction-apply'",
    "'reader-destruction-apply-delivery'",
    "'reader-destruction-receipt'",
    "'reader-destruction-attest'",
    "'reader-destruction-attestation'",
  ],
  'features/destruction/ReaderDestructionPage.tsx': [
    'ReaderDestructionPage',
    'ReaderDestructionPageProps',
    'ReaderDestructionBridge',
    "'./reader-destruction'",
  ],
  'features/destruction/reader-destruction.ts': [
    'ReaderDestructionBridge',
    'createReaderDestructionBridge',
    'readerDestructionBridge',
    "'reader-destruction-apply-delivery'",
    "'reader-destruction-attest'",
    "'reader-destruction-attestation'",
  ],
  'main.tsx': [
    'ReaderDestructionPage',
    'readerDestructionBridge',
    "'./features/destruction/ReaderDestructionPage'",
    "'./features/destruction/reader-destruction'",
    "'./features/destruction/files'",
  ],
  'vault/webauthn-prf.ts': ["'reader-destruction-apply'", "'reader-destruction-apply-delivery'"],
}

function withoutReaderCacheDestructionNames(file: string, text: string): string {
  let rest = text
  // Zeichenketten VOR Bezeichnern: sonst schnitte `ReaderDestructionPage` aus
  // `'./features/destruction/ReaderDestructionPage'` und der Pfad fehlte danach.
  const names = [...(readerCacheDestructionNames[file] ?? [])].sort(
    (left, right) => Number(right.startsWith("'")) - Number(left.startsWith("'")),
  )
  for (const name of names) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    // Ein Bezeichner nur als GANZES Wort: `readerDestructionApply` darf aus
    // `readerDestructionApplyStart` nichts herausschneiden.
    const pattern = new RegExp(name.startsWith("'") ? escaped : `(?<![\\w$])${escaped}(?![\\w$])`, 'g')
    expect(pattern.test(rest), `${file}: ${name}`).toBe(true)
    pattern.lastIndex = 0
    rest = rest.replace(pattern, '')
  }
  return rest
}

it('exposes no Reader route in the desktop shell', () => {
  expect(routeTable().map((route) => route.path)).toEqual(['/', '/einsatz', '/verwaltung'])
  expect(routeTable().some((route) => /reader|lese/i.test(route.label))).toBe(false)
})

// Jede Faehigkeit gehoert GENAU EINER Rolle. Eine Writer-Sitzung mit einem
// Eintrag `administration` bekommt die Verwaltung nicht, eine Admin-Sitzung mit
// einem Eintrag `capture` nicht die Erfassung — sonst genuegte ein
// Faehigkeitseintrag im Zertifikat, um die Rollengrenze zu verschieben.
it('binds each capability to exactly one verified role', () => {
  const paths = (session: VerifiedSession) => enabledRoutes(session).map((route) => route.path)
  expect(paths({ role: 'writer', capabilities: ['capture'] })).toEqual(['/', '/einsatz'])
  expect(paths({ role: 'organizationadmin', capabilities: ['administration'] })).toEqual([
    '/',
    '/verwaltung',
  ])
  expect(paths({ role: 'writer', capabilities: ['administration'] })).toEqual(['/'])
  expect(paths({ role: 'organizationadmin', capabilities: ['capture'] })).toEqual(['/'])
  expect(paths({ role: 'organizationadmin', capabilities: [] })).toEqual(['/'])
  expect(paths({ role: 'reader', capabilities: ['capture', 'administration'] })).toEqual(['/'])
  expect(paths({ role: 'writer', capabilities: ['capture', 'administration'] })).toEqual([
    '/',
    '/einsatz',
  ])
})

// „Geloescht statt portiert" heisst hier eine ERZWUNGENE Abwesenheit: ein
// `reader.rs` ist nie entstanden, und dieser Zeuge faellt, sobald eines
// einzieht. `admin.rs` traegt die Verwaltung (Stufe 5, Task 6).
// `destruction.rs` und `destruction_evidence.rs` sind Stufe 5, Task 13 (beide im
// Plan als „Create" gefuehrt): die administrative Vernichtung und die
// Finalisierung ihres Evidence-Eintrags, beide hinter
// `admin::require_administrator` — keine Reader-Leseflaeche.
it('declares no Reader command in src-tauri', async () => {
  const commands = await readdir(path.join(packageRoot, 'src-tauri/src/commands'))
  expect(commands.sort()).toEqual([
    'admin.rs',
    'destruction.rs',
    'destruction_evidence.rs',
    'master_data.rs',
    'mod.rs',
    'recovery',
    'recovery.rs',
    'session.rs',
    'sync.rs',
    'writer.rs',
  ])
})

// Die andere Richtung derselben Grenze: kein Writer, keine Administration, keine
// Root-Zeremonie, keine Provisionierung, kein Re-grant, keine Vernichtung im Web.
it('exposes no writer or administration surface in apps/web', async () => {
  const sources = await webSources()
  // Ohne diesen Zeugen laeuft die Schleife darunter ueber die leere Menge und
  // bleibt gruen — ein falscher Wurzelpfad saehe aus wie ein sauberes Web.
  expect(sources.length).toBeGreaterThan(0)
  expect(sources.map(([file]) => file)).toContain('main.tsx')
  // Jede Ausnahmedatei muss es geben; ein Tippfehler im Schluessel waere sonst
  // eine Ausnahme, die nie greift, und sahe trotzdem wie eine Regel aus.
  expect(sources.map(([file]) => file)).toEqual(
    expect.arrayContaining(Object.keys(readerCacheDestructionNames)),
  )
  for (const [file, text] of sources) {
    expect(withoutReaderCacheDestructionNames(file, text), file).not.toMatch(
      /finaliz|Root-Zeremonie|rootCeremony|provision|historicalRegrant|destruction|Entwurf verwerfen/i,
    )
    // Deutsche Oberflaechentexte fuer Auftragsschritte, die der Reader nie
    // ausfuehrt (§3). Bewusst eng: die Route `/vernichtung` mit dem Label
    // „Reader-Cache" bleibt erlaubt, ein Knopf „Vernichtung fortsetzen" nicht.
    expect(text, file).not.toMatch(
      /Vernichtung\s+(starten|fortsetzen|abbrechen|beantragen)|(Ü|Ue)bergang\s+signieren|Zustands(ü|ue)bergang/i,
    )
  }
})

// Die Ausnahme oben nimmt den NAMEN `ReaderDestructionBridge` aus dem Wortscan.
// Damit darunter keine neue Faehigkeit einzieht — etwa eine Methode `resume`
// ohne das Wort „destruction" —, ist ihre Methodenmenge hier festgeschrieben.
it('pins the methods of the exempted ReaderDestructionBridge', async () => {
  const source = await readFile(
    path.join(webSourceRoot, 'features/destruction/reader-destruction.ts'),
    'utf8',
  )
  const start = source.indexOf('export type ReaderDestructionBridge = {')
  expect(start, 'ReaderDestructionBridge type block').toBeGreaterThan(-1)
  const block = source.slice(start, source.indexOf('\n}', start))
  const methods = [...block.matchAll(/^\s*(?:readonly\s+)?([A-Za-z_$][\w$]*)\??\s*[:(]/gm)]
    .map((match) => match[1])
    .sort()
  expect(methods).toEqual(['apply', 'attest', 'historical'])
})
