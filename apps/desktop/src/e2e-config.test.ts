// Liest `apps/desktop/playwright.config.ts` und behauptet seine tragenden
// Schluessel, ohne einen Browser zu starten: das Suchverzeichnis, das die
// E2E-Suite im PAKET verankert, den `webServer`, der die Anwendung BAUT und
// dann die gebauten Bytes ausliefert, und den Traeger des abgeschalteten
// Netzzugangs, der die Zusage von Task 16 ("PASS mit abgeschaltetem Netz")
// ueberhaupt tragen kann. Dazu die Grenze zwischen den zwei Runnern: Vitest
// darf die Playwright-Spec von Task 16 nicht einsammeln.
import { expect, it } from 'vitest'

it('runs the e2e suite from the package, against the built app, with the network off', async () => {
  const config = (await import('../playwright.config')).default
  expect(config.testDir).toBe('tests/e2e')
  expect(config.webServer?.command).toContain('vite preview')
  // WANDERT MIT DER MESSUNG. Der Brief pinnt hier `toBe(true)`; ein
  // kontextweites `offline: true` schneidet in Chromium aber die Schleife mit
  // ab (`net::ERR_INTERNET_DISCONNECTED` auf `http://127.0.0.1:4173/`,
  // gemessen), womit die gebaute Anwendung selbst nie laedt. Der Netzzugang
  // wird deshalb durch `isPreviewRequest` abgeschaltet — siehe den Zeugen
  // unten — und dieser Schluessel haelt fest, dass der Kontext NICHT offline
  // erzeugt wird.
  expect(config.use?.offline).toBe(false)
})

it('builds before it previews and pins both halves to the IPv4 loopback', async () => {
  const config = (await import('../playwright.config')).default
  const command = config.webServer.command
  expect(command).toContain('vite build')
  expect(command.indexOf('vite build')).toBeLessThan(command.indexOf('vite preview'))
  // `vite preview` bindet ohne `--host` an `localhost` und damit auf diesem
  // Rechner an `[::1]`; der Bereitschaftstest gegen `url` liefe dann ins Leere.
  expect(command).toContain('--host 127.0.0.1')
  expect(config.webServer.url).toBe('http://127.0.0.1:4173')
  expect(config.use?.baseURL).toBe(config.webServer.url)
})

it('lets the preview origin through and aborts every other request', async () => {
  const { isPreviewRequest, PREVIEW_ORIGIN } = await import('../playwright.config')
  expect(isPreviewRequest(PREVIEW_ORIGIN)).toBe(true)
  expect(isPreviewRequest(`${PREVIEW_ORIGIN}/`)).toBe(true)
  expect(isPreviewRequest(`${PREVIEW_ORIGIN}/assets/index-abc123.js`)).toBe(true)
  expect(isPreviewRequest('https://example.com/telemetry')).toBe(false)
  expect(isPreviewRequest('http://127.0.0.1:9999/')).toBe(false)
  // Die Praefixfalle: eine fremde Herkunft, die mit dem Herkunftsliteral
  // beginnt, darf NICHT durchgelassen werden.
  expect(isPreviewRequest('http://127.0.0.1:4173.angreifer.example/x')).toBe(false)
})

// Die VERDRAHTUNG des Waechters, nicht nur seine Entscheidung. Ohne diesen
// Zeugen stand der Aufruf, den Task 16 fuehren muss, nur als Kommentar in
// `playwright.config.ts` — und ein Kommentar faellt nicht. Gemessen wird gegen
// ein Kontext-Doppel, also ohne Browser und ohne `dist/`.
type Decision = 'continue' | 'abort'

function routeDouble(url: string) {
  const decisions: Decision[] = []
  const route = {
    request: () => ({ url: () => url }),
    continue: async () => {
      decisions.push('continue')
    },
    abort: async () => {
      decisions.push('abort')
    },
  }
  return { decisions, route }
}

it('wires the guard onto every request and decides it per origin', async () => {
  const { installOfflineGuard, PREVIEW_ORIGIN } = await import('../playwright.config')

  const patterns: unknown[] = []
  let handler: ((route: unknown) => unknown) | undefined
  const context = {
    route: async (pattern: unknown, given: (route: unknown) => unknown) => {
      patterns.push(pattern)
      handler = given
    },
  }

  await installOfflineGuard(context as unknown as Parameters<typeof installOfflineGuard>[0])

  // DIE REICHWEITE. Ein engeres Muster laesst die nicht getroffenen Anfragen
  // still durch, und nichts sonst wuerde das bemerken.
  expect(patterns).toEqual(['**'])
  expect(handler).toBeTypeOf('function')

  const asset = routeDouble(`${PREVIEW_ORIGIN}/assets/index-abc123.js`)
  await handler?.(asset.route)
  expect(asset.decisions).toEqual(['continue'])

  const telemetry = routeDouble('https://example.com/telemetry')
  await handler?.(telemetry.route)
  expect(telemetry.decisions).toEqual(['abort'])

  const foreignLoopback = routeDouble('http://127.0.0.1:4174/probe')
  await handler?.(foreignLoopback.route)
  expect(foreignLoopback.decisions).toEqual(['abort'])
})

it('keeps the Playwright spec of Task 16 out of the Vitest run', async () => {
  const config = (await import('../vite.config')).default
  const include = config.test?.include ?? []
  // Die EIGENSCHAFT und nicht das Literal: jedes Suchmuster ist in `src/`
  // verwurzelt, also kann keines `tests/e2e/writer-offline.spec.ts` (Task 16)
  // erreichen. Das haelt eine spaetere, berechtigte Erweiterung innerhalb von
  // `src/` aus und faellt bei jedem Muster, das darueber hinausgreift.
  expect(include.length).toBeGreaterThan(0)
  expect(include.every((pattern) => pattern.startsWith('src/'))).toBe(true)
  expect(include.some((pattern) => pattern.includes('tests/'))).toBe(false)
})
