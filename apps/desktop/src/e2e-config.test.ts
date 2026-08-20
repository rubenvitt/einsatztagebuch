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
