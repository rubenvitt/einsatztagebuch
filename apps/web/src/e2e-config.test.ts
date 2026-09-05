// Liest `apps/web/playwright.config.ts` und behauptet seine tragenden
// Schluessel, ohne einen Browser zu starten: das Suchverzeichnis, das die
// E2E-Suite im PAKET verankert, den `webServer`, der das Buendel BAUT und dann
// die gebauten Bytes ausliefert, den eigenen Port neben dem des Desktops, die
// Herkunft, unter der eine WebAuthn-Zeremonie ueberhaupt laufen darf, und die
// DREI Engine-Projekte der Browsermatrix. Dazu die Grenze zwischen den zwei
// Runnern: Vitest darf `tests/e2e/enrollment.spec.ts` nicht einsammeln.
//
// Der Zeuge ist das Spiegelbild von `apps/desktop/src/e2e-config.test.ts` und
// zugleich der Grund, aus dem `playwright.config.ts` ueberhaupt im Programm von
// `tsc` liegt: `apps/web/tsconfig.json` fuehrt die Datei in `include`, und der
// `await import(...)` hier zieht sie ein zweites Mal, unabhaengig davon.
import { expect, it } from 'vitest'

it('runs the e2e suite from the package, against the built bundle, without a context-wide offline switch', async () => {
  const config = (await import('../playwright.config')).default
  expect(config.testDir).toBe('tests/e2e')
  expect(config.webServer.command).toContain('vite preview')
  // AUSDRUECKLICH FALSCH UND NICHT VERGESSEN: ein kontextweites
  // `offline: true` schneidet in Chromium die Schleife mit ab, und die
  // Anwendung selbst laedt dann nie.
  expect(config.use.offline).toBe(false)
})

it('builds before it previews and pins both halves to the IPv4 loopback on its own port', async () => {
  const config = (await import('../playwright.config')).default
  const command = config.webServer.command
  expect(command).toContain('vite build')
  expect(command.indexOf('vite build')).toBeLessThan(command.indexOf('vite preview'))
  // `vite preview` bindet ohne `--host` an `localhost` und damit auf diesem
  // Rechner an `[::1]`; der Bereitschaftstest gegen `url` liefe dann ins Leere.
  expect(command).toContain('--host 127.0.0.1')
  // EIN ANDERER PORT als die 4173 des Desktops, damit beide Suiten
  // nebeneinander laufen — und `--strictPort`, damit eine Kollision laut
  // abbricht statt still auf einen Port auszuweichen, auf dem `url` nie
  // antwortet.
  expect(command).toContain('--port 4174')
  expect(command).toContain('--strictPort')
  expect(config.webServer.url).toBe('http://127.0.0.1:4174')
  expect(config.use.baseURL).toBe(config.webServer.url)
})

it('offers the same preview under a hostname, because WebAuthn refuses an IP relying party', async () => {
  const { WEBAUTHN_PREVIEW_ORIGIN } = await import('../playwright.config')
  const config = (await import('../playwright.config')).default
  const host = new URL(WEBAUTHN_PREVIEW_ORIGIN).hostname
  // Die EIGENSCHAFT und nicht das Literal: der Host muss ein NAME sein. Unter
  // einer IP-Adresse faellt `navigator.credentials.create` mit
  // `SecurityError: This is an invalid domain.` (gemessen), also kann der
  // Browserzeuge die Seite nicht ueber `baseURL` aufrufen.
  expect(/^[0-9.]+$/.test(host)).toBe(false)
  expect(host).not.toContain(':')
  // Und trotzdem DERSELBE Dienst: gleicher Port wie der `webServer`, sonst
  // zeigte der Zeuge auf etwas, das niemand gestartet hat.
  expect(new URL(WEBAUTHN_PREVIEW_ORIGIN).port).toBe(new URL(config.webServer.url).port)
})

it('carries exactly the three engine projects of the browser matrix, in this order', async () => {
  const config = (await import('../playwright.config')).default
  // `web-reader-design.md` §11.4 ersetzt fuer den Reader die Achsen
  // Architektur, Installerformat und Key-Provider durch Engine, Version und
  // Plattform. Die drei Playwright-Engines sind die Engine-Achse; GENAU drei,
  // in GENAU dieser Reihenfolge, damit die Matrix eine bewusste Aenderung
  // bleibt und kein Nebeneffekt — dieselbe Rolle, die dieser Zeuge vorher fuer
  // das eine Projekt `chromium` hatte.
  expect(config.projects.map(project => project.name)).toEqual(['chromium', 'firefox', 'webkit'])
  // Jedes Projekt faehrt seine eigene Engine und keine Kopie einer anderen:
  // `defaultBrowserType` ist der Wert, aus dem Playwright den Start ableitet.
  expect(config.projects.map(project => project.use.defaultBrowserType)).toEqual([
    'chromium',
    'firefox',
    'webkit',
  ])
})

it('keeps the Playwright spec out of the Vitest run', async () => {
  const config = (await import('../vite.config')).default
  const include = config.test?.include ?? []
  // Die EIGENSCHAFT und nicht das Literal: jedes Suchmuster ist in `src/`
  // verwurzelt, also kann keines `tests/e2e/enrollment.spec.ts` erreichen. Ohne
  // das faende Vitest die Spezifikation und fiele, weil `@playwright/test`
  // unter Vitest keinen Runner hat.
  expect(include.length).toBeGreaterThan(0)
  expect(include.every((pattern) => pattern.startsWith('src/'))).toBe(true)
  expect(include.some((pattern) => pattern.includes('tests/'))).toBe(false)
})
