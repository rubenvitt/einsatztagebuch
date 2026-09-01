// Liest `apps/web/playwright.config.ts` und behauptet seine tragenden
// Schluessel, ohne einen Browser zu starten: das Suchverzeichnis, das die
// E2E-Suite im PAKET verankert, den `webServer`, der das Buendel BAUT und dann
// die gebauten Bytes ausliefert, den eigenen Port neben dem des Desktops, die
// Herkunft, unter der eine WebAuthn-Zeremonie ueberhaupt laufen darf, und das
// EINE Browserprojekt dieses Standes. Dazu die Grenze zwischen den zwei
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

it('carries exactly one browser project, and it is chromium', async () => {
  const config = (await import('../playwright.config')).default
  // `WebAuthn.addVirtualAuthenticator` ist eine CDP-Methode; Firefox und
  // WebKit bieten kein Gegenstueck. Der Gate-Task stellt zwei weitere Projekte
  // daneben — dieser Zeuge macht die Erweiterung zu einer bewussten Aenderung
  // statt zu einem Nebeneffekt.
  expect(config.projects.length).toBe(1)
  expect(config.projects[0]?.name).toBe('chromium')
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
