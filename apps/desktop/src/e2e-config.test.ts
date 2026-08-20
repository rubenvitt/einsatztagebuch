// Liest `apps/desktop/playwright.config.ts` und behauptet seine drei tragenden
// Schluessel, ohne einen Browser zu starten: das Suchverzeichnis, das die
// E2E-Suite im PAKET verankert, den `webServer`, der gegen die GEBAUTE
// Anwendung laeuft, und den abgeschalteten Netzzugang, der die Zusage von
// Task 16 ("PASS mit abgeschaltetem Netz") ueberhaupt tragen kann.
import { expect, it } from 'vitest'

it('runs the e2e suite from the package, against the built app, with the network off', async () => {
  const config = (await import('../playwright.config')).default
  expect(config.testDir).toBe('tests/e2e')
  expect(config.webServer?.command).toContain('vite preview')
  expect(config.use?.offline).toBe(true)
})
