import type { PlaywrightTestConfig } from '@playwright/test'

// Die Vorschau der GEBAUTEN Anwendung. `vite preview` liefert `dist/`, also
// genau die Bytes, die ins Tauri-Paket eingehen — nicht den Dev-Server mit
// seiner Modultransformation zur Laufzeit. `vite preview` BAUT nicht, deshalb
// steht `vite build` im selben Kommando davor: ohne den Vorlauf bricht der
// `webServer` mit 'The directory "dist" does not exist' ab, und zwar VOR der
// Testsuche, also ist die ganze Kette rot (gemessen).
const PREVIEW_PORT = 4173

// AUF DIE IPv4-SCHLEIFE GEPINNT, in beiden Haelften. `vite preview` bindet ohne
// `--host` an den Namen `localhost`, und Node loest den auf diesem Rechner zu
// `[::1]` auf — ein `http://127.0.0.1:4173` ist dann NICHT erreichbar (gemessen:
// `lsof` zeigt `TCP [::1]:4173 (LISTEN)`, `curl 127.0.0.1` = 000). Der
// Bereitschaftstest von Playwright laeuft gegen `url`, also haette der
// `webServer` nie gestartet. Das Literal macht die Herkunft zugleich
// vergleichbar — `isPreviewRequest` haengt daran.
export const PREVIEW_ORIGIN = `http://127.0.0.1:${PREVIEW_PORT}`

/**
 * Der TRAEGER der zweiten Haelfte der Offline-Zusage von Task 16: alles, was
 * nicht die Vorschau der eigenen Anwendung ist, wird abgebrochen — auch eine
 * Antwort, die ein Service Worker oder der Cache bediente.
 *
 * Warum ein Praedikat und kein kontextweites `offline: true` (gemessen, nicht
 * gefolgert):
 *   - `newContext({ offline: true })` + `page.goto(PREVIEW_ORIGIN)`
 *     => `net::ERR_INTERNET_DISCONNECTED`. Playwright setzt `offline` in Chromium
 *     ueber `Network.emulateNetworkConditions`, und das trifft den GESAMTEN
 *     Netzstapel des Kontexts einschliesslich `127.0.0.1`.
 *   - dasselbe MIT diesem Praedikat davor => weiterhin
 *     `net::ERR_INTERNET_DISCONNECTED`; ein `route.continue()` ueberlebt die
 *     Netzemulation nicht.
 *   - `context.route('**', route => route.abort())` WOERTLICH, ohne Ausnahme
 *     => `net::ERR_FAILED` auf der eigenen Herkunft; die Anwendung laedt nie.
 *   - dieses Praedikat allein => Anwendung laedt, ihr `reload` laedt auch, und
 *     ein `fetch` auf eine ANDERE Herkunft bricht ab. Zurechenbar gemessen
 *     gegen einen zweiten Dienst auf `http://127.0.0.1:4174`: mit dem
 *     Praedikat "blocked", mit einem stets wahren Praedikat "reached". Das ist
 *     die Zusage "PASS mit abgeschaltetem Netz".
 *
 * Task 16 verdrahtet es in seiner Fixture unter `tests/e2e/`:
 *   await context.route('**', route =>
 *     isPreviewRequest(route.request().url()) ? route.continue() : route.abort())
 */
export function isPreviewRequest(url: string): boolean {
  return url === PREVIEW_ORIGIN || url.startsWith(`${PREVIEW_ORIGIN}/`)
}

// `satisfies` statt `defineConfig(...)`: die Signatur von `defineConfig` gibt
// `PlaywrightTestConfig` zurueck, und dort ist `webServer` die Vereinigung
// `TestConfigWebServer | TestConfigWebServer[]`. `config.webServer?.command`
// aus `src/e2e-config.test.ts` faellt dagegen mit TS2339. `satisfies` prueft
// dieselbe Konfigurationsform und behaelt den Literaltyp, also bleibt die
// Zusicherung des Tests lesbar UND typisierbar. Playwright liest den
// Default-Export; die benannten Ausfuhren daneben sind fuer Playwright inert.
export default {
  // RELATIV ZUM PAKET. `<repo>/tests/` ist dem Rust-Mitglied
  // `tests/ea-system-tests` vorbehalten (`Cargo.toml`:2), deshalb liegt die
  // E2E-Suite unter `apps/desktop/tests/e2e` und
  // `pnpm --dir apps/desktop exec playwright test tests/e2e/<spec>` loest auf.
  testDir: 'tests/e2e',
  webServer: {
    command: `pnpm exec vite build && pnpm exec vite preview --host 127.0.0.1 --port ${PREVIEW_PORT} --strictPort`,
    url: PREVIEW_ORIGIN,
    reuseExistingServer: false,
    // Der Vorlauf baut jetzt mit; die Vorgabe von 60 s deckt einen kalten
    // Vite-Bau samt Ant-Design nicht zuverlaessig.
    timeout: 180_000,
  },
  use: {
    baseURL: PREVIEW_ORIGIN,
    // AUSDRUECKLICH FALSCH UND NICHT VERGESSEN. `offline: true` auf
    // Kontextebene schneidet die Schleife mit ab (Messung oben), die eigene
    // Anwendung laedt dann nie. Den Netzzugang schaltet `isPreviewRequest` in
    // der Fixture von Task 16 ab, und zwar praeziser: die Herkunft der
    // Vorschau bleibt erreichbar, jede andere Anfrage bricht ab — auch nach
    // einem `reload`, was ein nachgelagertes `context.setOffline(true)` nicht
    // aushaelt (ebenfalls gemessen).
    offline: false,
  },
} satisfies PlaywrightTestConfig
