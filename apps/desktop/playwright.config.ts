import type { PlaywrightTestConfig } from '@playwright/test'

// Die Vorschau der GEBAUTEN Anwendung. `vite preview` liefert `dist/`, also
// genau die Bytes, die ins Tauri-Paket eingehen — nicht den Dev-Server mit
// seiner Modultransformation zur Laufzeit.
const PREVIEW_PORT = 4173
const PREVIEW_URL = `http://127.0.0.1:${PREVIEW_PORT}`

// `satisfies` statt `defineConfig(...)`: die Signatur von `defineConfig` gibt
// `PlaywrightTestConfig` zurueck, und dort ist `webServer` die Vereinigung
// `TestConfigWebServer | TestConfigWebServer[]`. `config.webServer?.command`
// aus `src/e2e-config.test.ts` faellt dagegen mit TS2339. `satisfies` prueft
// dieselbe Konfigurationsform und behaelt den Literaltyp, also bleibt die
// Zusicherung des Tests lesbar UND typisierbar. Playwright liest den
// Default-Export; `defineConfig` ist mit einem Argument dessen Identitaet.
export default {
  // RELATIV ZUM PAKET. `<repo>/tests/` ist dem Rust-Mitglied
  // `tests/ea-system-tests` vorbehalten (`Cargo.toml`:2), deshalb liegt die
  // E2E-Suite unter `apps/desktop/tests/e2e` und
  // `pnpm --dir apps/desktop exec playwright test tests/e2e/<spec>` loest auf.
  testDir: 'tests/e2e',
  webServer: {
    command: `pnpm exec vite preview --port ${PREVIEW_PORT} --strictPort`,
    url: PREVIEW_URL,
    reuseExistingServer: false,
  },
  use: {
    baseURL: PREVIEW_URL,
    // Der abgeschaltete Netzzugang des Browserkontexts. Er ist die HAELFTE der
    // Zusage von Task 16 ("PASS mit abgeschaltetem Netz"): `offline` deckt den
    // Netzstapel des Kontexts. Die zweite Haelfte —
    // `context.route('**', route => route.abort())`, die auch einen vom
    // Service Worker oder aus dem Cache bedienten Aufruf abweist — gehoert in
    // die Spec bzw. Fixture, die Task 16 unter `tests/e2e/` anlegt; ein
    // Route-Handler ist in dieser Datei nicht ausdrueckbar.
    offline: true,
  },
} satisfies PlaywrightTestConfig
