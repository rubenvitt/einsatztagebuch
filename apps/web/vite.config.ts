import react from '@vitejs/plugin-react'
// AUS `vitest/config` und nicht aus `vite`: nur dieser Einstieg kennt den
// `test`-Schluessel. Mit `vite`s `defineConfig` ist `test` eine unbekannte
// Eigenschaft, und `pnpm --dir apps/web typecheck` faellt mit TS2769.
import { defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [react()],
  build: {
    // Die Zielflaeche ist der BROWSER und keine Webview des Wirts; `es2022` ist
    // in den unterstuetzten Staenden von Chromium, Firefox und WebKit
    // abgedeckt und deckt sich mit dem Ziel des Desktop-Paketes.
    target: 'es2022',
    // Gehashte Beiwerke: `static-antd.css` erreicht das Buendel als
    // `assets/index-<hash>.css` und damit als lokale, wiedererkennbare
    // Ressource. Unter `style-src 'self'` gibt es keinen anderen Weg.
    assetsInlineLimit: 0,
    sourcemap: false,
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test-setup.ts'],
    // NUR die Einheitentests des Pakets. Die Vitest-4-Vorgaben sind
    // `include = ["**/*.{test,spec}.?(c|m)[jt]s?(x)"]` und
    // `exclude = ["**/node_modules/**", "**/.git/**"]` — also KEINE
    // E2E-Ausnahme und kein `dist`. Der Schluessel steht hier, BEVOR die erste
    // Playwright-Spec unter `tests/e2e` entsteht: sonst sammelte
    // `pnpm web:test` sie ein und fiele, weil `@playwright/test` unter Vitest
    // keinen Runner findet (gemessen am Desktop-Pendant).
    include: ['src/**/*.test.{ts,tsx}'],
    // Node 26 definiert ein EIGENES `localStorage` auf `globalThis`, das ohne
    // `--localstorage-file` `undefined` liefert. Vitests `populateGlobal`
    // ueberspringt jeden Fensterschluessel, der bereits in `globalThis` steht
    // und nicht auf seiner festen KEYS-Liste vorkommt
    // (`vitest/dist/chunks/index.*.js`, `getWindowKeys`) — jsdoms ECHTES,
    // dokumentgebundenes `localStorage` wird dadurch nie sichtbar, und ein
    // blosses `localStorage.setItem` faellt mit "Cannot read properties of
    // undefined". Der Flag schaltet Nodes experimentelles Web Storage ab,
    // damit der Schluessel frei ist und jsdom ihn belegt. `execArgv` ist in
    // Vitest 4 ein Schluessel oberster Ebene unter `test`; `poolOptions` ist
    // dort entfallen.
    execArgv: ['--no-experimental-webstorage'],
  },
})
