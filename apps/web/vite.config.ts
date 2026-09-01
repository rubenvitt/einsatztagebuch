import react from '@vitejs/plugin-react'
// AUS `vitest/config` und nicht aus `vite`: nur dieser Einstieg kennt den
// `test`-Schluessel. Mit `vite`s `defineConfig` ist `test` eine unbekannte
// Eigenschaft, und `pnpm --dir apps/web typecheck` faellt mit TS2769.
import { defineConfig } from 'vitest/config'

export default defineConfig({
  base: './',
  plugins: [react()],
  build: {
    // Die Zielflaeche ist der BROWSER und keine Webview des Wirts; `es2022` ist
    // in den unterstuetzten Staenden von Chromium, Firefox und WebKit
    // abgedeckt und deckt sich mit dem Ziel des Desktop-Paketes.
    target: 'es2022',
    // Relative Beiwerkspfade, und das ist die Auslieferungstrennung nach §4.1
    // selbst: ein absoluter Pfad baende das Buendel an genau EINEN Origin und
    // machte die Trennung vom Sync-Server unbenutzbar.
    // Gehashte Beiwerke: `static-antd.css` erreicht das Buendel als
    // `assets/index-<hash>.css` und damit als lokale, wiedererkennbare
    // Ressource. Unter `style-src 'self'` gibt es keinen anderen Weg.
    assetsInlineLimit: 0,
    sourcemap: false,
    rollupOptions: {
      // ZWEI Einstiege in EINEM Durchgang. Der Service Worker ist ein
      // MODULWORKER, weil die von `wasm-bindgen` erzeugte Glue ein ES-Modul
      // ist: ein klassischer Worker koennte sie nicht importieren und muesste
      // die Entscheidung von aussen entgegennehmen — dann erzwaenge er nichts
      // mehr. `web-reader-design.md` §4.2 verlangt aber, dass ER die
      // Aktivierung prueft.
      //
      // GEMESSEN gegen diese Werkzeugkette (Vite 8.2.1 auf rolldown 1.2.5):
      // ein IIFE-Ausgang ist hier ohnehin NICHT waehlbar — zwei Einstiege
      // brechen mit `multiple inputs are not supported when
      // "output.codeSplitting" is false` ab, und mit `codeSplitting: true`
      // mit `UMD and IIFE are not supported for code-splitting builds`. Der
      // Zeuge in `src/sw/service-worker.test.ts` haelt genau das fest.
      // RELATIVE Einstiege und keine URL-Aufloesung: `src/e2e-config.test.ts`
      // importiert diese Datei, und dort ist `import.meta.url` kein
      // Dateipfad — `fileURLToPath` faellt dann mit „The URL must be of
      // scheme file". Vite loest beide gegen `root` auf.
      input: {
        index: 'index.html',
        'service-worker': 'src/sw/service-worker.ts',
      },
      output: {
        // Der Workername bleibt UNGEHASHT, jedes andere Beiwerk behaelt
        // seinen Hash: ein gehashter Workername waere bei jedem Bau ein
        // anderer Registrierungspfad und damit ein Aktivierungspfad, den die
        // Pinnung nicht sieht.
        entryFileNames: chunk =>
          chunk.name === 'service-worker' ? 'service-worker.js' : 'assets/[name]-[hash].js',
      },
    },
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
