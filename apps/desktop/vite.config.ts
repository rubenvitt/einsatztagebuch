import react from '@vitejs/plugin-react'
// AUS `vitest/config` und nicht aus `vite`: nur dieser Einstieg kennt den
// `test`-Schluessel. Mit `vite`s `defineConfig` ist `test` eine unbekannte
// Eigenschaft, und `pnpm --dir apps/desktop typecheck` faellt mit TS2769.
import { defineConfig } from 'vitest/config'

// Task 15 erweitert AUSSCHLIESSLICH den Build-Eintrag und die Konfiguration der
// gehashten Beiwerke dieser Datei. Die zwei `test`-Schluessel `environment` und
// `setupFiles` bleiben so, wie sie hier stehen: der erste traegt das DOM, der
// zweite die erweiterten Matcher, den Aufraeumhaken und die
// `userEvent`-Fixture.
export default defineConfig({
  plugins: [react()],
  // Der Bau-Einstieg und die gehashten Beiwerke — und sonst nichts. `index.html`
  // steht ausdruecklich da, weil dieser Eintrag der Einstieg IST und nicht die
  // Wiederholung einer Vorgabe: die Vorschau von `playwright.config.ts` und das
  // Paket von Tauri lesen beide `dist/`, und ein Bau ohne benannten Einstieg
  // waere an dieser Stelle nicht nachlesbar.
  build: {
    // Die Webview des Wirts ist WebKit (macOS), WebView2 (Windows) oder
    // WebKitGTK (Ubuntu); `es2022` ist von allen dreien in den unterstuetzten
    // Staenden abgedeckt.
    target: 'es2022',
    assetsDir: 'assets',
    // Gehashte Beiwerke: `static-antd.css` erreicht das Paket als
    // `assets/index-<hash>.css` und damit als lokale, wiedererkennbare
    // Ressource.
    assetsInlineLimit: 0,
    sourcemap: false,
    emptyOutDir: true,
    // RELATIV zur Wurzel und nicht ueber `import.meta.url` aufgeloest: diese
    // Datei wird von `src/e2e-config.test.ts` als MODUL importiert, und dort
    // ist `import.meta.url` keine `file:`-URL (gemessen: `TypeError: The URL
    // must be of scheme file`).
    rollupOptions: {
      input: 'index.html',
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test-setup.ts'],
    // GEMESSEN am 2026-09-01, nachdem der erste CI-Lauf ueberhaupt
    // (`.github/workflows/ci.yml`, Lauf 33541706571) an dieser Vorgabe fiel.
    //
    // Vitests Vorgabe ist 5000 ms je Test. Auf dem Entwicklungsrechner
    // brauchen die schwersten `userEvent`-Ketten dieses Pakets 2577 / 2219 /
    // 1708 / 1575 / 1520 ms — fuenf Tests innerhalb des Faktors 3,3 zur
    // Vorgabe, ohne dass es je jemand sah, weil es bis heute KEINE CI gab. Der
    // vierkernige GitHub-Laeufer ist rund doppelt so langsam; damit kippte
    // `distinguishes known zero from unknown and blocks finalize before review
    // confirmation` bei > 5000 ms, waehrend dieselbe Datei lokal in 17,2 s
    // vollstaendig gruen laeuft. Der Test HAENGT nicht — er ist die laengste
    // Interaktionskette des Pakets (neun `user`-Aktionen samt Tastatureingabe,
    // jede mit React-Neuzeichnung unter jsdom).
    //
    // Fuenfzehn Sekunden sind deshalb kein Zudecken, sondern die Frist, unter
    // der die gemessene Kette auch auf langsamerer Hardware sicher bleibt:
    // rund sechsfacher Abstand zum lokalen Maximum, rund dreifacher zum
    // beobachteten CI-Wert. Ein echtes Haengen faellt weiterhin auf, denn die
    // GANZE Datei laeuft in 24 s durch — ein einzelner Test, der 15 s zieht,
    // steht sofort allein an der Spitze der `--reporter=verbose`-Liste.
    testTimeout: 15_000,
    // NUR die Einheitentests des Pakets. Die Vitest-4-Vorgaben sind
    // `include = ["**/*.{test,spec}.?(c|m)[jt]s?(x)"]` und
    // `exclude = ["**/node_modules/**", "**/.git/**"]` — also KEINE E2E-Ausnahme
    // und kein `dist`. Ohne diese Eingrenzung sammelt `pnpm desktop:test` ab
    // Task 16 die Playwright-Spec `tests/e2e/writer-offline.spec.ts` ein und
    // faellt, weil `@playwright/test` unter Vitest keinen Runner findet
    // (gemessen: mit Spec und ohne diesen Schluessel 3 Dateien, eine rot; mit
    // dem Schluessel 2 Dateien, alle gruen).
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
