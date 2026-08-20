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
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test-setup.ts'],
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
