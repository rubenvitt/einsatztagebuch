// Die EINE Stelle, an der die Testumgebung von `apps/desktop` zusammengesetzt
// wird. `vite.config.ts` laedt sie als `setupFiles`, und jedes Testfile bezieht
// die `userEvent`-Fixture von hier — kein Testfile richtet Matcher oder
// Aufraeumhaken selbst ein.

// Die erweiterten DOM-Matcher (`toBeInTheDocument`, `toBeDisabled`,
// `toHaveValue`, ...) an `expect` von Vitest.
import '@testing-library/jest-dom/vitest'

import { cleanup } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach } from 'vitest'

// `@testing-library/react` haengt sein `cleanup` NUR ein, wenn `afterEach`
// global ist (`dist/index.js:23-29`). `globals` ist bewusst kein `test`-
// Schluessel dieser Konfiguration, also wird der Haken hier von Hand gesetzt.
// Ohne ihn traegt `document` die Ausgabe jedes vorigen Tests weiter und die
// zweite Abfrage derselben Rolle faellt mit "found multiple elements".
afterEach(() => {
  cleanup()
})

export { userEvent }

// `ResizeObserver` fehlt in jsdom, und `rc-textarea` sowie `rc-descriptions`
// beobachten damit ihre Groesse (`@rc-component/resize-observer`:
// `ensureResizeObserver`). Ohne diesen Stumpf faellt JEDER Test, der ein
// mehrzeiliges Ant-Eingabefeld rendert, mit `ResizeObserver is not defined` —
// und zwar im Effekt und damit unabhaengig von der Zusicherung. Ein Stumpf und
// keine Nachbildung: die Groesse ist in einer DOM-Attrappe ohne Layout ohnehin
// null, und kein Zeuge dieses Bauwerks prueft eine Pixelgroesse.
class ResizeObserverStub {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}

if (!('ResizeObserver' in globalThis)) {
  Object.defineProperty(globalThis, 'ResizeObserver', {
    value: ResizeObserverStub,
    writable: true,
  })
}

// `matchMedia` fehlt in jsdom, und Ant Designs `responsiveObserver` registriert
// damit seine Breakpoints (`antd/lib/_util/responsiveObserver.js`:95-104). Jede
// Komponente ueber `useBreakpoint` — `Descriptions` etwa — faellt ohne diesen
// Stumpf im Effekt. Wieder ein Stumpf und keine Nachbildung: eine DOM-Attrappe
// ohne Layout hat keine Breite, und kein Zeuge prueft einen Breakpoint.
Object.defineProperty(globalThis, 'matchMedia', {
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => undefined,
    removeListener: () => undefined,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => false,
  }),
  writable: true,
})
