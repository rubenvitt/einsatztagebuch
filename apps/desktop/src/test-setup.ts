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
