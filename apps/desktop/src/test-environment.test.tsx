// Beweist, dass die drei Dinge, die Task 15 und Task 16 benutzen ohne sie je zu
// deklarieren, tatsaechlich aufloesen: ein DOM, die erweiterten Matcher und die
// `userEvent`-Fixture. Ohne diesen Zeugen faellt eine fehlende
// Runner-Konfiguration erst in einem UI-Test auf, und dort sieht sie wie ein
// Fehler der Oberflaeche aus.
import { render, screen } from '@testing-library/react'
import { expect, it } from 'vitest'

// AUSDRUECKLICH aus der Setup-Datei und nicht aus dem Paket: die eine Stelle,
// an der die Testumgebung zusammengesetzt wird, ist damit auch die eine Stelle,
// aus der ein Testfile sie bezieht.
import { userEvent } from './test-setup'

it('provides a DOM, localStorage, and the extended matchers', () => {
  render(
    <button type="button" disabled>
      Finalisieren
    </button>,
  )
  expect(screen.getByRole('button', { name: 'Finalisieren' })).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Finalisieren' })).toBeDisabled()
  localStorage.setItem('probe', 'value')
  expect(localStorage.getItem('probe')).toBe('value')
})

// Der Zeuge fuer das automatische Aufraeumen. `@testing-library/react` haengt
// sein `cleanup` nur ein, wenn `afterEach` GLOBAL ist — und `globals` ist kein
// `test`-Schluessel dieser Konfiguration. Ohne die Einhaengung in
// `test-setup.ts` traegt das Dokument den Button des vorigen Tests weiter, und
// jede zweite Abfrage derselben Rolle in Task 15 fiele mit "found multiple
// elements". Dieser Test laeuft nach dem ersten und misst genau das.
it('resets the DOM between two tests of the same file', () => {
  expect(screen.queryByRole('button', { name: 'Finalisieren' })).toBeNull()
})

it('provides a userEvent fixture that types and clicks', async () => {
  const user = userEvent.setup()
  render(<input aria-label="Freitext" />)
  await user.type(screen.getByLabelText('Freitext'), 'Ada')
  expect(screen.getByLabelText('Freitext')).toHaveValue('Ada')
})
