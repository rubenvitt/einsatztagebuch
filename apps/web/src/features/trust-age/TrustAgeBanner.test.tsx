import { render, screen } from '@testing-library/react'
import { expect, it } from 'vitest'

import type { ReaderTrustAgeView } from '../../bridge/generated-contracts'
import { TrustAgeBanner } from './TrustAgeBanner'

const ONE_DAY_MS = 86_400_000

function view(overrides: Partial<ReaderTrustAgeView> = {}): ReaderTrustAgeView {
  return {
    trustAgeMs: ONE_DAY_MS,
    readerTrustRefreshMs: ONE_DAY_MS * 7,
    trustRefreshOverdue: false,
    ...overrides,
  }
}

it('weist das Alter als TEXT aus und nicht nur als Farbe', () => {
  render(<TrustAgeBanner view={view({ trustAgeMs: ONE_DAY_MS * 3 })} />)

  expect(screen.getByLabelText('Alter des Vertrauensbestands')).toBeInTheDocument()
  expect(screen.getByText('3 Tagen')).toBeInTheDocument()
  expect(screen.getByText('7 Tage')).toBeInTheDocument()
})

it('fordert bei Ueberschreitung zur Aktualisierung auf und sperrt NICHT', () => {
  render(
    <TrustAgeBanner
      view={view({ trustAgeMs: ONE_DAY_MS * 30, trustRefreshOverdue: true })}
    />,
  )

  expect(screen.getByText(/bitte aktualisieren/)).toBeInTheDocument()
  // Die Aussage, die §4.2 verlangt: benutzbar trotz Ueberschreitung.
  expect(screen.getByText(/bleibt benutzbar/)).toBeInTheDocument()
})

it('nennt eine ungesetzte Frist als ungesetzt statt als null Tage', () => {
  // `0 = unset` nach `schemas/archive/v1/trust.cddl`. „0 Tage" waere die
  // Anzeige einer Frist, die es nicht gibt.
  render(<TrustAgeBanner view={view({ readerTrustRefreshMs: 0 })} />)

  expect(screen.getByText('nicht gesetzt')).toBeInTheDocument()
})
