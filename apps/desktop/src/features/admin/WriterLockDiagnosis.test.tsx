import { act, render, screen } from '@testing-library/react'
import { expect, it, vi } from 'vitest'
import { userEvent } from '../../test-setup'
import { WriterLockDiagnosis, validateWriterLockDiagnosis } from './WriterLockDiagnosis'
import type { LocalWriterLockDiagnosis } from '../../bridge/generated-contracts'

it.each([
  ['Missing', 'Keine Sperrdatei vorhanden.'],
  ['AbandonedInert', 'Keine aktive Schreibsperre festgestellt.'],
  ['LiveOwner', 'Das Archiv wird gerade von einem Writer gesperrt.'],
  ['Unreadable', 'Der Sperrzustand konnte nicht sicher ermittelt werden.'],
] as const)('zeigt %s erst nach einer ausdrücklichen Prüfung', async (state, text) => {
  const diagnose = vi.fn().mockResolvedValue(state)
  render(<WriterLockDiagnosis diagnose={diagnose} busy={false} />)
  expect(diagnose).not.toHaveBeenCalled()
  await userEvent.setup().click(screen.getByRole('button', { name: 'Archiv-Sperre prüfen' }))
  expect(await screen.findByText(text)).toBeVisible()
  expect(diagnose).toHaveBeenCalledTimes(1)
  expect(screen.queryByRole('button', { name: /reparieren|löschen|freigeben/i })).not.toBeInTheDocument()
})

it('verwirft den bisherigen Status bei Lesefehlern und zeigt keine Fehlerdetails', async () => {
  const diagnose = vi.fn().mockResolvedValueOnce('AbandonedInert').mockRejectedValueOnce(new Error('/private/operator/key'))
  render(<WriterLockDiagnosis diagnose={diagnose} busy={false} />)
  const user = userEvent.setup()
  await user.click(screen.getByRole('button', { name: 'Archiv-Sperre prüfen' }))
  expect(await screen.findByText('Keine aktive Schreibsperre festgestellt.')).toBeVisible()
  await user.click(screen.getByRole('button', { name: 'Archiv-Sperre prüfen' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Die Archiv-Sperre konnte nicht geprüft werden.')
  expect(screen.queryByText('Keine aktive Schreibsperre festgestellt.')).not.toBeInTheDocument()
  expect(screen.queryByText(/private\/operator/)).not.toBeInTheDocument()
})

it('übernimmt keine verspätete Antwort einer vorherigen Bridge', async () => {
  let finish!: (value: LocalWriterLockDiagnosis) => void
  const previous = vi.fn(() => new Promise<LocalWriterLockDiagnosis>(resolve => { finish = resolve }))
  const current = vi.fn().mockResolvedValue('LiveOwner')
  const view = render(<WriterLockDiagnosis diagnose={previous} busy={false} />)
  const user = userEvent.setup()
  await user.click(screen.getByRole('button', { name: 'Archiv-Sperre prüfen' }))
  view.rerender(<WriterLockDiagnosis diagnose={current} busy={false} />)
  await user.click(screen.getByRole('button', { name: 'Archiv-Sperre prüfen' }))
  expect(await screen.findByText('Das Archiv wird gerade von einem Writer gesperrt.')).toBeVisible()
  await act(async () => { finish('AbandonedInert') })
  expect(screen.queryByText('Keine aktive Schreibsperre festgestellt.')).not.toBeInTheDocument()
})

it('verlangt die geschlossene native Antwort und berücksichtigt laufende Verwaltungsaktionen', () => {
  expect(() => validateWriterLockDiagnosis('Free')).toThrow()
  expect(() => validateWriterLockDiagnosis({ state: 'Missing', path: '/private' })).toThrow()
  const diagnose = vi.fn()
  render(<WriterLockDiagnosis diagnose={diagnose} busy />)
  expect(screen.getByRole('button', { name: 'Archiv-Sperre prüfen' })).toBeDisabled()
})
