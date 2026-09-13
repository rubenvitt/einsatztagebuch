import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { RecoveryTestWizard } from './RecoveryTestWizard'
import type { RecoveryBridge } from './RecoveryTestWizard'
import type { RecoveryAdministrationView } from '../../bridge/generated-contracts'

function pending(): RecoveryAdministrationView {
  return { lastSuccess: null, lastFailure: null, run: { operationId: '66'.repeat(16), phaseCode: 1,
    request: { runId: '11'.repeat(16), requestId: '22'.repeat(32), mediumIdHash: '33'.repeat(32),
      index: 1, total: 2, roleCode: 'root', certificateHash: '44'.repeat(32), expectedThumbprint: '55'.repeat(32),
      protectionCode: 2, testKindCode: 'signatureChallenge' }, observations: [], report: null, errorCode: null } }
}
function bridge(): RecoveryBridge {
  const initial = pending()
  return { initial, refresh: vi.fn(async () => initial), reauthenticate: vi.fn(async () => initial), start: vi.fn(async () => initial),
    submit: vi.fn(async () => initial), cancel: vi.fn(async () => ({ ...initial,
      run: { ...initial.run!, phaseCode: 5, request: null, errorCode: 'EA-RECOVERY-TEST-CANCELLED' } })) }
}
describe('RecoveryTestWizard', () => {
  it('keeps polling a requested cancellation until the native committed report is returned', async () => {
    const host = bridge()
    const waiting = { ...host.initial, run: { ...host.initial.run!, phaseCode: 7, request: null } }
    const report = { completed: false, exactPublicReportJson: '{}', envelopeHash: 'aa'.repeat(32),
      sourceEnvelopeHash: 'bb'.repeat(32), auditId: 'cc'.repeat(16), finishedAtMs: 1_700_000_000_000, nextDueAtMs: null }
    host.cancel = vi.fn(async () => waiting)
    host.refresh = vi.fn(async () => ({ ...waiting, lastFailure: report,
      run: { ...waiting.run!, phaseCode: 4, report } }))
    render(<RecoveryTestWizard bridge={host} />)
    await userEvent.setup().click(screen.getByRole('button', { name: 'Test abbrechen' }))
    expect(screen.getByRole('status')).toHaveTextContent('Abbruch wird abgeschlossen')
    expect(screen.queryByRole('button', { name: 'Recovery-Test starten' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Test abbrechen' })).toBeDisabled()
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Mit Fehlerbericht abgeschlossen'), { timeout: 2000 })
    expect(host.refresh).toHaveBeenCalled()
    expect(screen.getByText('aa'.repeat(32))).toBeVisible()
  })
  it('requires explicit native login after an expired read proof without restarting or auto-confirming a medium', async () => {
    const host = bridge()
    host.refresh = vi.fn(async () => { throw { code: 'EA-DESKTOP-NO-VERIFIED-SESSION' } })
    const user = userEvent.setup()
    render(<RecoveryTestWizard bridge={host} />)
    await user.click(screen.getByRole('button', { name: 'Status neu lesen' }))
    expect(host.reauthenticate).not.toHaveBeenCalled()
    await user.click(await screen.findByRole('button', { name: 'Erneut mit Betriebssystem anmelden' }))
    expect(host.reauthenticate).toHaveBeenCalledTimes(1)
    expect(host.start).not.toHaveBeenCalled()
    expect(host.submit).not.toHaveBeenCalled()
    expect(screen.getByRole('heading', { name: 'Sicherung 1 von 2' })).toBeVisible()
  })
  it('requires deliberate input for the current medium and never claims the expected key was observed', async () => {
    const host = bridge(); const user = userEvent.setup()
    render(<RecoveryTestWizard bridge={host} />)
    expect(screen.getByRole('heading', { name: 'Sicherung 1 von 2' })).toBeVisible()
    expect(screen.getByText('55'.repeat(32))).toBeVisible()
    expect(screen.queryByText('Bestanden')).not.toBeInTheDocument()
    expect(host.submit).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: 'Bereitgestellte Sicherung prüfen' }))
    expect(host.submit).toHaveBeenCalledExactlyOnceWith('66'.repeat(16), '11'.repeat(16), '22'.repeat(32), 0)
  })
  it('records an explicit missing medium and waits for the next native request before further input', async () => {
    const host = bridge(); const initial = host.initial
    const request = initial.run!.request!
    host.submit = vi.fn(async () => ({ ...initial, run: { ...initial.run!,
      request: { ...request, index: 2, requestId: 'aa'.repeat(32), mediumIdHash: 'bb'.repeat(32) },
      observations: [{ request, resultCode: 1, observedThumbprint: null, errorCode: 'EA-RECOVERY-TEST-INCOMPLETE' }] } }))
    render(<RecoveryTestWizard bridge={host} />)
    await userEvent.setup().click(screen.getByRole('button', { name: 'Sicherung fehlt' }))
    expect(host.submit).toHaveBeenCalledExactlyOnceWith('66'.repeat(16), '11'.repeat(16), '22'.repeat(32), 1)
    expect(await screen.findByRole('heading', { name: 'Sicherung 2 von 2' })).toBeVisible()
    expect(screen.getByText('Fehlt')).toBeVisible()
    expect(host.submit).toHaveBeenCalledTimes(1)
  })
  it('ignores a late input response after cancellation and keeps cancellation available during input', async () => {
    const host = bridge(); let resolve: (value: RecoveryAdministrationView) => void = () => undefined
    host.submit = vi.fn(() => new Promise<RecoveryAdministrationView>(done => { resolve = done }))
    render(<RecoveryTestWizard bridge={host} />)
    fireEvent.click(screen.getByRole('button', { name: 'Bereitgestellte Sicherung prüfen' }))
    await waitFor(() => expect(host.submit).toHaveBeenCalledTimes(1))
    await userEvent.setup().click(screen.getByRole('button', { name: 'Test abbrechen' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Abgebrochen')
    resolve(host.initial)
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Bereitgestellte Sicherung prüfen' })).not.toBeInTheDocument())
    expect(host.cancel).toHaveBeenCalledExactlyOnceWith('66'.repeat(16))
  })
})
