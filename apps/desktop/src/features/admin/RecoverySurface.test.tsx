import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import userEvent from '@testing-library/user-event'
import { connectRecoveryBridge, RecoverySurface } from './RecoverySurface'
const operationId = '11'.repeat(16), runId = '22'.repeat(16), requestId = '33'.repeat(32)
const idle = { lastSuccess: null, lastFailure: null, run: null }
const active = { ...idle, run: { operationId, phaseCode: 0, request: null, observations: [], report: null, errorCode: null } }
describe('native recovery bridge', () => {
  it('offers explicit login when the initial read proof has expired and opens only after a fresh verified read', async () => {
    const call = vi.fn<(_command: string, _args?: Record<string, unknown>) => Promise<unknown>>(async () => idle)
    call.mockRejectedValueOnce({ code: 'EA-DESKTOP-NO-VERIFIED-SESSION' })
    const connect = () => connectRecoveryBridge(call)
    const login = vi.fn(async () => undefined)
    render(<RecoverySurface connect={connect} login={login} />)
    expect(await screen.findByRole('alert')).toHaveTextContent('EA-DESKTOP-NO-VERIFIED-SESSION')
    expect(login).not.toHaveBeenCalled()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Erneut mit Betriebssystem anmelden' }))
    expect(await screen.findByRole('button', { name: 'Recovery-Test starten' })).toBeVisible()
    expect(login).toHaveBeenCalledTimes(1)
    expect(call.mock.calls.map(([command]) => command)).toEqual(['recovery_read', 'recovery_read'])
  })
  it('renews native login explicitly and re-reads the same operation only for a verified administrator', async () => {
    const call = vi.fn<(_command: string, _args?: Record<string, unknown>) => Promise<unknown>>(async () => active)
    const bridge = await connectRecoveryBridge(call)
    call.mockResolvedValueOnce({ role: 'organizationadmin', capabilities: ['administration'] })
    await bridge.reauthenticate()
    expect(call.mock.calls.slice(-2)).toEqual([['session_login'], ['recovery_read', {}]])
    call.mockResolvedValueOnce({ role: 'writer', capabilities: ['capture'] })
    await expect(bridge.reauthenticate()).rejects.toThrow()
    expect(call).toHaveBeenLastCalledWith('session_login')
  })
  it('uses exactly the four registered commands and opaque native request IDs', async () => {
    const call = vi.fn(async () => active)
    const bridge = await connectRecoveryBridge(call)
    expect(call).toHaveBeenLastCalledWith('recovery_read')
    await bridge.start()
    expect(call).toHaveBeenLastCalledWith('recovery_start', {})
    await bridge.submit(operationId, runId, requestId, 0)
    expect(call).toHaveBeenLastCalledWith('recovery_submit', { operationId, runId, requestId, choice: 0 })
    await bridge.submit(operationId, runId, requestId, 1)
    expect(call).toHaveBeenLastCalledWith('recovery_submit', { operationId, runId, requestId, choice: 1 })
    await bridge.cancel(operationId)
    expect(call).toHaveBeenLastCalledWith('recovery_cancel', { operationId })
    await bridge.refresh()
    expect(call).toHaveBeenLastCalledWith('recovery_read', {})
  })
  it('rejects missing runs and responses for another operation without trusting them as a completed action', async () => {
    const call = vi.fn<(_command: string, _args?: Record<string, unknown>) => Promise<unknown>>(async () => active)
    const bridge = await connectRecoveryBridge(call)
    call.mockResolvedValueOnce(idle)
    await expect(bridge.start()).rejects.toThrow()
    call.mockResolvedValueOnce({ ...active, run: { ...active.run, operationId: 'ff'.repeat(16) } })
    await expect(bridge.cancel(operationId)).rejects.toThrow()
    call.mockResolvedValueOnce({ ...active, run: { ...active.run, phaseCode: 3 } })
    await expect(bridge.refresh()).rejects.toThrow()
  })
  it('shows native refusal without opening test input', async () => {
    const connect = () => connectRecoveryBridge(async () => { throw { code: 'EA-DESKTOP-RECOVERY-UNAVAILABLE' } })
    render(<RecoverySurface connect={connect} />)
    expect(await screen.findByRole('alert')).toHaveTextContent('EA-DESKTOP-RECOVERY-UNAVAILABLE')
    expect(screen.queryByRole('button', { name: 'Recovery-Test starten' })).not.toBeInTheDocument()
  })
})
