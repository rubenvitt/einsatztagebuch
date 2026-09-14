import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { connectDestructionBridge, DestructionSurface } from './DestructionSurface'

const ID = '11'.repeat(16)
const SECOND_ID = '12'.repeat(16)
const HASH = '22'.repeat(32)
function raw(id: string | null = null) {
  return {
    privacyDecisionEnabled: true, policyHash: HASH, knownDestructionIds: [ID, SECOND_ID],
    process: id === null ? null : {
      destructionId: id, authorizationObjectHash: HASH, state: 'requested', scopeCode: 0, legalReasonCode: 0,
      controllerDeviceId: '33'.repeat(16), custodianDeviceId: '44'.repeat(16),
      approverCertificateHashes: ['55'.repeat(32), '66'.repeat(32)],
      targets: [{ entryHash: HASH, chainSequence: 1, stubObjectHash: null }], preflight: null, replicas: [], evidenceEntryHash: null,
    },
  }
}

describe('native destruction bridge', () => {
  it('uses the explicit custodian login command for the selected process and preflight', async () => {
    const reply = { ...raw(ID), process: { ...raw(ID).process!, replicas: [{ deviceId: '33'.repeat(16), kindCode: 0, attestationHash: null, resultCode: null, backupExpiryAt: null }], preflight: { jobHash: HASH, exactCanonicalReportJson: '{}', knownReplicaCount: 1 } } }
    const call = vi.fn(async () => reply)
    const bridge = await connectDestructionBridge(call)
    await bridge.authenticateCustodian(ID, HASH)
    expect(call).toHaveBeenLastCalledWith('destruction_authenticate_custodian', { destructionId: ID, expectedPreflightHash: HASH })
    await expect(bridge.authenticateCustodian(ID, 'ff'.repeat(32))).rejects.toThrow(/Vorbericht/)
    await expect(bridge.authenticateCustodian(SECOND_ID, HASH)).rejects.toThrow(/Vorgang/)
    await bridge.refresh()
    expect(call).toHaveBeenLastCalledWith('destruction_read', { destructionId: ID })
  })

  it('uses a separate exact server read command and rejects a reply for another preflight', async () => {
    const reply = { ...raw(ID), process: { ...raw(ID).process!, replicas: [{ deviceId: '33'.repeat(16), kindCode: 2, attestationHash: null, resultCode: null, backupExpiryAt: null }], preflight: { jobHash: HASH, exactCanonicalReportJson: '{}', knownReplicaCount: 1 } } }
    const call = vi.fn(async () => reply)
    const bridge = await connectDestructionBridge(call)
    await bridge.synchronize(ID, HASH)
    expect(call).toHaveBeenLastCalledWith('destruction_synchronize', { destructionId: ID, expectedPreflightHash: HASH })
    await expect(bridge.synchronize(ID, 'ff'.repeat(32))).rejects.toThrow(/Vorbericht/)
    expect(call.mock.calls).toHaveLength(3)
  })

  it('uses the separate explicit final command and rejects a reply for another preflight', async () => {
    const reply = { ...raw(ID), process: { ...raw(ID).process!, state: 'incompleteUnreachableReplica', replicas: [{ deviceId: '33'.repeat(16), kindCode: 1, attestationHash: null, resultCode: null, backupExpiryAt: null }], preflight: { jobHash: HASH, exactCanonicalReportJson: '{}', knownReplicaCount: 1 } } }
    const call = vi.fn(async (_command: string, _args?: Record<string, unknown>) => reply)
    const bridge = await connectDestructionBridge(call)
    const result = await bridge.markIncomplete(ID, HASH)
    expect(result.process?.state).toBe('incompleteUnreachableReplica')
    expect(call).toHaveBeenLastCalledWith('destruction_mark_incomplete', { destructionId: ID, expectedPreflightHash: HASH })
    await expect(bridge.markIncomplete(ID, 'ff'.repeat(32))).rejects.toThrow(/Vorbericht/)
    await expect(bridge.markIncomplete(SECOND_ID, HASH)).rejects.toThrow(/Vorgang/)
    expect(call.mock.calls.map(([command]) => command)).not.toContain('destruction_resume')
  })

  it('uses exact IPC fields and retains the selected persisted process across refresh', async () => {
    const call = vi.fn(async (_command: string, args?: Record<string, unknown>) => raw(typeof args?.destructionId === 'string' ? args.destructionId : null))
    const bridge = await connectDestructionBridge(call)
    expect(call).toHaveBeenLastCalledWith('destruction_read', { destructionId: null })
    await bridge.select(ID)
    await bridge.refresh()
    expect(call).toHaveBeenLastCalledWith('destruction_read', { destructionId: ID })
    await bridge.start(ID, HASH)
    expect(call).toHaveBeenLastCalledWith('destruction_start', { destructionId: ID, expectedPreflightHash: HASH })
    await bridge.resume(ID)
    expect(call).toHaveBeenLastCalledWith('destruction_resume', { destructionId: ID })
    await bridge.importProgress(ID, HASH, [[0, 255], [7]])
    expect(call).toHaveBeenLastCalledWith('destruction_import_progress', { destructionId: ID, expectedPreflightHash: HASH, exactEtbObjects: [[0, 255], [7]] })
  })

  it('passes the selected signed file bytes without modification or renderer authority flags', async () => {
    const call = vi.fn(async () => raw(ID))
    const bridge = await connectDestructionBridge(call)
    await bridge.importAuthorization([0, 255, 1, 0])
    expect(call).toHaveBeenLastCalledWith('destruction_prepare', { exactAuthorization: [0, 255, 1, 0] })
  })

  it('rejects a valid response for another process without replacing the last verified selection', async () => {
    const call = vi.fn(async () => raw(ID))
    const bridge = await connectDestructionBridge(call)
    await expect(bridge.select(SECOND_ID)).rejects.toThrow()
    await bridge.refresh()
    expect(call).toHaveBeenLastCalledWith('destruction_read', { destructionId: ID })
  })

  it('rejects malformed native responses before opening any workflow', async () => {
    const connect = () => connectDestructionBridge(async () => ({ ...raw(), privacyDecisionEnabled: 'true' }))
    render(<DestructionSurface connect={connect} />)
    expect(await screen.findByRole('alert')).toHaveTextContent('Vernichtungsverwaltung nicht geöffnet')
    expect(screen.queryByRole('button', { name: 'Vernichtung beantragen' })).not.toBeInTheDocument()
  })

  it('preserves the native refusal code and never substitutes an empty successful view', async () => {
    const connect = () => connectDestructionBridge(async () => { throw { code: 'EA-DESKTOP-DESTRUCTION-UNAVAILABLE' } })
    render(<DestructionSurface connect={connect} />)
    expect(await screen.findByRole('alert')).toHaveTextContent('EA-DESKTOP-DESTRUCTION-UNAVAILABLE')
    expect(screen.queryByRole('region', { name: 'Kontrollierte Vernichtung' })).not.toBeInTheDocument()
  })
})
