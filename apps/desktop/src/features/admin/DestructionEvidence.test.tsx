import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { DestructionEvidence } from './DestructionEvidence'
import type { DestructionEvidenceBridge } from './DestructionEvidence'
import { connectDestructionEvidenceBridge } from './destruction-evidence-bridge'
import { DESTRUCTION_STATE_V1_VALUES, STALE_DECISION_VALUES, SYNC_STATUS_VALUES } from '../../bridge/generated-contracts'
import type { DestructionProcessView, FinalizationPreviewView } from '../../bridge/generated-contracts'

function process(): DestructionProcessView {
  return {
    destructionId: '11'.repeat(16), authorizationObjectHash: '22'.repeat(32),
    state: DESTRUCTION_STATE_V1_VALUES[1], scopeCode: 0, legalReasonCode: 1,
    controllerDeviceId: '33'.repeat(16), custodianDeviceId: '44'.repeat(16),
    approverCertificateHashes: ['55'.repeat(32), '66'.repeat(32)],
    targets: [{ entryHash: '77'.repeat(32), chainSequence: 1, stubObjectHash: '88'.repeat(32) }],
    preflight: { jobHash: '99'.repeat(32), exactCanonicalReportJson: '{}', knownReplicaCount: 1 },
    replicas: [{ deviceId: 'aa'.repeat(16), kindCode: 1, attestationHash: null, resultCode: null, backupExpiryAt: null }],
    evidenceEntryHash: null,
  }
}
function preview(): FinalizationPreviewView {
  return {
    proposedSequence: 2, bindsPredecessor: true, effectiveNow: 1_789_000_000_000,
    trustAgeMs: 1_000, readerTrustRefreshMs: 86_400_000,
    trustRefreshOverdue: false, staleDecision: STALE_DECISION_VALUES[0],
  }
}
function bridge(selected = process()): DestructionEvidenceBridge {
  return {
    preview: vi.fn().mockResolvedValue({ writerDeviceId: selected.custodianDeviceId, process: selected, preview: preview() }),
    finalize: vi.fn().mockResolvedValue({ sequence: 2, entryHash: 'bb'.repeat(32), objectHash: 'cc'.repeat(32), sync: { status: SYNC_STATUS_VALUES[0], detailCause: null } }),
    recover: vi.fn(), discard: vi.fn(),
  }
}

describe('explicit normal Writer evidence draft', () => {
  it.each(['finalize', 'recover', 'discard'] as const)('preserves the completed %s result when the subsequent status read fails', async (operation) => {
    const selected = process()
    const native = bridge(selected)
    vi.mocked(native.recover).mockResolvedValue({ resume: { phase: 'ReversibleDraft', irreversible: false, outcomeCode: 'NothingPending', outcomeSequence: null }, blockedCode: null, sync: null })
    vi.mocked(native.discard).mockResolvedValue({ phaseCode: 'NewBlankDraft', complete: true })
    const refresh = vi.fn().mockRejectedValue({ code: 'EA-DESTRUCTION-READ-FAILED' })
    render(<DestructionEvidence process={selected} bridge={native} disabled={false} acquireBusy={() => ({ current: () => true, release: vi.fn() })} onRefresh={refresh} />)
    if (operation === 'finalize') {
      fireEvent.click(screen.getByRole('button', { name: 'Vernichtungsnachweis vorbereiten' }))
      await screen.findByText('Vorgeschlagene Sequenz: 2')
      fireEvent.click(screen.getByRole('checkbox', { name: /Ich habe den Vernichtungsnachweis und die Writer-Vorschau geprüft/ }))
      fireEvent.click(screen.getByRole('button', { name: 'Vernichtungsnachweis endgültig abschließen' }))
    } else if (operation === 'discard') {
      fireEvent.click(screen.getByRole('checkbox', { name: /Ich möchte nur den gebundenen Nachweisentwurf verwerfen/ }))
      fireEvent.click(screen.getByRole('button', { name: 'Nachweisentwurf verwerfen' }))
    } else {
      fireEvent.click(screen.getByRole('button', { name: 'Vorbereiteten Nachweisabschluss wieder aufnehmen' }))
    }
    await waitFor(() => expect(refresh).toHaveBeenCalledOnce())
    expect(screen.getByRole('alert')).toHaveTextContent('Vorgangsstand konnte nicht erneut gelesen werden')
    expect(screen.getByRole('alert')).toHaveTextContent('EA-DESTRUCTION-READ-FAILED')
    expect(screen.queryByText('Writer-Handlung nicht abgeschlossen')).not.toBeInTheDocument()
    expect(screen.getByRole('status')).toHaveTextContent(operation === 'finalize' ? 'Writer-Eintrag 2 abgeschlossen' : operation === 'discard' ? 'Der Nachweisentwurf ist verworfen' : 'Die gebundene Writer-Wiederaufnahme ist abgeschlossen')
    expect(native[operation]).toHaveBeenCalledTimes(1)
  })

  it('calls only the selected evidence command and checks the returned job and Writer identity', async () => {
    const selected = process()
    const call = vi.fn().mockResolvedValue({ writerDeviceId: selected.custodianDeviceId, process: selected, preview: preview() })
    const native = connectDestructionEvidenceBridge(call)
    expect(call).not.toHaveBeenCalled()
    await native.preview(selected.destructionId, selected.preflight!.jobHash)
    expect(call).toHaveBeenCalledWith('destruction_evidence_preview', { destructionId: selected.destructionId, expectedPreflightHash: selected.preflight!.jobHash })
    call.mockResolvedValue({ writerDeviceId: 'ff'.repeat(16), process: selected, preview: preview() })
    await expect(native.preview(selected.destructionId, selected.preflight!.jobHash)).rejects.toThrow()
    call.mockResolvedValue({ writerDeviceId: selected.custodianDeviceId, process: { ...selected, destructionId: 'dd'.repeat(16) }, preview: preview() })
    await expect(native.preview(selected.destructionId, selected.preflight!.jobHash)).rejects.toThrow()
    call.mockResolvedValue({ writerDeviceId: selected.custodianDeviceId, process: selected, preview: { ...preview(), proposedSequence: Number.MAX_SAFE_INTEGER + 1 } })
    await expect(native.preview(selected.destructionId, selected.preflight!.jobHash)).rejects.toThrow()
  })

  it('prepares only on request and requires confirmation before a separate finalization', async () => {
    const selected = process()
    const native = bridge(selected)
    const refresh = vi.fn().mockResolvedValue(undefined)
    render(<DestructionEvidence process={selected} bridge={native} disabled={false} acquireBusy={() => ({ current: () => true, release: vi.fn() })} onRefresh={refresh} />)
    expect(native.preview).not.toHaveBeenCalled()
    expect(native.finalize).not.toHaveBeenCalled()
    expect(native.recover).not.toHaveBeenCalled()
    expect(native.discard).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Vernichtungsnachweis vorbereiten' }))
    await screen.findByText('Vorgeschlagene Sequenz: 2')
    expect(native.preview).toHaveBeenCalledWith(selected.destructionId, selected.preflight!.jobHash)
    expect(screen.getByText(selected.custodianDeviceId)).toBeVisible()
    expect(screen.getByText(/Offene Replikennachweise bleiben offen/)).toBeVisible()
    const finalize = screen.getByRole('button', { name: 'Vernichtungsnachweis endgültig abschließen' })
    expect(finalize).toBeDisabled()
    fireEvent.click(screen.getByRole('checkbox', { name: /Ich habe den Vernichtungsnachweis und die Writer-Vorschau geprüft/ }))
    fireEvent.click(finalize)
    await waitFor(() => expect(native.finalize).toHaveBeenCalledWith(selected.destructionId, selected.preflight!.jobHash, preview()))
    await waitFor(() => expect(refresh).toHaveBeenCalledOnce())
    expect(native.finalize).toHaveBeenCalledTimes(1)
  })

  it('keeps an existing incident draft and the process visible after a native refusal', async () => {
    const native = bridge()
    vi.mocked(native.preview).mockRejectedValue({ code: 'EA-DRAFT-EVIDENCE-OCCUPIED' })
    render(<DestructionEvidence process={process()} bridge={native} disabled={false} acquireBusy={() => ({ current: () => true, release: vi.fn() })} onRefresh={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Vernichtungsnachweis vorbereiten' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('EA-DRAFT-EVIDENCE-OCCUPIED')
    expect(screen.queryByRole('button', { name: 'Vernichtungsnachweis endgültig abschließen' })).not.toBeInTheDocument()
    expect(native.discard).not.toHaveBeenCalled()
    expect(native.finalize).not.toHaveBeenCalled()
  })

  it('consumes a displayed preview even when finalization is refused', async () => {
    const native = bridge()
    vi.mocked(native.finalize).mockRejectedValue({ code: 'EA-WRITER-PREVIEW-MISMATCH' })
    render(<DestructionEvidence process={process()} bridge={native} disabled={false} acquireBusy={() => ({ current: () => true, release: vi.fn() })} onRefresh={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Vernichtungsnachweis vorbereiten' }))
    await screen.findByText('Vorgeschlagene Sequenz: 2')
    fireEvent.click(screen.getByRole('checkbox', { name: /Ich habe den Vernichtungsnachweis und die Writer-Vorschau geprüft/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Vernichtungsnachweis endgültig abschließen' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('EA-WRITER-PREVIEW-MISMATCH')
    expect(screen.queryByRole('button', { name: 'Vernichtungsnachweis endgültig abschließen' })).not.toBeInTheDocument()
    expect(native.finalize).toHaveBeenCalledTimes(1)
    expect(native.recover).not.toHaveBeenCalled()
  })

  it('ignores a late review after the selected native process changes', async () => {
    const first = process()
    const native = bridge(first)
    let resolve!: (value: Awaited<ReturnType<DestructionEvidenceBridge['preview']>>) => void
    vi.mocked(native.preview).mockImplementation(() => new Promise((done) => { resolve = done }))
    const props = { bridge: native, disabled: false, acquireBusy: () => ({ current: () => true, release: vi.fn() }), onRefresh: vi.fn() }
    const view = render(<DestructionEvidence {...props} process={first} />)
    fireEvent.click(screen.getByRole('button', { name: 'Vernichtungsnachweis vorbereiten' }))
    view.rerender(<DestructionEvidence {...props} process={{ ...first, destructionId: 'dd'.repeat(16) }} />)
    resolve({ writerDeviceId: first.custodianDeviceId, process: first, preview: preview() })
    await waitFor(() => expect(screen.queryByText('Vorgeschlagene Sequenz: 2')).not.toBeInTheDocument())
    expect(native.finalize).not.toHaveBeenCalled()
  })
})
