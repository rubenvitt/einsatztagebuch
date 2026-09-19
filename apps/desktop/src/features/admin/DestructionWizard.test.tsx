import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { DestructionWizard } from './DestructionWizard'
import type { DestructionBridge } from './DestructionWizard'
import type { DestructionEvidenceBridge } from './DestructionEvidence'
import type { DestructionAdministrationView, DestructionProcessView } from '../../bridge/generated-contracts'

const PROCESS_ID = '10101010101010101010101010101010'
const PREFLIGHT_HASH = 'aa'.repeat(32)

function process(overrides: Partial<DestructionProcessView> = {}): DestructionProcessView {
  return {
    destructionId: PROCESS_ID,
    authorizationObjectHash: 'ab'.repeat(32),
    state: 'requested',
    scopeCode: 1,
    legalReasonCode: 2,
    controllerDeviceId: '11'.repeat(16),
    custodianDeviceId: '22'.repeat(16),
    approverCertificateHashes: ['31'.repeat(32), '32'.repeat(32)],
    targets: [{ entryHash: 'cc'.repeat(32), chainSequence: 7, stubObjectHash: null }],
    evidenceEntryHash: null,
    preflight: {
      jobHash: PREFLIGHT_HASH,
      exactCanonicalReportJson: '{"knownReplicaCount":3}',
      knownReplicaCount: 3,
    },
    replicas: [
      { deviceId: '41'.repeat(16), kindCode: 0, attestationHash: 'a1'.repeat(32), resultCode: 0, backupExpiryAt: null },
      { deviceId: '42'.repeat(16), kindCode: 2, attestationHash: 'a2'.repeat(32), resultCode: 1, backupExpiryAt: 1_780_000_000_000 },
      { deviceId: '43'.repeat(16), kindCode: 1, attestationHash: null, resultCode: null, backupExpiryAt: null },
    ],
    ...overrides,
  }
}

function view(value: DestructionProcessView | null = process()): DestructionAdministrationView {
  return { privacyDecisionEnabled: true, policyHash: 'dd'.repeat(32), knownDestructionIds: [PROCESS_ID, '20'.repeat(16)], process: value }
}

function bridge(initial = view()): DestructionBridge {
  return {
    initial,
    importAuthorization: vi.fn(async () => view()),
    importProgress: vi.fn(async () => initial),
    refresh: vi.fn(async () => initial),
    select: vi.fn(async () => view()),
    start: vi.fn(async () => view(process({ state: 'inProgress' }))),
    resume: vi.fn(async () => initial),
    synchronize: vi.fn(async () => initial),
    authenticateCustodian: vi.fn(async () => initial),
    markIncomplete: vi.fn(async () => initial),
  }
}

/** Custodian Writer succeeded with verified stubs; Server deadline elapsed, Reader never attested. */
function offered(overrides: Partial<DestructionProcessView> = {}): DestructionProcessView {
  return process({
    state: 'inProgress',
    custodianDeviceId: '41'.repeat(16),
    targets: [{ entryHash: 'cc'.repeat(32), chainSequence: 7, stubObjectHash: 'e1'.repeat(32) }],
    ...overrides,
  })
}

describe('resuming an incomplete destruction (Ruling G2)', () => {
  const RESUME = 'Vernichtung fortsetzen'
  const incomplete = (): DestructionAdministrationView => view(offered({ state: 'incompleteUnreachableReplica' }))

  it('offers no new action: the existing resume chains the host retry and shows only the returned state', async () => {
    const host = { ...bridge(incomplete()), resume: vi.fn(async () => view(offered({ state: 'completeManagedScope' }))) }
    const user = userEvent.setup()
    render(<DestructionWizard bridge={host} />)
    expect(screen.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveTextContent('bekannte Replik nicht erreichbar')
    expect(screen.queryByRole('button', { name: /wiederholen|erneut versuchen/i })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: RESUME }))
    expect(host.resume).toHaveBeenCalledExactlyOnceWith(PROCESS_ID)
    await waitFor(() => expect(screen.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveTextContent('im verwalteten Umfang abgeschlossen'))
    expect(host.markIncomplete).not.toHaveBeenCalled()
  })

  for (const [code, explanation] of [
    ['EA-DESTRUCTION-RETRY-READER-DUTY', 'Der Vorgang kann nicht fortgesetzt werden: Die fehlende Löschbestätigung betrifft ein Lesegerät. Lesegeräte lassen sich in dieser Version nicht erneut anbinden; der Vorgang bleibt als unvollständig abgeschlossen.'],
    ['EA-DESTRUCTION-RETRY-NO-SERVER-DUTY', 'Der Vorgang kann nicht fortgesetzt werden: Für ihn ist kein Sync-Server als Löschort gebunden oder in dieser Anwendung eingerichtet. Ohne nachträgliche Serverbestätigung bleibt der Vorgang als unvollständig abgeschlossen.'],
  ] as const) {
    it(`explains ${code} in German instead of idling, keeps the code and re-reads the host state`, async () => {
      const host = {
        ...bridge(incomplete()),
        resume: vi.fn(async () => { throw { code } }),
        refresh: vi.fn(async () => incomplete()),
      }
      const user = userEvent.setup()
      render(<DestructionWizard bridge={host} />)
      await user.click(screen.getByRole('button', { name: RESUME }))
      const alert = await screen.findByRole('alert')
      expect(alert).toHaveTextContent(explanation)
      expect(alert).toHaveTextContent(code)
      await waitFor(() => expect(host.refresh).toHaveBeenCalledOnce())
      expect(screen.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveTextContent('bekannte Replik nicht erreichbar')
      expect(host.resume).toHaveBeenCalledExactlyOnceWith(PROCESS_ID)
    })
  }

  it('shows a durable 4→1 even when the chained completion fails afterwards', async () => {
    const host = {
      ...bridge(incomplete()),
      resume: vi.fn(async () => { throw { code: 'EA-DESTRUCTION-TRANSPORT-UNAVAILABLE' } }),
      refresh: vi.fn(async () => view(offered({ state: 'inProgress' }))),
    }
    const user = userEvent.setup()
    render(<DestructionWizard bridge={host} />)
    await user.click(screen.getByRole('button', { name: RESUME }))
    await waitFor(() => expect(screen.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveTextContent('in Bearbeitung'))
    expect(screen.getByRole('alert')).toHaveTextContent('EA-DESTRUCTION-TRANSPORT-UNAVAILABLE')
    expect(screen.getByRole('alert')).not.toHaveTextContent('Der Vorgang kann nicht fortgesetzt werden')
  })
})

describe('explicit final incomplete action', () => {
  const ACTION = 'Als unvollständig abschließen'
  // Ruling G3 (19.09.2026): final only for unreachable Readers; a server-bound case resumes later.
  const CONFIRM = 'Unvollständigen Abschluss signieren'
  const UNDERSTOOD = 'Ich habe verstanden, dass dieser Abschluss für nicht erreichbare Lesegeräte endgültig ist.'

  it('is offered only when the host view shows a replica without valid attestation or an elapsed deadline', () => {
    const rendered = render(<DestructionWizard bridge={bridge(view(offered()))} />)
    expect(screen.getByRole('button', { name: ACTION })).toBeEnabled()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    for (const other of [
      process({ state: 'inProgress' }),
      offered({ state: 'incompleteUnreachableReplica' }),
      offered({ state: 'completeManagedScope' }),
      offered({ replicas: [
        { deviceId: '41'.repeat(16), kindCode: 0, attestationHash: 'a1'.repeat(32), resultCode: 0, backupExpiryAt: null },
        { deviceId: '42'.repeat(16), kindCode: 2, attestationHash: 'a2'.repeat(32), resultCode: 1, backupExpiryAt: Date.now() + 3_600_000 },
      ], preflight: { ...process().preflight!, knownReplicaCount: 2 } }),
    ]) {
      rendered.rerender(<DestructionWizard bridge={bridge(view(other))} />)
      expect(screen.queryByRole('button', { name: ACTION })).not.toBeInTheDocument()
    }
  })

  it('requires a separate final confirmation and shows only the returned host state', async () => {
    const host = bridge(view(offered()))
    let finish: (result: DestructionAdministrationView) => void = () => undefined
    host.markIncomplete = vi.fn(() => new Promise<DestructionAdministrationView>((resolve) => { finish = resolve }))
    const user = userEvent.setup()
    render(<DestructionWizard bridge={host} />)
    await user.click(screen.getByRole('button', { name: ACTION }))
    const dialog = await screen.findByRole('dialog')
    // jsdom keeps the antd enter motion at opacity 0; presence in the dialog is the witness here.
    expect(within(dialog).getByText('Vorgang als unvollständig abschließen?')).toBeInTheDocument()
    expect(within(dialog).getByText('Mindestens eine bekannte Replik hat keine gültige Attestierung, oder eine attestierte Backup-Frist ist abgelaufen. Die Anwendung signiert dafür den Status „bekannte Replik nicht erreichbar“.')).toBeInTheDocument()
    expect(within(dialog).getByText('Für nicht erreichbare Lesegeräte ist dieser Schritt endgültig: Später eingehende Nachweise ändern diesen Status nicht mehr. Fehlen nur Bestätigungen von Sync-Servern, lässt sich der Vorgang mit „Vernichtung fortsetzen“ wieder aufnehmen, sobald alle Löschungen bestätigt sind. Importieren oder gleichen Sie vorher alle vorliegenden Nachweise ab.')).toBeInTheDocument()
    expect(dialog).not.toHaveTextContent(/Rückweg|Endgültig als unvollständig/)
    expect(within(dialog).getByText('Der Abschluss bestätigt keine Löschung auf den betroffenen Repliken.')).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: CONFIRM })).toBeDisabled()
    await user.click(within(dialog).getByRole('button', { name: 'Zurück' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(host.markIncomplete).not.toHaveBeenCalled()

    await user.click(screen.getByRole('button', { name: ACTION }))
    const reopened = await screen.findByRole('dialog')
    expect(within(reopened).getByRole('checkbox', { name: UNDERSTOOD })).not.toBeChecked()
    await user.click(within(reopened).getByRole('checkbox', { name: UNDERSTOOD }))
    const confirm = within(reopened).getByRole('button', { name: CONFIRM })
    fireEvent.click(confirm)
    fireEvent.click(confirm)
    expect(host.markIncomplete).toHaveBeenCalledExactlyOnceWith(PROCESS_ID, PREFLIGHT_HASH)
    expect(host.resume).not.toHaveBeenCalled()
    expect(screen.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveTextContent('in Bearbeitung')
    await act(async () => finish(view(offered({ state: 'incompleteUnreachableReplica' }))))
    await waitFor(() => expect(screen.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveTextContent('bekannte Replik nicht erreichbar'))
    expect(screen.queryByRole('button', { name: ACTION })).not.toBeInTheDocument()
  })

  it('keeps the verified process and shows the native refusal code', async () => {
    const host = { ...bridge(view(offered())), markIncomplete: vi.fn(async () => { throw { code: 'EA-DESTRUCTION-MARK-INCOMPLETE-NOT-OFFERED' } }) }
    const user = userEvent.setup()
    render(<DestructionWizard bridge={host} />)
    await user.click(screen.getByRole('button', { name: ACTION }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('checkbox', { name: UNDERSTOOD }))
    await user.click(within(dialog).getByRole('button', { name: CONFIRM }))
    expect(await screen.findByRole('alert')).toHaveTextContent('EA-DESTRUCTION-MARK-INCOMPLETE-NOT-OFFERED')
    expect(screen.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveTextContent('in Bearbeitung')
    expect(host.markIncomplete).toHaveBeenCalledExactlyOnceWith(PROCESS_ID, PREFLIGHT_HASH)
    expect(host.resume).not.toHaveBeenCalled()
  })

  it('re-reads the host state after a failure, so a durable local state4 is never hidden behind the old offer', async () => {
    // A transport failure after the durable local commit: the host already holds state4.
    const host = {
      ...bridge(view(offered())),
      markIncomplete: vi.fn(async () => { throw { code: 'EA-DESTRUCTION-TRANSPORT-UNAVAILABLE' } }),
      refresh: vi.fn(async () => view(offered({ state: 'incompleteUnreachableReplica' }))),
    }
    const user = userEvent.setup()
    render(<DestructionWizard bridge={host} />)
    await user.click(screen.getByRole('button', { name: ACTION }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('checkbox', { name: UNDERSTOOD }))
    await user.click(within(dialog).getByRole('button', { name: CONFIRM }))
    await waitFor(() => expect(screen.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveTextContent('bekannte Replik nicht erreichbar'))
    expect(screen.getByRole('alert')).toHaveTextContent('EA-DESTRUCTION-TRANSPORT-UNAVAILABLE')
    expect(screen.queryByRole('button', { name: ACTION })).not.toBeInTheDocument()
    expect(host.refresh).toHaveBeenCalledOnce()
    expect(host.markIncomplete).toHaveBeenCalledOnce()
    expect(host.resume).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: 'Status neu lesen' })).toBeEnabled()
  })

  it('keeps the action refusal visible when the re-read itself fails', async () => {
    const host = {
      ...bridge(view(offered())),
      markIncomplete: vi.fn(async () => { throw { code: 'EA-DESTRUCTION-TRANSPORT-UNAVAILABLE' } }),
      refresh: vi.fn(async () => { throw { code: 'EA-DESTRUCTION-NATIVE-SESSION' } }),
    }
    const user = userEvent.setup()
    render(<DestructionWizard bridge={host} />)
    await user.click(screen.getByRole('button', { name: ACTION }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('checkbox', { name: UNDERSTOOD }))
    await user.click(within(dialog).getByRole('button', { name: CONFIRM }))
    await waitFor(() => expect(host.refresh).toHaveBeenCalledOnce())
    await waitFor(() => expect(screen.getByRole('button', { name: 'Status neu lesen' })).toBeEnabled())
    expect(screen.getByRole('alert')).toHaveTextContent('EA-DESTRUCTION-TRANSPORT-UNAVAILABLE')
    expect(screen.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveTextContent('in Bearbeitung')
  })

  it('discards a late re-read that belongs to a replaced bridge', async () => {
    let finishRefresh!: (value: DestructionAdministrationView) => void
    const first = {
      ...bridge(view(offered())),
      markIncomplete: vi.fn(async () => { throw { code: 'EA-DESTRUCTION-TRANSPORT-UNAVAILABLE' } }),
      refresh: vi.fn(() => new Promise<DestructionAdministrationView>((resolve) => { finishRefresh = resolve })),
    }
    const second = bridge(view(offered()))
    const user = userEvent.setup()
    const rendered = render(<DestructionWizard bridge={first} />)
    await user.click(screen.getByRole('button', { name: ACTION }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('checkbox', { name: UNDERSTOOD }))
    await user.click(within(dialog).getByRole('button', { name: CONFIRM }))
    await waitFor(() => expect(first.refresh).toHaveBeenCalledOnce())
    rendered.rerender(<DestructionWizard bridge={second} />)
    await act(async () => finishRefresh(view(offered({ state: 'incompleteUnreachableReplica' }))))
    expect(screen.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveTextContent('in Bearbeitung')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(second.refresh).not.toHaveBeenCalled()
  })
})

describe('DestructionWizard', () => {
  it('shares its native busy lease with explicit Reader file delivery', async () => {
    const selected = process({ state: 'inProgress' })
    const native = bridge(view(selected))
    let complete!: (value: { destructionId: string; jobHash: string; readerId: string; exactAuthorization: number[]; exactInitiatingEvent: number[]; exactJobUpload: number[] }) => void
    const readerDelivery = { export: vi.fn(() => new Promise<Parameters<typeof complete>[0]>((resolve) => { complete = resolve })) }
    render(<DestructionWizard bridge={native} readerDeliveryBridge={readerDelivery} />)
    fireEvent.change(screen.getByRole('combobox', { name: 'Lesegerät für die Übergabe' }), { target: { value: '43'.repeat(16) } })
    fireEvent.click(screen.getByRole('button', { name: 'Dateien für Lesegerät bereitstellen' }))
    expect(screen.getByRole('button', { name: 'Status neu lesen' })).toBeDisabled()
    expect(native.start).not.toHaveBeenCalled()
    expect(native.resume).not.toHaveBeenCalled()
    await act(async () => { complete({ destructionId: PROCESS_ID, jobHash: PREFLIGHT_HASH, readerId: '43'.repeat(16), exactAuthorization: [1], exactInitiatingEvent: [2], exactJobUpload: [3] }) })
    expect(screen.getByRole('button', { name: 'Status neu lesen' })).toBeEnabled()
    expect(readerDelivery.export).toHaveBeenCalledExactlyOnceWith(PROCESS_ID, PREFLIGHT_HASH, '43'.repeat(16))
    expect(native.refresh).not.toHaveBeenCalled()
  })

  it('does not let a late evidence response release a new bridge action or display an old review', async () => {
    const selected = process({ state: 'inProgress' })
    const first = bridge(view(selected))
    const second = bridge(view(selected))
    let finishEvidence!: (value: Awaited<ReturnType<DestructionEvidenceBridge['preview']>>) => void
    let finishRefresh!: (value: DestructionAdministrationView) => void
    const evidence: DestructionEvidenceBridge = {
      preview: vi.fn(() => new Promise<Awaited<ReturnType<DestructionEvidenceBridge['preview']>>>((resolve) => { finishEvidence = resolve })),
      finalize: vi.fn(), recover: vi.fn(), discard: vi.fn(),
    }
    second.refresh = vi.fn(() => new Promise<DestructionAdministrationView>((resolve) => { finishRefresh = resolve }))
    const rendered = render(<DestructionWizard bridge={first} evidenceBridge={evidence} />)
    fireEvent.click(screen.getByRole('button', { name: 'Vernichtungsnachweis vorbereiten' }))
    rendered.rerender(<DestructionWizard bridge={second} evidenceBridge={evidence} />)
    fireEvent.click(screen.getByRole('button', { name: 'Status neu lesen' }))
    expect(second.refresh).toHaveBeenCalledOnce()
    await act(async () => finishEvidence({ writerDeviceId: selected.custodianDeviceId, process: selected, preview: {
      proposedSequence: 2, bindsPredecessor: true, effectiveNow: 1_789_000_000_000,
      trustAgeMs: 1000, readerTrustRefreshMs: 86_400_000, trustRefreshOverdue: false, staleDecision: 'Fresh',
    } }))
    expect(screen.getByRole('button', { name: 'Status neu lesen' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: 'Servernachweise abgleichen' }))
    expect(second.synchronize).not.toHaveBeenCalled()
    expect(screen.queryByText('Vorgeschlagene Sequenz: 2')).not.toBeInTheDocument()
    await act(async () => finishRefresh(second.initial))
    expect(screen.getByRole('button', { name: 'Status neu lesen' })).toBeEnabled()
  })

  it('authenticates the separate custodian only on request and preserves progress on refusal', async () => {
    const host = { ...bridge(view(process({ state: 'inProgress' }))), authenticateCustodian: vi.fn(async () => { throw { code: 'EA-OPERATOR-NATIVE-DENIED' } }) }
    const user = userEvent.setup()
    render(<DestructionWizard bridge={host} />)
    expect(host.authenticateCustodian).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: 'Ausführendes Writer-Gerät anmelden' }))
    expect(host.authenticateCustodian).toHaveBeenCalledExactlyOnceWith(PROCESS_ID, PREFLIGHT_HASH)
    expect(await screen.findByRole('alert')).toHaveTextContent('EA-OPERATOR-NATIVE-DENIED')
    expect(screen.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveTextContent('in Bearbeitung')
    expect(screen.getByText('a1'.repeat(32))).toBeVisible()
    expect(host.start).not.toHaveBeenCalled()
    expect(host.resume).not.toHaveBeenCalled()
    expect(host.synchronize).not.toHaveBeenCalled()
  })

  it('requires a separate resume click after successful custodian login', async () => {
    const host = bridge(view(process({ state: 'inProgress' })))
    const user = userEvent.setup()
    render(<DestructionWizard bridge={host} />)
    await user.click(screen.getByRole('button', { name: 'Ausführendes Writer-Gerät anmelden' }))
    expect(host.authenticateCustodian).toHaveBeenCalledExactlyOnceWith(PROCESS_ID, PREFLIGHT_HASH)
    expect(host.resume).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: 'Vernichtung fortsetzen' }))
    expect(host.resume).toHaveBeenCalledExactlyOnceWith(PROCESS_ID)
  })

  it('reads signed server progress explicitly and preserves the last report when the server refuses', async () => {
    const host = { ...bridge(view(process({ state: 'inProgress' }))), synchronize: vi.fn(async () => { throw { code: 'EA-DESTRUCTION-TRANSPORT-TLS' } }) }
    const user = userEvent.setup()
    render(<DestructionWizard bridge={host} />)
    await user.click(screen.getByRole('button', { name: 'Servernachweise abgleichen' }))
    expect(host.synchronize).toHaveBeenCalledExactlyOnceWith(PROCESS_ID, PREFLIGHT_HASH)
    expect(await screen.findByRole('alert')).toHaveTextContent('EA-DESTRUCTION-TRANSPORT-TLS')
    expect(screen.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveTextContent('in Bearbeitung')
    expect(screen.getByText('a1'.repeat(32))).toBeVisible()
    expect(host.start).not.toHaveBeenCalled()
    expect(host.resume).not.toHaveBeenCalled()
  })

  it('shows all verified approvers and permits deliberate start with more than two signatures', async () => {
    const host = bridge(view(process({ approverCertificateHashes: ['31'.repeat(32), '32'.repeat(32), '33'.repeat(32)] })))
    const user = userEvent.setup()
    render(<DestructionWizard bridge={host} />)
    expect(screen.getByText('33'.repeat(32))).toBeVisible()
    const start = screen.getByRole('button', { name: 'Unwiderruflich starten' })
    expect(start).toBeDisabled()
    await user.click(screen.getByRole('checkbox', { name: /Ich bestätige.*unwiderruflich/ }))
    await user.click(start)
    expect(host.start).toHaveBeenCalledExactlyOnceWith(PROCESS_ID, PREFLIGHT_HASH)
  })

  it('imports exact signed progress bytes for the selected job without changing its state optimistically', async () => {
    const initial = view(process({ state: 'inProgress' }))
    const host = bridge(initial)
    let finish: (result: DestructionAdministrationView) => void = () => undefined
    host.importProgress = vi.fn(() => new Promise<DestructionAdministrationView>((resolve) => { finish = resolve }))
    const user = userEvent.setup()
    render(<DestructionWizard bridge={host} />)
    await user.upload(screen.getByLabelText('Signierte Repliknachweise oder Statusereignisse'), [
      new File([new Uint8Array([0, 255])], 'attestation.etb'),
      new File([new Uint8Array([7, 0, 9])], 'transition.etb'),
    ])
    fireEvent.click(screen.getByRole('button', { name: 'Signierte Nachweise importieren' }))
    await waitFor(() => expect(host.importProgress).toHaveBeenCalledExactlyOnceWith(PROCESS_ID, PREFLIGHT_HASH, [[0, 255], [7, 0, 9]]))
    expect(screen.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveTextContent('in Bearbeitung')
    expect(screen.getByRole('button', { name: 'Signierte Nachweise importieren' })).toBeDisabled()
    finish(view(process({ state: 'pendingBackupExpiry' })))
    await waitFor(() => expect(screen.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveTextContent('wartet auf Backup-Frist'))
    expect(host.start).not.toHaveBeenCalled()
  })

  it('rejects too many progress files before reading or sending the batch', async () => {
    const host = bridge(view(process({ state: 'inProgress' })))
    const user = userEvent.setup()
    render(<DestructionWizard bridge={host} />)
    await user.upload(screen.getByLabelText('Signierte Repliknachweise oder Statusereignisse'), Array.from({ length: 257 }, (_, i) => new File([new Uint8Array([1])], `${i}.etb`)))
    await user.click(screen.getByRole('button', { name: 'Signierte Nachweise importieren' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('höchstens 256 Dateien')
    expect(host.importProgress).not.toHaveBeenCalled()
    expect(screen.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveTextContent('in Bearbeitung')
  })

  it.each(['requested', 'completeManagedScope'] as const)('imports another authorization after opening a %s process without reusing its consent', async (state) => {
    const host = bridge(view(process({ state })))
    const user = userEvent.setup()
    render(<DestructionWizard bridge={host} />)
    if (state === 'requested') await user.click(screen.getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: 'Weitere Autorisierung importieren' }))
    expect(screen.queryByRole('status', { name: 'Vernichtungsstatus' })).not.toBeInTheDocument()
    expect(screen.getByLabelText('Gespeicherter Vernichtungsvorgang')).toHaveValue('')
    await user.upload(screen.getByLabelText('Signierte Vernichtungsautorisierung'), new File([new Uint8Array([0, 7, 255])], 'second.etb'))
    await user.click(screen.getByRole('button', { name: 'Vernichtung beantragen' }))
    expect(await screen.findByRole('checkbox')).not.toBeChecked()
    expect(host.importAuthorization).toHaveBeenCalledExactlyOnceWith([0, 7, 255])
    expect(host.start).not.toHaveBeenCalled()
    expect(host.resume).not.toHaveBeenCalled()
  })

  it('shows only observed verified stubs and actually committed evidence', () => {
    render(<DestructionWizard bridge={bridge(view(process({
      targets: [{ entryHash: 'cc'.repeat(32), chainSequence: 7, stubObjectHash: 'e1'.repeat(32) }],
      evidenceEntryHash: 'e2'.repeat(32),
    })))} />)
    expect(screen.getByText('e1'.repeat(32))).toBeVisible()
    expect(screen.getByText('e2'.repeat(32))).toBeVisible()
    expect(screen.getByText('Finalisierter Vernichtungsnachweis')).toBeVisible()
  })

  it('does not turn an attestation or complete managed state into a committed evidence entry', () => {
    render(<DestructionWizard bridge={bridge(view(process({ state: 'completeManagedScope' })))} />)
    expect(screen.getByText('Kein verifizierter Stub im beobachteten Bestand.')).toBeVisible()
    expect(screen.getByText('Ein finalisierter Vernichtungsnachweis ist noch nicht nachgewiesen.')).toBeVisible()
  })

  it('opens a persisted process by its exact ID and clears prior consent when switching', async () => {
    const host = bridge()
    host.select = vi.fn(async (destructionId: string) => view(process({ destructionId, state: 'inProgress' })))
    const user = userEvent.setup()
    render(<DestructionWizard bridge={host} />)
    await user.click(screen.getByRole('checkbox', { name: /Ich bestätige.*unwiderruflich/i }))
    await user.selectOptions(screen.getByLabelText('Gespeicherter Vernichtungsvorgang'), '20'.repeat(16))
    expect(host.select).toHaveBeenCalledExactlyOnceWith('20'.repeat(16))
    expect(await screen.findByRole('status', { name: 'Vernichtungsstatus' })).toHaveTextContent('in Bearbeitung')
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
    expect(host.start).not.toHaveBeenCalled()
  })

  it('shows every replica, exact attestation and backup deadline without inferring deletion', () => {
    render(<DestructionWizard bridge={bridge(view(process({ state: 'pendingBackupExpiry' })))} />)
    const rows = within(screen.getByRole('table', { name: 'Verwaltete Repliken' })).getAllByRole('row')
    expect(rows).toHaveLength(4)
    expect(rows[1]).toHaveTextContent('41'.repeat(16))
    expect(rows[1]).toHaveTextContent('Erfolgsattestierung verifiziert')
    expect(rows[1]).toHaveTextContent('a1'.repeat(32))
    expect(rows[2]).toHaveTextContent('Backup-Frist offen')
    expect(rows[2]).toHaveTextContent('a2'.repeat(32))
    expect(rows[2]?.querySelector('time')).toHaveAttribute('dateTime', '2026-05-28T20:26:40.000Z')
    expect(rows[3]).toHaveTextContent('Noch keine Attestierung')
    expect(rows[3]).not.toHaveTextContent('Erfolgsattestierung verifiziert')
  })

  it('keeps request disabled without the documented privacy decision', () => {
    const host = bridge({ ...view(null), privacyDecisionEnabled: false })
    render(<DestructionWizard bridge={host} />)
    expect(screen.getByRole('button', { name: 'Vernichtung beantragen' })).toBeDisabled()
    expect(screen.getByText(/datenschutzrechtliche Freigabe fehlt/i)).toBeVisible()
    expect(host.importAuthorization).not.toHaveBeenCalled()
  })

  it('shows imported authorization, both approvers and exact targets before any irreversible step', async () => {
    const host = bridge(view(null))
    const user = userEvent.setup()
    render(<DestructionWizard bridge={host} />)
    const exact = new Uint8Array([0, 1, 2, 255])
    await user.upload(screen.getByLabelText('Signierte Vernichtungsautorisierung'), new File([exact], 'authorization.etb'))
    await user.click(screen.getByRole('button', { name: 'Vernichtung beantragen' }))
    expect(await screen.findByText('cc'.repeat(32))).toBeVisible()
    expect(host.importAuthorization).toHaveBeenCalledExactlyOnceWith([0, 1, 2, 255])
    expect(screen.getByText('31'.repeat(32))).toBeVisible()
    expect(screen.getByText('32'.repeat(32))).toBeVisible()
    expect(screen.getByText(/Bekannte Repliken: 3/)).toBeVisible()
    expect(screen.getByText(PREFLIGHT_HASH)).toBeVisible()
    expect(screen.getByRole('button', { name: 'Unwiderruflich starten' })).toBeDisabled()
    expect(host.start).not.toHaveBeenCalled()
  })

  it('binds explicit confirmation to the displayed process and preflight, with one native action', async () => {
    const host = bridge()
    let finish: (result: DestructionAdministrationView) => void = () => undefined
    host.start = vi.fn(() => new Promise<DestructionAdministrationView>((resolve) => { finish = resolve }))
    const user = userEvent.setup()
    render(<DestructionWizard bridge={host} />)
    await user.click(screen.getByRole('checkbox', { name: /Ich bestätige.*unwiderruflich/i }))
    const start = screen.getByRole('button', { name: 'Unwiderruflich starten' })
    fireEvent.click(start)
    fireEvent.click(start)
    expect(host.start).toHaveBeenCalledExactlyOnceWith(PROCESS_ID, PREFLIGHT_HASH)
    expect(screen.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveTextContent('beantragt')
    finish(view(process({ state: 'inProgress' })))
    await waitFor(() => expect(screen.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveTextContent('in Bearbeitung'))
    expect(screen.queryByRole('button', { name: /abbrechen|cancel|unwiderruflich starten/i })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Vernichtung fortsetzen' })).toBeEnabled()
  })

  it('requires confirmation again after reloading a changed preflight', async () => {
    const host = bridge()
    host.refresh = vi.fn(async () => view(process({ preflight: { ...process().preflight!, jobHash: 'ee'.repeat(32) } })))
    const user = userEvent.setup()
    render(<DestructionWizard bridge={host} />)
    await user.click(screen.getByRole('checkbox', { name: /Ich bestätige.*unwiderruflich/i }))
    await user.click(screen.getByRole('button', { name: 'Status neu lesen' }))
    expect(await screen.findByText('ee'.repeat(32))).toBeVisible()
    expect(screen.getByRole('checkbox')).not.toBeChecked()
    expect(screen.getByRole('button', { name: 'Unwiderruflich starten' })).toBeDisabled()
  })

  it('keeps the verified process when native presence or current authority is refused', async () => {
    const host = bridge()
    host.start = vi.fn(async () => { throw { code: 'EA-OPERATOR-REAUTHENTICATION' } })
    const user = userEvent.setup()
    render(<DestructionWizard bridge={host} />)
    await user.click(screen.getByRole('checkbox', { name: /Ich bestätige.*unwiderruflich/i }))
    await user.click(screen.getByRole('button', { name: 'Unwiderruflich starten' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('EA-OPERATOR-REAUTHENTICATION')
    expect(screen.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveTextContent('beantragt')
    expect(screen.getByRole('checkbox')).not.toBeChecked()
  })

  it.each([
    ['inProgress', 'in Bearbeitung'],
    ['pendingBackupExpiry', 'wartet auf Backup-Frist'],
    ['incompleteUnreachableReplica', 'bekannte Replik nicht erreichbar'],
  ] as const)('reopens %s with resume only and never infers completion from time', async (state, label) => {
    const host = bridge(view(process({ state })))
    const user = userEvent.setup()
    const first = render(<DestructionWizard bridge={host} />)
    first.unmount()
    render(<DestructionWizard bridge={host} />)
    expect(screen.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveTextContent(label)
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /abbrechen|cancel|beantragen|starten/i })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Vernichtung fortsetzen' }))
    expect(host.resume).toHaveBeenCalledExactlyOnceWith(PROCESS_ID)
    expect(screen.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveTextContent(label)
  })

  it('shows managed completion without offering another execution', () => {
    render(<DestructionWizard bridge={bridge(view(process({ state: 'completeManagedScope' })))} />)
    expect(screen.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveTextContent('im verwalteten Umfang abgeschlossen')
    const region = screen.getByRole('region', { name: 'Kontrollierte Vernichtung' })
    expect(within(region).queryByRole('button', { name: /fortsetzen|starten|beantragen/i })).not.toBeInTheDocument()
    expect(screen.getByText(/Unbekannte Exporte, Screenshots/)).toBeVisible()
  })
})
