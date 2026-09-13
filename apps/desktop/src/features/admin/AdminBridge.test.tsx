import { invoke } from '@tauri-apps/api/core'
import { beforeEach, expect, it, vi } from 'vitest'

import { ADMIN_COMMANDS, REAUTH_PURPOSES, connectAdminBridge } from './AdminPage'
import { WRITER_COMMANDS } from '../writer/WriterPage'

// Die Naht selbst: `connectAdminBridge` ist der EINZIGE Ort, an dem die Schale
// die Argumentnamen des Wirts ausschreibt (`admin-ui-contract.md` §5). Kein
// Zeuge ueber `AdminPage` sieht sie — die Seite bekommt eine fertige Bruecke.
// Deshalb wird hier `invoke` selbst besetzt und jede Handlung einmal gerufen:
// ein umbenanntes Feld (`{ id }` statt `{ ceremonyId }`) faellt an genau einer
// Zusicherung, und nicht erst im Playwright-Lauf.
vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }))

const invoked = vi.mocked(invoke)

const CEREMONY = {
  ceremonyId: 'zeremonie-1',
  round: 'ActivateRegistry', linkedCeremonyId: null, fingerprintSubject: null,
  kind: 'DeviceApprove',
  step: 'PendingRequest',
  targetFingerprint: null,
  exchangeFileName: null,
}

const TRANSITION = {
  phase: 'NoTransition',
  ceremonyId: null,
  currentWriterHash: 'AA'.repeat(32),
  newWriterHash: null,
  effectiveFromSequence: null,
}

/** Die Drahtantworten je Kommando — gueltig nach `contract-check.ts`. */
const ANSWERS: Record<string, unknown> = {
  [ADMIN_COMMANDS.diagnoseWriterLock]: 'Missing',
  [ADMIN_COMMANDS.openCeremonies]: [],
  [ADMIN_COMMANDS.pendingDeviceRequests]: [],
  [ADMIN_COMMANDS.goLiveChecklist]: { requirements: [], productionReady: false },
  [ADMIN_COMMANDS.registryHealth]: {
    registryVersion: 1,
    headHash: 'CC'.repeat(32),
    registryAgeMs: 1,
    maxRegistryAgeMs: 2,
    leaseValidThroughSequence: 3,
    nextSequence: 2,
    notAfterMs: 4,
    staleDecision: 'Fresh',
  },
  [ADMIN_COMMANDS.policyProfile]: {
    operatingProfile: 0,
    maxRegistryAgeMs: 1,
    maxFutureClockSkewMs: 1,
    registryExpiryBehavior: 0,
    evidenceMaxDelayMs: 1,
    readerInactivityMs: 1,
    readerTrustRefreshMs: 1,
    readerHistoryAccessAllowed: false,
    backupFrequencyMs: 1,
    restoreTestIntervalMs: 1,
    minimumRetentionMs: null,
    destructionEnabled: false,
    effectiveFromSequence: 1,
    leaseValidThroughSequence: 1,
    notAfterMs: 1,
  },
  [ADMIN_COMMANDS.writerTransitionState]: TRANSITION,
  [ADMIN_COMMANDS.clockReleaseOffer]: {
    availability: 'NotBlocked',
    floorMs: null,
    observedWallClockMs: null,
    maxFutureClockSkewMs: null,
    expiresAtMs: null,
    justifications: [],
  },
  [WRITER_COMMANDS.devicePosture]: { requirements: [], productionReady: false },
  [WRITER_COMMANDS.reauthenticate]: { fresh: true, purposeCode: 'EA-OPERATOR-REAUTH' },
  [ADMIN_COMMANDS.ceremonyBegin]: CEREMONY,
  [ADMIN_COMMANDS.ceremonyRead]: CEREMONY,
  [ADMIN_COMMANDS.ceremonyConfirmFingerprint]: CEREMONY,
  [ADMIN_COMMANDS.ceremonyAuthorize]: CEREMONY,
  [ADMIN_COMMANDS.ceremonyExportRequest]: CEREMONY,
  [ADMIN_COMMANDS.ceremonyImportReply]: CEREMONY,
  [ADMIN_COMMANDS.ceremonyPublish]: CEREMONY,
  [ADMIN_COMMANDS.goLiveExportUnresolved]: '{"format":"ea.go-live-checklist/v1","unresolved":[]}',
  [ADMIN_COMMANDS.clockReleaseIssue]: {
    releaseId: 'freigabe-1',
    expiresAtMs: 1,
    changesTimeFloor: false,
    changesRegistryExpiry: false,
    changesLease: false,
  },
  [ADMIN_COMMANDS.writerTransitionPrepare]: TRANSITION,
  [ADMIN_COMMANDS.writerTransitionActivate]: TRANSITION,
  [ADMIN_COMMANDS.revocationEffect]: {
    targetClass: 'NonAdminDevice',
    targetHash: 'DD'.repeat(32),
    stopsNewGrantsFromSequence: 1,
    recallsIssuedGrants: false,
    recallsDecryptedPlaintext: false,
  },
}

beforeEach(() => {
  invoked.mockReset()
  invoked.mockImplementation((command: string) => {
    if (!(command in ANSWERS)) {
      return Promise.reject(new Error(`unbekanntes Kommando: ${command}`))
    }
    return Promise.resolve(ANSWERS[command])
  })
})

it('reads the eight values with the eight argument-free commands', async () => {
  await connectAdminBridge()
  for (const command of [
    ADMIN_COMMANDS.openCeremonies,
    ADMIN_COMMANDS.pendingDeviceRequests,
    ADMIN_COMMANDS.goLiveChecklist,
    ADMIN_COMMANDS.registryHealth,
    ADMIN_COMMANDS.policyProfile,
    ADMIN_COMMANDS.writerTransitionState,
    ADMIN_COMMANDS.clockReleaseOffer,
    WRITER_COMMANDS.devicePosture,
  ]) {
    expect(invoked).toHaveBeenCalledWith(command, undefined)
  }
  expect(invoked).toHaveBeenCalledTimes(8)
})

it('sends every action under the argument names of the host contract', async () => {
  const bridge = await connectAdminBridge()

  await bridge.reauthenticate(REAUTH_PURPOSES.adminRootCeremony)
  expect(invoked).toHaveBeenLastCalledWith(WRITER_COMMANDS.reauthenticate, {
    purpose: 'admin-root-ceremony',
  })

  await bridge.beginCeremony('anfrage-1', 'DeviceApprove')
  expect(invoked).toHaveBeenLastCalledWith(ADMIN_COMMANDS.ceremonyBegin, {
    requestId: 'anfrage-1',
    kind: 'DeviceApprove',
  })

  await bridge.confirmFingerprint('zeremonie-1', 'AB:CD')
  expect(invoked).toHaveBeenLastCalledWith(ADMIN_COMMANDS.ceremonyConfirmFingerprint, {
    ceremonyId: 'zeremonie-1',
    reportedFingerprint: 'AB:CD',
  })

  await bridge.readCeremony('zeremonie-1')
  expect(invoked).toHaveBeenLastCalledWith(ADMIN_COMMANDS.ceremonyRead, { ceremonyId: 'zeremonie-1' })

  await bridge.authorize('zeremonie-1')
  expect(invoked).toHaveBeenLastCalledWith(ADMIN_COMMANDS.ceremonyAuthorize, {
    ceremonyId: 'zeremonie-1',
  })

  await bridge.exportRequest('zeremonie-1')
  expect(invoked).toHaveBeenLastCalledWith(ADMIN_COMMANDS.ceremonyExportRequest, {
    ceremonyId: 'zeremonie-1',
  })

  await bridge.importReply('zeremonie-1')
  expect(invoked).toHaveBeenLastCalledWith(ADMIN_COMMANDS.ceremonyImportReply, {
    ceremonyId: 'zeremonie-1',
  })

  await bridge.publish('zeremonie-1')
  expect(invoked).toHaveBeenLastCalledWith(ADMIN_COMMANDS.ceremonyPublish, {
    ceremonyId: 'zeremonie-1',
  })

  await bridge.exportUnresolved()
  expect(invoked).toHaveBeenLastCalledWith(ADMIN_COMMANDS.goLiveExportUnresolved, undefined)

  await bridge.issueClockRelease('OperatorVerifiedWallClock')
  expect(invoked).toHaveBeenLastCalledWith(ADMIN_COMMANDS.clockReleaseIssue, {
    justification: 'OperatorVerifiedWallClock',
  })

  await bridge.prepareWriterTransition('{"newWriter":"BB"}')
  expect(invoked).toHaveBeenLastCalledWith(ADMIN_COMMANDS.writerTransitionPrepare, {
    requestJson: '{"newWriter":"BB"}',
  })

  await bridge.activateWriterTransition()
  expect(invoked).toHaveBeenLastCalledWith(ADMIN_COMMANDS.writerTransitionActivate, undefined)

  await bridge.revocationEffect('DD'.repeat(32))
  expect(invoked).toHaveBeenLastCalledWith(ADMIN_COMMANDS.revocationEffect, {
    targetHash: 'DD'.repeat(32),
  })

  // Acht Werte plus dreizehn Handlungen: 21 Aufrufe, und jedes der 19
  // Verwaltungskommandos ist GENAU einmal ueber den Draht gegangen — keine
  // Handlung ruft ein zweites Kommando, keine laesst ihres aus.
  expect(invoked).toHaveBeenCalledTimes(21)
  await bridge.diagnoseWriterLock()
  expect(invoked).toHaveBeenLastCalledWith(ADMIN_COMMANDS.diagnoseWriterLock, undefined)
  const names = invoked.mock.calls.map(([command]) => command)
  for (const command of Object.values(ADMIN_COMMANDS)) {
    expect(names.filter((name) => name === command)).toHaveLength(1)
  }
  expect(names.filter((name) => name === WRITER_COMMANDS.reauthenticate)).toHaveLength(1)
  expect(names.filter((name) => name === WRITER_COMMANDS.devicePosture)).toHaveLength(1)
})

it('refuses the bridge when a value answer leaves the contract', async () => {
  invoked.mockImplementation((command: string) =>
    Promise.resolve(
      command === ADMIN_COMMANDS.policyProfile
        ? { ...(ANSWERS[command] as Record<string, unknown>), destructionEnabled: 'nein' }
        : ANSWERS[command],
    ),
  )
  await expect(connectAdminBridge()).rejects.toMatchObject({ name: 'ContractViolation' })
})

it('validates the clock release outcome the host returns', async () => {
  const bridge = await connectAdminBridge()
  invoked.mockImplementation(() =>
    Promise.resolve({ ...(ANSWERS[ADMIN_COMMANDS.clockReleaseIssue] as object), changesTimeFloor: 1 }),
  )
  await expect(bridge.issueClockRelease('HardwareClockMaintenance')).rejects.toMatchObject({
    name: 'ContractViolation',
  })
})

it('refuses a different ceremony when opening the linked activation', async () => {
  const bridge = await connectAdminBridge()
  await expect(bridge.readCeremony('other-id')).rejects.toMatchObject({ name: 'ContractViolation' })
})


it('diagnoses the lock only on request with no IPC arguments and validates every answer', async () => {
  const bridge = await connectAdminBridge()
  expect(invoked).not.toHaveBeenCalledWith('admin_writer_lock_diagnosis', undefined)
  for (const value of ['Missing', 'AbandonedInert', 'LiveOwner', 'Unreadable']) {
    invoked.mockResolvedValueOnce(value)
    await expect(bridge.diagnoseWriterLock()).resolves.toBe(value)
    expect(invoked).toHaveBeenLastCalledWith('admin_writer_lock_diagnosis', undefined)
  }
  for (const value of ['Ready', null, { state: 'Missing' }, '/private/archive']) {
    invoked.mockResolvedValueOnce(value)
    await expect(bridge.diagnoseWriterLock()).rejects.toMatchObject({ name: 'ContractViolation' })
  }
})
