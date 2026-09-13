import { describe, expect, it } from 'vitest'
import type { RecoveryAdministrationView, RecoveryMediumRequestView, RecoveryReportView } from '../../bridge/generated-contracts'
import { validateRecoveryAdministration } from './recovery-contract'

export const requestedMedium: RecoveryMediumRequestView = {
  runId: '11'.repeat(16), requestId: '22'.repeat(32), mediumIdHash: '33'.repeat(32),
  index: 1, total: 2, roleCode: 'root', certificateHash: '44'.repeat(32),
  expectedThumbprint: '55'.repeat(32), protectionCode: 2, testKindCode: 'signatureChallenge',
}
export function pendingRecovery(): RecoveryAdministrationView {
  return { lastSuccess: null, lastFailure: null, run: {
    operationId: '66'.repeat(16), phaseCode: 1, request: { ...requestedMedium },
    observations: [], report: null, errorCode: null,
  } }
}
function report(completed: boolean): RecoveryReportView {
  return { completed, exactPublicReportJson: JSON.stringify({ schemaId: 'ea.recovery-test/v1',
    testId: '11'.repeat(16), sourceEnvelopeHash: '77'.repeat(32), sourceMachine: 'aa'.repeat(32),
    targetMachine: 'bb'.repeat(32), targetInstallation: 'cc'.repeat(32), anchorHash: 'dd'.repeat(32),
    archiveInventoryHash: 'ee'.repeat(32), tipSequence: 0, tipEntryHash: 'ff'.repeat(32), registryVersion: 1,
    registryHeadHash: 'aa'.repeat(32), proposedSequence: 1, effectiveNow: 1_700_000_000_000,
    releaseVersion: '0.1.0', schemaVersions: [], suiteVersions: [], media: [], samples: [],
    result: completed ? 'complete' : 'failed' }), envelopeHash: '88'.repeat(32),
    sourceEnvelopeHash: '77'.repeat(32), auditId: '99'.repeat(16), finishedAtMs: 1_700_000_020_000,
    nextDueAtMs: completed ? 1_700_086_420_000 : null }
}
describe('native recovery view boundary', () => {
  it('accepts a pending cancellation only without an invented outcome or further medium input', () => {
    const pending = pendingRecovery()
    const cancelling = { ...pending, run: { ...pending.run!, phaseCode: 7, request: null } }
    expect(validateRecoveryAdministration(cancelling)).toEqual(cancelling)
    for (const patch of [{ request: requestedMedium }, { report: report(true) }, { errorCode: 'EA-RECOVERY-TEST-CANCELLED' }]) {
      expect(() => validateRecoveryAdministration({ ...cancelling, run: { ...cancelling.run, ...patch } })).toThrow()
    }
  })
  it('preserves the actual pending request and separately verified historical reports', () => {
    const view = { ...pendingRecovery(), lastSuccess: report(true), lastFailure: report(false) }
    expect(validateRecoveryAdministration(view)).toEqual(view)
    expect(validateRecoveryAdministration({ lastSuccess: null, lastFailure: null, run: null })).toEqual({ lastSuccess: null, lastFailure: null, run: null })
  })
  it('rejects missing identity fields, unsafe positions and unknown protocol codes', () => {
    for (const patch of [{ runId: undefined }, { requestId: 'AA'.repeat(32) }, { index: 0 },
      { index: 3 }, { total: 1025 }, { index: Number.MAX_SAFE_INTEGER + 1 },
      { roleCode: 'administrator-confirmed' }, { protectionCode: 5 }, { testKindCode: 'verified' }]) {
      const view = pendingRecovery(); Object.assign(view.run!.request!, patch)
      expect(() => validateRecoveryAdministration(view)).toThrow()
    }
  })
  it('does not accept an expected thumbprint as an actual successful observation', () => {
    for (const observed of [null, 'aa'.repeat(32)]) {
      const view = pendingRecovery(); Object.assign(view.run!, { phaseCode: 0, request: null,
        observations: [{ request: requestedMedium, resultCode: 0, observedThumbprint: observed, errorCode: null }] })
      expect(() => validateRecoveryAdministration(view)).toThrow()
    }
  })
  it('rejects a stale run or repeated medium in a later request', () => {
    for (const patch of [{ runId: 'aa'.repeat(16) }, { mediumIdHash: requestedMedium.mediumIdHash }, { index: 1 }]) {
      const view = pendingRecovery(); Object.assign(view.run!, { observations: [{ request: requestedMedium,
        resultCode: 1, observedThumbprint: null, errorCode: 'EA-RECOVERY-TEST-INCOMPLETE' }] })
      Object.assign(view.run!.request!, { index: 2, requestId: 'bb'.repeat(32), mediumIdHash: 'cc'.repeat(32) }, patch)
      expect(() => validateRecoveryAdministration(view)).toThrow()
    }
  })
  it('rejects completed status without its persisted success report or with a failed report', () => {
    for (const result of [null, report(false)]) {
      const view = pendingRecovery(); Object.assign(view.run!, { phaseCode: 3, request: null, report: result })
      expect(() => validateRecoveryAdministration(view)).toThrow()
    }
  })
  it('rejects a failure in lastSuccess and a success with contradictory public report bytes', () => {
    const failed = { ...pendingRecovery(), lastSuccess: report(false) }
    expect(() => validateRecoveryAdministration(failed)).toThrow()
    const mismatch = { ...pendingRecovery(), lastSuccess: { ...report(true), exactPublicReportJson: report(false).exactPublicReportJson } }
    expect(() => validateRecoveryAdministration(mismatch)).toThrow()
  })
  it('preserves native refusal and cancellation without inventing a result', () => {
    for (const phaseCode of [5, 6]) {
      const view = pendingRecovery(); Object.assign(view.run!, { phaseCode, request: null, errorCode: 'EA-RECOVERY-TEST-CANCELLED' })
      expect(validateRecoveryAdministration(view)).toEqual(view)
    }
  })
})
