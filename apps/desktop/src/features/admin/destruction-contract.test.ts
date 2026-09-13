import { describe, expect, it } from 'vitest'

import { validateDestructionAdministration } from './destruction-contract'

function current(): Record<string, unknown> {
  return {
    privacyDecisionEnabled: true,
    policyHash: '11'.repeat(32),
    knownDestructionIds: ['22'.repeat(16)],
    process: {
      destructionId: '22'.repeat(16),
      authorizationObjectHash: '33'.repeat(32),
      state: 'requested',
      scopeCode: 1,
      legalReasonCode: 2,
      controllerDeviceId: '44'.repeat(16),
      custodianDeviceId: '55'.repeat(16),
      approverCertificateHashes: ['66'.repeat(32), '77'.repeat(32)],
      targets: [{ entryHash: '88'.repeat(32), chainSequence: 7, stubObjectHash: null }],
      evidenceEntryHash: null,
      preflight: { jobHash: '99'.repeat(32), exactCanonicalReportJson: '{"knownReplicaCount":3}', knownReplicaCount: 3 },
      replicas: [
        { deviceId: 'aa'.repeat(16), kindCode: 0, attestationHash: null, resultCode: null, backupExpiryAt: null },
        { deviceId: 'bb'.repeat(16), kindCode: 1, attestationHash: null, resultCode: null, backupExpiryAt: null },
        { deviceId: 'cc'.repeat(16), kindCode: 2, attestationHash: null, resultCode: null, backupExpiryAt: null },
      ],
    },
  }
}

describe('destruction host contract', () => {
  it.each([
    ['sequence zero', { targets: [{ entryHash: '88'.repeat(32), chainSequence: 0, stubObjectHash: null }] }],
    ['three distinct approvers', { approverCertificateHashes: ['66'.repeat(32), '77'.repeat(32), 'aa'.repeat(32)] }],
    ['distinct hashes with equal sequence', { targets: [
      { entryHash: '88'.repeat(32), chainSequence: 7, stubObjectHash: null },
      { entryHash: '99'.repeat(32), chainSequence: 7, stubObjectHash: null },
    ] }],
  ])('preserves native-valid %s without redefining authorization', (_, fields) => {
    const raw = current()
    Object.assign(raw.process as Record<string, unknown>, fields)
    expect(validateDestructionAdministration(raw).process).toMatchObject(fields)
  })

  it('preserves the exact host preflight and excludes undeclared payload fields', () => {
    const raw = current()
    raw.plaintext = 'not part of the administrative view'
    const parsed = validateDestructionAdministration(raw)
    expect(parsed.process?.preflight?.exactCanonicalReportJson).toBe('{"knownReplicaCount":3}')
    expect(parsed).not.toHaveProperty('plaintext')
  })

  it.each([
    ['missing privacy decision', (raw: Record<string, unknown>) => { delete raw.privacyDecisionEnabled }],
    ['unknown state', (raw: Record<string, unknown>) => { (raw.process as Record<string, unknown>).state = 'complete' }],
    ['single approver', (raw: Record<string, unknown>) => { (raw.process as Record<string, unknown>).approverCertificateHashes = ['66'.repeat(32)] }],
    ['negative target sequence', (raw: Record<string, unknown>) => { (raw.process as Record<string, unknown>).targets = [{ entryHash: '88'.repeat(32), chainSequence: -1, stubObjectHash: null }] }],
    ['duplicate approver', (raw: Record<string, unknown>) => { (raw.process as Record<string, unknown>).approverCertificateHashes = ['66'.repeat(32), '66'.repeat(32)] }],
    ['missing preflight instead of explicit null', (raw: Record<string, unknown>) => { delete (raw.process as Record<string, unknown>).preflight }],
    ['host path instead of device ID', (raw: Record<string, unknown>) => { (raw.process as Record<string, unknown>).custodianDeviceId = '/Users/operator/database' }],
    ['unsafe target sequence', (raw: Record<string, unknown>) => { (raw.process as Record<string, unknown>).targets = [{ entryHash: '88'.repeat(32), chainSequence: Number.MAX_SAFE_INTEGER + 1, stubObjectHash: null }] }],
    ['duplicate target', (raw: Record<string, unknown>) => { const target = { entryHash: '88'.repeat(32), chainSequence: 7, stubObjectHash: null }; (raw.process as Record<string, unknown>).targets = [target, target] }],
    ['zero known replicas', (raw: Record<string, unknown>) => { (raw.process as Record<string, unknown>).preflight = { jobHash: '99'.repeat(32), exactCanonicalReportJson: '{}', knownReplicaCount: 0 } }],
    ['duplicate persisted ID', (raw: Record<string, unknown>) => { raw.knownDestructionIds = ['22'.repeat(16), '22'.repeat(16)] }],
    ['unlisted selected process', (raw: Record<string, unknown>) => { raw.knownDestructionIds = [] }],
    ['success without attestation', (raw: Record<string, unknown>) => { ((raw.process as Record<string, unknown>).replicas as Record<string, unknown>[])[0]!.resultCode = 0 }],
    ['unknown replica result', (raw: Record<string, unknown>) => { ((raw.process as Record<string, unknown>).replicas as Record<string, unknown>[])[0]!.resultCode = 3 }],
    ['pending backup without deadline', (raw: Record<string, unknown>) => { const replica = ((raw.process as Record<string, unknown>).replicas as Record<string, unknown>[])[0]!; replica.resultCode = 1; replica.attestationHash = '01'.repeat(32) }],
    ['truncated replica list', (raw: Record<string, unknown>) => { ((raw.process as Record<string, unknown>).replicas as Record<string, unknown>[]).pop() }],
    ['evidence path instead of hash', (raw: Record<string, unknown>) => { (raw.process as Record<string, unknown>).evidenceEntryHash = '/tmp/evidence.eip' }],
    ['missing explicit evidence observation', (raw: Record<string, unknown>) => { delete (raw.process as Record<string, unknown>).evidenceEntryHash }],
    ['missing explicit stub observation', (raw: Record<string, unknown>) => { delete ((raw.process as Record<string, unknown>).targets as Record<string, unknown>[])[0]!.stubObjectHash }],
  ])('refuses %s', (_, mutate) => {
    const raw = current()
    mutate(raw)
    expect(() => validateDestructionAdministration(raw)).toThrow()
  })

  it('allows an explicitly empty process without fabricating one', () => {
    const raw = { ...current(), process: null }
    expect(validateDestructionAdministration(raw).process).toBeNull()
  })
})
