import { describe, expect, it } from 'vitest'

import { markIncompleteOffered } from './mark-incomplete-offer'
import type { DestructionProcessView, DestructionReplicaView } from '../../bridge/generated-contracts'

const NOW = 1_789_000_000_000
const CUSTODIAN = '41'.repeat(16)
const writer: DestructionReplicaView = { deviceId: CUSTODIAN, kindCode: 0, attestationHash: 'a1'.repeat(32), resultCode: 0, backupExpiryAt: null }
const never = (n: string, kindCode = 1): DestructionReplicaView => ({ deviceId: n.repeat(16), kindCode, attestationHash: null, resultCode: null, backupExpiryAt: null })
const negative = (n: string): DestructionReplicaView => ({ deviceId: n.repeat(16), kindCode: 1, attestationHash: n.repeat(32), resultCode: 2, backupExpiryAt: null })
const backup = (n: string, expiry: number | null): DestructionReplicaView => ({ deviceId: n.repeat(16), kindCode: 1, attestationHash: n.repeat(32), resultCode: 1, backupExpiryAt: expiry })
const success = (n: string): DestructionReplicaView => ({ deviceId: n.repeat(16), kindCode: 1, attestationHash: n.repeat(32), resultCode: 0, backupExpiryAt: null })

function process(replicas: readonly DestructionReplicaView[], overrides: Partial<DestructionProcessView> = {}): DestructionProcessView {
  return {
    destructionId: '10'.repeat(16), authorizationObjectHash: 'ab'.repeat(32), state: 'inProgress', scopeCode: 1, legalReasonCode: 2,
    controllerDeviceId: '11'.repeat(16), custodianDeviceId: CUSTODIAN, approverCertificateHashes: ['31'.repeat(32), '32'.repeat(32)],
    targets: [{ entryHash: 'cc'.repeat(32), chainSequence: 7, stubObjectHash: 'e1'.repeat(32) }],
    preflight: { jobHash: 'aa'.repeat(32), exactCanonicalReportJson: '{}', knownReplicaCount: replicas.length },
    replicas, evidenceEntryHash: null, ...overrides,
  }
}

describe('markIncompleteOffered (visibility only)', () => {
  it.each(['inProgress', 'pendingBackupExpiry'] as const)('offers in %s for an elapsed deadline or a missing or negative attestation', (state) => {
    for (const replicas of [
      [writer, backup('42', NOW)],
      [writer, backup('42', NOW + 1), backup('43', NOW - 1)],
      [writer, never('42')],
      [writer, never('42', 2)],
      [writer, negative('42')],
      [writer, backup('42', NOW + 1), never('43')],
      [writer, success('42'), negative('43')],
    ]) {
      expect(markIncompleteOffered(process(replicas, { state }), NOW)).toBe(true)
    }
  })

  it('does not offer while every open duty still has a running deadline', () => {
    expect(markIncompleteOffered(process([writer, backup('42', NOW + 1)]), NOW)).toBe(false)
    expect(markIncompleteOffered(process([writer, success('42')]), NOW)).toBe(false)
  })

  it('stays inside the envelope the native core accepts', () => {
    // The core refuses a Pending claim without a deadline.
    expect(markIncompleteOffered(process([writer, never('42'), backup('43', null)]), NOW)).toBe(false)
    for (const state of ['requested', 'completeManagedScope', 'incompleteUnreachableReplica'] as const) {
      expect(markIncompleteOffered(process([writer, never('42')], { state }), NOW)).toBe(false)
    }
    expect(markIncompleteOffered(process([writer, never('42')], { targets: [{ entryHash: 'cc'.repeat(32), chainSequence: 7, stubObjectHash: null }] }), NOW)).toBe(false)
    expect(markIncompleteOffered(process([writer, never('42')], { targets: [] }), NOW)).toBe(false)
    expect(markIncompleteOffered(process([writer, never('42')], { preflight: null }), NOW)).toBe(false)
    expect(markIncompleteOffered(process([writer, never('42')], { custodianDeviceId: '77'.repeat(16) }), NOW)).toBe(false)
    // Before the custodian's own cleanup the offer stays closed.
    expect(markIncompleteOffered(process([never(CUSTODIAN.slice(0, 2), 0), never('42')]), NOW)).toBe(false)
  })
})
