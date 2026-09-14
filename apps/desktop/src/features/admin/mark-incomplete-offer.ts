import type { DestructionProcessView } from '../../bridge/generated-contracts'
import { DESTRUCTION_STATE_V1_VALUES } from '../../bridge/generated-contracts'

const [, IN_PROGRESS, PENDING_BACKUP_EXPIRY] = DESTRUCTION_STATE_V1_VALUES

/**
 * Visibility only for „Als unvollständig abschließen". Mirrors the host's offer
 * predicate (`mark_incomplete_job`): after the custodian Writer's verified
 * cleanup, a known replica has no attestation (`resultCode` null), a negative
 * latest one (2), or an attested backup deadline has elapsed (1). The host
 * re-reads its own status and decides with its own selected time; renderer
 * time grants no authority and never changes a state.
 */
export function markIncompleteOffered(process: DestructionProcessView, nowMs: number): boolean {
  if ((process.state !== IN_PROGRESS && process.state !== PENDING_BACKUP_EXPIRY)
    || process.preflight === null
    || process.targets.length === 0
    || process.targets.some((target) => target.stubObjectHash === null)
    || !process.replicas.some((replica) => replica.deviceId === process.custodianDeviceId
      && replica.kindCode === 0 && replica.resultCode === 0 && replica.attestationHash !== null)) {
    return false
  }
  let offered = false
  for (const replica of process.replicas) {
    if (replica.resultCode === 0) continue
    if (replica.resultCode === 1) {
      // The native core refuses a Pending claim without a deadline.
      if (replica.backupExpiryAt === null) return false
      if (replica.backupExpiryAt <= nowMs) offered = true
      continue
    }
    offered = true
  }
  return offered
}
