import { ContractViolation } from './contract-check'
import { DESTRUCTION_STATE_V1_VALUES } from '../../bridge/generated-contracts'
import type { DestructionAdministrationView, DestructionPreflightView, DestructionProcessView, DestructionReplicaView, DestructionTargetView } from '../../bridge/generated-contracts'

function reject(): never {
  throw new ContractViolation('Der Vernichtungsstand ist unvollständig oder außerhalb des Kontrakts.')
}

function object(raw: unknown): Record<string, unknown> {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return reject()
  return raw as Record<string, unknown>
}

function hex(raw: unknown, length: number): string {
  if (typeof raw !== 'string' || raw.length !== length || !/^[0-9a-f]+$/.test(raw)) return reject()
  return raw
}

function integer(raw: unknown, minimum: number): number {
  if (typeof raw !== 'number' || !Number.isSafeInteger(raw) || raw < minimum) return reject()
  return raw
}

function list(raw: unknown, minimum: number, maximum: number): unknown[] {
  if (!Array.isArray(raw) || raw.length < minimum || raw.length > maximum) return reject()
  return raw
}

function target(raw: unknown): DestructionTargetView {
  const value = object(raw)
  return {
    entryHash: hex(value.entryHash, 64),
    chainSequence: integer(value.chainSequence, 0),
    stubObjectHash: value.stubObjectHash === null ? null : hex(value.stubObjectHash, 64),
  }
}

function replica(raw: unknown): DestructionReplicaView {
  const value = object(raw)
  const kindCode = integer(value.kindCode, 0)
  const resultCode = value.resultCode === null ? null : integer(value.resultCode, 0)
  const attestationHash = value.attestationHash === null ? null : hex(value.attestationHash, 64)
  const backupExpiryAt = value.backupExpiryAt === null ? null : integer(value.backupExpiryAt, 0)
  if (kindCode > 2 || (resultCode !== null && resultCode > 2)
    || (resultCode === null) !== (attestationHash === null)
    || (resultCode === 1 && backupExpiryAt === null)
    || (backupExpiryAt !== null && Number.isNaN(new Date(backupExpiryAt).getTime()))) return reject()
  return { deviceId: hex(value.deviceId, 32), kindCode, attestationHash, resultCode, backupExpiryAt }
}

function preflight(raw: unknown): DestructionPreflightView | null {
  if (raw === null) return null
  const value = object(raw)
  if (typeof value.exactCanonicalReportJson !== 'string' || value.exactCanonicalReportJson.length === 0
    || value.exactCanonicalReportJson.length > 1_048_576) return reject()
  try { object(JSON.parse(value.exactCanonicalReportJson)) } catch { return reject() }
  return {
    jobHash: hex(value.jobHash, 64),
    exactCanonicalReportJson: value.exactCanonicalReportJson,
    knownReplicaCount: integer(value.knownReplicaCount, 1),
  }
}

export function validateDestructionProcess(raw: unknown): DestructionProcessView | null {
  if (raw === null) return null
  const value = object(raw)
  const state = DESTRUCTION_STATE_V1_VALUES.find((item) => item === value.state)
  if (state === undefined) return reject()
  const approvers = list(value.approverCertificateHashes, 2, Number.MAX_SAFE_INTEGER).map((item) => hex(item, 64))
  if (new Set(approvers).size !== approvers.length) return reject()
  const targets = list(value.targets, 1, 4096).map(target)
  if (new Set(targets.map((item) => item.entryHash)).size !== targets.length) return reject()
  const verifiedPreflight = preflight(value.preflight)
  const replicas = list(value.replicas, 0, 4096).map(replica)
  if (new Set(replicas.map((item) => item.deviceId)).size !== replicas.length
    || (verifiedPreflight !== null && verifiedPreflight.knownReplicaCount !== replicas.length)) return reject()
  return {
    destructionId: hex(value.destructionId, 32),
    authorizationObjectHash: hex(value.authorizationObjectHash, 64),
    state,
    scopeCode: integer(value.scopeCode, 0),
    legalReasonCode: integer(value.legalReasonCode, 0),
    controllerDeviceId: hex(value.controllerDeviceId, 32),
    custodianDeviceId: hex(value.custodianDeviceId, 32),
    approverCertificateHashes: approvers,
    targets,
    preflight: verifiedPreflight,
    replicas,
    evidenceEntryHash: value.evidenceEntryHash === null ? null : hex(value.evidenceEntryHash, 64),
  }
}

/** Structural validation only; native Rust verifies signatures and controls every action. */
export function validateDestructionAdministration(raw: unknown): DestructionAdministrationView {
  const value = object(raw)
  if (typeof value.privacyDecisionEnabled !== 'boolean') return reject()
  const knownDestructionIds = list(value.knownDestructionIds, 0, 4096).map((item) => hex(item, 32))
  const selected = validateDestructionProcess(value.process)
  if (new Set(knownDestructionIds).size !== knownDestructionIds.length
    || (selected !== null && !knownDestructionIds.includes(selected.destructionId))) return reject()
  return {
    privacyDecisionEnabled: value.privacyDecisionEnabled,
    policyHash: hex(value.policyHash, 64),
    knownDestructionIds,
    process: selected,
  }
}
