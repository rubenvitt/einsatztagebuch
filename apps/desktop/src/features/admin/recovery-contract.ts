import type { RecoveryAdministrationView, RecoveryMediumRequestView, RecoveryMediumObservationView, RecoveryReportView, RecoveryRunView } from '../../bridge/generated-contracts'
import { ContractViolation } from './contract-check'

function reject(): never { throw new ContractViolation('Der Recovery-Stand liegt außerhalb des Kontrakts.') }
function object(raw: unknown): Record<string, unknown> {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return reject()
  return raw as Record<string, unknown>
}
function hex(raw: unknown, length: number): string {
  if (typeof raw !== 'string' || raw.length !== length || !/^[0-9a-f]+$/.test(raw)) return reject()
  return raw
}
function integer(raw: unknown, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): number {
  if (typeof raw !== 'number' || !Number.isSafeInteger(raw) || raw < minimum || raw > maximum) return reject()
  return raw
}
function code(raw: unknown): string {
  if (typeof raw !== 'string' || !/^[A-Z0-9-]{1,128}$/.test(raw)) return reject()
  return raw
}
function literal(raw: unknown, allowed: readonly string[]): string {
  if (typeof raw !== 'string' || !allowed.includes(raw)) return reject()
  return raw
}
function list(raw: unknown): unknown[] {
  if (!Array.isArray(raw) || raw.length > 1024) return reject()
  return raw
}
function request(raw: unknown): RecoveryMediumRequestView {
  const value = object(raw), total = integer(value.total, 1, 1024)
  return {
    runId: hex(value.runId, 32), requestId: hex(value.requestId, 64), mediumIdHash: hex(value.mediumIdHash, 64),
    index: integer(value.index, 1, total), total,
    roleCode: literal(value.roleCode, ['root', 'organizationAdmin', 'writer', 'reader', 'recoveryRecipient', 'serverReceipt', 'keyApprover', 'historicalGrantAuthority', 'deletionAttest']),
    certificateHash: hex(value.certificateHash, 64), expectedThumbprint: hex(value.expectedThumbprint, 64),
    protectionCode: integer(value.protectionCode, 0, 4),
    testKindCode: literal(value.testKindCode, ['signatureChallenge', 'recoveryDecrypt', 'providerPresence']),
  }
}
function observation(raw: unknown): RecoveryMediumObservationView {
  const value = object(raw), expected = request(value.request), resultCode = integer(value.resultCode, 0, 2)
  const observedThumbprint = value.observedThumbprint === null ? null : hex(value.observedThumbprint, 64)
  const errorCode = value.errorCode === null ? null : code(value.errorCode)
  if (resultCode === 0 ? (observedThumbprint !== expected.expectedThumbprint || errorCode !== null)
    : (errorCode === null || (resultCode === 1 && observedThumbprint !== null))) return reject()
  return { request: expected, resultCode, observedThumbprint, errorCode }
}
function report(raw: unknown): RecoveryReportView | null {
  if (raw === null) return null
  const value = object(raw)
  if (typeof value.completed !== 'boolean' || typeof value.exactPublicReportJson !== 'string'
    || value.exactPublicReportJson.length === 0 || value.exactPublicReportJson.length > 4_194_304) return reject()
  let body: Record<string, unknown>
  try { body = object(JSON.parse(value.exactPublicReportJson)) } catch { return reject() }
  const sourceEnvelopeHash = hex(value.sourceEnvelopeHash, 64)
  if (body.schemaId !== 'ea.recovery-test/v1' || body.result !== (value.completed ? 'complete' : 'failed')
    || body.sourceEnvelopeHash !== sourceEnvelopeHash) return reject()
  hex(body.testId, 32)
  const finishedAtMs = integer(value.finishedAtMs)
  const nextDueAtMs = value.nextDueAtMs === null ? null : integer(value.nextDueAtMs, finishedAtMs)
  if (value.completed !== (nextDueAtMs !== null) || Number.isNaN(new Date(finishedAtMs).getTime())
    || (nextDueAtMs !== null && Number.isNaN(new Date(nextDueAtMs).getTime()))) return reject()
  return { completed: value.completed, exactPublicReportJson: value.exactPublicReportJson,
    envelopeHash: hex(value.envelopeHash, 64), sourceEnvelopeHash, auditId: hex(value.auditId, 32), finishedAtMs, nextDueAtMs }
}
function run(raw: unknown): RecoveryRunView | null {
  if (raw === null) return null
  const value = object(raw), phaseCode = integer(value.phaseCode, 0, 7)
  const pending = value.request === null ? null : request(value.request)
  const observations = list(value.observations).map(observation), verifiedReport = report(value.report)
  const errorCode = value.errorCode === null ? null : code(value.errorCode)
  if ((phaseCode === 1 || phaseCode === 2) !== (pending !== null)
    || ((phaseCode === 3 || phaseCode === 4) !== (verifiedReport !== null))
    || (verifiedReport !== null && verifiedReport.completed !== (phaseCode === 3))
    || ((phaseCode === 5 || phaseCode === 6) !== (errorCode !== null))) return reject()
  const requests = [...observations.map(item => item.request), ...(pending === null ? [] : [pending])]
  if (new Set(requests.map(item => item.requestId)).size !== requests.length
    || new Set(requests.map(item => item.mediumIdHash)).size !== requests.length
    || requests.some((item, index) => item.index !== index + 1 || item.runId !== requests[0]!.runId || item.total !== requests[0]!.total)) return reject()
  if (verifiedReport !== null && requests.length > 0) {
    const body = object(JSON.parse(verifiedReport.exactPublicReportJson))
    if (body.testId !== requests[0]!.runId) return reject()
  }
  return { operationId: hex(value.operationId, 32), phaseCode, request: pending, observations, report: verifiedReport, errorCode }
}
/** Structural validation only; native Rust verifies and persists all results. */
export function validateRecoveryAdministration(raw: unknown): RecoveryAdministrationView {
  const value = object(raw), lastSuccess = report(value.lastSuccess), lastFailure = report(value.lastFailure)
  if (lastSuccess?.completed === false || lastFailure?.completed === true) return reject()
  return { lastSuccess, lastFailure, run: run(value.run) }
}
