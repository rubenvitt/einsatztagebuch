import { invoke } from '@tauri-apps/api/core'

import { ContractViolation } from './contract-check'
import { validateDestructionProcess } from './destruction-contract'
import type { DestructionEvidenceBridge } from './DestructionEvidence'
import { validatePendingResume, validateSyncState } from '../writer/WriterPage'
import { STALE_DECISION_VALUES } from '../../bridge/generated-contracts'
import type { DestructionEvidenceReviewView, DiscardStateView, FinalizationPreviewView, FinalizeOutcomeView } from '../../bridge/generated-contracts'

function reject(): never { throw new ContractViolation('Die native Nachweisantwort passt nicht zum angeforderten Writer-Vorgang.') }
function object(raw: unknown): Record<string, unknown> {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return reject()
  return raw as Record<string, unknown>
}
function hex(raw: unknown, length: number): string {
  if (typeof raw !== 'string' || raw.length !== length || !/^[0-9a-f]+$/.test(raw)) return reject()
  return raw
}
function integer(raw: unknown): number {
  if (typeof raw !== 'number' || !Number.isSafeInteger(raw) || raw < 0) return reject()
  return raw
}
function bool(raw: unknown): boolean {
  if (typeof raw !== 'boolean') return reject()
  return raw
}
function preview(raw: unknown): FinalizationPreviewView {
  const value = object(raw)
  const effectiveNow = integer(value.effectiveNow)
  const staleDecision = STALE_DECISION_VALUES.find((item) => item === value.staleDecision)
  if (staleDecision === undefined || Number.isNaN(new Date(effectiveNow).getTime())) return reject()
  return {
    proposedSequence: integer(value.proposedSequence), bindsPredecessor: bool(value.bindsPredecessor),
    effectiveNow, trustAgeMs: integer(value.trustAgeMs), readerTrustRefreshMs: integer(value.readerTrustRefreshMs),
    trustRefreshOverdue: bool(value.trustRefreshOverdue), staleDecision,
  }
}
function review(raw: unknown, id: string, hash: string): DestructionEvidenceReviewView {
  const value = object(raw)
  const process = validateDestructionProcess(value.process)
  const writerDeviceId = hex(value.writerDeviceId, 32)
  if (process === null || process.destructionId !== id || process.preflight?.jobHash !== hash
    || writerDeviceId !== process.custodianDeviceId) return reject()
  return { writerDeviceId, process, preview: preview(value.preview) }
}
function outcome(raw: unknown): FinalizeOutcomeView {
  const value = object(raw)
  return { sequence: integer(value.sequence), entryHash: hex(value.entryHash, 64), objectHash: hex(value.objectHash, 64), sync: validateSyncState(value.sync) }
}
function discard(raw: unknown): DiscardStateView {
  const value = object(raw)
  if (typeof value.phaseCode !== 'string' || !/^[A-Za-z][A-Za-z0-9-]{0,127}$/.test(value.phaseCode)) return reject()
  return { phaseCode: value.phaseCode, complete: bool(value.complete) }
}

/** Connecting never opens a dialog or reads, finalizes, recovers or discards a draft. */
export function connectDestructionEvidenceBridge(
  call: (command: string, args: Record<string, unknown>) => Promise<unknown> = invoke,
): DestructionEvidenceBridge {
  const args = (destructionId: string, expectedPreflightHash: string) => ({ destructionId, expectedPreflightHash })
  return {
    preview: async (id, hash) => review(await call('destruction_evidence_preview', args(id, hash)), id, hash),
    finalize: async (id, hash, confirmed) => outcome(await call('destruction_evidence_finalize', { ...args(id, hash), confirmed: preview(confirmed) })),
    recover: async (id, hash) => validatePendingResume(await call('destruction_evidence_recover', args(id, hash))),
    discard: async (id, hash) => discard(await call('destruction_evidence_discard', args(id, hash))),
  }
}
