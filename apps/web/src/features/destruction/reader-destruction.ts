import type { EaOpfsResponse } from '../../bridge/opfs-worker'
import { bytesFromHex, callReaderWorker } from '../../vault/webauthn-prf'
import type { ReaderWorkerMessage } from '../../vault/webauthn-prf'
import { walkDirectoryHandle } from '../file-mode/DirectoryHandle'
import type { FileModeDirectoryHandleV1, FileModeWorkerPort } from '../file-mode/DirectoryHandle'
import { requireSession } from '../session/reader-session'
import { requireNotAborted } from './files'

/** Display data, never a signing capability or completion claim. */
export type ReaderRemovalReceipt = {
  readonly jobHash: string
  readonly replicaId: string
  readonly removedObjectHashes: readonly string[]
  readonly remainingObjectCount: number
}
export type ReaderDeliveryOriginals = { readonly authorization: Uint8Array; readonly initiatingEvent: Uint8Array; readonly jobUpload: Uint8Array }
export type ReaderDestructionBridge = {
  readonly apply: (handle: FileModeDirectoryHandleV1, originals: ReaderDeliveryOriginals, signal?: AbortSignal) => Promise<ReaderRemovalReceipt>
  readonly attest: (handle: FileModeDirectoryHandleV1, jobHash: string, certificate: string, signal?: AbortSignal) => Promise<Uint8Array>
  readonly historical: (handle: FileModeDirectoryHandleV1, jobHash: string, signal?: AbortSignal) => Promise<Uint8Array>
}
function raise(response: EaOpfsResponse): Extract<EaOpfsResponse, { ok: true }> {
  if (!response.ok) throw new Error(response.code)
  return response
}
function selector(hash: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/i.test(hash)) throw new Error('Der ausgewählte Hash muss aus 64 Hexzeichen bestehen.')
  return bytesFromHex(hash)
}
function receipt(status: string | undefined): ReaderRemovalReceipt {
  if (status === undefined) throw new Error('Die lokale Messquittung fehlt.')
  const value: unknown = JSON.parse(status)
  if (value === null || typeof value !== 'object') throw new Error('Die lokale Messquittung ist unvollständig.')
  const view = value as Partial<ReaderRemovalReceipt>
  if (typeof view.jobHash !== 'string' || typeof view.replicaId !== 'string' || !Array.isArray(view.removedObjectHashes) || !view.removedObjectHashes.every(hash => typeof hash === 'string') || !Number.isSafeInteger(view.remainingObjectCount) || (view.remainingObjectCount ?? -1) < 0) throw new Error('Die lokale Messquittung ist unvollständig.')
  selector(view.jobHash)
  return view as ReaderRemovalReceipt
}
function exactBytes(response: Extract<EaOpfsResponse, { ok: true }>): Uint8Array {
  if (!(response.bytes instanceof Uint8Array) || response.bytes.length === 0) throw new Error('Die exakten Belegbytes fehlen.')
  return response.bytes
}

/** The default dependencies retain the one actual Worker and existing session. */
export function createReaderDestructionBridge({ call = callReaderWorker, session = requireSession, now = Date.now }: { readonly call?: FileModeWorkerPort; readonly session?: () => number; readonly now?: () => number } = {}): ReaderDestructionBridge {
  async function withSource(handle: FileModeDirectoryHandleV1, consume: (session: number, source: number) => ReaderWorkerMessage, signal?: AbortSignal): Promise<Extract<EaOpfsResponse, { ok: true }>> {
    requireNotAborted(signal)
    const current = session() // A selector only; Rust enforces the actual session.
    const begun = raise(await call({ kind: 'file-mode-begin-directory' }))
    const source = Number(begun.status)
    if (begun.status === undefined || !Number.isSafeInteger(source) || source <= 0) throw new Error('Die Verzeichnisquelle fehlt.')
    const unavailable = (): Promise<EaOpfsResponse> => call({ kind: 'file-mode-directory-unavailable', handle: source })
    const permission = async (): Promise<boolean> => handle.queryPermission === undefined || (await handle.queryPermission({ mode: 'read' })) === 'granted'
    let result: Extract<EaOpfsResponse, { ok: true }>
    try {
      requireNotAborted(signal)
      if (await permission()) {
        requireNotAborted(signal)
        await walkDirectoryHandle(handle, async (pathHint, bytes) => {
          requireNotAborted(signal)
          raise(await call({ kind: 'file-mode-push-blob', handle: source, pathHint, bytes }))
          requireNotAborted(signal)
        })
      } else { raise(await unavailable()) }
      requireNotAborted(signal)
      if (!(await permission())) raise(await unavailable())
      requireNotAborted(signal)
      result = raise(await call(consume(current, source)))
      requireNotAborted(signal)
    } finally {
      // Apply can reject malformed transport before taking its source. Mark it
      // unavailable before consuming it, so cleanup cannot open a valid stand.
      // Already-consumed sources refuse unavailable and need no second open.
      const marked = await unavailable().catch(() => undefined)
      if (marked?.ok) await call({ kind: 'file-mode-open-directory', session: current, handle: source, effectiveNowMs: BigInt(now()) }).catch(() => undefined)
    }
    requireNotAborted(signal)
    return result
  }
  return {
    apply: async (handle, originals, signal) => receipt((await withSource(handle, (session, source) => ({ kind: 'reader-destruction-apply-delivery', session, source, ...originals, effectiveNowMs: BigInt(now()) }), signal)).status),
    attest: async (handle, job, certificate, signal) => {
      const jobHash = selector(job)
      const component = selector(certificate)
      return exactBytes(await withSource(handle, (session, source) => ({ kind: 'reader-destruction-attest', session, source, jobHash, certificate: component, effectiveNowMs: BigInt(now()) }), signal))
    },
    historical: async (handle, job, signal) => {
      const jobHash = selector(job)
      return exactBytes(await withSource(handle, (session, source) => ({ kind: 'reader-destruction-attestation', session, source, jobHash, effectiveNowMs: BigInt(now()) }), signal))
    },
  }
}
export const readerDestructionBridge = createReaderDestructionBridge()
