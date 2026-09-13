import { expect, test, vi } from 'vitest'
import type { EaOpfsResponse } from '../../bridge/opfs-worker'
import type { ReaderWorkerMessage } from '../../vault/webauthn-prf'
import type { FileModeDirectoryHandleV1 } from '../file-mode/DirectoryHandle'
import { createReaderDestructionBridge, readerDestructionBridge } from './reader-destruction'

const job = 'ab'.repeat(32)
const certificate = 'cd'.repeat(32)
const originals = { authorization: new Uint8Array([1]), initiatingEvent: new Uint8Array([2]), jobUpload: new Uint8Array([3]) }
const receipt = { jobHash: job, replicaId: 'ef'.repeat(16), removedObjectHashes: ['aa'.repeat(32)], remainingObjectCount: 0 }
function directory(permission = vi.fn(async () => 'granted')): FileModeDirectoryHandleV1 {
  return { kind: 'directory', queryPermission: permission, async *entries() {
    yield ['original.etb', { kind: 'file', getFile: async () => ({ arrayBuffer: async () => new Uint8Array([9, 8]).buffer }) }] as const
  } }
}
function harness(effect?: (request: ReaderWorkerMessage) => Promise<EaOpfsResponse>, cleanup?: () => void) {
  const calls: ReaderWorkerMessage[] = []
  const sources = new Map<number, boolean>()
  let next = 0
  const call = async (request: ReaderWorkerMessage): Promise<EaOpfsResponse> => {
    calls.push(request)
    if (request.kind === 'file-mode-begin-directory') { sources.set(++next, true); return { id: 0, ok: true, status: String(next) } }
    if (request.kind === 'file-mode-directory-unavailable') {
      cleanup?.()
      if (!sources.has(request.handle)) return { id: 0, ok: false, code: 'EA-READER-FILE-MODE-BRIDGE-ARGUMENT' }
      sources.set(request.handle, false); return { id: 0, ok: true }
    }
    if (request.kind === 'file-mode-open-directory') {
      expect(sources.get(request.handle)).toBe(false)
      sources.delete(request.handle)
      return { id: 0, ok: false, code: 'EA-ARCHIVE-UNAVAILABLE' }
    }
    if (request.kind === 'file-mode-push-blob') return { id: 0, ok: true }
    if ('source' in request) {
      const available = sources.get(request.source)
      const response = effect === undefined
        ? { id: 0, ok: true as const, status: JSON.stringify(receipt), bytes: new Uint8Array([7, 6, 5]) }
        : await effect(request)
      // A malformed delivery can fail before Rust takes the registered source.
      if (!(response.ok === false && response.code === 'EARLY-DECODER-REFUSAL')) sources.delete(request.source)
      if (!available) return { id: 0, ok: false, code: 'EA-ARCHIVE-UNAVAILABLE' }
      return response
    }
    throw new Error('unexpected request')
  }
  return { bridge: createReaderDestructionBridge({ call, session: () => 47, now: () => 800 }), calls, sources }
}

test('all actions register a new traversed source and keep exact bytes and explicit selectors', async () => {
  const { bridge, calls, sources } = harness()
  const handle = directory()
  expect(await bridge.apply(handle, originals)).toEqual(receipt)
  expect(await bridge.attest(handle, job, certificate)).toEqual(new Uint8Array([7, 6, 5]))
  expect(await bridge.historical(handle, job)).toEqual(new Uint8Array([7, 6, 5]))
  const apply = calls.find(r => r.kind === 'reader-destruction-apply-delivery')
  expect(apply).toMatchObject({ source: 1, session: 47, ...originals, effectiveNowMs: 800n })
  if (apply?.kind !== 'reader-destruction-apply-delivery') throw new Error('missing apply')
  expect(apply.authorization).toBe(originals.authorization)
  expect(apply.jobUpload).toBe(originals.jobUpload)
  expect(calls.find(r => r.kind === 'reader-destruction-attest')).toMatchObject({ source: 2, jobHash: new Uint8Array(32).fill(0xab), certificate: new Uint8Array(32).fill(0xcd) })
  expect(calls.find(r => r.kind === 'reader-destruction-attestation')).toMatchObject({ source: 3 })
  expect(calls.filter(r => r.kind === 'file-mode-push-blob')).toHaveLength(3)
  expect(calls.filter(r => r.kind === 'file-mode-open-directory')).toHaveLength(0)
  expect(sources.size).toBe(0)
})
test('early decoder refusal cleans up unavailable source without opening a valid stand', async () => {
  const { bridge, calls, sources } = harness(async () => ({ id: 0, ok: false, code: 'EARLY-DECODER-REFUSAL' }))
  await expect(bridge.apply(directory(), originals)).rejects.toThrow('EARLY-DECODER-REFUSAL')
  expect(calls.slice(-2).map(r => r.kind)).toEqual(['file-mode-directory-unavailable', 'file-mode-open-directory'])
  expect(sources.size).toBe(0)
})
test('revoked permission is checked again after traversal and never yields a local result', async () => {
  const permission = vi.fn().mockResolvedValueOnce('granted').mockResolvedValue('denied')
  const { bridge, sources } = harness()
  await expect(bridge.apply(directory(permission), originals)).rejects.toThrow('EA-ARCHIVE-UNAVAILABLE')
  expect(permission).toHaveBeenCalledTimes(2)
  expect(sources.size).toBe(0)
})
test('aborted traversal cleans up and dispatches no cache action', async () => {
  const controller = new AbortController()
  const { bridge, calls, sources } = harness()
  const handle: FileModeDirectoryHandleV1 = { kind: 'directory', async *entries() { controller.abort(); yield* [] } }
  await expect(bridge.apply(handle, originals, controller.signal)).rejects.toHaveProperty('name', 'AbortError')
  expect(calls.some(r => r.kind === 'reader-destruction-apply-delivery')).toBe(false)
  expect(sources.size).toBe(0)
})
test('abort during a consumer rejects its late result and retains cleanup', async () => {
  const controller = new AbortController()
  const { bridge, sources } = harness(async () => { controller.abort(); return { id: 0, ok: true, bytes: new Uint8Array([1]) } })
  await expect(bridge.historical(directory(), job, controller.signal)).rejects.toHaveProperty('name', 'AbortError')
  expect(sources.size).toBe(0)
})
test('abort during final source cleanup prevents late public-byte release', async () => {
  const controller = new AbortController()
  const { bridge } = harness(undefined, () => controller.abort())
  await expect(bridge.historical(directory(), job, controller.signal)).rejects.toHaveProperty('name', 'AbortError')
})
test('hash inputs are bounded selectors and never coerced to a different value', async () => {
  const { bridge, calls } = harness()
  await expect(bridge.attest(directory(), job, 'not-a-hash')).rejects.toThrow()
  await expect(bridge.historical(directory(), '12')).rejects.toThrow()
  expect(calls).toHaveLength(0)
})
test('production bridge without an existing session never implicitly unlocks a Vault', async () => {
  await expect(readerDestructionBridge.apply(directory(), originals)).rejects.toThrow('EA-READER-SESSION-UNKNOWN')
})
