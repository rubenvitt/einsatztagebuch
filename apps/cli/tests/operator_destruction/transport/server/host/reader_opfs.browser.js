// Test-only orchestration. Every stateful/cryptographic action belongs to the
// existing product Worker; this module transports bytes and checks witnesses.
import { callReaderWorker } from '/src/vault/webauthn-prf.ts'
import { walkDirectoryHandle } from '/src/features/file-mode/DirectoryHandle.ts'
import { createReaderDestructionBridge } from '/src/features/destruction/reader-destruction.ts'

const bytes = value => Uint8Array.from(value)
const unhex = value => Uint8Array.from(value.match(/../g).map(v => parseInt(v, 16)))
const check = (value, label) => { if (!value) throw new Error(label) }
const same = (a, b) => a?.length === b?.length && Array.from(a).every((v, i) => v === b[i])
async function ok(request) {
  const response = await callReaderWorker(request)
  if (!response.ok) throw new Error(`${request.kind}: ${response.code}`)
  return response
}
async function refused(request) {
  const response = await callReaderWorker(request)
  check(!response.ok, `${request.kind} must refuse`)
  return response.code
}
async function directory(input, populate) {
  // Independently retained verification archive outside the own-cache scope.
  const root = await navigator.storage.getDirectory()
  const handle = await root.getDirectoryHandle('native-verification-archive', { create: true })
  if (populate) for (const blob of input.archive) {
    const file = await handle.getFileHandle(blob.name, { create: true })
    const stream = await file.createWritable()
    await stream.write(bytes(blob.bytes)); await stream.close()
  }
  return handle
}
async function source(handle) {
  const response = await ok({ kind: 'file-mode-begin-directory' })
  const id = Number(response.status)
  check(Number.isSafeInteger(id), 'real source handle')
  await walkDirectoryHandle(handle, async (pathHint, data) => {
    await ok({ kind: 'file-mode-push-blob', handle: id, pathHint, bytes: data })
  })
  return id
}
async function unlock(input) {
  const result = await ok({ kind: 'vault-unlock', sealed: bytes(input.sealed),
    credentialId: bytes(input.credential), prfOutput: bytes(input.prf), nowMs: Date.now() })
  const session = Number(result.status)
  check(Number.isSafeInteger(session), 'real unlocked session')
  return session
}
async function absent(input) {
  for (const blob of input.cache) check((await ok({ kind: 'get', key: blob.key })).bytes == null,
    'target ciphertext absent from product OPFS')
}
const now = () => BigInt(Date.now())

window.readerHarness = {
  async ready() { await ok({ kind: 'file-mode-bundle-extension' }); return true },
  async apply(input) {
    const handle = await directory(input, true)
    for (const blob of input.cache) {
      await ok({ kind: 'put', key: blob.key, bytes: bytes(blob.bytes) })
      check(same((await ok({ kind: 'get', key: blob.key })).bytes, blob.bytes), 'populated OPFS ciphertext')
    }
    const session = await unlock(input)
    // The injected selector is the handle returned by the actual Worker
    // unlock. Worker, time, directory traversal and authority remain product.
    const bridge = createReaderDestructionBridge({ session: () => session })
    const apply = async overrides => ({ kind: 'reader-destruction-apply-delivery', session,
      source: await source(handle), authorization: bytes(input.authorization),
      initiatingEvent: bytes(input.initiatingEvent), jobUpload: bytes(input.jobUpload),
      effectiveNowMs: now(), ...overrides })
    const malformed = await refused(await apply({ jobUpload: bytes([0x80]) }))
    const corrupted = bytes(input.jobUpload); corrupted[corrupted.length - 1] ^= 1
    const altered = await refused(await apply({ jobUpload: corrupted }))
    const wrongSession = await unlock({ ...input, sealed: input.wrongSealed })
    const wrongProfile = await refused(await apply({ session: wrongSession }))
    await ok({ kind: 'session-lock', session: wrongSession })
    const emptyDirectory = await (await navigator.storage.getDirectory()).getDirectoryHandle('empty-verification-archive', { create: true })
    const wrongSource = await refused(await apply({ source: await source(emptyDirectory) }))
    for (const blob of input.cache) check(same((await ok({ kind: 'get', key: blob.key })).bytes, blob.bytes),
      'refused exact upload preserves populated OPFS')
    await ok({ kind: 'file-mode-open-directory', session, handle: await source(handle), effectiveNowMs: now() })
    check((await ok({ kind: 'reader-stand-view' })).status !== 'null', 'actual prior view')
    const pending = await source(handle)
    const receipt = await bridge.apply(handle, { authorization: bytes(input.authorization),
      initiatingEvent: bytes(input.initiatingEvent), jobUpload: bytes(input.jobUpload) })
    check(receipt.jobHash === input.jobHash && receipt.replicaId === input.readerId, 'same native job and Reader')
    check(receipt.remainingObjectCount === 0, 'zero remaining target count')
    check(JSON.stringify([...receipt.removedObjectHashes].sort()) === JSON.stringify([...input.targetHashes].sort()), 'measured exact native target hashes')
    check((await ok({ kind: 'reader-stand-view' })).status === 'null', 'previous plaintext view invalidated')
    await refused({ kind: 'file-mode-directory-unavailable', handle: pending })
    await absent(input)
    const attest = async certificate => ({ kind: 'reader-destruction-attest', session,
      source: await source(handle), jobHash: unhex(input.jobHash),
      certificate: unhex(certificate), effectiveNowMs: now() })
    const wrongComponent = await refused(await attest(input.wrongComponent))
    check((await ok({ kind: 'get', key: `destruction-attestation/v1/${input.jobHash}` })).bytes == null,
      'wrong component persists no attestation')
    const wrongJob = await refused({ ...await attest(input.component), jobHash: new Uint8Array(32).fill(0xff) })
    const original = await bridge.attest(handle, input.jobHash, input.component)
    check(original?.length > 0, 'product durable attestation bytes')
    check(same(await bridge.attest(handle, input.jobHash, input.component), original), 'repeat product attest returns identical ETB')
    await ok({ kind: 'session-lock', session })
    const locked = await refused(await attest(input.component))
    return { etb: Array.from(original), receipt, refusals: { malformed, altered, wrongProfile, wrongSource, wrongComponent, wrongJob, locked } }
  },
  async historical(input, expected, reappear = false) {
    const handle = await directory(input, false)
    const session = await unlock(input)
    const bridge = createReaderDestructionBridge({ session: () => session })
    await absent(input)
    const request = async () => ({ kind: 'reader-destruction-attestation', session,
      source: await source(handle), jobHash: unhex(input.jobHash), effectiveNowMs: now() })
    check(same(await bridge.historical(handle, input.jobHash), expected), 'historical ETB identical after profile and Vault reopen')
    if (reappear) {
      const blob = input.cache[0]
      await ok({ kind: 'put', key: blob.key, bytes: bytes(blob.bytes) })
      const historicalRefusal = await refused(await request())
      const currentRefusal = await refused({ kind: 'reader-destruction-attest', session,
        source: await source(handle), jobHash: unhex(input.jobHash), certificate: unhex(input.component), effectiveNowMs: now() })
      return { historicalRefusal, currentRefusal }
    }
    await ok({ kind: 'session-lock', session })
    return true
  },
}
