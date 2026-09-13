import { afterEach, expect, test, vi } from 'vitest'
import type { EaOpfsRequest, EaOpfsResponse } from '../bridge/opfs-worker'

afterEach(() => { vi.unstubAllGlobals(); vi.resetModules() })

test('both Apply routes invalidate visible plaintext before sending unchanged bytes through the existing single worker', async () => {
  vi.resetModules()
  let visiblePlaintext = true
  let created = 0
  const sent: EaOpfsRequest[] = []
  class TransportWorker {
    private receive: ((event: MessageEvent<EaOpfsResponse>) => void) | undefined
    constructor() { created += 1 }
    addEventListener(kind: string, callback: (event: MessageEvent<EaOpfsResponse>) => void) {
      if (kind === 'message') this.receive = callback
    }
    postMessage(request: EaOpfsRequest) {
      expect(visiblePlaintext).toBe(false)
      sent.push(request)
      this.receive?.({ data: { id: request.id, ok: false, code: 'EA-READER-DESTRUCTION-UNVERIFIED' } } as MessageEvent<EaOpfsResponse>)
    }
  }
  vi.stubGlobal('Worker', TransportWorker)
  const { onReaderViewsInvalidated } = await import('../bridge/reader-invalidation')
  const { callReaderWorker } = await import('./webauthn-prf')
  const unsubscribe = onReaderViewsInvalidated(() => { visiblePlaintext = false })
  const authorization = new Uint8Array([0x01, 0xff])
  const initiatingEvent = new Uint8Array([0x02, 0xfe])
  const jobUpload = new Uint8Array([0x03, 0xfd])
  try {
    const legacy = await callReaderWorker({ kind: 'reader-destruction-apply', session: 41, source: 73, authorization, initiatingEvent, preflightCore: jobUpload, preflightSignature: jobUpload, inventory: jobUpload, preflightCertificate: jobUpload, effectiveNowMs: 800n })
    expect(legacy.ok).toBe(false)
    visiblePlaintext = true
    const result = await callReaderWorker({ kind: 'reader-destruction-apply-delivery', session: 41, source: 74, authorization, initiatingEvent, jobUpload, effectiveNowMs: 800n })
    expect(result).toEqual({ id: 2, ok: false, code: 'EA-READER-DESTRUCTION-UNVERIFIED' })
    expect(created).toBe(1)
    expect(sent).toHaveLength(2)
    const delivered = sent[1]
    expect(delivered?.kind).toBe('reader-destruction-apply-delivery')
    if (delivered?.kind !== 'reader-destruction-apply-delivery') throw new Error('delivery route missing')
    expect(delivered.authorization).toBe(authorization)
    expect(delivered.initiatingEvent).toBe(initiatingEvent)
    expect(delivered.jobUpload).toBe(jobUpload)
    expect(delivered.session).toBe(41)
    expect(delivered.source).toBe(74)
  } finally { unsubscribe() }
})
