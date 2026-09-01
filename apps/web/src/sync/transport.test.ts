import { describe, expect, it } from 'vitest'

import { type ReaderSyncRequestV1, sendReaderSyncRequest } from './transport'

/**
 * Ein Request, wie `readerSyncNextRequest` ihn herausgibt.
 *
 * Die zwei Signaturkopfzeilen stehen hier als WERTE, weil sie in Rust
 * entstehen: `ea_sync_protocol::RequestSigner` bildet sie, und der Zeuge
 * `crates/ea-reader/tests/sync_attacks.rs::the_pull_request_is_signed_with_the_vault_ed25519_key`
 * misst ihre Form dort. Hier wird ausschliesslich gemessen, dass der Transport
 * sie UNVERAENDERT weiterreicht.
 */
function signedRequest(): ReaderSyncRequestV1 {
  return {
    method: 'GET',
    authority: 'sync.einsatzarchiv.invalid',
    target: '/v1/chains/13131313131313131313131313131313/entries?afterSequence=0&afterEntryHash=00',
    headers: [
      ['ea-request-id', 'AAAAAAAAAAAAAAAAAAAAAA'],
      ['signature-input', 'ea1=("@method" "@authority");created=1;keyid="abc";alg="ed25519"'],
      ['signature', 'ea1=:AAAA:'],
    ],
    bodyHex: '',
  }
}

/** Ein `fetch`-Doppel, das den Aufruf AUFZEICHNET. */
function recordingFetch(status: number, bytes: Uint8Array<ArrayBuffer>) {
  const calls: { url: string; init: RequestInit }[] = []
  const fetchImpl = async (url: string, init: RequestInit) => {
    calls.push({ url, init })
    return new Response(bytes, { status })
  }
  return { calls, fetchImpl }
}

describe('sendReaderSyncRequest', () => {
  it('sends exactly the headers the signed request carries and adds none', async () => {
    const request = signedRequest()
    const { calls, fetchImpl } = recordingFetch(200, new Uint8Array([1, 2, 3]))

    await sendReaderSyncRequest(request, fetchImpl)

    expect(calls).toHaveLength(1)
    // Die GESENDETE Menge ist die des Requests — nach Namen und Wert und ohne
    // eine einzige zusaetzliche Zeile. Ein `Content-Type`, das der Transport
    // von sich aus setzte, faellt hier auf: er stuende nicht in der
    // Signaturbasis, und der Server wiese den Request ab.
    expect(calls[0]?.init.headers).toEqual([
      ['ea-request-id', 'AAAAAAAAAAAAAAAAAAAAAA'],
      ['signature-input', 'ea1=("@method" "@authority");created=1;keyid="abc";alg="ed25519"'],
      ['signature', 'ea1=:AAAA:'],
    ])
    expect(calls[0]?.init.method).toBe('GET')
  })

  it('addresses exactly the authority and target the signature bound', async () => {
    const request = signedRequest()
    const { calls, fetchImpl } = recordingFetch(200, new Uint8Array())

    await sendReaderSyncRequest(request, fetchImpl)

    expect(calls[0]?.url).toBe(`https://${request.authority}${request.target}`)
  })

  it('returns the response bytes unchanged', async () => {
    const payload = new Uint8Array([0x82, 0x01, 0xff, 0x00])
    const { fetchImpl } = recordingFetch(200, payload)

    const bytes = await sendReaderSyncRequest(signedRequest(), fetchImpl)

    expect([...bytes]).toEqual([...payload])
  })

  it('reads no status as a trust statement and hands a 500 body on unchanged', async () => {
    // Der Status ist KEINE Aussage ueber Vertrauen, und dieser Zeuge haelt
    // genau das fest: der Transport gibt die Bytes heraus, ohne sie zu
    // beurteilen. Ueber ihre Bedeutung entscheidet `readerSyncAcceptBatch` —
    // eine Fehlerseite ist dort `EA-READER-PROTOCOL` und bewegt keinen Cursor.
    const payload = new Uint8Array([0x3c, 0x21, 0x2d, 0x2d])
    const { fetchImpl } = recordingFetch(500, payload)

    const bytes = await sendReaderSyncRequest(signedRequest(), fetchImpl)

    expect([...bytes]).toEqual([...payload])
  })

  it('sends no body for a request that carries none', async () => {
    const { calls, fetchImpl } = recordingFetch(200, new Uint8Array())

    await sendReaderSyncRequest(signedRequest(), fetchImpl)

    expect(calls[0]?.init.body).toBeUndefined()
  })
})
