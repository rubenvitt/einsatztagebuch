import { expect, test, vi } from 'vitest'
import { boundedRead } from './files'

test('rejects oversized files before reading and requests only the bounded slice', async () => {
  const slice = vi.fn(() => ({ arrayBuffer: async () => new Uint8Array([1, 2]).buffer }))
  await expect(boundedRead({ size: 3, slice }, 2)).rejects.toThrow()
  expect(slice).not.toHaveBeenCalled()
  await expect(boundedRead({ size: 2, slice }, 2)).resolves.toEqual(new Uint8Array([1, 2]))
  expect(slice).toHaveBeenCalledWith(0, 3)
})
test('refuses empty, truncated and cancelled reads without forwarding partial originals', async () => {
  const file = { size: 3, slice: () => ({ arrayBuffer: async () => new Uint8Array([1]).buffer }) }
  await expect(boundedRead(file, 4)).rejects.toThrow()
  await expect(boundedRead({ ...file, size: 0 }, 4)).rejects.toThrow()
  const controller = new AbortController()
  const cancelled = { size: 1, slice: () => ({ arrayBuffer: async () => { controller.abort(); return new Uint8Array([1]).buffer } }) }
  await expect(boundedRead(cancelled, 4, controller.signal)).rejects.toHaveProperty('name', 'AbortError')
})
