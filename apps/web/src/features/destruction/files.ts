// UI memory limits only. Rust still decides exact format and authority.
export const DELIVERY_READ_LIMITS = { authorization: 4 * 1024 * 1024, initiatingEvent: 4 * 1024 * 1024, jobUpload: 64 * 1024 * 1024 } as const
export type DeliveryFile = { readonly size: number; readonly slice: (start: number, end: number) => { readonly arrayBuffer: () => Promise<ArrayBuffer> } }
export function requireNotAborted(signal?: AbortSignal): void { signal?.throwIfAborted() }

export async function boundedRead(file: DeliveryFile, limit: number, signal?: AbortSignal): Promise<Uint8Array> {
  requireNotAborted(signal)
  if (!Number.isSafeInteger(file.size) || file.size <= 0 || file.size > limit) throw new Error('Die ausgewählte Datei ist leer oder überschreitet die Lesegrenze.')
  const bytes = new Uint8Array(await file.slice(0, limit + 1).arrayBuffer())
  requireNotAborted(signal)
  if (bytes.byteLength !== file.size || bytes.byteLength > limit) throw new Error('Die Datei konnte nicht vollständig innerhalb der Lesegrenze gelesen werden.')
  return bytes
}

/** Download the exact public ETB bytes; no re-encoding or plaintext export. */
export function downloadReaderAttestation(bytes: Uint8Array): void {
  const url = URL.createObjectURL(new Blob([bytes.slice()], { type: 'application/octet-stream' }))
  const link = document.createElement('a')
  link.href = url
  link.download = 'reader-loeschbeleg.etb'
  try { link.click() } finally { setTimeout(() => URL.revokeObjectURL(url), 0) }
}
