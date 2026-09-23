/**
 * Die Escrow-Zeremonien des Readers auf der Oberflaechenseite
 * (Escrow-Profil §5–§7, DRK-460): NUR Transport und Anzeige.
 *
 * Ziel, KEM-Gleichheitsgate, Versiegeln, Transport-Schluessel, Bindungs-
 * pruefung und Oeffnen stehen vollstaendig in geteiltem Rust
 * (`crates/ea-reader`, Ausfuhren in `crates/ea-reader-wasm/src/escrow_bridge.rs`).
 * Diese Datei reicht Dateibytes in den Worker und Status-DTOs heraus — Hex,
 * Zahlen, feste Codes und die OEFFENTLICHEN Bytes der Uebergabedateien. Sie
 * trifft keine Entscheidung, rechnet nichts und haelt kein Geheimnis: der
 * Transport-Schluessel liegt ausschliesslich in der Worker-Tabelle und
 * erscheint hier nur als Kennung und Abdruck.
 */
import type { EaOpfsResponse } from '../../bridge/opfs-worker'
import { callReaderWorker, enrollmentReleaseContext } from '../../vault/webauthn-prf'
import type { ReaderWorkerMessage } from '../../vault/webauthn-prf'
import { requireSession } from '../session/reader-session'

/** Der Registrierungsantrag, wie Rust ihn meldet. */
export type RegistrationFileView = {
  readonly fileName: string
  readonly bytesHex: string
  readonly kemFingerprint: string
  readonly signingFingerprint: string
}

/** Das Hinterlegungspaket (Zeremonie A), wie Rust es meldet. */
export type EscrowPackageView = {
  readonly fileName: string
  readonly bytesHex: string
  readonly escrowCoreHash: string
  readonly readerCertificate: string
  readonly recoveryCertificate: string
  readonly kemFingerprint: string
}

/** Der Beginn der Wiederherstellung (Zeremonie B). */
export type TransportBeginView = {
  readonly handle: number
  readonly transportFingerprint: string
  readonly escrowObjectHash: string
  readonly readerCertificate: string
  readonly fileName: string
  readonly bytesHex: string
}

/** Der geoeffnete Umschlag. */
export type TransportOpenView = {
  readonly restored: boolean
  readonly kemFingerprint: string
  readonly authorizationObjectHash: string
}

/** Eine ausgewaehlte Datei — die Form, die `<input type="file">` liefert. */
export type EscrowInputFile = {
  readonly name: string
  readonly size: number
  readonly slice: (start: number, end: number) => { readonly arrayBuffer: () => Promise<ArrayBuffer> }
}

export type ReaderKeyEscrowBridge = {
  readonly registrationRequest: () => Promise<RegistrationFileView>
  readonly sealPackage: (trustFiles: readonly EscrowInputFile[]) => Promise<EscrowPackageView>
  readonly transportBegin: (trustFiles: readonly EscrowInputFile[]) => Promise<TransportBeginView>
  readonly transportOpen: (handle: number, envelope: EscrowInputFile) => Promise<TransportOpenView>
  readonly abort: (handle: number) => Promise<void>
}

// Reine SPEICHERgrenzen der Oberflaeche. Form und Groesse entscheidet Rust.
const TRUST_FILE_READ_LIMIT = 4 * 1024 * 1024
const ENVELOPE_READ_LIMIT = 4 * 1024

/** Liest eine Datei vollstaendig innerhalb einer Speichergrenze der Oberflaeche. */
async function boundedRead(file: EscrowInputFile, limit: number): Promise<Uint8Array> {
  if (!Number.isSafeInteger(file.size) || file.size <= 0 || file.size > limit) {
    throw new Error('Die ausgewählte Datei ist leer oder überschreitet die Lesegrenze.')
  }
  const bytes = new Uint8Array(await file.slice(0, limit + 1).arrayBuffer())
  if (bytes.byteLength !== file.size) {
    throw new Error('Die Datei konnte nicht vollständig gelesen werden.')
  }
  return bytes
}

function raise(response: EaOpfsResponse): Extract<EaOpfsResponse, { ok: true }> {
  if (!response.ok) {
    throw new Error(response.code)
  }
  return response
}

async function status<T>(request: ReaderWorkerMessage): Promise<T> {
  const answer = raise(await callReaderWorker(request))
  if (answer.status === undefined) {
    throw new Error('Der Worker hat auf eine Hinterlegungsnachricht keinen Status geliefert.')
  }
  return JSON.parse(answer.status) as T
}

/** Die gewaehlten Trust-Dateien als Datei-Modus-Quelle im Worker. */
async function directorySource(files: readonly EscrowInputFile[]): Promise<number> {
  const begun = raise(await callReaderWorker({ kind: 'file-mode-begin-directory' }))
  const source = Number(begun.status)
  if (!Number.isSafeInteger(source) || source <= 0) {
    throw new Error('Die Verzeichnisquelle fehlt.')
  }
  try {
    for (const file of files) {
      const bytes = await boundedRead(file, TRUST_FILE_READ_LIMIT)
      raise(await callReaderWorker({ kind: 'file-mode-push-blob', handle: source, pathHint: file.name, bytes }))
    }
  } catch (reason) {
    await callReaderWorker({ kind: 'file-mode-directory-unavailable', handle: source }).catch(
      () => undefined,
    )
    throw reason
  }
  return source
}

export const readerKeyEscrowBridge: ReaderKeyEscrowBridge = {
  registrationRequest: async () =>
    status<RegistrationFileView>({
      kind: 'reader-registration-request',
      session: requireSession(),
      nowMs: Date.now(),
    }),

  sealPackage: async trustFiles => {
    const session = requireSession()
    const source = await directorySource(trustFiles)
    return status<EscrowPackageView>({
      kind: 'reader-key-escrow-seal-package',
      session,
      source,
      subjectId: enrollmentReleaseContext().subjectId,
      nowMs: Date.now(),
    })
  },

  transportBegin: async trustFiles => {
    const context = enrollmentReleaseContext()
    const source = await directorySource(trustFiles)
    return status<TransportBeginView>({
      kind: 'reader-key-escrow-transport-begin',
      pinnedAnchor: context.pinnedAnchor,
      subjectId: context.subjectId,
      source,
      nowMs: Date.now(),
    })
  },

  transportOpen: async (handle, envelope) =>
    status<TransportOpenView>({
      kind: 'reader-key-escrow-transport-open',
      handle,
      envelope: await boundedRead(envelope, ENVELOPE_READ_LIMIT),
    }),

  abort: async handle => {
    await callReaderWorker({ kind: 'reader-key-escrow-transport-abort', handle })
  },
}

/** Lieferung der EXAKTEN oeffentlichen Dateibytes unter dem Namen aus Rust. */
export function downloadEscrowFile(fileName: string, bytesHex: string): void {
  const bytes = new Uint8Array(bytesHex.length / 2)
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(bytesHex.slice(index * 2, index * 2 + 2), 16)
  }
  const url = URL.createObjectURL(new Blob([bytes], { type: 'application/cbor' }))
  const link = document.createElement('a')
  link.href = url
  link.download = fileName
  try {
    link.click()
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 0)
  }
}
