import { act, render, screen, waitFor } from '@testing-library/react'
import { expect, test, vi } from 'vitest'
import { userEvent } from '../../test-setup'
import type { ReaderSessionView } from '../../bridge/generated-contracts'
import type { FileModeDirectoryHandleV1 } from '../file-mode/DirectoryHandle'
import { ReaderDestructionPage } from './ReaderDestructionPage'
import type { ReaderDestructionBridge } from './reader-destruction'

const job = 'ab'.repeat(32)
const component = 'cd'.repeat(32)
const receipt = { jobHash: job, replicaId: 'ef'.repeat(16), removedObjectHashes: ['aa'.repeat(32)], remainingObjectCount: 0 }
const handle: FileModeDirectoryHandleV1 = { kind: 'directory', async *entries() { yield* [] } }
function fixture(locked = false) {
  const bytes = new Uint8Array([7, 8, 9])
  const bridge: ReaderDestructionBridge = { apply: vi.fn(async () => receipt), attest: vi.fn(async () => bytes), historical: vi.fn(async () => bytes) }
  const session = { unlock: vi.fn(async () => { locked = false }), stateAt: vi.fn(async () => ({ locked } as ReaderSessionView)) }
  const host = { showDirectoryPicker: vi.fn(async () => handle) }
  const download = vi.fn()
  return { bridge, session, host, download, bytes }
}
async function chooseDirectory(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: 'Archivordner auswählen' }))
  await screen.findByText('Archivordner ausgewählt')
}
async function files(user: ReturnType<typeof userEvent.setup>) {
  for (const [label, marker] of [['Autorisierung', 1], ['Startnachweis', 2], ['Jobdatei', 3]] as const) {
    const file = new File([new Uint8Array([marker])], 'umbenannt.beliebig')
    Object.defineProperty(file, 'slice', { value: () => ({ arrayBuffer: async () => new Uint8Array([marker]).buffer }) })
    await user.upload(screen.getByLabelText(label), file)
  }
}
test('requires an explicit unlock and three separate originals, with no automatic action', async () => {
  const f = fixture(true)
  render(<ReaderDestructionPage {...f} />)
  await screen.findByText('Tresorsitzung gesperrt')
  expect(f.session.unlock).not.toHaveBeenCalled()
  expect(f.bridge.apply).not.toHaveBeenCalled()
  expect(screen.getByLabelText('Autorisierung')).toHaveAttribute('type', 'file')
  expect(screen.getByLabelText('Startnachweis')).toHaveAttribute('type', 'file')
  expect(screen.getByLabelText('Jobdatei')).toHaveAttribute('type', 'file')
  expect(screen.getByRole('button', { name: 'Eigenen Cache löschen' })).toBeDisabled()
  await userEvent.setup().click(screen.getByRole('button', { name: 'Tresor entsperren' }))
  await waitFor(() => expect(f.session.unlock).toHaveBeenCalledTimes(1))
  expect(f.bridge.apply).not.toHaveBeenCalled()
})
test('applies exact three files and exports only on a separate explicit component action', async () => {
  const f = fixture()
  const user = userEvent.setup()
  render(<ReaderDestructionPage {...f} />)
  await chooseDirectory(user)
  await files(user)
  await user.click(screen.getByRole('button', { name: 'Eigenen Cache löschen' }))
  await screen.findByText('Lokale Cacheentfernung gemessen')
  expect(f.bridge.apply).toHaveBeenCalledWith(handle, { authorization: new Uint8Array([1]), initiatingEvent: new Uint8Array([2]), jobUpload: new Uint8Array([3]) }, expect.any(AbortSignal))
  expect(f.bridge.attest).not.toHaveBeenCalled()
  expect(f.download).not.toHaveBeenCalled()
  await user.type(screen.getByLabelText('Komponentenzertifikat für den aktuellen Beleg'), component)
  await user.click(screen.getByRole('button', { name: 'Aktuellen Löschbeleg herunterladen' }))
  await waitFor(() => expect(f.download).toHaveBeenCalledWith(f.bytes))
  expect(f.bridge.attest).toHaveBeenCalledWith(handle, job, component, expect.any(AbortSignal))
  expect(screen.queryByText(/completeManagedScope/i)).not.toBeInTheDocument()
})
test('a different original invalidates the previous receipt and current-export selection', async () => {
  const f = fixture()
  const user = userEvent.setup()
  render(<ReaderDestructionPage {...f} />)
  await chooseDirectory(user); await files(user)
  await user.click(screen.getByRole('button', { name: 'Eigenen Cache löschen' }))
  await screen.findByText('Lokale Cacheentfernung gemessen')
  await user.upload(screen.getByLabelText('Autorisierung'), new File(['other'], 'other.etb'))
  expect(screen.queryByText('Lokale Cacheentfernung gemessen')).not.toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Aktuellen Löschbeleg herunterladen' })).toBeDisabled()
})
test('historical export after reopen uses its own job selector and never applies or signs', async () => {
  const f = fixture()
  const user = userEvent.setup()
  render(<ReaderDestructionPage {...f} />)
  await chooseDirectory(user)
  await user.type(screen.getByLabelText('Jobhash des gespeicherten Belegs'), job)
  await user.click(screen.getByRole('button', { name: 'Historischen Löschbeleg herunterladen' }))
  await waitFor(() => expect(f.download).toHaveBeenCalledWith(f.bytes))
  expect(f.bridge.historical).toHaveBeenCalledWith(handle, job, expect.any(AbortSignal))
  expect(f.bridge.apply).not.toHaveBeenCalled()
  expect(f.bridge.attest).not.toHaveBeenCalled()
})
test('rejection displays its stable code and cannot produce an attestation or download', async () => {
  const f = fixture()
  vi.mocked(f.bridge.apply).mockRejectedValue(new Error('EA-READER-DESTRUCTION-UNVERIFIED'))
  const user = userEvent.setup()
  render(<ReaderDestructionPage {...f} />)
  await chooseDirectory(user); await files(user)
  await user.click(screen.getByRole('button', { name: 'Eigenen Cache löschen' }))
  await screen.findByText('EA-READER-DESTRUCTION-UNVERIFIED')
  expect(screen.queryByText('Lokale Cacheentfernung gemessen')).not.toBeInTheDocument()
  expect(f.download).not.toHaveBeenCalled()
  expect(f.bridge.attest).not.toHaveBeenCalled()
})
test('unmount aborts an outstanding historical export and discards late bytes', async () => {
  const f = fixture()
  let resolve!: (bytes: Uint8Array) => void
  vi.mocked(f.bridge.historical).mockReturnValue(new Promise(done => { resolve = done }))
  const user = userEvent.setup()
  const page = render(<ReaderDestructionPage {...f} />)
  await chooseDirectory(user)
  await user.type(screen.getByLabelText('Jobhash des gespeicherten Belegs'), job)
  await user.click(screen.getByRole('button', { name: 'Historischen Löschbeleg herunterladen' }))
  await waitFor(() => expect(f.bridge.historical).toHaveBeenCalledTimes(1))
  page.unmount()
  await act(async () => { resolve(f.bytes) })
  expect(f.download).not.toHaveBeenCalled()
})
test('an unavailable directory picker exposes the missing capability and permits no cache action', () => {
  const f = fixture()
  render(<ReaderDestructionPage {...f} host={{}} />)
  expect(screen.getByText(/keine Archivordnerauswahl/)).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Archivordner auswählen' })).not.toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Eigenen Cache löschen' })).toBeDisabled()
})
test('a stale initial session read cannot overwrite the explicit unlock result', async () => {
  const f = fixture()
  let resolve!: (state: ReaderSessionView) => void
  vi.mocked(f.session.stateAt).mockImplementationOnce(() => new Promise(done => { resolve = done }))
  render(<ReaderDestructionPage {...f} />)
  await userEvent.setup().click(screen.getByRole('button', { name: 'Tresor entsperren' }))
  await screen.findByText('Tresorsitzung entsperrt — zuletzt geprüft')
  await act(async () => { resolve({ locked: true } as ReaderSessionView) })
  expect(screen.queryByText('Tresorsitzung gesperrt')).not.toBeInTheDocument()
})
test.each(['bridge', 'host', 'download'] as const)('replacing %s discards a pending current attestation and its receipt', async dependency => {
  const f = fixture()
  const next = fixture()
  let resolve!: (bytes: Uint8Array) => void
  vi.mocked(f.bridge.attest).mockReturnValue(new Promise(done => { resolve = done }))
  const user = userEvent.setup()
  const page = render(<ReaderDestructionPage {...f} />)
  await chooseDirectory(user); await files(user)
  await user.click(screen.getByRole('button', { name: 'Eigenen Cache löschen' }))
  await screen.findByText('Lokale Cacheentfernung gemessen')
  await user.type(screen.getByLabelText('Komponentenzertifikat für den aktuellen Beleg'), component)
  await user.click(screen.getByRole('button', { name: 'Aktuellen Löschbeleg herunterladen' }))
  await waitFor(() => expect(f.bridge.attest).toHaveBeenCalledTimes(1))
  page.rerender(<ReaderDestructionPage {...f} {...{ [dependency]: next[dependency] }} />)
  await act(async () => { resolve(f.bytes) })
  expect(f.download).not.toHaveBeenCalled()
  expect(next.download).not.toHaveBeenCalled()
  expect(screen.queryByText('Lokale Cacheentfernung gemessen')).not.toBeInTheDocument()
})
test('an old export finalizer cannot clear a newer action after bridge replacement', async () => {
  const f = fixture()
  const next = fixture()
  let resolveOld!: (bytes: Uint8Array) => void
  let resolveNew!: (bytes: Uint8Array) => void
  vi.mocked(f.bridge.historical).mockReturnValue(new Promise(done => { resolveOld = done }))
  vi.mocked(next.bridge.historical).mockReturnValue(new Promise(done => { resolveNew = done }))
  const user = userEvent.setup()
  const page = render(<ReaderDestructionPage {...f} />)
  await chooseDirectory(user)
  await user.type(screen.getByLabelText('Jobhash des gespeicherten Belegs'), job)
  await user.click(screen.getByRole('button', { name: 'Historischen Löschbeleg herunterladen' }))
  await waitFor(() => expect(f.bridge.historical).toHaveBeenCalledTimes(1))
  page.rerender(<ReaderDestructionPage {...f} bridge={next.bridge} />)
  await chooseDirectory(user)
  await user.click(screen.getByRole('button', { name: 'Historischen Löschbeleg herunterladen' }))
  await waitFor(() => expect(next.bridge.historical).toHaveBeenCalledTimes(1))
  await act(async () => { resolveOld(f.bytes) })
  expect(screen.getByText('Aktion läuft …')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Tresor entsperren' })).toBeDisabled()
  expect(f.download).not.toHaveBeenCalled()
  await act(async () => { resolveNew(next.bytes) })
  expect(f.download).toHaveBeenCalledExactlyOnceWith(next.bytes)
})
