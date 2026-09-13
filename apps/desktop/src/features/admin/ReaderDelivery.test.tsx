import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ReaderDelivery } from './ReaderDelivery'
import { connectReaderDeliveryBridge } from './reader-delivery-bridge'
import type { DestructionProcessView, DestructionReaderDeliveryView } from '../../bridge/generated-contracts'

const ID = '11'.repeat(16)
const HASH = '22'.repeat(32)
const READER = '33'.repeat(16)
function process(): DestructionProcessView {
  return {
    destructionId: ID, authorizationObjectHash: HASH, state: 'inProgress', scopeCode: 0, legalReasonCode: 0,
    controllerDeviceId: '44'.repeat(16), custodianDeviceId: '55'.repeat(16),
    approverCertificateHashes: ['66'.repeat(32), '77'.repeat(32)],
    targets: [{ entryHash: HASH, chainSequence: 1, stubObjectHash: null }],
    preflight: { jobHash: HASH, exactCanonicalReportJson: '{}', knownReplicaCount: 2 },
    replicas: [
      { deviceId: READER, kindCode: 1, attestationHash: null, resultCode: null, backupExpiryAt: null },
      { deviceId: '55'.repeat(16), kindCode: 0, attestationHash: null, resultCode: null, backupExpiryAt: null },
    ], evidenceEntryHash: null,
  }
}
function delivery(): DestructionReaderDeliveryView {
  return { destructionId: ID, jobHash: HASH, readerId: READER,
    exactAuthorization: [0, 255, 1], exactInitiatingEvent: [2, 0, 3], exactJobUpload: [4, 5, 255] }
}
const release = vi.fn()
const acquireBusy = () => ({ current: () => true, release })

beforeEach(() => {
  let counter = 0
  Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: vi.fn(() => `blob:delivery-${++counter}`) })
  Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: vi.fn() })
})
afterEach(() => { vi.clearAllMocks() })

describe('Reader original delivery', () => {
  it('carries exact selectors and public originals without another native action', async () => {
    const call = vi.fn().mockResolvedValue(delivery())
    const bridge = connectReaderDeliveryBridge(call)
    expect(call).not.toHaveBeenCalled()
    expect(await bridge.export(ID, HASH, READER)).toEqual(delivery())
    expect(call).toHaveBeenCalledExactlyOnceWith('destruction_export_reader_delivery', {
      destructionId: ID, expectedPreflightHash: HASH, readerId: READER,
    })
  })

  it.each([
    { destructionId: 'ff'.repeat(16) }, { jobHash: 'ff'.repeat(32) }, { readerId: 'ff'.repeat(16) },
    { exactAuthorization: [] }, { exactInitiatingEvent: [256] }, { exactJobUpload: [-1] },
    { exactAuthorization: [1.5] }, { exactJobUpload: new Uint8Array([1]) },
    { exactAuthorization: new Array(4 * 1024 * 1024 + 1) },
    { exactJobUpload: new Array(64 * 1024 * 1024 + 1) },
  ])('rejects mismatched or unbounded native output before file creation', async (change) => {
    const bridge = connectReaderDeliveryBridge(vi.fn().mockResolvedValue({ ...delivery(), ...change }))
    await expect(bridge.export(ID, HASH, READER)).rejects.toThrow()
    expect(URL.createObjectURL).not.toHaveBeenCalled()
  })

  it('requires an explicit actual Reader choice and creates three byte-exact links only on request', async () => {
    const bridge = { export: vi.fn().mockResolvedValue(delivery()) }
    const { unmount } = render(<ReaderDelivery process={process()} bridge={bridge} disabled={false} acquireBusy={acquireBusy} />)
    expect(bridge.export).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: 'Dateien für Lesegerät bereitstellen' })).toBeDisabled()
    expect(screen.queryByRole('option', { name: '55'.repeat(16) })).not.toBeInTheDocument()
    fireEvent.change(screen.getByRole('combobox', { name: 'Lesegerät für die Übergabe' }), { target: { value: READER } })
    fireEvent.click(screen.getByRole('button', { name: 'Dateien für Lesegerät bereitstellen' }))
    expect(await screen.findAllByRole('link')).toHaveLength(3)
    expect(bridge.export).toHaveBeenCalledExactlyOnceWith(ID, HASH, READER)
    const blobs = vi.mocked(URL.createObjectURL).mock.calls.map(([blob]) => blob as Blob)
    const bytes = await Promise.all(blobs.map((blob) => new Promise<number[]>((resolve) => {
      const reader = new FileReader()
      reader.onload = () => { resolve(Array.from(new Uint8Array(reader.result as ArrayBuffer))) }
      reader.readAsArrayBuffer(blob)
    })))
    expect(bytes).toEqual([[0, 255, 1], [2, 0, 3], [4, 5, 255]])
    expect(screen.getByRole('status')).toHaveTextContent('Dateien stehen bereit')
    expect(screen.getByText(/Repliknachweis ist damit noch nicht erbracht/)).toBeVisible()
    unmount()
    expect(URL.revokeObjectURL).toHaveBeenCalledTimes(3)
  })

  it('discards a late reply after the selected job changes', async () => {
    let resolve!: (value: DestructionReaderDeliveryView) => void
    const bridge = { export: vi.fn(() => new Promise<DestructionReaderDeliveryView>((done) => { resolve = done })) }
    const selected = process()
    const { rerender } = render(<ReaderDelivery process={selected} bridge={bridge} disabled={false} acquireBusy={acquireBusy} />)
    fireEvent.change(screen.getByRole('combobox'), { target: { value: READER } })
    fireEvent.click(screen.getByRole('button', { name: 'Dateien für Lesegerät bereitstellen' }))
    rerender(<ReaderDelivery process={{ ...selected, destructionId: '99'.repeat(16) }} bridge={bridge} disabled={false} acquireBusy={acquireBusy} />)
    await act(async () => { resolve(delivery()) })
    expect(screen.queryByRole('link')).not.toBeInTheDocument()
    expect(URL.createObjectURL).not.toHaveBeenCalled()
    expect(release).toHaveBeenCalledOnce()
  })

  it('shows native refusal without downloads and permits a corrected retry', async () => {
    const bridge = { export: vi.fn().mockRejectedValueOnce({ code: 'EA-DESTRUCTION-NATIVE-SESSION' }).mockResolvedValue(delivery()) }
    render(<ReaderDelivery process={process()} bridge={bridge} disabled={false} acquireBusy={acquireBusy} />)
    fireEvent.change(screen.getByRole('combobox'), { target: { value: READER } })
    fireEvent.click(screen.getByRole('button', { name: 'Dateien für Lesegerät bereitstellen' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('EA-DESTRUCTION-NATIVE-SESSION')
    expect(screen.queryByRole('link')).not.toBeInTheDocument()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Dateien für Lesegerät bereitstellen' })).toBeEnabled())
    fireEvent.click(screen.getByRole('button', { name: 'Dateien für Lesegerät bereitstellen' }))
    expect(await screen.findAllByRole('link')).toHaveLength(3)
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('keeps a requested job unavailable even when it has a Reader and preflight', () => {
    const bridge = { export: vi.fn() }
    render(<ReaderDelivery process={{ ...process(), state: 'requested' }} bridge={bridge} disabled={false} acquireBusy={acquireBusy} />)
    fireEvent.change(screen.getByRole('combobox'), { target: { value: READER } })
    expect(screen.getByRole('button', { name: 'Dateien für Lesegerät bereitstellen' })).toBeDisabled()
    expect(bridge.export).not.toHaveBeenCalled()
  })
})
