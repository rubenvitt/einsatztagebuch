import { render, screen, waitFor } from '@testing-library/react'
import { expect, it, vi } from 'vitest'

import { userEvent } from '../../test-setup'
import type { ReaderKeyEscrowBridge } from './escrow-bridge'
import { EscrowPackagePage } from './EscrowPackagePage'

const user = userEvent.setup()

// Die Werte stehen im KOPF dieser Testdatei: Testdateien sind von den
// Quelltextscans ausgenommen, ein Hilfsmodul waere es nicht.
const SUBJECT_HEX = '5a'.repeat(16)
const PACKAGE = {
  fileName: 'aa.reader-key-escrow-package.cbor',
  bytesHex: '0102',
  escrowCoreHash: 'c'.repeat(64),
  readerCertificate: 'd'.repeat(64),
  recoveryCertificate: 'e'.repeat(64),
  kemFingerprint: 'f'.repeat(64),
}
const REGISTRATION = {
  fileName: 'bb.registration.cbor',
  bytesHex: '0304',
  kemFingerprint: '1'.repeat(64),
  signingFingerprint: '2'.repeat(64),
}

function stubBridge(overrides: Partial<ReaderKeyEscrowBridge> = {}): ReaderKeyEscrowBridge {
  return {
    registrationRequest: vi.fn(async () => REGISTRATION),
    sealPackage: vi.fn(async () => PACKAGE),
    transportBegin: vi.fn(async () => {
      throw new Error('nicht in Zeremonie A')
    }),
    transportOpen: vi.fn(async () => {
      throw new Error('nicht in Zeremonie A')
    }),
    abort: vi.fn(async () => undefined),
    ...overrides,
  }
}

function trustFile(): File {
  return new File([new Uint8Array([1, 2, 3])], 'trust.etb')
}

it('shows the Rust values verbatim and downloads under the Rust file name', async () => {
  const bridge = stubBridge()
  const download = vi.fn()
  render(<EscrowPackagePage bridge={bridge} download={download} />)

  expect(screen.getByRole('button', { name: 'Hinterlegungspaket erzeugen' })).toBeDisabled()
  await user.upload(screen.getByLabelText('Trust-Dateien wählen'), [trustFile()])
  await user.click(screen.getByRole('button', { name: 'Hinterlegungspaket erzeugen' }))

  await waitFor(() => expect(download).toHaveBeenCalledWith(PACKAGE.fileName, PACKAGE.bytesHex))
  expect(bridge.sealPackage).toHaveBeenCalledTimes(1)
  expect(screen.getByText(PACKAGE.escrowCoreHash)).toBeInTheDocument()
  expect(screen.getByText(PACKAGE.readerCertificate)).toBeInTheDocument()
  expect(screen.getByText(PACKAGE.recoveryCertificate)).toBeInTheDocument()
  expect(screen.getByText(PACKAGE.kemFingerprint)).toBeInTheDocument()
  expect(document.body.innerHTML).not.toContain(SUBJECT_HEX)
})

it('downloads the registration request under its Rust file name', async () => {
  const download = vi.fn()
  render(<EscrowPackagePage bridge={stubBridge()} download={download} />)
  await user.click(screen.getByRole('button', { name: 'Registrierungsantrag herunterladen' }))
  await waitFor(() =>
    expect(download).toHaveBeenCalledWith(REGISTRATION.fileName, REGISTRATION.bytesHex),
  )
  expect(screen.getByText(REGISTRATION.kemFingerprint)).toBeInTheDocument()
  expect(screen.getByText(REGISTRATION.signingFingerprint)).toBeInTheDocument()
})

it('shows a refusal code unchanged and downloads nothing', async () => {
  const download = vi.fn()
  const bridge = stubBridge({
    sealPackage: vi.fn(async () => {
      throw new Error('EA-READER-ESCROW-KEM-MISMATCH')
    }),
  })
  render(<EscrowPackagePage bridge={bridge} download={download} />)
  await user.upload(screen.getByLabelText('Trust-Dateien wählen'), [trustFile()])
  await user.click(screen.getByRole('button', { name: 'Hinterlegungspaket erzeugen' }))
  expect(await screen.findByText(/EA-READER-ESCROW-KEM-MISMATCH/)).toBeInTheDocument()
  expect(download).not.toHaveBeenCalled()
})
