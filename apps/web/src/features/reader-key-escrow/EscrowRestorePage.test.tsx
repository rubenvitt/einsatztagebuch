import { render, screen, waitFor } from '@testing-library/react'
import { expect, it, vi } from 'vitest'

import { userEvent } from '../../test-setup'
import type { ReaderKeyEscrowBridge } from './escrow-bridge'
import { EscrowRestorePage } from './EscrowRestorePage'

const user = userEvent.setup()

const SUBJECT_HEX = '5a'.repeat(16)
const BEGUN = {
  handle: 9,
  transportFingerprint: '7'.repeat(64),
  escrowObjectHash: '8'.repeat(64),
  readerCertificate: '9'.repeat(64),
  fileName: 'cc.reader-key-escrow-transport.cbor',
  bytesHex: '0506',
}
const OPENED = {
  restored: true,
  kemFingerprint: 'a'.repeat(64),
  authorizationObjectHash: 'b'.repeat(64),
}

function stubBridge(overrides: Partial<ReaderKeyEscrowBridge> = {}): ReaderKeyEscrowBridge {
  return {
    registrationRequest: vi.fn(async () => {
      throw new Error('nicht in Zeremonie B')
    }),
    sealPackage: vi.fn(async () => {
      throw new Error('nicht in Zeremonie B')
    }),
    transportBegin: vi.fn(async () => BEGUN),
    transportOpen: vi.fn(async () => OPENED),
    abort: vi.fn(async () => undefined),
    ...overrides,
  }
}

const file = (name: string) => new File([new Uint8Array([1])], name)

async function begin(): Promise<void> {
  await user.upload(screen.getByLabelText('Trust-Dateien wählen'), [file('trust.etb')])
  await user.click(screen.getByRole('button', { name: 'Wiederherstellung beginnen' }))
}

it('shows the transport fingerprint, downloads the request and keeps the import closed before', async () => {
  const bridge = stubBridge()
  const download = vi.fn()
  render(
    <EscrowRestorePage bridge={bridge} download={download} renderEnrollment={() => <p>neu</p>} />,
  )
  expect(screen.getByLabelText('Umschlag importieren')).toBeDisabled()
  await begin()
  expect(await screen.findByText(BEGUN.transportFingerprint)).toBeInTheDocument()
  expect(download).toHaveBeenCalledWith(BEGUN.fileName, BEGUN.bytesHex)
  expect(screen.getByLabelText('Umschlag importieren')).toBeEnabled()

  await user.upload(screen.getByLabelText('Umschlag importieren'), [file('x.cbor')])
  expect(await screen.findByText(OPENED.kemFingerprint)).toBeInTheDocument()
  expect(screen.getByText(OPENED.authorizationObjectHash)).toBeInTheDocument()
  expect(bridge.transportOpen).toHaveBeenCalledWith(BEGUN.handle, expect.anything())
  // Danach folgt das Enrollment des neuen Tresors.
  expect(screen.getByText('neu')).toBeInTheDocument()
  expect(document.body.innerHTML).not.toContain(SUBJECT_HEX)
})

it('aborts on unmount and on pagehide', async () => {
  const bridge = stubBridge()
  const view = render(
    <EscrowRestorePage bridge={bridge} download={vi.fn()} renderEnrollment={() => <p>neu</p>} />,
  )
  await begin()
  await screen.findByText(BEGUN.transportFingerprint)
  window.dispatchEvent(new Event('pagehide'))
  await waitFor(() => expect(bridge.abort).toHaveBeenCalledWith(BEGUN.handle))
  view.unmount()
  expect(bridge.abort).toHaveBeenCalledTimes(2)
})

it('shows a refusal code unchanged', async () => {
  const bridge = stubBridge({
    transportOpen: vi.fn(async () => {
      throw new Error('EA-READER-ESCROW-RESTORE-BINDING')
    }),
  })
  render(
    <EscrowRestorePage bridge={bridge} download={vi.fn()} renderEnrollment={() => <p>neu</p>} />,
  )
  await begin()
  await screen.findByText(BEGUN.transportFingerprint)
  await user.upload(screen.getByLabelText('Umschlag importieren'), [file('x.cbor')])
  expect(await screen.findByText(/EA-READER-ESCROW-RESTORE-BINDING/)).toBeInTheDocument()
  expect(screen.queryByText('neu')).toBeNull()
})
