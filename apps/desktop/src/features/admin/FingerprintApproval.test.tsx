import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, it, vi } from 'vitest'
import { FingerprintApproval } from './FingerprintApproval'
import type { TrustCeremonyView } from '../../bridge/generated-contracts'

const fingerprint = Array.from({ length: 32 }, () => 'AB').join(':')
function view(overrides: Partial<TrustCeremonyView> = {}): TrustCeremonyView {
  return {
    ceremonyId: 'issue-1', kind: 'DeviceApprove', step: 'PendingRequest',
    round: 'IssueTarget', linkedCeremonyId: null,
    fingerprintSubject: 'RegistrationRequest', targetFingerprint: fingerprint,
    exchangeFileName: null, ...overrides,
  }
}
function show(ceremony: TrustCeremonyView) {
  const open = vi.fn()
  render(<FingerprintApproval ceremony={ceremony} notice={null} error={null} busy={false}
    onConfirmFingerprint={vi.fn()} onAuthorize={vi.fn()} onExportRequest={vi.fn()}
    onImportReply={vi.fn()} onPublish={vi.fn()} onOpenLinkedCeremony={open} />)
  return open
}

it.each([
  ['RegistrationRequest', 'Fingerprint der Registrierungsanfrage'],
  ['IssuedCertificate', 'Fingerprint des ausgestellten Zertifikats'],
] as const)('names the exact %s fingerprint being compared', (fingerprintSubject, label) => {
  show(view({ fingerprintSubject }))
  expect(screen.getByText(label)).toBeVisible()
  expect(screen.getByLabelText('Vollständiger Fingerprint')).toHaveTextContent(fingerprint)
})

it('opens the linked activation only after target publication without claiming an active device', async () => {
  const open = show(view({ step: 'TargetPublished', linkedCeremonyId: 'activate-2' }))
  expect(screen.getByRole('heading')).toHaveTextContent('Ziel veröffentlicht')
  expect(screen.getByRole('heading')).toHaveTextContent('Schritt 6 von 6')
  expect(screen.queryByText('Gerät aktiv')).not.toBeInTheDocument()
  await userEvent.setup().click(screen.getByRole('button', { name: 'Registry-Aktivierung öffnen' }))
  expect(open).toHaveBeenCalledExactlyOnceWith('activate-2')
})

it('does not invent a linked activation before it exists', () => {
  show(view({ step: 'TargetPublished' }))
  expect(screen.queryByRole('button', { name: 'Registry-Aktivierung öffnen' })).not.toBeInTheDocument()
  expect(screen.getByText('Die Registry-Aktivierung steht noch aus.')).toBeVisible()
})

it('names an activated revocation without claiming that the revoked device is active', () => {
  show(view({ kind: 'DeviceRevoke', round: 'ActivateRegistry', step: 'RegistryPublished', fingerprintSubject: null, targetFingerprint: null }))
  expect(screen.getByRole('heading')).toHaveTextContent('Widerruf wirksam')
  expect(screen.queryByText('Gerät aktiv')).not.toBeInTheDocument()
})
