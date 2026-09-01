import { render, screen, waitFor } from '@testing-library/react'
import { expect, it, vi } from 'vitest'

import { userEvent } from '../../test-setup'
import type { EnrollmentBridge } from '../../vault/webauthn-prf'
import { EnrollmentPage } from './EnrollmentPage'

const user = userEvent.setup()

// `SHOWN` und `WRONG` stehen im KOPF DIESER DATEI und in keinem gemeinsamen
// Hilfsmodul: eine Testdatei ist von beiden Quelltextscans des Pakets
// ausgenommen (`bridge/no-hand-written-contracts.test.ts` und
// `design/static-css.test.ts` filtern `.test.tsx?` heraus), ein Hilfsmodul
// daneben waere es nicht und schleppte die Fingerprint-Literale in den
// gescannten Bestand.
const SHOWN = { keyFingerprint: 'a'.repeat(64), bundleFingerprint: 'b'.repeat(64) }
const WRONG = 'c'.repeat(64)

function stubBridge(overrides: Partial<EnrollmentBridge> = {}): EnrollmentBridge {
  // Der Zaehler ist ZUSTAND und keine Konstante: die Seite nimmt die Zahl der
  // registrierten Authenticators aus der Bruecke und zaehlt keine Klicks selbst
  // (§9). Ein Doppel, das immer `registered: 1` meldet, liesse das
  // Abschlusselement fuer immer gesperrt und der Zeuge waere rot.
  let registered = 0
  // Der Satz aufgenommener Kennungen ist im echten Ablauf ZUSTAND IN RUST und
  // das Argument der naechsten `excludeCredentials`; das Doppel spiegelt
  // deshalb, dass er MITWAECHST. Ein Doppel, das immer die leere Liste
  // zurueckgaebe, beschriebe eine Bruecke, die den Ausschluss nie fuellt.
  const ids: Uint8Array<ArrayBuffer>[] = []
  return {
    begin: vi.fn(async () => ({
      handle: 1,
      prfSalt: new Uint8Array(0),
      publicKeyAlgorithms: [-8],
      registeredCredentialIds: [],
    })),
    registerAuthenticator: vi.fn(async () => {
      registered += 1
      ids.push(new Uint8Array(16).fill(registered))
      return { registered, required: 2, registeredCredentialIds: [...ids] }
    }),
    fingerprints: vi.fn(async () => SHOWN),
    confirmFingerprints: vi.fn(async ({ expectedBundleFingerprint }) => ({
      confirmed: expectedBundleFingerprint === SHOWN.bundleFingerprint,
      code:
        expectedBundleFingerprint === SHOWN.bundleFingerprint
          ? undefined
          : 'EA-READER-ENROLLMENT-FINGERPRINT-MISMATCH',
    })),
    finish: vi.fn(async () => ({ finished: true })),
    ...overrides,
  }
}

it('keeps the enrollment closed until two authenticators and both fingerprints agree', async () => {
  render(<EnrollmentPage bridge={stubBridge()} />)
  expect(screen.getByRole('button', { name: 'Enrollment abschließen' })).toBeDisabled()
  await user.click(screen.getByRole('button', { name: 'Authenticator registrieren' }))
  expect(screen.getByText('Ein zweiter Authenticator ist erforderlich.')).toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Authenticator registrieren' }))
  expect(screen.getByText('2 von 2 Authenticators registriert.')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Enrollment abschließen' })).toBeDisabled()
  await user.type(screen.getByLabelText('Erwarteter Bundle-Fingerprint'), WRONG)
  await user.type(screen.getByLabelText('Erwarteter Schlüssel-Fingerprint'), SHOWN.keyFingerprint)
  expect(screen.getByRole('alert')).toHaveTextContent('EA-READER-ENROLLMENT-FINGERPRINT-MISMATCH')
  expect(screen.getByRole('button', { name: 'Enrollment abschließen' })).toBeDisabled()
  await user.clear(screen.getByLabelText('Erwarteter Bundle-Fingerprint'))
  await user.type(screen.getByLabelText('Erwarteter Bundle-Fingerprint'), SHOWN.bundleFingerprint)
  expect(screen.getByRole('button', { name: 'Enrollment abschließen' })).toBeEnabled()
})

it('derives no key and compares no fingerprint in TypeScript', async () => {
  const bridge = stubBridge()
  render(<EnrollmentPage bridge={bridge} />)
  await user.type(screen.getByLabelText('Erwarteter Bundle-Fingerprint'), SHOWN.bundleFingerprint)
  await user.type(screen.getByLabelText('Erwarteter Schlüssel-Fingerprint'), SHOWN.keyFingerprint)
  expect(bridge.confirmFingerprints).toHaveBeenCalledWith({
    handle: 1,
    expectedKeyFingerprint: SHOWN.keyFingerprint,
    expectedBundleFingerprint: SHOWN.bundleFingerprint,
  })
})

it('locks the registration control while a ceremony is in flight', async () => {
  // Der Spiegel der aufgenommenen Kennungen wird erst aus der ANTWORT von
  // `registerAuthenticator` gestellt. Ein zweiter Anlauf davor ginge mit dem
  // alten, zu kurzen Satz in `excludeCredentials` los — und genau dieser Satz
  // ist der Grund, aus dem eine zweite Zeremonie auf demselben Geraet
  // abgewiesen wird, statt den ersten Passkey zu ersetzen. Chromium laesst
  // heute ohnehin nur eine ausstehende `credentials.create`-Anfrage zu, aber
  // dieser Schutz gehoert dem BROWSER und nicht dieser Anwendung.
  let release: (() => void) | undefined
  const bridge = stubBridge({
    registerAuthenticator: vi.fn(async () => {
      await new Promise<void>((resolve) => {
        release = resolve
      })
      return { registered: 1, required: 2, registeredCredentialIds: [] }
    }),
  })
  render(<EnrollmentPage bridge={bridge} />)
  const control = screen.getByRole('button', { name: 'Authenticator registrieren' })
  await user.click(control)
  expect(control).toBeDisabled()
  expect(bridge.registerAuthenticator).toHaveBeenCalledTimes(1)
  await user.click(control)
  expect(bridge.registerAuthenticator).toHaveBeenCalledTimes(1)
  release?.()
  await waitFor(() => {
    expect(control).toBeEnabled()
  })
})

it('says in German that this device already carries a vault instead of showing the bare code', async () => {
  // Die Weigerung faellt in `ReaderEnrollment::begin` und reist als STABILER
  // CODE herauf; uebersetzt wird sie hier, entschieden wurde sie dort.
  const bridge = stubBridge({
    begin: vi.fn(async () => {
      throw new Error('EA-READER-ENROLLMENT-VAULT-PRESENT')
    }),
  })
  render(<EnrollmentPage bridge={bridge} />)
  const alert = await screen.findByRole('alert')
  expect(alert).toHaveTextContent('Dieses Gerät trägt bereits einen Reader-Tresor.')
  expect(alert).not.toHaveTextContent('EA-READER-ENROLLMENT-VAULT-PRESENT')
})
