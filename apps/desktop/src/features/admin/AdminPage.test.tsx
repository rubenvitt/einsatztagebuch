import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { render, screen, waitFor, within } from '@testing-library/react'
import { App, ConfigProvider } from 'antd'
import { expect, it, vi } from 'vitest'
import type { ReactElement } from 'react'

import { ADMIN_COMMANDS, AdminPage, AdminSurface, REAUTH_PURPOSES } from './AdminPage'
import type { AdminBridge } from './AdminPage'
import type {
  ClockReleaseOfferView,
  GoLiveChecklistView,
  TrustCeremonyKind,
  TrustCeremonyStep,
  TrustCeremonyView,
  WriterTransitionView,
} from '../../bridge/generated-contracts'
import { eaRuntimeTheme } from '../../design/tokens'
import { userEvent } from '../../test-setup'

const user = userEvent.setup()

const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')

/** 32 Paare Gross-Hex mit Doppelpunkt — die Form, die `ea_admin::fingerprint` liefert. */
const FINGERPRINT = Array.from({ length: 32 }, (_, index) =>
  ((index * 7 + 3) % 256).toString(16).padStart(2, '0').toUpperCase(),
).join(':')

const FINGERPRINT_SHAPE = /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/

const HOUR = 60 * 60 * 1000
const DAY = 24 * HOUR

const GO_LIVE_CODES = [
  'EA-GOLIVE-TWO-ADMINS',
  'EA-GOLIVE-KEY-BACKUP-ROOT',
  'EA-GOLIVE-KEY-BACKUP-ADMIN',
  'EA-GOLIVE-KEY-BACKUP-RECOVERY-KEM',
  'EA-GOLIVE-KEY-BACKUP-HGA',
  'EA-GOLIVE-REGISTRY-AGE',
  'EA-GOLIVE-REGISTRY-LEASE',
  'EA-GOLIVE-POLICY',
  'EA-GOLIVE-EVIDENCE-POLICY',
  'EA-GOLIVE-RECOVERY-TEST',
  'EA-GOLIVE-WRITER-TRANSITION',
  'EA-POSTURE-FULL-DISK-ENCRYPTION',
  'EA-POSTURE-ACCOUNT-EXCLUSIVE',
  'EA-POSTURE-SCREEN-LOCK',
  'EA-POSTURE-OS-PATCH-LEVEL',
] as const

function confirmedChecklist(): GoLiveChecklistView {
  return {
    requirements: GO_LIVE_CODES.map((code) => ({
      requirementCode: code,
      status: 'Confirmed',
      evidenceCode: `${code}-EVIDENCE`,
    })),
    productionReady: true,
  }
}

/** Eine Liste mit GENAU einer nicht automatisch pruefbaren Anforderung. */
function unknownChecklist(): GoLiveChecklistView {
  const ready = confirmedChecklist()
  return {
    requirements: ready.requirements.map((requirement) =>
      requirement.requirementCode === 'EA-GOLIVE-RECOVERY-TEST'
        ? {
            ...requirement,
            status: 'NotAutomaticallyVerifiable',
            evidenceCode: 'EA-GOLIVE-EVIDENCE-UNAVAILABLE',
          }
        : requirement,
    ),
    productionReady: false,
  }
}

function offeredRelease(): ClockReleaseOfferView {
  return {
    availability: 'Offered',
    floorMs: 1_771_000_000_000,
    observedWallClockMs: 1_771_000_900_000,
    maxFutureClockSkewMs: 5 * 60 * 1000,
    expiresAtMs: 1_771_003_600_000,
    justifications: [
      'OperatorVerifiedWallClock',
      'PlatformTimeSourceRecovery',
      'HardwareClockMaintenance',
    ],
  }
}

function noTransition(): WriterTransitionView {
  return {
    phase: 'NoTransition',
    currentWriterHash: 'AA'.repeat(32),
    newWriterHash: null,
    effectiveFromSequence: null,
  }
}

function ceremony(
  kind: TrustCeremonyKind,
  step: TrustCeremonyStep,
  exchangeFileName: string | null = null,
): TrustCeremonyView {
  return {
    ceremonyId: `zeremonie-${kind}`,
    kind,
    step,
    targetFingerprint: kind === 'DeviceApprove' ? FINGERPRINT : null,
    exchangeFileName,
  }
}

/**
 * Die Bruecke als Doppel. Jede Handlung ist ein `vi.fn`, damit ein Zeuge das
 * ARGUMENT messen kann — den Zweck der Wiederanmeldung vor allem.
 *
 * Die Zeremonie schreitet je Handlung um genau einen Schritt fort; die
 * Antworten tragen die Art der begonnenen Zeremonie weiter, damit der
 * Stepper ohne Fingerprint-Schritt messbar ist.
 */
function fakeAdminBridge(overrides: Partial<AdminBridge> = {}): AdminBridge {
  let kind: TrustCeremonyKind = 'DeviceApprove'
  return {
    pendingRequests: [
      {
        requestId: 'anfrage-1',
        certificateKindCode: 'EA-CERT-READER-DEVICE',
        fingerprint: FINGERPRINT,
        receivedAtMs: 1_771_000_000_000,
      },
    ],
    checklist: confirmedChecklist(),
    registryHealth: {
      registryVersion: 4,
      headHash: 'CC'.repeat(32),
      registryAgeMs: 2 * DAY + 2 * HOUR,
      maxRegistryAgeMs: 7 * DAY,
      leaseValidThroughSequence: 120,
      nextSequence: 87,
      notAfterMs: 1_771_600_000_000,
      staleDecision: 'Fresh',
    },
    policy: {
      operatingProfile: 0,
      maxRegistryAgeMs: 7 * DAY,
      maxFutureClockSkewMs: 5 * 60 * 1000,
      registryExpiryBehavior: 0,
      evidenceMaxDelayMs: 12 * HOUR,
      readerInactivityMs: 10 * 60 * 1000,
      readerTrustRefreshMs: DAY,
      readerHistoryAccessAllowed: false,
      backupFrequencyMs: DAY,
      restoreTestIntervalMs: 90 * DAY,
      retentionPolicy: 'EA-RETENTION-10Y',
      effectiveFromSequence: 12,
      leaseValidThroughSequence: 120,
      notAfterMs: 1_771_600_000_000,
    },
    writerTransition: noTransition(),
    clockReleaseOffer: {
      availability: 'NotBlocked',
      floorMs: null,
      observedWallClockMs: null,
      maxFutureClockSkewMs: null,
      expiresAtMs: null,
      justifications: [],
    },
    devicePosture: {
      requirements: [
        {
          requirementCode: 'EA-POSTURE-FULL-DISK-ENCRYPTION',
          satisfied: null,
          evidenceCode: 'EA-POSTURE-FDE-UNREPORTABLE',
        },
      ],
      productionReady: false,
    },
    reauthenticate: vi.fn((purpose: string) =>
      Promise.resolve({ fresh: true, purposeCode: `EA-OPERATOR-REAUTH-${purpose}` }),
    ),
    beginCeremony: vi.fn((_requestId: string, begun: TrustCeremonyKind) => {
      kind = begun
      return Promise.resolve(ceremony(kind, 'PendingRequest'))
    }),
    confirmFingerprint: vi.fn(() => Promise.resolve(ceremony(kind, 'FingerprintConfirmed'))),
    authorize: vi.fn(() => Promise.resolve(ceremony(kind, 'AdminAuthorized'))),
    exportRequest: vi.fn(() =>
      Promise.resolve(ceremony(kind, 'RootRequestExported', 'root-anfrage-0001.json')),
    ),
    importReply: vi.fn(() => Promise.resolve(ceremony(kind, 'RootReplyImported'))),
    publish: vi.fn(() => Promise.resolve(ceremony(kind, 'RegistryPublished'))),
    exportUnresolved: vi.fn(() =>
      Promise.resolve('{"format":"ea.go-live-checklist/v1","unresolved":[]}'),
    ),
    issueClockRelease: vi.fn(() =>
      Promise.resolve({
        releaseId: 'freigabe-0001',
        expiresAtMs: 1_771_003_600_000,
        changesTimeFloor: false,
        changesRegistryExpiry: false,
        changesLease: false,
      }),
    ),
    prepareWriterTransition: vi.fn(() =>
      Promise.resolve<WriterTransitionView>({
        phase: 'Prepared',
        currentWriterHash: 'AA'.repeat(32),
        newWriterHash: 'BB'.repeat(32),
        effectiveFromSequence: 88,
      }),
    ),
    activateWriterTransition: vi.fn(() =>
      Promise.resolve<WriterTransitionView>({
        phase: 'Activated',
        currentWriterHash: 'BB'.repeat(32),
        newWriterHash: null,
        effectiveFromSequence: 88,
      }),
    ),
    revocationEffect: vi.fn((targetHash: string) =>
      Promise.resolve({
        targetClass: 'NonAdminDevice' as const,
        targetHash,
        stopsNewGrantsFromSequence: 91,
        recallsIssuedGrants: false,
        recallsDecryptedPlaintext: false,
      }),
    ),
    ...overrides,
  }
}

function ceremonyRegion(name: RegExp | string) {
  return within(screen.getByRole('region', { name }))
}

// Der Schritt-1-Zeuge des Plans (Abschnitt Task 6), mit den Abfragen des
// Hausstils: Rolle und Name statt Testkennung.
it('does not collapse request fingerprint approval and Root import', async () => {
  render(<AdminPage bridge={fakeAdminBridge()} />)
  expect(screen.getByText('Anfrage ausstehend')).toBeVisible()
  await user.click(screen.getByRole('button', { name: 'Fingerprint vergleichen' }))
  expect(screen.getByLabelText('Vollständiger Fingerprint')).toHaveTextContent(FINGERPRINT_SHAPE)
  expect(
    screen.getByRole('img', { name: 'QR-Code des vollständigen Fingerprints' }),
  ).toBeVisible()
  expect(screen.queryByText('Gerät aktiv')).not.toBeInTheDocument()
})

// Der volle Weg einer Geraetefreigabe: sechs Schritte, je EINE Handlung, die
// Wiederanmeldung VOR der Autorisierung und VOR der Veroeffentlichung, der
// Fokus nach jedem Schritt auf der Ueberschrift — und „Gerät aktiv" erst, wenn
// die Registry veroeffentlicht ist.
it('walks the six device approval steps with one action each and fresh proof before Root steps', async () => {
  const bridge = fakeAdminBridge()
  render(<AdminPage bridge={bridge} />)
  await user.click(screen.getByRole('button', { name: 'Fingerprint vergleichen' }))
  const requests = ceremonyRegion('Geräteanfragen')

  const heading = () => requests.getByRole('heading', { level: 4 })
  expect(heading()).toHaveTextContent(/Schritt 1 von 6: Anfrage ausstehend/)
  expect(heading()).toHaveFocus()
  // Volltext UND QR gleichzeitig (design.md:1925).
  expect(requests.getByLabelText('Vollständiger Fingerprint')).toHaveTextContent(FINGERPRINT)
  expect(requests.getByRole('img', { name: 'QR-Code des vollständigen Fingerprints' })).toBeVisible()
  expect(requests.getAllByRole('button')).toHaveLength(2)

  await user.type(
    requests.getByLabelText('Über den zweiten Kanal gemeldeter Fingerprint'),
    FINGERPRINT,
  )
  await user.click(requests.getByRole('button', { name: 'Fingerprint bestätigen' }))
  expect(bridge.confirmFingerprint).toHaveBeenCalledWith('zeremonie-DeviceApprove', FINGERPRINT)
  await waitFor(() => {
    expect(heading()).toHaveTextContent(/Schritt 2 von 6: Fingerprint bestätigt/)
  })
  expect(heading()).toHaveFocus()
  expect(requests.getAllByRole('button')).toHaveLength(2)
  expect(bridge.reauthenticate).not.toHaveBeenCalled()

  await user.click(requests.getByRole('button', { name: 'Neu anmelden und autorisieren' }))
  await waitFor(() => {
    expect(heading()).toHaveTextContent(/Schritt 3 von 6: Admin-Autorisierung erteilt/)
  })
  expect(bridge.reauthenticate).toHaveBeenNthCalledWith(1, REAUTH_PURPOSES.adminRootCeremony)
  expect(bridge.authorize).toHaveBeenCalledTimes(1)
  expect(heading()).toHaveFocus()

  await user.click(requests.getByRole('button', { name: 'Root-Anfrage exportieren' }))
  await waitFor(() => {
    expect(heading()).toHaveTextContent(/Schritt 4 von 6: Root-Anfrage exportiert/)
  })
  expect(requests.getByText(/root-anfrage-0001\.json/)).toBeVisible()
  expect(heading()).toHaveFocus()

  await user.click(requests.getByRole('button', { name: 'Root-Antwort importieren' }))
  await waitFor(() => {
    expect(heading()).toHaveTextContent(/Schritt 5 von 6: Root-Antwort importiert/)
  })
  expect(screen.queryByText('Gerät aktiv')).not.toBeInTheDocument()
  expect(requests.getAllByRole('button')).toHaveLength(2)

  await user.click(requests.getByRole('button', { name: 'Neu anmelden und veröffentlichen' }))
  await waitFor(() => {
    expect(heading()).toHaveTextContent(/Schritt 6 von 6: Gerät aktiv/)
  })
  expect(bridge.reauthenticate).toHaveBeenNthCalledWith(2, REAUTH_PURPOSES.adminRootCeremony)
  expect(bridge.publish).toHaveBeenCalledTimes(1)
  expect(heading()).toHaveFocus()
  expect(requests.getByText('Gerät aktiv')).toBeVisible()
})

// Ohne frischen Nachweis KEINE Autorisierung — und das steht im Wortlaut da.
it('never authorizes when the re-authentication is not fresh', async () => {
  const bridge = fakeAdminBridge({
    reauthenticate: vi.fn(() =>
      Promise.resolve({ fresh: false, purposeCode: 'EA-OPERATOR-REAUTH-STALE' }),
    ),
  })
  render(<AdminPage bridge={bridge} />)
  await user.click(screen.getByRole('button', { name: 'Fingerprint vergleichen' }))
  const requests = ceremonyRegion('Geräteanfragen')
  await user.type(
    requests.getByLabelText('Über den zweiten Kanal gemeldeter Fingerprint'),
    FINGERPRINT,
  )
  await user.click(requests.getByRole('button', { name: 'Fingerprint bestätigen' }))
  await user.click(await requests.findByRole('button', { name: 'Neu anmelden und autorisieren' }))
  await waitFor(() => {
    expect(requests.getByText('Wiederanmeldung erforderlich')).toBeVisible()
  })
  expect(bridge.authorize).not.toHaveBeenCalled()
  expect(requests.getByRole('heading', { level: 4 })).toHaveTextContent(/Schritt 2 von 6/)
})

it('shows the host refusal code of a ceremony step and stays on the step', async () => {
  const bridge = fakeAdminBridge({
    confirmFingerprint: vi.fn(() => Promise.reject({ code: 'EA-WORKFLOW-FINGERPRINT-MISMATCH' })),
  })
  render(<AdminPage bridge={bridge} />)
  await user.click(screen.getByRole('button', { name: 'Fingerprint vergleichen' }))
  const requests = ceremonyRegion('Geräteanfragen')
  await user.type(requests.getByLabelText('Über den zweiten Kanal gemeldeter Fingerprint'), 'AB')
  await user.click(requests.getByRole('button', { name: 'Fingerprint bestätigen' }))
  await waitFor(() => {
    expect(requests.getByRole('alert')).toHaveTextContent('EA-WORKFLOW-FINGERPRINT-MISMATCH')
  })
  expect(requests.getByRole('heading', { level: 4 })).toHaveTextContent(/Schritt 1 von 6/)
})

// „Unknown ist nie gruen" — in beiden Richtungen: eine nicht automatisch
// pruefbare Anforderung nennt ihren Wortlaut und ihren Belegcode, und ein
// Wirt, der trotz einer offenen Zeile `productionReady: true` behauptet, wird
// von der Schale NICHT gruen gezeichnet.
it('never renders an unverifiable checklist as production ready', () => {
  render(<AdminPage bridge={fakeAdminBridge({ checklist: unknownChecklist() })} />)
  const status = screen.getByRole('status', { name: 'Go-live-Bereitschaft' })
  expect(status).toHaveTextContent('nicht produktionsbereit')
  expect(screen.queryByText('produktionsbereit')).not.toBeInTheDocument()
  const row = screen.getByText('EA-GOLIVE-RECOVERY-TEST').closest('li')
  expect(row).not.toBeNull()
  expect(row).toHaveTextContent('nicht automatisch prüfbar')
  expect(row).toHaveTextContent('EA-GOLIVE-EVIDENCE-UNAVAILABLE')
  expect(screen.getAllByText('bestätigt')).toHaveLength(14)
})

it('refuses a green light the host asserts over an unconfirmed row', () => {
  const checklist: GoLiveChecklistView = { ...unknownChecklist(), productionReady: true }
  render(<AdminPage bridge={fakeAdminBridge({ checklist })} />)
  expect(screen.getByRole('status', { name: 'Go-live-Bereitschaft' })).toHaveTextContent(
    'nicht produktionsbereit',
  )
  expect(screen.queryByText('produktionsbereit')).not.toBeInTheDocument()
})

it('renders production ready only when every row is confirmed', async () => {
  const bridge = fakeAdminBridge()
  render(<AdminPage bridge={bridge} />)
  expect(screen.getByRole('status', { name: 'Go-live-Bereitschaft' })).toHaveTextContent(
    /^produktionsbereit$/,
  )
  await user.click(screen.getByRole('button', { name: 'Offene Punkte exportieren' }))
  expect(bridge.exportUnresolved).toHaveBeenCalledTimes(1)
  await waitFor(() => {
    expect(screen.getByLabelText('Go-live-Nachweisliste')).toHaveTextContent(
      'ea.go-live-checklist/v1',
    )
  })
})

it('offers no clock release button when none is offered', () => {
  render(<AdminPage bridge={fakeAdminBridge()} />)
  const release = ceremonyRegion('Zeitfreigabe')
  expect(release.getByText('Keine Zeitfreigabe angeboten')).toBeVisible()
  expect(release.queryByRole('button')).not.toBeInTheDocument()
  expect(
    release.getByText(
      'Die Freigabe ändert weder den Zeit-Floor noch den Registry-Ablauf noch die Sequenz-Lease.',
    ),
  ).toBeVisible()
})

it('names the missing independent time source in words', () => {
  render(
    <AdminPage
      bridge={fakeAdminBridge({
        clockReleaseOffer: {
          availability: 'IndependentTimeUnavailable',
          floorMs: null,
          observedWallClockMs: null,
          maxFutureClockSkewMs: null,
          expiresAtMs: null,
          justifications: [],
        },
      })}
    />,
  )
  const release = ceremonyRegion('Zeitfreigabe')
  expect(release.getByText('Keine unabhängige Zeitquelle verfügbar')).toBeVisible()
  expect(release.queryByRole('button')).not.toBeInTheDocument()
})

it('issues an offered clock release only with a justification and fresh proof', async () => {
  const bridge = fakeAdminBridge({ clockReleaseOffer: offeredRelease() })
  render(<AdminPage bridge={bridge} />)
  const release = ceremonyRegion('Zeitfreigabe')
  expect(release.getByText('Zeit-Floor')).toBeVisible()
  expect(release.getByText('Wanduhr des Betriebssystems')).toBeVisible()
  expect(release.getByText('Signiertes Limit')).toBeVisible()
  expect(release.getByText('Ablauf')).toBeVisible()
  expect(
    release.getByText(
      'Die Freigabe ändert weder den Zeit-Floor noch den Registry-Ablauf noch die Sequenz-Lease.',
    ),
  ).toBeVisible()
  expect(release.getByRole('radiogroup', { name: 'Begründung' })).toBeVisible()
  expect(release.getAllByRole('radio')).toHaveLength(3)

  const confirm = release.getByRole('button', { name: 'Neu anmelden und Zeitfreigabe erteilen' })
  expect(confirm).toBeDisabled()
  await user.click(release.getByRole('checkbox'))
  // Ohne Begruendung bleibt die Handhabe zu.
  expect(confirm).toBeDisabled()
  await user.click(release.getByRole('radio', { name: 'Wanduhr vom Bediener geprüft' }))
  expect(confirm).toBeEnabled()
  await user.click(confirm)

  await waitFor(() => {
    expect(release.getByText('freigabe-0001')).toBeVisible()
  })
  expect(bridge.reauthenticate).toHaveBeenCalledWith(REAUTH_PURPOSES.clockSkewRelease)
  expect(bridge.issueClockRelease).toHaveBeenCalledWith('OperatorVerifiedWallClock')
  expect(release.getByText('Zeit-Floor geändert: nein')).toBeVisible()
  expect(release.getByText('Registry-Ablauf geändert: nein')).toBeVisible()
  expect(release.getByText('Sequenz-Lease geändert: nein')).toBeVisible()
  expect(release.queryByText('Unerwartete Änderung gemeldet')).not.toBeInTheDocument()
})

it('warns when a clock release outcome claims a change it must never make', async () => {
  const bridge = fakeAdminBridge({
    clockReleaseOffer: offeredRelease(),
    issueClockRelease: vi.fn(() =>
      Promise.resolve({
        releaseId: 'freigabe-0002',
        expiresAtMs: 1_771_003_600_000,
        changesTimeFloor: true,
        changesRegistryExpiry: false,
        changesLease: false,
      }),
    ),
  })
  render(<AdminPage bridge={bridge} />)
  const release = ceremonyRegion('Zeitfreigabe')
  await user.click(release.getByRole('checkbox'))
  await user.click(release.getByRole('radio', { name: 'Wartung der Hardware-Uhr' }))
  await user.click(release.getByRole('button', { name: 'Neu anmelden und Zeitfreigabe erteilen' }))
  await waitFor(() => {
    expect(release.getByText('Unerwartete Änderung gemeldet')).toBeVisible()
  })
  expect(release.getByText('Zeit-Floor geändert: ja')).toBeVisible()
})

// §12.4: die Grenze steht VOR dem Widerruf im Wortlaut da — und der Widerruf
// selbst ist eine Root-Zeremonie ohne Fingerprint-Schritt.
it('states both non-recall sentences and opens a revocation ceremony without a fingerprint step', async () => {
  const bridge = fakeAdminBridge()
  render(<AdminPage bridge={bridge} />)
  const revocation = ceremonyRegion('Widerruf')
  await user.type(revocation.getByLabelText('Zielhash'), 'DD'.repeat(32))
  await user.click(revocation.getByRole('button', { name: 'Wirkung prüfen' }))
  expect(bridge.revocationEffect).toHaveBeenCalledWith('DD'.repeat(32))
  await waitFor(() => {
    expect(revocation.getByText('Gerätezertifikat (kein Admin)')).toBeVisible()
  })
  expect(revocation.getByText(/ab Sequenz 91/)).toBeVisible()
  expect(revocation.getByText('Bereits erteilte Grants werden nicht zurückgerufen.')).toBeVisible()
  expect(
    revocation.getByText('Bereits entschlüsselte Inhalte können nicht zurückgerufen werden.'),
  ).toBeVisible()

  await user.click(revocation.getByRole('button', { name: 'Widerruf als Root-Zeremonie beginnen' }))
  expect(bridge.beginCeremony).toHaveBeenCalledWith('DD'.repeat(32), 'DeviceRevoke')
  const heading = await revocation.findByRole('heading', { level: 4 })
  expect(heading).toHaveTextContent(/Schritt 1 von 5: Anfrage ausstehend/)
  expect(revocation.queryByText('Fingerprint bestätigt')).not.toBeInTheDocument()
  expect(revocation.queryByLabelText('Vollständiger Fingerprint')).not.toBeInTheDocument()
  expect(revocation.queryByRole('img')).not.toBeInTheDocument()
  // Ohne Fingerprint-Schritt ist die ERSTE Handlung die Autorisierung.
  expect(revocation.getByRole('button', { name: 'Neu anmelden und autorisieren' })).toBeVisible()
})

it('refuses a recall promise the host must never make', async () => {
  const bridge = fakeAdminBridge({
    revocationEffect: vi.fn((targetHash: string) =>
      Promise.resolve({
        targetClass: 'OperatorBinding' as const,
        targetHash,
        stopsNewGrantsFromSequence: 91,
        recallsIssuedGrants: true,
        recallsDecryptedPlaintext: false,
      }),
    ),
  })
  render(<AdminPage bridge={bridge} />)
  const revocation = ceremonyRegion('Widerruf')
  await user.type(revocation.getByLabelText('Zielhash'), 'EE'.repeat(32))
  await user.click(revocation.getByRole('button', { name: 'Wirkung prüfen' }))
  await waitFor(() => {
    expect(revocation.getByText('Unerwartete Rückrufzusage gemeldet')).toBeVisible()
  })
  expect(revocation.getByText('Bedienerbindung')).toBeVisible()
  expect(
    revocation.queryByText('Bereits erteilte Grants werden nicht zurückgerufen.'),
  ).not.toBeInTheDocument()
  expect(
    revocation.queryByRole('button', { name: 'Widerruf als Root-Zeremonie beginnen' }),
  ).not.toBeInTheDocument()
})

it('opens a policy change as a Root ceremony without a fingerprint step', async () => {
  const bridge = fakeAdminBridge()
  render(<AdminPage bridge={bridge} />)
  const policy = ceremonyRegion('Richtlinie')
  expect(policy.getByText('EA-RETENTION-10Y')).toBeVisible()
  expect(policy.getByText(/Root-signiertes .*policyChange/)).toBeVisible()
  await user.click(policy.getByRole('button', { name: 'Richtlinienänderung vorbereiten' }))
  expect(bridge.beginCeremony).toHaveBeenCalledWith(expect.any(String), 'PolicyChange')
  const heading = await policy.findByRole('heading', { level: 4 })
  expect(heading).toHaveTextContent(/Schritt 1 von 5/)
  expect(heading).toHaveFocus()
  expect(policy.queryByText('Fingerprint bestätigt')).not.toBeInTheDocument()
  expect(policy.queryByRole('img')).not.toBeInTheDocument()
})

it('prepares and then activates a writer transition with fresh proof', async () => {
  const bridge = fakeAdminBridge()
  render(<AdminPage bridge={bridge} />)
  const transition = ceremonyRegion('Writer-Wechsel')
  expect(transition.getByText('kein Wechsel')).toBeVisible()
  expect(
    transition.getByText(
      'Es gibt genau einen aktiven Writer; der bisherige Writer bleibt nach der Aktivierung dauerhaft blockiert.',
    ),
  ).toBeVisible()
  expect(
    transition.queryByRole('button', { name: 'Neu anmelden und aktivieren' }),
  ).not.toBeInTheDocument()

  await user.type(transition.getByLabelText('Wechselanfrage (JSON)'), '{{"newWriter":"BB"}')
  await user.click(transition.getByRole('button', { name: 'Wechsel vorbereiten' }))
  expect(bridge.prepareWriterTransition).toHaveBeenCalledWith('{"newWriter":"BB"}')
  await waitFor(() => {
    expect(transition.getByText('vorbereitet')).toBeVisible()
  })
  expect(transition.getByText('BB'.repeat(32))).toBeVisible()
  expect(transition.getByText('88')).toBeVisible()

  await user.click(transition.getByRole('checkbox'))
  await user.click(transition.getByRole('button', { name: 'Neu anmelden und aktivieren' }))
  await waitFor(() => {
    expect(transition.getByText('aktiviert')).toBeVisible()
  })
  expect(bridge.reauthenticate).toHaveBeenCalledWith(REAUTH_PURPOSES.adminRootCeremony)
  expect(bridge.activateWriterTransition).toHaveBeenCalledTimes(1)
})

it('states registry age and lease as two separate numbers', () => {
  render(<AdminPage bridge={fakeAdminBridge()} />)
  const registry = ceremonyRegion('Registry')
  expect(registry.getByText('2 d 2 h')).toBeVisible()
  expect(registry.getByText('7 d 0 h')).toBeVisible()
  expect(registry.getByText('120')).toBeVisible()
  expect(registry.getByText('87')).toBeVisible()
  expect(registry.getByText('CC'.repeat(32))).toBeVisible()
  expect(registry.getByText('Vertrauensbestand aktuell.')).toBeVisible()
})

it('renders the eight administration regions in order and no incident content', () => {
  render(<AdminPage bridge={fakeAdminBridge()} />)
  const regions = screen.getAllByRole('region').map((region) => region.getAttribute('aria-label'))
  expect(regions).toEqual([
    'Go-live-Status',
    'Geräteanfragen',
    'Registry',
    'Richtlinie',
    'Writer-Wechsel',
    'Zeitfreigabe',
    'Gerätehaltung',
    'Widerruf',
  ])
  expect(screen.getByText(/auf dieser Plattform nicht belegbar/)).toBeVisible()
  // Die Rollengrenze: keine Leser-, keine Writer-Funktion, kein Fachinhalt.
  const forbidden = /archiv (lesen|öffnen)|einsatz erfassen|verlauf|entschlüsseln/i
  for (const control of [...screen.queryAllByRole('link'), ...screen.getAllByRole('button')]) {
    expect(control).not.toHaveAccessibleName(forbidden)
  }
  expect(screen.queryByText(/Einsatznummer/)).not.toBeInTheDocument()
})

it('shows the refusal code when the bridge cannot be built', async () => {
  render(
    <AdminSurface
      connect={() => Promise.reject({ code: 'EA-DESKTOP-ADMINISTRATION-FORBIDDEN' })}
    />,
  )
  await waitFor(() => {
    expect(screen.getByRole('alert')).toHaveTextContent('EA-DESKTOP-ADMINISTRATION-FORBIDDEN')
  })
  expect(screen.queryByRole('region')).not.toBeInTheDocument()
})

it('names the seventeen host commands once each', () => {
  const names = Object.values(ADMIN_COMMANDS)
  expect(names).toHaveLength(17)
  expect(new Set(names).size).toBe(17)
  for (const name of names) {
    expect(name).toMatch(/^admin_[a-z_]+$/)
  }
})

// Jede Handhabe traegt einen NAMEN und ist per Tabulator erreichbar
// (design.md:1946-1948).
it('gives every control an accessible name and a tab stop', async () => {
  render(<AdminPage bridge={fakeAdminBridge({ clockReleaseOffer: offeredRelease() })} />)
  await user.click(screen.getByRole('button', { name: 'Fingerprint vergleichen' }))
  const controls = [
    ...screen.getAllByRole('button'),
    ...screen.getAllByRole('textbox'),
    ...screen.getAllByRole('radio'),
    ...screen.getAllByRole('checkbox'),
  ]
  expect(controls.length).toBeGreaterThan(8)
  for (const control of controls) {
    expect(control).toHaveAccessibleName()
    if (!(control as HTMLButtonElement).disabled) {
      expect(control.tabIndex, control.outerHTML.slice(0, 80)).toBeGreaterThanOrEqual(0)
    }
  }
})

function Themed({ children }: { readonly children: ReactElement }): ReactElement {
  return (
    <ConfigProvider theme={eaRuntimeTheme}>
      <App>{children}</App>
    </ConfigProvider>
  )
}

// Dieselbe Zusicherung wie `AppShell.test.tsx` fuer die Verwaltungsflaeche:
// jede Regel, die Ant Design 6 unter `zeroRuntime` trotzdem einspritzt, steht
// in der eingecheckten Datei — auch die von `QRCode` und `Steps`.
it('carries every style the administration surface injects in the checked-in file', async () => {
  // NUR die Einspritzungen DIESES Renderlaufs: die Zeugen darueber rendern die
  // Flaeche ohne `ConfigProvider`, also unter dem Vorgabethema mit gehashten
  // Selektoren, und `@ant-design/cssinjs` raeumt seine Stilelemente zwischen
  // zwei Tests nicht ab (gemessen: ohne diesen Filter faellt der Zeuge an einem
  // Vorgabethema-Block, der in der eingecheckten Datei nichts zu suchen hat).
  const before = new Set([...document.querySelectorAll('style')].map((tag) => tag.textContent ?? ''))
  render(
    <Themed>
      <AdminPage bridge={fakeAdminBridge({ clockReleaseOffer: offeredRelease() })} />
    </Themed>,
  )
  await user.click(screen.getByRole('button', { name: 'Fingerprint vergleichen' }))
  const injected = [...document.querySelectorAll('style')].filter(
    (tag) => !before.has(tag.textContent ?? ''),
  )
  expect(injected.length).toBeGreaterThan(0)
  const staticCss = readFileSync(path.join(sourceRoot, 'design/static-antd.css'), 'utf8')
  for (const tag of injected) {
    const text = tag.textContent ?? ''
    expect(text.length).toBeGreaterThan(0)
    expect(staticCss, `nicht extrahiert: ${JSON.stringify(text.slice(0, 160))}`).toContain(text)
  }
})
