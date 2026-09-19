import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { render, screen, waitFor, within } from '@testing-library/react'
import { App, ConfigProvider } from 'antd'
import { expect, it, vi } from 'vitest'
import type { ReactElement } from 'react'

import { ADMIN_COMMANDS, AdminPage, AdminSurface, REAUTH_PURPOSES } from './AdminPage'
import type { AdminBridge } from './AdminPage'
import { validateChecklist } from './contract-check'
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
  'EA-GOLIVE-EDS-PRIVACY-DECISION',
] as const

function confirmedChecklist(): GoLiveChecklistView {
  return {
    requirements: GO_LIVE_CODES.map((code) => ({
      requirementCode: code,
      status: 'Confirmed',
      evidenceCode: `${code}-EVIDENCE`,
      decisionDocumentHash: null,
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
    ceremonyId: null,
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
    round: 'ActivateRegistry',
    linkedCeremonyId: null,
    fingerprintSubject: kind === 'DeviceApprove' ? 'IssuedCertificate' : null,
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
    diagnoseWriterLock: vi.fn(async () => 'Missing' as const),
    openCeremonies: [],
    readOpenCeremonies: vi.fn(async () => []),
    readCeremony: vi.fn(async () => ceremony(kind, 'PendingRequest')),
    readWriterTransition: vi.fn(async () => noTransition()),
    pendingRequests: [
      {
        requestId: 'anfrage-1',
        certificateKindCode: 'EA-CERT-READER-DEVICE',
        fingerprint: FINGERPRINT,
        receivedAtMs: 1_771_000_000_000,
        fingerprintSubject: 'IssuedCertificate',
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
      minimumRetentionMs: 3650 * DAY,
      destructionEnabled: false,
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
        ceremonyId: null,
        currentWriterHash: 'AA'.repeat(32),
        newWriterHash: 'BB'.repeat(32),
        effectiveFromSequence: 88,
      }),
    ),
    activateWriterTransition: vi.fn(() =>
      Promise.resolve<WriterTransitionView>({
        phase: 'Activated',
        ceremonyId: null,
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

/**
 * Jeder Textknoten der Seite, der das alleinstehende Wort „aktiv" traegt.
 *
 * Je KNOTEN und nicht ueber `textContent` der ganzen Seite: dort stossen die
 * Texte benachbarter Elemente ohne Leerzeichen aneinander („Gerät aktivAnfrage
 * ausstehend"), und `\b` findet die Grenze nicht mehr.
 */
function activeWordNodes(): string[] {
  const found: string[] = []
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT)
  for (let node = walker.nextNode(); node !== null; node = walker.nextNode()) {
    const text = node.textContent ?? ''
    if (/\baktiv\b/.test(text)) {
      found.push(text)
    }
  }
  return found
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
  const qr = screen.getByRole('img', { name: 'QR-Code des vollständigen Fingerprints' })
  expect(qr).toBeVisible()
  // Als SVG und nicht als Canvas: Ant Design legt Rolle und Namen auf das
  // gezeichnete Element selbst, also IST der benannte Knoten das SVG. Ein
  // Canvas waere in einer DOM-Attrappe leer und auf einem Drucker ein Bitmap.
  expect(qr).toBeInstanceOf(SVGElement)
  expect(qr.tagName.toLowerCase()).toBe('svg')
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
  // Je Schritt GENAU eine Handlung neben dem Listenknopf „Fingerprint
  // vergleichen" — an jedem Schritt gemessen, nicht nur an dreien.
  expect(requests.getAllByRole('button')).toHaveLength(2)

  await user.click(requests.getByRole('button', { name: 'Root-Anfrage exportieren' }))
  await waitFor(() => {
    expect(heading()).toHaveTextContent(/Schritt 4 von 6: Root-Anfrage exportiert/)
  })
  expect(requests.getByText(/root-anfrage-0001\.json/)).toBeVisible()
  expect(heading()).toHaveFocus()
  expect(requests.getAllByRole('button')).toHaveLength(2)

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
  // Am Ende bleibt nur der Listenknopf: die Zeremonie hat keine Handlung mehr.
  expect(requests.getAllByRole('button')).toHaveLength(1)
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
  expect(screen.getAllByText('bestätigt')).toHaveLength(15)
  // Und die FARBE sagt dasselbe wie das Wort: die offene Zeile ist nicht gruen,
  // eine bestaetigte ist es. Ohne diesen Zeugen koennte „nicht automatisch
  // prüfbar" in einem gruenen Etikett stehen.
  const unverifiableTag = row?.querySelector('.ant-tag')
  expect(unverifiableTag).not.toBeNull()
  expect(unverifiableTag).not.toHaveClass('ant-tag-success')
  const confirmedTag = screen.getByText('EA-GOLIVE-POLICY').closest('li')?.querySelector('.ant-tag')
  expect(confirmedTag).not.toBeNull()
  expect(confirmedTag).toHaveClass('ant-tag-success')
})

it('refuses a green light the host asserts over an unconfirmed row', () => {
  const checklist: GoLiveChecklistView = { ...unknownChecklist(), productionReady: true }
  render(<AdminPage bridge={fakeAdminBridge({ checklist })} />)
  expect(screen.getByRole('status', { name: 'Go-live-Bereitschaft' })).toHaveTextContent(
    'nicht produktionsbereit',
  )
  expect(screen.queryByText('produktionsbereit')).not.toBeInTheDocument()
})

// AK 44: der Go-live-Bericht zeigt Einstufung UND Entscheidung zum
// `.eds`-Restnachweis — die Einstufung als deutsches Wort zum Belegcode, die
// Entscheidung als signierter Dokumenthash. Die Schale bewertet nichts.
it('shows the eds classification and the signed decision document hash', () => {
  const hash = 'a2'.repeat(32)
  const withEds = (evidenceCode: string, status: 'Confirmed' | 'NotMet', decisionDocumentHash: string | null): GoLiveChecklistView => {
    const ready = confirmedChecklist()
    return {
      requirements: ready.requirements.map((requirement) =>
        requirement.requirementCode === 'EA-GOLIVE-EDS-PRIVACY-DECISION'
          ? { ...requirement, status, evidenceCode, decisionDocumentHash }
          : requirement,
      ),
      productionReady: status === 'Confirmed',
    }
  }
  const edsRow = () => screen.getByText('EA-GOLIVE-EDS-PRIVACY-DECISION').closest('li')

  const released = render(
    <AdminPage bridge={fakeAdminBridge({ checklist: withEds('EA-GOLIVE-EVIDENCE-EDS-RESIDUAL-RELEASED', 'Confirmed', hash) })} />,
  )
  expect(edsRow()).toHaveTextContent('Restnachweis freigegeben')
  expect(edsRow()).toHaveTextContent(`Dokumenthash der Entscheidung: ${hash}`)
  released.unmount()

  const disabled = render(
    <AdminPage bridge={fakeAdminBridge({ checklist: withEds('EA-GOLIVE-EVIDENCE-EDS-DESTRUCTION-DISABLED', 'Confirmed', null) })} />,
  )
  expect(edsRow()).toHaveTextContent('Vernichtung deaktiviert')
  expect(edsRow()).not.toHaveTextContent('Dokumenthash der Entscheidung')
  disabled.unmount()

  render(
    <AdminPage bridge={fakeAdminBridge({ checklist: withEds('EA-GOLIVE-EVIDENCE-EDS-PRIVACY-DECISION-MISSING', 'NotMet', null) })} />,
  )
  expect(edsRow()).toHaveTextContent('Vernichtung aktiviert ohne dokumentierte Freigabe')
  expect(edsRow()).toHaveTextContent('nicht erfüllt')
  expect(screen.getByRole('status', { name: 'Go-live-Bereitschaft' })).toHaveTextContent(
    'nicht produktionsbereit',
  )
  // Der Hash ist Beleg und kein Textkanal: nur `null` oder 64 Kleinbuchstaben-Hex.
  const row = { ...confirmedChecklist().requirements[15] }
  expect(validateChecklist({ requirements: [{ ...row, decisionDocumentHash: hash }], productionReady: true })
    .requirements[0]?.decisionDocumentHash).toBe(hash)
  for (const bad of ['A2'.repeat(32), 'a2'.repeat(31), 'Freigabe liegt vor', 42, undefined]) {
    expect(() =>
      validateChecklist({ requirements: [{ ...row, decisionDocumentHash: bad }], productionReady: true }),
    ).toThrow('Der Dokumenthash der Restnachweis-Entscheidung ist ungültig.')
  }
})

// Eine LEERE Liste ist kein Ja: ein Wirt, der ohne eine einzige Anforderung
// `productionReady: true` meldet, hat nichts bestaetigt.
it('refuses a green light over an empty checklist', () => {
  const checklist: GoLiveChecklistView = { requirements: [], productionReady: true }
  render(<AdminPage bridge={fakeAdminBridge({ checklist })} />)
  expect(screen.getByRole('status', { name: 'Go-live-Bereitschaft' })).toHaveTextContent(
    'nicht produktionsbereit',
  )
  expect(screen.queryByText('produktionsbereit')).not.toBeInTheDocument()
  expect(screen.queryByText('bestätigt')).not.toBeInTheDocument()
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
  // Die WERTE, nicht nur die Beschriftungen: Floor und Wanduhr als ISO-Zeitpunkt
  // in UTC, das Limit als Dauer in Minuten, der Ablauf als Zeitpunkt.
  expect(release.getByText('2026-02-13T16:26:40.000Z')).toBeVisible()
  expect(release.getByText('2026-02-13T16:41:40.000Z')).toBeVisible()
  expect(release.getByText('5 min')).toBeVisible()
  expect(release.getByText('2026-02-13T17:26:40.000Z')).toBeVisible()
  expect(release.queryByText('nicht genannt')).not.toBeInTheDocument()
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

// Zweite Verteidigungslinie hinter `validateClockReleaseOffer`: erreicht ein
// Angebot ohne eine seiner vier Zahlen doch die Flaeche, gibt es KEINE
// Handhabe — fail-closed und im Wortlaut.
it('offers no release when an offered clock release lacks one of its numbers', () => {
  render(
    <AdminPage
      bridge={fakeAdminBridge({ clockReleaseOffer: { ...offeredRelease(), expiresAtMs: null } })}
    />,
  )
  const release = ceremonyRegion('Zeitfreigabe')
  expect(release.getByText('Zeitfreigabe unvollständig gemeldet')).toBeVisible()
  expect(release.queryByRole('button')).not.toBeInTheDocument()
  expect(release.queryByRole('radio')).not.toBeInTheDocument()
  expect(release.queryByRole('checkbox')).not.toBeInTheDocument()
  expect(release.queryByText('Zeitfreigabe angeboten')).not.toBeInTheDocument()
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
  const heading = () => revocation.getByRole('heading', { level: 4 })
  await waitFor(() => {
    expect(heading()).toHaveTextContent(/Schritt 1 von 5: Anfrage ausstehend/)
  })
  expect(revocation.queryByText('Fingerprint bestätigt')).not.toBeInTheDocument()
  expect(revocation.queryByLabelText('Vollständiger Fingerprint')).not.toBeInTheDocument()
  expect(revocation.queryByRole('img')).not.toBeInTheDocument()
  // Ohne Fingerprint-Schritt ist die ERSTE Handlung die Autorisierung. Neben ihr
  // stehen „Wirkung prüfen" und der Beginn-Knopf — je Schritt also drei Knoepfe.
  expect(revocation.getByRole('button', { name: 'Neu anmelden und autorisieren' })).toBeVisible()
  expect(revocation.getAllByRole('button')).toHaveLength(3)

  await user.click(revocation.getByRole('button', { name: 'Neu anmelden und autorisieren' }))
  await waitFor(() => {
    expect(heading()).toHaveTextContent(/Schritt 2 von 5: Admin-Autorisierung erteilt/)
  })
  expect(revocation.getAllByRole('button')).toHaveLength(3)

  await user.click(revocation.getByRole('button', { name: 'Root-Anfrage exportieren' }))
  await waitFor(() => {
    expect(heading()).toHaveTextContent(/Schritt 3 von 5: Root-Anfrage exportiert/)
  })
  expect(revocation.getAllByRole('button')).toHaveLength(3)

  await user.click(revocation.getByRole('button', { name: 'Root-Antwort importieren' }))
  await waitFor(() => {
    expect(heading()).toHaveTextContent(/Schritt 4 von 5: Root-Antwort importiert/)
  })
  expect(revocation.getAllByRole('button')).toHaveLength(3)

  await user.click(revocation.getByRole('button', { name: 'Neu anmelden und veröffentlichen' }))
  await waitFor(() => {
    expect(heading()).toHaveTextContent(/Schritt 5 von 5/)
  })
  expect(revocation.getAllByRole('button')).toHaveLength(2)
  expect(bridge.reauthenticate).toHaveBeenCalledTimes(2)
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
  expect(policy.getByText('3650 d 0 h')).toBeVisible()
  expect(policy.getByText('nicht zugelassen')).toBeVisible()
  expect(policy.getByText(/Root-signiertes .*policyChange/)).toBeVisible()
  await user.click(policy.getByRole('button', { name: 'Richtlinienänderung vorbereiten' }))
  expect(bridge.beginCeremony).toHaveBeenCalledWith(expect.any(String), 'PolicyChange')
  const heading = () => policy.getByRole('heading', { level: 4 })
  await waitFor(() => {
    expect(heading()).toHaveTextContent(/Schritt 1 von 5/)
  })
  expect(heading()).toHaveFocus()
  expect(policy.queryByText('Fingerprint bestätigt')).not.toBeInTheDocument()
  expect(policy.queryByRole('img')).not.toBeInTheDocument()
  // Je Schritt GENAU eine Handlung neben „Richtlinienänderung vorbereiten".
  expect(policy.getAllByRole('button')).toHaveLength(2)

  await user.click(policy.getByRole('button', { name: 'Neu anmelden und autorisieren' }))
  await waitFor(() => {
    expect(heading()).toHaveTextContent(/Schritt 2 von 5: Admin-Autorisierung erteilt/)
  })
  expect(policy.getAllByRole('button')).toHaveLength(2)

  await user.click(policy.getByRole('button', { name: 'Root-Anfrage exportieren' }))
  await waitFor(() => {
    expect(heading()).toHaveTextContent(/Schritt 3 von 5: Root-Anfrage exportiert/)
  })
  expect(policy.getAllByRole('button')).toHaveLength(2)

  await user.click(policy.getByRole('button', { name: 'Root-Antwort importieren' }))
  await waitFor(() => {
    expect(heading()).toHaveTextContent(/Schritt 4 von 5: Root-Antwort importiert/)
  })
  expect(policy.getAllByRole('button')).toHaveLength(2)

  await user.click(policy.getByRole('button', { name: 'Neu anmelden und veröffentlichen' }))
  await waitFor(() => {
    expect(heading()).toHaveTextContent(/Schritt 5 von 5/)
  })
  expect(policy.getAllByRole('button')).toHaveLength(1)
})

it('opens the exact persisted writer round after preparing, without deriving a new round from a writer hash', async () => {
  const id = 'saved-writer-issue-round'
  const bridge = fakeAdminBridge({
    prepareWriterTransition: vi.fn(async () => ({ ...noTransition(), phase: 'Prepared' as const, ceremonyId: id })),
    readCeremony: vi.fn(async () => ({ ...ceremony('WriterTransition', 'PendingRequest'), ceremonyId: id, round: 'IssueTarget' as const })),
  })
  render(<AdminPage bridge={bridge} />)
  const region = ceremonyRegion('Writer-Wechsel')
  await user.type(region.getByLabelText('Wechselanfrage (JSON)'), '{{"request":"exact"}')
  await user.click(region.getByRole('button', { name: 'Wechsel vorbereiten' }))
  await user.click(await region.findByRole('button', { name: 'Gespeicherte Root-Runde öffnen' }))
  expect(bridge.readCeremony).toHaveBeenCalledWith(id)
  expect(bridge.beginCeremony).not.toHaveBeenCalled()
  expect(bridge.activateWriterTransition).not.toHaveBeenCalled()
  expect(activeWordNodes()).toHaveLength(0)
  expect(region.queryByRole('button', { name: 'Neu anmelden und aktivieren' })).not.toBeInTheDocument()
  await waitFor(() => expect(region.getByRole('heading', { level: 4 })).toHaveTextContent('Writer-Wechsel'))
})

it('refreshes the native writer state after publishing and exposes the saved activation round', async () => {
  const issue = 'writer-issue'
  const activation = 'writer-activation'
  const initial = { ...noTransition(), phase: 'Prepared' as const, ceremonyId: issue }
  const bridge = fakeAdminBridge({
    writerTransition: initial,
    readCeremony: vi.fn(async (id) => ({ ...ceremony('WriterTransition', 'RootReplyImported'), ceremonyId: id, round: 'IssueTarget' as const })),
    publish: vi.fn(async () => ({ ...ceremony('WriterTransition', 'TargetPublished'), ceremonyId: issue, round: 'IssueTarget' as const, linkedCeremonyId: activation })),
    readWriterTransition: vi.fn(async () => ({ ...initial, ceremonyId: activation })),
  })
  render(<AdminPage bridge={bridge} />)
  const region = ceremonyRegion('Writer-Wechsel')
  await user.click(region.getByRole('button', { name: 'Gespeicherte Root-Runde öffnen' }))
  await user.click(await region.findByRole('button', { name: 'Neu anmelden und veröffentlichen' }))
  await waitFor(() => expect(bridge.readWriterTransition).toHaveBeenCalledTimes(1))
  await user.click(region.getByRole('button', { name: 'Gespeicherte Root-Runde öffnen' }))
  expect(bridge.readCeremony).toHaveBeenLastCalledWith(activation)
  expect(bridge.beginCeremony).not.toHaveBeenCalled()
})

it('shows an activated native writer transition without starting another root round', () => {
  const bridge = fakeAdminBridge({ writerTransition: { ...noTransition(), phase: 'Activated', ceremonyId: null } })
  render(<AdminPage bridge={bridge} />)
  const region = ceremonyRegion('Writer-Wechsel')
  expect(region.getByText('Writer-Wechsel im signierten Registry-Stand wirksam')).toBeVisible()
  expect(region.queryByRole('button')).not.toBeInTheDocument()
  expect(region.queryByText(/noch nicht veröffentlicht/)).not.toBeInTheDocument()
})

it('resumes an existing policy round after reopening without creating or authorizing another round', async () => {
  const saved = { ...ceremony('PolicyChange', 'RootRequestExported', 'root-anfrage.json'), ceremonyId: 'saved-policy' }
  const bridge = fakeAdminBridge({
    openCeremonies: [saved],
    readCeremony: vi.fn(async () => saved),
    readOpenCeremonies: vi.fn(async () => [saved]),
  })
  render(<AdminPage bridge={bridge} />)
  const stored = ceremonyRegion('Gespeicherte Root-Runden')
  await user.click(stored.getByRole('button', { name: 'Richtlinienänderung – saved-policy öffnen' }))
  expect(bridge.readCeremony).toHaveBeenCalledWith('saved-policy')
  expect(bridge.beginCeremony).not.toHaveBeenCalled()
  expect(bridge.reauthenticate).not.toHaveBeenCalled()
  expect(bridge.authorize).not.toHaveBeenCalled()
  const policy = ceremonyRegion('Richtlinie')
  await waitFor(() => expect(policy.getByRole('heading', { level: 4 })).toHaveTextContent('Root-Anfrage exportiert'))
  expect(policy.getByRole('heading', { level: 4 })).toHaveFocus()
  expect(policy.getByRole('button', { name: 'Root-Antwort importieren' })).toBeVisible()
})

it('keeps a previously read round visible and shows a failed refresh instead of claiming there are no open rounds', async () => {
  const saved = { ...ceremony('DeviceRevoke', 'AdminAuthorized'), ceremonyId: 'saved-revocation' }
  const bridge = fakeAdminBridge({ openCeremonies: [saved], readOpenCeremonies: vi.fn(async () => { throw { code: 'EA-ADMINISTRATION-STALE' } }) })
  render(<AdminPage bridge={bridge} />)
  const stored = ceremonyRegion('Gespeicherte Root-Runden')
  await user.click(stored.getByRole('button', { name: 'Gespeicherte Runden neu lesen' }))
  expect(await stored.findByRole('alert')).toHaveTextContent('EA-ADMINISTRATION-STALE')
  expect(stored.getByRole('button', { name: 'Widerruf – saved-revocation öffnen' })).toBeVisible()
  expect(stored.queryByText('Keine offenen Root-Runden vorhanden.')).not.toBeInTheDocument()
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

it('renders the ten administration regions in order and no incident content', () => {
  render(<AdminPage bridge={fakeAdminBridge()} />)
  const regions = screen.getAllByRole('region').map((region) => region.getAttribute('aria-label'))
  expect(regions).toEqual([
    'Go-live-Status',
    'Gespeicherte Root-Runden',
    'Geräteanfragen',
    'Registry',
    'Archiv-Sperre',
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

// Eine Antwort AUSSERHALB des Kontrakts schliesst die Flaeche genauso — aber
// die Schale erfindet dafuer keinen Wirtscode und sagt auch nicht, der Wirt
// habe keinen genannt: sie nennt die Grenze, an der sie abgelehnt hat.
it('names a contract violation in words and shows no surface', async () => {
  let violation: unknown = null
  try {
    validateChecklist({ requirements: [], productionReady: 'ja' })
  } catch (error) {
    violation = error
  }
  expect(violation).not.toBeNull()
  render(<AdminSurface connect={() => Promise.reject(violation)} />)
  await waitFor(() => {
    expect(screen.getByRole('alert')).toHaveTextContent('Antwort außerhalb des Kontrakts')
  })
  expect(screen.getByRole('alert')).not.toHaveTextContent('keinen Fehlercode')
  expect(screen.queryByRole('region')).not.toBeInTheDocument()
})

// Ein Fehler OHNE Code und ohne Kontraktnamen bleibt, was er ist: ein Fehler,
// dessen Code fehlt — kein erfundener.
it('says that the code is missing for a bare error', async () => {
  render(<AdminSurface connect={() => Promise.reject(new Error('kaputt'))} />)
  await waitFor(() => {
    expect(screen.getByRole('alert')).toHaveTextContent('Der Wirt hat keinen Fehlercode genannt.')
  })
})

it('names the twenty host commands once each', () => {
  const names = Object.values(ADMIN_COMMANDS)
  expect(names).toHaveLength(20)
  expect(new Set(names).size).toBe(20)
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


it('offers the read-only archive lock diagnosis only after the explicit button press', async () => {
  const diagnoseWriterLock = vi.fn(async () => 'AbandonedInert' as const)
  render(<AdminPage bridge={fakeAdminBridge({ diagnoseWriterLock })} />)
  expect(diagnoseWriterLock).not.toHaveBeenCalled()
  const region = within(screen.getByRole('region', { name: 'Archiv-Sperre' }))
  await user.click(region.getByRole('button', { name: 'Archiv-Sperre prüfen' }))
  expect(await region.findByRole('status')).toHaveTextContent('Keine aktive Schreibsperre festgestellt.')
  expect(diagnoseWriterLock).toHaveBeenCalledTimes(1)
})
