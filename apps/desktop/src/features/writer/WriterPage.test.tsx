import { render, screen, waitFor, within } from '@testing-library/react'
import { expect, it, vi } from 'vitest'

import { WriterPage, validatePendingResume } from './WriterPage'
import type { WriterBridge } from './WriterPage'
import {
  DETAIL_CAUSE_VALUES,
  SYNC_STATUS_VALUES,
} from '../../bridge/generated-contracts'
import type {
  DraftStateView,
  FinalizationPreviewView,
  IncidentInputView,
  PendingResumeOutcomeView,
} from '../../bridge/generated-contracts'
import { userEvent } from '../../test-setup'

const user = userEvent.setup()

/**
 * Ein Entwurf, der die Eingabezusagen der Stufe 1 ERFUELLT.
 *
 * Beide Momentaufnahmelisten sind besetzt, also verlangt die biconditionale
 * Regel `EA-SCHEMA-LIST-REASON` keine Begruendung. Das ist die Vorbedingung
 * jedes Zeugen, der eine ANDERE Blockade messen will: mit zwei leeren Listen
 * stuenden zwei Meldungen da, und `getByRole('alert')` faende mehrere Elemente.
 */
function completeIncident(): IncidentInputView {
  return {
    humanIncidentNumber: '2026-0001',
    occurredAt: { start: 1_771_000_000_000, end: null },
    keyword: { referenceId: null, displayText: 'Verkehrsunfall' },
    location: {
      freeText: 'Bahnhofstraße 1',
      address: null,
      coordinates: null,
    },
    personnel: [{ masterPersonnelId: 'P-1', displayName: 'A. Beispiel', roleLabel: 'Zugführer' }],
    personnelEmptyReason: null,
    vehicles: [
      {
        masterVehicleId: 'V-1',
        displayName: 'RTW 1',
        radioCallName: 'Rotkreuz 1/83/1',
        licensePlate: 'K-DRK 1',
      },
    ],
    vehiclesEmptyReason: null,
    patientCountStatus: 'Known',
    patientCount: 2,
    notes: null,
    externalOrganizations: [],
  }
}

function freshPreview(): FinalizationPreviewView {
  return {
    proposedSequence: 7,
    bindsPredecessor: true,
    effectiveNow: 1_771_000_100_000,
    trustAgeMs: 3_600_000,
    readerTrustRefreshMs: 7 * 24 * 60 * 60 * 1000,
    trustRefreshOverdue: false,
    staleDecision: 'Fresh',
  }
}

/**
 * Derselbe Entwurf mit ZWEI LEEREN Momentaufnahmelisten und je einer
 * Begruendung.
 *
 * Nur in diesem Zustand existieren die beiden Begruendungsfelder ueberhaupt:
 * `MasterDataSelect` zeigt sie ausschliesslich bei leerer Liste, weil die
 * biconditionale Regel `EA-SCHEMA-LIST-REASON` sie sonst verbietet.
 */
function emptyListIncident(): IncidentInputView {
  return {
    ...completeIncident(),
    personnel: [],
    personnelEmptyReason: 'kein Personal disponiert',
    vehicles: [],
    vehiclesEmptyReason: 'kein Fahrzeug alarmiert',
  }
}

function draftState(incident: IncidentInputView = completeIncident()): DraftStateView {
  const [locallySaved] = SYNC_STATUS_VALUES
  return { incident, sync: { status: locallySaved, detailCause: null } }
}

/**
 * Die Bruecke als Doppel. Jede Methode ist ein `vi.fn`, damit ein Zeuge nicht
 * nur die Ausgabe, sondern auch das ARGUMENT messen kann.
 */
function fakeWriterBridge(overrides: Partial<WriterBridge> = {}): WriterBridge {
  const [locallySaved] = SYNC_STATUS_VALUES
  return {
    draft: draftState(),
    pendingResume: null,
    saveDraft: vi.fn(() => Promise.resolve({ status: locallySaved, detailCause: null })),
    searchMasterData: vi.fn(() =>
      Promise.resolve({
        personnel: [
          { masterPersonnelId: 'P-2', displayName: 'C. Beispiel', roleLabel: null },
        ],
        vehicles: [
          {
            masterVehicleId: 'V-2',
            displayName: 'KTW 2',
            radioCallName: null,
            licensePlate: null,
          },
        ],
        personnelTotal: 2,
        vehicleTotal: 2,
      }),
    ),
    preview: vi.fn(() => Promise.resolve(freshPreview())),
    acknowledgeStaleRegistry: vi.fn(() =>
      Promise.resolve({ captured: true, proofCode: 'EA-OPERATOR-REAUTH-FINALIZE' }),
    ),
    finalize: vi.fn(() =>
      Promise.resolve({
        sequence: 7,
        entryHash: 'a'.repeat(64),
        objectHash: 'b'.repeat(64),
        sync: { status: locallySaved, detailCause: null },
      }),
    ),
    archiveHealth: vi.fn(() =>
      Promise.resolve({ healthy: true, findingCodes: [], quarantineReasons: [] }),
    ),
    devicePosture: vi.fn(() =>
      Promise.resolve({
        requirements: [
          {
            requirementCode: 'EA-POSTURE-FDE',
            satisfied: null,
            evidenceCode: 'EA-POSTURE-FDE-UNREPORTABLE',
          },
        ],
        productionReady: false,
      }),
    ),
    reauthenticate: vi.fn(() =>
      Promise.resolve({ fresh: true, purposeCode: 'EA-OPERATOR-REAUTH-FINALIZE' }),
    ),
    discardDraft: vi.fn(() => Promise.resolve({ phaseCode: 'IntentCommitted', complete: false })),
    resumeDiscard: vi.fn(() => Promise.resolve({ phaseCode: 'BlankDraftCreated', complete: true })),
    exportBundle: vi.fn(() =>
      Promise.resolve({ path: '/tmp/archiv.eab', objectCount: 12, byteCount: 4096 }),
    ),
    ...overrides,
  }
}

/** Ein Head, der WAEHREND der Bindung veraltet ist — bestaetigungsfaehig. */
function staleWarnBridge(): WriterBridge {
  return fakeWriterBridge({
    preview: vi.fn(() =>
      Promise.resolve({ ...freshPreview(), staleDecision: 'StaleAcknowledgeable' as const }),
    ),
  })
}

/** Neun Tage alter Vertrauensbestand gegen eine Frist von sieben Tagen. */
function overdueTrustBridge(): WriterBridge {
  const day = 24 * 60 * 60 * 1000
  return fakeWriterBridge({
    preview: vi.fn(() =>
      Promise.resolve({
        ...freshPreview(),
        trustAgeMs: 9 * day,
        readerTrustRefreshMs: 7 * day,
        trustRefreshOverdue: true,
      }),
    ),
  })
}

/** Eine vorbereitete Transaktion, die fortgesetzt wird. */
function preparedPendingBridge(): WriterBridge {
  const uploadPending = SYNC_STATUS_VALUES[1]
  const networkWaiting = DETAIL_CAUSE_VALUES[0]
  const pendingResume: PendingResumeOutcomeView = {
    resume: {
      phase: 'PreparedAndFlushed',
      irreversible: true,
      outcomeCode: 'CommittedFromPreparedBytes',
      outcomeSequence: 7,
    },
    blockedCode: null,
    sync: { status: uploadPending, detailCause: networkWaiting },
  }
  return fakeWriterBridge({ pendingResume })
}

/** Ein zurueckgespieltes Backup: die externe Head-Reconciliation fehlt. */
function restoredBackupBridge(): WriterBridge {
  const pendingResume: PendingResumeOutcomeView = {
    resume: {
      phase: 'PreparedAndFlushed',
      irreversible: true,
      outcomeCode: null,
      outcomeSequence: null,
    },
    blockedCode: 'EA-WRITER-HEAD-RECONCILIATION-REQUIRED',
    sync: null,
  }
  return fakeWriterBridge({ pendingResume })
}

/** Entfernt das eine Fahrzeug und laesst die Personalliste besetzt. */
async function fillMinimalIncident(): Promise<void> {
  await user.click(screen.getByRole('button', { name: 'Fahrzeug RTW 1 entfernen' }))
}

/** Von der Erfassung in die Bestaetigung, samt der Antwort des Wirts. */
async function advanceToFinalize(): Promise<void> {
  await user.click(screen.getByRole('button', { name: 'Prüfen' }))
  await waitFor(() => {
    expect(screen.getByRole('status', { name: 'Vertrauensbestand' })).toBeVisible()
  })
}

it('distinguishes known zero from unknown and blocks finalize before review confirmation', async () => {
  render(<WriterPage bridge={fakeWriterBridge()} />)
  await user.click(screen.getByRole('radio', { name: 'bekannt' }))
  await user.clear(screen.getByLabelText('Anzahl'))
  await user.type(screen.getByLabelText('Anzahl'), '0')
  await user.click(screen.getByRole('button', { name: 'Prüfen' }))
  expect(screen.getByText('0 Patienten')).toBeVisible()
  expect(screen.getByRole('button', { name: 'Unwiderruflich finalisieren' })).toBeDisabled()
  await user.click(screen.getByRole('checkbox', { name: /unwiderruflich/i }))
  expect(screen.getByRole('button', { name: 'Unwiderruflich finalisieren' })).toBeEnabled()
  await user.click(screen.getByRole('button', { name: 'Zurück zur Erfassung' }))
  await user.click(screen.getByRole('radio', { name: 'unbekannt' }))
  await user.click(screen.getByRole('button', { name: 'Prüfen' }))
  expect(screen.queryByText('0 Patienten')).not.toBeInTheDocument()
  expect(screen.getByText('Patientenzahl unbekannt')).toBeVisible()
})

it('finalizes an incident without vehicles when a reason is given and rejects the empty list without one', async () => {
  const bridge = fakeWriterBridge()
  render(<WriterPage bridge={bridge} />)
  await fillMinimalIncident()
  await user.click(screen.getByRole('button', { name: 'Prüfen' }))
  expect(screen.getByRole('alert')).toHaveTextContent(/Begründung/i)
  expect(screen.getByRole('button', { name: 'Unwiderruflich finalisieren' })).toBeDisabled()
  await user.type(
    screen.getByLabelText('Begründung für leere Fahrzeugliste'),
    'kein Fahrzeug alarmiert',
  )
  await user.click(screen.getByRole('button', { name: 'Prüfen' }))
  expect(bridge.preview).toHaveBeenLastCalledWith(
    expect.objectContaining({ vehicles: [], vehiclesEmptyReason: 'kein Fahrzeug alarmiert' }),
  )
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()
})

it('never offers a bypass for stale Registry and obtains a signed acknowledgement only after re-auth', async () => {
  const bridge = staleWarnBridge()
  render(<WriterPage bridge={bridge} />)
  await advanceToFinalize()
  expect(screen.getByRole('alert')).toHaveTextContent(/Registry.*abgelaufen/i)
  expect(
    screen.queryByRole('button', { name: /trotzdem ohne bestätigung/i }),
  ).not.toBeInTheDocument()
  await user.click(
    screen.getByRole('button', { name: 'Warnung bestätigen und erneut authentisieren' }),
  )
  expect(bridge.acknowledgeStaleRegistry).toHaveBeenCalledTimes(1)
  expect(screen.getByText(/signierte Bestätigung erfasst/i)).toBeVisible()
})

it('shows trust age and refresh deadline as a warning without blocking finalization', async () => {
  render(<WriterPage bridge={overdueTrustBridge()} />)
  await advanceToFinalize()
  const warning = screen.getByRole('status', { name: 'Vertrauensbestand' })
  expect(warning).toHaveTextContent('Trust-Bestand 9 Tage alt')
  expect(warning).toHaveTextContent('Frist 7 Tage')
  expect(warning).toHaveTextContent('Aktualisierung erforderlich')
  await user.click(screen.getByRole('checkbox', { name: /unwiderruflich/i }))
  expect(screen.getByRole('button', { name: 'Unwiderruflich finalisieren' })).toBeEnabled()
})

it('resumes a prepared finalization and blocks a restored backup without any finalize control', async () => {
  const { rerender } = render(<WriterPage bridge={preparedPendingBridge()} />)
  expect(screen.getByRole('progressbar', { name: 'Fertigstellung läuft' })).toBeVisible()
  expect(screen.getByText('Upload ausstehend')).toBeVisible()
  expect(screen.getByText('Netzarchiv wartet')).toBeVisible()
  rerender(<WriterPage bridge={restoredBackupBridge()} />)
  expect(screen.getByRole('alert')).toHaveTextContent(/externe Head-Reconciliation ausstehend/i)
  expect(
    screen.queryByRole('button', { name: 'Unwiderruflich finalisieren' }),
  ).not.toBeInTheDocument()
})

// ---------------------------------------------------------------------------
// Zeugen, die der Brief nicht nennt — jeder deckt eine Zusage ab, die ohne ihn
// gruen bleiben koennte.
// ---------------------------------------------------------------------------

// Der Brieftest oben prueft die Blockade OHNE Begruendung. Er bliebe aber auch
// gruen, wenn das Feld IMMER sichtbar waere und die Begruendung IMMER mitginge —
// und dann verletzte jede Finalisierung mit besetzter Liste die andere Haelfte
// der biconditionalen Regel.
it('shows an empty list reason only while that list is empty and never sends it otherwise', async () => {
  const bridge = fakeWriterBridge()
  render(<WriterPage bridge={bridge} />)
  expect(screen.queryByLabelText('Begründung für leere Fahrzeugliste')).not.toBeInTheDocument()
  expect(screen.queryByLabelText('Begründung für leere Personalliste')).not.toBeInTheDocument()
  await fillMinimalIncident()
  expect(screen.getByLabelText('Begründung für leere Fahrzeugliste')).toBeVisible()
  expect(screen.queryByLabelText('Begründung für leere Personalliste')).not.toBeInTheDocument()
  await user.type(
    screen.getByLabelText('Begründung für leere Fahrzeugliste'),
    'kein Fahrzeug alarmiert',
  )
  await user.click(screen.getByRole('button', { name: 'Fahrzeug hinzufügen' }))
  expect(screen.queryByLabelText('Begründung für leere Fahrzeugliste')).not.toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Prüfen' }))
  expect(bridge.preview).toHaveBeenLastCalledWith(
    expect.objectContaining({ vehiclesEmptyReason: null }),
  )
})

// `patientCountStatus` ist am Draht `0 = unknown` und `1 = known`. Der
// Brieftest unterscheidet die ANZEIGE; dieser hier unterscheidet das ARGUMENT,
// das der Wirt bekommt — eine vertauschte Polaritaet faellt sonst niemandem auf.
it('sends the patient count status the wire demands, and null for unknown', async () => {
  const bridge = fakeWriterBridge()
  render(<WriterPage bridge={bridge} />)
  await user.click(screen.getByRole('radio', { name: 'unbekannt' }))
  await user.click(screen.getByRole('button', { name: 'Prüfen' }))
  expect(bridge.preview).toHaveBeenLastCalledWith(
    expect.objectContaining({ patientCountStatus: 'Unknown', patientCount: null }),
  )
  await user.click(screen.getByRole('button', { name: 'Zurück zur Erfassung' }))
  await user.click(screen.getByRole('radio', { name: 'bekannt' }))
  await user.clear(screen.getByLabelText('Anzahl'))
  await user.type(screen.getByLabelText('Anzahl'), '0')
  await user.click(screen.getByRole('button', { name: 'Prüfen' }))
  expect(bridge.preview).toHaveBeenLastCalledWith(
    expect.objectContaining({ patientCountStatus: 'Known', patientCount: 0 }),
  )
})

// Die Zusage „Finalisieren und Verwerfen verlangen JE eine erneute
// Authentisierung, das gewoehnliche Speichern nie". Ohne diesen Zeugen bliebe
// eine Oberflaeche gruen, in der das Speichern denselben Weg nimmt.
it('demands re-authentication for finalize and discard and never for an ordinary save', async () => {
  const bridge = fakeWriterBridge()
  render(<WriterPage bridge={bridge} />)
  await user.click(screen.getByRole('button', { name: 'Entwurf speichern' }))
  expect(bridge.saveDraft).toHaveBeenCalledTimes(1)
  expect(bridge.reauthenticate).not.toHaveBeenCalled()
  await advanceToFinalize()
  await user.click(screen.getByRole('checkbox', { name: /unwiderruflich/i }))
  await user.click(screen.getByRole('button', { name: 'Unwiderruflich finalisieren' }))
  expect(bridge.reauthenticate).toHaveBeenCalledTimes(1)
  expect(bridge.finalize).toHaveBeenCalledTimes(1)
})

// Der Nachweis wird NIE aufbewahrt: jede unwiderrufliche Handlung
// authentisiert erneut. Genau das traegt die Zusage „eine Rueckkehr aus der
// Sperre des Betriebssystems entwertet den Nachweis, also verlangt der naechste
// Versuch wieder eine Authentisierung" — eine Oberflaeche, die einen Nachweis
// zwischenspeichert, ueberlebte die Sperre.
it('never caches the session proof: every irreversible action authenticates again', async () => {
  const bridge = fakeWriterBridge()
  render(<WriterPage bridge={bridge} />)
  await user.click(screen.getByRole('button', { name: 'Entwurf verwerfen' }))
  await user.click(screen.getByRole('checkbox', { name: /entwurf unwiderruflich/i }))
  await user.click(screen.getByRole('button', { name: 'Verwerfen bestätigen' }))
  expect(bridge.reauthenticate).toHaveBeenCalledTimes(1)
  await advanceToFinalize()
  await user.click(screen.getByRole('checkbox', { name: /unwiderruflich/i }))
  await user.click(screen.getByRole('button', { name: 'Unwiderruflich finalisieren' }))
  expect(bridge.reauthenticate).toHaveBeenCalledTimes(2)
  expect(bridge.finalize).toHaveBeenCalledTimes(1)
})

// Nach dem Commit: Fingerabdruecke und Sequenz, der Sync-Zustand, und dann ein
// LEERES Formular. Kein Verlauf, kein „letzter Einsatz", kein Inhalt.
it('clears the surface after the commit and offers no history and no final content', async () => {
  render(<WriterPage bridge={fakeWriterBridge()} />)
  await advanceToFinalize()
  await user.click(screen.getByRole('checkbox', { name: /unwiderruflich/i }))
  await user.click(screen.getByRole('button', { name: 'Unwiderruflich finalisieren' }))
  await waitFor(() => {
    expect(screen.getByRole('region', { name: 'Abschluss' })).toBeVisible()
  })
  const closing = screen.getByRole('region', { name: 'Abschluss' })
  expect(closing).toHaveTextContent(SYNC_STATUS_VALUES[0])
  expect(closing).toHaveTextContent('7')
  // Hashes UND Sequenz: ohne diese zwei Zeilen zeigte der Fingerabdruck nach
  // dem unwiderruflichen Schritt nur eine Zahl.
  expect(closing).toHaveTextContent('a'.repeat(64))
  expect(closing).toHaveTextContent('b'.repeat(64))
  expect(closing).toHaveTextContent('Eintragshash')
  expect(closing).toHaveTextContent('Objekthash')
  expect(screen.getByLabelText('Einsatznummer')).toHaveValue('')
  expect(screen.queryByRole('button', { name: /verlauf|letzter einsatz|inhalt öffnen/i })).toBeNull()
})

// Der Bundle-Export steht PERMANENT und nicht hinter einer Bedingung: der
// Datei-Modus des Web-Readers ist in Safari und Firefox der einzige Weg.
it('offers the single file bundle export unconditionally', async () => {
  const bridge = fakeWriterBridge()
  render(<WriterPage bridge={bridge} />)
  const button = screen.getByRole('button', { name: 'Archiv-Bündel als Datei exportieren' })
  expect(button).toBeEnabled()
  await user.click(button)
  expect(bridge.exportBundle).toHaveBeenCalledTimes(1)
  await waitFor(() => {
    expect(screen.getByText(/12 Objekte/)).toBeVisible()
  })
})

// Verwerfen ist unwiderruflich, verlangt eine erneute Authentisierung UND eine
// eigene Bestaetigung — und ist eine andere Handhabe als das Speichern.
it('discards only after re-authentication and a separate irreversible confirmation', async () => {
  const bridge = fakeWriterBridge()
  render(<WriterPage bridge={bridge} />)
  await user.click(screen.getByRole('button', { name: 'Entwurf verwerfen' }))
  expect(bridge.discardDraft).not.toHaveBeenCalled()
  await user.click(screen.getByRole('checkbox', { name: /entwurf unwiderruflich/i }))
  await user.click(screen.getByRole('button', { name: 'Verwerfen bestätigen' }))
  expect(bridge.reauthenticate).toHaveBeenCalledTimes(1)
  expect(bridge.discardDraft).toHaveBeenCalledTimes(1)
})

// Evidence Grade, ein signiertes `block` und eine erschoepfte Lease sind KEINE
// bestaetigungsfaehigen Zustaende: dann gibt es die Handhabe gar nicht.
it('offers no finalize control at all under a hard block', async () => {
  render(
    <WriterPage
      bridge={fakeWriterBridge({
        preview: vi.fn(() =>
          Promise.resolve({ ...freshPreview(), staleDecision: 'HardBlock' as const }),
        ),
      })}
    />,
  )
  await advanceToFinalize()
  expect(screen.getByRole('alert')).toHaveTextContent(/gesperrt/i)
  expect(
    screen.queryByRole('button', { name: 'Unwiderruflich finalisieren' }),
  ).not.toBeInTheDocument()
  expect(
    screen.queryByRole('button', { name: 'Warnung bestätigen und erneut authentisieren' }),
  ).not.toBeInTheDocument()
})

// Der Bestaetigungszustand kommt AUS DER ANTWORT DES WIRTS und nicht aus einem
// Klick. Ohne diesen Zeugen zeigte die Oberflaeche eine erfasste Bestaetigung,
// die es nicht gibt — und genau das ist der heutige Stand des Kerns, dem der
// Bestaetigungspfad fehlt.
it('reports no captured acknowledgement when the host refuses one', async () => {
  const bridge = fakeWriterBridge({
    preview: vi.fn(() =>
      Promise.resolve({ ...freshPreview(), staleDecision: 'StaleAcknowledgeable' as const }),
    ),
    acknowledgeStaleRegistry: vi.fn(() =>
      Promise.reject(new Error('EA-DESKTOP-STALE-ACK-UNAVAILABLE')),
    ),
  })
  render(<WriterPage bridge={bridge} />)
  await advanceToFinalize()
  await user.click(
    screen.getByRole('button', { name: 'Warnung bestätigen und erneut authentisieren' }),
  )
  await waitFor(() => {
    expect(screen.getByText(/keine Bestätigung erfasst/i)).toBeVisible()
  })
  expect(screen.queryByText(/signierte Bestätigung erfasst/i)).not.toBeInTheDocument()
  expect(
    screen.queryByRole('button', { name: 'Unwiderruflich finalisieren' }),
  ).not.toBeInTheDocument()
})

// Die Uebersicht der Bestaetigung nennt Archivgesundheit und Geraetehaltung,
// und ein `Unknown` ist ein UNGEKLAERTER Stand und kein stilles Ja.
it('shows archive health and device posture with unknown as unresolved', async () => {
  const bridge = fakeWriterBridge()
  render(<WriterPage bridge={bridge} />)
  await advanceToFinalize()
  await waitFor(() => {
    expect(screen.getByRole('region', { name: 'Archivgesundheit' })).toBeVisible()
  })
  expect(bridge.archiveHealth).toHaveBeenCalledTimes(1)
  expect(bridge.devicePosture).toHaveBeenCalledTimes(1)
  const posture = screen.getByRole('region', { name: 'Gerätehaltung' })
  expect(posture).toHaveTextContent('EA-POSTURE-FDE')
  expect(posture).toHaveTextContent(/nicht belegbar/i)
  expect(posture).toHaveTextContent(/nicht produktionsbereit/i)
})

// Jede freie Texteingabe traegt die Warnung, dass hier keine
// identifizierenden Patientendaten stehen duerfen.
//
// Eine feste MINDESTZAHL und nicht `> 0`: mit `> 0` blieb der Zeuge gruen,
// solange irgendwo EINE Warnung stand — er konnte den Verlust der anderen nicht
// sehen. Vier sind es auf diesem Bestand, und zwar diese vier: Stichwort samt
// Referenz, Ort, Notizen und „Weitere Organisation". Die zwei
// Begruendungsfelder der leeren Listen existieren hier nicht (beide Listen sind
// besetzt) und haben ihren eigenen Zeugen darunter. Eine Gleichheit waere die
// falsche Form: ein fuenftes Freitextfeld MIT Warnung darf diesen Zeugen nicht
// rot machen, ein fehlendes Feld muss es.
const WARNED_FREE_TEXT_BLOCKS = 4

it('warns about patient data on every free text field', () => {
  render(<WriterPage bridge={fakeWriterBridge()} />)
  const warnings = screen.getAllByText(/keine identifizierenden Patientendaten/i)
  expect(warnings.length).toBeGreaterThanOrEqual(WARNED_FREE_TEXT_BLOCKS)
  for (const warning of warnings) {
    expect(warning).toBeVisible()
  }
})

// Das Begruendungsfeld der leeren Liste ist ein PERSISTIERTER Freitext: sein
// Wert reist als `personnelEmptyReason` bzw. `vehiclesEmptyReason` in der
// Nutzlast des Entwurfs und spaeter im Eintrag mit. Der Zeuge oben kann es
// nicht sehen — es existiert nur bei leerer Liste, und auf dem Bestand mit zwei
// besetzten Listen steht es nicht da.
//
// Die zweite Haelfte bindet die Warnung an GENAU dieses Feld und nicht bloss an
// den Abschnitt: das Suchfeld daneben traegt keine, weil sein Inhalt in keiner
// Nutzlast landet. Ohne diese Haelfte bliebe der Zeuge gruen, wenn die Warnung
// an das Suchfeld wanderte.
it('warns about patient data in the empty list reason of both master data sections', () => {
  const SECTIONS = ['Personal suchen', 'Fahrzeuge suchen']
  const filled = render(<WriterPage bridge={fakeWriterBridge()} />)
  for (const name of SECTIONS) {
    const section = screen.getByRole('region', { name })
    expect(within(section).queryByLabelText(/^Begründung für leere/)).toBeNull()
    expect(within(section).queryByText(/keine identifizierenden Patientendaten/i)).toBeNull()
  }
  filled.unmount()

  render(<WriterPage bridge={fakeWriterBridge({ draft: draftState(emptyListIncident()) })} />)
  for (const name of SECTIONS) {
    const section = screen.getByRole('region', { name })
    expect(within(section).getByLabelText(/^Begründung für leere/)).toBeVisible()
    expect(within(section).getByText(/keine identifizierenden Patientendaten/i)).toBeVisible()
  }
  expect(screen.getAllByText(/keine identifizierenden Patientendaten/i).length).toBeGreaterThanOrEqual(
    WARNED_FREE_TEXT_BLOCKS + SECTIONS.length,
  )
})

// Der Autospeicherzustand steht im Wortlaut da und kommt aus der emittierten
// Vereinigung — nicht aus einem Literal dieser Oberflaeche.
it('shows the autosave state from the emitted union', async () => {
  const bridge = fakeWriterBridge()
  render(<WriterPage bridge={bridge} />)
  const status = screen.getByRole('status', { name: 'Speicherzustand' })
  expect(status).toHaveTextContent(SYNC_STATUS_VALUES[0])
  await user.click(screen.getByRole('button', { name: 'Entwurf speichern' }))
  expect(bridge.saveDraft).toHaveBeenCalledTimes(1)
})

// Die Einsatznummer wird VORGESCHLAGEN und bleibt bis zum Abschluss
// bearbeitbar; die Eindeutigkeit entscheidet der Wirt und nicht die
// Oberflaeche.
it('suggests the incident number, keeps it editable, and decides no uniqueness', async () => {
  const bridge = fakeWriterBridge()
  render(<WriterPage bridge={bridge} />)
  const field = screen.getByLabelText('Einsatznummer')
  expect(field).toHaveValue('2026-0001')
  await user.clear(field)
  await user.type(field, '2026-0002')
  expect(field).toHaveValue('2026-0002')
  expect(screen.getByText(/ohne Entscheidung|entscheidet der Wirt/i)).toBeVisible()
})

// Jede Handhabe ist per Tastatur erreichbar und traegt einen zugaenglichen
// Namen. Ein Knopf ohne Namen ist fuer eine Bildschirmleseausgabe stumm.
it('gives every control an accessible name and keeps it reachable by keyboard', () => {
  render(<WriterPage bridge={fakeWriterBridge()} />)
  const controls = [
    ...screen.getAllByRole('button'),
    ...screen.getAllByRole('textbox'),
    ...screen.getAllByRole('radio'),
  ]
  expect(controls.length).toBeGreaterThan(5)
  for (const control of controls) {
    expect(control).toHaveAccessibleName()
    expect(control).not.toHaveAttribute('tabindex', '-1')
    expect(control).not.toBeDisabled()
  }
})

// Die STRENGSTE Antwort des Tasks: aus ihr entsteht die Entscheidung, ob es die
// Abschlusshandhabe ueberhaupt gibt. Ohne diesen Zeugen ginge ein ungepruefter
// Wahrheitswert aus einer Wirtsantwort direkt in die unwiderrufliche Grenze —
// und in allen Zeugen darueber kommen ausschliesslich wohlgeformte Doppel an,
// ein alles durchlassender Validierer waere also nirgends aufgefallen.
it('validates the pending finalization instead of believing it', () => {
  const [uploadPending] = [SYNC_STATUS_VALUES[1]]
  const wellFormed = {
    resume: {
      phase: 'PreparedAndFlushed',
      irreversible: true,
      outcomeCode: 'CommittedFromPreparedBytes',
      outcomeSequence: 7,
    },
    blockedCode: null,
    sync: { status: uploadPending, detailCause: DETAIL_CAUSE_VALUES[0] },
  }
  const accepted = validatePendingResume(wellFormed)
  expect(accepted.resume.irreversible).toBe(true)
  expect(accepted.blockedCode).toBeNull()
  expect(accepted.sync?.status).toBe(uploadPending)

  // Und jede Verletzung wird ABGELEHNT und nicht zurechtgebogen.
  const rejected: readonly unknown[] = [
    null,
    'nichts',
    { ...wellFormed, resume: { ...wellFormed.resume, irreversible: 'ja' } },
    { ...wellFormed, resume: { ...wellFormed.resume, phase: 'Irgendwas' } },
    { ...wellFormed, resume: undefined },
    { ...wellFormed, blockedCode: 42 },
    { ...wellFormed, sync: { status: 'erfunden', detailCause: null } },
    { ...wellFormed, sync: { status: uploadPending, detailCause: 'erfunden' } },
  ]
  for (const candidate of rejected) {
    expect(() => validatePendingResume(candidate), JSON.stringify(candidate)).toThrow()
  }
})

// Der Weg, den der Defektbefund C2 gegangen ist: Zustand „bekannt", Anzahl
// geleert. Die Anzeige sagte „Patientenzahl unbekannt", und der Draht truege
// `known, 0`. Ohne diesen Zeugen bleibt die Paarung ungeprueft, weil alle
// anderen Zeugen wohlgeformte Paare schicken.
it('blocks a known patient count without a number and asks the host for nothing', async () => {
  const bridge = fakeWriterBridge()
  render(<WriterPage bridge={bridge} />)
  await user.click(screen.getByRole('radio', { name: 'bekannt' }))
  await user.clear(screen.getByLabelText('Anzahl'))
  await user.click(screen.getByRole('button', { name: 'Prüfen' }))
  expect(screen.getByRole('alert')).toHaveTextContent(/Anzahl Pflicht/i)
  expect(bridge.preview).not.toHaveBeenCalled()
  expect(
    screen.queryByRole('button', { name: 'Unwiderruflich finalisieren' }),
  ).toBeDisabled()
  expect(screen.queryByText('0 Patienten')).not.toBeInTheDocument()
})

// Die Koordinaten sind eine EINGABE und nicht bloss eine Anzeige. Ohne diesen
// Zeugen bliebe `location.coordinates` aus der Oberflaeche immer `null`, und der
// Eingabevertrag waere unvollstaendig.
it('sends a typed coordinate pair as integer E7 values', async () => {
  const bridge = fakeWriterBridge()
  render(<WriterPage bridge={bridge} />)
  await user.type(screen.getByLabelText('Breite (E7)'), '507000000')
  await user.type(screen.getByLabelText('Länge (E7)'), '69000000')
  await user.click(screen.getByRole('button', { name: 'Prüfen' }))
  expect(bridge.preview).toHaveBeenLastCalledWith(
    expect.objectContaining({
      location: expect.objectContaining({ coordinates: { latE7: 507000000, lonE7: 69000000 } }),
    }),
  )
  // Und die Felder stehen in BEIDEN Ortsformen.
  await user.click(screen.getByRole('button', { name: 'Zurück zur Erfassung' }))
  await user.click(screen.getByRole('radio', { name: 'Ort als Adresse' }))
  expect(screen.getByLabelText('Breite (E7)')).toHaveValue(507000000)
  expect(screen.getByLabelText('Länge (E7)')).toHaveValue(69000000)
})

// Die Warnung ueber den veralteten Head nennt die Zahlen, die sie WIRKLICH hat,
// unter ihren eigenen Namen — und benennt die drei Angaben, die diese
// Ausbaustufe nicht meldet. Eine falsch benannte Zahl in einer
// sicherheitsrelevanten Warnung ist schlimmer als eine benannte Abwesenheit.
it('names the stale registry numbers correctly and declares the unreported ones', async () => {
  render(<WriterPage bridge={staleWarnBridge()} />)
  await advanceToFinalize()
  const alert = screen.getByRole('alert')
  expect(alert).toHaveTextContent('Vorgeschlagene Sequenz: 7')
  expect(alert).toHaveTextContent('beobachtete Zeit: 1771000100000')
  expect(alert).toHaveTextContent('Registry-Version: nicht gemeldet')
  expect(alert).toHaveTextContent('Registry-Head: nicht gemeldet')
  expect(alert).toHaveTextContent('Ablauf des Head: nicht gemeldet')
  expect(alert).not.toHaveTextContent('Gebundene Registry-Version: 7')
})
