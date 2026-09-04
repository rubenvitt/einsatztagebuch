import { fireEvent, render, screen, within } from '@testing-library/react'
import { Tag } from 'antd'
import { expect, it, vi } from 'vitest'

import type {
  ChainIntegrityNodeView,
  ReaderAmendmentThreadView,
  ReaderEntryView,
  ReaderSearchHitView,
  ReaderStandView,
  ReaderTechnicalView,
} from '../../bridge/generated-contracts'
import {
  ENTRY_STATUS_VALUES,
  SERVER_CONFIRMATION_V1_VALUES,
  VERIFICATION_STATUS_VALUES,
} from '../../bridge/generated-contracts'
import type { ReaderBridge } from '../../bridge/reader-bridge'
import { userEvent } from '../../test-setup'
import { formatOccurredAt } from './EntryView'
import { ReaderPage } from './ReaderPage'

// Jeder Statuswortlaut wird aus der GENERIERTEN Kontraktdatei gelesen und
// nirgends abgeschrieben. Eine Testdatei DARF ihn nennen —
// `bridge/no-hand-written-contracts.test.ts` nimmt `.test.tsx?` aus —, aber
// die Disziplin bleibt dieselbe wie in der Flaeche: der Index in die
// `*_VALUES`-Tabelle ist die einzige Verbindung zum Literal.
const [VERIFIED, GAP, MISSING_GRANT, , , INVALID] = VERIFICATION_STATUS_VALUES
const [PRESENT] = ENTRY_STATUS_VALUES
const [SERVER_CONFIRMED, NOT_SERVER_CONFIRMED] = SERVER_CONFIRMATION_V1_VALUES

/** Ein 64-stelliger Hex-Hash aus EINEM Zeichen — lesbar und eindeutig. */
function hash(fill: string): string {
  return fill.repeat(64)
}

function verifiedNode(label: string): ChainIntegrityNodeView {
  return { label, verified: true, detail: null }
}

const FOUR_VERIFIED_NODES: readonly ChainIntegrityNodeView[] = [
  verifiedNode('Manifestformat'),
  verifiedNode('Root und Trust'),
  verifiedNode('Manifestsignatur'),
  verifiedNode('Kette'),
]

/** Ein verifizierter, entschluesselter Eintrag — der Regelfall des Datei-Modus. */
function decryptedEntry(): ReaderEntryView {
  return {
    state: {
      entryHash: hash('a'),
      objectHash: hash('b'),
      sequence: 7,
      verification: VERIFIED,
      entryState: PRESENT,
      serverConfirmation: NOT_SERVER_CONFIRMED,
      detailCode: null,
    },
    incident: {
      incidentNumber: '2026-0007',
      occurredAtStartMs: Date.UTC(2026, 2, 1, 7, 30),
      timezone: 'Europe/Berlin',
      keyword: 'Brand 2',
    },
  }
}

/** Ein verifizierter Eintrag OHNE eigenen Grant: technisch da, fachlich leer. */
function missingGrantEntry(): ReaderEntryView {
  return {
    state: {
      entryHash: hash('c'),
      objectHash: hash('d'),
      sequence: 12,
      verification: MISSING_GRANT,
      entryState: PRESENT,
      serverConfirmation: NOT_SERVER_CONFIRMED,
      detailCode: null,
    },
    incident: null,
  }
}

function stand(overrides: Partial<ReaderStandView> = {}): ReaderStandView {
  return {
    entries: [decryptedEntry()],
    problems: [],
    chain: FOUR_VERIFIED_NODES,
    fullyVerified: true,
    serverConfirmation: NOT_SERVER_CONFIRMED,
    ...overrides,
  }
}

function technical(overrides: Partial<ReaderTechnicalView> = {}): ReaderTechnicalView {
  return {
    sequence: 7,
    previousEntryHash: hash('e'),
    entryHash: hash('a'),
    ciphertextHash: hash('f'),
    writerCertificateHash: hash('1'),
    registryVersion: 3,
    registryHeadHash: hash('2'),
    serverConfirmation: NOT_SERVER_CONFIRMED,
    evidenceDetailCode: null,
    ...overrides,
  }
}

/**
 * Die Klasse, die antd 6 fuer EINE Farbklasse der Marke wirklich ausgibt —
 * gemessen und nicht angenommen, damit ein `not.toMatch` unten nicht gruen
 * laeuft, weil es nach einer Klasse fragt, die es gar nicht gibt.
 */
function tagClassFor(color: 'success' | 'error'): string {
  const { container, unmount } = render(<Tag color={color}>Sonde</Tag>)
  const className = container.querySelector('.ant-tag')?.className ?? ''
  unmount()
  return className
}

/**
 * Das Doppel der Bruecke. Es kennt den Bestand, den es liefert, und sonst
 * nichts: `entryView` schlaegt im Bestand nach, `search` liefert, was der
 * Zeuge hineingibt, und `amendmentThread` ist ohne Faden `null`.
 */
function fakeBridge(
  view: ReaderStandView | null,
  overrides: Partial<ReaderBridge> = {},
): ReaderBridge {
  return {
    standView: vi.fn(async () => view),
    entryView: vi.fn(async (entryHash: string) => {
      const found = view?.entries.find(entry => entry.state.entryHash === entryHash)
      if (found === undefined) {
        throw new Error('EA-READER-VIEW-UNKNOWN-ENTRY')
      }
      return found
    }),
    technicalView: vi.fn(async () => technical()),
    amendmentThread: vi.fn(async () => null),
    search: vi.fn(async (): Promise<readonly ReaderSearchHitView[]> => []),
    closeStand: vi.fn(async () => undefined),
    ...overrides,
  }
}

function bridgeWithMissingGrant(): ReaderBridge {
  return fakeBridge(stand({ entries: [missingGrantEntry()], fullyVerified: false }))
}

function bridgeWithInvalidObject(): ReaderBridge {
  return fakeBridge(
    stand({
      problems: [
        {
          objectHash: hash('9'),
          verification: INVALID,
          detailCode: 'EA-VERIFY-DECRYPT-CEK-UNWRAP-FAILED',
        },
      ],
      fullyVerified: false,
    }),
  )
}

function bridgeInFileMode(): ReaderBridge {
  return fakeBridge(stand())
}

function bridgeWithFourVerifiedNodes(): ReaderBridge {
  return fakeBridge(stand({ chain: FOUR_VERIFIED_NODES }))
}

it('shows missing grant technically without rendering an empty incident', async () => {
  render(<ReaderPage bridge={bridgeWithMissingGrant()} />)
  expect(await screen.findByText(MISSING_GRANT)).toBeVisible()
  expect(screen.getByText(/Sequenz 12/)).toBeVisible()
  expect(screen.getByText(/[0-9a-f]{16}/)).toBeVisible()
  expect(screen.queryByRole('heading', { name: /Einsatznummer/ })).not.toBeInTheDocument()
  expect(screen.queryByRole('article', { name: /Einsatz/ })).not.toBeInTheDocument()
})

it('keeps invalid objects in Prüfprobleme and opens none of them as an incident', async () => {
  const user = userEvent.setup()
  render(<ReaderPage bridge={bridgeWithInvalidObject()} />)
  await screen.findByRole('tab', { name: 'Prüfprobleme' })
  expect(screen.queryByText(INVALID)).not.toBeInTheDocument()
  await user.click(screen.getByRole('tab', { name: 'Prüfprobleme' }))
  expect(screen.getByText(INVALID)).toBeVisible()
  expect(screen.getByText('EA-VERIFY-DECRYPT-CEK-UNWRAP-FAILED')).toBeVisible()
  // Kein Einsatz und keine Schaltflaeche, die einen oeffnete.
  const problems = screen.getByRole('region', { name: 'Prüfprobleme' })
  expect(within(problems).queryByRole('article')).not.toBeInTheDocument()
  expect(within(problems).queryByRole('button')).not.toBeInTheDocument()
  expect(within(problems).queryByRole('heading', { name: /Einsatznummer/ })).not.toBeInTheDocument()
})

// Die zwei Dimensionen aus design.md §17.4. Der Regelfall des Datei-Modus ist
// `verifiziert` UND `nicht server-bestätigt`; wer sie zusammenfaltet, macht aus
// dem Regelfall einen Mangel.
//
// ABWEICHUNG vom Planwortlaut, benannt: der Eintrag traegt DREI Statustraeger
// (Verifikation, Eintragszustand, Server-Bestaetigung), also ist
// `within(entry).getByRole('status')` mehrdeutig. Gefragt wird deshalb nach
// dem Traeger mit dem zugaenglichen Namen „Server-Bestätigung" — genau der,
// dessen Beschreibung „kein Mangel" tragen muss.
it('renders verification and server confirmation as two independent dimensions', async () => {
  render(<ReaderPage bridge={bridgeInFileMode()} />)
  const entry = await screen.findByRole('article', { name: /Einsatz 2026-0007/ })
  // Der Reiter, in dem der Eintrag steht, ist benannt und nicht nur da.
  expect(screen.getByRole('tab', { name: 'Einsätze' })).toBeVisible()
  expect(within(entry).getByText(VERIFIED)).toBeVisible()
  expect(within(entry).getByText(NOT_SERVER_CONFIRMED)).toBeVisible()
  for (const defect of [GAP, INVALID]) {
    expect(within(entry).queryByText(defect)).not.toBeInTheDocument()
  }
  const confirmation = within(entry).getByRole('status', { name: 'Server-Bestätigung' })
  expect(confirmation).toHaveTextContent(NOT_SERVER_CONFIRMED)
  expect(confirmation).toHaveAccessibleDescription(expect.stringContaining('kein Mangel'))
  // design.md §17.4: „nicht server-bestätigt" ist NIE als Fehler gestaltet.
  // Erst die Sonde — antd 6 gibt fuer `color="error"` wirklich `ant-tag-error`
  // aus —, dann die Zusicherung gegen genau diese Klasse.
  expect(tagClassFor('error')).toMatch(/\bant-tag-error\b/)
  expect(confirmation.className).not.toMatch(/\bant-tag-error\b/)
  // Der Verifikationstraeger ist ein ANDERES Element und traegt den anderen Wert.
  const verification = within(entry).getByRole('status', { name: 'Verifikation' })
  expect(verification).not.toBe(confirmation)
  expect(verification).toHaveTextContent(VERIFIED)
  expect(verification).not.toHaveTextContent(NOT_SERVER_CONFIRMED)
})

// Die Leiste ist kein Fortschrittsbalken. Ein Knoten, den niemand gemeldet hat,
// wird nicht erfunden.
it('renders only the chain nodes the bridge actually reported', async () => {
  render(<ReaderPage bridge={bridgeWithFourVerifiedNodes()} />)
  const rail = await screen.findByRole('region', { name: 'Integritätskette' })
  expect(within(rail).getAllByRole('listitem')).toHaveLength(4)
  expect(within(rail).queryByText('nicht geprüft')).not.toBeInTheDocument()
})

it('carries every status in text and not in colour or icon alone', async () => {
  render(<ReaderPage bridge={bridgeWithMissingGrant()} />)
  const statuses = await screen.findAllByRole('status')
  expect(statuses.length).toBeGreaterThan(0)
  for (const node of statuses) {
    expect(node.textContent?.trim().length ?? 0).toBeGreaterThan(0)
  }
})

// Die Suche RECHNET nichts: die vier Filter gehen so an die Bruecke, wie sie
// getippt wurden, und die Trefferliste ist genau die Antwort der Bruecke — in
// ihrer Reihenfolge, ohne Auslese.
it('hands the four filters unchanged to the bridge and lists only what it returned', async () => {
  const user = userEvent.setup()
  const hits: readonly ReaderSearchHitView[] = [
    { entryHash: hash('a'), sequence: 7, incidentNumber: '2026-0007', occurredAtStartMs: 1_000 },
    { entryHash: hash('3'), sequence: 3, incidentNumber: '2026-0003', occurredAtStartMs: 500 },
  ]
  const bridge = fakeBridge(stand(), { search: vi.fn(async () => hits) })
  render(<ReaderPage bridge={bridge} />)
  await screen.findByRole('article', { name: /Einsatz 2026-0007/ })

  // Die Zeitgrenzen werden in der Zone des LESEGERAETS getippt — und die
  // Flaeche sagt das, statt es den Nutzer raten zu lassen.
  const zone = Intl.DateTimeFormat().resolvedOptions().timeZone
  expect(screen.getByLabelText('Von')).toHaveAccessibleDescription(expect.stringContaining(zone))
  expect(screen.getByLabelText('Bis')).toHaveAccessibleDescription(expect.stringContaining(zone))
  expect(screen.getByText(/Zeitzone dieses Geräts/)).toBeVisible()

  const from = '2026-03-01T08:00'
  const to = '2026-03-02T20:15'
  fireEvent.change(screen.getByLabelText('Von'), { target: { value: from } })
  fireEvent.change(screen.getByLabelText('Bis'), { target: { value: to } })
  await user.type(screen.getByLabelText('Stichwort'), 'Brand')
  await user.type(screen.getByLabelText('Fahrzeug'), 'RTW 1')
  await user.type(screen.getByLabelText('Person'), 'Muster')
  await user.click(screen.getByRole('button', { name: 'Suchen' }))

  expect(bridge.search).toHaveBeenCalledTimes(1)
  expect(bridge.search).toHaveBeenCalledWith({
    fromMs: new Date(from).getTime(),
    toMs: new Date(to).getTime(),
    keyword: 'Brand',
    vehicle: 'RTW 1',
    person: 'Muster',
  })
  const results = await screen.findByRole('list', { name: 'Suchergebnisse' })
  const items = within(results).getAllByRole('listitem')
  expect(items).toHaveLength(2)
  expect(items[0]).toHaveTextContent('2026-0007')
  expect(items[1]).toHaveTextContent('2026-0003')
})

// Ohne Bestand gibt es KEINEN leeren Einsatz — nur den technischen Zustand und
// den Weg zum Oeffnen.
it('names the missing stand technically and renders no incident at all', async () => {
  render(<ReaderPage bridge={fakeBridge(null)} />)
  expect(await screen.findByText('Kein Bestand geöffnet')).toBeVisible()
  // Der Satz steht IM Pruefstand, und der Pruefstand meldet seinen Wechsel
  // von „wird gelesen" zu dieser Aussage — hoeflich, ohne zu unterbrechen.
  const region = screen.getByRole('region', { name: 'Prüfstand' })
  expect(region).toHaveTextContent('Kein Bestand geöffnet')
  expect(region).toHaveAttribute('aria-live', 'polite')
  expect(screen.getByRole('link', { name: /Datei-Modus/ })).toHaveAttribute('href', '/datei')
  expect(screen.queryByRole('article')).not.toBeInTheDocument()
  expect(screen.queryByRole('heading', { name: /Einsatznummer/ })).not.toBeInTheDocument()
  expect(screen.queryByRole('tab')).not.toBeInTheDocument()
})

// Original und Nachtrag sind ZWEI Ansichten desselben Zusammenhangs. Das
// Original bleibt stehen, wird nicht als ueberholt markiert, und der
// abgewiesene Nachtrag steht mit seinem Grund daneben.
it('shows original and amendments as separate views and hides neither', async () => {
  const user = userEvent.setup()
  const amendment: ReaderEntryView = {
    state: { ...decryptedEntry().state, entryHash: hash('5'), sequence: 9 },
    incident: { ...decryptedEntry().incident!, incidentNumber: '2026-0007-N1' },
  }
  const thread: ReaderAmendmentThreadView = {
    original: decryptedEntry(),
    amendments: [amendment],
    rejected: [{ entryHash: hash('6'), sequence: 10, reason: 'EA-AMEND-ORIGINAL-MISMATCH' }],
  }
  const bridge = fakeBridge(stand(), { amendmentThread: vi.fn(async () => thread) })
  render(<ReaderPage bridge={bridge} />)
  await screen.findByRole('article', { name: /Einsatz 2026-0007/ })
  await user.click(screen.getByRole('button', { name: 'Eintrag öffnen' }))

  const region = await screen.findByRole('region', { name: 'Nachtragszusammenhang' })
  expect(bridge.amendmentThread).toHaveBeenCalledWith(hash('a'))
  expect(within(region).getByRole('heading', { name: 'Original' })).toBeVisible()
  expect(within(region).getByRole('heading', { name: 'Nachträge' })).toBeVisible()
  expect(within(region).getByRole('article', { name: 'Einsatz 2026-0007' })).toBeVisible()
  expect(within(region).getByRole('article', { name: 'Einsatz 2026-0007-N1' })).toBeVisible()
  expect(within(region).getByText('EA-AMEND-ORIGINAL-MISMATCH')).toBeVisible()
  expect(within(region).queryByText(/überholt/)).not.toBeInTheDocument()
})

// Die technische Ansicht liest jeden Wert aus dem DTO und erklaert ihn — und
// die Server-Bestaetigung bleibt auch hier eine eigene Dimension.
it('explains every technical field from the DTO in the Technik tab', async () => {
  const user = userEvent.setup()
  const bridge = fakeBridge(stand())
  render(<ReaderPage bridge={bridge} />)
  await user.click(await screen.findByRole('tab', { name: 'Technik' }))
  await user.click(screen.getByRole('button', { name: /Sequenz 7/ }))

  const view = await screen.findByRole('region', { name: 'Technische Ansicht' })
  expect(bridge.technicalView).toHaveBeenCalledWith(hash('a'))
  for (const value of [hash('e'), hash('a'), hash('f'), hash('1'), hash('2')]) {
    expect(within(view).getByText(value)).toBeVisible()
  }
  expect(within(view).getByText(/Registry-Version 3/)).toBeVisible()
  expect(within(view).getByRole('status', { name: 'Server-Bestätigung' })).toHaveTextContent(
    NOT_SERVER_CONFIRMED,
  )
  // Ohne Evidence-Befund steht das auch so da: keine Beanstandung — und keine
  // Stufe, denn eine Stufe hat niemand festgestellt.
  const evidence = within(view).getByRole('status', { name: 'Evidence-Prüfung' })
  expect(evidence).toHaveTextContent('keine Beanstandung im Verifikationslauf')
  expect(evidence.className).not.toMatch(/\bant-tag-success\b/)
  expect(within(view).queryByText(/Evidenzstufe/)).not.toBeInTheDocument()
  expect(within(view).queryByText('nicht gemeldet')).not.toBeInTheDocument()
  expect(within(view).queryByText(SERVER_CONFIRMED)).not.toBeInTheDocument()
})

// Ein Evidence-BEFUNDCODE ist ein Befund und keine Stufe. Vor dieser
// Zusicherung landete der Code in `EvidenceStatus`, dessen nicht-`null`-Zweig
// eine gruene Marke mit „verified"-Zeichen unter „Evidenzstufe" rendert — ein
// Befund der Pruefung als bestandene Stufe.
it('shows an evidence finding code as a finding and never as a passed grade', async () => {
  const user = userEvent.setup()
  const code = 'EA-VERIFY-EVIDENCE-SUBJECT-MISMATCH'
  const bridge = fakeBridge(stand(), {
    technicalView: vi.fn(async () => technical({ evidenceDetailCode: code })),
  })
  render(<ReaderPage bridge={bridge} />)
  await user.click(await screen.findByRole('tab', { name: 'Technik' }))
  await user.click(screen.getByRole('button', { name: /Sequenz 7/ }))

  const view = await screen.findByRole('region', { name: 'Technische Ansicht' })
  const evidence = within(view).getByRole('status', { name: 'Evidence-Prüfung' })
  expect(evidence).toHaveTextContent(code)
  expect(evidence).toHaveAccessibleDescription(expect.stringContaining('Befund'))
  // Erst die Sonde, dann die Zusicherung: keine Erfolgsmarke in dieser Zeile.
  expect(tagClassFor('success')).toMatch(/\bant-tag-success\b/)
  expect(evidence.className).not.toMatch(/\bant-tag-success\b/)
  const row = evidence.parentElement
  expect(row).not.toBeNull()
  expect(row?.querySelector('.ant-tag-success')).toBeNull()
  expect(within(view).queryByText(/Evidenzstufe/)).not.toBeInTheDocument()
  expect(within(view).queryByText(/keine Beanstandung/)).not.toBeInTheDocument()
})

// Der permanente Pruefstand traegt sein Urteil als STATUS — bisher stand es
// als blosser Text da, und wer die Zusammenfassung entfernte, liess jeden
// Zeugen gruen.
it('carries the stand judgement and its server confirmation as statuses in the live Prüfstand', async () => {
  render(<ReaderPage bridge={bridgeInFileMode()} />)
  const region = screen.getByRole('region', { name: 'Prüfstand' })
  expect(region).toHaveAttribute('aria-live', 'polite')
  const judgement = await within(region).findByRole('status', { name: 'Prüfstand' })
  expect(judgement).toHaveTextContent('Alle Prüfungen bestanden')
  expect(within(region).getByRole('status', { name: 'Server-Bestätigung' })).toHaveTextContent(
    NOT_SERVER_CONFIRMED,
  )
  expect(within(region).getByText(/1 Einträge, 0 Prüfprobleme/)).toBeVisible()
})

it('names a stand with a finding as such in the Prüfstand status', async () => {
  render(<ReaderPage bridge={bridgeWithInvalidObject()} />)
  const region = screen.getByRole('region', { name: 'Prüfstand' })
  const judgement = await within(region).findByRole('status', { name: 'Prüfstand' })
  expect(judgement).toHaveTextContent('Prüfung mit Befund')
  expect(judgement).not.toHaveTextContent('Alle Prüfungen bestanden')
})

// Eine Abweisung beim Montieren ist eine ANTWORT. Bisher blieb „Der Bestand
// wird gelesen." neben dem Alarm stehen — die Flaeche behauptete Lesen und
// Fehlschlag zugleich.
it('replaces the loading sentence with the rejection when the bridge refuses the stand', async () => {
  const bridge = fakeBridge(null, {
    standView: vi.fn(async () => {
      throw new Error('EA-READER-VIEW-NO-STAND')
    }),
  })
  render(<ReaderPage bridge={bridge} />)
  const alert = await screen.findByRole('alert')
  expect(alert).toHaveTextContent('EA-READER-VIEW-NO-STAND')
  expect(screen.queryByText('Der Bestand wird gelesen.')).not.toBeInTheDocument()
  // Und keine Behauptung, die die Bruecke nicht gemacht hat: weder ein
  // Bestand noch „kein Bestand".
  expect(screen.queryByRole('article')).not.toBeInTheDocument()
  expect(screen.queryByText('Kein Bestand geöffnet')).not.toBeInTheDocument()
  const region = screen.getByRole('region', { name: 'Prüfstand' })
  expect(region.textContent?.trim().length ?? 0).toBeGreaterThan(0)
})

// Ein Zeitpunkt, den `Date` nicht tragen kann, ist kein `RangeError` auf der
// Flaeche, sondern ein Satz.
it('renders an unrepresentable occurredAt as plain text instead of throwing', () => {
  for (const ms of [Number.NaN, Number.POSITIVE_INFINITY, 1e20]) {
    expect(formatOccurredAt(ms, 'Europe/Berlin')).toBe('Zeitpunkt nicht darstellbar')
  }
  // Und ein tragbarer Zeitpunkt bleibt, was er war.
  expect(formatOccurredAt(Date.UTC(2026, 2, 1, 7, 30), 'Europe/Berlin')).toContain('Europe/Berlin')
})
