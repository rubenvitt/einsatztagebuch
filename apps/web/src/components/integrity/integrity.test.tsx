import { render, screen, within } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'

import type { ChainIntegrityNodeView } from '../../bridge/generated-contracts'
import { ChainIntegrityRail } from './ChainIntegrityRail'
import { EvidenceStatus } from './EvidenceStatus'
import { FingerprintBlock } from './FingerprintBlock'
import { VerificationBadge } from './VerificationBadge'

// Die vier Integritaetsbausteine, zum ersten Mal ueberhaupt bezeugt: die
// Desktop-Vorlagen tragen keinen Zeugen und kein `role="status"`. Jede
// Zusicherung hier liest den TEXT eines Zustands — Farbe und Zeichen sind
// nach `design.md` §17.5 nie der alleinige Traeger.

/** Jedes `role="status"` im Baum traegt einen nicht leeren Wortlaut. */
function everyStatusHasText(): void {
  const statuses = screen.getAllByRole('status')
  expect(statuses.length).toBeGreaterThan(0)
  for (const node of statuses) {
    expect(node.textContent?.trim().length ?? 0).toBeGreaterThan(0)
  }
}

it('renders the three wordings of the badge, each as a status with text', () => {
  const { rerender } = render(<VerificationBadge label="Manifest" verified={true} />)
  expect(screen.getByRole('status')).toHaveTextContent('geprüft')
  expect(screen.queryByText('nicht geprüft')).not.toBeInTheDocument()
  everyStatusHasText()

  rerender(<VerificationBadge label="Manifest" verified={false} />)
  expect(screen.getByRole('status')).toHaveTextContent('nicht bestätigt')
  everyStatusHasText()

  // Der DRITTE Wert: eine ungepruefte Aussage ist kein Nein und kein stilles Ja.
  rerender(<VerificationBadge label="Manifest" verified={null} />)
  expect(screen.getByRole('status')).toHaveTextContent('nicht geprüft')
  everyStatusHasText()
})

it('shows the badge detail beside the wording and never inside the status', () => {
  render(<VerificationBadge label="Signatur" verified={false} detail="EA-VERIFY-SIG" />)
  expect(screen.getByText('EA-VERIFY-SIG')).toBeVisible()
  expect(screen.getByRole('status')).toHaveTextContent('nicht bestätigt')
  expect(screen.getByRole('status')).not.toHaveTextContent('EA-VERIFY-SIG')
})

it('renders exactly the chain nodes it is given and invents none', () => {
  const nodes: readonly ChainIntegrityNodeView[] = [
    { label: 'Manifestformat', verified: true, detail: null },
    { label: 'Manifestsignatur', verified: true, detail: null },
    { label: 'Kette', verified: false, detail: 'EA-VERIFY-CHAIN' },
  ]
  render(<ChainIntegrityRail nodes={nodes} />)
  const rail = screen.getByRole('region', { name: 'Integritätskette' })
  expect(within(rail).getAllByRole('listitem')).toHaveLength(3)
  expect(within(rail).getAllByRole('status')).toHaveLength(3)
  // Kein Knoten ist `null`, also steht nirgends „nicht geprüft".
  expect(within(rail).queryByText('nicht geprüft')).not.toBeInTheDocument()
  expect(within(rail).getByText('EA-VERIFY-CHAIN')).toBeVisible()
  everyStatusHasText()
})

it('renders no list item for an empty chain', () => {
  render(<ChainIntegrityRail nodes={[]} />)
  const rail = screen.getByRole('region', { name: 'Integritätskette' })
  expect(within(rail).queryAllByRole('listitem')).toHaveLength(0)
  expect(within(rail).queryByText('nicht geprüft')).not.toBeInTheDocument()
})

it('carries nicht geprüft only for a node that is actually null', () => {
  render(
    <ChainIntegrityRail
      nodes={[
        { label: 'Manifestformat', verified: true, detail: null },
        { label: 'Registry', verified: null, detail: null },
      ]}
    />,
  )
  const rail = screen.getByRole('region', { name: 'Integritätskette' })
  expect(within(rail).getAllByRole('listitem')).toHaveLength(2)
  expect(within(rail).getAllByText('nicht geprüft')).toHaveLength(1)
})

it('names an unreported evidence grade as nicht gemeldet', () => {
  const { rerender } = render(<EvidenceStatus grade={null} />)
  expect(screen.getByRole('status')).toHaveTextContent('nicht gemeldet')
  expect(screen.getByText('Evidenzstufe')).toBeVisible()
  everyStatusHasText()

  // Eine gemeldete Stufe wird angezeigt und nicht umgedeutet.
  rerender(<EvidenceStatus grade="Stufe B" />)
  expect(screen.getByRole('status')).toHaveTextContent('Stufe B')
  expect(screen.queryByText('nicht gemeldet')).not.toBeInTheDocument()
})

it('renders fingerprint entries as a definition list of label and value', () => {
  const { container } = render(
    <FingerprintBlock
      entries={[
        { label: 'Eintragshash', value: '0123456789abcdef' },
        { label: 'Sequenz', value: '12' },
      ]}
    />,
  )
  const list = container.querySelector('dl')
  expect(list).not.toBeNull()
  const terms = [...(list?.querySelectorAll('dt') ?? [])].map((node) => node.textContent)
  const values = [...(list?.querySelectorAll('dd') ?? [])].map((node) => node.textContent)
  expect(terms).toEqual(['Eintragshash', 'Sequenz'])
  expect(values).toEqual(['0123456789abcdef', '12'])
  // Ein Fingerabdruck ist kein Zustand: der Block traegt keinen Statustraeger.
  expect(screen.queryAllByRole('status')).toHaveLength(0)
})

// Die Leiste nutzt dieselbe Ant-Flaeche wie jede andere Oberflaeche hier:
// `orientation`, nicht das veraltete `direction`. antd 6 meldet die veraltete
// Form ueber `console.error` — und im Testlauf jedes Mal, weil `warning.js`
// unter `NODE_ENV=test` seine Merkliste nach jeder Meldung leert.
afterEach(() => {
  vi.restoreAllMocks()
})

it('renders the rail without a deprecated-prop warning from antd', () => {
  const error = vi.spyOn(console, 'error').mockImplementation(() => undefined)
  render(<ChainIntegrityRail nodes={[{ label: 'Manifestformat', verified: true, detail: null }]} />)
  const deprecations = error.mock.calls
    .map((call) => call.map(String).join(' '))
    .filter((line) => /deprecated/.test(line))
  expect(deprecations).toEqual([])
})
