import { render, screen } from '@testing-library/react'
import { expect, it } from 'vitest'
import type { ReaderEntryView } from '../../bridge/generated-contracts'
import { AmendmentThread } from './AmendmentThread'

it('offers only the exact verified correction triple while keeping original and amendments', () => {
  const reference = { originalRecordId: '01970000000070008000000000000001', originalEntryHash: '31'.repeat(32), originalSequence: 3 }
  const entry: ReaderEntryView = {
    state: { entryHash: reference.originalEntryHash, objectHash: '41'.repeat(32), sequence: 3, verification: 'verifiziert', entryState: 'vorhanden', serverConfirmation: 'nicht server-bestätigt', detailCode: null },
    incident: { incidentNumber: '2026-0001', occurredAtStartMs: 1771000000000, timezone: 'Europe/Berlin', keyword: 'Einsatz' },
  }
  const thread = { original: entry, amendments: [], rejected: [], correctionReference: reference }
  render(<AmendmentThread thread={thread} />)
  expect(screen.getByRole('textbox', { name: 'Korrekturreferenz für den Writer' })).toHaveValue(JSON.stringify(reference))
  expect(screen.getByRole('textbox', { name: 'Korrekturreferenz für den Writer' })).toHaveAttribute('readonly')
  expect(screen.getByRole('heading', { name: 'Original' })).toBeVisible()
  expect(screen.getByRole('heading', { name: 'Nachträge' })).toBeVisible()
})
