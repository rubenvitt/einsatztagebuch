import { render, screen } from '@testing-library/react'
import { useState } from 'react'
import { expect, it } from 'vitest'

import { AmendmentDraft, blankAmendment, amendmentInputViolation } from './AmendmentDraft'
import { userEvent } from '../../test-setup'

const original = {
  originalRecordId: '0194f200-0000-7000-8000-000000000001',
  originalEntryHash: 'a'.repeat(64),
  originalSequence: 4,
}

// Omitting the reason/structured-change editors or making the original an
// editable field must break this visible input-contract witness.
it('keeps the original reference read-only while editing reason and structured changes', async () => {
  function Draft() {
    const [value, setValue] = useState(blankAmendment(original))
    return <AmendmentDraft value={value} onChange={setValue} />
  }
  render(<Draft />)
  const user = userEvent.setup()
  expect(screen.getByText(original.originalRecordId)).toBeVisible()
  expect(screen.getByText(original.originalEntryHash)).toBeVisible()
  expect(screen.getByText('Sequenz 4')).toBeVisible()
  expect(screen.queryByRole('textbox', { name: /Original/ })).not.toBeInTheDocument()
  expect(screen.getByText(/Das Original bleibt unverändert/)).toBeVisible()
  await user.type(screen.getByRole('textbox', { name: 'Begründung des Nachtrags' }), 'Anzahl berichtigen')
  await user.type(screen.getByRole('textbox', { name: 'Feldpfad 1' }), 'patientCount')
  await user.type(screen.getByRole('textbox', { name: 'Änderungstext 1' }), 'Zwei statt einer Person')
  expect(screen.getByRole('textbox', { name: 'Begründung des Nachtrags' })).toHaveValue('Anzahl berichtigen')
  await user.click(screen.getByRole('button', { name: 'Weitere Änderung' }))
  expect(screen.getByRole('textbox', { name: 'Feldpfad 2' })).toHaveValue('')
})

it('requires a reason and at least one complete structured change', () => {
  const empty = blankAmendment(original)
  expect(amendmentInputViolation(empty)).toBe('Die Begründung des Nachtrags fehlt.')
  expect(amendmentInputViolation({ ...empty, reason: 'Korrektur', changes: [] })).toBe('Mindestens eine Änderung ist erforderlich.')
  expect(amendmentInputViolation({ ...empty, reason: 'Korrektur' })).toBe('Feldpfad und Änderungstext müssen ausgefüllt sein.')
  expect(amendmentInputViolation({ ...empty, reason: 'Korrektur', changes: [{ fieldPath: 'notes', changeText: 'Nachtrag' }] })).toBeNull()
})
