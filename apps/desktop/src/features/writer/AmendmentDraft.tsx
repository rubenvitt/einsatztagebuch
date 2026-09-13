import { Button, Input, Space, Typography } from 'antd'
import type { ReactElement } from 'react'

import type { AmendmentInputView, CorrectionReferenceView } from '../../bridge/generated-contracts'

export type CorrectionReferenceInput = CorrectionReferenceView
export type AmendmentDraftValue = AmendmentInputView

export function blankAmendment(reference: CorrectionReferenceInput): AmendmentDraftValue {
  return { reference, reason: '', changes: [{ fieldPath: '', changeText: '' }] }
}

export function amendmentInputViolation(value: AmendmentDraftValue): string | null {
  if (value.reason.trim() === '') return 'Die Begründung des Nachtrags fehlt.'
  if (value.changes.length === 0) return 'Mindestens eine Änderung ist erforderlich.'
  if (value.changes.some(change => change.fieldPath.trim() === '' || change.changeText.trim() === '')) {
    return 'Feldpfad und Änderungstext müssen ausgefüllt sein.'
  }
  return null
}

export function AmendmentDraft({ value, onChange, disabled = false }: {
  readonly value: AmendmentDraftValue
  readonly onChange: (value: AmendmentDraftValue) => void
  readonly disabled?: boolean
}): ReactElement {
  return (
    <section aria-label="Nachtragsentwurf">
      <Space orientation="vertical" size="middle">
        <Typography.Title level={3}>Nachtrag zum Original</Typography.Title>
        <Typography.Text>Das Original bleibt unverändert. Der Nachtrag wird als eigener Eintrag abgeschlossen.</Typography.Text>
        <Typography.Text>{value.reference.originalRecordId}</Typography.Text>
        <Typography.Text>Sequenz {value.reference.originalSequence}</Typography.Text>
        <Typography.Text code>{value.reference.originalEntryHash}</Typography.Text>
        <label htmlFor="amendment-reason">Begründung des Nachtrags</label>
        <Input.TextArea id="amendment-reason" value={value.reason} disabled={disabled}
          onChange={event => onChange({ ...value, reason: event.target.value })} />
        {value.changes.map((change, index) => (
          <Space orientation="vertical" key={index}>
            <label htmlFor={`amendment-path-${index}`}>Feldpfad {index + 1}</label>
            <Input id={`amendment-path-${index}`} value={change.fieldPath} disabled={disabled}
              onChange={event => onChange({ ...value, changes: value.changes.map((item, position) => position === index ? { ...item, fieldPath: event.target.value } : item) })} />
            <label htmlFor={`amendment-text-${index}`}>Änderungstext {index + 1}</label>
            <Input.TextArea id={`amendment-text-${index}`} value={change.changeText} disabled={disabled}
              onChange={event => onChange({ ...value, changes: value.changes.map((item, position) => position === index ? { ...item, changeText: event.target.value } : item) })} />
            {value.changes.length > 1 ? <Button disabled={disabled} onClick={() => onChange({ ...value, changes: value.changes.filter((_, position) => position !== index) })}>Änderung {index + 1} entfernen</Button> : null}
          </Space>
        ))}
        <Button disabled={disabled} onClick={() => onChange({ ...value, changes: [...value.changes, { fieldPath: '', changeText: '' }] })}>Weitere Änderung</Button>
      </Space>
    </section>
  )
}
