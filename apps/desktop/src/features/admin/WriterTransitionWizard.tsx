import { Alert, Button, Descriptions, Input, Space, Typography } from 'antd'
import { useId, useState } from 'react'
import type { ReactElement } from 'react'

import { WRITER_TRANSITION_PHASE_VALUES } from '../../bridge/generated-contracts'
import type { WriterTransitionPhase, WriterTransitionView } from '../../bridge/generated-contracts'
import { IrreversibleActionConfirm } from '../../components/integrity/IrreversibleActionConfirm'

/** Die Phasen, AUS der emittierten Vereinigung: die zweite ist „vorbereitet". */
const [, PREPARED] = WRITER_TRANSITION_PHASE_VALUES

/** Der Wortlaut je Phase — erschoepfend, unzitierte Schluessel. */
export const WRITER_TRANSITION_PHASE_TEXT: Record<WriterTransitionPhase, string> = {
  NoTransition: 'kein Wechsel',
  Prepared: 'vorbereitet',
  Activated: 'aktiviert',
}

/**
 * Der Writer-Wechsel (§12.5): vorbereiten, dann mit frischem Nachweis
 * aktivieren.
 *
 * Es gibt genau einen aktiven Writer; die Aktivierung ist unwiderruflich und
 * nimmt deshalb die Handhabe fuer unwiderrufliche Handlungen. Die Wechselanfrage
 * kommt als JSON aus dem Werkzeug, das sie erzeugt hat — die Schale prueft sie
 * nicht nach, der Kern lehnt eine fremde ab (`EA-TRANSITION-*`).
 */
export function WriterTransitionWizard({
  state,
  notice,
  busy,
  onPrepare,
  onActivate,
}: {
  readonly state: WriterTransitionView
  readonly notice: string | null
  readonly busy: boolean
  readonly onPrepare: (requestJson: string) => void
  readonly onActivate: () => void
}): ReactElement {
  const [requestJson, setRequestJson] = useState('')
  const inputId = useId()
  const items = [
    { key: 'phase', label: 'Phase', children: WRITER_TRANSITION_PHASE_TEXT[state.phase] },
    {
      key: 'current',
      label: 'Bisheriger Writer',
      children: <Typography.Text code>{state.currentWriterHash}</Typography.Text>,
    },
    {
      key: 'next',
      label: 'Neuer Writer',
      children:
        state.newWriterHash === null ? (
          'nicht genannt'
        ) : (
          <Typography.Text code>{state.newWriterHash}</Typography.Text>
        ),
    },
    {
      key: 'sequence',
      label: 'Wirksam ab Sequenz',
      children:
        state.effectiveFromSequence === null ? 'nicht genannt' : String(state.effectiveFromSequence),
    },
  ]
  return (
    <Space direction="vertical" size="middle">
      <Descriptions size="small" column={1} items={items} />
      <Typography.Text>
        Es gibt genau einen aktiven Writer; der bisherige Writer bleibt nach der Aktivierung
        dauerhaft blockiert.
      </Typography.Text>
      {notice === null ? null : <Alert type="warning" showIcon={false} message={notice} />}
      {state.phase === PREPARED ? (
        <IrreversibleActionConfirm
          prompt="Wechsel aktivieren"
          consequence="Der neue Writer wird aktiv, der bisherige bleibt dauerhaft blockiert. Diese Handlung ist nicht umkehrbar."
          checkboxLabel="Ich habe verstanden, dass der bisherige Writer dauerhaft blockiert bleibt."
          confirmLabel="Neu anmelden und aktivieren"
          ready={!busy}
          onConfirm={onActivate}
        />
      ) : (
        <Space direction="vertical" size="small">
          <label htmlFor={inputId}>Wechselanfrage (JSON)</label>
          <Input.TextArea
            id={inputId}
            rows={4}
            value={requestJson}
            onChange={(event) => {
              setRequestJson(event.target.value)
            }}
          />
          <Button
            disabled={busy || requestJson.trim() === ''}
            onClick={() => {
              onPrepare(requestJson.trim())
            }}
          >
            Wechsel vorbereiten
          </Button>
        </Space>
      )}
    </Space>
  )
}
