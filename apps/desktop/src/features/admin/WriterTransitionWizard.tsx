import { Alert, Button, Descriptions, Input, Space, Typography } from 'antd'
import { useId, useState } from 'react'
import type { ReactElement } from 'react'

import type { WriterTransitionPhase, WriterTransitionView } from '../../bridge/generated-contracts'
import { IrreversibleActionConfirm } from '../../components/integrity/IrreversibleActionConfirm'

/**
 * Der Wortlaut je Phase — erschoepfend, unzitierte Schluessel.
 *
 * Die native Projektion liefert Activated erst aus dem signierten Registry-
 * Stand. Offene IssueTarget-/ActivateRegistry-Runden bleiben Prepared.
 */
export const WRITER_TRANSITION_PHASE_TEXT: Record<WriterTransitionPhase, string> = {
  NoTransition: 'kein Wechsel',
  Prepared: 'vorbereitet',
  Activated: 'Writer-Wechsel im signierten Registry-Stand wirksam',
}

/**
 * Welche Handhabe je Phase steht — genau EINE, als erschoepfende Abbildung.
 *
 * Eine gespeicherte Runde wird ausschliesslich ueber ihre native ID geoeffnet.
 * Ein bereits wirksamer Wechsel startet keine weitere Runde.
 */
const PHASE_ACTION: Record<WriterTransitionPhase, 'prepare' | 'activate' | 'done'> = {
  NoTransition: 'prepare',
  Prepared: 'activate',
  Activated: 'done',
}

/**
 * Der Satz, der nach der Aktivierung steht — die Grenze in Worten: bis zum
 * Root-signierten Registry-Ereignis hat sich am aktiven Writer NICHTS
 * geaendert.
 */
export const ACTIVATED_BOUNDARY_TEXT =
  'Der Wechsel wird erst mit dem Root-signierten Registry-Ereignis wirksam; bis dahin bleibt der bisherige Writer der einzige aktive.'

/**
 * Der Writer-Wechsel (§12.5): vorbereiten, mit frischem Nachweis aktivieren,
 * dann das Registry-Ereignis als Root-Zeremonie veroeffentlichen.
 *
 * Es gibt genau einen aktiven Writer. Die Wechselanfrage
 * kommt als JSON aus dem Werkzeug, das sie erzeugt hat — die Schale prueft sie
 * nicht nach, der Kern lehnt eine fremde ab (`EA-TRANSITION-*`). Die Oberflaeche
 * leitet weder einen Zielhash noch eine neue Root-Runde aus Writer-Hashes ab.
 */
export function WriterTransitionWizard({
  state,
  notice,
  busy,
  onPrepare,
  onActivate,
  onOpenCeremony,
}: {
  readonly state: WriterTransitionView
  readonly notice: string | null
  readonly busy: boolean
  readonly onPrepare: (requestJson: string) => void
  readonly onActivate: () => void
  readonly onOpenCeremony: (ceremonyId: string) => void
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

  const action = (): ReactElement => {
    if (state.ceremonyId !== null) {
      const id = state.ceremonyId
      return (
        <Space direction="vertical" size="small">
          <Typography.Text>{ACTIVATED_BOUNDARY_TEXT}</Typography.Text>
          <Button type="primary" disabled={busy} onClick={() => onOpenCeremony(id)}>
            Gespeicherte Root-Runde öffnen
          </Button>
        </Space>
      )
    }
    switch (PHASE_ACTION[state.phase]) {
      case 'activate':
        return (
          <IrreversibleActionConfirm
            prompt="Wechsel aktivieren"
            consequence="Das Wechselereignis wird an veröffentlichte Bytes gebunden; wirksam wird es erst mit dem Root-signierten Registry-Ereignis, danach bleibt der bisherige Writer dauerhaft blockiert. Diese Handlung ist nicht umkehrbar."
            checkboxLabel="Ich habe verstanden, dass der bisherige Writer dauerhaft blockiert bleibt."
            confirmLabel="Neu anmelden und aktivieren"
            ready={!busy}
            onConfirm={onActivate}
          />
        )
      case 'done':
        return <Typography.Text>Die Root-signierte Aktivierung ist veröffentlicht.</Typography.Text>
      case 'prepare':
        return (
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
        )
    }
  }

  return (
    <Space direction="vertical" size="middle">
      <Descriptions size="small" column={1} items={items} />
      <Typography.Text>
        Es gibt genau einen aktiven Writer; der bisherige Writer bleibt nach dem Root-signierten
        Registry-Ereignis dauerhaft blockiert.
      </Typography.Text>
      {notice === null ? null : <Alert type="warning" showIcon={false} message={notice} />}
      {action()}
    </Space>
  )
}
