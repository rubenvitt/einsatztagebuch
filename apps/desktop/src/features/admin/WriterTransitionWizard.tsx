import { Alert, Button, Descriptions, Input, Space, Typography } from 'antd'
import { useId, useState } from 'react'
import type { ReactElement } from 'react'

import type { WriterTransitionPhase, WriterTransitionView } from '../../bridge/generated-contracts'
import { IrreversibleActionConfirm } from '../../components/integrity/IrreversibleActionConfirm'

/**
 * Der Wortlaut je Phase — erschoepfend, unzitierte Schluessel.
 *
 * „aktiviert" heisst NICHT „aktiv": die dritte Phase bindet das Change-3-Ereignis
 * an veroeffentlichte Bytes (§12.5); Autoritaet entsteht erst, wenn Root das
 * Registry-Ereignis signiert und es veroeffentlicht ist. Der Phasenname sagt
 * deshalb dazu, was noch fehlt.
 */
export const WRITER_TRANSITION_PHASE_TEXT: Record<WriterTransitionPhase, string> = {
  NoTransition: 'kein Wechsel',
  Prepared: 'vorbereitet',
  Activated: 'aktiviert — Registry-Ereignis noch nicht veröffentlicht',
}

/**
 * Welche Handhabe je Phase steht — genau EINE, als erschoepfende Abbildung.
 *
 * Ohne Wechsel: die Anfrage einlesen. Vorbereitet: unwiderruflich aktivieren.
 * Aktiviert: das Registry-Ereignis als Root-Zeremonie beginnen — und KEIN
 * zweites Vorbereiten, solange das erste nicht veroeffentlicht ist.
 */
const PHASE_ACTION: Record<WriterTransitionPhase, 'prepare' | 'activate' | 'publish'> = {
  NoTransition: 'prepare',
  Prepared: 'activate',
  Activated: 'publish',
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
 * Es gibt genau einen aktiven Writer; die Aktivierung ist unwiderruflich und
 * nimmt deshalb die Handhabe fuer unwiderrufliche Handlungen. Die Wechselanfrage
 * kommt als JSON aus dem Werkzeug, das sie erzeugt hat — die Schale prueft sie
 * nicht nach, der Kern lehnt eine fremde ab (`EA-TRANSITION-*`). Das Wort
 * „aktiv" faellt auf dieser Flaeche nirgends ueber den NEUEN Writer: erst der
 * letzte Schritt des Steppers darf das sagen.
 */
export function WriterTransitionWizard({
  state,
  notice,
  busy,
  onPrepare,
  onActivate,
  onBeginCeremony,
}: {
  readonly state: WriterTransitionView
  readonly notice: string | null
  readonly busy: boolean
  readonly onPrepare: (requestJson: string) => void
  readonly onActivate: () => void
  /** Beginnt die Root-Zeremonie der Art Writer-Wechsel fuer den genannten Hash. */
  readonly onBeginCeremony: (targetHash: string) => void
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
      case 'publish':
        return (
          <Space direction="vertical" size="small">
            <Typography.Text>{ACTIVATED_BOUNDARY_TEXT}</Typography.Text>
            <Button
              type="primary"
              disabled={busy}
              onClick={() => {
                onBeginCeremony(state.newWriterHash ?? state.currentWriterHash)
              }}
            >
              Registry-Ereignis als Root-Zeremonie beginnen
            </Button>
          </Space>
        )
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
