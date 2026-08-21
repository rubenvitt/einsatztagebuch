import { Button, Space, Typography } from 'antd'
import { useState } from 'react'
import type { ReactElement } from 'react'

import type { DiscardStateView } from '../../bridge/generated-contracts'
import { IrreversibleActionConfirm } from '../../components/integrity/IrreversibleActionConfirm'

/**
 * Das Verwerfen des aktiven Entwurfs.
 *
 * Zwei Stufen, wie beim Abschluss: eine eigene Handhabe oeffnet die
 * Bestaetigung, und erst die Bestaetigung samt nativer Wiederanmeldung fuehrt
 * sie aus. Das gewoehnliche Speichern nimmt diesen Weg nie.
 *
 * Verwerfen ist unwiderruflich UND fortsetzbar: der Kern bucht die Absicht
 * dauerhaft, BEVOR etwas Unwiderrufliches geschieht, und jeder Neustart danach
 * ist eine Fortsetzung. Deshalb nennt diese Flaeche den Phasencode, den der
 * Wirt zurueckgibt — er ist die Aussage darueber, wo eine unterbrochene
 * Verwerfung stand.
 */
export function DiscardDraftAction({
  busy,
  onDiscard,
  onResume,
  state,
}: {
  readonly busy: boolean
  readonly onDiscard: () => void
  readonly onResume: () => void
  readonly state: DiscardStateView | null
}): ReactElement {
  const [open, setOpen] = useState(false)
  return (
    <Space direction="vertical" size="small">
      {state !== null ? null : open ? (
        <IrreversibleActionConfirm
          prompt="Der aktive Entwurf wird unwiderruflich verworfen."
          consequence={
            'Chiffrat und Entwurfsschlüssel gehen fort, und an ihrer Stelle entsteht ein ' +
            'dauerhaft leerer Entwurf. Eine vorbereitete Finalisierung gewinnt an jedem ' +
            'Eingang gegen diese Absicht.'
          }
          checkboxLabel="Ich bestätige, dass der Entwurf unwiderruflich verworfen wird."
          confirmLabel="Verwerfen bestätigen"
          ready={!busy}
          onConfirm={onDiscard}
        />
      ) : (
        <Button
          danger
          onClick={() => {
            setOpen(true)
          }}
        >
          Entwurf verwerfen
        </Button>
      )}
      {state === null ? null : (
        <Space direction="vertical" size="small">
          <Typography.Text>
            {`Verwerfen gebucht — Phase ${state.phaseCode}. ` +
              (state.complete
                ? 'Der leere Entwurf steht.'
                : 'Die Fortsetzung steht aus; jeder Neustart nimmt sie wieder auf.')}
          </Typography.Text>
          {state.complete ? null : <Button onClick={onResume}>Verwerfen fortsetzen</Button>}
        </Space>
      )}
    </Space>
  )
}
