import { Button, Checkbox, Space, Typography } from 'antd'
import { useState } from 'react'
import type { ReactElement } from 'react'

import { DecorativeIcon } from '../../design/icons'

/**
 * Die EINE Handhabe fuer jede unwiderrufliche Handlung.
 *
 * Zwei Schritte, und beide sind Pflicht: die ausdrueckliche Bestaetigung des
 * unwiderruflichen Charakters UND der eigene Knopf danach. Das gewoehnliche
 * Speichern nimmt diesen Weg nie — es hat eine andere Handhabe, und deshalb
 * kann ein Klick auf „speichern" nichts Unwiderrufliches ausloesen.
 *
 * Was diese Komponente NICHT kennt: den gesperrten Fall. Ist eine Handlung
 * gesperrt, wird sie GAR NICHT gerendert; ein deaktivierter Knopf waere die
 * Aussage „gleich vielleicht doch".
 */
export function IrreversibleActionConfirm({
  prompt,
  consequence,
  checkboxLabel,
  confirmLabel,
  ready = true,
  onConfirm,
}: {
  readonly prompt: string
  readonly consequence: string
  readonly checkboxLabel: string
  readonly confirmLabel: string
  /** Ob die Handlung ueberhaupt ausfuehrbar ist — etwa: liegt eine Vorschau. */
  readonly ready?: boolean
  readonly onConfirm: () => void
}): ReactElement {
  const [confirmed, setConfirmed] = useState(false)
  return (
    <Space direction="vertical" size="small">
      <Space size="small">
        <DecorativeIcon name="warning" />
        <Typography.Text strong>{prompt}</Typography.Text>
      </Space>
      <Typography.Text>{consequence}</Typography.Text>
      <Checkbox
        checked={confirmed}
        onChange={(event) => {
          setConfirmed(event.target.checked)
        }}
      >
        {checkboxLabel}
      </Checkbox>
      <Button danger type="primary" disabled={!confirmed || !ready} onClick={onConfirm}>
        {confirmLabel}
      </Button>
    </Space>
  )
}
