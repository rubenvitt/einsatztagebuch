import { Tag, Typography } from 'antd'
import { useId } from 'react'
import type { ReactElement } from 'react'

import type { ServerConfirmationV1 } from '../../bridge/generated-contracts'
import { SERVER_CONFIRMATION_V1_VALUES } from '../../bridge/generated-contracts'

/** Die Farbklassen der Marke; keine davon ist ein eigener Farbwert. */
export type DimensionColor = 'default' | 'success' | 'warning' | 'error' | 'processing'

/**
 * EINE Statusdimension: eine Beschriftung, ein Wert, ein Traeger.
 *
 * Der Wert steht als TEXT in der Marke, und die Marke ist der `role="status"`
 * — Farbe und Zeichen sind nach `design.md` §17.5 nie der alleinige Traeger.
 * Die Beschriftung ist ueber `aria-labelledby` der zugaengliche NAME des
 * Traegers, damit ein Zeuge und ein Screenreader „Verifikation" von
 * „Server-Bestätigung" unterscheiden koennen, ohne den Wert zu kennen; die
 * Beschreibung, wo eine steht, haengt ueber `aria-describedby` daran.
 *
 * Der Wert wird GERENDERT und nie getippt: er kommt aus dem generierten DTO.
 */
export function StatusDimension({
  label,
  value,
  color,
  description,
}: {
  readonly label: string
  readonly value: string
  readonly color: DimensionColor
  readonly description?: string
}): ReactElement {
  const labelId = useId()
  const descriptionId = useId()
  return (
    <div>
      <Typography.Text id={labelId} type="secondary">
        {label}
      </Typography.Text>{' '}
      <Tag
        role="status"
        color={color}
        aria-labelledby={labelId}
        aria-describedby={description === undefined ? undefined : descriptionId}
      >
        {value}
      </Tag>
      {description === undefined ? null : (
        <Typography.Text id={descriptionId} type="secondary">
          {description}
        </Typography.Text>
      )}
    </div>
  )
}

/** Der Wert „mit Serverquittung" — als Index in die generierte Tabelle. */
const [SERVER_CONFIRMED] = SERVER_CONFIRMATION_V1_VALUES

/**
 * Die ZWEITE Dimension aus `design.md` §17.4, an ihrem eigenen Traeger.
 *
 * Sie wird nie in dieselbe Marke wie der Verifikationsstatus gefaltet und
 * traegt keine Warn- und keine Fehlerfarbe: ein Objekt ohne Serverquittung ist
 * im Datei-Modus der REGELFALL (`web-reader-design.md` §5.4) und im
 * Server-Modus die Ausnahme — der Zustand ist derselbe, also ist es auch die
 * Darstellung. Der Satz daneben ist die zugaengliche Beschreibung: „kein
 * Mangel" steht dort wortwoertlich, weil die Zeugen ihn dort lesen.
 */
export function ServerConfirmationStatus({
  value,
}: {
  readonly value: ServerConfirmationV1
}): ReactElement {
  return (
    <StatusDimension
      label="Server-Bestätigung"
      value={value}
      color={value === SERVER_CONFIRMED ? 'processing' : 'default'}
      description="Eigene Dimension neben der Verifikation, kein Mangel: Sie sagt nur, ob eine Serverquittung vorliegt. Im Datei-Modus wird keine bezogen, und der Prüfstand darüber bleibt davon unberührt."
    />
  )
}
