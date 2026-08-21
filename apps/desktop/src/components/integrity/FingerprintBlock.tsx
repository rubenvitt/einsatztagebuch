import { Space, Typography } from 'antd'
import type { ReactElement } from 'react'

/** Ein benannter technischer Wert — Hash, Sequenz oder Fingerabdruck. */
export type FingerprintEntry = {
  readonly label: string
  readonly value: string
}

/**
 * Hashes, Sequenzen und Fingerabdruecke in der Monospace-Familie.
 *
 * `Typography.Text code` loest `fontFamilyCode` auf, und dieses Token ist
 * `ui-monospace, …` (`design/tokens.ts`, `design.md`:172). Die Familie steht
 * deshalb nicht hier: eine zweite Deklaration waere eine zweite Quelle.
 *
 * Was dieser Block ausdruecklich NICHT zeigt: Inhalt. Nach dem Abschluss sind
 * Hash und Sequenz alles, was der Writer ueber einen Eintrag noch erfaehrt.
 */
export function FingerprintBlock({
  entries,
}: {
  readonly entries: readonly FingerprintEntry[]
}): ReactElement {
  return (
    <dl>
      {entries.map((entry) => (
        <Space key={entry.label} size="small">
          <dt>
            <Typography.Text type="secondary">{entry.label}</Typography.Text>
          </dt>
          <dd>
            <Typography.Text code>{entry.value}</Typography.Text>
          </dd>
        </Space>
      ))}
    </dl>
  )
}
