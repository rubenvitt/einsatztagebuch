import { Space, Typography } from 'antd'
import type { ReactElement } from 'react'

import { VerificationBadge } from './VerificationBadge'

/** Ein TATSAECHLICH vorhandener Knoten der Integritaetskette. */
export type ChainNode = {
  readonly label: string
  readonly verified: boolean | null
  readonly detail: string | null
}

/**
 * Die Integritaetskette: eine Leiste aus WIRKLICHEN Pruefschritten.
 *
 * Keine Fortschrittsanzeige. Jeder Knoten steht fuer eine Aussage, die geprueft
 * wurde oder eben nicht — und ein Knoten, den niemand gemeldet hat, traegt
 * „nicht geprueft" und nicht die Abwesenheit. Deshalb ist die Liste ein
 * Argument und keine Konstante: sie kann nur so lang sein, wie es Aussagen gibt.
 */
export function ChainIntegrityRail({
  nodes,
}: {
  readonly nodes: readonly ChainNode[]
}): ReactElement {
  return (
    <section aria-label="Integritätskette">
      <Space direction="vertical" size="small">
        <Typography.Text strong>Integritätskette</Typography.Text>
        <ol>
          {nodes.map((node) => (
            <li key={node.label}>
              <VerificationBadge label={node.label} verified={node.verified} detail={node.detail} />
            </li>
          ))}
        </ol>
      </Space>
    </section>
  )
}
