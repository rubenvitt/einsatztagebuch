import { Space, Typography } from 'antd'
import type { ReactElement } from 'react'

import type { ChainIntegrityNodeView } from '../../bridge/generated-contracts'
import { VerificationBadge } from './VerificationBadge'

/**
 * Die Integritaetskette: eine Leiste aus WIRKLICHEN Pruefschritten.
 *
 * Keine Fortschrittsanzeige. Jeder Knoten steht fuer eine Aussage, die geprueft
 * wurde oder eben nicht — und ein Knoten, den niemand gemeldet hat, wird NICHT
 * erfunden. Deshalb ist die Liste ein Argument und keine Konstante: sie kann
 * nur so lang sein, wie es Aussagen gibt, und fuer eine leere Liste steht die
 * Leiste leer.
 *
 * Der Knoten ist `ChainIntegrityNodeView` aus den generierten Kontrakten und
 * kein lokaler Zwilling: der Baustein rechnet nichts und deutet nichts um — er
 * zeigt die drei Felder, wie sie aus `view.rs` ankommen.
 *
 * Portiert aus `apps/desktop/src/components/integrity/ChainIntegrityRail.tsx`;
 * `<section aria-label="Integritätskette"><ol><li>` bleibt, das `role="status"`
 * je Knoten kommt aus dem portierten `VerificationBadge`.
 */
export function ChainIntegrityRail({
  nodes,
}: {
  readonly nodes: readonly ChainIntegrityNodeView[]
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
