import { Space, Tag, Typography } from 'antd'
import type { ReactElement } from 'react'

import { DecorativeIcon } from '../../design/icons'

/**
 * Die Evidenzstufe des geoeffneten Bestands.
 *
 * `null` heisst „von der Bruecke nicht gemeldet" und ist die WAHRE Aussage,
 * solange keine Ausfuhr eine Stufe liefert. Eine erfundene Stufe waere eine
 * Aussage ueber ein Vertrauensniveau, das niemand gelesen hat, und die
 * Evidenzstufe ist getrennt von Verifikations-, Eintrags- und
 * Serverbestaetigungszustand zu fuehren.
 *
 * Der Baustein zeigt die uebergebene Zeichenkette an und kennt keinen Wert der
 * generierten Aufzaehlungen: den Wortlaut einer Stufe liefert ausschliesslich
 * `generated-contracts.ts`, und `no-hand-written-contracts.test.ts` haelt
 * jede Handkopie davon fern.
 *
 * Portiert aus `apps/desktop/src/components/integrity/EvidenceStatus.tsx`;
 * HINZUGEFUEGT ist `role="status"` auf der Marke.
 */
export function EvidenceStatus({ grade }: { readonly grade: string | null }): ReactElement {
  return (
    <Space size="small">
      <DecorativeIcon name={grade === null ? 'warning' : 'verified'} />
      <Typography.Text>Evidenzstufe</Typography.Text>
      {grade === null ? (
        <Tag role="status" color="default">
          nicht gemeldet
        </Tag>
      ) : (
        <Tag role="status" color="success">
          {grade}
        </Tag>
      )}
    </Space>
  )
}
