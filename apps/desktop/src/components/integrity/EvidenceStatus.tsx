import { Space, Tag, Typography } from 'antd'
import type { ReactElement } from 'react'

import { DecorativeIcon } from '../../design/icons'

/**
 * Die Evidenzstufe des gebundenen Bestands.
 *
 * `null` heisst „vom Wirt nicht gemeldet" und ist die WAHRE Aussage, solange
 * kein Kommando dieser Ausbaustufe eine Stufe liefert. Eine erfundene Stufe
 * waere eine Aussage ueber ein Vertrauensniveau, das niemand gelesen hat, und
 * die Evidenzstufe ist getrennt von Sync-, Verifikations-, Eintrags- und
 * Vernichtungszustand zu fuehren.
 */
export function EvidenceStatus({ grade }: { readonly grade: string | null }): ReactElement {
  return (
    <Space size="small">
      <DecorativeIcon name={grade === null ? 'warning' : 'verified'} />
      <Typography.Text>Evidenzstufe</Typography.Text>
      {grade === null ? (
        <Tag color="default">nicht gemeldet</Tag>
      ) : (
        <Tag color="success">{grade}</Tag>
      )}
    </Space>
  )
}
