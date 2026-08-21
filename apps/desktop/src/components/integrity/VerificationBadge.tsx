import { Space, Tag, Typography } from 'antd'
import type { ReactElement } from 'react'

import { DecorativeIcon } from '../../design/icons'

/**
 * Der Verifikationszustand EINER Aussage — dreiwertig.
 *
 * `null` heisst „nicht geprueft" und ist ausdruecklich kein Nein und kein
 * stilles Ja. Der Wortlaut steht neben dem Zeichen, weil ein Symbol allein
 * nie einen Sicherheitszustand vermitteln darf.
 */
export function VerificationBadge({
  label,
  verified,
  detail = null,
}: {
  readonly label: string
  readonly verified: boolean | null
  readonly detail?: string | null
}): ReactElement {
  const wording =
    verified === null ? 'nicht geprüft' : verified ? 'geprüft' : 'nicht bestätigt'
  const color = verified === null ? 'default' : verified ? 'success' : 'error'
  return (
    <Space size="small">
      <DecorativeIcon
        name={verified === true ? 'verified' : 'warning'}
        state={verified === true ? 'confirmed' : 'default'}
      />
      <Typography.Text>{label}</Typography.Text>
      <Tag color={color}>{wording}</Tag>
      {detail === null ? null : <Typography.Text type="secondary">{detail}</Typography.Text>}
    </Space>
  )
}
