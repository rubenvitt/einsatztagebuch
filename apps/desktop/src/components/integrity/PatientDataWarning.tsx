import { Space, Typography } from 'antd'
import type { ReactElement } from 'react'

import { DecorativeIcon } from '../../design/icons'

/**
 * Die Warnung, die an JEDEM Freitextfeld steht.
 *
 * Sie ist kein Hinweis auf eine Einstellung, sondern die Aussage ueber diese
 * Anwendung: der Entwurf bleibt lokal und verschluesselt, und identifizierende
 * Patientendaten sind ein Nichtziel des ganzen Produkts. Als Text und nicht als
 * Farbe oder Symbol, wie jede sicherheitsrelevante Aussage hier.
 */
export function PatientDataWarning(): ReactElement {
  return (
    <Space size="small">
      <DecorativeIcon name="warning" />
      <Typography.Text type="secondary">
        Dieser Freitext bleibt lokal und verschlüsselt. Hier stehen keine identifizierenden
        Patientendaten.
      </Typography.Text>
    </Space>
  )
}
