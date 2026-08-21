import { Space, Typography } from 'antd'
import type { ReactElement } from 'react'

import type { DevicePostureSummaryView } from '../../bridge/generated-contracts'
import { VerificationBadge } from './VerificationBadge'

/**
 * Die Haltung des Geraets — mit Unknown als UNGEKLAERTEM Stand.
 *
 * Dreiwertig und nicht zweiwertig: „auf dieser Plattform nicht belegbar" ist
 * kein automatisches Ja und auch kein gemessenes Nein. `productionReady` ist
 * im Kern fail-closed abgeleitet (leer oder ein einziges Unknown genuegt fuer
 * `false`), und diese Flaeche nennt genau das im Wortlaut.
 */
export function DevicePosturePanel({
  posture,
}: {
  readonly posture: DevicePostureSummaryView | null
}): ReactElement {
  return (
    <section aria-label="Gerätehaltung">
      <Space direction="vertical" size="small">
        <Typography.Text strong>Gerätehaltung</Typography.Text>
        {posture === null ? (
          <Typography.Text>Die Haltung dieses Geräts ist noch nicht gemeldet.</Typography.Text>
        ) : (
          <>
            {posture.requirements.map((requirement) => (
              <VerificationBadge
                key={requirement.requirementCode}
                label={requirement.requirementCode}
                verified={requirement.satisfied}
                detail={
                  requirement.satisfied === null
                    ? `auf dieser Plattform nicht belegbar (${requirement.evidenceCode})`
                    : requirement.evidenceCode
                }
              />
            ))}
            <Typography.Text>
              {posture.productionReady
                ? 'Dieses Gerät ist produktionsbereit: jede Anforderung ist belegt erfüllt.'
                : 'Dieses Gerät ist nicht produktionsbereit, solange eine Anforderung unbelegt oder verletzt ist.'}
            </Typography.Text>
          </>
        )}
      </Space>
    </section>
  )
}
