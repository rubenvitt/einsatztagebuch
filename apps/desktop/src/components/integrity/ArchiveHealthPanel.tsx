import { Alert, Space, Typography } from 'antd'
import type { ReactElement } from 'react'

import type { ArchiveHealthSummaryView } from '../../bridge/generated-contracts'
import { VerificationBadge } from './VerificationBadge'

/**
 * Der Gesundheitsbefund des Bestands, wie `ArchiveHealthReport` ihn liefert.
 *
 * `healthy` ist im Kern UND-verknuepft: ein isoliertes Objekt macht den Bestand
 * ungesund, auch wenn kein Gesundheitsbefund daneben steht. Diese Flaeche
 * rechnet das nicht nach — sie zeigt die Aussage des Wirts und daneben die
 * Codes, aus denen sie entstanden ist.
 *
 * Die Codes stehen als Text da und nicht als Farbe: ein Befund, den niemand
 * lesen kann, ist kein Befund.
 */
export function ArchiveHealthPanel({
  report,
}: {
  readonly report: ArchiveHealthSummaryView | null
}): ReactElement {
  return (
    <section aria-label="Archivgesundheit">
      <Space direction="vertical" size="small">
        <Typography.Text strong>Archivgesundheit</Typography.Text>
        {report === null ? (
          <Typography.Text>
            Der Gesundheitsbefund des Bestands ist noch nicht gemeldet.
          </Typography.Text>
        ) : (
          <>
            <VerificationBadge
              label="Bestand"
              verified={report.healthy}
              detail={
                report.healthy
                  ? 'Kein Befund und kein isoliertes Objekt.'
                  : 'Mindestens ein Befund oder ein isoliertes Objekt liegt vor.'
              }
            />
            {report.healthy ? null : (
              <Alert
                type="error"
                showIcon={false}
                message="Der Bestand ist nicht gesund"
                description={[...report.findingCodes, ...report.quarantineReasons].join(', ')}
              />
            )}
          </>
        )}
      </Space>
    </section>
  )
}
