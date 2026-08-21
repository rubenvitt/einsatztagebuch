import { Alert, Space, Typography } from 'antd'
import type { ReactElement } from 'react'

import type { FinalizationPreviewView, StaleDecision } from '../bridge/generated-contracts'
import { DecorativeIcon } from '../design/icons'

/**
 * Der WORTLAUT je Entscheidung — als Abbildung ueber die geschlossene
 * Aufzaehlung und nicht als Vergleichskette.
 *
 * Zwei Gruende, und beide sind bindend: `Record<StaleDecision, string>` ist
 * erschoepfend, also bricht ein vierter Arm die Uebersetzung statt still in den
 * Vorgabefall zu fallen; und die Schluessel stehen UNZITIERT, also wiederholt
 * diese Datei kein Kontraktliteral (`no-hand-written-contracts.test.ts`).
 */
const STALE_TEXT: Record<StaleDecision, string> = {
  Fresh: 'Vertrauensbestand aktuell.',
  StaleAcknowledgeable:
    'Vertrauensbestand veraltet. Ein Abschluss verlangt eine ausdrückliche Bestätigung.',
  HardBlock: 'Vertrauensbestand nicht mehr gültig. Ein Abschluss ist gesperrt.',
}

/**
 * Welche Entscheidung als positiv bestaetigt gilt — wieder als erschoepfende
 * Abbildung mit UNZITIERTEN Schluesseln. Ein Vergleich gegen ein Literal waere
 * eine zweite Quelle desselben Kontraktwerts.
 */
const CONFIRMED: Record<StaleDecision, boolean> = {
  Fresh: true,
  StaleAcknowledgeable: false,
  HardBlock: false,
}

function formatDuration(milliseconds: number): string {
  const totalHours = Math.floor(milliseconds / (60 * 60 * 1000))
  const days = Math.floor(totalHours / 24)
  const hours = totalHours % 24
  if (days === 0) {
    return `${String(hours)} h`
  }
  return `${String(days)} d ${String(hours)} h`
}

/**
 * Die Statusflaeche fuer das ALTER des gebundenen Vertrauensbestands und die
 * Policyfrist `readerTrustRefreshMs` (`schemas/archive/v1/trust.cddl`:134,
 * `crates/ea-format/src/etb.rs`:220).
 *
 * Alter und Frist stehen als zwei getrennte Zahlen da, weil die Ueberschreitung
 * eine WARNUNG ist und die Sperre an einer anderen Aussage haengt; beide Saetze
 * nennen ihren Wortlaut ausdruecklich und verlassen sich nicht auf Symbol oder
 * Farbe. Task 16 fuellt die Vorschauwerte.
 */
export function TrustAgeStatus({
  preview,
}: {
  readonly preview: FinalizationPreviewView | null
}): ReactElement {
  if (preview === null) {
    return (
      <Typography.Text>
        Vertrauensbestand: noch nicht geprüft. Alter und Auffrischungsfrist stehen erst mit der
        ersten Abschlussvorschau fest.
      </Typography.Text>
    )
  }

  return (
    <Space direction="vertical" size="small">
      <Space size="small">
        <DecorativeIcon
          name={CONFIRMED[preview.staleDecision] ? 'verified' : 'warning'}
          state={CONFIRMED[preview.staleDecision] ? 'confirmed' : 'default'}
        />
        <Typography.Text>{STALE_TEXT[preview.staleDecision]}</Typography.Text>
      </Space>
      <Typography.Text>
        {`Alter des gebundenen Vertrauensbestands: ${formatDuration(preview.trustAgeMs)}. ` +
          `Auffrischungsfrist der Policy: ${formatDuration(preview.readerTrustRefreshMs)}.`}
      </Typography.Text>
      {preview.trustRefreshOverdue ? (
        <Alert
          type="warning"
          showIcon={false}
          message="Auffrischungsfrist überschritten"
          description={
            'Der gebundene Vertrauensbestand ist älter als die Policyfrist. Das ist eine Warnung ' +
            'und keine Sperre; die Sperre hängt an der Gültigkeit des Bestands.'
          }
        />
      ) : null}
    </Space>
  )
}
