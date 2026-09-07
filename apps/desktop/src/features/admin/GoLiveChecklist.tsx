import { Button, Space, Tag, Typography } from 'antd'
import { useState } from 'react'
import type { ReactElement } from 'react'

import type {
  GoLiveChecklistView,
  GoLiveRequirementStatus,
} from '../../bridge/generated-contracts'

/**
 * Der WORTLAUT je Status — als erschoepfende Abbildung mit UNZITIERTEN
 * Schluesseln (Muster `TrustAgeStatus.tsx`).
 *
 * Die drei Woerter folgen §17.3 (`design.md`:1922-1930), §18.4 (`:1974`,
 * „nicht automatisch prüfbare Voraussetzungen im Go-live-Bericht") und §21
 * (`:2044-2073`); sie stehen NICHT in §17.4.
 */
export const GO_LIVE_STATUS_TEXT: Record<GoLiveRequirementStatus, string> = {
  Confirmed: 'bestätigt',
  NotMet: 'nicht erfüllt',
  NotAutomaticallyVerifiable: 'nicht automatisch prüfbar',
}

/**
 * Welcher Status als positiv bestaetigt gilt. Genau EINER — „nicht automatisch
 * prüfbar" ist weder ein Ja noch ein Nein und deshalb nie gruen.
 */
const GO_LIVE_CONFIRMED: Record<GoLiveRequirementStatus, boolean> = {
  Confirmed: true,
  NotMet: false,
  NotAutomaticallyVerifiable: false,
}

/** Die Farbe als ZWEITER Hinweis neben dem Wort — nie allein (design.md:1946-1948). */
const GO_LIVE_TAG_COLOR: Record<GoLiveRequirementStatus, 'success' | 'error' | 'default'> = {
  Confirmed: 'success',
  NotMet: 'error',
  NotAutomaticallyVerifiable: 'default',
}

/**
 * Ob die Schale ein gruenes Licht zeigt.
 *
 * `productionReady` rechnet der Kern (`GoLiveChecklist::production_ready`, wahr
 * NUR wenn alle bestaetigt). Die Schale rechnet es NICHT nach — sie verweigert
 * bloss: behauptet ein Wirt `true` ueber einer Zeile, die nicht bestaetigt ist,
 * bleibt die Anzeige „nicht produktionsbereit". Eine leere Liste ist ebenfalls
 * kein Ja.
 */
export function showsProductionReady(checklist: GoLiveChecklistView): boolean {
  return (
    checklist.productionReady &&
    checklist.requirements.length > 0 &&
    checklist.requirements.every((requirement) => GO_LIVE_CONFIRMED[requirement.status])
  )
}

/**
 * Die Go-live-Liste: fuenfzehn Anforderungen, je Wort, Farbe und Belegcode.
 *
 * Der Export der offenen Punkte ist der deterministische Bericht
 * `ea.go-live-checklist/v1` aus dem Kern; die Schale zeigt seinen Text und
 * schreibt ihn nicht um.
 */
export function GoLiveChecklist({
  checklist,
  onExportUnresolved,
}: {
  readonly checklist: GoLiveChecklistView
  readonly onExportUnresolved: () => Promise<string>
}): ReactElement {
  const [report, setReport] = useState<string | null>(null)
  const [refused, setRefused] = useState(false)
  const ready = showsProductionReady(checklist)

  return (
    <Space direction="vertical" size="small">
      <div role="status" aria-label="Go-live-Bereitschaft">
        <Typography.Text strong>
          {ready ? 'produktionsbereit' : 'nicht produktionsbereit'}
        </Typography.Text>
      </div>
      <ol>
        {checklist.requirements.map((requirement) => (
          <li key={requirement.requirementCode}>
            <Space size="small">
              <Typography.Text>{requirement.requirementCode}</Typography.Text>
              <Tag color={GO_LIVE_TAG_COLOR[requirement.status]}>
                {GO_LIVE_STATUS_TEXT[requirement.status]}
              </Tag>
              <Typography.Text type="secondary">{requirement.evidenceCode}</Typography.Text>
            </Space>
          </li>
        ))}
      </ol>
      <Button
        onClick={() => {
          setRefused(false)
          onExportUnresolved().then(setReport, () => {
            setRefused(true)
          })
        }}
      >
        Offene Punkte exportieren
      </Button>
      {refused ? (
        <Typography.Text>Die Nachweisliste konnte nicht erzeugt werden.</Typography.Text>
      ) : null}
      {report === null ? null : <pre aria-label="Go-live-Nachweisliste">{report}</pre>}
    </Space>
  )
}
