import { Alert, Button, Space, Typography } from 'antd'
import type { ReactElement } from 'react'

import type { FinalizationPreviewView, StaleAcknowledgementView } from '../../bridge/generated-contracts'

/**
 * Der veraltete Registry-Head im Standardprofil mit signiertem `warn`.
 *
 * Was hier ABSICHTLICH fehlt: ein Schliesskreuz, ein Tastaturausweg, ein
 * „nicht mehr anzeigen" und jeder allgemeine Weiterweg. Die Warnung ist
 * dauerhaft (`closable={false}`), sie steht in einem `role="alert"`, und der
 * EINZIGE Weg an ihr vorbei ist die Bestaetigung — nach einer erneuten nativen
 * Authentisierung und mit dem Nachweis, den der Wirt ausstellt.
 *
 * `captured` kommt AUS DER ANTWORT und nicht aus dem Klick. Der
 * Bestaetigungspfad ist im Kern eine benannte Auslassung
 * (`ea-writer/src/lib.rs`: `acknowledge_stale_registry` ist nicht gebaut, der
 * Ausgang ist fail-closed `EA-REGISTRY-STALE-ACK-REQUIRED`), also ist die
 * ehrliche Anzeige heute „keine Bestaetigung erfasst" — und genau die zeigt
 * diese Flaeche, wenn der Wirt ablehnt.
 */
export function StaleRegistryWarning({
  preview,
  acknowledgement,
  refused,
  busy,
  onAcknowledge,
}: {
  readonly preview: FinalizationPreviewView
  readonly acknowledgement: StaleAcknowledgementView | null
  readonly refused: boolean
  readonly busy: boolean
  readonly onAcknowledge: () => void
}): ReactElement {
  return (
    <Space direction="vertical" size="small">
      <Alert
        type="warning"
        showIcon={false}
        closable={false}
        message="Der gebundene Registry-Head ist abgelaufen"
        description={
          `Gebundene Registry-Version: ${String(preview.proposedSequence)} in Folge; ` +
          `beobachtete Zeit: ${String(preview.effectiveNow)}. ` +
          'Die Gültigkeit des gebundenen Vertrauensbestands ist überschritten. ' +
          'Ein Abschluss ohne ausdrückliche Bestätigung wird vom Kern abgelehnt, und ' +
          'ohne Netz kann dieses Gerät keinen frischen Head auswählen — die Bestätigung ' +
          'wird deshalb signiert festgehalten und bleibt am Eintrag nachprüfbar.'
        }
      />
      {acknowledgement?.captured === true ? (
        <Typography.Text>
          {`Signierte Bestätigung erfasst: ${acknowledgement.proofCode}.`}
        </Typography.Text>
      ) : (
        <Space direction="vertical" size="small">
          {refused ? (
            <Typography.Text>
              Es ist keine Bestätigung erfasst. Der Wirt hat keinen Nachweis ausgestellt, und
              damit bleibt der Abschluss gesperrt.
            </Typography.Text>
          ) : null}
          <Button disabled={busy} onClick={onAcknowledge}>
            Warnung bestätigen und erneut authentisieren
          </Button>
        </Space>
      )}
    </Space>
  )
}
