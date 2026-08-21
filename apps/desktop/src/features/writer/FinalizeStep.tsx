import { Alert, Button, Space, Typography } from 'antd'
import type { ReactElement } from 'react'

import { StaleRegistryWarning } from './StaleRegistryWarning'
import { STALE_DECISION_VALUES } from '../../bridge/generated-contracts'
import type {
  FinalizationPreviewView,
  StaleAcknowledgementView,
  StaleDecision,
} from '../../bridge/generated-contracts'
import { IrreversibleActionConfirm } from '../../components/integrity/IrreversibleActionConfirm'

const [FRESH, STALE_ACKNOWLEDGEABLE, HARD_BLOCK] = STALE_DECISION_VALUES

/**
 * Ob ein Zustand ueberhaupt eine Abschlusshandhabe erlaubt — als ERSCHOEPFENDE
 * Abbildung ueber die geschlossene Aufzaehlung.
 *
 * `Record<StaleDecision, boolean>` mit BERECHNETEN Schluesseln: der Uebersetzer
 * verlangt jeden Arm (ein vierter bricht die Uebersetzung, statt still in einen
 * Vorgabefall zu fallen), und die Schluessel stehen unzitiert, also wiederholt
 * diese Datei kein Kontraktliteral. StaleAcknowledgeable steht bewusst auf
 * false: die Handhabe entsteht dort erst mit der Bestaetigung, die der WIRT
 * erfasst.
 */
const PERMITS_FINALIZE: Record<StaleDecision, boolean> = {
  [FRESH]: true,
  [STALE_ACKNOWLEDGEABLE]: false,
  [HARD_BLOCK]: false,
}

/**
 * Der Abschluss — unwiderruflich, mit eigener Bestaetigung und eigener nativer
 * Wiederanmeldung.
 *
 * Drei Ausgaenge, und sie sind verschieden:
 *
 * * Fresh — die Handhabe steht.
 * * StaleAcknowledgeable — die dauerhafte Warnung steht, und die Handhabe
 *   entsteht ERST mit einer vom Wirt erfassten Bestaetigung.
 * * HardBlock — es gibt KEINE Handhabe. Kein deaktivierter Knopf, kein
 *   „trotzdem": Evidence Grade, ein signiertes `block` und eine erschoepfte
 *   Lease sind Sperren und keine Rueckfragen.
 */
export function FinalizeStep({
  preview,
  violation,
  acknowledgement,
  acknowledgementRefused,
  busy,
  onAcknowledge,
  onFinalize,
  onBack,
}: {
  readonly preview: FinalizationPreviewView | null
  /** Die offene Verletzung des Eingabevertrags, oder `null`. */
  readonly violation: string | null
  readonly acknowledgement: StaleAcknowledgementView | null
  readonly acknowledgementRefused: boolean
  readonly busy: boolean
  readonly onAcknowledge: () => void
  readonly onFinalize: () => void
  readonly onBack: () => void
}): ReactElement {
  const acknowledged = acknowledgement?.captured === true
  const decision = preview?.staleDecision
  // Zwei verschiedene Aussagen, und sie duerfen nicht zusammenfallen:
  //
  // * `offers` — GIBT ES die Handhabe. Nein bei einer Sperre und nein bei einer
  //   unbestaetigten Veralterung; dort waere ein deaktivierter Knopf die
  //   Andeutung, es koennte gleich doch gehen.
  // * `ready` — ist sie ausfuehrbar. Nein ohne erfuellten Eingabevertrag und
  //   nein ohne Vorschau des Wirts, denn der Abschluss rechnet gegen genau
  //   diese Vorschau nach.
  const permitted = decision === undefined || PERMITS_FINALIZE[decision]
  const offers = permitted || (decision === STALE_ACKNOWLEDGEABLE && acknowledged)
  const ready = !busy && violation === null && preview !== null

  return (
    <Space direction="vertical" size="middle">
      {decision === STALE_ACKNOWLEDGEABLE && preview !== null ? (
        <StaleRegistryWarning
          preview={preview}
          acknowledgement={acknowledgement}
          refused={acknowledgementRefused}
          busy={busy}
          onAcknowledge={onAcknowledge}
        />
      ) : null}
      {decision === HARD_BLOCK ? (
        <Alert
          type="error"
          showIcon={false}
          closable={false}
          message="Der Abschluss ist gesperrt"
          description={
            'Der gebundene Vertrauensbestand ist nicht mehr gültig, oder die Sequenzlease ist ' +
            'erschöpft. Es gibt für diesen Zustand keine Bestätigung und keinen Weiterweg; ' +
            'der Bestand muss aufgefrischt werden.'
          }
        />
      ) : null}
      {offers ? (
        <IrreversibleActionConfirm
          prompt="Dieser Schritt ist unwiderruflich."
          consequence={
            'Nach dem Abschluss gibt es keinen Zugriff auf den Inhalt dieses Eintrags — weder ' +
            'lesend noch ändernd. Korrekturen sind ausschließlich spätere, eigene Nachträge.'
          }
          checkboxLabel="Ich habe geprüft und bestätige den unwiderruflichen Abschluss."
          confirmLabel="Unwiderruflich finalisieren"
          ready={ready}
          onConfirm={onFinalize}
        />
      ) : null}
      <Space size="small">
        <Button onClick={onBack}>Zurück zur Erfassung</Button>
        <Typography.Text type="secondary">
          Das gewöhnliche Speichern liegt auf der Erfassung und ist eine andere Handhabe.
        </Typography.Text>
      </Space>
    </Space>
  )
}
