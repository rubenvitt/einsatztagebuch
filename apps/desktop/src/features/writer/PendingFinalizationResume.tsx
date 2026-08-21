import { Alert, Space, Typography } from 'antd'
import type { ReactElement } from 'react'

import type { PendingResumeOutcomeView } from '../../bridge/generated-contracts'
import { FingerprintBlock } from '../../components/integrity/FingerprintBlock'
import { SyncStatus } from '../../components/integrity/SyncStatus'

/**
 * Die angetroffene Finalisierung — GENAU zwei sichtbare Ausgaenge.
 *
 * 1. Die Fortsetzung einer vorbereiteten Transaktion, mit Fortschritt: der Kern
 *    vollendet aus den gespeicherten exakten Bytes, es wird nichts neu
 *    serialisiert, und die Oberflaeche zeigt Phase, Sequenz und den
 *    Veroeffentlichungszustand.
 * 2. Die Blockade nach dem Zurueckspielen eines Backups. Sie traegt den Text
 *    der ausstehenden externen Head-Reconciliation und KEINE
 *    Abschlusshandhabe — nicht eine deaktivierte, sondern keine.
 *
 * Ein dritter Ausgang ist nicht formulierbar: `blocked_code` entscheidet, und
 * beide Zweige stehen hier.
 */
export function PendingFinalizationResume({
  outcome,
}: {
  readonly outcome: PendingResumeOutcomeView
}): ReactElement {
  if (outcome.blockedCode !== null) {
    return (
      <section aria-label="Angetroffene Finalisierung">
        <Alert
          type="error"
          showIcon={false}
          closable={false}
          message="Externe Head-Reconciliation ausstehend"
          description={
            `Der Wirt verweigert die Fortsetzung (${outcome.blockedCode}). ` +
            'Dieses Gerät wurde offenbar aus einem Backup zurückgespielt, und eine bereits ' +
            'verbrauchte Sequenz darf kein zweites Mal entstehen. Bis die Kette gegen den ' +
            'externen Anker abgeglichen ist, gibt es hier keinen Abschluss.'
          }
        />
      </section>
    )
  }
  return (
    <section aria-label="Angetroffene Finalisierung">
      <Space direction="vertical" size="small">
        <Typography.Text strong>Eine vorbereitete Finalisierung wird vollendet</Typography.Text>
        <progress aria-label="Fertigstellung läuft" />
        <Typography.Text>
          Der Abschluss wird aus den gespeicherten exakten Bytes vollendet. Es wird nichts neu
          serialisiert, und es entsteht keine zweite Veröffentlichung.
        </Typography.Text>
        <FingerprintBlock
          entries={[
            { label: 'Erreichte Phase', value: outcome.resume.phase },
            {
              label: 'Sequenz',
              value:
                outcome.resume.outcomeSequence === null
                  ? 'nicht gemeldet'
                  : String(outcome.resume.outcomeSequence),
            },
            {
              label: 'Ausgang',
              value: outcome.resume.outcomeCode ?? 'nicht gemeldet',
            },
          ]}
        />
        {outcome.sync === null ? null : (
          <SyncStatus state={outcome.sync} label="Veröffentlichung" />
        )}
      </Space>
    </section>
  )
}
