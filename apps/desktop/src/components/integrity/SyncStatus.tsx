import { Space, Typography } from 'antd'
import type { ReactElement } from 'react'

import { SYNC_STATUS_VALUES } from '../../bridge/generated-contracts'
import type { SyncStateView, SyncStatus as SyncStatusValue } from '../../bridge/generated-contracts'
import { DecorativeIcon } from '../../design/icons'

/**
 * Die vier normativen Zustaende, AUS dem emittierten Array entpackt.
 *
 * Kein Literal in dieser Datei, und das ist keine Stilfrage: die vier Namen
 * sind woertliche Oberflaechenkopie einer globalen Randbedingung, ihre EINE
 * Quelle ist `crates/ea-archive-fs/src/publication_queue.rs`, und
 * `no-hand-written-contracts.test.ts` faellt, sobald hier einer davon in
 * Anfuehrungszeichen steht. Die Zerlegung eines `as const`-Arrays traegt die
 * Literaltypen, also prueft der Uebersetzer auch, dass es genau vier sind.
 */
const [LOCALLY_SAVED, UPLOAD_PENDING, SYNCHRONIZED, FAILED] = SYNC_STATUS_VALUES

/**
 * Der Zustand und sein Symbol — mit BERECHNETEN Schluesseln.
 *
 * `Record<SyncStatus, boolean>` verlangt vom Uebersetzer jeden der vier Arme,
 * und die berechneten Schluessel halten die Literale draussen. Ein fuenfter
 * Zustand kann nicht entstehen: die Vereinigung ist geschlossen, und die
 * Detailursache steht DANEBEN.
 */
const CONFIRMED: Record<SyncStatusValue, boolean> = {
  [LOCALLY_SAVED]: true,
  [UPLOAD_PENDING]: false,
  [SYNCHRONIZED]: true,
  [FAILED]: false,
}

/**
 * Der Sync-Zustand mit seiner Detailursache DANEBEN.
 *
 * Die Ursache ist niemals ein fuenfter Zustand: verliert ein freigegebenes
 * Netzbackend eine zugesicherte Faehigkeit, bleibt der Zustand derselbe und die
 * Ursache tritt als eigener Text daneben.
 *
 * `role="status"` mit einem NAMEN, weil dieselbe Komponente an zwei Stellen
 * steht — als Speicherzustand des Entwurfs und als Veroeffentlichungszustand
 * nach dem Abschluss — und eine Bildschirmleseausgabe die zwei unterscheiden
 * muss.
 */
export function SyncStatus({
  state,
  label,
}: {
  readonly state: SyncStateView
  readonly label: string
}): ReactElement {
  const confirmed = CONFIRMED[state.status]
  return (
    // `data-confirmed` traegt die Bestaetigung als eigenes, PRUEFBARES
    // Merkmal. Bis Stufe 3 lebte sie ausschliesslich im Symbol, und das Symbol
    // ist `aria-hidden` und dekorativ: die Unterscheidung „bestaetigt / nicht
    // bestaetigt" stand damit nirgends, wo ein Zeuge oder eine
    // Bildschirmleseausgabe sie haette finden koennen. Sie ist ein ATTRIBUT
    // und kein Text, weil sie keine zweite Beschriftung neben den vier
    // normativen Namen sein darf.
    <div role="status" aria-label={label} data-confirmed={confirmed}>
      <Space size="small">
        <DecorativeIcon
          name={confirmed ? 'verified' : 'warning'}
          state={confirmed ? 'confirmed' : 'default'}
        />
        <Typography.Text>{state.status}</Typography.Text>
        {state.detailCause === null ? null : (
          <Typography.Text type="secondary">{state.detailCause}</Typography.Text>
        )}
      </Space>
    </div>
  )
}
