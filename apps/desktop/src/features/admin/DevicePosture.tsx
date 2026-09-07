import type { ReactElement } from 'react'

import type { DevicePostureSummaryView } from '../../bridge/generated-contracts'
import { DevicePosturePanel } from '../../components/integrity/DevicePosturePanel'

/**
 * Die Geraetehaltung der Verwaltungsflaeche — eine duenne Huelle um die
 * Tafel der Erfassung.
 *
 * Dieselbe Komponente und keine zweite Fassung: `DevicePosturePanel` haelt
 * erfuellt, verletzt und „auf dieser Plattform nicht belegbar" schon
 * auseinander und zeichnet Unknown nie gruen (`design.md`:1974). Die Tafel
 * traegt ihre eigene Landmarke „Gerätehaltung"; die Verwaltungsflaeche legt
 * deshalb keine zweite darum.
 */
export function DevicePosture({
  posture,
}: {
  readonly posture: DevicePostureSummaryView | null
}): ReactElement {
  return <DevicePosturePanel posture={posture} />
}
