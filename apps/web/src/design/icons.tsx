import { LockKeyIcon } from '@phosphor-icons/react/dist/csr/LockKey'
import { MagnifyingGlassIcon } from '@phosphor-icons/react/dist/csr/MagnifyingGlass'
import { ShieldCheckIcon } from '@phosphor-icons/react/dist/csr/ShieldCheck'
import { WarningIcon } from '@phosphor-icons/react/dist/csr/Warning'
import type { ReactElement } from 'react'

/**
 * Die Symbole der Reader-Schale — je EIN Modulpfad pro Symbol.
 *
 * `@phosphor-icons/react` (der Katalogeinstieg) laedt jedes Symbol der Familie;
 * `dist/csr/<Name>` laedt genau eines. Kein Platzhalterimport und kein
 * dynamischer Import; die vom Plan ausgeschlossene zweite Symbolbibliothek ist
 * keine Abhaengigkeit dieses Pakets und wird deshalb hier auch nicht genannt.
 *
 * VIER und nicht sechs: `capture` und `resuming` des Desktops sind
 * Writer-Begriffe — der Reader erfasst nichts und nimmt keinen Abschluss
 * wieder auf. `search` kam mit der Reader-Flaeche dazu, so wie jede spaetere
 * Flaeche ihren Eintrag hier anhaengt.
 */
export const eaIcons = {
  verified: ShieldCheckIcon,
  warning: WarningIcon,
  locked: LockKeyIcon,
  search: MagnifyingGlassIcon,
} as const

export type EaIconName = keyof typeof eaIcons

/**
 * Der Zustand, der die Strichstaerke entscheidet.
 *
 * `confirmed` heisst „positiv bestaetigt oder aktiv" und ist der EINZIGE
 * Zustand, der die gefuellte Variante bekommt.
 */
export type EaIconState = 'default' | 'confirmed'

/**
 * Ein DEKORATIVES Symbol: es traegt `aria-hidden` und keinen zugaenglichen
 * Namen.
 *
 * Die Aussage steht immer im Text daneben, nie im Symbol und nie in der Farbe —
 * Sicherheits-, Integritaets-, Evidenz- und Vernichtungszustand nennen ihren
 * Wortlaut ausdruecklich (globale Randbedingung). Ein Symbol, das eine eigene
 * Aussage traegt, gibt es hier deshalb nicht.
 */
export function DecorativeIcon({
  name,
  state = 'default',
  size = 18,
}: {
  readonly name: EaIconName
  readonly state?: EaIconState
  readonly size?: number
}): ReactElement {
  const Icon = eaIcons[name]
  return (
    <Icon
      aria-hidden="true"
      focusable={false}
      size={size}
      weight={state === 'confirmed' ? 'fill' : 'regular'}
    />
  )
}
