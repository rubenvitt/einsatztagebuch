import { Button, Space, Typography } from 'antd'
import { useState } from 'react'
import type { ReactElement } from 'react'

import type { DiscardStateView } from '../../bridge/generated-contracts'
import { IrreversibleActionConfirm } from '../../components/integrity/IrreversibleActionConfirm'

/**
 * Das Verwerfen des aktiven Entwurfs.
 *
 * Zwei Stufen, wie beim Abschluss: eine eigene Handhabe oeffnet die
 * Bestaetigung, und erst die Bestaetigung samt nativer Wiederanmeldung fuehrt
 * sie aus. Das gewoehnliche Speichern nimmt diesen Weg nie.
 *
 * Verwerfen ist unwiderruflich UND fortsetzbar: der Kern bucht die Absicht
 * dauerhaft, BEVOR etwas Unwiderrufliches geschieht, und jeder Neustart danach
 * ist eine Fortsetzung. Deshalb nennt diese Flaeche den Phasencode, den der
 * Wirt zurueckgibt — er ist die Aussage darueber, wo eine unterbrochene
 * Verwerfung stand.
 */
/**
 * Die zwei Phasencodes, bei denen NICHTS fortzusetzen ist.
 *
 * Sie stehen als Literale hier, weil `DiscardStateView.phaseCode` am Draht eine
 * freie Zeichenkette ist — `generated-contracts.ts` emittiert dafür keine
 * Vereinigung, es gibt also keinen generierten Namen, den diese Datei einlesen
 * könnte. Die EINE Quelle bleibt trotzdem der Wirt
 * (`src-tauri/src/commands/writer.rs::restart_state_code` und
 * `ea_draft::PREPARED_FINALIZATION_BEATS_DISCARD_INTENT`): der Zeuge
 * `the_shell_names_every_discard_phase_without_a_continuation` in
 * `src-tauri/src/lib.rs` liest BEIDE Seiten und fällt, sobald eine davon
 * fortläuft.
 */
const PHASE_DRAFT_UNCHANGED = 'OriginalDraftUnchanged'
const PHASE_FINALIZATION_WINS = 'PreparedFinalizationBeatsDiscardIntent'

/**
 * Was der Bediener über diesen Ausgang liest — und ob es etwas fortzusetzen
 * gibt.
 *
 * Der Satz hängt an der PHASE und nicht bloß an `complete`. Ohne diese
 * Unterscheidung stünde „Verwerfen gebucht … die Fortsetzung steht aus" auch
 * über einem unveränderten Entwurf (es ist nichts gebucht) und über der
 * Vorrangregel der vorbereiteten Finalisierung (es wird nichts fortgesetzt) —
 * beides wäre eine Aussage über einen Vorgang, den es nicht gibt, samt einer
 * Handhabe, die ihn nicht fortsetzen kann.
 */
function outcomeOf(state: DiscardStateView): { readonly text: string; readonly resumable: boolean } {
  if (state.complete) {
    return {
      text: `Verwerfen gebucht — Phase ${state.phaseCode}. Der leere Entwurf steht.`,
      resumable: false,
    }
  }
  if (state.phaseCode === PHASE_DRAFT_UNCHANGED) {
    return { text: 'Nichts gebucht — der Entwurf ist unverändert.', resumable: false }
  }
  if (state.phaseCode === PHASE_FINALIZATION_WINS) {
    return {
      text: 'Eine vorbereitete Finalisierung liegt vor; kein Verwerfen wird begonnen oder fortgesetzt.',
      resumable: false,
    }
  }
  return {
    text:
      `Verwerfen gebucht — Phase ${state.phaseCode}. ` +
      'Die Fortsetzung steht aus; jeder Neustart nimmt sie wieder auf.',
    resumable: true,
  }
}

export function DiscardDraftAction({
  busy,
  onDiscard,
  onResume,
  state,
}: {
  readonly busy: boolean
  readonly onDiscard: () => void
  readonly onResume: () => void
  readonly state: DiscardStateView | null
}): ReactElement {
  const [open, setOpen] = useState(false)
  return (
    <Space direction="vertical" size="small">
      {state !== null ? null : open ? (
        <IrreversibleActionConfirm
          prompt="Der aktive Entwurf wird unwiderruflich verworfen."
          consequence={
            'Chiffrat und Entwurfsschlüssel gehen fort, und an ihrer Stelle entsteht ein ' +
            'dauerhaft leerer Entwurf. Eine vorbereitete Finalisierung gewinnt an jedem ' +
            'Eingang gegen diese Absicht.'
          }
          checkboxLabel="Ich bestätige, dass der Entwurf unwiderruflich verworfen wird."
          confirmLabel="Verwerfen bestätigen"
          ready={!busy}
          onConfirm={onDiscard}
        />
      ) : (
        <Button
          danger
          onClick={() => {
            setOpen(true)
          }}
        >
          Entwurf verwerfen
        </Button>
      )}
      {state === null ? null : (
        <Space direction="vertical" size="small">
          <Typography.Text>{outcomeOf(state).text}</Typography.Text>
          {outcomeOf(state).resumable ? (
            <Button onClick={onResume}>Verwerfen fortsetzen</Button>
          ) : null}
        </Space>
      )}
    </Space>
  )
}
