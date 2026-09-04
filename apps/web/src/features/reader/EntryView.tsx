import { Space, Typography } from 'antd'
import type { ReactElement } from 'react'

import type { ReaderEntryStateView, ReaderEntryView } from '../../bridge/generated-contracts'
import { ENTRY_STATUS_VALUES, VERIFICATION_STATUS_VALUES } from '../../bridge/generated-contracts'
import { FingerprintBlock } from '../../components/integrity/FingerprintBlock'
import { DecorativeIcon } from '../../design/icons'
import { ServerConfirmationStatus, StatusDimension } from './StatusDimension'
import type { DimensionColor } from './StatusDimension'

// Die Indizes in die generierten Tabellen — die einzige Verbindung dieser
// Datei zu einem Statuswortlaut. Ein abgeschriebenes Literal fiele in
// `bridge/no-hand-written-contracts.test.ts`.
const [VERIFIED, GAP] = VERIFICATION_STATUS_VALUES
const [PRESENT] = ENTRY_STATUS_VALUES

/**
 * Die Farbe der Verifikationsmarke — ein HINWEIS neben dem Wortlaut.
 *
 * Nur ein verifizierter Eintrag ist gruen, nur eine Fehlstelle in der Kette
 * ist gelb. Die uebrigen Zustaende (ohne eigenen Grant, unbekannter Absender,
 * fremdes Schema) sind technische Aussagen und keine Befunde ueber die Kette;
 * sie bleiben neutral. Ein ungueltiges Objekt erscheint hier nie — es lebt
 * allein unter Prüfprobleme, und das entscheidet `view.rs`, nicht diese Datei.
 */
function verificationColor(verification: ReaderEntryStateView['verification']): DimensionColor {
  if (verification === VERIFIED) {
    return 'success'
  }
  return verification === GAP ? 'warning' : 'default'
}

/**
 * Der Zeitpunkt in der Zeitzone des Einsatzes, als DARSTELLUNG.
 *
 * Die Bruecke gibt UTC-Millisekunden und die IANA-Zeitzone heraus, und der
 * Browser formatiert; das ist keine Sicherheitsentscheidung. Kennt der Browser
 * die Zone nicht, wirft `Intl` einen `RangeError` — dann steht die Zeit in UTC
 * und der Satz daneben sagt, warum. Eine still auf die Zone des Lesers
 * zurueckfallende Anzeige waere eine falsche Ortszeit ohne Hinweis.
 */
export function formatOccurredAt(ms: number, timezone: string): string {
  const style = { dateStyle: 'medium', timeStyle: 'short' } as const
  try {
    return `${new Intl.DateTimeFormat('de-DE', { ...style, timeZone: timezone }).format(ms)} (${timezone})`
  } catch {
    const utc = new Intl.DateTimeFormat('de-DE', { ...style, timeZone: 'UTC' }).format(ms)
    return `${utc} UTC — die Zeitzone „${timezone}" ist diesem Browser unbekannt`
  }
}

/**
 * Die drei Dimensionen des technischen Zustands, NEBENEINANDER.
 *
 * Jede an ihrem eigenen Traeger: Verifikation, Eintragszustand und
 * Server-Bestaetigung sind drei Aussagen, und eine zusammengefaltete waere
 * `design.md` §17.4 zuwider.
 */
function EntryStateBlock({ state }: { readonly state: ReaderEntryStateView }): ReactElement {
  return (
    <Space orientation="vertical" size="small">
      <StatusDimension
        label="Verifikation"
        value={state.verification}
        color={verificationColor(state.verification)}
        {...(state.detailCode === null ? {} : { description: `Befundcode ${state.detailCode}` })}
      />
      <StatusDimension
        label="Eintragszustand"
        value={state.entryState}
        color={state.entryState === PRESENT ? 'default' : 'warning'}
      />
      <ServerConfirmationStatus value={state.serverConfirmation} />
      <Typography.Text>Sequenz {state.sequence}</Typography.Text>
      <FingerprintBlock entries={[{ label: 'Eintragshash', value: state.entryHash }]} />
    </Space>
  )
}

/**
 * EIN Eintrag: sein fachlicher Inhalt, falls entschluesselt, und sein
 * technischer Zustand immer.
 *
 * Einsatznummer, Einsatzzeit und Stichwort kommen AUSSCHLIESSLICH aus
 * `entry.incident` — dem Geschwister von `entry.state`, das nur ein
 * entschluesselter Datensatz fuellt (`design.md` §17.2). Ist es `null`, gibt
 * es keinen Einsatz zu zeigen: keine Ueberschrift „Einsatznummer", kein
 * `article`, keine leere Maske — nur Sequenz, Hash und die drei Zustaende.
 * Ein Eintrag ohne eigenen Grant sieht deshalb technisch aus, weil er es ist.
 */
export function EntryView({ entry }: { readonly entry: ReaderEntryView }): ReactElement {
  const { incident, state } = entry
  if (incident === null) {
    return (
      <Space orientation="vertical" size="small">
        <Space size="small">
          <DecorativeIcon name="locked" />
          <Typography.Text>Nicht entschlüsselter Eintrag</Typography.Text>
        </Space>
        <EntryStateBlock state={state} />
      </Space>
    )
  }
  return (
    <article aria-label={`Einsatz ${incident.incidentNumber}`}>
      <Space orientation="vertical" size="small">
        <Typography.Title level={4}>Einsatznummer {incident.incidentNumber}</Typography.Title>
        <Typography.Text>
          Einsatzzeit: {formatOccurredAt(incident.occurredAtStartMs, incident.timezone)}
        </Typography.Text>
        <Typography.Text>Stichwort: {incident.keyword}</Typography.Text>
        <EntryStateBlock state={state} />
      </Space>
    </article>
  )
}
