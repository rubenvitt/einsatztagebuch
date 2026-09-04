import { Alert, Button, Input, Space, Typography } from 'antd'
import { useId, useState } from 'react'
import type { FormEvent, ReactElement } from 'react'

import type { ReaderSearchHitView } from '../../bridge/generated-contracts'
import type { ReaderBridge, ReaderSearchFilters } from '../../bridge/reader-bridge'
import { DecorativeIcon } from '../../design/icons'

/**
 * Eine Zeitgrenze aus dem `datetime-local`-Feld, als Millisekunden.
 *
 * Ein leeres Feld ist KEINE Grenze und wird deshalb weggelassen statt auf
 * null gesetzt; was der Browser nicht als Zeitpunkt lesen kann, ebenso. Das
 * ist die Umformung eines Eingabewerts an der Grenze und keine Deutung: ob
 * eine halbe Grenze ein halboffener Zeitraum ist, entscheidet `view.rs`.
 */
function boundFrom(field: string): number | undefined {
  if (field.length === 0) {
    return undefined
  }
  const ms = new Date(field).getTime()
  return Number.isNaN(ms) ? undefined : ms
}

/** Der Zeitpunkt eines Treffers — in UTC, weil der Treffer keine Zone traegt. */
function formatHitTime(ms: number): string {
  return `${new Intl.DateTimeFormat('de-DE', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' }).format(ms)} UTC`
}

/** Der Fehlschlag in der Form, in der Rust ihn gemeldet hat. */
function failureText(reason: unknown): string {
  return reason instanceof Error ? reason.message : String(reason)
}

/**
 * Die Suche: vier Filter, unveraendert an die Bruecke, und die Liste, die
 * zurueckkommt.
 *
 * Diese Flaeche filtert nichts selbst, sortiert nichts selbst und kennt keinen
 * Feldwert, den sie nicht angezeigt bekommen hat: der invertierte Index liegt
 * verschluesselt in Rust, und welcher Eintrag zu „Brand" oder zu einem
 * Fahrzeug gehoert, weiss nur er. Die Trefferliste ist die Antwort der
 * Bruecke in ihrer Reihenfolge — auch wenn sie leer ist.
 */
export function SearchPanel({
  search,
  onOpen,
}: {
  readonly search: ReaderBridge['search']
  /** Ein Treffer wird ueber seinen Eintragshash geoeffnet; wie, entscheidet die Seite. */
  readonly onOpen: (entryHash: string) => void
}): ReactElement {
  const fromId = useId()
  const toId = useId()
  const keywordId = useId()
  const vehicleId = useId()
  const personId = useId()
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [keyword, setKeyword] = useState('')
  const [vehicle, setVehicle] = useState('')
  const [person, setPerson] = useState('')
  const [hits, setHits] = useState<readonly ReaderSearchHitView[] | undefined>(undefined)
  const [failure, setFailure] = useState<string | undefined>(undefined)

  function submit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault()
    const fromMs = boundFrom(from)
    const toMs = boundFrom(to)
    const filters: ReaderSearchFilters = {
      ...(fromMs === undefined ? {} : { fromMs }),
      ...(toMs === undefined ? {} : { toMs }),
      keyword,
      vehicle,
      person,
    }
    void search(filters).then(
      found => {
        setFailure(undefined)
        setHits(found)
      },
      (reason: unknown) => {
        // Ein Fehlschlag loescht die vorige Liste: Treffer einer anderen
        // Anfrage stehen zu lassen, waere die gefaehrlichere Hoeflichkeit.
        setHits(undefined)
        setFailure(failureText(reason))
      },
    )
  }

  return (
    <section aria-label="Suche">
      <form onSubmit={submit}>
        <Space orientation="vertical" size="small">
          <Space size="small">
            <DecorativeIcon name="search" />
            <Typography.Title level={3}>Suche</Typography.Title>
          </Space>
          <Space size="small" wrap>
            <label htmlFor={fromId}>Von</label>
            <Input
              id={fromId}
              type="datetime-local"
              value={from}
              onChange={event => setFrom(event.target.value)}
            />
            <label htmlFor={toId}>Bis</label>
            <Input
              id={toId}
              type="datetime-local"
              value={to}
              onChange={event => setTo(event.target.value)}
            />
          </Space>
          <Space size="small" wrap>
            <label htmlFor={keywordId}>Stichwort</label>
            <Input id={keywordId} value={keyword} onChange={event => setKeyword(event.target.value)} />
            <label htmlFor={vehicleId}>Fahrzeug</label>
            <Input id={vehicleId} value={vehicle} onChange={event => setVehicle(event.target.value)} />
            <label htmlFor={personId}>Person</label>
            <Input id={personId} value={person} onChange={event => setPerson(event.target.value)} />
          </Space>
          <Button type="primary" htmlType="submit">
            Suchen
          </Button>
        </Space>
      </form>

      {failure === undefined ? null : (
        <Alert type="error" showIcon title="Die Suche liess sich nicht ausführen." description={failure} />
      )}

      {hits === undefined ? null : hits.length === 0 ? (
        <Typography.Text>Kein Eintrag entspricht diesen Filtern.</Typography.Text>
      ) : (
        <ol aria-label="Suchergebnisse">
          {hits.map(hit => (
            <li key={hit.entryHash}>
              <Space size="small" wrap>
                <Typography.Text>
                  Einsatz {hit.incidentNumber} · Sequenz {hit.sequence} ·{' '}
                  {formatHitTime(hit.occurredAtStartMs)}
                </Typography.Text>
                <Button size="small" onClick={() => onOpen(hit.entryHash)}>
                  Treffer öffnen
                </Button>
              </Space>
            </li>
          ))}
        </ol>
      )}
    </section>
  )
}
