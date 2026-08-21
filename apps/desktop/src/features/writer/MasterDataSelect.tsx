import { Button, Input, Space, Tag, Typography } from 'antd'
import type { ReactElement } from 'react'

import { PatientDataWarning } from '../../components/integrity/PatientDataWarning'

/** Eine auswaehlbare oder ausgewaehlte Zeile — Stammdaten ODER ad hoc. */
export type SelectableRow = {
  /** Die Stammdatenkennung, oder der Anzeigename bei einem Ad-hoc-Eintrag. */
  readonly key: string
  readonly displayName: string
  readonly detail: string | null
  readonly adHoc: boolean
}

/** Das Begruendungsfeld, das NUR bei leerer Liste existiert. */
export type EmptyReasonField = {
  readonly label: string
  readonly value: string
  readonly onChange: (value: string) => void
}

/**
 * Die durchsuchbare, favorisierbare Mehrfachauswahl fuer Personal und
 * Fahrzeuge.
 *
 * Drei Zusagen tragen sie:
 *
 * 1. **Ad-hoc ist HERVORGEHOBEN.** Ein Eintrag ohne Stammdatenzeile traegt
 *    keine Revision und keine Provenienz; er sieht deshalb anders aus, damit
 *    niemand ihn fuer eine importierte Zeile haelt.
 * 2. **Die Begruendung existiert nur bei leerer Liste.** Das ist die
 *    biconditionale Regel der Stufe 1 (`EA-SCHEMA-LIST-REASON`) als Gestalt und
 *    nicht als Pruefung: was nicht da ist, kann nicht falsch gesetzt werden.
 * 3. **Die Suche fragt den WIRT.** Diese Komponente haelt kein Verzeichnis und
 *    filtert keine Stammdaten selbst; sie zeigt, was das Kommando liefert.
 */
export function MasterDataSelect({
  kind,
  idPrefix,
  searchLabel,
  query,
  results,
  selected,
  favorites,
  emptyReason,
  onQuery,
  onTake,
  onAdHoc,
  onRemove,
  onToggleFavorite,
}: {
  /** `Person` oder `Fahrzeug` — der Wortstamm jeder Handhabenbezeichnung. */
  readonly kind: string
  readonly idPrefix: string
  readonly searchLabel: string
  readonly query: string
  readonly results: readonly SelectableRow[]
  readonly selected: readonly SelectableRow[]
  readonly favorites: readonly string[]
  readonly emptyReason: EmptyReasonField | null
  readonly onQuery: (value: string) => void
  readonly onTake: (row: SelectableRow) => void
  readonly onAdHoc: () => void
  readonly onRemove: (row: SelectableRow) => void
  readonly onToggleFavorite: (row: SelectableRow) => void
}): ReactElement {
  const searchId = `${idPrefix}-suche`
  const reasonId = `${idPrefix}-begruendung`
  return (
    <section aria-label={searchLabel}>
      <Space direction="vertical" size="small">
        <label htmlFor={searchId}>{searchLabel}</label>
        <Input
          id={searchId}
          value={query}
          onChange={(event) => {
            onQuery(event.target.value)
          }}
        />
        <Button onClick={onAdHoc}>{`${kind} hinzufügen`}</Button>
        {results.length === 0 ? null : (
          <ul aria-label={`${searchLabel} — Treffer`}>
            {results.map((row) => (
              <li key={row.key}>
                <Space size="small">
                  <Typography.Text>{row.displayName}</Typography.Text>
                  <Button
                    onClick={() => {
                      onTake(row)
                    }}
                  >
                    {`${kind} ${row.displayName} übernehmen`}
                  </Button>
                </Space>
              </li>
            ))}
          </ul>
        )}
        <ul aria-label={`${kind} — Auswahl`}>
          {selected.map((row) => (
            <li key={row.key}>
              <Space size="small">
                <Typography.Text>{row.displayName}</Typography.Text>
                {row.detail === null ? null : (
                  <Typography.Text type="secondary">{row.detail}</Typography.Text>
                )}
                {row.adHoc ? <Tag color="warning">ad hoc, ohne Stammdatenzeile</Tag> : null}
                {favorites.includes(row.key) ? <Tag color="success">Favorit</Tag> : null}
                <Button
                  onClick={() => {
                    onToggleFavorite(row)
                  }}
                >
                  {favorites.includes(row.key)
                    ? `${kind} ${row.displayName} nicht mehr merken`
                    : `${kind} ${row.displayName} merken`}
                </Button>
                <Button
                  onClick={() => {
                    onRemove(row)
                  }}
                >
                  {`${kind} ${row.displayName} entfernen`}
                </Button>
              </Space>
            </li>
          ))}
        </ul>
        {emptyReason === null ? null : (
          <Space direction="vertical" size="small">
            <label htmlFor={reasonId}>{emptyReason.label}</label>
            <Input
              id={reasonId}
              value={emptyReason.value}
              onChange={(event) => {
                emptyReason.onChange(event.target.value)
              }}
            />
            {/*
              Die Begruendung ist ein Freitext, der PERSISTIERT wird: ihr Wert
              liegt als `personnel_empty_reason` bzw. `vehicles_empty_reason` in
              der Nutzlast des Entwurfs und spaeter im Eintrag. Sie traegt
              deshalb dieselbe Warnung wie jedes andere Freitextfeld — anders
              als das Suchfeld oben, dessen Inhalt in keine Nutzlast geht.
            */}
            <PatientDataWarning />
          </Space>
        )}
      </Space>
    </section>
  )
}
