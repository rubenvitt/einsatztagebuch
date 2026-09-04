import { Alert, Button, ConfigProvider, Space, Tabs, Typography } from 'antd'
import deDE from 'antd/locale/de_DE'
import { useEffect, useState } from 'react'
import type { ReactElement } from 'react'

import type {
  ReaderAmendmentThreadView,
  ReaderEntryView,
  ReaderStandView,
  ReaderTechnicalView,
} from '../../bridge/generated-contracts'
import type { ReaderBridge } from '../../bridge/reader-bridge'
import { ChainIntegrityRail } from '../../components/integrity/ChainIntegrityRail'
import { DecorativeIcon } from '../../design/icons'
import { eaRuntimeTheme } from '../../design/tokens'
import { AmendmentThread } from './AmendmentThread'
import { EntryView } from './EntryView'
import { SearchPanel } from './SearchPanel'
import { ServerConfirmationStatus } from './StatusDimension'
import { TechnicalView } from './TechnicalView'
import { VerificationProblems } from './VerificationProblems'

/**
 * Der geladene Bestand — oder die Aussage, dass keiner offen ist.
 *
 * `undefined` heisst „noch nicht gefragt", `null` heisst „gefragt, und es
 * gibt keinen". Die zwei sind verschieden: waehrend die Bruecke antwortet,
 * steht nicht „Kein Bestand geöffnet", sondern gar nichts Behauptetes.
 */
type Loaded = { readonly stand: ReaderStandView | null }

/** Ein geoeffneter Eintrag samt dem Faden, in dem er steht — oder `null`. */
type Opened = {
  readonly entry: ReaderEntryView
  readonly thread: ReaderAmendmentThreadView | null
}

/** Der Fehlschlag in der Form, in der Rust ihn gemeldet hat. */
function failureText(reason: unknown): string {
  return reason instanceof Error ? reason.message : String(reason)
}

/**
 * Der permanent sichtbare Pruefstand des Bestandes.
 *
 * Er steht ausserhalb der Reiter, weil er die Aussage ueber den GANZEN
 * Bestand ist und kein Reiter ihn verdecken darf. Der Wortlaut ist eigener:
 * das Urteil des Berichts kommt als `fullyVerified` und traegt keinen
 * Statusbegriff — und die Zusammenfassung schreibt keinen. Die
 * Server-Bestaetigung des Bestandes steht daneben an ihrem eigenen Traeger.
 */
function VerificationSummary({ stand }: { readonly stand: ReaderStandView }): ReactElement {
  return (
    <Space orientation="vertical" size="small">
      <Space size="small">
        <DecorativeIcon
          name={stand.fullyVerified ? 'verified' : 'warning'}
          state={stand.fullyVerified ? 'confirmed' : 'default'}
        />
        <Typography.Text strong>
          {stand.fullyVerified ? 'Alle Prüfungen bestanden' : 'Prüfung mit Befund'}
        </Typography.Text>
      </Space>
      <Typography.Text type="secondary">
        {stand.entries.length} Einträge, {stand.problems.length} Prüfprobleme.
      </Typography.Text>
      <ServerConfirmationStatus value={stand.serverConfirmation} />
    </Space>
  )
}

/**
 * Die Reader-Flaeche: Pruefstand, Integritaetskette und drei Reiter ueber dem
 * EINEN geoeffneten Bestand.
 *
 * `bridge` ist PFLICHT und hat keinen Vorgabewert: die echte Bruecke spricht
 * mit dem dedizierten Worker, und `ReaderPage.test.tsx` stellt ein Doppel —
 * dieselbe Bauform wie `WriterPage` im Desktop und `OpenArchivePanel` hier.
 *
 * Ohne Bestand zeigt die Flaeche den technischen Zustand und den Weg zum
 * Oeffnen, nie einen leeren Einsatz: der Bestand entsteht im Datei-Modus,
 * und im Server-Modus fuellt ihn diese Stufe noch nicht aus dem Cache.
 */
export function ReaderPage({ bridge }: { readonly bridge: ReaderBridge }): ReactElement {
  const [loaded, setLoaded] = useState<Loaded | undefined>(undefined)
  const [failure, setFailure] = useState<string | undefined>(undefined)
  const [opened, setOpened] = useState<Opened | undefined>(undefined)
  const [technical, setTechnical] = useState<ReaderTechnicalView | undefined>(undefined)

  useEffect(() => {
    // Der Bestand wird beim Montieren EINMAL gelesen. Die Abbruchmarke haelt
    // eine spaete Antwort von einer schon abgebauten Flaeche fern.
    let cancelled = false
    void bridge.standView().then(
      stand => {
        if (!cancelled) {
          setLoaded({ stand })
        }
      },
      (reason: unknown) => {
        if (!cancelled) {
          setFailure(failureText(reason))
        }
      },
    )
    return () => {
      cancelled = true
    }
  }, [bridge])

  function openEntry(entryHash: string): void {
    void Promise.all([bridge.entryView(entryHash), bridge.amendmentThread(entryHash)]).then(
      ([entry, thread]) => {
        setFailure(undefined)
        setOpened({ entry, thread })
      },
      (reason: unknown) => setFailure(failureText(reason)),
    )
  }

  function openTechnical(entryHash: string): void {
    void bridge.technicalView(entryHash).then(
      view => {
        setFailure(undefined)
        setTechnical(view)
      },
      (reason: unknown) => setFailure(failureText(reason)),
    )
  }

  function closeStand(): void {
    void bridge.closeStand().then(
      () => {
        setOpened(undefined)
        setTechnical(undefined)
        setLoaded({ stand: null })
      },
      (reason: unknown) => setFailure(failureText(reason)),
    )
  }

  const stand = loaded?.stand

  return (
    <ConfigProvider locale={deDE} theme={eaRuntimeTheme}>
      <Space orientation="vertical" size="middle">
        <section aria-label="Prüfstand">
          {loaded === undefined ? (
            <Typography.Text>Der Bestand wird gelesen.</Typography.Text>
          ) : loaded.stand === null ? (
            <Space orientation="vertical" size="small">
              <Space size="small">
                <DecorativeIcon name="locked" />
                <Typography.Text strong>Kein Bestand geöffnet</Typography.Text>
              </Space>
              <Typography.Text>
                Ein Archiv wird im <a href="/datei">Datei-Modus</a> geöffnet; erst danach gibt es
                hier Einträge.
              </Typography.Text>
            </Space>
          ) : (
            <VerificationSummary stand={loaded.stand} />
          )}
        </section>

        {failure === undefined ? null : (
          <Alert type="error" showIcon title="Die Brücke hat abgewiesen." description={failure} />
        )}

        {stand === undefined || stand === null ? null : (
          <>
            <ChainIntegrityRail nodes={stand.chain} />
            <Tabs
              items={[
                {
                  key: 'einsaetze',
                  label: 'Einsätze',
                  children: (
                    <Space orientation="vertical" size="middle">
                      <SearchPanel search={bridge.search} onOpen={openEntry} />
                      <section aria-label="Einträge">
                        <Typography.Title level={3}>Einträge</Typography.Title>
                        <ol>
                          {stand.entries.map(entry => (
                            <li key={entry.state.entryHash}>
                              <Space orientation="vertical" size="small">
                                <EntryView entry={entry} />
                                <Button size="small" onClick={() => openEntry(entry.state.entryHash)}>
                                  Eintrag öffnen
                                </Button>
                              </Space>
                            </li>
                          ))}
                        </ol>
                      </section>
                      {opened === undefined ? null : opened.thread === null ? (
                        <section aria-label="Geöffneter Eintrag">
                          <Typography.Title level={3}>Geöffneter Eintrag</Typography.Title>
                          <EntryView entry={opened.entry} />
                          <Typography.Text type="secondary">
                            Dieser Eintrag steht in keinem Nachtragszusammenhang.
                          </Typography.Text>
                        </section>
                      ) : (
                        <AmendmentThread thread={opened.thread} />
                      )}
                    </Space>
                  ),
                },
                {
                  key: 'probleme',
                  label: 'Prüfprobleme',
                  children: <VerificationProblems problems={stand.problems} />,
                },
                {
                  key: 'technik',
                  label: 'Technik',
                  children: (
                    <Space orientation="vertical" size="middle">
                      <section aria-label="Technik">
                        <Typography.Text>
                          Die technische Ansicht eines Eintrags, Feld für Feld aus Manifest und
                          Bericht.
                        </Typography.Text>
                        <ul>
                          {stand.entries.map(entry => (
                            <li key={entry.state.entryHash}>
                              <Button size="small" onClick={() => openTechnical(entry.state.entryHash)}>
                                Sequenz {entry.state.sequence}
                              </Button>
                            </li>
                          ))}
                        </ul>
                      </section>
                      {technical === undefined ? null : <TechnicalView view={technical} />}
                    </Space>
                  ),
                },
              ]}
            />
            <Button onClick={closeStand}>Bestand schließen</Button>
          </>
        )}
      </Space>
    </ConfigProvider>
  )
}
