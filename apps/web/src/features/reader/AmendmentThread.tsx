import { Space, Typography } from 'antd'
import type { ReactElement } from 'react'

import type { ReaderAmendmentThreadView } from '../../bridge/generated-contracts'
import { FingerprintBlock } from '../../components/integrity/FingerprintBlock'
import { EntryView } from './EntryView'

/**
 * Original und Nachtraege als GETRENNTE Ansichten desselben Zusammenhangs.
 *
 * Nichts ist zusammengefuehrt und nichts ueberholt: das Original bleibt
 * stehen, wie es finalisiert wurde, jeder Nachtrag steht als eigener Eintrag
 * daneben, und ein abgewiesener Nachtrag steht mit dem Grund seiner
 * Abweisung da statt zu verschwinden. Korrekturen sind im Archiv nur als
 * Nachtrag moeglich — eine Flaeche, die das Original ausblendete oder als
 * ersetzt markierte, erfaende eine Aenderung, die es im Bestand nicht gibt.
 *
 * Gespeist aus `ReaderAmendmentThreadView`, der Projektion des Fadens aus
 * Rust; welcher Nachtrag zu welchem Original gehoert, hat `view.rs` anhand
 * der Originalreferenz entschieden.
 */
export function AmendmentThread({
  thread,
}: {
  readonly thread: ReaderAmendmentThreadView
}): ReactElement {
  return (
    <section aria-label="Nachtragszusammenhang">
      <Space orientation="vertical" size="middle">
        <Typography.Title level={3}>Original</Typography.Title>
        <EntryView entry={thread.original} />

        <Typography.Title level={3}>Nachträge</Typography.Title>
        {thread.amendments.length === 0 ? (
          <Typography.Text>Zu diesem Original liegt kein Nachtrag vor.</Typography.Text>
        ) : (
          <ol>
            {thread.amendments.map(amendment => (
              <li key={amendment.state.entryHash}>
                <EntryView entry={amendment} />
              </li>
            ))}
          </ol>
        )}

        {thread.rejected.length === 0 ? null : (
          <>
            <Typography.Title level={3}>Abgewiesene Nachträge</Typography.Title>
            <Typography.Text type="secondary">
              Diese Einträge nennen das Original, wurden aber nicht als Nachtrag angenommen. Der
              Grund steht bei jedem.
            </Typography.Text>
            <ul>
              {thread.rejected.map(rejected => (
                <li key={rejected.entryHash}>
                  <Space orientation="vertical" size="small">
                    <Typography.Text>Sequenz {rejected.sequence}</Typography.Text>
                    <FingerprintBlock
                      entries={[{ label: 'Eintragshash', value: rejected.entryHash }]}
                    />
                    <Typography.Text>
                      Grund: <Typography.Text code>{rejected.reason}</Typography.Text>
                    </Typography.Text>
                  </Space>
                </li>
              ))}
            </ul>
          </>
        )}
      </Space>
    </section>
  )
}
