import { Alert, Descriptions, Typography } from 'antd'
import type { ReactElement } from 'react'

import type { ReaderTrustAgeView } from '../../bridge/generated-contracts'

/**
 * Der Streifen, der das Alter des zuletzt bezogenen Trust-Standes ausweist.
 *
 * # Warum es diesen Streifen ueberhaupt gibt
 *
 * `web-reader-design.md` §4.2: ein Widerruf erreicht ein Geraet erst beim
 * naechsten Bezug des Trust-Bestandes. Ein dauerhaft im Datei-Modus
 * betriebenes Geraet kann deshalb eine widerrufene Bundle-Fassung weiter
 * ausfuehren, ohne es zu merken. Das Alter sichtbar zu machen ist die einzige
 * Gegenmassnahme, die dem Geraet selbst zur Verfuegung steht.
 *
 * # Eine AUFFORDERUNG und keine Sperre
 *
 * Die Ueberschreitung der Frist blockiert nichts. Wer daraus eine Sperre
 * machte, naehme einem Leser im Einsatz den Zugriff auf ein Archiv, das er
 * lesen darf — und §4.2 nennt genau diesen Unterschied.
 *
 * # Text und nicht nur Farbe
 *
 * Der Zustand steht als WORT da. `Alert` faerbt zusaetzlich, aber die Aussage
 * haengt nicht an der Farbe: die globalen Randbedingungen verlangen Text neben
 * Farbe und Symbol, und ein Streifen, der nur gelb wird, sagt einem
 * Screenreader nichts.
 *
 * # Er rechnet nichts
 *
 * Alle drei Werte kommen aus `ea_reader::reader_trust_age_view` ueber die
 * Bruecke. Diese Datei formatiert und vergleicht nichts — auch nicht die
 * Frist gegen das Alter.
 */
export function TrustAgeBanner({ view }: { readonly view: ReaderTrustAgeView }): ReactElement {
  const days = Math.floor(view.trustAgeMs / 86_400_000)
  const deadlineIsSet = view.readerTrustRefreshMs !== 0

  return (
    <section aria-label="Alter des Vertrauensbestands">
      <Alert
        type={view.trustRefreshOverdue ? 'warning' : 'info'}
        showIcon
        message={
          view.trustRefreshOverdue
            ? 'Vertrauensbestand veraltet — bitte aktualisieren'
            : 'Vertrauensbestand aktuell'
        }
        description={
          <>
            <Typography.Paragraph>
              {view.trustRefreshOverdue
                ? 'Ein Widerruf erreicht dieses Gerät erst beim nächsten Bezug des Vertrauensbestands. Die Anwendung bleibt benutzbar.'
                : 'Der Vertrauensbestand liegt innerhalb der vorgesehenen Frist.'}
            </Typography.Paragraph>
            <Descriptions size="small" column={1}>
              <Descriptions.Item label="Zuletzt bezogen vor">
                {days === 0 ? 'weniger als einem Tag' : `${days} Tagen`}
              </Descriptions.Item>
              <Descriptions.Item label="Frist">
                {deadlineIsSet
                  ? `${Math.floor(view.readerTrustRefreshMs / 86_400_000)} Tage`
                  : 'nicht gesetzt'}
              </Descriptions.Item>
            </Descriptions>
          </>
        }
      />
    </section>
  )
}
