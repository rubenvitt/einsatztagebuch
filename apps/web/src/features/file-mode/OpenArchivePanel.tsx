import { Alert, Button, ConfigProvider, Space, Typography } from 'antd'
import deDE from 'antd/locale/de_DE'
import { useId, useState } from 'react'
import type { ReactElement } from 'react'

import type { FileModeArchiveView } from '../../bridge/generated-contracts'
import { DecorativeIcon } from '../../design/icons'
import { eaRuntimeTheme } from '../../design/tokens'
import type { FileModeBridge, FileModeHost } from './DirectoryHandle'

/**
 * Die Fläche des Datei-Modus: ein Archiv aus dem Dateisystem öffnen, ohne
 * jede Serverbeteiligung (`web-reader-design.md` §5.2 bis §5.4).
 *
 * # Zwei Wege, und der universelle IMMER
 *
 * Der universelle Weg ist ein gewöhnliches Dateifeld und nimmt die EINE
 * exportierte Datei. Er steht hier ohne Bedingung, weil er der einzige ist,
 * den jede Engine hat: `showDirectoryPicker` fehlt in Safari und Firefox, und
 * `showOpenFilePicker` fehlt in denselben zweien — eine Schaltfläche statt des
 * Feldes drückte den universellen Weg also in genau die Abhängigkeit, die er
 * vermeiden soll.
 *
 * Der Komfortweg bindet über `showDirectoryPicker` einen Ordner an. Erkannt
 * wird er als FÄHIGKEIT am übergebenen Wirtsobjekt und nie an einer
 * Browserkennung: eine Kennungsliste veraltet still, eine Fähigkeitsabfrage
 * nicht. Fehlt die Fähigkeit, erscheint der Weg GAR NICHT — eine abgeblendete
 * Schaltfläche behauptete eine Fähigkeit, die es auf diesem Wirt nicht gibt,
 * und liesse den Leser nach der Bedingung suchen, unter der sie angeht.
 *
 * # Die zwei Dimensionen aus §17.4 bleiben getrennt
 *
 * Jedes Objekt trägt gleichzeitig einen Verifikationsbegriff und einen
 * Server-Bestätigungsbegriff, und die beiden werden NICHT zusammengezogen. Im
 * Datei-Modus ist der zweite fast immer der schwächere von zwei Werten, und
 * das ist der REGELFALL und kein Mangel: es gibt hier niemanden, der eine
 * Quittung ausstellen könnte. Praktisch heisst das — kein `alert`-Element,
 * keine Fehlerfarbe, kein Ausrufezeichen-Symbol; der Wert steht als TEXT neben
 * dem Verifikationsstand, mit dem Satz daneben, der ihn erklärt.
 *
 * # Diese Fläche schreibt keinen Statusbegriff selbst
 *
 * Der Wortlaut der Server-Bestätigung wird GERENDERT und nie getippt: er kommt
 * aus `ServerConfirmationV1::label` in `ea-verify`, über das generierte DTO.
 * `bridge/no-hand-written-contracts.test.ts` verbietet jede Handkopie, und der
 * Verbotskatalog reicht weiter, als man denkt — auch die naheliegende
 * Zusammenfassung mit dem Wort aus `EvidenceStatus` fiele dort. Der Wortlaut
 * lautet deshalb `Alle Objekte geprüft` beziehungsweise
 * `Nicht alle Objekte geprüft`.
 *
 * # Was hier ausdrücklich NICHT entsteht
 *
 * Die zeilenweise Darstellung je Eintrag. Sie gehört der Reader-Oberfläche;
 * diese Fläche zeigt das Ergebnis EINES Öffnens. Und es entsteht kein neues
 * Token und keine Laufzeit-CSS: die Komponentenregeln kommen aus
 * `static-antd.css`, `eaRuntimeTheme` trägt `zeroRuntime`, und die CSP
 * blockiert jede zur Laufzeit eingespritzte Regel.
 */
export type OpenArchivePanelProps = {
  /** Das Wirtsobjekt der Fähigkeitsabfrage — übergeben, nicht global gelesen. */
  readonly host: FileModeHost
  /** Die Brücke nach Rust. Ohne Vorgabewert: siehe unten. */
  readonly bridge: FileModeBridge
}

/**
 * Der Fehlschlag in der Form, in der Rust ihn gemeldet hat.
 *
 * Kein erfundener Satz und keine eigene Übersetzung: `EA-BUNDLE-MALFORMED`
 * für eine abgeschnittene oder umbenannte Datei, `EA-ARCHIVE-UNAVAILABLE` für
 * einen Ordner ohne Berechtigung, die zwei Deckelcodes für einen zu grossen
 * Bestand. Ein hier zusammengesetzter Satz behauptete eine Lage, die diese
 * Datei nicht kennt.
 */
function failureText(reason: unknown): string {
  return reason instanceof Error ? reason.message : String(reason)
}

/**
 * BEIDE Wege in eine Fläche, `bridge` als PFLICHTEIGENSCHAFT.
 *
 * Ohne Vorgabewert, und das ist gemessen und keine Vorliebe: die echte Brücke
 * in `./DirectoryHandle` spricht mit dem dedizierten Worker, und ein
 * Vorgabewert zöge ihn in jeden Lauf, der nur diese Datei rendert. Gestellt
 * wird sie an der Route in `src/main.tsx`.
 */
export function OpenArchivePanel({ host, bridge }: OpenArchivePanelProps): ReactElement {
  const fileInputId = useId()
  const [view, setView] = useState<FileModeArchiveView | undefined>(undefined)
  const [failure, setFailure] = useState<string | undefined>(undefined)
  // Die Endung kommt aus Rust und wird bei jedem Rendern neu erfragt; die
  // Brücke hält sie, sobald sie da ist. Solange nicht, trägt das Feld keinen
  // Filter — siehe die Begründung an `bundleExtension` in `./DirectoryHandle`.
  const bundleExtension = bridge.bundleExtension()

  function absorb(opening: Promise<FileModeArchiveView>): void {
    void opening.then(
      opened => {
        setFailure(undefined)
        setView(opened)
      },
      (reason: unknown) => {
        // Ein Fehlschlag löscht das vorige Ergebnis. Einen Bericht stehen zu
        // lassen, der zu einem anderen Bestand gehört, wäre die gefährlichere
        // Höflichkeit.
        setView(undefined)
        setFailure(failureText(reason))
      },
    )
  }

  const picker = host.showDirectoryPicker

  return (
    <ConfigProvider locale={deDE} theme={eaRuntimeTheme}>
      <section aria-label="Archiv öffnen">
        <Space orientation="vertical" size="middle">
          <Space size="small">
            <DecorativeIcon name="locked" />
            <Typography.Title level={2}>Archiv öffnen</Typography.Title>
          </Space>

          <Space orientation="vertical" size="small">
            {/*
              Der universelle Weg. Ein gewöhnliches Dateifeld und keine
              Schaltfläche: es braucht keine Dateisystem-API und trägt damit in
              jeder Engine. Der Filter ist ein HINWEIS — entschieden wird an
              der Magie des Containers, und eine umbenannte Datei fällt dort
              und nicht am Namen.
            */}
            <label htmlFor={fileInputId}>Archivdatei öffnen</label>
            <input
              id={fileInputId}
              type="file"
              accept={bundleExtension.length === 0 ? undefined : `.${bundleExtension}`}
              onChange={event => {
                const chosen = event.target.files?.[0]
                if (chosen === undefined) {
                  return
                }
                absorb(
                  chosen.arrayBuffer().then(buffer => bridge.openBundle(new Uint8Array(buffer))),
                )
              }}
            />
          </Space>

          {picker === undefined ? null : (
            <Space orientation="vertical" size="small">
              <Button
                onClick={() => {
                  absorb(picker.call(host).then(handle => bridge.openDirectory(handle)))
                }}
              >
                Archivordner verbinden
              </Button>
              <Typography.Text type="secondary">
                Dieser Browser kann einen Archivordner dauerhaft anbinden. Der Weg über die
                Einzeldatei bleibt daneben bestehen.
              </Typography.Text>
            </Space>
          )}

          {failure === undefined ? null : (
            <Alert
              type="error"
              showIcon
              title="Dieser Bestand liess sich nicht öffnen."
              description={failure}
            />
          )}

          {view === undefined ? null : (
            <Space orientation="vertical" size="small">
              <Space size="small">
                <DecorativeIcon
                  name={view.fullyVerified ? 'verified' : 'warning'}
                  state={view.fullyVerified ? 'confirmed' : 'default'}
                />
                <Typography.Text data-testid="verification-summary">
                  {view.fullyVerified ? 'Alle Objekte geprüft' : 'Nicht alle Objekte geprüft'}
                </Typography.Text>
              </Space>

              {/*
                Die ZWEITE Dimension, an einem EIGENEN Träger und ohne jede
                Warnform. Der Wortlaut wird gerendert und nie getippt.
              */}
              <Typography.Text data-testid="server-confirmation">
                {view.serverConfirmation}
              </Typography.Text>
              <Typography.Text type="secondary">
                Im Datei-Modus werden keine Serverquittungen bezogen. Ein Bestand ohne sie ist
                deshalb der Regelfall und kein Mangel — er senkt den Prüfstand darüber nicht.
              </Typography.Text>

              <Typography.Text>Archivobjekte: {view.archiveObjectCount}</Typography.Text>
              <Typography.Text>Einsatzpakete: {view.entryPackageCount}</Typography.Text>
              <Typography.Text>Fehlstellen in der Kette: {view.gapCount}</Typography.Text>
              <Typography.Text>Mit Serverquittung: {view.serverConfirmedCount}</Typography.Text>
              <Typography.Text>Ohne Serverquittung: {view.notServerConfirmedCount}</Typography.Text>
            </Space>
          )}
        </Space>
      </section>
    </ConfigProvider>
  )
}
