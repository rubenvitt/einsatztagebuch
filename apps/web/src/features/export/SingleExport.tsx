import { Alert, Button, ConfigProvider, Radio, Space, Typography } from 'antd'
import deDE from 'antd/locale/de_DE'
import { useCallback, useEffect, useState } from 'react'
import type { ReactElement } from 'react'

import type { ReaderSessionView, SingleExportReportView } from '../../bridge/generated-contracts'
import { DecorativeIcon } from '../../design/icons'
import { eaRuntimeTheme } from '../../design/tokens'
import type { ExportHost, ExportTargetChoice, ReaderSessionBridge } from '../session/reader-session'
import { chooseExportTarget } from '../session/reader-session'

/**
 * Die Fläche des Einzelexports: Sitzungszustand, die bewusste Wahl GENAU
 * EINES Datensatzes, die bewusste Wahl eines Ziels, die Bestätigung
 * (`web-reader-design.md` §6.5 und §8.2).
 *
 * # Diese Fläche entscheidet nichts
 *
 * Ob die Sitzung gesperrt ist, sagt `ReaderSession::state_at` — der Aufruf
 * über `bridge.stateAt` IST die Sperrentscheidung, und die Fläche rendert das
 * Ergebnis. Ob ein Ziel besetzt, eine Bestätigung abgelaufen oder ein
 * Datensatz nicht offen ist, sagt Rust als stabiler Code, und genau dieser
 * Code steht dann im `Alert` — nie ein hier erfundener Satz.
 *
 * # Der Poll ist der Beschleuniger, nicht der Mechanismus
 *
 * Die Fläche liest den Zustand beim Montieren und danach im Abstand von
 * `pollIntervalMs`. Das ist ein LESEN mit der Uhr der Seite und keine Frist:
 * fiele der Poll in einem gedrosselten Hintergrundtab aus, wäre die Sitzung
 * beim nächsten Zugriff — dem Export, dem Öffnen — trotzdem gesperrt, weil
 * Rust die Frist bei jedem Zugriff nachrechnet. Der Poll sorgt nur dafür,
 * dass die Anzeige das nicht erst beim nächsten Klick erfährt.
 *
 * # Was hier ausdrücklich NICHT erscheint
 *
 * Kein Klartext und kein Pfad. Der Bericht trägt den Entry-Hash und die
 * Zielart aus dem generierten `SingleExportReportView`; die Bytes gehen von
 * der Brücke in das gewählte Ziel und durch kein Element dieser Fläche. Die
 * Zwischenablage wird nicht angefasst — `SingleExport.test.tsx` hält jede
 * handgeschriebene Quelle davon fern.
 *
 * Die Fläche benutzt ausschliesslich Ant-Komponenten aus
 * `EXTRACTED_COMPONENTS` (`apps/web/src/design/extract-static-css.tsx`):
 * `eaRuntimeTheme` trägt `zeroRuntime`, und die CSP blockiert jede zur
 * Laufzeit eingespritzte Regel.
 */
export type SingleExportProps = {
  /** Die Sitzungsbrücke nach Rust. Ohne Vorgabewert: siehe unten. */
  readonly bridge: ReaderSessionBridge
  /** Das Wirtsobjekt der Zielwahl — übergeben, nicht global gelesen. */
  readonly host: ExportHost
  /** Der Abstand des lesenden Polls; Vorgabe eine Sekunde. */
  readonly pollIntervalMs?: number
}

/**
 * Der Fehlschlag in der Form, in der Rust ihn gemeldet hat: der stabile Code.
 *
 * `EA-READER-SESSION-LOCKED`, `EA-READER-EXPORT-TARGET-OCCUPIED`,
 * `EA-READER-EXPORT-CONFIRMATION-STALE` und die übrigen sind Aussagen von
 * Rust, und die Fläche liest dieselbe Aussage wie ein Zeuge in Rust.
 */
function failureText(reason: unknown): string {
  return reason instanceof Error ? reason.message : String(reason)
}

/** Der Wortlaut des Sitzungszustands — GENAU einer der drei. */
function sessionStateText(view: ReaderSessionView | undefined): string {
  if (view === undefined) {
    return 'Keine Sitzung'
  }
  return view.locked ? 'Sitzung gesperrt' : 'Sitzung entsperrt'
}

/** Der Wortlaut der Zielart aus `ReaderExportTargetKindV1`. */
function targetKindText(kind: number): string {
  return kind === 1 ? 'Datei' : 'Download'
}

/**
 * Die Fläche, `bridge` als PFLICHTEIGENSCHAFT.
 *
 * Ohne Vorgabewert, aus demselben gemessenen Grund wie bei `OpenArchivePanel`:
 * die echte Brücke spricht mit dem dedizierten Worker, und ein Vorgabewert
 * zöge ihn in jeden Lauf, der nur diese Datei rendert. Gestellt wird sie an
 * der Route in `src/main.tsx`.
 */
export function SingleExport({ bridge, host, pollIntervalMs = 1_000 }: SingleExportProps): ReactElement {
  const [view, setView] = useState<ReaderSessionView | undefined>(undefined)
  const [failure, setFailure] = useState<string | undefined>(undefined)
  const [chosenHash, setChosenHash] = useState<string | undefined>(undefined)
  const [target, setTarget] = useState<ExportTargetChoice | undefined>(undefined)
  const [report, setReport] = useState<SingleExportReportView | undefined>(undefined)
  const [busy, setBusy] = useState(false)

  const refresh = useCallback(async () => {
    try {
      setView(await bridge.stateAt(Date.now()))
    } catch (reason) {
      setFailure(failureText(reason))
    }
  }, [bridge])

  useEffect(() => {
    void refresh()
    const interval = setInterval(() => {
      void refresh()
    }, pollIntervalMs)
    return () => {
      clearInterval(interval)
    }
  }, [refresh, pollIntervalMs])

  // Die Wahl gilt nur, solange der Datensatz OFFEN ist. Nach einer Sperre ist
  // die Liste leer — die Datensätze sind mit dem Tresor gefallen —, und eine
  // Wahl, die das überlebte, zeigte auf etwas, das es nicht mehr gibt.
  const openHashes = view?.openEntryHashes ?? []
  const chosen = chosenHash !== undefined && openHashes.includes(chosenHash) ? chosenHash : undefined
  const identity = bridge.auditIdentity()
  const unlocked = view !== undefined && !view.locked
  const canExport =
    unlocked && chosen !== undefined && target !== undefined && identity !== undefined && !busy

  return (
    <ConfigProvider locale={deDE} theme={eaRuntimeTheme}>
      <section aria-label="Einzelexport">
        <Space orientation="vertical" size="middle">
          <Space size="small">
            <DecorativeIcon name="locked" state={unlocked ? 'confirmed' : 'default'} />
            <Typography.Title level={2}>Einzelexport</Typography.Title>
          </Space>

          <Space orientation="vertical" size="small">
            <Typography.Text data-testid="session-state">{sessionStateText(view)}</Typography.Text>
            <Button
              onClick={() => {
                void (async () => {
                  try {
                    await bridge.unlock(Date.now())
                    setFailure(undefined)
                  } catch (reason) {
                    setFailure(failureText(reason))
                  }
                  await refresh()
                })()
              }}
            >
              Sitzung entsperren
            </Button>
          </Space>

          {identity === undefined ? (
            <Alert
              type="warning"
              showIcon
              title="Kein Reader-Zertifikat auf diesem Gerät"
              description="Der Export braucht die Geräteidentität des Reader-Zertifikats für die Auditzeile. Dieser Stand trägt sie noch nicht; die Bestätigung bleibt gesperrt."
            />
          ) : null}

          <Space orientation="vertical" size="small">
            <Typography.Text strong>Datensatz</Typography.Text>
            {openHashes.length === 0 ? (
              <Typography.Text type="secondary">Kein Datensatz geöffnet.</Typography.Text>
            ) : (
              <Radio.Group
                value={chosen ?? null}
                onChange={event => {
                  setChosenHash(String(event.target.value))
                }}
                options={openHashes.map(hash => ({
                  value: hash,
                  label: <Typography.Text code>{hash}</Typography.Text>,
                }))}
              />
            )}
          </Space>

          <Space orientation="vertical" size="small">
            <Typography.Text strong>Ziel</Typography.Text>
            <Button
              onClick={() => {
                void (async () => {
                  try {
                    const choice = await chooseExportTarget(host)
                    // Ein abgebrochener Dialog lässt die vorige Wahl stehen;
                    // er ist keine Entscheidung gegen sie.
                    if (choice !== undefined) {
                      setTarget(choice)
                    }
                  } catch (reason) {
                    setFailure(failureText(reason))
                  }
                })()
              }}
            >
              Ziel wählen
            </Button>
            {/* Die ART und nie der Pfad: der Name des Handles kommt hier nicht an. */}
            <Typography.Text data-testid="target-kind">
              {target === undefined ? 'Kein Ziel gewählt.' : `Ziel: ${targetKindText(target.kind)}`}
            </Typography.Text>
          </Space>

          <Button
            type="primary"
            disabled={!canExport}
            onClick={() => {
              if (chosen === undefined || target === undefined || identity === undefined) {
                return
              }
              setBusy(true)
              void (async () => {
                try {
                  const exported = await bridge.exportOne({
                    entryHashHex: chosen,
                    target,
                    identity,
                    nowMs: Date.now(),
                  })
                  setFailure(undefined)
                  setReport(exported)
                } catch (reason) {
                  setReport(undefined)
                  setFailure(failureText(reason))
                } finally {
                  // Ein Versuch VERBRAUCHT die offene Kopie, ob er gelang oder
                  // nicht: `export_one` nimmt den Datensatz besitzend, und ein
                  // abgewiesener Versuch lässt ihn ebenso fallen. Der Zustand
                  // wird deshalb neu gelesen, und das Ziel wird verworfen — ob
                  // es jetzt besetzt ist, weiss nur eine neue Wahl.
                  setTarget(undefined)
                  setBusy(false)
                  await refresh()
                }
              })()
            }}
          >
            Export bestätigen
          </Button>

          {failure === undefined ? null : (
            <Alert type="error" showIcon title={failure} />
          )}

          {report === undefined ? null : (
            <Space orientation="vertical" size="small" data-testid="export-report">
              <Space size="small">
                <DecorativeIcon name="verified" state="confirmed" />
                <Typography.Text>Export abgeschlossen.</Typography.Text>
              </Space>
              <Typography.Text>
                Entry-Hash: <Typography.Text code>{report.entryHash}</Typography.Text>
              </Typography.Text>
              <Typography.Text>Zielart: {targetKindText(report.targetKind)}</Typography.Text>
            </Space>
          )}
        </Space>
      </section>
    </ConfigProvider>
  )
}
