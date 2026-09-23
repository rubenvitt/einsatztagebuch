import { Alert, Button, ConfigProvider, Descriptions, Space, Tag, Typography } from 'antd'
import deDE from 'antd/locale/de_DE'
import { useEffect, useRef, useState } from 'react'
import type { ReactElement } from 'react'

import { DecorativeIcon } from '../../design/icons'
import { eaRuntimeTheme } from '../../design/tokens'
import type { ReaderKeyEscrowBridge, TransportBeginView, TransportOpenView } from './escrow-bridge'

export type EscrowRestorePageProps = {
  readonly bridge: ReaderKeyEscrowBridge
  readonly download: (fileName: string, bytesHex: string) => void
  /** Das Enrollment des neuen Tresors um den wiederhergestellten Schlüssel. */
  readonly renderEnrollment: (restored: number) => ReactElement
}

/**
 * Zeremonie B (Escrow-Profil §6, §7): Transportanfrage, Import des Umschlags,
 * dann ein neuer Tresor mit zwei Authenticators. Der Transportschlüssel lebt
 * nur im Worker; beim Verlassen der Seite und auf `pagehide` wird er
 * verworfen.
 */
export function EscrowRestorePage({
  bridge,
  download,
  renderEnrollment,
}: EscrowRestorePageProps): ReactElement {
  const [files, setFiles] = useState<readonly File[]>([])
  const [begun, setBegun] = useState<TransportBeginView | undefined>(undefined)
  const [opened, setOpened] = useState<TransportOpenView | undefined>(undefined)
  const [busy, setBusy] = useState(false)
  const [failure, setFailure] = useState<string | undefined>(undefined)
  const handle = useRef<number | undefined>(undefined)

  useEffect(() => {
    const abort = (): void => {
      if (handle.current !== undefined) {
        void bridge.abort(handle.current).catch(() => undefined)
      }
    }
    window.addEventListener('pagehide', abort)
    return () => {
      window.removeEventListener('pagehide', abort)
      abort()
    }
  }, [bridge])

  const run = (step: () => Promise<void>): void => {
    setBusy(true)
    setFailure(undefined)
    void step()
      .catch((error: unknown) => setFailure(error instanceof Error ? error.message : String(error)))
      .finally(() => setBusy(false))
  }

  return (
    <ConfigProvider locale={deDE} theme={eaRuntimeTheme}>
      <section aria-label="Wiederherstellung">
        <Space orientation="vertical" size="middle">
          <Space size="small">
            <DecorativeIcon name="locked" />
            <Typography.Title level={2}>Wiederherstellung</Typography.Title>
          </Space>
          <Alert
            type="info"
            showIcon
            title="Reihenfolge"
            description={
              'Erst öffnen, dann neu zertifizieren, dann das alte Zertifikat widerrufen, dann ein ' +
              'neues Hinterlegungspaket. Ein Neuladen dieser Seite vernichtet den ' +
              'Transportschlüssel; danach braucht es eine neue Autorisierung.'
            }
          />
          {failure === undefined ? null : (
            <Alert type="error" showIcon title="Die Wiederherstellung ist gescheitert." description={failure} />
          )}
          <section aria-label="Transportanfrage">
            <Space orientation="vertical" size="small">
              <Space size="small">
                <Tag>Schritt 1</Tag>
                <Typography.Title level={3}>Transportanfrage</Typography.Title>
              </Space>
              <label>
                <Typography.Text>Trust-Dateien wählen</Typography.Text>
                <input
                  aria-label="Trust-Dateien wählen"
                  type="file"
                  multiple
                  disabled={begun !== undefined}
                  onChange={event => setFiles([...(event.currentTarget.files ?? [])])}
                />
              </label>
              <Button
                type="primary"
                disabled={busy || files.length === 0 || begun !== undefined}
                onClick={() =>
                  run(async () => {
                    const view = await bridge.transportBegin(files)
                    handle.current = view.handle
                    setBegun(view)
                    download(view.fileName, view.bytesHex)
                  })
                }
              >
                Wiederherstellung beginnen
              </Button>
              {begun === undefined ? null : (
                <Space orientation="vertical" size="small">
                  <Typography.Text>
                    Diesen Fingerprint den Approvern außerhalb des Systems vorlegen:
                  </Typography.Text>
                  <Typography.Title level={4} aria-label="Transport-Fingerprint">
                    <Typography.Text code>{begun.transportFingerprint}</Typography.Text>
                  </Typography.Title>
                  <Button onClick={() => download(begun.fileName, begun.bytesHex)}>
                    Transportanfrage herunterladen
                  </Button>
                </Space>
              )}
            </Space>
          </section>
          <section aria-label="Umschlag">
            <Space orientation="vertical" size="small">
              <Space size="small">
                <Tag>Schritt 2</Tag>
                <Typography.Title level={3}>Umschlag</Typography.Title>
              </Space>
              <label>
                <Typography.Text>Umschlag importieren</Typography.Text>
                <input
                  aria-label="Umschlag importieren"
                  type="file"
                  disabled={begun === undefined || opened !== undefined || busy}
                  onChange={event => {
                    const envelope = event.currentTarget.files?.[0]
                    // Zuruecksetzen, damit dieselbe Datei erneut gewaehlt
                    // werden kann — die Antwort darauf gibt Rust.
                    event.currentTarget.value = ''
                    if (begun === undefined || envelope === undefined) {
                      return
                    }
                    run(async () => {
                      setOpened(await bridge.transportOpen(begun.handle, envelope))
                    })
                  }}
                />
              </label>
              {opened === undefined ? null : (
                <Descriptions column={1} size="small">
                  <Descriptions.Item label="Wiederhergestellter Abdruck">
                    <Typography.Text code>{opened.kemFingerprint}</Typography.Text>
                  </Descriptions.Item>
                  <Descriptions.Item label="Autorisierung (nur angezeigt)">
                    <Typography.Text code>{opened.authorizationObjectHash}</Typography.Text>
                  </Descriptions.Item>
                </Descriptions>
              )}
            </Space>
          </section>
          {begun === undefined || opened === undefined ? null : renderEnrollment(begun.handle)}
        </Space>
      </section>
    </ConfigProvider>
  )
}
