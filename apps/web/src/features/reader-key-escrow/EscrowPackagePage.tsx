import { Alert, Button, ConfigProvider, Descriptions, Space, Tag, Typography } from 'antd'
import deDE from 'antd/locale/de_DE'
import { useState } from 'react'
import type { ReactElement } from 'react'

import { DecorativeIcon } from '../../design/icons'
import { eaRuntimeTheme } from '../../design/tokens'
import type { EscrowPackageView, ReaderKeyEscrowBridge, RegistrationFileView } from './escrow-bridge'

export type EscrowPackagePageProps = {
  readonly bridge: ReaderKeyEscrowBridge
  readonly download: (fileName: string, bytesHex: string) => void
}

/**
 * Zeremonie A (Escrow-Profil §5): Registrierungsantrag und
 * Hinterlegungspaket. Die Oberflaeche zeigt die Werte aus Rust woertlich; die
 * Subject-ID erscheint nicht.
 */
export function EscrowPackagePage({ bridge, download }: EscrowPackagePageProps): ReactElement {
  const [files, setFiles] = useState<readonly File[]>([])
  const [registration, setRegistration] = useState<RegistrationFileView | undefined>(undefined)
  const [sealed, setSealed] = useState<EscrowPackageView | undefined>(undefined)
  const [busy, setBusy] = useState(false)
  const [failure, setFailure] = useState<string | undefined>(undefined)

  const run = (step: () => Promise<void>): void => {
    setBusy(true)
    setFailure(undefined)
    void step()
      .catch((error: unknown) => setFailure(error instanceof Error ? error.message : String(error)))
      .finally(() => setBusy(false))
  }

  return (
    <ConfigProvider locale={deDE} theme={eaRuntimeTheme}>
      <section aria-label="Schlüsselhinterlegung">
        <Space orientation="vertical" size="middle">
          <Space size="small">
            <DecorativeIcon name="locked" />
            <Typography.Title level={2}>Schlüsselhinterlegung</Typography.Title>
          </Space>
          {failure === undefined ? null : (
            <Alert type="error" showIcon title="Die Hinterlegung ist gescheitert." description={failure} />
          )}
          <section aria-label="Registrierungsantrag">
            <Space orientation="vertical" size="small">
              <Space size="small">
                <Tag>Schritt 1</Tag>
                <Typography.Title level={3}>Registrierungsantrag</Typography.Title>
              </Space>
              <Typography.Text>
                Der Antrag trägt nur die öffentlichen Schlüssel dieses Tresors und geht als Datei an
                die Administration.
              </Typography.Text>
              <Button
                disabled={busy}
                onClick={() =>
                  run(async () => {
                    const file = await bridge.registrationRequest()
                    setRegistration(file)
                    download(file.fileName, file.bytesHex)
                  })
                }
              >
                Registrierungsantrag herunterladen
              </Button>
              {registration === undefined ? null : (
                <Descriptions column={1} size="small">
                  <Descriptions.Item label="Abdruck Entschlüsselungsschlüssel">
                    <Typography.Text code>{registration.kemFingerprint}</Typography.Text>
                  </Descriptions.Item>
                  <Descriptions.Item label="Abdruck Signaturschlüssel">
                    <Typography.Text code>{registration.signingFingerprint}</Typography.Text>
                  </Descriptions.Item>
                </Descriptions>
              )}
            </Space>
          </section>
          <section aria-label="Hinterlegungspaket">
            <Space orientation="vertical" size="small">
              <Space size="small">
                <Tag>Schritt 2</Tag>
                <Typography.Title level={3}>Hinterlegungspaket</Typography.Title>
              </Space>
              <Typography.Text>
                Wähle die Trust-Dateien, die das Reader-Zertifikat dieses Tresors tragen. Das Paket
                entsteht erst, wenn der Schlüssel des Tresors dem Zertifikat gleicht.
              </Typography.Text>
              <label>
                <Typography.Text>Trust-Dateien wählen</Typography.Text>
                <input
                  aria-label="Trust-Dateien wählen"
                  type="file"
                  multiple
                  onChange={event => setFiles([...(event.currentTarget.files ?? [])])}
                />
              </label>
              <Button
                type="primary"
                disabled={busy || files.length === 0}
                onClick={() =>
                  run(async () => {
                    const file = await bridge.sealPackage(files)
                    setSealed(file)
                    download(file.fileName, file.bytesHex)
                  })
                }
              >
                Hinterlegungspaket erzeugen
              </Button>
              {sealed === undefined ? null : (
                <Descriptions column={1} size="small">
                  <Descriptions.Item label="Corehash zur Freigabe">
                    <Typography.Text code>{sealed.escrowCoreHash}</Typography.Text>
                  </Descriptions.Item>
                  <Descriptions.Item label="Reader-Zertifikat">
                    <Typography.Text code>{sealed.readerCertificate}</Typography.Text>
                  </Descriptions.Item>
                  <Descriptions.Item label="Recovery-Zertifikat">
                    <Typography.Text code>{sealed.recoveryCertificate}</Typography.Text>
                  </Descriptions.Item>
                  <Descriptions.Item label="Abdruck Entschlüsselungsschlüssel">
                    <Typography.Text code>{sealed.kemFingerprint}</Typography.Text>
                  </Descriptions.Item>
                </Descriptions>
              )}
            </Space>
          </section>
        </Space>
      </section>
    </ConfigProvider>
  )
}
