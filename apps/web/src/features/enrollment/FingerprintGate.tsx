import { Alert, Input, Space, Tag, Typography } from 'antd'
import type { ReactElement } from 'react'

import { DecorativeIcon } from '../../design/icons'

/**
 * Der DRITTE Schritt: der nicht überspringbare Fingerprint-Vergleich (§4.3).
 *
 * Die Zusicherung ist nicht „es gibt eine Prüfung", sondern „es gibt keinen
 * Weg daran vorbei". Diese Datei vergleicht deshalb NICHTS: sie zeigt die
 * beiden Werte an, nimmt die unabhängig verteilte Referenz entgegen und gibt
 * beides an die Brücke. Ob es passt, entscheidet `confirm_fingerprints` in
 * `ea-reader`, und der Beweis liegt im Typ — `finish` nimmt eine
 * `FingerprintConfirmationV1`, und die kann die Grenze nach JavaScript gar
 * nicht überqueren.
 *
 * Ein Häkchen gäbe es hier nicht: bestätigt wird durch das Abtippen der
 * Referenz, nicht durch ein Zustimmen.
 */
export type FingerprintGateProps = {
  readonly keyFingerprint: string
  readonly bundleFingerprint: string
  readonly expectedKeyFingerprint: string
  readonly expectedBundleFingerprint: string
  readonly confirmed: boolean
  readonly refusalCode?: string | undefined
  readonly onExpectedKeyFingerprintChange: (value: string) => void
  readonly onExpectedBundleFingerprintChange: (value: string) => void
}

const KEY_FIELD_ID = 'erwarteter-schluessel-fingerprint'
const BUNDLE_FIELD_ID = 'erwarteter-bundle-fingerprint'

export function FingerprintGate({
  keyFingerprint,
  bundleFingerprint,
  expectedKeyFingerprint,
  expectedBundleFingerprint,
  confirmed,
  refusalCode,
  onExpectedKeyFingerprintChange,
  onExpectedBundleFingerprintChange,
}: FingerprintGateProps): ReactElement {
  return (
    <section aria-label="Fingerprint-Vergleich">
      <Space orientation="vertical" size="small">
        <Space size="small">
          <Tag>Schritt 2</Tag>
          <Typography.Title level={3}>Fingerprints vergleichen</Typography.Title>
        </Space>
        <Typography.Paragraph>
          Vergleiche beide Werte mit der unabhängig verteilten Referenz und tippe sie darunter
          ab. Weicht einer der beiden ab, brich ab und melde es der Administration.
        </Typography.Paragraph>
        {/*
          UNGRUPPIERT und ohne Trennzeichen, wie
          `apps/desktop/src/components/integrity/FingerprintBlock.tsx`: die
          Gegenseite dekodiert Hex und weist jedes Leer- und Bindezeichen ab,
          ein gruppierter Wert liefe also in
          `EA-READER-ENROLLMENT-FINGERPRINT-ENCODING` statt in eine
          Übereinstimmung. Die Kennung sitzt am WERT und nicht an seiner
          Umhüllung — auf einem Kasten mit Beschriftung käme sie über einen
          Textzugriff samt Beschriftung heraus.
        */}
        <dl>
          <Space size="small">
            <dt>
              <Typography.Text type="secondary">Schlüssel-Fingerprint</Typography.Text>
            </dt>
            <dd>
              <Typography.Text code data-testid="schluessel-fingerprint">
                {keyFingerprint}
              </Typography.Text>
            </dd>
          </Space>
          <Space size="small">
            <dt>
              <Typography.Text type="secondary">Bundle-Fingerprint</Typography.Text>
            </dt>
            <dd>
              <Typography.Text code data-testid="bundle-fingerprint">
                {bundleFingerprint}
              </Typography.Text>
            </dd>
          </Space>
        </dl>
        <div>
          <label htmlFor={KEY_FIELD_ID}>Erwarteter Schlüssel-Fingerprint</label>
          <Input
            id={KEY_FIELD_ID}
            value={expectedKeyFingerprint}
            onChange={(event) => {
              onExpectedKeyFingerprintChange(event.target.value)
            }}
          />
        </div>
        <div>
          <label htmlFor={BUNDLE_FIELD_ID}>Erwarteter Bundle-Fingerprint</label>
          <Input
            id={BUNDLE_FIELD_ID}
            value={expectedBundleFingerprint}
            onChange={(event) => {
              onExpectedBundleFingerprintChange(event.target.value)
            }}
          />
        </div>
        {refusalCode === undefined ? null : (
          <Alert
            type="error"
            showIcon
            title="Der Fingerprint-Vergleich ist nicht bestätigt."
            description={refusalCode}
          />
        )}
        {confirmed ? (
          <Space size="small">
            <DecorativeIcon name="verified" state="confirmed" />
            <Typography.Text>Beide Fingerprints sind bestätigt.</Typography.Text>
          </Space>
        ) : null}
      </Space>
    </section>
  )
}
