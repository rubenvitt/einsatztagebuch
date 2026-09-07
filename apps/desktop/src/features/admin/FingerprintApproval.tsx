import { Alert, Button, Input, QRCode, Space, Steps, Typography } from 'antd'
import { useEffect, useId, useRef, useState } from 'react'
import type { ReactElement } from 'react'

import {
  ADMIN_AUTHORIZED_STEP,
  PENDING_REQUEST_STEP,
  REGISTRY_PUBLISHED_STEP,
  ROOT_REPLY_IMPORTED_STEP,
  ROOT_REQUEST_EXPORTED_STEP,
  TRUST_CEREMONY_KIND_TEXT,
  TRUST_CEREMONY_STEP_TEXT,
  authorizationStep,
  visibleSteps,
} from './ceremony'
import type { TrustCeremonyView } from '../../bridge/generated-contracts'

/** Der Wortlaut, wenn der Wirt KEINEN frischen Nachweis ausgestellt hat. */
export const REAUTH_REQUIRED_TEXT = 'Wiederanmeldung erforderlich'

/**
 * Der Stepper EINER Root-Zeremonie — je Schritt genau eine Handlung.
 *
 * Die Schritte sind die geschlossene Aufzaehlung
 * `ea_admin::ceremony_steps::TrustCeremonyStep`; der Wirt schreitet sie um
 * genau einen Schritt fort, und diese Flaeche zeigt nie die Handlungen zweier
 * Schritte zugleich. Pending-Anfrage, Fingerprint-Abgleich, Admin-Autorisierung,
 * Root-Export, Root-Import und Veroeffentlichung bleiben getrennt
 * (`design.md`:1923).
 *
 * Der Wortlaut eines Schritts erscheint ERST, wenn er erreicht ist: „Gerät
 * aktiv" darf auf keiner Flaeche stehen, deren Geraet nicht aktiv ist, und ein
 * Sicherheitszustand, der als Vorschau schon da steht, ist eine Behauptung ueber
 * etwas, das nicht eingetreten ist. Kommende Schritte heissen deshalb
 * „Schritt n".
 *
 * Nach jedem Schritt wandert der Fokus auf die Ueberschrift des Schritts, damit
 * ein Screenreader den neuen Stand nennt (`design.md`:1946-1948).
 */
export function FingerprintApproval({
  ceremony,
  notice,
  error,
  busy,
  onConfirmFingerprint,
  onAuthorize,
  onExportRequest,
  onImportReply,
  onPublish,
}: {
  readonly ceremony: TrustCeremonyView
  /** Ein Hinweis ohne Fehlercode — etwa die verweigerte Wiederanmeldung. */
  readonly notice: string | null
  /** Der Fehlercode des Wirts zum letzten Schritt. */
  readonly error: string | null
  readonly busy: boolean
  readonly onConfirmFingerprint: (reported: string) => void
  readonly onAuthorize: () => void
  readonly onExportRequest: () => void
  readonly onImportReply: () => void
  readonly onPublish: () => void
}): ReactElement {
  const [reported, setReported] = useState('')
  const headingRef = useRef<HTMLHeadingElement>(null)
  const inputId = useId()
  const steps = visibleSteps(ceremony.kind)
  const index = Math.max(0, steps.indexOf(ceremony.step))
  const label = TRUST_CEREMONY_STEP_TEXT[ceremony.step]

  useEffect(() => {
    headingRef.current?.focus()
  }, [ceremony.ceremonyId, ceremony.step])

  const items = steps.map((step, position) => ({
    key: step,
    title: position <= index ? TRUST_CEREMONY_STEP_TEXT[step] : `Schritt ${String(position + 1)}`,
  }))

  const action = (): ReactElement => {
    const { step } = ceremony
    if (step === authorizationStep(ceremony.kind)) {
      return (
        <Space direction="vertical" size="small">
          <Typography.Text>
            Die Admin-Autorisierung verlangt eine frische native Wiederanmeldung; ohne sie wird
            nichts autorisiert.
          </Typography.Text>
          <Button type="primary" disabled={busy} onClick={onAuthorize}>
            Neu anmelden und autorisieren
          </Button>
        </Space>
      )
    }
    if (step === PENDING_REQUEST_STEP) {
      const fingerprint = ceremony.targetFingerprint ?? ''
      return (
        <Space direction="vertical" size="small">
          <Typography.Text>
            Vergleichen Sie den Fingerprint über einen zweiten Kanal. Volltext und QR-Code zeigen
            denselben Wert.
          </Typography.Text>
          <Typography.Text code aria-label="Vollständiger Fingerprint">
            {fingerprint}
          </Typography.Text>
          <QRCode
            type="svg"
            value={fingerprint}
            role="img"
            aria-label="QR-Code des vollständigen Fingerprints"
          />
          <label htmlFor={inputId}>Über den zweiten Kanal gemeldeter Fingerprint</label>
          <Input
            id={inputId}
            value={reported}
            onChange={(event) => {
              setReported(event.target.value)
            }}
          />
          <Button
            type="primary"
            disabled={busy || reported.trim() === ''}
            onClick={() => {
              onConfirmFingerprint(reported.trim())
            }}
          >
            Fingerprint bestätigen
          </Button>
        </Space>
      )
    }
    if (step === ADMIN_AUTHORIZED_STEP) {
      return (
        <Space direction="vertical" size="small">
          <Typography.Text>
            Die Root-Anfrage wird als Austauschdatei exportiert und offline durch Root signiert.
          </Typography.Text>
          <Button type="primary" disabled={busy} onClick={onExportRequest}>
            Root-Anfrage exportieren
          </Button>
        </Space>
      )
    }
    if (step === ROOT_REQUEST_EXPORTED_STEP) {
      return (
        <Space direction="vertical" size="small">
          <Typography.Text>
            {`Austauschdatei: ${ceremony.exchangeFileName ?? 'vom Wirt nicht genannt'}. Importieren Sie die Root-Antwort, sobald sie vorliegt.`}
          </Typography.Text>
          <Button type="primary" disabled={busy} onClick={onImportReply}>
            Root-Antwort importieren
          </Button>
        </Space>
      )
    }
    if (step === ROOT_REPLY_IMPORTED_STEP) {
      return (
        <Space direction="vertical" size="small">
          <Typography.Text>
            Die Veröffentlichung des Registry-Ereignisses verlangt eine frische native
            Wiederanmeldung.
          </Typography.Text>
          <Button type="primary" disabled={busy} onClick={onPublish}>
            Neu anmelden und veröffentlichen
          </Button>
        </Space>
      )
    }
    if (step === REGISTRY_PUBLISHED_STEP) {
      return (
        <Typography.Text>
          Das Root-signierte Registry-Ereignis ist veröffentlicht. Die Zeremonie ist abgeschlossen.
        </Typography.Text>
      )
    }
    return <Typography.Text>Dieser Schritt hat hier keine Handlung.</Typography.Text>
  }

  return (
    <Space direction="vertical" size="middle">
      <Typography.Title level={4} tabIndex={-1} ref={headingRef}>
        {`${TRUST_CEREMONY_KIND_TEXT[ceremony.kind]} — Schritt ${String(index + 1)} von ${String(steps.length)}: ${label}`}
      </Typography.Title>
      <Steps orientation="vertical" size="small" current={index} items={items} />
      {notice === null ? null : <Alert type="warning" showIcon={false} message={notice} />}
      {error === null ? null : <Alert type="error" showIcon={false} message={error} />}
      {action()}
    </Space>
  )
}
