import { Button, Space, Typography } from 'antd'
import type { ReactElement } from 'react'

import { PENDING_REQUEST_STEP, TRUST_CEREMONY_STEP_TEXT } from './ceremony'
import { formatInstant } from './format'
import type { PendingDeviceRequestView } from '../../bridge/generated-contracts'

/**
 * Die ausstehenden Geraeteanfragen — OHNE Fingerprint.
 *
 * Pending-Anfrage und externer Fingerprint-Abgleich sind getrennte Schritte
 * (`design.md`:1923). Die Liste nennt deshalb Zertifikatsart und Eingang; der
 * Fingerprint erscheint erst in der begonnenen Zeremonie, zusammen mit dem
 * QR-Code und dem Eingabefeld fuer den zweiten Kanal.
 */
export function DeviceRequests({
  requests,
  busy,
  onBegin,
}: {
  readonly requests: readonly PendingDeviceRequestView[]
  readonly busy: boolean
  readonly onBegin: (requestId: string) => void
}): ReactElement {
  if (requests.length === 0) {
    return <Typography.Text>Keine Geräteanfrage steht aus.</Typography.Text>
  }
  return (
    <ul>
      {requests.map((request) => (
        <li key={request.requestId}>
          <Space size="middle">
            <Typography.Text strong>{TRUST_CEREMONY_STEP_TEXT[PENDING_REQUEST_STEP]}</Typography.Text>
            <Typography.Text>{request.certificateKindCode}</Typography.Text>
            <time dateTime={formatInstant(request.receivedAtMs)}>
              {formatInstant(request.receivedAtMs)}
            </time>
            <Button
              disabled={busy}
              onClick={() => {
                onBegin(request.requestId)
              }}
            >
              Fingerprint vergleichen
            </Button>
          </Space>
        </li>
      ))}
    </ul>
  )
}
