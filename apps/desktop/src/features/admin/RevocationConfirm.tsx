import { Alert, Button, Input, Space, Typography } from 'antd'
import { useId, useState } from 'react'
import type { ReactElement } from 'react'

import type { RevocationEffectView, RevocationTargetClass } from '../../bridge/generated-contracts'

/**
 * Der Wortlaut je Zielart — erschoepfend, unzitierte Schluessel.
 *
 * Zielart 0 ist das Geraetezertifikat eines NICHT-Admins: Change 1 widerruft
 * nie einen Admin (Globale Randbedingung, Aktionscodes).
 */
export const REVOCATION_CLASS_TEXT: Record<RevocationTargetClass, string> = {
  NonAdminDevice: 'Gerätezertifikat (kein Admin)',
  OperatorBinding: 'Bedienerbindung',
  Component: 'Komponente',
}

/**
 * Die Wirkung eines Widerrufs — VOR dem Widerruf, im Wortlaut (§12.4,
 * `design.md`:1462).
 *
 * Die beiden Saetze zur Grenze entstehen aus den Wahrheitswerten des Kerns und
 * nicht aus Prosa: `recallsIssuedGrants` und `recallsDecryptedPlaintext` sind
 * immer `false`. Meldet ein Wirt `true`, verspricht er einen Rueckruf, den es
 * nicht gibt — dann steht eine Warnung da und KEINE Handhabe fuer den Widerruf.
 * Der Widerruf selbst ist eine Root-Zeremonie der Art DeviceRevoke ohne
 * Fingerprint-Schritt.
 */
export function RevocationConfirm({
  effect,
  notice,
  busy,
  onCheck,
  onBegin,
}: {
  readonly effect: RevocationEffectView | null
  readonly notice: string | null
  readonly busy: boolean
  readonly onCheck: (targetHash: string) => void
  readonly onBegin: (targetHash: string) => void
}): ReactElement {
  const [targetHash, setTargetHash] = useState('')
  const inputId = useId()
  const unexpected =
    effect !== null && (effect.recallsIssuedGrants || effect.recallsDecryptedPlaintext)

  return (
    <Space direction="vertical" size="middle">
      <Space direction="vertical" size="small">
        <label htmlFor={inputId}>Zielhash</label>
        <Input
          id={inputId}
          value={targetHash}
          onChange={(event) => {
            setTargetHash(event.target.value)
          }}
        />
        <Button
          disabled={busy || targetHash.trim() === ''}
          onClick={() => {
            onCheck(targetHash.trim())
          }}
        >
          Wirkung prüfen
        </Button>
      </Space>
      {notice === null ? null : <Alert type="error" showIcon={false} message={notice} />}
      {effect === null ? null : (
        <Space direction="vertical" size="small">
          <Typography.Text strong>{REVOCATION_CLASS_TEXT[effect.targetClass]}</Typography.Text>
          <Typography.Text code>{effect.targetHash}</Typography.Text>
          <Typography.Text>
            {`Neue Grants werden ab Sequenz ${String(effect.stopsNewGrantsFromSequence)} verhindert.`}
          </Typography.Text>
          {unexpected ? (
            <Alert
              type="error"
              showIcon={false}
              message="Unerwartete Rückrufzusage gemeldet"
              description="Der Wirt verspricht einen Rückruf bereits erteilter Grants oder bereits entschlüsselter Inhalte. Einen solchen Rückruf gibt es nicht; der Widerruf wird hier nicht begonnen."
            />
          ) : (
            <>
              <Typography.Text>Bereits erteilte Grants werden nicht zurückgerufen.</Typography.Text>
              <Typography.Text>
                Bereits entschlüsselte Inhalte können nicht zurückgerufen werden.
              </Typography.Text>
              <Button
                danger
                disabled={busy}
                onClick={() => {
                  onBegin(effect.targetHash)
                }}
              >
                Widerruf als Root-Zeremonie beginnen
              </Button>
            </>
          )}
        </Space>
      )}
    </Space>
  )
}
