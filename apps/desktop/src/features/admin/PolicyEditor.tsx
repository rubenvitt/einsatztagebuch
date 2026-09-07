import { Button, Descriptions, Space, Typography } from 'antd'
import type { ReactElement } from 'react'

import { formatInstant } from './format'
import { formatDuration } from '../../app/TrustAgeStatus'
import type { PolicyProfileView } from '../../bridge/generated-contracts'

/**
 * Die Kennung, unter der die Schale eine Richtlinienaenderung beim Wirt
 * beginnt.
 *
 * Eine Richtlinie hat keine Anfrage-Kennung wie ein Geraet; der Wirt ordnet
 * diesen Wert der Zeremonieart PolicyChange zu.
 */
export const POLICY_REQUEST_ID = 'policy-profile'

/**
 * Das Richtlinienprofil — LESBAR, und veraenderbar nur als Root-Zeremonie.
 *
 * Ein freies Bearbeitungsformular gibt es in v0.1 nicht: jede Aenderung ist
 * ein Root-signiertes Ereignis `policyChange` (Change 2), und die Schale
 * beginnt dafuer denselben Stepper wie fuer eine Geraetefreigabe, ohne den
 * Fingerprint-Schritt. Ein Datenbank- oder Konfigurationsschalter kann keine
 * Richtlinie setzen (Globale Randbedingung: append-only Root-signed objects).
 */
export function PolicyEditor({
  policy,
  busy,
  onBegin,
}: {
  readonly policy: PolicyProfileView
  readonly busy: boolean
  readonly onBegin: () => void
}): ReactElement {
  const items = [
    { key: 'profile', label: 'Betriebsprofil', children: String(policy.operatingProfile) },
    {
      key: 'age',
      label: 'Höchstalter der Registry',
      children: formatDuration(policy.maxRegistryAgeMs),
    },
    {
      key: 'skew',
      label: 'Zulässiger Zukunftsversatz der Uhr',
      children: formatDuration(policy.maxFutureClockSkewMs),
    },
    {
      key: 'expiry',
      label: 'Verhalten bei Registry-Ablauf',
      children: String(policy.registryExpiryBehavior),
    },
    {
      key: 'evidence',
      label: 'Evidence-Höchstverzug',
      children: formatDuration(policy.evidenceMaxDelayMs),
    },
    {
      key: 'inactivity',
      label: 'Reader-Inaktivität',
      children: formatDuration(policy.readerInactivityMs),
    },
    {
      key: 'refresh',
      label: 'Reader-Vertrauensauffrischung',
      children: formatDuration(policy.readerTrustRefreshMs),
    },
    {
      key: 'history',
      label: 'Historischer Zugriff für Reader',
      children: policy.readerHistoryAccessAllowed ? 'erlaubt' : 'nicht erlaubt',
    },
    { key: 'backup', label: 'Backupfrequenz', children: formatDuration(policy.backupFrequencyMs) },
    {
      key: 'restore',
      label: 'Restore-Testintervall',
      children: formatDuration(policy.restoreTestIntervalMs),
    },
    { key: 'retention', label: 'Aufbewahrungsrichtlinie', children: policy.retentionPolicy },
    {
      key: 'effective',
      label: 'Wirksam ab Sequenz',
      children: String(policy.effectiveFromSequence),
    },
    {
      key: 'lease',
      label: 'Sequenz-Lease gültig bis Sequenz',
      children: String(policy.leaseValidThroughSequence),
    },
    { key: 'notAfter', label: 'Ablauf', children: formatInstant(policy.notAfterMs) },
  ]
  return (
    <Space direction="vertical" size="small">
      <Descriptions size="small" column={1} items={items} />
      <Typography.Paragraph>
        Die Richtlinie ist hier nur lesbar. Jede Änderung wird ein Root-signiertes Ereignis
        policyChange und läuft als Root-Zeremonie ohne freien Text.
      </Typography.Paragraph>
      <Button disabled={busy} onClick={onBegin}>
        Richtlinienänderung vorbereiten
      </Button>
    </Space>
  )
}
