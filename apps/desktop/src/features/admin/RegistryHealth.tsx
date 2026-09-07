import { Descriptions, Typography } from 'antd'
import type { ReactElement } from 'react'

import { formatInstant } from './format'
import { STALE_TEXT, formatDuration } from '../../app/TrustAgeStatus'
import type { RegistryHealthView } from '../../bridge/generated-contracts'

/**
 * Der Zustand der gebundenen Registry.
 *
 * Alter und Sequenz-Lease stehen als ZWEI getrennte Zahlen da und werden nie
 * zusammengefasst: das Alter laeuft gegen `maxRegistryAgeMs` (§12.6, kein
 * zweiter lokaler Ablauf, keine Gnadenfrist), die Lease gegen die naechste
 * Sequenz — zwei Aussagen mit zwei Grenzen. Die Frischeentscheidung ist
 * dieselbe Abbildung wie in `TrustAgeStatus`, damit derselbe Wert nirgends
 * zwei Wortlaute hat.
 */
export function RegistryHealth({ health }: { readonly health: RegistryHealthView }): ReactElement {
  const items = [
    { key: 'version', label: 'Registry-Version', children: String(health.registryVersion) },
    {
      key: 'head',
      label: 'Head-Hash',
      children: <Typography.Text code>{health.headHash}</Typography.Text>,
    },
    { key: 'age', label: 'Registry-Alter', children: formatDuration(health.registryAgeMs) },
    { key: 'maxAge', label: 'Höchstalter', children: formatDuration(health.maxRegistryAgeMs) },
    {
      key: 'lease',
      label: 'Sequenz-Lease gültig bis Sequenz',
      children: String(health.leaseValidThroughSequence),
    },
    { key: 'next', label: 'Nächste Sequenz', children: String(health.nextSequence) },
    { key: 'notAfter', label: 'Ablauf', children: formatInstant(health.notAfterMs) },
    { key: 'stale', label: 'Frische', children: STALE_TEXT[health.staleDecision] },
  ]
  return <Descriptions size="small" column={1} items={items} />
}
