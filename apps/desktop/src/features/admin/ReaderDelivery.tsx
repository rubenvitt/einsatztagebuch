import { Alert, Button, Space, Typography } from 'antd'
import { useEffect, useId, useRef, useState } from 'react'
import type { ReactElement } from 'react'
import { refusalCode } from './AdminPage'
import type { DestructionBusyLease } from './DestructionEvidence'
import type { ReaderDeliveryBridge } from './reader-delivery-bridge'
import { DESTRUCTION_STATE_V1_VALUES } from '../../bridge/generated-contracts'
import type { DestructionProcessView, DestructionReaderDeliveryView } from '../../bridge/generated-contracts'

function DownloadFiles({ delivery }: { readonly delivery: DestructionReaderDeliveryView }): ReactElement {
  const [links, setLinks] = useState<readonly { label: string; filename: string; url: string }[]>([])
  const [failed, setFailed] = useState(false)
  useEffect(() => {
    const made: { label: string; filename: string; url: string }[] = []
    try {
      const prefix = `${delivery.destructionId}-${delivery.readerId}`
      for (const [label, suffix, exact] of [
        ['Autorisierung speichern', 'authorization.etb', delivery.exactAuthorization],
        ['Startnachweis speichern', 'started.etb', delivery.exactInitiatingEvent],
        ['Auftragsdatei speichern', 'job-upload.cbor', delivery.exactJobUpload],
      ] as const) {
        made.push({ label, filename: `${prefix}-${suffix}`, url: URL.createObjectURL(new Blob([Uint8Array.from(exact)], { type: 'application/octet-stream' })) })
      }
      setLinks(made)
      setFailed(false)
    } catch {
      for (const link of made) URL.revokeObjectURL(link.url)
      made.length = 0
      setLinks([])
      setFailed(true)
    }
    return () => { for (const link of made) URL.revokeObjectURL(link.url) }
  }, [delivery])
  if (failed) return <Alert role="alert" type="error" title="Dateilinks konnten nicht erstellt werden" />
  return <>
    {links.length === 3 && <Typography.Paragraph role="status">Dateien stehen bereit. Speichern Sie alle drei Dateien für das ausgewählte Lesegerät.</Typography.Paragraph>}
    <ul>{links.map((link) => <li key={link.filename}><a href={link.url} download={link.filename}>{link.label}</a></li>)}</ul>
  </>
}

/** Explicit public-original handoff; this never changes a job or claims a Reader result. */
export function ReaderDelivery({ process, bridge, disabled, acquireBusy }: {
  readonly process: DestructionProcessView
  readonly bridge: ReaderDeliveryBridge
  readonly disabled: boolean
  readonly acquireBusy: () => DestructionBusyLease | null
}): ReactElement {
  const inputId = useId()
  const [reader, setReader] = useState('')
  const [delivery, setDelivery] = useState<DestructionReaderDeliveryView | null>(null)
  const [refused, setRefused] = useState<string | null>(null)
  const [working, setWorking] = useState(false)
  const generation = useRef(0)
  const pending = useRef(false)
  useEffect(() => {
    generation.current += 1
    setReader('')
    setDelivery(null)
    setRefused(null)
    return () => { generation.current += 1 }
  }, [process, bridge])
  const readers = process.replicas.filter((replica) => replica.kindCode === 1)
  const allowed = !disabled && !working && process.preflight !== null
    && process.state !== DESTRUCTION_STATE_V1_VALUES[0] && readers.some((replica) => replica.deviceId === reader)
  const run = async (): Promise<void> => {
    if (!allowed || pending.current || process.preflight === null) return
    const lease = acquireBusy()
    if (lease === null) return
    const issued = generation.current
    pending.current = true
    setWorking(true)
    setDelivery(null)
    setRefused(null)
    try {
      const result = await bridge.export(process.destructionId, process.preflight.jobHash, reader)
      if (issued === generation.current && lease.current()) setDelivery(result)
    } catch (error: unknown) {
      if (issued === generation.current && lease.current()) setRefused(refusalCode(error))
    } finally {
      pending.current = false
      setWorking(false)
      lease.release()
    }
  }
  return <section aria-label="Auftrag an Lesegerät übergeben">
    <Space orientation="vertical" size="middle">
      <Typography.Title level={4}>Auftrag an Lesegerät übergeben</Typography.Title>
      <Typography.Paragraph>Wählen Sie das Lesegerät und speichern Sie die drei Originaldateien. Importieren Sie diese im entsperrten Reader zusammen mit dem ausdrücklich ausgewählten Archivordner. Ein Repliknachweis ist damit noch nicht erbracht.</Typography.Paragraph>
      <label htmlFor={inputId}>Lesegerät für die Übergabe</label>
      <select id={inputId} value={reader} disabled={disabled || working} onChange={(event) => {
        setReader(event.target.value)
        setDelivery(null)
        setRefused(null)
      }}>
        <option value="">Lesegerät auswählen</option>
        {readers.map((replica) => <option key={replica.deviceId} value={replica.deviceId}>{replica.deviceId}</option>)}
      </select>
      {readers.length === 0 && <Typography.Paragraph>Im verifizierten Auftrag ist kein Lesegerät enthalten.</Typography.Paragraph>}
      <Button aria-label="Dateien für Lesegerät bereitstellen" disabled={!allowed} loading={working} onClick={() => { void run() }}>Dateien für Lesegerät bereitstellen</Button>
      {refused !== null && <Alert role="alert" type="error" title="Übergabedateien nicht bereitgestellt" description={refused} />}
      {delivery !== null && <DownloadFiles delivery={delivery} />}
    </Space>
  </section>
}
