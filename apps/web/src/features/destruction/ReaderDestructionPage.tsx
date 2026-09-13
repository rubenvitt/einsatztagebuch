import { Alert, Button, ConfigProvider, Input, Space, Typography } from 'antd'
import deDE from 'antd/locale/de_DE'
import { useId, useLayoutEffect, useRef, useState } from 'react'
import type { ReactElement } from 'react'
import type { ReaderSessionView } from '../../bridge/generated-contracts'
import { eaRuntimeTheme } from '../../design/tokens'
import type { FileModeDirectoryHandleV1, FileModeHost } from '../file-mode/DirectoryHandle'
import type { ReaderSessionBridge } from '../session/reader-session'
import { boundedRead, DELIVERY_READ_LIMITS, requireNotAborted } from './files'
import type { ReaderDestructionBridge, ReaderRemovalReceipt } from './reader-destruction'

type OriginalSlot = keyof typeof DELIVERY_READ_LIMITS
const slots: readonly [OriginalSlot, string][] = [['authorization', 'Autorisierung'], ['initiatingEvent', 'Startnachweis'], ['jobUpload', 'Jobdatei']]
export type ReaderDestructionPageProps = {
  readonly bridge: ReaderDestructionBridge
  readonly session: Pick<ReaderSessionBridge, 'unlock' | 'stateAt'>
  readonly host: FileModeHost
  readonly download: (bytes: Uint8Array) => void
}

/** Local cache actions only. Displayed hashes are selectors, never authority. */
export function ReaderDestructionPage({ bridge, session, host, download }: ReaderDestructionPageProps): ReactElement {
  const prefix = useId()
  const [view, setView] = useState<ReaderSessionView>()
  const [handle, setHandle] = useState<FileModeDirectoryHandleV1>()
  const [files, setFiles] = useState<Partial<Record<OriginalSlot, File>>>({})
  const [receipt, setReceipt] = useState<ReaderRemovalReceipt>()
  const [certificate, setCertificate] = useState('')
  const [historicalJob, setHistoricalJob] = useState('')
  const [failure, setFailure] = useState<string>()
  const [notice, setNotice] = useState<string>()
  const [busy, setBusy] = useState(false)
  const active = useRef<AbortController | undefined>(undefined)
  const generation = useRef(0)
  const mounted = useRef(true)
  // Retire changed session/source/sink bindings during commit, before late
  // replies can publish through callbacks retained by an earlier render.
  useLayoutEffect(() => {
    mounted.current = true
    setBusy(false)
    setView(undefined)
    setHandle(undefined)
    setReceipt(undefined)
    setNotice(undefined)
    setFailure(undefined)
    let cancelled = false
    const token = generation.current
    void session.stateAt(Date.now()).then(state => {
      if (!cancelled && token === generation.current) setView(state)
    }, reason => {
      if (!cancelled && token === generation.current) setFailure(reason instanceof Error ? reason.message : String(reason))
    })
    return () => {
      cancelled = true
      mounted.current = false
      generation.current += 1
      active.current?.abort()
      active.current = undefined
    }
  }, [session, bridge, host, download])

  function changed(): void {
    generation.current += 1
    active.current?.abort()
    setReceipt(undefined)
    setNotice(undefined)
    setFailure(undefined)
  }
  async function run(action: (signal: AbortSignal, current: () => void) => Promise<void>): Promise<void> {
    if (active.current !== undefined) return
    const controller = new AbortController()
    active.current = controller
    const token = ++generation.current
    const current = (): void => {
      requireNotAborted(controller.signal)
      if (!mounted.current || token !== generation.current) throw new DOMException('Aktion abgebrochen', 'AbortError')
    }
    setBusy(true); setFailure(undefined); setNotice(undefined)
    try {
      current()
      await action(controller.signal, current)
      current()
    } catch (reason) {
      if (mounted.current && token === generation.current && !(reason instanceof DOMException && reason.name === 'AbortError')) {
        setFailure(reason instanceof Error ? reason.message : String(reason))
      }
    } finally {
      if (active.current === controller) {
        active.current = undefined
        if (mounted.current) setBusy(false)
      }
    }
  }
  const ready = !busy && view !== undefined && !view.locked && handle !== undefined
  const hasOriginals = slots.every(([slot]) => files[slot] !== undefined)
  const hashShape = (value: string): boolean => /^[0-9a-f]{64}$/i.test(value)
  const picker = host.showDirectoryPicker

  return <ConfigProvider locale={deDE} theme={eaRuntimeTheme}>
    <section aria-label="Reader-Cache löschen">
      <Space orientation="vertical" size="large">
        <div>
          <Typography.Title level={2}>Eigenen Reader-Cache löschen</Typography.Title>
          <Typography.Paragraph>Hier entfernen Sie lokale Cachekopien zu einem bereits autorisierten und gestarteten Auftrag. Die Belege betreffen diesen Reader. Den Gesamtauftrag führt die Administration weiter.</Typography.Paragraph>
        </div>
        <Space orientation="vertical">
          <Typography.Text>{view === undefined ? 'Keine Tresorsitzung' : view.locked ? 'Tresorsitzung gesperrt' : 'Tresorsitzung entsperrt — zuletzt geprüft'}</Typography.Text>
          <Button disabled={busy} onClick={() => { void run(async (_signal, current) => {
            await session.unlock(Date.now()); current()
            const state = await session.stateAt(Date.now()); current(); setView(state)
          }) }}>Tresor entsperren</Button>
          {picker === undefined ? <Typography.Paragraph>Dieser Browser bietet keine Archivordnerauswahl. Für diese Cacheaktion wird ein tatsächlich ausgewählter Archivordner benötigt.</Typography.Paragraph> : <Button disabled={busy} onClick={() => {
            changed()
            void run(async (_signal, current) => { const selected = await picker.call(host); current(); setHandle(selected) })
          }}>Archivordner auswählen</Button>}
          {handle === undefined ? null : <Typography.Text>Archivordner ausgewählt</Typography.Text>}
        </Space>

        <section aria-label="Drei Originaldateien anwenden">
          <Space orientation="vertical" size="middle">
            <Typography.Title level={3}>1. Auftrag anwenden</Typography.Title>
            <Typography.Paragraph>Wählen Sie die drei getrennten Originaldateien aus der Administration. Ein Dateiname ist kein Typ- oder Berechtigungsnachweis. Autorisierung und Startnachweis dürfen jeweils bis zu 4 MiB, die Jobdatei bis zu 64 MiB groß sein.</Typography.Paragraph>
            {slots.map(([slot, label]) => <Space orientation="vertical" key={slot}>
              <label htmlFor={`${prefix}-${slot}`}>{label}</label>
              <input id={`${prefix}-${slot}`} type="file" disabled={busy} onChange={event => {
                changed()
                const selected = event.target.files?.[0]
                setFiles(previous => { const next = { ...previous }; if (selected === undefined) delete next[slot]; else next[slot] = selected; return next })
              }} />
            </Space>)}
            <Button danger disabled={!ready || !hasOriginals} onClick={() => {
              setReceipt(undefined)
              void run(async (signal, current) => {
                if (handle === undefined || files.authorization === undefined || files.initiatingEvent === undefined || files.jobUpload === undefined) return
                const [authorization, initiatingEvent, jobUpload] = await Promise.all([
                  boundedRead(files.authorization, DELIVERY_READ_LIMITS.authorization, signal),
                  boundedRead(files.initiatingEvent, DELIVERY_READ_LIMITS.initiatingEvent, signal),
                  boundedRead(files.jobUpload, DELIVERY_READ_LIMITS.jobUpload, signal),
                ])
                current()
                const measured = await bridge.apply(handle, { authorization, initiatingEvent, jobUpload }, signal)
                current(); setReceipt(measured)
              })
            }}>Eigenen Cache löschen</Button>
          </Space>
        </section>

        {receipt === undefined ? null : <section aria-label="Lokale Messquittung">
          <Typography.Title level={3}>Lokale Cacheentfernung gemessen</Typography.Title>
          <Typography.Paragraph>Jobhash: <code>{receipt.jobHash}</code></Typography.Paragraph>
          <Typography.Paragraph>Reader: <code>{receipt.replicaId}</code></Typography.Paragraph>
          <Typography.Paragraph>Entfernte Objekte: {receipt.removedObjectHashes.length}. Verbleibende Zielobjekte: {receipt.remainingObjectCount}.</Typography.Paragraph>
          <Typography.Paragraph>Die Messquittung allein ist noch kein signierter Löschbeleg.</Typography.Paragraph>
        </section>}

        <section aria-label="Aktueller lokaler Löschbeleg">
          <Space orientation="vertical" size="middle">
            <Typography.Title level={3}>2. Aktuellen Löschbeleg exportieren</Typography.Title>
            <Typography.Paragraph>Der Reader prüft den ausgewählten Archivordner erneut und verwendet sein separat autorisiertes Komponentenzertifikat. Übergeben Sie die heruntergeladene Originaldatei anschließend an die Administration.</Typography.Paragraph>
            <label htmlFor={`${prefix}-certificate`}>Komponentenzertifikat für den aktuellen Beleg</label>
            <Input id={`${prefix}-certificate`} value={certificate} maxLength={64} disabled={busy} onChange={event => { setCertificate(event.target.value); setNotice(undefined) }} />
            <Button disabled={!ready || receipt === undefined || !hashShape(certificate)} onClick={() => { void run(async (signal, current) => {
              if (handle === undefined || receipt === undefined) return
              const exact = await bridge.attest(handle, receipt.jobHash, certificate, signal)
              current(); download(exact); setNotice('Aktueller lokaler Löschbeleg zum Download übergeben.')
            }) }}>Aktuellen Löschbeleg herunterladen</Button>
          </Space>
        </section>

        <section aria-label="Historischer lokaler Löschbeleg">
          <Space orientation="vertical" size="middle">
            <Typography.Title level={3}>Gespeicherten Beleg nach Wiederöffnung lesen</Typography.Title>
            <Typography.Paragraph>Dieser getrennte historische Pfad gibt einen bereits gespeicherten Beleg nach erneuter Prüfung aus. Er führt keine neue Cacheentfernung oder aktuelle Signierung aus. Wählen Sie dafür erneut den zugehörigen Archivordner.</Typography.Paragraph>
            <label htmlFor={`${prefix}-historical`}>Jobhash des gespeicherten Belegs</label>
            <Input id={`${prefix}-historical`} value={historicalJob} maxLength={64} disabled={busy} onChange={event => { setHistoricalJob(event.target.value); setNotice(undefined) }} />
            <Button disabled={!ready || !hashShape(historicalJob)} onClick={() => { void run(async (signal, current) => {
              if (handle === undefined) return
              const exact = await bridge.historical(handle, historicalJob, signal)
              current(); download(exact); setNotice('Historischer lokaler Löschbeleg zum Download übergeben.')
            }) }}>Historischen Löschbeleg herunterladen</Button>
          </Space>
        </section>
        {busy ? <Typography.Text role="status">Aktion läuft …</Typography.Text> : null}
        {notice === undefined ? null : <Typography.Paragraph role="status">{notice}</Typography.Paragraph>}
        {failure === undefined ? null : <Alert type="error" showIcon title="Readeraktion nicht abgeschlossen" description={failure} />}
      </Space>
    </section>
  </ConfigProvider>
}
