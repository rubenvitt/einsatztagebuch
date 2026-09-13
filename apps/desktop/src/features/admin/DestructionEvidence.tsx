import { Alert, Button, Checkbox, Descriptions, Space, Typography } from 'antd'
import { useEffect, useRef, useState } from 'react'
import type { ReactElement } from 'react'

import { refusalCode } from './AdminPage'
import { DestructionStatus } from './DestructionStatus'
import { STALE_DECISION_VALUES } from '../../bridge/generated-contracts'
import type {
  DestructionEvidenceReviewView, DestructionProcessView, DiscardStateView,
  FinalizationPreviewView, FinalizeOutcomeView, PendingResumeOutcomeView,
} from '../../bridge/generated-contracts'

export type DestructionEvidenceBridge = {
  preview: (id: string, expectedPreflightHash: string) => Promise<DestructionEvidenceReviewView>
  finalize: (id: string, expectedPreflightHash: string, confirmed: FinalizationPreviewView) => Promise<FinalizeOutcomeView>
  recover: (id: string, expectedPreflightHash: string) => Promise<PendingResumeOutcomeView>
  discard: (id: string, expectedPreflightHash: string) => Promise<DiscardStateView>
}

export type DestructionBusyLease = {
  readonly current: () => boolean
  readonly release: () => void
}

/** Every mutation is explicit. Native Writer results never advance replica status. */
export function DestructionEvidence({ process, bridge, disabled, acquireBusy, onRefresh }: {
  readonly process: DestructionProcessView
  readonly bridge: DestructionEvidenceBridge
  readonly disabled: boolean
  readonly acquireBusy: () => DestructionBusyLease | null
  readonly onRefresh: () => Promise<void>
}): ReactElement {
  const [review, setReview] = useState<DestructionEvidenceReviewView | null>(null)
  const [confirmed, setConfirmed] = useState(false)
  const [discardConfirmed, setDiscardConfirmed] = useState(false)
  const [refused, setRefused] = useState<string | null>(null)
  const [refreshRefused, setRefreshRefused] = useState<string | null>(null)
  const [result, setResult] = useState<string | null>(null)
  const pending = useRef(false)
  const generation = useRef(0)
  useEffect(() => {
    generation.current += 1
    setReview(null)
    setConfirmed(false)
    setDiscardConfirmed(false)
    setRefused(null)
    setRefreshRefused(null)
    setResult(null)
    return () => { generation.current += 1 }
  }, [process, bridge])

  const run = async (action: (current: () => boolean) => Promise<void>): Promise<void> => {
    if (disabled || pending.current || process.preflight === null) return
    const lease = acquireBusy()
    if (lease === null) return
    const issued = generation.current
    const current = () => issued === generation.current && lease.current()
    pending.current = true
    setRefused(null)
    setRefreshRefused(null)
    setResult(null)
    setConfirmed(false)
    setDiscardConfirmed(false)
    try { await action(current) } catch (error: unknown) {
      if (current()) setRefused(refusalCode(error))
    } finally {
      // The operation owns this busy slot until native work returns, including
      // when its result refreshes the selected process or the view unmounts.
      pending.current = false
      lease.release()
    }
  }
  const refreshAfterResult = async (current: () => boolean): Promise<void> => {
    try { await onRefresh() } catch (error: unknown) {
      if (current()) setRefreshRefused(refusalCode(error))
    }
  }
  const id = process.destructionId
  const hash = process.preflight?.jobHash
  const fresh = review?.preview.staleDecision === STALE_DECISION_VALUES[0]
  return (
    <section aria-label="Vernichtungsnachweis als Writer-Eintrag">
      <Space direction="vertical" size="middle" style={{ width: '100%' }}>
        <Typography.Title level={4}>Vernichtungsnachweis als Writer-Eintrag</Typography.Title>
        <Typography.Paragraph>
          Der Nachweis erhält einen eigenen Writer-Entwurf. Ein vorhandener Einsatzentwurf muss zuvor regulär abgeschlossen oder verworfen werden.
          Die Vorbereitung und der endgültige Abschluss verlangen jeweils die Anmeldung des ausführenden Writer-Geräts.
        </Typography.Paragraph>
        <Typography.Paragraph>Offene Replikennachweise bleiben offen, auch wenn der Vernichtungsnachweis endgültig abgeschlossen ist.</Typography.Paragraph>
        {refused !== null && <Alert role="alert" type="error" title="Writer-Handlung nicht abgeschlossen" description={refused} />}
        {refreshRefused !== null && <Alert role="alert" type="warning" title="Vorgangsstand konnte nicht erneut gelesen werden" description={refreshRefused} />}
        {result !== null && <Typography.Paragraph role="status">{result}</Typography.Paragraph>}
        <Button disabled={disabled || hash === undefined} onClick={() => {
          void run(async (current) => {
            setReview(null)
            const next = await bridge.preview(id, hash!)
            if (current()) setReview(next)
          })
        }}>Vernichtungsnachweis vorbereiten</Button>
        {review !== null && (
          <>
            <Typography.Text>Ausführendes Writer-Gerät: <Typography.Text code>{review.writerDeviceId}</Typography.Text></Typography.Text>
            <DestructionStatus state={review.process.state} />
            <Typography.Paragraph>Vorgeschlagene Sequenz: {review.preview.proposedSequence}</Typography.Paragraph>
            <Descriptions column={1} size="small" items={[
              { key: 'id', label: 'Vorgang', children: review.process.destructionId },
              { key: 'hash', label: 'Vorbericht-Hash', children: review.process.preflight?.jobHash },
              { key: 'predecessor', label: 'An Vorgänger gebunden', children: review.preview.bindsPredecessor ? 'Ja' : 'Nein' },
              { key: 'time', label: 'Geprüfter Zeitpunkt (UTC)', children: new Date(review.preview.effectiveNow).toISOString() },
              { key: 'age', label: 'Alter des Vertrauensbestands (ms)', children: review.preview.trustAgeMs },
              { key: 'refresh', label: 'Auffrischungsfrist (ms)', children: review.preview.readerTrustRefreshMs },
              { key: 'overdue', label: 'Auffrischungsfrist überschritten', children: review.preview.trustRefreshOverdue ? 'Ja' : 'Nein' },
            ]} />
            <details><summary>Geprüften Nachweisstand vollständig anzeigen</summary>
              <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(review.process, null, 2)}</pre>
            </details>
            {!fresh ? <Alert type="warning" title="Vertrauensbestand aktualisieren" description="Die aktuelle Writer-Vorschau erlaubt diesen Abschluss noch nicht." /> : (
              <>
                <Checkbox checked={confirmed} disabled={disabled} onChange={(event) => setConfirmed(event.target.checked)}>
                  Ich habe den Vernichtungsnachweis und die Writer-Vorschau geprüft und möchte den Eintrag endgültig abschließen.
                </Checkbox>
                <Button type="primary" disabled={disabled || !confirmed} onClick={() => {
                  const confirmedPreview = review.preview
                  void run(async (current) => {
                    setReview(null)
                    const outcome = await bridge.finalize(id, hash!, confirmedPreview)
                    if (!current()) return
                    setResult(`Writer-Eintrag ${String(outcome.sequence)} abgeschlossen: ${outcome.entryHash}`)
                    await refreshAfterResult(current)
                  })
                }}>Vernichtungsnachweis endgültig abschließen</Button>
              </>
            )}
          </>
        )}
        <Button disabled={disabled || hash === undefined} onClick={() => {
          void run(async (current) => {
            setReview(null)
            const outcome = await bridge.recover(id, hash!)
            if (!current()) return
            if (outcome.blockedCode !== null) throw { code: outcome.blockedCode }
            setResult('Die gebundene Writer-Wiederaufnahme ist abgeschlossen. Der Vorgangsstand wird erneut gelesen.')
            await refreshAfterResult(current)
          })
        }}>Vorbereiteten Nachweisabschluss wieder aufnehmen</Button>
        <Checkbox checked={discardConfirmed} disabled={disabled || hash === undefined} onChange={(event) => setDiscardConfirmed(event.target.checked)}>
          Ich möchte nur den gebundenen Nachweisentwurf verwerfen. Der Vernichtungsvorgang bleibt bestehen.
        </Checkbox>
        <Button disabled={disabled || hash === undefined || !discardConfirmed} onClick={() => {
          void run(async (current) => {
            setReview(null)
            const outcome = await bridge.discard(id, hash!)
            if (!current()) return
            setResult(outcome.complete ? 'Der Nachweisentwurf ist verworfen. Der Vernichtungsvorgang bleibt bestehen.' : 'Das Verwerfen ist noch nicht abgeschlossen. Der Entwurf bleibt gesperrt.')
            await refreshAfterResult(current)
          })
        }}>Nachweisentwurf verwerfen</Button>
      </Space>
    </section>
  )
}
