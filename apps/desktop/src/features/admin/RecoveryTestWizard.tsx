import { Alert, Button, Descriptions, Space, Typography } from 'antd'
import { useEffect, useRef, useState } from 'react'
import type { ReactElement } from 'react'
import { refusalCode } from './AdminPage'
import { SIGNER_ROLE_VALUES } from '../../bridge/generated-contracts'
import type { RecoveryAdministrationView, RecoveryReportView } from '../../bridge/generated-contracts'
export type RecoveryBridge = {
  readonly initial: RecoveryAdministrationView
  refresh: () => Promise<RecoveryAdministrationView>
  reauthenticate: () => Promise<RecoveryAdministrationView>
  start: () => Promise<RecoveryAdministrationView>
  submit: (operationId: string, runId: string, requestId: string, choice: 0 | 1) => Promise<RecoveryAdministrationView>
  cancel: (operationId: string) => Promise<RecoveryAdministrationView>
}
const roles: Readonly<Record<string, string>> = {
  root: SIGNER_ROLE_VALUES[3], organizationAdmin: 'Organisationsverwaltung', writer: 'Erfassungsgerät',
  reader: 'Lesegerät', recoveryRecipient: 'Recovery-Empfänger', serverReceipt: 'Serverbeleg',
  keyApprover: 'Schlüsselfreigabe', historicalGrantAuthority: 'Historische Zugriffsfreigabe', deletionAttest: 'Vernichtungsattestierung',
}
const phases = ['Test wird vorbereitet', 'Sicherung bereitstellen', 'Sicherung wird geprüft',
  'Erfolgreich abgeschlossen', 'Mit Fehlerbericht abgeschlossen', 'Abgebrochen', 'Test nicht durchgeführt',
  'Abbruch wird abgeschlossen']

function Report({ report, title }: { readonly report: RecoveryReportView | null, readonly title: string }): ReactElement {
  return <section aria-label={title}>
    <Typography.Title level={4}>{title}</Typography.Title>
    {report === null ? <Typography.Paragraph>Kein verifizierter Bericht vorhanden.</Typography.Paragraph> : <>
      <Typography.Paragraph>Abgeschlossen: <time dateTime={new Date(report.finishedAtMs).toISOString()}>
        {new Date(report.finishedAtMs).toLocaleString('de-DE')}</time></Typography.Paragraph>
      {report.nextDueAtMs !== null && <Typography.Paragraph>Nächster Test: <time dateTime={new Date(report.nextDueAtMs).toISOString()}>
        {new Date(report.nextDueAtMs).toLocaleString('de-DE')}</time></Typography.Paragraph>}
      <Typography.Paragraph>Berichts-Hash: <Typography.Text code>{report.envelopeHash}</Typography.Text></Typography.Paragraph>
      <details><summary>Verifizierten Bericht anzeigen</summary>
        <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{report.exactPublicReportJson}</pre>
      </details>
    </>}
  </section>
}

/** Input selects one configured source; only native observations establish its result. */
export function RecoveryTestWizard({ bridge }: { readonly bridge: RecoveryBridge }): ReactElement {
  const [view, setView] = useState(bridge.initial)
  const [busy, setBusy] = useState(false)
  const [cancelling, setCancelling] = useState(false)
  const [refused, setRefused] = useState<string | null>(null)
  const generation = useRef(0)
  const pending = useRef(false)
  const cancelPending = useRef(false)
  useEffect(() => {
    generation.current += 1
    pending.current = false
    cancelPending.current = false
    setView(bridge.initial)
    setBusy(false)
    setCancelling(false)
    setRefused(null)
    return () => { generation.current += 1 }
  }, [bridge])

  const run = view.run
  const active = run !== null && (run.phaseCode <= 2 || run.phaseCode === 7)
  const needsLogin = refused === 'EA-DESKTOP-NO-VERIFIED-SESSION' || refused === 'EA-DESKTOP-ADMINISTRATION-FORBIDDEN'
  useEffect(() => {
    if (!active || needsLogin) return
    let live = true, polling = false
    const timer = setInterval(() => {
      if (!live || polling || pending.current) return
      polling = true
      const issued = generation.current
      bridge.refresh().then(
        next => { if (live && issued === generation.current) setView(next) },
        (error: unknown) => { if (live && issued === generation.current) setRefused(refusalCode(error)) },
      ).finally(() => { polling = false })
    }, 750)
    return () => { live = false; clearInterval(timer) }
  }, [active, bridge, needsLogin])

  const act = async (action: () => Promise<RecoveryAdministrationView>, cancel = false): Promise<void> => {
    if (cancel ? cancelPending.current : pending.current) return
    const issued = ++generation.current
    pending.current = true
    cancelPending.current = cancel
    setBusy(true)
    setCancelling(cancel)
    setRefused(null)
    try {
      const next = await action()
      if (issued === generation.current) setView(next)
    } catch (error: unknown) {
      if (issued === generation.current) setRefused(refusalCode(error))
    } finally {
      if (issued === generation.current) {
        pending.current = false
        cancelPending.current = false
        setBusy(false)
        setCancelling(false)
      }
    }
  }
  const request = run?.request ?? null
  return <section aria-label="Recovery-Test">
    <Space direction="vertical" size="large" style={{ width: '100%', overflowWrap: 'anywhere' }}>
      <Typography.Title level={3}>Recovery-Test</Typography.Title>
      <Typography.Paragraph>Stellen Sie jede angeforderte Sicherung einzeln bereit. Die Anwendung prüft den tatsächlichen Schlüssel und dokumentiert das Ergebnis.</Typography.Paragraph>
      {refused !== null && <Alert role="alert" type="error" title="Handlung nicht abgeschlossen" description={refused} />}
      {needsLogin && <Space direction="vertical">
        <Typography.Paragraph>Für weitere Aktionen ist eine gültige native Anmeldung erforderlich.</Typography.Paragraph>
        <Button disabled={busy} onClick={() => { void act(bridge.reauthenticate) }}>Erneut mit Betriebssystem anmelden</Button>
      </Space>}
      {run !== null && <div role="status" aria-live="polite">{phases[run.phaseCode]}</div>}
      {run?.errorCode != null && <Alert type="warning" title="Der Lauf hat keinen erfolgreichen Abschlussbericht erstellt." description={run.errorCode} />}
      {request !== null && <section aria-label="Angeforderte Sicherung">
        <Typography.Title level={4}>Sicherung {request.index} von {request.total}</Typography.Title>
        <Descriptions column={1} size="small" items={[
          { key: 'role', label: 'Rolle', children: roles[request.roleCode] ?? request.roleCode },
          { key: 'certificate', label: 'Zertifikat', children: request.certificateHash },
          { key: 'expected', label: 'Erwarteter Fingerabdruck', children: request.expectedThumbprint },
        ]} />
        {run?.phaseCode === 1 && <Space wrap>
          <Button type="primary" disabled={busy || needsLogin} onClick={() => { void act(() => bridge.submit(run.operationId, request.runId, request.requestId, 0)) }}>
            Bereitgestellte Sicherung prüfen
          </Button>
          <Button disabled={busy || needsLogin} onClick={() => { void act(() => bridge.submit(run.operationId, request.runId, request.requestId, 1)) }}>Sicherung fehlt</Button>
        </Space>}
      </section>}
      {(run?.observations.length ?? 0) > 0 && <section aria-label="Geprüfte Sicherungen">
        <Typography.Title level={4}>Geprüfte Sicherungen</Typography.Title>
        <ol>{run!.observations.map(observation => <li key={observation.request.requestId}>
          <Typography.Paragraph>{roles[observation.request.roleCode] ?? observation.request.roleCode}: <strong>{['Bestanden', 'Fehlt', 'Fehlgeschlagen'][observation.resultCode]}</strong></Typography.Paragraph>
          <Typography.Paragraph>Erwartet: <Typography.Text code>{observation.request.expectedThumbprint}</Typography.Text></Typography.Paragraph>
          <Typography.Paragraph>Beobachtet: {observation.observedThumbprint === null ? 'Kein Schlüssel nachgewiesen' : <Typography.Text code>{observation.observedThumbprint}</Typography.Text>}</Typography.Paragraph>
          {observation.errorCode !== null && <Typography.Paragraph>{observation.errorCode}</Typography.Paragraph>}
        </li>)}</ol>
      </section>}
      <Space wrap>
        {active && run !== null ? <Button danger disabled={cancelling || needsLogin || run.phaseCode === 7} onClick={() => { void act(() => bridge.cancel(run.operationId), true) }}>Test abbrechen</Button>
          : <Button type="primary" disabled={busy || needsLogin} onClick={() => { void act(bridge.start) }}>Recovery-Test starten</Button>}
        <Button disabled={busy} onClick={() => { void act(bridge.refresh) }}>Status neu lesen</Button>
      </Space>
      <Report title="Letzter erfolgreicher Test" report={view.lastSuccess} />
      <Report title="Letzter fehlgeschlagener Test" report={view.lastFailure} />
    </Space>
  </section>
}
