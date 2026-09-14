import { Alert, Button, Checkbox, Descriptions, Modal, Space, Typography } from 'antd'
import { useEffect, useId, useRef, useState } from 'react'
import type { ReactElement } from 'react'

import { refusalCode } from './AdminPage'
import { DestructionEvidence } from './DestructionEvidence'
import type { DestructionBusyLease, DestructionEvidenceBridge } from './DestructionEvidence'
import { DestructionStatus } from './DestructionStatus'
import { markIncompleteOffered } from './mark-incomplete-offer'
import { ReaderDelivery } from './ReaderDelivery'
import type { ReaderDeliveryBridge } from './reader-delivery-bridge'
import { DESTRUCTION_STATE_V1_VALUES } from '../../bridge/generated-contracts'
import type { DestructionAdministrationView, DestructionProcessView } from '../../bridge/generated-contracts'

const [REQUESTED, , , COMPLETE] = DESTRUCTION_STATE_V1_VALUES

/** The selected signed file is passed unchanged; parsing and fresh presence live in the host. */
export type DestructionBridge = {
  readonly initial: DestructionAdministrationView
  importAuthorization: (exactAuthorization: readonly number[]) => Promise<DestructionAdministrationView | null>
  importProgress: (destructionId: string, expectedPreflightHash: string, exactEtbObjects: readonly (readonly number[])[]) => Promise<DestructionAdministrationView>
  refresh: () => Promise<DestructionAdministrationView>
  select: (destructionId: string) => Promise<DestructionAdministrationView>
  start: (destructionId: string, expectedPreflightHash: string) => Promise<DestructionAdministrationView>
  resume: (destructionId: string) => Promise<DestructionAdministrationView>
  synchronize: (destructionId: string, expectedPreflightHash: string) => Promise<DestructionAdministrationView>
  authenticateCustodian: (destructionId: string, expectedPreflightHash: string) => Promise<DestructionAdministrationView>
  /** The explicit, separately confirmed final action; never part of resume. */
  markIncomplete: (destructionId: string, expectedPreflightHash: string) => Promise<DestructionAdministrationView>
}

class AuthorizationFileError extends Error {}

function exactFile(file: File, label = 'Die Autorisierungsdatei'): Promise<number[]> {
  // Keep the renderer allocation bounded by the existing native ETB limit.
  if (file.size === 0 || file.size > 4 * 1024 * 1024) {
    return Promise.reject(new AuthorizationFileError(`${label} muss zwischen 1 Byte und 4 MiB groß sein.`))
  }
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onerror = () => { reject(new AuthorizationFileError(`${label} konnte nicht gelesen werden.`)) }
    reader.onabort = reader.onerror
    reader.onload = () => {
      if (!(reader.result instanceof ArrayBuffer)) {
        reject(new AuthorizationFileError(`${label} konnte nicht gelesen werden.`))
      } else {
        resolve(Array.from(new Uint8Array(reader.result)))
      }
    }
    reader.readAsArrayBuffer(file)
  })
}

async function exactProgressFiles(files: readonly File[]): Promise<number[][]> {
  if (files.length === 0 || files.length > 256) throw new AuthorizationFileError('Wählen Sie mindestens eine und höchstens 256 Dateien aus.')
  if (files.reduce((sum, file) => sum + file.size, 0) > 16 * 1024 * 1024) throw new AuthorizationFileError('Die ausgewählten Nachweise dürfen zusammen höchstens 16 MiB groß sein.')
  const exact: number[][] = []
  for (const file of files) exact.push(await exactFile(file, 'Die Nachweisdatei'))
  return exact
}

function ProcessDetails({ process }: { readonly process: DestructionProcessView }): ReactElement {
  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <DestructionStatus state={process.state} />
      <Descriptions column={1} size="small" items={[
        { key: 'id', label: 'Vorgang', children: process.destructionId },
        { key: 'authorization', label: 'Autorisierungs-Hash', children: process.authorizationObjectHash },
        { key: 'scope', label: 'Umfangscode', children: process.scopeCode },
        { key: 'reason', label: 'Rechtsgrund-Code', children: process.legalReasonCode },
        { key: 'controller', label: 'Verwaltendes Gerät', children: process.controllerDeviceId },
        { key: 'custodian', label: 'Ausführendes Writer-Gerät', children: process.custodianDeviceId },
      ]} />
      <section aria-label="Autorisierte Ziele">
        <Typography.Title level={4}>Autorisierte Ziele</Typography.Title>
        <ul>
          {process.targets.map((target) => (
            <li key={target.entryHash}>
              <Typography.Text>Sequenz {target.chainSequence}: </Typography.Text>
              <Typography.Text code>{target.entryHash}</Typography.Text>
              <Typography.Paragraph>
                {target.stubObjectHash === null ? 'Kein verifizierter Stub im beobachteten Bestand.' : (
                  <>Verifizierter Stub: <Typography.Text code>{target.stubObjectHash}</Typography.Text></>
                )}
              </Typography.Paragraph>
            </li>
          ))}
        </ul>
      </section>
      <section aria-label="Finalisierter Vernichtungsnachweis">
        <Typography.Title level={4}>Finalisierter Vernichtungsnachweis</Typography.Title>
        {process.evidenceEntryHash === null ? (
          <Typography.Paragraph>Ein finalisierter Vernichtungsnachweis ist noch nicht nachgewiesen.</Typography.Paragraph>
        ) : (
          <Typography.Paragraph>Eintrags-Hash: <Typography.Text code>{process.evidenceEntryHash}</Typography.Text></Typography.Paragraph>
        )}
      </section>
      <section aria-label="Zwei-Personen-Autorisierung">
        <Typography.Title level={4}>Zwei-Personen-Autorisierung</Typography.Title>
        <ul>
          {process.approverCertificateHashes.map((hash) => (
            <li key={hash}><Typography.Text code>{hash}</Typography.Text></li>
          ))}
        </ul>
      </section>
      {process.preflight !== null ? (
        <section aria-label="Verifizierter Vorbericht">
          <Typography.Title level={4}>Verifizierter Vorbericht</Typography.Title>
          <Typography.Paragraph>Bekannte Repliken: {process.preflight.knownReplicaCount}</Typography.Paragraph>
          <Typography.Paragraph>Vorbericht-Hash: <Typography.Text code>{process.preflight.jobHash}</Typography.Text></Typography.Paragraph>
          <details>
            <summary>Vollständigen Vorbericht anzeigen</summary>
            <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{process.preflight.exactCanonicalReportJson}</pre>
          </details>
        </section>
      ) : (
        <Typography.Text>Ein verifizierter Vorbericht liegt noch nicht vor.</Typography.Text>
      )}
      <section aria-label="Replikennachweise">
        <Typography.Title level={4}>Verwaltete Repliken</Typography.Title>
        {process.replicas.length === 0 ? <Typography.Text>Ein verifiziertes Replikenverzeichnis liegt noch nicht vor.</Typography.Text> : (
          <div style={{ overflowX: 'auto' }}>
            <table className="ea-destruction-replica-table" aria-label="Verwaltete Repliken">
              <thead><tr><th scope="col">Gerät</th><th scope="col">Art</th><th scope="col">Nachweisstand</th><th scope="col">Attestierung</th><th scope="col">Backup-Frist (UTC)</th></tr></thead>
              <tbody>{process.replicas.map((replica) => (
                <tr key={replica.deviceId}>
                  <th scope="row"><Typography.Text code>{replica.deviceId}</Typography.Text></th>
                  <td>{['Erfassungsgerät', 'Lesegerät', 'Sync-Server'][replica.kindCode]}</td>
                  <td>{replica.resultCode === null ? 'Noch keine Attestierung' : [
                    'Erfolgsattestierung verifiziert', 'Backup-Frist offen', 'Replik nicht erreichbar',
                  ][replica.resultCode]}</td>
                  <td>{replica.attestationHash === null ? 'Kein Nachweis' : <Typography.Text code>{replica.attestationHash}</Typography.Text>}</td>
                  <td>{replica.backupExpiryAt === null ? 'Keine Frist attestiert' : (
                    <time dateTime={new Date(replica.backupExpiryAt).toISOString()}>{new Date(replica.backupExpiryAt).toISOString()}</time>
                  )}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
        <Typography.Paragraph>Eine verstrichene Backup-Frist ersetzt keine Erfolgsattestierung. Der Status wird erst nach erneuter Prüfung im verwalteten Bestand aktualisiert.</Typography.Paragraph>
      </section>
    </Space>
  )
}

/** Shows only durable host results. A successful click never advances the state locally. */
export function DestructionWizard({ bridge, evidenceBridge, readerDeliveryBridge }: {
  readonly bridge: DestructionBridge
  readonly evidenceBridge?: DestructionEvidenceBridge
  readonly readerDeliveryBridge?: ReaderDeliveryBridge
}): ReactElement {
  const [view, setView] = useState(bridge.initial)
  const [confirmed, setConfirmed] = useState(false)
  const [finalOpen, setFinalOpen] = useState(false)
  const [finalConfirmed, setFinalConfirmed] = useState(false)
  const [busy, setBusy] = useState(false)
  const [refused, setRefused] = useState<string | null>(null)
  const [authorizationFile, setAuthorizationFile] = useState<File | null>(null)
  const [progressFiles, setProgressFiles] = useState<readonly File[]>([])
  const authorizationInputId = useId()
  const progressInputId = useId()
  const processInputId = useId()
  const pending = useRef<symbol | null>(null)
  const generation = useRef(0)

  useEffect(() => {
    generation.current += 1
    pending.current = null
    setView(bridge.initial)
    setConfirmed(false)
    setFinalOpen(false)
    setFinalConfirmed(false)
    setBusy(false)
    setRefused(null)
    setAuthorizationFile(null)
    setProgressFiles([])
    return () => { generation.current += 1 }
  }, [bridge])

  const acquireBusy = (): DestructionBusyLease | null => {
    if (pending.current !== null) return null
    const owner = Symbol('destruction operation')
    pending.current = owner
    setBusy(true)
    return {
      current: () => pending.current === owner,
      release: () => {
        if (pending.current === owner) {
          pending.current = null
          setBusy(false)
        }
      },
    }
  }

  const run = async (action: () => Promise<DestructionAdministrationView | null>): Promise<void> => {
    const lease = acquireBusy()
    if (lease === null) return
    const requestGeneration = generation.current
    setRefused(null)
    setConfirmed(false)
    try {
      const next = await action()
      if (requestGeneration === generation.current && next !== null) {
        setView(next)
        setAuthorizationFile(null)
        setProgressFiles([])
      }
    } catch (error: unknown) {
      if (requestGeneration === generation.current) {
        setRefused(error instanceof AuthorizationFileError ? error.message : refusalCode(error))
      }
    } finally {
      lease.release()
    }
  }

  const process = view.process
  const canReviewStart = process?.state === REQUESTED && process.preflight !== null
    && process.targets.length > 0 && process.approverCertificateHashes.length >= 2
    && new Set(process.approverCertificateHashes).size === process.approverCertificateHashes.length
  const canResume = process !== null && process.state !== REQUESTED && process.state !== COMPLETE
  // Visibility only; the host re-reads and decides with its own time.
  const canMarkIncomplete = process !== null && markIncompleteOffered(process, Date.now())
  const closeFinal = (): void => {
    setFinalOpen(false)
    setFinalConfirmed(false)
  }

  return (
    <section aria-label="Kontrollierte Vernichtung">
      <Space direction="vertical" size="large" style={{ width: '100%' }}>
        <Typography.Title level={3}>Kontrollierte Vernichtung</Typography.Title>
        {view.knownDestructionIds.length > 0 && (
          <>
            <label htmlFor={processInputId}>Gespeicherter Vernichtungsvorgang</label>
            <select id={processInputId} value={process?.destructionId ?? ''} disabled={busy} onChange={(event) => {
              const selected = event.target.value
              if (view.knownDestructionIds.includes(selected)) void run(() => bridge.select(selected))
            }}>
              <option value="" disabled>Vorgang auswählen</option>
              {view.knownDestructionIds.map((id) => <option value={id} key={id}>{id}</option>)}
            </select>
          </>
        )}
        {!view.privacyDecisionEnabled && (
          <Alert type="warning" title="Datenschutzrechtliche Freigabe fehlt" description="Die dokumentierte Richtlinie lässt keinen neuen Vernichtungsvorgang zu." />
        )}
        {refused !== null && <Alert role="alert" type="error" title="Handlung nicht abgeschlossen" description={refused} />}
        {process === null ? (
          <>
            <Typography.Paragraph>
              Importieren Sie die von zwei berechtigten Personen signierte Autorisierung.
              Prüfen Sie anschließend Ziele, Umfang, Rechtsgrund und bekannte Repliken im Vorbericht.
            </Typography.Paragraph>
            <label htmlFor={authorizationInputId}>Signierte Vernichtungsautorisierung</label>
            <input id={authorizationInputId} type="file" accept=".etb" disabled={busy || !view.privacyDecisionEnabled}
              onChange={(event) => { setAuthorizationFile(event.target.files?.[0] ?? null) }} />
            <Button disabled={busy || !view.privacyDecisionEnabled || authorizationFile === null} onClick={() => {
              if (authorizationFile !== null) void run(async () => bridge.importAuthorization(await exactFile(authorizationFile)))
            }}>
              Vernichtung beantragen
            </Button>
          </>
        ) : <ProcessDetails process={process} />}
        {process !== null && process.preflight !== null && process.state !== REQUESTED && readerDeliveryBridge !== undefined && (
          <ReaderDelivery process={process} bridge={readerDeliveryBridge} disabled={busy} acquireBusy={acquireBusy} />
        )}
        {process !== null && process.preflight !== null && process.state !== REQUESTED && evidenceBridge !== undefined && (
          <DestructionEvidence process={process} bridge={evidenceBridge} disabled={busy}
            acquireBusy={acquireBusy}
            onRefresh={async () => {
              const requestGeneration = generation.current
              const next = await bridge.refresh()
              if (requestGeneration === generation.current) setView(next)
            }} />
        )}
        {process !== null && process.preflight !== null && process.state !== REQUESTED && (
          <section aria-label="Signierte Nachweise importieren">
            <Space direction="vertical">
              <Typography.Title level={4}>Weitere Repliknachweise</Typography.Title>
              <Typography.Paragraph>Importieren Sie signierte Attestierungen oder Statusereignisse für diesen Vorgang. Die Anwendung prüft ihre Zuordnung und Signaturen mit einer erneuten nativen Anmeldung.</Typography.Paragraph>
              <label htmlFor={progressInputId}>Signierte Repliknachweise oder Statusereignisse</label>
              <input id={progressInputId} type="file" accept=".etb" multiple disabled={busy}
                onChange={(event) => { setProgressFiles(Array.from(event.target.files ?? [])) }} />
              <Button disabled={busy || progressFiles.length === 0} onClick={() => {
                void run(async () => bridge.importProgress(process.destructionId, process.preflight!.jobHash, await exactProgressFiles(progressFiles)))
              }}>Signierte Nachweise importieren</Button>
            </Space>
          </section>
        )}
        {canReviewStart && process !== null && (
          <Space direction="vertical">
            <Typography.Paragraph>
              Mit dem Start beginnt die unwiderrufliche Vernichtung der oben genannten Ziele.
              Die Anwendung fordert dafür erneut Ihre native Anmeldung an.
            </Typography.Paragraph>
            <Checkbox checked={confirmed} disabled={busy || !view.privacyDecisionEnabled} onChange={(event) => { setConfirmed(event.target.checked) }}>
              Ich bestätige die angezeigten Ziele und den Vorbericht und möchte die Vernichtung unwiderruflich starten.
            </Checkbox>
            <Button danger type="primary" disabled={busy || !confirmed || !view.privacyDecisionEnabled} onClick={() => {
              if (confirmed && process.preflight !== null && view.privacyDecisionEnabled) {
                void run(() => bridge.start(process.destructionId, process.preflight!.jobHash))
              }
            }}>
              Unwiderruflich starten
            </Button>
          </Space>
        )}
        <Space wrap>
          {process !== null && process.preflight !== null && (
            <Button disabled={busy} onClick={() => { void run(() => bridge.authenticateCustodian(process.destructionId, process.preflight!.jobHash)) }}>
              Ausführendes Writer-Gerät anmelden
            </Button>
          )}
          {process !== null && (
            <Button disabled={busy || !view.privacyDecisionEnabled} onClick={() => {
              if (!pending.current && view.privacyDecisionEnabled) {
                setConfirmed(false)
                setRefused(null)
                setAuthorizationFile(null)
                setProgressFiles([])
                setView({ ...view, process: null })
              }
            }}>
              Weitere Autorisierung importieren
            </Button>
          )}
          {canResume && process !== null && (
            <Button disabled={busy} onClick={() => { void run(() => bridge.resume(process.destructionId)) }}>
              Vernichtung fortsetzen
            </Button>
          )}
          {canMarkIncomplete && process !== null && (
            <Button danger disabled={busy} onClick={() => {
              setFinalConfirmed(false)
              setFinalOpen(true)
            }}>
              Als unvollständig abschließen
            </Button>
          )}
          {process?.preflight !== null && process !== null && process.replicas.some((replica) => replica.kindCode === 2) && (
            <Button disabled={busy} onClick={() => { void run(() => bridge.synchronize(process.destructionId, process.preflight!.jobHash)) }}>
              Servernachweise abgleichen
            </Button>
          )}
          <Button disabled={busy} onClick={() => { void run(bridge.refresh) }}>Status neu lesen</Button>
        </Space>
        {finalOpen && canMarkIncomplete && (
        // Mounted only while open: closing leaves no stale consent or dialog behind.
        <Modal
          open
          title="Vorgang endgültig als unvollständig abschließen?"
          onCancel={closeFinal}
          footer={[
            <Button key="back" onClick={closeFinal}>Zurück</Button>,
            <Button key="confirm" danger type="primary" disabled={busy || !finalConfirmed} onClick={() => {
              if (!finalConfirmed || process === null || process.preflight === null) return
              const destructionId = process.destructionId
              const jobHash = process.preflight.jobHash
              closeFinal()
              void run(() => bridge.markIncomplete(destructionId, jobHash))
            }}>
              Endgültig als unvollständig abschließen
            </Button>,
          ]}
        >
          <Typography.Paragraph>
            Mindestens eine bekannte Replik hat keine gültige Attestierung, oder eine attestierte Backup-Frist ist abgelaufen. Die Anwendung signiert dafür den Status „bekannte Replik nicht erreichbar“.
          </Typography.Paragraph>
          <Typography.Paragraph>
            Dieser Schritt ist endgültig. Später eingehende Nachweise ändern diesen Status nicht mehr, und einen Rückweg zur Fortsetzung gibt es derzeit nicht. Importieren oder gleichen Sie vorher alle vorliegenden Nachweise ab.
          </Typography.Paragraph>
          <Typography.Paragraph>
            Der Abschluss bestätigt keine Löschung auf den betroffenen Repliken.
          </Typography.Paragraph>
          <Checkbox checked={finalConfirmed} disabled={busy} onChange={(event) => { setFinalConfirmed(event.target.checked) }}>
            Ich habe verstanden, dass dieser Abschluss endgültig ist.
          </Checkbox>
        </Modal>
        )}
      </Space>
    </section>
  )
}
