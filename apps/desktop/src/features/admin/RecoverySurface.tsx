import { invoke } from '@tauri-apps/api/core'
import { Alert, Button, Space, Typography } from 'antd'
import { useEffect, useRef, useState } from 'react'
import type { ReactElement } from 'react'
import { refusalCode } from './AdminPage'
import { ContractViolation } from './contract-check'
import { validateRecoveryAdministration } from './recovery-contract'
import { RecoveryTestWizard } from './RecoveryTestWizard'
import { validateSession } from '../../app/session-lock'
import type { RecoveryBridge } from './RecoveryTestWizard'
type NativeCall = (command: string, args?: Record<string, unknown>) => Promise<unknown>
const nativeCall: NativeCall = (command, args) => invoke<unknown>(command, args)
async function authenticate(call: NativeCall): Promise<void> {
  const session = validateSession(await call('session_login'))
  if (session.role !== 'organizationadmin' || !session.capabilities.includes('administration')) {
    throw new ContractViolation('Die native Anmeldung hat keine Verwaltungssitzung bestätigt.')
  }
}
export async function connectRecoveryBridge(call: NativeCall = nativeCall): Promise<RecoveryBridge> {
  const initial = validateRecoveryAdministration(await call('recovery_read'))
  let operation = initial.run?.operationId
  const checked = async (command: string, args: Record<string, unknown>, expected?: string) => {
    const next = validateRecoveryAdministration(await call(command, args))
    if ((expected !== undefined && next.run?.operationId !== expected)
      || (command !== 'recovery_read' && next.run === null)) {
      throw new ContractViolation('Der native Recovery-Stand gehört nicht zum angeforderten Lauf.')
    }
    operation = next.run?.operationId
    return next
  }
  return { initial,
    reauthenticate: async () => { await authenticate(call); return checked('recovery_read', {}, operation) },
    refresh: () => checked('recovery_read', {}, operation),
    start: () => checked('recovery_start', {}),
    submit: (operationId, runId, requestId, choice) => checked('recovery_submit', { operationId, runId, requestId, choice }, operationId),
    cancel: (operationId) => checked('recovery_cancel', { operationId }, operationId),
  }
}
const nativeLogin = () => authenticate(nativeCall)
export function RecoverySurface({ connect = connectRecoveryBridge, login = nativeLogin }: {
  readonly connect?: () => Promise<RecoveryBridge>
  readonly login?: () => Promise<void>
}): ReactElement {
  const [bridge, setBridge] = useState<RecoveryBridge | null>(null)
  const [refused, setRefused] = useState<string | null>(null)
  const [attempt, setAttempt] = useState(0)
  const [loggingIn, setLoggingIn] = useState(false)
  const generation = useRef(0)
  const loginPending = useRef(false)
  useEffect(() => {
    generation.current += 1
    let live = true
    setBridge(null)
    setRefused(null)
    connect().then(
      next => { if (live) setBridge(next) },
      (error: unknown) => { if (live) setRefused(refusalCode(error)) },
    )
    return () => { live = false; generation.current += 1 }
  }, [connect, attempt])
  const renew = async (): Promise<void> => {
    if (loginPending.current) return
    const issued = generation.current
    loginPending.current = true
    setLoggingIn(true)
    try {
      await login()
      if (issued === generation.current) setAttempt(value => value + 1)
    } catch (error: unknown) {
      if (issued === generation.current) setRefused(refusalCode(error))
    } finally {
      loginPending.current = false
      if (issued === generation.current) setLoggingIn(false)
    }
  }
  if (refused !== null) return <Space direction="vertical">
    <Alert role="alert" type="error" title="Recovery-Test nicht geöffnet" description={refused} />
    {(refused === 'EA-DESKTOP-NO-VERIFIED-SESSION' || refused === 'EA-DESKTOP-ADMINISTRATION-FORBIDDEN') &&
      <Button disabled={loggingIn} onClick={() => { void renew() }}>Erneut mit Betriebssystem anmelden</Button>}
  </Space>
  if (bridge === null) return <Typography.Text>Der Recovery-Stand wird gelesen.</Typography.Text>
  return <RecoveryTestWizard bridge={bridge} />
}
