import { invoke } from '@tauri-apps/api/core'
import { Alert, Typography } from 'antd'
import { useEffect, useMemo, useState } from 'react'
import type { ReactElement } from 'react'

import { refusalCode } from './AdminPage'
import { ContractViolation } from './contract-check'
import { connectDestructionEvidenceBridge } from './destruction-evidence-bridge'
import { connectReaderDeliveryBridge } from './reader-delivery-bridge'
import { validateDestructionAdministration } from './destruction-contract'
import { DestructionWizard } from './DestructionWizard'
import type { DestructionBridge } from './DestructionWizard'
import type { DestructionAdministrationView } from '../../bridge/generated-contracts'

type NativeCall = (command: string, args?: Record<string, unknown>) => Promise<unknown>
const nativeCall: NativeCall = (command, args) => invoke<unknown>(command, args)

/** A remembered selection is navigation only. Every observation comes from Rust. */
export async function connectDestructionBridge(call: NativeCall = nativeCall): Promise<DestructionBridge> {
  const initial = validateDestructionAdministration(await call('destruction_read', { destructionId: null }))
  let selectedId: string | null = initial.process?.destructionId ?? null
  const checked = async (command: string, args: Record<string, unknown>, expectedId?: string): Promise<DestructionAdministrationView> => {
    const view = validateDestructionAdministration(await call(command, args))
    if ((expectedId !== undefined && view.process?.destructionId !== expectedId)
      || (command !== 'destruction_read' && view.process === null)) {
      throw new ContractViolation('Der native Vernichtungsstand gehört nicht zum angeforderten Vorgang.')
    }
    selectedId = view.process?.destructionId ?? null
    return view
  }
  return {
    initial,
    refresh: () => checked('destruction_read', { destructionId: selectedId }, selectedId ?? undefined),
    select: (destructionId) => checked('destruction_read', { destructionId }, destructionId),
    importAuthorization: (exactAuthorization) => checked('destruction_prepare', { exactAuthorization: Array.from(exactAuthorization) }),
    importProgress: (destructionId, expectedPreflightHash, exactEtbObjects) => checked('destruction_import_progress', {
      destructionId, expectedPreflightHash, exactEtbObjects: exactEtbObjects.map((exact) => Array.from(exact)),
    }, destructionId),
    start: (destructionId, expectedPreflightHash) => checked('destruction_start', { destructionId, expectedPreflightHash }, destructionId),
    resume: (destructionId) => checked('destruction_resume', { destructionId }, destructionId),
    authenticateCustodian: async (destructionId, expectedPreflightHash) => {
      const view = await checked('destruction_authenticate_custodian', { destructionId, expectedPreflightHash }, destructionId)
      if (view.process?.preflight?.jobHash !== expectedPreflightHash) {
        throw new ContractViolation('Die Anmeldung gehört nicht zum angezeigten Vorbericht.')
      }
      return view
    },
    synchronize: async (destructionId, expectedPreflightHash) => {
      const view = await checked('destruction_synchronize', { destructionId, expectedPreflightHash }, destructionId)
      if (view.process?.preflight?.jobHash !== expectedPreflightHash) {
        throw new ContractViolation('Die Servernachweise gehören nicht zum angezeigten Vorbericht.')
      }
      return view
    },
    markIncomplete: async (destructionId, expectedPreflightHash) => {
      const view = await checked('destruction_mark_incomplete', { destructionId, expectedPreflightHash }, destructionId)
      if (view.process?.preflight?.jobHash !== expectedPreflightHash) {
        throw new ContractViolation('Der Abschluss gehört nicht zum angezeigten Vorbericht.')
      }
      return view
    },
  }
}

export function DestructionSurface({ connect = connectDestructionBridge }: {
  readonly connect?: () => Promise<DestructionBridge>
}): ReactElement {
  const [bridge, setBridge] = useState<DestructionBridge | null>(null)
  const evidenceBridge = useMemo(() => connectDestructionEvidenceBridge(), [])
  const readerDeliveryBridge = useMemo(() => connectReaderDeliveryBridge(), [])
  const [refused, setRefused] = useState<string | null>(null)
  useEffect(() => {
    let live = true
    setBridge(null)
    setRefused(null)
    connect().then(
      (next) => { if (live) setBridge(next) },
      (error: unknown) => { if (live) setRefused(refusalCode(error)) },
    )
    return () => { live = false }
  }, [connect])
  if (refused !== null) return <Alert role="alert" type="error" title="Vernichtungsverwaltung nicht geöffnet" description={refused} />
  if (bridge === null) return <Typography.Text>Der Vernichtungsstand wird gelesen.</Typography.Text>
  return <DestructionWizard bridge={bridge} evidenceBridge={evidenceBridge} readerDeliveryBridge={readerDeliveryBridge} />
}
