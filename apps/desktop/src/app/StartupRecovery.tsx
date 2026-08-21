import { invoke } from '@tauri-apps/api/core'
import { Alert, Space, Spin, Typography } from 'antd'
import { useEffect, useState } from 'react'
import type { ReactElement, ReactNode } from 'react'

import { FINALIZATION_PHASE_VALUES } from '../bridge/generated-contracts'
import type { FinalizationPhase, PendingFinalizationResumeView } from '../bridge/generated-contracts'
import { DecorativeIcon } from '../design/icons'

/** Das Kommando, das `WriterService::recover_pending` ausfuehrt. */
export const STARTUP_RECOVERY_COMMAND = 'startup_recovery'

function isPhase(value: unknown): value is FinalizationPhase {
  return typeof value === 'string' && FINALIZATION_PHASE_VALUES.includes(value as FinalizationPhase)
}

/**
 * Prueft die Fortsetzungsansicht, statt ihr zu glauben.
 *
 * Der Brief verlangt ein VALIDIERTES Ansichtsmodell; ohne diese Pruefung waere
 * „unwiderruflich" ein ungeprueftes Wahrheitsbit aus einer Drahtantwort.
 */
export function validateResume(raw: unknown): PendingFinalizationResumeView {
  if (typeof raw !== 'object' || raw === null) {
    throw new Error('Die Wiederaufnahmeantwort ist kein Objekt.')
  }
  const candidate = raw as {
    phase?: unknown
    irreversible?: unknown
    outcomeCode?: unknown
    outcomeSequence?: unknown
  }
  if (!isPhase(candidate.phase)) {
    throw new Error('Die Wiederaufnahmeantwort nennt keine Phase des Kontrakts.')
  }
  if (typeof candidate.irreversible !== 'boolean') {
    throw new Error('Die Wiederaufnahmeantwort nennt die Grenze nicht.')
  }
  const code = candidate.outcomeCode
  if (code !== null && typeof code !== 'string') {
    throw new Error('Die Wiederaufnahmeantwort nennt keinen Ausgang.')
  }
  const sequence = candidate.outcomeSequence
  if (sequence !== null && typeof sequence !== 'number') {
    throw new Error('Die Wiederaufnahmeantwort nennt keine Sequenz.')
  }
  return {
    phase: candidate.phase,
    irreversible: candidate.irreversible,
    outcomeCode: code,
    outcomeSequence: sequence,
  }
}

/** Der automatische Startpfad: eine liegende Abschlussmarke wird aufgeloest. */
export async function startupRecovery(
  bridge: (command: string) => Promise<unknown> = invoke,
): Promise<PendingFinalizationResumeView> {
  return validateResume(await bridge(STARTUP_RECOVERY_COMMAND))
}

type RecoveryState =
  | { readonly kind: 'pending' }
  | { readonly kind: 'settled'; readonly view: PendingFinalizationResumeView }
  | { readonly kind: 'unavailable' }

/**
 * Die Klammer um jede Flaeche, die eine Kette anfassen koennte.
 *
 * Der Inhalt erscheint ERST, wenn `recover` zurueckgekehrt ist: eine liegende
 * Abschlussmarke wird aus den gespeicherten exakten Bytes vollendet oder der
 * Entwurf wiederhergestellt, und bis dahin darf keine Erfassungsflaeche die
 * Sequenz anfassen. Faellt der Aufruf aus, bleibt der Inhalt fort — fail-closed,
 * denn ein unbekannter Kettenzustand ist kein betretbarer.
 *
 * Der VERWEIS auf die Erfassung haengt dagegen an der Rolle und nicht hieran:
 * eine Schale, die ihre Navigation erst nach einem Wirtsaufruf zeigt, waere
 * ohne Wirt stumm.
 */
export function StartupRecovery({
  recover,
  children,
}: {
  readonly recover: () => Promise<PendingFinalizationResumeView>
  readonly children: ReactNode
}): ReactElement {
  const [state, setState] = useState<RecoveryState>({ kind: 'pending' })

  useEffect(() => {
    let live = true
    recover().then(
      (view) => {
        if (live) {
          setState({ kind: 'settled', view })
        }
      },
      () => {
        if (live) {
          setState({ kind: 'unavailable' })
        }
      },
    )
    return () => {
      live = false
    }
  }, [recover])

  if (state.kind === 'pending') {
    return (
      <Space>
        <Spin size="small" />
        <DecorativeIcon name="resuming" />
        <Typography.Text>Wiederaufnahme läuft — der Kettenzustand wird geprüft.</Typography.Text>
      </Space>
    )
  }

  if (state.kind === 'unavailable') {
    return (
      <Alert
        type="error"
        showIcon={false}
        message="Wiederaufnahme nicht abgeschlossen"
        description={
          'Der Kettenzustand dieses Geräts konnte nicht geprüft werden. ' +
          'Die Erfassung bleibt geschlossen, bis die Prüfung gelingt.'
        }
      />
    )
  }

  return (
    <>
      {state.view.outcomeCode !== null && state.view.outcomeSequence !== null ? (
        <Alert
          type="info"
          showIcon={false}
          message="Eine unterbrochene Finalisierung wurde aufgelöst"
          description={
            `Ausgang: ${state.view.outcomeCode}. Sequenz: ${String(state.view.outcomeSequence)}. ` +
            `Phase: ${state.view.phase}. ` +
            (state.view.irreversible
              ? 'Die unwiderrufliche Grenze war überschritten; die Transaktion wurde aus den vorbereiteten Bytes vollendet.'
              : 'Die unwiderrufliche Grenze war nicht überschritten; der Entwurf steht unverändert.')
          }
        />
      ) : null}
      {children}
    </>
  )
}
