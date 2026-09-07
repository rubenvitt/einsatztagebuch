import { invoke } from '@tauri-apps/api/core'
import { Alert, Space, Typography } from 'antd'
import { useEffect, useState } from 'react'
import type { ReactElement, ReactNode } from 'react'

import {
  DEVICE_APPROVE_KIND,
  DEVICE_REVOKE_KIND,
  POLICY_CHANGE_KIND,
  WRITER_TRANSITION_KIND,
} from './ceremony'
import { ClockReleaseWizard } from './ClockReleaseWizard'
import {
  isContractViolation,
  validateCeremony,
  validateChecklist,
  validateClockReleaseOffer,
  validateClockReleaseOutcome,
  validatePendingRequests,
  validatePolicyProfile,
  validateRegistryHealth,
  validateRevocationEffect,
  validateWriterTransition,
} from './contract-check'
import { DevicePosture } from './DevicePosture'
import { DeviceRequests } from './DeviceRequests'
import { FingerprintApproval, REAUTH_REQUIRED_TEXT } from './FingerprintApproval'
import { GoLiveChecklist } from './GoLiveChecklist'
import { POLICY_REQUEST_ID, PolicyEditor } from './PolicyEditor'
import { RegistryHealth } from './RegistryHealth'
import { RevocationConfirm } from './RevocationConfirm'
import { WriterTransitionWizard } from './WriterTransitionWizard'
import type {
  ClockReleaseJustificationV1,
  ClockReleaseOfferView,
  ClockReleaseOutcomeView,
  DevicePostureSummaryView,
  GoLiveChecklistView,
  PendingDeviceRequestView,
  PolicyProfileView,
  ReauthResultView,
  RegistryHealthView,
  RevocationEffectView,
  TrustCeremonyKind,
  TrustCeremonyView,
  WriterTransitionView,
} from '../../bridge/generated-contracts'
import { WRITER_COMMANDS } from '../writer/WriterPage'

/**
 * Die Kommandonamen dieser Flaeche, in der Reihenfolge ihrer Registrierung
 * (`admin-ui-contract.md` §5). `src-tauri/tests/admin_commands.rs` liest diese
 * Datei per `include_str!` und vergleicht die Literale — deshalb stehen sie
 * hier ausgeschrieben und nirgends ein zweites Mal.
 */
export const ADMIN_COMMANDS = {
  pendingDeviceRequests: 'admin_pending_device_requests',
  ceremonyBegin: 'admin_ceremony_begin',
  ceremonyConfirmFingerprint: 'admin_ceremony_confirm_fingerprint',
  ceremonyAuthorize: 'admin_ceremony_authorize',
  ceremonyExportRequest: 'admin_ceremony_export_request',
  ceremonyImportReply: 'admin_ceremony_import_reply',
  ceremonyPublish: 'admin_ceremony_publish',
  policyProfile: 'admin_policy_profile',
  registryHealth: 'admin_registry_health',
  goLiveChecklist: 'admin_go_live_checklist',
  goLiveExportUnresolved: 'admin_go_live_export_unresolved',
  clockReleaseOffer: 'admin_clock_release_offer',
  clockReleaseIssue: 'admin_clock_release_issue',
  writerTransitionState: 'admin_writer_transition_state',
  writerTransitionPrepare: 'admin_writer_transition_prepare',
  writerTransitionActivate: 'admin_writer_transition_activate',
  revocationEffect: 'admin_revocation_effect',
} as const

/**
 * Die zwei Zwecke, fuer die diese Flaeche eine Wiederanmeldung verlangt — in
 * der Drahtform `ReauthPurpose::label()` (`crates/ea-operator/src/session.rs`),
 * die `session_reauthenticate_core` zurueckuebersetzt: dasselbe Wort, das in
 * die signierte Challenge eingeht; jedes andere ist
 * `EA-DESKTOP-REAUTH-PURPOSE-UNKNOWN`. Ein Nachweis fuer die Root-Zeremonie
 * ist keiner fuer die Zeitfreigabe.
 */
export const REAUTH_PURPOSES = {
  adminRootCeremony: 'admin-root-ceremony',
  clockSkewRelease: 'clock-skew-release',
} as const

/**
 * Alles, was diese Flaeche vom Wirt braucht — und nichts darueber hinaus.
 *
 * Die sieben WERTE sind beim ersten Rendervorgang bekannt (Muster
 * `WriterBridge`): eine Verwaltungsflaeche, die ihre Go-live-Liste erst nach
 * einem Mikrotask kennt, haette einen Moment ohne Aussage ueber die
 * Produktionsbereitschaft. Alles andere ist eine HANDLUNG und asynchron. Was
 * es hier nicht gibt: ein Kommando, das einen Eintrag, einen Verlauf oder
 * einen Klartext oeffnet.
 */
export type AdminBridge = {
  readonly pendingRequests: readonly PendingDeviceRequestView[]
  readonly checklist: GoLiveChecklistView
  readonly registryHealth: RegistryHealthView
  readonly policy: PolicyProfileView
  readonly writerTransition: WriterTransitionView
  readonly clockReleaseOffer: ClockReleaseOfferView
  readonly devicePosture: DevicePostureSummaryView | null
  readonly reauthenticate: (purposeCode: string) => Promise<ReauthResultView>
  readonly beginCeremony: (requestId: string, kind: TrustCeremonyKind) => Promise<TrustCeremonyView>
  readonly confirmFingerprint: (
    ceremonyId: string,
    reportedFingerprint: string,
  ) => Promise<TrustCeremonyView>
  readonly authorize: (ceremonyId: string) => Promise<TrustCeremonyView>
  readonly exportRequest: (ceremonyId: string) => Promise<TrustCeremonyView>
  readonly importReply: (ceremonyId: string) => Promise<TrustCeremonyView>
  readonly publish: (ceremonyId: string) => Promise<TrustCeremonyView>
  readonly exportUnresolved: () => Promise<string>
  readonly issueClockRelease: (
    justification: ClockReleaseJustificationV1,
  ) => Promise<ClockReleaseOutcomeView>
  readonly prepareWriterTransition: (requestJson: string) => Promise<WriterTransitionView>
  readonly activateWriterTransition: () => Promise<WriterTransitionView>
  readonly revocationEffect: (targetHash: string) => Promise<RevocationEffectView>
}

/**
 * Der Satz fuer eine Antwort, die `contract-check.ts` abgelehnt hat.
 *
 * Kein Wirtscode — der Wirt hat keinen genannt, und die Schale erfindet
 * keinen. Aber auch nicht „keinen Fehlercode genannt": der Wirt hat
 * geantwortet, nur ausserhalb des Kontrakts, und das ist die Aussage.
 */
export const CONTRACT_VIOLATION_TEXT = 'Antwort außerhalb des Kontrakts'

/**
 * Der CODE einer Ablehnung des Wirts — und nur der.
 *
 * `CommandError` ist `{ code }`; ein Fehler ohne Code ist kein Fehler des
 * Wirts, und die Flaeche erfindet dann keinen. Sie sagt, dass der Code fehlt —
 * oder, wenn die Schale selbst an der Kontraktgrenze abgelehnt hat, genau das.
 */
export function refusalCode(error: unknown): string {
  if (isContractViolation(error)) {
    return CONTRACT_VIOLATION_TEXT
  }
  if (typeof error === 'object' && error !== null && 'code' in error) {
    const { code } = error as { code: unknown }
    if (typeof code === 'string' && code.length > 0) {
      return code
    }
  }
  return 'Der Wirt hat keinen Fehlercode genannt.'
}

/** Ein benannter Unterbereich der Verwaltung — Landmarke plus Ueberschrift. */
function Region({ title, children }: { readonly title: string; readonly children: ReactNode }): ReactElement {
  return (
    <section aria-label={title}>
      <Space direction="vertical" size="small">
        <Typography.Title level={3}>{title}</Typography.Title>
        {children}
      </Space>
    </section>
  )
}

/**
 * Die Verwaltungsflaeche.
 *
 * Acht Unterbereiche in fester Reihenfolge; die Root-Zeremonie oeffnet sich
 * unter dem Bereich, der sie begonnen hat (Geraeteanfrage, Richtlinie oder
 * Widerruf), und es laeuft hoechstens eine zugleich. Jede Root-Handlung
 * authentisiert ERST und jedes Mal neu; ist der Nachweis nicht frisch, geschieht
 * nichts, und das steht im Wortlaut da.
 *
 * KEINE eigene Landmarke: die Schale klammert diese Flaeche schon mit `region`
 * „Verwaltung" (`AppShell.tsx`), und eine zweite Landmarke desselben Namens
 * machte jede Abfrage nach ihr mehrdeutig — dieselbe Entscheidung wie in
 * `WriterPage`.
 */
export function AdminPage({ bridge }: { readonly bridge: AdminBridge }): ReactElement {
  const [ceremony, setCeremony] = useState<TrustCeremonyView | null>(null)
  const [ceremonyNotice, setCeremonyNotice] = useState<string | null>(null)
  const [ceremonyError, setCeremonyError] = useState<string | null>(null)
  const [clockOutcome, setClockOutcome] = useState<ClockReleaseOutcomeView | null>(null)
  const [clockNotice, setClockNotice] = useState<string | null>(null)
  const [transition, setTransition] = useState<WriterTransitionView>(bridge.writerTransition)
  const [transitionNotice, setTransitionNotice] = useState<string | null>(null)
  const [effect, setEffect] = useState<RevocationEffectView | null>(null)
  const [revocationNotice, setRevocationNotice] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  /** Eine Handlung des Wirts, deren Ablehnung als Code an `onRefused` geht. */
  const run = <T,>(
    act: () => Promise<T>,
    onDone: (value: T) => void,
    onRefused: (code: string) => void,
  ): void => {
    setBusy(true)
    act()
      .then(onDone, (error: unknown) => {
        onRefused(refusalCode(error))
      })
      .then(() => {
        setBusy(false)
      })
  }

  /**
   * Jede Root-Handlung authentisiert ERST — und jedes Mal neu.
   *
   * Ohne frischen Nachweis wird die Handlung NICHT gerufen; der Wirt lehnte sie
   * mit `EA-DESKTOP-REAUTH-REQUIRED` ohnehin ab, und ein Aufruf, dessen Antwort
   * feststeht, ist ein Aufruf zu viel.
   */
  const withFreshProof = <T,>(
    purpose: string,
    act: () => Promise<T>,
    onDone: (value: T) => void,
    onStale: () => void,
    onRefused: (code: string) => void,
  ): void => {
    run(
      () =>
        bridge.reauthenticate(purpose).then((proof) => (proof.fresh ? act() : Promise.resolve(null))),
      (value) => {
        if (value === null) {
          onStale()
        } else {
          onDone(value)
        }
      },
      onRefused,
    )
  }

  const ceremonyStep = (act: () => Promise<TrustCeremonyView>): void => {
    setCeremonyNotice(null)
    setCeremonyError(null)
    run(act, setCeremony, setCeremonyError)
  }

  const ceremonyRootStep = (act: () => Promise<TrustCeremonyView>): void => {
    setCeremonyNotice(null)
    setCeremonyError(null)
    withFreshProof(
      REAUTH_PURPOSES.adminRootCeremony,
      act,
      setCeremony,
      () => {
        setCeremonyNotice(REAUTH_REQUIRED_TEXT)
      },
      setCeremonyError,
    )
  }

  const begin = (requestId: string, kind: TrustCeremonyKind): void => {
    setCeremony(null)
    ceremonyStep(() => bridge.beginCeremony(requestId, kind))
  }

  const stepper = (kind: TrustCeremonyKind): ReactElement | null =>
    ceremony === null || ceremony.kind !== kind ? null : (
      <FingerprintApproval
        ceremony={ceremony}
        notice={ceremonyNotice}
        error={ceremonyError}
        busy={busy}
        onConfirmFingerprint={(reported) => {
          ceremonyStep(() => bridge.confirmFingerprint(ceremony.ceremonyId, reported))
        }}
        onAuthorize={() => {
          ceremonyRootStep(() => bridge.authorize(ceremony.ceremonyId))
        }}
        onExportRequest={() => {
          ceremonyStep(() => bridge.exportRequest(ceremony.ceremonyId))
        }}
        onImportReply={() => {
          ceremonyStep(() => bridge.importReply(ceremony.ceremonyId))
        }}
        onPublish={() => {
          ceremonyRootStep(() => bridge.publish(ceremony.ceremonyId))
        }}
      />
    )

  return (
    <Space direction="vertical" size="large">
      <Region title="Go-live-Status">
        <GoLiveChecklist checklist={bridge.checklist} onExportUnresolved={bridge.exportUnresolved} />
      </Region>

      <Region title="Geräteanfragen">
        <DeviceRequests
          requests={bridge.pendingRequests}
          busy={busy}
          onBegin={(requestId) => {
            begin(requestId, DEVICE_APPROVE_KIND)
          }}
        />
        {stepper(DEVICE_APPROVE_KIND)}
      </Region>

      <Region title="Registry">
        <RegistryHealth health={bridge.registryHealth} />
      </Region>

      <Region title="Richtlinie">
        <PolicyEditor
          policy={bridge.policy}
          busy={busy}
          onBegin={() => {
            begin(POLICY_REQUEST_ID, POLICY_CHANGE_KIND)
          }}
        />
        {stepper(POLICY_CHANGE_KIND)}
      </Region>

      <Region title="Writer-Wechsel">
        <WriterTransitionWizard
          state={transition}
          notice={transitionNotice}
          busy={busy}
          onPrepare={(requestJson) => {
            setTransitionNotice(null)
            run(() => bridge.prepareWriterTransition(requestJson), setTransition, setTransitionNotice)
          }}
          onActivate={() => {
            setTransitionNotice(null)
            withFreshProof(
              REAUTH_PURPOSES.adminRootCeremony,
              () => bridge.activateWriterTransition(),
              setTransition,
              () => {
                setTransitionNotice(REAUTH_REQUIRED_TEXT)
              },
              setTransitionNotice,
            )
          }}
          onBeginCeremony={(targetHash) => {
            begin(targetHash, WRITER_TRANSITION_KIND)
          }}
        />
        {stepper(WRITER_TRANSITION_KIND)}
      </Region>

      <Region title="Zeitfreigabe">
        <ClockReleaseWizard
          offer={bridge.clockReleaseOffer}
          outcome={clockOutcome}
          notice={clockNotice}
          busy={busy}
          onIssue={(justification) => {
            setClockNotice(null)
            withFreshProof(
              REAUTH_PURPOSES.clockSkewRelease,
              () => bridge.issueClockRelease(justification),
              setClockOutcome,
              () => {
                setClockNotice(REAUTH_REQUIRED_TEXT)
              },
              setClockNotice,
            )
          }}
        />
      </Region>

      <DevicePosture posture={bridge.devicePosture} />

      <Region title="Widerruf">
        <RevocationConfirm
          effect={effect}
          notice={revocationNotice}
          busy={busy}
          onCheck={(targetHash) => {
            setRevocationNotice(null)
            setEffect(null)
            run(() => bridge.revocationEffect(targetHash), setEffect, setRevocationNotice)
          }}
          onBegin={(targetHash) => {
            begin(targetHash, DEVICE_REVOKE_KIND)
          }}
        />
        {stepper(DEVICE_REVOKE_KIND)}
      </Region>
    </Space>
  )
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  return invoke<T>(command, args)
}

/**
 * Die Bruecke ueber die Kommandos des Wirts.
 *
 * Sie wird EINMAL gebaut, nachdem die sieben Werte gelesen sind. Jede Antwort
 * mit einer Position einer geschlossenen Aufzaehlung laeuft durch
 * `contract-check.ts`, statt geglaubt zu werden. Die Geraetehaltung ist die
 * einzige Antwort, deren Ausfall die Flaeche nicht schliesst: ohne Meldung
 * zeigt die Tafel „noch nicht gemeldet" — die wahre Aussage —, waehrend eine
 * fehlende Go-live-Liste oder ein fehlender Registry-Zustand die Verwaltung
 * GESCHLOSSEN laesst.
 */
export async function connectAdminBridge(): Promise<AdminBridge> {
  const [pendingRequests, checklist, registryHealth, policy, writerTransition, clockReleaseOffer, devicePosture] =
    await Promise.all([
      call<unknown>(ADMIN_COMMANDS.pendingDeviceRequests).then(validatePendingRequests),
      call<unknown>(ADMIN_COMMANDS.goLiveChecklist).then(validateChecklist),
      call<unknown>(ADMIN_COMMANDS.registryHealth).then(validateRegistryHealth),
      call<unknown>(ADMIN_COMMANDS.policyProfile).then(validatePolicyProfile),
      call<unknown>(ADMIN_COMMANDS.writerTransitionState).then(validateWriterTransition),
      call<unknown>(ADMIN_COMMANDS.clockReleaseOffer).then(validateClockReleaseOffer),
      call<DevicePostureSummaryView>(WRITER_COMMANDS.devicePosture).catch(() => null),
    ])
  const ceremonyCall = (command: string, args: Record<string, unknown>) =>
    call<unknown>(command, args).then(validateCeremony)
  return {
    pendingRequests,
    checklist,
    registryHealth,
    policy,
    writerTransition,
    clockReleaseOffer,
    devicePosture,
    reauthenticate: (purpose) => call(WRITER_COMMANDS.reauthenticate, { purpose }),
    beginCeremony: (requestId, kind) => ceremonyCall(ADMIN_COMMANDS.ceremonyBegin, { requestId, kind }),
    confirmFingerprint: (ceremonyId, reportedFingerprint) =>
      ceremonyCall(ADMIN_COMMANDS.ceremonyConfirmFingerprint, { ceremonyId, reportedFingerprint }),
    authorize: (ceremonyId) => ceremonyCall(ADMIN_COMMANDS.ceremonyAuthorize, { ceremonyId }),
    exportRequest: (ceremonyId) => ceremonyCall(ADMIN_COMMANDS.ceremonyExportRequest, { ceremonyId }),
    importReply: (ceremonyId) => ceremonyCall(ADMIN_COMMANDS.ceremonyImportReply, { ceremonyId }),
    publish: (ceremonyId) => ceremonyCall(ADMIN_COMMANDS.ceremonyPublish, { ceremonyId }),
    exportUnresolved: () => call(ADMIN_COMMANDS.goLiveExportUnresolved),
    issueClockRelease: (justification) =>
      call<unknown>(ADMIN_COMMANDS.clockReleaseIssue, { justification }).then(
        validateClockReleaseOutcome,
      ),
    prepareWriterTransition: (requestJson) =>
      call<unknown>(ADMIN_COMMANDS.writerTransitionPrepare, { requestJson }).then(
        validateWriterTransition,
      ),
    activateWriterTransition: () =>
      call<unknown>(ADMIN_COMMANDS.writerTransitionActivate).then(validateWriterTransition),
    revocationEffect: (targetHash) =>
      call<unknown>(ADMIN_COMMANDS.revocationEffect, { targetHash }).then(validateRevocationEffect),
  }
}

/**
 * Die Klammer, die die Bruecke aufbaut und erst danach die Flaeche zeigt.
 *
 * Faellt der Aufbau aus, bleibt die Verwaltung GESCHLOSSEN — mit dem Code des
 * Wirts (`EA-DESKTOP-ADMINISTRATION-FORBIDDEN`,
 * `EA-DESKTOP-ADMINISTRATION-UNAVAILABLE`, …) und nie mit einem Vorgabewert.
 */
export function AdminSurface({
  connect = connectAdminBridge,
}: {
  readonly connect?: () => Promise<AdminBridge>
}): ReactElement {
  const [bridge, setBridge] = useState<AdminBridge | null>(null)
  const [refused, setRefused] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    connect().then(
      (built) => {
        if (live) {
          setBridge(built)
        }
      },
      (error: unknown) => {
        if (live) {
          setRefused(refusalCode(error))
        }
      },
    )
    return () => {
      live = false
    }
  }, [connect])

  if (refused !== null) {
    return (
      <Alert
        type="error"
        showIcon={false}
        closable={false}
        message="Die Verwaltung ist nicht geöffnet"
        description={`Grund: ${refused}. Es wird keine Fläche gezeigt.`}
      />
    )
  }
  if (bridge === null) {
    return <Typography.Text>Der Verwaltungsstand wird gelesen.</Typography.Text>
  }
  return <AdminPage bridge={bridge} />
}
