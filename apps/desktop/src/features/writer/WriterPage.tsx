import { invoke } from '@tauri-apps/api/core'
import { Alert, Button, Space, Typography } from 'antd'
import { useEffect, useState } from 'react'
import type { ReactElement } from 'react'

import { ArchiveBundleExport } from './ArchiveBundleExport'
import { DiscardDraftAction } from './DiscardDraftAction'
import { FinalizeStep } from './FinalizeStep'
import { IncidentForm, blankIncident } from './IncidentForm'
import { PendingFinalizationResume } from './PendingFinalizationResume'
import { ReviewStep } from './ReviewStep'
import { validateResume } from '../../app/StartupRecovery'
import {
  DETAIL_CAUSE_VALUES,
  PATIENT_COUNT_STATUS_VALUES,
  SYNC_STATUS_VALUES,
} from '../../bridge/generated-contracts'
import type {
  ArchiveHealthSummaryView,
  BundleExportView,
  DiscardStateView,
  DetailCause,
  DevicePostureSummaryView,
  DraftStateView,
  FinalizationPreviewView,
  FinalizeOutcomeView,
  IncidentInputView,
  MasterDataResultView,
  PendingResumeOutcomeView,
  ReauthResultView,
  StaleAcknowledgementView,
  SyncStateView,
  SyncStatus as SyncStatusValue,
} from '../../bridge/generated-contracts'
import { FingerprintBlock } from '../../components/integrity/FingerprintBlock'
import { SyncStatus } from '../../components/integrity/SyncStatus'

/**
 * Der Zustand „bekannt", AUS der emittierten Vereinigung.
 *
 * Am Draht ist `patientCountStatus = 0` gleich `unknown` und `= 1` gleich
 * `known`; die Zerlegung traegt deshalb die Polaritaet und nicht ein Literal
 * dieser Datei.
 */
const [, KNOWN_STATUS] = PATIENT_COUNT_STATUS_VALUES

/** Der Zweck einer erneuten Authentisierung — je Handlung ein eigener. */
export const FINALIZE_PURPOSE = 'finalize'
export const DISCARD_PURPOSE = 'discard'
export const STALE_ACK_PURPOSE = 'stale-ack'

/** Die Kommandonamen dieser Flaeche, in der Reihenfolge ihrer Registrierung. */
export const WRITER_COMMANDS = {
  reauthenticate: 'session_reauthenticate',
  recoverPending: 'writer_recover_pending',
  masterDataSearch: 'master_data_search',
  draftLoadActive: 'draft_load_active',
  draftSave: 'draft_save',
  discardBegin: 'draft_discard_begin',
  discardResume: 'draft_discard_resume',
  preview: 'writer_preview',
  acknowledgeStaleRegistry: 'writer_acknowledge_stale_registry',
  finalize: 'writer_finalize',
  archiveHealth: 'archive_health_report',
  devicePosture: 'device_posture_report',
  exportBundle: 'archive_export_bundle_file',
} as const

/**
 * Alles, was diese Flaeche vom Wirt braucht — und nichts darueber hinaus.
 *
 * Zwei Felder sind WERTE und keine Aufrufe: der aktive Entwurf und die
 * angetroffene Finalisierung. Das ist eine Entscheidung und kein Versehen. Der
 * Startpfad ist gelaufen, BEVOR diese Flaeche entsteht (die Schale rendert
 * keinen Routeninhalt vor der Wiederaufnahme), also ist der Zustand zum
 * Zeitpunkt des ersten Rendervorgangs bekannt — und eine Flaeche, die ihn erst
 * nach einem Mikrotask kennt, haette einen Moment, in dem sie eine
 * Erfassungsmaske ueber einer liegenden Abschlussmarke zeigt.
 *
 * Alles andere ist eine HANDLUNG und damit asynchron.
 */
export type WriterBridge = {
  readonly draft: DraftStateView
  readonly pendingResume: PendingResumeOutcomeView | null
  readonly saveDraft: (input: IncidentInputView) => Promise<SyncStateView>
  readonly searchMasterData: (query: string) => Promise<MasterDataResultView>
  readonly preview: (input: IncidentInputView) => Promise<FinalizationPreviewView>
  readonly acknowledgeStaleRegistry: () => Promise<StaleAcknowledgementView>
  readonly finalize: (
    input: IncidentInputView,
    confirmed: FinalizationPreviewView,
  ) => Promise<FinalizeOutcomeView>
  readonly archiveHealth: () => Promise<ArchiveHealthSummaryView>
  readonly devicePosture: () => Promise<DevicePostureSummaryView>
  readonly reauthenticate: (purpose: string) => Promise<ReauthResultView>
  readonly discardDraft: () => Promise<DiscardStateView>
  readonly resumeDiscard: () => Promise<DiscardStateView>
  readonly exportBundle: () => Promise<BundleExportView>
}

/**
 * Der Eingabevertrag, lokal geprueft — und ausdruecklich NICHT die Autoritaet.
 *
 * Die zwei Begruendungsfelder folgen der biconditionalen Stufe-1-Regel
 * (`EA-SCHEMA-LIST-REASON`): sichtbar und Pflicht, solange die zugehoerige
 * Liste leer ist, und sonst niemals gesetzt. Die Durchsetzung liegt in
 * `ea-schema`; diese Pruefung erspart dem Wirt einen sinnlosen Aufruf und dem
 * Bediener eine Ablehnung, die er erst nach dem Netzweg saehe.
 */
export function firstInputViolation(incident: IncidentInputView): string | null {
  if (incident.humanIncidentNumber.trim() === '') {
    return 'Die Einsatznummer fehlt.'
  }
  if (incident.occurredAt.start === 0) {
    return 'Der Beginn des Einsatzes fehlt.'
  }
  if (incident.keyword.displayText.trim() === '') {
    return 'Das Stichwort fehlt.'
  }
  if (
    incident.location.address === null &&
    (incident.location.freeText ?? '').trim() === ''
  ) {
    return 'Der Einsatzort fehlt.'
  }
  if (incident.personnel.length === 0 && (incident.personnelEmptyReason ?? '') === '') {
    return 'Die Personalliste ist leer. Dann ist eine Begründung Pflicht.'
  }
  if (incident.vehicles.length === 0 && (incident.vehiclesEmptyReason ?? '') === '') {
    return 'Die Fahrzeugliste ist leer. Dann ist eine Begründung Pflicht.'
  }
  // Der Draht traegt ZWEI Positionen, und nur zwei Paarungen sind eine Eingabe:
  // `known` MIT Zahl und `unknown` OHNE. Ohne diese Pruefung waere ein geleertes
  // Feld bei `bekannt` eine Anzeige „Patientenzahl unbekannt" ueber einem Draht,
  // der `known, 0` traegt — die Grenze lehnt das ab (`INCIDENT_INPUT_REJECTED`),
  // und diese Zeile sagt dem Bediener, WAS fehlt.
  if (incident.patientCountStatus === KNOWN_STATUS && incident.patientCount === null) {
    return 'Die Patientenzahl ist als bekannt gewählt. Dann ist eine Anzahl Pflicht.'
  }
  if (incident.patientCountStatus !== KNOWN_STATUS && incident.patientCount !== null) {
    return 'Ohne bekannte Patientenzahl wird keine Zahl gesendet.'
  }
  return null
}

/**
 * Prueft den Sync-Zustand einer Wirtsantwort, statt ihm zu glauben.
 *
 * Beide Positionen kommen aus der emittierten Vereinigung; eine Zeichenkette,
 * die dort nicht steht, ist KEIN Zustand. Ohne diese Pruefung waere der
 * angezeigte Wortlaut ein beliebiger Text aus einer Antwort — und die vier
 * Zustandsnamen sind woertliche Oberflaechenkopie einer globalen Randbedingung.
 */
function validateSyncState(raw: unknown): SyncStateView {
  if (typeof raw !== 'object' || raw === null) {
    throw new Error('Der Sync-Zustand ist kein Objekt.')
  }
  const candidate = raw as { status?: unknown; detailCause?: unknown }
  const status = SYNC_STATUS_VALUES.find((value) => value === candidate.status)
  if (status === undefined) {
    throw new Error('Der Sync-Zustand nennt keinen Zustand des Kontrakts.')
  }
  if (candidate.detailCause === null) {
    return { status: status as SyncStatusValue, detailCause: null }
  }
  const cause = DETAIL_CAUSE_VALUES.find((value) => value === candidate.detailCause)
  if (cause === undefined) {
    throw new Error('Der Sync-Zustand nennt keine Detailursache des Kontrakts.')
  }
  return { status: status as SyncStatusValue, detailCause: cause as DetailCause }
}

/**
 * Prueft die angetroffene Finalisierung, statt ihr zu glauben.
 *
 * Diese Antwort ist die STRENGSTE des ganzen Tasks: aus `resume.irreversible`
 * und `blockedCode` entsteht die Entscheidung, ob es die Abschlusshandhabe
 * ueberhaupt GIBT. Ein ungeprueftes Wahrheitsbit an dieser Stelle heisst, dass
 * eine fehlerhafte oder fremde Antwort die unwiderrufliche Grenze verschieben
 * koennte.
 *
 * Die flache Fortsetzungsansicht prueft [`validateResume`] aus Task 15 — dieselbe
 * Pruefung und keine zweite Fassung.
 */
export function validatePendingResume(raw: unknown): PendingResumeOutcomeView {
  if (typeof raw !== 'object' || raw === null) {
    throw new Error('Die Antwort des Startpfads ist kein Objekt.')
  }
  const candidate = raw as { resume?: unknown; blockedCode?: unknown; sync?: unknown }
  const resume = validateResume(candidate.resume)
  const blocked = candidate.blockedCode
  if (blocked !== null && typeof blocked !== 'string') {
    throw new Error('Die Antwort des Startpfads nennt keinen Blockadecode.')
  }
  return {
    resume,
    blockedCode: blocked,
    sync: candidate.sync === null || candidate.sync === undefined
      ? null
      : validateSyncState(candidate.sync),
  }
}

type Stage =
  | { readonly kind: 'form' }
  | { readonly kind: 'review' }
  | { readonly kind: 'closed'; readonly outcome: FinalizeOutcomeView }

/**
 * Die Erfassungsflaeche des Writers.
 *
 * Der Weg ist Erfassung, Pruefung, unwiderruflicher Abschluss — und danach ein
 * LEERES Formular. Was es hier nicht gibt: einen Verlauf, einen „letzten
 * Einsatz", ein Entschluesseln, ein Loeschen eines abgeschlossenen Eintrags und
 * eine inhaltsfuehrende Ansicht der Publikationsschlange.
 */
export function WriterPage({ bridge }: { readonly bridge: WriterBridge }): ReactElement {
  const [incident, setIncident] = useState<IncidentInputView>(bridge.draft.incident)
  const [sync, setSync] = useState<SyncStateView>(bridge.draft.sync)
  const [stage, setStage] = useState<Stage>({ kind: 'form' })
  const [violation, setViolation] = useState<string | null>(null)
  const [preview, setPreview] = useState<FinalizationPreviewView | null>(null)
  const [previewRefused, setPreviewRefused] = useState(false)
  const [acknowledgement, setAcknowledgement] = useState<StaleAcknowledgementView | null>(null)
  const [acknowledgementRefused, setAcknowledgementRefused] = useState(false)
  const [health, setHealth] = useState<ArchiveHealthSummaryView | null>(null)
  const [posture, setPosture] = useState<DevicePostureSummaryView | null>(null)
  const [discardState, setDiscardState] = useState<DiscardStateView | null>(null)
  const [busy, setBusy] = useState(false)

  const reviewing = stage.kind === 'review'
  useEffect(() => {
    if (!reviewing) {
      return
    }
    void bridge.archiveHealth().then(setHealth, () => {
      setHealth(null)
    })
    void bridge.devicePosture().then(setPosture, () => {
      setPosture(null)
    })
  }, [bridge, reviewing])

  // Eine angetroffene Finalisierung schliesst JEDE andere Flaeche aus. Sie
  // steht vor der Zustandsmaschine, damit keine Erfassungsmaske ueber einer
  // liegenden Abschlussmarke entstehen kann.
  if (bridge.pendingResume !== null) {
    return <PendingFinalizationResume outcome={bridge.pendingResume} />
  }

  /**
   * Die Pruefung: Bestaetigungsflaeche zeigen, und den Wirt nur mit einem
   * ERFUELLTEN Eingabevertrag fragen.
   *
   * Beide Haelften sind Absicht. Die Flaeche erscheint auch bei einer
   * Verletzung, weil der Bediener dort sieht, was fehlt UND dass der Abschluss
   * bis dahin nicht ausfuehrbar ist; ein verstecktes Ergebnis waere eine
   * Fehlermeldung ohne Ort. Der Wirt wird bei einer Verletzung NICHT gefragt:
   * er lehnte mit demselben Code ab, und ein Aufruf, dessen Antwort schon
   * feststeht, ist ein Aufruf zu viel.
   */
  const check = (): void => {
    const found = firstInputViolation(incident)
    setViolation(found)
    setPreview(null)
    setPreviewRefused(false)
    setAcknowledgement(null)
    setAcknowledgementRefused(false)
    setStage({ kind: 'review' })
    if (found !== null) {
      return
    }
    void bridge.preview(incident).then(
      (result) => {
        setPreview(result)
      },
      () => {
        setPreviewRefused(true)
      },
    )
  }

  /**
   * Jede Aenderung am Rumpf entwertet die Pruefung.
   *
   * Sonst koennte eine bestaetigte Vorschau eine Bearbeitung ueberleben, und
   * der Bediener bestaetigte etwas anderes als das, was abgeschlossen wird. Der
   * Kern faengt das zwar auch (er rechnet die Vorschau unter der Sperre nach und
   * lehnt eine abweichende ab), aber eine Oberflaeche, die sich darauf
   * verlaesst, zeigt bis dahin eine Luege.
   */
  const edit = (next: IncidentInputView): void => {
    setIncident(next)
    setPreview(null)
    setAcknowledgement(null)
    if (stage.kind === 'review') {
      setStage({ kind: 'form' })
    }
  }

  /** Jede unwiderrufliche Handlung authentisiert ERST — und jedes Mal neu. */
  const withFreshProof = (purpose: string, act: () => Promise<void>): void => {
    setBusy(true)
    void bridge
      .reauthenticate(purpose)
      .then((result) => (result.fresh ? act() : Promise.resolve()))
      .catch(() => undefined)
      .then(() => {
        setBusy(false)
      })
  }

  const finalize = (): void => {
    if (preview === null) {
      return
    }
    const confirmed = preview
    withFreshProof(FINALIZE_PURPOSE, () =>
      bridge.finalize(incident, confirmed).then((outcome) => {
        // Nach dem Commit bleibt der Oberflaeche NICHTS als Hash und Sequenz.
        setStage({ kind: 'closed', outcome })
        setIncident(blankIncident())
        setSync(outcome.sync)
        setPreview(null)
        setAcknowledgement(null)
      }),
    )
  }

  const discard = (): void => {
    withFreshProof(DISCARD_PURPOSE, () =>
      bridge.discardDraft().then((state) => {
        setDiscardState(state)
        if (state.complete) {
          setIncident(blankIncident())
        }
      }),
    )
  }

  const acknowledge = (): void => {
    setAcknowledgementRefused(false)
    withFreshProof(STALE_ACK_PURPOSE, () =>
      bridge.acknowledgeStaleRegistry().then(
        (result) => {
          setAcknowledgement(result)
          if (!result.captured) {
            setAcknowledgementRefused(true)
          }
        },
        () => {
          setAcknowledgementRefused(true)
        },
      ),
    )
  }

  // KEINE eigene Landmarke: die Schale klammert diese Flaeche schon mit
  // `region` „Erfassung", und eine zweite Landmarke mit einem Namen derselben
  // Wortfamilie machte jede Abfrage nach ihr mehrdeutig. Die Unterbereiche
  // tragen ihre eigenen, unterscheidbaren Namen.
  return (
    <div>
      <Space direction="vertical" size="middle">
        {stage.kind === 'closed' ? (
          <section aria-label="Abschluss">
            <Space direction="vertical" size="small">
              <Typography.Text strong>Der Eintrag ist lokal abgeschlossen</Typography.Text>
              <FingerprintBlock
                entries={[
                  { label: 'Eintragshash', value: stage.outcome.entryHash },
                  { label: 'Objekthash', value: stage.outcome.objectHash },
                  { label: 'Sequenz', value: String(stage.outcome.sequence) },
                ]}
              />
              <SyncStatus state={stage.outcome.sync} label="Veröffentlichung" />
              <Typography.Text>
                Der Inhalt dieses Eintrags ist von hier aus nicht mehr erreichbar. Korrekturen
                sind ausschließlich spätere, eigene Nachträge.
              </Typography.Text>
            </Space>
          </section>
        ) : null}

        <Space direction="vertical" size="middle">
          <SyncStatus state={sync} label="Speicherzustand" />
          <IncidentForm
            incident={incident}
            onChange={edit}
            onSearch={bridge.searchMasterData}
          />
          <Space size="middle">
            <Button type="primary" onClick={check}>
              Prüfen
            </Button>
            <Button
              onClick={() => {
                void bridge.saveDraft(incident).then(setSync, () => undefined)
              }}
            >
              Entwurf speichern
            </Button>
          </Space>
          <DiscardDraftAction
            busy={busy}
            state={discardState}
            onDiscard={discard}
            onResume={() => {
              void bridge.resumeDiscard().then(setDiscardState, () => undefined)
            }}
          />
          <ArchiveBundleExport busy={busy} onExport={bridge.exportBundle} />
        </Space>

        {stage.kind === 'review' ? (
          <Space direction="vertical" size="middle">
            {violation === null ? null : (
              <Alert
                type="error"
                showIcon={false}
                closable={false}
                message="Der Eingabevertrag ist nicht erfüllt"
                description={violation}
              />
            )}
            <ReviewStep incident={incident} preview={preview} health={health} posture={posture} />
            {previewRefused ? (
              <Alert
                type="error"
                showIcon={false}
                closable={false}
                message="Die Abschlussvorschau ist abgelehnt worden"
                description={
                  'Der Wirt hat keine Vorschau ausgestellt. Ohne sie gibt es keinen Abschluss; ' +
                  'die Erfassung bleibt unverändert erhalten.'
                }
              />
            ) : null}
            <FinalizeStep
              preview={preview}
              violation={violation}
              acknowledgement={acknowledgement}
              acknowledgementRefused={acknowledgementRefused}
              busy={busy}
              onAcknowledge={acknowledge}
              onFinalize={finalize}
              onBack={() => {
                setStage({ kind: 'form' })
              }}
            />
          </Space>
        ) : null}
      </Space>
    </div>
  )
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  return invoke<T>(command, args)
}

/**
 * Die Bruecke ueber die Kommandos des Wirts.
 *
 * Sie wird EINMAL gebaut, nachdem der aktive Entwurf und die angetroffene
 * Finalisierung gelesen sind — die zwei Werte, die diese Flaeche synchron
 * braucht.
 */
export async function connectWriterBridge(): Promise<WriterBridge> {
  const [draft, raw] = await Promise.all([
    call<DraftStateView>(WRITER_COMMANDS.draftLoadActive),
    call<unknown>(WRITER_COMMANDS.recoverPending),
  ])
  const outcome = validatePendingResume(raw)
  // Eine ANGETROFFENE Finalisierung ist nicht jede Antwort des Startpfads: der
  // gewoehnliche Fall ist „nichts lag an", und der Wirt meldet ihn als
  // aufgeloesten Ausgang ueber der umkehrbaren Phase. Nur eine ueberschrittene
  // unwiderrufliche Grenze oder eine Blockade schliesst die Erfassungsmaske aus.
  const pendingResume =
    outcome.blockedCode !== null || outcome.resume.irreversible ? outcome : null
  return {
    draft,
    pendingResume,
    saveDraft: (input) => call(WRITER_COMMANDS.draftSave, { incident: input }),
    searchMasterData: (query) => call(WRITER_COMMANDS.masterDataSearch, { query }),
    preview: (input) => call(WRITER_COMMANDS.preview, { incident: input }),
    acknowledgeStaleRegistry: () => call(WRITER_COMMANDS.acknowledgeStaleRegistry),
    finalize: (input, confirmed) =>
      call(WRITER_COMMANDS.finalize, { incident: input, confirmed }),
    archiveHealth: () => call(WRITER_COMMANDS.archiveHealth),
    devicePosture: () => call(WRITER_COMMANDS.devicePosture),
    reauthenticate: (purpose) => call(WRITER_COMMANDS.reauthenticate, { purpose }),
    discardDraft: () => call(WRITER_COMMANDS.discardBegin),
    resumeDiscard: () => call(WRITER_COMMANDS.discardResume),
    exportBundle: () => call(WRITER_COMMANDS.exportBundle),
  }
}

/**
 * Die Klammer, die die Bruecke aufbaut und erst danach die Flaeche zeigt.
 *
 * Faellt der Aufbau aus, bleibt die Erfassung GESCHLOSSEN. Ein Formular ohne
 * gelesenen Entwurf waere ein zweiter aktiver Entwurf, und es gibt genau einen.
 */
export function WriterSurface({
  connect = connectWriterBridge,
}: {
  readonly connect?: () => Promise<WriterBridge>
}): ReactElement {
  const [bridge, setBridge] = useState<WriterBridge | null>(null)
  const [refused, setRefused] = useState(false)

  useEffect(() => {
    let live = true
    connect().then(
      (built) => {
        if (live) {
          setBridge(built)
        }
      },
      () => {
        if (live) {
          setRefused(true)
        }
      },
    )
    return () => {
      live = false
    }
  }, [connect])

  if (refused) {
    return (
      <Alert
        type="error"
        showIcon={false}
        closable={false}
        message="Die Erfassung ist nicht geöffnet"
        description={
          'Der aktive Entwurf konnte nicht gelesen werden. Die Erfassung bleibt geschlossen, ' +
          'damit kein zweiter Entwurf entsteht.'
        }
      />
    )
  }
  if (bridge === null) {
    return <Typography.Text>Der aktive Entwurf wird gelesen.</Typography.Text>
  }
  return <WriterPage bridge={bridge} />
}
