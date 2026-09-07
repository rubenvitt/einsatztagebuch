import { Alert, Descriptions, Radio, Space, Typography } from 'antd'
import { useId, useState } from 'react'
import type { ReactElement } from 'react'

import { formatInstant } from './format'
import { formatDuration } from '../../app/TrustAgeStatus'
import { CLOCK_RELEASE_AVAILABILITY_VALUES } from '../../bridge/generated-contracts'
import type {
  ClockReleaseAvailability,
  ClockReleaseJustificationV1,
  ClockReleaseOfferView,
  ClockReleaseOutcomeView,
} from '../../bridge/generated-contracts'
import { IrreversibleActionConfirm } from '../../components/integrity/IrreversibleActionConfirm'

/** Die Verfuegbarkeit, deren ERSTE Position das Angebot ist. */
const [OFFERED] = CLOCK_RELEASE_AVAILABILITY_VALUES

/** Der Wortlaut je Verfuegbarkeit — erschoepfend, unzitierte Schluessel. */
const AVAILABILITY_TEXT: Record<ClockReleaseAvailability, string> = {
  Offered: 'Zeitfreigabe angeboten',
  IndependentTimeUnavailable: 'Keine unabhängige Zeitquelle verfügbar',
  NotBlocked: 'Keine Zeitfreigabe angeboten',
}

/**
 * Die drei zulaessigen Begruendungen (`ea_format::ClockReleaseJustificationV1`,
 * `local_audit.rs:26`) mit ihrem Wortlaut. Eine vierte gibt es nicht, und ein
 * freier Text ist keine Begruendung.
 */
export const JUSTIFICATION_TEXT: Record<ClockReleaseJustificationV1, string> = {
  OperatorVerifiedWallClock: 'Wanduhr vom Bediener geprüft',
  PlatformTimeSourceRecovery: 'Zeitquelle der Plattform wiederhergestellt',
  HardwareClockMaintenance: 'Wartung der Hardware-Uhr',
}

/**
 * Die Zusage, die IMMER da steht — auch ohne Angebot: die Freigabe verschiebt
 * keine der drei Grenzen. Der Ausgang traegt dieselben drei Aussagen als
 * Felder, und die Flaeche leitet ihre Zeilen daraus ab und nicht aus Prosa.
 */
const INVARIANT_TEXT =
  'Die Freigabe ändert weder den Zeit-Floor noch den Registry-Ablauf noch die Sequenz-Lease.'

const yesNo = (changed: boolean): string => (changed ? 'ja' : 'nein')

/**
 * Die Zeitfreigabe nach blockierendem Uhrenversatz.
 *
 * Nur bei angebotener Freigabe gibt es eine Handhabe; ohne Angebot steht ein Satz und
 * KEIN deaktivierter Knopf (Muster `IrreversibleActionConfirm`). Die Freigabe
 * verlangt eine der drei Begruendungen UND eine frische Wiederanmeldung fuer
 * genau diesen Zweck; der Ausgang zeigt Kennung, Ablauf und die drei
 * „geändert: nein"-Zeilen aus den Wahrheitswerten — meldet der Wirt eine
 * Aenderung, steht eine Warnung da statt einer Beruhigung.
 */
export function ClockReleaseWizard({
  offer,
  outcome,
  notice,
  busy,
  onIssue,
}: {
  readonly offer: ClockReleaseOfferView
  readonly outcome: ClockReleaseOutcomeView | null
  readonly notice: string | null
  readonly busy: boolean
  readonly onIssue: (justification: ClockReleaseJustificationV1) => void
}): ReactElement {
  const [justification, setJustification] = useState<ClockReleaseJustificationV1 | null>(null)
  const legendId = useId()

  if (offer.availability !== OFFERED) {
    return (
      <Space direction="vertical" size="small">
        <Typography.Text>{AVAILABILITY_TEXT[offer.availability]}</Typography.Text>
        <Typography.Text>{INVARIANT_TEXT}</Typography.Text>
      </Space>
    )
  }

  const items = [
    {
      key: 'floor',
      label: 'Zeit-Floor',
      children: offer.floorMs === null ? 'nicht genannt' : formatInstant(offer.floorMs),
    },
    {
      key: 'wall',
      label: 'Wanduhr des Betriebssystems',
      children:
        offer.observedWallClockMs === null ? 'nicht genannt' : formatInstant(offer.observedWallClockMs),
    },
    {
      key: 'limit',
      label: 'Signiertes Limit',
      children:
        offer.maxFutureClockSkewMs === null
          ? 'nicht genannt'
          : formatDuration(offer.maxFutureClockSkewMs),
    },
    {
      key: 'expiry',
      label: 'Ablauf',
      children: offer.expiresAtMs === null ? 'nicht genannt' : formatInstant(offer.expiresAtMs),
    },
  ]
  const unexpected =
    outcome !== null &&
    (outcome.changesTimeFloor || outcome.changesRegistryExpiry || outcome.changesLease)

  return (
    <Space direction="vertical" size="middle">
      <Typography.Text>{AVAILABILITY_TEXT[offer.availability]}</Typography.Text>
      <Descriptions size="small" column={1} items={items} />
      <Typography.Text>{INVARIANT_TEXT}</Typography.Text>
      <Typography.Text id={legendId} strong>
        Begründung
      </Typography.Text>
      <Radio.Group
        aria-labelledby={legendId}
        value={justification}
        onChange={(event) => {
          setJustification(event.target.value as ClockReleaseJustificationV1)
        }}
        options={offer.justifications.map((value) => ({
          value,
          label: JUSTIFICATION_TEXT[value],
        }))}
      />
      {notice === null ? null : <Alert type="warning" showIcon={false} message={notice} />}
      {busy ? (
        <Typography.Text>Die Zeitfreigabe wird erteilt.</Typography.Text>
      ) : (
        <IrreversibleActionConfirm
          prompt="Zeitfreigabe erteilen"
          consequence="Die Freigabe wird als signiertes Auditobjekt festgehalten und läuft zum genannten Zeitpunkt ab."
          checkboxLabel="Ich habe die Wanduhr gegen eine unabhängige Quelle geprüft."
          confirmLabel="Neu anmelden und Zeitfreigabe erteilen"
          ready={justification !== null}
          onConfirm={() => {
            if (justification !== null) {
              onIssue(justification)
            }
          }}
        />
      )}
      {outcome === null ? null : (
        <Space direction="vertical" size="small">
          <Typography.Text strong>Freigabe erteilt</Typography.Text>
          <Typography.Text code>{outcome.releaseId}</Typography.Text>
          <Typography.Text>{`Ablauf: ${formatInstant(outcome.expiresAtMs)}`}</Typography.Text>
          <Typography.Text>{`Zeit-Floor geändert: ${yesNo(outcome.changesTimeFloor)}`}</Typography.Text>
          <Typography.Text>
            {`Registry-Ablauf geändert: ${yesNo(outcome.changesRegistryExpiry)}`}
          </Typography.Text>
          <Typography.Text>{`Sequenz-Lease geändert: ${yesNo(outcome.changesLease)}`}</Typography.Text>
          {unexpected ? (
            <Alert
              type="error"
              showIcon={false}
              message="Unerwartete Änderung gemeldet"
              description="Der Wirt meldet eine Änderung an einer Grenze, die eine Zeitfreigabe nie verschiebt. Prüfen Sie den Bestand, bevor Sie weiterarbeiten."
            />
          ) : null}
        </Space>
      )}
    </Space>
  )
}
