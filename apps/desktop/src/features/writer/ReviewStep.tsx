import { Descriptions, Space, Typography } from 'antd'
import type { ReactElement } from 'react'

import { PATIENT_COUNT_STATUS_VALUES } from '../../bridge/generated-contracts'
import type {
  ArchiveHealthSummaryView,
  DevicePostureSummaryView,
  FinalizationPreviewView,
  IncidentInputView,
} from '../../bridge/generated-contracts'
import { ArchiveHealthPanel } from '../../components/integrity/ArchiveHealthPanel'
import { ChainIntegrityRail } from '../../components/integrity/ChainIntegrityRail'
import { DevicePosturePanel } from '../../components/integrity/DevicePosturePanel'
import { EvidenceStatus } from '../../components/integrity/EvidenceStatus'
import { VerificationBadge } from '../../components/integrity/VerificationBadge'
import { DecorativeIcon } from '../../design/icons'

const [, KNOWN_STATUS] = PATIENT_COUNT_STATUS_VALUES

const DAY_MS = 24 * 60 * 60 * 1000

/** Ganze Tage, weil die Policyfrist in Tagen gedacht ist. */
function dayText(milliseconds: number): string {
  const days = Math.floor(milliseconds / DAY_MS)
  return days === 1 ? '1 Tag' : `${String(days)} Tage`
}

/**
 * Das ALTER des gebundenen Vertrauensbestands gegen die Policyfrist.
 *
 * Zwei getrennte Zahlen und eine dritte Aussage: die Ueberschreitung ist eine
 * WARNUNG mit Text und Symbol und niemals eine Sperre auf der Finalisierung.
 * Die Sperre haengt an der Gueltigkeit des Bestands und ist eine andere Aussage
 * (`StaleDecision`).
 */
function TrustHolding({
  preview,
}: {
  readonly preview: FinalizationPreviewView
}): ReactElement {
  return (
    <div role="status" aria-label="Vertrauensbestand">
      <Space direction="vertical" size="small">
        <Typography.Text>{`Trust-Bestand ${dayText(preview.trustAgeMs)} alt`}</Typography.Text>
        <Typography.Text>{`Frist ${dayText(preview.readerTrustRefreshMs)}`}</Typography.Text>
        {preview.trustRefreshOverdue ? (
          <Space size="small">
            <DecorativeIcon name="warning" />
            <Typography.Text>
              Aktualisierung erforderlich — eine Warnung und keine Sperre auf dem Abschluss.
            </Typography.Text>
          </Space>
        ) : (
          <Typography.Text>Die Auffrischungsfrist ist eingehalten.</Typography.Text>
        )}
      </Space>
    </div>
  )
}

/**
 * Die Bestaetigungsansicht: JEDES Feld, jede Momentaufnahme und der
 * Kettenzustand.
 *
 * Was hier nicht steht, kann niemand vor dem unwiderruflichen Schritt pruefen —
 * deshalb ist die Feldliste vollstaendig und nicht eine Auswahl. Der
 * Recovery-Empfaenger und die Evidenzstufe sind in dieser Ausbaustufe NICHT
 * gemeldet, und genau das steht da; eine erfundene Angabe waere schlimmer als
 * eine benannte Abwesenheit.
 */
export function ReviewStep({
  incident,
  preview,
  health,
  posture,
}: {
  readonly incident: IncidentInputView
  readonly preview: FinalizationPreviewView | null
  readonly health: ArchiveHealthSummaryView | null
  readonly posture: DevicePostureSummaryView | null
}): ReactElement {
  const known = incident.patientCountStatus === KNOWN_STATUS
  return (
    <section aria-label="Prüfung">
      <Space direction="vertical" size="middle">
        <Descriptions
          column={1}
          items={[
            {
              key: 'nummer',
              label: 'Einsatznummer',
              children: incident.humanIncidentNumber,
            },
            {
              key: 'zeit',
              label: 'Zeitraum',
              children:
                incident.occurredAt.end === null
                  ? `${String(incident.occurredAt.start)} (ohne Ende)`
                  : `${String(incident.occurredAt.start)} bis ${String(incident.occurredAt.end)}`,
            },
            {
              key: 'stichwort',
              label: 'Stichwort',
              children:
                incident.keyword.referenceId === null
                  ? incident.keyword.displayText
                  : `${incident.keyword.displayText} (${incident.keyword.referenceId})`,
            },
            {
              key: 'ort',
              label: 'Einsatzort',
              children:
                incident.location.address === null
                  ? (incident.location.freeText ?? '')
                  : [
                      incident.location.address.street,
                      incident.location.address.houseNumber,
                      incident.location.address.postalCode,
                      incident.location.address.locality,
                      incident.location.address.adminArea,
                      incident.location.address.countryCode,
                    ]
                      .filter((part) => part !== null)
                      .join(' '),
            },
            {
              key: 'koordinaten',
              label: 'Koordinaten',
              children:
                incident.location.coordinates === null
                  ? 'keine'
                  : `${String(incident.location.coordinates.latE7)} / ${String(
                      incident.location.coordinates.lonE7,
                    )}`,
            },
            {
              key: 'personal',
              label: 'Personal',
              children:
                incident.personnel.length === 0
                  ? `leer — ${incident.personnelEmptyReason ?? ''}`
                  : incident.personnel
                      .map(
                        (person) =>
                          `${person.displayName}${
                            person.masterPersonnelId === null ? ' (ad hoc)' : ''
                          }`,
                      )
                      .join(', '),
            },
            {
              key: 'fahrzeuge',
              label: 'Fahrzeuge',
              children:
                incident.vehicles.length === 0
                  ? `leer — ${incident.vehiclesEmptyReason ?? ''}`
                  : incident.vehicles
                      .map(
                        (vehicle) =>
                          `${vehicle.displayName}${
                            vehicle.masterVehicleId === null ? ' (ad hoc)' : ''
                          }`,
                      )
                      .join(', '),
            },
            {
              key: 'patienten',
              label: 'Patientenzahl',
              children:
                known && incident.patientCount !== null ? (
                  <Typography.Text>{`${String(incident.patientCount)} Patienten`}</Typography.Text>
                ) : (
                  <Typography.Text>Patientenzahl unbekannt</Typography.Text>
                ),
            },
            {
              key: 'notizen',
              label: 'Notizen',
              children: incident.notes ?? 'keine',
            },
            {
              key: 'organisationen',
              label: 'Beteiligte Organisationen',
              children:
                incident.externalOrganizations.length === 0
                  ? 'keine'
                  : incident.externalOrganizations
                      .map((organization) => organization.displayName)
                      .join(', '),
            },
          ]}
        />

        {preview === null ? (
          <Typography.Text>
            Die Abschlussvorschau des Wirts steht noch aus. Ohne sie gibt es keinen Abschluss.
          </Typography.Text>
        ) : (
          <>
            <TrustHolding preview={preview} />
            <ChainIntegrityRail
              nodes={[
                {
                  label: `Vorgeschlagene Sequenz ${String(preview.proposedSequence)}`,
                  verified: true,
                  detail: 'Vom Wirt unter der ausschließlichen Writer-Sperre vorgeschlagen.',
                },
                {
                  label: 'Bindung an den Vorgänger',
                  verified: preview.bindsPredecessor,
                  detail: preview.bindsPredecessor
                    ? 'Der direkte Vorgänger ist gebunden.'
                    : 'Kein Vorgänger — dies ist der erste Eintrag der Kette.',
                },
                {
                  label: 'Registry-Head',
                  verified: null,
                  detail: `Beobachtete Zeit ${String(preview.effectiveNow)}.`,
                },
                {
                  label: 'Recovery-Empfänger',
                  verified: null,
                  detail:
                    'In dieser Ausbaustufe meldet kein Kommando den Empfänger; die Prüfung ' +
                    'liegt im Wirt und wird vor dem lokalen Commit erzwungen.',
                },
              ]}
            />
            <VerificationBadge
              label="Abschlussvorschau"
              verified
              detail="Gegen dieselbe Vorschau wird der Abschluss nachgerechnet."
            />
            <EvidenceStatus grade={null} />
          </>
        )}

        <ArchiveHealthPanel report={health} />
        <DevicePosturePanel posture={posture} />
      </Space>
    </section>
  )
}
