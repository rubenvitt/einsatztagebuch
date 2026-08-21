import { Button, Input, Radio, Space, Typography } from 'antd'
import { useState } from 'react'
import type { ReactElement } from 'react'

import { MasterDataSelect } from './MasterDataSelect'
import type { SelectableRow } from './MasterDataSelect'
import { PATIENT_COUNT_STATUS_VALUES } from '../../bridge/generated-contracts'
import type {
  IncidentInputView,
  MasterDataResultView,
  PersonnelSelectionView,
  StructuredAddressView,
  VehicleSelectionView,
} from '../../bridge/generated-contracts'
import { PatientDataWarning } from '../../components/integrity/PatientDataWarning'

/**
 * Die zwei Zustaende der Patientenzahl, AUS der emittierten Vereinigung.
 *
 * Am Draht ist `patientCountStatus = 0` gleich `unknown` und `= 1` gleich
 * `known`; die emittierte Reihenfolge ist genau diese, also traegt die
 * Zerlegung die Polaritaet und kein Literal dieser Datei.
 */
const [UNKNOWN_STATUS, KNOWN_STATUS] = PATIENT_COUNT_STATUS_VALUES

/** Ein leerer Entwurf — die Gestalt, auf die der Abschluss zurueckfaellt. */
export function blankIncident(): IncidentInputView {
  return {
    humanIncidentNumber: '',
    occurredAt: { start: 0, end: null },
    keyword: { referenceId: null, displayText: '' },
    location: { freeText: '', address: null, coordinates: null },
    personnel: [],
    personnelEmptyReason: null,
    vehicles: [],
    vehiclesEmptyReason: null,
    patientCountStatus: UNKNOWN_STATUS,
    patientCount: null,
    notes: null,
    externalOrganizations: [],
  }
}

function isoOf(milliseconds: number): string {
  if (milliseconds === 0) {
    return ''
  }
  return new Date(milliseconds).toISOString()
}

function millisecondsOf(iso: string): number {
  const parsed = Date.parse(iso)
  return Number.isNaN(parsed) ? 0 : parsed
}

function personRow(person: PersonnelSelectionView): SelectableRow {
  return {
    key: person.masterPersonnelId ?? `adhoc:${person.displayName}`,
    displayName: person.displayName,
    detail: person.roleLabel,
    adHoc: person.masterPersonnelId === null,
  }
}

function vehicleRow(vehicle: VehicleSelectionView): SelectableRow {
  return {
    key: vehicle.masterVehicleId ?? `adhoc:${vehicle.displayName}`,
    displayName: vehicle.displayName,
    detail: vehicle.radioCallName ?? vehicle.licensePlate,
    adHoc: vehicle.masterVehicleId === null,
  }
}

const EMPTY_ADDRESS: StructuredAddressView = {
  street: null,
  houseNumber: null,
  postalCode: null,
  locality: null,
  adminArea: null,
  countryCode: null,
}

/** Die sechs Positionen der strukturierten Adresse, in Wire-Reihenfolge. */
const ADDRESS_FIELDS: readonly (readonly [keyof StructuredAddressView, string])[] = [
  ['street', 'Straße'],
  ['houseNumber', 'Hausnummer'],
  ['postalCode', 'Postleitzahl'],
  ['locality', 'Ort'],
  ['adminArea', 'Region'],
  ['countryCode', 'Ländercode'],
]

/**
 * Die Erfassungsmaske — der VOLLSTAENDIGE Eingabevertrag des Einsatzrumpfes.
 *
 * Zwoelf Positionen in der Reihenfolge von `payload-wire-addendum.md`:102-118.
 * Was diese Maske ausdruecklich nicht entscheidet: die Eindeutigkeit der
 * Einsatznummer. Sie wird VORGESCHLAGEN und bleibt bis zum Abschluss
 * bearbeitbar; das Register mit seiner `UNIQUE`-Bedingung und die Durchsetzung
 * unter der ausschliesslichen Writer-Sperre liegen im Wirt.
 */
export function IncidentForm({
  incident,
  onChange,
  onSearch,
}: {
  readonly incident: IncidentInputView
  readonly onChange: (next: IncidentInputView) => void
  readonly onSearch: (query: string) => Promise<MasterDataResultView>
}): ReactElement {
  const [personnelQuery, setPersonnelQuery] = useState('')
  const [vehicleQuery, setVehicleQuery] = useState('')
  const [found, setFound] = useState<MasterDataResultView | null>(null)
  const [favorites, setFavorites] = useState<readonly string[]>([])
  const [organizationDraft, setOrganizationDraft] = useState('')

  const search = (query: string): void => {
    void onSearch(query).then(
      (result) => {
        setFound(result)
      },
      () => {
        setFound(null)
      },
    )
  }

  const toggleFavorite = (row: SelectableRow): void => {
    setFavorites((current) =>
      current.includes(row.key)
        ? current.filter((key) => key !== row.key)
        : [...current, row.key],
    )
  }

  const known = incident.patientCountStatus === KNOWN_STATUS
  const structured = incident.location.address !== null
  const address = incident.location.address ?? EMPTY_ADDRESS

  return (
    <Space direction="vertical" size="middle">
      <Space direction="vertical" size="small">
        <label htmlFor="einsatznummer">Einsatznummer</label>
        <Input
          id="einsatznummer"
          value={incident.humanIncidentNumber}
          onChange={(event) => {
            onChange({ ...incident, humanIncidentNumber: event.target.value })
          }}
        />
        <Typography.Text type="secondary">
          Der Vorschlag folgt dem Muster JJJJ-NNNN und bleibt bis zum Abschluss bearbeitbar. Über
          die Eindeutigkeit je Organisation und Jahr entscheidet der Wirt unter der
          ausschließlichen Writer-Sperre — diese Maske zeigt sie ohne Entscheidung.
        </Typography.Text>
      </Space>

      <Space direction="vertical" size="small">
        <label htmlFor="beginn">Beginn (ISO 8601)</label>
        <Input
          id="beginn"
          value={isoOf(incident.occurredAt.start)}
          onChange={(event) => {
            onChange({
              ...incident,
              occurredAt: {
                ...incident.occurredAt,
                start: millisecondsOf(event.target.value),
              },
            })
          }}
        />
        <label htmlFor="ende">Ende (ISO 8601, optional)</label>
        <Input
          id="ende"
          value={incident.occurredAt.end === null ? '' : isoOf(incident.occurredAt.end)}
          onChange={(event) => {
            const value = event.target.value
            onChange({
              ...incident,
              occurredAt: {
                ...incident.occurredAt,
                end: value === '' ? null : millisecondsOf(value),
              },
            })
          }}
        />
      </Space>

      <Space direction="vertical" size="small">
        <label htmlFor="stichwort">Stichwort</label>
        <Input
          id="stichwort"
          value={incident.keyword.displayText}
          onChange={(event) => {
            onChange({
              ...incident,
              keyword: { ...incident.keyword, displayText: event.target.value },
            })
          }}
        />
        <label htmlFor="stichwort-referenz">Stichwort-Referenz (optional)</label>
        <Input
          id="stichwort-referenz"
          value={incident.keyword.referenceId ?? ''}
          onChange={(event) => {
            const value = event.target.value
            onChange({
              ...incident,
              keyword: { ...incident.keyword, referenceId: value === '' ? null : value },
            })
          }}
        />
        <PatientDataWarning />
      </Space>

      <Space direction="vertical" size="small">
        <Radio.Group
          aria-label="Form der Ortsangabe"
          value={structured ? 'adresse' : 'freitext'}
          onChange={(event) => {
            onChange({
              ...incident,
              location:
                event.target.value === 'adresse'
                  ? { freeText: null, address: address, coordinates: incident.location.coordinates }
                  : { freeText: '', address: null, coordinates: incident.location.coordinates },
            })
          }}
        >
          <Radio value="freitext">Ort als Freitext</Radio>
          <Radio value="adresse">Ort als Adresse</Radio>
        </Radio.Group>
        {structured ? (
          ADDRESS_FIELDS.map(([field, label]) => (
            <Space key={field} direction="vertical" size="small">
              <label htmlFor={`adresse-${field}`}>{label}</label>
              <Input
                id={`adresse-${field}`}
                value={address[field] ?? ''}
                onChange={(event) => {
                  const value = event.target.value
                  onChange({
                    ...incident,
                    location: {
                      ...incident.location,
                      freeText: null,
                      address: { ...address, [field]: value === '' ? null : value },
                    },
                  })
                }}
              />
            </Space>
          ))
        ) : (
          <>
            <label htmlFor="einsatzort">Einsatzort</label>
            <Input
              id="einsatzort"
              value={incident.location.freeText ?? ''}
              onChange={(event) => {
                onChange({
                  ...incident,
                  location: { ...incident.location, address: null, freeText: event.target.value },
                })
              }}
            />
          </>
        )}
        <PatientDataWarning />
      </Space>

      <MasterDataSelect
        kind="Person"
        idPrefix="personal"
        searchLabel="Personal suchen"
        query={personnelQuery}
        results={(found?.personnel ?? [])
          .filter(
            (person) =>
              !incident.personnel.some(
                (chosen) => chosen.masterPersonnelId === person.masterPersonnelId,
              ),
          )
          .map(personRow)}
        selected={incident.personnel.map(personRow)}
        favorites={favorites}
        emptyReason={
          incident.personnel.length > 0
            ? null
            : {
                label: 'Begründung für leere Personalliste',
                value: incident.personnelEmptyReason ?? '',
                onChange: (value) => {
                  onChange({
                    ...incident,
                    personnelEmptyReason: value === '' ? null : value,
                  })
                },
              }
        }
        onQuery={(value) => {
          setPersonnelQuery(value)
          search(value)
        }}
        onTake={(row) => {
          const person = (found?.personnel ?? []).find(
            (candidate) => personRow(candidate).key === row.key,
          )
          if (person !== undefined) {
            onChange({
              ...incident,
              personnel: [...incident.personnel, person],
              personnelEmptyReason: null,
            })
          }
        }}
        onAdHoc={() => {
          onChange({
            ...incident,
            personnel: [
              ...incident.personnel,
              {
                masterPersonnelId: null,
                displayName: personnelQuery === '' ? 'Ad-hoc-Person' : personnelQuery,
                roleLabel: null,
              },
            ],
            personnelEmptyReason: null,
          })
        }}
        onRemove={(row) => {
          onChange({
            ...incident,
            personnel: incident.personnel.filter(
              (person) => personRow(person).key !== row.key,
            ),
          })
        }}
        onToggleFavorite={toggleFavorite}
      />

      <MasterDataSelect
        kind="Fahrzeug"
        idPrefix="fahrzeuge"
        searchLabel="Fahrzeuge suchen"
        query={vehicleQuery}
        results={(found?.vehicles ?? [])
          .filter(
            (vehicle) =>
              !incident.vehicles.some(
                (chosen) => chosen.masterVehicleId === vehicle.masterVehicleId,
              ),
          )
          .map(vehicleRow)}
        selected={incident.vehicles.map(vehicleRow)}
        favorites={favorites}
        emptyReason={
          incident.vehicles.length > 0
            ? null
            : {
                label: 'Begründung für leere Fahrzeugliste',
                value: incident.vehiclesEmptyReason ?? '',
                onChange: (value) => {
                  onChange({
                    ...incident,
                    vehiclesEmptyReason: value === '' ? null : value,
                  })
                },
              }
        }
        onQuery={(value) => {
          setVehicleQuery(value)
          search(value)
        }}
        onTake={(row) => {
          const vehicle = (found?.vehicles ?? []).find(
            (candidate) => vehicleRow(candidate).key === row.key,
          )
          if (vehicle !== undefined) {
            onChange({
              ...incident,
              vehicles: [...incident.vehicles, vehicle],
              vehiclesEmptyReason: null,
            })
          }
        }}
        onAdHoc={() => {
          onChange({
            ...incident,
            vehicles: [
              ...incident.vehicles,
              {
                masterVehicleId: null,
                displayName: vehicleQuery === '' ? 'Ad-hoc-Fahrzeug' : vehicleQuery,
                radioCallName: null,
                licensePlate: null,
              },
            ],
            vehiclesEmptyReason: null,
          })
        }}
        onRemove={(row) => {
          onChange({
            ...incident,
            vehicles: incident.vehicles.filter(
              (vehicle) => vehicleRow(vehicle).key !== row.key,
            ),
          })
        }}
        onToggleFavorite={toggleFavorite}
      />

      <Space direction="vertical" size="small">
        <Radio.Group
          aria-label="Patientenzahl"
          value={incident.patientCountStatus}
          onChange={(event) => {
            const next: string = event.target.value
            onChange({
              ...incident,
              patientCountStatus: next === KNOWN_STATUS ? KNOWN_STATUS : UNKNOWN_STATUS,
              // Die Polaritaet des Drahts: `unknown` VERLANGT `null`, und eine
              // stehengebliebene Zahl waere eine erfundene Angabe.
              patientCount: next === KNOWN_STATUS ? (incident.patientCount ?? 0) : null,
            })
          }}
        >
          <Radio value={KNOWN_STATUS}>bekannt</Radio>
          <Radio value={UNKNOWN_STATUS}>unbekannt</Radio>
        </Radio.Group>
        {known ? (
          <>
            <label htmlFor="patientenzahl">Anzahl</label>
            <Input
              id="patientenzahl"
              type="number"
              min={0}
              value={incident.patientCount === null ? '' : String(incident.patientCount)}
              onChange={(event) => {
                const raw = event.target.value
                onChange({
                  ...incident,
                  patientCount: raw === '' ? null : Number.parseInt(raw, 10),
                })
              }}
            />
          </>
        ) : (
          <Typography.Text>
            Ohne bekannte Patientenzahl wird keine Zahl gesendet — und ausdrücklich nicht die Null.
          </Typography.Text>
        )}
      </Space>

      <Space direction="vertical" size="small">
        <label htmlFor="notizen">Notizen</label>
        <Input.TextArea
          id="notizen"
          value={incident.notes ?? ''}
          onChange={(event) => {
            const value = event.target.value
            onChange({ ...incident, notes: value === '' ? null : value })
          }}
        />
        <PatientDataWarning />
      </Space>

      <Space direction="vertical" size="small">
        <label htmlFor="organisation">Weitere Organisation</label>
        <Input
          id="organisation"
          value={organizationDraft}
          onChange={(event) => {
            setOrganizationDraft(event.target.value)
          }}
        />
        <Button
          onClick={() => {
            if (organizationDraft === '') {
              return
            }
            onChange({
              ...incident,
              externalOrganizations: [
                ...incident.externalOrganizations,
                { id: null, displayName: organizationDraft },
              ],
            })
            setOrganizationDraft('')
          }}
        >
          Organisation hinzufügen
        </Button>
        <ul aria-label="Beteiligte Organisationen">
          {incident.externalOrganizations.map((organization) => (
            <li key={organization.displayName}>
              <Space size="small">
                <Typography.Text>{organization.displayName}</Typography.Text>
                <Button
                  onClick={() => {
                    onChange({
                      ...incident,
                      externalOrganizations: incident.externalOrganizations.filter(
                        (candidate) => candidate.displayName !== organization.displayName,
                      ),
                    })
                  }}
                >
                  {`Organisation ${organization.displayName} entfernen`}
                </Button>
              </Space>
            </li>
          ))}
        </ul>
      </Space>
    </Space>
  )
}
