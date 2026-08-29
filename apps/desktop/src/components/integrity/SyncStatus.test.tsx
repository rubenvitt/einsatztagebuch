import { render, screen, within } from '@testing-library/react'
import { expect, it } from 'vitest'

import { SyncStatus } from './SyncStatus'
import { DETAIL_CAUSE_VALUES, SYNC_STATUS_VALUES } from '../../bridge/generated-contracts'

/**
 * Die vier Zustaende und die vier Ursachen, AUS dem emittierten Array entpackt.
 *
 * Kein Literal in dieser Datei, und aus demselben Grund wie in der Komponente:
 * die Namen sind woertliche Oberflaechenkopie einer globalen Randbedingung,
 * ihre EINE Quelle ist `crates/ea-archive-fs/src/publication_queue.rs`, und
 * `no-hand-written-contracts.test.ts` faellt, sobald hier einer davon in
 * Anfuehrungszeichen steht. Ein Test, der die Namen abschriebe, ginge mit
 * einer Umbenennung gruen weiter durch — und genau das soll er nicht.
 */
const [LOCALLY_SAVED, UPLOAD_PENDING, SYNCHRONIZED, FAILED] = SYNC_STATUS_VALUES
const [NETWORK_ARCHIVE_WAITING, , , RESUME_EXHAUSTED] = DETAIL_CAUSE_VALUES

/**
 * Die Vereinigung ist GESCHLOSSEN: genau vier Namen, nicht mehr.
 *
 * Der Zeuge steht hier und nicht nur im Uebersetzer, weil `SYNC_STATUS_VALUES`
 * eine LAUFZEITliste ist: ein fuenfter Eintrag in der emittierten Datei wuerde
 * typseitig anstandslos durchgehen und in der Oberflaeche als fuenfter Zustand
 * erscheinen.
 */
it('unpacks exactly the four normative states out of the emitted array', () => {
  expect(SYNC_STATUS_VALUES).toHaveLength(4)
  expect(new Set(SYNC_STATUS_VALUES).size).toBe(4)
})

/**
 * Der Zustand steht da, und zwar unter dem NAMEN seiner Rolle.
 *
 * Dieselbe Komponente steht an zwei Stellen — als Speicherzustand des Entwurfs
 * und als Veroeffentlichungszustand nach dem Abschluss —, und eine
 * Bildschirmleseausgabe muss die zwei unterscheiden koennen.
 */
it('names the region so two instances stay distinguishable', () => {
  render(
    <>
      <SyncStatus state={{ status: LOCALLY_SAVED, detailCause: null }} label="Speicherzustand" />
      <SyncStatus state={{ status: SYNCHRONIZED, detailCause: null }} label="Veröffentlichung" />
    </>,
  )
  expect(within(screen.getByRole('status', { name: 'Speicherzustand' })).getByText(LOCALLY_SAVED))
    .toBeInTheDocument()
  expect(within(screen.getByRole('status', { name: 'Veröffentlichung' })).getByText(SYNCHRONIZED))
    .toBeInTheDocument()
})

/**
 * Die Detailursache tritt DANEBEN und ersetzt den Zustand nie.
 *
 * `design.md` §11.5 ist an dieser Stelle ausdruecklich: verliert ein
 * freigegebenes Netzbackend eine zugesicherte Faehigkeit, BLEIBT der Zustand
 * `Upload ausstehend` und die Ursache tritt daneben. Der Zeuge prueft deshalb
 * BEIDE Texte im selben Bereich — ein Test, der nur die Ursache faende, waere
 * auch dann gruen, wenn sie den Zustand verdraengt haette.
 */
it('renders the detail cause beside the state and never instead of it', () => {
  render(
    <SyncStatus
      state={{ status: UPLOAD_PENDING, detailCause: NETWORK_ARCHIVE_WAITING }}
      label="Veröffentlichung"
    />,
  )
  const region = within(screen.getByRole('status', { name: 'Veröffentlichung' }))
  expect(region.getByText(UPLOAD_PENDING)).toBeInTheDocument()
  expect(region.getByText(NETWORK_ARCHIVE_WAITING)).toBeInTheDocument()
})

/**
 * Ohne Ursache steht KEIN zweiter Text da.
 *
 * Die Gegenprobe zum Zeugen darueber: ohne sie waere „die Ursache steht
 * daneben" auch dann gruen, wenn dort immer irgendein Text stuende.
 */
it('shows no second text when there is no detail cause', () => {
  render(<SyncStatus state={{ status: SYNCHRONIZED, detailCause: null }} label="Veröffentlichung" />)
  const region = screen.getByRole('status', { name: 'Veröffentlichung' })
  expect(region.textContent?.trim()).toBe(SYNCHRONIZED)
})

/**
 * Nur ein BESTAETIGTER Zustand ist als bestaetigt ausgewiesen.
 *
 * `Upload ausstehend` und `Fehler` sind keine Bestaetigung, und ein Haken an
 * ihnen waere eine Zusage, die der Bestand nicht traegt. Gemessen wird am
 * Attribut und nicht am Symbol: das Symbol ist `aria-hidden` und dekorativ,
 * also stuende die Aussage sonst an einer Stelle, die weder ein Zeuge noch
 * eine Bildschirmleseausgabe erreicht.
 */
it.each([
  [LOCALLY_SAVED, 'true'],
  [UPLOAD_PENDING, 'false'],
  [SYNCHRONIZED, 'true'],
  [FAILED, 'false'],
] as const)('marks %s as confirmed=%s', (status, confirmed) => {
  render(<SyncStatus state={{ status, detailCause: null }} label="Veröffentlichung" />)
  const region = screen.getByRole('status', { name: 'Veröffentlichung' })
  expect(region.getAttribute('data-confirmed')).toBe(confirmed)
})

/**
 * `Fehler` mit erschoepfter Wiederaufnahme bleibt VIER Zustaende gross.
 *
 * Die Ursache, die dieser Task ueberhaupt erst erreichbar macht, erzeugt keinen
 * fuenften Zustand: sie steht neben `Fehler`, und `Fehler` ist einer der vier.
 */
it('keeps the exhausted resume beside the failed state instead of becoming a fifth', () => {
  render(
    <SyncStatus
      state={{ status: FAILED, detailCause: RESUME_EXHAUSTED }}
      label="Veröffentlichung"
    />,
  )
  const region = within(screen.getByRole('status', { name: 'Veröffentlichung' }))
  expect(region.getByText(FAILED)).toBeInTheDocument()
  expect(region.getByText(RESUME_EXHAUSTED)).toBeInTheDocument()
  expect(SYNC_STATUS_VALUES).toContain(FAILED)
  expect(SYNC_STATUS_VALUES).not.toContain(RESUME_EXHAUSTED)
})
