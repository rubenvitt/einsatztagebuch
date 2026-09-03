import { render, screen } from '@testing-library/react'
import { expect, it, vi } from 'vitest'

import type { FileModeArchiveView } from '../../bridge/generated-contracts'
import { SERVER_CONFIRMATION_V1_VALUES } from '../../bridge/generated-contracts'
import { userEvent } from '../../test-setup'
import type { FileModeBridge, FileModeHost } from './DirectoryHandle'
import { OpenArchivePanel } from './OpenArchivePanel'

const user = userEvent.setup()

// Der Wortlaut kommt aus SERVER_CONFIRMATION_V1_VALUES der GENERIERTEN
// Kontraktdatei und wird hier gelesen, nicht abgeschrieben. Der TEST darf ihn
// nennen — `bridge/no-hand-written-contracts.test.ts` nimmt `.test.tsx?`
// ausdruecklich aus —, die FLAECHE darf es nicht.
const NOT_SERVER_CONFIRMED = SERVER_CONFIRMATION_V1_VALUES[1]

// Die Endung, die das Bruecken-Doppel herausgibt. Sie steht EINMAL, damit
// Doppel und Dateiname nicht auseinanderlaufen koennen, und der Zeuge
// assertiert AUSDRUECKLICH nicht auf sie: die Endung ist ein Hinweis fuer den
// Dateidialog, entschieden wird an der Magie des Containers.
const BUNDLE_EXTENSION_FROM_THE_BRIDGE = 'eabundle'

/**
 * Ein Wirtsobjekt MIT dem Komfortweg.
 *
 * `showDirectoryPicker` ist eine FAEHIGKEIT und keine Browserkennung: eine
 * Kennungsliste veraltet still, eine Faehigkeitsabfrage nicht.
 */
function hostWithPicker(): FileModeHost {
  return { showDirectoryPicker: vi.fn() }
}

/**
 * Dasselbe Wirtsobjekt OHNE ihn — Safari und Firefox.
 *
 * Der Schluessel FEHLT, er steht nicht auf `undefined`. Das ist kein Detail:
 * die Erkennung ist `'showDirectoryPicker' in host`, und ein Doppel, das den
 * Schluessel mit dem Wert `undefined` traegt, besteht diese Abfrage. Es
 * beschriebe damit einen Browser, den es nicht gibt, und der Zeuge waere gruen,
 * ohne die Abwesenheit je gemessen zu haben.
 */
function hostWithoutPicker(): FileModeHost {
  return {}
}

function viewWithoutReceipts(): FileModeArchiveView {
  return {
    archiveObjectCount: 4,
    entryPackageCount: 1,
    fullyVerified: true,
    gapCount: 0,
    serverConfirmedCount: 0,
    notServerConfirmedCount: 1,
    serverConfirmation: NOT_SERVER_CONFIRMED,
  }
}

function bridgeWithoutReceipts(): FileModeBridge {
  return {
    bundleExtension: vi.fn(() => BUNDLE_EXTENSION_FROM_THE_BRIDGE),
    openBundle: vi.fn(async () => viewWithoutReceipts()),
    openDirectory: vi.fn(async () => viewWithoutReceipts()),
  }
}

/**
 * Der universelle Weg ist IMMER da, und der Komfortweg erscheint gar nicht
 * erst.
 *
 * Der universelle Weg ist ein `<input type="file">` mit Beschriftung und
 * AUSDRUECKLICH keine Schaltflaeche: eine Schaltflaeche muesste
 * `showOpenFilePicker` rufen, und die fehlt in Safari und Firefox genauso wie
 * `showDirectoryPicker` — ein Zeuge, der hier eine Rolle `button` verlangte,
 * druecke die Flaeche in genau die Abhaengigkeit, die dieser Modus vermeiden
 * muss.
 *
 * Und der Komfortweg wird WEGGELASSEN, nicht abgeblendet: eine abgeblendete
 * Schaltflaeche behauptet eine Faehigkeit, die es auf diesem Wirt nicht gibt,
 * und laesst den Leser nach der Bedingung suchen, unter der sie angeht.
 */
it('offers the universal file path even when showDirectoryPicker is absent', () => {
  const withoutPicker = hostWithoutPicker()
  // ANTI-LEERLAUF ueber dem DOPPEL: siehe `hostWithoutPicker`.
  expect('showDirectoryPicker' in withoutPicker).toBe(false)

  render(<OpenArchivePanel host={withoutPicker} bridge={bridgeWithoutReceipts()} />)

  expect(screen.getByLabelText('Archivdatei öffnen')).toBeEnabled()
  expect(screen.queryByRole('button', { name: 'Archivordner verbinden' })).not.toBeInTheDocument()
})

/**
 * Die Gegenprobe: auf einem Wirt MIT der Faehigkeit steht der Komfortweg
 * NEBEN dem universellen und nicht an seiner Stelle.
 *
 * Ohne sie waere die Zusicherung darueber auch dann gruen, wenn die Flaeche den
 * Komfortweg ueberhaupt nicht kennte.
 */
it('adds the directory path where the capability exists, without taking the universal one away', () => {
  render(<OpenArchivePanel host={hostWithPicker()} bridge={bridgeWithoutReceipts()} />)

  expect(screen.getByRole('button', { name: 'Archivordner verbinden' })).toBeEnabled()
  expect(screen.getByLabelText('Archivdatei öffnen')).toBeEnabled()
})

/**
 * Die zwei Dimensionen aus `design.md` §17.4, an ZWEI getrennten Traegern und
 * nicht an einem.
 *
 * `toHaveTextContent` auf einem gemeinsamen Knoten waere auch dann gruen, wenn
 * die Flaeche die Begriffe zusammenzoege. `nicht server-bestaetigt` ist im
 * Datei-Modus der REGELFALL: kein `alert`, keine Fehlerfarbe, kein
 * Ausrufezeichen, und weder `Luecke` noch `ungueltig` im Dokument.
 */
it('marks every object as not server confirmed without calling it a defect', async () => {
  render(<OpenArchivePanel host={hostWithoutPicker()} bridge={bridgeWithoutReceipts()} />)

  await user.upload(
    screen.getByLabelText('Archivdatei öffnen'),
    new File([new Uint8Array([0x45])], `bestand.${BUNDLE_EXTENSION_FROM_THE_BRIDGE}`),
  )

  expect(await screen.findByTestId('server-confirmation')).toHaveTextContent(NOT_SERVER_CONFIRMED)
  expect(screen.getByTestId('verification-summary')).toHaveTextContent('Alle Objekte geprüft')
  expect(screen.queryByText('Lücke')).not.toBeInTheDocument()
  expect(screen.queryByText('ungültig')).not.toBeInTheDocument()
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()
})
