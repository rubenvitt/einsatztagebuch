import { expect, test } from '@playwright/test'

import { installOfflineGuard } from '../../playwright.config'

/**
 * Das Wirtsdoppel — als Init-Skript des TESTS und nicht als Schalter der
 * Anwendung.
 *
 * `apps/desktop/src` darf keine lokale Konfigurationsquelle lesen (der Zeuge
 * `reads no local configuration source at all` in `AppShell.test.tsx` liest
 * jede handgeschriebene Quelle und verbietet `localStorage`,
 * `import.meta.env` und `process.env`). Ein Testschalter IN der Anwendung waere
 * genau diese verbotene Quelle. `@tauri-apps/api` ruft ausschliesslich
 * `window.__TAURI_INTERNALS__.invoke` (`core.js`:202) und
 * `window.__TAURI_INTERNALS__.transformCallback` (`core.js`:72) — die Naht
 * liegt also im Fenster, und der Test besetzt sie, bevor das erste Modul
 * laeuft.
 *
 * Die Antworten sind die DRAHTFORM der Kommandos: `camelCase`, nackte Ziffern,
 * keine Zeichenkette fuer eine Zahl. Damit ist dieser Lauf zugleich der erste
 * Beleg dafuer, dass die Drahtform durch die IPC-Vermittlung unveraendert
 * ankommt.
 */
const HOST_DOUBLE = String(function installHostDouble(): void {
  const invoked: string[] = []
  const draft = {
    incident: {
      humanIncidentNumber: '2026-0001',
      occurredAt: { start: 1771000000000, end: null },
      keyword: { referenceId: null, displayText: 'Verkehrsunfall' },
      location: { freeText: 'Bahnhofstraße 1', address: null, coordinates: null },
      personnel: [{ masterPersonnelId: 'P-1', displayName: 'A. Beispiel', roleLabel: null }],
      personnelEmptyReason: null,
      vehicles: [
        {
          masterVehicleId: 'V-1',
          displayName: 'RTW 1',
          radioCallName: null,
          licensePlate: null,
        },
      ],
      vehiclesEmptyReason: null,
      patientCountStatus: 'Known',
      patientCount: 2,
      notes: null,
      externalOrganizations: [],
    },
    sync: { status: 'lokal gesichert', detailCause: null },
  }
  const answers: Record<string, unknown> = {
    'plugin:event|listen': 0,
    'plugin:event|unlisten': null,
    verified_session: { role: 'writer', capabilities: ['capture'] },
    startup_recovery: {
      phase: 'ReversibleDraft',
      irreversible: false,
      outcomeCode: 'NothingPending',
      outcomeSequence: null,
    },
    // Der gewoehnliche Fall: nichts lag an. Der Wirt meldet ihn als
    // aufgeloesten Ausgang ueber der UMKEHRBAREN Phase, und die Bruecke macht
    // daraus „keine angetroffene Finalisierung".
    writer_recover_pending: {
      resume: {
        phase: 'ReversibleDraft',
        irreversible: false,
        outcomeCode: 'NothingPending',
        outcomeSequence: null,
      },
      blockedCode: null,
      sync: null,
    },
    draft_load_active: draft,
    draft_save: { status: 'lokal gesichert', detailCause: null },
    master_data_search: { personnel: [], vehicles: [], personnelTotal: 1, vehicleTotal: 1 },
    writer_preview: {
      proposedSequence: 7,
      bindsPredecessor: true,
      effectiveNow: 1771000100000,
      trustAgeMs: 3600000,
      readerTrustRefreshMs: 604800000,
      trustRefreshOverdue: false,
      staleDecision: 'Fresh',
    },
    session_reauthenticate: { fresh: true, purposeCode: 'EA-OPERATOR-REAUTH-FINALIZE' },
    writer_finalize: {
      sequence: 7,
      entryHash: '11'.repeat(32),
      objectHash: '22'.repeat(32),
      sync: { status: 'lokal gesichert', detailCause: null },
    },
    archive_health_report: { healthy: true, findingCodes: [], quarantineReasons: [] },
    device_posture_report: {
      requirements: [
        {
          requirementCode: 'EA-POSTURE-FDE',
          satisfied: null,
          evidenceCode: 'EA-POSTURE-FDE-UNREPORTABLE',
        },
      ],
      productionReady: false,
    },
    archive_export_bundle_file: { path: '/tmp/archiv.eab', objectCount: 12, byteCount: 4096 },
  }
  const host = {
    invoke(command: string): Promise<unknown> {
      invoked.push(command)
      if (!(command in answers)) {
        return Promise.reject(new Error(`EA-E2E-UNKNOWN-COMMAND:${command}`))
      }
      return Promise.resolve(answers[command])
    },
    transformCallback(callback: (payload: unknown) => void): number {
      void callback
      return 1
    },
    unregisterCallback(): void {},
    invokedCommands(): string[] {
      return invoked
    },
  }
  Object.defineProperty(window, '__TAURI_INTERNALS__', { value: host, writable: true })
})

async function bootWriter(page: import('@playwright/test').Page): Promise<void> {
  await page.addInitScript(`(${HOST_DOUBLE})()`)
  await page.goto('/')
  await page.getByRole('link', { name: /einsatz erfassen/i }).click()
  await expect(page.getByRole('button', { name: 'Prüfen' })).toBeVisible()
}

test('finalizes with the network cut off and reopens a blank form', async ({ context, page }) => {
  await installOfflineGuard(context)
  await bootWriter(page)

  await expect(page.getByLabel('Einsatznummer')).toHaveValue('2026-0001')
  await page.getByRole('button', { name: 'Prüfen' }).click()
  await expect(page.getByRole('status', { name: 'Vertrauensbestand' })).toBeVisible()
  await page.getByRole('checkbox', { name: /unwiderruflich/i }).check()
  await page.getByRole('button', { name: 'Unwiderruflich finalisieren' }).click()

  const closing = page.getByRole('region', { name: 'Abschluss' })
  await expect(closing).toBeVisible()
  await expect(closing).toContainText('lokal gesichert')
  await expect(closing).toContainText('7')
  // Hashes UND Sequenz, durch die echte IPC-Vermittlung des Wirts.
  await expect(closing).toContainText('11'.repeat(32))
  await expect(closing).toContainText('22'.repeat(32))
  // Und danach ein LEERES Formular — kein Verlauf, kein letzter Einsatz.
  await expect(page.getByLabel('Einsatznummer')).toHaveValue('')
})

test('reaches no command that opens a decrypted entry, a history, or final content', async ({
  context,
  page,
}) => {
  await installOfflineGuard(context)
  await bootWriter(page)
  await page.getByRole('button', { name: 'Prüfen' }).click()
  await expect(page.getByRole('status', { name: 'Vertrauensbestand' })).toBeVisible()

  const invoked = await page.evaluate(() =>
    (
      window as unknown as { __TAURI_INTERNALS__: { invokedCommands: () => string[] } }
    ).__TAURI_INTERNALS__.invokedCommands(),
  )
  // Ohne diese Zusicherung laeuft die Schleife darunter ueber die leere Menge.
  expect(invoked.length).toBeGreaterThan(3)
  for (const command of invoked) {
    expect(command).not.toMatch(/decrypt|history|entry_content/)
  }
  await expect(page.getByRole('button', { name: /verlauf|letzter einsatz|inhalt öffnen/i })).toHaveCount(0)
  await expect(page.getByRole('link', { name: /archiv (lesen|öffnen)|verwaltung/i })).toHaveCount(0)
})

test('completes every control by keyboard with a named screen reader label', async ({
  context,
  page,
}) => {
  await installOfflineGuard(context)
  await bootWriter(page)

  // Reine Tastatur: von der Adresse der Schale bis zum Abschluss, ohne einen
  // einzigen Zeigerklick.
  const reached: string[] = []
  for (let step = 0; step < 60; step += 1) {
    await page.keyboard.press('Tab')
    const focused = await page.evaluate(() => {
      const element = document.activeElement
      if (element === null || element === document.body) {
        return null
      }
      // Der zugaengliche NAME, und nicht bloss der Textinhalt: ein
      // Eingabefeld traegt seinen Namen ueber ein zugeordnetes `label`, und
      // ein Zeuge, der nur `textContent` liest, faende dort die leere
      // Zeichenkette (gemessen).
      const labelled = element as HTMLInputElement & { labels?: NodeListOf<HTMLLabelElement> }
      const fromLabel =
        labelled.labels === undefined || labelled.labels.length === 0
          ? null
          : (labelled.labels[0]?.textContent ?? '').trim()
      const describedBy = element.getAttribute('aria-labelledby')
      const fromDescription =
        describedBy === null
          ? null
          : (document.getElementById(describedBy)?.textContent ?? '').trim()
      const label =
        element.getAttribute('aria-label') ??
        fromLabel ??
        fromDescription ??
        element.getAttribute('title') ??
        (element.textContent ?? '').trim()
      const outline = window.getComputedStyle(element)
      return {
        tag: element.tagName.toLowerCase(),
        label,
        visibleFocus: outline.outlineStyle !== 'none' || outline.boxShadow !== 'none',
      }
    })
    if (focused === null) {
      continue
    }
    // Jede erreichbare Handhabe traegt einen NAMEN und einen sichtbaren Fokus.
    expect(focused.label, `${focused.tag} ohne zugaenglichen Namen`).not.toBe('')
    expect(focused.visibleFocus, `${focused.tag} ohne sichtbaren Fokus`).toBe(true)
    reached.push(focused.label)
  }
  expect(reached.length).toBeGreaterThan(5)
  expect(reached.some((label) => label.includes('Prüfen'))).toBe(true)

  // Und der Abschluss selbst geht per Tastatur.
  await page.getByRole('button', { name: 'Prüfen' }).focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('status', { name: 'Vertrauensbestand' })).toBeVisible()
  await page.getByRole('checkbox', { name: /unwiderruflich/i }).focus()
  await page.keyboard.press('Space')
  await page.getByRole('button', { name: 'Unwiderruflich finalisieren' }).focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('region', { name: 'Abschluss' })).toBeVisible()
})
