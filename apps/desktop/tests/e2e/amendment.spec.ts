import { expect, test } from '@playwright/test'
import { installOfflineGuard } from '../../playwright.config'

// UI/IPC witness only; Rust independently exercises the real native Writer.
test('imports, reviews and finalizes a structured amendment', async ({ context, page }) => {
  await installOfflineGuard(context)
  await page.addInitScript(() => {
    const invoked: string[] = []
    const sync = { status: 'lokal gesichert', detailCause: null }
    const resume = { phase: 'ReversibleDraft', irreversible: false, outcomeCode: 'NothingPending', outcomeSequence: null }
    const answers: Record<string, unknown> = {
      'plugin:event|listen': 0, 'plugin:event|unlisten': null,
      verified_session: { role: 'writer', capabilities: ['capture'] },
      startup_recovery: resume,
      writer_recover_pending: { resume, blockedCode: null, sync: null },
      draft_load_active: { incident: { humanIncidentNumber: '', occurredAt: { start: 0, end: null }, keyword: { referenceId: null, displayText: '' }, location: { freeText: '', address: null, coordinates: null }, personnel: [], personnelEmptyReason: null, vehicles: [], vehiclesEmptyReason: null, patientCountStatus: 'Unknown', patientCount: null, notes: null, externalOrganizations: [] }, sync },
      writer_preview_amendment: { proposedSequence: 7, bindsPredecessor: true, effectiveNow: 1771000100000, trustAgeMs: 3600000, readerTrustRefreshMs: 604800000, trustRefreshOverdue: false, staleDecision: 'Fresh' },
      draft_save_amendment: sync,
      session_reauthenticate: { fresh: true, purposeCode: 'EA-OPERATOR-REAUTH-FINALIZE' },
      writer_finalize_amendment: { sequence: 7, entryHash: '11'.repeat(32), objectHash: '22'.repeat(32), sync },
      archive_health_report: { healthy: true, findingCodes: [], quarantineReasons: [] },
      device_posture_report: { requirements: [], productionReady: false },
    }
    Object.defineProperty(window, '__TAURI_INTERNALS__', { value: {
      invoke(command: string, args?: Record<string, unknown>): Promise<unknown> {
        invoked.push(command)
        if (command === 'writer_amendment_import') return Promise.resolve({ reference: args?.reference, reason: '', changes: [{ fieldPath: '', changeText: '' }] })
        return command in answers ? Promise.resolve(answers[command]) : Promise.reject(new Error(command))
      },
      transformCallback(): number { return 1 }, unregisterCallback(): void {}, invokedCommands(): string[] { return invoked },
    } })
  })
  await page.goto('/')
  await page.getByRole('link', { name: /einsatz erfassen/i }).click()
  const reference = { originalRecordId: '01970000-0000-7000-8000-000000000001', originalEntryHash: '31'.repeat(32), originalSequence: 3 }
  await page.getByLabel('Korrekturreferenz aus dem Reader').fill(JSON.stringify(reference))
  await page.getByRole('button', { name: 'Nachtrag beginnen' }).click()
  await expect(page.getByRole('region', { name: 'Nachtragsentwurf' })).toContainText(reference.originalEntryHash)
  await expect(page.getByLabel('Einsatznummer')).toHaveCount(0)
  await page.getByLabel('Begründung des Nachtrags').fill('Patientenzahl berichtigen')
  await page.getByLabel('Feldpfad 1', { exact: true }).fill('patientCount')
  await page.getByLabel('Änderungstext 1', { exact: true }).fill('Zwei statt einer Person')
  await page.getByRole('button', { name: 'Entwurf speichern' }).click()
  await page.getByRole('button', { name: 'Prüfen', exact: true }).click()
  await expect(page.getByRole('region', { name: 'Prüfung' })).toContainText('Zwei statt einer Person')
  await page.getByRole('checkbox', { name: /unwiderruflich/i }).check()
  await page.getByRole('button', { name: 'Unwiderruflich finalisieren' }).click()
  await expect(page.getByRole('region', { name: 'Abschluss' })).toBeVisible()
  await expect(page.getByLabel('Begründung des Nachtrags')).toHaveCount(0)
  const calls = await page.evaluate(() => (window as unknown as { __TAURI_INTERNALS__: { invokedCommands(): string[] } }).__TAURI_INTERNALS__.invokedCommands())
  for (const command of ['writer_amendment_import', 'draft_save_amendment', 'writer_preview_amendment', 'writer_finalize_amendment']) expect(calls).toContain(command)
  expect(calls.indexOf('session_reauthenticate')).toBeLessThan(calls.indexOf('writer_finalize_amendment'))
  expect(calls).not.toContain('writer_finalize')
})
