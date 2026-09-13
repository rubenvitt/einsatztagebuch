import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { installOfflineGuard } from '../../playwright.config'

// UI/IPC witness only; Rust independently exercises the real native Writer.
// The double never decides whether a reference is genuine: a refusal is what
// the native `writer_amendment_import` returns (ea-writer
// `caller_record_id_cannot_forge_an_original_link`), and these cases prove only
// that the built UI surfaces it and opens no draft on the caller's word.
type HostMode = 'accept' | 'refuse'

async function installHost(context: BrowserContext, page: Page, mode: HostMode): Promise<void> {
  await installOfflineGuard(context)
  await page.addInitScript((hostMode: HostMode) => {
    const invoked: string[] = []
    const finalized: unknown[] = []
    let sequence = 7
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
      archive_health_report: { healthy: true, findingCodes: [], quarantineReasons: [] },
      device_posture_report: { requirements: [], productionReady: false },
    }
    Object.defineProperty(window, '__TAURI_INTERNALS__', { value: {
      invoke(command: string, args?: Record<string, unknown>): Promise<unknown> {
        invoked.push(command)
        if (command === 'writer_amendment_import') {
          return hostMode === 'refuse'
            ? Promise.reject({ code: 'EA-WRITER-ORIGINAL-IDENTITY-MISMATCH' })
            : Promise.resolve({ reference: args?.reference, reason: '', changes: [{ fieldPath: '', changeText: '' }] })
        }
        if (command === 'writer_finalize_amendment') {
          finalized.push(args?.amendment)
          const own = sequence++
          return Promise.resolve({ sequence: own, entryHash: String(own).padStart(2, '0').repeat(32), objectHash: '22'.repeat(32), sync })
        }
        return command in answers ? Promise.resolve(answers[command]) : Promise.reject(new Error(command))
      },
      transformCallback(): number { return 1 }, unregisterCallback(): void {},
      invokedCommands(): string[] { return invoked }, finalizedAmendments(): unknown[] { return finalized },
    } })
  }, mode)
}

type Host = { invokedCommands(): string[], finalizedAmendments(): unknown[] }
const invokedCommands = (page: Page): Promise<string[]> =>
  page.evaluate(() => (window as unknown as { __TAURI_INTERNALS__: Host }).__TAURI_INTERNALS__.invokedCommands())
const finalizedAmendments = (page: Page): Promise<unknown[]> =>
  page.evaluate(() => (window as unknown as { __TAURI_INTERNALS__: Host }).__TAURI_INTERNALS__.finalizedAmendments())

const reference = { originalRecordId: '01970000-0000-7000-8000-000000000001', originalEntryHash: '31'.repeat(32), originalSequence: 3 }

test('imports, reviews and finalizes a structured amendment', async ({ context, page }) => {
  await installHost(context, page, 'accept')
  await page.goto('/')
  await page.getByRole('link', { name: /einsatz erfassen/i }).click()
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
  const calls = await invokedCommands(page)
  for (const command of ['writer_amendment_import', 'draft_save_amendment', 'writer_preview_amendment', 'writer_finalize_amendment']) expect(calls).toContain(command)
  expect(calls.indexOf('session_reauthenticate')).toBeLessThan(calls.indexOf('writer_finalize_amendment'))
  expect(calls).not.toContain('writer_finalize')
})

test('an unreadable or refused reference opens no amendment draft', async ({ context, page }) => {
  await installHost(context, page, 'refuse')
  await page.goto('/')
  await page.getByRole('link', { name: /einsatz erfassen/i }).click()
  const field = page.getByLabel('Korrekturreferenz aus dem Reader')
  const begin = page.getByRole('button', { name: 'Nachtrag beginnen' })

  // Free text naming the original is not a reference, and neither is a
  // triple with an impossible sequence: neither reaches the host.
  for (const text of ['Einsatz 2026-0001, Sequenz 3, bitte korrigieren', JSON.stringify({ ...reference, originalSequence: -1 })]) {
    await field.fill(text)
    await begin.click()
    await expect(page.getByRole('alert').filter({ hasText: 'Die Korrekturreferenz ist nicht lesbar.' })).toBeVisible()
    await expect(page.getByRole('region', { name: 'Nachtragsentwurf' })).toHaveCount(0)
  }
  expect(await invokedCommands(page)).not.toContain('writer_amendment_import')

  // A well-formed but forged triple is sent, refused by the host, and the
  // refusal is shown; the UI does not open a draft for the caller's reference.
  await field.fill(JSON.stringify({ ...reference, originalEntryHash: '32'.repeat(32) }))
  await begin.click()
  await expect(page.getByRole('alert').filter({ hasText: 'Die Originalreferenz wurde abgelehnt. EA-WRITER-ORIGINAL-IDENTITY-MISMATCH' })).toBeVisible()
  await expect(page.getByRole('region', { name: 'Nachtragsentwurf' })).toHaveCount(0)
  await expect(page.getByLabel('Begründung des Nachtrags')).toHaveCount(0)
  const calls = await invokedCommands(page)
  expect(calls.filter(command => command === 'writer_amendment_import')).toHaveLength(1)
  for (const command of ['draft_save_amendment', 'writer_preview_amendment', 'writer_finalize_amendment']) expect(calls).not.toContain(command)
})

test('two amendments to one original are finalized as separate entries with their own content', async ({ context, page }) => {
  await installHost(context, page, 'accept')
  await page.goto('/')
  await page.getByRole('link', { name: /einsatz erfassen/i }).click()

  const amend = async (reason: string, changes: ReadonlyArray<readonly [string, string]>): Promise<void> => {
    await page.getByLabel('Korrekturreferenz aus dem Reader').fill(JSON.stringify(reference))
    await page.getByRole('button', { name: 'Nachtrag beginnen' }).click()
    await expect(page.getByRole('region', { name: 'Nachtragsentwurf' })).toContainText(reference.originalEntryHash)
    await page.getByLabel('Begründung des Nachtrags').fill(reason)
    for (const [index, [path, text]] of changes.entries()) {
      if (index > 0) await page.getByRole('button', { name: 'Weitere Änderung' }).click()
      await page.getByLabel(`Feldpfad ${index + 1}`, { exact: true }).fill(path)
      await page.getByLabel(`Änderungstext ${index + 1}`, { exact: true }).fill(text)
    }
    await page.getByRole('button', { name: 'Prüfen', exact: true }).click()
    for (const [, text] of changes) await expect(page.getByRole('region', { name: 'Prüfung' })).toContainText(text)
    await page.getByRole('checkbox', { name: /unwiderruflich/i }).check()
    await page.getByRole('button', { name: 'Unwiderruflich finalisieren' }).click()
    await expect(page.getByRole('region', { name: 'Abschluss' })).toBeVisible()
  }

  await amend('Patientenzahl berichtigen', [['patientCount', 'Zwei statt einer Person'], ['notes', 'Nachalarmierung ergänzt']])
  await expect(page.getByRole('region', { name: 'Abschluss' })).toContainText('07'.repeat(32))
  await amend('Einsatzort präzisieren', [['location.freeText', 'Hauptstraße 5 statt 3']])
  await expect(page.getByRole('region', { name: 'Abschluss' })).toContainText('08'.repeat(32))

  expect(await finalizedAmendments(page)).toEqual([
    { reference, reason: 'Patientenzahl berichtigen', changes: [
      { fieldPath: 'patientCount', changeText: 'Zwei statt einer Person' },
      { fieldPath: 'notes', changeText: 'Nachalarmierung ergänzt' },
    ] },
    { reference, reason: 'Einsatzort präzisieren', changes: [
      { fieldPath: 'location.freeText', changeText: 'Hauptstraße 5 statt 3' },
    ] },
  ])
  const calls = await invokedCommands(page)
  expect(calls.filter(command => command === 'writer_amendment_import')).toHaveLength(2)
  expect(calls).not.toContain('writer_finalize')
})
