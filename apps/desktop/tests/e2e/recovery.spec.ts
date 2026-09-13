import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import type { RecoveryAdministrationView } from '../../src/bridge/generated-contracts'
import { installOfflineGuard } from '../../playwright.config'

const operationId = '11'.repeat(16), runId = '22'.repeat(16), requestId = '33'.repeat(32)
const request = { runId, requestId, mediumIdHash: '44'.repeat(32), index: 1, total: 2,
  roleCode: 'root', certificateHash: '55'.repeat(32), expectedThumbprint: '66'.repeat(32),
  protectionCode: 2, testKindCode: 'signatureChallenge' }

/** Browser IPC witness only. Actual native execution is tested independently. */
async function host(page: Page, delayedInput = false, commitBeforeCancel = false) {
  let view: RecoveryAdministrationView = { lastSuccess: null, lastFailure: null, run: null }
  const inputs: unknown[] = []
  let release: (() => void) | undefined
  await page.exposeBinding('nativeRecoveryForTest', async (_, command: string, args: Record<string, unknown> = {}) => {
    if (command === 'verified_session') return { role: 'organizationadmin', capabilities: ['administration'] }
    if (command.startsWith('plugin:event|')) return 1
    if (command === 'startup_recovery') return { phase: 'ReversibleDraft', irreversible: false, outcomeCode: 'NothingPending', outcomeSequence: null }
    if (command === 'recovery_read') return view
    if (command === 'recovery_start') {
      expect(args).toEqual({})
      view = { ...view, run: { operationId, phaseCode: 1, request, observations: [], report: null, errorCode: null } }
      return view
    }
    if (command === 'recovery_submit') {
      inputs.push(args)
      expect(args).toEqual({ operationId, runId, requestId, choice: expect.any(Number) })
      expect([0, 1]).toContain(args.choice)
      const prior = view
      if (delayedInput) return new Promise<RecoveryAdministrationView>(resolve => { release = () => resolve(prior) })
      view = { ...view, run: { ...view.run!, request: { ...request, index: 2, requestId: '77'.repeat(32), mediumIdHash: '88'.repeat(32) },
        observations: [{ request, resultCode: args.choice === 0 ? 0 : 1,
          observedThumbprint: args.choice === 0 ? request.expectedThumbprint : null,
          errorCode: args.choice === 0 ? null : 'EA-RECOVERY-TEST-INCOMPLETE' }] } }
      return view
    }
    if (command === 'recovery_cancel') {
      expect(args).toEqual({ operationId })
      view = { ...view, run: { ...view.run!, phaseCode: commitBeforeCancel ? 7 : 5, request: null,
        errorCode: commitBeforeCancel ? null : 'EA-RECOVERY-TEST-CANCELLED' } }
      return view
    }
    throw new Error('EA-E2E-UNCONFIGURED-ADMINISTRATION')
  })
  await page.addInitScript(() => {
    const bridge = window as unknown as { nativeRecoveryForTest: (command: string, args?: unknown) => Promise<unknown> }
    Object.defineProperty(window, '__TAURI_INTERNALS__', { value: {
      invoke: (command: string, args?: unknown) => bridge.nativeRecoveryForTest(command, args),
      transformCallback: () => 1, unregisterCallback: () => {},
    } })
  })
  return { inputs, release: () => { release?.() }, finishCommitted: () => {
    const report = { completed: false, exactPublicReportJson: JSON.stringify({ schemaId: 'ea.recovery-test/v1',
      result: 'failed', testId: runId, sourceEnvelopeHash: 'aa'.repeat(32) }), envelopeHash: 'bb'.repeat(32),
      sourceEnvelopeHash: 'aa'.repeat(32), auditId: 'cc'.repeat(16), finishedAtMs: 1_700_000_000_000, nextDueAtMs: null }
    view = { ...view, lastFailure: report, run: { ...view.run!, phaseCode: 4, request: null, report, errorCode: null } }
  } }
}
async function open(page: Page) {
  await page.goto('/')
  await page.getByRole('link', { name: 'Verwaltung' }).click()
  await page.getByRole('button', { name: 'Recovery-Test starten' }).click()
  await expect(page.getByRole('heading', { name: 'Sicherung 1 von 2' })).toBeVisible()
}

test('keyboard input confirms only the requested medium and reload preserves native progress', async ({ context, page }) => {
  await installOfflineGuard(context)
  const fixture = await host(page)
  await open(page)
  expect(fixture.inputs).toHaveLength(0)
  await expect(page.getByText('Bestanden', { exact: true })).toHaveCount(0)
  await page.getByRole('button', { name: 'Bereitgestellte Sicherung prüfen' }).focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('heading', { name: 'Sicherung 2 von 2' })).toBeVisible()
  expect(fixture.inputs).toEqual([{ operationId, runId, requestId, choice: 0 }])
  await expect(page.getByText('Bestanden', { exact: true })).toBeVisible()
  await expect(page.getByText('Erfolgreich abgeschlossen', { exact: true })).toHaveCount(0)
  await page.reload()
  await page.getByRole('link', { name: 'Verwaltung' }).click()
  await expect(page.getByRole('heading', { name: 'Sicherung 2 von 2' })).toBeVisible()
  expect(fixture.inputs).toHaveLength(1)
})

test('missing medium stays explicit and the narrow window keeps input within the viewport', async ({ context, page }) => {
  await installOfflineGuard(context)
  await page.setViewportSize({ width: 640, height: 900 })
  const fixture = await host(page)
  await open(page)
  await page.getByRole('button', { name: 'Sicherung fehlt' }).click()
  await expect(page.getByText('Fehlt', { exact: true })).toBeVisible()
  await expect(page.getByText('Kein Schlüssel nachgewiesen', { exact: false })).toBeVisible()
  expect(fixture.inputs).toEqual([{ operationId, runId, requestId, choice: 1 }])
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(640)
  await page.screenshot({ path: test.info().outputPath('recovery-narrow.png'), fullPage: true })
})

test('cancellation remains available during native input and a late reply cannot reopen it', async ({ context, page }) => {
  await installOfflineGuard(context)
  const fixture = await host(page, true)
  await open(page)
  await page.getByRole('button', { name: 'Bereitgestellte Sicherung prüfen' }).click()
  await expect.poll(() => fixture.inputs.length).toBe(1)
  await page.getByRole('button', { name: 'Test abbrechen' }).click()
  const recovery = page.getByRole('region', { name: 'Recovery-Test', exact: true })
  await expect(recovery.getByRole('status')).toHaveText('Abgebrochen')
  fixture.release()
  await expect(page.getByRole('button', { name: 'Bereitgestellte Sicherung prüfen' })).toHaveCount(0)
  await expect(recovery.getByRole('status')).toHaveText('Abgebrochen')
  await expect(recovery.getByText('Nächster Test:', { exact: false })).toHaveCount(0)
})

test('requested cancellation stays pending until polling receives the already committed report', async ({ context, page }) => {
  await installOfflineGuard(context)
  const fixture = await host(page, false, true)
  await open(page)
  await page.getByRole('button', { name: 'Test abbrechen' }).click()
  const recovery = page.getByRole('region', { name: 'Recovery-Test', exact: true })
  await expect(recovery.getByRole('status')).toHaveText('Abbruch wird abgeschlossen')
  await expect(recovery.getByRole('button', { name: 'Test abbrechen' })).toBeDisabled()
  await expect(recovery.getByRole('button', { name: 'Recovery-Test starten' })).toHaveCount(0)
  fixture.finishCommitted()
  await expect(recovery.getByRole('status')).toHaveText('Mit Fehlerbericht abgeschlossen')
  await expect(recovery.getByText('bb'.repeat(32))).toBeVisible()
  await expect(recovery.getByRole('button', { name: 'Recovery-Test starten' })).toBeEnabled()
})

test('renders the exact completed sixteen-medium native Host witness and retains both report histories after reload', async ({ context, page }) => {
  await installOfflineGuard(context)
  const exact = await readFile(new URL('../../../../docs/traceability/artifacts/drk-250-native-desktop-recovery-v4.json', import.meta.url))
  expect(createHash('sha256').update(exact).digest('hex')).toBe('dd4fd0b87f50313ff936c9773e7e08b14ecb70cb9c6459c77fdb973e1d142988')
  const captured = JSON.parse(exact.toString()) as RecoveryAdministrationView
  const actions: string[] = []
  await page.exposeBinding('nativeCapturedRecovery', (_, command: string) => {
    if (command === 'verified_session') return { role: 'organizationadmin', capabilities: ['administration'] }
    if (command.startsWith('plugin:event|')) return 1
    if (command === 'recovery_read') return captured
    if (command.startsWith('recovery_')) actions.push(command)
    throw { code: 'EA-TEST-UNAVAILABLE' }
  })
  await page.addInitScript(() => {
    const bridge = window as unknown as { nativeCapturedRecovery: (command: string) => Promise<unknown> }
    Object.defineProperty(window, '__TAURI_INTERNALS__', { value: {
      invoke: (command: string) => bridge.nativeCapturedRecovery(command),
      transformCallback: () => 1, unregisterCallback: () => {},
    } })
  })
  for (const reload of [false, true]) {
    if (reload) await page.reload()
    else await page.goto('/')
    await page.getByRole('link', { name: 'Verwaltung' }).click()
    const recovery = page.getByRole('region', { name: 'Recovery-Test', exact: true })
    await expect(recovery.getByRole('status')).toHaveText('Erfolgreich abgeschlossen')
    await expect(recovery.getByText('Bestanden', { exact: true })).toHaveCount(16)
    await expect(recovery.getByText(captured.lastSuccess!.envelopeHash, { exact: true })).toBeVisible()
    await expect(recovery.getByText(captured.lastFailure!.envelopeHash, { exact: true })).toBeVisible()
    await expect(recovery.getByText('Nächster Test:', { exact: false })).toBeVisible()
    expect(actions).toEqual([])
  }
})
