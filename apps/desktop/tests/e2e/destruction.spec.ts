import { expect, test } from '@playwright/test'
import { readFile } from 'node:fs/promises'
import type { Page } from '@playwright/test'
import { installOfflineGuard } from '../../playwright.config'

const ID = '11'.repeat(16)
const JOB = '22'.repeat(32)
type ProcessState = 'requested' | 'inProgress' | 'pendingBackupExpiry' | 'incompleteUnreachableReplica'

/** Browser boundary double only; actual native execution has a separate CLI witness. */
async function host(page: Page, initial: ProcessState | null = null, privacy = true, server = false, offer = false): Promise<string[]> {
  let saved = initial
  const invoked: string[] = []
  const view = () => ({
    privacyDecisionEnabled: privacy, policyHash: '33'.repeat(32),
    knownDestructionIds: saved === null ? [] : [ID],
    process: saved === null ? null : {
      destructionId: ID, authorizationObjectHash: '44'.repeat(32), state: saved,
      // `offer`: the custodian Writer succeeded with a verified stub (host view double only).
      scopeCode: 1, legalReasonCode: 2, controllerDeviceId: '55'.repeat(16), custodianDeviceId: (offer ? 'aa' : '66').repeat(16),
      approverCertificateHashes: ['77'.repeat(32), '88'.repeat(32)],
      targets: [{ entryHash: '99'.repeat(32), chainSequence: 7, stubObjectHash: offer ? 'ab'.repeat(32) : null }],
      evidenceEntryHash: null,
      preflight: { jobHash: JOB, exactCanonicalReportJson: JSON.stringify({ knownReplicaCount: server ? 3 : 2 }), knownReplicaCount: server ? 3 : 2 },
      replicas: [
        { deviceId: 'aa'.repeat(16), kindCode: 0, attestationHash: 'bb'.repeat(32), resultCode: 0, backupExpiryAt: null },
        { deviceId: 'cc'.repeat(16), kindCode: 1, attestationHash: saved === 'requested' ? null : 'dd'.repeat(32),
          resultCode: saved === 'requested' ? null : saved === 'incompleteUnreachableReplica' ? 2 : 1,
          backupExpiryAt: saved === 'requested' ? null : 915_148_800_000 },
        ...(server ? [{ deviceId: 'ee'.repeat(16), kindCode: 2, attestationHash: null, resultCode: null, backupExpiryAt: null }] : []),
      ],
    },
  })
  await page.exposeBinding('nativeDestructionForTest', async (_, command: string, args: Record<string, unknown> = {}) => {
    invoked.push(command)
    if (command === 'verified_session') return { role: 'organizationadmin', capabilities: ['administration'] }
    if (command.startsWith('plugin:event|')) return 1
    if (command === 'startup_recovery') return { phase: 'ReversibleDraft', irreversible: false, outcomeCode: 'NothingPending', outcomeSequence: null }
    if (command === 'destruction_read') {
      expect(args.destructionId === null || args.destructionId === ID).toBeTruthy()
      return view()
    }
    if (command === 'destruction_prepare') {
      expect(args).toEqual({ exactAuthorization: [0, 255, 3] })
      expect(privacy).toBeTruthy()
      saved = 'requested'
      return view()
    }
    if (command === 'destruction_start') {
      expect(args).toEqual({ destructionId: ID, expectedPreflightHash: JOB })
      saved = 'inProgress'
      return view()
    }
    if (command === 'destruction_export_reader_delivery') {
      expect(args).toEqual({ destructionId: ID, expectedPreflightHash: JOB, readerId: 'cc'.repeat(16) })
      return { destructionId: ID, jobHash: JOB, readerId: 'cc'.repeat(16),
        exactAuthorization: [0, 255, 1], exactInitiatingEvent: [2, 0, 3], exactJobUpload: [4, 5, 255] }
    }
    if (command === 'destruction_import_progress') {
      expect(args).toEqual({ destructionId: ID, expectedPreflightHash: JOB, exactEtbObjects: [[255, 0], [1, 2, 3]] })
      saved = 'pendingBackupExpiry'
      return view()
    }
    if (command === 'destruction_resume') {
      expect(args).toEqual({ destructionId: ID })
      // Ruling G2: resume in state4 chains the native retry; the Reader case is refused, never idle.
      if (saved === 'incompleteUnreachableReplica') throw { code: 'EA-DESTRUCTION-RETRY-READER-DUTY' }
      return view()
    }
    if (command === 'destruction_authenticate_custodian') {
      expect(args).toEqual({ destructionId: ID, expectedPreflightHash: JOB })
      return view()
    }
    if (command === 'destruction_synchronize' && server) {
      expect(args).toEqual({ destructionId: ID, expectedPreflightHash: JOB })
      saved = 'pendingBackupExpiry'
      return view()
    }
    if (command === 'destruction_mark_incomplete' && offer) {
      expect(args).toEqual({ destructionId: ID, expectedPreflightHash: JOB })
      saved = 'incompleteUnreachableReplica'
      return view()
    }
    throw new Error('EA-E2E-UNCONFIGURED-ADMINISTRATION')
  })
  await page.addInitScript(() => {
    const bridge = window as unknown as { nativeDestructionForTest: (command: string, args?: unknown) => Promise<unknown> }
    Object.defineProperty(window, '__TAURI_INTERNALS__', { value: {
      invoke: (command: string, args?: unknown) => bridge.nativeDestructionForTest(command, args),
      transformCallback: () => 1, unregisterCallback: () => {},
    } })
  })
  return invoked
}
async function open(page: Page): Promise<void> {
  await page.goto('/')
  await page.getByRole('link', { name: 'Verwaltung' }).click()
  await expect(page.getByRole('region', { name: 'Kontrollierte Vernichtung' })).toBeVisible()
}

test('explicit custodian login preserves progress and requires a separate resume action', async ({ context, page }) => {
  await installOfflineGuard(context)
  const invoked = await host(page, 'inProgress')
  await open(page)
  expect(invoked).not.toContain('destruction_authenticate_custodian')
  await page.getByRole('button', { name: 'Ausführendes Writer-Gerät anmelden' }).click()
  await expect(page.getByRole('button', { name: 'Vernichtung fortsetzen' })).toBeEnabled()
  expect(invoked.filter((command) => command === 'destruction_authenticate_custodian')).toHaveLength(1)
  expect(invoked).not.toContain('destruction_resume')
  expect(invoked).not.toContain('destruction_start')
  await expect(page.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveText('in Bearbeitung')
  await page.getByRole('button', { name: 'Vernichtung fortsetzen' }).click()
  expect(invoked.filter((command) => command === 'destruction_resume')).toHaveLength(1)
  await page.reload()
  await page.getByRole('link', { name: 'Verwaltung' }).click()
  await expect(page.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveText('in Bearbeitung')
  expect(invoked.filter((command) => command === 'destruction_authenticate_custodian')).toHaveLength(1)
})

test('explicit server synchronization uses its own command and retains the returned report after reload', async ({ context, page }) => {
  await installOfflineGuard(context)
  const invoked = await host(page, 'inProgress', true, true)
  await open(page)
  await page.getByRole('button', { name: 'Servernachweise abgleichen' }).click()
  await expect(page.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveText('wartet auf Backup-Frist')
  expect(invoked.filter((command) => command === 'destruction_synchronize')).toHaveLength(1)
  expect(invoked).not.toContain('destruction_start')
  expect(invoked).not.toContain('destruction_resume')
  await page.reload()
  await page.getByRole('link', { name: 'Verwaltung' }).click()
  await expect(page.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveText('wartet auf Backup-Frist')
})

test('explicit final incomplete action needs its own confirmation and the host state survives reload', async ({ context, page }) => {
  await installOfflineGuard(context)
  const invoked = await host(page, 'inProgress', true, false, true)
  await open(page)
  const action = page.getByRole('button', { name: 'Als unvollständig abschließen' })
  await action.click()
  const dialog = page.getByRole('dialog')
  await expect(dialog).toContainText('Für nicht erreichbare Lesegeräte ist dieser Schritt endgültig')
  const confirm = dialog.getByRole('button', { name: 'Als unvollständig abschließen' })
  await expect(confirm).toBeDisabled()
  await dialog.getByRole('button', { name: 'Zurück' }).click()
  await expect(dialog).toBeHidden()
  expect(invoked).not.toContain('destruction_mark_incomplete')
  await action.click()
  await dialog.getByRole('checkbox', { name: 'Ich habe verstanden, dass dieser Abschluss keine Löschung bestätigt und für nicht erreichbare Lesegeräte endgültig ist.' }).check()
  await confirm.click()
  await expect(page.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveText('bekannte Replik nicht erreichbar')
  expect(invoked.filter((command) => command === 'destruction_mark_incomplete')).toHaveLength(1)
  expect(invoked).not.toContain('destruction_resume')
  await expect(action).toHaveCount(0)
  await page.reload()
  await page.getByRole('link', { name: 'Verwaltung' }).click()
  await expect(page.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveText('bekannte Replik nicht erreichbar')
  await expect(page.getByRole('button', { name: 'Als unvollständig abschließen' })).toHaveCount(0)
})

test('keyboard confirmation starts the exact imported process once and reload restores it', async ({ context, page }) => {
  await installOfflineGuard(context)
  const invoked = await host(page)
  await open(page)
  await page.getByLabel('Signierte Vernichtungsautorisierung').setInputFiles({ name: 'authorization.etb', mimeType: 'application/octet-stream', buffer: Buffer.from([0, 255, 3]) })
  await page.getByRole('button', { name: 'Vernichtung beantragen' }).click()
  const consent = page.getByRole('checkbox', { name: /Ich bestätige.*unwiderruflich/ })
  await expect(page.getByRole('button', { name: 'Unwiderruflich starten' })).toBeDisabled()
  await consent.focus()
  await page.keyboard.press('Space')
  await page.keyboard.press('Tab')
  await expect(page.getByRole('button', { name: 'Unwiderruflich starten' })).toBeFocused()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveText('in Bearbeitung')
  expect(invoked.filter((command) => command === 'destruction_start')).toHaveLength(1)
  await page.reload()
  await page.getByRole('link', { name: 'Verwaltung' }).click()
  await expect(page.getByLabel('Gespeicherter Vernichtungsvorgang')).toHaveValue(ID)
  await expect(page.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveText('in Bearbeitung')
  await expect(page.getByRole('button', { name: /abbrechen|unwiderruflich starten/i })).toHaveCount(0)
})

for (const [state, copy] of [
  ['pendingBackupExpiry', 'wartet auf Backup-Frist'],
  ['incompleteUnreachableReplica', 'bekannte Replik nicht erreichbar'],
] as const) {
  test(`${state} preserves the actual host status despite an old backup deadline`, async ({ context, page }) => {
    await installOfflineGuard(context)
    await host(page, state)
    await open(page)
    await expect(page.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveText(copy)
    await expect(page.getByRole('table', { name: 'Verwaltete Repliken' }).locator('time')).toHaveAttribute('datetime', '1999-01-01T00:00:00.000Z')
    await page.getByRole('button', { name: 'Vernichtung fortsetzen' }).click()
    if (state === 'incompleteUnreachableReplica') {
      const refusal = page.getByRole('region', { name: 'Kontrollierte Vernichtung' }).getByRole('alert')
      await expect(refusal).toContainText('Die fehlende Löschbestätigung betrifft ein Lesegerät.')
      await expect(refusal).toContainText('EA-DESTRUCTION-RETRY-READER-DUTY')
    }
    await expect(page.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveText(copy)
    await page.reload()
    await page.getByRole('link', { name: 'Verwaltung' }).click()
    await expect(page.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveText(copy)
    await expect(page.getByText(/Unbekannte Exporte, Screenshots/)).toBeVisible()
  })
}

test('missing privacy approval keeps the file import closed', async ({ context, page }) => {
  await installOfflineGuard(context)
  const invoked = await host(page, null, false)
  await open(page)
  await expect(page.getByLabel('Signierte Vernichtungsautorisierung')).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Vernichtung beantragen' })).toBeDisabled()
  expect(invoked).not.toContain('destruction_prepare')
})

test('narrow window keeps the workflow visible and contains the replica table', async ({ context, page }) => {
  await installOfflineGuard(context)
  await page.setViewportSize({ width: 640, height: 900 })
  await host(page, 'pendingBackupExpiry')
  await open(page)
  const region = page.getByRole('region', { name: 'Kontrollierte Vernichtung' })
  await expect(region).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(640)
  const overlap = await page.evaluate(() => {
    const header = document.querySelector('header')!
    const navigation = document.querySelector('nav')!
    const children = Array.from(header.querySelectorAll('p, span')).map((node) => node.getBoundingClientRect().bottom)
    return Math.max(header.getBoundingClientRect().bottom, ...children) > navigation.getBoundingClientRect().top
  })
  expect(overlap, 'header and trust observation must stay above navigation').toBe(false)
  await page.screenshot({ path: test.info().outputPath('destruction-narrow.png'), fullPage: true })
})


test('signed progress files carry exact bytes and the returned state survives reload', async ({ context, page }) => {
  await installOfflineGuard(context)
  const invoked = await host(page, 'inProgress')
  await open(page)
  const submit = page.getByRole('button', { name: 'Signierte Nachweise importieren' })
  await expect(submit).toBeDisabled()
  await page.getByLabel('Signierte Repliknachweise oder Statusereignisse').setInputFiles([
    { name: 'attestation.etb', mimeType: 'application/octet-stream', buffer: Buffer.from([255, 0]) },
    { name: 'event.etb', mimeType: 'application/octet-stream', buffer: Buffer.from([1, 2, 3]) },
  ])
  await submit.click()
  await expect(page.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveText('wartet auf Backup-Frist')
  expect(invoked.filter((command) => command === 'destruction_import_progress')).toHaveLength(1)
  await expect(page.getByText('Ein finalisierter Vernichtungsnachweis ist noch nicht nachgewiesen.')).toBeVisible()
  await page.reload()
  await page.getByRole('link', { name: 'Verwaltung' }).click()
  await expect(page.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveText('wartet auf Backup-Frist')
  await page.getByRole('button', { name: 'Weitere Autorisierung importieren' }).click()
  await expect(page.getByLabel('Signierte Vernichtungsautorisierung')).toBeEnabled()
  await expect(page.getByLabel('Signierte Repliknachweise oder Statusereignisse')).toHaveCount(0)
  await page.getByLabel('Gespeicherter Vernichtungsvorgang').selectOption(ID)
  await expect(page.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveText('wartet auf Backup-Frist')
})


test('Reader handoff saves three exact original files without advancing destruction', async ({ context, page }) => {
  await installOfflineGuard(context)
  const invoked = await host(page, 'inProgress')
  await open(page)
  const section = page.getByRole('region', { name: 'Auftrag an Lesegerät übergeben' })
  expect(invoked).not.toContain('destruction_export_reader_delivery')
  await expect(section.getByRole('button', { name: 'Dateien für Lesegerät bereitstellen' })).toBeDisabled()
  await section.getByRole('combobox').selectOption('cc'.repeat(16))
  await section.getByRole('button', { name: 'Dateien für Lesegerät bereitstellen' }).click()
  await expect(section.getByRole('status')).toContainText('Dateien stehen bereit')
  for (const [label, suffix, bytes] of [
    ['Autorisierung speichern', 'authorization.etb', [0, 255, 1]],
    ['Startnachweis speichern', 'started.etb', [2, 0, 3]],
    ['Auftragsdatei speichern', 'job-upload.cbor', [4, 5, 255]],
  ] as const) {
    const received = page.waitForEvent('download')
    await section.getByRole('link', { name: label }).click()
    const download = await received
    expect(download.suggestedFilename()).toBe(`${ID}-${'cc'.repeat(16)}-${suffix}`)
    expect(await download.failure()).toBeNull()
    const path = await download.path()
    expect(path).not.toBeNull()
    expect(Array.from(await readFile(path!))).toEqual(bytes)
  }
  expect(invoked.filter((command) => command === 'destruction_export_reader_delivery')).toHaveLength(1)
  expect(invoked).not.toContain('destruction_start')
  expect(invoked).not.toContain('destruction_resume')
  expect(invoked).not.toContain('destruction_import_progress')
  await expect(page.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveText('in Bearbeitung')
  await page.reload()
  await page.getByRole('link', { name: 'Verwaltung' }).click()
  await expect(page.getByRole('region', { name: 'Auftrag an Lesegerät übergeben' }).getByRole('link')).toHaveCount(0)
})
