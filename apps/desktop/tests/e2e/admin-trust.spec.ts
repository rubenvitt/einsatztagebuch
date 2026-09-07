import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'

import { installOfflineGuard } from '../../playwright.config'

/** Die gepruefte Sitzung, die das Wirtsdoppel meldet. */
type SessionDouble = { readonly role: string; readonly capabilities: readonly string[] }

const ADMIN_SESSION: SessionDouble = { role: 'organizationadmin', capabilities: ['administration'] }
const WRITER_SESSION: SessionDouble = { role: 'writer', capabilities: ['capture'] }

/** 32 Paare Gross-Hex — die Form aus `ea_admin::fingerprint`. */
const FINGERPRINT = Array.from({ length: 32 }, (_, index) =>
  ((index * 11 + 5) % 256).toString(16).padStart(2, '0').toUpperCase(),
).join(':')

/**
 * Das Wirtsdoppel der Verwaltung — als Init-Skript des TESTS, mit demselben
 * Griff wie `writer-offline.spec.ts`: `@tauri-apps/api` ruft ausschliesslich
 * `window.__TAURI_INTERNALS__.invoke`, und der Test besetzt diese Naht, bevor
 * das erste Modul laeuft. Ein Testschalter IN der Anwendung waere eine
 * verbotene lokale Konfigurationsquelle (`AppShell.test.tsx`).
 *
 * Die Zeremonie ist ZUSTAND: jedes Kommando schreibt den Schritt um genau eine
 * Position fort, und ein gemeldeter Fingerprint, der nicht der Zielfingerprint
 * ist, wird mit dem Kerncode abgelehnt. Die Antworten sind die DRAHTFORM
 * (`camelCase`, nackte Ziffern, Variantennamen der Aufzaehlungen).
 */
const HOST_DOUBLE = String(function installHostDouble(
  session: SessionDouble,
  fingerprint: string,
): void {
  const invoked: string[] = []
  const goLiveCodes = [
    'EA-GOLIVE-TWO-ADMINS',
    'EA-GOLIVE-KEY-BACKUP-ROOT',
    'EA-GOLIVE-KEY-BACKUP-ADMIN',
    'EA-GOLIVE-KEY-BACKUP-RECOVERY-KEM',
    'EA-GOLIVE-KEY-BACKUP-HGA',
    'EA-GOLIVE-REGISTRY-AGE',
    'EA-GOLIVE-REGISTRY-LEASE',
    'EA-GOLIVE-POLICY',
    'EA-GOLIVE-EVIDENCE-POLICY',
    'EA-GOLIVE-RECOVERY-TEST',
    'EA-GOLIVE-WRITER-TRANSITION',
    'EA-POSTURE-FULL-DISK-ENCRYPTION',
    'EA-POSTURE-ACCOUNT-EXCLUSIVE',
    'EA-POSTURE-SCREEN-LOCK',
    'EA-POSTURE-OS-PATCH-LEVEL',
  ]
  const day = 24 * 60 * 60 * 1000
  let ceremonyKind = 'DeviceApprove'
  let ceremonyStep = 'PendingRequest'
  let exchangeFileName: string | null = null
  const ceremony = () => ({
    ceremonyId: 'zeremonie-1',
    kind: ceremonyKind,
    step: ceremonyStep,
    targetFingerprint: ceremonyKind === 'DeviceApprove' ? fingerprint : null,
    exchangeFileName,
  })
  // Jedes Zeremoniekommando nach dem Beginn traegt die Kennung der EINEN
  // laufenden Zeremonie unter dem Namen des Kontrakts (`ceremonyId`). Ein
  // umbenanntes Feld in `connectAdminBridge` faellt hier, nicht erst am Wirt.
  const requireCeremonyId = (args: { ceremonyId?: unknown }) => {
    if (args.ceremonyId !== 'zeremonie-1') {
      throw { code: 'EA-E2E-MISSING-ARG' }
    }
  }
  const advance = (step: string) => (args: { ceremonyId?: unknown }) => {
    requireCeremonyId(args)
    ceremonyStep = step
    return ceremony()
  }
  const answers: Record<string, unknown> = {
    'plugin:event|listen': 0,
    'plugin:event|unlisten': null,
    verified_session: session,
    startup_recovery: {
      phase: 'ReversibleDraft',
      irreversible: false,
      outcomeCode: 'NothingPending',
      outcomeSequence: null,
    },
    session_reauthenticate: (args: { purpose: string }) => ({
      fresh: true,
      purposeCode: `EA-OPERATOR-REAUTH-${args.purpose}`,
    }),
    device_posture_report: {
      requirements: [
        {
          requirementCode: 'EA-POSTURE-FULL-DISK-ENCRYPTION',
          satisfied: null,
          evidenceCode: 'EA-POSTURE-FDE-UNREPORTABLE',
        },
      ],
      productionReady: false,
    },
    admin_pending_device_requests: [
      {
        requestId: 'anfrage-1',
        certificateKindCode: 'EA-CERT-READER-DEVICE',
        fingerprint,
        receivedAtMs: 1771000000000,
      },
    ],
    admin_ceremony_begin: (args: { requestId: string; kind: string }) => {
      ceremonyKind = args.kind
      ceremonyStep = 'PendingRequest'
      exchangeFileName = null
      return ceremony()
    },
    admin_ceremony_confirm_fingerprint: (args: {
      ceremonyId?: unknown
      reportedFingerprint: string
    }) => {
      requireCeremonyId(args)
      if (args.reportedFingerprint.toUpperCase() !== fingerprint) {
        throw { code: 'EA-WORKFLOW-FINGERPRINT-MISMATCH' }
      }
      ceremonyStep = 'FingerprintConfirmed'
      return ceremony()
    },
    admin_ceremony_authorize: advance('AdminAuthorized'),
    admin_ceremony_export_request: (args: { ceremonyId?: unknown }) => {
      requireCeremonyId(args)
      exchangeFileName = 'root-anfrage-0001.json'
      ceremonyStep = 'RootRequestExported'
      return ceremony()
    },
    admin_ceremony_import_reply: advance('RootReplyImported'),
    admin_ceremony_publish: advance('RegistryPublished'),
    admin_policy_profile: {
      operatingProfile: 0,
      maxRegistryAgeMs: 7 * day,
      maxFutureClockSkewMs: 300000,
      registryExpiryBehavior: 0,
      evidenceMaxDelayMs: 12 * 60 * 60 * 1000,
      readerInactivityMs: 600000,
      readerTrustRefreshMs: day,
      readerHistoryAccessAllowed: false,
      backupFrequencyMs: day,
      restoreTestIntervalMs: 90 * day,
      minimumRetentionMs: 3650 * day,
      destructionEnabled: false,
      effectiveFromSequence: 12,
      leaseValidThroughSequence: 120,
      notAfterMs: 1771600000000,
    },
    admin_registry_health: {
      registryVersion: 4,
      headHash: 'CC'.repeat(32),
      registryAgeMs: 2 * day,
      maxRegistryAgeMs: 7 * day,
      leaseValidThroughSequence: 120,
      nextSequence: 87,
      notAfterMs: 1771600000000,
      staleDecision: 'Fresh',
    },
    admin_go_live_checklist: {
      requirements: goLiveCodes.map((code) =>
        code === 'EA-GOLIVE-RECOVERY-TEST'
          ? {
              requirementCode: code,
              status: 'NotAutomaticallyVerifiable',
              evidenceCode: 'EA-GOLIVE-EVIDENCE-UNAVAILABLE',
            }
          : { requirementCode: code, status: 'Confirmed', evidenceCode: `${code}-EVIDENCE` },
      ),
      productionReady: false,
    },
    admin_go_live_export_unresolved:
      '{"format":"ea.go-live-checklist/v1","unresolved":["EA-GOLIVE-RECOVERY-TEST"]}',
    admin_clock_release_offer: {
      availability: 'NotBlocked',
      floorMs: null,
      observedWallClockMs: null,
      maxFutureClockSkewMs: null,
      expiresAtMs: null,
      justifications: [],
    },
    admin_clock_release_issue: (args: { justification?: unknown }) => {
      if (typeof args.justification !== 'string') {
        throw { code: 'EA-E2E-MISSING-ARG' }
      }
      throw { code: 'EA-SKEW-NOT-BLOCKED' }
    },
    admin_writer_transition_state: {
      phase: 'NoTransition',
      currentWriterHash: 'AA'.repeat(32),
      newWriterHash: null,
      effectiveFromSequence: null,
    },
    admin_writer_transition_prepare: (args: { requestJson?: unknown }) => {
      if (typeof args.requestJson !== 'string' || args.requestJson === '') {
        throw { code: 'EA-E2E-MISSING-ARG' }
      }
      return {
        phase: 'Prepared',
        currentWriterHash: 'AA'.repeat(32),
        newWriterHash: 'BB'.repeat(32),
        effectiveFromSequence: 88,
      }
    },
    admin_writer_transition_activate: {
      phase: 'Activated',
      currentWriterHash: 'BB'.repeat(32),
      newWriterHash: null,
      effectiveFromSequence: 88,
    },
    admin_revocation_effect: (args: { targetHash: string }) => ({
      targetClass: 'NonAdminDevice',
      targetHash: args.targetHash,
      stopsNewGrantsFromSequence: 91,
      recallsIssuedGrants: false,
      recallsDecryptedPlaintext: false,
    }),
  }
  const host = {
    invoke(command: string, args: unknown): Promise<unknown> {
      invoked.push(command)
      if (!(command in answers)) {
        return Promise.reject(new Error(`EA-E2E-UNKNOWN-COMMAND:${command}`))
      }
      const answer = answers[command]
      try {
        return Promise.resolve(
          typeof answer === 'function' ? (answer as (given: unknown) => unknown)(args) : answer,
        )
      } catch (refusal) {
        return Promise.reject(refusal)
      }
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

async function bootSession(page: Page, session: SessionDouble): Promise<void> {
  await page.addInitScript(
    `(${HOST_DOUBLE})(${JSON.stringify(session)}, ${JSON.stringify(FINGERPRINT)})`,
  )
  await page.goto('/')
}

async function bootAdmin(page: Page): Promise<void> {
  await bootSession(page, ADMIN_SESSION)
  await page.getByRole('link', { name: 'Verwaltung' }).click()
  await expect(page.getByRole('region', { name: 'Go-live-Status' })).toBeVisible()
}

async function invokedCommands(page: Page): Promise<string[]> {
  return page.evaluate(() =>
    (
      window as unknown as { __TAURI_INTERNALS__: { invokedCommands: () => string[] } }
    ).__TAURI_INTERNALS__.invokedCommands(),
  )
}

test('shows the eight regions and walks a device approval to an active device', async ({
  context,
  page,
}) => {
  await installOfflineGuard(context)
  await bootAdmin(page)

  for (const name of [
    'Go-live-Status',
    'Geräteanfragen',
    'Registry',
    'Richtlinie',
    'Writer-Wechsel',
    'Zeitfreigabe',
    'Gerätehaltung',
    'Widerruf',
  ]) {
    await expect(page.getByRole('region', { name })).toBeVisible()
  }
  await expect(page.getByRole('status', { name: 'Go-live-Bereitschaft' })).toHaveText(
    'nicht produktionsbereit',
  )
  await expect(page.getByText('nicht automatisch prüfbar')).toBeVisible()

  const requests = page.getByRole('region', { name: 'Geräteanfragen' })
  await expect(requests.getByText('Anfrage ausstehend')).toBeVisible()
  await requests.getByRole('button', { name: 'Fingerprint vergleichen' }).click()

  // Volltext UND QR-Code gleichzeitig (design.md:1925), durch die echte
  // IPC-Vermittlung der Schale.
  await expect(requests.getByLabel('Vollständiger Fingerprint')).toHaveText(FINGERPRINT)
  await expect(
    requests.getByRole('img', { name: 'QR-Code des vollständigen Fingerprints' }),
  ).toBeVisible()
  await expect(page.getByText('Gerät aktiv')).toHaveCount(0)

  await requests.getByLabel('Über den zweiten Kanal gemeldeter Fingerprint').fill(FINGERPRINT)
  await requests.getByRole('button', { name: 'Fingerprint bestätigen' }).click()
  await expect(requests.getByRole('heading', { level: 4 })).toContainText('Fingerprint bestätigt')
  await requests.getByRole('button', { name: 'Neu anmelden und autorisieren' }).click()
  await expect(requests.getByRole('heading', { level: 4 })).toContainText(
    'Admin-Autorisierung erteilt',
  )
  await requests.getByRole('button', { name: 'Root-Anfrage exportieren' }).click()
  await expect(requests.getByText(/root-anfrage-0001\.json/)).toBeVisible()
  await requests.getByRole('button', { name: 'Root-Antwort importieren' }).click()
  await expect(page.getByText('Gerät aktiv')).toHaveCount(0)
  await requests.getByRole('button', { name: 'Neu anmelden und veröffentlichen' }).click()
  await expect(requests.getByRole('heading', { level: 4 })).toContainText('Gerät aktiv')

  const invoked = await invokedCommands(page)
  expect(invoked.filter((command) => command === 'session_reauthenticate')).toHaveLength(2)
  expect(invoked).toContain('admin_ceremony_publish')
})

test('reaches no reader or writer function from the administration', async ({ context, page }) => {
  await installOfflineGuard(context)
  await bootAdmin(page)

  await expect(
    page.getByRole('link', { name: /einsatz erfassen|archiv (lesen|öffnen)|verlauf/i }),
  ).toHaveCount(0)
  await expect(
    page.getByRole('button', { name: /einsatz|verlauf|entschlüsseln|inhalt öffnen/i }),
  ).toHaveCount(0)
  await expect(page.getByText('Einsatznummer')).toHaveCount(0)

  const invoked = await invokedCommands(page)
  // Ohne diese Zusicherung laeuft die Schleife darunter ueber die leere Menge.
  expect(invoked.length).toBeGreaterThan(5)
  for (const command of invoked) {
    expect(command).not.toMatch(/decrypt|history|entry|content|read/)
  }
})

test('completes every control by keyboard with a named screen reader label', async ({
  context,
  page,
}) => {
  await installOfflineGuard(context)
  await bootAdmin(page)
  await page.getByRole('button', { name: 'Fingerprint vergleichen' }).click()
  await expect(page.getByRole('img', { name: 'QR-Code des vollständigen Fingerprints' })).toBeVisible()

  const reached: string[] = []
  for (let step = 0; step < 80; step += 1) {
    await page.keyboard.press('Tab')
    const focused = await page.evaluate(() => {
      const element = document.activeElement
      if (element === null || element === document.body) {
        return null
      }
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
    expect(focused.label, `${focused.tag} ohne zugaenglichen Namen`).not.toBe('')
    expect(focused.visibleFocus, `${focused.tag} ohne sichtbaren Fokus`).toBe(true)
    reached.push(focused.label)
  }
  expect(reached.length).toBeGreaterThan(5)
  // Die beiden Bestaetigungsknoepfe stehen hier NICHT: sie sind ohne Eingabe
  // deaktiviert und damit kein Tabstopp. Erreichbar sind ihre Eingabefelder.
  expect(reached.some((label) => label.includes('Über den zweiten Kanal gemeldeter Fingerprint'))).toBe(true)
  expect(reached.some((label) => label.includes('Zielhash'))).toBe(true)
  expect(reached.some((label) => label.includes('Offene Punkte exportieren'))).toBe(true)

  // Und der Fingerprint-Schritt selbst geht per Tastatur.
  await page.getByLabel('Über den zweiten Kanal gemeldeter Fingerprint').focus()
  await page.keyboard.type(FINGERPRINT)
  await page.getByRole('button', { name: 'Fingerprint bestätigen' }).focus()
  await page.keyboard.press('Enter')
  const heading = page.getByRole('region', { name: 'Geräteanfragen' }).getByRole('heading', { level: 4 })
  await expect(heading).toContainText('Fingerprint bestätigt')
  await expect(heading).toBeFocused()
})

// Die andere Richtung derselben Grenze, neben `writer-offline.spec.ts:173`: die
// Writer-Sitzung bekommt keinen Verweis auf die Verwaltung.
test('shows no administration link to a writer session', async ({ context, page }) => {
  await installOfflineGuard(context)
  await bootSession(page, WRITER_SESSION)
  await expect(page.getByRole('link', { name: 'Einsatz erfassen' })).toBeVisible()
  await expect(page.getByRole('link', { name: /verwaltung|administration/i })).toHaveCount(0)
  await expect(page.getByRole('region', { name: 'Verwaltung' })).toHaveCount(0)
})
