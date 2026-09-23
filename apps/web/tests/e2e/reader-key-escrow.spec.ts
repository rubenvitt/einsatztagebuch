// Der BROWSERZEUGE der Escrow-Zeremonien (Escrow-Profil §5–§7, DRK-460).
//
// Echter Chromium, virtuelle PRF-Authenticators, die GEBAUTE Anwendung —
// und als Gegenseite der Rust-Peer, der den echten Oeffnungsdienst
// (`ea_recovery::ReaderKeyEscrowOpeningService`) ruft. Uebergaben laufen als
// DATEIEN (Ruling U3): Downloads der Seite gehen an den Peer, seine Dateien
// ueber `setInputFiles` zurueck.
//
// Vorbedingungen (laut, nicht still): `cargo run --locked -p xtask -- build-wasm`
// und `cargo build --locked -p ea-system-tests --example reader_key_escrow_browser_peer`.
import { mkdtempSync, readFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { expect, test } from '@playwright/test'
import type { CDPSession, Download, Page } from '@playwright/test'

import { WEBAUTHN_PREVIEW_ORIGIN } from '../../playwright.config'
import { FIRST_TRANSPORT, SECOND_TRANSPORT, VIRTUAL, completeTwoAuthenticatorEnrollment, stubEnrollmentEndpoints } from './support/enrollment'
import { filesIn, peer } from './support/escrow-peer'
import type { PeerReleaseContext } from './support/escrow-peer'

test.skip(({ browserName }) => browserName !== 'chromium')

/** Der KEM-Seed der Peer-Linie (`escrow_support::READER_KEM_SEED`). */
const PEER_KEM_SEED_HEX = 'b1'.repeat(32)

function workdir(): string {
  return mkdtempSync(path.join(os.tmpdir(), 'ea-escrow-e2e-'))
}

async function stageRelease(page: Page, context: PeerReleaseContext): Promise<void> {
  await page.addInitScript(value => {
    Object.defineProperty(globalThis, '__eaReaderEnrollmentContext', { value })
  }, {
    organizationId: context.organizationId,
    subjectId: context.subjectId,
    pinnedAnchor: context.pinnedAnchor,
    bundleFingerprint: '7e'.repeat(32),
    authority: 'sync.einsatzarchiv.example',
  })
}

async function twoAuthenticators(page: Page): Promise<{ cdp: CDPSession; ids: string[] }> {
  const cdp = await page.context().newCDPSession(page)
  await cdp.send('WebAuthn.enable')
  const first = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { ...VIRTUAL, transport: FIRST_TRANSPORT },
  })
  const second = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { ...VIRTUAL, transport: SECOND_TRANSPORT },
  })
  return { cdp, ids: [first.authenticatorId, second.authenticatorId] }
}

async function saved(download: Promise<Download>, directory: string): Promise<string> {
  const file = await download
  const target = path.join(directory, file.suggestedFilename())
  await file.saveAs(target)
  return target
}

/** Enrollment im Browser, entsperren, dann zur Hinterlegung — ohne Neuladen. */
async function enrolledOnEscrowPage(page: Page): Promise<void> {
  const release = peer<PeerReleaseContext>(['anchor'])
  const { cdp, ids } = await twoAuthenticators(page)
  await stubEnrollmentEndpoints(page)
  await stageRelease(page, release)
  await page.goto(`${WEBAUTHN_PREVIEW_ORIGIN}/enrollment`)
  // Erst wenn Rust das Enrollment begonnen hat, traegt die Seite eine Kennung.
  await expect(page.getByTestId('schluessel-fingerprint')).not.toBeEmpty()
  await completeTwoAuthenticatorEnrollment(page, cdp, ids)
  await page.getByRole('button', { name: 'Tresor entsperren' }).click()
  await expect(page.getByText('Tresor entsperrt.')).toBeVisible()
  await page.getByRole('link', { name: 'Schlüsselhinterlegung' }).click()
}

type OpfsFile = { readonly name: string; readonly hex: string }

/** Die rohen OPFS-Bytes, gelesen vom Hauptthread. */
async function opfsFiles(page: Page): Promise<OpfsFile[]> {
  return page.evaluate(async () => {
    type Entry = { kind: string; getFile?: () => Promise<File> }
    type Directory = Entry & { entries: () => AsyncIterable<[string, Entry]> }
    const found: { name: string; hex: string }[] = []
    const walk = async (directory: Directory, prefix: string): Promise<void> => {
      for await (const [name, entry] of directory.entries()) {
        if (entry.kind === 'directory') {
          await walk(entry as Directory, `${prefix}${name}/`)
        } else if (entry.getFile !== undefined) {
          const bytes = new Uint8Array(await (await entry.getFile()).arrayBuffer())
          found.push({
            name: `${prefix}${name}`,
            hex: Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join(''),
          })
        }
      }
    }
    await walk((await navigator.storage.getDirectory()) as unknown as Directory, '')
    return found
  })
}

test('ceremony A: a browser-enrolled vault seals a package the native side accepts', async ({ page }) => {
  const work = workdir()
  await enrolledOnEscrowPage(page)

  const requested = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Registrierungsantrag herunterladen' }).click()
  const request = await saved(requested, work)
  expect(path.basename(request)).toMatch(/^[0-9a-f]{64}\.registration\.cbor$/)

  const trust = path.join(work, 'trust')
  peer(['certify', request, trust])
  await page.getByLabel('Trust-Dateien wählen').setInputFiles(filesIn(trust))
  const packaged = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Hinterlegungspaket erzeugen' }).click()
  const escrowPackage = await saved(packaged, work)
  expect(path.basename(escrowPackage)).toMatch(/^[0-9a-f]{64}\.reader-key-escrow-package\.cbor$/)

  const checked = peer<{ ok: boolean; escrowCoreHash: string }>(['check-package', escrowPackage, request])
  expect(checked.ok).toBe(true)
  await expect(page.getByText(checked.escrowCoreHash)).toBeVisible()
})

test('ceremony A: a certificate with a foreign key yields no package and no download', async ({ page }) => {
  const work = workdir()
  await enrolledOnEscrowPage(page)
  const requested = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Registrierungsantrag herunterladen' }).click()
  const request = await saved(requested, work)

  const trust = path.join(work, 'trust')
  peer(['certify-foreign', request, trust])
  let downloads = 0
  page.on('download', () => {
    downloads += 1
  })
  await page.getByLabel('Trust-Dateien wählen').setInputFiles(filesIn(trust))
  await page.getByRole('button', { name: 'Hinterlegungspaket erzeugen' }).click()
  await expect(page.getByRole('alert').filter({ hasText: 'EA-TRUST-ESCROW-ENROLLMENT-MISMATCH' })).toBeVisible()
  expect(downloads).toBe(0)
})

type EscrowLineV1 = PeerReleaseContext & { readonly expectedKemFingerprint: string }

async function beganRestore(page: Page, work: string): Promise<{ line: EscrowLineV1; transport: string; state: string }> {
  const trust = path.join(work, 'trust')
  const state = path.join(work, 'state')
  const line = peer<EscrowLineV1>(['line-with-escrow', trust, state])
  await stageRelease(page, line)
  await page.goto(`${WEBAUTHN_PREVIEW_ORIGIN}/wiederherstellung`)
  await page.getByLabel('Trust-Dateien wählen').setInputFiles(filesIn(trust))
  const requested = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Wiederherstellung beginnen' }).click()
  const transport = await saved(requested, work)
  expect(path.basename(transport)).toMatch(/^[0-9a-f]{64}\.reader-key-escrow-transport\.cbor$/)
  await expect(page.getByLabel('Transport-Fingerprint')).toHaveText(/^[0-9a-f]{64}$/)
  return { line, transport, state }
}

test('ceremony B: the envelope opens once and a new vault is sealed locally with two authenticators', async ({ page }) => {
  const work = workdir()
  const { cdp, ids } = await twoAuthenticators(page)
  const { line, transport, state } = await beganRestore(page, work)
  const before = await opfsFiles(page)

  const envelope = path.join(work, 'envelope.cbor')
  peer(['open', transport, state, envelope])
  await page.getByLabel('Umschlag importieren').setInputFiles(envelope)
  await expect(page.getByText(line.expectedKemFingerprint).first()).toBeVisible()
  await expect(page.getByTestId('schluessel-fingerprint')).toHaveText(line.expectedKemFingerprint)
  // Vor dem Abschluss liegt kein Byte im lokalen Speicher: der Beginn des
  // Enrollments oeffnet den Tresorschluessel nur (leere Datei), geschrieben
  // wird erst beim lokalen Abschluss.
  for (const file of await opfsFiles(page)) {
    expect(file.hex, file.name).toBe('')
  }

  await completeTwoAuthenticatorEnrollment(page, cdp, ids)
  await page.getByRole('button', { name: 'Tresor entsperren' }).click()
  await expect(page.getByText('Tresor entsperrt.')).toBeVisible()

  // Kanarienvögel: der Reader-KEM steht weder im DOM noch in einer Datei
  // noch roh im lokalen Speicher; Browser-Speicher neben OPFS bleibt leer.
  const after = await opfsFiles(page)
  expect(before).toEqual([])
  expect(after.some(file => file.hex.length > 0)).toBe(true)
  expect(await page.content()).not.toContain(PEER_KEM_SEED_HEX)
  expect(readFileSync(transport).toString('hex')).not.toContain(PEER_KEM_SEED_HEX)
  for (const file of after) {
    expect(file.hex, file.name).not.toContain(PEER_KEM_SEED_HEX)
  }
  expect(await page.evaluate(() => localStorage.length)).toBe(0)
  expect(await page.evaluate(async () => (await indexedDB.databases()).length)).toBe(0)
})

test('ceremony B: a foreign envelope is refused, the transport is gone, and a reload leaves nothing to import', async ({ page }) => {
  const work = workdir()
  const { state } = await beganRestore(page, work)
  const foreign = path.join(work, 'foreign.cbor')
  peer(['open-foreign', state, foreign])
  await page.getByLabel('Umschlag importieren').setInputFiles(foreign)
  await expect(page.getByRole('alert').filter({ hasText: 'EA-READER-ESCROW-RESTORE-BINDING' })).toBeVisible()
  await page.getByLabel('Umschlag importieren').setInputFiles(foreign)
  await expect(page.getByRole('alert').filter({ hasText: 'EA-READER-ESCROW-BRIDGE-ARGUMENT' })).toBeVisible()

  await page.reload()
  await expect(page.getByLabel('Umschlag importieren')).toBeDisabled()
})
