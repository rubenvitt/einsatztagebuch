// Die BROWSERMATRIX nach `web-reader-design.md` §11.4: derselbe eingefrorene
// Bestand, derselbe Verifikationskern, drei Engines — und GENAU EIN
// Literalwert, gegen den jede Engine ihren Bericht misst.
//
// Die Aussage ist: der Kern ist geteilter Rust-Code, uebersetzt nach
// `wasm32-unknown-unknown`, also DARF sich sein Bericht zwischen Chromium,
// Firefox und WebKit nicht unterscheiden. Taete er es, waere Wirtsverhalten in
// den Kern gelaufen. `webkit` ist Playwrights WebKit-Bau und NICHT Safari.
//
// # Warum dieser Lauf NICHT durch die Oberflaeche geht — gemessen
//
// Der Plan skizziert `openPinnedBundle(page)` und drei Testkennungen
// (`report-hash`, `verification-status`, `server-confirmation`). Im Baum gibt
// es davon nur `server-confirmation` und `verification-summary`
// (`src/features/file-mode/OpenArchivePanel.tsx`), und der Oeffnungsweg der
// Flaeche laeuft ueber `readerSession()` in
// `src/features/file-mode/DirectoryHandle.ts` — eine WebAuthn-PRF-Zeremonie,
// die in Playwright nur ueber `WebAuthn.addVirtualAuthenticator` (CDP, also
// nur Chromium) fuehrbar ist. Ein UI-Lauf koennte die Gleichheit auf Firefox
// und WebKit deshalb nie zeigen.
//
// Dieser Zeuge spricht darum den GEBAUTEN Worker der Anwendung direkt an:
// `dist/assets/opfs-worker-<hash>.js` ist derselbe Modulworker, den
// `src/vault/webauthn-prf.ts` startet, mit demselben wasm-Modul unter
// derselben CSP (`worker-src 'self'`, `script-src 'wasm-unsafe-eval'`). Drei
// seiner Nachrichten reichen: `vault-unlock` ist reines Rust
// (`readerVaultUnlock` in `crates/ea-reader-wasm/src/vault_bridge.rs`) und
// braucht KEINEN Authenticator, nur den versiegelten Tresor, die
// `credentialId` und die rohe PRF-Ausgabe; `file-mode-open-bundle` faehrt
// `ReaderFileMode::open_bundle_observed` — alle neun Gates —, und
// `reader-stand-view` gibt den Bestand als `ReaderStandView` heraus.
//
// # Woher die eingefrorenen Bytes stammen
//
// Alle drei Dateien sind aus der Kulisse
// `crates/ea-reader/tests/verify_fixtures/fixtures.rs` gezogen, OHNE eine
// Rust-Datei des Baums zu aendern (ein Wegwerf-Binary ausserhalb des Baums hat
// das Modul per `#[path]` eingebunden und die Werte geschrieben):
//
// - `fixtures/sealed-vault.hex`: `ReaderVault::seal` ueber DENSELBEN Inhalt
//   wie `unlocked_vault_with_pinned_anchor()` (KEM-Seed
//   `complete_recipient_secret_bytes()`, Audit-Seed `[0x52; 32]`, Anker
//   `complete_archive_anchor_bytes()`), Entsperrweg `VAULT_CREDENTIAL_ID_V1`
//   = `ea-reader-verify-passkey` mit `VAULT_PRF_OUTPUT_V1` = `[0xa1; 32]`.
// - `fixtures/complete-archive.eabundle.hex`:
//   `exported_bundle_bytes(complete_archive_with_a_genesis_plaintext())` — der
//   EINZIGE Bestand der Kulisse mit schemagueltigem Klartext, also der, dessen
//   Eintrag auf `verifiziert` steht und nicht auf `nicht darstellbares Schema`.
// - `fixtures/complete-archive-stand-view.json`: `view::stand_json` ueber
//   genau diesem Bestand, auf dem WIRT gerechnet (nativ, nicht wasm). Der
//   Literalwert unten ist sein SHA-256; jede Engine muss ihn treffen, und
//   damit trifft sie auch die native Rechnung. Sein `incident: null` ist eine
//   Aussage ueber DIESEN Bestand: `file-mode-open-bundle` entschluesselt
//   zwar (`view::build_stand`), aber der eine Eintrag traegt den
//   Genesis-Klartext und keine Einsatznutzlast, also gibt es nichts
//   Fachliches auszuweisen (`crates/ea-reader-wasm/src/view.rs`,
//   „`incident: null` ist eine Aussage"). Eine Neuerzeugung ueber einem
//   Bestand MIT Einsatznutzlast froere Einsatznummer, Stichwort und Zeit als
//   fachlichen Klartext in eine eingecheckte Datei ein und DARF NICHT
//   committet werden.
//
// Die wirksame Zeit ist `fixtures::EFFECTIVE_NOW` =
// `verify_support::FIXTURE_OS_WALL_CLOCK_V1` = 800 ms — NICHT frei waehlbar,
// Gate `registry` misst gegen das Fenster der Fixture-Koepfe.
//
// # Was hier ausdruecklich NICHT bezeugt wird
//
// Kein Enrollment und kein Fingerprintnachweis auf Firefox und WebKit — CDP,
// siehe `enrollment.spec.ts`. Keine Mindestversionen je Plattform
// (`web-reader-design.md` §14, offener Punkt 3, Stufe 7).
import { createHash } from 'node:crypto'
import { readdirSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'

const here = path.dirname(fileURLToPath(import.meta.url))
const fixtureRoot = path.join(here, 'fixtures')
const distAssets = path.join(here, '..', '..', 'dist', 'assets')

/**
 * Der EINE Literalwert: SHA-256 (hex) ueber die `ReaderStandView`-JSON, die der
 * Wirt nativ ueber den eingefrorenen Bestand gerechnet hat.
 */
const FROZEN_STAND_VIEW_SHA256 = '32348bced6752b87372f67085341f16b3c1fc988a1e1988784182c12fb38425a'

/** `fixtures::EFFECTIVE_NOW` — siehe Kopf. */
const EFFECTIVE_NOW_MS = 800
/** `VAULT_CREDENTIAL_ID_V1` der Kulisse. */
const CREDENTIAL_ID = 'ea-reader-verify-passkey'
/** `VAULT_PRF_OUTPUT_V1` der Kulisse: 32 Bytes `0xa1`. */
const PRF_OUTPUT = new Uint8Array(32).fill(0xa1)

/**
 * Der Bericht des Datei-Modus, wie ihn der Wirt nativ ueber denselben Bytes
 * gerechnet hat — als Objekt, damit ein abweichendes Feld beim Namen faellt.
 */
const FROZEN_FILE_MODE_VIEW = {
  archiveObjectCount: 15,
  entryPackageCount: 1,
  fullyVerified: true,
  gapCount: 0,
  serverConfirmedCount: 0,
  notServerConfirmedCount: 1,
  serverConfirmation: 'nicht server-bestätigt',
} as const

/**
 * Der Bericht ueber DENSELBEN Bestand mit EINEM gekippten Byte im
 * Einsatzpaket — gemessen auf Chromium und als Literal gepinnt, damit auch
 * der Fehlschlag auf jeder Engine derselbe ist.
 *
 * Der Kern faellt dabei NICHT mit einem Code der Bruecke: ein unlesbares
 * Paket ist ein Pruefproblem DES BESTANDS (`ungültig`, `EA-FORMAT-SHAPE` an
 * Gate `format`), das Paket verschwindet aus `entries`, und ein zweites
 * Objekt steht ohne Detailcode daneben. Der erste Objekthash ist der der
 * GEKIPPTEN Bytes, deshalb weicht er von jedem Hash des heilen Bestands ab.
 */
const FROZEN_FLIPPED_FILE_MODE_VIEW = {
  archiveObjectCount: 15,
  entryPackageCount: 0,
  fullyVerified: false,
  gapCount: 0,
  serverConfirmedCount: 0,
  notServerConfirmedCount: 0,
  serverConfirmation: 'nicht server-bestätigt',
} as const
const FROZEN_FLIPPED_STAND_VIEW = {
  entries: [],
  problems: [
    {
      objectHash: '1d807b9a47ee5aaeccc5c40ffc9e18f05dd7b392c8eff43be7eb2b3656ea312f',
      verification: 'ungültig',
      detailCode: 'EA-FORMAT-SHAPE',
    },
    {
      objectHash: '6bc9a0d690d46a9d8adb602dd14828494cd775d1a90d732d0911785a1ef6d51d',
      verification: 'ungültig',
      detailCode: null,
    },
  ],
  chain: [{ label: 'format', verified: false, detail: 'EA-FORMAT-SHAPE' }],
  fullyVerified: false,
  serverConfirmation: 'nicht server-bestätigt',
} as const

/** Die Engine-Achse der Matrix, in der Reihenfolge von `playwright.config.ts`. */
const MATRIX_ENGINES = ['chromium', 'firefox', 'webkit'] as const

function bytesFromHexFile(name: string): Uint8Array {
  const hex = readFileSync(path.join(fixtureRoot, name), 'utf8').trim()
  const bytes = new Uint8Array(hex.length / 2)
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}

/**
 * Ein Byte MITTEN im ersten Blob des Containers.
 *
 * Containerform (`crates/ea-archive/src/bundle.rs`): 32 Bytes Magic, u64
 * Blobzahl, u64 Indexlaenge, der Index, dann die Nutzlasten in Indexfolge.
 * Der erste Indexeintrag ist `u16 Pfadlaenge, Pfad, u64 Offset, u64 Laenge`;
 * gelesen wird er hier, damit die Kontrolle nicht auf einem abgeschriebenen
 * Offset steht. Der erste Blob MUSS das Einsatzpaket sein — sonst misst die
 * Kontrolle ein anderes Objekt als sie behauptet.
 */
function entryPackageOffset(bundle: Uint8Array): number {
  const view = new DataView(bundle.buffer, bundle.byteOffset, bundle.byteLength)
  const indexLength = Number(view.getBigUint64(40))
  const pathLength = view.getUint16(48)
  const firstPath = new TextDecoder().decode(bundle.subarray(50, 50 + pathLength))
  expect(firstPath).toBe('entries/000000000000_entry.eip')
  const firstOffset = Number(view.getBigUint64(50 + pathLength))
  const firstLength = Number(view.getBigUint64(58 + pathLength))
  expect(firstOffset).toBe(0)
  expect(firstLength).toBeGreaterThan(0)
  return 48 + indexLength + firstOffset + Math.floor(firstLength / 2)
}

function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex')
}

/**
 * Der Pfad des GEBAUTEN Workers unter der Vorschau.
 *
 * Vite schreibt ihn als `assets/opfs-worker-<hash>.js` (gemessen:
 * `opfs-worker-C6EOk47k.js`); der Hash wechselt mit jedem Bau, deshalb wird
 * das Verzeichnis gelesen statt ein Name geraten. GENAU EIN Treffer — zwei
 * hiessen, dass zwei Fassungen desselben Workers ausgeliefert wuerden.
 */
function builtWorkerPath(): string {
  const matches = readdirSync(distAssets).filter(name => /^opfs-worker-[^.]+\.js$/.test(name))
  expect(matches, `genau ein gebauter Worker unter ${distAssets}`).toHaveLength(1)
  return `/assets/${matches[0] ?? ''}`
}

/** Die Antwort des Workers, so wie `src/bridge/opfs-worker.ts` sie formt. */
type WorkerReply =
  | { readonly id: number; readonly ok: true; readonly status?: string }
  | { readonly id: number; readonly ok: false; readonly code: string }

type KernelRun = {
  readonly fileModeView: string
  readonly standView: string
  readonly flippedFileModeView: string
  readonly flippedStandView: string
}

/**
 * Faehrt den Kern im GEBAUTEN Worker: Tresor entsperren, Buendel oeffnen,
 * Bestand abfragen — und denselben Bestand mit EINEM gekippten Byte ein
 * zweites Mal, als Negativkontrolle.
 */
async function runKernel(
  page: Page,
  workerPath: string,
  bundle: Uint8Array,
  eipOffset: number,
): Promise<KernelRun> {
  return page.evaluate(
    async ({ workerPath, sealed, bundle, eipOffset, credentialId, prfOutput, effectiveNowMs }) => {
      const worker = new Worker(workerPath, { type: 'module' })
      let nextId = 1
      const call = (request: Record<string, unknown>): Promise<WorkerReply> =>
        new Promise((resolve, reject) => {
          const id = nextId
          nextId += 1
          const onMessage = (event: MessageEvent<WorkerReply>) => {
            if (event.data.id !== id) {
              return
            }
            worker.removeEventListener('message', onMessage)
            resolve(event.data)
          }
          worker.addEventListener('message', onMessage)
          worker.addEventListener(
            'error',
            event => reject(new Error(`Worker-Fehler: ${event.message}`)),
            { once: true },
          )
          worker.postMessage({ id, ...request })
        })
      const must = (reply: WorkerReply, what: string): string => {
        if (!reply.ok) {
          throw new Error(`${what}: ${reply.code}`)
        }
        if (reply.status === undefined) {
          throw new Error(`${what}: keine Antwort`)
        }
        return reply.status
      }

      const session = Number(
        must(
          await call({
            kind: 'vault-unlock',
            sealed,
            credentialId: new TextEncoder().encode(credentialId),
            prfOutput,
            // Dieselbe Uhr wie das Oeffnen darunter: seit der Sitzungssperre
            // eroeffnet `vault-unlock` eine `ReaderSession` und setzt damit
            // die Untaetigkeitsfrist, die `ReaderSession::state_at` bei jedem
            // Zugriff nachrechnet. Ein Entsperren zur Wirtszeit und ein
            // Oeffnen zu `effectiveNowMs` lagen fuenf Minuten auseinander und
            // faenden eine gesperrte Sitzung.
            nowMs: effectiveNowMs,
          }),
          'vault-unlock',
        ),
      )
      const fileModeView = must(
        await call({
          kind: 'file-mode-open-bundle',
          session,
          bytes: bundle,
          effectiveNowMs: BigInt(effectiveNowMs),
        }),
        'file-mode-open-bundle',
      )
      const standView = must(await call({ kind: 'reader-stand-view' }), 'reader-stand-view')

      // Negativkontrolle: EIN Byte im Einsatzpaket gekippt. Das Paket ist der
      // erste Blob des Containers (`entries/000000000000_entry.eip`, Index
      // sortiert nach Adressbytes); `eipOffset` zeigt in seine Nutzlast.
      // Das letzte Byte des Containers taugt NICHT: es liegt in einem
      // Registry-Ereignis, das die Aufloesung nicht auswaehlt, und der Bericht
      // blieb dort gemessen unveraendert.
      const flipped = new Uint8Array(bundle)
      flipped[eipOffset] = (flipped[eipOffset] ?? 0) ^ 0x01
      const rejected = await call({
        kind: 'file-mode-open-bundle',
        session,
        bytes: flipped,
        effectiveNowMs: BigInt(effectiveNowMs),
      })
      if (!rejected.ok) {
        throw new Error(`file-mode-open-bundle ueber dem gekippten Byte: ${rejected.code}`)
      }
      const flippedFileModeView = rejected.status ?? ''
      const flippedStandView = must(await call({ kind: 'reader-stand-view' }), 'reader-stand-view')
      worker.terminate()
      return { fileModeView, standView, flippedFileModeView, flippedStandView }
    },
    {
      workerPath,
      sealed: bytesFromHexFile('sealed-vault.hex'),
      bundle,
      eipOffset,
      credentialId: CREDENTIAL_ID,
      prfOutput: PRF_OUTPUT,
      effectiveNowMs: EFFECTIVE_NOW_MS,
    },
  )
}

// Der wasm-Bau ist 7,9 MB; Firefox und WebKit brauchen fuer Laden und
// Instanziieren im Worker spuerbar laenger als Chromium. Gemessen liegt der
// ganze Lauf unter 20 s; 90 s ist die Frist, unter der ein Haengen trotzdem
// auffaellt.
test.setTimeout(90_000)

test('the same frozen archive verifies to the same report on every engine of the matrix', async ({
  page,
  browserName,
}) => {
  // ANTI-LEERLAUF 1: der Lauf faehrt WIRKLICH in einer Engine der Matrix, und
  // das Projekt, unter dem er laeuft, traegt ihren Namen.
  expect(MATRIX_ENGINES).toContain(browserName)
  expect(test.info().project.name).toBe(browserName)

  // ANTI-LEERLAUF 2: die eingefrorene Referenz trifft den Literalwert. Wer die
  // Datei austauscht, ohne den Wert zu bewegen, faellt HIER und nicht erst an
  // der Engine.
  const frozenStandView = readFileSync(
    path.join(fixtureRoot, 'complete-archive-stand-view.json'),
    'utf8',
  ).trim()
  expect(sha256Hex(frozenStandView)).toBe(FROZEN_STAND_VIEW_SHA256)

  const pageErrors: string[] = []
  page.on('pageerror', error => pageErrors.push(String(error)))

  // Die GEBAUTE Anwendung unter ihrer CSP, in dieser Engine: die Route
  // montiert und der universelle Weg steht.
  await page.goto('/datei')
  await expect(page.getByLabel('Archivdatei öffnen')).toHaveAttribute('type', 'file')

  const bundle = bytesFromHexFile('complete-archive.eabundle.hex')
  const run = await runKernel(page, builtWorkerPath(), bundle, entryPackageOffset(bundle))

  // Der Bericht des Datei-Modus, Feld fuer Feld gegen die native Rechnung.
  expect(JSON.parse(run.fileModeView)).toEqual(FROZEN_FILE_MODE_VIEW)

  // Der Bestand: BYTEGLEICH zur nativen Rechnung, und sein Hash ist der EINE
  // Literalwert. Die zwei Zeilen tragen dieselbe Aussage — die erste nennt
  // beim Abweichen das Feld, die zweite ist der Wert, den der Gate-Bericht
  // zitiert.
  expect(run.standView).toBe(frozenStandView)
  expect(sha256Hex(run.standView)).toBe(FROZEN_STAND_VIEW_SHA256)

  // Und das, was der Wert bedeutet, ausgeschrieben: ein Eintrag, verifiziert,
  // neun Gate-Knoten, alle bestanden, nicht server-bestaetigt — der Regelfall
  // des Datei-Modus, kein Mangel.
  const stand = JSON.parse(run.standView) as {
    entries: readonly { state: { verification: string; serverConfirmation: string } }[]
    problems: readonly unknown[]
    chain: readonly { verified: boolean }[]
    fullyVerified: boolean
    serverConfirmation: string
  }
  expect(stand.entries.map(entry => entry.state.verification)).toEqual(['verifiziert'])
  expect(stand.problems).toEqual([])
  expect(stand.chain).toHaveLength(9)
  expect(stand.chain.every(node => node.verified)).toBe(true)
  expect(stand.fullyVerified).toBe(true)
  expect(stand.serverConfirmation).toBe('nicht server-bestätigt')

  // ANTI-LEERLAUF 3: der Kern hat die BYTES gelesen. Ein gekipptes Byte im
  // Einsatzpaket aendert den Bericht — und der GEAENDERTE Bericht ist auf
  // jeder Engine derselbe. Ein Kern, der nur ein Literal zurueckgaebe, koennte
  // beides nicht.
  expect(JSON.parse(run.flippedFileModeView)).toEqual(FROZEN_FLIPPED_FILE_MODE_VIEW)
  expect(JSON.parse(run.flippedStandView)).toEqual(FROZEN_FLIPPED_STAND_VIEW)
  expect(run.flippedStandView).not.toBe(run.standView)

  expect(pageErrors, `Unbehandelte Ausnahmen: ${pageErrors.join(' | ')}`).toEqual([])
})

/**
 * Die Faehigkeit, die den universellen Weg noetig macht, JE ENGINE als
 * gemessene Tatsache: `showDirectoryPicker` gibt es in Chromium und in keiner
 * der zwei anderen Engines. `file-mode.spec.ts` konnte das mit einem Projekt
 * nur fuer Chromium sagen; hier steht die Tabelle.
 */
const DIRECTORY_PICKER_BY_ENGINE: Record<(typeof MATRIX_ENGINES)[number], boolean> = {
  chromium: true,
  firefox: false,
  webkit: false,
}

test('offers the universal file input on every engine and the directory picker only where the engine has it', async ({
  page,
  browserName,
}) => {
  expect(MATRIX_ENGINES).toContain(browserName)
  const expectedPicker = DIRECTORY_PICKER_BY_ENGINE[browserName]

  await page.goto('/datei')
  const universal = page.getByLabel('Archivdatei öffnen')
  await expect(universal).toBeVisible()
  await expect(universal).toBeEnabled()
  await expect(universal).toHaveAttribute('type', 'file')

  // Die Tatsache selbst, gemessen an der Engine …
  expect(await page.evaluate(() => 'showDirectoryPicker' in window)).toBe(expectedPicker)
  // … und die Flaeche folgt ihr: der Komfortweg steht GENAU dort, wo die
  // Faehigkeit ist, und nirgends sonst.
  await expect(page.getByRole('button', { name: 'Archivordner verbinden' })).toHaveCount(
    expectedPicker ? 1 : 0,
  )
  await expect(page.getByRole('alert')).toHaveCount(0)
})
