// Der BROWSERZEUGE der Reader-Flaeche unter `/`.
//
// Gemessen wird, was nur ein echter Browser messen kann: dass die Route in der
// GEBAUTEN Anwendung montiert, dass der permanente Pruefstand TEXT traegt,
// dass die Flaeche bedienbar bleibt, waehrend die Bruecke noch nicht antwortet,
// und dass jede Bedienung per Tastatur mit SICHTBAREM Fokus erreichbar ist.
//
// # Der „simulierte Sync" ist eine simulierte BRUECKENLATENZ
//
// `apps/web` traegt keinen Sync-Treiber (gemessen im Plan zu Task 13:
// `transport.ts` stellt `sendReaderSyncRequest` bereit, `main.tsx` ruft es
// nirgends). Was die Flaeche waehrend eines Sync erlebt, ist eine Bruecke, die
// nicht antwortet — und genau das stellt `page.route` her: das wasm-Modul des
// dedizierten Workers wird ZURUECKGEHALTEN, jede Reader-Nachricht wartet im
// Worker hinter `ready`, und die Flaeche muss trotzdem bedienbar sein.
//
// # Was OHNE geoeffneten Bestand auf `/` steht — und was NICHT
//
// `ReaderPage` rendert die drei Reiter (`Einsätze`, `Prüfprobleme`,
// `Technik`), die `Integritätskette` und die `Suche` NUR ueber einem
// geoeffneten Bestand. Der entsteht im Datei-Modus, und der braucht eine
// entsperrte Tresorsitzung (`readerSession()` in `DirectoryHandle.ts` fuehrt
// eine WebAuthn-PRF-Zeremonie) und ein signiertes Archiv. Beides ist die Tiefe
// von `enrollment.spec.ts`, nicht dieses Zeugen. Auf `/` steht in dieser Lage
// der TECHNISCHE Zustand „Kein Bestand geöffnet" — und die Zeugen unten
// halten ausdruecklich fest, dass dort KEIN Reiter und KEINE Suche steht,
// damit ein spaeterer Lauf ueber einem Bestand die Reiter-Tastatur als
// bewusste Erweiterung nachtraegt und nicht als Nebeneffekt.
//
// # Alle drei Engines — mit EINER gemessenen Ausnahme
//
// Die Zeugen dieser Datei brauchen weder WebAuthn noch CDP und laufen in
// `chromium`, `firefox` und `webkit`. Ausnahme ist der Tastaturlauf: in
// Headless-Firefox verlaesst der Fokus das Dokument nach dem letzten
// fokussierbaren Element NICHT (gemessen: `Tab` springt wieder auf den ersten
// Verweis, der Lauf zaehlt fuenf Treffer bei vier Elementen), waehrend
// Chromium und WebKit den Fokus an den Browser abgeben und der Zyklus dort
// endet. Der Lauf ist deshalb dort uebersprungen, mit diesem Grund.
import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'


/** Der permanente Pruefstand — `<section aria-label="Prüfstand">`. */
function verificationStatus(page: Page) {
  return page.getByRole('region', { name: 'Prüfstand' })
}

/**
 * Sammelt UNBEHANDELTE Ausnahmen der Seite.
 *
 * `pageerror` und nicht `console`: die Schale meldet unter
 * `style-src-elem 'self'` blockierte Inline-Stile als Konsolenfehler — ein
 * vorbestehender Befund der Stilquelle, den `bundle-activation.spec.ts`
 * bereits benennt. Eine unbehandelte Ausnahme ist dagegen IMMER ein Befund
 * dieser Flaeche.
 */
function collectPageErrors(page: Page): string[] {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(String(error)))
  return errors
}

/** Das, was ein Tastaturnutzer gerade sieht — oder `null`, wenn nichts fokussiert ist. */
type FocusProbe = {
  readonly tag: string
  readonly role: string | null
  readonly name: string
  readonly href: string | null
  readonly insideMain: boolean
  readonly outlineStyle: string
  readonly outlineWidth: string
  readonly boxShadow: string
}

async function probeFocus(page: Page): Promise<FocusProbe | null> {
  return page.evaluate(() => {
    const element = document.activeElement
    if (!(element instanceof HTMLElement) || element === document.body) {
      return null
    }
    const style = getComputedStyle(element)
    return {
      tag: element.tagName.toLowerCase(),
      role: element.getAttribute('role'),
      name: (element.getAttribute('aria-label') ?? element.textContent ?? '').trim(),
      href: element.getAttribute('href'),
      insideMain: element.closest('main') !== null,
      outlineStyle: style.outlineStyle,
      outlineWidth: style.outlineWidth,
      boxShadow: style.boxShadow,
    }
  })
}

/** Ein sichtbarer Fokusindikator: ein Umriss mit Breite, oder ein Schatten. */
function hasVisibleFocusRing(probe: FocusProbe): boolean {
  const outline = probe.outlineStyle !== 'none' && Number.parseFloat(probe.outlineWidth) > 0
  return outline || probe.boxShadow !== 'none'
}

test('mounts the Reader route with its permanent textual verification status in a real engine', async ({
  page,
}) => {
  const errors = collectPageErrors(page)
  await page.goto('/')

  // Der Pruefstand steht IMMER — und er traegt Text, keine Farbe allein.
  const status = verificationStatus(page)
  await expect(status).toBeVisible()
  await expect(status).not.toBeEmpty()

  // Ohne Bestand der TECHNISCHE Zustand. `toContainText` wartet ueber „Der
  // Bestand wird gelesen." hinweg, bis die Bruecke mit `null` geantwortet hat
  // — das ist die echte wasm-Bruecke im dedizierten Worker, kein Doppel.
  await expect(status).toContainText('Kein Bestand geöffnet')
  // Der Weg zum Oeffnen wird BENANNT statt verschwiegen.
  await expect(status.getByRole('link', { name: 'Datei-Modus' })).toHaveAttribute('href', '/datei')

  // Und KEIN leerer Einsatz: kein Artikel, keine Einsatznummer.
  await expect(page.locator('article')).toHaveCount(0)
  await expect(page.getByRole('heading', { name: /Einsatznummer/ })).toHaveCount(0)
  // „kein Bestand" ist ein Zustand und kein Alarm.
  await expect(page.getByRole('alert')).toHaveCount(0)

  expect(errors, `Unbehandelte Ausnahmen: ${errors.join(' | ')}`).toEqual([])
})

test('stays operable while the bridge is slow', async ({ page }) => {
  const errors = collectPageErrors(page)
  const HOLD_MS = 3_000

  // Die simulierte Brueckenlatenz: das wasm-Modul wird ZURUECKGEHALTEN. Der
  // Kontext dieses Tests ist frisch, der Service Worker hat keinen
  // `fetch`-Handler — die Anfrage des Workers geht ins Netz und landet hier.
  // Gezaehlt wird, damit der Zeuge nicht still ins Leere misst.
  let heldWasmRequests = 0
  await page.route('**/*.wasm', async route => {
    heldWasmRequests += 1
    await new Promise(resolve => setTimeout(resolve, HOLD_MS))
    await route.continue()
  })

  const startedAt = Date.now()
  await page.goto('/')

  // WAEHREND die Bruecke schweigt: die Flaeche behauptet nichts ueber den
  // Bestand — weder „kein Bestand" noch einen leeren Einsatz.
  const status = verificationStatus(page)
  await expect(status).toBeVisible()
  await expect(status).toContainText('Der Bestand wird gelesen.')
  await expect(status).not.toContainText('Kein Bestand geöffnet')
  await expect(page.locator('article')).toHaveCount(0)

  // Und sie ist BEDIENBAR, per Tastatur: die Hauptbereiche sind erreichbar und
  // ein Wechsel laeuft, ohne auf die Bruecke zu warten. `Tab` ×3 landet auf
  // dem dritten Verweis der Navigation, `Enter` aktiviert ihn.
  const nav = page.getByRole('navigation', { name: 'Hauptbereiche' })
  await expect(nav.getByRole('link')).toHaveCount(3)
  await page.locator('body').press('Tab')
  await page.keyboard.press('Tab')
  await page.keyboard.press('Tab')
  await expect(nav.getByRole('link', { name: 'Datei-Modus' })).toBeFocused()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('region', { name: 'Datei-Modus' })).toBeVisible()
  await expect(page.getByLabel('Archivdatei öffnen')).toBeVisible()

  // Zurueck zum Reader, ebenfalls per Tastatur.
  await page.keyboard.press('Shift+Tab')
  await page.keyboard.press('Shift+Tab')
  await expect(nav.getByRole('link', { name: 'Reader' })).toBeFocused()
  await page.keyboard.press('Enter')
  await expect(nav.getByRole('link', { name: 'Reader' })).toHaveAttribute('aria-current', 'page')

  // Dann trifft das Modul ein, und die Flaeche kommt zur Ruhe — auf dem
  // technischen Zustand und ohne Ausnahme.
  await expect(verificationStatus(page)).toContainText('Kein Bestand geöffnet', {
    timeout: HOLD_MS + 15_000,
  })
  // ANTI-LEERLAUF: die Ruhe kam NACH der Latenz, und die Latenz traf die
  // Anfrage des Workers. Ohne diese zwei Zeilen bliebe offen, ob der Zeuge
  // eine langsame Bruecke gemessen hat oder eine, die gar nicht gebremst war.
  expect(Date.now() - startedAt).toBeGreaterThanOrEqual(HOLD_MS)
  expect(heldWasmRequests).toBeGreaterThanOrEqual(1)

  await expect(page.locator('article')).toHaveCount(0)
  await expect(page.getByRole('alert')).toHaveCount(0)
  expect(errors, `Unbehandelte Ausnahmen: ${errors.join(' | ')}`).toEqual([])
})

test('reaches every control by keyboard with a visible focus ring', async ({ page, browserName }) => {
  test.skip(
    browserName === 'firefox',
    'Headless-Firefox laesst den Fokus nicht aus dem Dokument; der Zyklus endet nie (gemessen, siehe Kopf).',
  )
  await page.goto('/')
  // Erst die RUHE: der Verweis im Pruefstand steht erst, wenn die Bruecke
  // „kein Bestand" gemeldet hat.
  await expect(verificationStatus(page)).toContainText('Kein Bestand geöffnet')

  // Alles, was die Seite fokussierbar macht — gezaehlt, damit der Tastaturlauf
  // unten NICHTS auslassen kann, ohne dass es auffiele.
  const focusableCount = await page.evaluate(
    () =>
      document.querySelectorAll(
        'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      ).length,
  )
  expect(focusableCount).toBeGreaterThan(0)

  // Vom `body` aus, `Tab` fuer `Tab`, bis der Zyklus wieder am Anfang steht.
  await page.evaluate(() => {
    const active = document.activeElement
    if (active instanceof HTMLElement) {
      active.blur()
    }
  })
  // GEDECKELT auf 25 Schritte: ein Zeuge, der eine Fokusfalle mit einer
  // Endlosschleife beantwortete, saesse selbst in ihr fest.
  const reached: FocusProbe[] = []
  for (let step = 0; step < 25; step += 1) {
    await page.keyboard.press('Tab')
    const probe = await probeFocus(page)
    if (probe === null) {
      // Der Fokus hat das Dokument verlassen — das Zyklusende, sobald vorher
      // etwas erreicht wurde. Vorher waere es eine Seite ohne Bedienung.
      if (reached.length > 0) {
        break
      }
      continue
    }
    reached.push(probe)
    if (reached.length > focusableCount) {
      // Mehr erreicht als es Fokussierbares gibt: der Zyklus laeuft im Kreis,
      // und die Zusicherung darunter benennt es.
      break
    }
  }

  // JEDES fokussierbare Element wurde erreicht — nicht mehr, nicht weniger.
  expect(reached, JSON.stringify(reached, null, 2)).toHaveLength(focusableCount)
  // Alles Bedienbare liegt im Hauptbereich (`Layout.Content` rendert `<main>`).
  for (const probe of reached) {
    expect(probe.insideMain, `ausserhalb von <main>: ${JSON.stringify(probe)}`).toBe(true)
  }
  // Und JEDES traegt einen SICHTBAREN Fokusindikator: `:focus-visible` in
  // `app.css` steht unlayered und ueberstimmt jede Ant-Regel, die den Umriss
  // entfernte — gemessen am berechneten Stil, nicht an der Stilquelle.
  const bare = reached.filter(probe => !hasVisibleFocusRing(probe))
  expect(bare, `ohne sichtbaren Fokus: ${JSON.stringify(bare, null, 2)}`).toEqual([])

  // Die Menge: die drei Verweise der Navigation und der Verweis im Pruefstand.
  const navNames = reached.filter(probe => probe.tag === 'a').map(probe => probe.name)
  expect(navNames).toEqual(expect.arrayContaining(['Reader', 'Enrollment', 'Datei-Modus']))
  expect(reached.filter(probe => probe.href === '/datei')).toHaveLength(2)

  // BENANNTE GRENZE, festgehalten statt verschwiegen: ohne geoeffneten Bestand
  // stehen hier KEIN Reiter, KEINE Suche und KEINE Integritaetskette. Ein Lauf,
  // der die Reiter mit `ArrowRight`/`ArrowLeft` bedient, braucht einen Bestand
  // — und damit die Tiefe von `enrollment.spec.ts`. Wer diese Zusicherung
  // rot sieht, hat einen Bestand ohne Zeremonie geoeffnet und soll die
  // Reiter-Tastatur HIER nachtragen.
  await expect(page.getByRole('tab')).toHaveCount(0)
  await expect(page.getByRole('tablist')).toHaveCount(0)
  await expect(page.getByRole('region', { name: 'Suche' })).toHaveCount(0)
  await expect(page.getByRole('region', { name: 'Integritätskette' })).toHaveCount(0)
})

test('keeps rendering under prefers-reduced-motion', async ({ page }) => {
  const errors = collectPageErrors(page)
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await page.goto('/')

  // ANTI-LEERLAUF: die Emulation greift wirklich.
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
  ).toBe(true)

  const status = verificationStatus(page)
  await expect(status).toBeVisible()
  await expect(status).toContainText('Kein Bestand geöffnet')
  await expect(page.getByRole('navigation', { name: 'Hauptbereiche' })).toBeVisible()
  await expect(page.getByRole('alert')).toHaveCount(0)
  expect(errors, `Unbehandelte Ausnahmen: ${errors.join(' | ')}`).toEqual([])
})
