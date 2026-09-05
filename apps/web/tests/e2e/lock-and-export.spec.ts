// Der BROWSERZEUGE der Sitzungssperre nach `web-reader-design.md` §6.5 — und
// der Grund, aus dem er neben den Rust-Zeugen steht.
//
// # Was `crates/ea-reader/tests/session_lock.rs` misst, und was NICHT
//
// Die Rust-Zeugen messen die REGEL: fuenf Minuten ohne Eingabe, dreissig
// Sekunden nach dem Wechsel in den Hintergrund, eine Uhr, die nie rueckwaerts
// verlaengert, das Nullen beim Sperren — alles ueber `ReaderSession::state_at`
// mit einer Uhr, die der Test als Wert hineinreicht. Was sie nicht messen
// KOENNEN, ist der Weg dorthin: dass eine echte Engine ein echtes
// `visibilitychange`-Ereignis ausloest, dass der Haken in `src/main.tsx` es
// samt der Uhr der SEITE ueber den Worker nach Rust traegt, und dass die
// Sperre faellt, OHNE dass irgendwo ein Timer laeuft. Genau das ist der
// adversariale Fall (2) aus dem Plan: verlegt jemand die Sperrpruefung aus
// `state_at` in einen `setTimeout`, bleibt der reine Rusttest gruen — und
// dieser Lauf faellt.
//
// # Was GENAU gemessen wird, und wie
//
// Die Seitenuhr wird installiert und nach dem Enrollment ANGEHALTEN
// (`page.clock.pauseAt`): von da an ist `Date.now()` der Seite eine bekannte
// Zahl, die nur die Spruenge dieses Zeugen bewegen. Die Flaeche rendert neben
// dem Zustand den Zeitwert, mit dem sie ihn zuletzt GELESEN hat
// (`session-read-at`), und der Zeuge prueft nach JEDEM Sprung zuerst diesen
// Stempel und erst dann den Zustand. Ohne den Stempel waere „Sitzung
// entsperrt" nach einem Sprung nicht vom Text VOR dem Sprung zu unterscheiden
// — die Zusicherung traefe den alten Wortlaut, bevor der Worker geantwortet
// hat, und saehe gruen aus, ohne etwas gemessen zu haben.
//
// Zwei Arten von Sprung, und der Unterschied ist die Aussage:
//
// - `fastForward` bewegt die Uhr UND feuert faellige Timer der Seite
//   hoechstens einmal — der lesende Poll der Flaeche liest also genau einmal
//   mit der gesprungenen Uhr. Das misst, dass die Sperre an der UHR haengt,
//   sagt aber nichts darueber, ob nicht auch ein Timer sie getragen haette.
// - `setSystemTime` bewegt NUR die Uhr und feuert KEINEN Timer. Danach loest
//   der Zeuge ein Lesen ohne Timer aus: er wechselt ueber die Verweise der
//   Schale nach „Datei-Modus" und zurueck nach „Einzelexport" (clientseitig,
//   ohne Neuladen), die Flaeche wird neu montiert und liest beim Montieren.
//   Faellt die Sperre HIER, dann ohne dass irgendein Timer der Seite gelaufen
//   ist — das ist der Hintergrundtab-Fall, und so ist „kein Timer" gemessen
//   und nicht behauptet.
//
// `page.clock` faelscht die Uhr und die Timer der SEITE, nicht des Workers und
// nicht des wasm-Moduls. Dass die Sperre trotzdem faellt, ist die Zusage
// selbst: Rust liest keine Uhr, die Seite reicht ihre als Argument.
//
// # Der Lauf ist SAME-ORIGIN und braucht ein Enrollment DIESES Seitenlaufs
//
// Die Seite wird ueber den NAMEN aufgerufen und nicht ueber `baseURL`: unter
// `http://127.0.0.1:4174` faellt die erste Zeremonie mit `SecurityError: This
// is an invalid domain.`, weil WebAuthn aus dem Host die Relying-Party-Kennung
// ableitet und eine IP-Adresse dort keine ist (`WEBAUTHN_PREVIEW_ORIGIN` in
// `playwright.config.ts`). Und von `/enrollment` nach `/export` geht es ueber
// den Verweis der Schale und NICHT ueber `page.goto`: das PRF-Salz lebt in der
// Seite, ein Neuladen wuerfe es fort, und `recover_and_unlock_vault` ist in
// diesem Stand an keine Ausfuhr verdrahtet.
//
// # Was dieser Lauf NICHT misst
//
// Keinen Export: der Browser-Reader traegt in diesem Stand kein
// Reader-Zertifikat, also keine Identitaet fuer die Auditzeile, und die
// Flaeche sperrt die Bestaetigung mit genau dieser Aussage. Der Exportpfad —
// `Accepted` vor dem Schreiben, `Completed` oder `Failed` danach, die
// Weigerungen — ist in `crates/ea-reader/tests/export.rs` bezeugt.
import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'

import { WEBAUTHN_PREVIEW_ORIGIN } from '../../playwright.config'
import {
  FIRST_TRANSPORT,
  SECOND_TRANSPORT,
  VIRTUAL,
  completeTwoAuthenticatorEnrollment,
  stageEnrollmentRelease,
  stubEnrollmentEndpoints,
} from './support/enrollment'

test.skip(({ browserName }) => browserName !== 'chromium')

// Die zwei Fristen aus `crates/ea-reader/src/session.rs`, hier als
// ZEITSPRUENGE und nicht als Zusicherung: `READER_BACKGROUND_INACTIVITY_MS_V1`
// und `READER_INACTIVITY_MS_V1` werden dort gegen den Desktop gemessen. Der
// Zeuge springt EINE Sekunde weniger und dann ueber die Frist, damit die
// Sperre der Frist zugeschrieben werden kann und nicht dem Sprung.
const BACKGROUND_DEADLINE_MS = 30_000
const INACTIVITY_DEADLINE_MS = 5 * 60_000

// Feste Zeitwerte, damit jeder erwartete Stempel eine Konstante ist. Die Uhr
// wird bei `INSTALLED_AT` installiert und laeuft waehrend des Enrollments in
// Echtzeit weiter; `PAUSED_AT` liegt zehn Minuten spaeter, damit `pauseAt`
// auch auf einem langsamen Rechner in die Zukunft springt und nie „in die
// Vergangenheit" faellt.
const INSTALLED_AT = '2026-09-04T10:00:00.000Z'
const PAUSED_AT_MS = Date.parse(INSTALLED_AT) + 10 * 60_000

/**
 * Schickt den Tab in den Hintergrund, wie die Engine es meldet: die
 * Eigenschaft sagt `hidden`, und das Ereignis heisst `visibilitychange`.
 *
 * Ein echter Tabwechsel ist mit Playwright nicht zu erzwingen, ohne die Seite
 * zu verlieren; die Eigenschaft samt Ereignis ist genau die Flaeche, an der
 * der Haken in `src/main.tsx` haengt — und mehr sieht der Haken auch bei
 * einem echten Wechsel nicht.
 */
async function sendTabToBackground(page: Page): Promise<void> {
  await page.evaluate(() => {
    Object.defineProperty(document, 'visibilityState', {
      configurable: true,
      get: () => 'hidden',
    })
    document.dispatchEvent(new Event('visibilitychange'))
  })
}

/** Holt den Tab zurueck — die Rueckkehr beendet die kurze Frist, ist aber keine Eingabe. */
async function bringTabToForeground(page: Page): Promise<void> {
  await page.evaluate(() => {
    Object.defineProperty(document, 'visibilityState', {
      configurable: true,
      get: () => 'visible',
    })
    document.dispatchEvent(new Event('visibilitychange'))
  })
}

/**
 * Der Stempel des letzten Lesens muss GENAU die gesprungene Uhr nennen.
 *
 * Diese Zusicherung steht vor jeder Zusicherung ueber den Zustand: erst wenn
 * sie gruen ist, ist der Zustand daneben das Ergebnis eines Lesens zu dieser
 * Uhr und nicht der Text von vorhin.
 */
async function expectReadAt(page: Page, nowMs: number): Promise<void> {
  await expect(page.getByTestId('session-read-at')).toHaveText(
    `Stand: ${new Date(nowMs).toISOString()}`,
  )
}

test('a backgrounded tab and five idle minutes lock the session through the worker with a paused page clock and no timer', async ({
  page,
}) => {
  // VOR der Navigation: die Faelschung wird als Init-Skript installiert, und
  // die Timer der Flaeche muessen auf der gefaelschten Uhr entstehen, sonst
  // saehe `fastForward` sie nicht.
  await page.clock.install({ time: INSTALLED_AT })

  const cdp = await page.context().newCDPSession(page)
  await cdp.send('WebAuthn.enable')
  const first = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { ...VIRTUAL, transport: FIRST_TRANSPORT },
  })
  const second = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { ...VIRTUAL, transport: SECOND_TRANSPORT },
  })
  await stubEnrollmentEndpoints(page)
  await stageEnrollmentRelease(page)

  await page.goto(`${WEBAUTHN_PREVIEW_ORIGIN}/enrollment`)
  // DER ANLAUF ZUERST, aus dem Grund, den `enrollment.spec.ts` ausschreibt:
  // faellt `begin`, bleibt jede Flaeche darunter leer.
  await expect(page.getByRole('alert')).toHaveCount(0)
  await expect(page.getByTestId('schluessel-fingerprint')).not.toBeEmpty()
  await completeTwoAuthenticatorEnrollment(page, cdp, [
    first.authenticatorId,
    second.authenticatorId,
  ])

  // AB HIER steht die Uhr, und `now` ist die Zahl, die die Seite sieht.
  await page.clock.pauseAt(PAUSED_AT_MS)
  let now = PAUSED_AT_MS

  // CLIENTSEITIG zur Exportflaeche — kein Neuladen, siehe Kopf.
  await page.getByRole('link', { name: 'Einzelexport' }).click()
  const state = page.getByTestId('session-state')
  await expectReadAt(page, now)
  await expect(state).toHaveText('Keine Sitzung')
  const confirm = page.getByRole('button', { name: 'Export bestätigen' })
  await expect(confirm).toBeDisabled()

  const unlock = page.getByRole('button', { name: 'Sitzung entsperren' })
  await unlock.click()
  await expectReadAt(page, now)
  await expect(state).toHaveText('Sitzung entsperrt')
  // Offen heisst: keine zweite Zeremonie neben der offenen Sitzung.
  await expect(unlock).toBeDisabled()

  // ANTI-LEERLAUF: kurz VOR der kurzen Frist, im Vordergrund, bleibt die
  // Sitzung offen — GELESEN mit der gesprungenen Uhr, wie der Stempel
  // belegt. Ohne diese Zeile bliebe offen, ob die Sperre unten die Frist
  // misst oder jeden Sprung.
  await page.clock.fastForward(BACKGROUND_DEADLINE_MS - 1_000)
  now += BACKGROUND_DEADLINE_MS - 1_000
  await expectReadAt(page, now)
  await expect(state).toHaveText('Sitzung entsperrt')

  // DER HINTERGRUNDTAB. Das Ereignis traegt die Uhr der Seite nach Rust.
  // Dann springt NUR die Uhr (`setSystemTime`), kein Timer feuert, und das
  // naechste Lesen loest kein Timer aus, sondern die Neumontage der Flaeche
  // ueber zwei Verweise der Schale. Faellt die Sperre hier, dann ohne Timer
  // — und ein `setTimeout`, der die Sperre truege, haette diesen Sprung nie
  // gesehen.
  await sendTabToBackground(page)
  await page.clock.setSystemTime(now + BACKGROUND_DEADLINE_MS)
  now += BACKGROUND_DEADLINE_MS
  await page.getByRole('link', { name: 'Datei-Modus' }).click()
  await expect(page.getByRole('link', { name: 'Datei-Modus' })).toHaveAttribute(
    'aria-current',
    'page',
  )
  await page.getByRole('link', { name: 'Einzelexport' }).click()
  await expectReadAt(page, now)
  await expect(state).toHaveText('Sitzung gesperrt')
  await expect(confirm).toBeDisabled()
  await expect(page.getByText('Kein Datensatz geöffnet.')).toBeVisible()
  await expect(unlock).toBeEnabled()

  // ZWEITES SZENARIO: dieselbe Seite, eine NEUE Sitzung nach erneuter
  // Bestaetigung (§6.5: nach jeder Sperre), im Vordergrund, und fuenf Minuten
  // ohne Eingabe. Der Klick selbst ist die letzte Eingabe; ab da schweigt die
  // Seite. Hier springt die Uhr mit `fastForward`, der Poll liest also genau
  // einmal je Sprung — und der Stempel belegt, dass er es getan hat.
  await bringTabToForeground(page)
  await unlock.click()
  await expect(state).toHaveText('Sitzung entsperrt')
  await expectReadAt(page, now)
  await expect(unlock).toBeDisabled()

  await page.clock.fastForward(INACTIVITY_DEADLINE_MS - 60_000)
  now += INACTIVITY_DEADLINE_MS - 60_000
  await expectReadAt(page, now)
  await expect(state).toHaveText('Sitzung entsperrt')

  await page.clock.fastForward(60_000)
  now += 60_000
  await expectReadAt(page, now)
  await expect(state).toHaveText('Sitzung gesperrt')
  await expect(confirm).toBeDisabled()

  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: first.authenticatorId })
  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: second.authenticatorId })
})
