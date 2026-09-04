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
// dieser Lauf faellt, weil `page.clock` die Seitenuhr springen laesst und ein
// Timer im Hintergrundtab diesen Sprung nicht sieht.
//
// # Die gefaelschte Seitenuhr erreicht Rust als WERT
//
// `page.clock.install()` faelscht `Date.now()` und die Timer der SEITE, nicht
// des Workers und nicht des wasm-Moduls. Dass die Sperre trotzdem faellt, ist
// die Zusage selbst: Rust liest keine Uhr, die Seite reicht ihre als Argument,
// und der lesende Poll der Flaeche ist der Beschleuniger der Anzeige und nicht
// der Mechanismus. `fastForward` feuert faellige Timer HOECHSTENS EINMAL —
// der Poll liest also nach dem Sprung genau einmal mit der gesprungenen Uhr,
// und das muss reichen.
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

test('a backgrounded tab and five idle minutes lock the session through the worker with a faked page clock and no timer', async ({
  page,
}) => {
  // VOR der Navigation: die Faelschung wird als Init-Skript installiert, und
  // der Poll der Flaeche muss auf der gefaelschten Uhr entstehen, sonst
  // saehe `fastForward` ihn nicht.
  await page.clock.install()

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

  // CLIENTSEITIG zur Exportflaeche — kein Neuladen, siehe Kopf.
  await page.getByRole('link', { name: 'Einzelexport' }).click()
  const state = page.getByTestId('session-state')
  await expect(state).toHaveText('Keine Sitzung')
  const confirm = page.getByRole('button', { name: 'Export bestätigen' })
  await expect(confirm).toBeDisabled()

  await page.getByRole('button', { name: 'Sitzung entsperren' }).click()
  await expect(state).toHaveText('Sitzung entsperrt')

  // ANTI-LEERLAUF: kurz VOR der kurzen Frist, im Vordergrund, bleibt die
  // Sitzung offen. Ohne diese Zeile bliebe offen, ob die Sperre unten die
  // Frist misst oder jeden Sprung.
  await page.clock.fastForward(BACKGROUND_DEADLINE_MS - 1_000)
  await expect(state).toHaveText('Sitzung entsperrt')

  // DER HINTERGRUNDTAB. Das Ereignis traegt die Uhr der Seite nach Rust, der
  // Sprung darueber laesst die kurze Frist faellig werden, und der naechste
  // lesende Zugriff — der Poll — bringt die Sperre. Kein Timer in Rust, und
  // der Sprung ist gross genug, dass ein Timer der Seite, der die Sperre
  // truege, hier ebenso gefeuert haette: die Zusage ist, dass es ihn nicht
  // BRAUCHT, und die faellt beim adversarialen Fall (2) des Plans, weil ein
  // gedrosselter Hintergrundtimer den echten Sprung nicht sieht.
  await sendTabToBackground(page)
  await page.clock.fastForward(BACKGROUND_DEADLINE_MS)
  await expect(state).toHaveText('Sitzung gesperrt')
  await expect(confirm).toBeDisabled()
  await expect(page.getByText('Kein Datensatz geöffnet.')).toBeVisible()

  // ZWEITES SZENARIO: dieselbe Seite, eine NEUE Sitzung nach erneuter
  // Bestaetigung (§6.5: nach jeder Sperre), im Vordergrund, und fuenf Minuten
  // ohne Eingabe. Der Klick selbst ist die letzte Eingabe; ab da schweigt die
  // Seite.
  await bringTabToForeground(page)
  await page.getByRole('button', { name: 'Sitzung entsperren' }).click()
  await expect(state).toHaveText('Sitzung entsperrt')

  await page.clock.fastForward(INACTIVITY_DEADLINE_MS - 60_000)
  await expect(state).toHaveText('Sitzung entsperrt')
  await page.clock.fastForward(60_000)
  await expect(state).toHaveText('Sitzung gesperrt')
  await expect(confirm).toBeDisabled()

  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: first.authenticatorId })
  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: second.authenticatorId })
})
