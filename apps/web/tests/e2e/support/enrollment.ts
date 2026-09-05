// Die Hilfen des Browser-Enrollments, GETEILT zwischen `enrollment.spec.ts`
// und `lock-and-export.spec.ts`.
//
// # Warum es dieses Modul ueberhaupt gibt
//
// Die Sitzungssperre und der Einzelexport brauchen einen ENTSPERRTEN Tresor,
// und den gibt es nur ueber ein vollstaendiges Enrollment in demselben
// Seitenlauf — das PRF-Salz lebt in der Seite, und `recover_and_unlock_vault`
// ist in diesem Stand an keine Ausfuhr verdrahtet. Frueher standen diese
// Hilfen im Kopf von `enrollment.spec.ts`, mit der Begruendung, ein geteiltes
// Doppel sei eine zweite Stelle, an der jemand die Zusagen des Zeugen weicher
// macht. Die Abwaegung hat sich mit dem zweiten Verbraucher umgedreht: eine
// KOPIE der Hilfen in der zweiten Spec waere genau diese zweite Stelle, und
// sie liefe ohne Verbindung zur ersten auseinander. Was hier steht, ist
// deshalb UNVERAENDERT der Wortlaut aus `enrollment.spec.ts`; die Zusagen der
// Zeugen — welche Zeremonie abgewiesen wird, welches Geraet stillgelegt wird —
// stehen weiterhin in den Specs selbst und nicht hier.
import { expect } from '@playwright/test'
import type { CDPSession, Page } from '@playwright/test'

export const VIRTUAL = {
  protocol: 'ctap2',
  hasResidentKey: true,
  hasUserVerification: true,
  hasPrf: true,
  isUserVerified: true,
  automaticPresenceSimulation: true,
} as const

// ZWEI VERSCHIEDENE TRANSPORTE, und das ist gemessen und keine Vorliebe:
// zweimal `transport: 'internal'` beantwortet Chromium mit
// `Protocol error (WebAuthn.addVirtualAuthenticator): Chrome only supports one
// internal authenticator per environment`. Gemessen durchgelassen werden
// daneben `usb`, `nfc` und `ble`; `usb` steht hier, weil
// `transport_profile` in `crates/ea-reader-wasm/src/webauthn.rs` es wie
// `internal` auf `ClientDevice` abbildet — der zweite Authenticator bleibt also
// ein Geraet AN DIESEM Rechner und nicht der Cross-Device-QR-Flow, den §6.4.1
// als Entsperrpfad abweist.
export const FIRST_TRANSPORT = 'internal'
export const SECOND_TRANSPORT = 'usb'

/**
 * Der Enrollment-Kontext, GESTELLT wie eine Freigabe ihn stellt.
 *
 * Der Zeuge stellt hier NICHT weniger und nicht mehr, als der Lauf braucht: die
 * fuenf Werte sind Freigabekonfiguration und keine Sicherheitsentscheidung.
 * Ihr dauerhaftes Zuhause ist die `webBundleRelease` des Buendel-Tasks; bis
 * dahin stellt sie, wer das Buendel ausliefert, und in diesem Lauf ist das der
 * Zeuge — genauso, wie er ueber `stubEnrollmentEndpoints` auch den Server
 * stellt.
 *
 * `PINNED_ANCHOR` sind ECHTE Ankerbytes und keine Fuellung: `decode_trust_anchor`
 * rechnet den eingebetteten Bootstrap-Hash beim Dekodieren NEU, ein erfundener
 * Puffer faellt dort mit `EA-TRUST-ANCHOR-HASH`. Erzeugt aus
 * `fixtures::pinned_anchor_exact_bytes()` in
 * `crates/ea-reader/tests/fixtures/mod.rs` — dieselbe Rechnung, dieselbe Form.
 * Was der Zeuge damit misst, ist die ZEREMONIE; ob dieser Anker der richtige
 * ist, ist eine Betriebsfrage und keine des Browsers.
 */
const PINNED_ANCHOR =
  '8c781d45494e5341545a4152434849562d54525553542d414e43484f522d763101582009' +
  '1dcf5fd3d7799d7e8c08f25fc4a427d1a8d962f909ed39783f901fa30c17865012121212' +
  '12121212121212121212121250131313131313131313131313131313135828a301012006' +
  '215820d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873758' +
  '20df8534b253850532d848039d3ff84290439e14706b55db70007af45822fa1144582014' +
  '141414141414141414141414141414141414141414141414141414141414148258202121' +
  '212121212121212121212121212121212121212121212121212121212121582022222222' +
  '222222222222222222222222222222222222222222222222222222228258203131313131' +
  '313131313131313131313131313131313131313131313131313131582032323232323232' +
  '323232323232323232323232323232323232323232323232325820444444444444444444' +
  '444444444444444444444444444444444444444444444480'

/**
 * Legt den Kontext ab, BEVOR das Buendel laeuft.
 *
 * `addInitScript` und nicht `evaluate`: `main.tsx` montiert beim ersten Skript,
 * und `EnrollmentPage` ruft `begin` schon beim Montieren. Ein nachgereichter
 * Wert kaeme zu spaet, und die Seite zeigte den Fehlschlag statt der Flaeche.
 */
export async function stageEnrollmentRelease(page: Page): Promise<void> {
  await page.addInitScript(
    ({ pinnedAnchor }) => {
      Object.defineProperty(globalThis, '__eaReaderEnrollmentContext', {
        value: {
          organizationId: '12121212121212121212121212121212',
          subjectId: '5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b',
          pinnedAnchor,
          bundleFingerprint: '7e'.repeat(32),
          // Die signierte `@authority` nennt den SYNC-SERVER und nicht den
          // Buendel-Origin; dass beide in diesem Lauf auseinanderfallen, ist
          // die im Kopf von `enrollment.spec.ts` benannte Grenze und kein
          // Versehen.
          authority: 'sync.einsatzarchiv.example',
        },
      })
    },
    { pinnedAnchor: PINNED_ANCHOR },
  )
}

/**
 * Die drei Stufe-3-Endpunkte, beantwortet OHNE Server.
 *
 * Die Antwort ist LEER und traegt 200: `ReaderEnrollment::finish` liest den
 * Koerper der beiden `POST /v1/webauthn-credentials` und des
 * `PUT /v1/vault-blobs` nicht — nur der Abruf `POST
 * /v1/vault-blobs/retrievals` tut das, und der gehoert
 * `recover_and_unlock_vault` und nicht diesem Ablauf.
 */
export async function stubEnrollmentEndpoints(page: Page): Promise<void> {
  await page.route('**/v1/**', (route) =>
    route.fulfill({ status: 200, contentType: 'application/cbor', body: '' }),
  )
}

/**
 * Der erste virtuelle Authenticator aus `ids`, der schon ein Credential haelt.
 *
 * GEFRAGT und nicht angenommen: welches Geraet Chromium fuer eine
 * `create`-Zeremonie waehlt, steht in keinem Vertrag, und CDP bietet kein
 * Zielgeraet an. Findet sich keines, WIRFT die Funktion — ein `undefined`, das
 * weiterliefe, legte anschliessend nichts still und der Zeuge maesse etwas
 * anderes, als sein Name sagt.
 */
export async function deviceHoldingACredential(
  cdp: CDPSession,
  ids: readonly string[],
): Promise<string> {
  for (const authenticatorId of ids) {
    const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId })
    if (credentials.length > 0) {
      return authenticatorId
    }
  }
  throw new Error('Nach der ersten Zeremonie haelt kein virtueller Authenticator ein Credential.')
}

/**
 * Das Enrollment auf ZWEI virtuellen Authenticators, bis „Enrollment
 * abgeschlossen." steht — die Klickfolge des ersten Zeugen in
 * `enrollment.spec.ts`, OHNE dessen Zwischenzusicherungen.
 *
 * Fuer einen Zeugen, der einen entsperrten Tresor BRAUCHT und das Enrollment
 * nicht misst. Der erste Zeuge in `enrollment.spec.ts` faehrt dieselbe Folge
 * weiterhin selbst aus, weil seine Zusicherungen ZWISCHEN den Klicks stehen —
 * die Abweisung des falschen Fingerprints etwa —, und eine Hilfe, die sie
 * ueberspraenge, maesse dort weniger als sein Name sagt.
 *
 * Das Geraet, auf dem Zeremonie 1 gelandet ist, wird fuer Zeremonie 2
 * STILLGELEGT und danach wieder eingeschaltet; die Begruendung samt Messung
 * steht im ersten Zeugen von `enrollment.spec.ts` und wird hier nicht
 * wiederholt. Der Aufrufer hat die Seite bereits auf `/enrollment` und den
 * Anlauf abgewartet.
 */
export async function completeTwoAuthenticatorEnrollment(
  page: Page,
  cdp: CDPSession,
  authenticatorIds: readonly string[],
): Promise<void> {
  await page.getByRole('button', { name: 'Authenticator registrieren' }).click()
  await expect(page.getByText('Ein zweiter Authenticator ist erforderlich.')).toBeVisible()

  const holder = await deviceHoldingACredential(cdp, authenticatorIds)
  await cdp.send('WebAuthn.setAutomaticPresenceSimulation', {
    authenticatorId: holder,
    enabled: false,
  })
  await page.getByRole('button', { name: 'Authenticator registrieren' }).click()
  await expect(page.getByText('2 von 2 Authenticators registriert.')).toBeVisible()
  await cdp.send('WebAuthn.setAutomaticPresenceSimulation', {
    authenticatorId: holder,
    enabled: true,
  })

  const shownKey = await page.getByTestId('schluessel-fingerprint').innerText()
  const shownBundle = await page.getByTestId('bundle-fingerprint').innerText()
  await page.getByLabel('Erwarteter Schlüssel-Fingerprint').fill(shownKey)
  await page.getByLabel('Erwarteter Bundle-Fingerprint').fill(shownBundle)
  await page.getByRole('button', { name: 'Enrollment abschließen' }).click()
  await expect(page.getByText('Enrollment abgeschlossen.')).toBeVisible()
}
