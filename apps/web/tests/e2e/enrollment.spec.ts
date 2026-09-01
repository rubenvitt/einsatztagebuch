// Der BROWSERZEUGE des Enrollments — und der einzige Zeuge dieses Plans, der
// eine ECHTE PRF-Ausgabe beruehrt.
//
// Gemessen wird die BROWSERHAELFTE: ein echter virtueller CTAP2-Authenticator
// mit `hasPrf`, zwei echte `navigator.credentials.create`-Zeremonien, die
// Kardinalitaet, die Abweisung eines falschen Fingerprints und zuletzt die
// LEBENDE Paritaet — derselbe Authenticator wird ein zweites Mal befragt, und
// der Tresor, den dieser Lauf gebaut hat, muss sich mit dem oeffnen, was dabei
// herauskommt. Was der SERVER mit den drei Aufrufen macht, misst
// `pnpm test:server` mit `--test webauthn_credential_api --test vault_blob_api`.
//
// ZWEI Zeugen stehen hier, und sie messen gegenlaeufige Lagen. Der erste faehrt
// den vollstaendigen Ablauf auf ZWEI virtuellen Authenticators. Der zweite,
// unten, faehrt ihn auf EINEM und haelt fest, dass die zweite Zeremonie dort
// abgewiesen wird, statt den ersten Passkey still zu ersetzen — die
// Unabhaengigkeit aus §6.3 ist eine MUSS-Aussage, und der Browser ist die
// einzige Instanz, die sie durchsetzen kann UND der einzige Ort, an dem sie
// beobachtbar ist: in `ea-reader` sind beide Faelle ununterscheidbar.
//
// # Der Lauf ist SAME-ORIGIN, und das ist eine benannte Grenze
//
// `apps/web/index.html` traegt `connect-src 'self'`, und Chromium setzt die
// Richtlinie im Renderer durch, BEVOR eine Anfrage den Prozess verlaesst — ein
// `page.route` auf eine fremde Herkunft kaeme also nie zum Zug. Der
// Abfangjaeger unten faengt deshalb den PFAD aus
// `EnrollmentRequestV1::target_uri` auf dem Buendel-Origin. Gemessen ist damit
// die Zeremonie und die REIHENFOLGE der drei Aufrufe, NICHT der echte
// herkunftsuebergreifende Transport; den schliesst der Buendel-Task, wenn
// `connect-src` die Herkunft des Sync-Servers aufnimmt.
import { expect, test } from '@playwright/test'
import type { CDPSession, Page } from '@playwright/test'

import { WEBAUTHN_PREVIEW_ORIGIN } from '../../playwright.config'

test.skip(({ browserName }) => browserName !== 'chromium')

const VIRTUAL = {
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
const FIRST_TRANSPORT = 'internal'
const SECOND_TRANSPORT = 'usb'

/**
 * Der Enrollment-Kontext, GESTELLT wie eine Freigabe ihn stellt.
 *
 * Er steht im KOPF dieser Datei und in keinem gemeinsamen Hilfsmodul — aus
 * demselben Grund wie `stubEnrollmentEndpoints` darunter.
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
async function stageEnrollmentRelease(page: Page): Promise<void> {
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
          // die im Kopf dieser Datei benannte Grenze und kein Versehen.
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
 * Sie steht im KOPF dieser Datei und in keinem gemeinsamen Hilfsmodul — aus
 * demselben Grund wie `stubBridge` in der Vitest-Datei: ein geteiltes Doppel
 * waere eine zweite Stelle, an der jemand die Zusagen dieses Zeugen weicher
 * macht, ohne dass es hier auffiele.
 *
 * Die Antwort ist LEER und traegt 200: `ReaderEnrollment::finish` liest den
 * Koerper der beiden `POST /v1/webauthn-credentials` und des
 * `PUT /v1/vault-blobs` nicht — nur der Abruf `POST
 * /v1/vault-blobs/retrievals` tut das, und der gehoert
 * `recover_and_unlock_vault` und nicht diesem Ablauf.
 */
async function stubEnrollmentEndpoints(page: Page): Promise<void> {
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
async function deviceHoldingACredential(
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

test('two authenticators are required, a wrong fingerprint aborts, and a real PRF output opens the vault this run built', async ({
  page,
}) => {
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

  // UEBER DEN NAMEN und nicht ueber `baseURL`: unter `http://127.0.0.1:4174`
  // faellt die erste Zeremonie mit `SecurityError: This is an invalid domain.`,
  // weil WebAuthn aus dem Host die Relying-Party-Kennung ableitet und eine
  // IP-Adresse dort keine ist. Die Begruendung samt Messung steht bei
  // `WEBAUTHN_PREVIEW_ORIGIN` in `playwright.config.ts`.
  await page.goto(`${WEBAUTHN_PREVIEW_ORIGIN}/enrollment`)

  // DER ANLAUF ZUERST, sonst misst dieser Zeuge etwas anderes, als sein Name
  // sagt: `EnrollmentPage` ruft beim Montieren `begin` und `fingerprints`, und
  // faellt das, bleibt jede Flaeche darunter leer und die Ursache steht in
  // einem `Alert` daneben. Ohne diese zwei Zeilen liefe die Kardinalitaetsprobe
  // in ihr Zeitbudget und meldete „Text nicht gefunden" — eine Meldung, die auf
  // die Oberflaeche zeigt und nicht auf den gescheiterten Anlauf.
  await expect(page.getByRole('alert')).toHaveCount(0)
  await expect(page.getByTestId('schluessel-fingerprint')).not.toBeEmpty()

  await page.getByRole('button', { name: 'Authenticator registrieren' }).click()
  await expect(page.getByText('Ein zweiter Authenticator ist erforderlich.')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Enrollment abschließen' })).toBeDisabled()

  // DAS GERAET, AUF DEM ZEREMONIE 1 GELANDET IST, WIRD FUER ZEREMONIE 2
  // STILLGELEGT — und das bildet nach, was ein Mensch tut; es glaettet nichts
  // weg. Seit die Zeremonie `excludeCredentials` traegt (siehe den zweiten
  // Zeugen unten), beantwortet ein Authenticator, der eine ausgeschlossene
  // Kennung haelt, die Anfrage mit `CTAP2_ERR_CREDENTIAL_EXCLUDED`, und dieser
  // Fehler ist im WebAuthn-Algorithmus TERMINAL: der Client bricht die ganze
  // Zeremonie mit `InvalidStateError` ab, statt die uebrigen Authenticators
  // weiterzufragen. Vor einem ECHTEN Geraetepaar stellt sich die Lage nicht,
  // weil die Auswahl dort beim Menschen liegt — er beruehrt genau EINES, und
  // nur das antwortet. `automaticPresenceSimulation: true` laesst dagegen BEIDE
  // virtuellen Geraete sofort antworten, der ausgeschlossene gewinnt das
  // Rennen, und der Lauf maesse die Abwesenheit einer Auswahl statt der
  // Kardinalitaet. GEMESSEN, alle drei Reihen mit `WebAuthn.getCredentials`
  // nachgezaehlt: `internal`+`usb`, `usb`+`nfc` und `usb`+`internal` enden ohne
  // diese Zeilen samtlich auf `InvalidStateError`; mit ihnen legt Zeremonie 2
  // in allen dreien ein Credential auf dem zweiten Geraet an.
  // `WebAuthn.setAutomaticPresenceSimulation` ist die einzige Stellschraube,
  // die CDP fuer diese Auswahl anbietet — ein Zielgeraet fuer `create` kennt es
  // nicht, und genau das schreibt der Absatz „Was der Browserlauf beweist" im
  // Plan seit jeher aus.
  //
  // WELCHES der beiden das ist, wird GEFRAGT und nicht angenommen: gemessen
  // bevorzugt Chromium in allen drei Reihen den abnehmbaren Authenticator, das
  // erste Credential liegt hier also auf `second` und nicht auf `first`. Eine
  // festgeschriebene Kennung waere ein Zeuge, der beim naechsten Chromium still
  // das falsche Geraet stilllegt.
  const holder = await deviceHoldingACredential(cdp, [
    first.authenticatorId,
    second.authenticatorId,
  ])
  await cdp.send('WebAuthn.setAutomaticPresenceSimulation', {
    authenticatorId: holder,
    enabled: false,
  })
  await page.getByRole('button', { name: 'Authenticator registrieren' }).click()
  await expect(page.getByText('2 von 2 Authenticators registriert.')).toBeVisible()
  // Und wieder AN: die lebende Paritaet unten befragt einen beliebigen der
  // beiden, und ein stillgelegtes Geraet nimmt ihr einen Entsperrpfad, ueber den
  // dieser Zeuge nichts aussagen will.
  await cdp.send('WebAuthn.setAutomaticPresenceSimulation', {
    authenticatorId: holder,
    enabled: true,
  })

  const shownKey = await page.getByTestId('schluessel-fingerprint').innerText()
  await page.getByLabel('Erwarteter Schlüssel-Fingerprint').fill(shownKey)
  await page.getByLabel('Erwarteter Bundle-Fingerprint').fill('0'.repeat(64))
  await expect(page.getByRole('alert')).toContainText('EA-READER-ENROLLMENT-FINGERPRINT-MISMATCH')
  await expect(page.getByRole('button', { name: 'Enrollment abschließen' })).toBeDisabled()

  const shownBundle = await page.getByTestId('bundle-fingerprint').innerText()
  await page.getByLabel('Erwarteter Bundle-Fingerprint').fill(shownBundle)
  await page.getByRole('button', { name: 'Enrollment abschließen' }).click()
  await expect(page.getByText('Enrollment abgeschlossen.')).toBeVisible()

  // DIE LEBENDE PARITAET. Bis hierher ist der Tresor mit PRF-Ausgaben gebaut,
  // die der virtuelle Authenticator SELBST gezogen hat und die niemand kennt.
  // Jetzt wird derselbe Authenticator ein zweites Mal befragt, und der Tresor
  // muss sich mit dem oeffnen, was dabei herauskommt.
  await page.getByRole('button', { name: 'Tresor entsperren' }).click()
  await expect(page.getByText('Tresor entsperrt.')).toBeVisible()

  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: first.authenticatorId })
  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: second.authenticatorId })
})

// Der ZWEITE Zeuge dieser Datei, und er misst die Lage, die der erste
// ausdruecklich NICHT misst: dessen Kopf schreibt aus, dass CDP kein Zielgeraet
// fuer einen `create`-Aufruf erzwingt, also belegt er die UNABHAENGIGKEIT der
// zwei Authenticators nicht. Hier gibt es deshalb nur EINEN virtuellen
// Authenticator — und damit genau die Lage, die `hints: ['client-device']` auf
// einem Rechner mit Touch ID, Windows Hello oder einem einzelnen
// Resident-Key-Stick ohnehin herstellt.
//
// # Was ohne `excludeCredentials` passiert, GEMESSEN und nicht gefolgert
//
// Beide Zeremonien tragen dieselbe `rp.id` und dasselbe `user.id`, und ein
// `authenticatorMakeCredential` mit `rk=true` auf ein bereits vorhandenes Paar
// (rpId, userHandle) ERSETZT das auffindbare Credential. Auf Chromiums
// virtuellem Authenticator gemessen: nach zwei Zeremonien ohne die Liste liegt
// auf dem Geraet GENAU EIN Credential, und seine Kennung ist die der ZWEITEN —
// der erste Passkey ist fort, und mit ihm sein CredRandom. `ea-reader` kann das
// nicht auffangen: seine Doppelungspruefung de-dupliziert auf der
// `credentialId`, und die ist frisch; `AttestedAuthenticatorV1` traegt kein
// AAGUID und kein anderes geraeteunterscheidendes Feld. Das Enrollment meldete
// „2 von 2", versiegelte zwei Envelopes und genau EINER ginge noch auf.
//
// # Was dieser Zeuge deshalb misst
//
// Mit der Liste weist Chromium die zweite Zeremonie mit `InvalidStateError` ab
// (gemessen, mit und ohne `transports` am Deskriptor). Der Zeuge haelt drei
// Dinge fest: das Enrollment steht NICHT auf zwei, die Flaeche SAGT das in
// Worten statt still hochzuzaehlen, und auf dem Geraet liegt danach immer noch
// derselbe erste Passkey. Ohne den dritten Punkt bliebe der Zeuge auch dann
// gruen, wenn die Zeremonie den ersten Passkey zerstoerte und erst danach
// abbrach.
test('a second ceremony on the same authenticator is refused instead of silently replacing the first passkey', async ({
  page,
}) => {
  const cdp = await page.context().newCDPSession(page)
  await cdp.send('WebAuthn.enable')
  // GENAU EINER. Ein zweiter machte diesen Zeugen zum ersten.
  const only = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { ...VIRTUAL, transport: FIRST_TRANSPORT },
  })
  const residentCredentials = async (): Promise<readonly string[]> =>
    (
      await cdp.send('WebAuthn.getCredentials', { authenticatorId: only.authenticatorId })
    ).credentials.map((credential) => credential.credentialId)

  await stubEnrollmentEndpoints(page)
  await stageEnrollmentRelease(page)
  await page.goto(`${WEBAUTHN_PREVIEW_ORIGIN}/enrollment`)

  // DER ANLAUF ZUERST, aus demselben Grund wie im ersten Zeugen: faellt
  // `begin`, bleibt jede Flaeche darunter leer, und die Weigerung weiter unten
  // waere die falsche.
  await expect(page.getByRole('alert')).toHaveCount(0)
  await expect(page.getByTestId('schluessel-fingerprint')).not.toBeEmpty()

  await page.getByRole('button', { name: 'Authenticator registrieren' }).click()
  await expect(page.getByText('Ein zweiter Authenticator ist erforderlich.')).toBeVisible()
  const afterFirst = await residentCredentials()
  expect(afterFirst).toHaveLength(1)

  await page.getByRole('button', { name: 'Authenticator registrieren' }).click()

  // Die Flaeche sagt es IN WORTEN — und zwar den Satz, der die URSACHE nennt.
  // Nicht „nimm ein anderes Geraet": `CTAP2_ERR_CREDENTIAL_EXCLUDED` ist im
  // WebAuthn-Algorithmus terminal, dieselbe Abweisung trifft also auch
  // jemanden, der SEHR WOHL ein zweites Geraet vorgehalten hat und dessen
  // Zeremonie ein dritter, ausgeschlossener Authenticator zuerst beantwortet
  // hat. Der Zeuge pinnt beide Haelften des Satzes: den Befund und die
  // Bedingung fuer den naechsten Versuch.
  await expect(page.getByRole('alert')).toContainText(
    'der bereits einen Passkey dieses Readers traegt',
  )
  await expect(page.getByRole('alert')).toContainText(
    'das noch keinen Passkey dieses Readers haelt',
  )
  // Und sie zaehlt NICHT hoch: der Stand bleibt der, den Rust kennt.
  await expect(page.getByText('Ein zweiter Authenticator ist erforderlich.')).toBeVisible()
  await expect(page.getByText('2 von 2 Authenticators registriert.')).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Enrollment abschließen' })).toBeDisabled()

  // DER ERSTE PASSKEY LEBT NOCH. Dieselbe Kennung, ein einziges Credential —
  // die Zeremonie ist abgewiesen worden, bevor sie etwas ersetzen konnte.
  expect(await residentCredentials()).toEqual(afterFirst)

  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: only.authenticatorId })
})
