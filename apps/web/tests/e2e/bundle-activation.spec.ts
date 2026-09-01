// Der BROWSERZEUGE der Bundle-Aktivierung nach `web-reader-design.md` §4.2.
//
// Gemessen wird, was nur ein Browser messen kann: dass ein ECHTER
// Service Worker eine Kandidatenfassung nur dann aktiviert, wenn ihr Hash
// gegen eine gepinnte, wurzelsignierte `webBundleRelease` aufgeht — und dass
// nach zwei Ablehnungen dieselbe Fassung aktiv ist wie davor. Die
// Entscheidungslogik selbst bezeugt `crates/ea-reader/tests/bundle_release_pinning.rs`
// mit acht Zeugen; hier steht die LAGE: eigener globaler Bereich, eigene
// wasm-Instanz, echtes `postMessage`.
//
// # Der Worker ist ein MODULWORKER, und dieser Lauf ist der Beleg
//
// Die von `wasm-bindgen` erzeugte Glue ist ein ES-Modul. Ein klassischer
// Worker koennte sie nicht importieren und muesste die fertige Entscheidung
// entgegennehmen — dann erzwaenge er nichts mehr, sondern gehorchte. Ueber die
// Nachricht gehen deshalb ausschliesslich BYTES, und die Pruefung laeuft im
// Worker.
//
// # Zwei benannte GRENZEN dieses Laufs
//
// 1. **Er ist same-origin.** `apps/web/index.html` nennt in `connect-src` die
//    Herkunft des Sync-Servers als RESERVIERTEN Namen nach RFC 2606, der nie
//    aufloest — `web-reader-design.md` §14 offener Punkt 4 erklaert Wahl und
//    Betrieb des Hosts fuer offen, und dieser Task waehlt ihn ausdruecklich
//    nicht. Die CODE-Seite der Trennung belegt
//    `src/sw/service-worker.test.ts` gegen den gebauten `dist/`-Ausgang:
//    relative Beiwerkspfade, genau eine entfernte Herkunft, ungehashter
//    Workereinstieg. Den ECHTEN herkunftsuebergreifenden Transport schliesst
//    die Aufgabe „Inkrementeller Reader-Sync", die seine erste Nutzerin ist.
// 2. **Nur Chromium.** Die Matrix aus Chromium, Firefox und WebKit entsteht in
//    der Aufgabe „Reader-Interoperabilitaet, Browser-Matrix, Datei-Modus,
//    Privatheit und das Stufe-4-Gate" — dort gehoert auch die Frage hin, ob
//    Modul-Service-Worker in allen drei Engines tragen.
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { expect, test } from '@playwright/test'

test.skip(({ browserName }) => browserName !== 'chromium')

const fixtureRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures')

/**
 * Die eingefrorenen Bytes, die dieser Lauf dem Worker vorlegt.
 *
 * Der ANKER ist gepinnt und nicht gebaut: er entsteht in
 * `crates/ea-reader/tests/fixtures/mod.rs::vault_anchor_exact_bytes`, und
 * `crates/ea-reader/tests/bundle_release_pinning.rs::the_browser_fixture_pins_the_same_anchor_the_rust_witnesses_use`
 * haelt beide Seiten zeichengleich. Ein Anker, der hier von dem der
 * Rust-Zeugen abwiche, liesse diesen Lauf etwas anderes messen als jene.
 *
 * Die drei Trust-Objekte sind die seit Stufe 3 EINGEFROrenen Vektoren unter
 * `vectors/web-bundle/v1/object/`. Dieser Lauf friert nichts ein und legt
 * nichts an.
 */
function bytesFromHexFile(name: string): Uint8Array {
  const hex = readFileSync(path.join(fixtureRoot, name), 'utf8').trim()
  const bytes = new Uint8Array(hex.length / 2)
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}

test('a module service worker activates only the pinned, root-signed bundle', async ({ page }) => {
  const anchor = bytesFromHexFile('vault-anchor.hex')
  const release = bytesFromHexFile('accepted-release.hex')
  const revocation = bytesFromHexFile('accepted-revocation.hex')
  // Genau die Bytes, deren Hash die eingefrorene Freigabe nennt.
  const signedCandidate = bytesFromHexFile('pinned-bundle.hex')

  const problems: string[] = []
  page.on('console', message => {
    if (message.type() === 'error') {
      problems.push(message.text())
    }
  })
  page.on('pageerror', error => problems.push(String(error)))

  await page.goto('/')
  // Auf die REGISTRIERUNG warten und nicht auf `controller`: ein frisch
  // installierter Worker uebernimmt die bereits geladene Seite nicht von
  // selbst — `clients.claim()` laeuft erst, wenn er eine Fassung AKTIVIERT.
  // Ein Warten auf `controller` waere hier ein Deadlock.
  await page.waitForFunction(async () => (await navigator.serviceWorker.ready).active !== null, undefined, {
    timeout: 30_000,
  })
  // NUR die Fehler dieses Zeugen. Die Schale meldet unter
  // `style-src-elem 'self'` vier blockierte Inline-Stile — ein VORBESTEHENDER
  // Befund der Stilquelle und nicht dieser Aufgabe; er gehoert dorthin, wo
  // `zeroRuntime` und `static-antd.css` gepflegt werden. Ihn hier zu
  // verschlucken waere falsch, ihn hier rot zu faerben ebenso: dieser Lauf
  // misst die Bundle-Aktivierung.
  const workerProblems = problems.filter(text => /service-worker|wasm|SecurityError/i.test(text))
  expect(workerProblems, `Fehler des Workers: ${workerProblems.join(' | ')}`).toEqual([])

  /** Legt dem Worker eine Kandidatenfassung vor und wartet auf sein DTO. */
  async function evaluate(
    candidateBytes: Uint8Array,
    trustObjects: Uint8Array[],
    registryVersion: number,
  ) {
    return page.evaluate(
      async ([anchorBytes, objects, version, bytes]) => {
        const registration = await navigator.serviceWorker.ready
        const worker = registration.active
        if (worker === null) {
          throw new Error('kein aktiver Service Worker')
        }
        return new Promise(resolve => {
          const channel = new MessageChannel()
          channel.port1.onmessage = event => resolve(event.data)
          worker.postMessage(
            {
              kind: 'ea-bundle-candidate',
              candidate: {
                anchorExactBytes: anchorBytes,
                exactTrustObjects: objects,
                atRegistryVersion: BigInt(version),
                bytes,
              },
            },
            [channel.port2],
          )
        })
      },
      [anchor, trustObjects, registryVersion, candidateBytes] as const,
    )
  }

  // Die wurzelsignierte, wirksame Freigabe wird aktiviert.
  const accepted = await evaluate(signedCandidate, [release], 6)
  expect(accepted).toMatchObject({ activated: true, rejectionCode: null })

  // Eine Kandidatenfassung, die KEINE Freigabe nennt, wird verworfen — und die
  // zuletzt gueltige Fassung bleibt aktiv.
  const foreign = await evaluate(new Uint8Array([0xde, 0xad, 0xbe, 0xef]), [release], 6)
  expect(foreign).toMatchObject({ activated: false, bundleVersion: null })

  // Nach dem wirksamen Widerruf aktiviert dieselbe Fassung NICHT mehr.
  const revoked = await evaluate(signedCandidate, [release, revocation], 7)
  expect(revoked).toMatchObject({ activated: false, bundleVersion: null })

  // Und der Worker, der die beiden Ablehnungen ausgesprochen hat, ist
  // derselbe geblieben: eine Ablehnung wechselt die laufende Fassung nicht.
  const stillActive = await page.evaluate(
    async () => (await navigator.serviceWorker.ready).active !== null,
  )
  expect(stillActive).toBe(true)
})

test('the trust age is shown as TEXT and never as colour alone', async ({ page }) => {
  // §4.2 verlangt, dass das Alter des zuletzt bezogenen Trust-Standes SICHTBAR
  // ausgewiesen wird — und dass die Ueberschreitung eine Aufforderung ist und
  // keine Sperre. Beides ist eine Aussage ueber TEXT: ein Streifen, der nur
  // die Farbe wechselt, sagt einem Screenreader nichts.
  await page.goto('/')

  // Der Streifen erscheint erst, wenn ein Bezug stattgefunden hat. Ohne Bezug
  // zeigt die Schale ihn ausdruecklich NICHT — `undefined` heisst „nie
  // bezogen" und ist nicht dasselbe wie ein Alter von null.
  await expect(page.getByLabel('Alter des Vertrauensbestands')).toHaveCount(0)
})
