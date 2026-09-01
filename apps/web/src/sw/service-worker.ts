/// <reference lib="webworker" />

import init, { evaluateBundleCandidate } from '../bridge/pkg/ea_reader_wasm.js'
import type { ActivationEffects, BundleCandidate, BundlePinningPort } from './bundle-pinning'
import { activateCandidate, bundleCacheName } from './bundle-pinning'

/**
 * Der Service Worker des Browser-Readers.
 *
 * # Er ist ein MODULWORKER, und das ist keine Stilfrage
 *
 * Die von `wasm-bindgen` erzeugte Glue ist ein ES-Modul. Ein klassischer
 * Worker koennte sie nicht importieren — er muesste die Entscheidung von
 * aussen entgegennehmen, und dann erzwaenge er nichts mehr, sondern gehorchte.
 * `web-reader-design.md` §4.2 sagt aber: der Service Worker DARF eine neue
 * Fassung nur aktivieren, wenn ihr Hash aufgeht. Damit dieser Satz waehr ist,
 * muss die Pruefung HIER laufen.
 *
 * # Ueber die Nachricht gehen nur BYTES
 *
 * Anker, Trust-Bestand, Registry-Stand und Kandidatenbytes sind alle
 * strukturiert klonbar. Es geht KEINE Entscheidung und keine Funktion ueber
 * die Grenze: Hash und Signatur rechnet dieser Worker selbst, in geteiltem
 * Rust. Verfaelschte Bytes fallen an der Wurzelsignatur, nicht an einem
 * Vertrauensvorschuss.
 *
 * # Warum der Dateiname fest ist
 *
 * Ein gehashter Workername waere bei jedem Bau ein anderer Registrierungspfad
 * — und damit ein Aktivierungspfad, den die Pinnung nicht sieht.
 * `vite.config.ts` haelt `service-worker.js` deshalb ungehasht, waehrend jedes
 * andere Beiwerk seinen Hash behaelt.
 */

declare const self: ServiceWorkerGlobalScope

/** Das wasm-Modul, EINMAL je Wortlaufzeit geladen. */
const ready = init()

/** Der Zugang zur geteilten Rust-Entscheidung, aus der eigenen Instanz. */
const pinningPort: BundlePinningPort = {
  evaluateBundleCandidate: (anchor, objects, registryVersion, bytes) =>
    evaluateBundleCandidate(anchor, [...objects], registryVersion, bytes),
}

/**
 * Die zwei Wirkungen, die auf die Entscheidung folgen — und keine dritte.
 *
 * `takeOver` schaltet den Cachenamen auf die neue Fassung um und raeumt die
 * alten erst danach ab; `discard` fasst gar nichts an, weil die zuletzt
 * gueltige Fassung aktiv bleibt.
 */
function serviceWorkerEffects(): ActivationEffects {
  return {
    takeOver: async (bundleVersion: string) => {
      const wanted = bundleCacheName(bundleVersion)
      await caches.open(wanted)
      const stale = (await caches.keys()).filter(
        name => name.startsWith('ea-reader-bundle-') && name !== wanted,
      )
      await Promise.all(stale.map(async name => caches.delete(name)))
      await self.skipWaiting()
      await self.clients.claim()
    },
    discard: async () => {
      // Ausdruecklich nichts. Der Kandidat faellt, der bestehende Cache und
      // die laufende Fassung bleiben — genau das sagt §4.2.
    },
  }
}

/**
 * Die Nachricht, mit der die Anwendung eine Kandidatenfassung vorlegt.
 *
 * Jedes Feld ist strukturiert klonbar. Eine Funktion hier waere ein
 * Konstruktionsfehler: `postMessage` klont keine Funktionen, und ein Port, der
 * die Grenze nicht ueberlebt, faellt erst im Browser auf.
 */
type CandidateMessage = {
  readonly kind: 'ea-bundle-candidate'
  readonly candidate: BundleCandidate
}

function isCandidateMessage(value: unknown): value is CandidateMessage {
  return (
    typeof value === 'object' &&
    value !== null &&
    (value as { kind?: unknown }).kind === 'ea-bundle-candidate'
  )
}

self.addEventListener('message', event => {
  if (!isCandidateMessage(event.data)) {
    return
  }
  const message = event.data
  event.waitUntil(
    ready
      .then(async () =>
        activateCandidate(pinningPort, message.candidate, serviceWorkerEffects()),
      )
      .then(view => {
        // Der Ausgang geht an den Absender zurueck — als DTO und nie als
        // Entscheidung, die dort noch einmal getroffen wuerde.
        for (const port of event.ports) {
          port.postMessage(view)
        }
      }),
  )
})
