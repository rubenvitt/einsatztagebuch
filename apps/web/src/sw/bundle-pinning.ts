import type { BundleActivationView } from '../bridge/generated-contracts'

/**
 * Der Zugang zur geteilten Rust-Entscheidung.
 *
 * Ein PORT und kein Import: der Service Worker laeuft in einem eigenen
 * globalen Bereich, und der Zeuge dieser Datei faehrt unter `vitest` ohne
 * wasm-Modul. Die Grenze ist damit einspeisbar, ohne dass irgendwo ein
 * zweiter Entscheidungsweg entsteht.
 */
export type BundlePinningPort = {
  /**
   * Gibt einen `BundleActivationView` als JSON zurueck.
   *
   * Die KANDIDATENBYTES gehen hinein, nicht ihr Hash: gaebe ihn der Aufrufer
   * mit, koennte ein untergeschobenes Buendel den passenden Hash beilegen,
   * und die Pruefung von §4.2 waere wertlos. Gerechnet wird er in Rust.
   */
  readonly evaluateBundleCandidate: (
    anchorExactBytes: Uint8Array,
    exactTrustObjects: readonly Uint8Array[],
    atRegistryVersion: bigint,
    exactCandidateBundle: Uint8Array,
  ) => string
}

/** Alles, was eine Kandidatenfassung zur Beurteilung mitbringt. */
export type BundleCandidate = {
  /** Die exakten Bytes des im Tresor gepinnten Ankers. */
  readonly anchorExactBytes: Uint8Array
  /** Der lokale Trust-Bestand, exakte Objektbytes. */
  readonly exactTrustObjects: readonly Uint8Array[]
  /** Der zuletzt verifizierte Registry-Stand aus dem Tresor. */
  readonly atRegistryVersion: bigint
  /** Die Bytes der Kandidatenfassung selbst. */
  readonly bytes: Uint8Array
}

/**
 * Die zwei Wirkungen, die auf die Entscheidung folgen — und keine dritte.
 *
 * Sie stehen als Schnittstelle da, weil der Zeuge sie beobachten muss, ohne
 * einen echten Service-Worker-Bereich zu haben. `service-worker.ts` speist die
 * echten ein.
 */
export type ActivationEffects = {
  /** Uebernehmen: `skipWaiting`, `clients.claim`, Cache auf die neue Fassung. */
  readonly takeOver: (bundleVersion: string) => Promise<void>
  /** Verwerfen: der Kandidat faellt, der bestehende Cache bleibt. */
  readonly discard: () => Promise<void>
}

/**
 * Beurteilt eine Kandidatenfassung und wendet GENAU EINE der zwei Wirkungen an.
 *
 * Hier faellt keine Sicherheitsentscheidung. Hash und Signatur rechnet Rust,
 * TypeScript sieht das DTO — `web-reader-design.md` §9 laesst Kryptographie
 * ausschliesslich in geteiltem Rust zu, und der Quelltextscan von
 * `no-hand-written-contracts.test.ts` ist der Waechter dieser Grenze.
 *
 * Es gibt keinen dritten Ausgang. „Aktivieren, aber mit Warnung" existiert
 * nicht: §4.2 laesst die zuletzt gueltige Fassung aktiv, wenn der Hash nicht
 * aufgeht.
 */
export async function activateCandidate(
  port: BundlePinningPort,
  candidate: BundleCandidate,
  effects: ActivationEffects,
): Promise<BundleActivationView> {
  const view = JSON.parse(
    port.evaluateBundleCandidate(
      candidate.anchorExactBytes,
      candidate.exactTrustObjects,
      candidate.atRegistryVersion,
      candidate.bytes,
    ),
  ) as BundleActivationView

  if (view.activated && view.bundleVersion !== null) {
    await effects.takeOver(view.bundleVersion)
  } else {
    await effects.discard()
  }
  return view
}

/**
 * Der Name des Caches einer Fassung.
 *
 * Er traegt die Fassung, damit ein Wechsel den alten Bestand NICHT ueberschreibt:
 * bleibt die zuletzt gueltige Fassung aktiv, muss ihr Cache unangetastet
 * daliegen.
 */
export function bundleCacheName(bundleVersion: string): string {
  return `ea-reader-bundle-${bundleVersion}`
}
