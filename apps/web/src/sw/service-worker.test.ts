import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it, vi } from 'vitest'

import { SYNC_SERVER_ORIGIN } from '../app/csp.test'
import type { BundleActivationView } from '../bridge/generated-contracts'
import type { BundleCandidate, BundlePinningPort } from './bundle-pinning'
import { activateCandidate, bundleCacheName } from './bundle-pinning'

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')

function candidate(): BundleCandidate {
  return {
    anchorExactBytes: new Uint8Array([1, 2, 3]),
    exactTrustObjects: [new Uint8Array([4, 5, 6])],
    atRegistryVersion: 6n,
    bytes: new Uint8Array([7, 8, 9]),
  }
}

function portReturning(view: BundleActivationView): BundlePinningPort {
  return { evaluateBundleCandidate: () => JSON.stringify(view) }
}

describe('die Aktivierungsentscheidung', () => {
  it('uebergibt die KANDIDATENBYTES und nie einen mitgelieferten Hash', async () => {
    // Der ganze Punkt von §4.2: gaebe der Kandidat seinen Hash mit, koennte
    // ein untergeschobenes Buendel den passenden beilegen.
    const evaluate = vi.fn(() =>
      JSON.stringify({ activated: false, bundleVersion: null, rejectionCode: 'HashMismatch' }),
    )
    await activateCandidate({ evaluateBundleCandidate: evaluate }, candidate(), {
      takeOver: vi.fn(async () => {}),
      discard: vi.fn(async () => {}),
    })

    expect(evaluate).toHaveBeenCalledTimes(1)
    const call = evaluate.mock.calls[0]
    expect(call).toBeDefined()
    const [anchor, objects, registryVersion, bytes] = call as unknown as [
      Uint8Array,
      readonly Uint8Array[],
      bigint,
      Uint8Array,
    ]
    expect(anchor).toEqual(new Uint8Array([1, 2, 3]))
    expect(objects).toEqual([new Uint8Array([4, 5, 6])])
    expect(registryVersion).toBe(6n)
    expect(bytes).toEqual(new Uint8Array([7, 8, 9]))
  })

  it('uebernimmt genau dann, wenn die Bruecke aktiviert', async () => {
    const takeOver = vi.fn(async () => {})
    const discard = vi.fn(async () => {})
    await activateCandidate(
      portReturning({ activated: true, bundleVersion: '2026.3.1', rejectionCode: null }),
      candidate(),
      { takeOver, discard },
    )

    expect(takeOver).toHaveBeenCalledWith('2026.3.1')
    expect(discard).not.toHaveBeenCalled()
  })

  it('verwirft jeden anderen Ausgang und laesst die laufende Fassung stehen', async () => {
    // Es gibt keinen dritten Ausgang: „aktivieren, aber mit Warnung" existiert
    // nicht. Die Codes werden hier NICHT aufgezaehlt — jedes Literal der
    // generierten Vereinigungen ist aus handgeschriebenen Quellen verbannt,
    // und ein Test, der sie abschriebe, waere die zweite Quelle.
    for (const rejectionCode of [null, 'irgendein-code']) {
      const takeOver = vi.fn(async () => {})
      const discard = vi.fn(async () => {})
      await activateCandidate(
        portReturning({
          activated: false,
          bundleVersion: null,
          rejectionCode: rejectionCode as BundleActivationView['rejectionCode'],
        }),
        candidate(),
        { takeOver, discard },
      )

      expect(takeOver).not.toHaveBeenCalled()
      expect(discard).toHaveBeenCalledTimes(1)
    }
  })

  it('fuehrt den Cache je Fassung, damit die vorherige nicht ueberschrieben wird', () => {
    expect(bundleCacheName('2026.3.1')).not.toBe(bundleCacheName('2026.2.9'))
  })
})

describe('die Auslieferungstrennung nach §4.1', () => {
  it('builds a bundle that addresses nothing absolutely and names no bundle origin', () => {
    // Liest den AUSGANG des Baus und nicht die Quelle: was ausgeliefert wird,
    // entscheidet ueber die Trennung.
    const html = readFileSync(path.join(packageRoot, 'dist', 'index.html'), 'utf8')

    // Kein Beiwerkspfad beginnt mit `/`: ein absoluter Pfad baende das Buendel
    // an genau einen Origin.
    for (const attribute of html.matchAll(/(?:src|href)="([^"]*)"/g)) {
      expect(attribute[1]).not.toMatch(/^\//)
      expect(attribute[1]).not.toMatch(/^https?:\/\//)
    }

    // Und die Richtlinie nennt GENAU EINE entfernte Herkunft — die des
    // Sync-Servers, nicht die des Bundle-Hosts.
    const policy = /<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]*)"/.exec(html)?.[1]
    expect(typeof policy).toBe('string')
    const remotes = String(policy)
      .split(/[;\s]+/)
      .filter(value => /^https?:\/\//.test(value))
    expect(remotes).toEqual([SYNC_SERVER_ORIGIN])
  })

  it('emits the service worker under a stable, unhashed name', () => {
    // Ein gehashter Workername waere bei jedem Bau ein anderer
    // Registrierungspfad — und damit ein Aktivierungspfad ausserhalb der
    // Pinnung.
    const worker = readFileSync(path.join(packageRoot, 'dist', 'service-worker.js'), 'utf8')
    expect(worker.length).toBeGreaterThan(0)
  })

  it('pins the vite configuration that makes the separation possible', () => {
    const config = readFileSync(path.join(packageRoot, 'vite.config.ts'), 'utf8')
    // Relative Beiwerkspfade: ein absoluter Pfad baende das Buendel an genau
    // einen Origin und machte die Trennung unbenutzbar.
    expect(config).toContain("base: './'")
    // Der Worker ist ein eigener Einstieg und traegt einen UNGEHASHTEN Namen.
    expect(config).toMatch(/'service-worker':/)
    expect(config).toMatch(/'service-worker\.js'/)
    // Und er ist ein MODUL: die wasm-bindgen-Glue ist ein ES-Modul, ein
    // klassischer Worker koennte sie nicht importieren und muesste die
    // Entscheidung von aussen entgegennehmen.
    expect(config).not.toMatch(/format:\s*'iife'/)
  })

  it('registers the worker as a module and never absolutely', () => {
    const main = readFileSync(path.join(packageRoot, 'src', 'main.tsx'), 'utf8')
    expect(main).toContain("register('./service-worker.js', { type: 'module' })")
    expect(main).not.toContain("register('/service-worker.js'")
  })
})
