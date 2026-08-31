import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { expect, it } from 'vitest'

// Der erste der zwei gegateten Zeugen. Er faehrt die vier Elemente aus
// `web-reader-design.md` §14.1, die `spikes/wasm-runtime-proof/` heute
// AUSSERHALB jedes Gates faehrt: ein Nachweis, den kein Lauf faehrt, verfaellt
// still.
//
// Die Gestalt des Berichts steht hier als Typ und nicht als Zusicherung: der
// Zeuge liest ihn, er schreibt ihn nicht. Jede Zahl darin entsteht in Rust,
// und TypeScript bekommt eine JSON-Zeichenkette und nie ein Rechenobjekt.
type RuntimeWitness = {
  readonly targetTriple: string
  readonly getrandom: {
    readonly draw1: string
    readonly draw2: string
    readonly freshSealsUsedDistinctEphemeralKeys: boolean
    readonly largeDrawLength: number
  }
  readonly hpke: {
    readonly vectorFile: string
    readonly recoveredContentEncryptionKey: string
    readonly rejectedTamperedVectors: {
      readonly flippedEncapsulatedKey: string
      readonly flippedWrappedCek: string
    }
  }
  readonly ed25519: {
    readonly acceptedValidSignature: boolean
    readonly tamperedRejectionCode: string
  }
}

// BEFUND, GEMESSEN und nicht angenommen: `xtask build-wasm` ruft
// `wasm-bindgen --target web`. Der Ausgang dieses Ziels exportiert die
// Instanziierung als Vorgabeeinstieg, und die BENANNTEN Ausfuhren greifen erst
// danach auf das Modul zu — davor faellt jeder Aufruf mit
// `Cannot read properties of undefined (reading '__wbindgen_free')`. Der
// Planentwurf dieser Datei ruft `readerRuntimeWitness` unmittelbar hinter dem
// `import`; `--target web` ist aber die richtige Wahl, weil derselbe Ausgang im
// dedizierten OPFS-Worker laeuft. Also holt DIESE Datei die Instanziierung
// nach, statt das Ziel zu wechseln. Keine Zusicherung darunter ist davon
// beruehrt.
//
// Die Bytes werden GELESEN und nicht geholt: ohne Argument bildet der
// Vorgabeeinstieg `fetch(new URL('ea_reader_wasm_bg.wasm', import.meta.url))`,
// und Node kennt kein `fetch` auf einer `file:`-URL.
//
// Der Pfad entsteht ueber `fileURLToPath` und NICHT ueber `new URL(…,
// import.meta.url)`: Vite erkennt die zweite Form als Beiwerksverweis und
// ersetzt sie durch eine bediente URL (gemessen: `TypeError: The URL must be of
// scheme file`).
const bridgeDirectory = path.dirname(fileURLToPath(import.meta.url))
const wasmBytes = readFileSync(path.join(bridgeDirectory, 'pkg/ea_reader_wasm_bg.wasm'))

async function readerRuntimeWitnessOf(): Promise<() => string> {
  const bridge = await import('./pkg/ea_reader_wasm.js')
  await bridge.default({ module_or_path: wasmBytes })
  return bridge.readerRuntimeWitness
}

it('opens the frozen HPKE encapsulation and rejects both tampered vectors', async () => {
  const readerRuntimeWitness = await readerRuntimeWitnessOf()
  const witness = JSON.parse(readerRuntimeWitness()) as RuntimeWitness
  expect(witness.targetTriple).toBe('wasm32-unknown-unknown')
  expect(witness.hpke.vectorFile).toBe('vectors/crypto/suite-1/hpke/base-mode-wrapped-cek.bin')
  expect(witness.hpke.recoveredContentEncryptionKey).toBe('c0'.repeat(32))
  expect(witness.hpke.rejectedTamperedVectors.flippedEncapsulatedKey).toBe('EA-CRYPTO-HPKE-OPEN')
  expect(witness.hpke.rejectedTamperedVectors.flippedWrappedCek).toBe('EA-CRYPTO-HPKE-OPEN')
})

it('verifies RFC 8032 test 1 and rejects the flipped signature', async () => {
  const readerRuntimeWitness = await readerRuntimeWitnessOf()
  const witness = JSON.parse(readerRuntimeWitness()) as RuntimeWitness
  expect(witness.ed25519.acceptedValidSignature).toBe(true)
  expect(witness.ed25519.tamperedRejectionCode).toBe('EA-TRUST-SIGNATURE-INVALID')
})

it('draws entropy from the host and not from the module', async () => {
  const readerRuntimeWitness = await readerRuntimeWitnessOf()
  const witness = JSON.parse(readerRuntimeWitness()) as RuntimeWitness
  expect(witness.getrandom.draw1).not.toBe(witness.getrandom.draw2)
  expect(witness.getrandom.freshSealsUsedDistinctEphemeralKeys).toBe(true)
  expect(witness.getrandom.largeDrawLength).toBe(100_000)
})

// Die Gegenkontrolle des Spikes, hier als Testfall statt als Ausgangswert eines
// Skripts: ohne Web Crypto MUSS getrandom scheitern. Sie traegt den staerksten
// Teil des Nachweises fuer Element 2.
//
// BEFUND, GEMESSEN, und die Stelle, an der zwei Saetze des Plans einander
// widersprechen. Der Planentwurf dieser Datei erwartet einen WURF
// (`expect(() => readerRuntimeWitness()).toThrow()`). Derselbe Plan verlangt
// aber, `runtime_proof_json` UNVERAENDERT aus dem Spike zu heben, und diese
// Rechnung berichtet, statt zu werfen:
// `crates/ea-reader-wasm/src/bridge.rs` schreibt ausdruecklich auf, dass der
// Bericht IMMER wohlgeformtes JSON ist und ein Fehlschlag als `"ok": false`
// samt `"errors"` darin steht, „damit der Aufrufer ihn ausgeben kann, statt an
// einem Trap zu ersticken". Ein Wurf waere dort ein Panik-Trap.
//
// Die Zusicherung folgt deshalb der GEMESSENEN Flaeche und nicht dem Entwurf,
// und sie ist dabei nicht schwaecher, sondern genauer: sie benennt, WELCHES
// der vier Elemente geschlossen gefallen ist. Ohne Web Crypto ist
// `getrandom` `null`, `ok` ist `false`, und `errors` nennt es.
it('fails closed when the host has no Web Crypto API', async () => {
  const saved = globalThis.crypto
  Reflect.deleteProperty(globalThis, 'crypto')
  try {
    // Ein FRISCHES Modul und nicht das oben instanziierte: der Suffix ist eine
    // Vite-Anfrage und erzwingt eine zweite Instanz, deren Instanziierung ohne
    // Web Crypto stattfindet.
    const bridge = await import('./pkg/ea_reader_wasm.js?no-webcrypto')
    await bridge.default({ module_or_path: wasmBytes })
    const report = JSON.parse(bridge.readerRuntimeWitness()) as {
      readonly ok: boolean
      readonly errors: string
      readonly getrandom: unknown
    }
    expect(report.ok).toBe(false)
    expect(report.getrandom).toBeNull()
    expect(report.errors).toContain('getrandom')
  } finally {
    Object.defineProperty(globalThis, 'crypto', { value: saved, configurable: true })
  }
})
