import { readFile, readdir } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { expect, it } from 'vitest'

// Die Haelfte, die ein Rusttest nicht sehen kann: er assertiert ueber die
// Zeichenkette, die er selbst erzeugt hat, aber nur ein TypeScript-Test liest
// den BAUM, der sie verbraucht. Der Wert dieser Datei ist jeder spaetere Lauf
// und nicht dieser: sie steht hier, damit sie an ihrem Platz ist, BEVOR die
// erste Schale und die ersten Merkmalsquellen entstehen.
const bridgeDirectory = path.dirname(fileURLToPath(import.meta.url))
const sourceRoot = path.resolve(bridgeDirectory, '..')
const generatedContracts = path.join(bridgeDirectory, 'generated-contracts.ts')

/**
 * Jede Quelle unter `src`, ausser der generierten Datei selbst und ausser den
 * Testdateien — deren Zusicherungen MUESSEN die gerenderte Zeichenkette
 * benennen duerfen.
 */
async function handWrittenSources(): Promise<[string, string][]> {
  const entries = await readdir(sourceRoot, { recursive: true, withFileTypes: true })
  const files = entries
    .filter(entry => entry.isFile())
    .map(entry => path.join(entry.parentPath, entry.name))
    .filter(file => /\.tsx?$/.test(file))
    .filter(file => file !== generatedContracts)
    .filter(file => !/\.test\.tsx?$/.test(file))
    .sort()
  return Promise.all(
    files.map(
      async file =>
        [path.relative(sourceRoot, file), await readFile(file, 'utf8')] as [string, string],
    ),
  )
}

/**
 * Die Literale JEDER Zeichenkettenvereinigung der generierten Datei — gelesen
 * und nicht hier wiederholt. Eine Liste von Hand waere die zweite Quelle
 * derselben Wahrheit und damit genau der Defekt, den diese Datei bewacht.
 */
async function securityEnumLiterals(): Promise<string[]> {
  const text = await readFile(generatedContracts, 'utf8')
  const literals = new Set<string>()
  let insideUnion = false
  for (const line of text.split('\n')) {
    if (line.startsWith('export type ') && line.endsWith('=')) {
      insideUnion = true
      continue
    }
    // Die Erfassung kommt VOR der Pruefung, damit sie unter
    // `noUncheckedIndexedAccess` als `string` und nicht als
    // `string | undefined` ankommt.
    const captured = /^ {2}\| '([^']*)'$/.exec(line)?.[1]
    if (insideUnion && captured !== undefined) {
      literals.add(captured)
      continue
    }
    if (!line.startsWith(' ')) {
      insideUnion = false
    }
  }
  return [...literals].sort()
}

it('reads both sides it compares', async () => {
  // Ohne diesen Zeugen kann die Datei gruen laufen, ohne etwas zu pruefen: ein
  // Laufwerksfehler, eine zu weite Ausnahme oder ein falscher Wurzelpfad
  // liefert eine LEERE Quellenmenge, und beide Zusicherungen unten iterieren
  // dann ueber nichts.
  const sources = await handWrittenSources()
  expect(sources.length).toBeGreaterThan(0)
  expect(sources.map(([file]) => file)).not.toContain('bridge/generated-contracts.ts')
  const literals = await securityEnumLiterals()
  expect(literals.length).toBeGreaterThan(0)
  // Der Anker der READER-Haelfte. Der Desktop pinnt hier `lokal gesichert` aus
  // `SyncStatus`; dieses Literal traegt die Reader-Datei nicht. Gewaehlt ist
  // ein MEHRWORTIGER Begriff aus den sechs Verifikationszustaenden, weil er
  // dieselbe Form hat wie das Desktop-Pendant und weil die globalen
  // Randbedingungen genau ihn gegen Verwechslung schuetzen: `fehlender Grant`
  // ist nie eine `Lücke`, nie `unbekannter Schlüssel` und nie `ungültig`.
  expect(literals).toContain('fehlender Grant')
})

it('declares no security enum outside the generated contracts', async () => {
  const sources = await handWrittenSources()
  for (const literal of await securityEnumLiterals()) {
    // Die ZITIERTE Form, weil ein Bezeichnerliteral wie `Writer` als blosse
    // Teilzeichenkette in jedem Writer-Modul steht; ein mehrwortiges Literal
    // kann nur Oberflaechenkopie sein und faellt deshalb auch unzitiert auf.
    const forms = [`'${literal}'`, `"${literal}"`, `\`${literal}\``]
    if (literal.includes(' ')) {
      forms.push(literal)
    }
    for (const [file, text] of sources) {
      for (const form of forms) {
        expect(text, `${file} duplicates the security literal ${literal}`).not.toContain(form)
      }
    }
  }
})

it('creates no grant, hash, signature, ciphertext, or archive byte in TypeScript', async () => {
  const sources = await handWrittenSources()
  for (const [file, text] of sources) {
    expect(text, file).not.toMatch(
      /crypto\.subtle|createHash|Ed25519|X25519|ChaCha20|new Uint8Array\(32\)/,
    )
  }
})
