import { readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { expect, it } from 'vitest'

import { EA_CUSTOM_PROPERTY_BLOCK, EXTRACTED_COMPONENTS, extractStaticCss } from './extract-static-css'
import { eaAction, eaDanger, eaExtractionTheme, eaInk, eaRuntimeTheme, eaSurface, eaTokens, eaVerified, eaWarning } from './tokens'

const designDirectory = path.dirname(fileURLToPath(import.meta.url))
const sourceRoot = path.resolve(designDirectory, '..')

/** Die Komponenten, die `@ant-design/static-style-extract` selbst aussortiert. */
const LIBRARY_BLACKLIST = ['ConfigProvider', 'Grid']

function read(relative: string): string {
  return readFileSync(path.join(sourceRoot, relative), 'utf8')
}

function handWrittenSources(): [string, string][] {
  const entries = readdirSync(sourceRoot, { recursive: true, withFileTypes: true })
  return entries
    .filter((entry) => entry.isFile())
    .map((entry) => path.join(entry.parentPath, entry.name))
    .filter((file) => /\.tsx?$/.test(file))
    .filter((file) => !/\.test\.tsx?$/.test(file))
    .sort()
    .map((file) => [path.relative(sourceRoot, file), readFileSync(file, 'utf8')] as [string, string])
}

it('extracts byte-identical css twice', () => {
  expect(extractStaticCss()).toBe(extractStaticCss())
})

// Ohne diesen Zeugen ist die Zusicherung des Briefes
// `expect(loadedStaticCss()).toContain('--ea-ink')` UNFAELLBAR: den
// Merkmalsblock schreibt diese Datei selbst, VOR der Ant-Ausgabe. Eine
// Extraktion, die — etwa unter `zeroRuntime: true` — die leere Zeichenkette
// liefert, wuerde jene Pruefung weiter bestehen. Diese hier nicht.
it('carries actual Ant Design rules and not just the token block', () => {
  const css = extractStaticCss()
  const antPart = css.slice(EA_CUSTOM_PROPERTY_BLOCK.length)
  expect(antPart.length).toBeGreaterThan(10_000)
  for (const selector of ['.ant-app', '.ant-layout', '.ant-btn', '.ant-alert', '.ant-modal']) {
    expect(antPart, selector).toContain(selector)
  }
})

it('emits the frozen custom property block before the Ant output', () => {
  const css = extractStaticCss()
  expect(css.startsWith(EA_CUSTOM_PROPERTY_BLOCK)).toBe(true)
  expect(EA_CUSTOM_PROPERTY_BLOCK).toBe(
    ':root{--ea-ink:#172033;--ea-surface:#F5F7FA;--ea-action:#245EA8;--ea-danger:#C6352B;--ea-verified:#187255;--ea-warning:#A65F00}',
  )
})

// Der Grund, warum die Extraktion ueberhaupt gegen eine EINGECHECKTE Datei
// vergleichbar ist: kein Entwicklungspraefix im Text. Mit dem Vorgabewert
// `hashed: true` traegt jeder Selektor `css-dev-only-do-not-override-…`, sobald
// `NODE_ENV` nicht `production` ist — die Datei haette dann in `vitest` andere
// Bytes als im Produktionsbau. Und der Themenblock haengt am FESTEN
// `cssVar.key`; ohne ihn vergibt `antd` ihn ueber `React.useId()`, und keine
// einzige `var(--ant-…)`-Referenz loeste zur Laufzeit auf.
it('produces environment independent selectors', () => {
  const css = extractStaticCss()
  expect(css).not.toContain('dev-only')
  expect(css).toContain(`.${eaExtractionTheme.cssVar.key}{--ant-`)
  expect(css).toContain(`.${eaExtractionTheme.cssVar.key}.ant-btn{--ant-`)

  // Der OFFENGELEGTE Rest: `@ant-design/static-style-extract` rendert `Modal`,
  // `message` und `notification` ueber ihre `PurePanel`-Formen, und jede davon
  // legt einen EIGENEN `ConfigProvider` mit eigenem `React.useId`-Schluessel um
  // sich. Die so entstehenden Bloecke sind Duplikate des Blocks oben (gemessen:
  // dieselben Werte, einschliesslich `--ant-color-primary`), und ihr Selektor
  // trifft zur Laufzeit nichts. Sie sind deterministisch — der Rendezweig der
  // Extraktion ist fest —, also bleibt die Datei vergleichbar; die Zahl steht
  // hier, damit ein Wachstum dieses Restes auffaellt und nicht einzieht.
  const anonymousScopes = new Set(css.match(/css-var-_R_[0-9a-z]+_/g) ?? [])
  expect(anonymousScopes.size).toBeLessThanOrEqual(3)
  for (const scope of anonymousScopes) {
    for (const block of css.matchAll(new RegExp(`\\.${scope}[^{]*\\{([^}]*)\\}`, 'g'))) {
      expect(block[1] ?? '', scope).toMatch(/^--ant-/)
    }
  }
})

// Die eingecheckte Datei IST der Emitterausdruck. Neu erzeugt wird sie mit
//   pnpm --dir apps/desktop test --run -u
it('matches the checked-in static-antd.css byte for byte', async () => {
  await expect(extractStaticCss()).toMatchFileSnapshot('./static-antd.css')
})

// Die zwei Themen sind EIN Wert mit einer Differenz, und die Differenz ist die
// ganze Zusage. Gemessen: unter `zeroRuntime: true` kehrt
// `cssinjs-utils/es/util/genStyleUtils.js:123` vor `useStyleRegister` zurueck,
// die Extraktion liefert dann KEINE Komponentenregel; ohne `zeroRuntime` zur
// Laufzeit spritzt Ant Design seine Regeln doppelt ein und die CSP blockiert
// sie. Beides ist ein stiller Totalausfall der Oberflaeche.
it('separates the extraction theme from the runtime theme by exactly the zeroRuntime switch', () => {
  expect(eaRuntimeTheme.zeroRuntime).toBe(true)
  expect('zeroRuntime' in eaExtractionTheme).toBe(false)
  expect(eaRuntimeTheme.token).toBe(eaTokens)
  expect(eaExtractionTheme.token).toBe(eaTokens)
  expect(eaRuntimeTheme.hashed).toBe(false)
  expect(eaExtractionTheme.hashed).toBe(false)
  expect(eaRuntimeTheme.cssVar.key).toBe(eaExtractionTheme.cssVar.key)
})

it('derives every Ant alias from the six frozen colours and adds no seventh', () => {
  expect(eaTokens.colorText).toBe(eaInk)
  expect(eaTokens.colorBgLayout).toBe(eaSurface)
  expect(eaTokens.colorPrimary).toBe(eaAction)
  expect(eaTokens.colorError).toBe(eaDanger)
  expect(eaTokens.colorSuccess).toBe(eaVerified)
  expect(eaTokens.colorWarning).toBe(eaWarning)
  expect(eaTokens.colorInfo).toBe(eaAction)
  expect(eaTokens.colorLink).toBe(eaAction)
  const hexLiterals = new Set(read('design/tokens.ts').match(/#[0-9A-Fa-f]{6}/g) ?? [])
  expect([...hexLiterals].sort()).toEqual(
    [eaInk, eaSurface, eaAction, eaDanger, eaVerified, eaWarning].sort(),
  )
  // Die Extraktion leitet ab und schreibt keinen Farbwert.
  expect(read('design/extract-static-css.tsx')).not.toMatch(/#[0-9A-Fa-f]{6}/)
})

// Der Umfang der Extraktion ist eine LISTE, und eine Liste veraltet. Dieser
// Zeuge macht das Veralten sichtbar: eine Ant-Komponente, die irgendeine
// handgeschriebene Quelle importiert, aber niemand extrahiert hat, hat unter
// `zeroRuntime: true` und dieser CSP keine einzige Regel.
it('extracts every Ant component the hand written sources import', () => {
  const imported = new Set<string>()
  for (const [, text] of handWrittenSources()) {
    for (const match of text.matchAll(/import\s+(type\s+)?\{([^}]*)\}\s+from\s+'antd'/g)) {
      if (match[1] !== undefined) {
        continue
      }
      for (const raw of (match[2] ?? '').split(',')) {
        const name = raw.trim()
        if (name.length > 0 && !name.startsWith('type ')) {
          imported.add(name)
        }
      }
    }
  }
  expect(imported.size).toBeGreaterThan(0)
  const expected = [...imported].filter((name) => !LIBRARY_BLACKLIST.includes(name)).sort()
  expect(expected.filter((name) => !EXTRACTED_COMPONENTS.includes(name))).toEqual([])
  // Die drei Ueberlagerungen des Briefes stehen zusaetzlich drin: sie werden
  // erst in Task 16 gerendert, und eine unformatierte Bestaetigung waere genau
  // dort die falsche Ueberraschung.
  for (const popup of ['Modal', 'message', 'notification']) {
    expect(EXTRACTED_COMPONENTS).toContain(popup)
  }
})

// `app.css` ist der EINE Ort, an dem Anwendungsregeln stehen — und der
// `@import` mit `layer(antd)` ist der Grund, warum sie die herabgestufte
// Ant-Kaskade ueberstimmen. Gemessen: `vite build` loest den Import auf und
// erzeugt daraus `@layer antd{…}`.
it('puts the extracted file in its own cascade layer and keeps the app rules out of it', () => {
  const appCss = read('design/app.css')
  // OHNE Kommentare: die Begruendungen darin nennen `@layer antd{…}` und
  // `https://`-freie Prosa, und eine Zusicherung ueber Kommentartext waere
  // keine ueber die Kaskade.
  const rules = appCss.replaceAll(/\/\*[\s\S]*?\*\//g, '')
  const importStatement = '@import url(static-antd.css) layer(antd);'
  expect(rules).toContain(importStatement)
  // KEINE Regel vor dem Import: ein `@import` nach der ersten Regel ist
  // ungueltig und wuerde stillschweigend verworfen.
  expect(rules.slice(0, rules.indexOf(importStatement))).not.toContain('{')
  // Die Anwendungsregeln bleiben UNLAYERED — nur so ueberstimmen sie die
  // herabgestufte Ant-Kaskade.
  expect(rules.match(/@layer/g)).toBeNull()
  expect(rules.match(/layer\(/g)).toHaveLength(1)
  expect(rules).toMatch(/@media \(prefers-reduced-motion: reduce\)/)
  expect(rules).toMatch(/:focus-visible/)
  expect(rules).not.toMatch(/https?:/)
})
