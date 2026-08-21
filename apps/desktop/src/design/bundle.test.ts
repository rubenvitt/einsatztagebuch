import { existsSync, readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { expect, it } from 'vitest'

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const distributionRoot = path.join(packageRoot, 'dist')

type BundleFile = { readonly name: string; readonly text: string }

/**
 * Jede Datei des Produktionsbuendels. Die Ausgabe entsteht in
 * `pnpm --dir apps/desktop build`, und deshalb laeuft der Bau VOR diesem Test.
 */
function bundleFiles(): BundleFile[] {
  expect(
    existsSync(distributionRoot),
    'apps/desktop/dist fehlt — `pnpm --dir apps/desktop build` laeuft vor diesem Test',
  ).toBe(true)
  return readdirSync(distributionRoot, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => path.join(entry.parentPath, entry.name))
    .sort()
    .map((file) => ({
      name: path.relative(distributionRoot, file),
      text: readFileSync(file, 'utf8'),
    }))
}

function withExtension(extension: string): BundleFile[] {
  return bundleFiles().filter((file) => file.name.endsWith(extension))
}

it('reads a real bundle', () => {
  const files = bundleFiles()
  expect(files.map((file) => file.name)).toContain('index.html')
  expect(withExtension('.css').length).toBeGreaterThan(0)
  expect(withExtension('.js').length).toBeGreaterThan(0)
  // Die gehashten Beiwerke: ohne Hash im Namen gaebe es keine
  // wiedererkennbare, lokale Ressource.
  for (const file of [...withExtension('.css'), ...withExtension('.js')]) {
    expect(file.name, file.name).toMatch(/-[A-Za-z0-9_-]{8,}\.(css|js)$/)
  }
})

it('carries no external font and no external style sheet', () => {
  for (const file of withExtension('.css')) {
    expect(file.text, file.name).not.toMatch(/url\(\s*['"]?https?:/)
    expect(file.text, file.name).not.toMatch(/@import\s+(url\()?['"]?https?:/)
  }
  for (const file of withExtension('.html')) {
    expect(file.text, file.name).not.toMatch(/<link[^>]+href\s*=\s*["']https?:/)
    expect(file.text, file.name).not.toMatch(/<script[^>]+src\s*=\s*["']https?:/)
  }
}) 

it('names react-icons nowhere in the bundle', () => {
  for (const file of bundleFiles()) {
    expect(file.text, file.name).not.toContain('react-icons')
  }
})

// Was die CSP verlangt, am ARTEFAKT gemessen: `script-src 'self'` verbietet ein
// Skript ohne Quelle, `style-src-elem 'self'` ein `<style>`-Element.
it('embeds no inline script and no inline style element', () => {
  for (const file of withExtension('.html')) {
    expect(file.text, file.name).not.toMatch(/<style[\s>]/)
    for (const script of file.text.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)) {
      expect((script[1] ?? '').includes('src='), file.name).toBe(true)
      expect((script[2] ?? '').trim(), file.name).toBe('')
    }
  }
})

// Die extrahierte Datei erreicht das Buendel — MIT ihrer Kaskadenschicht. Ohne
// die Schicht koennte eine herabgestufte Ant-Regel eine Anwendungsregel
// ueberstimmen; ohne die Regeln selbst waere die Oberflaeche unformatiert.
it('ships the extracted Ant rules inside their own cascade layer', () => {
  const styles = withExtension('.css')
  expect(styles.length).toBeGreaterThan(0)
  const joined = styles.map((file) => file.text).join('\n')
  expect(joined).toContain('@layer antd{')
  expect(joined).toContain('--ea-ink')
  expect(joined).toContain('.ant-btn')
  // Die Anwendungsregeln bleiben AUSSERHALB der Schicht: alles nach dem
  // schliessenden Ende des Schichtblocks.
  expect(joined.indexOf('@layer antd{')).toBe(joined.lastIndexOf('@layer antd{'))
})
