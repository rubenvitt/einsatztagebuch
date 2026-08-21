import { readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { render } from '@testing-library/react'
import { expect, it } from 'vitest'

import { DecorativeIcon, eaIcons } from './icons'

const designDirectory = path.dirname(fileURLToPath(import.meta.url))
const sourceRoot = path.resolve(designDirectory, '..')

/** Genau EIN Symbol pro Modulpfad — die Vorgabe des Briefes. */
const PER_ICON_MODULE = /^@phosphor-icons\/react\/dist\/csr\/[A-Z][A-Za-z0-9]*$/

function iconsSource(): string {
  return readFileSync(path.join(designDirectory, 'icons.tsx'), 'utf8')
}

function handWrittenSources(): [string, string][] {
  return readdirSync(sourceRoot, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => path.join(entry.parentPath, entry.name))
    .filter((file) => /\.tsx?$/.test(file))
    .filter((file) => !/\.test\.tsx?$/.test(file))
    .sort()
    .map((file) => [path.relative(sourceRoot, file), readFileSync(file, 'utf8')] as [string, string])
}

it('imports every icon from its own per-icon module', () => {
  const source = iconsSource()
  const specifiers = [...source.matchAll(/from\s+'([^']+)'/g)].map((match) => match[1] ?? '')
  const phosphor = specifiers.filter((specifier) => specifier.includes('@phosphor-icons'))
  expect(phosphor.length).toBeGreaterThan(0)
  expect(phosphor.length).toBe(Object.keys(eaIcons).length)
  for (const specifier of phosphor) {
    expect(specifier, specifier).toMatch(PER_ICON_MODULE)
  }
  expect(new Set(phosphor).size).toBe(phosphor.length)
})

it('pulls in no full catalogue, no wildcard, and no dynamic import', () => {
  const source = iconsSource()
  // Der KATALOGeinstieg. `dist/index.es.js` ist 190 kB und zieht jedes Symbol.
  expect(source).not.toMatch(/from\s+'@phosphor-icons\/react'/)
  expect(source).not.toMatch(/from\s+'@phosphor-icons\/react\/(ssr|lib)/)
  expect(source).not.toMatch(/import\s+\*\s+as/)
  expect(source).not.toMatch(/import\s*\(/)
  expect(source).not.toMatch(/require\s*\(/)
})

it('names react-icons nowhere in the hand written sources', () => {
  for (const [file, text] of handWrittenSources()) {
    expect(text, file).not.toContain('react-icons')
  }
})

it('marks decorative icons as hidden and gives them no accessible name', () => {
  const { container } = render(<DecorativeIcon name="verified" />)
  const svg = container.querySelector('svg')
  expect(svg).not.toBeNull()
  expect(svg?.getAttribute('aria-hidden')).toBe('true')
  expect(svg?.getAttribute('focusable')).toBe('false')
  expect(svg?.getAttribute('aria-label')).toBeNull()
  expect(svg?.getAttribute('alt')).toBeNull()
})

// `weight="fill"` ist der Zustandstraeger und darf nicht die Vorgabe sein. Die
// Zusicherung liest die GERENDERTE Gestalt und nicht das Attribut: ein
// weitergegebenes, aber unwirksames `weight` faellt damit auf.
it('fills an icon only for a positively confirmed state', () => {
  const { container } = render(
    <>
      <DecorativeIcon name="verified" />
      <DecorativeIcon name="verified" state="confirmed" />
      <DecorativeIcon name="verified" state="default" />
    </>,
  )
  const drawn = [...container.querySelectorAll('svg')].map((svg) => svg.innerHTML)
  expect(drawn).toHaveLength(3)
  expect(drawn[0]).not.toBe(drawn[1])
  expect(drawn[0]).toBe(drawn[2])
  expect(iconsSource().match(/'fill'/g)).toHaveLength(1)
})

it('resolves every declared icon to a real component', () => {
  const names = Object.keys(eaIcons)
  expect(names.length).toBeGreaterThan(0)
  for (const name of names) {
    const { container, unmount } = render(<DecorativeIcon name={name as keyof typeof eaIcons} />)
    expect(container.querySelector('svg'), name).not.toBeNull()
    unmount()
  }
})
