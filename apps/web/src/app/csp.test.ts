import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { expect, it } from 'vitest'

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')

// Die Zielrichtlinie, Position fuer Position. Sie steht hier als LITERAL und
// nicht abgeleitet: dieser Test IST der Pin, und eine abgeleitete Erwartung
// koennte mit der Richtlinie gemeinsam wandern.
const EXPECTED_DIRECTIVES = [
  "default-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self'",
  "style-src-elem 'self'",
  "style-src-attr 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "worker-src 'self'",
  "frame-src 'none'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
]

// Der Desktop liest `src-tauri/tauri.conf.json`; hier steht die Richtlinie im
// `<meta http-equiv>` von `index.html`, weil der Browser-Reader keine
// Wirtkonfiguration hat. NUR die Beschaffung wechselt — die Zerlegung darunter
// ist zeichengleich zur Desktop-Fassung, damit beide Pins dieselbe Form haben.
function policy(): string {
  const html = readFileSync(path.join(packageRoot, 'index.html'), 'utf8')
  const meta = /<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]*)"\s*\/?>/.exec(html)?.[1]
  expect(typeof meta).toBe('string')
  return String(meta)
}

function directives(): string[] {
  return policy()
    .split(';')
    .map((directive) => directive.trim())
    .filter((directive) => directive.length > 0)
}

it('pins the content security policy directive list position by position', () => {
  expect(directives()).toEqual(EXPECTED_DIRECTIVES)
})

// Die drei Stilrichtlinien einzeln, weil sie die TRAGENDE Entscheidung dieses
// Tasks sind: `style-src` und `style-src-elem` auf `'self'` verbieten jede
// eingespritzte und jede entfernte Stilregel, waehrend `style-src-attr` auf
// `'unsafe-inline'` bleibt, weil React und Ant Design Elementattribute setzen —
// ein Stilattribut laedt nichts und spritzt kein Regelwerk ein.
it('forbids injected and remote style sheets while allowing the style attribute', () => {
  const list = directives()
  expect(list).toContain("style-src 'self'")
  expect(list).toContain("style-src-elem 'self'")
  expect(list).toContain("style-src-attr 'unsafe-inline'")
  const styleRules = list.filter((directive) => /^style-src(-elem)? /.test(directive))
  expect(styleRules).toHaveLength(2)
  for (const rule of styleRules) {
    expect(rule).not.toContain('unsafe-inline')
    expect(rule).not.toContain('http')
  }
})

// Die Ersetzung des Desktop-Zeugen `allows no script evaluation and no inline
// script`: dessen `not.toContain('unsafe-eval')` ist im Browser-Reader per
// Definition falsch, weil `WebAssembly.instantiate` unter `default-src 'none'`
// sonst blockiert. Die verfeinerte Fassung prueft den GANZEN Wert und laesst
// genau einen Quellenausdruck mehr zu als die Desktop-Grundlinie.
it('adds exactly one directive value beyond the desktop policy, and it is wasm-unsafe-eval', () => {
  const script = directives().find((directive) => directive.startsWith('script-src '))
  expect(script).toBe("script-src 'self' 'wasm-unsafe-eval'")
  expect(directives().join('; ')).not.toContain('unsafe-eval;')
  expect(directives().join('; ')).not.toContain("'unsafe-inline'; script")
})

// Die Rolle, die beim Desktop der IPC-Kanal hatte: `worker-src 'self'` ist
// keine Erweiterung, sondern die Voraussetzung des OPFS-Workers — unter
// `default-src 'none'` gaebe es sonst keinen dedizierten Worker. Das
// `not.toMatch(/https?:/)` ist zugleich der Beleg, dass die VERENGUNG von
// `connect-src` vollzogen ist: `http://ipc.localhost` faerbte es rot.
it('keeps the OPFS worker reachable and admits no remote origin', () => {
  expect(directives()).toContain("worker-src 'self'")
  expect(directives().join('; ')).not.toMatch(/https?:/)
})
